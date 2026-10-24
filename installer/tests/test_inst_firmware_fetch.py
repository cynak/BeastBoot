"""firmware catalog / fetch (docs/BEASTNET.md section 6) against a local HTTPS server,
and the pack cpio format."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess

import pytest
from conftest import read_events, run_cli, step_ids
from fwhelpers import PACKS, TAG, FwServer, contents, have_openssl, make_bn_dist, make_catalog, make_cert, write_catalog

from beastbooter import firmware
from beastbooter.cpio import build_pack, read_newc

pytestmark = pytest.mark.skipif(not have_openssl(), reason="openssl is needed to make a test certificate")


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return make_cert(tmp_path_factory.mktemp("tls"))


@pytest.fixture
def server(cert, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(cert[0]))  # trust the test CA; verification stays on
    monkeypatch.setattr(firmware, "RETRY_DELAYS", (0.0, 0.0))
    s = FwServer(*cert)
    yield s
    s.close()


@pytest.fixture
def catalog_file(server, tmp_path):
    return write_catalog(tmp_path / "catalog.json", make_catalog(server.template))


def fetch(catalog_file, out, *packs, progress=None, extra=()):
    args = ["firmware", "fetch", "--catalog", catalog_file, "--out", out]
    for p in packs:
        args += ["--pack", p]
    if progress:
        args += ["--progress-file", progress]
    return run_cli(*args, *extra)


def test_fetch_ok(server, catalog_file, tmp_path):
    out, progress = tmp_path / "packs", tmp_path / "p.jsonl"
    assert fetch(catalog_file, out, "acme-wifi", "tiny-eth", progress=progress) == 0
    assert sorted(os.listdir(out)) == ["acme-wifi.cpio", "acme-wifi.json", "tiny-eth.cpio", "tiny-eth.json"]
    for pid in PACKS:
        data = (out / f"{pid}.cpio").read_bytes()
        assert data == build_pack(contents(pid))
        files = {e.name: e.data for e in read_newc(data) if e.is_file}
        assert files == {f"lib/firmware/{k}": v for k, v in contents(pid).items()}
        entry = json.loads((out / f"{pid}.json").read_text())
        assert entry["id"] == pid and entry["catalog_tag"] == TAG
        assert entry["cpio_sha256"] == hashlib.sha256(data).hexdigest()
        assert [f["path"] for f in entry["files"]] == [p for p, _ in PACKS[pid]]
    # source_path is downloaded (and installed as path); spaces are %20-quoted on the wire
    assert "real/c-1.bin" in server.requests and "acme/c.bin" not in server.requests
    assert "odd/name with space.txt" in server.requests
    events = read_events(progress)
    assert events[0] == {"v": 1, "event": "start", "action": "firmware-fetch", "target": str(out)}
    assert step_ids(events) == ["download", "write-firmware", "download", "write-firmware"]
    done = events[-1]
    assert done["event"] == "done" and done["info"]["packs"] == ["acme-wifi", "tiny-eth"]
    pcts = [e["pct"] for e in events if e["event"] == "step"]
    assert pcts == sorted(pcts)


def test_fetch_is_deterministic(server, catalog_file, tmp_path):
    assert fetch(catalog_file, tmp_path / "a", "acme-wifi") == 0
    assert fetch(catalog_file, tmp_path / "b", "acme-wifi", "acme-wifi") == 0
    assert (tmp_path / "a/acme-wifi.cpio").read_bytes() == (tmp_path / "b/acme-wifi.cpio").read_bytes()
    assert (tmp_path / "a/acme-wifi.json").read_bytes() == (tmp_path / "b/acme-wifi.json").read_bytes()


def test_checksum_mismatch_discards(server, catalog_file, tmp_path, capsys):
    server.files["acme/sub/fw-b.bin"] = b"\x00\x01\x02 firmware X"  # same size, other bytes
    out, progress = tmp_path / "packs", tmp_path / "p.jsonl"
    assert fetch(catalog_file, out, "acme-wifi", progress=progress) == 1
    assert "SHA-256 mismatch" in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "checksum-mismatch"
    assert os.listdir(out) == []  # no pack, no temporary folder or partial file


def test_size_mismatch(server, catalog_file, tmp_path):
    server.files["acme/fw-a.bin"] += b"!"
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "acme-wifi", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "checksum-mismatch"


def test_plain_http_refused(cert, tmp_path, monkeypatch):
    s = FwServer(None, None, tls=False)
    try:
        cat = write_catalog(tmp_path / "c.json", make_catalog(s.template))
        progress = tmp_path / "p.jsonl"
        assert fetch(cat, tmp_path / "o", "tiny-eth", progress=progress) == 1
        assert read_events(progress)[-1]["code"] == "insecure-url"
        assert s.requests == []  # refused before any connection
    finally:
        s.close()


def test_redirect_to_http_refused(server, catalog_file, tmp_path):
    server.redirect["z.bin"] = "http://localhost:1/plain/z.bin?h=" + TAG
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "tiny-eth", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "insecure-url"


def test_untrusted_certificate(server, catalog_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "no-such-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "tiny-eth", progress=progress) == 1
    assert "certificate" in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "download-failed"
    assert len(server.requests) == 0  # the TLS handshake failed: no request was made


def test_transient_errors_are_retried(server, catalog_file, tmp_path):
    server.fail["z.bin"] = [503, 500]
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "tiny-eth", progress=progress) == 0
    assert server.requests.count("z.bin") == 3
    assert sum(e["event"] == "warning" for e in read_events(progress)) == 2


def test_gives_up_after_attempts(server, catalog_file, tmp_path):
    server.fail["z.bin"] = [503, 503, 503]
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "tiny-eth", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "download-failed"


def test_not_found_is_not_retried(server, catalog_file, tmp_path):
    del server.files["z.bin"]
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "tiny-eth", progress=progress) == 1
    assert server.requests.count("z.bin") == 1
    assert read_events(progress)[-1]["code"] == "download-failed"


def test_cancel_during_download(server, catalog_file, tmp_path):
    cancel, progress, out = tmp_path / "cancel", tmp_path / "p.jsonl", tmp_path / "o"
    server.on_request = lambda path: cancel.touch() if path == "acme/sub/fw-b.bin" else None
    assert fetch(catalog_file, out, "acme-wifi", progress=progress, extra=("--cancel-file", cancel)) == 130
    assert read_events(progress)[-1]["code"] == "cancelled"
    assert os.listdir(out) == []


def test_unknown_pack(server, catalog_file, tmp_path):
    progress = tmp_path / "p.jsonl"
    assert fetch(catalog_file, tmp_path / "o", "nope", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "invalid-argument"
    assert server.requests == []


@pytest.mark.parametrize("change,msg", [
    (lambda c: c["packs"][0]["files"][0].update(path="../etc/passwd"), "not a valid firmware path"),
    (lambda c: c["packs"][0]["files"][0].update(sha256="00"), "bad sha256"),
    (lambda c: c["packs"][0].update(id="Bad ID"), "bad pack id"),
    (lambda c: c.update(v=2), "version 1"),
    (lambda c: c["source"].update(url_template="https://x/{nope}"), "url_template"),
])
def test_bad_catalog(tmp_path, capsys, change, msg):
    cat = make_catalog("https://localhost/plain/{path}?h={tag}")
    change(cat)
    progress = tmp_path / "p.jsonl"
    assert fetch(write_catalog(tmp_path / "c.json", cat), tmp_path / "o", "tiny-eth", progress=progress) == 1
    assert msg in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "catalog-invalid"


# ---------------------------------------------------------------------------
# firmware catalog
# ---------------------------------------------------------------------------


def test_catalog_json_has_urls(tmp_path, capsys):
    cat = make_catalog("https://example.org/plain/{path}?h={tag}")
    assert run_cli("firmware", "catalog", "--catalog", write_catalog(tmp_path / "c.json", cat), "--json") == 0
    out = json.loads(capsys.readouterr().out)
    files = {f["path"]: f["url"] for p in out["packs"] for f in p["files"]}
    assert files["acme/c.bin"] == f"https://example.org/plain/real/c-1.bin?h={TAG}"
    assert files["odd/name with space.txt"] == f"https://example.org/plain/odd/name%20with%20space.txt?h={TAG}"


def test_catalog_from_dist(tmp_path, capsys):
    dist = make_bn_dist(tmp_path / "dist", make_catalog("https://example.org/{path}?h={tag}"))
    assert run_cli("firmware", "catalog", "--dist", dist) == 0
    text = capsys.readouterr().out
    assert "acme-wifi" in text and "tiny-eth" in text and TAG in text
    # a dist .zip works too
    shutil.make_archive(str(tmp_path / "d"), "zip", tmp_path, "dist")
    assert run_cli("firmware", "catalog", "--dist", tmp_path / "d.zip", "--json") == 0
    assert json.loads(capsys.readouterr().out)["source"]["tag"] == TAG


def test_catalog_missing_and_tampered(tmp_path, fake_dist, capsys):
    assert run_cli("firmware", "catalog", "--dist", fake_dist) == 1
    assert "built without beast-net" in capsys.readouterr().err
    dist = make_bn_dist(tmp_path / "dist", make_catalog("https://example.org/{path}?h={tag}"))
    p = dist / "esp/beast-net/catalog.json"
    p.write_text(p.read_text().replace(TAG, "20990102"))
    progress = tmp_path / "p.jsonl"
    assert run_cli("firmware", "fetch", "--dist", dist, "--pack", "tiny-eth", "--out", tmp_path / "o",
                   "--progress-file", progress) == 1
    assert "sha256 mismatch" in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "catalog-invalid"


# ---------------------------------------------------------------------------
# The pack format
# ---------------------------------------------------------------------------


def test_cpio_layout_is_kernel_newc():
    """Header by header: what the kernel's initramfs unpacker (and gen_init_cpio) expects."""
    files = contents("acme-wifi")
    data = build_pack(files)
    assert len(data) % 4 == 0
    pos, names = 0, []
    while True:
        assert pos % 4 == 0
        h = data[pos:pos + 110]
        assert h[:6] == b"070701"
        f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        ino, mode, uid, gid, nlink, mtime, size, dmaj, dmin, rmaj, rmin, namesize, check = f
        name = data[pos + 110:pos + 110 + namesize]
        assert name.endswith(b"\0") and b"\0" not in name[:-1]
        name = name[:-1].decode()
        assert (uid, gid, mtime, dmaj, dmin, rmaj, rmin, check) == (0,) * 8
        start = pos + 110 + namesize
        start += -start % 4
        assert not any(data[pos + 110 + namesize:start])
        if name == "TRAILER!!!":
            assert (ino, mode, nlink, size) == (0, 0, 1, 0)
            assert start == len(data)
            break
        names.append(name)
        if stat.S_ISDIR(mode):
            assert (mode, nlink, size) == (0o040755, 2, 0)
        else:
            assert (mode, nlink) == (0o100644, 1)
            assert data[start:start + size] == files[name.removeprefix("lib/firmware/")]
        assert ino == len(names)
        pos = start + size + (-size % 4)
    assert names == sorted(names, key=str.encode)
    assert names[:2] == ["lib", "lib/firmware"]
    assert "lib/firmware/acme/sub" in names and "lib/firmware/odd" in names
    for n in names:  # every parent comes first
        parent = n.rsplit("/", 1)[0]
        assert "/" not in n or names.index(parent) < names.index(n)


@pytest.mark.skipif(shutil.which("cpio") is None, reason="GNU cpio not installed")
def test_cpio_reads_with_gnu_cpio(tmp_path):
    archive = tmp_path / "p.cpio"
    archive.write_bytes(build_pack(contents("acme-wifi")))
    listing = subprocess.run(["cpio", "-itv", "-F", str(archive)], capture_output=True, text=True, check=True).stdout
    assert all(line.split()[2:4] == ["root", "root"] for line in listing.splitlines())
    out = tmp_path / "x"
    out.mkdir()
    subprocess.run(["cpio", "-idm", "--quiet", "-F", str(archive)], cwd=out, check=True, capture_output=True)
    for path, data in contents("acme-wifi").items():
        p = out / "lib/firmware" / path
        assert p.read_bytes() == data and stat.S_IMODE(p.stat().st_mode) == 0o644 and p.stat().st_mtime == 0


def test_read_newc_is_strict():
    good = build_pack({"a.bin": b"abc"})
    assert [e.name for e in read_newc(good)] == ["lib", "lib/firmware", "lib/firmware/a.bin"]
    with pytest.raises(Exception, match="070701|magic"):
        read_newc(b"070702" + good[6:])
    with pytest.raises(Exception, match="TRAILER"):
        read_newc(good[:-124])
    with pytest.raises(Exception, match="after the TRAILER"):
        read_newc(good + b"junk")
    read_newc(good + b"\0" * 512)  # zero padding after the trailer is fine
