"""scripts/check_iso_sources.py, offline: local HTTPS server, throwaway CA."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import lzma
import os
import sys

import pytest

from beastnet.download import Downloader

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "scripts", "check_iso_sources.py")


@pytest.fixture(scope="module")
def cs():
    spec = importlib.util.spec_from_file_location("check_iso_sources", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_iso_sources"] = mod
    spec.loader.exec_module(mod)
    return mod


def fake_iso(n: int = 96 * 1024) -> bytes:
    b = bytearray(os.urandom(n))
    b[0x8001:0x8006] = b"CD001"
    return bytes(b)


def newc(entries: list[tuple[str, int, bytes]]) -> bytes:
    """A newc cpio archive of (name, mode, data), with the trailer."""
    out = bytearray()
    for ino, (name, mode, data) in enumerate([*entries, ("TRAILER!!!", 0, b"")], start=1):
        nb = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0]
        out += b"070701" + b"".join(b"%08X" % v for v in fields) + nb
        out += b"\0" * ((4 - len(out) % 4) % 4) + data
        out += b"\0" * ((4 - len(out) % 4) % 4)
    return bytes(out)


def test_ca_from_initrd(cs, tmp_path):
    pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    initrd = tmp_path / "initrd.img"
    initrd.write_bytes(lzma.compress(newc([("etc", 0o40755, b""), ("etc/hostname", 0o100644, b"bn\n"),
                                           ("etc/ssl/certs/ca-certificates.crt", 0o100644, pem)]),
                                     format=lzma.FORMAT_XZ))
    got = cs.ca_from_initrd(initrd, tmp_path)
    assert got is not None and got.read_bytes() == pem


def test_ca_from_initrd_ignores_a_link_and_bad_files(cs, tmp_path):
    initrd = tmp_path / "initrd.img"
    initrd.write_bytes(lzma.compress(newc([("etc/ssl/certs/ca-certificates.crt", 0o120777, b"/elsewhere")]),
                                     format=lzma.FORMAT_XZ))
    assert cs.ca_from_initrd(initrd, tmp_path) is None
    (tmp_path / "plain").write_bytes(b"not xz")
    assert cs.ca_from_initrd(tmp_path / "plain", tmp_path) is None


def downloader(certs, data_root) -> Downloader:
    return Downloader(data_root, certs.ca, timeout=5, retries=0, retry_delays=(0,))


def test_ok_with_checksum_file(cs, site, https, certs, data_root):
    digest = site.add("/iso/x.iso", fake_iso())
    site.add("/iso/SHA256SUMS", f"{digest} *x.iso\n".encode())
    site.redirects["/latest.iso"] = https.url("/iso/x.iso")
    r = cs.check(downloader(certs, data_root), {"id": "x", "url": https.url("/latest.iso"),
                                                "sha256_url": https.url("/iso/SHA256SUMS"), "min_bytes": 1000})
    assert r["ok"], r
    assert (r["sha256"], r["range_status"], r["iso9660"]) == (digest, 206, True)
    assert r["final_host"] == "127.0.0.1" and r["dest"] == "/downloads/x.iso"
    agents = {h.get("User-Agent") for _p, h in site.requests}
    assert agents == {cs.USER_AGENT}, agents  # only beast-net's own header while things work
    assert ("/iso/x.iso", "bytes=0-") in {(p, h.get("Range")) for p, h in site.requests}


def test_refused_only_for_beastnet_agent(cs, site, https, certs, data_root):
    site.add("/x.iso", fake_iso())
    site.refuse_agent["/x.iso"] = "beast-net/"
    r = cs.check(downloader(certs, data_root), {"id": "x", "url": https.url("/x.iso")})
    assert not r["ok"] and r["kind"] == "blocked" and r["status"] == 403, r
    assert r["diagnosis"] == {"refused": "ISO link", "url": https.url("/x.iso"), "beast-net": "403",
                              "others": {"curl": "206", "empty User-Agent": "206"}}


def test_refused_checksum_file_is_blamed_not_the_iso(cs, site, https, certs, data_root, capsys):
    digest = site.add("/x.iso", fake_iso())
    site.add("/SHA256SUMS", f"{digest} *x.iso\n".encode())
    site.refuse_agent["/SHA256SUMS"] = "beast-net/"
    r = cs.check(downloader(certs, data_root), {"id": "x", "url": https.url("/x.iso"),
                                                "sha256_url": https.url("/SHA256SUMS")})
    assert r["kind"] == "blocked" and r["diagnosis"]["refused"] == "checksum file", r
    assert r["diagnosis"]["url"] == https.url("/SHA256SUMS")
    cs.show(r)
    assert "the checksum file refused beast-net (403)" in capsys.readouterr().out


def test_refused_for_everyone(cs, site, https, certs, data_root):
    site.status["/x.iso"] = 403
    r = cs.check(downloader(certs, data_root), {"id": "x", "url": https.url("/x.iso")})
    assert r["kind"] == "blocked" and set(r["diagnosis"]["others"].values()) == {"403"}, r


def test_gone_and_not_an_iso(cs, site, https, certs, data_root):
    dl = downloader(certs, data_root)
    assert cs.check(dl, {"id": "x", "url": https.url("/missing.iso")})["kind"] == "gone"
    site.add("/notes.iso", b"just text\n" * 10000)
    r = cs.check(dl, {"id": "y", "url": https.url("/notes.iso")})
    assert not r["ok"] and "ISO 9660" in r["error"], r


def test_stall_after_the_headers_is_reported_not_raised(cs, site, https, certs, data_root):
    site.stall["/x.iso"] = 3  # headers, then nothing: the read times out
    dl = Downloader(data_root, certs.ca, timeout=1, retries=0, retry_delays=(0,))
    r = cs.check(dl, {"id": "x", "url": https.url("/x.iso")})
    assert not r["ok"] and r["error"].startswith("ranged read: "), r


def test_checksum_file_without_this_iso(cs, site, https, certs, data_root):
    site.add("/x.iso", fake_iso())
    site.add("/SHA256SUMS", b"0" * 64 + b" *other.iso\n")
    r = cs.check(downloader(certs, data_root), {"id": "x", "url": https.url("/x.iso"),
                                                "sha256_url": https.url("/SHA256SUMS")})
    assert not r["ok"] and r["kind"] == "checksum-mismatch", r


def test_main_exit_status_and_json(cs, site, https, certs, tmp_path, capsys):
    site.add("/x.iso", fake_iso())
    out = tmp_path / "r.json"
    assert cs.main(["--url", https.url("/x.iso"), "--ca", certs.ca, "--json", str(out)]) == 0
    assert json.loads(out.read_text())["results"][0]["ok"] is True
    site.status["/x.iso"] = 404
    assert cs.main(["--url", https.url("/x.iso"), "--ca", certs.ca]) == 1
    assert "gone" in capsys.readouterr().out
    assert cs.main(["--only", "no-such-source"]) == 2


def test_catalog_entries_are_complete(cs):
    with open(cs.CATALOG) as f:
        sources = json.load(f)["sources"]
    ids = [s["id"] for s in sources]
    assert len(ids) == len(set(ids))
    for s in sources:
        assert s["url"].startswith("https://"), s
        assert s.get("sha256_url") is None or s["sha256_url"].startswith("https://"), s
        assert isinstance(s.get("vm"), bool) and "recipe" in s and s.get("min_bytes", 0) > 0, s
    assert hashlib.sha256  # stdlib only
