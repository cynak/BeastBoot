"""Room for firmware packs: the pre-check before anything is downloaded (`firmware fetch
--for-image/--for-device`), the numbers `firmware list` gives the GUI, and the one
formula (esp.fw_space) every check uses. Also: device writes report what they unmounted."""

from __future__ import annotations

import json

import pytest
from conftest import read_events, run_cli
from fakebackend import FakeBackend
from fwhelpers import PACKS, FwServer, contents, have_openssl, make_bn_dist, make_catalog, make_cert, \
    make_fetched, write_catalog

from beastbooter import commands, esp, firmware
from beastbooter.cpio import build_pack
from beastbooter.errors import BeastError
from beastbooter.fatfs import FatVolume

CATALOG = make_catalog("https://example.invalid/plain/{path}?h={tag}")
needs_tls = pytest.mark.skipif(not have_openssl(), reason="openssl is needed to make a test certificate")


@pytest.fixture(scope="module")
def bn_dist(tmp_path_factory):
    return make_bn_dist(tmp_path_factory.mktemp("bndist") / "dist", CATALOG)


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return make_cert(tmp_path_factory.mktemp("tls"))


@pytest.fixture
def server(cert, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(cert[0]))
    monkeypatch.setattr(firmware, "RETRY_DELAYS", (0.0, 0.0))
    s = FwServer(*cert)
    yield s
    s.close()


@pytest.fixture
def catalog_file(server, tmp_path):
    return write_catalog(tmp_path / "catalog.json", make_catalog(server.template))


@pytest.fixture
def image(tmp_path, bn_dist):
    img = tmp_path / "bb.img"
    assert run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet", "--dist", bn_dist) == 0
    return img


def listed(image, capsys) -> dict:
    capsys.readouterr()
    assert run_cli("firmware", "list", "--image", image, "--json") == 0
    return json.loads(capsys.readouterr().out)


def fetch_for(catalog_file, out, target_opt, target, *packs, progress):
    args = ["firmware", "fetch", "--catalog", catalog_file, "--out", out, target_opt, target,
            "--progress-file", progress]
    for p in packs:
        args += ["--pack", p]
    return run_cli(*args)


# ---------------------------------------------------------------------------
# the formula
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pid", sorted(PACKS))
def test_archive_size_from_the_catalog_is_exact(pid):
    cat = firmware.parse_catalog(json.dumps(CATALOG).encode(), "test")
    files = [(f.path, f.size) for f in cat.packs[pid].files]
    assert esp.fw_archive_size(files) == len(build_pack(contents(pid)))


def test_installed_entry_estimate_is_generous():
    cat = firmware.parse_catalog(json.dumps(CATALOG).encode(), "test")
    for pack in cat.packs.values():
        exact = len(firmware._installed_json({"v": 1, "packs": [firmware.pack_entry(pack, cat, "0" * 64)]}))
        assert exact <= esp.installed_entry_estimate(f.path for f in pack.files) < exact + 1024


def test_fw_space_counts_what_a_reinstall_replaces():
    cs = 4096
    s = esp.fw_space({"a": 10 * cs + 1, "b": cs}, free=10 * cs, cluster=cs,
                     on_drive={"A.CPIO": 3 * cs, "other.cpio": 50 * cs, "installed.json": 100}, json_size=500)
    assert s.need == (11 + 1 + 1 + 2) * cs  # whole clusters + installed.json + two directories
    assert s.reclaimed == (3 + 1) * cs  # a.cpio (any case) and the old installed.json; not other.cpio
    assert s.available == 14 * cs and not s.fits
    assert esp.fw_space({"b": cs}, free=4 * cs, cluster=cs, on_drive={}, json_size=1).fits


# ---------------------------------------------------------------------------
# firmware list: the numbers the GUI checks with
# ---------------------------------------------------------------------------


def test_list_reports_space_details(image, tmp_path, capsys):
    d = listed(image, capsys)
    assert d["esp_free"] > 0 and d["esp_cluster"] >= 512 and d["esp_label"] == "BEAST-EFI"
    assert d["installed_json_size"] == 0 and d["packs"] == []
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth")
    assert run_cli("firmware", "install", "--image", image, "--from", src, "--quiet") == 0
    d2 = listed(image, capsys)
    (p,) = d2["packs"]
    assert p["cpio_size"] == (src / "tiny-eth.cpio").stat().st_size and "missing" not in p
    assert d2["installed_json_size"] > 0 and d2["esp_free"] < d["esp_free"]


def test_install_no_space_names_the_numbers(image, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(FatVolume, "free_bytes", lambda self: 8192)
    progress = tmp_path / "i.jsonl"
    src = make_fetched(tmp_path / "f", CATALOG, "acme-wifi")
    assert run_cli("firmware", "install", "--image", image, "--from", src, "--progress-file", progress) == 1
    ev = read_events(progress)[-1]
    assert ev["code"] == "no-space"
    assert "boot partition (BEAST-EFI)" in ev["message"] and "needed, 8.0 KiB available" in ev["message"]


# ---------------------------------------------------------------------------
# fetch --for-image / --for-device: refused before anything is downloaded
# ---------------------------------------------------------------------------


@needs_tls
def test_fetch_for_image_refuses_before_any_download(server, catalog_file, image, tmp_path, monkeypatch):
    monkeypatch.setattr(FatVolume, "free_bytes", lambda self: 8192)
    out, progress = tmp_path / "packs", tmp_path / "p.jsonl"
    assert fetch_for(catalog_file, out, "--for-image", image, "acme-wifi", "tiny-eth", progress=progress) == 1
    assert server.requests == []  # not one request reached the server
    assert not out.exists() or not list(out.iterdir())
    events = read_events(progress)
    assert events[-1]["code"] == "no-space" and "acme-wifi, tiny-eth" in events[-1]["message"]
    assert "deselect packs or remove installed ones" in events[-1]["message"]
    assert [e["step"] for e in events if e["event"] == "step"] == ["check-target"]


@needs_tls
def test_fetch_for_image_counts_the_pack_it_replaces(server, catalog_file, image, tmp_path, monkeypatch, capsys):
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth")
    assert run_cli("firmware", "install", "--image", image, "--from", src, "--quiet") == 0
    cs = listed(image, capsys)["esp_cluster"]
    # tiny-eth needs 4 clusters (pack, installed.json, 2 directories); 2 are free and its old
    # pack and installed.json free 2 more: re-installing fits, a new pack doesn't.
    monkeypatch.setattr(FatVolume, "free_bytes", lambda self: 2 * cs)
    progress = tmp_path / "a.jsonl"
    assert fetch_for(catalog_file, tmp_path / "a", "--for-image", image, "acme-wifi", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "no-space" and server.requests == []
    progress = tmp_path / "t.jsonl"
    assert fetch_for(catalog_file, tmp_path / "t", "--for-image", image, "tiny-eth", progress=progress) == 0
    assert sorted(server.requests) == sorted(p for p, _src in PACKS["tiny-eth"])
    assert (tmp_path / "t" / "tiny-eth.cpio").stat().st_size == esp.fw_archive_size(
        (p, len(d)) for p, d in contents("tiny-eth").items())


@needs_tls
def test_fetch_for_image_that_is_not_a_drive(server, catalog_file, tmp_path):
    junk = tmp_path / "junk.img"
    junk.write_bytes(b"\0" * (1 << 20))
    progress = tmp_path / "p.jsonl"
    assert fetch_for(catalog_file, tmp_path / "o", "--for-image", junk, "tiny-eth", progress=progress) == 1
    assert server.requests == []


class ReadProtected(FakeBackend):
    """A drive that can't be opened without administrator rights."""

    def open_raw(self, disk, *, writable):
        if not self.elevated:
            raise BeastError(f"permission denied opening {disk.id} (administrator rights are needed)")
        return super().open_raw(disk, writable=writable)


@needs_tls
def test_fetch_for_device(server, catalog_file, bn_dist, tmp_path, monkeypatch, capsys):
    backend = ReadProtected(tmp_path)
    monkeypatch.setattr(commands, "get_backend", lambda: backend)
    assert run_cli("install", "--device", backend.disk.id, "--yes", "--quiet", "--dist", bn_dist) == 0
    backend.calls.clear()
    # with the rights: read, and refused before downloading
    monkeypatch.setattr(FatVolume, "free_bytes", lambda self: 8192)
    progress = tmp_path / "e.jsonl"
    assert fetch_for(catalog_file, tmp_path / "e", "--for-device", backend.disk.id, "tiny-eth",
                     progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "no-space" and server.requests == []
    assert ("open_raw", False) in backend.calls and "check_safe" not in backend.names()  # read only
    # without them: skipped with a warning (install checks again), and the download goes ahead
    backend.elevated = False
    capsys.readouterr()
    progress = tmp_path / "u.jsonl"
    assert fetch_for(catalog_file, tmp_path / "u", "--for-device", backend.disk.id, "tiny-eth",
                     progress=progress) == 0
    warnings = [e["message"] for e in read_events(progress) if e["event"] == "warning"]
    assert len(warnings) == 1 and "without administrator rights" in warnings[0]
    assert "firmware install` checks it" in warnings[0] and "warning: cannot read" in capsys.readouterr().err
    assert server.requests and (tmp_path / "u" / "tiny-eth.cpio").is_file()


# ---------------------------------------------------------------------------
# writing to a drive unmounts it, and says so
# ---------------------------------------------------------------------------


class MountedStick(FakeBackend):
    mounts = ["/media/user/BEASTBOOTER", "/mnt/stick"]
    busy = False

    def prepare(self, disk):
        super().prepare(disk)
        if self.busy:
            raise BeastError("cannot unmount /mnt/stick: it is busy (target is busy); close the programs using it",
                             code="busy")
        return list(self.mounts)


@pytest.fixture
def stick(tmp_path, monkeypatch):
    b = MountedStick(tmp_path)
    monkeypatch.setattr(commands, "get_backend", lambda: b)
    return b


def unmount_steps(progress):
    return [e["message"] for e in read_events(progress) if e["event"] == "step" and e["step"] == "prepare"]


def test_device_writes_report_what_was_unmounted(stick, bn_dist, tmp_path):
    progress = tmp_path / "i.jsonl"
    assert run_cli("install", "--device", stick.disk.id, "--yes", "--quiet", "--dist", bn_dist,
                   "--progress-file", progress) == 0
    msg = "Unmounted /media/user/BEASTBOOTER, /mnt/stick (on /dev/fakesdz)"
    assert unmount_steps(progress) == ["Unmounting the volumes on /dev/fakesdz", msg]
    progress = tmp_path / "f.jsonl"
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth")
    assert run_cli("firmware", "install", "--device", stick.disk.id, "--from", src, "--progress-file", progress) == 0
    assert unmount_steps(progress)[-1] == msg
    progress = tmp_path / "r.jsonl"
    assert run_cli("firmware", "remove", "--device", stick.disk.id, "--pack", "tiny-eth",
                   "--progress-file", progress) == 0
    assert unmount_steps(progress)[-1] == msg
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--device", stick.disk.id, "--yes", "--quiet", "--dist", bn_dist,
                   "--progress-file", progress) == 0
    assert unmount_steps(progress)[-1] == msg
    stick.mounts = []  # nothing was mounted: no extra line
    progress = tmp_path / "n.jsonl"
    assert run_cli("firmware", "install", "--device", stick.disk.id, "--from", src, "--progress-file", progress) == 0
    assert unmount_steps(progress) == ["Unmounting the volumes on /dev/fakesdz"]


def test_busy_volume_fails_with_code_busy(stick, bn_dist, tmp_path):
    assert run_cli("install", "--device", stick.disk.id, "--yes", "--quiet", "--dist", bn_dist) == 0
    stick.busy = True
    stick.calls.clear()
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth")
    progress = tmp_path / "f.jsonl"
    assert run_cli("firmware", "install", "--device", stick.disk.id, "--from", src, "--progress-file", progress) == 1
    ev = read_events(progress)[-1]
    assert ev["code"] == "busy" and "/mnt/stick" in ev["message"] and "close the programs" in ev["message"]
    assert ("open_raw", True) not in stick.calls  # nothing was written
