"""firmware install / remove / list on images and through the fake device backend."""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import fsck, info_json, needs_fsck, read_events, run_cli, sha_region, step_ids
from fakebackend import FakeBackend
from fwhelpers import TAG, contents, make_bn_dist, make_catalog, make_fetched

from beastbooter import commands, firmware
from beastbooter.blockio import ImageTarget
from beastbooter.cpio import FILE_MODE, build_pack, header, trailer
from beastbooter.fatfs import FatVolume
from beastbooter.layout import FIRMWARE_INSTALLED_PATH, SECTOR_SIZE

CATALOG = make_catalog("https://example.invalid/plain/{path}?h={tag}")


@pytest.fixture(scope="module")
def bn_dist(tmp_path_factory):
    return make_bn_dist(tmp_path_factory.mktemp("bndist") / "dist", CATALOG)


@pytest.fixture
def image(tmp_path, bn_dist):
    img = tmp_path / "bb.img"
    assert run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet", "--dist", bn_dist) == 0
    return img


@pytest.fixture(scope="module")
def packs(tmp_path_factory):
    d = tmp_path_factory.mktemp("fetched")
    make_fetched(d / "both", CATALOG, "acme-wifi")
    make_fetched(d / "both", CATALOG, "tiny-eth")
    make_fetched(d / "tiny", CATALOG, "tiny-eth")
    return d


def esp_read(img, path):
    j = info_json(img)
    with ImageTarget(img, writable=False) as t:
        vol = FatVolume(t, j["esp"]["start_lba"] * SECTOR_SIZE)
        return vol.read_file(path) if vol.exists(path) else None


def outside_esp_hash(img):
    j = info_json(img)
    return sha_region(img, 0, j["esp"]["start_lba"])  # boot area + partition 1


def fw(*args, progress=None):
    extra = ("--progress-file", progress) if progress else ()
    return run_cli("firmware", *args, *extra)


@needs_fsck
def test_install_list_remove_on_image(image, packs, tmp_path, capsys):
    before = outside_esp_hash(image)
    progress = tmp_path / "i.jsonl"
    assert fw("install", "--image", image, "--from", packs / "both", progress=progress) == 0
    events = read_events(progress)
    assert events[0] == {"v": 1, "event": "start", "action": "firmware-install", "target": str(image)}
    assert step_ids(events) == ["check-target", "verify-packs", "write-firmware", "flush", "verify-write"]
    done = events[-1]["info"]
    assert done["catalog"]["source"] == "drive" and done["catalog"]["tag"] == TAG
    assert [p["id"] for p in done["installed"]["packs"]] == ["acme-wifi", "tiny-eth"]
    for pid in ("acme-wifi", "tiny-eth"):
        assert esp_read(image, f"beast-net/firmware/{pid}.cpio") == (packs / "both" / f"{pid}.cpio").read_bytes()
    installed = json.loads(esp_read(image, FIRMWARE_INSTALLED_PATH))
    assert installed["v"] == 1 and [p["id"] for p in installed["packs"]] == ["acme-wifi", "tiny-eth"]
    entry = installed["packs"][0]
    assert entry["catalog_tag"] == TAG
    assert entry["cpio_sha256"] == hashlib.sha256((packs / "both/acme-wifi.cpio").read_bytes()).hexdigest()
    assert {f["path"] for f in entry["files"]} == set(contents("acme-wifi"))
    assert outside_esp_hash(image) == before  # only the ESP was written
    j = info_json(image)
    p = fsck("fsck.fat", image, j["esp"]["start_lba"] * SECTOR_SIZE, j["esp"]["size_lba"] * SECTOR_SIZE, tmp_path)
    assert p.returncode == 0, p.stdout

    capsys.readouterr()
    assert fw("list", "--image", image, "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert [p["id"] for p in listed["packs"]] == ["acme-wifi", "tiny-eth"] and listed["unlisted"] == []
    assert listed["catalog_tag"] == TAG and not any(p.get("missing") for p in listed["packs"])

    # reinstalling a pack replaces it
    assert fw("install", "--image", image, "--from", packs / "tiny") == 0

    progress = tmp_path / "r.jsonl"
    assert fw("remove", "--image", image, "--pack", "acme-wifi", progress=progress) == 0
    assert read_events(progress)[-1]["info"]["installed"]["packs"][0]["id"] == "tiny-eth"
    assert esp_read(image, "beast-net/firmware/acme-wifi.cpio") is None
    assert [p["id"] for p in json.loads(esp_read(image, FIRMWARE_INSTALLED_PATH))["packs"]] == ["tiny-eth"]
    assert outside_esp_hash(image) == before
    progress = tmp_path / "l.jsonl"
    assert fw("list", "--image", image, progress=progress) == 0
    ev = read_events(progress)
    assert ev[0]["action"] == "firmware-list" and ev[-1]["info"]["installed"]["packs"][0]["id"] == "tiny-eth"


def test_remove_not_installed(image, tmp_path):
    progress = tmp_path / "r.jsonl"
    assert fw("remove", "--image", image, "--pack", "acme-wifi", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "invalid-argument"


def refused(image, src, tmp_path, code, capsys=None, text=None):
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    progress = tmp_path / "x.jsonl"
    assert fw("install", "--image", image, "--from", src, progress=progress) == 1
    assert read_events(progress)[-1]["code"] == code
    if capsys is not None:
        assert text in capsys.readouterr().err
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before


def test_tampered_file_refused(image, tmp_path, capsys):
    files = contents("acme-wifi")
    files["acme/fw-a.bin"] = b"firmware B " * 300  # same size, other contents
    src = make_fetched(tmp_path / "f", CATALOG, "acme-wifi", files=files)  # json matches the tampered cpio
    refused(image, src, tmp_path, "checksum-mismatch", capsys, "SHA-256 mismatch with the catalog")


def test_cpio_not_matching_json(image, tmp_path, capsys):
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth")
    (src / "tiny-eth.cpio").write_bytes(build_pack(contents("acme-wifi")))
    refused(image, src, tmp_path, "pack-invalid", capsys, "does not match the SHA-256")


def test_extra_and_missing_files_refused(image, tmp_path, capsys):
    files = dict(contents("tiny-eth"), **{"evil.bin": b"x"})
    refused(image, make_fetched(tmp_path / "a", CATALOG, "tiny-eth", files=files), tmp_path, "pack-invalid",
            capsys, "not in the catalog: evil.bin")
    files = contents("tiny-eth")
    del files["z.bin"]
    refused(image, make_fetched(tmp_path / "b", CATALOG, "tiny-eth", files=files), tmp_path, "pack-invalid",
            capsys, "missing: z.bin")


def test_non_canonical_cpio_refused(image, tmp_path, capsys):
    files = contents("tiny-eth")
    data = b""  # right files, but no directory entries and a different inode order
    for ino, (path, content) in enumerate(sorted(files.items()), start=7):
        data += header(f"lib/firmware/{path}", ino=ino, mode=FILE_MODE, nlink=1, filesize=len(content))
        data += content + b"\0" * (-len(content) % 4)
    data += trailer()
    src = make_fetched(tmp_path / "f", CATALOG, "tiny-eth", cpio=data)
    refused(image, src, tmp_path, "pack-invalid", capsys, "canonical")


def test_catalog_tag_mismatch_refused(image, tmp_path, capsys):
    other = make_catalog(CATALOG["source"]["url_template"], tag="20990202")
    src = make_fetched(tmp_path / "f", other, "tiny-eth")
    refused(image, src, tmp_path, "pack-mismatch", capsys, "fetched for linux-firmware tag 20990202")
    other = make_catalog(CATALOG["source"]["url_template"], kernel="1.2.3")
    refused(image, make_fetched(tmp_path / "g", other, "tiny-eth"), tmp_path, "pack-mismatch")


def test_esp_space_refusal(image, packs, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(FatVolume, "free_bytes", lambda self: 8192)
    refused(image, packs / "both", tmp_path, "no-space", capsys, "not enough space on the boot partition")


def test_empty_pack_folder(image, tmp_path):
    (tmp_path / "empty").mkdir()
    refused(image, tmp_path / "empty", tmp_path, "invalid-argument")


def test_drive_without_catalog_uses_dist(tmp_path, fake_dist, bn_dist, packs, capsys):
    img = tmp_path / "old.img"  # boot files without beast-net
    assert run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet", "--dist", fake_dist) == 0
    progress = tmp_path / "i.jsonl"
    assert fw("install", "--image", img, "--from", packs / "tiny", "--dist", fake_dist, progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "catalog-missing"
    assert fw("install", "--image", img, "--from", packs / "tiny", "--dist", bn_dist, progress=progress) == 0
    err = capsys.readouterr().err
    assert "no firmware catalog" in err and "no beast-net helper" in err
    assert read_events(progress)[-1]["info"]["catalog"]["source"] == "dist"


def test_update_keeps_installed_packs(image, packs, bn_dist, tmp_path, capsys):
    assert fw("install", "--image", image, "--from", packs / "both") == 0
    before = esp_read(image, FIRMWARE_INSTALLED_PATH)
    capsys.readouterr()
    assert run_cli("update", "--image", image, "--dist", bn_dist, "--quiet") == 0
    assert "warning" not in capsys.readouterr().err  # the same catalog: nothing stale
    assert esp_read(image, FIRMWARE_INSTALLED_PATH) == before
    assert esp_read(image, "beast-net/firmware/acme-wifi.cpio") == (packs / "both/acme-wifi.cpio").read_bytes()
    assert esp_read(image, "beast-net/catalog.json") is not None
    assert fw("list", "--image", image, "--json") == 0
    assert not any(p.get("stale") for p in json.loads(capsys.readouterr().out)["packs"])


NEW_KERNEL = "9.9.10-2-generic"


def new_kernel_catalog() -> dict:
    """The catalog of boot files whose helper moved to another kernel with the same
    linux-firmware tag (0.1.1 -> 0.1.2): acme-wifi's drivers ask for other files."""
    cat = make_catalog(CATALOG["source"]["url_template"], kernel=NEW_KERNEL)
    acme = next(p for p in cat["packs"] if p["id"] == "acme-wifi")
    acme["files"] = [f for f in acme["files"] if f["path"] != "odd/name with space.txt"]
    acme["size"] = sum(f["size"] for f in acme["files"])
    return cat


def test_update_flags_packs_made_for_another_kernel(image, packs, tmp_path, capsys):
    assert fw("install", "--image", image, "--from", packs / "both") == 0
    new = new_kernel_catalog()
    assert new["source"]["tag"] == TAG  # only the kernel and the file lists differ
    dist2 = make_bn_dist(tmp_path / "dist2", new)
    capsys.readouterr()
    assert run_cli("update", "--image", image, "--dist", dist2, "--quiet") == 0
    err = capsys.readouterr().err
    assert ("firmware packs acme-wifi (made for kernel 9.9.9-1-generic), tiny-eth (made for kernel "
            "9.9.9-1-generic) do not match the new helper") in err
    assert f"kernel {NEW_KERNEL}" in err and "Reinstall them" in err and "firmware install" in err
    assert esp_read(image, "beast-net/firmware/acme-wifi.cpio") == (packs / "both/acme-wifi.cpio").read_bytes()

    assert fw("list", "--image", image, "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["kernel"] == NEW_KERNEL
    assert {p["id"]: p.get("stale_reason") for p in listed["packs"] if p.get("stale")} == {
        "acme-wifi": "made for kernel 9.9.9-1-generic", "tiny-eth": "made for kernel 9.9.9-1-generic"}
    assert fw("list", "--image", image) == 0
    out = capsys.readouterr().out
    assert "(STALE: made for kernel 9.9.9-1-generic; reinstall it)" in out and "replaces it" in out

    # reinstalling, fetched with the new catalog, replaces the pack made for the old kernel
    src = make_fetched(tmp_path / "new", new, "acme-wifi",
                       files={k: v for k, v in contents("acme-wifi").items() if k != "odd/name with space.txt"})
    assert fw("install", "--image", image, "--from", src) == 0
    assert esp_read(image, "beast-net/firmware/acme-wifi.cpio") == (src / "acme-wifi.cpio").read_bytes()
    entry = next(p for p in json.loads(esp_read(image, FIRMWARE_INSTALLED_PATH))["packs"] if p["id"] == "acme-wifi")
    assert entry["kernel"] == NEW_KERNEL and "odd/name with space.txt" not in {f["path"] for f in entry["files"]}
    capsys.readouterr()
    assert fw("list", "--image", image, "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert [p["id"] for p in listed["packs"] if p.get("stale")] == ["tiny-eth"]


def test_stale_reason():
    cat = firmware.parse_catalog(json.dumps(CATALOG).encode(), "test")
    entry = firmware.pack_entry(cat.packs["acme-wifi"], cat, "0" * 64)
    assert firmware.stale_reason(entry, cat) is None
    assert firmware.stale_reason({**entry, "kernel": ""}, cat) is None  # an entry without a kernel: by its files
    assert firmware.stale_reason({**entry, "kernel": "1.0"}, cat) == "made for kernel 1.0"
    assert firmware.stale_reason({**entry, "catalog_tag": "20000101"}, cat) == "made for linux-firmware tag 20000101"
    other = {**entry, "files": entry["files"][1:]}  # same tag and kernel, other files
    assert firmware.stale_reason(other, cat) == "made for other firmware files than the catalog lists"
    assert firmware.stale_reason({**entry, "id": "gone-pack"}, cat) == "not in the drive's catalog"
    assert firmware.stale_hint("not in the drive's catalog") == "remove it"
    # a valid-JSON but malformed installed.json (mixed types) is "other files", never a crash
    bad = {**entry, "files": [{"path": None}, {"path": "a", "size": "x"}, "junk"]}
    assert firmware.stale_reason(bad, cat) == "made for other firmware files than the catalog lists"


# ---------------------------------------------------------------------------
# Devices (FakeBackend: a file posing as a USB stick)
# ---------------------------------------------------------------------------


@pytest.fixture
def backend(tmp_path, monkeypatch):
    b = FakeBackend(tmp_path)
    monkeypatch.setattr(commands, "get_backend", lambda: b)
    return b


def test_device_install_list_remove(backend, bn_dist, packs, tmp_path, capsys):
    assert run_cli("install", "--device", backend.disk.id, "--yes", "--quiet", "--dist", bn_dist) == 0
    img = backend.disk_file
    before = outside_esp_hash(img)
    backend.calls.clear()
    progress = tmp_path / "d.jsonl"
    # no --yes, stdin is not a terminal: the GUI's command line must not prompt
    assert fw("install", "--device", backend.disk.id, "--from", packs / "both", progress=progress) == 0
    names = backend.names()
    assert names.index("check_safe") < names.index("prepare") < names.index("rescan")
    assert backend.calls.count(("open_raw", True)) == 1
    assert step_ids(read_events(progress)) == ["check-target", "verify-packs", "prepare", "write-firmware",
                                                "flush", "rescan", "verify-write"]
    assert outside_esp_hash(img) == before
    capsys.readouterr()
    assert fw("list", "--device", "fakesdz", "--json") == 0
    assert [p["id"] for p in json.loads(capsys.readouterr().out)["packs"]] == ["acme-wifi", "tiny-eth"]
    assert fw("remove", "--device", backend.disk.id, "--pack", "tiny-eth") == 0
    assert [p["id"] for p in json.loads(esp_read(img, FIRMWARE_INSTALLED_PATH))["packs"]] == ["acme-wifi"]
    assert outside_esp_hash(img) == before


def test_device_refused_when_unsafe(backend, bn_dist, packs, tmp_path):
    assert run_cli("install", "--device", backend.disk.id, "--yes", "--quiet", "--dist", bn_dist) == 0
    backend.set_disk(removable=False, bus="sata")
    backend.calls.clear()
    progress = tmp_path / "d.jsonl"
    assert fw("install", "--device", backend.disk.id, "--from", packs / "tiny", progress=progress) == 1
    assert read_events(progress)[-1]["code"] == "target-refused"
    assert "open_raw" not in backend.names() and "prepare" not in backend.names()
    assert fw("install", "--device", backend.disk.id, "--from", packs / "tiny", "--allow-fixed-disk") == 0
