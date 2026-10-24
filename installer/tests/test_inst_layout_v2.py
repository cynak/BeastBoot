"""Layout version 2: a 512 MiB FAT32 ESP with grub/grubenv; update keeps grubenv
and the firmware packs, and refuses a layout-1 drive."""

from __future__ import annotations

import hashlib
import shutil
import subprocess

import pytest
from conftest import (
    ODD_SIZE,
    fresh_image,
    info_json,
    mtype,
    needs_fsck,
    needs_tools,
    read_events,
    run_cli,
    sha_region,
    validate_drive,
)

from beastbooter import esp as esp_mod
from beastbooter import fatfs, plan
from beastbooter.blockio import ImageTarget
from beastbooter.esp import new_grubenv
from beastbooter.fatfs import FatVolume
from beastbooter.layout import (
    ESP_FAT_BITS,
    ESP_MARKER_PATH,
    ESP_SIZE_MIB,
    ESP_SIZE_SECTORS,
    FIRMWARE_INSTALLED_PATH,
    GRUBENV_PATH,
    LAYOUT_VERSION,
    MIN_DISK_MIB,
    SECTOR_SIZE,
)

ONESHOT_ENV = b"# GRUB Environment Block\nbb_oneshot=/isos/ubuntu.iso\n"
ONESHOT_ENV += b"#" * (1024 - len(ONESHOT_ENV))


def test_constants():
    assert (LAYOUT_VERSION, ESP_SIZE_MIB, ESP_FAT_BITS, MIN_DISK_MIB) == (2, 512, 32, 1024)
    assert ESP_SIZE_SECTORS == 512 * 2048


def esp_vol(t, img):
    j = info_json(img)
    return FatVolume(t, j["esp"]["start_lba"] * SECTOR_SIZE)


@needs_tools
@needs_fsck
@pytest.mark.parametrize("layout,fs", [("msdos", "exfat"), ("gpt", "fat32")])
def test_v2_image_validates(installed, tmp_path, layout, fs):
    img = installed(layout, fs)
    j = validate_drive(img, layout, fs, "BEASTBOOTER", tmp_path)  # sfdisk -V, fsck.fat -n on the FAT32 ESP, blkid
    assert j["layout_version"] == 2 and j["esp"]["size_lba"] == ESP_SIZE_SECTORS
    with ImageTarget(img, writable=False) as t:
        vol = esp_vol(t, img)
        assert vol.fat_bits == 32 and vol.label == "BEAST-EFI"
        assert vol.read_file(GRUBENV_PATH) == new_grubenv()
        assert "layout_version=2" in vol.read_file(ESP_MARKER_PATH).decode()
    off = j["esp"]["start_lba"] * SECTOR_SIZE
    assert mtype(img, off, "grub/grubenv").encode() == new_grubenv()
    assert run_cli("info", "--image", img) == 0


@pytest.mark.skipif(shutil.which("grub-editenv") is None, reason="grub-editenv not installed")
def test_grubenv_matches_grub_editenv(tmp_path):
    ref = tmp_path / "grubenv"
    subprocess.run(["grub-editenv", str(ref), "create"], check=True)
    assert new_grubenv() == ref.read_bytes()
    assert len(new_grubenv()) == 1024
    # grub-editenv reads and edits ours
    ours = tmp_path / "ours"
    ours.write_bytes(new_grubenv())
    subprocess.run(["grub-editenv", str(ours), "set", "bb_oneshot=/isos/x.iso"], check=True)
    out = subprocess.run(["grub-editenv", str(ours), "list"], check=True, capture_output=True, text=True).stdout
    assert out == "bb_oneshot=/isos/x.iso\n" and len(ours.read_bytes()) == 1024


def add_pack(img, name=b"pack bytes"):
    """Put a firmware pack and a used grubenv on the image's ESP (what the helper
    and `firmware install` leave there)."""
    with ImageTarget(img, writable=True) as t:
        vol = esp_vol(t, img)
        vol.write_file(GRUBENV_PATH, ONESHOT_ENV)
        vol.write_file("beast-net/firmware/acme-wifi.cpio", name * 1000)
        vol.write_file(FIRMWARE_INSTALLED_PATH, b'{"v": 1, "packs": [{"id": "acme-wifi"}]}\n')
        vol.flush()


@needs_fsck
def test_update_keeps_grubenv_and_packs(tmp_path, fake_dist, fake_dist_v2):
    img = fresh_image(tmp_path, fake_dist, "msdos", "exfat")
    add_pack(img)
    j = info_json(img)
    data_hash = sha_region(img, j["data"]["start_lba"], j["data"]["size_lba"])
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--image", img, "--dist", fake_dist_v2, "--quiet", "--progress-file", progress) == 0
    j2 = info_json(img)
    assert j2["version"] == "0.2.0" and j2["layout_version"] == 2
    assert sha_region(img, j["data"]["start_lba"], j["data"]["size_lba"]) == data_hash
    with ImageTarget(img, writable=False) as t:
        vol = esp_vol(t, img)
        assert vol.read_file(GRUBENV_PATH) == ONESHOT_ENV
        assert vol.read_file("beast-net/firmware/acme-wifi.cpio") == b"pack bytes" * 1000
        assert vol.read_file(FIRMWARE_INSTALLED_PATH).startswith(b'{"v": 1')
    from conftest import fsck
    p = fsck("fsck.fat", img, j["esp"]["start_lba"] * SECTOR_SIZE, j["esp"]["size_lba"] * SECTOR_SIZE, tmp_path)
    assert p.returncode == 0, p.stdout
    assert read_events(progress)[-1]["event"] == "done"


def test_update_replaces_a_broken_grubenv(tmp_path, fake_dist, capsys):
    img = fresh_image(tmp_path, fake_dist, "gpt", "exfat")
    with ImageTarget(img, writable=True) as t:
        esp_vol(t, img).write_file(GRUBENV_PATH, b"garbage")
    assert run_cli("update", "--image", img, "--dist", fake_dist, "--quiet") == 0
    assert "not a GRUB environment block" in capsys.readouterr().err
    with ImageTarget(img, writable=False) as t:
        assert esp_vol(t, img).read_file(GRUBENV_PATH) == new_grubenv()


def make_layout1_image(tmp_path, dist, monkeypatch):
    """A real layout-1 drive (64 MiB FAT16 ESP, 300 MB disk), as 0.1 development builds made it."""
    with monkeypatch.context() as m:
        m.setattr(plan, "ESP_SIZE_SECTORS", 64 * 2048)
        m.setattr(plan, "MIN_DISK_MIB", 256)
        m.setattr(fatfs, "ESP_FAT_BITS", 16)
        m.setattr(esp_mod, "LAYOUT_VERSION", 1)
        img = fresh_image(tmp_path, dist, "msdos", "exfat", "300000001")
    return img


def test_update_refuses_layout_1(tmp_path, fake_dist, monkeypatch, capsys):
    img = make_layout1_image(tmp_path, fake_dist, monkeypatch)
    j = info_json(img)
    assert (j["layout_version"], j["esp"]["size_lba"]) == (1, 64 * 2048)
    before = hashlib.sha256(img.read_bytes()).hexdigest()
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--image", img, "--dist", fake_dist, "--yes", "--progress-file", progress) == 1
    err = capsys.readouterr().err
    assert "reinstall needed (layout 1 -> 2)" in err
    assert read_events(progress)[-1]["code"] == "reinstall-needed"
    assert hashlib.sha256(img.read_bytes()).hexdigest() == before
    # the firmware commands refuse it the same way
    assert run_cli("firmware", "list", "--image", img, "--progress-file", progress) == 1
    assert read_events(progress)[-1]["code"] == "reinstall-needed"


def test_update_refuses_newer_layout(tmp_path, fake_dist, capsys):
    img = fresh_image(tmp_path, fake_dist, "msdos", "fat32", ODD_SIZE)
    with ImageTarget(img, writable=True) as t:
        vol = esp_vol(t, img)
        text = vol.read_file(ESP_MARKER_PATH).decode().replace("layout_version=2", "layout_version=3")
        vol.write_file(ESP_MARKER_PATH, text.encode())
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--image", img, "--dist", fake_dist, "--progress-file", progress) == 1
    assert "newer beast-booter" in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "layout-too-new"
