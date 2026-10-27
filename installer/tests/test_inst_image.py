"""install --image: partition table readback, ESP contents, data filesystems."""

import os
import uuid

import pytest

from beastbooter.blockio import ImageTarget
from beastbooter.esp import parse_marker, parse_set_lines
from beastbooter.exfatfs import ExfatVolume
from beastbooter.fatfs import FatVolume
from beastbooter.layout import (
    DEVICE_CFG_PATH,
    ESP_SIZE_SECTORS,
    GRUBENV_PATH,
    ESP_MARKER_PATH,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_DATA,
    GPT_TYPE_ESP,
    REQUIRED_ESP_FILES,
    SECTOR_SIZE,
)
from beastbooter.plan import make_plan
from conftest import (
    ODD_SIZE,
    blkid_at,
    fresh_image,
    mdir_files,
    mtype,
    needs_tools,
    run_cli,
    sfdisk_json,
)

pytestmark = needs_tools
SECTORS = int(ODD_SIZE) // SECTOR_SIZE
FS_BLKID = {"exfat": ("exfat", None), "fat32": ("vfat", "FAT32"), "ntfs": ("ntfs", None)}


@pytest.mark.parametrize("fs,mbr_type", [("exfat", "7"), ("fat32", "c"), ("ntfs", "7")])
def test_sfdisk_readback_msdos(installed, fs, mbr_type):
    img = installed("msdos", fs)
    assert os.path.getsize(img) == SECTORS * SECTOR_SIZE  # rounded down to whole sectors
    plan = make_plan(SECTORS, "msdos")
    t = sfdisk_json(img)
    assert t["label"] == "dos" and t["sectorsize"] == 512
    p1, p2 = t["partitions"]
    assert (p1["start"], p1["size"], p1["type"], p1.get("bootable")) == (2048, plan.data.size, mbr_type, True)
    assert (p2["start"], p2["size"], p2["type"]) == (plan.esp.start, ESP_SIZE_SECTORS, "ef")
    assert not p2.get("bootable", False)
    assert p1["node"].endswith("1") and p2["node"].endswith("2")


@pytest.mark.parametrize("fs", ["exfat", "fat32", "ntfs"])
def test_sfdisk_readback_gpt(installed, fs):
    img = installed("gpt", fs)
    plan = make_plan(SECTORS, "gpt")
    t = sfdisk_json(img)
    assert t["label"] == "gpt"
    assert (t["firstlba"], t["lastlba"]) == (34, SECTORS - 34)
    parts = {p["node"][-1]: p for p in t["partitions"]}
    assert set(parts) == {"1", "2", "3"}
    want = {
        "1": (2048, plan.data.size, GPT_TYPE_DATA, "BEAST-DATA"),
        "2": (plan.esp.start, ESP_SIZE_SECTORS, GPT_TYPE_ESP, "BEAST-EFI"),
        "3": (34, 2014, GPT_TYPE_BIOS_BOOT, "BEAST-BIOS"),
    }
    for n, (start, size, ptype, name) in want.items():
        p = parts[n]
        assert (p["start"], p["size"], p["type"], p["name"]) == (start, size, ptype, name)
    assert plan.esp.end <= SECTORS - 34 and (plan.esp.end + 1) % 2048 == 0


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
@pytest.mark.parametrize("fs", ["exfat", "fat32", "ntfs"])
def test_data_fs_and_device_cfg(installed, layout, fs):
    img = installed(layout, fs)
    plan = make_plan(SECTORS, layout)
    probe = blkid_at(img, plan.data.offset)
    want_type, want_version = FS_BLKID[fs]
    assert probe["TYPE"] == want_type
    if want_version:
        assert probe["VERSION"] == want_version
    assert probe["LABEL"] == "BEASTBOOTER"
    assert probe["UUID"]
    cfg = parse_set_lines(mtype(img, plan.esp.offset, DEVICE_CFG_PATH))
    assert cfg == {
        "bb_install_id": cfg["bb_install_id"],
        "bb_layout": layout,
        "bb_data_fs": fs,
        "bb_data_uuid": probe["UUID"].upper(),  # GRUB 2.14 prints these upper case
        "bb_data_uuid_linux": probe["UUID"],
        "bb_data_label": "BEASTBOOTER",
        "bb_serial": "0",
    }
    assert uuid.UUID(cfg["bb_install_id"]).version == 4
    marker = parse_marker(mtype(img, plan.esp.offset, ESP_MARKER_PATH))
    assert marker["install_id"] == cfg["bb_install_id"]
    assert marker["version"] == "0.1.0"
    if fs != "ntfs":  # prepare-windows finds the drive by its /beast-booter/ folder
        with ImageTarget(img, writable=False) as t:
            vol = (ExfatVolume if fs == "exfat" else FatVolume)(t, plan.data.offset)
            assert [(e.name, e.is_dir) for e in vol.listdir("/")] == [("beast-booter", True)]


def test_device_cfg_format(installed):
    img = installed("msdos", "exfat")
    text = mtype(img, make_plan(SECTORS, "msdos").esp.offset, DEVICE_CFG_PATH)
    lines = text.splitlines()
    assert [line.split("=")[0] for line in lines] == [
        "set bb_install_id", "set bb_layout", "set bb_data_fs", "set bb_data_uuid",
        "set bb_data_uuid_linux", "set bb_data_label", "set bb_serial",
    ]
    assert all(line.startswith("set ") and line.endswith('"') for line in lines)


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
def test_esp_contents(installed, fake_dist, layout):
    img = installed(layout, "exfat")
    off = make_plan(SECTORS, layout).esp.offset
    probe = blkid_at(img, off)
    assert (probe["TYPE"], probe["VERSION"], probe["LABEL"]) == ("vfat", "FAT32", "BEAST-EFI")
    files = mdir_files(img, off)
    dist_files = {p.relative_to(fake_dist / "esp").as_posix() for p in (fake_dist / "esp").rglob("*") if p.is_file()}
    assert set(REQUIRED_ESP_FILES) <= files
    assert files == dist_files | {DEVICE_CFG_PATH, ESP_MARKER_PATH, GRUBENV_PATH}
    for rel in ("EFI/BOOT/BOOTX64.EFI", "grub/beast/version.cfg", "grub/i386-pc/normal.mod"):
        assert mtype(img, off, rel) == (fake_dist / "esp" / rel).read_text()
    assert not any(f.lower().endswith("fbx64.efi") for f in files)


def test_image_is_sparse(installed):
    img = installed("gpt", "exfat")
    assert os.stat(img).st_blocks * 512 < 16 * 1024 * 1024  # 1049 MiB image, little allocated


def test_label_serial_and_fat_uppercase(tmp_path, fake_dist):
    img = fresh_image(tmp_path, fake_dist, "gpt", "fat32", "1G", "--label", "my usb", "--serial-console")
    plan = make_plan(1024 * 2048, "gpt")
    assert blkid_at(img, plan.data.offset)["LABEL"] == "MY USB"
    cfg = parse_set_lines(mtype(img, plan.esp.offset, DEVICE_CFG_PATH))
    assert cfg["bb_data_label"] == "MY USB" and cfg["bb_serial"] == "1"


def test_exfat_custom_label_keeps_case(tmp_path, fake_dist):
    img = fresh_image(tmp_path, fake_dist, "msdos", "exfat", "1G", "--label", "Beast-USB_1")
    assert blkid_at(img, 2048 * 512)["LABEL"] == "Beast-USB_1"


@pytest.mark.parametrize("label,fs", [("TWELVECHARSX", "fat32"), ("bad\"quote", "exfat"), ("a$b", "ntfs"),
                                      ("x" * 16, "exfat"), ("", "exfat"), (" lead", "exfat")])
def test_bad_labels_rejected(tmp_path, fake_dist, capsys, label, fs):
    img = tmp_path / "x.img"
    assert run_cli("install", "--image", img, "--size", "1G", "--fs", fs, "--label", label,
                   "--yes", "--dist", fake_dist) == 1
    assert "label" in capsys.readouterr().err
    assert not img.exists()


def test_too_small_image(tmp_path, fake_dist, capsys):
    img = tmp_path / "small.img"
    assert run_cli("install", "--image", img, "--size", "1023M", "--yes", "--dist", fake_dist) == 1
    assert "too small" in capsys.readouterr().err
    assert not img.exists()


def test_minimum_size_image(tmp_path, fake_dist):
    img = fresh_image(tmp_path, fake_dist, "gpt", "fat32", "1G")
    assert os.path.getsize(img) == 1 << 30


def test_refuses_non_regular_target(tmp_path, fake_dist, capsys):
    d = tmp_path / "adir"
    d.mkdir()
    assert run_cli("install", "--image", d, "--size", "1G", "--yes", "--dist", fake_dist) == 1
    assert "not a regular file" in capsys.readouterr().err
    assert run_cli("install", "--image", "/dev/null", "--size", "1G", "--yes", "--dist", fake_dist) == 1


def test_existing_image_needs_confirmation(tmp_path, fake_dist, capsys, monkeypatch):
    img = tmp_path / "old.img"
    img.write_bytes(b"precious")
    monkeypatch.setattr("beastbooter.commands.confirm", lambda prompt: "n")
    assert run_cli("install", "--image", img, "--size", "1G", "--dist", fake_dist) == 1
    assert img.read_bytes() == b"precious"
    monkeypatch.setattr("beastbooter.commands.confirm", lambda prompt: "y")
    assert run_cli("install", "--image", img, "--size", "1G", "--quiet", "--dist", fake_dist) == 0
    assert os.path.getsize(img) == 1 << 30


def test_overwrite_existing_image_with_yes(tmp_path, fake_dist):
    img = fresh_image(tmp_path, fake_dist, "gpt", "ntfs", "1100M")
    img2 = fresh_image(tmp_path, fake_dist, "gpt", "ntfs", "1G")  # same path, smaller
    assert img == img2 and os.path.getsize(img) == 1 << 30
    assert sfdisk_json(img)["lastlba"] == 1024 * 2048 - 34
