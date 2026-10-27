"""update keeps partition 1 and device.cfg; info --json schema; partition table parser."""

import json
import subprocess

import pytest

from beastbooter.commands import _reconcile_config
from beastbooter.disk import read_partition_table
from beastbooter.errors import BeastError
from beastbooter.esp import DeviceConfig, parse_marker, parse_set_lines
from beastbooter.layout import DEVICE_CFG_PATH, ESP_MARKER_PATH, ESP_SIZE_SECTORS, LAYOUT_VERSION, SECTOR_SIZE
from beastbooter.plan import make_plan
from beastbooter.blockio import ImageTarget
from beastbooter.target import GuardedTarget
from beastbooter.util import Reporter
from conftest import (
    MTOOLS_ENV,
    blkid_at,
    fresh_image,
    info_json,
    mtype,
    needs_tools,
    run_cli,
    sfdisk_json,
    sha_region,
)


def esp_offset(img):
    return info_json(img)["esp"]["start_lba"] * SECTOR_SIZE


@needs_tools
@pytest.mark.parametrize("layout,fs", [("msdos", "fat32"), ("gpt", "exfat"), ("gpt", "ntfs")])
def test_update_keeps_data_and_device_cfg(tmp_path, fake_dist, fake_dist_v2, layout, fs):
    img = fresh_image(tmp_path, fake_dist, layout, fs)
    before = info_json(img)
    d = before["data"]
    if fs == "fat32":  # put a user file on partition 1
        user = tmp_path / "linux.iso"
        user.write_bytes(b"ISO" * 1000)
        subprocess.run(["mcopy", "-i", f"{img}@@{d['start_lba'] * 512}", str(user), "::/linux.iso"],
                       check=True, env=MTOOLS_ENV)
    data_hash = sha_region(img, d["start_lba"], d["size_lba"])
    off = esp_offset(img)
    cfg_before = mtype(img, off, DEVICE_CFG_PATH)
    esp_uuid = blkid_at(img, off)["UUID"]
    table_before = sfdisk_json(img)

    assert run_cli("update", "--image", img, "--quiet", "--dist", fake_dist_v2) == 0

    assert sha_region(img, d["start_lba"], d["size_lba"]) == data_hash
    assert mtype(img, off, DEVICE_CFG_PATH) == cfg_before
    assert sfdisk_json(img) == table_before
    assert blkid_at(img, off)["UUID"] == esp_uuid  # ESP volume id kept
    assert mtype(img, off, "EFI/BOOT/grubx64.efi") == (fake_dist_v2 / "esp/EFI/BOOT/grubx64.efi").read_text()
    after = info_json(img)
    assert after["version"] == "0.2.0"
    assert {k: v for k, v in after.items() if k != "version"} == {k: v for k, v in before.items() if k != "version"}
    marker = parse_marker(mtype(img, off, ESP_MARKER_PATH))
    assert marker["install_id"] == before["install_id"] and marker["version"] == "0.2.0"
    if fs == "fat32":
        out = subprocess.run(["mtype", "-i", f"{img}@@{d['start_lba'] * 512}", "::/linux.iso"],
                             check=True, env=MTOOLS_ENV, capture_output=True).stdout
        assert out == b"ISO" * 1000


@needs_tools
def test_update_rewrites_boot_code(tmp_path, fake_dist, fake_dist_v2):
    img = fresh_image(tmp_path, fake_dist, "gpt", "exfat")
    with open(img, "r+b") as f:  # clobber the boot code
        f.write(b"\0" * 440)
        f.seek(0x1BE)
        f.write(b"\0")
    assert run_cli("update", "--image", img, "--quiet", "--dist", fake_dist_v2) == 0
    raw = img.read_bytes()[:512]
    assert raw[0x5C:0x64] == (34).to_bytes(8, "little") and raw[0x1BE] == 0x80
    assert info_json(img)["bios_core_lba"] == 34


@needs_tools
def test_update_refuses_non_beast_drive(tmp_path, fake_dist, fake_dist_v2, capsys):
    img = fresh_image(tmp_path, fake_dist, "msdos", "exfat")
    off = esp_offset(img)
    subprocess.run(["mdel", "-i", f"{img}@@{off}", f"::/{ESP_MARKER_PATH}"], check=True, env=MTOOLS_ENV)
    before = img.read_bytes()
    assert run_cli("update", "--image", img, "--dist", fake_dist_v2) == 1
    assert "not a beast-boot drive" in capsys.readouterr().err
    assert img.read_bytes() == before
    assert run_cli("info", "--image", img, "--json") == 1


@needs_tools
def test_update_refuses_layout_mismatch(tmp_path, fake_dist, fake_dist_v2, capsys):
    img = fresh_image(tmp_path, fake_dist, "msdos", "exfat")
    with open(img, "ab") as f:  # disk grew: the ESP is no longer where we would put it
        f.truncate(f.tell() + 8 * 1024 * 1024)
    before = img.read_bytes()
    assert run_cli("update", "--image", img, "--dist", fake_dist_v2) == 1
    assert "does not match" in capsys.readouterr().err
    assert img.read_bytes() == before


@needs_tools
def test_update_blank_image(tmp_path, fake_dist_v2, capsys):
    img = tmp_path / "blank.img"
    img.write_bytes(b"\0" * (1 << 20))
    assert run_cli("update", "--image", img, "--dist", fake_dist_v2) == 1
    err = capsys.readouterr().err
    assert "not a beast-boot drive" in err and "Traceback" not in err


def test_reconcile_follows_reformatted_partition():
    old = DeviceConfig("id-1", "msdos", "exfat", "AAAA-BBBB", "AAAA-BBBB", "BEASTBOOTER", True)
    rep = Reporter(quiet=True)
    same = _reconcile_config(old, {"TYPE": "exfat", "UUID": "AAAA-BBBB", "LABEL": "BEASTBOOTER"}, {}, "msdos", rep)
    assert same == old
    new = _reconcile_config(old, {"TYPE": "vfat", "VERSION": "FAT32", "UUID": "CCCC-DDDD", "LABEL": "NEW"}, {}, "msdos", rep)
    assert (new.data_fs, new.data_uuid, new.data_uuid_linux, new.data_label) == ("fat32", "CCCC-DDDD", "CCCC-DDDD", "NEW")
    assert (new.install_id, new.serial) == ("id-1", True)
    assert _reconcile_config(old, {}, {}, "msdos", rep) == old  # unknown fs: keep values
    made = _reconcile_config(None, {"TYPE": "ntfs", "UUID": "0123456789ABCDEF"}, {"install_id": "m-1"}, "gpt", rep)
    assert (made.install_id, made.layout, made.data_fs) == ("m-1", "gpt", "ntfs")
    with pytest.raises(BeastError):
        _reconcile_config(None, {}, {}, "gpt", rep)


def test_write_guard(tmp_path):
    p = tmp_path / "g.img"
    p.write_bytes(b"\0" * 4096)
    with GuardedTarget(ImageTarget(str(p), writable=True), [(0, 1024), (2048, 3072)]) as t:
        t.write(0, b"x" * 1024)
        t.write(2048, b"y" * 1024)
        with pytest.raises(AssertionError):
            t.write(1000, b"x" * 100)  # crosses the end of the first area
        with pytest.raises(AssertionError):
            t.write(1024, b"z")  # between the areas
    assert p.read_bytes() == b"x" * 1024 + b"\0" * 1024 + b"y" * 1024 + b"\0" * 1024


def test_device_cfg_roundtrip_escaping():
    cfg = DeviceConfig("i", "gpt", "ntfs", "U", "U", 'we"ird $label\\', False)
    text = cfg.render()
    assert r'set bb_data_label="we\"ird \$label\\"' in text
    assert DeviceConfig.parse(text) == cfg
    assert parse_set_lines('set bb_version=0.1.0  # c\nset x="a b"\n') == {"bb_version": "0.1.0", "x": "a b"}


# --------------------------------------------------------------------------- info


@needs_tools
@pytest.mark.parametrize("layout,fs", [("msdos", "exfat"), ("gpt", "fat32"), ("msdos", "ntfs")])
def test_info_json_schema(installed, layout, fs):
    img = installed(layout, fs)
    j = info_json(img)
    assert list(j) == ["layout", "layout_version", "version", "build_id", "install_id", "disk_sectors", "bios_core_lba", "data", "esp"]
    assert list(j["data"]) == ["index", "start_lba", "size_lba", "fs", "uuid", "label"]
    assert list(j["esp"]) == ["index", "start_lba", "size_lba"]
    plan = make_plan(j["disk_sectors"], layout)
    assert j["layout"] == layout and j["version"] == "0.1.0" and j["layout_version"] == LAYOUT_VERSION == 2
    assert j["disk_sectors"] == 1100000001 // 512
    assert j["bios_core_lba"] == (1 if layout == "msdos" else 34)
    assert j["data"] == {"index": 1, "start_lba": 2048, "size_lba": plan.data.size, "fs": fs,
                         "uuid": blkid_at(img, 2048 * 512)["UUID"], "label": "BEASTBOOTER"}
    assert j["esp"] == {"index": 2, "start_lba": plan.esp.start, "size_lba": ESP_SIZE_SECTORS}
    cfg = parse_set_lines(mtype(img, plan.esp.offset, DEVICE_CFG_PATH))
    assert j["install_id"] == cfg["bb_install_id"]
    for k in ("disk_sectors", "bios_core_lba"):
        assert isinstance(j[k], int)


@needs_tools
def test_info_human(installed, capsys):
    img = installed("gpt", "exfat")
    assert run_cli("info", "--image", img) == 0
    out = capsys.readouterr().out
    assert "layout:      gpt" in out and "BIOS core:   LBA 34" in out and "exfat" in out


def test_info_missing_and_garbage(tmp_path, capsys):
    assert run_cli("info", "--image", tmp_path / "nope.img", "--json") == 1
    assert "does not exist" in capsys.readouterr().err
    g = tmp_path / "g.img"
    g.write_bytes(b"\xff" * 4096)
    assert run_cli("info", "--image", g, "--json") == 1
    err = capsys.readouterr().err
    assert err.startswith("beast-boot: error:") and "Traceback" not in err


@needs_tools
@pytest.mark.parametrize("layout", ["msdos", "gpt"])
def test_python_parser_matches_sfdisk(installed, layout):
    img = installed(layout, "ntfs")
    with ImageTarget(str(img), writable=False) as t:
        table = read_partition_table(t.read, t.size // SECTOR_SIZE)
    sf = sfdisk_json(img)
    assert table.label == ("msdos" if sf["label"] == "dos" else "gpt")
    for p in sf["partitions"]:
        e = table.entries[int(p["node"][-1])]
        assert (e.start, e.size) == (p["start"], p["size"])
        if layout == "gpt":
            assert (e.type, e.name) == (p["type"], p["name"])
        else:
            assert int(e.type, 16) == int(p["type"], 16) and e.bootable == p.get("bootable", False)
    if layout == "gpt":
        assert table.pmbr_active and table.disk_id == sf["id"]


@needs_tools
def test_gpt_crc_checked(tmp_path, fake_dist, capsys):
    img = fresh_image(tmp_path, fake_dist, "gpt", "exfat", "1G")
    with open(img, "r+b") as f:
        f.seek(2 * 512 + 56)  # inside the first partition entry's name
        f.write(b"X")
    assert run_cli("info", "--image", img, "--json") == 1
    assert "checksum" in capsys.readouterr().err


@needs_tools
def test_info_cli_subprocess_json(installed):
    img = installed("msdos", "fat32")
    out = subprocess.run(["python3", "-m", "beastbooter", "info", "--image", str(img), "--json"],
                         capture_output=True, text=True, check=True,
                         env={**MTOOLS_ENV, "PYTHONPATH": str(__import__("conftest").HERE.parent)})
    assert json.loads(out.stdout)["data"]["fs"] == "fat32"
    assert out.stderr == ""
