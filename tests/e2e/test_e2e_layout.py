"""Drive layout (ARCHITECTURE §3, layout.py) of real installer output, and GPT boot smoke.

Static checks read the image bytes directly (no QEMU): partition table,
BIOS boot code placement and patch points, filesystems, `info --json`, and the
ESP contents (exactly the dist/ files, verbatim, plus the installer's two files).
The boot checks start the GPT image under BIOS and UEFI.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys

import pytest

from bbe2e import checks, env, images

sys.path.insert(0, str(env.INSTALLER_DIR))
from beastbooter import layout as L  # noqa: E402  (the layout contract)

sys.path.pop(0)

KINDS = [pytest.param("browse", id="msdos"), pytest.param("gpt", id="gpt")]


def esp_of(drive):
    _, parts = images.partitions(drive.path)
    return {p.index: p for p in parts}[L.ESP_PART_INDEX]


def device_cfg(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*set\s+(\w+)="?([^"]*)"?\s*(#.*)?$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


@pytest.mark.parametrize("kind", KINDS)
def test_partition_table(kind, base_drives):
    drive = base_drives(kind)
    style, parts = images.partitions(drive.path)
    assert style == drive.layout
    by = {p.index: p for p in parts}
    data, esp = by[L.DATA_PART_INDEX], by[L.ESP_PART_INDEX]
    disk_sectors = drive.path.stat().st_size // L.SECTOR_SIZE

    assert data.start_lba == L.DATA_START_LBA
    assert esp.size_lba == L.ESP_SIZE_SECTORS
    assert (esp.start_lba + esp.size_lba) % L.MIB_SECTORS == 0, "ESP end must be 1 MiB aligned"
    assert data.start_lba + data.size_lba <= esp.start_lba
    mbr, mbr_parts = images.read_mbr(drive.path)
    if style == "msdos":
        assert set(by) == {L.DATA_PART_INDEX, L.ESP_PART_INDEX}
        assert data.type == f"0x{L.MBR_TYPE_DATA[drive.fs]:02x}" and data.active
        assert esp.type == f"0x{L.MBR_TYPE_ESP:02x}"
        assert esp.start_lba + esp.size_lba <= disk_sectors
    else:
        assert set(by) == {L.DATA_PART_INDEX, L.ESP_PART_INDEX, L.BIOS_BOOT_PART_INDEX}
        bios = by[L.BIOS_BOOT_PART_INDEX]
        assert (data.type, esp.type, bios.type) == (L.GPT_TYPE_DATA, L.GPT_TYPE_ESP, L.GPT_TYPE_BIOS_BOOT)
        assert (data.name, esp.name, bios.name) == (L.GPT_NAME_DATA, L.GPT_NAME_ESP, L.GPT_NAME_BIOS_BOOT)
        assert (bios.start_lba, bios.start_lba + bios.size_lba - 1) == (L.GPT_BIOS_BOOT_START_LBA, L.GPT_BIOS_BOOT_END_LBA)
        hdr, _ = images.read_gpt(drive.path)
        assert hdr["backup_lba"] == disk_sectors - 1
        assert esp.start_lba + esp.size_lba - 1 <= hdr["last_usable"]
        pmbr = [p for p in mbr_parts if p.type == "0xee"]
        assert len(pmbr) == 1 and pmbr[0].active, "protective MBR entry must carry the active flag"

    inf = drive.info
    assert inf["layout"] == style
    assert int(inf["disk_sectors"]) == disk_sectors
    assert (int(inf["data"]["start_lba"]), int(inf["data"]["size_lba"])) == (data.start_lba, data.size_lba)
    assert (int(inf["esp"]["start_lba"]), int(inf["esp"]["size_lba"])) == (esp.start_lba, esp.size_lba)
    assert inf["data"]["fs"] == drive.fs
    assert inf["data"]["uuid"].upper() == drive.data_uuid


@pytest.mark.parametrize("kind", KINDS)
def test_bios_boot_code(kind, base_drives, dist_dir):
    drive = base_drives(kind)
    boot = (dist_dir / L.DIST_BOOT_IMG).read_bytes()
    core = (dist_dir / L.DIST_CORE_IMG).read_bytes()
    core_lba = L.MBR_CORE_LBA if drive.layout == "msdos" else L.GPT_CORE_LBA
    sectors = math.ceil(len(core) / L.SECTOR_SIZE)
    with open(drive.path, "rb") as f:
        mbr = f.read(512)
        f.seek(core_lba * L.SECTOR_SIZE)
        on_disk = f.read(sectors * L.SECTOR_SIZE)
    assert mbr[510:512] == b"\x55\xaa"
    assert struct.unpack_from("<Q", mbr, L.BOOT_KERNEL_SECTOR_OFFSET)[0] == core_lba
    assert mbr[L.BOOT_DRIVE_CHECK_OFFSET : L.BOOT_DRIVE_CHECK_OFFSET + 2] == b"\x90\x90"
    patched = set(range(L.BOOT_KERNEL_SECTOR_OFFSET, L.BOOT_KERNEL_SECTOR_OFFSET + 8)) | {
        L.BOOT_DRIVE_CHECK_OFFSET, L.BOOT_DRIVE_CHECK_OFFSET + 1}
    diff = [i for i in range(L.BOOT_IMG_CODE_LEN) if i not in patched and mbr[i] != boot[i]]
    assert not diff, f"boot.img code differs from dist at offsets {diff[:10]}"
    start, count, seg = struct.unpack_from("<QHH", on_disk, L.CORE_BLOCKLIST_OFFSET)
    assert (start, count, seg) == (core_lba + 1, sectors - 1, L.CORE_BLOCKLIST_SEGMENT)
    blk = range(L.CORE_BLOCKLIST_OFFSET, L.CORE_BLOCKLIST_OFFSET + 12)
    diff = [i for i in range(len(core)) if i not in blk and on_disk[i] != core[i]]
    assert not diff, f"core.img on disk differs from dist at offsets {diff[:10]}"


@pytest.mark.parametrize("kind", KINDS)
def test_filesystems_and_esp_contents(kind, base_drives, dist_dir):
    drive = base_drives(kind)
    esp = esp_of(drive)
    fs, _ = images.volume_id(drive.path, drive.data_offset)
    assert fs == drive.fs
    esp_fs, _ = images.volume_id(drive.path, esp.offset)
    assert esp_fs == f"fat{L.ESP_FAT_BITS}"

    w = images.FatWriter(drive.path, esp.offset)
    listed = images.env.run(["mdir", "-/", "-b", "-i", w.spec, "::/"]).stdout.split()
    on_esp = {p[3:].lower() for p in listed if p.startswith("::/") and not p.endswith("/")}
    manifest = json.loads((dist_dir / L.DIST_MANIFEST).read_text())
    prefix = L.DIST_ESP_DIR + "/"
    expected = {k[len(prefix):].lower(): v for k, v in manifest["files"].items() if k.startswith(prefix)}
    installer_files = {L.DEVICE_CFG_PATH.lower(), L.ESP_MARKER_PATH.lower(), L.GRUBENV_PATH.lower()}
    assert installer_files <= on_esp, f"missing installer files: {installer_files - on_esp}"
    unexplained = on_esp - set(expected) - installer_files
    assert not unexplained, f"files on the ESP that are not in dist/manifest.json: {sorted(unexplained)}"
    missing = set(expected) - on_esp
    assert not missing, f"dist files missing from the ESP: {sorted(missing)}"
    assert "efi/boot/fbx64.efi" not in on_esp, "no fallback loader on the ESP (ARCHITECTURE §4)"
    for rel, meta in expected.items():
        data = w.read("/" + rel)
        assert hashlib.sha256(data).hexdigest() == meta["sha256"], f"{rel} differs from dist/manifest.json"

    cfg = device_cfg(w.read("/" + L.DEVICE_CFG_PATH).decode())
    assert cfg.get("bb_layout") == drive.layout
    assert cfg.get("bb_data_fs") == drive.fs
    assert cfg.get("bb_data_uuid_linux") == drive.data_uuid
    assert cfg.get("bb_data_uuid", "").upper() == drive.data_uuid
    assert cfg.get("bb_data_label") == L.DATA_LABEL_DEFAULT
    assert cfg.get("bb_serial") == "1"
    assert cfg.get("bb_install_id") and cfg["bb_install_id"] in w.read("/" + L.ESP_MARKER_PATH).decode()


GPT_MODES = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
             pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]


@pytest.mark.slow
@pytest.mark.parametrize("mode", GPT_MODES)
def test_gpt_boots(mode, make_drive, vm_factory):
    drive = make_drive("gpt", images.user_config())
    vm = vm_factory(mode, drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform=checks.PLATFORM[mode], sb=0, fs="fat32",
                       **checks.expected_devs("gpt"))
    dirs, isos = checks.listing(vm, "/")
    assert (dirs, isos) == (["/linux"], ["/top.iso"])
