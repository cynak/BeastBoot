"""Pure-Python MBR / GPT writer (parttable.py), checked with independent tools.

sfdisk -J / -V, sgdisk -v and (when udisks allows it) the Linux kernel read the
tables we write; the result must equal what today's sfdisk path produces.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import time
import uuid
import zlib
from pathlib import Path

import pytest

from beastbooter import parttable
from beastbooter.bootcode import boot_writes
from beastbooter.disk import read_partition_table
from beastbooter.errors import BeastError
from beastbooter.layout import (
    BOOT_IMG_CODE_LEN,
    GPT_NAME_BIOS_BOOT,
    GPT_NAME_DATA,
    GPT_NAME_ESP,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_DATA,
    GPT_TYPE_ESP,
    MBR_TYPE_DATA,
    MBR_TYPE_ESP,
    MIB,
    MIN_DISK_MIB,
    SECTOR_SIZE,
)
from beastbooter.plan import make_plan, sfdisk_script

needs_sfdisk = pytest.mark.skipif(shutil.which("sfdisk") is None, reason="sfdisk not installed")
needs_sgdisk = pytest.mark.skipif(shutil.which("sgdisk") is None, reason="sgdisk not installed")

TIB = 1 << 40
SIZES = {
    "min-1GiB": MIN_DISK_MIB * MIB,
    "odd-bytes": MIN_DISK_MIB * MIB + 511,  # the minimum plus a partial sector: not a whole number of sectors
    "odd-sectors": (1 << 30) + 12_345 * SECTOR_SIZE + 7,
    "16GiB+1s": (16 << 30) + SECTOR_SIZE,  # CHS fields overflow (clamped to 1023/254/63)
}
BIG_GPT = 3 * TIB  # sparse; GPT only
BIG_MSDOS = (2**32 - 1) * SECTOR_SIZE  # the largest disk sfdisk still accepts for msdos

IDS = {
    "disk_signature": 0x1234ABCD,
    "disk_guid": "11111111-2222-4333-8444-555555555555",
    "part_guids": {
        1: "AAAAAAAA-0000-4000-8000-000000000001",
        2: "AAAAAAAA-0000-4000-8000-000000000002",
        3: "AAAAAAAA-0000-4000-8000-000000000003",
    },
}


class ImageFile:
    """Minimal BlockTarget over a (sparse) image file."""

    sector_size = SECTOR_SIZE

    def __init__(self, path: Path, size: int | None = None):
        flags = os.O_RDWR | os.O_CREAT | (os.O_TRUNC if size is not None else 0)
        self.fd = os.open(path, flags, 0o644)
        if size is not None:
            os.ftruncate(self.fd, size)
        self.size = os.fstat(self.fd).st_size
        self.writes: list[tuple[int, int]] = []

    def read(self, offset: int, length: int) -> bytes:
        return os.pread(self.fd, length, offset)

    def write(self, offset: int, data: bytes) -> None:
        assert 0 <= offset and offset + len(data) <= self.size, "write outside the image"
        os.pwrite(self.fd, data, offset)
        self.writes.append((offset, len(data)))

    def flush(self) -> None:
        os.fsync(self.fd)

    def close(self) -> None:
        os.close(self.fd)


class SectorImage(ImageFile):
    """Behaves like a raw device: only whole, aligned sectors may be read or written."""

    def read(self, offset: int, length: int) -> bytes:
        assert offset % SECTOR_SIZE == 0 and length % SECTOR_SIZE == 0, ("unaligned read", offset, length)
        return super().read(offset, length)

    def write(self, offset: int, data: bytes) -> None:
        assert offset % SECTOR_SIZE == 0 and len(data) % SECTOR_SIZE == 0, ("unaligned write", offset, len(data))
        super().write(offset, data)


def run(*cmd, check=True) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, check=check)


def make_image(path: Path, size: int, layout: str, fs: str = "exfat", **ids) -> Path:
    t = ImageFile(path, size)
    try:
        parttable.write_partition_table(t, make_plan(size // SECTOR_SIZE, layout), fs, **ids)
    finally:
        t.close()
    return path


def make_sfdisk_image(path: Path, size: int, layout: str, fs: str = "exfat") -> Path:
    """Today's path: plan.sfdisk_script() fed to sfdisk, with the IDS identifiers."""
    lines = sfdisk_script(make_plan(size // SECTOR_SIZE, layout), fs).splitlines()
    label_id = IDS["disk_guid"] if layout == "gpt" else f"0x{IDS['disk_signature']:08x}"
    lines.insert(1, f"label-id: {label_id}")
    if layout == "gpt":
        lines = [
            f"{line}, uuid={IDS['part_guids'][int(line.split(':')[0].strip()[-1])]}"
            if line.startswith("beast-p") else line
            for line in lines
        ]
    ImageFile(path, size).close()
    subprocess.run(["sfdisk", "--no-reread", "--no-tell-kernel", "--quiet", str(path)],
                   input="\n".join(lines) + "\n", text=True, capture_output=True, check=True)
    return path


def sfdisk_json(img: Path) -> dict:
    table = json.loads(run("sfdisk", "-J", img).stdout)["partitiontable"]
    table.pop("device")
    for p in table["partitions"]:
        p["node"] = int(re.search(r"(\d+)$", p["node"]).group(1))  # partition number
    return table


def read_region(img: Path, lba: int, sectors: int) -> bytes:
    with open(img, "rb") as f:
        f.seek(lba * SECTOR_SIZE)
        return f.read(sectors * SECTOR_SIZE)


def table_regions(img: Path) -> tuple[bytes, bytes]:
    """LBA 0..33 and the last 33 LBAs: everything either writer may touch."""
    sectors = img.stat().st_size // SECTOR_SIZE
    return read_region(img, 0, 34), read_region(img, sectors - 33, 33)


def expected_partitions(size: int, layout: str, fs: str) -> dict[int, dict]:
    plan = make_plan(size // SECTOR_SIZE, layout)
    if layout == "msdos":
        return {
            1: {"start": plan.data.start, "size": plan.data.size, "type": f"{MBR_TYPE_DATA[fs]:x}", "bootable": True},
            2: {"start": plan.esp.start, "size": plan.esp.size, "type": f"{MBR_TYPE_ESP:x}"},
        }
    return {
        1: {"start": plan.data.start, "size": plan.data.size, "type": GPT_TYPE_DATA, "name": GPT_NAME_DATA},
        2: {"start": plan.esp.start, "size": plan.esp.size, "type": GPT_TYPE_ESP, "name": GPT_NAME_ESP},
        3: {"start": plan.bios.start, "size": plan.bios.size, "type": GPT_TYPE_BIOS_BOOT, "name": GPT_NAME_BIOS_BOOT},
    }


CASES = [(name, size, layout) for name, size in SIZES.items() for layout in ("msdos", "gpt")]
CASES += [("3TiB", BIG_GPT, "gpt"), ("2TiB-1s", BIG_MSDOS, "msdos")]


# ---------------------------------------------------------------------------
# Independent validators
# ---------------------------------------------------------------------------


@needs_sfdisk
@pytest.mark.parametrize("name,size,layout", CASES, ids=[f"{c[2]}-{c[0]}" for c in CASES])
def test_tools_read_the_planned_geometry(tmp_path, name, size, layout):
    fs = "fat32" if layout == "msdos" else "exfat"
    img = make_image(tmp_path / "disk.img", size, layout, fs)
    plan = make_plan(size // SECTOR_SIZE, layout)
    table = sfdisk_json(img)
    assert table["label"] == ("dos" if layout == "msdos" else "gpt")
    assert table["sectorsize"] == SECTOR_SIZE
    got = {p["node"]: {k: v for k, v in p.items() if k not in ("node", "uuid")} for p in table["partitions"]}
    assert got == expected_partitions(size, layout, fs)
    if layout == "gpt":
        assert (table["firstlba"], table["lastlba"]) == (34, plan.last_usable_lba)

    verify = run("sfdisk", "-V", img, check=False)
    assert verify.returncode == 0 and "No errors detected" in verify.stdout, verify.stdout + verify.stderr

    # The installer's own parser agrees too.
    with open(img, "rb") as f:
        parsed = read_partition_table(lambda off, n: os.pread(f.fileno(), n, off), size // SECTOR_SIZE)
    assert {i: (e.start, e.size) for i, e in parsed.entries.items()} == {
        p.index: (p.start, p.size) for p in plan.parts
    }
    if layout == "gpt":
        assert parsed.pmbr_active  # ARCHITECTURE.md section 3


@needs_sgdisk
@pytest.mark.parametrize("size", [SIZES["min-1GiB"], SIZES["odd-bytes"], SIZES["odd-sectors"], BIG_GPT],
                         ids=["min", "odd-bytes", "odd-sectors", "3TiB"])
def test_sgdisk_finds_no_problems(tmp_path, size):
    img = make_image(tmp_path / "disk.img", size, "gpt")
    out = run("sgdisk", "-v", img, check=False)
    text = out.stdout + out.stderr
    assert out.returncode == 0, text
    assert "No problems found" in text, text
    assert "Problem:" not in text and "CRC" not in text, text
    # Expected remarks: the PMBR active flag (required by some BIOSes) and, for
    # the odd-sized test images, that the file is not a whole number of sectors.
    expected = ("marked as active", "File size is not a multiple of 512")
    remarks = [w for w in re.findall(r"Warning: [^\n]*", text) if not any(e in w for e in expected)]
    assert remarks == [], text


@needs_sfdisk
@pytest.mark.parametrize("name,size,layout", CASES[:4] + [("3TiB", BIG_GPT, "gpt")],
                         ids=[f"{c[2]}-{c[0]}" for c in CASES[:4]] + ["gpt-3TiB"])
def test_identical_to_the_sfdisk_path(tmp_path, name, size, layout):
    """Same identifiers in, byte-identical tables out (and the same parse)."""
    for fs in (("exfat", "fat32") if layout == "msdos" else ("exfat",)):
        mine = make_image(tmp_path / f"mine-{fs}.img", size, layout, fs, **IDS)
        ref = make_sfdisk_image(tmp_path / f"sfdisk-{fs}.img", size, layout, fs)
        assert sfdisk_json(mine) == sfdisk_json(ref)
        head_mine, tail_mine = table_regions(mine)
        head_ref, tail_ref = table_regions(ref)
        if layout == "gpt":  # we set the PMBR active flag that bootcode.py would add later
            assert head_ref[446] == 0x00 and head_mine[446] == 0x80
            head_ref = head_ref[:446] + b"\x80" + head_ref[447:]
        assert head_mine == head_ref
        assert tail_mine == tail_ref


# ---------------------------------------------------------------------------
# Structure details (UEFI spec)
# ---------------------------------------------------------------------------


def test_gpt_structures_follow_the_spec(tmp_path):
    size = SIZES["odd-sectors"]
    img = make_image(tmp_path / "disk.img", size, "gpt", **IDS)
    n = size // SECTOR_SIZE
    last = n - 1
    pmbr = read_region(img, 0, 1)
    assert pmbr[:440] == bytes(440)  # boot code left for bootcode.py
    assert pmbr[440:446] == bytes(6)  # disk signature unused in a PMBR
    assert pmbr[446:462] == bytes([0x80, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF]) + struct.pack("<II", 1, n - 1)
    assert pmbr[462:510] == bytes(48) and pmbr[510:] == b"\x55\xaa"

    def header(lba):
        raw = read_region(img, lba, 1)
        assert raw[:8] == b"EFI PART" and raw[92:] == bytes(420)
        fields = struct.unpack_from("<IIIIQQQQ16sQIII", raw, 8)
        crc = zlib.crc32(raw[:16] + b"\0\0\0\0" + raw[20:92]) & 0xFFFFFFFF
        assert fields[2] == crc
        return fields

    p, b = header(1), header(last)
    rev, hsize, _crc, rsv, my, alt, first, lastu, guid, ent_lba, count, esize, ecrc = p
    assert (rev, hsize, rsv, my, alt, first, lastu) == (0x10000, 92, 0, 1, last, 34, n - 34)
    assert uuid.UUID(bytes_le=guid) == uuid.UUID(IDS["disk_guid"])
    assert (ent_lba, count, esize) == (2, 128, 128)
    assert (b[4], b[5], b[9]) == (last, 1, n - 33)  # backup: MyLBA, AlternateLBA, entries LBA
    assert b[6:9] == p[6:9] and b[10:] == p[10:]

    entries = read_region(img, 2, 32)
    assert entries == read_region(img, n - 33, 32)
    assert zlib.crc32(entries) & 0xFFFFFFFF == ecrc
    plan = make_plan(n, "gpt")
    names = {1: GPT_NAME_DATA, 2: GPT_NAME_ESP, 3: GPT_NAME_BIOS_BOOT}
    for part in plan.parts:
        e = entries[(part.index - 1) * 128 : part.index * 128]
        tguid, pguid, start, end, attrs = struct.unpack_from("<16s16sQQQ", e)
        assert uuid.UUID(bytes_le=pguid) == uuid.UUID(IDS["part_guids"][part.index])
        assert (start, end, attrs) == (part.start, part.end, 0)
        assert e[56:].decode("utf-16-le").rstrip("\0") == names[part.index]
    assert entries[3 * 128 :] == bytes(125 * 128)


def test_msdos_mbr_bytes(tmp_path):
    img = make_image(tmp_path / "disk.img", SIZES["odd-bytes"], "msdos", "fat32", disk_signature=0xCAFEF00D)
    mbr = read_region(img, 0, 1)
    assert mbr[:440] == bytes(440)
    assert struct.unpack_from("<IH", mbr, 440) == (0xCAFEF00D, 0)
    plan = make_plan(SIZES["odd-bytes"] // SECTOR_SIZE, "msdos")
    e1, e2 = mbr[446:462], mbr[462:478]
    assert e1[0] == 0x80 and e1[4] == 0x0C and struct.unpack_from("<II", e1, 8) == (plan.data.start, plan.data.size)
    assert e2[0] == 0x00 and e2[4] == 0xEF and struct.unpack_from("<II", e2, 8) == (plan.esp.start, plan.esp.size)
    assert e1[1:4] == bytes([32, 33, 0])  # LBA 2048 = C0 H32 S33 with 255x63
    assert mbr[478:510] == bytes(32) and mbr[510:] == b"\x55\xaa"


def test_chs_encoding():
    assert parttable.chs(0) == bytes([0, 1, 0])
    assert parttable.chs(62) == bytes([0, 63, 0])
    assert parttable.chs(63) == bytes([1, 1, 0])
    assert parttable.chs(255 * 63) == bytes([0, 1, 1])
    assert parttable.chs(256 * 255 * 63) == bytes([0, 1 | 0x40, 0])  # cylinder 256: bit 8 in the sector byte
    assert parttable.chs(1024 * 255 * 63 - 1) == bytes([254, 63 | 0xC0, 0xFF])
    assert parttable.chs(1024 * 255 * 63) == parttable.CHS_MAX == bytes([0xFE, 0xFF, 0xFF])


# ---------------------------------------------------------------------------
# Identifiers, boot code, re-labelling
# ---------------------------------------------------------------------------


@needs_sfdisk
def test_identifiers_random_unless_given(tmp_path):
    size = SIZES["min-1GiB"]
    ta = sfdisk_json(make_image(tmp_path / "a.img", size, "gpt"))
    tb = sfdisk_json(make_image(tmp_path / "b.img", size, "gpt"))
    guids = [ta["id"], tb["id"]] + [p["uuid"] for p in ta["partitions"] + tb["partitions"]]
    assert len(set(guids)) == len(guids) == 8
    assert all(uuid.UUID(g).version == 4 for g in guids)
    m1 = read_region(make_image(tmp_path / "m1.img", size, "msdos"), 0, 1)
    m2 = read_region(make_image(tmp_path / "m2.img", size, "msdos"), 0, 1)
    assert m1[440:444] != m2[440:444] and m1[440:444] != bytes(4)
    # Deterministic when everything is given.
    c = make_image(tmp_path / "c.img", size, "gpt", **IDS)
    d = make_image(tmp_path / "d.img", size, "gpt", **IDS)
    assert table_regions(c) == table_regions(d)


def test_keep_boot_code(tmp_path):
    size = SIZES["min-1GiB"]
    code = bytes(range(256)) + bytes(range(184))
    assert len(code) == BOOT_IMG_CODE_LEN
    for layout in ("msdos", "gpt"):
        img = tmp_path / f"{layout}.img"
        t = ImageFile(img, size)
        t.write(0, code)
        plan = make_plan(size // SECTOR_SIZE, layout)
        parttable.write_partition_table(t, plan, "exfat", keep_boot_code=True)
        assert t.read(0, BOOT_IMG_CODE_LEN) == code
        parttable.write_partition_table(t, plan, "exfat")
        assert t.read(0, BOOT_IMG_CODE_LEN) == bytes(BOOT_IMG_CODE_LEN)
        t.close()


@needs_sfdisk
def test_bootcode_on_top_keeps_the_table(tmp_path):
    """bootcode.boot_writes() after write_partition_table(): table still valid."""
    size = SIZES["odd-bytes"]
    boot_img = bytearray(512)
    boot_img[510:] = b"\x55\xaa"
    core_img = bytes(40 * 512)
    for layout in ("msdos", "gpt"):
        img = tmp_path / f"{layout}.img"
        plan = make_plan(size // SECTOR_SIZE, layout)
        t = ImageFile(img, size)
        parttable.write_partition_table(t, plan, "exfat", **IDS)
        before = t.read(440, 72)
        for off, data in boot_writes(plan, bytes(boot_img), core_img):
            t.write(off, data)
        assert t.read(440, 72) == before
        t.close()
        assert run("sfdisk", "-V", img, check=False).returncode == 0


@needs_sfdisk
def test_relabel_wipes_the_other_table(tmp_path):
    size = SIZES["odd-sectors"]
    n = size // SECTOR_SIZE
    img = tmp_path / "disk.img"
    t = ImageFile(img, size)
    parttable.write_partition_table(t, make_plan(n, "gpt"), "exfat")
    parttable.write_partition_table(t, make_plan(n, "msdos"), "exfat")
    assert t.read(SECTOR_SIZE, 8) != b"EFI PART" and t.read((n - 1) * SECTOR_SIZE, 8) != b"EFI PART"
    t.close()
    assert sfdisk_json(img)["label"] == "dos"
    if shutil.which("blkid"):
        probe = run("blkid", "-p", "-o", "export", img, check=False).stdout
        assert "PTTYPE=dos" in probe and "gpt" not in probe
    t = ImageFile(img)
    parttable.write_partition_table(t, make_plan(n, "gpt"), "exfat")
    t.close()
    assert sfdisk_json(img)["label"] == "gpt"


def test_writes_stay_in_the_table_areas(tmp_path):
    size = BIG_GPT
    n = size // SECTOR_SIZE
    t = ImageFile(tmp_path / "disk.img", size)
    parttable.write_partition_table(t, make_plan(n, "gpt"), "exfat")
    t.close()
    for off, length in t.writes:
        assert off + length <= 34 * SECTOR_SIZE or off >= (n - 33) * SECTOR_SIZE
    assert sum(length for _off, length in t.writes) == (34 + 33) * SECTOR_SIZE
    assert os.stat(tmp_path / "disk.img").st_blocks * 512 < 1 << 20  # still sparse


def test_errors(tmp_path):
    size = SIZES["min-1GiB"]
    plan = make_plan(size // SECTOR_SIZE, "gpt")
    t = ImageFile(tmp_path / "disk.img", size)
    with pytest.raises(BeastError, match="unknown filesystem"):
        parttable.write_partition_table(t, plan, "ext4")
    with pytest.raises(BeastError, match="not in the plan"):
        parttable.write_partition_table(t, plan, "exfat", part_guids={4: IDS["disk_guid"]})
    with pytest.raises(BeastError, match="invalid GUID"):
        parttable.write_partition_table(t, plan, "exfat", disk_guid="not-a-guid")
    msdos = make_plan(size // SECTOR_SIZE, "msdos")
    for bad in (1 << 32, -1, "0x1234", True, 1.0):  # never a TypeError, never True == 1
        for p in (msdos, plan):
            with pytest.raises(BeastError, match="32-bit"):
                parttable.write_partition_table(t, p, "exfat", disk_signature=bad)
    for fs in (None, ["exfat"], b"exfat"):
        with pytest.raises(BeastError, match="unknown filesystem"):
            parttable.write_partition_table(t, plan, fs)
    with pytest.raises(BeastError, match="DiskPlan"):
        parttable.write_partition_table(t, "gpt", "exfat")
    with pytest.raises(BeastError, match="part_guids must map"):
        parttable.write_partition_table(t, plan, "exfat", part_guids=[IDS["disk_guid"]])
    with pytest.raises(BeastError, match="not in the plan"):
        parttable.write_partition_table(t, plan, "exfat", part_guids={"1": IDS["disk_guid"], 1.5: IDS["disk_guid"]})
    for guids in ({"disk_guid": b"11111111-2222-4333-8444-555555555555"}, {"disk_guid": ""},
                  {"part_guids": {1: ""}}, {"part_guids": {2: 123}}):  # "" is not "make one up"
        with pytest.raises(BeastError, match="invalid GUID"):
            parttable.write_partition_table(t, plan, "exfat", **guids)
    with pytest.raises(BeastError, match="plan is for"):
        parttable.write_partition_table(t, make_plan(size // SECTOR_SIZE + 2048, "gpt"), "exfat")
    t.sector_size = 4096
    with pytest.raises(BeastError, match="512-byte sectors"):
        parttable.write_partition_table(t, plan, "exfat")
    t.close()
    assert t.writes == []


# ---------------------------------------------------------------------------
# The Linux kernel's partition parser (rootless loop device via udisks)
# ---------------------------------------------------------------------------


def _udisks_loop(img: Path) -> str | None:
    if shutil.which("udisksctl") is None:
        return None
    proc = run("udisksctl", "loop-setup", "-f", img, "--no-user-interaction", check=False)
    m = re.search(r"as (/dev/loop\d+)", proc.stdout)
    return m.group(1) if proc.returncode == 0 and m else None


def _udisks_delete(dev: str) -> None:
    for _ in range(20):
        if run("udisksctl", "loop-delete", "-b", dev, "--no-user-interaction", check=False).returncode == 0:
            return
        time.sleep(0.25)


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
def test_kernel_reads_the_table(tmp_path, layout):
    size = SIZES["odd-bytes"]
    img = make_image(tmp_path / "disk.img", size, layout)
    dev = _udisks_loop(img)
    if dev is None:
        pytest.skip("udisksctl loop-setup is not available here")
    try:
        name = os.path.basename(dev)
        plan = make_plan(size // SECTOR_SIZE, layout)
        want = {p.index: (p.start, p.size) for p in plan.parts}
        got: dict[int, tuple[int, int]] = {}
        for _ in range(40):  # partitions appear asynchronously
            got = {}
            for idx in want:
                sysdir = Path(f"/sys/class/block/{name}p{idx}")
                if sysdir.is_dir():
                    got[idx] = (int((sysdir / "start").read_text()), int((sysdir / "size").read_text()))
            if got == want:
                break
            time.sleep(0.1)
        assert got == want
    finally:
        _udisks_delete(dev)


def test_sector_aligned_io(tmp_path):
    """Raw devices on Windows/macOS need whole sectors; the writer never asks for less."""
    size = SIZES["odd-sectors"]
    n = size // SECTOR_SIZE
    t = SectorImage(tmp_path / "disk.img", n * SECTOR_SIZE)
    for layout in ("gpt", "msdos", "gpt"):
        parttable.write_partition_table(t, make_plan(n, layout), "exfat", keep_boot_code=True)
        parttable.write_partition_table(t, make_plan(n, layout), "fat32")
    t.close()
