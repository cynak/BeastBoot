"""exfatfs: pure-Python exFAT format + reader/writer, checked against independent tools.

Validators: fsck.exfat -n and mkfs.exfat (exfatprogs), blkid, and the Linux
kernel exFAT driver (an image mounted rootless through udisks). Tests that
need a tool skip when it is missing; the kernel tests also skip when udisks
cannot set up a loop device (e.g. no desktop session).
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import shutil
import struct
import subprocess
import time
from pathlib import Path

import pytest

from beastbooter import exfatfs
from beastbooter.errors import BeastError
from beastbooter.exfatfs import (
    ENTRY_SIZE,
    UPCASE_TABLE,
    UPCASE_TABLE_CHECKSUM,
    BootSector,
    ExfatVolume,
    format_exfat,
    plan_layout,
)
from beastbooter.interfaces import BlockTarget, DirEntry, format_volume_id

MIB = 1 << 20
GIB = 1 << 30
TIB = 1 << 40
SERIAL = 0x1A2B3C4D
LABEL = "BEASTBOOTER"

FSCK = shutil.which("fsck.exfat")
MKFS = shutil.which("mkfs.exfat")
BLKID = shutil.which("blkid")
UDISKSCTL = shutil.which("udisksctl")
needs_fsck = pytest.mark.skipif(FSCK is None, reason="fsck.exfat (exfatprogs) not installed")
needs_mkfs = pytest.mark.skipif(MKFS is None, reason="mkfs.exfat (exfatprogs) not installed")
needs_blkid = pytest.mark.skipif(BLKID is None, reason="blkid not installed")


class FileTarget:
    """Minimal BlockTarget over an image file (what blockio.ImageTarget provides)."""

    sector_size = 512

    def __init__(self, path: Path) -> None:
        self._fd = os.open(path, os.O_RDWR)
        self.size = os.fstat(self._fd).st_size
        self.writes = 0

    def read(self, offset: int, length: int) -> bytes:
        return os.pread(self._fd, length, offset)

    def write(self, offset: int, data: bytes) -> None:
        assert offset >= 0 and offset + len(data) <= self.size, "write outside the target"
        view = memoryview(data)
        while view:
            n = os.pwrite(self._fd, view, offset)
            offset += n
            view = view[n:]
        self.writes += 1

    def flush(self) -> None:
        os.fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)


def sparse_image(path: Path, size: int) -> Path:
    with open(path, "wb") as f:
        f.truncate(size)
    return path


def formatted(path: Path, size: int, **kw) -> Path:
    sparse_image(path, size)
    t = FileTarget(path)
    try:
        format_exfat(t, 0, size, label=kw.pop("label", LABEL), volume_serial=kw.pop("volume_serial", SERIAL), **kw)
    finally:
        t.close()
    return path


class opened:
    """with opened(img) as vol: an ExfatVolume on an image file."""

    def __init__(self, path: Path, offset: int = 0, **kw) -> None:
        self.t = FileTarget(path)
        self.offset, self.kw = offset, kw

    def __enter__(self) -> ExfatVolume:
        return ExfatVolume(self.t, self.offset, **self.kw)

    def __exit__(self, *exc) -> None:
        self.t.close()


def fsck(path: Path) -> str:
    proc = subprocess.run([FSCK, "-n", str(path)], capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0 and "clean" in out and "ERROR" not in out, out
    return out


def blkid(path: Path, offset: int = 0) -> dict[str, str]:
    out = subprocess.run([BLKID, "-p", "-O", str(offset), "-o", "export", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def mkfs_reference(path: Path, size: int, label: str = LABEL) -> Path:
    sparse_image(path, size)
    subprocess.run([MKFS, "-q", "-L", label, str(path)], check=True, capture_output=True)
    return path


def walk(vol: ExfatVolume, path: str = "/") -> dict[str, bytes | None]:
    """{path: content} for every file (None for directories) below `path`."""
    out: dict[str, bytes | None] = {}
    for entry in vol.listdir(path):
        child = path.rstrip("/") + "/" + entry.name
        if entry.is_dir:
            out[child] = None
            out.update(walk(vol, child))
        else:
            out[child] = vol.read_file(child)
    return out


def walk_mounted(root: Path) -> dict[str, bytes | None]:
    out: dict[str, bytes | None] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            out["/" + str((Path(dirpath) / d).relative_to(root))] = None
        for f in filenames:
            out["/" + str((Path(dirpath) / f).relative_to(root))] = (Path(dirpath) / f).read_bytes()
    return out


def region(path: Path, offset: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


# ---------------------------------------------------------------------------
# Checksums, up-case table, geometry
# ---------------------------------------------------------------------------


def test_upcase_table_is_the_specifications_recommended_table():
    assert len(UPCASE_TABLE) == exfatfs.UPCASE_TABLE_SIZE == 5836
    assert exfatfs.upcase_table_checksum(UPCASE_TABLE) == UPCASE_TABLE_CHECKSUM == 0xE619D30D
    mapping = exfatfs.decompress_upcase_table(UPCASE_TABLE)
    assert mapping == exfatfs.default_upcase_mapping()
    up = lambda s: "".join(chr(mapping[ord(c)]) for c in s)  # noqa: E731
    assert up("abcz") == "ABCZ"
    assert up("éñøÿ") == "ÉÑØŸ"
    assert up("ωяß") == "ΩЯß"  # sharp s has no single-character upper case
    assert up("ｚ") == "Ｚ"  # fullwidth
    assert up("A1-_") == "A1-_"


def test_checksum_algorithms_against_spec_examples():
    # The algorithms rotate right by one bit and add each byte (§3.4, §6.3.3, §7.6.4).
    assert exfatfs.boot_checksum(bytes(512 * 11)) == 0
    assert exfatfs.boot_checksum(b"\x01") == 1
    assert exfatfs.boot_checksum(b"\x01\x00") == 0x80000000
    sector = bytearray(512 * 11)
    sector[106], sector[107], sector[112] = 0xFF, 0xFF, 0xFF  # VolumeFlags + PercentInUse excluded
    assert exfatfs.boot_checksum(bytes(sector)) == 0
    entry = bytearray(64)
    entry[2:4] = b"\xff\xff"  # SetChecksum field excluded
    assert exfatfs.entry_set_checksum(bytes(entry)) == 0
    assert exfatfs.name_hash(b"\x01\x00") == 0x8000


@needs_mkfs
def test_checksums_match_what_mkfs_exfat_writes(tmp_path):
    img = mkfs_reference(tmp_path / "ref.img", 64 * MIB)
    data = region(img, 0, 24 * 512)
    for start in (0, 12 * 512):
        expected = struct.unpack_from("<I", data, start + 11 * 512)[0]
        assert exfatfs.boot_checksum(data[start:start + 11 * 512]) == expected
    with opened(img) as vol:  # also checks the up-case table checksum on the way
        assert vol.label == LABEL and vol.listdir("/") == []


@pytest.mark.parametrize("size", [8 * MIB, 100 * MIB + 512, 256 * MIB, 256 * MIB + 512, 4 * GIB,
                                  32 * GIB, 32 * GIB + MIB, 64 * GIB, TIB, 2 * TIB, 231842304])
def test_geometry_and_default_cluster_size_match_mkfs_exfat(tmp_path, size):
    if MKFS is None:
        pytest.skip("mkfs.exfat not installed")
    ours = formatted(tmp_path / "ours.img", size)
    ref = mkfs_reference(tmp_path / "ref.img", size)
    a = BootSector.parse(region(ours, 0, 512))
    b = BootSector.parse(region(ref, 0, 512))
    assert a.volume_serial == SERIAL
    a.volume_serial = b.volume_serial
    assert a == b  # every boot sector field, PercentInUse and FileSystemRevision 1.00 included
    assert a.file_system_revision == 0x0100 and a.number_of_fats == 1
    expected_cs = 4096 if size <= 256 * MIB else 32768 if size <= 32 * GIB else 131072
    assert a.cluster_size == expected_cs

    # FAT, bitmap, up-case table and root directory are byte-identical too.
    ss, cs = a.sector_size, a.cluster_size
    layout = plan_layout(size, ss)
    fat_used = (2 + layout.used_clusters) * 4
    assert region(ours, a.fat_offset * ss, fat_used + 64) == region(ref, a.fat_offset * ss, fat_used + 64)
    heap = a.cluster_heap_offset * ss
    meta = layout.used_clusters * cs
    assert region(ours, heap, meta) == region(ref, heap, meta)


@needs_mkfs
def test_boot_region_differs_from_mkfs_exfat_only_where_intended(tmp_path):
    """Intentional differences: VolumeSerialNumber (given, not time-based), the
    boot code (a halt loop instead of zeros) and therefore the checksum sectors."""
    ours = region(formatted(tmp_path / "ours.img", 256 * MIB), 0, 24 * 512)
    ref = region(mkfs_reference(tmp_path / "ref.img", 256 * MIB), 0, 24 * 512)
    differing = {i % (12 * 512) for i in range(len(ours)) if ours[i] != ref[i]}
    allowed = set(range(100, 104)) | set(range(120, 124)) | set(range(11 * 512, 12 * 512))
    assert differing <= allowed
    assert ours[:12 * 512] == ours[12 * 512:]  # backup boot region == main
    assert ours[120:124] == exfatfs.BOOT_CODE


def test_boot_region_structure(tmp_path):
    img = formatted(tmp_path / "v.img", 256 * MIB)
    data = region(img, 0, 24 * 512)
    assert data[0:3] == b"\xeb\x76\x90" and data[3:11] == b"EXFAT   "
    assert data[11:64] == bytes(53) and data[510:512] == b"\x55\xaa"
    for sector in range(1, 9):  # Extended Boot Sectors
        s = data[sector * 512:(sector + 1) * 512]
        assert s[:508] == bytes(508) and s[508:] == b"\x00\x00\x55\xaa"
    assert data[9 * 512:11 * 512] == bytes(1024)  # OEM parameters + reserved
    checksum = struct.pack("<I", exfatfs.boot_checksum(data[:11 * 512]))
    assert data[11 * 512:12 * 512] == checksum * 128
    boot = BootSector.parse(data[:512])
    assert (boot.volume_flags, boot.drive_select, boot.partition_offset) == (0, 0x80, 0)


def test_small_volumes_align_to_the_cluster_size(tmp_path):
    """Below 8 MiB, 1 MiB alignment would waste most of the volume (mkfs.exfat
    keeps it, leaving e.g. 1 of 3 MiB); we align to the cluster size instead."""
    for size in (1 * MIB, 3 * MIB, 8 * MIB - 512):
        layout = plan_layout(size)
        assert layout.boot.fat_offset == 24
        assert layout.boot.cluster_heap_offset * 512 % 4096 == 0
        if FSCK:
            fsck(formatted(tmp_path / f"s{size}.img", size))


# ---------------------------------------------------------------------------
# format_exfat validated with fsck.exfat and blkid
# ---------------------------------------------------------------------------


@needs_fsck
@needs_blkid
@pytest.mark.parametrize("size", [256 * MIB, 4 * GIB, 64 * GIB, TIB])
def test_format_is_fsck_clean_and_blkid_identifies_it(tmp_path, size):
    img = formatted(tmp_path / "v.img", size)
    fsck(img)
    info = blkid(img)
    assert info["TYPE"] == "exfat"
    assert info["LABEL"] == LABEL
    assert info["UUID"] == format_volume_id(SERIAL) == "1A2B-3C4D"
    assert info["VERSION"] == "1.0"
    with opened(img) as vol:
        assert (vol.label, vol.volume_serial, vol.listdir("/")) == (LABEL, SERIAL, [])
        assert vol.boot.percent_in_use == 0


def test_formatting_2tib_takes_seconds_and_stays_sparse(tmp_path):
    img = sparse_image(tmp_path / "big.img", 2 * TIB)
    t = FileTarget(img)
    assert isinstance(t, BlockTarget)
    start = time.monotonic()
    format_exfat(t, 0, 2 * TIB, label=LABEL, volume_serial=SERIAL)
    elapsed = time.monotonic() - start
    t.close()
    assert elapsed < 15, f"format took {elapsed:.1f} s"
    allocated = os.stat(img).st_blocks * 512
    assert allocated < 128 * MIB  # FAT (64 MiB) + bitmap (2 MiB) + a little
    if FSCK:
        fsck(img)


@needs_fsck
def test_quick_format_does_not_rely_on_a_zeroed_target(tmp_path):
    size = 256 * MIB
    clean = formatted(tmp_path / "clean.img", size)
    dirty = tmp_path / "dirty.img"
    junk = bytes(range(256)) * (4096 * 4)  # 4 MiB of non-zero bytes
    with open(dirty, "wb") as f:
        for _ in range(size // len(junk)):
            f.write(junk)
    t = FileTarget(dirty)
    format_exfat(t, 0, size, label=LABEL, volume_serial=SERIAL)
    t.close()
    layout = plan_layout(size)
    metadata_end = layout.boot.cluster_heap_offset * 512 + layout.used_clusters * layout.boot.cluster_size
    assert region(dirty, 0, metadata_end) == region(clean, 0, metadata_end)
    fsck(dirty)


@needs_blkid
def test_format_inside_a_disk_image_at_an_offset(tmp_path):
    """The data partition starts at 1 MiB; PartitionOffset records it, nothing outside is touched."""
    disk = tmp_path / "disk.img"
    with open(disk, "wb") as f:
        f.write(b"\xaa" * (300 * MIB))
    offset, size = 1 * MIB, 200 * MIB + 4096
    t = FileTarget(disk)
    format_exfat(t, offset, size, label="DATA", volume_serial=0xDEADBEEF)
    vol = ExfatVolume(t, offset)
    vol.write_file("/beast-booter/config.cfg", b"set timeout=5\n")
    t.close()
    assert region(disk, 0, offset) == b"\xaa" * offset
    assert region(disk, offset + size, 1 * MIB) == b"\xaa" * MIB
    boot = BootSector.parse(region(disk, offset, 512))
    assert boot.partition_offset == offset // 512
    assert boot.volume_length == size // 512
    info = blkid(disk, offset)
    assert (info["TYPE"], info["LABEL"], info["UUID"]) == ("exfat", "DATA", "DEAD-BEEF")
    if FSCK:  # fsck.exfat has no offset option: check a copy of the partition
        part = tmp_path / "part.img"
        part.write_bytes(region(disk, offset, size))
        fsck(part)


@pytest.mark.parametrize("cluster_size", [512, 4096, 65536, 1 * MIB])
def test_explicit_cluster_sizes(tmp_path, cluster_size):
    img = formatted(tmp_path / "v.img", 64 * MIB, cluster_size=cluster_size)
    with opened(img) as vol:
        assert vol.cluster_size == cluster_size
        vol.write_file("/beast-booter/config.cfg", b"x" * 3000)
        vol.write_file("/a/b/c.bin", os.urandom(cluster_size * 2 + 1))
        assert vol.read_file("/BEAST-BOOTER/CONFIG.CFG") == b"x" * 3000
    if FSCK:
        fsck(img)


class FileTarget4K(FileTarget):
    sector_size = 4096


@needs_fsck
def test_4k_sector_volumes(tmp_path):
    size = 512 * MIB
    img = sparse_image(tmp_path / "v.img", size)
    t = FileTarget4K(img)
    format_exfat(t, 0, size, label=LABEL, volume_serial=SERIAL)
    vol = ExfatVolume(t, 0)
    assert (vol.sector_size, vol.cluster_size) == (4096, 32768)
    vol.write_file("/beast-booter/config.cfg", b"4k")
    t.close()
    fsck(img)
    if MKFS:  # same geometry as mkfs.exfat -s 4096, and we read and write its volumes
        ref = sparse_image(tmp_path / "ref.img", size)
        subprocess.run([MKFS, "-q", "-s", "4096", "-L", LABEL, str(ref)], check=True, capture_output=True)
        a = BootSector.parse(region(img, 0, 4096))
        b = BootSector.parse(region(ref, 0, 4096))
        a.volume_serial, a.percent_in_use = b.volume_serial, b.percent_in_use
        assert a == b
        with opened(ref) as vol:  # a 512-byte-sector target holding a 4K-sector volume
            assert vol.sector_size == 4096 and vol.label == LABEL
            vol.write_file("/beast-booter/config.cfg", b"ref")
            assert vol.read_file("/beast-booter/config.cfg") == b"ref"
        fsck(ref)


def test_format_rejects_bad_parameters(tmp_path):
    img = sparse_image(tmp_path / "v.img", 64 * MIB)
    t = FileTarget(img)
    try:
        cases = [
            dict(label="TWELVE_CHARS"),  # exFAT labels hold 11 UTF-16 code units
            dict(label="\U0001F600" * 6),  # 6 emoji = 12 UTF-16 code units
            dict(label="A:B"),
            dict(label="TAB\tX"),
            dict(label="\ud800"),  # lone surrogate: not encodable as UTF-16
            dict(label=None),
            dict(label=123),
            dict(volume_serial="1234"),
            dict(volume_serial=1.5),
            dict(volume_serial=True),
            dict(cluster_size="4096"),
            dict(size=64.0 * MIB),
            dict(cluster_size=3000),
            dict(cluster_size=256),  # smaller than a sector
            dict(cluster_size=64 * MIB),  # larger than 32 MiB
            dict(volume_serial=1 << 32),
            dict(size=512 * 1024),  # below the 1 MiB minimum
            dict(size=65 * MIB),  # does not fit in the target
            dict(offset=100),  # not sector-aligned
        ]
        for case in cases:
            kw = dict(label=LABEL, volume_serial=SERIAL)
            kw.update(case)
            offset, size = kw.pop("offset", 0), kw.pop("size", 64 * MIB)
            with pytest.raises(BeastError):
                format_exfat(t, offset, size, **kw)
        assert t.writes == 0  # validation happens before anything is written
        with pytest.raises(BeastError, match="cluster size 512 is too small"):
            plan_layout(4 * TIB, cluster_size=512)
        format_exfat(t, 0, 64 * MIB, label="", volume_serial=0)  # empty label is fine
        assert ExfatVolume(t, 0).label == ""
        format_exfat(t, 0, 64 * MIB, label="Ünïcødé ✓", volume_serial=0)
        assert ExfatVolume(t, 0).label == "Ünïcødé ✓"
        emoji = "\U0001F600" * 5 + "A"  # 11 UTF-16 code units: the maximum
        format_exfat(t, 0, 64 * MIB, label=emoji, volume_serial=0xFFFFFFFF)
        assert ExfatVolume(t, 0).label == emoji
    finally:
        t.close()
    if FSCK:
        fsck(img)
    # callers can check a label before they write anything to the disk
    exfatfs.check_label(LABEL)
    exfatfs.check_label("")
    for bad in ("ABCDEFGHIJKL", "A*B", "\udcff", b"BYTES"):
        with pytest.raises(BeastError):
            exfatfs.check_label(bad)


# ---------------------------------------------------------------------------
# ExfatVolume: reading and writing
# ---------------------------------------------------------------------------


@needs_fsck
def test_write_files_and_directories_then_fsck(tmp_path):
    img = formatted(tmp_path / "v.img", 256 * MIB)
    long_name = "A very long file name that needs several File Name entries - " * 3 + ".iso"
    files = {
        "/beast-booter/config.cfg": b"set timeout=5\nset bb_debug=1\n",
        "/empty.txt": b"",
        "/one-cluster.bin": b"\x01" * 4096,
        "/multi.bin": os.urandom(50_000),
        "/ISOs/linux/" + long_name: os.urandom(10_000),
        "/Ünïcødé dir/файл ✓.txt": "grüße".encode(),
        "/deep/a/b/c/d/e/f/leaf": b"leaf",
    }
    with opened(img) as vol:
        for path, data in files.items():
            vol.write_file(path, data)
        assert walk(vol) == {
            **files,
            "/beast-booter": None, "/ISOs": None, "/ISOs/linux": None, "/Ünïcødé dir": None,
            "/deep": None, "/deep/a": None, "/deep/a/b": None, "/deep/a/b/c": None,
            "/deep/a/b/c/d": None, "/deep/a/b/c/d/e": None, "/deep/a/b/c/d/e/f": None,
        }
        assert vol.listdir("/beast-booter") == [DirEntry("config.cfg", False, len(files["/beast-booter/config.cfg"]))]
        assert DirEntry("ISOs", True, 0) in vol.listdir("/")
        assert vol.read_file("/isos/LINUX/" + long_name.upper()) == files["/ISOs/linux/" + long_name]
        assert vol.read_file("/ÜNÏCØDÉ DIR/ФАЙЛ ✓.TXT") == "grüße".encode()
        assert vol.exists("/Beast-Booter/Config.cfg") and not vol.exists("/nope")
        assert not vol.dirty and vol.boot.volume_flags == 0
    fsck(img)
    boot = BootSector.parse(region(img, 0, 512))
    assert boot.volume_flags & exfatfs.VOLUME_FLAG_DIRTY == 0


@needs_fsck
def test_replace_and_remove(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)
    with opened(img, clock=lambda: 1_700_000_000.0) as vol:
        vol.write_file("/beast-booter/config.cfg", b"a" * 10_000)
        created = vol._lookup("/beast-booter/config.cfg").raw[8:12]
    with opened(img, clock=lambda: 1_800_000_000.0) as vol:
        free_before = vol._bitmap.used_count()
        vol.write_file("/beast-booter/config.cfg", b"short")  # same name: entry set rewritten in place
        node = vol._lookup("/beast-booter/config.cfg")
        assert node.raw[8:12] == created  # creation time kept, modification time updated
        assert node.raw[12:16] != created
        assert vol._bitmap.used_count() == free_before - 2  # 3 clusters -> 1
        vol.write_file("/BEAST-BOOTER/CONFIG.CFG", b"upper")  # case-insensitive replace
        assert [e.name for e in vol.listdir("/beast-booter")] == ["CONFIG.CFG"]
        vol.write_file("/beast-booter/CONFIG.CFG", b"x" * 100_000)
        assert vol.read_file("/beast-booter/config.cfg") == b"x" * 100_000
        vol.write_file("/beast-booter/a much longer name than before.cfg", b"1")
        vol.remove("/beast-booter/a much longer name than before.cfg")
        with pytest.raises(BeastError, match="not empty"):
            vol.remove("/beast-booter")
        vol.remove("/beast-booter/config.cfg")
        vol.remove("/beast-booter")
        assert vol.listdir("/") == []
        assert vol._bitmap.used_count() == plan_layout(64 * MIB).used_clusters
        with pytest.raises(BeastError, match="no such"):
            vol.read_file("/beast-booter/config.cfg")
    fsck(img)


def test_invalid_names_and_paths_are_refused(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)
    with opened(img) as vol:
        vol.write_file("/file", b"data")
        for bad in ("/a:b", "/what?", "/trailing.", "/trailing ", "/" + "x" * 256, "/tab\there",
                    "/lone \udcff surrogate", "/new parent/a:b", "/new parent/bad\ud800/x"):
            with pytest.raises(BeastError):
                vol.write_file(bad, b"")
        for bad in ("/new parent/a:b", "/new parent/" + "x" * 256):  # nothing is created first
            with pytest.raises(BeastError):
                vol.mkdir(bad)
        with pytest.raises(BeastError, match="must be a string"):
            vol.write_file(b"/bytes-path", b"")
        with pytest.raises(BeastError, match="needs bytes"):
            vol.write_file("/text", "not bytes")
        with pytest.raises(BeastError, match="not a directory"):
            vol.write_file("/file/child", b"")
        with pytest.raises(BeastError, match="not a directory"):
            vol.mkdir("/file")
        vol.mkdir("/dir")
        vol.mkdir("/dir")  # existing directories are fine
        with pytest.raises(BeastError, match="is a directory"):
            vol.write_file("/dir", b"")
        with pytest.raises(BeastError, match="is a directory"):
            vol.read_file("/dir")
        with pytest.raises(BeastError):
            vol.write_file("/", b"")
        assert [e.name for e in vol.listdir("/")] == ["file", "dir"]
    # refused writes changed nothing, so the volume is not left marked dirty
    assert BootSector.parse(region(img, 0, 512)).volume_flags == 0


@needs_fsck
def test_directories_grow_past_one_cluster(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)  # 4 KiB clusters: 128 entries each
    with opened(img) as vol:
        names = [f"file number {i:03d} with a longer name.txt" for i in range(150)]  # 5 entries each
        for name in names:  # empty files need no data clusters: the directory can grow in place
            vol.write_file("/contig/" + name, b"")
        for name in names:
            vol.write_file("/sub/" + name, name.encode())
            vol.write_file("/" + name, name.encode())
        root_clusters = len(vol._dir_clusters(vol.root))
        sub, contig = vol._lookup("/sub"), vol._lookup("/contig")
        assert root_clusters >= 6 and sub.data_length >= 6 * 4096 and contig.data_length >= 6 * 4096
        assert not sub.no_fat_chain  # file data was allocated behind it: converted to a FAT chain
        assert contig.no_fat_chain  # the next clusters were free: it stayed contiguous
        assert [e.name for e in vol.listdir("/sub")] == names
        assert [e.name for e in vol.listdir("/contig")] == names
        for name in names[::17]:
            assert vol.read_file("/SUB/" + name.upper()) == name.encode()
    fsck(img)


@needs_fsck
def test_fragmented_writes_use_a_fat_chain(tmp_path):
    img = formatted(tmp_path / "v.img", 8 * MIB)  # 1536 clusters of 4 KiB
    with opened(img) as vol:
        for i in range(15):  # 15 x 100 clusters: fills almost everything
            vol.write_file(f"/f{i:02d}", bytes([i]) * (100 * 4096))
        for i in (1, 5, 9):  # three holes of 100 clusters
            vol.remove(f"/f{i:02d}")
        big = os.urandom(250 * 4096 + 7)  # needs 251 clusters: no hole is that large
        vol.write_file("/big.bin", big)
        node = vol._lookup("/big.bin")
        assert not node.no_fat_chain
        assert vol.read_file("/big.bin") == big
        with pytest.raises(BeastError, match="not enough free space"):
            vol.write_file("/too-big", bytes(200 * 4096))
        assert vol.read_file("/f00") == bytes([0]) * (100 * 4096)
    fsck(img)
    with opened(img) as vol:
        assert vol.read_file("/big.bin") == big
        vol.remove("/big.bin")  # frees the chain and its FAT entries
        assert all(vol._fat_get(c) == 0 for c in range(node.first_cluster, node.first_cluster + 3))
    fsck(img)


@needs_fsck
def test_dirty_flag_and_percent_in_use(tmp_path):
    img = formatted(tmp_path / "v.img", 16 * MIB)
    with opened(img) as vol:
        vol.write_file("/half", bytes(8 * MIB))
    boot = BootSector.parse(region(img, 0, 512))
    layout = plan_layout(16 * MIB)
    expected = (layout.used_clusters + 2048) * 100 // layout.boot.cluster_count
    assert boot.volume_flags == 0 and boot.percent_in_use == expected == 57
    # a volume that was already dirty (not cleanly unmounted) stays dirty
    data = bytearray(region(img, 0, 512))
    data[106] |= exfatfs.VOLUME_FLAG_DIRTY
    with open(img, "r+b") as f:
        f.write(data)
    with opened(img) as vol:
        assert vol.dirty
        vol.write_file("/x", b"x")
    assert BootSector.parse(region(img, 0, 512)).volume_flags & exfatfs.VOLUME_FLAG_DIRTY


def test_damaged_main_boot_region_falls_back_to_backup(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)
    with open(img, "r+b") as f:
        f.seek(5 * 512 + 100)  # inside an extended boot sector: only the checksum notices
        f.write(b"\x01")
    with opened(img) as vol:
        assert vol.label == LABEL and vol._boot_index == 1
        with pytest.raises(BeastError, match="main boot region is damaged"):
            vol.write_file("/x", b"x")
    with open(img, "r+b") as f:
        f.seek(12 * 512 + 3)
        f.write(b"NOTEXFAT")
    with pytest.raises(BeastError, match="no valid exFAT volume"):
        with opened(img):
            pass


def test_corrupted_entry_set_is_reported(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)
    with opened(img) as vol:
        vol.write_file("/file.txt", b"content")
        node = vol._lookup("/file.txt")
        offset = vol._cluster_offset(vol._dir_clusters(vol.root)[0]) + node.index * ENTRY_SIZE
    with open(img, "r+b") as f:
        f.seek(offset + 2 * ENTRY_SIZE + 2)  # first character of the name
        f.write(b"F")
    with opened(img) as vol, pytest.raises(BeastError, match="SetChecksum"):
        vol.listdir("/")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fill(vol: ExfatVolume, leave: int, path: str = "/filler.bin") -> None:
    """Write a file that leaves exactly `leave` clusters free."""
    vol.write_file(path, bytes((vol._bitmap.free_count() - leave) * vol.cluster_size))
    assert vol._bitmap.free_count() == leave


@needs_fsck
def test_full_volume_refuses_writes_and_changes_nothing(tmp_path):
    """No room left: BeastError, and not one byte written (not even the dirty flag)."""
    img = formatted(tmp_path / "v.img", 64 * MIB)  # 4 KiB clusters
    config = b"x" * 7600  # 2 data clusters, plus 1 for the new /beast-booter directory
    with opened(img) as vol:
        fill(vol, leave=2)
    fsck(img)
    before = sha256(img)
    with opened(img) as vol:
        refused = [
            lambda: vol.write_file("beast-booter/config.cfg", config),
            lambda: vol.write_file("newdir/sub/big.bin", bytes(80 * MIB)),  # larger than the volume
            lambda: vol.write_file("/three.bin", bytes(3 * 4096)),
            lambda: vol.mkdir("/a/b/c"),
        ]
        for attempt in refused:
            with pytest.raises(BeastError, match="not enough free space"):
                attempt()
        assert sha256(img) == before and vol._bitmap.free_count() == 2
        # the same object still allocates correctly: these fit exactly
        vol.write_file("other/small.txt", b"hello")
        assert vol._bitmap.free_count() == 0
        with pytest.raises(BeastError, match="not enough free space"):
            vol.write_file("/one-more", b"1")
        vol.write_file("/empty", b"")  # no data clusters, and the root has room for the entry set
        vol.remove("/filler.bin")
        vol.write_file("beast-booter/config.cfg", config)
    fsck(img)
    with opened(img) as vol:
        assert not vol.dirty
        assert vol.read_file("/beast-booter/config.cfg") == config
        assert vol.read_file("/other/small.txt") == b"hello"
        assert vol._bitmap.used_count() == plan_layout(64 * MIB).used_clusters + 2 + 3


@needs_fsck
def test_free_space_check_counts_directory_growth(tmp_path):
    # 1. the parent directory must grow by a cluster to take the new entry set
    img = formatted(tmp_path / "v.img", 64 * MIB)
    with opened(img) as vol:
        fill(vol, leave=2)
        i = 0
        while vol._free_slots(vol.root, 3)[1] == 0:  # empty files until the root is full
            vol.write_file(f"/e{i:03d}", b"")
            i += 1
        before = sha256(img)
        with pytest.raises(BeastError, match=r"\(3 clusters needed, 2 free\)"):
            vol.write_file("/x", bytes(2 * 4096))  # 2 data + 1 root growth
        assert sha256(img) == before
        vol.write_file("/x", bytes(4096))  # 1 data + 1 root growth
        assert vol._bitmap.free_count() == 0 and len(vol._dir_clusters(vol.root)) == 2
    fsck(img)
    # 2. a new directory must grow at once: 512-byte clusters hold 16 entries, a
    #    255-character name needs 19 (File + Stream Extension + 17 File Name entries)
    img = formatted(tmp_path / "small-clusters.img", 8 * MIB, cluster_size=512)
    name = "/new dir/" + "L" * 255
    with opened(img) as vol:
        fill(vol, leave=3)
        vol.write_file("/one", b"1")
        before = sha256(img)
        with pytest.raises(BeastError, match=r"\(3 clusters needed, 2 free\)"):
            vol.write_file(name, b"data")  # new dir 1 + its growth 1 + data 1
        assert sha256(img) == before
        vol.remove("/one")
        vol.write_file(name, b"data")
        assert vol._bitmap.free_count() == 0 and vol._lookup("/new dir").data_length == 2 * 512
    fsck(img)
    with opened(img) as vol:
        assert vol.read_file(name) == b"data"


@needs_fsck
def test_io_error_mid_write_keeps_the_volume_consistent_and_dirty(tmp_path):
    img = formatted(tmp_path / "v.img", 64 * MIB)
    base = plan_layout(64 * MIB).used_clusters
    dirty = exfatfs.VOLUME_FLAG_DIRTY
    with opened(img) as vol:
        # a failure before anything was written: the volume is marked clean again
        def broken_allocate(*args, **kw):
            raise OSError("simulated I/O error")

        vol._allocate = broken_allocate
        with pytest.raises(OSError):
            vol.write_file("/newdir/x", b"x")
        del vol._allocate
        assert not vol.dirty and vol._bitmap.used_count() == base
        assert BootSector.parse(region(img, 0, 512)).volume_flags & dirty == 0

        # a failure half-way: the new directories are on disk, the file data is not
        original = vol._write_clusters

        def broken_write(clusters, data):
            if data:
                raise OSError("simulated I/O error")
            original(clusters, data)

        vol._write_clusters = broken_write
        with pytest.raises(OSError):
            vol.write_file("/newdir/sub/f.bin", b"x" * 10_000)
        del vol._write_clusters
        # every cluster it allocated stays allocated (3 data clusters are lost until a
        # filesystem check), so a later write cannot hand out a directory's cluster again
        assert vol.dirty and vol._bitmap.used_count() == base + 2 + 3
        vol.write_file("/other/small.txt", b"hello")
    # ... and the volume stays marked dirty through that later, successful write
    assert BootSector.parse(region(img, 0, 512)).volume_flags & dirty
    fsck(img)  # no cluster is both in use and marked free, none is used twice
    with opened(img) as vol:
        assert vol.dirty and vol._bitmap.used_count() == base + 2 + 3 + 2
        assert vol.listdir("/newdir/sub") == []
        clusters = [vol._lookup(p).first_cluster for p in ("/newdir", "/newdir/sub", "/other", "/other/small.txt")]
        assert len(set(clusters)) == 4 and all(vol._bitmap.is_used(c) for c in clusters)
        assert vol.read_file("/other/small.txt") == b"hello"


# ---------------------------------------------------------------------------
# Interoperability with the Linux kernel driver (udisks loop mount, rootless)
# ---------------------------------------------------------------------------


class LoopMount:
    """Mount an image read-write through udisks; always unmounts and frees the loop device."""

    def __init__(self, image: Path, offset: int, size: int) -> None:
        self.image, self.offset, self.size = image, offset, size
        self.device: str | None = None
        self.mountpoint: Path | None = None

    def __enter__(self) -> Path:
        proc = self._udisks("loop-setup", "-f", str(self.image), "--offset", str(self.offset),
                            "--size", str(self.size))
        match = re.search(r"(/dev/loop\d+)", proc.stdout)
        if proc.returncode != 0 or not match:
            pytest.skip(f"udisks loop-setup not available: {(proc.stderr or proc.stdout).strip()}")
        self.device = match.group(1)
        try:
            error = ""
            deadline = time.monotonic() + 20
            while self.mountpoint is None and time.monotonic() < deadline:
                self.mountpoint = self._find_mountpoint()
                if self.mountpoint is None:  # a desktop session may auto-mount it first
                    error = self._udisks("mount", "-b", self.device).stderr.strip()
                    if "NotAuthorized" in error:
                        pytest.skip(f"udisks may not mount here: {error}")
                    time.sleep(0.2)
            if self.mountpoint is None:  # e.g. the kernel rejected the filesystem
                raise AssertionError(f"could not mount {self.device}: {error}")
            return self.mountpoint
        except BaseException:
            self._cleanup()
            raise

    def __exit__(self, *exc) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        if self.device is None:
            return
        os.sync()
        for _ in range(50):
            if self._find_mountpoint() is None:
                break
            self._udisks("unmount", "-b", self.device)
            time.sleep(0.1)
        name = self.device.rsplit("/", 1)[1]
        backing = Path(f"/sys/block/{name}/loop/backing_file")
        if backing.exists() and backing.read_text().strip() == str(self.image.resolve()):
            self._udisks("loop-delete", "-b", self.device)  # usually auto-cleared already
        self.device = None

    def _find_mountpoint(self) -> Path | None:
        for line in Path("/proc/mounts").read_text().splitlines():
            fields = line.split()
            if fields[0] == self.device:
                return Path(fields[1].encode().decode("unicode_escape"))
        return None

    @staticmethod
    def _udisks(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([UDISKSCTL, *args, "--no-user-interaction"], capture_output=True, text=True)


needs_kernel_mount = pytest.mark.skipif(
    UDISKSCTL is None or FSCK is None or not Path("/proc/mounts").exists(),
    reason="needs udisksctl, fsck.exfat and Linux")


@needs_kernel_mount
def test_kernel_reads_our_volume_and_we_read_the_kernels_files(tmp_path):
    size = 400 * MIB
    img = formatted(tmp_path / "v.img", size)
    rng = random.Random(1)
    ours = {
        "/beast-booter/config.cfg": b"set timeout=5\n",
        "/written by python/" + "long name " * 20 + ".bin": rng.randbytes(70_000),
        "/written by python/ünïcødé ✓.txt": "grüße".encode(),
        "/empty": b"",
    }
    with opened(img) as vol:
        for path, data in ours.items():
            vol.write_file(path, data)
    fsck(img)

    big = rng.randbytes(100 * MIB)
    with LoopMount(img, 0, size) as mnt:
        # the kernel sees what ExfatVolume wrote
        seen = walk_mounted(mnt)
        for path, data in ours.items():
            assert seen[path] == data, path
        # now the kernel writes: a 100 MiB file, nested directories, many entries,
        # and two files appended to in turn so their clusters interleave (FAT chains)
        (mnt / "ISOs" / "linux" / "nested deeper").mkdir(parents=True)
        (mnt / "ISOs" / "big.iso").write_bytes(big)
        for i in range(120):
            (mnt / "ISOs" / "linux" / f"entry {i:03d} with a longish name.txt").write_text(str(i))
        with open(mnt / "ISOs" / "frag-a", "wb") as fa, open(mnt / "ISOs" / "frag-b", "wb") as fb:
            for i in range(40):
                for f, tag in ((fa, b"a"), (fb, b"b")):
                    f.write(tag * 32768 + bytes([i]) * 100)
                    f.flush()
                    os.fsync(f.fileno())
        (mnt / "ISOs" / "linux" / "nested deeper" / "Ωmega.cfg").write_bytes(b"omega")
        (mnt / "written by python" / "ünïcødé ✓.txt").unlink()
        expected = walk_mounted(mnt)
    fsck(img)

    with opened(img) as vol:
        assert not vol.dirty
        got = walk(vol)
        assert got.keys() == expected.keys(), (f"only ExfatVolume sees {sorted(got.keys() - expected.keys())}, "
                                               f"only the kernel saw {sorted(expected.keys() - got.keys())}")
        for path in expected:
            assert got[path] == expected[path], path
        assert hashlib.sha256(got["/ISOs/big.iso"]).digest() == hashlib.sha256(big).digest()
        assert not vol._lookup("/ISOs/frag-a").no_fat_chain  # the kernel had to chain these
        # write into kernel-made directories (the 120-entry one may be FAT-chained)
        vol.write_file("/ISOs/linux/added by python.cfg", b"python")
        vol.write_file("/beast-booter/config.cfg", b"set timeout=10\n")
        for i in range(60):
            vol.write_file(f"/ISOs/linux/python {i:02d} with a long name to grow the dir.txt", b"p%d" % i)
        expected = walk(vol)
    fsck(img)

    with LoopMount(img, 0, size) as mnt:
        assert walk_mounted(mnt) == expected
    fsck(img)


@needs_kernel_mount
def test_kernel_mounts_a_volume_inside_a_disk_image(tmp_path):
    """Like the real drive: the exFAT volume at 1 MiB in a larger image."""
    disk = sparse_image(tmp_path / "disk.img", 512 * MIB)
    offset, size = 1 * MIB, 447 * MIB
    t = FileTarget(disk)
    format_exfat(t, offset, size, label=LABEL, volume_serial=SERIAL)
    ExfatVolume(t, offset).write_file("/beast-booter/config.cfg", b"set timeout=1\n")
    t.close()
    with LoopMount(disk, offset, size) as mnt:
        assert (mnt / "beast-booter" / "config.cfg").read_bytes() == b"set timeout=1\n"
        (mnt / "hello.txt").write_text("hello")
    t = FileTarget(disk)
    try:
        assert ExfatVolume(t, offset).read_file("/hello.txt") == b"hello"
    finally:
        t.close()


@needs_kernel_mount
def test_volume_filled_by_the_kernel_refuses_writes_cleanly(tmp_path):
    """The installer's real case: the user filled the drive, then config.cfg is updated."""
    size = 64 * MIB
    img = formatted(tmp_path / "v.img", size)
    with LoopMount(img, 0, size) as mnt:
        (mnt / "one-cluster").write_bytes(b"1")
        chunk = bytes(1 * MIB)
        with open(mnt / "big.iso", "wb", buffering=0) as f:
            try:
                while f.write(chunk) == len(chunk):
                    pass
                f.write(chunk)  # after a short write, this one fails with ENOSPC
            except OSError:
                pass
            os.fsync(f.fileno())
        (mnt / "one-cluster").unlink()
        os.sync()
        assert os.statvfs(mnt).f_bavail == 1  # exactly one free cluster
    fsck(img)
    before = sha256(img)
    with opened(img) as vol:
        assert vol._bitmap.free_count() == 1
        with pytest.raises(BeastError, match=r"not enough free space .*\(3 clusters needed, 1 free\)"):
            vol.write_file("beast-booter/config.cfg", b"x" * 7600)
        assert sha256(img) == before  # nothing written, not even the dirty flag
        vol.write_file("/note.txt", b"fits in the last cluster")
    fsck(img)
    with LoopMount(img, 0, size) as mnt:
        assert sorted(p.name for p in mnt.iterdir()) == ["big.iso", "note.txt"]
        assert (mnt / "note.txt").read_bytes() == b"fits in the last cluster"
    fsck(img)
