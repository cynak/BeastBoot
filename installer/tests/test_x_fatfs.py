"""Pure-Python FAT12/16/32 (fatfs.py), checked with independent tools.

fsck.fat, blkid, mtools (both directions), mkfs.fat (same geometry choices)
and, when udisks allows a rootless loop mount, the Linux kernel's vfat driver.
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
from contextlib import contextmanager
from pathlib import Path

import pytest

from beastbooter import fatfs
from beastbooter.errors import BeastError
from beastbooter.fatfs import FatVolume, build_esp, fat_geometry, format_fat
from beastbooter.interfaces import DirEntry, format_volume_id
from beastbooter.layout import ESP_FAT_BITS, ESP_LABEL, ESP_SIZE_SECTORS, MIB, MIN_DISK_MIB, SECTOR_SIZE
from beastbooter.parttable import write_partition_table
from beastbooter.plan import make_plan

REPO = Path(__file__).resolve().parents[2]
DIST_ESP = REPO / "dist" / "esp"
ESP_SIZE = ESP_SIZE_SECTORS * SECTOR_SIZE
GIB = 1 << 30
TIB = 1 << 40
VID = 0x1A2B3C4D
DISK_SIZE = MIN_DISK_MIB * MIB + 300_001  # the smallest disk, plus a tail that is not a whole sector
ODD_SIZE = 300_000_001  # a FAT32 volume size that is odd on purpose
MTOOLS_ENV = {**os.environ, "MTOOLS_SKIP_CHECK": "1", "MTOOLSRC": "/dev/null", "LC_ALL": "C.UTF-8"}

needs_fsck = pytest.mark.skipif(shutil.which("fsck.fat") is None, reason="fsck.fat not installed")
needs_blkid = pytest.mark.skipif(shutil.which("blkid") is None, reason="blkid not installed")
needs_mkfs = pytest.mark.skipif(shutil.which("mkfs.fat") is None, reason="mkfs.fat not installed")
needs_mtools = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("mdir", "mtype", "mcopy", "mmd")),
    reason="mtools not on PATH (source scripts/dev-env.sh)",
)


class ImageFile:
    """Minimal BlockTarget over a (sparse) image file, recording its writes."""

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

    @property
    def written(self) -> int:
        return sum(n for _off, n in self.writes)


class SectorImage(ImageFile):
    """Behaves like a raw device: only whole, aligned sectors may be read or written."""

    def read(self, offset: int, length: int) -> bytes:
        assert offset % SECTOR_SIZE == 0 and length % SECTOR_SIZE == 0, ("unaligned read", offset, length)
        return super().read(offset, length)

    def write(self, offset: int, data: bytes) -> None:
        assert offset % SECTOR_SIZE == 0 and len(data) % SECTOR_SIZE == 0, ("unaligned write", offset, len(data))
        super().write(offset, data)


# ---------------------------------------------------------------------------
# Tool helpers
# ---------------------------------------------------------------------------


def run(*cmd, check=True, env=None, text=True) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=text, check=check, env=env)


def spec(img: Path, offset: int) -> str:
    return f"{img}@@{offset}" if offset else str(img)


def fsck_clean(img: Path, offset: int = 0, size: int | None = None, tmp: Path | None = None) -> str:
    """fsck.fat -n -V must find nothing. A volume inside a disk image is copied out first."""
    if offset or size is not None:
        assert tmp is not None
        part = tmp / f"part-{offset}.img"
        with open(img, "rb") as src, open(part, "wb") as dst:
            src.seek(offset)
            left = size
            while left:
                chunk = src.read(min(left, 1 << 22))
                assert chunk
                dst.write(chunk)
                left -= len(chunk)
        img = part
    proc = run("fsck.fat", "-n", "-V", img, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    lines = [line for line in out.splitlines() if line.strip()]
    noise = ("fsck.fat ", "Starting check/repair pass.", "Starting verification pass.")
    problems = [line for line in lines if not line.startswith(noise) and not re.match(r".*: \d+ files, \d+/\d+ clusters$", line)]
    assert problems == [], out
    return out


def blkid(img: Path, offset: int = 0) -> dict[str, str]:
    out = run("blkid", "-p", "-O", offset, "-o", "export", img).stdout
    pairs = (line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {k: re.sub(r"\\(.)", r"\1", v) for k, v in pairs}


def mdir_tree(img: Path, offset: int = 0) -> tuple[set[str], set[str]]:
    """(files, directories) as mtools lists them recursively, without leading '/'."""
    out = run("mdir", "-/", "-b", "-i", spec(img, offset), "::/", env=MTOOLS_ENV).stdout
    files, dirs = set(), set()
    for line in out.splitlines():
        if line.startswith("::/"):
            path = line[3:]
            (dirs if path.endswith("/") else files).add(path.rstrip("/"))
    return files, dirs


def mtype(img: Path, offset: int, path: str) -> bytes:
    literal = re.sub(r"([\\\[\]*?])", r"\\\1", path)  # mtools globs [ ] * ? in source names
    return run("mtype", "-i", spec(img, offset), f"::/{literal}", env=MTOOLS_ENV, text=False).stdout


def mdir_raw(img: Path, offset: int, path: str = "") -> str:
    return run("mdir", "-i", spec(img, offset), f"::/{path}", env=MTOOLS_ENV).stdout


def content(path: str, size: int) -> bytes:
    return random.Random(path).randbytes(size)


def dirs_of(paths) -> set[str]:
    out = set()
    for p in paths:
        parts = p.split("/")[:-1]
        out.update("/".join(parts[: i + 1]) for i in range(len(parts)))
    return out


def new_volume(tmp_path: Path, size: int, bits: int, *, label="TESTVOL", name="vol.img", **kw) -> ImageFile:
    t = ImageFile(tmp_path / name, size)
    format_fat(t, 0, size, fat_bits=bits, label=label, volume_id=VID, hidden_sectors=2048, **kw)
    return t


# A tree with every kind of name: plain 8.3, lower case, spaces, many dots,
# 8.3 alias collisions, Unicode, LFN-only punctuation, a leading dot, a 254
# character name, deep nesting; sizes around cluster boundaries.
TREE = {
    "README.TXT": 100,
    "readme2.txt": 0,
    "Mixed Case Name With Spaces.data": 5000,
    "multiple.dots.in.name.tar.gz": 1,
    "longfilename1.txt": 2048,
    "longfilename2.txt": 2049,
    "longfilename3.txt": 7,
    "ünïcödé-файл-日本.txt": 33,
    "+plus,comma;semi=eq[brackets].txt": 12,
    ".hidden": 3,
    "n" * 250 + ".bin": 1,
    "EFI/BOOT/BOOTX64.EFI": 70_000,
    "EFI/BOOT/grubx64.efi": 150_001,
    "grub/i386-pc/normal.mod": 30_000,
    "deep/a/b/c/d/e/f/file.cfg": 10,
    "Deep Folder Name/Sub Folder/x.y.z": 4097,
}


# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------

# Microsoft's tables (fatgen103), the same values Windows and mkfs.fat use for FAT32.
TABLE = [
    (16, 15 * MIB, 2), (16, 16 * MIB, 4), (16, 64 * MIB, 4), (16, 128 * MIB, 4), (16, 129 * MIB, 8),
    (16, 256 * MIB, 8), (16, 300 * MIB, 16), (16, 512 * MIB, 16), (16, GIB, 32), (16, 2 * GIB - MIB, 64),
    (32, 64 * MIB, 1), (32, 260 * MIB, 1), (32, 261 * MIB, 8), (32, ESP_SIZE, 8), (32, 8 * GIB, 8), (32, 8 * GIB + MIB, 16),
    (32, 16 * GIB, 16), (32, 32 * GIB, 32), (32, 32 * GIB + MIB, 64), (32, 2 * TIB - SECTOR_SIZE, 64),
    (12, MIB, 1), (12, 3 * MIB, 2), (12, 16 * MIB, 16),
]


@pytest.mark.parametrize("bits,size,spc", TABLE, ids=[f"fat{b}-{s}" for b, s, _ in TABLE])
def test_cluster_size_table(bits, size, spc):
    g = fat_geometry(size // SECTOR_SIZE, bits)
    assert g.sectors_per_cluster == spc
    assert fatfs.MIN_CLUSTERS[bits] <= g.cluster_count <= fatfs.MAX_CLUSTERS[bits]
    assert g.fat_sectors * SECTOR_SIZE * 8 // bits >= g.cluster_count + 2  # an entry per cluster
    assert g.data_start_sector % spc == 0  # clusters aligned to their size
    assert g.reserved_sectors >= (32 if bits == 32 else 1)
    assert g.root_entries == (0 if bits == 32 else max(512, spc * 16))


def test_fat_type_thresholds():
    """Cluster counts never leave the spec's range: the next cluster size is used instead."""
    for bits in (12, 16, 32):
        lo, hi = fatfs.MIN_CLUSTERS[bits], fatfs.MAX_CLUSTERS[bits]
        for sectors in range(2048 if bits == 12 else 8192, 1 << (14 if bits == 12 else 22), 7919):
            try:
                g = fat_geometry(sectors, bits)
            except BeastError:
                continue
            assert lo <= g.cluster_count <= hi
    with pytest.raises(BeastError, match="too small for FAT16"):
        fat_geometry(2 * MIB // SECTOR_SIZE, 16)
    with pytest.raises(BeastError, match="too small for FAT32"):
        fat_geometry(32 * MIB // SECTOR_SIZE, 32)
    with pytest.raises(BeastError, match="too large for FAT16"):
        fat_geometry(4 * GIB // SECTOR_SIZE, 16)
    with pytest.raises(BeastError, match="too large for FAT12"):
        fat_geometry(256 * MIB // SECTOR_SIZE, 12)
    with pytest.raises(BeastError, match="at most 2 TiB"):
        fat_geometry(2 * TIB // SECTOR_SIZE, 32)
    with pytest.raises(BeastError, match="invalid FAT cluster size"):
        fat_geometry(GIB // SECTOR_SIZE, 32, cluster_size=3000)
    assert fat_geometry(2 * GIB // SECTOR_SIZE, 32, cluster_size=16384).sectors_per_cluster == 32
    with pytest.raises(BeastError, match="too small for FAT32 with 16384-byte clusters"):
        fat_geometry(GIB // SECTOR_SIZE, 32, cluster_size=16384)  # < 65525 clusters


def _bpb(raw: bytes) -> dict:
    keys = "bps spc rsvd nfats rootent tot16 media fatsz16 spt heads hidden tot32".split()
    d = dict(zip(keys, struct.unpack_from("<HBHBHHBHHHII", raw, 11)))
    d["fatsz"] = d["fatsz16"] or struct.unpack_from("<I", raw, 36)[0]
    return d


@needs_mkfs
@pytest.mark.parametrize("bits,size", [(16, 64 * MIB), (32, 64 * MIB), (32, 300 * MIB), (32, ESP_SIZE), (32, GIB),
                                       (32, 9 * GIB), (32, 33 * GIB)])
def test_same_choices_as_mkfs_fat(tmp_path, bits, size):
    ref_img = tmp_path / "ref.img"
    ImageFile(ref_img, size).close()
    run("mkfs.fat", "-F", bits, "-n", "BEAST", "-h", 2048, "-i", "1A2B3C4D", ref_img)
    with open(ref_img, "rb") as f:
        ref = _bpb(f.read(SECTOR_SIZE))
    t = new_volume(tmp_path, size, bits, label="BEAST")
    ours = _bpb(t.read(0, SECTOR_SIZE))
    t.close()
    for k in ("bps", "spc", "rsvd", "nfats", "rootent", "media", "hidden"):
        assert ours[k] == ref[k], k
    if (ref["tot16"] or ref["tot32"]) == size // SECTOR_SIZE:
        assert ours["fatsz"] == ref["fatsz"]  # mkfs.fat sometimes trims the size to whole tracks


@needs_mkfs
def test_esp_boot_sector_matches_mkfs_fat(tmp_path):
    """The 512 MiB FAT32 ESP as build_esp makes it: same BPB and extended BPB as
    `mkfs.fat -F 32` (bar the CHS heads field and the total sector count)."""
    assert ESP_FAT_BITS == 32
    ref_img = tmp_path / "ref.img"
    ImageFile(ref_img, ESP_SIZE).close()
    run("mkfs.fat", "-F", 32, "-n", ESP_LABEL, "-h", 4061184, "-i", f"{VID:08X}", ref_img)
    ref = open(ref_img, "rb").read(SECTOR_SIZE)
    t = ImageFile(tmp_path / "esp.img", ESP_SIZE)
    build_esp(t, 0, ESP_SIZE, {}, label=ESP_LABEL, volume_id=VID, hidden_sectors=4061184)
    ours = t.read(0, SECTOR_SIZE)
    t.close()
    assert ours[:3] == ref[:3] == b"\xeb\x58\x90"
    assert ours[11:26] == ref[11:26]  # bytes/sector .. sectors per track
    assert ours[28:32] == ref[28:32]  # hidden sectors
    # Total sectors: ours is the whole partition; mkfs.fat trims a few sectors off a FAT32 volume.
    assert struct.unpack_from("<I", ours, 32)[0] == ESP_SIZE_SECTORS
    assert ours[36:90] == ref[36:90]  # FAT size, root cluster, FSInfo, backup, drive, boot sig, id, label, "FAT32   "
    assert ours[82:90] == b"FAT32   "
    assert ours[510:] == ref[510:] == b"\x55\xaa"


# ---------------------------------------------------------------------------
# Formatting: fsck, blkid, quick format
# ---------------------------------------------------------------------------

VOLUMES = [
    ("fat12-1MiB", MIB, 12),
    ("fat12-3MiB-odd", 3 * MIB + 3 * SECTOR_SIZE + 100, 12),
    ("fat16-5MiB", 5 * MIB, 16),
    ("fat16-64MiB", 64 * MIB, 16),
    ("fat16-300MiB", 300 * MIB, 16),
    ("fat16-2GiB-1MiB", 2 * GIB - MIB, 16),
    ("fat32-33MiB", 33 * MIB, 32),
    ("fat32-odd", ODD_SIZE, 32),
    ("fat32-esp", ESP_SIZE, 32),
    ("fat32-1GiB-odd", GIB + 12_345 * SECTOR_SIZE, 32),
    ("fat32-8GiB+1MiB", 8 * GIB + MIB, 32),
    ("fat32-32GiB+1MiB", 32 * GIB + MIB, 32),
    ("fat32-128GiB", 128 * GIB, 32),
]


@needs_fsck
@needs_blkid
@needs_mtools
@pytest.mark.parametrize("name,size,bits", VOLUMES, ids=[v[0] for v in VOLUMES])
def test_format_is_clean(tmp_path, name, size, bits):
    label = "BEASTBOOTER" if bits == 32 else "BEAST-EFI"
    t = ImageFile(tmp_path / "vol.img", size)
    format_fat(t, 0, size, fat_bits=bits, label=label, volume_id=VID, hidden_sectors=2048)
    g = fat_geometry(size // SECTOR_SIZE, bits)
    root = g.cluster_size if bits == 32 else g.root_dir_sectors * SECTOR_SIZE
    # Quick format: reserved area + FATs + root directory, nothing else.
    assert t.written == (g.reserved_sectors + g.num_fats * g.fat_sectors) * SECTOR_SIZE + root
    fsck_clean(tmp_path / "vol.img")
    probe = blkid(tmp_path / "vol.img")
    assert probe["TYPE"] == "vfat" and probe["VERSION"] == f"FAT{bits}"
    assert probe["LABEL"] == label and probe["UUID"] == format_volume_id(VID) == "1A2B-3C4D"

    vol = FatVolume(t, 0)
    assert (vol.fat_bits, vol.label, vol.volume_id, vol.hidden_sectors) == (bits, label, VID, 2048)
    assert vol.cluster_size == g.cluster_size and vol.cluster_count == g.cluster_count
    assert vol.listdir("/") == []
    # A few writes, then everything must still be clean and readable by mtools.
    files = {"beast-booter/config.cfg": b"set timeout=5\n", "Big File.bin": content("big", 3 * g.cluster_size + 5)}
    for path, data in files.items():
        vol.write_file(path, data)
    assert vol.free_bytes() == (g.cluster_count - (1 if bits == 32 else 0) - 1 - 1 - 4) * g.cluster_size
    t.close()
    fsck_clean(tmp_path / "vol.img")
    for path, data in files.items():
        assert mtype(tmp_path / "vol.img", 0, path) == data
    if size > 8 * GIB:
        assert os.stat(tmp_path / "vol.img").st_blocks * 512 < 64 * MIB  # still sparse


def test_fat32_reserved_area(tmp_path):
    t = new_volume(tmp_path, GIB, 32, label="BEASTBOOTER")
    g = fat_geometry(GIB // SECTOR_SIZE, 32)
    boot, info = t.read(0, SECTOR_SIZE), t.read(SECTOR_SIZE, SECTOR_SIZE)
    assert boot[:3] == b"\xeb\x58\x90" and boot[3:11] == b"MSWIN4.1" and boot[510:] == b"\x55\xaa"
    assert struct.unpack_from("<IHHIHH", boot, 36) == (g.fat_sectors, 0, 0, 2, 1, 6)
    assert boot[0x40:0x43] == b"\x80\x00\x29" and boot[0x52:0x5A] == b"FAT32   "
    assert boot[0x5A : 0x5A + len(fatfs.BOOT_STUB)] == fatfs.BOOT_STUB
    assert t.read(6 * SECTOR_SIZE, SECTOR_SIZE) == boot and t.read(7 * SECTOR_SIZE, SECTOR_SIZE) == info
    assert struct.unpack_from("<I", info, 0)[0] == 0x41615252
    assert struct.unpack_from("<III", info, 484) == (0x61417272, g.cluster_count - 1, 2)
    assert struct.unpack_from("<I", info, 508)[0] == 0xAA550000
    fat = t.read(g.reserved_sectors * SECTOR_SIZE, 16)
    assert fat[:12] == b"\xf8\xff\xff\x0f\xff\xff\xff\x0f\xff\xff\xff\x0f" and fat[12:] == bytes(4)
    t.close()


def test_label_rules(tmp_path):
    assert fatfs.label_bytes("beast-efi") == b"BEAST-EFI  "
    assert fatfs.label_bytes("") == b"NO NAME    "
    assert fatfs.label_bytes("MY DRIVE") == b"MY DRIVE   "
    for bad in ("TWELVE_CHARS", "a.b", "x/y", " LEAD", "ÄÖÜ"):
        with pytest.raises(BeastError, match="invalid FAT label"):
            fatfs.label_bytes(bad)
    t = new_volume(tmp_path, 5 * MIB, 16, label="")
    assert FatVolume(t, 0).label == ""
    t.close()


# ---------------------------------------------------------------------------
# build_esp with the real boot files
# ---------------------------------------------------------------------------


def _synthetic_esp() -> dict[str, bytes]:
    """Stand-in shaped like dist/esp (~330 files) when the real build is missing."""
    rnd = random.Random(1)
    files = {
        "EFI/BOOT/BOOTX64.EFI": rnd.randbytes(966_768),
        "EFI/BOOT/mmx64.efi": rnd.randbytes(856_280),
        "EFI/BOOT/grubx64.efi": rnd.randbytes(1_406_584),
        "ENROLL_THIS_KEY_IN_MOKMANAGER.cer": rnd.randbytes(869),
        "grub/grub.cfg": b"source $prefix/beast/main.cfg\n",
        "grub/fonts/unicode.pf2": rnd.randbytes(2_400_000),
    }
    for i in range(12):
        files[f"grub/beast/part{i}.cfg"] = rnd.randbytes(rnd.randint(100, 9000))
    for i in range(300):
        files[f"grub/i386-pc/module_{i:03d}_{'x' * (i % 17)}.mod"] = rnd.randbytes(rnd.randint(500, 60_000))
    return files


@pytest.fixture(scope="module")
def esp_files() -> dict[str, bytes]:
    if (DIST_ESP / "EFI" / "BOOT").is_dir():
        files = {p.relative_to(DIST_ESP).as_posix(): p.read_bytes()
                 for p in sorted(DIST_ESP.rglob("*")) if p.is_file()}
    else:
        files = _synthetic_esp()
    files["grub/beast/device.cfg"] = b'set bb_install_id="test"\nset bb_layout="msdos"\n'
    files["BEAST-BOOTER.ID"] = b"beast-booter\ninstall_id=test\nlayout_version=1\nversion=0.1.0\n"
    return files


@needs_fsck
@needs_blkid
@needs_mtools
def test_build_esp_real_tree(tmp_path, esp_files):
    img = tmp_path / "disk.img"
    plan = make_plan(DISK_SIZE // SECTOR_SIZE, "msdos")
    esp = plan.esp
    t = ImageFile(img, DISK_SIZE)
    write_partition_table(t, plan, "exfat")
    t.writes.clear()
    start = time.monotonic()
    build_esp(t, esp.offset, esp.size_bytes, esp_files, label=ESP_LABEL, volume_id=VID,
              hidden_sectors=esp.start)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"build_esp took {elapsed:.2f} s"
    assert all(esp.offset <= off and off + n <= esp.offset + esp.size_bytes for off, n in t.writes)
    assert len(t.writes) < len(esp_files) + 50  # one write per file, plus metadata

    probe = blkid(img, esp.offset)
    assert (probe["TYPE"], probe["VERSION"], probe["LABEL"]) == ("vfat", "FAT32", ESP_LABEL)
    assert probe["UUID"] == format_volume_id(VID)

    files, dirs = mdir_tree(img, esp.offset)
    assert files == set(esp_files)
    assert dirs == dirs_of(esp_files)
    for path, data in esp_files.items():
        assert mtype(img, esp.offset, path) == data, path

    vol = FatVolume(t, esp.offset)
    assert (vol.fat_bits, vol.label, vol.volume_id, vol.hidden_sectors) == (32, ESP_LABEL, VID, esp.start)
    for path, data in esp_files.items():
        assert vol.read_file(path) == data
    assert vol.read_file("efi/boot/bootx64.efi") == esp_files["EFI/BOOT/BOOTX64.EFI"]  # case-insensitive
    t.close()
    fsck_clean(img, esp.offset, esp.size_bytes, tmp_path)


def test_build_esp_is_reproducible(tmp_path, esp_files):
    digests = []
    for name, ts in (("a", None), ("b", None), ("c", 1_760_000_000)):
        t = ImageFile(tmp_path / f"{name}.img", ESP_SIZE)
        build_esp(t, 0, ESP_SIZE, esp_files, label=ESP_LABEL, volume_id=VID, hidden_sectors=2048, timestamp=ts)
        t.close()
        digests.append(hashlib.sha256((tmp_path / f"{name}.img").read_bytes()).hexdigest())
    assert digests[0] == digests[1]
    assert digests[2] != digests[0]


def test_build_esp_too_big(tmp_path):
    t = ImageFile(tmp_path / "esp.img", ESP_SIZE)
    blob = bytes(4 * MIB)  # shared by every file: over 512 MiB of content in 4 MiB of memory
    files = {f"big{i}.bin": blob for i in range(ESP_SIZE // len(blob) + 1)}
    with pytest.raises(BeastError, match=rf"do not fit into the {ESP_SIZE / MIB:.1f} MiB ESP"):
        build_esp(t, 0, ESP_SIZE, files, label=ESP_LABEL, volume_id=VID, hidden_sectors=2048)
    assert FatVolume(t, 0).listdir("") == []  # nothing half-written became visible
    t.close()


# ---------------------------------------------------------------------------
# Interop with mtools, both ways
# ---------------------------------------------------------------------------


def _mtools_populate(img: Path, tree: dict[str, int], tmp: Path) -> dict[str, bytes]:
    data = {path: content(path, size) for path, size in tree.items()}
    for d in sorted(dirs_of(tree), key=lambda p: p.count("/")):
        run("mmd", "-i", img, f"::/{d}", env=MTOOLS_ENV)
    src = tmp / "src.bin"
    for path, blob in data.items():
        src.write_bytes(blob)
        run("mcopy", "-i", img, "-o", src, f"::/{path}", env=MTOOLS_ENV)
    return data


def _check_listing(vol: FatVolume, data: dict[str, bytes], empty_dirs: tuple[str, ...] = ()) -> None:
    want: dict[str, set[tuple[str, bool, int]]] = {d: set() for d in empty_dirs}
    for path, blob in [*data.items(), *((f"{d}/", b"") for d in empty_dirs)]:
        parts = path.split("/")
        for i in range(len(parts)):
            parent = "/".join(parts[:i])
            is_dir = i < len(parts) - 1
            if parts[i]:
                want.setdefault(parent, set()).add((parts[i], is_dir, 0 if is_dir else len(blob)))
    for parent, entries in want.items():
        assert {(e.name, e.is_dir, e.size) for e in vol.listdir(parent)} == entries, parent


@needs_mkfs
@needs_mtools
@pytest.mark.parametrize("bits,size", [(12, 2 * MIB), (16, 20 * MIB), (32, 40 * MIB)], ids=["fat12", "fat16", "fat32"])
def test_fatvolume_reads_what_mtools_wrote(tmp_path, bits, size):
    img = tmp_path / "vol.img"
    ImageFile(img, size).close()
    run("mkfs.fat", "-F", bits, "-n", "MTOOLS", "-i", "CAFE0001", img)
    data = _mtools_populate(img, TREE, tmp_path)
    t = ImageFile(img)
    vol = FatVolume(t, 0)
    assert (vol.fat_bits, vol.label, vol.volume_id) == (bits, "MTOOLS", 0xCAFE0001)
    for path, blob in data.items():
        assert vol.read_file(path) == blob, path
        if path.isascii():
            assert vol.read_file(path.upper()) == blob  # case-insensitive lookup
    _check_listing(vol, data)
    assert vol.exists("deep/a/b") and not vol.exists("deep/nope") and vol.exists("")
    t.close()


@needs_fsck
@needs_mkfs
@needs_mtools
@pytest.mark.parametrize("bits,size,formatter", [
    (12, 2 * MIB, "ours"), (16, 20 * MIB, "ours"), (32, 40 * MIB, "ours"),
    (16, 20 * MIB, "mkfs.fat"), (32, 40 * MIB, "mkfs.fat"),
], ids=["fat12", "fat16", "fat32", "fat16-mkfs", "fat32-mkfs"])
def test_mtools_reads_what_fatvolume_wrote(tmp_path, bits, size, formatter):
    img = tmp_path / "vol.img"
    if formatter == "ours":
        t = new_volume(tmp_path, size, bits)
    else:
        ImageFile(img, size).close()
        run("mkfs.fat", "-F", bits, "-n", "TESTVOL", "-i", "1A2B3C4D", img)
        t = ImageFile(img)
    vol = FatVolume(t, 0)
    data = {path: content(path, n) for path, n in TREE.items()}
    for path, blob in data.items():  # one transaction each
        vol.write_file(path, blob)
    vol.mkdir("empty/dir")
    vol.mkdir("empty/dir")  # existing: fine
    # Replace: bigger, smaller, empty; remove a file and a whole tree.
    data["EFI/BOOT/grubx64.efi"] = content("bigger", 200_000)
    data["longfilename2.txt"] = b"short now"
    data["Mixed Case Name With Spaces.data"] = b""
    for path in ("EFI/BOOT/grubx64.efi", "longfilename2.txt", "Mixed Case Name With Spaces.data"):
        vol.write_file(path, data[path])
    vol.remove("README.TXT")
    del data["README.TXT"]
    vol.remove("deep", recursive=True)
    data = {p: b for p, b in data.items() if not p.startswith("deep/")}
    t.close()

    fsck_clean(img)
    files, dirs = mdir_tree(img)
    assert files == set(data)
    assert dirs == dirs_of(data) | {"empty", "empty/dir"}
    for path, blob in data.items():
        assert mtype(img, 0, path) == blob, path
    listing = mdir_raw(img, 0)
    for k in (1, 2, 3):  # generated 8.3 aliases, long names intact (so the checksums are right)
        assert re.search(rf"^LONGFI~{k} TXT .* longfilename{k}\.txt$", listing, re.M), listing
    assert re.search(r"^README +TXT", listing, re.M) is None  # README.TXT was removed

    t = ImageFile(img)
    vol = FatVolume(t, 0)
    for path, blob in data.items():
        assert vol.read_file(path) == blob
    _check_listing(vol, data, ("empty", "empty/dir"))
    t.close()


@needs_fsck
@needs_mtools
def test_write_files_batch_into_existing_volume(tmp_path):
    t = new_volume(tmp_path, 40 * MIB, 32)
    vol = FatVolume(t, 0)
    vol.write_file("keep/me.txt", b"keep")
    batch = {f"grub/i386-pc/mod_{i:03d}_with_a_long_name.mod": content(str(i), i * 97) for i in range(150)}
    batch["keep/new.txt"] = b"new"
    vol.write_files(batch)
    t.close()
    fsck_clean(tmp_path / "vol.img")
    files, _dirs = mdir_tree(tmp_path / "vol.img")
    assert files == set(batch) | {"keep/me.txt"}
    for path in list(batch)[::25]:
        assert mtype(tmp_path / "vol.img", 0, path) == batch[path]


# ---------------------------------------------------------------------------
# Names and timestamps
# ---------------------------------------------------------------------------


def test_short_name_rules():
    assert fatfs.plain_short_name("BOOTX64.EFI") == b"BOOTX64 EFI"
    assert fatfs.plain_short_name("EFI") == b"EFI        "
    assert fatfs.plain_short_name("LONGFI~1.TXT") == b"LONGFI~1TXT"
    for name in ("bootx64.efi", "A.B.C", "TOOLONGNAME.TXT", "ABC.TOOL", ".HIDDEN", "A B.TXT", "A+B.TXT"):
        assert fatfs.plain_short_name(name) is None, name
    assert fatfs._basis_name("grubx64.efi") == ("GRUBX64", "EFI", False)
    assert fatfs._basis_name("ENROLL_THIS_KEY_IN_MOKMANAGER.cer") == ("ENROLL_T", "CER", True)
    assert fatfs._basis_name("multiple.dots.tar.gz") == ("MULTIPLE", "GZ", True)
    assert fatfs._basis_name(".hidden") == ("HIDDEN", "", True)
    assert fatfs._basis_name("a+b c.txt") == ("A_BC", "TXT", True)


def test_lfn_checksum_matches_reference():
    def rotate_right(name11: bytes) -> int:  # the spec's formulation
        s = 0
        for c in name11:
            s = ((s >> 1) | ((s & 1) << 7)) + c
            s &= 0xFF
        return s

    rnd = random.Random(7)
    for _ in range(200):
        name = bytes(rnd.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_~ ") for _ in range(11))
        assert fatfs.lfn_checksum(name) == rotate_right(name)


def test_long_name_entries_layout():
    name = "ENROLL_THIS_KEY_IN_MOKMANAGER.cer"  # 33 characters -> 3 entries
    raw = fatfs._lfn_entries(name, 0x5A)
    assert len(raw) == 3 * 32
    first, last = raw[:32], raw[64:]
    assert first[0] == 0x43 and last[0] == 0x01  # ordinal 3 | LAST flag first on disk
    assert all(raw[i * 32 + 11] == 0x0F and raw[i * 32 + 13] == 0x5A and raw[i * 32 + 26 : i * 32 + 28] == b"\0\0"
               for i in range(3))
    chars = b"".join(e[1:11] + e[14:26] + e[28:32] for e in (raw[64:], raw[32:64], raw[:32]))
    assert chars[: len(name) * 2].decode("utf-16-le") == name
    assert chars[len(name) * 2 : len(name) * 2 + 2] == b"\0\0" and set(chars[len(name) * 2 + 2 :]) == {0xFF}
    exact = fatfs._lfn_entries("x" * 13, 1)  # exactly one entry: no terminator, no padding
    assert len(exact) == 32 and (exact[1:11] + exact[14:26] + exact[28:32]).decode("utf-16-le") == "x" * 13


@needs_mtools
def test_timestamps(tmp_path):
    ts = 1_715_000_000  # 2024-05-06 12:53:20 UTC
    t = ImageFile(tmp_path / "vol.img", 20 * MIB)
    format_fat(t, 0, 20 * MIB, fat_bits=16, label="DATED", volume_id=VID, hidden_sectors=0, timestamp=ts)
    FatVolume(t, 0, timestamp=ts).write_file("dir/a.txt", b"x")
    FatVolume(t, 0).write_file("b.txt", b"y")
    t.close()
    root = mdir_raw(tmp_path / "vol.img", 0)
    assert re.search(r"^DIR +<DIR> +2024-05-06 +12:53", root, re.M), root
    assert re.search(r"^B +TXT +1 1980-01-01 +0:00", root, re.M), root
    assert re.search(r"^A +TXT +1 2024-05-06 +12:53", mdir_raw(tmp_path / "vol.img", 0, "dir"), re.M)
    assert fatfs._stamp(ts) == ((44 << 9) | (5 << 5) | 6, (12 << 11) | (53 << 5) | 10, 0)
    assert fatfs._stamp(0) == fatfs._stamp(None) == ((0 << 9) | (1 << 5) | 1, 0, 0)  # clamped to 1980
    assert fatfs._stamp(1 << 40)[0] >> 9 == 127  # clamped to 2107


# ---------------------------------------------------------------------------
# Errors, rollback, odd cases
# ---------------------------------------------------------------------------


def test_errors(tmp_path):
    t = new_volume(tmp_path, 5 * MIB, 16)
    vol = FatVolume(t, 0)
    vol.write_file("dir/file.txt", b"data")
    with pytest.raises(BeastError, match="no such file"):
        vol.read_file("dir/missing.txt")
    with pytest.raises(BeastError, match="no such directory"):
        vol.listdir("nope")
    with pytest.raises(BeastError, match="is a file, not a directory"):
        vol.listdir("dir/file.txt")
    with pytest.raises(BeastError, match="is a file, not a directory"):
        vol.write_file("dir/file.txt/x", b"")
    with pytest.raises(BeastError, match="is a directory"):
        vol.read_file("dir")
    with pytest.raises(BeastError, match="is a directory"):
        vol.write_file("dir", b"")
    with pytest.raises(BeastError, match="not empty"):
        vol.remove("dir")
    with pytest.raises(BeastError, match="root directory"):
        vol.remove("/")
    for bad in ("a:b", "trailing.", "trailing ", "q?", "x" * 256, "tab\there"):
        with pytest.raises(BeastError, match="invalid FAT file name|longer than 255"):
            vol.write_file(bad, b"")
    with pytest.raises(BeastError, match="'.' and '..'"):
        vol.write_file("dir/../x", b"")
    with pytest.raises(BeastError, match="given twice"):
        vol.write_files({"A.txt": b"", "a.TXT": b""})
    with pytest.raises(BeastError, match="both a file and a directory"):
        vol.write_files({"x": b"", "x/y": b""})
    assert vol.read_file("DIR/FILE.TXT") == b"data"
    with pytest.raises(BeastError, match="does not fit"):
        format_fat(t, 0, t.size + SECTOR_SIZE, fat_bits=16, label="", volume_id=0, hidden_sectors=0)
    with pytest.raises(BeastError, match="32-bit"):
        format_fat(t, 0, t.size, fat_bits=16, label="", volume_id=1 << 32, hidden_sectors=0)
    t.close()
    zero = ImageFile(tmp_path / "zero.img", MIB)
    with pytest.raises(BeastError, match="no FAT filesystem"):
        FatVolume(zero, 0)
    zero.close()


@needs_fsck
def test_full_volume_rolls_back(tmp_path):
    t = new_volume(tmp_path, 5 * MIB, 16)
    vol = FatVolume(t, 0)
    vol.write_file("keep.txt", b"keep")
    with pytest.raises(BeastError, match="not enough free space"):
        vol.write_files({"a.bin": bytes(2 * MIB), "b.bin": bytes(3 * MIB)})
    assert not vol.exists("a.bin")  # the whole batch was dropped
    vol.write_file("after.txt", b"still works")
    fresh = FatVolume(t, 0)
    assert {e.name for e in fresh.listdir("")} == {"keep.txt", "after.txt"}
    t.close()
    fsck_clean(tmp_path / "vol.img")


@needs_fsck
def test_replace_on_a_nearly_full_volume(tmp_path):
    """Replacing a file bigger than the free space reuses its own clusters."""
    t = new_volume(tmp_path, 5 * MIB, 16)
    vol = FatVolume(t, 0)
    free = vol.free_bytes()
    vol.write_file("big.bin", content("one", free * 6 // 10))
    new = content("two", free * 7 // 10)
    vol.write_file("big.bin", new)
    assert FatVolume(t, 0).read_file("big.bin") == new
    t.close()
    fsck_clean(tmp_path / "vol.img")


@needs_fsck
def test_fixed_root_directory_full(tmp_path):
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    with pytest.raises(BeastError, match="root directory is full"):
        vol.write_files({f"F{i:04d}.TXT": b"x" for i in range(600)})
    assert vol.listdir("") == []
    for i in range(511):  # 512 entries minus the volume label
        vol.write_file(f"F{i:04d}.TXT", b"x")
    with pytest.raises(BeastError, match="root directory is full"):
        vol.write_file("ONE.TOO", b"x")
    t.close()
    fsck_clean(tmp_path / "vol.img")


@needs_fsck
@needs_mtools
def test_deleted_slots_are_reused(tmp_path):
    t = new_volume(tmp_path, 40 * MIB, 32)
    vol = FatVolume(t, 0)
    for i in range(40):
        vol.write_file(f"dir/a long file name number {i}.txt", str(i).encode())
    root_dir = vol._walk(["dir"])
    clusters_before = list(root_dir.clusters)
    for i in range(0, 40, 2):
        vol.remove(f"dir/a long file name number {i}.txt")
    for i in range(20):
        vol.write_file(f"dir/other name {i}.txt", b"o")
    assert vol._walk(["dir"]).clusters == clusters_before
    t.close()
    fsck_clean(tmp_path / "vol.img")
    files, _ = mdir_tree(tmp_path / "vol.img")
    assert len(files) == 40


# Keys that are (or fold to) the 8.3 alias another key of the same batch would
# get: each must still become its own entry, whatever the creation order.
COLLISIONS = {
    "EXTRA/Long File Name With Spaces.txt": 5000,  # would be LONGFI~1.TXT
    "EXTRA/LONGFI~1.TXT": 1,
    "EXTRA/longfi~2.txt": 2,  # lower case, but its 8.3 name is LONGFI~2.TXT as well
    "Long Dir Name/inside.txt": 3,  # the directory would be LONGDI~1 ...
    "LONGDI~1": 4,  # ... which a file wants
    "Long Other Dir/x.txt": 5,  # would be LONGOT~1 ...
    "LONGOT~1/y.txt": 6,  # ... which another directory wants
}


@needs_fsck
@needs_mtools
@pytest.mark.parametrize("how", ["build_esp", "write_files-fat32"])
def test_names_that_look_like_aliases_stay_separate(tmp_path, how):
    data = {path: content(path, n) for path, n in {**TREE, **COLLISIONS}.items()}
    img = tmp_path / "vol.img"
    if how == "build_esp":
        t = ImageFile(img, ESP_SIZE)
        build_esp(t, 0, ESP_SIZE, data, label=ESP_LABEL, volume_id=VID, hidden_sectors=2048)
    else:
        t = new_volume(tmp_path, 40 * MIB, 32)
        FatVolume(t, 0).write_files(data)
    vol = FatVolume(t, 0)
    for path, blob in data.items():
        assert vol.read_file(path) == blob, path
    _check_listing(vol, data)
    t.close()
    fsck_clean(img)
    files, dirs = mdir_tree(img)
    assert files == set(data)
    assert dirs == dirs_of(data)
    for path, blob in data.items():
        assert mtype(img, 0, path) == blob, path
    extra = mdir_raw(img, 0, "EXTRA")
    assert re.search(r"^LONGFI~1 TXT +1 ", extra, re.M), extra
    assert re.search(r"^LONGFI~2 TXT +2 .* longfi~2\.txt$", extra, re.M), extra
    assert re.search(r"^LONGFI~3 TXT +5000 .* Long File Name With Spaces\.txt$", extra, re.M), extra
    root = mdir_raw(img, 0)
    assert re.search(r"^LONGDI~1 +4 ", root, re.M), root
    assert re.search(r"^LONGDI~2 +<DIR> .* Long Dir Name$", root, re.M), root
    assert re.search(r"^LONGOT~1 +<DIR> ", root, re.M), root
    assert re.search(r"^LONGOT~2 +<DIR> .* Long Other Dir$", root, re.M), root


@needs_fsck
def test_two_keys_for_one_existing_file(tmp_path):
    """An existing file is also reachable by its 8.3 alias (as on Windows and
    Linux); a batch naming it both ways would lose one of the two contents."""
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    vol.write_file("dir/Long File Name.txt", b"old")
    with pytest.raises(BeastError, match="name the same file"):
        vol.write_files({"dir/Long File Name.txt": b"a", "dir/LONGFI~1.TXT": b"b", "new.txt": b"n"})
    assert vol.read_file("dir/Long File Name.txt") == b"old"  # rolled back
    assert not vol.exists("new.txt")
    vol.write_file("dir/LONGFI~1.TXT", b"via the alias")  # one name: opens the existing file
    fresh = FatVolume(t, 0)
    assert fresh.listdir("dir") == [DirEntry("Long File Name.txt", False, 13)]
    assert fresh.read_file("dir/long file name.txt") == b"via the alias"
    t.close()
    fsck_clean(tmp_path / "vol.img")


def test_bad_argument_types(tmp_path):
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    fmt = dict(fat_bits=16, label="X", volume_id=VID, hidden_sectors=0)
    calls = {
        "label=None": lambda: format_fat(t, 0, t.size, **{**fmt, "label": None}),
        "volume_id='12'": lambda: format_fat(t, 0, t.size, **{**fmt, "volume_id": "12"}),
        "volume_id=True": lambda: format_fat(t, 0, t.size, **{**fmt, "volume_id": True}),
        "hidden_sectors=1.0": lambda: format_fat(t, 0, t.size, **{**fmt, "hidden_sectors": 1.0}),
        "fat_bits=16.0": lambda: format_fat(t, 0, t.size, **{**fmt, "fat_bits": 16.0}),
        "cluster_size='4096'": lambda: format_fat(t, 0, t.size, **fmt, cluster_size="4096"),
        "timestamp='now'": lambda: format_fat(t, 0, t.size, **fmt, timestamp="now"),
        "timestamp=nan": lambda: format_fat(t, 0, t.size, **fmt, timestamp=float("nan")),
        "offset='0'": lambda: format_fat(t, "0", t.size, **fmt),
        "FatVolume offset=None": lambda: FatVolume(t, None),
        "FatVolume offset=100": lambda: FatVolume(t, 100),
        "write_file(str)": lambda: vol.write_file("a.txt", "text"),
        "write_file(int)": lambda: vol.write_file("a.txt", 5),  # bytes(5) would be 5 zero bytes
        "write_file(path=None)": lambda: vol.write_file(None, b""),
        "read_file(bytes path)": lambda: vol.read_file(b"dir"),
        "listdir(None)": lambda: vol.listdir(None),
        "remove(3)": lambda: vol.remove(3),
        "write_files(list)": lambda: vol.write_files([("a.txt", b"")]),
        "write_files(int key)": lambda: vol.write_files({1: b""}),
    }
    for what, call in calls.items():
        try:
            call()
        except BeastError:
            continue
        except Exception as e:  # anything else is the bug this test is about
            pytest.fail(f"{what}: {type(e).__name__}: {e}")
        pytest.fail(f"{what}: no error")
    assert vol.listdir("") == []
    vol.write_file("ok.bin", memoryview(b"view"))  # bytes-like objects are fine
    vol.write_file("ok2.bin", bytearray(b"array"))
    assert FatVolume(t, 0).read_file("ok.bin") == b"view"
    t.close()
    esp = ImageFile(tmp_path / "esp.img", ESP_SIZE)
    with pytest.raises(BeastError, match="must be bytes, not str"):
        build_esp(esp, 0, ESP_SIZE, {"EFI/BOOT/BOOTX64.EFI": b"ok", "a.txt": "str"}, label=ESP_LABEL,
                  volume_id=VID, hidden_sectors=2048)
    assert esp.writes == []  # checked before formatting: an existing ESP stays intact
    esp.close()


def _point_entry_at(t, vol: FatVolume, parent: str, name: str, cluster: int) -> None:
    """Corrupt the volume: make directory entry parent/name start at `cluster`."""
    d = vol._walk(fatfs._split(parent))
    ent = d.lookup(name)
    raw = bytearray(d.data[ent.slot * 32 : (ent.slot + 1) * 32])
    struct.pack_into("<H", raw, 20, cluster >> 16)
    struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
    cs = vol.cluster_size
    t.write(vol._cluster_offset(d.clusters[ent.slot * 32 // cs]) + ent.slot * 32 % cs, bytes(raw))


@pytest.mark.parametrize("bits,size,target", [(16, 20 * MIB, "parent"), (32, 40 * MIB, "parent"),
                                              (32, 40 * MIB, "root")])
def test_remove_stops_at_a_directory_loop(tmp_path, bits, size, target):
    t = new_volume(tmp_path, size, bits)
    vol = FatVolume(t, 0)
    vol.write_file("A/B/x.txt", b"x")
    vol.write_file("A/other.txt", b"o")
    loop_to = vol._walk(["A"]).key if target == "parent" else vol._root_key()
    _point_entry_at(t, vol, "A", "B", loop_to)
    before = (tmp_path / "vol.img").read_bytes()
    vol = FatVolume(t, 0)
    with pytest.raises(BeastError, match="directory loop"):
        vol.remove("A", recursive=True)
    assert (tmp_path / "vol.img").read_bytes() == before  # nothing was written
    assert {e.name for e in vol.listdir("A")} == {"B", "other.txt"}
    t.close()


@needs_fsck
def test_remove_a_very_deep_tree(tmp_path):
    """Deeper than Python's recursion limit: removal must not recurse."""
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    depth = 1100
    vol.write_file("/".join(["d"] * depth) + "/leaf.txt", b"leaf")
    vol.write_file("keep.txt", b"keep")
    free = FatVolume(t, 0).free_bytes()
    vol.remove("d", recursive=True)
    fresh = FatVolume(t, 0)
    assert fresh.listdir("") == [DirEntry("keep.txt", False, 4)]
    assert fresh.free_bytes() == free + (depth + 1) * fresh.cluster_size
    t.close()
    fsck_clean(tmp_path / "vol.img")


# ---------------------------------------------------------------------------
# The Linux kernel's vfat driver (rootless loop mount via udisks)
# ---------------------------------------------------------------------------


def _mountpoint(dev: str) -> str | None:
    for line in Path("/proc/mounts").read_text().splitlines():
        fields = line.split()
        if fields[0] == dev:
            return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[1])
    return None


@contextmanager
def udisks_mount(img: Path, offset: int, size: int):
    if shutil.which("udisksctl") is None:
        pytest.skip("udisksctl not installed")
    proc = run("udisksctl", "loop-setup", "-f", img, "--offset", offset, "--size", size,
               "--no-user-interaction", check=False)
    m = re.search(r"as (/dev/loop\d+)", proc.stdout)
    if proc.returncode != 0 or not m:
        pytest.skip(f"udisksctl loop-setup is not allowed here: {proc.stderr.strip()}")
    dev = m.group(1)
    try:
        mp = None
        for _ in range(40):  # a desktop session may auto-mount it first
            mp = _mountpoint(dev)
            if mp:
                break
            out = run("udisksctl", "mount", "-b", dev, "--no-user-interaction", check=False)
            if out.returncode == 0:
                mp = _mountpoint(dev)
                break
            time.sleep(0.25)
        if not mp:
            pytest.skip("udisksctl mount is not allowed here")
        yield Path(mp)
    finally:
        for _ in range(40):
            if _mountpoint(dev) is None:
                break
            run("udisksctl", "unmount", "-b", dev, "--no-user-interaction", check=False)
            time.sleep(0.25)
        for _ in range(40):
            if run("udisksctl", "loop-delete", "-b", dev, "--no-user-interaction", check=False).returncode == 0:
                break
            time.sleep(0.25)


def _read_tree(root: Path) -> dict[str, bytes]:
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


@needs_fsck
def test_kernel_mount_esp(tmp_path, esp_files):
    img = tmp_path / "disk.img"
    plan = make_plan(DISK_SIZE // SECTOR_SIZE, "msdos")
    esp = plan.esp
    t = ImageFile(img, DISK_SIZE)
    write_partition_table(t, plan, "exfat")
    build_esp(t, esp.offset, esp.size_bytes, esp_files, label=ESP_LABEL, volume_id=VID, hidden_sectors=esp.start)
    t.flush()
    with udisks_mount(img, esp.offset, esp.size_bytes) as mp:
        assert _read_tree(mp) == esp_files
        (mp / "Kernel Dir" / "sub dir").mkdir(parents=True)
        (mp / "Kernel Dir" / "sub dir" / "hello wörld.txt").write_bytes(b"from linux\n")
        (mp / "grub" / "beast" / "device.cfg").write_bytes(b"set bb_layout=\"gpt\"\n")
        (mp / "BEAST-BOOTER.ID").unlink()
    fsck_clean(img, esp.offset, esp.size_bytes, tmp_path)
    vol = FatVolume(t, esp.offset)
    assert vol.read_file("Kernel Dir/sub dir/hello wörld.txt") == b"from linux\n"
    assert vol.read_file("grub/beast/device.cfg") == b"set bb_layout=\"gpt\"\n"
    assert not vol.exists("BEAST-BOOTER.ID")
    t.close()


@needs_fsck
def test_kernel_mount_fat32(tmp_path):
    size = ODD_SIZE
    t = new_volume(tmp_path, size, 32, label="BEASTBOOTER")
    vol = FatVolume(t, 0)
    data = {path: content(path, n) for path, n in {**TREE, **COLLISIONS}.items()}
    vol.write_files(data)
    t.flush()
    with udisks_mount(tmp_path / "vol.img", 0, size - size % SECTOR_SIZE) as mp:
        assert _read_tree(mp) == data
        (mp / "beast-booter").mkdir()
        (mp / "beast-booter" / "config.cfg").write_bytes(b"set timeout=3\n")
    fsck_clean(tmp_path / "vol.img")
    assert FatVolume(t, 0).read_file("beast-booter/config.cfg") == b"set timeout=3\n"
    assert DirEntry("config.cfg", False, 14) in FatVolume(t, 0).listdir("beast-booter")
    t.close()


@pytest.mark.parametrize("bits,size", [(12, 2 * MIB), (16, 20 * MIB), (32, 40 * MIB), ("esp", ESP_SIZE)],
                         ids=["fat12", "fat16", "fat32", "esp"])
def test_sector_aligned_io(tmp_path, bits, size):
    """Raw devices on Windows/macOS need whole sectors; fatfs never asks for less."""
    offset = 2048 * SECTOR_SIZE
    t = SectorImage(tmp_path / "disk.img", offset + size)
    if bits == "esp":
        build_esp(t, offset, size, {p: content(p, n) for p, n in TREE.items()}, label=ESP_LABEL,
                  volume_id=VID, hidden_sectors=2048)
    else:
        format_fat(t, offset, size, fat_bits=bits, label="ALIGNED", volume_id=VID, hidden_sectors=2048)
        FatVolume(t, offset).write_files({p: content(p, n) for p, n in TREE.items()})
    vol = FatVolume(t, offset)
    assert vol.fat_bits == (32 if bits == "esp" else bits)
    for path, n in TREE.items():
        assert vol.read_file(path) == content(path, n)
    vol.write_file("EFI/BOOT/grubx64.efi", b"replaced")
    vol.mkdir("a/b/c")
    vol.remove("deep", recursive=True)
    vol.remove("README.TXT")
    vol.listdir("Deep Folder Name/Sub Folder")
    assert vol.free_bytes() > 0
    t.close()
