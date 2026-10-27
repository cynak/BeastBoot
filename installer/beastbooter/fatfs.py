"""FAT12 / FAT16 / FAT32 in pure Python: format a volume, read and write files.

This replaces mkfs.fat and mtools, so the installer behaves the same on Linux,
Windows and macOS. It follows Microsoft's "FAT: General Overview of On-Disk
Format" (fatgen103) and the VFAT long-file-name rules.

Formatting (format_fat) is a quick format: it writes the reserved sectors
(boot sector; on FAT32 also FSInfo and their backups at sectors 6 and 7),
both FATs (zeroed) and the root directory. The data area is not touched.

Layout choices (the same as mkfs.fat for the 64 MiB ESP):

* 512-byte sectors, media 0xF8, two FATs, OEM name "MSWIN4.1" (the value
  Microsoft recommends for compatibility), extended boot signature 0x29 with
  the volume id and label, drive number 0x80, hidden sectors = the partition's
  start LBA (given by the caller).
* Cluster size from Microsoft's tables (fatgen103 DskTableFAT16/FAT32, the
  tables Windows and mkfs.fat use for FAT32), e.g. 2 KiB for the 64 MiB ESP,
  4 KiB up to 8 GiB and 32 KiB above 32 GiB for FAT32. If the table value
  would give a cluster count outside the FAT type's range, the next size that
  fits is used.
* FAT type limits per the spec: FAT12 < 4085 clusters <= FAT16 < 65525 <= FAT32.
* FAT12/16: 1 reserved sector, 512 root entries. FAT32: 32 reserved sectors,
  root directory in cluster 2. Like mkfs.fat, the reserved area, each FAT and
  the root directory are rounded up to whole clusters so that every cluster is
  aligned to its own size on the partition (partitions start on 1 MiB).
* The boot code area holds a 6-byte stub (int 18h = "not bootable, try the
  next device", then halt). beast-boot boots through the MBR, never through
  this volume boot record.

Names: a name that is already a valid upper-case 8.3 name is stored as just
that. Any other name gets VFAT long-name entries (UTF-16, checksummed) plus a
generated 8.3 alias ("GRUBX64.EFI", "ENROLL~1.CER"). Lookups are
case-insensitive and match either name. Within one write_files() batch, no
generated alias takes an 8.3 name that another file of the batch asks for.

Timestamps: every entry gets the same time, `timestamp` (Unix seconds,
stored as UTC), or 1980-01-01 00:00:00 when none is given, so building the
same files twice gives a byte-identical volume.

Writes reach the target in a crash-friendly order: file data, then the FAT,
then directory entries, then (for replaced or removed files) the freeing of
old clusters, then FSInfo. Nothing is flushed; call FatVolume.flush() or flush
the target.
"""

from __future__ import annotations

import array
import math
import struct
import sys
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from .errors import BeastError
from .interfaces import DirEntry
from .layout import ESP_FAT_BITS, SECTOR_SIZE

# ---------------------------------------------------------------------------
# On-disk constants
# ---------------------------------------------------------------------------

MEDIA_FIXED_DISK = 0xF8
OEM_NAME = b"MSWIN4.1"
NUM_FATS = 2
ROOT_ENTRIES_FAT1216 = 512
RESERVED_SECTORS = {12: 1, 16: 1, 32: 32}
FAT32_ROOT_CLUSTER = 2
FAT32_FSINFO_SECTOR = 1
FAT32_BACKUP_BOOT_SECTOR = 6
DRIVE_NUMBER = 0x80
EXT_BOOT_SIGNATURE = 0x29
NO_LABEL = b"NO NAME    "

FSINFO_LEAD_SIG = 0x41615252
FSINFO_STRUC_SIG = 0x61417272
FSINFO_TRAIL_SIG = 0xAA550000
FSINFO_UNKNOWN = 0xFFFFFFFF

# Cluster-count limits per FAT type (fatgen103 "FAT type determination").
MIN_CLUSTERS = {12: 1, 16: 4085, 32: 65525}
MAX_CLUSTERS = {12: 4084, 16: 65524, 32: 0x0FFFFFF5}
EOC_MIN = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}  # >= this: end of chain
EOC = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}  # what we write

# Microsoft's cluster size tables: (volume size in sectors up to, sectors per cluster).
_FAT16_TABLE = ((32680, 2), (262144, 4), (524288, 8), (1048576, 16), (2097152, 32), (4194304, 64))
_FAT32_TABLE = ((532480, 1), (16777216, 8), (33554432, 16), (67108864, 32), (0xFFFFFFFF, 64))
MAX_AUTO_SECTORS_PER_CLUSTER = 64  # 32 KiB: the largest size every implementation accepts

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LONG_NAME = 0x0F  # READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID
ATTR_LONG_NAME_MASK = 0x3F

DIRENT_SIZE = 32
DELETED = 0xE5
LFN_LAST = 0x40
LFN_CHARS = 13
LFN_MAX_CHARS = 255
MAX_DIR_ENTRIES = 65536  # a directory may not be larger than 2 MiB
NTRES_LOWER_BASE = 0x08
NTRES_LOWER_EXT = 0x10
DOT = b".          "
DOTDOT = b"..         "

# Characters allowed in 8.3 names and labels besides A-Z and 0-9.
_SHORT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&")
# Characters never allowed in a long name.
_LFN_FORBIDDEN = frozenset('"*/:<>?\\|')

# x86 real-mode stub for the boot code area: we never boot through the VBR.
BOOT_STUB = bytes([
    0xCD, 0x18,  # int 18h   ; BIOS: booting from this device failed, try the next one
    0xFA,        # cli
    0xF4,        # hlt       ; should int 18h return, stop here
    0xEB, 0xFD,  # jmp short (back to hlt)
])

_FAT_EPOCH = 315532800  # 1980-01-01 00:00:00 UTC
_FAT_LAST = 4354819198  # 2107-12-31 23:59:58 UTC
_ZEROS = bytes(1 << 20)


class FatNoSpace(BeastError):
    """The volume (or a fixed-size root directory) is full."""


# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FatGeometry:
    fat_bits: int
    total_sectors: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_sectors: int  # per FAT
    root_entries: int  # 0 on FAT32
    num_fats: int = NUM_FATS
    bytes_per_sector: int = SECTOR_SIZE

    @property
    def cluster_size(self) -> int:
        return self.sectors_per_cluster * self.bytes_per_sector

    @property
    def root_dir_sectors(self) -> int:
        return -(-self.root_entries * DIRENT_SIZE // self.bytes_per_sector)

    @property
    def root_dir_sector(self) -> int:  # first sector after the FATs
        return self.reserved_sectors + self.num_fats * self.fat_sectors

    @property
    def data_start_sector(self) -> int:
        return self.root_dir_sector + self.root_dir_sectors

    @property
    def cluster_count(self) -> int:
        return (self.total_sectors - self.data_start_sector) // self.sectors_per_cluster


def _align(value: int, unit: int) -> int:
    return -(-value // unit) * unit


def _layout(total: int, bits: int, spc: int) -> FatGeometry | None:
    """Geometry for a given cluster size, or None if nothing fits."""
    bps = SECTOR_SIZE
    reserved = _align(RESERVED_SECTORS[bits], spc)
    if bits == 32:
        root_entries, root_secs = 0, 0
    else:
        root_secs = _align(ROOT_ENTRIES_FAT1216 * DIRENT_SIZE // bps, spc)
        root_entries = root_secs * bps // DIRENT_SIZE

    def clusters(fat: int) -> int:
        return max(total - reserved - root_secs - NUM_FATS * fat, 0) // spc

    def fat_for(n: int) -> int:  # sectors per FAT for n clusters (+2 reserved entries)
        return _align(-(-(n + 2) * bits // (8 * bps)), spc)

    # A FAT sized for the clusters there would be without FATs is big enough;
    # then shrink it while the smaller FAT still covers the (now more) clusters.
    fat = fat_for(clusters(0))
    while fat > spc and fat_for(clusters(fat - spc)) <= fat - spc:
        fat -= spc
    if clusters(fat) == 0:
        return None
    return FatGeometry(bits, total, spc, reserved, fat, root_entries)


def _table_spc(total: int, bits: int) -> int:
    if bits == 12:
        return 1  # smallest first; the search below doubles it until it fits
    for limit, spc in _FAT16_TABLE if bits == 16 else _FAT32_TABLE:
        if total <= limit:
            return spc
    return MAX_AUTO_SECTORS_PER_CLUSTER


def fat_geometry(total_sectors: int, fat_bits: int, cluster_size: int | None = None) -> FatGeometry:
    """Choose the layout of a FAT volume of `total_sectors` 512-byte sectors."""
    if not _is_int(fat_bits) or fat_bits not in (12, 16, 32):
        raise BeastError(f"unsupported FAT type {fat_bits!r} (use 12, 16 or 32)")
    if not _is_int(total_sectors) or total_sectors < 0:
        raise BeastError(f"invalid FAT volume size {total_sectors!r} (a number of sectors)")
    if total_sectors > 0xFFFFFFFF:
        raise BeastError("a FAT volume can be at most 2 TiB with 512-byte sectors; use exFAT")
    if cluster_size is not None:
        if not _is_int(cluster_size):
            raise BeastError(f"invalid FAT cluster size {cluster_size!r} (512 .. 65536, a power of two)")
        spc, rem = divmod(cluster_size, SECTOR_SIZE)
        if rem or spc < 1 or spc > 128 or spc & (spc - 1):
            raise BeastError(f"invalid FAT cluster size {cluster_size} (512 .. 65536, a power of two)")
        candidates = [spc]
    else:
        spc = _table_spc(total_sectors, fat_bits)
        larger = [spc << i for i in range(1, 8) if spc << i <= MAX_AUTO_SECTORS_PER_CLUSTER]
        smaller = [spc >> i for i in range(1, 8) if spc >> i >= 1]
        candidates = [spc] + larger + smaller
    too_small = too_large = False
    for spc in candidates:
        g = _layout(total_sectors, fat_bits, spc)
        if g is None or g.cluster_count < MIN_CLUSTERS[fat_bits]:
            too_small = True
        elif g.cluster_count > MAX_CLUSTERS[fat_bits]:
            too_large = True
        else:
            return g
    size = _human(total_sectors * SECTOR_SIZE)
    with_cs = f" with {cluster_size}-byte clusters" if cluster_size else ""
    if too_small and not too_large:
        raise BeastError(f"{size} is too small for FAT{fat_bits}{with_cs}")
    if too_large and not too_small:
        raise BeastError(f"{size} is too large for FAT{fat_bits}{with_cs}")
    raise BeastError(f"{size} cannot be formatted as FAT{fat_bits}{with_cs}")


def _human(n: int) -> str:
    for unit, shift in (("GiB", 30), ("MiB", 20), ("KiB", 10)):
        if n >= 1 << shift:
            return f"{n / (1 << shift):.1f} {unit}"
    return f"{n} bytes"


# ---------------------------------------------------------------------------
# Small encoders
# ---------------------------------------------------------------------------


def _is_int(value) -> bool:
    """A real integer (True/False are not accepted as numbers here)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _u32(value, what: str) -> int:
    if not _is_int(value) or not 0 <= value <= 0xFFFFFFFF:
        raise BeastError(f"{what} {value!r} is not a 32-bit number")
    return value


def _file_bytes(data, path: str) -> bytes:
    """File contents as bytes: bytes, bytearray or memoryview, nothing else
    (bytes(5) would quietly mean five zero bytes, bytes("x") fails)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BeastError(f"the contents of {path!r} must be bytes, not {type(data).__name__}")
    return bytes(data)


def _fold(name: str) -> str:
    """Case-fold for name comparison: upper-case character by character."""
    return "".join(u if len(u := c.upper()) == 1 else c for c in name)


def label_bytes(label: str) -> bytes:
    """11-byte FAT volume label (upper case, space padded); NO NAME if empty."""
    if not isinstance(label, str):
        raise BeastError(f"invalid FAT label {label!r}: it must be a string")
    up = _fold(label)
    if not up:
        return NO_LABEL
    if len(up) > 11 or up[0] == " " or any(c not in _SHORT_CHARS and c != " " for c in up):
        raise BeastError(
            f"invalid FAT label {label!r}: up to 11 characters A-Z 0-9 space and $%'-_@~`!(){{}}^#&"
        )
    return up.encode("ascii").ljust(11, b" ")


def _stamp(timestamp: float | None) -> tuple[int, int, int]:
    """(date, time, tenths of 10 ms) in FAT format, from Unix seconds (UTC)."""
    if timestamp is not None and (
        isinstance(timestamp, bool) or not isinstance(timestamp, (int, float))
        or (isinstance(timestamp, float) and not math.isfinite(timestamp))
    ):
        raise BeastError(f"invalid timestamp {timestamp!r} (Unix seconds expected)")
    ts = _FAT_EPOCH if timestamp is None else min(max(int(timestamp), _FAT_EPOCH), _FAT_LAST)
    tm = time.gmtime(ts)
    sec = min(tm.tm_sec, 59)
    date = ((tm.tm_year - 1980) << 9) | (tm.tm_mon << 5) | tm.tm_mday
    clock = (tm.tm_hour << 11) | (tm.tm_min << 5) | (sec // 2)
    return date, clock, (sec % 2) * 100


def lfn_checksum(name11: bytes) -> int:
    """Checksum of an 8.3 name stored in each of its long-name entries."""
    s = 0
    for c in name11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _short_entry(name11: bytes, attr: int, cluster: int, size: int, stamp: tuple[int, int, int]) -> bytes:
    date, clock, tenths = stamp
    stored = b"\x05" + name11[1:] if name11[0] == DELETED else name11
    return stored + struct.pack(
        "<BBBHHHHHHHI", attr, 0, tenths, clock, date, date, cluster >> 16, clock, date, cluster & 0xFFFF, size
    )


def _lfn_entries(name: str, checksum: int) -> bytes:
    """Long-name entries for `name`, in on-disk order (last part first)."""
    units = name.encode("utf-16-le")
    if len(units) % (2 * LFN_CHARS):
        units += b"\0\0"
        units += b"\xff" * (-len(units) % (2 * LFN_CHARS))
    count = len(units) // (2 * LFN_CHARS)
    out = bytearray()
    for seq in range(count, 0, -1):
        part = units[(seq - 1) * 2 * LFN_CHARS : seq * 2 * LFN_CHARS]
        e = bytearray(DIRENT_SIZE)
        e[0] = seq | (LFN_LAST if seq == count else 0)
        e[1:11] = part[0:10]
        e[11] = ATTR_LONG_NAME
        e[13] = checksum
        e[14:26] = part[10:22]
        e[28:32] = part[22:26]
        out += e
    return bytes(out)


def _check_name(name: str) -> None:
    if not name or name in (".", "..") or name.strip(" .") == "":
        raise BeastError(f"invalid FAT file name {name!r}")
    if name[-1] in " .":
        raise BeastError(f"invalid FAT file name {name!r}: it must not end with a space or a dot")
    bad = sorted({c for c in name if c in _LFN_FORBIDDEN or ord(c) < 0x20})
    if bad:
        raise BeastError(f"invalid FAT file name {name!r}: it contains {''.join(bad)!r}")
    try:
        units = len(name.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        raise BeastError(f"invalid FAT file name {name!r}") from None
    if units > LFN_MAX_CHARS:
        raise BeastError(f"FAT file name is longer than {LFN_MAX_CHARS} characters: {name!r}")


def _pack83(base: str, ext: str) -> bytes:
    return base.encode("ascii").ljust(8, b" ") + ext.encode("ascii").ljust(3, b" ")


def plain_short_name(name: str) -> bytes | None:
    """The 11-byte 8.3 name if `name` is exactly a valid upper-case 8.3 name."""
    base, dot, ext = name.partition(".")
    if "." in ext or not 1 <= len(base) <= 8 or len(ext) > 3 or (dot and not ext):
        return None
    if all(c in _SHORT_CHARS for c in base + ext):
        return _pack83(base, ext)
    return None


def _basis_name(name: str) -> tuple[str, str, bool]:
    """(base, ext, lossy) per the Windows basis-name rules (fatgen103 section 7)."""
    up = _fold(name)
    lossy = False
    s = up.replace(" ", "")
    stripped = s.lstrip(".")
    lossy |= s != up or stripped != s
    base, dot, ext = stripped.rpartition(".")
    if not dot:
        base, ext = ext, ""
    if "." in base:
        base, lossy = base.replace(".", ""), True

    def conv(part: str) -> str:
        nonlocal lossy
        out = []
        for c in part:
            if c in _SHORT_CHARS:
                out.append(c)
            else:
                out.append("_")
                lossy = True
        return "".join(out)

    base, ext = conv(base), conv(ext)
    if len(base) > 8 or len(ext) > 3 or not base:
        lossy = True
    return (base[:8] or "_"), ext[:3], lossy


def _short_display(name11: bytes, ntres: int) -> str:
    base = name11[:8].rstrip(b" ").decode("cp437")
    ext = name11[8:].rstrip(b" ").decode("cp437")
    if ntres & NTRES_LOWER_BASE:
        base = base.lower()
    if ntres & NTRES_LOWER_EXT:
        ext = ext.lower()
    return f"{base}.{ext}" if ext else base


def _slots_for(name: str) -> int:
    """Directory entries `name` needs (long-name parts + the 8.3 entry)."""
    if plain_short_name(name) is not None:
        return 1
    return 1 + -(-len(name.encode("utf-16-le")) // (2 * LFN_CHARS))


def _split(path: str) -> list[str]:
    if not isinstance(path, str):
        raise BeastError(f"invalid path {path!r}: it must be a string")
    parts = [p for p in path.split("/") if p]
    for p in parts:
        if p in (".", ".."):
            raise BeastError(f"invalid path {path!r}: '.' and '..' are not allowed")
    return parts


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def _chs_geometry(total_sectors: int) -> tuple[int, int]:
    """(sectors per track, heads) for the BPB: meaningless with LBA, but tools
    check them; mkfs.fat's values (small volumes 32/64, so a 64 MiB ESP is a
    whole number of tracks for mtools)."""
    if total_sectors * SECTOR_SIZE < 512 << 20:
        return 32, 64
    return 63, 255


def boot_sector(g: FatGeometry, *, label11: bytes, volume_id: int, hidden_sectors: int) -> bytes:
    fat32 = g.fat_bits == 32
    b = bytearray(SECTOR_SIZE)
    b[0:3] = b"\xeb\x58\x90" if fat32 else b"\xeb\x3c\x90"  # jmp short to the boot code, nop
    b[3:11] = OEM_NAME
    total16 = g.total_sectors if not fat32 and g.total_sectors < 0x10000 else 0
    spt, heads = _chs_geometry(g.total_sectors)
    struct.pack_into(
        "<HBHBHHBHHHII", b, 11,
        g.bytes_per_sector, g.sectors_per_cluster, g.reserved_sectors, g.num_fats,
        g.root_entries, total16, MEDIA_FIXED_DISK, 0 if fat32 else g.fat_sectors,
        spt, heads, hidden_sectors, 0 if total16 else g.total_sectors,
    )
    if fat32:
        # FATSz32, ExtFlags (0: all FATs mirrored), FSVer 0.0, RootClus, FSInfo, BkBootSec
        struct.pack_into("<IHHIHH", b, 36, g.fat_sectors, 0, 0, FAT32_ROOT_CLUSTER,
                         FAT32_FSINFO_SECTOR, FAT32_BACKUP_BOOT_SECTOR)
        ext = 64
    else:
        ext = 36
    fs_type = {12: b"FAT12   ", 16: b"FAT16   ", 32: b"FAT32   "}[g.fat_bits]
    struct.pack_into("<BBBI11s8s", b, ext, DRIVE_NUMBER, 0, EXT_BOOT_SIGNATURE, volume_id, label11, fs_type)
    code = ext + 26  # 0x3E (FAT12/16) or 0x5A (FAT32), where the jump lands
    b[code : code + len(BOOT_STUB)] = BOOT_STUB
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def fsinfo_sector(free_clusters: int, next_free: int) -> bytes:
    b = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", b, 0, FSINFO_LEAD_SIG)
    struct.pack_into("<III", b, 484, FSINFO_STRUC_SIG, free_clusters, next_free)
    struct.pack_into("<I", b, 508, FSINFO_TRAIL_SIG)
    return bytes(b)


def _check_region(t, offset: int, size: int) -> None:
    if t.sector_size != SECTOR_SIZE:
        raise BeastError(f"only {SECTOR_SIZE}-byte sectors are supported (target has {t.sector_size})")
    if not (_is_int(offset) and _is_int(size)):
        raise BeastError(f"FAT volume offset and size must be integers (got {offset!r}, {size!r})")
    if offset < 0 or offset % SECTOR_SIZE or size <= 0 or offset + size > t.size:
        raise BeastError(f"FAT volume at {offset} (+{size}) does not fit the {t.size}-byte target")


def _write_zeros(t, offset: int, length: int, head: bytes = b"") -> None:
    pos = 0
    while pos < length:
        n = min(len(_ZEROS), length - pos)
        chunk = head + _ZEROS[len(head) : n] if pos == 0 and head else _ZEROS[:n]
        t.write(offset + pos, chunk)
        pos += n


def format_fat(t, offset: int, size: int, *, fat_bits: int, label: str, volume_id: int,
               hidden_sectors: int, cluster_size: int | None = None,
               timestamp: float | None = None) -> None:
    """Quick-format [offset, offset+size) of the BlockTarget `t` as FAT12/16/32.

    volume_id is the 32-bit serial (blkid shows it as format_volume_id(volume_id)),
    hidden_sectors the partition's start LBA. cluster_size (bytes) overrides the
    automatic choice; timestamp (Unix seconds) dates the volume label entry.
    """
    _check_region(t, offset, size)
    _u32(volume_id, "FAT volume id")
    _u32(hidden_sectors, "hidden sectors")
    label11 = label_bytes(label)
    stamp = _stamp(timestamp)
    g = fat_geometry(size // SECTOR_SIZE, fat_bits, cluster_size)
    bps = g.bytes_per_sector
    boot = boot_sector(g, label11=label11, volume_id=volume_id, hidden_sectors=hidden_sectors)

    reserved = bytearray(g.reserved_sectors * bps)
    reserved[0:bps] = boot
    if fat_bits == 32:
        info = fsinfo_sector(g.cluster_count - 1, FAT32_ROOT_CLUSTER)  # root dir uses cluster 2
        for sector, data in ((0, boot), (1, info), (6, boot), (7, info)):
            reserved[sector * bps : (sector + 1) * bps] = data
    t.write(offset, bytes(reserved))

    # FAT[0] = media byte + all ones, FAT[1] = end of chain (clean, no errors);
    # on FAT32 also FAT[2] = end of chain for the root directory.
    head = {
        12: b"\xf8\xff\xff",
        16: b"\xf8\xff\xff\xff",
        32: b"\xf8\xff\xff\x0f\xff\xff\xff\x0f\xff\xff\xff\x0f",
    }[fat_bits]
    for i in range(g.num_fats):
        _write_zeros(t, offset + (g.reserved_sectors + i * g.fat_sectors) * bps, g.fat_sectors * bps, head)

    if fat_bits == 32:
        root_off = offset + g.data_start_sector * bps  # cluster 2
        root = bytearray(g.cluster_size)
    else:
        root_off = offset + g.root_dir_sector * bps
        root = bytearray(g.root_dir_sectors * bps)
    if label11 != NO_LABEL:
        root[0:DIRENT_SIZE] = _short_entry(label11, ATTR_VOLUME_ID, 0, 0, stamp)
    t.write(root_off, bytes(root))


# ---------------------------------------------------------------------------
# The FAT itself (paged cache)
# ---------------------------------------------------------------------------


class _Fat:
    PAGE = 16384

    def __init__(self, t, read_offset: int, write_offsets: list[int], nbytes: int, bits: int, max_cluster: int):
        self._t = t
        self._read_offset = read_offset
        self._write_offsets = write_offsets
        self._nbytes = nbytes
        self.bits = bits
        self.max_cluster = max_cluster
        self._pages: dict[int, bytearray] = {}
        self._dirty: set[int] = set()

    def _page(self, i: int) -> bytearray:
        page = self._pages.get(i)
        if page is None:
            lo = i * self.PAGE
            n = min(self.PAGE, self._nbytes - lo)
            page = bytearray(self._t.read(self._read_offset + lo, n))
            if len(page) != n:
                raise BeastError("short read from the FAT")
            self._pages[i] = page
        return page

    def _byte(self, pos: int) -> int:
        return self._page(pos // self.PAGE)[pos % self.PAGE]

    def _set_byte(self, pos: int, value: int) -> None:
        i = pos // self.PAGE
        self._page(i)[pos % self.PAGE] = value
        self._dirty.add(i)

    def get(self, n: int) -> int:
        if self.bits == 16:
            return struct.unpack_from("<H", self._page(n * 2 // self.PAGE), n * 2 % self.PAGE)[0]
        if self.bits == 32:
            return struct.unpack_from("<I", self._page(n * 4 // self.PAGE), n * 4 % self.PAGE)[0] & 0x0FFFFFFF
        pos = n + n // 2
        v = self._byte(pos) | self._byte(pos + 1) << 8
        return v >> 4 if n & 1 else v & 0xFFF

    def set(self, n: int, value: int) -> None:
        if self.bits == 16:
            i = n * 2 // self.PAGE
            struct.pack_into("<H", self._page(i), n * 2 % self.PAGE, value)
            self._dirty.add(i)
        elif self.bits == 32:
            i, pos = divmod(n * 4, self.PAGE)
            page = self._page(i)
            old = struct.unpack_from("<I", page, pos)[0]
            struct.pack_into("<I", page, pos, (old & 0xF0000000) | (value & 0x0FFFFFFF))  # keep the top 4 bits
            self._dirty.add(i)
        else:
            pos = n + n // 2
            if n & 1:
                self._set_byte(pos, (self._byte(pos) & 0x0F) | ((value << 4) & 0xF0))
                self._set_byte(pos + 1, (value >> 4) & 0xFF)
            else:
                self._set_byte(pos, value & 0xFF)
                self._set_byte(pos + 1, (self._byte(pos + 1) & 0xF0) | ((value >> 8) & 0x0F))

    def find_free(self, count: int, start: int) -> list[int] | None:
        """`count` free clusters, searching upwards from `start` (wrapping around)."""
        out: list[int] = []
        c = start
        for _ in range(self.max_cluster - 1):
            if c > self.max_cluster:
                c = 2
            if self.get(c) == 0:
                out.append(c)
                if len(out) == count:
                    return out
            c += 1
        return None

    def count_free(self) -> int:
        if self.bits == 12:
            return sum(1 for c in range(2, self.max_cluster + 1) if self.get(c) == 0)
        width = self.bits // 8
        code = "H" if width == 2 else ("I" if array.array("I").itemsize == 4 else "L")
        free = 0
        first, last = 2, self.max_cluster  # entry numbers to count
        per_page = self.PAGE // width
        for i in range(first // per_page, last // per_page + 1):
            entries = array.array(code, bytes(self._page(i)))
            if sys.byteorder == "big":
                entries.byteswap()
            lo = max(first - i * per_page, 0)
            hi = min(last - i * per_page + 1, len(entries))
            free += entries[lo:hi].count(0)
        return free

    def flush(self) -> None:
        for i in sorted(self._dirty):
            data = bytes(self._pages[i])
            for off in self._write_offsets:
                self._t.write(off + i * self.PAGE, data)
        self._dirty.clear()


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


@dataclass
class _Ent:
    name: str  # long name, or the 8.3 name as shown
    short: bytes  # 11-byte 8.3 name
    attr: int
    cluster: int
    size: int
    first_slot: int  # first long-name entry (== slot without a long name)
    slot: int  # the 8.3 entry

    @property
    def is_dir(self) -> bool:
        return bool(self.attr & ATTR_DIRECTORY)


class _Dir:
    """A directory's raw entries in memory, plus a parsed index."""

    def __init__(self, key: int, clusters: list[int], data: bytearray, block: int, *, fat32: bool, is_root: bool):
        self.key = key  # first cluster (0 = FAT12/16 fixed root)
        self.clusters = clusters
        self.data = data
        self.block = block  # dirty-tracking unit: a cluster, or a sector of the fixed root
        self.dirty: set[int] = set()
        self.fat32 = fat32
        self.is_root = is_root
        self.label: bytes | None = None
        self.entries: list[_Ent] = []
        self.by_name: dict[str, _Ent] = {}
        self.shorts: set[bytes] = set()
        self.end = 0  # first never-used slot
        self.has_deleted = False
        self._parse()

    @property
    def capacity(self) -> int:
        return len(self.data) // DIRENT_SIZE

    def _parse(self) -> None:
        data = self.data
        parts: dict[int, bytes] = {}
        lfn_count = expect = lfn_sum = lfn_start = 0
        self.end = self.capacity
        for i in range(self.capacity):
            o = i * DIRENT_SIZE
            first = data[o]
            if first == 0:
                self.end = i
                break
            if first == DELETED:
                self.has_deleted = True
                lfn_count = 0
                continue
            attr = data[o + 11]
            if attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME:
                seq = first & 0x3F
                chunk = bytes(data[o + 1 : o + 11] + data[o + 14 : o + 26] + data[o + 28 : o + 32])
                if first & LFN_LAST and seq:
                    lfn_count, lfn_sum, lfn_start, expect = seq, data[o + 13], i, seq - 1
                    parts = {seq: chunk}
                elif lfn_count and expect and seq == expect and data[o + 13] == lfn_sum:
                    parts[seq] = chunk
                    expect -= 1
                else:
                    lfn_count = 0  # orphaned long-name entry: ignore it
                continue
            name11 = bytes(data[o : o + 11])
            if name11[0] == 0x05:
                name11 = bytes([DELETED]) + name11[1:]
            if attr & ATTR_VOLUME_ID:
                if self.is_root and self.label is None:
                    self.label = name11
                lfn_count = 0
                continue
            if name11 in (DOT, DOTDOT):
                lfn_count = 0
                continue
            long_name = None
            start = i
            if lfn_count and not expect and lfn_sum == lfn_checksum(name11):
                raw = b"".join(parts[k] for k in range(1, lfn_count + 1))
                long_name = raw.decode("utf-16-le", "replace").split("\0", 1)[0].replace("￿", "")
                start = lfn_start
            lfn_count = 0
            hi, lo, size = struct.unpack_from("<H4xHI", data, o + 20)
            cluster = lo | (hi << 16 if self.fat32 else 0)
            name = long_name or _short_display(name11, data[o + 12])
            self.add(_Ent(name, name11, attr, cluster, size, start, i))

    def add(self, ent: _Ent) -> None:
        self.entries.append(ent)
        self.by_name.setdefault(_fold(ent.name), ent)
        self.by_name.setdefault(_fold(_short_display(ent.short, 0)), ent)
        self.shorts.add(ent.short)

    def forget(self, ent: _Ent) -> None:
        self.entries = [e for e in self.entries if e is not ent]
        for k in [k for k, v in self.by_name.items() if v is ent]:
            del self.by_name[k]
        self.shorts.discard(ent.short)

    def lookup(self, name: str) -> _Ent | None:
        return self.by_name.get(_fold(name))

    def find_slots(self, n: int) -> int | None:
        if self.has_deleted:
            run = 0
            for i in range(self.end):
                if self.data[i * DIRENT_SIZE] == DELETED:
                    run += 1
                    if run == n:
                        return i - n + 1
                else:
                    run = 0
        if self.end + n <= self.capacity:
            return self.end
        return None

    def put(self, slot: int, raw: bytes) -> None:
        lo = slot * DIRENT_SIZE
        hi = lo + len(raw)
        self.data[lo:hi] = raw
        self.dirty.update(range(lo // self.block, (hi - 1) // self.block + 1))
        self.end = max(self.end, hi // DIRENT_SIZE)


class _BatchPlan:
    """The files of a write_files() / build_esp() call, checked and indexed
    before anything is written. Keys are tuples of case-folded names."""

    def __init__(self, files) -> None:
        if not isinstance(files, Mapping):
            raise BeastError(f"the files must be a mapping of path -> bytes, not {type(files).__name__}")
        self.items: dict[tuple[str, ...], tuple[list[str], bytes]] = {}
        for path, data in files.items():
            parts = _split(path)
            if not parts:
                raise BeastError(f"invalid file path {path!r}")
            for p in parts:
                _check_name(p)
            key = tuple(_fold(p) for p in parts)
            if key in self.items:
                raise BeastError(f"{path!r} is given twice (FAT names are case-insensitive)")
            self.items[key] = (parts, _file_bytes(data, path))
        self.dirs: dict[tuple[str, ...], list[str]] = {}  # every directory on the way
        self.slots: dict[tuple[str, ...], int] = {}  # directory -> entries its children need
        # directory -> the 8.3 names its children ask for: a child "LONGFI~1.TXT"
        # (or "longfi~1.txt") must not lose its name to the alias generated
        # for a sibling "Long File Name.txt", whatever the order of creation.
        self.shorts: dict[tuple[str, ...], set[bytes]] = {}
        seen: set[tuple[str, ...]] = set()
        for key, (parts, _data) in self.items.items():
            for i in range(len(parts)):
                child = key[: i + 1]
                if i < len(parts) - 1:
                    if child in self.items:
                        raise BeastError(f"/{'/'.join(parts[: i + 1])} is both a file and a directory")
                    self.dirs.setdefault(child, parts[: i + 1])
                if child not in seen:
                    seen.add(child)
                    self.slots[key[:i]] = self.slots.get(key[:i], 0) + _slots_for(parts[i])
                    short = plain_short_name(child[-1])
                    if short is not None:
                        self.shorts.setdefault(key[:i], set()).add(short)


# ---------------------------------------------------------------------------
# FatVolume
# ---------------------------------------------------------------------------


class FatVolume:
    """An existing FAT12/16/32 volume at byte `offset` of the BlockTarget `t`.

    Paths use "/" and are case-insensitive. Every change is written when the
    method returns, or when the outermost `with vol.batch():` block ends.
    """

    def __init__(self, t, offset: int, *, timestamp: float | None = None) -> None:
        if not _is_int(offset) or offset < 0 or offset % SECTOR_SIZE:
            raise BeastError(f"invalid FAT volume offset {offset!r} (a multiple of {SECTOR_SIZE} bytes)")
        self._t = t
        self._offset = offset
        self._stamp = _stamp(timestamp)
        self._depth = 0
        self._failed = False
        # While write_files() runs: {directory key: 8.3 names that entries of
        # the batch need for themselves}, so no generated alias takes them.
        self._reserved: dict[int, set[bytes]] = {}
        self._read_boot_sector()
        self._reset_state()
        root = self._root()
        raw_label = root.label if root.label is not None else self._bpb_label
        self.label = raw_label.decode("cp437").rstrip(" ") if raw_label not in (None, NO_LABEL) else ""

    # -- boot sector -------------------------------------------------------

    def _read_boot_sector(self) -> None:
        t, off = self._t, self._offset
        bs = t.read(off, SECTOR_SIZE)
        where = f"at byte offset {off}"
        if len(bs) < SECTOR_SIZE:
            raise BeastError(f"no FAT filesystem {where} (cannot read the boot sector)")
        (bps, spc, rsvd, nfats, root_entries, tot16, media, fatsz16, _spt, _heads, hidden,
         tot32) = struct.unpack_from("<HBHBHHBHHHII", bs, 11)
        fatsz = fatsz16 or struct.unpack_from("<I", bs, 36)[0]
        total = tot16 or tot32
        if (bps not in (512, 1024, 2048, 4096) or not spc or spc & (spc - 1) or not rsvd or not nfats
                or not (media >= 0xF8 or media == 0xF0) or not fatsz or not total):
            raise BeastError(f"no FAT filesystem {where}")
        root_secs = -(-root_entries * DIRENT_SIZE // bps)
        data_start = rsvd + nfats * fatsz + root_secs
        if total <= data_start:
            raise BeastError(f"no FAT filesystem {where} (inconsistent boot sector)")
        clusters = (total - data_start) // spc
        # FAT32 is recognised by FATSz16 == 0 (as Linux does), FAT12 vs FAT16 by
        # the cluster count (as the spec says).
        bits = 32 if fatsz16 == 0 else (12 if clusters < MIN_CLUSTERS[16] else 16)
        if bits == 32:
            ext_flags, _ver, root_clus, fsinfo = struct.unpack_from("<HHIH", bs, 40)
            ext = 64
        else:
            ext_flags, root_clus, fsinfo = 0, 0, 0
            ext = 36
        if fatsz * bps * 8 // bits < clusters + 2:
            raise BeastError(f"corrupt FAT filesystem {where}: the FAT is too small for {clusters} clusters")
        if off + total * bps > t.size:
            raise BeastError(f"the FAT filesystem {where} extends beyond the end of the target")
        sig = bs[ext + 2]
        self.volume_id = struct.unpack_from("<I", bs, ext + 3)[0] if sig in (0x28, 0x29) else 0
        self._bpb_label = bytes(bs[ext + 7 : ext + 18]) if sig == 0x29 else None
        self.fat_bits = bits
        self.bytes_per_sector = bps
        self.cluster_size = spc * bps
        self.cluster_count = clusters
        self.hidden_sectors = hidden
        self.total_sectors = total
        self._max_cluster = clusters + 1
        self._fat_bytes = fatsz * bps
        self._fat_offsets = [off + (rsvd + i * fatsz) * bps for i in range(nfats)]
        if bits == 32 and ext_flags & 0x80:  # mirroring off: only the active FAT is used
            active = ext_flags & 0x0F
            if active >= nfats:
                raise BeastError(f"corrupt FAT32 filesystem {where}: active FAT {active} does not exist")
            self._fat_offsets = [self._fat_offsets[active]]
        self._root_offset = off + (rsvd + nfats * fatsz) * bps
        self._root_bytes = root_secs * bps
        self._data_offset = off + data_start * bps
        self._root_cluster = root_clus
        if bits == 32 and not 2 <= root_clus <= self._max_cluster:
            raise BeastError(f"corrupt FAT32 filesystem {where}: invalid root cluster {root_clus}")
        self._fsinfo_offset = off + fsinfo * bps if bits == 32 and 0 < fsinfo < rsvd else None

    def _reset_state(self) -> None:
        """(Re)load everything cached from disk: the start, and the rollback."""
        self._fat = _Fat(self._t, self._fat_offsets[0], self._fat_offsets, self._fat_bytes,
                         self.fat_bits, self._max_cluster)
        self._dirs: dict[int, _Dir] = {}
        self._pending_free: list[list[int]] = []
        self._free: int | None = None
        self._hint = 2
        self._last_alloc: int | None = None
        self._fsinfo: bytearray | None = None
        if self._fsinfo_offset is not None:
            info = bytearray(self._t.read(self._fsinfo_offset, SECTOR_SIZE)).ljust(SECTOR_SIZE, b"\0")
            lead, = struct.unpack_from("<I", info, 0)
            struc, free, nxt = struct.unpack_from("<III", info, 484)
            if lead == FSINFO_LEAD_SIG and struc == FSINFO_STRUC_SIG:
                self._fsinfo = info
                if free <= self.cluster_count:
                    self._free = free
                if 2 <= nxt <= self._max_cluster:
                    self._hint = nxt + 1 if nxt < self._max_cluster else 2

    # -- clusters ----------------------------------------------------------

    def _cluster_offset(self, n: int) -> int:
        return self._data_offset + (n - 2) * self.cluster_size

    def _chain(self, first: int, limit: int | None = None) -> list[int]:
        bits = self.fat_bits
        if not 2 <= first <= self._max_cluster:
            raise BeastError(f"corrupt FAT filesystem: invalid cluster number {first}")
        out = [first]
        c = first
        while limit is None or len(out) < limit:
            nxt = self._fat.get(c)
            if nxt >= EOC_MIN[bits]:
                break
            if not 2 <= nxt <= self._max_cluster:
                raise BeastError(f"corrupt FAT filesystem: cluster {c} points to {nxt:#x}")
            if len(out) >= self.cluster_count:
                raise BeastError("corrupt FAT filesystem: cluster chain loops")
            out.append(nxt)
            c = nxt
        return out

    def _runs(self, chain: list[int]) -> list[tuple[int, int]]:
        """[(first cluster, count)] of contiguous stretches."""
        runs: list[tuple[int, int]] = []
        for c in chain:
            if runs and runs[-1][0] + runs[-1][1] == c:
                runs[-1] = (runs[-1][0], runs[-1][1] + 1)
            else:
                runs.append((c, 1))
        return runs

    def _read_clusters(self, chain: list[int]) -> bytes:
        cs = self.cluster_size
        out = bytearray()
        for first, count in self._runs(chain):
            data = self._t.read(self._cluster_offset(first), count * cs)
            if len(data) != count * cs:
                raise BeastError("short read from the FAT volume")
            out += data
        return bytes(out)

    def _write_clusters(self, chain: list[int], data: bytes) -> None:
        """Write `data` over the chain; the last cluster is padded with zeros."""
        cs = self.cluster_size
        pos = 0
        for first, count in self._runs(chain):
            off = self._cluster_offset(first)
            end = pos + count * cs
            while pos < end:
                n = min(end - pos, 8 << 20)
                chunk = data[pos : pos + n]
                if len(chunk) < n:
                    chunk = bytes(chunk) + bytes(n - len(chunk))
                self._t.write(off, bytes(chunk))
                off += n
                pos += n

    def _alloc(self, count: int) -> list[int]:
        """Allocate and link `count` clusters (contiguous when possible)."""
        if count == 0:
            return []
        if self._free is not None and count > self._free:  # fail fast instead of scanning the FAT
            self._free = self._fat.count_free()  # FSInfo may be stale: count exactly
            if count > self._free and self._pending_free:
                self._apply_frees()
            if count > self._free:
                raise FatNoSpace(
                    f"not enough free space on the FAT volume ({_human(count * self.cluster_size)} needed, "
                    f"{_human(self._free * self.cluster_size)} free)"
                )
        found = self._fat.find_free(count, self._hint)
        if found is None and self._pending_free:
            self._apply_frees()
            found = self._fat.find_free(count, self._hint)
        if found is None:
            raise FatNoSpace(
                f"not enough free space on the FAT volume (need {count} clusters of {self.cluster_size} bytes)"
            )
        for a, b in zip(found, found[1:]):
            self._fat.set(a, b)
        self._fat.set(found[-1], EOC[self.fat_bits])
        self._last_alloc = found[-1]
        self._hint = found[-1] + 1 if found[-1] < self._max_cluster else 2
        if self._free is not None:
            self._free -= count
        return found

    def _apply_frees(self) -> None:
        for chain in self._pending_free:
            for c in chain:
                if self._fat.get(c) == 0:
                    continue  # freed already (cross-linked chains on a corrupt volume)
                self._fat.set(c, 0)
                if self._free is not None:
                    self._free += 1
        self._pending_free = []

    # -- directories -------------------------------------------------------

    def _root_key(self) -> int:
        return self._root_cluster if self.fat_bits == 32 else 0

    def _root(self) -> _Dir:
        return self._dir(self._root_key())

    def _dir(self, key: int) -> _Dir:
        d = self._dirs.get(key)
        if d is None:
            fat32 = self.fat_bits == 32
            is_root = key == self._root_key()
            if key == 0 and not fat32:
                data = bytearray(self._t.read(self._root_offset, self._root_bytes))
                d = _Dir(0, [], data, self.bytes_per_sector, fat32=False, is_root=True)
            else:
                chain = self._chain(key)
                if len(chain) * self.cluster_size > MAX_DIR_ENTRIES * DIRENT_SIZE:
                    raise BeastError("corrupt FAT filesystem: directory larger than 2 MiB")
                data = bytearray(self._read_clusters(chain))
                d = _Dir(key, chain, data, self.cluster_size, fat32=fat32, is_root=is_root)
            self._dirs[key] = d
        return d

    def _block_offset(self, d: _Dir, i: int) -> int:
        if not d.clusters:
            return self._root_offset + i * d.block
        return self._cluster_offset(d.clusters[i])

    def _flush_dir(self, d: _Dir) -> None:
        if not d.dirty:
            return
        blocks = sorted(d.dirty)
        start = prev = blocks[0]
        for i in blocks[1:] + [None]:
            if i is not None and i == prev + 1 and self._block_offset(d, i) == self._block_offset(d, prev) + d.block:
                prev = i
                continue
            self._t.write(self._block_offset(d, start), bytes(d.data[start * d.block : (prev + 1) * d.block]))
            if i is not None:
                start = prev = i
        d.dirty.clear()

    def _grow_dir(self, d: _Dir, slots: int) -> None:
        """Make room for `slots` more entries at the end of `d`."""
        if not d.clusters:
            raise FatNoSpace(f"the root directory is full ({d.capacity} entries)")
        need = (d.end + slots) * DIRENT_SIZE - len(d.data)
        if need <= 0:
            return
        count = -(-need // self.cluster_size)
        if len(d.data) + count * self.cluster_size > MAX_DIR_ENTRIES * DIRENT_SIZE:
            raise BeastError("a FAT directory cannot hold more than 65536 entries")
        new = self._alloc(count)
        self._fat.set(d.clusters[-1], new[0])
        first_block = len(d.clusters)
        d.clusters.extend(new)
        d.data.extend(bytes(count * self.cluster_size))
        d.dirty.update(range(first_block, len(d.clusters)))

    def _short_name(self, d: _Dir, name: str) -> tuple[bytes, bool]:
        """(8.3 name, needs long-name entries)."""
        reserved = self._reserved.get(d.key, ())
        own = plain_short_name(_fold(name))  # what this name may take even if reserved

        def free(cand: bytes) -> bool:
            return cand not in d.shorts and (cand == own or cand not in reserved)

        plain = plain_short_name(name)
        if plain is not None and free(plain):
            return plain, False
        base, ext, lossy = _basis_name(name)
        if not lossy and free(_pack83(base, ext)):
            return _pack83(base, ext), True
        for k in range(1, 1_000_000):
            tail = f"~{k}"
            cand = _pack83(base[: 8 - len(tail)] + tail, ext)
            if free(cand):
                return cand, True
        raise BeastError(f"no free 8.3 alias for {name!r}")

    def _add_entry(self, d: _Dir, name: str, attr: int, cluster: int, size: int) -> _Ent:
        _check_name(name)
        short, needs_lfn = self._short_name(d, name)
        raw = _lfn_entries(name, lfn_checksum(short)) if needs_lfn else b""
        raw += _short_entry(short, attr, cluster, size, self._stamp)
        n = len(raw) // DIRENT_SIZE
        slot = d.find_slots(n)
        if slot is None:
            self._grow_dir(d, n)
            slot = d.find_slots(n)
            assert slot is not None
        d.put(slot, raw)
        ent = _Ent(name if needs_lfn else _short_display(short, 0), short, attr, cluster, size,
                   slot, slot + n - 1)
        d.add(ent)
        return ent

    def _make_dir(self, parent: _Dir, name: str, slots: int = 2) -> _Dir:
        _check_name(name)
        count = max(1, -(-slots * DIRENT_SIZE // self.cluster_size))
        chain = self._alloc(count)
        data = bytearray(count * self.cluster_size)
        parent_cluster = 0 if parent.is_root else parent.key  # '..' of a root child is 0, also on FAT32
        data[0:DIRENT_SIZE] = _short_entry(DOT, ATTR_DIRECTORY, chain[0], 0, self._stamp)
        data[DIRENT_SIZE : 2 * DIRENT_SIZE] = _short_entry(DOTDOT, ATTR_DIRECTORY, parent_cluster, 0, self._stamp)
        d = _Dir(chain[0], chain, data, self.cluster_size, fat32=self.fat_bits == 32, is_root=False)
        d.dirty.update(range(count))
        self._dirs[chain[0]] = d
        self._add_entry(parent, name, ATTR_DIRECTORY, chain[0], 0)
        return d

    def _walk(self, parts: list[str], *, create: bool = False) -> _Dir:
        d = self._root()
        for i, part in enumerate(parts):
            ent = d.lookup(part)
            if ent is None:
                if not create:
                    raise BeastError(f"/{'/'.join(parts[: i + 1])}: no such directory on the FAT volume")
                d = self._make_dir(d, part)
            elif not ent.is_dir:
                raise BeastError(f"/{'/'.join(parts[: i + 1])} is a file, not a directory")
            elif ent.cluster == 0:
                raise BeastError(f"corrupt FAT filesystem: directory /{'/'.join(parts[: i + 1])} has no cluster")
            else:
                d = self._dir(ent.cluster)
        return d

    def _find(self, path: str) -> tuple[_Dir, _Ent]:
        parts = _split(path)
        if not parts:
            raise BeastError("the root directory is not a file")
        parent = self._walk(parts[:-1])
        ent = parent.lookup(parts[-1])
        if ent is None:
            raise BeastError(f"/{'/'.join(parts)}: no such file or directory on the FAT volume")
        return parent, ent

    def _put_file(self, parent: _Dir, name: str, data: bytes) -> _Ent:
        """Create or replace `name` in `parent`; returns its directory entry."""
        ent = parent.lookup(name)
        if ent is not None and ent.is_dir:
            raise BeastError(f"{name!r} is a directory")
        old = self._chain(ent.cluster) if ent is not None and ent.cluster else []
        count = -(-len(data) // self.cluster_size)
        try:
            chain = self._alloc(count)  # the old clusters stay allocated until the entry points away
        except FatNoSpace:
            if not old:
                raise
            self._pending_free.append(old)
            old = []
            chain = self._alloc(count)
        self._write_clusters(chain, data)
        first = chain[0] if chain else 0
        if ent is None:
            return self._add_entry(parent, name, ATTR_ARCHIVE, first, len(data))
        raw = bytearray(parent.data[ent.slot * DIRENT_SIZE : (ent.slot + 1) * DIRENT_SIZE])
        date, clock, _tenths = self._stamp
        raw[11] |= ATTR_ARCHIVE
        struct.pack_into("<HHHHHI", raw, 18, date, first >> 16, clock, date, first & 0xFFFF, len(data))
        parent.put(ent.slot, bytes(raw))
        ent.cluster, ent.size = first, len(data)
        if old:
            self._pending_free.append(old)
        return ent

    def _delete(self, parent: _Dir, ent: _Ent) -> None:
        """Remove `ent` from `parent`; a directory takes its whole subtree along.

        Only the entry in `parent` is marked deleted. The subtree is walked
        without recursion (so depth does not matter) to collect the cluster
        chains to free; its directories are freed as a whole, so their own
        entries need no rewriting. A directory reached twice, e.g. a corrupt
        entry pointing back at an ancestor, is an error, not an endless loop."""
        chains: list[list[int]] = []
        subdirs: list[int] = []
        seen = {self._root_key(), parent.key}
        todo = [ent]
        while todo:
            e = todo.pop()
            if not e.cluster:
                continue  # an empty file (or a corrupt directory entry): nothing to free
            if e.is_dir:
                if e.cluster in seen:
                    raise BeastError(f"corrupt FAT filesystem: directory loop at {e.name!r}")
                seen.add(e.cluster)
                todo.extend(self._dir(e.cluster).entries)
                subdirs.append(e.cluster)
            chains.append(self._chain(e.cluster))
        for slot in range(ent.first_slot, ent.slot + 1):
            raw = bytearray(parent.data[slot * DIRENT_SIZE : (slot + 1) * DIRENT_SIZE])
            raw[0] = DELETED
            parent.put(slot, bytes(raw))
        parent.has_deleted = True
        parent.forget(ent)
        for key in subdirs:  # never written back: their clusters are freed
            self._dirs.pop(key, None)
        self._pending_free.extend(chains)

    # -- transactions ------------------------------------------------------

    @contextmanager
    def batch(self):
        """Group changes: they are written when the outermost batch ends.

        If an error escapes from inside a batch, all of its changes are dropped
        (what is on disk stays as it was, apart from data written to clusters
        that are still free)."""
        self._depth += 1
        try:
            yield self
        except BaseException:
            self._depth -= 1
            if self._depth == 0:
                self._failed = False
                self._reset_state()
            else:
                self._failed = True  # the outermost batch must not commit half of it
            raise
        self._depth -= 1
        if self._depth:
            return
        if self._failed:
            self._failed = False
            self._reset_state()
            raise BeastError("changes to the FAT volume were dropped after an earlier error")
        try:
            self._commit()
        except BaseException:
            self._reset_state()
            raise

    def _commit(self) -> None:
        self._fat.flush()
        for d in self._dirs.values():
            self._flush_dir(d)
        if self._pending_free:
            self._apply_frees()
            self._fat.flush()
        if self._fsinfo is not None:
            info = self._fsinfo
            free = self._free if self._free is not None else FSINFO_UNKNOWN
            nxt = self._last_alloc if self._last_alloc is not None else struct.unpack_from("<I", info, 492)[0]
            if struct.unpack_from("<II", info, 488) != (free, nxt):
                struct.pack_into("<II", info, 488, free, nxt)
                self._t.write(self._fsinfo_offset, bytes(info))

    # -- public API --------------------------------------------------------

    def listdir(self, path: str = "") -> list[DirEntry]:
        d = self._walk(_split(path))
        return [DirEntry(e.name, e.is_dir, 0 if e.is_dir else e.size)
                for e in sorted(d.entries, key=lambda e: e.slot)]

    def exists(self, path: str) -> bool:
        parts = _split(path)
        try:
            parent = self._walk(parts[:-1])
        except BeastError:
            return False
        return not parts or parent.lookup(parts[-1]) is not None

    def read_file(self, path: str) -> bytes:
        _parent, ent = self._find(path)
        if ent.is_dir:
            raise BeastError(f"{path} is a directory")
        if ent.size == 0:
            return b""
        need = -(-ent.size // self.cluster_size)
        chain = self._chain(ent.cluster, need)
        if len(chain) < need:
            raise BeastError(f"corrupt FAT filesystem: {path} is shorter than its size")
        return self._read_clusters(chain)[: ent.size]

    def write_file(self, path: str, data: bytes) -> None:
        """Create or replace a file; missing parent directories are created."""
        parts = _split(path)
        if not parts:
            raise BeastError("cannot write to the root directory itself")
        data = _file_bytes(data, path)
        with self.batch():
            self._put_file(self._walk(parts[:-1], create=True), parts[-1], data)

    def mkdir(self, path: str) -> None:
        """Create a directory and any missing parents (an existing directory is fine)."""
        with self.batch():
            self._walk(_split(path), create=True)

    def remove(self, path: str, *, recursive: bool = False) -> None:
        """Remove a file or a directory (non-empty ones only with recursive=True)."""
        with self.batch():
            parent, ent = self._find(path)
            if ent.is_dir and ent.cluster and not recursive and self._dir(ent.cluster).entries:
                raise BeastError(f"{path}: directory is not empty")
            self._delete(parent, ent)

    def write_files(self, files: dict[str, bytes]) -> None:
        """Write many files in one batch; new directories get room for all their
        entries up front, so each directory occupies contiguous clusters.

        Every key names its own file: two keys that would end up as the same
        entry (the same name in another case, or one key being the 8.3 alias
        of an existing file another key names) are an error, and no generated
        8.3 alias takes a name that another key of the batch asks for."""
        self._write_batch(_BatchPlan(files))

    def _write_batch(self, plan: _BatchPlan) -> None:
        self._check_space(list(plan.items.values()))
        with self.batch():
            try:
                root = self._root()
                self._reserve(root, plan, ())
                if root.clusters:  # FAT32: reserve room in the root directory too
                    free_tail = root.capacity - root.end
                    if plan.slots.get((), 0) > free_tail:
                        self._grow_dir(root, plan.slots[()])
                for key in sorted(plan.dirs):  # a parent sorts before its children
                    parts = plan.dirs[key]
                    parent = self._walk(parts[:-1])
                    ent = parent.lookup(parts[-1])
                    if ent is None:
                        d = self._make_dir(parent, parts[-1], 2 + plan.slots.get(key, 0))
                    elif not ent.is_dir:
                        raise BeastError(f"/{'/'.join(parts)} is a file, not a directory")
                    else:
                        d = self._walk(parts)
                    self._reserve(d, plan, key)
                written: dict[tuple[int, int], str] = {}  # (directory, slot) -> path
                for key in sorted(plan.items):
                    parts, data = plan.items[key]
                    parent = self._walk(parts[:-1])
                    ent = self._put_file(parent, parts[-1], data)
                    path = "/".join(parts)
                    other = written.setdefault((parent.key, ent.slot), path)
                    if other != path:
                        raise BeastError(f"{other!r} and {path!r} name the same file on the FAT volume")
            finally:
                self._reserved = {}

    def _reserve(self, d: _Dir, plan: _BatchPlan, key: tuple[str, ...]) -> None:
        self._reserved.setdefault(d.key, set()).update(plan.shorts.get(key, ()))

    def _check_space(self, items: list[tuple[list[str], bytes]]) -> None:
        """Fail before writing any data when the files clearly cannot fit."""
        cs = self.cluster_size
        need = sum(-(-len(data) // cs) for _parts, data in items)
        reusable = 0  # clusters of files that are about to be replaced
        for parts, _data in items:
            try:
                ent = self._walk(parts[:-1]).lookup(parts[-1])
            except BeastError:
                continue
            if ent is not None and not ent.is_dir:
                reusable += -(-ent.size // cs)
        if need > self.free_bytes() // cs + reusable:
            self._free = self._fat.count_free()  # FSInfo may be stale: count exactly
            if need > self._free + reusable:
                raise FatNoSpace(
                    f"not enough free space on the FAT volume ({_human(need * cs)} needed, "
                    f"{_human(self._free * cs)} free)"
                )

    def free_bytes(self) -> int:
        if self._free is None:
            self._free = self._fat.count_free()
        return self._free * self.cluster_size

    def flush(self) -> None:
        """Make everything written so far durable."""
        self._t.flush()


# ---------------------------------------------------------------------------
# The ESP
# ---------------------------------------------------------------------------


def build_esp(t, offset: int, size: int, files: dict[str, bytes], *, label: str, volume_id: int,
              hidden_sectors: int, timestamp: float | None = None) -> None:
    """Format [offset, offset+size) as the ESP (FAT32 in layout 2) and write every file
    (keys are ESP paths like "EFI/BOOT/BOOTX64.EFI").

    The file list is checked first, so bad names or contents never leave a
    freshly formatted, empty ESP behind."""
    plan = _BatchPlan(files)
    format_fat(t, offset, size, fat_bits=ESP_FAT_BITS, label=label, volume_id=volume_id,
               hidden_sectors=hidden_sectors, timestamp=timestamp)
    vol = FatVolume(t, offset, timestamp=timestamp)
    try:
        vol._write_batch(plan)
    except FatNoSpace as e:
        total = sum(len(data) for _parts, data in plan.items.values())
        raise BeastError(
            f"the boot files ({_human(total)} in {len(files)} files) do not fit into the "
            f"{_human(size)} ESP ({e})"
        ) from None
