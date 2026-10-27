"""exFAT in pure Python: quick format (format_exfat) and a small reader/writer (ExfatVolume).

Follows the Microsoft "exFAT file system specification"
(https://learn.microsoft.com/windows/win32/fileio/exfat-specification); section
numbers in comments refer to it. No external tools are needed, so the data
partition can be created the same way on Linux, Windows and macOS. Linux tools
(fsck.exfat, blkid, the kernel driver) are used only by the tests, as
independent validators.

What format_exfat writes (sector numbers relative to the start of the volume):

    0         Main Boot Sector: geometry, serial number, FileSystemRevision 1.00
    1..8      Main Extended Boot Sectors: empty, signature AA550000h at the end
    9         Main OEM Parameters: zero
    10        reserved: zero
    11        Main Boot Checksum: one 32-bit checksum of sectors 0..10, repeated
    12..23    Backup Boot Region: identical copy of sectors 0..11
    ..        zero up to FatOffset
    FatOffset FAT: entry 0 = media type F8, entry 1 = FFFFFFFF, cluster chains of
              the three metadata objects below, every other entry zero (free)
    ..        zero up to ClusterHeapOffset
    ClusterHeapOffset = cluster 2, the first cluster:
              Allocation Bitmap (1 bit per cluster; 1 = in use)
              Up-case Table (the specification's recommended table, compressed)
              Root directory: Volume Label, an unused slot (room for a Volume GUID
              entry, like mkfs.exfat), Allocation Bitmap and Up-case Table entries

The geometry (FatOffset, FatLength, ClusterHeapOffset, ClusterCount, cluster
size) is computed exactly as exfatprogs' mkfs.exfat 1.3 computes it: FAT and
cluster heap aligned to 1 MiB from the start of the volume, cluster size 4 KiB
up to 256 MiB, 32 KiB up to 32 GiB, 128 KiB above (the Windows defaults). The
tests compare every boot sector field, the FAT, bitmap, up-case table and root
directory with what mkfs.exfat writes for the same size. Intentional differences:

  * VolumeSerialNumber is the caller's `volume_serial` (mkfs.exfat: from the clock).
  * BootCode is a 4-byte halt loop instead of zeros (and so the checksum differs).
  * PartitionOffset is the volume's position in the target (mkfs.exfat: the
    partition start from sysfs, 0 for an image file; same meaning).
  * Volumes under 8 MiB are aligned to the cluster size instead of 1 MiB
    (mkfs.exfat would spend 2 MiB of a 3 MiB volume on alignment).
  * PercentInUse is computed (mkfs.exfat writes 0; equal except on tiny volumes).
  * No Volume GUID entry (optional in the specification; neither mkfs.exfat nor
    Windows write one by default). Like mkfs.exfat, the root keeps an unused
    slot for one, so tune.exfat -U can add it in place.

This is a quick format: only metadata is written, but every metadata byte is
written (the whole region in front of the cluster heap, the FAT included, and
every metadata cluster), so nothing depends on the target having been zero.
mkfs.exfat's quick format writes only the used FAT entries and relies on discard.

ExfatVolume reads any spec-conforming exFAT volume (files, nested directories,
contiguous "NoFatChain" and FAT-chained data, long and non-ASCII names,
case-insensitive lookup through the volume's own up-case table). It can also
create directories and write, replace and remove files - meant for small files
such as /beast-booter/config.cfg; data is written contiguously when possible.
A change is checked in full first (names, and free space for every cluster it
allocates), so a refused one, e.g. on a full volume, writes nothing at all.
"""

from __future__ import annotations

import struct
import time
from array import array
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .errors import BeastError
from .interfaces import BlockTarget, DirEntry

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

SECTOR_SIZES = (512, 1024, 2048, 4096)  # BytesPerSectorShift 9..12 (§3.1.14)
MAX_CLUSTER_SIZE = 32 * MIB  # BytesPerSectorShift + SectorsPerClusterShift <= 25 (§3.1.15)
MAX_CLUSTER_COUNT = 0xFFFFFFF5  # 2^32 - 11 (§3.1.9)
MIN_VOLUME_SIZE = 1 * MIB  # VolumeLength >= 2^20 bytes (§3.1.5)
BOUNDARY_ALIGN = 1 * MIB  # FAT and cluster heap start on a 1 MiB boundary (as mkfs.exfat)
SMALL_VOLUME = 8 * MIB  # below this, align to the cluster size instead (1 MiB would waste too much)

BOOT_REGION_SECTORS = 12  # boot + 8 extended + OEM + reserved + checksum (§3)
EXTENDED_BOOT_SIGNATURE = b"\x00\x00\x55\xaa"  # AA550000h, little-endian (§3.2.1)
FILE_SYSTEM_NAME = b"EXFAT   "
JUMP_BOOT = b"\xeb\x76\x90"  # jmp short to BootCode, nop (§3.1.1)
# BootCode (§3.1.20): this volume is not meant to be booted (the MBR boots GRUB).
# If something jumps here anyway, stop safely: cli; hlt; jmp back to hlt.
BOOT_CODE = b"\xfa\xf4\xeb\xfd"
FILE_SYSTEM_REVISION = 0x0100  # 1.00
DRIVE_SELECT = 0x80

FIRST_CLUSTER = 2  # clusters are numbered from 2; bit 0 of the bitmap is cluster 2
FAT_FREE = 0x00000000
FAT_BAD = 0xFFFFFFF7
FAT_MEDIA = 0xFFFFFFF8  # FatEntry[0]: media type F8h (§4.1.1)
FAT_EOF = 0xFFFFFFFF  # end of a cluster chain; also FatEntry[1] (§4.1.2)

VOLUME_FLAG_ACTIVE_FAT = 0x0001  # VolumeFlags bits (§3.1.13)
VOLUME_FLAG_DIRTY = 0x0002
VOLUME_FLAG_MEDIA_FAILURE = 0x0004

ENTRY_SIZE = 32
ENTRY_END = 0x00  # end-of-directory marker (§6.2.1.1)
ENTRY_IN_USE = 0x80  # with this bit clear an entry is unused (deleted)
ENTRY_SECONDARY = 0x40  # TypeCategory: 0 = primary, 1 = secondary
ENTRY_BITMAP = 0x81  # Allocation Bitmap (§7.1)
ENTRY_UPCASE = 0x82  # Up-case Table (§7.2)
ENTRY_LABEL = 0x83  # Volume Label (§7.3)
ENTRY_FILE = 0x85  # File (§7.4)
ENTRY_GUID = 0xA0  # Volume GUID (§7.5)
ENTRY_STREAM = 0xC0  # Stream Extension (§7.6)
ENTRY_NAME = 0xC1  # File Name (§7.7)
ENTRY_GUID_SLOT = ENTRY_GUID & ~ENTRY_IN_USE  # unused entry mkfs.exfat leaves for a GUID

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

STREAM_ALLOCATION_POSSIBLE = 0x01  # GeneralSecondaryFlags (§6.4.1)
STREAM_NO_FAT_CHAIN = 0x02  # data is contiguous; the FAT is not used for it

LABEL_MAX_CHARS = 11  # Volume Label: 11 UTF-16 code units (§7.3.2)
NAME_MAX_CHARS = 255  # File name: 255 UTF-16 code units (§7.6.3)
NAME_CHARS_PER_ENTRY = 15
INVALID_NAME_CHARS = frozenset('"*/:<>?\\|') | frozenset(chr(c) for c in range(0x20))  # §7.7.3
UTC_OFFSET_VALID = 0x80  # UtcOffset field: bit 7 = offset is valid; 0 = UTC (§7.4.10)

ZERO_CHUNK = 4 * MIB  # bytes per write when clearing a region
FAT_CACHE_CHUNK = 64 * KIB


# ---------------------------------------------------------------------------
# Up-case table (§7.2.5)
# ---------------------------------------------------------------------------
#
# The specification's "recommended up-case table", rebuilt byte for byte from
# readable data instead of a binary blob. Each tuple (first, last, step, delta)
# means: for code points first, first+step, ... last, the upper-case form is
# code point + delta. Every code point not listed maps to itself.

_UPCASE_RANGES = (
    (0x0061, 0x007A, 1, -32), (0x00E0, 0x00F6, 1, -32), (0x00F8, 0x00FE, 1, -32),
    (0x00FF, 0x00FF, 1, +121), (0x0101, 0x012F, 2, -1), (0x0133, 0x0137, 2, -1),
    (0x013A, 0x0148, 2, -1), (0x014B, 0x0177, 2, -1), (0x017A, 0x017E, 2, -1),
    (0x0180, 0x0180, 1, +195), (0x0183, 0x0185, 2, -1), (0x0188, 0x0188, 1, -1),
    (0x018C, 0x018C, 1, -1), (0x0192, 0x0192, 1, -1), (0x0195, 0x0195, 1, +97),
    (0x0199, 0x0199, 1, -1), (0x019A, 0x019A, 1, +163), (0x019E, 0x019E, 1, +130),
    (0x01A1, 0x01A5, 2, -1), (0x01A8, 0x01A8, 1, -1), (0x01AD, 0x01AD, 1, -1),
    (0x01B0, 0x01B0, 1, -1), (0x01B4, 0x01B6, 2, -1), (0x01B9, 0x01B9, 1, -1),
    (0x01BD, 0x01BD, 1, -1), (0x01BF, 0x01BF, 1, +56), (0x01C6, 0x01C6, 1, -2),
    (0x01C9, 0x01C9, 1, -2), (0x01CC, 0x01CC, 1, -2), (0x01CE, 0x01DC, 2, -1),
    (0x01DD, 0x01DD, 1, -79), (0x01DF, 0x01EF, 2, -1), (0x01F3, 0x01F3, 1, -2),
    (0x01F5, 0x01F5, 1, -1), (0x01F9, 0x021F, 2, -1), (0x0223, 0x0233, 2, -1),
    (0x023A, 0x023A, 1, +10795), (0x023C, 0x023C, 1, -1), (0x023E, 0x023E, 1, +10792),
    (0x0242, 0x0242, 1, -1), (0x0247, 0x024F, 2, -1), (0x0253, 0x0253, 1, -210),
    (0x0254, 0x0254, 1, -206), (0x0256, 0x0257, 1, -205), (0x0259, 0x0259, 1, -202),
    (0x025B, 0x025B, 1, -203), (0x0260, 0x0260, 1, -205), (0x0263, 0x0263, 1, -207),
    (0x0268, 0x0268, 1, -209), (0x0269, 0x0269, 1, -211), (0x026B, 0x026B, 1, +10743),
    (0x026F, 0x026F, 1, -211), (0x0272, 0x0272, 1, -213), (0x0275, 0x0275, 1, -214),
    (0x027D, 0x027D, 1, +10727), (0x0280, 0x0280, 1, -218), (0x0283, 0x0283, 1, -218),
    (0x0288, 0x0288, 1, -218), (0x0289, 0x0289, 1, -69), (0x028A, 0x028B, 1, -217),
    (0x028C, 0x028C, 1, -71), (0x0292, 0x0292, 1, -219), (0x037B, 0x037D, 1, +130),
    (0x03AC, 0x03AC, 1, -38), (0x03AD, 0x03AF, 1, -37), (0x03B1, 0x03C1, 1, -32),
    (0x03C2, 0x03C2, 1, -31), (0x03C3, 0x03CB, 1, -32), (0x03CC, 0x03CC, 1, -64),
    (0x03CD, 0x03CE, 1, -63), (0x03D9, 0x03EF, 2, -1), (0x03F2, 0x03F2, 1, +7),
    (0x03F8, 0x03F8, 1, -1), (0x03FB, 0x03FB, 1, -1), (0x0430, 0x044F, 1, -32),
    (0x0450, 0x045F, 1, -80), (0x0461, 0x0481, 2, -1), (0x048B, 0x04BF, 2, -1),
    (0x04C2, 0x04CE, 2, -1), (0x04CF, 0x04CF, 1, -15), (0x04D1, 0x0513, 2, -1),
    (0x0561, 0x0586, 1, -48), (0x1D7D, 0x1D7D, 1, +3814), (0x1E01, 0x1E95, 2, -1),
    (0x1EA1, 0x1EF9, 2, -1), (0x1F00, 0x1F07, 1, +8), (0x1F10, 0x1F15, 1, +8),
    (0x1F20, 0x1F27, 1, +8), (0x1F30, 0x1F37, 1, +8), (0x1F40, 0x1F45, 1, +8),
    (0x1F51, 0x1F57, 2, +8), (0x1F60, 0x1F67, 1, +8), (0x1F70, 0x1F71, 1, +74),
    (0x1F72, 0x1F75, 1, +86), (0x1F76, 0x1F77, 1, +100), (0x1F78, 0x1F79, 1, +128),
    (0x1F7A, 0x1F7B, 1, +112), (0x1F7C, 0x1F7D, 1, +126), (0x1F80, 0x1F87, 1, +8),
    (0x1F90, 0x1F97, 1, +8), (0x1FA0, 0x1FA7, 1, +8), (0x1FB0, 0x1FB1, 1, +8),
    (0x1FB3, 0x1FB3, 1, +9), (0x1FCC, 0x1FCC, 1, -9), (0x1FD0, 0x1FD1, 1, +8),
    (0x1FE0, 0x1FE1, 1, +8), (0x1FE5, 0x1FE5, 1, +7), (0x1FFC, 0x1FFC, 1, -9),
    (0x214E, 0x214E, 1, -28), (0x2170, 0x217F, 1, -16), (0x2184, 0x2184, 1, -1),
    (0x24D0, 0x24E9, 1, -26), (0x2C30, 0x2C5E, 1, -48), (0x2C61, 0x2C61, 1, -1),
    (0x2C68, 0x2C6C, 2, -1), (0x2C76, 0x2C76, 1, -1), (0x2C81, 0x2CE3, 2, -1),
    (0x2D00, 0x2D25, 1, -7264), (0xFF41, 0xFF5A, 1, -32),
)

# Runs of code points that map to themselves and that the recommended table
# stores compressed, as the pair FFFFh, <run length> (inclusive ranges).
_UPCASE_COMPRESSED_RUNS = ((0x0587, 0x1D7C), (0x2185, 0x24CF), (0x24EA, 0x2C2F), (0x2D26, 0xFF40))

UPCASE_TABLE_SIZE = 5836  # bytes of the compressed recommended table
UPCASE_TABLE_CHECKSUM = 0xE619D30D  # its TableChecksum, as given in the specification


def _le16_bytes(words: array) -> bytes:
    """An array of 16-bit words as little-endian bytes (on any host byte order)."""
    if struct.pack("=H", 1) != struct.pack("<H", 1):
        words = array("H", words)
        words.byteswap()
    return words.tobytes()


def default_upcase_mapping() -> array:
    """Upper-case form of every UTF-16 code unit, per the recommended table."""
    mapping = array("H", range(0x10000))
    for first, last, step, delta in _UPCASE_RANGES:
        for code in range(first, last + 1, step):
            mapping[code] = code + delta
    return mapping


def build_upcase_table() -> bytes:
    """The recommended up-case table in its compressed on-disk form (§7.2.5.1)."""
    mapping = default_upcase_mapping()
    runs = {first: last for first, last in _UPCASE_COMPRESSED_RUNS}
    words = array("H")
    code = 0
    while code < 0x10000:
        if code in runs:
            words.extend((0xFFFF, runs[code] - code + 1))
            code = runs[code] + 1
        else:
            words.append(mapping[code])
            code += 1
    return _le16_bytes(words)


def decompress_upcase_table(data: bytes) -> array:
    """Mapping of all 65536 code units from an on-disk up-case table (compressed or not)."""
    mapping = array("H", range(0x10000))
    words = array("H", data[: len(data) // 2 * 2])
    if struct.pack("=H", 1) != struct.pack("<H", 1):
        words.byteswap()
    code = 0
    skip_next = False
    for word in words:
        if code > 0xFFFF:
            break
        if skip_next:  # word after FFFFh: number of code points that map to themselves
            code += word
            skip_next = False
        elif word == code:
            code += 1
        elif word == 0xFFFF:
            skip_next = True
        else:
            mapping[code] = word
            code += 1
    return mapping


def upcase_table_checksum(data: bytes) -> int:
    """TableChecksum of an up-case table (§7.2.2)."""
    checksum = 0
    for byte in data:
        checksum = (((checksum >> 1) | ((checksum & 1) << 31)) + byte) & 0xFFFFFFFF
    return checksum


UPCASE_TABLE = build_upcase_table()


# ---------------------------------------------------------------------------
# Checksums and hashes
# ---------------------------------------------------------------------------


def boot_checksum(sectors: bytes) -> int:
    """Boot Checksum over sectors 0..10 of a boot region (§3.4).

    VolumeFlags (bytes 106-107) and PercentInUse (byte 112) of the boot sector
    are left out, so they can change without rewriting the checksum.
    """
    checksum = 0
    for index, byte in enumerate(sectors):
        if index in (106, 107, 112):
            continue
        checksum = (((checksum >> 1) | ((checksum & 1) << 31)) + byte) & 0xFFFFFFFF
    return checksum


def entry_set_checksum(entry_set: bytes) -> int:
    """SetChecksum of a directory entry set, skipping the field itself (§6.3.3)."""
    checksum = 0
    for index, byte in enumerate(entry_set):
        if index in (2, 3):
            continue
        checksum = (((checksum >> 1) | ((checksum & 1) << 15)) + byte) & 0xFFFF
    return checksum


def name_hash(upcased_name: bytes) -> int:
    """NameHash of an up-cased UTF-16LE file name (§7.6.4)."""
    checksum = 0
    for byte in upcased_name:
        checksum = (((checksum >> 1) | ((checksum & 1) << 15)) + byte) & 0xFFFF
    return checksum


# ---------------------------------------------------------------------------
# Boot sector and volume geometry
# ---------------------------------------------------------------------------

# Main Boot Sector fields from byte 64 to 119 (§3.1, table 3).
_BOOT_FIELDS = struct.Struct("<QQIIIIIIHHBBBBB7x")
_BOOT_FIELDS_OFFSET = 64
_BOOT_CODE_OFFSET = 120
_VOLUME_FLAGS_OFFSET = 106
_PERCENT_IN_USE_OFFSET = 112


@dataclass
class BootSector:
    """The fields of an exFAT Main/Backup Boot Sector. Offsets and lengths are in sectors."""

    partition_offset: int  # where the volume starts on the disk; 0 = unknown
    volume_length: int
    fat_offset: int
    fat_length: int
    cluster_heap_offset: int
    cluster_count: int
    root_cluster: int  # FirstClusterOfRootDirectory
    volume_serial: int
    file_system_revision: int = FILE_SYSTEM_REVISION
    volume_flags: int = 0
    bytes_per_sector_shift: int = 9
    sectors_per_cluster_shift: int = 0
    number_of_fats: int = 1
    drive_select: int = DRIVE_SELECT
    percent_in_use: int = 0

    @property
    def sector_size(self) -> int:
        return 1 << self.bytes_per_sector_shift

    @property
    def cluster_size(self) -> int:
        return 1 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)

    def pack(self) -> bytes:
        sector = bytearray(self.sector_size)
        sector[0:3] = JUMP_BOOT
        sector[3:11] = FILE_SYSTEM_NAME
        # bytes 11..63 (MustBeZero, where FAT12/16/32 keep their BPB) stay zero
        sector[_BOOT_FIELDS_OFFSET:_BOOT_CODE_OFFSET] = _BOOT_FIELDS.pack(
            self.partition_offset, self.volume_length, self.fat_offset, self.fat_length,
            self.cluster_heap_offset, self.cluster_count, self.root_cluster, self.volume_serial,
            self.file_system_revision, self.volume_flags, self.bytes_per_sector_shift,
            self.sectors_per_cluster_shift, self.number_of_fats, self.drive_select,
            self.percent_in_use,
        )
        sector[_BOOT_CODE_OFFSET:_BOOT_CODE_OFFSET + len(BOOT_CODE)] = BOOT_CODE
        sector[510:512] = b"\x55\xaa"
        return bytes(sector)

    @classmethod
    def parse(cls, sector: bytes) -> BootSector:
        """Decode and check a boot sector; BeastError if it is not a valid exFAT one."""
        if len(sector) < 512 or sector[3:11] != FILE_SYSTEM_NAME:
            raise BeastError("not an exFAT boot sector (no 'EXFAT' signature)")
        if sector[510:512] != b"\x55\xaa":
            raise BeastError("exFAT boot sector has no 55AA signature")
        if any(sector[11:64]):
            raise BeastError("exFAT boot sector: MustBeZero area is not zero")
        boot = cls(*_BOOT_FIELDS.unpack_from(sector, _BOOT_FIELDS_OFFSET))
        shift, spc_shift = boot.bytes_per_sector_shift, boot.sectors_per_cluster_shift
        problems = []
        if not 9 <= shift <= 12:
            problems.append(f"BytesPerSectorShift {shift}")
        if spc_shift > 25 - shift:
            problems.append(f"SectorsPerClusterShift {spc_shift}")
        if boot.number_of_fats not in (1, 2):
            problems.append(f"NumberOfFats {boot.number_of_fats}")
        if boot.file_system_revision >> 8 != 1:
            problems.append(f"FileSystemRevision {boot.file_system_revision >> 8}.{boot.file_system_revision & 0xFF:02d}")
        if boot.fat_offset < 24 or boot.fat_length == 0:
            problems.append("FAT position")
        if boot.cluster_heap_offset < boot.fat_offset + boot.fat_length * boot.number_of_fats:
            problems.append("ClusterHeapOffset")
        max_clusters = (boot.volume_length - boot.cluster_heap_offset) >> spc_shift if shift <= 12 else 0
        if not 0 < boot.cluster_count <= min(max_clusters, MAX_CLUSTER_COUNT):
            problems.append(f"ClusterCount {boot.cluster_count}")
        if boot.fat_length << shift < (boot.cluster_count + 2) * 4:
            problems.append("FatLength")
        if not FIRST_CLUSTER <= boot.root_cluster <= boot.cluster_count + 1:
            problems.append(f"FirstClusterOfRootDirectory {boot.root_cluster}")
        if problems:
            raise BeastError("invalid exFAT boot sector: " + ", ".join(problems))
        return boot


def default_cluster_size(size: int) -> int:
    """Cluster size Windows and mkfs.exfat choose for a volume of `size` bytes."""
    if size <= 256 * MIB:
        return 4 * KIB
    if size <= 32 * GIB:
        return 32 * KIB
    return 128 * KIB


def _round_up(value: int, multiple: int) -> int:
    return -(-value // multiple) * multiple


def _ceil_div(value: int, divisor: int) -> int:
    return -(-value // divisor)


@dataclass(frozen=True)
class Layout:
    """Where format_exfat puts things: the boot sector plus the metadata clusters."""

    boot: BootSector
    bitmap_cluster: int
    bitmap_bytes: int
    bitmap_clusters: int
    upcase_cluster: int
    upcase_clusters: int

    @property
    def root_cluster(self) -> int:
        return self.boot.root_cluster

    @property
    def used_clusters(self) -> int:
        return self.bitmap_clusters + self.upcase_clusters + 1  # + the root directory


def plan_layout(size: int, sector_size: int = 512, *, cluster_size: int | None = None,
                partition_offset: int = 0, volume_serial: int = 0) -> Layout:
    """Compute the volume geometry for `size` bytes (the algorithm of mkfs.exfat 1.3).

    FatOffset and ClusterHeapOffset are rounded up to BOUNDARY_ALIGN (1 MiB),
    measured from the start of the volume (beast-boot partitions start on a
    1 MiB boundary of the disk, so this is also disk-aligned). The FAT is
    sized for the most clusters that could fit behind it, each costing one
    cluster in the heap plus 4 bytes of FAT.
    """
    if sector_size not in SECTOR_SIZES:
        raise BeastError(f"unsupported sector size {sector_size} for exFAT (use 512..4096)")
    if cluster_size is None:
        cluster_size = default_cluster_size(size)
    if (cluster_size & (cluster_size - 1) or not sector_size <= cluster_size <= MAX_CLUSTER_SIZE):
        raise BeastError(
            f"invalid exFAT cluster size {cluster_size}: use a power of two from "
            f"{sector_size} bytes to 32 MiB")
    volume_sectors = size // sector_size
    volume_bytes = volume_sectors * sector_size
    if volume_bytes < MIN_VOLUME_SIZE:
        raise BeastError(f"exFAT volume too small: {size} bytes (minimum 1 MiB)")
    align = BOUNDARY_ALIGN if volume_bytes >= SMALL_VOLUME else cluster_size

    fat_offset = _round_up(24 * sector_size, align)  # the two boot regions use sectors 0..23
    max_clusters = (volume_bytes - fat_offset - 8 - 1) // (cluster_size + 4) + 1
    fat_bytes = _round_up((max_clusters + 2) * 4, sector_size)
    heap_offset = _round_up(fat_offset + fat_bytes, align)
    cluster_count = (volume_bytes - heap_offset) // cluster_size if volume_bytes > heap_offset else 0
    if cluster_count > MAX_CLUSTER_COUNT:
        raise BeastError(
            f"exFAT cluster size {cluster_size} is too small for {size} bytes "
            f"({cluster_count} clusters, maximum {MAX_CLUSTER_COUNT})")

    bitmap_bytes = _ceil_div(cluster_count, 8)
    bitmap_clusters = _ceil_div(bitmap_bytes, cluster_size)
    upcase_clusters = _ceil_div(len(UPCASE_TABLE), cluster_size)
    if cluster_count < bitmap_clusters + upcase_clusters + 2:  # metadata + one free cluster
        raise BeastError(f"exFAT volume too small for cluster size {cluster_size}: {size} bytes")

    boot = BootSector(
        partition_offset=partition_offset,
        volume_length=volume_sectors,
        fat_offset=fat_offset // sector_size,
        fat_length=fat_bytes // sector_size,
        cluster_heap_offset=heap_offset // sector_size,
        cluster_count=cluster_count,
        root_cluster=FIRST_CLUSTER + bitmap_clusters + upcase_clusters,
        volume_serial=volume_serial,
        bytes_per_sector_shift=sector_size.bit_length() - 1,
        sectors_per_cluster_shift=(cluster_size // sector_size).bit_length() - 1,
    )
    layout = Layout(boot, FIRST_CLUSTER, bitmap_bytes, bitmap_clusters,
                    FIRST_CLUSTER + bitmap_clusters, upcase_clusters)
    boot.percent_in_use = layout.used_clusters * 100 // cluster_count
    return layout


def build_boot_region(boot: BootSector) -> bytes:
    """The 12 sectors of a Main (or Backup) Boot Region (§3)."""
    ss = boot.sector_size
    region = bytearray(BOOT_REGION_SECTORS * ss)
    region[0:ss] = boot.pack()
    for sector in range(1, 9):  # Extended Boot Sectors: only the signature
        region[(sector + 1) * ss - 4:(sector + 1) * ss] = EXTENDED_BOOT_SIGNATURE
    # sector 9 (OEM Parameters) and sector 10 (reserved) stay zero
    checksum = struct.pack("<I", boot_checksum(region[:11 * ss]))
    region[11 * ss:12 * ss] = checksum * (ss // 4)
    return bytes(region)


def check_label(label: str) -> None:
    """Raise BeastError unless `label` can be an exFAT volume label.

    At most 11 UTF-16 code units (§7.3.2; a character outside the BMP, such as
    an emoji, takes two), none of them a control character or " * / : < > ? \\ |.
    format_exfat checks the same; this lets a caller refuse a bad label before
    anything is written to the disk.
    """
    _encode_label(label)


def _encode_label(label: str) -> bytes:
    if not isinstance(label, str):
        raise BeastError(f"exFAT volume label must be a string, not {type(label).__name__}")
    if any(ch in INVALID_NAME_CHARS for ch in label):
        raise BeastError(f"invalid exFAT volume label {label!r}: control characters and "
                         '" * / : < > ? \\ | are not allowed')
    try:
        data = label.encode("utf-16-le")
    except UnicodeEncodeError:  # a lone surrogate, e.g. from undecodable bytes
        raise BeastError(f"exFAT volume label {label!r} is not valid Unicode") from None
    if len(data) // 2 > LABEL_MAX_CHARS:
        raise BeastError(f"exFAT volume label {label!r} is too long (max {LABEL_MAX_CHARS} characters)")
    return data


def _require_int(what: str, value: object) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BeastError(f"exFAT {what} must be an integer, not {value!r}")


def _fat_chain(first: int, count: int) -> bytes:
    """FAT entries for `count` consecutive clusters starting at `first`, ending in EOF."""
    nexts = list(range(first + 1, first + count)) + [FAT_EOF]
    return struct.pack(f"<{count}I", *nexts)


def _write_zeros(t: BlockTarget, offset: int, length: int) -> None:
    chunk = bytes(min(length, ZERO_CHUNK))
    while length > 0:
        n = min(length, len(chunk))
        t.write(offset, chunk if n == len(chunk) else chunk[:n])
        offset += n
        length -= n


# ---------------------------------------------------------------------------
# format_exfat
# ---------------------------------------------------------------------------


def format_exfat(t: BlockTarget, offset: int, size: int, *, label: str,
                 volume_serial: int, cluster_size: int | None = None) -> None:
    """Quick-format an exFAT volume in the bytes [offset, offset + size) of `t`.

    `offset` is where the partition starts on the disk (recorded as
    PartitionOffset); `volume_serial` is the 32-bit serial number that blkid
    and GRUB show as the UUID ("ABCD-1234"); `label` has at most 11 characters.
    """
    for what, value in (("volume offset", offset), ("volume size", size), ("volume serial", volume_serial)):
        _require_int(what, value)
    if cluster_size is not None:
        _require_int("cluster size", cluster_size)
    ss = t.sector_size
    if offset < 0 or offset % ss:
        raise BeastError(f"exFAT volume offset {offset} is not a multiple of the sector size {ss}")
    if size <= 0 or offset + size > t.size:
        raise BeastError(f"exFAT volume [{offset}, {offset + size}) does not fit in the target ({t.size} bytes)")
    if not 0 <= volume_serial <= 0xFFFFFFFF:
        raise BeastError(f"exFAT volume serial {volume_serial} does not fit in 32 bits")
    label_utf16 = _encode_label(label)
    layout = plan_layout(size, ss, cluster_size=cluster_size,
                         partition_offset=offset // ss, volume_serial=volume_serial)
    boot = layout.boot
    cs = boot.cluster_size
    region = build_boot_region(boot)

    def cluster_offset(cluster: int) -> int:
        return offset + boot.cluster_heap_offset * ss + (cluster - FIRST_CLUSTER) * cs

    # 1. Everything in front of the cluster heap: zero. This also clears the
    #    whole FAT (every cluster free) and any old boot sector or superblock.
    _write_zeros(t, offset, boot.cluster_heap_offset * ss)

    # 2. Backup boot region, then the main one except its first sector, which
    #    is written last: until the end the volume is not recognised as exFAT.
    t.write(offset + BOOT_REGION_SECTORS * ss, region)
    t.write(offset + ss, region[ss:])

    # 3. FAT: the two reserved entries and the chains of bitmap, up-case table, root.
    fat = (struct.pack("<II", FAT_MEDIA, FAT_EOF)
           + _fat_chain(layout.bitmap_cluster, layout.bitmap_clusters)
           + _fat_chain(layout.upcase_cluster, layout.upcase_clusters)
           + _fat_chain(layout.root_cluster, 1))
    t.write(offset + boot.fat_offset * ss, fat)

    # 4. Allocation bitmap: the metadata clusters are the first clusters of the heap.
    used = layout.used_clusters
    head = b"\xff" * (used // 8) + (bytes([(1 << (used % 8)) - 1]) if used % 8 else b"")
    t.write(cluster_offset(layout.bitmap_cluster), head)
    _write_zeros(t, cluster_offset(layout.bitmap_cluster) + len(head), layout.bitmap_clusters * cs - len(head))

    # 5. Up-case table, padded to whole clusters.
    t.write(cluster_offset(layout.upcase_cluster), UPCASE_TABLE.ljust(layout.upcase_clusters * cs, b"\0"))

    # 6. Root directory: one cluster.
    root = bytearray(cs)
    struct.pack_into("<BB22s", root, 0, ENTRY_LABEL, len(label_utf16) // 2, label_utf16)
    root[ENTRY_SIZE] = ENTRY_GUID_SLOT
    struct.pack_into("<BB18xIQ", root, 2 * ENTRY_SIZE, ENTRY_BITMAP, 0,
                     layout.bitmap_cluster, layout.bitmap_bytes)
    struct.pack_into("<B3xI12xIQ", root, 3 * ENTRY_SIZE, ENTRY_UPCASE,
                     UPCASE_TABLE_CHECKSUM, layout.upcase_cluster, len(UPCASE_TABLE))
    t.write(cluster_offset(layout.root_cluster), bytes(root))
    t.flush()

    t.write(offset, region[:ss])
    t.flush()


# ---------------------------------------------------------------------------
# ExfatVolume
# ---------------------------------------------------------------------------


@dataclass
class _Node:
    """A file or directory: its directory entry set and where that set lives."""

    name: str
    attributes: int
    flags: int  # GeneralSecondaryFlags of the Stream Extension
    first_cluster: int
    data_length: int
    valid_data_length: int
    parent: _Dir
    index: int  # entry index of the File entry inside the parent directory
    raw: bytearray  # the entry set as stored (File + Stream Extension + File Name entries ...)

    @property
    def is_dir(self) -> bool:
        return bool(self.attributes & ATTR_DIRECTORY)

    @property
    def no_fat_chain(self) -> bool:
        return bool(self.flags & STREAM_NO_FAT_CHAIN)

    @property
    def entry_count(self) -> int:
        return len(self.raw) // ENTRY_SIZE


@dataclass
class _Dir:
    """A directory: the root (node is None, always FAT-chained) or a sub-directory."""

    node: _Node | None = None


class _Bitmap:
    """The Allocation Bitmap, held in memory (1 bit per cluster: 1 MiB per 8M clusters)."""

    def __init__(self, data: bytes, cluster_count: int) -> None:
        self.bits = bytearray(data)
        self.cluster_count = cluster_count
        self.dirty_lo: int | None = None
        self.dirty_hi = 0

    def is_used(self, cluster: int) -> bool:
        i = cluster - FIRST_CLUSTER
        return bool(self.bits[i >> 3] >> (i & 7) & 1)

    def mark(self, clusters: list[int], used: bool) -> None:
        for cluster in clusters:
            i = cluster - FIRST_CLUSTER
            if used:
                self.bits[i >> 3] |= 1 << (i & 7)
            else:
                self.bits[i >> 3] &= ~(1 << (i & 7)) & 0xFF
            byte = i >> 3
            self.dirty_lo = byte if self.dirty_lo is None else min(self.dirty_lo, byte)
            self.dirty_hi = max(self.dirty_hi, byte + 1)

    def used_count(self) -> int:
        count = int.from_bytes(self.bits, "little").bit_count()
        tail = self.cluster_count % 8
        if tail:  # bits past the last cluster (padding in the last byte) do not count
            count -= (self.bits[-1] >> tail).bit_count()
        return count

    def free_count(self) -> int:
        return self.cluster_count - self.used_count()

    def find_run(self, count: int, start: int = FIRST_CLUSTER) -> int | None:
        """First cluster of the first run of `count` free clusters at or after `start`."""
        bits, end = self.bits, self.cluster_count
        i = start - FIRST_CLUSTER
        run_start, run_len = i, 0
        while i < end:
            byte = bits[i >> 3]
            if i & 7 == 0 and i + 8 <= end and byte in (0x00, 0xFF):
                if byte == 0xFF:  # 8 used clusters
                    run_len = 0
                else:  # 8 free clusters
                    if run_len == 0:
                        run_start = i
                    run_len += 8
                i += 8
            else:
                if byte >> (i & 7) & 1:
                    run_len = 0
                else:
                    if run_len == 0:
                        run_start = i
                    run_len += 1
                i += 1
            if run_len >= count:
                return run_start + FIRST_CLUSTER
        return None

    def find_free(self, count: int) -> list[int] | None:
        """The first `count` free clusters, wherever they are."""
        found: list[int] = []
        cluster = FIRST_CLUSTER
        while len(found) < count:
            cluster = self.find_run(1, cluster)
            if cluster is None:
                return None
            found.append(cluster)
            cluster += 1
        return found


class ExfatVolume:
    """An existing exFAT volume inside a BlockTarget, starting at byte `offset`.

    Paths use "/" and are looked up case-insensitively (with the volume's
    up-case table). Writing sets VolumeDirty while it works and clears it
    when everything is flushed, as the Linux and Windows drivers do.
    """

    def __init__(self, t: BlockTarget, offset: int, *, clock: Callable[[], float] = time.time) -> None:
        self._t = t
        self._base = offset
        self._clock = clock
        self._fat_cache: dict[int, bytes] = {}
        self._changed = False  # set by _write_abs
        self.boot, self._boot_index = self._read_boot_region()
        boot = self.boot
        self.sector_size = boot.sector_size
        self.cluster_size = boot.cluster_size
        self.cluster_count = boot.cluster_count
        self.volume_serial = boot.volume_serial
        self.dirty = bool(boot.volume_flags & VOLUME_FLAG_DIRTY)
        self._active_fat = boot.volume_flags & VOLUME_FLAG_ACTIVE_FAT if boot.number_of_fats == 2 else 0
        self._fat_start = offset + (boot.fat_offset + self._active_fat * boot.fat_length) * self.sector_size
        self._heap_start = offset + boot.cluster_heap_offset * self.sector_size
        self.root = _Dir()
        self._load_root_metadata()

    # -- opening -------------------------------------------------------------

    def _read_boot_region(self) -> tuple[BootSector, int]:
        """The main boot region if it is valid, else the backup one (§3.1, §3.4)."""
        errors = []
        for index, name in ((0, "main"), (1, "backup")):
            problem = "no exFAT boot sector"
            for ss in SECTOR_SIZES:  # where the region is depends on the sector size
                start = index * BOOT_REGION_SECTORS * ss
                try:
                    if self._read(start, 512)[108] != ss.bit_length() - 1:
                        continue
                    region = self._read(start, BOOT_REGION_SECTORS * ss)
                    boot = BootSector.parse(region[:ss])
                    expected = struct.pack("<I", boot_checksum(region[:11 * ss])) * (ss // 4)
                    if region[11 * ss:] != expected:
                        raise BeastError("boot checksum mismatch")
                    return boot, index
                except BeastError as e:
                    problem = str(e)
            errors.append(f"{name} boot region: {problem}")
        raise BeastError(f"no valid exFAT volume at offset {self._base}: " + "; ".join(errors))

    def _load_root_metadata(self) -> None:
        bitmap = upcase = None
        label = ""
        _, data = self._read_dir(self.root)
        for index in range(len(data) // ENTRY_SIZE):
            entry = data[index * ENTRY_SIZE:(index + 1) * ENTRY_SIZE]
            if entry[0] == ENTRY_END:
                break
            if entry[0] == ENTRY_BITMAP and entry[1] & 1 == self._active_fat:
                bitmap = struct.unpack_from("<IQ", entry, 20)
            elif entry[0] == ENTRY_UPCASE:
                upcase = struct.unpack_from("<I12xIQ", entry, 4)
            elif entry[0] == ENTRY_LABEL:
                count = min(entry[1], LABEL_MAX_CHARS)
                label = entry[2:2 + 2 * count].decode("utf-16-le", "surrogatepass")
        if bitmap is None or upcase is None:
            raise BeastError("exFAT root directory has no Allocation Bitmap or Up-case Table entry")
        self.label = label

        first, length = bitmap
        if length < _ceil_div(self.cluster_count, 8):
            raise BeastError("exFAT Allocation Bitmap is smaller than the cluster count")
        self._bitmap_clusters = self._chain(first, _ceil_div(length, self.cluster_size))
        data = self._read_clusters(self._bitmap_clusters, _ceil_div(self.cluster_count, 8))
        self._bitmap = _Bitmap(data, self.cluster_count)

        checksum, first, length = upcase
        if not 0 < length <= 2 * 0x10000 + 4:
            raise BeastError(f"exFAT Up-case Table has an invalid size ({length} bytes)")
        table = self._read_clusters(self._chain(first, _ceil_div(length, self.cluster_size)), length)
        if upcase_table_checksum(table) != checksum:
            raise BeastError("exFAT Up-case Table checksum mismatch (run a filesystem check)")
        self._upcase = decompress_upcase_table(table)

    # -- low-level I/O ---------------------------------------------------------

    def _read(self, offset: int, length: int) -> bytes:
        """Read relative to the volume start."""
        return self._read_abs(self._base + offset, length)

    def _read_abs(self, offset: int, length: int) -> bytes:
        data = self._t.read(offset, length)
        if len(data) != length:
            raise BeastError(f"short read at byte {offset} of the exFAT volume's disk")
        return data

    def _write_abs(self, offset: int, data: bytes) -> None:
        """Every change to the volume goes through here (see _modifying)."""
        self._changed = True
        self._t.write(offset, data)

    def _cluster_offset(self, cluster: int) -> int:
        return self._heap_start + (cluster - FIRST_CLUSTER) * self.cluster_size

    def _check_cluster(self, cluster: int) -> None:
        if not FIRST_CLUSTER <= cluster <= self.cluster_count + 1:
            raise BeastError(f"exFAT: cluster {cluster:#x} is outside the cluster heap (run a filesystem check)")

    def _fat_get(self, cluster: int) -> int:
        position = cluster * 4
        chunk = position // FAT_CACHE_CHUNK
        if chunk not in self._fat_cache:
            start = chunk * FAT_CACHE_CHUNK
            length = min(FAT_CACHE_CHUNK, (self.cluster_count + 2) * 4 - start)
            self._fat_cache[chunk] = self._read_abs(self._fat_start + start, length)
        return struct.unpack_from("<I", self._fat_cache[chunk], position % FAT_CACHE_CHUNK)[0]

    def _fat_set_chain(self, clusters: list[int]) -> None:
        """Link `clusters` in the FAT in this order, the last one marked end-of-chain."""
        nexts = clusters[1:] + [FAT_EOF]
        self._fat_write(list(zip(clusters, nexts)))

    def _fat_write(self, pairs: list[tuple[int, int]]) -> None:
        """Set FAT entries ((cluster, value) pairs); consecutive clusters share one write."""
        self._fat_cache.clear()
        pairs = sorted(pairs)
        i = 0
        while i < len(pairs):
            j = i + 1
            while j < len(pairs) and pairs[j][0] == pairs[j - 1][0] + 1:
                j += 1
            values = [value for _, value in pairs[i:j]]
            self._write_abs(self._fat_start + pairs[i][0] * 4, struct.pack(f"<{len(values)}I", *values))
            i = j

    def _chain(self, first: int, limit: int | None = None) -> list[int]:
        """Clusters of a FAT chain (at most `limit` of them)."""
        clusters = []
        cluster = first
        while True:
            self._check_cluster(cluster)
            clusters.append(cluster)
            if limit is not None and len(clusters) >= limit:
                return clusters
            if len(clusters) > self.cluster_count:
                raise BeastError("exFAT: cluster chain loops (run a filesystem check)")
            cluster = self._fat_get(cluster)
            if cluster == FAT_EOF:
                if limit is not None:
                    raise BeastError("exFAT: cluster chain is shorter than the data (run a filesystem check)")
                return clusters

    def _data_clusters(self, first: int, no_fat_chain: bool, length: int) -> list[int]:
        count = _ceil_div(length, self.cluster_size)
        if count == 0:
            return []
        if no_fat_chain:
            self._check_cluster(first)
            self._check_cluster(first + count - 1)
            return list(range(first, first + count))
        return self._chain(first, count)

    @staticmethod
    def _runs(clusters: list[int]) -> Iterator[tuple[int, int]]:
        """(first cluster, count) of each run of consecutive clusters."""
        i = 0
        while i < len(clusters):
            j = i + 1
            while j < len(clusters) and clusters[j] == clusters[j - 1] + 1:
                j += 1
            yield clusters[i], j - i
            i = j

    def _read_clusters(self, clusters: list[int], length: int) -> bytes:
        parts = []
        left = length
        for first, count in self._runs(clusters):
            n = min(left, count * self.cluster_size)
            if n <= 0:
                break
            parts.append(self._read_abs(self._cluster_offset(first), n))
            left -= n
        data = b"".join(parts)
        if len(data) < length:
            raise BeastError("exFAT: data is longer than its clusters (run a filesystem check)")
        return data

    def _write_clusters(self, clusters: list[int], data: bytes) -> None:
        """Write `data` over `clusters`, zero-padding the last cluster."""
        position = 0
        for first, count in self._runs(clusters):
            n = count * self.cluster_size
            chunk = data[position:position + n]
            self._write_abs(self._cluster_offset(first), chunk + bytes(n - len(chunk)))
            position += n

    # -- directories -------------------------------------------------------------

    def _dir_clusters(self, d: _Dir) -> list[int]:
        if d.node is None:
            return self._chain(self.boot.root_cluster)
        return self._data_clusters(d.node.first_cluster, d.node.no_fat_chain, d.node.data_length)

    def _read_dir(self, d: _Dir) -> tuple[list[int], bytes]:
        clusters = self._dir_clusters(d)
        return clusters, self._read_clusters(clusters, len(clusters) * self.cluster_size)

    def _entries(self, d: _Dir) -> list[_Node]:
        """The files and directories in `d`, in on-disk order."""
        _, data = self._read_dir(d)
        nodes = []
        total = len(data) // ENTRY_SIZE
        index = 0
        while index < total:
            etype = data[index * ENTRY_SIZE]
            if etype == ENTRY_END:
                break
            if not etype & ENTRY_IN_USE or etype & ENTRY_SECONDARY or etype in (ENTRY_BITMAP, ENTRY_UPCASE, ENTRY_LABEL):
                index += 1  # unused, stray secondary, or a one-entry critical primary
                continue
            secondary_count = data[index * ENTRY_SIZE + 1]
            if etype == ENTRY_FILE:
                raw = bytearray(data[index * ENTRY_SIZE:(index + 1 + secondary_count) * ENTRY_SIZE])
                nodes.append(self._parse_entry_set(raw, d, index))
            index += 1 + secondary_count  # also skips benign primaries (Volume GUID, ...)
        return nodes

    def _parse_entry_set(self, raw: bytearray, d: _Dir, index: int) -> _Node:
        where = f"exFAT directory entry set at index {index}"
        count = len(raw) // ENTRY_SIZE
        if count < 3 or count != raw[1] + 1:
            raise BeastError(f"{where} is truncated (run a filesystem check)")
        if struct.unpack_from("<H", raw, 2)[0] != entry_set_checksum(raw):
            raise BeastError(f"{where}: SetChecksum mismatch (run a filesystem check)")
        if raw[ENTRY_SIZE] != ENTRY_STREAM:
            raise BeastError(f"{where} has no Stream Extension entry")
        attributes = struct.unpack_from("<H", raw, 4)[0]
        flags, name_length, _hash, valid_length, first, length = struct.unpack_from("<BxBH2xQ4xIQ", raw, ENTRY_SIZE + 1)
        name_entries = _ceil_div(name_length, NAME_CHARS_PER_ENTRY)
        if name_length == 0 or 2 + name_entries > count:
            raise BeastError(f"{where} has an invalid name length")
        name_bytes = b""
        for i in range(2, 2 + name_entries):
            if raw[i * ENTRY_SIZE] != ENTRY_NAME:
                raise BeastError(f"{where}: missing File Name entry")
            name_bytes += raw[i * ENTRY_SIZE + 2:(i + 1) * ENTRY_SIZE]
        name = name_bytes[:2 * name_length].decode("utf-16-le", "surrogatepass")
        if valid_length > length:
            raise BeastError(f"{where}: ValidDataLength is larger than DataLength")
        return _Node(name, attributes, flags, first, length, valid_length, d, index, raw)

    def _upcase_units(self, name: str) -> bytes:
        units = array("H", name.encode("utf-16-le", "surrogatepass"))
        if struct.pack("=H", 1) != struct.pack("<H", 1):
            units.byteswap()
        return _le16_bytes(array("H", (self._upcase[u] for u in units)))

    def _find(self, d: _Dir, name: str) -> _Node | None:
        wanted = self._upcase_units(name)
        for node in self._entries(d):
            if self._upcase_units(node.name) == wanted:
                return node
        return None

    @staticmethod
    def _split(path: str) -> list[str]:
        if not isinstance(path, str):
            raise BeastError(f"exFAT path must be a string, not {type(path).__name__}")
        return [part for part in path.replace("\\", "/").split("/") if part not in ("", ".")]

    def _walk(self, parts: list[str], path: str) -> _Dir:
        """The directory reached by following `parts` from the root."""
        d = self.root
        for i, part in enumerate(parts):
            node = self._find(d, part)
            if node is None:
                raise BeastError(f"{'/' + '/'.join(parts[:i + 1])}: no such directory on the exFAT volume")
            if not node.is_dir:
                raise BeastError(f"{'/' + '/'.join(parts[:i + 1])}: not a directory (in {path})")
            d = _Dir(node)
        return d

    def _lookup(self, path: str) -> _Node:
        parts = self._split(path)
        if not parts:
            raise BeastError("the root directory has no directory entry")
        node = self._find(self._walk(parts[:-1], path), parts[-1])
        if node is None:
            raise BeastError(f"{path}: no such file or directory on the exFAT volume")
        return node

    # -- reading -------------------------------------------------------------

    def listdir(self, path: str = "/") -> list[DirEntry]:
        parts = self._split(path)
        if parts:
            node = self._lookup(path)
            if not node.is_dir:
                raise BeastError(f"{path}: not a directory")
            d = _Dir(node)
        else:
            d = self.root
        return [DirEntry(n.name, n.is_dir, 0 if n.is_dir else n.data_length) for n in self._entries(d)]

    def exists(self, path: str) -> bool:
        try:
            if self._split(path):
                self._lookup(path)
            return True
        except BeastError:
            return False

    def read_file(self, path: str) -> bytes:
        node = self._lookup(path)
        if node.is_dir:
            raise BeastError(f"{path}: is a directory")
        clusters = self._data_clusters(node.first_cluster, node.no_fat_chain, node.data_length)
        data = self._read_clusters(clusters, node.valid_data_length)
        # bytes between ValidDataLength and DataLength read as zero (§7.6.5)
        return data + bytes(node.data_length - node.valid_data_length)

    # -- writing -------------------------------------------------------------

    # Every change is checked in full before the first byte is written: the
    # names, the path, and that the free space covers every cluster it will
    # allocate (new directories, directory growth, file data). So a refused
    # change - most likely "not enough free space" - leaves the volume exactly
    # as it was. Only an I/O error can stop a change half-way; see _modifying.

    def write_file(self, path: str, data: bytes) -> None:
        """Create or replace a file (parent directories are created)."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise BeastError(f"write_file needs bytes, not {type(data).__name__}")
        if not isinstance(data, bytes):
            data = bytes(data)
        parts = self._split(path)
        if not parts:
            raise BeastError("write_file needs a file path")
        *dir_names, name = parts
        parent, new_dirs = self._existing_dirs(dir_names)
        for part in [*new_dirs, name]:
            _check_name(part)
        old = None if new_dirs else self._find(parent, name)
        if old is not None and old.is_dir:
            raise BeastError(f"{path}: is a directory")
        # a replaced file's entry set is rewritten in place when it has the same size
        in_place = old is not None and old.entry_count == _entry_count(name)
        data_clusters = _ceil_div(len(data), self.cluster_size)
        self._check_space(data_clusters + self._clusters_needed(parent, new_dirs, None if in_place else name))
        with self._modifying():
            parent = self._make_dirs(parent, new_dirs)
            clusters = self._allocate(data_clusters)
            self._write_clusters(clusters, data)
            no_fat_chain = self._link(clusters)
            # a replaced file keeps its creation time (timestamp, 10 ms increment, UTC offset)
            created = (struct.unpack_from("<I", old.raw, 8)[0], old.raw[20], old.raw[22]) if old else None
            raw = self._build_entry_set(name, ATTR_ARCHIVE, clusters, no_fat_chain, len(data), created)
            if in_place:
                self._write_entries(old.parent, old.index, raw)
            else:
                self._insert_entry_set(parent, raw)
                if old is not None:
                    self._delete_entry_set(old)
            if old is not None:  # only now, when nothing on disk refers to its clusters any more
                self._free(old)

    def mkdir(self, path: str) -> None:
        """Create a directory and its parents; existing directories are fine."""
        parent, new_dirs = self._existing_dirs(self._split(path))
        if not new_dirs:
            return
        for name in new_dirs:
            _check_name(name)
        self._check_space(self._clusters_needed(parent, new_dirs, None))
        with self._modifying():
            self._make_dirs(parent, new_dirs)

    def remove(self, path: str) -> None:
        """Remove a file or an empty directory."""
        node = self._lookup(path)
        if node.is_dir and self._entries(_Dir(node)):
            raise BeastError(f"{path}: directory is not empty")
        with self._modifying():
            self._delete_entry_set(node)
            self._free(node)

    def _existing_dirs(self, parts: list[str]) -> tuple[_Dir, list[str]]:
        """Follow `parts` from the root while they exist: (deepest directory, names still missing)."""
        d = self.root
        for i, part in enumerate(parts):
            node = self._find(d, part)
            if node is None:
                return d, parts[i:]
            if not node.is_dir:
                raise BeastError(f"/{'/'.join(parts[:i + 1])}: exists and is not a directory")
            d = _Dir(node)
        return d, []

    def _clusters_needed(self, d: _Dir, new_dirs: list[str], file_name: str | None) -> int:
        """Clusters that creating the nested directories `new_dirs` in `d` takes,
        and then a File entry set for `file_name` in the innermost one (not its data).

        Mirrors what _make_dirs and _insert_entry_set will do: one cluster per new
        directory, plus the clusters each directory must grow by to hold its new
        entry set. The first set goes into `d` as it is now; each later one into
        a directory just created, which is one empty cluster.
        """
        needed = len(new_dirs)
        names = new_dirs if file_name is None else [*new_dirs, file_name]
        for i, name in enumerate(names):
            entries = _entry_count(name)
            if i == 0:
                needed += self._free_slots(d, entries)[1]
            else:
                needed += _ceil_div(max(0, entries * ENTRY_SIZE - self.cluster_size), self.cluster_size)
        return needed

    def _check_space(self, clusters: int) -> None:
        free = self._bitmap.free_count()
        if clusters > free:
            raise BeastError(f"not enough free space on the exFAT volume "
                             f"({clusters} clusters needed, {free} free)")

    @contextmanager
    def _modifying(self) -> Iterator[None]:
        """Mark the volume dirty while changing it; flush; then mark it clean again.

        Callers check the change before calling this, so a refused change writes
        nothing. If it fails anyway after something was written (an I/O error):

          * the in-memory Allocation Bitmap, which holds every cluster this change
            allocated, is written out, so no directory entry or FAT chain on disk
            can point at a cluster marked free, which would get it handed out
            twice. At worst some clusters stay allocated but unused until a
            filesystem check gives them back.
          * the volume stays marked dirty, also through later writes on this
            object, so the next OS that mounts it knows it needs a check.

        If nothing was written yet, the volume is marked clean again. A volume
        that was already dirty when opened stays dirty.
        """
        if self.boot.number_of_fats != 1:
            raise BeastError("writing to an exFAT volume with two FATs (TexFAT) is not supported")
        if self._boot_index != 0:
            raise BeastError("the exFAT main boot region is damaged (run a filesystem check); not writing")
        bitmap_before = bytes(self._bitmap.bits)
        self._set_volume_flags(dirty=True)
        self._t.flush()
        self._changed = False
        try:
            yield
        except BaseException:
            self._fat_cache.clear()  # may hold entries that were not written
            if not self._changed:
                self._bitmap = _Bitmap(bitmap_before, self.cluster_count)
                self._set_volume_flags(dirty=self.dirty)
                self._t.flush()
            else:
                self.dirty = True
                try:
                    self._flush_bitmap()
                    self._t.flush()
                except (OSError, BeastError):
                    pass  # the error being raised matters more; VolumeDirty is already set on disk
            raise
        self._flush_bitmap()
        self._t.flush()
        self._set_volume_flags(dirty=self.dirty)
        self._t.flush()

    def _set_volume_flags(self, *, dirty: bool) -> None:
        """Update VolumeFlags and PercentInUse in the main boot sector (not in the checksum)."""
        sector = bytearray(self._read(0, self.sector_size))
        flags = struct.unpack_from("<H", sector, _VOLUME_FLAGS_OFFSET)[0]
        flags = flags | VOLUME_FLAG_DIRTY if dirty else flags & ~VOLUME_FLAG_DIRTY
        struct.pack_into("<H", sector, _VOLUME_FLAGS_OFFSET, flags)
        sector[_PERCENT_IN_USE_OFFSET] = min(100, self._bitmap.used_count() * 100 // self.cluster_count)
        self._t.write(self._base, bytes(sector))

    def _flush_bitmap(self) -> None:
        bm = self._bitmap
        if bm.dirty_lo is None:
            return
        cs = self.cluster_size
        position, end = bm.dirty_lo, bm.dirty_hi
        while position < end:  # the bitmap may span several (chained) clusters
            cluster = self._bitmap_clusters[position // cs]
            n = min(end - position, cs - position % cs)
            self._write_abs(self._cluster_offset(cluster) + position % cs, bytes(bm.bits[position:position + n]))
            position += n
        bm.dirty_lo, bm.dirty_hi = None, 0

    def _allocate(self, count: int, near: int | None = None) -> list[int]:
        """Reserve `count` free clusters: one contiguous run when possible."""
        if count == 0:
            return []
        start = None
        if near is not None and FIRST_CLUSTER <= near <= self.cluster_count + 1 - count + 1:
            if all(not self._bitmap.is_used(c) for c in range(near, near + count)):
                start = near
        if start is None:
            start = self._bitmap.find_run(count)
        clusters = list(range(start, start + count)) if start is not None else self._bitmap.find_free(count)
        if clusters is None:
            raise BeastError(f"not enough free space on the exFAT volume ({count} clusters needed)")
        self._bitmap.mark(clusters, True)
        return clusters

    def _link(self, clusters: list[int]) -> bool:
        """Write the FAT chain if the clusters are not contiguous; True = NoFatChain."""
        if clusters and not _contiguous(clusters):
            self._fat_set_chain(clusters)
            return False
        return bool(clusters)

    def _free(self, node: _Node) -> None:
        clusters = self._data_clusters(node.first_cluster, node.no_fat_chain, node.data_length)
        if not node.no_fat_chain and clusters:
            self._fat_write([(c, FAT_FREE) for c in clusters])
        self._bitmap.mark(clusters, False)

    def _make_dirs(self, d: _Dir, names: list[str]) -> _Dir:
        """Create the nested directories `names` inside `d`; returns the innermost one."""
        for name in names:
            clusters = self._allocate(1)
            self._write_clusters(clusters, b"")  # zeroed before anything points to it
            raw = self._build_entry_set(name, ATTR_DIRECTORY, clusters, True, self.cluster_size)
            d = _Dir(self._insert_entry_set(d, raw))
        return d

    def _build_entry_set(self, name: str, attributes: int, clusters: list[int], no_fat_chain: bool,
                         length: int, created: tuple[int, int, int] | None = None) -> bytearray:
        """File + Stream Extension + File Name entries for a new file or directory."""
        name_utf16 = name.encode("utf-16-le", "surrogatepass")
        name_length = len(name_utf16) // 2
        name_entries = _ceil_div(name_length, NAME_CHARS_PER_ENTRY)
        raw = bytearray(ENTRY_SIZE * (2 + name_entries))
        timestamp, centiseconds = _timestamp(self._clock())
        if created is None:
            created = (timestamp, centiseconds, UTC_OFFSET_VALID)
        # File entry (§7.4): timestamps are UTC, so every UtcOffset is "valid, +0".
        struct.pack_into("<BBHH2xIIIBBBBB", raw, 0, ENTRY_FILE, 1 + name_entries, 0, attributes,
                         created[0], timestamp, timestamp, created[1], centiseconds,
                         created[2], UTC_OFFSET_VALID, UTC_OFFSET_VALID)
        # Stream Extension (§7.6): an empty file has no clusters and must not claim NoFatChain.
        flags = STREAM_ALLOCATION_POSSIBLE | (STREAM_NO_FAT_CHAIN if clusters and no_fat_chain else 0)
        struct.pack_into("<BBxBH2xQ4xIQ", raw, ENTRY_SIZE, ENTRY_STREAM, flags, name_length,
                         name_hash(self._upcase_units(name)), length,
                         clusters[0] if clusters else 0, length)
        for i in range(name_entries):  # File Name entries (§7.7), 15 characters each
            chunk = name_utf16[i * 2 * NAME_CHARS_PER_ENTRY:(i + 1) * 2 * NAME_CHARS_PER_ENTRY]
            struct.pack_into("<Bx30s", raw, (2 + i) * ENTRY_SIZE, ENTRY_NAME, chunk)
        struct.pack_into("<H", raw, 2, entry_set_checksum(raw))
        return raw

    def _write_entries(self, d: _Dir, index: int, raw: bytes, clusters: list[int] | None = None) -> None:
        """Write directory entries starting at entry `index` of `d` (they may cross clusters)."""
        if clusters is None:
            clusters = self._dir_clusters(d)
        cs = self.cluster_size
        position = index * ENTRY_SIZE
        done = 0
        while done < len(raw):
            n = min(len(raw) - done, cs - position % cs)
            self._write_abs(self._cluster_offset(clusters[position // cs]) + position % cs,
                            bytes(raw[done:done + n]))
            done += n
            position += n

    def _insert_entry_set(self, d: _Dir, raw: bytearray) -> _Node:
        """Store a new entry set in the first free slots of `d`, growing it if needed."""
        start, grow, clusters = self._free_slots(d, len(raw) // ENTRY_SIZE)
        if grow:
            clusters = self._grow_dir(d, clusters, grow)
        self._write_entries(d, start, raw, clusters)
        return self._parse_entry_set(raw, d, start)

    def _free_slots(self, d: _Dir, need: int) -> tuple[int, int, list[int]]:
        """Where `need` consecutive free entries of `d` start, the number of
        clusters `d` must grow by to have them, and `d`'s clusters."""
        clusters, data = self._read_dir(d)
        total = len(data) // ENTRY_SIZE
        start, run = 0, 0
        for index in range(total):
            etype = data[index * ENTRY_SIZE]
            if etype == ENTRY_END:  # this and everything after it is free
                if run == 0:
                    start = index
                run += total - index
                break
            if etype & ENTRY_IN_USE:
                run = 0
            else:
                if run == 0:
                    start = index
                run += 1
                if run >= need:
                    break
        if run >= need:
            return start, 0, clusters
        # Not enough room: the loop ended with `run` free entries that reach the
        # end of `d` (maybe none), so the new clusters go right behind them.
        if run == 0:
            start = total
        return start, _ceil_div((need - run) * ENTRY_SIZE, self.cluster_size), clusters

    def _grow_dir(self, d: _Dir, clusters: list[int], count: int) -> list[int]:
        """Append `count` zeroed clusters to directory `d`; returns its new cluster list."""
        new = self._allocate(count, near=clusters[-1] + 1)
        self._write_clusters(new, b"")
        all_clusters = clusters + new
        node = d.node
        if node is None or not node.no_fat_chain:
            self._fat_set_chain([clusters[-1]] + new)  # append to the FAT chain
        elif not _contiguous(all_clusters):
            self._fat_set_chain(all_clusters)  # was contiguous, now needs a FAT chain
        if node is not None:
            flags = node.flags if _contiguous(all_clusters) else node.flags & ~STREAM_NO_FAT_CHAIN
            length = len(all_clusters) * self.cluster_size
            struct.pack_into("<B", node.raw, ENTRY_SIZE + 1, flags)
            struct.pack_into("<Q", node.raw, ENTRY_SIZE + 8, length)  # ValidDataLength
            struct.pack_into("<Q", node.raw, ENTRY_SIZE + 24, length)  # DataLength
            struct.pack_into("<H", node.raw, 2, entry_set_checksum(node.raw))
            self._write_entries(node.parent, node.index, node.raw)
            node.flags, node.data_length, node.valid_data_length = flags, length, length
        return all_clusters

    def _delete_entry_set(self, node: _Node) -> None:
        raw = bytearray(node.raw)
        for i in range(0, len(raw), ENTRY_SIZE):
            raw[i] &= ~ENTRY_IN_USE & 0xFF
        self._write_entries(node.parent, node.index, raw)


def _contiguous(clusters: list[int]) -> bool:
    return all(b == a + 1 for a, b in zip(clusters, clusters[1:]))


def _entry_count(name: str) -> int:
    """Directory entries of a File entry set: File + Stream Extension + File Name entries."""
    return 2 + _ceil_div(len(name.encode("utf-16-le", "surrogatepass")) // 2, NAME_CHARS_PER_ENTRY)


def _check_name(name: str) -> None:
    """Names we create must be valid exFAT names that Windows and macOS also accept."""
    if name in (".", ".."):
        raise BeastError(f"invalid file name {name!r}")
    try:
        name.encode("utf-16-le")
    except UnicodeEncodeError:  # a lone surrogate, e.g. from undecodable bytes
        raise BeastError(f"file name {name!r} is not valid Unicode") from None
    bad = sorted({ch for ch in name if ch in INVALID_NAME_CHARS})
    if bad:
        raise BeastError(f"invalid character(s) {''.join(bad)!r} in file name {name!r}")
    if name.endswith((" ", ".")):
        raise BeastError(f"file name {name!r} must not end with a space or a dot (Windows cannot open it)")
    if len(name.encode("utf-16-le", "surrogatepass")) // 2 > NAME_MAX_CHARS:
        raise BeastError(f"file name {name[:20]!r}... is too long (max {NAME_MAX_CHARS} characters)")


def _timestamp(epoch: float) -> tuple[int, int]:
    """exFAT timestamp (§7.4.8) and 10 ms increment (§7.4.9) for a UTC time."""
    tm = time.gmtime(epoch)
    if tm.tm_year < 1980:
        return (0 << 25) | (1 << 21) | (1 << 16), 0  # 1980-01-01 00:00:00
    if tm.tm_year > 2107:
        return (127 << 25) | (12 << 21) | (31 << 16) | (23 << 11) | (59 << 5) | 29, 199
    second = min(tm.tm_sec, 59)
    stamp = ((tm.tm_year - 1980) << 25 | tm.tm_mon << 21 | tm.tm_mday << 16
             | tm.tm_hour << 11 | tm.tm_min << 5 | second // 2)
    return stamp, (second % 2) * 100 + int(epoch % 1 * 100)
