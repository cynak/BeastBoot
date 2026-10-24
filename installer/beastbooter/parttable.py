"""Write MBR ("msdos") and GPT partition tables in pure Python.

This replaces `sfdisk` for creating a beast-booter drive, so the installer
works the same on Linux, Windows and macOS. The geometry comes from
plan.make_plan(); types, names and flags come from layout.py.

What is written (512-byte sectors only):

msdos
  LBA 0: classic MBR. Bytes 0..439 (boot code) are zero, or the existing boot
  code when keep_boot_code=True. Bytes 440..443 hold the 32-bit disk
  signature, 444..445 are zero, then four 16-byte partition entries and the
  55 AA signature. Entry 1 = data (active, type from MBR_TYPE_DATA), entry 2 =
  ESP (type 0xEF). CHS fields use the 255 heads x 63 sectors geometry and are
  clamped to 1023/254/63 beyond cylinder 1023, like sfdisk/libfdisk.
  A stale GPT header (from an earlier GPT layout) at LBA 1 or at the last LBA
  is zeroed so no tool sees two partition tables.

gpt (UEFI specification 2.10, chapter 5)
  LBA 0: protective MBR with one 0xEE entry covering LBA 1 .. min(last, 2^32-1),
  start CHS 00 02 00 and end CHS FF FF FF (as sfdisk and parted write it), disk
  signature zero. The entry carries the active flag (ARCHITECTURE.md section 3:
  needed by many BIOSes; UEFI firmware must ignore it).
  LBA 1: primary header. LBA 2..33: 128 partition entries of 128 bytes.
  Last 33 LBAs: backup entries, then the backup header in the very last LBA,
  with MyLBA/AlternateLBA/PartitionEntryLBA mirrored. Header CRC32 covers the
  92 header bytes (with the CRC field zero), the entries CRC32 covers all 128
  entries. Partition slots follow the partition numbers: slot 1 = data, slot 2
  = ESP, slot 3 = BIOS boot. Names are UTF-16LE, attribute bits are zero.

The result is byte-identical to what `sfdisk` produces from
plan.sfdisk_script() with the same identifiers (the tests check this), except
that the protective MBR entry is already marked active here.

Nothing is flushed; the caller flushes the target when it is done with it.
"""

from __future__ import annotations

import secrets
import struct
import uuid
import zlib
from collections.abc import Mapping

from .errors import BeastError
from .layout import (
    BOOT_IMG_CODE_LEN,
    GPT_BACKUP_SECTORS,
    GPT_NAME_BIOS_BOOT,
    GPT_NAME_DATA,
    GPT_NAME_ESP,
    GPT_PRIMARY_SECTORS,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_DATA,
    GPT_TYPE_ESP,
    LAYOUTS,
    MBR_ACTIVE_FLAG,
    MBR_TYPE_DATA,
    MBR_TYPE_ESP,
    SECTOR_SIZE,
)
from .plan import GPT_ENTRY_COUNT, DiskPlan, Part

MBR_DISK_SIGNATURE_OFFSET = 440
MBR_PART_TABLE_OFFSET = 446
MBR_BOOT_SIGNATURE = b"\x55\xaa"
MBR_TYPE_GPT_PROTECTIVE = 0xEE

GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x00010000  # 1.0
GPT_HEADER_SIZE = 92
GPT_ENTRY_SIZE = 128
GPT_ENTRIES_LBA = 2
GPT_ENTRIES_SECTORS = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE // SECTOR_SIZE  # 32
GPT_NAME_MAX_CHARS = 36  # 72 bytes of UTF-16LE

# CHS geometry used for the legacy CHS fields (what sfdisk uses for image files
# and what every BIOS-era tool assumes for LBA-addressed disks).
CHS_HEADS = 255
CHS_SECTORS = 63
CHS_MAX = bytes([0xFE, 0xFF, 0xFF])  # cylinder 1023, head 254, sector 63


def write_partition_table(
    t,
    plan: DiskPlan,
    fs: str,
    *,
    disk_signature: int | None = None,
    disk_guid: str | None = None,
    part_guids: dict[int, str] | None = None,
    keep_boot_code: bool = False,
) -> None:
    """Write the partition table for `plan` to the BlockTarget `t`.

    msdos: disk_signature (32-bit) is used; random (non-zero) when None.
    gpt:   disk_guid and part_guids ({partition number: GUID}) are used; random
           GUIDs (version 4, from the `secrets` module) for anything not given.
           disk_signature is ignored (the UEFI spec wants it zero in a PMBR).
    keep_boot_code=True keeps bytes 0..439 of the current LBA 0 (the BIOS boot
    code); by default they are zero, and bootcode.py fills them in later.
    """
    if not isinstance(plan, DiskPlan):
        raise BeastError(f"expected a plan.DiskPlan, not {type(plan).__name__}")
    if plan.layout not in LAYOUTS:
        raise BeastError(f"unknown layout {plan.layout!r}")
    if not isinstance(fs, str) or fs not in MBR_TYPE_DATA:
        raise BeastError(f"unknown filesystem {fs!r}")
    if disk_signature is not None and not _is_u32(disk_signature):
        raise BeastError(f"disk signature {disk_signature!r} is not a 32-bit number")
    if part_guids is not None and not isinstance(part_guids, Mapping):
        raise BeastError(f"part_guids must map partition numbers to GUIDs, not {type(part_guids).__name__}")
    if t.sector_size != SECTOR_SIZE:
        raise BeastError(
            f"the target has {t.sector_size}-byte sectors; only {SECTOR_SIZE}-byte sectors are supported"
        )
    if t.size // SECTOR_SIZE != plan.disk_sectors:
        raise BeastError(
            f"partition plan is for {plan.disk_sectors} sectors but the target has "
            f"{t.size // SECTOR_SIZE}"
        )
    # All I/O is in whole sectors, so raw devices never need read-modify-write.
    boot_code = t.read(0, SECTOR_SIZE)[:BOOT_IMG_CODE_LEN] if keep_boot_code else bytes(BOOT_IMG_CODE_LEN)
    if len(boot_code) != BOOT_IMG_CODE_LEN:
        raise BeastError("could not read the current boot sector")

    if plan.layout == "msdos":
        sig = _random_disk_signature() if disk_signature is None else disk_signature
        mbr = build_mbr(plan, fs, sig, boot_code=boot_code)
        _wipe_stale_gpt(t, plan.disk_sectors)
        t.write(0, mbr)
        return

    guids = _gpt_guids(plan, disk_guid, part_guids)
    primary, backup = build_gpt(plan, guids["disk"], guids)
    last = plan.disk_sectors - 1
    # Backup first and the protective MBR last: until LBA 0 is written, no
    # tool recognises a half-written GPT.
    t.write((last - GPT_ENTRIES_SECTORS) * SECTOR_SIZE, backup)
    t.write(SECTOR_SIZE, primary)
    t.write(0, build_protective_mbr(plan.disk_sectors, boot_code=boot_code))


# ---------------------------------------------------------------------------
# MBR
# ---------------------------------------------------------------------------


def chs(lba: int) -> bytes:
    """3-byte CHS address (head, sector | cylinder bits 8-9, cylinder bits 0-7)."""
    if lba >= 1024 * CHS_HEADS * CHS_SECTORS:
        return CHS_MAX
    cyl, rem = divmod(lba, CHS_HEADS * CHS_SECTORS)
    head, sector = divmod(rem, CHS_SECTORS)
    return bytes([head, (sector + 1) | ((cyl >> 8) << 6), cyl & 0xFF])


def mbr_entry(status: int, ptype: int, start: int, size: int) -> bytes:
    if not (0 < start <= 0xFFFFFFFF and 0 < size <= 0xFFFFFFFF):
        raise BeastError(f"partition at LBA {start} (+{size}) cannot be described in an MBR")
    return (
        bytes([status]) + chs(start) + bytes([ptype]) + chs(start + size - 1)
        + struct.pack("<II", start, size)
    )


def _is_u32(value) -> bool:
    """An integer 0 .. 2^32-1 (True/False are not accepted as numbers here)."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF


def _mbr_sector(boot_code: bytes, disk_signature: int, entries: list[bytes]) -> bytes:
    if not _is_u32(disk_signature):
        raise BeastError(f"disk signature {disk_signature!r} is not a 32-bit number")
    table = b"".join(entries).ljust(4 * 16, b"\0")
    sector = boot_code + struct.pack("<IH", disk_signature, 0) + table + MBR_BOOT_SIGNATURE
    assert len(sector) == SECTOR_SIZE
    return sector


def build_mbr(plan: DiskPlan, fs: str, disk_signature: int, *, boot_code: bytes = bytes(BOOT_IMG_CODE_LEN)) -> bytes:
    """LBA 0 of an msdos-layout drive (partition 1 active)."""
    entries = [
        mbr_entry(MBR_ACTIVE_FLAG, MBR_TYPE_DATA[fs], plan.data.start, plan.data.size),
        mbr_entry(0, MBR_TYPE_ESP, plan.esp.start, plan.esp.size),
    ]
    return _mbr_sector(boot_code, disk_signature, entries)


def build_protective_mbr(disk_sectors: int, *, boot_code: bytes = bytes(BOOT_IMG_CODE_LEN)) -> bytes:
    """LBA 0 of a GPT drive: one 0xEE entry over the whole disk (or 2^32-1 sectors)."""
    size = min(disk_sectors - 1, 0xFFFFFFFF)
    entry = (
        bytes([MBR_ACTIVE_FLAG]) + b"\x00\x02\x00" + bytes([MBR_TYPE_GPT_PROTECTIVE])
        + b"\xff\xff\xff" + struct.pack("<II", 1, size)
    )
    return _mbr_sector(boot_code, 0, [entry])


def _random_disk_signature() -> int:
    while True:  # 0 means "no signature" to Windows
        value = secrets.randbits(32)
        if value:
            return value


def _wipe_stale_gpt(t, disk_sectors: int) -> None:
    for lba in (1, disk_sectors - 1):
        if t.read(lba * SECTOR_SIZE, SECTOR_SIZE)[: len(GPT_SIGNATURE)] == GPT_SIGNATURE:
            t.write(lba * SECTOR_SIZE, bytes(SECTOR_SIZE))


# ---------------------------------------------------------------------------
# GPT
# ---------------------------------------------------------------------------


def _guid_bytes(value: str, what: str) -> bytes:
    try:
        return uuid.UUID(value).bytes_le
    except (ValueError, TypeError, AttributeError):
        raise BeastError(f"invalid GUID for {what}: {value!r}") from None


def _random_guid() -> str:
    return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4)).upper()


def _gpt_guids(plan: DiskPlan, disk_guid: str | None, part_guids: dict[int, str] | None) -> dict:
    """{"disk": GUID, partition number: GUID}; a given value is used as it is
    (so an empty string is an invalid GUID, not a request for a random one)."""
    given = dict(part_guids or {})
    known = {p.index for p in plan.parts}
    unknown = sorted(set(given) - known, key=repr)
    if unknown:
        raise BeastError(f"part_guids names partitions that are not in the plan: {unknown}")
    out: dict = {"disk": _random_guid() if disk_guid is None else disk_guid}
    for p in plan.parts:
        out[p.index] = given[p.index] if given.get(p.index) is not None else _random_guid()
    for what, value in out.items():
        _guid_bytes(value, "the disk" if what == "disk" else f"partition {what}")
    return out


def _gpt_type_and_name(part: Part) -> tuple[str, str]:
    return {
        "data": (GPT_TYPE_DATA, GPT_NAME_DATA),
        "esp": (GPT_TYPE_ESP, GPT_NAME_ESP),
        "bios": (GPT_TYPE_BIOS_BOOT, GPT_NAME_BIOS_BOOT),
    }[part.role]


def gpt_entry(type_guid: str, part_guid: str, first: int, last: int, name: str) -> bytes:
    if len(name) > GPT_NAME_MAX_CHARS:
        raise BeastError(f"GPT partition name {name!r} is longer than {GPT_NAME_MAX_CHARS} characters")
    return (
        _guid_bytes(type_guid, "partition type") + _guid_bytes(part_guid, "partition")
        + struct.pack("<QQQ", first, last, 0)  # attributes: none
        + name.encode("utf-16-le").ljust(72, b"\0")
    )


def gpt_header(*, my_lba: int, alternate_lba: int, first_usable: int, last_usable: int,
               disk_guid: str, entries_lba: int, entries_crc: int) -> bytes:
    """One 512-byte header sector (92 header bytes + zero padding), CRC filled in."""
    def pack(crc: int) -> bytes:
        return (
            GPT_SIGNATURE
            + struct.pack("<IIII", GPT_REVISION, GPT_HEADER_SIZE, crc, 0)
            + struct.pack("<QQQQ", my_lba, alternate_lba, first_usable, last_usable)
            + _guid_bytes(disk_guid, "disk")
            + struct.pack("<QIII", entries_lba, GPT_ENTRY_COUNT, GPT_ENTRY_SIZE, entries_crc)
        )
    header = pack(zlib.crc32(pack(0)) & 0xFFFFFFFF)
    assert len(header) == GPT_HEADER_SIZE
    return header.ljust(SECTOR_SIZE, b"\0")


def build_gpt(plan: DiskPlan, disk_guid: str, part_guids: dict[int, str]) -> tuple[bytes, bytes]:
    """(primary, backup): primary = header + entries for LBA 1..33,
    backup = entries + header for the last 33 LBAs."""
    entries = bytearray(GPT_ENTRY_COUNT * GPT_ENTRY_SIZE)
    for p in plan.parts:
        type_guid, name = _gpt_type_and_name(p)
        pos = (p.index - 1) * GPT_ENTRY_SIZE
        entries[pos : pos + GPT_ENTRY_SIZE] = gpt_entry(type_guid, part_guids[p.index], p.start, p.end, name)
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    last = plan.disk_sectors - 1
    backup_entries_lba = last - GPT_ENTRIES_SECTORS
    first_usable, last_usable = GPT_PRIMARY_SECTORS, plan.last_usable_lba
    assert backup_entries_lba == plan.disk_sectors - GPT_BACKUP_SECTORS
    for p in plan.parts:
        if not first_usable <= p.start <= p.end <= last_usable:
            raise BeastError(f"partition {p.index} lies outside the usable GPT area")
    common = dict(first_usable=first_usable, last_usable=last_usable, disk_guid=disk_guid,
                  entries_crc=entries_crc)
    primary = gpt_header(my_lba=1, alternate_lba=last, entries_lba=GPT_ENTRIES_LBA, **common)
    backup = gpt_header(my_lba=last, alternate_lba=1, entries_lba=backup_entries_lba, **common)
    return primary + bytes(entries), bytes(entries) + backup
