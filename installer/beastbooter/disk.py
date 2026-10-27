"""Read MBR / GPT partition tables (pure Python, struct-based)."""

from __future__ import annotations

import struct
import uuid
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from .errors import BeastError
from .layout import SECTOR_SIZE

GPT_SIGNATURE = b"EFI PART"
MBR_TYPE_GPT_PROTECTIVE = 0xEE
MBR_EXTENDED_TYPES = (0x05, 0x0F, 0x85)


@dataclass
class PartEntry:
    index: int
    start: int  # first LBA
    size: int  # sectors
    type: str  # MBR: "0x07"; GPT: upper-case type GUID
    bootable: bool = False  # MBR active flag
    name: str | None = None  # GPT partition name

    @property
    def end(self) -> int:
        return self.start + self.size - 1


@dataclass
class PartTable:
    label: str  # "msdos" | "gpt"
    disk_id: str
    entries: dict[int, PartEntry] = field(default_factory=dict)
    pmbr_active: bool = False  # GPT: protective MBR entry has the active flag


ReadAt = Callable[[int, int], bytes]


def _guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw)).upper()


def parse_mbr_entries(mbr: bytes) -> list[tuple[int, int, int, int]]:
    """[(slot 1..4, status, type, start, size)] for non-empty entries."""
    out = []
    for i in range(4):
        status, ptype, start, size = struct.unpack_from("<B3xB3xII", mbr, 0x1BE + 16 * i)
        if ptype != 0 and size != 0:
            out.append((i + 1, status, ptype, start, size))
    return out


def read_partition_table(read_at: ReadAt, disk_sectors: int) -> PartTable:
    mbr = read_at(0, SECTOR_SIZE)
    if len(mbr) < SECTOR_SIZE or mbr[510:512] != b"\x55\xaa":
        raise BeastError("no partition table found (no MBR boot signature)")
    entries = parse_mbr_entries(mbr)
    if any(e[2] == MBR_TYPE_GPT_PROTECTIVE for e in entries):
        table = _read_gpt(read_at, disk_sectors)
        table.pmbr_active = any(
            e[2] == MBR_TYPE_GPT_PROTECTIVE and e[1] & 0x80 for e in entries
        )
        return table
    disk_id = "0x%08x" % struct.unpack_from("<I", mbr, 0x1B8)[0]
    table = PartTable("msdos", disk_id)
    for slot, status, ptype, start, size in entries:
        if ptype in MBR_EXTENDED_TYPES:
            continue  # logical partitions are never part of a beast-boot layout
        table.entries[slot] = PartEntry(slot, start, size, "0x%02x" % ptype, bool(status & 0x80))
    return table


def _read_gpt(read_at: ReadAt, disk_sectors: int) -> PartTable:
    hdr = read_at(SECTOR_SIZE, SECTOR_SIZE)
    if hdr[:8] != GPT_SIGNATURE:
        raise BeastError("protective MBR found but no GPT header at LBA 1")
    (hdr_size,) = struct.unpack_from("<I", hdr, 12)
    if not 92 <= hdr_size <= SECTOR_SIZE:
        raise BeastError("GPT header has an invalid size")
    (hdr_crc,) = struct.unpack_from("<I", hdr, 16)
    check = bytearray(hdr[:hdr_size])
    check[16:20] = b"\0\0\0\0"
    if zlib.crc32(check) & 0xFFFFFFFF != hdr_crc:
        raise BeastError("GPT header checksum mismatch (corrupt partition table)")
    disk_guid = _guid(hdr[56:72])
    entries_lba, n_entries, entry_size, entries_crc = struct.unpack_from("<QIII", hdr, 72)
    if entry_size < 128 or n_entries > 1024 or entries_lba >= disk_sectors:
        raise BeastError("GPT header has invalid partition entry fields")
    raw = read_at(entries_lba * SECTOR_SIZE, n_entries * entry_size)
    if zlib.crc32(raw) & 0xFFFFFFFF != entries_crc:
        raise BeastError("GPT partition entries checksum mismatch (corrupt partition table)")
    table = PartTable("gpt", disk_guid)
    for i in range(n_entries):
        e = raw[i * entry_size : (i + 1) * entry_size]
        if e[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le", errors="replace").split("\0", 1)[0]
        table.entries[i + 1] = PartEntry(i + 1, first, last - first + 1, _guid(e[:16]), name=name)
    return table
