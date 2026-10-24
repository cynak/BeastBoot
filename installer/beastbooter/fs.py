"""Data partition filesystems: label rules, identifying a filesystem, NTFS via mkfs.ntfs.

exFAT and FAT32 are written by exfatfs.py / fatfs.py. NTFS is the one
filesystem made by an external tool (Linux: mkfs.ntfs; Windows: Format-Volume
through the platform backend; macOS cannot make it).

probe_fs() identifies the filesystem at an offset of a BlockTarget in pure
Python and answers in the shape of `blkid -p -o export` (TYPE, VERSION, UUID,
LABEL), with UUIDs printed exactly as blkid and GRUB print them.
"""

from __future__ import annotations

import re
import shutil
import struct

from .errors import BeastError
from .exfatfs import ExfatVolume
from .fatfs import FatVolume
from .interfaces import format_volume_id
from .layout import FILESYSTEMS, SECTOR_SIZE
from .util import run

# Max label length per filesystem (characters), as the GUI checks it.
# NOTE: exFAT really allows only 11 (exFAT specification 7.3.2; mkfs.exfat and
# exfatfs refuse longer labels): commands.check_data_label() enforces that
# before anything is written. 15 stays here until the GUI tests are updated.
LABEL_MAX = {"fat32": 11, "exfat": 11, "ntfs": 32}  # exFAT: 11 UTF-16 units (spec 7.3)
# Conservative character set: valid on FAT/exFAT/NTFS and safe in GRUB scripts.
_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]([A-Za-z0-9 _-]*[A-Za-z0-9_-])?$")

NTFS_TOOL = "mkfs.ntfs"


def normalize_label(label: str, fs: str) -> str:
    """Validate a data partition label; FAT labels are upper-cased."""
    if fs not in FILESYSTEMS:
        raise BeastError(f"unknown filesystem {fs!r} (choose from {', '.join(FILESYSTEMS)})")
    if not _LABEL_RE.match(label):
        raise BeastError(
            f"invalid label {label!r}: use letters, digits, '_', '-' and inner spaces"
        )
    if len(label) > LABEL_MAX[fs]:
        raise BeastError(f"label {label!r} is too long for {fs} (max {LABEL_MAX[fs]} characters)")
    return label.upper() if fs == "fat32" else label


# ---------------------------------------------------------------------------
# NTFS (external formatter)
# ---------------------------------------------------------------------------


def have_mkfs_ntfs() -> bool:
    return shutil.which(NTFS_TOOL) is not None


def mkfs_data_cmd(fs: str, path: str, label: str, *, start_lba: int | None) -> list[str]:
    """mkfs command for an NTFS data filesystem.

    start_lba is given when `path` is a plain file (image build): it is the
    partition's start on the final disk, recorded as "hidden sectors" in the
    boot sector. On a partition device node mkfs.ntfs detects it.
    """
    if fs != "ntfs":
        raise BeastError(f"{fs} is written by beast-booter itself, not by an external mkfs")
    cmd = [NTFS_TOOL, "-q", "-Q", "-L", label]
    if start_lba is not None:
        cmd += ["-F", "-p", str(start_lba), "-H", "255", "-S", "63"]
    return cmd + [path]


def make_data_fs(fs: str, path: str, label: str, *, start_lba: int | None) -> None:
    run(mkfs_data_cmd(fs, path, label, start_lba=start_lba), what=f"creating the {fs} filesystem")


def ntfs_serial(boot_sector: bytes) -> str | None:
    """The NTFS volume serial as blkid prints it ("5D75E8BF295A314D"), or None."""
    if len(boot_sector) < SECTOR_SIZE or boot_sector[3:11] != b"NTFS    ":
        return None
    (serial,) = struct.unpack_from("<Q", boot_sector, 0x48)
    return f"{serial:016X}"


# ---------------------------------------------------------------------------
# Probing (pure Python)
# ---------------------------------------------------------------------------


def probe_fs(t, offset: int) -> dict[str, str]:
    """{TYPE, VERSION?, UUID, LABEL?} of the filesystem at `offset` of the BlockTarget
    `t` (TYPE: exfat, vfat, ntfs, as blkid names them); {} if none is recognised."""
    try:
        bs = t.read(offset, SECTOR_SIZE)
    except BeastError:
        return {}
    if len(bs) < SECTOR_SIZE or bs[510:512] != b"\x55\xaa":
        return {}
    try:
        if bs[3:11] == b"EXFAT   ":
            vol = ExfatVolume(t, offset)
            return {"TYPE": "exfat", "UUID": format_volume_id(vol.volume_serial), "LABEL": vol.label}
        if bs[3:11] == b"NTFS    ":
            out = {"TYPE": "ntfs", "UUID": ntfs_serial(bs)}
            label = _ntfs_label(t, offset, bs)
            if label is not None:
                out["LABEL"] = label
            return out
        vol = FatVolume(t, offset)
    except (BeastError, struct.error, IndexError, ValueError, UnicodeDecodeError):
        return {}
    return {"TYPE": "vfat", "VERSION": f"FAT{vol.fat_bits}", "UUID": format_volume_id(vol.volume_id),
            "LABEL": vol.label}


def _ntfs_label(t, offset: int, bs: bytes) -> str | None:
    """The label ($VOLUME_NAME of MFT record 3, $Volume); "" if it has none,
    None if the MFT cannot be read."""
    bps = struct.unpack_from("<H", bs, 0x0B)[0]
    spc = bs[0x0D]
    if spc > 0x80:  # clusters over 64 KiB: stored as a negative power of two
        spc = 1 << (256 - spc)
    if bps not in (512, 1024, 2048, 4096) or not spc:
        return None
    cluster = bps * spc
    (mft_lcn,) = struct.unpack_from("<Q", bs, 0x30)
    (per_record,) = struct.unpack_from("<b", bs, 0x40)
    rec_size = per_record * cluster if per_record > 0 else 1 << -per_record
    if not 512 <= rec_size <= 65536:
        return None
    rec = bytearray(t.read(offset + mft_lcn * cluster + 3 * rec_size, rec_size))
    if rec[:4] != b"FILE":
        return None
    usa_off, usa_count = struct.unpack_from("<HH", rec, 4)
    if usa_count < 2 or usa_off + 2 * usa_count > rec_size or (usa_count - 1) * 512 > rec_size:
        return None
    usn = rec[usa_off : usa_off + 2]
    for i in range(1, usa_count):  # undo the update sequence fixups (one per 512 bytes)
        end = i * 512
        if rec[end - 2 : end] != usn:
            return None  # torn write
        rec[end - 2 : end] = rec[usa_off + 2 * i : usa_off + 2 * i + 2]
    pos = struct.unpack_from("<H", rec, 0x14)[0]
    while pos + 24 <= rec_size:
        atype, alen = struct.unpack_from("<II", rec, pos)
        if atype == 0xFFFFFFFF or alen < 24 or pos + alen > rec_size:
            break
        if atype == 0x60 and rec[pos + 8] == 0:  # $VOLUME_NAME, resident
            vlen, voff = struct.unpack_from("<IH", rec, pos + 0x10)
            if pos + voff + vlen > rec_size:
                return None
            return rec[pos + voff : pos + voff + vlen].decode("utf-16-le", errors="replace")
        pos += alen
    return ""


def fs_name(probe: dict[str, str]) -> str | None:
    """Map blkid TYPE/VERSION to our filesystem names."""
    t = probe.get("TYPE")
    if t == "exfat":
        return "exfat"
    if t == "ntfs":
        return "ntfs"
    if t == "vfat":
        return "fat32" if probe.get("VERSION", "FAT32") == "FAT32" else probe.get("VERSION", "vfat").lower()
    return t


def grub_uuid(blkid_uuid: str) -> str:
    """UUID as GRUB's `probe --fs-uuid` prints it.

    Verified with GRUB 2.14 (i386-pc, QEMU): FAT32, exFAT and NTFS UUIDs are
    printed in upper case ("1A2B-3C4D", "5D75E8BF295A314D"), i.e. the same as
    blkid. (ARCHITECTURE.md §5 says lower case; that note is wrong.)
    `search --fs-uuid` compares case-insensitively, so either form finds it.
    """
    return blkid_uuid.upper()
