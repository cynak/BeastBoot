"""BIOS boot code: patch GRUB's boot.img and core.img the way grub-install does.

Pure functions; offsets come from layout.py (ARCHITECTURE.md §3).
"""

from __future__ import annotations

import struct

from .errors import BeastError
from .layout import (
    BOOT_DRIVE_CHECK_OFFSET,
    BOOT_IMG_CODE_LEN,
    BOOT_IMG_SIZE,
    BOOT_KERNEL_SECTOR_OFFSET,
    CORE_BLOCKLIST_OFFSET,
    CORE_BLOCKLIST_SEGMENT,
    MBR_ACTIVE_FLAG,
    SECTOR_SIZE,
)
from .plan import DiskPlan

MBR_PART_TABLE_OFFSET = 0x1BE  # first partition entry; byte 0 = status (active flag)


def patch_boot_img(boot_img: bytes, core_lba: int) -> bytes:
    """Return boot.img with the core.img LBA and the drive-check NOPs patched in."""
    if len(boot_img) != BOOT_IMG_SIZE:
        raise BeastError(f"boot.img must be {BOOT_IMG_SIZE} bytes, got {len(boot_img)}")
    if boot_img[510:512] != b"\x55\xaa":
        raise BeastError("boot.img has no 55 AA boot signature; is it GRUB's i386-pc boot.img?")
    b = bytearray(boot_img)
    struct.pack_into("<Q", b, BOOT_KERNEL_SECTOR_OFFSET, core_lba)
    b[BOOT_DRIVE_CHECK_OFFSET : BOOT_DRIVE_CHECK_OFFSET + 2] = b"\x90\x90"
    return bytes(b)


def core_sectors(core_img: bytes) -> int:
    return -(-len(core_img) // SECTOR_SIZE)


def patch_core_img(core_img: bytes, core_lba: int, max_sectors: int) -> bytes:
    """Return core.img padded to whole sectors with its first blocklist patched:
    start = core_lba + 1, count = sectors - 1, segment = 0x820."""
    n = core_sectors(core_img)
    if n < 2:
        raise BeastError(f"core.img is too small ({len(core_img)} bytes); expected at least 2 sectors")
    if n > max_sectors:
        raise BeastError(
            f"core.img is {n} sectors but only {max_sectors} fit before partition 1"
        )
    if n - 1 > 0xFFFF:
        raise BeastError("core.img is too large for the blocklist")
    b = bytearray(core_img)
    b.extend(b"\0" * (n * SECTOR_SIZE - len(b)))
    struct.pack_into("<QHH", b, CORE_BLOCKLIST_OFFSET, core_lba + 1, n - 1, CORE_BLOCKLIST_SEGMENT)
    return bytes(b)


def boot_writes(plan: DiskPlan, boot_img: bytes, core_img: bytes) -> list[tuple[int, bytes]]:
    """All (byte offset, data) writes that install the BIOS boot code.

    Only boot.img bytes 0..439 go to LBA 0, so the disk signature and the
    partition table survive. On GPT the protective MBR entry is marked active.
    """
    boot = patch_boot_img(boot_img, plan.core_lba)
    core = patch_core_img(core_img, plan.core_lba, plan.core_max_sectors)
    writes = [
        (plan.core_lba * SECTOR_SIZE, core),
        (0, boot[:BOOT_IMG_CODE_LEN]),
    ]
    if plan.layout == "gpt":
        writes.append((MBR_PART_TABLE_OFFSET, bytes([MBR_ACTIVE_FLAG])))
    return writes


def read_core_lba(mbr: bytes) -> int:
    """The core.img LBA recorded in an installed boot sector."""
    return struct.unpack_from("<Q", mbr, BOOT_KERNEL_SECTOR_OFFSET)[0]
