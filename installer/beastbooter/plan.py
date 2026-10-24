"""Partition plan: where each partition goes for a given disk size and layout.

Pure arithmetic on top of layout.py, plus rendering the plan as an sfdisk script.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import BeastError
from .layout import (
    BIOS_BOOT_PART_INDEX,
    DATA_PART_INDEX,
    DATA_START_LBA,
    ESP_PART_INDEX,
    ESP_SIZE_SECTORS,
    FILESYSTEMS,
    GPT_BACKUP_SECTORS,
    GPT_BIOS_BOOT_END_LBA,
    GPT_BIOS_BOOT_START_LBA,
    GPT_CORE_LBA,
    GPT_CORE_MAX_SECTORS,
    GPT_NAME_BIOS_BOOT,
    GPT_NAME_DATA,
    GPT_NAME_ESP,
    GPT_PRIMARY_SECTORS,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_DATA,
    GPT_TYPE_ESP,
    LAYOUTS,
    MBR_CORE_LBA,
    MBR_CORE_MAX_SECTORS,
    MBR_TYPE_DATA,
    MBR_TYPE_ESP,
    MIB,
    MIB_SECTORS,
    MIN_DISK_MIB,
    SECTOR_SIZE,
)

MBR_MAX_LBA = 0xFFFFFFFF  # 32-bit LBA fields in an MBR partition entry
GPT_ENTRY_COUNT = 128


@dataclass(frozen=True)
class Part:
    index: int  # 1-based partition number
    role: str  # "data" | "esp" | "bios"
    start: int  # first LBA
    size: int  # sectors

    @property
    def end(self) -> int:
        """Last LBA (inclusive)."""
        return self.start + self.size - 1

    @property
    def offset(self) -> int:
        return self.start * SECTOR_SIZE

    @property
    def size_bytes(self) -> int:
        return self.size * SECTOR_SIZE


@dataclass(frozen=True)
class DiskPlan:
    layout: str
    disk_sectors: int
    data: Part
    esp: Part
    bios: Part | None  # GPT only
    core_lba: int
    core_max_sectors: int

    @property
    def parts(self) -> list[Part]:
        parts = [self.data, self.esp] + ([self.bios] if self.bios else [])
        return sorted(parts, key=lambda p: p.index)

    @property
    def last_usable_lba(self) -> int:
        if self.layout == "gpt":
            return self.disk_sectors - GPT_BACKUP_SECTORS - 1
        return self.disk_sectors - 1


def make_plan(disk_sectors: int, layout: str) -> DiskPlan:
    if layout not in LAYOUTS:
        raise BeastError(f"unknown layout {layout!r} (choose from {', '.join(LAYOUTS)})")
    min_sectors = MIN_DISK_MIB * MIB // SECTOR_SIZE
    if disk_sectors < min_sectors:
        raise BeastError(
            f"target is too small: {disk_sectors * SECTOR_SIZE} bytes, "
            f"need at least {MIN_DISK_MIB} MiB"
        )
    if layout == "gpt":
        usable_end = disk_sectors - GPT_BACKUP_SECTORS  # exclusive
    else:
        usable_end = disk_sectors
    esp_end = usable_end // MIB_SECTORS * MIB_SECTORS  # exclusive, aligned down to 1 MiB
    esp_start = esp_end - ESP_SIZE_SECTORS
    if layout == "msdos" and esp_end - 1 > MBR_MAX_LBA:
        raise BeastError(
            "target is larger than 2 TiB; the msdos layout cannot address it, use --layout gpt"
        )
    data = Part(DATA_PART_INDEX, "data", DATA_START_LBA, esp_start - DATA_START_LBA)
    esp = Part(ESP_PART_INDEX, "esp", esp_start, ESP_SIZE_SECTORS)
    if layout == "gpt":
        bios = Part(
            BIOS_BOOT_PART_INDEX,
            "bios",
            GPT_BIOS_BOOT_START_LBA,
            GPT_BIOS_BOOT_END_LBA - GPT_BIOS_BOOT_START_LBA + 1,
        )
        return DiskPlan(layout, disk_sectors, data, esp, bios, GPT_CORE_LBA, GPT_CORE_MAX_SECTORS)
    return DiskPlan(layout, disk_sectors, data, esp, None, MBR_CORE_LBA, MBR_CORE_MAX_SECTORS)


def sfdisk_script(plan: DiskPlan, fs: str) -> str:
    """sfdisk input for the plan. Partition numbers come from the trailing
    digits of the node names, so partition 3 (BIOS boot) can sit first on disk."""
    if fs not in FILESYSTEMS:
        raise BeastError(f"unknown filesystem {fs!r}")
    d, e = plan.data, plan.esp
    if plan.layout == "msdos":
        lines = [
            "label: dos",
            "unit: sectors",
            f"sector-size: {SECTOR_SIZE}",
            "",
            f"beast-p{d.index} : start={d.start}, size={d.size}, type={MBR_TYPE_DATA[fs]:x}, bootable",
            f"beast-p{e.index} : start={e.start}, size={e.size}, type={MBR_TYPE_ESP:x}",
        ]
    else:
        b = plan.bios
        assert b is not None
        lines = [
            "label: gpt",
            "unit: sectors",
            f"sector-size: {SECTOR_SIZE}",
            f"first-lba: {GPT_PRIMARY_SECTORS}",
            f"last-lba: {plan.last_usable_lba}",
            f"table-length: {GPT_ENTRY_COUNT}",
            "",
            f'beast-p{b.index} : start={b.start}, size={b.size}, type={GPT_TYPE_BIOS_BOOT}, name="{GPT_NAME_BIOS_BOOT}"',
            f'beast-p{d.index} : start={d.start}, size={d.size}, type={GPT_TYPE_DATA}, name="{GPT_NAME_DATA}"',
            f'beast-p{e.index} : start={e.start}, size={e.size}, type={GPT_TYPE_ESP}, name="{GPT_NAME_ESP}"',
        ]
    return "\n".join(lines) + "\n"
