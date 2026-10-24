"""Partition plan math (pure) and the sfdisk script."""

import pytest

from beastbooter.errors import BeastError
from beastbooter.layout import (
    DATA_START_LBA,
    ESP_SIZE_SECTORS,
    GPT_BACKUP_SECTORS,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_DATA,
    GPT_TYPE_ESP,
    MIB,
    MIB_SECTORS,
    MIN_DISK_MIB,
    SECTOR_SIZE,
)
from beastbooter.plan import make_plan, sfdisk_script

MIN_SECTORS = MIN_DISK_MIB * MIB // SECTOR_SIZE


def test_msdos_minimum_size():
    p = make_plan(MIN_SECTORS, "msdos")
    assert (p.data.index, p.data.start, p.data.size) == (1, 2048, MIN_SECTORS - ESP_SIZE_SECTORS - 2048)
    assert (p.esp.index, p.esp.start, p.esp.size) == (2, MIN_SECTORS - ESP_SIZE_SECTORS, ESP_SIZE_SECTORS)
    assert p.esp.end == MIN_SECTORS - 1  # exactly at the end: already MiB aligned
    assert p.bios is None
    assert (p.core_lba, p.core_max_sectors) == (1, 2047)


def test_gpt_minimum_size():
    p = make_plan(MIN_SECTORS, "gpt")
    # The backup GPT takes the last 33 LBAs, so the ESP moves down one MiB.
    assert p.esp.start == MIN_SECTORS - MIB_SECTORS - ESP_SIZE_SECTORS == 1046528
    assert p.esp.end == MIN_SECTORS - MIB_SECTORS - 1
    assert (p.data.start, p.data.size) == (2048, 1046528 - 2048)
    assert (p.bios.index, p.bios.start, p.bios.end, p.bios.size) == (3, 34, 2047, 2014)
    assert (p.core_lba, p.core_max_sectors) == (34, 2014)
    assert p.last_usable_lba == MIN_SECTORS - 34


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
def test_too_small(layout):
    with pytest.raises(BeastError, match="too small"):
        make_plan(MIN_SECTORS - 1, layout)


def test_size_not_whole_mib():
    n = 1100000001 // SECTOR_SIZE  # 2148437 sectors = 1049 MiB + 85 sectors
    m, g = make_plan(n, "msdos"), make_plan(n, "gpt")
    assert m.esp.start == g.esp.start == 1049 * MIB_SECTORS - ESP_SIZE_SECTORS == 1099776
    assert m.data.size == g.data.size == 1097728
    # 1600 MiB + 10 sectors: msdos ends the ESP at 1600 MiB, gpt one MiB earlier.
    n = 1600 * MIB_SECTORS + 10
    m, g = make_plan(n, "msdos"), make_plan(n, "gpt")
    assert m.esp.end + 1 == 1600 * MIB_SECTORS
    assert g.esp.end + 1 == 1599 * MIB_SECTORS


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
@pytest.mark.parametrize("n", [MIN_SECTORS, MIN_SECTORS + 1, MIN_SECTORS + 2047, 2148437,
                               8 * (1 << 30) // 512, 31266816, 2 ** 32 - 1])
def test_plan_invariants(layout, n):
    p = make_plan(n, layout)
    assert p.data.start == DATA_START_LBA
    assert p.data.end + 1 == p.esp.start  # data runs right up to the ESP
    assert p.esp.size == ESP_SIZE_SECTORS
    assert (p.esp.end + 1) % MIB_SECTORS == 0  # end aligned to 1 MiB
    assert p.esp.start % MIB_SECTORS == 0
    assert p.esp.end <= p.last_usable_lba
    assert p.last_usable_lba == (n - 1 - GPT_BACKUP_SECTORS if layout == "gpt" else n - 1)
    assert p.last_usable_lba - p.esp.end < MIB_SECTORS  # nothing wasted beyond alignment
    if layout == "gpt":
        assert p.bios.end < p.data.start


def test_msdos_limit_2tib():
    with pytest.raises(BeastError, match="--layout gpt"):
        make_plan(2 ** 32 + MIB_SECTORS, "msdos")
    assert make_plan(2 ** 33, "gpt").esp.end > 2 ** 32
    assert make_plan(2 ** 32, "msdos").esp.end == 2 ** 32 - 1  # exactly 2 TiB still fits


def test_unknown_layout():
    with pytest.raises(BeastError):
        make_plan(MIN_SECTORS, "apm")


def test_sfdisk_script_msdos():
    p = make_plan(MIN_SECTORS, "msdos")
    s = sfdisk_script(p, "fat32")
    assert "label: dos" in s
    assert f"beast-p1 : start=2048, size={p.data.size}, type=c, bootable" in s
    assert f"beast-p2 : start={p.esp.start}, size={ESP_SIZE_SECTORS}, type=ef\n" in s
    assert "type=7," in sfdisk_script(p, "exfat") and "type=7," in sfdisk_script(p, "ntfs")


def test_sfdisk_script_gpt():
    p = make_plan(MIN_SECTORS, "gpt")
    s = sfdisk_script(p, "exfat")
    assert "label: gpt" in s and "first-lba: 34" in s and f"last-lba: {MIN_SECTORS - 34}" in s
    assert f'beast-p3 : start=34, size=2014, type={GPT_TYPE_BIOS_BOOT}, name="BEAST-BIOS"' in s
    assert f'type={GPT_TYPE_DATA}, name="BEAST-DATA"' in s
    assert f'type={GPT_TYPE_ESP}, name="BEAST-EFI"' in s
