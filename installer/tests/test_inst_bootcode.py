"""boot.img / core.img patching (pure) and its placement in created images."""

import struct

import pytest

from beastbooter.bootcode import boot_writes, patch_boot_img, patch_core_img, read_core_lba
from beastbooter.errors import BeastError
from beastbooter.layout import (
    BOOT_IMG_CODE_LEN,
    DIST_BOOT_IMG,
    DIST_CORE_IMG,
    GPT_CORE_MAX_SECTORS,
    MBR_CORE_MAX_SECTORS,
)
from beastbooter.plan import make_plan
from conftest import needs_tools, sfdisk_json

MIN = 2097152  # MIN_DISK_MIB in sectors


def stock_boot(fake_dist):
    return (fake_dist / DIST_BOOT_IMG).read_bytes()


@pytest.mark.parametrize("lba", [1, 34])
def test_patch_boot_img(fake_dist, lba):
    orig = stock_boot(fake_dist)
    b = patch_boot_img(orig, lba)
    assert len(b) == 512
    assert b[0x5C:0x64] == struct.pack("<Q", lba)
    assert b[0x66:0x68] == b"\x90\x90"
    assert read_core_lba(b) == lba
    # nothing else changes
    for i in range(512):
        if not (0x5C <= i < 0x64 or 0x66 <= i < 0x68):
            assert b[i] == orig[i], hex(i)


def test_patch_boot_img_rejects_bad_input():
    with pytest.raises(BeastError, match="512 bytes"):
        patch_boot_img(b"\0" * 511, 1)
    with pytest.raises(BeastError, match="55 AA"):
        patch_boot_img(b"\0" * 512, 1)


@pytest.mark.parametrize("lba,maxs", [(1, MBR_CORE_MAX_SECTORS), (34, GPT_CORE_MAX_SECTORS)])
def test_patch_core_img(lba, maxs):
    core = bytes(range(256)) * 20 + b"\x01\x02\x03"  # 5123 bytes -> 11 sectors
    c = patch_core_img(core, lba, maxs)
    assert len(c) == 11 * 512
    assert c[0x1F4:0x200] == struct.pack("<QHH", lba + 1, 10, 0x0820)
    assert c[:0x1F4] == core[:0x1F4]
    assert c[0x200 : len(core)] == core[0x200:]
    assert c[len(core):] == b"\0" * (len(c) - len(core))


def test_core_size_limits():
    assert patch_core_img(b"\1" * 2047 * 512, 1, MBR_CORE_MAX_SECTORS)
    with pytest.raises(BeastError, match="2048 sectors but only 2047 fit"):
        patch_core_img(b"\1" * (2047 * 512 + 1), 1, MBR_CORE_MAX_SECTORS)
    assert patch_core_img(b"\1" * 2014 * 512, 34, GPT_CORE_MAX_SECTORS)
    with pytest.raises(BeastError, match="2015 sectors but only 2014 fit"):
        patch_core_img(b"\1" * 2014 * 512 + b"\1", 34, GPT_CORE_MAX_SECTORS)
    with pytest.raises(BeastError, match="too small"):
        patch_core_img(b"\1" * 512, 1, MBR_CORE_MAX_SECTORS)


def test_boot_writes_msdos(fake_dist):
    boot, core = stock_boot(fake_dist), (fake_dist / DIST_CORE_IMG).read_bytes()
    w = dict(boot_writes(make_plan(MIN, "msdos"), boot, core))
    assert set(w) == {0, 512}
    assert w[0] == patch_boot_img(boot, 1)[:BOOT_IMG_CODE_LEN]
    assert len(w[0]) == 440
    assert w[512] == patch_core_img(core, 1, MBR_CORE_MAX_SECTORS)


def test_boot_writes_gpt(fake_dist):
    boot, core = stock_boot(fake_dist), (fake_dist / DIST_CORE_IMG).read_bytes()
    w = dict(boot_writes(make_plan(MIN, "gpt"), boot, core))
    assert set(w) == {0, 34 * 512, 0x1BE}
    assert w[0] == patch_boot_img(boot, 34)[:440]
    assert w[0x1BE] == b"\x80"  # protective MBR entry marked active
    assert w[34 * 512][0x1F4:0x200] == struct.pack("<QHH", 35, len(w[34 * 512]) // 512 - 1, 0x820)


@needs_tools
@pytest.mark.parametrize("layout", ["msdos", "gpt"])
def test_boot_code_on_image(installed, fake_dist, layout):
    img = installed(layout, "exfat")
    raw = img.read_bytes()[: 2048 * 512]
    boot, core = stock_boot(fake_dist), (fake_dist / DIST_CORE_IMG).read_bytes()
    lba = 1 if layout == "msdos" else 34
    assert raw[:440] == patch_boot_img(boot, lba)[:440]
    pc = patch_core_img(core, lba, 2047)
    assert raw[lba * 512 : lba * 512 + len(pc)] == pc
    assert raw[510:512] == b"\x55\xaa"
    assert raw[0x1BE] == 0x80  # msdos: data partition active; gpt: protective entry active
    if layout == "gpt":
        assert raw[0x1C2] == 0xEE
        assert raw[512:520] == b"EFI PART"  # primary GPT header untouched
    # the partition table survived the boot code write
    t = sfdisk_json(img)
    assert t["label"] == ("dos" if layout == "msdos" else "gpt")
    assert len(t["partitions"]) == (2 if layout == "msdos" else 3)
