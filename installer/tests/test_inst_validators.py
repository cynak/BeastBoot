"""Independent tools agree with what the pure-Python installer wrote:
sfdisk -V / sgdisk -v, fsck.fat -n (ESP), fsck.exfat -n / fsck.fat -n (data),
and blkid's label + UUID of the data partition == device.cfg == info --json."""

from __future__ import annotations

import re

import pytest
from conftest import (
    blkid_at,
    fresh_image,
    info_json,
    needs_fsck,
    needs_tools,
    validate_drive,
)

from beastbooter.blockio import ImageTarget
from beastbooter.fs import probe_fs
from beastbooter.interfaces import format_volume_id

pytestmark = [needs_tools, needs_fsck]


@pytest.mark.parametrize("layout", ["msdos", "gpt"])
@pytest.mark.parametrize("fs", ["exfat", "fat32"])
def test_validators_accept_image(installed, tmp_path, layout, fs):
    j = validate_drive(installed(layout, fs), layout, fs, "BEASTBOOTER", tmp_path)
    assert re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", j["data"]["uuid"])


@pytest.mark.parametrize("layout,fs,label", [("gpt", "exfat", "Beast_Data1"), ("msdos", "fat32", "MY USB")])
def test_validators_custom_label_and_large_image(tmp_path, fake_dist, layout, fs, label):
    img = fresh_image(tmp_path, fake_dist, layout, fs, "3G", "--label", label)
    validate_drive(img, layout, fs, label, tmp_path)


@pytest.mark.parametrize("layout,fs", [("msdos", "exfat"), ("gpt", "fat32"), ("gpt", "ntfs"), ("msdos", "ntfs")])
def test_probe_matches_blkid(installed, layout, fs):
    """fs.probe_fs (used by update and info) reads what blkid reads."""
    img = installed(layout, fs)
    j = info_json(img)
    with ImageTarget(str(img), writable=False) as t:
        for start in (j["data"]["start_lba"], j["esp"]["start_lba"]):
            ours, theirs = probe_fs(t, start * 512), blkid_at(img, start * 512)
            assert ours["TYPE"] == theirs["TYPE"] and ours["UUID"] == theirs["UUID"]
            assert ours.get("LABEL") == theirs.get("LABEL")
            assert ours.get("VERSION", theirs.get("VERSION")) == theirs.get("VERSION")
        assert probe_fs(t, 0) == {}  # the MBR is not a filesystem


def test_volume_id_format():
    assert format_volume_id(0x1A2B3C4D) == "1A2B-3C4D"
    assert format_volume_id(0x0000000F) == "0000-000F"
