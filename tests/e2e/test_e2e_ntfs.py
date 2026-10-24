"""NTFS data partition (installer --fs ntfs): boots and lists. Populated through
udisks like exFAT; skips when udisksctl cannot set up a loop device."""

from __future__ import annotations

import pytest

from bbe2e import checks, images

pytestmark = [pytest.mark.ntfs, pytest.mark.slow]

MODES = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
         pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]


@pytest.mark.parametrize("mode", MODES)
def test_ntfs_ready_and_listing(mode, udisks_ok, make_drive, vm_factory):
    drive = make_drive("ntfs", images.user_config())
    assert images.volume_id(drive.path, drive.data_offset)[0] == "ntfs"
    vm = vm_factory(mode, drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform=checks.PLATFORM[mode], sb=0, fs="ntfs",
                       **checks.expected_devs("msdos"))
    dirs, isos = checks.listing(vm, "/")
    assert "/$Extend" not in dirs, (
        "the NTFS system directory $Extend is listed; NTFS metadata must be hidden "
        "(layout.DATA_HIDDEN_DIRS has no entry for it)")
    assert (dirs, isos) == (["/linux"], ["/top.iso"])
