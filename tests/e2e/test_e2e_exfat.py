"""exFAT data partition (the installer default). Populating exFAT needs a
kernel mount, done through udisks; these tests skip when udisksctl cannot set
up a loop device (e.g. inside a sandbox without the system D-Bus)."""

from __future__ import annotations

import pytest

from bbe2e import checks, images, trees

pytestmark = [pytest.mark.exfat, pytest.mark.slow]

MODES = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
         pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]


@pytest.mark.parametrize("mode", MODES)
def test_exfat_ready_and_listing(mode, udisks_ok, make_drive, vm_factory):
    drive = make_drive("exfat", images.user_config())
    assert images.volume_id(drive.path, drive.data_offset)[0] == "exfat"
    vm = vm_factory(mode, drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform=checks.PLATFORM[mode], sb=0, fs="exfat",
                       **checks.expected_devs("msdos"))
    dirs, isos = checks.listing(vm, "/")
    assert (dirs, isos) == (["/linux"], ["/top.iso"])


@pytest.mark.uefi
def test_exfat_casper_dryrun(udisks_ok, make_drive, vm_factory):
    path = trees.BROWSE_NESTED_PATH
    drive = make_drive("exfat", images.user_config(dryrun=True, autoboot=path))
    vm = vm_factory("uefi", drive.path)
    boot = vm.wait_record("boot", timeout=120)
    assert boot.text.startswith(f"boot {path} ") and checks.recipe_of(boot) == "casper", str(boot)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert lin.has_token("boot=casper") and lin.has_token(f"iso-scan/filename={path}"), str(lin)
