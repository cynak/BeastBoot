"""exFAT data partition (the installer default). Populating exFAT needs a
kernel mount, done through udisks; these tests skip when udisksctl cannot set
up a loop device (e.g. inside a sandbox without the system D-Bus)."""

from __future__ import annotations

import re

import pytest

from bbe2e import checks, images, isos, trees

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
    # A casper ISO without a squashfs: nothing to take the exfat module from.
    fsmod = vm.wait_record("fsmod", after=boot.start)
    assert fsmod.args == "none no-squashfs", str(fsmod)
    ird = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert ird.matches(r"^dryrun initrd \(loop\)/casper/initrd$"), str(ird)


KVER = isos.builder().FIXTURE_KVER
ADDON_KO = f"(bbsq)/usr/lib/modules/{KVER}/kernel/fs/exfat/exfat.ko.zst"
HOOK_RX = r"^newc:conf/conf\.d/zz-beastbooter\.conf:\(.+\)/grub/beast/hooks/initramfs-tools\.sh$"


@pytest.mark.parametrize("mode", MODES)
def test_exfat_fs_addon_dryrun(mode, udisks_ok, make_drive, vm_factory):
    """Ubuntu 24.04+ style ISO (loopback.cfg, casper, modules in a squashfs) on
    exFAT: booted with the casper recipe, and the ISO's own exfat module plus
    the hook script are added to its initrd (bb_addon_prepare)."""
    path = trees.EXFAT_ADDON_PATH
    drive = make_drive("exfat", images.user_config(dryrun=True, autoboot=path))
    vm = vm_factory(mode, drive.path)
    boot = vm.wait_record("boot", timeout=120)
    assert boot.text.startswith(f"boot {path} ") and checks.recipe_of(boot) == "casper", str(boot)
    fsmod = vm.wait_record("fsmod", after=boot.start)
    assert fsmod.has_token("exfat") and fsmod.has_token(ADDON_KO), str(fsmod)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert lin.has_token("(loop)/casper/vmlinuz") and lin.has_token("boot=casper"), str(lin)
    assert lin.has_token(f"iso-scan/filename={path}"), str(lin)
    ird = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert ird.has_token("(loop)/casper/initrd"), str(ird)
    assert ird.has_token(f"newc:beast-boot/modules/exfat.ko.zst:{ADDON_KO}"), str(ird)
    assert any(re.match(HOOK_RX, t) for v in ird.variants() for t in v.split()), str(ird)


@pytest.mark.uefi
def test_exfat_fs_addon_disabled(udisks_ok, make_drive, vm_factory):
    """bb_fs_addon=0: the ISO keeps its own loopback.cfg and nothing is added."""
    path = trees.EXFAT_ADDON_PATH
    config = images.user_config(dryrun=True, autoboot=path, extra='set bb_fs_addon="0"\nexport bb_fs_addon\n')
    drive = make_drive("exfat", config)
    vm = vm_factory("uefi", drive.path)
    boot = vm.wait_record("boot", timeout=120)
    assert checks.recipe_of(boot) == "loopback", str(boot)
    fsmod = vm.wait_record("fsmod", after=boot.start)
    assert fsmod.args == "none disabled", str(fsmod)
    vm.wait_record("dryrun", r"^dryrun configfile (\(loop\))?/boot/grub/loopback\.cfg$", after=boot.start)
