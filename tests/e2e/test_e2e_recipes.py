"""Every ISO boot recipe (ARCHITECTURE §6), driven by bb_autoboot.

With bb_dryrun=1 the menu must report the recipe and the exact kernel, initrd
and kernel parameters it would use (path, ISO label and data-partition UUID
substituted). Without dry run: the loopback fixture's own loopback.cfg runs
with the right iso_path, and on UEFI the efi-chainload fixture's unsigned
payload actually runs (Secure Boot off).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import pytest

from bbe2e import checks, images, isos, trees

pytestmark = pytest.mark.slow

FIXTURES = isos.builder().FIXTURES


@dataclass(frozen=True)
class Linux:
    recipe: str
    kernel: str
    initrd: tuple[str, ...]
    params: tuple[str, ...]  # required cmdline tokens; {path} {label} {uuid} substituted


LINUX = {
    "casper": Linux("casper", "(loop)/casper/vmlinuz", ("(loop)/casper/initrd",),
                    ("boot=casper", "iso-scan/filename={path}")),
    "casper-lz": Linux("casper", "(loop)/casper/vmlinuz", ("(loop)/casper/initrd.lz",),
                       ("boot=casper", "iso-scan/filename={path}")),
    "live-boot": Linux("live-boot", "(loop)/live/vmlinuz", ("(loop)/live/initrd.img",),
                       ("boot=live", "findiso={path}", "components")),
    "archiso": Linux("archiso", "(loop)/arch/boot/x86_64/vmlinuz-linux", ("(loop)/arch/boot/x86_64/initramfs-linux.img",),
                     ("archisobasedir=arch", "archisolabel={label}", "img_dev=/dev/disk/by-uuid/{uuid}", "img_loop={path}")),
    "dracut-live": Linux("dracut-live", "(loop)/images/pxeboot/vmlinuz", ("(loop)/images/pxeboot/initrd.img",),
                         ("root=live:CDLABEL={label}", "rd.live.image", "iso-scan/filename={path}")),
    "anaconda": Linux("anaconda", "(loop)/images/pxeboot/vmlinuz", ("(loop)/images/pxeboot/initrd.img",),
                      ("inst.stage2=hd:UUID={uuid}:{path}",)),
    "suse": Linux("suse", "(loop)/boot/x86_64/loader/linux", ("(loop)/boot/x86_64/loader/initrd",),
                  ("isofrom_device=/dev/disk/by-uuid/{uuid}", "isofrom_system={path}")),
}

BOTH = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
        pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]
UEFI = [pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]


def boot_iso(make_drive, vm_factory, mode: str, path: str, *, dryrun: bool):
    drive = make_drive("main", images.user_config(dryrun=dryrun, autoboot=path))
    return drive, vm_factory(mode, drive.path)


def kernel_of(rec) -> set[str]:
    return {v.split()[2] for v in rec.variants() if len(v.split()) > 2}


def error_code(rec) -> str:
    parts = rec.text.split()
    return parts[1] if len(parts) > 1 else ""


def check_linux_dryrun(vm, drive, fixture: str, path: str):
    spec = LINUX[fixture]
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == spec.recipe, str(boot)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert spec.kernel in kernel_of(lin), f"kernel: {lin}"
    subst = dict(path=path, label=FIXTURES[fixture]["label"], uuid=drive.data_uuid)
    for tmpl in spec.params:
        tok = tmpl.format(**subst)
        if " " in path:
            # A path with spaces cannot be one whitespace-separated token; it may be quoted.
            assert lin.contains(tok) or lin.contains(tok.replace(path, f'"{path}"')) or \
                lin.contains(f'"{tok}"'), f"missing {tok!r} in {lin}"
        else:
            assert lin.has_token(tok), f"missing {tok!r} in {lin}"
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert tuple(ini.tokens[2:]) == spec.initrd, str(ini)
    assert not vm.records("error", after=boot.start), [str(r) for r in vm.records("error")]


@pytest.mark.parametrize("mode", BOTH)
@pytest.mark.parametrize("fixture", sorted(LINUX))
def test_linux_recipe_dryrun(mode, fixture, make_drive, vm_factory):
    path = trees.recipe_path(fixture)
    drive, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    check_linux_dryrun(vm, drive, fixture, path)


@pytest.mark.parametrize("mode", BOTH)
def test_path_with_spaces_dryrun(mode, make_drive, vm_factory):
    drive, vm = boot_iso(make_drive, vm_factory, mode, trees.SPACES_ISO, dryrun=True)
    check_linux_dryrun(vm, drive, "casper", trees.SPACES_ISO)


@pytest.mark.parametrize("mode", BOTH)
def test_loopback_dryrun(mode, make_drive, vm_factory):
    path = trees.recipe_path("loopback")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "loopback", "loopback.cfg must win over /casper (recipe order)"
    vm.wait_record("dryrun", r"^dryrun configfile (\(loop\))?/boot/grub/loopback\.cfg$", after=boot.start)
    assert not [r for r in vm.records("dryrun", after=boot.start) if r.text.startswith("dryrun linux")]


@pytest.mark.parametrize("mode", BOTH)
def test_loopback_runs_iso_config(mode, make_drive, vm_factory):
    path = trees.recipe_path("loopback")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=False)
    rec = vm.wait_record("loopback", prefix="BEAST_FIXTURE", timeout=120)
    assert rec.fields.get("iso_path") == path, str(rec)


@pytest.mark.parametrize("mode", BOTH)
def test_windows_unsupported(mode, make_drive, vm_factory):
    _, vm = boot_iso(make_drive, vm_factory, mode, trees.recipe_path("windows"), dryrun=True)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "unsupported-windows", str(err)
    assert not vm.records("dryrun")


@pytest.mark.parametrize("mode", BOTH)
def test_no_recipe(mode, make_drive, vm_factory):
    _, vm = boot_iso(make_drive, vm_factory, mode, trees.recipe_path("none"), dryrun=True)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "no-recipe", str(err)
    assert not vm.records("dryrun")


@pytest.mark.bios
def test_efi_chainload_is_uefi_only(make_drive, vm_factory):
    _, vm = boot_iso(make_drive, vm_factory, "bios", trees.recipe_path("efi-chainload"), dryrun=True)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "no-recipe", str(err)


@pytest.mark.uefi
@pytest.mark.parametrize("fixture", ["efi-chainload", "efi-chainload-lower"])
def test_efi_chainload_dryrun(fixture, make_drive, vm_factory):
    path = trees.recipe_path(fixture)
    _, vm = boot_iso(make_drive, vm_factory, "uefi", path, dryrun=True)
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "efi-chainload", str(boot)
    vm.wait_record("dryrun", r"(?i)^dryrun chainloader (\(loop\))?/efi/boot/bootx64\.efi$", after=boot.start)


@pytest.mark.uefi
def test_efi_chainload_runs_payload(make_drive, vm_factory):
    _, vm = boot_iso(make_drive, vm_factory, "uefi", trees.recipe_path("efi-chainload"), dryrun=False)
    vm.wait_record("chainload", prefix="BEAST_FIXTURE", timeout=120)


@pytest.mark.uefi
def test_iso_not_found(make_drive, vm_factory):
    _, vm = boot_iso(make_drive, vm_factory, "uefi", "/no/such/image.iso", dryrun=True)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "iso-not-found", str(err)


@pytest.mark.uefi
def test_unbootable_kernel_reports_boot_failed(make_drive, vm_factory):
    """Not a dry run: the fixture kernel is dummy bytes, so `linux` fails; the
    menu must say so (boot-failed) instead of hanging or rebooting."""
    _, vm = boot_iso(make_drive, vm_factory, "uefi", trees.recipe_path("casper"), dryrun=False)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "boot-failed", str(err)
