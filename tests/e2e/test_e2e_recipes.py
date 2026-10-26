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
def test_debian_installer_dryrun(mode, make_drive, vm_factory):
    """The installer's CD is the ISO file: the whole ISO, the ISO's loop-modules
    udeb and the startup script go into the initrd (hooks/d-i-iso.sh)."""
    path = trees.recipe_path("debian-installer")
    drive, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "debian-installer", str(boot)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert "(loop)/install.amd/vmlinuz" in kernel_of(lin), str(lin)
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert ini.tokens[2] == "(loop)/install.amd/initrd.gz", str(ini)
    assert any(t.startswith("newc:beast-booter/debian.iso:") and t.endswith(path) for t in ini.tokens), str(ini)
    assert any(t.startswith("newc:beast-booter/loop.udeb:(loop)/pool/main/l/linux-signed-amd64/loop-modules-")
               for t in ini.tokens), str(ini)
    # /lib is a symlink in the installer's initrd: the script must not be under lib/
    assert any(t.startswith("newc:usr/lib/debian-installer-startup.d/S45beast-iso:") for t in ini.tokens), str(ini)
    assert not vm.records("error", after=boot.start)


@pytest.mark.parametrize("mode", BOTH)
def test_debian_installer_without_loop_modules(mode, make_drive, vm_factory):
    path = trees.recipe_path("debian-installer-nokernelmods")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "boot-failed", str(err)
    assert not vm.records("dryrun")


@pytest.mark.parametrize("mode", BOTH)
def test_alpine_dryrun(mode, make_drive, vm_factory):
    """Alpine cannot open an ISO file: the ISO goes into the initramfs and
    hooks/alpine-init.sh (rdinit) attaches it to a loop device."""
    path = trees.recipe_path("alpine")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "alpine", str(boot)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert "(loop)/boot/vmlinuz-lts" in kernel_of(lin), str(lin)
    assert lin.has_token("rdinit=/beast-init"), str(lin)
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert ini.tokens[2] == "(loop)/boot/initramfs-lts", str(ini)
    assert any(t.startswith("newc:beast-booter/alpine.iso:") and t.endswith(path) for t in ini.tokens), str(ini)
    assert any(t.startswith("newc:beast-init:") for t in ini.tokens), str(ini)
    assert not vm.records("error", after=boot.start)


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
def test_layered_ubuntu_on_fat32_keeps_loopback(mode, make_drive, vm_factory):
    """The exFAT add-on is for exFAT only: on FAT32 the ISO's initramfs can
    mount the data partition, so its own loopback.cfg runs unchanged."""
    path = trees.recipe_path("ubuntu-layered")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "loopback", str(boot)
    vm.wait_record("dryrun", r"^dryrun configfile (\(loop\))?/boot/grub/loopback\.cfg$", after=boot.start)
    assert not vm.records("fsmod", after=boot.start)


@pytest.mark.parametrize("mode", BOTH)
def test_loopback_runs_iso_config(mode, make_drive, vm_factory):
    path = trees.recipe_path("loopback")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=False)
    rec = vm.wait_record("loopback", prefix="BEAST_FIXTURE", timeout=120)
    assert rec.fields.get("iso_path") == path, str(rec)


WIN_INJECT = ("winpeshl.ini", "beastboot.cmd", "beastboot.txt")


def check_windows_dryrun(vm, mode: str, path: str, win_mode: str):
    """wimboot with linux16/initrd16 on BIOS, linux/initrd on UEFI; boot.wim from the
    ISO; the start-up files (and beastmount.exe in setup mode) from the ESP; the
    ISO path and mode saved to grubenv (tests/e2e/REAL_ISOS.md "Windows")."""
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    assert checks.recipe_of(boot) == "windows", str(boot)
    vm.wait_record("windows", rf"^windows mode={win_mode}$", after=boot.start)
    lx, rd = ("linux16", "initrd16") if mode == "bios" else ("linux", "initrd")
    lin = vm.wait_record("dryrun", rf"^dryrun {lx} ", after=boot.start)
    args = ["index=1"] if win_mode == "pe" else []
    assert any(re.fullmatch(r"\(.+\)/beast-booter/wimboot", v.split()[2]) and v.split()[3:] == args
               for v in lin.variants()), str(lin)
    ini = vm.wait_record("dryrun", rf"^dryrun {rd} ", after=boot.start)
    want = {"setup": [*WIN_INJECT, "beastmount.exe"], "pe": list(WIN_INJECT), "native": []}[win_mode]
    src_rx = re.compile(r"\(.+\)/(beast-booter/winpe/[a-z.]+|grub/grubenv)")

    def initrd_ok(v: str) -> bool:      # one way of re-joining GRUB's wrapped serial lines
        t = v.split()
        if t[2:3] != ["newc:boot.wim:(loop)/sources/boot.wim"]:
            return False
        parts = [w.split(":", 2) for w in t[3:]]
        return [p[1] for p in parts if len(p) == 3] == want and len(parts) == len(want) and \
            all(src_rx.fullmatch(p[2]) for p in parts)
    assert any(initrd_ok(v) for v in ini.variants()), str(ini)
    saves = vm.records("dryrun", after=boot.start)
    saved = [r for r in saves if r.text.startswith("dryrun save_env ")]
    if win_mode == "native":
        assert not saved, [str(r) for r in saved]
    else:
        assert saved and saved[0].text == f"dryrun save_env bb_winpe_iso={path} bb_winpe_mode={win_mode}", \
            [str(r) for r in saved]
    assert not vm.records("error", after=boot.start), [str(r) for r in vm.records("error")]


@pytest.mark.parametrize("mode", BOTH)
def test_windows_setup_dryrun(mode, make_drive, vm_factory):
    path = trees.recipe_path("windows")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    check_windows_dryrun(vm, mode, path, "setup")


@pytest.mark.parametrize("mode", BOTH)
def test_windows_pe_dryrun(mode, make_drive, vm_factory):
    path = trees.recipe_path("windows")
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=path,
                                                  extra='set bb_windows="pe"\nexport bb_windows'))
    check_windows_dryrun(vm_factory(mode, drive.path), mode, path, "pe")


@pytest.mark.parametrize("mode", BOTH)
def test_winpe_iso_native_dryrun(mode, make_drive, vm_factory):
    """A Windows PE / WinRE ISO (no install image) boots as it is: nothing injected."""
    path = trees.recipe_path("winpe")
    _, vm = boot_iso(make_drive, vm_factory, mode, path, dryrun=True)
    check_windows_dryrun(vm, mode, path, "native")


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
