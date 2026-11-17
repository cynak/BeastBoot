"""The menu is inside the signed GRUB image (docs/ARCHITECTURE.md section 5,
docs/SECURITY_REVIEW-0.4.0.md D3).

Under UEFI, with Secure Boot on or off, grubx64.efi runs grub.cfg,
grub/beast/*.cfg, the hooks, the theme and the fonts from its own memdisk
(what the beast-boot key signs). The copies on the ESP are for legacy BIOS.

* every menu file on the ESP changed (scripts, version.cfg, hooks, theme,
  fonts), and a grub.cfg put next to grubx64.efi (where Ubuntu's GRUB looks
  first, $fw_path): no effect under UEFI; legacy BIOS runs exactly those
  files, which also shows that the changes in this test are real ones
* files written per drive or at run time are data: a hostile device.env,
  grubenv or config.env cannot run a command or set a variable outside its
  list of names, and a value of the wrong form is dropped; a device.cfg (the
  GRUB script that drives had before 0.5.0) is not read at all
* the two Windows PE start-up scripts (winpeshl.ini, beastboot.cmd): under UEFI
  the menu hands wimboot the copies inside the signed image, changed copies
  on the ESP are not used
* debug and pager (GRUB's own debug output) can be set in config.env, on UEFI
  with and without Secure Boot
* /beast-booter/config.cfg (GRUB script) and bb_theme (a theme on the data
  partition) are not used on UEFI without Secure Boot either (with it:
  test_e2e_secureboot.py); legacy BIOS still runs config.cfg
"""

from __future__ import annotations

import re

import pytest

from bbe2e import beastnet as bn
from bbe2e import checks, images, trees

pytestmark = pytest.mark.slow

UEFI = [pytest.param("uefi", marks=pytest.mark.uefi, id="uefi"),
        pytest.param("uefi-sb", marks=pytest.mark.secureboot, id="uefi-sb")]
ALL = [pytest.param("bios", marks=pytest.mark.bios, id="bios"), *UEFI]

MARK = "BEAST_TAMPER"
FAKE_VERSION = "6.6.6"
ALPINE = trees.recipe_path("alpine")  # its recipe passes hooks/alpine-init.sh to the kernel
ARCHISO = trees.recipe_path("archiso")  # its recipe puts bb_data_uuid_linux on the kernel command line
EVIL_KARG = "init=/bin/evil"


def boot(request, vm_factory, mode: str, drive):
    kw = {}
    if mode == "uefi-sb":
        request.getfixturevalue("secureboot_ok")
        kw["mok_certs"] = [request.getfixturevalue("mok_cert")]
    return vm_factory(mode, drive.path, **kw)


def esp_menu_files(esp: images.FatWriter) -> list[str]:
    """Every file under the ESP's /grub/ that is part of the menu (not the BIOS
    modules, and not the data files grubenv and device.env)."""
    out = []
    for line in esp.listing("/grub"):
        path = line[2:] if line.startswith("::") else line
        if path.endswith("/") or "/i386-pc/" in path or path.rsplit("/", 1)[1] in ("grubenv", "device.env"):
            continue
        out.append(path)
    return out


def tamper_scripts(drive: images.Drive) -> list[str]:
    """What someone who can write the ESP could do to the menu scripts: every
    .cfg under /grub/ gets a command that prints MARK and its own path, lib.cfg
    a replaced function, version.cfg another version, every hook other contents.
    The menu still works when these files are run (legacy BIOS). Returns the
    paths changed."""
    esp = bn.esp_writer(drive)
    changed = []
    for path in esp_menu_files(esp):
        if path.endswith(".cfg"):
            text = esp.read(path).decode()
            if path.endswith("/lib.cfg"):
                # sourced before the serial console is on: replace a function the menu calls later
                text += f'\nfunction bb_dbg_nl {{\n  echo "{MARK} {path}"\n}}\n'
            else:
                text += f'\necho "{MARK} {path}"\n'
            if path.endswith("/version.cfg"):
                text += f'set bb_version="{FAKE_VERSION}"\n'
            esp.put(path, text)
        elif "/hooks/" in path:
            esp.put(path, f"#!/bin/sh\necho {MARK} {path}\n")
        else:
            continue
        changed.append(path)
    # Ubuntu's GRUB looks for grub.cfg in the directory of the EFI binary before $prefix
    # (build/early-efi.cfg). If this file were started, the menu would never appear.
    esp.put("/EFI/BOOT/grub.cfg", f'echo "{MARK} /EFI/BOOT/grub.cfg"\nsleep 600\n')
    changed.append("/EFI/BOOT/grub.cfg")
    return changed


def break_theme_and_fonts(drive: images.Drive) -> list[str]:
    """Replace the theme files, images and fonts on the ESP with junk."""
    esp = bn.esp_writer(drive)
    changed = [p for p in esp_menu_files(esp) if "/themes/" in p and not p.endswith(".cfg") or "/fonts/" in p]
    for path in changed:
        esp.put(path, b"not what GRUB expects here\n" * 8)
    return changed


def hook_source(vm, after: int) -> str:
    """The GRUB path the alpine recipe takes its hook from (dry run)."""
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=after)
    src = [t.split(":", 2)[2] for t in ini.tokens if t.startswith("newc:beast-init:")]
    assert len(src) == 1, str(ini)
    return src[0]


# ---------------------------------------------------------------------------
# Changed menu files on the ESP
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", UEFI)
def test_changed_esp_menu_files_have_no_effect_on_uefi(request, mode, make_drive, vm_factory, dist_version):
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=ALPINE))
    scripts = tamper_scripts(drive)
    junk = break_theme_and_fonts(drive)
    names = {p.rsplit("/", 1)[1] for p in scripts}
    assert {"grub.cfg", "main.cfg", "lib.cfg", "level.cfg", "browse.cfg", "version.cfg", "console.cfg",
            "alpine-init.sh", "d-i-iso.sh", "initramfs-tools.sh"} <= names, scripts
    assert any("/themes/beast/theme-efi" in p for p in junk) and any(p.endswith(".png") for p in junk), junk
    assert sum(p.endswith(".pf2") for p in junk) >= 5, junk

    vm = boot(request, vm_factory, mode, drive)
    ready = checks.wait_ready(vm, timeout=120)
    checks.check_ready(ready, platform="efi", sb=checks.SB[mode], fs="fat32", version=dist_version,
                       **checks.expected_devs("msdos"))
    # the hook handed to the kernel is the one inside the signed image
    rec = vm.wait_record("boot", rf"^boot {re.escape(ALPINE)} recipe=alpine", timeout=120)
    assert hook_source(vm, rec.start) == "(memdisk)/grub/beast/hooks/alpine-init.sh"
    # the built-in theme and fonts are used although the ESP's are junk
    disp = vm.wait_record("display", timeout=60, after=rec.start)
    assert disp.fields.get("gfx") == "1", str(disp)
    # a folder menu (level.cfg, browse.cfg, nav-*.cfg) works and is the built-in one
    vm.wait_record("dir", r"^dir /$", timeout=60, after=rec.start)
    menu = vm.wait_menu(timeout=60)
    mark = vm.mark()
    vm.keys(*["down"] * menu.entries.index("recipes/"), "enter")
    vm.wait_record("dir", r"^dir /recipes/?$", timeout=60, after=mark)
    vm.wait_menu(first_entry="..", timeout=60)
    vm.expect_absent(MARK, within=2)
    assert not vm.records("error"), [str(r) for r in vm.records("error")]


@pytest.mark.bios
def test_legacy_bios_runs_the_menu_files_on_the_esp(make_drive, vm_factory, dist_version):
    """The other half: legacy BIOS has no signed chain and reads the menu from
    the ESP, so the same changes do take effect there."""
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=ALPINE))
    vm = vm_factory("bios", drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="pc", sb=0, version=dist_version)
    rec = vm.wait_record("boot", rf"^boot {re.escape(ALPINE)} recipe=alpine", timeout=120)
    assert hook_source(vm, rec.start) == "(hd0,msdos2)/grub/beast/hooks/alpine-init.sh"
    assert vm.wait_record("display", timeout=60, after=rec.start).fields.get("gfx") == "1"
    vm.stop()
    assert MARK not in vm.text()

    scripts = tamper_scripts(drive)
    vm = vm_factory("bios", drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="pc", sb=0, version=FAKE_VERSION)
    vm.wait_record("dir", r"^dir /$", timeout=120)
    vm.wait_menu(timeout=60)
    text = vm.text()
    for path in scripts:
        # (version.cfg runs before the serial console is on: FAKE_VERSION above shows that it ran)
        # (and /EFI/BOOT/grub.cfg means nothing to the BIOS GRUB)
        if path.startswith("/grub/") and path.rsplit("/", 1)[1] in ("grub.cfg", "main.cfg", "lib.cfg", "console.cfg"):
            assert f"{MARK} {path}" in text, f"{path} on the ESP was not run under legacy BIOS"
    vm.stop()

    break_theme_and_fonts(drive)
    vm = vm_factory("bios", drive.path)
    checks.wait_ready(vm, timeout=120)
    assert vm.wait_record("display", timeout=120).fields.get("gfx") == "0", "junk fonts on the ESP: text menu"


# ---------------------------------------------------------------------------
# Data files from the drive: device.env, grubenv, config.env
# ---------------------------------------------------------------------------

WINDOWS = trees.recipe_path("windows")
WINPE = "/beast-booter/winpe"
WINPE_SCRIPTS = ("winpeshl.ini", "beastboot.cmd")


def injected(vm, mode: str, after: int) -> dict[str, str]:
    """name in Windows PE -> GRUB path, from the dry run's initrd line."""
    ini = vm.wait_record("dryrun", r"^dryrun initrd(16)? ", after=after)
    best: dict[str, str] = {}
    for v in ini.variants():  # ways of re-joining GRUB's wrapped serial lines
        parts = dict(w.split(":", 2)[1:] for w in v.split()[2:] if w.count(":") >= 2)
        if len(parts) > len(best):
            best = parts
    return best


@pytest.mark.parametrize("mode", ALL)
def test_winpe_start_up_scripts_on_the_esp(request, mode, make_drive, vm_factory, dist_dir):
    """winpeshl.ini and beastboot.cmd on the ESP replaced: under UEFI the menu
    takes them from the memdisk inside the signed grubx64.efi (and the files it
    names there are the ones of the build: build/verify-dist.sh finds the memdisk
    made from dist/ in the image); legacy BIOS takes the ESP's. Dry run: this
    shows which files GRUB would hand to wimboot, not their bytes in Windows PE."""
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=WINDOWS))
    esp = bn.esp_writer(drive)
    for name in WINPE_SCRIPTS:
        assert esp.read(f"{WINPE}/{name}") == (dist_dir / "esp" / WINPE.lstrip("/") / name).read_bytes()
        esp.put(f"{WINPE}/{name}", f"rem {MARK} {name}\r\n" * 40)
    vm = boot(request, vm_factory, mode, drive)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform=checks.PLATFORM[mode], sb=checks.SB[mode])
    rec = vm.wait_record("boot", rf"^boot {re.escape(WINDOWS)} recipe=windows", timeout=120)
    got = injected(vm, mode, rec.start)
    scripts = "(hd0,msdos2)/beast-booter/winpe" if mode == "bios" else "(memdisk)/beast-booter/winpe"
    assert got == {
        "boot.wim": "(loop)/sources/boot.wim",
        "winpeshl.ini": f"{scripts}/winpeshl.ini",
        "beastboot.cmd": f"{scripts}/beastboot.cmd",
        "beastboot.txt": "(hd0,msdos2)/grub/grubenv",                       # data: which ISO to attach
        "beastmount.exe": "(hd0,msdos2)/beast-booter/winpe/beastmount.exe",  # still from the ESP
    }, got


@pytest.mark.secureboot
def test_winpe_start_up_scripts_reach_wimboot_from_the_signed_image(request, make_drive, vm_factory, dist_dir):
    """A real start (Secure Boot on) with changed scripts on the ESP: the signed
    wimboot starts and is given files of the sizes the build's scripts have,
    not of the changed ones on the ESP (wimboot prints every file it receives)."""
    drive = make_drive("main", images.user_config(autoboot=WINDOWS))
    esp = bn.esp_writer(drive)
    sizes = {}
    for name in WINPE_SCRIPTS:
        sizes[name] = len((dist_dir / "esp" / WINPE.lstrip("/") / name).read_bytes())
        esp.put(f"{WINPE}/{name}", f"rem {MARK} {name}\r\n" * 40 + "rem padding\r\n" * (3 + len(name)))
        assert len(esp.read(f"{WINPE}/{name}")) != sizes[name]
    vm = boot(request, vm_factory, "uefi-sb", drive)
    checks.wait_ready(vm, timeout=120)
    rec = vm.wait_record("boot", rf"^boot {re.escape(WINDOWS)} recipe=windows", timeout=120)
    vm.wait_for(r"wimboot v[0-9][^ ]* -- Windows Imaging Format bootloader", timeout=120, after=rec.end)
    seen = {}
    for name in WINPE_SCRIPTS:
        m = vm.wait_for(rf"Using {re.escape(name)} via \S+ len (0x[0-9a-f]+)\s*\n", timeout=60, after=rec.end)
        seen[name] = int(m.group(1), 16)
    assert seen == sizes, (seen, sizes)


@pytest.mark.parametrize("mode", UEFI)
def test_grub_debug_and_pager_from_config_env(request, mode, make_drive, vm_factory):
    """debug and pager in config.env apply on UEFI, with Secure Boot on too:
    GRUB prints its debug messages (file:line:facility: text) and pauses with
    --MORE-- when a screen is full."""
    drive = make_drive("browse", None, images.env_block({"debug": "all", "pager": "1"}))
    vm = boot(request, vm_factory, mode, drive)
    vm.wait_for(r"[a-z0-9_/]+\.c:\d+:[a-z0-9_]+: ", timeout=120)
    vm.wait_for(r"--MORE--", timeout=120)
    assert "config.env: debug has a value" not in vm.text() and "config.env: pager has a value" not in vm.text()


# Names no file on the drive may set, with values that would show.
NOT_SETTABLE = {
    "bb_sb": "0", "lockdown": "n", "check_signatures": "no", "prefix": "(hd0,msdos1)/evil", "root": "hd0,msdos1",
    "cmdpath": "(hd0,msdos1)/evil", "bb_cfg": "(hd0,msdos1)/evil", "bb_esp": "hd0,msdos1", "bb_data": "hd0,msdos2",
    "bb_platform": "pc", "bb_version": FAKE_VERSION, "theme": "(hd0,msdos1)/evil/theme.txt",
    "bb_p1": "hd0,msdos2",
}


def check_untouched(vm, mode: str, dist_version: str, iso: str = ALPINE):
    """The menu started as itself: right version, platform, Secure Boot state
    and devices; the ISO in bb_autoboot is started (dry run) with nothing
    hostile on its kernel command line and, for the alpine fixture, with the
    hook from where it must come. Returns the `dryrun linux` record."""
    ready = checks.wait_ready(vm, timeout=120)
    checks.check_ready(ready, platform=checks.PLATFORM[mode], sb=checks.SB[mode], fs="fat32", version=dist_version,
                       **checks.expected_devs("msdos"))
    rec = vm.wait_record("boot", rf"^boot {re.escape(iso)} recipe=", timeout=120)
    if iso == ALPINE:
        want = "(memdisk)" if mode != "bios" else "(hd0,msdos2)"
        assert hook_source(vm, rec.start) == f"{want}/grub/beast/hooks/alpine-init.sh"
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=rec.start)
    assert not lin.contains(EVIL_KARG) and not lin.contains("evil"), str(lin)
    vm.wait_record("dir", r"^dir /$", timeout=60, after=rec.start)
    vm.expect_absent(MARK, within=2)
    return lin


@pytest.mark.parametrize("mode", ALL)
def test_hostile_device_env(request, mode, make_drive, vm_factory, dist_version):
    """device.env with names outside its list and values of the wrong form: the
    names are not set, the bad values are dropped (the data partition is then
    found by position and its UUID read from it), bb_serial=1 (a valid value)
    still applies."""
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=ARCHISO))
    good = bn.read_grubenv(drive, "/grub/beast/device.env")
    assert good["bb_serial"] == "1" and good["bb_data_uuid_linux"] == drive.data_uuid
    bn.write_grubenv(drive, {
        **NOT_SETTABLE, "bb_kargs": EVIL_KARG, "bb_autoboot": "/evil.iso", "bb_debug": "0", "bb_dryrun": "0",
        "bb_install_id": good["bb_install_id"], "bb_serial": "1",
        "bb_layout": "gpt; halt", "bb_data_fs": "ext4", "bb_data_uuid": "0000-0000 --set=root",
        "bb_data_uuid_linux": f"x {EVIL_KARG}", "bb_data_label": 'a"b',
    }, "/grub/beast/device.env")
    vm = boot(request, vm_factory, mode, drive)
    lin = check_untouched(vm, mode, dist_version, ARCHISO)
    assert lin.has_token(f"img_dev=/dev/disk/by-uuid/{drive.data_uuid}"), str(lin)
    if mode != "bios":
        # device.env is read before config.env switches the debug lines on, and under BIOS before
        # the serial console is on; under UEFI the firmware console shows the menu's notices
        bad = set(re.findall(r"device\.env: (bb_\w+) has a value", vm.text()))
        assert bad == {"bb_layout", "bb_data_fs", "bb_data_uuid", "bb_data_uuid_linux", "bb_data_label"}, bad


@pytest.mark.parametrize("mode", ALL)
def test_device_cfg_script_is_not_run(request, mode, make_drive, vm_factory, dist_version):
    """GRUB script where the menu expects data: a device.cfg as drives had before
    0.5.0, and a device.env that is script instead of an environment block.
    Neither is run. (bb_serial then comes from config.env, so the menu shows.)"""
    script = f'set bb_serial="1"\nset bb_version="{FAKE_VERSION}"\necho "{MARK} device"\n'
    cfg = images.user_config(dryrun=True, autoboot=ALPINE, extra='set bb_serial="1"\nexport bb_serial')
    drive = make_drive("main", cfg)
    esp = bn.esp_writer(drive)
    esp.put("/grub/beast/device.cfg", script)
    esp.put("/grub/beast/device.env", script)
    vm = boot(request, vm_factory, mode, drive)
    check_untouched(vm, mode, dist_version)
    assert not [r for r in vm.records("error") if "device-env" in r.text]


@pytest.mark.parametrize("mode", ALL)
def test_hostile_grubenv(request, mode, make_drive, vm_factory, dist_version):
    """grub/grubenv with names outside its list (the menu reads bb_oneshot only)
    and a one-shot path that is not a path: nothing is set, the entry is refused
    and cleared."""
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=ALPINE))
    bn.write_grubenv(drive, {**NOT_SETTABLE, "bb_kargs": EVIL_KARG, "bb_debug": "0", "bb_dryrun": "0",
                             "bb_oneshot": '/evil".iso'})
    vm = boot(request, vm_factory, mode, drive)
    check_untouched(vm, mode, dist_version)
    assert [r.text for r in vm.records("error") if "oneshot" in r.text] == ["error oneshot-bad-path"]
    assert not vm.records("oneshot")
    vm.stop()
    assert bn.read_grubenv(drive).get("bb_oneshot", "") == "", "the refused one-shot entry must be cleared"


@pytest.mark.parametrize("mode", UEFI)
def test_hostile_config_env(request, mode, make_drive, vm_factory, dist_version):
    """config.env with names outside its list and values of the wrong form. (The
    harness derives config.env from the `set` lines of this text; on UEFI the
    menu does not read config.cfg itself, which also holds a command.)"""
    extra = "\n".join(f'set {k}="{v}"' for k, v in NOT_SETTABLE.items())
    extra += (f'\nset bb_data_uuid_linux="x {EVIL_KARG}"\nset bb_beastnet_script="/plan.json {EVIL_KARG}"'
              '\nset bb_gfxmode="1x1 evil"\nset bb_windows="evil"\nset timeout="evil"'
              '\nset debug="all; halt"\nset pager="2"'
              f'\necho "{MARK} config.cfg"')
    cfg = images.user_config(dryrun=True, autoboot=ALPINE, extra=extra)
    env_block = images.config_env(cfg)
    assert all(f"\n{k}=".encode() in env_block for k in ("bb_sb", "prefix", "bb_cfg", "bb_data_uuid_linux")), env_block
    drive = make_drive("main", cfg)
    vm = boot(request, vm_factory, mode, drive)
    check_untouched(vm, mode, dist_version)
    assert vm.records("config-cfg-ignored"), "the menu must say that config.cfg is not read on UEFI"
    errs = [r for r in vm.records("error") if r.text.startswith("error config-env-bad-value ")]
    # (GRUB acts on `debug` from the moment load_env set it: while the menu checks that one value,
    # its debug lines repeat the record, with a comma after the name)
    bad = {r.text.split()[2].rstrip(",") for r in errs}
    assert bad == {"bb_beastnet_script", "bb_gfxmode", "bb_windows", "timeout", "debug", "pager"}, bad
    # the refused `debug` value is gone as soon as it was checked: `pager` is checked next
    text = vm.text()
    assert not re.search(r"[a-z0-9_/]+\.c:\d+:[a-z0-9_]+: ", text[text.rfind("config-env-bad-value pager"):]), \
        "GRUB's debug output stayed on after the refused `debug` value was dropped"


@pytest.mark.parametrize("mode", UEFI)
def test_config_env_that_is_script_is_not_run(request, mode, make_drive, vm_factory):
    drive = make_drive("browse", None, f'set bb_debug="1"\necho "{MARK} config.env"\n')
    vm = boot(request, vm_factory, mode, drive)
    vm.wait_for(r"config\.env is not a GRUB environment block; it is ignored", timeout=120)
    vm.wait_menu(timeout=60)
    vm.expect_absent(MARK, within=2)
    assert not vm.records(), "bb_debug from a file that is not an environment block must not apply"


# ---------------------------------------------------------------------------
# config.cfg and bb_theme without Secure Boot
# ---------------------------------------------------------------------------

@pytest.mark.uefi
def test_uefi_without_secure_boot_ignores_config_cfg_and_bb_theme(make_drive, vm_factory):
    """One UEFI code path: what test_e2e_secureboot.py checks with Secure Boot on
    also holds with it off. config.env still applies (debug, bb_theme is seen)."""
    theme = "/beast-booter/mytheme/theme.txt"
    cfg = images.user_config(extra=f'set bb_theme="{theme}"\nexport bb_theme\necho "{MARK} config.cfg"')
    drive = make_drive("browse", cfg)
    with drive.data_writer() as w:
        w.mkdir("/beast-booter/mytheme")
        w.put(theme, "not a theme\n")
    vm = vm_factory("uefi", drive.path)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="efi", sb=0)
    assert vm.records("config-cfg-ignored") and vm.records("theme-ignored")
    assert vm.wait_record("display", timeout=60).fields.get("gfx") == "1"
    menu = vm.wait_menu(timeout=60)
    assert "Settings ignored on UEFI - help" in menu.entries, menu.entries
    vm.expect_absent(MARK, within=2)


@pytest.mark.bios
def test_legacy_bios_still_runs_config_cfg(make_drive, vm_factory):
    cfg = images.user_config(extra=f'echo "{MARK} config.cfg"')
    vm = vm_factory("bios", make_drive("browse", cfg).path)
    checks.wait_ready(vm, timeout=120)
    vm.wait_menu(timeout=60)
    assert f"{MARK} config.cfg" in vm.text()
    assert not vm.records("config-cfg-ignored")
    assert "Settings ignored on UEFI - help" not in vm.menu().entries
