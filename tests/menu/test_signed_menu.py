"""The menu inside the signed GRUB image (docs/ARCHITECTURE.md section 5,
docs/SECURITY_REVIEW-0.4.0.md D3).

Under UEFI everything GRUB runs or parses as menu (grub.cfg, grub/beast/*.cfg,
the hooks, the theme, the fonts, version.cfg) comes from the memdisk of
grubx64.efi, which the beast-boot key signs: its embedded early config sets
$prefix to (memdisk)/grub and removes Ubuntu GRUB's other way to a first
config (fw_path). What
the drive still provides is data: GRUB environment blocks read with load_env
and a list of names, every value checked. Static checks of the menu sources
and of build/build.sh; tests/e2e/test_e2e_signed_menu.py checks the behaviour
in GRUB (changed files on the ESP have no effect under UEFI).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GRUB = ROOT / "grub"
LIB = GRUB / "beast" / "lib.cfg"
MAIN = GRUB / "beast" / "main.cfg"
BUILD_SH = ROOT / "build" / "build.sh"
EARLY_EFI = ROOT / "build" / "early-efi.cfg"

DEVICE_NAMES = ["bb_install_id", "bb_layout", "bb_data_fs", "bb_data_uuid", "bb_data_uuid_linux", "bb_data_label",
                "bb_serial"]
# Never settable from a file on the drive: where files come from, whether they are checked.
FORBIDDEN = {"bb_sb", "bb_cfg", "bb_esp", "bb_boot_dev", "bb_data", "bb_p1", "bb_platform", "prefix", "root", "fw_path",
             "check_signatures", "lockdown", "theme", "bb_theme", "bb_kargs", "bb_autoboot", "bb_oneshot",
             "bb_version", "bb_build_id", "bb_path", "bb_debug", "bb_dryrun", "timeout", "default"}


def code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def all_cfg() -> dict[Path, str]:
    return {p: code(p.read_text()) for p in sorted(GRUB.rglob("*.cfg"))}


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def test_script_is_run_only_from_the_prefix():
    """Every source / configfile / normal FILE in the menu names a file under
    $bb_cfg ($prefix/beast) or the built-in theme's directory, which under UEFI
    are in the memdisk. The two exceptions: config.cfg, in the legacy BIOS branch
    (tests/menu/test_user_config.py), and the loopback.cfg of an ISO the user
    chose, which is that ISO's own boot menu (docs/ARCHITECTURE.md section 5)."""
    seen = []
    for path, text in all_cfg().items():
        for m in re.finditer(r'^\s*(source|configfile|normal)[ \t]+("?)([^\n"]+)\2\s*$', text, re.M):
            seen.append((path.relative_to(GRUB).as_posix(), m.group(1), m.group(3)))
    elsewhere = sorted(s for s in seen if not s[2].startswith(("$bb_cfg/", "$bb_g_dir/")))
    assert elsewhere == [
        ("beast/lib.cfg", "configfile", "/boot/grub/loopback.cfg"),
        ("beast/main.cfg", "source", "($bb_data)/beast-booter/config.cfg"),
    ], elsewhere
    assert len(seen) > 8, seen


def test_bb_cfg_and_the_theme_directory_are_the_prefix():
    grub_cfg = code((GRUB / "grub.cfg").read_text())
    assert re.findall(r"set bb_cfg=\S+", "\n".join(all_cfg().values())) == ['set bb_cfg="$prefix/beast"']
    assert 'source "$bb_cfg/main.cfg"' in grub_cfg and "device" not in grub_cfg
    body = code(function_body(LIB.read_text(), "bb_gfx_init"))
    assert re.findall(r"set bb_g_dir=\S+", body) == ['set bb_g_dir="$prefix/themes/beast"']
    # no menu file sets the variables that say where GRUB's own files are
    for path, text in all_cfg().items():
        assert not re.search(r"^\s*set (prefix|fw_path|bb_boot_dev)=", text, re.M), path


def test_early_config_makes_the_memdisk_menu_the_only_one():
    """build/early-efi.cfg, exactly: keep the boot device for the menu, drop
    fw_path (Ubuntu's GRUB starts $fw_path/grub.cfg, i.e. ESP:/EFI/BOOT/grub.cfg,
    before $prefix/grub.cfg), then point root and prefix into the memdisk."""
    assert code(EARLY_EFI.read_text()).strip().splitlines() == [
        'set bb_boot_dev="$root"',
        "unset fw_path",
        "set root=memdisk",
        'set prefix="(memdisk)/grub"',
    ]


def test_uefi_takes_the_esp_from_the_boot_device_not_from_the_prefix():
    """Under UEFI $prefix is the memdisk, so the ESP (grubenv, device.env, the
    helper, wimboot) is the device grubx64.efi was started from."""
    text = code(MAIN.read_text())
    assert re.search(r'^set bb_esp=""\nif \[ "\$bb_platform" = "efi" \]; then\n  set bb_esp="\$bb_boot_dev"\nelse\n',
                     text, re.M), "main.cfg must take bb_esp from bb_boot_dev under UEFI"
    everything = "\n".join(all_cfg().values())
    assert everything.count("bb_boot_dev") == 1 and "fw_path" not in everything and "cmdpath" not in everything


def test_hooks_come_from_the_prefix():
    text = code(LIB.read_text())
    hooks = re.findall(r"newc:[^:\s\"]+:(\S*hooks/[a-z-]+\.sh)", text)
    assert len(hooks) == 3 and all(h.startswith("$bb_cfg/hooks/") for h in hooks), hooks
    assert sorted(h.rsplit("/", 1)[1] for h in hooks) == sorted(p.name for p in (GRUB / "beast" / "hooks").iterdir())


def test_winpe_start_up_scripts_come_from_the_memdisk_on_uefi():
    """winpeshl.ini and beastboot.cmd run as SYSTEM in Windows PE: UEFI injects the
    copies inside the signed image, legacy BIOS the ESP's. beastmount.exe: the ESP's."""
    body = code(function_body(LIB.read_text(), "bb_win_boot"))
    assert ('set bb_w_pe="$bb_w/winpe"\n  if [ "$bb_platform" = "efi" ]; then\n'
            '    set bb_w_pe="(memdisk)/beast-booter/winpe"\n  fi\n') in body
    inj = dict(re.findall(r"newc:([a-z.]+):(\S+?)[\" ]", body))
    del inj["boot.wim"]
    assert inj == {"winpeshl.ini": "$bb_w_pe/winpeshl.ini", "beastboot.cmd": "$bb_w_pe/beastboot.cmd",
                   "beastboot.txt": "($bb_esp)/grub/grubenv", "beastmount.exe": "$bb_w/winpe/beastmount.exe"}, inj
    sh = code(BUILD_SH.read_text())
    assert 'memdisk_list+=("beast-booter/winpe/$f=esp/beast-booter/winpe/$f")' in sh
    assert "for f in winpeshl.ini beastboot.cmd; do" in sh[sh.index('EFI_PREFIX="/grub"'):sh.index("efi_image() {")]


def test_theme_and_fonts_are_never_taken_from_the_drive_on_uefi():
    body = code(function_body(LIB.read_text(), "bb_gfx_init"))
    themes = re.findall(r'set bb_g_theme="([^"]*)"', body)
    assert [t for t in themes if not t.startswith("$bb_g_dir/")] == ["($bb_data)$bb_theme"]
    # fonts: by name from (memdisk)/fonts on UEFI; a path only in the legacy BIOS branches
    assert 'if [ "$bb_platform" = "efi" ]; then\n    set bb_g_fdir="(memdisk)/fonts"\n  else\n' in body
    loads = re.findall(r"\bloadfont ([^\s;]+)", body)
    assert sorted(loads) == ['"$bb_g_fdir/unicode.pf2"', '"$bb_g_font"', "unicode"], loads
    assert re.search(r'if \[ "\$bb_platform" = "efi" \]; then\n      set bb_g_font="\$bb_g_f"\n    else\n', body)
    assert re.search(r'if \[ "\$bb_platform" = "efi" \]; then\n    if \[ -f "\$bb_g_fdir/unicode\.pf2" \]; then\n'
                     r'      loadfont unicode\n    fi\n  elif \[ -f "\$bb_g_fdir/unicode\.pf2" \]; then\n'
                     r'    loadfont "\$bb_g_fdir/unicode\.pf2"\n', body)
    for path, text in all_cfg().items():
        if path != LIB:
            assert "loadfont" not in text and not re.search(r"set theme=", text), path


def test_device_env_is_read_as_data_with_an_allow_list():
    main = code(MAIN.read_text())
    assert 'bb_dev_load "($bb_esp)/grub/beast/device.env"' in main
    assert "device.cfg" not in "\n".join(all_cfg().values()), "device.cfg (GRUB script) must not be read any more"
    body = function_body(LIB.read_text(), "bb_dev_load")
    m = re.search(r'^\s*if load_env --file "\$1" ([^;]+); then$', body, re.M)
    assert m and m.group(1).split() == DEVICE_NAMES
    assert not set(DEVICE_NAMES) & FORBIDDEN
    pats = dict(re.findall(r"bb_env_ok (\w+) \"\$\w+\" '([^']*)'", body))
    assert list(pats) == DEVICE_NAMES
    for n in DEVICE_NAMES:
        assert re.search(rf'else set {n}=""; fi', body), f"a bad {n} must be dropped"
    # before the data partition is looked for and before the user settings
    assert main.index("bb_dev_load") < main.index("search --no-floppy --fs-uuid") < main.index("bb_env_load")


@pytest.mark.parametrize("name, value, ok", [
    ("bb_install_id", "3f0c1c62-7a54-4b8e-9a51-0d6d8f1f2a10", True), ("bb_install_id", "x; halt", False),
    ("bb_layout", "msdos", True), ("bb_layout", "gpt", True), ("bb_layout", "gpt2", False),
    ("bb_data_fs", "exfat", True), ("bb_data_fs", "fat32", True), ("bb_data_fs", "ntfs", True),
    ("bb_data_fs", "ext4", False),
    ("bb_data_uuid", "6A2B-91F3", True), ("bb_data_uuid", "unknown", False), ("bb_data_uuid", "1234 --set=root", False),
    ("bb_data_uuid_linux", "6A2B-91F3", True), ("bb_data_uuid_linux", "01DC3A4B5C6D7E8F", True),
    ("bb_data_uuid_linux", "x init=/bin/sh", False), ("bb_data_uuid_linux", "", False),
    ("bb_data_label", "MY USB", True), ("bb_data_label", 'a"b', False),
    ("bb_serial", "1", True), ("bb_serial", "2", False),
])
def test_device_env_value_patterns(name, value, ok):
    """Values as they come out of load_env (bb_env_ok refuses control characters
    itself). The patterns are POSIX EREs that mean the same in Python's re."""
    pats = dict(re.findall(r"bb_env_ok (\w+) \"\$\w+\" '([^']*)'", function_body(LIB.read_text(), "bb_dev_load")))
    assert bool(re.search(pats[name], value)) is ok


def test_every_file_read_from_the_drive_as_settings_goes_through_load_env():
    """The complete list of load_env calls: the user settings, the installer's
    device.env, the helper's one-shot entry and the Windows copy's stamp."""
    calls = []
    for path, text in all_cfg().items():
        calls += [(path.name, " ".join(m.group(1).split())) for m in re.finditer(r"load_env\b([^\n;]*)", text)]
    assert sorted(calls) == sorted([
        ("lib.cfg", '--file "$1" ' + " ".join(DEVICE_NAMES)),
        ("lib.cfg", '--file "$1" timeout default bb_autoboot bb_debug bb_dryrun bb_serial bb_gfx bb_gfxmode bb_theme '
                    "bb_fs_addon bb_kargs bb_windows bb_beastnet_script debug pager"),
        ("lib.cfg", '-f "$bb_wb_d/stamp.env" bb_wb_iso bb_wb_kind'),
        ("main.cfg", '--file "($bb_esp)/grub/grubenv" bb_oneshot'),
    ]), calls


def test_build_puts_the_menu_and_the_early_config_into_the_image():
    sh = code(BUILD_SH.read_text())
    m = re.search(r'"\$GRUB_MKIMAGE" -O x86_64-efi [^\n]*-m "\$2/memdisk\.tar" -p "\$EFI_PREFIX" \\\n'
                  r'\s*-c "\$WORK/early-efi\.cfg" ', sh)
    assert m, "grubx64.efi must be built with the memdisk and build/early-efi.cfg"
    assert sh.count('"$GRUB_MKIMAGE" -O x86_64-efi') == 1, "one grub-mkimage call for x86_64-efi (efi_image)"
    assert 'strip_early "$HERE/early-efi.cfg" > "$WORK/early-efi.cfg"' in sh
    assert "--disable-shim-lock" not in sh
    # everything staged under esp/grub/ except the BIOS modules, plus version.cfg
    loop = sh[sh.index('EFI_PREFIX="/grub"'):sh.index("efi_image() {")]
    assert 'find "$STAGE/esp/grub" -type f -print0 | sort -z' in loop
    skipped = re.findall(r"^\s*([^\s)]+)\) continue ;;", loop, re.M)
    assert skipped == ["i386-pc/*"], skipped
    assert 'memdisk_list+=("grub/beast/version.cfg=esp/grub/beast/version.cfg")' in loop
    # the image is built before the id (empty id) and again with it; the id uses the first one's hash
    assert sh.index('efi_image "" "$WORK/efi-noid"') < sh.index('BUILD_ID="$(bbtool build-id') \
        < sh.index('efi_image "$BUILD_ID" "$WORK/efi"')
    assert 'bbtool build-id "$STAGE" "$VERSION" "$NOID_SHA"' in sh


def test_menu_files_still_ship_on_the_esp_for_legacy_bios():
    import sys
    sys.path.insert(0, str(ROOT / "installer"))
    try:
        from beastbooter import layout
    finally:
        sys.path.pop(0)
    for rel in ("grub/grub.cfg", "grub/beast/main.cfg", "grub/beast/version.cfg", "grub/i386-pc/normal.mod"):
        assert rel in layout.REQUIRED_ESP_FILES
    assert layout.DEVICE_ENV_PATH == "grub/beast/device.env"
