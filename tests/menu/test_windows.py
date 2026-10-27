"""Windows ISOs (wimboot, also with Secure Boot via a prepared boot.wim copy): static checks of the menu recipe, the Windows PE start-up
script and beastmount.c against the design in tests/e2e/REAL_ISOS.md "Windows (wimboot)".
The behaviour in GRUB is checked by tests/e2e/test_e2e_recipes.py (dry runs) and
test_e2e_secureboot.py (secure boot); a real Windows ISO by tests/e2e/test_e2e_real_isos.py."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "grub" / "beast" / "lib.cfg"
MAIN = ROOT / "grub" / "beast" / "main.cfg"
WINCFG = ROOT / "grub" / "beast" / "windows.cfg"
CMD = ROOT / "build" / "winpe" / "beastboot.cmd"
MOUNT_C = ROOT / "build" / "winpe" / "beastmount.c"


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_windows_sb_refusal_is_gone():
    text = LIB.read_text()
    assert "windows-sb " not in text.replace("windows-sb-no-helper", "")
    body = function_body(text, "bb_r_windows")
    assert "bb_sb" not in body and "wimboot is not signed" not in text


def test_prepared_copy_is_matched_and_read_safely():
    """SB on + stamp whose ISO path and iso-head.bin match + boot.wim -> windows recipe
    on the copy. stamp.env is data: explicit variable list, never sourced."""
    text = LIB.read_text()
    body = function_body(text, "bb_wb_probe")
    lines = code_lines(body)
    assert 'load_env -f "$bb_wb_d/stamp.env" bb_wb_iso bb_wb_kind' in lines
    assert 'if cmp "(loop)64+128" "$bb_wb_d/iso-head.bin"; then' in lines
    assert not any("probe" in ln or "uuid" in ln for ln in lines)
    assert 'set bb_wb_d="($bb_data)/beast-booter/winboot$bb_iso"' in lines
    assert 'if [ "$bb_wb_iso" = "$bb_iso" -a -f "$bb_wb_d/boot.wim" ]; then' in lines
    assert 'if [ -f "$bb_wb_d/stamp.env" ]; then' in lines
    assert 'set bb_wb_dir="$bb_wb_d"' in lines and "set bb_recipe=windows" in lines
    # stale head / missing copy -> offer
    assert "set bb_wb_offer=1" in lines and "set bb_wb_offer=2" in lines
    assert "if [ -f (loop)/readme.txt -o -f (loop)/README.TXT ]; then" in lines
    # never sourced anywhere in the menu scripts
    for f in (ROOT / "grub" / "beast").glob("*.cfg"):
        for ln in code_lines(f.read_text()):
            assert not re.match(r"(source|\.)\s", ln) or "stamp" not in ln, (f, ln)
            assert "stamp.env" not in ln or ln.startswith(("load_env", "if [ -f", "set bb_wb_d")), (f, ln)
    # only on Secure Boot, only when nothing else matched (SB off unchanged)
    det = function_body(text, "bb_detect")
    assert 'if [ "$bb_recipe" = "none" -a "$bb_sb" = "1" ]; then\n    bb_wb_probe' in det


def test_prepare_offer_and_no_helper_error():
    text = LIB.read_text()
    none = code_lines(function_body(text, "bb_r_none"))
    assert 'if [ "$bb_wb_offer" = "1" ]; then' in none and "bb_r_wb_prepare" in none
    assert 'bb_err windows-sb-no-helper "$bb_iso"' in none
    assert none.index('bb_err windows-sb-no-helper "$bb_iso"') < none.index('bb_err no-recipe "$bb_iso"')
    prep = code_lines(function_body(text, "bb_r_wb_prepare"))
    assert 'bb_dbg "windows-prepare $bb_iso"' in prep
    cfg = WINCFG.with_name("winprepare.cfg").read_text()
    assert 'menuentry "Prepare this Windows ISO for Secure Boot"' in cfg and "bb_wb_prepare" in cfg
    wp = code_lines(function_body(text, "bb_wb_prepare"))
    assert any(ln.startswith("if save_env --file \"($bb_esp)/grub/grubenv\" bb_wb_iso; then") for ln in wp)
    assert "bb_beastnet winboot" in wp
    # the ISO's identity is saved before the helper starts
    assert wp.index("bb_beastnet winboot") > wp.index('set bb_wb_iso="$bb_iso"')


@pytest.mark.skipif(not shutil.which("grub-script-check"), reason="grub-script-check not installed")
def test_winprepare_cfg_grub_script_check():
    p = subprocess.run(["grub-script-check", str(WINCFG.with_name("winprepare.cfg"))], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr


def test_prepared_copy_used_by_windows_recipe():
    text = LIB.read_text()
    body = function_body(text, "bb_r_windows")
    assert 'if [ "$bb_wb_kind" = "setup" ]; then' in body
    assert "export bb_iso bb_wb_dir bb_wb_kind" in body
    lines = code_lines(function_body(text, "bb_win_boot"))
    assert 'set bb_w_wim="newc:boot.wim:$bb_wb_dir/boot.wim"' in lines
    assert 'bb_dbg "windows mode=$1 copy=$bb_wb_dir"' in lines
    assert 'bb_dbg "windows mode=$1"' in lines
    # the dry-run initrd line prints bb_w_wim, so it shows the copy path
    assert 'bb_dry "$bb_w_rd $bb_w_wim $bb_w_inj"' in lines


def test_install_media_menu_and_autoboot():
    body = function_body(LIB.read_text(), "bb_r_windows")
    assert "(loop)/sources/install.wim" in body and "(loop)/sources/install.esd" in body
    assert 'configfile "$bb_cfg/windows.cfg"' in body
    assert "bb_win_boot setup" in body and "bb_win_boot pe" in body and "bb_win_boot native" in body
    # autoboot: setup unless the user config says bb_windows=pe
    assert re.search(r'if \[ "\$bb_windows" = "pe" \]; then\s+bb_win_boot pe\s+else\s+bb_win_boot setup', body)


def test_windows_menu_offers_setup_first():
    lines = code_lines(WINCFG.read_text())
    entries = [ln for ln in lines if ln.startswith("menuentry ")]
    assert len(entries) == 2, entries
    assert "Install Windows" in entries[0] and "Windows PE" in entries[1]
    calls = [ln for ln in lines if ln.startswith("bb_win_boot ")]
    assert calls == ["bb_win_boot setup", "bb_win_boot pe"]
    assert "set timeout=-1" in lines


def test_wimboot_commands_per_platform():
    body = function_body(LIB.read_text(), "bb_win_boot")
    lines = code_lines(body)
    assert 'if ! linux16 "$bb_w/wimboot" $bb_w_args; then' in lines
    assert 'if ! initrd16 "$bb_w_wim" $bb_w_inj; then' in lines
    assert 'if ! linux "$bb_w/wimboot" $bb_w_args; then' in lines
    assert 'if ! initrd "$bb_w_wim" $bb_w_inj; then' in lines
    assert 'set bb_w_wim="newc:boot.wim:(loop)/sources/boot.wim"' in lines
    assert 'set bb_w_args="index=1"' in lines
    inj = next(ln for ln in lines if ln.startswith('set bb_w_inj="newc:winpeshl.ini:'))
    assert inj == ('set bb_w_inj="newc:winpeshl.ini:$bb_w/winpe/winpeshl.ini newc:beastboot.cmd:'
                   '$bb_w/winpe/beastboot.cmd newc:beastboot.txt:($bb_esp)/grub/grubenv"')
    assert 'set bb_w_inj="$bb_w_inj newc:beastmount.exe:$bb_w/winpe/beastmount.exe"' in lines
    assert "bb_kargs" not in body


def test_iso_path_and_mode_saved_to_grubenv():
    lines = code_lines(function_body(LIB.read_text(), "bb_win_boot"))
    assert 'if save_env --file "($bb_esp)/grub/grubenv" bb_winpe_iso bb_winpe_mode bb_winpe_uuid; then' in lines
    assert 'set bb_winpe_iso="$bb_iso"' in lines and 'set bb_winpe_mode="$1"' in lines
    assert 'bb_err grubenv-not-writable "$bb_iso"' in lines
    # saved before wimboot is loaded
    assert lines.index('bb_err grubenv-not-writable "$bb_iso"') < lines.index('if ! linux "$bb_w/wimboot" $bb_w_args; then')


def test_bios_loads_linux16():
    insmod = [w.rstrip(";") for w in next(ln for ln in MAIN.read_text().splitlines() if "for bb_m in" in ln).split()]
    assert {"linux16", "loadenv", "udf", "ntfs", "exfat"} <= set(insmod)


def test_startup_script_markers_in_order():
    """RESULT.TXT lines (tests/e2e/REAL_ISOS.md): iso-mounted only once the install image
    was found on the new drive; setup-running only after beastmount --running saw Setup
    running from that drive."""
    s = CMD.read_text()
    order = ["call :log winpe-ok", "set \"BB_LINE=iso-found ", "call :log iso-mounted %BB_SRC% %BB_INST%",
             "call :log setup-started %BB_SETUP%", "start \"\" \"%BB_SETUP%\"",
             "beastmount.exe --running %BB_SRC% 60", "call :log setup-running", "call :log setup-process"]
    pos = [s.find(o, s.find(":setup\n")) for o in order]
    assert all(p >= 0 for p in pos), dict(zip(order, pos))
    assert pos == sorted(pos), dict(zip(order, pos))
    # the install image is what makes a drive count as the ISO's
    assert re.search(r'for %%f in \(install\.wim install\.esd install\.swm\) do .*'
                     r'if exist "%1:\\sources\\%%f" set "BB_INST=%1:\\sources\\%%f"', s)
    assert 'if not defined BB_PROC (' in s and "setup-not-running:" in s


def test_startup_script_failures_explained():
    s = CMD.read_text()
    for reason in ("no-iso-path", "iso-not-found", "no-mount-tool", "attach-failed", "no-media", "no-setup",
                   "setup-not-running", "unknown-mode"):
        m = re.search(rf'set "BB_MSG={reason}: ([^"]+)"', s)
        assert m and len(m.group(1)) > 30, reason
    fail = s[s.index("\n:fail\n"):s.index("\n:test_end\n")]
    assert "cmd /k" in fail and "!BB_MSG!" in fail


def test_startup_script_powers_off_only_for_tests():
    s = CMD.read_text()
    assert s.count("wpeutil shutdown") == 1
    end = s[s.index("\n:test_end\n"):]
    assert "wpeutil shutdown" in end.split("\n:log\n")[0]
    for ln in s.splitlines():
        if "goto test_end" in ln:
            assert "if defined BB_LOG" in ln or ln.strip() == "goto test_end", ln
    # ISO names (user data) are echoed and logged through variables only
    assert "echo BeastBoot: looking for %BB_ISO%" not in s
    assert not re.search(r"call :log[^\n]*%BB_ISO%", s)


def test_startup_script_never_writes_the_data_partition():
    code = "\n".join(ln for ln in CMD.read_text().lower().splitlines()
                     if not ln.lstrip().startswith("rem ") and "(dir, diskpart)" not in ln)
    for bad in ("format ", "diskpart", "del ", "copy ", "move ", ">\"%bb_data%", ">>\"%bb_data%"):
        assert bad not in code, bad


def test_beastmount_modes():
    c = MOUNT_C.read_text()
    assert "BB_ATTACH_READ_ONLY | BB_ATTACH_PERMANENT" in c
    assert "BB_ACCESS_READ" in c and "VIRTUAL_DISK_ACCESS_READ" in c
    assert '!wcscmp(argv[1], L"--running")' in c and "QueryFullProcessImageNameW" in c
    assert '!wcscmp(argv[1], L"--sleep")' in c
    # the script's timer: beastmount where it is injected (ping needs the network stack)
    assert '"%BB_SYS%\\beastmount.exe" --sleep %~1' in CMD.read_text()
    for name in ("setup.exe", "setuphost.exe", "setupprep.exe"):
        assert f'L"{name}"' in c
    assert re.search(r'^#define BEASTMOUNT_VERSION "[0-9.]+"$', c, re.M)


@pytest.mark.skipif(not shutil.which("grub-script-check"), reason="grub-script-check not installed")
def test_windows_cfg_grub_script_check():
    p = subprocess.run(["grub-script-check", str(WINCFG)], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr


def test_iso_names_with_quote_or_control_character_are_refused():
    body = function_body(LIB.read_text(), "bb_win_boot")
    lines = code_lines(body)
    assert """if regexp '["[:cntrl:]]' "$bb_iso"; then""" in lines
    assert 'bb_err windows-bad-name "$bb_iso"' in lines
    # refused before anything is saved or loaded
    assert lines.index('bb_err windows-bad-name "$bb_iso"') < lines.index('set bb_winpe_iso="$bb_iso"')


def test_data_partition_is_matched_by_volume_serial():
    text = CMD.read_text(encoding="utf-8")
    assert 'bb_winpe_uuid" set "BB_UUID=%%b"' in text
    assert re.search(r'if exist "%%d:%BB_ISO%" call :is_data %%d && set "BB_DATA=%%d:"', text)
    assert "\n:is_data\r\n" in text or "\n:is_data\n" in text
