"""Windows ISOs (wimboot): static checks of the menu recipe, the Windows PE start-up
script and beastmount.c against the design in tests/e2e/REAL_ISOS.md "Windows (wimboot)".
The behaviour in GRUB is checked by tests/e2e/test_e2e_recipes.py (dry runs) and
test_e2e_secureboot.py (refusal); a real Windows ISO by tests/e2e/test_e2e_real_isos.py."""

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


def test_secure_boot_refused_before_anything_runs():
    body = code_lines(function_body(LIB.read_text(), "bb_r_windows"))
    assert body[0] == 'if [ "$bb_sb" = "1" ]; then', body[:2]
    assert body[1] == 'bb_err windows-sb "$bb_iso"'
    refusal = body[:body.index("return 1") + 1]
    text = " ".join(refusal)
    assert "turn Secure Boot off in the firmware settings" in text
    assert "bb_finish" in refusal
    for cmd in ("linux", "linux16", "initrd", "initrd16", "boot", "save_env", "bb_win_boot", "configfile"):
        assert not any(ln.split()[0] == cmd for ln in refusal), cmd


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
    assert 'if save_env --file "($bb_esp)/grub/grubenv" bb_winpe_iso bb_winpe_mode; then' in lines
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
