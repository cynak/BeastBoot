"""ISO path characters on Linux kernel command lines (docs/MENU.md "Booting
an ISO"). The ISO path goes into parameters such as iso-scan/filename=PATH.
GRUB only wraps a parameter with a space in double quotes and escapes a `"`
with a backslash, which Linux's command line parser ignores, so a file named
`x" url=http://evil/p ".iso` would add kernel parameters to a genuine ISO's
boot. bb_boot_iso refuses such paths before any Linux recipe (or an ISO's own
loopback.cfg, which gets the path as iso_path). Static checks of the menu;
the patterns are run with grep -E (GNU regex, as GRUB's regexp module)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GRUB = ROOT / "grub"
LIB = GRUB / "beast" / "lib.cfg"
MAIN = GRUB / "beast" / "main.cfg"
MENU_MD = ROOT / "docs" / "MENU.md"

# Recipes that put the ISO path on no kernel command line: Windows has its
# own check (bb_win_boot), none boots nothing, an EFI loader gets no path.
NO_CMDLINE = {"windows", "none", "efi-chainload"}


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def grub_dq(s: str) -> str:
    """The value of a GRUB double-quoted string body (\\\\, \\" and \\$ escapes)."""
    return re.sub(r'\\([\\"$])', r"\1", s)


def name_check() -> tuple[str, str]:
    """(guard line, ERE) of the ISO name check in bb_boot_iso."""
    body = code(function_body(LIB.read_text(), "bb_boot_iso"))
    m = re.search(r'^  (if \[ [^\n]*\]; then)\n    if regexp -- "((?:[^"\\]|\\.)*)" "\$bb_iso"; then\n'
                  r'(.*?)\n    fi\n  fi\n', body, re.M | re.S)
    assert m, "bb_boot_iso has no ISO name check for the kernel command line"
    block = m.group(3)
    assert "bb_err iso-bad-name" in block and "bb_finish" in block and "return 1" in block, block
    assert "Rename" in block, "the message must tell the user to rename the file"
    return m.group(1), grub_dq(m.group(2))


def ere_matches(pattern: str, value: str) -> bool:
    p = subprocess.run(["grep", "-qE", "--", pattern], input=value.encode(), capture_output=True)
    assert p.returncode in (0, 1), p.stderr
    return p.returncode == 0


def test_check_comes_before_every_linux_recipe():
    body = code(function_body(LIB.read_text(), "bb_boot_iso"))
    guard, _ = name_check()
    check = body.index(guard)
    # After detection and the add-on (bb_recipe is final), before dispatch.
    assert body.index("bb_detect") < check and body.rindex('set bb_recipe="$bb_addon_for"') < check
    for call in ("bb_r_linux", "bb_r_loopback"):
        assert check < body.index(f"\n    {call}\n"), call
    # The guard skips exactly the recipes without a kernel command line.
    skipped = set(re.findall(r'"\$bb_recipe" != "([a-z-]+)"', guard))
    assert skipped == NO_CMDLINE, guard
    assert re.fullmatch(r'if \[ "\$bb_recipe" != "[a-z-]+"(?: -a "\$bb_recipe" != "[a-z-]+")* \]; then', guard)


def test_linux_recipes_reached_only_from_bb_boot_iso():
    for path in sorted(GRUB.rglob("*.cfg")):
        text = code(path.read_text())
        for fn in ("bb_r_linux", "bb_r_loopback"):
            calls = re.findall(rf"^\s*{fn}\b(?! \{{)", text, re.M)
            if path == LIB:
                body = code(function_body(path.read_text(), "bb_boot_iso"))
                assert len(calls) == 1 and len(re.findall(rf"^\s*{fn}$", body, re.M)) == 1, (path, fn)
            else:
                assert not calls, (path, fn)


@pytest.mark.skipif(not shutil.which("grep"), reason="grep not installed")
@pytest.mark.parametrize("path, refused", [
    ("/linux/ubuntu-24.04.iso", False),
    ("/linux/My Distro (26.04) [x86_64] & more, 50%.iso", False),
    ('/linux/x" url=http://evil/p ".iso', True),
    ('/x" init=/bin/sh "/ubuntu.iso', True),
    ("/linux/it's.iso", True),
    ("/linux/a\\b.iso", True),
    ("/linux/a\tb.iso", True),
    ("/linux/a\x1bb.iso", True),
    ("/linux/a\x7fb.iso", True),
])
def test_name_pattern(path, refused):
    _, pattern = name_check()
    assert ere_matches(pattern, path) is refused, (pattern, path)


def test_name_pattern_covers_newline():
    # grep works line by line; [:cntrl:] covers newline and CR as well.
    _, pattern = name_check()
    assert "[:cntrl:]" in pattern


def oneshot_check() -> str:
    text = code(MAIN.read_text())
    m = re.search(r'save_env --file "\(\$bb_esp\)/grub/grubenv" bb_oneshot; then\n(.*?)\n    else\n', text, re.S)
    assert m, "one-shot block not found"
    block = m.group(1)
    v = re.search(r"^      if regexp -- '([^']*)' \"\$bb_oneshot_iso\"; then\n"
                  r"(?:(?!\n      (?:else|fi)\b).)*set bb_autoboot=\"\$bb_oneshot_iso\"\n      else\n", block, re.M | re.S)
    assert v, "bb_oneshot must be checked before it becomes bb_autoboot"
    assert block.count('set bb_autoboot="$bb_oneshot_iso"') == 1
    return v.group(1)


@pytest.mark.skipif(not shutil.which("grep"), reason="grep not installed")
@pytest.mark.parametrize("value, ok", [
    ("/downloads/ubuntu-24.04.iso", True),
    ("/isos/Win 11 (x64).iso", True),
    ("downloads/x.iso", False),
    ('/x" init=/bin/sh ".iso', False),
    ("/x\tinit=/bin/sh.iso", False),
    ("/x\x1b.iso", False),
])
def test_oneshot_pattern(value, ok):
    assert ere_matches(oneshot_check(), value) is ok


def test_oneshot_cleared_before_the_check():
    # Cleared whatever its value, so a bad entry cannot come back on every boot.
    text = code(MAIN.read_text())
    pat = oneshot_check()
    assert text.index('set bb_oneshot=""\n    if save_env') < text.index(f"if regexp -- '{pat}'")


def test_documented():
    menu = MENU_MD.read_text()
    assert "`iso-bad-name`" in menu
