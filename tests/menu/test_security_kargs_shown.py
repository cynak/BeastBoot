"""bb_kargs stays honoured (docs/MENU.md "With Secure Boot on") but is never
silent: when it is set, the root menu shows it in a help entry, with and
without Secure Boot, and a real boot prints it. Static checks of the menu."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "grub" / "beast" / "lib.cfg"
MAIN = ROOT / "grub" / "beast" / "main.cfg"
MENU_MD = ROOT / "docs" / "MENU.md"


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def data_branch() -> str:
    text = code(MAIN.read_text())
    m = re.search(r'^if \[ -z "\$bb_data" \]; then\n.*?^else\n(.*?)^fi$', text, re.M | re.S)
    assert m, "menu block not found"
    return m.group(1)


def test_root_menu_shows_kargs_in_both_modes():
    branch = data_branch()
    m = re.search(r'^  if \[ -n "\$bb_kargs" \]; then\n'
                  r'    menuentry "Extra kernel parameters: \$bb_kargs[^"\n]*" --class=help \{\n'
                  r'      bb_kargs_text\n      bb_pause\n    \}\n  fi\n', branch, re.M)
    assert m, "the root menu must show bb_kargs when it is set"
    # Top level of the data branch: not under a Secure Boot condition, and
    # after the ISOs, so it does not move a numeric `default`.
    assert branch.index("bb_list / menu") < m.start()


def test_help_text_shows_the_value():
    body = function_body(LIB.read_text(), "bb_kargs_text")
    assert re.search(r'^\s*echo "  \$bb_kargs"$', body, re.M), body
    assert "config.env" in body


def test_real_boot_prints_kargs():
    body = function_body(LIB.read_text(), "bb_r_linux")
    m = re.search(r'^  if \[ -n "\$bb_kargs" \]; then\n    echo "[^"\n]*\$bb_kargs[^"\n]*"\n  fi\n', body, re.M)
    assert m, "bb_r_linux must print bb_kargs before it starts the kernel"
    assert m.start() < body.index("bb_linux ")


def test_documented():
    menu = MENU_MD.read_text()
    assert "Extra kernel parameters:" in menu
