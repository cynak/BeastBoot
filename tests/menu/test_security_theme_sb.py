"""bb_theme under Secure Boot: a theme from the data partition would make the
signed GRUB parse theme and PNG files from untrusted storage (GRUB's Secure
Boot checks do not cover them). With Secure Boot on the menu ignores
bb_theme, uses its built-in theme and says so like it does for config.cfg.
Without Secure Boot nothing changes. Static checks of the menu."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "grub" / "beast" / "lib.cfg"
MAIN = ROOT / "grub" / "beast" / "main.cfg"
MENU_MD = ROOT / "docs" / "MENU.md"
GUIDE_MD = ROOT / "docs" / "USER_GUIDE.md"


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def test_main_drops_bb_theme_under_secure_boot():
    text = code(MAIN.read_text())
    last_sb = text.rindex('if [ "$lockdown" = "y" ]; then\n  set bb_sb=1')
    m = re.search(r'^if \[ "\$bb_sb" = "1" -a -n "\$bb_theme" \]; then\n'
                  r'  set bb_theme=""\n  set bb_theme_ignored=1\n  bb_dbg "theme-ignored-sb"\n'
                  r'  echo "[^"\n]*bb_theme[^"\n]*"\n', text, re.M)
    assert m, "main.cfg must drop bb_theme with Secure Boot on and say so"
    # After bb_sb is final, before the graphical menu is set up.
    assert last_sb < m.start() < text.index("bb_gfx_init")
    assert re.search(r"^set bb_theme_ignored=0$", text[:m.start()], re.M)


def test_gfx_init_never_loads_a_data_theme_under_secure_boot():
    body = code(function_body(LIB.read_text(), "bb_gfx_init"))
    m = re.search(r'^  if \[ ([^\n]*) \]; then\n    if \[ -f "\(\$bb_data\)\$bb_theme" \]; then\n'
                  r'      set bb_g_theme="\(\$bb_data\)\$bb_theme"\n', body, re.M)
    assert m, "data-partition theme block not found"
    assert '"$bb_sb" != "1"' in m.group(1).split(" -a "), m.group(1)
    assert body.count("$bb_theme") == 3


def test_ignored_settings_entry_lists_the_theme():
    text = code(MAIN.read_text())
    m = re.search(r'^  if \[ "\$bb_cfg_ignored" = "1" -o "\$bb_theme_ignored" = "1" \]; then\n'
                  r'    menuentry "[^"\n]*Secure Boot[^"\n]*" --class=help \{\n'
                  r'      bb_cfg_ignored_text\n', text, re.M)
    assert m, "the help entry must also appear when only bb_theme was ignored"
    body = function_body(LIB.read_text(), "bb_cfg_ignored_text")
    theme = re.search(r'^  if \[ "\$bb_theme_ignored" = "1" \]; then\n(.*?)^  fi\n', body, re.M | re.S)
    assert theme and re.search(r'echo "[^"\n]*bb_theme', theme.group(1)), body
    assert re.search(r'if \[ "\$bb_cfg_ignored" = "1" \]; then\n\s*echo "[^"\n]*config\.cfg', body)


def test_documented():
    menu = MENU_MD.read_text()
    assert "theme-ignored-sb" in menu
    sb = menu[menu.index("### With Secure Boot on"):]
    assert "`bb_theme`" in sb[:sb.index("\n## ")]
    assert "bb_theme" in GUIDE_MD.read_text().split("**Secure Boot on:**", 1)[1][:800]
