"""bb_kargs: extra kernel parameters for every ISO recipe (docs/MENU.md,
tests/e2e/REAL_ISOS.md). Static checks of the menu source; the behaviour in a
real GRUB is checked by tests/e2e/test_e2e_real_isos.py::test_kargs_dryrun."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "grub" / "beast" / "lib.cfg"
MAIN = ROOT / "grub" / "beast" / "main.cfg"
RECIPES = ("casper", "live-boot", "archiso", "dracut-live", "anaconda", "suse", "debian-installer", "alpine")


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_every_linux_recipe_appends_kargs_unquoted():
    body = function_body(LIB.read_text(), "bb_r_linux")
    calls = [ln for ln in code_lines(body) if ln.startswith("bb_linux ")]
    assert len(calls) == len(RECIPES), calls
    for ln in calls:
        # Last word, unquoted: GRUB splits it into separate kernel parameters,
        # and an empty value adds nothing.
        assert ln.endswith(" $bb_kargs"), ln
        assert ln.count("bb_kargs") == 1, ln


def test_kargs_only_in_iso_recipes():
    text = LIB.read_text()
    users = [ln for ln in code_lines(text) if "bb_kargs" in ln]
    body = code_lines(function_body(text, "bb_r_linux"))
    assert users and all(ln in body for ln in users), users
    for fn in ("bb_beastnet", "bb_r_loopback", "bb_r_windows", "bb_r_efi_chainload", "bb_linux"):
        assert "bb_kargs" not in function_body(text, fn), fn


def test_kargs_exported_and_not_set_by_default():
    main = MAIN.read_text()
    exports = [ln for ln in code_lines(main) if ln.startswith("export ")]
    assert any("bb_kargs" in ln.split() for ln in exports), exports
    for f in (LIB, MAIN):
        assert not re.search(r"^\s*set bb_kargs=", f.read_text(), re.M), f"{f.name} sets bb_kargs"


def test_documented():
    menu_md = (ROOT / "docs" / "MENU.md").read_text()
    assert re.search(r"^\| `bb_kargs=", menu_md, re.M)


@pytest.mark.skipif(not shutil.which("grub-script-check"), reason="grub-script-check not installed")
@pytest.mark.parametrize("path", [LIB, MAIN], ids=lambda p: p.name)
def test_grub_script_check(path, tmp_path):
    # lib.cfg holds only function definitions, which grub-script-check reports
    # as "contains no commands"; one trailing command avoids that.
    f = tmp_path / path.name
    f.write_text(path.read_text() + "\ntrue\n")
    p = subprocess.run(["grub-script-check", str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
