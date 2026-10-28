"""User settings on the data partition (docs/MENU.md "User configuration"):
/beast-booter/config.env is a GRUB environment block read with load_env and an
allow-list; /beast-booter/config.cfg is GRUB script and is never read with
Secure Boot on (docs/SECURITY_REVIEW-0.4.0.md D1). Static checks of the menu;
the behaviour in GRUB is checked by tests/e2e/test_e2e_secureboot.py."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GRUB = ROOT / "grub"
LIB = GRUB / "beast" / "lib.cfg"
MAIN = GRUB / "beast" / "main.cfg"
MENU_MD = ROOT / "docs" / "MENU.md"
GUIDE_MD = ROOT / "docs" / "USER_GUIDE.md"

ALLOWED = {"timeout", "default", "bb_autoboot", "bb_debug", "bb_dryrun", "bb_serial", "bb_gfx",
           "bb_gfxmode", "bb_theme", "bb_fs_addon", "bb_kargs", "bb_windows", "bb_beastnet_script"}
# Never settable from the data partition: they say where files come from or
# whether they are checked.
FORBIDDEN = {"bb_sb", "bb_cfg", "bb_esp", "bb_data", "bb_data_uuid", "bb_data_uuid_linux", "bb_data_fs",
             "bb_data_label", "bb_p1", "bb_platform", "prefix", "root", "check_signatures", "lockdown",
             "bb_oneshot", "bb_path", "bb_version", "bb_install_id", "bb_layout"}


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(1)


def code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def all_cfg() -> dict[Path, str]:
    return {p: code(p.read_text()) for p in sorted(GRUB.rglob("*.cfg"))}


def load_env_names() -> list[str]:
    body = function_body(LIB.read_text(), "bb_env_load")
    m = re.search(r'^\s*if load_env --file "\$1" ([^;]+); then$', body, re.M)
    assert m, "bb_env_load must call load_env with an explicit list of names"
    return m.group(1).split()


def env_patterns() -> dict[str, str]:
    body = function_body(LIB.read_text(), "bb_env_load")
    return dict(re.findall(r"bb_env_ok (\w+) \"\$\w+\" '([^']*)'", body))


def test_config_cfg_is_sourced_only_without_secure_boot():
    text = code(MAIN.read_text())
    sources = re.findall(r'(?:source|configfile)\s+"?\(\$bb_data\)[^\n]*', text)
    assert sources == ['source "($bb_data)/beast-booter/config.cfg"'], sources
    block = re.search(r'if \[ -f "\(\$bb_data\)/beast-booter/config\.cfg" \]; then\n(.*?)\n  fi\n', text, re.S)
    assert block, "config.cfg block not found"
    assert re.fullmatch(
        r'\s*if \[ "\$bb_sb" = "1" \]; then\n(?:(?!\n\s*(?:else|elif|fi)\b).)*\n\s*else\n'
        r'\s*source "\(\$bb_data\)/beast-booter/config\.cfg"\n\s*fi', block.group(1), re.S), block.group(1)


def test_no_other_menu_file_runs_data_partition_script():
    for path, text in all_cfg().items():
        if path == MAIN:
            continue
        assert not re.search(r'(?:source|configfile)\s+"?\(\$bb_data\)', text), path


def test_bb_sb_comes_only_from_lockdown():
    text = code(MAIN.read_text())
    sets = re.findall(r"set bb_sb=\S+", text)
    assert sets == ["set bb_sb=1", "set bb_sb=0"] * 2, sets
    first_lockdown = text.index('if [ "$lockdown" = "y" ]; then\n  set bb_sb=1')
    config = text.index('beast-booter/config.env')
    last_lockdown = text.rindex('if [ "$lockdown" = "y" ]; then\n  set bb_sb=1')
    cfg = text.rindex('source "($bb_data)/beast-booter/config.cfg"')
    assert first_lockdown < config < cfg < last_lockdown
    for path, t in all_cfg().items():
        if path != MAIN:
            assert not re.search(r"set bb_sb=", t), path


def test_config_env_allow_list():
    names = load_env_names()
    assert set(names) == ALLOWED, set(names) ^ ALLOWED
    assert not set(names) & FORBIDDEN
    assert not [n for n in names if n.startswith("bb_data")]


def test_every_load_env_has_an_explicit_list():
    for path, text in all_cfg().items():
        for m in re.finditer(r"load_env\b([^\n;]*)", text):
            args = m.group(1).split()
            # --file FILE NAME...: at least one name after the file
            assert "--skip-sig" not in args, (path, m.group(0))
            assert len(args) >= 3 and args[0] in ("--file", "-f"), (path, m.group(0))


def test_config_env_file_is_read_through_bb_env_load():
    text = code(MAIN.read_text())
    assert 'bb_env_load "($bb_data)/beast-booter/config.env"' in text
    assert text.index("bb_env_load") < text.index('source "($bb_data)/beast-booter/config.cfg"'), \
        "config.env first, so config.cfg wins without Secure Boot"


def test_every_allowed_value_is_validated():
    pats = env_patterns()
    assert set(pats) == ALLOWED, set(pats) ^ ALLOWED
    # bb_debug is checked first, so the other checks can report.
    body = function_body(LIB.read_text(), "bb_env_load")
    assert body.index("bb_env_ok bb_debug") < min(body.index(f"bb_env_ok {n} ") for n in ALLOWED - {"bb_debug"})
    for n in ALLOWED:
        assert re.search(rf'else set {n}=""; fi', body), f"a bad {n} must be dropped"


# Values as they come out of load_env (bb_env_ok drops one trailing CR first and
# refuses any control character). The patterns are POSIX EREs; these ones mean
# the same in Python's re.
@pytest.mark.parametrize("name, value, ok", [
    ("bb_debug", "1", True), ("bb_debug", "yes", False), ("bb_serial", "0", True), ("bb_serial", "01", False),
    ("bb_gfx", "0", True), ("bb_fs_addon", "2", False),
    ("bb_windows", "pe", True), ("bb_windows", "setup", True), ("bb_windows", "pex", False),
    ("timeout", "10", True), ("timeout", "-1", False), ("timeout", "5 ", False),
    ("default", "0", True), ("default", 'a"b', False),
    ("bb_gfxmode", "1280x720", True), ("bb_gfxmode", "1920x1080,1280x720,1024x768,auto", True),
    ("bb_gfxmode", "1024x768x32;auto", True), ("bb_gfxmode", "1280x720 x", False), ("bb_gfxmode", "", False),
    ("bb_autoboot", "/linux/My Distro (26.04).iso", True), ("bb_autoboot", "linux/x.iso", False),
    ("bb_autoboot", '/x".iso', False),
    ("bb_theme", "/beast-booter/mytheme/theme.txt", True), ("bb_theme", "theme.txt", False),
    ("bb_beastnet_script", "/beast-booter/plan.json", True),
    ("bb_beastnet_script", "/plan.json init=/bin/sh", False), ("bb_beastnet_script", "plan.json", False),
    ("bb_kargs", "console=ttyS0,115200 nomodeset", True), ("bb_kargs", 'a="b"', False),
])
def test_value_patterns(name, value, ok):
    assert bool(re.search(env_patterns()[name], value)) is ok


def test_allowed_names_are_documented():
    menu, guide = MENU_MD.read_text(), GUIDE_MD.read_text()
    assert "config.env" in menu and "config.env" in guide
    for n in ALLOWED:
        assert f"`{n}" in menu, f"{n} missing from docs/MENU.md"


@pytest.mark.skipif(not shutil.which("grub-editenv"), reason="grub-editenv not installed")
def test_e2e_harness_writes_what_grub_editenv_reads(tmp_path):
    sys.path.insert(0, str(ROOT / "tests" / "e2e"))
    try:
        from bbe2e import images
    finally:
        sys.path.pop(0)
    cfg = images.user_config(dryrun=True, autoboot="/isos/Win 11.iso", extra='set bb_kargs="a\\\\b"\necho x')
    f = tmp_path / "config.env"
    f.write_bytes(images.config_env(cfg))
    assert f.stat().st_size == 1024
    out = subprocess.run(["grub-editenv", str(f), "list"], capture_output=True, text=True, check=True).stdout
    assert dict(ln.split("=", 1) for ln in out.splitlines()) == {
        "bb_debug": "1", "bb_dryrun": "1", "bb_autoboot": "/isos/Win 11.iso", "bb_kargs": "a\\b"}, out
