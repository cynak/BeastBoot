"""Compatibility shims the menu defines before it runs an ISO's own loopback.cfg."""

from __future__ import annotations

import re
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "grub" / "beast" / "lib.cfg"


def function_body(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)} \{{\n(.*?)^\}}", text, re.S | re.M)
    assert m, f"function {name} is not defined in lib.cfg"
    return m.group(1)


def test_grub_platform_is_a_no_op_for_linux_mint():
    """Linux Mint's grub.cfg runs `grub_platform` (a command only Mint's GRUB has) and then
    reads $grub_platform. Without a stand-in, BeastBoot printed "can't find command" there."""
    text = LIB.read_text()
    body = [ln.strip() for ln in function_body(text, "grub_platform").splitlines() if ln.strip()]
    assert body == ["true"]
    # it must not set or clear GRUB's own variable
    assert "set grub_platform" not in text and "unset grub_platform" not in text
