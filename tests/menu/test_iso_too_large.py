"""iso-too-large: alpine and debian-installer copy the whole ISO into the initrd, so a
failing `initrd` for those recipes is reported as a too-large ISO (measured with a real
Alpine ISO padded to 700 MiB / 1.1 GiB / 2 GiB; see docs/ISO_SUPPORT.md). The behaviour in
GRUB was exercised with real GRUB (legacy BIOS, 1.1 GiB); this checks the wiring."""

from __future__ import annotations

import re
from pathlib import Path

LIB = (Path(__file__).resolve().parents[2] / "grub" / "beast" / "lib.cfg").read_text()


def fail_body() -> str:
    m = re.search(r"^function bb_fail \{\n(.*?)^\}\n", LIB, re.M | re.S)
    assert m
    return m.group(1)


def test_initrd_failure_of_whole_iso_recipes_is_iso_too_large():
    body = fail_body()
    i = body.index("bb_err iso-too-large")
    head = body[:i]
    assert '"$1" = "initrd"' in head
    assert '"$bb_recipe" = "alpine"' in head and '"$bb_recipe" = "debian-installer"' in head
    # before the Secure Boot wording: the kernel was accepted, so it is not a signature problem
    assert i < body.index("sb-verify-failed")
    assert "netinst" in body[i:] and "bb_finish" in body[i:]


def test_whole_iso_recipes_load_the_iso_through_initrd():
    assert 'bb_initrd "$bb_ird" "newc:beast-booter/alpine.iso:' in LIB
    assert 'bb_initrd "$bb_ird" "newc:beast-booter/debian.iso:' in LIB
    assert re.search(r'bb_initrd[^\n]*\n\s*fi\n\s*if \[ "\$bb_ok" != "1" \]; then\n\s*bb_fail initrd', LIB)
