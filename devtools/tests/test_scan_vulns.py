"""scripts/scan_vulns.py: the id of an SBAT revocation finding and what VEX may do with it.
(The scan as a whole is exercised by scripts/selftest.py on a built dist/.)"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import efi_inspect as efi  # noqa: E402
import scan_vulns as sv  # noqa: E402

GRUB = "file:esp/EFI/BOOT/grubx64.efi"
LEVELS = """
Revocations for:
 - November 2025 grub CVEs

sbat,1,2025112400
shim,4
grub,6

Revocations for:
 - September 2026 grub CVE (CVE-2026-97876)

sbat,1,2026092500
shim,4
grub,7
"""


def _finding(fid: str) -> dict:
    return {"id": fid, "aliases": [], "status": "open", "vex": None,
            "component": {"bom-ref": GRUB, "name": "esp/EFI/BOOT/grubx64.efi", "purl": None, "cpe": None}}


def _stmt(name: str, status: str = "fixed", **kw) -> dict:
    return {"vulnerability": {"name": name}, "products": [{"@id": GRUB}], "status": status,
            "timestamp": "2026-10-25T00:00:00Z", **kw}


def _vex_file(tmp_path: Path, statements: list) -> Path:
    p = tmp_path / "vex.openvex.json"
    p.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "t",
                             "timestamp": "2026-11-15T00:00:00Z", "version": 1, "statements": statements}))
    return p


def test_the_finding_id_names_the_required_generation():
    latest = efi.parse_sbat_level_variable_txt(LEVELS)[-1]["components"]["grub"]
    assert latest == 7
    assert sv.sbat_required(6, latest, 5, 5) == 7
    assert sv.sbat_finding_id("grub", sv.sbat_required(6, latest)) == "BB-SBAT-REVOKED-grub-7"
    assert sv.sbat_required(7, latest, 5, 5) is None, "grub,7 meets the level: no finding"
    assert sv.sbat_required(None, latest) is None
    assert sv.sbat_required(4, None, 5, 6) == 6, "the highest requirement above what is shipped"


def test_an_old_statement_does_not_close_a_later_revocation(tmp_path):
    """The statement that hid grub,7 on 2026-11-15: 'fixed', written when the level asked for
    grub,6, under the id without a generation. It is reported and ignored, and neither it nor
    a statement about grub,6 touches the finding for grub,7."""
    old = _stmt("BB-SBAT-REVOKED-grub", status_notes="embeds grub,6, which meets SbatLevel 2025112400")
    good, errs, _ = sv.load_vex(_vex_file(tmp_path, [old, _stmt("BB-SBAT-REVOKED-grub-6")]))
    assert [s["vulnerability"]["name"] for s in good] == ["BB-SBAT-REVOKED-grub-6"]
    assert len(errs) == 1 and "names no SBAT generation" in errs[0] and "statement ignored" in errs[0]
    f = _finding("BB-SBAT-REVOKED-grub-7")
    sv.apply_vex([f], [old, *good])           # even if the old one slipped past load_vex
    assert (f["status"], f["vex"]) == ("open", None)


def test_no_statement_calls_a_measured_revocation_fixed():
    """The finding exists only while the shipped binary is below the level, so 'fixed' and
    'not_affected' cannot be true for it; 'affected' with a plan is recorded and stays open."""
    f = _finding("BB-SBAT-REVOKED-grub-7")
    sv.apply_vex([f], [_stmt("BB-SBAT-REVOKED-grub-7"),
                       _stmt("BB-SBAT-REVOKED-grub-7", "not_affected", justification="vulnerable_code_not_present")])
    assert (f["status"], f["vex"]) == ("open", None)
    sv.apply_vex([f], [_stmt("BB-SBAT-REVOKED-grub-7", "affected", action_statement="claim grub,7 and rebuild")])
    assert f["status"] == "affected" and f["vex"]["action_statement"]
    other = _finding("BB-SHIM-UEFI-CA-2011-ONLY")      # other boot-chain findings take VEX as before
    sv.apply_vex([other], [_stmt("BB-SHIM-UEFI-CA-2011-ONLY")])
    assert other["status"] == "fixed"


def test_the_repo_vex_file_has_no_statement_the_scan_ignores():
    good, errs, meta = sv.load_vex(ROOT / "sbom" / "vex.openvex.json")
    assert not errs, errs
    assert len(good) == meta["statements"]
    sbat = [s["vulnerability"]["name"] for s in good if s["vulnerability"]["name"].startswith(sv.SBAT_REVOKED)]
    assert sbat == ["BB-SBAT-REVOKED-grub-6"], sbat
