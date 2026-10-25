"""build/grub/grubsrc.py: the check that proves a fix is in the GRUB source (its upstream
commit reverse-applies), and the consistency of the repo's GRUB inputs (patches/series,
security-fixes.json, upstream/*.patch). The full build is exercised by `make build`."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GRUB = ROOT / "build" / "grub"


def _load():
    spec = importlib.util.spec_from_file_location("bb_grubsrc", GRUB / "grubsrc.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gs = _load()
FIXES = json.loads((GRUB / "security-fixes.json").read_text())
SERIES = [ln.split("#", 1)[0].strip() for ln in (GRUB / "patches" / "series").read_text().splitlines()]
SERIES = [s for s in SERIES if s]

UPSTREAM_PATCH = """From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001
Subject: [PATCH] kern/x: Unregister on unload

---
 grub-core/kern/x.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/grub-core/kern/x.c b/grub-core/kern/x.c
index 1111111..2222222 100644
--- a/grub-core/kern/x.c
+++ b/grub-core/kern/x.c
@@ -1,4 +1,5 @@
 void fini (void)
 {
   grub_unregister_a (a);
+  grub_unregister_b (b);
 }
--
GitLab
"""
OLD = "void fini (void)\n{\n  grub_unregister_a (a);\n}\n"
NEW = "void fini (void)\n{\n  grub_unregister_a (a);\n  grub_unregister_b (b);\n}\n"


@pytest.fixture
def tree(tmp_path, monkeypatch):
    if not shutil.which("patch"):
        pytest.skip("needs patch(1)")
    up = tmp_path / "upstream"
    up.mkdir()
    (up / "0123456789abcdef0123456789abcdef01234567.patch").write_text(UPSTREAM_PATCH)
    monkeypatch.setattr(gs, "UPSTREAM", up)
    src = tmp_path / "src"
    (src / "grub-core" / "kern").mkdir(parents=True)
    return src


def test_fix_present_only_when_the_fixed_code_is_there(tree):
    ev = {"commit": "0123456789abcdef0123456789abcdef01234567"}
    (tree / "grub-core/kern/x.c").write_text(OLD)
    assert gs.fix_present(tree, ev)[0] is False
    (tree / "grub-core/kern/x.c").write_text(NEW)
    ok, detail = gs.fix_present(tree, ev)
    assert ok, detail
    # the dry run changes nothing
    assert (tree / "grub-core/kern/x.c").read_text() == NEW


def test_fix_present_files_filter_and_missing_file(tree):
    (tree / "grub-core/kern/x.c").write_text(NEW)
    ev = {"commit": "0123456789abcdef0123456789abcdef01234567", "files": ["grub-core/kern/y.c"]}
    ok, detail = gs.fix_present(tree, ev)
    assert not ok and "does not touch" in detail


def test_split_patch_stops_at_the_signature_and_drop_hunks():
    chunks = gs.split_patch((GRUB / "upstream" / "26beaa3b2720fefdc4d04c1ae209b776fe6848d6.patch").read_text())
    paths = [p for p, _ in chunks]
    assert "grub-core/term/serial.c" in paths and "include/grub/serial.h" in paths
    assert not any("GitLab" in c for _, c in chunks)
    serial = dict(chunks)["grub-core/term/serial.c"]
    kept, dropped = gs.drop_hunks(serial, "grub_serial_pl011_add_mmio")
    assert dropped == 1 and "grub_serial_pl011_add_mmio" not in kept and "grub_serial_reject_untrusted_address" in kept


def test_series_patches_have_a_note():
    assert SERIES, "build/grub/patches/series is empty"
    for name in SERIES:
        text = (GRUB / "patches" / name).read_text()
        head = text.split("\n---\n", 1)[0]
        assert head.startswith("Description: "), name
        assert re.search(r"(?m)^Origin: (upstream|vendor), https://", head), name


def test_every_fix_has_its_upstream_commit_and_patch():
    ids = set()
    for f in FIXES["fixes"]:
        assert f["id"] not in ids, f["id"]
        ids.add(f["id"])
        for ev in f["evidence"]:
            if ev.get("patch"):          # no upstream GRUB commit: our patch is the evidence
                assert not f["upstream_commits"] and f.get("vendor_commits"), f["id"]
                assert ev["patch"].removeprefix("patches/") in SERIES, f["id"]
                assert f["where"].startswith("build/grub/" + ev["patch"]), f["id"]
                continue
            assert ev["commit"] in f["upstream_commits"], f["id"]
            assert (GRUB / "upstream" / f"{ev['commit']}.patch").is_file(), f["id"]
        if f["where"].startswith("build/grub/patches/"):
            name = f["where"].removeprefix("build/grub/patches/").split()[0]
            assert name in SERIES, f"{f['id']}: {name} not in patches/series"
    for f in FIXES["fixes"]:
        assert f["evidence"], f"{f['id']}: no evidence"      # the build would refuse it (load_fixes)
    for claim in FIXES["sbat_claims"]:
        assert claim["requires"], claim
        assert set(claim["requires"]) <= ids, claim
        # only security fixes can earn an SBAT generation
        assert all(next(f for f in FIXES["fixes"] if f["id"] == r).get("type", "security") == "security"
                   for r in claim["requires"])


def test_shim_insecure_mode_fix_is_the_unmodified_upstream_commit():
    """patches/0002 (needed with shim 16 after `mokutil --disable-validation`) carries
    upstream 089d0567 unchanged, and the build checks for it on every run."""
    fix = next(f for f in FIXES["fixes"] if f["id"] == "GRUB-089d0567-shim-insecure-mode")
    assert fix["type"] == "defect" and "0002-" in fix["where"]
    ours = gs.split_patch((GRUB / "patches" / SERIES[1]).read_text())
    upstream = gs.split_patch((GRUB / "upstream" / "089d0567cee02464268cfc1c29830ab12dd17e68.patch").read_text())
    assert ours == upstream
    assert [p for p, _ in ours] == ["grub-core/kern/efi/init.c", "grub-core/kern/efi/sb.c", "include/grub/efi/sb.h"]


def test_peimage_loader_fix_is_debians_change():
    """patches/0003 makes exactly the change of Debian's salsa commit 8719ef8a, which edits
    debian/patches/secure-boot/efi-peimage.patch: there '++x' adds line x of peimage.c and
    '-+x' removes it. peimage registers its loader only when shim has no image loader
    protocol (shim 15.x keeps it); GRUB_MOD_FINI unregisters only what was registered."""
    fix = next(f for f in FIXES["fixes"] if f["id"] == "GRUB-DEBIAN-8719ef8a-peimage-loader")
    assert fix["type"] == "defect" and fix["evidence"] == [{"patch": "patches/" + SERIES[2]}]
    deb = (GRUB / "upstream" / "debian-8719ef8a523f2a89aeff1b86f5e14c3bba7a7d11.patch").read_text()
    deb_changes = [("+" if ln.startswith("++") else "-") + ln[2:]
                   for ln in deb.splitlines() if ln[:2] in ("++", "-+") and not ln.startswith("+++")]
    ours = gs.split_patch((GRUB / "patches" / SERIES[2]).read_text())
    assert [p for p, _ in ours] == ["grub-core/loader/efi/peimage.c"]
    hunks = ours[0][1].split("\n@@ ", 1)[1]
    our_changes = [ln for ln in hunks.splitlines()[1:] if ln[:1] in "+-"]
    assert deb_changes and our_changes == deb_changes
    assert "if (grub_efi_locate_protocol (&shim_loader_guid, 0) != NULL)\n+    return;" in hunks
    assert "+  if (registered)\n+    grub_efi_unregister_loader (&peimage_loader);" in hunks


# --------------------------------------------------------------------------- fail closed

def _fix(fid: str, evidence: list) -> dict:
    return {"id": fid, "where": "upstream GRUB 2.14 release", "upstream_commits": [], "evidence": evidence}


def _claim(gen: int, requires: list) -> dict:
    return {"component": "grub", "generation": gen, "shim_sbat_level": "x", "requires": requires}


def test_repo_inputs_load():
    assert gs.load_fixes()["sbat_claims"]
    assert gs.load_lock()["purl_distro"] == "ubuntu-26.10"


@pytest.mark.parametrize("fixes, claims, msg", [
    ([_fix("A", [])], [_claim(7, ["A"])], "has no evidence"),
    ([_fix("A", [{"commit": "c"}])], [_claim(7, [])], "requires no fixes"),
    ([_fix("A", [{"commit": "c"}])], [_claim(7, ["A", "B"])], "does not list"),
    ([dict(_fix("A", [{"commit": "c"}]), type="defect")], [_claim(7, ["A"])], "non-security"),
])
def test_load_fixes_rejects_what_would_prove_nothing(tmp_path, monkeypatch, fixes, claims, msg):
    p = tmp_path / "security-fixes.json"
    p.write_text(json.dumps({"schema": 1, "fixes": fixes, "sbat_claims": claims}))
    monkeypatch.setattr(gs, "FIXES", p)
    with pytest.raises(gs.Fail, match=msg):
        gs.load_fixes()


def test_check_fixes_fails_closed(tmp_path, monkeypatch):
    """Even past load_fixes: a fix with no evidence is not present, a claim needing no fix is not proven."""
    fx = {"schema": 1, "fixes": [_fix("NOEV", [])],
          "sbat_claims": [_claim(7, ["NOEV"]), _claim(8, [])]}
    monkeypatch.setattr(gs, "load_fixes", lambda: fx)
    r = gs.check_fixes(tmp_path)
    assert r["fixes"][0]["present"] is False and r["missing"] == ["NOEV"]
    assert [c["proven"] for c in r["sbat_claims"]] == [False, False]
    assert all(c["missing"] for c in r["sbat_claims"])


def _out(tmp_path: Path, fixes: list, claims: list) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    (out / "sbat.ubuntu.csv.in").write_text("sbat,1,SBAT Version,sbat,1,https://example\n"
                                            "grub,4,Free Software Foundation,grub,@UPSTREAM_VERSION@,https://x\n")
    info = {"schema": gs.INFO_SCHEMA, "version": "2.14-2ubuntu3+bb1", "upstream_version": "2.14",
            "source_version": "2.14-2ubuntu3",
            "files": {"sbat.ubuntu.csv.in": gs.sha256_file(out / "sbat.ubuntu.csv.in")},
            "security_fixes": {"fixes": fixes, "missing": [], "sbat_claims": claims}}
    (out / "build-info.json").write_text(json.dumps(info))
    return out


def _done(fid: str, evidence: list) -> dict:
    return {"id": fid, "present": True, "where": "w", "evidence": evidence}


@pytest.mark.parametrize("fixes, requires", [
    ([_done("A", [])], ["A"]),                                          # fix without evidence
    ([_done("A", [{"present": True}])], []),                            # claim without required fixes
    ([_done("A", [{"present": False}])], ["A"]),                        # evidence that failed
    ([_done("A", [{"present": True}])], ["A", "B"]),                    # required fix not recorded
])
def test_verify_rechecks_claims_fail_closed(tmp_path, fixes, requires):
    """A build-info.json that says proven is re-checked before sbat_lines raises the generation."""
    out = _out(tmp_path, fixes, [dict(_claim(6, requires), proven=True, missing=[])])
    with pytest.raises(gs.Fail, match="not proven"):
        gs.sbat_lines(out)


def test_sbat_lines_raise_the_proven_generation(tmp_path):
    out = _out(tmp_path, [_done("A", [{"present": True}])], [dict(_claim(6, ["A"]), proven=True, missing=[])])
    assert gs.sbat_lines(out)[1].startswith("grub,6,Free Software Foundation,grub,2.14,")


# --------------------------------------------------------------------------- BB_OFFLINE

def test_offline_never_downloads(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used with BB_OFFLINE=1")
    monkeypatch.setenv("BB_OFFLINE", "1")
    monkeypatch.setattr(gs.urllib.request, "urlopen", boom)
    monkeypatch.setattr(gs.subprocess, "run", boom)
    with pytest.raises(gs.Fail, match="BB_OFFLINE=1"):
        gs.fetch_url(["https://example.invalid/x"], tmp_path / "x.tar.xz", "0" * 64, None)
    e = {"package": "bison", "version": "2:3.8", "arch": "amd64", "sha256": "0" * 64}
    with pytest.raises(gs.Fail, match="BB_OFFLINE=1"):
        gs.fetch_deb(e, tmp_path / "dl")
    cached = tmp_path / "c.tar.xz"
    cached.write_bytes(b"data")
    assert gs.fetch_url(["https://example.invalid/c"], cached, gs.sha256_bytes(b"data"), 4) == cached
    with pytest.raises(gs.Fail, match="BB_OFFLINE=1"):
        gs.build_docker(gs.load_lock(), tmp_path / "cache", 1)


# --------------------------------------------------------------------------- generators, builders

def _tool(d: Path, name: str, body: str) -> None:
    p = d / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(0o755)


def test_unusable_generators_run_each_tool(tmp_path):
    for name in ("flex", "gawk", "autopoint"):
        _tool(tmp_path, name, f"echo '{name} 1.0'")
    _tool(tmp_path, "bison", "echo \"bison: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.38' not found\" >&2; exit 1")
    env = {"PATH": str(tmp_path)}  # only the fake tools: a gawk/bison on the host must not count
    bad = gs.unusable_generators(env, {"bison"})
    assert len(bad) == 1 and bad[0].startswith("bison (unpacked") and "GLIBC_2.38" in bad[0]
    (tmp_path / "gawk").unlink()
    assert any(b.startswith("gawk (not found)") for b in gs.unusable_generators(env, set()))


class _Docker(Exception):
    pass


def _build_args(tmp_path, builder):
    return argparse.Namespace(cache=str(tmp_path), jobs=1, builder=builder, builder_label=None, force=False)


def test_auto_uses_docker_when_generators_do_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "native_env", lambda lock, cache: ({"PATH": "/usr/bin"}, ["bison (unpacked ...)"]))
    monkeypatch.setattr(gs, "check_native", lambda env: [])

    def docker(*a):
        raise _Docker
    monkeypatch.setattr(gs, "build_docker", docker)
    with pytest.raises(_Docker):
        gs.cmd_build(_build_args(tmp_path, "auto"))
    with pytest.raises(gs.Fail, match=r"cannot build natively, missing: bison \(unpacked"):
        gs.cmd_build(_build_args(tmp_path, "native"))


def _elf(ptypes: list[int]) -> bytes:
    head = bytearray(64)
    head[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", head, 0x20, 64)
    struct.pack_into("<HH", head, 0x36, 56, len(ptypes))
    return bytes(head) + b"".join(struct.pack("<I", t) + bytes(52) for t in ptypes)


def test_elf_is_static(tmp_path):
    p = tmp_path / "a"
    p.write_bytes(_elf([6, 3, 1, 1, 2]))        # PHDR, INTERP, LOAD, LOAD, DYNAMIC: dynamic
    assert gs.elf_is_static(p) is False
    p.write_bytes(_elf([1, 1, 4, 7]))           # LOAD, LOAD, NOTE, TLS: static
    assert gs.elf_is_static(p) is True
    p.write_bytes(b"#!/bin/sh\n")
    with pytest.raises(gs.Fail):
        gs.elf_is_static(p)
    if Path("/bin/sh").is_file() and Path("/bin/sh").read_bytes()[:4] == b"\x7fELF":
        assert gs.elf_is_static(Path("/bin/sh").resolve()) is False


def test_check_mkimage_runs(tmp_path):
    (tmp_path / "bin").mkdir()
    _tool(tmp_path / "bin", "grub-mkimage", "echo 'grub-mkimage (GRUB) 2.14'")
    gs.check_mkimage_runs(tmp_path)
    _tool(tmp_path / "bin", "grub-mkimage", "echo \"version 'GLIBC_2.38' not found\" >&2; exit 1")
    with pytest.raises(gs.Fail, match="glibc too old"):
        gs.check_mkimage_runs(tmp_path)


# --------------------------------------------------------------------------- SBOM purl

def test_sbom_grub_purl_names_the_source_series():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("bb_gen_sbom", ROOT / "scripts" / "gen_sbom.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    assert gen.grub_purl_distro(ROOT, {}) == gs.load_lock()["purl_distro"] == "ubuntu-26.10"
    assert gen.grub_purl_distro(ROOT, {"purl_distro": "ubuntu-27.04"}) == "ubuntu-27.04"
    assert gen.grub_purl("2.14-2ubuntu3+bb1", "ubuntu-26.10") == (
        "pkg:deb/beastboot/grub2@2.14-2ubuntu3%2Bbb1?arch=amd64&distro=ubuntu-26.10&upstream=grub2-unsigned")
