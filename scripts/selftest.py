#!/usr/bin/env python3
"""Regression tests for the sbom-vuln scripts (no network, never touches the real sbom/).

    python3 -I scripts/selftest.py [--root DIR] [--keep]

Each test builds a scratch repository root in a temporary directory: a copy of dist/, the
repo files that dist/manifest.json names as repo:/key: origins (public files only - never
keys/*.key), the installer sources and sbom/vex.openvex.json; .tools/{bin,debs,root} are
symlinks to the real ones and .tools/cache starts EMPTY (only the pinned schemas are linked,
gen_sbom/validate_sbom need them). Then the real scripts run against it with --root.

  keys            every remediation key the scanner emits has a catalogue entry
  empty-cache     --offline with an empty cache: the report is still written, SBAT and dbx
                  say "not checked" (BB-*-NOT-CHECKED, R-DATA-UNAVAILABLE) and --fail-on exits 3
  stale-sbom      dist/ changed after gen_sbom -> BB-SBOM-STALE
  origin          one byte appended to a package file (manifest updated to match) -> gen_sbom
                  records MISMATCH, validate_sbom FAILs origin-verified, scan reports critical
                  BB-ORIGIN-MISMATCH; an edited repo file -> BB-ORIGIN-UNVERIFIED + warning
  modules         gettext / net (pulled in by normal) are never proposed for removal; a
                  directly requested, dependency-free module is
  coverage        the beast-net kernel (syft's purl, tracked via the linux source package),
                  initrd.img linked to every package it contains, one portable runtime per
                  target (pinned SHA-256) and a scannable CPython component
  kernel-vex      scripts/kernel_vex.py on a synthetic kernel tree: a file built into a module the
                  initramfs lacks, another architecture and an unset config -> not_affected; a
                  built-in file, a header (built-in includer / no includer), an unknown condition
                  and a module modules.order does not explain -> stay open
  gate            scripts/release/release_tool.py gate: only new findings at/above the
                  severity without a VEX statement block (baseline, --ignore-unfixed, warn)
  boot-chain      Debian's shim + MokManager have Debian purls (distro from the lock, sid
                  written as debian-unstable), the re-signed helper kernel is verified by
                  Authenticode digest, efi_inspect reads every signature (a copy of shim
                  with only its first one lacks the 2023 CA),
                  only the given CA is a trust anchor (not one in $SSL_CERT_DIR), --only
                  fails on an extra unparseable signature, and the offline scan finds both
                  Microsoft CAs (no BB-SHIM-UEFI-CA-2011-ONLY)
  debian-grype    a known-vulnerable shim (15.4-7) under each distro of debian-shim.lock, as
                  debinfo writes its purl, gets >= 1 grype match offline (skipped without
                  .tools/bin/grype or its DB)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, bool(ok), detail))
    print(f"selftest: {'PASS' if ok else 'FAIL'}  {name}" + (f" - {detail}" if detail and not ok else ""))
    return bool(ok)


def validate_python() -> str:
    """validate_sbom.py needs jsonschema + referencing, which .venv lacks: pick an
    interpreter that has them, like scripts/sbom-vuln.sh does."""
    for py in (sys.executable, shutil.which("python3"), "/usr/bin/python3", "/usr/local/bin/python3"):
        if py and Path(py).exists() and subprocess.run(
                [py, "-I", "-c", "import jsonschema, referencing"], capture_output=True).returncode == 0:
            return py
    return sys.executable


def run(*cmd, root: Path) -> subprocess.CompletedProcess:
    py = validate_python() if Path(str(cmd[0])).name == "validate_sbom.py" else sys.executable
    return subprocess.run([py, "-I", *map(str, cmd), "--root", str(root)],
                          capture_output=True, text=True, timeout=900)


def scratch_root(real: Path, base: Path, name: str) -> Path:
    r = base / name
    shutil.copytree(real / "dist", r / "dist")
    manifest = json.loads((r / "dist/manifest.json").read_text())
    for meta in manifest["files"].values():
        m = re.fullmatch(r"(?:repo|key):([^\s,]+)", meta["origin"].strip())
        # Only repo-relative origins belong in the scratch copy. In CI the signing
        # certificate's origin is an absolute temp path (BB_KEY_DIR); joining it
        # onto r would point back at the original file.
        if m and Path(m.group(1)).is_absolute():
            continue
        if m and not m.group(1).endswith(".key") and (real / m.group(1)).is_file():
            (r / m.group(1)).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real / m.group(1), r / m.group(1))
    shutil.copytree(real / "installer/beastbooter", r / "installer/beastbooter",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for f in ["README.md", "LICENSE", "VERSION", *[p.relative_to(real).as_posix()
                                                 for p in (real / "build").glob("early-*.cfg")]]:
        if (real / f).is_file():
            (r / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real / f, r / f)
    (r / "sbom").mkdir()
    shutil.copy2(real / "sbom/vex.openvex.json", r / "sbom/vex.openvex.json")
    (r / ".tools/cache").mkdir(parents=True)
    for d in ("bin", "debs", "root", "debian"):          # debian: build/shim/fetch.py
        if (real / ".tools" / d).exists():
            (r / ".tools" / d).symlink_to(real / ".tools" / d)
    (r / ".tools/cache/schemas").symlink_to(real / ".tools/cache/schemas")
    # beast-net .debs (build/beastnet/packages.lock) and the portable runtimes (runtimes.lock)
    for lock in ("build/beastnet/packages.lock", "packaging/portable/runtimes.lock", "build/shim/debian-shim.lock",
                 "build/shim/microsoft-uefi-ca-2011.pem", "build/shim/microsoft-uefi-ca-2023.pem",
                 "build/grub/source.lock.json"):                  # gen_sbom: the GRUB purl distro
        if (real / lock).is_file():
            (r / lock).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real / lock, r / lock)
    for cache in ("beastnet", "pbs", "grub-src"):     # grub-src: build-info.json of the GRUB source build
        if (real / ".tools/cache" / cache).is_dir():
            (r / ".tools/cache" / cache).symlink_to(real / ".tools/cache" / cache)
    return r


def report(root: Path) -> dict:
    return json.loads((root / "sbom/vulnerabilities.json").read_text())


def by_id(rep: dict) -> dict:
    return {f["id"]: f for f in rep["findings"]}


def test_keys() -> None:
    import scan_vulns as sv
    src = (HERE / "scan_vulns.py").read_text()
    used = set(re.findall(r'"(R-[A-Z0-9-]+)"', src))
    missing = sorted(used - set(sv.REMEDIATION_TEXT))
    check("keys: every quoted remediation key has catalogue text", not missing, f"missing {missing}")


def test_empty_cache(root: Path) -> None:
    g = run(HERE / "gen_sbom.py", root=root)
    if not check("empty-cache: gen_sbom", g.returncode == 0, g.stderr[-500:]):
        return
    for f in ("vulnerabilities.json", "VULNERABILITIES.md"):
        (root / "sbom" / f).unlink(missing_ok=True)
    s = run(HERE / "scan_vulns.py", "--offline", "--fail-on", "critical", root=root)
    check("empty-cache: scan does not crash", "Traceback" not in s.stderr, s.stderr[-800:])
    check("empty-cache: --fail-on exits 3 (checks not run)", s.returncode == 3, f"rc={s.returncode}")
    ok = (root / "sbom/vulnerabilities.json").is_file() and (root / "sbom/VULNERABILITIES.md").is_file()
    if not check("empty-cache: report written", ok):
        return
    rep = report(root)
    f = by_id(rep)
    for fid in ("BB-SBAT-NOT-CHECKED", "BB-DBX-NOT-CHECKED"):
        x = f.get(fid)
        check(f"empty-cache: {fid} reported with R-DATA-UNAVAILABLE",
              x is not None and x["remediation_key"] == "R-DATA-UNAVAILABLE" and x["remediation"],
              json.dumps(x)[:300] if x else "absent")
    check("empty-cache: catalogue has R-DATA-UNAVAILABLE",
          bool(rep["remediation_catalogue"].get("R-DATA-UNAVAILABLE")))
    md = (root / "sbom/VULNERABILITIES.md").read_text()
    check("empty-cache: markdown says not checked", "not checked" in md and "### R-DATA-UNAVAILABLE" in md)
    s0 = run(HERE / "scan_vulns.py", "--offline", root=root)
    check("empty-cache: without --fail-on exits 0", s0.returncode == 0, f"rc={s0.returncode} {s0.stderr[-300:]}")
    sc = report(root)["boot_chain"]["signers"].get("shim_ca") or {}
    check("boot-chain: offline scan verifies shim through both Microsoft UEFI CAs, one digest",
          sc.get("uefi_ca_2011") and sc.get("uefi_ca_2023") and sc.get("one_digest")
          and isinstance(sc.get("verified_with"), list), json.dumps(sc)[:400])
    check("boot-chain: no BB-SHIM-UEFI-CA-2011-ONLY", "BB-SHIM-UEFI-CA-2011-ONLY" not in by_id(report(root)))


def test_boot_chain(real: Path, base: Path) -> None:
    """Debian's shim in the SBOM, the re-signed helper kernel, every signature read."""
    import contextlib
    import io
    import struct

    import efi_inspect as efi
    cdx = json.loads((real / "sbom/beast-boot.cdx.json").read_text())

    def walk(cs):
        for c in cs or []:
            yield c
            yield from walk(c.get("components"))
    comps = list(walk(cdx["components"]))
    lock = {}
    for line in (real / "build/shim/debian-shim.lock").read_text().splitlines():
        x = line.split("#", 1)[0].split()
        if len(x) >= 6:
            lock[x[0]] = (x[1], x[4])
    import debinfo as deb
    for pkg, (ver, lock_distro) in sorted(lock.items()):
        distro = deb.purl_distro(lock_distro)       # debian-sid -> debian-unstable (grype ignores sid)
        purls = [c.get("purl", "") for c in comps if c.get("purl", "").startswith(f"pkg:deb/debian/{pkg}@")]
        check(f"boot-chain: {pkg} is pkg:deb/debian/...@{ver}?distro={distro}",
              len(purls) == 1 and purls[0].startswith(f"pkg:deb/debian/{pkg}@{ver.replace('+', '%2B')}?")
              and f"distro={distro}" in purls[0], str(purls))
    check("boot-chain: no Ubuntu shim-signed in the SBOM",
          not [c for c in comps if c.get("purl", "").startswith("pkg:deb/ubuntu/shim-signed@")])
    manifest = json.loads((real / "dist/manifest.json").read_text())
    if "esp/beast-net/vmlinuz" in manifest["files"]:
        k = next((c for c in comps if c["name"] == "esp/beast-net/vmlinuz"), {})
        props = {p["name"]: p["value"] for p in k.get("properties", [])}
        check("boot-chain: helper kernel marked re-signed, verified by Authenticode digest",
              "beast-boot:re-signed" in props
              and props.get("beast-boot:origin-verified", "").startswith("authenticode sha256 matches"),
              str(props)[:400])
    shim = real / "dist/esp/EFI/BOOT/BOOTX64.EFI"
    cas = [f"Microsoft Corporation UEFI CA 2011={real / 'build/shim/microsoft-uefi-ca-2011.pem'}",
           f"Microsoft UEFI CA 2023={real / 'build/shim/microsoft-uefi-ca-2023.pem'}"]
    with contextlib.redirect_stdout(io.StringIO()):
        probs = efi.require(shim, cas, None, None)
    check("boot-chain: efi_inspect require passes for the shipped shim", probs == [], str(probs))
    data = bytearray(shim.read_bytes())
    pe = efi.parse_pe(bytes(data))
    first = (struct.unpack_from("<I", data, pe.cert_off)[0] + 7) & ~7
    one = data[:pe.cert_off + first]
    struct.pack_into("<II", one, pe.certdir_off, pe.cert_off, first)
    cut = base / "shim-first-signature-only.efi"
    cut.write_bytes(bytes(one))
    with contextlib.redirect_stdout(io.StringIO()):
        probs = efi.require(cut, cas, None, None)
    check("boot-chain: shim with only its first signature lacks the 2023 CA",
          len(probs) == 1 and "Microsoft UEFI CA 2023" in probs[0], str(probs))

    # The CA given is the only trust anchor: a certificate in OpenSSL's default store
    # ($SSL_CERT_DIR) must not count. Here our MOK certificate is put there, so grubx64.efi
    # (signed by it) would otherwise "chain to" Microsoft UEFI CA 2023.
    grub, mok = real / "dist/esp/EFI/BOOT/grubx64.efi", base / "mok.pem"
    subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(real / "dist/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer"),
                    "-out", str(mok)], check=True, capture_output=True)
    store = base / "ssl-cert-dir"
    store.mkdir()
    h = subprocess.run(["openssl", "x509", "-hash", "-noout", "-in", str(mok)],
                       check=True, capture_output=True, text=True).stdout.strip()
    shutil.copy(mok, store / f"{h}.0")
    old = os.environ.get("SSL_CERT_DIR")
    os.environ["SSL_CERT_DIR"] = str(store)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            probs = efi.require(grub, cas[1:], None, None)
    finally:
        if old is None:
            os.environ.pop("SSL_CERT_DIR", None)
        else:
            os.environ["SSL_CERT_DIR"] = old
    check("boot-chain: a certificate in $SSL_CERT_DIR is not a trust anchor",
          len(probs) == 1 and "Microsoft UEFI CA 2023" in probs[0], str(probs))

    # --only (exactly one signature, ours) also counts entries the parser cannot read:
    # grubx64.efi plus a BER (indefinite-length) PKCS#7 entry, which shim's OpenSSL would read.
    data = bytearray(grub.read_bytes())
    pe = efi.parse_pe(bytes(data))
    body = b"\x30\x80\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02\x00\x00"
    entry = struct.pack("<IHH", 8 + len(body), 0x0200, 0x0002) + body
    entry += b"\0" * (-len(entry) % 8)
    two = data[:pe.cert_off + pe.cert_size] + entry
    struct.pack_into("<II", two, pe.certdir_off, pe.cert_off, pe.cert_size + len(entry))
    ber = base / "grub-plus-ber-signature.efi"
    ber.write_bytes(bytes(two))
    with contextlib.redirect_stdout(io.StringIO()):
        ok_probs = efi.require(grub, [], f"beast-boot={mok}", None)
        probs = efi.require(ber, [], f"beast-boot={mok}", None)
    check("boot-chain: --only passes for grubx64.efi", ok_probs == [], str(ok_probs))
    check("boot-chain: --only fails with a second, unparseable signature",
          any("cannot read every signature" in p for p in probs)
          and any("2 signatures, expected exactly one" in p for p in probs), str(probs))


def test_debian_grype(real: Path, base: Path) -> None:
    """A Debian purl as debinfo writes it is matched by grype: shim 15.4-7 (CVE-2022-28737,
    CVE-2023-40546, ...) under each distro of build/shim/debian-shim.lock gets >= 1 match.
    With distro=debian-sid grype matched nothing, and Debian's shim went unscanned."""
    import debinfo as deb
    grype = real / ".tools/bin/grype"
    cache = real / ".tools/cache/grype"
    if not grype.is_file():
        print("selftest: SKIP  debian-grype - .tools/bin/grype missing (scripts/install-tools.sh)")
        return
    if not list(cache.glob("*/vulnerability.db")):
        print(f"selftest: SKIP  debian-grype - no grype DB in {cache} (sbom-vuln.sh scan, online, once)")
        return
    distros = sorted({v[2] for v in deb.debian_lock(real).values()})
    if not check("debian-grype: build/shim/debian-shim.lock names a distro", bool(distros)):
        return
    env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(cache), GRYPE_DB_AUTO_UPDATE="false",
               GRYPE_CHECK_FOR_APP_UPDATE="false", GRYPE_DB_VALIDATE_AGE="false")
    for distro in distros:
        p = deb.source_purl("shim", "15.4-7", distro, namespace="debian")
        f = base / f"grype-purl-{distro}.txt"
        f.write_text(p + "\n")
        r = subprocess.run([str(grype), f"purl:{f}", "-o", "json"], capture_output=True, text=True,
                           env=env, timeout=600)
        try:
            ids = sorted({m["vulnerability"]["id"] for m in json.loads(r.stdout)["matches"]})
        except (ValueError, KeyError, TypeError):
            ids = None
        check(f"debian-grype: {p} has grype matches (lock distro {distro})", bool(ids),
              f"rc={r.returncode} matches={ids} {r.stderr.strip()[-300:]}")


def tamper(root: Path, rel: str) -> None:
    mpath = root / "dist/manifest.json"
    m = json.loads(mpath.read_text())
    p = root / "dist" / rel
    p.write_bytes(p.read_bytes() + b"\0")
    m["files"][rel]["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
    m["files"][rel]["size"] = p.stat().st_size
    if "sha1" in m["files"][rel]:
        m["files"][rel]["sha1"] = hashlib.sha1(p.read_bytes()).hexdigest()
    mpath.write_text(json.dumps(m, indent=2) + "\n")


def test_origin(root: Path) -> None:
    g = run(HERE / "gen_sbom.py", root=root)
    if not check("origin: baseline gen_sbom", g.returncode == 0, g.stderr[-500:]):
        return
    v = run(HERE / "validate_sbom.py", root=root)
    check("origin: baseline validate PASS (incl. origin-verified)",
          v.returncode == 0 and "PASS  origin-verified" in v.stdout, v.stdout[-600:] + v.stderr[-600:])
    manifest = json.loads((root / "dist/manifest.json").read_text())
    # a GRUB module (from the GRUB source build, or a package in older dists), else any package file
    rel = next((r for r, x in sorted(manifest["files"].items())
                if x["origin"].startswith(("grub-src:", "deb:")) and r.endswith("normal.mod")), None) or \
        next(r for r, x in sorted(manifest["files"].items()) if x["origin"].startswith("deb:"))
    repo_rel = next((r for r, x in sorted(manifest["files"].items()) if x["origin"].startswith("repo:")), None)
    tamper(root, rel)
    # the SBOM now describes the old manifest
    s = run(HERE / "scan_vulns.py", "--offline", root=root)
    f = by_id(report(root)) if (root / "sbom/vulnerabilities.json").is_file() else {}
    check("stale-sbom: BB-SBOM-STALE raised", "BB-SBOM-STALE" in f, s.stderr[-400:])
    if repo_rel:
        src = root / manifest["files"][repo_rel]["origin"].split(":", 1)[1]
        src.write_text(src.read_text() + "\n# edited after the build\n")
    g = run(HERE / "gen_sbom.py", root=root)
    check("origin: gen_sbom flags PROVENANCE ERROR", g.returncode == 0 and "PROVENANCE ERROR" in g.stderr
          and rel in g.stderr, g.stderr[-500:])
    cdx = json.loads((root / "sbom/beast-boot.cdx.json").read_text())

    def walk(cs):
        for c in cs or []:
            yield c
            yield from walk(c.get("components"))
    comp = next(c for c in walk(cdx["components"]) if c["name"] == rel)
    ov = {p["name"]: p["value"] for p in comp.get("properties", [])}.get("beast-boot:origin-verified", "")
    check("origin: SBOM property says MISMATCH", ov.startswith("MISMATCH"), ov)
    v = run(HERE / "validate_sbom.py", root=root)
    val = json.loads((root / "sbom/validation.json").read_text())["checks"]["origin-verified"]
    check("origin: validate_sbom FAILs origin-verified (rc 1)",
          v.returncode == 1 and val["result"] == "FAIL" and any(rel in x for x in val["detail"]["mismatch"]),
          json.dumps(val)[:500])
    if repo_rel:
        check("origin: edited repo file listed as a validation warning",
              any(repo_rel in x and "DRIFT" in x for x in val["detail"]["repo_warnings"]), json.dumps(val)[:500])
    s = run(HERE / "scan_vulns.py", "--offline", root=root)
    f = by_id(report(root))
    x = f.get("BB-ORIGIN-MISMATCH")
    check("origin: scan reports critical BB-ORIGIN-MISMATCH (R-ORIGIN)",
          x is not None and x["severity"] == "critical" and x["remediation_key"] == "R-ORIGIN"
          and rel in x["description"], json.dumps(x)[:400] if x else s.stderr[-400:])
    check("origin: provenance counts it", any(m["file"] == rel for m in
                                             report(root)["boot_chain"]["provenance"]["origin_mismatch"]))
    check("origin: BB-SBOM-STALE gone after regenerating", "BB-SBOM-STALE" not in f)
    if repo_rel:
        y = f.get("BB-ORIGIN-UNVERIFIED")
        check("origin: edited repo file -> BB-ORIGIN-UNVERIFIED", y is not None and repo_rel in y["description"],
              json.dumps(y)[:300] if y else "absent")
    md = (root / "sbom/VULNERABILITIES.md").read_text()
    check("origin: markdown shows the mismatch", "BB-ORIGIN-MISMATCH" in md and "**1 not identical" in md)


def test_modules(real: Path) -> None:
    import scan_vulns as sv
    dist = real / "dist"
    manifest = json.loads((dist / "manifest.json").read_text())
    bom, idx = sv.load_sbom(real / "sbom/beast-boot.cdx.json")
    mods = sv.grub_modules(real, dist, manifest, idx)
    if not check("modules: moddep.lst of the EFI modules verified", mods.get("efi_deps") is not None,
                 mods.get("efi_closure_source", "")):
        return
    for mod in ("gettext", "net"):
        if mod not in mods["efi"]:
            continue
        w = sv.module_removability(mod, mods)
        check(f"modules: {mod} not removable (pulled in by normal)",
              w["removable"] is False and "normal" in (w["pulled_in_by"] or []), json.dumps(w))
    # the GRUB source build (grub-src:grub2@<version>), or the Ubuntu package in older dists
    efi_comp = next((c for c in idx.values() if c["ref"].startswith("grub-src:") and c["role"] == "shipped"), None) \
        or next((c for c in idx.values() if c["name"] == "grub-efi-amd64-bin" and c["role"] == "shipped"), None)
    if efi_comp is None:
        check("modules: the GRUB component (grub-src:grub2@...) in SBOM", False)
        return

    def fake(title):
        f = {"id": "CVE-0000-0001", "aliases": [], "scope": "shipped", "fix": {"versions": []}, "evidence": [],
             "title": title, "description": title, "severity": "high",
             "component": {"bom-ref": efi_comp["ref"], "name": efi_comp["name"], "purl": efi_comp["purl"]}}
        f["grub_modules"] = sv.grub_module_hint(f, [], mods)
        return sv.remediation(f, idx, "test", {})
    for mod in ("gettext", "net"):
        if mod not in mods["efi"]:
            continue
        key, txt = fake(f"use-after-free in GRUB's {mod} module")
        check(f"modules: {mod} remediation does not propose dropping it",
              key == "R-GRUB-EMBEDDED" and "cannot be removed" in txt and "propose dropping" not in txt,
              f"{key}: {txt[:400]}")
    cand = next((m for m in sorted(mods["efi_requested"])
                 if (w := sv.module_removability(m, mods))["removable"] and m in mods["bios"]), None)
    if cand:
        key, txt = fake(f"heap overflow in GRUB's {cand} module")
        check(f"modules: removable {cand} still gets the drop option",
              key == "R-GRUB-EMBEDDED" and f"propose dropping {cand}" in txt, f"{key}: {txt[:300]}")


def test_coverage(real: Path) -> None:
    """beast-net and portable runtimes in the SBOM gen_sbom wrote for the real dist/."""
    import gen_sbom
    o = gen_sbom.parse_origin("built:x from deb:a=1.0-1, deb:b=2:3.4~5.1; 9 modules of deb:c=7.0-1.1 + depmod")
    check("coverage: origin parser keeps a package followed by ';'",
          [d["name"] for d in o["debs"]] == ["a", "b", "c"], str(o["debs"]))
    cdx = json.loads((real / "sbom/beast-boot.cdx.json").read_text())

    def walk(cs, parent=None):
        for c in cs or []:
            yield c, parent
            yield from walk(c.get("components"), c)
    comps = {c["bom-ref"]: (c, p) for c, p in walk(cdx["components"])}
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in cdx["dependencies"]}
    manifest = json.loads((real / "dist/manifest.json").read_text())
    if "esp/beast-net/vmlinuz" in manifest["files"]:
        ks = [(c, p) for c, p in comps.values() if c["bom-ref"].startswith("kernel:")]
        ok = len(ks) == 1 and ks[0][0]["purl"].startswith("pkg:generic/linux-kernel@") and \
            (ks[0][1] or {}).get("name", "").startswith("linux-image-") and "cpe" not in ks[0][0]
        check("coverage: beast-net kernel component (syft's purl, under linux-image, no CPE)", ok,
              str([c["bom-ref"] for c, _ in ks]))
        if ks:
            check("coverage: kernel tracked through the Ubuntu linux source package",
                  any(r.startswith("deb-src:linux@") for r in deps.get(ks[0][0]["bom-ref"], ())),
                  str(deps.get(ks[0][0]["bom-ref"])))
        init = next(c for c, _ in comps.values() if c["name"] == "esp/beast-net/initrd.img")
        want = {f"deb:{d['name']}@{d['version']}" for d in
                gen_sbom.parse_origin(manifest["files"]["esp/beast-net/initrd.img"]["origin"])["debs"]}
        missing = sorted(want - deps.get(init["bom-ref"], set()))
        check("coverage: initrd.img linked to every package of its origin", not missing and len(want) > 5,
              f"{len(want)} packages, missing {missing[:5]}")
    if (real / "packaging/portable/runtimes.lock").is_file():
        lock = json.loads((real / "packaging/portable/runtimes.lock").read_text())
        rts = [c for c, _ in comps.values() if c["bom-ref"].startswith("runtime:python-build-standalone")]
        hashes = {h["content"] for c in rts for h in c.get("hashes", [])}
        check("coverage: one portable runtime per target, with its pinned SHA-256",
              len(rts) == len(lock["targets"]) and hashes == {t["sha256"] for t in lock["targets"].values()},
              f"{len(rts)} runtimes")
        py = comps.get(f"runtime:cpython@{lock['python']}", ({}, None))[0]
        check("coverage: CPython component with a CPE (scannable)", "python:python" in py.get("cpe", ""), str(py)[:200])


def test_kernel_vex(base: Path) -> None:
    import kernel_vex as kv
    mk = {
        "Kbuild": "obj-y += drivers/\nobj-y += arch/$(SRCARCH)/\n",
        "Makefile": "",
        "arch/x86/Makefile": "libs-y += arch/x86/lib/\n",
        "arch/x86/Kbuild": "obj-y += kernel/\n",
        "arch/x86/kernel/Makefile": "obj-y += setup.o\n",
        "arch/arm64/kernel/Makefile": "obj-y += cpu.o\n",
        "drivers/Makefile": "obj-y += net/\nobj-$(CONFIG_FOO) += foo/\n",
        "drivers/net/Makefile": ("obj-$(CONFIG_SHIPPED) += shipped.o\n"
                                 "obj-$(CONFIG_NOTSHIPPED) += big.o\n"
                                 "big-y := big_main.o\nbig-$(CONFIG_BIG_EXTRA) += big_util.o\n"
                                 "obj-$(CONFIG_CORE) += core.o\n"
                                 "obj-$(CONFIG_UNSET) += gone.o\n"
                                 "ifeq ($(call cc-option,-x),)\nobj-y += maybe.o\nendif\n"
                                 "obj-$(CONFIG_ODD) += odd.o\n"),
        "drivers/foo/Makefile": "obj-y += foo.o\n",
    }
    files = set(mk) | {"arch/x86/kernel/setup.c", "arch/arm64/kernel/cpu.c", "arch/arm64/include/asm/cpu.h",
                       "drivers/foo/foo.c", "Documentation/net.rst"} | \
        {f"drivers/net/{n}" for n in ("shipped.c", "big_main.c", "big_util.c", "core.c", "gone.c", "maybe.c",
                                      "odd.c", "big.h", "common.h", "only.h")}
    inc = {"drivers/net/big_main.c": ['q:big.h', 'q:common.h'], "drivers/net/core.c": ['q:common.h'],
           "arch/arm64/kernel/cpu.c": ["a:asm/cpu.h"], "arch/x86/kernel/setup.c": ["a:asm/cpu.h"]}
    tree = kv.Tree(files, mk, inc)
    cfg = {"CONFIG_SHIPPED": "m", "CONFIG_NOTSHIPPED": "m", "CONFIG_BIG_EXTRA": "y", "CONFIG_CORE": "y",
           "CONFIG_ODD": "m"}
    order = {"kernel/drivers/net/shipped.ko", "kernel/drivers/net/big.ko", "kernel/drivers/net/odd.ko",
             "kernel/drivers/net/ghost.ko"}
    b = kv.Build(tree, cfg, order, {"kernel/drivers/net/core.ko"}, {"kernel/drivers/net/shipped.ko"})
    # ghost.ko is not derivable -> drivers/net becomes opaque; rerun with a consistent modules.order
    check("kernel-vex: self-check flags a module the Makefiles do not explain",
          any("ghost.ko" in m for m in b.mismatch) and b.classify("drivers/net/big_util.c")[0] == "unknown",
          json.dumps(b.mismatch))
    b = kv.Build(tree, cfg, order - {"kernel/drivers/net/ghost.ko"}, {"kernel/drivers/net/core.ko"},
                 {"kernel/drivers/net/shipped.ko"})
    st = {p: b.classify(p) for p in sorted(files)}
    check("kernel-vex: module not in the initramfs -> not present",
          st["drivers/net/big_util.c"][:2] == ("absent", "module-not-shipped") and "big.ko" in
          st["drivers/net/big_util.c"][2] and "CONFIG_NOTSHIPPED=m" in st["drivers/net/big_util.c"][2],
          str(st["drivers/net/big_util.c"]))
    check("kernel-vex: shipped module -> present", st["drivers/net/shipped.c"][0] == "present")
    check("kernel-vex: built-in -> present", st["drivers/net/core.c"][:2] == ("present", "built-in"))
    check("kernel-vex: other architecture -> not present", st["arch/arm64/kernel/cpu.c"][1] == "other-arch")
    check("kernel-vex: renamed/missing file of another architecture -> not present",
          b.classify("arch/s390/kvm/interrupt.c")[:2] == ("absent", "other-arch") and
          b.classify("arch/x86/kvm/missing.c")[0] == "unknown", str(b.classify("arch/s390/kvm/interrupt.c")))
    check("kernel-vex: unset config -> not present",
          st["drivers/net/gone.c"][:2] == ("absent", "config-not-set") and "CONFIG_UNSET is not set" in
          st["drivers/net/gone.c"][2], str(st["drivers/net/gone.c"]))
    check("kernel-vex: unreached directory -> not present", st["drivers/foo/foo.c"][1] == "dir-not-built")
    check("kernel-vex: unknown condition -> present (may be built)", st["drivers/net/maybe.c"][0] == "present")
    check("kernel-vex: header with a built-in includer -> present", st["drivers/net/common.h"][0] == "present")
    check("kernel-vex: header without includer -> unknown", st["drivers/net/only.h"][0] == "unknown")
    check("kernel-vex: <asm/..> header of another arch -> not present",
          st["arch/arm64/include/asm/cpu.h"][0] == "absent", str(st["arch/arm64/include/asm/cpu.h"]))
    rec = lambda *pf: {"containers": {"cna": {"affected": [{"programFiles": list(pf)}]}}}  # noqa: E731
    recs = {"CVE-1": rec("drivers/net/big_util.c", "drivers/net/big.h"), "CVE-2": rec("drivers/net/core.c"),
            "CVE-3": rec("drivers/net/only.h"), "CVE-4": rec("arch/arm64/kernel/cpu.c", "Documentation/net.rst"),
            "CVE-5": rec("drivers/net/big_main.c", "drivers/net/common.h"), "CVE-6": {"containers": {"cna": {}}}}
    res = {e["id"]: e["classification"] for e in kv.classify_cves(b, sorted(recs) + ["CVE-7"], recs)}
    check("kernel-vex: CVE classification (all files absent -> not_present, else open)",
          res == {"CVE-1": "not_present", "CVE-2": "present", "CVE-3": "unresolved", "CVE-4": "not_present",
                  "CVE-5": "present", "CVE-6": "unresolved", "CVE-7": "unresolved"}, json.dumps(res))
    bin_res = kv.classify_cves(b, ["CVE-1"], recs, {"vmlinux": ["drivers/net/big_util.c"], "modules": {}})
    check("kernel-vex: path found in the shipped binary overrides not_present",
          bin_res[0]["classification"] == "unresolved")

    # fixed in the shipped kernel: CNA fix version vs the upstream base, Ubuntu tracker vs the series
    mkf = "VERSION = 7\nPATCHLEVEL = {}\nSUBLEVEL = {}\nEXTRAVERSION = {}\nNAME = x\n"
    rc6, stable = kv.upstream_base(mkf.format(3, 0, "-rc6")), kv.upstream_base(mkf.format(0, 14, ""))
    check("kernel-vex: upstream base from the top-level Makefile (rc and stable)",
          rc6 and rc6["tag"] == "v7.3-rc6" and rc6["rc"] == 6 and stable and stable["tag"] == "v7.0.14"
          and kv.upstream_base(mkf.format(3, 0, "-ubuntu")) is None, f"{rc6} {stable}")

    def fixrec(*vers):
        return {"containers": {"cna": {"affected": [{"versions": [dict(zip(("version", "lessThanOrEqual", "versionType"),
                                                                            v), status="unaffected") for v in vers]}]}}}
    main = lambda v: ("" if v is None else v, "*", "original_commit_for_fix")  # noqa: E731
    check("kernel-vex: mainline fix in an earlier release -> fixed",
          (kv.cna_fix(fixrec(main("7.2")), rc6) or {}).get("rule") == "mainline")
    check("kernel-vex: mainline fix in the base's own release, base is -rcN -> not fixed",
          kv.cna_fix(fixrec(main("7.3")), rc6) is None and kv.cna_fix(fixrec(main("7.4")), stable) is None)
    check("kernel-vex: mainline fix in the base's release, base is that release + stable -> fixed",
          kv.cna_fix(fixrec(main("7.0")), stable) is not None)
    check("kernel-vex: stable-branch fix <= base SUBLEVEL -> fixed, later or other branch -> not",
          (kv.cna_fix(fixrec(("7.0.9", "7.0.*", "semver")), stable) or {}).get("rule") == "stable"
          and kv.cna_fix(fixrec(("7.0.15", "7.0.*", "semver"), main("7.1")), stable) is None
          and kv.cna_fix(fixrec(("7.3.1", "7.3.*", "semver")), rc6) is None)
    check("kernel-vex: Debian version order",
          kv.deb_vercmp("7.3.0-5.5", "7.3.0-9.9") < 0 and kv.deb_vercmp("7.3.0-10.10", "7.3.0-9.9") > 0
          and kv.deb_vercmp("1.0~rc1-1", "1.0-1") < 0 and kv.deb_vercmp("1:0.1", "2.0") > 0
          and kv.deb_vercmp("7.0.0-38.38", "7.0.0-38.38") == 0)
    tr = {"updated_at": "x", "linux": [{"release_codename": "stonking", "status": "not-affected", "description": "7.3.0-5.5"},
                                       {"release_codename": "resolute", "status": "released", "description": "7.0.0-38.38"}]}
    check("kernel-vex: tracker released/not-affected <= shipped in the shipped series -> fixed",
          (kv.tracker_fix(tr, "stonking", "7.3.0-9.9") or {}).get("version") == "7.3.0-5.5"
          and kv.tracker_fix(tr, "resolute", "7.0.0-38.38") is not None)
    check("kernel-vex: tracker pending/needed, newer version, other series or no version -> open",
          kv.tracker_fix({"linux": [{"release_codename": "stonking", "status": "pending", "description": "7.3.0-9.9"},
                                    {"release_codename": "tenacious", "status": "released", "description": "7.3.0-1.1"}]},
                         "stonking", "7.3.0-9.9") is None
          and kv.tracker_fix({"linux": [{"release_codename": "stonking", "status": "released",
                                         "description": "7.3.0-10.10"}]}, "stonking", "7.3.0-9.9") is None
          and kv.tracker_fix({"linux": [{"release_codename": "stonking", "status": "not-affected",
                                         "description": "code not present"}]}, "stonking", "7.3.0-9.9") is None)
    pubs = {"publications": [{"series": "stonking", "pocket": "Proposed", "status": "Published"},
                             {"series": "tenacious", "pocket": "Release", "status": "Published"}],
            "series": {"stonking": {"version": "26.10"}, "tenacious": {"version": "27.04"}}}
    check("kernel-vex: shipped series = purl distro, released pockets only (never -proposed)",
          kv.shipped_series(pubs, "ubuntu-26.10") is None
          and (kv.shipped_series(pubs, "ubuntu-27.04") or {}).get("codename") == "tenacious")
    cfg_ok = {"CONFIG_SECURITY_LOCKDOWN_LSM": "y", "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY": "y",
              "CONFIG_LOCK_DOWN_IN_SECURE_BOOT": "y"}
    src_ok = {"arch/x86/kernel/setup.c": 'x\n\tsecurity_lock_kernel_down("EFI Secure Boot mode", LOCKDOWN_INTEGRITY_MAX);\n'}
    st_ok = kv.vendor_specific("CVE-2025-1272", cfg_ok, src_ok) or ""
    check("kernel-vex: vendor-specific CVE closed only when config and source both hold",
          "arch/x86/kernel/setup.c:2" in st_ok
          and kv.vendor_specific("CVE-2025-1272", dict(cfg_ok, CONFIG_LOCK_DOWN_IN_SECURE_BOOT="n"), src_ok) is None
          and kv.vendor_specific("CVE-2025-1272", cfg_ok, {}) is None
          and kv.vendor_specific("CVE-1", cfg_ok, src_ok) is None, st_ok[:120])


def test_gate(base: Path) -> None:
    """scripts/release/release_tool.py gate: blocks only NEW findings >= severity without VEX."""
    tool = HERE / "release" / "release_tool.py"
    if not tool.is_file():
        return

    def fnd(i, sev="critical", status="open", scope="shipped", fix=()):
        return {"id": i, "severity": sev, "status": status, "scope": scope, "source": "scanner",
                "component": {"name": "pkg", "version": "1"}, "fix": {"versions": list(fix)}}
    rep = base / "gate-report.json"

    def gate(findings, *extra):
        rep.write_text(json.dumps({"findings": findings}))
        r = subprocess.run([sys.executable, "-I", str(tool), "gate", "--report", str(rep),
                            "--out", str(base / "gate.json"), *extra], capture_output=True, text=True)
        return r.returncode
    check("gate: new critical without VEX blocks (enforce)", gate([fnd("CVE-1")]) == 1)
    check("gate: same finding with a VEX statement passes", gate([fnd("CVE-1", status="affected")]) == 0)
    check("gate: high does not block at the default severity", gate([fnd("CVE-1", sev="high")]) == 0)
    check("gate: high blocks with --severity high", gate([fnd("CVE-1", sev="high")], "--severity", "high") == 1)
    check("gate: build tooling never blocks", gate([fnd("CVE-1", scope="build")]) == 0)
    (base / "baseline.json").write_text(json.dumps({"findings": [fnd("CVE-1")]}))
    check("gate: finding known in the baseline passes",
          gate([fnd("CVE-1")], "--baseline", str(base / "baseline.json")) == 0)
    check("gate: a new one next to the baseline still blocks",
          gate([fnd("CVE-1"), fnd("CVE-2")], "--baseline", str(base / "baseline.json")) == 1)
    check("gate: --ignore-unfixed lets unfixed through, not fixable ones",
          gate([fnd("CVE-1")], "--ignore-unfixed") == 0 and gate([fnd("CVE-1", fix=["2"])], "--ignore-unfixed") == 1)
    check("gate: mode warn reports but exits 0", gate([fnd("CVE-1")], "--mode", "warn") == 0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--keep", action="store_true", help="keep the scratch roots")
    a = ap.parse_args()
    real = Path(a.root).resolve()
    if not (real / "dist/manifest.json").is_file() or not (real / "sbom/beast-boot.cdx.json").is_file():
        print("selftest: needs dist/ (make build) and sbom/beast-boot.cdx.json (sbom-vuln.sh sbom)", file=sys.stderr)
        return 2
    base = Path(tempfile.mkdtemp(prefix="bb-sbom-selftest-", dir=os.environ.get("TMPDIR")))
    try:
        test_keys()
        test_kernel_vex(base)
        test_coverage(real)
        test_gate(base)
        test_boot_chain(real, base)
        test_debian_grype(real, base)
        test_modules(real)
        test_empty_cache(scratch_root(real, base, "empty-cache"))
        test_origin(scratch_root(real, base, "origin"))
    finally:
        if a.keep:
            print(f"selftest: scratch roots kept in {base}")
        else:
            shutil.rmtree(base, ignore_errors=True)
    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"selftest: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
