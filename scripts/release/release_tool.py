#!/usr/bin/env python3
"""Helpers for scripts/release/build_release.sh (Python standard library only; run with -I).

    release_tool.py version   [--tag TAG] [--require-tag]
    release_tool.py dist-zip  --dist DIR --out FILE --prefix NAME
    release_tool.py cert      --cer FILE --out FILE --version V [--official] [--json FILE]
    release_tool.py gate      --report FILE --out FILE [--mode enforce|warn|off] [--severity critical|high]
                              [--baseline FILE] [--ignore-unfixed]
    release_tool.py sums      --dir DIR
    release_tool.py notes     --dir DIR --version V --out FILE [--official] [--tag TAG] [--repo OWNER/REPO]
    release_tool.py verify    --dir DIR --version V [--root REPO]

The release files and their names are the contract in docs/RELEASING.md (ASSETS below).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "scripts"))

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
OPEN = ("open", "affected", "under_investigation")
# Every release file except SHA256SUMS, in the order they are listed.
ASSETS = [
    "beast-boot-{v}-linux-x86_64.tar.gz",
    "beast-boot-{v}-windows-x86_64.zip",
    "beast-boot-{v}-macos-x86_64.zip",
    "beast-boot-{v}-macos-arm64.zip",
    "beast-boot-{v}-dist.zip",
    "beast-boot-{v}-sbom.cdx.json",
    "beast-boot-{v}-sbom.spdx.json",
    "beast-boot-{v}-vulnerabilities.json",
    "beast-boot-{v}-VULNERABILITIES.md",
    "beast-boot-{v}-ENROLL_THIS_KEY_IN_MOKMANAGER.cer",
    "beast-boot-{v}-CERTIFICATE.txt",
]
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-~+][0-9A-Za-z.+~-]+)?")


def die(msg: str, code: int = 1) -> None:
    print(f"release_tool: error: {msg}", file=sys.stderr)
    sys.exit(code)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def assets(v: str) -> list[str]:
    return [a.format(v=v) for a in ASSETS]


def read_version() -> str:
    return (REPO / "VERSION").read_text().strip()


# --------------------------------------------------------------------------- version


def cmd_version(a) -> int:
    v = read_version()
    if not VERSION_RE.fullmatch(v):
        die(f"VERSION '{v}' is not X.Y.Z or X.Y.Z-suffix")
    if a.tag:
        if a.tag != f"v{v}":
            die(f"tag {a.tag} does not match VERSION {v} (expected tag v{v}); bump VERSION or retag")
    elif a.require_tag:
        die("an official release needs its tag (BB_RELEASE_TAG, or HEAD tagged v<VERSION>)")
    prerelease = bool(re.search(r"[-~]", v))
    print(json.dumps({"version": v, "tag": a.tag or None, "prerelease": prerelease}))
    return 0


# --------------------------------------------------------------------------- dist.zip


def cmd_dist_zip(a) -> int:
    """Deterministic zip of dist/: one top-level folder, sorted entries, fixed time and modes."""
    dist = Path(a.dist)
    manifest = json.loads((dist / "manifest.json").read_text())
    epoch = int(manifest["source_date_epoch"])
    import time
    stamp = max(time.gmtime(epoch)[:6], (1980, 1, 1, 0, 0, 0))
    files = sorted(p for p in dist.rglob("*") if p.is_file())
    listed = set(manifest["files"]) | {"manifest.json"}
    rels = {p.relative_to(dist).as_posix() for p in files}
    if rels != listed:
        die(f"dist/ does not match its manifest (extra {sorted(rels - listed)[:5]}, missing "
            f"{sorted(listed - rels)[:5]}); rebuild with `make build`")
    out = Path(a.out)
    tmp = out.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w") as zf:
        for p in files:
            zi = zipfile.ZipInfo(f"{a.prefix}/{p.relative_to(dist).as_posix()}", date_time=stamp)
            zi.create_system = 3                      # Unix, so the mode bits below are honoured
            zi.external_attr = (0o100644 << 16)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, p.read_bytes(), compresslevel=9)
    os.replace(tmp, out)
    print(f"release_tool: {out.name}: {len(files)} files")
    return 0


# --------------------------------------------------------------------------- certificate


def cert_facts(cer: Path) -> dict:
    import efi_inspect
    c = efi_inspect.cert_info(cer.read_bytes())
    sha1 = c["sha1"].upper()
    pairs = [sha1[i:i + 2] for i in range(0, len(sha1), 2)]
    return {"subject": c["subject"], "issuer": c["issuer"], "serial": c["serial"],
            "not_before": c["not_before"], "not_after": c["not_after"],
            "key": f"{c['key_algorithm']} {c['key_bits']}", "sha1": c["sha1"], "sha256": c["sha256"],
            "sha1_mokmanager": " ".join(pairs[:10]) + " / " + " ".join(pairs[10:]),
            "sha1_colons": ":".join(pairs), "sha256_colons": ":".join(
                c["sha256"].upper()[i:i + 2] for i in range(0, len(c["sha256"]), 2))}


def cmd_cert(a) -> int:
    f = cert_facts(Path(a.cer))
    name = f"beast-boot-{a.version}-ENROLL_THIS_KEY_IN_MOKMANAGER.cer"
    lines = [f"beast-boot {a.version} - Secure Boot certificate", ""]
    if not a.official:
        lines += ["*** UNOFFICIAL LOCAL BUILD: signed with a local development key, NOT the project's",
                  "*** release key. Do not enroll this certificate unless you made this build yourself.", ""]
    lines += [
        f"File:         {name} (DER; also on every drive as ENROLL_THIS_KEY_IN_MOKMANAGER.cer)",
        f"Subject:      {f['subject']}",
        f"Issuer:       {f['issuer']}",
        f"Serial:       {f['serial']}",
        f"Valid from:   {f['not_before']}",
        f"Valid until:  {f['not_after']} (firmware and shim do not check certificate dates)",
        f"Key:          {f['key']}",
        "",
        "SHA-1 fingerprint, as MokManager's View key shows it (two rows of 10 pairs):",
        f"  {f['sha1_mokmanager']}",
        f"  ({f['sha1_colons']})",
        "",
        "SHA-256 fingerprint:",
        f"  {f['sha256_colons']}",
        "",
        "Check the file you enroll (docs/SECURE_BOOT.md):",
        f"  openssl x509 -inform DER -in {name} -noout -subject -fingerprint -sha1 -fingerprint -sha256",
        "Only enroll it if both fingerprints match these release notes.",
    ]
    Path(a.out).write_text("\n".join(lines) + "\n")
    if a.json:
        Path(a.json).write_text(json.dumps(dict(f, official=a.official), indent=1) + "\n")
    return 0


# --------------------------------------------------------------------------- gate


def finding_key(f: dict) -> tuple[str, str]:
    return f["id"], f["component"].get("name") or f["component"].get("bom-ref", "")


def cmd_gate(a) -> int:
    """Block a release only on NEW findings at or above the severity that have no VEX statement.

    new      = not in the baseline report (the previous release's vulnerabilities.json), if given
    no VEX   = status "open" (a VEX statement of any status - affected with an action plan,
               under_investigation, not_affected, fixed - means it was triaged)
    scope    = shipped (drive, portable runtimes) and boot-chain findings; build tools never block
    --ignore-unfixed also lets findings through that have no fixed version published yet."""
    rep = json.loads(Path(a.report).read_text())
    base = set()
    if a.baseline:
        bp = Path(a.baseline)
        if bp.is_file():
            base = {finding_key(f) for f in json.loads(bp.read_text()).get("findings", [])}
        else:
            print(f"release_tool: gate: baseline {bp} not found - every finding counts as new", file=sys.stderr)
    thr = SEV_RANK[a.severity]
    blocking, known, unfixed = [], 0, 0
    for f in rep.get("findings", []):
        if f.get("scope") != "shipped" or f.get("status") != "open" or SEV_RANK.get(f["severity"], 0) < thr:
            continue
        if finding_key(f) in base:
            known += 1
            continue
        if a.ignore_unfixed and not (f.get("fix") or {}).get("versions"):
            unfixed += 1
            continue
        blocking.append({"id": f["id"], "severity": f["severity"], "component": f["component"].get("name"),
                         "version": f["component"].get("version"), "fix": f.get("fix"),
                         "source": f.get("source"), "remediation_key": f.get("remediation_key")})
    not_checked = [f["id"] for f in rep.get("findings", []) if f["id"].endswith("-NOT-CHECKED")]
    res = {"mode": a.mode, "severity": a.severity, "baseline": a.baseline or None,
           "ignore_unfixed": a.ignore_unfixed, "blocking": blocking, "known_in_baseline": known,
           "ignored_unfixed": unfixed, "boot_chain_not_checked": not_checked,
           "blocked": bool(blocking) and a.mode == "enforce"}
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n")
    for b in blocking[:20]:
        print(f"release_tool: gate: NEW {b['severity']} {b['id']} in {b['component']} {b['version']} "
              f"(no VEX statement; {b['remediation_key']})", file=sys.stderr)
    if len(blocking) > 20:
        print(f"release_tool: gate: ... {len(blocking) - 20} more (see {a.out})", file=sys.stderr)
    for n in not_checked:
        print(f"release_tool: gate: warning: boot-chain check {n} did not run (no data)", file=sys.stderr)
    verdict = "PASS" if not blocking else ("BLOCKED" if a.mode == "enforce" else "WOULD BLOCK (mode warn)")
    print(f"release_tool: gate ({a.mode}, >= {a.severity}): {verdict}: {len(blocking)} new finding(s) without "
          f"VEX, {known} known from the baseline, {unfixed} ignored as unfixed")
    return 1 if res["blocked"] else 0


# --------------------------------------------------------------------------- SHA256SUMS


def cmd_sums(a) -> int:
    d = Path(a.dir)
    v = read_version()
    names = assets(v)
    missing = [n for n in names if not (d / n).is_file()]
    if missing:
        die(f"missing release files: {missing}")
    (d / "SHA256SUMS").write_text("".join(f"{sha256(d / n)}  {n}\n" for n in names))
    return 0


# --------------------------------------------------------------------------- notes


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def cmd_notes(a) -> int:
    d, v = Path(a.dir), a.version
    rep = json.loads((d / f"beast-boot-{v}-vulnerabilities.json").read_text())
    cert = cert_facts(d / f"beast-boot-{v}-ENROLL_THIS_KEY_IN_MOKMANAGER.cer")
    gate = json.loads(Path(a.gate).read_text()) if a.gate and Path(a.gate).is_file() else None
    s = rep.get("summary", {})

    def counts(c: dict) -> str:
        return ", ".join(f"{n} {k}" for k, n in c.items() if n) or "none"
    op = s.get("open", {})
    boot = []
    for f in rep.get("findings", []):
        if f.get("source") != "boot-chain" or f.get("status") not in OPEN:
            continue
        vex = f.get("vex") or {}
        plan = vex.get("action_statement") or vex.get("impact_statement") or vex.get("justification") or ""
        boot.append(f"- **{f['severity'].upper()} {f['id']}**: {f['title']}"
                    + (f" - VEX **{vex.get('status')}**: {plan}" if vex else " - no VEX statement yet"))
    shipped_crit = sorted({f["id"] for f in rep.get("findings", []) if f.get("scope") == "shipped"
                           and f.get("source") != "boot-chain" and f.get("status") in OPEN
                           and f["severity"] in ("critical", "high")})
    rows = ["| File | Size | SHA-256 |", "|---|---|---|"]
    for n in assets(v) + ["SHA256SUMS"]:
        p = d / n
        rows.append(f"| `{n}` | {human(p.stat().st_size)} | `{sha256(p)[:16]}...` |")
    if gate is None:
        gate_txt = "not run"
    elif not gate["blocking"]:
        gate_txt = (f"passed: no new {gate['severity']} finding without a VEX statement"
                    + (f" (baseline: previous release, {gate['known_in_baseline']} known)" if gate.get("baseline") else ""))
    else:
        ids = sorted({b["id"] for b in gate["blocking"]})
        gate_txt = (f"{len(ids)} new {gate['severity']} vulnerabilities ({len(gate['blocking'])} component findings) "
                    f"without a VEX statement (mode {gate['mode']}): " + ", ".join(ids[:10])
                    + (f" and {len(ids) - 10} more" if len(ids) > 10 else ""))
    banner = "" if a.official else (
        "> **UNOFFICIAL LOCAL BUILD.** Signed with a local development key "
        f"(`{cert['subject']}`), not the project's release key. Not for publication; do not enroll its "
        "certificate unless you made this build yourself.\n\n")
    repo = a.repo or os.environ.get("BB_RELEASE_REPO") or ""
    attest = (f"gh attestation verify beast-boot-{v}-dist.zip -R {repo}   # build provenance, any file"
              if repo and a.attestations else "")
    tmpl = Template((HERE / "RELEASE_NOTES.md.in").read_text())
    text = tmpl.substitute(
        version=v, tag=a.tag or f"v{v}", banner=banner,
        kind="Release" if a.official else "Unofficial local build",
        gate=gate_txt,
        open_boot=counts(op.get("boot_chain", {})), open_shipped=counts(op.get("shipped", {})),
        open_build=counts(op.get("build", {})), closed=s.get("closed", 0),
        boot_findings="\n".join(boot) or "- none open",
        shipped_high=(", ".join(shipped_crit[:15]) + (f" and {len(shipped_crit) - 15} more" if len(shipped_crit) > 15
                                                      else "")) or "none",
        cert_subject=cert["subject"], cert_sha1=cert["sha1_mokmanager"], cert_sha1_colons=cert["sha1_colons"],
        cert_sha256=cert["sha256_colons"], cert_until=cert["not_after"],
        attest_line=("\n" + attest) if attest else "",
        assets_table="\n".join(rows),
    )
    Path(a.out).write_text(text)
    return 0


# --------------------------------------------------------------------------- verify


def cmd_verify(a) -> int:
    d, v = Path(a.dir), a.version
    root = Path(a.root)
    problems: list[str] = []
    names = assets(v)
    sums = {}
    for line in (d / "SHA256SUMS").read_text().splitlines():
        h, _, n = line.partition("  ")
        sums[n] = h
    if sorted(sums) != sorted(names):
        problems.append(f"SHA256SUMS lists {sorted(set(sums) ^ set(names))} differently from the contract")
    for n in names:
        p = d / n
        if not p.is_file():
            problems.append(f"{n}: missing")
        elif sums.get(n) != sha256(p):
            problems.append(f"{n}: SHA-256 differs from SHA256SUMS")
    extra = sorted(p.name for p in d.iterdir() if p.is_file() and p.name not in names + ["SHA256SUMS"])
    if extra:
        problems.append(f"unexpected files in the release directory: {extra}")
    # SBOM: identical to the validated sbom/ copy, all validations PASS, schemas re-checked on the copies
    import validate_sbom as vs
    schemas = root / ".tools" / "cache" / "schemas"
    pairs = [(f"beast-boot-{v}-sbom.cdx.json", "beast-boot.cdx.json", "cyclonedx-1.6", "bom-1.6.schema.json"),
             (f"beast-boot-{v}-sbom.spdx.json", "beast-boot.spdx.json", "spdx-2.3", "spdx-schema.json")]
    for rel_name, src, sdir, sfile in pairs:
        if (d / rel_name).is_file():
            if sha256(d / rel_name) != sha256(root / "sbom" / src):
                problems.append(f"{rel_name} differs from the validated sbom/{src}")
            errs = vs.schema_errors(vs.load_validator(schemas / sdir, sfile), json.loads((d / rel_name).read_text()))
            if errs:
                problems.append(f"{rel_name}: {len(errs)} schema error(s): {errs[:3]}")
    val = json.loads((root / "sbom" / "validation.json").read_text())
    bad = [k for k, r in val["checks"].items() if r["result"] != "PASS"]
    if bad:
        problems.append(f"sbom/validation.json has failing checks: {bad}")
    cdx = json.loads((d / f"beast-boot-{v}-sbom.cdx.json").read_text())
    comps = list(vs.walk_components(cdx.get("components")))
    for need, why in (("esp/beast-net/vmlinuz", "beast-net kernel"), ("esp/beast-net/initrd.img", "beast-net initrd")):
        if need in json.loads((root / "dist" / "manifest.json").read_text())["files"] and \
                not any(c["name"] == need for c in comps):
            problems.append(f"SBOM lacks {need} ({why})")
    if not any(c.get("bom-ref", "").startswith("runtime:python-build-standalone") for c in comps):
        problems.append("SBOM lacks the portable runtimes (packaging/portable/runtimes.lock)")
    # dist.zip: every file matches the manifest inside it, and that manifest is dist/manifest.json
    zp = d / f"beast-boot-{v}-dist.zip"
    with zipfile.ZipFile(zp) as zf:
        prefix = f"beast-boot-{v}-dist/"
        names_in = zf.namelist()
        if any(not n.startswith(prefix) for n in names_in):
            problems.append(f"{zp.name}: entries outside {prefix}")
        man = json.loads(zf.read(prefix + "manifest.json"))
        if zf.read(prefix + "manifest.json") != (root / "dist" / "manifest.json").read_bytes():
            problems.append(f"{zp.name}: manifest.json differs from dist/manifest.json")
        for rel, meta in man["files"].items():
            try:
                data = zf.read(prefix + rel)
            except KeyError:
                problems.append(f"{zp.name}: {rel} missing")
                continue
            if hashlib.sha256(data).hexdigest() != meta["sha256"]:
                problems.append(f"{zp.name}: {rel} differs from its manifest entry")
        if len(names_in) != len(man["files"]) + 1:
            problems.append(f"{zp.name}: {len(names_in)} entries for {len(man['files'])} manifest files")
    # the certificate equals the one on the drive
    cer = d / f"beast-boot-{v}-ENROLL_THIS_KEY_IN_MOKMANAGER.cer"
    if sha256(cer) != man.get("secure_boot", {}).get("cert_sha256"):
        problems.append(f"{cer.name} is not the certificate dist/ was signed for")
    for p in problems:
        print(f"release_tool: verify: FAIL {p}", file=sys.stderr)
    print(f"release_tool: verify: {'FAIL' if problems else 'PASS'} ({len(names) + 1} files, SBOM, dist.zip, "
          "certificate)")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("version")
    p.add_argument("--tag", default="")
    p.add_argument("--require-tag", action="store_true")
    p = sub.add_parser("dist-zip")
    p.add_argument("--dist", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--prefix", required=True)
    p = sub.add_parser("cert")
    p.add_argument("--cer", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--official", action="store_true")
    p.add_argument("--json")
    p = sub.add_parser("gate")
    p.add_argument("--report", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--mode", choices=["enforce", "warn", "off"], default="enforce")
    p.add_argument("--severity", choices=["critical", "high"], default="critical")
    p.add_argument("--baseline", default="")
    p.add_argument("--ignore-unfixed", action="store_true")
    p = sub.add_parser("sums")
    p.add_argument("--dir", required=True)
    p = sub.add_parser("notes")
    p.add_argument("--dir", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--official", action="store_true")
    p.add_argument("--tag", default="")
    p.add_argument("--repo", default="")
    p.add_argument("--attestations", action="store_true", help="the CI attests build provenance (GitHub)")
    p.add_argument("--gate")
    p = sub.add_parser("verify")
    p.add_argument("--dir", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--root", default=str(REPO))
    a = ap.parse_args()
    if a.cmd == "gate" and a.mode == "off":
        Path(a.out).write_text(json.dumps({"mode": "off", "severity": a.severity, "baseline": None,
                                           "known_in_baseline": 0, "blocking": [], "blocked": False}) + "\n")
        print("release_tool: gate: off")
        return 0
    return {"version": cmd_version, "dist-zip": cmd_dist_zip, "cert": cmd_cert, "gate": cmd_gate,
            "sums": cmd_sums, "notes": cmd_notes, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
