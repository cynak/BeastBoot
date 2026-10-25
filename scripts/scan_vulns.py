#!/usr/bin/env python3
"""Find vulnerabilities and boot-chain risks in what beast-booter ships.

    python3 -I scripts/scan_vulns.py [--offline] [--fail-on critical|high]

Reads sbom/beast-booter.cdx.json (run gen_sbom.py first), dist/ and the OpenVEX files
(sbom/vex.openvex.json, hand-maintained, plus every sbom/vex.*.openvex.json, generated from
evidence, e.g. vex.kernel.openvex.json; never vex.proposed.openvex.json).
Writes sbom/vulnerabilities.json, sbom/VULNERABILITIES.md and sbom/vex.proposed.openvex.json.

Steps
  1. grype (Anchore DB, cached in .tools/cache/grype) on the CycloneDX SBOM, distro
     ubuntu:<VERSION_ID>, with the OpenVEX file.
  2. osv-scanner on the SBOM, plus on a derived view that names each Debian *source*
     package (OSV's Ubuntu records are keyed by source package).
  3. merge + dedupe by (vulnerability id/alias, component); tag shipped vs build.
  4. apply OpenVEX triage (sbom/vex.openvex.json + sbom/vex.*.openvex.json); invalid statements are reported.
  5. evidence for triage: CVEs recorded as fixed in the shipped package's changelog,
     Ubuntu CVE tracker status, GRUB module named by the advisory vs. modules embedded
     in grubx64.efi. Evidence becomes *proposed* VEX statements, never applied silently.
  6. boot-chain checks: SBAT revocation, Authenticode signers / CA expiry, beast-booter
     certificate, dbx, manifest integrity and provenance.
External data is cached in .tools/cache/sbom-vuln; see references/data-sources.md.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import debinfo as deb          # noqa: E402
import efi_inspect as efi      # noqa: E402

P = "beast-booter:"
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"]
UA = "beast-booter-sbom-vuln/1"
SBAT_URL = "https://raw.githubusercontent.com/rhboot/shim/main/SbatLevel_Variable.txt"
SBAT_COMMITS = "https://api.github.com/repos/rhboot/shim/commits?path=SbatLevel_Variable.txt&per_page=1"
DBX_JSON_URL = ("https://raw.githubusercontent.com/microsoft/secureboot_objects/main/"
                "PreSignedObjects/DBX/dbx_info_msft_latest.json")
DBX_BIN_URL = ("https://raw.githubusercontent.com/microsoft/secureboot_objects/main/"
               "PostSignedObjects/DBX/amd64/DBXUpdate.bin")
DBX_COMMITS = "https://api.github.com/repos/microsoft/secureboot_objects/commits?path=PreSignedObjects/DBX&per_page=1"
LP_SOURCES = ("https://api.launchpad.net/devel/ubuntu/+archive/primary?ws.op=getPublishedSources"
              "&source_name={name}&exact_match=true&order_by_date=true&ws.size=30")
UBUNTU_CVE = "https://ubuntu.com/security/cves/{id}.json"
EFI_CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
OPENVEX_JUSTIFICATIONS = {"component_not_present", "vulnerable_code_not_present",
                          "vulnerable_code_not_in_execute_path",
                          "vulnerable_code_cannot_be_controlled_by_adversary",
                          "inline_mitigations_already_exist"}
OPENVEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
FAMILY = {"grub2": "grub2", "grub2-unsigned": "grub2", "grub2-signed": "grub2",
          "shim": "shim", "shim-signed": "shim"}


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"scan: {msg}", file=sys.stderr)


# =========================================================================== cached fetch


class Fetcher:
    def __init__(self, cache: Path, offline: bool, max_age_h: float, refresh: bool):
        self.cache, self.offline, self.max_age, self.refresh = cache, offline, max_age_h, refresh
        cache.mkdir(parents=True, exist_ok=True)
        self.used: dict[str, dict] = {}
        self.failed: dict[str, str] = {}     # no second attempt within one run

    def get(self, key: str, url: str, max_age_h: float | None = None, timeout: float = 45) -> tuple[bytes | None, dict]:
        f, mf = self.cache / key, self.cache / (key + ".meta.json")
        meta = json.loads(mf.read_text()) if mf.exists() else None
        age_ok = False
        if meta and f.exists():
            fetched = dt.datetime.fromisoformat(meta["fetched_at"].replace("Z", "+00:00"))
            age_ok = (now_utc() - fetched).total_seconds() < 3600 * (self.max_age if max_age_h is None else max_age_h)
        if not self.offline and (self.refresh or not age_ok) and key not in self.failed:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read()
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data)
                meta = {"url": url, "fetched_at": iso(now_utc()), "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data)}
                mf.write_text(json.dumps(meta, indent=1))
                out = dict(meta, source="network")
                self.used[key] = out
                return data, out
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                err = f"fetch failed ({e.__class__.__name__}: {str(e)[:120]})"
                self.failed[key] = err
                if meta and f.exists():
                    out = dict(meta, source="cache", note=err + f"; using cached copy from {meta['fetched_at']}")
                    self.used[key] = out
                    return f.read_bytes(), out
                out = {"url": url, "source": "unavailable", "note": err}
                self.used[key] = out
                return None, out
        if meta and f.exists():
            out = dict(meta, source="cache",
                       note=("offline: " if self.offline else "") + f"cached copy from {meta['fetched_at']}")
            self.used[key] = out
            return f.read_bytes(), out
        out = {"url": url, "source": "unavailable",
               "note": self.failed.get(key) or "offline and no cached copy"}
        self.used[key] = out
        return None, out

    def json(self, key, url, max_age_h=None, timeout=45):
        data, meta = self.get(key, url, max_age_h, timeout)
        if data is None:
            return None, meta
        try:
            return json.loads(data), meta
        except ValueError:
            return None, dict(meta, note=(meta.get("note", "") + " (invalid JSON)").strip())

    def commit(self, key: str, url: str) -> dict:
        d, meta = self.json(key, url)
        if isinstance(d, list) and d:
            return {"commit": d[0]["sha"], "date": d[0]["commit"]["committer"]["date"], "source": meta["source"]}
        return {"commit": None, "date": None, "source": meta.get("source"), "note": meta.get("note")}


# =========================================================================== SBOM


def walk(comps, parent=None):
    for c in comps or []:
        yield c, parent
        yield from walk(c.get("components"), c)


def load_sbom(path: Path) -> tuple[dict, dict]:
    bom = json.loads(path.read_text())
    idx = {}
    for c, parent in walk(bom.get("components")):
        pr = {}
        for p in c.get("properties", []):
            k = p["name"].removeprefix(P)
            pr[k] = pr[k] + "\n" + p["value"] if k in pr else p["value"]
        role = pr.get("role", "shipped" if c.get("scope") == "required" else "build")
        idx[c["bom-ref"]] = {"ref": c["bom-ref"], "name": c["name"], "version": c.get("version"),
                             "purl": c.get("purl"), "cpe": c.get("cpe"), "type": c["type"],
                             "scope": c.get("scope"), "role": role, "props": pr,
                             "group": c.get("group"), "parent": parent["bom-ref"] if parent else None}
    return bom, idx


def purl_key(p: str | None) -> str | None:
    """pkg:type/ns/name@version (qualifiers dropped, unquoted) for matching."""
    if not p:
        return None
    from urllib.parse import unquote
    base = p.split("?", 1)[0].split("#", 1)[0]
    return unquote(base)


def bucket(role: str) -> str:
    """shipped = on the drive (dist/) or in the portable packages (role portable); build = tooling."""
    return "shipped" if role in ("shipped", "portable") else "build"


def beastnet_component(c: dict, idx: dict) -> bool:
    """A beast-net package (build/beastnet/packages.lock), its kernel, or a source package built into one."""
    pr = c.get("props", {})
    if pr.get("beast-net-package") or c["ref"].startswith("kernel:"):
        return True
    names = set((pr.get("built-using-of") or "").split()) | set((pr.get("upstream-of") or "").split())
    return any(x.get("props", {}).get("beast-net-package") and x["name"] in names for x in idx.values())


# =========================================================================== scanners


def tool_version(binpath: Path, args: list[str]) -> str:
    try:
        r = subprocess.run([str(binpath)] + args, capture_output=True, text=True, timeout=60)
        m = re.search(r"(\d+\.\d+\.\d+)", r.stdout + r.stderr)
        return m.group(1) if m else "?"
    except (OSError, subprocess.TimeoutExpired):
        return "missing"


def run_grype(root: Path, sbom: Path, vex: list[Path], distro: str, offline: bool, work: Path) -> dict:
    grype = root / ".tools/bin/grype"
    if not grype.exists():
        return {"ok": False, "error": "grype not installed (scripts/install-tools.sh)", "matches": []}
    env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(root / ".tools/cache/grype"),
               GRYPE_CHECK_FOR_APP_UPDATE="false", GRYPE_DB_AUTO_UPDATE="false")
    info: dict = {"version": tool_version(grype, ["version"])}
    if not offline:
        r = subprocess.run([str(grype), "db", "update"], capture_output=True, text=True, env=env, timeout=1800)
        info["db_update"] = "ok" if r.returncode == 0 else f"failed: {(r.stderr or r.stdout).strip()[-300:]}"
    st = subprocess.run([str(grype), "db", "status", "-o", "json"], capture_output=True, text=True, env=env)
    try:
        s = json.loads(st.stdout)
        info["db"] = {"schema": s.get("schemaVersion"), "built": s.get("built"), "from": s.get("from", "").split("?")[0],
                      "valid": s.get("valid")}
    except ValueError:
        info["db"] = {"error": (st.stderr or st.stdout).strip()[-300:]}
    built = info["db"].get("built")
    if built:
        age_d = (now_utc() - dt.datetime.fromisoformat(built.replace("Z", "+00:00"))).total_seconds() / 86400
        info["db"]["age_days"] = round(age_d, 1)
        if age_d > 5:
            env["GRYPE_DB_VALIDATE_AGE"] = "false"
            info["db"]["stale"] = True
    out = work / "grype.json"
    cmd = [str(grype), f"sbom:{sbom}", "--distro", distro.replace("-", ":", 1), "-o", "json", "--file", str(out)]
    for v in vex:
        if v.exists():
            cmd += ["--vex", str(v)]
    info["command"] = " ".join(["grype"] + cmd[1:]).replace(str(root) + "/", "")
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
    if r.returncode != 0 or not out.exists():
        info.update(ok=False, error=(r.stderr or r.stdout).strip()[-800:], matches=[])
        return info
    g = json.loads(out.read_text())
    info.update(ok=True, matches=g.get("matches", []), ignored=g.get("ignoredMatches", []) or [],
                stderr_tail=r.stderr.strip()[-300:], match_count=len(g.get("matches", [])),
                ignored_by_vex=len(g.get("ignoredMatches", []) or []))
    return info


def run_osv(root: Path, sbom_file: Path, work: Path, label: str, offline: bool = False,
            download_db: bool = False) -> dict:
    osv = root / ".tools/bin/osv-scanner"
    if not osv.exists():
        return {"ok": False, "error": "osv-scanner not installed", "packages": []}
    out = work / f"osv-{label}.json"
    env = dict(os.environ, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(root / ".tools/cache/osv-scanner"))
    cmd = [str(osv), "scan", "source", "-L", str(sbom_file), "--format", "json", "--output-file", str(out)]
    if offline:          # local OSV databases only (cached by an earlier --osv-download-db run)
        cmd[3:3] = ["--offline"]
    elif download_db:    # also cache the ecosystem databases for later --offline runs
        cmd[3:3] = ["--download-offline-databases", "--offline-vulnerabilities"]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
    info = {"label": label, "version": tool_version(osv, ["--version"]),
            "command": " ".join(["osv-scanner"] + cmd[1:]).replace(str(root) + "/", "").replace(str(work) + "/", "<tmp>/"),
            "exit_code": r.returncode}
    m = re.search(r"found (\d+) packages", r.stderr)
    info["packages_scanned"] = int(m.group(1)) if m else None
    m = re.search(r"Filtered (\d+) local/unscannable", r.stderr + r.stdout)
    info["filtered_unscannable"] = int(m.group(1)) if m else 0
    # osv-scanner: 0 = no vulns, 1 = vulns found, 128 = no packages found, others = error
    if r.returncode not in (0, 1) or not out.exists():
        err = (r.stderr or r.stdout).strip()[-800:]
        if offline:
            err = ("not run offline: no usable local OSV database in .tools/cache/osv-scanner (run once online "
                   "with --osv-download-db to cache it). " + err[-300:])
        info.update(ok=False, error=err, packages=[])
        return info
    info["mode"] = "offline (local OSV databases)" if offline else ("online, local DB refreshed" if download_db
                                                                    else "online (api.osv.dev)")
    d = json.loads(out.read_text())
    pk = [p for res in d.get("results", []) or [] for p in res.get("packages", []) or []]
    info.update(ok=True, packages=pk)
    return info


def osv_source_view(idx: dict, work: Path) -> tuple[Path, dict]:
    """CycloneDX listing each Debian source package once -> {source@ver: [component refs]}."""
    seen: dict[str, list[str]] = {}
    comps = []
    for c in idx.values():
        if not (c.get("purl") or "").startswith("pkg:deb/") or "arch=source" in c["purl"]:
            continue
        src, sver = c["props"].get("source-package"), c["props"].get("source-version")
        if not src or (src == c["name"] and sver == c["version"]):
            continue
        key = f"{src}@{sver}"
        if key not in seen:
            distro = re.search(r"distro=([^&]+)", c["purl"]).group(1)
            comps.append({"type": "application", "bom-ref": f"src:{key}", "name": src, "version": sver,
                          "purl": deb.source_purl(src, sver, distro)})
            seen[key] = []
        seen[key].append(c["ref"])
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}
    path = work / "beast-booter-sources.cdx.json"
    path.write_text(json.dumps(doc))
    return path, seen


# =========================================================================== normalise


def canon_id(ids: list[str]) -> str:
    cves = sorted(i for i in ids if re.fullmatch(r"CVE-\d{4}-\d+", i))
    return cves[0] if cves else sorted(ids)[0]


def sev_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    return ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4
            else "low" if score > 0 else "unknown")


def norm_sev(s: str | None) -> str:
    s = (s or "unknown").lower()
    return s if s in SEV_RANK else {"moderate": "medium", "important": "high", "untriaged": "unknown"}.get(s, "unknown")


def from_grype(g: dict, idx: dict, by_purl: dict) -> list[dict]:
    out = []
    for m in g.get("matches", []) + [dict(x, _ignored=True) for x in g.get("ignored", [])]:
        v, a = m["vulnerability"], m["artifact"]
        ref = None
        for cand in (purl_key(a.get("purl")),):
            if cand and cand in by_purl:
                ref = by_purl[cand]
        if ref is None:
            for c in idx.values():
                if (c["name"] == a["name"] or f"{c.get('group')}/{c['name']}" == a["name"]) and c.get("version") == a["version"]:
                    ref = c["ref"]
                    break
        if ref is None:
            continue
        ids = [v["id"]] + [r["id"] for r in m.get("relatedVulnerabilities", []) or []]
        md = (m.get("matchDetails") or [{}])[0]
        out.append({
            "ids": ids, "component": ref, "scanner": "grype",
            "severity": norm_sev(v.get("severity")),
            "severity_source": f"{v.get('namespace')}: {v.get('severity')}",
            "fix": {"state": (v.get("fix") or {}).get("state"), "versions": (v.get("fix") or {}).get("versions") or []},
            "title": "", "description": (v.get("description") or next(
                (r.get("description") for r in m.get("relatedVulnerabilities", []) or [] if r.get("description")), "")),
            "urls": ([v.get("dataSource")] if v.get("dataSource") else []) + (v.get("urls") or [])[:3],
            "match": f"{md.get('type')} ({md.get('matcher')})", "namespace": v.get("namespace"),
            "grype_vex": [r for r in m.get("appliedIgnoreRules", []) or []] if m.get("_ignored") else None,
            "cpe_only": md.get("type") == "cpe-match",
        })
    return out


def osv_fix(vuln: dict, name: str, eco: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []) or []:
        p = aff.get("package", {})
        if p.get("name") == name and p.get("ecosystem") == eco:
            for r in aff.get("ranges", []) or []:
                out += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return sorted(set(out))


def from_osv(runs: list[tuple[dict, dict]], idx: dict) -> list[dict]:
    out = []
    for info, mapping in runs:
        for pk in info.get("packages", []):
            pkg = pk["package"]
            refs = mapping.get(f"{pkg['name']}@{pkg['version']}")
            if refs is None:
                refs = [c["ref"] for c in idx.values() if c["name"] == pkg["name"] and c.get("version") == pkg["version"]]
            groups = {i: g for g in pk.get("groups", []) or [] for i in g.get("ids", [])}
            for v in pk.get("vulnerabilities", []) or []:
                ids = [v["id"]] + (v.get("aliases") or []) + (v.get("upstream") or [])
                sev, src = "unknown", "osv"
                for s in v.get("severity", []) or []:
                    if s.get("type") == "Ubuntu":
                        sev, src = norm_sev(s.get("score")), f"Ubuntu priority (OSV): {s.get('score')}"
                if sev == "unknown":
                    g = groups.get(v["id"], {})
                    try:
                        sc = float(g.get("max_severity") or "nan")
                        sev, src = sev_from_score(sc if sc == sc else None), f"CVSS max {g.get('max_severity')} (OSV)"
                    except ValueError:
                        pass
                fixes = osv_fix(v, pkg["name"], pkg["ecosystem"])
                for ref in refs:
                    out.append({"ids": ids, "component": ref, "scanner": f"osv-scanner ({info['label']})",
                                "severity": sev, "severity_source": src,
                                "fix": {"state": "fixed" if fixes else "not-fixed", "versions": fixes},
                                "title": v.get("summary") or "", "description": v.get("details") or "",
                                "urls": [f"https://osv.dev/vulnerability/{v['id']}"], "match": f"OSV {pkg['ecosystem']}",
                                "namespace": pkg["ecosystem"], "cpe_only": False})
    return out


def merge(raw: list[dict], idx: dict) -> list[dict]:
    """Dedupe by (vulnerability, component): ids that alias each other are one finding."""
    by_comp: dict[str, list[dict]] = {}
    for r in raw:
        by_comp.setdefault(r["component"], []).append(r)
    merged = []
    for ref, rs in by_comp.items():
        groups: list[dict] = []
        for r in rs:
            ids = set(r["ids"])
            hit = [g for g in groups if g["ids"] & ids]
            if hit:
                g = hit[0]
                for other in hit[1:]:
                    g["ids"] |= other["ids"]
                    g["recs"] += other["recs"]
                    groups.remove(other)
                g["ids"] |= ids
                g["recs"].append(r)
            else:
                groups.append({"ids": set(ids), "recs": [r]})
        for g in groups:
            recs = g["recs"]
            sev = max((r["severity"] for r in recs), key=lambda s: SEV_RANK[s])
            fixv = sorted({v for r in recs for v in r["fix"]["versions"]})
            states = {r["fix"]["state"] for r in recs if r["fix"]["state"]}
            c = idx[ref]
            cid = canon_id(sorted(g["ids"]))
            merged.append({
                "id": cid, "aliases": sorted(g["ids"] - {cid}), "severity": sev,
                "severity_sources": sorted({r["severity_source"] for r in recs}),
                "component": {"bom-ref": ref, "name": (f"{c['group']}/{c['name']}" if c.get("group") else c["name"]),
                              "version": c.get("version"), "purl": c.get("purl"), "cpe": c.get("cpe")},
                "scope": bucket(c["role"]), "role": c["role"],
                "sources": sorted({r["scanner"] for r in recs}),
                "fix": {"state": "fixed" if fixv else (sorted(states)[0] if states else "unknown"), "versions": fixv},
                "title": next((r["title"] for r in recs if r["title"]), ""),
                "description": max((r["description"] for r in recs), key=len)[:600],
                "urls": sorted({u for r in recs for u in r["urls"] if u})[:4],
                "match": sorted({r["match"] for r in recs}),
                "cpe_only": all(r["cpe_only"] for r in recs),
                "status": "open", "vex": None,
            })
    merged.sort(key=lambda f: (f["scope"] != "shipped", -SEV_RANK[f["severity"]], f["id"], f["component"]["name"]))
    return merged


# =========================================================================== VEX


def load_vex(path: Path) -> tuple[list[dict], list[str], dict]:
    if not path.exists():
        return [], [f"{path.name} not found"], {}
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        return [], [f"{path.name}: invalid JSON: {e}"], {}
    errs = []
    for k in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if k not in doc:
            errs.append(f"document lacks {k}")
    if not str(doc.get("@context", "")).startswith("https://openvex.dev/ns/"):
        errs.append("@context is not an OpenVEX context")
    good = []
    for n, s in enumerate(doc.get("statements", []) or []):
        where = f"statement {n}"
        st = s.get("status")
        vname = (s.get("vulnerability") or {}).get("name")
        if not vname:
            errs.append(f"{where}: vulnerability.name missing")
            continue
        if st not in OPENVEX_STATUSES:
            errs.append(f"{where} ({vname}): status {st!r} invalid")
            continue
        if st == "not_affected" and not (s.get("justification") in OPENVEX_JUSTIFICATIONS or s.get("impact_statement")):
            errs.append(f"{where} ({vname}): not_affected needs a justification ({', '.join(sorted(OPENVEX_JUSTIFICATIONS))}) "
                        "or an impact_statement - statement ignored")
            continue
        if s.get("justification") and s["justification"] not in OPENVEX_JUSTIFICATIONS:
            errs.append(f"{where} ({vname}): unknown justification {s['justification']!r} - statement ignored")
            continue
        if st == "affected" and not s.get("action_statement"):
            errs.append(f"{where} ({vname}): affected needs an action_statement - statement ignored")
            continue
        if not s.get("products"):
            errs.append(f"{where} ({vname}): no products - statement ignored")
            continue
        good.append(s)
    meta = {"@id": doc.get("@id"), "author": doc.get("author"), "version": doc.get("version"),
            "timestamp": doc.get("timestamp"), "statements": len(doc.get("statements", []) or [])}
    return good, errs, meta


VEX_HAND = "vex.openvex.json"
VEX_PROPOSED = "vex.proposed.openvex.json"


def default_vex_files(sbom_dir: Path) -> list[Path]:
    """The hand-maintained file first, then every generated sbom/vex.*.openvex.json (sorted);
    the scanner's own proposals are never applied."""
    extra = sorted(p for p in sbom_dir.glob("vex.*.openvex.json") if p.name != VEX_PROPOSED)
    return [sbom_dir / VEX_HAND, *extra]


def load_vex_files(paths: list[Path], root: Path) -> tuple[list[dict], list[str], dict]:
    """load_vex for several files: statements combined, problems prefixed with the file name.
    A missing generated file is fine; a missing hand-maintained file is reported as before."""
    good, errs, files = [], [], []
    for path in paths:
        if not path.exists() and path.name != VEX_HAND:
            continue
        g, e, m = load_vex(path)
        good += g
        errs += [x if x.startswith(path.name) else f"{path.name}: {x}" for x in e]
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        files.append({"path": rel, **m, "applicable": len(g)})
    meta = {"statements": sum(f.get("statements", 0) for f in files), "files": files}
    if files:
        meta.update({k: files[0].get(k) for k in ("@id", "author", "version", "timestamp")})
    return good, errs, meta


def apply_vex(findings: list[dict], statements: list[dict]) -> None:
    def prod_ids(s):
        for p in s.get("products", []):
            yield p.get("@id")
            for sc in p.get("subcomponents", []) or []:
                yield sc.get("@id")
    for f in findings:
        names = {f["id"], *f["aliases"]}
        comp = f["component"]
        cands = {comp.get("bom-ref"), comp.get("purl"), purl_key(comp.get("purl")), comp.get("cpe")}
        cands.discard(None)
        best = None
        for s in statements:
            vn = {s["vulnerability"]["name"], *(s["vulnerability"].get("aliases") or [])}
            if not names & vn:
                continue
            ok = False
            for pid in prod_ids(s):
                if not pid:
                    continue
                if pid in cands or purl_key(pid) in cands:
                    ok = True
                # versionless purl: pkg:deb/ubuntu/name -> any version
                elif pid.startswith("pkg:") and "@" not in pid.split("?")[0] and comp.get("purl") and \
                        purl_key(comp["purl"]).split("@")[0] == purl_key(pid):
                    ok = True
            if ok and (best is None or (s.get("timestamp") or "") >= (best.get("timestamp") or "")):
                best = s
        if best:
            f["status"] = best["status"]
            f["vex"] = {k: best.get(k) for k in ("status", "justification", "impact_statement",
                                                  "action_statement", "status_notes", "timestamp") if best.get(k)}


# =========================================================================== evidence


def changelog_index(idx: dict, root: Path) -> dict[str, dict]:
    """bom-ref -> {'cves': {...}, 'where': path} for every Debian binary package component."""
    out = {}
    resolve = deb.Resolver(root)
    for c in idx.values():
        if not (c.get("purl") or "").startswith("pkg:deb/") or "arch=source" in c["purl"]:
            continue
        p = resolve(c["name"], c["version"])
        if p is None:
            continue
        text, where = deb.changelog(p, root / ".tools/root")
        if text:
            out[c["ref"]] = {"cves": deb.changelog_cves(text), "where": where.replace(str(root) + "/", ""),
                             "pkg": p}
    return out


def code_version(c: dict) -> tuple[str | None, str | None]:
    """(family, version of the family's code inside this component)."""
    src = c["props"].get("source-package") or c["name"]
    fam = FAMILY.get(src)
    if c["ref"].startswith("upstream:"):
        return FAMILY.get(c["name"], "grub2" if "grub" in c["name"] else c["name"]), c["version"]
    if c["ref"].startswith("deb-src:"):
        return FAMILY.get(c["name"]), c["version"]
    for part in (c["props"].get("built-using") or "").split(","):
        m = re.match(r"\s*(\S+) \(= ([^)]+)\)", part)
        if m and FAMILY.get(m.group(1)):
            return FAMILY[m.group(1)], m.group(2)
    return fam, c["props"].get("source-version") or c["version"]


def evidence_for(f: dict, idx: dict, cl: dict) -> list[dict]:
    c = idx[f["component"]["bom-ref"]]
    fam, ver = code_version(c)
    cands = []
    for ref, info in cl.items():
        o = idx[ref]
        if ref == c["ref"]:
            cands.append(ref)
            continue
        ofam, over = code_version(o)
        if fam and ofam == fam and (over == ver or (c["ref"].startswith("upstream:") and
                                                   deb.upstream_version(over or "") == ver)):
            cands.append(ref)
    ev = []
    for ref in cands:
        info = cl[ref]
        for name in [f["id"], *f["aliases"]]:
            for hit in info["cves"].get(name, []):
                txt = hit["context"] + " " + hit["line"]
                kind = "fix" if re.search(r"SECURITY U\w*DATE|\bfix", txt, re.I) and not re.search(r"revert", txt, re.I) \
                    else "mention"
                ev.append({"kind": kind, "package": idx[ref]["name"], "package_version": idx[ref]["version"],
                           "changelog": info["where"], "entry": f"{hit['source']} ({hit['version']})",
                           "context": hit["context"]})
    uniq = {(e["package"], e["entry"], e["context"]): e for e in ev}
    return list(uniq.values())


def grub_module_hint(f: dict, ev: list[dict], modules: dict) -> list[dict]:
    """GRUB code area named by the advisory -> is that module embedded in grubx64.efi?"""
    if not modules["bios"]:
        return []
    texts = [e["context"] for e in ev] + [f.get("title", ""), f.get("description", "")]
    areas = set()
    for t in texts:
        m = re.search(r"SECURITY U\w*DATE:\s*([A-Za-z0-9_/.+-]+):", t)
        if m:
            areas.add(m.group(1))
        for m in re.finditer(r"\b(?:fs|commands?|video/readers|loader|disk|net|lib|font|term|normal)/([a-z0-9_]+)", t):
            areas.add(m.group(0))
        for m in re.finditer(r"(?:GRUB2?|bootloader)'?s ([A-Za-z0-9_+]+) (?:module|filesystem|command)", t):
            areas.add(m.group(1))
        for m in re.finditer(r"\bthe ([a-z0-9_]+) (?:module|filesystem module)\b", t):
            areas.add(m.group(1))
    out = []
    for a in sorted(areas):
        leaf = a.rsplit("/", 1)[-1].lower().replace("+", "plus")
        leaf = {"network": "net"}.get(leaf, leaf)
        mods = sorted(x for x in modules["bios"] if x == leaf or re.fullmatch(leaf + r"\d?(_be)?", x))
        if not mods:
            continue
        emb = sorted(x for x in mods if x in modules["efi"])
        out.append({"area": a, "modules": mods, "in_efi_image": emb,
                    "in_bios_core": sorted(x for x in mods if x in modules["bios_core"]),
                    "efi_removability": [module_removability(x, modules) for x in emb]})
    return out


# Modules beast-booter cannot drop whatever the dependency graph says.
ESSENTIAL_MODULES = {
    "normal": "normal is GRUB's normal mode (script parser, menu, config loading) - without it there is no "
              "beast-booter menu, only the rescue shell",
}


def _moddep(text: str) -> dict[str, list[str]]:
    dep = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if k.strip():
            dep[k.strip()] = v.split()
    return dep


def _commands(text: str) -> dict[str, list[str]]:
    """command.lst ('*cmd: module' / 'cmd: module') -> {module: [commands]}"""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if k.strip() and v.strip():
            out.setdefault(v.strip(), []).append(k.strip().lstrip("*"))
    return out


def _closure(start: set[str], dep: dict[str, list[str]]) -> set[str]:
    seen, todo = set(), list(start)
    while todo:
        x = todo.pop()
        if x not in seen:
            seen.add(x)
            todo += dep.get(x, [])
    return seen


def grub_modules(root: Path, dist: Path, manifest: dict, idx: dict) -> dict:
    """Modules really inside grubx64.efi / core.img: the requested lists from manifest.json
    plus their dependencies per moddep.lst (grub-mkimage pulls those in)."""
    b = manifest.get("build", {})
    efi_req, core_req = set(b.get("efi_modules", [])), set(b.get("bios_core_modules", []))
    out = {"efi": set(efi_req), "bios_core": set(core_req),
           "bios": {Path(r).stem for r in manifest["files"] if r.endswith(".mod")},
           "x86_64_efi_modules_shipped": any("/x86_64-efi/" in r for r in manifest["files"]),
           "efi_closure_source": "manifest efi_modules only (moddep.lst unavailable)"}
    bios_dep = dist / "esp/grub/i386-pc/moddep.lst"
    if bios_dep.exists():
        out["bios_core"] = _closure(core_req, _moddep(bios_dep.read_text()))
    m = re.search(r"deb:(grub-efi-amd64-bin)=(\S+?)[,:\s]", next((v["origin"] for k, v in manifest["files"].items()
                                                                   if k.endswith("grubx64.efi")), "") + " ")
    out["efi_requested"] = sorted(efi_req)
    out["efi_deps"] = None                  # moddep.lst graph of the EFI package, when verifiable
    out["efi_commands"] = {}
    if m:
        p = deb.Resolver(root)(m.group(1), m.group(2))

        def pkg_text(member: str) -> str | None:
            if p and p.origin == "dpkg":
                f = Path(member)
                md5 = deb.dpkg_md5sums(p.name, p.arch).get(member)
                if f.exists() and md5 == hashlib.md5(f.read_bytes()).hexdigest():
                    return f.read_text()
            elif p and p.deb_path:
                raw = deb.deb_member_bytes(p.deb_path, member)
                return raw.decode() if raw else None
            return None
        text = pkg_text("/usr/lib/grub/x86_64-efi/moddep.lst")
        if text:
            out["efi_deps"] = _moddep(text)
            out["efi"] = _closure(efi_req, out["efi_deps"])
            out["efi_closure_source"] = f"moddep.lst of {p.name} {p.version} (verified against the package)"
        out["efi_commands"] = _commands(pkg_text("/usr/lib/grub/x86_64-efi/command.lst") or "")
    # shipped GRUB scripts (comments stripped): used to tell whether the menu calls a module's commands
    cfgs = [dist / r for r in manifest["files"] if r.endswith(".cfg")] + sorted((root / "build").glob("early-*.cfg"))
    out["menu_text"] = "\n".join(re.sub(r"(?m)^\s*#.*$", "", f.read_text(errors="replace"))
                                 for f in cfgs if f.is_file())
    return out


def module_removability(mod: str, modules: dict) -> dict:
    """Why is `mod` in grubx64.efi, and could build/modules-efi.lst drop it?  grub-mkimage embeds the
    requested modules plus their moddep.lst closure, so a module that another requested module depends
    on stays in the image even when its own line is deleted."""
    req = set(modules.get("efi_requested") or [])
    dep = modules.get("efi_deps")
    cmds = modules.get("efi_commands", {}).get(mod, [])
    used = sorted(c for c in cmds if re.search(r"(?<![\w.-])" + re.escape(c) + r"(?![\w-])",
                                               modules.get("menu_text", "")))
    w = {"module": mod, "requested": mod in req, "pulled_in_by": None, "menu_uses": used,
         "essential": ESSENTIAL_MODULES.get(mod), "removable": None}
    if dep is None:
        return w
    w["pulled_in_by"] = sorted(r for r in req if r != mod and mod in _closure({r}, dep))
    w["removable"] = w["requested"] and not w["pulled_in_by"] and not w["essential"] and not used
    return w


def removability_text(w: dict) -> str:
    mod = w["module"]
    if w["pulled_in_by"] is None:
        return (f"`{mod}`: moddep.lst of the EFI package could not be verified, so it is unknown what pulls it "
                "in - check /usr/lib/grub/x86_64-efi/moddep.lst before proposing any module change")
    if w["pulled_in_by"]:
        t = (f"`{mod}` cannot be removed: grub-mkimage pulls it in as a dependency of "
             f"{', '.join(w['pulled_in_by'])} (moddep.lst)")
        if w["requested"]:
            t += "; it is also listed in build/modules-efi.lst, but deleting that line would not remove it"
        ess = [ESSENTIAL_MODULES[x] for x in [mod, *w["pulled_in_by"]] if x in ESSENTIAL_MODULES]
        return t + (f"; {ess[0]}" if ess else "")
    if w["essential"]:
        return f"`{mod}` cannot be removed: {w['essential']}"
    if w["menu_uses"]:
        return (f"`{mod}` is needed: the shipped menu scripts call its command(s) "
                f"{', '.join('`' + c + '`' for c in w['menu_uses'])}")
    return (f"`{mod}` is requested directly in build/modules-efi.lst, nothing else in the image depends on "
            "it and the shipped .cfg files call none of its commands: if beast-booter does not need it, "
            "propose removing it (owner: build), then `make build`, `make e2e` and re-scan")


def context_severity(f: dict) -> tuple[str | None, str | None]:
    """beast-booter-specific: GRUB's config and the ESP are on a user-writable FAT partition, so
    'an attacker who controls grub.cfg / the boot media' is a given for a USB boot drive."""
    t = (f.get("description") or "") + " " + (f.get("title") or "")
    if re.search(r"secure ?boot|lockdown", t, re.I) and re.search(r"bypass|unsigned|circumvent", t, re.I):
        return "high", ("raised to high for beast-booter: a Secure Boot / lockdown bypass, and beast-booter's "
                        "grub.cfg and modules live on a FAT ESP that anyone holding the drive can modify")
    return None, None


def ubuntu_status(fetch: Fetcher, cve: str, sources: set[str], codename: str) -> dict | None:
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve):
        return None
    d, meta = fetch.json(f"ubuntu-cve/{cve}.json", UBUNTU_CVE.format(id=cve), max_age_h=24, timeout=20)
    if not isinstance(d, dict):
        return {"error": meta.get("note")}
    st = {}
    for p in d.get("packages", []) or []:
        if p.get("name") in sources:
            for s in p.get("statuses", []) or []:
                if s.get("release_codename") == codename:
                    st[p["name"]] = f"{s.get('status')}" + (f" ({s['description']})" if s.get("description") else "")
    return {"priority": d.get("priority"), "status": st, "source": meta.get("source")}


# =========================================================================== boot chain


def parse_dbx_bin(data: bytes) -> dict:
    """EFI_VARIABLE_AUTHENTICATION_2 + EFI_SIGNATURE_LISTs -> sha256 hashes and X.509 certs."""
    hashes, certs = set(), []
    off = 16                                        # EFI_TIME
    dwlen = struct.unpack_from("<I", data, off)[0]
    off += dwlen                                    # WIN_CERTIFICATE_UEFI_GUID (incl. header)
    while off + 28 <= len(data):
        stype = uuid.UUID(bytes_le=data[off:off + 16])
        lsize, hsize, ssize = struct.unpack_from("<III", data, off + 16)
        if lsize < 28 or ssize < 16:
            break
        body = off + 28 + hsize
        n = (lsize - 28 - hsize) // ssize
        for i in range(n):
            e = data[body + i * ssize + 16: body + (i + 1) * ssize]
            if stype == EFI_CERT_SHA256:
                hashes.add(e.hex())
            elif stype == EFI_CERT_X509:
                certs.append(e)
        off += lsize
    return {"sha256": hashes, "x509": certs}


ORIGIN_DEB_FILE = re.compile(r"deb:([a-z0-9][a-z0-9+.-]*)=(\S+?):(/\S+)")
ORIGIN_REPO_FILE = re.compile(r"(?:repo|key):([^\s,]+)")


def check_boot_chain(root: Path, dist: Path, manifest: dict, fetch: Fetcher, idx: dict,
                     manifest_sha: str, sbom_manifest_sha: str | None) -> dict:
    now = now_utc()
    efis = {rel: efi.inspect_efi(dist / rel) for rel in sorted(manifest["files"]) if rel.lower().endswith(".efi")}
    res: dict = {"findings": [], "efi": {rel: efi.public_view(i) for rel, i in efis.items()}}
    F = res["findings"]

    def finding(fid, sev, comp, title, detail, remediation, source):
        if remediation not in REMEDIATION_TEXT:     # a key, never free text (it indexes the catalogue)
            log(f"internal: {fid} uses unknown remediation key {remediation!r}")
        F.append({"id": fid, "severity": sev, "component": comp, "title": title, "detail": detail,
                  "remediation": remediation, "source": source})

    def comp_of(rel):
        c = idx.get(f"file:{rel}")
        return {"bom-ref": f"file:{rel}", "name": rel, "version": None, "purl": None, "cpe": None,
                "origin": c["props"].get("origin") if c else None}

    # ---- SBAT ------------------------------------------------------------------------
    data, meta = fetch.get("SbatLevel_Variable.txt", SBAT_URL)
    commit = fetch.commit("SbatLevel_Variable.commits.json", SBAT_COMMITS)
    sbat = {"source": SBAT_URL, "fetch": meta, "upstream_commit": commit, "binaries": {}}
    shim_rel = next((r for r in efis if r.upper().endswith("BOOTX64.EFI")), None)
    shim_levels = efis[shim_rel]["sbatlevel"] if shim_rel else None
    emb = {k: efi.parse_sbat_level(v) for k, v in (shim_levels or {}).items()}
    sbat["shipped_shim_embedded_levels"] = emb
    if data is None:
        sbat["result"] = f"not checked: {meta.get('note')}"
        finding("BB-SBAT-NOT-CHECKED", "high", comp_of(shim_rel or "esp/EFI/BOOT/BOOTX64.EFI"),
                "SBAT revocation not checked",
                f"{meta.get('note')}. Needs {SBAT_URL} once (it is then cached for --offline runs).",
                "R-DATA-UNAVAILABLE", "boot-chain:sbat")
    else:
        levels = efi.parse_sbat_level_variable_txt(data.decode("utf-8", "replace"))
        latest = levels[-1]
        sbat["latest_level"] = latest
        sbat["levels_known"] = [lv["datestamp"] for lv in levels]
        bad_any = False
        for rel, info in efis.items():
            rows = [r for r in efi.parse_sbat_csv(info["sbat"] or "") if r["component"] != "sbat"]
            table = []
            for r in rows:
                req = latest["components"].get(r["component"])
                req_prev = emb.get("previous", {}).get("components", {}).get(r["component"])
                req_lat = emb.get("latest", {}).get("components", {}).get(r["component"])
                status = "ok"
                if req is not None and r["generation"] is not None and r["generation"] < req:
                    status = "REVOKED by upstream latest"
                if any(x is not None and r["generation"] is not None and r["generation"] < x for x in (req_prev, req_lat)):
                    status = "REVOKED by the shipped shim itself"
                table.append({"component": r["component"], "generation": r["generation"],
                              "vendor_version": r["version"], "required_upstream_latest": req,
                              "required_shim_previous": req_prev, "required_shim_latest": req_lat,
                              "status": status})
                if status != "ok":
                    bad_any = True
                    finding(f"BB-SBAT-REVOKED-{r['component']}", "critical", comp_of(rel),
                            f"{rel}: SBAT {r['component']},{r['generation']} is below the revocation level "
                            f"{r['component']},{req} (SbatLevel {latest['datestamp']})",
                            f"Machines whose SbatLevel UEFI variable has reached {latest['datestamp']} refuse this "
                            f"binary under Secure Boot. Our SBAT line: {r['component']},{r['generation']},{r['vendor']},"
                            f"{r['package']},{r['version']}.",
                            "R-SBAT", "boot-chain:sbat")
            sbat["binaries"][rel] = {"sbat": rows and info["sbat"].strip(), "components": table}
        if emb.get("latest") and emb["latest"]["datestamp"] and emb["latest"]["datestamp"] < latest["datestamp"]:
            sbat["note"] = (f"the shipped shim embeds SbatLevel latest={emb['latest']['datestamp']} / previous="
                            f"{emb.get('previous', {}).get('datestamp')}; upstream is at {latest['datestamp']}. Our shim "
                            "never applies the newer level itself, but a newer shim booted on the same machine "
                            "(another distro, a firmware/OS update) can, and then the components below it are refused.")
        sbat["result"] = "revoked components found" if bad_any else "ok"

    # ---- signers ---------------------------------------------------------------------
    signers = {"binaries": {}, "alternatives": []}
    for rel, info in efis.items():
        sigs = []
        for s in info["signatures"]:
            if "error" in s:
                sigs.append({"error": s["error"]})
                continue
            chain = [{"cn": c["cn"], "issuer_cn": c["issuer_cn"], "not_after": c["not_after"],
                      "expired": bool(c["not_after"] and c["not_after"] < iso(now)), "sha1": c["sha1"],
                      "sha256": c["sha256"]} for c in s["certificates"]]
            sigs.append({"signer": (s["signer"] or {}).get("cn"), "issuer": (s["signer"] or {}).get("issuer_cn"),
                         "digest_matches_signature": s["digest_matches_signature"], "chain": chain})
        signers["binaries"][rel] = sigs
        if not any(x.get("digest_matches_signature") for x in sigs):
            finding(f"BB-SIG-BROKEN-{Path(rel).name}", "critical", comp_of(rel), f"{rel}: no valid Authenticode digest",
                    "The image's own signature does not match its content (or it is unsigned).",
                    "R-SIG-BROKEN", "boot-chain:signers")
    # shim and the 2011 CA
    if shim_rel:
        sigs = signers["binaries"][shim_rel]
        roots = {c["cn"] for s in sigs for c in s.get("chain", [])}
        ca2011 = [c for s in sigs for c in s.get("chain", []) if c["cn"] == "Microsoft Corporation UEFI CA 2011"]
        has2023 = any("UEFI CA 2023" in cn for cn in roots)
        # what else is available?
        cand_files = sorted(set(glob.glob("/usr/lib/shim/shim*.efi*") +
                                glob.glob(str(root / ".tools/root/usr/lib/shim/shim*.efi*"))))
        for cf in cand_files:
            if os.path.islink(cf):
                continue
            try:
                ci = efi.inspect_efi(Path(cf))
            except (efi.PEError, OSError, ValueError):
                continue
            chains = [[c["cn"] for c in s.get("certificates", [])] for s in ci["signatures"] if "error" not in s]
            signers["alternatives"].append({"file": cf, "signature_chains": chains,
                                            "uefi_ca_2023": any("UEFI CA 2023" in cn for ch in chains for cn in ch),
                                            "sbat": (ci["sbat"] or "").strip().replace("\n", " | ")})
        pol = subprocess.run(["apt-cache", "policy", "shim-signed"], capture_output=True, text=True)
        signers["apt_policy_shim_signed"] = " ".join(pol.stdout.split())[:400]
        if ca2011 and not has2023:
            c = ca2011[0]
            days = (now - dt.datetime.fromisoformat(c["not_after"].replace("Z", "+00:00"))).days
            alt2023 = [a["file"] for a in signers["alternatives"] if a["uefi_ca_2023"]]
            finding("BB-SHIM-UEFI-CA-2011-ONLY", "high", comp_of(shim_rel),
                    f"{shim_rel} is signed only through Microsoft Corporation UEFI CA 2011 "
                    f"(notAfter {c['not_after']}, {'expired ' + str(days) + ' days ago' if days > 0 else 'expires in ' + str(-days) + ' days'})",
                    "UEFI firmware does not enforce certificate expiry, so machines that trust the 2011 CA keep "
                    "booting this shim. Machines that ship only the 'Microsoft UEFI CA 2023' in db (new hardware), or "
                    "where the 2011 CA is removed/revoked, refuse it. No signature chains to a 2023 CA. "
                    + (f"Host files signed by a 2023 CA: {alt2023}." if alt2023 else
                       "No shim signed by a Microsoft UEFI CA 2023 was found on this host (/usr/lib/shim, .tools/root) "
                       "and the configured Ubuntu archive offers only: " + signers["apt_policy_shim_signed"]),
                    "R-CA2011", "boot-chain:signers")
    # ---- beast-booter certificate ------------------------------------------------------
    cer = next((r for r in manifest["files"] if r.endswith(".cer")), None)
    bbcert = None
    if cer:
        c = efi.cert_info((dist / cer).read_bytes())
        exp = dt.datetime.fromisoformat(c["not_after"].replace("Z", "+00:00"))
        days_left = (exp - now).days
        grub_rel = next((r for r in efis if r.endswith("grubx64.efi")), None)
        grub_signer = None
        if grub_rel:
            for s in efis[grub_rel]["signatures"]:
                if s.get("signer"):
                    grub_signer = s["signer"]["sha256"]
        bbcert = {"file": cer, "subject": c["subject"], "sha256": c["sha256"], "key": f"{c['key_algorithm']} {c['key_bits']}",
                  "signature_algorithm": c["signature_algorithm"], "not_before": c["not_before"],
                  "not_after": c["not_after"], "days_left": days_left, "eku": c["extended_key_usage"],
                  "code_signing_eku": c["code_signing_eku"], "self_signed": c["self_signed"],
                  "matches_manifest": c["sha256"] == manifest.get("secure_boot", {}).get("cert_sha256"),
                  "signs_grubx64": grub_signer == c["sha256"]}
        problems = []
        if c["key_algorithm"] == "rsaEncryption" and (c["key_bits"] or 0) < 2048:
            problems.append(f"RSA key of {c['key_bits']} bits (< 2048)")
        if not c["code_signing_eku"]:
            problems.append("no extendedKeyUsage codeSigning")
        if days_left < 0:
            problems.append(f"expired {-days_left} days ago")
        elif days_left < 365:
            problems.append(f"expires in {days_left} days")
        if not bbcert["matches_manifest"]:
            problems.append("differs from manifest.secure_boot.cert_sha256")
        if not bbcert["signs_grubx64"]:
            problems.append("grubx64.efi is not signed by this certificate")
        if "sha1" in c["signature_algorithm"].lower() or "md5" in c["signature_algorithm"].lower():
            problems.append(f"weak signature algorithm {c['signature_algorithm']}")
        bbcert["problems"] = problems
        if problems:
            sev = "critical" if any(x.startswith(("expired", "grubx64", "differs", "no extended")) for x in problems) else "medium"
            finding("BB-CERT-PROBLEM", sev, comp_of(cer), "beast-booter signing certificate: " + "; ".join(problems),
                    json.dumps({k: bbcert[k] for k in ("subject", "key", "not_after")}), "R-CERT", "boot-chain:cert")

    # ---- dbx ---------------------------------------------------------------------------
    dj, mj = fetch.json("dbx_info_msft_latest.json", DBX_JSON_URL)
    db_bin, mb = fetch.get("DBXUpdate-amd64.bin", DBX_BIN_URL)
    dcommit = fetch.commit("secureboot_objects-dbx.commits.json", DBX_COMMITS)
    dbx = {"sources": [DBX_JSON_URL, DBX_BIN_URL], "fetch": {"json": mj, "bin": mb}, "upstream_commit": dcommit,
           "binaries": {}}
    hashes: dict[str, str] = {}
    cert_thumbs: dict[str, str] = {}
    if isinstance(dj, dict):
        for arch, imgs in (dj.get("images") or {}).items():
            for im in imgs:
                h = (im.get("authenticodeHash") or "").lower()
                if h:
                    hashes[h] = f"{im.get('filename')} ({im.get('companyName')}, {arch}, added {im.get('dateOfAddition')}) {im.get('description') or ''}".strip()
                fh = (im.get("flatHash") or "").lower()
                if fh:
                    hashes.setdefault(fh, f"flat hash of {im.get('filename')}")
        for ce in dj.get("certificates") or []:
            cert_thumbs[(ce.get("thumbprint") or "").lower()] = f"{ce.get('subjectName')} ({ce.get('description')})"
        dbx["json_entries"] = {"image_hashes": len(hashes), "certificates": len(cert_thumbs),
                               "newest_dateOfAddition": max((im.get("dateOfAddition") or "" for imgs in
                                                             (dj.get("images") or {}).values() for im in imgs), default=None)}
    if db_bin:
        try:
            parsed = parse_dbx_bin(db_bin)
            for h in parsed["sha256"]:
                hashes.setdefault(h, "DBXUpdate.bin (amd64) SHA-256 entry")
            for der in parsed["x509"]:
                cert_thumbs.setdefault(hashlib.sha1(der).hexdigest(), "DBXUpdate.bin X.509 entry")
            dbx["bin_entries"] = {"sha256": len(parsed["sha256"]), "x509": len(parsed["x509"])}
        except (struct.error, ValueError) as e:
            dbx["bin_entries"] = {"error": str(e)}
    if not hashes:
        dbx["result"] = f"not checked: {mj.get('note') or mb.get('note') or 'no dbx data'}"
        finding("BB-DBX-NOT-CHECKED", "high", comp_of(shim_rel or "esp/EFI/BOOT/BOOTX64.EFI"), "dbx not checked",
                f"{dbx['result'].removeprefix('not checked: ')}. Needs {DBX_JSON_URL} or {DBX_BIN_URL} once (then cached for --offline runs).",
                "R-DATA-UNAVAILABLE", "boot-chain:dbx")
    else:
        hits = 0
        for rel, info in efis.items():
            h = info["authenticode_sha256"]
            hit = hashes.get(h) or hashes.get(info["file_sha256"])
            chain_hits = [f"{c['cn']}: {cert_thumbs[c['sha1']]}" for s in info["signatures"] if "error" not in s
                          for c in s["certificates"] if c["sha1"] in cert_thumbs]
            dbx["binaries"][rel] = {"authenticode_sha256": h, "revoked": bool(hit), "entry": hit,
                                    "revoked_certificates": chain_hits}
            if hit or chain_hits:
                hits += 1
                finding(f"BB-DBX-{Path(rel).name}", "critical", comp_of(rel), f"{rel} is revoked by the UEFI dbx",
                        hit or "; ".join(chain_hits), "R-DBX", "boot-chain:dbx")
        dbx["result"] = f"{hits} revoked" if hits else "ok: no shipped EFI binary or signer certificate is in dbx"

    # ---- manifest integrity + provenance ------------------------------------------------
    # Re-verified here from dist/ itself (not taken from the SBOM): every file the manifest says was
    # copied from a package must be byte-identical to that package's file, every repo:/key: file to
    # the working tree.
    prov = {"files": len(manifest["files"]), "sha256_mismatch": [], "local_origins": [], "fallback_loader": None,
            "origin_checked": 0, "origin_mismatch": [], "origin_unverified": [],
            "sbom_matches_manifest": sbom_manifest_sha is None or sbom_manifest_sha == manifest_sha}
    pkg_cache: dict = {}
    resolver = deb.Resolver(root)
    member_cache: dict = {}
    for rel, meta in manifest["files"].items():
        p = dist / rel
        o = meta["origin"]
        if o.startswith("local:"):
            prov["local_origins"].append({"file": rel, "origin": o})
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != meta["sha256"]:
            prov["sha256_mismatch"].append(rel)
            continue                                # BB-MANIFEST-MISMATCH covers it
        md = ORIGIN_DEB_FILE.fullmatch(o.strip())
        mr = ORIGIN_REPO_FILE.fullmatch(o.strip())
        if o.startswith("deb:"):
            prov["origin_checked"] += 1
            if not md:
                prov["origin_mismatch"].append({"file": rel, "origin": o, "result": "MISMATCH: origin names no "
                                                "single package file (expected deb:<pkg>=<version>:/path)"})
                continue
            key = (md.group(1), md.group(2))
            if key not in pkg_cache:
                pkg_cache[key] = resolver(md.group(1), md.group(2))
            if pkg_cache[key] is None:
                prov["origin_unverified"].append({"file": rel, "origin": o, "result": (
                    f"{md.group(1)}={md.group(2)} is neither installed on this host nor in .tools/debs "
                    "or the beast-net cache "
                    "(package changed since the build)")})
                continue
            v = deb.verify_member(p, pkg_cache[key], md.group(3), member_cache)
            if v.startswith("MISMATCH"):
                prov["origin_mismatch"].append({"file": rel, "origin": o, "result": v})
        elif mr:
            prov["origin_checked"] += 1
            src = (root / mr.group(1)).resolve()
            if not src.is_relative_to(root) or not src.is_file():
                prov["origin_unverified"].append({"file": rel, "origin": o,
                                                  "result": f"{mr.group(1)} is not in the working tree"})
            elif hashlib.sha256(src.read_bytes()).hexdigest() != meta["sha256"]:
                prov["origin_unverified"].append({"file": rel, "origin": o, "result": (
                    f"differs from working-tree {mr.group(1)} (the tree changed after the build, or the "
                    "shipped file was altered)")})
    prov["fallback_loader"] = [r for r in manifest["files"] if r.lower().endswith("fbx64.efi")]
    if prov["sha256_mismatch"]:
        finding("BB-MANIFEST-MISMATCH", "critical", {"bom-ref": "beast-booter", "name": "dist/manifest.json"},
                "dist/ files differ from manifest.json", ", ".join(prov["sha256_mismatch"][:10]),
                "R-MANIFEST", "boot-chain:manifest")
    if prov["origin_mismatch"]:
        finding("BB-ORIGIN-MISMATCH", "critical", comp_of(prov["origin_mismatch"][0]["file"]),
                f"{len(prov['origin_mismatch'])} shipped file(s) are not the package file their manifest origin names",
                "; ".join(f"{x['file']} ({x['origin']}): {x['result']}" for x in prov["origin_mismatch"][:10])
                + (f"; ... {len(prov['origin_mismatch']) - 10} more" if len(prov["origin_mismatch"]) > 10 else ""),
                "R-ORIGIN", "boot-chain:provenance")
    if prov["origin_unverified"]:
        finding("BB-ORIGIN-UNVERIFIED", "medium", comp_of(prov["origin_unverified"][0]["file"]),
                f"{len(prov['origin_unverified'])} shipped file(s) cannot be matched to their stated source today",
                "; ".join(f"{x['file']}: {x['result']}" for x in prov["origin_unverified"][:10]),
                "R-ORIGIN-REBUILD", "boot-chain:provenance")
    if not prov["sbom_matches_manifest"]:
        finding("BB-SBOM-STALE", "high", {"bom-ref": "beast-booter", "name": "sbom/beast-booter.cdx.json"},
                "the SBOM describes a different dist/manifest.json than the one on disk",
                f"SBOM manifest-sha256 {sbom_manifest_sha}, dist/manifest.json {manifest_sha}: the package "
                "findings below are for the old build", "R-SBOM-STALE", "boot-chain:manifest")
    if prov["local_origins"]:
        finding("BB-PROVENANCE-LOCAL", "medium", comp_of(prov["local_origins"][0]["file"]),
                f"{len(prov['local_origins'])} shipped file(s) come from outside the repository",
                "; ".join(f"{x['file']} <- {x['origin']}" for x in prov["local_origins"]),
                "R-PROVENANCE", "boot-chain:provenance")
    if prov["fallback_loader"]:
        finding("BB-FALLBACK-LOADER", "medium", comp_of(prov["fallback_loader"][0]), "fbx64.efi is shipped",
                "ARCHITECTURE section 4 forbids fbx64.efi (it creates firmware boot entries).", "R-FALLBACK",
                "boot-chain:manifest")
    nx = {rel: info["nx_compat"] for rel, info in efis.items()}

    # ---- archive: newer boot packages? ----------------------------------------------------
    arch = {}
    for src in ("shim-signed", "shim", "grub2-unsigned", "grub2-signed"):
        d, m = fetch.json(f"launchpad/{src}.json", LP_SOURCES.format(name=src), max_age_h=24)
        if isinstance(d, dict):
            pubs = [{"version": e["source_package_version"], "series": e["distro_series_link"].rsplit("/", 1)[-1],
                     "pocket": e["pocket"], "status": e["status"], "date": e.get("date_published")}
                    for e in d.get("entries", []) if e.get("status") in ("Published", "Pending")]
            arch[src] = {"published": pubs[:8], "source": m.get("source")}
        else:
            arch[src] = {"error": m.get("note")}
    res.update(sbat=sbat, signers=signers, beast_booter_cert=bbcert, dbx=dbx, provenance=prov, nx_compat=nx,
               archive=arch)
    return res


# =========================================================================== remediation


def remediation(f: dict, idx: dict, codename: str, archive: dict) -> tuple[str, str]:
    c = f["component"]
    cc = idx.get(c["bom-ref"], {})
    src = cc.get("props", {}).get("source-package") or c["name"]
    pkgname = c["name"]
    if f["scope"] == "build":
        fixv = ", ".join(f["fix"]["versions"]) or "none published yet"
        return ("R-BUILD", f"Build/test tooling only - nothing from {pkgname} is on the drive. Update {pkgname} on the "
                f"build host (fixed version: {fixv}); for .tools/debs packages re-run `make tools`. Lower priority; "
                "recorded so it is not forgotten.")
    ev = f.get("evidence") or []
    ub0 = (f.get("ubuntu") or {}).get("status") or {}
    ubs0 = f" Ubuntu {codename}: " + ", ".join(f"{k} {v}" for k, v in ub0.items()) + "." if ub0 else ""
    if cc.get("role") == "portable":
        if f["fix"]["versions"] or not f.get("cpe_only"):
            return ("R-RUNTIME-UPDATE", f"{pkgname} {c.get('version')} is bundled in the portable packages' "
                    f"python-build-standalone runtime (targets: {cc.get('props', {}).get('targets') or 'all'}), not "
                    "on the drive. Move packaging/portable/runtimes.lock to a python-build-standalone release whose "
                    f"{pkgname} includes the fix" + (f" ({', '.join(f['fix']['versions'])})" if f["fix"]["versions"]
                                                     else "") +
                    " (new asset names, URLs and SHA-256 from its SHA256SUMS), rebuild with "
                    "`scripts/build_portable.sh --all`, regenerate the SBOM and re-scan.")
        return ("R-RUNTIME-TRACK", f"{pkgname} {c.get('version')} in the portable runtime matches this advisory by "
                "CPE only. Check the advisory's affected range against the bundled version; when it applies, track "
                "the next python-build-standalone release (R-RUNTIME-UPDATE), otherwise record OpenVEX not_affected "
                "with a justification.")
    if beastnet_component(cc, idx):
        bu = cc.get("props", {}).get("built-using-of")
        static = (f" {pkgname} is built into {bu} (Built-Using), so the fix reaches beast-net only when Ubuntu "
                  f"rebuilds {bu} against it." if bu else "")
        if f["fix"]["versions"]:
            return ("R-BEASTNET-UPDATE", f"Fixed in {pkgname} {', '.join(f['fix']['versions'])} (Ubuntu {codename}).{static} "
                    "beast-net (esp/beast-net, the download helper) uses the packages pinned in "
                    "build/beastnet/packages.lock: regenerate it with `python3 -I build/beastnet/lock.py` once the "
                    "update is in the archive (a new kernel ABI also needs build/beastnet/packages.in), then "
                    "`make build`, `make e2e` (test_e2e_beastnet), regenerate the SBOM and re-scan.")
        return ("R-BEASTNET-TRACK", f"No fixed Ubuntu package for {pkgname} yet.{ubs0} It is part of beast-net, the "
                "helper Linux that boots only when the user chooses to download an ISO and runs from RAM. Track the "
                "Ubuntu update (USN); when it is published, refresh build/beastnet/packages.lock as in "
                "R-BEASTNET-UPDATE. Meanwhile record an OpenVEX statement: affected with an action_statement, or "
                "not_affected (e.g. vulnerable_code_not_present when the affected driver is not in "
                "build/beastnet/modules.list).")
    if f["fix"]["versions"]:
        return ("R-UPDATE", f"Fixed in {pkgname} {', '.join(f['fix']['versions'])} (Ubuntu {codename}). Update the "
                f"package used by the build (host: `apt-get install --only-upgrade {pkgname}`; .tools/debs: `make tools`), "
                "then `make build`, regenerate the SBOM, `make e2e`, re-scan and confirm the finding is gone.")
    if any(e["kind"] == "fix" for e in ev):
        e = next(e for e in ev if e["kind"] == "fix")
        return ("R-VEX-FIXED", f"The shipped code already contains the fix: {e['changelog']} records "
                f"'{e['context']}' in {e['entry']}, an ancestor of the shipped {e['package']} {e['package_version']}. "
                "The scanner reports it because the Ubuntu tracker has not triaged this package"
                + (f" (Ubuntu {codename}: {', '.join(f'{k}: {v}' for k, v in (f.get('ubuntu') or {}).get('status', {}).items())})"
                   if (f.get("ubuntu") or {}).get("status") else "")
                + ". Review the proposed statement (status fixed) in sbom/vex.proposed.openvex.json and copy it into "
                "sbom/vex.openvex.json.")
    desc = (f.get("description") or "") + " " + (f.get("title") or "")
    m = re.search(r"\b(grub2?-[a-z0-9-]+)\b(?: utility| tool| program)", desc)
    if m:
        return ("R-VEX-NOTPRESENT", f"The advisory is about `{m.group(1)}`, a userland tool beast-booter does not ship "
                "(no such file in the SBOM). Record OpenVEX not_affected with justification component_not_present "
                "(proposed in sbom/vex.proposed.openvex.json).")
    hints = f.get("grub_modules") or []
    emb = sorted({x for h in hints for x in h["in_efi_image"]})
    newer, checked = [], []
    fam = FAMILY.get(src) or ("grub2" if c["name"].endswith("grub2") else None)
    for s in {"grub2": ("grub2-unsigned", "grub2-signed"), "shim": ("shim-signed", "shim")}.get(fam, ()):
        shipped = next((x["props"].get("source-version") for x in idx.values()
                        if x["props"].get("source-package") == s and x.get("role") in ("shipped", "build")), None)
        if not shipped or not (archive.get(s) or {}).get("published"):
            continue
        checked.append(f"{s} {shipped}")
        for p in archive[s]["published"]:
            if deb.compare_versions(p["version"], "gt", shipped):
                newer.append(f"{s} {p['version']} ({p['series']}-{p['pocket'].lower()})")
    track = (f" Newer in the Ubuntu archive: {', '.join(sorted(set(newer))[:4])}." if newer else
             f" Launchpad shows nothing newer than {', '.join(checked)} in any Ubuntu series." if checked else "")
    ub = (f.get("ubuntu") or {}).get("status") or {}
    ubs = f" Ubuntu {codename}: " + ", ".join(f"{k} {v}" for k, v in ub.items()) + "." if ub else ""
    if f.get("severity_context") and (FAMILY.get(src) == "grub2" or c["name"].endswith("grub2")):
        return ("R-SB-BYPASS", f"No fixed GRUB package yet and no evidence the fix is in the shipped build.{ubs} This is a "
                "Secure Boot / lockdown bypass that needs control of GRUB's configuration - on a beast-booter drive grub.cfg, "
                "grub/beast/*.cfg and /grub/ are on a FAT ESP anyone holding the drive can modify, so treat it as reachable. "
                "Actions: (1) take the Ubuntu grub2 fix as soon as it is published (it should also raise the SBAT "
                "generation, see R-SBAT), `make build`, `make e2e`, re-scan; (2) document the gap in SECURITY.md / "
                "docs/SECURE_BOOT.md; (3) proposal for the build owner: evaluate GRUB's GPG verification of everything "
                "it reads (grub-mkimage --pubkey + check_signatures=enforce, menu files signed at build time) so a "
                f"tampered ESP is detected. Record OpenVEX affected with that action_statement meanwhile.{track}")
    if FAMILY.get(src) == "grub2" or c["name"].endswith("grub2"):
        if hints and not emb:
            mods = sorted({x for h in hints for x in h["modules"]})
            return ("R-GRUB-NOT-EMBEDDED", f"No fixed GRUB package yet.{ubs} The advisory names {', '.join(h['area'] for h in hints)} "
                    f"(module {', '.join(mods)}), which is NOT in grubx64.efi (build/modules-efi.lst plus moddep.lst "
                    "dependencies) and no x86_64-efi modules are shipped, so the UEFI path does not contain the code; it "
                    "ships only as a BIOS module in /grub/i386-pc. Review the proposed OpenVEX not_affected / "
                    "vulnerable_code_not_present statement for the EFI package (sbom/vex.proposed.openvex.json) and "
                    f"track grub2 updates for grub-pc-bin.{track}")
        if emb:
            ws = list({w["module"]: w for h in hints for w in h.get("efi_removability") or []}.values())
            why = "; ".join(removability_text(w) for w in ws)
            drop = [w["module"] for w in ws if w["removable"]]
            opts = ["(1) take the Ubuntu grub2 update as soon as it is published, then `make build`, `make e2e` "
                    "and re-scan"]
            if drop:
                opts.append(f"({len(opts) + 1}) propose dropping {', '.join(drop)} from build/modules-efi.lst "
                            "(owner: build) if beast-booter does not need it")
            opts.append(f"({len(opts) + 1}) record OpenVEX under_investigation (or affected with an "
                        "action_statement) meanwhile")
            return ("R-GRUB-EMBEDDED", f"No fixed GRUB package yet.{ubs} The advisory names module(s) {', '.join(emb)}, "
                    f"which ARE embedded in grubx64.efi. {why}. "
                    + ("Removing the module is therefore not an option; the package update is the fix. " if not drop else "")
                    + f"Options: {'; '.join(opts)}.{track}")
        if f.get("cpe_only"):
            return ("R-NVD-CPE", "NVD lists this CVE for every GRUB version (CPE without a version range), so it matches "
                    "GNU GRUB 2.14 by name only. Check the upstream fix commit against GRUB 2.14 / Ubuntu 2.14-2ubuntu1; "
                    "record OpenVEX fixed (or not_affected with a justification) when it is included, otherwise "
                    f"treat as R-GRUB-EMBEDDED.{track}")
        return ("R-GRUB-TRACK", f"No fixed GRUB package yet and no evidence the fix is in 2.14-2ubuntu1.{ubs} Find the "
                "upstream fix commit and check the grub2-unsigned source; if absent, track the Ubuntu grub2 update "
                "(it will also bump the SBAT generation - see R-SBAT), rebuild with `make build` and re-scan. Record "
                f"OpenVEX under_investigation meanwhile.{track}")
    if FAMILY.get(src) == "shim":
        return ("R-SHIM-TRACK", f"No fixed shim-signed package yet.{ubs} shim must stay the Microsoft-signed Ubuntu "
                "binary (beast-booter cannot rebuild it). Track shim-signed updates; when one is published, update the "
                "host package, `make build`, `make e2e` (including the Secure Boot run) and re-scan. Assess impact "
                f"(e.g. a local DoS needing physical access) and record OpenVEX under_investigation or affected.{track}")
    return ("R-TRACK", f"No fixed package yet for {pkgname}.{ubs} Track the distribution update; rebuild and re-scan when "
            "it lands, and record an OpenVEX statement with the assessment meanwhile.")


# =========================================================================== report


def vex_proposals(findings: list[dict], ts: str, product: str, modules: dict) -> dict:
    st = []
    for f in findings:
        if f["status"] != "open" or f["scope"] != "shipped":
            continue
        prod = [{"@id": product, "subcomponents": [
            {"@id": f["component"]["purl"] or f["component"]["cpe"] or f["component"]["bom-ref"]}]}]
        if f["remediation_key"] == "R-VEX-FIXED":
            e = next(e for e in f["evidence"] if e["kind"] == "fix")
            st.append({"vulnerability": {"name": f["id"], "aliases": f["aliases"]}, "products": prod,
                       "status": "fixed", "timestamp": ts,
                       "status_notes": f"PROPOSED by scan_vulns.py - verify before use. {e['changelog']}: "
                                       f"{e['entry']}: {e['context']}"})
        elif f["remediation_key"] == "R-VEX-NOTPRESENT":
            st.append({"vulnerability": {"name": f["id"], "aliases": f["aliases"]}, "products": prod,
                       "status": "not_affected", "justification": "component_not_present", "timestamp": ts,
                       "impact_statement": "PROPOSED by scan_vulns.py - verify before use. The affected userland "
                                           "utility is not part of beast-booter (not in the SBOM)."})
        elif f["remediation_key"] == "R-GRUB-NOT-EMBEDDED" and "efi" in (f["component"]["name"] + (f["component"]["purl"] or "")) \
                and not modules.get("x86_64_efi_modules_shipped"):
            mods = sorted({x for h in f.get("grub_modules", []) for x in h["modules"]})
            st.append({"vulnerability": {"name": f["id"], "aliases": f["aliases"]}, "products": prod,
                       "status": "not_affected", "justification": "vulnerable_code_not_present",
                       "timestamp": ts,
                       "impact_statement": f"PROPOSED by scan_vulns.py - verify before use. Affected module(s) "
                                           f"{', '.join(mods)} are not in beast-booter's grubx64.efi ({modules.get('efi_closure_source')}), "
                                           "and beast-booter ships no x86_64-efi modules on the drive (GRUB lockdown would "
                                           "refuse to load them under Secure Boot anyway). The BIOS path is a separate "
                                           "product component (grub-pc-bin) and is not covered by this statement."})
    return {"@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://beast-booter.invalid/vex/proposed-{hashlib.sha256(json.dumps(st, sort_keys=True).encode()).hexdigest()[:16]}",
            "author": "beast-booter sbom-vuln scan_vulns.py (proposals; not authoritative)",
            "timestamp": ts, "version": 1, "statements": st}


def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def write_markdown(path: Path, rep: dict) -> None:
    L = []
    a = L.append
    s = rep["summary"]
    a("# beast-booter vulnerability report")
    a("")
    a(f"Generated {rep['generated']} by `scripts/scan_vulns.py` from "
      f"`{rep['sbom']['path']}` (serial `{rep['sbom']['serialNumber']}`, beast-booter {rep['sbom']['version']}, "
      f"build `{rep['sbom']['build_id']}`). Machine-readable: `sbom/vulnerabilities.json`.")
    a("")
    g = rep["scanners"]["grype"]
    a(f"- **grype** {g.get('version')} - DB schema {g.get('db', {}).get('schema')}, built {g.get('db', {}).get('built')}"
      + (" (**stale**)" if g.get("db", {}).get("stale") else "") + f"; {'ok' if g.get('ok') else 'FAILED: ' + str(g.get('error'))}")
    for o in rep["scanners"]["osv-scanner"]:
        a(f"- **osv-scanner** {o.get('version')} ({o['label']}) - {o.get('packages_scanned')} packages, "
          f"{o.get('mode', 'n/a')}; {'ok' if o.get('ok') else 'FAILED: ' + str(o.get('error'))}")
    vfiles = rep["vex"]["meta"].get("files") or [{"path": rep["vex"].get("path") or "sbom/vex.openvex.json",
                                                  "statements": rep["vex"]["meta"].get("statements", 0)}]
    a("- **VEX**: " + ", ".join(f"`{f['path']}` - {f.get('statements', 0)} statement(s)" for f in vfiles)
      + (f", **{len(rep['vex']['errors'])} problem(s)**: " + "; ".join(rep["vex"]["errors"]) if rep["vex"]["errors"] else ""))
    a("- **Boot-chain checks**: SBAT, Authenticode signers, beast-booter certificate, dbx, manifest/provenance "
      "(sources and dates below).")
    a("")
    a("## Summary")
    a("")
    a("| Open findings | Critical | High | Medium | Low | Negligible | Unknown | Total |")
    a("|---|---:|---:|---:|---:|---:|---:|---:|")
    for k, label in (("boot_chain", "Boot chain (beast-booter checks)"), ("shipped", "Shipped packages (on the drive)"),
                     ("build", "Build / install / test tooling")):
        row = s["open"][k]
        a(f"| {label} | " + " | ".join(str(row.get(x, 0)) for x in SEV_ORDER) + f" | {sum(row.values())} |")
    a("")
    a(f"Closed by VEX: {s['closed']}. Raw scanner matches: grype {s['raw']['grype']}, osv-scanner {s['raw']['osv']}; "
      f"after merging aliases and duplicates: {s['merged']} findings on {s['components_affected']} components. "
      f"{s['proposals']} findings have an evidence-backed VEX proposal in `sbom/vex.proposed.openvex.json`.")
    a("")
    a("### What to do first")
    a("")
    for i, t in enumerate(rep["top_actions"], 1):
        a(f"{i}. {t}")
    a("")
    # ---- boot chain
    bc = rep["boot_chain"]
    a("## Boot-chain checks")
    a("")
    sb = bc["sbat"]
    a("### SBAT revocation")
    a("")
    a(f"Source: {sb['source']} - {sb['fetch'].get('source')} copy fetched {sb['fetch'].get('fetched_at', 'n/a')}"
      + (f", upstream commit `{(sb['upstream_commit'] or {}).get('commit', '')[:12]}` ({(sb['upstream_commit'] or {}).get('date')})"
         if (sb.get("upstream_commit") or {}).get("commit") else "") + (f". {sb['fetch'].get('note')}" if sb["fetch"].get("note") else "") + ".")
    a("")
    if sb.get("latest_level"):
        lv = sb["latest_level"]
        a(f"Latest revocation level: `sbat,1,{lv['datestamp']}` " + " ".join(f"`{k},{v}`" for k, v in lv["components"].items())
          + f". Shipped shim embeds: previous `{(sb['shipped_shim_embedded_levels'].get('previous') or {}).get('datestamp')}`, "
          f"latest `{(sb['shipped_shim_embedded_levels'].get('latest') or {}).get('datestamp')}`.")
        a("")
        a("| Binary | SBAT component | Generation | Required (upstream latest) | Required (our shim) | Result |")
        a("|---|---|---:|---:|---:|---|")
        for rel, b in sb["binaries"].items():
            for r in b["components"]:
                ours = "/".join(str(x) for x in (r["required_shim_previous"], r["required_shim_latest"]) if x is not None) or "-"
                a(f"| `{rel}` | {r['component']} ({md_escape(r['vendor_version'])}) | {r['generation']} | "
                  f"{r['required_upstream_latest'] if r['required_upstream_latest'] is not None else '-'} | {ours} | "
                  f"{'**' + r['status'] + '**' if r['status'] != 'ok' else 'ok'} |")
        if sb.get("note"):
            a("")
            a(f"Note: {sb['note']}")
    else:
        a(f"**{sb.get('result')}**")
    a("")
    a("### Authenticode signers")
    a("")
    a("| Binary | Signer | Certificates in the signature (notAfter) | Digest |")
    a("|---|---|---|---|")
    for rel, sigs in bc["signers"]["binaries"].items():
        for sg in sigs:
            if "error" in sg:
                a(f"| `{rel}` | {sg['error']} | | |")
                continue
            chain = "; ".join(f"{c['cn']} ({c['not_after'][:10]}{', expired' if c['expired'] else ''})" for c in sg["chain"])
            a(f"| `{rel}` | {md_escape(sg['signer'])} | {md_escape(chain)} | {'ok' if sg['digest_matches_signature'] else 'MISMATCH'} |")
    a("")
    a("Other shim builds on this host: " + ("; ".join(
        f"`{x['file']}`: " + (" + ".join(' <- '.join(ch) for ch in x["signature_chains"]) or "unsigned") + (" (**UEFI CA 2023**)" if x["uefi_ca_2023"] else "")
        for x in bc["signers"]["alternatives"]) or "none") + ".")
    a("")
    a(f"`apt-cache policy shim-signed`: {bc['signers'].get('apt_policy_shim_signed', 'n/a')}")
    a("")
    arch = bc.get("archive", {})
    if arch:
        a("Ubuntu archive (Launchpad), newest published boot packages: " + "; ".join(
            f"{k}: " + ", ".join(sorted({f"{p['version']} ({p['series']})" for p in v.get('published', [])[:6]}))
            for k, v in arch.items() if v.get("published")) + ".")
        a("")
    c = bc.get("beast_booter_cert")
    a("### beast-booter signing certificate")
    a("")
    if c:
        a(f"`{c['file']}`: `{c['subject']}`, {c['key']}, {c['signature_algorithm']}, valid {c['not_before'][:10]} to "
          f"{c['not_after'][:10]} ({c['days_left']} days left), EKU: {c['eku'] or 'none'}, self-signed: {c['self_signed']}, "
          f"matches manifest: {c['matches_manifest']}, signs grubx64.efi: {c['signs_grubx64']}. SHA-256 `{c['sha256']}`. "
          + ("Problems: " + "; ".join(c["problems"]) if c["problems"] else "No problems found."))
    else:
        a("No certificate in dist/.")
    a("")
    d = bc["dbx"]
    a("### dbx (UEFI revocation list)")
    a("")
    a(f"Sources: Microsoft secureboot_objects `dbx_info_msft_latest.json` ({d['fetch']['json'].get('source')}, fetched "
      f"{d['fetch']['json'].get('fetched_at', 'n/a')}) and `DBXUpdate.bin` amd64 ({d['fetch']['bin'].get('source')})"
      + (f", upstream commit `{(d['upstream_commit'] or {}).get('commit', '')[:12]}` ({(d['upstream_commit'] or {}).get('date')})"
         if (d.get("upstream_commit") or {}).get("commit") else "") + ". "
      + (f"{d.get('json_entries', {}).get('image_hashes')} image hashes and {d.get('json_entries', {}).get('certificates')} certificates "
         f"(newest entry {d.get('json_entries', {}).get('newest_dateOfAddition')}); DBXUpdate.bin: {d.get('bin_entries')}." if d.get("json_entries") else ""))
    a("")
    a(f"Result: **{d['result']}**")
    a("")
    if d.get("binaries"):
        a("| Binary | Authenticode SHA-256 | In dbx |")
        a("|---|---|---|")
        for rel, b in d["binaries"].items():
            a(f"| `{rel}` | `{b['authenticode_sha256']}` | {'**YES: ' + md_escape(b['entry'] or '; '.join(b['revoked_certificates'])) + '**' if b['revoked'] or b['revoked_certificates'] else 'no'} |")
        a("")
    pv = bc["provenance"]
    a("### Manifest and provenance")
    a("")
    a(f"{pv['files']} files in dist/manifest.json; SHA-256 mismatches against the manifest: {len(pv['sha256_mismatch'])}; "
      f"origin re-verified for {pv.get('origin_checked', 0)} package/repo files: **{len(pv.get('origin_mismatch', []))} not "
      f"identical to their package file**, {len(pv.get('origin_unverified', []))} not verifiable today; SBOM describes "
      f"this manifest: {pv.get('sbom_matches_manifest')}; fbx64.efi shipped: "
      f"{bool(pv['fallback_loader'])}; files from outside the repo: {len(pv['local_origins'])}"
      + (" (" + ", ".join(f"`{x['file']}`" for x in pv["local_origins"]) + ")" if pv["local_origins"] else "") + ". "
      "NX_COMPAT flag: " + ", ".join(f"`{Path(k).name}` {'yes' if v else 'no'}" for k, v in bc["nx_compat"].items()) + ".")
    a("")
    a("| ID | Severity | Finding | Remediation |")
    a("|---|---|---|---|")
    for f in bc["findings"]:
        a(f"| {f['id']} | **{f['severity']}** | {md_escape(f['title'])}. {md_escape(f['detail'])} | [{f['remediation']}](#{f['remediation'].lower()}) |")
    a("")
    # ---- shipped findings
    a("## Shipped findings (on the drive)")
    a("")
    sf = [f for f in rep["findings"] if f["scope"] == "shipped" and f["status"] in ("open", "affected", "under_investigation")
          and f["source"] != "boot-chain"]
    by_id: dict[str, list] = {}
    for f in sf:
        by_id.setdefault(f["id"], []).append(f)
    for sev in SEV_ORDER:
        rows = [(i, fs) for i, fs in by_id.items() if max(fs, key=lambda x: SEV_RANK[x["severity"]])["severity"] == sev]
        if not rows:
            continue
        a(f"### {sev.capitalize()} ({len(rows)} vulnerabilities, {sum(len(fs) for _, fs in rows)} component findings)")
        a("")
        # Below high, beast-net findings without a published fix (thousands for the kernel) are
        # summarised: there is nothing to do per finding but track the Ubuntu update.
        tracked = []
        if SEV_RANK[sev] < SEV_RANK["high"]:
            tracked = [(i, fs) for i, fs in rows if {f["remediation_key"] for f in fs} == {"R-BEASTNET-TRACK"}]
            rows = [r for r in rows if r not in tracked]
        if tracked:
            comps_t = sorted({f["component"]["name"] for _, fs in tracked for f in fs})
            a(f"{len(tracked)} of them are beast-net findings with no fixed Ubuntu package yet "
              f"([R-BEASTNET-TRACK](#r-beastnet-track); components: {md_escape(', '.join(comps_t))}), listed in "
              f"vulnerabilities.json, for example {', '.join(sorted(i for i, _ in tracked)[:12])}.")
            a("")
        if not rows:
            continue
        a("| Vulnerability | Components | Fix | Evidence / Ubuntu status | Scanners | Remediation |")
        a("|---|---|---|---|---|---|")
        for i, fs in sorted(rows):
            comps = ", ".join(sorted({f"{f['component']['name']} {f['component']['version'] or ''}".strip() for f in fs}))
            fix = ", ".join(sorted({v for f in fs for v in f["fix"]["versions"]})) or (fs[0]["fix"]["state"] or "unknown")
            evs = []
            for f in fs:
                for e in f.get("evidence") or []:
                    if e["kind"] == "fix":
                        evs.append(f"changelog {e['entry']}")
                for h in f.get("grub_modules") or []:
                    by = sorted({x for w in h.get("efi_removability") or [] for x in w.get("pulled_in_by") or []})
                    evs.append(f"module {'/'.join(h['modules'])}: {'in' if h['in_efi_image'] else 'not in'} grubx64.efi"
                               + (f" (dependency of {', '.join(by[:4])}{', ...' if len(by) > 4 else ''})" if by else ""))
                ub = (f.get("ubuntu") or {}).get("status") or {}
                evs += [f"Ubuntu {k}: {v.split(' (')[0]}" for k, v in ub.items()]
                if (f.get("ubuntu") or {}).get("error"):
                    evs.append("Ubuntu tracker: unavailable")
            keys = sorted({f["remediation_key"] for f in fs})
            title = md_escape((fs[0]["title"] or fs[0]["description"])[:110])
            a(f"| [{i}]({fs[0]['urls'][0] if fs[0]['urls'] else 'https://osv.dev/' + i}) {title} | {md_escape(comps)} | {md_escape(fix)} | "
              f"{md_escape('; '.join(sorted(set(evs))))} | {', '.join(sorted({x for f in fs for x in f['sources']}))} | "
              + ", ".join(f"[{k}](#{k.lower()})" for k in keys) + " |")
        a("")
    if not sf:
        a("None.")
        a("")
    # ---- remediation catalogue
    a("## Remediations")
    a("")
    a("Each open finding above points to one of these. The detailed, per-finding text (with the exact package, "
      "version and evidence) is in `sbom/vulnerabilities.json` (`remediation`). General guide: "
      "`.claude/skills/sbom-vuln/references/remediation.md`.")
    a("")
    for k, txt in rep["remediation_catalogue"].items():
        a(f"### {k}")
        a("")
        a(txt)
        a("")
    # ---- build
    a("## Build, install and test tooling (not on the drive)")
    a("")
    bf = [f for f in rep["findings"] if f["scope"] == "build" and f["status"] in ("open", "affected", "under_investigation")]
    by_pkg: dict[str, list] = {}
    for f in bf:
        src = f.get("source_package") or f["component"]["name"]
        by_pkg.setdefault(src, []).append(f)
    if bf:
        a("Remediation for every row: [R-BUILD](#r-build) - update the package on the build host / `make tools`, rebuild, re-scan.")
        a("")
        a("| Source package (components) | Role | Open | Highest | Fixable now | Vulnerability IDs |")
        a("|---|---|---:|---|---|---|")
        for src, fs in sorted(by_pkg.items(), key=lambda kv: (-max(SEV_RANK[f["severity"]] for f in kv[1]), kv[0])):
            ids = sorted({f["id"] for f in fs})
            comps = sorted({f["component"]["name"] for f in fs})
            fixable = sorted({f"{f['id']}->{','.join(f['fix']['versions'])}" for f in fs if f["fix"]["versions"]})
            hi = max((f["severity"] for f in fs), key=lambda x: SEV_RANK[x])
            a(f"| {src} ({', '.join(comps)}) | {', '.join(sorted({f['role'] for f in fs}))} | {len(ids)} | {hi} | "
              f"{md_escape(', '.join(fixable)) or 'none'} | {', '.join(ids)} |")
    else:
        a("None.")
    a("")
    closed = [f for f in rep["findings"] if f["status"] in ("not_affected", "fixed")]
    a("## Closed by VEX")
    a("")
    if closed:
        a("| Vulnerability | Component | Status | Justification / notes |")
        a("|---|---|---|---|")
        for f in closed:
            v = f["vex"] or {}
            a(f"| {f['id']} | {f['component']['name']} | {f['status']} | {md_escape(v.get('justification') or '')} "
              f"{md_escape(v.get('impact_statement') or v.get('status_notes') or '')} |")
    else:
        a("None yet - `sbom/vex.openvex.json` has no statements. See `sbom/vex.proposed.openvex.json` for "
          "evidence-backed proposals to review.")
    a("")
    a("## Data sources")
    a("")
    a("| Data | URL | Copy used | Fetched |")
    a("|---|---|---|---|")
    for k, m in sorted(rep["data_sources"].items()):
        if k.startswith("ubuntu-cve/"):
            continue
        a(f"| {k} | {m.get('url', '')} | {m.get('source')} | {m.get('fetched_at', '')} {md_escape(m.get('note', ''))} |")
    ub = [m for k, m in rep["data_sources"].items() if k.startswith("ubuntu-cve/")]
    n_bad = sum(1 for m in ub if m.get("source") == "unavailable")
    a(f"| Ubuntu CVE tracker | https://ubuntu.com/security/cves/<id>.json | {len(ub) - n_bad} records"
      + (f", {n_bad} unavailable (ubuntu.com timed out; re-run later)" if n_bad else "") + " | cached 24 h |")
    a("")
    path.write_text("\n".join(L) + "\n")


REMEDIATION_TEXT = {
    "R-SBAT": "GRUB's SBAT generation is below shim's published revocation level, so machines that have applied that "
              "level refuse grubx64.efi under Secure Boot. Fix by moving to a GRUB build whose upstream SBAT generation "
              "meets the level: update grub-efi-amd64-bin **and** grub-efi-amd64-signed (the SBAT source) to an Ubuntu "
              "release that carries it, then `make build`, `make e2e`, regenerate the SBOM and re-scan. Do **not** edit "
              "the `grub,N` line by hand - SBAT must truthfully describe the code. Only bump `grub.beastbooter` in "
              "build/sbat-beastbooter.csv for beast-booter's own GRUB bugs. Until a fixed package exists, document the "
              "limitation (docs/SECURE_BOOT.md) and keep the BIOS and Secure-Boot-off paths working.",
    "R-CA2011": "Ship a shim that is also signed by the Microsoft UEFI CA 2023 as soon as Ubuntu publishes one "
                "(watch shim-signed in the archive; Launchpad data is in this report). When it exists: point the build at "
                "it (build/build.sh copies BB_SHIM_DIR/shimx64.efi.signed.latest), keep MokManager from the same "
                "shim-signed build, rebuild, run the e2e Secure Boot test with an OVMF varstore that has only the 2023 CA. "
                "Meanwhile document in docs/SECURE_BOOT.md that machines whose db lacks the 2011 CA cannot boot "
                "beast-booter with Secure Boot on.",
    "R-CERT": "Regenerate the beast-booter key with `make keys` (RSA >= 2048, codeSigning EKU, long validity), rebuild "
              "(`make build`) and tell users to enroll the new ENROLL_THIS_KEY_IN_MOKMANAGER.cer.",
    "R-DBX": "Never ship a binary that is in dbx. Replace it with a non-revoked build of the same component (newer "
             "shim-signed / GRUB package), rebuild, and verify with this scan.",
    "R-SIG-BROKEN": "The binary's Authenticode digest does not match its content: rebuild (`make build`) and check "
                    "`sbverify --list`; never ship it.",
    "R-MANIFEST": "dist/ does not match manifest.json - rebuild with `make build` (another process may be writing dist/).",
    "R-ORIGIN": "A shipped file is not byte-identical to the package file its manifest origin names (deb:<pkg>=<ver>:/path): "
                "dist/ was altered after the build, the build copied a modified host file, or the origin names the wrong "
                "package - and then every CVE match for that file is wrong too. Do not release. Check the host package "
                "(`dpkg --verify <pkg>`) or re-fetch .tools/debs (`make tools`), rebuild with `make build`, regenerate "
                "the SBOM and re-run validation and the scan until BB-ORIGIN-MISMATCH is gone. If beast-booter patches "
                "the file on purpose, the build must record it as `built:` with its inputs, not as `deb:`.",
    "R-ORIGIN-REBUILD": "The stated source of a shipped file cannot be checked today: a repo:/key: file differs from the "
                        "working tree (edited after the build) or the named package version is no longer installed / in "
                        ".tools/debs. Rebuild with `make build` from the current tree and packages, then regenerate "
                        "the SBOM and re-scan, so the drive matches what the repository says.",
    "R-SBOM-STALE": "The SBOM was generated from a different dist/manifest.json. Regenerate it "
                    "(`sbom-vuln.sh sbom`) and scan again; the package findings of this run describe the old build.",
    "R-DATA-UNAVAILABLE": "A boot-chain check could not run: its data source was unreachable and no cached copy exists "
                          "(first run offline, or the host blocks raw.githubusercontent.com / api.github.com). The "
                          "result is unknown, not ok - do not release on this report (`--fail-on` exits 3 while a "
                          "check is not run). Re-run the scan online once; the data is then cached in "
                          ".tools/cache/sbom-vuln and later `--offline` runs use that copy (references/data-sources.md).",
    "R-PROVENANCE": "Rebuild dist/ from the repository's grub/ directory (unset BB_MENU_DIR or point it at the repo) so "
                    "every shipped file has a repo: or deb: origin, then regenerate the SBOM.",
    "R-FALLBACK": "Remove fbx64.efi from the build (ARCHITECTURE section 4).",
    "R-UPDATE": "A fixed Ubuntu package exists: update it on the build host (or `make tools` for .tools/debs), "
                "`make build`, regenerate the SBOM, `make e2e`, re-scan and confirm the finding is closed.",
    "R-VEX-FIXED": "The package changelog shows the fix is already in the shipped version; the scanner flags it only "
                   "because the distribution tracker has not triaged it. Review the proposed `fixed` statement in "
                   "sbom/vex.proposed.openvex.json (it quotes the changelog entry) and copy it into sbom/vex.openvex.json.",
    "R-VEX-NOTPRESENT": "The advisory concerns a userland utility that beast-booter does not ship. Record OpenVEX "
                        "not_affected / component_not_present (proposal provided).",
    "R-GRUB-NOT-EMBEDDED": "The affected GRUB module is not in grubx64.efi (requested modules plus their moddep.lst "
                           "dependencies) and beast-booter ships no x86_64-efi modules, so the UEFI path does not contain "
                           "the code; the BIOS path can load it from /grub/i386-pc. Record not_affected / "
                           "vulnerable_code_not_present for the EFI package (proposal provided) and track the grub2 "
                           "update for grub-pc-bin.",
    "R-GRUB-EMBEDDED": "The affected module is embedded in grubx64.efi. The fix is the Ubuntu grub2 update: take it "
                       "as soon as it is published, `make build`, `make e2e`, re-scan. Dropping the module from "
                       "build/modules-efi.lst is an option only when it is requested directly, no other requested "
                       "module depends on it (moddep.lst) and the menu does not call its commands - the per-finding "
                       "text says which applies. Modules pulled in by `normal` (gettext, net, crypto, extcmd, ...) or "
                       "`chain` (net, efinet) cannot be removed. Record OpenVEX under_investigation (or affected + "
                       "action_statement) meanwhile.",
    "R-NVD-CPE": "NVD record without a version range matched by product name. Verify against GRUB 2.14 and record a "
                 "VEX statement either way.",
    "R-GRUB-TRACK": "No fix and no evidence yet: find the upstream fix commit, check the grub2-unsigned source, track the "
                    "Ubuntu update, rebuild and re-scan; under_investigation meanwhile.",
    "R-SHIM-TRACK": "shim must remain the Microsoft-signed Ubuntu binary: track shim-signed updates, rebuild, run the "
                    "Secure Boot e2e test, re-scan; assess impact and record VEX meanwhile.",
    "R-SB-BYPASS": "A Secure Boot / lockdown bypass reachable through files on the ESP (which any holder of the "
                   "drive can modify). Take the Ubuntu fix as soon as it exists and rebuild; document the gap; consider "
                   "GRUB GPG verification of menu files (grub-mkimage --pubkey, check_signatures=enforce) as hardening; "
                   "record OpenVEX affected + action_statement meanwhile.",
    "R-TRACK": "Track the distribution update, rebuild and re-scan; record a VEX assessment meanwhile.",
    "R-BUILD": "Tooling only (not on the drive): update on the build host or with `make tools`; lower priority.",
    "R-BEASTNET-UPDATE": "A fixed Ubuntu package exists for a beast-net package (kernel, modules or initrd "
                         "userland): regenerate build/beastnet/packages.lock (`python3 -I build/beastnet/lock.py`), "
                         "`make build`, `make e2e` (test_e2e_beastnet), regenerate the SBOM and re-scan.",
    "R-BEASTNET-TRACK": "No fixed Ubuntu package yet for a beast-net package: track the USN, refresh "
                        "build/beastnet/packages.lock when it lands; record an OpenVEX statement (affected + "
                        "action_statement, or not_affected with a justification) meanwhile.",
    "R-RUNTIME-UPDATE": "A library or CPython in the portable packages' python-build-standalone runtime is affected: "
                        "move packaging/portable/runtimes.lock to a release with the fix, rebuild the portable "
                        "packages (`scripts/build_portable.sh --all`), regenerate the SBOM and re-scan.",
    "R-RUNTIME-TRACK": "CPE-only match on a bundled runtime library: check the affected range; track the next "
                       "python-build-standalone release or record OpenVEX not_affected with a justification.",
}


# =========================================================================== main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--offline", action="store_true", help="no network: cached data only (grype DB, data files)")
    ap.add_argument("--refresh", action="store_true", help="refetch cached data files even if fresh")
    ap.add_argument("--max-age-hours", type=float, default=24.0, help="data cache freshness (default 24)")
    ap.add_argument("--no-ubuntu-tracker", action="store_true", help="skip Ubuntu CVE tracker lookups")
    ap.add_argument("--vex", action="append",
                    help="OpenVEX file; repeat for several (default: sbom/vex.openvex.json and every "
                         "sbom/vex.*.openvex.json except vex.proposed.openvex.json)")
    ap.add_argument("--osv-download-db", action="store_true",
                    help="also download OSV's ecosystem databases into .tools/cache/osv-scanner for --offline runs")
    ap.add_argument("--out", help="output directory (default: sbom/)")
    ap.add_argument("--fail-on", choices=["none", "critical", "high"], default="none",
                    help="exit 3 when open shipped/boot-chain findings reach this severity, "
                         "or when a boot-chain check could not run (no data)")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    sbom_dir = root / "sbom"
    cdx_path = sbom_dir / "beast-booter.cdx.json"
    if not cdx_path.exists():
        log("sbom/beast-booter.cdx.json missing - run gen_sbom.py first")
        return 2
    bom, idx = load_sbom(cdx_path)
    dist = root / "dist"
    manifest = json.loads((dist / "manifest.json").read_text())
    meta_props = {p["name"].removeprefix(P): p["value"] for p in bom["metadata"].get("properties", [])}
    distro = meta_props.get("distro", "ubuntu-26.04")
    codename = meta_props.get("build-host-os-codename", "")
    by_purl = {purl_key(c["purl"]): c["ref"] for c in idx.values() if c.get("purl")}
    fetch = Fetcher(root / ".tools/cache/sbom-vuln", a.offline, a.max_age_hours, a.refresh)
    vex_paths = [Path(v).resolve() for v in a.vex] if a.vex else default_vex_files(sbom_dir)
    out_dir = Path(a.out).resolve() if a.out else sbom_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = iso(now_utc())

    with tempfile.TemporaryDirectory(prefix="bb-scan-") as td:
        work = Path(td)
        log("grype ...")
        g = run_grype(root, cdx_path, vex_paths, distro, a.offline, work)
        if not g.get("ok"):
            log(f"grype failed: {g.get('error')}")
        log("osv-scanner ...")
        o1 = run_osv(root, cdx_path, work, "sbom", a.offline, a.osv_download_db)
        src_view, src_map = osv_source_view(idx, work)
        o2 = run_osv(root, src_view, work, "source packages", a.offline, a.osv_download_db)
        for o in (o1, o2):
            if not o.get("ok"):
                log(f"osv-scanner ({o['label']}) failed: {o.get('error')}")
    raw = from_grype(g, idx, by_purl) + from_osv([(o1, {}), (o2, src_map)], idx)
    findings = merge(raw, idx)
    vex_ok, vex_errs, vex_meta = load_vex_files(vex_paths, root)
    apply_vex(findings, vex_ok)

    log("evidence (changelogs, Ubuntu tracker, GRUB modules) ...")
    cl = changelog_index(idx, root)
    modules = grub_modules(root, dist, manifest, idx)
    # The Ubuntu tracker is asked about shipped findings, except beast-net ones below critical: grype's
    # Ubuntu namespace already carries the tracker's state for those, and the kernel alone has thousands.
    def want_tracker(f: dict) -> bool:
        return (f["scope"] == "shipped" and f["id"].startswith("CVE-") and idx[f["component"]["bom-ref"]]["role"] != "portable"
                and (f["severity"] == "critical" or not beastnet_component(idx[f["component"]["bom-ref"]], idx)))
    if not a.no_ubuntu_tracker:          # warm the cache in parallel (ubuntu.com can be slow)
        from concurrent.futures import ThreadPoolExecutor
        ids = sorted({f["id"] for f in findings if want_tracker(f)})
        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(lambda i: ubuntu_status(fetch, i, set(), codename), ids))
    for f in findings:
        c = idx[f["component"]["bom-ref"]]
        f["source_package"] = c["props"].get("source-package")
        f["source"] = "scanner"
        if f["scope"] != "shipped":
            continue
        f["evidence"] = evidence_for(f, idx, cl)
        fam = FAMILY.get(c["props"].get("source-package") or c["name"]) or \
            ("grub2" if c["ref"].startswith("upstream:gnu-grub") else None)
        if fam == "grub2":
            f["grub_modules"] = grub_module_hint(f, f["evidence"], modules)
        cs, why = context_severity(f)
        if cs and SEV_RANK[cs] > SEV_RANK[f["severity"]]:
            f["scanner_severity"], f["severity"], f["severity_context"] = f["severity"], cs, why
        if not a.no_ubuntu_tracker and want_tracker(f):
            srcs = {c["props"].get("source-package") or c["name"]}
            if c["ref"].startswith("upstream:"):
                srcs = {"grub2", "grub2-unsigned", "grub2-signed"} if fam == "grub2" else {"shim", "shim-signed"}
            f["ubuntu"] = ubuntu_status(fetch, f["id"], srcs, codename)

    log("boot-chain checks ...")
    sbom_manifest_sha = next((p["value"] for p in bom["metadata"].get("component", {}).get("properties", [])
                              if p["name"] == P + "manifest-sha256"), None)
    bc = check_boot_chain(root, dist, manifest, fetch, idx,
                          hashlib.sha256((dist / "manifest.json").read_bytes()).hexdigest(), sbom_manifest_sha)
    for f in findings:
        key, txt = remediation(f, idx, codename, bc.get("archive", {}))
        f["remediation_key"], f["remediation"] = key, txt
    bc_findings = []
    for b in bc["findings"]:
        bc_findings.append({"id": b["id"], "aliases": [], "severity": b["severity"], "component": b["component"],
                            "scope": "shipped", "role": "shipped", "sources": [b["source"]], "source": "boot-chain",
                            "fix": {"state": "unknown", "versions": []}, "title": b["title"], "description": b["detail"],
                            "urls": [], "status": "open", "vex": None, "remediation_key": b["remediation"],
                            "remediation": REMEDIATION_TEXT.get(b["remediation"], "")})
    # Boot-chain findings take VEX statements too (e.g. "affected" + the maintainers' action plan).
    apply_vex(bc_findings, vex_ok)
    all_f = bc_findings + findings

    # ---- summary ------------------------------------------------------------------------
    def count(fs):
        out = {s: 0 for s in SEV_ORDER}
        for f in fs:
            out[f["severity"]] += 1
        return out
    open_st = ("open", "affected", "under_investigation")
    summary = {
        "open": {"boot_chain": count([f for f in bc_findings if f["status"] in open_st]),
                 "shipped": count([f for f in findings if f["scope"] == "shipped" and f["status"] in open_st]),
                 "build": count([f for f in findings if f["scope"] == "build" and f["status"] in open_st])},
        "closed": sum(1 for f in findings if f["status"] in ("not_affected", "fixed")),
        "raw": {"grype": len(g.get("matches", [])) + len(g.get("ignored", [])),
                "osv": sum(len(p.get("vulnerabilities", [])) for o in (o1, o2) for p in o.get("packages", []))},
        "merged": len(findings),
        "components_affected": len({f["component"]["bom-ref"] for f in findings}),
    }
    findings.sort(key=lambda f: (f["scope"] != "shipped", -SEV_RANK[f["severity"]], f["id"], f["component"]["name"]))
    proposals = vex_proposals(findings, ts, bom["metadata"]["component"].get("purl") or "beast-booter", modules)
    summary["proposals"] = len(proposals["statements"])
    top = []
    for b in sorted(bc_findings, key=lambda x: -SEV_RANK[x["severity"]]):
        vex = b.get("vex") or {}
        plan = vex.get("action_statement") or vex.get("impact_statement") or vex.get("justification")
        top.append(f"**{b['severity'].upper()} {b['id']}** - {b['title']} -> [{b['remediation_key']}](#{b['remediation_key'].lower()})"
                   + (f". VEX {vex['status']}: {plan}" if vex else ""))
    keys = {}
    for f in findings:
        if f["scope"] == "shipped" and f["status"] in open_st:
            keys.setdefault(f["remediation_key"], []).append(f)
    for k, fs in sorted(keys.items(), key=lambda kv: (-max(SEV_RANK[f["severity"]] for f in kv[1]), kv[0])):
        ids = sorted({f["id"] for f in fs})
        top.append(f"{len(ids)} shipped finding(s) -> [{k}](#{k.lower()}): {', '.join(ids[:8])}{' ...' if len(ids) > 8 else ''}")
    rep = {
        "schema": 1, "generated": ts,
        "sbom": {"path": str(cdx_path.relative_to(root)), "serialNumber": bom.get("serialNumber"),
                 "sha256": hashlib.sha256(cdx_path.read_bytes()).hexdigest(), "version": manifest.get("version"),
                 "build_id": manifest.get("build_id"), "distro": distro},
        "scanners": {"grype": {k: v for k, v in g.items() if k not in ("matches", "ignored")},
                     "osv-scanner": [{k: v for k, v in o.items() if k != "packages"} for o in (o1, o2)]},
        "vex": {"path": vex_meta["files"][0]["path"] if vex_meta.get("files") else None,
                "paths": [f["path"] for f in vex_meta.get("files", [])],
                "meta": vex_meta, "errors": vex_errs,
                "applied": sum(1 for f in all_f if f["vex"])},
        "summary": summary, "top_actions": top,
        "boot_chain": {k: v for k, v in bc.items() if k != "efi"},
        "findings": all_f,
        "remediation_catalogue": {k: REMEDIATION_TEXT.get(k, f"(no catalogue entry for {k}; see the finding)") for k in sorted({f["remediation_key"] for f in all_f
                                                                          if f["status"] in open_st})},
        "data_sources": fetch.used,
    }
    (out_dir / "vulnerabilities.json").write_text(json.dumps(rep, indent=1, default=str) + "\n")
    (out_dir / "vex.proposed.openvex.json").write_text(json.dumps(proposals, indent=2) + "\n")
    write_markdown(out_dir / "VULNERABILITIES.md", rep)
    so, bo = summary["open"]["shipped"], summary["open"]["boot_chain"]
    rel = out_dir.relative_to(root) if out_dir.is_relative_to(root) else out_dir
    log(f"wrote {rel}/vulnerabilities.json, {rel}/VULNERABILITIES.md, {rel}/vex.proposed.openvex.json")
    print("scan: open boot-chain: " + ", ".join(f"{k}={v}" for k, v in bo.items() if v))
    print("scan: open shipped:    " + ", ".join(f"{k}={v}" for k, v in so.items() if v))
    print("scan: open build-time: " + ", ".join(f"{k}={v}" for k, v in summary["open"]["build"].items() if v))
    print(f"scan: closed by VEX: {summary['closed']}; VEX proposals: {summary['proposals']}; VEX problems: {len(vex_errs)}")
    not_run = [f["id"] for f in bc_findings if f["id"].endswith("-NOT-CHECKED")]
    if not_run:
        print(f"scan: boot-chain checks NOT RUN (no data): {', '.join(not_run)} - see R-DATA-UNAVAILABLE")
    worst = max([SEV_RANK[f["severity"]] for f in all_f if f["scope"] == "shipped" and f["status"] in open_st] or [0])
    if a.fail_on != "none" and (worst >= SEV_RANK[a.fail_on] or not_run):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
