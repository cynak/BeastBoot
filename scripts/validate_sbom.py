#!/usr/bin/env python3
"""Validate and cross-check the SBOM produced by gen_sbom.py.

    python3 -I scripts/validate_sbom.py [--root DIR]

Checks (each one PASS/FAIL, written to sbom/validation.json):
  cdx-schema        CycloneDX output validates against the official 1.6 JSON schema
                    (pinned copy in .tools/cache/schemas, see install-tools.sh)
  spdx-schema       SPDX output validates against the official 2.3 JSON schema
  spdx-structure    unique SPDXIDs, every relationship end exists, DESCRIBES present,
                    every LicenseRef declared, every file has SHA1 + SHA256
  cdx-structure     unique bom-refs, every dependency ref exists, every dist/ file once
  origin-verified   every file copied from a package (origin deb:...) carries
                    beast-booter:origin-verified and it is a match, not MISMATCH (the shipped
                    bytes equal the package's file: dpkg md5sums or the .deb contents);
                    repo:/key: files that differ from the working tree are listed as warnings
  formats-agree     CycloneDX and SPDX list the same files (SHA-256) and purls
  syft-roundtrip    syft converts both documents (cdx->spdx, spdx->cdx) without error
                    and keeps every purl
  syft-dist         `syft scan dir:dist`: every file syft sees is in the SBOM with the
                    same SHA-256, and every package syft identifies (the beast-net kernel)
                    is a component with the same purl, linked to that file
  syft-purls        syft's own purls for the same Debian packages (fake dpkg db for
                    host packages, deb-archive cataloger for .tools/debs and the
                    beast-net .deb cache) equal ours
  beastnet-coverage (when dist/ has esp/beast-net) every beast-net file is a component,
                    initrd.img is linked to every package its manifest origin names (all
                    shipped), vmlinuz contains a pkg:generic/linux-kernel component that is
                    linked to the Ubuntu linux source package
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def load_validator(schema_dir: Path, main: str):
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    resources = []
    for f in schema_dir.glob("*.json"):
        doc = json.loads(f.read_text())
        res = Resource.from_contents(doc, default_specification=DRAFT7)
        if "$id" in doc:
            resources.append((doc["$id"], res))
        # CycloneDX refs siblings by bare file name relative to its $id
        resources.append((f"http://cyclonedx.org/schema/{f.name}", res))
    registry = Registry().with_resources(resources)
    schema = json.loads((schema_dir / main).read_text())
    cls = jsonschema.validators.validator_for(schema)
    return cls(schema, registry=registry, format_checker=cls.FORMAT_CHECKER)


def schema_errors(validator, doc) -> list[str]:
    errs = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:300]}" for e in errs]


def walk_components(comps):
    for c in comps or []:
        yield c
        yield from walk_components(c.get("components"))


def norm_purl(p: str) -> str:
    """purl without the distro qualifier and with sorted qualifiers (syft's deb-archive
    cataloger cannot know the distro of a loose .deb)."""
    base, _, q = p.partition("?")
    base = base.replace("pkg:deb/ubuntu/", "pkg:deb/")
    qs = sorted(x for x in q.split("&") if x and not x.startswith("distro=") and not x.startswith("package-id="))
    return base + ("?" + "&".join(qs) if qs else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    a = ap.parse_args()
    root = Path(a.root).resolve()
    sbom_dir = root / "sbom"
    bindir = root / ".tools" / "bin"
    schemas = root / ".tools" / "cache" / "schemas"
    cdx_path, spdx_path = sbom_dir / "beast-booter.cdx.json", sbom_dir / "beast-booter.spdx.json"
    cdx, spdx = json.loads(cdx_path.read_text()), json.loads(spdx_path.read_text())
    manifest = json.loads((root / "dist" / "manifest.json").read_text())
    results: dict[str, dict] = {}

    def record(name, ok, detail):
        results[name] = {"result": "PASS" if ok else "FAIL", "detail": detail}

    # ---- schemas ---------------------------------------------------------------------
    if not (schemas / "cyclonedx-1.6" / "bom-1.6.schema.json").is_file():
        print("validate: schemas missing - run scripts/install-tools.sh", file=sys.stderr)
        return 2
    errs = schema_errors(load_validator(schemas / "cyclonedx-1.6", "bom-1.6.schema.json"), cdx)
    record("cdx-schema", not errs, {"schema": "CycloneDX bom-1.6.schema.json (tag 1.6.2)",
                                    "errors": len(errs), "first": errs[:20]})
    errs = schema_errors(load_validator(schemas / "spdx-2.3", "spdx-schema.json"), spdx)
    record("spdx-schema", not errs, {"schema": "SPDX 2.3 spdx-schema.json (tag v2.3)",
                                     "errors": len(errs), "first": errs[:20]})

    # ---- SPDX structure --------------------------------------------------------------
    problems = []
    ids = [p["SPDXID"] for p in spdx.get("packages", [])] + [f["SPDXID"] for f in spdx.get("files", [])]
    if len(ids) != len(set(ids)):
        problems.append("duplicate SPDXIDs")
    known = set(ids) | {"SPDXRef-DOCUMENT"}
    for r in spdx.get("relationships", []):
        for k in ("spdxElementId", "relatedSpdxElement"):
            if r[k] not in known and r[k] not in ("NONE", "NOASSERTION"):
                problems.append(f"relationship refers to unknown {r[k]}")
    if not any(r["relationshipType"] == "DESCRIBES" and r["spdxElementId"] == "SPDXRef-DOCUMENT"
               for r in spdx.get("relationships", [])):
        problems.append("no DOCUMENT DESCRIBES relationship")
    declared = {x["licenseId"] for x in spdx.get("hasExtractedLicensingInfos", [])}
    for p in spdx.get("packages", []):
        for ref in re.findall(r"LicenseRef-[A-Za-z0-9.-]+", p.get("licenseDeclared", "")):
            if ref not in declared:
                problems.append(f"{p['SPDXID']}: {ref} not in hasExtractedLicensingInfos")
        if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", p["SPDXID"]):
            problems.append(f"bad SPDXID {p['SPDXID']}")
    for f in spdx.get("files", []):
        algos = {c["algorithm"] for c in f.get("checksums", [])}
        if not {"SHA1", "SHA256"} <= algos:
            problems.append(f"{f['fileName']}: checksums {sorted(algos)}")
    if "#" in spdx.get("documentNamespace", "#"):
        problems.append("documentNamespace must be a URI without '#'")
    record("spdx-structure", not problems, {"problems": problems[:30], "packages": len(spdx.get("packages", [])),
                                            "files": len(spdx.get("files", [])),
                                            "relationships": len(spdx.get("relationships", []))})

    # ---- CycloneDX structure ---------------------------------------------------------
    problems = []
    comps = list(walk_components(cdx.get("components")))
    refs = [c["bom-ref"] for c in comps] + [cdx["metadata"]["component"]["bom-ref"]]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-refs")
    refset = set(refs)
    for d in cdx.get("dependencies", []):
        for r in [d["ref"]] + d.get("dependsOn", []):
            if r not in refset:
                problems.append(f"dependency refers to unknown {r}")
    for wf in cdx.get("formulation", [{}])[0].get("workflows", []):
        for rr in wf.get("resourceReferences", []):
            if rr.get("ref") not in refset:
                problems.append(f"workflow {wf['uid']} refers to unknown {rr.get('ref')}")
    file_comps = {c["name"]: c for c in comps if c["type"] == "file"}
    listed = {k for k, v in manifest["files"].items() if not v["origin"].startswith("built:sbom")}
    if sorted(file_comps) != sorted(listed):
        problems.append("file components differ from dist/manifest.json files")
    for name, c in file_comps.items():
        h = {x["alg"]: x["content"] for x in c.get("hashes", [])}
        if h.get("SHA-256") != manifest["files"].get(name, {}).get("sha256"):
            problems.append(f"{name}: SHA-256 differs from manifest")
    record("cdx-structure", not problems, {"problems": problems[:30], "components": len(comps),
                                           "files": len(file_comps)})

    # ---- per-file provenance ---------------------------------------------------------
    mismatch, unverified, warnings = [], [], []
    for name, c in sorted(file_comps.items()):
        pr = {p["name"]: p["value"] for p in c.get("properties", [])}
        origin = manifest["files"].get(name, {}).get("origin", "")
        v = pr.get("beast-booter:origin-verified")
        if origin.startswith("deb:"):
            if v is None:
                unverified.append(name)
            elif not v.startswith(("md5 matches", "sha256 matches")):
                mismatch.append(f"{name}: {v}")
        elif v is not None and not v.startswith("sha256 matches"):
            warnings.append(f"{name}: {v}")
    n_pkg = sum(1 for n in file_comps if manifest["files"].get(n, {}).get("origin", "").startswith("deb:"))
    record("origin-verified", not mismatch and not unverified,
           {"package_files": n_pkg, "mismatch": mismatch[:30], "mismatch_count": len(mismatch),
            "no_verification_property": unverified[:30], "repo_warnings": warnings[:30]})

    # ---- beast-net coverage ----------------------------------------------------------
    bn = {k: v for k, v in manifest["files"].items() if k.startswith("esp/beast-net/")}
    if bn:
        problems, linked_pkgs = [], []
        by_ref = {c["bom-ref"]: c for c in comps}
        deps_all = {d["ref"]: set(d.get("dependsOn", [])) for d in cdx.get("dependencies", [])}
        problems += [f"{k}: no file component" for k in sorted(bn) if k not in file_comps]
        init = bn.get("esp/beast-net/initrd.img")
        if init and "esp/beast-net/initrd.img" in file_comps:
            fref = file_comps["esp/beast-net/initrd.img"]["bom-ref"]
            for name, ver in re.findall(r"deb:([a-z0-9][a-z0-9+.-]*)=([0-9][0-9A-Za-z.+~:-]*?)(?=[\s,;)\]]|$)",
                                        init["origin"]):
                ref = f"deb:{name}@{ver}"
                c = by_ref.get(ref)
                if c is None or c.get("scope") != "required":
                    problems.append(f"initrd.img package {ref}: not a shipped component")
                elif ref not in deps_all.get(fref, set()):
                    problems.append(f"initrd.img is not linked to {ref}")
                else:
                    linked_pkgs.append(ref)
        vml = file_comps.get("esp/beast-net/vmlinuz")
        kernels = sorted(r for r in deps_all.get(vml["bom-ref"], set()) if r.startswith("kernel:")) if vml else []
        if vml and not kernels:
            problems.append("esp/beast-net/vmlinuz has no linux-kernel component")
        for k in kernels:
            kc = by_ref.get(k, {})
            if not any(r.startswith(("deb-src:linux", "deb:linux")) for r in deps_all.get(k, set())):
                problems.append(f"{k} is not linked to the Ubuntu linux source package (vulnerability tracking)")
            if not kc.get("purl", "").startswith("pkg:generic/linux-kernel@"):
                problems.append(f"{k}: unexpected purl {kc.get('purl')}")
        record("beastnet-coverage", not problems, {"files": sorted(bn), "initrd_packages": len(linked_pkgs),
                                                   "kernels": kernels, "problems": problems[:30]})

    # ---- formats agree ---------------------------------------------------------------
    cdx_files = {n: {x["alg"]: x["content"] for x in c["hashes"]}["SHA-256"] for n, c in file_comps.items()}
    spdx_files = {f["fileName"].removeprefix("./"): {c["algorithm"]: c["checksumValue"] for c in f["checksums"]}["SHA256"]
                  for f in spdx.get("files", [])}
    cdx_purls = sorted(c["purl"] for c in comps + [cdx["metadata"]["component"]] if c.get("purl"))
    spdx_purls = sorted(r["referenceLocator"] for p in spdx.get("packages", []) for r in p.get("externalRefs", [])
                        if r["referenceType"] == "purl")
    record("formats-agree", cdx_files == spdx_files and cdx_purls == spdx_purls,
           {"files": len(cdx_files), "purls": len(cdx_purls),
            "file_diff": sorted(set(cdx_files.items()) ^ set(spdx_files.items()))[:10],
            "purl_diff": sorted(set(cdx_purls) ^ set(spdx_purls))[:10]})

    syft = bindir / "syft"
    if not syft.exists():
        for k in ("syft-roundtrip", "syft-dist", "syft-purls"):
            record(k, False, {"error": "syft not installed (run scripts/install-tools.sh)"})
    else:
        env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
        # ---- syft round trip ---------------------------------------------------------
        detail = {}
        ok = True
        for src, fmt, key in ((cdx_path, "spdx-json", "cdx->spdx"), (spdx_path, "cyclonedx-json", "spdx->cdx")):
            r = run([str(syft), "convert", str(src), "-o", fmt, "-q"], env=env)
            if r.returncode != 0:
                ok = False
                detail[key] = {"error": r.stderr.strip()[-500:]}
                continue
            out = json.loads(r.stdout)
            if fmt == "spdx-json":
                got = {x["referenceLocator"] for p in out.get("packages", []) for x in p.get("externalRefs", [])
                       if x.get("referenceType") == "purl"}
            else:
                got = {c["purl"] for c in walk_components(out.get("components")) if c.get("purl")}
            lost = sorted(set(cdx_purls) - got - {cdx["metadata"]["component"].get("purl")})
            ok &= not lost
            detail[key] = {"purls_in": len(cdx_purls), "purls_out": len(got), "lost": lost[:10]}
        record("syft-roundtrip", ok, detail)

        # ---- syft dir:dist -----------------------------------------------------------
        r = run([str(syft), "scan", f"dir:{root / 'dist'}", "-o", "json", "-q"],
                env=dict(env, SYFT_FILE_METADATA_SELECTION="all", SYFT_FILE_METADATA_DIGESTS="sha256"))
        if r.returncode != 0:
            record("syft-dist", False, {"error": r.stderr.strip()[-500:]})
        else:
            sj = json.loads(r.stdout)
            seen = {}
            for f in sj.get("files", []):
                if f.get("metadata", {}).get("type") != "RegularFile":
                    continue
                path = f["location"]["path"].lstrip("/")
                dg = {d["algorithm"]: d["value"] for d in f.get("digests") or []}
                seen[path] = dg.get("sha256")
            seen.pop("manifest.json", None)
            for k, v in manifest["files"].items():
                if v["origin"].startswith("built:sbom"):
                    seen.pop(k, None)
            missed = sorted(p for p in seen if p not in cdx_files)
            mismatch = sorted(p for p in seen if p in cdx_files and seen[p] != cdx_files[p])
            not_seen = sorted(p for p in cdx_files if p not in seen)
            pkgs = [{"name": x["name"], "version": x["version"], "type": x["type"], "purl": x.get("purl"),
                     "locations": sorted({loc.get("path", "").lstrip("/") for loc in x.get("locations") or []})}
                    for x in sj.get("artifacts", [])]
            # A package syft identifies (e.g. pkg:generic/linux-kernel@<release> from vmlinuz's bzImage
            # header) must be a component with the same purl, nested under the package of the file syft
            # found it in (or reachable from that file through a CONTAINS dependency).
            by_purl = {c["purl"]: c for c in comps if c.get("purl")}
            parent_of = {ch["bom-ref"]: c["bom-ref"] for c in comps for ch in c.get("components") or []}
            dep_of = {d["ref"]: set(d.get("dependsOn", [])) for d in cdx.get("dependencies", [])}
            file_ref = {c["name"]: c["bom-ref"] for c in file_comps.values()}
            reconciled, pk_missed = [], []
            for p in pkgs:
                c = by_purl.get(p["purl"])
                if c is None:
                    pk_missed.append(p)
                    continue
                files = [file_ref[f] for f in p["locations"] if f in file_ref]
                linked = [f for f in files if c["bom-ref"] in dep_of.get(f, set())
                          or parent_of.get(c["bom-ref"]) == parent_of.get(f)]
                if files and not linked:
                    pk_missed.append(dict(p, problem=f"{c['bom-ref']} is not linked to {', '.join(files)}"))
                    continue
                reconciled.append({"syft": p["purl"], "sbom": c["bom-ref"], "files": files,
                                   "package": parent_of.get(c["bom-ref"])})
            unknowns = sorted({u for f in sj.get("files", []) for u in f.get("unknowns", []) or []})
            record("syft-dist", not missed and not mismatch and not not_seen and not pk_missed, {
                "syft_files": len(seen), "sbom_files": len(cdx_files), "files_missing_from_sbom": missed,
                "sha256_mismatch": mismatch, "sbom_files_syft_did_not_see": not_seen[:10],
                "syft_packages": pkgs, "packages_missing_from_sbom": pk_missed,
                "packages_reconciled": reconciled, "syft_unknowns": unknowns,
                "reconciliation": ("syft has no package metadata to read in dist/ (the PE files are reported as "
                                   "'no package identified'); the only packages it identifies come from binary "
                                   "headers (the beast-net kernel). Each must be an SBOM component with the same "
                                   "purl, linked to the file syft found it in. Package attribution otherwise comes "
                                   "from manifest.json origins, verified per file against dpkg md5sums or the .deb "
                                   "contents (property beast-booter:origin-verified).")})

        # ---- syft purls for the same packages -----------------------------------------
        deb_comps = [c for c in comps if c.get("purl", "").startswith("pkg:deb/") and "arch=source" not in c["purl"]]
        host, loose = [], []
        for c in deb_comps:
            pr = {p["name"]: p["value"] for p in c.get("properties", [])}
            (host if pr.get("beast-booter:package-origin") == "host dpkg database" else loose).append(c)
        mism = []
        with tempfile.TemporaryDirectory(prefix="bb-syft-") as td:
            t = Path(td)
            (t / "etc").mkdir()
            (t / "var/lib/dpkg").mkdir(parents=True)
            (t / "etc/os-release").write_text(Path("/etc/os-release").read_text())
            names = {c["name"] for c in host}
            stanzas = [s for s in Path("/var/lib/dpkg/status").read_text().split("\n\n")
                       if (m := re.search(r"^Package: (\S+)", s, re.M)) and m.group(1) in names]
            (t / "var/lib/dpkg/status").write_text("\n\n".join(x.strip() for x in stanzas) + "\n")
            r = run([str(syft), "scan", f"dir:{t}", "-o", "json", "-q"], env=env)
            syft_host = {x["name"]: x["purl"] for x in json.loads(r.stdout).get("artifacts", [])} if r.returncode == 0 else {}
        for c in host:
            if syft_host.get(c["name"]) != c["purl"]:
                mism.append({"ours": c["purl"], "syft": syft_host.get(c["name"])})
        # .deb archives: .tools/debs and the beast-net cache (property beast-booter:package-origin
        # "<dir>/<file>.deb sha256:..."); each directory is scanned once.
        deb_dirs = {root / ".tools" / "debs"}
        for c in loose:
            pr = {p["name"]: p["value"] for p in c.get("properties", [])}
            path = pr.get("beast-booter:package-origin", "").split(" sha256:")[0]
            if path.endswith(".deb"):
                deb_dirs.add((root / path).parent)
        syft_loose = {}
        for debs in sorted(d for d in deb_dirs if d.is_dir()):
            r = run([str(syft), "scan", f"dir:{debs}", "-o", "json", "-q", "--select-catalogers", "deb"], env=env)
            if r.returncode == 0:
                syft_loose.update({x["name"]: x["purl"] for x in json.loads(r.stdout).get("artifacts", [])})
        # syft's deb-archive cataloger skips very large archives (linux-modules, ~170 MB): give those
        # to its dpkg-db cataloger instead, as a status stanza made from the .deb's control fields.
        missing = [c for c in loose if c["name"] not in syft_loose]
        if missing:
            with tempfile.TemporaryDirectory(prefix="bb-syft-") as td:
                t = Path(td)
                (t / "etc").mkdir()
                (t / "var/lib/dpkg").mkdir(parents=True)
                (t / "etc/os-release").write_text(Path("/etc/os-release").read_text())
                stanzas = []
                for c in missing:
                    pr = {p["name"]: p["value"] for p in c.get("properties", [])}
                    path = root / pr.get("beast-booter:package-origin", "").split(" sha256:")[0]
                    if path.suffix == ".deb" and path.is_file():
                        r = run(["dpkg-deb", "-f", str(path)])
                        if r.returncode == 0:
                            ctl = r.stdout.strip().splitlines()
                            stanzas.append("\n".join(ctl[:1] + ["Status: install ok installed"] + ctl[1:]))
                (t / "var/lib/dpkg/status").write_text("\n\n".join(stanzas) + "\n")
                r = run([str(syft), "scan", f"dir:{t}", "-o", "json", "-q"], env=env)
                if r.returncode == 0:
                    syft_loose.update({x["name"]: x["purl"] for x in json.loads(r.stdout).get("artifacts", [])})
        for c in loose:
            s = syft_loose.get(c["name"])
            if s is None or norm_purl(s) != norm_purl(c["purl"]):
                mism.append({"ours": c["purl"], "syft": s})
        record("syft-purls", not mism, {"host_packages": len(host), "deb_archives": len(loose),
                                        "deb_dirs": sorted(str(d.relative_to(root)) if d.is_relative_to(root) else str(d)
                                                           for d in deb_dirs),
                                        "mismatches": mism[:20]})

    out = {"sbom": {"cyclonedx": str(cdx_path.relative_to(root)), "spdx": str(spdx_path.relative_to(root)),
                    "serialNumber": cdx.get("serialNumber")},
           "checks": results}
    (sbom_dir / "validation.json").write_text(json.dumps(out, indent=2) + "\n")
    bad = [k for k, v in results.items() if v["result"] != "PASS"]
    for k, v in results.items():
        print(f"validate: {v['result']}  {k}")
    for w in results.get("origin-verified", {}).get("detail", {}).get("repo_warnings", []):
        print(f"validate: warning: {w}", file=sys.stderr)
    if bad:
        for k in bad:
            print(f"validate: {k}: {json.dumps(results[k]['detail'])[:1500]}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
