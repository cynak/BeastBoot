"""Debian/Ubuntu package metadata for the SBOM (python3 stdlib + dpkg tools).

Packages come from the host dpkg database (`dpkg-query`) or, for packages that
scripts/bootstrap-tools.sh unpacked rootless into .tools/root, from the .deb
files in .tools/debs (`dpkg-deb`). Licenses come from DEP-5 copyright files;
anything that is not machine-readable is NOASSERTION, never a guess.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

FIELDS = ["Package", "Version", "Architecture", "source:Package", "source:Version",
          "Maintainer", "Homepage", "Built-Using", "db:Status-Abbrev"]


@dataclass
class DebPkg:
    name: str
    version: str
    arch: str
    source: str
    source_version: str
    maintainer: str = ""
    homepage: str = ""
    built_using: list[tuple[str, str]] = field(default_factory=list)
    origin: str = "dpkg"            # "dpkg" (host) or "deb:<path>" (.tools/debs)
    deb_path: Path | None = None

    @property
    def upstream_version(self) -> str:
        return upstream_version(self.source_version or self.version)


def upstream_version(v: str) -> str:
    v = v.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v


def parse_built_using(s: str) -> list[tuple[str, str]]:
    out = []
    for part in s.split(","):
        m = re.match(r"\s*([a-z0-9][a-z0-9+.-]*)\s*\(\s*=\s*([^)\s]+)\s*\)", part)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def dpkg_query(name: str) -> DebPkg | None:
    fmt = "\\t".join("${%s}" % f for f in FIELDS) + "\\n"
    r = subprocess.run(["dpkg-query", "-W", "-f", fmt, name], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        f = line.split("\t")
        if len(f) != len(FIELDS) or not f[8].startswith("ii"):
            continue
        return DebPkg(name=f[0], version=f[1], arch=f[2], source=f[3] or f[0],
                      source_version=f[4] or f[1], maintainer=f[5], homepage=f[6],
                      built_using=parse_built_using(f[7]))
    return None


def deb_fields(deb: Path) -> DebPkg:
    r = subprocess.run(["dpkg-deb", "-f", str(deb)], check=True, capture_output=True, text=True)
    fields: dict[str, str] = {}
    key = None
    for line in r.stdout.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            fields[key.strip()] = val.strip()
    src = fields.get("Source", fields["Package"])
    m = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", src)
    return DebPkg(name=fields["Package"], version=fields["Version"],
                  arch=fields.get("Architecture", ""), source=m.group(1),
                  source_version=m.group(2) or fields["Version"],
                  maintainer=fields.get("Maintainer", ""), homepage=fields.get("Homepage", ""),
                  built_using=parse_built_using(fields.get("Built-Using", "")),
                  origin=f"deb:{deb.name}", deb_path=deb)


def find_deb(debs_dir: Path, name: str, version: str | None = None) -> Path | None:
    if not debs_dir.is_dir():
        return None
    for p in sorted(debs_dir.glob(f"{name}_*.deb")):
        if version is None:
            return p
        try:
            if deb_fields(p).version == version:
                return p
        except subprocess.CalledProcessError:
            continue
    return None


def resolve_pkg(name: str, version: str | None, debs_dir: Path) -> DebPkg | None:
    """Host dpkg first (when the version matches), then .tools/debs."""
    p = dpkg_query(name)
    if p and (version is None or p.version == version):
        return p
    deb = find_deb(debs_dir, name, version)
    if deb:
        return deb_fields(deb)
    return p if version is None else None


def beastnet_cache(root: Path) -> Path:
    """The beast-net .deb cache (build/beastnet/build.sh: BB_BEASTNET_CACHE)."""
    return Path(os.environ.get("BB_BEASTNET_CACHE") or root / ".tools" / "cache" / "beastnet") / "debs"


def beastnet_lock(root: Path) -> dict[str, tuple[str, str]]:
    """build/beastnet/packages.lock -> {package: (version, sha256 of the .deb)}."""
    out: dict[str, tuple[str, str]] = {}
    lock = root / "build" / "beastnet" / "packages.lock"
    if lock.is_file():
        for line in lock.read_text().splitlines():
            f = line.split()
            if len(f) >= 4 and not line.startswith("#"):
                out[f[0]] = (f[1], f[3])
    return out


class Resolver:
    """Finds the package a file came from, in this order:
    1. beast-net packages (build/beastnet/packages.lock): the locked .deb in the beast-net
       cache whose SHA-256 matches the lock - exactly what build/beastnet/build.sh unpacked,
       so the SBOM is the same on any build host;
    2. the host dpkg database (same version);
    3. .tools/debs, then the beast-net cache (any .deb of that version)."""

    def __init__(self, root: Path):
        self.root = root
        self.debs_dirs = [root / ".tools" / "debs", beastnet_cache(root)]
        self.lock = beastnet_lock(root)
        self.cache: dict[tuple[str, str | None], DebPkg | None] = {}

    def _locked(self, name: str, version: str | None) -> DebPkg | None:
        import hashlib
        lv = self.lock.get(name)
        if not lv or (version is not None and version != lv[0]):
            return None
        d = find_deb(self.debs_dirs[1], name, lv[0])
        if d is None:
            return None
        h = hashlib.sha256()
        with open(d, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return deb_fields(d) if h.hexdigest() == lv[1] else None

    def __call__(self, name: str, version: str | None) -> DebPkg | None:
        key = (name, version)
        if key not in self.cache:
            p = self._locked(name, version) or resolve_pkg(name, version, self.debs_dirs[0])
            if p is None or (version is not None and p.version != version):
                d = find_deb(self.debs_dirs[1], name, version)
                p = deb_fields(d) if d else p
            self.cache[key] = p
        return self.cache[key]

    def origin_text(self, p: DebPkg) -> str:
        """Where the package metadata came from, for the SBOM (paths relative to the repo)."""
        if p.origin == "dpkg" or p.deb_path is None:
            return "host dpkg database"
        import hashlib
        path = p.deb_path.resolve()
        shown = path.relative_to(self.root).as_posix() if path.is_relative_to(self.root) else str(path)
        return f"{shown} sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def compare_versions(a: str, op: str, b: str) -> bool:
    return subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0


def purl(pkg: DebPkg, distro: str, namespace: str = "ubuntu") -> str:
    """Same shape syft emits: qualifiers sorted, upstream=<src>[@<srcver>] when it differs."""
    q = {"arch": pkg.arch, "distro": distro}
    if pkg.source != pkg.name or pkg.source_version != pkg.version:
        up = pkg.source if pkg.source_version == pkg.version else f"{pkg.source}@{pkg.source_version}"
        q["upstream"] = up
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in sorted(q.items()) if v)
    return f"pkg:deb/{namespace}/{quote(pkg.name, safe='')}@{quote(pkg.version, safe='')}?{qs}"


def source_purl(name: str, version: str, distro: str, namespace: str = "ubuntu") -> str:
    return (f"pkg:deb/{namespace}/{quote(name, safe='')}@{quote(version, safe='')}"
            f"?arch=source&distro={quote(distro, safe='')}")


# --------------------------------------------------------------------------- files in packages


def deb_member_hashes(deb: Path) -> dict[str, str]:
    """{'/usr/lib/...': sha256} for every regular file in a .deb."""
    import hashlib
    r = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True, capture_output=True)
    out = {}
    with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tf:
        for m in tf:
            if m.isfile():
                f = tf.extractfile(m)
                out["/" + m.name.lstrip("./")] = hashlib.sha256(f.read()).hexdigest()
    return out


def deb_member_bytes(deb: Path, member: str) -> bytes | None:
    r = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True, capture_output=True)
    want = member.lstrip("/")
    with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tf:
        for m in tf:
            if m.name.lstrip("./") == want and m.isfile():
                return tf.extractfile(m).read()
    return None


def verify_member(path: Path, pkg: DebPkg, member: str, cache: dict) -> str:
    """Is `path` (a file in dist/) byte-identical to `member` (e.g. /usr/lib/grub/i386-pc/normal.mod)
    of package `pkg`?  Host packages are checked against the package's own dpkg md5sums list (so a
    modified host file is caught too), .tools/debs packages against the .deb contents (SHA-256).
    Returns a description; it starts with "MISMATCH" when the bytes differ or the package has no
    such file. `cache` is a dict reused across calls (md5sums lists / .deb member hashes)."""
    import hashlib
    data = path.read_bytes()
    if pkg.origin == "dpkg":
        key = ("md5sums", pkg.name, pkg.arch)
        if key not in cache:
            cache[key] = dpkg_md5sums(pkg.name, pkg.arch)
        want = cache[key].get(member)
        if want is None:
            return f"MISMATCH: {member} is not listed in the dpkg md5sums of {pkg.name} {pkg.version}"
        got = hashlib.md5(data).hexdigest()
        return (f"md5 matches /var/lib/dpkg/info/{pkg.name} md5sums" if got == want else
                f"MISMATCH: md5 {got} vs dpkg md5sums {want} ({pkg.name} {pkg.version}:{member})")
    key = ("deb", str(pkg.deb_path))
    if key not in cache:
        cache[key] = deb_member_hashes(pkg.deb_path)
    want = cache[key].get(member)
    if want is None:
        return f"MISMATCH: {member} is not in {pkg.deb_path.name}"
    got = hashlib.sha256(data).hexdigest()
    return (f"sha256 matches {pkg.deb_path.name}:{member}" if got == want else
            f"MISMATCH: not identical to {pkg.deb_path.name}:{member}")


def dpkg_md5sums(name: str, arch: str) -> dict[str, str]:
    for cand in (f"/var/lib/dpkg/info/{name}:{arch}.md5sums", f"/var/lib/dpkg/info/{name}.md5sums"):
        if os.path.exists(cand):
            out = {}
            for line in Path(cand).read_text(errors="replace").splitlines():
                md5, _, path = line.partition("  ")
                out["/" + path.strip()] = md5
            return out
    return {}


# --------------------------------------------------------------------------- doc files


def doc_file(pkg: DebPkg, fname: str, tools_root: Path) -> tuple[bytes | None, str]:
    """Read /usr/share/doc/<pkg>/<fname>, following a doc-dir symlink to a sibling
    package of the same source. Returns (content, description of where it came from)."""
    if pkg.origin == "dpkg":
        base = Path("/usr/share/doc")
    else:
        base = tools_root / "usr/share/doc"
    d = base / pkg.name
    note = ""
    if d.is_symlink():
        target = os.readlink(d)
        note = f" (doc dir is a symlink to {target})"
        d = base / target
        if not d.exists() and pkg.origin != "dpkg":
            # sibling package installed on the host - only if built from the same source version
            sib = dpkg_query(os.path.basename(target))
            if sib and sib.source == pkg.source and sib.source_version == pkg.source_version:
                d = Path("/usr/share/doc") / target
                note += f", read from host {sib.name} {sib.version} (same source {sib.source} {sib.source_version})"
    for cand in (fname, fname + ".gz"):
        p = d / cand
        if p.is_file():
            raw = p.read_bytes()
            return (gzip.decompress(raw) if cand.endswith(".gz") else raw), f"{p}{note}"
    if pkg.deb_path:
        for cand in (fname, fname + ".gz"):
            raw = deb_member_bytes(pkg.deb_path, f"/usr/share/doc/{pkg.name}/{cand}")
            if raw is not None:
                return (gzip.decompress(raw) if cand.endswith(".gz") else raw), f"{pkg.deb_path.name}:/usr/share/doc/{pkg.name}/{cand}"
    return None, f"no {fname} for {pkg.name}{note}"


def changelog(pkg: DebPkg, tools_root: Path) -> tuple[str | None, str]:
    for name in ("changelog.Debian", "changelog"):
        raw, where = doc_file(pkg, name, tools_root)
        if raw is not None:
            return raw.decode("utf-8", "replace"), where
    return None, f"no changelog for {pkg.name}"


ENTRY_RE = re.compile(r"^(\S+) \(([^)]+)\) [^;]*; urgency=", re.M)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def changelog_cves(text: str) -> dict[str, list[dict]]:
    """{CVE: [{'version', 'source', 'context'}]} - where a changelog mentions a CVE."""
    out: dict[str, list[dict]] = {}
    heads = list(ENTRY_RE.finditer(text))
    for i, h in enumerate(heads):
        body = text[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        bullet = ""
        for line in body.splitlines():
            s = line.strip()
            if s.startswith("*"):
                bullet = s.lstrip("* ").strip()
            for cve in CVE_RE.findall(line):
                ctx = bullet if bullet and cve not in bullet else s.lstrip("*- ").strip()
                out.setdefault(cve, []).append({"version": h.group(2), "source": h.group(1),
                                                "context": ctx[:200], "line": s[:200]})
    return out


# --------------------------------------------------------------------------- licenses (DEP-5)

# DEP-5 short names that map 1:1 to an SPDX id (copyright-format/1.0 "License
# specification" table). Anything else that is not literally an SPDX id becomes a
# LicenseRef-, so nothing is guessed.
DEP5_TO_SPDX = {
    "GPL-1+": "GPL-1.0-or-later", "GPL-2+": "GPL-2.0-or-later", "GPL-3+": "GPL-3.0-or-later",
    "GPL-1": "GPL-1.0-only", "GPL-2": "GPL-2.0-only", "GPL-3": "GPL-3.0-only",
    "LGPL-2+": "LGPL-2.0-or-later", "LGPL-2.1+": "LGPL-2.1-or-later", "LGPL-3+": "LGPL-3.0-or-later",
    "LGPL-2": "LGPL-2.0-only", "LGPL-2.1": "LGPL-2.1-only", "LGPL-3": "LGPL-3.0-only",
    "AGPL-3+": "AGPL-3.0-or-later", "AGPL-3": "AGPL-3.0-only",
    "GFDL-1.2+": "GFDL-1.2-or-later", "GFDL-1.3+": "GFDL-1.3-or-later",
    "Expat": "MIT", "CC0": "CC0-1.0", "Zlib": "Zlib", "ISC": "ISC",
    "BSD-2-clause": "BSD-2-Clause", "BSD-3-clause": "BSD-3-Clause", "BSD-4-clause": "BSD-4-Clause",
    "Apache-2.0": "Apache-2.0", "MPL-2.0": "MPL-2.0", "PSF-2": "PSF-2.0",
}


def load_spdx_ids(schema: Path) -> dict[str, str]:
    """lower-case id -> canonical SPDX license id, from CycloneDX's spdx.schema.json."""
    try:
        ids = json.loads(schema.read_text())["enum"]
    except (OSError, ValueError, KeyError):
        ids = sorted(set(DEP5_TO_SPDX.values()))
    return {i.lower(): i for i in ids}


def license_ref(name: str) -> str:
    return "LicenseRef-DEP5-" + re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-")


def dep5_to_spdx(expr: str, spdx_ids: dict[str, str], refs: dict[str, str]) -> str:
    """One DEP-5 License: short line -> SPDX expression. Unknown names -> LicenseRef."""
    expr = expr.strip()
    if re.search(r"\bwith\b", expr, re.I):            # "GPL-3+ with OpenSSL exception"
        ref = license_ref(expr)
        refs[ref] = expr
        return ref
    parts = re.split(r"\s+(or|and)\s+|\s*,\s*(?:or|and)\s+", expr, flags=re.I)
    out = []
    for p in parts:
        if p is None or p == "":
            continue
        if p.lower() in ("or", "and"):
            out.append(p.upper())
            continue
        if p in DEP5_TO_SPDX:
            out.append(DEP5_TO_SPDX[p])
        elif p.lower() in spdx_ids:
            out.append(spdx_ids[p.lower()])
        else:
            ref = license_ref(p)
            refs[ref] = p
            out.append(ref)
    return " ".join(out) if len(out) == 1 else "(" + " ".join(out) + ")"


def parse_dep5(text: str) -> dict | None:
    paras = [p for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]
    if not paras or not re.search(r"^Format:\s*\S*copyright-format/1\.0", paras[0], re.M | re.I):
        return None
    files_licenses, standalone = [], {}
    for p in paras[1:]:
        fields: dict[str, str] = {}
        key = None
        for line in p.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                fields[key] = val.strip()
        if "license" not in fields:
            continue
        short, _, body = fields["license"].partition("\n")
        short = short.strip()
        if "files" in fields:
            pats = fields["files"].split()
            if pats and all(x.startswith("debian/") for x in pats):
                continue                                   # packaging only, not shipped code
            if short:
                files_licenses.append(short)
        elif short and body.strip():
            standalone[short] = body
    return {"licenses": sorted(set(files_licenses)), "texts": standalone}


def package_license(pkg: DebPkg, tools_root: Path, spdx_ids: dict[str, str]) -> dict:
    raw, where = doc_file(pkg, "copyright", tools_root)
    if raw is None:
        return {"expression": "NOASSERTION", "source": where, "refs": {}}
    d = parse_dep5(raw.decode("utf-8", "replace"))
    if d is None or not d["licenses"]:
        return {"expression": "NOASSERTION", "source": f"{where} (not DEP-5 machine-readable)",
                "refs": {}}
    refs: dict[str, str] = {}
    exprs = sorted({dep5_to_spdx(x, spdx_ids, refs) for x in d["licenses"]})
    expr = exprs[0] if len(exprs) == 1 else " AND ".join(exprs)
    texts = {}
    for ref, name in refs.items():
        texts[ref] = d["texts"].get(name, f"See {where}, License: {name}")
    return {"expression": expr, "source": where, "dep5": d["licenses"], "refs": texts}
