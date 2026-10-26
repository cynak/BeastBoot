#!/usr/bin/env python3
"""Generate beast-booter's Software Bill of Materials.

    python3 -I scripts/gen_sbom.py [--root DIR]

Inputs (read-only): dist/manifest.json + dist/ files (docs/ARCHITECTURE.md
section 4), the host dpkg database, .tools/debs/*.deb, /usr/share/doc/*/copyright,
installer/beastbooter/*.py.

Outputs: sbom/beast-booter.cdx.json (CycloneDX 1.6) and sbom/beast-booter.spdx.json
(SPDX 2.3). Output is deterministic for the same inputs: timestamps come from the
manifest's source_date_epoch and identifiers are derived from content hashes.

What is modelled:
  shipped    every distribution package that supplies a file on the drive, the
             upstream projects (GNU GRUB, rhboot shim) with CPEs, Built-Using
             source packages, and one component per dist/ file (nested under its
             package, or top-level for files built here / taken from the repo)
  build      packages whose tools or data are used to build dist/ (grub-mkimage,
             sbsign, the SBAT source package, ...), scope "excluded"
  install    host tools the installer runs (mkfs.*, mtools, sfdisk, blkid)
  test       the rootless QEMU/OVMF test toolchain from .tools/debs
  certs      every certificate in an Authenticode signature of a shipped EFI
             binary (CycloneDX cryptographic-asset)
  beast-net  esp/beast-net/vmlinuz nested under its linux-image package plus the kernel
             itself (pkg:generic/linux-kernel@<release>, the identity syft reports; no CPE,
             its vulnerabilities are tracked through the Ubuntu linux source package);
             initrd.img GENERATED_FROM every package of build/beastnet/packages.lock it
             contains (resolved from the locked .debs in the beast-net cache)
  portable   role "portable" (scope required): the python-build-standalone runtime of each
             portable package (packaging/portable/runtimes.lock, archive SHA-256), CPython
             and the libraries/distributions bundled in it (with CPEs/purls for scanning)
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import debinfo as deb          # noqa: E402
import efi_inspect as efi      # noqa: E402

TOOL_NAME = "beast-booter sbom-vuln gen_sbom.py"
TOOL_VERSION = "1"
P = "beast-booter:"            # property namespace
SHIPPED_ROLES = ("shipped", "portable")   # CycloneDX scope "required": on the drive / in the release packages

# Packages the build, the installer and the tests use (not shipped). The SBOM records
# them with scope "excluded" so they can be scanned without being mistaken for
# drive content. (package, role, what it is used for)
TOOLING = [
    ("grub2-common", "build", "grub-mkfont makes the menu fonts (grub-mkimage comes from our GRUB source build)"),
    ("sbsigntool", "build", "sbsign/sbverify/sbattach sign and check grubx64.efi"),
    ("openssl", "build", "make keys (key + certificate), certificate checks"),
    ("binutils", "build", "objcopy reads the .sbat/.sbatlevel sections"),
    ("python3", "build", "python3 interpreter (build/bbtool.py, the installer)"),
    ("python3.14", "build", "Python runtime behind python3"),
    ("dosfstools", "install", "mkfs.fat: validates the FAT32 ESP and FAT32 data partitions"),
    ("exfatprogs", "install", "mkfs.exfat: exFAT data partition (default)"),
    ("ntfs-3g", "install", "mkfs.ntfs: NTFS data partition"),
    ("mtools", "install", "mmd/mcopy write the ESP without mounting it"),
    ("fdisk", "install", "sfdisk writes the partition table"),
    ("util-linux", "install", "blkid probes the filesystems"),
]
INSTALLER_TOOLS = ["python3", "python3.14", "dosfstools", "exfatprogs", "ntfs-3g", "mtools",
                   "fdisk", "util-linux"]

UPSTREAMS = {
    # source package family -> upstream project
    "grub2": {"key": "gnu-grub", "name": "grub2", "group": "gnu", "title": "GNU GRUB",
              "supplier": "Free Software Foundation", "cpe_vendor": "gnu", "cpe_product": "grub2",
              "website": "https://www.gnu.org/software/grub/",
              "vcs": "https://git.savannah.gnu.org/git/grub.git", "license": "GPL-3.0-or-later"},
    "shim": {"key": "rhboot-shim", "name": "shim", "group": "rhboot", "title": "rhboot shim",
             "supplier": "rhboot (UEFI shim maintainers)", "cpe_vendor": "redhat", "cpe_product": "shim",
             "website": "https://github.com/rhboot/shim",
             "vcs": "https://github.com/rhboot/shim", "license": "BSD-2-Clause"},
    "wimboot": {"key": "ipxe-wimboot", "name": "wimboot", "group": "ipxe", "title": "iPXE wimboot",
                "supplier": "iPXE project", "cpe_vendor": "ipxe", "cpe_product": "wimboot",
                "website": "https://ipxe.org/wimboot",
                "vcs": "https://github.com/ipxe/wimboot", "license": "GPL-2.0-or-later"},
}
SOURCE_FAMILY = {"grub2": "grub2", "grub2-unsigned": "grub2", "grub2-signed": "grub2",
                 "shim": "shim", "shim-signed": "shim", "shim-helpers-amd64-signed": "shim"}
VENDOR_NAME = {"ubuntu": "Ubuntu", "debian": "Debian"}
# A file whose signature build.sh replaced: "built:deb:<pkg>=<ver>:<path> with its signatures
# removed (sbattach --remove), signed:beast-booter" (the beast-net helper kernel).
RESIGNED_MARK = "with its signatures removed"


def die(msg: str) -> None:
    print(f"gen_sbom: error: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"gen_sbom: warning: {msg}", file=sys.stderr)


def sha(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def props(d: dict) -> list[dict]:
    out = []
    for k, v in d.items():
        if v is None or v == "" or v == []:
            continue
        for item in (v if isinstance(v, list) else [v]):
            out.append({"name": P + k, "value": str(item)})
    return out


def spdx_id(prefix: str, text: str, used: set) -> str:
    base = f"SPDXRef-{prefix}-" + re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-")
    sid, n = base, 2
    while sid in used:
        sid, n = f"{base}-{n}", n + 1
    used.add(sid)
    return sid


def os_release() -> dict:
    out = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        k, _, v = line.partition("=")
        out[k] = v.strip().strip('"')
    return out


# Debian versions use only [0-9A-Za-z.+~:-]; stopping there keeps a closing ")", "]" or ";" of
# prose like "(... from deb:pkg=1.0)" or "deb:a=1, deb:b=2; 497 modules" out of the version.
ORIGIN_DEB = re.compile(r"deb:([a-z0-9][a-z0-9+.-]*)=([0-9][0-9A-Za-z.+~:-]*?)(?::(/[^\s,;)\]]*))?(?=[\s,;)\]]|$)")
ORIGIN_REPO = re.compile(r"repo:([^\s,]+)")
# GRUB built from source by build/grub/grubsrc.py: grub-src:grub2=<version>[:/<path in its build dir>]
ORIGIN_GRUB = re.compile(r"grub-src:([a-z0-9][a-z0-9+.-]*)=([0-9][0-9A-Za-z.+~:-]*?)(?::(/[^\s,;)\]]*))?(?=[\s,;)\]]|$)")
# wimboot built from source by build/wimboot/wimbootsrc.py: wimboot-src:wimboot=<version>:/<path in its build dir>
ORIGIN_WIMBOOT = re.compile(r"wimboot-src:([a-z0-9][a-z0-9+.-]*)=([0-9][0-9A-Za-z.+~-]*?):(/[^\s,;)\]]*)(?=[\s,;)\]]|$)")


def resigned_origin(path: Path, p: deb.DebPkg, member: str | None) -> str:
    """A re-signed file (RESIGNED_MARK): its Authenticode digest (code without signatures) must be
    that of `member` in package `p`."""
    if not member:
        return f"MISMATCH: origin names no file inside {p.name}"
    if p.deb_path is not None:
        where = f"{p.deb_path.name}:{member}"
    else:
        where = f"host {member} ({p.name} {p.version})"
    try:
        if p.deb_path is not None:
            src = deb.deb_member_bytes(p.deb_path, member)
        else:
            src = Path(member).read_bytes() if Path(member).is_file() else None
    except (OSError, subprocess.CalledProcessError) as e:
        # e.g. /boot/vmlinuz-* is mode 0600 on Ubuntu: not verified, which is not a mismatch
        return f"unverified: cannot read {where} ({e.__class__.__name__}: {e})"
    if src is None:
        return f"MISMATCH: {member} is not in {p.name} {p.version}"
    try:
        a = efi.authenticode_digest(efi.parse_pe(src)).hex()
        b = efi.authenticode_digest(efi.parse_pe(path.read_bytes())).hex()
    except efi.PEError as e:
        return f"MISMATCH: not a PE image ({e})"
    if a != b:
        return f"MISMATCH: Authenticode digest differs from {where}"
    return f"authenticode sha256 matches {where} (signature replaced by the beast-booter key)"


def parse_origin(origin: str) -> dict:
    kind = origin.split(":", 1)[0] if ":" in origin else "unknown"
    debs = [{"name": m.group(1), "version": m.group(2), "path": m.group(3)}
            for m in ORIGIN_DEB.finditer(origin)]
    grub = [{"name": m.group(1), "version": m.group(2), "path": m.group(3)}
            for m in ORIGIN_GRUB.finditer(origin)]
    wimboot = [{"name": m.group(1), "version": m.group(2), "path": m.group(3)}
               for m in ORIGIN_WIMBOOT.finditer(origin)]
    return {"kind": {"deb": "copied"}.get(kind, kind), "debs": debs, "grub": grub, "wimboot": wimboot,
            "repo": ORIGIN_REPO.findall(origin), "signed_by_bb": "signed:beast-booter" in origin,
            "raw": origin}


def evidence_label(e: dict) -> str:
    """How a fix of the GRUB source build was proven: its upstream commit, or our patch
    (build/grub/security-fixes.json evidence of a fix with no upstream GRUB commit)."""
    return f"upstream {e['commit'][:12]}" if e.get("commit") else (e.get("patch") or "?")


def grub_purl(version: str, distro: str) -> str:
    """purl of our GRUB source build. Scanners (grype) match Debian/Ubuntu data through the
    upstream (source package) qualifier; Ubuntu tracks GRUB's CVEs under grub2-unsigned."""
    return (f"pkg:deb/beastboot/grub2@{quote(version, safe='')}?arch=amd64&distro={quote(distro, safe='')}"
            "&upstream=grub2-unsigned")


def grub_purl_distro(root: Path, info: dict) -> str:
    """distro qualifier of our GRUB's purl: the Ubuntu series its source package comes from
    (build/grub/source.lock.json purl_distro, recorded in build-info.json), not the build host's."""
    if info.get("purl_distro"):
        return info["purl_distro"]
    return json.loads((root / "build/grub/source.lock.json").read_text())["purl_distro"]


def load_grub_build(root: Path, manifest: dict) -> dict | None:
    """The source-built GRUB the manifest names (build.grub_*): its build-info.json from the
    build/grub/grubsrc.py cache, accepted only if its SHA-256 is the one the manifest recorded."""
    b = manifest.get("build", {})
    ver, key = b.get("grub_version"), b.get("grub_build_key")
    if not ver or not key:
        return None
    cache = Path(os.environ.get("BB_GRUB_CACHE") or root / ".tools/cache/grub-src")
    out = cache / "out" / key
    info, note = None, None
    p = out / "build-info.json"
    if p.is_file():
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() == b.get("grub_build_info_sha256"):
            info = json.loads(raw)
        else:
            note = f"{p} is not the build-info.json the manifest recorded (grub_build_info_sha256)"
    else:
        note = (f"GRUB build {key} is not in {cache.relative_to(root) if cache.is_relative_to(root) else cache}/out "
                "(`python3 -I build/grub/grubsrc.py build` recreates it)")
    return {"version": ver, "key": key, "dir": out, "info": info, "note": note}


def load_wimboot_build(root: Path, manifest: dict) -> dict | None:
    """The source-built wimboot the manifest names (build.wimboot_*): its build-info.json from the
    build/wimboot/wimbootsrc.py cache, accepted only if its SHA-256 is the one the manifest recorded."""
    b = manifest.get("build", {})
    ver, key = b.get("wimboot_version"), b.get("wimboot_build_key")
    if not ver or not key:
        return None
    cache = Path(os.environ.get("BB_WIMBOOT_CACHE") or root / ".tools/cache/wimboot")
    p = cache / "out" / key / "build-info.json"
    info, note = None, None
    if p.is_file():
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() == b.get("wimboot_build_info_sha256"):
            info = json.loads(raw)
        else:
            note = f"{p} is not the build-info.json the manifest recorded (wimboot_build_info_sha256)"
    else:
        note = (f"wimboot build {key} is not in the wimboot cache "
                "(`python3 -I build/wimboot/wimbootsrc.py build` recreates it)")
    return {"version": ver, "key": key, "info": info, "note": note}


ORIGIN_REPO_FILE = re.compile(r"(?:repo|key):([^\s,]+)")


def verify_repo_origin(root: Path, path: Path, origin: str) -> str:
    """A file copied verbatim from the repo ("repo:grub/grub.cfg", "key:keys/x.cer"): compare it
    with the working tree. DRIFT means the tree changed after the build (or dist/ was altered)."""
    m = ORIGIN_REPO_FILE.fullmatch(origin.strip())
    if not m:
        return "UNVERIFIED: origin is not a single repository path"
    src = (root / m.group(1)).resolve()
    if not src.is_relative_to(root) or not src.is_file():
        return f"UNVERIFIED: {m.group(1)} is not a file in the working tree"
    if sha(src, "sha256") == sha(path, "sha256"):
        return f"sha256 matches working-tree {m.group(1)}"
    return (f"DRIFT: differs from working-tree {m.group(1)} (the tree changed after the build, "
            "or the shipped file was altered)")


def installer_imports(root: Path) -> dict:
    pkg = root / "installer" / "beastbooter"
    mods, files = set(), 0
    for f in sorted(pkg.rglob("*.py")):
        files += 1
        tree = ast.parse(f.read_text(), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
    own = {"beastbooter"}
    third = sorted(m for m in mods - own if m not in sys.stdlib_module_names)
    return {"files": files, "modules": sorted(mods - own), "non_stdlib": third,
            "stdlib_only": not third and files > 0,
            "checked_with": f"sys.stdlib_module_names of Python {sys.version.split()[0]}"}


def kernel_version_string(path: Path) -> str | None:
    """The version string of an x86 Linux bzImage ("7.0.0-38-generic (buildd@...) #38-Ubuntu SMP ..."):
    boot protocol header "HdrS" at 0x202, kernel_version pointer at 0x20E (offset - 0x200)."""
    with open(path, "rb") as f:
        head = f.read(0x8000)
        if len(head) < 0x210 or head[0x202:0x206] != b"HdrS":
            return None
        ptr = int.from_bytes(head[0x20E:0x210], "little")
        if not ptr:
            return None
        f.seek(ptr + 0x200)
        raw = f.read(256).split(b"\0", 1)[0]
    text = raw.decode("ascii", "replace").strip()
    return text if re.match(r"\d+\.\d+", text) else None


# =========================================================================== portable runtimes

# Libraries python-build-standalone links into its runtimes, found by their version strings in the
# shipped binaries: name -> (regex, CPE vendor:product, purl type, description).
RUNTIME_LIBS = {
    "openssl": (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) +\d+ [A-Z][a-z]{2} \d{4}", "openssl:openssl", "OpenSSL (ssl, hashlib)"),
    "expat": (rb"expat_(\d+\.\d+\.\d+)", "libexpat_project:libexpat", "Expat XML parser (pyexpat)"),
    "zlib": (rb"(?:deflate|inflate) (\d+\.\d+(?:\.\d+)*) Copyright", "zlib:zlib", "zlib (zlib module)"),
    "bzip2": (rb"(1\.0\.\d+), \d+-[A-Z][a-z]{2}-\d{4}", "bzip:bzip2", "bzip2 (bz2 module)"),
    "tcl": (rb"package require -exact [Tt]cl (\d+\.\d+\.\d+)", "tcl:tcl", "Tcl/Tk (tkinter, the GUI)"),
    "mpdecimal": (rb"mpdecimal[^\x00]{0,10}?(\d+\.\d+\.\d+)", None, "mpdecimal (decimal module)"),
}
RUNTIME_SCAN_FILES = re.compile(r"(_ssl|_hashlib|libssl|libcrypto|pyexpat|zlib|_bz2|_lzma|_decimal|libmpdec|"
                                r"libpython3[^/]*|python3\d*\.dll|init\.tcl)[^/]*$")
SQLITE_SOURCE_ID = re.compile(rb"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [0-9a-f]{64})")


def inspect_runtime(archive: Path) -> dict:
    """Bundled library versions and Python distributions inside a python-build-standalone archive."""
    import tarfile
    libs: dict[str, str] = {}
    dists: dict[str, str] = {}
    sqlite = None
    with tarfile.open(archive) as tf:
        for m in tf:
            parts = m.name.split("/")
            for seg in parts:
                dm = re.fullmatch(r"([A-Za-z0-9_.-]+?)-(\d[^-]*)\.dist-info", seg)
                if dm and "site-packages" in parts:
                    dists[dm.group(1).lower().replace("_", "-")] = dm.group(2)
            if not m.isfile() or not RUNTIME_SCAN_FILES.search(m.name) or m.name.endswith(".pdb"):
                continue
            data = tf.extractfile(m).read()
            for name, (rx, _cpe, _d) in RUNTIME_LIBS.items():
                hit = re.search(rx, data)
                if hit and name not in libs:
                    libs[name] = hit.group(1).decode()
            if sqlite is None and (hit := SQLITE_SOURCE_ID.search(data)):
                sqlite = hit.group(1).decode()
    return {"libs": libs, "dists": dists, "sqlite_source_id": sqlite}


def add_portable_runtimes(m: Model, root: Path, lock_path: Path, version: str, cache: Path) -> None:
    """Portable packages (packaging/portable): one python-build-standalone runtime per target, the
    CPython in it and the libraries it bundles. Deterministic: only runtimes.lock and the pinned
    archives (checked against the lock's SHA-256) are read."""
    lock = json.loads(lock_path.read_text())
    rel_lock = lock_path.relative_to(root).as_posix() if lock_path.is_relative_to(root) else str(lock_path)
    pref = f"beast-booter-portable@{version}"
    m.add({"ref": pref, "kind": "portable", "role": "portable", "name": "beast-booter-portable", "version": version,
           "purl": f"pkg:generic/beast-booter-portable@{version}",
           "license": "GPL-3.0-or-later", "license_source": "README.md + LICENSE",
           "description": "no-install portable packages (packaging/portable, release assets "
                          "beast-booter-<version>-<target>.zip/.tar.gz): the installer, dist/ and a bundled "
                          "Python runtime per target",
           "props": {"role": "portable", "runtimes-lock": rel_lock, "targets": " ".join(sorted(lock["targets"]))}})
    m.dep(pref, f"beast-booter@{version}", "CONTAINS")
    m.dep(pref, f"beast-booter-installer@{version}", "CONTAINS")
    py = lock["python"]
    cref = f"runtime:cpython@{py}"
    m.add({"ref": cref, "kind": "runtime-lib", "role": "portable", "name": "python", "version": py,
           "group": "python.org", "purl": f"pkg:generic/python@{py}",
           "cpe": f"cpe:2.3:a:python:python:{py}:*:*:*:*:*:*:*", "supplier": "Python Software Foundation",
           "homepage": "https://www.python.org/", "license": "PSF-2.0",
           "license_source": "CPython LICENSE (python-build-standalone ships it as python/LICENSE.txt)",
           "description": f"CPython {py} interpreter and standard library in every portable runtime",
           "props": {"role": "portable", "targets": " ".join(sorted(lock["targets"]))}})
    for target, spec in sorted(lock["targets"].items()):
        rref = f"runtime:python-build-standalone@{lock['release']}:{target}"
        arc = cache / spec["asset"]
        info, inspected = {"libs": {}, "dists": {}, "sqlite_source_id": None}, "no"
        if arc.is_file() and sha(arc, "sha256") == spec["sha256"]:
            info, inspected = inspect_runtime(arc), "yes"
        else:
            m.notes.append(f"portable runtime {spec['asset']} not in {cache} (or SHA-256 differs): "
                           "bundled library versions not inspected")
        m.add({"ref": rref, "kind": "runtime", "role": "portable", "parent": pref,
               "name": f"python-build-standalone-{target}", "group": "astral-sh",
               "version": f"{py}+{lock['release']}",
               "purl": (f"pkg:generic/python-build-standalone-{target}@{py}%2B{lock['release']}?"
                        f"checksum=sha256%3A{spec['sha256']}&download_url={quote(spec['url'], safe='')}"),
               "hashes": {"SHA-256": spec["sha256"]}, "distribution": spec["url"],
               "supplier": "Astral (python-build-standalone)", "homepage": lock.get("project_url"),
               "vcs": lock.get("project_url"), "license": "NOASSERTION",
               "license_source": "per bundled component (python/LICENSE.txt and the licenses of each library)",
               "description": f"relocatable CPython {py} for {target} ({spec['asset']}), bundled in "
                              f"beast-booter-<version>-{target}",
               "props": {"role": "portable", "target": target, "asset": spec["asset"], "contents-inspected": inspected,
                         "bundled-sqlite-source-id": info["sqlite_source_id"],
                         "bundled-libraries": " ".join(f"{k}@{v}" for k, v in sorted(info["libs"].items())),
                         "bundled-python-distributions": " ".join(f"{k}@{v}" for k, v in sorted(info["dists"].items()))}})
        m.dep(rref, cref, "CONTAINS")
        for lib, ver in sorted(info["libs"].items()):
            _rx, cpe, desc = RUNTIME_LIBS[lib]
            lref = f"runtime:{lib}@{ver}"
            it = m.add({"ref": lref, "kind": "runtime-lib", "role": "portable", "name": lib, "version": ver,
                        "purl": f"pkg:generic/{lib}@{ver}",
                        "cpe": f"cpe:2.3:a:{cpe}:{ver}:*:*:*:*:*:*:*" if cpe else None,
                        "license": "NOASSERTION", "license_source": "bundled by python-build-standalone",
                        "description": f"{desc}, linked into the python-build-standalone runtime "
                                       "(version read from the shipped binary)",
                        "props": {"role": "portable", "targets": []}})
            it["props"]["targets"].append(target)
            m.dep(rref, lref, "CONTAINS")
        for dist, ver in sorted(info["dists"].items()):
            dref = f"runtime:pypi-{dist}@{ver}"
            it = m.add({"ref": dref, "kind": "runtime-lib", "role": "portable", "name": dist, "version": ver,
                        "purl": f"pkg:pypi/{dist}@{ver}", "license": "NOASSERTION",
                        "license_source": "Python distribution metadata (not read)",
                        "description": f"Python distribution {dist} in the runtime's site-packages",
                        "props": {"role": "portable", "targets": []}})
            it["props"]["targets"].append(target)
            m.dep(rref, dref, "CONTAINS")


# =========================================================================== model


class Model:
    """Format-neutral inventory; emitted as CycloneDX and SPDX."""

    def __init__(self):
        self.items: dict[str, dict] = {}       # bom-ref -> item
        self.deps: dict[str, list[tuple[str, str]]] = {}   # ref -> [(ref, spdx relationship)]
        self.notes: list[str] = []
        self.provenance_errors: list[str] = []      # shipped files that differ from their stated package

    def add(self, item: dict) -> dict:
        ref = item["ref"]
        if ref in self.items:
            return self.items[ref]
        self.items[ref] = item
        self.deps.setdefault(ref, [])
        return item

    def dep(self, a: str, b: str, rel: str = "DEPENDS_ON") -> None:
        if (b, rel) not in self.deps.setdefault(a, []):
            self.deps[a].append((b, rel))


def beastnet_kernel_distros(root: Path) -> dict[tuple[str, str], str]:
    """(package, version) -> purl distro of the beast-net kernel and modules packages that
    build/beastnet/packages.lock takes from another Ubuntu series (its 6th column, e.g.
    ubuntu-26.10, read by lock.py from that series' signed InRelease)."""
    out: dict[tuple[str, str], str] = {}
    lock = root / "build" / "beastnet" / "packages.lock"
    if lock.is_file():
        for line in lock.read_text().splitlines():
            f = line.split("#", 1)[0].split()
            if len(f) == 6 and f[4] in ("kernel", "modules"):
                out[(f[0], f[1])] = f[5]
    return out


def build_model(root: Path, dist: Path, distro: str, spdx_ids: dict,
                runtimes: Path | None = None) -> tuple[Model, dict]:
    mpath = dist / "manifest.json"
    if not mpath.is_file():
        die(f"{mpath} not found - run `make build` first")
    manifest_raw = mpath.read_bytes()
    manifest = json.loads(manifest_raw)
    if manifest.get("schema") != 1:
        die(f"unsupported manifest schema {manifest.get('schema')!r}")
    debs_dir = root / ".tools" / "debs"
    tools_root = root / ".tools" / "root"
    resolve = deb.Resolver(root)
    beastnet_pkgs = set(resolve.lock)
    kernel_distro = beastnet_kernel_distros(root)
    m = Model()
    version = manifest["version"]
    root_ref = f"beast-booter@{version}"
    sb = manifest.get("secure_boot", {})

    # ---- dist/ files: verify against the manifest ------------------------------------
    on_disk = sorted(p.relative_to(dist).as_posix() for p in dist.rglob("*")
                     if p.is_file() and p.relative_to(dist).as_posix() != "manifest.json")
    listed = sorted(manifest["files"])
    if on_disk != listed:
        extra = sorted(set(on_disk) - set(listed))
        missing = sorted(set(listed) - set(on_disk))
        die(f"dist/ does not match manifest.json (unlisted: {extra[:5]}, missing: {missing[:5]}); "
            "dist/ may be mid-rebuild - rerun after `make build` finishes")
    files = {}
    # An SBOM copied onto the drive (origin "built:sbom...") cannot describe itself: skip it.
    self_sboms = sorted(r for r, meta in manifest["files"].items() if meta["origin"].startswith("built:sbom"))
    for r in self_sboms:
        m.notes.append(f"{r}: SBOM file shipped on the drive; not inventoried by itself")
    for rel, meta in manifest["files"].items():
        if rel in self_sboms:
            continue
        p = dist / rel
        s256 = sha(p, "sha256")
        if s256 != meta["sha256"] or p.stat().st_size != meta["size"]:
            die(f"{rel}: SHA-256/size differs from manifest.json - dist/ changed; rerun `make build`")
        files[rel] = {"sha256": s256, "sha1": sha(p, "sha1"), "size": meta["size"],
                      "origin": parse_origin(meta["origin"])}

    # ---- packages named in the manifest -------------------------------------------------
    pkgs: dict[str, deb.DebPkg] = {}
    pkg_roles: dict[str, str] = {}
    wanted: dict[str, str] = {}
    for rel, f in files.items():
        for d in f["origin"]["debs"]:
            wanted[d["name"]] = d["version"]
    for blk in (manifest.get("build", {}).get("grub_mkimage", ""), manifest.get("build", {}).get("sbsign", ""),
                sb.get("sbat_source", "")):
        for d in ORIGIN_DEB.finditer(blk or ""):
            wanted.setdefault(d.group(1), d.group(2))
    for name, ver in sorted(wanted.items()):
        p = resolve(name, ver)
        if p is None:
            die(f"package {name}={ver} (named in manifest.json) is neither installed nor in "
                f"{', '.join(str(d) for d in resolve.debs_dirs)}")
        pkgs[name] = p

    shipped_pkgs = sorted({d["name"] for f in files.values() if f["origin"]["kind"] == "copied"
                           for d in f["origin"]["debs"]} |
                          {d["name"] for f in files.values() if f["origin"]["kind"] == "built"
                           for d in f["origin"]["debs"]})
    for n in shipped_pkgs:
        pkg_roles[n] = "shipped"
    sbat_src = ORIGIN_DEB.search(sb.get("sbat_source", "") or "")
    if sbat_src and sbat_src.group(1) not in pkg_roles:
        pkg_roles[sbat_src.group(1)] = "build"

    # ---- root -------------------------------------------------------------------------
    m.add({"ref": root_ref, "kind": "root", "name": "beast-booter", "version": version,
           "purl": f"pkg:generic/beast-booter@{version}",
           "description": "beast-booter boot files (dist/): copied to the ESP and boot area of a "
                          "beast-booter drive by the installer",
           "license": "GPL-3.0-or-later", "license_source": "README.md (License) + LICENSE (GPLv3 text)",
           "props": {"build-id": manifest.get("build_id"), "source-date-epoch": manifest.get("source_date_epoch"),
                     "manifest-sha256": hashlib.sha256(manifest_raw).hexdigest(),
                     "manifest-schema": manifest.get("schema"),
                     "secure-boot-cert-sha256": sb.get("cert_sha256"),
                     "secure-boot-cert-subject": sb.get("cert_subject"),
                     "grub-efi-modules": " ".join(manifest.get("build", {}).get("efi_modules", [])),
                     "grub-efi-prefix": manifest.get("build", {}).get("efi_prefix"),
                     "grub-bios-core-modules": " ".join(manifest.get("build", {}).get("bios_core_modules", [])),
                     "grub-build-key": manifest.get("build", {}).get("grub_build_key"),
                     "sbat-version-check": sb.get("sbat_version_check")}})

    # ---- licenses + package components ----------------------------------------------------
    license_refs: dict[str, str] = {}

    def add_pkg(p: deb.DebPkg, role: str, used_for: str = "") -> str:
        ref = f"deb:{p.name}@{p.version}"
        if ref in m.items:
            return ref
        lic = deb.package_license(p, tools_root, spdx_ids)
        lic["source"] = lic["source"].replace(str(root) + "/", "")
        license_refs.update({k: v.replace(str(root) + "/", "") for k, v in lic["refs"].items()})
        maint = re.match(r"\s*(.*?)\s*<([^>]+)>", p.maintainer or "")
        item = {"ref": ref, "kind": "package", "role": role, "name": p.name, "version": p.version,
                "purl": deb.purl(p, kernel_distro.get((p.name, p.version), distro)), "arch": p.arch,
                "supplier": maint.group(1) if maint else (p.maintainer or None),
                "supplier_email": maint.group(2) if maint else None,
                "homepage": p.homepage or None, "license": lic["expression"],
                "license_source": lic["source"],
                "props": {"role": role, "used-for": used_for, "source-package": p.source,
                          "source-version": p.source_version,
                          "built-using": ", ".join(f"{a} (= {b})" for a, b in p.built_using),
                          "package-origin": resolve.origin_text(p),
                          "beast-net-package": ("build/beastnet/packages.lock" if p.name in beastnet_pkgs
                                                and resolve.lock[p.name][0] == p.version else None),
                          "license-source": lic["source"]}}
        m.add(item)
        fam = SOURCE_FAMILY.get(p.source)
        if fam and role == "shipped":
            up = add_upstream(fam, p.upstream_version if fam == "grub2" else None, p)
            if up:
                m.dep(ref, up, "DESCENDANT_OF")
                item["props"]["upstream"] = up
        return ref

    def add_upstream(fam: str, ver: str | None, p: deb.DebPkg | None, of: str | None = None) -> str | None:
        u = UPSTREAMS[fam]
        if ver is None:          # shim: version from Built-Using (shim-signed embeds shim X)
            bu = dict(p.built_using)
            if "shim" in bu:
                ver = deb.upstream_version(bu["shim"])
            elif p.source == "shim":
                ver = p.upstream_version
            else:
                return None
        ref = f"upstream:{u['key']}@{ver}"
        m.add({"ref": ref, "kind": "upstream", "role": "shipped", "name": u["name"], "group": u["group"],
               "version": ver, "title": u["title"], "supplier": u["supplier"],
               "cpe": f"cpe:2.3:a:{u['cpe_vendor']}:{u['cpe_product']}:{ver}:*:*:*:*:*:*:*",
               "homepage": u["website"], "vcs": u["vcs"], "license": u["license"],
               "license_source": "upstream project (also stated in README.md)",
               "description": (f"{u['title']} {ver} upstream source, as packaged by "
                               f"{VENDOR_NAME.get(p.vendor, p.vendor)}") if p is not None else
                              f"{u['title']} {ver} upstream source, built by beast-booter ({of})",
               "props": {"role": "shipped", "upstream-of": []}})
        m.items[ref]["props"]["upstream-of"].append(of or p.name)
        return ref

    for name in sorted(pkgs):
        role = pkg_roles.get(name)
        if role is None:
            continue
        used = {"grub-efi-amd64-signed": "only its SBAT CSV is copied into grubx64.efi's .sbat; "
                                         "its signed grubx64.efi.signed is NOT shipped",
                "grub2-common": "shipped: grub/fonts/unicode.pf2; build: grub-mkfont",
                "shim-signed": "shipped: esp/EFI/BOOT/BOOTX64.EFI (Debian's shim, signed through Microsoft "
                               "UEFI CA 2011 and Microsoft UEFI CA 2023)",
                "shim-helpers-amd64-signed": "shipped: esp/EFI/BOOT/mmx64.efi (MokManager, signed with "
                                             "Debian's shim key); its fbx64.efi is NOT shipped"}.get(name, "")
        if pkgs[name].vendor != "ubuntu":
            used = (used + "; " if used else "") + "pinned in build/shim/debian-shim.lock"
        ref = add_pkg(pkgs[name], role, used)
        p = pkgs[name]
        if role == "shipped":
            m.dep(root_ref, ref, "CONTAINS")
            for src, sver in p.built_using:          # code embedded in this binary package
                bref = f"deb-src:{src}@{sver}"
                m.add({"ref": bref, "kind": "source", "role": "shipped", "name": src, "version": sver,
                       "purl": deb.source_purl(src, sver, kernel_distro.get((p.name, p.version)) or p.distro or distro, namespace=p.vendor),
                       "supplier": VENDOR_NAME.get(p.vendor, p.vendor),
                       "license": "NOASSERTION", "license_source": "source package (see binary package)",
                       "description": f"source package built into {p.name} (Built-Using)",
                       "props": {"role": "shipped", "built-using-of": p.name}})
                m.dep(ref, bref, "GENERATED_FROM")
        else:
            m.dep(ref, root_ref, "BUILD_DEPENDENCY_OF")

    # ---- GRUB built from source (build/grub/grubsrc.py) -----------------------------------
    # One component for our build (the code on the drive), DESCENDANT_OF upstream GNU GRUB
    # (CPE: NVD ranges apply to the upstream version) and GENERATED_FROM Ubuntu's source
    # package. Its purl names that source package with our patch level as the version, so
    # scanners match Ubuntu's tracker data for grub2 against exactly this build.
    grub = load_grub_build(root, manifest)
    grub_ref = None
    if grub:
        info = grub["info"] or {}
        grub_ref = f"grub-src:grub2@{grub['version']}"
        if grub["note"]:
            m.notes.append(grub["note"])
        src_ver = info.get("source_version") or grub["version"].rsplit("+bb", 1)[0]
        up_ver = info.get("upstream_version") or src_ver.split("-", 1)[0]
        fixes = (info.get("security_fixes") or {}).get("fixes", [])
        claims = (info.get("security_fixes") or {}).get("sbat_claims", [])
        patches = info.get("beast_booter_patches", [])
        pedigree_patches = []
        for p_ in patches:
            fixed = [f for f in fixes if f["where"].startswith(f"build/grub/patches/{p_['name']}")]
            pedigree_patches.append({"type": "backport", "diff": {"url": f"build/grub/patches/{p_['name']}"},
                                     "resolves": [{"type": "defect" if f.get("type") == "defect" else "security",
                                                   "id": f["id"]} for f in fixed]})
        dsc = next((s for s in info.get("source", []) if s["name"].endswith(".dsc")), None)
        grub_distro = grub_purl_distro(root, info)

        def fix_label(f: dict) -> str:
            return f"{f['id']} ({', '.join(evidence_label(e) for e in f['evidence'])}; {f['where']})"
        sec_fixes = [f for f in fixes if f["present"] and f.get("type", "security") != "defect"]
        defect_fixes = [f for f in fixes if f["present"] and f.get("type") == "defect"]
        m.add({"ref": grub_ref, "kind": "source-build", "role": "shipped", "name": "grub2",
               "version": grub["version"], "purl": grub_purl(grub["version"], grub_distro),
               "supplier": "beast-booter maintainers", "homepage": UPSTREAMS["grub2"]["website"],
               "license": "GPL-3.0-or-later", "license_source": "GNU GRUB (debian/copyright of the grub2 source package)",
               "description": (f"GNU GRUB {up_ver} built by beast-booter (build/grub/grubsrc.py) from Ubuntu's grub2 "
                               f"{src_ver} source package with its {info.get('ubuntu_patches', '?')} Ubuntu patches "
                               f"plus {len(patches)} beast-booter patch(es); x86_64-efi (grubx64.efi) and i386-pc"),
               "pedigree": {"patches": pedigree_patches,
                            "notes": (f"Ubuntu grub2 {src_ver} (debian/patches/series, applied unchanged) + "
                                      "build/grub/patches/series. Each fix is proven present by reverse-applying "
                                      "its evidence to the patched source (patch -R --dry-run -F0): its upstream "
                                      "commit, or, for a fix with no upstream GRUB commit, our patch (which must "
                                      "not reverse-apply to Ubuntu's tree alone). Security fixes: " +
                                      ("; ".join(fix_label(f) for f in sec_fixes) or "none") +
                                      (". Defect fixes (no SBAT generation): " + "; ".join(fix_label(f) for f in defect_fixes)
                                       if defect_fixes else ""))}
               if info else None,
               "props": {"role": "shipped", "source-package": "grub2", "source-version": src_ver,
                         "upstream": f"upstream:gnu-grub@{up_ver}",
                         "grub-build-key": grub["key"],
                         "grub-build-info-sha256": manifest.get("build", {}).get("grub_build_info_sha256"),
                         "built-by": "build/grub/grubsrc.py (inputs: build/grub/source.lock.json, patches/, "
                                     "security-fixes.json)",
                         "toolchain": "; ".join(f"{k}: {info['toolchain'][k]}" for k in ("gcc", "ld", "bison")
                                                if k in info.get("toolchain", {})) or None,
                         "beast-booter-patches": [f"{p_['name']} sha256:{p_['sha256']}" for p_ in patches],
                         "security-fixes": [f"{f['id']}: {'present' if f['present'] else 'MISSING'} "
                                            f"({', '.join(evidence_label(e) for e in f['evidence'])}; {f['where']})"
                                            for f in fixes],
                         "sbat-claims": [f"{c['component']},{c['generation']} (SbatLevel {c['shim_sbat_level']}): "
                                         f"{'proven' if c['proven'] else 'NOT proven'}" for c in claims],
                         "vulnerability-tracking": (
                             f"purl: vendor beastboot, distro {grub_distro} (the series of the grub2 source package, "
                             "build/grub/source.lock.json), upstream=grub2-unsigned - Ubuntu's CVE "
                             "tracker records GRUB's state under grub2-unsigned (the source package of Ubuntu's EFI "
                             "GRUB, built from the same grub2 source), so scanners compare that data with our build "
                             f"version; the upstream:gnu-grub@{up_ver} component carries the CPE (NVD)")}})
        m.dep(root_ref, grub_ref, "CONTAINS")
        up = add_upstream("grub2", up_ver, None, of=f"grub2 {grub['version']} (source build)")
        m.dep(grub_ref, up, "DESCENDANT_OF")
        sref = f"deb-src:grub2@{src_ver}"
        m.add({"ref": sref, "kind": "source", "role": "shipped", "name": "grub2", "version": src_ver,
               "supplier": "Ubuntu", "license": "GPL-3.0-or-later",
               "license_source": "debian/copyright of the grub2 source package",
               "distribution": dsc["url"] if dsc else None,
               "hashes": {"SHA-256": dsc["sha256"]} if dsc else None,
               "description": f"Ubuntu grub2 {src_ver} source package (.dsc + orig + debian tarballs, SHA-256 in "
                              "build/grub/source.lock.json) that our GRUB is built from",
               "props": {"role": "shipped", "source-files": [f"{s['name']} sha256:{s['sha256']}"
                                                             for s in info.get("source", [])],
                         "vulnerability-tracking": f"on {grub_ref} (this exact source plus our patches); "
                                                   "no purl here so findings are not reported twice"}})
        m.dep(grub_ref, sref, "GENERATED_FROM")

    # ---- wimboot built from source (build/wimboot/wimbootsrc.py) ---------------------------
    # Our patched build (the file on the drive), DESCENDANT_OF upstream iPXE wimboot, whose
    # component carries the CPE (NVD names iPXE's projects with vendor "ipxe").
    wim = load_wimboot_build(root, manifest)
    wim_ref = None
    if wim:
        winfo = wim["info"] or {}
        wim_ref = f"wimboot-src:wimboot@{wim['version']}"
        if wim["note"]:
            m.notes.append(wim["note"])
        wup_ver = winfo.get("upstream_version") or wim["version"].split("+", 1)[0]
        tag = winfo.get("tag") or f"v{wup_ver}"
        wpatches = winfo.get("patches", [])
        m.add({"ref": wim_ref, "kind": "source-build", "role": "shipped", "name": "wimboot",
               "version": wim["version"], "purl": f"pkg:github/ipxe/wimboot@{quote(tag, safe='')}",
               "supplier": "beast-booter maintainers", "homepage": UPSTREAMS["wimboot"]["website"],
               "license": "GPL-2.0-or-later", "license_source": "wimboot LICENSE.txt and source headers",
               "description": (f"iPXE wimboot {wup_ver} built by beast-booter (build/wimboot/wimbootsrc.py) from "
                               f"the {tag} source archive plus {len(wpatches)} beast-booter patch(es); x86_64 "
                               "hybrid image (BIOS via GRUB linux16, UEFI via GRUB linux), unsigned"),
               "pedigree": {"patches": [{"type": "unofficial",
                                         "diff": {"url": f"build/wimboot/patches/{p_['name']}"}}
                                        for p_ in wpatches],
                            "notes": "build/wimboot/patches/series on top of the release tag; each patch says why"}
               if winfo else None,
               "props": {"role": "shipped", "upstream": f"upstream:ipxe-wimboot@{wup_ver}",
                         "source-commit": winfo.get("commit"),
                         "source-archive": (f"{winfo['source']['name']} sha256:{winfo['source']['sha256']}"
                                            if winfo.get("source") else None),
                         "wimboot-build-key": wim["key"],
                         "wimboot-build-info-sha256": manifest.get("build", {}).get("wimboot_build_info_sha256"),
                         "built-by": "build/wimboot/wimbootsrc.py (inputs: build/wimboot/source.lock.json, patches/)",
                         "toolchain": "; ".join(f"{k}: {winfo['toolchain'][k]}" for k in ("gcc", "ld")
                                                if k in winfo.get("toolchain", {})) or None,
                         "beast-booter-patches": [f"{p_['name']} sha256:{p_['sha256']}" for p_ in wpatches],
                         "sbat": (winfo.get("sbat") or "").strip().replace("\n", " ") or None,
                         "secure-boot": "not signed: the menu boots Windows only with Secure Boot off",
                         "vulnerability-tracking": (f"CPE on upstream:ipxe-wimboot@{wup_ver} (NVD vendor ipxe, "
                                                    f"product wimboot); the purl names the upstream tag {tag}")}})
        m.dep(root_ref, wim_ref, "CONTAINS")
        wup = add_upstream("wimboot", wup_ver, None, of=f"wimboot {wim['version']} (source build)")
        m.dep(wim_ref, wup, "DESCENDANT_OF")

    # ---- tooling (build / install / test) ---------------------------------------------------
    for name, role, used in TOOLING:
        p = pkgs.get(name) or resolve(name, None)
        if p is None:
            m.notes.append(f"tool package {name} not found on host or in .tools/debs")
            continue
        ref = add_pkg(p, m.items.get(f"deb:{p.name}@{p.version}", {}).get("role") or role, used)
        it = m.items[ref]
        if it["role"] == "shipped":
            it["props"]["also-build-tool"] = used
        elif role == "build":
            m.dep(ref, root_ref, "BUILD_TOOL_OF")
    known = {i["name"] for i in m.items.values() if i["kind"] == "package"}
    for d in sorted(debs_dir.glob("*.deb")) if debs_dir.is_dir() else []:
        p = deb.deb_fields(d)
        if p.name in known:
            continue
        known.add(p.name)
        ref = add_pkg(p, "test", "rootless test/dev toolchain (scripts/bootstrap-tools.sh, .tools/debs)")
        m.dep(ref, root_ref, "TEST_TOOL_OF")

    # ---- installer ------------------------------------------------------------------------
    imp = installer_imports(root)
    if not imp["stdlib_only"]:
        warn(f"installer imports non-stdlib modules: {imp['non_stdlib']}")
    inst_ref = f"beast-booter-installer@{version}"
    m.add({"ref": inst_ref, "kind": "installer", "role": "install", "name": "beast-booter-installer",
           "version": version, "license": "GPL-3.0-or-later", "license_source": "README.md + LICENSE",
           "description": "installer CLI (installer/beastbooter, bin/beast-booter): writes dist/ to a "
                          "drive; runs on the user's machine and is not copied to the drive",
           "props": {"role": "install", "python-stdlib-only": str(imp["stdlib_only"]).lower(),
                     "python-imports": " ".join(imp["modules"]),
                     "python-non-stdlib-imports": " ".join(imp["non_stdlib"]) or "none",
                     "python-stdlib-check": imp["checked_with"], "python-files": imp["files"],
                     "python-minimum": "3.10"}})
    m.dep(inst_ref, root_ref, "OTHER")
    for name in INSTALLER_TOOLS:
        for it in list(m.items.values()):
            if it["kind"] == "package" and it["name"] == name:
                m.dep(it["ref"], inst_ref, "RUNTIME_DEPENDENCY_OF")

    # ---- files ------------------------------------------------------------------------------
    member_hashes: dict = {}                    # cache for deb.verify_member
    certs: dict[str, dict] = {}
    efi_facts: dict[str, dict] = {}

    def pkg_ref(name: str, ver: str) -> str:
        return f"deb:{name}@{ver}"

    for rel in sorted(files):
        f = files[rel]
        o = f["origin"]
        fref = f"file:{rel}"
        item = {"ref": fref, "kind": "file", "role": "shipped", "name": rel, "sha256": f["sha256"],
                "sha1": f["sha1"], "size": f["size"], "origin": o["raw"],
                "props": {"origin": o["raw"], "size": f["size"], "origin-kind": o["kind"]}}
        if o["kind"] == "copied":
            d = o["debs"][0]
            p = pkgs[d["name"]]
            item["parent"] = pkg_ref(p.name, p.version)
            item["props"]["package-path"] = d["path"]
            if not d["path"]:
                item["props"]["origin-verified"] = f"MISMATCH: origin names no file inside {p.name}"
            else:
                item["props"]["origin-verified"] = deb.verify_member(dist / rel, p, d["path"], member_hashes)
            if item["props"]["origin-verified"].startswith("MISMATCH"):
                m.notes.append(f"{rel}: {item['props']['origin-verified']}")
                m.provenance_errors.append(f"{rel}: {item['props']['origin-verified']}")
            m.dep(fref, item["parent"], "CONTAINED_BY")
        elif o["kind"] == "grub-src":
            g = o["grub"][0] if o["grub"] else {}
            if grub_ref is None or g.get("version") != grub["version"] or not g.get("path"):
                item["props"]["origin-verified"] = "MISMATCH: origin names no file of the manifest's GRUB build"
            elif grub["info"] is None:
                item["props"]["origin-verified"] = f"UNVERIFIED: {grub['note']}"
            else:
                want = grub["info"]["files"].get(g["path"].lstrip("/"))
                item["props"]["origin-verified"] = (
                    f"sha256 matches build-info.json of GRUB build {grub['key']} ({g['path'].lstrip('/')})"
                    if want == f["sha256"] else
                    f"MISMATCH: differs from {g['path'].lstrip('/')} of GRUB build {grub['key']}")
                item["props"]["package-path"] = g["path"]
            if grub_ref:
                item["parent"] = grub_ref
                m.dep(fref, grub_ref, "CONTAINED_BY")
            if item["props"]["origin-verified"].startswith("MISMATCH"):
                m.notes.append(f"{rel}: {item['props']['origin-verified']}")
                m.provenance_errors.append(f"{rel}: {item['props']['origin-verified']}")
        elif o["kind"] == "wimboot-src":
            w = o["wimboot"][0] if o["wimboot"] else {}
            if wim_ref is None or w.get("version") != wim["version"]:
                item["props"]["origin-verified"] = "MISMATCH: origin names no file of the manifest's wimboot build"
            elif wim["info"] is None:
                item["props"]["origin-verified"] = f"UNVERIFIED: {wim['note']}"
            else:
                want = wim["info"]["files"].get(w["path"].lstrip("/"))
                item["props"]["origin-verified"] = (
                    f"sha256 matches build-info.json of wimboot build {wim['key']} ({w['path'].lstrip('/')})"
                    if want == f["sha256"] else
                    f"MISMATCH: differs from {w['path'].lstrip('/')} of wimboot build {wim['key']}")
                item["props"]["package-path"] = w["path"]
            if wim_ref:
                item["parent"] = wim_ref
                m.dep(fref, wim_ref, "CONTAINED_BY")
            if item["props"]["origin-verified"].startswith("MISMATCH"):
                m.notes.append(f"{rel}: {item['props']['origin-verified']}")
                m.provenance_errors.append(f"{rel}: {item['props']['origin-verified']}")
        elif o["kind"] == "built":
            item["props"]["built-from"] = o["raw"].removeprefix("built:")
            tools = []
            if "grub-mkimage" in o["raw"]:
                tools.append(manifest.get("build", {}).get("grub_mkimage", "grub-mkimage"))
            if o["signed_by_bb"]:
                tools.append(manifest.get("build", {}).get("sbsign", "sbsign"))
            item["props"]["built-with"] = tools
            for d in o["debs"]:
                m.dep(fref, pkg_ref(d["name"], d["version"]), "GENERATED_FROM")
            if grub_ref and any(g["version"] == grub["version"] for g in o["grub"]):
                m.dep(fref, grub_ref, "GENERATED_FROM")
                if rel.endswith("grubx64.efi"):
                    item["props"]["sbat-source"] = sb.get("sbat_source")
            if rel.endswith("grubx64.efi") and sbat_src:
                m.dep(fref, pkg_ref(sbat_src.group(1), sbat_src.group(2)), "GENERATED_FROM")
                item["props"]["sbat-source"] = sb.get("sbat_source")
            if RESIGNED_MARK in o["raw"] and o["debs"]:
                v = resigned_origin(dist / rel, pkgs[o["debs"][0]["name"]], o["debs"][0]["path"])
                item["props"]["origin-verified"] = v
                item["props"]["re-signed"] = ("the package's signature was removed and the file signed with the "
                                              "beast-booter key; the code (Authenticode digest) is unchanged")
                if v.startswith("MISMATCH"):
                    m.notes.append(f"{rel}: {v}")
                    m.provenance_errors.append(f"{rel}: {v}")
        elif o["kind"] == "local":
            item["props"]["provenance-warning"] = (
                "built from a local path outside the repository; not reproducible from the repo - "
                "rebuild dist/ from the repo's grub/ before release")
            m.notes.append(f"{rel}: origin {o['raw']} is outside the repository")
        elif o["kind"] in ("repo", "key"):
            item["props"]["origin-verified"] = verify_repo_origin(root, dist / rel, o["raw"])
            if not item["props"]["origin-verified"].startswith("sha256 matches"):
                m.notes.append(f"{rel}: {item['props']['origin-verified']}")
        if o["kind"] not in ("copied", "grub-src", "wimboot-src") or (o["kind"] == "grub-src" and grub_ref is None) \
                or (o["kind"] == "wimboot-src" and wim_ref is None):
            m.dep(root_ref, fref, "CONTAINS")
        # EFI binaries: SBAT, Authenticode, signers
        if rel.lower().endswith(".efi"):
            info = efi.inspect_efi(dist / rel)
            efi_facts[rel] = efi.public_view(info)
            item["props"].update({
                "efi-machine": info["machine"], "efi-nx-compat": str(info["nx_compat"]).lower(),
                "sbat": info["sbat"].strip() if info["sbat"] else "none",
                "authenticode-sha256": info["authenticode_sha256"]})
            if info["sbatlevel"]:
                item["props"]["shim-sbatlevel-previous"] = info["sbatlevel"]["previous"].strip().replace("\n", " ")
                item["props"]["shim-sbatlevel-latest"] = info["sbatlevel"]["latest"].strip().replace("\n", " ")
            signers = []
            for s in info["signatures"]:
                if "error" in s:
                    signers.append(s["error"])
                    continue
                signer = s["signer"] or {}
                chain = " <- ".join(c["cn"] for c in s["certificates"])
                signers.append(f"{signer.get('cn', '?')} (issuer {signer.get('issuer_cn', '?')}; "
                               f"{s['digest_algorithm']}; digest {'ok' if s['digest_matches_signature'] else 'MISMATCH'}; "
                               f"certs in signature: {chain})")
                for c, der in zip(s["certificates"], s["cert_der"]):
                    cref = f"cert:{c['sha256'][:16]}"
                    certs.setdefault(cref, c)
                    m.dep(fref, cref, "DEPENDS_ON")
            item["props"]["authenticode-signers"] = signers or ["unsigned"]
            if rel.endswith("grubx64.efi"):
                ok = (sb.get("sbat") or "").strip() == (info["sbat"] or "").strip()
                item["props"]["manifest-sbat-matches"] = str(ok).lower()
                if not ok:
                    m.notes.append("grubx64.efi .sbat differs from manifest.secure_boot.sbat")
        if rel.endswith(".cer"):
            c = efi.cert_info((dist / rel).read_bytes())
            cref = f"cert:{c['sha256'][:16]}"
            certs.setdefault(cref, c)
            m.dep(fref, cref, "DEPENDS_ON")
            item["props"]["certificate-sha256"] = c["sha256"]
            item["props"]["manifest-cert-matches"] = str(c["sha256"] == sb.get("cert_sha256")).lower()
        # Linux kernel images (beast-net): the kernel itself as a component, with the identity
        # syft derives from the bzImage header (pkg:generic/linux-kernel@<release>).
        kv = kernel_version_string(dist / rel) if o["kind"] == "copied" or RESIGNED_MARK in o["raw"] else None
        if kv:
            release = kv.split()[0]
            p = pkgs[o["debs"][0]["name"]]
            kref = f"kernel:linux-kernel@{release}"
            srcs = [f"deb-src:{n}@{v}" for n, v in p.built_using if n == "linux" or n.startswith("linux-")]
            srcs = [r for r in srcs if r in m.items] or ([f"deb:{p.name}@{p.version}"] if p.source == "linux" else [])
            m.add({"ref": kref, "kind": "upstream", "role": "shipped", "parent": pkg_ref(p.name, p.version),
                   "name": "linux-kernel", "version": release, "purl": f"pkg:generic/linux-kernel@{release}",
                   "supplier": "Canonical Ltd. (Ubuntu kernel team)", "homepage": "https://www.kernel.org/",
                   "vcs": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                   "license": "GPL-2.0-only", "license_source": "Linux kernel COPYING",
                   "description": f"Linux kernel {release} (Ubuntu build of upstream Linux "
                                  f"{'.'.join(release.split('.')[:2])}) in {rel}",
                   "props": {"role": "shipped", "kernel-version-string": kv, "identified-by":
                             "x86 boot protocol header kernel_version string (syft's linux-kernel cataloger "
                             "reports the same purl)",
                             "vulnerability-tracking": (
                                 f"via {', '.join(srcs) or 'the Ubuntu linux source package'}: Ubuntu backports "
                                 "fixes without changing the upstream version, so this component carries no CPE "
                                 "(NVD ranges for upstream Linux would not apply)")}})
            m.dep(fref, kref, "CONTAINS")
            for r in srcs:
                m.dep(kref, r, "GENERATED_FROM")
            item["props"]["linux-kernel-release"] = release
        m.add(item)

    for cref, c in sorted(certs.items()):
        m.add({"ref": cref, "kind": "cert", "role": "shipped", "name": c["cn"], "cert": c,
               "props": {"role": "shipped", "certificate-sha256": c["sha256"], "certificate-sha1": c["sha1"],
                         "subject": c["subject"], "issuer": c["issuer"], "serial": c["serial"],
                         "key": f"{c['key_algorithm']} {c['key_bits']}",
                         "extended-key-usage": c["extended_key_usage"] or "none"}})
    if runtimes is not None and runtimes.is_file():
        add_portable_runtimes(m, root, runtimes, version, root / ".tools" / "cache" / "pbs")
    return m, {"manifest": manifest, "efi": efi_facts, "license_refs": license_refs,
               "installer": imp, "files": files}


# =========================================================================== CycloneDX


def to_cyclonedx(m: Model, ctx: dict, distro: str, osr: dict) -> dict:
    man = ctx["manifest"]
    ts = dt.datetime.fromtimestamp(int(man["source_date_epoch"]), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = next(i for i in m.items.values() if i["kind"] == "root")

    def lic(i):
        e = i.get("license")
        if not e or e == "NOASSERTION":
            return None
        return [{"expression": e, "acknowledgement": "declared"}]

    def comp(i: dict) -> dict:
        c: dict = {"type": {"package": "application", "upstream": "application", "source": "application",
                            "installer": "application", "root": "application", "file": "file",
                            "portable": "application", "runtime": "application", "runtime-lib": "library",
                            "source-build": "application", "cert": "cryptographic-asset"}[i["kind"]],
                   "bom-ref": i["ref"]}
        if i.get("supplier"):
            c["supplier"] = {"name": i["supplier"]}
            if i.get("supplier_email"):
                c["supplier"]["contact"] = [{"email": i["supplier_email"]}]
        if i.get("group"):
            c["group"] = i["group"]
        c["name"] = i["name"]
        if i.get("version"):
            c["version"] = i["version"]
        if i.get("description"):
            c["description"] = i["description"]
        if i["kind"] == "file":
            c["hashes"] = [{"alg": "SHA-256", "content": i["sha256"]}, {"alg": "SHA-1", "content": i["sha1"]}]
        elif i.get("hashes"):
            c["hashes"] = [{"alg": k, "content": v} for k, v in sorted(i["hashes"].items())]
        if i["kind"] != "root":
            c["scope"] = "required" if i.get("role") in SHIPPED_ROLES else "excluded"
        lc = lic(i)
        if lc:
            c["licenses"] = lc
        if i.get("cpe"):
            c["cpe"] = i["cpe"]
        if i.get("purl"):
            c["purl"] = i["purl"]
        refs = []
        if i.get("homepage"):
            refs.append({"type": "website", "url": i["homepage"]})
        if i.get("vcs"):
            refs.append({"type": "vcs", "url": i["vcs"]})
        if i.get("distribution"):
            refs.append({"type": "distribution", "url": i["distribution"]})
        if refs:
            c["externalReferences"] = refs
        if i.get("pedigree"):
            c["pedigree"] = i["pedigree"]
        if i["kind"] == "cert":
            ce = i["cert"]
            c["cryptoProperties"] = {"assetType": "certificate", "certificateProperties": {
                "subjectName": ce["subject"], "issuerName": ce["issuer"],
                "notValidBefore": ce["not_before"], "notValidAfter": ce["not_after"],
                "certificateFormat": "X.509", "certificateExtension": "der"}}
        pr = dict(i.get("props", {}))
        if i.get("license") == "NOASSERTION":
            pr["license"] = f"NOASSERTION ({i.get('license_source')})"
        if pr:
            c["properties"] = props(pr)
        return c

    top, children = [], {}
    for ref in sorted(m.items):
        i = m.items[ref]
        if i["kind"] == "root":
            continue
        if i.get("parent"):
            children.setdefault(i["parent"], []).append(comp(i))
        else:
            top.append(comp(i))
    def nest(cs: list[dict]) -> None:
        for c in cs:
            if c["bom-ref"] in children:
                c["components"] = children[c["bom-ref"]]
                nest(c["components"])
    nest(top)
    # CycloneDX "dependsOn": forward relationships as-is; RUNTIME_DEPENDENCY_OF reversed
    # (the installer depends on mkfs.* etc.). Build/test tooling is described by
    # `formulation` below instead, so it never looks like a runtime dependency.
    fwd: dict[str, set] = {ref: set() for ref in m.items}
    for a, lst in m.deps.items():
        for b, rel in lst:
            if rel in ("DEPENDS_ON", "CONTAINS", "GENERATED_FROM", "DESCENDANT_OF", "CONTAINED_BY"):
                fwd[a].add(b)
            elif rel == "RUNTIME_DEPENDENCY_OF":
                fwd[b].add(a)
    deps = [{"ref": ref, "dependsOn": sorted(fwd[ref])} for ref in sorted(m.items)]

    def workflow(uid: str, name: str, ttype: str, refs: list[str], desc: str) -> dict:
        return {"bom-ref": f"workflow:{uid}", "uid": uid, "name": name, "description": desc,
                "taskTypes": [ttype], "resourceReferences": [{"ref": r} for r in sorted(refs)]}
    def by_rel(rel: str) -> list[str]:
        return [a for a, lst in m.deps.items() for b, r in lst if r == rel]
    inst = [i["ref"] for i in m.items.values() if i["kind"] == "installer"]
    formulation = [{"bom-ref": "formula:beast-booter", "workflows": [
        workflow("make-build", "make build (build/build.sh)", "build",
                 by_rel("BUILD_TOOL_OF") + by_rel("BUILD_DEPENDENCY_OF") +
                 [i["ref"] for i in m.items.values() if i.get("props", {}).get("also-build-tool")],
                 "Builds dist/ from Ubuntu packages, Debian's shim packages and repo files; signs grubx64.efi "
                 "and the beast-net helper kernel with the beast-booter key."),
        workflow("install", "beast-booter install / update (installer)", "deploy",
                 inst + by_rel("RUNTIME_DEPENDENCY_OF"),
                 "Partitions and formats a drive and copies dist/ onto it."),
        workflow("make-e2e", "make e2e (tests/e2e)", "test", by_rel("TEST_TOOL_OF"),
                 "Boots test images in rootless QEMU (SeaBIOS, OVMF, OVMF + Secure Boot)."),
    ]}]
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "beast-booter-sbom:" + root["props"]["manifest-sha256"] + ":" +
                        hashlib.sha256(json.dumps(top, sort_keys=True).encode()).hexdigest())
    meta_props = {"distro": distro, "build-host-os": osr.get("PRETTY_NAME"),
                  "build-host-os-codename": osr.get("VERSION_CODENAME"),
                  "sbom-scope": "shipped = every file under dist/ (what the installer writes to the drive) and, "
                                "with role portable, the runtimes bundled in the portable packages; "
                                "scope=excluded components are build/install/test tooling, not on the drive",
                  "notes": m.notes}
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{serial}", "version": 1,
        "metadata": {
            "timestamp": ts,
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "group": "beast-booter", "name": TOOL_NAME,
                                      "version": TOOL_VERSION}]},
            "authors": [{"name": "beast-booter maintainers"}],
            "component": comp(root),
            "properties": props(meta_props),
        },
        "components": top,
        "dependencies": deps,
        "formulation": formulation,
    }


# =========================================================================== SPDX


def to_spdx(m: Model, ctx: dict, distro: str, cdx: dict) -> dict:
    man = ctx["manifest"]
    ts = cdx["metadata"]["timestamp"]
    used: set = set()
    ids: dict[str, str] = {}
    root = next(i for i in m.items.values() if i["kind"] == "root")
    for ref in sorted(m.items):
        i = m.items[ref]
        if i["kind"] == "cert":
            continue
        prefix = {"file": "File", "root": "Package"}.get(i["kind"], "Package")
        ids[ref] = spdx_id(prefix, ref.replace(":", "-").replace("@", "-"), used)
    packages, files_out, rels = [], [], []

    def comment(i):
        pr = i.get("props", {})
        parts = []
        for k, v in pr.items():
            if v in (None, "", []):
                continue
            parts.append(f"{k}: {'; '.join(map(str, v)) if isinstance(v, list) else v}")
        return "\n".join(parts) or None

    for ref in sorted(m.items):
        i = m.items[ref]
        if i["kind"] == "cert":
            continue
        sid = ids[ref]
        if i["kind"] == "file":
            ftype = "BINARY" if re.search(r"\.(efi|img|mod|pf2|cer)$", i["name"], re.I) else "TEXT"
            f = {"SPDXID": sid, "fileName": "./" + i["name"],
                 "checksums": [{"algorithm": "SHA1", "checksumValue": i["sha1"]},
                               {"algorithm": "SHA256", "checksumValue": i["sha256"]}],
                 "fileTypes": [ftype], "licenseConcluded": "NOASSERTION",
                 "copyrightText": "NOASSERTION"}
            c = comment(i)
            if c:
                f["comment"] = c
            files_out.append(f)
            continue
        lic = i.get("license") or "NOASSERTION"
        supplier = "NOASSERTION"
        if i.get("supplier"):
            supplier = f"Organization: {i['supplier']}" + (f" ({i['supplier_email']})" if i.get("supplier_email") else "")
        elif i["kind"] in ("root", "installer", "portable"):
            supplier = "Organization: beast-booter maintainers"
        p = {"SPDXID": sid, "name": i["name"], "versionInfo": i.get("version") or "NOASSERTION",
             "supplier": supplier, "downloadLocation": i.get("distribution") or "NOASSERTION",
             "filesAnalyzed": False,
             "licenseConcluded": "NOASSERTION", "licenseDeclared": lic, "copyrightText": "NOASSERTION",
             "primaryPackagePurpose": ("OPERATING_SYSTEM" if ref.startswith("kernel:") else
                                       {"source": "SOURCE", "upstream": "SOURCE", "runtime-lib": "LIBRARY"}
                                       .get(i["kind"], "APPLICATION"))}
        if i.get("homepage"):
            p["homepage"] = i["homepage"]
        if i.get("hashes"):
            p["checksums"] = [{"algorithm": k.replace("-", ""), "checksumValue": v}
                              for k, v in sorted(i["hashes"].items())]
        if i.get("description"):
            p["description"] = i["description"]
        if i.get("props", {}).get("source-package"):
            p["sourceInfo"] = (f"built from source package {i['props']['source-package']} "
                               f"{i['props'].get('source-version', '')}").strip()
        ext = []
        if i.get("purl"):
            ext.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                        "referenceLocator": i["purl"]})
        if i.get("cpe"):
            ext.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                        "referenceLocator": i["cpe"]})
        if ext:
            p["externalRefs"] = ext
        c = comment(i)
        if c:
            p["comment"] = c
        packages.append(p)

    rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                 "relatedSpdxElement": ids[root["ref"]]})
    for a in sorted(m.deps):
        if a not in ids:
            continue
        for b, rel in m.deps[a]:
            if b not in ids:
                continue
            if rel == "GENERATED_FROM":
                # same fact as "b GENERATES a"; syft's SPDX reader drops GENERATED_FROM
                # targets as if they were source packages, which would hide them from grype
                r = {"spdxElementId": ids[b], "relationshipType": "GENERATES", "relatedSpdxElement": ids[a]}
            else:
                r = {"spdxElementId": ids[a], "relationshipType": rel, "relatedSpdxElement": ids[b]}
            if rel == "OTHER":
                r["comment"] = "the installer writes these boot files to a drive"
            rels.append(r)
    # certificates are not SPDX 2.3 elements; record them on the files instead (comments above)
    ext_lic = [{"licenseId": k, "name": k.removeprefix("LicenseRef-DEP5-"), "extractedText": v}
               for k, v in sorted(ctx["license_refs"].items())]
    doc = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"beast-booter-{man['version']}",
        "documentNamespace": (f"https://beast-booter.invalid/spdx/beast-booter-{man['version']}-"
                              f"{man.get('build_id', 'nobuildid')}-{cdx['serialNumber'].rsplit(':', 1)[1]}"),
        "creationInfo": {"created": ts, "creators": [f"Tool: {TOOL_NAME.replace(' ', '-')}-{TOOL_VERSION}",
                                                     "Organization: beast-booter maintainers"],
                         "comment": f"Same inventory as beast-booter.cdx.json ({cdx['serialNumber']}). "
                                    f"Distro: {distro}. Signing certificates are listed as CycloneDX "
                                    "cryptographic-asset components; here they appear in file comments."},
        "packages": packages, "files": files_out, "relationships": rels,
    }
    if ext_lic:
        doc["hasExtractedLicensingInfos"] = ext_lic
    return doc


# =========================================================================== main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent), help="repository root")
    ap.add_argument("--dist", help="dist directory (default: ROOT/dist)")
    ap.add_argument("--out", help="output directory (default: ROOT/sbom)")
    ap.add_argument("--distro", help="purl distro qualifier (default: from /etc/os-release, e.g. ubuntu-26.04)")
    ap.add_argument("--runtimes-lock", help="portable runtimes lock (default: ROOT/packaging/portable/runtimes.lock)")
    ap.add_argument("--no-runtimes", action="store_true", help="leave the portable runtimes out")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    dist = Path(a.dist).resolve() if a.dist else root / "dist"
    out = Path(a.out).resolve() if a.out else root / "sbom"
    osr = os_release()
    distro = a.distro or f"{osr.get('ID', 'ubuntu')}-{osr.get('VERSION_ID', '')}"
    spdx_ids = deb.load_spdx_ids(root / ".tools/cache/schemas/cyclonedx-1.6/spdx.schema.json")

    runtimes = None if a.no_runtimes else (Path(a.runtimes_lock).resolve() if a.runtimes_lock
                                           else root / "packaging" / "portable" / "runtimes.lock")
    model, ctx = build_model(root, dist, distro, spdx_ids, runtimes)
    cdx = to_cyclonedx(model, ctx, distro, osr)
    spdx = to_spdx(model, ctx, distro, cdx)
    out.mkdir(parents=True, exist_ok=True)
    (out / "beast-booter.cdx.json").write_text(json.dumps(cdx, indent=2, sort_keys=False) + "\n")
    (out / "beast-booter.spdx.json").write_text(json.dumps(spdx, indent=2, sort_keys=False) + "\n")

    kinds: dict[str, int] = {}
    for i in model.items.values():
        key = f"{i['kind']}/{i.get('role', '-')}"
        kinds[key] = kinds.get(key, 0) + 1
    print(f"gen_sbom: wrote {out / 'beast-booter.cdx.json'} and {out / 'beast-booter.spdx.json'}")
    print("gen_sbom: components: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"gen_sbom: installer stdlib-only: {ctx['installer']['stdlib_only']} "
          f"({ctx['installer']['files']} files; non-stdlib: {ctx['installer']['non_stdlib'] or 'none'})")
    for n in model.notes:
        print(f"gen_sbom: note: {n}")
    for e in model.provenance_errors:
        print(f"gen_sbom: PROVENANCE ERROR: {e}", file=sys.stderr)
    if model.provenance_errors:
        print(f"gen_sbom: {len(model.provenance_errors)} shipped file(s) are not byte-identical to the package "
              "file their manifest origin names; recorded as MISMATCH in beast-booter:origin-verified "
              "(validate_sbom.py fails, scan_vulns.py reports BB-ORIGIN-MISMATCH)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
