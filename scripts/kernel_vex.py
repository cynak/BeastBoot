#!/usr/bin/env python3
"""OpenVEX statements for beast-net kernel CVEs: not_affected (code not on the drive) or fixed.

    python3 -I scripts/kernel_vex.py [--root DIR] [--offline] [--refresh] [--tracker-severity SEV]

beast-net boots Ubuntu's signed kernel (dist/esp/beast-net/vmlinuz) with a SUBSET of its
modules in dist/esp/beast-net/initrd.img (build/beastnet/modules.list). The scanner lists
every Ubuntu linux CVE against it. For each kernel finding in sbom/vulnerabilities.json
(whatever its current VEX status) this script decides whether the fixed code is on the drive:

  1. files: "programFiles" of the kernel CNA's CVE record
     (git.kernel.org/pub/scm/linux/security/vulns.git, cve/published/<year>/<id>.json);
  2. how Ubuntu builds each file, from Ubuntu's exact source (linux_<v>.orig.tar.gz +
     linux_<v>-<r>.diff.gz from Launchpad, SHA-256 checked) and the shipped config
     (/boot/config-<kver> in the linux-modules .deb): the Kbuild files are evaluated
     (obj-y / obj-m / lib-y, composite objects, subdirectory descent, conditionals; an
     unknown condition runs both branches, so the result over-approximates what is built);
     a file #included by other files takes the state of its includers;
  3. built in -> present; built into module M -> present only when M.ko is in the
     initramfs; not compiled (config unset, directory never reached, other architecture,
     Documentation/, tools/) -> not present.

A CVE gets not_affected / vulnerable_code_not_present only when EVERY listed file is not
present. Anything not provable stays open: files absent from the 7.0 tree, references the
evaluator cannot explain (rules, recipes, non-kbuild variables, $(build)= descents), dirs
whose module set disagrees with modules.order / modules.builtin (self-check), headers with
an includer that is present or unknown, scripts/ and the build-time tools under tools/
(objtool, resolve_btfids and their libraries: they rewrite the shipped objects). A final
check reads the source paths (__FILE__ of WARN/BUG/dynamic-debug sites) out of the shipped
vmlinuz and initramfs modules: a file found there is never declared not present.

A CVE gets fixed (the evidence in status_notes; takes precedence over not_affected) when the
shipped kernel contains its fix:
  a. kernel CNA record: the mainline fix (original_commit_for_fix X.Y) is in an earlier release
     than the upstream base of Ubuntu's source (its top-level Makefile VERSION.PATCHLEVEL.SUBLEVEL
     EXTRAVERSION; Ubuntu's stable updates bump SUBLEVEL), or in release X.Y itself when the base
     is X.Y[.z] (not when it is X.Y-rcN), or the base's own stable branch X.Y.* is fixed at a
     version <= the base;
  b. Ubuntu's CVE tracker (asked only about CVEs still open): linux in the series the SBOM purl
     names (distro=ubuntu-YY.MM, matched to the Launchpad series that publishes this version in
     a released pocket - never -proposed) is "released" or "not-affected" at a version <= the
     shipped one. A status without a version is not used.

Writes sbom/vex.kernel.openvex.json (OpenVEX 0.2.0) and sbom/kernel-vex-report.json (every
kernel CVE: not_present / present / unresolved + evidence, fix evidence, vex_status, the
critical/high ones still open). Caches .tools/cache/kernel-vex/ (Ubuntu tracker answers 24 h).
Deterministic: the timestamp is SOURCE_DATE_EPOCH, else the kernel config's date in the .deb.
"""
from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import lzma
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
VULNS_GIT = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
LP_UBUNTU = "https://api.launchpad.net/devel/ubuntu"
LP_API = LP_UBUNTU + "/+archive/primary"
UBUNTU_CVE = "https://ubuntu.com/security/cves/{id}.json"
INDEX_FORMAT = 4
# CVEs without a kernel CNA record that describe another vendor's kernel patches. Each claim is
# checked on every run against the shipped kernel config and Ubuntu's source (the index keeps
# these files); if any config value or source pattern does not hold, the CVE stays open.
VENDOR_SPECIFIC = {
    "CVE-2025-1272": {
        "about": "Fedora Linux kernels from 6.12 on left lockdown disabled when booted with Secure Boot (CVE: "
                 "'affects only Fedora Linux'; Ubuntu's tracker, upstream: 'Red Hat specific lockdown regression')",
        "config": {"CONFIG_SECURITY_LOCKDOWN_LSM": "y", "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY": "y",
                   "CONFIG_LOCK_DOWN_IN_SECURE_BOOT": "y"},
        "source": {"arch/x86/kernel/setup.c": r'security_lock_kernel_down\("EFI Secure Boot mode", '
                                              r'LOCKDOWN_INTEGRITY_MAX\)'},
        "holds": "the shipped kernel locks itself down (integrity) when it is booted with EFI Secure Boot",
    },
    "CVE-2015-7837": {
        "about": "The kernel of Red Hat Enterprise Linux 7, kernel-rt and MRG 2 (Red Hat's securelevel patches) "
                 "mishandled the secure_boot flag across a kexec reboot",
        "config": {"CONFIG_SECURITY_LOCKDOWN_LSM": "y", "CONFIG_LOCK_DOWN_IN_SECURE_BOOT": "y",
                   "CONFIG_KEXEC_SIG": "y", "CONFIG_KEXEC_BZIMAGE_VERIFY_SIG": "y"},
        "source": {"arch/x86/kernel/kexec-bzimage64.c": r"params->secure_boot = boot_params\.secure_boot;",
                   "kernel/kexec.c": r"security_locked_down\(LOCKDOWN_KEXEC\)",
                   "kernel/kexec_file.c": r"security_locked_down\(LOCKDOWN_KEXEC\)"},
        "holds": "under Secure Boot the shipped kernel is locked down (lockdown LSM, not securelevel), which "
                 "refuses kexec_load and requires a signed image for kexec_file_load, and kexec_file_load hands "
                 "the secure_boot flag to the next kernel",
    },
}
EVIDENCE_FILES = {p for v in VENDOR_SPECIFIC.values() for p in v["source"]}
ARCH = "x86"
VEX_ID = "https://beast-boot.invalid/vex/beast-boot-kernel"
UNK = "\x01?\x01"          # marker for a value the evaluator cannot know

CODE_EXT = {".c", ".S", ".s", ".rs"}
INCLUDABLE_EXT = {".h", ".inc", ".lds", ".tbl", ".uc", ".x"}
SCAN_EXT = {".c", ".h", ".S", ".s", ".inc", ".lds", ".y", ".l", ".cpp", ".cc", ".tbl", ".uc", ".x"}
MAKEFILE_RE = re.compile(r"^(Makefile|Kbuild)(\..+)?$|\.(mk|include|rules)$")
INCLUDE_RE = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]', re.M)
# tools/ code that runs at kernel build time and rewrites vmlinux/modules (objtool,
# resolve_btfids and their libraries): its bugs can end up in the shipped binaries
TOOLS_BUILD = ("tools/objtool/", "tools/bpf/resolve_btfids/", "tools/lib/", "tools/include/", "tools/arch/",
               "tools/build/", "tools/scripts/")
ENV = {"ARCH": ARCH, "SRCARCH": ARCH, "SUBARCH": ARCH, "BITS": "64", "KBUILD_EXTMOD": "",
       "KBUILD_BUILTIN": "y", "KBUILD_MODULES": "y", "srctree": "@T", "objtree": "@T", "srcroot": "@T", "KBUILD_SRC": "", "quiet": "", "Q": "",
       "MAKE": "make", "space": " ", "comma": ",", "empty": "", "pound": "#", "squote": "'"}
# kbuild variables that collect objects to build (see scripts/Makefile.build / .lib)
LIST_BASE_EXCLUDE = {"always", "extra", "targets", "hostprogs", "userprogs", "userprogs-always",
                     "hostprogs-always", "ccflags", "asflags", "ldflags", "subdir-ccflags",
                     "subdir-asflags", "clean-files", "clean-dirs", "no-clean-files", "header-test",
                     "dtb", "dtbo", "dtc", "always-y", "rustflags", "subdir-rustflags"}
FUNCS = {"subst", "patsubst", "strip", "findstring", "filter", "filter-out", "sort", "word",
         "wordlist", "words", "firstword", "lastword", "dir", "notdir", "suffix", "basename",
         "addsuffix", "addprefix", "join", "wildcard", "realpath", "abspath", "if", "or", "and",
         "foreach", "call", "value", "origin", "flavor", "shell", "error", "warning", "info",
         "eval", "file", "guile", "let", "intcmp"}


def log(msg: str) -> None:
    print(f"kernel_vex: {msg}", file=sys.stderr, flush=True)


class Fail(Exception):
    pass


# ============================================================================ downloads
def http_get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "beast-boot-kernel-vex/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except OSError as e:
        raise Fail(f"{url}: {e} (use --offline with a warm cache)") from e


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, sha256: str) -> None:
    tmp = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "beast-boot-kernel-vex/1"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    except OSError as e:
        raise Fail(f"{url}: {e}") from e
    got = sha256_file(tmp)
    if got != sha256:
        tmp.unlink()
        raise Fail(f"{url}: SHA-256 {got} != {sha256}")
    os.replace(tmp, dest)


# ============================================================================ .deb / initrd
def ar_members(path: Path):
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise Fail(f"{path}: not an ar archive")
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                return
            name = hdr[:16].decode().strip().rstrip("/")
            size = int(hdr[48:58].decode().strip())
            data = f.read(size)
            if size % 2:
                f.read(1)
            yield name, data


def deb_files(deb: Path, wanted: set[str]) -> tuple[dict[str, bytes], dict[str, int]]:
    """Contents and mtimes of WANTED paths (without leading ./) in an uncompressed or xz/gz data.tar."""
    for name, data in ar_members(deb):
        if not name.startswith("data.tar"):
            continue
        if name.endswith(".zst"):
            raise Fail(f"{deb}: zstd data member (needs Python 3.14 compression.zstd)")
        mode = "r:xz" if name.endswith(".xz") else "r:gz" if name.endswith(".gz") else "r:"
        out, mt = {}, {}
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as t:
            for m in t:
                n = m.name[2:] if m.name.startswith("./") else m.name
                if n in wanted and m.isfile():
                    out[n] = t.extractfile(m).read()
                    mt[n] = int(m.mtime)
        return out, mt
    raise Fail(f"{deb}: no data.tar member")


def initrd_modules(path: Path) -> tuple[str, list[str]]:
    """(kernel version, sorted module paths kernel/...ko) of an xz-compressed newc cpio."""
    raw = path.read_bytes()
    data = lzma.decompress(raw) if raw[:6] == b"\xfd7zXZ\x00" else raw
    off, mods, kvers = 0, [], set()
    while off + 110 <= len(data):
        if data[off] == 0:
            off += 1
            continue
        if data[off:off + 6] not in (b"070701", b"070702"):
            raise Fail(f"{path}: bad cpio header at {off}")
        fsize = int(data[off + 54:off + 62], 16)
        nsize = int(data[off + 94:off + 102], 16)
        name = data[off + 110:off + 110 + nsize - 1].decode()
        off = (off + 110 + nsize + 3) & ~3
        off = (off + fsize + 3) & ~3
        m = re.match(r"(?:usr/)?lib/modules/([^/]+)/(kernel/.+\.ko)(?:\.(?:zst|xz|gz))?$", name)
        if m:
            kvers.add(m.group(1))
            mods.append(m.group(2))
    if len(kvers) != 1:
        raise Fail(f"{path}: expected modules of one kernel, found {sorted(kvers)}")
    return kvers.pop(), sorted(set(mods))


PATH_STR_RE = re.compile(rb"(?<![A-Za-z0-9_./+-])((?:arch|block|certs|crypto|drivers|fs|include|init|io_uring|ipc|"
                         rb"kernel|lib|mm|net|rust|samples|security|sound|ubuntu|usr|virt)/[A-Za-z0-9_./+-]+"
                         rb"\.(?:c|h|rs|S))(?![A-Za-z0-9_])")


def decompress_any(data: bytes) -> bytes | None:
    """xz / gzip / zstd (Python 3.14 compression.zstd or the zstd tool); None if impossible."""
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMADecompressor().decompress(data)
    if data[:3] == b"\x1f\x8b\x08":
        return gzip.GzipFile(fileobj=io.BytesIO(data)).read()
    if data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd   # Python >= 3.14
            return zstd.ZstdDecompressor().decompress(data)
        except ImportError:
            pass
        if shutil.which("zstd"):
            r = subprocess.run(["zstd", "-dcq"], input=data, capture_output=True)
            return r.stdout or None
        return None
    return data


def binary_paths(vmlinuz: Path, initrd: Path) -> dict:
    """Source paths (__FILE__ of WARN/BUG/dynamic-debug sites) in the shipped vmlinux and in the
    modules of the initramfs - an independent check: a file found there is on the drive."""
    img = vmlinuz.read_bytes()
    kpaths: set[str] = set()
    for magic in (b"\x28\xb5\x2f\xfd", b"\xfd7zXZ\x00", b"\x1f\x8b\x08"):
        i = img.find(magic)
        if i >= 0:
            try:
                raw = decompress_any(img[i:])
            except (lzma.LZMAError, OSError, EOFError, ValueError):
                raw = None
            if raw and len(raw) > len(img):
                kpaths = {m.decode() for m in PATH_STR_RE.findall(raw)}
                break
    data = initrd.read_bytes()
    data = lzma.decompress(data) if data[:6] == b"\xfd7zXZ\x00" else data
    mpaths: dict[str, list[str]] = {}
    off, undecoded = 0, 0
    while off + 110 <= len(data):
        if data[off] == 0:
            off += 1
            continue
        fsize = int(data[off + 54:off + 62], 16)
        nsize = int(data[off + 94:off + 102], 16)
        name = data[off + 110:off + 110 + nsize - 1].decode()
        o2 = (off + 110 + nsize + 3) & ~3
        body = data[o2:o2 + fsize]
        off = (o2 + fsize + 3) & ~3
        if re.search(r"\.ko(\.(zst|xz|gz))?$", name):
            raw = decompress_any(body)
            if raw is None:
                undecoded += 1
                continue
            for m in set(PATH_STR_RE.findall(raw)):
                mpaths.setdefault(m.decode(), []).append(posixpath.basename(name).split(".ko")[0] + ".ko")
    return {"vmlinux": sorted(kpaths), "modules": {k: sorted(v) for k, v in sorted(mpaths.items())},
            "undecoded_modules": undecoded}


# ============================================================================ unified diff
def parse_diff(text: str) -> dict[str, list]:
    """{path: [(old_start, old_len, new_start, new_len, [lines])]} of a dpkg-source diff."""
    files: dict[str, list] = {}
    cur = None
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            path = lines[i + 1][4:].split("\t")[0]
            path = path.split("/", 1)[1] if "/" in path else path
            cur = files.setdefault(path, [])
            i += 2
            continue
        m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", ln)
        if m and cur is not None:
            os_, ol, ns, nl = int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)
            body = []
            a = b = 0
            i += 1
            while i < len(lines) and (a < ol or b < nl or (i < len(lines) and lines[i].startswith("\\"))):
                x = lines[i]
                if x.startswith("\\"):
                    body.append(x)
                elif x[:1] == " " or x == "":
                    body.append(" " + x[1:])
                    a += 1
                    b += 1
                elif x[:1] == "-":
                    body.append(x)
                    a += 1
                elif x[:1] == "+":
                    body.append(x)
                    b += 1
                else:
                    break
                i += 1
            cur.append((os_, ol, ns, nl, body))
            continue
        i += 1
    return files


def apply_hunks(path: str, orig: str | None, hunks: list) -> str | None:
    """Patched text (None = deleted). Exact application; raises on mismatch."""
    parts = (orig or "").split("\n")    # not splitlines(): latin-1 text may contain \x85
    old = [x + "\n" for x in parts[:-1]] + ([parts[-1]] if parts[-1] else [])
    out: list[str] = []
    pos = 0
    for os_, ol, _ns, nl, body in hunks:
        start = os_ - 1 if ol else os_
        if start < pos or start > len(old):
            raise Fail(f"diff: {path}: hunk at {os_} out of range")
        out.extend(old[pos:start])
        pos = start
        for x in body:
            if x.startswith("\\"):
                if out and out[-1].endswith("\n"):
                    out[-1] = out[-1][:-1]
                continue
            tag, s = x[0], x[1:] + "\n"
            if tag in " -":
                if pos >= len(old) or old[pos].rstrip("\n") != s.rstrip("\n"):
                    raise Fail(f"diff: {path}: context mismatch at line {pos + 1}")
                if tag == " ":
                    out.append(old[pos])
                pos += 1
            else:
                out.append(s)
    out.extend(old[pos:])
    if hunks and all(h[3] == 0 for h in hunks) and not out:
        return None
    return "".join(out)


def includes_of(data: bytes) -> list[str]:
    return [("q:" if m.group(1) == b'"' else "a:") + m.group(2).decode("latin-1").strip()
            for m in INCLUDE_RE.finditer(data)]


# ============================================================================ source index
class Tree:
    """File list, Kbuild files and #include directives of one kernel source tree."""

    def __init__(self, files: set[str], makefiles: dict[str, str], includes: dict[str, list[str]]):
        self.files = files
        self.makefiles = makefiles
        self.includes = includes
        self.dirs: set[str] = set()
        for f in files:
            d = posixpath.dirname(f)
            while d and d not in self.dirs:
                self.dirs.add(d)
                d = posixpath.dirname(d)
        self._rev: dict[str, list[tuple[str, str, str]]] | None = None

    def rev(self) -> dict[str, list[tuple[str, str, str]]]:
        if self._rev is None:
            r: dict[str, list] = {}
            for f, incs in self.includes.items():
                for inc in incs:
                    kind, t = inc[0], inc[2:]
                    r.setdefault(posixpath.basename(t), []).append((f, kind, t))
            self._rev = r
        return self._rev

    def includers(self, h: str) -> list[str]:
        """Files whose #include may resolve to H (over-approximation, except that a quoted
        include resolves to the includer's own directory when that file exists)."""
        out = set()
        other_arch = re.match(r"arch/([^/]+)/", h)
        other_arch = other_arch.group(1) if other_arch and other_arch.group(1) != ARCH else None
        for f, kind, t in self.rev().get(posixpath.basename(h), []):
            if f == h:
                continue
            nt = posixpath.normpath(t)
            if kind == "q":
                local = posixpath.normpath(posixpath.join(posixpath.dirname(f), t))
                if local in self.files:
                    if local == h:
                        out.add(f)
                    continue
            if other_arch and not f.startswith(f"arch/{other_arch}/"):
                # <asm/..>-style paths only resolve into arch/<other>/include on that arch;
                # explicit paths naming the directory still count
                if f"arch/{other_arch}/" not in posixpath.normpath(posixpath.join(posixpath.dirname(f), t)) \
                        and f"arch/{other_arch}/" not in t:
                    continue
            if ".." in nt.split("/") or h.endswith("/" + nt) or h == nt:
                out.add(f)
        return sorted(out)

    def glob(self, pattern: str) -> list[str]:
        pre = "@T/" if pattern.startswith("@T/") else ""
        pat = pattern[len(pre):]
        pat = posixpath.normpath(pat) if pat else pat
        if not any(c in pat for c in "*?["):
            return [pre + pat] if pat in self.files or pat in self.dirs else []
        d = posixpath.dirname(pat)
        return sorted(pre + f for f in self.files if posixpath.dirname(f) == d and fnmatch.fnmatchcase(f, pat))


def build_index(orig: Path, diff: Path | None, out: Path) -> None:
    """Index Ubuntu's source: ORIG + DIFF (.orig.tar.gz + .diff.gz) or, for a native upload
    (DIFF None, e.g. linux_7.3.0-9.9.tar.gz), the tarball alone."""
    log(f"indexing {orig.name}{' + ' + diff.name if diff else ''} (one-time, ~1-2 min)")
    patches = {} if diff is None else \
        {p: h for p, h in parse_diff(gzip.decompress(diff.read_bytes()).decode("latin-1")).items()
         if not p.startswith("debian")}
    files: set[str] = set()
    makefiles: dict[str, str] = {}
    includes: dict[str, list[str]] = {}
    keep: dict[str, str] = {}
    evidence: dict[str, str] = {}
    with tarfile.open(orig, mode="r|gz") as t:
        for m in t:
            if not (m.isfile() or m.issym()):
                continue
            path = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if not path or (diff is None and path.startswith("debian")):    # packaging, as in the diff case
                continue
            files.add(path)
            if not m.isfile():
                continue
            base = posixpath.basename(path)
            ext = posixpath.splitext(path)[1]
            is_mk = bool(MAKEFILE_RE.search(base))
            if path in patches or is_mk or ext in SCAN_EXT:
                data = t.extractfile(m).read()
                if path in patches:
                    keep[path] = data.decode("latin-1")
                    continue
                if path in EVIDENCE_FILES:
                    evidence[path] = data.decode("latin-1")
                if is_mk:
                    makefiles[path] = data.decode("latin-1")
                if ext in SCAN_EXT:
                    incs = includes_of(data)
                    if incs:
                        includes[path] = incs
    for path, hunks in patches.items():
        new = apply_hunks(path, keep.get(path), hunks)
        if new is None:
            files.discard(path)
            continue
        files.add(path)
        if path in EVIDENCE_FILES:
            evidence[path] = new
        if MAKEFILE_RE.search(posixpath.basename(path)):
            makefiles[path] = new
        if posixpath.splitext(path)[1] in SCAN_EXT:
            incs = includes_of(new.encode("latin-1"))
            if incs:
                includes[path] = incs
    doc = {"format": INDEX_FORMAT, "orig": orig.name, "orig_sha256": sha256_file(orig),
           "diff": diff.name if diff else None, "diff_sha256": sha256_file(diff) if diff else None,
           "patched_files": len(patches),
           "files": sorted(files), "makefiles": makefiles, "includes": includes,
           "evidence_files": sorted(EVIDENCE_FILES), "evidence": evidence}
    tmp = out.with_name(out.name + ".part")
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=6) as f:
        json.dump(doc, f, sort_keys=True)
    os.replace(tmp, out)
    log(f"index: {len(files)} files, {len(makefiles)} Kbuild files, {len(patches)} patched by Ubuntu")


# ============================================================================ make evaluator
def _match_close(s: str, i: int) -> int:
    """S[i] is '(' or '{'; index of its matching closer, or -1."""
    o = s[i]
    c = ")" if o == "(" else "}"
    depth = 0
    for j in range(i, len(s)):
        if s[j] == o:
            depth += 1
        elif s[j] == c:
            depth -= 1
            if depth == 0:
                return j
    return -1


def _split_args(s: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _pmatch(pat: str, w: str):
    if "%" not in pat:
        return (w == pat), ""
    p, s = pat.split("%", 1)
    if len(w) >= len(p) + len(s) and w.startswith(p) and w.endswith(s):
        return True, w[len(p):len(w) - len(s)]
    return False, ""


def _psub(rep: str, stem: str) -> str:
    return rep.replace("%", stem, 1) if "%" in rep else rep


def _top_level(s: str, chars: str) -> int:
    depth = 0
    for i, ch in enumerate(s):
        if ch == "$" and i + 1 < len(s) and s[i + 1] in "({":
            pass
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
        elif depth == 0 and ch in chars:
            return i
    return -1


def logical_lines(text: str):
    """(physical line no, text, starts with tab) with continuations joined, comments removed."""
    out, buf, start = [], [], 0
    for n, ln in enumerate(text.split("\n"), 1):
        if not buf:
            start = n
        bs = len(ln) - len(ln.rstrip("\\"))
        if bs % 2 == 1:
            buf.append(ln[:-1] if not buf else ln[:-1].lstrip())
            continue
        buf.append(ln if len(buf) == 0 else ln.lstrip())
        full = " ".join(buf) if len(buf) > 1 else buf[0]
        buf = []
        tab = full.startswith("\t")
        # strip comments (an unescaped '#')
        j = 0
        while True:
            j = full.find("#", j)
            if j < 0:
                break
            if j > 0 and full[j - 1] == "\\":
                full = full[:j - 1] + full[j:]
                continue
            full = full[:j]
            break
        out.append((start, full.rstrip(), tab))
    if buf:
        out.append((start, " ".join(buf), False))
    return out


class Line:
    __slots__ = ("file", "no", "text", "kind", "mode", "lhs", "val")

    def __init__(self, file, no, text, kind, mode, lhs=None, val=None):
        self.file, self.no, self.text, self.kind, self.mode, self.lhs = file, no, text, kind, mode, lhs
        self.val = val       # RHS expanded when the line ran (assignments)


class MakeEval:
    """GNU make subset for Kbuild files. 'may' mode (unknown condition) turns assignments
    into unions, so final values over-approximate the real ones."""

    def __init__(self, tree: Tree, config: dict[str, str], dirpath: str, external: frozenset = frozenset()):
        self.tree, self.config, self.dir, self.external = tree, config, dirpath, external
        self.vars: dict[str, list] = {}
        self.opaque: list[str] = []
        self.lines: list[Line] = []
        self.assigned: dict[str, list[str]] = {}   # name -> raw RHS of executed assignments
        self.included: list[str] = []
        self.last_val: str | None = None
        self._depth = 0
        self.mode = "run"
        for v in ("obj-y", "obj-m", "lib-y", "lib-m", "subdir-y", "subdir-m", "always-y", "targets",
                  "extra-y", "ccflags-y", "asflags-y", "ldflags-y", "subdir-ccflags-y"):
            self.vars[v] = ["s", ""]
        self.local = {"src": "@T/" + dirpath if dirpath else "@T", "obj": dirpath or "."}

    # ---- values
    def lookup(self, name: str) -> str:
        if UNK in name:
            return UNK
        if name in self.vars:
            fl, val = self.vars[name]
            if fl == "s":
                return val
            self._depth += 1
            try:
                return UNK if self._depth > 60 else self.expand(val)
            finally:
                self._depth -= 1
        if name in self.local:
            return self.local[name]
        if name in self.config:
            return self.config[name]
        if name.startswith("CONFIG_") or name.isdigit():
            return ""
        if name in ENV:
            return ENV[name]
        # a sub-make sees only what the top-level / arch / kbuild Makefiles define (exported or
        # not, to be safe); anything else that is undefined is empty, as in make
        return UNK if name in self.external else ""

    def defined(self, name: str) -> bool | None:
        if UNK in name:
            return None
        if name in self.vars:
            return self.vars[name][1].strip() != ""
        if name in self.local or name in ENV:
            return bool((self.local.get(name) or ENV.get(name) or "").strip())
        if name in self.config:
            return True
        if name.startswith("CONFIG_"):
            return False
        return None if name in self.external else False

    def expand(self, s: str) -> str:
        if "$" not in s:
            return s
        out, i, n = [], 0, len(s)
        while i < n:
            j = s.find("$", i)
            if j < 0:
                out.append(s[i:])
                break
            out.append(s[i:j])
            i = j
            if i + 1 >= n:
                out.append("$")
                break
            d = s[i + 1]
            if d == "$":
                out.append("$")
                i += 2
            elif d in "({":
                k = _match_close(s, i + 1)
                if k < 0:
                    out.append(UNK)
                    break
                out.append(self._ref(s[i + 2:k]))
                i = k + 1
            else:
                out.append(self.lookup(d))
                i += 2
        return "".join(out)

    def _ref(self, inner: str) -> str:
        m = re.match(r"([a-z-]+)[ \t]", inner)
        if m and m.group(1) in FUNCS:
            return self._func(m.group(1), inner[m.end():].lstrip(" \t"))
        k = _top_level(inner, ":")
        if k > 0 and "=" in inner[k:]:
            name = self.expand(inner[:k]).strip()
            a, b = inner[k + 1:].split("=", 1)
            a, b = self.expand(a), self.expand(b)
            val = self.lookup(name)
            if UNK in val or UNK in a or UNK in b:
                return UNK
            if "%" not in a:
                a, b = "%" + a, "%" + b
            res = []
            for w in val.split():
                ok, st = _pmatch(a, w)
                res.append(_psub(b, st) if ok else w)
            return " ".join(res)
        return self.lookup(self.expand(inner).strip())

    def _func(self, fn: str, argstr: str) -> str:
        if fn in ("if", "or", "and", "foreach"):
            raw = _split_args(argstr)
            if fn == "if":
                c = self.expand(raw[0]).strip()
                if UNK in c:
                    return UNK
                if c:
                    return self.expand(raw[1]) if len(raw) > 1 else ""
                return self.expand(",".join(raw[2:])) if len(raw) > 2 else ""
            if fn == "or":
                for r in raw:
                    v = self.expand(r).strip()
                    if UNK in v:
                        return UNK
                    if v:
                        return v
                return ""
            if fn == "and":
                v = ""
                for r in raw:
                    v = self.expand(r).strip()
                    if UNK in v:
                        return UNK
                    if not v:
                        return ""
                return v
            # foreach
            if len(raw) < 3:
                return UNK
            var = self.expand(raw[0]).strip()
            lst = self.expand(raw[1])
            if UNK in lst or UNK in var:
                return UNK
            saved = self.vars.get(var)
            res = []
            for w in lst.split():
                self.vars[var] = ["s", w]
                res.append(self.expand(",".join(raw[2:])))
            if saved is None:
                self.vars.pop(var, None)
            else:
                self.vars[var] = saved
            return " ".join(res)
        if fn == "value":
            v = self.vars.get(self.expand(argstr).strip())
            return v[1] if v else ""
        if fn == "call":
            raw = _split_args(argstr)
            name = self.expand(raw[0]).strip()
            if name not in self.vars:
                return UNK
            args = [self.expand(a) for a in raw[1:]]
            saved = {k: self.vars.get(k) for k in [str(i) for i in range(0, 10)]}
            self.vars["0"] = ["s", name]
            for i in range(1, 10):
                self.vars[str(i)] = ["s", args[i - 1] if i <= len(args) else ""]
            try:
                fl, body = self.vars[name]
                res = self.expand(body) if fl == "r" else body
            finally:
                for k, v in saved.items():
                    if v is None:
                        self.vars.pop(k, None)
                    else:
                        self.vars[k] = v
            return res
        if fn == "eval":
            text = self.expand(argstr)    # unknown parts stay UNK markers in what it defines
            self.run_text(text, f"{self.dir or '.'}/<eval>", eval_=True)
            return ""
        if fn in ("error", "warning", "info"):
            return ""
        if fn in ("shell", "origin", "flavor", "file", "guile", "let", "intcmp", "realpath", "abspath"):
            return UNK
        args = [self.expand(a) for a in _split_args(argstr)]
        if any(UNK in a for a in args):
            return UNK
        W = [a.split() for a in args]
        if fn == "subst":
            if len(args) < 3:
                return UNK
            return ",".join(args[2:]).replace(args[0], args[1]) if args[0] else ",".join(args[2:])
        if fn == "patsubst":
            pat, rep = args[0].strip(), args[1].strip()
            res = []
            for w in ",".join(args[2:]).split():
                ok, st = _pmatch(pat, w)
                res.append(_psub(rep, st) if ok else w)
            return " ".join(res)
        if fn == "strip":
            return " ".join(",".join(args).split())
        if fn == "findstring":
            return args[0] if len(args) > 1 and args[0] in args[1] else ""
        if fn in ("filter", "filter-out"):
            pats = W[0]
            words = ",".join(args[1:]).split()
            hit = [w for w in words if any(_pmatch(p, w)[0] for p in pats)]
            return " ".join(hit if fn == "filter" else [w for w in words if w not in hit])
        if fn == "sort":
            return " ".join(sorted(set(",".join(args).split())))
        if fn == "words":
            return str(len(",".join(args).split()))
        if fn in ("firstword", "lastword"):
            ws = ",".join(args).split()
            return (ws[0] if fn == "firstword" else ws[-1]) if ws else ""
        if fn == "word":
            ws = ",".join(args[1:]).split()
            try:
                k = int(args[0])
            except ValueError:
                return UNK
            return ws[k - 1] if 0 < k <= len(ws) else ""
        if fn == "wordlist":
            try:
                a, b = int(args[0]), int(args[1])
            except ValueError:
                return UNK
            return " ".join(",".join(args[2:]).split()[a - 1:b])
        if fn == "dir":
            return " ".join((w[:w.rfind("/") + 1] if "/" in w else "./") for w in ",".join(args).split())
        if fn == "notdir":
            return " ".join(w[w.rfind("/") + 1:] for w in ",".join(args).split())
        if fn in ("suffix", "basename"):
            res = []
            for w in ",".join(args).split():
                b = w[w.rfind("/") + 1:]
                k = b.rfind(".")
                if fn == "suffix":
                    if k >= 0:
                        res.append(b[k:])
                else:
                    res.append(w[:len(w) - len(b) + k] if k >= 0 else w)
            return " ".join(res)
        if fn in ("addsuffix", "addprefix"):
            x = args[0]
            ws = ",".join(args[1:]).split()
            return " ".join((w + x) if fn == "addsuffix" else (x + w) for w in ws)
        if fn == "join":
            a, b = W[0], (W[1] if len(W) > 1 else [])
            return " ".join((a[i] if i < len(a) else "") + (b[i] if i < len(b) else "")
                            for i in range(max(len(a), len(b))))
        if fn == "wildcard":
            res = []
            for p in ",".join(args).split():
                if p.startswith("@T/") or not p.startswith("/"):
                    res.extend(self.tree.glob(p))
                else:
                    return UNK
            return " ".join(res)
        return UNK

    # ---- statements
    def assign(self, lhs: str, op: str, rhs: str) -> str | None:
        name = self.expand(lhs).strip()
        if not name or UNK in name or " " in name:
            self.opaque.append(f"assignment to an unknown variable name: {lhs.strip()[:80]}")
            return None
        rhs = rhs.lstrip(" \t")
        self.assigned.setdefault(name, []).append(rhs)
        # for evidence only; never expand $(eval ...) twice (side effects)
        self.last_val = self.expand(rhs) if op != "!=" and "eval" not in rhs else None
        cur = self.vars.get(name)
        may = self.mode == "may"
        if op == "?=":
            if cur is None:
                self.vars[name] = ["r", rhs]
        elif op == "!=":
            self.vars[name] = ["s", UNK]
        elif op in (":=", "::=", ":::="):
            val = self.expand(rhs)
            if may and cur:
                val = (self.lookup(name) + " " + val).strip()
            self.vars[name] = ["s", val]
        elif op == "=":
            if may and cur:
                old = cur[1] if cur[0] == "r" else cur[1].replace("$", "$$")
                self.vars[name] = ["r", old + " " + rhs]
            else:
                self.vars[name] = ["r", rhs]
        else:  # +=
            if cur is None:
                self.vars[name] = ["r", rhs]
            elif cur[0] == "s":
                cur[1] = (cur[1] + " " + self.expand(rhs)).strip()
            else:
                cur[1] = cur[1] + " " + rhs
        return name

    def _cond(self, kw: str, rest: str) -> bool | None:
        rest = rest.strip()
        if kw in ("ifdef", "ifndef"):
            name = self.expand(rest).strip()
            d = self.defined(name)
            return None if d is None else (d if kw == "ifdef" else not d)
        if rest.startswith("("):
            k = _match_close(rest, 0)
            if k < 0:
                return None
            parts = _split_args(rest[1:k])
            if len(parts) != 2:
                return None
            a, b = parts
        else:
            m = re.match(r"""(["'])(.*?)\1\s+(["'])(.*?)\3""", rest)
            if not m:
                return None
            a, b = m.group(2), m.group(4)
        a, b = self.expand(a).strip(), self.expand(b).strip()
        if UNK in a or UNK in b:
            return None
        return (a == b) if kw == "ifeq" else (a != b)

    def run_file(self, path: str) -> None:
        text = self.tree.makefiles.get(path)
        if text is None:
            self.opaque.append(f"{path} not found")
            return
        self.included.append(path)
        self.run_text(text, path)

    def run_text(self, text: str, fname: str, eval_: bool = False) -> None:
        stack: list[list] = []   # [parent_mode, taken]
        in_rule = False
        lines = logical_lines(text)
        i = 0
        while i < len(lines):
            no, t, tab = lines[i]
            i += 1
            s = t.strip()
            if not s:
                continue
            word = re.match(r"(-?[a-z]+)", s)
            kw = word.group(1) if word else ""
            if kw in ("ifeq", "ifneq", "ifdef", "ifndef") and re.match(r"-?[a-z]+[\s(]", s):
                cond = self._cond(kw, s[len(kw):]) if self.mode != "skip" else False
                stack.append([self.mode, cond if self.mode != "skip" else True])
                self.mode = self._branch(self.mode, cond)
                self.lines.append(Line(fname, no, s, "directive", self.mode))
                continue
            if kw == "else" and stack and (s == "else" or s[4] in " \t"):
                parent, taken = stack[-1]
                rest = s[4:].strip()
                if parent == "skip":
                    self.mode = "skip"
                    continue
                if rest:
                    k2 = re.match(r"(ifeq|ifneq|ifdef|ifndef)\b", rest)
                    cond = self._cond(k2.group(1), rest[len(k2.group(1)):]) if k2 else None
                else:
                    cond = True
                if taken is True:
                    cond = False
                elif taken is None and cond is not False:
                    cond = None
                if cond is True:
                    stack[-1][1] = True
                elif cond is None and taken is False:
                    stack[-1][1] = None
                self.mode = self._branch(parent, cond)
                continue
            if kw == "endif" and stack:
                self.mode = stack.pop()[0]
                continue
            if kw == "define":
                name = s[6:].strip()
                op = "="
                m = re.match(r"(.*?)\s*(:::=|::=|:=|\+=|\?=|=)\s*$", name)
                if m:
                    name, op = m.group(1), m.group(2)
                body = []
                while i < len(lines) and lines[i][1].strip() != "endef":
                    body.append(lines[i][1])
                    i += 1
                i += 1
                if self.mode != "skip":
                    self.assign(name, op if op != "=" else "=", "\n".join(body))
                continue
            if tab and in_rule:
                self.lines.append(Line(fname, no, s, "recipe", self.mode))
                continue
            in_rule = False
            if self.mode == "skip":
                self.lines.append(Line(fname, no, s, "skip", "skip"))
                continue
            if kw in ("include", "-include", "sinclude") and re.match(r"-?s?include\s", s):
                self.lines.append(Line(fname, no, s, "directive", self.mode))
                self._include(s.split(None, 1)[1] if " " in s or "\t" in s else "", kw != "include")
                continue
            if kw in ("export", "unexport", "override", "private", "undefine", "vpath"):
                rest = s[len(kw):].strip()
                if kw in ("unexport", "vpath") or not rest:
                    continue
                if kw == "undefine":
                    if self.mode == "run":
                        self.vars.pop(self.expand(rest).strip(), None)
                    continue
                s = rest
                if kw == "export" and re.match(r"override\s", s):
                    s = s[8:].strip()
                if _top_level(s, "=:") < 0:
                    continue
            k = _top_level(s, "=:")
            if k < 0:
                v = self.expand(s).strip()
                if v and UNK not in v:
                    self.run_text(v, fname, eval_=True)
                elif UNK in v:
                    self.opaque.append(f"{fname}:{no}: line with an unknown expansion: {s[:80]}")
                self.lines.append(Line(fname, no, s, "other", self.mode))
                continue
            if s[k] == ":":
                m = re.match(r"(:::=|::=|:=)", s[k:])
                if m:
                    self.last_val = None
                    name = self.assign(s[:k], m.group(1), s[k + len(m.group(1)):])
                    self.lines.append(Line(fname, no, s, "assign", self.mode, name, self.last_val))
                else:
                    in_rule = True
                    self.lines.append(Line(fname, no, s, "rule", self.mode))
                    semi = _top_level(s, ";")
                    if semi > 0:
                        self.lines.append(Line(fname, no, s[semi + 1:], "recipe", self.mode))
                continue
            op = "="
            lhs = s[:k]
            if lhs.endswith(("+", "?", "!")):
                op = lhs[-1] + "="
                lhs = lhs[:-1]
            self.last_val = None
            name = self.assign(lhs, op, s[k + 1:])
            self.lines.append(Line(fname, no, s, "assign", self.mode, name, self.last_val))
        if stack and not eval_:
            self.opaque.append(f"{fname}: unbalanced conditionals")
            self.mode = stack[0][0]

    @staticmethod
    def _branch(parent: str, cond: bool | None) -> str:
        if parent == "skip" or cond is False:
            return "skip"
        if cond is None:
            return "may"
        return parent

    def _include(self, arg: str, optional: bool) -> None:
        val = self.expand(arg)
        if UNK in val:
            if not optional:
                self.opaque.append(f"include of an unknown file: {arg}")
            return
        for w in val.split():
            p = w[3:] if w.startswith("@T/") else w
            p = posixpath.normpath(p)
            if p.startswith("include/config/") or p in ("scripts/Kbuild.include", "scripts/Makefile.lib",
                                                         "scripts/Makefile.compiler"):
                continue
            if p in self.tree.makefiles and len(self.included) < 500:
                self.run_file(p)
            elif not optional:
                self.opaque.append(f"include {p}: not in the tree index")

    # ---- results
    def words(self, name: str) -> list[str]:
        if name not in self.vars:
            return []
        return self.lookup(name).split()

    def members(self, word: str, module: bool) -> list[tuple[str, str]] | None:
        """[(member object, composite name)] of a composite object, None if not composite.
        One level, like real-search in scripts/Makefile.build (-objs -y, plus -m for modules)."""
        base = word[:-2]
        sufs = ("-objs", "-y", "-m") if module else ("-objs", "-y")
        ws = []
        for suf in sufs:
            ws += self.words(base + suf)
        return [(w, base) for w in ws] if ws else None


# ============================================================================ the build model
class Build:
    def __init__(self, tree: Tree, config: dict[str, str], modules_order: set[str],
                 modules_builtin: set[str], initrd: set[str]):
        self.tree, self.config = tree, config
        self.order, self.builtin, self.initrd = modules_order, modules_builtin, initrd
        self.reach: dict[str, str] = {}         # dir -> 'y' (linked) | 'm' (modules only) | 's' (descended)
        self.evals: dict[str, MakeEval] = {}
        self.objmap: dict[str, list[tuple]] = {}  # object path -> [(kind, module ko|None, dir)]
        self.opaque: dict[str, str] = {}        # dir -> reason (dir and everything below)
        self.mismatch: list[str] = []
        self.extra_evals: list[MakeEval] = []
        self._walk()
        self._self_check()
        self._mentions = self._mention_index()
        self._memo: dict[str, tuple] = {}

    # ---- evaluation
    def _kbuild_file(self, d: str) -> str | None:
        for n in ("Kbuild", "Makefile"):
            p = f"{d}/{n}" if d else n
            if p in self.tree.makefiles:
                return p
        return None

    EXTERNAL_FILES = ("Makefile", f"arch/{ARCH}/Makefile", "scripts/Kbuild.include", "scripts/Makefile.build",
                      "scripts/Makefile.lib", "scripts/Makefile.compiler", "scripts/Makefile.extrawarn")

    def _external_names(self) -> frozenset:
        names = set()
        rx = re.compile(r"^\s*(?:export\s+|override\s+)*([A-Za-z_][A-Za-z0-9_.-]*)\s*(?::{1,3}=|\+=|\?=|!=|=)", re.M)
        for p in self.EXTERNAL_FILES:
            t = self.tree.makefiles.get(p, "")
            names.update(rx.findall(t))
            names.update(re.findall(r"^\s*define\s+([A-Za-z_][A-Za-z0-9_.-]*)", t, re.M))
            for m in re.finditer(r"^\s*export\s+([^=:+?!\n]+)$", t, re.M):
                names.update(m.group(1).split())
        return frozenset(n for n in names if not n.startswith("CONFIG_"))

    def _walk(self) -> None:
        self.external = self._external_names()
        arch = MakeEval(self.tree, self.config, "")
        arch.vars.update({"core-y": ["s", ""], "drivers-y": ["s", ""], "libs-y": ["s", "lib/"]})
        arch.run_file(f"arch/{ARCH}/Makefile")
        self.extra_evals.append(arch)
        pre = {"ARCH_CORE": arch.words("core-y"),
               "ARCH_LIB": [w for w in arch.words("libs-y") if w.endswith("/")],
               "ARCH_DRIVERS": arch.words("drivers-y") + arch.words("drivers-m")}
        for v in pre.values():
            if any(UNK in w for w in v):
                raise Fail(f"arch/{ARCH}/Makefile: core-y/libs-y/drivers-y not evaluable")
        top = MakeEval(self.tree, self.config, "")
        top.run_file("Makefile")
        self.extra_evals.append(top)
        for ev in (arch, top):
            self._build_targets(ev)
        queue = [""]
        self.reach[""] = "y"
        root_pre = {k: ["s", " ".join(v)] for k, v in pre.items()}
        while queue:
            d = queue.pop(0)
            if d in self.evals:
                continue
            ev = MakeEval(self.tree, self.config, d, self.external)
            if d == "":
                ev.vars.update(root_pre)
            kf = self._kbuild_file(d)
            if kf is None:
                self._set_opaque(d, "reached, but has no Kbuild/Makefile")
                self.evals[d] = ev
                continue
            ev.run_file(kf)
            self.evals[d] = ev
            if ev.opaque:
                self._set_opaque(d, "; ".join(sorted(set(ev.opaque)))[:300])
            self._build_targets(ev)
            state = self.reach[d]
            obj_y = set(ev.words("obj-y"))
            obj_m = [w for w in ev.words("obj-m") if w not in obj_y]
            lib = [w for w in ev.words("lib-y") + ev.words("lib-m") if w not in obj_y]
            subs: list[tuple[str, str]] = []
            for w in sorted(obj_y):
                if UNK in w:
                    self._set_opaque(d, "obj-y has an unknown value")
                elif w.endswith("/"):
                    subs.append((w, "y" if state == "y" else "s"))
                elif w.endswith(".o"):
                    for leaf, comp in ev.members(w, False) or [(w, w[:-2])]:
                        self._add(d, leaf, ("y", None, d, comp))
            for w in obj_m:
                if UNK in w:
                    self._set_opaque(d, "obj-m has an unknown value")
                elif w.endswith("/"):
                    subs.append((w, "m"))
                elif w.endswith(".o"):
                    ko = "kernel/" + self._norm(d, w[:-2] + ".ko")
                    for leaf, comp in ev.members(w, True) or [(w, w[:-2])]:
                        self._add(d, leaf, ("m", ko, d, comp))
            for w in lib:
                if UNK in w:
                    self._set_opaque(d, "lib-y has an unknown value")
                elif w.endswith(".o"):
                    self._add(d, w, ("lib", None, d, w[:-2]))
            for w in ev.words("subdir-y") + ev.words("subdir-m"):
                if UNK in w:
                    self._set_opaque(d, "subdir-y has an unknown value")
                else:
                    subs.append((w.rstrip("/") + "/", "s"))
            for w, st in subs:
                c = self._norm(d, w.rstrip("/"))
                old = self.reach.get(c)
                rank = {"y": 3, "m": 2, "s": 1}
                if old is None or rank[st] > rank[old]:
                    self.reach[c] = st
                if c not in self.evals and c not in queue:
                    queue.append(c)

    @staticmethod
    def _norm(d: str, w: str) -> str:
        if w.startswith("@T/"):
            return posixpath.normpath(w[3:])
        return posixpath.normpath(posixpath.join(d, w)) if d else posixpath.normpath(w)

    def _add(self, d: str, leaf: str, entry: tuple) -> None:
        if UNK in leaf:
            self._set_opaque(d, "object list has an unknown value")
            return
        self.objmap.setdefault(self._norm(d, leaf), []).append(entry)

    def _set_opaque(self, d: str, why: str) -> None:
        self.opaque.setdefault(d, why)

    def _build_targets(self, ev: MakeEval) -> None:
        """$(MAKE) $(build)=DIR descents (arch/x86/boot, realmode/rm, ...): not obj-y, so opaque."""
        for ln in ev.lines:
            if ln.mode == "skip" or "build)=" not in ln.text:
                continue
            for m in re.finditer(r"\$\(build\)=(\S+)", ln.text):
                v = ev.expand(m.group(1))
                if UNK in v or "$" in v:
                    continue
                p = self._norm("", v[3:] if v.startswith("@T/") else v)
                if p and p != ".":
                    self._set_opaque(p, f"built via $(build)= from {ln.file}:{ln.no}")
                    if p not in self.reach and self._kbuild_file(p):
                        self.reach[p] = "s"

    def _self_check(self) -> None:
        """Every module of modules.order / modules.builtin must be explained by the evaluator."""
        mods = {e[1] for es in self.objmap.values() for e in es if e[0] == "m"}
        for ko in sorted(self.order - mods):
            self.mismatch.append(f"{ko} is in modules.order but not derived from the Makefiles")
            self._opaque_for(ko[len("kernel/"):])
        for ko in sorted(mods - self.order):
            if not self._under_opaque(posixpath.dirname(ko[7:])):
                self.mismatch.append(f"{ko} derived from the Makefiles but not in modules.order")
            self._opaque_for(ko[len("kernel/"):])
        comps = {self._norm(e[2], x) for es in self.objmap.values() for e in es if e[0] == "y"
                 for x in (e[3], posixpath.basename(e[3]))}    # builtin modname: Makefile dir + basename
        for ko in sorted(self.builtin):
            rel = ko[len("kernel/"):-3]
            d, name = posixpath.dirname(rel), posixpath.basename(rel)
            if not {rel, f"{d}/{name.replace('-', '_')}", f"{d}/{name.replace('_', '-')}"} & comps:
                self.mismatch.append(f"{ko} is in modules.builtin but not derived as built-in")
                self._opaque_for(rel)

    def _opaque_for(self, rel: str) -> None:
        d = posixpath.dirname(rel)
        # the nearest evaluated ancestor decided wrongly: make its whole subtree unknown
        while d and d not in self.evals:
            d = posixpath.dirname(d)
        self._set_opaque(d if d else posixpath.dirname(rel), f"self-check: {rel}.ko not explained")

    def _under_opaque(self, path_dir: str) -> str | None:
        d = path_dir
        while True:
            if d in self.opaque:
                return d
            if not d:
                return None
            d = posixpath.dirname(d)

    # ---- mentions of a file in executed Kbuild lines
    def _mention_index(self) -> dict[str, list[tuple[Line, MakeEval, str]]]:
        idx: dict[str, list] = {}
        tok = re.compile(r"[^\s=,;:()'\"]*?([A-Za-z0-9_+.-]+)\.(o|c|S|s|rs|ko|lds|i|a|h)\b")
        for ev in list(self.evals.values()) + self.extra_evals:
            for ln in ev.lines:
                for m in tok.finditer(ln.text):
                    idx.setdefault(m.group(1), []).append((ln, ev, m.group(0)))
        return idx

    def _explained_vars(self, ev: MakeEval) -> set[str]:
        cache = getattr(ev, "_expl", None)
        if cache is not None:
            return cache
        names = set(ev.assigned)
        expl = {n for n in names if re.match(r"(obj|lib|subdir)-", n)}
        work = list(expl)
        while work:
            n = work.pop()
            for rhs in ev.assigned.get(n, []):
                for b in re.findall(r"([A-Za-z0-9_+./-]+)\.o\b", rhs):
                    for m in names:
                        if m.startswith(b + "-") and m[len(b) + 1:] in ("", "y", "m", "n", "objs") \
                                and m not in expl:
                            expl.add(m)
                            work.append(m)
                for r in re.findall(r"\$[({]([A-Za-z0-9_.-]+)[)}]", rhs):
                    if r in names and r not in expl and not r.startswith("CONFIG_"):
                        expl.add(r)
                        work.append(r)
        expl = {n for n in expl if n.rsplit("-", 1)[0] not in LIST_BASE_EXCLUDE}
        ev._expl = expl
        return expl

    def mentions(self, path: str) -> tuple[list[tuple[str, Line, MakeEval]], list[str]]:
        """Mentions of PATH's object/source in the evaluated Kbuild files:
        good = [(tag, line, eval)] with tag inactive (false conditional) | flags | target | list,
        bad = descriptions of mentions the evaluator does not model (rules, recipes, other vars)."""
        stem_path = posixpath.splitext(path)[0]
        stem = posixpath.basename(stem_path)
        d = posixpath.dirname(path)
        good, bad = [], []
        for ln, ev, token in self._mentions.get(stem, []):
            t = token
            for k, v in (("$(srctree)/", "@T/"), ("$(objtree)/", "@T/"), ("$(src)/", ev.local["src"] + "/"),
                         ("$(obj)/", ev.local["obj"] + "/")):
                t = t.replace(k, v)
            mdir = posixpath.dirname(ln.file) if not ln.file.endswith("<eval>") else ev.dir
            if "$" in t or "%" in t or "*" in t:
                hit = True
            else:
                p = t[3:] if t.startswith("@T/") else posixpath.join(ev.dir if t != token else mdir, t)
                hit = posixpath.splitext(posixpath.normpath(p))[0] == stem_path
                if not hit and mdir == d and ln.kind != "assign":
                    hit = True       # a rule/recipe in the file's own directory naming the stem
            if not hit:
                continue
            where = f"{ln.file}:{ln.no}: {ln.text[:160]}"
            if ln.mode == "skip" or ln.kind == "skip":
                good.append(("inactive", ln, ev))
            elif ln.kind == "rule" and token in ln.text[:max(_top_level(ln.text, ":"), 0)] \
                    and token not in ln.text[_top_level(ln.text, ":"):]:
                good.append(("target", ln, ev))   # only a target: adds prerequisites, builds nothing
            elif ln.kind == "assign" and ln.lhs:
                lhs_part = ln.text[:_top_level(ln.text, "=:")]
                if re.search(r"(?<![A-Za-z0-9_+.-])" + re.escape(stem) + r"\.(o|c|S|s|i)\b", lhs_part):
                    good.append(("flags", ln, ev))   # per-object flags: CFLAGS_foo.o := ...
                elif ln.lhs in self._explained_vars(ev):
                    good.append(("list", ln, ev))
                else:
                    bad.append(where)
            else:
                bad.append(where)
        return good, bad

    @staticmethod
    def _inactive_lhs(lhs: str | None) -> bool:
        """obj-, obj-n, foo-, foo-n: what $(CONFIG_X) gives when X is not set."""
        return bool(lhs) and (lhs.endswith("-") or lhs.endswith("-n"))

    def not_built_lines(self, good: list) -> list[Line] | None:
        """Independent of the evaluated lists: the Kbuild lines naming the object must all be
        inactive (false conditional, unset config), directly or through their composite.
        None when any line is active or not understood."""
        out: list[Line] = []
        for tag, ln, ev in good:
            if tag in ("flags", "target"):
                continue
            if tag == "inactive" or self._inactive_lhs(ln.lhs):
                out.append(ln)
                continue
            sub = self._var_inactive(ev, ln.lhs, set())
            if sub is None:
                return None
            out.append(ln)
            out.extend(sub)
        return out or None

    def _var_inactive(self, ev: MakeEval, name: str, seen: set) -> list[Line] | None:
        """Lines proving that nothing in variable NAME reaches a built list (obj-y/obj-m/lib-y),
        following composites (foo-y -> foo.o) and $(NAME) references; None if not provable."""
        if name in seen:
            return []
        seen.add(name)
        m = re.match(r"(obj|lib|subdir)-(.*)$", name)
        if m:
            return [] if m.group(2) in ("", "n") else None
        proof: list[Line] = []
        consumers = 0
        base, _, suf = name.rpartition("-")
        if base and suf in ("y", "m", "objs", "", "n"):
            if any(e[3] == base and e[2] == ev.dir for es in self.objmap.values() for e in es):
                return None                      # the composite is built
            rx = re.compile(r"(?<![\w./-])" + re.escape(base) + r"\.o\b")
            for c in ev.lines:
                if not rx.search(c.text):
                    continue
                if c.mode == "skip" or c.kind == "skip":
                    consumers += 1
                    proof.append(c)
                elif c.kind == "assign" and c.lhs and re.match(r"(obj|lib)-", c.lhs):
                    if not self._inactive_lhs(c.lhs):
                        return None
                    consumers += 1
                    proof.append(c)
                elif c.kind == "assign" and c.lhs and c.lhs.startswith(base + "-"):
                    continue                     # its own member lines
                else:
                    return None
        ref = re.compile(r"\$[({]" + re.escape(name) + r"[:)}]")
        for c in ev.lines:
            if not ref.search(c.text):
                continue
            if c.mode == "skip" or c.kind == "skip":
                consumers += 1
                proof.append(c)
                continue
            if c.kind != "assign" or not c.lhs or c.lhs == name:
                return None
            sub = self._var_inactive(ev, c.lhs, seen)
            if sub is None:
                return None
            consumers += 1
            proof.append(c)
            proof.extend(sub)
        if consumers == 0 and not self._inactive_lhs(name):
            return None
        return proof

    def lines_note(self, lines: list[Line]) -> str:
        seen, parts = set(), []
        for ln in lines:
            if (ln.file, ln.no) in seen:
                continue
            seen.add((ln.file, ln.no))
            parts.append(f"{ln.file}:{ln.no} `{' '.join(ln.text.split())[:140]}`"
                         + (" (in a conditional block that is false for this config)"
                            if ln.mode == "skip" or ln.kind == "skip" else ""))
        note = self.cfg_note(" ".join(ln.text for ln in lines))
        return "; ".join(parts[:3]) + (f" ({note})" if note else "")

    # ---- classification
    def cfg_note(self, text: str) -> str:
        syms = sorted(set(re.findall(r"CONFIG_[A-Za-z0-9_]+", text)))
        return ", ".join(f"{s}={self.config[s]}" if s in self.config else f"{s} is not set" for s in syms)

    def classify(self, path: str) -> tuple[str, str, str]:
        """(state, category, evidence); state: absent | present | unknown."""
        st, cat, why, tainted = self._classify(path, set(), [0])
        return st, cat, why

    def _classify(self, path: str, visiting: set, budget: list) -> tuple[str, str, str, bool]:
        if path in self._memo:
            return self._memo[path] + (False,)
        if path in visiting:
            return "absent", "cycle", f"{path} (include cycle)", True
        budget[0] += 1
        if budget[0] > 400:
            return "unknown", "too-wide", "include graph too large to prove", False
        visiting.add(path)
        try:
            r = self._classify_inner(path, visiting, budget)
        finally:
            visiting.discard(path)
        if not r[3]:
            self._memo[path] = r[:3]
        return r

    def _classify_inner(self, path: str, visiting: set, budget: list) -> tuple[str, str, str, bool]:
        top = path.split("/", 1)[0]
        base = posixpath.basename(path)
        ext = posixpath.splitext(path)[1]
        d = posixpath.dirname(path)
        if top == "Documentation":
            return "absent", "documentation", f"{path} is documentation (not compiled)", False
        if top == "scripts":
            return "unknown", "scripts", f"{path}: host build tool; its output may be in the kernel", False
        if path not in self.tree.files:
            return "unknown", "not-in-tree", f"{path} is not in the Ubuntu 7.0 source tree (renamed?)", False
        if path.startswith(TOOLS_BUILD):
            return "unknown", "build-tool", f"{path}: build-host tool that rewrites kernel objects (objtool, resolve_btfids)", False
        if top == "tools":
            # userspace tooling, never shipped - unless the kernel build compiles or includes it
            bad = [b for b in self.mentions(path)[1] if "tools/" in b]
            if bad:
                return "unknown", "tools", f"{path}: compiled by the kernel build ({bad[0]})", False
            incl = [i for i in self.tree.includers(path) if not i.startswith("tools/")]
            res = self._includers_state(path, incl, visiting, budget)
            if res and res[0] != "absent":
                return res
            return "absent", "tools", f"{path} is userspace tooling (tools/), not part of the kernel", bool(res and res[3])
        if MAKEFILE_RE.search(base) or base.startswith("Kconfig"):
            if d not in self.reach and not self._under_opaque(d):
                r = self._unreached_reason(d)
                if r:
                    return "absent", r[0], f"{path}: {r[1]}", False
            return "unknown", "build-file", f"{path}: Kconfig/Kbuild change of a built directory", False
        if ext in CODE_EXT:
            return self._classify_code(path, visiting, budget)
        if ext in INCLUDABLE_EXT:
            return self._classify_header(path, visiting, budget)
        return "unknown", "other-file", f"{path}: not a C/assembly/Rust source or header", False

    def _unreached_reason(self, d: str) -> tuple[str, str] | None:
        """Why directory D is never descended by Kbuild, or None if that cannot be shown."""
        parts = d.split("/")
        if parts[0] == "arch" and len(parts) > 1 and parts[1] != ARCH:
            return "other-arch", f"arch/{parts[1]}/ is another architecture (the x86_64 build descends only arch/$(SRCARCH)/ = arch/{ARCH}/)"
        # nearest reached ancestor and its line naming the child directory
        child = d
        par = posixpath.dirname(d)
        while par and par not in self.reach:
            child, par = par, posixpath.dirname(par)
        if child in self.reach:
            return None
        if self._under_opaque(par) or par not in self.evals:
            return None
        cname = posixpath.basename(child)
        ev = self.evals[par]
        hits = []
        for ln in ev.lines:
            if re.search(r"(?<![\w.-])" + re.escape(cname) + r"(?:/|(?![\w.-]))", ln.text):
                if ln.mode == "skip" or ln.kind == "skip":
                    hits.append((ln, True))
                elif ln.kind == "assign" and self._inactive_lhs(ln.lhs) and \
                        (re.match(r"(obj|subdir)-", ln.lhs) or ln.lhs in self._explained_vars(ev)):
                    hits.append((ln, True))
                else:
                    hits.append((ln, False))   # active, a rule, or not a kbuild list: cannot prove
        if not hits or not all(ok for _, ok in hits):
            return None
        return "dir-not-built", f"directory {child}/ is not built: " + self.lines_note([h for h, _ in hits])

    def _classify_code(self, path: str, visiting: set, budget: list) -> tuple[str, str, str, bool]:
        d = posixpath.dirname(path)
        obj = posixpath.splitext(path)[0] + ".o"
        entries = self.objmap.get(obj, [])
        good, bad = self.mentions(path)
        for kind, ko, edir, comp in entries:
            if kind in ("y", "lib") and self.reach.get(edir) == "y":
                how = "built into vmlinux" if kind == "y" else "in lib.a, linked into the kernel"
                return "present", "built-in", f"{path} is {how} ({edir or '.'}: {comp}.o)", False
        for kind, ko, edir, comp in entries:
            if kind == "m" and ko in self.initrd:
                return "present", "module-shipped", f"{path} is built into {posixpath.basename(ko)}, which the initramfs ships", False
        if any(kind in ("y", "lib") for kind, *_ in entries):
            return "unknown", "builtin-unlinked", f"{path}: obj-y in a directory that is not linked into vmlinux", False
        if bad:
            return "unknown", "unexplained-ref", f"{path}: referenced outside obj-y/obj-m lists ({bad[0]})", False
        op = self._under_opaque(d)
        if op is not None:
            return "unknown", "opaque-dir", f"{path}: {op or '.'}/ cannot be evaluated ({self.opaque[op]})", False
        inc = self.tree.includers(path)
        inc_res = self._includers_state(path, inc, visiting, budget)
        if inc_res and inc_res[0] != "absent":
            return inc_res
        tainted = bool(inc_res and inc_res[3])
        mods = [e for e in entries if e[0] == "m"]
        if mods:
            for kind, ko, edir, comp in mods:
                if ko not in self.order:
                    return "unknown", "self-check", f"{path}: {ko} not in modules.order", tainted
            names = sorted({posixpath.basename(e[1]) for e in mods})
            # the obj-m line of each composite carries the config symbol
            objlines = []
            for _k, _ko, edir, comp in mods:
                ev = self.evals.get(edir)
                for ln in (ev.lines if ev else []):
                    if ln.kind == "assign" and ln.mode != "skip" and re.match(r"obj-", ln.lhs or "") and \
                            (re.search(r"(?<![\w./-])" + re.escape(comp) + r"\.o\b", ln.text)
                             or comp + ".o" in (ln.val or "").split()):
                        objlines.append(ln)
                        break
            if len(objlines) < len({(e[2], e[3]) for e in mods}):
                return "unknown", "self-check", f"{path}: no obj-m line found for {', '.join(names)}", tainted
            return "absent", "module-not-shipped", (
                f"{path} is built into {', '.join(names)} (" + self.lines_note(objlines)
                + f"); the beast-net initramfs does not contain {', '.join(names)} (build/beastnet/modules.list)"
                + (f"; {inc_res[2]}" if inc_res else "")), tainted
        if d in self.reach:
            if not good:
                if inc_res:          # only #included (foo.c pulled into bar.c), by files not built
                    return "absent", "includers-absent", inc_res[2], tainted
                return "unknown", "no-ref", f"{path}: no Kbuild line builds it", tainted
            lines = self.not_built_lines(good)
            if lines is None:
                return "unknown", "unproven", f"{path}: not in the evaluated lists, but its Kbuild lines are not all inactive", tainted
            return "absent", "config-not-set", (f"{path} is not compiled: " + self.lines_note(lines)
                                                + (f"; {inc_res[2]}" if inc_res else "")), tainted
        r = self._unreached_reason(d)
        if r is None:
            return "unknown", "dir-unknown", f"{path}: cannot show why {d}/ is not built", tainted
        return "absent", r[0], f"{path}: {r[1]}" + (f"; {inc_res[2]}" if inc_res else ""), tainted

    def _includers_state(self, path, inc, visiting, budget):
        if not inc:
            return None
        if len(inc) > 150:
            return "unknown", "too-wide", f"{path} is included by {len(inc)} files", False
        tainted = False
        absent, unknown = [], None
        for f in inc:
            st, cat, why, t = self._classify(f, visiting, budget)
            tainted |= t
            if st == "present":
                return "present", "included", f"{path} is included by {f}: {why}", tainted
            if st == "unknown" and unknown is None:
                unknown = ("unknown", "includer-unknown", f"{path} is included by {f}: {why}", tainted)
            if cat != "cycle" and st == "absent":
                absent.append(f)
        if unknown:
            return unknown[:3] + (tainted,)
        shown = ", ".join(absent[:4]) + (f" and {len(absent) - 4} more" if len(absent) > 4 else "")
        return "absent", "includers-absent", f"{path} is included only by files that are not built ({shown})", tainted

    def _classify_header(self, path: str, visiting: set, budget: list) -> tuple[str, str, str, bool]:
        if path.startswith("include/asm-generic/") or "/include/generated/" in path:
            return "unknown", "header", f"{path}: reached through generated wrappers", False
        _good, bad = self.mentions(path)
        if bad:
            return "unknown", "unexplained-ref", f"{path}: named by a Kbuild file ({bad[0]})", False
        inc = self.tree.includers(path)
        if not inc:
            r = self._unreached_reason(posixpath.dirname(path))
            if r and r[0] == "other-arch":
                return "absent", "other-arch", f"{path}: {r[1]}", False
            return "unknown", "header", f"{path}: no includer found", False
        return self._includers_state(path, inc, visiting, budget)


# ============================================================================ inputs
def load_config(text: str) -> dict[str, str]:
    cfg = {}
    for ln in text.splitlines():
        m = re.match(r"(CONFIG_[A-Za-z0-9_]+)=(.*)$", ln)
        if m:
            cfg[m.group(1)] = m.group(2)
    return cfg


def kernel_components(cdx: dict) -> tuple[str, str]:
    src = mod = None
    for c in cdx.get("components", []):
        p = c.get("purl") or ""
        if p.startswith("pkg:deb/ubuntu/linux@"):
            src = p
        elif p.startswith("pkg:deb/ubuntu/linux-modules-"):
            mod = p
    if not src or not mod:
        raise Fail("sbom/beast-boot.cdx.json: no linux / linux-modules component (run sbom-vuln.sh sbom)")
    return src, mod


def purl_parts(purl: str) -> tuple[str, str]:
    name_ver = urllib.parse.unquote(purl.split("?")[0].rsplit("/", 1)[1])
    name, ver = name_ver.split("@", 1)
    return name, ver


class Sources:
    def __init__(self, root: Path, offline: bool, refresh: bool):
        self.root, self.offline, self.refresh = root, offline, refresh
        self.cache = root / ".tools/cache/kernel-vex"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.notes: dict[str, object] = {}

    # ---- Ubuntu source + index
    def source_index(self, version: str) -> tuple[Tree, dict]:
        src = self.cache / "src"
        src.mkdir(exist_ok=True)
        meta_p = src / f"linux_{version}.files.json"
        meta = json.loads(meta_p.read_text()) if meta_p.is_file() else None
        if meta is None or (self.refresh and not self.offline):
            if self.offline:
                raise Fail(f"{meta_p} missing and --offline")
            try:
                pubs = json.loads(http_get(f"{LP_API}?ws.op=getPublishedSources&source_name=linux"
                                           f"&version={urllib.parse.quote(version)}&exact_match=true"))
                if not pubs.get("entries"):
                    raise Fail(f"Launchpad has no linux {version} source publication")
                link = pubs["entries"][0]["self_link"]
                meta = json.loads(http_get(f"{link}?ws.op=sourceFileUrls&include_meta=true"))
                meta_p.write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
            except (Fail, ValueError, KeyError) as e:
                if meta is None:
                    raise Fail(f"Launchpad source metadata: {e}") from e
                log(f"WARNING: could not refresh {meta_p.name}: {e}; using the cached copy")
        want = {}
        for e in meta:
            fn = e["url"].rsplit("/", 1)[1]
            if fn.endswith((".orig.tar.gz", ".diff.gz")):
                want["orig" if fn.endswith(".orig.tar.gz") else "diff"] = (fn, e["url"], e["sha256"])
            elif fn == f"linux_{version}.tar.gz":          # native upload (development series kernels)
                want["native"] = (fn, e["url"], e["sha256"])
        if "native" in want and not want.keys() & {"orig", "diff"}:
            want["orig"] = want.pop("native")
        elif set(want) != {"orig", "diff"}:
            raise Fail(f"linux {version}: expected .orig.tar.gz + .diff.gz or a native .tar.gz, "
                       f"got {[e['url'] for e in meta]}")
        diff_sha = want["diff"][2] if "diff" in want else None
        idx_p = self.cache / f"index-linux_{version}.json.gz"
        doc = None
        if idx_p.is_file():
            with gzip.open(idx_p, "rt", encoding="utf-8") as f:
                doc = json.load(f)
            if doc.get("format") != INDEX_FORMAT or doc.get("orig_sha256") != want["orig"][2] \
                    or doc.get("evidence_files") != sorted(EVIDENCE_FILES) \
                    or doc.get("diff_sha256") != diff_sha:
                doc = None
        if doc is None:
            for _k, (fn, url, sha) in sorted(want.items()):
                p = src / fn
                if not p.is_file() or sha256_file(p) != sha:
                    if self.offline:
                        raise Fail(f"{p} missing and --offline")
                    log(f"downloading {url}")
                    download(url, p, sha)
            build_index(src / want["orig"][0], src / want["diff"][0] if "diff" in want else None, idx_p)
            with gzip.open(idx_p, "rt", encoding="utf-8") as f:
                doc = json.load(f)
        self.notes["source"] = {"orig": want["orig"][0], "orig_sha256": want["orig"][2],
                                "diff": want["diff"][0] if "diff" in want else None, "diff_sha256": diff_sha,
                                "url": want["orig"][1].rsplit("/", 1)[0] + "/"}
        return Tree(set(doc["files"]), doc["makefiles"], doc["includes"]), doc

    # ---- where Launchpad publishes this linux version (series, pocket) + the series' versions
    def publications(self, version: str) -> dict:
        p = self.cache / "src" / f"linux_{version}.publications.json"
        doc = json.loads(p.read_text()) if p.is_file() else None
        if (doc is None or self.refresh) and not self.offline:
            try:
                pubs = json.loads(http_get(f"{LP_API}?ws.op=getPublishedSources&source_name=linux"
                                           f"&version={urllib.parse.quote(version)}&exact_match=true"))
                ents = sorted(({"series": e["distro_series_link"].rsplit("/", 1)[1], "pocket": e["pocket"],
                                "status": e["status"], "date_published": e.get("date_published")}
                               for e in pubs.get("entries", [])), key=lambda e: (e["series"], e["pocket"]))
                series = {}
                for s in sorted({e["series"] for e in ents}):
                    d = json.loads(http_get(f"{LP_UBUNTU}/{s}"))
                    series[s] = {"version": d.get("version"), "status": d.get("status")}
                doc = {"version": version, "publications": ents, "series": series}
                p.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            except (Fail, ValueError, KeyError) as e:
                log(f"WARNING: Launchpad publications of linux {version}: {e}"
                    + ("; using the cached copy" if doc else "; Ubuntu tracker evidence disabled"))
        self.notes["publications"] = doc
        return doc or {}

    # ---- Ubuntu CVE tracker: the linux statuses of each CVE (trimmed copy cached for 24 h)
    def ubuntu_tracker(self, ids: list[str]) -> dict[str, dict]:
        from concurrent.futures import ThreadPoolExecutor
        d = self.cache / "ubuntu-cve"
        d.mkdir(exist_ok=True)
        out: dict[str, dict] = {}
        todo = []
        for i in ids:
            p = d / f"{i}.json"
            if p.is_file():
                try:
                    out[i] = json.loads(p.read_text())
                except ValueError:
                    pass
            fresh = i in out and not self.refresh and time.time() - p.stat().st_mtime < 24 * 3600
            if not self.offline and not fresh and re.fullmatch(r"CVE-\d{4}-\d+", i):
                todo.append(i)

        def get(i: str) -> tuple[str, dict | None]:
            try:
                raw = json.loads(http_get(UBUNTU_CVE.format(id=i), timeout=30))
            except (Fail, ValueError):
                return i, None
            return i, {"id": raw.get("id"), "updated_at": raw.get("updated_at"),
                       "linux": [s for pk in raw.get("packages") or [] if pk.get("name") == "linux"
                                 for s in pk.get("statuses") or []]}
        errs = 0
        if todo:
            log(f"Ubuntu CVE tracker: {len(todo)} lookups")
            with ThreadPoolExecutor(max_workers=8) as ex:
                for i, rec in ex.map(get, todo):
                    if rec is None:
                        errs += 1
                        continue
                    (d / f"{i}.json").write_text(json.dumps(rec, sort_keys=True) + "\n")
                    out[i] = rec
        self.notes["ubuntu_tracker"] = {"url": UBUNTU_CVE, "asked": len(ids), "fetched": len(todo) - errs,
                                        "failed": errs, "answered": len(out)}
        return out

    # ---- kernel CNA records
    def cve_records(self, ids: list[str]) -> dict[str, dict]:
        repo = self.cache / "vulns.git"
        have = self._scan_records(repo)
        missing = [i for i in ids if i not in have]
        stale = not (repo / ".git").is_dir() or self.refresh or \
            (missing and time.time() - self._fetched(repo) > 6 * 3600)
        if stale and not self.offline:
            self._update_repo(repo)
            have = self._scan_records(repo)
        recs = {}
        for i in ids:
            if i in have:
                try:
                    recs[i] = json.loads(have[i].read_text())
                except ValueError:
                    pass
        try:
            head = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%H %cI"],
                                  capture_output=True, text=True, check=True).stdout.split()
            self.notes["cve_records"] = {"repo": VULNS_GIT, "commit": head[0], "date": head[1]}
        except (OSError, subprocess.CalledProcessError, IndexError):
            self.notes["cve_records"] = {"repo": VULNS_GIT, "commit": None}
        return recs

    @staticmethod
    def _scan_records(repo: Path) -> dict[str, Path]:
        base = repo / "cve/published"
        if not base.is_dir():
            return {}
        return {p.stem: p for p in base.glob("*/CVE-*.json")}

    @staticmethod
    def _fetched(repo: Path) -> float:
        p = repo / ".git/FETCH_HEAD"
        q = repo / ".git/HEAD"
        return max((x.stat().st_mtime for x in (p, q) if x.exists()), default=0.0)

    def _update_repo(self, repo: Path) -> None:
        def git(*a, cwd=repo):
            subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True, timeout=1800)
        try:
            if not (repo / ".git").is_dir():
                log(f"cloning {VULNS_GIT} (JSON records only)")
                shutil.rmtree(repo, ignore_errors=True)
                git("clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout", VULNS_GIT,
                    str(repo), cwd=self.cache)
                git("sparse-checkout", "set", "--no-cone", "/cve/published/**/*.json")
                git("checkout", "-q")
            else:
                log("updating the kernel CVE records")
                git("fetch", "-q", "--depth", "1", "origin")
                git("reset", "-q", "--hard", "FETCH_HEAD")
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log(f"WARNING: could not update {VULNS_GIT}: {e}; using the cached records")


# ============================================================================ fixed in the shipped kernel?
def _order(c: str) -> int:
    if c == "":
        return 0
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return -1 if c == "~" else ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = _order(a[i] if i < len(a) else ""), _order(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first and a[i] != b[j]:
                first = -1 if a[i] < b[j] else 1
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def deb_vercmp(a: str, b: str) -> int:
    """Debian version comparison (deb-version(7), dpkg's verrevcmp): -1, 0 or 1."""
    def split(v: str) -> tuple[int, str, str]:
        e, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(e or 0), up, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def upstream_base(makefile: str) -> dict | None:
    """The upstream release a kernel source tree is: VERSION/PATCHLEVEL/SUBLEVEL/EXTRAVERSION of
    its top-level Makefile (Ubuntu's stable updates bump SUBLEVEL; a development kernel built
    from a release candidate keeps EXTRAVERSION = -rcN). None when it cannot be read."""
    v = {}
    for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"):
        m = re.search(rf"^{k}[ \t]*=[ \t]*(\S*)[ \t]*$", makefile, re.M)
        if not m:
            return None
        v[k] = m.group(1)
    rc = re.fullmatch(r"-rc(\d+)", v["EXTRAVERSION"])
    if not all(v[k].isdigit() for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL")) or (v["EXTRAVERSION"] and not rc):
        return None
    ver = (int(v["VERSION"]), int(v["PATCHLEVEL"]), int(v["SUBLEVEL"]))
    tag = f"v{ver[0]}.{ver[1]}" + (f".{ver[2]}" if ver[2] else "") + v["EXTRAVERSION"]
    return {"version": ver, "rc": int(rc.group(1)) if rc else None, "tag": tag,
            "makefile": ", ".join(f"{k} = {v[k]}" for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"))}


def cna_fix(rec: dict | None, base: dict | None) -> dict | None:
    """Fix evidence from the kernel CNA record: the fix is in the shipped kernel's upstream base when
    the mainline fix (original_commit_for_fix) is in an earlier release, or in the base's own release
    when the base is that release or later (not a release candidate of it), or when the base's stable
    branch X.Y.* is fixed at X.Y.F <= the base's SUBLEVEL."""
    if not rec or not base:
        return None
    (bmaj, bmin, bsub), brc = base["version"], base["rc"]
    for a in (rec.get("containers", {}).get("cna", {}) or {}).get("affected", []) or []:
        for v in a.get("versions") or []:
            if v.get("status") != "unaffected":
                continue
            ver = str(v.get("version") or "")
            if v.get("versionType") == "original_commit_for_fix" and v.get("lessThanOrEqual") == "*":
                m = re.fullmatch(r"(\d+)\.(\d+)(?:-rc(\d+))?", ver)
                if not m:
                    continue
                fx, frc = (int(m[1]), int(m[2])), (int(m[3]) if m[3] else None)
                if fx < (bmaj, bmin) or (fx == (bmaj, bmin) and (brc is None or (frc is not None and frc <= brc))):
                    return {"source": "cna", "rule": "mainline", "fixed_in": ver}
            elif v.get("versionType") == "semver" and v.get("lessThanOrEqual") == f"{bmaj}.{bmin}.*" and brc is None:
                m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", ver)
                if m and (int(m[1]), int(m[2])) == (bmaj, bmin) and int(m[3]) <= bsub:
                    return {"source": "cna", "rule": "stable", "fixed_in": ver}
    return None


def tracker_fix(tr: dict | None, codename: str | None, shipped: str) -> dict | None:
    """Fix evidence from Ubuntu's CVE tracker: linux in the shipped series is 'released' or
    'not-affected' at a version <= the shipped one (a status without a version is not used)."""
    if not tr or not codename:
        return None
    for s in tr.get("linux") or []:
        if s.get("release_codename") != codename:
            continue
        st, desc = s.get("status"), (s.get("description") or "").strip()
        if st in ("released", "not-affected") and re.fullmatch(r"\d[0-9A-Za-z.+~:-]*", desc) \
                and deb_vercmp(desc, shipped) <= 0:
            return {"source": "ubuntu-tracker", "status": st, "version": desc, "updated_at": tr.get("updated_at")}
    return None


def shipped_series(pubs: dict, distro: str | None) -> dict | None:
    """The Ubuntu series (from Launchpad) whose version is the SBOM purl's distro and that publishes
    the source in a released pocket (never -proposed)."""
    ver = distro.split("-", 1)[1] if distro and distro.startswith("ubuntu-") else None
    order = {"Security": 0, "Updates": 1, "Release": 2}
    for e in sorted(pubs.get("publications", []), key=lambda e: (e["series"], order.get(e["pocket"], 9))):
        s = (pubs.get("series") or {}).get(e["series"]) or {}
        if ver and s.get("version") == ver and e["pocket"] in order and e["status"] in ("Published", "Superseded"):
            return {"codename": e["series"], "version": ver, "pocket": e["pocket"], "status": e["status"]}
    return None


def vendor_specific(cid: str, config: dict[str, str], evidence: dict[str, str]) -> str | None:
    """Impact statement for a VENDOR_SPECIFIC CVE when every config value and source pattern holds."""
    v = VENDOR_SPECIFIC.get(cid)
    if not v:
        return None
    if any(config.get(k) != want for k, want in v["config"].items()):
        return None
    where = []
    for path, pat in sorted(v["source"].items()):
        text = evidence.get(path)
        m = re.search(pat, text) if text is not None else None
        if not m:
            return None
        where.append(f"{path}:{text.count(chr(10), 0, m.start()) + 1}")
    return (f"{v['about']}. Not that code: {v['holds']}. Shipped config: "
            + ", ".join(f"{k}={want}" for k, want in v["config"].items())
            + f"; Ubuntu source: {', '.join(where)}. Checked by scripts/kernel_vex.py.")


def fix_statement(cid: str, fx: dict, kver: str, base: dict | None, series: dict | None, notes: dict) -> str:
    if fx["source"] == "cna":
        rec = notes.get("cve_records") or {}
        where = f"{VULNS_GIT} at {rec['commit'][:12]}" if rec.get("commit") else VULNS_GIT
        if fx["rule"] == "mainline":
            what = f"fixed in mainline Linux {fx['fixed_in']} (original_commit_for_fix)"
        else:
            what = f"fixed in the {fx['fixed_in'].rsplit('.', 1)[0]}.y stable branch at {fx['fixed_in']}"
        return (f"kernel.org CNA record {cid} ({where}): {what}. The shipped kernel is Ubuntu linux {kver}, built "
                f"from upstream {base['tag']} (top-level Makefile of Ubuntu's source: {base['makefile']}), which "
                f"contains that fix. Evaluated by scripts/kernel_vex.py.")
    return (f"Ubuntu CVE tracker (https://ubuntu.com/security/cves/{cid}.json, updated {fx.get('updated_at') or '?'}): "
            f"linux in {series['codename']} (Ubuntu {series['version']}) is {fx['status']} ({fx['version']}); the "
            f"shipped linux {kver} ({series['codename']} {series['pocket']} pocket) is >= {fx['version']}. "
            "Evaluated by scripts/kernel_vex.py.")


# ============================================================================ main
def classify_cves(build: Build, ids: list[str], recs: dict[str, dict], binp: dict | None = None) -> list[dict]:
    out = []
    kp = set((binp or {}).get("vmlinux", []))
    mp = (binp or {}).get("modules", {})
    for cid in ids:
        r = recs.get(cid)
        ent = {"id": cid}
        if r is None:
            ent.update(classification="unresolved", reason="no kernel CNA record (vulns.git) for this id", files=[])
            out.append(ent)
            continue
        pf: set[str] = set()
        for a in (r.get("containers", {}).get("cna", {}) or {}).get("affected", []) or []:
            pf.update(a.get("programFiles") or [])
        if not pf:
            ent.update(classification="unresolved", reason="the CVE record lists no programFiles", files=[])
            out.append(ent)
            continue
        files = []
        for p in sorted(pf):
            st, cat, why = build.classify(p.strip().lstrip("/"))
            if st == "absent" and (p in kp or p in mp):
                where = "vmlinuz" if p in kp else ", ".join(mp[p][:3])
                st, cat, why = "unknown", "binary-contradiction", f"{p}: its path is in {where} ({why})"
            files.append({"path": p, "state": st, "category": cat, "evidence": why})
        states = {f["state"] for f in files}
        if "present" in states:
            ent["classification"] = "present"
            ent["reason"] = next(f["evidence"] for f in files if f["state"] == "present")
        elif "unknown" in states:
            ent["classification"] = "unresolved"
            ent["reason"] = next(f["evidence"] for f in files if f["state"] == "unknown")
        else:
            ent["classification"] = "not_present"
            cats = sorted({f["category"] for f in files})
            ent["category"] = cats[0] if len(cats) == 1 else "mixed: " + ", ".join(cats)
            ent["reason"] = " ".join(f["evidence"].rstrip(".") + "." for f in files)
        ent["files"] = files
        out.append(ent)
    return out


def impact_statement(ent: dict, kver: str) -> str:
    parts = [f["evidence"].rstrip(".") + "." for f in ent["files"]]
    if len(parts) > 8:
        parts = parts[:8] + [f"(+{len(parts) - 8} more files, all not built; see sbom/kernel-vex-report.json)"]
    return (" ".join(parts) + f" Evaluated by scripts/kernel_vex.py against the Ubuntu linux {kver} Kbuild files"
            " and its shipped kernel config; every file the kernel CNA record lists (programFiles) is absent"
            " from vmlinuz and from the beast-net initramfs.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--offline", action="store_true", help="cached data only")
    ap.add_argument("--refresh", action="store_true", help="refetch the CVE records and Launchpad metadata")
    ap.add_argument("--tracker-severity", default="low", choices=("critical", "high", "medium", "low", "negligible"),
                    help="ask Ubuntu's CVE tracker about open CVEs of at least this severity (default: low)")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    sbom = root / "sbom"
    try:
        vulns = json.loads((sbom / "vulnerabilities.json").read_text())
        cdx = json.loads((sbom / "beast-boot.cdx.json").read_text())
        src_purl, mod_purl = kernel_components(cdx)
        _n, kver = purl_parts(src_purl)
        mod_name, mod_ver = purl_parts(mod_purl)
        kabi = mod_name[len("linux-modules-"):]
        product = "pkg:generic/beast-boot@" + (root / "VERSION").read_text().strip()
        findings = [f for f in vulns.get("findings", [])
                    if (f.get("component") or {}).get("purl") in (src_purl, mod_purl)]
        sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1}
        sev: dict[str, str] = {}
        for f in findings:
            if sev_rank.get(f.get("severity"), 0) >= sev_rank.get(sev.get(f["id"]), 0):
                sev[f["id"]] = f.get("severity") or "unknown"
        ids = sorted(sev)
        log(f"{len(findings)} kernel findings, {len(ids)} CVE ids (linux {kver}, {kabi})")

        srcs = Sources(root, a.offline, a.refresh)
        debdir = Path(os.environ.get("BB_BEASTNET_CACHE", root / ".tools/cache/beastnet")) / "debs"
        deb = debdir / f"{mod_name}_{mod_ver}_amd64.deb"
        if not deb.is_file():
            raise Fail(f"{deb} missing (make build fetches it)")
        want = {f"boot/config-{kabi}", f"usr/lib/modules/{kabi}/modules.order",
                f"usr/lib/modules/{kabi}/modules.builtin"}
        got, mtimes = deb_files(deb, want)
        if set(got) != want:
            raise Fail(f"{deb}: missing {sorted(want - set(got))}")
        config = load_config(got[f"boot/config-{kabi}"].decode())
        order = {ln.strip() for ln in got[f"usr/lib/modules/{kabi}/modules.order"].decode().splitlines() if ln.strip()}
        builtin = {ln.strip() for ln in got[f"usr/lib/modules/{kabi}/modules.builtin"].decode().splitlines() if ln.strip()}

        ir_cache = srcs.cache / "initrd-modules.json"
        ir_path = root / "dist/esp/beast-net/initrd.img"
        try:
            ir_sha = sha256_file(ir_path)
            ikver, imods = initrd_modules(ir_path)
            ir_cache.write_text(json.dumps({"initrd_sha256": ir_sha, "kernel": ikver, "modules": imods},
                                           indent=1) + "\n")
        except (OSError, Fail, lzma.LZMAError, ValueError) as e:
            if not ir_cache.is_file():
                raise Fail(f"{ir_path}: {e} (and no cached module list)") from e
            log(f"WARNING: {ir_path}: {e}; using the cached module list")
            c = json.loads(ir_cache.read_text())
            ir_sha, ikver, imods = c["initrd_sha256"], c["kernel"], c["modules"]
        if ikver != kabi:
            raise Fail(f"initramfs modules are for {ikver}, the SBOM names {kabi}")
        initrd = set(imods)

        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        ts_epoch = int(epoch) if epoch else mtimes[f"boot/config-{kabi}"]
        ts = datetime.fromtimestamp(ts_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        bin_cache = srcs.cache / "binary-paths.json"
        vmlinuz = root / "dist/esp/beast-net/vmlinuz"
        binp = None
        try:
            key = {"vmlinuz_sha256": sha256_file(vmlinuz), "initrd_sha256": ir_sha}
            if bin_cache.is_file():
                c = json.loads(bin_cache.read_text())
                if {k: c.get(k) for k in key} == key:
                    binp = c
            if binp is None and ir_sha == sha256_file(ir_path):
                binp = dict(key, **binary_paths(vmlinuz, ir_path))
                bin_cache.write_text(json.dumps(binp) + "\n")
        except (OSError, Fail, lzma.LZMAError, ValueError) as e:
            log(f"WARNING: binary cross-check unavailable: {e}")
        if binp is None and bin_cache.is_file():
            binp = json.loads(bin_cache.read_text())
            log("WARNING: dist/ changed; binary cross-check uses the cached path list")
        if binp and not binp.get("vmlinux"):
            log("WARNING: could not decompress vmlinuz (zstd needs Python 3.14 or the zstd tool)")
        tree, doc = srcs.source_index(kver)
        recs = srcs.cve_records(ids)
        log(f"{len(recs)}/{len(ids)} CVE records; evaluating Kbuild")
        build = Build(tree, config, order, builtin, initrd)
        log(f"{len(build.evals)} directories evaluated, {len(build.opaque)} opaque, "
            f"{len(build.mismatch)} self-check mismatches")
        res = classify_cves(build, ids, recs, binp)

        # fixed in the shipped kernel? 1. the CNA record's fix version vs the upstream base of
        # Ubuntu's source; 2. Ubuntu's tracker for the series the SBOM names (open CVEs only)
        base = upstream_base(doc["makefiles"].get("Makefile", ""))
        if base is None:
            log("WARNING: top-level Makefile of the source has no plain version; no CNA fix evidence")
        distro = (re.search(r"[?&]distro=([^&]+)", src_purl) or [None, None])[1]
        series = shipped_series(srcs.publications(kver), distro)
        if series is None:
            log(f"WARNING: linux {kver} is not published in a released pocket of {distro}; "
                "no Ubuntu tracker evidence")
        for ent in res:
            ent["fix"] = cna_fix(recs.get(ent["id"]), base)
            if ent["id"] not in recs:
                ent["vendor_specific"] = vendor_specific(ent["id"], config, doc.get("evidence") or {})
        ask = [e["id"] for e in res if not e["fix"] and e["classification"] != "not_present"
               and sev_rank.get(sev[e["id"]], 0) >= sev_rank[a.tracker_severity]]
        trk = srcs.ubuntu_tracker(ask) if series else {}
        for ent in res:
            if not ent["fix"] and ent["id"] in ask:
                ent["fix"] = tracker_fix(trk.get(ent["id"]), series["codename"], kver)
            if ent["id"] in trk:
                ent["ubuntu_tracker"] = {s["release_codename"]: f"{s.get('status')} {s.get('description') or ''}".strip()
                                         for s in trk[ent["id"]].get("linux") or []
                                         if s.get("release_codename") in (series["codename"], "upstream")}
    except Fail as e:
        log(f"ERROR: {e}")
        return 2

    stmts = []
    prods = [{"@id": product, "subcomponents": [{"@id": src_purl}, {"@id": mod_purl}]}]
    for ent in res:
        ent["severity"] = sev[ent["id"]]
        if ent["fix"]:
            ent["vex_status"] = "fixed"
            stmts.append({"vulnerability": {"name": ent["id"]}, "products": prods, "status": "fixed",
                          "status_notes": fix_statement(ent["id"], ent["fix"], kver, base, series, srcs.notes),
                          "timestamp": ts})
        elif ent.get("vendor_specific"):
            ent["vex_status"] = "not_affected"
            stmts.append({"vulnerability": {"name": ent["id"]}, "products": prods, "status": "not_affected",
                          "justification": "vulnerable_code_not_present",
                          "impact_statement": ent["vendor_specific"], "timestamp": ts})
        elif ent["classification"] == "not_present":
            ent["vex_status"] = "not_affected"
            stmts.append({
                "vulnerability": {"name": ent["id"]},
                "products": prods,
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "impact_statement": impact_statement(ent, kver),
                "timestamp": ts,
            })
        else:
            ent["vex_status"] = "open"
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": VEX_ID, "author": "beast-boot maintainers",
           "role": "Document Creator", "timestamp": ts, "version": 1,
           "tooling": ("generated by scripts/kernel_vex.py: kernel CNA programFiles "
                       f"({srcs.notes['cve_records'].get('commit') or 'cached'}) vs Ubuntu linux {kver} Kbuild "
                       f"+ /boot/config-{kabi} + beast-net initramfs modules (not_affected); CNA fix versions vs "
                       f"the upstream base {base['tag'] if base else '?'} and Ubuntu's CVE tracker for "
                       f"{series['codename'] if series else '?'} (fixed); do not edit, re-run the script"),
           "statements": stmts}
    summ: dict[str, dict] = {}
    for ent in res:
        c = ent["classification"]
        key = ent.get("category", "")
        s = summ.setdefault(c, {"total": 0, "by_severity": {}, "by_reason": {}})
        s["total"] += 1
        s["by_severity"][ent["severity"]] = s["by_severity"].get(ent["severity"], 0) + 1
        if c == "not_present":
            s["by_reason"][key] = s["by_reason"].get(key, 0) + 1
        else:
            cats = sorted({f["category"] for f in ent["files"] if f["state"] == ("present" if c == "present" else "unknown")}) \
                or ["no-record"]
            for k in cats:
                s["by_reason"][k] = s["by_reason"].get(k, 0) + 1
    vsum: dict[str, dict] = {}
    for ent in res:
        k = ent["vex_status"] + (f" ({ent['fix']['source']})" if ent["fix"] else
                                 " (vendor-specific)" if ent.get("vendor_specific") else "")
        s = vsum.setdefault(k, {"total": 0, "by_severity": {}})
        s["total"] += 1
        s["by_severity"][ent["severity"]] = s["by_severity"].get(ent["severity"], 0) + 1
    still_open = [{"id": e["id"], "severity": e["severity"], "classification": e["classification"],
                   "files": [f["path"] for f in e["files"]][:6], "reason": e.get("reason"),
                   "ubuntu_tracker": e.get("ubuntu_tracker")}
                  for e in res if e["vex_status"] == "open" and e["severity"] in ("critical", "high")]
    report = {
        "generated_by": "scripts/kernel_vex.py",
        "timestamp": ts,
        "kernel": {"source": f"linux {kver}", "flavour": kabi, "modules_deb": deb.name, "upstream_base": base,
                   "series": series,
                   "initrd_sha256": ir_sha, "initrd_modules": len(initrd), "modules_order": len(order),
                   "modules_builtin": len(builtin)},
        "data_sources": srcs.notes,
        "method": __doc__.split("\n\n", 2)[1].strip(),
        "self_check": {"evaluated_dirs": len(build.evals), "opaque_dirs": dict(sorted(build.opaque.items())),
                       "mismatches": build.mismatch,
                       "binary_cross_check": {
                           "vmlinux_source_paths": len((binp or {}).get("vmlinux", [])),
                           "module_source_paths": len((binp or {}).get("modules", {})),
                           "undecoded_modules": (binp or {}).get("undecoded_modules"),
                           "contradictions": sorted({f["path"] for e in res for f in e["files"]
                                                     if f["category"] == "binary-contradiction"})}},
        "summary": summ,
        "vex_summary": vsum,
        "open_critical_high": still_open,
        "cves": res,
    }
    (sbom / "vex.kernel.openvex.json").write_text(json.dumps(vex, indent=2) + "\n")
    (sbom / "kernel-vex-report.json").write_text(json.dumps(report, indent=1) + "\n")
    log(f"wrote sbom/vex.kernel.openvex.json ({len(stmts)} statements: "
        + ", ".join(f"{k} {v['total']}" for k, v in sorted(vsum.items()))
        + ") and sbom/kernel-vex-report.json: " + ", ".join(f"{k} {v['total']}" for k, v in sorted(summ.items()))
        + f"; open critical/high: {len(still_open)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
