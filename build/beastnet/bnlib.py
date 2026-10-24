"""Shared helpers for build/beastnet (Python 3.10+ standard library only).

Used by mkinitrd.py, lock.py and gen_catalog.py. Nothing here touches the
network or anything outside the paths it is given.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
from dataclasses import dataclass, field

MULTIARCH = "x86_64-linux-gnu"
LIB_DIRS = (f"usr/lib/{MULTIARCH}", "usr/lib", "usr/lib64")


class BuildError(Exception):
    pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# packages.lock
# ---------------------------------------------------------------------------
@dataclass
class LockEntry:
    name: str
    version: str
    arch: str
    sha256: str
    role: str          # kernel | modules | tool | lib | data

    @property
    def key(self) -> str:
        return f"{self.name}={self.version}"

    @property
    def filename(self) -> str:
        return deb_filename(self.name, self.version, self.arch)


def deb_filename(name: str, version: str, arch: str) -> str:
    # apt-get download names files <pkg>_<version with ':' as %3a>_<arch>.deb
    return f"{name}_{version.replace(':', '%3a')}_{arch}.deb"


ROLES = ("kernel", "modules", "tool", "lib", "data")


def read_lock(path: str) -> list[LockEntry]:
    out: list[LockEntry] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 5:
                raise BuildError(f"{path}:{n}: expected '<package> <version> <arch> <sha256> <role>'")
            e = LockEntry(*parts)
            if not re.fullmatch(r"[0-9a-f]{64}", e.sha256):
                raise BuildError(f"{path}:{n}: bad sha256 for {e.name}")
            if e.role not in ROLES:
                raise BuildError(f"{path}:{n}: unknown role {e.role!r}")
            if e.name in seen:
                raise BuildError(f"{path}:{n}: {e.name} listed twice")
            seen.add(e.name)
            out.append(e)
    return out


# ---------------------------------------------------------------------------
# Globs: '*' and '?' never cross '/', '**' matches any number of path parts
# ---------------------------------------------------------------------------
def glob_regex(pattern: str) -> re.Pattern:
    i, out = 0, []
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j < 0:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


# ---------------------------------------------------------------------------
# userland.list
# ---------------------------------------------------------------------------
@dataclass
class Userland:
    takes: dict[str, list[str]] = field(default_factory=dict)   # package -> globs
    excludes: list[str] = field(default_factory=list)


def read_userland(path: str) -> Userland:
    u = Userland()
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = strip_comment(raw)
            if not line:
                continue
            word, *globs = line.split()
            if not globs:
                raise BuildError(f"{path}:{n}: '{word}' without paths")
            for g in globs:
                if g.startswith("/"):
                    raise BuildError(f"{path}:{n}: paths are relative to / (no leading slash): {g}")
            if word == "exclude":
                u.excludes.extend(globs)
            else:
                u.takes.setdefault(word, []).extend(globs)
    return u


# ---------------------------------------------------------------------------
# ELF: interpreter, DT_NEEDED and DT_RUNPATH of 64-bit little-endian objects
# ---------------------------------------------------------------------------
@dataclass
class ElfInfo:
    interp: str | None
    needed: list[str]
    runpath: list[str]


def elf_info(path: str) -> ElfInfo | None:
    """None if PATH is not an ELF file. Raises BuildError for ELF files we cannot read."""
    with open(path, "rb") as f:
        head = f.read(64)
        if len(head) < 64 or head[:4] != b"\x7fELF":
            return None
        if head[4] != 2 or head[5] != 1:
            raise BuildError(f"{path}: not a 64-bit little-endian ELF file")
        data = head + f.read()
    (e_phoff,) = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    loads, interp, dyn = [], None, None
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 3:
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\0").decode()
        elif p_type == 2:
            dyn = (p_offset, p_filesz)
    if dyn is None:
        return ElfInfo(interp, [], [])

    def v2o(vaddr: int) -> int:
        for va, off, size in loads:
            if va <= vaddr < va + size:
                return off + vaddr - va
        raise BuildError(f"{path}: address {vaddr:#x} outside PT_LOAD segments")

    entries, strtab = [], None
    off, end = dyn[0], dyn[0] + dyn[1]
    while off + 16 <= end:
        tag, val = struct.unpack_from("<qQ", data, off)
        off += 16
        if tag == 0:
            break
        if tag == 5:
            strtab = v2o(val)
        entries.append((tag, val))
    if strtab is None:
        return ElfInfo(interp, [], [])

    def s(o: int) -> str:
        e = data.index(b"\0", strtab + o)
        return data[strtab + o:e].decode()

    needed = [s(v) for t, v in entries if t == 1]
    runpath: list[str] = []
    for t, v in entries:
        if t in (15, 29):
            runpath.extend(p for p in s(v).split(":") if p)
    return ElfInfo(interp, needed, runpath)


def resolve_in_tree(root: str, rel: str, max_links: int = 40) -> str | None:
    """Resolve REL (relative to ROOT) following symlinks inside ROOT; returns the
    final relative path or None if it does not exist."""
    parts = [p for p in rel.split("/") if p]
    done: list[str] = []
    links = 0
    while parts:
        p = parts.pop(0)
        if p == ".":
            continue
        if p == "..":
            if done:
                done.pop()
            continue
        cand = "/".join(done + [p])
        full = os.path.join(root, cand)
        if os.path.islink(full):
            links += 1
            if links > max_links:
                return None
            target = os.readlink(full)
            if target.startswith("/"):
                done = []
            parts = [x for x in target.split("/") if x] + parts
            continue
        if not os.path.lexists(full):
            return None
        done.append(p)
    return "/".join(done)


# ---------------------------------------------------------------------------
# Running the pinned kmod from an unpacked tree (independent of the host's kmod)
# ---------------------------------------------------------------------------
def tree_exec(root: str, binary: str, argv0: str, args: list[str], **kw) -> subprocess.CompletedProcess:
    """Run ROOT/BINARY with ROOT's own dynamic loader and libraries."""
    ld = os.path.join(root, "usr/lib64/ld-linux-x86-64.so.2")
    if not os.path.exists(ld):
        ld = os.path.join(root, f"usr/lib/{MULTIARCH}/ld-linux-x86-64.so.2")
    libpath = ":".join(os.path.join(root, d) for d in LIB_DIRS)
    cmd = [ld, "--library-path", libpath, "--argv0", argv0, os.path.join(root, binary)] + args
    return subprocess.run(cmd, **kw)


# ---------------------------------------------------------------------------
# .deb handling
# ---------------------------------------------------------------------------
LAUNCHPAD_FILES = "https://launchpad.net/ubuntu/+archive/primary/+files/"


def deb_field(deb: str, name: str) -> str:
    return subprocess.run(["dpkg-deb", "-f", deb, name], check=True, capture_output=True,
                          text=True).stdout.strip()


def fetch_deb(cache: str, name: str, version: str | None, arch: str | None = None,
              sha256: str | None = None, log=print, offline: bool = False) -> str:
    """Return the path of NAME_VERSION_ARCH.deb in CACHE, downloading it with
    `apt-get download` (apt checks it against the signed archive index) or, when
    the archive no longer carries that version and SHA256 is known, from
    Launchpad's file store. With SHA256 the file is always checked."""
    os.makedirs(cache, exist_ok=True)
    if version and arch:
        path = os.path.join(cache, deb_filename(name, version, arch))
        if os.path.exists(path) and (sha256 is None or sha256_file(path) == sha256):
            return path
        if os.path.exists(path):
            os.unlink(path)            # wrong content: fetch again
    if offline:
        raise BuildError(f"{name}={version}: not in {cache} and BB_OFFLINE=1")
    spec = f"{name}={version}" if version else name
    log(f"downloading {spec}")
    before = set(os.listdir(cache))
    r = subprocess.run(["apt-get", "download", spec], cwd=cache, capture_output=True, text=True)
    new = sorted(set(os.listdir(cache)) - before)
    if r.returncode == 0 and not new and version and arch:
        new = [deb_filename(name, version, arch)]
    if r.returncode != 0 or not new:
        if not (version and arch and sha256):
            raise BuildError(f"apt-get download {spec} failed:\n{r.stderr.strip()}")
        fn = deb_filename(name, version, arch)
        # archive pool file names have no epoch
        url = LAUNCHPAD_FILES + f"{name}_{version.split(':', 1)[-1]}_{arch}.deb"
        log(f"apt-get download {spec} failed ({r.stderr.strip().splitlines()[-1:]}); trying {url}")
        import urllib.request
        tmp = os.path.join(cache, fn + ".part")
        with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        os.replace(tmp, os.path.join(cache, fn))
        new = [fn]
    debs = [n for n in new if n.endswith(".deb") and n.startswith(name + "_")]
    if len(debs) != 1:
        raise BuildError(f"apt-get download {spec}: unexpected files {new}")
    path = os.path.join(cache, debs[0])
    if sha256 is not None and sha256_file(path) != sha256:
        bad = path + ".bad"
        os.replace(path, bad)
        raise BuildError(f"{path}: SHA-256 differs from packages.lock (moved to {bad})")
    return path


def deb_md5sums(deb: str) -> dict[str, str]:
    r = subprocess.run(["dpkg-deb", "-I", deb, "md5sums"], capture_output=True, text=True)
    if r.returncode != 0:
        return {}
    out = {}
    for line in r.stdout.splitlines():
        if line.strip():
            s, p = line.split(None, 1)
            out[p.strip()] = s
    return out


def extract_deb(deb: str, dest: str) -> None:
    """dpkg-deb -x into DEST, then check every regular file listed in the
    package's md5sums."""
    os.makedirs(dest, exist_ok=True)
    subprocess.run(["dpkg-deb", "-x", deb, dest], check=True)
    for rel, want in deb_md5sums(deb).items():
        p = os.path.join(dest, rel)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        h = hashlib.md5()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != want:
            raise BuildError(f"{deb}: {rel} does not match the package's md5sums")


def first_depends(deb: str) -> list[str]:
    """Package names from Pre-Depends/Depends (first alternative of each)."""
    names = []
    for fld in ("Pre-Depends", "Depends"):
        val = deb_field(deb, fld)
        for item in filter(None, (x.strip() for x in val.split(","))):
            first = item.split("|")[0].strip()
            names.append(re.split(r"[\s(:]", first, maxsplit=1)[0])
    return names


def walk_files(root: str):
    """Yield (relpath, is_link) for every non-directory under ROOT, sorted."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                dirnames.remove(d)
                filenames.append(d)
        for fn in sorted(filenames):
            r = fn if rel == "." else f"{rel}/{fn}"
            yield r, os.path.islink(os.path.join(dirpath, fn))


def modinfo_all(tree: str, paths: list[str]) -> dict[str, dict[str, list[str]]]:
    """Run the shipped modinfo once over PATHS; {module path: {field: [values]}}."""
    r = tree_exec(tree, "usr/bin/kmod", "modinfo", list(paths), capture_output=True, text=True)
    if r.returncode != 0:
        raise BuildError(f"modinfo failed:\n{r.stderr}")
    out: dict[str, dict[str, list[str]]] = {}
    cur: dict[str, list[str]] | None = None
    last = None
    for line in r.stdout.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*)$", line)
        if m and m.group(1) == "filename":
            cur = out.setdefault(m.group(2).strip(), {})
            last = None
        elif m and cur is not None:
            last = m.group(1)
            cur.setdefault(last, []).append(m.group(2).strip())
        elif cur is not None and last and line.startswith("\t"):
            cur[last][-1] += line.strip()          # continuation (signature bytes)
    missing = set(paths) - set(out)
    if missing:
        raise BuildError(f"modinfo printed nothing for {sorted(missing)[:3]}")
    return out
