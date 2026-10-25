#!/usr/bin/env python3
"""Build the beast-net initramfs (docs/BEASTNET.md section 5).

Called by build/beastnet/build.sh; not meant to be run by hand. Inputs are the
pinned .debs (packages.lock, already downloaded and SHA-256-checked by
build.sh), userland.list, modules.list and the app from beastnet/. Output:

  --out-initrd    xz-compressed (CRC32 check, LZMA2 only) newc cpio, deterministic:
                  sorted entries, uid/gid 0, mtime SOURCE_DATE_EPOCH, inode
                  numbers 1..n, modes normalised (dirs 0755, files 0644/0755)
  --out-contents  JSON: every file in the initramfs with its origin and SHA-256
  --out-info      JSON summary for build.sh (kernel version, packages, modules)
  --stage         the unpacked tree is left here (gen_catalog.py reads its modules)

Every file is either copied unmodified from a locked package (and checked
against that package's md5sums), copied from the repo, or generated here (busybox
applet links, merged-/usr links, CA bundle, a few /etc files, depmod output);
contents.json says which for each one.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import bnlib  # noqa: E402
from bnlib import BuildError  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))

# Python modules the app needs (docs/BEASTNET.md section 5); checked by running
# the shipped interpreter at build time. runtime.json may add more.
REQUIRED_PY = ["ssl", "hashlib", "curses", "json", "urllib.parse", "http.client",
               "socket", "subprocess", "select", "fcntl", "struct", "zlib", "termios", "signal",
               "argparse", "shutil", "threading", "ipaddress", "base64", "binascii",
               "email.utils", "datetime", "re", "time", "os", "errno", "ctypes", "locale"]
TERMINALS = ["linux", "vt100", "vt102", "vt220", "xterm", "xterm-256color", "screen", "dumb"]

# Merged /usr, except /lib: a firmware pack (docs/BEASTNET.md section 6) is a
# cpio with a "lib" *directory* entry, and the kernel's initramfs unpacker
# replaces an existing entry of another type (it would delete a /lib symlink).
# So /lib is a real directory holding firmware/ and a modules -> ../usr/lib/modules
# link; everything else that packages put under /lib lives in /usr/lib.
MERGED_USR = {"bin": "usr/bin", "sbin": "usr/sbin", "lib64": "usr/lib64"}


def canon(rel: str) -> str:
    """Where a package path lives in the initramfs."""
    rel = os.path.normpath(rel).lstrip("/")
    top, _, rest = rel.partition("/")
    if top in MERGED_USR and rest:
        return f"{MERGED_USR[top]}/{rest}"
    if top == "lib" and rest and not rest.startswith("firmware/") and rest != "firmware":
        return f"usr/lib/{rest}"
    return rel

ETC_FILES = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
    "etc/group": "root:x:0:\n",
    "etc/hosts": "127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n",
    "etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files dns\nnetworks: files\n"
                         "protocols: files\nservices: files\n",
    "etc/hostname": "beast-net\n",
}
DIRS = {"dev": 0o755, "proc": 0o755, "sys": 0o755, "run": 0o755, "tmp": 0o1777, "root": 0o700,
        "mnt": 0o755, "mnt/data": 0o755, "mnt/esp": 0o755, "var": 0o755, "var/tmp": 0o1777,
        "etc": 0o755, "lib": 0o755, "lib/firmware": 0o755}


def log(msg: str) -> None:
    print(f"beastnet: {msg}", file=sys.stderr)


@dataclass
class Entry:
    kind: str                 # dir | file | link | chr
    mode: int                 # permission bits
    origin: str
    src: str | None = None    # file on disk (file)
    data: bytes | None = None  # generated content (file)
    target: str | None = None  # symlink target
    rdev: tuple[int, int] = (0, 0)


class Stage:
    """The initramfs being assembled: entries in memory, regular files and
    symlinks also materialised under self.root (for ELF/symlink resolution and
    for running the shipped tools)."""

    def __init__(self, root: str):
        self.root = root
        self.e: dict[str, Entry] = {}
        os.makedirs(root, exist_ok=True)

    def _parents(self, rel: str) -> None:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            d = "/".join(parts[:i])
            cur = self.e.get(d)
            if cur is None:
                self.e[d] = Entry("dir", 0o755, "dir")
                os.makedirs(os.path.join(self.root, d), exist_ok=True)
            elif cur.kind == "link":
                raise BuildError(f"/{rel}: parent /{d} is a symlink (ship the real path instead)")

    def has(self, rel: str) -> bool:
        return rel in self.e

    def add_dir(self, rel: str, mode: int = 0o755, origin: str = "dir") -> None:
        self._parents(rel)
        cur = self.e.get(rel)
        if cur and cur.kind != "dir":
            raise BuildError(f"/{rel}: directory clashes with an existing {cur.kind}")
        self.e[rel] = Entry("dir", mode, origin)
        os.makedirs(os.path.join(self.root, rel), exist_ok=True)

    def _check_new(self, rel: str, origin: str, override_built: bool) -> None:
        cur = self.e.get(rel)
        if cur is None:
            return
        if override_built and cur.origin.startswith("built:"):
            p = os.path.join(self.root, rel)
            if os.path.lexists(p) and not os.path.isdir(p):
                os.unlink(p)
            return
        raise BuildError(f"/{rel}: two sources ({cur.origin} and {origin})")

    def add_file(self, rel: str, src: str | None, origin: str, data: bytes | None = None,
                 mode: int | None = None, override_built: bool = False) -> None:
        self._check_new(rel, origin, override_built)
        self._parents(rel)
        dst = os.path.join(self.root, rel)
        if data is None:
            st = os.stat(src)
            if mode is None:
                mode = 0o755 if st.st_mode & 0o111 else 0o644
            shutil.copyfile(src, dst)
        else:
            mode = 0o644 if mode is None else mode
            with open(dst, "wb") as f:
                f.write(data)
            src = None
        os.chmod(dst, 0o755 if mode & 0o111 else 0o644)
        self.e[rel] = Entry("file", mode, origin, src=dst)

    def add_link(self, rel: str, target: str, origin: str, override_built: bool = False) -> None:
        self._check_new(rel, origin, override_built)
        self._parents(rel)
        os.symlink(target, os.path.join(self.root, rel))
        self.e[rel] = Entry("link", 0o777, origin, target=target)

    def add_chr(self, rel: str, mode: int, major: int, minor: int, origin: str) -> None:
        self._parents(rel)
        self.e[rel] = Entry("chr", mode, origin, rdev=(major, minor))

    def remove(self, rel: str) -> None:
        ent = self.e.pop(rel)
        p = os.path.join(self.root, rel)
        if ent.kind in ("file", "link") and os.path.lexists(p):
            os.unlink(p)


# ---------------------------------------------------------------------------
# cpio (newc) + xz
# ---------------------------------------------------------------------------
def cpio_bytes(stage: Stage, mtime: int) -> bytes:
    out = io.BytesIO()
    ino = 0

    def hdr(name: str, mode: int, nlink: int, size: int, rdev=(0, 0)) -> None:
        nonlocal ino
        ino += 1
        nb = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, nlink, mtime, size, 0, 0, rdev[0], rdev[1], len(nb), 0]
        out.write(b"070701" + b"".join(b"%08X" % v for v in fields))
        out.write(nb)
        out.write(b"\0" * (-(110 + len(nb)) % 4))

    for rel in sorted(stage.e, key=lambda p: p.encode()):
        ent = stage.e[rel]
        if ent.kind == "dir":
            hdr(rel, stat.S_IFDIR | ent.mode, 2, 0)
        elif ent.kind == "chr":
            hdr(rel, stat.S_IFCHR | ent.mode, 1, 0, ent.rdev)
        elif ent.kind == "link":
            t = ent.target.encode()
            hdr(rel, stat.S_IFLNK | 0o777, 1, len(t))
            out.write(t + b"\0" * (-len(t) % 4))
        else:
            with open(ent.src, "rb") as f:
                d = f.read()
            m = 0o755 if ent.mode & 0o111 else 0o644
            hdr(rel, stat.S_IFREG | m, 1, len(d))
            out.write(d + b"\0" * (-len(d) % 4))
    ino_trailer = 0
    nb = b"TRAILER!!!\0"
    out.write(b"070701" + b"".join(b"%08X" % v for v in
                                   [ino_trailer, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nb), 0]))
    out.write(nb + b"\0" * (-(110 + len(nb)) % 4))
    data = out.getvalue()
    return data + b"\0" * (-len(data) % 512)


def xz(data: bytes) -> bytes:
    # The kernel's XZ decoder needs CRC32 (or no) checks and supports LZMA2 (+BCJ);
    # one LZMA2 filter, dictionary capped at the input size.
    dict_size = 1 << max(20, min(26, (len(data) - 1).bit_length()))
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32,
                         filters=[{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,
                                   "dict_size": dict_size}])


# ---------------------------------------------------------------------------
# Kernel modules
# ---------------------------------------------------------------------------
def modname(path: str) -> str:
    b = os.path.basename(path)
    return re.sub(r"\.ko(\.\w+)?$", "", b).replace("-", "_")


def read_modules_list(path: str) -> list[tuple[str, bool, int]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = bnlib.strip_comment(raw)
            if not line:
                continue
            neg = line.startswith("!")
            out.append((line[1:] if neg else line, neg, n))
    return out


def select_modules(moddir: str, listfile: str) -> tuple[list[str], dict[str, list[str]]]:
    """Return (sorted module paths relative to moddir, {pattern: matches})."""
    dep: dict[str, list[str]] = {}
    with open(os.path.join(moddir, "modules.dep"), encoding="utf-8") as f:
        for line in f:
            k, _, v = line.partition(":")
            dep[k.strip()] = v.split()
    byname = {modname(p): p for p in dep}
    soft: dict[str, list[str]] = {}
    for fn, rx in (("modules.softdep", r"^softdep\s+(\S+)\s+(.*)$"),
                   ("modules.weakdep", r"^weakdep\s+(\S+)\s+(.*)$")):
        p = os.path.join(moddir, fn)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                m = re.match(rx, line.strip())
                if m:
                    names = [w for w in m.group(2).split() if not w.endswith(":")]
                    soft.setdefault(m.group(1).replace("-", "_"), []).extend(names)

    roots: set[str] = set()
    matches: dict[str, list[str]] = {}
    for pat, neg, n in read_modules_list(listfile):
        if "/" in pat:
            rx = bnlib.glob_regex(pat)
            hit = [p for p in dep if rx.match(re.sub(r"\.ko(\.\w+)?$", "", p[len("kernel/"):]))]
        else:
            rx = bnlib.glob_regex(pat.replace("-", "_"))
            hit = [p for name, p in byname.items() if rx.match(name)]
        if not hit:
            raise BuildError(f"{listfile}:{n}: '{pat}' matches no module of this kernel")
        matches[("!" if neg else "") + pat] = sorted(hit)
        if neg:
            roots.difference_update(hit)
        else:
            roots.update(hit)

    sel: set[str] = set()
    todo = sorted(roots)
    while todo:
        p = todo.pop()
        if p in sel:
            continue
        sel.add(p)
        todo.extend(dep.get(p, []))
        for s in soft.get(modname(p), []):
            q = byname.get(s.replace("-", "_"))
            if q:
                todo.append(q)
    return sorted(sel), matches


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True)
    ap.add_argument("--debs", required=True)
    ap.add_argument("--userland", required=True)
    ap.add_argument("--modules", required=True)
    ap.add_argument("--app", help="beastnet/ directory of the repo (rootfs/, python/beastnet/)")
    ap.add_argument("--sde", type=int, required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--out-initrd", required=True)
    ap.add_argument("--out-contents", required=True)
    ap.add_argument("--out-info", required=True)
    a = ap.parse_args()

    lock = bnlib.read_lock(a.lock)
    pk = {e.name: e for e in lock}
    kernels = [e for e in lock if e.role == "kernel"]
    modpkgs = [e for e in lock if e.role == "modules"]
    if len(kernels) != 1 or len(modpkgs) != 1:
        raise BuildError("packages.lock needs exactly one 'kernel' and one 'modules' package")
    kver = kernels[0].name[len("linux-image-"):]
    if modpkgs[0].name != f"linux-modules-{kver}" or modpkgs[0].version != kernels[0].version:
        raise BuildError(f"{modpkgs[0].key} is not the module package of {kernels[0].key}")

    pool = os.path.join(a.work, "pool")
    for e in lock:
        deb = os.path.join(a.debs, e.filename)
        if bnlib.sha256_file(deb) != e.sha256:
            raise BuildError(f"{deb}: SHA-256 differs from packages.lock")
        if e.role != "kernel":
            bnlib.extract_deb(deb, os.path.join(pool, e.name))
    def ptree(name: str) -> str:
        return os.path.join(pool, name)

    def origin(name: str, rel: str) -> str:
        return f"deb:{pk[name].key}:/{rel}"

    st = Stage(a.stage)
    for link, target in MERGED_USR.items():
        st.add_link(link, target, "built:merged /usr")
    st.add_link("lib/modules", "../usr/lib/modules", "built:kmod looks in /lib/modules")
    for d, mode in DIRS.items():
        st.add_dir(d, mode)
    st.add_chr("dev/console", 0o600, 5, 1, "built:device node")
    for rel, text in ETC_FILES.items():
        st.add_file(rel, None, "built:build/beastnet/mkinitrd.py", data=text.encode())

    # --- userland from tool/data packages --------------------------------------
    userland = bnlib.read_userland(a.userland)
    excl = [bnlib.glob_regex(g) for g in userland.excludes]
    excluded = lambda rel: any(r.match(rel) for r in excl)  # noqa: E731
    for name, globs in userland.takes.items():
        if name not in pk:
            raise BuildError(f"userland.list names {name}, which is not in packages.lock")
        rxs = [(g, bnlib.glob_regex(g)) for g in globs]
        hit = {g: 0 for g in globs}
        for rel, is_link in bnlib.walk_files(ptree(name)):
            ok = [g for g, r in rxs if r.match(rel)]
            if not ok:
                continue
            for g in ok:
                hit[g] += 1
            if excluded(rel):
                continue
            src = os.path.join(ptree(name), rel)
            if is_link:
                st.add_link(canon(rel), os.readlink(src), origin(name, rel))
            else:
                st.add_file(canon(rel), src, origin(name, rel))
        for g, c in hit.items():
            if c == 0:
                raise BuildError(f"userland.list: '{name} {g}' matches nothing in {pk[name].key}")

    # --- generated: python3, busybox applets, CA bundle, OpenSSL default paths ---
    st.add_link("usr/bin/python3", "python3.14", "built:python3 -> python3.14 (as python3-minimal)")
    # busybox is dynamically linked: list its applets with the locked glibc, not the host's.
    if "busybox" not in pk or "libc6" not in pk:
        raise BuildError("packages.lock needs busybox and libc6")
    bb = os.path.join(ptree("busybox"), "usr/bin/busybox")
    applets = bnlib.tree_exec(ptree("libc6"), bb, "busybox", ["--list-full"], check=True,
                              capture_output=True, text=True).stdout.split()
    n_app = 0
    for ap_path in sorted(applets):
        top, _, rest = ap_path.partition("/")
        rel = {"bin": "usr/bin/", "sbin": "usr/sbin/"}.get(top, top + "/") + rest
        if not rel.startswith("usr/") or rel.endswith("/busybox") or st.has(rel) or excluded(rel):
            continue  # userland.list "exclude" also drops applet links (the code stays in busybox)
        st.add_link(rel, "/usr/bin/busybox", f"built:busybox applet link ({pk['busybox'].key})")
        n_app += 1

    ca = pk.get("ca-certificates")
    if ca is None:
        raise BuildError("packages.lock has no ca-certificates")
    cadir = os.path.join(ptree("ca-certificates"), "usr/share/ca-certificates")
    certs = sorted((os.path.relpath(os.path.join(d, f), cadir)
                    for d, _, fs in os.walk(cadir) for f in fs if f.endswith(".crt")),
                   key=lambda s: s.encode())
    bundle = b""
    for c in certs:
        d = open(os.path.join(cadir, c), "rb").read()
        bundle += d if d.endswith(b"\n") else d + b"\n"
    if len(certs) < 50:
        raise BuildError(f"only {len(certs)} certificates in {ca.key}")
    st.add_file("etc/ssl/certs/ca-certificates.crt", None,
                f"built:all {len(certs)} certificates of deb:{ca.key}:/usr/share/ca-certificates/**/*.crt "
                "concatenated in file name order (what update-ca-certificates writes)", data=bundle)
    st.add_link("usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "built:OpenSSL default CA file")
    st.add_link("usr/lib/ssl/certs", "/etc/ssl/certs", "built:OpenSSL default CA dir")

    # --- the app (beastnet/) -------------------------------------------------------
    app_files = 0
    runtime = {}
    if a.app:
        rootfs = os.path.join(a.app, "rootfs")
        pydir = os.path.join(a.app, "python", "beastnet")
        for need in (os.path.join(rootfs, "init"), os.path.join(pydir, "__init__.py")):
            if not os.path.exists(need):
                raise BuildError(f"{need} not found (beastnet app incomplete)")
        for rel, is_link in bnlib.walk_files(rootfs):
            if os.path.basename(rel).startswith(".") or rel.endswith(("~", ".swp")):
                continue
            src = os.path.join(rootfs, rel)
            o = "repo:" + os.path.relpath(src, ROOT)
            if is_link:
                st.add_link(rel, os.readlink(src), o, override_built=True)
            else:
                st.add_file(rel, src, o, override_built=True)
            app_files += 1
        for rel, is_link in bnlib.walk_files(pydir):
            if "__pycache__" in rel.split("/") or rel.endswith((".pyc", "~", ".swp")) or \
                    os.path.basename(rel).startswith("."):
                continue
            src = os.path.join(pydir, rel)
            dst = "usr/lib/python3/dist-packages/beastnet/" + rel
            if is_link:
                raise BuildError(f"{src}: symlinks are not allowed in the Python package")
            st.add_file(dst, src, "repo:" + os.path.relpath(src, ROOT), mode=0o644)
            app_files += 1
        init = st.e.get("init")
        if init is None or init.kind != "file":
            raise BuildError("beastnet/rootfs/init must be a regular file")
        init.mode = 0o755
        os.chmod(os.path.join(st.root, "init"), 0o755)
        rj = os.path.join(a.app, "runtime.json")
        if os.path.exists(rj):
            runtime = json.load(open(rj, encoding="utf-8"))
            if not isinstance(runtime, dict):
                raise BuildError(f"{rj}: expected a JSON object")

    # runtime.json "files": paths that must be shipped (taken from any locked
    # package if userland.list did not already include them)
    for p in runtime.get("files", []):
        rel = p.lstrip("/")
        if st.has(rel):
            continue
        cands = [e.name for e in lock if e.role in ("tool", "lib", "data")
                 and os.path.lexists(os.path.join(ptree(e.name), rel))]
        if not cands:
            raise BuildError(f"runtime.json needs {p}, which no locked package ships")
        src = os.path.join(ptree(cands[0]), rel)
        if os.path.islink(src):
            st.add_link(rel, os.readlink(src), origin(cands[0], rel))
        else:
            st.add_file(rel, src, origin(cands[0], rel))

    # --- shared libraries: DT_NEEDED closure against the locked packages -------
    lib_pkgs = [e.name for e in lock if e.role in ("lib", "tool")]
    provides: dict[str, tuple[str, str]] = {}
    for name in lib_pkgs:
        for d in bnlib.LIB_DIRS:
            full = os.path.join(ptree(name), d)
            if os.path.isdir(full):
                for fn in sorted(os.listdir(full)):
                    provides.setdefault(fn, (name, f"{d}/{fn}"))

    def ship_chain(name: str, rel: str) -> None:
        """Ship REL from package NAME plus every symlink hop to its final file."""
        seen = 0
        rel = canon(rel)
        while True:
            seen += 1
            if seen > 20:
                raise BuildError(f"symlink loop at {name}:/{rel}")
            if st.has(rel):
                ent = st.e[rel]
                if ent.kind != "link":
                    return
                rel = canon(os.path.join(os.path.dirname(rel), ent.target)
                            if not ent.target.startswith("/") else ent.target)
                continue
            src = os.path.join(ptree(name), rel)
            if os.path.islink(src):
                t = os.readlink(src)
                st.add_link(rel, t, origin(name, rel))
                rel = canon(os.path.join(os.path.dirname(rel), t) if not t.startswith("/") else t)
                continue
            if not os.path.isfile(src):
                raise BuildError(f"{name}:/{rel} does not exist")
            st.add_file(rel, src, origin(name, rel))
            return

    unresolved: list[str] = []
    done: set[str] = set()
    changed = True
    while changed:
        changed = False
        for rel in sorted(st.e):
            ent = st.e[rel]
            if ent.kind != "file" or rel in done:
                continue
            done.add(rel)
            info = bnlib.elf_info(ent.src)
            if info is None:
                continue
            wants = list(info.needed)
            if info.interp:
                if not bnlib.resolve_in_tree(st.root, info.interp.lstrip("/")):
                    name = provides.get(os.path.basename(info.interp), (None,))[0]
                    if name is None:
                        unresolved.append(f"/{rel}: interpreter {info.interp}")
                        continue
                    ship_chain(name, info.interp.lstrip("/"))
                    changed = True
            rp = [p.replace("$ORIGIN", "/" + os.path.dirname(rel)).lstrip("/") for p in info.runpath]
            for so in wants:
                if any(bnlib.resolve_in_tree(st.root, f"{d}/{so}") for d in rp + list(bnlib.LIB_DIRS)):
                    continue
                if so not in provides:
                    unresolved.append(f"/{rel}: {so}")
                    continue
                ship_chain(*provides[so])
                changed = True
    if unresolved:
        raise BuildError("unresolved shared libraries (add the package to packages.in and run lock.py):\n  "
                         + "\n  ".join(unresolved))

    # --- kernel modules ------------------------------------------------------------
    mtree = ptree(modpkgs[0].name)
    os.symlink("usr/lib", os.path.join(mtree, "lib"))
    full_moddir = os.path.join(mtree, "usr/lib/modules", kver)
    emptyconf = tempfile.mkdtemp(dir=a.work)

    def depmod(base: str) -> None:
        r = bnlib.tree_exec(st.root, "usr/bin/kmod", "depmod",
                            ["-b", base, "-C", emptyconf, kver], capture_output=True, text=True)
        if r.returncode != 0 or r.stderr.strip():
            raise BuildError(f"depmod -b {base} failed:\n{r.stderr}")

    depmod(mtree)
    mods, matches = select_modules(full_moddir, a.modules)
    builtin = set()
    with open(os.path.join(full_moddir, "modules.builtin"), encoding="utf-8") as f:
        builtin = {modname(line.strip()) for line in f if line.strip()}
    for p in mods:
        rel = f"usr/lib/modules/{kver}/{p}"
        st.add_file(rel, os.path.join(full_moddir, p), origin(modpkgs[0].name, rel), mode=0o644)
    for fn in ("modules.order", "modules.builtin", "modules.builtin.modinfo"):
        rel = f"usr/lib/modules/{kver}/{fn}"
        st.add_file(rel, os.path.join(full_moddir, fn), origin(modpkgs[0].name, rel), mode=0o644)
    depmod(st.root)
    mdir = os.path.join(st.root, f"usr/lib/modules/{kver}")
    for fn in sorted(os.listdir(mdir)):
        rel = f"usr/lib/modules/{kver}/{fn}"
        if fn.startswith("modules.") and not st.has(rel):
            st.e[rel] = Entry("file", 0o644, f"built:depmod of the module subset ({pk['kmod'].key})",
                              src=os.path.join(mdir, fn))
    # every shipped module must be signed, all with the same key (Canonical's
    # per-build key, trusted by the signed kernel) - checked again in QEMU
    mi = bnlib.modinfo_all(st.root, [os.path.join(st.root, f"usr/lib/modules/{kver}/{p}") for p in mods])
    unsigned = [m for m, d in mi.items() if not d.get("signer")]
    if unsigned:
        raise BuildError(f"unsigned modules: {unsigned[:5]} ...")
    signers = {(d["signer"][0], d.get("sig_key", ["?"])[0]) for d in mi.values()}
    if len(signers) != 1:
        raise BuildError(f"modules are signed with {len(signers)} different keys: {sorted(signers)}")
    signer, sig_key = signers.pop()

    # --- runtime.json binaries -----------------------------------------------------
    for b in runtime.get("binaries", []):
        cands = [b.lstrip("/")] if "/" in b else [f"usr/bin/{b}", f"usr/sbin/{b}"]
        if not any(bnlib.resolve_in_tree(st.root, c) for c in cands):
            raise BuildError(f"runtime.json needs binary {b}, which is not shipped "
                             "(no locked package / busybox applet provides it)")

    # --- smoke test: the shipped Python, run from the stage -----------------------
    py_mods = REQUIRED_PY + [m for m in runtime.get("python_modules", []) if m not in REQUIRED_PY]
    code = (
        "import importlib, importlib.util, sys\n"
        f"mods = {py_mods!r}\n"
        "bad = []\n"
        "for m in mods:\n"
        "    try: importlib.import_module(m)\n"
        "    except Exception as e: bad.append(f'{m}: {e!r}')\n"
        "import ssl, curses\n"
        "ctx = ssl.create_default_context(cafile=sys.argv[1])\n"
        "n = ctx.cert_store_stats()['x509_ca']\n"
        "if n < 50: bad.append(f'CA bundle: only {n} CAs')\n"
        f"for t in {TERMINALS!r}:\n"
        "    try: curses.setupterm(t, 1)\n"
        "    except Exception as e: bad.append(f'terminfo {t}: {e!r}')\n"
        "if sys.argv[2] == '1' and importlib.util.find_spec('beastnet') is None:\n"
        "    bad.append('beastnet not on sys.path')\n"
        "print(ssl.OPENSSL_VERSION, '|', sys.version.split()[0], '|', n, 'CAs')\n"
        "if bad: print('\\n'.join(bad), file=sys.stderr); sys.exit(1)\n")
    env = {"PYTHONHOME": os.path.join(st.root, "usr"), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1", "LC_ALL": "C",
           "TERMINFO": os.path.join(st.root, "usr/share/terminfo"), "PATH": "/usr/bin:/bin"}
    with tempfile.TemporaryDirectory(dir=a.work) as cwd:
        r = bnlib.tree_exec(st.root, "usr/bin/python3.14", "python3", ["-c", code,
                            os.path.join(st.root, "etc/ssl/certs/ca-certificates.crt"),
                            "1" if a.app else "0"], capture_output=True, text=True, env=env, cwd=cwd)
    if r.returncode != 0:
        raise BuildError(f"Python smoke test failed:\n{r.stdout}{r.stderr}")
    py_report = r.stdout.strip()
    log(f"python smoke test ok: {py_report}")

    # --- leftovers check: every stage symlink must resolve inside the stage -------
    for rel, ent in sorted(st.e.items()):
        if ent.kind == "link":
            if bnlib.resolve_in_tree(st.root, rel) is None:
                raise BuildError(f"/{rel} -> {ent.target} points to nothing in the initramfs")

    # --- write ------------------------------------------------------------------------
    cpio = cpio_bytes(st, a.sde)
    blob = xz(cpio)
    with open(a.out_initrd + ".tmp", "wb") as f:
        f.write(blob)
    os.replace(a.out_initrd + ".tmp", a.out_initrd)

    files = []
    used: dict[str, int] = {}
    for rel in sorted(st.e, key=lambda p: p.encode()):
        ent = st.e[rel]
        item = {"path": "/" + rel, "type": ent.kind, "origin": ent.origin}
        if ent.kind == "file":
            item["mode"] = "0755" if ent.mode & 0o111 else "0644"
            item["size"] = os.path.getsize(ent.src)
            item["sha256"] = bnlib.sha256_file(ent.src)
        elif ent.kind == "link":
            item["target"] = ent.target
        elif ent.kind == "chr":
            item["rdev"] = f"{ent.rdev[0]}:{ent.rdev[1]}"
        files.append(item)
        for nm in re.findall(r"(?:deb:|\()([a-z0-9][a-z0-9.+-]*)=", ent.origin):
            used[nm] = used.get(nm, 0) + (1 if ent.origin.startswith(f"deb:{nm}=") else 0)
    unused = [e.name for e in lock if e.role != "kernel" and e.name not in used]
    if unused:
        raise BuildError(f"locked packages that contribute nothing: {unused} (re-run lock.py)")
    contents = {
        "v": 1, "kernel": kver, "source_date_epoch": a.sde,
        "initrd": {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob),
                   "cpio_sha256": hashlib.sha256(cpio).hexdigest(), "cpio_size": len(cpio),
                   "format": "newc cpio, xz (LZMA2, CRC32)"},
        "packages": [{"name": e.name, "version": e.version, "arch": e.arch, "deb_sha256": e.sha256,
                      "role": e.role, "files": used.get(e.name, 0)} for e in lock],
        "modules": {"count": len(mods), "signer": signer, "sig_key": sig_key,
                    "list": [modname(p) for p in mods]},
        "files": files,
    }
    with open(a.out_contents, "w", encoding="utf-8") as f:
        json.dump(contents, f, indent=1, sort_keys=False)
        f.write("\n")
    info = {
        "kernel": kver, "kernel_pkg": kernels[0].key, "modules_pkg": modpkgs[0].key,
        "packages": [e.key for e in lock if e.role != "kernel"],
        "modules": [{"name": modname(p), "path": f"usr/lib/modules/{kver}/{p}"} for p in mods],
        "builtin": sorted(builtin), "n_files": len(files), "n_applets": n_app, "app_files": app_files,
        "python": py_report, "signer": signer,
        "initrd_size": len(blob), "cpio_size": len(cpio),
    }
    with open(a.out_info, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=1)
    log(f"initrd: {len(st.e)} entries, {len(mods)} modules, {n_app} busybox applets, "
        f"{len(cpio) / 1e6:.1f} MB cpio -> {len(blob) / 1e6:.1f} MB xz")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as e:
        print(f"beastnet: error: {e}", file=sys.stderr)
        sys.exit(1)
