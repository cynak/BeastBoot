#!/usr/bin/env python3
"""Check a beast-booter portable package against its PACKAGE-MANIFEST.json.

    python3 verify-package.py              # the package folder this script is in
    python3 verify-package.py FOLDER       # an unpacked package
    python3 verify-package.py PACKAGE.zip  # or .tar.gz, checked without unpacking

    runtime/bin/python3 -I -S -B verify-package.py   # with the package's own Python:
                                                     # -B is required, see below

What it checks:
  * every file listed in PACKAGE-MANIFEST.json is present with the listed
    SHA-256 and size; symlinks point where they should; executable bits are set
    (exact permissions for archives; not checkable on Windows folders);
  * nothing else is in the package. In an archive, any extra entry is an error.
    In an unpacked folder, an extra file is an error inside runtime/, app/ and
    payload/ (all of BeastBooter.app on macOS), and anywhere if it is code
    (.py, .pyc, .pth, .dll, .so, ...), because Python or the system could load
    it from there. Other extra files are only reported, such as .DS_Store or a
    disk image you saved into the folder;
  * the package holds no Python bytecode (.pyc): Python would run a .pyc instead
    of the .py file you can read. The bundled Python writes .pyc files into the
    package when it runs without -B, so always pass -B when you run it yourself;
  * the boot files match payload/dist/manifest.json (the same check the
    installer makes before it writes a drive);
  * the layout for the package's OS: bundled runtime, launchers (CRLF line
    endings for .cmd, LF for sh scripts), Info.plist on macOS.

This proves the files are the ones the package was built with. It cannot prove
the package itself is genuine: compare the archive's SHA-256 with the published
SHA256SUMS first (README.txt says how). Standard library only; any Python 3.8+
works (your own, or runtime/ of this package with -I -S -B).
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import posixpath
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

MANIFEST_NAME = "PACKAGE-MANIFEST.json"
MAC_RES = "BeastBooter.app/Contents/Resources/"
BYTECODE_SUFFIXES = (".pyc", ".pyo")
# Unlisted files with these suffixes are errors anywhere in an unpacked package:
# Python, the dynamic loader or a shell could run them.
CODE_SUFFIXES = BYTECODE_SUFFIXES + (
    ".py", ".pyw", ".pth", ".so", ".dylib", ".dll", ".pyd", ".exe", ".cmd", ".bat",
    ".ps1", ".vbs", ".js", ".sh", ".command", ".desktop", ".tcl", ".tm",
)
# Files that file managers and operating systems add to folders: only reported.
CLUTTER_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", "Icon\r"}


class Node:
    """One entry of a package: kind is 'file', 'symlink', 'dir' or 'other'."""

    def __init__(self, kind, sha256=None, size=None, mode=None, target=None):
        self.kind, self.sha256, self.size, self.mode, self.target = kind, sha256, size, mode, target


def _hash_stream(f):
    h, size = hashlib.sha256(), 0
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            return h.hexdigest(), size
        h.update(chunk)
        size += len(chunk)


class Source:
    """A package to check: a folder, a .zip or a .tar.gz. Paths are relative to its top folder."""

    exact_modes = True  # archives store exact permissions
    check_modes = True

    def __init__(self):
        self.nodes = {}
        self.top = ""

    def read(self, rel):
        raise NotImplementedError

    def close(self):
        pass

    def _set_top(self, raw):
        tops = {p.split("/", 1)[0] for p in raw}
        if len(tops) != 1:
            raise ValueError(f"expected one top folder, found {len(tops)}: {sorted(tops)[:5]}")
        self.top = tops.pop()
        for p, node in raw.items():
            if p != self.top:
                self.nodes[p[len(self.top) + 1:]] = node


class DirSource(Source):
    def __init__(self, root):
        super().__init__()
        self.root = Path(root)
        self.top = self.root.name
        self.exact_modes = False  # umask and copying change permissions
        self.check_modes = os.name != "nt"
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                if os.path.islink(full):
                    self.nodes[rel] = Node("symlink", target=os.readlink(full))
                elif name in dirnames:
                    self.nodes[rel] = Node("dir")
                elif os.path.isfile(full):
                    with open(full, "rb") as f:
                        digest, size = _hash_stream(f)
                    mode = stat.S_IMODE(os.stat(full).st_mode) if self.check_modes else None
                    self.nodes[rel] = Node("file", digest, size, mode)
                else:
                    self.nodes[rel] = Node("other")

    def read(self, rel):
        return (self.root / rel).read_bytes()


class ZipSource(Source):
    def __init__(self, path):
        super().__init__()
        self.zf = zipfile.ZipFile(path)
        raw, self.names = {}, {}
        for zi in self.zf.infolist():
            name = zi.filename.rstrip("/")
            if name in raw:
                raise ValueError(f"{name}: stored twice in the zip")
            unix = zi.external_attr >> 16 if zi.create_system == 3 else 0
            if zi.is_dir():
                raw[name] = Node("dir")
            elif stat.S_ISLNK(unix):
                raw[name] = Node("symlink", target=self.zf.read(zi).decode("utf-8"))
            else:
                with self.zf.open(zi) as f:
                    digest, size = _hash_stream(f)
                raw[name] = Node("file", digest, size, stat.S_IMODE(unix) if unix else None)
            self.names[name] = zi
        self._set_top(raw)

    def read(self, rel):
        return self.zf.read(self.names[f"{self.top}/{rel}"])

    def close(self):
        self.zf.close()


class TarSource(Source):
    def __init__(self, path):
        super().__init__()
        self.tf = tarfile.open(path, "r:*")
        raw, self.members = {}, {}
        for m in self.tf:
            name = m.name.rstrip("/")
            if name in raw:
                raise ValueError(f"{name}: stored twice in the archive")
            if m.isdir():
                raw[name] = Node("dir")
            elif m.issym():
                raw[name] = Node("symlink", target=m.linkname)
            elif m.isreg():
                f = self.tf.extractfile(m)
                digest, size = _hash_stream(f)
                raw[name] = Node("file", digest, size, stat.S_IMODE(m.mode))
            else:
                raw[name] = Node("other")
            self.members[name] = m
        self._set_top(raw)

    def read(self, rel):
        return self.tf.extractfile(self.members[f"{self.top}/{rel}"]).read()

    def close(self):
        self.tf.close()


def open_source(path):
    path = Path(path)
    if path.is_dir():
        if not (path / MANIFEST_NAME).is_file():  # a folder that holds one unpacked package
            inner = [p for p in path.iterdir() if (p / MANIFEST_NAME).is_file()]
            if len(inner) != 1:
                raise ValueError(f"{path}: no {MANIFEST_NAME} here (or more than one package below)")
            path = inner[0]
        return DirSource(path)
    if path.name.endswith(".zip"):
        return ZipSource(path)
    if path.name.endswith((".tar.gz", ".tgz", ".tar")):
        return TarSource(path)
    raise ValueError(f"{path}: not a folder, .zip or .tar.gz")


def resolve(nodes, path, hops=0):
    """Follow symlinks inside the package; returns (path, node) or (path, None)."""
    node = nodes.get(path)
    if node is None or node.kind != "symlink":
        return path, node
    if hops > 20 or node.target.startswith("/"):
        return path, None
    nxt = posixpath.normpath(posixpath.join(posixpath.dirname(path), node.target))
    if nxt.startswith("../") or nxt == "..":
        return path, None
    return resolve(nodes, nxt, hops + 1)


def code_folders(manifest):
    """Folders of an unpacked package in which every extra file is an error."""
    if str(manifest.get("target", "")).startswith("macos"):
        return ("BeastBooter.app/",)
    return ("runtime/", "app/", "payload/")


def is_clutter(path):
    name = posixpath.basename(path)
    return name in CLUTTER_NAMES or name.startswith("._")  # ._*: macOS metadata on FAT/exFAT


BYTECODE_HELP = (
    "the package holds no bytecode: these .pyc files were added after unpacking. Python "
    "would run them instead of the .py files, so they cannot be trusted. Running the "
    "bundled Python without -B leaves such files: unpack the package again, then check "
    "with -B (for example: runtime/bin/python3 -I -S -B verify-package.py)"
)
MAX_LISTED = 10  # bytecode files named one by one; the rest are counted


def unlisted_problem(path, node, manifest):
    """Why an entry that is not in the manifest matters, or None if it is harmless."""
    if is_clutter(path) and node.kind == "file":
        return None
    if node.kind != "file":
        return f"{path}: unexpected {node.kind} that is not part of the package"
    if path.startswith(code_folders(manifest)) or path.lower().endswith(CODE_SUFFIXES):
        return (f"{path}: not part of the package, and Python or the system could load it from "
                "here (added after unpacking?)")
    return None


def check_files(src, manifest, errors, warnings):
    if str(manifest.get("target", "")).startswith("windows"):
        src.check_modes = False  # Windows has no exec bits; unzip tools differ in what they set
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        errors.append(f"{MANIFEST_NAME}: no \"files\"")
        return
    for path, meta in sorted(files.items()):
        node = src.nodes.get(path)
        if node is None:
            errors.append(f"{path}: missing")
        elif "symlink" in meta:
            if node.kind != "symlink":
                errors.append(f"{path}: should be a symlink to {meta['symlink']}, is a {node.kind}")
            elif node.target != meta["symlink"]:
                errors.append(f"{path}: symlink points to {node.target}, expected {meta['symlink']}")
        elif node.kind != "file":
            errors.append(f"{path}: should be a file, is a {node.kind}")
        elif node.sha256 != meta.get("sha256") or node.size != meta.get("size"):
            errors.append(f"{path}: content differs (sha256 {node.sha256[:12]}..., expected {str(meta.get('sha256'))[:12]}...)")
        elif node.mode is not None and "mode" in meta and src.check_modes:
            want = int(meta["mode"], 8)
            if src.exact_modes and node.mode != want:
                errors.append(f"{path}: mode {node.mode:04o}, expected {want:04o}")
            elif not src.exact_modes and bool(node.mode & 0o100) != bool(want & 0o100):
                errors.append(f"{path}: executable bit is {'set' if node.mode & 0o100 else 'missing'}"
                              f" (expected mode {want:04o})")
    bytecode = []
    for path, node in sorted(src.nodes.items()):
        if node.kind == "dir" or path == MANIFEST_NAME or path in files:
            continue
        if src.exact_modes:
            errors.append(f"{path}: in the archive but not in {MANIFEST_NAME}")
        elif node.kind == "file" and path.lower().endswith(BYTECODE_SUFFIXES):
            bytecode.append(path)
        else:
            problem = unlisted_problem(path, node, manifest)
            if problem:
                errors.append(problem)
            else:
                warnings.append(f"{path}: not part of the package (added after unpacking?)")
    if bytecode:
        errors.extend(f"{path}: Python bytecode, not part of the package" for path in bytecode[:MAX_LISTED])
        if len(bytecode) > MAX_LISTED:
            errors.append(f"... and {len(bytecode) - MAX_LISTED} more .pyc files")
        errors.append(BYTECODE_HELP)


def check_dist(src, manifest, errors):
    """payload/dist must match its own manifest.json, like the installer requires.

    Files added after unpacking are reported by check_files; this checks that the
    package's own boot files and dist/manifest.json agree.
    """
    dist = (MAC_RES if str(manifest.get("target", "")).startswith("macos") else "") + "payload/dist"
    try:
        dm = json.loads(src.read(f"{dist}/manifest.json"))
        listed = dm["files"]
    except (KeyError, OSError, ValueError, TypeError) as e:
        errors.append(f"{dist}/manifest.json: cannot read it ({e})")
        return
    for p, meta in sorted(listed.items()):
        node = src.nodes.get(f"{dist}/{p}")
        if node is None or node.kind != "file":
            errors.append(f"{dist}/{p}: boot file missing")
        elif node.sha256 != str(meta.get("sha256", "")).lower():
            errors.append(f"{dist}/{p}: does not match {dist}/manifest.json")
    for path in manifest.get("files", {}):
        if path.startswith(dist + "/"):
            rel = path[len(dist) + 1:]
            if rel != "manifest.json" and rel not in listed:
                errors.append(f"{path}: not listed in {dist}/manifest.json")


def check_layout(src, manifest, errors):
    """The files each OS needs to start, with the right line endings and exec bits."""
    target = str(manifest.get("target", ""))
    os_name = target.split("-", 1)[0]
    nodes = src.nodes

    def need_file(path, executable=False):
        real, node = resolve(nodes, path)
        if node is None or node.kind != "file":
            errors.append(f"{path}: required file missing")
            return False
        if executable and src.check_modes and node.mode is not None and not node.mode & 0o100:
            errors.append(f"{path}: must be executable")
        return True

    def text(path, *, crlf):
        if not need_file(path, executable=not crlf and os_name != "windows"):
            return ""
        data = src.read(path)
        if crlf and b"\n" in data.replace(b"\r\n", b""):
            errors.append(f"{path}: has LF-only line endings (cmd.exe needs CRLF)")
        if not crlf and b"\r" in data:
            errors.append(f"{path}: has CR characters (sh needs LF line endings)")
        return data.decode("utf-8", "replace")

    def glob_one(prefix, suffix):
        return any(p.startswith(prefix) and p.endswith(suffix) for p in nodes)

    res = MAC_RES if os_name == "macos" else ""
    for p in ("README.txt", "LICENSE", "verify-package.py", f"{res}VERSION",
              f"{res}app/beast_booter_launch.py", f"{res}app/beastbooter/__init__.py",
              f"{res}app/beastbooter/cli.py", f"{res}payload/dist/manifest.json",
              f"{res}docs/SECURE_BOOT.md"):
        need_file(p)
    bytecode = [p for p in manifest.get("files", {}) if p.lower().endswith(BYTECODE_SUFFIXES)]
    if bytecode:
        errors.append(f"{MANIFEST_NAME}: the package must not contain bytecode: {bytecode[:3]}")
    if f"{res}VERSION" in nodes:
        found = src.read(f"{res}VERSION").decode("utf-8", "replace").strip()
        if found != manifest.get("version"):
            errors.append(f"{res}VERSION says {found!r}, the manifest says {manifest.get('version')!r}")

    if os_name == "linux":
        for sh in ("BeastBooter", "beast-booter"):
            if not text(sh, crlf=False).startswith("#!/bin/sh\n"):
                errors.append(f"{sh}: must start with #!/bin/sh")
        if "[Desktop Entry]" not in text("beast-booter.desktop", crlf=False):
            errors.append("beast-booter.desktop: no [Desktop Entry] group")
        need_file("runtime/bin/python3", executable=True)
        if not glob_one("runtime/lib/python3.", "/tkinter/__init__.py"):
            errors.append("runtime: tkinter is missing (the GUI needs it)")
    elif os_name == "windows":
        gui = text("BeastBooter.cmd", crlf=True)
        cli = text("beast-booter.cmd", crlf=True)
        if "runtime\\pythonw.exe" not in gui or "start " not in gui:
            errors.append("BeastBooter.cmd: must start runtime\\pythonw.exe with start (no console window)")
        if "runtime\\python.exe" not in cli:
            errors.append("beast-booter.cmd: must run runtime\\python.exe")
        if b"\n" in src.read("README.txt").replace(b"\r\n", b""):
            errors.append("README.txt: Windows package README must have CRLF line endings")
        for p in ("runtime/python.exe", "runtime/pythonw.exe", "runtime/Lib/tkinter/__init__.py"):
            need_file(p)
        links = [p for p, n in nodes.items() if n.kind == "symlink"]
        if links:
            errors.append(f"Windows package must not contain symlinks: {links[:3]}")
    elif os_name == "macos":
        app = "BeastBooter.app/Contents"
        if not text(f"{app}/MacOS/BeastBooter", crlf=False).startswith("#!/bin/sh\n"):
            errors.append(f"{app}/MacOS/BeastBooter: must start with #!/bin/sh")
        if not text("beast-booter.command", crlf=False).startswith("#!/bin/sh\n"):
            errors.append("beast-booter.command: must start with #!/bin/sh")
        if need_file(f"{app}/Info.plist"):
            try:
                info = plistlib.loads(src.read(f"{app}/Info.plist"))
            except Exception as e:  # plistlib raises several exception types
                errors.append(f"{app}/Info.plist: does not parse ({e})")
                info = {}
            exe = info.get("CFBundleExecutable")
            if exe != "BeastBooter" or info.get("CFBundlePackageType") != "APPL":
                errors.append(f"{app}/Info.plist: CFBundleExecutable/CFBundlePackageType wrong")
            if info.get("CFBundleShortVersionString") != manifest.get("version"):
                errors.append(f"{app}/Info.plist: version does not match the manifest")
            if not info.get("LSMinimumSystemVersion"):
                errors.append(f"{app}/Info.plist: LSMinimumSystemVersion missing")
        py = f"{MAC_RES}runtime/bin/python3"
        if nodes.get(py) is None or nodes[py].kind != "symlink":
            errors.append(f"{py}: must be a symlink (as in the runtime); were symlinks lost?")
        need_file(py, executable=True)
        if not glob_one(f"{MAC_RES}runtime/lib/python3.", "/tkinter/__init__.py"):
            errors.append("runtime: tkinter is missing (the GUI needs it)")
    else:
        errors.append(f"{MANIFEST_NAME}: unknown target {target!r}")


def runs_without_b_from(root):
    """True if this interpreter lives inside root and may write .pyc files there."""
    if sys.flags.dont_write_bytecode:
        return False
    try:
        Path(sys.executable).resolve().relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return False
    return True


def verify_path(path):
    """Check one package; returns (errors, warnings, summary)."""
    errors, warnings = [], []
    try:
        src = open_source(path)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
        return [str(e)], [], ""
    try:
        try:
            manifest = json.loads(src.read(MANIFEST_NAME))
        except (KeyError, OSError, ValueError) as e:
            return [f"{MANIFEST_NAME}: cannot read it ({e})"], [], ""
        if manifest.get("schema") != 1:
            return [f"{MANIFEST_NAME}: unsupported schema {manifest.get('schema')!r}"], [], ""
        if manifest.get("top") != src.top and not isinstance(src, DirSource):  # folders may be renamed
            errors.append(f"top folder is {src.top!r}, the manifest says {manifest.get('top')!r}")
        if isinstance(src, DirSource) and runs_without_b_from(src.root):
            warnings.append(
                f"this check runs on the package's own Python without -B, so Python may just "
                f"have written bytecode into the package. Unpack it again and run: "
                f"{Path(sys.executable).name} -I -S -B verify-package.py")
        check_files(src, manifest, errors, warnings)
        check_dist(src, manifest, errors)
        check_layout(src, manifest, errors)
        if manifest.get("test_only"):
            warnings.append("TEST BUILD: the boot files are fake; do not use this package")
        n_links = sum(1 for m in manifest["files"].values() if "symlink" in m)
        summary = (f"{manifest.get('name')} {manifest.get('version')} {manifest.get('target')}: "
                   f"{len(manifest['files'])} entries ({n_links} symlinks) match {MANIFEST_NAME}")
        return errors, warnings, summary
    finally:
        src.close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    targets = argv or [str(Path(__file__).resolve().parent)]
    status = 0
    for t in targets:
        errors, warnings, summary = verify_path(t)
        for w in warnings:
            print(f"warning: {w}")
        for e in errors:
            print(f"ERROR: {e}")
        if errors:
            print(f"FAILED: {t}: {len(errors)} problem(s)")
            status = 1
        else:
            print(f"OK: {summary}")
    return status


if __name__ == "__main__":
    sys.exit(main())
