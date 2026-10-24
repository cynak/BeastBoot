#!/usr/bin/env python3
"""Build the no-install portable packages of beast-booter (docs/PORTABLE.md).

    python3 -I packaging/portable/build.py --all
    python3 -I packaging/portable/build.py --target linux-x86_64 [--target ...]
    python3 -I packaging/portable/build.py --all --fetch-only   # download + verify the runtimes
    python3 -I packaging/portable/build.py --verify out/portable/<package>.zip ...

Every package is one archive with one top folder that holds:

  runtime/    an official python-build-standalone CPython ("install_only" build),
              pinned with its SHA-256 in runtimes.lock, unmodified except that its
              bytecode caches (__pycache__/*.pyc) are left out (listed in the manifest)
  app/        the installer as plain .py files: installer/beastbooter/** and
              installer/beast_booter_launch.py (no tests, no bytecode)
  payload/    dist/ (the boot files, verified against dist/manifest.json) and sbom/
  docs/       SECURE_BOOT.md (the GUI links to it) and PORTABLE.md
  launchers, README.txt, LICENSE, VERSION, verify-package.py, and
  PACKAGE-MANIFEST.json: SHA-256 and origin of every other file in the package.

The package holds no bytecode at all: Python compiles every module from the .py
files you can read, and the launchers run it with -B, so it never writes any.

On macOS runtime/, app/, payload/, docs/ and VERSION live in BeastBooter.app/Contents/Resources.

Outputs go to out/portable/: beast-booter-<VERSION>-<target>.(tar.gz|zip) and
SHA256SUMS. The archives are reproducible: sorted entries, every timestamp set to
SOURCE_DATE_EPOCH (default: last git commit time, else the mtime of VERSION),
owner 0/0, permissions normalised to 0644 / 0755 (symlinks kept as symlinks).
Rebuilding from the same inputs with the same Python gives identical bytes.

Standard library only. The only network access is downloading a pinned runtime
that is not in the cache yet (.tools/cache/pbs/); --offline forbids even that.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import plistlib
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LOCK_FILE = HERE / "runtimes.lock"
LAUNCHERS = HERE / "launchers"
README_TEMPLATE = HERE / "README-PORTABLE.txt"
VERIFY_SCRIPT = HERE / "verify_package.py"
DEFAULT_CACHE = REPO / ".tools" / "cache" / "pbs"
DEFAULT_OUT = REPO / "out" / "portable"

MANIFEST_NAME = "PACKAGE-MANIFEST.json"
MANIFEST_SCHEMA = 1
DIST_MANIFEST_SCHEMA = 1
APP_NAME = "BeastBooter"
BUNDLE_ID = "org.beast-booter.BeastBooter"  # placeholder reverse-DNS id, like the SBAT project URL

# target -> (os, archive extension)
TARGETS = {
    "linux-x86_64": ("linux", "tar.gz"),
    "windows-x86_64": ("windows", "zip"),
    "macos-x86_64": ("macos", "zip"),
    "macos-arm64": ("macos", "zip"),
}
TARGET_NAMES = {
    "linux-x86_64": "Linux (x86_64)",
    "windows-x86_64": "Windows (x86_64)",
    "macos-x86_64": "macOS (Intel, x86_64)",
    "macos-arm64": "macOS (Apple silicon, arm64)",
}
MACOS_ARCH = {"macos-x86_64": "x86_64", "macos-arm64": "arm64"}
MACOS_RESOURCES = f"{APP_NAME}.app/Contents/Resources/"

# Never copied from installer/beastbooter into the package.
APP_SKIP_DIRS = {"__pycache__", "tests", "test"}
APP_SKIP_SUFFIXES = (".pyc", ".pyo", "~", ".orig", ".rej")
# Copied from docs/ into <res>docs/ (controller.docs_path looks there for SECURE_BOOT.md).
PACKAGE_DOCS = ("SECURE_BOOT.md", "PORTABLE.md")
BYTECODE_SUFFIXES = (".pyc", ".pyo")

ZIP_EPOCH_MIN = 315532800  # 1980-01-01T00:00:00Z: the earliest time a zip entry can hold
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BuildError(Exception):
    """An expected failure, printed as one message without a traceback."""


def log(msg: str) -> None:
    print(f"portable: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"portable: WARNING: {msg}", file=sys.stderr, flush=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def repo_rel(path: Path) -> str:
    return path.resolve().relative_to(REPO).as_posix()


def check_member_path(p: str) -> None:
    """A path inside a package or archive: relative, '/'-separated, no '..'."""
    if (
        not p
        or p.startswith("/")
        or "\\" in p
        or "\0" in p
        or posixpath.normpath(p) != p
        or p == ".."
        or p.startswith("../")
    ):
        raise BuildError(f"invalid path {p!r}")


@contextlib.contextmanager
def atomic_output(dest: Path):
    """Yield a temp path next to dest; on success rename it over dest (all or nothing)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
    os.close(fd)
    try:
        yield Path(tmp)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# Pinned runtimes (runtimes.lock) and the download cache
# ---------------------------------------------------------------------------


def read_lock() -> dict:
    try:
        lock = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BuildError(f"cannot read {LOCK_FILE}: {e}") from None
    if not isinstance(lock, dict) or lock.get("schema") != 1:
        raise BuildError(f"{LOCK_FILE}: unsupported lock file (expected \"schema\": 1)")
    if not re.fullmatch(r"3\.\d+\.\d+", str(lock.get("python", ""))):
        raise BuildError(f"{LOCK_FILE}: \"python\" must be a version like 3.13.17")
    targets = lock.get("targets")
    if not isinstance(targets, dict):
        raise BuildError(f"{LOCK_FILE}: \"targets\" missing")
    for t in TARGETS:
        spec = targets.get(t)
        if not isinstance(spec, dict):
            raise BuildError(f"{LOCK_FILE}: no runtime pinned for {t}")
        asset, url, digest = spec.get("asset"), spec.get("url"), spec.get("sha256")
        if not isinstance(asset, str) or "/" in asset or not asset.endswith(".tar.gz"):
            raise BuildError(f"{LOCK_FILE}: {t}: bad asset name {asset!r}")
        parsed = urllib.parse.urlparse(str(url))
        if parsed.scheme != "https" or urllib.parse.unquote(posixpath.basename(parsed.path)) != asset:
            raise BuildError(f"{LOCK_FILE}: {t}: url must be https and end in the asset name")
        if not isinstance(digest, str) or not HEX64.match(digest):
            raise BuildError(f"{LOCK_FILE}: {t}: sha256 must be 64 lowercase hex digits")
    return lock


def fetch_runtime(spec: dict, cache_dir: Path, *, offline: bool) -> Path:
    """Make sure the pinned runtime archive is in the cache with the right SHA-256."""
    path = cache_dir / spec["asset"]
    problem = f"is not in {cache_dir}"
    if path.is_file():
        if sha256_file(path) == spec["sha256"]:
            return path
        problem = f"in {cache_dir} does not match the SHA-256 pinned in runtimes.lock"
    if offline:
        raise BuildError(f"{spec['asset']} {problem} (and --offline was given)")
    if path.is_file():
        warn(f"cached {path} does not match the pinned SHA-256; fetching it again")
    cache_dir.mkdir(parents=True, exist_ok=True)
    log(f"downloading {spec['url']}")
    # Temp file + rename: other builds sharing the cache never see a partial file.
    fd, tmp = tempfile.mkstemp(dir=cache_dir, prefix=f".{spec['asset']}.", suffix=".part")
    h = hashlib.sha256()
    try:
        req = urllib.request.Request(spec["url"], headers={"User-Agent": "beast-booter-portable-build"})
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(req, timeout=60) as resp:
            while chunk := resp.read(1 << 20):
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != spec["sha256"]:
            raise BuildError(
                f"{spec['asset']}: downloaded file has SHA-256 {h.hexdigest()}, "
                f"runtimes.lock pins {spec['sha256']}; refusing to use it"
            )
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        raise BuildError(f"download of {spec['url']} failed: {e}") from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    return path


def read_runtime(spec: dict, cache_dir: Path, *, offline: bool) -> bytes:
    """The runtime archive's bytes, hash-checked on this read (not only when downloaded)."""
    data = fetch_runtime(spec, cache_dir, offline=offline).read_bytes()
    if sha256(data) != spec["sha256"]:
        raise BuildError(f"{spec['asset']}: SHA-256 changed in the cache while building; run again")
    return data


# ---------------------------------------------------------------------------
# Inputs: dist/, sbom/, installer sources
# ---------------------------------------------------------------------------


@dataclass
class DistSnapshot:
    """A verified in-memory copy of dist/; only these bytes go into the packages."""

    root: Path
    manifest_bytes: bytes
    manifest: dict
    files: dict[str, bytes]  # path relative to dist/ -> content (hash-checked)
    test_only: bool  # made by installer/tests/fakedist.py: not bootable


def load_dist(dist_dir: Path) -> DistSnapshot:
    """Read dist/ and verify it against its manifest, like the installer does before writing."""
    if not dist_dir.is_dir():
        raise BuildError(f"dist directory not found: {dist_dir} (run `make build`, or pass --dist DIR)")
    mpath = dist_dir / "manifest.json"
    try:
        manifest_bytes = mpath.read_bytes()
        manifest = json.loads(manifest_bytes)
    except FileNotFoundError:
        raise BuildError(f"{mpath} is missing; is {dist_dir} a beast-booter dist directory?") from None
    except (OSError, ValueError) as e:
        raise BuildError(f"cannot read {mpath}: {e}") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != DIST_MANIFEST_SCHEMA:
        raise BuildError(f"{mpath}: unsupported manifest (expected \"schema\": {DIST_MANIFEST_SCHEMA})")
    listed = manifest.get("files")
    if not isinstance(listed, dict) or not listed:
        raise BuildError(f"{mpath}: \"files\" must be a non-empty object")

    problems: list[str] = []
    files: dict[str, bytes] = {}
    for p, meta in sorted(listed.items()):
        try:
            check_member_path(p)
        except BuildError:
            problems.append(f"{p!r}: invalid path in manifest")
            continue
        if p == "manifest.json" or not isinstance(meta, dict) or not isinstance(meta.get("sha256"), str):
            problems.append(f"{p}: bad manifest entry")
            continue
        full = dist_dir / p
        try:
            st = os.lstat(full)
        except FileNotFoundError:
            problems.append(f"{p}: missing")
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{p}: not a regular file")
            continue
        data = full.read_bytes()
        if sha256(data) != meta["sha256"].lower():
            problems.append(f"{p}: sha256 mismatch (manifest {meta['sha256'][:12]}..., file {sha256(data)[:12]}...)")
        files[p] = data
    # Everything in dist/ must be accounted for: no unlisted files, no symlinks.
    for dirpath, dirnames, filenames in os.walk(dist_dir):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, dist_dir).replace(os.sep, "/")
            if os.path.islink(full):
                problems.append(f"{rel}: symlinks are not allowed in dist/")
            elif name in filenames and rel != "manifest.json" and rel not in listed:
                problems.append(f"{rel}: present in dist/ but not listed in manifest.json")
    if problems:
        more = f"\n  ... and {len(problems) - 10} more" if len(problems) > 10 else ""
        raise BuildError(f"dist verification failed for {dist_dir}:\n  " + "\n  ".join(problems[:10]) + more)
    test_only = any(str(m.get("origin", "")).startswith("test:") for m in listed.values())
    return DistSnapshot(dist_dir, manifest_bytes, manifest, files, test_only)


def check_with_installer(dist: DistSnapshot) -> None:
    """Also run the installer's own verifier: the package must hold a dist/ it accepts."""
    sys.path.insert(0, str(REPO / "installer"))
    try:
        from beastbooter.dist import load_dist as installer_load_dist
        from beastbooter.errors import BeastError
    except ImportError as e:
        warn(f"skipping the installer's dist check (cannot import it: {e})")
        return
    finally:
        sys.path.pop(0)
    with tempfile.TemporaryDirectory(prefix="bb-portable-") as tmp:
        try:
            checked = installer_load_dist(dist.root, Path(tmp) / "staging")
        except BeastError as e:
            raise BuildError(f"the installer rejects {dist.root}: {e}") from None
        except (TypeError, AttributeError) as e:
            warn(f"skipping the installer's dist check (its API changed: {e})")
            return
    if getattr(checked, "manifest", None) != dist.manifest:
        raise BuildError(f"{dist.root} changed while it was being packaged; run the build again")


def load_sbom(sbom_dir: Path, dist: DistSnapshot) -> tuple[dict[str, bytes], dict]:
    """Files under sbom/, but only if they describe exactly this dist/."""
    if not sbom_dir.is_dir():
        return {}, {"included": False, "reason": f"no {sbom_dir.name}/ directory"}
    files: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(sbom_dir):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d != "__pycache__")
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                raise BuildError(f"{full}: symlinks are not allowed in sbom/")
            files[full.relative_to(sbom_dir).as_posix()] = full.read_bytes()
    if not files:
        return {}, {"included": False, "reason": f"{sbom_dir.name}/ is empty"}
    expected = sha256(dist.manifest_bytes)
    recorded = None
    try:
        cdx = json.loads(files.get("beast-booter.cdx.json", b"null"))
        for prop in cdx["metadata"]["component"]["properties"]:
            if prop.get("name") == "beast-booter:manifest-sha256":
                recorded = prop.get("value")
    except (ValueError, KeyError, TypeError):
        pass
    if recorded is None:
        raise BuildError(
            f"{sbom_dir}: cannot tell which dist/ it describes (no beast-booter:manifest-sha256 in "
            "beast-booter.cdx.json); regenerate the SBOM or build with --no-sbom"
        )
    if recorded != expected:
        raise BuildError(
            f"{sbom_dir} describes a different dist/ (its manifest sha256 is {recorded[:12]}..., "
            f"{dist.root}/manifest.json is {expected[:12]}...); regenerate the SBOM or build with --no-sbom"
        )
    # Origin prefix for the files: repo:sbom/... normally, file:/abs/dir/... for an outside --sbom.
    where = f"repo:{repo_rel(sbom_dir)}" if sbom_dir.resolve().is_relative_to(REPO) else f"file:{sbom_dir.resolve()}"
    return files, {"included": True, "origin": where, "dist_manifest_sha256": expected}


def app_sources() -> list[tuple[str, str, bytes]]:
    """(path in app/, repo path, content) for the installer package and its entry point."""
    out = []
    pkg_dir = REPO / "installer" / "beastbooter"
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in APP_SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            if name.startswith((".", "test_")) or name.endswith(APP_SKIP_SUFFIXES):
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                raise BuildError(f"{full}: symlinks are not allowed in the installer sources")
            rel = full.relative_to(REPO / "installer").as_posix()
            out.append((rel, repo_rel(full), full.read_bytes()))
    launch = REPO / "installer" / "beast_booter_launch.py"
    if not launch.is_file():
        raise BuildError(f"{launch} is missing")
    out.append(("beast_booter_launch.py", repo_rel(launch), launch.read_bytes()))
    if not any(rel == "beastbooter/cli.py" for rel, _, _ in out):
        raise BuildError(f"{pkg_dir}/cli.py is missing")
    return out


def source_date_epoch() -> int:
    env = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if env:
        if not env.isdigit():
            raise BuildError(f"SOURCE_DATE_EPOCH must be a whole number of seconds, not {env!r}")
        return int(env)
    out = git("log", "-1", "--format=%ct")
    if out and out.isdigit():
        return int(out)
    return int((REPO / "VERSION").stat().st_mtime)


def git(*args: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


# ---------------------------------------------------------------------------
# Package contents
# ---------------------------------------------------------------------------


@dataclass
class Entry:
    kind: str  # "file" | "symlink"
    origin: str
    data: bytes = b""
    target: str = ""  # symlink target (relative)
    executable: bool = False
    extra: dict = field(default_factory=dict)  # extra manifest fields

    @property
    def mode(self) -> int:
        if self.kind == "symlink":
            return 0o777
        return 0o755 if self.executable else 0o644


class Package:
    def __init__(self, target: str, version: str) -> None:
        self.target = target
        self.os, self.ext = TARGETS[target]
        self.version = version
        self.top = f"beast-booter-{version}-{target}"
        self.archive_name = f"{self.top}.{self.ext}"
        # Where runtime/, app/, payload/ and VERSION go.
        self.res = MACOS_RESOURCES if self.os == "macos" else ""
        self.entries: dict[str, Entry] = {}
        # Runtime bytecode caches left out of the package: asset member -> SHA-256.
        self.omitted_bytecode: dict[str, str] = {}

    def add_file(self, path: str, data: bytes, origin: str, *, executable: bool = False, **extra) -> None:
        if self.os == "windows":  # no exec bits on Windows: every file is stored as 0644
            executable = False
        self._add(path, Entry("file", origin, data=data, executable=executable, extra=extra))

    def add_symlink(self, path: str, target: str, origin: str) -> None:
        self._add(path, Entry("symlink", origin, target=target))

    def _add(self, path: str, entry: Entry) -> None:
        check_member_path(path)
        if path in self.entries:
            raise BuildError(f"{self.target}: {path} added twice")
        self.entries[path] = entry

    def tree(self) -> list[tuple[str, str, Entry | None]]:
        """Every entry plus the directories that hold them, sorted (the archive order)."""
        dirs = {""}
        for p in self.entries:
            parts = p.split("/")
            dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
        clash = sorted(dirs & set(self.entries))
        if clash:
            raise BuildError(f"{self.target}: {clash[0]} is both a file and a directory")
        items: list[tuple[str, str, Entry | None]] = [(d, "dir", None) for d in dirs]
        items += [(p, e.kind, e) for p, e in self.entries.items()]
        items.sort(key=lambda it: it[0].encode("utf-8"))
        return items


def cached_source(rel: str) -> str | None:
    """The .py file a bytecode cache belongs to: 'd/__pycache__/m.cpython-313.opt-1.pyc' -> 'd/m.py'.

    None if rel is not a file directly inside a __pycache__ folder.
    """
    folder, _, name = rel.rpartition("/")
    if posixpath.basename(folder) != "__pycache__" or not name.endswith(".pyc"):
        return None
    module = name.split(".", 1)[0]  # module names cannot contain dots
    return posixpath.join(posixpath.dirname(folder), module + ".py")


def add_runtime(pkg: Package, archive: bytes, asset: str) -> str:
    """Copy the runtime archive's python/ tree into <res>runtime/, unmodified.

    Bytecode caches (__pycache__/*.pyc) are left out and recorded in
    pkg.omitted_bytecode. The upstream ones are stale (they record a source mtime
    that differs from the archive's), so Python never used them; worse, any run of
    the bundled Python without -B would rewrite them and the package would no
    longer match its manifest. Without them the package holds no bytecode, and
    Python runs only the .py sources. Bytecode without its source is refused.

    Returns the path of the real python executable inside the package.
    """
    dest = f"{pkg.res}runtime"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        members = []
        for m in tf.getmembers():
            name = m.name[2:] if m.name.startswith("./") else m.name
            members.append((name.rstrip("/"), m))
        names = {name for name, _ in members}
        for name, m in members:
            if name == "python":
                continue
            if not name.startswith("python/"):
                raise BuildError(f"{asset}: unexpected member {m.name!r} (not under python/)")
            rel = name[len("python/"):]
            try:
                check_member_path(rel)
            except BuildError:
                raise BuildError(f"{asset}: unsafe member path {m.name!r}") from None
            origin = f"runtime:{name}"
            if m.isdir():
                continue
            if rel.endswith(BYTECODE_SUFFIXES) or "__pycache__" in rel.split("/"):
                source = cached_source(rel)
                if not m.isreg() or source is None:
                    raise BuildError(f"{asset}: unexpected bytecode or __pycache__ entry {m.name}")
                if f"python/{source}" not in names:
                    raise BuildError(
                        f"{asset}: {m.name} is bytecode without its source {source}; "
                        "the package must run only source code"
                    )
                f = tf.extractfile(m)
                assert f is not None
                pkg.omitted_bytecode[name] = sha256(f.read())
                continue
            if m.isreg() or m.islnk():  # a hard link is stored as a copy of its target
                f = tf.extractfile(m)
                assert f is not None
                pkg.add_file(f"{dest}/{rel}", f.read(), origin, executable=bool(m.mode & 0o111))
            elif m.issym():
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), m.linkname))
                if m.linkname.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    raise BuildError(f"{asset}: symlink {m.name} points outside the runtime ({m.linkname})")
                if pkg.os == "windows":
                    raise BuildError(f"{asset}: unexpected symlink {m.name} in a Windows runtime")
                pkg.add_symlink(f"{dest}/{rel}", m.linkname, origin)
            else:
                raise BuildError(f"{asset}: unsupported member type for {m.name}")
    if pkg.os == "windows":
        exe = f"{dest}/python.exe"
        for need in (exe, f"{dest}/pythonw.exe"):
            if need not in pkg.entries:
                raise BuildError(f"{asset}: {need[len(dest) + 1:]} not found in the runtime")
        return exe
    link = pkg.entries.get(f"{dest}/bin/python3")
    if link is None:
        raise BuildError(f"{asset}: bin/python3 not found in the runtime")
    if link.kind == "symlink":
        real = posixpath.normpath(posixpath.join(f"{dest}/bin", link.target))
        if pkg.entries.get(real, Entry("missing", "")).kind != "file":
            raise BuildError(f"{asset}: bin/python3 -> {link.target} does not lead to a file")
        return real
    return f"{dest}/bin/python3"


def macho_min_os(data: bytes) -> str | None:
    """Minimum macOS version recorded in a Mach-O executable (LC_BUILD_VERSION / LC_VERSION_MIN_MACOSX)."""
    if len(data) < 32:
        return None
    if data[:4] == b"\xca\xfe\xba\xbe":  # universal binary: look at the first slice
        offset, size = struct.unpack_from(">II", data, 16)
        return macho_min_os(data[offset:offset + size])
    if struct.unpack_from("<I", data)[0] != 0xFEEDFACF:  # 64-bit little-endian Mach-O
        return None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if cmd == 0x32:  # LC_BUILD_VERSION: platform, minos
            version = struct.unpack_from("<I", data, pos + 12)[0]
            break
        if cmd == 0x24:  # LC_VERSION_MIN_MACOSX: version
            version = struct.unpack_from("<I", data, pos + 8)[0]
            break
        pos += size
    else:
        return None
    major, minor, patch = version >> 16, (version >> 8) & 0xFF, version & 0xFF
    return f"{major}.{minor}.{patch}" if patch else f"{major}.{minor}"


def render_text_template(text: str, os_name: str, values: dict[str, str]) -> str:
    """'%% if linux macos' ... '%% end' keeps a block for those OSes; '%%#' lines are comments."""
    out, active = [], True
    for line in text.splitlines():
        if line.startswith("%%#"):
            continue
        if line.startswith("%% if "):
            active = os_name in line[6:].split()
            continue
        if line.strip() == "%% end":
            active = True
            continue
        if line.startswith("%%"):
            raise BuildError(f"{README_TEMPLATE}: unknown directive {line!r}")
        if active:
            out.append(line)
    rendered = "\n".join(out).rstrip("\n") + "\n"
    for key, value in values.items():
        rendered = rendered.replace(f"@{key}@", value)
    left = re.search(r"@[A-Z_]+@", rendered)
    if left:
        raise BuildError(f"{README_TEMPLATE}: unknown placeholder {left.group(0)}")
    return rendered


def render_info_plist(version: str, arch: str, min_os: str) -> bytes:
    template = LAUNCHERS / "macos" / "Info.plist.in"
    values = {"@VERSION@": version, "@ARCH@": arch, "@MACOS_MIN@": min_os, "@BUNDLE_ID@": BUNDLE_ID}

    def fill(v):
        if isinstance(v, str):
            for key, value in values.items():
                v = v.replace(key, value)
            if re.search(r"@[A-Z_]+@", v):
                raise BuildError(f"{template}: unknown placeholder in {v!r}")
            return v
        if isinstance(v, list):
            return [fill(x) for x in v]
        if isinstance(v, dict):
            return {k: fill(x) for k, x in v.items()}
        return v

    try:
        info = plistlib.loads(template.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError) as e:
        raise BuildError(f"cannot read {template}: {e}") from None
    return plistlib.dumps(fill(info), fmt=plistlib.FMT_XML, sort_keys=True)


def launcher(rel: str, *, crlf: bool) -> tuple[bytes, str]:
    """A launcher script from launchers/, with its line endings checked."""
    path = LAUNCHERS / rel
    data = path.read_bytes()
    origin = f"repo:{repo_rel(path)}"
    if crlf:  # cmd.exe misparses batch files with bare LF line endings
        fixed = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        if fixed != data:
            data, origin = fixed, origin + " (line endings converted to CRLF)"
    elif b"\r" in data:
        raise BuildError(f"{path}: must have LF line endings (sh fails on CR)")
    return data, origin


@dataclass
class Inputs:
    version: str
    epoch: int
    lock: dict
    dist: DistSnapshot
    sbom: dict[str, bytes]
    sbom_info: dict
    app: list[tuple[str, str, bytes]]
    git_commit: str | None


def assemble(target: str, inp: Inputs, runtime: bytes) -> tuple[Package, bytes]:
    """All entries of one package, plus its PACKAGE-MANIFEST.json."""
    spec = inp.lock["targets"][target]
    pkg = Package(target, inp.version)
    res = pkg.res
    python_exe = add_runtime(pkg, runtime, spec["asset"])

    for rel, origin_path, data in inp.app:
        pkg.add_file(f"{res}app/{rel}", data, f"repo:{origin_path}")
    pkg.add_file(f"{res}payload/dist/manifest.json", inp.dist.manifest_bytes, "dist:manifest.json")
    for p, data in sorted(inp.dist.files.items()):
        meta = inp.dist.manifest["files"][p]
        pkg.add_file(f"{res}payload/dist/{p}", data, f"dist:{p}", dist_origin=str(meta.get("origin", "")))
    for p, data in sorted(inp.sbom.items()):
        pkg.add_file(f"{res}payload/sbom/{p}", data, f"{inp.sbom_info['origin']}/{p}")
    # beastbooter/__init__.py reads the version from VERSION two levels above itself.
    version_file = REPO / "VERSION"
    pkg.add_file(f"{res}VERSION", version_file.read_bytes(), "repo:VERSION")

    for name in PACKAGE_DOCS:
        doc = REPO / "docs" / name
        pkg.add_file(f"{res}docs/{name}", doc.read_bytes(), f"repo:{repo_rel(doc)}")

    pkg.add_file("LICENSE", (REPO / "LICENSE").read_bytes(), "repo:LICENSE")
    pkg.add_file("verify-package.py", VERIFY_SCRIPT.read_bytes(), f"repo:{repo_rel(VERIFY_SCRIPT)}",
                 executable=True)

    if pkg.os == "linux":
        gui, cli = "BeastBooter", "beast-booter"
        for name in ("BeastBooter", "beast-booter", "beast-booter.desktop"):
            data, origin = launcher(f"linux/{name}", crlf=False)
            pkg.add_file(name, data, origin, executable=True)
        python_cli = "runtime/bin/python3"
    elif pkg.os == "windows":
        gui, cli = "BeastBooter.cmd", "beast-booter.cmd"
        for name in (gui, cli):
            data, origin = launcher(f"windows/{name}", crlf=True)
            pkg.add_file(name, data, origin, executable=True)
        python_cli = "runtime/python.exe"
    else:
        gui, cli = f"{APP_NAME}.app/Contents/MacOS/{APP_NAME}", "beast-booter.command"
        data, origin = launcher("macos/BeastBooter", crlf=False)
        pkg.add_file(gui, data, origin, executable=True)
        data, origin = launcher("macos/beast-booter.command", crlf=False)
        pkg.add_file(cli, data, origin, executable=True)
        min_os = macho_min_os(pkg.entries[python_exe].data)
        if not min_os:
            raise BuildError(f"{spec['asset']}: cannot read the minimum macOS version from {python_exe}")
        pkg.add_file(f"{APP_NAME}.app/Contents/Info.plist",
                     render_info_plist(inp.version, MACOS_ARCH[target], min_os),
                     f"generated:{repo_rel(LAUNCHERS / 'macos' / 'Info.plist.in')}")
        python_cli = f"{res}runtime/bin/python3"

    readme = render_text_template(
        README_TEMPLATE.read_text(encoding="utf-8"), pkg.os,
        {
            "VERSION": inp.version, "TARGET": target, "TARGET_NAME": TARGET_NAMES[target],
            "TOP": pkg.top, "ARCHIVE": pkg.archive_name, "PYTHON": inp.lock["python"],
            "PBS_RELEASE": str(inp.lock.get("release", "")), "RUNTIME_ASSET": spec["asset"],
            "RUNTIME_SHA256": spec["sha256"],
            "TEST_WARNING": TEST_WARNING if inp.dist.test_only else "",
        },
    )
    if pkg.os == "windows":
        readme = readme.replace("\n", "\r\n")  # for Notepad on older Windows
    pkg.add_file("README.txt", readme.encode("utf-8"), f"generated:{repo_rel(README_TEMPLATE)}")

    manifest = package_manifest(pkg, inp, spec, gui=gui, cli=cli, python_cli=python_cli)
    return pkg, manifest


TEST_WARNING = (
    "\n*** TEST BUILD: the boot files in this package are FAKE (installer/tests/fakedist.py).\n"
    "*** A drive made with it does not boot. Do not publish or use this package.\n"
)


def package_manifest(pkg: Package, inp: Inputs, spec: dict, *, gui: str, cli: str, python_cli: str) -> bytes:
    files = {}
    for path, e in sorted(pkg.entries.items()):
        if e.kind == "symlink":
            files[path] = {"symlink": e.target, "origin": e.origin}
        else:
            files[path] = {"sha256": sha256(e.data), "size": len(e.data), "mode": f"{e.mode:04o}",
                           "origin": e.origin, **e.extra}
    dm = inp.dist.manifest
    sb = dm.get("secure_boot") if isinstance(dm.get("secure_boot"), dict) else {}
    res = pkg.res
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "name": "beast-booter",
        "version": inp.version,
        "target": pkg.target,
        "top": pkg.top,
        "source_date_epoch": inp.epoch,
        "git_commit": inp.git_commit,
        "test_only": inp.dist.test_only,
        "layout": {
            "gui": gui,
            "cli": cli,
            "python": python_cli,
            "runtime": f"{res}runtime",
            "app": f"{res}app",
            "dist": f"{res}payload/dist",
            "sbom": f"{res}payload/sbom" if inp.sbom else None,
            "docs": f"{res}docs",
        },
        "sources": {
            "runtime": {
                "project": inp.lock.get("project"),
                "project_url": inp.lock.get("project_url"),
                "release": inp.lock.get("release"),
                "python": inp.lock.get("python"),
                "asset": spec["asset"],
                "url": spec["url"],
                "sha256": spec["sha256"],
                "note": "runtime/ is the asset's python/ folder, unmodified, except that its bytecode "
                        "caches (__pycache__/*.pyc) are left out: they are listed in omitted_bytecode "
                        "with their SHA-256. Python compiles the .py sources instead.",
                "omitted_bytecode": dict(sorted(pkg.omitted_bytecode.items())),
            },
            "dist": {
                "version": dm.get("version"),
                "build_id": dm.get("build_id"),
                "source_date_epoch": dm.get("source_date_epoch"),
                "manifest_sha256": sha256(inp.dist.manifest_bytes),
                "secure_boot_cert_sha256": sb.get("cert_sha256"),
                "secure_boot_cert_subject": sb.get("cert_subject"),
            },
            "sbom": inp.sbom_info,
        },
        "origins": {
            "runtime:<path>": "file <path> of the runtime asset in sources.runtime, unmodified",
            "repo:<path>": "file <path> of the beast-booter source tree, unmodified",
            "dist:<path>": "boot file <path> of dist/, checked against dist/manifest.json "
                           "(which names where it came from: dist_origin)",
            "generated:<path>": "written by packaging/portable/build.py from the template <path>",
            "file:<path>": "file given on the build.py command line from outside the source tree",
        },
        "files": files,
    }
    return (json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


def write_tar_gz(dest: Path, pkg: Package, epoch: int) -> None:
    with atomic_output(dest) as tmp, open(tmp, "wb") as raw, \
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for path, kind, e in pkg.tree():
            ti = tarfile.TarInfo(f"{pkg.top}/{path}" if path else pkg.top)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = epoch, 0, 0, "", ""
            if kind == "dir":
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type, ti.mode, ti.linkname = tarfile.SYMTYPE, 0o777, e.target
                tf.addfile(ti)
            else:
                ti.mode, ti.size = e.mode, len(e.data)
                tf.addfile(ti, io.BytesIO(e.data))


def write_zip(dest: Path, pkg: Package, epoch: int) -> None:
    date_time = time.gmtime(max(epoch, ZIP_EPOCH_MIN))[:6]
    with atomic_output(dest) as tmp, zipfile.ZipFile(tmp, "w") as zf:
        for path, kind, e in pkg.tree():
            name = f"{pkg.top}/{path}" if path else pkg.top
            if kind == "dir":
                zi = zipfile.ZipInfo(name + "/", date_time)
                zi.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10  # 0x10: MS-DOS directory flag
                data, method = b"", zipfile.ZIP_STORED
            elif kind == "symlink":  # a symlink is stored as its target text with S_IFLNK set
                zi = zipfile.ZipInfo(name, date_time)
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                data, method = e.target.encode("utf-8"), zipfile.ZIP_STORED
            else:
                zi = zipfile.ZipInfo(name, date_time)
                zi.external_attr = (stat.S_IFREG | e.mode) << 16
                data, method = e.data, zipfile.ZIP_DEFLATED
            zi.create_system = 3  # Unix: unzip, ditto and Archive Utility honour modes and symlinks
            zi.compress_type = method
            zf.writestr(zi, data, compresslevel=9 if method == zipfile.ZIP_DEFLATED else None)


def write_package(pkg: Package, manifest: bytes, out_dir: Path, epoch: int) -> Path:
    pkg.add_file(MANIFEST_NAME, manifest, "generated:packaging/portable/build.py")
    dest = out_dir / pkg.archive_name
    (write_tar_gz if pkg.ext == "tar.gz" else write_zip)(dest, pkg, epoch)
    return dest


def verify_archives(paths: list[Path]) -> bool:
    """Run verify_package.py's checks (manifest + layout) on built archives."""
    sys.path.insert(0, str(HERE))
    try:
        import verify_package
    finally:
        sys.path.pop(0)
    ok = True
    for p in paths:
        errors, warnings, summary = verify_package.verify_path(Path(p))
        for w in warnings:
            warn(f"{Path(p).name}: {w}")
        for e in errors:
            print(f"portable: {Path(p).name}: ERROR: {e}", file=sys.stderr)
        if errors:
            ok = False
        else:
            log(f"verified {Path(p).name}: {summary}")
    return ok


def write_sums(out_dir: Path, version: str) -> Path:
    names = sorted(
        f"beast-booter-{version}-{t}.{ext}" for t, (_os, ext) in TARGETS.items()
        if (out_dir / f"beast-booter-{version}-{t}.{ext}").is_file()
    )
    text = "".join(f"{sha256_file(out_dir / n)}  {n}\n" for n in names)
    dest = out_dir / "SHA256SUMS"
    with atomic_output(dest) as tmp:
        tmp.write_text(text, encoding="ascii")
    return dest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build(args: argparse.Namespace) -> int:
    lock = read_lock()
    targets = list(TARGETS) if args.all else list(dict.fromkeys(args.target))
    for t in targets:  # fail fast on a bad runtime before reading anything else
        fetch_runtime(lock["targets"][t], args.cache, offline=args.offline)
        log(f"runtime for {t}: {lock['targets'][t]['asset']} (sha256 ok)")
    if args.fetch_only:
        return 0

    version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9A-Za-z.+~-]+", version):
        raise BuildError(f"VERSION: unexpected content {version!r}")
    dist = load_dist(args.dist)
    if dist.test_only and not args.allow_test_dist:
        raise BuildError(
            f"{args.dist} is a test-only fake dist (origin test:...); it does not boot. "
            "Build the real one (`make build`), or pass --allow-test-dist for packaging tests"
        )
    if dist.test_only:
        warn("packaging a FAKE dist/: these packages are marked test-only and must not be published")
    check_with_installer(dist)
    if str(dist.manifest.get("version")) != version:
        warn(f"dist/ is version {dist.manifest.get('version')}, VERSION says {version}")
    if args.no_sbom:
        sbom, sbom_info = {}, {"included": False, "reason": "built with --no-sbom"}
    else:
        sbom, sbom_info = load_sbom(args.sbom, dist)
    inp = Inputs(version, source_date_epoch(), lock, dist, sbom, sbom_info, app_sources(), git("rev-parse", "HEAD"))
    log(f"version {version}, dist build {dist.manifest.get('build_id')}, "
        f"{len(dist.files)} boot files, sbom: {'yes' if sbom else 'no'}, SOURCE_DATE_EPOCH={inp.epoch}")

    built = []
    for t in targets:
        runtime = read_runtime(lock["targets"][t], args.cache, offline=args.offline)
        pkg, manifest = assemble(t, inp, runtime)
        del runtime
        path = write_package(pkg, manifest, args.out, inp.epoch)
        log(f"wrote {path} ({path.stat().st_size / 1e6:.1f} MB, {len(pkg.entries)} files)")
        built.append(path)
        del pkg
    if not verify_archives(built):
        for p in built:
            with contextlib.suppress(FileNotFoundError):
                p.unlink()
        raise BuildError("a package failed verification (removed); see the errors above")
    sums = write_sums(args.out, version)
    log(f"wrote {sums}")
    return 0


def main(argv: list[str] | None = None) -> int:
    sys.dont_write_bytecode = True  # imports below must not leave __pycache__ in the source tree
    ap = argparse.ArgumentParser(
        prog="build.py", description="Build beast-booter's no-install portable packages.",
        epilog="Run with python3 -I from the repository root. See docs/PORTABLE.md.",
    )
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--all", action="store_true", help="build every target: " + ", ".join(TARGETS))
    what.add_argument("--target", action="append", choices=list(TARGETS), help="build this target (repeatable)")
    what.add_argument("--verify", nargs="+", type=Path, metavar="ARCHIVE",
                      help="only check built archives against their PACKAGE-MANIFEST.json")
    ap.add_argument("--fetch-only", action="store_true", help="only download and verify the pinned runtimes")
    ap.add_argument("--dist", type=Path, default=REPO / "dist", help="boot files (default: %(default)s)")
    ap.add_argument("--sbom", type=Path, default=REPO / "sbom", help="SBOM directory (default: %(default)s)")
    ap.add_argument("--no-sbom", action="store_true", help="leave the SBOM out")
    ap.add_argument("--allow-test-dist", action="store_true",
                    help="accept a fake dist/ from installer/tests/fakedist.py (packages are marked test-only)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default: %(default)s)")
    ap.add_argument("--cache", type=Path, default=Path(os.environ.get("BB_PBS_CACHE", DEFAULT_CACHE)),
                    help="runtime download cache (default: %(default)s, or $BB_PBS_CACHE)")
    ap.add_argument("--offline", action="store_true", help="never download; the runtimes must be cached")
    args = ap.parse_args(argv)
    try:
        if args.verify:
            return 0 if verify_archives(args.verify) else 1
        return build(args)
    except BuildError as e:
        print(f"portable: error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("portable: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
