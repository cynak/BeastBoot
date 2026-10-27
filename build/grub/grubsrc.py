#!/usr/bin/env python3
"""Build GRUB 2 for beast-boot from pinned source: x86_64-efi and i386-pc
platform files (modules, kernel.img, boot images, debug symbols) and the
matching grub-mkimage.

    python3 -I build/grub/grubsrc.py build   [--cache DIR] [--builder auto|native|docker] [-j N] [--quiet]
    python3 -I build/grub/grubsrc.py key     [--cache DIR]       print the cache key of the current inputs
    python3 -I build/grub/grubsrc.py verify  OUTDIR              check OUTDIR against its build-info.json
    python3 -I build/grub/grubsrc.py sbat    OUTDIR              print the SBAT lines OUTDIR's code may carry

`build` prints the output directory (.tools/cache/grub-src/out/<key>) on stdout
as its last line; everything else goes to stderr.

Inputs (all in build/grub/, all hashed into the cache key):
  source.lock.json     Ubuntu grub2 source package (.dsc, orig, debian tarball),
                       the liblzo2-dev .deb with minilzo, host tool .debs,
                       docker image + apt snapshot - each with its SHA-256
  patches/series       our patches on top of Ubuntu's debian/patches/series
  security-fixes.json  which security fix is where, with the upstream commit;
                       upstream/*.patch are those commits. Every fix is proven
                       present by applying its upstream commit IN REVERSE
                       (dry run) to the patched tree: that only succeeds when
                       the fixed code is there. The build fails if a fix that
                       the claimed SBAT generation requires is missing.
  grubsrc.py           this script
plus the toolchain identity (compiler, binutils, generators, build flags).

Builders: `native` uses the host's toolchain (bison/flex/autopoint/gawk from the
locked .debs if the host lacks them, used only if they run here); `docker` runs
the native build inside the pinned Ubuntu image and links grub-mkimage
statically there, because the host runs it; `auto` (default) is native, else
docker. BB_OFFLINE=1: no downloads - everything must be in the cache already.

Steps: fetch + check -> unpack orig, apply Ubuntu's patches (as dpkg-source
does: patch -p1 -F0 in series order), add debian/grub-extras/915resolution
and minilzo the way debian/rules does -> apply our patches -> check the
security fixes -> autogen.sh -> configure (Ubuntu's flags for those
platforms) -> make -> install into out/<key>/{x86_64-efi,i386-pc,bin}.

Reproducible: SOURCE_DATE_EPOCH is the date of the Ubuntu changelog entry,
paths are mapped (-ffile-prefix-map) to /build/grub2-<version>, and the
toolchain is part of the cache key. Two builds with the same key give the
same files (build-info.json lists their SHA-256).
"""
from __future__ import annotations

import argparse
import email.utils
import fcntl
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LOCK = HERE / "source.lock.json"
SERIES = HERE / "patches" / "series"
FIXES = HERE / "security-fixes.json"
UPSTREAM = HERE / "upstream"
LAUNCHPAD_FILES = "https://launchpad.net/ubuntu/+archive/primary/+files/"
PLATFORMS = {           # target dir -> (obj dir, configure flags) - from Ubuntu's debian/rules
    "i386-pc": ("grub-pc", ["--with-platform=pc"]),
    "x86_64-efi": ("grub-efi-amd64", ["--with-platform=efi", "--target=amd64-pe", "--program-prefix="]),
}
GENERATORS = ["bison", "flex", "autopoint", "gawk"]
NEEDED = ["gcc", "ld", "objcopy", "strip", "nm", "make", "python3", "autoconf", "automake", "aclocal",
          "patch", "m4", "xz", "tar", "pkg-config"]
INFO_SCHEMA = 1
QUIET = False


class Fail(Exception):
    pass


def log(msg: str) -> None:
    if not QUIET:
        print(f"grub: {msg}", file=sys.stderr, flush=True)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, logf: Path | None = None,
        check: bool = True, input_: bytes | None = None) -> subprocess.CompletedProcess:
    """Run CMD; with LOGF, output goes there (and the tail is shown on failure)."""
    if logf:
        with open(logf, "ab") as out:
            out.write(f"\n$ {' '.join(cmd)}  (in {cwd})\n".encode())
            out.flush()
            r = subprocess.run(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, input=input_)
        if check and r.returncode != 0:
            tail = logf.read_text(errors="replace").splitlines()[-40:]
            raise Fail(f"{' '.join(cmd[:3])} failed (exit {r.returncode}); last lines of {logf}:\n  "
                       + "\n  ".join(tail))
        return r
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, input=input_)
    if check and r.returncode != 0:
        raise Fail(f"{' '.join(cmd)} failed (exit {r.returncode}):\n{r.stderr.decode(errors='replace')[-3000:]}")
    return r


# --------------------------------------------------------------------------- inputs

def load_lock() -> dict:
    lock = json.loads(LOCK.read_text())
    if lock.get("schema") != 1:
        raise Fail(f"{LOCK}: unsupported schema")
    # the purl names the Ubuntu series the source package comes from, not the build host's
    if not re.fullmatch(r"ubuntu-\d\d\.\d\d", str(lock.get("purl_distro"))):
        raise Fail(f"{LOCK}: purl_distro must name the source's Ubuntu series (ubuntu-YY.MM)")
    return lock


def build_version(lock: dict) -> str:
    """Version of our GRUB: Ubuntu's source version + our patch level, e.g. 2.14-2ubuntu3+bb1."""
    return f"{lock['source_version']}+bb{lock['patch_level']}"


def read_series() -> list[Path]:
    out = []
    for line in SERIES.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            p = HERE / "patches" / line
            if not p.is_file():
                raise Fail(f"{SERIES}: {line} not found")
            out.append(p)
    return out


def load_fixes() -> dict:
    fx = json.loads(FIXES.read_text())
    if fx.get("schema") != 1:
        raise Fail(f"{FIXES}: unsupported schema")
    # fail closed: a fix is proven only by its evidence, a generation only by the fixes it requires
    kinds = {}
    for f in fx["fixes"]:
        if not f.get("evidence"):
            raise Fail(f"{FIXES}: fix {f.get('id')} has no evidence (nothing would prove it present)")
        kinds[f["id"]] = f.get("type", "security")
    for c in fx["sbat_claims"]:
        claim = f"SBAT claim {c.get('component')},{c.get('generation')}"
        if not c.get("requires"):
            raise Fail(f"{FIXES}: {claim} requires no fixes (a generation is earned only by its fixes)")
        unknown = [i for i in c["requires"] if i not in kinds]
        if unknown:
            raise Fail(f"{FIXES}: {claim} requires fixes it does not list: {unknown}")
        if any(kinds[i] != "security" for i in c["requires"]):
            raise Fail(f"{FIXES}: {claim} requires non-security fixes (only security fixes earn a generation)")
    return fx


def input_files() -> list[Path]:
    """Every repo file that defines the build (hashed into the key)."""
    fx = load_fixes()
    ups = sorted({UPSTREAM / f"{c}.patch" for f in fx["fixes"] for c in f["upstream_commits"]})
    return [LOCK, SERIES, *read_series(), FIXES, *ups, Path(__file__).resolve()]


# --------------------------------------------------------------------------- downloads

def offline() -> bool:
    return os.environ.get("BB_OFFLINE") == "1"


def no_download(dest: Path) -> None:
    """BB_OFFLINE=1 (make release ARGS=--offline): never download; the cache must have DEST."""
    if offline():
        raise Fail(f"{dest.name} is not in {dest.parent} (or does not match the lock) and BB_OFFLINE=1: "
                   "run the build once online to fill the cache")


def fetch_url(urls: list[str], dest: Path, sha256: str, size: int | None) -> Path:
    if dest.is_file() and sha256_file(dest) == sha256:
        return dest
    no_download(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    errors = []
    for url in urls:
        tmp = dest.with_name(dest.name + ".part")
        try:
            log(f"downloading {url}")
            with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
        except OSError as e:
            errors.append(f"{url}: {e}")
            tmp.unlink(missing_ok=True)
            continue
        got = sha256_file(tmp)
        if got != sha256 or (size is not None and tmp.stat().st_size != size):
            errors.append(f"{url}: SHA-256 {got} / size {tmp.stat().st_size}, lock says {sha256} / {size}")
            tmp.unlink(missing_ok=True)
            continue
        os.replace(tmp, dest)
        return dest
    raise Fail(f"cannot fetch {dest.name}:\n  " + "\n  ".join(errors))


def deb_name(e: dict) -> str:
    return f"{e['package']}_{e['version'].split(':', 1)[-1]}_{e['arch']}.deb"


def fetch_deb(e: dict, dl: Path) -> Path:
    """apt-get download (apt checks the signed archive index) at the locked version,
    else Launchpad's file store; always checked against the lock's SHA-256."""
    dest = dl / deb_name(e)
    if dest.is_file() and sha256_file(dest) == e["sha256"]:
        return dest
    no_download(dest)                       # apt-get download fetches too
    dl.mkdir(parents=True, exist_ok=True)
    if shutil.which("apt-get"):
        with tempfile.TemporaryDirectory(dir=dl) as t:
            r = subprocess.run(["apt-get", "download", f"{e['package']}={e['version']}"], cwd=t,
                               capture_output=True, text=True)
            got = [p for p in Path(t).glob("*.deb")]
            if r.returncode == 0 and len(got) == 1 and sha256_file(got[0]) == e["sha256"]:
                os.replace(got[0], dest)
                return dest
    return fetch_url([LAUNCHPAD_FILES + deb_name(e)], dest, e["sha256"], e.get("size"))


def fetch_sources(lock: dict, dl: Path) -> dict[str, Path]:
    out = {}
    for e in lock["source"]:
        out[e["name"]] = fetch_url(e["urls"], dl / e["name"], e["sha256"], e.get("size"))
    # The .dsc names the tarballs with their SHA-256: lock and .dsc must agree.
    dsc = next(p for n, p in out.items() if n.endswith(".dsc"))
    text = dsc.read_text()
    block = re.search(r"(?m)^Checksums-Sha256:\n((?: .*\n)+)", text)
    if not block:
        raise Fail(f"{dsc}: no Checksums-Sha256")
    listed = {ln.split()[2]: ln.split()[0] for ln in block.group(1).splitlines() if ln.strip()}
    if not re.search(rf"(?m)^Version: {re.escape(lock['source_version'])}$", text):
        raise Fail(f"{dsc} is not version {lock['source_version']}")
    for name, p in out.items():
        if name.endswith(".dsc"):
            continue
        if listed.get(name) != sha256_file(p):
            raise Fail(f"{name}: SHA-256 differs from {dsc.name}")
    if set(listed) - set(out):
        raise Fail(f"{dsc.name} lists files the lock lacks: {sorted(set(listed) - set(out))}")
    return out


# --------------------------------------------------------------------------- toolchain

def tool_version(cmd: list[str], env: dict) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "missing"
    first = (r.stdout or r.stderr).strip().splitlines()
    # some tools (autopoint) start with their own path: keep the name, so the key does not depend on it
    return re.sub(r"^\S*/(\S+)", r"\1", first[0].strip()) if first else f"exit {r.returncode}"


def host_flags(env: dict) -> dict:
    """HOST_* flags as debian/rules computes them (dpkg-buildflags, -lto); fixed fallbacks without dpkg."""
    e = dict(env, DEB_BUILD_MAINT_OPTIONS="optimize=-lto")
    out = {}
    for k, default in (("CPPFLAGS", ""), ("CFLAGS", "-g -O2"), ("LDFLAGS", "")):
        v = default
        if shutil.which("dpkg-buildflags"):
            r = subprocess.run(["dpkg-buildflags", "--get", k], capture_output=True, text=True, env=e)
            if r.returncode == 0:
                v = r.stdout.strip()
        # dpkg-buildflags maps the current directory; the build maps its own paths below
        v = re.sub(r"-f(?:file|debug)-prefix-map=\S+", "", v)
        out[k] = " ".join(v.replace("-O3", "-O2").split())
    out["CFLAGS"] = " ".join(["-Wall", "-Wno-error=unused-result", out["CFLAGS"]]).strip()
    return out


def toolchain(env: dict) -> dict:
    t = {name: tool_version([name, "--version"], env)
         for name in ("gcc", "ld", "as", "objcopy", "make", "bison", "flex", "gawk", "autoconf", "automake",
                      "m4", "python3", "patch", "pkg-config")}
    t["gcc-full"] = tool_version(["gcc", "-dumpfullversion"], env) + " " + tool_version(["gcc", "-dumpmachine"], env)
    t["autopoint"] = tool_version(["autopoint", "--version"], env)
    t["libc"] = tool_version(["ldd", "--version"], env)
    t["freetype2"] = tool_version(["pkg-config", "--modversion", "freetype2"], env)
    t["host-flags"] = host_flags(env)
    return t


def setup_generators(lock: dict, cache: Path, env: dict) -> tuple[dict, list[str]]:
    """Make bison/flex/autopoint/gawk available: host first, else the locked .debs
    unpacked without root into the cache (wrappers fix their data paths).
    Returns the env and the generators that are missing or do not run here."""
    missing = [g for g in GENERATORS if not shutil.which(g, path=env["PATH"])]
    if not missing:
        return env, unusable_generators(env, set())
    base = cache / "hosttools"
    root, bindir = base / "root", base / "bin"
    pkgs = [e for e in lock["host_tools"]["packages"] if set(e["provides"]) & set(missing)]
    stamp = base / ("unpacked-" + sha256_bytes(json.dumps(pkgs, sort_keys=True).encode())[:16])
    if not stamp.exists():
        log(f"host lacks {', '.join(missing)}: unpacking the locked .debs into {base} (no root)")
        shutil.rmtree(base, ignore_errors=True)
        root.mkdir(parents=True)
        for e in pkgs:
            deb = fetch_deb(e, cache / "dl")
            run(["dpkg-deb", "-x", str(deb), str(root)])
        bindir.mkdir(parents=True, exist_ok=True)
        wrappers = {
            "bison": f'BISON_PKGDATADIR="{root}/usr/share/bison" exec "{root}/usr/bin/bison" "$@"',
            "flex": f'exec "{root}/usr/bin/flex" "$@"',
            "autopoint": f'gettext_datadir="{root}/usr/share/gettext" exec "{root}/usr/bin/autopoint" "$@"',
            "gawk": f'exec "{root}/usr/bin/gawk" "$@"',
        }
        for name in missing:
            w = bindir / name
            w.write_text(f"#!/bin/sh\n# written by build/grub/grubsrc.py\n{wrappers[name]}\n")
            w.chmod(0o755)
        if "bison" in missing:      # some scripts call yacc
            (bindir / "yacc").write_text(f'#!/bin/sh\nexec "{bindir}/bison" -y "$@"\n')
            (bindir / "yacc").chmod(0o755)
        stamp.touch()
    env = dict(env, PATH=f"{bindir}:{env['PATH']}")
    return env, unusable_generators(env, set(missing))


def unusable_generators(env: dict, unpacked: set[str]) -> list[str]:
    """GENERATORS that are not on PATH or do not run (`--version` fails): the unpacked
    Ubuntu 26.04 .debs need a glibc as new as 26.04's. Counted as missing by cmd_build,
    so auto mode then uses docker."""
    bad = []
    for g in GENERATORS:
        if not shutil.which(g, path=env["PATH"]):
            bad.append(f"{g} (not found)")
            continue
        try:
            r = subprocess.run([g, "--version"], env=env, capture_output=True, text=True, timeout=30)
            err = None if r.returncode == 0 else ((r.stderr or r.stdout).strip().splitlines() or [f"exit {r.returncode}"])[-1]
        except (OSError, subprocess.TimeoutExpired) as e:
            err = str(e)
        if err is not None:
            what = ("unpacked Ubuntu .deb does not run on this host (glibc too old?)" if g in unpacked
                    else "does not run")
            bad.append(f"{g} ({what}: {err[:200]})")
    return bad


def check_native(env: dict) -> list[str]:
    miss = [t for t in NEEDED if not shutil.which(t, path=env["PATH"])]
    # build-time font tools (ascii.h, widthspec.h from unifont) need FreeType, as in Ubuntu's build
    if "pkg-config" not in miss and subprocess.run(["pkg-config", "--exists", "freetype2"], env=env).returncode:
        miss.append("libfreetype-dev (pkg-config freetype2)")
    return miss


# --------------------------------------------------------------------------- source tree

def safe_extract(tar: Path, dest: Path, strip: int = 0) -> None:
    with tarfile.open(tar) as tf:
        members = []
        for m in tf.getmembers():
            parts = Path(m.name).parts[strip:]
            if not parts:
                continue
            if m.issym() or m.islnk():
                tgt = Path(m.linkname)
                if tgt.is_absolute() or ".." in tgt.parts:
                    raise Fail(f"{tar}: unsafe link {m.name} -> {m.linkname}")
            if any(p == ".." for p in parts) or Path(m.name).is_absolute():
                raise Fail(f"{tar}: unsafe member {m.name}")
            m.name = str(Path(*parts))
            members.append(m)
        tf.extractall(dest, members=members, filter="tar")


def apply_patch(src: Path, patch: Path, logf: Path) -> None:
    """As dpkg-source applies quilt patches: no fuzz, fail on any reject."""
    run(["patch", "-p1", "-F0", "-N", "-t", "-u", "-E", "-s", "--no-backup-if-mismatch", "-i", str(patch)],
        cwd=src, logf=logf)


def split_patch(text: str) -> list[tuple[str, str]]:
    """[(path, per-file diff)] of a git format-patch / unified diff."""
    chunks, cur, path = [], [], None
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("diff --git ") or (ln.startswith("--- ") and i + 1 < len(lines)
                                             and lines[i + 1].startswith("+++ ") and path is None):
            if cur and path:
                chunks.append((path, "".join(cur)))
            cur, path = [], None
        if ln.startswith("+++ "):
            p = ln[4:].split("\t")[0].strip()
            path = p[2:] if p.startswith("b/") else p
        if ln == "-- \n" and (i + 1 == len(lines) or re.match(r"^(\d+\.\d|GitLab)", lines[i + 1])):
            break                                       # git / GitLab signature
        if path is not None or ln.startswith(("diff --git ", "--- ", "+++ ", "index ", "new file", "deleted file")):
            cur.append(ln)
        i += 1
        if ln.startswith("diff --git "):
            path = None
    if cur and path:
        chunks.append((path, "".join(cur)))
    return chunks


def drop_hunks(chunk: str, pattern: str) -> tuple[str, int]:
    """Remove the hunks of a per-file diff whose changed lines match PATTERN."""
    head, *hunks = re.split(r"(?m)^(?=@@ )", chunk)
    keep = [h for h in hunks if not any(re.search(pattern, ln) for ln in h.splitlines()[1:] if ln[:1] in "+-")]
    return head + "".join(keep), len(hunks) - len(keep)


def fix_present(src: Path, ev: dict) -> tuple[bool, str]:
    """Apply the upstream commit in reverse, dry run: works only if the fixed code is in SRC.
    A fix with no upstream GRUB commit (a distribution's change to its own patch) names our
    patch instead ({"patch": "patches/<name>"}); the build also checks that it is absent from
    Ubuntu's tree alone, so the check still tells fixed from unfixed code."""
    patch = HERE / ev["patch"] if ev.get("patch") else UPSTREAM / f"{ev['commit']}.patch"
    files = ev.get("files")
    chunks = [(p, c) for p, c in split_patch(patch.read_text()) if not files or p in files]
    if files and sorted({p for p, _ in chunks}) != sorted(files):
        return False, f"{patch.name} does not touch {sorted(set(files) - {p for p, _ in chunks})}"
    dropped = 0
    if ev.get("skip_hunks_matching"):       # e.g. code for a driver 2.14 does not have
        chunks = [(p, drop_hunks(c, ev["skip_hunks_matching"])) for p, c in chunks]
        dropped = sum(n for _, (_, n) in chunks)
        chunks = [(p, c) for p, (c, _) in chunks]
    body = "".join(c for _, c in chunks)
    if "\n@@ " not in body:
        return False, "no hunks left to check"
    r = subprocess.run(["patch", "-p1", "-R", "--dry-run", "-F0", "-t", "-s", "-f"], cwd=src,
                       input=body.encode(), capture_output=True)
    out = (r.stdout + r.stderr).decode(errors="replace").strip()
    note = f" ({dropped} hunk(s) matching {ev['skip_hunks_matching']!r} not checked)" if dropped else ""
    return r.returncode == 0, (out or "reverse-applies cleanly (fuzz 0)") + note


def check_fixes(src: Path) -> dict:
    fx = load_fixes()
    results, missing = [], []
    for f in fx["fixes"]:
        evs = []
        for ev in f["evidence"]:
            ok, detail = fix_present(src, ev)
            what = f"our {ev['patch']}" if ev.get("patch") else "upstream commit"
            evs.append({"commit": ev.get("commit"), "patch": ev.get("patch"), "files": ev.get("files"), "present": ok,
                        "check": f"{what} reverse-applies to the patched source (patch -R --dry-run -F0)",
                        "detail": detail.splitlines()[:6]})
        present = bool(evs) and all(e["present"] for e in evs)    # no evidence proves nothing
        results.append({"id": f["id"], "type": f.get("type", "security"), "present": present, "where": f["where"],
                        "evidence": evs})
        if not present:
            missing.append(f["id"])
    claims = []
    for c in fx["sbat_claims"]:
        req = list(c.get("requires") or [])
        req_missing = [i for i in req if i in missing or i not in {f["id"] for f in fx["fixes"]}]
        claims.append({"component": c["component"], "generation": c["generation"], "shim_sbat_level": c["shim_sbat_level"],
                       "requires": req, "proven": bool(req) and not req_missing,       # nothing required proves nothing
                       "missing": req_missing if req else ["(the claim requires no fixes)"]})
    return {"fixes": results, "missing": missing, "sbat_claims": claims}


def claim_proven(sf: dict, c: dict) -> bool:
    """An SBAT claim of check_fixes() output SF, re-checked (fail closed): proven only if it
    requires at least one fix and every required fix is present with all its evidence."""
    fixes = {f["id"]: f for f in sf.get("fixes", [])}
    req = c.get("requires") or []
    return bool(c.get("proven")) and bool(req) and all(
        i in fixes and fixes[i].get("present") is True and fixes[i].get("evidence")
        and all(e.get("present") is True for e in fixes[i]["evidence"]) for i in req)


def prepare(lock: dict, srcs: dict[str, Path], cache: Path, work: Path, logf: Path) -> tuple[Path, dict]:
    src = work / "src"
    src.mkdir(parents=True)
    orig = next(p for n, p in srcs.items() if ".orig.tar" in n)
    debian = next(p for n, p in srcs.items() if ".debian.tar" in n)
    safe_extract(orig, src, strip=1)
    safe_extract(debian, src)
    ubuntu_series = [ln.strip() for ln in (src / "debian/patches/series").read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
    log(f"applying {len(ubuntu_series)} Ubuntu patches (debian/patches/series)")
    for name in ubuntu_series:
        apply_patch(src, src / "debian/patches" / name, logf)
    # debian/rules override_dh_autoreconf: the grub-extras it enables, then minilzo from liblzo2-dev
    extras = src / "debian/grub-extras-enabled"
    extras.mkdir()
    shutil.copytree(src / "debian/grub-extras/915resolution", extras / "915resolution")
    ours = read_series()
    before = {f["id"]: f["present"] for f in check_fixes(src)["fixes"]}   # Ubuntu's tree alone
    log(f"applying {len(ours)} beast-boot patch(es) (build/grub/patches/series)")
    applied = []
    for p in ours:
        apply_patch(src, p, logf)
        applied.append({"name": p.name, "sha256": sha256_file(p)})
    fixes = check_fixes(src)
    for f in fixes["fixes"]:
        f["present_without_our_patches"] = before[f["id"]]
    log("security fixes: " + ", ".join(f"{f['id']} {'ok' if f['present'] else 'MISSING'}" for f in fixes["fixes"]))
    for c in fixes["sbat_claims"]:
        if not c["proven"]:
            raise Fail(f"SBAT {c['component']},{c['generation']} is claimed in build/grub/security-fixes.json, "
                       f"but these fixes are NOT in the source: {', '.join(c['missing'])}. "
                       "Add the missing fixes (build/grub/patches) or lower the claim - never ship a "
                       "generation the code does not earn.")
    if fixes["missing"]:
        raise Fail(f"build/grub/security-fixes.json lists fixes that are not in the source: {fixes['missing']}")
    # A fix we say our patch brings must be absent from Ubuntu's tree: shows both that the
    # patch is needed and that the reverse-apply check tells fixed from unfixed code.
    wrong = [f["id"] for f in fixes["fixes"] if f["where"].startswith("build/grub/patches/")
             and f["present_without_our_patches"]]
    if wrong:
        raise Fail(f"fixes said to come from build/grub/patches are already in Ubuntu's source: {wrong}")
    info = {"ubuntu_patches": len(ubuntu_series),
            "ubuntu_series_sha256": sha256_file(src / "debian/patches/series"),
            "beast_booter_patches": applied, "security_fixes": fixes}
    return src, info


def extract_member(e: dict, cache: Path, dest: Path) -> Path:
    """One file (e['path']) of a locked .deb, unpacked into DEST."""
    deb = fetch_deb(e, cache / "dl")
    dest.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(dest)])
    p = dest / e["path"]
    if not p.is_file():
        raise Fail(f"{deb} has no {e['path']}")
    return p


def minilzo(lock: dict, cache: Path, src: Path) -> dict:
    e = lock["minilzo"]
    deb = fetch_deb(e, cache / "dl")
    with tempfile.TemporaryDirectory(dir=cache) as t:
        run(["dpkg-deb", "-x", str(deb), t])
        d = Path(t) / "usr/share/lzo/minilzo"
        files = sorted(p for p in d.iterdir() if p.suffix in (".c", ".h"))
        if not files:
            raise Fail(f"{deb}: no minilzo sources")
        for p in files:
            shutil.copyfile(p, src / "grub-core/lib/minilzo" / p.name)
    return {"package": f"{e['package']}={e['version']}", "files": [p.name for p in files]}


# --------------------------------------------------------------------------- build

def changelog_epoch(src: Path, version: str) -> int:
    text = (src / "debian/changelog").read_text()
    m = re.match(r"grub2 \(([^)]+)\)", text)
    if not m or m.group(1) != version:
        raise Fail(f"debian/changelog starts with {m and m.group(1)}, expected {version}")
    t = re.search(r"(?m)^ -- .*?>  (.+)$", text)
    return int(email.utils.parsedate_to_datetime(t.group(1)).timestamp())


def elf_is_static(p: Path) -> bool:
    """True if P (64-bit little-endian ELF) has no program interpreter and no dynamic
    section, so it needs no shared library (not even the host's libc) to run."""
    with open(p, "rb") as f:
        head = f.read(64)
        if len(head) < 64 or head[:4] != b"\x7fELF" or head[4:6] != b"\x02\x01":
            raise Fail(f"{p}: not a 64-bit little-endian ELF file")
        phoff, = struct.unpack_from("<Q", head, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", head, 0x36)
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
    if phentsize < 4 or len(ph) < phentsize * phnum:
        raise Fail(f"{p}: truncated ELF program headers")
    types = {struct.unpack_from("<I", ph, i * phentsize)[0] for i in range(phnum)}
    return not types & {2, 3}                   # PT_DYNAMIC, PT_INTERP


def build_platforms(lock: dict, src: Path, work: Path, env: dict, jobs: int, logs: Path, cache: Path,
                    static_mkimage: bool = False) -> None:
    """As debian/rules: build dirs obj/<package> inside the source tree, so the relative
    source paths GRUB embeds (__FILE__ in messages) are the same as in Ubuntu's build."""
    ver = build_version(lock)
    hf = env["_HOST_FLAGS"]
    mapped = f"/build/grub2-{ver}"
    pmap = f"-ffile-prefix-map={src}={mapped}"
    unifont = extract_member(lock["unifont"], cache, work / "unifont")
    benv = {k: v for k, v in env.items() if not k.startswith("_")}
    benv.update({
        "CPPFLAGS": "", "CFLAGS": "", "LDFLAGS": "",                    # debian/rules: keep debhelper's out
        "HOST_CPPFLAGS": hf["CPPFLAGS"], "HOST_CFLAGS": f"{hf['CFLAGS']} {pmap}", "HOST_LDFLAGS": hf["LDFLAGS"],
        "TARGET_CPPFLAGS": f"-Wno-unused-but-set-variable {pmap}", "TARGET_LDFLAGS": "-no-pie",
        "PYTHON": "python3", "GRUB_CONTRIB": str(src / "debian/grub-extras-enabled"),
    })
    log("autogen.sh")
    run(["./autogen.sh"], cwd=src, env=benv, logf=logs / "autogen.log")

    common = [f"PACKAGE_VERSION={ver}", f"PACKAGE_STRING=GRUB {ver}", "CC=gcc", "TARGET_CC=gcc",
              "--prefix=/usr", "--libdir=/usr/lib", "--libexecdir=/usr/lib", "--sysconfdir=/etc",
              "--localstatedir=/var", "--disable-silent-rules", "--disable-dependency-tracking",
              "--disable-maintainer-mode",
              # debian/rules confflags that change target code (Ubuntu: flicker-free boot) ...
              "--enable-ubuntu-recovery", "--enable-quiet-boot", "--enable-quick-boot", "--enable-gfxpayload-dynamic",
              "--disable-grub-emu-usb",
              # ... and utilities we do not build (grub-mkfont and the starfield theme come from grub2-common)
              "--disable-grub-mkfont", "--disable-grub-themes", "--disable-grub-mount", "--disable-device-mapper",
              "--disable-libzfs", f"--with-unifont={unifont}"]

    def configure(target: str) -> None:
        obj, flags = PLATFORMS[target]
        d = src / "obj" / obj
        d.mkdir(parents=True)
        log(f"configure {target}")
        clog = logs / f"configure-{target}.log"
        run(["../../configure", *common, *flags], cwd=d, env=benv, logf=clog)
        if f"With unifont from {unifont}" not in clog.read_text(errors="replace"):
            raise Fail(f"configure {target} did not take unifont (FreeType for the build missing?), see {clog}")

    with ThreadPoolExecutor(2) as ex:
        list(ex.map(configure, PLATFORMS))
    for target, (obj, _) in PLATFORMS.items():
        d = src / "obj" / obj
        log(f"make {target} (-j{jobs})")
        # headers made from unifont at the top level (font.mod's ASCII font, normal.mod's width table)
        run(["make", f"-j{jobs}", "ascii.h", "widthspec.h"], cwd=d, env=benv, logf=logs / f"make-{target}.log")
        run(["make", f"-j{jobs}", "-C", "grub-core"], cwd=d, env=benv, logf=logs / f"make-{target}.log")
        run(["make", f"-j{jobs}", "-C", "grub-core", "install", f"DESTDIR={work / 'inst'}"], cwd=d, env=benv,
            logf=logs / f"make-{target}.log")
    # grub-mkimage: debian/rules makes every image with the COMMON_PLATFORM (pc) build's grub-mkimage
    log("make grub-mkimage")
    pc = src / "obj" / PLATFORMS["i386-pc"][0]
    run(["make", f"-j{jobs}", "-C", "grub-core/lib/gnulib"], cwd=pc, env=benv, logf=logs / "make-grub-mkimage.log")
    mk = ["make", f"-j{jobs}", "grub-mkimage"]
    if static_mkimage:
        # docker builder: the host runs this grub-mkimage, and the image's glibc (26.04, GLIBC_2.38)
        # is newer than many hosts'. It needs only libc (no NSS), so link it statically.
        # configure leaves LDFLAGS empty (debian/rules: CPPFLAGS/CFLAGS/LDFLAGS=""): nothing is dropped.
        mk.append("LDFLAGS=-static")
    run(mk, cwd=pc, env=benv, logf=logs / "make-grub-mkimage.log")
    if static_mkimage and not elf_is_static(pc / "grub-mkimage"):
        raise Fail(f"grub-mkimage is not statically linked (see {logs / 'make-grub-mkimage.log'})")


def collect(lock: dict, src: Path, work: Path, out: Path) -> dict:
    files = {}
    for target in PLATFORMS:
        d = work / "inst/usr/lib/grub" / target
        if not (d / "kernel.img").is_file():
            raise Fail(f"make install left no {target}/kernel.img")
        # *.image are intermediate files Ubuntu does not ship either
        shutil.copytree(d, out / target, ignore=shutil.ignore_patterns("*.image"))
        # modinfo.sh records the compiler flags, -ffile-prefix-map with the build path included
        mi = out / target / "modinfo.sh"
        mi.write_text(mi.read_text().replace(str(src), f"/build/grub2-{build_version(lock)}"))
    (out / "bin").mkdir()
    shutil.copy2(src / "obj" / PLATFORMS["i386-pc"][0] / "grub-mkimage", out / "bin/grub-mkimage")
    shutil.copyfile(src / "debian/sbat.ubuntu.csv.in", out / "sbat.ubuntu.csv.in")
    shutil.copyfile(src / "debian/changelog", out / "debian-changelog")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            files[p.relative_to(out).as_posix()] = sha256_file(p)
    return files


def normalise_times(out: Path, epoch: int) -> None:
    for p in sorted(out.rglob("*"), reverse=True):
        os.utime(p, (epoch, epoch), follow_symlinks=False)


def cache_key(lock: dict, tc: dict, builder: str) -> tuple[str, dict]:
    inputs = {str(p.relative_to(ROOT)): sha256_file(p) for p in input_files()}
    material = {"inputs": inputs, "toolchain": tc, "builder": builder, "schema": INFO_SCHEMA}
    return sha256_bytes(json.dumps(material, sort_keys=True).encode())[:24], material


def native_env(lock: dict, cache: Path) -> tuple[dict, list[str]]:
    """The build env and the generators that are missing or do not run (see setup_generators)."""
    env = {k: v for k, v in os.environ.items()
           if k in ("PATH", "HOME", "TMPDIR", "LD_LIBRARY_PATH") or k.startswith("BB_")}
    env.update(LC_ALL="C", TZ="UTC", LANG="C")
    return setup_generators(lock, cache, env)


def build_native(lock: dict, cache: Path, jobs: int, env: dict, tc: dict, key: str, material: dict,
                 force: bool = False) -> Path:
    out = cache / "out" / key
    srcs = fetch_sources(lock, cache / "dl")
    tmp_root = cache / "work"
    tmp_root.mkdir(parents=True, exist_ok=True)
    # a fixed path per key (and one build per key at a time): nothing random reaches the output
    lockf = open(tmp_root / f"{key}.lock", "w")
    fcntl.flock(lockf, fcntl.LOCK_EX)
    if (out / "build-info.json").is_file() and not force:
        return out                                  # another process just built it
    work = tmp_root / f"{key}.build"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    logs = work / "logs"
    logs.mkdir()
    t0 = time.monotonic()
    try:
        src, info = prepare(lock, srcs, cache, work, logs / "patch.log")
        info["minilzo"] = minilzo(lock, cache, src)
        epoch = changelog_epoch(src, lock["source_version"])
        env = dict(env, SOURCE_DATE_EPOCH=str(epoch), _HOST_FLAGS=tc["host-flags"])
        static = material["builder"].startswith("docker:")
        build_platforms(lock, src, work, env, jobs, logs, cache, static_mkimage=static)
        u = lock["unifont"]
        info["unifont"] = f"{u['package']}={u['version']}:/{u['path']}"
        stage = Path(tempfile.mkdtemp(prefix=f"{key}.out.", dir=tmp_root))
        files = collect(lock, src, work, stage)
        build_info = {
            "schema": INFO_SCHEMA, "key": key, "name": "grub2", "version": build_version(lock),
            "source_package": lock["source_package"], "source_version": lock["source_version"],
            "upstream_version": lock["upstream_version"], "patch_level": lock["patch_level"],
            "purl_distro": lock["purl_distro"],
            "grub_mkimage_link": "static" if static else "dynamic (host libc)",
            "source_date_epoch": epoch, "platforms": list(PLATFORMS),
            "configure": {t: f for t, (_, f) in PLATFORMS.items()},
            "source": [{"name": e["name"], "sha256": e["sha256"], "url": e["urls"][0]} for e in lock["source"]],
            "inputs": material["inputs"], "toolchain": tc, "builder": material["builder"],
            **info, "files": files,
        }
        (stage / "build-info.json").write_text(json.dumps(build_info, indent=1, sort_keys=True) + "\n")
        normalise_times(stage, epoch)
        if out.exists():
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage, out)
        log(f"built GRUB {build_version(lock)} in {time.monotonic() - t0:.0f}s -> {out}")
    except BaseException:
        keep = tmp_root / f"failed-{key}"
        shutil.rmtree(keep, ignore_errors=True)
        shutil.move(str(logs), keep)
        print(f"grub: build logs kept in {keep}", file=sys.stderr)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def build_docker(lock: dict, cache: Path, jobs: int) -> Path:
    """Run this script with --builder native inside the pinned Ubuntu image."""
    d = lock["docker"]
    if offline():
        raise Fail("the docker GRUB builder pulls its image and installs packages from the network, and "
                   "BB_OFFLINE=1 forbids that: build natively (BB_GRUB_BUILDER=native)")
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise Fail("docker is not usable (no docker CLI or the daemon is not running)")
    uid, gid = os.getuid(), os.getgid()
    apt = " ".join(d["apt"])
    # snapshot.ubuntu.com is https-only, and the base image has no CA certificates yet
    script = (f"set -e; export DEBIAN_FRONTEND=noninteractive; apt-get -q update >/dev/null; "
              "apt-get -q install -y --no-install-recommends ca-certificates >/dev/null; "
              f"apt-get -q update --snapshot {d['snapshot']} >/dev/null; "
              f"DEBIAN_FRONTEND=noninteractive apt-get -q install -y --no-install-recommends --snapshot {d['snapshot']} "
              f"{apt} >/dev/null; "
              f"python3 -I /bb/build/grub/grubsrc.py build --builder native --builder-label docker:{d['image']} "
              f"--cache /cache -j {jobs}; chown -R {uid}:{gid} /cache")
    cache.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{HERE}:/bb/build/grub:ro", "-v", f"{cache}:/cache",
           "-e", "LC_ALL=C", "-e", "TZ=UTC", d["image"], "bash", "-c", script]
    log(f"docker build in {d['image']} (apt snapshot {d['snapshot']})")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise Fail(f"docker build failed (exit {r.returncode})")
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if not lines:
        raise Fail("docker build printed no output directory")
    return cache / Path(lines[-1]).relative_to("/cache")


# --------------------------------------------------------------------------- commands

def default_cache() -> Path:
    return Path(os.environ.get("BB_GRUB_CACHE") or ROOT / ".tools/cache/grub-src")


def cmd_build(a) -> int:
    lock = load_lock()
    cache = Path(a.cache).resolve()
    jobs = a.jobs or os.cpu_count() or 4
    builder = a.builder or os.environ.get("BB_GRUB_BUILDER") or "auto"
    if builder in ("auto", "native"):
        env, unusable = native_env(lock, cache)
        miss = check_native(env) + unusable
        if not miss:
            tc = toolchain(env)
            key, material = cache_key(lock, tc, a.builder_label or "native")
            out = cache / "out" / key
            if (out / "build-info.json").is_file() and not a.force:
                verify(out, quiet=True)
                log(f"cached: {out}")
            else:
                out = build_native(lock, cache, jobs, env, tc, key, material, force=a.force)
                verify(out, quiet=True)
            check_mkimage_runs(out)
            point_current(cache, out)
            print(out)
            return 0
        if builder == "native":
            raise Fail(f"cannot build natively, missing: {', '.join(miss)}")
        log(f"host lacks {', '.join(miss)}; using docker")
    out = build_docker(lock, cache, jobs)
    verify(out, quiet=True)
    check_mkimage_runs(out)
    point_current(cache, out)
    print(out)
    return 0


def check_mkimage_runs(out: Path) -> None:
    """build.sh and verify-dist.sh run OUT's grub-mkimage on this host: make sure it runs."""
    mk = out / "bin/grub-mkimage"
    try:
        r = subprocess.run([str(mk), "--version"], capture_output=True, text=True, timeout=60)
        err = None if r.returncode == 0 else (r.stderr or r.stdout).strip()[-500:] or f"exit {r.returncode}"
    except (OSError, subprocess.TimeoutExpired) as e:
        err = str(e)
    if err is not None:
        raise Fail(f"{mk} does not run on this host ({err}): a grub-mkimage linked against another system's "
                   "glibc needs that glibc or newer (host glibc too old?). The docker builder links it statically; "
                   f"remove {out} and build again")


def point_current(cache: Path, out: Path) -> None:
    """cache/current -> out/<key>: what scripts/dev-env.sh offers the dev tools (gdb, doctor,
    test stubs) as BB_GRUB_EFI_DIR / BB_GRUB_BIOS_DIR. build.sh never uses it."""
    link = cache / "current"
    tmp = cache / f".current.{os.getpid()}"
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(Path("out") / out.name)
    os.replace(tmp, link)


def verify(out: Path, quiet: bool = False) -> dict:
    info = json.loads((out / "build-info.json").read_text())
    if info.get("schema") != INFO_SCHEMA:
        raise Fail(f"{out}: build-info.json schema {info.get('schema')}")
    on_disk = sorted(p.relative_to(out).as_posix() for p in out.rglob("*")
                     if p.is_file() and p.name != "build-info.json")
    if on_disk != sorted(info["files"]):
        raise Fail(f"{out}: files differ from build-info.json "
                   f"(extra {sorted(set(on_disk) - set(info['files']))[:5]}, "
                   f"missing {sorted(set(info['files']) - set(on_disk))[:5]})")
    bad = [r for r, h in info["files"].items() if sha256_file(out / r) != h]
    if bad:
        raise Fail(f"{out}: modified files: {bad[:10]}")
    for c in info["security_fixes"]["sbat_claims"]:
        if not claim_proven(info["security_fixes"], c):
            raise Fail(f"{out}: SBAT claim {c['component']},{c['generation']} not proven")
    if not quiet:
        print(f"{out}: {len(info['files'])} files match build-info.json (GRUB {info['version']})")
    return info


def sbat_lines(out: Path) -> list[str]:
    """sbat + grub lines and Ubuntu's vendor lines (debian/sbat.ubuntu.csv.in, filled in as
    debian/rules does), with the grub generation raised to what security-fixes.json proves."""
    info = verify(out, quiet=True)
    proven = {c["component"]: c["generation"] for c in info["security_fixes"]["sbat_claims"] if c["proven"]}
    lines = []
    for ln in (out / "sbat.ubuntu.csv.in").read_text().splitlines():
        if not ln.strip():
            continue
        ln = ln.replace("@UPSTREAM_VERSION@", info["upstream_version"]).replace("@DEB_VERSION@", info["source_version"])
        f = ln.split(",")
        if len(f) != 6 or "@" in ln:
            raise Fail(f"unexpected SBAT template line: {ln}")
        if f[0] in proven and int(f[1]) < proven[f[0]]:
            f[1] = str(proven[f[0]])
        lines.append(",".join(f))
    return lines


def main() -> int:
    global QUIET
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--cache", default=str(default_cache()))
    b.add_argument("--builder", choices=["auto", "native", "docker"])
    b.add_argument("--builder-label", help=argparse.SUPPRESS)
    b.add_argument("-j", "--jobs", type=int)
    b.add_argument("--force", action="store_true", help="rebuild even if the cache has this key")
    b.add_argument("--quiet", action="store_true")
    k = sub.add_parser("key")
    k.add_argument("--cache", default=str(default_cache()))
    v = sub.add_parser("verify")
    v.add_argument("outdir")
    s = sub.add_parser("sbat")
    s.add_argument("outdir")
    i = sub.add_parser("info", help="print FIELD values of OUTDIR/build-info.json, one per line")
    i.add_argument("outdir")
    i.add_argument("fields", nargs="+")
    a = ap.parse_args()
    try:
        if a.cmd == "build":
            QUIET = a.quiet
            return cmd_build(a)
        if a.cmd == "key":
            lock = load_lock()
            env, _ = native_env(lock, Path(a.cache).resolve())
            key, material = cache_key(lock, toolchain(env), "native")
            print(json.dumps({"key": key, **material}, indent=1, sort_keys=True))
            return 0
        if a.cmd == "verify":
            verify(Path(a.outdir))
            return 0
        if a.cmd == "sbat":
            print("\n".join(sbat_lines(Path(a.outdir))))
            return 0
        if a.cmd == "info":
            info = json.loads((Path(a.outdir) / "build-info.json").read_text())
            for f in a.fields:
                v = info
                for part in f.split("."):
                    v = v[part]
                print(v if isinstance(v, (str, int)) else json.dumps(v, sort_keys=True))
            return 0
    except Fail as e:
        print(f"grub: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
