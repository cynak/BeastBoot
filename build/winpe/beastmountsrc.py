#!/usr/bin/env python3
"""Build beastmount.exe (attaches an ISO in Windows PE) with the pinned MinGW-w64 cross compiler.

    python3 -I build/winpe/beastmountsrc.py build  [--cache DIR] [--builder auto|native|docker] [--force] [--quiet]
    python3 -I build/winpe/beastmountsrc.py key    print the cache key of the current inputs
    python3 -I build/winpe/beastmountsrc.py verify OUTDIR          check OUTDIR against its build-info.json
    python3 -I build/winpe/beastmountsrc.py info   OUTDIR FIELD... print build-info.json fields
    python3 -I build/winpe/beastmountsrc.py check  FILE            check a beastmount.exe image, print its facts

`build` prints the output directory (.tools/cache/beastmount/out/<key>) on stdout as its last
line; everything else goes to stderr. OUTDIR/beastmount.exe is the file build/build.sh ships
as esp/beast-booter/winpe/beastmount.exe.

Inputs (all hashed into the cache key):
  build/winpe/beastmount.c          the program (our own source, GPL-3.0-or-later)
  build/winpe/mingw-w64.lock.json   the compiler: Ubuntu 26.04's MinGW-w64 .deb files (SHA-256,
                                    size), the compiler flags
  build/winpe/beastmountsrc.py      this script
The .deb files are downloaded once into the cache, checked, unpacked with `dpkg-deb -x` and the
compiler runs from there (it finds its own as/ld/headers relative to itself), so every build
uses the same compiler bytes whatever the host has installed. Only the compiler's shared
libraries come from the host (lock "host_libs"); without them, or without dpkg-deb, the build
runs in GRUB's pinned Ubuntu image (build/grub/source.lock.json "docker", apt snapshot).

Reproducible: every build compiles the program twice, in two different directories, and fails
unless both give the same bytes; the image has no time stamp (TimeDateStamp 0), no symbols
and no build path. BB_OFFLINE=1: no downloads (the .deb files must be in the cache).
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LOCK = HERE / "mingw-w64.lock.json"
SOURCE = HERE / "beastmount.c"
GRUB_LOCK = ROOT / "build" / "grub" / "source.lock.json"
INFO_SCHEMA = 1
OUTPUT = "beastmount.exe"
ALLOWED_DLLS = {"kernel32.dll", "msvcrt.dll"}   # in every Windows PE; virtdisk.dll is loaded at run time
QUIET = False


class Fail(Exception):
    pass


def log(msg: str) -> None:
    if not QUIET:
        print(f"beastmount: {msg}", file=sys.stderr, flush=True)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lock() -> dict:
    lock = json.loads(LOCK.read_text())
    if lock.get("schema") != 1:
        raise Fail(f"{LOCK}: unknown schema {lock.get('schema')}")
    for k in ("mirrors", "packages", "gcc", "cflags"):
        if k not in lock:
            raise Fail(f"{LOCK}: '{k}' missing")
    for p in lock["packages"]:
        if not re.fullmatch(r"pool/[a-z0-9/+._-]+\.deb", p["file"]) or ".." in p["file"]:
            raise Fail(f"{LOCK}: bad file {p['file']!r}")
    return lock


def source_version() -> str:
    m = re.search(r'^#define BEASTMOUNT_VERSION "([0-9][0-9A-Za-z.+~-]*)"$', SOURCE.read_text(), re.M)
    if not m:
        raise Fail(f"{SOURCE}: no BEASTMOUNT_VERSION")
    return m.group(1)


def input_files() -> list[Path]:
    return [SOURCE, LOCK, Path(__file__).resolve()]


def offline() -> bool:
    return os.environ.get("BB_OFFLINE") == "1"


def default_cache() -> Path:
    return Path(os.environ.get("BB_BEASTMOUNT_CACHE") or ROOT / ".tools/cache/beastmount")


def cache_key(builder: str) -> tuple[str, dict]:
    inputs = {str(p.relative_to(ROOT)): sha256_file(p) for p in input_files()}
    material = {"inputs": inputs, "builder": builder, "schema": INFO_SCHEMA}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:24], material


def toolchain_id(lock: dict) -> str:
    return hashlib.sha256(json.dumps(lock["packages"], sort_keys=True).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- toolchain

def fetch_debs(lock: dict, dl: Path) -> list[Path]:
    dl.mkdir(parents=True, exist_ok=True)
    out = []
    for p in lock["packages"]:
        dest = dl / p["file"].rsplit("/", 1)[1]
        out.append(dest)
        if dest.is_file() and dest.stat().st_size == p["size"] and sha256_file(dest) == p["sha256"]:
            continue
        if offline():
            raise Fail(f"{dest.name} is not in {dl} (or does not match the lock) and BB_OFFLINE=1: "
                       "run the build once online to fill the cache")
        errors = []
        for mirror in lock["mirrors"]:
            url = mirror + p["file"]
            tmp = dest.with_name(dest.name + ".part")
            try:
                log(f"downloading {url}")
                with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as f:
                    while chunk := resp.read(1 << 20):
                        f.write(chunk)
            except OSError as e:
                errors.append(f"{url}: {e}")
                tmp.unlink(missing_ok=True)
                continue
            got, size = sha256_file(tmp), tmp.stat().st_size
            if got != p["sha256"] or size != p["size"]:
                errors.append(f"{url}: SHA-256 {got} / size {size}, lock says {p['sha256']} / {p['size']}")
                tmp.unlink(missing_ok=True)
                continue
            os.replace(tmp, dest)
            break
        else:
            raise Fail(f"cannot fetch {dest.name}:\n  " + "\n  ".join(errors))
    return out


def deb_control(deb: Path) -> dict:
    r = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"],
                       capture_output=True, text=True, check=True)
    return dict(ln.split(": ", 1) for ln in r.stdout.splitlines() if ": " in ln)


def toolchain(lock: dict, cache: Path) -> Path:
    """The unpacked compiler (cache/toolchain/<id>), made once from the checked .deb files."""
    tc = cache / "toolchain" / toolchain_id(lock)
    stamp = tc / ".bb-complete"
    tc.parent.mkdir(parents=True, exist_ok=True)
    lockf = open(tc.parent / f"{tc.name}.lock", "w")
    fcntl.flock(lockf, fcntl.LOCK_EX)
    if stamp.is_file():
        return tc
    debs = fetch_debs(lock, cache / "dl")
    stage = Path(tempfile.mkdtemp(prefix=f"{tc.name}.", dir=tc.parent))
    try:
        for p, deb in zip(lock["packages"], debs):
            c = deb_control(deb)
            if (c.get("Package"), c.get("Version"), c.get("Architecture")) != (p["name"], p["version"], p["arch"]):
                raise Fail(f"{deb.name}: control says {c}, the lock {p['name']} {p['version']} {p['arch']}")
            subprocess.run(["dpkg-deb", "-x", str(deb), str(stage)], check=True)
        (stage / ".bb-complete").write_text(json.dumps(lock["packages"], indent=1) + "\n")
        tc.parent.mkdir(parents=True, exist_ok=True)
        if tc.exists():
            shutil.rmtree(tc)
        os.replace(stage, tc)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return tc


def build_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME")}
    env.update(LC_ALL="C", TZ="UTC", LANG="C")
    return env


def host_ready() -> list[str]:
    """What the native builder lacks: dpkg-deb, or a compiler that runs here."""
    miss = [t for t in ("dpkg-deb",) if shutil.which(t) is None]
    return miss


def compiler_runs(gcc: Path, env: dict) -> str | None:
    """None if the unpacked compiler runs (its shared libraries are on the host), else why not."""
    try:
        r = subprocess.run([str(gcc), "-E", "-x", "c", "-", "-o", os.devnull], input=b"#include <windows.h>\n",
                           capture_output=True, env=env, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e)
    return None if r.returncode == 0 else (r.stderr.decode(errors="replace").strip().splitlines() or ["?"])[-1]


def host_lib_versions(lock: dict) -> dict:
    out = {}
    for name in lock.get("host_libs", []):
        r = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", f"{name}:amd64"], capture_output=True, text=True)
        if r.returncode != 0:
            r = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", name], capture_output=True, text=True)
        out[name] = r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else "unknown"
    return out


# --------------------------------------------------------------------------- output checks

def pe_facts(data: bytes) -> dict:
    """What Windows PE relies on and what makes the file reproducible: PE32+ x86_64 console
    program, no time stamp, no signature, the DLLs it imports."""
    if len(data) < 0x200 or data[:2] != b"MZ":
        raise Fail("not an MZ/PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise Fail("no PE header")
    machine, nsect, stamp = struct.unpack_from("<HHI", data, pe + 4)
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    oh = pe + 24
    if struct.unpack_from("<H", data, oh)[0] != 0x20B:
        raise Fail("not a PE32+ image")
    subsystem, dllchar = struct.unpack_from("<HH", data, oh + 68)
    nrva = struct.unpack_from("<I", data, oh + 108)[0]
    dirs = [struct.unpack_from("<II", data, oh + 112 + 8 * i) for i in range(min(nrva, 16))]
    sections = []
    sh = oh + opt_size
    for i in range(nsect):
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, sh + 40 * i + 8)
        sections.append((va, max(vsize, rsize), roff))

    def off(rva: int) -> int:
        for va, size, roff in sections:
            if va <= rva < va + size:
                return rva - va + roff
        raise Fail(f"RVA {rva:#x} is in no section")

    def cstr(rva: int) -> str:
        o = off(rva)
        return data[o:data.index(b"\0", o)].decode("ascii", "replace")

    dlls = []
    if len(dirs) > 1 and dirs[1][0]:
        o = off(dirs[1][0])
        while True:
            desc = struct.unpack_from("<IIIII", data, o)
            if not any(desc):
                break
            dlls.append(cstr(desc[3]))
            o += 20
    return {"machine": f"{machine:#06x}", "subsystem": subsystem, "timestamp": stamp,
            "dll_characteristics": f"{dllchar:#06x}", "signed": len(dirs) > 4 and dirs[4][1] != 0,
            "imports": dlls, "size": len(data)}


def check_output(path: Path, version: str | None = None) -> dict:
    data = path.read_bytes()
    f = pe_facts(data)
    problems = []
    if f["machine"] != "0x8664":
        problems.append(f"PE machine {f['machine']}, not x86_64")
    if f["subsystem"] != 3:
        problems.append(f"subsystem {f['subsystem']}, not a console program (3)")
    if f["timestamp"] != 0:
        problems.append(f"TimeDateStamp {f['timestamp']:#x}, not 0 (--no-insert-timestamp missing?)")
    if f["signed"]:
        problems.append("the image carries a signature (we build it unsigned)")
    extra = sorted({d.lower() for d in f["imports"]} - ALLOWED_DLLS)
    if extra:
        problems.append(f"imports {extra}: Windows PE may not have them (allowed: {sorted(ALLOWED_DLLS)})")
    for leak in (b"/home/", b"/tmp/", b"/build/", b".tools/"):
        if leak in data:
            problems.append(f"contains a build path ({leak.decode()})")
    if version is not None and f"beastmount {version}".encode("utf-16-le") not in data:
        problems.append(f"no 'beastmount {version}' version string")
    if problems:
        raise Fail(f"{path}: " + "; ".join(problems))
    return f


# --------------------------------------------------------------------------- build

def compile_once(gcc: Path, lock: dict, work: Path, env: dict, logf: Path) -> bytes:
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    shutil.copyfile(SOURCE, work / SOURCE.name)
    cmd = [str(gcc), *lock["cflags"], f"-ffile-prefix-map={work}=/beastmount", "-o", OUTPUT, SOURCE.name]
    with open(logf, "ab") as out:
        out.write(f"\n$ {' '.join(cmd)}  (in {work})\n".encode())
        out.flush()
        r = subprocess.run(cmd, cwd=work, env=dict(env, TMPDIR=str(work)), stdout=out, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        tail = logf.read_text(errors="replace").splitlines()[-30:]
        raise Fail(f"compiling beastmount.c failed (exit {r.returncode}):\n  " + "\n  ".join(tail))
    return (work / OUTPUT).read_bytes()


def build_native(lock: dict, cache: Path, key: str, material: dict, force: bool = False) -> Path:
    out = cache / "out" / key
    tc = toolchain(lock, cache)
    gcc = tc / lock["gcc"]
    env = build_env()
    why = compiler_runs(gcc, env)
    if why is not None:
        raise Fail(f"the pinned compiler does not run on this host ({why}); host libraries needed: "
                   f"{', '.join(lock.get('host_libs', []))} (or BB_BEASTMOUNT_BUILDER=docker)")
    tmp_root = cache / "work"
    tmp_root.mkdir(parents=True, exist_ok=True)
    lockf = open(tmp_root / f"{key}.lock", "w")
    fcntl.flock(lockf, fcntl.LOCK_EX)
    if (out / "build-info.json").is_file() and not force:
        return out
    version = source_version()
    logf = tmp_root / f"{key}.log"
    logf.unlink(missing_ok=True)
    t0 = time.monotonic()
    a_dir, b_dir = tmp_root / f"{key}.a", tmp_root / f"{key}.b-other-path"
    try:
        a = compile_once(gcc, lock, a_dir, env, logf)
        b = compile_once(gcc, lock, b_dir, env, logf)
        if a != b:
            raise Fail(f"two builds differ (sha256 {hashlib.sha256(a).hexdigest()} and "
                       f"{hashlib.sha256(b).hexdigest()}): the build is not reproducible")
        facts = check_output(a_dir / OUTPUT, version)
        stage = Path(tempfile.mkdtemp(prefix=f"{key}.out.", dir=tmp_root))
        os.chmod(stage, 0o755)
        shutil.copyfile(a_dir / OUTPUT, stage / OUTPUT)
        os.chmod(stage / OUTPUT, 0o644)
        gcc_ver = subprocess.run([str(gcc), "--version"], capture_output=True, text=True, env=env).stdout
        info = {
            "schema": INFO_SCHEMA, "key": key, "name": "beastmount", "version": version,
            "license": "GPL-3.0-or-later", "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": sha256_file(SOURCE), "inputs": material["inputs"], "builder": material["builder"],
            "toolchain": {"packages": [{k: p[k] for k in ("name", "version", "arch", "sha256")}
                                       for p in lock["packages"]],
                          "distro": lock.get("distro"), "snapshot": lock.get("snapshot"),
                          "gcc": gcc_ver.splitlines()[0] if gcc_ver else "unknown",
                          "cflags": lock["cflags"], "host_libs": host_lib_versions(lock)},
            "reproducible": "built twice in different directories: identical",
            "facts": facts, "files": {OUTPUT: sha256_file(stage / OUTPUT)},
        }
        (stage / "build-info.json").write_text(json.dumps(info, indent=1, sort_keys=True) + "\n")
        if out.exists():
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage, out)
        log(f"built beastmount {version} in {time.monotonic() - t0:.1f}s (twice, identical) -> {out}")
    except BaseException:
        if logf.is_file():
            keep = tmp_root / f"failed-{key}.log"
            shutil.copyfile(logf, keep)
            print(f"beastmount: build log kept in {keep}", file=sys.stderr)
        raise
    finally:
        shutil.rmtree(a_dir, ignore_errors=True)
        shutil.rmtree(b_dir, ignore_errors=True)
    return out


def build_docker(lock: dict, cache: Path) -> Path:
    """Run this script with --builder native inside GRUB's pinned Ubuntu image (host libraries
    and dpkg from its apt snapshot; the compiler is the same pinned .deb files)."""
    d = json.loads(GRUB_LOCK.read_text())["docker"]
    if offline():
        raise Fail("the docker builder installs packages from the network and BB_OFFLINE=1 forbids that")
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise Fail("docker is not usable (no docker CLI or the daemon is not running)")
    fetch_debs(lock, cache / "dl")              # on the host: the container builds offline
    uid, gid = os.getuid(), os.getgid()
    apt = " ".join(["python3", "dpkg", *lock.get("host_libs", [])])
    script = (f"set -e; export DEBIAN_FRONTEND=noninteractive; apt-get -q update >/dev/null; "
              "apt-get -q install -y --no-install-recommends ca-certificates >/dev/null; "
              f"apt-get -q update --snapshot {d['snapshot']} >/dev/null; "
              f"apt-get -q install -y --no-install-recommends --snapshot {d['snapshot']} {apt} >/dev/null; "
              f"BB_OFFLINE=1 python3 -I /bb/build/winpe/beastmountsrc.py build --builder native "
              f"--builder-label docker --cache /cache; chown -R {uid}:{gid} /cache")
    cache.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{HERE}:/bb/build/winpe:ro", "-v", f"{cache}:/cache",
           "-e", "LC_ALL=C", "-e", "TZ=UTC", d["image"], "bash", "-c", script]
    log(f"docker build in {d['image']} (apt snapshot {d['snapshot']})")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if r.returncode != 0 or not lines:
        raise Fail(f"docker build failed (exit {r.returncode})")
    return cache / Path(lines[-1]).relative_to("/cache")


def verify(out: Path, quiet: bool = False) -> dict:
    info = json.loads((out / "build-info.json").read_text())
    if info.get("schema") != INFO_SCHEMA:
        raise Fail(f"{out}: build-info.json schema {info.get('schema')}")
    on_disk = sorted(p.relative_to(out).as_posix() for p in out.rglob("*")
                     if p.is_file() and p.name != "build-info.json")
    if on_disk != sorted(info["files"]):
        raise Fail(f"{out}: files differ from build-info.json ({on_disk} vs {sorted(info['files'])})")
    bad = [r for r, h in info["files"].items() if sha256_file(out / r) != h]
    if bad:
        raise Fail(f"{out}: modified files: {bad}")
    check_output(out / OUTPUT, info["version"])
    if not quiet:
        print(f"{out}: {OUTPUT} matches build-info.json (beastmount {info['version']}, sha256 {info['files'][OUTPUT]})")
    return info


def cmd_build(a) -> int:
    lock = load_lock()
    cache = Path(a.cache).resolve()
    builder = a.builder or os.environ.get("BB_BEASTMOUNT_BUILDER") or "auto"
    if builder in ("auto", "native"):
        miss = host_ready()
        why = None
        if not miss:
            key, material = cache_key(a.builder_label or "native")
            out = cache / "out" / key
            if (out / "build-info.json").is_file() and not a.force:
                log(f"cached: {out}")
                verify(out, quiet=True)
                print(out)
                return 0
            try:
                out = build_native(lock, cache, key, material, force=a.force)
                verify(out, quiet=True)
                print(out)
                return 0
            except Fail as e:
                if builder == "native" or "does not run on this host" not in str(e):
                    raise
                why = str(e)
        if builder == "native":
            raise Fail(f"cannot build natively, missing: {', '.join(miss)}")
        log(f"{why or 'host lacks ' + ', '.join(miss)}; using docker")
    out = build_docker(lock, cache)
    verify(out, quiet=True)
    print(out)
    return 0


def main() -> int:
    global QUIET
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--cache", default=str(default_cache()))
    b.add_argument("--builder", choices=["auto", "native", "docker"])
    b.add_argument("--builder-label", help=argparse.SUPPRESS)
    b.add_argument("--force", action="store_true", help="rebuild even if the cache has this key")
    b.add_argument("--quiet", action="store_true")
    sub.add_parser("key")
    v = sub.add_parser("verify")
    v.add_argument("outdir")
    i = sub.add_parser("info", help="print FIELD values of OUTDIR/build-info.json, one per line")
    i.add_argument("outdir")
    i.add_argument("fields", nargs="+")
    c = sub.add_parser("check", help="check FILE as a beastmount.exe image; print its facts")
    c.add_argument("file")
    a = ap.parse_args()
    try:
        if a.cmd == "build":
            QUIET = a.quiet
            return cmd_build(a)
        if a.cmd == "key":
            key, material = cache_key("native")
            print(json.dumps({"key": key, **material}, indent=1, sort_keys=True))
            return 0
        if a.cmd == "verify":
            verify(Path(a.outdir))
            return 0
        if a.cmd == "check":
            print(json.dumps(check_output(Path(a.file)), sort_keys=True))
            return 0
        if a.cmd == "info":
            info = json.loads((Path(a.outdir) / "build-info.json").read_text())
            for f in a.fields:
                val = info
                for part in f.split("."):
                    val = val[part]
                print(val if isinstance(val, (str, int)) else json.dumps(val, sort_keys=True))
            return 0
    except Fail as e:
        print(f"beastmount: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
