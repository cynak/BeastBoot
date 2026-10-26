#!/usr/bin/env python3
"""Build iPXE's wimboot (the Windows PE loader on the ESP) from pinned source.

    python3 -I build/wimboot/wimbootsrc.py build  [--cache DIR] [--builder auto|native|docker] [--force] [-j N] [--quiet]
    python3 -I build/wimboot/wimbootsrc.py key    [--cache DIR]   print the cache key of the current inputs
    python3 -I build/wimboot/wimbootsrc.py verify OUTDIR          check OUTDIR against its build-info.json
    python3 -I build/wimboot/wimbootsrc.py info   OUTDIR FIELD... print build-info.json fields
    python3 -I build/wimboot/wimbootsrc.py check  FILE VERSION    check a wimboot image (headers, unsigned, SBAT)

`build` prints the output directory (.tools/cache/wimboot/out/<key>) on stdout
as its last line; everything else goes to stderr. OUTDIR/wimboot is the file
build/build.sh ships as esp/beast-booter/wimboot.

Inputs (all in build/wimboot/, all hashed into the cache key):
  source.lock.json   the release tag's source archive (SHA-256, size, commit id)
  patches/series     our patches (each one explains itself), applied with patch -p1 -F0
  wimbootsrc.py      this script
plus the toolchain identity (gcc, binutils, make, patch, libc) and the builder.

One binary serves both firmware types: wimboot's x86_64 image is a hybrid with
a bzImage header (GRUB `linux16` on BIOS) and a PE32+ EFI entry point (GRUB
`linux` on UEFI). `build` checks both headers, the PE MajorImageVersion that
GRUB needs to pass the initrd (patch 0002), that the image carries no
signature, and its SBAT lines.

Builders: `native` uses the host's gcc/binutils/make; `docker` runs the native
build inside GRUB's pinned Ubuntu image (build/grub/source.lock.json, packages
from its apt snapshot); `auto` (default) is native when the tools are there,
else docker. BB_OFFLINE=1: no downloads (the source must be in the cache).
Reproducible: a fixed build path per key, -ffile-prefix-map, LC_ALL=C, TZ=UTC
and fixed file times; wimboot itself embeds no date. Two builds with the same
key give the same bytes (build-info.json lists their SHA-256).
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
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LOCK = HERE / "source.lock.json"
SERIES = HERE / "patches" / "series"
GRUB_LOCK = ROOT / "build" / "grub" / "source.lock.json"
NEEDED = ["gcc", "as", "ld", "ar", "objcopy", "make", "patch", "cut"]
INFO_SCHEMA = 1
OUTPUT = "wimboot"
QUIET = False


class Fail(Exception):
    pass


def log(msg: str) -> None:
    if not QUIET:
        print(f"wimboot: {msg}", file=sys.stderr, flush=True)


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
    for k in ("upstream_version", "commit", "patch_level", "source", "source_date_epoch", "target"):
        if k not in lock:
            raise Fail(f"{LOCK}: '{k}' missing")
    return lock


def build_version(lock: dict) -> str:
    """Our version: upstream's plus +bb<patch level> (wimboot prints it as v<version>)."""
    return f"{lock['upstream_version']}+bb{lock['patch_level']}"


def read_series() -> list[Path]:
    names = [ln.split("#", 1)[0].strip() for ln in SERIES.read_text().splitlines()]
    out = [SERIES.parent / n for n in names if n]
    for p in out:
        if not p.is_file():
            raise Fail(f"{SERIES}: {p.name} not found")
    return out


def input_files() -> list[Path]:
    return [LOCK, SERIES, *read_series(), Path(__file__).resolve()]


def offline() -> bool:
    return os.environ.get("BB_OFFLINE") == "1"


def fetch_source(lock: dict, dl: Path) -> Path:
    s = lock["source"]
    dest = dl / s["name"]
    if dest.is_file() and sha256_file(dest) == s["sha256"]:
        return dest
    if offline():
        raise Fail(f"{dest.name} is not in {dl} (or does not match the lock) and BB_OFFLINE=1: "
                   "run the build once online to fill the cache")
    dl.mkdir(parents=True, exist_ok=True)
    errors = []
    for url in s["urls"]:
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
        got, size = sha256_file(tmp), tmp.stat().st_size
        if got != s["sha256"] or size != s["size"]:
            errors.append(f"{url}: SHA-256 {got} / size {size}, lock says {s['sha256']} / {s['size']}")
            tmp.unlink(missing_ok=True)
            continue
        os.replace(tmp, dest)
        return dest
    raise Fail(f"cannot fetch {dest.name}:\n  " + "\n  ".join(errors))


KEEP = ("src", "LICENSE.txt")       # what the build needs from the archive (test/ has symlinks)


def safe_extract(tar: Path, dest: Path, commit: str) -> None:
    """Unpack src/ and LICENSE.txt of TAR into DEST, without the top directory; refuse links or
    paths that leave DEST, and an archive that is not of COMMIT (GitHub records it in the pax
    global header)."""
    with tarfile.open(tar) as tf:
        got = tf.pax_headers.get("comment", "")
        if got != commit:
            raise Fail(f"{tar.name} is of commit '{got}', the lock says {commit}")
        members = []
        for m in tf.getmembers():
            parts = Path(m.name).parts[1:]
            if not parts or parts[0] not in KEEP:
                continue
            if Path(m.name).is_absolute() or ".." in Path(m.name).parts:
                raise Fail(f"{tar.name}: unsafe member {m.name}")
            if m.issym() or m.islnk():
                tgt = Path(m.linkname)
                if tgt.is_absolute() or ".." in tgt.parts:
                    raise Fail(f"{tar.name}: unsafe link {m.name} -> {m.linkname}")
            m.name = str(Path(*parts))
            members.append(m)
        tf.extractall(dest, members=members, filter="tar")


def run(cmd: list[str], cwd: Path, env: dict, logf: Path) -> None:
    with open(logf, "ab") as out:
        out.write(f"\n$ {' '.join(cmd)}  (in {cwd})\n".encode())
        out.flush()
        r = subprocess.run(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        tail = logf.read_text(errors="replace").splitlines()[-30:]
        raise Fail(f"{' '.join(cmd[:3])} failed (exit {r.returncode}); last lines of {logf}:\n  " + "\n  ".join(tail))


def tool_version(cmd: list[str], env: dict) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "missing"
    first = (r.stdout or r.stderr).strip().splitlines()
    return re.sub(r"^\S*/(\S+)", r"\1", first[0].strip()) if first else f"exit {r.returncode}"


def build_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR")}
    env.update(LC_ALL="C", TZ="UTC", LANG="C")
    return env


def toolchain(env: dict) -> dict:
    t = {n: tool_version([n, "--version"], env) for n in ("gcc", "as", "ld", "ar", "objcopy", "make", "patch")}
    t["gcc-full"] = tool_version(["gcc", "-dumpfullversion"], env) + " " + tool_version(["gcc", "-dumpmachine"], env)
    t["libc"] = tool_version(["ldd", "--version"], env)
    return t


def missing_tools(env: dict) -> list[str]:
    path = env.get("PATH", "")
    miss = [t for t in NEEDED if shutil.which(t, path=path) is None]
    if "gcc" not in miss:
        # the host tool elf2efi needs the C library headers (libc6-dev)
        try:
            r = subprocess.run(["gcc", "-E", "-x", "c", "-", "-o", os.devnull], input=b"#include <unistd.h>\n",
                               capture_output=True, env=env, timeout=60)
            if r.returncode != 0:
                miss.append("C library headers (libc6-dev)")
        except (OSError, subprocess.TimeoutExpired):
            miss.append("gcc (does not run)")
    return miss


def cache_key(tc: dict, builder: str) -> tuple[str, dict]:
    inputs = {str(p.relative_to(ROOT)): sha256_file(p) for p in input_files()}
    material = {"inputs": inputs, "toolchain": tc, "builder": builder, "schema": INFO_SCHEMA}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:24], material


# --------------------------------------------------------------------------- output checks

def pe_facts(data: bytes) -> dict:
    """What GRUB and the firmware rely on: the bzImage header (BIOS, linux16), the PE32+ x86_64
    header (UEFI), MajorImageVersion (GRUB's LoadFile2 initrd path), no signature, SBAT."""
    if len(data) < 0x400 or data[:2] != b"MZ":
        raise Fail("not an MZ/PE image")
    facts = {"bzimage": data[0x202:0x206] == b"HdrS",
             "boot_protocol": f"{struct.unpack_from('<H', data, 0x206)[0]:#06x}"}
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise Fail("no PE header")
    machine, nsect = struct.unpack_from("<HH", data, pe + 4)
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    oh = pe + 24
    if struct.unpack_from("<H", data, oh)[0] != 0x20B:
        raise Fail("not a PE32+ image")
    facts["machine"] = f"{machine:#06x}"
    facts["major_image_version"] = struct.unpack_from("<H", data, oh + 44)[0]
    nrva = struct.unpack_from("<I", data, oh + 108)[0]
    facts["signed"] = nrva > 4 and struct.unpack_from("<II", data, oh + 112 + 8 * 4)[1] != 0
    sbat = ""
    sh = oh + opt_size
    for i in range(nsect):
        name = data[sh + 40 * i:sh + 40 * i + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, _va, rsize, roff = struct.unpack_from("<IIII", data, sh + 40 * i + 8)
        if name == ".sbat":
            sbat = data[roff:roff + min(vsize or rsize, rsize)].split(b"\0", 1)[0].decode("ascii", "replace")
    facts["sbat"] = sbat
    return facts


def check_output(path: Path, version: str) -> dict:
    f = pe_facts(path.read_bytes())
    problems = []
    if not f["bzimage"]:
        problems.append("no bzImage header (GRUB linux16 could not load it on BIOS)")
    if f["machine"] != "0x8664":
        problems.append(f"PE machine {f['machine']}, not x86_64")
    if f["major_image_version"] < 1:
        problems.append("PE MajorImageVersion 0: GRUB would not pass the initrd on UEFI (patch 0002 missing?)")
    if f["signed"]:
        problems.append("the image carries a signature (we build it unsigned)")
    if not re.search(r"^wimboot,\d+,iPXE,wimboot,", f["sbat"], re.M):
        problems.append("SBAT lacks upstream's wimboot line")
    if f"wimboot.beastboot,1,BeastBoot,wimboot,v{version}," not in f["sbat"]:
        problems.append("SBAT lacks our vendor line (patch 0003 missing?)")
    if problems:
        raise Fail(f"{path}: " + "; ".join(problems))
    return f


# --------------------------------------------------------------------------- build

def build_native(lock: dict, cache: Path, jobs: int, env: dict, tc: dict, key: str, material: dict,
                 force: bool = False) -> Path:
    out = cache / "out" / key
    tar = fetch_source(lock, cache / "dl")
    tmp_root = cache / "work"
    tmp_root.mkdir(parents=True, exist_ok=True)
    # a fixed path per key (one build per key at a time): nothing random reaches the output
    lockf = open(tmp_root / f"{key}.lock", "w")
    fcntl.flock(lockf, fcntl.LOCK_EX)
    if (out / "build-info.json").is_file() and not force:
        return out
    work = tmp_root / f"{key}.build"
    shutil.rmtree(work, ignore_errors=True)
    src = work / f"wimboot-{lock['upstream_version']}"
    src.mkdir(parents=True)
    logf = work / "build.log"
    t0 = time.monotonic()
    version = build_version(lock)
    try:
        safe_extract(tar, src, lock["commit"])
        removed = []
        for rel in lock.get("prebuilt", []):
            p = src / rel
            if p.exists():
                p.unlink()
                removed.append(rel)
        patches = []
        for p in read_series():
            run(["patch", "-p1", "-F0", "-N", "--no-backup-if-mismatch", "-i", str(p)], src, env, logf)
            patches.append({"name": p.name, "sha256": sha256_file(p)})
        epoch = int(lock["source_date_epoch"])
        benv = dict(env, SOURCE_DATE_EPOCH=str(epoch))
        run(["make", "-C", "src", f"-j{jobs}", lock["target"], f"VERSION=v{version}",
             f"EXTRA_CFLAGS=-ffile-prefix-map={src}=/build/wimboot-{lock['upstream_version']}"],
            src, benv, logf)
        built = src / "src" / lock["target"]
        facts = check_output(built, version)
        stage = Path(tempfile.mkdtemp(prefix=f"{key}.out.", dir=tmp_root))
        os.chmod(stage, 0o755)
        shutil.copyfile(built, stage / OUTPUT)
        os.chmod(stage / OUTPUT, 0o644)
        s = lock["source"]
        info = {
            "schema": INFO_SCHEMA, "key": key, "name": "wimboot", "version": version,
            "upstream_version": lock["upstream_version"], "tag": lock.get("tag"), "commit": lock["commit"],
            "patch_level": lock["patch_level"], "license": lock.get("license"),
            "source": {"name": s["name"], "sha256": s["sha256"], "url": s["urls"][0]},
            "prebuilt_removed": removed, "patches": patches, "make_target": lock["target"],
            "source_date_epoch": epoch, "inputs": material["inputs"], "toolchain": tc,
            "builder": material["builder"], "facts": {k: v for k, v in facts.items() if k != "sbat"},
            "sbat": facts["sbat"], "files": {OUTPUT: sha256_file(stage / OUTPUT)},
        }
        (stage / "build-info.json").write_text(json.dumps(info, indent=1, sort_keys=True) + "\n")
        for p in sorted(stage.rglob("*"), reverse=True):
            os.utime(p, (epoch, epoch), follow_symlinks=False)
        os.utime(stage, (epoch, epoch))
        if out.exists():
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage, out)
        log(f"built wimboot {version} in {time.monotonic() - t0:.0f}s -> {out}")
    except BaseException:
        keep = tmp_root / f"failed-{key}.log"
        if logf.is_file():
            shutil.copyfile(logf, keep)
            print(f"wimboot: build log kept in {keep}", file=sys.stderr)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def build_docker(lock: dict, cache: Path, jobs: int) -> Path:
    """Run this script with --builder native inside GRUB's pinned Ubuntu image."""
    d = json.loads(GRUB_LOCK.read_text())["docker"]
    if offline():
        raise Fail("the docker builder installs packages from the network and BB_OFFLINE=1 forbids that: "
                   "build natively (BB_WIMBOOT_BUILDER=native)")
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise Fail("docker is not usable (no docker CLI or the daemon is not running)")
    fetch_source(lock, cache / "dl")              # on the host: the container builds offline
    uid, gid = os.getuid(), os.getgid()
    apt = " ".join(lock["docker_apt"])
    script = (f"set -e; export DEBIAN_FRONTEND=noninteractive; apt-get -q update >/dev/null; "
              "apt-get -q install -y --no-install-recommends ca-certificates >/dev/null; "
              f"apt-get -q update --snapshot {d['snapshot']} >/dev/null; "
              f"apt-get -q install -y --no-install-recommends --snapshot {d['snapshot']} {apt} >/dev/null; "
              f"BB_OFFLINE=1 python3 -I /bb/build/wimboot/wimbootsrc.py build --builder native "
              f"--builder-label docker:{d['image']} --cache /cache -j {jobs}; chown -R {uid}:{gid} /cache")
    cache.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{HERE}:/bb/build/wimboot:ro", "-v", f"{cache}:/cache",
           "-e", "LC_ALL=C", "-e", "TZ=UTC", d["image"], "bash", "-c", script]
    log(f"docker build in {d['image']} (apt snapshot {d['snapshot']})")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if r.returncode != 0 or not lines:
        raise Fail(f"docker build failed (exit {r.returncode})")
    return cache / Path(lines[-1]).relative_to("/cache")


def default_cache() -> Path:
    return Path(os.environ.get("BB_WIMBOOT_CACHE") or ROOT / ".tools/cache/wimboot")


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
        print(f"{out}: {OUTPUT} matches build-info.json (wimboot {info['version']}, sha256 {info['files'][OUTPUT]})")
    return info


def cmd_build(a) -> int:
    lock = load_lock()
    cache = Path(a.cache).resolve()
    jobs = a.jobs or os.cpu_count() or 4
    builder = a.builder or os.environ.get("BB_WIMBOOT_BUILDER") or "auto"
    if builder in ("auto", "native"):
        env = build_env()
        miss = missing_tools(env)
        if not miss:
            tc = toolchain(env)
            key, material = cache_key(tc, a.builder_label or "native")
            out = cache / "out" / key
            if (out / "build-info.json").is_file() and not a.force:
                log(f"cached: {out}")
            else:
                out = build_native(lock, cache, jobs, env, tc, key, material, force=a.force)
            verify(out, quiet=True)
            print(out)
            return 0
        if builder == "native":
            raise Fail(f"cannot build natively, missing: {', '.join(miss)}")
        log(f"host lacks {', '.join(miss)}; using docker")
    out = build_docker(lock, cache, jobs)
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
    b.add_argument("-j", "--jobs", type=int)
    b.add_argument("--force", action="store_true", help="rebuild even if the cache has this key")
    b.add_argument("--quiet", action="store_true")
    k = sub.add_parser("key")
    k.add_argument("--cache", default=str(default_cache()))
    v = sub.add_parser("verify")
    v.add_argument("outdir")
    i = sub.add_parser("info", help="print FIELD values of OUTDIR/build-info.json, one per line")
    i.add_argument("outdir")
    i.add_argument("fields", nargs="+")
    c = sub.add_parser("check", help="check FILE as a wimboot VERSION image of ours; print its facts")
    c.add_argument("file")
    c.add_argument("version")
    a = ap.parse_args()
    try:
        if a.cmd == "build":
            QUIET = a.quiet
            return cmd_build(a)
        if a.cmd == "key":
            key, material = cache_key(toolchain(build_env()), "native")
            print(json.dumps({"key": key, **material}, indent=1, sort_keys=True))
            return 0
        if a.cmd == "verify":
            verify(Path(a.outdir))
            return 0
        if a.cmd == "check":
            facts = check_output(Path(a.file), a.version)
            print(json.dumps({k: v for k, v in facts.items() if k != "sbat"}, sort_keys=True))
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
        print(f"wimboot: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
