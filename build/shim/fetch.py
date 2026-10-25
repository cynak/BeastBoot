#!/usr/bin/env python3
"""Fetch, verify and unpack the Debian shim packages of build/shim/debian-shim.lock (stdlib only).

  fetch.py fetch [DIR]            download the locked .debs into DIR/debs (pool URL first, then
                                  the snapshot.debian.org fallback), check each against its pinned
                                  SHA-256 and its control fields, unpack into DIR/root with
                                  `dpkg-deb -x` (no maintainer scripts) and check the unpacked
                                  files against the package's md5sums. Idempotent and additive.
  fetch.py origin FILE MEMBER [DIR]
                                  print the manifest origin "deb:<pkg>=<version>:<MEMBER>" when FILE
                                  is byte-identical (SHA-256) to MEMBER of a locked .deb in DIR/debs
                                  whose own SHA-256 matches the lock; exit 1 otherwise.
  fetch.py distro PACKAGE         print the Debian suite a package is locked from (e.g. debian-sid;
                                  SBOM purls write sid as debian-unstable, scripts/debinfo.py)

DIR defaults to $BB_DEBIAN_DIR, else <repo>/.tools/debian. BB_OFFLINE=1 never downloads.
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LOCK = HERE / "debian-shim.lock"


def die(msg: str) -> None:
    print(f"shim-fetch: error: {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg: str) -> None:
    print(f"shim-fetch: {msg}", file=sys.stderr)


@dataclass
class Entry:
    package: str
    version: str
    arch: str
    sha256: str
    distro: str
    urls: list[str]

    @property
    def filename(self) -> str:
        return urllib.parse.unquote(self.urls[0].rsplit("/", 1)[1])


def read_lock(path: Path = LOCK) -> list[Entry]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if len(f) < 6 or len(f[3]) != 64 or not all(u.startswith("https://") for u in f[5:]):
            die(f"{path}:{n}: expected <package> <version> <arch> <sha256> <distro> <https url>...")
        out.append(Entry(f[0], f[1], f[2], f[3].lower(), f[4], f[5:]))
    if not out:
        die(f"{path}: no packages")
    return out


def default_dir() -> Path:
    return Path(os.environ.get("BB_DEBIAN_DIR") or ROOT / ".tools" / "debian")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def control(deb: Path) -> dict[str, str]:
    r = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die(f"{deb}: not a .deb ({r.stderr.strip()})")
    return dict(line.split(": ", 1) for line in r.stdout.splitlines() if ": " in line)


def check_deb(e: Entry, deb: Path) -> str | None:
    """None when DEB is the locked package, else what is wrong."""
    got = sha256_file(deb)
    if got != e.sha256:
        return f"SHA-256 {got}, the lock pins {e.sha256}"
    c = control(deb)
    want = {"Package": e.package, "Version": e.version, "Architecture": e.arch}
    if c != want:
        return f"control fields {c}, expected {want}"
    return None


def download(e: Entry, dest: Path) -> None:
    tmp = dest.with_name(dest.name + ".part")
    errors = []
    for url in e.urls:
        log(f"downloading {url}")
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
        except OSError as ex:
            errors.append(f"{url}: {ex}")
            tmp.unlink(missing_ok=True)
            continue
        bad = check_deb(e, tmp)
        if bad:
            errors.append(f"{url}: {bad}")
            tmp.unlink(missing_ok=True)
            continue
        os.replace(tmp, dest)
        return
    die(f"{e.package} {e.version}: no URL gave the locked file:\n  " + "\n  ".join(errors))


def md5sums(deb: Path) -> dict[str, str]:
    r = subprocess.run(["dpkg-deb", "-I", str(deb), "md5sums"], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"{deb} has no md5sums")
    out = {}
    for line in r.stdout.splitlines():
        if line.strip():
            s, p = line.split(None, 1)
            out[p.strip()] = s
    return out


def unpacked_ok(deb: Path, root: Path) -> bool:
    for rel, want in md5sums(deb).items():
        p = root / rel
        if p.is_symlink() or not p.is_file():
            return False
        if hashlib.md5(p.read_bytes()).hexdigest() != want:
            return False
    return True


def cmd_fetch(d: Path) -> None:
    debs, root = d / "debs", d / "root"
    debs.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=True)
    for e in read_lock():
        deb = debs / e.filename
        if deb.exists():
            bad = check_deb(e, deb)
            if bad:
                die(f"{deb}: {bad}. Remove it and run this again.")
        elif os.environ.get("BB_OFFLINE") == "1":
            die(f"{deb} missing and BB_OFFLINE=1")
        else:
            download(e, deb)
        if not unpacked_ok(deb, root):
            subprocess.run(["dpkg-deb", "-x", str(deb), str(root)], check=True)
            if not unpacked_ok(deb, root):
                die(f"{deb}: unpacked files do not match its md5sums")
            log(f"unpacked {e.package} {e.version} into {root}")
        else:
            log(f"{e.package} {e.version}: ok ({e.distro})")


def member_bytes(deb: Path, member: str) -> bytes | None:
    r = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True, capture_output=True)
    want = member.lstrip("/")
    with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tf:
        for m in tf:
            if m.isfile() and m.name.lstrip("./") == want:
                return tf.extractfile(m).read()
    return None


def cmd_origin(path: Path, member: str, d: Path) -> None:
    data = path.read_bytes()
    for e in read_lock():
        deb = d / "debs" / e.filename
        if not deb.is_file():
            continue
        content = member_bytes(deb, member)
        if content is None:
            continue
        bad = check_deb(e, deb)
        if bad:
            die(f"{deb}: {bad}")
        if hashlib.sha256(content).digest() != hashlib.sha256(data).digest():
            die(f"{path} differs from {member} in {deb.name} (modified or from another build)")
        print(f"deb:{e.package}={e.version}:{member}")
        return
    die(f"no locked package in {d / 'debs'} ships {member} (run build/shim/fetch.py fetch)")


def main() -> None:
    a = sys.argv[1:]
    if a[:1] == ["fetch"] and len(a) <= 2:
        cmd_fetch(Path(a[1]) if len(a) == 2 else default_dir())
    elif a[:1] == ["origin"] and len(a) in (3, 4):
        cmd_origin(Path(a[1]), a[2], Path(a[3]) if len(a) == 4 else default_dir())
    elif a[:1] == ["distro"] and len(a) == 2:
        e = next((e for e in read_lock() if e.package == a[1]), None)
        if e is None:
            die(f"{a[1]} is not in {LOCK}")
        print(e.distro)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
