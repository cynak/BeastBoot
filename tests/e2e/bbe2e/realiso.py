"""Real-ISO boot checks (contract: tests/e2e/REAL_ISOS.md).

catalog   tests/e2e/real_isos.json: load() and validate()
cache     fetch(): download once into .tools/cache/real-isos/<id>/ (resumable),
          verify against the vendor's SHA-256 (or SHA-512) before every use;
          BB_ISO_<ID>=/path uses a local copy, verified the same way
drives    build_drive(): a fresh BeastBoot drive per (ISO, data filesystem),
          installed like the other e2e drives (--serial-console, bb_debug), the
          ISO on the data partition, bb_kargs from the catalog, bb_oneshot set
boots     run_case(): one QEMU boot per (ISO, mode, filesystem) on a snapshot
          of that drive; Windows entries also get a BBTEST disk
oracle    Oracle: pass/fail from the serial log, or from BBTEST:\\RESULT.TXT
results   one JSON line per case in out/real/results.jsonl, serial log kept

Downloads are untrusted data: nothing from an ISO runs on this computer; the
ISO is only read by GRUB and the ISO's own kernel inside the VM.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import env, images
from .qemu import VM
from .serial import BOUNDARY, parse_records

CATALOG = env.E2E_DIR / "real_isos.json"
CACHE_DIR = Path(os.environ.get("BB_REAL_CACHE", env.BB_ROOT / ".tools" / "cache" / "real-isos"))
OUT_DIR = Path(os.environ.get("BB_REAL_OUT", env.BB_ROOT / "out" / "real"))
RESULTS = OUT_DIR / "results.jsonl"
LOG_DIR = OUT_DIR / "logs"
WORK_DIR = OUT_DIR / "work"

MODES = ("uefi", "bios", "uefi-sb")
# uefi-sb: OVMF Secure Boot (Microsoft db) with the BeastBoot key in MokList; Windows
# entries only, booted from a copy prepared with `beast-boot prepare-windows`
# (docs/WINDOWS_SECURE_BOOT.md). Not on NTFS: GRUB cannot read it in lockdown.
SB_FAMILIES = ("windows",)
FILESYSTEMS = ("exfat", "fat32", "ntfs")
PLATFORM = {"uefi": "efi", "bios": "pc", "uefi-sb": "efi"}
SB = {"uefi": "0", "bios": "0", "uefi-sb": "1"}  # the ready record's sb= per mode
HASH_LEN = {"sha256": 64, "sha512": 128}
GIB = 1 << 30

# systemd (v254+) reads credentials from SMBIOS type 11 strings: this one asks
# systemd-getty-generator for a login prompt on ttyS0, so an ISO started with
# its own loopback.cfg (no bb_kargs, so no console=ttyS0) still shows on the
# serial log that its userspace came up. Ignored by everything that is not systemd.
SMBIOS_GETTY = ["-smbios", "type=11,value=io.systemd.credential:getty.ttys.serial=ttyS0"]

# The ISO's system gave up: stop waiting (a few seconds later, for context).
FAIL_FAST = [
    r"Kernel panic - not syncing",
    r"Entering emergency mode",
    r"You are in emergency mode",
    r"^\(initramfs\) ",
    r"dracut:/# ",
    r"Unable to find a medium containing a live file system",
    r"Unable to find a live file system on the network",
    r"No repository found\.",
    r"Aborted\. Press any key to exit\.",  # shim / an EFI loader gave up
    # GRUB (ours, or one the ISO brought) gave up on the ISO's menu or config
    r"Failed to boot both default and fallback entries",
    r"error: can't find command",
    r"Minimal BASH-like line editing is supported",
]
# Kernel lines that echo the command line (and could contain marker text).
_CMDLINE_RE = re.compile(r"^.*\b(?:Kernel command line|Command line):.*$", re.M)
# GRUB menu / help redraw lines (they name entries and keys, not the ISO's system).
_MENU_RE = re.compile(r"^.*(?:Press enter to boot the selected OS|automatically in|Use the \^ and v keys).*$", re.M)
_NOISE_RE = re.compile(f"{_CMDLINE_RE.pattern}|{_MENU_RE.pattern}", re.M)

KEYS = {"id", "family", "name", "version", "url", "size", "recipe", "modes", "fs", "ram_mb", "timeout_s"}


class Unverifiable(Exception):
    """No vendor checksum for this ISO, so it must not be used."""


class FetchError(Exception):
    pass


class Stale(FetchError):
    """The vendor's checksum file no longer lists this ISO: the catalog is out of date (a failure, not a skip)."""


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def env_name(iso_id: str) -> str:
    """BB_ISO_<ID>: the id upper-cased, every other character as `_`."""
    return "BB_ISO_" + re.sub(r"[^A-Z0-9]", "_", iso_id.upper())


def validate(cat: dict) -> list[str]:
    """Problems in a catalog (empty list: valid)."""
    errs = []
    if cat.get("v") != 1:
        errs.append("v must be 1")
    seen = set()
    for i, e in enumerate(cat.get("isos", [])):
        where = f"isos[{i}] {e.get('id', '?')}"
        missing = sorted(KEYS - e.keys())
        if missing:
            errs.append(f"{where}: missing {', '.join(missing)}")
            continue
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", e["id"]):
            errs.append(f"{where}: id must be lower-case letters, digits, '.' and '-'")
        if e["id"] in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(e["id"])
        for k in ("url", "sha256_url", "sha512_url"):
            if e.get(k) and urlparse(e[k]).scheme != "https":
                errs.append(f"{where}: {k} must be https")
        sums = [e.get(k) for k in ("sha256", "sha256_url", "sha512_url")]
        if not any(sums) and not e.get("unverifiable"):
            errs.append(f"{where}: needs sha256, sha256_url or sha512_url (or \"unverifiable\": reason)")
        if e.get("sha256") and not re.fullmatch(r"[0-9a-f]{64}", e["sha256"]):
            errs.append(f"{where}: sha256 must be 64 lower-case hex digits")
        if not e["modes"] or set(e["modes"]) - set(MODES):
            errs.append(f"{where}: modes must be a subset of {MODES}")
        if "uefi-sb" in e["modes"] and e["family"] not in SB_FAMILIES:
            errs.append(f"{where}: uefi-sb is for {', '.join(SB_FAMILIES)} entries only")
        if not e["fs"] or set(e["fs"]) - set(FILESYSTEMS):
            errs.append(f"{where}: fs must be a subset of {FILESYSTEMS}")
        windows = e["family"] == "windows"
        if windows:
            if not e.get("result") or e.get("success") or e.get("kargs"):
                errs.append(f"{where}: Windows entries have \"result\" lines, no \"success\" and no kargs")
        else:
            if not e.get("success") or e.get("result"):
                errs.append(f"{where}: Linux entries need \"success\" regexes (and no \"result\")")
        for rx in e.get("success", []) + e.get("result", []) + e.get("fail", []):
            try:
                re.compile(rx)
            except re.error as ex:
                errs.append(f"{where}: bad regex {rx!r}: {ex}")
        rfs = e.get("recipe_fs") or {}
        if set(rfs) - set(FILESYSTEMS) or not all(isinstance(v, str) for v in rfs.values()):
            errs.append(f"{where}: recipe_fs must map data filesystems to recipe names")
        if '"' in e.get("kargs", "") or "\\" in e.get("kargs", ""):
            errs.append(f"{where}: kargs must not contain quotes or backslashes")
        sets = e.get("settings") or {}
        if "net" in e and not isinstance(e["net"], bool):
            errs.append(f"{where}: net must be true or false")
        if not isinstance(sets, dict) or not all(
                isinstance(k, str) and re.fullmatch(r"bb_[a-z][a-z0-9_]*", k) and k != "bb_kargs"
                and isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.,=:/-]*", v) for k, v in sets.items()):
            errs.append(f"{where}: settings must map bb_* menu variables to plain values")
    ids = {e.get("id") for e in cat.get("isos", [])}
    for e in cat.get("isos", []):
        if e.get("cache_id") and (e["cache_id"] not in ids or e["cache_id"] == e.get("id")):
            errs.append(f"isos[{e.get('id')}]: cache_id must name another entry (same ISO)")
    return errs


def load(path: Path = CATALOG) -> list[dict]:
    cat = json.loads(Path(path).read_text())
    errs = validate(cat)
    if errs:
        raise ValueError(f"{path}: " + "; ".join(errs))
    return cat["isos"]


def select(entries: list[dict], ids: str | None = None) -> list[dict]:
    """Entries named in BB_REAL_IDS (comma-separated), else all."""
    ids = os.environ.get("BB_REAL_IDS", "") if ids is None else ids
    wanted = [x.strip() for x in ids.split(",") if x.strip()]
    if not wanted:
        return list(entries)
    unknown = sorted(set(wanted) - {e["id"] for e in entries})
    if unknown:
        raise ValueError(f"BB_REAL_IDS: unknown id(s) {', '.join(unknown)}")
    return [e for e in entries if e["id"] in wanted]


def cases(entry: dict) -> list[tuple[str, str]]:
    """(mode, fs) pairs of one entry, in run order."""
    return [(mode, fs) for fs in entry["fs"] for mode in entry["modes"] if not (mode == "uefi-sb" and fs == "ntfs")]


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------

def parse_sums(text: str, algo: str) -> list[tuple[str, str | None]]:
    """(hex, file name or None) for each `algo` line: GNU (`<hex>  name`,
    `<hex> *name`), BSD (`SHA256 (name) = <hex>`) or a bare hash. Lines of
    other lengths (other algorithms) and PGP armour are ignored."""
    n = HASH_LEN[algo]
    tag = algo.upper().replace("SHA", "SHA-?")
    bsd = re.compile(rf"^{tag}\s*\((.+)\)\s*=\s*([0-9a-fA-F]{{{n}}})$", re.I)
    gnu = re.compile(rf"^([0-9a-fA-F]{{{n}}})(?:[ \t]+\*?|\s*\*)(\S.*)$")
    bare = re.compile(rf"^[0-9a-fA-F]{{{n}}}$")
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:]
        if not line or line.startswith("#"):
            continue
        if m := bsd.match(line):
            out.append((m.group(2).lower(), m.group(1).strip()))
        elif bare.match(line):
            out.append((line.lower(), None))
        elif m := gnu.match(line):
            out.append((m.group(1).lower(), m.group(2).strip().lstrip("*")))
    return out


def pick(entries: list[tuple[str, str | None]], names: list[str]) -> tuple[str, str | None] | None:
    """The (hex, name) for one of `names` (exact, then case-insensitive). A file
    with exactly one entry applies to the download (Tumbleweed `-Current`:
    the line names the snapshot the link points to). Never guesses between entries."""
    base = [os.path.basename(n) for n in names if n]
    named = [(h, os.path.basename(n)) for h, n in entries if n]
    for w in base:
        for h, n in named:
            if n == w:
                return h, n
    low = [w.lower() for w in base]
    for h, n in named:
        if n.lower() in low:
            return h, n
    if len(entries) == 1:
        h, n = entries[0]
        return h, (os.path.basename(n) if n else None)
    return None


def hash_file(path: Path) -> dict[str, str]:
    """SHA-256 and SHA-512 of a file, in one pass."""
    hs = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with open(path, "rb") as f:
        while chunk := f.read(8 << 20):
            for h in hs.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def _curl() -> list[str]:
    # https only, also after redirects; no config file from $HOME.
    return ["curl", "-q", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "-fsSL",
            "--connect-timeout", "30", "-A", "beastboot-real-iso-tests"]


def http_text(url: str, timeout: float = 120) -> str:
    p = subprocess.run(_curl() + ["--max-time", str(int(timeout)), "--max-filesize", str(4 << 20), url],
                       capture_output=True, timeout=timeout + 30)
    if p.returncode != 0:
        raise FetchError(f"{url}: curl exit {p.returncode}: {p.stderr.decode(errors='replace').strip()[-300:]}")
    return p.stdout.decode("utf-8", "replace")


@dataclass
class Expected:
    algo: str
    hex: str
    name: str  # file name in the cache
    source: str  # where the value came from


def url_name(url: str) -> str:
    return unquote(os.path.basename(urlparse(url).path))


def expected(entry: dict, get=http_text) -> Expected:
    """The vendor's checksum for this entry. A checksum file is fetched every
    time (a re-released ISO under the same link must not pass as the old one);
    when it cannot be fetched, the value recorded at the last download is used."""
    name = entry.get("file") or url_name(entry["url"])
    if entry.get("sha256"):
        return Expected("sha256", entry["sha256"], name, "catalog")
    meta = _read_meta(entry)
    errors = []
    for algo in ("sha256", "sha512"):
        url = entry.get(f"{algo}_url")
        if not url:
            continue
        try:
            got = pick(parse_sums(get(url), algo), [entry.get("checksum_name"), name])
        except FetchError as e:
            errors.append(str(e))
            continue
        if got is None:
            raise Stale(f"catalog stale: {url} has no {algo} line for {name}")
        hexv, n = got
        return Expected(algo, hexv, n or name, url)
    if meta and meta.get("algo") and meta.get("hex"):
        return Expected(meta["algo"], meta["hex"], meta["name"], meta["source"] + " (cached: " + "; ".join(errors) + ")")
    if errors:
        raise FetchError("; ".join(errors))
    if entry.get("unverifiable"):
        raise Unverifiable(entry["unverifiable"])
    raise Stale("catalog stale: the entry has no checksum source and no \"unverifiable\" reason")


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

@dataclass
class Iso:
    entry: dict
    path: Path
    size: int
    sha256: str
    verified: str  # "sha256 <hex> from <source>"


def cache_dir(entry: dict) -> Path:
    """Download cache of the entry's ISO; entries with `cache_id` share another entry's
    (the same ISO booted with other settings)."""
    return CACHE_DIR / entry.get("cache_id", entry["id"])


def _read_meta(entry: dict) -> dict | None:
    try:
        return json.loads((cache_dir(entry) / "meta.json").read_text())
    except (OSError, ValueError):
        return None


def _verify(path: Path, exp: Expected) -> dict[str, str]:
    got = hash_file(path)
    if got[exp.algo] != exp.hex:
        raise FetchError(f"{path}: {exp.algo} {got[exp.algo]} does not match the vendor's {exp.hex} ({exp.source})")
    return got


def download(url: str, dest: Path, log: Path) -> None:
    """Resumable download to `dest` (a .part file); curl retries itself."""
    cmd = _curl() + ["--retry", "8", "--retry-delay", "10", "--retry-all-errors", "--speed-limit", "20000",
                     "--speed-time", "120", "-C", "-", "-o", str(dest), url]
    with open(log, "ab") as f:
        f.write(f"\n$ {' '.join(cmd)}\n".encode())
        f.flush()
        p = subprocess.run(cmd, stdout=f, stderr=f)
        if p.returncode == 33 or p.returncode == 36:  # server ignores Range: start over
            dest.unlink(missing_ok=True)
            p = subprocess.run(cmd, stdout=f, stderr=f)
    if p.returncode != 0:
        raise FetchError(f"download of {url} failed (curl exit {p.returncode}); see {log}")


_fetch_lock = threading.Lock()


def fetch(entry: dict, get=http_text) -> Iso:
    """The verified ISO for `entry`: BB_ISO_<ID>, else the cache, else a download."""
    with _fetch_lock:  # one download at a time in this process
        exp = expected(entry, get)
        override = os.environ.get(env_name(entry["id"])) or (
            entry.get("cache_id") and os.environ.get(env_name(entry["cache_id"])))
        if override:
            path = Path(override).expanduser().resolve()
            got = _verify(path, exp)
            return Iso(entry, path, path.stat().st_size, got["sha256"], f"{exp.algo} {exp.hex} from {exp.source}")
        d = cache_dir(entry)
        d.mkdir(parents=True, exist_ok=True)
        # ...and in other processes sharing the cache (another test run).
        with open(d / ".download.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return _fetch_locked(entry, exp, d)


def _fetch_locked(entry: dict, exp: Expected, d: Path) -> Iso:
    path = d / exp.name
    if path.is_file():
        try:
            got = _verify(path, exp)
        except FetchError:
            path.replace(path.with_name(path.name + ".bad"))
            got = None
    else:
        got = None
    if got is None:
        part = path.with_name(path.name + ".part")
        download(entry["url"], part, d / "download.log")
        try:
            got = _verify(part, exp)
        except FetchError:
            part.replace(path.with_name(path.name + ".bad"))
            raise
        part.replace(path)
        for old in d.iterdir():  # superseded downloads (a new Tumbleweed snapshot)
            if old != path and old.suffix in (".iso", ".part", ".bad"):
                old.unlink(missing_ok=True)
    (d / "meta.json").write_text(json.dumps({
        "url": entry["url"], "name": exp.name, "algo": exp.algo, "hex": exp.hex, "source": exp.source,
        "size": path.stat().st_size, "sha256": got["sha256"], "verified": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }, indent=1) + "\n")
    return Iso(entry, path, path.stat().st_size, got["sha256"], f"{exp.algo} {exp.hex} from {exp.source}")


# ---------------------------------------------------------------------------
# Drives
# ---------------------------------------------------------------------------

FAT32_MAX_FILE = (4 << 30) - 1


def fs_skip_reason(iso_bytes: int, fs: str) -> str | None:
    """Why an ISO cannot be tested on this data filesystem (None: it can)."""
    if fs == "fat32" and iso_bytes > FAT32_MAX_FILE:
        return f"FAT32 cannot hold a file over 4 GiB (the ISO is {iso_bytes} bytes)"
    return None


def drive_size(iso_bytes: int) -> str:
    """Image size for the installer: the ISO plus room for the ESP and slack (sparse)."""
    return f"{math.ceil((iso_bytes + 2 * GIB) / GIB)}G"


def config_text(entry: dict) -> str:
    """config.cfg for a test drive: debug lines, bb_kargs, and a menu timeout so
    that an ISO's own loopback.cfg menu cannot wait for a key forever."""
    lines = []
    if entry.get("kargs"):
        lines += [f'set bb_kargs="{entry["kargs"]}"', "export bb_kargs"]
    for k, v in sorted((entry.get("settings") or {}).items()):  # menu variables (validated)
        lines += [f'set {k}="{v}"', f"export {k}"]
    return images.user_config(debug=True, timeout=5, extra="\n".join(lines))


def iso_dest(iso: Iso) -> str:
    return "/" + iso.path.name


def stage(iso: Iso, dest: Path) -> Path:
    """A private copy of the ISO whose SHA-256 is checked while it is copied, so a
    file replaced after the vendor check (BB_ISO_*, the cache) cannot reach the drive."""
    h = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(iso.path, "rb") as src, open(dest, "wb") as out:
        while chunk := src.read(8 << 20):
            h.update(chunk)
            out.write(chunk)
    if h.hexdigest() != iso.sha256:
        dest.unlink(missing_ok=True)
        raise FetchError(f"{iso.path} changed after it was verified (sha256 {h.hexdigest()}, expected {iso.sha256})")
    return dest


def build_drive(iso: Iso, fs: str, path: Path) -> images.Drive:
    from . import beastnet as bn  # grubenv helpers

    path.parent.mkdir(parents=True, exist_ok=True)
    images.install(path, layout="msdos", fs=fs, size=drive_size(iso.size), dist=env.DIST, serial=True)
    drive = images.Drive.open(path, "msdos", fs)
    root = path.parent / f".stage-{iso.entry['id']}-{fs}"
    shutil.rmtree(root, ignore_errors=True)
    staged = stage(iso, root / iso_dest(iso).lstrip("/"))
    try:
        prepared = prepare_windows(root, iso_dest(iso)) if "uefi-sb" in iso.entry["modes"] else []
        with drive.data_writer() as w:
            w.put(iso_dest(iso), staged)
            w.mkdir("/beast-booter")
            cfg = config_text(iso.entry)
            w.put(images.USER_CONFIG, cfg)
            w.put(images.USER_ENV, images.config_env(cfg))  # read instead under Secure Boot
            for rel in prepared:
                w.mkdir(rel.rsplit("/", 1)[0])
                w.put(rel, root / rel.lstrip("/"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    bn.write_grubenv(drive, {"bb_oneshot": iso_dest(iso)})
    return drive


def prepare_windows(root: Path, dest: str) -> list[str]:
    """Run prepare-windows' code (beastbooter.winboot.prepare, staging=True: root is the
    folder the drive image is built from, not a mounted drive) on the staged ISO (root +
    dest); returns the files it wrote, as data-partition paths. The stamp is last, as
    the tool writes it (docs/WINDOWS_SECURE_BOOT.md)."""
    (root / "beast-booter").mkdir(parents=True, exist_ok=True)
    code = ("import sys; from beastbooter import winboot; from beastbooter.util import Reporter; "
            "winboot.prepare(sys.argv[1], sys.argv[2], False, Reporter(quiet=True), staging=True)")
    env.run([env.python(), "-c", code, str(root / dest.lstrip("/")), str(root)], timeout=1200)
    d = root / "beast-booter" / "winboot" / dest.lstrip("/")
    return [f"/beast-booter/winboot{dest}/{n}" for n in ("boot.wim", "iso-head.bin", "stamp.env") if (d / n).is_file()]


BBTEST_OFFSET = 1 << 20
BBTEST_SIZE = 64 << 20


def make_bbtest(path: Path, case_id: str) -> Path:
    """A small MBR disk with one FAT32 partition labelled BBTEST and ID.TXT."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.truncate(BBTEST_OFFSET + BBTEST_SIZE)
        sectors = BBTEST_SIZE // 512
        entry = struct.pack("<B3sB3sII", 0, b"\xfe\xff\xff", 0x0C, b"\xfe\xff\xff", BBTEST_OFFSET // 512, sectors)
        f.seek(446)
        f.write(entry + b"\0" * 48 + b"\x55\xaa")
    img = f"{path}@@{BBTEST_OFFSET}"
    env.run(["mformat", "-i", img, "-F", "-c", "1", "-v", "BBTEST", "-T", str(BBTEST_SIZE // 512), "::"])
    idf = path.with_suffix(".id.txt")
    idf.write_text(case_id + "\r\n")
    env.run(["mcopy", "-i", img, str(idf), "::/ID.TXT"])
    return path


def read_bbtest(path: Path) -> str | None:
    p = env.run(["mtype", "-i", f"{path}@@{BBTEST_OFFSET}", "::/RESULT.TXT"], check=False)
    return p.stdout if p.returncode == 0 else None


def bbtest_args(path: Path) -> list[str]:
    # AHCI, which WinPE has a driver for (virtio it has not).
    return ["-drive", f"if=none,id=bbtest,format=raw,file={path}", "-device", "ide-hd,drive=bbtest,bus=ide.2"]


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    status: str  # pass | fail | timeout | skip
    reason: str
    recipe: str | None = None
    matched: list[str] = field(default_factory=list)


class Oracle:
    """Pass/fail from the serial log of one boot.

    A pass needs, in this order of checks: a `BEAST: ready` record with the
    case's platform, sb (1 only for uefi-sb) and data filesystem; exactly one `BEAST: boot <iso>`
    record (the config exports timeout=5, so a failed attempt boots again); a
    `recipe` pinned in the catalog and equal to the boot record's; every
    success regex matched after the boot record, in text with all `BEAST:`
    records, kernel command-line echoes and GRUB menu redraw lines removed;
    and no fail-fast line or `BEAST: error` that starts before the end of the
    last required success match.
    """

    def __init__(self, entry: dict, mode: str, iso_path: str, fs: str | None = None):
        self.entry, self.mode, self.iso_path, self.fs = entry, mode, iso_path, fs
        self.success = [re.compile(rx, re.M) for rx in entry.get("success", [])]
        self.fail = [re.compile(rx, re.M) for rx in FAIL_FAST + entry.get("fail", [])]
        self.recipe: str | None = None
        self.boot_at: int | None = None
        self.boots = 0
        self.mode_error: str | None = None
        self.errors: list[tuple[int, str]] = []  # (offset, text) of BEAST: error records
        self.ready = False
        self.boot_rx = re.compile(rf"^boot {re.escape(iso_path)} recipe=")

    def records(self, clean: str) -> str:
        """Read the BEAST records of `clean`; returns the text markers are matched against."""
        self.recipe = self.boot_at = self.mode_error = None
        self.boots, self.errors, self.ready = 0, [], False
        recs = [r for r in parse_records(clean, final=True)]
        text = list(clean.replace(BOUNDARY, "\n"))
        for r in recs:
            for i in range(r.start, min(r.end, len(text))):
                if text[i] != "\n":
                    text[i] = " "
            if r.prefix != "BEAST":
                continue
            if r.kind == "ready" and not self.ready:
                self.ready = True
                f = r.fields
                want, sb = PLATFORM[self.mode], SB[self.mode]
                if f.get("platform") != want or f.get("sb") != sb:
                    self.mode_error = f"wrong mode: {r.text} (expected platform={want} sb={sb})"
                elif self.fs and f.get("fs") != self.fs:
                    self.mode_error = f"wrong data filesystem: {r.text} (expected fs={self.fs})"
            elif r.kind == "boot" and r.matches(self.boot_rx):
                # (a regex, not r.fields: kernel output right after the record can
                # look like a continuation of a wrapped line)
                self.boots += 1
                self.boot_at = r.end  # the last one is the one used; two fail anyway
                m = re.search(r"\brecipe=([A-Za-z0-9_.-]+)", r.text)
                self.recipe = m.group(1) if m else None
            elif r.kind == "error" and self.ready:
                self.errors.append((r.start, r.text))
        return _NOISE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), "".join(text))

    def matched(self, text: str) -> list[tuple[str, int]]:
        """(pattern, end offset of its first match after the boot record)."""
        out = []
        for rx in self.success:
            m = rx.search(text, self.boot_at or 0) if self.boot_at is not None else None
            if m:
                out.append((rx.pattern, m.end()))
        return out

    def first_failure(self, text: str) -> tuple[int, str] | None:
        """(offset, line) of the earliest fail-fast match after the boot record."""
        if self.boot_at is None:
            return None
        hits = [(m.start(), m.group(0).strip()) for rx in self.fail if (m := rx.search(text, self.boot_at))]
        return min(hits) if hits else None

    @property
    def want_recipe(self) -> str | None:
        """The pinned recipe; `recipe_fs` overrides it per data filesystem (exFAT takes the
        menu's own add-on route, FAT32 and NTFS the ISO's loopback.cfg)."""
        return (self.entry.get("recipe_fs") or {}).get(self.fs, self.entry.get("recipe"))

    def recipe_ok(self) -> bool:
        return self.want_recipe is not None and self.recipe == self.want_recipe

    def recipe_note(self) -> str:
        want = self.want_recipe
        if want is None:
            return f"recipe not pinned (the menu used recipe={self.recipe}; set \"recipe\" in the catalog)"
        if self.recipe != want:
            return f"recipe={self.recipe}, expected {want}"
        return ""

    def gate(self, exited: bool, timed_out: bool) -> Verdict | None:
        """Checks common to Linux and Windows; a failing verdict, or None."""
        if self.mode_error:
            return Verdict("fail", self.mode_error, self.recipe)
        if not self.ready:
            if self.boots or exited or timed_out:
                return Verdict("fail", "no BEAST: ready record", self.recipe)
            return None
        if self.boots >= 2:
            return Verdict("fail", f"booted more than once ({self.boots} 'BEAST: boot' records; "
                           "the first attempt failed and the menu re-booted)", self.recipe)
        return None


def last_lines(text: str, n: int = 3) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " | ".join(lines[-n:])[-300:]


def judge_linux(o: Oracle, clean: str, *, exited: bool, timed_out: bool, exit_code: int | None) -> Verdict | None:
    """A verdict, or None to keep waiting."""
    text = o.records(clean)
    if v := o.gate(exited, timed_out):
        return v
    if not o.ready:
        return None
    got = o.matched(text)
    names = [p for p, _ in got]
    done = o.boot_at is not None and len(got) == len(o.success)
    last_end = max((e for _, e in got), default=0) if done else None
    for pos, err in o.errors:
        if last_end is None or pos < last_end:
            return Verdict("fail", f"menu: {err}", o.recipe, names)
    bad = o.first_failure(text)
    if done:
        if bad and bad[0] < last_end:
            return Verdict("fail", f"ISO gave up before the last success marker: {bad[1]!r}", o.recipe, names)
        if not o.recipe_ok():
            why = "booted, but " + o.recipe_note()
            return Verdict("fail", why, o.recipe, names)
        return Verdict("pass", "all success markers", o.recipe, names)
    if bad or exited or timed_out:
        note = "; " + o.recipe_note() if o.recipe_note() else ""
        after = text[o.boot_at:] if o.boot_at is not None else ""
        n = f"{len(got)}/{len(o.success)} markers"
        if o.boot_at is None:
            why = "no 'BEAST: boot' record for the ISO (menu did not start it)"
        elif bad:
            why = f"ISO gave up: {bad[1]!r}"
        elif exited:
            why = f"QEMU exited (code {exit_code}); last: {last_lines(after)}"
        else:
            why = f"no success after the timeout; last: {last_lines(after)}"
        return Verdict("timeout" if timed_out and not bad and o.boot_at is not None else "fail",
                       f"{why}; {n}{note}", o.recipe, names)
    return None


def ordered_matches(patterns: list[str], text: str) -> list[str]:
    """The leading patterns that match `text` in order, each after the end of the
    previous match (a later line cannot vouch for an earlier step)."""
    pos, out = 0, []
    for p in patterns:
        m = re.compile(p, re.M).search(text, pos)
        if not m:
            break
        out.append(p)
        pos = m.end()
    return out


def judge_windows(o: Oracle, clean: str, result_txt: str | None, *, timed_out: bool) -> Verdict:
    """RESULT.TXT lines must match in the order of "result". Marker names (script side,
    REAL_ISOS.md): `iso-mounted <L>: ... install.(wim|esd)` only after the file was
    found on the mounted drive, `setup-running` only after tasklist showed setup.exe
    from that drive."""
    o.records(clean)
    if v := o.gate(True, timed_out):
        return v
    want = o.entry["result"]
    got = (result_txt or "").replace("\r", "")
    matched = ordered_matches(want, got)
    for _, err in o.errors:
        return Verdict("fail", f"menu: {err}", o.recipe, matched)
    if o.boot_at is None:
        return Verdict("fail", "no 'BEAST: boot' record for the ISO (menu did not start it)", o.recipe, matched)
    if len(matched) == len(want):
        if not o.recipe_ok():
            return Verdict("fail", "RESULT.TXT complete, but " + o.recipe_note(), o.recipe, matched)
        return Verdict("pass", "RESULT.TXT complete", o.recipe, matched)
    why = "RESULT.TXT missing" if result_txt is None else f"RESULT.TXT: {last_lines(got)}"
    note = "; " + o.recipe_note() if o.recipe_note() else ""
    return Verdict("timeout" if timed_out else "fail", f"{why}; {len(matched)}/{len(want)} lines (in order){note}",
                   o.recipe, matched)


# ---------------------------------------------------------------------------
# One case
# ---------------------------------------------------------------------------

def case_id(entry: dict, mode: str, fs: str) -> str:
    return f"{entry['id']}-{mode}-{fs}"


def run_case(iso: Iso, drive: images.Drive, mode: str, fs: str) -> Verdict:
    entry = iso.entry
    cid = case_id(entry, mode, fs)
    work = WORK_DIR / cid
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    windows = entry["family"] == "windows"
    extra = list(SMBIOS_GETTY)
    if entry.get("net"):  # network installers (e.g. openSUSE NET) fetch their packages
        extra += ["-nic", "user"]
    bbtest = None
    if windows:
        bbtest = make_bbtest(work / "bbtest.img", cid)
        extra += bbtest_args(bbtest)
    timeout = float(entry["timeout_s"])
    mok = [env.DIST / "esp" / "ENROLL_THIS_KEY_IN_MOKMANAGER.cer"] if mode == "uefi-sb" else []
    vm = VM(cid, mode=mode, disk=drive.path, workdir=work, log_dir=LOG_DIR, memory=int(entry["ram_mb"]),
            smp=int(entry.get("smp", 2)), hard_timeout=(env.t(timeout) + 300) / env.t(1), extra_args=extra, snapshot=True,
            mok_certs=mok)
    o = Oracle(entry, mode, iso_dest(iso), fs)
    verdict = None
    timed_out = False
    vm.start()
    try:
        deadline = time.monotonic() + env.t(timeout)
        keys_sent = 0
        while True:
            time.sleep(2)
            exited = not vm.running
            timed_out = time.monotonic() > deadline
            if windows:
                # The startup script writes RESULT.TXT and powers off.
                o.records(vm.clean())
                if o.errors or o.mode_error or exited or timed_out:
                    break
                continue
            verdict = judge_linux(o, vm.clean(), exited=exited, timed_out=timed_out,
                                  exit_code=vm.proc.returncode if exited else None)
            if verdict is not None:
                if verdict.status == "fail" and not exited:
                    time.sleep(5)  # context for the log
                break
            # An ISO's own GRUB menu (loopback.cfg) without a countdown despite
            # timeout=5: press Enter once.
            if (o.recipe == "loopback" and not keys_sent and time.monotonic() - vm.started_at > 30
                    and vm.menu() is not None and "automatically in" not in vm.text()[-3000:]):
                try:
                    vm.qmp.cmd("send-key", keys=[{"type": "qcode", "data": "ret"}])
                except Exception:  # noqa: BLE001 - best effort
                    pass
                keys_sent += 1
    finally:
        if vm.running:
            vm.save_failure_artifacts()
        vm.stop()
    if windows:
        verdict = judge_windows(o, vm.clean(), read_bbtest(bbtest), timed_out=timed_out)
    if not env.keep_work() and verdict.status == "pass":
        shutil.rmtree(work, ignore_errors=True)
    return verdict


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

_results_lock = threading.Lock()


def record(entry: dict, mode: str, fs: str, verdict: Verdict, *, seconds: float, iso: Iso | None) -> dict:
    row = {
        "id": entry["id"], "mode": mode, "fs": fs, "status": verdict.status, "recipe": verdict.recipe,
        "matched": verdict.matched, "reason": verdict.reason,
        "log": str(LOG_DIR / f"{case_id(entry, mode, fs)}.log"), "seconds": round(seconds, 1),
        "iso_sha256": iso.sha256 if iso else None, "beastboot_version": beastboot_version(),
        "expected_recipe": (entry.get("recipe_fs") or {}).get(fs, entry.get("recipe")), "when": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    with _results_lock:
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        with open(RESULTS, "a") as f:
            f.write(json.dumps(row) + "\n")
    return row


def latest_results(rows: list[dict] | None = None, version: str | None = None,
                   iso_sha256: dict[str, str] | None = None) -> list[dict]:
    """Rows to summarise: the latest per (id, mode, fs), only for `version` (default:
    the current beastboot_version) and only for the ISO hash now current for that id
    (`iso_sha256`, else the hash of the id's newest row). Older runs never count."""
    if rows is None:
        try:
            rows = [json.loads(ln) for ln in RESULTS.read_text().splitlines() if ln.strip()]
        except OSError:
            rows = []
    version = beastboot_version() if version is None else version
    rows = [r for r in rows if r.get("beastboot_version") == version]
    current = dict(iso_sha256 or {})
    if not iso_sha256:
        for r in rows:  # the newest row with a hash defines the current ISO
            if r.get("iso_sha256"):
                current[r["id"]] = r["iso_sha256"]
    latest: dict[tuple, dict] = {}
    for r in rows:
        want = current.get(r["id"])
        if want and r.get("iso_sha256") not in (None, want):
            continue
        latest[(r["id"], r["mode"], r["fs"])] = r
    return list(latest.values())


def summary(rows: list[dict] | None = None) -> str:
    """One line per case of the latest run (latest_results)."""
    return "\n".join(f"{r['status']:7} {r['id']}-{r['mode']}-{r['fs']}  {r['reason'][:100]}"
                     for r in latest_results(rows))


def beastboot_version() -> str:
    v = env.read_version() or "unknown"
    try:
        build = json.loads((env.DIST / "manifest.json").read_text()).get("build_id")
    except (OSError, ValueError):
        build = None
    return f"{v}+{build}" if build else v


# ---------------------------------------------------------------------------
# Runner: downloads one at a time, boots BB_REAL_PARALLEL drives at a time
# ---------------------------------------------------------------------------

class Runner:
    """Runs every case of `entries` in the background. Downloads are sequential
    (in catalog order); each (ISO, fs) drive is built once and its modes boot
    one after the other on snapshots; drives of different ISOs run in parallel."""

    def __init__(self, entries: list[dict], parallel: int | None = None):
        self.entries = entries
        self.parallel = parallel or int(os.environ.get("BB_REAL_PARALLEL", "2"))
        self.pool = ThreadPoolExecutor(max_workers=max(1, self.parallel), thread_name_prefix="realiso")
        self.futures: dict[str, Future] = {}
        self._group: dict[tuple[str, str], Future] = {}
        self._started = False
        self._lock = threading.Lock()
        for e in entries:
            for mode, fs in cases(e):
                self.futures[case_id(e, mode, fs)] = Future()

    def start(self) -> Runner:
        with self._lock:
            if not self._started:
                self._started = True
                threading.Thread(target=self._downloads, name="realiso-fetch", daemon=True).start()
        return self

    def _finish(self, entry: dict, mode: str, fs: str, verdict: Verdict, seconds: float, iso: Iso | None):
        row = record(entry, mode, fs, verdict, seconds=seconds, iso=iso)
        fut = self.futures[case_id(entry, mode, fs)]
        if not fut.done():
            fut.set_result(row)

    def _downloads(self) -> None:
        for e in self.entries:
            t0 = time.monotonic()
            try:
                iso = fetch(e)
            except Unverifiable as ex:
                for mode, fs in cases(e):
                    self._finish(e, mode, fs, Verdict("skip", f"not verifiable: {ex}"), time.monotonic() - t0, None)
                continue
            except Exception as ex:  # noqa: BLE001 - recorded per case
                for mode, fs in cases(e):
                    self._finish(e, mode, fs, Verdict("fail", str(ex) if isinstance(ex, Stale) else f"fetch: {ex}"), time.monotonic() - t0, None)
                continue
            for fs in e["fs"]:
                if why := fs_skip_reason(iso.size, fs):
                    for mode, f in cases(e):
                        if f == fs:
                            self._finish(e, mode, fs, Verdict("skip", why), 0.0, iso)
                    continue
                self.pool.submit(self._group_job, iso, fs)

    def _group_job(self, iso: Iso, fs: str) -> None:
        e = iso.entry
        modes = [m for m, f in cases(e) if f == fs]
        img = WORK_DIR / "drives" / f"{e['id']}-{fs}.img"
        t0 = time.monotonic()
        try:
            drive = build_drive(iso, fs, img)
        except Exception as ex:  # noqa: BLE001 - recorded per case
            for mode in modes:
                self._finish(e, mode, fs, Verdict("fail", f"drive: {str(ex)[-400:]}"), time.monotonic() - t0, iso)
            img.unlink(missing_ok=True)
            return
        try:
            for mode in modes:
                t1 = time.monotonic()
                try:
                    v = run_case(iso, drive, mode, fs)
                except Exception as ex:  # noqa: BLE001
                    v = Verdict("fail", f"harness: {type(ex).__name__}: {str(ex)[-400:]}")
                self._finish(e, mode, fs, v, time.monotonic() - t1, iso)
        finally:
            if not env.keep_work():
                img.unlink(missing_ok=True)

    def result(self, cid: str, timeout: float | None = None) -> dict:
        self.start()
        return self.futures[cid].result(timeout=timeout)


if __name__ == "__main__":
    print(summary())
