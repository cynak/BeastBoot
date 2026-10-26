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
from .qemu import VM, plain_text_from_clean
from .serial import parse_records

CATALOG = env.E2E_DIR / "real_isos.json"
CACHE_DIR = Path(os.environ.get("BB_REAL_CACHE", env.BB_ROOT / ".tools" / "cache" / "real-isos"))
OUT_DIR = Path(os.environ.get("BB_REAL_OUT", env.BB_ROOT / "out" / "real"))
RESULTS = OUT_DIR / "results.jsonl"
LOG_DIR = OUT_DIR / "logs"
WORK_DIR = OUT_DIR / "work"

MODES = ("uefi", "bios")
FILESYSTEMS = ("exfat", "fat32", "ntfs")
PLATFORM = {"uefi": "efi", "bios": "pc"}
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

KEYS = {"id", "family", "name", "version", "url", "size", "recipe", "modes", "fs", "ram_mb", "timeout_s"}


class Unverifiable(Exception):
    """No vendor checksum for this ISO, so it must not be used."""


class FetchError(Exception):
    pass


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
        if '"' in e.get("kargs", "") or "\\" in e.get("kargs", ""):
            errs.append(f"{where}: kargs must not contain quotes or backslashes")
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
    return [(mode, fs) for fs in entry["fs"] for mode in entry["modes"]]


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
            raise Unverifiable(f"{url} has no {algo} line for {name}")
        hexv, n = got
        return Expected(algo, hexv, n or name, url)
    if meta and meta.get("algo") and meta.get("hex"):
        return Expected(meta["algo"], meta["hex"], meta["name"], meta["source"] + " (cached: " + "; ".join(errors) + ")")
    if errors:
        raise FetchError("; ".join(errors))
    raise Unverifiable(entry.get("unverifiable") or "the vendor publishes no checksum for this ISO")


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
    return CACHE_DIR / entry["id"]


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
        override = os.environ.get(env_name(entry["id"]))
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

def drive_size(iso_bytes: int) -> str:
    """Image size for the installer: the ISO plus room for the ESP and slack (sparse)."""
    return f"{math.ceil((iso_bytes + 2 * GIB) / GIB)}G"


def config_text(entry: dict) -> str:
    """config.cfg for a test drive: debug lines, bb_kargs, and a menu timeout so
    that an ISO's own loopback.cfg menu cannot wait for a key forever."""
    lines = []
    if entry.get("kargs"):
        lines += [f'set bb_kargs="{entry["kargs"]}"', "export bb_kargs"]
    return images.user_config(debug=True, timeout=5, extra="\n".join(lines))


def iso_dest(iso: Iso) -> str:
    return "/" + iso.path.name


def build_drive(iso: Iso, fs: str, path: Path) -> images.Drive:
    from . import beastnet as bn  # grubenv helpers

    path.parent.mkdir(parents=True, exist_ok=True)
    images.install(path, layout="msdos", fs=fs, size=drive_size(iso.size), dist=env.DIST, serial=True)
    drive = images.Drive.open(path, "msdos", fs)
    with drive.data_writer() as w:
        w.put(iso_dest(iso), iso.path)
        w.mkdir("/beast-booter")
        w.put(images.USER_CONFIG, config_text(iso.entry))
    bn.write_grubenv(drive, {"bb_oneshot": iso_dest(iso)})
    return drive


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

    Order: `BEAST: ready` must show the expected platform with Secure Boot off;
    `BEAST: boot <iso> recipe=<r>` gives the recipe; a `BEAST: error` record
    after it fails at once. Success regexes count only after the boot record,
    with lines that echo the kernel command line removed.
    """

    def __init__(self, entry: dict, mode: str, iso_path: str):
        self.entry, self.mode, self.iso_path = entry, mode, iso_path
        self.success = [re.compile(rx, re.M) for rx in entry.get("success", [])]
        self.fail = [re.compile(rx, re.M) for rx in FAIL_FAST + entry.get("fail", [])]
        self.recipe: str | None = None
        self.boot_at: int | None = None
        self.mode_error: str | None = None
        self.error: str | None = None
        self.ready = False
        self.boot_rx = re.compile(rf"^boot {re.escape(iso_path)} recipe=")

    def records(self, clean: str) -> None:
        for r in parse_records(clean, final=True):
            if r.prefix != "BEAST":
                continue
            if r.kind == "ready" and self.boot_at is None:
                self.ready = True
                f = r.fields
                want = PLATFORM[self.mode]
                if f.get("platform") != want or f.get("sb") != "0":
                    self.mode_error = f"wrong mode: {r.text} (expected platform={want} sb=0)"
            elif r.kind == "boot" and self.boot_at is None and r.matches(self.boot_rx):
                # (a regex, not r.fields: kernel output right after the record can
                # look like a continuation of a wrapped line)
                m = re.search(r"\brecipe=([A-Za-z0-9_.-]+)", r.text)
                self.recipe = m.group(1) if m else None
                self.boot_at = r.end
            elif r.kind == "error" and self.ready and not self.error:
                self.error = r.text  # e.g. iso-not-found comes before any boot record

    def after_boot(self, clean: str) -> str:
        if self.boot_at is None:
            return ""
        return _CMDLINE_RE.sub("", plain_text_from_clean(clean[self.boot_at:]))

    def matched(self, text: str) -> list[str]:
        return [rx.pattern for rx in self.success if rx.search(text)]

    def failed(self, text: str) -> str | None:
        for rx in self.fail:
            if m := rx.search(text):
                return m.group(0).strip()
        return None

    def recipe_ok(self) -> bool:
        want = self.entry.get("recipe")
        return want is None or self.recipe == want

    def recipe_note(self) -> str:
        if self.recipe_ok():
            return ""
        return f"recipe={self.recipe}, expected {self.entry['recipe']}"


def last_lines(text: str, n: int = 3) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " | ".join(lines[-n:])[-300:]


def judge_linux(o: Oracle, clean: str, *, exited: bool, timed_out: bool, exit_code: int | None) -> Verdict | None:
    """A verdict, or None to keep waiting."""
    o.records(clean)
    if o.mode_error:
        return Verdict("fail", o.mode_error, o.recipe)
    text = o.after_boot(clean)
    matched = o.matched(text)
    if o.error:
        return Verdict("fail", f"menu: {o.error}", o.recipe, matched)
    if o.boot_at is not None and len(matched) == len(o.success):
        if o.recipe_ok():
            return Verdict("pass", "all success markers", o.recipe, matched)
        return Verdict("fail", f"booted, but {o.recipe_note()}", o.recipe, matched)
    bad = o.failed(text)
    if bad or exited or timed_out:
        note = "; " + o.recipe_note() if o.recipe_note() else ""
        got = f"{len(matched)}/{len(o.success)} markers"
        if o.boot_at is None:
            why = "no 'BEAST: boot' record for the ISO (menu did not start it)"
        elif bad:
            why = f"ISO gave up: {bad!r}"
        elif exited:
            why = f"QEMU exited (code {exit_code}); last: {last_lines(text)}"
        else:
            why = f"no success after the timeout; last: {last_lines(text)}"
        return Verdict("timeout" if timed_out and not bad and o.boot_at is not None else "fail",
                       f"{why}; {got}{note}", o.recipe, matched)
    return None


def judge_windows(o: Oracle, clean: str, result_txt: str | None, *, timed_out: bool) -> Verdict:
    o.records(clean)
    if o.mode_error:
        return Verdict("fail", o.mode_error, o.recipe)
    want = [re.compile(rx, re.M) for rx in o.entry["result"]]
    got = result_txt or ""
    matched = [rx.pattern for rx in want if rx.search(got)]
    if o.error:
        return Verdict("fail", f"menu: {o.error}", o.recipe, matched)
    if o.boot_at is None:
        return Verdict("fail", "no 'BEAST: boot' record for the ISO (menu did not start it)", o.recipe, matched)
    if len(matched) == len(want) and o.recipe_ok():
        return Verdict("pass", "RESULT.TXT complete", o.recipe, matched)
    why = "RESULT.TXT missing" if result_txt is None else f"RESULT.TXT: {last_lines(got)}"
    note = "; " + o.recipe_note() if o.recipe_note() else ""
    return Verdict("timeout" if timed_out else "fail", f"{why}; {len(matched)}/{len(want)} lines{note}",
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
    bbtest = None
    if windows:
        bbtest = make_bbtest(work / "bbtest.img", cid)
        extra += bbtest_args(bbtest)
    timeout = float(entry["timeout_s"])
    vm = VM(cid, mode=mode, disk=drive.path, workdir=work, log_dir=LOG_DIR, memory=int(entry["ram_mb"]),
            smp=int(entry.get("smp", 2)), hard_timeout=timeout + 300, extra_args=extra, snapshot=True)
    o = Oracle(entry, mode, iso_dest(iso))
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
                if o.error or o.mode_error or exited or timed_out:
                    break
                continue
            verdict = judge_linux(o, vm.clean(), exited=exited, timed_out=timed_out,
                                  exit_code=vm.proc.returncode if exited else None)
            if verdict is not None:
                if verdict.status == "fail" and not exited and o.failed(o.after_boot(vm.clean())):
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
        "expected_recipe": entry.get("recipe"), "when": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    with _results_lock:
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        with open(RESULTS, "a") as f:
            f.write(json.dumps(row) + "\n")
    return row


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
                    self._finish(e, mode, fs, Verdict("fail", f"fetch: {ex}"), time.monotonic() - t0, None)
                continue
            for fs in e["fs"]:
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
