"""`beast-boot firmware ...`: optional firmware packs for beast-net (docs/BEASTNET.md section 6).

  catalog   show the catalog (<dist>/esp/beast-net/catalog.json, or --catalog)
  fetch     unprivileged: download every file of the packs from the catalog's
            source (HTTPS only, certificates verified), check each file's
            SHA-256 and size while it streams in, retry transient errors,
            then write DIR/<id>.cpio (cpio.py) and DIR/<id>.json (the
            installed.json entry); with --for-image / --for-device it first
            checks that the packs fit on that target (check_room)
  install   re-parse every cpio, re-check every file against the catalog on
            the drive (or the dist's when the drive has none), check the
            drive's catalog tag / kernel and the free space, then write
            beast-net/firmware/<id>.cpio and installed.json in one FAT batch
            (new clusters first, the directory entries switch at the end)
  remove    delete beast-net/firmware/<id>.cpio and its installed.json entry
  list      installed.json of a drive, plus what is missing or unlisted

Writes to a drive go through a GuardedTarget restricted to the ESP. These
commands never ask for confirmation (they never erase anything, and the GUI
confirms with the user before it starts them); `--yes` is accepted.
`install`, `remove` and `list` put the installed.json object in the "done"
event (`info.installed`), as the GUI cannot read an elevated process's stdout.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from . import commands as cmd
from . import esp
from .blockio import ImageTarget
from .cpio import DIR_MODE, FILE_MODE, FIRMWARE_ROOT, iter_pack, read_newc
from .distsource import prepare_dist_dir
from .errors import BeastError
from .fatfs import FatVolume
from .target import GuardedTarget
from .layout import (
    BEASTNET_CATALOG_PATH,
    BEASTNET_DIR,
    DIST_CATALOG,
    DIST_MANIFEST,
    FIRMWARE_DIR,
    FIRMWARE_INSTALLED_PATH,
    MIB,
)
from .util import Reporter, human_size

PACK_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT_RE = re.compile(r"[A-Za-z0-9._+,=@~ -]+\Z")
MAX_FILE_SIZE = 256 * MIB

DOWNLOAD_TIMEOUT = 60  # seconds without data before a connection counts as failed
ATTEMPTS = 3
RETRY_DELAYS = (2.0, 5.0)  # seconds before the 2nd and 3rd attempt
CHUNK = 64 * 1024
PROGRESS_EVERY = 512 * 1024
VERSION_PATH = BEASTNET_DIR + "/VERSION"
KERNEL_PATH = BEASTNET_DIR + "/vmlinuz"


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FwFile:
    path: str  # installed as lib/firmware/<path>
    sha256: str
    size: int
    source_path: str | None  # what to download, when it differs (WHENCE Link:)


@dataclass(frozen=True)
class FwPack:
    id: str
    title: str
    files: tuple[FwFile, ...]

    @property
    def size(self) -> int:
        return sum(f.size for f in self.files)


@dataclass(frozen=True)
class Catalog:
    tag: str
    kernel: str
    url_template: str
    packs: dict  # id -> FwPack, in catalog order
    raw: dict
    where: str

    def url(self, f: FwFile) -> str:
        """The per-file URL (the same rule as the GUI's)."""
        return self.url_template.format(path=urllib.parse.quote(f.source_path or f.path, safe="/"),
                                        tag=urllib.parse.quote(self.tag))


def _invalid(where: str, msg: str) -> BeastError:
    return BeastError(f"{where}: invalid firmware catalog: {msg}", code="catalog-invalid")


def check_fw_path(p, what: str, where: str) -> str:
    """A firmware path: relative, "/"-separated, no "." / ".." / empty parts."""
    if not isinstance(p, str) or not p or len(p) > 255:
        raise _invalid(where, f"{what} {p!r} is not a valid firmware path")
    for seg in p.split("/"):
        if seg in (".", "..") or not _SEGMENT_RE.match(seg) or seg != seg.strip():
            raise _invalid(where, f"{what} {p!r} is not a valid firmware path")
    return p


def parse_catalog(data: bytes, where: str) -> Catalog:
    try:
        raw = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise _invalid(where, f"not JSON ({e})") from None
    if not isinstance(raw, dict) or raw.get("v") != 1:
        raise _invalid(where, "not a version 1 catalog")
    src = raw.get("source")
    if not isinstance(src, dict):
        raise _invalid(where, "no source")
    tag, template, kernel = src.get("tag"), src.get("url_template"), raw.get("kernel", "")
    if not isinstance(tag, str) or not TAG_RE.match(tag):
        raise _invalid(where, f"bad source tag {tag!r}")
    if not isinstance(kernel, str):
        raise _invalid(where, "bad kernel")
    if not isinstance(template, str) or "{path}" not in template:
        raise _invalid(where, "source.url_template has no {path}")
    try:
        template.format(path="p", tag="t")
    except (KeyError, IndexError, ValueError):
        raise _invalid(where, f"bad source.url_template {template!r}") from None
    packs: dict[str, FwPack] = {}
    if not isinstance(raw.get("packs"), list):
        raise _invalid(where, "no packs list")
    for p in raw["packs"]:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not PACK_ID_RE.match(p["id"]):
            raise _invalid(where, f"bad pack id {p.get('id') if isinstance(p, dict) else p!r}")
        pid = p["id"]
        if pid in packs:
            raise _invalid(where, f"pack {pid} is listed twice")
        if not isinstance(p.get("files"), list) or not p["files"]:
            raise _invalid(where, f"pack {pid} has no files")
        files, seen = [], set()
        for f in p["files"]:
            if not isinstance(f, dict):
                raise _invalid(where, f"pack {pid}: bad file entry")
            path = check_fw_path(f.get("path"), "path", where)
            source = f.get("source_path")
            if source is not None:
                check_fw_path(source, "source_path", where)
            sha, size = f.get("sha256"), f.get("size")
            if not isinstance(sha, str) or not SHA256_RE.match(sha):
                raise _invalid(where, f"pack {pid}: {path}: bad sha256")
            if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_SIZE:
                raise _invalid(where, f"pack {pid}: {path}: bad size")
            if path in seen:
                raise _invalid(where, f"pack {pid}: {path} is listed twice")
            seen.add(path)
            files.append(FwFile(path, sha, size, source))
        packs[pid] = FwPack(pid, str(p.get("title") or pid), tuple(files))
    return Catalog(tag, kernel, template, packs, raw, where)


def load_catalog(path: str) -> Catalog:
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        raise BeastError(f"firmware catalog not found: {path}", code="catalog-missing") from None
    except OSError as e:
        raise BeastError(f"cannot read the firmware catalog {path}: {e.strerror or e}",
                         code="catalog-missing") from None
    return parse_catalog(data, path)


def dist_catalog(dist: str) -> Catalog:
    """The catalog shipped in a dist/ directory or .zip, checked against its
    manifest.json when the manifest lists it."""
    with tempfile.TemporaryDirectory(prefix="beast-boot-") as tmp:
        root = prepare_dist_dir(dist, tmp)
        path = root / DIST_CATALOG
        where = f"{dist}: {DIST_CATALOG}"
        if not path.is_file():
            raise BeastError(f"the boot files in {dist} have no firmware catalog ({DIST_CATALOG}; "
                             f"they were built without beast-net)", code="catalog-missing")
        data = path.read_bytes()
        try:
            manifest = json.loads((root / DIST_MANIFEST).read_text(encoding="utf-8"))
            entry = manifest.get("files", {}).get(DIST_CATALOG)
        except (OSError, ValueError, AttributeError):
            entry = None
        if isinstance(entry, dict) and entry.get("sha256") != hashlib.sha256(data).hexdigest():
            raise BeastError(f"{where}: sha256 mismatch with {DIST_MANIFEST}", code="catalog-invalid")
    return parse_catalog(data, where)


def catalog_json(cat: Catalog) -> dict:
    """The catalog as shipped, with each file's download URL added ("url")."""
    out = json.loads(json.dumps(cat.raw))
    for p in out["packs"]:
        pack = cat.packs[p["id"]]
        for f, ff in zip(p["files"], pack.files):
            f["url"] = cat.url(ff)
    return out


def format_catalog(cat: Catalog) -> str:
    lines = [f"Firmware catalog {cat.where}",
             f"  source: {cat.raw['source'].get('name', '?')} {cat.raw['source'].get('repo', '')}, tag {cat.tag}",
             f"  kernel: {cat.kernel or '?'}", ""]
    rows = [("PACK", "SIZE", "FILES", "TITLE")]
    rows += [(p.id, human_size(p.size), str(len(p.files)), p.title) for p in cat.packs.values()]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines += ["  " + "  ".join(c.ljust(w) for c, w in zip(r[:3], widths)) + "  " + r[3] for r in rows]
    if cat.packs:
        lines += ["", "Files are downloaded from URLs like " + cat.url(next(iter(cat.packs.values())).files[0])]
    lines.append("Use --json for every file with its SHA-256, licence and URL.")
    return "\n".join(lines).rstrip()


def pack_entry(pack: FwPack, cat: Catalog, cpio_sha256: str) -> dict:
    """The installed.json entry for a pack (also DIR/<id>.json)."""
    return {"id": pack.id, "catalog_tag": cat.tag, "kernel": cat.kernel, "cpio_sha256": cpio_sha256,
            "files": [{"path": f.path, "sha256": f.sha256, "size": f.size} for f in pack.files]}


def stale_reason(entry: dict, cat: Catalog) -> str | None:
    """Why an installed pack (its installed.json entry) no longer matches the
    catalog of the helper on the drive, or None when it does. An update can
    change the helper's kernel, and with it the files a pack must hold, while
    the linux-firmware tag stays the same; such packs still load but may lack
    what the new drivers ask for, so they are flagged for reinstalling."""
    pack = cat.packs.get(entry.get("id"))
    if pack is None:
        return "not in the drive's catalog"
    tag, kernel = entry.get("catalog_tag"), entry.get("kernel")
    if kernel and cat.kernel and kernel != cat.kernel:
        return f"made for kernel {kernel}"
    if tag != cat.tag:
        return f"made for linux-firmware tag {tag or '?'}"
    files = entry.get("files")
    have = sorted(((f.get("path"), f.get("sha256"), f.get("size")) for f in files if isinstance(f, dict)),
                  key=repr) \
        if isinstance(files, list) else None
    if have != sorted(((f.path, f.sha256, f.size) for f in pack.files), key=repr):
        return "made for other firmware files than the catalog lists"
    return None


def stale_hint(reason: str) -> str:
    """What to do about a stale pack (stale_reason)."""
    return "remove it" if reason.startswith("not in") else "reinstall it"


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------


class _Transient(Exception):
    """A download error worth another attempt (timeout, reset, HTTP 5xx/429)."""


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise BeastError(f"{req.full_url} redirects to {newurl}, which is not HTTPS; refusing it",
                             code="insecure-url")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    # The default context verifies the certificate chain and the host name;
    # nothing here ever turns that off.
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _HttpsOnlyRedirect())


def check_https(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.netloc:
        raise BeastError(f"refusing to download {url}: only https:// URLs are allowed", code="insecure-url")


def _mismatch(f: FwFile, url: str, what: str) -> BeastError:
    return BeastError(f"{f.path}: {what} (from {url}); the download was discarded", code="checksum-mismatch")


def _download_once(opener, url: str, f: FwFile, dest: str, rep: Reporter, on_bytes) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": f"beast-boot/{__version__}",
                                               "Accept-Encoding": "identity"})
    try:
        resp = opener.open(req, timeout=DOWNLOAD_TIMEOUT)
    except urllib.error.HTTPError as e:
        e.close()
        if e.code in (408, 425, 429) or 500 <= e.code <= 599:
            raise _Transient(f"HTTP {e.code} {e.reason}") from None
        raise BeastError(f"downloading {url} failed: HTTP {e.code} {e.reason}", code="download-failed") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise BeastError(f"downloading {url} failed: the server's certificate could not be verified "
                             f"({e.reason.verify_message or e.reason}); nothing was downloaded",
                             code="download-failed") from None
        if isinstance(e.reason, ssl.SSLError):
            raise BeastError(f"downloading {url} failed: TLS error ({e.reason})", code="download-failed") from None
        raise _Transient(str(e.reason)) from None
    except (OSError, http.client.HTTPException) as e:
        raise _Transient(str(e) or type(e).__name__) from None
    with resp:
        check_https(resp.geturl())
        length = resp.headers.get("Content-Length")
        if length is not None and length.strip().isdigit() and int(length) != f.size:
            raise _mismatch(f, url, f"the server sends {int(length)} bytes, the catalog says {f.size}")
        h, n = hashlib.sha256(), 0
        try:
            with open(dest, "wb") as out:
                while True:
                    rep.check_cancel(within=True)
                    try:
                        chunk = resp.read(CHUNK)
                    except (OSError, http.client.HTTPException) as e:
                        raise _Transient(str(e) or type(e).__name__) from None
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > f.size:
                        raise _mismatch(f, url, f"more than the {f.size} bytes the catalog says")
                    h.update(chunk)
                    out.write(chunk)
                    on_bytes(n)
            if n != f.size:
                if length is None:
                    raise _mismatch(f, url, f"{n} bytes, the catalog says {f.size}")
                raise _Transient(f"connection closed after {n} of {f.size} bytes")
            got = h.hexdigest()
            if got != f.sha256:
                raise _mismatch(f, url, f"SHA-256 mismatch (expected {f.sha256}, got {got})")
        except BaseException:
            try:
                os.unlink(dest)
            except OSError:
                pass
            raise


def _sleep(seconds: float, rep: Reporter) -> None:
    end = time.monotonic() + seconds
    while (left := end - time.monotonic()) > 0:
        rep.check_cancel(within=True)
        time.sleep(min(0.2, left))


def _download(opener, url: str, f: FwFile, dest: str, rep: Reporter, on_bytes) -> None:
    for attempt in range(1, ATTEMPTS + 1):
        try:
            _download_once(opener, url, f, dest, rep, on_bytes)
            return
        except _Transient as e:
            on_bytes(0)
            if attempt == ATTEMPTS:
                raise BeastError(f"downloading {url} failed after {ATTEMPTS} attempts: {e}",
                                 code="download-failed") from None
            delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS)) - 1]
            rep.warn(f"downloading {f.path} failed ({e}); trying again in {delay:g} s")
            _sleep(delay, rep)


def _replace_atomically(path: str, write) -> None:
    tmp = path + ".part"
    try:
        with open(tmp, "wb") as out:
            write(out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fetch(pack_ids: list[str], out_dir: str, cat: Catalog, rep: Reporter, *,
          for_image: str | None = None, for_device: str | None = None) -> dict:
    """Download, verify and pack; returns the "done" info (the caller sent the "start" event).
    With for_image / for_device, first check that the packs fit on that target (check_room)."""
    ids = list(dict.fromkeys(pack_ids))
    unknown = [p for p in ids if p not in cat.packs]
    if unknown:
        raise BeastError(f"no firmware pack {', '.join(map(repr, unknown))} in the catalog {cat.where} "
                         f"(packs: {', '.join(cat.packs)})", code="invalid-argument")
    packs = [cat.packs[p] for p in ids]
    for pack in packs:  # refuse before anything is downloaded
        for f in pack.files:
            check_https(cat.url(f))
    if for_image is not None or for_device is not None:
        check_room(packs, cat, for_image, for_device, rep)
    os.makedirs(out_dir, exist_ok=True)
    total = sum(p.size for p in packs)
    done = 0
    opener = _opener()
    results = []
    for pack in packs:
        with tempfile.TemporaryDirectory(prefix=f".fetch-{pack.id}-", dir=out_dir) as tmp:
            local: dict[str, str] = {}
            rep.step(f"Downloading {pack.id} ({len(pack.files)} files, {human_size(pack.size)}) "
                     f"from linux-firmware tag {cat.tag}", "download", 90 * done / max(total, 1))
            for i, f in enumerate(pack.files):
                url = cat.url(f)
                last = [0]

                def on_bytes(n: int, f=f, i=i) -> None:
                    if n - last[0] >= PROGRESS_EVERY or n == f.size or n == 0:
                        last[0] = n
                        rep.progress("download", f"Downloading {pack.id}: {f.path} ({i + 1} of {len(pack.files)})",
                                     90 * (done + n) / max(total, 1))

                dest = os.path.join(tmp, f"{i:05d}")
                _download(opener, url, f, dest, rep, on_bytes)
                local[f.path] = dest
                done += f.size
            rep.note(f"{pack.id}: all {len(pack.files)} files match their SHA-256 in the catalog")
            rep.step(f"Writing {pack.id}.cpio", "write-firmware", 90 * done / max(total, 1))
            h = hashlib.sha256()

            def write_cpio(out) -> None:
                for chunk in iter_pack(local):
                    h.update(chunk)
                    out.write(chunk)

            cpio_path = os.path.join(out_dir, f"{pack.id}.cpio")
            _replace_atomically(cpio_path, write_cpio)
            entry = pack_entry(pack, cat, h.hexdigest())
            _replace_atomically(os.path.join(out_dir, f"{pack.id}.json"),
                                lambda out: out.write((json.dumps(entry, indent=1) + "\n").encode("utf-8")))
            results.append({"id": pack.id, "cpio": cpio_path, "cpio_sha256": entry["cpio_sha256"],
                            "size": os.path.getsize(cpio_path), "files": len(pack.files)})
    rep.step(f"done: {len(results)} firmware pack(s) in {out_dir}")
    return {"packs": ids, "out": out_dir, "catalog_tag": cat.tag, "kernel": cat.kernel, "results": results}


# ---------------------------------------------------------------------------
# Drives: install / remove / list
# ---------------------------------------------------------------------------


@dataclass
class _FwState:
    table: object
    plan: object
    catalog: Catalog | None  # the one on the drive
    installed: dict  # installed.json ({"v": 1, "packs": [...]})
    files: dict  # name in beast-net/firmware/ -> size
    has_kernel: bool
    free: int
    cluster: int
    label: str = ""


def _read_installed(vol: FatVolume, rep: Reporter | None) -> dict:
    empty = {"v": 1, "packs": []}
    if not vol.exists(FIRMWARE_INSTALLED_PATH):
        return empty
    try:
        d = json.loads(vol.read_file(FIRMWARE_INSTALLED_PATH))
        packs = d["packs"]
        if d.get("v") != 1 or not isinstance(packs, list) or not all(
                isinstance(p, dict) and isinstance(p.get("id"), str) for p in packs):
            raise ValueError("unexpected structure")
        return {"v": 1, "packs": packs}
    except (ValueError, KeyError, TypeError, BeastError, UnicodeDecodeError) as e:
        if rep is not None:
            rep.warn(f"{FIRMWARE_INSTALLED_PATH} is unreadable ({e}); it is rewritten from the packs installed now")
        return empty


def _read_state(t, where: str, rep: Reporter | None) -> _FwState:
    table, plan, vol, _marker = cmd.read_drive_esp(t, where)
    catalog = None
    if vol.exists(BEASTNET_CATALOG_PATH):
        catalog = parse_catalog(vol.read_file(BEASTNET_CATALOG_PATH), f"{where}: {BEASTNET_CATALOG_PATH}")
    files = {}
    if vol.exists(FIRMWARE_DIR):
        files = {e.name: e.size for e in vol.listdir(FIRMWARE_DIR) if not e.is_dir}
    return _FwState(table, plan, catalog, _read_installed(vol, rep), files, vol.exists(KERNEL_PATH),
                    vol.free_bytes(), vol.cluster_size, vol.label)


def _esp_only(plan) -> list[tuple[int, int]]:
    return [(plan.esp.offset, plan.esp.offset + plan.esp.size_bytes)]


class _Drive:
    """Opens a target the way update does: an image file, or a disk through the
    platform backend (check_safe; prepare before writing; rescan after)."""

    def __init__(self, image: str | None, device: str | None, *, allow_fixed: bool, writable: bool):
        self.image, self.backend, self.disk = image, None, None
        if device is not None:
            self.backend = cmd.get_backend()
            self.disk = self.backend.get_disk(device)
            if writable:
                self.backend.check_safe(self.disk, allow_fixed=allow_fixed)
            self.where = self.disk.id
        else:
            assert image is not None
            cmd._existing_image(image)
            self.where = image

    def reader(self):
        if self.disk is not None:
            t = self.backend.open_raw(self.disk, writable=False)
            cmd._drop_cache(self.backend, t)
            return t
        return ImageTarget(self.image, writable=False)

    def writer(self, st: _FwState, rep: Reporter, pct: float):
        if self.disk is not None:
            cmd.prepare_device(self.backend, self.disk, rep, pct)
            t = cmd._open_device(self.backend, self.disk, _esp_only(st.plan))
        else:
            t = GuardedTarget(ImageTarget(self.image, writable=True), _esp_only(st.plan))
        try:
            cmd._drop_cache(self.backend, t)
            if cmd._read_table(t, self.where) != st.table:
                raise BeastError(f"the partition table of {self.where} changed while it was being read; try again")
        except BaseException:
            t.close()
            raise
        return t

    def finish(self, rep: Reporter, pct: float) -> None:
        if self.disk is not None:
            rep.step("Letting the system re-read the drive", "rescan", pct)
            cmd._rescan(self.backend, self.disk, rep)


def _installed_json(installed: dict) -> bytes:
    packs = sorted(installed["packs"], key=lambda p: p["id"])
    return (json.dumps({"v": 1, "packs": packs}, indent=1) + "\n").encode("utf-8")


def _no_space(where: str, ids: list[str], space: esp.FwSpace) -> BeastError:
    on = f" ({space.label})" if space.label else ""
    freed = f", counting {human_size(space.reclaimed)} freed by what they replace" if space.reclaimed else ""
    return BeastError(
        f"not enough space on the boot partition{on} of {where} for {', '.join(ids)}: "
        f"{human_size(space.need)} needed, {human_size(space.available)} available{freed}; deselect packs or "
        f"remove installed ones first (beast-boot firmware remove)", code="no-space")


def check_room(packs: list[FwPack], cat: Catalog, image: str | None, device: str | None,
               rep: Reporter) -> esp.FwSpace | None:
    """`fetch --for-image P | --for-device X`: refuse with "no-space" before anything is
    downloaded when the packs (sizes from the catalog, which fetch's archives match
    exactly) can't fit on the target's boot partition, counting the packs they replace.

    Reading a drive needs administrator rights (fetch itself doesn't): when the drive
    can't be opened without them, the check is skipped with a warning, and
    `firmware install` still makes its own final check before it writes anything."""
    where = device if device is not None else image
    rep.step(f"Checking the free space on the boot partition of {where}", "check-target", 0)
    drive = _Drive(image, device, allow_fixed=True, writable=False)
    try:
        t = drive.reader()
    except BeastError as e:
        if drive.backend is None or drive.backend.is_elevated():
            raise
        rep.warn(f"cannot read {drive.where} without administrator rights ({e}), so its free space was not "
                 "checked before downloading; `firmware install` checks it before writing (run fetch as "
                 "administrator to check it first)")
        return None
    with t:
        st = _read_state(t, drive.where, None)
    ids = [p.id for p in packs]
    kept = [p for p in st.installed["packs"] if p["id"] not in ids]
    blob = _installed_json({"v": 1, "packs": kept + [pack_entry(p, cat, "0" * 64) for p in packs]})
    space = esp.fw_space({p.id: esp.fw_archive_size((f.path, f.size) for f in p.files) for p in packs},
                         free=st.free, cluster=st.cluster, on_drive=st.files, json_size=len(blob), label=st.label)
    if not space.fits:
        raise _no_space(drive.where, ids, space)
    rep.note(f"{human_size(space.need)} needed, {human_size(space.available)} available on the boot partition "
             f"of {drive.where}")
    return space


def verify_pack(pid: str, data: bytes, entry: dict, cat: Catalog) -> dict:
    """Check a fetched pack against the catalog; returns its installed.json entry."""
    pack = cat.packs.get(pid)
    if pack is None:
        raise BeastError(f"{pid}: the catalog {cat.where} (tag {cat.tag}) has no pack {pid!r}", code="pack-mismatch")
    tag, kernel = entry.get("catalog_tag"), entry.get("kernel")
    if tag != cat.tag or (kernel and cat.kernel and kernel != cat.kernel):
        raise BeastError(
            f"{pid} was fetched for linux-firmware tag {tag} (kernel {kernel or '?'}), but the beast-net on the "
            f"target uses tag {cat.tag} (kernel {cat.kernel or '?'}); fetch it again with that catalog "
            f"(or update the drive first)", code="pack-mismatch")
    sha = hashlib.sha256(data).hexdigest()
    if entry.get("cpio_sha256") != sha:
        raise BeastError(f"{pid}.cpio does not match the SHA-256 in {pid}.json", code="pack-invalid")
    entries = read_newc(data, f"{pid}.cpio")
    found: dict[str, bytes] = {}
    prefix = FIRMWARE_ROOT + "/"
    for e in entries:
        if (e.uid, e.gid, e.mtime, e.devmajor, e.devminor, e.rdevmajor, e.rdevminor, e.check) != (0,) * 8:
            raise BeastError(f"{pid}.cpio: {e.name} has unexpected owner/time/device fields", code="pack-invalid")
        if e.is_dir and e.mode == DIR_MODE and not e.data:
            continue
        if not (e.is_file and e.mode == FILE_MODE and e.name.startswith(prefix)):
            raise BeastError(f"{pid}.cpio: unexpected entry {e.name!r} (mode {e.mode:o})", code="pack-invalid")
        found[e.name[len(prefix):]] = e.data
    want = {f.path: f for f in pack.files}
    extra, missing = sorted(set(found) - set(want)), sorted(set(want) - set(found))
    if extra or missing:
        raise BeastError(f"{pid}.cpio does not hold the files the catalog lists"
                         + (f"; not in the catalog: {', '.join(extra[:5])}" if extra else "")
                         + (f"; missing: {', '.join(missing[:5])}" if missing else ""), code="pack-invalid")
    for path, f in want.items():
        got = hashlib.sha256(found[path]).hexdigest()
        if len(found[path]) != f.size or got != f.sha256:
            raise BeastError(f"{pid}.cpio: {path}: SHA-256 mismatch with the catalog (expected {f.sha256}, "
                             f"got {got})", code="checksum-mismatch")
    canonical = hashlib.sha256()
    for chunk in iter_pack(found):
        canonical.update(chunk)
    if canonical.hexdigest() != sha:
        raise BeastError(f"{pid}.cpio is not in the canonical pack format (docs/BEASTNET.md section 6)",
                         code="pack-invalid")
    return pack_entry(pack, cat, sha)


def _read_pack_dir(from_dir: str) -> list[tuple[str, bytes, dict]]:
    try:
        names = sorted(os.listdir(from_dir))
    except OSError as e:
        raise BeastError(f"cannot read the pack folder {from_dir}: {e.strerror or e}", code="invalid-argument") from None
    out = []
    for name in names:
        if not name.endswith(".json") or name.startswith("."):
            continue
        pid = name[:-5]
        if not PACK_ID_RE.match(pid):
            continue
        try:
            entry = json.loads(Path(from_dir, name).read_text(encoding="utf-8"))
            data = Path(from_dir, f"{pid}.cpio").read_bytes()
        except FileNotFoundError:
            raise BeastError(f"{from_dir}: {pid}.json has no {pid}.cpio next to it", code="pack-invalid") from None
        except (OSError, ValueError, UnicodeDecodeError) as e:
            raise BeastError(f"{from_dir}: cannot read {name}: {e}", code="pack-invalid") from None
        if not isinstance(entry, dict) or entry.get("id") != pid:
            raise BeastError(f"{from_dir}: {name} is not the entry of pack {pid}", code="pack-invalid")
        out.append((pid, data, entry))
    if not out:
        raise BeastError(f"no firmware packs (<id>.cpio + <id>.json, from `firmware fetch`) in {from_dir}",
                         code="invalid-argument")
    return out


def _result(st: _FwState, where: str) -> dict:
    """The installed.json object, plus what the GUI may show: each pack's
    "missing" (its .cpio is gone) or "cpio_size", unlisted .cpio files, the
    drive's catalog tag and kernel, and what the GUI needs to check the free
    space before it downloads anything (esp.fw_space): esp_free, esp_cluster,
    esp_label, installed_json_size. A pack that no longer matches the drive's
    catalog (made for another kernel or tag, or other files: stale_reason)
    also gets "stale": true and "stale_reason"."""
    sizes = {n.lower(): size for n, size in st.files.items()}
    packs = []
    for p in sorted(st.installed["packs"], key=lambda p: p["id"]):
        p = dict(p)
        size = sizes.get(f"{p['id']}.cpio".lower())
        if size is None:
            p["missing"] = True
        else:
            p["cpio_size"] = size
        reason = stale_reason(p, st.catalog) if st.catalog is not None else None
        if reason:
            p["stale"], p["stale_reason"] = True, reason
        packs.append(p)
    listed = {f"{p['id']}.cpio".lower() for p in packs}
    return {"v": 1, "packs": packs, "target": where,
            "unlisted": sorted(n for n in st.files if n.lower().endswith(".cpio") and n.lower() not in listed),
            "esp_free": st.free, "esp_cluster": st.cluster, "esp_label": st.label,
            "installed_json_size": sizes.get(esp.INSTALLED_JSON, 0),
            "catalog_tag": st.catalog.tag if st.catalog else None,
            "kernel": st.catalog.kernel if st.catalog else None}


def install(image: str | None, device: str | None, from_dir: str, dist: str | None, *,
            allow_fixed: bool, rep: Reporter) -> dict:
    where = device if device is not None else image
    rep.start("firmware-install", where)
    rep.step(f"Reading the beast-boot drive {where}", "check-target", 5)
    drive = _Drive(image, device, allow_fixed=allow_fixed, writable=True)
    where = drive.where
    fetched = _read_pack_dir(from_dir)
    with drive.reader() as t:
        st = _read_state(t, where, rep)
    if st.catalog is not None:
        cat, source = st.catalog, "drive"
        rep.note(f"checking against the catalog on {where} (linux-firmware tag {cat.tag}, kernel {cat.kernel})")
    else:
        if dist is None:
            raise BeastError(f"{where} has no firmware catalog ({BEASTNET_CATALOG_PATH}) and no boot files were "
                             f"given to take one from", code="catalog-missing")
        cat, source = dist_catalog(dist), "dist"
        rep.warn(f"{where} has no firmware catalog ({BEASTNET_CATALOG_PATH}); checking against the one in the "
                 f"boot files {dist} (tag {cat.tag}) instead")
    if not st.has_kernel:
        rep.warn(f"{where} has no beast-net helper ({KERNEL_PATH}) yet; the packs are used once the drive is "
                 "updated with boot files that include it")
    rep.step(f"Re-checking {len(fetched)} pack(s) against the catalog (tag {cat.tag})", "verify-packs", 15)
    new_entries = {}
    for pid, data, entry in fetched:
        rep.check_cancel(within=True)
        new_entries[pid] = verify_pack(pid, data, entry, cat)
    installed = {"v": 1, "packs": [p for p in st.installed["packs"] if p["id"] not in new_entries]
                 + list(new_entries.values())}
    blob = _installed_json(installed)
    space = esp.fw_space({pid: len(d) for pid, d, _e in fetched}, free=st.free, cluster=st.cluster,
                         on_drive=st.files, json_size=len(blob), label=st.label)
    if not space.fits:
        raise _no_space(where, list(new_entries), space)
    with drive.writer(st, rep, 30) as t:
        vol = FatVolume(t, st.plan.esp.offset)
        rep.step(f"Writing {len(fetched)} pack(s) to {FIRMWARE_DIR}/ on {where}", "write-firmware", 40)
        with vol.batch():
            for pid, data, _entry in fetched:
                rep.check_cancel(within=True)
                vol.write_file(f"{FIRMWARE_DIR}/{pid}.cpio", data)
            vol.write_file(FIRMWARE_INSTALLED_PATH, blob)
        rep.step("Flushing data to the drive" if device else "Flushing the image file", "flush", 85)
        t.flush()
    drive.finish(rep, 90)
    rep.step("Checking what was written", "verify-write", 95)
    with drive.reader() as t:
        st2 = _read_state(t, where, None)
        vol = FatVolume(t, st2.plan.esp.offset)
        for pid, data, _entry in fetched:
            if hashlib.sha256(vol.read_file(f"{FIRMWARE_DIR}/{pid}.cpio")).hexdigest() != new_entries[pid]["cpio_sha256"]:
                raise BeastError(f"{where}: {pid}.cpio read back differs from what was written", code="verify-failed")
        if {p["id"] for p in st2.installed["packs"]} != {p["id"] for p in installed["packs"]}:
            raise BeastError(f"{where}: installed.json read back differs from what was written", code="verify-failed")
    rep.step(f"done: {', '.join(new_entries)} installed on {where}")
    result = _result(st2, where)
    return {"installed": result, "catalog": {"source": source, "where": cat.where, "tag": cat.tag,
                                             "kernel": cat.kernel}}


def remove(image: str | None, device: str | None, pack_id: str, *, allow_fixed: bool, rep: Reporter) -> dict:
    where = device if device is not None else image
    rep.start("firmware-remove", where)
    rep.step(f"Reading the beast-boot drive {where}", "check-target", 10)
    drive = _Drive(image, device, allow_fixed=allow_fixed, writable=True)
    where = drive.where
    with drive.reader() as t:
        st = _read_state(t, where, rep)
    cpio_name = next((n for n in st.files if n.lower() == f"{pack_id}.cpio"), None)
    listed = any(p["id"] == pack_id for p in st.installed["packs"])
    if cpio_name is None and not listed:
        raise BeastError(f"firmware pack {pack_id} is not installed on {where}", code="invalid-argument")
    installed = {"v": 1, "packs": [p for p in st.installed["packs"] if p["id"] != pack_id]}
    with drive.writer(st, rep, 30) as t:
        vol = FatVolume(t, st.plan.esp.offset)
        rep.step(f"Removing {FIRMWARE_DIR}/{pack_id}.cpio from {where}", "write-firmware", 50)
        with vol.batch():
            if cpio_name is not None:
                vol.remove(f"{FIRMWARE_DIR}/{cpio_name}")
            vol.write_file(FIRMWARE_INSTALLED_PATH, _installed_json(installed))
        rep.step("Flushing data to the drive" if device else "Flushing the image file", "flush", 80)
        t.flush()
    drive.finish(rep, 88)
    rep.step("Checking what was written", "verify-write", 95)
    with drive.reader() as t:
        st2 = _read_state(t, where, None)
    if any(p["id"] == pack_id for p in st2.installed["packs"]) or f"{pack_id}.cpio" in {n.lower() for n in st2.files}:
        raise BeastError(f"{where}: {pack_id} is still there after removing it", code="verify-failed")
    rep.step(f"done: {pack_id} removed from {where}")
    return {"installed": _result(st2, where)}


def list_installed(image: str | None, device: str | None, rep: Reporter) -> dict:
    where = device if device is not None else image
    rep.start("firmware-list", where)
    rep.step(f"Reading {FIRMWARE_INSTALLED_PATH} on {where}", "check-target", 50)
    drive = _Drive(image, device, allow_fixed=True, writable=False)
    with drive.reader() as t:
        st = _read_state(t, drive.where, None)
    return _result(st, drive.where)


def format_installed(d: dict) -> str:
    kernel = f", kernel {d['kernel']}" if d.get("kernel") else ""
    lines = [f"Firmware packs on {d['target']} (catalog tag {d['catalog_tag'] or 'none'}{kernel}, "
             f"{human_size(d['esp_free'])} free on the boot partition):"]
    if not d["packs"]:
        lines.append("  none installed")
    for p in d["packs"]:
        note = "  (MISSING: its .cpio is gone; remove and reinstall it)" if p.get("missing") else ""
        if p.get("stale") and not note:
            reason = p.get("stale_reason") or "made for another catalog"
            note = f"  (STALE: {reason}; {stale_hint(reason)})"
        lines.append(f"  {p['id']:24} tag {p.get('catalog_tag')}, {len(p.get('files') or [])} files{note}")
    for n in d["unlisted"]:
        lines.append(f"  {n}: not in installed.json")
    if any(p.get("stale") and not p.get("missing") and stale_hint(p.get("stale_reason") or "") == "reinstall it"
           for p in d["packs"]):
        lines.append("  Reinstall a stale pack with `firmware fetch --pack ID` and `firmware install` (or "
                     "Download and install... on the app's Firmware packs page); that replaces it.")
    return "\n".join(lines)
