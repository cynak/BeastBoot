"""Firmware packs for the network helper (docs/BEASTNET.md section 6), without any GUI toolkit.

The packs are closed-source firmware files from the linux-firmware project,
needed only for WiFi and some Ethernet adapters in beast-net ("Download an ISO
from a link"). The catalog shipped with the boot files
(<dist>/esp/beast-net/catalog.json) names every file with its SHA-256 and the
exact upstream URL it comes from; the window shows all of that before anything
is downloaded.

Installing packs is two CLI runs (three when the free space on the target's
boot partition isn't known yet: `firmware list` runs first, so a selection that
doesn't fit is refused before anything is downloaded):

    firmware fetch --pack ID ... --out DIR --catalog FILE --progress-file F
        unprivileged: downloads into a private temporary directory, checks
        every SHA-256, builds DIR/<id>.cpio and DIR/<id>.json
    firmware install (--device X | --image P) --from DIR --progress-file F
        elevated for a drive: re-checks the packs and writes them to the
        boot partition

`firmware remove` and `firmware list` report their result (the drive's
installed.json) in the "done" event of the progress file, because the output
of an elevated process can't be read back on every OS.

State machine (FirmwareController.phase):

    IDLE --request_install/remove--> CONFIRMING --confirm--> RUNNING --> DONE / FAILED
      ^               (refresh_installed goes straight to RUNNING)        |
      +----------------------------- cancel_request / dismiss ------------+
"""

from __future__ import annotations

import enum
import json
import os
import re
import shutil
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import BeastError
from ..esp import INSTALLED_JSON, FwSpace, fw_archive_size, fw_space, installed_entry_estimate
from ..interfaces import DiskInfo
from ..layout import DIST_ESP_DIR, ESP_LABEL
from ..util import human_size
from .controller import (
    ELEVATION_CANCELLED,
    ELEVATION_FAILED,
    Controller,
    DriveRow,
    Phase,
    _error_text,
    _quote,
)
from .localproc import LocalProcess
from .progress import LogLine, ProgressReader, ProgressState

CATALOG_REL = f"{DIST_ESP_DIR}/beast-net/catalog.json"
PACK_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

ABOUT = ("Firmware packs are closed-source firmware from linux-firmware. They are needed only for WiFi "
         "and some Ethernet adapters in the network helper (\"Download an ISO from a link\" in the boot "
         "menu). Nothing is downloaded until you choose to install a pack, and every file is checked "
         "against the SHA-256 in the catalog.")
CLOSED_SOURCE = "Closed-source firmware from linux-firmware"


# Extra advice for some of the CLI's error codes (its own message is always shown first).
CODE_HINTS = {
    "reinstall-needed": "This drive was made by an older beast-booter without the network helper. Install "
                        "beast-booter on it again (this erases it), then add the packs.",
    "layout-too-new": "This drive was made by a newer beast-booter. Use that version to change its firmware packs.",
    "layout-unsupported": "This drive's layout has no room for the network helper. Install beast-booter on it again.",
    "no-space": "The boot partition is full. Remove a pack you don't need, then try again.",
    "busy": "A program is still using the drive (an open file, or a file manager or terminal showing it). "
            "Close it, then try again. Nothing was changed.",
    "download-failed": "Check the internet connection, then try again. Nothing was installed.",
    "checksum-mismatch": "A downloaded file did not match the catalog, so it was discarded. Nothing was installed.",
    "insecure-url": "The catalog names a download that is not https://, so it was refused.",
    "catalog-missing": "These boot files have no firmware catalog.",
    "catalog-invalid": "The firmware catalog of these boot files is damaged.",
}


class CatalogError(BeastError):
    """The catalog is missing or not what docs/BEASTNET.md describes."""


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FwFile:
    path: str  # installed as lib/firmware/<path>
    sha256: str
    size: int
    license: str
    url: str  # where it is downloaded from (exact, with the tag)
    source_path: str = ""  # path in linux-firmware when it differs (a WHENCE Link:)


@dataclass(frozen=True)
class FwPack:
    id: str
    title: str
    description: str
    modules: tuple[str, ...]
    licenses: tuple[str, ...]
    size: int
    files: tuple[FwFile, ...]

    @property
    def size_text(self) -> str:
        return human_size(self.size)

    @property
    def modules_text(self) -> str:
        return ", ".join(self.modules)

    def describe_files(self) -> str:
        return f"{len(self.files)} file{'s' if len(self.files) != 1 else ''}, {self.size_text}"


@dataclass(frozen=True)
class Catalog:
    path: Path
    kernel: str
    source_name: str
    repo: str
    tag: str
    url_template: str
    packs: tuple[FwPack, ...]

    def pack(self, pack_id: str) -> FwPack | None:
        return next((p for p in self.packs if p.id == pack_id), None)

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.repo).hostname or self.repo


def catalog_path(dist: Path | None) -> Path | None:
    return None if dist is None else Path(dist) / CATALOG_REL


def file_url(template: str, tag: str, path: str) -> str:
    """The download URL of one file: the catalog's url_template, path and tag
    percent-encoded (BEASTNET.md: .../plain/<path>?h=<tag>)."""
    return template.format(path=urllib.parse.quote(path, safe="/"), tag=urllib.parse.quote(tag, safe=""))


def _need(cond: bool, what: str) -> None:
    if not cond:
        raise CatalogError(f"the firmware catalog is not valid: {what}")


def _str(obj: dict, key: str, where: str) -> str:
    v = obj.get(key)
    _need(isinstance(v, str) and bool(v), f"{where}: {key!r} missing")
    return v


def _int(obj: dict, key: str, where: str) -> int:
    v = obj.get(key)
    _need(isinstance(v, int) and not isinstance(v, bool) and v >= 0, f"{where}: {key!r} is not a size")
    return v


def parse_catalog(obj, path: Path) -> Catalog:
    _need(isinstance(obj, dict), "not a JSON object")
    _need(obj.get("v") == 1, f"unknown version {obj.get('v')!r} (this window knows 1)")
    src = obj.get("source")
    _need(isinstance(src, dict), "'source' missing")
    repo, tag, template = _str(src, "repo", "source"), _str(src, "tag", "source"), _str(src, "url_template", "source")
    _need(repo.startswith("https://") and template.startswith("https://"), "the source is not an https:// URL")
    _need("{path}" in template, "url_template has no {path}")
    packs = obj.get("packs")
    _need(isinstance(packs, list), "'packs' missing")
    out: list[FwPack] = []
    for i, p in enumerate(packs):
        _need(isinstance(p, dict), f"pack {i} is not an object")
        pid = _str(p, "id", f"pack {i}")
        _need(bool(PACK_ID_RE.match(pid)), f"pack id {pid!r}")
        _need(all(q.id != pid for q in out), f"pack {pid} listed twice")
        files = []
        for j, f in enumerate(p.get("files") or []):
            where = f"pack {pid} file {j}"
            _need(isinstance(f, dict), f"{where} is not an object")
            fpath = _str(f, "path", where)
            _need(not fpath.startswith("/") and ".." not in fpath.split("/"), f"{where}: unsafe path {fpath!r}")
            sha = _str(f, "sha256", where).lower()
            _need(bool(SHA256_RE.match(sha)), f"{where}: bad sha256")
            source = f.get("source_path") if isinstance(f.get("source_path"), str) else ""
            url = f.get("url") if isinstance(f.get("url"), str) and f["url"].startswith("https://") else ""
            files.append(FwFile(fpath, sha, _int(f, "size", where), str(f.get("license") or ""),
                                url or file_url(template, tag, source or fpath), source))
        _need(bool(files), f"pack {pid} has no files")
        mods = p.get("modules") if isinstance(p.get("modules"), list) else []
        lics = p.get("licenses") if isinstance(p.get("licenses"), list) else []
        size = p.get("size") if isinstance(p.get("size"), int) else sum(f.size for f in files)
        out.append(FwPack(pid, _str(p, "title", f"pack {pid}"), str(p.get("description") or ""),
                          tuple(str(m) for m in mods), tuple(str(x) for x in lics), size, tuple(files)))
    return Catalog(path, str(obj.get("kernel") or ""), str(src.get("name") or "linux-firmware"), repo, tag,
                   template, tuple(out))


def load_catalog(path: Path) -> Catalog:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CatalogError(f"{path} does not exist") from None
    except (OSError, UnicodeDecodeError) as e:
        raise CatalogError(f"cannot read {path}: {e}") from None
    try:
        obj = json.loads(text)
    except ValueError as e:
        raise CatalogError(f"{path} is not valid JSON ({e})") from None
    return parse_catalog(obj, Path(path))


def details_text(cat: Catalog, pack: FwPack) -> str:
    """Everything about one pack, as plain text (the details view, also copyable)."""
    lines = [
        f"{pack.title} ({pack.id})",
        f"Source:      {cat.source_name}",
        f"Repository:  {cat.repo}",
        f"Tag:         {cat.tag}",
        f"Drivers:     {pack.modules_text or '-'}",
        f"Size:        {pack.describe_files()}",
        "Licences:    " + ("\n             ".join(pack.licenses) or "-"),
        "",
    ]
    for f in pack.files:
        lines.append(f"{f.path}  ({human_size(f.size)})")
        lines.append(f"  SHA-256  {f.sha256}")
        lines.append(f"  URL      {f.url}")
        if f.license:
            lines.append(f"  Licence  {f.license}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# What is installed on a drive or image (installed.json, BEASTNET.md section 6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstalledPack:
    id: str
    catalog_tag: str
    cpio_sha256: str
    files: int


def parse_installed(info) -> tuple[InstalledPack, ...] | None:
    """The packs from a `firmware list/install/remove` "done" event's info:
    installed.json itself ({"v":1,"packs":[...]}) or {"installed": <that>}.
    None if it is neither."""
    if not isinstance(info, dict):
        return None
    if isinstance(info.get("installed"), dict):
        info = info["installed"]
    packs = info.get("packs")
    if not isinstance(packs, list):
        return None
    out = []
    for p in packs:
        if isinstance(p, dict) and isinstance(p.get("id"), str) and PACK_ID_RE.match(p["id"]):
            files = p.get("files")
            out.append(InstalledPack(p["id"], str(p.get("catalog_tag") or ""), str(p.get("cpio_sha256") or ""),
                                     len(files) if isinstance(files, list) else 0))
    return tuple(out)


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


@dataclass(frozen=True)
class EspSpace:
    """The target's boot partition, from a `firmware list/install/remove` result."""
    free: int
    cluster: int
    label: str
    files: dict = field(default_factory=dict)  # beast-net/firmware/ name (lower case) -> size

    @property
    def json_size(self) -> int:
        return self.files.get(INSTALLED_JSON, 0)


def parse_space(info) -> EspSpace | None:
    """Free space, cluster size, label and the installed packs' sizes from a "done"
    event's info (see firmware._result); None if it doesn't say how much is free."""
    if not isinstance(info, dict):
        return None
    if isinstance(info.get("installed"), dict):
        info = info["installed"]
    if not _count(info.get("esp_free")):
        return None
    cluster = info.get("esp_cluster")
    label = info.get("esp_label")
    files: dict[str, int] = {}
    for p in info.get("packs") if isinstance(info.get("packs"), list) else ():
        if not (isinstance(p, dict) and isinstance(p.get("id"), str) and PACK_ID_RE.match(p["id"])) or p.get("missing"):
            continue
        size = p.get("cpio_size")
        if not _count(size):  # not reported: what fetch built from the files it lists
            entries = p.get("files") if isinstance(p.get("files"), list) else []
            ok = all(isinstance(f, dict) and isinstance(f.get("path"), str) and _count(f.get("size")) for f in entries)
            size = fw_archive_size((f["path"], f["size"]) for f in entries) if ok and entries else 0
        files[f"{p['id']}.cpio"] = size
    if _count(info.get("installed_json_size")):
        files[INSTALLED_JSON] = info["installed_json_size"]
    return EspSpace(info["esp_free"], cluster if _count(cluster) and cluster > 0 else 4096,
                    label.strip() if isinstance(label, str) and label.strip() else ESP_LABEL, files)


# ---------------------------------------------------------------------------
# Targets and the CLI command lines
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FwTarget:
    kind: str  # "device" | "image"
    target: str  # device id or absolute image path
    disk: DiskInfo | None = None

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.target}"

    @property
    def text(self) -> str:
        if self.disk is not None:
            return DriveRow(self.disk, None).describe()
        return self.target

    @property
    def short(self) -> str:
        if self.disk is not None:
            return DriveRow(self.disk, None).title
        return os.path.basename(self.target)


def build_fw_argv(command: str, *, python: str, launcher: str, progress_file: str,
                  target: FwTarget | None = None, packs: tuple[str, ...] = (), out_dir: str | None = None,
                  from_dir: str | None = None, catalog: str | None = None) -> list[str]:
    """The exact `beast-booter firmware ...` command line (a list, never a shell string)."""
    paths = [("python", python), ("launcher", launcher), ("progress file", progress_file)]
    paths += [(n, p) for n, p in (("download folder", out_dir), ("pack folder", from_dir), ("catalog", catalog))
              if p is not None]
    if target is not None and target.kind == "image":
        paths.append(("image", target.target))
    for what, p in paths:
        if not p or not os.path.isabs(p):
            raise BeastError(f"internal error: {what} path must be absolute, got {p!r}")
    for pid in packs:
        if not PACK_ID_RE.match(pid):
            raise BeastError(f"internal error: bad pack id {pid!r}")
    argv = [python, "-s", "-E", "-B", launcher, "firmware", command]

    def target_args() -> list[str]:
        if target is None or target.kind not in ("device", "image"):
            raise BeastError(f"internal error: firmware {command} needs a target")
        return ["--device" if target.kind == "device" else "--image", target.target]

    if command == "fetch":
        if not packs or out_dir is None:
            raise BeastError("internal error: fetch needs packs and a folder")
        for pid in packs:
            argv += ["--pack", pid]
        argv += ["--out", out_dir]
        if catalog:
            argv += ["--catalog", catalog]
    elif command == "install":
        if from_dir is None:
            raise BeastError("internal error: install needs the fetched packs")
        argv += target_args() + ["--from", from_dir]
    elif command == "remove":
        if len(packs) != 1:
            raise BeastError("internal error: remove takes one pack")
        argv += target_args() + ["--pack", packs[0]]
    elif command == "list":
        argv += target_args() + ["--json"]
    else:
        raise BeastError(f"internal error: unknown firmware command {command!r}")
    return argv + ["--progress-file", progress_file]


# ---------------------------------------------------------------------------
# The controller
# ---------------------------------------------------------------------------


class FwPhase(enum.Enum):
    IDLE = "idle"
    CONFIRMING = "confirming"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class FwRequest:
    action: str  # "install" | "remove"
    target: FwTarget
    packs: tuple[FwPack, ...]
    title: str
    details: tuple[str, ...]
    confirm_label: str
    danger: bool = False


@dataclass(frozen=True)
class FwOutcome:
    ok: bool
    action: str  # "install" | "remove" | "list"
    title: str
    message: str
    target: FwTarget
    code: str | None = None
    exit_code: int | None = None
    output_tail: tuple[str, ...] = ()
    cancelled: bool = False


@dataclass
class _FwJob:
    stage: str  # "fetch" | "install" | "remove" | "list"
    action: str
    target: FwTarget
    packs: tuple[FwPack, ...]
    argv: list[str]
    proc: object
    reader: ProgressReader
    state: ProgressState
    tmpdir: str  # private (0700); holds the progress files and the downloaded packs
    elevated: bool
    started_at: float
    log: list[LogLine] = field(default_factory=list)  # all stages
    cancel_requested: bool = False


class FirmwareController:
    """Catalog, pack selection, target, and the fetch/install/remove/list runs."""

    STAGES = {"check": (0.0, 0.0), "fetch": (0.0, 0.7), "install": (0.7, 1.0), "remove": (0.0, 1.0),
              "list": (0.0, 1.0)}

    def __init__(self, main: Controller, *, clock=time.monotonic):
        self.main = main
        self._clock = clock
        main.other_job_running = lambda: self.phase is FwPhase.RUNNING
        self.catalog: Catalog | None = None
        self.catalog_error: str | None = None
        self.selected: set[str] = set()
        self.target: FwTarget | None = None
        self.installed: dict[str, tuple[InstalledPack, ...]] = {}  # target key -> packs (when known)
        self.space: dict[str, EspSpace] = {}  # target key -> its boot partition (when known)
        self.phase = FwPhase.IDLE
        self.request: FwRequest | None = None
        self.job: _FwJob | None = None
        self.outcome: FwOutcome | None = None
        self.final_log: list[LogLine] = []
        self.reload_catalog()

    # -- catalog ------------------------------------------------------------

    def reload_catalog(self) -> None:
        path = catalog_path(self.main.dist.path if self.main.dist_summary.ok else None)
        self.catalog, self.catalog_error = None, None
        if path is None:
            self.catalog_error = "The boot files were not found, so there is no firmware catalog."
            return
        if not path.is_file():
            self.catalog_error = ("Firmware packs are not available in this build: its boot files have no "
                                  f"network helper catalog ({CATALOG_REL}).")
            return
        try:
            self.catalog = load_catalog(path)
        except CatalogError as e:
            self.catalog_error = str(e)[:1].upper() + str(e)[1:] + "."
        self.selected &= {p.id for p in self.catalog.packs} if self.catalog else set()

    @property
    def available(self) -> bool:
        return self.catalog is not None and bool(self.catalog.packs)

    # -- selection ----------------------------------------------------------

    def set_selected(self, pack_id: str, on: bool) -> None:
        if self.phase is not FwPhase.IDLE:
            return
        if self.catalog is None or self.catalog.pack(pack_id) is None:
            raise BeastError(f"no such firmware pack: {pack_id}")
        (self.selected.add if on else self.selected.discard)(pack_id)

    @property
    def selected_packs(self) -> tuple[FwPack, ...]:
        if self.catalog is None:
            return ()
        return tuple(p for p in self.catalog.packs if p.id in self.selected)

    @property
    def download_size(self) -> int:
        return sum(p.size for p in self.selected_packs)

    # -- target -------------------------------------------------------------

    def target_choices(self) -> list[DriveRow]:
        return [r for r in self.main.rows if r.eligible]

    def set_target_drive(self, drive_id: str | None) -> None:
        if self.phase is not FwPhase.IDLE:
            return
        row = next((r for r in self.target_choices() if r.id == drive_id), None)
        self.target = FwTarget("device", row.id, row.disk) if row else None

    def set_target_image(self, path: str) -> None:
        if self.phase is not FwPhase.IDLE:
            return
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(path):
            raise BeastError(f"{path} is not a file")
        self.target = FwTarget("image", path)

    def sync_target(self) -> None:
        """After the drive list changed: drop a drive that is gone or changed."""
        t = self.target
        if t is None or t.kind != "device" or self.phase is FwPhase.RUNNING:
            return
        row = next((r for r in self.target_choices() if r.id == t.target), None)
        if row is None or row.disk != t.disk:
            if row is not None and (row.disk.size, row.disk.model) != (t.disk.size, t.disk.model):
                self._forget(t.key)  # another drive under the same name
            self.target = FwTarget("device", row.id, row.disk) if row else None

    @property
    def installed_on_target(self) -> tuple[InstalledPack, ...] | None:
        return self.installed.get(self.target.key) if self.target else None

    def is_installed(self, pack_id: str) -> bool:
        packs = self.installed_on_target
        return bool(packs) and any(p.id == pack_id for p in packs)

    def _remember(self, target: FwTarget, info) -> None:
        """What a list/install/remove run reported about the target (forgotten if it didn't say)."""
        packs, space = parse_installed(info), parse_space(info)
        if packs is not None:
            self.installed[target.key] = packs
        else:
            self.installed.pop(target.key, None)  # changed, and the CLI didn't say how: unknown now
        if space is not None:
            self.space[target.key] = space
        else:
            self.space.pop(target.key, None)

    def _forget(self, key: str) -> None:
        self.installed.pop(key, None)
        self.space.pop(key, None)

    # -- room on the boot partition ------------------------------------------

    @property
    def space_on_target(self) -> EspSpace | None:
        return self.space.get(self.target.key) if self.target else None

    def _space_for(self, target: FwTarget, packs: tuple[FwPack, ...]) -> FwSpace | None:
        sp = self.space.get(target.key)
        if sp is None:
            return None
        new = {p.id: fw_archive_size((f.path, f.size) for f in p.files) for p in packs}
        json_size = sp.json_size + sum(installed_entry_estimate(f.path for f in p.files) for p in packs)
        return fw_space(new, free=sp.free, cluster=sp.cluster, on_drive=sp.files, json_size=json_size,
                        label=sp.label)

    @property
    def space_check(self) -> FwSpace | None:
        """Room for the selected packs on the target's boot partition, when it is known
        (from the last list/install/remove of that target). Packs being re-installed
        count with the space their old copy frees."""
        return self._space_for(self.target, self.selected_packs) if self.target else None

    def space_text(self) -> str | None:
        """The live "Selected: X of Y free" line (None while the free space is unknown)."""
        sp, s = self.space_on_target, self.space_check
        if sp is None or s is None:
            return None
        if not self.selected:
            return f"{human_size(sp.free)} free on {sp.label}."
        text = f"Selected: {human_size(s.need)} of {human_size(s.available)} free on {sp.label}"
        if s.reclaimed and any(self.is_installed(p.id) for p in self.selected_packs):
            text += f" (with {human_size(s.reclaimed)} freed by replacing installed packs)"
        return text + "."

    @staticmethod
    def no_room_text(s: FwSpace) -> str:
        need, avail = human_size(s.need), human_size(s.available)
        short = f" ({human_size(s.need - s.available)} too little)" if need == avail else ""
        return (f"Needs {need}, {avail} free on {s.label or ESP_LABEL}{short}. "
                "Deselect packs or remove installed ones.")

    # -- what can be started ------------------------------------------------

    def _common_blocker(self) -> str | None:
        if self.phase is not FwPhase.IDLE or self.main.phase is not Phase.IDLE:
            return "Busy."
        if not self.available:
            return self.catalog_error or "No firmware packs in this build."
        if self.target is None:
            return "Choose the beast-booter drive or image first."
        return None

    def install_blocker(self) -> str | None:
        if p := self._common_blocker():
            return p
        if not self.selected:
            return "Select the packs to install."
        s = self.space_check
        if s is not None and not s.fits:
            return self.no_room_text(s)
        return None

    def list_blocker(self) -> str | None:
        p = self._common_blocker()
        return None if p == "Select the packs to install." else p

    # -- confirmation -------------------------------------------------------

    def _require(self, *phases: FwPhase) -> None:
        if self.phase not in phases:
            raise BeastError(f"not possible while {self.phase.value}")

    @staticmethod
    def _unmount_note(t: FwTarget) -> tuple[str, ...]:
        if t.disk is None or not t.disk.mountpoints:
            return ()
        return ("Its volumes are unmounted first: " + ", ".join(t.disk.mountpoints)
                + ". Close any program that uses them.",)

    def _rights_note(self, t: FwTarget, *, check_first: bool = False) -> str:
        if t.kind == "device" and check_first and not self.main.backend().is_elevated():
            return ("Your system will ask for administrator rights twice: first to check the free space on the "
                    "drive, before anything is downloaded, then to write to it.")
        if t.kind == "device":
            return "Your system will ask for administrator rights to write to the drive."
        return "No administrator rights are needed for an image file."

    def request_install(self) -> FwRequest:
        self._require(FwPhase.IDLE)
        if blocker := self.install_blocker():
            raise BeastError(blocker)
        assert self.catalog is not None and self.target is not None
        packs, cat = self.selected_packs, self.catalog
        lics = sorted({lic.rstrip(". ") for p in packs for lic in p.licenses})
        details = (
            f"{CLOSED_SOURCE}, downloaded from {cat.host} ({cat.source_name}, tag {cat.tag}): "
            f"{sum(len(p.files) for p in packs)} files, {human_size(sum(p.size for p in packs))}.",
            "Every file is checked against the SHA-256 in the catalog; a file that doesn't match is discarded "
            "and nothing is installed.",
            "Licences: " + ("; ".join(lics) if lics else "see the pack details") + ".",
            "Only the network helper's firmware folder on the boot partition changes. Your ISO files are "
            "not touched.",
            *self._unmount_note(self.target),
            self._rights_note(self.target, check_first=self.space_on_target is None),
        )
        names = ", ".join(p.title for p in packs)
        req = FwRequest("install", self.target, packs, f"Install {names}?", details, "Download and install")
        self.request, self.phase = req, FwPhase.CONFIRMING
        return req

    def request_remove(self, pack_id: str) -> FwRequest:
        self._require(FwPhase.IDLE)
        if blocker := self.list_blocker():
            raise BeastError(blocker)
        assert self.catalog is not None and self.target is not None
        if not self.is_installed(pack_id):
            raise BeastError(f"{pack_id} is not installed on {self.target.short}")
        pack = self.catalog.pack(pack_id) or FwPack(pack_id, pack_id, "", (), (), 0, ())
        details = (
            f"The {pack.title} firmware is removed from the network helper on this drive. Adapters that need it "
            "won't work there until you install it again.",
            *self._unmount_note(self.target),
            self._rights_note(self.target),
        )
        req = FwRequest("remove", self.target, (pack,), f"Remove {pack.title}?", details, "Remove", danger=True)
        self.request, self.phase = req, FwPhase.CONFIRMING
        return req

    def cancel_request(self) -> None:
        self._require(FwPhase.CONFIRMING)
        self.request, self.phase = None, FwPhase.IDLE

    def confirm(self) -> None:
        self._require(FwPhase.CONFIRMING)
        req = self.request
        assert req is not None
        self.request = None
        self.phase = FwPhase.IDLE
        if req.target.kind == "device":
            assert req.target.disk is not None
            self.main.recheck_disk(req.target.disk)  # raises: nothing started
        if req.action == "install":  # check the free space first when it isn't known
            self._start("fetch" if req.target.key in self.space else "check", "install", req.target, req.packs)
        else:
            self._start("remove", "remove", req.target, req.packs)

    def refresh_installed(self) -> None:
        """Read installed.json from the target (asks for administrator rights for a drive)."""
        self._require(FwPhase.IDLE)
        if blocker := self.list_blocker():
            raise BeastError(blocker)
        assert self.target is not None
        if self.target.kind == "device":
            assert self.target.disk is not None
            self.main.recheck_disk(self.target.disk)
        self._start("list", "list", self.target, ())

    # -- running ------------------------------------------------------------

    def _launch(self, job_stage: str, action: str, target: FwTarget, packs: tuple[FwPack, ...], tmp: str,
                log: list[LogLine]) -> None:
        progress_file = os.path.join(tmp, f"{job_stage}.jsonl")
        open(progress_file, "x").close()  # ours, even when an elevated CLI appends to it
        state = ProgressState(log=log)
        main = self.main
        ids = tuple(p.id for p in packs)
        assert self.catalog is not None
        common = dict(python=main.python, launcher=main.launcher, progress_file=progress_file)
        if job_stage == "fetch":
            argv = build_fw_argv("fetch", packs=ids, out_dir=os.path.join(tmp, "packs"),
                                 catalog=str(self.catalog.path), **common)
            os.mkdir(os.path.join(tmp, "packs"), 0o700)
        elif job_stage == "install":
            argv = build_fw_argv("install", target=target, from_dir=os.path.join(tmp, "packs"), **common)
        elif job_stage == "remove":
            argv = build_fw_argv("remove", target=target, packs=ids, **common)
        else:
            argv = build_fw_argv("list", target=target, **common)
        if not os.path.isfile(main.launcher):
            raise BeastError(f"{main.launcher} is missing; the beast-booter folder is incomplete")
        # Downloading never needs rights; writing to (or reading) a drive does.
        elevated = job_stage != "fetch" and target.kind == "device" and not main.backend().is_elevated()
        state.note("running: " + " ".join(_quote(a) for a in argv), "debug")
        if elevated:
            state.note("asking for administrator rights")
            proc = main.backend().run_elevated(argv)
        else:
            proc = LocalProcess(argv, os.path.join(tmp, f"{job_stage}-output.txt"))
        self.job = _FwJob(job_stage, action, target, packs, argv, proc, ProgressReader(progress_file), state,
                          tmp, elevated, self._clock(), log)
        self.phase = FwPhase.RUNNING

    def _start(self, stage: str, action: str, target: FwTarget, packs: tuple[FwPack, ...]) -> None:
        tmp = tempfile.mkdtemp(prefix="beast-booter-fw-", dir=self.main._tmp_root)
        self.outcome, self.final_log = None, []
        log: list[LogLine] = []
        try:
            self._launch(stage, action, target, packs, tmp, log)
        except Exception as e:  # noqa: BLE001 - shown in the window
            shutil.rmtree(tmp, ignore_errors=True)
            log.append(LogLine("error", _error_text(e)))
            self._fail(action, target, _error_text(e), "start-failed", None, (), log)

    @property
    def progress(self) -> ProgressState | None:
        return self.job.state if self.job else None

    @property
    def log(self) -> list[LogLine]:
        return self.job.log if self.job else self.final_log

    @property
    def overall_pct(self) -> float:
        job = self.job
        if job is None:
            return 100.0 if self.outcome and self.outcome.ok else 0.0
        lo, hi = self.STAGES[job.stage]
        return 100 * lo + (hi - lo) * job.state.pct

    def stage_text(self) -> str:
        job = self.job
        if job is None:
            return ""
        if job.stage == "check":
            return f"Checking the free space on {job.target.short}"
        if job.stage == "fetch":
            return f"Step 1 of 2: downloading from {self.catalog.host if self.catalog else 'linux-firmware'}"
        if job.stage == "install":
            return f"Step 2 of 2: writing to {job.target.short}"
        if job.stage == "remove":
            return f"Removing from {job.target.short}"
        return f"Reading the installed packs on {job.target.short}"

    def poll(self) -> bool:
        job = self.job
        if self.phase is not FwPhase.RUNNING or job is None:
            return False
        events = job.reader.read_new()
        for ev in events:
            job.state.apply(ev)
        try:
            rc = job.proc.poll()
        except Exception as e:  # noqa: BLE001
            job.state.note(f"lost track of the installer process: {_error_text(e)}", "error")
            rc = -1
        if rc is None:
            return bool(events)
        for ev in job.reader.finish():
            job.state.apply(ev)
        self._stage_done(job, rc)
        return True

    def _stage_done(self, job: _FwJob, rc: int) -> None:
        st = job.state
        tail: tuple[str, ...] = ()
        output_tail = getattr(job.proc, "output_tail", None)
        if callable(output_tail) and rc != 0:
            tail = tuple(output_tail())
            for line in tail:
                st.note(f"output: {line}", "debug")
        st.note(f"installer exited with code {rc}", "debug" if rc == 0 else "error")
        ok = rc == 0 and st.error_code is None and (st.done_ok or not st.done_seen)
        if ok and job.stage == "check":
            self._remember(job.target, st.done_info)
            space = self._space_for(job.target, job.packs)
            if space is not None and not space.fits:
                self._finish(job, FwOutcome(False, job.action, "Not enough space on the drive",
                                            self.no_room_text(space) + " Nothing was downloaded.", job.target,
                                            "no-space", rc))
                return
            try:
                self._launch("fetch", job.action, job.target, job.packs, job.tmpdir, job.log)
            except Exception as e:  # noqa: BLE001
                job.log.append(LogLine("error", _error_text(e)))
                self._finish_fail(job, rc, _error_text(e), "start-failed", tail)
            return
        if ok and job.stage == "fetch":
            missing = [p.id for p in job.packs
                       if not os.path.isfile(os.path.join(job.tmpdir, "packs", f"{p.id}.cpio"))]
            if missing:
                self._finish_fail(job, rc, "The download finished, but these packs are missing: "
                                  + ", ".join(missing) + ". Nothing was installed.", "fetch-incomplete", tail)
                return
            if job.cancel_requested:
                self._finish_fail(job, rc, "You stopped it after the download. Nothing was installed.",
                                  "cancelled", tail, cancelled=True)
                return
            try:  # the drive may have been swapped during the download
                if job.target.kind == "device":
                    assert job.target.disk is not None
                    self.main.recheck_disk(job.target.disk)
                self._launch("install", job.action, job.target, job.packs, job.tmpdir, job.log)
            except Exception as e:  # noqa: BLE001
                job.log.append(LogLine("error", _error_text(e)))
                self._finish_fail(job, rc, _error_text(e), "start-failed", tail)
            return
        if ok:
            self._remember(job.target, st.done_info)
            self._finish(job, FwOutcome(True, job.action, *self._ok_texts(job), job.target, exit_code=rc))
            return
        cancelled = job.cancel_requested and st.error_code in (None, "cancelled", "interrupted")
        if cancelled:
            msg, code = "You stopped it.", "cancelled"
        elif st.error_code is not None:
            msg, code = st.error_message or "", st.error_code
        elif not st.started and job.elevated and rc == ELEVATION_CANCELLED:
            msg, code, cancelled = "The administrator prompt was cancelled.", "elevation-cancelled", True
        elif not st.started and job.elevated and rc == ELEVATION_FAILED:
            msg, code = ("Administrator rights could not be obtained: this account is not allowed, or the "
                         "system has no way to ask (on Linux: no polkit agent running)."), "elevation-failed"
        elif not st.started:
            msg, code = f"The firmware command did not start (exit code {rc}).", "not-started"
        else:
            msg, code = f"The firmware command stopped unexpectedly (exit code {rc}).", f"exit-{rc}"
        self._finish_fail(job, rc, msg, code, tail, cancelled=cancelled)

    def _ok_texts(self, job: _FwJob) -> tuple[str, str]:
        names = ", ".join(p.title for p in job.packs)
        if job.action == "install":
            return "Firmware installed", (f"{names} {'is' if len(job.packs) == 1 else 'are'} now on "
                                          f"{job.target.text}. The network helper loads "
                                          f"{'it' if len(job.packs) == 1 else 'them'} at its next start.")
        if job.action == "remove":
            return "Firmware removed", f"{names} was removed from {job.target.text}."
        return "Installed packs read", f"Read the installed firmware packs of {job.target.text}."

    def _fail_title(self, action: str) -> str:
        return {"install": "Installing the firmware failed", "remove": "Removing the firmware failed"}.get(
            action, "Reading the installed packs failed")

    def _finish_fail(self, job: _FwJob, rc: int, msg: str, code: str, tail, *, cancelled: bool = False) -> None:
        if hint := CODE_HINTS.get(code):
            msg = f"{msg.rstrip()} {hint}" if msg else hint
        if job.stage == "install" and "write-firmware" in job.state.steps_seen and not cancelled:
            msg += " The packs that were on the drive before may be incomplete now; install them again."
        title = "Stopped" if cancelled else self._fail_title(job.action)
        self._finish(job, FwOutcome(False, job.action, title, msg, job.target, code, rc, tuple(tail), cancelled))

    def _finish(self, job: _FwJob, outcome: FwOutcome) -> None:
        self.outcome, self.final_log = outcome, job.log
        self.phase = FwPhase.DONE if outcome.ok else FwPhase.FAILED
        self.job = None
        shutil.rmtree(job.tmpdir, ignore_errors=True)  # downloaded packs and progress files

    def _fail(self, action, target, msg, code, rc, tail, log) -> None:
        self.final_log = log
        self.outcome = FwOutcome(False, action, self._fail_title(action), msg, target, code, rc, tuple(tail))
        self.phase = FwPhase.FAILED

    @property
    def can_cancel(self) -> bool:
        """Downloads run without rights and stop by signal; an elevated write can't be
        reached from here (the firmware commands have no --cancel-file) and is short."""
        job = self.job
        return bool(job and self.phase is FwPhase.RUNNING and not job.elevated and not job.cancel_requested)

    def cancel(self) -> None:
        self._require(FwPhase.RUNNING)
        job = self.job
        assert job is not None
        if not self.can_cancel:
            raise BeastError("This step runs with administrator rights and can't be stopped from the window. "
                             "It takes only a moment.")
        job.cancel_requested = True
        job.state.note("stop requested", "warning")
        try:
            job.proc.cancel()
        except Exception as e:  # noqa: BLE001
            job.state.note(f"could not stop it: {_error_text(e)}", "error")

    def dismiss(self) -> None:
        self._require(FwPhase.DONE, FwPhase.FAILED)
        if self.outcome is not None and self.outcome.ok and self.outcome.action == "install":
            self.selected.clear()
        self.phase, self.outcome = FwPhase.IDLE, None

    def shutdown(self) -> None:
        if self.can_cancel:
            self.cancel()
