"""Everything the GUI decides, with no GUI toolkit involved.

The window (app.py) only displays this controller's state and forwards
clicks to it, so all the logic that matters here can be unit-tested without
a display: which drives may be written, option validation, the exact command
line the CLI is started with, following its progress, cancelling, and the
state machine

    IDLE --request_install/update--> CONFIRMING --confirm--> RUNNING --> DONE
      ^           (start_image goes straight to RUNNING)         \\--> FAILED
      +------------- cancel_confirm / dismiss ----------------------------+

Privilege separation: the GUI never runs as administrator. Listing drives
happens in-process through the PlatformBackend (no rights needed). Writing
to a drive starts the CLI with administrator rights through
backend.run_elevated() and follows the JSON-lines progress file it writes.
Image files need no rights, so the CLI runs as a normal child process.
"""

from __future__ import annotations

import dataclasses
import enum
import inspect
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import BeastError
from ..fs import normalize_label
from ..installed import NEWER, OTHER_BUILD, REINSTALL, Freshness, ProbeResult, assess
from ..interfaces import DiskInfo, ElevatedProcess, PlatformBackend
from ..layout import (
    DATA_LABEL_DEFAULT,
    DEFAULT_FS,
    DEFAULT_LAYOUT,
    ESP_LABEL,
    ESP_SIZE_MIB,
    FILESYSTEMS,
    LAYOUTS,
    MIB,
    MIN_DISK_MIB,
)
from ..util import human_size, parse_size
from . import distinfo
from .localproc import LocalProcess
from .progress import LogLine, ProgressReader, ProgressState

CERT_FILE = distinfo.CERT_FILE

# Exit codes of an ElevatedProcess whose elevation did not happen (the CLI never
# ran). Same values as platforms/common.py; kept here so the GUI works without
# importing the platforms package.
ELEVATION_CANCELLED = 126  # the user dismissed the password / UAC prompt
ELEVATION_FAILED = 127  # not authorized, or no way to ask (no polkit agent, ...)

# Whether the CLI accepts `--cancel-file PATH`: between steps it checks whether
# PATH exists and, if it does, stops with an "error" event of code "cancelled".
# That is the only dependable way to stop an *elevated* CLI: it runs as root or
# with an elevated token, so this unprivileged window can't signal it (Linux:
# pkexec's child is root, kill() fails with EPERM; macOS: terminating osascript
# leaves its root child running; Windows: TerminateProcess may be refused).
# The CLI has it (checked between steps and during the boot-partition copy).
# With it off, an elevated run can't be stopped from the window, and the window
# says so instead of pretending. Runs without elevation (image files) are also
# stopped with a signal.
CLI_HAS_CANCEL_FILE = True

CANNOT_STOP = ("The installer runs with administrator rights, so this window can't stop it. "
               "It finishes on its own; don't unplug the drive until it has.")


class Phase(enum.Enum):
    IDLE = "idle"
    CONFIRMING = "confirming"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class StateError(BeastError):
    """An action that is not possible right now (e.g. Install while already running)."""


# ---------------------------------------------------------------------------
# Drives
# ---------------------------------------------------------------------------

BUS_NAMES = {
    "usb": "USB", "sata": "SATA", "nvme": "NVMe", "sd": "SD card", "scsi": "SCSI",
    "virtual": "Virtual", "unknown": "Unknown",
}


# External buses: a disk here is a USB stick/SSD/HDD or a card, never the
# machine's own internal disk (the platform backends use the same rule).
EXTERNAL_BUSES = ("usb", "sd")


def drive_problem(d: DiskInfo) -> str | None:
    """Why the GUI will not write to this disk (a few words), or None if it may.

    Same rules as the CLI without --allow-fixed-disk: disks on the USB or SD
    bus are eligible even when they report themselves as fixed (many USB SSDs
    and hard disks do); internal disks never are, and the GUI cannot override that.
    """
    if d.system:
        return "holds the running system"
    if d.read_only:
        return "write-protected"
    if not d.removable and d.bus not in EXTERNAL_BUSES:
        return "internal disk"
    if d.size <= 0:
        return "no medium"
    if d.size < MIN_DISK_MIB * MIB:
        return f"too small (min. {MIN_DISK_MIB} MiB)"
    return None


PROBLEM_DETAILS = {
    "holds the running system": "It holds the running operating system (or its boot or swap space).",
    "write-protected": "It is write-protected. Check for a lock switch on the drive or card.",
    "internal disk": "It is an internal disk. beast-booter only writes to removable drives.",
    "no medium": "There is no medium in it (an empty card reader?).",
}


def problem_detail(problem: str) -> str:
    if problem.startswith("too small"):
        return f"It is smaller than the {MIN_DISK_MIB} MiB beast-booter needs."
    return PROBLEM_DETAILS.get(problem, problem)


@dataclass(frozen=True)
class DriveRow:
    disk: DiskInfo
    problem: str | None
    # Which beast-booter the drive has, compared with this app's boot files
    # (installed.assess); None: not a beast-booter drive, or not checked (yet).
    freshness: Freshness | None = None
    probe: ProbeResult | None = None  # what backend.probe_installed said (firmware packs: probe.installed.firmware)

    @property
    def id(self) -> str:
        return self.disk.id

    @property
    def eligible(self) -> bool:
        return self.problem is None

    @property
    def title(self) -> str:
        return self.disk.model.strip() or "Unknown drive"

    @property
    def size_text(self) -> str:
        return human_size(self.disk.size) if self.disk.size > 0 else "-"

    @property
    def bus_text(self) -> str:
        return BUS_NAMES.get(self.disk.bus, self.disk.bus or "Unknown")

    @property
    def notes(self) -> str:
        if self.problem:
            return f"Not usable: {self.problem}"
        if self.disk.mountpoints:
            return "In use: " + ", ".join(self.disk.mountpoints)
        return ""

    def describe(self) -> str:
        return f"{self.title} ({self.size_text}, {self.bus_text}, {self.id})"


def drive_rows(disks: list[DiskInfo], *, show_all: bool) -> list[DriveRow]:
    """Rows for the drive list: usable drives first. Without show_all, only
    removable non-system disks are listed, whatever the backend returned."""
    rows = [DriveRow(d, drive_problem(d)) for d in disks]
    if not show_all:
        rows = [r for r in rows if (r.disk.removable or r.disk.bus in EXTERNAL_BUSES) and not r.disk.system]
    # Usable first, virtual devices (loop, snaps, ...) last; otherwise the backend's order.
    return sorted(rows, key=lambda r: (not r.eligible, r.disk.bus == "virtual"))


@dataclass(frozen=True)
class UpdateNotice:
    """Shown above the drive list when listed drives have older (or other) boot files."""

    title: str
    text: str
    drive_id: str | None  # the one drive it is about, None when it names several
    short: str = ""  # one line, for a short window


def _probe(probe: Callable[..., ProbeResult | None], disk: DiskInfo, kw: dict) -> tuple[str, ProbeResult | None]:
    try:
        return disk.id, probe(disk, **kw)
    except Exception:  # noqa: BLE001 - probes never raise; if one does, the drive just gets no badge
        return disk.id, None


def _takes_should_stop(fn: Callable) -> bool:
    """probe_installed(disk, *, should_stop=None): backends and test fakes without it exist."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "should_stop" or p.kind is p.VAR_KEYWORD for p in params)


# A job that writes to a drive does not start while a drive check runs (it may have
# the boot partition mounted read-only for a moment). The check stops before its
# next drive once a job is requested, so this limit only covers one stuck drive.
PROBE_LIMIT = 120.0
PROBE_BUSY = ("A check of the drives is still running, so nothing was started: writing while it may have "
              "the drive's boot partition mounted is not safe. Unplug the drive, plug it in again, then try again.")


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

LAYOUT_TEXT = {"msdos": "MBR", "gpt": "GPT"}
FS_TEXT = {"exfat": "exFAT", "fat32": "FAT32", "ntfs": "NTFS"}
LAYOUT_NOTES = {
    "msdos": "MBR boots on the widest range of computers, with BIOS and with UEFI.",
    "gpt": "GPT also boots with BIOS and UEFI; choose it if your computer or tools require GPT.",
}
FS_NOTES = {
    "exfat": "exFAT works with Secure Boot on and off and holds files larger than 4 GiB.",
    "fat32": "FAT32 is readable everywhere, but cannot hold files larger than 4 GiB (many ISOs are).",
    "ntfs": "NTFS can't be read while Secure Boot is on: the menu shows no ISOs then. "
            "Use it only on computers with Secure Boot off or with BIOS.",
}


@dataclass(frozen=True)
class Options:
    layout: str = DEFAULT_LAYOUT
    fs: str = DEFAULT_FS
    label: str = DATA_LABEL_DEFAULT


@dataclass(frozen=True)
class OptionsCheck:
    label: str  # the label as it will be written ("" while invalid)
    errors: dict[str, str] = field(default_factory=dict)  # field -> problem
    notes: dict[str, str] = field(default_factory=dict)  # field -> explanation

    @property
    def ok(self) -> bool:
        return not self.errors


def ntfs_supported(platform: str) -> bool:
    return platform != "darwin"  # macOS has no NTFS formatter


def check_options(opts: Options, platform: str) -> OptionsCheck:
    errors: dict[str, str] = {}
    notes: dict[str, str] = {}
    if opts.layout in LAYOUTS:
        notes["layout"] = LAYOUT_NOTES[opts.layout]
    else:
        errors["layout"] = f"unknown partition table {opts.layout!r}"
    label = ""
    if opts.fs not in FILESYSTEMS:
        errors["fs"] = f"unknown file system {opts.fs!r}"
    else:
        notes["fs"] = FS_NOTES[opts.fs]
        if opts.fs == "ntfs" and not ntfs_supported(platform):
            errors["fs"] = "NTFS is not available on macOS (macOS cannot create NTFS file systems)."
        if not opts.label:
            errors["label"] = "Enter a volume label."
        else:
            try:
                label = normalize_label(opts.label, opts.fs)  # the CLI's own rules
            except BeastError as e:
                errors["label"] = _capitalize(str(e)) + "."
            else:
                if label != opts.label:
                    notes["label"] = f"Will be written as {label} ({FS_TEXT[opts.fs]} labels are upper case)."
    return OptionsCheck(label, errors, notes)


def _capitalize(s: str) -> str:
    return s[:1].upper() + s[1:]


IMAGE_SIZES = ("1G", "2G", "4G", "8G", "16G", "32G", "64G")
DEFAULT_IMAGE_SIZE = "4G"


def check_image_size(text: str) -> int:
    """Image size in bytes from '4G', '512M', a byte count, ... (the CLI's --size syntax)."""
    size = parse_size(text.strip())
    if size < MIN_DISK_MIB * MIB:
        raise BeastError(f"the image must be at least {MIN_DISK_MIB} MiB")
    return size


# ---------------------------------------------------------------------------
# The CLI command line
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JobSpec:
    action: str  # "install" | "update"
    kind: str  # "device" | "image"
    target: str  # device id (DiskInfo.id) or absolute image path
    disk: DiskInfo | None = None
    options: Options | None = None  # install only; label already normalized
    image_size: int | None = None  # install --image only

    @property
    def target_text(self) -> str:
        if self.disk is not None:
            return DriveRow(self.disk, None).describe()
        return self.target


def build_cli_argv(spec: JobSpec, *, python: str, launcher: str, progress_file: str, dist: str,
                   cancel_file: str | None = None) -> list[str]:
    """The exact command line the CLI runs with. A list, never a shell string.

    `-s -E`: ignore user site-packages and PYTHON* variables, so the elevated
    interpreter runs only the code shipped next to the launcher. `-B`: write no
    .pyc files; the CLI often runs as root/Administrator and would otherwise
    leave root-owned __pycache__ folders in the user's portable package (which
    must stay exactly as unpacked, see docs/PORTABLE.md). Every path is
    absolute because elevation may start the process in another directory.
    """
    paths = [("python", python), ("launcher", launcher), ("progress file", progress_file), ("dist", dist)]
    if cancel_file is not None:
        paths.append(("cancel file", cancel_file))
    for what, p in paths:
        if not p or not os.path.isabs(p):
            raise BeastError(f"internal error: {what} path must be absolute, got {p!r}")
    if spec.action not in ("install", "update") or spec.kind not in ("device", "image"):
        raise BeastError(f"internal error: bad job {spec.action}/{spec.kind}")
    argv = [python, "-s", "-E", "-B", launcher, spec.action]
    if spec.kind == "device":
        argv += ["--device", spec.target]
    else:
        if not os.path.isabs(spec.target):
            raise BeastError(f"internal error: image path must be absolute, got {spec.target!r}")
        argv += ["--image", spec.target]
        if spec.action == "install":
            if not spec.image_size:
                raise BeastError("internal error: install --image needs a size")
            argv += ["--size", str(spec.image_size)]
    argv += ["--yes", "--progress-file", progress_file]
    if cancel_file is not None:
        argv += ["--cancel-file", cancel_file]
    argv += ["--dist", dist]
    if spec.action == "install":
        if spec.options is None:
            raise BeastError("internal error: install needs options")
        o = spec.options
        # "--label=VALUE" in one argument: a label may legally start with "-".
        argv += ["--layout", o.layout, "--fs", o.fs, f"--label={o.label}"]
    return argv


# ---------------------------------------------------------------------------
# Confirmation and results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfirmRequest:
    spec: JobSpec
    needs_ack: bool  # the "I understand ..." checkbox must be ticked
    title: str
    drive: str  # model, size, bus, id
    details: tuple[str, ...]
    ack_text: str
    confirm_label: str


ACK_TEXT = "I understand all data on it will be erased"


@dataclass(frozen=True)
class Outcome:
    ok: bool
    spec: JobSpec
    title: str
    message: str
    code: str | None = None  # the CLI's error code, "cancelled", "exit-N", ...
    exit_code: int | None = None
    info: dict | None = None  # the "done" event's info (same as `info --json`)
    cancelled: bool = False
    target_state: str = ""  # failures: what state the drive / image is in now
    output_tail: tuple[str, ...] = ()  # failures: the CLI's last output lines, when they can be read


@dataclass
class _Job:
    spec: JobSpec
    argv: list[str]
    proc: ElevatedProcess | None  # None while it waits for a drive check to finish
    reader: ProgressReader
    state: ProgressState
    tmpdir: str
    elevated: bool
    started_at: float
    cancel_path: str | None = None  # the --cancel-file; creating it asks the CLI to stop
    cancel_requested: bool = False


class _Task:
    """A function run off the GUI thread; its result is picked up by Controller.poll()."""

    def __init__(self, fn: Callable, done: Callable):
        self.fn, self.done = fn, done
        self.result = None
        self.error: BaseException | None = None
        self.finished = threading.Event()

    def run(self) -> None:
        try:
            self.result = self.fn()
        except BaseException as e:  # noqa: BLE001 - reported in the GUI, not swallowed
            self.error = e
        finally:
            self.finished.set()


def thread_spawn(task: _Task) -> None:
    threading.Thread(target=task.run, name="beast-booter-gui", daemon=True).start()


def inline_spawn(task: _Task) -> None:
    """For tests: run background work immediately."""
    task.run()


def _default_backend() -> PlatformBackend:
    # Imported lazily: the platforms package may be unavailable (or broken) on
    # some system, and creating image files must still work then.
    from ..platforms import get_backend

    return get_backend()


def _platform_from_sys() -> str:
    return {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")


def _error_text(e: BaseException) -> str:
    if isinstance(e, BeastError):
        return str(e)
    if isinstance(e, OSError):
        return f"{e.strerror or e}" + (f": {e.filename}" if e.filename else "")
    return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# The controller
# ---------------------------------------------------------------------------


class Controller:
    def __init__(
        self,
        *,
        backend_factory: Callable[[], PlatformBackend] | None = None,
        dist: distinfo.DistLocation | None = None,
        python: str | None = None,
        launcher: str | os.PathLike | None = None,
        spawn: Callable[[_Task], None] = thread_spawn,
        tmp_root: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        cancel_file: bool = CLI_HAS_CANCEL_FILE,
    ):
        self._backend_factory = backend_factory or _default_backend
        self._backend: PlatformBackend | None = None
        self.backend_error: str | None = None
        python = python or sys.executable  # may be "" in an embedded interpreter: build_cli_argv refuses it
        self.python = os.path.abspath(python) if python else ""
        self.launcher = os.path.abspath(launcher or distinfo.launcher_path())
        self.dist = dist or distinfo.find_dist(None)
        self.dist_summary = distinfo.read_summary(self.dist)
        self.verify_result: distinfo.VerifyResult | None = None
        self.verifying = False
        self._spawn = spawn
        self._tmp_root = tmp_root
        self._clock = clock
        self._cancel_file = cancel_file  # pass --cancel-file to the CLI (see CLI_HAS_CANCEL_FILE)
        self._tasks: list[_Task] = []

        self.phase = Phase.IDLE
        self.options = Options()
        self.show_all = False
        self.rows: list[DriveRow] = []
        self.rows_version = 0  # bumped whenever `rows` is replaced
        self.loading = False
        self.list_error: str | None = None
        self._list_gen = 0
        self.selected_id: str | None = None
        # Which beast-booter the listed drives have (backend.probe_installed, in a worker thread)
        self.probing = False
        self._probe_pending = False  # the rows still need a check (deferred while a job runs)
        self._probe_gen = 0  # bumped when the rows' results would be stale
        self._probe_task: _Task | None = None
        self._probe_cancel: threading.Event | None = None
        self.confirm_request: ConfirmRequest | None = None
        self.job: _Job | None = None
        self.outcome: Outcome | None = None
        self.final_log: list[LogLine] = []
        # Set by firmware.FirmwareController: a firmware job is running (installs wait).
        self.other_job_running: Callable[[], bool] = lambda: False
        # Set by FirmwareController: install/update ran on this drive (its packs may be gone).
        self.drive_written: Callable[[str], None] = lambda drive_id: None

    # -- backend ------------------------------------------------------------

    def backend(self) -> PlatformBackend:
        if self._backend is None:
            if self.backend_error is None:
                try:
                    self._backend = self._backend_factory()
                except Exception as e:  # noqa: BLE001 - shown in the window
                    self.backend_error = f"Drive access is not available on this system: {_error_text(e)}"
            if self._backend is None:
                raise BeastError(self.backend_error or "no backend")
        return self._backend

    @property
    def platform(self) -> str:
        if self._backend is not None:
            return self._backend.name
        return _platform_from_sys()

    # -- background work ----------------------------------------------------

    def _start_task(self, fn: Callable, done: Callable) -> _Task:
        task = _Task(fn, done)
        self._tasks.append(task)
        self._spawn(task)
        return task

    def _poll_tasks(self) -> bool:
        finished = [t for t in self._tasks if t.finished.is_set()]
        for t in finished:
            self._tasks.remove(t)
            t.done(t.result, t.error)
        return bool(finished)

    def busy(self) -> bool:
        """Background work or a CLI run in progress (for tests and shutdown)."""
        return bool(self._tasks) or self.phase is Phase.RUNNING

    # -- drive list ---------------------------------------------------------

    def refresh_drives(self) -> None:
        try:
            backend = self.backend()
        except BeastError as e:
            self.list_error = str(e)
            self.loading = False
            return
        self._list_gen += 1
        gen, include_fixed = self._list_gen, self.show_all
        self.loading = True
        self._start_task(lambda: backend.list_disks(include_fixed=include_fixed),
                         lambda res, err: self._on_list(gen, res, err))

    def _on_list(self, gen: int, disks, err) -> None:
        if gen != self._list_gen:
            return  # a newer refresh is running (e.g. "show all" was toggled)
        self.loading = False
        if err is not None:
            self.list_error = f"Could not list drives: {_error_text(err)}"
            disks = []
        else:
            self.list_error = None
        old = {r.id: r for r in self.rows}
        rows = drive_rows(list(disks), show_all=self.show_all)
        # Keep what the last check found until the new one is done (no badge flicker on Refresh)
        self.rows = [dataclasses.replace(r, freshness=o.freshness, probe=o.probe)
                     if (o := old.get(r.id)) is not None and o.disk == r.disk and r.eligible else r for r in rows]
        self.rows_version += 1
        self._probe_gen += 1
        self._probe_pending = True
        self._start_probe()
        current = self.selected_row
        if current is None or not current.eligible:
            self.selected_id = None
            usable = [r for r in self.rows if r.eligible]
            if len(usable) == 1:  # one candidate: preselect it (the confirmation names it)
                self.selected_id = usable[0].id

    # -- which beast-booter the drives have ----------------------------------

    def _start_probe(self) -> None:
        """Check the usable drives for beast-booter boot files, in a worker thread.
        Never while an install, update or firmware job runs (poll() retries later)."""
        if not self._probe_pending or self.probing or self.phase is Phase.RUNNING or self.other_job_running():
            return
        self._probe_pending = False
        probe = getattr(self._backend, "probe_installed", None)  # test fakes may not have it
        disks = [r.disk for r in self.rows if r.eligible]
        if probe is None or not disks or not self.dist_summary.version:
            return
        gen, cancel = self._probe_gen, threading.Event()
        # The probe also asks before it mounts anything (should_stop)
        kw = {"should_stop": cancel.is_set} if _takes_should_stop(probe) else {}

        def check() -> list:
            found = []
            for d in disks:
                if cancel.is_set():  # a job was requested: not one more drive
                    break
                found.append(_probe(probe, d, kw))
            return found

        self.probing, self._probe_cancel = True, cancel
        self._probe_task = self._start_task(check, lambda res, err: self._on_probed(gen, res, err))

    def _on_probed(self, gen: int, results, err) -> None:
        self.probing, self._probe_task, self._probe_cancel = False, None, None
        if gen == self._probe_gen and err is None:
            found = dict(results)
            rows = [dataclasses.replace(r, probe=found[r.id], freshness=self.freshness_of(found[r.id]))
                    if r.id in found else r for r in self.rows]
            if rows != self.rows:
                self.rows = rows
                self.rows_version += 1
        self._start_probe()  # the rows changed while this check ran

    def probe_busy(self) -> bool:
        """The check's thread is still running (it may have a boot partition mounted)."""
        return self._probe_task is not None and not self._probe_task.finished.is_set()

    def hold_probes(self) -> None:
        """A job that uses a drive was requested: a running check stops before its next
        drive (it runs again later), and no new one starts until the job is over."""
        if self.probe_busy() and self._probe_cancel is not None:
            self._probe_cancel.set()
            self._probe_pending = True

    @property
    def checking(self) -> bool:
        """A drive check is running or will run as soon as it may."""
        return self.probing or self._probe_pending

    @property
    def waiting_for_probe(self) -> bool:
        return self.phase is Phase.RUNNING and self.job is not None and self.job.proc is None

    def freshness_of(self, result: ProbeResult | None) -> Freshness | None:
        if result is None or not self.dist_summary.version:
            return None
        return assess(result.installed, self.dist_summary.version, self.dist_summary.build_id)

    @property
    def update_notice(self) -> UpdateNotice | None:
        """The drives whose boot files Update boot files would bring up to this app's.
        Its text does not depend on the selection, so the list below it stays put."""
        rows = [r for r in self.rows if r.eligible and r.freshness is not None and r.freshness.needs_update]
        if not rows:
            return None
        app = self.dist_summary.version

        def has(f: Freshness) -> str:
            v = f.installed.version if f.installed else ""
            if f.state == OTHER_BUILD:
                return f"{v}, a different build" if v else "a different build"
            return v or "an unknown version"

        if len(rows) == 1:
            r = rows[0]
            f = r.freshness
            assert f is not None
            if f.state == OTHER_BUILD:
                what = f"{r.title} has a different build of beast-booter {app} than this app."
                short = f"Update available: {r.title} has a different build of beast-booter {app}."
            else:
                what = f"{r.title} has beast-booter {has(f)}; this app has {app}."
                short = f"Update available: {r.title} has beast-booter {has(f)} (this app: {app})."
            return UpdateNotice("Boot files update available", f"{what} Select it and click Update boot files.",
                                r.id, short)
        names = ", ".join(f"{r.title} ({has(r.freshness)})" for r in rows if r.freshness)
        return UpdateNotice("Boot files updates available",
                            f"These drives have older or different beast-booter boot files than this app "
                            f"({app}): {names}. Select one and click Update boot files.", None,
                            f"Update available for {len(rows)} drives with older or different boot files.")

    @property
    def suggest_update(self) -> bool:
        """The selected drive's boot files should be updated (and can be now)."""
        row = self.selected_row
        return (row is not None and row.freshness is not None and row.freshness.needs_update
                and self.update_blocker() is None)

    def set_show_all(self, value: bool) -> None:
        if value != self.show_all:
            self.show_all = value
            self.refresh_drives()

    @property
    def selected_row(self) -> DriveRow | None:
        return next((r for r in self.rows if r.id == self.selected_id), None)

    def select_drive(self, drive_id: str | None) -> str | None:
        """Select a drive. Returns why it can't be selected (and clears the selection), or None."""
        row = next((r for r in self.rows if r.id == drive_id), None)
        if row is None or not row.eligible:
            self.selected_id = None
            return row.problem if row else None
        self.selected_id = row.id
        return None

    # -- options ------------------------------------------------------------

    def set_option(self, name: str, value: str) -> None:
        if self.phase is not Phase.IDLE:
            raise StateError("options can't be changed now")
        if name not in ("layout", "fs", "label"):
            raise ValueError(name)
        self.options = Options(**{**self.options.__dict__, name: value})

    @property
    def options_check(self) -> OptionsCheck:
        return check_options(self.options, self.platform)

    # -- what can be started ------------------------------------------------

    def _dist_problem(self) -> str | None:
        if not self.dist_summary.ok:
            return self.dist_summary.error or "Boot files not found."
        if self.verify_result is not None and not self.verify_result.ok:
            return "The boot files failed verification."
        return None

    def install_blocker(self) -> str | None:
        if self.phase is not Phase.IDLE or self.other_job_running():
            return "Busy."
        if p := self._dist_problem():
            return p
        if self.selected_row is None:
            return "Select a USB drive."
        if not self.options_check.ok:
            return "Fix the options first."
        return None

    def update_blocker(self) -> str | None:
        if self.phase is not Phase.IDLE or self.other_job_running():
            return "Busy."
        if p := self._dist_problem():
            return p
        if self.selected_row is None:
            return "Select a beast-booter USB drive."
        return None

    def image_blocker(self) -> str | None:
        if self.phase is not Phase.IDLE or self.other_job_running():
            return "Busy."
        if p := self._dist_problem():
            return p
        if not self.options_check.ok:
            return "Fix the options first."
        return None

    # -- confirmation -------------------------------------------------------

    def _require(self, *phases: Phase) -> None:
        if self.phase not in phases:
            raise StateError(f"not possible while {self.phase.value}")

    def request_install(self) -> ConfirmRequest:
        self._require(Phase.IDLE)
        if blocker := self.install_blocker():
            raise BeastError(blocker)
        row = self.selected_row
        assert row is not None
        chk = self.options_check
        o = Options(self.options.layout, self.options.fs, chk.label)
        spec = JobSpec("install", "device", row.id, disk=row.disk, options=o)
        details = [
            "Everything on this drive will be erased: all partitions and all files on them.",
            f"beast-booter then creates a storage partition for your ISO files ({FS_TEXT[o.fs]}, "
            f"label {o.label}) and a {ESP_SIZE_MIB} MiB boot partition ({ESP_LABEL}). "
            f"Partition table: {LAYOUT_TEXT[o.layout]}.",
        ]
        if row.disk.mountpoints:
            details.append("Its volumes will be unmounted first: " + ", ".join(row.disk.mountpoints))
        f = row.freshness
        if f is not None and f.state != REINSTALL:
            have = f"beast-booter {f.installed.version}" if f.installed and f.installed.version else "beast-booter"
            details.append(f"It already has {have}. To keep the files on it, cancel and use "
                           "Update boot files instead.")
        details.append("Your system will ask for administrator rights to write to the drive.")
        req = ConfirmRequest(spec, True, "Erase this drive?", row.describe(), tuple(details),
                             ACK_TEXT, "Erase and install")
        self.confirm_request, self.phase = req, Phase.CONFIRMING
        return req

    def request_update(self) -> ConfirmRequest:
        self._require(Phase.IDLE)
        if blocker := self.update_blocker():
            raise BeastError(blocker)
        row = self.selected_row
        assert row is not None
        spec = JobSpec("update", "device", row.id, disk=row.disk)
        version = self.dist_summary.version
        f = row.freshness
        now = f" (it has {f.installed.version} now)" if f and f.installed and f.installed.version else ""
        details = (
            f"The boot code and the boot partition are replaced with beast-booter {version}{now}.",
            *(("That is older than what the drive has: this downgrades it.",) if f and f.state == NEWER else ()),
            "The storage partition with your files is not touched.",
            "This only works on a drive that beast-booter installed; anything else is refused.",
            "Your system will ask for administrator rights to write to the drive.",
        )
        req = ConfirmRequest(spec, False, "Update the boot files?", row.describe(), details, "", "Update")
        self.confirm_request, self.phase = req, Phase.CONFIRMING
        return req

    def cancel_confirm(self) -> None:
        self._require(Phase.CONFIRMING)
        self.confirm_request, self.phase = None, Phase.IDLE

    def confirm(self, acknowledged: bool = False) -> None:
        """The user confirmed: re-check the drive, then start the CLI."""
        self._require(Phase.CONFIRMING)
        req = self.confirm_request
        assert req is not None
        if req.needs_ack and not acknowledged:
            raise BeastError(f'Tick "{req.ack_text}" first.')
        try:
            self._recheck(req.spec)
        except BeastError:
            self.confirm_request, self.phase = None, Phase.IDLE
            self.refresh_drives()
            raise
        self.confirm_request = None
        self._start_job(req.spec)

    def _recheck(self, spec: JobSpec) -> None:
        assert spec.disk is not None
        self.recheck_disk(spec.disk)

    def recheck_disk(self, old: DiskInfo) -> None:
        """Make sure the device id still names the drive the user confirmed.

        Drives can be swapped while the list is on screen, and a new drive can
        get the old one's name (/dev/sdb, PhysicalDrive2). Raises BeastError.
        """
        try:
            fresh = self.backend().get_disk(old.id)
        except Exception as e:  # noqa: BLE001
            raise BeastError(f"The drive {old.id} is no longer available ({_error_text(e)}). Nothing was written.") from None
        if (fresh.model, fresh.size, fresh.sector_size) != (old.model, old.size, old.sector_size):
            now = DriveRow(fresh, None).describe()
            raise BeastError(f"The drive at {old.id} has changed (now: {now}). Nothing was written; "
                             "check the drive list and try again.")
        if problem := drive_problem(fresh):
            raise BeastError(f"{DriveRow(fresh, None).describe()} can't be used: {problem}. Nothing was written.")

    # -- running ------------------------------------------------------------

    def start_image(self, path: str, size_text: str) -> None:
        """Create an image file. No administrator rights and no extra
        confirmation: the save dialog already asked about overwriting."""
        self._require(Phase.IDLE)
        if blocker := self.image_blocker():
            raise BeastError(blocker)
        size = check_image_size(size_text)
        path = os.path.abspath(os.path.expanduser(path))
        if os.path.isdir(path):
            raise BeastError(f"{path} is a folder; choose a file name")
        chk = self.options_check
        o = Options(self.options.layout, self.options.fs, chk.label)
        self._start_job(JobSpec("install", "image", path, options=o, image_size=size))

    def _start_job(self, spec: JobSpec) -> None:
        if spec.kind == "device":
            self.hold_probes()
        # A private directory (mode 0700): nobody else can create its cancel file.
        tmp = tempfile.mkdtemp(prefix="beast-booter-gui-", dir=self._tmp_root)
        progress_file = os.path.join(tmp, "progress.jsonl")
        # Created here so it belongs to the user even when an elevated CLI appends to it.
        open(progress_file, "x").close()
        cancel_path = os.path.join(tmp, "cancel") if self._cancel_file else None  # created only to cancel
        state = ProgressState()
        self.outcome, self.final_log = None, []
        try:
            assert self.dist.path is not None
            argv = build_cli_argv(spec, python=self.python, launcher=self.launcher,
                                  progress_file=progress_file, dist=str(self.dist.path), cancel_file=cancel_path)
            if not os.path.isfile(self.launcher):
                raise BeastError(f"{self.launcher} is missing; the beast-booter folder is incomplete")
            elevated = spec.kind == "device" and not self.backend().is_elevated()
            state.note("running: " + " ".join(_quote(a) for a in argv), "debug")
        except Exception as e:  # noqa: BLE001 - shown in the window
            self._start_failed(spec, state, tmp, e)
            return
        job = self.job = _Job(spec, argv, None, ProgressReader(progress_file), state, tmp, elevated, self._clock(),
                              cancel_path)
        self.phase = Phase.RUNNING
        if spec.kind == "device" and self.probe_busy():
            state.note("waiting for a drive check to finish before writing")
        else:
            self._launch(job)

    def _launch(self, job: _Job) -> None:
        try:
            if job.elevated:
                job.state.note("asking for administrator rights")
                job.proc = self.backend().run_elevated(job.argv)
            else:
                job.proc = LocalProcess(job.argv, os.path.join(job.tmpdir, "output.txt"))
        except Exception as e:  # noqa: BLE001 - shown in the window
            self.job = None
            self._start_failed(job.spec, job.state, job.tmpdir, e)

    def _start_failed(self, spec: JobSpec, state: ProgressState, tmp: str, e: BaseException) -> None:
        self._not_started(spec, state, tmp, _fail_title(spec), _error_text(e), "start-failed")

    def _not_started(self, spec: JobSpec, state: ProgressState, tmp: str, title: str, message: str, code: str,
                     *, cancelled: bool = False) -> None:
        shutil.rmtree(tmp, ignore_errors=True)
        state.note(message, "warning" if cancelled else "error")
        self.final_log = state.log
        self.outcome = Outcome(False, spec, title, message, code=code, cancelled=cancelled,
                               target_state="Nothing was written.")
        self.phase = Phase.FAILED

    def _poll_waiting(self, job: _Job) -> bool:
        """A job that waits for a drive check: start it when the check is over."""
        if job.cancel_requested:
            self.job = None
            self._not_started(job.spec, job.state, job.tmpdir, "Cancelled", "You stopped it before it started.",
                              "cancelled", cancelled=True)
        elif not self.probe_busy():
            self._launch(job)
        elif self._clock() - job.started_at > PROBE_LIMIT:
            self.job = None
            self._not_started(job.spec, job.state, job.tmpdir, _fail_title(job.spec), PROBE_BUSY, "probe-busy")
        else:
            return False
        return True

    @property
    def progress(self) -> ProgressState | None:
        return self.job.state if self.job else None

    @property
    def log(self) -> list[LogLine]:
        return self.job.state.log if self.job else self.final_log

    def poll(self) -> bool:
        """Call regularly from the GUI loop. Returns True when something changed."""
        changed = self._poll_tasks()
        if self.phase is Phase.RUNNING and self.job is not None:
            changed |= self._poll_job(self.job)
        if self._probe_pending:
            self._start_probe()
        return changed

    def _poll_job(self, job: _Job) -> bool:
        if job.proc is None:
            return self._poll_waiting(job)
        events = job.reader.read_new()
        for ev in events:
            job.state.apply(ev)
        try:
            rc = job.proc.poll()
        except Exception as e:  # noqa: BLE001 - a broken backend process handle
            job.state.note(f"lost track of the installer process: {_error_text(e)}", "error")
            rc = -1
        if rc is None:
            return bool(events)
        for ev in job.reader.finish():
            job.state.apply(ev)
        self._finish(job, rc)
        return True

    def _finish(self, job: _Job, rc: int) -> None:
        st, spec = job.state, job.spec
        output_tail = getattr(job.proc, "output_tail", None)  # LocalProcess / macOS keep the CLI's output
        tail: tuple[str, ...] = ()
        if callable(output_tail) and rc != 0:
            try:
                tail = tuple(output_tail())
            except Exception:  # noqa: BLE001 - only for display
                tail = ()
            for line in tail:
                st.note(f"output: {line}", "debug")
        st.note(f"installer exited with code {rc}", "debug" if rc == 0 else "error")
        if job.cancel_requested and rc == 0 and st.error_code is None:
            st.note("the installer finished before it could stop", "warning")
        if rc == 0 and st.error_code is None and (st.done_ok or not st.done_seen):
            if not st.done_seen:
                st.note("the installer did not report a result; its exit code says it succeeded", "warning")
            outcome = Outcome(True, spec, _ok_title(spec), _ok_message(spec, self.dist_summary.version),
                              exit_code=rc, info=st.done_info)
        elif job.cancel_requested and st.error_code in (None, "cancelled", "interrupted"):
            outcome = Outcome(False, spec, "Cancelled", "You stopped the installer.", code="cancelled",
                              exit_code=rc, cancelled=True, target_state=_target_state(spec, st))
        elif st.error_code is not None:
            outcome = Outcome(False, spec, _fail_title(spec), st.error_message or "", code=st.error_code,
                              exit_code=rc, target_state=_target_state(spec, st))
        elif not st.started and job.elevated and rc == ELEVATION_CANCELLED:
            outcome = Outcome(False, spec, "Not started", "The administrator prompt was cancelled.",
                              code="elevation-cancelled", exit_code=rc, cancelled=True,
                              target_state="Nothing was written.")
        elif not st.started and job.elevated and rc == ELEVATION_FAILED:
            outcome = Outcome(False, spec, _fail_title(spec),
                              "Administrator rights could not be obtained: this account is not allowed, "
                              "or the system has no way to ask (on Linux: no polkit agent running).",
                              code="elevation-failed", exit_code=rc, target_state="Nothing was written.")
        elif not st.started:
            outcome = Outcome(False, spec, _fail_title(spec), f"The installer did not start (exit code {rc}).",
                              code="not-started", exit_code=rc, target_state="Nothing was written.")
        elif rc == 0:
            outcome = Outcome(False, spec, _fail_title(spec), "The installer finished but reported a problem.",
                              code="not-ok", exit_code=rc, target_state=_target_state(spec, st))
        else:
            outcome = Outcome(False, spec, _fail_title(spec),
                              f"The installer stopped unexpectedly (exit code {rc}).",
                              code=f"exit-{rc}", exit_code=rc, target_state=_target_state(spec, st))
        if not outcome.ok and tail:
            outcome = dataclasses.replace(outcome, output_tail=tail)
        self.outcome = outcome
        self.final_log = st.log
        self.phase = Phase.DONE if outcome.ok else Phase.FAILED
        if spec.kind == "device":
            self.drive_written(spec.target)  # its firmware packs too (FirmwareController)
            # What the drive has now is unknown until it is checked again (dismiss() lists and checks).
            self._probe_gen += 1
            self._probe_pending = False
            self.rows = [dataclasses.replace(r, freshness=None, probe=None) if r.id == spec.target else r
                         for r in self.rows]
            self.rows_version += 1
        shutil.rmtree(job.tmpdir, ignore_errors=True)

    @property
    def can_cancel(self) -> bool:
        """Whether a stop request can reach the running CLI.

        Our own child process (no elevation): yes, by signal. An elevated CLI:
        only through its --cancel-file (see CLI_HAS_CANCEL_FILE); signalling the
        elevation wrapper would at best do nothing and at worst make this window
        lose track of a CLI that keeps writing.
        """
        job = self.job
        return bool(job and self.phase is Phase.RUNNING and (not job.elevated or job.cancel_path))

    def cancel(self) -> None:
        """Ask the CLI to stop. The outcome arrives through poll(): the CLI may
        finish anyway (it then reports success), or stop and leave the target
        unusable. Raises BeastError when the CLI can't be reached (can_cancel)."""
        self._require(Phase.RUNNING)
        job = self.job
        assert job is not None
        if not self.can_cancel:
            raise BeastError(CANNOT_STOP)
        job.cancel_requested = True
        job.state.note("stop requested", "warning")
        if job.proc is None:
            return  # not started yet: poll() ends it
        if job.cancel_path:
            try:
                with open(job.cancel_path, "a", encoding="utf-8"):
                    pass
            except OSError as e:
                job.state.note(f"could not ask the installer to stop: {_error_text(e)}", "error")
        if not job.elevated:
            try:
                job.proc.cancel()
            except Exception as e:  # noqa: BLE001
                job.state.note(f"could not stop the installer: {_error_text(e)}", "error")

    @property
    def cancel_requested(self) -> bool:
        return bool(self.job and self.job.cancel_requested and self.phase is Phase.RUNNING)

    def stopping_text(self) -> str:
        """Shown while a stop request is under way."""
        job = self.job
        if job is not None and job.elevated:
            return "Stopping after the current step..."
        return "Stopping..."

    def cancel_warning(self) -> str:
        spec = self.job.spec if self.job else None
        if spec is None or spec.kind == "image":
            return "The image file will be incomplete and must be created again."
        if spec.action == "update":
            return ("Stopping in the middle can leave the boot files incomplete, so the drive may not boot "
                    "until you run Update again. Your own files are not touched by an update.")
        return ("Stopping in the middle of writing leaves the drive unusable until you install beast-booter "
                "on it again, and its previous contents may already be gone.")

    def dismiss(self) -> None:
        """Back to the start page after a result."""
        self._require(Phase.DONE, Phase.FAILED)
        self.phase, self.job, self.outcome = Phase.IDLE, None, None
        self.refresh_drives()

    # -- boot files ---------------------------------------------------------

    def verify_dist(self) -> None:
        if self.verifying or self.dist.path is None:
            return
        path = self.dist.path
        self.verifying = True
        self._start_task(lambda: distinfo.verify(path), self._on_verified)

    def _on_verified(self, result, err) -> None:
        self.verifying = False
        if err is not None:
            result = distinfo.VerifyResult(False, f"verification failed: {_error_text(err)}")
        self.verify_result = result
        self.dist_summary = distinfo.read_summary(self.dist)

    def docs_path(self, name: str = "SECURE_BOOT.md") -> Path | None:
        base = distinfo.app_dir().parent
        for cand in (base / "docs" / name, base / "payload" / "docs" / name):
            if cand.is_file():
                return cand
        return None

    def next_steps(self, outcome: Outcome) -> list[str]:
        """What to do after a successful run, one paragraph per step."""
        label = (self.options.label if outcome.spec.options is None else outcome.spec.options.label)
        data = (outcome.info or {}).get("data") if isinstance(outcome.info, dict) else None
        if isinstance(data, dict) and isinstance(data.get("label"), str) and data["label"]:
            label = data["label"]
        secure_boot = (
            "First start with Secure Boot on: shim reports that it cannot verify beast-booter and opens "
            f'MokManager. Choose "Enroll key from disk", open {ESP_LABEL} and select {CERT_FILE}. '
            'Choose "View key" and compare its fingerprint with the one below, then Continue, Yes, '
            "Reboot. Each computer asks only once."
        )
        # Before secure_boot: the key fingerprint card follows the last step.
        ubuntu = (
            "With Secure Boot on, Ubuntu and Ubuntu-based ISOs (such as Linux Mint) start only after you run "
            "\"Trust Ubuntu's Secure Boot key\" from the drive's boot menu (once per computer), or "
            "with Secure Boot off."
        )
        if outcome.spec.kind == "image":
            return [
                f"Write {os.path.basename(outcome.spec.target)} to a USB drive with any disk imaging tool, "
                "or attach it to a virtual machine.",
                f"Copy your ISO files onto its {label} partition, like onto any USB drive.",
                ubuntu,
                secure_boot,
            ]
        if outcome.spec.action == "update":
            return [
                "Your ISO files and other data on the drive were not touched.",
                ubuntu,
                "Computers that already enrolled this beast-booter key start it directly. "
                "On any other computer: " + secure_boot[0].lower() + secure_boot[1:],
            ]
        return [
            f"Copy your ISO files onto the {label} drive, like onto any USB drive. Folders are fine.",
            "Start the computer from the drive (a key like F12, F11, F8 or Esc usually opens the boot menu).",
            ubuntu,
            secure_boot,
        ]

    def shutdown(self) -> None:
        """Window closed: stop a running CLI if it can be reached; an elevated
        CLI that can't be stopped keeps running and finishes on its own."""
        if self.phase is Phase.RUNNING and self.can_cancel and not self.cancel_requested:
            self.cancel()


def _ok_title(spec: JobSpec) -> str:
    if spec.kind == "image":
        return "Image file created"
    return "Boot files updated" if spec.action == "update" else "beast-booter is ready"


def _ok_message(spec: JobSpec, version: str) -> str:
    if spec.kind == "image":
        return f"{spec.target} now holds beast-booter {version}."
    if spec.action == "update":
        return f"{spec.target_text} now has the boot files of beast-booter {version}."
    return f"{spec.target_text} is now a beast-booter {version} drive."


def _fail_title(spec: JobSpec) -> str:
    if spec.kind == "image":
        return "Creating the image failed"
    return "Update failed" if spec.action == "update" else "Installation failed"


def _target_state(spec: JobSpec, st: ProgressState) -> str:
    if not st.wrote_to_target:
        what = "the image file" if spec.kind == "image" else "the drive"
        return f"The installer stopped before it started writing, so nothing was written to {what}."
    if spec.kind == "image":
        return "The image file is incomplete; create it again."
    if spec.action == "update":
        return ("The boot files on the drive may be incomplete: run Update again before using it. "
                "Your files in the storage partition are not touched by an update.")
    return ("The drive was partly rewritten and won't work until you install beast-booter on it again. "
            "Its previous contents are gone.")


def _quote(arg: str) -> str:
    """For the log only (the command itself is never run through a shell)."""
    if arg and all(c.isalnum() or c in "-_./:=\\+,@" for c in arg):
        return arg
    return '"' + arg.replace('"', '\\"') + '"'
