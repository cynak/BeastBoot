"""macOS backend: diskutil (property lists) for listing, /dev/rdiskN for raw I/O.

Listing
  `diskutil list -plist` gives every whole disk, its partitions and the APFS
  containers (synthesized virtual disks) with their physical stores and
  volumes; `diskutil info -plist diskN` gives the details of each whole disk
  (bus protocol, internal/removable/ejectable, block size, writable). Only
  physical whole disks are listed: APFS containers and disk images
  (VirtualOrPhysical = Virtual) are skipped.

System disk
  Every physical disk that ends up under the running system is "system":
  the disk behind "/" (`diskutil info -plist /`: ParentWholeDisk, the APFS
  container and its physical stores), the boot volume (BooterDeviceIdentifier),
  and any APFS container with a volume mounted at "/" or under
  /System/Volumes (Data, VM = swap, Preboot, ...). APFS containers are mapped
  to their physical stores with `diskutil apfs list -plist`. If the root cannot
  be traced to a physical disk (CoreStorage, an unknown layout), every internal
  disk is treated as a system disk.

In use
  A disk with an AppleRAID or CoreStorage member partition (Content Apple_RAID,
  Apple_RAID_Offline, Apple_CoreStorage, or RAIDSlice) is refused: the set it
  belongs to is a separate (virtual) disk whose volumes `unmountDisk` on the
  member would leave mounted.

Raw I/O
  prepare() runs `diskutil unmountDisk force` (APFS containers on the disk
  first). The raw node /dev/rdiskN bypasses the buffer cache and only accepts
  offsets and lengths that are multiples of the block size, so the target is
  an AlignedTarget (read-modify-write) with a page-aligned bounce buffer.
  flush() uses fcntl F_FULLFSYNC and the DKIOCSYNCHRONIZECACHE ioctl.

Re-reading the partition table (researched; untested on a real Mac)
  macOS has no "re-read" verb. IOKit re-probes a medium for partitions when a
  writer closes its BSD device node: that is why the "disk not readable" dialog
  pops up the moment `dd ... of=/dev/rdiskN` finishes. So the installer closes
  the raw target, and rescan() reads the new table back, then polls
  `diskutil list -plist diskN` until diskutil shows that many partitions.
  DiskArbitration then mounts the new volumes by itself.

NTFS
  macOS cannot create NTFS (no formatter ships with it): format_ntfs() refuses.

Elevation
  `osascript -e 'do shell script "..." with administrator privileges'` shows
  the standard macOS password dialog. The command is quoted twice: first for
  /bin/sh (shlex.quote each argument), then as an AppleScript string literal
  (backslash, double quote and control characters escaped).
  The root shell does not exec the command: it starts it in the background
  with its output going to a file, runs a small watcher, and waits for it
  (see supervised_command). An unprivileged process cannot signal a root one,
  so cancel() creates a file the root watcher turns into SIGTERM (a second
  cancel(): SIGKILL). osascript is left alone once the command has started, so
  it exits exactly when the installer has exited, and the installer never
  depends on osascript's output pipe staying open.
"""

from __future__ import annotations

import mmap
import os
import plistlib
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time

from ..blockio import AlignedTarget, _open_fd
from ..disk import read_partition_table
from ..errors import BeastError
from ..interfaces import DiskInfo
from .common import (ELEVATION_CANCELLED, ELEVATION_FAILED, PopenProcess, check_common, check_same_drive,
                     natural_key)

DISKUTIL = "/usr/sbin/diskutil"
OSASCRIPT = "/usr/bin/osascript"

# <sys/disk.h>: _IOR('d', 24, uint32_t), _IOR('d', 25, uint64_t), _IO('d', 22)
DKIOCGETBLOCKSIZE = 0x40046418
DKIOCGETBLOCKCOUNT = 0x40086419
DKIOCSYNCHRONIZECACHE = 0x20006416

RESCAN_TIMEOUT = 20.0

_WHOLE_RE = re.compile(r"^(?:/dev/)?r?(disk\d+)")
_ID_RE = re.compile(r"^(?:/dev/)?r?(disk\d+)(s\d+)*$")

BUS_MAP = {
    "usb": "usb",
    "sata": "sata",
    "ata": "sata",
    "pci-express": "nvme",
    "pci": "nvme",
    "nvme": "nvme",
    "apple fabric": "nvme",  # Apple silicon internal SSD
    "secure digital": "sd",
    "sd": "sd",
    "sas": "scsi",
    "scsi": "scsi",
    "fibre channel interface": "scsi",
    "disk image": "virtual",
    "virtual interface": "virtual",
}


# Partition contents that make the disk part of another (virtual) disk.
MEMBER_CONTENT = {
    "Apple_RAID": "a member of an AppleRAID set",
    "52414944-0000-11AA-AA11-00306543ECAC": "a member of an AppleRAID set",
    "Apple_RAID_Offline": "a member of an AppleRAID set (offline)",
    "52414944-5F4F-11AA-AA11-00306543ECAC": "a member of an AppleRAID set (offline)",
    "Apple_CoreStorage": "a CoreStorage physical volume (Fusion Drive or encrypted volume)",
    "53746F72-6167-11AA-AA11-00306543ECAC": "a CoreStorage physical volume (Fusion Drive or encrypted volume)",
}


def _whole(ident: str) -> str:
    """'disk3s1s1' -> 'disk3' (the whole disk an identifier belongs to)."""
    m = _WHOLE_RE.match(ident)
    return m.group(1) if m else ident


def parse_plist(data: bytes, what: str = "diskutil") -> dict:
    """Parse a property list printed by a tool (tolerates text before the XML)."""
    start = min((i for i in (data.find(b"<?xml"), data.find(b"<plist")) if i >= 0), default=-1)
    if start > 0:
        data = data[start:]
    try:
        value = plistlib.loads(data)
    except Exception as e:  # plistlib raises several types (InvalidFileException, ExpatError, ...)
        raise BeastError(f"could not parse the output of {what}: {e}") from None
    if not isinstance(value, dict):
        raise BeastError(f"unexpected output from {what} (not a dictionary)")
    return value


def _run_tool(argv: list[str]) -> bytes:
    try:
        proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL,
                              env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        raise BeastError(f"required tool {argv[0]} was not found") from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        raise BeastError(f"{' '.join(argv[:3])} failed: {detail}")
    return proc.stdout


def _bus(protocol: str) -> str:
    return BUS_MAP.get((protocol or "").strip().lower(), "unknown")


def _stores(value) -> list[str]:
    """APFS physical store identifiers from any of diskutil's spellings."""
    out = []
    for item in value or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            ident = item.get("APFSPhysicalStore") or item.get("DeviceIdentifier")
            if ident:
                out.append(ident)
    return out


class _Snapshot:
    """What diskutil says right now: whole disks, partitions, APFS containers, root."""

    def __init__(self, backend: DarwinBackend):
        self.listing = backend._plist("list", "-plist")
        try:
            self.apfs = backend._plist("apfs", "list", "-plist")
        except BeastError:
            self.apfs = {}  # very old macOS / no APFS: the listing still has the stores
        try:
            self.root = backend._plist("info", "-plist", "/")
        except BeastError:
            self.root = {}
        self.entries = {e.get("DeviceIdentifier"): e for e in self.listing.get("AllDisksAndPartitions", [])}
        self.whole_disks = list(self.listing.get("WholeDisks") or self.entries)
        # APFS container (synthesized disk) -> physical store partitions; and its volumes.
        self.containers: dict[str, list[str]] = {}
        self.container_mounts: dict[str, list[str]] = {}
        for c in self.apfs.get("Containers", []):
            ref = c.get("ContainerReference")
            if ref:
                stores = _stores(c.get("PhysicalStores")) or ([c["DesignatedPhysicalStore"]]
                                                              if c.get("DesignatedPhysicalStore") else [])
                self.containers[ref] = stores
        for ident, e in self.entries.items():
            if "APFSPhysicalStores" in e or "APFSVolumes" in e:
                self.containers.setdefault(ident, [])
                if not self.containers[ident]:
                    self.containers[ident] = _stores(e.get("APFSPhysicalStores"))
                mounts = []
                for v in e.get("APFSVolumes", []):
                    if v.get("MountPoint"):
                        mounts.append(v["MountPoint"])
                    for snap in v.get("MountedSnapshots", []) or []:
                        if snap.get("SnapshotMountPoint"):
                            mounts.append(snap["SnapshotMountPoint"])
                self.container_mounts[ident] = mounts

    def physical_of(self, ident: str, depth: int = 0) -> set[str] | None:
        """Whole physical disk names under an identifier; None if it cannot be traced."""
        whole = _whole(ident)
        if whole in self.containers:
            stores = self.containers[whole]
            if not stores or depth > 8:
                return None
            out: set[str] = set()
            for s in stores:
                sub = self.physical_of(s, depth + 1)
                if sub is None:
                    return None
                out |= sub
            return out
        return {whole}

    def partitions(self, disk: str) -> list[dict]:
        return list(self.entries.get(disk, {}).get("Partitions", []))

    def containers_on(self, disk: str) -> list[str]:
        return [c for c, stores in self.containers.items() if any(_whole(s) == disk for s in stores)]

    def mountpoints(self, disk: str) -> list[str]:
        out = []
        entry = self.entries.get(disk, {})
        if entry.get("MountPoint"):
            out.append(entry["MountPoint"])
        for p in self.partitions(disk):
            if p.get("MountPoint"):
                out.append(p["MountPoint"])
        for c in self.containers_on(disk):
            out += self.container_mounts.get(c, [])
        return out

    def system_seeds(self) -> list[tuple[str, str]]:
        """(identifier, why) pairs for everything the running system lives on."""
        seeds = []
        r = self.root
        for key in ("DeviceIdentifier", "ParentWholeDisk", "APFSContainerReference"):
            if r.get(key):
                seeds.append((r[key], 'holds the running macOS ("/")'))
        for s in _stores(r.get("APFSPhysicalStores")):
            seeds.append((s, 'holds the running macOS ("/")'))
        if r.get("BooterDeviceIdentifier"):
            seeds.append((r["BooterDeviceIdentifier"], "holds the macOS boot volume"))
        for c, mounts in self.container_mounts.items():
            for m in mounts:
                if m == "/" or m.startswith("/System/Volumes/"):
                    seeds.append((c, f"holds the running macOS ({m})"))
        for ident, e in self.entries.items():
            for p in [e, *e.get("Partitions", [])]:
                if p.get("MountPoint") == "/":
                    seeds.append((p.get("DeviceIdentifier", ident), 'holds the running macOS ("/")'))
        return seeds


class DarwinRawTarget(AlignedTarget):
    """/dev/rdiskN: aligned pread/pwrite through a page-aligned bounce buffer."""

    def __init__(self, path: str, *, writable: bool, sector_size: int, size: int):
        fd = _open_fd(path, writable, device_hint=" (administrator rights are needed)")
        try:
            geometry = _ioctl_geometry(fd)
            if geometry:
                block, count = geometry
                if block != sector_size:
                    raise BeastError(f"{path}: block size changed ({sector_size} -> {block})")
                if block * count != size:
                    raise BeastError(f"{path}: size changed (expected {size} bytes, device has {block * count})")
            super().__init__(path, size=size, sector_size=sector_size, writable=writable)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        self._buf = mmap.mmap(-1, self.max_io)  # anonymous mmap = page aligned

    def _read_aligned(self, offset: int, length: int) -> bytes:
        done = 0
        with memoryview(self._buf) as mv:
            while done < length:
                os.lseek(self.fd, offset + done, os.SEEK_SET)
                n = os.readv(self.fd, [mv[done:length]])
                if n <= 0:
                    raise BeastError(f"unexpected end of {self.path} at byte {offset + done}")
                done += n
            return bytes(mv[:length])

    def _write_aligned(self, offset: int, data) -> None:
        length = len(data)
        with memoryview(self._buf) as mv:
            mv[:length] = data
            done = 0
            while done < length:
                n = os.pwrite(self.fd, mv[done:length], offset + done)
                if n <= 0:
                    raise BeastError(f"short write to {self.path} at byte {offset + done}")
                done += n

    def flush(self) -> None:
        if not self.writable:
            return
        import fcntl  # POSIX only: imported here so this module imports on Windows too

        full = getattr(fcntl, "F_FULLFSYNC", None)
        try:
            if full is None:
                raise OSError
            fcntl.fcntl(self.fd, full)  # data and the drive's cache to stable storage
        except OSError:
            os.fsync(self.fd)
        if sys.platform == "darwin":
            try:
                fcntl.ioctl(self.fd, DKIOCSYNCHRONIZECACHE)
            except OSError:
                pass

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
            try:
                self._buf.close()
            except BufferError:  # a view is still referenced (traceback); the GC frees it
                pass


def _ioctl_geometry(fd: int) -> tuple[int, int] | None:
    """(block size, block count) from the disk driver; None when not a macOS disk."""
    if sys.platform != "darwin":
        return None
    import fcntl

    try:
        (block,) = struct.unpack("=I", fcntl.ioctl(fd, DKIOCGETBLOCKSIZE, bytes(4)))
        (count,) = struct.unpack("=Q", fcntl.ioctl(fd, DKIOCGETBLOCKCOUNT, bytes(8)))
    except OSError:
        return None
    return block, count


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

ELEVATION_PROMPT = "beast-boot needs administrator rights to write to the selected drive."


def applescript_string(s: str) -> str:
    """An AppleScript string literal for s ("..." with \\ \" \\n \\r \\t escapes)."""
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{out}"'


def command_line(argv: list[str]) -> str:
    """POSIX sh words for argv (each argument single-quoted as needed)."""
    return " ".join(shlex.quote(a) for a in argv)


class ElevationFiles:
    """Files shared by this (unprivileged) process and the root shell, in a fresh
    private (0700) directory: the command's output, and the markers below."""

    def __init__(self, parent: str | None = None):
        self.dir = tempfile.mkdtemp(prefix="beast-boot-elevated-", dir=parent)
        self.output = os.path.join(self.dir, "output.txt")  # stdout + stderr of the command
        self.started = os.path.join(self.dir, "started")  # mkdir'ed by the root shell first thing
        self.cancel = os.path.join(self.dir, "cancel")  # created by cancel(): SIGTERM
        self.kill = os.path.join(self.dir, "kill")  # created by a second cancel(): SIGKILL
        # The root shell also mkdirs "pid-<command's pid>" and, when it has ended, "exit-<status>".
        with open(self.output, "x"):  # ours, so the root shell only writes into it
            pass

    def marker(self, prefix: str) -> int | None:
        """N from a "<prefix>N" marker the root shell made, or None."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return None
        for name in names:
            if name.startswith(prefix) and name[len(prefix):].isdigit():
                return int(name[len(prefix):])
        return None

    def remove(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def supervised_command(argv: list[str], files: ElevationFiles) -> str:
    """The /bin/sh script `do shell script` runs as root (one line):

        mkdir STARTED                       # tells cancel() the password was accepted
        ARGV </dev/null >OUTPUT 2>&1 &      # the installer, independent of osascript's pipe
        mkdir DIR/pid-PID                   # lets poll() check the installer is still alive
        ( watcher ) &                       # CANCEL file -> SIGTERM, KILL file -> SIGKILL
        wait; mkdir DIR/exit-STATUS         # the installer's status (128+N if a signal ended it)
        exit STATUS

    mkdir (not `>`) creates the markers because it never follows a symlink.
    """
    q = shlex.quote
    watcher = ("term=; while kill -0 \"$pid\" 2>/dev/null; do "
               f"if [ -e {q(files.kill)} ]; then kill -s KILL \"$pid\"; exit 0; fi; "
               f"if [ -z \"$term\" ] && [ -e {q(files.cancel)} ]; then kill -s TERM \"$pid\"; term=1; fi; "
               "sleep 0.2; done")
    marker = q(files.dir + "/")
    return (f"mkdir {q(files.started)} 2>/dev/null; "
            f"{command_line(argv)} </dev/null >{q(files.output)} 2>&1 & pid=$!; "
            f"mkdir {marker}pid-\"$pid\" 2>/dev/null; "
            f"( {watcher} ) </dev/null >/dev/null 2>&1 & watcher=$!; "
            f"wait \"$pid\"; rc=$?; mkdir {marker}exit-\"$rc\" 2>/dev/null; "
            "kill \"$watcher\" 2>/dev/null; exit \"$rc\"")


def elevation_command(argv: list[str], files: ElevationFiles | None = None,
                      prompt: str = ELEVATION_PROMPT) -> list[str]:
    """osascript argv running argv as root (supervised when `files` is given, else exec'ed)."""
    if not argv:
        raise ValueError("empty command")
    shell = supervised_command(argv, files) if files else "exec " + command_line(argv)
    script = (f"do shell script {applescript_string(shell)} "
              f"with prompt {applescript_string(prompt)} with administrator privileges")
    return [OSASCRIPT, "-e", script]


_OSA_CODE_RE = re.compile(r"\((-?\d+)\)\s*$")


def osascript_exit_code(returncode: int, stderr: str) -> int:
    """The elevated command's exit status, recovered from osascript.

    osascript exits 1 for any error and reports "...: execution error: <text> (N)":
    N > 0 is the shell command's exit status, -128 means the user pressed
    Cancel, other negative numbers are AppleScript/authorization errors.
    """
    if returncode == 0:
        return 0
    lines = [line for line in stderr.splitlines() if line.strip()]
    m = _OSA_CODE_RE.search(lines[-1]) if lines else None
    if not m:
        return ELEVATION_FAILED
    code = int(m.group(1))
    if code == -128:
        return ELEVATION_CANCELLED
    return code if code > 0 else ELEVATION_FAILED


class OsascriptProcess(PopenProcess):
    """osascript running the command as root (see supervised_command).

    poll()/wait() report the command's own exit status: once the command has
    started, osascript only exits after it. Should osascript be killed from
    outside, poll() keeps answering None while the command's pid is alive and
    then reports the status the root shell recorded. `output` is the command's
    stdout and stderr; `stdout`/`stderr` are osascript's.
    """

    def __init__(self, popen, argv, files: ElevationFiles, out, err):
        super().__init__(popen, argv)
        self.files = files
        self._out, self._err = out, err
        self._cancels = 0
        self._stopped_before_start = False
        self.stdout = ""
        self.stderr = ""
        self.output = ""

    def started(self) -> bool:
        """The password was accepted and the root shell is running the command."""
        return os.path.isdir(self.files.started)

    def _command_alive(self) -> bool:
        pid = self.files.marker("pid-")
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:  # alive, and root's
            return True
        return True

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        rc = self._p.poll()
        if rc is None:
            return None
        if rc < 0 and self.started() and self.files.marker("exit-") is None and self._command_alive():
            return None  # osascript was killed, the installer itself still runs
        self.returncode = self._finish(rc)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            rc = self.poll()
            if rc is not None:
                return rc
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"elevated process still running after {timeout} s")
            time.sleep(0.05)

    def cancel(self) -> None:
        """First call: the root watcher sends SIGTERM to the command; later calls: SIGKILL.
        At the password dialog (nothing started yet) osascript itself is stopped."""
        if self.poll() is not None:
            return
        self._cancels += 1
        marker = self.files.cancel if self._cancels == 1 else self.files.kill
        try:
            with open(marker, "a"):
                pass
        except OSError:
            pass
        if not self.started():
            # Nothing runs as root yet: closing osascript closes the dialog. Should the shell
            # start anyway, the cancel file already exists and the watcher stops the command
            # before Python has even loaded it.
            self._stopped_before_start = True
            super().cancel()

    def _read_output(self) -> str:
        try:
            with open(self.files.output, "rb") as f:
                return f.read()[-64 * 1024:].decode("utf-8", "replace")
        except OSError:
            return self.output

    def output_tail(self, max_lines: int = 20) -> list[str]:
        """Last lines of the command's output, then osascript's error (for the GUI log)."""
        text = self.output if self.returncode is not None else self._read_output()
        lines = [line for line in text.splitlines() if line.strip()][-max_lines:]
        return lines + [line for line in self.stderr.splitlines() if line.strip()]

    def _finish(self, rc: int) -> int:
        for f, attr in ((self._out, "stdout"), (self._err, "stderr")):
            try:
                f.seek(0)
                setattr(self, attr, f.read().decode("utf-8", "replace"))
                f.close()
            except (OSError, ValueError):
                pass
        self.output = self._read_output()
        status = self.files.marker("exit-")  # the root shell's record of the command's exit
        self.files.remove()
        if status is not None:  # the command ran (even if only to be stopped at once)
            return status
        if self._stopped_before_start:
            return ELEVATION_CANCELLED
        return osascript_exit_code(rc, self.stderr)


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class DarwinBackend:
    name = "darwin"

    def __init__(self, runner=None):
        # runner(argv) -> stdout bytes; raises BeastError on failure (tests pass a fake).
        self._run = runner or _run_tool

    def _plist(self, *args: str) -> dict:
        return parse_plist(self._run([DISKUTIL, *args]), f"diskutil {' '.join(args[:2])}")

    # -- listing ---------------------------------------------------------------
    def _disk_infos(self, snap: _Snapshot, names: list[str], want: str | None = None) -> dict[str, dict]:
        """diskutil info for each physical whole disk (virtual ones dropped).

        A disk that vanished since `diskutil list` is skipped, unless it is `want`.
        """
        out = {}
        for name in names:
            if name in snap.containers:
                continue  # APFS container: a synthesized (virtual) disk
            try:
                info = self._plist("info", "-plist", name)
            except BeastError:
                if name == want:
                    raise
                continue
            if info.get("VirtualOrPhysical") == "Virtual" or _bus(info.get("BusProtocol", "")) == "virtual":
                continue  # disk image, RAM disk
            out[name] = info
        return out

    def _system_map(self, snap: _Snapshot, infos: dict[str, dict]) -> dict[str, str]:
        reasons: dict[str, str] = {}
        traced = bool(snap.root)
        for ident, why in snap.system_seeds():
            disks = snap.physical_of(ident)
            if disks is None or not disks <= set(infos):
                traced = False
                continue
            for d in disks:
                reasons.setdefault(d, why)
        for name, info in infos.items():
            if info.get("OSInternalMedia") is True:
                reasons.setdefault(name, "is marked as OS internal media")
        if not traced:
            for name, info in infos.items():
                if info.get("Internal", True):
                    reasons.setdefault(
                        name, "is an internal disk, and the disk holding the running macOS could not be identified"
                    )
        return reasons

    def _make_info(self, name: str, info: dict, snap: _Snapshot, reason: str | None) -> DiskInfo:
        internal = bool(info.get("Internal", True))
        removable_media = bool(info.get("RemovableMedia") or info.get("Removable"))
        ejectable = bool(info.get("Ejectable"))
        writable = info.get("WritableMedia", info.get("Writable", True))
        parts = sorted((p.get("DeviceIdentifier", "") for p in snap.partitions(name)), key=natural_key)
        return DiskInfo(
            id=f"/dev/{name}",
            path=f"/dev/r{name}",
            model=(info.get("MediaName") or info.get("IORegistryEntryName") or "").strip(),
            size=int(info.get("Size") or info.get("TotalSize") or info.get("IOKitSize") or 0),
            sector_size=int(info.get("DeviceBlockSize") or 512),
            bus=_bus(info.get("BusProtocol", "")),
            removable=removable_media or ejectable or not internal,
            system=reason is not None,
            read_only=not writable,
            mountpoints=tuple(snap.mountpoints(name)),
            partitions=tuple(f"/dev/{p}" for p in parts if p),
            extra={"bsd_name": name, "bus_protocol": info.get("BusProtocol", ""), "internal": internal,
                   "removable_media": removable_media, "ejectable": ejectable,
                   "content": info.get("Content", ""), "system_reason": reason,
                   "member_of": self._member_reason(name, info, snap)},
        )

    @staticmethod
    def _member_reason(name: str, info: dict, snap: _Snapshot) -> str | None:
        """Why the disk belongs to an AppleRAID set / CoreStorage group, or None."""
        if info.get("RAIDSlice") is True:
            return f"a member of an AppleRAID set ({name})"
        for p in [snap.entries.get(name, {}), *snap.partitions(name)]:
            what = MEMBER_CONTENT.get(str(p.get("Content", "")).strip())
            if what:
                return f"{what} ({p.get('DeviceIdentifier', name)})"
        return None

    @staticmethod
    def _check_member(disk: DiskInfo) -> None:
        if disk.extra.get("member_of"):
            raise BeastError(
                f"refusing: {disk.id} is {disk.extra['member_of']}; remove it from the set in Disk Utility "
                "(or with `diskutil appleRAID` / `diskutil cs`) first"
            )

    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]:
        snap = _Snapshot(self)
        infos = self._disk_infos(snap, sorted(snap.whole_disks, key=natural_key))
        system = self._system_map(snap, infos)
        out = []
        for name in sorted(infos, key=natural_key):
            d = self._make_info(name, infos[name], snap, system.get(name))
            if include_fixed or (d.removable and not d.system):
                out.append(d)
        return out

    @staticmethod
    def parse_id(device: str) -> str:
        """'/dev/disk4', '/dev/rdisk4' or 'disk4' -> 'disk4'."""
        m = _ID_RE.match(device.strip())
        if not m:
            raise BeastError(f"{device!r} is not a macOS disk (expected /dev/diskN; see `diskutil list`)")
        if m.group(2):
            raise BeastError(f"{device} is a partition; pass the whole disk (/dev/{m.group(1)})")
        return m.group(1)

    def get_disk(self, device: str) -> DiskInfo:
        name = self.parse_id(device)
        snap = _Snapshot(self)
        if name not in snap.whole_disks:
            raise BeastError(f"/dev/{name} does not exist (see `diskutil list`)")
        if name in snap.containers:
            raise BeastError(f"/dev/{name} is an APFS container (a virtual disk), not a physical drive")
        infos = self._disk_infos(snap, sorted(snap.whole_disks, key=natural_key), want=name)
        if name not in infos:
            raise BeastError(f"/dev/{name} is a virtual disk (disk image), not a physical drive")
        return self._make_info(name, infos[name], snap, self._system_map(snap, infos).get(name))

    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None:
        fresh = self.get_disk(disk.id)  # things may have changed since listing
        check_same_drive(disk, fresh)
        check_common(fresh, allow_fixed=allow_fixed)
        self._check_member(fresh)

    def prepare(self, disk: DiskInfo) -> list[str]:
        """Unmount every volume of the disk (its APFS containers first); returns the
        mountpoints that were unmounted (for the progress output)."""
        name = self.parse_id(disk.id)
        fresh = self.get_disk(disk.id)
        if fresh.system:
            raise BeastError(f"refusing: {fresh.id} {fresh.extra['system_reason']}")
        self._check_member(fresh)
        snap = _Snapshot(self)
        mounted = snap.mountpoints(name)
        try:
            for c in snap.containers_on(name):  # APFS volumes living on this disk's partitions
                self._run([DISKUTIL, "unmountDisk", "force", f"/dev/{c}"])
            self._run([DISKUTIL, "unmountDisk", "force", f"/dev/{name}"])
        except BeastError as e:
            where = ", ".join(mounted) or f"/dev/{name}"
            raise BeastError(f"cannot unmount {where} ({e}); close the programs using it and try again",
                             code="busy") from None
        left = _Snapshot(self).mountpoints(name)
        if left:
            raise BeastError(f"/dev/{name} is still mounted at {', '.join(left)}; close the programs using it "
                             "and try again", code="busy")
        return mounted

    # -- I/O ---------------------------------------------------------------------
    def open_raw(self, disk: DiskInfo, *, writable: bool) -> DarwinRawTarget:
        return DarwinRawTarget(disk.path, writable=writable, sector_size=disk.sector_size, size=disk.size)

    def rescan(self, disk: DiskInfo, timeout: float = RESCAN_TIMEOUT) -> None:
        """Wait until macOS shows the partitions now on the disk (see module docstring)."""
        name = self.parse_id(disk.id)
        with self.open_raw(disk, writable=False) as t:
            table = read_partition_table(t.read, t.size // t.sector_size)
            expected = {i: e.size * t.sector_size for i, e in table.entries.items()}
        deadline = time.monotonic() + timeout
        while True:
            seen = self._partition_sizes(name)
            if seen == expected:
                return
            if time.monotonic() > deadline:
                raise BeastError(
                    f"macOS did not pick up the new partition table on /dev/{name} "
                    f"(diskutil shows {len(seen)} of {len(expected)} partitions); unplug and reconnect the drive"
                )
            time.sleep(0.5)

    def _partition_sizes(self, name: str) -> dict[int, int]:
        """{partition number: size in bytes} as diskutil currently shows them."""
        out = {}
        for p in self._plist("list", "-plist", f"/dev/{name}").get("AllDisksAndPartitions", []):
            if p.get("DeviceIdentifier") != name:
                continue
            for part in p.get("Partitions", []):
                m = re.fullmatch(r"disk\d+s(\d+)", part.get("DeviceIdentifier", ""))
                if m:
                    out[int(m.group(1))] = int(part.get("Size", 0))
        return out

    def partition_path(self, disk: DiskInfo, index: int) -> str:
        return f"/dev/{self.parse_id(disk.id)}s{index}"

    def format_ntfs(self, disk: DiskInfo, index: int, label: str) -> None:
        raise BeastError("macOS cannot create NTFS filesystems; choose exFAT (default) or FAT32")

    # -- elevation ---------------------------------------------------------------
    def probe_installed(self, disk: DiskInfo, *, should_stop=None):
        """interfaces.PlatformBackend.probe_installed (installed_probe.py)."""
        from ..installed_probe import probe_darwin

        return probe_darwin(self, disk, should_stop=should_stop)

    def is_elevated(self) -> bool:
        return os.geteuid() == 0

    def run_elevated(self, argv: list[str]) -> OsascriptProcess:
        files = ElevationFiles()
        cmd = elevation_command(argv, files)
        out = tempfile.TemporaryFile()
        err = tempfile.TemporaryFile()
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True)
        except OSError as e:
            out.close()
            err.close()
            files.remove()
            raise BeastError(f"cannot start {cmd[0]}: {e.strerror}") from None
        return OsascriptProcess(p, cmd, files, out, err)
