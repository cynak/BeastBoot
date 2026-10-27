"""Helpers shared by the platform backends: common safety rules, elevated processes."""

from __future__ import annotations

import os
import re
import subprocess
import sys

from ..errors import BeastError
from ..interfaces import DiskInfo
from ..layout import SECTOR_SIZE
from ..util import human_size

# Exit codes an ElevatedProcess reports when the elevation itself did not happen.
# They are pkexec's documented codes; the macOS and Windows backends map their
# equivalents onto them, so the GUI has one rule for every OS.
ELEVATION_CANCELLED = 126  # the user dismissed the password / UAC prompt
ELEVATION_FAILED = 127  # not authorized, or no way to ask (no polkit agent, ...)

BUSES = ("usb", "sata", "nvme", "sd", "scsi", "virtual", "unknown")


def describe(disk: DiskInfo) -> str:
    kind = "removable" if disk.removable else "fixed"
    model = disk.model or "unknown model"
    return f"{disk.id}: {model}, {human_size(disk.size)} ({disk.bus}, {kind})"


def program_paths() -> list[str]:
    """Files the running installer is executing from (interpreter + this package)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../beastbooter
    paths = [here]
    if sys.executable:
        paths.append(sys.executable)
    return [os.path.realpath(p) for p in paths]


def running_from(mountpoints, paths=None, *, pathmod=os.path) -> str | None:
    """The mountpoint (of the target disk) that holds the running program, if any.

    Writing the disk the installer runs from would pull its own files out from
    under it (on Windows a forced dismount crashes the process mid-write).
    """
    paths = program_paths() if paths is None else paths
    for mp in mountpoints:
        if not mp:
            continue
        base = pathmod.normcase(pathmod.normpath(mp))
        for p in paths:
            q = pathmod.normcase(pathmod.normpath(p))
            try:
                if pathmod.commonpath([base, q]) == base:
                    return mp
            except ValueError:  # different drives (Windows)
                continue
    return None


def check_same_drive(selected: DiskInfo, fresh: DiskInfo) -> None:
    """Refuse if the device name now belongs to a different drive than the one selected
    (sticks swapped: the new one gets the same /dev/sdb, /dev/disk4 or disk number)."""
    if (selected.size, selected.model) != (fresh.size, fresh.model):
        raise BeastError(
            f"{fresh.id} changed since it was selected (was {selected.model or 'unknown model'}, "
            f"{human_size(selected.size)}; now {fresh.model or 'unknown model'}, {human_size(fresh.size)}); "
            "select the drive again"
        )


def check_common(disk: DiskInfo, *, allow_fixed: bool, paths=None, pathmod=os.path) -> None:
    """The rules every backend applies once its own OS-specific checks passed."""
    if disk.system:
        reason = disk.extra.get("system_reason") or "holds the running operating system, its boot volume or swap"
        raise BeastError(f"refusing: {disk.id} {reason}")
    mp = running_from(disk.mountpoints, paths, pathmod=pathmod)
    if mp:
        raise BeastError(
            f"refusing: beast-boot itself is running from {disk.id} ({mp}); "
            "start it from another drive to write this one"
        )
    if disk.read_only:
        raise BeastError(f"{disk.id} is read-only (write-protect switch?)")
    if disk.sector_size != SECTOR_SIZE:
        raise BeastError(
            f"{disk.id} has {disk.sector_size}-byte sectors; only {SECTOR_SIZE}-byte sectors are supported"
        )
    if disk.size <= 0:
        raise BeastError(f"{disk.id} has no medium (size 0)")
    if not disk.removable and not allow_fixed:
        raise BeastError(
            f"refusing: {describe(disk)} is not a removable or external drive; "
            "if you are sure it is the right disk, pass --allow-fixed-disk"
        )


def natural_key(s: str):
    """Sort 'disk2' before 'disk10', 'sdb' before 'sdc'."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


class PopenProcess:
    """ElevatedProcess backed by subprocess.Popen (Linux pkexec/sudo, macOS osascript).

    wait(timeout) raises TimeoutError when the timeout expires. cancel() is best
    effort: the elevated child usually runs as root and an unprivileged parent
    may not be allowed to signal it.
    """

    def __init__(self, popen: subprocess.Popen, argv: list[str]):
        self._p = popen
        self.argv = list(argv)  # the full command that was started (for logs)
        self.returncode: int | None = None

    @property
    def pid(self) -> int:
        return self._p.pid

    def _finish(self, rc: int) -> int:
        return rc

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        rc = self._p.poll()
        if rc is None:
            return None
        self.returncode = self._finish(rc)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        try:
            rc = self._p.wait(timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"elevated process still running after {timeout} s") from None
        self.returncode = self._finish(rc)
        return self.returncode

    def cancel(self) -> None:
        try:
            self._p.terminate()
        except OSError:  # already gone, or not ours to signal (runs as root)
            pass
