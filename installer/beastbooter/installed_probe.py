"""Read the beast-booter version on a drive WITHOUT administrator rights.

The backends' probe_installed() (interfaces.py) call these. Each returns
  None                       the drive does not look like a beast-booter drive
  ProbeResult(installed)     it does, and installed.read_from_dir() read the version
  ProbeResult(None, note)    it does, but the version could not be read (note says why)
and never raises. Anything mounted for the probe is unmounted again.

All three first make a cheap check that partition 2 is a beast-booter boot
partition (label / partition name BEAST-EFI) and touch nothing otherwise.
  Linux    udev database (/run/udev/data/b<major>:<minor>), else /dev/disk/by-*
           links; read in place if mounted, else a temporary read-only udisks
           mount (`udisksctl mount --options ro --no-user-interaction`: polkit
           lets the active desktop user mount a removable drive) and unmount.
  macOS    `diskutil info -plist diskNs2`; read in place if mounted, else
           `diskutil mount readOnly` and `diskutil unmount` (no admin needed for
           an external drive).
  Windows  the volume list of the listing (disk.extra["volumes"]); readable
           only when Windows gave the boot partition a drive letter (or a
           volume path is listed).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

from . import device as devmod
from .installed import ProbeResult, read_from_dir
from .interfaces import DiskInfo
from .layout import DATA_LABEL_DEFAULT, ESP_LABEL, ESP_MARKER_PATH, ESP_PART_INDEX, GPT_NAME_ESP

# Linux worst case per drive (a hung udisksd): mount 4 + late-mount watch 2 +
# udisksctl info 1.5 + unmount 2 + 0.25 + forced unmount 2 = under 12 s.
TOOL_TIMEOUT = 10.0  # default for _run
MOUNT_TIMEOUT = 4.0
UNMOUNT_TIMEOUT = 2.0
INFO_TIMEOUT = 1.5
LATE_MOUNT_WATCH = 2.0  # after a mount timeout: how long to look for a mount udisksd finishes late
LATE_MOUNT_POLL = 0.2
UDEV_DATA = "/run/udev/data"
DEV_DISK = "/dev/disk"
UNMOUNT_RETRY_DELAY = 0.25


def _run(argv: list[str], timeout: float = TOOL_TIMEOUT) -> tuple[int, str]:
    """(exit code, stdout + stderr) of a tool; 127 not found, 124 timed out. Never raises."""
    try:
        p = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, text=True, errors="replace",
                           timeout=timeout, env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        return 127, f"{argv[0]} was not found"
    except subprocess.TimeoutExpired:
        return 124, f"{os.path.basename(argv[0])} did not finish within {timeout:g} s"
    except OSError as e:
        return 126, f"{argv[0]}: {e.strerror or e}"
    return p.returncode, "\n".join(s.strip() for s in (p.stdout, p.stderr) if s and s.strip())


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else "no details"


def _read_root(root: str, how: str) -> ProbeResult | None:
    """Read a folder that should be the boot partition. None if it holds no
    beast-booter marker; ProbeResult(None, note) if its files can't be read."""
    installed = read_from_dir(root, how)
    if installed is not None:
        return ProbeResult(installed)
    marker = os.path.join(root, ESP_MARKER_PATH)
    if not os.access(root, os.R_OK | os.X_OK) or (os.path.exists(marker) and not os.access(marker, os.R_OK)):
        return ProbeResult(None, f"the boot partition's files ({root}) can't be read without administrator rights")
    return None


def _stopped(should_stop) -> bool:
    try:
        return bool(should_stop and should_stop())
    except Exception:
        return False


def _is_esp_name(*values) -> bool:
    names = {ESP_LABEL.upper(), GPT_NAME_ESP.upper()}
    return any(isinstance(v, str) and v.strip().upper() in names for v in values)


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _linux_partition(disk: DiskInfo, index: int) -> tuple[str, str] | None:
    """(device node, "major:minor") of the disk's partition `index`, from sysfs."""
    name = disk.extra.get("name") or os.path.basename(disk.id)
    sysdir = os.path.realpath(os.path.join(devmod.SYS, "block", name))
    try:
        entries = sorted(os.listdir(sysdir))
    except OSError:
        return None
    for entry in entries:
        if _read_text(os.path.join(sysdir, entry, "partition")) == str(index):
            devnum = _read_text(os.path.join(sysdir, entry, "dev"))
            return (os.path.join(devmod.DEV, entry), devnum) if devnum else None
    return None


def _udev_properties(devnum: str) -> dict[str, str] | None:
    """The E: properties udev recorded for a block device; None without a udev database."""
    try:
        with open(os.path.join(UDEV_DATA, f"b{devnum}"), encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    out = {}
    for line in lines:
        if line.startswith("E:") and "=" in line:
            key, value = line[2:].split("=", 1)
            out[key] = value
    return out


def _linux_looks_ours(node: str, devnum: str) -> tuple[bool, str]:
    """(is a beast-booter boot partition, filesystem type or "") without opening the device."""
    props = _udev_properties(devnum)
    if props is not None:
        ours = _is_esp_name(props.get("ID_FS_LABEL"), props.get("ID_PART_ENTRY_NAME"))
        return ours, props.get("ID_FS_TYPE", "")
    real = os.path.realpath(node)
    for sub, label in (("by-label", ESP_LABEL), ("by-partlabel", GPT_NAME_ESP)):
        link = os.path.join(DEV_DISK, sub, label)
        if os.path.lexists(link) and os.path.realpath(link) == real:
            return True, ""
    return False, ""


def _linux_mountpoint(devnum: str) -> str | None:
    try:
        mounts = devmod.read_mounts()
    except Exception:  # BeastError: no /proc
        return None
    for devnums, _source, mnt in mounts:
        if devnum in devnums:
            return mnt
    return None


_UDISKS_MOUNTED = re.compile(r"^Mounted \S+ at (.+?)\.?$", re.M)
_UDISKS_MOUNTPOINTS = re.compile(r"^\s*MountPoints:[ \t]*(\S[^\n]*)$", re.M)
_TIMED_OUT = re.compile(r"timeout was reached|timed out", re.I)  # udisksctl's own D-Bus timeout


def _udisks_mountpoint(udisksctl: str, node: str) -> str | None:
    """Where udisks says the partition is mounted (also sees mounts in other mount namespaces)."""
    rc, out = _run([udisksctl, "info", "-b", node], timeout=INFO_TIMEOUT)
    m = _UDISKS_MOUNTPOINTS.search(out) if rc == 0 else None
    return m.group(1).strip() if m else None


def _late_mount(udisksctl: str, node: str, devnum: str, wait: float) -> str | None:
    """After a failed or timed-out mount: did it get mounted anyway? Watches mountinfo
    for `wait` seconds, then asks udisks once. Cleanup: should_stop does not cut it short."""
    deadline = time.monotonic() + wait
    while True:
        mnt = _linux_mountpoint(devnum)
        if mnt:
            return mnt
        if time.monotonic() >= deadline:
            break
        time.sleep(LATE_MOUNT_POLL)
    return _udisks_mountpoint(udisksctl, node)


def _udisks_unmount(udisksctl: str, node: str, should_stop=None) -> bool:
    """Unmount what we mounted: once, then lazily (it is read-only). should_stop only
    skips the pause between the two; the unmount itself always runs."""
    base = [udisksctl, "unmount", "-b", node, "--no-user-interaction"]
    for argv in (base, base + ["--force"]):
        rc, out = _run(argv, timeout=UNMOUNT_TIMEOUT)
        if rc == 0 or "not mounted" in out.lower():
            return True
        if argv is base and not _stopped(should_stop):
            time.sleep(UNMOUNT_RETRY_DELAY)
    return False


def probe_linux(backend, disk: DiskInfo, should_stop=None) -> ProbeResult | None:
    """should_stop: optional callable checked before mounting and before the unmount
    retry; once it returns True nothing more is mounted (cleanup still runs)."""
    try:
        part = _linux_partition(disk, ESP_PART_INDEX)
        if part is None:
            return None
        node, devnum = part
        ours, fstype = _linux_looks_ours(node, devnum)
    except Exception:
        return None
    if not ours:
        return None
    try:
        return _probe_linux_esp(node, devnum, fstype, should_stop)
    except Exception as e:  # never raises: the drive is ours, its version just can't be read
        return ProbeResult(None, f"could not read the boot partition {node}: {e}")


def _probe_linux_esp(node: str, devnum: str, fstype: str, should_stop=None) -> ProbeResult | None:
    mnt = _linux_mountpoint(devnum)
    if mnt:
        return _read_root(mnt, f"mounted at {mnt}")
    if fstype and fstype != "vfat":
        return ProbeResult(None, f"the boot partition {node} has no FAT filesystem ({fstype})")
    udisksctl = shutil.which("udisksctl")
    if not udisksctl:
        return ProbeResult(None, "udisksctl (udisks2) is not installed, so the boot partition can't be "
                                 "mounted without administrator rights")
    if _stopped(should_stop):
        return ProbeResult(None, "stopped before mounting the boot partition")
    rc, out = _run([udisksctl, "mount", "-b", node, "--options", "ro", "--no-user-interaction"],
                   timeout=MOUNT_TIMEOUT)
    timed_out = rc == 124 or (rc != 0 and bool(_TIMED_OUT.search(out)))
    mine = rc == 0
    result: ProbeResult | None = None
    left_mounted = False
    try:
        mnt = _linux_mountpoint(devnum)
        if rc == 0 and not mnt:
            m = _UDISKS_MOUNTED.search(out)
            mnt = m.group(1) if m else _udisks_mountpoint(udisksctl, node)
        elif rc != 0:
            # udisksd may finish a mount after its client gave up: find it and take it down
            # again. A plain refusal ("not authorized", "already mounted") mounts nothing,
            # so one look is enough there, and what is mounted then is someone else's.
            if not mnt:
                mnt = _late_mount(udisksctl, node, devnum, LATE_MOUNT_WATCH if timed_out else 0.0)
            mine = timed_out and mnt is not None
        if not mnt:
            result = ProbeResult(None, f"udisks did not mount the boot partition {node} read-only: {_last_line(out)}")
        else:
            result = _read_root(mnt, f"udisks read-only mount of {node}" if mine else f"mounted at {mnt}")
    finally:
        if mine:
            left_mounted = not _udisks_unmount(udisksctl, node, should_stop)
    if left_mounted and result is not None:
        result = ProbeResult(result.installed, f"{node} could not be unmounted again (still mounted read-only)")
    return result


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def probe_darwin(backend, disk: DiskInfo, should_stop=None) -> ProbeResult | None:
    from .platforms.darwin import DISKUTIL

    name = disk.extra.get("bsd_name") or os.path.basename(disk.id)
    ident = f"{name}s{ESP_PART_INDEX}"
    if disk.partitions and f"/dev/{ident}" not in disk.partitions:
        return None
    try:
        info = backend._plist("info", "-plist", ident)
    except Exception:
        return None
    if not _is_esp_name(info.get("VolumeName"), info.get("MediaName"), info.get("IORegistryEntryName")):
        return None
    try:
        mnt = (info.get("MountPoint") or "").strip()
        if mnt:
            return _read_root(mnt, f"mounted at {mnt}")
        if _stopped(should_stop):
            return ProbeResult(None, "stopped before mounting the boot partition")
        try:
            backend._run([DISKUTIL, "mount", "readOnly", f"/dev/{ident}"])
        except Exception as e:
            return ProbeResult(None, f"diskutil did not mount the boot partition /dev/{ident} read-only: {e}")
        result: ProbeResult | None = None
        try:
            mnt = (backend._plist("info", "-plist", ident).get("MountPoint") or "").strip()
            result = (_read_root(mnt, f"diskutil read-only mount of /dev/{ident}") if mnt else
                      ProbeResult(None, f"diskutil mounted /dev/{ident} but shows no mount point"))
        finally:
            try:
                backend._run([DISKUTIL, "unmount", f"/dev/{ident}"])
            except Exception:
                if result is not None:
                    result = ProbeResult(result.installed, f"/dev/{ident} could not be unmounted again")
        return result
    except Exception as e:
        return ProbeResult(None, f"could not read the boot partition /dev/{ident}: {e}")


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def probe_windows(backend, disk: DiskInfo, should_stop=None) -> ProbeResult | None:
    """Mounts nothing; should_stop is accepted for symmetry."""
    try:
        volumes = [v for v in (disk.extra.get("volumes") or []) if isinstance(v, dict)]
        esp = sorted((v for v in volumes if _is_esp_name(v.get("label"))),
                     key=lambda v: v.get("partition") != ESP_PART_INDEX)
        data = any(str(v.get("label") or "").strip().upper() == DATA_LABEL_DEFAULT for v in volumes)
    except Exception:
        return None
    if not esp and not data:
        return None
    try:
        tried = False
        for v in esp:
            letter, path = v.get("letter"), v.get("path")  # "path": \\?\Volume{GUID}\ if the listing has it
            for root, how in ((f"{letter}:\\" if letter else "", f"drive {letter}:"), (path or "", "volume path")):
                if root:
                    tried = True
                    result = _read_root(root if root.endswith("\\") else root + "\\", how)
                    if result is not None:
                        return result
        return None if tried else ProbeResult(None, "the boot partition has no drive letter")
    except Exception as e:
        return ProbeResult(None, f"could not read the boot partition: {e}")
