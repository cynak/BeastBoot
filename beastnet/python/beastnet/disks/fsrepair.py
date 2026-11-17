"""Check and repair a filesystem that keeps a copy's progress (docs/DISK_TOOLS.md s.6).

After a power cut the FAT32/exFAT data partition of the stick, or a destination opened
with ``use_disk``, is dirty, and the kernel may make it read-only at the first
inconsistency it meets (the copy then failed with "Read-only file system"). Only two
kinds of filesystem are ever checked, each with its own checker in automatic mode:

* the BeastBoot stick's own data partition: ``check_stick`` when Disk tools start,
  before the guard is applied. Dirty = the kernel logged "Volume was not properly
  unmounted" for it this boot, or it is mounted read-only although init mounted it
  read-write. It is unmounted, checked and mounted again with init's options;
* a disk the user confirmed for writing with the typed serial (``use_disk``):
  ``check_dest`` after the guard made it writable and before it is mounted. Dirty = the
  volume's own flag (exFAT VolumeDirty; FAT32/FAT16 the Linux state byte or the
  Windows clean-shutdown bit in FAT[1]).

Never a source, never a disk opened read-only to read an image from, never any other
disk: those functions are only called for the two cases above.

| fs | what happens |
|---|---|
| vfat (FAT32/16) | ``fsck.fat -a -w`` |
| exfat | ``fsck.exfat -p`` |
| ext4 | nothing to run: mounting read-write replays the journal |
| xfs | nothing to run: mounting replays the log (xfs_repair has no safe automatic mode) |
| ntfs | not repaired (no safe checker on Linux): refused with "run chkdsk /f in Windows" |

Events: ``fs repair dev=<dev> fs=<type> result=<fixed|clean|refused|failed>``. Plain-words
notes go to the screen; a refusal is ``disk-refused`` with what the user can do.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass

from .. import errors as E
from ..errors import BeastNetError

CHECKERS = {
    "vfat": (["fsck.fat", "-a", "-w"], (0, 1)),
    "exfat": (["fsck.exfat", "-p"], (0, 1)),
}
REPLAYED = {"ext4", "xfs"}          # the mount itself replays the journal/log
NTFS_HINT = "BeastBoot does not repair NTFS: run chkdsk /f on it in Windows, then try again."
STICK_OPTS = "rw,noatime,nosuid,nodev,noexec"   # as beastnet/rootfs/init mounts the data partition
_DIRTY_RX = re.compile(r"(?:FAT-fs|exFAT-fs) \((?P<dev>[^)]+)\): .*(?:not properly unmounted|"
                       r"set read-only)", re.I)
_REPAIRED: set[str] = set()         # devices checked this boot (the kernel log keeps the warning)


@dataclass
class Mount:
    device: str
    mountpoint: str
    fs_type: str
    options: list[str]


def mount_of(ctx, path: str) -> Mount | None:
    """The mount that holds ``path`` (longest mount point prefix in /proc/mounts)."""
    try:
        with open(os.path.join(ctx.paths.proc, "mounts"), encoding="utf-8", errors="replace") as f:
            rows = [line.split() for line in f if line.strip()]
    except OSError:
        return None
    path = os.path.abspath(path)
    best = None
    for r in rows:
        if len(r) < 4:
            continue
        mp = r[1].replace("\\040", " ")
        if path == mp or path.startswith(mp.rstrip("/") + "/"):
            if best is None or len(mp) > len(best.mountpoint):
                best = Mount(r[0], mp, r[2], r[3].split(","))
    return best


def _kernel_log(ctx) -> str:
    path = getattr(ctx.paths, "kernel_log", None)
    dev = getattr(ctx.paths, "dev", "") or "/dev"
    if not path and not os.path.exists(os.path.join(dev, "kmsg")):
        return ""
    from ..firmware import read_kernel_log
    return read_kernel_log(path, dev_dir=dev)


def logged_dirty(ctx, device: str) -> bool:
    name = os.path.basename(device)
    return any(m.group("dev") == name for m in _DIRTY_RX.finditer(_kernel_log(ctx)))


def volume_dirty(device: str, fs_type: str) -> bool:
    """The filesystem's own "not cleanly unmounted" flag, read from the unmounted device."""
    try:
        with open(device, "rb") as f:
            bs = f.read(512)
            if fs_type == "exfat":
                return len(bs) >= 108 and bool(struct.unpack_from("<H", bs, 106)[0] & 0x0002)
            if fs_type != "vfat" or len(bs) < 90:
                return False
            bps, reserved = struct.unpack_from("<HH", bs, 11)
            fat16_size = struct.unpack_from("<H", bs, 22)[0]
            fat32 = fat16_size == 0
            state = bs[65] if fat32 else bs[37]          # Linux: FAT_STATE_DIRTY = 0x01
            f.seek(reserved * bps)
            fat = f.read(8)
    except (OSError, struct.error):
        return False
    if state & 0x01:
        return True
    if fat32 and len(fat) >= 8:                          # Windows: FAT[1] bit 27 = clean shutdown
        return not struct.unpack_from("<I", fat, 4)[0] & 0x08000000
    if not fat32 and len(fat) >= 4:                      # FAT16: FAT[1] bit 15
        return not struct.unpack_from("<H", fat, 2)[0] & 0x8000
    return False


def _event(ctx, device: str, fs_type: str, result: str) -> None:
    ctx.reporter.emit("fs repair", f"dev={device}", f"fs={fs_type}", f"result={result}")


def _check(ctx, device: str, fs_type: str, what: str, why: str, say) -> list[str]:
    """Run the checker on the unmounted ``device``; returns notes or raises disk-refused."""
    if fs_type in ("ntfs", "ntfs3"):
        _event(ctx, device, fs_type, "refused")
        raise BeastNetError(E.DISK_REFUSED, f"{what} ({device}) {why}", NTFS_HINT)
    argv, ok = CHECKERS[fs_type]
    if say:
        say(f"{what} ({device}) {why}. Checking and repairing it with {argv[0]}...")
    cp = ctx.system.runner.run([*argv, device], timeout=3600)
    if cp.returncode not in ok:
        _event(ctx, device, fs_type, "failed")
        last = ((cp.stderr or cp.stdout or "").strip().splitlines() or [f"exit {cp.returncode}"])[-1]
        raise BeastNetError(E.DISK_REFUSED, f"{what} ({device}) {why} and could not be repaired: {last[:160]}",
                            "Check it on another computer (Windows: chkdsk /f), then try again.")
    _REPAIRED.add(device)
    _event(ctx, device, fs_type, "fixed" if cp.returncode else "clean")
    return [f"{what} {why}; {argv[0]} checked it ({'errors fixed' if cp.returncode else 'no errors found'})."]


def check_stick(ctx, say=None) -> tuple[list[str], str]:
    """The stick's data partition: (notes, problem). ``problem`` is set when it is dirty or
    read-only and could not be repaired; copies that keep a mapfile there then refuse."""
    m = mount_of(ctx, ctx.paths.data)
    if m is None or m.mountpoint != os.path.abspath(ctx.paths.data) or m.device in _REPAIRED:
        return [], ""
    if m.fs_type in ("tmpfs", "ramfs"):
        return [], ""
    why = ("is read-only (the kernel stopped writing to it after an error)" if "ro" in m.options
           else "was not shut down cleanly (power cut or unplugged)" if logged_dirty(ctx, m.device) else "")
    if not why:
        return [], ""
    what = "The BeastBoot drive"
    if m.fs_type in REPLAYED:
        return [], ""
    run = ctx.system.runner.run
    try:
        run(["sync"], timeout=600)
        if run(["umount", m.mountpoint], timeout=600).returncode != 0:
            _event(ctx, m.device, m.fs_type, "failed")
            raise BeastNetError(E.DISK_REFUSED, f"{what} ({m.device}) {why} but is in use, so it cannot be checked",
                                "Restart the computer and open Disk tools first.")
        try:
            notes = _check(ctx, m.device, m.fs_type, what, why, say)
        finally:
            back = run(["mount", "-t", m.fs_type, "-o", STICK_OPTS, m.device, m.mountpoint], timeout=600)
        if back.returncode != 0 or not os.access(m.mountpoint, os.W_OK):
            raise BeastNetError(E.DISK_REFUSED, f"{what} ({m.device}) could not be mounted read-write again",
                                "Restart the computer; if it stays read-only, check it on another computer.")
        return notes, ""
    except BeastNetError as e:
        return [], e.text + (" " + e.hint if e.hint else "")


def check_dest(ctx, device: str, fs_type: str, what: str, say=None) -> list[str]:
    """A disk confirmed for writing (made writable by the guard, not mounted yet)."""
    if fs_type in REPLAYED or device in _REPAIRED:
        return []
    if fs_type not in CHECKERS and fs_type not in ("ntfs", "ntfs3"):
        return []
    if fs_type in ("ntfs", "ntfs3"):
        return []   # ntfs3 refuses to mount a dirty volume read-write; its mount error says so
    if not volume_dirty(device, fs_type):
        return []
    return _check(ctx, device, fs_type, what, "was not shut down cleanly (power cut or unplugged)", say)


__all__ = ["CHECKERS", "Mount", "check_dest", "check_stick", "logged_dirty", "mount_of", "volume_dirty"]
