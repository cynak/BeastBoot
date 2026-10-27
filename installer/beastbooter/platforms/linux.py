"""Linux backend: sysfs / procfs inspection (device.py) and raw I/O on /dev/sdX.

Listing walks /sys/block; the safety rules build on device.py's helpers
(inspect_disk, read_mounts, read_swaps, backing_disks, _exclusive_open), so
tests point device.SYS / DEV / PROC_* at a fake tree exactly as for device.py.

A disk is refused when it
  * holds a system filesystem (SYSTEM_MOUNTPOINTS: /, /boot, /boot/efi as in
    device.py, plus /usr, /var, /home, ... and the places live systems mount
    their boot medium, e.g. /cdrom or /run/live/medium), directly or through
    device-mapper/LVM/LUKS/RAID or a loop device whose backing file is on it;
  * holds active swap: a swap partition, or a swap file on one of its
    filesystems;
  * is held by device-mapper/LVM/LUKS/RAID (sysfs holders), or a loop device
    uses a file on it (a mounted ISO, a live system's squashfs);
  * holds the running beast-boot itself (platforms/common.check_common).
Being mounted is not a refusal: prepare() unmounts every filesystem of the
selected drive (desktop auto-mounts under /media or /run/media through
`udisksctl unmount`, so udisks and the desktop stay in step, falling back to
`umount`; mounts made by hand, e.g. /mnt/stick, with `umount`) and returns
their mountpoints for the progress output. A busy mount is retried for a few
seconds; if it stays busy, or the kernel still refuses exclusive access
afterwards, prepare fails with code "busy" and names what holds the drive
(find_users: processes with open files or their current folder on it, loop
devices of disk images on it, device-mapper/RAID holders, mounts in other
mount namespaces). (macOS and Windows dismount the volumes of the selected
drive the same way.)

Some USB sticks stop responding right after their filesystem is unmounted
(when warm, or after a long time mounted): they report "medium not present"
and the kernel sets the disk's size to 0. prepare() therefore checks the
medium (device.medium_sectors) after unmounting; if it is gone it asks the
kernel to check again (device.request_rescan) and waits up to MEDIUM_TIMEOUT
for the drive to come back with its old size (safe: prepare runs before the
writes it guards; commands.py says whether earlier steps wrote already, as
install's second prepare does after the partition table and mkfs.ntfs). It
also does so when the exclusive open reports no medium. It never waits for or
accepts another device that shows
up under the same name (device.disk_identity: sysfs device, devnum, model,
serial, WWN). Otherwise it fails with code "device-vanished"
(commands.py words the message). medium_gone() lets commands.py tell such a
drive from an ordinary I/O error later on, and kernel_log() records what the
kernel says about the disk (/dev/kmsg) so a failure can show it.

"removable" means removable media OR attached via USB or as an SD card,
because many USB sticks and SSDs report removable=0 (DiskInfo.extra keeps the
raw sysfs flag as "removable_media"). The O_EXCL busy probe needs root, so
check_safe() runs it only when elevated and nothing is mounted; prepare()
always runs it after unmounting and keeps that O_EXCL fd open until release()
(called by rescan() and format_ntfs(), and by commands.py when it gives up):
while it is open the kernel refuses to mount or claim any partition of the
disk, so the desktop cannot mount the drive again while it is written.

Raw I/O: /dev/sdX is opened O_RDWR (the page cache accepts any offset) and,
while writable, locked with flock(LOCK_EX) as systemd documents for programs
that modify block devices (https://systemd.io/BLOCK_DEVICE_LOCKING/): udev then
does not probe or re-read the half-written disk. Closing it lets udev see the
change; rescan() then makes the kernel re-read the table (BLKRRPART ioctl,
falling back to `partx -u`) and waits for udev (`udevadm settle`).
"""

from __future__ import annotations

import errno
import os
import re
import shutil
import subprocess
import time

from .. import device as devmod
from ..blockio import FdTarget
from ..errors import BeastError
from ..fs import make_data_fs
from ..interfaces import DiskInfo
from ..util import human_size, run
from .common import PopenProcess, check_common, check_same_drive, natural_key

BLKRRPART = 0x125F  # _IO(0x12, 95): re-read the partition table
LOCK_TIMEOUT = 10.0  # seconds to wait for udev to drop its shared lock
PROC = "/proc"
KMSG = "/dev/kmsg"
STATE_DIR = "/var/lib/beast-booter"  # as root (an update's recovery copy, commands._UpdateRecords)
# Pauses between attempts while a mount or the whole disk is busy (about 4 s in all):
# a file manager or udev often lets go within a second or two.
BUSY_RETRY_DELAYS = (0.25, 0.5, 1.0, 1.0, 1.5)
MEDIUM_TIMEOUT = 10.0  # seconds to wait for a drive that reported "no medium" to come back
UDISKSCTL_TIMEOUT = 30.0
AUTOMOUNT_ROOTS = ("/media/", "/run/media/")  # where udisks mounts (the desktop's automounts)
MAX_USERS = 8  # holders named in a "busy" message

# A disk holding one of these belongs to the running system (exact mountpoints).
SYSTEM_MOUNTPOINTS = (
    *devmod.SYSTEM_MOUNTPOINTS, "/efi", "/boot/firmware", "/usr", "/var", "/home", "/srv", "/opt", "/root",
    "/nix",
    # Live systems keep their boot medium mounted: casper (Ubuntu), live-boot (Debian),
    # dracut (Fedora), archiso (Arch).
    "/cdrom", "/isodevice", "/rofs", "/run/live/medium", "/run/live/rootfs", "/run/initramfs/live",
    "/run/initramfs/isoscan", "/run/archiso/bootmnt", "/run/archiso/img_dev",
)


def _file_devnum(path: str) -> str | None:
    """'major:minor' of the filesystem a file lives on (its st_dev), or None."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"


def _loop_backing_file(name: str) -> str | None:
    """The file behind loop device `name` (None: not a loop device, or not attached)."""
    if not name.startswith("loop"):
        return None
    path = devmod._read(os.path.join(devmod.SYS, "block", name, "loop", "backing_file"))
    return path.removesuffix(" (deleted)") or None


def _swap_files() -> list[str]:
    """Active swap files (device.read_swaps covers swap partitions)."""
    out = []
    try:
        with open(devmod.PROC_SWAPS, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "file":
            out.append(devmod._unescape_mount(fields[0]))
    return out


def _bus(name: str, sysdir: str) -> str:
    """Bus from the device's sysfs path (…/usb2/2-1/…/block/sdb, …/ata3/…, …/nvme/…)."""
    if name.startswith("nvme"):
        return "nvme"
    if name.startswith("mmcblk"):
        # SD cards say "SD"; soldered-on eMMC says "MMC".
        return "sd" if devmod._read(os.path.join(sysdir, "device", "type")) == "SD" else "unknown"
    rel = os.path.relpath(sysdir, os.path.realpath(devmod.SYS)).split(os.sep)
    if any(p.startswith("usb") for p in rel):
        return "usb"
    if (name.startswith(("loop", "nbd", "zd", "rbd", "vd", "xvd"))
            or "virtual" in rel or any(p.startswith("virtio") for p in rel)):
        return "virtual"
    if any(re.fullmatch(r"ata\d+", p) for p in rel):
        return "sata"
    if any(re.fullmatch(r"host\d+", p) for p in rel):
        return "scsi"
    return "unknown"


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def _run_quiet(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    """Run a tool with a time limit (util.run has none); a failure to start or a
    timeout is a non-zero result, never an exception."""
    try:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 124, "", str(e))


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _under(path: str, roots) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _detail(proc: subprocess.CompletedProcess) -> str:
    return (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"


def find_users(nodes, devnums, mountpoints, *, limit: int = MAX_USERS) -> list[str]:
    """Processes that keep the drive busy, for "busy" messages: an open file or the
    current folder (cwd, root, executable) under one of `mountpoints`, the device
    nodes themselves open (`nodes`: a disk utility, a VM), or a mount of the drive
    (`devnums`) in another mount namespace (a snap, flatpak or container keeps its
    own copy of the desktop's mounts). Needs root to see other users' processes;
    best effort, never raises."""
    out: list[str] = []
    nodes, devnums, mountpoints = set(nodes), set(devnums), list(mountpoints)
    own_ns = _readlink(os.path.join(PROC, "self", "ns", "mnt"))
    seen_ns = {own_ns}
    try:
        pids = sorted((p for p in os.listdir(PROC) if p.isdigit()), key=int)
    except OSError:
        return out
    for pid in pids:
        if len(out) >= limit:
            break
        if int(pid) == os.getpid():
            continue
        base = os.path.join(PROC, pid)
        who = f"process {pid} ({devmod._read(os.path.join(base, 'comm')) or '?'})"
        found = None
        for link, what in (("cwd", "has its current folder in"), ("root", "runs inside"), ("exe", "runs")):
            target = _readlink(os.path.join(base, link))
            if target and mountpoints and _under(target, mountpoints):
                found = f"{who} {what} {target}"
                break
        if found is None:
            try:
                fds = sorted(os.listdir(os.path.join(base, "fd")), key=lambda x: int(x) if x.isdigit() else -1)
            except OSError:
                fds = []
            for fd in fds:
                target = _readlink(os.path.join(base, "fd", fd))
                if target and (target in nodes or (mountpoints and _under(target, mountpoints))):
                    found = f"{who} has {target} open"
                    break
        if found:
            out.append(found)
        ns = _readlink(os.path.join(base, "ns", "mnt"))
        if ns and own_ns and ns not in seen_ns and len(out) < limit:
            seen_ns.add(ns)
            try:
                mounts = devmod.read_mounts(os.path.join(base, "mountinfo"))
            except BeastError:
                mounts = []
            for mount_devnums, _src, mnt in mounts:
                if mount_devnums & devnums:
                    out.append(f"{who} still has it mounted at {mnt} in its own mount namespace "
                               "(a snap, flatpak or container app)")
                    break
    return out


def kernel_patterns(name: str, sysdir: str) -> list[str]:
    """Regexes for kernel messages about disk `name` (sysfs path `sysdir`): the
    disk and its partitions (sdb, [sdb], sdb1), its SCSI address (sd 6:0:0:0),
    SCSI host (scsi host6) and USB port (usb 2-1, usb-storage 2-1:1.0)."""
    pats = [rf"\b{re.escape(name)}(?:p?\d+)?\b"]
    port = None
    for part in sysdir.split(os.sep):
        if re.fullmatch(r"\d+-\d+(?:\.\d+)*", part):
            port = part  # the last one is the drive's own port (the others are hubs)
        elif re.fullmatch(r"\d+:\d+:\d+:\d+", part):
            pats.append(rf"\b{re.escape(part)}\b")
        elif m := re.fullmatch(r"host(\d+)", part):
            pats.append(rf"\bscsi host{m.group(1)}\b")
    if port:
        pats += [rf"\busb {re.escape(port)}(?![\d.])", rf"\b{re.escape(port)}:\d"]
    return pats


def _kmsg_text(raw: str) -> str | None:
    """The text of one /dev/kmsg record line ("prio,seq,usec,flags;text"),
    None for its continuation lines (" SUBSYSTEM=...")."""
    if not raw.strip() or raw.startswith(" "):
        return None
    head, sep, text = raw.partition(";")
    if not sep:
        return raw.strip()
    fields = head.split(",")
    try:
        return f"[{int(fields[2]) / 1e6:.1f}] {text.strip()}"
    except (IndexError, ValueError):
        return text.strip()


class KernelLog:
    """Kernel messages about one disk since open() (/dev/kmsg read without
    blocking, from its end at open time). Reading kmsg needs root on most
    systems; everything here is best effort and never raises."""

    MAX_LINES = 200
    MAX_READS = 20000

    def __init__(self, fd: int, patterns: list[str]):
        self.fd = fd
        self.patterns = [re.compile(p) for p in patterns]
        self._lines: list[str] = []

    @classmethod
    def open(cls, patterns: list[str], path: str | None = None) -> KernelLog | None:
        try:
            fd = os.open(path or KMSG, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            os.lseek(fd, 0, os.SEEK_END)  # only what happens from now on
        except OSError:
            pass
        return cls(fd, patterns)

    def lines(self) -> list[str]:
        """The matching messages so far (oldest first, at most MAX_LINES)."""
        for _ in range(self.MAX_READS):
            if self.fd < 0:
                break
            try:
                chunk = os.read(self.fd, 8192)  # kmsg: one record per read
            except BlockingIOError:
                break
            except OSError as e:
                if e.errno == errno.EPIPE:
                    continue  # records were overwritten before we read them: go on with the next
                break
            if not chunk:
                break
            for raw in chunk.decode("utf-8", "replace").splitlines():
                text = _kmsg_text(raw)
                if text and any(p.search(text) for p in self.patterns):
                    self._lines.append(text)
        del self._lines[:-self.MAX_LINES]
        return list(self._lines)

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


class _State:
    """One snapshot of mounts, swaps and loop devices, shared by all disks of a listing."""

    def __init__(self):
        self.mounts = devmod.read_mounts()
        self.swaps = devmod.read_swaps()
        self.swap_files = _swap_files()
        self._backing: dict[str, set[str]] = {}

    def backing(self, devnum: str) -> set[str]:
        """Whole disks a block device lives on: through partitions and dm/md slaves
        (device.backing_disks) and, for a loop device, the disk holding its backing file."""
        if devnum not in self._backing:
            self._backing[devnum] = set()  # placeholder: stops loop-on-loop cycles
            disks = set()
            for name in devmod.backing_disks(devnum):
                disks.add(name)
                backing_file = _loop_backing_file(name)
                if backing_file:
                    disks |= self.disks_of_file(backing_file)
            self._backing[devnum] = disks
        return self._backing[devnum]

    def mount_of(self, path: str) -> tuple[set[str], str, str] | None:
        """The mount a path is on: the longest mountpoint above it (the last one if stacked)."""
        best = None
        for m in self.mounts:
            mnt = m[2]
            if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
                if best is None or len(mnt) >= len(best[2]):
                    best = m
        return best

    def disks_of_file(self, path: str) -> set[str]:
        """Whole disks holding a file (a swap file, a loop device's image)."""
        devnums: set[str] = set()
        dn = _file_devnum(path)
        if dn:
            devnums.add(dn)
            for mount_devnums, _source, _mnt in self.mounts:
                if dn in mount_devnums:  # btrfs: st_dev is anonymous, the mount names the device
                    devnums |= mount_devnums
        else:
            m = self.mount_of(path)
            if m:
                devnums |= m[0]
        out: set[str] = set()
        for d in devnums:
            out |= self.backing(d)
        return out

    def system_reason(self, name: str) -> str | None:
        for devnums, source, mnt in self.mounts:
            if mnt in SYSTEM_MOUNTPOINTS and any(name in self.backing(dn) for dn in devnums):
                return f"holds the system's {mnt} filesystem ({source})"
        for dn, path in self.swaps:
            if name in self.backing(dn):
                return f"is in use as swap ({path})"
        for path in self.swap_files:
            if name in self.disks_of_file(path):
                return f"holds an active swap file ({path})"
        return None

    def loops_on(self, name: str) -> list[tuple[str, str]]:
        """[(loop device, backing file)] for attached loop devices whose file is on the disk."""
        out = []
        block = os.path.join(devmod.SYS, "block")
        for loop in sorted(os.listdir(block), key=natural_key):
            backing_file = _loop_backing_file(loop)
            if backing_file and name in self.disks_of_file(backing_file):
                out.append((os.path.join(devmod.DEV, loop), backing_file))
        return out

    def mountpoints(self, name: str) -> list[str]:
        """Mountpoints of filesystems on the disk (directly or through dm/LUKS/RAID/loop)."""
        out = []
        for devnums, _source, mnt in self.mounts:
            if any(name in self.backing(dn) for dn in devnums) and mnt not in out:
                out.append(mnt)
        return out


class LinuxDiskTarget(FdTarget):
    """A whole-disk block device; flock(LOCK_EX) held while open for writing."""

    def __init__(self, path: str, *, writable: bool, sector_size: int):
        super().__init__(path, writable=writable, sector_size=sector_size,
                         device_hint=" (run as root, e.g. with sudo)")
        if writable:
            try:
                self._lock()
            except BaseException:
                self.close()
                raise

    def _lock(self) -> None:
        import fcntl  # POSIX only: imported here so this module imports on Windows too

        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as e:
                if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise BeastError(f"cannot lock {self.path}: {e.strerror}") from None
            if time.monotonic() > deadline:
                raise BeastError(f"{self.path} is locked by another program (udev, a partition editor?)")
            time.sleep(0.1)

    def flush(self) -> None:
        if self.writable:
            os.fsync(self.fd)  # on a block device this also flushes the drive's write cache


def _users_text(users: list[str]) -> str:
    return f"in use by: {'; '.join(users)}; " if users else ""


def _blkrrpart(path: str) -> None:
    """BLKRRPART on the whole disk, holding flock(LOCK_EX) like sfdisk does, so udev
    does not probe (open) the partitions while the kernel replaces them."""
    import fcntl  # POSIX only (see LinuxDiskTarget._lock)

    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        deadline = time.monotonic() + 2.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    break  # best effort: re-read anyway
                time.sleep(0.05)
        fcntl.ioctl(fd, BLKRRPART)
    finally:
        os.close(fd)


def elevation_command(argv: list[str], env=None, which=shutil.which) -> list[str]:
    """The command that runs argv as root.

    In a graphical session (DISPLAY or WAYLAND_DISPLAY set) pkexec is used: the
    desktop's polkit agent shows a password dialog. pkexec exits 126 when the
    user dismisses it and 127 when no agent is running / not authorized.

    Without a graphical session sudo is used. sudo asks for the password on the
    controlling terminal; with no terminal (and no SUDO_ASKPASS helper) it fails
    with exit 1, so the non-GUI case is really meant for the CLI in a terminal.

    pkexec and sudo reset the environment and pkexec may change the working
    directory, so every path in argv must be absolute (argv[0] is resolved here).
    """
    env = os.environ if env is None else env
    if not argv:
        raise ValueError("empty command")
    prog = argv[0]
    if not os.path.isabs(prog):
        prog = which(prog) or prog
    rest = list(argv[1:])
    graphical = bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))
    pkexec = which("pkexec") if graphical else None
    if pkexec:
        return [pkexec, prog, *rest]
    sudo = which("sudo")
    if sudo:
        cmd = [sudo]
        if env.get("SUDO_ASKPASS"):
            cmd.append("-A")
        return [*cmd, "--", prog, *rest]
    raise BeastError("cannot get root rights: neither pkexec nor sudo was found; run beast-boot as root")


class LinuxBackend:
    name = "linux"
    notes: list[str] | tuple[str, ...] = ()  # what the last prepare() has to tell (commands.prepare_device)
    medium_returned = False  # the last prepare() saw the drive stop responding and come back
    _held: int | None = None  # O_EXCL fd on the whole disk, from prepare() until release()
    _selected: dict[str, dict[str, str] | None] | None = None  # disk name -> disk_identity at check_safe()

    # -- listing ---------------------------------------------------------------
    def _info(self, bd: devmod.BlockDisk, state: _State) -> DiskInfo:
        bus = _bus(bd.name, bd.sysdir)
        reason = state.system_reason(bd.name)
        parts = sorted(bd.partitions, key=natural_key)
        return DiskInfo(
            id=bd.node,
            path=bd.node,
            model=bd.model,
            size=bd.size_bytes,
            sector_size=bd.logical_block_size,
            bus=bus,
            removable=bd.removable or bus in ("usb", "sd"),
            system=reason is not None,
            read_only=bd.readonly,
            mountpoints=tuple(state.mountpoints(bd.name)),
            partitions=tuple(os.path.join(devmod.DEV, p) for p in parts),
            extra={"name": bd.name, "devnum": bd.devnum, "removable_media": bd.removable,
                   "system_reason": reason},
        )

    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]:
        state = _State()
        out = []
        block = os.path.join(devmod.SYS, "block")
        for name in sorted(os.listdir(block), key=natural_key):
            if name.startswith(devmod.REFUSED_PREFIXES):
                continue
            try:
                bd = devmod.inspect_disk(os.path.join(devmod.DEV, name))
            except BeastError:
                continue
            if bd.size_bytes == 0:  # unused loop device, card reader without a card
                continue
            info = self._info(bd, state)
            if include_fixed or (info.removable and not info.system):
                out.append(info)
        return out

    def get_disk(self, device: str) -> DiskInfo:
        path = device if "/" in device else os.path.join(devmod.DEV, device)
        return self._info(devmod.inspect_disk(path), _State())

    # -- safety ------------------------------------------------------------------
    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None:
        bd = devmod.inspect_disk(disk.id)  # fresh: things may have changed since listing
        state = _State()
        fresh = self._info(bd, state)
        check_same_drive(disk, fresh)
        if self._selected is None:
            self._selected = {}
        self._selected[bd.name] = devmod.disk_identity(bd.name)  # prepare() makes sure it is still this drive
        self._check_unused(bd, state)
        check_common(fresh, allow_fixed=allow_fixed)
        if self.is_elevated() and not self._mounted(bd, state):
            os.close(self._probe_exclusive(bd, []))

    def _check_unused(self, bd: devmod.BlockDisk, state: _State) -> None:
        """Refuse if the system, swap, device-mapper/RAID or a loop device uses the disk
        (plain mounts are fine: prepare() unmounts them)."""
        reason = state.system_reason(bd.name)
        if reason:
            raise BeastError(f"refusing: {bd.node} {reason}")
        for name in [bd.name, *bd.partitions]:
            base = bd.sysdir if name == bd.name else os.path.join(bd.sysdir, name)
            hdir = os.path.join(base, "holders")
            holders = sorted(os.listdir(hdir)) if os.path.isdir(hdir) else []
            if holders:
                raise BeastError(
                    f"refusing: {os.path.join(devmod.DEV, name)} is in use by {', '.join(holders)} "
                    "(device-mapper/LVM/LUKS/RAID); deactivate it first"
                )
        loops = state.loops_on(bd.name)
        if loops:
            loop, backing_file = loops[0]
            raise BeastError(
                f"refusing: {loop} uses {backing_file}, a file on {bd.node} (a mounted disk image?); "
                f"unmount it and detach {loop} first"
            )

    @staticmethod
    def _ours(bd: devmod.BlockDisk) -> dict[str, str]:
        """devnum -> node for the disk and its partitions."""
        return {bd.devnum: bd.node} | {dn: os.path.join(devmod.DEV, n) for n, dn in bd.partitions.items()}

    def _mounted(self, bd: devmod.BlockDisk, state: _State) -> list[str]:
        return [mnt for mnt, _src in self._mounts(bd, state)]

    def _mounts(self, bd: devmod.BlockDisk, state: _State) -> list[tuple[str, str]]:
        """[(mountpoint, our device node)] of filesystems on the disk or its partitions."""
        ours = self._ours(bd)
        return [(mnt, ours[sorted(devnums & set(ours))[0]]) for devnums, _src, mnt in state.mounts
                if devnums & set(ours)]

    def prepare(self, disk: DiskInfo) -> list[str]:
        """Unmount every filesystem of the disk, make sure the drive still has its
        medium, then open it exclusively (O_EXCL) and keep it open until release(),
        so nothing can mount a partition while it is written. Returns the
        mountpoints that were unmounted (for the progress output); what is worth
        telling the user besides (a drive that came back) is left in self.notes."""
        self.release()
        self.notes: list[str] = []
        self.medium_returned = False
        bd = devmod.inspect_disk(disk.id)
        state = _State()
        # The drive as checked by check_safe(), to recognise it (also when it comes back).
        base = (self._selected or {}).get(bd.name) or devmod.disk_identity(bd.name)
        self._check_identity(bd, base)  # (its size may be 0 now: _ensure_medium deals with that)
        self._check_unused(bd, state)  # again: things may have changed since check_safe()
        sectors = disk.size // 512
        unmounted: list[str] = []
        forced = False
        for _round in range(3):
            self._unmount_all(bd, state, unmounted)
            if not self._ensure_medium(bd, sectors, base):
                try:
                    self._held = self._probe_exclusive(bd, unmounted, unmount=True)
                    return list(dict.fromkeys(unmounted))
                except BeastError as e:
                    if e.code != "device-vanished" or forced:
                        raise
                    forced = True  # "no medium" when opening it: check it again once
                    self._ensure_medium(bd, sectors, base, force=True)
            # It came back: the kernel re-read its partitions and the desktop may have
            # mounted them again, so go round once more, if it is still the same drive.
            bd = devmod.inspect_disk(disk.id)
            state = _State()
            self._check_identity(bd, base)
            check_same_drive(disk, self._info(bd, state))
            self._check_unused(bd, state)
        raise BeastError(f"{bd.node} keeps stopping responding", code="device-vanished")

    def _unmount_all(self, bd: devmod.BlockDisk, state: _State, unmounted: list[str]) -> None:
        mounts = self._mounts(bd, state)
        # Deepest first, so nested mounts come off before their parents; a mountpoint
        # listed twice (stacked mounts) is unmounted twice.
        for mnt, node in sorted(mounts, key=lambda m: (m[0].count("/"), m[0]), reverse=True):
            self._unmount(bd, mnt, node, sum(1 for m, _n in mounts if m == mnt) > 1)
        unmounted += [mnt for mnt, _node in mounts]
        left = self._mounted(bd, _State())
        if left:
            users = self._users(bd, _State(), left)
            raise BeastError(f"{bd.node} is still mounted at {', '.join(left)}; {_users_text(users)}"
                             "close the programs using it and try again", code="busy")

    def _check_identity(self, bd: devmod.BlockDisk, base: dict[str, str] | None) -> None:
        now = devmod.disk_identity(bd.name)
        if base is not None and now != base:
            raise BeastError(f"{bd.node} is now another device than the drive that was selected (unplugged and "
                             "plugged in again, or replaced)", code="device-vanished")

    def release(self, disk: DiskInfo | None = None) -> None:
        """Close the exclusive hold prepare() keeps on the drive (before rescan(), the
        formatter, or when giving up)."""
        fd, self._held = self._held, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _unmount(self, bd: devmod.BlockDisk, mnt: str, node: str, stacked: bool) -> None:
        """Unmount one mountpoint, retrying while it is busy (BUSY_RETRY_DELAYS)."""
        detail = ""
        for delay in (*BUSY_RETRY_DELAYS, None):
            proc = self._unmount_once(bd, mnt, node, stacked)
            if proc is None:
                return
            detail = _detail(proc)
            if "busy" not in detail.lower():
                raise BeastError(f"cannot unmount {mnt} ({detail}); close the programs using it and try again")
            if delay is not None:
                time.sleep(delay)
        users = self._users(bd, _State(), [mnt])
        raise BeastError(f"cannot unmount {mnt}: it is busy ({detail}); {_users_text(users)}close the programs "
                         "using it (open files, a terminal or file manager in that folder) and try again",
                         code="busy")

    def _unmount_once(self, bd: devmod.BlockDisk, mnt: str, node: str,
                      stacked: bool) -> subprocess.CompletedProcess | None:
        """One attempt: None on success, else the failed command's result. A desktop
        automount goes through udisks (which then forgets the mount cleanly); when
        udisks is not there or refuses for another reason than "busy", umount does it."""
        udisksctl = _which("udisksctl")
        if udisksctl and not stacked and mnt.startswith(AUTOMOUNT_ROOTS):
            proc = _run_quiet([udisksctl, "unmount", "-b", node, "--no-user-interaction"], UDISKSCTL_TIMEOUT)
            if proc.returncode == 0 and mnt not in self._mounted(bd, _State()):
                return None
            if proc.returncode != 0 and "busy" in _detail(proc).lower():
                return proc
        proc = run(["umount", mnt], check=False)
        return None if proc.returncode == 0 else proc

    def _ensure_medium(self, bd: devmod.BlockDisk, sectors: int, base: dict[str, str] | None, *,
                       force: bool = False) -> bool:
        """After unmounting: if the drive reports no medium (or, with `force`, opening it
        said so), ask the kernel to check it again and wait for the same device to come
        back with its old size. True if it came back, False if it never went;
        BeastError (code "device-vanished") if it did not come back, went away or is
        now another device (never wait for a drive plugged in meanwhile)."""
        devmod.settle()
        now = devmod.medium_sectors(bd.name)
        if not force and (now == sectors or sectors <= 0):
            return False
        ident = devmod.disk_identity(bd.name)
        if now is None or ident is None:
            raise BeastError(f"{bd.node} was disconnected", code="device-vanished")
        self._check_identity(bd, base)
        if now and not force:
            raise BeastError(f"{bd.node}: size changed (expected {sectors * 512} bytes, the device has "
                             f"{now * 512}); a different drive or card?")
        self.notes.append(f"{bd.node} stopped responding (the kernel sees no medium); asking the kernel to check "
                          "it again")
        devmod.request_rescan(bd.name)
        back = devmod.wait_for_medium(bd.name, ident, MEDIUM_TIMEOUT)
        if back is None:
            raise BeastError(f"{bd.node} was disconnected or replaced while it was checked again",
                             code="device-vanished")
        if back != sectors:
            if back:
                raise BeastError(f"{bd.node} came back with another size ({back * 512} bytes, was "
                                 f"{sectors * 512}); unplug it, plug it back in and try again", code="device-vanished")
            raise BeastError(f"{bd.node} stopped responding (the kernel sees no medium)", code="device-vanished")
        self.notes.append(f"{bd.node} is back ({human_size(sectors * 512)})")
        self.medium_returned = True
        devmod.settle()
        return True

    def _probe_exclusive(self, bd: devmod.BlockDisk, mountpoints: list[str], *, unmount: bool = False) -> int:
        """device._exclusive_open (returns the fd), retried while busy (udev or a desktop
        service often holds the disk for a moment after an unmount); then say what
        holds it. With `unmount` (prepare), a filesystem the desktop mounted again
        meanwhile (it does when a drive comes back) is unmounted too, added to
        `mountpoints`, and the disk probed once more."""
        delays = list(BUSY_RETRY_DELAYS)
        remounts = 0
        while True:
            try:
                return devmod._exclusive_open(bd.node)
            except BeastError as e:
                if e.code != "busy":
                    raise
            again = self._mounts(bd, _State()) if unmount and remounts < 3 else []
            if again:
                remounts += 1
                for mnt, node in sorted(again, key=lambda m: (m[0].count("/"), m[0]), reverse=True):
                    self._unmount(bd, mnt, node, False)
                    mountpoints.append(mnt)
                continue
            if not delays:
                break
            time.sleep(delays.pop(0))
        users = self._users(bd, _State(), mountpoints)
        if users:
            what = "; ".join(users)
        else:
            what = ("the kernel refuses exclusive access, but no program could be named (a disk utility, a "
                    "virtual machine or a backup tool may have it open)")
        raise BeastError(f"{bd.node} is still in use{' after unmounting its volumes' if mountpoints else ''}: "
                         f"{what}; close the programs using it and try again", code="busy")

    def _users(self, bd: devmod.BlockDisk, state: _State, mountpoints: list[str]) -> list[str]:
        """What holds the drive: device-mapper/RAID holders, loop devices of files on
        it, processes (find_users). For "busy" messages; never raises."""
        out: list[str] = []
        try:
            for name in [bd.name, *bd.partitions]:
                base = bd.sysdir if name == bd.name else os.path.join(bd.sysdir, name)
                hdir = os.path.join(base, "holders")
                for h in sorted(os.listdir(hdir)) if os.path.isdir(hdir) else []:
                    out.append(f"{os.path.join(devmod.DEV, name)} is used by {h} (device-mapper/LVM/LUKS/RAID)")
            loops = dict(state.loops_on(bd.name))
            block = os.path.join(devmod.SYS, "block")
            for loop in sorted(os.listdir(block), key=natural_key):
                backing_file = _loop_backing_file(loop)
                if backing_file and mountpoints and _under(backing_file, mountpoints):
                    loops.setdefault(os.path.join(devmod.DEV, loop), backing_file)
            for loop, backing_file in sorted(loops.items(), key=lambda x: natural_key(x[0])):
                out.append(f"{loop} uses {backing_file} (a disk image opened from the drive; "
                           f"detach it with: udisksctl loop-delete -b {loop})")
            nodes = list(self._ours(bd).values())
            out += find_users(nodes, set(self._ours(bd)), mountpoints, limit=max(1, MAX_USERS - len(out)))
        except (OSError, BeastError):
            pass
        return out[:MAX_USERS]

    # -- a drive that stops responding -------------------------------------------
    def medium_gone(self, disk: DiskInfo) -> bool:
        """True if the drive has no medium any more (size 0) or was unplugged."""
        name = disk.extra.get("name") or os.path.basename(disk.path)
        devmod.settle()
        return not devmod.medium_sectors(name)

    def kernel_log(self, disk: DiskInfo) -> KernelLog | None:
        """Start recording kernel messages about the drive (root only; None if not possible)."""
        if not self.is_elevated():
            return None
        try:
            bd = devmod.inspect_disk(disk.id)
        except BeastError:
            return None
        return KernelLog.open(kernel_patterns(bd.name, bd.sysdir))

    def state_dir(self) -> str:
        """Where this machine keeps beast-boot's state (an interrupted update's recovery copy)."""
        if self.is_elevated():
            return STATE_DIR
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        return os.path.join(base, "beast-booter")

    # -- I/O ---------------------------------------------------------------------
    def open_raw(self, disk: DiskInfo, *, writable: bool) -> LinuxDiskTarget:
        t = LinuxDiskTarget(disk.path, writable=writable, sector_size=disk.sector_size)
        if t.size != disk.size:
            t.close()
            raise BeastError(f"{disk.path}: size changed (expected {disk.size} bytes, device has {t.size})")
        return t

    def rescan(self, disk: DiskInfo) -> None:
        """Make the kernel re-read the partition table (BLKRRPART, else `partx -u`).
        Ends prepare()'s exclusive hold first: BLKRRPART needs to claim the disk."""
        self.release()
        error = None
        for _attempt in range(5):
            devmod.settle()  # let udev finish probing after our close (it opens the partitions)
            try:
                _blkrrpart(disk.path)
                error = None
                break
            except OSError as e:
                error = f"BLKRRPART: {e.strerror}"
                if e.errno != errno.EBUSY:
                    break
                time.sleep(0.5)
        if error:
            # Fallback: partx adds/updates/removes the kernel's partitions one by one.
            proc = run(["partx", "-u", disk.path], check=False)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout).strip() or f"exit {proc.returncode}"
                raise BeastError(
                    f"the kernel did not accept the new partition table on {disk.path} "
                    f"({error}; partx: {detail}); unplug and reconnect the drive"
                )
        devmod.settle()

    def partition_path(self, disk: DiskInfo, index: int) -> str:
        return devmod.partition_node(devmod.inspect_disk(disk.id), index)

    def wait_partitions(self, disk: DiskInfo, indexes: list[int], timeout: float = 15.0) -> dict[int, str]:
        """Wait until the partition device nodes exist (after rescan); index -> node."""
        return devmod.wait_for_partitions(devmod.inspect_disk(disk.id), indexes, timeout)

    def format_ntfs(self, disk: DiskInfo, index: int, label: str) -> None:
        self.release()  # mkfs.ntfs opens the partition exclusively
        node = self.wait_partitions(disk, [index])[index]
        make_data_fs("ntfs", node, label, start_lba=None)  # mkfs.ntfs -q -Q -L LABEL /dev/sdX1

    # -- elevation ---------------------------------------------------------------
    def probe_installed(self, disk: DiskInfo, *, should_stop=None):
        """interfaces.PlatformBackend.probe_installed (installed_probe.py)."""
        from ..installed_probe import probe_linux

        return probe_linux(self, disk, should_stop=should_stop)

    def is_elevated(self) -> bool:
        return os.geteuid() == 0

    def run_elevated(self, argv: list[str]) -> PopenProcess:
        cmd = elevation_command(argv)
        try:
            p = subprocess.Popen(cmd, close_fds=True)
        except OSError as e:
            raise BeastError(f"cannot start {cmd[0]}: {e.strerror}") from None
        return PopenProcess(p, cmd)


__all__ = ["KernelLog", "LinuxBackend", "LinuxDiskTarget", "elevation_command", "find_users", "kernel_patterns"]
