"""Linux backend: sysfs / procfs inspection (device.py) and raw I/O on /dev/sdX.

Listing walks /sys/block; the safety rules build on device.py's helpers
(inspect_disk, read_mounts, read_swaps, backing_disks, _exclusive_probe), so
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
  * holds the running beast-booter itself (platforms/common.check_common).
Being mounted is not a refusal: prepare() unmounts every filesystem of the
selected drive (desktop auto-mounts under /media or /run/media as well as
mounts made by hand, e.g. /mnt/stick) and returns their mountpoints for the
progress output. A mount that cannot come off because a program still uses
it fails with code "busy", naming the mountpoint. (macOS and Windows dismount
the volumes of the selected drive the same way.)

"removable" means removable media OR attached via USB or as an SD card,
because many USB sticks and SSDs report removable=0 (DiskInfo.extra keeps the
raw sysfs flag as "removable_media"). The O_EXCL busy probe needs root, so
check_safe() runs it only when elevated and nothing is mounted; prepare()
always runs it after unmounting.

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
from ..util import run
from .common import PopenProcess, check_common, check_same_drive, natural_key

BLKRRPART = 0x125F  # _IO(0x12, 95): re-read the partition table
LOCK_TIMEOUT = 10.0  # seconds to wait for udev to drop its shared lock

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
    raise BeastError("cannot get root rights: neither pkexec nor sudo was found; run beast-booter as root")


class LinuxBackend:
    name = "linux"

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
        self._check_unused(bd, state)
        check_common(fresh, allow_fixed=allow_fixed)
        if self.is_elevated() and not self._mounted(bd, state):
            devmod._exclusive_probe(bd.node)

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
        ours = set(self._ours(bd))
        return [mnt for devnums, _src, mnt in state.mounts if devnums & ours]

    def prepare(self, disk: DiskInfo) -> list[str]:
        """Unmount every filesystem of the disk, then make sure the kernel sees it unused.
        Returns the mountpoints that were unmounted (for the progress output)."""
        bd = devmod.inspect_disk(disk.id)
        state = _State()
        self._check_unused(bd, state)  # again: things may have changed since check_safe()
        mounted = self._mounted(bd, state)
        # Deepest first, so nested mounts come off before their parents; a mountpoint
        # listed twice (stacked mounts) is unmounted twice.
        for mnt in sorted(mounted, key=lambda m: (m.count("/"), m), reverse=True):
            proc = run(["umount", mnt], check=False)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout).strip() or f"exit {proc.returncode}"
                if "busy" in detail.lower():
                    raise BeastError(f"cannot unmount {mnt}: it is busy ({detail}); close the programs using it "
                                     "(open files, a terminal or file manager in that folder) and try again",
                                     code="busy")
                raise BeastError(f"cannot unmount {mnt} ({detail}); close the programs using it and try again")
        left = self._mounted(bd, _State())
        if left:
            raise BeastError(f"{bd.node} is still mounted at {', '.join(left)}; close the programs using it "
                             "and try again", code="busy")
        devmod._exclusive_probe(bd.node)
        return list(dict.fromkeys(mounted))

    # -- I/O ---------------------------------------------------------------------
    def open_raw(self, disk: DiskInfo, *, writable: bool) -> LinuxDiskTarget:
        t = LinuxDiskTarget(disk.path, writable=writable, sector_size=disk.sector_size)
        if t.size != disk.size:
            t.close()
            raise BeastError(f"{disk.path}: size changed (expected {disk.size} bytes, device has {t.size})")
        return t

    def rescan(self, disk: DiskInfo) -> None:
        """Make the kernel re-read the partition table (BLKRRPART, else `partx -u`)."""
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
        node = self.wait_partitions(disk, [index])[index]
        make_data_fs("ntfs", node, label, start_lba=None)  # mkfs.ntfs -q -Q -L LABEL /dev/sdX1

    # -- elevation ---------------------------------------------------------------
    def is_elevated(self) -> bool:
        return os.geteuid() == 0

    def run_elevated(self, argv: list[str]) -> PopenProcess:
        cmd = elevation_command(argv)
        try:
            p = subprocess.Popen(cmd, close_fds=True)
        except OSError as e:
            raise BeastError(f"cannot start {cmd[0]}: {e.strerror}") from None
        return PopenProcess(p, cmd)


__all__ = ["LinuxBackend", "LinuxDiskTarget", "elevation_command"]
