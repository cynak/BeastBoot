"""Block devices: inspection via sysfs and the safety checks before writing.

All system paths are module attributes (SYS, PROC_MOUNTINFO, PROC_SWAPS, DEV)
and the two syscalls that need a real device (_stat_block, _exclusive_probe)
are small functions, so tests can point them at a fake tree.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import time
from dataclasses import dataclass, field

from .errors import BeastError
from .layout import SECTOR_SIZE
from .util import human_size, run

SYS = "/sys"
DEV = "/dev"
PROC_MOUNTINFO = "/proc/self/mountinfo"
PROC_SWAPS = "/proc/swaps"
SYSTEM_MOUNTPOINTS = ("/", "/boot", "/boot/efi")
# Virtual / unsuitable whole-disk devices we never write to.
REFUSED_PREFIXES = ("dm-", "md", "sr", "ram", "zram")


@dataclass
class BlockDisk:
    node: str  # /dev/sdb
    name: str  # sdb
    sysdir: str  # /sys/devices/.../block/sdb
    devnum: str  # "8:16"
    size_bytes: int
    removable: bool
    readonly: bool
    model: str
    logical_block_size: int
    partitions: dict[str, str] = field(default_factory=dict)  # name -> devnum

    def describe(self) -> str:
        kind = "removable" if self.removable else "fixed"
        model = self.model or "unknown model"
        return f"{self.node}: {model}, {human_size(self.size_bytes)} ({kind})"


def _stat_block(path: str) -> str | None:
    """'major:minor' if path is a block device, else None."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISBLK(st.st_mode):
        return None
    return f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"


def _exclusive_probe(node: str) -> None:
    """Open the disk with O_EXCL: the kernel refuses if it or a partition is in use."""
    try:
        fd = os.open(node, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC)
    except PermissionError:
        raise BeastError(f"permission denied opening {node}: run as root (sudo)") from None
    except OSError as e:
        if e.errno == errno.EBUSY:
            raise BeastError(f"{node} is in use by the system (mounted, swap, RAID or device-mapper)") from None
        raise BeastError(f"cannot open {node}: {e.strerror}") from None
    os.close(fd)


def _read(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


def _sysdir(devnum: str) -> str | None:
    p = os.path.join(SYS, "dev", "block", devnum)
    return os.path.realpath(p) if os.path.exists(p) else None


def inspect_disk(path: str) -> BlockDisk:
    """Resolve `path` to a whole-disk block device, or raise BeastError."""
    if not os.path.exists(path):
        raise BeastError(f"{path} does not exist")
    real = os.path.realpath(path)
    devnum = _stat_block(real)
    if devnum is None:
        raise BeastError(f"{path} is not a block device (use --image for image files)")
    sysdir = _sysdir(devnum)
    if sysdir is None:
        raise BeastError(f"{path}: no sysfs entry for block device {devnum}")
    name = os.path.basename(sysdir)
    if os.path.exists(os.path.join(sysdir, "partition")):
        parent = os.path.basename(os.path.dirname(sysdir))
        raise BeastError(f"{path} is a partition; pass the whole disk (e.g. {DEV}/{parent})")
    if name.startswith(REFUSED_PREFIXES):
        raise BeastError(f"{path} ({name}) is not a physical disk drive")
    partitions = {}
    for entry in sorted(os.listdir(sysdir)):
        sub = os.path.join(sysdir, entry)
        if os.path.exists(os.path.join(sub, "partition")):
            partitions[entry] = _read(os.path.join(sub, "dev"))
    vendor = _read(os.path.join(sysdir, "device", "vendor"))
    model = _read(os.path.join(sysdir, "device", "model"))
    return BlockDisk(
        node=os.path.join(DEV, name),
        name=name,
        sysdir=sysdir,
        devnum=devnum,
        size_bytes=int(_read(os.path.join(sysdir, "size"), "0") or 0) * 512,  # sysfs: 512-byte units
        removable=_read(os.path.join(sysdir, "removable")) == "1",
        readonly=_read(os.path.join(sysdir, "ro")) == "1",
        model=" ".join(x for x in (vendor, model) if x),
        logical_block_size=int(_read(os.path.join(sysdir, "queue", "logical_block_size"), "512") or 512),
        partitions=partitions,
    )


def _unescape_mount(s: str) -> str:
    """mountinfo / swaps escape space, tab, newline and backslash as \\ooo."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def read_mounts() -> list[tuple[set[str], str, str]]:
    """[(devnums, source, mountpoint)] from mountinfo."""
    out = []
    try:
        with open(PROC_MOUNTINFO, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise BeastError(f"cannot read {PROC_MOUNTINFO}: {e.strerror}") from None
    for line in lines:
        left, sep, right = line.partition(" - ")
        lf, rf = left.split(), right.split()
        if not sep or len(lf) < 5 or len(rf) < 2:
            continue
        source = _unescape_mount(rf[1])
        devnums = {lf[2]}
        if source.startswith("/"):
            dn = _stat_block(os.path.realpath(source))
            if dn:
                devnums.add(dn)
        out.append((devnums, source, _unescape_mount(lf[4])))
    return out


def read_swaps() -> list[tuple[str, str]]:
    """[(devnum, path)] of active swap block devices."""
    out = []
    try:
        with open(PROC_SWAPS, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if parts:
            dn = _stat_block(os.path.realpath(_unescape_mount(parts[0])))
            if dn:
                out.append((dn, parts[0]))
    return out


def backing_disks(devnum: str, _depth: int = 0) -> set[str]:
    """Names of the whole disks a block device ultimately lives on
    (follows partitions and device-mapper/md 'slaves')."""
    sysdir = _sysdir(devnum)
    if sysdir is None or _depth > 16:
        return set()
    if os.path.exists(os.path.join(sysdir, "partition")):
        return {os.path.basename(os.path.dirname(sysdir))}
    slaves_dir = os.path.join(sysdir, "slaves")
    slaves = sorted(os.listdir(slaves_dir)) if os.path.isdir(slaves_dir) else []
    if not slaves:
        return {os.path.basename(sysdir)}
    out: set[str] = set()
    for s in slaves:
        sdn = _read(os.path.join(os.path.realpath(os.path.join(slaves_dir, s)), "dev"))
        if sdn:
            out |= backing_disks(sdn, _depth + 1)
    return out


def check_safe(disk: BlockDisk, *, allow_fixed: bool) -> None:
    """Refuse unless `disk` is an unused, removable, non-system whole disk."""
    mounts = read_mounts()
    # 1. System disk: backs /, /boot or /boot/efi (directly or via LVM/LUKS/RAID).
    for devnums, source, mnt in mounts:
        if mnt in SYSTEM_MOUNTPOINTS:
            disks: set[str] = set()
            for dn in devnums:
                disks |= backing_disks(dn)
            if disk.name in disks:
                raise BeastError(f"refusing: {disk.node} holds the system's {mnt} filesystem ({source})")
    # 2. Mounted: the disk or any partition.
    ours = {disk.devnum: disk.node} | {dn: os.path.join(DEV, n) for n, dn in disk.partitions.items()}
    for devnums, source, mnt in mounts:
        hit = devnums & set(ours)
        if hit:
            node = ours[sorted(hit)[0]]
            raise BeastError(f"refusing: {node} is mounted at {mnt}; unmount it first")
    for dn, path in read_swaps():
        if dn in ours:
            raise BeastError(f"refusing: {ours[dn]} is in use as swap ({path}); swapoff it first")
    # 3. Holders: device-mapper, LVM, LUKS, md RAID built on top of it.
    for name in [disk.name] + list(disk.partitions):
        base = disk.sysdir if name == disk.name else os.path.join(disk.sysdir, name)
        hdir = os.path.join(base, "holders")
        holders = sorted(os.listdir(hdir)) if os.path.isdir(hdir) else []
        if holders:
            raise BeastError(
                f"refusing: {os.path.join(DEV, name)} is in use by {', '.join(holders)} "
                "(device-mapper/LVM/RAID); deactivate it first"
            )
    if disk.readonly:
        raise BeastError(f"{disk.node} is read-only (write-protect switch?)")
    if disk.logical_block_size != SECTOR_SIZE:
        raise BeastError(
            f"{disk.node} has {disk.logical_block_size}-byte sectors; only {SECTOR_SIZE}-byte sectors are supported"
        )
    # 4. Removable unless overridden.
    if not disk.removable and not allow_fixed:
        raise BeastError(
            f"refusing: {disk.describe()} is not a removable drive; "
            "if you are sure it is the right disk, pass --allow-fixed-disk"
        )
    # 5. Final kernel-level check: exclusive open fails if anything holds it.
    _exclusive_probe(disk.node)


def partition_node(disk: BlockDisk, index: int) -> str:
    """Device node of partition `index` (sdb -> sdb1, nvme0n1 -> nvme0n1p1)."""
    for name in sorted(os.listdir(disk.sysdir)):
        if _read(os.path.join(disk.sysdir, name, "partition")) == str(index):
            return os.path.join(DEV, name)
    sep = "p" if disk.name[-1].isdigit() else ""
    return os.path.join(DEV, f"{disk.name}{sep}{index}")


def reread_partitions(disk: BlockDisk) -> None:
    """Make the kernel pick up a new partition table."""
    errors = []
    for cmd in (["blockdev", "--rereadpt", disk.node], ["partx", "-u", disk.node]):
        proc = run(cmd, check=False)
        if proc.returncode == 0:
            return
        errors.append(f"{cmd[0]}: {(proc.stderr or proc.stdout).strip() or proc.returncode}")
    raise BeastError(
        f"the kernel did not accept the new partition table on {disk.node} ({'; '.join(errors)}); "
        "unplug and reconnect the drive, then run install again"
    )


def settle() -> None:
    if _have("udevadm"):
        run(["udevadm", "settle", "--timeout=10"], check=False)


def _have(tool: str) -> bool:
    from shutil import which

    return which(tool) is not None


def wait_for_partitions(disk: BlockDisk, indexes: list[int], timeout: float = 15.0) -> dict[int, str]:
    """Wait until the partition device nodes exist; returns index -> node."""
    settle()
    deadline = time.monotonic() + timeout
    while True:
        nodes = {i: partition_node(disk, i) for i in indexes}
        if all(_stat_block(n) for n in nodes.values()):
            return nodes
        if time.monotonic() > deadline:
            missing = ", ".join(n for n in nodes.values() if not _stat_block(n))
            raise BeastError(f"partition device nodes did not appear: {missing}")
        time.sleep(0.2)
