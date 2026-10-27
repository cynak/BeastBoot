"""The read-only guard (docs/DISK_TOOLS.md section 1, rules 1 and 3).

BLKROSET is a software flag the kernel enforces for every open for writing
(root can clear it, which is why only this module ever does, and only for one
confirmed target). The flag is a second layer: the first is that nothing in
Disk tools opens a source for writing.

Not protected on purpose: loop, ram and zram devices (reconstruction keeps
copy-on-write data there) and anything listed with ``exempt()`` (the dm
snapshot overlays that reconstruction writes to).
"""

from __future__ import annotations

import errno
import fcntl
import os
import struct
from dataclasses import dataclass, field

from ..context import Context
from ..errors import DISK_CHANGED, DISK_REFUSED, BeastNetError
from .discover import SKIP_PREFIXES, block_names, mounted_devices, partition_names, slaves_of
from .model import Disk

BLKROSET = 0x125D
BLKROGET = 0x125E

_UNGUARDED_PREFIXES = tuple(p for p in SKIP_PREFIXES if p in ("loop", "ram", "zram"))


def _ioctl(fd: int, request: int, arg):  # replaced in tests to record the calls
    return fcntl.ioctl(fd, request, arg)


_writable: set[str] = set()  # kernel names a WritableHandle currently owns
_exempt: set[str] = set()    # kernel names that stay writable (reconstruction overlays)


def exempt(*names: str) -> None:
    """Keep these kernel names (dm overlay devices) out of the guard."""
    _exempt.update(names)


def unexempt(*names: str) -> None:
    _exempt.difference_update(names)


def set_ro(path: str, ro: bool) -> None:
    """BLKROSET on one node. Raises OSError."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _ioctl(fd, BLKROSET, struct.pack("i", 1 if ro else 0))
    finally:
        os.close(fd)


def get_ro(path: str) -> bool | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        res = _ioctl(fd, BLKROGET, struct.pack("i", 0))
        if isinstance(res, (bytes, bytearray)) and len(res) >= 4:
            return struct.unpack("i", bytes(res[:4]))[0] != 0
        return None
    except OSError:
        return None
    finally:
        os.close(fd)


def ensure_node(ctx: Context, name: str) -> str:
    """The /dev node of a kernel name; made from /sys/block/*/dev when udev/mdev has not."""
    node = os.path.join(ctx.paths.dev, name)
    if os.path.exists(node):
        return node
    for base in (os.path.join(ctx.paths.sys, "class", "block", name), os.path.join(ctx.paths.sys, "block", name)):
        try:
            with open(os.path.join(base, "dev"), encoding="ascii") as f:
                major, minor = (int(x) for x in f.read().strip().split(":"))
            os.mknod(node, 0o600 | 0o060000, os.makedev(major, minor))
            return node
        except (OSError, ValueError):
            continue
    return node


def node_names(ctx: Context) -> list[str]:
    """Every block device and partition name in sysfs that should be guarded."""
    out = []
    for name in block_names(ctx.paths.sys):
        if name.startswith(_UNGUARDED_PREFIXES) or not os.path.isdir(os.path.join(ctx.paths.sys, "block", name)):
            continue
        out.append(name)
        out.extend(partition_names(ctx.paths.sys, name))
    return out


def protect_all(ctx: Context) -> dict[str, bool]:
    """Set read-only on every disk, partition, md and dm node. Emits `disk ro` per node.
    Returns {name: True} for each protected node. Raises BeastNetError(disk-refused)
    if a node that exists could not be made read-only (the tools must not go on)."""
    done: dict[str, bool] = {}
    failed = []
    for name in node_names(ctx):
        if name in _writable or name in _exempt:
            continue
        node = ensure_node(ctx, name)
        if not os.path.exists(node):
            continue
        try:
            set_ro(node, True)
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ENXIO, errno.ENODEV):
                continue  # gone between the listing and now
            failed.append(name)
            ctx.reporter.emit("disk ro", f"id={name}", "ro=0", f"errno={e.errno}")
            continue
        done[name] = True
        ctx.reporter.emit("disk ro", f"id={name}", "ro=1")
    if failed:
        raise BeastNetError(DISK_REFUSED, "could not make read-only: " + ", ".join(failed),
                            "Disk tools will not go on while a disk could be written to.")
    return done


def reapply(ctx: Context) -> dict[str, bool]:
    """After any rescan or assembly: new nodes are protected too. Nodes of an open
    WritableHandle (the confirmed target) are left alone."""
    return protect_all(ctx)


def status(ctx: Context) -> dict[str, bool | None]:
    """name -> read-only now? (None when the node is missing or cannot be asked)."""
    return {n: get_ro(os.path.join(ctx.paths.dev, n)) for n in node_names(ctx)}


# -- the one confirmed target -------------------------------------------------------------

@dataclass
class WritableHandle:
    ctx: Context
    disk_id: str
    names: list[str] = field(default_factory=list)
    closed: bool = False
    partition: str | None = None  # kernel name when only one partition was made writable

    def close(self) -> None:
        """Back to read-only on the nodes this handle opened (for a whole-disk handle: the
        disk and every partition it has now). A node another open handle still holds
        (a whole-disk node shared by two partition targets) stays writable for it."""
        if self.closed:
            return
        self.closed = True
        if self in _handles:
            _handles.remove(self)
        names = set(self.names)
        if self.partition is None:
            names |= {self.disk_id, *partition_names(self.ctx.paths.sys, self.disk_id)}
        held = {n for h in _handles for n in h.names}
        for n in sorted(names - held):
            _writable.discard(n)
            node = os.path.join(self.ctx.paths.dev, n)
            try:
                set_ro(node, True)
                self.ctx.reporter.emit("disk ro", f"id={n}", "ro=1")
            except OSError:
                if os.path.exists(node):
                    self.ctx.reporter.emit("disk ro", f"id={n}", "ro=0", "restore=failed")

    def __enter__(self) -> WritableHandle:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


_handles: list[WritableHandle] = []  # open handles, so close() leaves shared nodes alone


def _refuse(reason: str) -> BeastNetError:
    return BeastNetError(DISK_REFUSED, reason)


def make_writable(ctx: Context, disk: Disk, *, confirmed: bool = False,
                  partition: str | None = None) -> WritableHandle:
    """Clear read-only for a target the user confirmed: ONE disk and its partitions, or,
    with ``partition`` (a kernel name like "sdb2" or "nvme0n1p2", or its /dev path), only
    that partition and the whole-disk node (a read-only disk makes every partition on it
    read-only); the other partitions stay read-only.
    Refuses the stick, a disk without a serial, a disk whose identity changed, a
    partition that is not on this disk, any call without ``confirmed``, and a mounted,
    swap or md/dm/LVM-held node among those made writable (for a whole disk: any of its
    partitions; for a partition: that partition or the whole disk itself)."""
    if not confirmed:
        raise _refuse("the target was not confirmed")
    if disk.is_boot_stick:
        raise _refuse(f"{disk.id} is the BeastBoot stick")
    if not disk.serial:
        raise _refuse(f"{disk.id} reports no serial number, so it cannot be told apart safely")
    sys_root = ctx.paths.sys
    base = os.path.join(sys_root, "block", disk.id)
    if not os.path.isdir(base):
        raise BeastNetError(DISK_CHANGED, f"{disk.id} is gone")
    from .discover import read_disk
    now = read_disk(ctx, disk.id)
    if now.identity() != disk.identity():
        raise BeastNetError(DISK_CHANGED, f"{disk.id} is not the disk that was chosen (serial, WWN or size differ)")
    parts = partition_names(sys_root, disk.id)
    part = os.path.basename(partition.rstrip("/")) if partition else None
    if part is not None and part not in parts:
        raise _refuse(f"{part} is not a partition of {disk.id}")
    names = [disk.id, *parts] if part is None else [disk.id, part]
    mounted = mounted_devices(ctx)
    for n in names:
        if n in mounted:
            raise _refuse(f"{n} is mounted or used as swap")
        holders = os.path.join(sys_root, "block", n) if n == disk.id else os.path.join(base, n)
        try:
            if os.listdir(os.path.join(holders, "holders")):
                raise _refuse(f"{n} is in use by {', '.join(os.listdir(os.path.join(holders, 'holders')))}")
        except OSError:
            pass
    for other in block_names(sys_root):
        if other.startswith(("md", "dm-")) and set(names) & set(slaves_of(sys_root, other)):
            raise _refuse(f"{disk.id} is part of the active device {other}")
    handle = WritableHandle(ctx, disk.id, names, partition=part)
    _handles.append(handle)
    try:
        for n in names:
            node = ensure_node(ctx, n)
            set_ro(node, False)
            _writable.add(n)
            ctx.reporter.emit("disk ro", f"id={n}", "ro=0")
    except OSError:
        handle.close()
        raise _refuse(f"could not make {part or disk.id} writable") from None
    return handle
