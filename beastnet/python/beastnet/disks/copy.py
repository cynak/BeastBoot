"""Copy engine: clone (volume -> disk/partition), image (volume -> file) and
restore (file -> disk/partition), driven by an external GNU ddrescue.

Safety first (docs/DISK_TOOLS.md section 1, rules 3-6): every refusal is made
in plan(), before anything is written; run() re-identifies the target, holds
it open with O_EXCL for the whole job and only then asks the guard to make it
writable. The only path ever passed to ddrescue as output is plan.target.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .. import errors as E
from ..cmdline import netboot
from ..errors import BeastNetError
from .model import (CopyKind, CopyPlan, CopyProgress, CopyResult, Disk, Inventory,
                    Partition, Stack, Volume, VolumeKind)

IMAGE_FS = frozenset({"exfat", "ntfs", "ntfs3", "ext4", "xfs"})
CONFIRM_LEN = 6
CHUNK = 4 * 1024 * 1024
SET_NOTE = "one disk of a set, not a copy of the array"
RAM_MAP_NOTE = ("Started over the network, without a BeastBoot drive: the progress file is kept in "
                "memory, so a stopped copy resumes only until this computer restarts.")
DUP_NOTE = ("The clone has the same disk and partition IDs as the source. "
            "Keep only one of the two disks attached when you boot.")


# --------------------------------------------------------------------------
# Plan extension and hooks
# --------------------------------------------------------------------------

@dataclass
class DiskCopyPlan(CopyPlan):
    """CopyPlan plus what run() and the plan screen need (still a CopyPlan)."""
    src_label: str = ""          # event text: volume id or image path
    dst_label: str = ""          # event text: disk/partition id or image path
    sector: int = 512            # ddrescue -b
    retries: int = 2
    timeout: int = 180           # seconds without a good read; 0 = off
    expected_confirmation: str = ""   # what the user must type (clone/restore)
    target_disk_id: str = ""
    target_is_partition: bool = False
    notes: list[str] = field(default_factory=list)   # plain words for the plan screen
    member_of_set: bool = False
    overwrite: bool = False


@dataclass
class Location:
    """Where a path lives: filesystem, physical disks, mount."""
    fs_type: str = ""
    disk_ids: list[str] = field(default_factory=list)
    readonly: bool = False
    mountpoint: str = ""
    esp: bool = False


def _lazy_guard(name: str, **fixed):
    def call(*a, **kw):
        try:
            from . import guard
        except ImportError as e:
            raise BeastNetError(E.COPY, "the disk guard module is not available") from e
        return getattr(guard, name)(*a, **{**fixed, **kw})
    return call


def _lazy_scan(ctx):
    try:
        from . import discover
    except ImportError as e:
        raise BeastNetError(E.COPY, "the disk scanner is not available") from e
    return discover.scan(ctx)


def _open_exclusive(path: str) -> int:
    """Claim a block device exclusively (read-only open with O_EXCL: it works on a
    read-only node and keeps mounts, md and others off until closed)."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        if stat.S_ISBLK(os.stat(path).st_mode):
            flags |= os.O_EXCL
        return os.open(path, flags)
    except OSError as e:
        raise BeastNetError(E.DISK_REFUSED, f"{path} is busy or cannot be opened exclusively ({e.strerror})") from e


def _is_block(path: str) -> bool:
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


@dataclass
class Hooks:
    """Everything that touches the machine, replaceable in tests."""
    rescan: Callable = _lazy_scan                       # (ctx) -> Inventory
    # (ctx, disk); run() calls it only for a plan confirmed by the typed serial
    make_writable: Callable = _lazy_guard("make_writable", confirmed=True)
    relock: Callable = _lazy_guard("reapply")           # (ctx)
    open_exclusive: Callable[[str], int] = _open_exclusive
    is_block: Callable[[str], bool] = _is_block
    spawn: Callable = subprocess.Popen
    which: Callable[[str], str | None] = shutil.which
    statvfs: Callable = os.statvfs
    locate: Callable | None = None                      # (ctx, inv, path) -> Location
    poll: float = 0.5


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _refuse(text: str, hint: str = ""):
    raise BeastNetError(E.DISK_REFUSED, text, hint)


def _unescape(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def _real(p: str) -> str:
    return os.path.realpath(p)


def confirmation_for(inv: Inventory, disk: Disk) -> str:
    """Last 6 characters of the serial; the whole serial when another disk ends the same."""
    tail = disk.serial[-CONFIRM_LEN:]
    for d in inv.disks:
        if d is not disk and d.id != disk.id and d.serial and d.serial[-CONFIRM_LEN:] == tail:
            return disk.serial
    return tail


def confirm_plan(plan: DiskCopyPlan, text: str) -> DiskCopyPlan:
    """Mark the plan confirmed if ``text`` is what was asked for, else refuse."""
    if plan.expected_confirmation and (text or "").strip() == plan.expected_confirmation:
        plan.confirmed = True
        return plan
    _refuse("the typed confirmation does not match the target's serial number")


def _mounts(ctx) -> list[tuple[str, str, str, bool]]:
    """(source, mountpoint, fstype, readonly) from /proc/self/mountinfo."""
    out = []
    try:
        with open(os.path.join(ctx.paths.proc, "self", "mountinfo"), encoding="utf-8", errors="replace") as f:
            for line in f:
                head, sep, tail = line.partition(" - ")
                if not sep:
                    continue
                h, t = head.split(), tail.split()
                if len(h) < 6 or len(t) < 2:
                    continue
                opts = h[5].split(",")
                out.append((_unescape(t[1]), _unescape(h[4]), t[0], "ro" in opts))
    except OSError:
        pass
    return out


def _existing_parent(path: str) -> str:
    p = _real(path)
    while p and not os.path.exists(p):
        np = os.path.dirname(p)
        if np == p:
            break
        p = np
    return p


def default_locate(ctx, inv: Inventory, path: str) -> Location:
    rp = _existing_parent(path)
    best = None
    for src, mp, fst, ro in _mounts(ctx):
        m = mp.rstrip("/") or "/"
        if rp == m or m == "/" or rp.startswith(m + "/"):
            if best is None or len(m) >= len(best[1]):
                best = (src, m, fst, ro)
    if best is None:
        return Location()
    src, mp, fst, ro = best
    loc = Location(fs_type=fst, readonly=ro, mountpoint=mp)
    try:
        loc.esp = bool(ctx.paths.esp) and _real(ctx.paths.esp) == mp
    except AttributeError:
        pass
    rs = _real(src)
    for v in inv.volumes:
        if _real(v.path) == rs and v.disk_ids:
            loc.disk_ids = list(v.disk_ids)
            return loc
    for d in inv.disks:
        if _real(d.path) == rs:
            loc.disk_ids = [d.id]
            return loc
        for p in d.partitions:
            if _real(p.path) == rs:
                loc.disk_ids = [d.id]
                return loc
    return loc


def _locate(ctx, inv, path, h: Hooks) -> Location:
    return (h.locate or default_locate)(ctx, inv, path)


def _owner(inv: Inventory, partition_path: str) -> tuple[Disk, Partition] | None:
    for d in inv.disks:
        for p in d.partitions:
            if _real(p.path) == _real(partition_path):
                return d, p
    return None


def _in_use(ctx, nodes: dict[str, str], holders_dirs: list[str]) -> str:
    """Reason string if any node is mounted, swapped or held by md/dm; else ''."""
    want = {_real(p) for p in nodes}
    for src, mp, _fs, _ro in _mounts(ctx):
        if _real(src) in want:
            return f"{src} is mounted at {mp}"
    try:
        with open(os.path.join(ctx.paths.proc, "swaps"), encoding="utf-8", errors="replace") as f:
            for line in list(f)[1:]:
                dev = line.split()[0] if line.split() else ""
                if _real(_unescape(dev)) in want:
                    return f"{dev} is used as swap"
    except OSError:
        pass
    for d in holders_dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        if names:
            return f"{os.path.basename(os.path.dirname(d))} is in use by {', '.join(sorted(names))}"
    return ""


# --------------------------------------------------------------------------
# ddrescue command lines and mapfile
# --------------------------------------------------------------------------

def ddrescue_argv(plan: DiskCopyPlan, phase: str, *, force: bool, direct_in: bool,
                  direct_out: bool) -> list[str]:
    """phase 'fast' = first pass, no trimming/scraping; 'retry' = the rest."""
    argv = ["ddrescue"]
    if force:
        argv.append("-f")
    if direct_in:
        argv.append("-d")
    if direct_out:
        argv.append("-D")
    argv += ["-b", str(plan.sector)]
    if phase == "fast":
        argv.append("-n")
    else:
        argv.append(f"-r{plan.retries}")
    if plan.timeout:
        argv.append(f"--timeout={plan.timeout}")
    argv += [plan.source, plan.target, plan.mapfile]
    return argv


def _check_argv(plan: DiskCopyPlan, argv: list[str]) -> None:
    """Last line of defence: output is exactly the plan target, never the source."""
    if (argv[-3:] != [plan.source, plan.target, plan.mapfile] or plan.target == plan.source
            or argv.count(plan.source) != 1):
        raise BeastNetError(E.COPY, "internal check failed: ddrescue arguments do not match the plan")


def parse_mapfile(path: str) -> tuple[list[tuple[int, int, str]], str]:
    """(blocks, current_status) of a ddrescue mapfile; ([], '') if absent."""
    blocks: list[tuple[int, int, str]] = []
    phase = ""
    seen_status = False
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                w = line.split()
                try:
                    if not seen_status:
                        seen_status = True
                        phase = w[1] if len(w) > 1 else ""
                    elif len(w) >= 3:
                        blocks.append((int(w[0], 0), int(w[1], 0), w[2]))
                except ValueError:
                    continue
    except OSError:
        return [], ""
    return blocks, phase


_PHASES = {"?": "copying", "c": "copying", "f": "copying", "g": "copying", "t": "trimming",
           "s": "scraping", "r": "retrying", "+": "finished"}


def mapfile_state(path: str, total: int) -> tuple[int, int, int, str]:
    """(bytes finished, bad areas, bytes unfinished, phase) within [0, total)."""
    blocks, ph = parse_mapfile(path)
    done = bad = 0
    for pos, size, st in blocks:
        size = max(0, min(size, total - pos))
        if st == "+":
            done += size
        elif st == "-" and size:
            bad += 1
    if not blocks:
        return 0, 0, total, ""
    return done, bad, max(0, total - done), _PHASES.get(ph, "copying")


# --------------------------------------------------------------------------
# plan()
# --------------------------------------------------------------------------

def _resolve_volume(inv: Inventory, ref: str) -> Volume:
    for v in inv.volumes:
        if ref and ref in (v.id, v.path):
            return v
    d = inv.disk(ref) or next((x for x in inv.disks if x.path == ref), None)
    if d:
        for v in inv.volumes:
            if v.id == d.id:
                return v
        return Volume(id=d.id, path=d.path, kind=VolumeKind.DISK, size=d.size, disk_ids=[d.id])
    _refuse(f"unknown source {ref!r}")


def _resolve_target(inv: Inventory, ref: str) -> tuple[Disk, Partition | None]:
    d = inv.disk(ref) or next((x for x in inv.disks if x.path == ref), None)
    if d:
        return d, None
    for dd in inv.disks:
        for p in dd.partitions:
            if ref in (p.id, p.path):
                return dd, p
    _refuse(f"unknown target {ref!r}: it is not a disk or partition BeastBoot found")


def _volume_disk_ids(inv: Inventory, v: Volume) -> list[str]:
    ids = list(v.disk_ids)
    if not ids and v.kind == VolumeKind.PARTITION:
        o = _owner(inv, v.path)
        ids = [o[0].id] if o else []
    if not ids and v.kind == VolumeKind.DISK:
        ids = [v.id]
    if v.from_stack:
        for st in inv.stacks:
            if st.id == v.from_stack:
                ids += [m.disk_id for m in st.members]
    return sorted(set(ids))


def _member_stack(inv: Inventory, v: Volume, disk_ids: list[str]) -> Stack | None:
    if v.kind not in (VolumeKind.DISK, VolumeKind.PARTITION):
        return None
    for st in inv.stacks:
        if len(st.members) < 2:
            continue
        for m in st.members:
            if m.device == v.path or (v.kind == VolumeKind.DISK and m.disk_id in disk_ids):
                return st
    return None


def _check_image_dest(ctx, inv, dest, size, src_disks, overwrite, h) -> Location:
    if h.is_block(dest) or os.path.isdir(dest):
        _refuse(f"{dest} is a device or folder, not an image file name")
    parent = os.path.dirname(dest) or "."
    if not os.path.isdir(parent):
        _refuse(f"the folder {parent} does not exist")
    loc = _locate(ctx, inv, parent, h)
    if loc.esp or loc.fs_type in ("vfat", "msdos", "fat", "fat32"):
        _refuse("image files cannot go on FAT32 or the boot partition (4 GiB limit, no room)",
                "Use a disk formatted as exFAT, NTFS, ext4 or xfs.")
    if loc.fs_type not in IMAGE_FS:
        _refuse(f"image files can only be written to exFAT, NTFS, ext4 or xfs "
                f"(this place is {loc.fs_type or 'not a disk filesystem'})")
    if loc.readonly:
        _refuse(f"{parent} is mounted read-only")
    if set(loc.disk_ids) & set(src_disks):
        _refuse("the image would be written to the disk it is read from")
    have = 0
    if os.path.exists(dest):
        try:
            have = os.stat(dest).st_size
        except OSError:
            pass
    try:
        st = h.statvfs(_existing_parent(parent))
        free = st.f_bavail * st.f_frsize
    except OSError:
        free = 0
    if free + have < size:
        _refuse(f"not enough free space for the image: need {size} bytes, {free + have} available")
    return loc


def _mapfile_place(ctx, inv, kind, name_key, mapfile_dir, image_dest, forbidden, h):
    """Pick and validate the mapfile directory; returns its path."""
    cands = []
    # Network boot (no stick): the data partition is RAM, so the image's own folder
    # (on a disk) comes first; RAM is the last resort (RAM_MAP_NOTE).
    ram_ok = netboot(ctx)
    if mapfile_dir and not ram_ok:
        cands.append(mapfile_dir)
    else:
        if kind == CopyKind.IMAGE and image_dest:
            cands.append(os.path.dirname(image_dest) or ".")
        data = getattr(ctx.paths, "data", "")
        if mapfile_dir:
            cands.append(mapfile_dir)
        elif data:
            cands.append(os.path.join(data, "disk-tools"))
    reason = "there is nowhere safe to keep the ddrescue mapfile (the stick's data partition or a third disk)"
    ram = None
    for d in cands:
        loc = _locate(ctx, inv, d, h)
        stick = {x.id for x in inv.disks if x.is_boot_stick}
        if not loc.disk_ids:
            reason = f"{d} is not on a disk (RAM or unknown), so a mapfile there would not survive"
            if ram_ok and ram is None and not loc.readonly and os.access(_existing_parent(d), os.W_OK):
                ram = d
            continue
        if set(loc.disk_ids) & set(forbidden):
            reason = f"the mapfile would be on {', '.join(sorted(set(loc.disk_ids) & set(forbidden)))}, the source or target"
            continue
        if loc.readonly or not os.access(_existing_parent(d), os.W_OK):
            reason = f"{d} is not writable"
            continue
        if not (set(loc.disk_ids) & stick) and not (set(loc.disk_ids) - set(forbidden)):
            continue
        return d
    if ram is not None:
        return ram
    _refuse(reason, "Plug in another disk or make the BeastBoot data partition writable.")


def plan(ctx, inv: Inventory, kind, source: str, target: str, *, confirm: str | None = None,
         mapfile_dir: str | None = None, verify: bool = True, member_of_set: bool = False,
         overwrite: bool = False, retries: int = 2, timeout: int = 180,
         hooks: Hooks | None = None) -> DiskCopyPlan:
    """Resolve source and target and apply every refusal. Raises
    BeastNetError(DISK_REFUSED) with the reason; nothing is touched."""
    h = hooks or Hooks()
    kind = CopyKind(kind)
    notes: list[str] = []
    tdisk: Disk | None = None
    tpart: Partition | None = None
    dest_file = ""

    # ---- source
    if kind == CopyKind.RESTORE:
        src_path = os.path.abspath(source)
        if h.is_block(src_path) or not os.path.isfile(src_path):
            _refuse(f"{source} is not an image file")
        size = os.stat(src_path).st_size
        if size <= 0:
            _refuse("the image file is empty")
        src_disks = _locate(ctx, inv, src_path, h).disk_ids
        src_label, vol, set_stack = src_path, None, None
    else:
        vol = _resolve_volume(inv, source)
        src_path, size = vol.path, vol.size
        if size <= 0:
            _refuse("the source has no size")
        src_disks = _volume_disk_ids(inv, vol)
        src_label = vol.id
        set_stack = _member_stack(inv, vol, src_disks)
        if set_stack is not None:
            if not member_of_set:
                _refuse(f"{vol.id} is one member of {set_stack.kind.value} set {set_stack.id}; "
                        f"a copy of one member is not a copy of the array",
                        "Assemble the array and copy that, or ask explicitly for member imaging.")
            notes.append(SET_NOTE)
            src_disks = sorted(set(src_disks) | {m.disk_id for m in set_stack.members}) \
                if kind == CopyKind.CLONE else src_disks

    # ---- target
    if kind == CopyKind.IMAGE:
        dest_file = os.path.abspath(target)
        if _real(dest_file) == _real(src_path):
            _refuse("the image file cannot be the source")
        if os.path.exists(dest_file) and not overwrite and not _has_mapfile(ctx, mapfile_dir, dest_file):
            raise BeastNetError(E.EXISTS, f"{dest_file} already exists",
                                "Choose another name, or allow replacing it.")
        dst_path, erases, dst_label = dest_file, "", dest_file
        dloc = _check_image_dest(ctx, inv, dest_file, size, src_disks, overwrite, h)
        target_disk_ids = set(dloc.disk_ids)
    else:
        tdisk, tpart = _resolve_target(inv, target)
        dst_path = tpart.path if tpart else tdisk.path
        dst_label = tpart.id if tpart else tdisk.id
        tsize = tpart.size if tpart else tdisk.size
        if tdisk.is_boot_stick:
            _refuse("that is the BeastBoot stick itself")
        if not tdisk.serial:
            _refuse(f"{tdisk.id} reports no serial number, so it cannot be told apart safely; "
                    f"it cannot be a target")
        if sum(1 for d in inv.disks if d.serial == tdisk.serial) > 1:
            _refuse(f"two disks report the serial {tdisk.serial}; the target cannot be told apart")
        if tdisk.id in src_disks:
            _refuse("the target is the source, or a disk the source is built on")
        if _real(dst_path) == _real(src_path):
            _refuse("target and source are the same device")
        # rule 4 is about the disk: also for a partition target, no partition of that
        # disk may be mounted, held, or part of a running set
        nodes = {tdisk.path: tdisk.id}
        holders = []
        sysb = os.path.join(ctx.paths.sys, "block")
        for p in tdisk.partitions:
            nodes[p.path] = p.id
            holders.append(os.path.join(sysb, tdisk.id, p.id, "holders"))
        holders.append(os.path.join(sysb, tdisk.id, "holders"))
        for v in inv.volumes:
            if v.from_stack and tdisk.id in v.disk_ids:
                _refuse(f"{tdisk.id} is part of the running {v.id} ({v.from_stack})")
        why = _in_use(ctx, nodes, holders)
        if why:
            _refuse(f"the target is in use: {why}")
        if tsize < size:
            _refuse(f"the target is smaller than the source ({tsize} < {size} bytes)")
        if kind == CopyKind.CLONE and not tpart and vol is not None:
            sdisks = [d for d in inv.disks if d.id in src_disks]
            if sdisks and sdisks[0].logical_sector != tdisk.logical_sector:
                _refuse(f"different sector sizes ({sdisks[0].logical_sector} and {tdisk.logical_sector}): "
                        f"a raw copy would break the partition table")
        target_disk_ids = {tdisk.id}
        erases = _erases_text(tdisk, tpart)
        if kind == CopyKind.CLONE:
            notes.append(DUP_NOTE)
        if tsize > size and not tpart:
            notes.append("The target is larger: the copy keeps the source's size, the rest stays unused "
                         "(a GPT backup table is moved to the end of the disk).")
        if kind == CopyKind.RESTORE:
            lss = read_info(src_path).get("logical_sector")
            if isinstance(lss, int) and lss != tdisk.logical_sector and not tpart:
                _refuse(f"different sector sizes (the image is from a {lss}-byte-sector disk, the target "
                        f"has {tdisk.logical_sector}): a raw restore would break the partition table")
            if not isinstance(lss, int):
                notes.append("The image does not record its sector size; make sure it came from a disk with "
                             f"{tdisk.logical_sector}-byte sectors.")

    # ---- mapfile
    key = hashlib.sha1(f"{kind.value}|{src_path}|{dst_path}|"
                       f"{tdisk.serial if tdisk else ''}".encode()).hexdigest()[:12]
    # A restore reads an image *file*: its mapfile may sit on the same drive (e.g. the stick);
    # a disk being rescued (clone/image source) never gets one.
    forbidden = (set(src_disks) if kind != CopyKind.RESTORE else set()) | \
        (target_disk_ids if kind != CopyKind.IMAGE else set())
    mdir = _mapfile_place(ctx, inv, kind, key, mapfile_dir, dest_file, forbidden, h)
    if netboot(ctx) and not _locate(ctx, inv, mdir, h).disk_ids:
        notes.append(RAM_MAP_NOTE)
    if kind == CopyKind.IMAGE and _real(mdir) == _real(os.path.dirname(dest_file)):
        mapfile = dest_file + ".map"
    else:
        mapfile = os.path.join(mdir, f"copy-{kind.value}-{key}.map")
    if _real(mapfile) in (_real(src_path), _real(dst_path)):
        _refuse("the mapfile would overwrite the source or target")

    # ---- confirmation
    expected = confirmation_for(inv, tdisk) if tdisk else ""
    if kind in (CopyKind.CLONE, CopyKind.RESTORE) and confirm is not None \
            and confirm.strip() != expected:
        _refuse("the typed confirmation does not match the target's serial number")

    sdisk = next((d for d in inv.disks if d.id in src_disks), None)
    sector = (tdisk.logical_sector if tdisk and kind == CopyKind.RESTORE
              else sdisk.logical_sector if sdisk else (tdisk.logical_sector if tdisk else 512)) or 512
    p = DiskCopyPlan(kind=kind, source=src_path, target=dst_path, size=size, mapfile=mapfile,
                     target_identity=tdisk.identity() if tdisk else None,
                     source_disk_ids=sorted(set(src_disks)), erases=erases, verify=verify,
                     src_label=src_label, dst_label=dst_label, sector=sector, retries=retries,
                     timeout=timeout, expected_confirmation=expected,
                     target_disk_id=tdisk.id if tdisk else "", target_is_partition=tpart is not None,
                     notes=notes, member_of_set=set_stack is not None, overwrite=overwrite,
                     confirmed=kind == CopyKind.IMAGE or (confirm is not None and confirm.strip() == expected))
    blk_out = kind != CopyKind.IMAGE
    blk_in = h.is_block(src_path)
    p.commands = [ddrescue_argv(p, "fast", force=blk_out, direct_in=blk_in, direct_out=blk_out),
                  ddrescue_argv(p, "retry", force=blk_out, direct_in=blk_in, direct_out=blk_out)]
    if tdisk and not tpart and tdisk.size > size and kind != CopyKind.IMAGE:
        p.commands.append(["sfdisk", "--relocate", "gpt-bak-std", dst_path])
    return p


def _has_mapfile(ctx, mapfile_dir, dest) -> bool:
    return os.path.exists(dest + ".map")


def _erases_text(disk: Disk, part: Partition | None) -> str:
    gb = lambda n: f"{n / 1e9:.1f} GB"  # noqa: E731
    if part:
        return (f"Everything on partition {part.id} ({gb(part.size)}, {part.fs_type or 'no filesystem'}) "
                f"of {disk.model or disk.id}, serial {disk.serial}")
    parts = ", ".join(f"{p.id} ({p.fs_type or 'unknown'})" for p in disk.partitions) or "no partitions"
    return (f"Everything on {disk.model or disk.id} ({disk.id}, {gb(disk.size)}), serial {disk.serial}, "
            f"including {parts}")


# --------------------------------------------------------------------------
# run()
# --------------------------------------------------------------------------

class _Stopped(Exception):
    pass


def _drop_cache(fd: int) -> None:
    try:
        import fcntl
        fcntl.ioctl(fd, 0x1261, 0)  # BLKFLSBUF
    except (OSError, ImportError):
        pass
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except (OSError, AttributeError):
        pass


def _hash_range(path: str, size: int, should_stop, tick, other: str | None = None) -> tuple[str, bool]:
    """sha256 of the first ``size`` bytes of path; with ``other``, also compare it
    byte for byte. Returns (hex, equal)."""
    h = hashlib.sha256()
    equal = True
    done = 0
    with open(path, "rb", buffering=0) as f, \
            (open(other, "rb", buffering=0) if other else _Null()) as g:
        _drop_cache(f.fileno())
        if other:
            _drop_cache(g.fileno())
        while done < size:
            if should_stop():
                raise _Stopped
            n = min(CHUNK, size - done)
            buf = f.read(n)
            if not buf:
                break
            h.update(buf)
            if other and g.read(len(buf)) != buf:
                equal = False
            done += len(buf)
            tick(done)
    if done < size:
        equal = False
    return h.hexdigest(), equal


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _reidentify(ctx, plan: DiskCopyPlan, h: Hooks) -> Disk:
    inv = h.rescan(ctx)
    disk = next((d for d in inv.disks if d.id == plan.target_disk_id), None)
    if disk is None:
        raise BeastNetError(E.DISK_CHANGED, f"{plan.target_disk_id} is no longer there")
    if plan.target_identity is None or disk.identity() != tuple(plan.target_identity):
        raise BeastNetError(E.DISK_CHANGED,
                            f"{disk.id} is not the same disk as when the plan was made "
                            f"(serial, WWN or size differ); nothing was written")
    if not plan.target_is_partition and disk.path != plan.target:
        raise BeastNetError(E.DISK_CHANGED, f"{disk.id} now has a different device path")
    if plan.target_is_partition and not any(p.path == plan.target for p in disk.partitions):
        raise BeastNetError(E.DISK_CHANGED, f"partition {plan.target} changed or disappeared")
    if disk.is_boot_stick:
        raise BeastNetError(E.DISK_REFUSED, "that is the BeastBoot stick itself")
    if disk.id in plan.source_disk_ids:
        raise BeastNetError(E.DISK_REFUSED, "the target is now part of the source")
    return disk


def run(ctx, plan: CopyPlan, on_progress: Callable[[CopyProgress], None] | None = None,
        should_stop: Callable[[], bool] | None = None, *, hooks: Hooks | None = None) -> CopyResult:
    h = hooks or Hooks()
    on_progress = on_progress or (lambda p: None)
    should_stop = should_stop or (lambda: False)
    if not isinstance(plan, DiskCopyPlan):
        raise BeastNetError(E.COPY, "the plan was not made by disks.copy.plan()")
    kind = plan.kind
    writes_device = kind != CopyKind.IMAGE
    if writes_device and not plan.confirmed:
        raise BeastNetError(E.DISK_REFUSED, "the plan was not confirmed by typing the target's serial")
    if getattr(ctx, "dry_run", False):
        ctx.notes.append("[dry-run] would run: " + "; ".join(" ".join(c) for c in plan.commands))
        return CopyResult(ok=True, bytes=0, errors=0, notes=["dry run: nothing written"])
    exe = h.which("ddrescue")
    if not exe:
        raise BeastNetError(E.COPY, "ddrescue is not installed in this helper")
    rep = ctx.reporter
    notes = list(plan.notes)
    fd = None
    disk = None
    unlocked = False
    writable = None  # guard handle: closed in `finally`, so the target is read-only again
    t_timeout = _SgTimeout(ctx, plan)
    try:
        # target checks come before anything is created or changed
        if writes_device:
            disk = _reidentify(ctx, plan, h)
            fd = h.open_exclusive(plan.target)
            try:
                tsize = os.lseek(fd, 0, os.SEEK_END)
            except OSError:
                tsize = plan.size
            if tsize < plan.size:
                raise BeastNetError(E.DISK_CHANGED, "the target is smaller than the plan expected")
            if not os.path.exists(plan.source):
                raise BeastNetError(E.DISK_CHANGED, "the source is gone")
        else:
            if not os.path.exists(plan.source):
                raise BeastNetError(E.DISK_CHANGED, "the source is gone")
        os.makedirs(os.path.dirname(plan.mapfile) or ".", exist_ok=True)
        if writes_device:
            unlocked = True
            # a partition target: only the disk node (a read-only disk blocks its
            # partitions) and that partition become writable; siblings stay read-only
            writable = h.make_writable(ctx, disk, partition=plan.target if plan.target_is_partition else None)
        t_timeout.apply()
        rep.emit("copy start", f"kind={kind.value}", f"src={plan.src_label or plan.source}",
                 f"dst={plan.dst_label or plan.target}", f"size={plan.size}")

        direct_in = h.is_block(plan.source)
        direct_out = writes_device and h.is_block(plan.target)
        force = writes_device and direct_out
        last_emit = [0.0]
        state = {"t": time.monotonic(), "done": 0, "rate": 0.0}

        def report(phase_override: str = "", done_override: int | None = None) -> tuple[int, int, int]:
            done, bad, left, ph = mapfile_state(plan.mapfile, plan.size)
            if done_override is not None:
                done = done_override
            now = time.monotonic()
            dt = now - state["t"]
            if dt >= 0.5:
                state["rate"] = max(0.0, (done - state["done"]) / dt)
                state["t"], state["done"] = now, done
            prog = CopyProgress(done=done, total=plan.size, errors=bad, rate=state["rate"],
                                phase=phase_override or ph)
            on_progress(prog)
            if now - last_emit[0] >= 1.0 or done >= plan.size:
                last_emit[0] = now
                rep.emit("copy progress", f"done={done}", f"errors={bad}", f"rate={int(state['rate'])}")
            return done, bad, left

        # a finished mapfile here can only be a run that stopped before verifying
        stopped = False
        for phase in ("fast", "retry"):
            done, bad, left, _ = mapfile_state(plan.mapfile, plan.size)
            if phase == "retry" and left == 0:
                break
            if phase == "fast" and left == 0:
                break
            argv = ddrescue_argv(plan, phase, force=force, direct_in=direct_in, direct_out=direct_out)
            _check_argv(plan, argv)
            argv[0] = exe
            rc, stopped, err = _run_child(h, argv, plan, report, should_stop)
            if not stopped and phase == "fast" and should_stop():
                stopped = True
            if stopped:
                break
            if rc != 0:
                done, bad, left, _ = mapfile_state(plan.mapfile, plan.size)
                msg = (err or f"ddrescue exited with {rc}").strip().splitlines()[-1:] or [""]
                low = (err or "").lower()
                if "timeout" in low or "interrupt" in low:
                    notes.append("No progress for too long: the disk may be hanging. Power-cycle it if "
                                 "needed and run the same copy again to resume.")
                    stopped = True
                    break
                code = E.DISK_IO if ("write" in low and "error" in low) else E.COPY
                raise BeastNetError(code, f"ddrescue failed: {msg[0]}")
        if stopped:
            rep.emit("copy stopped", "resumable=1")
            done, bad, left, _ = mapfile_state(plan.mapfile, plan.size)
            return CopyResult(ok=False, bytes=done, errors=left, resumable=True, notes=notes)

        done, bad, left, _ = mapfile_state(plan.mapfile, plan.size)
        report("finished")
        sha = ""
        if plan.verify and left == 0:
            try:
                sha = _verify(plan, should_stop, lambda d: report("verifying", d), notes)
            except _Stopped:
                rep.emit("copy stopped", "resumable=1")
                return CopyResult(ok=False, bytes=done, errors=0, resumable=True,
                                  notes=notes + ["Stopped while verifying; run again to finish."])
        elif plan.verify and left:
            notes.append(f"Not verified: {left} bytes could not be read.")
        if left:
            notes.append(f"{left} bytes could not be recovered ({bad} bad areas). The mapfile "
                         f"{plan.mapfile} lets you try again.")
        # finished: close the claim, tidy the table, retire the mapfile
        if writes_device and fd is not None:
            os.close(fd)
            fd = None
            if left == 0:
                notes += _after_copy(ctx, plan, disk, h)
        _retire_mapfile(plan) if left == 0 else None
        if kind == CopyKind.IMAGE:
            _write_info(plan, notes)
        rep.emit("copy done", f"kind={kind.value}", f"bytes={done}", f"errors={left}",
                 f"sha256={sha or '-'}")
        return CopyResult(ok=True, bytes=done, errors=left, sha256=sha, notes=notes)
    except BeastNetError:
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        t_timeout.restore()
        if unlocked:
            try:
                if writable is not None and hasattr(writable, "close"):
                    writable.close()
                h.relock(ctx)
            except Exception:  # never hide the real error behind a guard failure
                pass


def _run_child(h: Hooks, argv, plan, report, should_stop) -> tuple[int, bool, str]:
    logp = plan.mapfile + ".log"
    with open(logp, "ab") as log:
        proc = h.spawn(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
        stopped = False
        try:
            while True:
                try:
                    rc = proc.wait(timeout=h.poll)
                    break
                except subprocess.TimeoutExpired:
                    pass
                report()
                if not stopped and should_stop():
                    stopped = True
                    proc.send_signal(signal.SIGINT)  # ddrescue saves the mapfile and exits
                    try:
                        rc = proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        try:
                            rc = proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            rc = proc.wait()
                    break
        except BaseException:
            proc.kill()
            proc.wait()
            raise
    try:
        with open(logp, "rb") as f:
            f.seek(max(0, os.path.getsize(logp) - 2000))
            err = f.read().decode(errors="replace")
    except OSError:
        err = ""
    return rc, stopped, err


INFO_SUFFIX = ".info.json"  # next to an image: what a restore must match


def _write_info(plan: DiskCopyPlan, notes: list[str]) -> None:
    try:
        with open(plan.target + INFO_SUFFIX, "w", encoding="utf-8") as f:
            json.dump({"logical_sector": plan.sector, "size": plan.size, "source": plan.src_label}, f)
    except OSError:
        notes.append("Could not write the .info.json file next to the image (its sector size).")


def read_info(image: str) -> dict:
    try:
        with open(image + INFO_SUFFIX, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _verify(plan: DiskCopyPlan, should_stop, tick, notes) -> str:
    if plan.kind == CopyKind.IMAGE:
        sha, _ = _hash_range(plan.target, plan.size, should_stop, tick)
        try:
            with open(plan.target + ".sha256", "w", encoding="utf-8") as f:
                f.write(f"{sha}  {os.path.basename(plan.target)}\n")
        except OSError:
            notes.append("Could not write the .sha256 file next to the image.")
        return sha
    sha, same = _hash_range(plan.target, plan.size, should_stop, tick, other=plan.source)
    if not same:
        raise BeastNetError(E.DISK_IO, "read-back check failed: the target does not match the source",
                            "The target disk may be failing. Do not rely on this copy.")
    notes.append("Read-back check passed: the target matches the source.")
    return sha


def _retire_mapfile(plan: DiskCopyPlan) -> None:
    try:
        os.replace(plan.mapfile, plan.mapfile + ".done")
    except OSError:
        pass


def _after_copy(ctx, plan: DiskCopyPlan, disk: Disk | None, h: Hooks) -> list[str]:
    """GPT backup header to the end of a larger disk; ask the kernel to re-read."""
    notes: list[str] = []
    if disk is None or plan.target_is_partition:
        return notes
    ss = disk.logical_sector or 512
    if disk.size > plan.size:
        try:
            with open(plan.target, "rb", buffering=0) as f:
                f.seek(ss)
                hdr = f.read(92)
        except OSError:
            hdr = b""
        if hdr[:8] == b"EFI PART":
            alt = int.from_bytes(hdr[32:40], "little")
            if alt != disk.size // ss - 1:
                cp = ctx.system.runner.run(["sfdisk", "--relocate", "gpt-bak-std", plan.target], timeout=120)
                if cp.returncode == 0:
                    notes.append("Moved the GPT backup table to the end of the larger disk.")
                else:
                    notes.append("Could not move the GPT backup table; run: sfdisk --relocate gpt-bak-std "
                                 + plan.target)
        else:
            notes.append("The target is larger; the extra space is unused until you extend a partition.")
    try:
        import fcntl
        fd = os.open(plan.target, os.O_RDONLY)
        try:
            fcntl.ioctl(fd, 0x125F, 0)  # BLKRRPART
        finally:
            os.close(fd)
    except (OSError, ImportError):
        pass
    return notes


class _SgTimeout:
    """Shorten the SCSI command timeout of source disks while copying (a dying
    disk should not stall the bus for minutes); restored afterwards."""

    def __init__(self, ctx, plan: DiskCopyPlan) -> None:
        self.saved: dict[str, str] = {}
        self.ctx, self.plan = ctx, plan

    def apply(self) -> None:
        for did in self.plan.source_disk_ids:
            p = os.path.join(self.ctx.paths.sys, "block", did, "device", "timeout")
            try:
                with open(p) as f:
                    old = f.read().strip()
                with open(p, "w") as f:
                    f.write("30")
                self.saved[p] = old
            except OSError:
                pass

    def restore(self) -> None:
        for p, old in self.saved.items():
            try:
                with open(p, "w") as f:
                    f.write(old)
            except OSError:
                pass
