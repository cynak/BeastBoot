"""Copy-on-write overlays over RAID members (docs/DISK_TOOLS.md, safety rule 2).

Every reconstruction experiment runs on dm-snapshot overlays: reads come from the
member, writes (md superblocks, a journal replay nobody asked for) land in a COW file
in RAM. The COW files live in a tmpfs we mount ourselves with ``size=<cap>``, so the
kernel enforces the cap: when it is full the snapshot turns invalid and writes fail;
a member is never written. The COW never goes on a member, the BeastBoot stick or
any disk at all.

  create(ctx, devices, cow_dir=None, cap_bytes=None, prefix=PREFIX) -> overlay paths (/dev/mapper/<prefix>*)
  remove(ctx, overlays)        dmsetup remove, losetup -d, delete the COW file
  owned(ctx, prefix, devices)  the overlays one user (prefix) made over these devices
  usage(ctx) -> list[Usage]    from `dmsetup status` (allocated / total sectors)
  ensure_room(ctx)             refuses (code reconstruct) when the tmpfs is nearly full

The disk guard sets BLKROSET on every dm node; overlays must stay writable for md
--create, so each overlay's dm kernel name ("dm-7") is exempted through the ``exempt``
hook (default: disks.guard.exempt) and un-exempted on removal. Members stay read-only:
dm-snapshot opens its origin for reading only.

Users: reconstruction (prefix "bbov_") and read-only assembly (assemble.OVERLAY_PREFIX,
"bbro_", not exempted: md and LVM write through the kernel, which only warns on a
read-only node, and those writes land in the COW). An overlay is only ever reused by
the user (prefix) that made it, so a started stack and a reconstruction of the same
disks never share one: each has its own snapshot of the member, and tearing one down
cannot touch the other's.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

from ..errors import DISK_REFUSED, RECONSTRUCT, BeastNetError

PREFIX = "bbov_"                    # reconstruction
PREFIXES = ("bbov_", "bbro_")       # every overlay user (assembly: "bbro_")
DM_ENV = {"DM_DISABLE_UDEV": "1"}   # no udev in the helper: libdevmapper makes the nodes
STATE = "overlays.json"
MiB = 1024 * 1024
MIN_CAP = 32 * MiB
ROOM = 0.85                         # refuse new work above this share of the cap
RAM_FS = ("tmpfs", "ramfs", "rootfs")

Hook = Callable[..., None]
_statvfs = os.statvfs  # tests replace it


@dataclass
class Overlay:
    name: str        # dm name, "bbov_sdb"
    path: str        # "/dev/mapper/bbov_sdb"
    device: str      # the member it covers
    loop: str        # loop device holding the COW
    cow: str         # sparse COW file in the tmpfs
    sectors: int     # size of the member (and the overlay), 512-byte sectors
    kname: str = ""  # "dm-7", for the guard


@dataclass
class Usage:
    name: str
    used: int        # bytes of COW in use (data + metadata)
    total: int       # bytes the COW can hold
    invalid: bool    # the snapshot overflowed (writes fail; the member is untouched)


def _guard_exempt(*names: str) -> None:
    try:
        from . import guard  # type: ignore[attr-defined]
    except ImportError:
        return
    guard.exempt(*names)


def _guard_unexempt(*names: str) -> None:
    try:
        from . import guard  # type: ignore[attr-defined]
    except ImportError:
        return
    guard.unexempt(*names)


def _run(ctx, argv: Sequence[str], *, timeout: float = 60, env: dict | None = None):
    return ctx.system.runner.run(list(argv), timeout=timeout, env=env)


def _fail(text: str, cp=None, code: str = RECONSTRUCT) -> BeastNetError:
    if cp is not None:
        detail = (cp.stderr or cp.stdout or "").strip().splitlines()
        text = f"{text}: {detail[-1] if detail else f'exit {cp.returncode}'}"
    return BeastNetError(code, text)


def cow_root(ctx) -> str:
    return os.path.join(ctx.paths.run, "overlay")


def _mounts(ctx) -> list[tuple[str, str]]:
    """(mount point, fs type) from /proc/mounts."""
    out = []
    try:
        with open(os.path.join(ctx.paths.proc, "mounts"), encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    out.append((parts[1].replace("\\040", " "), parts[2]))
    except OSError:
        pass
    return out


def fs_type_of(ctx, path: str) -> str:
    """Type of the filesystem holding ``path`` (longest mount-point prefix)."""
    real = os.path.realpath(path)
    best, kind = "", ""
    for mnt, t in _mounts(ctx):
        if (real == mnt or real.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
            best, kind = mnt, t
    return kind


def _under(path: str, top: str) -> bool:
    a, b = os.path.realpath(path), os.path.realpath(top)
    return a == b or a.startswith(b.rstrip("/") + "/")


def default_cap(ctx) -> int:
    """A quarter of the available RAM, at most 4 GiB."""
    avail = 0
    try:
        with open(os.path.join(ctx.paths.proc, "meminfo"), encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return min(avail // 4, 4096 * MiB) if avail else 256 * MiB


def _load(cow_dir: str) -> dict[str, Overlay]:
    try:
        with open(os.path.join(cow_dir, STATE), encoding="utf-8") as f:
            return {k: Overlay(**v) for k, v in json.load(f).items()}
    except (OSError, ValueError, TypeError):
        return {}


def _save(cow_dir: str, state: dict[str, Overlay]) -> None:
    tmp = os.path.join(cow_dir, STATE + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({k: asdict(v) for k, v in state.items()}, f)
    os.replace(tmp, os.path.join(cow_dir, STATE))


def overlays(ctx, cow_dir: str | None = None) -> dict[str, Overlay]:
    """Overlays this session made, by overlay path."""
    return _load(cow_dir or cow_root(ctx))


def _prepare(ctx, cow_dir: str, cap: int) -> None:
    for top in (ctx.paths.data, ctx.paths.esp):
        if top and _under(cow_dir, top):
            raise _fail(f"refusing to put overlay data on the BeastBoot stick ({cow_dir})", code=DISK_REFUSED)
    os.makedirs(cow_dir, mode=0o700, exist_ok=True)
    if fs_type_of(ctx, cow_dir) != "tmpfs" or os.path.realpath(cow_dir) not in {m for m, _ in _mounts(ctx)}:
        cp = _run(ctx, ["mount", "-t", "tmpfs", "-o", f"size={cap},mode=0700", "bbcow", cow_dir])
        if cp.returncode != 0:
            raise _fail("could not make the RAM area for overlays", cp)
    kind = fs_type_of(ctx, cow_dir)
    if kind not in RAM_FS:
        raise _fail(f"overlay data must stay in RAM, but {cow_dir} is on {kind or 'an unknown filesystem'}",
                    code=DISK_REFUSED)


def _size_sectors(ctx, dev: str) -> int:
    cp = _run(ctx, ["blockdev", "--getsize64", dev])
    try:
        return int(cp.stdout.strip()) // 512 if cp.returncode == 0 else 0
    except ValueError:
        return 0


def dm_kname(ctx, name: str) -> str:
    """Kernel name ("dm-7") of a dm device, by `dmsetup info`, else sysfs."""
    cp = _run(ctx, ["dmsetup", "info", "-c", "--noheadings", "-o", "blkdevname", name], env=DM_ENV)
    k = cp.stdout.strip() if cp.returncode == 0 else ""
    if re.fullmatch(r"dm-\d+", k):
        return k
    block = os.path.join(ctx.paths.sys, "block")
    try:
        for d in os.listdir(block):
            if d.startswith("dm-"):
                try:
                    with open(os.path.join(block, d, "dm", "name"), encoding="utf-8") as f:
                        if f.read().strip() == name:
                            return d
                except OSError:
                    continue
    except OSError:
        pass
    return ""


def is_overlay_name(name: str) -> bool:
    """A dm name ("bbov_sdb") one of our overlays uses."""
    return name.startswith(PREFIXES)


def is_overlay_kname(ctx, kname: str) -> bool:
    """Is the dm kernel device ``kname`` ("dm-7") one of our overlays (by its dm name in sysfs)?"""
    try:
        with open(os.path.join(ctx.paths.sys, "block", kname, "dm", "name"), encoding="utf-8") as f:
            return is_overlay_name(f.read().strip())
    except OSError:
        return False


def owned(ctx, prefix: str, devices: Sequence[str] | None = None, *, cow_dir: str | None = None) -> list[Overlay]:
    """The overlays made with ``prefix`` (over ``devices``, when given), in ``devices`` order."""
    mine = [o for o in _load(cow_dir or cow_root(ctx)).values() if o.name.startswith(prefix)]
    if devices is None:
        return mine
    by_dev = {o.device: o for o in mine}
    return [by_dev[d] for d in devices if d in by_dev]


def _dm_name(dev: str, taken: set[str], prefix: str = PREFIX) -> str:
    base = prefix + (re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(dev.rstrip("/"))) or "dev")
    name, i = base, 1
    while name in taken:
        i += 1
        name = f"{base}_{i}"
    return name


def create(ctx, devices: Sequence[str], *, cow_dir: str | None = None, cap_bytes: int | None = None,
           exempt: Hook | None = None, prefix: str = PREFIX) -> list[str]:
    """An overlay over each device; returns their paths in the same order. An overlay this
    ``prefix`` already has over a device is reused; one another user made is not."""
    if not prefix.startswith(PREFIXES) or not re.fullmatch(r"[a-z]+_", prefix):
        raise ValueError(f"unknown overlay prefix {prefix!r}")
    cow_dir = cow_dir or cow_root(ctx)
    state = _load(cow_dir)
    have = {o.device: o for o in state.values() if o.name.startswith(prefix)}
    cap = cap_bytes or default_cap(ctx)
    if cap < MIN_CAP:
        raise _fail(f"not enough RAM for overlays ({cap // MiB} MiB; {MIN_CAP // MiB} MiB needed)")
    if not state:
        _prepare(ctx, cow_dir, cap)
    else:
        ensure_room(ctx, cow_dir=cow_dir)
    exempt = exempt or _guard_exempt
    out = []
    made: list[Overlay] = []
    try:
        for dev in devices:
            if dev in have:
                out.append(have[dev].path)
                continue
            sectors = _size_sectors(ctx, dev)
            if sectors <= 0:
                raise _fail(f"cannot read the size of {dev}")
            name = _dm_name(dev, {o.name for o in state.values()}, prefix)
            cow = os.path.join(cow_dir, name + ".cow")
            with open(cow, "wb") as f:
                f.truncate(cap)                       # sparse; the tmpfs size is the real cap
            cp = _run(ctx, ["losetup", "--find", "--show", cow])
            loop = cp.stdout.strip() if cp.returncode == 0 else ""
            if not loop.startswith("/dev/"):
                os.unlink(cow)
                raise _fail(f"no loop device for the overlay of {dev}", cp)
            ov = Overlay(name, f"/dev/mapper/{name}", dev, loop, cow, sectors)
            cp = _run(ctx, ["dmsetup", "create", name, "--table", f"0 {sectors} snapshot {dev} {loop} P 8"],
                      env=DM_ENV)
            if cp.returncode != 0:
                _run(ctx, ["losetup", "-d", loop])
                os.unlink(cow)
                raise _fail(f"could not create the overlay of {dev}", cp)
            ov.kname = dm_kname(ctx, name)
            if ov.kname:
                exempt(ov.kname)
            state[ov.path] = ov
            made.append(ov)
            _save(cow_dir, state)
            out.append(ov.path)
    except BaseException:
        if made:
            remove(ctx, [o.path for o in made], cow_dir=cow_dir)
        raise
    return out


def remove(ctx, paths: Sequence[str], *, cow_dir: str | None = None, unexempt: Hook | None = None) -> None:
    """Tear overlays down (dm first, then the loop, then the COW file)."""
    cow_dir = cow_dir or cow_root(ctx)
    state = _load(cow_dir)
    unexempt = unexempt or _guard_unexempt
    errors = []
    for p in paths:
        # by path or dm name; by member device only among reconstruction overlays (the
        # old callers), so a device name never takes down another user's overlay
        ov = state.get(p) or next((o for o in state.values() if p == o.name), None) or \
            next((o for o in state.values() if p == o.device and o.name.startswith(PREFIX)), None)
        if ov is None:
            continue
        cp = _run(ctx, ["dmsetup", "remove", "--retry", ov.name], env=DM_ENV)
        if cp.returncode != 0:
            errors.append(f"{ov.name}: {(cp.stderr or '').strip()}")
            continue
        if ov.kname:
            unexempt(ov.kname)
        _run(ctx, ["losetup", "-d", ov.loop])
        try:
            os.unlink(ov.cow)
        except OSError:
            pass
        state.pop(ov.path, None)
    if os.path.isdir(cow_dir):
        _save(cow_dir, state)
    if not state and os.path.realpath(cow_dir) in {m for m, _ in _mounts(ctx)}:
        _run(ctx, ["umount", cow_dir])
    if errors:
        raise _fail("could not remove overlay " + "; ".join(errors))


def parse_status(line: str) -> tuple[int, int, bool] | None:
    """(used sectors, total sectors, invalid) from one `dmsetup status` snapshot line."""
    parts = line.split()
    if len(parts) < 4 or parts[2] != "snapshot":
        return None
    if parts[3] in ("Invalid", "Overflow", "Merge", "Unknown"):
        return 0, 0, parts[3] in ("Invalid", "Overflow")
    m = re.fullmatch(r"(\d+)/(\d+)", parts[3])
    if not m:
        return None
    used = int(m.group(1))
    if len(parts) >= 5 and parts[4].isdigit():
        used = max(used, int(parts[4]))  # metadata sectors are part of the allocation
    return used, int(m.group(2)), False


def usage(ctx, *, cow_dir: str | None = None) -> list[Usage]:
    out = []
    for ov in _load(cow_dir or cow_root(ctx)).values():
        cp = _run(ctx, ["dmsetup", "status", ov.name], env=DM_ENV)
        st = parse_status(cp.stdout.strip()) if cp.returncode == 0 else None
        if st is None:
            out.append(Usage(ov.name, 0, 0, True))
            continue
        out.append(Usage(ov.name, st[0] * 512, st[1] * 512, st[2]))
    return out


def ensure_room(ctx, *, cow_dir: str | None = None, fraction: float = ROOM) -> None:
    """Refuse (code reconstruct) when the overlays' RAM is nearly full or one overflowed."""
    cow_dir = cow_dir or cow_root(ctx)
    try:
        st = _statvfs(cow_dir)
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    except OSError:
        total = free = 0
    if total and (total - free) >= fraction * total:
        raise _fail(f"the RAM for overlays is {100 * (total - free) // total}% full; "
                    "tear down a reconstruction first")
    for u in usage(ctx, cow_dir=cow_dir):
        if u.invalid:
            raise _fail(f"overlay {u.name} overflowed; tear the reconstruction down and start again")
