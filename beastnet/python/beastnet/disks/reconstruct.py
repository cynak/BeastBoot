"""Generic RAID reconstruction (docs/DISK_TOOLS.md, sections 1-5).

For arrays whose metadata no Linux tool reads (AMD RAIDXpert2, Storage Spaces
simple/mirror, unknown NAS layouts, destroyed metadata):

  detect(ctx, devices, budget_bytes=...) -> list[Candidate]   ranked, from the data only
  build(ctx, devices, cand) -> Volume       assembled on copy-on-write overlays, read-only
  validate(ctx, volume) -> float            > 0 when a filesystem on it reads (evidence kept)
  teardown(ctx, volume)                     everything build made, in reverse order
  manual(ctx, devices, level=..., ...)      the manual builder: build() with the user's Candidate
  auto(ctx, devices)                        detect, build + validate the best few, keep the best

Safety (rule 2): members are only ever opened O_RDONLY here (detect reads them; build
and validate never open them at all) and are only named to the kernel as the origin of
a dm-snapshot, which reads its origin. raid0/raid1/raid10/linear volumes are dm tables
(striped/linear) over the overlays, loaded --readonly: nothing is written anywhere.
raid5/raid6 need md: `mdadm --create --assume-clean --bitmap=none` runs on per-member
views = [1 MiB RAM prefix for the md superblock | the overlay from the data offset],
so the superblock lands in RAM, not even in an overlay; the array is switched
read-only and its sync_action frozen right after.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..errors import RECONSTRUCT, BeastNetError
from . import fswalk, overlay, raidmath
from .model import Candidate, Volume, VolumeKind

KiB = 1024
MiB = 1024 * KiB
DEFAULT_BUDGET = 256 * MiB           # bytes read from each member by detect()
PREFIX = "bbrc"
EXT = 1 * MiB                        # RAM prefix of each md view (holds the md superblock)
MD_ENV = {"MDADM_NO_UDEV": "1"}
FS_MOUNT = {  # start_kind -> (mount type, options)
    "ext": ("ext4", "ro,noatime,nodev,nosuid,noexec,noload"),
    "xfs": ("xfs", "ro,noatime,nodev,nosuid,noexec,norecovery"),
    "ntfs": ("ntfs3", "ro,noatime,nodev,nosuid,noexec"),
    "btrfs": ("btrfs", "ro,noatime,nodev,nosuid,noexec,rescue=nologreplay"),
    "fat": ("vfat", "ro,noatime,nodev,nosuid,noexec"),
    "exfat": ("exfat", "ro,noatime,nodev,nosuid,noexec"),
}
WALK_ENTRIES = 20000


@dataclass
class Built:
    volume: Volume
    candidate: Candidate
    devices: list[str]
    overlays: list[str]
    dm: list[str] = field(default_factory=list)       # dm names made on top, in creation order
    exempt: list[str] = field(default_factory=list)   # dm kernel names given to the guard
    md: str = ""
    loop: str = ""
    files: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


_BUILT: dict[str, Built] = {}


# -- plumbing --------------------------------------------------------------------------------

def _run(ctx, argv: Sequence[str], *, timeout: float = 120, env: dict | None = None):
    return ctx.system.runner.run(list(argv), timeout=timeout, env=env)


def _err(text: str, cp=None, hint: str = "") -> BeastNetError:
    if cp is not None:
        lines = (cp.stderr or cp.stdout or "").strip().splitlines()
        text = f"{text}: {lines[-1] if lines else f'exit {cp.returncode}'}"
    return BeastNetError(RECONSTRUCT, text, hint)


def _open_ro(path: str) -> int:
    """The only way this module opens a device: read-only."""
    return os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))


def _reader(fd: int):
    return lambda off, n: os.pread(fd, n, off)


def _dev_size(fd: int) -> int:
    return os.lseek(fd, 0, os.SEEK_END)


def _disk_id(ctx, dev: str) -> str:
    name = os.path.basename(os.path.realpath(dev))
    p = os.path.join(ctx.paths.sys, "class", "block", name)
    if os.path.exists(os.path.join(p, "partition")):
        return os.path.basename(os.path.dirname(os.path.realpath(p)))
    return name


def _guard(ctx, names: Sequence[str], on: bool) -> None:
    hook = overlay._guard_exempt if on else overlay._guard_unexempt
    for n in names:
        if n:
            hook(n)


# -- detect ---------------------------------------------------------------------------------

def detect(ctx, devices: Sequence[str], *, budget_bytes: int = DEFAULT_BUDGET,
           levels: Sequence[str] | None = None, allow_missing: bool = True, top: int = 5) -> list[Candidate]:
    """Ranked reconstruction candidates for ``devices`` (members, any order)."""
    devices = list(devices)
    if len(devices) < 2:
        raise _err("reconstruction needs at least two member disks")
    fds = []
    try:
        for d in devices:
            try:
                fds.append(_open_ro(d))
            except OSError as e:
                raise _err(f"cannot read {d}: {e.strerror}") from None
        src = raidmath.Source([_reader(fd) for fd in fds], [_dev_size(fd) for fd in fds], budget=budget_bytes)
        a = raidmath.analyse(src, levels=levels, allow_missing=allow_missing, top=top)
    finally:
        for fd in fds:
            os.close(fd)
    per = max(a.bytes_read) if a.bytes_read else 0
    out = []
    for h in a.hypotheses[:top]:
        g = h.geom
        order = [devices[m] if m != raidmath.MISSING else "" for m in h.order]
        member_size = None
        vs = h.result.hints.get("volume_size")
        if vs and g.level not in ("linear",) and g.data_slots:
            need = -(-vs // g.data_slots)
            if g.chunk:
                need = -(-need // g.chunk) * g.chunk
            if need < raidmath.usable_size(g, src.sizes):
                member_size = need
        ev = list(h.evidence) + [f"read {per // MiB} MiB per member in {a.seconds:.1f} s"] + a.notes
        out.append(Candidate(level=g.level, chunk=g.chunk, order=order, data_offset=g.offset, layout=g.layout,
                             member_size=member_size, score=h.confidence, evidence=ev))
    for rank, c in enumerate(out, 1):
        idx = ",".join(str(devices.index(d)) if d else "-" for d in c.order)
        ctx.reporter.emit("reconstruct candidate", f"rank={rank}", f"level={c.level}", f"chunk={c.chunk}",
                          f"order={idx}", f"layout={c.layout or '-'}", f"offset={c.data_offset}",
                          f"score={c.score:.3f}")
    if not out or out[0].score <= 0:
        raise _err("no known filesystem or partition table fits these members as an array",
                   hint="The data may be encrypted, or the disks may not belong together. "
                        "Use the manual RAID builder if you know the parameters.")
    return out


# -- build ----------------------------------------------------------------------------------

def check_candidate(devices: Sequence[str], cand: Candidate) -> None:
    """Refuse parameters md/dm cannot build (the manual builder's input check)."""
    lv = cand.level
    if lv not in raidmath.LEVELS:
        raise _err(f"unknown RAID level {lv!r}")
    present = [d for d in cand.order if d]
    if len(set(present)) != len(present) or any(d not in devices for d in present):
        raise _err("the member order must name each member once")
    missing = len(cand.order) - len(present)
    allowed = {"raid0": 0, "linear": 0, "raid1": len(cand.order) - 1, "raid5": 1, "raid6": 2,
               "raid10": len(cand.order) // 2}[lv]
    if missing > allowed:
        raise _err(f"{lv} cannot be read with {missing} member(s) missing")
    need = {"raid0": 2, "linear": 2, "raid1": 2, "raid5": 3, "raid6": 4, "raid10": 4}[lv]
    if len(cand.order) < need:
        raise _err(f"{lv} needs at least {need} members")
    if lv in ("raid0", "raid5", "raid6", "raid10"):
        c = cand.chunk
        if c < 4 * KiB or c > 16 * MiB or c & (c - 1):
            raise _err("the chunk size must be a power of two from 4 KiB to 16 MiB")
    if lv in ("raid5", "raid6") and cand.layout not in raidmath.LAYOUTS:
        raise _err(f"unknown layout {cand.layout!r}")
    if lv == "raid10" and len(cand.order) % 2:
        raise _err("raid10 (near 2) needs an even number of members")
    if cand.data_offset < 0 or cand.data_offset % 512:
        raise _err("the data offset must be a multiple of 512 bytes")


def _next_id() -> str:
    i = 0
    while f"{PREFIX}{i}" in _BUILT:
        i += 1
    return f"{PREFIX}{i}"


def _free_md(ctx) -> str:
    for n in range(120, 1000):
        if not os.path.exists(os.path.join(ctx.paths.sys, "block", f"md{n}")) \
                and not any(b.md == f"/dev/md{n}" for b in _BUILT.values()):
            return f"/dev/md{n}"
    raise _err("no free md device number")


def _dm_create(ctx, b: Built, name: str, table: str, *, readonly: bool, exempt: bool = False) -> str:
    argv = ["dmsetup", "create", name] + (["--readonly"] if readonly else []) + ["--table", table]
    cp = _run(ctx, argv, env=overlay.DM_ENV)
    if cp.returncode != 0:
        raise _err(f"could not create {name}", cp)
    b.dm.append(name)
    if exempt:
        k = overlay.dm_kname(ctx, name)
        if k:
            overlay._guard_exempt(k)
            b.exempt.append(k)
    return f"/dev/mapper/{name}"


def build(ctx, devices: Sequence[str], cand: Candidate, *, cap_bytes: int | None = None) -> Volume:
    """Assemble ``cand`` on overlays of the members; returns a read-only Volume."""
    devices = list(devices)
    check_candidate(devices, cand)
    vid = _next_id()
    present = [d for d in cand.order if d]
    ovl = overlay.create(ctx, present, cap_bytes=cap_bytes)
    by_dev = dict(zip(present, ovl))
    vol = Volume(id=vid, path="", kind=VolumeKind.OVERLAY_ARRAY, size=0, readonly=True,
                 disk_ids=sorted({_disk_id(ctx, d) for d in present}))
    b = Built(vol, cand, devices, ovl)
    _BUILT[vid] = b
    try:
        sizes = {d: overlay._size_sectors(ctx, by_dev[d]) * 512 for d in present}
        if min(sizes.values()) <= cand.data_offset:
            raise _err("the data offset is beyond the end of a member")
        _assemble(ctx, b, by_dev, sizes)
    except BaseException:
        teardown(ctx, vol)
        raise
    b.evidence.append(f"built {cand.level} on overlays: {vol.path} ({vol.size // MiB} MiB, read-only)")
    return vol


def _assemble(ctx, b: Built, by_dev: dict[str, str], sizes: dict[str, int]) -> None:
    c = b.candidate
    lv, chunk, off = c.level, c.chunk, c.data_offset
    off_s = off // 512
    vol = b.volume
    if lv == "linear":
        rows, pos = [], 0
        for d in c.order:
            ln = sizes[d] - off
            if chunk:
                ln -= ln % chunk
            if c.member_size:
                ln = min(ln, c.member_size)
            rows.append(f"{pos // 512} {ln // 512} linear {by_dev[d]} {off_s}")
            pos += ln
        vol.path = _dm_create(ctx, b, b.volume.id, "\n".join(rows), readonly=True)
        vol.size = pos
        return
    usable = min(sizes.values()) - off
    if c.member_size:
        usable = min(usable, c.member_size)
    if chunk and lv != "raid1":
        usable -= usable % chunk
    if usable <= 0:
        raise _err("the members are too small for these parameters")
    if lv == "raid1":
        first = next(d for d in c.order if d)
        vol.path = _dm_create(ctx, b, vol.id, f"0 {usable // 512} linear {by_dev[first]} {off_s}", readonly=True)
        vol.size = usable
        return
    if lv in ("raid0", "raid10"):
        if lv == "raid0":
            legs = [by_dev[d] for d in c.order]
        else:  # near-2: raid0 over the mirrored pairs, one copy of each
            legs = []
            for i in range(0, len(c.order), 2):
                d = c.order[i] or c.order[i + 1]
                if not d:
                    raise _err("both copies of a raid10 pair are missing")
                legs.append(by_dev[d])
        total = usable * len(legs)
        table = f"0 {total // 512} striped {len(legs)} {chunk // 512} " + \
            " ".join(f"{leg} {off_s}" for leg in legs)
        vol.path = _dm_create(ctx, b, vol.id, table, readonly=True)
        vol.size = total
        return
    # raid5 / raid6: md on views [RAM prefix | overlay from the data offset]
    n = len(c.order)
    cow_dir = overlay.cow_root(ctx)
    ext = os.path.join(cow_dir, f"{vol.id}.ext")
    with open(ext, "wb") as f:
        f.truncate(n * EXT)
    b.files.append(ext)
    cp = _run(ctx, ["losetup", "--find", "--show", ext])
    b.loop = cp.stdout.strip() if cp.returncode == 0 else ""
    if not b.loop.startswith("/dev/"):
        raise _err("no loop device for the md superblocks", cp)
    legs = []
    for i, d in enumerate(c.order):
        if not d:
            legs.append("missing")
            continue
        table = f"0 {EXT // 512} linear {b.loop} {i * EXT // 512}\n" \
                f"{EXT // 512} {usable // 512} linear {by_dev[d]} {off_s}"
        legs.append(_dm_create(ctx, b, f"{vol.id}_v{i}", table, readonly=False, exempt=True))
    md = _free_md(ctx)
    argv = ["mdadm", "--create", md, "--run", "--force", "--assume-clean", "--bitmap=none",
            "--metadata=1.2", f"--data-offset={EXT // KiB}K", f"--level={lv[4:]}", f"--layout={c.layout}",
            f"--chunk={chunk // KiB}K", f"--raid-devices={n}", f"--size={usable // KiB}K",
            f"--name={vol.id}", *legs]
    cp = _run(ctx, argv, timeout=120, env=MD_ENV)
    if cp.returncode != 0:
        raise _err("mdadm could not assemble the candidate on the overlays", cp)
    b.md = md
    _run(ctx, ["mdadm", "--readonly", md], env=MD_ENV)
    sync = os.path.join(ctx.paths.sys, "block", os.path.basename(md), "md", "sync_action")
    try:
        with open(sync, "w", encoding="ascii") as f:
            f.write("frozen\n")
    except OSError:
        pass
    vol.path = md
    vol.size = usable * (n - (1 if lv == "raid5" else 2))


def manual(ctx, devices: Sequence[str], *, level: str, chunk: int = 0, order: Sequence[str] | None = None,
           layout: str = "", offset: int = 0, member_size: int | None = None,
           cap_bytes: int | None = None) -> Volume:
    """The manual RAID builder: the user's parameters, built like a detected candidate."""
    cand = Candidate(level=level, chunk=chunk, order=list(order if order is not None else devices),
                     data_offset=offset, layout=layout, member_size=member_size,
                     evidence=["parameters given by hand"])
    return build(ctx, devices, cand, cap_bytes=cap_bytes)


# -- validate -------------------------------------------------------------------------------

def evidence(volume: Volume) -> list[str]:
    b = _BUILT.get(volume.id)
    return list(b.evidence) if b else []


def _walk_dir(top: str, limit: int = WALK_ENTRIES) -> tuple[int, int]:
    """(entries seen, errors) walking a mounted filesystem and reading file heads."""
    entries = errors = reads = 0

    def onerror(_e: OSError) -> None:
        nonlocal errors
        errors += 1

    for root, dirs, files in os.walk(top, onerror=onerror):
        entries += len(dirs) + len(files)
        for name in files:
            if reads >= 64:
                break
            p = os.path.join(root, name)
            try:
                if not stat.S_ISREG(os.lstat(p).st_mode):
                    continue  # no FIFOs, sockets or device nodes
            except OSError:
                errors += 1
                continue
            reads += 1
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.read(fd, 4096)
                finally:
                    os.close(fd)
            except OSError:
                errors += 1
        if entries >= limit:
            break
    return entries, errors


def _targets(ctx, b: Built) -> list[tuple[str, int]]:
    """(device, size) of what to check: the partitions when there is a table, else the volume."""
    vol = b.volume
    fd = _open_ro(vol.path)
    try:
        head = os.pread(fd, 64 * KiB, 0)
    finally:
        os.close(fd)
    parts = fswalk.gpt_partitions(head)
    if not parts:
        return [(vol.path, vol.size)]
    out = []
    for i, (start, size) in enumerate(parts[:8], 1):
        if start + size > vol.size:
            size = vol.size - start
        if size <= 0:
            continue
        p = _dm_create(ctx, b, f"{vol.id}p{i}", f"0 {size // 512} linear {vol.path} {start // 512}", readonly=True)
        out.append((p, size))
    return out


def validate(ctx, volume: Volume) -> float:
    """Score 0..1; > 0 means a filesystem on the volume mounts read-only (or checks clean)."""
    b = _BUILT.get(volume.id)
    if b is None:
        raise _err(f"{volume.id} is not a reconstruction")
    overlay.ensure_room(ctx)
    ev: list[str] = []
    fd = _open_ro(volume.path)
    try:
        res = fswalk.run(_reader(fd), volume.size, 3000)
    finally:
        os.close(fd)
    tot = res.passed + res.failed
    walk = res.passed / tot if tot else 0.0
    ev.append(f"structure checks on the volume: {int(res.passed)}/{int(tot)} passed")
    best = 0.0
    for dev, _size in _targets(ctx, b):
        fd = _open_ro(dev)
        try:
            head = os.pread(fd, 72 * KiB, 0)
        finally:
            os.close(fd)
        kind = fswalk.start_kind(head[:8 * KiB]) or ("btrfs" if fswalk.btrfs_super(head[64 * KiB:]) else "")
        fsck = None
        if kind == "ext":
            cp = _run(ctx, ["e2fsck", "-n", "-f", dev], timeout=1800)
            fsck = {0: True, 1: True, 4: False}.get(cp.returncode)
        elif kind == "xfs":
            cp = _run(ctx, ["xfs_repair", "-n", dev], timeout=1800)
            fsck = {0: True, 1: False}.get(cp.returncode)
        if fsck is not None:
            ev.append(f"{dev}: {'e2fsck' if kind == 'ext' else 'xfs_repair'} -n "
                      f"{'found no errors' if fsck else 'found errors'}")
        mounted, entries, errors = False, 0, 0
        if kind in FS_MOUNT:
            mnt = os.path.join(ctx.paths.run, "rc-mnt", os.path.basename(dev))
            os.makedirs(mnt, exist_ok=True)
            fstype, opts = FS_MOUNT[kind]
            cp = _run(ctx, ["mount", "-t", fstype, "-o", opts, dev, mnt], timeout=120)
            if cp.returncode == 0:
                mounted = True
                try:
                    entries, errors = _walk_dir(mnt)
                finally:
                    if _run(ctx, ["umount", mnt], timeout=120).returncode != 0:
                        _run(ctx, ["umount", "-l", mnt], timeout=60)
                ev.append(f"{dev}: {fstype} mounts read-only; {entries} entries, {errors} read errors")
            else:
                ev.append(f"{dev}: {fstype} does not mount")
        if not mounted and not fsck:
            continue
        s = 0.25 * walk
        s += 0.35 if mounted else 0.0
        s += {True: 0.25, False: 0.05, None: 0.15}[fsck]
        if mounted and entries:
            s += 0.15 * (1 - min(1.0, errors / max(1, entries)))
        best = max(best, round(min(s, 1.0), 3))
    if not best:
        ev.append("no filesystem on it reads")
    b.evidence += ev
    b.candidate.evidence += ev
    return best


# -- teardown -------------------------------------------------------------------------------

def teardown(ctx, volume: Volume) -> None:
    """Remove everything build() made (users first, overlays last). Safe to repeat."""
    b = _BUILT.pop(volume.id, None)
    if b is None:
        return
    problems: list[str] = []

    def dm_remove(names: Sequence[str]) -> None:
        for n in reversed(names):
            for _ in range(3):
                cp = _run(ctx, ["dmsetup", "remove", "--retry", n], env=overlay.DM_ENV)
                if cp.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                problems.append(f"dmsetup remove {n}: {(cp.stderr or '').strip()}")

    parts = [n for n in b.dm if n.startswith(f"{volume.id}p")]
    if b.md:  # partition views, then the array, then the member views under it
        dm_remove(parts)
        cp = _run(ctx, ["mdadm", "--stop", b.md], env=MD_ENV)
        if cp.returncode != 0:
            problems.append(f"mdadm --stop {b.md}: {(cp.stderr or '').strip()}")
        dm_remove([n for n in b.dm if n not in parts])
    else:
        dm_remove(b.dm)
    _guard(ctx, b.exempt, False)
    if b.loop:
        _run(ctx, ["losetup", "-d", b.loop])
    for f in b.files:
        try:
            os.unlink(f)
        except OSError:
            pass
    try:
        overlay.remove(ctx, b.overlays)
    except BeastNetError as e:
        problems.append(e.text)
    if problems:
        raise _err("teardown left something behind: " + "; ".join(problems))


# -- auto -----------------------------------------------------------------------------------

def auto(ctx, devices: Sequence[str], *, budget_bytes: int = DEFAULT_BUDGET, tries: int = 3,
         cap_bytes: int | None = None) -> tuple[Volume, Candidate, float]:
    """detect, then build + validate the best ``tries`` candidates; keep the best one."""
    cands = detect(ctx, devices, budget_bytes=budget_bytes)
    best: tuple[Volume, Candidate, float] | None = None
    for cand in cands[:tries]:
        try:
            vol = build(ctx, devices, cand, cap_bytes=cap_bytes)
        except BeastNetError as e:
            cand.evidence.append(f"build failed: {e.text}")
            continue
        score = validate(ctx, vol)
        if best is None or score > best[2]:
            if best is not None:
                teardown(ctx, best[0])
            best = (vol, cand, score)
        else:
            teardown(ctx, vol)
        if score >= 0.95:
            break
    if best is None or best[2] <= 0:
        if best is not None:
            teardown(ctx, best[0])
        raise _err("no reconstruction candidate validated",
                   hint="Try the manual RAID builder, or image the members one by one.")
    return best
