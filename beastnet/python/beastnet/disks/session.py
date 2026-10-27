"""One Disk tools session: what script mode and the screens share.

Entering protects every block device (guard.protect_all) and scans; every
later step works on that inventory. Leaving stops what the session started
(reconstructed arrays first, then assembled stacks); the guard stays on.

Script-mode steps (docs/DISK_TOOLS.md section 6) are checked by
``parse_steps`` before anything runs, so a typo never leaves a half-done plan.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..cmdline import netboot
from ..context import Context
from ..errors import COPY, DISK_REFUSED, SCRIPT, BeastNetError
from ..paths import normalize_data_path
from .model import Candidate, CopyKind, CopyProgress, CopyResult, Disk, Health, Inventory, Stack, Volume

OPS = ("scan", "health", "assemble", "reconstruct", "use_disk", "image", "clone", "restore")
LEVELS = ("raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "linear")
MAPS_DIR = "/disk-tools"  # ddrescue mapfiles on the stick's data partition
DEST_FS = {"exfat": "exfat", "ntfs": "ntfs3", "ext4": "ext4", "xfs": "xfs"}  # blkid TYPE -> mount -t
DEST_OPTS = "rw,noatime,nodev,nosuid,noexec"
# read-only, and no journal replay (a replay writes even on a read-only mount)
SOURCE_OPTS = {"exfat": "ro", "ntfs": "ro", "ext4": "ro,noload", "xfs": "ro,norecovery"}

_STEP_KEYS = {
    "scan": ({"op"}, set()),
    "health": ({"op", "disk"}, set()),
    "assemble": ({"op", "stack"}, {"passphrase"}),
    "reconstruct": ({"op", "members"}, {"mode", "name", "level", "chunk", "order", "offset",
                                         "layout"}),
    "use_disk": ({"op", "disk", "confirm"}, {"partition"}),
    "image": ({"op", "source", "dest"}, {"verify", "member_of_set", "on"}),
    "clone": ({"op", "source", "target", "confirm"}, {"verify", "member_of_set"}),
    "restore": ({"op", "image", "target", "confirm"}, {"verify", "on"}),
}


def _bad(text: str) -> BeastNetError:
    return BeastNetError(SCRIPT, text)


def parse_steps(steps: object) -> list[dict]:
    """Check a plan's ``steps`` list; returns the steps unchanged."""
    if not isinstance(steps, list) or not steps:
        raise _bad("steps must be a non-empty list")
    for i, s in enumerate(steps, 1):
        if not isinstance(s, dict) or s.get("op") not in OPS:
            raise _bad(f"step {i}: op must be one of {', '.join(OPS)}")
        need, extra = _STEP_KEYS[s["op"]]
        missing = need - s.keys()
        unknown = s.keys() - need - extra
        if missing:
            raise _bad(f"step {i} ({s['op']}): missing {', '.join(sorted(missing))}")
        if unknown:
            raise _bad(f"step {i} ({s['op']}): unknown {', '.join(sorted(unknown))}")
        for k, v in s.items():
            if k in ("members", "order"):
                if not isinstance(v, list) or not all(isinstance(x, str) for x in v) or not v:
                    raise _bad(f"step {i}: {k} must be a non-empty list of strings")
            elif k in ("chunk", "offset"):
                if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                    raise _bad(f"step {i}: {k} must be a number of bytes")
            elif k in ("verify", "member_of_set"):
                if not isinstance(v, bool):
                    raise _bad(f"step {i}: {k} must be true or false")
            elif not isinstance(v, str) or not v:
                raise _bad(f"step {i}: {k} must be a non-empty string")
        if s["op"] == "reconstruct":
            mode = s.get("mode", "auto")
            if mode not in ("auto", "manual"):
                raise _bad(f"step {i}: mode must be auto or manual")
            if mode == "manual":
                if s.get("level") not in LEVELS or "chunk" not in s:
                    raise _bad(f"step {i}: manual reconstruction needs level ({', '.join(LEVELS)}) "
                               "and chunk")
            elif {"level", "chunk", "order", "offset", "layout"} & s.keys():
                raise _bad(f"step {i}: level/chunk/order/offset/layout are for mode manual")
        for k in ("dest", "image"):
            if k in s:
                try:
                    normalize_data_path(s[k])
                except ValueError as e:
                    raise _bad(f"step {i}: {e}") from None
    return steps


class _Modules:
    """The part modules, imported when first used (tests pass fakes instead)."""

    def __getattr__(self, name: str) -> Any:
        mod = importlib.import_module(f"{__package__}.{name}")
        setattr(self, name, mod)
        return mod


@dataclass
class Dest:
    """A disk the user confirmed for image files: one filesystem mounted read-write."""
    disk_id: str
    device: str
    fs_type: str
    mountpoint: str
    free: int
    handle: Any = None
    names: list[str] = field(default_factory=list)
    writable: bool = True


@dataclass
class Built:
    """A reconstructed array the session keeps (on overlays, read-only)."""
    volume: Volume
    candidate: Candidate
    score: float
    devices: list[str] = field(default_factory=list)


class DiskSession:
    def __init__(self, ctx: Context, *, modules: Any = None) -> None:
        self.ctx = ctx
        self.m = modules or _Modules()
        self.inv = Inventory([], [], [])
        self.started: dict[str, list[Volume]] = {}  # Stack.id -> volumes assemble.start gave
        self.built: dict[str, Built] = {}           # name -> reconstructed array
        self.health: dict[str, Health] = {}         # Disk.id -> last reading
        self.dests: dict[str, Dest] = {}            # Disk.id -> mounted image destination
        self.entered = False

    # -- life cycle -------------------------------------------------------------------
    def enter(self) -> Inventory:
        self.m.guard.protect_all(self.ctx)
        self.entered = True
        return self.scan()

    def leave(self) -> None:
        """Stop what this session started; errors are reported, not raised."""
        for disk_id in list(self.dests):
            self._quiet(self.release_disk, disk_id)
        for name in list(self.built):
            self._quiet(self.m.reconstruct.teardown, self.ctx, self.built.pop(name).volume)
        for sid in reversed(list(self.started)):
            stack = self._stack(sid, required=False)
            if stack is not None:
                self._quiet(self.m.assemble.stop, self.ctx, stack)
            self.started.pop(sid, None)

    def _quiet(self, fn: Callable[..., Any], *args: Any) -> None:
        try:
            fn(*args)
        except BeastNetError as e:
            self.ctx.reporter.error(e.code, e.text)

    def scan(self) -> Inventory:
        inv = self.m.discover.scan(self.ctx)
        self.m.guard.reapply(self.ctx)
        seen = {v.path for v in inv.volumes}
        for b in self.built.values():  # overlay arrays: discovery need not know them
            if b.volume.path not in seen:
                inv.volumes.append(b.volume)
        self.inv = inv
        return inv

    # -- lookups ----------------------------------------------------------------------
    def disk(self, ref: str) -> Disk:
        d = self.inv.disk(ref)
        if d is None:
            raise BeastNetError(SCRIPT, f"no disk with serial or name {ref!r}")
        return d

    def _stack(self, ref: str, *, required: bool = True) -> Stack | None:
        for s in self.inv.stacks:
            if s.id == ref:
                return s
        if required:
            raise BeastNetError(SCRIPT, f"no stack {ref!r} (run scan first?)")
        return None

    def volume(self, ref: str) -> Volume:
        """A copy source: a reconstruction name, a started stack (one volume),
        a volume id or path, or a disk serial/name (the whole disk)."""
        if ref in self.built:
            return self.built[ref].volume
        if ref in self.started:
            vols = self.started[ref]
            if len(vols) != 1:
                ids = ", ".join(v.id for v in vols) or "none"
                raise BeastNetError(SCRIPT, f"stack {ref} has several volumes ({ids}): name one")
            return vols[0]
        for v in self.inv.volumes:
            if ref in (v.id, v.path):
                return v
        d = self.inv.disk(ref)
        if d is not None:
            for v in self.inv.volumes:
                if v.id == d.id:
                    return v
        raise BeastNetError(SCRIPT, f"no disk or volume {ref!r}")

    def device(self, ref: str) -> str:
        """A reconstruction member: a disk serial/name, a partition name or a /dev path."""
        d = self.inv.disk(ref)
        if d is not None:
            return d.path
        for disk in self.inv.disks:
            if ref == disk.path:
                return disk.path
            for p in disk.partitions:
                if ref in (p.id, p.path):
                    return p.path
        raise BeastNetError(SCRIPT, f"no disk or partition {ref!r}")

    # -- image destinations on other disks ----------------------------------------------
    def dest_choices(self, disk: Disk) -> list[tuple[str, str, int, str]]:
        """(device, fs type, size, kernel id) of the filesystems on ``disk`` that can
        hold image files, largest first."""
        out = [(p.path, p.fs_type, p.size, p.id) for p in disk.partitions if p.fs_type in DEST_FS]
        if disk.fs_type in DEST_FS:
            out.append((disk.path, disk.fs_type, disk.size, disk.id))
        return sorted(out, key=lambda c: -c[2])

    def in_use(self, disk_id: str) -> str:
        """Why this disk must stay read-only ("" when it is free to use)."""
        st = self.member_stack(disk_id)
        if st is None:
            st = next((x for x in self.inv.stacks if any(m.disk_id == disk_id for m in x.members)), None)
        if st is not None:
            return f"it belongs to {st.kind.value} set {st.name or st.id}"
        for vols in self.started.values():
            if any(disk_id in v.disk_ids for v in vols):
                return "a started set reads from it"
        if any(disk_id in b.volume.disk_ids for b in self.built.values()):
            return "a rebuilt RAID reads from it"
        return ""

    def use_disk(self, ref: str, confirm: str, partition: str | None = None) -> Dest:
        """Mount one filesystem of a confirmed disk read-write for image files."""
        return self.open_disk(ref, write=True, confirm=confirm, partition=partition)

    def open_disk(self, ref: str, *, write: bool, confirm: str | None = None,
                  partition: str | None = None) -> Dest:
        """Mount one exFAT/NTFS/ext4/XFS filesystem of a disk: read-write for new image
        files (typed confirmation, guard lifted for this disk only), or read-only with
        no journal replay to read an image from it (no confirmation needed)."""
        d = self.disk(ref)
        have = self.dests.get(d.id)
        if have is not None and (have.writable or not write):
            return have
        if d.is_boot_stick:
            raise BeastNetError(DISK_REFUSED, "the BeastBoot drive's data partition is already the default place")
        if not d.serial:
            raise BeastNetError(DISK_REFUSED, f"{d.id} reports no serial number, so it cannot be told apart safely")
        if any(o.serial == d.serial for o in self.inv.disks if o.id != d.id):
            raise BeastNetError(DISK_REFUSED, f"another disk reports the same serial as {d.id}; "
                                "they cannot be told apart safely")
        why = self.in_use(d.id)
        if why:
            raise BeastNetError(DISK_REFUSED, f"{d.id} cannot hold images: {why}")
        if write and (confirm or "").strip() != self.m.copy.confirmation_for(self.inv, d):
            raise BeastNetError(DISK_REFUSED, "the typed serial does not match the disk")
        choices = self.dest_choices(d)
        if partition:
            choices = [c for c in choices if partition in (c[3], c[0], c[3].removeprefix(d.id).lstrip("p"))]
        if not choices:
            raise BeastNetError(DISK_REFUSED, f"{d.id} has no exFAT, NTFS, ext4 or XFS filesystem to hold images")
        if have is not None:  # open read-only before: remount read-write
            self.release_disk(d.id)
        device, fs_type, _, _ = choices[0]
        names = [d.id, *(p.id for p in d.partitions)]
        mp = os.path.join(self.ctx.paths.run, "dest", d.id)
        handle = None
        mounted = False
        try:
            if write:
                handle = self.m.guard.make_writable(self.ctx, d, confirmed=True)
                self.m.guard.exempt(*names)
            os.makedirs(mp, exist_ok=True)
            opts = DEST_OPTS if write else SOURCE_OPTS[fs_type] + ",nodev,nosuid,noexec"
            cp = self.ctx.system.runner.run(["mount", "-t", DEST_FS[fs_type], "-o", opts, device, mp],
                                            timeout=120)
            if cp.returncode != 0:
                raise BeastNetError(DISK_REFUSED, f"{device} could not be mounted: "
                                    f"{(cp.stderr or cp.stdout or '').strip()[:200]}",
                                    "A Windows disk must be shut down fully (no fast startup).")
            mounted = True
            st = os.statvfs(mp)
        except BaseException:
            if mounted:
                self.ctx.system.runner.run(["umount", mp], timeout=600)
            if write:
                self.m.guard.unexempt(*names)
                if handle is not None:
                    handle.close()
            raise
        dest = Dest(d.id, device, fs_type, mp, st.f_bavail * st.f_frsize, handle,
                    names if write else [], writable=write)
        self.dests[d.id] = dest
        self.ctx.reporter.emit("disk dest", f"id={d.id}", f"dev={device}", f"fs={fs_type}",
                               f"rw={int(write)}", f"free={dest.free}")
        return dest

    def release_disk(self, disk_id: str) -> None:
        dest = self.dests.pop(disk_id)
        run = self.ctx.system.runner.run
        run(["sync"], timeout=600)
        cp = run(["umount", dest.mountpoint], timeout=600)
        self.m.guard.unexempt(*dest.names)
        if dest.handle is not None:
            dest.handle.close()
        self.m.guard.reapply(self.ctx)
        if cp.returncode != 0:
            raise BeastNetError(DISK_REFUSED, f"{dest.device} could not be unmounted; power off before unplugging it")

    def dest_path(self, path: str, on: str | None, *, write: bool = True) -> str:
        """A data-partition path, or a path on another disk: opened by use_disk for
        writing, or opened read-only here to read an image from it."""
        if not on:
            if netboot(self.ctx):
                raise BeastNetError(DISK_REFUSED, "started over the network: there is no BeastBoot drive "
                                    "for image files", "Open another disk for them (use_disk) and name it "
                                    "with \"on\".")
            return self.ctx.paths.data_local(path)
        d = self.disk(on)
        if d.id not in self.dests:
            if write:
                raise BeastNetError(SCRIPT, f"use_disk {on} first: it is not open for image files")
            self.open_disk(d.id, write=False)
        return os.path.join(self.dests[d.id].mountpoint, normalize_data_path(path).lstrip("/"))

    # -- steps ------------------------------------------------------------------------
    def read_health(self, ref: str) -> Health:
        d = self.disk(ref)
        h = self.m.health.read(self.ctx, d)
        self.health[d.id] = h
        return h

    def assemble(self, ref: str, passphrase: str | None = None) -> list[Volume]:
        stack = self._stack(ref)
        assert stack is not None
        if stack.id in self.started:
            return self.started[stack.id]
        vols = self.m.assemble.start(self.ctx, stack, passphrase=passphrase)
        self.started[stack.id] = list(vols)
        self.scan()
        return self.started[stack.id]

    def candidates(self, members: list[str]) -> list[Candidate]:
        devices = [self.device(r) for r in members]
        return list(self.m.reconstruct.detect(self.ctx, devices))

    def _release(self, name: str, devices: list[str]) -> None:
        """Tear down the array called ``name`` and any other one built on these
        disks: their overlays are per disk, so two at once would collide."""
        for other in list(self.built):
            if other == name or set(self.built[other].devices) & set(devices):
                self._quiet(self.m.reconstruct.teardown, self.ctx, self.built.pop(other).volume)

    def build(self, name: str, devices: list[str], cand: Candidate, *, keep_bad: bool) -> Built | None:
        """Assemble one candidate on overlays and validate it; keeps it when it
        scores above zero (or always with ``keep_bad``, the manual builder)."""
        self._release(name, devices)
        vol = self.m.reconstruct.build(self.ctx, devices, cand)
        try:
            score = float(self.m.reconstruct.validate(self.ctx, vol))
        except BeastNetError:
            self._quiet(self.m.reconstruct.teardown, self.ctx, vol)
            raise
        if score <= 0 and not keep_bad:
            self._quiet(self.m.reconstruct.teardown, self.ctx, vol)
            return None
        cand.score = score
        b = Built(vol, cand, score, devices)
        self.built[name] = b
        self.scan()
        return b

    def reconstruct_auto(self, name: str, members: list[str]) -> Built:
        """reconstruct.auto: detect, then build and validate the best few one at a
        time, keeping the best (raises ``reconstruct`` when none reads)."""
        devices = [self.device(r) for r in members]
        self._release(name, devices)
        vol, cand, score = self.m.reconstruct.auto(self.ctx, devices)
        cand.score = score
        b = Built(vol, cand, score, devices)
        self.built[name] = b
        self.scan()
        return b

    def reconstruct_manual(self, name: str, members: list[str], level: str, chunk: int,
                           order: list[str] | None = None, offset: int = 0, layout: str = "") -> Built:
        devices = [self.device(r) for r in members]
        if order:
            ordered = ["" if r in ("", "missing") else self.device(r) for r in order]
            if any(d and d not in devices for d in ordered):
                raise BeastNetError(SCRIPT, "order names a disk that is not one of the members")
        else:
            ordered = devices
        cand = Candidate(level=level, chunk=chunk, order=ordered, data_offset=offset, layout=layout,
                         evidence=["manual"])
        b = self.build(name, devices, cand, keep_bad=True)
        assert b is not None
        return b

    def member_stack(self, disk_id: str) -> Stack | None:
        """The multi-disk set this disk belongs to (copying it alone is not the set)."""
        for st in self.inv.stacks:
            if len(st.members) > 1 and any(m.disk_id == disk_id for m in st.members):
                return st
        return None

    def plan_copy(self, kind: CopyKind, source: str, target: str, *, confirm: str | None = None,
                  verify: bool = True, member_of_set: bool = False):
        """source: volume ref (clone/image) or a local image path (restore);
        target: disk serial (clone/restore) or a local image path (image).
        ``member_of_set``: the user asked for one disk of a set on its own."""
        if kind is not CopyKind.RESTORE:
            source = self.volume(source).id
        if kind is CopyKind.IMAGE:
            roots = [os.path.abspath(self.ctx.paths.data), *(d.mountpoint for d in self.dests.values())]
            if any(os.path.commonpath([os.path.abspath(target), r]) == r for r in roots):
                os.makedirs(os.path.dirname(target), exist_ok=True)  # e.g. /images
        maps = self.ctx.paths.data_local(MAPS_DIR)
        return self.m.copy.plan(self.ctx, self.inv, kind, source, target, confirm=confirm,
                                mapfile_dir=maps, verify=verify, member_of_set=member_of_set)

    def run_copy(self, plan, on_progress: Callable[[CopyProgress], None] | None = None,
                 should_stop: Callable[[], bool] | None = None) -> CopyResult:
        result = self.m.copy.run(self.ctx, plan, on_progress or (lambda p: None),
                                 should_stop or (lambda: False))
        self.m.guard.reapply(self.ctx)
        return result

    # -- script mode ------------------------------------------------------------------
    def run_steps(self, steps: list[dict]) -> None:
        if not self.entered:
            self.enter()
        for s in steps:
            self.run_step(s)

    def run_step(self, s: dict) -> None:
        op = s["op"]
        if op == "scan":
            self.scan()
        elif op == "health":
            self.read_health(s["disk"])
        elif op == "assemble":
            self.assemble(s["stack"], s.get("passphrase"))
        elif op == "use_disk":
            self.use_disk(s["disk"], s["confirm"], s.get("partition"))
        elif op == "reconstruct":
            name = s.get("name", "reconstructed")
            if s.get("mode", "auto") == "manual":
                self.reconstruct_manual(name, s["members"], s["level"], s["chunk"], s.get("order"),
                                        s.get("offset", 0), s.get("layout", ""))
            else:
                self.reconstruct_auto(name, s["members"])
        else:
            verify = s.get("verify", True)
            member = s.get("member_of_set", False)
            if op == "image":
                plan = self.plan_copy(CopyKind.IMAGE, s["source"], self.dest_path(s["dest"], s.get("on")),
                                      verify=verify, member_of_set=member)
            elif op == "clone":
                plan = self.plan_copy(CopyKind.CLONE, s["source"], s["target"], confirm=s["confirm"],
                                      verify=verify, member_of_set=member)
            else:
                plan = self.plan_copy(CopyKind.RESTORE, self.dest_path(s["image"], s.get("on"), write=False),
                                      s["target"],
                                      confirm=s["confirm"], verify=verify)
            result = self.run_copy(plan)
            if not result.ok:
                if result.errors and result.bytes:
                    raise BeastNetError(COPY, f"{result.errors} bytes could not be read",
                                        "Run the same plan again to retry the bad areas.")
                raise BeastNetError(COPY, "; ".join(result.notes) or "the copy did not finish")


def run_plan(ctx: Context, steps: list[dict], *, modules: Any = None) -> None:
    """Script mode: run the steps in one session, then stop what it started."""
    s = DiskSession(ctx, modules=modules)
    try:
        s.run_steps(steps)
    finally:
        s.leave()


__all__ = ["DiskSession", "OPS", "parse_steps", "run_plan"]
