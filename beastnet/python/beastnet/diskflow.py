"""Disk tools screens (docs/DISK_TOOLS.md): see every disk and RAID or volume
set, check health, start a set read-only, work out an unknown RAID layout,
and clone, image or restore. All the work is in disks.session; this module
only asks and shows."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .cmdline import netboot
from .disks.model import (Candidate, CopyKind, CopyPlan, CopyProgress, CopyResult, Disk, Health,
                          HealthStatus, Stack, StackKind, Support, Volume)
from .disks.session import LEVELS, DiskSession
from .download import Progress, human_size
from .errors import BeastNetError
from .paths import normalize_data_path
from .ui import Field, Item

if TYPE_CHECKING:
    from .flow import Interactive

TITLE = "Disk tools"
SUBTITLE = "beast-net: Disk tools (recovery and cloning)"
IMAGES = "/images"

KIND_NAME = {
    StackKind.MD: "Linux RAID",
    StackKind.IMSM: "Intel RST RAID",
    StackKind.DDF: "Firmware RAID (DDF)",
    StackKind.LVM: "LVM volume group",
    StackKind.LUKS: "Encrypted (LUKS)",
    StackKind.BITLOCKER: "BitLocker",
    StackKind.BTRFS: "Btrfs on several disks",
    StackKind.ZFS: "ZFS pool",
    StackKind.LDM: "Windows dynamic disks",
    StackKind.STORAGE_SPACES: "Windows Storage Spaces",
    StackKind.AMD_RAID: "May be an AMD RAID member",
    StackKind.FAKERAID_OTHER: "Firmware RAID",
    StackKind.UNKNOWN: "Unknown set",
}

SUPPORT_TEXT = {
    Support.ASSEMBLE: "BeastBoot can start it read-only.",
    Support.RECONSTRUCT: "Linux cannot read its RAID information. BeastBoot can work out the "
                         "layout from the data itself, without writing to the disks.",
    Support.DETECT: "BeastBoot cannot read it as a whole: image each disk on its own.",
    Support.NEEDS_PACK: "Needs the ZFS pack: add it with the BeastBoot app on your computer, "
                        "then start Disk tools again.",
}

HEALTH_KIND = {HealthStatus.OK: "", HealthStatus.WARN: "warn", HealthStatus.FAIL: "warn",
               HealthStatus.UNKNOWN: "muted"}

ABOUT = """\
Disk tools never change a disk you did not pick as the target.

- When Disk tools start, every disk and partition is set read-only in the
  kernel. RAID sets, LVM and encrypted volumes start read-only too.
- Working out an unknown RAID layout (AMD RAID, Storage Spaces, a set whose
  RAID information is lost) happens on copy-on-write overlays in memory: the
  disks themselves are only read.
- A disk becomes writable only after the plan screen and after you type the
  last 6 characters of its serial number. It is checked again (serial, size)
  right before writing.
- The BeastBoot drive, the source and the disks of the source set are never
  targets. The progress of a copy (a ddrescue mapfile) is kept on the
  BeastBoot drive, so a stopped copy can resume.
- A copy of one disk of a RAID set is a copy of that disk, not of the set.
"""

# Started over the network (beastnet.netboot=1, BeastServer): there is no BeastBoot drive.
ABOUT_NETBOOT = ABOUT.replace("""- The BeastBoot drive, the source and the disks of the source set are never
  targets. The progress of a copy (a ddrescue mapfile) is kept on the
  BeastBoot drive, so a stopped copy can resume.
""", """- Started over the network: there is no BeastBoot drive. The source and the
  disks of the source set are never targets. Image files go to another disk
  (for example a USB disk with exFAT, NTFS, ext4 or XFS). The progress of a
  copy (a ddrescue mapfile) is kept next to the image, else in memory: then a
  stopped copy resumes only until this computer restarts.
""")


def disk_label(d: Disk) -> str:
    return f"{d.model or 'Disk'}  {human_size(d.size)}"


def serial_tail(d: Disk) -> str:
    return ("..." + d.serial[-6:]) if len(d.serial) > 6 else (d.serial or "no serial")


def stack_label(st: Stack) -> str:
    bits = [KIND_NAME.get(st.kind, st.kind.value)]
    if st.name:
        bits.append(st.name)
    if st.level:
        bits.append(st.level)
    return "  ".join(bits)


def candidate_label(c: Candidate) -> str:
    chunk = f"chunk {c.chunk // 1024} KiB" if c.chunk else ""
    order = ",".join(os.path.basename(d) if d else "missing" for d in c.order)
    return "  ".join(x for x in (c.level, c.layout, chunk, f"order {order}") if x)


def plan_text(plan: CopyPlan, inv_disk: Callable[[str], Disk | None]) -> str:
    lines = [f"From: {plan.source}", f"To:   {plan.target}", f"Size: {human_size(plan.size)}"]
    if plan.erases:
        lines += ["", f"Erased: {plan.erases}"]
    notes = getattr(plan, "notes", None) or []
    if notes:
        lines += [""] + list(notes)
    lines += ["", f"Progress file: {plan.mapfile} (a stopped copy resumes from it)"]
    if plan.verify:
        lines.append("Checked after the copy (SHA-256).")
    if plan.commands:
        lines += ["", "Commands:"] + ["  " + " ".join(c) for c in plan.commands]
    return "\n".join(lines)


def to_progress(cp: CopyProgress) -> Progress:
    eta = (cp.total - cp.done) / cp.rate if cp.rate > 0 and cp.total else None
    note = cp.phase.capitalize() if cp.phase else ""
    if cp.errors:
        note = f"{note}  {cp.errors} unreadable area(s) so far".strip()
    return Progress("verify" if cp.phase == "verify" else "copy", done=cp.done, total=cp.total or None,
                    speed=cp.rate, eta=eta, note=note)


class DiskScreens:
    def __init__(self, flow: Interactive, session: DiskSession | None = None) -> None:
        self.flow = flow
        self.ui = flow.ui
        self.ctx = flow.ctx
        self.s = session or DiskSession(flow.ctx)

    # -- top level --------------------------------------------------------------------
    def run(self, entry: bool = False) -> None:
        old = self.ui.set_mode(SUBTITLE, ())
        try:
            try:
                self.ui.task(TITLE, "Finding disks and setting all of them read-only...", self.s.enter)
            except BeastNetError as e:
                self.flow.show_error(e, TITLE)
                return
            self.home(entry)
        finally:
            self.s.leave()
            self.ui.set_mode(*old)

    def _error(self, e: BeastNetError) -> None:
        self.flow.show_error(e, TITLE)

    def _try(self, text: str, fn: Callable[[], Any]) -> Any:
        """Run fn behind a busy screen; None (after showing it) on a BeastNetError."""
        try:
            return self.ui.task(TITLE, text, fn)
        except BeastNetError as e:
            self._error(e)
            return None

    def home(self, entry: bool) -> None:
        while True:
            inv = self.s.inv
            items: list[Item] = []
            for d in inv.disks:
                h = self.s.health.get(d.id)
                detail = f"{d.transport.value}  {serial_tail(d)}"
                if d.is_boot_stick:
                    items.append(Item(disk_label(d), ("disk", d.id), detail="BeastBoot drive",
                                      kind="muted", hint="The drive Disk tools run from."))
                    continue
                items.append(Item(disk_label(d), ("disk", d.id),
                                  detail=f"{detail}  {h.status.value}" if h else detail,
                                  kind=HEALTH_KIND.get(h.status, "") if h else "",
                                  hint=h.summary if h else ""))
            for st in inv.stacks:
                started = " (started)" if st.id in self.s.started else ""
                items.append(Item(stack_label(st) + started, ("stack", st.id),
                                  detail=f"{len(st.members)} disks  {st.state.value}",
                                  kind="warn" if st.kind is StackKind.AMD_RAID else "",
                                  hint=(st.notes[0] if st.notes else SUPPORT_TEXT[st.support])))
            for name, b in self.s.built.items():
                items.append(Item(f"Rebuilt RAID: {name}", ("built", name),
                                  detail=human_size(b.volume.size),
                                  hint=f"{candidate_label(b.candidate)} (read-only, on overlays)"))
            items += [Item("Check the health of every disk", "health"),
                      Item("Restore an image onto a disk", "restore"),
                      Item("Work out a RAID layout from chosen disks", "reconstruct",
                           hint="For RAID sets Linux cannot read (AMD RAID, lost RAID information)."),
                      Item("Scan again", "rescan"),
                      Item("What is safe here?", "about")]
            if not (entry and netboot(self.ctx)):   # network boot: nothing to download to
                items.append(Item("Download an ISO from a link", None) if entry else Item("Back", None))
            items += self.flow.common_items()
            n_sets = len(inv.stacks)
            text = (f"{len(inv.disks)} disk(s), {n_sets} RAID or volume set(s). Every disk is "
                    "read-only until you confirm one as a copy target.")
            choice = self.ui.menu(TITLE, text, items, back=not entry)
            if choice is None:
                return
            if isinstance(choice, tuple):
                what, ref = choice
                if what == "disk":
                    self.disk_menu(ref)
                elif what == "stack":
                    self.stack_menu(ref)
                else:
                    self.copy_from(self.s.built[ref].volume)
            elif choice == "health":
                self.health_all()
            elif choice == "restore":
                self.restore()
            elif choice == "reconstruct":
                members = self.pick_disks("Which disks belong to the RAID set?")
                if members:
                    self.reconstruct(members)
            elif choice == "rescan":
                self._try("Scanning again...", self.s.scan)
            elif choice == "about":
                self.ui.document("What is safe here?", ABOUT_NETBOOT if netboot(self.ctx) else ABOUT,
                                 [Item("Back", True)])
            else:
                self.flow.common(choice)

    # -- one disk ---------------------------------------------------------------------
    def disk_menu(self, disk_id: str) -> None:
        while True:
            d = self.s.inv.disk(disk_id)
            if d is None:
                return
            lines = [f"{d.model or 'Disk'}, {human_size(d.size)}, {d.transport.value}",
                     f"Serial: {d.serial or '(none: it cannot be a copy target)'}",
                     f"Sectors: {d.logical_sector} bytes logical, {d.physical_sector} physical"]
            for p in d.partitions:
                desc = " ".join(x for x in (p.fs_type, p.label) if x)
                lines.append(f"  {p.id}  {human_size(p.size)}  {desc}")
            h = self.s.health.get(d.id)
            if h:
                lines += ["", f"Health: {h.summary}"]
            if d.is_boot_stick:
                lines += ["", "This is the BeastBoot drive. It is never a copy target."]
                self.ui.message(disk_label(d), "\n".join(lines))
                return
            member = self.s.member_stack(d.id)
            if member is not None:
                lines += ["", f"One disk of {stack_label(member)}: a copy of it alone is a copy "
                          "of this disk, not of the set."]
                items = [Item("Check its health", "health"),
                         Item("Copy this one disk to another disk", "clone"),
                         Item("Save this one disk as an image file", "image"),
                         Item("Open the set", ("set", member.id)),
                         Item("Back", None)]
            else:
                items = [Item("Check its health", "health"),
                         Item("Copy it to another disk (clone)", "clone"),
                         Item("Save it as an image file", "image"),
                         Item("Restore an image onto it", "restore"),
                         Item("Back", None)]
            for p in d.partitions:
                items.insert(-1, Item(f"Copy or image partition {p.id}", ("part", p.id)))
            choice = self.ui.menu(disk_label(d), "\n".join(lines), items)
            if choice is None:
                return
            if choice == "health":
                self._read_health(d)
            elif choice == "restore":
                self.restore(target=d)
            elif isinstance(choice, tuple) and choice[0] == "set":
                self.stack_menu(choice[1])
            elif isinstance(choice, tuple):
                self.copy_from(self.s.volume(choice[1]))
            else:
                vol = self.s.volume(d.id)
                one = member is not None
                self.clone(vol, member_of_set=one) if choice == "clone" else self.image(vol, member_of_set=one)

    def _read_health(self, d: Disk) -> Health | None:
        h = self._try(f"Reading the health of {d.model or d.id} (SMART)...",
                      lambda: self.s.read_health(d.id))
        if h is not None:
            self.ui.message(f"Health: {disk_label(d)}", h.summary, kind=HEALTH_KIND.get(h.status, ""))
        return h

    def health_all(self) -> None:
        disks = [d for d in self.s.inv.disks if not d.is_boot_stick]

        def read_all() -> list[str]:
            out = []
            for d in disks:
                try:
                    h = self.s.read_health(d.id)
                    out.append(f"{disk_label(d)} ({serial_tail(d)}): {h.status.value.upper()}  {h.summary}")
                except BeastNetError as e:
                    out.append(f"{disk_label(d)} ({serial_tail(d)}): could not read ({e.text})")
            return out

        lines = self._try("Reading the health of every disk (SMART)...", read_all)
        if lines is not None:
            self.ui.document("Disk health", "\n".join(lines) or "No disks found.", [Item("Back", True)])

    # -- sets -------------------------------------------------------------------------
    def stack_menu(self, stack_id: str) -> None:
        while True:
            st = next((s for s in self.s.inv.stacks if s.id == stack_id), None)
            if st is None:
                return
            lines = [stack_label(st), f"State: {st.state.value}", SUPPORT_TEXT[st.support], ""]
            lines += [f"  {m.device}  {m.state}".rstrip() for m in st.members]
            if st.notes:
                lines += [""] + st.notes
            started = self.s.started.get(st.id)
            items: list[Item] = []
            if started:
                for v in started:
                    items.append(Item(f"Copy or image {v.id}", ("vol", v.id),
                                      detail=human_size(v.size), hint=" ".join((v.fs_type, v.label))))
            elif st.support is Support.ASSEMBLE:
                items.append(Item("Start it read-only", "start"))
            if st.support in (Support.RECONSTRUCT, Support.DETECT) and len(st.members) > 1:
                items.append(Item("Work out its RAID layout (read-only)", "reconstruct"))
            items.append(Item("Back", None))
            choice = self.ui.menu(stack_label(st), "\n".join(lines), items)
            if choice is None:
                return
            if choice == "start":
                self.start(st)
            elif choice == "reconstruct":
                self.reconstruct([m.device for m in st.members])
            elif isinstance(choice, tuple):
                self.copy_from(self.s.volume(choice[1]))

    def start(self, st: Stack) -> None:
        passphrase = None
        if st.kind in (StackKind.LUKS, StackKind.BITLOCKER):
            what = "recovery key or password" if st.kind is StackKind.BITLOCKER else "passphrase"
            v = self.ui.form("Unlock (read-only)", f"Type the {what}. It is used only to open the "
                             "volume read-only and is not saved.",
                             [Field("pw", what.capitalize(), secret=True)])
            if not v:
                return
            passphrase = v["pw"]
        vols = self._try(f"Starting {stack_label(st)} read-only...",
                         lambda: self.s.assemble(st.id, passphrase))
        if vols is not None:
            names = ", ".join(f"{v.id} ({human_size(v.size)})" for v in vols) or "nothing"
            self.ui.message("Started read-only", f"Now readable: {names}.", kind="ok")

    # -- reconstruction ---------------------------------------------------------------
    def pick_disks(self, title: str) -> list[str]:
        chosen: list[str] = []
        while True:
            items = [Item(("[x] " if d.id in chosen else "[ ] ") + disk_label(d), d.id,
                          detail=serial_tail(d)) for d in self.s.inv.disks if not d.is_boot_stick]
            items.append(Item(f"Done ({len(chosen)} chosen)", "done"))
            choice = self.ui.menu(title, "Pick every disk of the set, then Done.", items)
            if choice is None:
                return []
            if choice == "done":
                if len(chosen) >= 2:
                    return [self.s.inv.disk(i).path for i in chosen if self.s.inv.disk(i)]
                self.ui.message(title, "Pick at least two disks.")
            elif choice in chosen:
                chosen.remove(choice)
            else:
                chosen.append(choice)

    def reconstruct(self, members: list[str]) -> None:
        cands = self._try("Reading samples from each disk to work out the layout (read-only)...",
                          lambda: self.s.candidates(members))
        if cands is None:
            return
        name = f"raid{len(self.s.built) + 1}"
        while True:
            items = [Item(candidate_label(c), c, detail=f"{c.score:.2f}" if c.score else "",
                          hint="; ".join(c.evidence[:2])) for c in cands[:8]]
            if cands:
                items.insert(0, Item("Try the best layouts and keep the one that reads", "auto"))
            items += [Item("Manual RAID builder", "manual",
                           hint="Type the level, chunk size and disk order if you know them."),
                      Item("Back", None)]
            text = (f"{len(cands)} possible layout(s), best first." if cands else
                    "No layout fits the data on these disks. Check that every disk of the set is "
                    "attached, or use the manual RAID builder.")
            choice = self.ui.menu("RAID layout", text, items)
            if choice is None:
                return
            if choice == "auto":
                b = self._try("Building the best layouts on overlays and checking the filesystem...",
                              lambda: self.s.reconstruct_auto(name, members))
            elif choice == "manual":
                b = self.manual(name, members)
            else:
                b = self._try("Building this layout on overlays and checking the filesystem...",
                              lambda c=choice: self.s.build(name, members, c, keep_bad=True))
            if b is None:
                continue
            ok = b.score > 0
            text = (f"{candidate_label(b.candidate)}\nSize: {human_size(b.volume.size)}\n"
                    f"Check score: {b.score:.2f}\n\n" +
                    ("A filesystem reads on it. It stays read-only (changes go to memory only)."
                     if ok else "No filesystem reads on it: this layout is probably wrong."))
            go = self.ui.menu(f"Rebuilt RAID: {name}", text,
                              [Item("Copy or image it", True), Item("Back to the layouts", False)],
                              kind="ok" if ok else "warn")
            if go is True:
                self.copy_from(b.volume)
                return

    def manual(self, name: str, members: list[str]) -> Any:
        error = ""
        default_order = ",".join(os.path.basename(m) for m in members)
        while True:
            v = self.ui.form("Manual RAID builder", "Works on overlays: the disks are only read.",
                             [Field("level", "Level", "raid5", hint=" ".join(LEVELS)),
                              Field("chunk", "Chunk size (KiB)", "64"),
                              Field("order", "Disk order", default_order,
                                    hint="Comma-separated; write 'missing' for an absent disk."),
                              Field("offset", "Data offset (KiB)", "0"),
                              Field("layout", "Layout (raid5/6)", "left-symmetric")], error=error)
            if not v:
                return None
            try:
                level = v["level"].strip().lower()
                if level not in LEVELS:
                    raise ValueError(f"level must be one of {', '.join(LEVELS)}")
                chunk = int(v["chunk"]) * 1024
                offset = int(v["offset"]) * 1024
                if chunk <= 0 or offset < 0:
                    raise ValueError("chunk must be above 0 and the offset 0 or more")
                by_name = {os.path.basename(m): m for m in members}
                order = []
                for part in (x.strip() for x in v["order"].split(",")):
                    if part == "missing":
                        order.append("")
                    elif part in by_name:
                        order.append(by_name[part])
                    else:
                        raise ValueError(f"{part!r} is not one of {', '.join(by_name)}")
            except ValueError as e:
                error = str(e)
                continue
            layout = v["layout"].strip() if level in ("raid5", "raid6") else ""
            return self._try("Building this layout on overlays and checking the filesystem...",
                             lambda: self.s.reconstruct_manual(name, members, level, chunk, order,
                                                               offset, layout))

    # -- copies -----------------------------------------------------------------------
    def copy_from(self, vol: Volume) -> None:
        choice = self.ui.menu(f"Copy {vol.id}", f"{vol.id}: {human_size(vol.size)} {vol.fs_type}",
                              [Item("To another disk (clone)", "clone"),
                               Item("To an image file (on another disk)" if netboot(self.ctx) else
                                    "To an image file (on the BeastBoot drive or another disk)", "image"),
                               Item("Back", None)])
        if choice == "clone":
            self.clone(vol)
        elif choice == "image":
            self.image(vol)

    def pick_target(self, title: str, exclude: set[str]) -> Disk | None:
        disks = [d for d in self.s.inv.disks if not d.is_boot_stick and d.id not in exclude]
        if not disks:
            self.ui.message(title, "There is no other disk to write to.")
            return None
        items = [Item(disk_label(d), d.id, detail=serial_tail(d)) for d in disks] + [Item("Back", None)]
        ref = self.ui.menu(title, "Everything on the disk you pick is overwritten (after a plan "
                           "screen and your confirmation).", items)
        return self.s.inv.disk(ref) if ref else None

    def clone(self, vol: Volume, *, member_of_set: bool = False) -> None:
        target = self.pick_target("Copy to which disk?", set(vol.disk_ids))
        if target is not None:
            self.do_copy(CopyKind.CLONE, vol.id, target, member_of_set=member_of_set)

    def pick_place(self, title: str, exclude: set[str], *, write: bool = True) -> tuple[str | None, str] | None:
        """Where image files are: (None, "the BeastBoot drive") or (disk serial, label)
        of another disk: opened read-write after its typed confirmation (``write``), or
        read-only to read an image from it. None = back."""
        items = [] if netboot(self.ctx) else [Item("The BeastBoot drive", "stick", detail="data partition")]
        for d in self.s.inv.disks:
            if d.is_boot_stick or d.id in exclude or self.s.in_use(d.id):
                continue
            ch = self.s.dest_choices(d)
            if ch:
                opened = " (open)" if d.id in self.s.dests else ""
                hint = ("Its filesystem is opened read-write for image files after you confirm the disk."
                        if write else "Its filesystem is opened read-only.")
                items.append(Item(disk_label(d) + opened, d.id, detail=f"{ch[0][1]}  {serial_tail(d)}",
                                  hint=hint))
        text = "Image files need exFAT, NTFS, ext4 or XFS (not FAT32)."
        if not items:
            text += (" Started over the network, there is no BeastBoot drive: plug in a disk with one of "
                     "these filesystems, then choose Scan again.")
        items.append(Item("Back", None))
        choice = self.ui.menu(title, text, items)
        if choice is None:
            return None
        if choice == "stick":
            return None, "the BeastBoot drive"
        d = self.s.inv.disk(choice)
        if not write:
            try:
                self.ui.task(TITLE, "Opening it read-only...", lambda: self.s.open_disk(d.id, write=False))
            except BeastNetError as e:
                self._error(e)
                return None
            return d.serial, disk_label(d)
        if d.id not in self.s.dests or not self.s.dests[d.id].writable:
            error = ""
            while True:
                v = self.ui.form("Open a disk for image files",
                                 f"{disk_label(d)} (serial {d.serial}) is opened read-write; files on it stay, "
                                 "new image files are added. Type the last 6 characters of its serial.",
                                 [Field("serial", "Serial (last 6)")], error=error)
                if not v:
                    return None
                try:
                    self.ui.task(TITLE, "Opening it...", lambda: self.s.use_disk(d.id, v["serial"]))
                    break
                except BeastNetError as e:
                    if "typed serial" not in e.text:
                        self._error(e)
                        return None
                    error = e.text
        return d.serial, disk_label(d)

    def image(self, vol: Volume, *, member_of_set: bool = False) -> None:
        place = self.pick_place("Save the image where?", set(vol.disk_ids))
        if place is None:
            return
        on, label = place
        error = ""
        while True:
            v = self.ui.form("Image file", f"File name on {label}.",
                             [Field("path", "File", f"{IMAGES}/{vol.id}.img")], error=error)
            if not v:
                return
            try:
                rel = normalize_data_path(v["path"])
                local = self.s.dest_path(rel, on)
            except (ValueError, BeastNetError) as e:
                error = getattr(e, "text", None) or str(e)
                continue
            self.do_copy(CopyKind.IMAGE, vol.id, local, shown=f"{rel} on {label}", member_of_set=member_of_set)
            return

    def restore(self, target: Disk | None = None) -> None:
        place = self.pick_place("Restore an image from where?", {target.id} if target else set(), write=False)
        if place is None:
            return
        on, label = place
        folder = self.s.dest_path(IMAGES, on, write=False)
        try:
            files = sorted(f for f in os.listdir(folder) if f.endswith(".img"))
        except OSError:
            files = []
        items = [Item(f, f"{IMAGES}/{f}") for f in files] + [Item("Type a path", "type"),
                                                            Item("Back", None)]
        choice = self.ui.menu("Restore which image?", f"Images in {IMAGES} on {label}.", items)
        if choice is None:
            return
        if choice == "type":
            v = self.ui.form("Image file", "", [Field("path", f"File on {label}", IMAGES + "/")])
            if not v:
                return
            choice = v["path"]
        try:
            rel = normalize_data_path(choice)
        except ValueError as e:
            self.ui.message("Image file", str(e), kind="error")
            return
        exclude = {self.s.inv.disk(on).id} if on else set()
        target = target or self.pick_target("Restore onto which disk?", exclude)
        if target is not None:
            self.do_copy(CopyKind.RESTORE, self.s.dest_path(rel, on, write=False), target,
                         shown=f"{rel} on {label}")

    def do_copy(self, kind: CopyKind, source: str, target: Disk | str, *, shown: str = "",
                member_of_set: bool = False) -> None:
        tref = target.serial if isinstance(target, Disk) else target
        plan = self._try("Checking the plan...", lambda: self.s.plan_copy(
            kind, source, tref, member_of_set=member_of_set))
        if plan is None:
            return
        go = self.ui.document(f"Plan: {kind.value}", plan_text(plan, self.s.inv.disk),
                              [Item("Continue", True), Item("Back", False)],
                              kind="warn" if plan.erases else "")
        if go is not True:
            return
        if isinstance(target, Disk):
            plan = self.confirm(kind, source, target, member_of_set)
            if plan is None:
                return
        self.run_copy(plan, shown or plan.target)

    def confirm(self, kind: CopyKind, source: str, target: Disk,
                member_of_set: bool = False) -> CopyPlan | None:
        error = ""
        while True:
            v = self.ui.form("Confirm the disk to erase",
                             f"Everything on {disk_label(target)} (serial {target.serial}) is "
                             "overwritten. Type the last 6 characters of its serial number "
                             "(the whole serial if another disk's ends the same).",
                             [Field("serial", "Serial (last 6)")], error=error)
            if not v:
                return None
            try:
                return self.ui.task(TITLE, "Checking...", lambda: self.s.plan_copy(
                    kind, source, target.serial, confirm=v["serial"].strip(),
                    member_of_set=member_of_set))
            except BeastNetError as e:
                error = e.text

    def run_copy(self, plan: CopyPlan, shown: str) -> None:
        def job(on_progress: Callable[[Progress], None], cancel: Any) -> CopyResult:
            on_progress(Progress("copy", done=0, total=plan.size or None))
            return self.s.run_copy(plan, lambda cp: on_progress(to_progress(cp)), cancel.is_set)

        lines = [f"From: {plan.source}", f"To:   {shown}"]
        try:
            r = self.ui.download(f"{plan.kind.value.capitalize()}", lines, job, what="copy")
        except BeastNetError as e:
            self._error(e)
            return
        if r.resumable and not r.ok:
            text = ("Stopped. Start the same copy again to resume where it stopped (its progress "
                    + ("is kept with the image, or in memory until this computer restarts)."
                       if netboot(self.ctx) else "is saved on the BeastBoot drive)."))
            kind = "warn"
        elif r.errors:
            text = (f"Copied {human_size(r.bytes)}, but {human_size(r.errors)} could not be read. "
                    "Running the same copy again retries only those areas.")
            kind = "warn"
        elif r.ok:
            text = f"Copied {human_size(r.bytes)}."
            if r.sha256:
                text += f"\nSHA-256: {r.sha256}"
            kind = "ok"
        else:
            text, kind = "The copy did not finish.", "error"
        if r.notes:
            text += "\n\n" + "\n".join(r.notes)
        self.ui.message("Copy finished" if r.ok else "Copy not finished", text, kind=kind)
