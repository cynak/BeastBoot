"""Stack detection: which devices belong together and what can be done with them.

Read-only: blkid probes, `mdadm --examine`, `lvm pvs/vgs`, sysfs. Each stack
carries plain-words ``notes`` for the screens. `detect()` is called by
discover.scan(); it can also be called on its own after an assembly (nested
stacks: LVM on an md array, LUKS on a partition, ...).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..context import Context
from . import overlay
from .discover import blkid_all, part_type, read_text
from .model import Disk, Member, Stack, StackKind, StackState, Support, Volume

# -- partition type GUIDs / codes ---------------------------------------------------------
STORAGE_SPACES_GPT = "e75caf8f-f680-4cee-afa3-b001e56efc2d"
LDM_GPT = ("5808c8aa-7e8f-42e0-85d2-e1e90434cfb3", "af9b60a0-1431-4f62-bc68-3311714a69ad")
LDM_MBR = "0x42"

MD_TYPES = {"linux_raid_member": StackKind.MD, "isw_raid_member": StackKind.IMSM, "ddf_raid_member": StackKind.DDF}
FAKERAID_TYPES = {
    "adaptec_raid_member": "Adaptec HostRAID",
    "hpt37x_raid_member": "HighPoint HPT37x",
    "hpt45x_raid_member": "HighPoint HPT45x",
    "jmicron_raid_member": "JMicron",
    "lsi_mega_raid_member": "LSI MegaRAID",
    "nvidia_raid_member": "NVIDIA nForce",
    "promise_fasttrack_raid_member": "Promise FastTrack",
    "silicon_medley_raid_member": "Silicon Image Medley",
    "via_raid_member": "VIA",
}
# What a lot of tools should be told so that no udev is needed and nothing is written.
TOOL_ENV = {"MDADM_NO_UDEV": "1", "DM_DISABLE_UDEV": "1", "LVM_SUPPRESS_FD_WARNINGS": "1"}
LVM_CONFIG = ("global{metadata_read_only=1} activation{udev_sync=0 udev_rules=0 verify_udev_operations=0}")
PCI_RAID_CLASS = 0x0104
AMD_VENDOR, INTEL_VENDOR = 0x1022, 0x8086
UNRECOGNISED_MIN = 1 << 30  # ignore tiny devices when looking for AMD members


@dataclass
class Dev:
    path: str
    disk_id: str
    info: dict
    is_disk: bool = False


def short_id(prefix: str, parts: Sequence[str]) -> str:
    return f"{prefix}:" + hashlib.sha1("\0".join(sorted(parts)).encode()).hexdigest()[:8]


def have_tool(ctx: Context, tool: str, probe_arg: str = "--version") -> bool:
    """True when the program exists in the helper (exit 127/126 = missing)."""
    return ctx.system.runner.run([tool, probe_arg], timeout=15).returncode not in (126, 127)


def pci_devices(ctx: Context) -> list[tuple[int, int, int]]:
    """(vendor, device, class) for each PCI function in sysfs."""
    base = os.path.join(ctx.paths.sys, "bus", "pci", "devices")
    out = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for n in names:
        try:
            vendor = int(read_text(os.path.join(base, n, "vendor")), 16)
            dev = int(read_text(os.path.join(base, n, "device")) or "0", 16)
            cls = int(read_text(os.path.join(base, n, "class")), 16)
        except ValueError:
            continue
        out.append((vendor, dev, cls))
    return out


def _raid_controller(ctx: Context, vendor: int) -> bool:
    return any(v == vendor and (c >> 8) == PCI_RAID_CLASS for v, _d, c in pci_devices(ctx))


def intel_raid_present(ctx: Context) -> bool:
    """An Intel RAID-mode controller (RST/VROC/VMD) is in this machine. When it is
    not, IMSM arrays only assemble with IMSM_NO_PLATFORM=1."""
    return _raid_controller(ctx, INTEL_VENDOR)


def amd_raid_controller(ctx: Context) -> bool:
    return _raid_controller(ctx, AMD_VENDOR)


def _zero_start(path: str, n: int = 1 << 20) -> bool | None:
    try:
        with open(path, "rb") as f:
            data = f.read(n)
    except OSError:
        return None
    return not any(data) if data else None


# -- md / IMSM / DDF ----------------------------------------------------------------------

def _tolerance(level: str, n: int) -> int:
    """How many missing members an array of ``level`` survives (conservative)."""
    return {"raid1": n - 1, "raid4": 1, "raid5": 1, "raid6": 2, "raid10": 1}.get(level, 0)


def redundancy_state(level: str, expected: int, present: int) -> StackState:
    if expected <= 0:
        return StackState.UNKNOWN
    if present >= expected:
        return StackState.CLEAN
    if not level:
        return StackState.UNKNOWN
    return StackState.DEGRADED if expected - present <= _tolerance(level, expected) else StackState.INCOMPLETE


def _export(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def mdadm_env(ctx: Context) -> dict[str, str]:
    env = {"MDADM_NO_UDEV": "1"}
    if not intel_raid_present(ctx):
        env["IMSM_NO_PLATFORM"] = "1"
    return env


def detect_md(ctx: Context, devs: list[Dev]) -> list[Stack]:
    cands = [d for d in devs if d.info.get("TYPE") in MD_TYPES]
    if not cands:
        return []
    groups: dict[tuple[StackKind, str], list[tuple[Dev, dict[str, str]]]] = {}
    mdadm_missing = False
    for d in cands:
        kind = MD_TYPES[d.info["TYPE"]]
        meta: dict[str, str] = {}
        cp = ctx.system.runner.run(["mdadm", "--examine", "--export", d.path], env=mdadm_env(ctx), timeout=30)
        if cp.returncode == 127:
            mdadm_missing = True
        else:
            meta = _export(cp.stdout or "")
        uuid = meta.get("MD_UUID") or d.info.get("UUID") or os.path.basename(d.path)
        groups.setdefault((kind, uuid), []).append((d, meta))
    stacks = []
    for (kind, uuid), members in groups.items():
        meta0 = members[0][1]
        level = meta0.get("MD_LEVEL", "")
        expected = int(meta0["MD_DEVICES"]) if meta0.get("MD_DEVICES", "").isdigit() else 0
        notes = []
        if kind != StackKind.MD:
            level = _volume_level(ctx, members[0][0].path) if level == "container" or not level else level
        mem = []
        active = 0
        for d, meta in members:
            role = ""
            for k, v in meta.items():
                if re.fullmatch(r"MD_DEVICE_.+_ROLE", k):
                    role = v
                    break
            idx = int(role) if role.isdigit() else None
            state = "spare" if role == "spare" else "active"
            active += state == "active"
            mem.append(Member(device=d.path, disk_id=d.disk_id, index=idx, state=state))
        if mdadm_missing:
            notes.append("mdadm is not in this helper, so the array details are unknown.")
        label = {StackKind.MD: "Linux software RAID (md)", StackKind.IMSM: "Intel RST / VROC RAID (IMSM)",
                 StackKind.DDF: "SNIA DDF RAID"}[kind]
        notes.append(f"{label}: {len(mem)} of {expected or '?'} members found.")
        if kind == StackKind.IMSM and not intel_raid_present(ctx):
            notes.append("No Intel RAID controller in this machine: the array is opened with IMSM_NO_PLATFORM=1, "
                         "read-only.")
        state = redundancy_state(level, expected, active)
        if state == StackState.DEGRADED:
            notes.append("Some members are missing but the array can still be read (degraded).")
        elif state == StackState.INCOMPLETE:
            notes.append("Too many members are missing to read the array; image what is there or try reconstruction.")
        stacks.append(Stack(id=f"{kind.value}:{uuid}", kind=kind, members=mem, support=Support.ASSEMBLE,
                            level=level, state=state, name=(meta0.get("MD_NAME", "").split(":")[-1]),
                            notes=notes))
    return stacks


def _volume_level(ctx: Context, dev: str) -> str:
    """RAID level of the first volume inside an IMSM/DDF container (text `--examine`)."""
    cp = ctx.system.runner.run(["mdadm", "--examine", dev], env=mdadm_env(ctx), timeout=30)
    # IMSM: "RAID Level : 5"; DDF: "Raid Level[0] : RAID1"
    m = re.search(r"RAID Level(?:\[\d+\])?\s*:\s*(\S+)", cp.stdout or "", re.IGNORECASE)
    if not m:
        return ""
    lv = m.group(1).lower()
    return f"raid{lv}" if lv.isdigit() else lv


# -- LVM ----------------------------------------------------------------------------------

def lvm_argv(*args: str) -> list[str]:
    return ["lvm", *args, "--reportformat", "json", "--config", LVM_CONFIG]


def _rows(text: str, key: str) -> list[dict]:
    try:
        rep = json.loads(text or "{}").get("report", [])
        return [r for blk in rep for r in blk.get(key, [])]
    except (ValueError, AttributeError):
        return []


def detect_lvm(ctx: Context, devs: list[Dev]) -> list[Stack]:
    pvs = [d for d in devs if d.info.get("TYPE") == "LVM2_member"]
    if not pvs:
        return []
    cp = ctx.system.runner.run(
        lvm_argv("pvs", "-o", "pv_name,pv_uuid,vg_name,vg_uuid,pv_missing"), env=TOOL_ENV, timeout=60)
    rows = _rows(cp.stdout, "pv") if cp.returncode == 0 else []
    if not rows:  # no lvm tool (or it found nothing): one stack per PV, detect only
        return [Stack(id=f"lvm:{d.info.get('UUID') or os.path.basename(d.path)}", kind=StackKind.LVM,
                      members=[Member(d.path, d.disk_id)], support=Support.DETECT, name="",
                      notes=["LVM physical volume. The lvm tool is not available here, so only the member is shown."])
                for d in pvs]
    cp = ctx.system.runner.run(lvm_argv("vgs", "-o", "vg_name,vg_uuid,pv_count,vg_missing_pv_count"),
                               env=TOOL_ENV, timeout=60)
    vgs = {r.get("vg_uuid"): r for r in _rows(cp.stdout, "vg")}
    by_path = {d.path: d for d in pvs}
    groups: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("vg_name") and r.get("vg_uuid"):
            groups.setdefault(r["vg_uuid"], []).append(r)
    stacks = []
    for vg_uuid, prs in groups.items():
        mem = [Member(r["pv_name"], by_path[r["pv_name"]].disk_id, state="missing" if r.get("pv_missing") else "active")
               for r in prs if r.get("pv_name") in by_path]
        vg = vgs.get(vg_uuid, {})
        total = int(vg["pv_count"]) if str(vg.get("pv_count", "")).isdigit() else len(mem)
        missing = int(vg["vg_missing_pv_count"]) if str(vg.get("vg_missing_pv_count", "")).isdigit() else 0
        missing = max(missing, total - len(mem))
        state = StackState.CLEAN if missing == 0 else StackState.INCOMPLETE
        notes = [f"LVM volume group '{prs[0]['vg_name']}' with {total} physical volume(s)."]
        if missing:
            notes.append(f"{missing} physical volume(s) are missing: the logical volumes cannot be opened as they are.")
        stacks.append(Stack(id=f"lvm:{vg_uuid}", kind=StackKind.LVM, members=mem, support=Support.ASSEMBLE,
                            state=state, name=prs[0]["vg_name"], notes=notes))
    return stacks


# -- one-device stacks and filesystem groups ----------------------------------------------

def detect_crypto(devs: list[Dev]) -> list[Stack]:
    out = []
    for d in devs:
        t = d.info.get("TYPE")
        if t == "crypto_LUKS":
            ver = d.info.get("VERSION", "")
            out.append(Stack(
                id=f"luks:{d.info.get('UUID') or os.path.basename(d.path)}", kind=StackKind.LUKS,
                members=[Member(d.path, d.disk_id, state="active")], support=Support.ASSEMBLE, state=StackState.CLEAN,
                level=f"luks{ver}" if ver else "",
                notes=["Encrypted with LUKS. It can be opened read-only if you know the passphrase; "
                       "without it, image the encrypted device as it is."]))
        elif t and t.lower() == "bitlocker":
            out.append(Stack(
                id=f"bitlocker:{d.info.get('UUID') or os.path.basename(d.path)}", kind=StackKind.BITLOCKER,
                members=[Member(d.path, d.disk_id, state="active")], support=Support.ASSEMBLE, state=StackState.CLEAN,
                notes=["Encrypted with BitLocker. It can be opened read-only with the password or the 48-digit "
                       "recovery key; without it, image the encrypted device as it is."]))
    return out


def detect_btrfs(devs: list[Dev]) -> list[Stack]:
    groups: dict[str, list[Dev]] = {}
    for d in devs:
        if d.info.get("TYPE") == "btrfs" and d.info.get("UUID"):
            groups.setdefault(d.info["UUID"], []).append(d)
    out = []
    for uuid, ds in groups.items():
        if len(ds) < 2:
            continue
        out.append(Stack(
            id=f"btrfs:{uuid}", kind=StackKind.BTRFS, members=[Member(d.path, d.disk_id, state="active") for d in ds],
            support=Support.ASSEMBLE, state=StackState.UNKNOWN, name=ds[0].info.get("LABEL", ""),
            notes=[f"Btrfs spread over {len(ds)} devices. Mount any one of them read-only (add 'degraded' if a "
                   "device is missing); a single member is not a copy of the whole."]))
    return out


def detect_zfs(ctx: Context, devs: list[Dev]) -> list[Stack]:
    groups: dict[str, list[Dev]] = {}
    for d in devs:
        if d.info.get("TYPE") == "zfs_member":
            groups.setdefault(d.info.get("UUID") or d.info.get("LABEL") or os.path.basename(d.path), []).append(d)
    if not groups:
        return []
    ready = have_tool(ctx, "zpool", "version")
    out = []
    for key, ds in groups.items():
        notes = [f"ZFS pool '{ds[0].info.get('LABEL', '?')}' ({len(ds)} device(s) found)."]
        if not ready:
            notes.append("Reading ZFS needs the optional ZFS pack (install it from the desktop app); "
                         "until then, image the member disks.")
        out.append(Stack(id=f"zfs:{key}", kind=StackKind.ZFS, members=[Member(d.path, d.disk_id) for d in ds],
                         support=Support.ASSEMBLE if ready else Support.NEEDS_PACK, state=StackState.UNKNOWN,
                         name=ds[0].info.get("LABEL", ""), notes=notes))
    return out


def detect_fakeraid(devs: list[Dev]) -> list[Stack]:
    groups: dict[str, list[Dev]] = {}
    for d in devs:
        t = d.info.get("TYPE", "")
        if t in FAKERAID_TYPES:
            groups.setdefault(t, []).append(d)
    out = []
    for t, ds in groups.items():
        multi = len(ds) > 1
        out.append(Stack(
            id=f"fakeraid:{t.removesuffix('_raid_member')}", kind=StackKind.FAKERAID_OTHER,
            members=[Member(d.path, d.disk_id) for d in ds],
            support=Support.RECONSTRUCT if multi else Support.DETECT, state=StackState.UNKNOWN,
            notes=[f"Old firmware RAID ({FAKERAID_TYPES[t]}), {len(ds)} member(s) seen. Linux no longer opens these; "
                   + ("reconstruction can try to rebuild RAID 0 or RAID 1 from the members."
                      if multi else "image the member disk (it may be one half of a mirror).")]))
    return out


def detect_partition_stacks(devs: list[Dev], disks: list[Disk]) -> list[Stack]:
    """Storage Spaces and Windows dynamic disks (LDM), from partition types."""
    ss = [(d, p) for d in disks for p in d.partitions if p.type == STORAGE_SPACES_GPT]
    ldm: list[Disk] = [d for d in disks if any(p.type in LDM_GPT or p.type == LDM_MBR for p in d.partitions)]
    out = []
    if ss:
        mem = [Member(p.path, d.id) for d, p in ss]
        out.append(Stack(
            id=short_id("storage-spaces", [m.device for m in mem]), kind=StackKind.STORAGE_SPACES, members=mem,
            support=Support.RECONSTRUCT, state=StackState.UNKNOWN,
            notes=["Windows Storage Spaces. Linux has no reader for it. Image each member, or try "
                   "reconstruction for simple (striped) and mirror spaces."]))
    if ldm:
        mem = [Member(d.path, d.id) for d in ldm]
        out.append(Stack(
            id=short_id("ldm", [m.device for m in mem]), kind=StackKind.LDM, members=mem,
            support=Support.DETECT, state=StackState.UNKNOWN,
            notes=["Windows dynamic disks (spanned, striped, mirrored or RAID 5 volumes). Disk tools do not "
                   "open them: image each disk (the images keep the whole dynamic disk group)."]))
    return out


# -- AMD RAIDXpert2 (heuristic) -----------------------------------------------------------

def detect_amd(ctx: Context, disks: list[Disk], blk: dict[str, dict[str, str]], taken: set[str]) -> list[Stack]:
    """AMD keeps its metadata in a format no Linux tool reads, so this is a guess:

    * the machine has an AMD controller in RAID mode (PCI vendor 0x1022, class 0x0104), and/or
    * disks with no partition table, no file system and no signature, not removable/USB.

    With the controller present every such disk is offered as a possible member.
    Without it, only when two or more such disks have the same size and are not
    all zeros at the start (a brand-new blank disk is not a RAID member).
    Limits: member 0 of a striped set can hold a (partial) GPT and look like an
    ordinary disk; a blank disk next to an AMD controller is offered too."""
    suspects = []
    for d in disks:
        if d.is_boot_stick or d.id in taken or d.removable or d.partitions or d.size < UNRECOGNISED_MIN:
            continue
        if d.transport.value in ("usb", "mmc"):
            continue
        info = blk.get(d.path, {})
        if info.get("TYPE") or info.get("PTTYPE"):
            continue
        suspects.append(d)
    controller = amd_raid_controller(ctx)
    if controller:
        members = suspects
    else:
        members = [d for d in suspects if _zero_start(d.path) is False]
        sizes: dict[int, list[Disk]] = {}
        for d in members:
            sizes.setdefault(d.size, []).append(d)
        members = [d for ds in sizes.values() if len(ds) >= 2 for d in ds]
    if not members:
        return []
    notes = ["may be an AMD RAID member; Linux cannot read AMD's metadata; use reconstruction or image each disk"]
    if controller:
        notes.append("This machine has an AMD RAID-mode controller.")
    else:
        notes.append("No AMD RAID controller was seen; these disks only look like unrecognised members "
                     "(same size, data but no partition table or file system).")
    return [Stack(id=short_id("amd-raid", [m.id for m in members]), kind=StackKind.AMD_RAID,
                  members=[Member(m.path, m.id) for m in members], support=Support.RECONSTRUCT,
                  state=StackState.UNKNOWN, notes=notes)]


# -- entry point --------------------------------------------------------------------------

def detect(ctx: Context, disks: list[Disk], volumes: Sequence[Volume] = (),
           blk: dict[str, dict[str, str]] | None = None) -> list[Stack]:
    """Every stack visible on ``disks`` (and on assembled ``volumes``, for nested stacks)."""
    # our RAM overlays carry their member's metadata: counted, they would double every stack
    volumes = [v for v in volumes if not overlay.is_overlay_kname(ctx, v.id)]
    if blk is None:
        paths = [d.path for d in disks] + [p.path for d in disks for p in d.partitions] + [v.path for v in volumes]
        blk = blkid_all(ctx, paths)
    devs: list[Dev] = []
    for d in disks:
        devs.append(Dev(d.path, d.id, blk.get(d.path, {}), True))
        for p in d.partitions:
            info = dict(blk.get(p.path, {}))
            if p.type and not info.get("PART_ENTRY_TYPE"):
                info["PART_ENTRY_TYPE"] = p.type
            devs.append(Dev(p.path, d.id, info))
    for v in volumes:
        devs.append(Dev(v.path, v.disk_ids[0] if v.disk_ids else v.id, blk.get(v.path, {})))
    for d in disks:  # partition types, from blkid when discover has not filled them in yet
        for p in d.partitions:
            if not p.type:
                p.type = part_type(blk.get(p.path, {}))

    stacks: list[Stack] = []
    stacks += detect_md(ctx, devs)
    stacks += detect_lvm(ctx, devs)
    stacks += detect_crypto(devs)
    stacks += detect_btrfs(devs)
    stacks += detect_zfs(ctx, devs)
    stacks += detect_fakeraid(devs)
    part_stacks = detect_partition_stacks(devs, disks)
    stacks += part_stacks
    taken = {m.disk_id for s in stacks if s.kind in (StackKind.MD, StackKind.IMSM, StackKind.DDF, StackKind.FAKERAID_OTHER)
             for m in s.members}
    stacks += detect_amd(ctx, disks, blk, taken)
    return stacks
