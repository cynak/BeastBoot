"""Find every disk, partition and assembled device from sysfs and blkid (read-only).

Nothing here writes to a device: sysfs reads, `blkid -p` (low-level probe, no
cache, no udev) and a read of /proc/mounts. Stacks are found by probe.py.
"""

from __future__ import annotations

import os
import re

from ..context import Context
from .model import Disk, Inventory, Partition, Transport, Volume, VolumeKind
from .overlay import is_overlay_kname

# Kernel names that are never a source disk: RAM and loop devices, optical drives, floppies.
SKIP_PREFIXES = ("loop", "ram", "zram", "sr", "fd", "nbd")


def read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def read_int(path: str, default: int = 0) -> int:
    try:
        return int(read_text(path), 0)
    except ValueError:
        return default


def is_assembled_name(name: str) -> bool:
    return bool(re.fullmatch(r"md\d+|dm-\d+", name))


def block_names(sys_root: str) -> list[str]:
    try:
        return sorted(os.listdir(os.path.join(sys_root, "block")))
    except OSError:
        return []


def partition_names(sys_root: str, disk: str) -> list[str]:
    base = os.path.join(sys_root, "block", disk)
    try:
        names = os.listdir(base)
    except OSError:
        return []
    return sorted((n for n in names if n.startswith(disk) and os.path.exists(os.path.join(base, n, "partition"))),
                  key=lambda n: read_int(os.path.join(base, n, "partition")))


# -- one disk -----------------------------------------------------------------------------

def transport_of(sys_root: str, name: str) -> Transport:
    """From where the kernel put the device in the device tree."""
    real = os.path.relpath(os.path.realpath(os.path.join(sys_root, "block", name)), os.path.realpath(sys_root))
    parts = real.split("/")
    if name.startswith("nvme") or any(p.startswith("nvme") for p in parts):
        return Transport.NVME
    if any(p.startswith("usb") or re.fullmatch(r"\d+-\d+(\.\d+)*(:\d+\.\d+)?", p) for p in parts):
        return Transport.USB
    if any(p.startswith("virtio") for p in parts):
        return Transport.VIRTIO
    if name.startswith("mmcblk") or any(p.startswith("mmc") for p in parts):
        return Transport.MMC
    if any(re.fullmatch(r"ata\d+", p) for p in parts):
        return Transport.SATA
    if any(p.startswith(("port-", "end_device-", "rport-")) or p == "sas" for p in parts) \
            or any(re.fullmatch(r"host\d+", p) for p in parts):
        return Transport.SAS
    return Transport.OTHER


def _vpd_serial(path: str) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(260)
    except OSError:
        return ""
    if len(data) < 4 or data[1] != 0x80:
        return ""
    n = (data[2] << 8) | data[3]
    return data[4:4 + n].decode("ascii", "replace").strip("\0 ")


def serial_of(sys_root: str, name: str) -> str:
    base = os.path.join(sys_root, "block", name)
    for p in (os.path.join(base, "serial"), os.path.join(base, "device", "serial")):
        s = read_text(p)
        if s:
            return s
    s = _vpd_serial(os.path.join(base, "device", "vpd_pg80"))
    if s:
        return s
    if name.startswith("nvme"):
        ctrl_dir = os.path.join(sys_root, "class", "nvme")
        m = re.match(r"(nvme\d+)n\d+", name)
        if m:
            s = read_text(os.path.join(ctrl_dir, m.group(1), "serial"))
            if s:
                return s
        # multipath naming (nvme0c0n1, nvme-subsys): the namespace is a child of its controller
        try:
            for ctrl in sorted(os.listdir(ctrl_dir)):
                if os.path.exists(os.path.join(ctrl_dir, ctrl, name)):
                    s = read_text(os.path.join(ctrl_dir, ctrl, "serial"))
                    if s:
                        return s
        except OSError:
            pass
    return ""


def wwn_of(sys_root: str, name: str) -> str:
    base = os.path.join(sys_root, "block", name)
    for p in (os.path.join(base, "wwid"), os.path.join(base, "device", "wwid"),
              os.path.join(base, "device", "nguid"), os.path.join(base, "eui")):
        s = read_text(p)
        if s:
            return s
    return ""


def model_of(sys_root: str, name: str) -> str:
    dev = os.path.join(sys_root, "block", name, "device")
    model = read_text(os.path.join(dev, "model"))
    vendor = read_text(os.path.join(dev, "vendor"))
    if vendor and model and not model.lower().startswith(vendor.lower()):
        model = f"{vendor} {model}"
    return " ".join(model.split()) or vendor


def read_disk(ctx: Context, name: str) -> Disk:
    sys_root = ctx.paths.sys
    base = os.path.join(sys_root, "block", name)
    q = os.path.join(base, "queue")
    logical = read_int(os.path.join(q, "logical_block_size"), 512) or 512
    return Disk(
        id=name,
        path=os.path.join(ctx.paths.dev, name),
        model=model_of(sys_root, name),
        serial=serial_of(sys_root, name),
        wwn=wwn_of(sys_root, name),
        size=read_int(os.path.join(base, "size")) * 512,
        logical_sector=logical,
        physical_sector=read_int(os.path.join(q, "physical_block_size"), logical) or logical,
        transport=transport_of(sys_root, name),
        rotational=read_int(os.path.join(q, "rotational")) == 1,
        removable=read_int(os.path.join(base, "removable")) == 1,
    )


def read_partitions(ctx: Context, disk: str) -> list[Partition]:
    base = os.path.join(ctx.paths.sys, "block", disk)
    out = []
    for pn in partition_names(ctx.paths.sys, disk):
        pb = os.path.join(base, pn)
        out.append(Partition(
            id=pn, path=os.path.join(ctx.paths.dev, pn), number=read_int(os.path.join(pb, "partition")),
            start=read_int(os.path.join(pb, "start")) * 512, size=read_int(os.path.join(pb, "size")) * 512))
    return out


# -- blkid --------------------------------------------------------------------------------

def blkid_all(ctx: Context, paths: list[str]) -> dict[str, dict[str, str]]:
    """`blkid -p -o export` for many devices -> {device path: {KEY: value}}.
    A device blkid knows nothing about maps to {}."""
    out: dict[str, dict[str, str]] = {p: {} for p in paths}
    for i in range(0, len(paths), 40):
        chunk = paths[i:i + 40]
        cp = ctx.system.runner.run(["blkid", "-p", "-o", "export", *chunk], timeout=60)
        cur: dict[str, str] = {}
        for line in (cp.stdout or "").splitlines() + [""]:
            line = line.strip()
            if not line:
                if cur.get("DEVNAME") in out:
                    out[cur["DEVNAME"]].update(cur)
                elif cur and len(chunk) == 1:  # one device: some blkid versions omit DEVNAME
                    out[chunk[0]].update(cur)
                cur = {}
            elif "=" in line:
                k, v = line.split("=", 1)
                cur[k] = v
    return out


def part_type(info: dict[str, str]) -> str:
    t = info.get("PART_ENTRY_TYPE", "").lower()
    if re.fullmatch(r"0x[0-9a-f]+", t):
        return f"0x{int(t, 16):02x}"
    return t


# -- assembled devices (md, dm) -----------------------------------------------------------

def slaves_of(sys_root: str, name: str) -> list[str]:
    try:
        return sorted(os.listdir(os.path.join(sys_root, "block", name, "slaves")))
    except OSError:
        return []


def physical_disks(sys_root: str, name: str, _seen: frozenset = frozenset()) -> list[str]:
    """Kernel names of the physical disks under a device (through partitions, md and dm)."""
    if name in _seen:
        return []
    seen = _seen | {name}
    for disk in block_names(sys_root):  # a partition lives in /sys/block/<disk>/<name>
        if disk != name and os.path.exists(os.path.join(sys_root, "block", disk, name, "partition")):
            return physical_disks(sys_root, disk, seen)
    sl = slaves_of(sys_root, name)
    if not sl:
        return [name]
    out: list[str] = []
    for s in sl:
        for d in physical_disks(sys_root, s, seen):
            if d not in out:
                out.append(d)
    return out


def md_metadata(sys_root: str, name: str) -> str:
    return read_text(os.path.join(sys_root, "block", name, "md", "metadata_version"))


def is_md_container(sys_root: str, name: str) -> bool:
    meta = md_metadata(sys_root, name)
    return meta.startswith("external:") and not meta.startswith("external:/")


def assembled_volumes(ctx: Context) -> list[Volume]:
    """Every md and dm device that exists right now, as a Volume (containers left out)."""
    sys_root = ctx.paths.sys
    vols = []
    for name in block_names(sys_root):
        if not is_assembled_name(name):
            continue
        base = os.path.join(sys_root, "block", name)
        if name.startswith("md"):
            if is_md_container(sys_root, name):
                continue
            kind = VolumeKind.MD
        else:
            if is_overlay_kname(ctx, name):
                continue  # a RAM copy-on-write view of a member, not something to copy
            duuid = read_text(os.path.join(base, "dm", "uuid"))
            kind = VolumeKind.CRYPT if duuid.startswith("CRYPT-") else VolumeKind.LV
            if duuid.startswith("LDM-"):
                kind = VolumeKind.LDM
        size = read_int(os.path.join(base, "size")) * 512
        if size == 0:
            continue
        vols.append(Volume(id=name, path=os.path.join(ctx.paths.dev, name), kind=kind, size=size,
                           readonly=read_int(os.path.join(base, "ro")) == 1,
                           disk_ids=physical_disks(sys_root, name)))
    return vols


# -- mounts and the BeastBoot stick -------------------------------------------------------

def _node_name(src: str) -> str:
    return os.path.basename(os.path.realpath(src)) if os.path.islink(src) else os.path.basename(src)


def mount_sources(ctx: Context, mountpoints: list[str]) -> list[str]:
    """Device nodes mounted at any of ``mountpoints`` (from /proc/mounts)."""
    wanted = {os.path.normpath(m) for m in mountpoints if m}
    out = []
    for line in read_text(os.path.join(ctx.paths.proc, "mounts")).splitlines():
        f = line.split()
        if len(f) >= 2 and os.path.normpath(f[1].replace("\\040", " ")) in wanted:
            out.append(f[0])
    return out


def mounted_devices(ctx: Context) -> set[str]:
    """Kernel names of every block device with a mounted filesystem or active swap."""
    names = set()
    for line in read_text(os.path.join(ctx.paths.proc, "mounts")).splitlines():
        f = line.split()
        if f and f[0].startswith("/"):
            names.add(_node_name(f[0]))
    for line in read_text(os.path.join(ctx.paths.proc, "swaps")).splitlines()[1:]:
        f = line.split()
        if f:
            names.add(_node_name(f[0]))
    return names


def stick_disk_ids(ctx: Context, disks: list[Disk]) -> set[str]:
    names = {d.id for d in disks}
    ids = set()
    for src in mount_sources(ctx, [ctx.paths.data, ctx.paths.esp]):
        for d in physical_disks(ctx.paths.sys, _node_name(src)):
            if d in names:
                ids.add(d)
    return ids


# -- the scan -----------------------------------------------------------------------------

def _tok(value: object) -> str:
    return "-" if value in ("", None) else str(value).replace(" ", "_")


def scan(ctx: Context) -> Inventory:
    """Read-only inventory: disks, partitions, stacks, volumes. Emits `disk found`
    and `stack found` lines. Call guard.protect_all(ctx) first."""
    from . import probe

    disks: list[Disk] = []
    for name in block_names(ctx.paths.sys):
        if name.startswith(SKIP_PREFIXES) or is_assembled_name(name):
            continue
        if not os.path.exists(os.path.join(ctx.paths.sys, "block", name, "size")):
            continue
        d = read_disk(ctx, name)
        if d.size <= 0:
            continue
        d.partitions = read_partitions(ctx, name)
        disks.append(d)

    sticks = stick_disk_ids(ctx, disks)
    for d in disks:
        d.is_boot_stick = d.id in sticks

    assembled = assembled_volumes(ctx)
    paths = [d.path for d in disks] + [p.path for d in disks for p in d.partitions] + [v.path for v in assembled]
    blk = blkid_all(ctx, paths)

    volumes: list[Volume] = []
    for d in disks:
        info = blk.get(d.path, {})
        d.fs_type = info.get("TYPE", "")
        volumes.append(Volume(id=d.id, path=d.path, kind=VolumeKind.DISK, size=d.size, fs_type=d.fs_type,
                              label=info.get("LABEL", ""), disk_ids=[d.id], readonly=True))
        for p in d.partitions:
            pi = blk.get(p.path, {})
            p.fs_type, p.label, p.uuid, p.type = pi.get("TYPE", ""), pi.get("LABEL", ""), pi.get("UUID", ""), part_type(pi)
            volumes.append(Volume(id=p.id, path=p.path, kind=VolumeKind.PARTITION, size=p.size, fs_type=p.fs_type,
                                  label=p.label, disk_ids=[d.id], readonly=True))
    for v in assembled:
        vi = blk.get(v.path, {})
        v.fs_type, v.label = vi.get("TYPE", ""), vi.get("LABEL", "")
        volumes.append(v)

    stacks = probe.detect(ctx, disks, assembled, blk)

    for d in disks:
        ctx.reporter.emit("disk found", f"id={d.id}", f"serial={_tok(d.serial)}", f"size={d.size}",
                          f"lss={d.logical_sector}", f"pss={d.physical_sector}",
                          f"transport={d.transport.value}", f"stick={1 if d.is_boot_stick else 0}")
    for s in stacks:
        ctx.reporter.emit("stack found", f"id={s.id}", f"kind={s.kind.value}", f"level={_tok(s.level)}",
                          f"members={len(s.members)}", f"state={s.state.value}", f"support={s.support.value}")
    return Inventory(disks=disks, stacks=stacks, volumes=volumes)
