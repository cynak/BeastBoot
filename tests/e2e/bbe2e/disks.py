"""Harness for the Disk tools e2e tests (docs/DISK_TOOLS.md sections 4, 6, 7).

* attach fixture images (tests/e2e/fixtures/disks.py) to the helper VM as NVMe
  (`-device nvme,serial=`) or AHCI (`ide-hd,serial=` on q35) disks;
* write script-mode plans (`beastnet.script=`), wait for the event lines;
* boot the helper under UEFI, legacy BIOS or UEFI with Secure Boot (`boot_helper(mode=)`);
* the immutability gate: every source image is hashed fully before and after
  a flow; any changed byte fails;
* targets and image destinations for copy tests: blank sparse disks and an
  ext4 "images" disk, both created on the host without root (mke2fs on a file,
  debugfs to read files back).
"""

from __future__ import annotations

import hashlib
import lzma
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import beastnet as bn
from . import env

MIB = 1024 * 1024
# Where the stick's helper looks for the images disk's files (see IMAGE_DEST).
IMAGES_SERIAL = "BBIMG001"
TARGET_SERIAL = "BBTGT001"
OTHER_TARGET_SERIAL = "BBTGT002"
SMALL_TARGET_SERIAL = "BBSML001"
IMAGE_DEST = "/images/x.img"   # path on the images disk: plans open it with use_disk, then image "on" it

# helper modules whose presence in the initramfs marks a feature (docs/DISK_TOOLS.md section 3)
FEATURE_MODULES = {
    "discover": "beastnet/disks/discover.py",
    "assemble": "beastnet/disks/assemble.py",
    "reconstruct": "beastnet/disks/reconstruct.py",
    "copy": "beastnet/disks/copy.py",
    "script": "beastnet/disks/script.py",
}
FEATURE_TOOLS = {"mdadm": "mdadm", "lvm": "lvm", "cryptsetup": "cryptsetup", "ddrescue": "ddrescue"}


# ---------------------------------------------------------------------------
# Attached disks
# ---------------------------------------------------------------------------

@dataclass
class Attached:
    path: Path
    serial: str
    transport: str = "nvme"        # nvme | ahci | usb (usb-storage on its own xHCI controller)
    name: str = ""
    snapshot: bool = False         # writes go to a temporary overlay (QEMU snapshot=on)
    lbs: int = 512                 # logical sector size (4096 = 4Kn; NVMe and USB only, IDE is 512)
    pbs: int = 0                   # physical sector size (4096 with lbs 512 = 512e); 0 = same as lbs
    throttle_bps: int = 0          # QEMU read throttling (bytes/s), to stop a copy halfway
    blkdebug: Path | None = None   # blkdebug config: read errors injected on chosen sectors


def from_manifest(manifest: dict, *sets: str, only_present: bool = True) -> list[Attached]:
    out = []
    for s in sets:
        for d in manifest["sets"][s]["disks"]:
            if d.get("omit") and only_present:
                continue
            out.append(Attached(Path(d["path"]), d["serial"], d["transport"], d["name"], lbs=d.get("lss", 512)))
    return out


def qemu_args(disks: list[Attached]) -> list[str]:
    """-drive/-device arguments for the extra disks. AHCI disks take ports ide.5, ide.4, ...
    (the stick keeps ide.0 if it is attached as IDE)."""
    args: list[str] = []
    ahci = 5
    usb_ctrl = False
    for i, d in enumerate(disks):
        did = f"fx{i}"
        snap = "on" if d.snapshot else "off"
        if d.blkdebug:
            spec = (f"if=none,id={did},driver=raw,file.driver=blkdebug,file.config={d.blkdebug},"
                    f"file.image.driver=file,file.image.filename={d.path}")
        else:
            spec = f"if=none,id={did},file={d.path},format=raw"
        spec += f",snapshot={snap},cache=unsafe"
        if d.throttle_bps:
            spec += f",throttling.bps-read={d.throttle_bps}"
        args += ["-drive", spec]
        blk = ""
        if d.lbs != 512 or d.pbs:
            blk = f",logical_block_size={d.lbs},physical_block_size={d.pbs or d.lbs}"
        if d.transport == "nvme":
            args += ["-device", f"nvme,serial={d.serial},drive={did}{blk}"]
        elif d.transport == "ahci":
            if ahci < 1:
                raise ValueError("more than 5 AHCI disks")
            if d.lbs != 512:
                raise ValueError("IDE/AHCI disks have 512-byte logical sectors")
            args += ["-device", f"ide-hd,serial={d.serial},drive={did},bus=ide.{ahci}{blk}"]
            ahci -= 1
        elif d.transport == "usb":
            if not usb_ctrl:
                args += ["-device", "qemu-xhci,id=bbxhci"]
                usb_ctrl = True
            args += ["-device", f"usb-storage,bus=bbxhci.0,serial={d.serial},drive={did},removable=off{blk}"]
        else:
            raise ValueError(d.transport)
    return args


# ---------------------------------------------------------------------------
# Data disks made on the host: random content, read errors, byte ranges
# ---------------------------------------------------------------------------

def random_disk(path: Path, size: int, serial: str, seed: str, transport: str = "nvme") -> Attached:
    """A disk full of seeded pseudo-random bytes (no partition table): every byte is checkable."""
    import random
    r = random.Random(seed)
    with open(path, "wb") as f:
        left = size
        while left:
            n = min(8 * MIB, left)
            f.write(r.randbytes(n))
            left -= n
    return Attached(Path(path), serial, transport, Path(path).name)


def blkdebug_config(path: Path, bad: list[tuple[int, int]]) -> Path:
    """QEMU blkdebug rules: every read touching a sector in the (first, count) ranges fails with
    EIO, every time (one rule per sector: blkdebug matches single sectors)."""
    rules = []
    for first, count in bad:
        for s in range(first, first + count):
            rules.append(f'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "{s}"\nonce = "off"\n')
    Path(path).write_text("\n".join(rules))
    return Path(path)


def fill_range(path: Path, start: int, length: int, byte: int) -> None:
    with open(path, "r+b") as f:
        f.seek(start)
        left = length
        while left:
            n = min(MIB, left)
            f.write(bytes([byte]) * n)
            left -= n


def sha256_range(path: Path, start: int, length: int) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(start)
        left = length
        while left:
            b = f.read(min(8 * MIB, left))
            if not b:
                break
            h.update(b)
            left -= len(b)
    return h.hexdigest()


def read_range(path: Path, start: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(length)


def parse_mapfile(text: str) -> list[tuple[int, int, str]]:
    """ddrescue mapfile blocks (pos, size, status); the first data line is the current status."""
    blocks, seen = [], False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        w = line.split()
        if not seen:
            seen = True
            continue
        if len(w) >= 3:
            blocks.append((int(w[0], 0), int(w[1], 0), w[2]))
    return blocks


def stick_mapfiles(drive) -> dict[str, bytes | None]:
    """ddrescue mapfiles the helper left in /disk-tools on the stick's data partition.
    None = listed but unreadable (after a power cut the FAT may not hold the file's clusters)."""
    out: dict[str, bytes | None] = {}
    with drive.data_writer() as w:
        if not w.exists("/disk-tools"):
            return out
        for entry in w.listing("/disk-tools"):
            name = entry.rsplit("/", 1)[-1]
            if name.endswith(".map"):
                try:
                    out[name] = w.read("/disk-tools/" + name)
                except subprocess.CalledProcessError:
                    out[name] = None
    return out


def gpt_header(path: Path, lba: int, ss: int) -> dict | None:
    import struct
    with open(path, "rb") as f:
        f.seek(lba * ss)
        h = f.read(92)
    if h[:8] != b"EFI PART":
        return None
    my, alt, first, last = struct.unpack_from("<QQQQ", h, 24)
    entries, n, esz, ecrc = struct.unpack_from("<QIII", h, 72)
    return {"my": my, "alt": alt, "first_usable": first, "last_usable": last, "entries_lba": entries,
            "n_entries": n, "entry_size": esz, "entries_crc": ecrc}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(8 * MIB), b""):
            h.update(blk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# The immutability gate
# ---------------------------------------------------------------------------

class GateViolation(AssertionError):
    pass


class Gate:
    """Hash every source image fully before and after; any change fails.
    `expected` (optional) = SHA-256 as built (manifest image_sha256): the images
    must also match the cache before the flow starts."""

    def __init__(self, paths: list[Path], expected: dict[str, str] | None = None):
        self.paths = [Path(p) for p in paths]
        self.expected = expected or {}
        self.before: dict[Path, str] = {}

    def start(self) -> None:
        self.before = {p: sha256_file(p) for p in self.paths}
        for p, want in self.expected.items():
            got = self.before.get(Path(p))
            if got is not None and got != want:
                raise GateViolation(f"{p} differs from the fixture cache before the flow even started "
                                    f"(cache corrupted by an earlier run?): {got} != {want}")

    def check(self) -> None:
        bad = []
        for p, h in self.before.items():
            now = sha256_file(p)
            if now != h:
                bad.append(f"{p.name}: {h[:16]} -> {now[:16]}")
        if bad:
            raise GateViolation("source image(s) CHANGED during a read-only flow: " + "; ".join(bad))


@contextmanager
def gate(attached: list[Attached], manifest: dict | None = None):
    exp = {}
    if manifest:
        for s in manifest["sets"].values():
            for d in s["disks"]:
                if d.get("path"):
                    exp[d["path"]] = d["image_sha256"]
    g = Gate([d.path for d in attached if not d.snapshot], exp)
    g.start()
    yield g
    g.check()


# ---------------------------------------------------------------------------
# Targets and the images disk (host side, no root)
# ---------------------------------------------------------------------------

def blank_disk(path: Path, size: int, serial: str, transport: str = "nvme", fill: int | None = None) -> Attached:
    """A sparse blank disk. fill=<byte> writes a recognisable pattern into the first MiB."""
    with open(path, "wb") as f:
        f.truncate(size)
        if fill is not None:
            f.write(bytes([fill]) * MIB)
    return Attached(Path(path), serial, transport, Path(path).name)


def images_disk(path: Path, size_mib: int = 512, serial: str = IMAGES_SERIAL, transport: str = "ahci") -> Attached:
    """An ext4 disk (whole device, no partition table) with a /images directory."""
    path = Path(path)
    with open(path, "wb") as f:
        f.truncate(size_mib * MIB)
    mke2fs = env.which("mke2fs") or "mke2fs"
    env.run([mke2fs, "-q", "-F", "-t", "ext4", "-L", "BBIMAGES", str(path)], timeout=120)
    env.run([env.which("debugfs") or "debugfs", "-w", "-R", "mkdir /images", str(path)], timeout=60)
    return Attached(path, serial, transport, path.name)


def ext4_read(img: Path, fs_path: str, dest: Path) -> bool:
    """Copy a file out of an ext4 image with debugfs (no mount). False if it does not exist."""
    dest.unlink(missing_ok=True)
    debugfs = env.which("debugfs") or "debugfs"
    p = subprocess.run([debugfs, "-R", f"dump {fs_path} {dest}", str(img)], capture_output=True, text=True, timeout=300)
    return dest.exists() and p.returncode == 0


def ext4_sha256(img: Path, fs_path: str, workdir: Path) -> str | None:
    tmp = workdir / ("dump-" + re.sub(r"\W+", "_", fs_path))
    if not ext4_read(img, fs_path, tmp):
        return None
    try:
        return sha256_file(tmp)
    finally:
        tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Script plans (docs/DISK_TOOLS.md section 6)
# ---------------------------------------------------------------------------

def plan(*steps: dict, then: str = "poweroff", on_error: str = "poweroff") -> dict:
    return {"action": "disk", "then": then, "on_error": on_error, "steps": list(steps)}


def write_plan(drive, p: dict) -> None:
    bn.write_plan(drive, p)


def confirm(serial: str) -> str:
    return serial[-6:]


# ---------------------------------------------------------------------------
# Event lines
# ---------------------------------------------------------------------------

def events(vm, kind: str, after: int = 0) -> list[dict[str, str]]:
    """Every `BEASTNET: <kind> ...` line so far as field dicts (plus "_" = the line)."""
    out = []
    for ln in bn.lines(vm, after):
        if ln == kind or ln.startswith(kind + " "):
            d = bn.fields(ln)
            d["_"] = ln
            out.append(d)
    return out


def wait_events(vm, kind: str, count: int = 1, *, timeout: float = 240, after: int = 0) -> list[dict[str, str]]:
    """Wait until at least `count` lines of `kind` were seen; returns all of them."""
    import time

    end = time.monotonic() + env.t(timeout)
    while True:
        got = events(vm, kind, after)
        if len(got) >= count:
            return got
        if time.monotonic() > end or not vm.running:
            vm_tail = "\n".join(bn.lines(vm, after)[-25:])
            raise AssertionError(f"waited for {count} x 'BEASTNET: {kind}', saw {len(got)}; last helper lines:\n{vm_tail}")
        time.sleep(0.5)


def errors(vm, after: int = 0) -> list[str]:
    return [ln for ln in bn.lines(vm, after) if ln.startswith("error ")]


def wait_disks(vm, serials: list[str], *, after: int = 0, timeout: float = 240) -> dict[str, dict[str, str]]:
    """Wait for a `disk found` line for each serial; returns serial -> fields."""
    import time

    end = time.monotonic() + env.t(timeout)
    while True:
        found = {e["serial"]: e for e in events(vm, "disk found", after) if "serial" in e}
        if all(s in found for s in serials):
            return found
        if time.monotonic() > end or not vm.running:
            raise AssertionError(f"disk found missing for {sorted(set(serials) - set(found))}; seen {sorted(found)}; "
                                 f"last lines:\n" + "\n".join(bn.lines(vm, after)[-25:]))
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Helper features (what the initramfs ships)
# ---------------------------------------------------------------------------

_features_cache: dict[str, set[str]] = {}


def initrd_names(initrd: Path) -> list[str]:
    """Names in the helper's xz-compressed newc initramfs (data skipped, not kept)."""
    names: list[str] = []
    with lzma.open(initrd) as f:
        while True:
            hdr = f.read(110)
            if len(hdr) < 110:
                break
            if hdr[:6] != b"070701":
                hdr = hdr.lstrip(b"\0")  # zero padding between concatenated archives
                hdr += f.read(110 - len(hdr))
                if len(hdr) < 110 or hdr[:6] != b"070701":
                    break
            size = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
            name = f.read((110 + namesize + 3 & ~3) - 110)[:namesize - 1].decode(errors="replace")
            if name == "TRAILER!!!":
                continue
            names.append(name.removeprefix("./"))
            f.read((size + 3) & ~3)
    return names


def helper_features(dist_dir: Path) -> set[str]:
    """Feature names present in the helper: modules (FEATURE_MODULES) and tools (FEATURE_TOOLS)."""
    initrd = Path(dist_dir) / "esp" / "beast-net" / "initrd.img"
    key = str(initrd)
    if key not in _features_cache:
        names = initrd_names(initrd)
        have: set[str] = set()
        for feat, suffix in FEATURE_MODULES.items():
            if any(n.endswith(suffix) for n in names):
                have.add(feat)
        for feat, tool in FEATURE_TOOLS.items():
            if any(n.rsplit("/", 1)[-1] == tool and n.split("/")[0] in ("sbin", "bin", "usr") for n in names):
                have.add(feat)
        _features_cache[key] = have
    return _features_cache[key]


def wait_done(vm, timeout: float, *, grace: float = 25, after: int = 0) -> None:
    """Wait for the plan to end: the VM powers off (`then`/`on_error=poweroff`). If an `error`
    line shows and the helper still has not powered off after `grace` seconds (script errors
    before the plan starts leave the helper in its menu), stop the VM: the error is the result."""
    import time

    end = time.monotonic() + env.t(timeout)
    err_at = None
    while vm.running:
        if err_at is None and errors(vm, after):
            err_at = time.monotonic()
        if err_at is not None and time.monotonic() - err_at > env.t(grace):
            vm.stop()
            return
        if time.monotonic() > end:
            raise AssertionError(f"{vm.name}: the plan did not finish in {timeout}s; last lines:\n"
                                 + "\n".join(bn.lines(vm, after)[-25:]))
        time.sleep(0.5)


@dataclass
class Boot:
    vm: object
    boot_end: int = 0
    notes: list[str] = field(default_factory=list)


def boot_helper(vm_factory, drive, attached: list[Attached], *, memory: int = 2048, hard_timeout: float = 600,
                mode: str = "uefi", mok_certs: list[Path] | tuple = ()) -> Boot:
    """Boot the stick, pick the helper entry (the plan in `drive` is run by script mode) with
    the fixture disks attached. `mode` is a VM mode: "uefi", "bios" or "uefi-sb". "uefi-sb" is
    the real Secure Boot chain (shim, signed GRUB, signed helper kernel in lockdown) and needs
    the BeastBoot certificate in `mok_certs`; there the helper asks on the console before it
    runs a plan from the stick, and this answers it."""
    kw = {"mok_certs": list(mok_certs)} if mode == "uefi-sb" else {}
    vm = vm_factory(mode, drive.path, memory=memory, hard_timeout=hard_timeout, extra_args=qemu_args(attached), **kw)
    rec = bn.select_entry(vm)
    if mode == "uefi-sb":
        bn.confirm_script(vm, after=rec.end)
    return Boot(vm, rec.end)
