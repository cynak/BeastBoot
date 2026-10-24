"""install / update / info / list-devices.

Everything on the drive is written by this package in pure Python, through a
BlockTarget (interfaces.py): an image file (blockio.ImageTarget, sparse) or a
whole disk opened by the platform backend (platforms.get_backend()):

  partition table   parttable.write_partition_table
  data partition    exfatfs.format_exfat / fatfs.format_fat (FAT32), with a
                    volume serial chosen here, so device.cfg is known up front;
                    NTFS is the exception (mkfs.ntfs for images, the backend's
                    format_ntfs on drives; refused where the OS has none)
  ESP               fatfs.build_esp, first into memory (so "does not fit"
                    fails before the drive is touched), then copied over
  BIOS boot code    bootcode.boot_writes

`update` and `info` read the ESP with fatfs.FatVolume and identify partition 1
with fs.probe_fs. `update` writes through a GuardedTarget that only allows the
boot area and the ESP: it can never write partition 1. It rebuilds the ESP,
carrying over grub/grubenv and the installed firmware packs
(beast-net/firmware/), and refuses a drive of another layout version (the ESP
size changed: a reinstall is needed).

An interrupted update (Stop pressed, the drive stopped responding or was
unplugged while the ESP was written) is finished by running update again:
the ESP's boot sector is zeroed first and written last (_write_esp_and_boot),
so a half-written ESP is recognisable, and the files update carries over are
kept on the host meanwhile (_UpdateRecords; Linux: /var/lib/beast-booter).
_watch_device turns errors of a drive that vanished into one clear
"device-vanished" error and shows what the kernel said about the drive.

The `firmware` commands live in firmware.py.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace

from .blockio import ImageTarget
from .bootcode import boot_writes, read_core_lba
from .disk import PartTable, read_partition_table
from .dist import Dist, load_dist
from .device import MEDIUM_ERRNOS
from .distsource import prepare_dist_dir
from .errors import BeastError, Cancelled, DeviceVanished
from .esp import (
    DeviceConfig,
    esp_files,
    marker_layout_version,
    parse_marker,
    read_kept_files,
    parse_set_lines,
    read_esp_text,
    render_marker,
)
from .exfatfs import check_label as check_exfat_label
from .exfatfs import format_exfat
from .fatfs import FatVolume, build_esp, format_fat, label_bytes
from .fs import (
    NTFS_TOOL,
    fs_name,
    grub_uuid,
    have_mkfs_ntfs,
    make_data_fs,
    normalize_label,
    ntfs_serial,
    probe_fs,
)
from .interfaces import format_volume_id
from .layout import (
    BIOS_BOOT_PART_INDEX,
    DATA_PART_INDEX,
    DATA_START_LBA,
    DEVICE_CFG_PATH,
    ESP_LABEL,
    ESP_MARKER_PATH,
    ESP_PART_INDEX,
    ESP_SIZE_MIB,
    FILESYSTEMS,
    FIRMWARE_INSTALLED_PATH,
    GPT_TYPE_BIOS_BOOT,
    GPT_TYPE_ESP,
    LAYOUT_VERSION,
    MBR_TYPE_ESP,
    MIB,
    MIN_DISK_MIB,
    SECTOR_SIZE,
)
from .parttable import write_partition_table
from .plan import DiskPlan, make_plan
from .platforms import get_backend
from .platforms.common import check_common, describe
from .target import GuardedTarget, MemoryTarget, copy_written
from .util import Reporter, confirm, copy_file_to_target, human_size, parse_size

VERSION_CFG_PATH = "grub/beast/version.cfg"

# Error code for the progress file when a BeastError has none of its own:
# what was going on when it happened.
STEP_ERROR_CODES = {
    "verify-dist": "dist-invalid",
    "check-target": "target-refused",
    "prepare": "prepare-failed",
    "partition": "write-failed",
    "format-data": "write-failed",
    "write-esp": "write-failed",
    "boot-code": "write-failed",
    "flush": "write-failed",
    "rescan": "rescan-failed",
    "verify-write": "verify-failed",
    # firmware fetch / install / remove (firmware.py)
    "download": "download-failed",
    "verify-packs": "pack-invalid",
    "write-firmware": "write-failed",
}

def prepare_device(backend, disk, rep: Reporter, pct: float, *, written: bool = False) -> list[str]:
    """backend.prepare() as a progress step: unmount (Linux, macOS) or lock and dismount
    (Windows) every volume of the drive, then say which mountpoints were unmounted.
    `written`: this run has written to the drive already (install's second prepare)."""
    rep.step(f"Unmounting the volumes on {disk.id}", "prepare", pct)
    try:
        unmounted = list(backend.prepare(disk) or ())
    finally:
        for note in getattr(backend, "notes", None) or ():  # Linux: a drive that stopped responding came back
            rep.warn(note)
    if getattr(backend, "medium_returned", False):
        rep.warn("continuing: what was written before it stopped is checked first" if written
                 else "continuing: nothing had been written to it yet")
    if unmounted:
        rep.step(f"Unmounted {', '.join(unmounted)} (on {disk.id})", "prepare", pct)
    return unmounted


# Raw devices are flushed this often while the ESP is copied, so the progress
# shown follows the drive and not the page cache.
DEVICE_FLUSH_EVERY = 16 * MIB
ESP_PROGRESS_EVERY = 2 * MIB
BLKFLSBUF = 0x1261  # Linux _IO(0x12, 97): write back and drop a block device's page cache


@dataclass
class InstallOptions:
    layout: str
    fs: str
    label: str
    dist_dir: str
    serial: bool = False
    yes: bool = False
    allow_fixed: bool = False


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@contextmanager
def _invalid_argument():
    """BeastErrors raised inside are about the command line (code invalid-argument)."""
    try:
        yield
    except BeastError as e:
        if e.code is None:
            e.code = "invalid-argument"
        raise


def check_data_label(label: str, fs: str) -> str:
    """normalize_label(), plus the filesystem writer's own rules (exFAT: 11
    characters), so a bad label is refused before anything is written."""
    label = normalize_label(label, fs)
    if fs == "exfat":
        check_exfat_label(label)
    elif fs == "fat32":
        label_bytes(label)
    return label


def _new_serial() -> int:
    """A random, non-zero 32-bit FAT/exFAT volume serial."""
    while True:
        value = secrets.randbits(32)
        if value:
            return value


def _verify_dist(dist_dir: str, tmp: str, rep: Reporter, pct: float) -> Dist:
    rep.step(f"Checking the boot files in {dist_dir} against manifest.json", "verify-dist", pct)
    root = prepare_dist_dir(dist_dir, tmp)
    return load_dist(root, os.path.join(tmp, "staging"))


def _esp_timestamp(dist: Dist) -> int | None:
    """File times on the ESP: the build's SOURCE_DATE_EPOCH (else 1980-01-01)."""
    value = dist.manifest.get("source_date_epoch")
    if isinstance(value, int) and not isinstance(value, bool) and 315532800 <= value < 4354819198:
        return value
    return None


def _new_config(opts: InstallOptions, label: str) -> tuple[DeviceConfig, int | None]:
    """device.cfg for a new install and the data volume serial (None for NTFS,
    whose serial is only known once mkfs.ntfs / Format-Volume has run)."""
    if opts.fs == "ntfs":
        serial, linux_uuid = None, "0" * 16  # placeholder, replaced after formatting
    else:
        serial = _new_serial()
        linux_uuid = format_volume_id(serial)
    cfg = DeviceConfig(
        install_id=str(uuid.uuid4()),
        layout=opts.layout,
        data_fs=opts.fs,
        data_uuid=grub_uuid(linux_uuid),
        data_uuid_linux=linux_uuid,
        data_label=label,
        serial=opts.serial,
    )
    return cfg, serial


def _build_esp(plan: DiskPlan, dist: Dist, cfg: DeviceConfig, volume_id: int,
               keep: dict[str, bytes] | None = None) -> MemoryTarget:
    """The complete ESP volume, built in memory (`keep`: files update carries over)."""
    mem = MemoryTarget(plan.esp.size_bytes)
    files = esp_files(dist.esp_dir, cfg, render_marker(cfg.install_id, dist.version), keep)
    build_esp(mem, 0, plan.esp.size_bytes, files, label=ESP_LABEL, volume_id=volume_id,
              hidden_sectors=plan.esp.start, timestamp=_esp_timestamp(dist))
    return mem


def _format_data(t, plan: DiskPlan, fs: str, label: str, serial: int, timestamp: int | None) -> None:
    """exFAT / FAT32 on partition 1. The serial is ours (device.cfg knows it already);
    FAT32's label entry is dated `timestamp` (format_exfat writes no timestamps)."""
    if fs == "exfat":
        format_exfat(t, plan.data.offset, plan.data.size_bytes, label=label, volume_serial=serial)
    elif fs == "fat32":
        format_fat(t, plan.data.offset, plan.data.size_bytes, fat_bits=32, label=label,
                   volume_id=serial, hidden_sectors=plan.data.start, timestamp=timestamp)
    else:
        raise BeastError(f"internal error: {fs} is not formatted in place")


def _write_esp_and_boot(t, plan: DiskPlan, mem: MemoryTarget, writes, rep: Reporter,
                        pct: tuple[float, float, float], *, flush_every: int | None) -> None:
    """Copy the ESP built in memory onto the target, then the BIOS boot code."""
    start, end, boot_pct = pct
    total = mem.written_bytes()
    rep.step(f"Writing the boot partition ({ESP_LABEL}, {human_size(total)})", "write-esp", start)
    last = [0]

    def progress(done: int, total: int) -> None:
        if done - last[0] >= ESP_PROGRESS_EVERY or done == total:
            last[0] = done
            rep.check_cancel(within=True)  # the longest loop: honour --cancel-file inside it too
            rep.progress("write-esp", f"Writing the boot partition: {human_size(done)} of {human_size(total)}",
                         start + (end - start) * done / max(total, 1))

    # The ESP's boot sector goes first as zeros and last for real, each flushed: until
    # all of the new ESP is on the drive it has no valid boot sector, so an
    # interrupted write is recognisable (_interrupted_state) and the next update
    # finishes it, instead of reading a half-old, half-new ESP.
    boot_sector = bytes(mem.buf[0:SECTOR_SIZE])
    t.write(plan.esp.offset, bytes(SECTOR_SIZE))
    t.flush()
    mem.buf[0:SECTOR_SIZE] = bytes(SECTOR_SIZE)
    try:
        copy_written(mem, t, plan.esp.offset, on_progress=progress, flush_every=flush_every)
    finally:
        mem.buf[0:SECTOR_SIZE] = boot_sector
    t.flush()
    t.write(plan.esp.offset, boot_sector)
    rep.step("Writing the BIOS boot code", "boot-code", boot_pct)
    for offset, data in writes:
        t.write(offset, data)


def _boot_area_and_esp(plan: DiskPlan) -> list[tuple[int, int]]:
    """Byte ranges update may write: everything before partition 1, and the ESP."""
    return [
        (0, DATA_START_LBA * SECTOR_SIZE),
        (plan.esp.offset, plan.esp.offset + plan.esp.size_bytes),
    ]


def _check_table_matches(table: PartTable, plan: DiskPlan) -> None:
    """The on-disk table must be the beast-booter layout we would create for this disk."""
    problems = []
    esp = table.entries.get(ESP_PART_INDEX)
    want_esp_type = GPT_TYPE_ESP if plan.layout == "gpt" else "0x%02x" % MBR_TYPE_ESP
    if esp is None:
        problems.append("partition 2 (ESP) is missing")
    elif (esp.start, esp.size, esp.type) != (plan.esp.start, plan.esp.size, want_esp_type):
        problems.append(
            f"partition 2 is start={esp.start} size={esp.size} type={esp.type}, expected "
            f"start={plan.esp.start} size={plan.esp.size} type={want_esp_type}"
        )
    data = table.entries.get(DATA_PART_INDEX)
    if data is None:
        problems.append("partition 1 (data) is missing")
    elif data.start != plan.data.start or data.end >= plan.esp.start:
        problems.append(f"partition 1 is start={data.start} size={data.size}, expected start={plan.data.start} ending before the ESP")
    if plan.layout == "gpt":
        b, want = table.entries.get(BIOS_BOOT_PART_INDEX), plan.bios
        assert want is not None
        if b is None or (b.start, b.size, b.type) != (want.start, want.size, GPT_TYPE_BIOS_BOOT):
            problems.append(f"partition 3 is not the BIOS boot partition at LBA {want.start}..{want.end}")
    for idx, e in table.entries.items():
        if idx not in (DATA_PART_INDEX, ESP_PART_INDEX, BIOS_BOOT_PART_INDEX):
            problems.append(f"unexpected partition {idx}")
    if problems:
        raise BeastError("the partition layout does not match a beast-booter drive: " + "; ".join(problems))


def _read_table(t, where: str) -> PartTable:
    try:
        return read_partition_table(t.read, t.size // SECTOR_SIZE)
    except BeastError as e:
        raise BeastError(f"{where} is not a beast-booter drive: {e}") from None


def _no_marker(where: str) -> BeastError:
    return BeastError(f"{where} is not a beast-booter drive (no {ESP_MARKER_PATH} marker on partition 2)")


def _open_esp(t, esp_offset: int, where: str) -> FatVolume:
    try:
        return FatVolume(t, esp_offset)
    except BeastError:
        raise _no_marker(where) from None


def _read_marker(vol: FatVolume, where: str) -> dict[str, str]:
    text = read_esp_text(vol, ESP_MARKER_PATH)
    marker = parse_marker(text) if text is not None else None
    if marker is None:
        raise _no_marker(where)
    return marker


def check_layout_version(marker: dict[str, str], where: str) -> int:
    """The drive's layout version, which must be this installer's (LAYOUT_VERSION).

    Layout 1 had a 64 MiB FAT16 ESP; there is no migration (partition 1 would
    have to shrink), so an older drive needs a reinstall."""
    lv = marker_layout_version(marker)
    if lv is None:
        raise BeastError(f"{where}: {ESP_MARKER_PATH} has an unknown layout version "
                         f"{marker.get('layout_version')!r}", code="layout-unsupported")
    if lv < LAYOUT_VERSION:
        raise BeastError(
            f"{where} has the beast-booter layout {lv} (a smaller boot partition); this beast-booter "
            f"needs layout {LAYOUT_VERSION} (a {ESP_SIZE_MIB} MiB FAT32 boot partition): reinstall needed "
            f"(layout {lv} -> {LAYOUT_VERSION}). install erases the whole drive, so copy your files "
            f"off partition 1 first", code="reinstall-needed")
    if lv > LAYOUT_VERSION:
        raise BeastError(f"{where} was made by a newer beast-booter (layout {lv}; this one knows layout "
                         f"{LAYOUT_VERSION}); use a newer beast-booter", code="layout-too-new")
    return lv


def read_drive_esp(t, where: str) -> tuple[PartTable, DiskPlan, FatVolume, dict[str, str]]:
    """Open the ESP of a beast-booter drive of the current layout: (table, plan,
    ESP volume, marker). The layout version is checked before the partition
    sizes, so an old drive gets "reinstall needed", not "does not match"."""
    table = _read_table(t, where)
    esp = table.entries.get(ESP_PART_INDEX)
    if esp is not None:
        check_layout_version(_read_marker(_open_esp(t, esp.start * SECTOR_SIZE, where), where), where)
    plan = make_plan(t.size // SECTOR_SIZE, table.label)
    _check_table_matches(table, plan)
    vol = _open_esp(t, plan.esp.offset, where)
    return table, plan, vol, _read_marker(vol, where)


def _image_path_check(path: str, yes: bool) -> None:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode):
        raise BeastError(f"{path} exists and is not a regular file; use --device for block devices")
    if st.st_size and not yes:
        answer = confirm(f"{path} exists and will be overwritten. Continue? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            raise BeastError("aborted", code="aborted")


def _existing_image(path: str) -> None:
    if not os.path.exists(path):
        raise BeastError(f"{path} does not exist")
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise BeastError(f"{path} is not a regular file; use --device for block devices")


def _short_name(disk) -> str:
    return disk.extra.get("name") or re.split(r"[\\/]", disk.id)[-1] or disk.id


def _confirm_device(disk, action: str) -> None:
    print(f"Target: {describe(disk)}")
    print(action)
    short = _short_name(disk)
    answer = confirm(f"Type the device name ({short}) to continue: ").strip()
    if not answer or answer not in (short, disk.id, disk.path):
        raise BeastError("aborted (device name not confirmed)", code="aborted")


def _prepare_and_open(backend, disk, rep: Reporter, pct: float, allowed, watch: _DeviceWatch, *,
                      check=None):
    """prepare_device, _open_device and `check(t)` (what is read before writing).
    If the drive stops responding in between and nothing has been written yet,
    once more: prepare() asks the kernel to check the drive again and waits for
    it. Returns (target, check's result)."""
    for attempt in (1, 2):
        prepare_device(backend, disk, rep, pct, written=watch.phase != "before")
        t = None
        try:
            t = _open_device(backend, disk, allowed)
            return t, (check(t) if check is not None else None)
        except (BeastError, OSError) as e:
            if t is not None:
                t.close()
            if attempt == 2 or watch.phase != "before" or not watch.vanished(e):
                raise
            rep.warn(f"{disk.id} stopped responding before anything was written ({e}); checking it again")
    raise AssertionError("unreachable")


def _open_device(backend, disk, allowed: list[tuple[int, int]] | None = None) -> GuardedTarget:
    t = backend.open_raw(disk, writable=True)
    if t.size != disk.size:
        t.close()
        raise BeastError(f"{disk.id}: size changed (expected {disk.size} bytes, the device has {t.size})")
    return GuardedTarget(t, allowed)


def _drop_cache(backend, t) -> None:
    """Linux: drop the whole-disk node's page cache, so reads come from the drive
    (and see what a formatter wrote through the partition node). Best effort."""
    if getattr(backend, "name", None) != "linux" or not sys.platform.startswith("linux"):
        return
    inner = getattr(t, "inner", t)
    fd = getattr(inner, "fd", None)
    if fd is None or fd < 0:
        return
    import fcntl

    try:
        fcntl.ioctl(fd, BLKFLSBUF)
    except OSError:
        pass


def _wipe_old_tables(t) -> None:
    """Zero the first and the last MiB: old partition tables (GPT backup), boot
    code and filesystem signatures (e.g. of an ISO written to the stick) go."""
    zeros = bytes(MIB)
    t.write(0, zeros)
    t.write(t.size - MIB, zeros)


def _ntfs_supported(backend_name: str | None) -> None:
    """Refuse NTFS up front where it cannot be made (before anything is written)."""
    if backend_name == "darwin":
        raise BeastError("macOS cannot create NTFS filesystems; choose exFAT (default) or FAT32",
                         code="unsupported")
    if backend_name in (None, "linux") and not have_mkfs_ntfs():
        what = "an NTFS image" if backend_name is None else "NTFS"
        raise BeastError(
            f"creating {what} needs {NTFS_TOOL} (package ntfs-3g), which was not found; "
            "choose --fs exfat (default) or fat32", code="unsupported"
        )


def _ntfs_on_image(t, plan: DiskPlan, label: str, tmp: str, cfg: DeviceConfig) -> DeviceConfig:
    """mkfs.ntfs into a sparse temporary file, copied into the (fresh, zero) image."""
    part = os.path.join(tmp, "data.img")
    with open(part, "wb") as f:
        f.truncate(plan.data.size_bytes)
    try:
        make_data_fs("ntfs", part, label, start_lba=plan.data.start)
        copy_file_to_target(part, t, plan.data.offset, skip_holes=True)
    finally:
        os.unlink(part)
    return _with_ntfs_uuid(cfg, t.read(plan.data.offset, SECTOR_SIZE))


def _with_ntfs_uuid(cfg: DeviceConfig, boot_sector: bytes) -> DeviceConfig:
    linux_uuid = ntfs_serial(boot_sector)
    if not linux_uuid:
        raise BeastError("no NTFS filesystem was found on partition 1 after formatting it")
    return replace(cfg, data_uuid=grub_uuid(linux_uuid), data_uuid_linux=linux_uuid)


def _rescan(backend, disk, rep: Reporter, watch: _DeviceWatch | None = None) -> None:
    """The OS re-reads the partition table. The drive is complete at this point,
    so a failure is a warning (unplugging and reconnecting it does the same),
    unless the drive is gone: then the check that follows cannot work either."""
    try:
        backend.rescan(disk)
    except BeastError as e:
        if watch is not None and watch.gone():
            raise
        rep.warn(str(e))


class _DeviceWatch:
    """What _watch_device knows about a drive being written: how far it got
    (`phase`: "before" anything was written, "writing", "written" = flushed)
    and the kernel's messages about it (backend.kernel_log, Linux as root)."""

    def __init__(self, backend, disk, action: str):
        self.backend, self.disk, self.action = backend, disk, action
        self.phase = "before"
        self.log = None
        start = getattr(backend, "kernel_log", None) if disk is not None else None
        if start is not None:
            try:
                self.log = start(disk)
            except Exception:  # evidence is best effort: never fail because of it
                self.log = None

    def gone(self) -> bool:
        """The drive has no medium any more (backend.medium_gone; only Linux can tell)."""
        check = getattr(self.backend, "medium_gone", None) if self.disk is not None else None
        try:
            return bool(check is not None and check(self.disk))
        except Exception:
            return False

    def vanished(self, e: BaseException) -> bool:
        if self.disk is None:
            return False
        if getattr(e, "code", None) == "device-vanished":
            return True
        if isinstance(e, OSError) and e.errno in MEDIUM_ERRNOS:
            return True
        return self.gone()  # EIO, ENOSPC (its size dropped to 0), short reads, "size changed", ...

    def kernel_lines(self) -> list[str]:
        try:
            return self.log.lines() if self.log is not None else []
        except Exception:
            return []

    def close(self) -> None:
        if self.log is not None:
            try:
                self.log.close()
            except Exception:
                pass


def vanished_message(where: str, action: str, phase: str) -> str:
    """The "device-vanished" message: what happened, whose fault, what to do."""
    when = {
        "before": "before anything was written",
        "writing": "while it was being written",
    }.get(phase, "after it was written, before it could be checked")
    if action == "update":
        again = "Update"
        result = "the update starts over and completes"
        result += "; nothing was changed" if phase == "before" else "; partition 1 (your files) is not touched"
    else:
        again = "Install"
        result = "the installation starts over and completes"
        if phase == "before":
            result += "; nothing was changed"
    return (f"{where} stopped responding {when}: the system now sees it as empty (no medium). This is the drive, "
            "not beast-booter: some USB sticks do this when they are warm or after long use. Unplug it, plug it "
            f"back in and run {again} again; {result}.")


KERNEL_LINES_SHOWN = 20


@contextmanager
def _watch_device(backend, disk, action: str, rep: Reporter):
    """Around everything an install/update does to a drive (`disk` None: an image,
    nothing to watch). On failure: an error of a drive that stopped responding
    becomes one DeviceVanished with vanished_message, and the kernel's messages
    about the drive since the start are shown as warnings (the evidence)."""
    watch = _DeviceWatch(backend, disk, action)
    try:
        yield watch
    except (Cancelled, KeyboardInterrupt):
        raise
    except Exception as e:
        failure: BaseException = e
        if isinstance(e, (BeastError, OSError)) and watch.vanished(e):
            failure = DeviceVanished(vanished_message(disk.id, action, watch.phase))
        lines = watch.kernel_lines()
        if lines:
            rep.warn(f"the kernel's messages about {disk.id} since this {action} started "
                     f"(last {min(len(lines), KERNEL_LINES_SHOWN)}):")
            for line in lines[-KERNEL_LINES_SHOWN:]:
                rep.warn(f"kernel: {line}")
        if failure is e:
            raise
        raise failure from e
    finally:
        watch.close()
        release = getattr(backend, "release", None) if disk is not None else None
        if release is not None:  # Linux: prepare()'s exclusive hold, if nothing ended it yet
            release(disk)


def _done_line(rep: Reporter, where: str, cfg: DeviceConfig, dist: Dist) -> None:
    rep.step(
        f"done: {where} is a beast-booter {dist.version} drive "
        f"({cfg.layout}, {cfg.data_fs} data partition UUID {cfg.data_uuid_linux})"
    )


def _verify_install(t, where: str, cfg: DeviceConfig, plan: DiskPlan) -> dict:
    """Read the new drive back: layout, device.cfg and the data filesystem must be what was written."""
    problems = []
    _check_table_matches(_read_table(t, where), plan)
    d = _read_info(t, where)
    if (d["layout"], d["install_id"]) != (cfg.layout, cfg.install_id):
        problems.append(f"the ESP says layout {d['layout']} / install id {d['install_id']}")
    probe = probe_fs(t, plan.data.offset)
    found = (fs_name(probe), probe.get("UUID"))
    if found != (cfg.data_fs, cfg.data_uuid_linux):
        problems.append(f"partition 1 holds {found[0] or 'no filesystem'} {found[1] or ''}".rstrip()
                        + f", expected {cfg.data_fs} {cfg.data_uuid_linux}")
    if problems:
        raise BeastError(f"{where}: what was read back differs from what was written: " + "; ".join(problems),
                         code="verify-failed")
    return d


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------


def install_image(path: str, size_text: str, opts: InstallOptions, rep: Reporter) -> dict:
    """Create the image file `path` as a beast-booter drive. Returns `info` of it."""
    rep.start("install", path)
    with _invalid_argument():
        label = check_data_label(opts.label, opts.fs)
        size = parse_size(size_text)
        sectors = size // SECTOR_SIZE
        plan = make_plan(sectors, opts.layout)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".beast-booter-", dir=parent) as tmp:
        dist = _verify_dist(opts.dist_dir, tmp, rep, 3)
        writes = boot_writes(plan, dist.boot_img, dist.core_img)
        rep.step(f"Checking the image file {path}", "check-target", 8)
        _image_path_check(path, opts.yes)
        if opts.fs == "ntfs":
            _ntfs_supported(None)
        if size % SECTOR_SIZE:
            msg = f"size rounded down to whole sectors: {sectors * SECTOR_SIZE} bytes"
            rep.note(msg)
            rep.progress("check-target", msg, 8)
        cfg, serial = _new_config(opts, label)
        esp_id = _new_serial()
        mem = _build_esp(plan, dist, cfg, esp_id)
        created = False
        try:
            rep.note(f"creating the {human_size(sectors * SECTOR_SIZE)} image {path}")
            t = ImageTarget.create(path, sectors * SECTOR_SIZE)
            created = True
            with t:
                rep.step(f"Writing the {opts.layout} partition table", "partition", 14)
                write_partition_table(t, plan, opts.fs)
                rep.step(f"Creating the {opts.fs} data partition (label {label})", "format-data", 20)
                if opts.fs == "ntfs":
                    cfg = _ntfs_on_image(t, plan, label, tmp, cfg)
                    mem = _build_esp(plan, dist, cfg, esp_id)
                else:
                    _format_data(t, plan, opts.fs, label, serial, _esp_timestamp(dist))
                _write_esp_and_boot(t, plan, mem, writes, rep, (30, 82, 85), flush_every=None)
                rep.step("Flushing the image file", "flush", 90)
                t.flush()
            rep.step("Checking what was written", "verify-write", 96)
            with ImageTarget(path, writable=False) as t:
                d = _verify_install(t, path, cfg, plan)
        except BaseException:
            if created:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            raise
    _done_line(rep, path, cfg, dist)
    return d


def install_device(device: str, opts: InstallOptions, rep: Reporter) -> dict:
    """Make the whole disk `device` a beast-booter drive. Returns `info` of it."""
    rep.start("install", device)
    with _invalid_argument():
        label = check_data_label(opts.label, opts.fs)
    backend = get_backend()
    with tempfile.TemporaryDirectory(prefix="beast-booter-") as tmp:
        dist = _verify_dist(opts.dist_dir, tmp, rep, 2)
        rep.step(f"Checking that {device} is safe to erase", "check-target", 5)
        disk = backend.get_disk(device)
        with _watch_device(backend, disk, "install", rep) as watch:
            d, cfg = _install_on(backend, disk, dist, opts, label, rep, watch)
    _done_line(rep, disk.id, cfg, dist)
    return d


def _install_on(backend, disk, dist: Dist, opts: InstallOptions, label: str, rep: Reporter,
                watch: _DeviceWatch) -> tuple[dict, DeviceConfig]:
    backend.check_safe(disk, allow_fixed=opts.allow_fixed)
    plan = make_plan(disk.size // SECTOR_SIZE, opts.layout)
    writes = boot_writes(plan, dist.boot_img, dist.core_img)
    ntfs = opts.fs == "ntfs"
    if ntfs:
        _ntfs_supported(backend.name)
    cfg, serial = _new_config(opts, label)
    esp_id = _new_serial()
    mem = _build_esp(plan, dist, cfg, esp_id)  # fails here, not half-way, if the files do not fit
    if not opts.yes:
        _confirm_device(disk, f"ALL DATA on {disk.id} will be destroyed.")
    t, _ = _prepare_and_open(backend, disk, rep, 8, None, watch)
    with t:
        watch.phase = "writing"
        rep.step(f"Writing the {opts.layout} partition table to {disk.id}", "partition", 12)
        _wipe_old_tables(t)
        write_partition_table(t, plan, opts.fs)
        if not ntfs:
            rep.step(f"Creating the {opts.fs} data partition (label {label})", "format-data", 18)
            _format_data(t, plan, opts.fs, label, serial, _esp_timestamp(dist))
            _write_esp_and_boot(t, plan, mem, writes, rep, (28, 80, 84), flush_every=DEVICE_FLUSH_EVERY)
        rep.step("Flushing data to the drive", "flush", 14 if ntfs else 88)
        t.flush()
    if ntfs:
        # NTFS is made by the OS's formatter on the partition, which must exist first.
        rep.step("Letting the system re-read the drive", "rescan", 15)
        backend.rescan(disk)
        rep.step(f"Creating the ntfs data partition (label {label})", "format-data", 18)
        backend.format_ntfs(disk, DATA_PART_INDEX, label)
        t, _ = _prepare_and_open(backend, disk, rep, 26, _boot_area_and_esp(plan), watch)
        with t:
            _drop_cache(backend, t)
            _check_table_matches(_read_table(t, disk.id), plan)
            cfg = _with_ntfs_uuid(cfg, t.read(plan.data.offset, SECTOR_SIZE))
            mem = _build_esp(plan, dist, cfg, esp_id)
            _write_esp_and_boot(t, plan, mem, writes, rep, (28, 80, 84), flush_every=DEVICE_FLUSH_EVERY)
            rep.step("Flushing data to the drive", "flush", 88)
            t.flush()
    watch.phase = "written"
    rep.step("Letting the system re-read the drive", "rescan", 92)
    _rescan(backend, disk, rep, watch)
    rep.step("Checking what was written", "verify-write", 96)
    with backend.open_raw(disk, writable=False) as t:
        _drop_cache(backend, t)
        return _verify_install(t, disk.id, cfg, plan), cfg


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


@dataclass
class _DriveState:
    table: PartTable
    plan: DiskPlan
    marker: dict
    cfg: DeviceConfig
    esp_volume_id: int
    keep: dict  # ESP path -> bytes: grub/grubenv and beast-net/firmware/**


def _read_drive_state(t, where: str, rep: Reporter, records: _UpdateRecords | None = None) -> _DriveState:
    try:
        table, plan, vol, marker = read_drive_esp(t, where)
    except BeastError:
        st = _interrupted_state(t, where, rep, records)
        if st is None:
            raise
        return st
    if records is not None:  # the ESP is complete: an update finished since any record was made
        records.remove(table, plan, t.size)
    cfg_text = read_esp_text(vol, DEVICE_CFG_PATH)
    old_cfg = DeviceConfig.parse(cfg_text) if cfg_text else None
    cfg = _reconcile_config(old_cfg, probe_fs(t, plan.data.offset), marker, table.label, rep)
    return _DriveState(table, plan, marker, cfg, vol.volume_id, read_kept_files(vol, rep))


def _interrupted_state(t, where: str, rep: Reporter, records: _UpdateRecords | None) -> _DriveState | None:
    """The state of a drive whose last update stopped while the ESP was written
    (our partition layout, an all-zero ESP boot sector: see _write_esp_and_boot),
    or None if it is not one. With the record the update saved on this computer
    (and nothing written to the drive since, as far as can be seen), everything
    is carried over as planned; without, the ESP is rebuilt from partition 1
    (grubenv and firmware packs are lost, with a warning)."""
    try:
        table = _read_table(t, where)
        plan = make_plan(t.size // SECTOR_SIZE, table.label)
        _check_table_matches(table, plan)
        if any(t.read(plan.esp.offset, SECTOR_SIZE)):
            return None
    except BeastError:
        return None
    probe = probe_fs(t, plan.data.offset)
    saved = records.load(table, plan, t.size) if records is not None else None
    if saved is not None:
        stale = saved.stale_for(t, probe.get("UUID"))
        if stale:
            rep.warn(f"the copy of {where}'s settings saved on this computer ({saved.when}) is not used: {stale}")
            records.remove(table, plan, t.size)
        else:
            rep.warn(f"the last update of {where} ({saved.when}) did not finish; finishing it now with the settings "
                     "and files it saved on this computer")
            return _DriveState(table, plan, saved.marker, saved.cfg, saved.esp_volume_id, saved.keep)
    install_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "beast-booter:" + _UpdateRecords.key(table, plan, t.size)))
    rep.warn(f"the boot partition of {where} is incomplete (an update did not finish); it is rebuilt. Its GRUB "
             "settings and firmware packs could not be recovered on this computer: add the packs you need again")
    if fs_name(probe) in FILESYSTEMS and probe.get("UUID"):
        cfg = _reconcile_config(None, probe, {"install_id": install_id}, table.label, _quiet())
    else:
        rep.warn("the filesystem on partition 1 was not recognised, so the new device.cfg has placeholder values; "
                 "the boot menu then looks for partition 1 itself")
        cfg = DeviceConfig(install_id=install_id, layout=table.label, data_fs=FILESYSTEMS[0], data_uuid="unknown",
                           data_uuid_linux="unknown", data_label="", serial=False)
    return _DriveState(table, plan, {}, cfg, 0, {})


BOOT_AREA = DATA_START_LBA * SECTOR_SIZE  # what update writes outside the ESP lies before partition 1
RECORD_MAX_AGE = 30 * 24 * 3600


def _sha(data) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class _Record:
    marker: dict
    cfg: DeviceConfig
    esp_volume_id: int
    keep: dict
    when: str
    data_uuid: str
    boot_area: tuple  # sha256 of the boot area before and after the update's boot code

    def stale_for(self, t, data_uuid: str | None) -> str | None:
        """Why this record no longer fits the drive (None: it does)."""
        if data_uuid and self.data_uuid not in (data_uuid, "unknown"):
            return f"partition 1 changed since (UUID {self.data_uuid} -> {data_uuid})"
        if _sha(t.read(0, BOOT_AREA)) not in self.boot_area:
            return "the drive was written since (its boot code changed)"
        return None


class _UpdateRecords:
    """While update writes a drive, a copy of what it carries over (marker,
    device.cfg, ESP volume id, grub/grubenv, firmware packs) is kept on this
    computer, in `directory` (backend.state_dir(); None: not kept), one JSON file
    per drive, named after what identifies the drive while its ESP cannot be
    read: the partition table's disk id, layout and geometry, and the disk size.
    If the write is interrupted, the next update of that drive finds the record
    (_interrupted_state). A record is removed once the drive's ESP is complete
    again, and records older than RECORD_MAX_AGE are pruned."""

    VERSION = 2

    def __init__(self, directory: str | None):
        self.dir = os.path.join(directory, "update-recovery") if directory else None

    @classmethod
    def for_backend(cls, backend) -> _UpdateRecords:
        get = getattr(backend, "state_dir", None) if backend is not None else None
        try:
            return cls(get() if get is not None else None)
        except Exception:
            return cls(None)

    @staticmethod
    def key(table: PartTable, plan: DiskPlan, disk_size: int) -> str:
        ident = f"{table.label}|{table.disk_id}|{disk_size}|{plan.esp.start}|{plan.esp.size}|{plan.data.start}"
        return _sha(ident.encode("utf-8"))[:32]

    def path(self, table: PartTable, plan: DiskPlan, disk_size: int) -> str | None:
        return os.path.join(self.dir, f"update-{self.key(table, plan, disk_size)}.json") if self.dir else None

    def save(self, st: _DriveState, t, writes, where: str, rep: Reporter) -> None:
        path = self.path(st.table, st.plan, t.size)
        if path is None:
            return
        assert self.dir is not None
        boot = bytearray(t.read(0, BOOT_AREA))
        before = _sha(boot)
        for offset, data in writes:
            if offset + len(data) <= BOOT_AREA:
                boot[offset:offset + len(data)] = data
        rec = {
            "v": self.VERSION, "where": where, "saved": time.strftime("%Y-%m-%d %H:%M:%S"),
            "key": self.key(st.table, st.plan, t.size), "data_uuid": st.cfg.data_uuid_linux,
            "boot_area": [before, _sha(boot)],
            "marker": st.marker, "device_cfg": st.cfg.render(), "esp_volume_id": st.esp_volume_id,
            "keep": {k: base64.b64encode(v).decode("ascii") for k, v in st.keep.items()},
        }
        tmp = path + ".tmp"
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            self._prune()
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(rec, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError as e:
            for leftover in (tmp, path):  # an older record of this drive must not be used later either
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
            rep.warn(f"could not keep a copy of the drive's settings on this computer ({e.strerror or e}); "
                     "if this update is interrupted, the next one cannot carry the firmware packs over")

    def _prune(self) -> None:
        assert self.dir is not None
        cutoff = time.time() - RECORD_MAX_AGE
        for name in os.listdir(self.dir):
            p = os.path.join(self.dir, name)
            try:
                if name.startswith("update-") and os.stat(p).st_mtime < cutoff:
                    os.unlink(p)
            except OSError:
                pass

    def load(self, table: PartTable, plan: DiskPlan, disk_size: int) -> _Record | None:
        path = self.path(table, plan, disk_size)
        if path is None or not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                rec = json.load(f)
            if rec.get("v") != self.VERSION or rec.get("key") != self.key(table, plan, disk_size):
                return None
            if os.stat(path).st_mtime < time.time() - RECORD_MAX_AGE:
                return None
            return _Record(
                marker=dict(rec.get("marker") or {}), cfg=DeviceConfig.parse(rec["device_cfg"]),
                esp_volume_id=int(rec.get("esp_volume_id") or 0),
                keep={k: base64.b64decode(v) for k, v in rec.get("keep", {}).items()},
                when=str(rec.get("saved", "?")), data_uuid=str(rec.get("data_uuid") or ""),
                boot_area=tuple(rec.get("boot_area") or ()),
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError, BeastError):
            return None

    def remove(self, table: PartTable, plan: DiskPlan, disk_size: int) -> None:
        path = self.path(table, plan, disk_size)
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def _warn_firmware_tag(keep: dict[str, bytes], dist: Dist, rep: Reporter) -> None:
    """Installed packs stay across update; say so when the new boot files'
    catalog pins another linux-firmware tag than the packs were made for."""
    raw = keep.get(FIRMWARE_INSTALLED_PATH)
    catalog = os.path.join(dist.esp_dir, "beast-net", "catalog.json")
    if raw is None or not os.path.isfile(catalog):
        return
    try:
        packs = json.loads(raw).get("packs") or []
        with open(catalog, encoding="utf-8") as f:
            tag = json.load(f)["source"]["tag"]
        old = sorted({p.get("id", "?") for p in packs if p.get("catalog_tag") != tag})
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        return
    if old:
        rep.warn(f"firmware packs {', '.join(old)} were made for another linux-firmware tag than the new "
                 f"catalog ({tag}); they are kept, reinstall them if a network adapter does not work")


def update(image: str | None, device: str | None, dist_dir: str, *, yes: bool,
           allow_fixed: bool, rep: Reporter) -> dict:
    """Replace the boot code and the ESP; partition 1 is never written. Returns `info`."""
    where = device if device is not None else image
    assert where is not None
    rep.start("update", where)
    backend = disk = None
    with tempfile.TemporaryDirectory(prefix="beast-booter-") as tmp:
        dist = _verify_dist(dist_dir, tmp, rep, 4)
        rep.step(f"Reading the beast-booter drive {where}", "check-target", 10)
        if device is not None:
            backend = get_backend()
            disk = backend.get_disk(device)
            where = disk.id
        else:
            assert image is not None
            _existing_image(image)
        with _watch_device(backend, disk, "update", rep) as watch:
            d = _update_on(backend, disk, image, where, dist, yes=yes, allow_fixed=allow_fixed, rep=rep,
                           watch=watch)
    rep.step(f"done: {where} updated to beast-booter {dist.version}")
    return d


def _quiet() -> Reporter:
    """A Reporter that says nothing (a second read of what was reported already)."""
    return Reporter(quiet=True, stream=io.StringIO())


def _update_on(backend, disk, image: str | None, where: str, dist: Dist, *, yes: bool, allow_fixed: bool,
               rep: Reporter, watch: _DeviceWatch) -> dict:
    records = _UpdateRecords.for_backend(backend)
    if disk is not None:
        backend.check_safe(disk, allow_fixed=allow_fixed)
        reader = backend.open_raw(disk, writable=False)
    else:
        assert image is not None
        reader = ImageTarget(image, writable=False)
    with reader as t:
        _drop_cache(backend, t)  # nothing cached from before the drive was last written is used
        st = _read_drive_state(t, where, rep, records)
    plan = st.plan
    writes = boot_writes(plan, dist.boot_img, dist.core_img)
    mem = _build_esp(plan, dist, st.cfg, st.esp_volume_id or _new_serial(), st.keep)  # ESP volume id kept
    old_version = st.marker.get("version", "unknown")
    rep.step(f"updating {where}: {old_version} -> {dist.version} ({plan.layout}, keeps partition 1)")
    packs = sorted(k for k in st.keep if k.lower().endswith(".cpio"))
    if packs:
        rep.note(f"keeping {len(packs)} installed firmware pack(s) and grub/grubenv")
        _warn_firmware_tag(st.keep, dist, rep)
    if disk is not None and not yes:
        _confirm_device(disk, "The boot files will be replaced; partition 1 (your files) is not touched.")
    def reread(t) -> _DriveState:
        # Read the drive again now that nothing has it mounted, past the page cache:
        # what is written is built from the drive as it is now.
        _drop_cache(backend, t)
        return _read_drive_state(t, where, _quiet(), records)

    if disk is not None:
        writer, fresh = _prepare_and_open(backend, disk, rep, 18, _boot_area_and_esp(plan), watch, check=reread)
    else:
        writer = GuardedTarget(ImageTarget(image, writable=True), _boot_area_and_esp(plan))
        fresh = reread(writer)
    with writer as t:
        if (fresh.table, fresh.plan) != (st.table, st.plan):
            raise BeastError(f"the partition table of {where} changed while it was being read; run update again")
        if fresh != st:
            rep.note("the boot partition changed since it was first read; using what is on it now")
            st = fresh
            mem = _build_esp(plan, dist, st.cfg, st.esp_volume_id or _new_serial(), st.keep)
        records.save(st, t, writes, where, rep)
        watch.phase = "writing"
        _write_esp_and_boot(t, plan, mem, writes, rep, (25, 80, 84),
                            flush_every=DEVICE_FLUSH_EVERY if disk is not None else None)
        rep.step("Flushing data to the drive" if disk is not None else "Flushing the image file", "flush", 88)
        t.flush()
        watch.phase = "written"
    if disk is not None:
        rep.step("Letting the system re-read the drive", "rescan", 92)
        _rescan(backend, disk, rep, watch)
    rep.step("Checking what was written", "verify-write", 96)
    with (backend.open_raw(disk, writable=False) if disk is not None else ImageTarget(image, writable=False)) as t:
        _drop_cache(backend, t)
        d = _read_info(t, where)
        vol = _open_esp(t, plan.esp.offset, where)
        marker = _read_marker(vol, where)
        if (d["install_id"], marker.get("version")) != (st.cfg.install_id, dist.version):
            raise BeastError(f"{where}: the ESP read back is not the one just written", code="verify-failed")
        for path, data in st.keep.items():
            if not vol.exists(path) or vol.read_file(path) != data:
                raise BeastError(f"{where}: {path} was not carried over by the update", code="verify-failed")
    records.remove(st.table, plan, d["disk_sectors"] * SECTOR_SIZE)
    return d


def _reconcile_config(old: DeviceConfig | None, probe: dict, marker: dict, layout: str,
                      rep: Reporter) -> DeviceConfig:
    """Keep device.cfg values; follow partition 1 if it was reformatted since install."""
    fs = fs_name(probe) if probe else None
    linux_uuid = probe.get("UUID") if probe else None
    found = fs in FILESYSTEMS and bool(linux_uuid)
    if old is None:
        if not found:
            raise BeastError("device.cfg is missing and partition 1 has no supported filesystem")
        rep.warn("device.cfg was missing; recreating it from partition 1")
        return DeviceConfig(
            install_id=marker.get("install_id") or str(uuid.uuid4()), layout=layout, data_fs=fs,
            data_uuid=grub_uuid(linux_uuid), data_uuid_linux=linux_uuid,
            data_label=probe.get("LABEL", ""), serial=False,
        )
    cfg = old
    if cfg.layout != layout:
        rep.warn(f"device.cfg says layout {cfg.layout}, the disk is {layout}; using {layout}")
        cfg = replace(cfg, layout=layout)
    if not found:
        rep.warn("could not identify the filesystem on partition 1; keeping the device.cfg values")
        return cfg
    # A label that could not be read (NTFS with an unreadable MFT) is not a change.
    now = (fs, linux_uuid, probe.get("LABEL", cfg.data_label))
    was = (cfg.data_fs, cfg.data_uuid_linux, cfg.data_label)
    if now != was:
        rep.warn(f"partition 1 changed since install ({' '.join(was)} -> {' '.join(now)}); updating device.cfg")
        cfg = replace(cfg, data_fs=fs, data_uuid=grub_uuid(linux_uuid), data_uuid_linux=linux_uuid,
                      data_label=now[2])
    return cfg


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def _read_info(t, where: str) -> dict:
    table = _read_table(t, where)
    data = table.entries.get(DATA_PART_INDEX)
    esp = table.entries.get(ESP_PART_INDEX)
    if data is None or esp is None:
        raise BeastError(f"{where} is not a beast-booter drive (partition 1 or 2 is missing)")
    vol = _open_esp(t, esp.start * SECTOR_SIZE, where)
    marker = _read_marker(vol, where)
    cfg_text = read_esp_text(vol, DEVICE_CFG_PATH)
    cfg = parse_set_lines(cfg_text) if cfg_text else {}
    version_cfg = parse_set_lines(read_esp_text(vol, VERSION_CFG_PATH) or "")
    fs, fs_uuid, label = cfg.get("bb_data_fs"), cfg.get("bb_data_uuid_linux"), cfg.get("bb_data_label")
    if not cfg:
        probe = probe_fs(t, data.start * SECTOR_SIZE)
        fs, fs_uuid, label = fs_name(probe) if probe else None, probe.get("UUID"), probe.get("LABEL")
    return {
        "layout": table.label,
        "layout_version": marker_layout_version(marker),
        "version": version_cfg.get("bb_version") or marker.get("version"),
        "build_id": version_cfg.get("bb_build_id") or None,
        "install_id": cfg.get("bb_install_id") or marker.get("install_id"),
        "disk_sectors": t.size // SECTOR_SIZE,
        "bios_core_lba": read_core_lba(t.read(0, SECTOR_SIZE)),
        "data": {"index": data.index, "start_lba": data.start, "size_lba": data.size,
                 "fs": fs, "uuid": fs_uuid, "label": label},
        "esp": {"index": esp.index, "start_lba": esp.start, "size_lba": esp.size},
    }


def info(image: str | None, device: str | None) -> dict:
    if device is not None:
        backend = get_backend()
        disk = backend.get_disk(device)
        where, t = disk.id, backend.open_raw(disk, writable=False)
    else:
        assert image is not None
        if os.path.exists(image) and not stat.S_ISREG(os.stat(image).st_mode):
            raise BeastError(f"{image} is not a regular file; use --device for block devices")
        where, t = image, ImageTarget(image, writable=False)
    with t:
        return _read_info(t, where)


def format_info(d: dict, where: str) -> str:
    data, esp = d["data"], d["esp"]
    return "\n".join([
        f"beast-booter drive: {where}",
        f"  version:     {d['version']}",
        f"  build:       {d.get('build_id') or 'unknown'}",
        f"  install id:  {d['install_id']}",
        f"  layout:      {d['layout']} (beast-booter layout version {d.get('layout_version')})",
        f"  disk:        {d['disk_sectors']} sectors ({human_size(d['disk_sectors'] * SECTOR_SIZE)})",
        f"  BIOS core:   LBA {d['bios_core_lba']}",
        f"  partition {data['index']}: data, LBA {data['start_lba']} + {data['size_lba']} "
        f"({human_size(data['size_lba'] * SECTOR_SIZE)}), {data['fs']}, UUID {data['uuid']}, label {data['label']}",
        f"  partition {esp['index']}: ESP,  LBA {esp['start_lba']} + {esp['size_lba']} "
        f"({human_size(esp['size_lba'] * SECTOR_SIZE)})",
    ])


# ---------------------------------------------------------------------------
# list-devices
# ---------------------------------------------------------------------------


EXTERNAL_BUSES = ("usb", "sd")


def disk_problem(disk) -> str | None:
    """Why `install --device` (without --allow-fixed-disk) would refuse this disk, or None.

    Disks on an external bus (USB, SD) are eligible even when they report
    themselves as fixed (USB SSDs and hard disks do), as in the platform
    backends; internal buses need --allow-fixed-disk. System, read-only and
    in-use disks are always refused (check_common, and the backend's check_safe
    at install time)."""
    if disk.bus in EXTERNAL_BUSES and not disk.removable:
        disk = dataclasses.replace(disk, removable=True)
    try:
        check_common(disk, allow_fixed=False)
    except BeastError as e:
        msg = str(e)
        return msg.removeprefix("refusing: ")
    if disk.size < MIN_DISK_MIB * MIB:
        return f"too small ({human_size(disk.size)}; beast-booter needs at least {MIN_DISK_MIB} MiB)"
    return None


def list_devices(include_all: bool = False, check_installed: bool = False) -> dict:
    """The `list-devices --json` object (interfaces.py). check_installed: also
    report which beast-booter each drive has (installed.py; no admin rights
    needed, may mount a boot partition read-only for a moment)."""
    from . import __version__
    from .installed import assess

    backend = get_backend()
    disks = backend.list_disks(include_fixed=include_all)
    rows = []
    for disk in disks:
        reason = disk_problem(disk)
        row = dataclasses.asdict(disk)
        row["mountpoints"] = list(row["mountpoints"])
        row["partitions"] = list(row["partitions"])
        row["eligible"] = reason is None
        row["reason"] = reason
        if check_installed:
            probe = backend.probe_installed(disk)
            row["installed"] = None
            if probe is not None:
                f = assess(probe.installed, __version__)
                row["installed"] = {"version": probe.installed.version if probe.installed else None,
                                    "build_id": probe.installed.build_id if probe.installed else None,
                                    "state": f.state, "summary": f.summary, "note": probe.note}
        rows.append(row)
    return {"v": 1, "platform": backend.name, "elevated": bool(backend.is_elevated()), "disks": rows}


def format_devices(d: dict, include_all: bool) -> str:
    disks = d["disks"]
    if not disks:
        hint = "" if include_all else " (--all also lists fixed and system disks)"
        return f"No removable drives found{hint}."
    rows = [("DEVICE", "SIZE", "BUS", "TYPE", "MODEL", "STATUS")]
    for r in disks:
        status = "eligible" if r["eligible"] else f"not eligible: {r['reason']}"
        if r.get("installed"):
            status += f"; {r['installed']['summary']}"
        rows.append((r["id"], human_size(r["size"]), r["bus"], "removable" if r["removable"] else "fixed",
                     r["model"] or "-", status))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row[:-1], widths)) + "  " + row[-1] for row in rows]
    if not d["elevated"]:
        lines.append("(writing a drive needs administrator rights: run install as root / Administrator, "
                     "or use the beast-booter window)")
    return "\n".join(line.rstrip() for line in lines)
