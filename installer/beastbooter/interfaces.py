"""Contracts for the cross-platform (Linux / Windows / macOS) portable installer.

Owned by the lead. Builders implement these interfaces in their own modules and
must not change this file; propose changes in their report instead.

Design (0.1 portable):

* **No external tools for the disk formats we write.** The partition tables
  (MBR, GPT), the FAT32 ESP (layout 2), FAT32 data partitions and exFAT data partitions
  are written by pure-Python code (parttable.py, fatfs.py, exfatfs.py), so the
  installer behaves identically on every OS and works rootless on image files.
  Linux tools (sfdisk, fsck.fat, fsck.exfat, blkid, mtools) are used only by
  tests, as independent validators.
* **NTFS** is the exception: it is created with the OS's own formatter where one
  exists (Linux mkfs.ntfs, Windows Format-Volume). macOS cannot create NTFS, so
  it is refused there. (GRUB cannot read NTFS under Secure Boot anyway.)
* **Per-OS device access** lives behind PlatformBackend (platforms/linux.py,
  platforms/darwin.py, platforms/windows.py): listing disks, safety checks,
  unmounting/locking volumes, raw sector I/O, re-reading the partition table,
  and running a command with admin rights.
* **Privilege separation.** The GUI never runs as root/admin. For a device
  operation it starts the CLI elevated (`run_elevated`) with `--progress-file`,
  and follows the JSON-lines progress written there.
* **Portable packaging.** Each OS gets a folder/archive with a relocatable
  CPython (python-build-standalone, pinned + checksummed), the beastbooter
  sources as plain .py files, the boot files (dist/ + SBOM), and a launcher.
  Nothing is installed; unpack and run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Block I/O  (blockio.py implements ImageTarget; backends implement raw devices)
# ---------------------------------------------------------------------------


@runtime_checkable
class BlockTarget(Protocol):
    """A disk image file or a raw whole-disk device, addressed in bytes.

    write() accepts any offset/length. Implementations whose underlying device
    needs sector-aligned I/O (macOS /dev/rdiskN, Windows \\\\.\\PhysicalDriveN)
    do read-modify-write internally. Writers in this package write metadata
    only (quick format): untouched areas keep whatever they held.
    """

    sector_size: int  # logical sector size in bytes (only 512 is supported in 0.1)
    size: int  # total size in bytes

    def read(self, offset: int, length: int) -> bytes: ...
    def write(self, offset: int, data: bytes) -> None: ...
    def flush(self) -> None: ...  # durable on return (fsync / FlushFileBuffers)
    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Disk formats  (signatures each module must provide)
# ---------------------------------------------------------------------------
#
# parttable.py
#   def write_partition_table(t: BlockTarget, plan: "plan.DiskPlan", fs: str, *,
#                             disk_signature: int | None = None,
#                             disk_guid: str | None = None,
#                             part_guids: dict[int, str] | None = None) -> None
#       msdos: MBR at LBA 0 (boot code bytes 0..439 left as zero for bootcode.py),
#              data part active, types from layout.MBR_TYPE_DATA / MBR_TYPE_ESP.
#       gpt:   protective MBR (single 0xEE entry, active flag per ARCHITECTURE §3),
#              primary header LBA 1 + 128 entries LBA 2..33, backup entries + header
#              in the last 33 LBAs, CRC32s, names/types from layout.py.
#       Random signature/GUIDs (secrets) when not given; deterministic when given.
#
# fatfs.py
#   def format_fat(t: BlockTarget, offset: int, size: int, *, fat_bits: int,
#                  label: str, volume_id: int, hidden_sectors: int) -> None
#       Quick-format FAT16 or FAT32 in [offset, offset+size) (layout 2: ESP and FAT32 data use FAT32).
#   class FatVolume:  # open an existing FAT12/16/32 volume inside a target
#       def __init__(self, t: BlockTarget, offset: int) -> None
#       label: str; volume_id: int; fat_bits: int
#       def listdir(self, path: str) -> list[DirEntry]
#       def read_file(self, path: str) -> bytes
#       def write_file(self, path: str, data: bytes) -> None   # creates parents, replaces
#       def mkdir(self, path: str) -> None
#       def remove(self, path: str) -> None
#       (long file names read and written; paths use "/", case-insensitive lookup)
#   def build_esp(t: BlockTarget, offset: int, size: int, files: dict[str, bytes], *,
#                 label: str, volume_id: int, hidden_sectors: int) -> None
#       Format FAT32 (layout.ESP_FAT_BITS) and write every file (keys are ESP paths like "EFI/BOOT/BOOTX64.EFI").
#
# exfatfs.py
#   def format_exfat(t: BlockTarget, offset: int, size: int, *, label: str,
#                    volume_serial: int, cluster_size: int | None = None) -> None
#       exFAT per the Microsoft exFAT specification: boot region + backup boot
#       region (with checksum sectors), FAT, allocation bitmap, up-case table,
#       root directory with volume label / bitmap / up-case entries. Cluster size
#       defaults like Windows/mkfs.exfat (e.g. 32 KiB up to 32 GiB, 128 KiB above).
#   class ExfatVolume: same read/write API as FatVolume (write_file may be limited
#       to small files, e.g. /beast-booter/config.cfg), plus label and volume_serial.

if TYPE_CHECKING:
    from .installed import ProbeResult


@dataclass(frozen=True)
class DirEntry:
    name: str
    is_dir: bool
    size: int


def format_volume_id(value: int) -> str:
    """32-bit FAT/exFAT serial as blkid and GRUB print it: 'ABCD-1234'."""
    return f"{(value >> 16) & 0xFFFF:04X}-{value & 0xFFFF:04X}"


# ---------------------------------------------------------------------------
# Platform backends  (platforms/__init__.py: get_backend() -> PlatformBackend)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiskInfo:
    id: str  # what the user passes to --device: /dev/sdb, /dev/disk4, \\.\PhysicalDrive2
    path: str  # raw I/O path: /dev/sdb, /dev/rdisk4, \\.\PhysicalDrive2
    model: str
    size: int  # bytes
    sector_size: int  # logical
    bus: str  # usb | sata | nvme | sd | scsi | virtual | unknown
    removable: bool
    system: bool  # holds the running OS, its boot volume, or swap
    read_only: bool
    mountpoints: tuple[str, ...] = ()
    partitions: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)  # backend-specific details for display


class PlatformBackend(Protocol):
    name: str  # "linux" | "darwin" | "windows"

    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]: ...
    def get_disk(self, device: str) -> DiskInfo: ...  # accepts the id forms above (+ "2" on Windows)
    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None: ...  # raises BeastError
    def prepare(self, disk: DiskInfo) -> None: ...  # unmount / lock + dismount all volumes on it
    def open_raw(self, disk: DiskInfo, *, writable: bool) -> BlockTarget: ...
    def rescan(self, disk: DiskInfo) -> None: ...  # OS re-reads the new partition table
    def partition_path(self, disk: DiskInfo, index: int) -> str: ...  # for native formatters
    def format_ntfs(self, disk: DiskInfo, index: int, label: str) -> None: ...  # BeastError if unsupported
    def is_elevated(self) -> bool: ...
    # Which beast-boot the drive already has (installed.py), WITHOUT administrator
    # rights; may mount the boot partition read-only for a moment (Linux: udisks)
    # and always leaves it as it found it. None: not a beast-boot drive as far
    # as can be seen. Never raises (problems become ProbeResult(None, note)).
    # should_stop: optional callable; when it returns True the probe stops before mounting.
    def probe_installed(self, disk: DiskInfo, *, should_stop=None) -> ProbeResult | None: ...
    def run_elevated(self, argv: list[str]) -> ElevatedProcess: ...  # prompts the user (UAC/polkit/macOS auth)


class ElevatedProcess(Protocol):
    def poll(self) -> int | None: ...  # exit code, or None while running
    def wait(self, timeout: float | None = None) -> int: ...
    def cancel(self) -> None: ...  # best effort


# ---------------------------------------------------------------------------
# CLI additions the GUI relies on (commands.py / cli.py, wired by the lead)
# ---------------------------------------------------------------------------
#
#   beast-boot list-devices [--json] [--all]
#       --all includes fixed/system disks (marked not eligible).
#   beast-boot install ... --progress-file PATH
#   beast-boot update  ... --progress-file PATH
#       Appends JSON lines (schema below) to PATH as work proceeds; stdout/stderr
#       stay as today. --dist also accepts a .zip of a dist/ directory.
#
# list-devices --json:
#   {"v": 1, "platform": "linux", "elevated": false,
#    "disks": [{...DiskInfo fields..., "eligible": true, "reason": null}]}
#
# Progress events (one JSON object per line, "v": 1 in each):
#   {"v":1,"event":"start","action":"install"|"update","target":"<device or image>"}
#   {"v":1,"event":"step","step":"<id>","message":"<human text>","pct":<0-100>}
#        step ids: verify-dist, check-target, prepare, partition, format-data,
#                  write-esp, boot-code, flush, rescan, verify-write
#   {"v":1,"event":"warning","message":"..."}
#   {"v":1,"event":"done","ok":true,"info":{...same object as `info --json`...}}
#   {"v":1,"event":"error","code":"<short id>","message":"<human text>"}
#        e.g. "busy": a volume of the drive could not be unmounted because a program
#        still uses it (the message names the mountpoint and, on Linux, the programs);
#        "device-vanished": the drive stopped responding (no medium, unplugged) while
#        it was prepared or written; the message says to replug it and run the same
#        command again (an interrupted update is finished by the next one)

PROGRESS_SCHEMA_VERSION = 1
PROGRESS_STEPS = (
    "verify-dist", "check-target", "prepare", "partition", "format-data",
    "write-esp", "boot-code", "flush", "rescan", "verify-write",
    # firmware commands (docs/BEASTNET.md section 6)
    "download", "verify-packs", "write-firmware",
)
