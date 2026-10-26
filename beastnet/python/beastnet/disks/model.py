"""Disk tools data model (docs/DISK_TOOLS.md section 2). Shared by every part:
change it only through the lead."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Transport(str, Enum):
    NVME = "nvme"
    SATA = "sata"      # also PATA/IDE through libata
    SAS = "sas"        # incl. hardware RAID virtual disks
    USB = "usb"
    VIRTIO = "virtio"
    MMC = "mmc"
    OTHER = "other"


class StackKind(str, Enum):
    MD = "md"                  # Linux md, native metadata 0.90 / 1.x
    IMSM = "imsm"              # Intel RST / VROC (mdadm container + volumes)
    DDF = "ddf"                # SNIA DDF (some LSI/Adaptec firmware RAID)
    LVM = "lvm"
    LUKS = "luks"
    BITLOCKER = "bitlocker"
    BTRFS = "btrfs"            # multi-device btrfs
    ZFS = "zfs"
    LDM = "ldm"                # Windows dynamic disks
    STORAGE_SPACES = "storage-spaces"
    AMD_RAID = "amd-raid"      # AMD RAIDXpert2: detected by heuristics only
    FAKERAID_OTHER = "fakeraid"  # Promise/NVIDIA/JMicron/SiI/VIA/HPT signatures
    UNKNOWN = "unknown"        # members the user groups by hand for reconstruction


class Support(str, Enum):
    ASSEMBLE = "assemble"        # a Linux tool can start it read-only
    RECONSTRUCT = "reconstruct"  # only the generic reconstruction can read it
    DETECT = "detect"            # we can say what it is; image the members raw
    NEEDS_PACK = "needs-pack"    # assemble once an optional pack is installed (ZFS)


class StackState(str, Enum):
    CLEAN = "clean"
    DEGRADED = "degraded"        # readable, redundancy missing
    INCOMPLETE = "incomplete"    # too few members to read
    UNKNOWN = "unknown"


@dataclass
class Partition:
    id: str                      # kernel name, e.g. "sda2", "nvme0n1p3"
    path: str                    # "/dev/sda2"
    number: int
    start: int                   # bytes from the start of the disk
    size: int                    # bytes
    type: str = ""               # GPT type GUID or "0x07" style MBR type
    fs_type: str = ""            # blkid TYPE ("ntfs", "linux_raid_member", ...)
    label: str = ""
    uuid: str = ""


@dataclass
class Disk:
    id: str                      # kernel name, e.g. "sda", "nvme0n1"
    path: str                    # "/dev/sda"
    model: str
    serial: str                  # "" if the device reports none (then refuse writes)
    wwn: str
    size: int                    # bytes
    logical_sector: int
    physical_sector: int
    transport: Transport
    rotational: bool
    removable: bool
    is_boot_stick: bool = False  # the BeastBoot drive the helper runs from
    partitions: list[Partition] = field(default_factory=list)
    fs_type: str = ""            # blkid TYPE of the whole disk (members without a table)

    def identity(self) -> tuple[str, str, int]:
        """What must not change between plan and write (serial, wwn, size)."""
        return (self.serial, self.wwn, self.size)


@dataclass
class Member:
    device: str                  # "/dev/sdb" or "/dev/sdb1"
    disk_id: str                 # owning Disk.id
    index: int | None = None     # slot / order in the array when the metadata says
    state: str = ""              # "active", "spare", "faulty", "missing", ...


@dataclass
class Stack:
    id: str                      # "<kind>:<uuid or name>"
    kind: StackKind
    members: list[Member]
    support: Support
    level: str = ""              # "raid0", "raid1", "raid5", "raid10", "linear", "mirror", ...
    state: StackState = StackState.UNKNOWN
    name: str = ""               # array/VG/pool name as the metadata calls it
    chunk: int | None = None     # bytes, when known
    notes: list[str] = field(default_factory=list)  # plain-words facts for the UI


class VolumeKind(str, Enum):
    DISK = "disk"
    PARTITION = "partition"
    MD = "md"
    LV = "lv"
    CRYPT = "crypt"
    OVERLAY_ARRAY = "overlay-array"  # a reconstructed array on overlays
    ZFS_DATASET = "zfs-dataset"
    LDM = "ldm"


@dataclass
class Volume:
    id: str                      # disk/partition kernel name, "md127", "dm-3", ...
    path: str                    # block device path
    kind: VolumeKind
    size: int
    readonly: bool = True
    fs_type: str = ""
    label: str = ""
    from_stack: str | None = None  # Stack.id it came from
    disk_ids: list[str] = field(default_factory=list)  # every physical disk it reads


@dataclass
class Inventory:
    disks: list[Disk]
    stacks: list[Stack]
    volumes: list[Volume]        # every copyable thing (disks and partitions included)

    def disk(self, ref: str) -> Disk | None:
        """By kernel id or serial (script plans use serials)."""
        for d in self.disks:
            if ref in (d.id, d.serial) and ref:
                return d
        return None


class HealthStatus(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass
class Health:
    disk_id: str
    status: HealthStatus
    summary: str                 # one plain-words line for the list screen
    power_on_hours: int | None = None
    reallocated: int | None = None
    pending: int | None = None
    wear_percent: int | None = None      # NVMe "percentage used"
    temperature_c: int | None = None
    raw: dict = field(default_factory=dict)  # smartctl --json output, for "details"


@dataclass
class Candidate:
    """One reconstruction hypothesis (docs/DISK_TOOLS.md section 3)."""
    level: str                   # "raid0", "raid1", "raid5", "raid6", "raid10", "linear"
    chunk: int                   # bytes
    order: list[str]             # member devices in array order ("" = missing member)
    data_offset: int             # bytes from the start of each member
    layout: str = ""             # md layout name for raid5/6 ("left-symmetric", ...)
    member_size: int | None = None  # bytes of each member used, None = to the end
    score: float = 0.0           # higher is better, from validate()
    evidence: list[str] = field(default_factory=list)  # why (signatures found, parity checks)


class CopyKind(str, Enum):
    CLONE = "clone"              # volume -> disk/partition
    IMAGE = "image"              # volume -> image file
    RESTORE = "restore"          # image file -> disk/partition


@dataclass
class CopyPlan:
    kind: CopyKind
    source: str                  # volume path or image file path
    target: str                  # device path or image file path
    size: int                    # bytes that will be read
    mapfile: str                 # ddrescue mapfile (on the stick or a third disk)
    target_identity: tuple[str, str, int] | None = None  # Disk.identity() checked again before writing
    source_disk_ids: list[str] = field(default_factory=list)
    erases: str = ""             # plain words: what on the target is overwritten ("" for image files)
    commands: list[list[str]] = field(default_factory=list)  # what will run, for the plan screen
    verify: bool = True          # hash/read-back after the copy


@dataclass
class CopyProgress:
    done: int                    # bytes rescued or copied
    total: int
    errors: int                  # bad areas so far
    rate: float                  # bytes/second
    phase: str = ""              # ddrescue pass name ("copying", "trimming", "scraping", "retrying")


@dataclass
class CopyResult:
    ok: bool
    bytes: int
    errors: int                  # bytes not recovered (0 = complete copy)
    sha256: str = ""             # of the image / target range, when verify ran
    resumable: bool = False      # stopped early; run the same plan again to resume
    notes: list[str] = field(default_factory=list)
