"""beast-boot on-disk layout contract.

This module is the single source of truth for where things live on a
beast-boot drive. The installer, the build script and the end-to-end tests
all rely on these numbers; docs/ARCHITECTURE.md describes them in prose.
Changing a value here is a format change: bump LAYOUT_VERSION.

Drive layout (both partition table styles use the same partition numbers):

  partition 1  DATA  exFAT (default) / FAT32 / NTFS  - normal storage, ISOs go here
  partition 2  ESP   FAT32, 512 MiB, at the end of the disk - boot files, the
                     beast-net helper and its optional firmware packs
  partition 3  BIOS boot (GPT only), LBA 34..2047 - holds GRUB core.img

MBR ("msdos") layout:
  LBA 0              MBR: GRUB boot.img code (440 bytes) + partition table
  LBA 1 .. 2047      GRUB core.img (BIOS), in the gap before partition 1
  LBA 2048 ..        partition 1 (DATA), active/boot flag set
  last 512 MiB       partition 2 (ESP), type 0xEF, end aligned down to 1 MiB

GPT layout:
  LBA 0              protective MBR with GRUB boot.img code, PMBR entry marked active
  LBA 1 .. 33        primary GPT
  LBA 34 .. 2047     partition 3 (BIOS boot), holds core.img
  LBA 2048 ..        partition 1 (DATA)
  before backup GPT  partition 2 (ESP), end aligned down to 1 MiB
  last 33 LBAs       backup GPT

Layout versions (written to the ESP marker as layout_version=N):

  1  64 MiB FAT16 ESP (0.1 development builds only; never released)
  2  512 MiB FAT32 ESP, room for beast-net (~52 MB) and firmware packs
     (up to ~165 MiB); the installer creates grub/grubenv

`update` only works on a drive of the current layout version (it never moves
partitions, so partition 1 stays untouched); an older layout needs a reinstall.
"""

from __future__ import annotations

LAYOUT_VERSION = 2

SECTOR_SIZE = 512
MIB = 1024 * 1024
MIB_SECTORS = MIB // SECTOR_SIZE  # 2048

# Partition table styles. "msdos" matches GRUB's partmap name.
LAYOUTS = ("msdos", "gpt")
DEFAULT_LAYOUT = "msdos"

# Partition numbers (1-based, as the OS and GRUB see them).
DATA_PART_INDEX = 1
ESP_PART_INDEX = 2
BIOS_BOOT_PART_INDEX = 3  # GPT only

# Partition 1 (data) always starts at 1 MiB.
DATA_START_LBA = 2048

# Partition 2 (ESP)
ESP_SIZE_MIB = 512  # layout 2 (layout 1: 64)
ESP_SIZE_SECTORS = ESP_SIZE_MIB * MIB_SECTORS
ESP_FAT_BITS = 32  # mkfs.fat -F 32 (layout 1: FAT16); 4 KiB clusters at 512 MiB
ESP_LABEL = "BEAST-EFI"  # FAT label, max 11 chars

# Data partition filesystems
FILESYSTEMS = ("exfat", "fat32", "ntfs")
DEFAULT_FS = "exfat"
DATA_LABEL_DEFAULT = "BEASTBOOTER"  # fits FAT (11), exFAT (15) and NTFS limits

# Smallest drive/image we will create: the 512 MiB ESP + ~511 MiB of storage.
MIN_DISK_MIB = 1024

# MBR partition type bytes
MBR_TYPE_DATA = {"exfat": 0x07, "ntfs": 0x07, "fat32": 0x0C}
MBR_TYPE_ESP = 0xEF
MBR_ACTIVE_FLAG = 0x80

# GPT partition type GUIDs
GPT_TYPE_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"  # Microsoft basic data
GPT_TYPE_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"  # EFI System
GPT_TYPE_BIOS_BOOT = "21686148-6449-6E6F-744E-656564454649"  # BIOS boot
GPT_NAME_DATA = "BEAST-DATA"
GPT_NAME_ESP = "BEAST-EFI"
GPT_NAME_BIOS_BOOT = "BEAST-BIOS"
GPT_PRIMARY_SECTORS = 34  # LBA 0..33 (PMBR + header + 128 entries)
GPT_BACKUP_SECTORS = 33  # last 33 LBAs (entries + header)
GPT_BIOS_BOOT_START_LBA = 34
GPT_BIOS_BOOT_END_LBA = DATA_START_LBA - 1  # 2047, inclusive

# Where BIOS core.img is written.
MBR_CORE_LBA = 1
MBR_CORE_MAX_SECTORS = DATA_START_LBA - MBR_CORE_LBA  # 2047
GPT_CORE_LBA = GPT_BIOS_BOOT_START_LBA
GPT_CORE_MAX_SECTORS = GPT_BIOS_BOOT_END_LBA - GPT_BIOS_BOOT_START_LBA + 1  # 2014

# GRUB i386-pc boot.img / diskboot.img patch points
# (grub/include/grub/i386/pc/boot.h and grub-core/boot/i386/pc/diskboot.S).
BOOT_IMG_SIZE = 512
BOOT_IMG_CODE_LEN = 440  # bytes 0..439 are code; 440.. is disk signature + table
BOOT_KERNEL_SECTOR_OFFSET = 0x5C  # u64 LE: LBA of the first core.img sector
BOOT_DRIVE_CHECK_OFFSET = 0x66  # 2 bytes; set to 0x90 0x90 (as grub-install does for disks)
CORE_BLOCKLIST_OFFSET = 0x1F4  # in core.img sector 0: u64 start LBA, u16 sector count, u16 segment
CORE_BLOCKLIST_SEGMENT = 0x820

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

# dist/ is produced by build/build.sh. These paths are relative to dist/.
DIST_MANIFEST = "manifest.json"
DIST_BOOT_IMG = "bios/boot.img"
DIST_CORE_IMG = "bios/core.img"
DIST_ESP_DIR = "esp"  # copied verbatim into the ESP root

# Files that must be present under dist/esp/ (paths inside the ESP).
REQUIRED_ESP_FILES = (
    "EFI/BOOT/BOOTX64.EFI",  # shim, Microsoft-signed
    "EFI/BOOT/mmx64.efi",  # MokManager
    "EFI/BOOT/grubx64.efi",  # beast-boot GRUB, signed with the beast-boot key
    "ENROLL_THIS_KEY_IN_MOKMANAGER.cer",  # DER certificate for MokManager
    "grub/grub.cfg",
    "grub/beast/main.cfg",
    "grub/beast/version.cfg",
    "grub/i386-pc/normal.mod",
)

# Written by the installer into the ESP at install/update time.
DEVICE_CFG_PATH = "grub/beast/device.cfg"
# Marker so tools can recognise a beast-boot ESP. Contains the install id
# and the layout version. On-disk names keep the pre-rename "beast-booter"
# spelling (marker, user config folder, esp/beast-booter/): 0.1.x/0.2.0 drives
# use them, and the app must keep reading and updating those drives.
ESP_MARKER_PATH = "BEAST-BOOTER.ID"
# GRUB environment block (bb_oneshot hand-off from beast-net, docs/BEASTNET.md
# section 4). Created by install; update keeps its contents.
GRUBENV_PATH = "grub/grubenv"
GRUBENV_SIZE = 1024

# beast-net (docs/BEASTNET.md sections 3 and 6). The helper files come from
# dist/esp/beast-net/; the firmware packs are installed by `firmware install`
# and kept by update.
BEASTNET_DIR = "beast-net"
BEASTNET_CATALOG_PATH = "beast-net/catalog.json"
FIRMWARE_DIR = "beast-net/firmware"
FIRMWARE_INSTALLED_PATH = "beast-net/firmware/installed.json"
DIST_CATALOG = DIST_ESP_DIR + "/" + BEASTNET_CATALOG_PATH  # relative to dist/

# Optional user configuration on the DATA partition (GRUB script syntax).
USER_CONFIG_PATH = "beast-booter/config.cfg"
# Directories on the data partition the menu never lists.
DATA_HIDDEN_DIRS = ("beast-booter", "System Volume Information", "$RECYCLE.BIN", "$Extend", "lost+found")
