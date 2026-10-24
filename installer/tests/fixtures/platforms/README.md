# Platform backend fixtures

Command outputs the platform backends parse, used by `test_x_platforms_*.py`.
They were **written by hand from the documented formats**, not captured on a
real machine (the test host is Linux): field names, value types, key order and
quirks follow Apple's `diskutil` property lists and Windows PowerShell 5.1's
`ConvertTo-Json`. Replace them with real captures when someone runs the
commands below on real hardware; the tests should keep passing.

## darwin/ (Apple silicon Mac, macOS 14)

| File | Command |
|---|---|
| `diskutil-list.plist` | `diskutil list -plist` |
| `diskutil-apfs-list.plist` | `diskutil apfs list -plist` |
| `diskutil-info-root.plist` | `diskutil info -plist /` |
| `diskutil-info-diskN.plist` | `diskutil info -plist diskN` |

Disks: `disk0` internal 500 GB SSD (4096-byte blocks, "Apple Fabric") with
three APFS containers (`disk1` iBoot System Container, `disk3` macOS with the
sealed system snapshot mounted at `/`, `disk2` recovery); `disk4` 32 GB USB
stick (MBR, FAT32 mounted at `/Volumes/STICK`); `disk5` 1 TB USB SSD
(removable = no, internal = no) holding APFS container `disk6`
(`/Volumes/Backups`); `disk7` an attached disk image (virtual).

AppleRAID / CoreStorage member disks are added to these plists inside
`test_x_platforms_darwin.py` (`add_member_disks`).

## windows/ (desktop PC, Windows 11)

The backend runs one PowerShell script that prints these sections (see
`windows.LIST_SCRIPT`):

| File | Command |
|---|---|
| `get-disk.json` | `Get-Disk \| Select-Object Number, FriendlyName, ... \| ConvertTo-Json -Depth 4` |
| `get-partition.json` | `Get-Partition \| Select-Object DiskNumber, PartitionNumber, DriveLetter, ... \| ConvertTo-Json -Depth 4` |
| `get-volume.json` | `Get-Volume \| Select-Object DriveLetter, FileSystemLabel, ... \| ConvertTo-Json -Depth 4` |
| `env.json` | `$env:SystemRoot` and `Win32_PageFileUsage` names |
| `get-disk-single.json`, `get-partition-single.json` | a laptop with one disk / one partition: ConvertTo-Json prints a single object, not an array; this one has the raw numeric enum values (BusType 17 = NVMe) |

Disks: 0 = system NVMe (EFI, MSR, C:, recovery), 1 = SATA HDD with D: (holds
the page file) and a folder-mounted volume `C:\Archive\`, 2 = USB stick E:.
Partitions without a drive letter show `"DriveLetter": "\u0000"` (a [char] 0).
`MbrType` / `GptType` are what MSFT_Partition reports (the other one is null);
the backend uses them to spot dynamic (LDM) disks. `env.json` has
`PageFilesKnown: true` (false would mean neither Win32_PageFileUsage nor the
registry's `ExistingPageFiles` could be read). Dynamic-disk and page-file
variants (a mirrored C:, the `{"value": [...], "Count": n}` wrapper, unknown
page files) are derived from these files inside `test_x_platforms_windows.py`.

## linux/

`mountinfo` (`/proc/self/mountinfo`) and `swaps` (`/proc/swaps`) of an Ubuntu
desktop: NVMe root and ESP, a snap squashfs on a loop device, a swap file, and
a USB stick auto-mounted by udisks at `/media/user/MY STICK`. The sysfs tree
is built by the test itself (realistic device paths under `/sys/devices`),
including loop devices' `loop/backing_file` for live-medium and mounted-ISO cases.
