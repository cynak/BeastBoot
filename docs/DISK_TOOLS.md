# Disk tools (0.3.0): recovery and cloning, RAID-aware

The beast-net helper gains **Disk tools**: see every disk and what is on it,
check health, rescue a failing disk, clone or image disks, partitions and
RAID volumes, and restore an image. It must work with RAIDed devices:

| Storage | How BeastBoot reaches the data |
|---|---|
| Hardware RAID controllers (MegaRAID/PERC, Smart Array, Adaptec, LSI) | their in-tree drivers show each array as one disk |
| Linux md (mdadm 0.90/1.x), Intel RST/VROC (IMSM), SNIA DDF | `mdadm --assemble --readonly` |
| LVM, LUKS/BitLocker, Btrfs, Windows dynamic disks (LDM) | their own tools, read-only |
| ZFS | optional pack built by the desktop app from Canonical's signed packages (never shipped by BeastBoot) |
| AMD RAIDXpert2, Storage Spaces (simple/mirror), unknown or destroyed metadata | **generic reconstruction**: parameters detected from the data, assembled on copy-on-write overlays, validated read-only; manual RAID builder as fallback |

This file is the contract between the parts built in parallel. Code:
`beastnet/python/beastnet/disks/` (model in `model.py`; one module per part).

## 1. Safety rules (non-negotiable)

1. **Sources are read-only.** On entering Disk tools, `guard.protect_all()` sets
   `BLKROSET` on every block device node (disks *and* partitions, also md/dm
   nodes as they appear) and re-applies it after every rescan. Arrays start
   with `--readonly`, LVM activates read-only, LUKS opens `--readonly`, pools
   import `readonly=on`, mounts use `ro,noatime` (+ `norecovery`/`noload`
   where the filesystem has a journal). Nothing starts on its own (no udev).
2. **Reconstruction never writes to members.** Every experiment runs on
   dm-snapshot overlays whose COW lives in RAM (tmpfs, capped); md
   `--create --assume-clean` and `--bitmap=none` only on overlays, resync
   speed set to 0.
3. **Only a confirmed target becomes writable**, after the plan screen and a
   typed confirmation (last 6 characters of the target's serial; the whole
   serial if two disks end the same). The target is re-identified (serial,
   WWN, size) right before writing and opened `O_EXCL` for the whole job.
4. **Refusals** (`disk-refused`, reason shown): the BeastBoot stick itself;
   the source or any member of the source stack; a disk holding the image,
   mapfile or hash list; a disk with a mounted filesystem or an active
   md/dm/LVM/ZFS member; a raw clone or restore onto a smaller disk, or one
   with a different logical sector size; an image destination on FAT32 or the
   ESP (exFAT/NTFS/ext4/xfs only).
5. **Mapfiles** (ddrescue) live on the stick's data partition or a third disk,
   never on source or target; no writable place = refuse to start.
6. **A member clone is not the array**: never offered or labelled as one.
7. Never write keys/passphrases to logs or the stick; never weaken Secure
   Boot (no third-party module, no MOK-signed module).

## 2. Data model (`disks/model.py`)

`Disk` (a whole device: id, path, model, serial, wwn, size, sector sizes,
transport, rotational, removable, `is_boot_stick`) with `Partition`s;
`Stack` (a multi-device or layered structure: kind, members, level, state,
support level) with `Member`s; `Volume` (something that can be copied or
mounted: disk, partition, md array, LV, dm-crypt, overlay array);
`Health`; `Candidate` (one reconstruction hypothesis); `CopyPlan`,
`CopyProgress`, `CopyResult`. Stable ids: disks by kernel name plus
serial; stacks as `<kind>:<uuid or name>`.

## 3. Parts and their API (who owns what)

| Module | Owner | Provides |
|---|---|---|
| `disks/discover.py`, `disks/guard.py`, `disks/health.py`, `disks/probe.py` | discovery | `scan(ctx) -> Inventory`; `protect_all`, `reapply`, `make_writable(disk)`; `read(ctx, disk) -> Health`; stack detection incl. "may be an AMD RAID member" |
| `disks/assemble.py` | discovery | `start(ctx, stack) -> list[Volume]`, `stop(ctx, stack)` for md/IMSM/DDF, LVM, LUKS/BitLocker, Btrfs, LDM, ZFS (if the pack is present) |
| `disks/overlay.py`, `disks/reconstruct.py` | reconstruction | overlays; `detect(ctx, members) -> list[Candidate]`; `build(ctx, members, cand) -> Volume`; `validate(ctx, vol) -> score`; manual builder |
| `disks/copy.py` | copy | `plan(...) -> CopyPlan` (all refusals), `run(ctx, plan, on_progress, should_stop) -> CopyResult`, resume, verify |
| `ui/`, `flow.py`, `script.py`, `cmdline.py` (`beastnet.action=disk`), GRUB "Disk tools" entry | UI | screens and script-mode plans |
| `build/beastnet/*` | platform | storage modules, mdadm/lvm2/cryptsetup/ddrescue/smartmontools/ldmtool in the helper; RAM/size budget |
| `tests/e2e/fixtures/disks*`, `tests/e2e/test_e2e_disks.py` | tests | QEMU disk fixtures and end-to-end checks |

Shared files (`errors.py`, `events.py`, `paths.py`, `conftest.py`) are the
lead's: ask for additions in your report.

## 4. Event lines (serial console, `BEASTNET:` prefix; tests read them)

```
disk found id=<kernel> serial=<s> size=<bytes> lss=<n> pss=<n> transport=<t> stick=0|1
disk ro id=<node> ro=1                       # guard applied (one line per node)
stack found id=<kind:uuid> kind=<kind> level=<l> members=<n> state=<s> support=<assemble|detect|reconstruct>
assemble ok id=<stack> dev=<path> ro=1   |   assemble fail id=<stack> code=<code>
reconstruct candidate rank=<n> level=<l> chunk=<bytes> order=<i,j,...> layout=<l> offset=<bytes> score=<f>
copy start kind=<clone|image|restore> src=<id|path> dst=<id|path> size=<bytes>
copy progress done=<bytes> errors=<n> rate=<bytes/s>
copy done kind=<k> bytes=<n> errors=<n> sha256=<hex|->   |   copy stopped resumable=1
health id=<kernel> status=<ok|warn|fail> hours=<n> realloc=<n> pending=<n> wear=<pct|->
```

## 5. Error codes (added to `errors.py`)

`disk-refused` (a safety rule refused the plan), `disk-changed` (identity
or presence changed between plan and write), `disk-io` (read/write error
beyond what ddrescue records), `assemble` (a stack could not start read-only),
`reconstruct` (no candidate validated), `copy` (the copy failed).

## 6. Script mode (tests; `beastnet.script=` plan)

```json
{"action": "disk", "then": "poweroff", "on_error": "poweroff",
 "steps": [
   {"op": "scan"},
   {"op": "health", "disk": "<serial>"},
   {"op": "assemble", "stack": "<kind:uuid>"},
   {"op": "reconstruct", "members": ["<serial>", ...], "mode": "auto"},
   {"op": "image", "source": "<volume id or serial>", "dest": "/images/x.img"},
   {"op": "clone", "source": "<volume id or serial>", "target": "<serial>", "confirm": "<last 6 of serial>"},
   {"op": "restore", "image": "/images/x.img", "target": "<serial>", "confirm": "<last 6>"}
 ]}
```

Disks are named by serial (QEMU drives get `serial=`). A step that a safety
rule refuses ends the plan with `error disk-refused` (tests assert it).

## 7. Tests

- Unit tests with fake sysfs/proc trees and stub tools (`beastnet/tests/`).
- QEMU e2e: NVMe (`-device nvme,serial=`) and AHCI disks, not virtio; md
  RAID 0/1/5/6/10 incl. degraded; IMSM/DDF made with
  `IMSM_NO_PLATFORM=1 mdadm -e imsm|ddf`; LVM, LUKS, btrfs RAID1; arrays
  with wiped metadata and shuffled order for reconstruction (oracle: the
  original parameters and file hashes); dm-flakey/blkdebug for read errors.
- **The gate:** the host hashes every source image before and after each
  read-only flow (scan, assemble, reconstruct, image, clone); any changed
  byte fails.
- Real hardware later: the maintainer's Intel RST/VMD board.
