# Disk tools (0.3.0): recovery and cloning, RAID-aware

The beast-net helper gains **Disk tools**: see every disk and what is on it,
check health, rescue a failing disk, clone or image disks, partitions and
RAID volumes, and restore an image. It must work with RAIDed devices:

| Storage | How BeastBoot reaches the data |
|---|---|
| Hardware RAID controllers (MegaRAID/PERC, Smart Array, Adaptec, LSI) | their in-tree drivers show each array as one disk |
| Linux md (mdadm 0.90/1.x), SNIA DDF | `mdadm --assemble --readonly` on RAM copy-on-write overlays of the members |
| Intel RST/VROC (IMSM) | `mdadm --assemble --readonly` directly (IMSM needs the disks' serials), only when no member uses RWH/PPL, a bitmap or a journal and no migration runs; else refused |
| LVM | read-only activation on overlays of the PVs, only VGs whose LVs are all linear or striped (raid, mirror, cache, thin, writecache, integrity, vdo, snapshot: refused, image the PVs) |
| LUKS/BitLocker, Btrfs | their own tools, read-only |
| Windows dynamic disks (LDM) | detected only in 0.3.0: image each disk |
| ZFS | optional pack built by the desktop app from Canonical's signed packages (never shipped by BeastBoot) |
| AMD RAIDXpert2, Storage Spaces (simple/mirror), unknown or destroyed metadata | **generic reconstruction**: parameters detected from the data, assembled on copy-on-write overlays, validated read-only; manual RAID builder as fallback |

This file is the contract between the parts built in parallel. Code:
`beastnet/python/beastnet/disks/` (model in `model.py`; one module per part).

## 1. Safety rules (non-negotiable)

1. **Sources are read-only.** On entering Disk tools, `guard.protect_all()` sets
   `BLKROSET` on every block device node (disks *and* partitions, also md/dm
   nodes as they appear) and re-applies it after every rescan. Arrays start
   with `--readonly` on copy-on-write overlays of their members (IMSM: see
   the table), LVM activates read-only on overlays, LUKS opens `--readonly`, pools
   import `readonly=on`, mounts use `ro,noatime` (+ `norecovery`/`noload`
   where the filesystem has a journal). Nothing starts on its own (no udev).
2. **Reconstruction never writes to members.** Every experiment runs on
   dm-snapshot overlays whose COW lives in RAM (tmpfs, capped); md
   `--create --assume-clean` and `--bitmap=none` only on overlays, resync
   speed set to 0.
3. **Only a confirmed target becomes writable**, after the plan screen and a
   typed confirmation (last 6 characters of the target's serial; the whole
   serial if two disks end the same). The target is re-identified (serial,
   WWN, size, and a hash of its first and last MiB taken when the plan was
   made) right before writing and opened `O_EXCL` for the whole job.
   A serial that two attached disks report (many USB bridges report a fixed
   one) names neither: no source, target or image disk can be given by it,
   and neither disk can be written until one is unplugged.
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

The helper kernel boots with `raid=noautodetect md_mod.start_ro=1` (every
beast-net entry, `bb_beastnet` in grub/beast/lib.cfg): no array starts by
itself, and any array that starts is read-auto (no resync, no superblock
write) until Disk tools set it read-only.

`BLKROSET` stops writes through a device node from user space and makes a
read-write mount fail, but the kernel only *warns* when md/dm/filesystem
code on top submits a write to a read-only device. So every layer must
start read-only on its own (rule 1); the guard is the second line, and the
overlays are the third: md and LVM start on dm-snapshot views of the members
(`bbro_<dev>`, COW in RAM, origin opened read-only), so a write the kernel
makes anyway (an md internal bitmap is rewritten on start and stop even in
read-only mode; tested with a stale bitmap) lands in RAM. The only writable
nodes are the reconstruction overlays (`bbov_<dev>`, `guard.exempt`), a disk
opened for image files (`use_disk`), and, after confirmation, the copy
target (`guard.make_writable(ctx, disk, confirmed=True, partition=...)`: for
a partition target only the disk node and that partition; closed when the
copy ends). Started-stack and reconstruction overlays share one RAM cap: a
reconstruction that fills it makes the started stack's reads fail.

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
| `disks/assemble.py` | discovery | `start(ctx, stack) -> list[Volume]`, `stop(ctx, stack)` for md/IMSM/DDF, LVM, LUKS/BitLocker, Btrfs, ZFS (if the pack is present) |
| `disks/overlay.py`, `disks/reconstruct.py` | reconstruction | overlays; `detect(ctx, members) -> list[Candidate]`; `build(ctx, members, cand) -> Volume`; `validate(ctx, vol) -> score`; manual builder |
| `disks/copy.py` | copy | `plan(...) -> CopyPlan` (all refusals), `run(ctx, plan, on_progress, should_stop) -> CopyResult`, resume, verify |
| `ui/`, `flow.py`, `script.py`, `cmdline.py` (`beastnet.action=disk`), GRUB "Disk tools" entry | UI | screens and script-mode plans |
| `build/beastnet/*` | platform | storage modules, mdadm/lvm2/cryptsetup/ddrescue/smartmontools in the helper; RAM/size budget |
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
                                             # order: indices into the given members by slot, "-" = missing; layout "-" = none
copy start kind=<clone|image|restore> src=<id|path> dst=<id|path> size=<bytes>
copy progress done=<bytes> errors=<n> unread=<bytes> rate=<bytes/s>
copy done kind=<k> bytes=<n> errors=<n> unread=<bytes> sha256=<hex|->   |   copy stopped resumable=1
                                             # errors = bad areas in the mapfile (both lines), unread = bytes not recovered
fs repair dev=<dev> fs=<type> result=<fixed|clean|refused|failed>   # a dirty drive checked before a copy (s.6)
health id=<kernel> status=<ok|warn|fail> hours=<n> realloc=<n> pending=<n> wear=<pct|->
disk dest id=<kernel> dev=<path> fs=<type> rw=0|1 free=<bytes>   # a disk opened for image files (rw=1) or to read one (rw=0)
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
`disks/session.py` checks every step before anything runs and runs them in
one session (guard on first; at the end, reconstructed arrays and started
stacks are stopped). Optional keys:

| Step | Optional keys |
|---|---|
| `assemble` | `passphrase` (LUKS/BitLocker; tests only: it sits in plain text on the stick) |
| `reconstruct` | `name` (default `reconstructed`; later steps use it as `source`); `mode: "manual"` with `level`, `chunk` (bytes), `order` (members in array order, `"missing"` for an absent one), `offset` (bytes), `layout` |
| `use_disk` (`disk`, `confirm`) | `partition`: opens one exFAT/NTFS/ext4/XFS filesystem of a confirmed disk read-write for image files (largest one by default); refused for the stick, a disk without a serial, or a disk of any set |
| `image`, `clone` | `verify` (default true); `member_of_set: true` to copy one disk of a multi-disk set on its own (refused otherwise); `image` also `on` (serial of a disk opened by `use_disk`) |
| `restore` | `verify`; `on` (the image is on another disk: opened read-only, no journal replay, no confirmation; or the disk `use_disk` opened) |
| `image`, `clone`, `restore` | `restart: true`: start over when the saved progress cannot be trusted (without it the step ends with `error copy ... cannot be trusted`) |

Without `on`, image paths are on the stick's data partition. A `use_disk`
disk is made writable through the guard (`make_writable`, then `exempt`
while mounted `rw,noatime,nodev,nosuid,noexec`); leaving the session syncs,
unmounts and sets it read-only again. `use_disk` refuses a disk whose serial
another disk also reports. An image gets `<image>.sha256` (when verified) and
`<image>.info.json` (logical sector size, size, source); a raw restore onto a
disk with a different logical sector size is refused. A restore's mapfile may
sit on the drive that holds the image file (a file, not a disk being rescued).

A `source` is a reconstruction name, a started stack id (when it gave one
volume), a volume id or path, or a disk serial or name. Image paths are on
the stick's data partition; ddrescue mapfiles go to `/disk-tools` there.

**Progress that survives a power cut** (`disks/mapstore.py`, `disks/fsrepair.py`).
ddrescue writes its mapfile in RAM (`/run/beastnet/disk-maps`). Every 30 seconds, after
each ddrescue pass, on a stop and at the end, the engine copies it to the mapfile's
place. It does this only when the map is complete (it covers the whole source, has no
gaps and no unknown states). Before the copy, it fsyncs the target, so every area the
map calls finished is on the target. The copy is written as `<map>.tmp`, fsynced and
renamed over `<map>`, then the directory is fsynced. Each copy carries the source size
and its own SHA-256 in its first line.

30 seconds keeps a slow USB stick from an fsync storm: one small file and three fsyncs
per interval. A power cut loses at most about a minute of progress, because ddrescue
itself saves the RAM map every 30 seconds.

When a copy starts, it uses the newest saved map whose checksum and coverage hold.
A map that is damaged, torn, or was not written this way is never used: the step stops
with `error copy ... cannot be trusted`. The screen then offers "Start over", and script
mode has `restart: true`. The damaged file is kept as `<map>.untrusted`.

Disk tools check two kinds of filesystem after a power cut. The stick's data partition is
checked when Disk tools start, before the guard. A `use_disk` disk, confirmed with its
serial, is checked before it is mounted. Each has its checker run in automatic mode, and
the screen and an `fs repair` line say so:

| fs | handling |
|---|---|
| FAT32 | `fsck.fat -a -w` |
| exFAT | `fsck.exfat -p` |
| ext4 | the read-write mount replays the journal |
| XFS | the read-write mount replays the log |
| NTFS | refused with "run chkdsk /f in Windows" |

Sources and disks opened read-only are never checked. If the stick cannot be repaired,
copies that would keep their map there are refused with the reason.

**Confirmation in two stages.** `copy.plan(..., confirm=None)` runs every
other check and returns the plan with `confirmed=False` (for the plan
screen); `copy.plan(..., confirm=<typed>)` raises `disk-refused` when the
typed text is wrong and sets `confirmed=True` otherwise; `copy.run()`
refuses an unconfirmed clone or restore and re-identifies the target itself
(`discover.scan`). `copy.Hooks` holds the injectable pieces (rescan,
make_writable, relock, open_exclusive, spawn, ...) for tests.

## 7. Tests

- Unit tests with fake sysfs/proc trees and stub tools (`beastnet/tests/`, `make test`).
  Rescue and stop/resume at this level use a stub `ddrescue`.
- QEMU e2e, `tests/e2e/test_e2e_disks.py`: NVMe (`-device nvme,serial=`) and
  AHCI disks, not virtio. Detection and read-only assembly of md RAID 0/1/5/6/10/linear,
  incl. degraded RAID1/RAID5 and internal and stale write-intent bitmaps. md metadata
  0.90, 1.0 and 1.1 (RAID1 and RAID5 each) besides 1.2; a RAID1 member with the superblock
  at the end reads as a plain ext4 disk and is still refused as a place for images. IMSM RAID5 and
  DDF RAID1, made with `IMSM_NO_PLATFORM=1 mdadm -e imsm|ddf`. LVM, incl. a duplicate VG
  name and a refused raid1 LV. LUKS2, btrfs RAID1. Wiped md RAID0/RAID5/RAID5-missing:
  the reconstruction candidate's parameters are checked against the original ones (the
  rebuilt array is not imaged). Image and restore of a 512-byte GPT disk; clone AHCI to
  NVMe; the clone refusals.
- QEMU e2e, `tests/e2e/test_e2e_disks_copy.py`:
  - Clone onto an equal-size and a larger target, MBR and GPT. On the larger target the
    partitions are byte-exact, the extra space is untouched and the GPT backup header
    moves to the end.
  - 4Kn to 4Kn (NVMe `logical_block_size=4096`); 512e source or target (AHCI
    `physical_block_size=4096`). Refused: a clone between 4Kn and 512 in either
    direction, and a raw restore of a 4Kn image onto a 512 disk.
  - A USB target (`usb-storage`).
  - An assembled md RAID1, an LVM LV and an opened LUKS volume as the source: cloned to a
    disk, and imaged to a file and restored to another disk.
  - Rescue with the real `ddrescue` against read errors injected with QEMU `blkdebug`
    (bad sectors at the start, in the middle and a 1 MiB region), cloned and imaged. The
    tests check the mapfile, every readable byte and the bad-area count. dm-flakey is not used.
  - Stop and resume: QEMU is killed mid-copy (a power cut) and the same plan runs again,
    for a clone and for a rescue. The second run checks the stick's FAT, continues from
    the mapfile and ends with the same result as an uninterrupted copy. A stop without a
    power cut has no QEMU test: script mode has no stop.
- **Firmware modes.** Every test above boots the helper under UEFI. A chosen set also runs
  under legacy BIOS and under UEFI with Secure Boot (shim, the signed GRUB, the signed helper
  kernel in lockdown, `beastnet.sb=1`): the scan; detection, read-only assembly and imaging
  of md RAID 0/1/linear/5/10, LVM, LUKS2 and btrfs; one disk clone; the rescue with a power
  cut and resume. `test_modules_load_under_lockdown` checks under Secure Boot that the
  kernel is locked down, that every on-demand module of section 8 loads, and that an
  unsigned copy of a shipped module is refused. Under Secure Boot the helper asks on the
  console before it runs a plan from the stick; the tests answer it.
- **The gate:** the host hashes every source image before and after each
  flow (scan, assemble, reconstruct, image, clone, rescue); any changed
  byte fails.
- Not in QEMU (hardware only): Intel RST/VMD with real serials, hardware RAID
  controllers, USB bridges' SMART, a genuinely failing disk. The maintainer's Intel
  RST/VMD board comes later.

## 8. Platform notes (helper image: drivers, tools, running without udev)

These lines were exercised in QEMU (q35, 2 GiB, no udev, `tests/e2e/test_e2e_disks*.py`; UEFI, and a chosen set under BIOS and Secure Boot, see section 7): mdadm (md RAID 0/1/5/6/10/linear and IMSM/DDF read-only assemble), LVM (read-only activation), dmsetup, cryptsetup (LUKS2 read-only) and ddrescue (real read errors). The LDM, partial-VG and smartctl-on-USB lines are untested, and so is running at 1 GiB.

**Drivers.** `nvme`, `ahci`, `sata_*`, `pata_*`, `vmd` and the HBA/RAID-controller drivers
(`megaraid_sas`, `mpt3sas`, `mpi3mr`, `hpsa`, `smartpqi`, `aacraid`, `3w-*`, `arcmsr`) load at
coldplug by PCI modalias, like the network drivers; a RAID controller shows up as ordinary
disks. Built into the kernel: `md-mod`, `dm-mod`, `loop`, `libata`, `sd_mod`, `ext4`, `vfat`,
and the crypto used by LUKS (aes, xts, cbc, sha256/512). Loaded **on demand, by the
kernel** when mdadm, device-mapper, cryptsetup or `mount` first need them (the Python code
does not `modprobe` them; it only does so for the optional ZFS pack): md levels `raid0 raid1 raid10 raid456
linear`, `dm-crypt dm-snapshot dm-mirror dm-raid dm-thin-pool dm-cache
dm-integrity dm-zero dm-delay dm-flakey`, `btrfs xfs hfsplus hfs udf exfat ntfs3 isofs`,
`essiv adiantum lrw serpent_generic twofish_generic`. A btrfs set is offered as a device and
not mounted, so starting one does not load `btrfs`. All are in-tree modules signed by the
kernel build, so they load under Secure Boot lockdown (`beastnet.sb=1`); nothing else may be
added. This is tested: with Secure Boot on, lockdown reads `integrity`, each module in this
list loads, and a module with its signature removed is refused (section 7).
There is no APFS, no ReFS and no ZFS module (ZFS is the optional pack).

**Programs** (`/usr/sbin`, `/usr/bin`): `mdadm mdmon lvm (pvs vgs lvs pvscan vgscan lvscan
vgchange lvchange vgmknodes ...) dmsetup cryptsetup ddrescue ddrescuelog smartctl blkid
blockdev lsblk partx findmnt losetup sfdisk e2fsck dumpe2fs xfs_repair xfs_db btrfs
btrfs-find-root`. Mutating LVM commands (`pvcreate`, `vgcreate`, `lvcreate`, ...) are not
shipped; `mkfs.*`, `smartd`, udev rules and units are not shipped either. The BusyBox `mount`,
`umount`, `blkid`, `fdisk` etc. remain, but `blkid`, `lsblk`, `blockdev`, `partx`, `findmnt`,
`losetup`, `sfdisk` are the full util-linux programs (`lsblk -J`, `blkid -p -o export`).

**No udev, no daemons.** Nothing creates device nodes except devtmpfs and the tools themselves:

| Tool | How to call it |
|---|---|
| mdadm | environment `MDADM_NO_UDEV=1 MDADM_NO_SYSTEMCTL=1`; always `--config=/dev/null` for scans (there is no mdadm.conf); `mdadm --examine <dev>` / `--examine --scan` to detect; `mdadm --assemble --readonly --run /dev/md/<name> <members...>` or `--assemble --scan --readonly --run --config=/dev/null` (degraded arrays need `--run`). The node is the devtmpfs `/dev/mdN` (md127 and up, `/dev/md/<name>` is a symlink mdadm makes itself). IMSM/DDF: also `IMSM_NO_PLATFORM=1`; the container and its volume both appear. `mdadm --stop /dev/mdN` (stop the volume before the container). Needs `/run/mdadm` (the Python code creates it; `/run` is a tmpfs). |
| LVM | `/etc/lvm/lvm.conf` (shipped in the image) sets `udev_sync=0`, `udev_rules=0`, `obtain_device_list_from_udev=0`, `use_devicesfile=0`, `monitoring=0`, `use_lvmpolld=0` and `global/metadata_read_only=1`, so any command that would write metadata fails (verified: `lvcreate` fails). Create `/run/lvm` and `/run/lock/lvm` first. Scan: `lvm pvs/vgs/lvs --reportformat json`. Activate read-only: `lvm vgchange -ay --config 'activation { read_only_volume_list = ["<vg>"] }' <vg>` (dm table flag `r`, `blockdev --getro` = 1). LVM itself creates `/dev/mapper/<vg>-<lv>` and `/dev/<vg>/<lv>`; `lvm vgchange -an <vg>` removes them. Partial/degraded VGs need `--activationmode partial`. |
| device-mapper | `dmsetup table/info -c/ls`; `dmsetup mknodes` re-creates missing `/dev/mapper` nodes (run it after any dm change made through `dmsetup` or `cryptsetup` if a node is absent); `dmsetup remove <name>` (children first). Overlays: create `snapshot` targets with a RAM-backed COW (loop on tmpfs) and `dmsetup create <name> --table '...'`. |
| cryptsetup | `cryptsetup isLuks`, `luksDump`, `open --readonly [--type luks|bitlk] --key-file - <dev> <name>` (verified: node `/dev/mapper/<name>`, `blockdev --getro` = 1, no udev needed); `cryptsetup close <name>`. LUKS2 with Argon2 may need about 1 GiB of free memory: check `MemAvailable` before opening. Keys come from stdin (`--key-file -`), never from a file on the stick. |
| losetup / partx | `losetup --read-only --find --show [-P] <file>`; for new partition nodes after `BLKRRPART`/`partx -a` run `mdev -s` (BusyBox) or read `/sys/block/<d>/<p>/dev` and `mknod`; devtmpfs already creates them in the common case. |
| hotplug | `init` sets `/proc/sys/kernel/hotplug` to `/sbin/mdev`, so devtmpfs nodes and `mdev.conf` rules cover new md/dm/loop devices; `mdev -s` re-scans `/sys` for anything missed. Run `guard.reapply()` after each rescan. |
| smartctl | `smartctl -j -a <dev>` (JSON); `smartctl --scan` lists `-d` types; NVMe works as `/dev/nvme0`; USB bridges need `-d sat`. The drive database is `/usr/share/smartmontools/drivedb.h`. |
| ddrescue | `ddrescue -f` only after the typed confirmation; mapfile on the data partition or a third disk. |
| filesystem checks | read-only only: `e2fsck -n`, `xfs_repair -n`, `btrfs check --readonly`, `dumpe2fs -h`, `xfs_db -r`. Never on a source without `-n` / `--readonly`; XFS/ext journals are not replayed (`norecovery`, `noload`). |
| LDM | not shipped in 0.3.0: `ldmtool create` makes writable dm tables; dynamic disks are detected from their partition types and imaged disk by disk. |

`MemAvailable` after coldplug at 1 GiB is about 700 MB with the full module set and tools.

## 9. AMD RAID: what is known

- **SATA in RAID mode** (seen on an ASUS ROG Crosshair VIII Hero, X570,
  BIOS 4702, Ubuntu 26.04 kernel 7.0): the FCH SATA controllers show up as
  PCI class 0x0104 `1022:7916`, Linux's in-tree `ahci` driver binds them
  ("AMD is using RAID class only for ahci controllers"), and every disk is
  visible as a plain disk. So the members of an AMD SATA array can be read,
  imaged and reconstructed.
- **NVMe in RAID mode:** the drives sit behind AMD's RAID function and the
  in-tree `nvme` driver does not see them (not yet verified on hardware). The
  arrays stay readable by switching the BIOS back to NVMe/AHCI mode, which
  leaves the data in place (also to verify).
- The metadata format is undocumented; reading it exactly is the
  separate project chipraid (clean-room, userspace, read-only dm tables).
  Until then: generic reconstruction (section 3).

