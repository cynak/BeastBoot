# Disk tools: coverage matrix

> **Last verified run (2026-11-13, x86 Linux host, KVM, UEFI only):** `devtools/e2e-on-kvm-host.sh all`.
> Unit suite 684 passed, 0 failed. Disk end-to-end suite 37 passed, 0 failed, 0 skipped
> (helper beast-net 0.4.1, kernel 7.3.0-9-generic, fixtures recipe b5cb7bc958734564).
> Every cell marked QEMU below passed in that run. Cells marked "not tested" are unchanged.
>
> **Run of 2026-11-15 (same host, KVM; UEFI, legacy BIOS and UEFI with Secure Boot):**
> `devtools/e2e-on-kvm-host.sh disks`. Disk end-to-end suite 93 passed, 0 failed, 0 skipped
> (helper beast-net 0.4.1, kernel 7.3.0-9-generic, fixtures recipe 40ffa8e4acc444e3).
> Run again later that day with kernel 7.3.0-10-generic and GRUB carrying SBAT `grub,7`:
> the same 93 passed. What the run added is in the next section.
>
> **2026-11-16:** the unit suite (`beastnet/tests`) has 650 tests: 649 passed, 1 skipped on the
> same host.

## Added 2026-11-15: BIOS, Secure Boot, md metadata 0.90 / 1.0 / 1.1

Until this run the helper only booted under plain UEFI in the disk tests, and every md fixture
had metadata 1.2. Now a chosen set of tests also runs under legacy BIOS and under UEFI with
Secure Boot. The Secure Boot run uses the real chain: shim, the signed GRUB, the signed helper
kernel, `beastnet.sb=1`, kernel lockdown on. All of it passed on the first run; no product
change was needed.

| Cell | BIOS | Secure Boot |
|---|---|---|
| Scan: every disk found, the stick marked, all disks set read-only | PASS | PASS |
| Stacks detected: md RAID0/1/linear, RAID5/10, LVM, LUKS2, btrfs RAID1 (5 groups) | PASS | PASS |
| Read-only assembly of the same 5 groups; md and LUKS volumes imaged, every file hash checked | PASS | PASS |
| Clone a GPT disk (AHCI to NVMe), byte-exact | PASS | PASS |
| Rescue with read errors, power cut, resume from the mapfile | PASS | PASS |
| The kernel is locked down and still loads what the tools need | n/a | PASS (see below) |

The other disk tests (IMSM, DDF, degraded and bitmap arrays, reconstruction, restore, 4Kn,
the refusals, the rest of the copy tests) still run under UEFI only. They add storage layouts,
not other kernel modules or another boot path.

**Module loading under lockdown** (`e-lock`). The test starts md RAID5, RAID10, LUKS2 and
btrfs under Secure Boot, then looks inside the helper:

- `/sys/kernel/security/lockdown` reads `[integrity]` (without Secure Boot: `[none]`).
- The plan itself made the kernel load `raid456`, `raid10`, `dm_snapshot` and `dm_crypt`.
- All 28 on-demand modules that DISK_TOOLS.md s.8 lists load from their shipped files
  (`modprobe`): the md levels, the device-mapper targets, the filesystems and the ciphers.
- A copy of a shipped module (`dm-zero`) with its signature cut off is refused: `insmod`
  fails with "Key was rejected by service". The same copy loads without Secure Boot, so
  the refusal is the kernel's signature check.

**md metadata 0.90, 1.0 and 1.1** (UEFI). Two new fixture sets, RAID1 and RAID5 for each
version. All six arrays are detected, started read-only and imaged, and every file hash
matches. With 0.90 and 1.0 the superblock is at the end of the member, so a RAID1 member
is a readable ext4 filesystem from its first byte (the test reads the files straight from
the member image to prove it). The tools still treat such a disk as an array member: the
scan reports the array, and `use_disk` on the member is refused ("it belongs to md set"),
so it is never mounted as a place for images. No byte of a member changed.

Not covered: 0.90 on a partition that ends at the end of the disk (the same superblock
then shows on the disk and on the partition), degraded arrays with old metadata, and
reconstruction of wiped arrays that had old metadata.

## Added after the first matrix (2026-11-13, `tests/e2e/test_e2e_disks_copy.py`)

Full cold run on the same host: 56 passed, 2 expected failures. These results replace the
"not tested" entries for the same setups in the tables below. Nothing wrote to a source disk,
cloned onto the wrong disk or reported success with wrong data.

| Cell | Result |
|---|---|
| Clone MBR disk, equal-size target | PASS (sha256 equal) |
| Clone MBR / GPT disk, larger target | PASS: partitions byte-exact, extra space untouched, GPT backup header moved to the last LBA |
| Clone GPT disk, equal-size target | PASS |
| 4Kn clone (NVMe lbs 4096) | PASS |
| 512e as source or target (AHCI pbs 4096) | PASS (QEMU NVMe cannot express 512e) |
| Refuse clone 4Kn<->512, refuse restore of a 4Kn image to 512 | PASS |
| USB target (usb-storage) | PASS after the discover.py USB-serial fix |
| Clone md RAID1 / LVM LV / opened LUKS volume to a disk | PASS (files plus the RAID1 data area byte-compared; nothing written past the volume) |
| Image md/LVM/LUKS volume, restore to another disk | PASS |
| Stop and resume of a clone (power cut) | XFAIL on 2026-11-13 (the mapfile was lost on FAT). Fixed since; PASS in the run of 2026-11-15 |
| Rescue with real ddrescue + blkdebug (start, middle, 1 MiB region), clone and image | PASS: mapfile exact, 3 bad areas, every readable byte equal, bad areas untouched |
| Rescue stop and resume (power cut) | XFAIL on 2026-11-13 (internal error on the next run). Fixed since; PASS in the run of 2026-11-15, also under BIOS and Secure Boot |
| Partition target, NVMe->NVMe clone other than above, NTFS-disk source | not added |

On 2026-11-13 **stop and resume after a power cut** did not resume (the clone restarted from
zero and still ended byte-exact; the rescue stopped with an internal error on the next run).
Both were fixed afterwards and the tests are no longer expected failures: in the run of
2026-11-15 the second run continues from the mapfile. Not possible in QEMU: 512e on NVMe, and
a clean stop (script mode has none).

What is proven about the disk tools today, and what is not. Engine contract:
[DISK_TOOLS.md](DISK_TOOLS.md).

How this was made: every test named below was found by name and read far enough
to see which storage setup and which operation it exercises. The tests were
**not run** for this document. QEMU tests skip when KVM, the disk fixtures or a
built helper are missing, so "QEMU" means "a test exists and asserts it", not
"it passed on the last release build". No hardware run is recorded anywhere in
the repository (see Gaps).

## 1. Reading the tables

A cell starts with one status in backticks, then the test keys (s.6) that prove it.

| Status | Meaning |
|---|---|
| `U` | unit test (fake sysfs, stub tools, file-backed disks); no kernel, no real tool |
| `Q` | QEMU end to end: real helper kernel and tools, fixture disks, source images hashed before and after (the gate) |
| `H` | real hardware (none exist yet) |
| `R` | refused by design; the refusal itself is tested (the tag says where) |
| `-` | not tested (a note says why, or what is only partly covered) |
| `n/a` | the operation does not apply to this setup |

A cell with two proofs shows two statuses, e.g. `U` `Q`. Columns: **Scan** =
scan/identify; **Health**; **Assemble** = assemble read-only (start the stack);
**Recon** = reconstruct; **Image** = image to file; **Restore**; **Clone** = clone
disk to disk; **Rescue** = rescue with read errors; **Stop** = stop and resume;
**Verify** = verify the copy (read-back hash, host-side compare).

All QEMU runs of the helper in `test_e2e_disks.py` boot under **UEFI**; the tests listed in
2f also boot under legacy BIOS and under UEFI with Secure Boot. The fixtures have 512-byte
sectors (one 4Kn disk for the copy tests), md arrays with metadata 1.2 (0.90, 1.0 and 1.1
in the `md-meta-a` and `md-meta-b` sets) and AHCI (`ide-hd`) or NVMe disks. The
fixture disk transport is `nvme` for odd serial numbers and `ahci` for even ones
(`fixtures/disks.py`), so the gpt source disk (BB000044, by counting the recipe) is AHCI;
copy targets made by `blank_disk` are NVMe.

## 2. Matrix: storage setups by operation

### 2a. Single disks, transports and sector sizes

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| Copy engine on file-backed stub disks (any transport) | n/a | n/a | n/a | n/a | `U` c-run | `U` c-run | `U` c-run | `U` c-bad (ddrescue is a stub) | `U` c-resume | `U` c-run, c-rb |
| Disk on NVMe | `U` d-scan, d-mp; `Q` e-scan | `U` h-rules, h-num (parser only) | n/a | n/a | `-` no NVMe source is imaged whole | `Q` e-ir (NVMe target) | `Q` e-clone (NVMe target) | `-` | `-` | `Q` e-ir, e-clone |
| Disk on SATA (AHCI) | `U` d-scan; `Q` e-scan | `U` h-rules (ata) | n/a | n/a | `Q` e-ir | `-` AHCI is never a target | `Q` e-clone (AHCI source) | `-` | `-` | `Q` e-ir, e-clone |
| Disk on USB | `U` d-scan | `U` h-usb | n/a | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| 512n (512/512) | `Q` e-scan | n/a | n/a | n/a | `Q` e-ir | `Q` e-ir | `Q` e-clone | `-` | `-` | `Q` e-ir |
| 512e (512 logical, 4096 physical) | `U` d-scan | n/a | n/a | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| 4Kn (4096/4096) copied to 4Kn | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| 512 source onto 4Kn target (or the reverse) | n/a | n/a | n/a | n/a | n/a | `R` U c-sec, c-info | `R` U c-sec | n/a | n/a | n/a |
| GPT disk (ext4 + NTFS) | `Q` e-scan, e-manifest | n/a | n/a | n/a | `Q` e-ir | `Q` e-ir; `U` c-big (larger target, backup GPT relocated) | `Q` e-clone; `U` c-big | `-` | `-` | `Q` e-ir, e-clone |
| MBR disk | `-` | n/a | n/a | n/a | `-` | `-` | `Q` ec-mbr (equal and larger NVMe target) | `-` | `-` | `Q` ec-mbr |
| Partition as clone/restore target | n/a | n/a | n/a | n/a | n/a | `U` c-part | `U` c-part | n/a | n/a | `-` |

### 2b. Linux md RAID (fixtures: metadata 1.2 only, members 96 MiB)

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| md RAID0 (2 members) | `U` p-md; `Q` e-det[md-a] | `-` | `Q` e-asm[md-a]; `U` a-md | n/a | `Q` e-asm[md-a] | `-` | `-` volume to disk | `-` | `-` | `Q` file hashes in the image, gate |
| md RAID1 | `U` p-md; `Q` e-det[md-a] | `-` | `Q` e-asm[md-a] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID5 (3, left-symmetric) | `U` p-md; `Q` e-det[md-b] | `-` | `Q` e-asm[md-b] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID6 (4) | `U` p-md; `Q` e-det[md-c] | `-` | `Q` e-asm[md-c] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID10 (4, n2) | `Q` e-det[md-b] | `-` | `Q` e-asm[md-b] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md linear | `U` p-md; `Q` e-det[md-a] | `-` | `Q` e-asm[md-a] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID1 degraded | `U` p-md; `Q` e-det[md-c] (state "degraded") | `-` | `Q` e-asm[md-c]; `U` a-md (`--run`, never `--force`) | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID5 degraded | `U` p-md; `Q` e-det[md-c] | `-` | `Q` e-asm[md-c] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| md RAID6 degraded (one or two missing) | `U` p-md (raid6, 2 of 4) | `-` | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| md RAID10 degraded | `-` | `-` | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| md RAID0 / linear with a missing member | `U` p-md (incomplete) | `-` | `R` U a-ref | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| md with internal write-intent bitmap (RAID1, RAID5) | `Q` e-det[md-bitmap] | `-` | `Q` e-asm[md-bitmap] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` gate |
| md with a stale bitmap (md rewrites it on start) | `Q` e-det | `-` | `Q` e-asm: the rewrite lands in the RAM overlay, member bytes unchanged | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` gate |
| md metadata 0.90 (RAID1, RAID5), 1.0 (RAID1, RAID5), 1.1 (RAID1, RAID5) | `Q` e-det[md-meta-a, md-meta-b]; e-manifest (superblock version) | `-` | `Q` e-asm[md-meta-a, md-meta-b] | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` file hashes, gate |
| md RAID1 member with the superblock at the end (0.90, 1.0): it reads as a plain ext4 disk | `Q` e-det[md-meta-a] (reported as an array); e-manifest (ext4 readable from byte 0) | `-` | `Q` e-asm[md-meta-a] | n/a | `R` Q e-endmeta (`use_disk` on the member refused: never mounted for images) | `-` | `-` | `-` | `-` | `Q` gate |
| md on partitions, md under LVM | `U` p-md-part, p-lvm | `-` | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| Stop (md refused while mounted; arrays before container; overlays removed) | n/a | n/a | `U` a-stop | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

### 2c. Vendor RAID and containers

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| Intel RST/VROC (IMSM), RAID5, 3 members, clean | `U` p-imsm; `Q` e-det[imsm] | `-` | `U` a-imsm; `Q` e-asm[imsm] (members opened directly, no overlay) | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` gate |
| IMSM with RWH/PPL, a bitmap, or a running migration | `-` | `-` | `R` U a-imsm-ref | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| IMSM RAID0/1/10, degraded, or on a real Intel RST/VMD board | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| SNIA DDF RAID1 | `U` p-ddf; `Q` e-det[ddf] | `-` | `U` a-ddf; `Q` e-asm[ddf] (on overlays) | n/a | `Q` e-asm | `-` | `-` | `-` | `-` | `Q` |
| Hardware RAID controller (MegaRAID/PERC, Smart Array, Adaptec, LSI): array appears as one disk | `-` driver list only (`build/beastnet/modules.list`), no boot with a controller | `-` | n/a | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| Other fake RAID (Promise, VIA, ...) | `U` p-fake (detect only) | n/a | `R` U a-ref | n/a | `-` | `-` | `-` | `-` | `-` | `-` |

### 2d. LVM, encryption, file-system level pools

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| LVM linear (2 PVs, ext4 + xfs LVs; a second VG; a same-named VG on another disk) | `U` p-lvm; `Q` e-det[lvm] | `-` | `U` a-lvm; `Q` e-asm[lvm] (read-only, on overlays) | n/a | `-` LVs are assembled but not imaged (not in IMAGEABLE) | `-` | `-` | `-` | `-` | `-` |
| LVM striped | `-` | `-` | `U` a-lvm (stub lists "striped" as allowed); `Q` `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| LVM with raid1, raid5, mirror, thin, cache, writecache, integrity, vdo, snapshot or error LVs | `Q` e-det[lvm-raid] | `-` | `R` Q e-lvmraid (raid1); `R` U a-lvm-ref (12 segment types) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| LVM partial VG (missing PV) | `U` p-lvm | `-` | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| LUKS2 | `U` p-luks; `Q` e-det[luks] | `-` | `U` a-luks; `Q` e-asm[luks] (passphrase on stdin, read-only) | n/a | `Q` e-asm[luks] | `-` | `-` | `-` | `-` | `Q` |
| LUKS1 | `-` | `-` | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| BitLocker | `U` p-luks | `-` | `U` a-bl (stub only; no BitLocker volume anywhere) | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| Btrfs single device (a plain file system, not a stack) | `U` p-btrfs (not reported as a stack) | `-` | n/a | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| Btrfs RAID1 (2 devices) | `U` p-btrfs; `Q` e-det[btrfs] | `-` | `U` a-btrfs; `Q` e-asm[btrfs] (volume offered, ro; no file read back) | n/a | `-` | `-` | `-` | `-` | `-` | `-` |
| ZFS pack (optional) | `U` p-zfs | `-` | `U` a-zfs (fake `zpool`); `Q` `-` fixture not built (no zfs module on the Docker host) | n/a | `-` | `-` | `-` | `-` | `-` | `-` |

### 2e. Windows, AMD, wiped metadata (reconstruction)

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| Windows dynamic disks (LDM) | `U` p-ldm (detect only) | `-` | `R` U a-ldm ("image each disk") | n/a | `-` the per-disk image is the generic path, not tested for an LDM disk | `-` | `-` | `-` | `-` | `-` |
| AMD RAIDXpert2 (SATA RAID mode, disks seen as plain disks) | `U` p-amd (heuristics); `H` observation only, docs s.9 (one X570 board, no tool run recorded) | `-` | `R` U a-ref | `U` m-det (raid0 x2, 128K, NTFS, GPT, "AMD-like" case); `Q` `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| AMD RAID on NVMe in RAID mode | `-` docs s.9: "not yet verified on hardware" | `-` | n/a | `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| Windows Storage Spaces (simple/mirror) | `U` p-fake (by GPT type) | `-` | `R` U a-ref | `-` no Storage Spaces metadata in any fixture; only generic raid0/raid1 math | `-` | `-` | `-` | `-` | `-` | `-` |
| md RAID0, wiped metadata, shuffled order | `Q` e-wipe (not offered as assemblable) | `-` | n/a | `Q` e-rec[wiped-raid0] (rank 1, level, chunk, offset, order); `U` m-det, r-build | `-` rebuilt array not imaged in QEMU | `-` | `-` | `-` | `-` | `-` |
| md RAID5, wiped | `Q` e-wipe | `-` | n/a | `Q` e-rec[wiped-raid5]; `U` m-det | `-` | `-` | `-` | `-` | `-` | `-` |
| md RAID5, wiped, one member missing | `Q` e-wipe | `-` | n/a | `Q` e-rec[wiped-raid5-missing]; `U` m-det, m-rest (parity rebuild) | `-` | `-` | `-` | `-` | `-` | `-` |
| Wiped RAID1, RAID6, RAID10, linear, NTFS volume on the array | `-` | `-` | n/a | `U` m-det (synthetic images); `Q` `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| Manual RAID builder | n/a | n/a | n/a | `U` r-build, s-man; `Q` `-` | `-` | `-` | `-` | `-` | `-` | `-` |
| Random data (no array) gives no confident layout | n/a | n/a | n/a | `U` m-rest | n/a | n/a | n/a | n/a | n/a | n/a |

### 2f. Firmware modes

| Setup | Scan | Health | Assemble | Recon | Image | Restore | Clone | Rescue | Stop | Verify |
|---|---|---|---|---|---|---|---|---|---|---|
| UEFI | `Q` e-scan | `-` | `Q` e-asm | `Q` e-rec | `Q` e-ir | `Q` e-ir | `Q` e-clone | `-` | `-` | `Q` |
| BIOS (legacy) | `Q` e-scan[bios], e-det[5 groups, bios] | `-` | `Q` e-asm[md-a, md-b, lvm, luks, btrfs; bios] | `-` | `Q` e-asm (md and LUKS volumes) | `-` | `Q` e-clone[bios] | `Q` ec-rstop[bios] | `Q` ec-rstop[bios] (power cut) | `Q` |
| UEFI with Secure Boot (shim, signed GRUB, signed kernel; `beastnet.sb=1`: only signed in-tree modules may load) | `Q` e-scan[uefi-sb], e-det[5 groups, uefi-sb] | `-` | `Q` e-asm[md-a, md-b, lvm, luks, btrfs; uefi-sb]; `Q` e-lock (lockdown on, modules load, unsigned module refused) | `-` | `Q` e-asm (md and LUKS volumes) | `-` | `Q` e-clone[uefi-sb] | `Q` ec-rstop[uefi-sb] | `Q` ec-rstop[uefi-sb] (power cut) | `Q` |

Under Secure Boot the helper asks on the console before it runs a plan from the stick; the
tests answer it (`boot_helper(mode="uefi-sb")`). Health, reconstruction and restore run under
UEFI only.

### 2g. Cross-cutting safety rules (DISK_TOOLS.md s.1)

| Rule | Proof |
|---|---|
| Sources read-only: BLKROSET on every node, re-applied after rescan | `U` g-all (12 guard tests); `Q` e-scan asserts `disk ro` on every node |
| Source images unchanged after scan, assemble, reconstruct, image, clone | `Q` the gate in every flow of `test_e2e_disks.py`; gate self-test `Q` e-gate (no-change passes, one byte in a hole fails) |
| Overlays in RAM, capped, never on the stick; torn down in order | `U` o-all (7 tests), a-ov (3 tests in test_disks_assemble) |
| Command allow-list (mdadm, lvm, cryptsetup, dmsetup, zpool) | `U` a-cmd |
| Typed confirmation, wrong text refused, nothing written | `U` c-conf; `Q` e-x[wrong_confirm] |
| Smaller target refused | `U` c-sec; `Q` e-x[smaller_target] |
| Source as target / member of the source stack as target / the stick as target | `U` c-plan; `Q` e-x[source_as_target, member_of_source_stack_as_target, stick_as_target] |
| Mounted target, active md/dm holder, target holding the mapfile, target without a serial | `U` c-plan, g-mw; `Q` `-`. Two disks with the same serial (refused; a look-alike swapped in before the write is caught by the first-and-last-MiB hash): `U` test_disks_serial_dups; `Q` `-` |
| Target re-identified before writing; `O_EXCL` open | `U` c-id, c-excl; `Q` `-` |
| Image destination rules (FAT32/ESP refused, free space, not on the source disk) | `U` c-dest |
| A member of a multi-disk set is refused unless `member_of_set` | `U` c-member |
| Passphrases never in logs or argv | `U` a-luks |

## 3. Matrix: how a session is driven

| Driver | Inventory | Assemble / unlock | Recon | Image | Restore | Clone | Rescue | Cancel / resume | Refusals and confirmations |
|---|---|---|---|---|---|---|---|---|---|
| Local text screen (curses or line UI) | `U` s-scr-err | `-` | `U` s-amd | `U` s-use, s-from | `U` s-from | `U` s-clone (scripted UI, fake modules) | `-` no rescue screen test | `-` | `U` s-clone (wrong serial asked again), s-use-ref |
| Script mode (`beastnet.script=`) | `Q` e-scan; `U` s-parse | `Q` e-asm | `Q` e-rec | `Q` e-asm, e-ir | `Q` e-ir | `Q` e-clone | `-` | `-` | `Q` e-x (5 refusal tests); `U` s-parse |

## 4. Known limits

What the tools refuse, in plain words. Each is in the code and, where noted, tested.

- **The stick is never touched.** Not a source for writing, not a target, not a
  place for a mapfile or an image (`copy.py`, `guard.py`; tested in
  `test_refuse_stick_as_target`).
- **No clone or restore onto a smaller disk, or onto a disk with a different
  logical sector size** (512 to 4Kn or back), DISK_TOOLS.md s.1 rule 4. Tested
  with faked sector sizes only (c-sec, c-info).
- **A clone or restore target needs a serial number**, and no other disk may
  report the same one. Reason: the typed confirmation is the last six
  characters of the serial, and the target is re-identified by it. Disks
  behind some USB bridges that report none cannot be written.
- **The target must be idle**: no mounted file system, no swap, no active
  md/dm/LVM/ZFS use, and not part of the source's stack.
- **One disk of a multi-disk set is not offered as "the array"** and is refused
  unless the operator asks for that member alone (`member_of_set`). A member
  clone is not the array.
- **Images cannot go to FAT32 or the ESP** (4 GiB limit), only to exFAT, NTFS,
  ext4 or xfs, and never to the disk being read.
- **Intel RST/VROC (IMSM) is refused** when any member uses RWH/PPL, a bitmap or
  a journal, or a migration is running. Reason: IMSM members cannot sit behind
  an overlay (mdadm finds them by the disk's serial), so the array starts on
  the members, and the kernel must have nothing to write.
- **LVM**: only volume groups whose LVs are all linear or striped. raid, mirror,
  cache, thin, writecache, integrity, vdo, snapshot and error LVs write when
  they activate (resync marks, metadata, pending merges), so the VG is refused:
  image the physical volumes instead.
- **md arrays with a missing member beyond their redundancy** (RAID0, linear,
  RAID5 with two missing) are not assembled; use reconstruction or image the
  members.
- **Degraded md arrays start with `--run`, never `--force`** (a-md).
- **Windows dynamic disks (LDM) are detected, not opened.** `ldmtool` would make
  writable tables. Image each disk.
- **AMD RAIDXpert2, Storage Spaces and unknown fake RAID are not assembled.**
  They go through generic reconstruction on RAM overlays, which reports a ranked
  guess and a validation score, not a guarantee. AMD RAID on NVMe may not be
  visible at all (docs s.9, unverified).
- **ZFS needs a pack** built by the desktop app; without it the pool is
  reported and not opened. No APFS, no ReFS.
- **BitLocker and LUKS need the secret** (recovery key or passphrase). Passphrases
  are read from stdin only.
- **Reconstruction memory is shared** with started stacks; one that fills the RAM
  cap makes the started stack's reads fail. LUKS2 with Argon2 may need about 1 GiB free.
- **Hardware RAID arrays** are reached through the controller's in-tree driver and
  appear as plain disks (DISK_TOOLS.md table); BeastBoot does not see the members.

## 5. Gaps, by risk to a customer's data

"QEMU" means a Linux host with KVM (and Docker `--privileged` to build fixtures).
"Hardware" means a run by the owner on a real machine.

| # | Gap | Why it matters | Test that closes it | Needs |
|---|---|---|---|---|
| 1 | **IMSM is only tested as one clean RAID5.** IMSM members are opened without overlays, the one place the kernel could write to a source. The refusals (PPL, bitmap, migration) are unit-only. The fixture records device names as serials (`IMSM_DEVNAME_AS_SERIAL` in `_disks_inside.py`), so matching by serial, the real-world path, may not be exercised. | Highest write-to-source risk | QEMU: IMSM RAID0/1/10, degraded, PPL and bitmap volumes, with the gate; one with real serials (QEMU `serial=` on the disk and `IMSM_NO_PLATFORM`). Then the same on the maintainer's Intel RST/VMD board | QEMU, then hardware |
| 2 | **Clone and restore only run on one plain 512 GPT disk (AHCI to NVMe).** Not covered: cloning an md/LVM/LUKS volume to a disk, restoring to a larger target, partition targets, a USB target, clone between NVMe and NVMe. | The only operations that write to a customer disk | QEMU: clone and restore matrix (source: md, LVM LV, LUKS volume, MBR disk, NTFS disk; target: larger, equal, partition, USB via `usb-storage`), host compares bytes; targets filled with a pattern beforehand | QEMU |
| 3 | **Rescue with read errors and stop/resume run only against a stub `ddrescue`.** DISK_TOOLS.md s.7 promises `dm-flakey`/`blkdebug`; no test uses either. The real mapfile, real bad areas, a killed VM mid-copy and a resumed run are untested. | Failing disks are the main use case | QEMU: source disk behind `blkdebug` (error ranges), image it, check `errors` and the mapfile; kill QEMU mid-clone, boot again, resume, compare. Hardware: one genuinely failing disk | QEMU, then hardware |
| 4 | **4Kn and 512e.** Only discovery of 512e and refusal logic with a faked 4096 sector size are tested. No md, LVM, reconstruction, image or clone on a 4Kn disk; the GPT relocation (`sfdisk --relocate`) runs only as a stubbed command. | Wrong-geometry copies are silent | QEMU: fixtures built with 4096-byte sectors (`losetup --sector-size`), attached with `logical_block_size=4096` on NVMe; same flows as 2. Hardware: a real 4Kn disk | QEMU, hardware |
| 5 | **No hardware run of anything.** Not tested: hardware RAID controllers (MegaRAID/PERC, Smart Array, ...), VMD/RST, USB bridges, SMART (`smartctl -d sat`, NVMe), AMD RAID on NVMe, a real BitLocker volume. Health is tested on parsed JSON only. | Everything a customer has is hardware | Hardware: Intel RST/VMD, one hardware RAID controller, NVMe, SATA, 4Kn, a USB target. QEMU can add the `megasas` emulation for driver binding only and the emulated NVMe SMART log for `smartctl` | hardware (partly QEMU) |
| 6 | **Reconstruction is proven only for wiped md RAID0 / RAID5 / RAID5 with one missing, and only the candidate parameters are checked** (rank 1, level, chunk, offset, order); the rebuilt array is never imaged or read in QEMU. RAID1/6/10/linear, NTFS on the array, AMD RAIDXpert2 and Storage Spaces metadata are synthetic-unit only. | A wrong guess presented as right | QEMU: image the rebuilt volume and compare file hashes for each wiped fixture; add wiped RAID6, RAID10, RAID1, NTFS volume, a Storage Spaces image. Hardware: an AMD board | QEMU, hardware |
| 7 | **Closed in QEMU on 2026-11-15** (was: Secure Boot and BIOS never run the disk tools). Scan, assembly, image, clone and rescue now run in all three modes, and `e-lock` proves module loading under lockdown (section 2f). Left: reconstruction, restore, health and the text screens run under UEFI only; no real machine has run the tools with Secure Boot on. | A feature that fails closed on SB machines | Hardware: one run with Secure Boot on (covered by gap 5) | hardware |
| 8 | **Encryption and pools.** LUKS1, BitLocker (real volume), btrfs data read (assemble only checks the offered volume), degraded btrfs, ZFS (fixture cannot be built on the current Docker host) and LVM striped / LVM on md are untested beyond stubs. LUKS2 Argon2 memory check untested. | Unlock failures and unreadable data | QEMU: LUKS1 fixture, btrfs file hashes through a read-only mount, LVM striped, LVM on md. BitLocker needs an image made on Windows. ZFS needs a Linux host with the zfs module | QEMU; Windows/ZFS host for two |
| 9 | **Degraded RAID6 / RAID10.** Only RAID1/RAID5 degraded have fixtures. The md metadata part of this gap was closed on 2026-11-15 (0.90, 1.0 and 1.1 fixtures, RAID1 and RAID5). Left for old metadata: 0.90 on a partition that ends at the end of the disk, and degraded arrays. | Common NAS layouts | QEMU: add fixtures in `fixtures/disks.py` and the groups in `GROUPS` | QEMU |
| 10 | **Local text screen: no QEMU run of the Disk tools screens** (image, restore, clone, rescue). No rescue screen test at all. | The operator path most customers use | QEMU: keystrokes through the serial console or QMP `send-key` | QEMU |
| 11 | **RAM cap and low memory.** Overlay and RAM-cap behaviour is unit-only; the helper runs with 2 GiB in `boot_helper` while DISK_TOOLS.md plans for 1 GiB. | Out-of-memory reads of a started stack | QEMU: `memory=1024` with the largest stack and a reconstruction | QEMU |

### Where the docs and the tests disagree

- DISK_TOOLS.md s.7 lists `dm-flakey`/`blkdebug` read-error tests; none exists.
- DISK_TOOLS.md s.8 calls IMSM/DDF "untested" in QEMU; `test_e2e_disks.py` has
  `imsm` and `ddf` groups (written, run status unknown).

## 6. Test keys

Unit tests are under `beastnet/tests/`, QEMU tests in `tests/e2e/test_e2e_disks.py`
(`e-`) and `tests/e2e/test_e2e_disks_copy.py` (`ec-`).

| Key | File::test |
|---|---|
| e-gate | test_e2e_disks.py::test_gate_selftest, ::test_fixture_manifest_is_the_oracle, ::test_helper_boots_with_all_disks_under_the_gate |
| e-manifest | test_e2e_disks.py::test_fixture_manifest_is_the_oracle |
| e-scan | test_e2e_disks.py::test_scan_finds_every_disk_and_marks_the_stick[uefi, bios, uefi-sb] |
| e-det[g] | test_e2e_disks.py::test_stacks_detected[md-a, md-b, md-c, imsm, ddf, lvm, luks, btrfs, md-bitmap, lvm-raid, md-meta-a, md-meta-b]; md-a, md-b, lvm, luks and btrfs also as `[<group>-bios]` and `[<group>-uefi-sb]` |
| e-wipe | test_e2e_disks.py::test_wiped_arrays_are_not_assembled |
| e-asm[g] | test_e2e_disks.py::test_assemble_read_only_and_image[same groups and modes, not lvm-raid]; images md, imsm, ddf, luks groups and checks every file hash; lvm and btrfs only assert `assemble ok ro=1` |
| e-endmeta | test_e2e_disks.py::test_md_member_that_looks_like_ext4_is_not_a_place_for_images[m090-raid1, m10-raid1] |
| e-lock | test_e2e_disks.py::test_modules_load_under_lockdown[uefi-sb] (and `[uefi-no-lockdown]`, the control without Secure Boot) |
| ec-rstop | test_e2e_disks_copy.py::test_rescue_stop_and_resume[uefi, bios, uefi-sb] |
| ec-mbr | test_e2e_disks_copy.py::test_clone_equal_size_target[mbr], ::test_clone_larger_target[mbr] (byte compare with the source) |
| e-lvmraid | test_e2e_disks.py::test_lvm_vg_with_a_raid_lv_is_refused |
| e-rec[a] | test_e2e_disks.py::test_reconstruct_wiped[wiped-raid0, wiped-raid5, wiped-raid5-missing] |
| e-ir | test_e2e_disks.py::test_image_restore_roundtrip |
| e-clone | test_e2e_disks.py::test_clone_disk[uefi, bios, uefi-sb] |
| e-x | test_e2e_disks.py::test_refuse_wrong_confirm, ::test_refuse_smaller_target, ::test_refuse_source_as_target, ::test_refuse_stick_as_target, ::test_refuse_member_of_source_stack_as_target |
| d-scan | test_disks_discover.py::test_scan_finds_every_disk (NVMe, SATA, USB, virtio; 512e) |
| d-mp | test_disks_discover.py::test_nvme_multipath_serial_from_controller |
| h-rules | test_disks_health.py::test_status_rules (17 ata/nvme cases) |
| h-num | test_disks_health.py::test_numbers_and_event, ::test_nvme_wear_in_event, ::test_no_smartctl |
| h-usb | test_disks_health.py::test_usb_bridge_tries_sat_first_then_auto |
| p-md | test_disks_probe.py::test_md_clean_and_degraded_and_incomplete, ::test_md_member_counts (raid1, raid5, raid6 degraded; raid0, raid5, linear incomplete), ::test_md_spare_is_not_counted |
| p-md-part | test_disks_probe.py::test_md_on_partitions |
| p-imsm | test_disks_probe.py::test_imsm_without_intel_controller_needs_no_platform, ::test_imsm_with_intel_raid_controller_does_not_set_the_variable |
| p-ddf | test_disks_probe.py::test_ddf |
| p-lvm | test_disks_probe.py::test_lvm, ::test_lvm_missing_pv, ::test_lvm_on_an_assembled_md_device |
| p-luks | test_disks_probe.py::test_luks_and_bitlocker |
| p-btrfs | test_disks_probe.py::test_btrfs_multi_device_only |
| p-zfs | test_disks_probe.py::test_zfs_needs_pack_until_zpool_exists |
| p-fake | test_disks_probe.py::test_fakeraid, ::test_storage_spaces_by_gpt_type |
| p-ldm | test_disks_probe.py::test_ldm_by_partition_type_is_detect_only |
| p-amd | test_disks_probe.py::test_amd_controller_in_raid_mode_flags_unrecognised_disks and the five other test_amd_* tests |
| a-md | test_disks_assemble.py::test_md_start_is_readonly_and_reports, ::test_md_degraded_uses_run_never_force, ::test_md_read_auto_is_pushed_to_readonly, ::test_md_that_did_not_start_readonly_is_stopped_and_fails, ::test_md_refuses_to_start_when_start_ro_cannot_be_set |
| a-imsm | test_disks_assemble.py::test_imsm_assembles_container_then_volumes_with_no_platform |
| a-imsm-ref | test_disks_assemble.py::test_imsm_with_a_bitmap_or_ppl_is_refused_before_anything_starts[3 variants], ::test_imsm_in_migration_is_refused |
| a-ddf | test_disks_assemble.py::test_ddf_starts_on_overlays |
| a-ov | test_disks_assemble.py::test_md_stop_finds_the_array_on_overlays_and_removes_them, ::test_reconstruction_overlays_are_not_shared, ::test_rescan_does_not_count_overlays_as_members |
| a-stop | test_disks_assemble.py::test_stop_md_refuses_while_mounted_then_stops_arrays_before_container, ::test_stop_luks_closes_the_mapping |
| a-lvm | test_disks_assemble.py::test_lvm_activates_read_only_on_overlays_and_returns_top_level_volumes, ::test_lvm_writable_activation_is_rolled_back |
| a-lvm-ref | test_disks_assemble.py::test_lvm_with_lvs_that_write_on_activation_is_refused[12 segment types], ::test_lvm_unreadable_lv_types_are_refused |
| a-luks | test_disks_assemble.py::test_luks_needs_a_passphrase, ::test_luks_open_is_readonly_and_the_secret_only_goes_to_stdin, ::test_wrong_passphrase_message_does_not_echo_it, ::test_unlocked_device_that_is_writable_is_closed_again |
| a-bl | test_disks_assemble.py::test_bitlocker_uses_bitlk_type |
| a-btrfs | test_disks_assemble.py::test_btrfs_needs_no_assembly |
| a-zfs | test_disks_assemble.py::test_zfs_imports_readonly_without_mounting_or_cachefile, ::test_zfs_without_the_pack_fails_plainly |
| a-ldm | test_disks_assemble.py::test_ldm_is_detect_only[2 variants] |
| a-ref | test_disks_assemble.py::test_unsupported_and_incomplete_stacks_are_refused (AMD, Storage Spaces, other fake RAID, ZFS without pack, incomplete md) |
| a-cmd | test_disks_assemble.py::test_unsafe_commands_are_refused, ::test_read_only_commands_pass, ::test_run_filters_before_anything_executes |
| g-all, g-mw | test_disks_guard.py (all 12; g-mw = test_make_writable_refuses_active_md_member, ::test_make_writable_refusals, ::test_make_writable_partition_only_clears_the_disk_node_and_that_partition) |
| o-all | test_disks_overlay.py (all 7) |
| m-det | test_disks_raidmath.py::test_detect_ranks_the_true_parameters_first (raid0 x2/3/4, raid1 x2/3, raid10 x4/6, raid5 x3/4/5 all four layouts and two with a missing member, raid6 x4/5, linear x2/3, an AMD-like raid0 with GPT + NTFS, a NAS-like raid5 with md 1.2 offset) |
| m-rest | test_disks_raidmath.py::test_missing_member_is_rebuilt_from_parity, ::test_random_data_gives_no_confident_candidate, ::test_real_filesystems_walk_clean_and_are_detected |
| r-build | test_disks_reconstruct.py::test_build_raid0_is_a_readonly_stripe_over_overlays, ::test_build_raid5_runs_md_on_views_never_on_members, ::test_build_and_validate_never_open_a_member_for_writing, ::test_manual_builder_builds_a_mirror_and_a_span, ::test_manual_builder_refuses_impossible_parameters |
| c-run | test_disks_copy.py::test_clone_runs_and_guards, ::test_image_hash_and_bad_area, ::test_identity_mismatch, ::test_exclusive_open_failure_writes_nothing |
| c-bad | test_disks_copy.py::test_image_hash_and_bad_area (stub ddrescue with `STUB_BAD`) |
| c-resume | test_disks_copy.py::test_stop_and_resume |
| c-rb | test_disks_copy.py::test_readback_mismatch |
| c-big | test_disks_copy.py::test_larger_target_relocates_gpt |
| c-part | test_disks_copy.py::test_partition_target, ::test_partition_target_refused_while_a_sibling_is_mounted |
| c-sec | test_disks_copy.py::test_refuses_smaller_and_sector |
| c-info | test_disks_copy.py::test_image_records_its_sector_size_and_restore_checks_it |
| c-plan | test_disks_copy.py::test_refuses_stick, ::test_refuses_source_as_target, ::test_refuses_source_stack_disk, ::test_refuses_no_serial, ::test_refuses_mounted_target, ::test_refuses_holders, ::test_refuses_active_stack_volume, ::test_refuses_target_holding_mapfile |
| c-conf | test_disks_copy.py::test_confirmation |
| c-id, c-excl | test_disks_copy.py::test_identity_mismatch, ::test_exclusive_open_failure_writes_nothing |
| c-dest | test_disks_copy.py::test_image_destination_rules, ::test_mapfile_rules, ::test_restore_rules |
| c-member | test_disks_copy.py::test_member_clone_refused_unless_asked |
| s-parse | test_disks_session.py::test_parse_steps_accepts_the_contract_plan, ::test_parse_steps_refuses_bad_plans, ::test_script_plan_and_cmdline_know_the_disk_action |
| s-man | test_disks_session.py::test_manual_builder_keeps_a_low_score_and_allows_a_missing_member |
| s-clone | test_disks_session.py::test_screens_clone_needs_the_typed_serial (also test_clone_by_serial_with_confirmation for script mode) |
| s-amd | test_disks_session.py::test_screens_amd_set_offers_reconstruction |
| s-scr-err | test_disks_session.py::test_screens_report_errors_and_quit_cleanly, ::test_flow_more_menu_opens_disk_tools |
| s-use, s-from, s-use-ref | test_disks_session.py::test_use_disk_mounts_after_confirmation_and_leave_releases, ::test_restore_from_another_disk_opens_it_read_only, ::test_use_disk_refusals[...] |

## 7. How to run

From `BeastBoot/` after `source scripts/dev-env.sh`. `make test` runs
`installer/tests`, `tests/menu` and `beastnet/tests`.

| What | Command | Needs |
|---|---|---|
| Disk tools and UI unit tests | `pytest -q beastnet/tests` (disk part: `pytest -q beastnet/tests -k "disks or ui"`) | nothing special, seconds |
| Fixture check / build / list | `python tests/e2e/fixtures/disks.py needs`, `... build` (about 3 minutes, cached by recipe hash in `.tools/cache/disk-fixtures/`, override `BB_DISK_FIXTURE_CACHE`), `... list` | **Linux**, `docker run --privileged` |
| Helper build for QEMU | `make keys && make build` | Linux (on macOS the Makefile runs it in the build container) |
| Disk tools QEMU end to end | `pytest -q tests/e2e/test_e2e_disks.py` (another helper: `BB_E2E_DIST=<dist>`) | **Linux with KVM**, the fixtures, a built `dist/`; skips with a reason otherwise |
| Whole BeastBoot QEMU suite (BIOS, UEFI, Secure Boot) | `make e2e` (= `pytest -q tests/e2e`) | Linux; KVM for the speed |
