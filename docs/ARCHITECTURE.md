# BeastBoot architecture

BeastBoot turns a USB drive into a multi-boot drive that stays usable as
normal storage. You copy `.iso` files onto it like any other files; when you
boot from it, a menu lists the ISOs (and lets you browse folders) and boots the
one you pick. It works on legacy BIOS, UEFI, and UEFI with Secure Boot enabled.

This document is the contract between the components. The numeric layout lives
in code in [`installer/beastbooter/layout.py`](../installer/beastbooter/layout.py);
if this document and that file disagree, the file wins and this document is a bug.

## 1. Principles

1. **Transparent.** Every file that ends up on the drive is either built from
   source in this repo, built from pinned, SHA-256-checked source (GRUB:
   Ubuntu's grub2 source package + `build/grub/patches`, see
   docs/SECURE_BOOT.md), or copied unmodified from a named distribution
   package, and recorded (with its SHA-256 and origin) in `dist/manifest.json`.
   No unexplained binaries.
2. **Secure Boot is respected, never weakened.**
   - BeastBoot never disables, patches, hooks or overrides firmware or shim
     signature verification. Everything loaded after shim is verified by shim
     against the firmware `db`, the MOK list, or shim's built-in vendor cert.
   - BeastBoot never ships known-vulnerable or revoked signed binaries.
   - The SBAT metadata in our GRUB truthfully describes the GRUB code we ship
     (copied from the matching distribution build) plus our own product line.
   - Trusting the BeastBoot key requires the user to enroll it themselves in
     MokManager, which requires physical presence at the machine (shim design).
   - The shim (Debian's) trusts Debian's key, not Canonical's. Trusting
     Ubuntu's key is opt-in ("Trust Ubuntu's Secure Boot key"): the helper only
     *requests* it with mokutil, Ubuntu's revocations (MokListX) before
     Canonical's CA (MokList), and the user confirms each step in MokManager.
     It never touches the firmware's db/dbx (`build/trust/README.md`).
   - An ISO whose kernel is not signed by a trusted key **fails closed**: the
     menu explains why and what the user can do (trust Ubuntu's key for
     Ubuntu-signed kernels, enroll that distro's key via MokManager, or turn
     Secure Boot off). It does not try to work around it.
3. **The drive stays normal storage.** Partition 1 is a plain exFAT (or
   FAT32/NTFS) filesystem that any OS can mount and write. Updating
   BeastBoot rewrites only the boot area and partition 2, never partition 1.
4. **Boring, auditable code.** Installer (CLI and Tkinter GUI) and `bb-dev`:
   Python 3.10+ standard library only. Menu: plain GRUB script. Build: bash.
   No network access at install time; the only command that downloads is
   `firmware fetch`, on the user's request, from pinned URLs checked against
   pinned SHA-256s.

## 2. Boot flows

```
UEFI (Secure Boot on or off)
  firmware -> ESP:\EFI\BOOT\BOOTX64.EFI   shim 16.1, Microsoft-signed through UEFI CA 2011 and 2023
                                         (from Debian shim-signed, docs/SECURE_BOOT.md §1)
           -> ESP:\EFI\BOOT\grubx64.efi   beast-boot GRUB, signed with the beast-boot key
                (first boot with SB on and key not enrolled: shim shows a verification
                 error and starts MokManager (mmx64.efi); the user picks
                 "Enroll key from disk" -> ENROLL_THIS_KEY_IN_MOKMANAGER.cer -> reboot)
           -> /grub/grub.cfg on the ESP -> beast-boot menu (grub/beast/*.cfg)
           -> selected ISO: kernel verified by shim (SB on), then booted

Legacy BIOS
  firmware -> MBR boot.img -> core.img (MBR gap, or GPT BIOS boot partition)
           -> /grub/grub.cfg on the ESP (modules from /grub/i386-pc/) -> same menu

beast-net ("Download an ISO from a link", docs/BEASTNET.md), any mode
  menu -> linux ESP:/beast-net/vmlinuz (Ubuntu's kernel, re-signed with the beast-boot
          key, verified by shim with SB on) + initrd ESP:/beast-net/initrd.img [+ firmware/*.cpio]
       -> download to DATA:/downloads/ -> bb_oneshot=<path> in ESP:/grub/grubenv
       -> reboot -> menu boots <path> once, through the normal recipes

"Trust Ubuntu's Secure Boot key" (UEFI, docs/BEASTNET.md §8)
  menu -> same helper with beastnet.action=trust-ubuntu
       -> mokutil request (MokXNew: Ubuntu's revoked certs, or, once all are in MokListX,
          MokNew: Canonical's Master CA) -> reboot -> shim starts MokManager -> user confirms
```

The EFI GRUB image has every module it needs embedded (with Secure Boot on,
GRUB lockdown forbids loading modules from disk). It is built with prefix
`/grub`, so GRUB uses the ESP it was loaded from as `$root`.

The BIOS core.img is built with prefix `(,msdos2)/grub` and an embedded early
config (`build/early-bios.cfg`). That config runs in GRUB's rescue parser, which
has no `if` and no comments, so it probes the partition map of partition 2 on
the boot disk and sets `root`/`prefix` to `msdos2` or `gpt2` accordingly. One
core.img serves both partition table styles.

## 3. Disk layout

See the docstring in `layout.py`. Summary:

| Part | Role | Size | FS | MBR type | GPT type |
|---|---|---|---|---|---|
| 1 | DATA (storage + ISOs), label `BEASTBOOTER` | rest of disk | exFAT (default), FAT32, NTFS | 0x07 (exFAT/NTFS), 0x0C (FAT32), active flag | Microsoft basic data |
| 2 | ESP, label `BEAST-EFI` | 512 MiB at end, end aligned to 1 MiB (layout 2) | FAT32 | 0xEF | EFI System |
| 3 | BIOS boot (GPT only) | LBA 34–2047 | none (raw core.img) | – | BIOS boot |

Data filesystem and Secure Boot: GRUB 2.14 disables its NTFS driver in lockdown
mode, so an NTFS data partition is invisible when Secure Boot is on (the menu
says so). exFAT (default) and FAT32 work in every mode. Recommend NTFS only for
BIOS / Secure-Boot-off use.

BIOS boot code placement:

- MBR: core.img at LBA 1 (max 2047 sectors). GPT: core.img at LBA 34 (max 2014 sectors).
- `boot.img` bytes 0..439 are written to LBA 0 (the partition table is preserved).
  Patch `boot.img[0x5C..0x64)` = core LBA (u64 LE) and `boot.img[0x66..0x68)` = `90 90`.
- Patch core.img sector 0 blocklist at `0x1F4`: start = core LBA + 1 (u64 LE),
  count = core sectors − 1 (u16), segment = 0x0820 (u16).
- GPT: the protective MBR entry gets the active flag (needed by many BIOSes).

## 4. Build output: `dist/`

`build/build.sh` produces:

```
dist/
  manifest.json
  bios/boot.img              stock GRUB i386-pc boot.img (512 bytes)
  bios/core.img              GRUB i386-pc core image (see §2)
  esp/                       copied verbatim into the ESP root
    EFI/BOOT/BOOTX64.EFI     Debian's shim 16.1 (Microsoft-signed, UEFI CA 2011 + 2023)
    EFI/BOOT/mmx64.efi       Debian's MokManager (signed through shim's Debian key)
    EFI/BOOT/grubx64.efi     beast-boot GRUB x86_64-efi: all modules embedded, SBAT,
                             memdisk with the menu fonts (see below), signed
    ENROLL_THIS_KEY_IN_MOKMANAGER.cer   beast-boot signing cert (DER)
    grub/grub.cfg            from repo grub/grub.cfg
    grub/beast/*.cfg         from repo grub/beast/
    grub/beast/version.cfg   generated: set bb_version=...  set bb_build_id=...
    grub/themes/beast/       graphical theme: theme-{efi-sb,efi,pc}.txt, console.cfg,
                             PNG images, all drawn by build/theme/mktheme.py
    grub/fonts/*.pf2         NotoSans-{Regular-16,Regular-20,Bold-20}, NotoSansMono-Regular-16
                             (grub-mkfont from fonts-noto-core/-mono), unicode.pf2 (GRUB)
    grub/i386-pc/*.mod *.lst BIOS GRUB modules
    beast-net/vmlinuz        Ubuntu's kernel, re-signed with the beast-boot key (code unchanged)
    beast-net/initrd.img     helper initramfs (build/beastnet/, docs/BEASTNET.md §5)
    beast-net/VERSION        "beast-net <bb version> kernel <kver>"
    beast-net/catalog.json   firmware pack catalog (docs/BEASTNET.md §6)
    beast-booter/wimboot     iPXE's wimboot (Windows PE loader), built from its pinned release
                             source + our patches (build/wimboot/); one x86_64 hybrid image for
                             BIOS (GRUB linux16) and UEFI (GRUB linux); signed with the BeastBoot key
    beast-booter/winpe/      winpeshl.ini, beastboot.cmd: the Windows PE start-up files the menu
                             injects with wimboot (build/winpe/, CRLF line endings)
```

There is deliberately **no** `fbx64.efi` in `EFI/BOOT/`: shim would run the
fallback loader and create firmware boot entries on the user's machine.

Fonts and Secure Boot: under lockdown GRUB loads fonts only from the memdisk
of its own (shim-verified) image, so the Noto `.pf2` files are also packed
into a deterministic tar (`build/theme/mkmemdisk.py`) embedded in
`grubx64.efi` with `grub-mkimage -m`; the manifest records its member list
and SHA-256 (`build.efi_memdisk`, `build.efi_memdisk_sha256`). The copies in
`grub/fonts/` serve legacy BIOS. Theme files and PNGs load from the ESP in
every mode. `BB_SKIP_BEASTNET=1` builds without `beast-net/`; the menu then
hides its entry.

wimboot and Secure Boot: our wimboot is patched (on UEFI it takes the files
GRUB passes with `initrd newc:...` through LoadFile2, see
build/wimboot/README.md) and signed by the build with the BeastBoot key (the
one that signs GRUB; manifest `secure_boot.wimboot_unsigned_sha256` is the
image without its signature). GRUB cannot read UDF under Secure Boot, so the
menu boots a copy of the ISO's `boot.wim` from
`($data)/beast-booter/winboot/<iso>/` (made once by the helper action
`winboot` or by `beast-boot prepare-windows`); see
[WINDOWS_SECURE_BOOT.md](WINDOWS_SECURE_BOOT.md). With Secure Boot off the
menu reads the ISO directly.
`beast-booter/winpe/beastmount.exe` (attaches the ISO in Windows PE) is our
own program, built reproducibly with pinned MinGW-w64 packages
(build/winpe/beastmountsrc.py). `BB_SKIP_WIMBOOT=1` builds without `beast-booter/`.

The installer adds to the ESP, outside `dist/`: `BEAST-BOOTER.ID` (install
id and layout version), `grub/beast/device.cfg` (§5), `grub/grubenv` (1024
bytes, §5) and, through `firmware install`, `beast-net/firmware/<id>.cpio`
plus `installed.json`. `update` keeps `device.cfg` values, `grubenv` and the
firmware packs.

`manifest.json` (schema 1):

```json
{
  "schema": 1,
  "name": "beast-boot",
  "version": "0.3.0",
  "source_date_epoch": 1760000000,
  "secure_boot": {
    "cert_sha256": "<sha256 of the DER cert>",
    "cert_subject": "CN=...",
    "sbat": "<exact .sbat CSV embedded in grubx64.efi>"
  },
  "files": {
    "esp/EFI/BOOT/BOOTX64.EFI": {"sha256": "...", "size": 1088816,
       "origin": "deb:shim-signed=1.51+16.1-2:/usr/lib/shim/shimx64.efi.signed"},
    "esp/EFI/BOOT/grubx64.efi": {"sha256": "...", "size": 0,
       "origin": "built:grub-mkimage from grub-src:grub2=2.14-2ubuntu3+bb1:/x86_64-efi + memdisk (build.efi_memdisk), signed:beast-boot"},
    "esp/grub/i386-pc/normal.mod": {"sha256": "...", "size": 0,
       "origin": "grub-src:grub2=2.14-2ubuntu3+bb1:/i386-pc/normal.mod"},
    "esp/grub/beast/main.cfg": {"sha256": "...", "size": 0, "origin": "repo:grub/beast/main.cfg"}
  }
}
```

`files` lists every file under `dist/` except `manifest.json`. The installer
refuses to write if a file is missing or its SHA-256 does not match.

The build also records `build_id`, a `build{}` section (tool and package
versions; for GRUB, which is built from source by `build/grub/grubsrc.py`:
`grub_version`, `grub_build_key`, `grub_build_info_sha256`, `grub_source`,
`grub_patches`, `grub_toolchain`; for wimboot, built by
`build/wimboot/wimbootsrc.py`: `wimboot_version`, `wimboot_build_key`,
`wimboot_build_info_sha256`, `wimboot_source`, `wimboot_patches`,
`wimboot_toolchain`), and in `secure_boot`: `cert_sha1` (what
MokManager shows), `sbat_version_check`, `sbat_source`, `grub_security_fixes`,
`shim_sbat_level_latest`, `shim_signers`, `shim_authenticode_sha256`,
`shim_distro`, `grub_unsigned_sha256` and, for the re-signed helper kernel,
`beastnet_kernel_source`, `beastnet_kernel_authenticode_sha256`,
`beastnet_kernel_unsigned_sha256`, `beastnet_kernel_replaced_signers` and `wimboot_unsigned_sha256` (wimboot is signed with the BeastBoot key). A `grub-src:` origin names
a file of that GRUB build; gen_sbom.py and scan_vulns.py check it against the
build's `build-info.json`. A `wimboot-src:wimboot=<version>:/wimboot` origin
names the file of the wimboot build; gen_sbom.py checks it the same way. `sbsign` embeds a signing time, so a re-signed
`grubx64.efi` differs byte-wise; the build keeps the existing signature when the
unsigned image is unchanged (`BB_RESIGN=1` forces a new one), and
`build/verify-dist.sh --rebuild` checks that the unsigned image and `core.img`
rebuild byte-identically.

## 5. GRUB runtime contract

Files on the ESP, sourced in this order by `grub/grub.cfg`:

1. `$prefix/beast/version.cfg` (build) — `bb_version`, `bb_build_id`.
2. `$prefix/beast/device.cfg` (installer, may be missing) — see below.
3. `$prefix/beast/main.cfg` — the menu. It locates the data partition, then
   reads the optional user settings **from the data partition**, then shows
   the menu (or autoboots, see below): `/beast-booter/config.env`, a GRUB
   environment block read with `load_env` and an allow-list of names, then
   `/beast-booter/config.cfg`, GRUB script, sourced only with Secure Boot
   off. With Secure Boot on, `config.cfg` is ignored: anyone who can write
   the drive could otherwise run GRUB commands in lockdown and choose the
   arguments of signed kernels and loaders. `bb_sb` comes from GRUB's
   `lockdown` before and again after the settings, so no setting can change
   it ([MENU.md](MENU.md#user-configuration-configenv-and-configcfg)).

`device.cfg`, written by the installer (GRUB script, `set` lines only):

```
set bb_install_id="6f1c...-uuid4"
set bb_layout="msdos"                # msdos | gpt
set bb_data_fs="exfat"               # exfat | fat32 | ntfs
set bb_data_uuid="1A2B-3C4D"         # as GRUB 2.14 `probe --fs-uuid` prints it (uppercase, same as blkid)
set bb_data_uuid_linux="1A2B-3C4D"   # as blkid / /dev/disk/by-uuid shows it, for kernel cmdlines
set bb_data_label="BEASTBOOTER"
set bb_serial="0"                    # 1 = also use serial console (installer --serial-console)
```

Data partition discovery (`main.cfg`): `search --no-floppy --fs-uuid --set=bb_data $bb_data_uuid`;
if that fails or `device.cfg` is missing, use partition 1 of the disk holding the ESP
(`$root` with the partition number replaced by 1).

Variables the menu sets and other scripts may read:

| Variable | Meaning |
|---|---|
| `bb_esp` | GRUB device of the ESP, e.g. `hd0,msdos2` |
| `bb_data` | GRUB device of the data partition, e.g. `hd0,msdos1` |
| `bb_platform` | `efi` or `pc` (copy of `grub_platform`) |
| `bb_sb` | `1` when GRUB is in lockdown (Secure Boot on), else `0` |
| `bb_path` | directory currently being browsed, `/` = data root, no trailing slash except root |

User/test settings (may be set in the user config on the data partition):

| Variable | Effect |
|---|---|
| `timeout` | standard GRUB menu timeout (default: none, wait for the user) |
| `bb_debug=1` | print machine-readable `BEAST:` lines (below) |
| `bb_dryrun=1` | do everything except the final hand-off: print what would be run and return to the menu |
| `bb_autoboot=/path/x.iso` | skip the menu and boot that ISO immediately |
| `bb_serial=1` | mirror the menu on serial port 0 at 115200 8N1 |
| `bb_gfx=0` | text menu only; default: graphical menu when a graphics mode, theme and fonts are usable |
| `bb_gfxmode=WxH[,...]` | GRUB `gfxmode` list for the graphical menu (default `1920x1080,1280x720,1024x768,auto`) |
| `bb_theme=/path/theme.txt` | GRUB theme file on the data partition instead of `grub/themes/beast/` |
| `bb_beastnet_script=/path` | pass `beastnet.script=/path` to the beast-net helper: a non-interactive JSON plan on the data partition (docs/BEASTNET.md §5) |

`main.cfg` loads these after the data partition is found; the same `set`
lines are also honoured in `device.cfg` (values from the user config win).
Details: docs/MENU.md.

One-shot hand-off (`ESP:/grub/grubenv`, standard 1024-byte GRUB environment
block, created by the installer): before the menu is built, `main.cfg` runs
`load_env` for `bb_oneshot`. If it is set, it clears it with `save_env` and,
only if that succeeded, boots that path like `bb_autoboot`; otherwise it
prints `BEAST: error oneshot-not-cleared <path>` and shows the menu, so a
failing ISO can never cause a reboot loop. Only the beast-net helper sets
`bb_oneshot`.

Machine-readable output when `bb_debug=1` (one per line, exact prefix `BEAST: `):

```
BEAST: ready version=<v> platform=<efi|pc> sb=<0|1> esp=<dev> data=<dev> fs=<fs>
BEAST: dir <path>
BEAST: item dir <path>
BEAST: item iso <path>
BEAST: oneshot <iso path>
BEAST: boot <iso path> recipe=<recipe id>
BEAST: fsmod exfat <module path>          (exFAT add-on used, §6)
BEAST: fsmod none <reason> [<squashfs>]   (exFAT add-on not used: disabled, hook-missing,
                                           no-squashfs, squashfs-unreadable, no-exfat-module)
BEAST: boot beast-net recipe=beast-net
BEAST: dryrun linux <kernel path> <cmdline...>
BEAST: dryrun initrd <path> [<path>...]
BEAST: dryrun configfile <path>
BEAST: dryrun chainloader <path>
BEAST: error <code> <free text>
```

Error codes: `no-data-partition`, `iso-not-found`, `loopback-failed`,
`no-recipe`, `ntfs-unsupported`, `windows-sb-no-helper`, `windows-bad-name`, `windows-no-wimboot`, `grubenv-not-writable`, `iso-too-large`,
`sb-verify-failed`, `boot-failed`, `oneshot-not-cleared`.

## 6. ISO boot recipes

The ISO is attached with `loopback loop ($bb_data)<path>`. Detection runs in
this order; the first match wins. `<path>` is the ISO path on the data
partition (starts with `/`), `<uuid>` is `bb_data_uuid_linux`, `<label>` is the
ISO's volume label (`probe --label (loop)`).

| # | Recipe id | Detect (file inside ISO) | Kernel / initrd | Kernel command line |
|---|---|---|---|---|
| 1 | `loopback` | `/boot/grub/loopback.cfg` | – | set+export `iso_path=<path>`, `root=loop`, `configfile /boot/grub/loopback.cfg` |
| 2 | `casper` | `/casper/vmlinuz` | `/casper/vmlinuz` / first of `/casper/initrd`, `initrd.lz`, `initrd.gz`, `initrd.img` | `boot=casper iso-scan/filename=<path> quiet splash ---` |
| 3 | `live-boot` | `/live/vmlinuz` | `/live/vmlinuz` / `/live/initrd.img` | `boot=live findiso=<path> components quiet splash` |
| 4 | `archiso` | `/arch/boot/x86_64/vmlinuz-linux` | that / `/arch/boot/x86_64/initramfs-linux.img` | `archisobasedir=arch archisolabel=<label> img_dev=/dev/disk/by-uuid/<uuid> img_loop=<path>` |
| 5 | `dracut-live` | `/LiveOS/squashfs.img` and `/images/pxeboot/vmlinuz` | `/images/pxeboot/vmlinuz` / `/images/pxeboot/initrd.img` | `root=live:CDLABEL=<label> rd.live.image iso-scan/filename=<path> quiet` |
| 6 | `anaconda` | `/images/pxeboot/vmlinuz` (no `/LiveOS`) | same as above | `inst.stage2=hd:UUID=<uuid>:<path> quiet` |
| 7 | `suse` | `/boot/x86_64/loader/linux` | that / `/boot/x86_64/loader/initrd` | `isofrom_device=/dev/disk/by-uuid/<uuid> isofrom_system=<path> splash=silent` |
| 8 | `windows` | `/sources/boot.wim` and (`/bootmgr` or `/efi/microsoft/boot/bcd`) | `($esp)/beast-booter/wimboot` / `newc:boot.wim:(loop)/sources/boot.wim` + the Windows PE start-up files | Secure Boot on: boots the prepared copy `newc:boot.wim:$bb_wb_dir/boot.wim` (record `windows mode=<m> copy=<dir>`); an unprepared UDF-bridge ISO gets the "Prepare this Windows ISO for Secure Boot" entry (`windows-prepare`), or `windows-sb-no-helper` without the helper. Install media (`/sources/install.wim`, `.esd`, `.swm`): menu `windows.cfg` (Windows Setup, default; or Windows PE `index=1`), ISO path and mode saved to `grub/grubenv` for `beastboot.cmd`; other `boot.wim` ISOs as they are. BIOS `linux16`/`initrd16`, UEFI `linux`/`initrd` (tests/e2e/REAL_ISOS.md "Windows") |
| 9 | `efi-chainload` | UEFI only: `/EFI/BOOT/BOOTX64.EFI` (any case) | – | `chainloader (loop)/EFI/BOOT/BOOTX64.EFI`, with a warning that many ISOs cannot find their files this way |
| – | none | – | – | `BEAST: error no-recipe ...` and explain |

Recipes 2–7 need the ISO's own initramfs to be able to mount the data
partition's filesystem in order to find the ISO file. FAT32 is universally
supported; exFAT and NTFS depend on the distribution. docs/ISO_SUPPORT.md
tracks what is known. A filesystem-independent mapping (a small initramfs
add-on that maps the ISO's sectors as a block device) is planned for later.

**exFAT add-on** (`bb_addon_prepare` in `grub/beast/lib.cfg`). When the data
partition is exFAT and the ISO is a casper ISO (`/casper/vmlinuz`) or a
live-boot ISO (`/live/vmlinuz` and `/live/initrd.img`), detected as that
recipe or as `loopback`:

1. The first of `/casper/minimal.squashfs`, `/casper/filesystem.squashfs`,
   `/live/filesystem.squashfs` is attached as `loopback bbsq`.
2. The first `(bbsq)/usr/lib/modules/*/kernel/fs/exfat/exfat.ko{.zst,.xz,.gz,}`
   (else under `/lib/modules`) is the module. It is the ISO's own, built and
   signed for the ISO's kernel.
3. The initrd line becomes `initrd <iso initrd>
   newc:beast-boot/modules/<module file>:<module path>
   newc:conf/conf.d/zz-beastbooter.conf:$bb_cfg/hooks/initramfs-tools.sh`.
   A `loopback` ISO switches to the casper / live-boot recipe for this,
   because its `loopback.cfg` would load the initrd without the add-on.
4. initramfs-tools' `/init` sources every `/conf/conf.d/*` file before the
   boot scripts. The hook loads the module with kmod (klibc's `insmod`
   cannot load compressed modules) and, when exfat is then in
   `/proc/filesystems`, appends a wider `is_supported_fs` to casper's
   `/scripts/casper-helpers` (casper only mounts types from a fixed list;
   live-boot already accepts anything in `/proc/filesystems`).

GRUB's squash4 reads gzip, lzo and xz squashfs, not zstd; such ISOs keep the
old behaviour (`fsmod none squashfs-unreadable`). `bb_fs_addon=0` turns the
add-on off. Nothing on the drive or in the ISO is modified, and the kernel
still checks the module signature (lockdown under Secure Boot).

## 7. Installer CLI

Package `installer/beastbooter`, run as `python3 -m beastbooter`,
`bin/beast-boot`, or `installer/beast_booter_launch.py` (self-contained
entry point of the portable packages; `--gui` as first argument starts the
Tkinter GUI in `beastbooter/gui/`). Every command has `--help`.

```
beast-boot install (--device DEV | --image PATH --size SIZE)
                     [--layout msdos|gpt] [--fs exfat|fat32|ntfs] [--label LABEL]
                     [--serial-console] [--dist DIR|ZIP] [--yes] [--allow-fixed-disk]
                     [--quiet] [--progress-file PATH] [--cancel-file PATH]
beast-boot update  (--device DEV | --image PATH) [--dist DIR|ZIP] [--yes]
                     [--allow-fixed-disk] [--quiet] [--progress-file PATH] [--cancel-file PATH]
beast-boot info    (--device DEV | --image PATH) [--json]
beast-boot list-devices [--json] [--all] [--check-installed]
beast-boot firmware catalog [--dist DIR|ZIP] [--catalog FILE] [--json]
beast-boot firmware fetch   --pack ID [--pack ID ...] --out DIR [--catalog FILE] [--dist DIR|ZIP]
beast-boot firmware install (--device DEV | --image PATH) --from DIR [--dist DIR|ZIP]
beast-boot firmware remove  (--device DEV | --image PATH) --pack ID
beast-boot firmware list    (--device DEV | --image PATH) [--json]
```

- `DEV` is a whole disk: `/dev/sdX` (Linux), `/dev/diskN` (macOS),
  `\\.\PhysicalDriveN` or `N` (Windows), as `list-devices` prints it.
- `--size` accepts `1G`, `8G`, or a byte count (minimum 1 GiB).
- `install` destroys everything on the target. On a device it refuses unless
  the target is a whole-disk device that holds no system filesystem (`/`,
  `/boot`, `/boot/efi`, ...), no active swap and nothing held by
  device-mapper/LVM/LUKS/RAID or a loop device (any other mounts on the target
  are unmounted by `prepare()`; a busy one fails with `busy`), and is
  removable or attached via USB/SD (override with `--allow-fixed-disk`). It
  shows model and size and asks the user to type the device name unless
  `--yes`. Details per OS: `platforms/` and `device.py`.
- `update` rewrites boot code + partition 2 from a newer `dist/`, keeping
  `device.cfg` values, `grub/grubenv` and the installed firmware packs, and
  never writing partition 1 (it writes through a target that only allows the
  boot area and the ESP). It refuses a drive of another layout version:
  `reinstall-needed` (older) or `layout-too-new` (newer).
- `list-devices --json` prints `{"v": 1, "platform": ..., "elevated": ...,
  "disks": [{...DiskInfo..., "eligible": true|false, "reason": ...}]}`; without
  `--all` only eligible (removable, non-system) disks are listed. With
  `--check-installed` each disk also gets `"installed"`: `null` (not a
  BeastBoot drive) or `{"version", "build_id", "state", "summary", "note"}`,
  read without administrator rights by `PlatformBackend.probe_installed`
  (`installed.py`, `installed_probe.py`; Linux mounts partition 2 read-only
  with udisks for a moment and unmounts it again). `state` is one of
  `current`, `outdated`, `other-build`, `newer`, `reinstall`, `unknown`.
- `info --json` includes `build_id` (from `grub/beast/version.cfg`).
- An `update` that the drive interrupts (Linux: the stick reports "no medium",
  `device-vanished`) can be re-run: the ESP's boot sector is written zeroed
  first and for real last, and a copy of what update carries over (marker,
  `device.cfg`, `grubenv`, firmware packs) is kept on the computer
  (`state_dir()`, `update-recovery/`) until the update is verified.
- `firmware fetch` needs no administrator rights: it downloads each file of a
  pack from the catalog's pinned source, checks its SHA-256 and writes
  `DIR/<id>.cpio` and `DIR/<id>.json`. `firmware install` re-verifies every
  file inside each cpio against the catalog before writing it to the ESP.
  These commands never erase anything (`--yes` is accepted for symmetry).
  Contract: docs/BEASTNET.md §6.
- `info --json` prints:

```json
{"layout": "msdos", "layout_version": 2, "version": "0.3.0", "install_id": "...",
 "disk_sectors": 2097152, "bios_core_lba": 1,
 "data": {"index": 1, "start_lba": 2048, "size_lba": 1046528, "fs": "fat32",
          "uuid": "96BC-D565", "label": "BEASTBOOTER"},
 "esp":  {"index": 2, "start_lba": 1048576, "size_lba": 1048576}}
```

**Progress and cancel** (used by the GUI, which runs the CLI elevated):
`--progress-file PATH` appends JSON-lines events, each with `"v": 1`:
`start` (`action`, `target`), `step` (`step`, `message`, `pct`), `warning`,
`done` (`ok`, `info` = the `info --json` object) and `error` (`code`,
`message`). Step ids: `verify-dist`, `check-target`, `prepare`, `partition`,
`format-data`, `write-esp`, `boot-code`, `flush`, `rescan`, `verify-write`,
and for `firmware`: `download`, `verify-packs`, `write-firmware`. The schema
is in `interfaces.py`. `--cancel-file PATH`: the command stops cleanly once
PATH exists, checked between steps and while writing (error event
`cancelled`, exit status 130); SIGINT and SIGTERM do the same.

**Dist lookup**: `--dist` (a `dist/` directory or a `.zip` of one) >
`$BEAST_BOOTER_DIST` > the portable package's `payload/dist` (GUI) >
`<repo>/dist`. The installer refuses to write when a file is missing,
unlisted or has the wrong SHA-256 (`dist.py`, `load_dist`).

The installer writes everything itself, in pure Python, on Linux, Windows and
macOS: partition tables (`parttable.py`), FAT16/FAT32 (`fatfs.py`) and exFAT
(`exfatfs.py`), through a block target (`blockio.py`; per-OS raw device access
in `platforms/`). Images are created rootless. Only NTFS uses the OS's own
formatter (Linux `mkfs.ntfs`, Windows Format-Volume; refused on macOS).
Firmware pack cpio archives are written by `cpio.py`.

## 8. Repository layout and ownership

```
installer/beastbooter/   installer package (layout.py = layout contract,
                         interfaces.py = CLI/GUI/platform interfaces, gui/ = Tkinter GUI)
installer/beast_booter_launch.py   self-contained CLI/GUI entry point (portable packages)
installer/tests/         installer and GUI unit tests (pytest)
grub/                    menu scripts -> dist/esp/grub/
build/                   build.sh, module lists, SBAT template, keygen, verify-dist.sh,
                         Containerfile; theme/ (mktheme.py, mkmemdisk.py);
                         beastnet/ (helper build: packages, modules, initramfs, catalog)
beastnet/                beast-net helper app: python/beastnet/, rootfs/ (/init), tests/
keys/                    local signing keys (private keys are git-ignored)
bin/                     beast-boot (installer), bb-dev (developer helpers)
devtools/                bbdev/ (bb-dev), gdb/ (GRUB gdb helpers), tests/
tests/e2e/               QEMU end-to-end tests and fixture ISO builders
packaging/portable/      portable packages: build.py, launchers, runtimes.lock,
                         verify_package.py, ci/
scripts/                 bootstrap-tools.sh (rootless toolchain), dev-env.sh, dev-setup.sh,
                         lint.sh, build_portable.sh, sbom-vuln.sh + gen_sbom.py,
                         validate_sbom.py, scan_vulns.py, install-tools.sh; release/
sbom/                    vex.openvex.json (triage decisions); generated reports are git-ignored
docs/                    this file and the other documentation
.github/workflows/       CI: portable packages, releases (tag vX.Y.Z)
.claude/skills/sbom-vuln/  the SBOM / vulnerability workflow (Claude Code skill)
.vscode/, .devcontainer/ editor tasks and debug configurations; dev container
```

Make targets: `tools`, `keys`, `build`, `test`, `image`, `e2e`, `dev`,
`doctor`, `dev-image`, `vm`, `vm-sb`, `menu-sync`, `lint`, `sbom`, `vulns`,
`portable`, `release`, `clean` (`make help` describes them).

Environment variables:

| Variable | Used by | Meaning |
|---|---|---|
| `BB_ROOT` | all | repository root (set by `scripts/dev-env.sh`) |
| `BB_SHIM_DIR`, `BB_OVMF_DIR`, `BB_SEABIOS_DIR` | build, tests, bb-dev | package directories; `scripts/dev-env.sh` prefers the system location, else `.tools/root/...` (`BB_SHIM_DIR`: Debian's pinned shim in `$BB_DEBIAN_DIR/root/usr/lib/shim` first, `build/shim/`); a value set before sourcing wins |
| `BB_GRUB_EFI_DIR`, `BB_GRUB_BIOS_DIR`, `BB_GRUB_EFI_SIGNED_DIR` | tests, bb-dev (not build.sh) | GRUB module directories, by default the last GRUB source build (`.tools/cache/grub-src/current/<platform>`); Ubuntu's signed GRUB only for the e2e stub images |
| `BB_GRUB_BUILDER`, `BB_GRUB_CACHE` | build/grub/grubsrc.py | `auto` (native, else docker), `native` or `docker`; cache directory (default `.tools/cache/grub-src`) |
| `BB_GRUB_DBG_DIR`, `BB_GRUB_PC_DBG_DIR`, `BB_GRUB_EFI_DBG_DIR` | bb-dev gdb | GRUB debug symbols (default `.tools/grub-dbg`) |
| `BB_MENU_DIR`, `BB_KEY_DIR`, `BB_DIST_DIR` | build.sh | menu source, signing key and output directories |
| `BB_PROJECT_URL` | build.sh | URL in the `grub.beastbooter` SBAT line |
| `SOURCE_DATE_EPOCH` | build.sh, portable build | timestamps (default: last git commit time, else mtime of `VERSION`) |
| `BB_RESIGN=1` | build.sh | always make a fresh signature (§4) |
| `BB_NOTO_DIR` | build.sh | Noto `.ttf` fonts for the graphical menu |
| `BB_SKIP_BEASTNET=1` | build.sh | build without `beast-net/` |
| `BB_BEASTNET_CACHE`, `BB_FIRMWARE_CACHE`, `BB_BEASTNET_APP`, `BB_OFFLINE=1`, `BB_BEASTNET_REVERIFY=1` | build/beastnet/build.sh | caches, app directory, offline mode, re-download every catalog file (header of that script) |
| `BEAST_BOOTER_DIST` | installer | default boot files (see Dist lookup) |
| `BB_PBS_CACHE` | packaging/portable/build.py | portable runtime cache (default `.tools/cache/pbs`) |
| `BB_GUI_TEST_DISPLAY` | installer/tests | X display for the real Tk window tests |
| `BB_E2E_*` | tests/e2e | see tests/e2e/README.md |
