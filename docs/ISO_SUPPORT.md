# ISO support

BeastBoot boots an ISO file straight from the data partition: GRUB opens
the file as a loop device (`loopback loop (<data>)<path>`), looks inside it
to decide which **recipe** applies, and then starts the ISO's own kernel with
a command line that tells the ISO's initramfs where to find the ISO file
again. Nothing is extracted or copied. The recipes are specified in section 6
of [ARCHITECTURE.md](ARCHITECTURE.md) and implemented in
[`grub/beast/lib.cfg`](../grub/beast/lib.cfg).

Status words used below:

- **tested**: checked with the BeastBoot test fixtures (fake ISOs that have
  the right files but dummy kernels). This proves the detection and the
  command line, not that the distribution then boots.
- **expected**: what the distribution's documentation or boot scripts say
  should work. Not yet tried with real ISOs by this project.
- **unverified**: our best understanding, likely to have exceptions.
- **tested (real ISO)**: the vendor's own ISO, checksum-verified, booted from a
  BeastBoot drive in QEMU by `tests/e2e/test_e2e_real_isos.py`
  ([tests/e2e/REAL_ISOS.md](../tests/e2e/REAL_ISOS.md)) until its own system
  or installer was running from the ISO.

Real-ISO results are very welcome; please include the ISO file name, the
data filesystem, BIOS/UEFI/Secure Boot, and the `BEAST:` lines (set
`bb_debug=1`, see [MENU.md](MENU.md)).

## Recipes

Detection runs top to bottom; the first match wins. `<path>` is the ISO's
path on the data partition, `<uuid>` the data partition's UUID as Linux shows
it in `/dev/disk/by-uuid/`, `<label>` the ISO's volume label as GRUB reads it.

| Recipe id | Detected by (file inside the ISO) | Kernel command line | Covers (expected) |
|---|---|---|---|
| `loopback` | `/boot/grub/loopback.cfg` | the ISO's own `loopback.cfg`, with `iso_path=<path>` exported and `root=loop` | Ubuntu and its official flavours, Linux Mint, many Ubuntu-based distributions, Debian live images, GParted Live, Clonezilla, SystemRescue (unverified for each) |
| `casper` | `/casper/vmlinuz` | `boot=casper iso-scan/filename=<path> quiet splash ---` | Ubuntu-based ISOs without a `loopback.cfg` |
| `live-boot` | `/live/vmlinuz` | `boot=live findiso=<path> components quiet splash` | Debian live and Debian-based live systems that use live-boot |
| `archiso` | `/arch/boot/x86_64/vmlinuz-linux` | `archisobasedir=arch archisolabel=<label> img_dev=/dev/disk/by-uuid/<uuid> img_loop=<path>` | Arch Linux ISO, archiso-based ISOs that keep the default layout |
| `dracut-live` | `/LiveOS/squashfs.img` and `/images/pxeboot/vmlinuz` | `root=live:CDLABEL=<label> rd.live.image iso-scan/filename=<path> quiet` | Fedora live ISOs (Workstation, spins), other dracut live images with this layout. Also, with the kernel at `/boot/x86_64/loader/linux` (KIWI layout): `/LiveOS/squashfs.img`, or `/boot/grub2/grub.cfg` without `/LiveOS` (Fedora 44+ Workstation Live, openSUSE Tumbleweed live, Leap 16 Agama installer) |
| `anaconda` | `/images/pxeboot/vmlinuz` and no `/LiveOS` | `inst.stage2=hd:UUID=<uuid>:<path> quiet` | Fedora Server/Everything netinst and DVD, RHEL, AlmaLinux, Rocky Linux, CentOS Stream installers |
| `suse` | `/boot/x86_64/loader/linux` (the dracut cases above win first) | `isofrom_device=/dev/disk/by-uuid/<uuid> isofrom_system=<path> splash=silent` | linuxrc installers such as Tumbleweed NET (the installation source comes from the network; the VM needs a NIC); openSUSE/SLE DVD ISOs are unverified |
| `debian-installer` | `/install.amd/vmlinuz` + `.disk/info` | the whole ISO and its loop-modules udeb are added to the initrd, `hooks/d-i-iso.sh` mounts it on `/cdrom` (needs RAM for the ISO twice; netinst only, not DVD sets: see [Size limit](#size-limit-of-alpine-and-debian-installer-isos)); when `bb_kargs` preseeds answers (`priority=`, `locale=`, `a/b=`...) the installer runs on the preferred console only, as d-i does for a preseed file | Debian netinst / CD installers |
| `alpine` | `/.alpine-release` + `/apks/.boot_repository` | the whole ISO is added to the initramfs, `rdinit=/beast-init` (`hooks/alpine-init.sh`) attaches it to `/dev/loop0` | Alpine standard / extended (RAM for the ISO) |
| `windows` | `/sources/boot.wim` and (`/bootmgr` or `/efi/microsoft/boot/bcd`) | no kernel: wimboot starts the ISO's `sources/boot.wim` from memory. Installation ISOs: **Windows Setup** from the ISO (default) or a Windows PE command prompt; other `boot.wim` ISOs (Windows PE, WinRE) as they are. **Secure Boot off only** ([below](#windows)) | Windows 11: **tested (real ISO)**, see below. Windows 10 and Windows Server installation ISOs: expected. Windows PE / WinRE ISOs: unverified |
| `efi-chainload` | UEFI only: `/EFI/BOOT/BOOTX64.EFI` in any letter case | `chainloader` the ISO's own UEFI boot loader | self-contained EFI programs (for example memtest86+ or netboot.xyz, unverified); most other ISOs fail, see below |
| `none` | nothing matched | the menu explains that the ISO is unknown | |

All recipes are **tested** for detection and command line (fixture ISOs,
UEFI, see the end of this page).

Notes per recipe:

- **loopback** is preferred because the distribution's own `loopback.cfg`
  knows its kernel parameters best. A `loopback.cfg` runs as a normal GRUB
  menu; Esc returns to BeastBoot.
- **casper** picks the first of `/casper/initrd`, `initrd.lz`, `initrd.gz`,
  `initrd.img` that exists.
- **dracut-live** and **archiso** use the ISO's volume label. If an ISO has a
  Joliet directory tree, GRUB reports the Joliet label, which is at most 16
  characters, while Linux reports the full (up to 32 character) ISO 9660
  label. A longer label would then not match and the initramfs would wait for
  a device that never appears (unverified in practice: Fedora live ISOs are
  not known to carry Joliet; archiso finds its loop device through `img_dev`
  and `img_loop` and does not need the label there).
- **efi-chainload** starts the ISO's boot loader the way firmware would
  start it from a CD. The loader then looks for its own files on a CD or USB
  device of its own, which does not exist, so most Linux ISOs stop at a GRUB
  prompt or an error. It is meant for self-contained EFI programs. A warning
  is shown before starting.
- **windows**: see [Windows](#windows) below.
- **debian-installer**: in the Debian installer, the BeastBoot stick itself
  can show up as an ordinary disk in the partitioning step. Do not choose it
  as the installation target: that would erase your ISOs.

### Size limit of Alpine and Debian installer ISOs

`alpine` and `debian-installer` put the whole ISO into the initrd, in memory,
so they only work for small ISOs. GRUB cannot read a file's size in a menu
script, so there is no check beforehand: when GRUB cannot load the initrd, the
menu stops with `BEAST: error iso-too-large` and says which ISO and what to
use instead. Measured with a real Alpine 3.24.3 ISO padded to a given size
(4 GB of RAM): legacy BIOS loads 700 MiB but not 1.1 GiB (the BIOS loader needs
the initrd in memory below 4 GiB next to the kernel, so plan for about
900 MiB at most); UEFI loads 1.1 GiB, and with 2 GiB the kernel itself ran out
of memory ("Kernel panic": the kernel keeps a second copy of the ISO, so
plan for 2.5 times the ISO size in RAM; this failure cannot be caught by the
menu). A Debian DVD-1 (about 3.7 GB) or an Alpine "extended" ISO is too large
for BIOS and for most PCs: use the netinst / CD ISO (Debian) or the standard ISO
(Alpine), or write the large ISO to its own stick.

## Windows

What happens when you pick a Windows installation ISO (one with
`sources/install.wim` or `install.esd`):

1. A small menu asks: **Install Windows** (default) or **Windows PE command
   prompt** (repair and tools, no Setup). With `bb_autoboot` the menu is
   skipped: Setup, or the command prompt with `bb_windows=pe`
   ([MENU.md](MENU.md)).
2. GRUB writes the ISO's path to the drive's `grub/grubenv` and starts
   [wimboot](https://ipxe.org/wimboot) (iPXE's Windows PE loader, built from
   source with our patches, `build/wimboot/`). wimboot loads the ISO's
   `sources/boot.wim` into memory and starts Windows PE from it, with three
   small files added: a start-up script, the ISO path, and `beastmount.exe`.
   Nothing on the ISO or the drive is changed.
3. In Windows PE the start-up script finds the BeastBoot data partition,
   attaches the ISO file **read-only** as a DVD drive (`beastmount.exe`, our
   own small program built from `build/winpe/beastmount.c`), and starts
   Windows Setup from that drive, as from a Microsoft USB stick. It checks
   that Setup really runs from the ISO. If a step fails, it says what failed
   in plain words and leaves a command prompt open.

ISOs with `boot.wim` but no install image (Windows PE, WinRE, recovery tool
ISOs) boot as they are: their own start-up runs, nothing is added.

**Tested (real ISO)**: Windows 11 Enterprise 26H2 evaluation (x64, en-US,
Microsoft's checksum), UEFI and legacy BIOS, on an exFAT and on an NTFS data
partition: Windows Setup starts from the attached ISO and shows its first
screen ("Select language settings"); a path with spaces and `&` in a folder
works. The Windows PE command prompt variant also starts on UEFI and BIOS.
On these test VMs (no TPM, firmware without Secure Boot support) Windows 11
Setup then stops at its own check, "This PC doesn't currently meet Windows 11
system requirements" (TPM 2.0, Secure Boot), as it would from Microsoft's
stick; closing it returns to BeastBoot's command prompt. Installing Windows
to the end was not part of the test.

**Untested**: Windows Server 2025 (and other Windows Server editions). Microsoft
publishes no checksum for the evaluation ISO, so it cannot be verified and
is not in the test catalog; it uses the same code path as Windows 11.

Limits:

- **Secure Boot must be off.** wimboot is not signed (and Microsoft's signed
  wimboot cannot start from GRUB on UEFI), so with Secure Boot on the menu
  stops with `BEAST: error windows-sb` and says to turn Secure Boot off.
  BeastBoot never works around Secure Boot. Turn it off for the
  installation; the installed Windows starts normally with Secure Boot on
  again.
- **Memory**: about twice the size of `boot.wim` plus 1 GB, because wimboot
  keeps `boot.wim` in memory and Windows copies it into its own RAM disk.
  With Windows 11 26H2 (`boot.wim` 610 MB) Setup started with 2.5 GB
  (UEFI) and 4 GB (UEFI and BIOS); Windows 11 itself requires 4 GB.
- **Windows 11's hardware check** is Setup's own, the same as from
  Microsoft's USB stick: on a PC without TPM 2.0 or Secure Boot support (or
  started in legacy BIOS mode), Windows 11 Setup says the PC does not meet the
  requirements. BeastBoot does not bypass it.
- **Data partition**: exFAT or NTFS (the ISO is larger than 4 GiB, too big
  for FAT32). Windows PE reads both.
- **Restart during Setup**: Setup restarts the PC to finish. Let it start
  from the internal disk (remove the stick, or pick the disk in the firmware
  boot menu); choosing the ISO in BeastBoot again starts Setup from the
  beginning.
- USB 2 sticks: loading `boot.wim` takes about a minute before anything
  moves on the screen.

## Paths with spaces and special characters

ISO paths with spaces work in GRUB. GRUB passes each kernel parameter that
contains a space to the kernel wrapped in double quotes, for example
`"iso-scan/filename=/Some Folder/My Distro.iso"`. The Linux kernel accepts a
quoted `"param=value with spaces"` and hands the value to the initramfs
without the quotes. Whether each distribution's initramfs script then copes
with the space is **unverified** (shell scripts that do not quote their
variables would break). If an ISO does not boot from a folder with spaces,
try a path without spaces first.

Avoid `"`, `'` and `\` in ISO paths: GRUB escapes them with a backslash, which
the kernel does not undo. Labels with spaces have the same caveat as paths.

## The data partition's filesystem

Recipes `casper`, `live-boot`, `archiso`, `dracut-live`, `anaconda` and `suse`
(and most `loopback.cfg` files) work in two steps: GRUB loads the kernel and
initramfs from the ISO, then the ISO's own initramfs has to **mount the data
partition** to find the ISO file and continue from it. So the initramfs must
support the data partition's filesystem:

| Data filesystem | GRUB can read it | ISO initramfs can mount it |
|---|---|---|
| FAT32 | yes | yes, every Linux initramfs supports vfat (expected) |
| exFAT (default) | yes | **Ubuntu desktop: tested** with Ubuntu 26.04.1 (UEFI, UEFI with Secure Boot, legacy BIOS; with Secure Boot on, 0.1.2 first needs [Ubuntu's key trusted](#secure-boot)), through the [exFAT add-on](#the-exfat-add-on). Other casper ISOs with a `minimal.squashfs` or `filesystem.squashfs` (official flavours, Linux Mint) and Debian live-boot ISOs: expected through the same add-on, unverified. **Ubuntu Server: tested** (26.04.1 live server, exFAT; its layer `ubuntu-server-minimal.squashfs` is read like the others). Other distributions need the `exfat` module in their own initramfs (Linux 5.7 or later); unverified per distribution. |
| NTFS | yes, **but not under Secure Boot**: GRUB 2.14 switches its NTFS driver off in lockdown mode, so with Secure Boot on the menu cannot see an NTFS data partition at all | **Tested**: Ubuntu desktop (its own `loopback.cfg`), Debian live (the add-on brings the ISO's `ntfs3`), openSUSE Tumbleweed NET (`suse`, UEFI and BIOS; the `suse` recipe is not refused on NTFS) and Windows (Windows PE reads NTFS). **Refused** with `ntfs-unsupported`: dracut-based ISOs and Anaconda (Fedora, RHEL family, openSUSE Leap 16 and Tumbleweed live), whose initramfs has no NTFS driver. Others: needs `ntfs3` (Linux 5.15+) in the initramfs; unverified. |

If an ISO is not covered by the add-on below and you are unsure, use FAT32
for the data partition (`--fs fat32`). Its 4 GiB per-file limit is the catch:
larger ISOs (current Ubuntu desktop, some Windows and DVD images) do not fit.
A filesystem-independent mapping (a small initramfs add-on that maps the ISO's
sectors as a block device) is planned for later.

### The exFAT add-on

Ubuntu's initramfs has no exFAT driver, and casper (Ubuntu's live-boot
scripts) only searches partitions of a fixed list of filesystem types. Without
help, an Ubuntu ISO on an exFAT drive stops in an initramfs shell with
"Could not find the ISO". The driver is on the ISO, though: its squashfs
contains `exfat.ko` for exactly the ISO's kernel, signed with that kernel's
key. So, on an exFAT data partition, the menu:

1. reads the exfat module out of the ISO's squashfs (`/casper/minimal.squashfs`
   on Ubuntu 24.04 and later, `/casper/filesystem.squashfs` before that,
   `/live/filesystem.squashfs` on Debian live);
2. adds it, plus a small script from the boot partition
   ([`grub/beast/hooks/initramfs-tools.sh`](../grub/beast/hooks/initramfs-tools.sh)),
   to the ISO's initramfs as extra files when it starts the kernel. An ISO
   with its own `loopback.cfg` (Ubuntu has one) is started with the `casper`
   recipe instead, because `loopback.cfg` would start it without them;
3. the script loads the module and lets casper search exFAT partitions too.

Nothing on the drive or in the ISO changes. The kernel checks the module's
signature as usual: with Secure Boot on it is accepted because it is the ISO's
own. You can see it worked in the live system with
`sudo dmesg | grep beast-booter`:

```
beast-booter: exfat support loaded (exfat.ko.zst from the ISO)
beast-booter: casper may now search exfat partitions for the ISO
```

With `bb_debug=1` the menu prints `BEAST: fsmod exfat <module>` when it uses
the add-on, or `BEAST: fsmod none <reason>` when it cannot (see
[MENU.md](MENU.md#debug-output-bb_debug1)). Limits: only the squashfs
names above (and `ubuntu-server-minimal.squashfs` on Ubuntu Server) are looked
at, so other layouts boot as before (`fsmod none no-squashfs`); GRUB cannot read zstd-compressed
squashfs images, so such ISOs boot as before too; the safe-graphics
and other extra entries of the ISO's own `loopback.cfg` are not offered while
the add-on is used. To turn it off, put `set bb_fs_addon=0` in
`/beast-booter/config.cfg`.

On an NTFS data partition Debian live ISOs get the same kind of add-on with
the ISO's `ntfs3` module: live-boot's initramfs has no NTFS driver and only
accepts NTFS when the `ntfs-3g` program exists, so the hook also leaves a
stand-in `ntfs-3g` and a `mount.ntfs` helper that mounts as `ntfs3`
(`BEAST: fsmod ntfs <module>`). Ubuntu (casper) ISOs on NTFS keep using the
ISO's own `loopback.cfg`, whose initramfs mounts NTFS itself.

The kernel command lines use the data partition's UUID as Linux shows it
(`bb_data_uuid_linux` from the installer's `device.cfg`). If `device.cfg` is
missing, or the partition was reformatted since, the menu reads the UUID
itself (GRUB shows FAT/exFAT UUIDs in upper case already and NTFS ones in
lower case; the menu converts them to upper case like `/dev/disk/by-uuid`).

## Secure Boot

With Secure Boot on, BeastBoot's GRUB is started by shim and every kernel
or EFI program it starts is verified through shim: against the firmware's
`db`, the MOK list (keys you enrolled with MokManager), or the vendor
certificate built into shim. Since 0.1.2 BeastBoot ships Debian's
Microsoft-signed shim 16.1, whose vendor certificate is Debian's (0.1.1 and
older shipped Ubuntu's shim, whose vendor certificate is Canonical's).

| ISO kernel signed by | Boots with Secure Boot on? |
|---|---|
| Debian | yes, through Debian's shim vendor certificate (expected) |
| Canonical (Ubuntu, official Ubuntu flavours, distributions that reuse Ubuntu's signed kernel, such as Linux Mint) | only after you run "Trust Ubuntu's Secure Boot key" in the menu once on that computer (it adds Ubuntu's revocations to MokListX, then Canonical's CA to MokList, each confirmed in MokManager; see [SECURE_BOOT.md](SECURE_BOOT.md#trust-ubuntus-secure-boot-key-optional)); otherwise turn Secure Boot off |
| another distribution's key (Fedora/Red Hat, openSUSE/SUSE, ...) | only after you enroll that distribution's signing certificate with MokManager ("Enroll a key (MokManager)" in the menu), if the distribution publishes one; otherwise turn Secure Boot off |
| nobody (Arch Linux ISO, many smaller distributions) | no: turn Secure Boot off in the firmware settings |

These distributions' own shims are Microsoft-signed too, but BeastBoot
does not chain-load other distributions' shims: it boots their kernels
directly, so their kernel signing keys must be trusted by our shim.

When a kernel is refused, the menu prints the GRUB error, then
`BEAST: error sb-verify-failed ...` and an explanation with these options
(Ubuntu-signed: "Trust Ubuntu's Secure Boot key"; another distribution:
enroll its key; a release that supports Secure Boot; or Secure Boot off),
and returns to the menu. It never retries without verification.
Depending on the shim and GRUB versions, the refusal is reported when the
kernel is loaded (`linux`) or when it is started (`boot`); both are handled.

Under Secure Boot, ISOs booted through their own `loopback.cfg` (recipe
`loopback`) show GRUB's error from inside the ISO's menu instead, because the
ISO's script runs the `linux` command itself.

Kernel modules the ISO's kernel loads later, and anything after the kernel
has started, are the distribution's business: a kernel in Secure Boot mode
typically refuses unsigned modules (for example proprietary drivers).

## Tests

The fixtures behind the **tested** marks are fake ISOs built with `xorriso`
that contain exactly the detection files above (dummy kernels), booted in
QEMU with OVMF (UEFI, Secure Boot off) and SeaBIOS (legacy BIOS) using
`bb_dryrun=1` and `bb_debug=1`, and checked for the `BEAST: boot` and
`BEAST: dryrun` lines, for paths with spaces, and for the `loopback.cfg` case
(the fixture's `loopback.cfg` prints `$iso_path`). Secure Boot rejection was
first checked with OVMF in Secure Boot mode (Microsoft keys), Ubuntu's signed
shim and GRUB: an unsigned EFI program and a dummy kernel are both refused by
shim (`error: bad shim lock signature.`) and reported as `sb-verify-failed`.
The end-to-end tests in `tests/e2e/` repeat this with BeastBoot's own build
(Debian's shim 16.1 since 0.1.2), and check that Ubuntu's Canonical-signed
kernel is refused until Canonical's CA is in MokList.
