# BeastBoot user guide

How to make a BeastBoot USB drive, fill it with ISOs, boot it (with or
without Secure Boot), keep it up to date, download ISOs from the boot menu,
and what to do when something does not boot.

Contents:

1. [What you need](#1-what-you-need)
2. [Make a drive with the app](#2-make-a-drive-with-the-app)
3. [Make a drive with the command line](#3-make-a-drive-with-the-command-line)
4. [Copy ISOs](#4-copy-isos)
5. [Boot from the drive](#5-boot-from-the-drive)
6. [First boot with Secure Boot on](#6-first-boot-with-secure-boot-on)
7. [Update the boot files](#7-update-the-boot-files)
8. [Download an ISO from a link](#8-download-an-iso-from-a-link)
9. [Menu settings](#9-menu-settings)
10. [Troubleshooting](#10-troubleshooting)

## 1. What you need

- A USB drive of at least 1 GiB. **Everything on it is erased** when you
  make it a BeastBoot drive (later updates keep your files).
- A computer running Linux (x86_64), Windows 10 or newer (x86_64), or macOS
  (10.15+ on Intel, 11+ on Apple silicon) to prepare the drive.
- The portable package for that computer from the release page, plus the
  release's `SHA256SUMS`. Check the download before you run it:
  [SECURITY.md](../SECURITY.md#verifying-a-release) and
  [PORTABLE.md](PORTABLE.md#check-the-download-first).

## 2. Make a drive with the app

1. Unpack the package and start the app:
   - **Windows:** extract the `.zip`, double-click `BeastBooter.cmd`.
   - **macOS:** double-click the `.zip`, then `BeastBooter`
     (`BeastBooter.app`).
   - **Linux:** `tar xzf beast-booter-<v>-linux-x86_64.tar.gz`, then
     `./BeastBooter` in the folder.

   The app is not code signed, so the first start shows a SmartScreen or
   Gatekeeper warning; see [Troubleshooting](#unsigned-app-warnings).
2. On **Make a drive**, choose the USB drive in **Choose the USB drive**.
   Only removable drives are offered; **Show all disks** also lists fixed and
   system disks, marked as not usable, so you can see why a disk is missing.
   **Refresh** re-reads the list after you plug in a drive.
3. Click **Next: options** and choose:

   | Option | Choices | Meaning |
   |---|---|---|
   | **File system** | **exFAT (recommended)**, FAT32, NTFS (not on macOS) | the file system of the storage partition, where your ISOs go. exFAT works in every boot mode and holds files over 4 GiB. FAT32 is readable by every Linux ISO but holds no file of 4 GiB or more. NTFS is invisible to the menu with Secure Boot on. |
   | **Partition table** | **MBR (recommended)**, GPT | MBR boots on the most machines, old BIOSes included. GPT for firmware that wants it; some old BIOSes do not boot from GPT. |
   | **Volume label** | default `BEASTBOOTER` | the name the storage partition shows in your file manager |

4. Click **Install...**. The app shows what it will erase. Writing to a
   drive needs administrator rights, so your OS asks once:
   - **Windows:** a UAC prompt for `pythonw.exe` (the app's own Python),
     publisher unknown because it is unsigned;
   - **macOS:** a dialog for an administrator's name and password;
   - **Linux:** a polkit password dialog (`pkexec`), or a `sudo` prompt.

   Only that write step runs as administrator; the window itself runs as
   you. Why, and exactly what runs elevated:
   [PORTABLE.md](PORTABLE.md#administrator-prompts-when-and-why).
5. The app checks every boot file against its manifest, writes the drive
   and shows **NEXT STEPS** with the fingerprint of the Secure Boot key
   (SHA-1, as MokManager shows it). Note it for [section 6](#6-first-boot-with-secure-boot-on).

**Make an image file instead** writes a disk image file (no administrator
rights) that you can test in a virtual machine or write to a drive later.
**Verify boot files** checks the boot files in the package against their
manifest without writing anything.

## 3. Make a drive with the command line

The package has a command line program: `beast-booter.cmd` (Windows),
`./beast-booter.command` (macOS), `./beast-booter` (Linux). From a source
checkout it is `bin/beast-booter`. Writing a device needs administrator
rights: `sudo` on Linux and macOS, a terminal started with **Run as
administrator** on Windows.

```sh
./beast-booter list-devices                         # drives you can write to (--all: every disk)
sudo ./beast-booter install --device /dev/sdX       # Linux: asks you to type the device name
sudo ./beast-booter.command install --device /dev/disk4    # macOS
beast-booter.cmd install --device \\.\PhysicalDrive2       # Windows (or --device 2)
./beast-booter install --image my-drive.img --size 8G      # an image file, no admin rights
sudo ./beast-booter info --device /dev/sdX           # layout, version, partitions
```

`install` options (see `install --help`):

| Option | Default | Meaning |
|---|---|---|
| `--fs exfat\|fat32\|ntfs` | `exfat` | storage partition file system (as in the app) |
| `--layout msdos\|gpt` | `msdos` | partition table: `msdos` = MBR |
| `--label LABEL` | `BEASTBOOTER` | storage partition label |
| `--serial-console` | off | also show the menu on serial port 0 (headless machines) |
| `--size SIZE` | – | image size with `--image`: `1G` (minimum), `8G` or bytes |
| `--yes`, `-y` | ask | do not ask for confirmation |
| `--allow-fixed-disk` | refuse | allow a non-removable disk; be very sure |
| `--dist DIR\|ZIP` | the package's boot files | use other boot files, e.g. ones you built |

`install` unmounts the drive where your desktop mounted it automatically.
It refuses a disk that is mounted elsewhere, holds your running system, or
is not removable (unless `--allow-fixed-disk`).

## 4. Copy ISOs

Mount the drive's **BEASTBOOTER** partition like any USB stick and copy
`.iso` files onto it, in the root or in folders of your choice (for example
`linux/`, `rescue/`). The menu shows folders and files whose name ends in
`.iso` (any letter case); other files are kept but not listed. The folder
`beast-booter/` on the drive is for your settings and hidden from the menu.

Keep a few hundred entries per folder at most: GRUB sorts each folder when
you open it, so very large folders open slowly.

## 5. Boot from the drive

1. Plug in the drive and start the computer.
2. Open the firmware's one-time boot menu: a key pressed right after power
   on, often **F12**, **F11**, **F10**, **F8** or **Esc** depending on the
   maker. Pick the USB drive. On UEFI machines it may be listed twice
   (UEFI and legacy); choose the UEFI entry unless you want legacy BIOS.
3. The BeastBoot menu shows your folders and ISOs, then the tools.

Keys: **↑ ↓** select, **Enter** boots an ISO or opens a folder, **Esc** (or
**Backspace**) goes back to the parent folder, **c** opens the GRUB console.

The tools at the bottom of the root menu:

| Entry | What it does |
|---|---|
| `System: <maker> <model> · UEFI · Secure Boot on` | System information: firmware, CPU, memory, boot mode, Secure Boot state, BeastBoot version, the drive's partitions |
| Download an ISO from a link | the network helper ([section 8](#8-download-an-iso-from-a-link)); only when it is on the drive |
| Trust Ubuntu's Secure Boot key | UEFI: let this computer start Ubuntu and Ubuntu-based ISOs with Secure Boot on ([section 6](#ubuntu-isos-with-secure-boot-on)); only when the network helper is on the drive |
| Secure Boot status / help | whether Secure Boot is on and what that means for your ISOs |
| Enroll a key (MokManager) | UEFI: enroll a distribution's signing key |
| UEFI firmware settings | UEFI: reboot into the firmware setup, if supported |
| Reboot, Power off | |

Which ISOs boot and how: [ISO_SUPPORT.md](ISO_SUPPORT.md).

## 6. First boot with Secure Boot on

Once per computer, you enroll the BeastBoot key in MokManager. Nothing
running in an operating system can do this for you; it needs a keyboard
at the machine.

1. Boot the drive. A blue screen says **Verification failed: (0x1A)
   Security Violation**. Press **Enter**.
2. Press any key at **Press any key to perform MOK management** (within 10
   seconds; otherwise boot the drive again).
3. **Enroll key from disk** > **BEAST-EFI** > **ENROLL_THIS_KEY_IN_MOKMANAGER.cer**.
4. **View key 0**: the fingerprint must match the one the app showed, or
   the release's `CERTIFICATE.txt` for official drives. Then **Continue** >
   **Yes** > **Reboot**.

From then on the computer starts the menu directly. BeastBoot starts on
PCs that trust Microsoft's old (2011) or new (2023) UEFI certificate.

Which ISOs then boot with Secure Boot on:

- **Debian** ISOs: right away (they are signed with Debian's key, which the
  drive's shim has built in).
- **Ubuntu and ISOs based on it** (Kubuntu, Xubuntu, Linux Mint and others
  that use Ubuntu's signed kernel): only after you let this computer trust
  Ubuntu's key once ([below](#ubuntu-isos-with-secure-boot-on)), or with
  Secure Boot off. Until then the menu says "Secure Boot stopped this ISO
  from starting".
- **Other distributions** (Fedora, openSUSE, ...): after you enroll their
  own key with **Enroll a key (MokManager)**, if they publish one.
- **Unsigned ISOs** (for example Arch Linux): only with Secure Boot off.

Screens, how to check the key first, how to remove it again, and how to use
your own key: [SECURE_BOOT.md](SECURE_BOOT.md).

### Ubuntu ISOs with Secure Boot on

Since 0.1.2 the drive starts through Debian's shim, which does not trust
Ubuntu's key by itself. Either turn Secure Boot off in the firmware settings,
or let this computer trust Ubuntu's key. That takes two steps, each confirmed
in MokManager after a reboot:

1. In the BeastBoot menu choose **Trust Ubuntu's Secure Boot key** (with the
   other tools at the bottom of the root menu; the network helper's **More**
   menu has it too).
2. **Step 1 of 2: add Ubuntu's revocations.** The screen lists the eight
   older Ubuntu certificates that Ubuntu itself revoked, with their
   fingerprints. Choose **Continue** and type a new one-time password twice
   (4 to 32 letters or digits; MokManager may use a US keyboard layout).
3. Reboot from the stick. A blue **Perform MOK management** screen appears:
   press a key within 10 seconds, choose **Enroll MOKX**, then **Continue**
   and **Yes**, type the password, and choose **Reboot**.
4. Choose **Trust Ubuntu's Secure Boot key** again. It now says *revocations
   only (step 1 of 2 done)*. Choose **Step 2 of 2: trust Ubuntu's Secure Boot
   key** and do the same; in MokManager choose **Enroll MOK**. Before you
   confirm, choose **View key** and compare it with the fingerprint below.

Ubuntu's key, as MokManager shows it:

- Subject: **Canonical Ltd. Master Certificate Authority**
- SHA-1: `76 A0 92 06 58 00 BF 37 69 01 C3 72 CD 55 A9 0E 1F DE D2 E0`
- SHA-256: `ed1fe72cb9ca31c9af5b757afcd733323d675825032e6ced7fe1ae9eb767998c`

Ubuntu-signed ISOs now start with Secure Boot on. Very old releases (signed
before about mid-2022) may still be refused, because their keys are among
the ones Ubuntu revoked.

This setting belongs to the **computer, not the stick**: other systems
installed on it (an installed Ubuntu, Fedora, Debian...) trust Ubuntu-signed
software too. To undo it, open the same entry and choose **Stop trusting
Ubuntu's key**, then confirm **Delete MOK** in MokManager. If MokManager
times out or you choose **Continue boot**, nothing changes; the screen shows
whether a request is still waiting. Details:
[SECURE_BOOT.md](SECURE_BOOT.md#trust-ubuntus-secure-boot-key-optional).

## 7. Update the boot files

A newer BeastBoot replaces only the boot partition and boot code; your
ISOs and other files on partition 1 are never written.

- **App:** choose the drive and click **Update boot files...**.
- **Command line:** `sudo ./beast-booter update --device /dev/sdX`.

**The app tells you when a drive is out of date.** For every BeastBoot
drive in the list it reads which version the drive has, without asking for
administrator rights, and shows it on the drive's card: *update available*,
*up to date*, *different build*, *newer than this app* (don't update with an
older app) or *needs a reinstall*. A notice above the list names drives
with older boot files; select one and **Update boot files...** becomes the
main button. On Linux the app reads the version by mounting the drive's
boot partition read-only for a moment (udisks, no password); on Windows and
macOS it can read it only where the system shows that partition, otherwise
the card just says *BeastBoot drive*. From the command line:
`./beast-booter list-devices --check-installed`.

Installed firmware packs and a pending one-time download boot are carried
over (for packs installed before 0.1.2, see
[Firmware packs](#firmware-packs)). If the new boot files are signed with a
different key (for example, you move from boot files you built yourself to
a release), enroll the new key once more as in
[section 6](#6-first-boot-with-secure-boot-on).

**Updating a drive from 0.1.1 or older to 0.1.2** changes its shim: the
drive now also starts on PCs that trust only Microsoft's 2023 certificate,
but with Secure Boot on, Ubuntu and Ubuntu-based ISOs that booted before are
refused until you trust Ubuntu's key on that computer
([section 6](#ubuntu-isos-with-secure-boot-on)) or turn Secure Boot off.

A drive made by BeastBoot before layout 2 (512 MiB boot partition) cannot
be updated: `update` stops with `reinstall-needed`. Copy your files off,
run `install` again, and copy them back.

**If an update stops because the drive stopped responding**
(`device-vanished`): some USB sticks report "no medium" right after their
files are unmounted, especially when they are warm or have been plugged in
for a long time. That is the stick, not BeastBoot. Unplug it, plug it
back in and click **Update boot files...** again. An update that was
interrupted this way is finished by the next one, including your firmware
packs and a pending one-time boot (the app keeps a copy of them on this
computer while it writes). Your ISOs and files are never written by an
update.

## 8. Download an ISO from a link

Choose **Download an ISO from a link** in the root menu. A small Linux
environment starts (Ubuntu's kernel, signed with the BeastBoot key, so this
works with Secure Boot on once that key is enrolled):

1. **Network.** Ethernet is configured automatically (DHCP). For WiFi, pick
   the network and type its passphrase.
2. **Link.** Type the ISO's URL (HTTPS) and, if you have it, its SHA-256 or
   the URL of a checksum file. A plain `http://` link is accepted only with a
   SHA-256.
3. **Download.** The ISO is saved under `/downloads/` on the drive, with
   progress and resume. The server's certificate is checked against Ubuntu's
   CA list, and the SHA-256 when you gave one; a mismatching file is not kept.
4. **Boot it now.** The helper reboots into the menu, which boots that ISO
   once through the normal recipes and Secure Boot checks. The ISO stays on
   the drive.

### Firmware packs

Most Ethernet adapters work out of the box. Many WiFi chips (and some
Ethernet ones) need closed-source firmware files, which BeastBoot does
not put on the drive by default. When firmware is missing, the helper names
the driver and the pack to install.

To install a pack, in the app open **Firmware packs**, select the packs
your adapters need (Intel, Realtek, MediaTek, Qualcomm Atheros and Broadcom
WiFi, Realtek Ethernet), choose the drive under **Install to** and click
**Download and install...**. Before anything is downloaded, **Details and
files** shows the source (the upstream `linux-firmware` repository on
kernel.org, at one pinned tag), each file's exact URL, licence and SHA-256.
Every file must match its SHA-256 or it is discarded. The packs go on the
drive's boot partition (BEAST-EFI): the app shows how much room the selected
packs take ("Selected: X of Y free") and keeps **Download and install...**
disabled while they don't fit; deselect packs, or remove installed ones you
don't need. Re-installing a pack counts the room its old copy frees. When you
choose a drive, the app shows the packs already installed on it and its free
space straight away (read without administrator rights, as for the version
check in [section 7](#7-update-the-boot-files)); **Check installed packs**
reads them again, with administrator rights, where that is not possible. If the
drive is mounted, it is unmounted first; close any program that still uses
it. Command line:

```sh
./beast-booter firmware catalog                                  # the packs on offer
./beast-booter firmware fetch --pack intel-wifi --out fw/        # download + verify, no admin rights
#   add --for-device /dev/sdX (with sudo) or --for-image P to check the free space first
sudo ./beast-booter firmware install --device /dev/sdX --from fw/
sudo ./beast-booter firmware list --device /dev/sdX              # what is installed
sudo ./beast-booter firmware remove --device /dev/sdX --pack intel-wifi
```

**Packs installed before 0.1.2.** 0.1.2 moved the helper to a newer Linux
kernel (7.3 instead of 7.0). An update keeps the installed packs and they
still load, but they hold the files the old kernel's drivers asked for, so
the update warns and names them, and the Firmware packs page and
`firmware list` mark each one "Made for kernel 7.0... - reinstall" (STALE).
After the update, install those packs again: select them and click
**Download and install...** (or `firmware fetch` and `firmware install`
above); that replaces the old copy. `firmware install` refuses packs that
were fetched for another kernel or `linux-firmware` tag than the drive's
helper uses (`pack-mismatch`): update the drive first, then fetch them again.

Details: [BEASTNET.md](BEASTNET.md).

## 9. Menu settings

Create `beast-booter/config.cfg` on the BEASTBOOTER partition; plain `set`
lines:

```sh
# /beast-booter/config.cfg
set timeout=10                       # start the default entry after 10 s
set default=0                        # the first entry
set bb_autoboot="/linux/ubuntu.iso"  # boot this ISO straight away
set bb_gfx=0                         # text menu instead of the graphical one
set bb_gfxmode=1280x720              # screen mode of the graphical menu
set bb_serial=1                      # also show the menu on serial port 0
```

The file is GRUB script: a typo shows up as a GRUB error at boot. All
settings, including your own theme (`bb_theme`) and debug output:
[MENU.md](MENU.md).

## 10. Troubleshooting

### Messages in the menu

With `set bb_debug=1` in `config.cfg`, the menu also prints a `BEAST: error
<code>` line; include it in bug reports.

| Code | Meaning | What to do |
|---|---|---|
| `sb-verify-failed` | Secure Boot refused the ISO's kernel: it is not signed by a key this computer trusts | Ubuntu or based on it: **Trust Ubuntu's Secure Boot key** ([section 6](#ubuntu-isos-with-secure-boot-on)). Other distributions: enroll their key with **Enroll a key (MokManager)** if they publish one. Or turn Secure Boot off for this ISO. BeastBoot never retries without verification. |
| `no-recipe` | BeastBoot does not recognise how this ISO boots | check [ISO_SUPPORT.md](ISO_SUPPORT.md#recipes); report the ISO |
| `unsupported-windows` | a Windows installer ISO | not supported in 0.1 |
| `no-data-partition` | the menu cannot find the storage partition | with Secure Boot on and NTFS, see below; otherwise the partition was deleted or reformatted: reinstall |
| `iso-not-found`, `loopback-failed` | the ISO file is gone or cannot be opened | copy it again; check it with its SHA-256 |
| `boot-failed` | the ISO's kernel or boot loader did not start | try the other boot mode (UEFI / legacy) |

**The ISO starts, then stops looking for its files** (an initramfs shell,
"unable to find a medium"): the ISO's own Linux must mount the storage
partition to find the ISO. On exFAT, BeastBoot gives Ubuntu desktop ISOs
(and, untested, other casper and Debian live ISOs) the exFAT driver from the
ISO itself ([the exFAT add-on](ISO_SUPPORT.md#the-exfat-add-on)); if Ubuntu
desktop still says "Could not find the ISO", update the drive's boot files and
send the `BEAST: fsmod` line (with `bb_debug=1`). Ubuntu Server ISOs, other
distributions, and old releases (for example Ubuntu 18.04, Debian 10) may not
mount exFAT. Make the drive with **FAT32** for them
([ISO_SUPPORT.md](ISO_SUPPORT.md#the-data-partitions-filesystem)).

### NTFS and Secure Boot

GRUB 2.14 switches its NTFS driver off when Secure Boot is on, so the menu
cannot see an NTFS storage partition at all and says so. Use exFAT or FAT32,
or boot with Secure Boot off.

### Secure Boot refuses BeastBoot itself

If the blue shim screen keeps coming back after you enrolled the key, or
shim reports an SBAT violation, check the drive's BeastBoot version (the app
shows it on the drive's card). BeastBoot 0.1.1 and older hit two known
limits, both fixed in 0.1.2:

- **SBAT `grub,6`.** Since November 2025, shim's revocation level can require
  GRUB generation 6. Up to 0.1.1 our GRUB was Ubuntu's 2.14 build and
  truthfully said `grub,5`, so a computer that applied that level (through a
  newer shim, OS or firmware update) refuses it. 0.1.2 builds GRUB from
  source with the fixes and proves them before it says `grub,6`; the SBAT
  number is never raised by hand.
- **Only the 2023 Microsoft CA.** Up to 0.1.1 our shim was signed only by
  Microsoft's UEFI CA 2011, so a computer whose firmware trusts only the 2023
  CA refuses it. 0.1.2 ships Debian's shim, signed through both.

Update the drive's boot files ([section 7](#7-update-the-boot-files)); until
then, boot with Secure Boot off on such computers. Details:
[SECURE_BOOT.md](SECURE_BOOT.md#known-compatibility-limits-of-011-and-older-found-by-make-vulns-2026-10-23).

### Download helper

| Message | Meaning |
|---|---|
| missing firmware for a driver (`no-firmware`) | install the firmware pack it names ([section 8](#firmware-packs)) |
| `wifi-auth` | wrong WiFi passphrase |
| `no-network`, `dhcp` | no cable or link, or no DHCP server |
| `tls` | the server's certificate is not trusted (or the computer's clock is far off) |
| `refused-plain-http` | an `http://` link (or a redirect to one) without a SHA-256 |
| `checksum-mismatch` | the file does not match the SHA-256; it is not kept |
| `no-space` | the drive is full; on FAT32, a file of 4 GiB or more cannot be stored at all |

The full list is in [BEASTNET.md](BEASTNET.md).

### Unsigned app warnings

The portable app is not code signed yet. Check the download against
`SHA256SUMS` first, then:

- **Windows SmartScreen** ("Windows protected your PC"): **More info** >
  **Run anyway**. Unblocking the `.zip` before you extract it (Properties >
  **Unblock**) avoids the warning.
- **macOS Gatekeeper** ("cannot be opened because Apple cannot check it"):
  on macOS 14 and older, right-click **BeastBooter** > **Open**; on macOS 15
  and newer, try once, then **System Settings** > **Privacy & Security** >
  **Open Anyway**.

More: [PORTABLE.md](PORTABLE.md#run-it).

### The drive is not offered as a boot device

- Legacy BIOS without the drive listed: the firmware may have no legacy/CSM
  support (use UEFI), or dislikes GPT (reinstall with MBR).
- UEFI: make sure USB boot is enabled in the firmware settings.

### Other installer errors

| Code | Meaning |
|---|---|
| `reinstall-needed` | the drive has an older layout; `update` cannot convert it ([section 7](#7-update-the-boot-files)) |
| `layout-too-new` | the drive was made by a newer BeastBoot; use that version |
| `cancelled` | you stopped it (Cancel, Ctrl+C); after a cancelled `install`, run it again before using the drive |
| `busy` | a program still uses the drive; on Linux the message names it (an open file, a terminal in a folder on it, an ISO attached as a disk image). Close it and try again |
| `device-vanished` | the drive stopped responding while it was prepared or written (it reported "no medium" or was unplugged). Unplug it, plug it back in and run the same command again ([section 7](#7-update-the-boot-files)) |

Still stuck? [Open an issue](https://github.com/cynak/BeastBoot/issues) with the BeastBoot version (`bb_version` on the
System information page), the computer model, the boot mode and the
`BEAST:` lines. Security problems go privately, see
[SECURITY.md](../SECURITY.md).
