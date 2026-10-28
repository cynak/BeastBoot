<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/hero-dark.svg">
    <img src="docs/assets/hero-light.svg" width="100%" alt="BeastBoot: one USB drive, many ISOs, Secure Boot intact. Boots on legacy BIOS, UEFI, and UEFI with Secure Boot via MOK, from a drive that stays normal exFAT storage; Ubuntu ISOs boot from exFAT, ISOs download over WiFi or Ethernet, and out-of-date drives are pointed out.">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/badge/license-GPL--3.0--or--later-52525b"></a>
  <a href="VERSION"><img alt="Version: 0.3.0" src="https://img.shields.io/badge/version-0.3.0-orange"></a>
  <a href="docs/ARCHITECTURE.md#2-boot-flows"><img alt="Platforms: BIOS, UEFI, Secure Boot" src="https://img.shields.io/badge/platforms-BIOS%20%7C%20UEFI%20%7C%20Secure%20Boot-d62839"></a>
  <br>
  <a href="sbom/README.md"><img alt="SBOM: CycloneDX 1.6 + SPDX 2.3" src="https://img.shields.io/badge/SBOM-CycloneDX%201.6%20%2B%20SPDX%202.3-52525b"></a>
  <a href="sbom/README.md"><img alt="Vulnerabilities: report with every release" src="https://img.shields.io/badge/vulnerabilities-report%20per%20release-52525b"></a>
  <a href="https://ko-fi.com/cynak"><img alt="Support on Ko-fi" src="https://img.shields.io/badge/Ko--fi-cynak-FF5E5B?logo=kofi&logoColor=white"></a>
  <a href="https://buymeacoffee.com/cynak"><img alt="Buy me a coffee" src="https://img.shields.io/badge/Buy%20me%20a%20coffee-cynak-d62839?logo=buymeacoffee&logoColor=white"></a>
  <a href="https://github.com/cynak/BeastBoot/releases"><img alt="Release on GitHub" src="https://img.shields.io/github/v/release/cynak/BeastBoot?include_prereleases&color=d62839&label=release"></a>
  <a href="docs/CODE_QUALITY.md"><img alt="Lint: ruff + ShellCheck" src="https://img.shields.io/badge/lint-ruff%20%2B%20ShellCheck-52525b"></a>
</p>

<p align="center">
  <strong>An open-source, fully transparent multi-boot USB drive, in the spirit of Ventoy.</strong><br>
  Copy <code>.iso</code> files onto a drive that stays normal storage and boot them on BIOS or UEFI.<br>
  Secure Boot can stay on: nothing is disabled or bypassed.
</p>

<p align="center">
  <a href="#screenshots">Screenshots</a> ·
  <a href="#download-and-use">Download</a> ·
  <a href="#quick-start">Quick&nbsp;start</a> ·
  <a href="#how-it-works">How&nbsp;it&nbsp;works</a> ·
  <a href="#secure-boot">Secure&nbsp;Boot</a> ·
  <a href="#download-an-iso-from-a-link">Network&nbsp;download</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

## Why

I wanted a all in one utility for booting my operating systems from a USB drive, but I also wanted to be able to store data on the drive as well. I also wanted to be able to download/boot ISO from the internet in the case I dont have any ISO on my drive and my system is completely borked (has happened a couple times). Im also very paranoid about security and in todays age where the next zero day is a vibe code away it requires a level of caution and trust to download and use something from the internet. The goal of this project is to provide a fully transparent application that anyone can vet.

## What it is

- **Copy ISOs, boot them.** The drive stays a normal storage drive (exFAT by
  default). Drop `.iso` files anywhere on it, in any folders. When you boot
  from it, a graphical menu lists the ISOs and lets you browse folders.
- **Boots everywhere.** Legacy BIOS, UEFI, and UEFI with Secure Boot on.
- **Secure Boot done properly.** Debian's Microsoft-signed shim (signed
  through both the 2011 and the 2023 UEFI CA), then BeastBoot's GRUB 2.14,
  built from source with current security fixes and signed with a BeastBoot
  key that *you* enroll once in MokManager. Nothing is disabled or bypassed.
  An ISO whose kernel your machine doesn't trust is refused, with an
  explanation.
- **Download an ISO from the boot menu.** A small Linux helper connects over
  Ethernet or WiFi, downloads an ISO over HTTPS, checks it and boots it.
- **Fully transparent.** Every file placed on the drive is built from this
  repo or from pinned sources, or copied unmodified from a named Ubuntu or
  Debian package (the helper kernel only gets a new signature), and listed
  with its origin and SHA-256 in a manifest you can verify. Every release
  publishes an SBOM and a vulnerability report.
- **Drives stay current.** The app notices when a drive has older boot files
  and updates them in place; your ISOs and files are never touched.
- **One app for Linux, Windows and macOS.** A desktop app and a command line,
  in plain Python, shipped as portable packages that need no installation.

> Status: **0.1, in development.** See the [roadmap](#roadmap) and the
> [known Secure Boot limits](#secure-boot).

> The project is **BeastBoot**. The program, its commands and files, and the
> drive's labels keep the technical name `beast-boot` (for example
> `./beast-boot install`, `beast-boot-<v>-linux-x86_64.tar.gz`,
> the `BEASTBOOTER` partition), so existing drives keep working.

## Screenshots

<table>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/menu-root.png" width="100%" alt="The BeastBoot boot menu: folders and ISO files with distribution icons, then System information, Download an ISO from a link, Secure Boot help, Reboot and Power off"><br>
<sub><b>Boot menu.</b> ISOs and folders on the drive, each with its distribution's icon, then the tools.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/menu-folder.png" width="100%" alt="The boot menu inside the Linux folder, listing ISO files"><br>
<sub><b>Folders.</b> Any folder on the drive opens as its own list; Esc goes back.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/menu-system.png" width="100%" alt="The System information page of the boot menu"><br>
<sub><b>System information.</b> What the firmware reports: board, CPU, memory, boot mode, Secure Boot.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/menu-download.png" width="100%" alt="The text screen of the download helper"><br>
<sub><b>Download an ISO from a link.</b> The network helper asks for a link, downloads it over HTTPS and checks it.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-drive.png" width="100%" alt="The BeastBoot desktop app listing USB drives"><br>
<sub><b>The app: choose the drive.</b> Only removable drives are offered; system and read-only disks are refused.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-options.png" width="100%" alt="The options page of the desktop app"><br>
<sub><b>Options.</b> File system, partition table, label, and the boot files with their Secure Boot key fingerprints.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-confirm.png" width="100%" alt="The erase confirmation dialog of the desktop app"><br>
<sub><b>Nothing is erased by accident.</b> You tick a box before the drive is erased.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-update-available.png" width="100%" alt="The desktop app pointing out a drive with older BeastBoot boot files and offering Update boot files"><br>
<sub><b>Out-of-date drives are pointed out.</b> A drive with older boot files gets a notice and one-click Update boot files; your files on it stay.</sub></td>
</tr>
</table>

<details>
<summary>More of the app</summary>

<table>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-done.png" width="100%" alt="The desktop app after a finished install"><br>
<sub><b>Ready.</b> Next steps, with the key fingerprint to compare in MokManager.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-installing.png" width="100%" alt="The desktop app while it installs"><br>
<sub><b>Installing.</b> Every step is shown; details are one click away.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-firmware.png" width="100%" alt="The firmware packs page of the desktop app"><br>
<sub><b>Firmware packs.</b> Optional WiFi and Ethernet firmware for the download helper, from linux-firmware, every file checked by SHA-256. What a drive already has is shown without a password.</sub></td>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-firmware-details.png" width="100%" alt="Details of a firmware pack: source, files, SHA-256 and download URLs"><br>
<sub><b>Every file, its source and its SHA-256.</b> </sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/assets/screenshots/app-drive-light.png" width="100%" alt="The desktop app in its light theme"><br>
<sub><b>Light theme.</b> </sub></td>
<td width="50%"></td>
</tr>
</table>

</details>

The boot menu pictures are from QEMU; the app pictures use its demo mode (simulated drives, an
example Secure Boot key). [`scripts/make_screenshots.sh`](scripts/make_screenshots.sh) takes them all
again; the colours are in [docs/assets/BRAND.md](docs/assets/BRAND.md).

## Download and use

Each [release](https://github.com/cynak/BeastBoot/releases) has a portable package per OS. Unpack it
and run it; nothing is installed.

| OS | File | Start |
|---|---|---|
| Windows 10+ (x86_64) | `beast-boot-<v>-windows-x86_64.zip` | `BeastBooter.cmd` |
| macOS, Apple silicon | `beast-boot-<v>-macos-arm64.zip` | `BeastBooter.app` |
| macOS, Intel | `beast-boot-<v>-macos-x86_64.zip` | `BeastBooter.app` |
| Linux (x86_64) | `beast-boot-<v>-linux-x86_64.tar.gz` | `./BeastBooter` |

Check the download against the release's `SHA256SUMS` first (how:
[SECURITY.md](SECURITY.md#verifying-a-release)). The apps are not code
signed yet, so Windows SmartScreen and macOS Gatekeeper warn on the first
start; [docs/PORTABLE.md](docs/PORTABLE.md#run-it) says how to get past
them. The window runs as you; only writing to the USB drive asks for
administrator rights.

The same package has the command line (`beast-boot.cmd`,
`beast-boot.command`, `./beast-boot`):

```sh
beast-boot list-devices                      # drives you can write to
beast-boot install --device /dev/sdX         # make a beast-boot drive (ERASES it)
beast-boot update  --device /dev/sdX         # new boot files, your ISOs stay
beast-boot info    --device /dev/sdX         # show the drive's layout
beast-boot firmware catalog                  # optional WiFi/Ethernet firmware packs
```

`--device` is `/dev/sdX` on Linux, `/dev/diskN` on macOS and
`\\.\PhysicalDriveN` (or `N`) on Windows. `--image FILE --size 8G` makes a
disk image instead, without administrator rights. Every command has
`--help`.

## Quick start

1. Start **BeastBooter**, choose the USB drive, click **Next: options**,
   keep the defaults (exFAT, MBR) and click **Install...**. Everything on
   the drive is erased.
2. Copy `.iso` files onto the drive's `BEASTBOOTER` partition, in any folders.
3. Boot the computer from the drive (its one-time boot menu key, often F12,
   F11, F10, F8 or Esc) and pick an ISO.
4. With Secure Boot on, enroll the BeastBoot key once per computer (below).

The step-by-step version, with every option and the common errors:
[docs/USER_GUIDE.md](docs/USER_GUIDE.md).

## How it works

```
 USB drive
 ├── partition 1  "BEASTBOOTER"  exFAT / FAT32 / NTFS   your files and ISOs
 └── partition 2  "BEAST-EFI"    FAT32, 512 MiB         boot files: shim, GRUB, menu, theme, network helper
```

On boot, GRUB finds partition 1, lists the `.iso` files and folders, and
boots the one you choose with a recipe for its distribution family
(Ubuntu/casper, Debian live, Arch, Fedora live and installer, openSUSE, or
the ISO's own `loopback.cfg`). Updating rewrites only partition 2 and the
boot code; your files are never touched. Settings go in
`/beast-booter/config.cfg` on the drive ([docs/MENU.md](docs/MENU.md)).
Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ISO_SUPPORT.md](docs/ISO_SUPPORT.md).

## ISO compatibility

Which ISOs boot from which data-partition filesystem. Every ✅ is a real,
official ISO (checksum-verified) booted from a BeastBoot drive in QEMU on
both UEFI and legacy BIOS with Secure Boot off, until its own system or
installer was running. exFAT is the default and the safest choice; FAT32
cannot hold files over 4 GiB; some distributions' start-up code cannot read
NTFS. With Secure Boot on, see [Secure Boot](#secure-boot).

<!-- iso-matrix:start -->
| ISO | exFAT | FAT32 | NTFS |
|---|---|---|---|
| Fedora Workstation 44 Live | ✅ | ✅ | 🚫 |
| Fedora Everything 44 netinst (Anaconda) | ✅ | ✅ | 🚫 |
| AlmaLinux 10.2 boot ISO (Anaconda) | ✅ | ✅ | 🚫 |
| Rocky Linux 10.2 boot ISO (Anaconda) | ✅ | ✅ | 🚫 |
| openSUSE Tumbleweed GNOME Live (KIWI) | ✅ | ✅ | 🚫 |
| openSUSE Tumbleweed NET installer (linuxrc) | ✅ | ✅ | ✅ |
| openSUSE Leap 15.6 NET installer (linuxrc) | ✅ | ✅ | ✅ |
| openSUSE Leap 16.0 online installer (Agama, KIWI) | ✅ | ✅ | 🚫 |
| Ubuntu 26.04.1 Desktop | ✅ | 📏 | ✅ |
| Ubuntu 26.04.1 Server | ✅ | ✅ | ✅ |
| Linux Mint 22.3 Cinnamon | ✅ | ✅ | ✅ |
| Debian 13.7 live standard | ✅ | ✅ | ✅ |
| Debian 13.7 netinst (debian-installer) | ✅ | ✅ | ✅ |
| Arch Linux 2026.10.01 | ✅ | ✅ | ✅ |
| Alpine Linux 3.24.3 standard | ✅ | ✅ | ✅ |
| SystemRescue 13.02 | ✅ | ✅ | ✅ |
| GParted Live 1.8.1-6 | ✅ | ✅ | ✅ |
| Clonezilla live 3.3.3-37 | ✅ | ✅ | ✅ |
| Windows 11 Enterprise 26H2 evaluation (en-US) | ✅ | 📏 | ✅ |

✅ boots on UEFI and BIOS (Secure Boot off), tested with the real ISO · 🚫 refused with an explanation: the ISO's own start-up code cannot read NTFS · 📏 does not fit: FAT32 files are limited to 4 GiB · – not tested yet.

Generated by `scripts/iso_matrix.py` from the real-ISO boot checks of BeastBoot 0.3.1+425d511009dc (`BB_REAL_ISO=1`, [tests/e2e/REAL_ISOS.md](tests/e2e/REAL_ISOS.md)); details per ISO in [docs/ISO_SUPPORT.md](docs/ISO_SUPPORT.md).
<!-- iso-matrix:end -->

## Disk tools

New in 0.3.0. Pick **Disk tools: recovery and cloning** in the boot menu's
Tools. BeastBoot starts its helper and shows every disk and every RAID or
volume set on the computer. You can check disk health, rescue a failing
disk, clone a disk, a partition or a RAID volume to another disk, save it as
an image file, or restore an image. It needs the helper on the drive and
1 GiB of RAM.

| Storage | What BeastBoot does | Tested |
|---|---|---|
| Plain disks, GPT/MBR, NTFS, ext4 | shows, health-checks, clones, images, restores | yes (QEMU, NVMe and SATA) |
| Linux md RAID 0, 1, 5, 6, 10 and linear, also degraded or with a write-intent bitmap | starts the set read-only on in-memory overlays; copy the whole volume | yes (QEMU) |
| Intel RST/VROC (IMSM) RAID | starts it read-only (refused while it rebuilds or migrates, or with RWH/PPL turned on) | RAID5 in QEMU; not on real Intel RST/VMD hardware yet |
| DDF firmware RAID | starts it read-only on in-memory overlays | RAID1 in QEMU |
| LVM (also two groups with the same name) | starts plain (linear/striped) volumes read-only on overlays; groups with RAID, mirror, cache, thin or snapshot volumes are refused: image their disks | yes (QEMU) |
| LUKS2, BitLocker | opens it read-only with your passphrase or recovery key | LUKS2 in QEMU; BitLocker not yet |
| Windows dynamic disks | detected; image each disk | not yet |
| Btrfs on several disks | starts it read-only | RAID1 in QEMU |
| Hardware RAID controllers (MegaRAID/PERC, Smart Array, Adaptec, LSI) | drivers are included; each array shows as one disk | not tested |
| AMD RAID, Storage Spaces, a set whose RAID information is gone | works out the layout from the data, on in-memory overlays; manual RAID builder if needed | wiped md RAID0/RAID5 rebuilt, also with one member missing (QEMU); not real AMD arrays |
| ZFS | needs an optional ZFS pack (not shipped yet); the menu says so | no |

On an AMD board in SATA RAID mode Linux sees each disk on its own, so the
members can be imaged and the set rebuilt. AMD NVMe RAID is not verified.
Details: [docs/DISK_TOOLS.md](docs/DISK_TOOLS.md).

### What BeastBoot promises

- **Sources are never written.** When Disk tools start, every disk and
  partition is set read-only. RAID sets, LVM and encrypted volumes start
  read-only too, and RAID sets and LVM on in-memory copy-on-write overlays,
  so even a write the kernel makes on its own (a RAID bitmap update) lands
  in memory.
- **Guessing a RAID layout never touches the disks.** Experiments run on
  copy-on-write overlays in memory.
- **Only the target you confirm can be written.** You see a plan first, then
  type the last 6 characters of the target's serial number. The disk is
  checked again right before writing.
- **Refused:** the BeastBoot drive, the source, any disk of the source set,
  a disk in use, and a smaller target.
- **Stopped copies resume.** The progress file is kept on the BeastBoot drive.
- **Checked.** A copy is verified with SHA-256 by default.
- **A copy of one disk of a RAID set is that disk, not the set.**

In our tests every source disk was hashed before and after and stayed
unchanged. Even so, for data you cannot lose, copy it first and work on the
copy.

### Rescue a disk

1. Boot the drive and choose **Tools**, then **Disk tools: recovery and cloning**.
2. Pick the disk (or the RAID set) with the problem. **Check its health**
   first. For a RAID set Linux cannot read, pick **Work out its RAID layout**.
3. Choose **Copy it to another disk (clone)** or **Save it as an image
   file**. Images go to the BeastBoot drive (exFAT or NTFS) or to another
   disk you open for image files (exFAT, NTFS, ext4 or XFS).
4. Read the plan. For a clone, type the last 6 characters of the target's
   serial number.
5. Wait for the copy. If it stops, start the same copy again and it
   resumes. Then work on the copy, not on the failing disk.

Full walk-through: [docs/USER_GUIDE.md](docs/USER_GUIDE.md#9-disk-tools).

## Secure Boot

On the first boot with Secure Boot on, shim reports that it can't verify
BeastBoot and opens MokManager. Choose **Enroll key from disk**, select
`ENROLL_THIS_KEY_IN_MOKMANAGER.cer` on the `BEAST-EFI` volume, check the
fingerprint, confirm, and reboot. This is a one-time step per computer.
ISOs then boot if their kernel is signed by a key the machine trusts:
Debian out of the box; other distributions after you enroll their key;
unsigned ones only with Secure Boot off.

**Ubuntu and Ubuntu-based ISOs** (Linux Mint and others that use Ubuntu's
signed kernel): since 0.1.2 the drive's shim is Debian's, which does not
trust Ubuntu's key by itself. Either turn Secure Boot off, or choose
**Trust Ubuntu's Secure Boot key** in the menu's tools once per computer: it
adds Ubuntu's revoked keys to MokListX, then Ubuntu's key to MokList, each
confirmed in MokManager after a reboot. That setting belongs to the computer,
so other systems on it trust Ubuntu's key too.

**Known limits of 0.1.1 and older** (Secure Boot on only), fixed in 0.1.2:
a PC that has applied the November 2025 SBAT revocation (`grub,6`) refused
their GRUB (Ubuntu's 2.14 build, truthfully `grub,5`; 0.1.2 builds GRUB from
source and proves the fixes before it says `grub,6`), and a PC whose
firmware trusts only Microsoft's 2023 UEFI CA refused their shim (signed only
by the 2011 CA; 0.1.2 ships Debian's shim, signed by both). With an NTFS data
partition, GRUB cannot see your ISOs under Secure Boot; use exFAT or FAT32.
Full guide: [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md).

## Download an ISO from a link

The menu entry **Download an ISO from a link** starts beast-net, a small
helper built from Ubuntu's kernel, re-signed with the BeastBoot key (so it
works with Secure Boot on). It brings up Ethernet by DHCP or joins a WiFi network, downloads
an ISO over HTTPS into `/downloads/` with resume, checks an optional SHA-256
(required for plain `http://`), and reboots into the menu to boot it once.

Many WiFi chips need closed-source firmware, which BeastBoot does not
ship. If you want it, install a **firmware pack** from the desktop app
(**Firmware packs**) or with `beast-boot firmware fetch` and
`beast-boot firmware install`. Each pack's files come from the upstream
`linux-firmware` repository at one pinned tag; the app shows the source URL
and every SHA-256 before it downloads anything, and checks them all.
Details: [docs/BEASTNET.md](docs/BEASTNET.md).

## SBOM and vulnerabilities

BeastBoot puts third-party code in the boot chain (GNU GRUB built from
Ubuntu's source package, Debian's shim, and a Linux kernel from Ubuntu's
packages), so every release publishes what it
ships and what is known to be wrong with it:

| Release file | Contents |
|---|---|
| `beast-boot-<v>-sbom.cdx.json` | software bill of materials, CycloneDX 1.6 |
| `beast-boot-<v>-sbom.spdx.json` | the same in SPDX 2.3 |
| `beast-boot-<v>-vulnerabilities.json` | known vulnerabilities, machine-readable, with VEX status |
| `beast-boot-<v>-VULNERABILITIES.md` | the same for people, with how each one is remediated |

To produce them for your own build: `make build`, then `make vulns`. Besides
CVEs (grype, osv-scanner), the scan checks boot-chain risks that CVE
databases miss: SBAT revocation levels, the certificates that signed shim
and GRUB, and the UEFI revocation list (dbx). Triage decisions are kept in
[`sbom/vex.openvex.json`](sbom/vex.openvex.json). How it all fits:
[sbom/README.md](sbom/README.md). To report a vulnerability:
[SECURITY.md](SECURITY.md).

## Develop

```sh
make dev       # toolchain (rootless, into .tools/), .venv, signing key, dist/, tests, dev image
make doctor    # what is missing and how to fix it
make test      # installer unit tests
make e2e       # 100 end-to-end tests in QEMU: BIOS, UEFI, Secure Boot, beast-net
make lint      # ruff + ShellCheck
make vm        # boot the dev image in QEMU (MODE=bios|uefi|sb|sb-enrolled|sb-fresh)
```

No root needed. Guide: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).

## Build

```sh
make keys       # your own Secure Boot signing key in keys/
make build      # boot files into dist/ (with dist/manifest.json)
make portable   # portable app for this OS into out/portable/ (ARGS=--all for all four)
make release    # every release file into out/release/
```

Releases are built by GitHub Actions when a `vX.Y.Z` tag is pushed, with
`SHA256SUMS` and build-provenance attestations. See
[docs/RELEASING.md](docs/RELEASING.md) and
[docs/PORTABLE.md](docs/PORTABLE.md#building-the-packages-yourself).

## Documentation

| Document | For |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | making a drive, booting, updating, troubleshooting |
| [docs/PORTABLE.md](docs/PORTABLE.md) | the portable packages: checking, running, building |
| [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md) | chain of trust, enrolling and removing the key, SBAT |
| [docs/MENU.md](docs/MENU.md) | the boot menu and `/beast-booter/config.cfg` |
| [docs/ISO_SUPPORT.md](docs/ISO_SUPPORT.md) | which ISOs boot, recipes, filesystems |
| [docs/BEASTNET.md](docs/BEASTNET.md) | network download and firmware packs |
| [docs/DISK_TOOLS.md](docs/DISK_TOOLS.md) | Disk tools: safety rules, support, script steps |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the contract between the components |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | dev setup, loops, tests, debugging |
| [docs/CODE_QUALITY.md](docs/CODE_QUALITY.md) | `make lint`: ruff and ShellCheck |
| [docs/RELEASING.md](docs/RELEASING.md) | release process and release files |
| [tests/e2e/README.md](tests/e2e/README.md) | the QEMU end-to-end tests |
| [sbom/README.md](sbom/README.md) | SBOM, vulnerability reports, VEX triage |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) | contributing, security policy, verifying releases |

## Roadmap

- **0.1:** desktop app and CLI for Linux, Windows and macOS
  (portable packages); drives and images, MBR/GPT, exFAT/FAT32/NTFS; dark
  graphical menu with folder browsing and a System information page; Linux
  distro recipes; BIOS + UEFI + Secure Boot via MOK; network download over
  Ethernet and WiFi with optional firmware packs; Ubuntu desktop ISOs boot
  from exFAT using the ISO's own exFAT driver; reproducible,
  manifest-verified build; SBOM and vulnerability scan; QEMU test suite.
- **0.1.2:** GRUB built from source with `grub,6` and
  current security fixes; Debian's shim, signed through Microsoft's 2011 and 2023 UEFI CAs;
  opt-in "Trust Ubuntu's Secure Boot key"; helper kernel 7.3.
- **0.2.0:** real ISOs verified to boot (UEFI and BIOS, Secure
  Boot off) by an opt-in QEMU harness: Fedora/Alma/Rocky (live and
  Anaconda), openSUSE Tumbleweed and Leap 16, Ubuntu desktop and server,
  Mint, Debian live and netinst, Arch, Alpine, SystemRescue, GParted,
  Clonezilla; Windows 11 installation ISOs (Windows Setup from the ISO on
  the stick, or Windows PE; Windows 10 expected, not tested) with Secure
  Boot off. See [ISO compatibility](#iso-compatibility).
- **0.3.0 (this release):** Disk tools: recovery and cloning, RAID-aware
  (md, Intel RST, DDF, LVM, LUKS, Btrfs; layout reconstruction for AMD RAID and
  lost RAID information). See [Disk tools](#disk-tools).
- **Next:** filesystem-independent ISO mapping, so a distro's
  initramfs no longer needs to understand exFAT/NTFS (dracut ISOs on NTFS);
  Windows under Secure Boot; code-signed app packages.
- **Later:** 32-bit and ARM64 UEFI, persistence, per-ISO settings.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). BeastBoot distributes GNU GRUB
(GPL-3.0-or-later, built from Ubuntu's source package), shim (BSD-2-Clause,
Debian's package) and a Linux kernel (GPL-2.0, Ubuntu's package); each package's licence is listed in the SBOM.
