# Secure Boot and BeastBoot

BeastBoot boots with UEFI Secure Boot **on**. It does that the same way
Linux distributions do: with a Microsoft-signed *shim*, and without weakening
any check. The one thing you have to do yourself is enroll the BeastBoot
key once per computer, in a blue screen called MokManager. This page explains
what is trusted and why, how to enroll (and later remove) the key, how to
check the key first, which ISOs can boot with Secure Boot on, and how to let a
computer trust Ubuntu's key, which Ubuntu ISOs need since 0.1.2.

Statements marked **(unverified)** are believed correct but have not been
tested by the project. Corrections are welcome.

## 1. Chain of trust

```
firmware (Secure Boot db: Microsoft UEFI CA 2011 and/or 2023)
  └─ EFI/BOOT/BOOTX64.EFI     shim 16.1, from Debian's shim-signed, signed by Microsoft
       │                      (through both the 2011 and the 2023 UEFI CA)
       ├─ EFI/BOOT/mmx64.efi  MokManager, signed by Debian (trusted via shim's built-in Debian certificate)
       └─ EFI/BOOT/grubx64.efi  BeastBoot GRUB with the menu inside it, signed with the BeastBoot
            │                   GRUB certificate (trusted only after YOU enrolled the BeastBoot CA
            │                   certificate, which issued it, as a MOK)
            ├─ beast-net/vmlinuz  the network helper: Ubuntu's kernel, re-signed with the BeastBoot
            │                     kernel certificate (same CA)
            ├─ beast-booter/wimboot  the Windows loader, signed with the BeastBoot wimboot certificate
            │                        (same CA)
            └─ kernel of the ISO you pick: GRUB hands it to shim, which checks it
               against the firmware db, your MOK list and Debian's certificate
               (and refuses anything in dbx, your MokListX or shim's own revocation lists)
```

| File on the drive | Signed by | Trusted because |
|---|---|---|
| `EFI/BOOT/BOOTX64.EFI` (shim 16.1, Debian `shim-signed 1.51+16.1-2`, unmodified) | Microsoft, twice over the same Authenticode digest: one signature chains to Microsoft Corporation UEFI CA 2011, the other to Microsoft UEFI CA 2023 | one of those CAs is in the firmware `db`: old PCs have the 2011 CA, new ones may have only the 2023 CA |
| `EFI/BOOT/mmx64.efi` (MokManager, Debian `shim-helpers-amd64-signed 1+16.1+2`, unmodified) | Debian Secure Boot Signer 2022 - shim | shim has Debian's CA built in |
| `EFI/BOOT/grubx64.efi` (BeastBoot GRUB; since 0.5.0 with the menu scripts, hooks, theme and fonts inside, [below](#the-menu-is-inside-the-signed-image-050)) | the BeastBoot GRUB certificate, issued by the BeastBoot CA ([below](#one-ca-three-signing-certificates-050)) | you enrolled the CA certificate, `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`, in MokManager |
| `beast-booter/wimboot` (iPXE wimboot 2.9.0 + our patches, 0.4.0) | the BeastBoot wimboot certificate (it also carries the BeastBoot SBAT line) | the same enrolled CA certificate |
| `beast-net/vmlinuz` (Ubuntu's kernel, code unchanged) | the BeastBoot kernel certificate (the build removes Canonical's signature and signs it again) | the same enrolled CA certificate |
| kernels inside ISOs | their distribution | see [section 6](#6-which-isos-boot-with-secure-boot-on) |

Why BeastBoot has its own GRUB: Ubuntu's signed GRUB cannot read exFAT or
NTFS, the filesystems your ISOs usually live on. BeastBoot's GRUB has exFAT
and NTFS built in and is signed under the BeastBoot CA. Ventoy uses the same
model.

### One CA, three signing certificates (0.5.0)

Up to 0.4.x one self-signed certificate signed everything, and that
certificate was what you enrolled. A bad build of one component could then
only be shut out one file at a time (by its hash), or by giving up the key
for all of them.

Since 0.5.0 you enroll the **BeastBoot CA certificate**. The CA signs nothing
that boots; it issued three signing certificates ("leaves"), and each signed
file has its own:

| File | Signed with | Subject says |
|---|---|---|
| `EFI/BOOT/grubx64.efi` | the GRUB leaf | `OU=grub` |
| `beast-net/vmlinuz` | the kernel leaf | `OU=kernel` |
| `beast-booter/wimboot` | the wimboot leaf | `OU=wimboot` |

- shim trusts a file when its signer chains to something in MokList, so one
  enrolled certificate, the CA's, covers all three. The signature carries
  only the leaf certificate; shim finds the CA in MokList.
- shim refuses a file when its signer is in MokListX. So **one MokListX entry,
  a leaf certificate, shuts out every build of that one component** and
  leaves the other two working, also while the CA stays in MokList. The
  project can then issue a new leaf from the CA: builds signed with it start
  again with nothing new to enroll ([section 7](#7-sbat-and-revocation-in-plain-words)).
- The CA's private key is offline, on the maintainer's own computer, never in
  GitHub or CI. Only the three leaf keys are where releases are signed
  ([RELEASING.md section 3](RELEASING.md#3-the-release-signing-keys)).
- `build/verify-dist.sh` checks that each of the three files carries exactly
  one signature, made with the leaf the manifest names for it
  (`secure_boot.signer_<component>_*`), that the leaf's subject names that
  component, that no two share a leaf, and that all chain to the CA
  certificate on the drive (`--cert`: to the one you got elsewhere).

What was checked with the drive's shim (Debian 16.1) under OVMF with Secure
Boot on, MokList and MokListX pre-seeded as MokManager stores them
(`tests/e2e/test_e2e_ca_chain.py`):

| Case | Result |
|---|---|
| only the CA in MokList | shim starts GRUB; GRUB (through shim) starts the helper's kernel and wimboot |
| the kernel leaf, or the wimboot leaf, in MokListX (CA still in MokList) | that one is refused, GRUB and the other start |
| the GRUB leaf in MokListX | shim refuses GRUB (the screen of [section 2](#2-first-boot-with-secure-boot-on-enroll-the-key), step 1) |
| the wimboot leaf in MokListX, wimboot signed with a new leaf from the same CA | starts; MokList unchanged |
| only a 0.4.x-style certificate in MokList | shim refuses GRUB, as on a PC that enrolled nothing |
| the CA certificate also embedded in the signature (`sbsign --addcert`) | starts: allowed, not needed |
| the leaf enrolled instead of the CA | starts |
| the issuing certificate is not a CA (`CA:FALSE`), or its keyUsage lacks `keyCertSign` | refused |
| the issuing CA has no keyUsage at all, no `pathlen`, or an added `codeSigning` EKU | starts |
| the leaf has no EKU, another EKU (`serverAuth`), or no extensions at all | starts: shim does not require `codeSigning` on the signer |
| the *enrolled* certificate carries the "kernel module signing only" EKU (1.3.6.1.4.1.2312.16.1.2) | refused |
| a leaf with that EKU under an enrolled CA without it | starts: shim checks that EKU on the certificate it trusts, not on the signer |
| leaf expired, CA expired, leaf not yet valid | starts: dates are not checked |

The last rows are why BeastBoot's certificates are strict by construction
(`build/keygen.sh`: CA `CA:TRUE, pathlen:0, keyCertSign`; leaf `CA:FALSE,
digitalSignature, codeSigning`) and why the build, not shim, enforces the
rest: a file must be signed with *its own component's* leaf (the `OU`), by a
leaf the pinned CA issued, exactly once.

#### Certificate dates

Firmware and shim do not check certificate dates (tested above, for a leaf
and for the CA). The CA is made for 20 years and a leaf for 10. When a leaf
expires nothing that is already signed stops booting. What stops is the
build: `build/build.sh` and `build/sign.sh` refuse to sign with an expired
leaf, and `make vulns` reports a leaf or CA within a year of its end. The
maintainer then issues a new leaf from the CA; users notice nothing. An
expired CA can no longer issue leaves that the build's tools accept, so a new
CA (and a new enrolment for everyone) is due before then, in 2046 for a CA
made in 2026.

### Why Debian's shim

Up to 0.1.1 the drive used Ubuntu's shim (`shim-signed 1.59+15.8-0ubuntu2`),
which is signed only through Microsoft UEFI CA 2011. New PCs whose firmware
trusts only Microsoft UEFI CA 2023 refuse it. Since 0.1.2 the drive uses
Debian's shim 16.1, which carries both signatures, so it starts on old and
new PCs.

- The pin is Debian **sid**, not trixie: trixie's shim
  (`1.51~1+deb13u1+16.1-2~deb13u1`) is dual-signed too, but not marked
  `NX_COMPAT`; sid's is. Both packages and their SHA-256 are pinned in
  `build/shim/debian-shim.lock` (see `build/shim/README.md`).
- The build fails unless `BOOTX64.EFI` has a signature chaining to each
  Microsoft CA, both over the image's own Authenticode digest
  (`scripts/efi_inspect.py`, an `openssl` check against
  `build/shim/microsoft-uefi-ca-{2011,2023}.pem`), unless MokManager is
  signed through shim's vendor certificate, and unless both files are
  byte-identical to the ones in the locked `.deb`s. `build/verify-dist.sh`
  repeats the signature checks on `dist/`.
- The cost: Debian's shim has Debian's key built in, not Canonical's. With
  Secure Boot on, kernels signed by Ubuntu are therefore refused until you
  choose to trust Ubuntu's key
  ([section 6](#trust-ubuntus-secure-boot-key-optional)). Kernels signed by
  Debian now boot.
- The helper kernel (`beast-net/vmlinuz`) is Ubuntu's, so the build treats it
  like `grubx64.efi`: it checks that the kernel is signed through Canonical's
  Master CA and not by a certificate Ubuntu revoked (`build/trust/canonical/`),
  removes every signature (`sbattach --remove`) and signs it with the
  BeastBoot kernel certificate. The code is unchanged: its Authenticode digest is the same
  before and after, and the manifest records it
  (`secure_boot.beastnet_kernel_*`). An existing `dist/` copy is kept when
  the unsigned image is unchanged (`BB_RESIGN=1` forces a new signature).

### Where grubx64.efi comes from

BeastBoot **builds GRUB from source** (`build/grub/grubsrc.py`, run by
`make build`), so it can carry security fixes that Ubuntu has not shipped yet:

- **Source:** Ubuntu's `grub2` source package **2.14-2ubuntu3** (GNU GRUB 2.14
  with Ubuntu's 103 patches, including the Secure Boot ones: shim lock,
  lockdown, the `peimage` loader, font verification). The `.dsc`, the upstream
  tarball (byte-identical to `grub-2.14.tar.xz` from ftp.gnu.org) and the
  Debian tarball are pinned by SHA-256 in `build/grub/source.lock.json`.
- **Our patches** (`build/grub/patches/`, each with a header naming the CVE,
  the upstream commit and why): the fix for **CVE-2026-97876** (the `serial`
  command accepted raw port/MMIO addresses under lockdown; Debian's backport
  of upstream commit `26beaa3b`, which is in GRUB 2.16; this is the fix SBAT
  generation `grub,7` stands for, see section 7), and upstream commit
  `089d0567` (GRUB 2.16, no CVE): with shim 16, kernels failed to boot after
  `mokutil --disable-validation`, because GRUB then skipped shim's protocols
  and asked the firmware to load the kernel. Lockdown and signature checks
  are decided exactly as before. And Debian's fix `8719ef8a` (no CVE): with
  shim 16, Ubuntu's `peimage` module registered a second EFI loader next to
  shim's, so every Secure Boot boot printed "error: trying to register
  different loader."; `peimage` now registers only when shim offers no image
  loader (shim 15.x). The build checks all three are in the source.
- **Build:** Ubuntu's configure flags for `x86_64-efi` and `i386-pc`, the way
  `debian/rules` builds them, plus the matching `grub-mkimage`. The result is
  cached under `.tools/cache/grub-src/out/<key>` (key = source + patches +
  `security-fixes.json` + toolchain) and is reproducible: two builds give
  identical files, natively (the build deps of `debian/control` that matter;
  missing code generators are unpacked from pinned `.deb`s) or with
  `BB_GRUB_BUILDER=docker` in the pinned `ubuntu:26.04` image with an apt
  snapshot, which gives the same files. 296 of 304 `x86_64-efi` modules (including
  `kernel.img`) are byte-identical to Ubuntu's own `grub-efi-amd64-bin`; the
  rest differ only by the version string and our patch.
- **Version:** `2.14-2ubuntu3+bb1` (Ubuntu's version + our patch level).
- `grub-mkimage` is never given `--disable-shim-lock`, lockdown stays on, and
  the image keeps the PE `NX_COMPAT` flag that Ubuntu's signed GRUB has.
  GRUB hands kernels to shim through shim's image loader protocol when the
  shim offers it (shim 16) and through the `shim_lock` protocol otherwise
  (shim 15.x); both are in this source.

`build/verify-dist.sh --rebuild` builds GRUB from the same source and checks
that `grubx64.efi` (without its signature), `core.img`, `boot.img` and every
BIOS module on the drive are byte-identical.

With Secure Boot on, GRUB runs in *lockdown*: it refuses to load GRUB modules
from disk and asks shim to verify every kernel or EFI program before running
it. A kernel that does not verify is not started, and the menu tells you why.

### The menu is inside the signed image (0.5.0)

Lockdown and shim decide which *code* may run. They say nothing about the
GRUB script that drives GRUB. Up to 0.4.x that script (`grub.cfg`,
`grub/beast/*.cfg`), the hooks handed to a booted Linux, and the theme were
plain files on the boot partition: with Secure Boot on, someone who could
write to the drive could change what the menu does (skip its checks, show
fake screens, start another ISO than the one chosen, choose the arguments of
signed kernels, wimboot and the helper, change the hooks that run as root in
the booted system). Only signed code ran, but the menu could not be trusted.

Since 0.5.0 all of it is inside `grubx64.efi`, in a memdisk that is part of
what the BeastBoot GRUB certificate signs, and shim verifies the whole file before GRUB
starts:

- On UEFI GRUB starts the `grub.cfg` in that memdisk and nothing else. The
  image's embedded early config (`build/early-efi.cfg`) points GRUB's prefix
  at the memdisk and unsets `fw_path`, the variable through which Ubuntu's
  GRUB would otherwise start a `grub.cfg` found next to `grubx64.efi`.
- The menu runs no script and uses no hook, theme or font from the drive,
  **with Secure Boot on or off**: there is one UEFI code path. So
  `config.cfg` and `bb_theme` no longer work on UEFI
  ([MENU.md](MENU.md#on-uefi)).
- What it still reads from the drive is data: `grub/beast/device.env`,
  `grub/grubenv`, `/beast-booter/config.env` and the stamp of a prepared
  Windows copy, each a GRUB environment block read with `load_env` and a
  list of names, every value checked
  ([ARCHITECTURE.md §5](ARCHITECTURE.md#5-grub-runtime-contract)).
- The two scripts that the menu injects into Windows PE (`winpeshl.ini`,
  `beastboot.cmd`; they decide what runs there as SYSTEM) are in the memdisk
  too, and on UEFI wimboot gets those copies.
- `build/verify-dist.sh` rebuilds the memdisk from the menu files in the
  package and finds it, and the early config, in `grubx64.efi` byte for byte;
  `--rebuild` rebuilds the whole unsigned image.

What this does not cover, on purpose or by nature:

- **The ISOs.** Someone who can write the drive can replace an ISO. With
  Secure Boot on its kernel must still be signed by a key the PC trusts, but
  a signed kernel with another initramfs or root file system is not yours
  any more. An ISO that ships its own `boot/grub/loopback.cfg` has that file
  run by our GRUB when you start the ISO (it is that ISO's boot menu); it
  runs in lockdown, like everything else.
- **Unsigned parts of what is booted, still read from the drive**: the
  helper's `initrd.img` and firmware packs (they run as root in the helper),
  `beast-booter/winpe/beastmount.exe` (runs as SYSTEM in Windows PE; it
  attaches the ISO for Windows Setup), a Windows ISO's or prepared copy's
  `boot.wim`, and any ISO's initramfs. Secure Boot signs kernels and EFI
  programs, not these. For the files BeastBoot ships, the SHA-256 is in
  `manifest.json` (the installer checks them when writing the drive); nothing
  checks them at boot. The two Windows PE start-up *scripts* (`winpeshl.ini`,
  `beastboot.cmd`) are not in this list any more: on UEFI the menu injects
  the copies inside the signed `grubx64.efi`.
- **Settings.** `config.env` can still set `bb_autoboot`, `bb_kargs` and the
  other listed settings; the menu shows `bb_kargs` whenever it is set.
- **Legacy BIOS.** There is no chain of trust; GRUB reads the menu from the
  boot partition as before.
- **Rollback.** The drive is writable, so an older signed `grubx64.efi` (one
  that reads the menu from the drive) can be put back. Those images are
  SBAT generation `grub.beastbooter,1` and 0.5.0 is `2`, so they can be
  revoked as a class by SBAT, but nothing does that yet
  ([section 7](#7-sbat-and-revocation-in-plain-words)). What does work: they
  are signed with the pre-0.5.0 certificate, so a computer stops starting
  them once that certificate is removed from it
  ([section 4](#4-remove-a-certificate-later)).
- **Someone at the keyboard.** GRUB's command line (`c`) and entry editor
  (`e`) are there, in lockdown.

`tests/e2e/test_e2e_signed_menu.py` changes every menu file on the boot
partition, adds a `grub.cfg` next to `grubx64.efi`, and feeds the menu
hostile `device.env`, `grubenv` and `config.env` files, and replaces the two
Windows PE start-up scripts: none of it has an
effect under UEFI (Secure Boot on and off), while legacy BIOS runs the
changed files.

Every file on the drive is listed in `dist/manifest.json` with its SHA-256 and
origin (`deb:<package>=<version>:<path>` for files copied unmodified from an
Ubuntu or Debian package, `grub-src:grub2=<version>:<path>` for files of our GRUB
build, `built:deb:...` for the re-signed helper kernel). The build checks each such file against the package's own checksums
or the GRUB build's `build-info.json`.

## 2. First boot with Secure Boot on: enroll the key

You do this once per computer. It needs a keyboard at the computer; nothing
running in an operating system can do it for you (that is the point of MOK).
These screens were recorded with Ubuntu's shim 15.8 (BeastBoot 0.1.1) in a
virtual machine; Debian's shim 16.1 MokManager, which 0.1.2 ships, has the same
menus **(unverified: exact wording)**. Real firmware looks the same because shim
draws them, but colours and fonts may differ.

1. Boot from the BeastBoot drive. A blue screen says
   **ERROR — Verification failed: (0x1A) Security Violation** with an **OK** button.
   This is shim refusing BeastBoot's GRUB because it does not know the
   certificate yet. Press **Enter**.
2. **Shim UEFI key management — Press any key to perform MOK management**, with
   a countdown (10 seconds). Press any key. (If the countdown runs out, the
   computer moves on to the next boot device; just boot the drive again.)
3. **Perform MOK management**: choose **Enroll key from disk**.
4. **Select Key**: a list of volumes. Choose **BEAST-EFI** (the drive's boot
   partition). Some firmware may show a device path instead of the name.
5. A list of files: choose **ENROLL_THIS_KEY_IN_MOKMANAGER.cer**.
6. **[Enroll MOK]**: choose **View key 0** and check it (see
   [section 3](#3-check-the-key-before-you-enroll-it)): *Subject* should be
   the BeastBoot CA, and *[Fingerprint]* must match the published SHA-1
   fingerprint. Press a key to go back, then choose **Continue**.
7. **Enroll the key(s)?** The cursor starts on **No**. Choose **Yes**.
8. **Perform MOK management**: choose **Reboot**.

From now on this computer boots the BeastBoot menu directly.

**Coming from BeastBoot 0.4.x or older.** 0.5.0 is signed under a new
certificate (the BeastBoot CA; [section 1](#one-ca-three-signing-certificates-050)).
After you update a drive to 0.5.0, every computer with Secure Boot on shows
the screens above once more, also computers that enrolled the old
certificate: do steps 1 to 8 again, with the fingerprint of the new
certificate. The installer says so before it updates such a drive. With
Secure Boot off, and in legacy BIOS mode, nothing changes. A drive you have
not updated keeps starting with the old certificate. Once all your drives
are on 0.5.0 or later, remove the old certificate from each computer
([section 4](#4-remove-a-certificate-later)): until you do, that computer
still starts 0.4.x and older BeastBoot boot loaders, which run their menu
from the drive unsigned.

Alternative, if the computer already runs Linux: `sudo mokutil --import
ENROLL_THIS_KEY_IN_MOKMANAGER.cer` asks you to choose a one-time password;
on the next reboot MokManager shows **Enroll MOK** and asks for that password.

## 3. Check the key before you enroll it

Enrolling a key means: *this computer will run any boot program signed with
it*. Only enroll a key whose fingerprint you got from a source you trust: the
release notes of the BeastBoot build you use, or, if you built the drive
yourself, the output of `make keys` / `build/verify-dist.sh`.

Official releases from 0.5.0 on ship this certificate, the BeastBoot CA:

| | BeastBoot CA |
|---|---|
| Subject | `CN=BeastBoot Secure Boot CA` |
| SHA-1 (what MokManager shows) | `1B C0 9C 59 D6 9C 96 86 17 39` / `89 39 6B AF 6F A7 81 1F C7 8C` |
| SHA-256 | `46de5c5d5cd3a265b1da2ebbeed043f113705450f8546e273a54ec157b04d6b3` |
| Expires | 2046-11-12 |

A drive you built yourself has your own certificate, with other fingerprints.

MokManager's **View key** shows the **SHA-1** fingerprint as 20 hex pairs in
two rows, for example `97 4C 1D E1 A6 35 22 FA 23 3C` / `7A 24 B8 85 1B 62 C3 59 BA 94`
(that is the fingerprint of one developer's local test key, not a release key).

On Linux, print the fingerprints of the file on the drive:

```sh
openssl x509 -inform DER -in /path/to/BEAST-EFI/ENROLL_THIS_KEY_IN_MOKMANAGER.cer \
  -noout -subject -enddate -fingerprint -sha1 -fingerprint -sha256
```

or check a whole build (hashes, signatures, SBAT, fingerprints):

```sh
build/verify-dist.sh dist/                        # in a checkout of this repository
build/verify-dist.sh dist/ --cert published.crt   # also compare with a certificate you got elsewhere
```

After enrolling, `mokutil --list-enrolled` lists it with its `SHA1 Fingerprint`,
and `mokutil --test-key ENROLL_THIS_KEY_IN_MOKMANAGER.cer` says whether it is enrolled.

## 4. Remove a certificate later

From Linux on that computer (any Secure Boot Ubuntu live USB works too),
with the certificate file at hand:

```sh
sudo mokutil --delete ENROLL_THIS_KEY_IN_MOKMANAGER.cer   # choose a one-time password
sudo reboot
```

On reboot MokManager shows **Delete MOK**: view the key, confirm, enter the
password, reboot. `mokutil --list-delete` shows the pending request and
`mokutil --revoke-delete` cancels it. (`mokutil --reset` deletes *all* MOKs,
including keys used for DKMS drivers. Avoid it unless you know you want that.)

After removal, BeastBoot's GRUB is refused again (you get the screen from
step 1). Nothing else on the computer changes.

**The old certificate of 0.4.x and older.** After an update the drive holds
only the new certificate file, so take the old one from the computer itself:

```sh
mokutil --export                       # writes MOK-0001.der, MOK-0002.der, ... (everything enrolled)
for f in MOK-*.der; do echo "$f: $(openssl x509 -inform DER -in "$f" -noout -subject -fingerprint -sha1)"; done
sudo mokutil --delete MOK-000N.der     # the one whose subject is the old beast-boot key, not the BeastBoot CA
sudo reboot                            # confirm in MokManager: Delete MOK
```

(or use the `.cer` of the 0.4.x release you had, if you kept it). The old
certificate is self-signed and its subject is the name of the old key, for a
release build `beast-boot Secure Boot release key`; the new one is the
BeastBoot CA. Compare the SHA-1 fingerprints with the release notes if in
doubt. BeastBoot cannot remove it for you: like enrolling, removing a MOK
takes someone at that computer.

## 5. Use your own key instead

If you would rather trust keys you made yourself:

```sh
make keys      # build/keygen.sh: a local CA and three signing certificates (RSA-2048)
make build     # signs grubx64.efi, beast-net/vmlinuz and beast-booter/wimboot, each with its own
beast-boot update --device /dev/sdX    # or install, see the README
```

- `make keys` writes into `keys/` (git-ignored): `beast-boot-ca.key` (the
  CA's private key, mode 0600), `beast-boot.crt` and `beast-boot.cer` (the CA
  certificate; the `.cer` is copied to the drive), and
  `beast-boot-{grub,kernel,wimboot}.key` and `.crt` (the three leaves). It
  prints the fingerprints. It refuses to overwrite existing files unless you
  run `build/keygen.sh --force`. `build/keygen.sh leaf wimboot --force`
  replaces one leaf and keeps the CA. `BB_KEY_CN` sets the CA's name,
  `BB_KEY_DIR` the directory (`make build` reads `BB_KEY_DIR` too), `BB_CA_DIR`
  a separate place for the CA (`build/keygen.sh ca`, `build/keygen.sh leaf all`).
  The build needs the leaf keys and the certificates, never the CA key.
- Computers must enroll *your* certificate (section 2). A computer that
  enrolled another BeastBoot key will not trust your build, and the reverse.
- This is also how you change the menu or its look for UEFI: the menu
  scripts (`grub/`, or `BB_MENU_DIR`) and the theme (`build/theme/`) are
  inside `grubx64.efi`, so a changed menu is your own build, signed with your
  own key. Editing the files on the drive only changes what legacy BIOS runs.
- **Protect the private keys.** Anyone who has the CA key, or a leaf key, can
  make boot programs that every computer with your CA certificate enrolled
  will run. Keep the CA key offline. If a leaf key leaks, revoke that leaf
  (section 7) and issue a new one; if the CA key leaks, remove the CA
  certificate from every computer (section 4) and make a new CA.
- Rebuilding with the same keys keeps the existing signature as long as the
  GRUB image (or the helper kernel) did not change (`BB_RESIGN=1` forces a new signature). A new
  signature has a new signing time, so `grubx64.efi` gets a new SHA-256; the
  manifest's `grub_unsigned_sha256` (the image without its signature) stays
  the same and can be reproduced by anyone with `build/verify-dist.sh --rebuild`.

## 6. Which ISOs boot with Secure Boot on

GRUB asks shim to verify the ISO's kernel (or EFI program). shim accepts it if
it is signed by a key in the firmware `db`, by a key in your MOK list, or by
Debian (the key built into Debian's shim), and it is not revoked (firmware
`dbx`, your MokListX, shim's own revocation list, SBAT). Since 0.1.2 shim has
**no** Canonical key built in.

- **Debian** (official images): kernels are signed by Debian, so they boot
  **(expected; not tested with a real Debian ISO)**.
- **Ubuntu and its official flavours** (Kubuntu, Xubuntu, Ubuntu MATE, ...)
  and **distributions that ship Ubuntu's signed kernels** (for example Linux
  Mint, elementary OS, Zorin OS **(unverified)**): kernels are signed by Canonical,
  so they are **refused** until you trust Ubuntu's key on that computer
  ([below](#trust-ubuntus-secure-boot-key-optional)), or boot with Secure Boot
  off. The menu says so: "Secure Boot stopped this ISO from starting", with
  "Trust Ubuntu's Secure Boot key" as the first suggestion. **Old releases may
  not boot even then**: the trust step also puts the eight older Canonical
  signing certificates Ubuntu revoked (2012 to 2021) into MokListX, so ISOs
  whose kernel was signed with them are refused — roughly anything released
  before mid-2022 **(unverified cut-off)**. Check with `sbverify --list` on the
  ISO's kernel.
- **Other distributions** (Fedora, openSUSE, ...) sign their kernels
  with their own keys, which only *their* shim trusts. With BeastBoot you
  can either enroll that distribution's Secure Boot certificate as a MOK
  (get it from the distribution, then `mokutil --import` it) **(unverified:
  works if the kernel signature chains to that certificate)**, or turn Secure
  Boot off in the firmware settings for that boot.
- **Unsigned kernels** (for example Arch Linux's official ISO, many rescue
  ISOs) do not boot with Secure Boot on. Turn Secure Boot off, or sign them
  yourself and enroll your key — your choice, not BeastBoot's.
- **Windows ISOs** (installation, Windows PE) boot through wimboot, which
  since 0.4.0 is signed by BeastBoot (since 0.5.0 with its own certificate
  under the CA you already enrolled, so there is nothing new to trust). GRUB cannot read Microsoft's
  UDF ISOs while Secure Boot is on, so the ISO's `boot.wim` is copied once to
  the data partition (**Prepare this Windows ISO for Secure Boot** in the
  menu, or `beast-boot prepare-windows` on the computer). The copy needs no
  trust: the firmware verifies Windows' own boot manager and Windows verifies
  the rest. Limit: Windows' boot manager must be trusted by the PC's `db` and
  not be revoked in `dbx`. An old ISO on an updated PC, or a `db` without the
  right Microsoft CA, fails exactly as Microsoft's own USB media would;
  wimboot then shows `Could not load ...` and the menu only sees
  `boot-failed`. Details: [ISO_SUPPORT.md](ISO_SUPPORT.md#windows) and
  [WINDOWS_SECURE_BOOT.md](WINDOWS_SECURE_BOOT.md).

BeastBoot never works around a failed check. The menu explains what failed
and what you can do (trust Ubuntu's key, enroll that distribution's key, or
turn Secure Boot off).

### Trust Ubuntu's Secure Boot key (optional)

**Tools menu > "Trust Ubuntu's Secure Boot key"** (UEFI only, shown when the
network helper is on the drive; also in the helper's own **More** menu). It
starts the beast-net helper with `beastnet.action=trust-ubuntu`, which
enrolls exactly what Ubuntu's own shim trusts and revokes, in two steps. Each
step is only a *request*: you confirm it in MokManager after a reboot, with a
one-time password you choose in the helper.

1. **Revocations first.** Ubuntu's eight revoked Canonical signing
   certificates (Ubuntu shim's `vendor_dbx`) go into **MokListX**
   (`mokutil --mokx --import`). MokManager shows **Enroll MOKX**.
2. **Then the CA.** Only once all of them are in MokListX (as shim reports
   in `MokListXRT`) does the helper request **Canonical Ltd. Master
   Certificate Authority** for **MokList** (`mokutil --import`). MokManager
   shows **Enroll MOK**.

So Canonical's key is never requested while any revocation is missing, and
nothing new is requested while an earlier request is still waiting for
MokManager. Each request is read back from its EFI variable and cancelled
unless it holds exactly the requested files. The helper never touches the
firmware's `db` or `dbx`, and never enrolls anything other than these files
(`build/trust/canonical/`, extracted from Ubuntu's `shim-signed
1.59+15.8-0ubuntu2` and checked against `trust.json`).

Before each request the helper shows every certificate's subject and its
SHA-256 and SHA-1 fingerprints. Those files come from the stick, so compare
the CA with this page before you confirm it in MokManager (**View key**):

| | Canonical Ltd. Master Certificate Authority |
|---|---|
| Subject | `C=GB, ST=Isle of Man, L=Douglas, O=Canonical Ltd., CN=Canonical Ltd. Master Certificate Authority` |
| SHA-1 (what MokManager shows) | `76 A0 92 06 58 00 BF 37 69 01 C3 72 CD 55 A9 0E 1F DE D2 E0` |
| SHA-256 | `ed1fe72cb9ca31c9af5b757afcd733323d675825032e6ced7fe1ae9eb767998c` |
| Expires | 2042-04-11 |

In a checkout: `openssl x509 -inform DER -in
build/trust/canonical/canonical-master-ca.der -noout -subject -fingerprint -sha1`
(and `-sha256`).

What it means:

- **MokList and MokListX belong to the computer, not to the drive.** Every
  shim-based system on that computer (an installed Ubuntu, Fedora, Debian
  ...) then trusts what Canonical signed — boot loaders, kernels, firmware
  tools — and refuses the revoked certificates.
- **Undo:** the same screen offers **Stop trusting Ubuntu's key**, which
  requests deleting the CA from MokList (`mokutil --delete`; MokManager shows
  **Delete MOK**). The revocations stay in MokListX: they can only make shim
  refuse programs, never trust them.
- If MokManager times out or you choose **Continue boot**, nothing changes;
  the helper's screen shows whether a request is still waiting.
- The states it reports: *not trusted*, *revocations only (step 1 of 2
  done)*, *trusted*, *partly set up*, *built into this drive's shim* (a drive
  whose shim already trusts Canonical, as 0.1.1 and older did: nothing to
  enroll) and *cannot be checked here* (legacy BIOS, or no EFI variables).
  With Secure Boot off it still works, and says that the keys matter only
  with Secure Boot on.

The step-by-step version for users: [USER_GUIDE.md](USER_GUIDE.md#ubuntu-isos-with-secure-boot-on).
How the parts fit: `build/trust/README.md`; the helper side:
[BEASTNET.md](BEASTNET.md#8-trust-ubuntus-secure-boot-key).

### Tests

`tests/e2e/test_e2e_secureboot.py` boots the drive under OVMF with Secure Boot,
the keys pre-seeded with `virt-fw-vars` exactly as MokManager would store them:
the menu runs locked down, also with a `db` that holds only Microsoft UEFI CA
2023; unsigned EFI programs and kernels are refused; Ubuntu's Canonical-signed
kernel is refused without the trust step and boots with Canonical's CA in
MokList and the revoked certificates in MokListX; and MokListX works (a kernel
signed by a leaf certificate boots with its CA in MokList, and is refused once
the leaf is in MokListX). `tests/e2e/test_e2e_ca_chain.py` does the same for
BeastBoot's own CA and three leaves ([section 1](#one-ca-three-signing-certificates-050)). `tests/e2e/test_e2e_trust_ubuntu.py` runs the helper's
two steps under OVMF and reads the VM's variable store back: step 1 requests
exactly the eight revoked certificates, step 2 only Canonical's CA.

**Ubuntu on an exFAT drive with Secure Boot on.** For Ubuntu desktop (and
other casper or Debian live) ISOs on an exFAT drive the menu adds two files to
the ISO's initramfs (the
[exFAT add-on](ISO_SUPPORT.md#the-exfat-add-on)): the ISO's own `exfat`
kernel module and a small script that loads it. This does not touch the chain
of trust. shim still verifies the ISO's kernel; the initramfs is not covered
by Secure Boot signatures in any GRUB boot (the same is true when Ubuntu's own
`loopback.cfg` loads it); and the kernel, locked down by Secure Boot, still
checks the module's signature. It accepts the module because the ISO's kernel
build signed it. BeastBoot ships no kernel modules and signs none: the
module is exactly what the distribution built for that kernel. Tested with
Ubuntu 26.04.1 under OVMF with Secure Boot on (BeastBoot 0.1.1, whose shim
trusted Ubuntu's key by itself; since 0.1.2 Ubuntu's key must be trusted
first, see above): lockdown `integrity`, module loaded, not tainted.

Note that a locked-down Ubuntu kernel trusts more than its own build key: it
also accepts kernels and modules signed by keys enrolled in MOK, and that
includes the BeastBoot CA certificate you enrolled, and with it whatever a
certificate issued by that CA signs **(not tested; it follows from how the
kernel builds its trust chain)**. This is how DKMS modules work under Secure
Boot, and it is one more reason to check the certificate before you enroll
it (§3) and to remove it when you no longer need it (§4).

## 7. SBAT and revocation, in plain words

Signatures prove *who* made a boot program, not that it is free of known
security holes. When a hole is found in, say, GRUB, the fixed version gets a
higher **generation number**, and computers are told "refuse GRUB below
generation N". That table of names and generations inside each program is
**SBAT** (Secure Boot Advanced Targeting). shim checks it on every boot.
Revoking by generation is much cheaper than adding every old file's hash to
the firmware's small revocation list (`dbx`).

BeastBoot's GRUB carries these SBAT lines:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,7,Free Software Foundation,grub,2.14,https://www.gnu.org/software/grub/
grub.ubuntu,2,Ubuntu,grub2,2.14-2ubuntu3,https://www.ubuntu.com/
grub.ubuntu26,1,Ubuntu,grub2,2.14-2ubuntu3,https://www.ubuntu.com/
grub.peimage,2,Canonical,grub2,2.14-2ubuntu3,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
grub.beastbooter,2,beast-boot,grub2,2.14-2ubuntu3+bb1,https://github.com/cynak/BeastBoot
```

- **`grub,7`** (since 0.5.0; `grub,6` in 0.1.2 to 0.4.x) is the generation
  that shim's current revocation levels require. shim's
  `SbatLevel_Variable.txt` (rhboot/shim, branch main, read on 2026-11-15) says:

  ```
  Revocations for:
   - September 2026 grub CVE (CVE-2026-97876)

  sbat,1,2026092500
  shim,4
  grub,7
  ```

  This level was added by shim commit `20e9be4d` ("sbat: bump for September
  2026 Grub CVE", 2026-10-27). The newest level, `2026102600` (commit
  `e794a714`, a fwupd-efi issue), keeps `grub,7`. The level before,
  `2025112400`, requires `grub,6` (the November 2025 GRUB CVEs:
  CVE-2025-54770, -54771, -61661, -61662, -61663, -61664).
  We claim a generation only because the build *proves* every fix it stands
  for is in our source: `build/grub/security-fixes.json` names
  the upstream commit of each fix, and the GRUB build applies each commit **in
  reverse** (dry run, no fuzz) to the fully patched source, which only works
  when the fixed code is there. A missing fix stops the build (for `grub,7`:
  without our patch for CVE-2026-97876 the build refuses the claim); the result is
  recorded in the GRUB build's `build-info.json`, the manifest and the SBOM.
  (The November 2025 fixes are already in upstream GRUB 2.14; Ubuntu's 2.14
  packages just still say `grub,5`. The fix for CVE-2026-97876 is not in
  Ubuntu's 2.14 source; it comes from our patch.)
- **`grub.ubuntu`, `grub.ubuntu26`, `grub.peimage`** are Ubuntu's own lines
  from the source package (`debian/sbat.ubuntu.csv.in`), filled in as Ubuntu's
  build does. They describe Ubuntu's patches, which we include unchanged, so
  if Ubuntu's GRUB is revoked through them, ours is revoked too.
- **`grub.beastbooter`** is BeastBoot's own line: it is raised when a problem
  is specific to BeastBoot (our patches, the module choice, a bad signing), so
  older BeastBoot builds can be revoked without touching anyone else's.
  It is **2 since 0.5.0** (1 in 0.1.0 to 0.4.x). Generation 1 is every
  `grubx64.efi` that runs the menu from the boot partition, unsigned;
  generation 2 has the menu inside the signed image
  ([above](#the-menu-is-inside-the-signed-image-050)). What the bump means:
  - It is a label, not a revocation. **Nothing is revoked yet**: a 0.4.x
    drive, and a 0.4.x `grubx64.efi` copied onto a newer drive, still boot on
    every PC that has the pre-0.5.0 BeastBoot certificate enrolled.
  - It makes a revocation possible: a shim whose SbatLevel says
    `grub.beastbooter,2` refuses all generation 1 images at once and no
    0.5.0 or later image. SbatLevel comes only from the shim's built-in
    policy, and with Debian's shim we cannot add our line to it (the same
    limit as for wimboot, below). The working way to shut out the old images
    is their certificate: 0.5.0 is signed under the new BeastBoot CA, so
    removing the old certificate from a computer (section 4) ends every
    0.4.x and older image there.
  - Ubuntu's lines, shim's own SBAT and wimboot's lines are what they were.
    The `grub` line went from 6 to 7 in the same release, for the reason
    given above; that is a separate change.
- The build also refuses if any of our generations is below the revocation
  level built into the shim it ships.
- **Nothing is claimed ahead of shim.** A generation is raised only after shim
  publishes the level that requires it. 0.4.x already contained the fix for
  CVE-2026-97876 but said `grub,6`, because the level with `grub,7` was then
  only a proposal.

If a future revocation hits the GRUB on your drive, shim refuses it like an
unknown key (the screen from step 1) **(unverified: exact message)**. Update
the drive with a newer BeastBoot release; your ISOs on partition 1 are not
touched.

### Revoking one component, and replacing its certificate (0.5.0)

Two independent handles exist: SBAT generations (above) and certificates.
Certificates are the one BeastBoot can use today.

- **One component must stop booting** (its signing key leaked, or a build of
  it is vulnerable and must not start any more): the project publishes that
  component's *old* leaf certificate as a `.cer` with a release, issues a new
  leaf from the CA and signs the new build with it. On each computer:

  ```sh
  sudo mokutil --mokx --import beast-boot-wimboot-revoked.cer   # choose a one-time password
  sudo reboot                                                   # MokManager: Enroll MOKX, confirm
  ```

  From then on that computer refuses every wimboot (in this example) signed
  with the old leaf, whatever drive it is on, and starts GRUB, the helper and
  any wimboot signed with the new leaf. Nothing new is enrolled in MokList.
  `mokutil --mokx --list-enrolled` shows the entry. You can also take the
  certificate from a file you no longer trust yourself: `sbverify --list
  FILE` names its signer, and `make vulns` prints each signed file's leaf
  with its SHA-256.
- **You must run `mokutil` yourself.** BeastBoot does not distribute MokListX
  entries: the menu's "Trust Ubuntu's Secure Boot key" tool only knows
  Ubuntu's published revocations, and any MOK change needs someone at the
  computer to confirm it in MokManager. A release that revokes a leaf says so
  in its notes and attaches the `.cer`.
- **One bad file, without waiting for a release:** import its Authenticode
  SHA-256 as a blocked hash, `mokutil --mokx --import-hash <authenticode
  sha256>` (`make vulns` prints the hash of each signed file).
- **The CA key is compromised or lost:** a new CA and a new enrolment on every
  computer ([RELEASING.md](RELEASING.md#replace-the-ca-the-ca-key-leaked-or-is-lost));
  remove the old CA certificate (section 4), and add it to MokListX if its
  key leaked.
- **SBAT:** wimboot carries `wimboot,1` (upstream's name) and
  `wimboot.beastboot,1` (ours), GRUB `grub.beastbooter,2`. A higher generation
  in a later build lets a shim that has that generation in its SbatLevel
  refuse the older builds, but SbatLevel comes only from shim's built-in
  policy: with Debian's shim we cannot add our own level.
- **Rollback:** a drive you can write to lets anyone put back an older signed
  wimboot or GRUB. Revocation (above) is what stops that, not the drive. In
  particular a computer that still has the pre-0.5.0 certificate enrolled
  starts every 0.4.x and older build: remove that certificate (section 4).
- **The prepared copy is not a security boundary.** The copy of an ISO that
  BeastBoot prepares on the data partition can be changed by anyone who can
  write to it. A tampered `boot.wim`, like a tampered ISO, can run anything in
  Windows PE. Secure Boot protects the boot chain (shim, GRUB, wimboot), not
  the contents of the ISO.

### Known compatibility limits of 0.1.1 and older (found by `make vulns`, 2026-10-23)

With Secure Boot **on**, BeastBoot 0.4.x and older will not start on a PC that
has applied shim's revocation level `2026092500` or newer (it requires
`grub,7`; those releases carry `grub,6` or lower). **Fixed in 0.5.0**, which
carries `grub,7`: update the drive's boot files. Our own shim does not apply
that level by itself; a newer shim of another system on the same PC, or an
OS or firmware update, can.

BeastBoot 0.1.1 and older also will not start in either of these two
situations. Booting with Secure Boot off is unaffected. Both
are fixed in 0.1.2.

1. **The PC has applied the November 2025 SBAT revocation** (`SbatLevel`
   `2025112400`, which requires `grub,6`). BeastBoot 0.1.1 and older use
   Ubuntu's prebuilt 2.14 GRUB and truthfully carry `grub,5`, so shim refuses
   them. **Fixed** by the GRUB source build above, which proves the fixes and
   carries `grub,6`.
2. **The PC's firmware trusts only Microsoft's 2023 UEFI CA.** The shim of
   0.1.1 and older (Ubuntu's) is signed only by the Microsoft UEFI CA 2011
   (certificate expired 2026-06-27). Most PCs still trust the 2011 CA, but new
   ones may ship without it. **Fixed** by Debian's shim 16.1, which is signed
   through both CAs ([section 1](#why-debians-shim)); the e2e tests boot it
   with a `db` that holds only the 2023 CA.

`make vulns` reports them as boot-chain findings (`BB-SBAT-REVOKED-grub-7`,
`BB-SHIM-UEFI-CA-2011-ONLY`) while they apply. The SBAT finding's name ends in
the generation the level requires, and a triage (VEX) entry cannot close it:
it stays open until the shipped GRUB carries that generation.

The shim's own revocation levels (`.sbatlevel`) are `sbat,1,2025021800 shim,4
grub,5` ("previous", which shim applies by default) and `sbat,1,2025051000
shim,4 grub,5 grub.proxmox,2` ("latest", recorded in the manifest as
`shim_sbat_level_latest`). Neither revokes our GRUB or current Ubuntu or
Debian GRUBs.

## 8. What BeastBoot never does

- Never disables, patches, hooks or works around signature verification —
  not in firmware, not in shim, not in GRUB. Our GRUB is built without
  `--disable-shim-lock`, and our GRUB patches only add fixes (a security fix
  and two shim 16 compatibility fixes from upstream and Debian).
- Never ships a modified shim or MokManager: they are byte-for-byte Debian's,
  checked against the package at build time and listed with SHA-256. The
  helper kernel's code is Ubuntu's, unchanged; only its signature is replaced
  with one made under the BeastBoot CA.
- Never ships binaries it knows to be vulnerable or revoked, and never
  inflates SBAT generations.
- Never enrolls a key for you, and never touches the firmware's own key
  databases (PK, KEK, db, dbx). Trust comes only from the firmware, from the
  key built into the shim (Debian's), or from a key **you** confirmed in
  MokManager. "Trust Ubuntu's Secure Boot key" only *requests* the
  enrollment; nothing changes until you confirm it there.
- Never adds boot entries to your computer: there is deliberately no
  `fbx64.efi` on the drive.
- Never boots a kernel that failed verification; it explains and stops.
- On UEFI, never runs a menu script, hook, theme or font from the drive: they
  are inside the signed `grubx64.efi` (0.5.0).
- Never needs network access to install, and puts nothing on the drive that is
  not listed in `manifest.json`.
