# Secure Boot and beast-booter

beast-booter boots with UEFI Secure Boot **on**. It does that the same way
Linux distributions do: with a Microsoft-signed *shim*, and without weakening
any check. The one thing you have to do yourself is enroll the beast-booter
key once per computer, in a blue screen called MokManager. This page explains
what is trusted and why, how to enroll (and later remove) the key, how to
check the key first, and which ISOs can boot with Secure Boot on.

Statements marked **(unverified)** are believed correct but have not been
tested by the project. Corrections are welcome.

## 1. Chain of trust

```
firmware (Secure Boot db: Microsoft UEFI CA)
  └─ EFI/BOOT/BOOTX64.EFI     shim, from Ubuntu's shim-signed, signed by Microsoft
       ├─ EFI/BOOT/mmx64.efi  MokManager, signed by Canonical (trusted via shim's built-in Canonical certificate)
       └─ EFI/BOOT/grubx64.efi  beast-booter GRUB, signed with the beast-booter key
            │                   (trusted only after YOU enrolled that key as a MOK)
            └─ kernel of the ISO you pick: GRUB hands it to shim, which checks it
               against the firmware db, your MOK list and Canonical's certificate
```

| File on the drive | Signed by | Trusted because |
|---|---|---|
| `EFI/BOOT/BOOTX64.EFI` (shim 15.8, Ubuntu) | Microsoft Corporation UEFI CA 2011 | that CA is in the firmware `db` of most PCs |
| `EFI/BOOT/mmx64.efi` (MokManager, Ubuntu) | Canonical Ltd. Secure Boot Signing (2022 v1) | shim has Canonical's CA built in |
| `EFI/BOOT/grubx64.efi` (beast-booter GRUB) | the beast-booter key | you enrolled `ENROLL_THIS_KEY_IN_MOKMANAGER.cer` in MokManager |
| kernels inside ISOs | their distribution | see [section 6](#6-which-isos-boot-with-secure-boot-on) |

Why beast-booter has its own GRUB: Ubuntu's signed GRUB cannot read exFAT or
NTFS, the filesystems your ISOs usually live on. beast-booter's GRUB is built
from **the same Ubuntu GRUB package** (unmodified modules from
`grub-efi-amd64-bin`, same version as Ubuntu's signed GRUB), with exFAT and
NTFS added, and is signed with the beast-booter key. Ventoy uses the same model.

With Secure Boot on, GRUB runs in *lockdown*: it refuses to load GRUB modules
from disk and asks shim to verify every kernel or EFI program before running
it. A kernel that does not verify is not started, and the menu tells you why.

Every file on the drive is listed in `dist/manifest.json` with its SHA-256 and
origin (`deb:<package>=<version>:<path>` for files copied unmodified from an
Ubuntu package). The build also checks each such file against the package's
own checksums.

## 2. First boot with Secure Boot on: enroll the key

You do this once per computer. It needs a keyboard at the computer; nothing
running in an operating system can do it for you (that is the point of MOK).
These screens were recorded with shim 15.8 in a virtual machine; real firmware
looks the same because shim draws them, but colours and fonts may differ.

1. Boot from the beast-booter drive. A blue screen says
   **ERROR — Verification failed: (0x1A) Security Violation** with an **OK** button.
   This is shim refusing beast-booter's GRUB because it does not know the key yet.
   Press **Enter**.
2. **Shim UEFI key management — Press any key to perform MOK management**, with
   a countdown (10 seconds). Press any key. (If the countdown runs out, the
   computer moves on to the next boot device; just boot the drive again.)
3. **Perform MOK management**: choose **Enroll key from disk**.
4. **Select Key**: a list of volumes. Choose **BEAST-EFI** (the drive's boot
   partition). Some firmware may show a device path instead of the name.
5. A list of files: choose **ENROLL_THIS_KEY_IN_MOKMANAGER.cer**.
6. **[Enroll MOK]**: choose **View key 0** and check it (see
   [section 3](#3-check-the-key-before-you-enroll-it)): *Subject* should be
   the beast-booter key, and *[Fingerprint]* must match the published SHA-1
   fingerprint. Press a key to go back, then choose **Continue**.
7. **Enroll the key(s)?** The cursor starts on **No**. Choose **Yes**.
8. **Perform MOK management**: choose **Reboot**.

From now on this computer boots the beast-booter menu directly.

Alternative, if the computer already runs Linux: `sudo mokutil --import
ENROLL_THIS_KEY_IN_MOKMANAGER.cer` asks you to choose a one-time password;
on the next reboot MokManager shows **Enroll MOK** and asks for that password.

## 3. Check the key before you enroll it

Enrolling a key means: *this computer will run any boot program signed with
it*. Only enroll a key whose fingerprint you got from a source you trust: the
release notes of the beast-booter build you use, or, if you built the drive
yourself, the output of `make keys` / `build/verify-dist.sh`.

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

## 4. Remove the key later

From Linux on that computer (any Secure Boot Ubuntu live USB works too):

```sh
sudo mokutil --delete ENROLL_THIS_KEY_IN_MOKMANAGER.cer   # choose a one-time password
sudo reboot
```

On reboot MokManager shows **Delete MOK**: view the key, confirm, enter the
password, reboot. `mokutil --list-delete` shows the pending request and
`mokutil --revoke-delete` cancels it. (`mokutil --reset` deletes *all* MOKs,
including keys used for DKMS drivers. Avoid it unless you know you want that.)

After removal, beast-booter's GRUB is refused again (you get the screen from
step 1). Nothing else on the computer changes.

## 5. Use your own key instead

If you would rather trust a key you made yourself:

```sh
make keys      # build/keygen.sh: RSA-2048, self-signed, codeSigning, ~10 years
make build     # signs dist/esp/EFI/BOOT/grubx64.efi with keys/beast-booter.key
beast-booter update --device /dev/sdX    # or install, see the README
```

- `make keys` writes `keys/beast-booter.key` (private, mode 0600, git-ignored),
  `keys/beast-booter.crt` (PEM) and `keys/beast-booter.cer` (DER, copied to the
  drive). It prints the fingerprints. It refuses to overwrite an existing key
  unless you run `build/keygen.sh --force`. `BB_KEY_CN` sets the certificate
  name, `BB_KEY_DIR` the directory (`make build` reads `BB_KEY_DIR` too).
- Computers must enroll *your* certificate (section 2). A computer that
  enrolled another beast-booter key will not trust your build, and the reverse.
- **Protect the private key.** Anyone who has it can make boot programs that
  every computer with your certificate enrolled will run. Keep it offline;
  if it leaks, remove the certificate from every computer (section 4) and
  make a new key.
- Rebuilding with the same key keeps the existing signature as long as the
  GRUB image did not change (`BB_RESIGN=1` forces a new signature). A new
  signature has a new signing time, so `grubx64.efi` gets a new SHA-256; the
  manifest's `grub_unsigned_sha256` (the image without its signature) stays
  the same and can be reproduced by anyone with `build/verify-dist.sh --rebuild`.

## 6. Which ISOs boot with Secure Boot on

GRUB asks shim to verify the ISO's kernel (or EFI program). shim accepts it if
it is signed by a key in the firmware `db`, by a key in your MOK list, or by
Canonical (Ubuntu's shim has Canonical's certificate built in), and it is not
revoked.

- **Ubuntu and its official flavours** (Kubuntu, Xubuntu, Ubuntu MATE, ...):
  kernels are signed by Canonical, so they boot. **Old releases may not**:
  current shim revokes older Canonical signing keys (the 2017–2021 keys listed
  in Ubuntu's `/usr/lib/shim/is-not-revoked`), so ISOs whose kernel was
  signed with them are refused — roughly anything released before mid-2022
  **(unverified cut-off)**. Check with `sbverify --list` on the ISO's kernel.
- **Distributions that ship Ubuntu's signed kernels** (for example Linux Mint,
  elementary OS, Zorin OS) should boot the same way **(unverified)**.
- **Other distributions** (Fedora, Debian, openSUSE, ...) sign their kernels
  with their own keys, which only *their* shim trusts. With beast-booter you
  can either enroll that distribution's Secure Boot certificate as a MOK
  (get it from the distribution, then `mokutil --import` it) **(unverified:
  works if the kernel signature chains to that certificate)**, or turn Secure
  Boot off in the firmware settings for that boot.
- **Unsigned kernels** (for example Arch Linux's official ISO, many rescue
  ISOs) do not boot with Secure Boot on. Turn Secure Boot off, or sign them
  yourself and enroll your key — your choice, not beast-booter's.
- **Windows installers** are not supported by beast-booter 0.1 (with or
  without Secure Boot).

beast-booter never works around a failed check. The menu explains what failed
and what you can do (enroll that distribution's key, or turn Secure Boot off).

## 7. SBAT and revocation, in plain words

Signatures prove *who* made a boot program, not that it is free of known
security holes. When a hole is found in, say, GRUB, the fixed version gets a
higher **generation number**, and computers are told "refuse GRUB below
generation N". That table of names and generations inside each program is
**SBAT** (Secure Boot Advanced Targeting). shim checks it on every boot.
Revoking by generation is much cheaper than adding every old file's hash to
the firmware's small revocation list (`dbx`).

beast-booter's GRUB carries these SBAT lines:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,5,Free Software Foundation,grub,2.14,https://www.gnu.org/software/grub/
grub.ubuntu,2,Ubuntu,grub2,2.14-2ubuntu1,https://www.ubuntu.com/
grub.ubuntu26,1,Ubuntu,grub2,2.14-2ubuntu1,https://www.ubuntu.com/
grub.peimage,2,Canonical,grub2,2.14-2ubuntu1,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
grub.beastbooter,1,beast-booter,grub2,2.14-2ubuntu1+bb0.1.0,<project URL>
```

- The first five lines are copied **verbatim** from Ubuntu's signed GRUB of
  the same version. Our GRUB contains exactly Ubuntu's GRUB code, so it must
  share Ubuntu's fate: if that GRUB is revoked, ours is revoked too, and you
  need a newer beast-booter build. We never claim a higher generation than the
  code deserves. The build refuses to run if the signed Ubuntu GRUB and the
  GRUB modules are different versions (a development override exists and is
  recorded in the manifest as `sbat_version_check`).
- The last line is beast-booter's own. If a problem is specific to
  beast-booter (for example a bad module choice), that generation is raised
  and older beast-booter builds can be revoked without touching Ubuntu's.
- The build also refuses if any of our generations is below the revocation
  level built into the shim it ships.

If a future revocation hits the GRUB on your drive, shim refuses it like an
unknown key (the screen from step 1) **(unverified: exact message)**. Update
the drive with a newer beast-booter release; your ISOs on partition 1 are not
touched.

### Known compatibility limits in 0.1 (found by `make vulns`, 2026-10-23)

With Secure Boot **on**, beast-booter 0.1 will not start on a PC in either of
these situations. Booting with Secure Boot off is unaffected.

1. **The PC has applied the November 2025 SBAT revocation** (`SbatLevel`
   `2025112400`, which requires `grub,6`). Our GRUB is Ubuntu's 2.14 build and
   truthfully carries `grub,5`, so shim refuses it. A newer shim from any
   distribution, or a firmware/OS update, can apply this level. The fix is to
   rebuild from a GRUB that carries `grub,6`; we will not raise the number by
   hand, because that would hide the revocation instead of fixing it.
2. **The PC's firmware trusts only Microsoft's 2023 UEFI CA.** The shipped shim
   is signed only by the Microsoft UEFI CA 2011 (certificate expired
   2026-06-27). Most PCs still trust the 2011 CA, but new ones may ship
   without it. The fix is to ship a shim signed by the 2023 CA.

`make vulns` reports both as boot-chain findings (`BB-SBAT-REVOKED-grub`,
`BB-SHIM-UEFI-CA-2011-ONLY`) until they are fixed.

## 8. What beast-booter never does

- Never disables, patches, hooks or works around signature verification —
  not in firmware, not in shim, not in GRUB. Our GRUB is built without
  `--disable-shim-lock`.
- Never ships a modified shim or MokManager: they are byte-for-byte Ubuntu's,
  checked against the package at build time and listed with SHA-256.
- Never ships binaries it knows to be vulnerable or revoked, and never
  inflates SBAT generations.
- Never enrolls a key for you, and never touches the firmware's own key
  databases (PK, KEK, db, dbx). Trust comes only from the firmware or from
  a key **you** enrolled in MokManager.
- Never adds boot entries to your computer: there is deliberately no
  `fbx64.efi` on the drive.
- Never boots a kernel that failed verification; it explains and stops.
- Never needs network access to install, and puts nothing on the drive that is
  not listed in `manifest.json`.
