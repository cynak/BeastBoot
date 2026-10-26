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
       └─ EFI/BOOT/grubx64.efi  BeastBoot GRUB, signed with the BeastBoot key
            │                   (trusted only after YOU enrolled that key as a MOK)
            ├─ beast-net/vmlinuz  the network helper: Ubuntu's kernel, re-signed with the BeastBoot key
            └─ kernel of the ISO you pick: GRUB hands it to shim, which checks it
               against the firmware db, your MOK list and Debian's certificate
               (and refuses anything in dbx, your MokListX or shim's own revocation lists)
```

| File on the drive | Signed by | Trusted because |
|---|---|---|
| `EFI/BOOT/BOOTX64.EFI` (shim 16.1, Debian `shim-signed 1.51+16.1-2`, unmodified) | Microsoft, twice over the same Authenticode digest: one signature chains to Microsoft Corporation UEFI CA 2011, the other to Microsoft UEFI CA 2023 | one of those CAs is in the firmware `db`: old PCs have the 2011 CA, new ones may have only the 2023 CA |
| `EFI/BOOT/mmx64.efi` (MokManager, Debian `shim-helpers-amd64-signed 1+16.1+2`, unmodified) | Debian Secure Boot Signer 2022 - shim | shim has Debian's CA built in |
| `EFI/BOOT/grubx64.efi` (BeastBoot GRUB) | the BeastBoot key | you enrolled `ENROLL_THIS_KEY_IN_MOKMANAGER.cer` in MokManager |
| `beast-net/vmlinuz` (Ubuntu's kernel, code unchanged) | the BeastBoot key (the build removes Canonical's signature and signs it again) | the same enrolled BeastBoot key |
| kernels inside ISOs | their distribution | see [section 6](#6-which-isos-boot-with-secure-boot-on) |

Why BeastBoot has its own GRUB: Ubuntu's signed GRUB cannot read exFAT or
NTFS, the filesystems your ISOs usually live on. BeastBoot's GRUB has exFAT
and NTFS built in and is signed with the BeastBoot key. Ventoy uses the same
model.

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
  BeastBoot key. The code is unchanged: its Authenticode digest is the same
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
  of upstream commit `26beaa3b`, which is in GRUB 2.16), and upstream commit
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
   This is shim refusing BeastBoot's GRUB because it does not know the key yet.
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
   the BeastBoot key, and *[Fingerprint]* must match the published SHA-1
   fingerprint. Press a key to go back, then choose **Continue**.
7. **Enroll the key(s)?** The cursor starts on **No**. Choose **Yes**.
8. **Perform MOK management**: choose **Reboot**.

From now on this computer boots the BeastBoot menu directly.

Alternative, if the computer already runs Linux: `sudo mokutil --import
ENROLL_THIS_KEY_IN_MOKMANAGER.cer` asks you to choose a one-time password;
on the next reboot MokManager shows **Enroll MOK** and asks for that password.

## 3. Check the key before you enroll it

Enrolling a key means: *this computer will run any boot program signed with
it*. Only enroll a key whose fingerprint you got from a source you trust: the
release notes of the BeastBoot build you use, or, if you built the drive
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

After removal, BeastBoot's GRUB is refused again (you get the screen from
step 1). Nothing else on the computer changes.

## 5. Use your own key instead

If you would rather trust a key you made yourself:

```sh
make keys      # build/keygen.sh: RSA-2048, self-signed, codeSigning, ~10 years
make build     # signs dist/esp/EFI/BOOT/grubx64.efi and dist/esp/beast-net/vmlinuz with keys/beast-booter.key
beast-booter update --device /dev/sdX    # or install, see the README
```

- `make keys` writes `keys/beast-booter.key` (private, mode 0600, git-ignored),
  `keys/beast-booter.crt` (PEM) and `keys/beast-booter.cer` (DER, copied to the
  drive). It prints the fingerprints. It refuses to overwrite an existing key
  unless you run `build/keygen.sh --force`. `BB_KEY_CN` sets the certificate
  name, `BB_KEY_DIR` the directory (`make build` reads `BB_KEY_DIR` too).
- Computers must enroll *your* certificate (section 2). A computer that
  enrolled another BeastBoot key will not trust your build, and the reverse.
- **Protect the private key.** Anyone who has it can make boot programs that
  every computer with your certificate enrolled will run. Keep it offline;
  if it leaks, remove the certificate from every computer (section 4) and
  make a new key.
- Rebuilding with the same key keeps the existing signature as long as the
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
  is not signed, so only with Secure Boot **off**. With Secure Boot on, the
  menu stops with `windows-sb` and says to turn it off for that boot
  ([ISO_SUPPORT.md](ISO_SUPPORT.md#windows)).

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
the leaf is in MokListX). `tests/e2e/test_e2e_trust_ubuntu.py` runs the helper's
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
includes the BeastBoot key you enrolled. This is how DKMS modules work
under Secure Boot, and it is one more reason to check the key before you
enroll it (§3) and to remove it when you no longer need it (§4).

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
grub,6,Free Software Foundation,grub,2.14,https://www.gnu.org/software/grub/
grub.ubuntu,2,Ubuntu,grub2,2.14-2ubuntu3,https://www.ubuntu.com/
grub.ubuntu26,1,Ubuntu,grub2,2.14-2ubuntu3,https://www.ubuntu.com/
grub.peimage,2,Canonical,grub2,2.14-2ubuntu3,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
grub.beastbooter,1,beast-booter,grub2,2.14-2ubuntu3+bb1,https://github.com/cynak/BeastBoot
```

- **`grub,6`** is the generation that shim's revocation level `2025112400`
  requires (the November 2025 GRUB CVEs: CVE-2025-54770, -54771, -61661,
  -61662, -61663, -61664). We claim it only because the build *proves* every
  fix of that push is in our source: `build/grub/security-fixes.json` names
  the upstream commit of each fix, and the GRUB build applies each commit **in
  reverse** (dry run, no fuzz) to the fully patched source, which only works
  when the fixed code is there. A missing fix stops the build; the result is
  recorded in the GRUB build's `build-info.json`, the manifest and the SBOM.
  (Those fixes are already in upstream GRUB 2.14; Ubuntu's 2.14 packages just
  still say `grub,5`. Upstream GRUB 2.16 says `grub,6` for the same push.)
- **`grub.ubuntu`, `grub.ubuntu26`, `grub.peimage`** are Ubuntu's own lines
  from the source package (`debian/sbat.ubuntu.csv.in`), filled in as Ubuntu's
  build does. They describe Ubuntu's patches, which we include unchanged, so
  if Ubuntu's GRUB is revoked through them, ours is revoked too.
- **`grub.beastbooter`** is BeastBoot's own line: it is raised when a problem
  is specific to BeastBoot (our patches, the module choice, a bad signing), so
  older BeastBoot builds can be revoked without touching anyone else's.
- The build also refuses if any of our generations is below the revocation
  level built into the shim it ships.
- **Not claimed: `grub,7`.** shim has a proposal (not merged) to require
  `grub,7` for CVE-2026-97876. Our GRUB already contains that fix, but we keep
  `grub,6` until shim publishes the level; then the claim is raised in
  `build/grub/security-fixes.json` (the build checks the fix is there).

If a future revocation hits the GRUB on your drive, shim refuses it like an
unknown key (the screen from step 1) **(unverified: exact message)**. Update
the drive with a newer BeastBoot release; your ISOs on partition 1 are not
touched.

### Known compatibility limits of 0.1.1 and older (found by `make vulns`, 2026-10-23)

With Secure Boot **on**, BeastBoot 0.1.1 and older will not start on a PC in
either of these situations. Booting with Secure Boot off is unaffected. Both
are fixed in 0.1.2: update the drive's boot files.

1. **The PC has applied the November 2025 SBAT revocation** (`SbatLevel`
   `2025112400`, which requires `grub,6`). BeastBoot 0.1.1 and older use
   Ubuntu's prebuilt 2.14 GRUB and truthfully carry `grub,5`, so shim refuses
   them. **Fixed** by the GRUB source build above, which proves the fixes and
   carries `grub,6`. A future level that requires `grub,7` will be refused
   until we raise the claim (see above).
2. **The PC's firmware trusts only Microsoft's 2023 UEFI CA.** The shim of
   0.1.1 and older (Ubuntu's) is signed only by the Microsoft UEFI CA 2011
   (certificate expired 2026-06-27). Most PCs still trust the 2011 CA, but new
   ones may ship without it. **Fixed** by Debian's shim 16.1, which is signed
   through both CAs ([section 1](#why-debians-shim)); the e2e tests boot it
   with a `db` that holds only the 2023 CA.

`make vulns` reports them as boot-chain findings (`BB-SBAT-REVOKED-grub`,
`BB-SHIM-UEFI-CA-2011-ONLY`) while they apply.

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
  with the BeastBoot key's.
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
- Never needs network access to install, and puts nothing on the drive that is
  not listed in `manifest.json`.
