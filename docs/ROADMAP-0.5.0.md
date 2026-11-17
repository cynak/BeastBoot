# 0.5.0 roadmap: a wider signed chain

Both items came out of the 0.4.0 security review
([SECURITY_REVIEW-0.4.0.md](SECURITY_REVIEW-0.4.0.md)) and were moved here by the
maintainer. Both change behaviour for people who customise their drives, so
they ship together.

## 1. Menu scripts inside the signed GRUB image

Up to 0.4.x `grub.cfg`, `grub/beast/*.cfg`, `hooks/*.sh` and the theme files were
read from the ESP, unsigned. With Secure Boot on, someone who could write the ESP could
change what the menu does: skip its checks, show fake screens, boot another ISO
than the one chosen, pass any arguments and inputs to signed kernels, wimboot and
the helper, and change the hooks that run as root in a booted Linux. Lockdown
still allowed only signed code; this is about the menu's integrity.

Done (design and what is checked: [ARCHITECTURE.md §5](ARCHITECTURE.md#5-grub-runtime-contract),
[SECURE_BOOT.md](SECURE_BOOT.md#the-menu-is-inside-the-signed-image-050)):

- `grub.cfg`, `grub/beast/*.cfg`, `hooks/*.sh`, `version.cfg`, the theme and
  the fonts (GNU Unifont too) are in the memdisk of `grubx64.efi`; one UEFI
  code path, Secure Boot on or off. BIOS keeps reading them from disk.
- The first config: the image carries `build/early-efi.cfg`, which points the
  prefix at the memdisk and unsets `fw_path`. Ubuntu's GRUB starts
  `$fw_path/grub.cfg` (a `grub.cfg` next to `grubx64.efi` on the ESP) before
  `$prefix/grub.cfg`, so the prefix alone would not have been enough.
- Data written per drive or at run time is read as data with allow-lists:
  `device.env` (a GRUB environment block; replaces `device.cfg`, which
  `update` migrates), `grubenv`, `config.env` (done in 0.4.0). On UEFI
  `config.cfg` and `bb_theme` are no longer used, with Secure Boot off too.
- The two Windows PE start-up scripts (`winpeshl.ini`, `beastboot.cmd`) are
  in the memdisk too; UEFI injects those copies.
- `debug` and `pager` are on the `config.env` list, so GRUB's debug output
  can still be switched on from the drive on UEFI.
- The build id is in the image (its `version.cfg`): the image is built twice,
  the id covers the first (empty id), and the certificate is no longer part
  of the id, so the unsigned job and the signing job build the same image.
- `bb-dev menu-sync` only affects legacy BIOS boots and says so; the UEFI dev
  loop is `make build` + `bb-dev vm` ([DEVELOPMENT.md 4.2](DEVELOPMENT.md#42-the-menu-edit-loop)).
  `bb-dev debug-config` and `bb-dev image` write `config.env` too.
- No e2e test steered the menu through files on the ESP; the ones that used
  `config.cfg` for it have `config.env` next to it. `tests/e2e/test_e2e_signed_menu.py`
  proves that changed menu files and hostile data files have no effect under
  UEFI, and that legacy BIOS still runs the files on the ESP.
- Size: `grubx64.efi` is 4.4 MB signed (memdisk 3.0 MB, of which GNU Unifont
  2.4 MB; it would be 2.0 MB without Unifont). The ESP is 512 MiB.

Left open, for a decision:

- An ISO's own `boot/grub/loopback.cfg` is still run by our GRUB when that
  ISO is started (recipe 1): script from the data partition, in lockdown.
- `beastmount.exe`, the helper's `initrd.img` and firmware packs are loaded
  from the ESP unsigned (hashes in the manifest, checked at install time
  only). Decided: left as they are for 0.5.0.
- Rollback to a pre-0.5.0 signed `grubx64.efi` (same key): 0.5.0 carries
  `grub.beastbooter,2` (older images are 1), so they can be revoked as a
  class; nothing revokes them yet. Closed by key or certificate rotation,
  see item 2.

## 2. BeastBoot CA with per-component certificates

0.4.0 signs GRUB, the helper kernel and wimboot with one key, so a bad wimboot can
only be revoked by its hash (`mokutil --mokx --import-hash`), one build at a time.

Done (design and what was tested: [SECURE_BOOT.md](SECURE_BOOT.md#one-ca-three-signing-certificates-050);
the keys and the offline procedure: [RELEASING.md section 3](RELEASING.md#3-the-release-signing-keys)):

- Users enroll the BeastBoot CA certificate once; GRUB, the helper kernel and
  wimboot each have their own leaf certificate from it (`build/keygen.sh`,
  `build/sbkeys.sh`). One MokListX entry, a leaf, revokes every build of one
  component without touching the others; a new leaf from the CA works with
  nothing new enrolled. Tested under OVMF with Debian's shim 16.1
  (`tests/e2e/test_e2e_ca_chain.py`).
- The CA key is offline and never in GitHub or CI; the release environment
  holds the three leaf keys. `build/sign.sh` signs each file with its own
  leaf; the key-less build refuses a file that is not signed exactly once
  with its own component's leaf from the pinned CA.
- Existing users enroll once more after updating a drive: the installer says
  so before it writes, and the user guide, the menu's Secure Boot help and
  the release notes say how, and how to remove the old certificate.
- Key rotation and revocation: replace one leaf, replace the CA
  ([RELEASING.md](RELEASING.md#replace-one-leaf-a-components-key-leaked-was-misused-or-expires),
  [SECURE_BOOT.md section 7](SECURE_BOOT.md#revoking-one-component-and-replacing-its-certificate-050)).

Not done, by decision or by nature:

- MokListX entries are not distributed by BeastBoot: users run `mokutil`.
- A computer keeps starting 0.4.x and older builds until its user removes the
  old certificate.

## Sign in a separate release job

Done (not yet run on GitHub: the first dry run of the release workflow is its test):
`build/sign.sh`, `BB_UNSIGNED_OUT` and `BB_PRESIGNED_DIR` in `build/build.sh`, and the
jobs `unsigned`, `sign` and `build` in the release workflow
([RELEASING.md](RELEASING.md), "Signing in its own job").

Today the release key is on the runner's disk for the whole release job: the
GRUB build, the test suite, the QEMU e2e tests and the third-party scanners run
next to it (security review 2026-10-28, CI-1). Split the job: build and test
unsigned in the existing job, then sign in a small job that downloads the
unsigned files, runs only `sbsign`/`sbverify` (and the signature-reuse check)
inside the protected `release` environment, and uploads the signed files.
`build/build.sh` needs a "sign only" entry point for that.

## Scope (decided 2026-11-13)

0.5.0 stays the signed-chain release: the three items above and nothing else
define it. The Disk tools work done after 0.4.1 (stop and
resume after a power cut, the coverage tests; see
[DISK_TOOLS_MATRIX.md](DISK_TOOLS_MATRIX.md)) is not part of that definition,
but it is held and ships with 0.5.0 (no 0.4.2). Before it ships it needs the
shared-serial fix (done; two left-over gaps are in [ROADMAP-0.5.1.md](ROADMAP-0.5.1.md))
and Disk tools runs under BIOS and Secure Boot.

## Decisions on the CA (maintainer, 2026-11-15)

- Revocation and removing the 0.4.x certificate are manual (`mokutil`) in
  0.5.0; a helper entry for them is in [ROADMAP-0.5.1.md](ROADMAP-0.5.1.md).
- The 0.4.x certificate stays enrolled until a user removes it: documented,
  not enforced.
- The app's update dialog shows the certificate notice by version (older than
  0.5.0); the command line compares the certificates. Left as is.
- The CA private key stays offline on the maintainer's computer and is never
  given to GitHub or CI.
