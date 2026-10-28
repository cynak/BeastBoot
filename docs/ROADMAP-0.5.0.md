# 0.5.0 roadmap: a wider signed chain

Both items came out of the 0.4.0 security review
([SECURITY_REVIEW-0.4.0.md](SECURITY_REVIEW-0.4.0.md)) and were moved here by the
maintainer. Both change behaviour for people who customise their drives, so
they ship together.

## 1. Menu scripts inside the signed GRUB image

Today `grub.cfg`, `grub/beast/*.cfg`, `hooks/*.sh` and the theme files are read
from the ESP, unsigned. With Secure Boot on, someone who can write the ESP can
change what the menu does: skip its checks, show fake screens, boot another ISO
than the one chosen, pass any arguments and inputs to signed kernels, wimboot and
the helper, and change the hooks that run as root in a booted Linux. Lockdown
still allows only signed code; this is about the menu's integrity.

- Embed `grub.cfg`, `grub/beast/*.cfg`, `hooks/*.sh`, `version.cfg` and the
  themes in the memdisk of `grubx64.efi` (as the fonts already are); one UEFI code
  path. BIOS keeps reading them from disk.
- Data written per drive or at run time is read as data with allow-lists:
  `device.cfg` (as an environment block), `grubenv`, `config.env` (done in 0.4.0).
- `bb-dev menu-sync` no longer affects Secure Boot VMs: document the dev loop
  (rebuild, or Secure Boot off).
- e2e tests that change menu files on the ESP move to build-time fixtures.
- Size: `grubx64.efi` about 1.7 MB (2.3 MB with themes).

## 2. BeastBoot CA with per-component certificates

0.4.0 signs GRUB, the helper kernel and wimboot with one key, so a bad wimboot can
only be revoked by its hash (`mokutil --mokx --import-hash`), one build at a time.

- Users enroll a BeastBoot CA once; GRUB, the helper kernel and wimboot get their
  own leaf certificates. One MokListX entry then revokes every build of one
  component without touching the others.
- Existing users re-enroll once (MokManager); the menu and docs explain it.
- Key rotation procedure documented with it.
