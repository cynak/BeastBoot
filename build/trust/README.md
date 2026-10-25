# Optional trust: Ubuntu's Secure Boot key

Since 0.1.2 the drive boots through **Debian's shim 16.1**. It is signed through both
Microsoft UEFI CA 2011 and Microsoft UEFI CA 2023, so it boots on old and new PCs.
That shim has Debian's key built in, not Canonical's. So, with Secure Boot on:

- our GRUB (signed with the BeastBoot MOK key) boots as before, and so does the
  beast-net helper kernel: `build.sh` removes Canonical's signature and signs it
  with the same MOK key;
- kernels signed by Debian now boot, as a side effect;
- kernels signed by Canonical (Ubuntu ISOs, and the many ISOs that use Ubuntu's
  signed kernels) are refused, **until the user opts in** to "Trust Ubuntu's
  Secure Boot key".

This folder holds exactly what Ubuntu's own shim trusts and revokes. It was
extracted from Ubuntu's signed shim (shim-signed 1.59+15.8-0ubuntu2) with
`scripts/shim_trust.py extract`; check it with `scripts/shim_trust.py check build/trust/canonical`.

| File | What it is | Where it goes |
|---|---|---|
| `canonical/canonical-master-ca.der` | Ubuntu shim's vendor certificate: Canonical Ltd. Master Certificate Authority | MokList (as a MOK) |
| `canonical/revoked/*.der` | Ubuntu shim's vendor_dbx: 8 older Canonical signing certificates Ubuntu revoked | MokListX |
| `canonical/revoked-sha256.txt` | vendor_dbx SHA-256 entries (none today) | MokListX (as hashes) |
| `canonical/trust.json` | manifest: source file, SHA-256 of every file, subjects, validity | read by the helper and the tests |

## Interface between the parts

**On the drive.** The beast-net initramfs contains this folder at
`/usr/share/beastnet/trust/canonical/` (copied by `build/beastnet/mkinitrd.py`
from `build/trust/canonical/`). Nothing is copied to the ESP.

**Menu → helper.** The Tools menu has an entry **"Trust Ubuntu's Secure Boot key"**,
shown on UEFI when the helper is on the drive. It boots the helper the same way
"Download an ISO from a link" does, with `beastnet.action=trust-ubuntu` added to
the kernel command line. When GRUB refuses a kernel under Secure Boot, the error
text says that Ubuntu-signed kernels need this step (and that Secure Boot can be
turned off instead).

**Helper action `trust-ubuntu`.** It is reachable from the menu entry above and
from the helper's own menu. It works in two steps, so Canonical is never trusted
without Ubuntu's revocations:

1. If any certificate or hash from `revoked/` / `revoked-sha256.txt` is missing
   from MokListX (read `MokListXRT`), request them with `mokutil --mokx --import ...`.
   The user reboots, and MokManager asks them to confirm "Enroll MOKX".
2. Only when all revocations are in MokListX, and the Canonical CA is not yet in
   MokList (read `MokListRT`), request it with `mokutil --import`. The user
   reboots, and MokManager asks them to confirm "Enroll MOK".

Before each request the helper shows what will be enrolled: subject, SHA-256 and
SHA-1 fingerprints (MokManager shows SHA-1), and the source (`trust.json`). It
asks for a one-time password, which MokManager asks for again. The helper also
shows the current state (not trusted / revocations only / trusted) and offers
"Stop trusting Ubuntu's key" (`mokutil --delete` for the CA; the revocations stay).
It never touches the firmware db/dbx, never imports anything other than these
files, and verifies every file against `trust.json` before using it.

**Effect.** MokList and MokListX belong to the machine, not to the drive: every
shim on that machine (including an installed Ubuntu, Fedora, Debian ...) then
trusts Canonical-signed binaries and refuses the revoked ones. The docs say this.
