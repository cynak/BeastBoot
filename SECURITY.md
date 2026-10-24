# Security policy

beast-booter sits in the boot chain, so its security rules are part of the design.

## What beast-booter promises

1. It never disables, patches, hooks or overrides firmware or shim signature
   verification. Everything loaded after shim is verified by shim.
2. It never ships known-vulnerable or revoked signed binaries.
3. The SBAT metadata embedded in its GRUB truthfully describes the GRUB code it
   ships, so that existing revocations apply to it. It adds its own
   `grub.beastbooter` entry so beast-booter-specific issues can be revoked too.
4. Machines only trust beast-booter after the owner enrolls its key in
   MokManager, which requires physical presence.
5. Every file placed on a drive is listed in `dist/manifest.json` with its
   origin and SHA-256. `build/verify-dist.sh` re-checks a build.

A change that breaks any of these is a security bug, even if it makes more ISOs boot.

## Signing keys

Release builds are signed with the project release key. It is generated once on
an offline machine and stored only as encrypted GitHub Actions secrets that the
release workflow uses; it is never committed. Local builds are signed with a key
you generate yourself (`make keys`), which is never committed either. You can always build and sign with your own key and enroll that key
instead of the project's.

How release builds are made, signed and published:
[docs/RELEASING.md](docs/RELEASING.md).

## Verifying a release

Every release publishes `SHA256SUMS`, GitHub build-provenance attestations
for its files, and the Secure Boot certificate with its fingerprints
(`beast-booter-<v>-ENROLL_THIS_KEY_IN_MOKMANAGER.cer`,
`beast-booter-<v>-CERTIFICATE.txt`). Check all three before you run or
enroll anything.

1. **Hashes.** Download `SHA256SUMS` from the same release page, next to the
   files, and run:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS                       # Linux
   grep -F macos-arm64.zip SHA256SUMS | shasum -a 256 -c -         # macOS, one file
   ```

   On Windows, compare `Get-FileHash <file> -Algorithm SHA256` with the line
   in `SHA256SUMS`.
2. **Provenance.** With the GitHub CLI, check that a file was built by this
   project's release workflow from the tagged source (use the repository the
   release page belongs to):

   ```sh
   gh attestation verify beast-booter-<v>-linux-x86_64.tar.gz --repo cynak/BeastBoot
   ```
3. **Certificate.** `CERTIFICATE.txt` gives the subject, validity and the
   SHA-1 and SHA-256 fingerprints of the signing certificate. They must
   match the `.cer` file of the release, the `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`
   on the drive's `BEAST-EFI` partition, and what MokManager shows under
   **View key** (SHA-1) before you enroll it:

   ```sh
   openssl x509 -inform DER -in beast-booter-<v>-ENROLL_THIS_KEY_IN_MOKMANAGER.cer \
     -noout -subject -enddate -fingerprint -sha1 -fingerprint -sha256
   ```

   In a checkout, `build/verify-dist.sh DIST --cert FILE` checks a whole set
   of boot files (hashes, signatures, SBAT) and that it is signed with that
   certificate. The portable packages can also be checked file by file
   against their `PACKAGE-MANIFEST.json`
   ([docs/PORTABLE.md](docs/PORTABLE.md#check-the-download-first)).

## Reporting a vulnerability

Please report security issues privately, with GitHub's private vulnerability
reporting (https://github.com/cynak/BeastBoot/security/advisories/new), instead of opening a
public issue. Include the beast-booter version (`bb_version` in
`grub/beast/version.cfg` on the drive), firmware/machine details, and steps to
reproduce.
