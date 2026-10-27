# Releasing BeastBoot

A release is made by pushing a tag `vX.Y.Z`. GitHub Actions then builds every
release file, tests it, writes the SBOM and the vulnerability report, attests
build provenance and publishes the GitHub Release. All of the building and
checking is one script, `scripts/release/build_release.sh`, so the same thing
runs on your machine with `make release`.

## 1. What a release contains

`<v>` is the content of the `VERSION` file; the tag must be `v<v>`.

| File | What it is |
|---|---|
| `beast-boot-<v>-linux-x86_64.tar.gz` | portable package for Linux (docs/PORTABLE.md) |
| `beast-boot-<v>-windows-x86_64.zip` | portable package for Windows |
| `beast-boot-<v>-macos-x86_64.zip` | portable package for Intel Macs |
| `beast-boot-<v>-macos-arm64.zip` | portable package for Apple silicon Macs |
| `beast-boot-<v>-dist.zip` | the signed boot files (`dist/` with `manifest.json`); `beast-boot install --dist <zip>` |
| `beast-boot-<v>-sbom.cdx.json` | SBOM, CycloneDX 1.6: everything shipped (drive files, beast-net kernel and initrd packages, portable runtimes) |
| `beast-boot-<v>-sbom.spdx.json` | the same SBOM in SPDX 2.3 |
| `beast-boot-<v>-vulnerabilities.json` | vulnerability and boot-chain scan, OpenVEX applied |
| `beast-boot-<v>-VULNERABILITIES.md` | the same, for people |
| `beast-boot-<v>-ENROLL_THIS_KEY_IN_MOKMANAGER.cer` | the release Secure Boot certificate (DER) |
| `beast-boot-<v>-CERTIFICATE.txt` | its subject, validity and SHA-1 (as MokManager shows it) / SHA-256 fingerprints |
| `SHA256SUMS` | SHA-256 of every file above |

Every file also gets a GitHub build-provenance attestation. The release notes
come from `scripts/release/RELEASE_NOTES.md.in`: certificate fingerprints, the
vulnerability summary (counts, boot-chain findings with their VEX status, the
gate result) and how to verify the download.

## 2. What `build_release.sh` does

```
scripts/release/build_release.sh [--out DIR] [--official] [--skip-e2e] [--offline]
```

1. **Version**: `VERSION` must look like `X.Y.Z` or `X.Y.Z-suffix` and match the tag
   (`BB_RELEASE_TAG`, the CI's tag variable, or a `v*` tag on HEAD). `--official`
   requires the tag. A suffix (`-rc.1`) makes a pre-release.
2. **Signing key**: `BB_KEY_DIR` (default `keys/`). `--official` refuses the
   development key in `keys/`; `BB_RELEASE_CERT_SHA256` pins the expected certificate.
3. **`make build`**: boot files and beast-net into `dist/`, signed with that key.
4. **Tests**: installer, devtools and beast-net unit tests; the QEMU end-to-end
   tests unless `--skip-e2e` or there is no usable `/dev/kvm`.
5. **SBOM**: `scripts/sbom-vuln.sh tools`, `sbom` (generate + all validation
   checks must PASS), the SBOM tooling self-test, then `scan` (grype +
   osv-scanner + boot-chain checks, `sbom/vex.openvex.json` applied).
6. **Vulnerability gate** (section 6).
7. **Portable packages**: `scripts/build_portable.sh --all` (they include `sbom/`).
8. **Release files**: the names above, a deterministic `dist.zip` (one top folder,
   sorted entries, fixed times), the certificate files, `SHA256SUMS`, the notes.
9. **Self-verification**: every hash, the SBOM files against the validated
   `sbom/` and the JSON schemas, beast-net and runtime coverage in the SBOM,
   `dist.zip` against its manifest, the certificate against the one `dist/` was
   signed for, and every archive with `packaging/portable/build.py --verify`.

Output: `DIR` (default `out/release`) holds exactly the release files and
`SHA256SUMS`; `DIR/_release/` holds `RELEASE_NOTES.md`, `release.json`,
`gate.json`, `certificate.json` and a log per step.

Without `--official` everything is marked **unofficial local build**: the notes
start with a warning, `CERTIFICATE.txt` says not to enroll the key, the gate
only warns and `release.json` has `"official": false`.

Environment variables (all optional):

| Variable | Meaning |
|---|---|
| `BB_KEY_DIR` | directory with `beast-boot.key`, `.crt`, `.cer` |
| `BB_RELEASE_TAG` | the tag being released |
| `BB_RELEASE_CERT_SHA256` | refuse any certificate but this one |
| `BB_RELEASE_GATE` | `enforce`, `warn` or `off` (default: `enforce` with `--official`, else `warn`) |
| `BB_RELEASE_GATE_SEVERITY` | `critical` (default) or `high` |
| `BB_RELEASE_GATE_BASELINE` | the previous release's `vulnerabilities.json` |
| `BB_RELEASE_GATE_IGNORE_UNFIXED` | `1` (default): findings without a published fix never block (they are still listed in the report and the release notes); `0`: they block too |
| `BB_RELEASE_REPO`, `BB_RELEASE_ATTESTATIONS=1` | `owner/repo` for the `gh attestation verify` line in the notes |
| `BB_PROJECT_URL` | project URL in grubx64.efi's SBAT entry (CI: the repository URL) |
| `BB_RELEASE_SKIP_TESTS=1` | troubleshooting only: skip the unit tests; refused with `--official` |

### Locally

```sh
make release                                   # out/release, unofficial, signed with keys/
make release ARGS="--out out/rc --skip-e2e"    # without the QEMU tests
make release ARGS="--offline"                  # only cached downloads and vulnerability data
```

It needs the build host of docs/DEVELOPMENT.md (Ubuntu 26.04, GRUB 2.14,
shim-signed, the beast-net packages pinned in `build/beastnet/packages.lock`)
and network for the runtimes, beast-net packages, linux-firmware catalog and
vulnerability data, unless the caches are warm and you pass `--offline`. A full
run takes roughly 15-30 minutes, most of it the scan and the tests.

## 3. The release signing key (once)

Every BeastBoot user enrolls the release certificate in MokManager once.
Changing the key forces everyone to enroll again, so create it once, carefully:

1. On an offline machine with a checkout of this repository:

   ```sh
   BB_KEY_DIR=/media/usb/bb-release-key \
   BB_KEY_CN="beast-boot Secure Boot release key" \
   build/keygen.sh
   ```

   (RSA-2048, `extendedKeyUsage=codeSigning`, 10 years; firmware and shim do not
   check the dates.)
2. Keep `beast-boot.key` offline and backed up (for example two encrypted USB
   sticks in different places). **Never commit it** and never put it anywhere
   but the two places below.
3. In GitHub: *Settings → Secrets and variables → Actions → New repository secret*:
   - `BB_SB_KEY_PEM` = the contents of `beast-boot.key`
   - `BB_SB_CERT_PEM` = the contents of `beast-boot.crt`

   or with the GitHub CLI: `gh secret set BB_SB_KEY_PEM < beast-boot.key` and
   `gh secret set BB_SB_CERT_PEM < beast-boot.crt`.
4. Recommended: pin the certificate. Set the repository *variable*
   `BB_RELEASE_CERT_SHA256` to `sha256sum beast-boot.cer` (the DER file), so a
   wrong or swapped secret fails the build instead of shipping a new key.
5. Publish the SHA-1 and SHA-256 fingerprints (`openssl x509 -in beast-boot.crt
   -noout -fingerprint -sha1 -fingerprint -sha256`) in docs/SECURE_BOOT.md.

The workflow writes the key to a fresh 0700 directory (umask 077), derives the
`.cer` with openssl, never prints it, and shreds it at the end of the job. A tag
build without the two secrets fails. If the key leaks: see SECURITY.md; the
certificate must be replaced and users told to delete the old MOK
(docs/SECURE_BOOT.md section 4).

## 4. Cutting a release

1. Make sure `main` is green (ci.yml) and `make vulns` looks as expected.
2. Bump `VERSION` (for example `0.2.0`, or `0.2.0-rc.1` for a pre-release) and commit.
3. Tag and push:

   ```sh
   git tag -a v0.2.0 -m "beast-boot 0.2.0"
   git push origin v0.2.0
   ```

4. Watch *Actions → release*. When it is green, the release is published with
   all files, notes and attestations.

## 5. Dry runs

*Actions → release → Run workflow* with **dry_run** ticked (the default), or
`gh workflow run release.yml -f dry_run=true --ref main`. It runs the whole
pipeline with a throwaway signing key, marks everything unofficial, never
touches the release secrets and only uploads workflow artifacts
(`release-files`, `release-logs` on failure): no release, no attestations.

`dry_run` unticked on a tag (`--ref v0.2.0`) re-runs that tag's real release,
for example after a runner failure. On a branch it fails (no tag).

## 6. When the scan blocks

The scan never blocks a release because findings exist: known findings are
recorded in `sbom/vex.openvex.json` (for example the boot-chain findings as
`affected` with an action plan). The gate (`release_tool.py gate`) blocks only
on a finding that is

- in shipped software (drive, beast-net, portable runtimes) or the boot chain,
- at or above `BB_RELEASE_GATE_SEVERITY` (default `critical`),
- without any VEX statement (status `open`), and
- **new**: not in the previous release's `vulnerabilities.json` (the workflow
  downloads it as the baseline; for the first release every finding is new).

The log names each blocking finding; `_release/gate.json` has the list and the
remediation key (the catalogue is in `VULNERABILITIES.md`). Then:

1. **Fix it** when a fixed package exists: `R-UPDATE` (host packages, `make
   tools`), `R-BEASTNET-UPDATE` (regenerate `build/beastnet/packages.lock` with
   `python3 -I build/beastnet/lock.py`), `R-RUNTIME-UPDATE` (move
   `packaging/portable/runtimes.lock` to a newer python-build-standalone).
2. **Or triage it**: copy the matching proposal from
   `sbom/vex.proposed.openvex.json` (or write one) into `sbom/vex.openvex.json`:
   `not_affected` with a justification, or `affected` with an
   `action_statement`. Review it like code.
3. Commit, then release again. A tag names a commit, so the fix needs a new
   tag: if nothing was published yet, move it (`git tag -d v0.2.0; git push
   origin :refs/tags/v0.2.0`, tag the new commit, push); otherwise bump to the
   next patch version.

The policy is configurable with repository variables: `BB_RELEASE_GATE_SEVERITY=high`
(stricter), `BB_RELEASE_GATE_IGNORE_UNFIXED=0` (also block on findings that have no fix yet; the default `1` blocks only when a fix exists),
`BB_RELEASE_GATE=warn` (report only; record why in the release notes).

Note: Ubuntu lists every kernel CVE against the `linux` source package until it
is triaged, so the beast-net kernel brings thousands of findings, a few of them
critical and without a fix yet. By default (maintainer decision 2026-10-23) those
don't block a release but are listed in VULNERABILITIES.md and the release notes;
triage them with OpenVEX over time, and take Ubuntu's fixes as they are published.

## 7. Verifying a release (users)

In the folder with the downloaded files:

```sh
sha256sum -c SHA256SUMS --ignore-missing     # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
gh attestation verify beast-boot-<v>-linux-x86_64.tar.gz -R cynak/BeastBoot
```

On Windows: `Get-FileHash .\beast-boot-<v>-windows-x86_64.zip -Algorithm SHA256`
and compare with the line in `SHA256SUMS`. The attestation proves the file was
built by this repository's release workflow from the tagged commit.

Before enrolling the certificate, compare its fingerprint with
`beast-boot-<v>-CERTIFICATE.txt`, the release notes and docs/SECURE_BOOT.md
(section 3, "Check the key before you enroll it"): MokManager's **View key**
must show the same SHA-1 fingerprint. Every release since the key was created
has the same certificate; a different one means the drive or download is not an
official BeastBoot build.

## 8. CI details (GitHub Actions)

`.github/workflows/release.yml`:

| Job | Runs on | Permissions | Does |
|---|---|---|---|
| `probe` | ubuntu-latest | none | finds out whether the runner has `/dev/kvm` |
| `build` | ubuntu-latest, `container: ubuntu:26.04` (`--device /dev/kvm` when present) | `contents: read` | installs the build packages, sets up the key, fetches the gate baseline, runs `build_release.sh [--official] [--skip-e2e]`, uploads `release-files` |
| `portable-test` | ubuntu-latest, windows-latest, macos-latest (arm64), macos-15-intel (x86_64) | `contents: read` | `portable-test.yml`: unpack each package on its OS, verify it, `--version`/`--help`, `--gui --selftest` (xvfb on Linux), image install + `info --json` with the bundled runtime |
| `publish` | ubuntu-latest | `contents: write`, `id-token: write`, `attestations: write` | official runs only: checks `SHA256SUMS`, `actions/attest-build-provenance` for every file, `gh release create` (pre-release when the version has a suffix) |

Concurrency: one run per tag, never cancelled. Actions are pinned to full commit
SHAs. `macos-13` is retired, so the Intel macOS package is tested on
`macos-15-intel`. Without `/dev/kvm` the e2e tests are skipped with a notice.

`.github/workflows/ci.yml` (push to `main`, pull requests): `scripts/lint.sh
--ci`, the unit tests, the portable packages (fake `dist/` unless run manually
with the real one) and the same `portable-test.yml` smoke tests.
