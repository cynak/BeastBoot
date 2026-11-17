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
| `beast-boot-<v>-ENROLL_THIS_KEY_IN_MOKMANAGER.cer` | the BeastBoot CA certificate users enroll (DER) |
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
2. **Signing keys**: `BB_KEY_DIR` (default `keys/`). `--official` refuses the
   development keys in `keys/`; `BB_RELEASE_CERT_SHA256` pins the expected CA certificate.
   With `BB_PRESIGNED_DIR` only the certificate has to be there (see "Signing in
   its own job" below).
3. **`make build`**: boot files and beast-net into `dist/`, signed with that key,
   or, with `BB_PRESIGNED_DIR`, using the three files that were signed elsewhere.
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
| `BB_KEY_DIR` | directory with the CA certificate (`beast-boot.crt`, `.cer`) and the three leaves (`beast-boot-{grub,kernel,wimboot}.key`, `.crt`); with `BB_PRESIGNED_DIR` no key is needed |
| `BB_RELEASE_TAG` | the tag being released |
| `BB_RELEASE_CERT_SHA256` | refuse any CA certificate but this one (SHA-256 of `beast-boot.cer`) |
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

## 3. The release signing keys

Every BeastBoot user enrolls one certificate in MokManager, once: the
**BeastBoot CA** certificate. The CA signs nothing that boots. It issues three
signing ("leaf") certificates, one per signed file:

| Leaf | Signs | Key and certificate |
|---|---|---|
| `grub` | `EFI/BOOT/grubx64.efi` | `beast-boot-grub.key`, `.crt` |
| `kernel` | `beast-net/vmlinuz` (the helper's kernel) | `beast-boot-kernel.key`, `.crt` |
| `wimboot` | `beast-booter/wimboot` | `beast-boot-wimboot.key`, `.crt` |

Where each key lives:

| Key | Where | Who can use it |
|---|---|---|
| CA private key (`beast-boot-ca.key`) | **offline, on your own computer or an encrypted USB stick, with a backup**. Never in GitHub, never in CI, never on a build host | you, by hand, to issue or replace a leaf |
| the three leaf keys | the protected GitHub environment `release` (and your offline backup) | the release workflow's `sign` job, for `v*.*.*` tags, after your approval |
| CA certificate, leaf certificates | public: in every release | everyone |

A leaked or misused leaf key is replaced with the CA key and revoked with one
MokListX entry; users enroll nothing again. A new CA means every user enrolls
again, so create it once, carefully.

### Once: create the CA and the first leaves (offline)

1. On an offline machine with a checkout of this repository and an encrypted
   USB stick mounted at, say, `/media/usb`:

   ```sh
   export BB_CA_DIR=/media/usb/bb-ca            # the CA: stays offline
   export BB_KEY_DIR=/media/usb/bb-leaves       # the leaves: go to GitHub
   BB_KEY_CN="BeastBoot Secure Boot CA" build/keygen.sh ca
   build/keygen.sh leaf all
   ```

   It prints each certificate's subject, validity and fingerprints. The CA is
   RSA-2048, `CA:TRUE, pathlen:0`, `keyCertSign`, 20 years; a leaf is RSA-2048,
   `CA:FALSE`, `digitalSignature`, `codeSigning`, 10 years, and names its
   component in the subject's `OU` (the build refuses a file signed with
   another component's leaf). Firmware and shim do not check the dates
   ([SECURE_BOOT.md](SECURE_BOOT.md#certificate-dates)); the build does.
2. Back up `bb-ca/` (the CA key and certificate) and `bb-leaves/` to a second
   encrypted medium kept somewhere else. Without the CA key you cannot replace
   a leaf: the only way forward is then a new CA and a new enrolment for
   everyone. **Never commit a key** and never put the CA key anywhere but
   those two media.
3. In GitHub, create the environment `release` (*Settings → Environments → New
   environment*) and protect it:
   - *Deployment branches and tags*: selected tags only, pattern `v*.*.*`;
   - *Required reviewers*: yourself (each release waits for one click);
   - add a tag ruleset (*Settings → Rules → Rulesets*) for `v*` so only you can
     create, move or delete release tags.

   Then add seven secrets to that environment, **not** as repository secrets
   (the certificates are public; they are secrets only so that a release
   cannot be made with others):

   ```sh
   cd /media/usb/bb-leaves
   gh secret set BB_SB_CA_CERT_PEM      --env release < beast-boot.crt
   gh secret set BB_SB_GRUB_KEY_PEM     --env release < beast-boot-grub.key
   gh secret set BB_SB_GRUB_CERT_PEM    --env release < beast-boot-grub.crt
   gh secret set BB_SB_KERNEL_KEY_PEM   --env release < beast-boot-kernel.key
   gh secret set BB_SB_KERNEL_CERT_PEM  --env release < beast-boot-kernel.crt
   gh secret set BB_SB_WIMBOOT_KEY_PEM  --env release < beast-boot-wimboot.key
   gh secret set BB_SB_WIMBOOT_CERT_PEM --env release < beast-boot-wimboot.crt
   ```

   `beast-boot-ca.key` is not among them and must never be. Delete the secrets
   of the old single key (`BB_SB_KEY_PEM`, `BB_SB_CERT_PEM`) and any repository
   secrets of these names. The release job uses `release` only for official
   runs (tag pushes, `dry_run=false`); dry runs use the secret-less
   environment `dry-run` and make a throwaway CA and leaves, and the key step
   refuses any ref that is not a `v*.*.*` tag.
4. Pin the CA. Set the repository *variable* `BB_RELEASE_CERT_SHA256` to
   `sha256sum /media/usb/bb-ca/beast-boot.cer` (the DER file), so a wrong or
   swapped CA certificate fails the build instead of shipping. The leaves need
   no pin: the build accepts a leaf only if the pinned CA issued it, for the
   right component.
5. Publish the CA's SHA-1 and SHA-256 fingerprints (`openssl x509 -in
   beast-boot.crt -noout -fingerprint -sha1 -fingerprint -sha256`) in
   docs/SECURE_BOOT.md.

The workflow writes the leaf keys to a fresh 0700 directory (umask 077), never
prints them, and shreds them at the end of the `sign` job. A tag build without
the seven secrets fails.

### Replace one leaf (a component's key leaked, was misused, or expires)

Nobody has to enroll anything: the CA stays.

1. Offline, with the CA medium mounted: `BB_CA_DIR=/media/usb/bb-ca
   BB_KEY_DIR=/media/usb/bb-leaves build/keygen.sh leaf wimboot --force`
   (or `grub`, `kernel`). Keep the **old** certificate: copy
   `beast-boot-wimboot.crt` aside before, it is what gets revoked.
2. Update the two secrets of that leaf (`gh secret set BB_SB_WIMBOOT_KEY_PEM
   ...`, `BB_SB_WIMBOOT_CERT_PEM ...`) and back up the new files.
3. Release. The new build is signed with the new leaf; older builds keep
   working until their leaf is revoked.
4. If the old leaf must stop working (a leaked key, a vulnerable build that
   must not boot any more): publish the old certificate as a `.cer` (DER:
   `openssl x509 -in old.crt -outform DER -out beast-boot-wimboot-revoked.cer`)
   with the release and tell users to add it to MokListX
   ([SECURE_BOOT.md section 7](SECURE_BOOT.md#7-sbat-and-revocation-in-plain-words)):
   `sudo mokutil --mokx --import beast-boot-wimboot-revoked.cer`, reboot,
   confirm in MokManager. BeastBoot cannot do this for them: it takes someone
   at each computer, as every MOK change does. From then on that computer
   refuses every build signed with the old leaf and starts the new ones.

### Replace the CA (the CA key leaked or is lost)

The worst case, and the only one where every user acts.

1. New CA and leaves as in "Once" above, new secrets, new
   `BB_RELEASE_CERT_SHA256`, new fingerprints in the docs.
2. Release. After updating, every computer with Secure Boot on shows the
   first-time enrolment again (the installer says so before it updates a
   drive whose certificate changes).
3. Users remove the old CA certificate ([SECURE_BOOT.md section
   4](SECURE_BOOT.md#4-remove-a-certificate-later)); if its key leaked they
   should also add it to MokListX (`mokutil --mokx --import old-ca.cer`), so
   that nothing signed under it starts even if the certificate is enrolled
   again by mistake.

The 0.4.x to 0.5.0 step is this case once, planned: the single self-signed
certificate of 0.1 to 0.4 is replaced by the CA.

### Signing in its own job

The release key is only ever on the disk of the job `sign`, which does nothing
but sign three files. The GRUB build, the tests, the QEMU runs and the scanners
run in jobs that have no secret:

| Job | Environment | What it does |
|---|---|---|
| `unsigned` | none | `BB_UNSIGNED_OUT=out/unsigned make build` with throwaway keys; uploads the unsigned `grubx64.efi`, `vmlinuz` and `wimboot` |
| `sign` | `release` (dry run: `dry-run`) | `build/sign.sh unsigned signed`: refuses any other file and any file that already has a signature, signs each file with its own leaf key, checks each result, uploads the signed files and the certificates (the CA's and the three leaves', never a key). The CA key is not there |
| `build` | none | builds again with `BB_PRESIGNED_DIR`: each signed file must carry exactly one signature, made with its own component's leaf, which the pinned CA issued, over exactly the image this job built; then tests, scan, packaging |

So `sign` signs only what a build without secrets produced, and `build` refuses
signed files that are not its own build. If the two builds differ (they are
reproducible, so they should not), `build` stops with "is not this build's ...".

The unsigned images must not depend on the key, although `unsigned` and
`build` run with different certificates. Since 0.5.0 `grubx64.efi` contains
the menu and with it `version.cfg` and the build id, so the build id leaves
the certificate file out (`build/bbtool.py`, `BUILD_ID_EXCLUDE`): the same
sources give the same id and the same unsigned images whoever signs them, and
the manifest says who did (`secure_boot.cert_sha256`).
`devtools/e2e-on-kvm-host.sh signflow` runs this split with throwaway keys
(the leaves of a second CA whose key is elsewhere), compares two key-less
rebuilds byte for byte, checks that a file signed with another component's
leaf or with a leaf of another CA is refused, and replaces one leaf.
A dry run takes the same three jobs with a throwaway CA and leaves made in `sign`
(the CA key is deleted before anything is signed, as in a release it is never there).

By hand, the same split is:

```sh
BB_UNSIGNED_OUT=/tmp/unsigned make build                            # any keys
BB_KEY_DIR=/media/usb/bb-leaves build/sign.sh /tmp/unsigned /tmp/signed   # the three leaf keys
BB_KEY_DIR=/tmp/signed BB_PRESIGNED_DIR=/tmp/signed make build      # no private key
```

If a key leaks: see SECURITY.md and "Replace one leaf" / "Replace the CA" above.

## 4. Cutting a release

1. Make sure `main` is green (ci.yml) and `make vulns` looks as expected.
2. Bump `VERSION` (for example `0.2.0`, or `0.2.0-rc.1` for a pre-release).
3. Run the local pre-release routine on that exact tree (see below), regenerate the
   README's ISO table from its real-ISO results (`.venv/bin/python scripts/iso_matrix.py
   --readme`) and commit.
4. Tag and push:

   ```sh
   git tag -a v0.2.0 -m "beast-boot 0.2.0"
   git push origin v0.2.0
   ```

5. Watch *Actions → release*. When it is green, the release is published with
   all files, notes and attestations.

### Before tagging: `make prerelease`

`scripts/release/prerelease.sh` runs everything a release must pass on this machine,
including what the CI release cannot (it has no real ISOs and no time for them):

| Step | What |
|---|---|
| build, lint, lock | `make build`, `make lint`, `build/beastnet/lock.py --check` |
| installer, menu, beastnet, devtools | every unit suite |
| e2e | the QEMU end-to-end suite (`tests/e2e`, incl. Disk tools) |
| scan-pre, kernel-vex, scan | `make vulns`, `scripts/kernel_vex.py` (kernel VEX against today's data), `make vulns` again; fails on an incomplete scan (a scanner failed) or VEX problems |
| selftest | `scripts/selftest.py` against the SBOM the scan just wrote (with `--quick`: right after the unit suites, against the SBOM already there) |
| real-iso | every real ISO boots (`BB_REAL_ISO=1`, about 25 minutes, tens of GB downloaded once) |
| verify-dist | `build/verify-dist.sh --rebuild`: GRUB, wimboot and beastmount rebuilt from source, byte-identical |
| portable | `scripts/build_portable.sh --all` |

Every step runs even after a failure; the summary (`out/prerelease/summary.txt`, one log
per step beside it) shows them all, and the exit code is the number of failed steps.
It also fails when the tree changes while it runs (another editor or session), because
the results would then not describe what gets tagged.

Each step prints a start line and, every 30 seconds, its elapsed time and the last line
of its log (`ARGS="--progress 10"`, or `--progress 0` for start and end lines only). Each
step has a time limit (in its `step` line in the script, e.g. 15 minutes for the
beast-net unit tests, 3 hours for e2e): a step that runs past it is stopped with all its
child processes and counted as `TIMEOUT`, so one hung test cannot block the run. Ctrl+C
(or SIGTERM) stops the running step the same way.

The build signs with the key in `keys/`; in a git worktree, which has no `keys/`, point
`BB_KEY_DIR` at the main checkout's keys (`BB_KEY_DIR=/path/to/beast-booter/keys make
prerelease`), or the build step fails at once.

```sh
make prerelease                          # everything (about an hour)
make prerelease ARGS=--skip-real-iso     # no real ISOs
make prerelease ARGS=--quick             # unit tests, lint, lock check only
```

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
