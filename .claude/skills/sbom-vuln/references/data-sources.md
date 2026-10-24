# Data sources

Everything the skill reads, where it comes from, how it is cached and what happens
without network. Caches live under `.tools/` (git-ignored). `scan_vulns.py --offline`
never touches the network; `--refresh` re-fetches cached data files; data files are
re-fetched when older than `--max-age-hours` (default 24).

## Tools and schemas (install-tools.sh)

| What | URL | Pin / verification | Cache | Offline |
|---|---|---|---|---|
| syft 1.54.1 | github.com/anchore/syft/releases/download/v1.54.1/ | SHA-256 of tarball pinned in the script and matched against the publisher's `checksums.txt` (whose own SHA-256 is pinned too) | `.tools/cache/downloads`, binary in `.tools/bin` | kept once installed |
| grype 0.120.1 | github.com/anchore/grype/releases/download/v0.120.1/ | same | same | same |
| osv-scanner 2.6.0 | github.com/google/osv-scanner/releases/download/v2.6.0/ | same (`osv-scanner_SHA256SUMS`) | same | same |
| CycloneDX 1.6 JSON schema (+ `spdx.schema.json`, `jsf-0.82.schema.json`) | raw.githubusercontent.com/CycloneDX/specification/e833d73.../schema/ (tag 1.6.2) | SHA-256 pinned | `.tools/cache/schemas/cyclonedx-1.6` | kept |
| SPDX 2.3 JSON schema | raw.githubusercontent.com/spdx/spdx-spec/aadf3b0.../schemas/spdx-schema.json (tag v2.3) | SHA-256 pinned | `.tools/cache/schemas/spdx-2.3` | kept |

`.tools/sbom-vuln-tools.json` records what was installed; to move a pin, update version +
both SHA-256 values in `install-tools.sh` from the publisher's checksum file.

## Local inputs (gen_sbom.py)

| What | Where | Notes |
|---|---|---|
| shipped files, origins, SHA-256 | `dist/manifest.json` + `dist/` | every file re-hashed; mismatch aborts |
| package metadata | `dpkg-query -W` (host); `dpkg-deb -f` on `.tools/debs/*.deb` (rootless packages, e.g. grub-pc-bin, mtools) | version must equal the manifest origin |
| per-file origin check | `/var/lib/dpkg/info/<pkg>.md5sums` (host) or the `.deb` contents (SHA-256); `repo:`/`key:` files against the working tree | property `beast-booter:origin-verified`; `MISMATCH` fails validate_sbom (`origin-verified`) and the scan re-checks every file itself (BB-ORIGIN-MISMATCH); working-tree drift is a warning + BB-ORIGIN-UNVERIFIED |
| licences | `/usr/share/doc/<pkg>/copyright` (DEP-5 only; doc-dir symlinks followed to the same source version) | non-DEP-5 -> NOASSERTION |
| signing facts | the EFI binaries themselves (`.sbat`, `.sbatlevel`, Authenticode PKCS#7) + `openssl x509` | Authenticode digest cross-checked against the signature |
| installer imports | `installer/beastbooter/*.py` (ast) vs `sys.stdlib_module_names` | records stdlib-only |
| purl shape | syft on a minimal dpkg db / the .deb files (validate_sbom.py) | ours must equal syft's |

## Vulnerability data (scan_vulns.py)

| What | URL | Cache | Offline / failure |
|---|---|---|---|
| Anchore vulnerability DB (Ubuntu tracker, NVD, GHSA, ...) | grype.anchore.io (via `grype db update`) | `.tools/cache/grype` (~3 GB) | uses the cached DB; if older than 5 days it is used with age validation off and the report marks it **stale**; no DB = grype fails and the report says so |
| OSV.dev | api.osv.dev (osv-scanner queries per package; run twice: binary names from the SBOM, and Debian source names) | none by default; `--osv-download-db` also caches OSV's ecosystem databases in `.tools/cache/osv-scanner` | `--offline` runs osv-scanner with `--offline` against that local DB; without one both runs are reported as "not run offline" and only grype results are used |
| Ubuntu CVE tracker | https://ubuntu.com/security/cves/<CVE>.json | `.tools/cache/sbom-vuln/ubuntu-cve/` (24 h) | per-CVE "unavailable"; slow responses time out after 20 s |
| Package changelogs (triage evidence) | `/usr/share/doc/<pkg>/changelog.Debian.gz` or inside the `.deb` | none (local) | - |
| GRUB module graph (is a module embedded, can it be dropped?) | `/usr/lib/grub/x86_64-efi/moddep.lst` + `command.lst` of the grub-efi-amd64-bin version in the manifest (md5-verified against dpkg, or read from the `.deb`); the shipped `.cfg` files | none (local) | unverifiable -> removal is never proposed |

## Boot-chain data (scan_vulns.py)

| What | URL | Cache | Offline / failure |
|---|---|---|---|
| shim SBAT revocation levels | https://raw.githubusercontent.com/rhboot/shim/main/SbatLevel_Variable.txt (+ GitHub commits API for the commit/date) | `.tools/cache/sbom-vuln/SbatLevel_Variable.txt` (+ `.meta.json` with fetch time and SHA-256) | cached copy (report shows its date); none -> finding **BB-SBAT-NOT-CHECKED** (high) |
| UEFI dbx | https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/dbx_info_msft_latest.json and .../PostSignedObjects/DBX/amd64/DBXUpdate.bin (+ commits API) | `.tools/cache/sbom-vuln/` | cached copy; none -> **BB-DBX-NOT-CHECKED** (high) |
| Alternative shim builds | `/usr/lib/shim/shim*.efi*`, `.tools/root/usr/lib/shim/`, `apt-cache policy shim-signed` | none (local) | - |
| Ubuntu archive versions of boot packages | api.launchpad.net `getPublishedSources` for shim-signed, shim, grub2-unsigned, grub2-signed | `.tools/cache/sbom-vuln/launchpad/` (24 h) | omitted from the report |
| beast-booter certificate | `dist/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer` | - | - (the private key is never read) |

With **no network and an empty cache** (first run offline, or raw.githubusercontent.com
blocked) the scan still writes every report: SBAT and dbx become **BB-SBAT-NOT-CHECKED** /
**BB-DBX-NOT-CHECKED** with remediation R-DATA-UNAVAILABLE, the Launchpad and Ubuntu tracker
lines say "unavailable", grype without a cached DB is reported as failed, and `--fail-on`
exits 3 because an unknown result is not a pass. `scripts/selftest.py` covers this case.

The SBAT and dbx checks compare against the **latest** published data: a binary that passes
today can be revoked tomorrow. Re-run the scan before every release and periodically.
