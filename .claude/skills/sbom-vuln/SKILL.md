---
name: sbom-vuln
description: Generate beast-booter's Software Bill of Materials (CycloneDX 1.6 + SPDX 2.3) from dist/manifest.json and dpkg metadata, scan it for vulnerabilities (grype + osv-scanner with OpenVEX triage) and for boot-chain risks (SBAT revocation, Secure Boot signer / Microsoft UEFI CA 2011 expiry, dbx revocation, signing-key health), and drive remediation. Use this whenever someone mentions an SBOM, software bill of materials, CycloneDX, SPDX, vulnerabilities, CVEs, a dependency or supply-chain scan, SBAT, revocation, dbx, the UEFI CA 2011/2023, VEX or triage, remediation, licences of what ships, or asks "is this vulnerable?" or "what exactly is on the drive?" - and after `make build` changed dist/ or before any release.
---

# sbom-vuln

beast-booter promises that users can see exactly what lands on their drive and
whether any of it is vulnerable or revoked. This skill produces that evidence.

| Output (all in `sbom/`) | What it is |
|---|---|
| `beast-booter.cdx.json` | CycloneDX 1.6 SBOM: shipped packages, upstream projects (CPE), every dist/ file (SHA-256, origin), signer certificates, build/install/test tooling (`scope: excluded`) |
| `beast-booter.spdx.json` | SPDX 2.3, same inventory |
| `validation.json` | schema + structural checks, per-file provenance, syft cross-checks |
| `vulnerabilities.json` | every finding: id, severity, component, shipped/build, scanners, VEX status, fix, remediation |
| `VULNERABILITIES.md` | human report: counts, boot-chain results, per-severity tables, remediations |
| `vex.proposed.openvex.json` | evidence-backed triage *proposals* (never applied automatically) |
| `vex.openvex.json` | **hand-maintained** triage (OpenVEX). The only file here people edit. |

## Workflow

Run from the repo root. Everything is rootless and writes only to `sbom/` and `.tools/`.

1. **Tools** (once; re-run is cheap): `bash scripts/install-tools.sh`
   - pinned, checksum-verified syft / grype / osv-scanner + CycloneDX/SPDX schemas.
2. **Inputs**: `dist/manifest.json` must exist (`make build`). dist/ is read-only input here.
   If it changes mid-run, gen_sbom aborts with "dist/ may be mid-rebuild" - wait and re-run.
3. **SBOM**: `bash scripts/sbom-vuln.sh sbom`
   (gen_sbom.py, then validate_sbom.py). All 9 checks must PASS; on FAIL read
   `sbom/validation.json` and fix the generator, never the output - except `origin-verified`:
   that FAIL means a shipped file is not the package file its manifest origin names (the
   drive content is wrong, not the SBOM; see R-ORIGIN).
4. **Scan**: `bash scripts/sbom-vuln.sh scan`
   (needs network for fresh data; ~1 min with a warm grype DB, first DB download ~1 min / 3 GB).
   Offline: add `--offline` - cached data is used and the report says so; checks without
   data say "not checked" (BB-SBAT-NOT-CHECKED / BB-DBX-NOT-CHECKED) instead of passing, and
   `--fail-on` then exits 3 (osv-scanner needs a local DB cached earlier with `--osv-download-db`).
5. **Read** `sbom/VULNERABILITIES.md` top-down: boot-chain findings first (they decide whether
   the drive boots at all), then shipped findings, then tooling.
6. **Triage + fix** each open finding with [references/remediation.md](references/remediation.md):
   scan -> triage -> fix -> rebuild -> re-scan -> confirm closed.

`sbom-vuln.sh all` does 1, 3 and 4 in one go; if validation fails it still scans (so the
report shows the problem) and exits 1. `--fail-on critical` makes the scan exit 3 when an open
shipped or boot-chain finding is critical, or a boot-chain check could not run (CI / `make vulns`).
After changing any script run `python3 -I scripts/selftest.py`
(offline, ~15 s: empty cache, tampered file, stale SBOM, module-removal advice).

## Decision points

- **Shipped vs build**: only `scope: required` components are on the drive. A CVE in qemu,
  OVMF, binutils or python is tooling - record it, fix it at lower priority.
- **Boot-chain critical (SBAT revoked, dbx hit, broken signature)** outranks every package CVE:
  the image is refused under Secure Boot. Fix by moving packages, never by editing SBAT
  generations (only `grub.beastbooter` in build/sbat-beastbooter.csv is ours to bump).
- **Provenance** (BB-ORIGIN-MISMATCH, critical): a shipped file must be byte-identical to
  the package file its origin names. Never "fix" it by editing the manifest - rebuild.
- **Module CVEs in grubx64.efi**: only propose dropping a module when the report says it is
  removable; `gettext`/`net` come in through `normal` and cannot go.
- **"not-fixed" from the scanner is not "affected"**: check the evidence columns (changelog
  entry, GRUB module embedded or not, Ubuntu tracker status). With evidence, review the
  proposal in `vex.proposed.openvex.json` and copy it into `vex.openvex.json`. Without
  evidence, keep it open or record `under_investigation` / `affected` + `action_statement`.
- **OpenVEX rules** (enforced by the scanner): `not_affected` needs a `justification` (or an
  `impact_statement`), `affected` needs an `action_statement`; product = `pkg:generic/beast-booter@<version>`
  with the package purl (or CPE) as subcomponent. Invalid statements are reported and ignored.
- **Files owned by others** (build/, grub/, installer/, Makefile, docs/): do not edit them to
  remediate; write the proposal into the report / your hand-off.
- Never weaken Secure Boot to make a finding go away (no disabling verification, no
  self-signed shim, no fake SBAT).

## Details

- [references/remediation.md](references/remediation.md) - finding type -> fix in this repo, the loop, VEX examples.
- [references/data-sources.md](references/data-sources.md) - every external source, URL, cache, offline behaviour.
- Scripts (`scripts/`, python3 stdlib, run with `python3 -I`): `gen_sbom.py`, `validate_sbom.py`,
  `scan_vulns.py`, helpers `efi_inspect.py` (PE/Authenticode/SBAT) and `debinfo.py` (dpkg, DEP-5, changelogs),
  regression tests `selftest.py`.
