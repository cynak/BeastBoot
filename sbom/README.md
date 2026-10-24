# sbom/: software bill of materials and vulnerability triage

BeastBoot puts third-party code in the boot chain (GNU GRUB, shim, a
Linux kernel and userland from Ubuntu's packages), so it publishes exactly
what it ships and what is known to be wrong with it.

## What is committed here

| File | What it is |
|---|---|
| `README.md` | this file |
| [`vex.openvex.json`](vex.openvex.json) | the project's triage decisions, in [OpenVEX](https://github.com/openvex/spec): for each finding, whether it affects BeastBoot and why. Hand-maintained; the only file here people edit. |

Everything else in this directory is generated and git-ignored (see
`.gitignore`).

## Why the reports are not committed

An SBOM describes one build: it lists every file of one `dist/` with its
SHA-256, and is tied to it by `beast-booter:manifest-sha256` (the SHA-256 of
`dist/manifest.json`). A vulnerability report is a snapshot of the scanners'
databases on one day. Committed copies would describe a build nobody has and
go stale silently. So each release publishes its own, made from the same
`dist/` it ships, and anyone can regenerate them for their own build.

## Regenerate

```sh
make build      # dist/ (the SBOM is made from dist/manifest.json)
make sbom       # SBOM only
make vulns      # SBOM + vulnerability and boot-chain scan
```

Both run [`scripts/sbom-vuln.sh`](../scripts/sbom-vuln.sh); `bash
scripts/sbom-vuln.sh all` also fetches the pinned, checksum-verified tools
(syft, grype, osv-scanner and the schemas) into `.tools/` first. The run is
rootless and writes only to `sbom/` and `.tools/`. Output:

| File | What it is |
|---|---|
| `beast-booter.cdx.json` | CycloneDX 1.6 SBOM: shipped packages, upstream projects, every `dist/` file (SHA-256, origin), signer certificates, build tooling |
| `beast-booter.spdx.json` | the same inventory in SPDX 2.3 |
| `validation.json` | schema and structural checks, per-file provenance |
| `vulnerabilities.json` | every finding: id, severity, component, scanners, VEX status, fix |
| `VULNERABILITIES.md` | the report for people: counts, boot-chain results, remediations |
| `vex.proposed.openvex.json` | evidence-backed triage proposals; never applied automatically |

Besides CVEs, the scan checks boot-chain risks CVE databases do not cover:
SBAT revocation levels against the shipped GRUB and shim, the certificates
that signed them (such as the expired Microsoft UEFI CA 2011), dbx entries,
and the signing key's health. The workflow, options and remediation rules
are in the project's skill,
[`.claude/skills/sbom-vuln/SKILL.md`](../.claude/skills/sbom-vuln/SKILL.md).

## In releases

Each release publishes, built from the release's own `dist/`:

- `beast-booter-<v>-sbom.cdx.json`, `beast-booter-<v>-sbom.spdx.json`
- `beast-booter-<v>-vulnerabilities.json`, `beast-booter-<v>-VULNERABILITIES.md`

They are listed in `SHA256SUMS` and covered by the release's provenance
attestations ([SECURITY.md](../SECURITY.md#verifying-a-release),
[docs/RELEASING.md](../docs/RELEASING.md)). The portable packages carry the
SBOM too, when it describes exactly their boot files.

## How VEX triage works

1. `make vulns` matches the SBOM against the vulnerability databases. A
   scanner match is not proof that BeastBoot is affected: the vulnerable
   code may not be built in (for example a GRUB module that is not embedded),
   or Ubuntu may have patched it without changing the upstream version.
2. For findings where the evidence says so (changelog entry, module not
   embedded, Ubuntu security tracker status), the scan writes a proposal to
   `vex.proposed.openvex.json`. Nothing is decided automatically.
3. A maintainer reviews a proposal and copies it into `vex.openvex.json`, or
   records `under_investigation` or `affected` with an `action_statement`
   when there is no evidence. `not_affected` needs a `justification` or an
   `impact_statement`; the scanner ignores (and reports) invalid statements.
4. The next `make vulns` applies `vex.openvex.json`, and the report shows
   each finding's VEX status next to it.

Triage never makes a boot-chain finding go away by weakening Secure Boot,
and an SBAT generation is never raised by hand: a revoked GRUB or shim is
fixed by shipping a fixed build
([docs/SECURE_BOOT.md](../docs/SECURE_BOOT.md#7-sbat-and-revocation-in-plain-words)).
To report a vulnerability, see [SECURITY.md](../SECURITY.md).
