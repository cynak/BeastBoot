# Remediation guide (beast-booter)

Every open finding in `sbom/VULNERABILITIES.md` carries a remediation key (`R-...`). This
guide explains each one in terms of *this* repository. File ownership matters: build/ (build +
signing), grub/ (menu), installer/, tests/e2e/ and the Makefile belong to their owners - when
a fix needs a change there, write it up as a proposal for that owner.

## The loop

```
scan ──> triage ──> fix ──> rebuild ──> re-scan ──> confirm closed
 │         │          │        │            │             │
 │         │          │        make build   sbom-vuln.sh  finding gone, or closed by
 │         │          │        make e2e     sbom + scan   a VEX statement you wrote
 │         │          update package / key / config
 │         VEX statement (with justification) or a fix plan
 sbom-vuln.sh scan
```

1. `bash scripts/sbom-vuln.sh scan` - read `sbom/VULNERABILITIES.md`.
2. Triage each open finding (table below). Decide: fix now, or record an OpenVEX statement.
3. Fix: change the package version, key or configuration in the right place.
4. Rebuild: `make build`, then `make e2e` (BIOS, UEFI, UEFI + Secure Boot must still boot).
5. Re-scan: `sbom-vuln.sh sbom && sbom-vuln.sh scan` (the SBOM must be regenerated after every build).
6. Confirm: the finding is gone, or shows as closed with your VEX statement. Commit the new
   `sbom/` outputs together with the change that caused them.

## Finding type -> fix

| Key | Finding | Fix in this repo | Priority |
|---|---|---|---|
| R-SBAT | SBAT generation of a shipped EFI binary is below shim's published revocation level (SbatLevel_Variable.txt) | Move to GRUB / shim **packages** whose SBAT meets the level: update `grub-efi-amd64-bin` and `grub-efi-amd64-signed` together (build.sh copies the SBAT CSV from the signed package and checks the versions match), `make build`, `make e2e`, re-scan. Never edit the `grub,N` (or `shim,N`) line by hand - SBAT must truthfully describe the code. Bump the `grub.beastbooter` generation in `build/sbat-beastbooter.csv` **only** for beast-booter's own security bugs (e.g. a menu/config bug that lets an attacker escape lockdown), so old beast-booter GRUBs can be revoked. Until a fixed package exists: document the limitation in docs/SECURE_BOOT.md. | critical |
| R-DBX | A shipped EFI binary (or a certificate in its signature) is in the UEFI dbx | Never ship it. Find a non-revoked build of the same component (newer shim-signed / GRUB package), rebuild, re-scan. | critical |
| R-SIG-BROKEN | Authenticode digest does not match the image | Rebuild; inspect with `sbverify --list`; never ship. | critical |
| R-MANIFEST | dist/ differs from manifest.json | Rebuild with `make build`; something else is writing dist/. | critical |
| R-ORIGIN | **BB-ORIGIN-MISMATCH**: a shipped file is not byte-identical to the package file its manifest origin (`deb:<pkg>=<ver>:/path`) names - checked against the dpkg md5sums (host packages) or the `.deb` contents (`.tools/debs`) by gen_sbom (`beast-booter:origin-verified`, validate_sbom check `origin-verified` FAILs) and again independently by the scan | Do not release: dist/ was altered after the build, the build copied a modified host file, or the origin names the wrong package (then every CVE match for that file is wrong too). `dpkg --verify <pkg>` on the host or `make tools` for `.tools/debs`, `make build`, regenerate the SBOM, re-scan until it is gone. If beast-booter patches a package file on purpose, the build must record it as `built:` with its inputs, never as `deb:`. | critical |
| R-ORIGIN-REBUILD | **BB-ORIGIN-UNVERIFIED**: a `repo:`/`key:` file differs from the working tree, or the named package version is no longer installed / in `.tools/debs` | The drive no longer matches the repository: `make build` from the current tree, regenerate the SBOM, re-scan. | medium |
| R-SBOM-STALE | **BB-SBOM-STALE**: the SBOM was generated from a different `dist/manifest.json` | `sbom-vuln.sh sbom`, then scan again - the package findings of that run describe the old build. | high |
| R-DATA-UNAVAILABLE | **BB-SBAT-NOT-CHECKED** / **BB-DBX-NOT-CHECKED**: the data source was unreachable and nothing is cached (first run offline, blocked host) | The result is *unknown*, not ok: `--fail-on` exits 3. Re-run the scan online once; later `--offline` runs use the cached copy (references/data-sources.md). Never release on a report with a check not run. | blocks release |
| R-CA2011 | shim signed only through *Microsoft Corporation UEFI CA 2011* (expired June 2026) | Switch the shim source to a build that is (also) signed by the *Microsoft UEFI CA 2023* once Ubuntu publishes it (watch `shim-signed`; the report lists Launchpad versions and every shim on the host with its signers). Then point the build at it, take MokManager from the same package, rebuild and run the Secure Boot e2e test with a varstore that has only the 2023 CA. Meanwhile document: machines whose db lacks the 2011 CA cannot boot beast-booter with Secure Boot on. Never self-sign or patch shim. | high |
| R-CERT | beast-booter signing certificate weak/expiring/mismatched | `make keys` (RSA >= 2048, EKU codeSigning, long validity), `make build`; users re-enroll `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`. | depends |
| R-SB-BYPASS | Secure Boot / lockdown bypass needing control of GRUB's config | On a beast-booter drive the config is on a writable FAT ESP, so assume reachable. Take the Ubuntu fix as soon as it exists; document; propose GRUB GPG verification of menu files (`grub-mkimage --pubkey`, `check_signatures=enforce`) to the build/menu owners; record OpenVEX `affected` + `action_statement` meanwhile. | high |
| R-UPDATE | Package CVE in a shipped component, fixed Ubuntu version exists | Move to the fixed Ubuntu package version: host packages `apt-get install --only-upgrade <pkg>` (needs the user/admin), `.tools/debs` packages `make tools` (scripts/bootstrap-tools.sh downloads the current version). Then `make build`, regenerate the SBOM, `make e2e`, re-scan. | by severity |
| R-VEX-FIXED | Scanner says not-fixed, but the shipped package's changelog records the fix | The distro tracker has not triaged the package. Review the proposed `fixed` statement (it quotes the changelog entry) in `sbom/vex.proposed.openvex.json` and copy it into `sbom/vex.openvex.json`. | triage |
| R-GRUB-NOT-EMBEDDED | Advisory is about a GRUB module that is not in grubx64.efi | grubx64.efi contains only `build/modules-efi.lst` plus their `moddep.lst` dependencies and no x86_64-efi modules ship on the drive, so the UEFI path does not contain the code. Copy the proposed `not_affected` / `vulnerable_code_not_present` statement for the EFI package. The BIOS module still ships in `/grub/i386-pc/` - keep that finding open on grub-pc-bin or assess it separately. | triage |
| R-GRUB-EMBEDDED | Advisory names a module that *is* embedded (directly or as a dependency) | The fix is the Ubuntu grub2 update: take it when published, `make build`, `make e2e`, re-scan. grub-mkimage embeds the requested modules **plus their moddep.lst closure**, so dropping a module from `build/modules-efi.lst` only helps when it is requested directly, no other requested module depends on it and the menu does not call its commands. The per-finding remediation computes this (`efi_removability` in vulnerabilities.json): e.g. `gettext` and `net` are dependencies of `normal` (and `net` of `chain`), so they cannot be removed without dropping `normal` - which is the menu itself. Only then propose a removal to the build owner. Record `under_investigation` (or `affected` + `action_statement`) meanwhile. | by severity |
| R-GRUB-TRACK / R-SHIM-TRACK / R-TRACK | No fix, no evidence | Find the upstream fix commit and check the shipped source version; track the Ubuntu update; record `under_investigation` (or `affected` + `action_statement`). shim is never rebuilt by us - only replaced by a newer Microsoft-signed Ubuntu shim. | by severity |
| R-NVD-CPE | NVD record matched by product name only (CPE without version range) | Verify against GRUB 2.14 / Ubuntu 2.14-2ubuntu1, then record `fixed` or `not_affected` with a justification. | triage |
| R-VEX-NOTPRESENT | Advisory is about a userland tool beast-booter does not ship (e.g. `grub2-set-bootflag`) | Record `not_affected` / `component_not_present` (proposal provided). | triage |
| R-PROVENANCE | A shipped file comes from outside the repository (`local:` origin) | Rebuild dist/ from the repo (`BB_MENU_DIR` unset or pointing at `grub/`). | medium |
| R-BUILD | Finding in build/install/test tooling (scope excluded) | Not on the drive. Update the host package or `make tools`; lower priority but keep it recorded. A *build* tool that writes shipped bytes (grub-mkimage, sbsign, objcopy) deserves a closer look than a test tool (qemu, OVMF). | low |

## Writing OpenVEX statements (`sbom/vex.openvex.json`)

Write a statement instead of ignoring a finding. Product = the beast-booter release; the
affected package goes in `subcomponents` with the purl (or CPE) exactly as in the SBOM.
Bump `version` and `timestamp` of the document whenever you change it.

```json
{
  "vulnerability": {"name": "CVE-2024-56737"},
  "products": [{"@id": "pkg:generic/beast-booter@0.1.0",
                "subcomponents": [{"@id": "pkg:deb/ubuntu/grub-efi-amd64-bin@2.14-2ubuntu1?arch=amd64&distro=ubuntu-26.04&upstream=grub2-unsigned"}]}],
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "fs/hfs is not in grubx64.efi (build/modules-efi.lst + moddep.lst) and no x86_64-efi modules are shipped.",
  "timestamp": "2026-10-23T00:00:00Z"
}
```

- `not_affected` requires `justification` (one of `component_not_present`,
  `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`)
  or an `impact_statement`. Prefer both.
- `fixed` = the shipped version contains the fix (cite the changelog entry in `status_notes`).
- `affected` requires an `action_statement` (what we do and when).
- `under_investigation` keeps the finding open but shows it is being looked at.
- The statement must name the same id the scanner reports or one of its aliases.
- When copying a proposal from `sbom/vex.proposed.openvex.json`, verify the evidence and
  replace the "PROPOSED by scan_vulns.py" text with your own assessment.
- Re-scan after editing: the report lists closed findings and any statement it rejected.

## Notes specific to beast-booter

- shim (`BOOTX64.EFI`, `mmx64.efi`) must remain the unmodified Microsoft/Canonical-signed
  Ubuntu binaries. Remediation = a different Ubuntu shim-signed build, never a rebuild.
- grubx64.efi is built here from Ubuntu's modules and signed with the beast-booter key; its
  SBAT is Ubuntu's plus `grub.beastbooter`. A GRUB CVE fix therefore always arrives as an
  Ubuntu package update + `make build`.
- BIOS GRUB (`core.img`, `/grub/i386-pc/*.mod`) has no Secure Boot; module CVEs there matter
  for crafted filesystems/ISOs, not for signature bypass. Ubuntu marks most of them
  "does not affect Secure Boot" for grub2.
- The SBOM must be regenerated after every `make build` - the scanner reports **BB-SBOM-STALE**
  when the SBOM describes a different manifest.
- Provenance is enforced, not just recorded: a shipped file that differs from its package is a
  validation FAIL and a critical boot-chain finding (BB-ORIGIN-MISMATCH), never a footnote.
