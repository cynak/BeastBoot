# 0.4.0 roadmap: Windows ISOs with Secure Boot on

Branch `feat/0.4.0-wimboot-sb` (based on 850d43f, the 0.3.0 merge). Goal: boot
Windows Setup / Windows PE ISOs with Secure Boot **on**, without weakening
Secure Boot.

## Approach

Sign the patched wimboot with the BeastBoot key, the key that already signs
GRUB. A user who boots BeastBoot with Secure Boot on has enrolled that key as a
MOK already, so no new trust is asked for. After wimboot, Windows verifies
itself: the firmware checks the ISO's Microsoft-signed boot manager against
`db`/`dbx`, and Windows checks its own loader and drivers.

Not chosen: Microsoft-signed upstream wimboot (unpatched, cannot start from
GRUB on UEFI; upstreaming patches 0001/0002 is a separate, slow track), an
ISO-as-disk EFI driver (much more code, same own-key trust), copying the ISO's
`boot.wim` to the ESP (does not fit in 512 MiB), enabling GRUB's UDF driver in
lockdown (weakens Secure Boot).

## Spike results (2026-10-26, OVMF Secure Boot VM, shim 16.1, Windows 11 26300 ISO)

| Check | Result |
|---|---|
| GRUB/shim accept the BeastBoot-signed wimboot | pass: `wimboot v2.9.0+bb1` starts, initrd via LoadFile2 |
| wimboot starts the ISO's boot manager under shim (no SBAT in it) | pass: `Secure Boot is enabled`, `Loaded bootmgfw_EX.efi`, Windows PE runs |
| `db` with only the 2023 Microsoft CAs | pass with Windows UEFI CA 2023 in db; refused (`Security Policy Violation`) when db lacks it |
| BIOS and UEFI with Secure Boot off, signed wimboot | pass: Setup runs from the mounted ISO |
| wimboot signed with another key | refused by shim (`bad shim loader signature`) |
| **Stock Windows ISO, Secure Boot on** | **fail: `no-recipe`.** GRUB 2.14 disables UDF in lockdown (`grub-core/fs/udf.c`), and Microsoft ISOs hide everything but `README.TXT` from ISO9660 |

Boot manager signers on this ISO: `bootmgfw.efi` = Microsoft Windows Production
PCA 2011; `bootmgfw_EX.efi` = Windows UEFI CA 2023 (wimboot tries it first).

## Phases

| # | Work | Status |
|---|---|---|
| 1 | Build signing: sign wimboot in `build/build.sh` (reproducible like GRUB), `verify-dist.sh`, SBOM checks | done in the working tree, needs a full build on this base |
| 1 | (verified on the 0.3.0 base: `make build` + `verify-dist.sh` pass) | done (e310ca4) |
| 2 | Getting `boot.wim` past the UDF limit: option C chosen (helper + host tool), interface in [WINDOWS_SECURE_BOOT.md](WINDOWS_SECURE_BOOT.md); helper action `winboot`, menu, host `prepare-windows` built in parallel | in progress |
| 3 | Menu: drop the `windows-sb` refusal; Secure Boot path uses the readable copy of the boot files; `boot-failed` explanation when the firmware refuses the boot manager | after 2 |
| 4 | Tests: replace `windows-sb` e2e tests with "boots under Secure Boot" + "wrong key refused"; real-ISO catalog gains a `uefi-sb` Windows case | after 2 |
| 5 | Docs: SECURE_BOOT.md §6, ISO_SUPPORT.md Windows limits, ARCHITECTURE.md, build/wimboot/README.md, REAL_ISOS.md, DEVELOPMENT.md error table | after 2 |
| 6 | Security review of the signed surface; SBAT generation plan for revoking a bad wimboot; `make vulns` | after 3-5 |
| 7 | Release: VERSION 0.4.0, full e2e + real-ISO run | last |

## Phase 2 options: boot files GRUB can read in lockdown

Only `boot.wim`, the boot manager, `bcd` and `boot.sdi` need to be readable by
GRUB; Setup then reads the ISO itself in Windows PE (beastmount). The copied
files need no trust of their own: the firmware verifies the boot manager and
Windows verifies everything it loads from `boot.wim`.

- **A. The signed beast-net helper extracts them** (it already boots under
  Secure Boot and reads UDF) to the data partition, keyed by the ISO's identity;
  the menu then boots the copy. Works however the ISO got onto the drive.
- **B. The host tool extracts them** when it adds an ISO. No extra boot, but
  ISOs copied by hand are not covered.
- **C. Both**: host tool when available, helper as the fallback.

## Risks

- Old Windows ISOs fail on PCs whose `dbx` revokes old boot managers (BlackLotus
  fix) or whose `db` lacks the CA that signed them. Same as Microsoft's own USB
  media; the docs must say so. The menu only sees `boot-failed`; wimboot's
  `Could not load ...: 0x...1a` is the on-screen clue.
- Signing wimboot makes it part of what the BeastBoot key vouches for: a wimboot
  bug that runs unsigned code would be a Secure Boot bypass on PCs that trust
  the key. Mitigation: SBAT vendor line (patch 0003) so a bad build can be
  revoked, and keeping wimboot pinned and minimally patched.
- Untested: a `db` without Windows UEFI CA 2023 (fallback to `bootmgfw.efi`).
