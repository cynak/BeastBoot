# Contributing to BeastBoot

Thank you for helping. BeastBoot sits in the boot chain of other people's
computers, so a few rules matter more here than in most projects; they are
listed under [Principles](#principles). Everything else is in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Set up

Linux on x86_64 (development happens on Ubuntu 26.04), Python 3.10+, bash,
make and git. No root is needed.

```sh
make dev        # = bin/bb-dev setup --yes: rootless toolchain in .tools/, .venv,
                #   your own signing key in keys/, dist/, unit tests, a dev image
make doctor     # what is missing, and how to fix it
```

`make dev` is idempotent: run it again after pulling. With KVM
(`/dev/kvm` usable by you) the QEMU tests are 4 to 10 times faster.

## Test

Run what covers your change before you send it:

| Change in | Run |
|---|---|
| `installer/` | `make test` |
| `devtools/` | `pytest -q devtools/tests` |
| `beastnet/` | `pytest -q beastnet/tests` |
| `build/beastnet/` | `make build`, then `pytest -q tests/e2e -m beastnet` |
| `grub/`, `build/`, anything that boots | `make build && make e2e` (84 QEMU tests: BIOS, UEFI, Secure Boot, exFAT/NTFS, beast-net) |
| `packaging/` | `make portable` |

Use `.venv/bin/pytest` (or `source .venv/bin/activate`) when `pytest` is not
on your `PATH`. Tests skip, and say why, when something they need is
missing; `pytest -rs` lists the reasons. Details: [docs/DEVELOPMENT.md
§5](docs/DEVELOPMENT.md#5-running-tests) and
[tests/e2e/README.md](tests/e2e/README.md).

If you changed what ends up on the drive, also run `make vulns` and read
`sbom/VULNERABILITIES.md` ([sbom/README.md](sbom/README.md)).

## Lint

```sh
make lint       # ruff (Python) + ShellCheck (shell scripts)
```

It must pass. Configuration and how to silence a warning properly:
[docs/CODE_QUALITY.md](docs/CODE_QUALITY.md).

## Principles

- **Never weaken Secure Boot.** Nothing that ships may disable, patch, hook
  or bypass firmware or shim signature verification, or ship a revoked or
  known-vulnerable signed binary. SBAT generations describe the code we
  ship and are never raised by hand. A change that makes more ISOs boot by
  weakening any of this will not be merged
  ([SECURITY.md](SECURITY.md), [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md)).
- **Transparency.** Every file on the drive is built from this repository or
  copied unmodified from a named distribution package, and listed in
  `dist/manifest.json` with its origin and SHA-256. No unexplained binaries,
  no generated files without the generator.
- **Pinned and checksum-verified downloads.** Packages come from the signed
  Ubuntu archive with exact versions; everything else (Python wheels,
  runtimes, tools, firmware) is pinned by version and SHA-256 and checked
  before use. Builds are reproducible.
- **Only open-source tooling** to build, test and analyse the project, run
  locally. Closed firmware is never shipped; firmware packs are optional and
  installed by the user.
- **Boring, auditable code.** Installer and `bb-dev`: Python standard library
  only. Menu: plain GRUB script. Build: bash.
- **Dev tooling never writes real block devices**; only the installer does,
  with its safety checks. Keep private keys (`keys/*.key`) out of commits,
  images and bug reports.
- **Contracts first.** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
  [docs/MENU.md](docs/MENU.md) and [docs/BEASTNET.md](docs/BEASTNET.md)
  describe interfaces between components. Change the document in the same
  change as the code.

## Sending a change

- Keep a change focused; say what it changes and how you tested it (which
  commands, which firmware modes, real hardware if any).
- Update the documentation the change affects, and add or adjust tests.
- New third-party input (a package, a tool, a download) needs its pin and
  checksum, an entry in the manifest or SBOM where it ships, and its licence.

## Security issues

Do not open a public issue for a vulnerability. Report it privately as
described in [SECURITY.md](SECURITY.md#reporting-a-vulnerability).

## License

By contributing you agree that your contribution is licensed under
GPL-3.0-or-later, like the rest of the project ([LICENSE](LICENSE)).
