# Code quality: ruff + ShellCheck

`make lint` (the same as `scripts/lint.sh`) runs two static checkers:

| Tool | Checks | Settings | Version |
|---|---|---|---|
| [ruff](https://docs.astral.sh/ruff/) | all Python: `installer/`, `devtools/`, `beastnet/`, `tests/`, `build/`, `scripts/`, `packaging/` | [`ruff.toml`](../ruff.toml) | pinned with SHA-256 hashes in `requirements-dev.txt`, installed into `.venv` |
| [ShellCheck](https://www.shellcheck.net/) | every shell script, found by extension (`.sh`, `.bash`) and by a `sh`/`bash`/`dash`/`ksh` shebang (`bin/*`, `beastnet/rootfs/init`, the udhcpc scripts, the portable launchers, ...) | [`.shellcheckrc`](../.shellcheckrc) | pinned static binary in `.tools/bin/shellcheck` |

It must pass before a change goes in. Files that git ignores (`out/`, `dist/`,
`.tools/`, `.venv/`) are never checked, and neither are GRUB `.cfg` files:
they look like shell but are GRUB script.

## Running it

```sh
make lint                                  # everything; exit status 1 on findings
scripts/lint.sh installer/beastbooter      # one directory (or several files)
scripts/lint.sh --only shellcheck          # one tool: ruff or shellcheck
scripts/lint.sh --fix                      # apply ruff's safe fixes, then report what is left
make lint ARGS="--only ruff devtools"      # the same options through make
```

Exit status: `0` clean, `1` findings, `2` a tool is missing or a bad option.
Findings print one per line (`file:line:col: CODE message`), so editors and the
VS Code tasks can jump to them; a summary with the count per tool comes last.

### Where the tools come from

- **ruff**: `.venv/bin/ruff`, created by `bin/bb-dev setup` (or `make dev`)
  with `pip install --require-hashes -r requirements-dev.txt`. Without a
  `.venv` the script falls back to `python3 -m ruff`, then to `ruff` on
  `PATH`; if none is there it says to run `bin/bb-dev setup --minimal`.
  To move to a newer ruff, update its version and hashes in
  `requirements-dev.txt` (see the header of that file) and run
  `bin/bb-dev setup --minimal` again.
- **ShellCheck**: the first run downloads the official static build of
  ShellCheck 0.11.0 for this host (Linux x86_64/aarch64, macOS x86_64/arm64)
  from the project's GitHub releases, checks it against the SHA-256 pinned in
  `scripts/lint.sh` (the digest GitHub publishes for the release asset),
  and installs it as `.tools/bin/shellcheck`. No root, no package manager.
  The download is kept in `.tools/cache/lint/`. If the download is not
  possible (offline, other CPU), a `shellcheck` on `PATH` is used with a
  warning that it is not the pinned version. To move to a newer release,
  change `SC_VERSION` and the four digests in `sc_asset()` in `scripts/lint.sh`.

## What is checked

### ruff (`ruff.toml`)

- `target-version = "py310"`: the installer, bb-dev and beast-net support
  Python 3.10+, so ruff also reports syntax that needs a newer Python (for
  example, quotes reused inside an f-string, which is 3.12+).
- Rules: `E4`, `E7`, `E9` (imports, statements, syntax errors), `F` (pyflakes:
  unused imports and variables, undefined names, ...), `UP` (pyupgrade for the
  3.10 baseline). `UP031` (printf-style `%` formatting) is off.
- Per-file exceptions: test modules and `devtools/gdb/demo.py` may import after
  putting a directory on `sys.path` (`E402`); `build/bbtool.py` keeps its
  argparse table one sub-command per line (`E702`).
- `exclude` replaces ruff's default list on purpose: the default skips every
  directory named `build`, and `build/` holds Python sources here.

ruff's formatter (`ruff format`) is not enforced.

### ShellCheck (`.shellcheckrc`)

- `external-sources=true` and `source-path=SCRIPTDIR`: ShellCheck follows
  `source`/`.` to the file, resolved next to the script, so variables and
  functions defined in a sourced helper (`scripts/dev-env.sh`, ...) are known.
- All severities are reported (error, warning, info, style).
- The shell dialect comes from each script's shebang (`#!/bin/sh` scripts are
  checked as POSIX sh; beast-net's `init` runs under busybox `sh`).

## Fixing findings

- `scripts/lint.sh --fix` applies the fixes ruff marks as safe (shown with
  `[*]`). It never passes `--unsafe-fixes`; anything else is fixed by hand.
  Review the diff afterwards.
- ShellCheck has no automatic fixes. The wiki page for every code explains the
  problem and the usual fix: `https://www.shellcheck.net/wiki/SC2086`.

### Silencing a finding properly

Fix the code when you can. When a finding is wrong for that one line, silence
it there, with the reason, never for a whole file or the whole repository
unless the rule really does not apply anywhere:

```python
from bbdev import paths  # noqa: E402  # needs the sys.path line above
```

```sh
# shellcheck disable=SC2094  # $CONSOLE is a tty, read and written on purpose
setsid -c sh -l <"$CONSOLE" >"$CONSOLE" 2>&1
```

A ShellCheck directive applies to the next command (a function definition or
compound command counts as one). Directly after the shebang it applies to the
whole file, which is right only for things like variables that the caller
sets in the environment (the udhcpc scripts). Rules that should be off for a
group of files go into `per-file-ignores` in `ruff.toml`, with a comment.

## Continuous integration

CI runs:

```sh
scripts/lint.sh --ci
```

`--ci` turns colours off and prints findings as GitHub Actions annotations
(`::error file=...,line=...`), so they show up on the changed lines of a pull
request; ShellCheck notes and style findings become `::notice`. The job needs
the `.venv` from `bin/bb-dev setup --minimal` (or any Python with the pinned
ruff) and network access to GitHub releases the first time, to fetch the
pinned ShellCheck; cache `.tools/cache/lint/` to skip that download.

## Editor integration

VS Code (or VSCodium / Code - OSS) recommends these extensions in
`.vscode/extensions.json`, all open source:

| Extension | Licence | Use |
|---|---|---|
| `charliermarsh.ruff` (Ruff) | MIT | ruff findings while you type; uses `.venv`'s ruff (`"ruff.importStrategy": "fromEnvironment"`) and `ruff.toml` |
| `timonwong.shellcheck` (ShellCheck) | MIT | ShellCheck findings while you type; reads `.shellcheckrc` |
| `ms-python.python`, `ms-python.debugpy` | MIT | Python, Test Explorer, the debugpy launch configurations |
| `eclipse-cdt.cdt-gdb-vscode` (CDT GDB Debug Adapter) | EPL-2.0 | the "GRUB (BIOS/UEFI): attach gdb to QEMU" launch configurations |

Tasks (**Terminal > Run Task**): **lint: all**, **lint: ruff**,
**lint: shellcheck** and **lint: apply ruff's safe fixes** run
`scripts/lint.sh` and send findings to the Problems panel.

Other editors: ruff and ShellCheck have plugins or language-server support
for most editors (Neovim, Emacs, Helix, Sublime, JetBrains); they read the
same `ruff.toml` and `.shellcheckrc`.

## Licensing

Only open-source tools are used, and nothing needs a licence key, an
account or a server:

- ruff: MIT. ShellCheck: GPL-3.0 (run as a separate program; nothing of it is
  shipped on a drive or linked into beast-booter).
- The recommended editor extensions are MIT or EPL-2.0 (table above).

Note that the Marketplace build of `ms-python.python` installs Pylance, a
closed-source Microsoft extension, as part of its extension pack. You do not
need it for anything here; uninstall or disable it if you want an
all-open-source editor setup (Ruff covers the linting).
