# Portable packages (no installation)

beast-booter is also published as a portable package for Linux, Windows and
macOS: unpack the archive, start the program, delete the folder when you are
done. Nothing is installed, nothing is added to your system, and nothing is
downloaded while it runs, except the optional firmware packs when you ask for
them (from the URLs and with the SHA-256s it shows first; see
[BEASTNET.md](BEASTNET.md#6-firmware-packs)).

Each package is built to be checked by its users. It contains:

- an **official CPython runtime** from
  [python-build-standalone](https://github.com/astral-sh/python-build-standalone),
  pinned by SHA-256 in `packaging/portable/runtimes.lock` and unmodified, except
  that its stale bytecode caches are left out (see below);
- the beast-booter program as **plain `.py` source files**, which you can read.
  The package holds no Python bytecode (`.pyc`) at all, so Python runs exactly
  the `.py` files you can read;
- the **boot files** (`dist/`) with their own `manifest.json`, which gives the
  origin and SHA-256 of every file that is written to a drive (see
  ARCHITECTURE.md §4), plus the SBOM when one was built for exactly these files;
- small, readable **launcher scripts**; and
- **`PACKAGE-MANIFEST.json`**, which lists every file in the package with its
  SHA-256 and where it came from.

## Download

| File | For |
|---|---|
| `beast-booter-<version>-windows-x86_64.zip` | Windows 10 or newer, 64-bit (x86_64) |
| `beast-booter-<version>-macos-arm64.zip` | Macs with Apple silicon (M1 and later), macOS 11 or newer |
| `beast-booter-<version>-macos-x86_64.zip` | Intel Macs, macOS 10.15 or newer |
| `beast-booter-<version>-linux-x86_64.tar.gz` | Linux x86_64 with glibc 2.17 or newer, and X11 or XWayland for the window |
| `SHA256SUMS` | SHA-256 of every release file |

The same release page also has the boot files on their own
(`beast-booter-<version>-dist.zip`, usable with `--dist`), the Secure Boot
certificate (`beast-booter-<version>-ENROLL_THIS_KEY_IN_MOKMANAGER.cer` and
`beast-booter-<version>-CERTIFICATE.txt` with its fingerprints), the SBOM
(`-sbom.cdx.json`, `-sbom.spdx.json`) and the vulnerability report
(`-vulnerabilities.json`, `-VULNERABILITIES.md`), all listed in `SHA256SUMS`
and covered by GitHub build-provenance attestations. How to check those:
[SECURITY.md](../SECURITY.md#verifying-a-release); the full list:
[RELEASING.md](RELEASING.md).

## Check the download first

Do this before you run anything from the package.

**1. The archive matches `SHA256SUMS`.** Get `SHA256SUMS` from the same release
page and compare:

```sh
# Linux
sha256sum -c --ignore-missing SHA256SUMS
# macOS (checks only the line for your archive)
grep -F macos-arm64.zip SHA256SUMS | shasum -a 256 -c -
```

```powershell
# Windows (PowerShell): compare the output with the line for this file in SHA256SUMS
Get-FileHash .\beast-booter-0.1.0-windows-x86_64.zip -Algorithm SHA256
```

**2. The unpacked files match `PACKAGE-MANIFEST.json`.** Unpack the archive and run
the included checker with any Python 3.8 or newer:

```sh
python3 beast-booter-0.1.0-linux-x86_64/verify-package.py
```

It recomputes the SHA-256 of every file and checks symlinks and executable
bits. It also checks the boot files against `payload/dist/manifest.json` (the
same check the installer makes before it writes a drive) and the layout the
launchers need, and it reports any file that is missing or that is not part of
the package. You can also run it on an archive without unpacking it:
`python3 verify-package.py beast-booter-0.1.0-macos-arm64.zip`.

If you have no Python, use the bundled one, but only after step 1, and always
with `-I -S -B`:

```sh
runtime/bin/python3 -I -S -B verify-package.py                                # Linux
BeastBooter.app/Contents/Resources/runtime/bin/python3 -I -S -B verify-package.py  # macOS
```

```bat
runtime\python.exe -I -S -B verify-package.py
```

`-B` matters. Without it, Python writes bytecode caches (`__pycache__/*.pyc`)
into the runtime folder while it starts, and the check then fails, rightly,
because Python would run those files instead of the `.py` sources. If that
happened, unpack the archive again. (`-I` ignores your Python settings, and `-S`
skips `site-packages` and its `.pth` files.)

What counts as "not part of the package" in an unpacked folder: inside
`runtime/`, `app/` and `payload/` (on macOS, anywhere in `BeastBooter.app`),
every extra file is an error, because Python, Tcl/Tk or the system could load
it from there. Elsewhere, an extra file is an error if it is code (`.py`,
`.pyc`, `.pth`, `.dll`, `.so`, `.exe`, `.cmd`, ...) and otherwise only a
warning, for example a disk image you saved into the folder or the
`.DS_Store` and `Thumbs.db` files that file managers add. In an archive, every
extra entry is an error.

Step 2 shows that the files are the ones the package was built with. Step 1
(with a `SHA256SUMS` you got from a source you trust) shows that the package
is the one that was published.

**Going further.**

- *Runtime:* `PACKAGE-MANIFEST.json` → `sources.runtime` names the
  python-build-standalone asset, its URL and its SHA-256. Download that asset
  yourself, check it against the release's own `SHA256SUMS`, unpack it, and
  compare its `python/` folder with the package's `runtime/` folder:
  `diff -r -x __pycache__ python runtime` finds no difference. The only files
  left out are the upstream bytecode caches, listed with their SHA-256 in
  `sources.runtime.omitted_bytecode` (3 files on Linux and macOS arm64, 568 on
  Windows, none on macOS x86_64). They are stale: each records a source
  modification time that differs from the one in the asset, so Python never
  used them, and any run of the bundled Python without `-B` would overwrite
  them.
- *Program:* every file in `app/` is listed with `origin: repo:<path>`. Compare
  these files with the same commit of the source repository
  (`git_commit` in the manifest, when the build had one).
- *Boot files:* in a source checkout, `build/verify-dist.sh <package>/payload/dist`
  checks the signatures (shim signed by Microsoft, GRUB signed by the
  beast-booter key), the SBAT, and the certificate fingerprint that MokManager
  shows (see SECURE_BOOT.md).

## Run it

### Windows

1. Optional, but it avoids the warnings below: before you unpack, right-click
   the `.zip` > **Properties** > tick **Unblock** > **OK** (or run
   `Unblock-File .\beast-booter-<version>-windows-x86_64.zip` in PowerShell).
2. Unpack the archive (right-click > **Extract All...**) to any folder, for
   example your Desktop or a USB stick. The path may contain spaces.
3. Double-click **`BeastBooter.cmd`**. A console window flashes up and closes,
   and the BeastBooter window opens.

Command line: open a terminal in the folder and run `beast-booter.cmd --help`
or `beast-booter.cmd install --device \\.\PhysicalDrive2`. To write to a device,
start the terminal with **Run as administrator**.

**SmartScreen.** The package is not code signed. If you did not unblock the
zip, Windows may show *"Windows protected your PC"* or an *"Open File -
Security Warning"*. Check the download first (above), then choose
**More info** > **Run anyway** (or **Run**).

### macOS

1. Double-click the `.zip` to unpack it (Archive Utility keeps the symlinks and
   permissions the runtime needs). If you unpack it from the command line, use
   `ditto -x -k <file>.zip <folder>` or `unzip`, not a tool that drops symlinks.
2. Double-click **BeastBooter** (`BeastBooter.app`).

Command line: `./beast-booter.command --help`,
`sudo ./beast-booter.command install --device /dev/disk4`. Double-clicking
`beast-booter.command` opens Terminal and shows the help.

**Gatekeeper.** The app is not signed or notarized by Apple, so the first
double-click is refused ("cannot be opened because Apple cannot check it for
malicious software", or "Apple could not verify ..."). Check the download
first (above), then:

- **macOS 14 and older:** right-click (Control-click) **BeastBooter** >
  **Open**, then **Open** in the dialog. macOS remembers the choice.
- **macOS 15 and newer:** try to open the app once, then go to **System
  Settings** > **Privacy & Security**, click **Open Anyway** next to the message
  about BeastBooter, and confirm.
- **Or, for the whole folder**, remove the quarantine flag that the browser
  set on the download:

  ```sh
  xattr -dr com.apple.quarantine ~/Downloads/beast-booter-0.1.0-macos-arm64
  ```

While an app is quarantined, macOS may run it from a hidden, read-only copy
("App Translocation"). beast-booter still works then, because it never writes
into its own folder.

### Linux

```sh
tar xzf beast-booter-0.1.0-linux-x86_64.tar.gz
cd beast-booter-0.1.0-linux-x86_64
./BeastBooter                  # the GUI
./beast-booter --help          # the CLI
sudo ./beast-booter install --device /dev/sdX
```

`beast-booter.desktop` starts the GUI from a file manager. In GNOME Files,
right-click it and choose **Allow Launching** first. It finds `BeastBooter`
next to itself, so it only works inside the package folder. For a menu entry,
copy it to `~/.local/share/applications/` and set `Exec=` to the absolute path
of `BeastBooter`.

## Administrator prompts: when and why

The window always runs **as you**, without administrator rights. It can list
drives, read the boot files and show what it is going to do. Only one step needs
more rights: **writing to the USB drive**. Every OS reserves raw access to a
whole disk (`/dev/sdX`, `\\.\PhysicalDriveN`, `/dev/rdiskN`) for administrators,
because that access bypasses all file permissions. For that step, the GUI starts
the bundled command line program with administrator rights and follows its
progress:

| OS | What you see | What runs elevated |
|---|---|---|
| Windows | UAC: *"Do you want to allow this app to make changes to your device?"* (the program shown is the bundled `pythonw.exe`, the GUI's own interpreter; unknown publisher because it is unsigned) | `runtime\pythonw.exe -s -E app\beast_booter_launch.py install --device ... --progress-file ...` (no console window: the GUI follows the progress file) |
| macOS | a password dialog asking for an administrator's name and password (shown through `osascript ... with administrator privileges`) | the bundled `runtime/bin/python3 ... install --device ...` |
| Linux | polkit password dialog (`pkexec`), or a `sudo` prompt in a terminal | the bundled `runtime/bin/python3 ... install --device ...` |

Elevation resets the environment on every OS, so the GUI passes the boot files
to the elevated program explicitly (`--dist`) and does not rely on
`BEAST_BOOTER_DIST`. Writing a disk **image file** (`--image`) never needs
administrator rights. On
the command line you choose: use `sudo` (or an administrator terminal on Windows)
only for `--device`.

## What is inside a package

```
beast-booter-<v>-windows-x86_64/           beast-booter-<v>-linux-x86_64/
  BeastBooter.cmd     GUI (pythonw.exe)      BeastBooter            GUI (sh)
  beast-booter.cmd    CLI (python.exe)       beast-booter           CLI (sh)
  runtime\            CPython, unmodified    beast-booter.desktop   file-manager launcher
  app\                beastbooter\*.py,      runtime/               CPython, unmodified
                      beast_booter_launch.py app/                   beastbooter/*.py, beast_booter_launch.py
  payload\dist\       boot files + manifest  payload/dist/          boot files + manifest.json
  payload\sbom\       SBOM (if built)        payload/sbom/          SBOM (if built)
  docs\               SECURE_BOOT.md,        docs/                  SECURE_BOOT.md, PORTABLE.md
                      PORTABLE.md
  VERSION, README.txt, LICENSE,              VERSION, README.txt, LICENSE,
  verify-package.py, PACKAGE-MANIFEST.json   verify-package.py, PACKAGE-MANIFEST.json

beast-booter-<v>-macos-arm64/  (and -macos-x86_64)
  BeastBooter.app/Contents/
    Info.plist                 bundle id, version, minimum macOS, architecture
    MacOS/BeastBooter          GUI (sh)
    Resources/runtime/         CPython, unmodified (bin/ uses symlinks)
    Resources/app/             beastbooter/*.py, beast_booter_launch.py
    Resources/payload/dist/    boot files + manifest.json
    Resources/payload/sbom/    SBOM (if built)
    Resources/docs/            SECURE_BOOT.md, PORTABLE.md
    Resources/VERSION
  beast-booter.command         CLI (sh)
  README.txt, LICENSE, verify-package.py, PACKAGE-MANIFEST.json
```

**Launchers.** Each launcher finds its own folder, so the package works from
any path, including paths with spaces and paths reached through a symlink. It
uses no absolute paths and no system Python. It then runs:

```
<runtime python> -s -E -B -S <app>/beast_booter_launch.py [--gui] <your arguments>
```

with `BEAST_BOOTER_DIST=<package>/payload/dist`. `-s` ignores per-user
site-packages, `-E` ignores `PYTHONPATH`, `PYTHONHOME` and the other `PYTHON*`
variables, `-B` writes no `.pyc` files, so the folder stays exactly as listed
in the manifest, and `-S` skips the `site` module, so nothing in
`site-packages` (and no `.pth` file there) is loaded: only the standard library
and `app/` are importable. `beast_booter_launch.py` puts its own folder on
`sys.path`, so it does not need `site`. The launchers also clear `TCL_LIBRARY`
and `TK_LIBRARY`, so the bundled Tcl/Tk is used. `--dist DIR` on the command line
still takes precedence. `beastbooter/__init__.py` reads the version from the
`VERSION` file two folders above it, which is why `VERSION` sits next to `app/`.

**`PACKAGE-MANIFEST.json`** (schema 1) contains:

- `name`, `version`, `target`, `top` (the folder name), `source_date_epoch`,
  `git_commit` and `test_only`;
- `layout`, the paths of the GUI and CLI launchers, the runtime, the app,
  the boot files and the docs;
- `sources.runtime`, the python-build-standalone release, asset, URL and
  SHA-256, and `omitted_bytecode`: each upstream `__pycache__/*.pyc` that was
  left out, with its SHA-256;
- `sources.dist`, the version, build id, SHA-256 of `manifest.json` and the
  Secure Boot certificate fingerprint of the boot files;
- `sources.sbom`, whether the SBOM is included and which `manifest.json` it
  describes;
- `files`, one entry per file: `sha256`, `size`, `mode` and `origin`. Symlinks
  have `symlink` (the target) instead of a hash. The kinds of origin are:
  - `runtime:<path>`: the file at that path in the runtime asset;
  - `repo:<path>`: the file at that path in the source tree, unmodified;
  - `dist:<path>`: a boot file, with `dist_origin` copied from `dist/manifest.json`
    (for example `deb:shim-signed=...:/usr/lib/shim/shimx64.efi.signed.latest`);
  - `generated:<template>`: `README.txt` and `Info.plist`, rendered from the
    template named in the origin.

  The manifest does not list itself.

## Building the packages yourself

You need a working build environment (`make dev`, see
[DEVELOPMENT.md](DEVELOPMENT.md)), Python 3.10 or newer, and network access
once, to download the four pinned runtimes (about 175 MB in total). The
runtimes are cached in `.tools/cache/pbs/`.

The usual way is `make portable`, which runs `scripts/build_portable.sh`:

```sh
make portable                    # this machine's target, e.g. linux-x86_64
make portable ARGS=--all         # linux-x86_64, windows-x86_64, macos-x86_64, macos-arm64
scripts/build_portable.sh --target windows-x86_64 --target macos-arm64
ls out/portable/
#   beast-booter-0.1.0-linux-x86_64.tar.gz   beast-booter-0.1.0-macos-arm64.zip
#   beast-booter-0.1.0-macos-x86_64.zip      beast-booter-0.1.0-windows-x86_64.zip
#   SHA256SUMS
```

It refreshes the boot files (`make build`), regenerates the SBOM so that it
matches `dist/` (`make sbom`), runs `packaging/portable/build.py`, verifies
every archive against its `PACKAGE-MANIFEST.json` and prints the results.
Options: `--all`, `--target T` (repeatable), `--skip-build` (package the
existing `dist/`), `--keep-sbom` (don't regenerate the SBOM; it must already
match `dist/`), `--no-sbom` (leave it out), `--offline` (cached runtimes
only), `--out DIR` (default `out/portable`). `make release` builds the
packages the same way, together with the other release files
([RELEASING.md](RELEASING.md)).

`build.py` can also be run directly, on an existing `dist/`:

```sh
make build                                     # boot files -> dist/
python3 -I packaging/portable/build.py --all   # -> out/portable/
```

Its options: `--target T` (repeatable) instead of `--all`; `--dist DIR`,
`--sbom DIR`, `--no-sbom`, `--out DIR`, `--cache DIR` (or `$BB_PBS_CACHE`);
`--offline` (never download); `--fetch-only` (only download and verify the
runtimes); `--verify ARCHIVE...` (check built archives); and
`--allow-test-dist` (accept the fake `dist/` from `installer/tests/fakedist.py`
for packaging tests only: the packages are then marked `test_only` and their
README says that they do not boot).

What `build.py` checks before it writes anything:

- each runtime archive matches its pinned SHA-256 every time it is used, not
  only when it is downloaded. Downloads go to a temporary file and are renamed
  into the cache only after the hash matches;
- `dist/` matches its `manifest.json`: every listed file is present with the
  right SHA-256, no file is unlisted, and there are no symlinks. The installer's
  own verifier (`beastbooter.dist.load_dist`) must also accept it;
- `sbom/` is included only if it describes exactly this `dist/` (its
  `beast-booter:manifest-sha256` equals the SHA-256 of `dist/manifest.json`).
  Otherwise the build stops; pass `--no-sbom` to build without it;
- runtime members stay inside the runtime folder (no absolute paths and no `..`,
  and symlinks only on Linux and macOS);
- the runtime's bytecode caches are left out and recorded, and bytecode without
  its `.py` source next to it stops the build: the package runs only source
  code;
- after writing, every archive is re-read and checked with `verify_package.py`.

**Reproducible output.** Entries are sorted. Every timestamp (tar, zip and
gzip header) is `SOURCE_DATE_EPOCH`, which defaults to the last git commit
time, else to the mtime of `VERSION`. Owners are 0/0, and permissions are
normalised to 0644/0755 (0644 throughout the Windows package). Building twice
from the same inputs gives byte-identical archives:

```sh
python3 -I packaging/portable/build.py --all
cp out/portable/SHA256SUMS /tmp/first
python3 -I packaging/portable/build.py --all --out /tmp/again
diff /tmp/first /tmp/again/SHA256SUMS && echo reproducible
```

The bytes of the compressed data depend on the zlib that Python uses, so a
different Python or zlib build can produce different archives. The content
stays the same, and so do the hashes in `PACKAGE-MANIFEST.json`.

**Updating the runtime.** Edit `packaging/portable/runtimes.lock`: the
`release`, `python` and, for all four targets, `asset`, `url` and `sha256`,
taken from the release's `SHA256SUMS`. Then rebuild. `build.py` refuses an
asset whose name does not match its URL, or whose hash does not match.

**CI.** `.github/workflows/ci.yml` (with the reusable `portable-test.yml`; releases: `release.yml`, see [RELEASING.md](RELEASING.md)) builds the packages on Ubuntu (twice,
to check reproducibility). Each package is then unpacked on its own OS
(`ubuntu-latest`, `windows-latest`, `macos-latest` for arm64, `macos-15-intel`
for x86_64), the same way a user would do it (tar, Explorer's
`Expand-Archive`, Finder's `ditto`), into a folder with spaces in its path. The
workflow then:

- checks `SHA256SUMS` and `verify-package.py` (with the bundled runtime and
  `-I -S -B`);
- runs `--version`, `--help` and the GUI `--selftest` (under `xvfb-run` on
  Linux) through the real launchers (`packaging/portable/ci/smoke.py`). On
  Windows the GUI self-test runs with `python.exe` and `pythonw.exe` directly,
  because `BeastBooter.cmd` returns at once and cannot report the GUI's exit
  code. A separate step double-clicks the way Explorer does: it checks that
  `BeastBooter.cmd` returns at once (so no console window stays open) and that
  the package's `pythonw.exe` is then running the GUI;
- runs the platform-independent unit tests (`installer/tests/test_x_*.py`)
  against the packaged sources with the bundled runtime, including the real Tk
  window tests (`test_x_gui_window.py`: on Linux under Xvfb, through
  `BB_GUI_TEST_DISPLAY`);
- makes an image with `install --image` and reads it with `info --json`;
- on Windows and macOS, installs to a throwaway virtual disk (a diskpart VHDX
  or an `hdiutil` RAM disk);
- finally runs `verify-package.py` again, to show that running the package
  changed nothing in its folder.

Pushes and pull requests package the fake `dist/`. A manual run can build the
real boot files in `build/Containerfile`, signed with a throwaway key.

## Known limitations

- **Unsigned binaries.** Neither the packages nor the bundled runtime are code
  signed, so you get the SmartScreen and Gatekeeper prompts described above.
  Signing for Windows (Authenticode) and signing plus notarization for macOS
  need a code-signing certificate and an Apple Developer account. That is
  future work. The checks in "Check the download first" are the substitute.
- **No NTFS on macOS.** macOS cannot create NTFS, so the installer refuses
  `--fs ntfs` there. Use exFAT (the default) or FAT32. GRUB cannot read NTFS
  with Secure Boot enabled anyway.
- **macOS app details.** The app's main program is a shell script, so the Dock
  shows the Python icon and name while it runs. On Apple silicon, use the arm64
  package: the x86_64 one needs Rosetta.
- **The `.desktop` file** only works inside the package folder (desktop entries
  cannot use relative paths).
- **Size.** The python-build-standalone `install_only` builds are kept
  unmodified, so that anyone can compare them with the official asset. The
  Linux build includes debug symbols (about 80 MB packed) and the Windows build
  includes `.pdb` files (about 52 MB packed).
- **x86_64 and arm64 only.** There are no 32-bit packages and no Windows on Arm
  or Linux arm64 packages yet.
