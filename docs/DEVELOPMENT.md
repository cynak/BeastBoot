# Developing BeastBoot

This is the developer guide: how to set up a working environment, the
edit-build-boot loops (boot menu, installer, beast-net helper, desktop app),
the tests, every `bb-dev` helper, debugging (from the serial console to gdb
inside GRUB), VS Code, the dev container, lint, SBOM and release dry runs.
How to send a change: [CONTRIBUTING.md](../CONTRIBUTING.md).

What the pieces are and how they fit together is in
[ARCHITECTURE.md](ARCHITECTURE.md); read sections 2 (boot flows), 4 (`dist/`),
5 (GRUB runtime contract) and 7 (installer CLI) first. The menu and its
settings are in [MENU.md](MENU.md), Secure Boot in [SECURE_BOOT.md](SECURE_BOOT.md),
ISO recipes in [ISO_SUPPORT.md](ISO_SUPPORT.md), the network helper in
[BEASTNET.md](BEASTNET.md).

Contents:

1. [Prerequisites](#1-prerequisites)
2. [One-command setup](#2-one-command-setup)
3. [Repository map](#3-repository-map)
4. [The development loops](#4-the-development-loops)
5. [Running tests](#5-running-tests)
6. [bb-dev reference](#6-bb-dev-reference)
7. [Debugging recipes](#7-debugging-recipes)
8. [VS Code](#8-vs-code)
9. [Dev container](#9-dev-container)
10. [Lint, SBOM and releases](#10-lint-sbom-and-releases)
11. [Ground rules](#11-ground-rules)

## 1. Prerequisites

- **Linux on x86_64.** Development happens on Ubuntu 26.04; any recent
  Debian/Ubuntu works the same. Other distributions work for the installer
  and the tests as long as the tools below are available.
- **Python 3.10 or later** (`python3`). The installer and `bb-dev` use the
  standard library only. The dev virtualenv needs `python3 -m venv`
  (Debian/Ubuntu: `python3-venv`; without it `bb-dev setup` bootstraps a
  pinned, hash-checked pip wheel).
- **bash, make, git, coreutils, util-linux** (`sfdisk`, `blkid`), **openssl**.
- **KVM** (strongly recommended): `/dev/kvm` must be readable and writable by
  you (membership in the `kvm` group, or the desktop session's ACL). Without
  KVM everything still works under TCG, about 4 to 10 times slower.
- **Disk space:** about 15 GB. The rootless toolchain in `.tools/` is the
  big part (QEMU, firmware, GRUB, the beast-net package cache, plus ShellCheck
  and the SBOM scanners if you install them); dev images are sparse 4 GiB files.
- **Optional:** `udisksctl` usable by your user (a normal desktop session
  has it), needed for exFAT and NTFS images and their tests; `gdb` for
  debugging GRUB; a Python with tkinter and `xvfb-run` (package `xvfb`) for
  the desktop app (see [4.5](#45-desktop-app-loop)); VS Code; docker or podman
  for the dev container.

**No root is needed.** Everything that is missing is fetched by
`scripts/bootstrap-tools.sh` with `apt-get download` and unpacked into
`.tools/root` with `dpkg-deb -x` (no maintainer scripts run); small wrappers
in `.tools/bin` set the library path for those tools only. If you prefer a
system-wide install, the header of `scripts/bootstrap-tools.sh` has the
`sudo apt install ...` line with the same packages.

## 2. One-command setup

```sh
make dev                     # = bin/bb-dev setup --yes
# or, interactively (asks before downloading):
scripts/dev-setup.sh         # = exec bin/bb-dev setup "$@"
```

`bb-dev setup` runs these steps and skips every step that is already done,
so a second run is a quick check:

1. **doctor**: what is missing, and which of it needs the system (sudo);
2. **toolchain**: `scripts/bootstrap-tools.sh`, if a tool is missing
   (rootless, into `.tools/`, including the GRUB debug symbols);
3. **venv**: `.venv/` from `requirements-dev.txt` (pytest, coverage,
   debugpy, ruff and their dependencies, every file pinned by SHA-256 and
   installed with `pip --require-hashes`; on hosts without `ensurepip` the
   pinned pip wheel is downloaded and checked first);
4. **keys**: `make keys`, if `keys/` holds no signing key yet;
5. **build**: `make build`, if `dist/` is missing or older than `grub/` or `build/`;
6. **unit tests**: `pytest -q installer/tests`, when something changed;
7. **dev image**: `bb-dev image --fixtures --debug`, if the image is missing.

It ends with a checklist of what is ready and what to do next.

| Option | Effect |
|---|---|
| `--minimal` | steps 1 to 5 only (keys only because the build needs them) |
| `--no-venv` | do not create `.venv/` |
| `--no-image` | do not build the dev image |
| `--yes`, `-y` | do not ask before downloading |

Afterwards, and whenever something behaves oddly, run the doctor:

```sh
bin/bb-dev doctor            # or: make doctor
```

### The environment

`make` targets and `bb-dev` load the environment themselves (they source
`scripts/dev-env.sh`). For an interactive shell, source it yourself:

```sh
source scripts/dev-env.sh    # bash or zsh; safe to source more than once
```

It puts `.tools/bin` first on `PATH`, adds `installer/` to `PYTHONPATH`, and
exports `BB_ROOT`, `BB_GRUB_EFI_DIR`, `BB_GRUB_EFI_SIGNED_DIR`,
`BB_GRUB_BIOS_DIR`, `BB_SHIM_DIR`, `BB_OVMF_DIR` and `BB_SEABIOS_DIR`. Each
`BB_*_DIR` prefers the system location (for example `/usr/share/OVMF`) and
falls back to `.tools/root/...`; the GRUB module directories prefer the last
GRUB source build (`.tools/cache/grub-src/current/`). A value you set before
sourcing wins, which is how you point the VMs and tests at other firmware or
GRUB files. The build itself always uses GRUB built from source
(`build/grub/grubsrc.py`, see docs/SECURE_BOOT.md).

GRUB builder (`BB_GRUB_BUILDER`): `native` uses the host's compiler; if the
host lacks bison, flex, autopoint or gawk, it unpacks the locked Ubuntu 26.04
`.deb`s into the cache and uses them only if their `--version` runs (they
need glibc 2.38 or newer). `docker` builds in the pinned Ubuntu 26.04 image
and links `grub-mkimage` statically, because the host runs it. `auto`, the
default, builds natively and falls back to docker when a tool is missing or
does not run. Either way, the build fails if `bin/grub-mkimage --version`
does not run on the host. With `BB_OFFLINE=1`, the GRUB build downloads
nothing. It needs the sources and `.deb`s in `.tools/cache/grub-src/dl/`,
and the docker builder is refused because it needs the network.

wimboot (`build/wimboot/wimbootsrc.py`, the Windows PE loader on the ESP)
works the same way, in seconds: `BB_WIMBOOT_BUILDER` (`auto`, `native` with
the host's gcc/binutils/make, or `docker` in GRUB's pinned image), cache
`.tools/cache/wimboot/` (`BB_WIMBOOT_CACHE`), `BB_OFFLINE=1` honoured.
`BB_SKIP_WIMBOOT=1` builds without it. See
[build/wimboot/README.md](../build/wimboot/README.md) for the patches and why
one binary serves BIOS and UEFI.

`.venv/` is used by VS Code (interpreter, debugger, Test Explorer, ruff).
Activate it in a shell with `source .venv/bin/activate` if you want its
`pytest`/`ruff` on your `PATH`; `make` does not need it.

## 3. Repository map

| Path | What it is |
|---|---|
| `installer/beastbooter/` | the installer package (`bin/beast-boot`, `python3 -m beastbooter`). `layout.py` is the numeric layout contract. |
| `installer/beastbooter/gui/`, `installer/beast_booter_launch.py` | the graphical front end and the self-contained CLI/GUI entry point |
| `installer/tests/` | installer unit tests (pytest; image files in temporary directories) |
| `grub/` | the menu: `grub.cfg` and `beast/*.cfg` (GRUB script) -> `dist/esp/grub/` |
| `build/` | `build.sh` (writes `dist/`), `keygen.sh`, `verify-dist.sh`, module lists, SBAT template, `early-bios.cfg`, the release `Containerfile` |
| `build/theme/` | `mktheme.py` (draws the graphical menu's theme images) and `mkmemdisk.py` (the font memdisk inside `grubx64.efi`) |
| `build/wimboot/` | builds iPXE's wimboot (`dist/esp/beast-booter/wimboot`) from its pinned release source plus our patches; see [build/wimboot/README.md](../build/wimboot/README.md) |
| `build/winpe/` | the Windows PE start-up files the menu injects with wimboot (`dist/esp/beast-booter/winpe/`): `winpeshl.ini`, `beastboot.cmd`, and `beastmount.exe`, built from `beastmount.c` by `beastmountsrc.py` with the pinned MinGW-w64 .debs of `mingw-w64.lock.json` (reproducible: compiled twice and compared; `BB_BEASTMOUNT_BUILDER`, `BB_BEASTMOUNT_CACHE`) |
| `build/beastnet/` | builds the beast-net helper (`dist/esp/beast-net/`): pinned Ubuntu packages, module list, initramfs, firmware catalog; see [build/beastnet/README.md](../build/beastnet/README.md) |
| `beastnet/` | the helper's own code: `python/beastnet/` (network, WiFi, download, hand-off, curses and plain UIs), `rootfs/` (`/init`, udhcpc script), `tests/` (unit tests) |
| `keys/` | your local Secure Boot signing key (`make keys`; private files are git-ignored) |
| `dist/` | build output (git-ignored): exactly what goes on a drive, plus `manifest.json` |
| `bin/` | `beast-boot` (installer) and `bb-dev` (developer helpers) |
| `devtools/bbdev/` | `bb-dev`: `cli.py`, `paths.py`, `qemu.py` (all QEMU flags), `commands/<command>.py` |
| `devtools/gdb/` | gdb scripts and the Python helper (`bbgrub.py`) used by `bb-dev gdb` |
| `devtools/tests/` | unit tests of `bb-dev` (fast, no QEMU) |
| `tests/e2e/` | QEMU end-to-end tests, harness (`bbe2e/`) and fixture ISO builder; see [tests/e2e/README.md](../tests/e2e/README.md) |
| `scripts/` | `bootstrap-tools.sh`, `dev-env.sh`, `dev-setup.sh`, `lint.sh` (`make lint`), `build_portable.sh` (`make portable`), `sbom-vuln.sh` and its helpers (`make sbom`, `make vulns`), `release/` (`make release`) |
| `docs/` | this guide and the other documentation |
| `sbom/`, `.claude/skills/sbom-vuln/` | VEX triage decisions (generated reports are git-ignored, see [sbom/README.md](../sbom/README.md)), and the skill that drives the scan |
| `.vscode/`, `.devcontainer/` | VS Code tasks, debug configurations and settings; the dev container |
| `requirements-dev.txt` | pinned, hashed Python dev tools for `.venv/` |
| `packaging/` | portable packages: `packaging/portable/build.py`, launchers, `runtimes.lock`, `verify_package.py`, CI smoke tests |
| `.github/workflows/` | CI: portable packages on every OS, and the release workflow (tag `vX.Y.Z`, see [RELEASING.md](RELEASING.md)) |

Generated, git-ignored:

| Path | What it holds |
|---|---|
| `.tools/` | rootless toolchain (`bin/` wrappers, `root/` unpacked packages, `debs/`) and other tools (ShellCheck, syft, grype, osv-scanner); `cache/` holds the beast-net `.deb`s, linux-firmware files and the portable runtimes. Never delete files you did not put there. |
| `.venv/` | Python dev virtualenv |
| `out/dev/` | dev images: `beast-boot-dev.img` by default |
| `out/vm/<image stem>/` | per-image VM state: `<mode>.vars`, `serial-<mode>.log`, `ovmf-debug.log`/`seabios-debug.log`, `monitor.sock`, `qmp.sock`, `qemu-<mode>.cmd` |
| `out/dev/vscode.env` | environment for VS Code's Test Explorer (written by a VS Code task, see section 8) |
| `out/e2e/` | e2e logs, cached fixture ISOs, base images, per-test work dirs |
| `out/portable/`, `out/release/` | `make portable` and `make release` output |

## 4. The development loops

### 4.1 Full loop: edit, build, image, boot

Use this after changing anything in `build/`, `installer/`, the module lists,
the SBAT template or the key, and before trusting a result:

```sh
make build                              # dist/ (signs GRUB with keys/beast-boot.key)
bin/bb-dev image --fixtures --debug     # out/dev/beast-boot-dev.img (make dev-image)
bin/bb-dev image --fixtures --debug --force   # ... again, replacing the existing image
bin/bb-dev vm                           # boot it: UEFI, USB stick, a window (make vm)
bin/bb-dev vm --mode bios               # the same image under SeaBIOS (make vm MODE=bios)
bin/bb-dev vm --mode sb-enrolled        # Secure Boot, key already enrolled (make vm-sb)
```

`bb-dev image` warns when `dist/` is missing or older than `grub/` or
`build/` and offers to run `make build`. It prints the data-partition offset
and what it put on the image. The fixture ISOs are the e2e test ISOs (dummy
kernels that exercise every boot recipe); with `--debug` the menu prints its
`BEAST:` lines, and with `--dryrun` it stops before handing over to the
ISO, which is what you want for most menu work. The fixtures land in
`/recipes/` on the data partition (`/recipes/casper.iso`, `/recipes/loopback.iso`,
...), the same paths the e2e tests use.

The image is built as `<out>.partial` and renamed only when complete, so a
failed build never leaves a half-written image, and a VM still running on
the old image keeps its file. The options it was built with go into a
recipe next to it, `out/dev/<name>.bbdev.json` (with the `dist/` build id
and the installer's layout version), so it can be rebuilt the same way.
On an existing image without `--force`, `bb-dev image` offers a refresh
instead of failing: nothing to do when the image is current,
`beast-boot update` (boot files only, data partition kept) when only the
build differs, a rebuild with the given options when its layout is older.
`--yes` answers that question; `--force` always replaces the image.

**The VM always boots the current bootloader.** Before booting,
`bb-dev vm` compares the image with `dist/` and the installer (the ESP's
`bb_build_id` in `/grub/beast/version.cfg`, the layout version in its
marker):

| The image | What `bb-dev vm` does |
|---|---|
| same layout and build id as `dist/` | boots it |
| another build id, same layout | runs `bin/beast-boot update --image IMG --yes` and says so; the ISOs and `config.cfg` on the data partition stay |
| an older layout (layout 1: 64 MiB FAT16 ESP, no beast-net) | `update` cannot move partitions, so it asks, then rebuilds it from its recipe (`bb-dev image --force` with the same options, fixtures and ISOs copied again); `--yes` skips the question. An image without a recipe gets the setup defaults (`--fixtures --debug`), and it says so |
| any of these with `--snapshot` | changes nothing, warns that it boots the old bootloader |
| `dist/` older than `grub/` or `build/` | warns and suggests `make build`; `--build` runs it first |

`--refresh never` only warns; `--refresh always` runs `update` even on a
current image (it drops `menu-sync` edits). An image a VM runs on, or one
attached or mounted on the host, is never changed: you get the command that
releases it. `bb-dev doctor` and `bb-dev setup` report whether the default
dev image is current.

Your own ISOs:

```sh
bin/bb-dev image --isos ~/isos --force                  # copy ~/isos (folders kept) into a new image
bin/bb-dev image --out out/dev/gpt.img --layout gpt --fs fat32 --fixtures --dryrun
bin/bb-dev image --fixtures --debug --autoboot /recipes/casper.iso --force   # boot one ISO straight away
bin/bb-dev image --fixtures --serial-console --force    # installer --serial-console (bb_serial=1 in device.cfg)
```

The data partition is exFAT by default when `udisksctl` works for you
(exFAT and NTFS are filled through a udisks loop device). Otherwise
`bb-dev image` falls back to FAT32 and says so; FAT32 cannot hold files of
4 GiB or more.

### 4.2 Fast menu loop: edit grub/, sync, reboot

For changes to the menu scripts (`grub/`), skip the build and reinstall:

```sh
bin/bb-dev menu-sync                # copy changed grub/ files into the image's ESP
bin/bb-dev menu-sync --watch        # keep syncing on every save (make menu-sync WATCH=1)
```

Then reboot the guest: `system_reset` on the QEMU monitor (see 7.1),
Ctrl+Alt+Del in the QEMU window, or quit and run `bin/bb-dev vm` again.

- It uses the same file selection as `build/build.sh` (no dotfiles, editor
  backups or `*.md`). The ESP's `/grub/` then mirrors `grub/`: changed files
  are rewritten, new ones added, menu files you deleted are removed. It
  never touches `version.cfg`, `device.cfg`, `grubenv` or what the build
  puts under `/grub/` from elsewhere (per `dist/manifest.json`: the theme
  from `build/theme`, the fonts, `i386-pc/`). `BB_MENU_DIR` overrides the
  source directory, as for `build.sh`.
- It refuses an image whose boot files are older than `dist/` (another
  build id, or an older layout), so menu edits are never tried on an old
  bootloader, and prints the fix: `bin/beast-boot update --image ...`, or
  the `bb-dev image --force ...` command from the image's recipe. Running
  `bin/bb-dev vm` once does the same.
- It writes the ESP with mtools at the offset `beast-boot info --json`
  reports, and prints what changed. `--watch` polls every second
  (`--interval`).
- It works in every mode, Secure Boot included: GRUB script files are not
  signature-checked (shim verifies GRUB itself and the kernels it starts),
  so nothing about verification changes.
- A synced image no longer matches `dist/manifest.json`. `make build`
  followed by `bb-dev vm` (a new build id triggers `update`), or
  `bb-dev vm --refresh always`, brings it back in line; do that before
  trusting an e2e run or a release.

### 4.3 Installer loop

```sh
make test                                           # installer unit tests (seconds)
bin/beast-boot install --image out/dev/try.img --size 2G --fs fat32 --yes
bin/beast-boot info --image out/dev/try.img --json
bin/beast-boot update --image out/dev/try.img --yes   # rewrite boot code + ESP from dist/
```

Drives use layout 2: partition 1 is the data partition (exFAT, FAT32 or
NTFS), partition 2 the 512 MiB FAT32 ESP at the end of the disk (plus a BIOS
boot partition with GPT); `layout.py` has the numbers. `update` refuses a
drive of an older layout (`reinstall-needed`).

`info --json` gives `data.start_lba`/`size_lba` and `esp.start_lba`/`size_lba`
in 512-byte sectors; multiply by 512 for byte offsets. To look inside the
ESP of an image with mtools:

```sh
source scripts/dev-env.sh
esp=$(bin/beast-boot info --image out/dev/try.img --json |
      python3 -c 'import json, sys; print(json.load(sys.stdin)["esp"]["start_lba"] * 512)')
MTOOLS_SKIP_CHECK=1 mdir -i "out/dev/try.img@@$esp" ::/grub/beast
MTOOLS_SKIP_CHECK=1 mtype -i "out/dev/try.img@@$esp" ::/grub/beast/device.cfg
```

To debug the installer in VS Code, see [section 8](#8-vs-code).

### 4.4 beast-net loop: the network helper

The helper ("Download an ISO from a link", [BEASTNET.md](BEASTNET.md)) has
two parts: the build in `build/beastnet/` (Ubuntu's signed kernel, pinned
packages, initramfs, firmware catalog) and the app in `beastnet/` (Python,
`/init`). `make build` runs `build/beastnet/build.sh` and puts the result in
`dist/esp/beast-net/`; `BB_SKIP_BEASTNET=1 make build` leaves it out (the menu
then hides the entry).

```sh
pytest -q beastnet/tests                     # app unit tests (seconds, no QEMU)
bash build/beastnet/build.sh out/bn          # helper only, into out/bn/beast-net/
python3 -I build/beastnet/test/qemu_test.py out/bn --app   # boot it directly in QEMU
make build && pytest -q tests/e2e -m beastnet              # through the real menu, BIOS/UEFI/SB
```

`qemu_test.py` boots the helper kernel with a test overlay and checks
modules, DHCP, TLS, WiFi (mac80211_hwsim), exFAT/FAT32 and firmware-pack
layering; `--app` also boots the real `/init`
([build/beastnet/README.md](../build/beastnet/README.md#test)). The first
build downloads the pinned `.deb`s into `.tools/cache/beastnet/`; after that
`BB_OFFLINE=1` enforces offline builds. Package versions live in
`build/beastnet/packages.in`; `packages.lock` is generated by
`build/beastnet/lock.py`, never edited.

To try the helper by hand, boot a dev image with a NIC (`bb-dev vm` starts
QEMU without one, `-nodefaults`) and choose **Download an ISO from a link**:

```sh
bin/bb-dev vm -- -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=
```

QEMU's user network gives the guest 10.0.2.15 and the host as 10.0.2.2.
For a non-interactive run, put a plan in a JSON file on the data partition
and point `bb_beastnet_script` at it (`bb-dev debug-config --set
bb_beastnet_script=/plan.json`; format in [BEASTNET.md §5](BEASTNET.md#5-the-helper-environment-initramfs)).
`bb-dev menu-sync` does not update `beast-net/`; run `make build`, and the
next `bb-dev vm` updates the image (or `bin/beast-boot update --image ...`).

### 4.5 Desktop app loop

The GUI is `installer/beastbooter/gui/` (Tkinter), started with
`python3 installer/beast_booter_launch.py --gui`. Useful flags: `--demo`
(simulated drives, nothing is written anywhere), `--theme dark|light`,
`--scale FACTOR`, `--dist DIR`, `--selftest` (draw the window once and exit).

Ubuntu's `python3` has no tkinter unless `python3-tk` is installed. Without
root, use the pinned python-build-standalone runtime that the portable
packages ship (cached in `.tools/cache/pbs/` by `make portable` or
`python3 -I packaging/portable/build.py --fetch-only`):

```sh
mkdir -p out/gui-runtime
tar -xzf .tools/cache/pbs/cpython-*-x86_64-unknown-linux-gnu-install_only.tar.gz -C out/gui-runtime
out/gui-runtime/python/bin/python3 installer/beast_booter_launch.py --gui --demo
```

That is the same interpreter the Linux package runs, so it is also the
closest check of what users get. To test the real package, `make portable`
and unpack `out/portable/beast-boot-<v>-linux-x86_64.tar.gz`.

The real Tk window tests (`installer/tests/test_x_gui_window.py`) only run
when `BB_GUI_TEST_DISPLAY` names an X display, so they never pop up windows
on your desktop. Run them headless under Xvfb, with a Python that has tkinter:

```sh
xvfb-run -a sh -c 'BB_GUI_TEST_DISPLAY=$DISPLAY exec .venv/bin/python -m pytest -q installer/tests/test_x_gui_window.py'
```

The other `installer/tests/test_x_gui_*.py` tests need no display.
Elevation (UAC, `osascript`, `pkexec`) is only exercised on a real desktop;
[PORTABLE.md](PORTABLE.md#administrator-prompts-when-and-why) describes it.

## 5. Running tests

| What | Command | Time |
|---|---|---|
| installer unit tests | `make test` | seconds |
| bb-dev unit tests | `pytest -q devtools/tests` | seconds |
| beast-net app unit tests | `pytest -q beastnet/tests` | seconds |
| e2e, everything | `make e2e` | about 3 minutes with KVM (89 tests; the live ones skip) |
| e2e, beast-net only | `pytest -q tests/e2e -m beastnet` | about 1.5 minutes with KVM |
| e2e, no VM boots | `source scripts/dev-env.sh && pytest -q tests/e2e -m "not slow"` | seconds |
| e2e, one firmware | `pytest -q tests/e2e -m "bios and not secureboot"` | |
| e2e, one file / test | `pytest -q tests/e2e/test_e2e_smoke.py -k uefi` | |
| harness self-test | `pytest -q tests/e2e -m selftest` (needs no `dist/`) | |
| official ISO links, quick (internet) | `make net-sources` | seconds |
| official ISO downloads in the QEMU lab (internet) | `make e2e-live` | minutes per ISO, several GB each |

`pytest` here means the one in `.venv/bin/` (or `python3-pytest`); for the
e2e tests source `scripts/dev-env.sh` first. E2E markers: `bios`, `uefi`,
`secureboot`, `exfat`, `ntfs`, `beastnet`, `live` (internet, opt-in), `selftest`, `slow` (boots QEMU). Useful variables: `BB_E2E_KVM=0|1`,
`BB_E2E_TIMEOUT_SCALE`, `BB_E2E_DISK_IF=usb|ide|virtio`, `BB_E2E_KEYS=serial|qmp`,
`BB_E2E_KEEP=1` (keep the per-test disk copies and vars). The full list,
the outputs (`out/e2e/logs/<test>.log`, `.qemu.txt`, `.screen.txt`, `.png`
on failure) and how the harness reads the menu are in
[tests/e2e/README.md](../tests/e2e/README.md).

Things to know:

- **Build first.** Everything except the self-test installs from `dist/`;
  run `make build` after changing `grub/` or `build/` (menu-sync does not
  update `dist/`).
- **Tests skip, they do not fail, when something is missing** (dist/,
  firmware, `virt-fw-vars`, `udisksctl`), and say what. `-rs` lists the reasons.
- **exFAT/NTFS tests** need udisks (system D-Bus + polkit). In a sandbox or
  container that blocks them, those tests skip.
- **Known flake:** some OVMF + KVM boots stall at `BdsDxe: starting`, more
  often with a serial input backend attached. `-cpu host` (which bb-dev
  and the harness use with KVM) and a retry help; if one test fails that
  way, re-run it before digging. The same can happen to `bb-dev vm`: quit
  and start it again.
- **Run the installer tests and the e2e tests as separate pytest runs**
  (as `make test` and `make e2e` do). The installer tests import helpers
  with `from conftest import ...`, and both directories have a `conftest.py`,
  so a single `pytest installer/tests tests/e2e` run can pick the wrong one.

## 6. bb-dev reference

`bin/bb-dev` runs `python3 -m bbdev` with `PYTHONPATH=devtools:installer`.
Every command sources `scripts/dev-env.sh` for its subprocesses, so you do
not need to. Results go to stdout and progress to stderr, so `--print-cmd`
and `--print` output can be piped. `bin/bb-dev <command> --help` shows the
options; this section is the overview.

| make target | runs |
|---|---|
| `make dev` | `bin/bb-dev setup --yes` |
| `make doctor` | `bin/bb-dev doctor` |
| `make dev-image` | `bin/bb-dev image --fixtures --debug` |
| `make vm [MODE=bios\|uefi\|sb\|sb-enrolled\|sb-fresh]` | `bin/bb-dev vm --mode $MODE` (default `uefi`) |
| `make vm-sb` | `bin/bb-dev vm --mode sb-enrolled` |
| `make menu-sync [WATCH=1]` | `bin/bb-dev menu-sync [--watch]` |

### `bb-dev setup [--minimal] [--no-venv] [--no-image] [--yes]`

One-shot, idempotent environment setup; see [section 2](#2-one-command-setup).

```sh
bin/bb-dev setup                  # asks before downloading
bin/bb-dev setup --yes --no-image # what the dev container runs after creation
bin/bb-dev setup --minimal        # tools, .venv, keys if missing, build
```

### `bb-dev doctor [--json]`

Checks the environment and prints `OK`, `WARN` or `FAIL` per check, each
WARN/FAIL with a one-line fix. Exit status 0 when nothing FAILed.

Checks: Python >= 3.10; GRUB EFI and BIOS module directories; the GRUB
source build (`build/grub/grubsrc.py`: every SBAT claim proven); Ubuntu's
signed GRUB (only the e2e stub images use its SBAT data); Debian's shim and
MokManager (`shimx64.efi.signed`, `mmx64.efi.signed`);
OVMF code and vars (including `OVMF_CODE_4M.secboot.fd` and
`OVMF_VARS_4M.ms.fd`); SeaBIOS; QEMU and its GTK display module; KVM access;
mtools; xorriso; sfdisk; `mkfs.fat`, `mkfs.exfat`, `mkfs.ntfs`; sbsign/sbverify;
openssl; virt-fw-vars; a usable `udisksctl`; gdb and the GRUB debug symbols;
`.venv`; the signing key (and how long its certificate is still valid);
`dist/` present and not older than `grub/` and `build/`; whether the
default dev image is current (the installer's layout version and the build
id of `dist/`), with the command that refreshes it; free disk space.

```sh
bin/bb-dev doctor
bin/bb-dev doctor --json | python3 -m json.tool
```

### `bb-dev image [options]`

Builds a drive image from `dist/` with the real installer, copies ISOs onto
the data partition and writes `/beast-booter/config.cfg`.

| Option | Default | Effect |
|---|---|---|
| `--out PATH` | `out/dev/beast-boot-dev.img` | image file |
| `--size SIZE` | `4G` | image size (`256M`, `8G`, bytes) |
| `--layout msdos\|gpt` | `msdos` | partition table |
| `--fs exfat\|fat32\|ntfs` | exFAT if udisks works, else FAT32 | data filesystem |
| `--isos DIR` | | copy this directory tree of ISOs (structure kept) |
| `--fixtures` | | add the e2e fixture ISOs under `/recipes/` (built and cached in `out/e2e/fixtures/`) |
| `--debug` | | `set bb_debug=1` in config.cfg |
| `--dryrun` | | `set bb_dryrun=1` |
| `--autoboot PATH` | | `set bb_autoboot="PATH"` |
| `--serial-console` | | installer `--serial-console` (`bb_serial=1` in device.cfg) |
| `--force` | | replace an existing image at `--out` |
| `--yes`, `-y` | | existing image without `--force`: refresh or rebuild it without asking |

It writes `out/dev/<name>.bbdev.json` next to the image: the options above,
the `dist/` build id and the layout version. `bb-dev vm` rebuilds the image
from it when the installer's layout has moved on.

### `bb-dev vm [options] [-- extra QEMU args]`

Boots an image in QEMU with the flags the e2e suite uses (KVM with
`kernel-irqchip=split`, `-nodefaults -device VGA`, the image as a USB stick).

| Option | Default | Effect |
|---|---|---|
| `--image PATH` | `out/dev/beast-boot-dev.img` | the drive |
| `--mode MODE` | `uefi` | firmware, see below |
| `--bus usb\|sata\|virtio\|nvme` | `usb` | how the drive is attached |
| `--display gtk\|sdl\|vnc\|none` | `gtk` if there is a desktop session and QEMU's GTK module works, else `sdl` if its SDL module works, else `none` | `gtk` and `sdl` open a window; `vnc` listens on 127.0.0.1:5900+N; an explicit `gtk` that cannot work falls back to `sdl`, then to `vnc`; an explicit `sdl` is used as given |
| `--serial stdio\|pty\|file` | `stdio` | serial port 0 on this terminal (Ctrl-A x quits QEMU, Ctrl-A h lists more), on a new pty, or only in the log; `serial-<mode>.log` is written in every case |
| `--snapshot` | | guest writes are thrown away; the image stays unchanged |
| `--gdb [PORT]` | port 1234 | QEMU gdb stub on 127.0.0.1 |
| `--wait-gdb` | | start paused until gdb continues (implies `--gdb`) |
| `--fw-debug` | | firmware debug port 0x402 -> `ovmf-debug.log` (`seabios-debug.log` in BIOS mode) |
| `--mem MB` | 2048 | guest memory |
| `--cdrom ISO` | | also attach an ISO as a CD-ROM |
| `--reset-vars` | | start this mode's firmware vars over |
| `--print-cmd` | | print the QEMU command line and exit (no freshness check) |
| `--refresh auto\|always\|never` | `auto` | bring the image's boot files up to date with `dist/` first: `update` for another build, a rebuild (after a question) for an older layout; `always` updates even a current image; `never` only warns. See [4.1](#41-full-loop-edit-build-image-boot) |
| `--build` | | run `make build` first when `dist/` is missing or older than `grub/` or `build/` (otherwise just a warning) |
| `--yes`, `-y` | | rebuild an image of an older layout without asking |

| Mode | Firmware | Vars |
|---|---|---|
| `bios` | SeaBIOS | none |
| `uefi` | OVMF, Secure Boot off | `out/vm/<stem>/uefi.vars`, kept between runs |
| `sb` | OVMF Secure Boot, Microsoft keys | `sb.vars`, created from the Microsoft-keys template on first run and kept, so a key you enroll by hand in MokManager stays enrolled |
| `sb-fresh` | same | brand-new Microsoft-keys vars on every run: never enrolled |
| `sb-enrolled` | same | rebuilt on every run: Microsoft keys plus `keys/beast-boot.cer` in MokList (`virt-fw-vars --add-mok`, exactly what MokManager enrollment stores). Warns when the image was signed with another key (`bb-dev image --force` rebuilds it) |

Everything for one image lives in `out/vm/<image stem>/`: `<mode>.vars`,
`serial-<mode>.log`, `ovmf-debug.log` / `seabios-debug.log`, `monitor.sock`
(human monitor), `qmp.sock` (QMP), `qemu.pid` while it runs and
`qemu-<mode>.cmd` (the last command line). When that path is too long for a
unix socket, the two sockets go to `$XDG_RUNTIME_DIR/bb-dev-<hash>/`
instead; the summary bb-dev prints at start shows where. Only one VM can
run per image at a time.

**SDL on GNOME.** On some GNOME desktops QEMU's GTK window cannot start
(GNOME 50 dropped an xsettings key that GTK 3 still reads, and GTK aborts).
bb-dev detects that and opens the window with SDL instead, also when you
asked for `--display gtk`; it says so when it starts. Pass `--display sdl`
to skip the check, or `--display vnc` if neither works.

Under `--mode bios` GRUB uses the serial port only when `bb_serial=1` is
set (`bb-dev debug-config --set bb_serial=1`); bb-dev warns when it is not.
Under UEFI, OVMF mirrors its console to serial anyway.

```sh
bin/bb-dev vm                                   # UEFI, in a window (GTK, else SDL)
bin/bb-dev vm --mode bios --display none        # menu on this terminal (needs bb_serial=1)
bin/bb-dev vm --mode sb-fresh --snapshot        # watch the MokManager flow, change nothing
bin/bb-dev vm --bus nvme --mem 4096
bin/bb-dev vm --cdrom ~/isos/ubuntu.iso -- -smp 4
bin/bb-dev vm --mode sb --print-cmd -- -d int   # just show the command (with extra QEMU args)
```

### `bb-dev menu-sync [--image PATH] [--watch] [--interval SECONDS]`

Copies `grub/` into the image's ESP (`/grub/`), see [4.2](#42-fast-menu-loop-edit-grub-sync-reboot).
`--watch` polls every `--interval` seconds and re-syncs on change. Refuses
an image with older boot files than `dist/`, with the command that fixes it.

### `bb-dev debug-config [--image PATH] [--show] [--set KEY=VALUE ...] [--unset KEY ...] [--clear] [--print]`

Edits `/beast-booter/config.cfg` on the image's data partition (FAT32 with
mtools, exFAT/NTFS through udisks).

| Key | Meaning |
|---|---|
| `bb_debug` | `1` = machine-readable `BEAST:` lines |
| `bb_dryrun` | `1` = stop before the hand-off, print what would run |
| `bb_autoboot` | ISO path on the data partition to boot without the menu |
| `bb_serial` | `1` = menu also on serial port 0, 115200 8N1 |
| `timeout` | GRUB menu timeout in seconds |
| `debug` | GRUB's own debug output, for example `linux,loader` (see 7.4) |
| `pager` | `1` = GRUB pauses after each screen of output |

```sh
bin/bb-dev debug-config                                  # show (same as --show)
bin/bb-dev debug-config --set bb_dryrun=1 timeout=5 --show
bin/bb-dev debug-config --unset bb_autoboot
bin/bb-dev debug-config --set debug=linux,loader pager=1
bin/bb-dev debug-config --clear                          # delete config.cfg
bin/bb-dev debug-config --clear --set bb_debug=1         # start over with just this
bin/bb-dev debug-config --set bb_debug=1 bb_serial=1 --print > config.cfg   # for a real stick, see 7.8
```

- `--set` and `--unset` take one or more items and can be repeated.
  Booleans accept `1/0`, `on/off`, `yes/no`; `timeout` must be a number.
  Other names are written as given (with a warning) and GRUB gets them
  unchanged.
- The menu reads config.cfg at boot: after a change, reboot the VM
  (monitor `system_reset`). bb-dev reminds you when a VM is running on the
  image.
- `--print` writes nothing: it prints the resulting file on stdout, for a
  **real USB stick** (you copy it to `/beast-booter/config.cfg` on the
  stick's data partition yourself; bb-dev never writes real devices). It
  starts from an empty file, or from the config.cfg of `--image` when you
  give one.

### `bb-dev gdb [--port 1234] [--platform pc|efi] [--image PATH] [--print-cmd]`

Starts gdb attached to GRUB running under `bb-dev vm --gdb`, with GRUB's
debug symbols (Ubuntu `grub-pc-dbg` / `grub-efi-amd64-dbg`, the versions
matching the shipped modules, fetched rootless into `.tools/`) and the
helpers in `devtools/gdb/` loaded so module symbols resolve. `--print-cmd`
shows the gdb command line. What works on `pc` and on `efi` is in
[7.5](#75-gdb-on-bios) and [7.6](#76-gdb-on-uefi-the-honest-story).

## 7. Debugging recipes

### 7.1 Serial console, logs and the QEMU monitor

Every boot writes the guest's serial output to
`out/vm/<image stem>/serial-<mode>.log` (also when serial is on stdio), for
the default image `out/vm/beast-boot-dev/serial-uefi.log`:

```sh
tail -F out/vm/beast-boot-dev/serial-uefi.log
grep -a 'BEAST:' out/vm/beast-boot-dev/serial-bios.log
```

- By default (`--serial stdio`) the terminal you started `bb-dev vm` in is
  serial port 0: you can drive the menu from it, Ctrl-A x quits QEMU.
  `--serial pty` gives a pty to attach `screen`/`picocom` to; `--serial file`
  only logs.
- OVMF mirrors its own console to the serial port, so under UEFI every menu
  line appears there even without `bb_serial` (turning `bb_serial=1` on as
  well can show characters twice). Under SeaBIOS you only see the menu on
  serial with `bb_serial=1`.
- The log contains GRUB's terminal escape codes; `grep -a` and `less -R`
  cope with that. Lines wrap at 80 columns unless `bb_debug=1` and
  `bb_serial=1` are both on (then GRUB is told the terminal is 1024 wide).
- The human monitor is a unix socket: `nc -U out/vm/beast-boot-dev/monitor.sock`
  (OpenBSD netcat) or `socat - UNIX-CONNECT:out/vm/beast-boot-dev/monitor.sock`,
  then for example `system_reset`, `sendkey ret`, `sendkey esc`,
  `screendump /tmp/screen.ppm`, `info status`, `quit`. Sending keys through
  the monitor is more reliable than typing into a serial console attached
  to OVMF. `qmp.sock` is the same for scripts (JSON).
- The e2e logs are in `out/e2e/logs/<test>.log` with the QEMU command line
  next to them (`<test>.qemu.txt`).

### 7.2 Firmware debug log

`bin/bb-dev vm --fw-debug` sends the firmware's debug port (I/O port 0x402,
`isa-debugcon`) to `out/vm/<stem>/ovmf-debug.log`, or `seabios-debug.log`
in BIOS mode. The file is recreated on every run.

- **SeaBIOS** (`--mode bios`) writes its log there (`seabios-debug.log`):
  version, detected drives, boot order, which device it boots. Useful when BIOS does not even
  reach GRUB.
- **Ubuntu's OVMF is a release build and writes nothing to that port**: the
  log stays empty (checked with OVMF 2025.11-3ubuntu7.3). Its few `BdsDxe:`
  messages ("starting Boot0001 ...", "failed to load ...") go to the serial
  log instead. For a full OVMF log you need a DEBUG build of OVMF (build
  edk2 yourself); point `BB_OVMF_DIR` at a directory with the same file
  names (`OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`, `.secboot.fd`, `.ms.fd`).
  Those builds are slower and very chatty.

### 7.3 The menu's own debug settings

Set them on the dev image with `bb-dev debug-config` (or when building the
image with `--debug`, `--dryrun`, `--autoboot`) and reboot the VM:

```sh
bin/bb-dev debug-config --set bb_debug=1          # BEAST: ready / dir / item / boot / error lines
bin/bb-dev debug-config --set bb_dryrun=1         # BEAST: dryrun linux/initrd/configfile/chainloader, back to the menu
bin/bb-dev debug-config --set bb_autoboot=/recipes/casper.iso   # boot that ISO without the menu
bin/bb-dev debug-config --set bb_serial=1         # menu on COM1 too, 115200 8N1
```

The `BEAST:` line format and the error codes are specified in
[ARCHITECTURE.md section 5](ARCHITECTURE.md#5-grub-runtime-contract) and
explained in [MENU.md](MENU.md#debug-output-bb_debug1). A dry run is the
fastest way to check a recipe: the `BEAST: dryrun linux ...` line shows the
exact kernel and command line the ISO would get.

`config.cfg` is read after the data partition was found. To get `bb_debug`
output when the data partition itself is the problem, the same settings can
go in `grub/beast/device.cfg` on the ESP (see MENU.md). bb-dev leaves
`device.cfg` to the installer: `bb-dev image --serial-console` puts
`bb_serial=1` there, and for anything else copy the file out and back with
`mtype`/`mcopy` at the ESP offset ([4.3](#43-installer-loop)) on a scratch
copy of the image.

### 7.4 GRUB's own debug output

GRUB prints internal debug messages for every "facility" listed in its
`debug` variable (the first argument of `grub_dprintf()` in GRUB's source):

```sh
bin/bb-dev debug-config --set debug=linux,loader pager=1
```

- `linux,loader`: kernel and initrd loading, the most useful pair when an
  ISO's kernel does not start. Others include `disk`, `partition`, `efi`
  (UEFI memory and loaders), `modules`, or `all`. The names are the first
  argument of `grub_dprintf()` calls; in a GRUB source tree,
  `grep -rhoE 'grub_dprintf \("[a-z_]+"' grub-core | sort | uniq -c` lists them.
- `all` is extremely verbose and makes GRUB visibly slow, especially over
  serial. Narrow it down.
- `pager=1` makes GRUB stop after every screen with `--MORE--`; leave it off
  when the output only needs to reach the serial log.
- Like the `bb_*` settings, this takes effect when config.cfg is sourced,
  so messages from before that point (finding the ESP and data partition)
  are not shown.

### 7.5 gdb on BIOS

This is where gdb works best: GRUB i386-pc's kernel runs at its link
address (0x9000), so its symbols need no relocation, and the helpers load
each module's symbols as GRUB loads it.

```sh
bin/bb-dev vm --mode bios --gdb --wait-gdb      # terminal 1: QEMU paused at reset, stub on 127.0.0.1:1234
bin/bb-dev gdb --platform pc                    # terminal 2: connects, runs to grub_main, stops there
```

In gdb (`bb-help` lists the helpers from `devtools/gdb/bbgrub.py`):

```gdb
(gdb) bb-break grub_cmd_linux        # safe breakpoint (a hardware one under KVM)
(gdb) continue                       # module symbols load as GRUB loads modules
(gdb) bb-modules                     # loaded modules, their .text address, symbols yes/no
(gdb) bt
```

- **Symbols are checked, not trusted.** They come from the GRUB source build
  (`kernel.exec` and `*.module` next to the modules dist/ ships, in
  `.tools/cache/grub-src/current/`); for module directories you point at an
  Ubuntu package instead, `make tools` fetches the matching `grub-pc-dbg`.
  `bb-dev gdb` compares their code with the modules and refuses to start on a
  mismatch. `bb-dev doctor` shows the state.
- **KVM allows hardware breakpoints only** in BIOS GRUB: 4 in total, one is
  used by the helpers. Use `bb-break` or `hbreak`, not `break`.
- **Backtraces:** `qemu-system-x86_64`'s gdb stub reports 64-bit registers
  even while GRUB runs 32-bit code, so frame #0, arguments and breakpoints
  are right but backtraces beyond frame #0 are garbage. `bb-dev gdb` warns
  about it; [devtools/gdb/README.md](../devtools/gdb/README.md) shows how
  to run the VM with `qemu-system-i386` for full backtraces.
- `bb-dev gdb` takes the platform and port from the last `bb-dev vm` run on
  `--image` (`out/vm/<stem>/qemu-<mode>.cmd`). More options:
  `--break FUNC` (repeatable), `--ex CMD`, `-x FILE`, `--batch` (run them
  and exit), `--port`, `--host`, `--print-cmd`.
- GRUB's own sources are not in this repository; gdb shows file names such
  as `../../../grub-core/kern/main.c` from the Ubuntu build. Point gdb at a
  `grub2` source tree (`apt-get source grub2`, the same version) with
  `set substitute-path` (or `sourceFileMap` in VS Code) to see source lines.

From VS Code: run the task **VM: wait for gdb** (mode `bios`), then start
**GRUB (BIOS): attach gdb to QEMU** (F5); see [section 8](#8-vs-code).

### 7.6 gdb on UEFI: the honest story

```sh
bin/bb-dev vm --gdb                    # UEFI (or --mode sb-enrolled); wait until the menu shows
bin/bb-dev gdb --platform efi          # finds GRUB in memory, loads kernel + module symbols
```

It works, with limits:

- The firmware (through shim) loads `grubx64.efi` at an address chosen at
  run time. The helpers find it through the firmware's
  `EFI_DEBUG_IMAGE_INFO_TABLE` (shim points its own loaded-image entry at
  GRUB) and load `kernel.exec` and the module symbols there. All modules
  are embedded in `grubx64.efi`, so they are all there from the start.
- **GRUB must already be running** for that: attach once the menu is on
  screen. If you attached earlier, `continue`, wait for the menu, press
  Ctrl+C and run `bb-efi-find`.
- The address found is cached in `out/vm/<stem>/gdb-efi.json`. Next time,
  with `bb-dev vm --gdb --wait-gdb`, `bb-dev gdb --platform efi` runs to
  GRUB's entry point at that address and stops there, so start-up code can
  be debugged too, as long as the firmware loads GRUB at the same place
  (same image, memory size and vars, as a rule).
- By hand: at a GRUB command line (`c` in the menu, if available) the
  `gdbinfo` command prints `dynamic_load_symbols ADDRESS`; in gdb run
  `bb-load-kernel ADDRESS`.
- Secure Boot modes (`sb`, `sb-enrolled`) are debugged the same way. The
  gdb stub is part of QEMU, outside the guest: nothing about verification
  changes, and nothing in the shipped boot chain is altered for debugging.
- What the helpers do and do not do, and why GRUB's own `gdb_grub` script
  is not used: [devtools/gdb/README.md](../devtools/gdb/README.md).

### 7.7 Testing Secure Boot

| Goal | Mode |
|---|---|
| see exactly what a user sees on first boot (shim's "Verification failed", MokManager, enroll from disk) | `sb-fresh`: brand-new Microsoft-keys vars every run, never enrolled |
| enroll the key by hand once and keep it, like a real machine | `sb`: vars persist in `out/vm/<stem>/sb.vars`; `--reset-vars` starts over |
| iterate fast on the menu with Secure Boot on | `sb-enrolled`: key pre-enrolled, straight to the menu |

The first-boot walkthrough (which screen, which key, what to choose) is
[SECURE_BOOT.md section 2](SECURE_BOOT.md#2-first-boot-with-secure-boot-on-enroll-the-key).
In QEMU MokManager is easiest to drive in the QEMU window (GTK or SDL); on a headless
VM send keys through the monitor (`sendkey down`, `sendkey ret`).

With Secure Boot on, the menu must show `sb=1` in `BEAST: ready`, NTFS data
partitions are invisible (GRUB lockdown disables the driver), and an ISO
whose kernel is not trusted fails with `BEAST: error sb-verify-failed`. Test
those cases; never "fix" them by turning verification off. Secure Boot
tests only ever change firmware variables (fresh, Microsoft keys, MOK
pre-enrolled), never the signed binaries or the verification in them.

### 7.8 Debugging on real hardware

1. Write a stick with the installer (`bin/beast-boot install --device /dev/sdX`;
   it refuses fixed disks and mounted devices and asks you to type the
   device name). bb-dev itself never touches real devices.
2. Make a debug config and copy it onto the stick's data partition, into
   the (hidden) `beast-boot` folder:

   ```sh
   bin/bb-dev debug-config --set bb_debug=1 bb_serial=1 pager=1 --print > config.cfg
   mkdir -p /media/$USER/BEASTBOOTER/beast-boot
   cp config.cfg /media/$USER/BEASTBOOTER/beast-booter/config.cfg
   ```

   Add `--set bb_dryrun=1` to see what an ISO would be booted with
   without booting it, or `--set debug=linux,loader` for GRUB's own messages.
3. Read the output: on screen (`pager=1` stops it scrolling away; a phone
   photo is a fine bug report), or on a serial console at 115200 8N1
   (`picocom -b 115200 /dev/ttyUSB0`, `screen /dev/ttyUSB0 115200`) when
   the machine has a serial port or header and `bb_serial=1` is set.
4. Delete `config.cfg` (or the lines) afterwards; it is your file, BeastBoot
   never writes the data partition.

Common failures:

| You see | Meaning | What to do |
|---|---|---|
| blue shim screen "Verification failed: (0x1A) Security Violation" | Secure Boot on, BeastBoot key not enrolled on this machine | enroll it, [SECURE_BOOT.md §2](SECURE_BOOT.md#2-first-boot-with-secure-boot-on-enroll-the-key) |
| shim "SBAT data failed: Security Policy Violation" | the machine's SBAT revocation level is newer than our GRUB | rebuild with a newer GRUB; the sbom-vuln skill checks SBAT |
| `grub rescue>` or "error: file '/grub/...' not found" | GRUB found no usable ESP / menu files (damaged ESP, or BIOS core.img could not find partition 2) | `beast-boot update --device /dev/sdX` |
| `BEAST: error no-data-partition`, menu empty | partition 1 not found or not readable; with Secure Boot on an NTFS data partition is invisible | check the partition table (`beast-boot info`); use exFAT/FAT32 |
| `BEAST: error iso-not-found` | `bb_autoboot` (or a menu path) points to a file that is not there | fix the path; it is relative to the data partition root |
| `BEAST: error loopback-failed` | GRUB could not open the ISO as a loop device | check the file (checksum); try copying it again |
| `BEAST: error no-recipe` | the ISO layout is not recognised | [ISO_SUPPORT.md](ISO_SUPPORT.md#recipes); report it with the `BEAST:` output |
| `BEAST: error windows-sb-no-helper` | Windows ISO with Secure Boot on, not prepared, and the beast-net helper is not on the drive | `beast-boot prepare-windows ISO` on the computer, or update the drive to get the helper (`windows-sb` was removed in 0.4.0) |
| `BEAST: windows-prepare <iso>` (record) | the menu offers "Prepare this Windows ISO for Secure Boot" | choose it; it runs the helper action `winboot` |
| helper error `winboot` (`errors.py` `WINBOOT`) | preparing the ISO was refused or failed (data partition NTFS, not enough space, `boot.wim` over 4 GiB on FAT32, not a Windows ISO) | read the helper screen; fix and retry. Spec: [WINDOWS_SECURE_BOOT.md](WINDOWS_SECURE_BOOT.md) |
| `BEAST: error grubenv-not-writable` | `save_env` to `($esp)/grub/grubenv` failed (Windows setup/pe mode) | the drive's grubenv is missing or damaged: `beast-boot update` recreates it |
| `BEAST: error sb-verify-failed` | shim refused the ISO's kernel (unsigned, or signed by a key this machine does not trust) | enroll that distribution's key via "Enroll a key (MokManager)", or turn Secure Boot off for that boot |
| `BEAST: error boot-failed` | GRUB's `linux`, `initrd`, `chainloader` or `boot` failed without Secure Boot | read the GRUB error just above; `debug=linux,loader` |
| kernel starts, then the live system cannot find its medium (casper "Unable to find a medium containing a live file system", dracut timeouts, "/dev/disk/by-uuid/... does not exist") | the ISO's initramfs cannot mount the data partition's filesystem | use a FAT32 data partition, see [ISO_SUPPORT.md](ISO_SUPPORT.md#the-data-partitions-filesystem) |
| the stick is not offered as a boot device (BIOS) | firmware without legacy/CSM, or an old BIOS that dislikes GPT | use UEFI, or install with `--layout msdos` |

## 8. VS Code

Open the repository folder, accept the recommended extensions
(`.vscode/extensions.json`: Python, Python Debugger, Ruff, ShellCheck,
C/C++ (for its gdb front end), Dev Containers), then:

1. Run the task **dev: setup (bb-dev setup)** (Terminal > Run Task...), or
   `make dev` in a terminal.
2. Pick `.venv/bin/python` as the interpreter if VS Code did not (it is the
   workspace default).
3. Run the task **dev: write out/dev/vscode.env (Test Explorer environment)**
   once. `python.envFile` points at that file, so tests run and debugged
   from the Testing view get `.tools/bin` on `PATH` and the `BB_*`
   variables. Without it, installer tests that need mtools are skipped.

### Tasks (`.vscode/tasks.json`)

All tasks run in bash from the repository root through `make`, `bin/bb-dev`
or with `scripts/dev-env.sh` sourced, exactly like the commands in this guide.

| Group | Tasks |
|---|---|
| build | **build: make build** (default build task, Ctrl+Shift+B), build: verify dist/, keys: make keys |
| tests | **test: installer unit tests (make test)** (default test task), test: devtools unit tests, test: all unit tests, test: pytest current file, e2e: full suite (make e2e), e2e: quick, no VM boots, e2e: smoke boots, e2e: by marker... |
| images and VMs | image: dev image (bb-dev image --fixtures --debug), image: ... --force, VM: bios / uefi / sb / sb-enrolled / sb-fresh, VM: headless, serial console in this terminal..., VM: pick mode, bus, display..., VM: wait for gdb, VM: print the QEMU command..., VM: follow the serial log..., VM: follow the firmware debug log... |
| menu | menu-sync: once, **menu-sync: watch (background)**, debug-config: show / set... / clear / print for a real USB stick |
| debugging | gdb: attach in a terminal (bb-dev gdb), gdb: prepare VS Code session (pc / efi) (pre-launch tasks of the GRUB debug configurations) |
| environment | dev: doctor, dev: setup, dev: setup, minimal, dev: write out/dev/vscode.env |
| lint | the **lint:** tasks: ShellCheck and ruff, the same checks as `make lint` ([CODE_QUALITY.md](CODE_QUALITY.md)) |
| SBOM | sbom: generate + vulnerability scan (sbom-vuln skill), sbom: regenerate SBOM only, sbom: offline re-scan |

Pytest, ShellCheck and ruff failures land in the Problems panel with file
and line (pytest: the line where the failing assertion or exception was
raised). The menu-sync watcher and the log followers are background tasks:
stop them with the trash icon of their terminal. VM tasks open their own
terminal; with a window (GTK or SDL) that terminal shows bb-dev's messages, with
`--display none` it is the serial console.

### Debug configurations (`.vscode/launch.json`)

| Configuration | What it debugs |
|---|---|
| Installer: info --json (dev image) | `python -m beastbooter info --image out/dev/beast-boot-dev.img --json` |
| Installer: install a scratch image... | `install --image out/dev/debug-install.img --size 2G` with a layout and filesystem you pick |
| Installer: custom arguments... | `python -m beastbooter` with arguments you type |
| bb-dev: doctor / image / vm --print-cmd / menu-sync / debug-config --show / custom arguments... | `python -m bbdev ...` with `PYTHONPATH=devtools:installer` |
| pytest: current file | `python -m pytest` on the open file |
| pytest: current file, selected test name | the same with `-k <selected text>` |
| Python: debug tests (Test Explorer) | used automatically when you debug a test from the Testing view |
| GRUB (BIOS): attach gdb to QEMU | CDT GDB (`eclipse-cdt.cdt-gdb-vscode`, open source) on the VM's stub (port 1234) with GRUB i386-pc symbols: the `bb-dev gdb` session (`devtools/gdb/pc.gdb`), prepared by a pre-launch task |
| GRUB (UEFI): attach gdb to QEMU | the same for x86_64-efi (`devtools/gdb/efi.gdb`, see 7.6) |

All Python configurations use `.venv/bin/python` and put `.tools/bin` on
`PATH`. bb-dev starts the installer and other helpers as subprocesses;
debugpy follows Python subprocesses, so breakpoints in `installer/` also
hit when you debug `bb-dev image`.

GRUB debugging step by step:

1. Run the task **VM: wait for gdb** and choose `bios`: QEMU starts paused
   with its gdb stub on port 1234.
2. Start **GRUB (BIOS): attach gdb to QEMU** (F5). Its pre-launch task runs
   `bb-dev gdb --platform pc --print-cmd`, which writes the session file
   `out/vm/beast-boot-dev/gdb-pc.gdb` (symbol directories, stub address,
   the helpers from `devtools/gdb/`) without starting gdb, and links the
   matching `kernel.exec` next to it as the configuration's `program`. The
   C/C++ debugger then starts gdb and sources that session file instead of
   doing its own `target remote`, so the session is exactly what
   `bb-dev gdb` gives you in a terminal.
3. The session stops in `grub_main`. Add breakpoints in the Debug Console:
   `-exec bb-break grub_cmd_linux` (under KVM only hardware breakpoints
   work, so prefer `bb-break` over clicking in the editor), then Continue
   (F5). Any gdb command works with the `-exec` prefix, for example
   `-exec bb-modules` or `-exec bb-help`.
4. Stop debugging, then quit QEMU (Ctrl-A x in the VM terminal, or `quit`
   on the monitor).

For UEFI use **GRUB (UEFI): attach gdb to QEMU** the same way, after the
VM (task **VM: wait for gdb**, mode `uefi`, or `bin/bb-dev vm --gdb`) has
reached the menu at least once (see 7.6). Both configurations work on the
default image `out/dev/beast-boot-dev.img`; for another image use
`bb-dev gdb --image PATH` in a terminal.

The gdb side of this (sourcing the session file over MI with async mode,
stop in `grub_main`, module symbols loading on continue, interrupt) was
checked against a running VM with gdb's MI interpreter; the VS Code UI
itself has not been exercised. The call stack beyond frame #0 is garbage
on BIOS for the reason given in 7.5, and the editor shows disassembly
unless you map GRUB's source paths (`sourceFileMap`) to a `grub2` source
tree.

### Test Explorer

The Testing view discovers `devtools/tests` and `installer/tests`. The e2e
suite is left out on purpose: it boots VMs for minutes, needs the full
environment, and must run in its own pytest session (see section 5). Run
and debug e2e tests with the e2e tasks and the **pytest: current file**
configurations instead.

### Editor settings (`.vscode/settings.json`)

- `grub/**/*.cfg` and `build/early-bios.cfg` are shown as shell script
  (GRUB script is shell-like), and ShellCheck is told to ignore them: its
  warnings make no sense for GRUB script.
- `.tools/`, `out/`, `dist/`, `.venv/` are excluded from search and from
  the file watcher (they hold gigabytes of images and toolchain).
- Ruff uses the pinned version from `.venv` when it is there. Nothing is
  formatted on save.

## 9. Dev container

`.devcontainer/` describes an Ubuntu 26.04 container with the same packages
the header of `scripts/bootstrap-tools.sh` lists for a system-wide install,
plus gdb, socat, python3-venv and the GRUB debug symbol packages.

**Status: written without access to a container runtime; not yet tested.**
Reports and fixes are welcome.

Use it from VS Code with "Dev Containers: Reopen in Container", or with the
devcontainer CLI (`devcontainer up --workspace-folder .`). On creation it
runs `bin/bb-dev setup --yes --no-image`.

- **Host:** Linux with KVM, docker or podman. The container gets
  `/dev/kvm` (`--device=/dev/kvm`) and the host's `kvm` group ID
  (`--group-add`). The default is 991, the ID on the development machine;
  set yours before opening the folder:
  `export BB_KVM_GID=$(getent group kvm | cut -d: -f3)`. With rootless
  podman use `export BB_KVM_GID=keep-groups`.
- **Same paths as the host.** The repository is mounted at its host path,
  not under `/workspaces`, because `.tools/bin` wrappers and `.venv`
  contain absolute paths. A checkout set up on the host therefore works
  unchanged in the container and the other way round (both are Ubuntu
  26.04).
- **User:** a non-root user `dev`; VS Code maps its UID/GID to yours so
  files in the checkout keep your ownership. There is no sudo: everything is
  rootless; to add packages, change the Dockerfile and rebuild. The apt
  package lists are kept in the image, because `scripts/bootstrap-tools.sh`
  and the GRUB debug-symbol fetch use `apt-get download`, which needs them;
  rebuild the container to refresh them.
- **No udisks in a container.** `bb-dev image` falls back to FAT32 data
  partitions (with a warning) and the exFAT/NTFS e2e tests skip.
- **No GTK or SDL window.** `bb-dev vm` uses `--display none` with the serial
  console in the terminal; or use `--display vnc` and connect a VNC viewer
  to the forwarded port 5900 (+N).

## 10. Lint, SBOM and releases

- **Lint:** `make lint` runs `scripts/lint.sh`: ruff for Python and
  ShellCheck for shell scripts, with the pinned versions; it must pass
  before a change goes in. Configuration, how to run one tool or one file,
  and how to silence a warning properly: [CODE_QUALITY.md](CODE_QUALITY.md).
  While you type: the Ruff and ShellCheck extensions (section 8).
- **SBOM and vulnerabilities:** `bash scripts/sbom-vuln.sh all`
  fetches its pinned tools, generates the CycloneDX and SPDX SBOMs from
  `dist/manifest.json`, scans them (grype, osv-scanner, OpenVEX triage) and
  checks the boot chain (SBAT, signer certificates, dbx). `make sbom` (SBOM
  only) and `make vulns` (SBOM + scan) run the same steps once the tools are
  there. Read `sbom/VULNERABILITIES.md`. Run it after `make build` changed
  `dist/` and before a release. The reports are git-ignored; only the triage
  decisions (`sbom/vex.openvex.json`) are committed
  ([sbom/README.md](../sbom/README.md)). Details and the triage workflow:
  [.claude/skills/sbom-vuln/SKILL.md](../.claude/skills/sbom-vuln/SKILL.md).
- **Portable packages:** `make portable` (this machine's target) or
  `make portable ARGS=--all` (all four) runs `scripts/build_portable.sh`:
  `make build`, SBOM, package, verify. Output in `out/portable/`
  ([PORTABLE.md](PORTABLE.md#building-the-packages-yourself)).
- **Release dry run:** `make release` runs `scripts/release/build_release.sh`
  and writes every release file to `out/release/`. `make release
  ARGS=--skip-e2e` skips the QEMU suite for a quicker local check. Real
  releases are built by GitHub Actions from a `vX.Y.Z` tag:
  [RELEASING.md](RELEASING.md).

## 11. Ground rules

- **Never weaken Secure Boot.** No disabling, patching or bypassing of
  signature verification in anything that ships. Dev tooling may *test*
  firmware states (fresh, Microsoft keys, MOK pre-enrolled), nothing more.
- **Dev tooling never writes real block devices.** Only the installer does,
  with its safety checks. Loop devices are created through udisks for our
  own image files only, and always unmounted and deleted again.
- **Pin and verify downloads.** Packages come from the signed Ubuntu
  archive; other downloads are pinned with SHA-256 (pip with `--require-hashes`).
- **Only open-source tooling**, run locally, to build, test and analyse.
- **Keep private keys private.** `keys/*.key` is git-ignored; never copy
  it into images, containers or bug reports.
- **Installer and bb-dev: Python standard library only. Menu: plain GRUB
  script. Build: bash.**
