# BeastBoot end-to-end tests

These tests boot real BeastBoot drive images in QEMU, under legacy BIOS
(SeaBIOS), UEFI (OVMF) and UEFI with Secure Boot (OVMF secboot, Microsoft keys).
They check the menu, folder browsing and every ISO boot recipe through the
serial console, using the machine-readable `BEAST:` lines from
docs/ARCHITECTURE.md §5.

## Running

```sh
source scripts/dev-env.sh
make keys && make build          # dist/ (needed by everything except the self-test)
pytest -q tests/e2e              # whole suite, about 3 minutes with KVM
pytest -q tests/e2e -m selftest  # harness self-test only (no dist/ or installer needed)
pytest -q tests/e2e -m "bios and not secureboot"
pytest -q tests/e2e -m "not slow"   # no QEMU boots: unit tests and static image checks
```

Tests that need something missing skip with the reason: `dist/` (from
`make build`), the installer (`python3 -m beastbooter`), the BeastBoot
certificate (`keys/beast-booter.cer`, or the one in dist/), Secure Boot firmware
and `virt-fw-vars`, or a usable `udisksctl`.

**exFAT and NTFS tests** fill the data partition through a loop device that
udisks sets up. This needs the system D-Bus and polkit. Inside a sandbox that
blocks them, the tests skip. Run pytest outside the sandbox to include them.
Loop devices are always unmounted and deleted, and only one backed by our own
image file is ever touched.

Markers: `bios`, `uefi`, `secureboot`, `exfat`, `ntfs`, `beastnet`, `selftest`, `slow` (boots QEMU).

Environment variables (all optional):

| Variable | Effect |
|---|---|
| `BB_E2E_DIST` | dist/ directory to install from (default `$BB_ROOT/dist`) |
| `BB_E2E_OUT` | output directory (default `$BB_ROOT/out/e2e`) |
| `BB_E2E_KVM` | `1` = require KVM, `0` = never use it (default: use it if `/dev/kvm` is usable) |
| `BB_E2E_TIMEOUT_SCALE` | multiply every timeout (default 1, or 4 without KVM) |
| `BB_E2E_DISK_IF` | how the drive is attached: `usb` (default, xHCI mass storage), `ide` (AHCI), `virtio` |
| `BB_E2E_KEYS` | how keys are sent: `serial` (default; Down = `ESC [ B`, Enter = `CR`) or `qmp` (PS/2 via QMP `send-key`) |
| `BB_E2E_KEEP` | `1` = keep per-test work dirs (disk copies, UEFI vars) even when the test passes |

## Outputs (`out/e2e/`, git-ignored)

- `logs/<test>.log`: the full raw serial log of each VM (written as it arrives).
  `<test>.qemu.txt` holds the QEMU command line, exit code and stderr.
  `<test>.screen.txt` holds the emulated serial screen at the end. On failure,
  `<test>.png` holds a screendump taken through QMP.
- `fixtures/`: fixture ISOs, cached. A fixture is rebuilt only when its definition changes.
- `images/`: base drive images, built once per session by the real installer.
- `work/<test>/`: the per-test drive copy (`cp --sparse=always`) and UEFI vars.
  These are deleted when the test passes.
- `selftest/`: stub images for the harness self-test.

## Layout

```
conftest.py                 markers, skip logic, vm_factory, session-cached base images
bbe2e/env.py                paths, tools, KVM detection, timeouts
bbe2e/qemu.py               QEMU launcher (modes bios / uefi / uefi-sb), serial capture, waits, keys, QMP
bbe2e/serial.py             BEAST: record parser and VT100 screen emulator (menu reading)
bbe2e/images.py             installer wrapper, partition parsing, FAT (mtools) and udisks writers
bbe2e/trees.py              data-partition trees and the listings they must produce
bbe2e/checks.py             shared assertions (ready line, listing, interactive browse flow)
bbe2e/beastnet.py           beast-net helpers: BEASTNET: lines, ESP/grubenv access, fake firmware packs, host HTTP(S) server
bbe2e/stubs.py              stand-in GRUB images for the self-test (incl. a shim + throwaway-signed GRUB)
fixtures/build_fixtures.py  fixture ISOs (python3 tests/e2e/fixtures/build_fixtures.py [--force] [NAME...])
test_e2e_*.py               the tests
```

## How a test drives the menu

Each test copies a base image and writes `/beast-booter/config.cfg` on the
data partition, for example `bb_debug=1`, `bb_dryrun=1` or `bb_autoboot=/path.iso`.
It then boots the copy and waits for `BEAST:` records.

The serial stream is not clean line-by-line text, and the parser in
`bbe2e/serial.py` copes with that:

- GRUB's serial terminal word-wraps at 80 columns. The inserted break looks
  exactly like a newline. GRUB sometimes splits a long word, and even the
  `BEAST:` marker itself, when the cursor starts near the right edge.
- Under OVMF, the firmware console is mirrored to the same UART, so every line
  arrives twice. The copies are collapsed into one, keeping the unwrapped copy.

So assertions check tokens and regexes (`Record.has_token`, `Record.matches`)
that try every way of re-joining the wrapped lines, rather than whole lines.

## beast-net tests (`test_e2e_beastnet.py`, marker `beastnet`)

They cover "Download an ISO from a link" (docs/BEASTNET.md) end to end, about
1.5 minutes with KVM:

- **Menu** (GRUB only, dry run): with no ISOs on the data partition the root
  menu is `System: ...`, then **Download an ISO from a link**; selecting it
  prints `BEAST: boot beast-net recipe=beast-net` and the exact helper command
  line (data and ESP UUIDs, `beastnet.sb`, serial console) and initrds.
- **Helper boot** on BIOS, UEFI and UEFI + Secure Boot (MOK enrolled): Ubuntu's
  signed kernel starts through our GRUB (shim verifies it) and prints
  `BEASTNET: ready kernel=<kver> sb=<0|1>`.
- **Download and one-shot** in script mode (`bb_beastnet_script` in config.cfg
  -> `beastnet.script=`): DHCP on a virtio NIC, HTTP download from a server on
  the host, SHA-256 check, `handoff`, reboot; the next boot prints
  `BEAST: oneshot <path>` and boots the ISO through the casper recipe; the boot
  after that is normal. Also on Secure Boot, and on exFAT with a path that has
  spaces. The interactive line UI (no script) is driven over the serial port too.
- **Refusals**: wrong SHA-256, plain HTTP without SHA-256, an untrusted
  (self-signed) HTTPS certificate: an `error` line, no hand-off, nothing left
  under `/downloads`.
- **Firmware packs**: a tiny pack (`lib/firmware/beastbooter-test.bin`, built
  with the installer's cpio module and written to the ESP with mtools) is passed
  as an extra initrd, listed in `ready ... firmware=` and readable in the helper.

Networking is QEMU user mode (slirp) with `-device virtio-net-pci,romfile=`: the
guest is 10.0.2.15 and reaches the host's 127.0.0.1 as 10.0.2.2, so the test
servers listen on 127.0.0.1 only. The helper reboots or powers off at the end
of a plan; with `-no-reboot` QEMU exits, and the test boots the same image
again. Real WiFi is not covered; real public HTTPS downloads are covered by
the opt-in live tests below.

## Live downloads (`test_e2e_beastnet_live.py`, marker `live`)

Skipped unless `BB_LIVE_NET=1` (`make e2e-live` sets it): each test downloads
a real ISO over the internet, several GB. The helper boots on UEFI with QEMU
user networking, downloads the official link from
[live_sources.json](live_sources.json) onto a fresh exFAT image
(`BB_LIVE_IMAGE_SIZE`, default 16G), checks the vendor's SHA-256 when there is
a checksum file, hands off, and the menu then opens the ISO once (dry run) and
must detect the catalog's `recipe` (Ubuntu: `casper` with `fsmod exfat`;
Windows: `unsupported-windows`). The file on the drive is hashed again on the
host and must match what the helper reported.

| Variable | Meaning |
|---|---|
| `BB_LIVE_NET` | `1` = run the live tests |
| `BB_LIVE_SOURCE` | comma-separated catalog ids (default: entries with `"vm": true`) |
| `BB_LIVE_URL` | test this link instead (`BB_LIVE_SHA256_URL` or `BB_LIVE_SHA256`, `BB_LIVE_RECIPE` optional) |
| `BB_LIVE_TIMEOUT` | seconds for one download (default 5400) |

The quick check without a VM is `make net-sources`
([docs/BEASTNET.md](../../docs/BEASTNET.md#7-downloading-from-official-sources)).

## QEMU flags that matter

- `-machine q35,kernel-irqchip=split` with KVM. With the in-kernel IOAPIC,
  OVMF hung in BDS on most boots from AHCI, USB or NVMe disks on the
  development host (kernel 7.0). virtio-blk was not affected.
- `-nodefaults -device VGA -display none` plus `-L .tools/root/usr/share/seabios -L .tools/root/usr/share/qemu`.
  The `.tools` QEMU looks for `vgabios-*.bin` and option ROMs in the host's
  `/usr/share/qemu`, which lacks the SeaBIOS files.
- BIOS: `-bios $BB_SEABIOS_DIR/bios-256k.bin`. UEFI: `OVMF_CODE_4M.fd` (read-only
  pflash) and a copy of `OVMF_VARS_4M.fd`.
- Secure Boot: `-machine q35,smm=on,...`, `-global driver=cfi.pflash01,property=secure,value=on`,
  `OVMF_CODE_4M.secboot.fd`, and vars from `OVMF_VARS_4M.ms.fd`.
  "Enrolled" means `virt-fw-vars --add-mok <guid> <cert>`, which pre-seeds MokList
  exactly as MokManager enrollment would. Nothing else about verification is changed.
- `-chardev stdio,signal=off -serial chardev:ser0`, `-qmp unix:...`, `-no-reboot`.
  A watchdog kills QEMU after a hard timeout.
