# beast-net helper application

The program that runs inside the small Linux environment started by the
beast-booter menu entry **Download an ISO from a link**. It brings up the
network (Ethernet automatically, or a WiFi network the user picks), asks for an
ISO link and an optional SHA-256, downloads the ISO onto the stick under
`/downloads/`, verifies it, and hands it to the beast-booter menu to boot once.
The contract is [docs/BEASTNET.md](../docs/BEASTNET.md) (sections 1, 4, 5 and 6).

## Layout

| Path | What |
|---|---|
| `rootfs/` | copied verbatim into the initramfs root by `build/beastnet/` |
| `rootfs/init` | PID 1 (busybox sh): kernel filesystems, driver coldplug, mounts the data partition (`/mnt/data`, exFAT/FAT32/NTFS) and ESP (`/mnt/esp`) by UUID, starts the app on the console, offers a shell if anything fails |
| `rootfs/usr/share/beastnet/udhcpc.script` | busybox `udhcpc` event script (address, route, DNS) |
| `rootfs/etc/beast-net-release` | marks the real environment; without it the app never changes the network and never reboots |
| `python/beastnet/` | the app, installed as `/usr/lib/python3/dist-packages/beastnet` (stdlib only, Python 3.10+) |
| `runtime.json` | binaries and Python modules the app needs beyond the builder's defaults (read by `build/beastnet/mkinitrd.py`) |
| `tests/` | pytest suite (host, no root) and `qemu_smoke.py` (manual QEMU run) |

Modules: `download` (HTTPS client, redirects, resume, checksums, free space),
`checksums` (SHA256SUMS / BSD / single-hash files), `grubenv` (GRUB environment
block, byte-compatible with `grub-editenv`), `net` + `firmware` + `wifi` (NICs,
missing firmware -> catalog pack, DHCP, `iw` scan, wpa_supplicant), `script`
(`beastnet.script=` plans), `flow` (the interactive steps), `ui/tui.py` (curses)
and `ui/plain.py` (line-based fallback), `events` (`BEASTNET:` lines), `app`
(command line).

## How it runs

1. `/init` mounts `/proc`, `/sys`, `/dev`, `/run`, loads drivers for every
   `modalias` (a few rounds, so USB devices behind new controllers are found),
   waits up to 30 s for `beastnet.data=` / `beastnet.esp=` and mounts them read-write.
   The console is `tty1`, or the serial port when the last `console=` is `ttyS*`.
2. `/init` runs `python3 -m beastnet` as a child (never `exec`: if the app ends,
   PID 1 shows the exit code and a shell, then starts the app again).
3. The app prints `BEASTNET: ready ...`, probes the adapters (`nic` and
   `firmware missing` lines), and either runs the script plan or the screens
   **Network -> Link -> Download -> Done**.
4. **Boot it now** sets `bb_oneshot=/downloads/<file>` in `ESP:/grub/grubenv`
   (rewritten in place, fsynced), syncs, unmounts both partitions and
   `reboot -f`. The menu side of the hand-off is in `grub/`.

Security rules, all enforced in `download.py` and covered by tests:
certificate and host name verification against `/etc/ssl/certs/ca-certificates.crt`
only (no option to turn it off); `http://` only with a SHA-256 that came from the
user or from an `https://` checksum file; no HTTPS -> HTTP redirects; at most 10
redirects; a checksum mismatch deletes everything; an existing file is never
replaced without the user choosing to (script mode: `"overwrite": true`).

Kernel parameters: those of BEASTNET.md section 5, plus `beastnet.ui=plain`
(line-based interface even when curses works). Script plans accept two
optional keys beyond the contract: `"on_error"` (`stay` (default), `reboot`,
`poweroff`, `shell`) and `"overwrite"`. Extra error codes: `script` (bad
plan), `exists` (destination exists), `internal` (a bug).

## Testing

```sh
source scripts/dev-env.sh
pytest -q beastnet/tests            # about 6 s, no root, no network
```

The suite runs local HTTP and HTTPS servers (with a throwaway CA made by
`openssl`), compares the grubenv writer byte for byte with `grub-editenv`, parses
fake sysfs trees and kernel logs, recorded-format `iw` output, plays back
wpa_supplicant control-socket events, runs script mode end to end, and draws
the curses screens both into a fake screen and into a real pseudo-terminal.

Host dry run (outside beast-net the app implies `--dry-run --no-net`):

```sh
PYTHONPATH=beastnet/python python3 -m beastnet --help
PYTHONPATH=beastnet/python python3 -m beastnet --root /tmp/bn --script /plan.json --ca-file my-ca.pem
# reads /tmp/bn/proc/cmdline, /tmp/bn/mnt/data/plan.json, writes /tmp/bn/mnt/esp/grub/grubenv
```

In QEMU, with the kernel and initrd built by `build/beastnet/`:

```sh
python3 beastnet/tests/qemu_smoke.py                       # plain-http-sha, tls-untrusted
python3 beastnet/tests/qemu_smoke.py --scenario internet   # real HTTPS (needs Internet)
```

It overlays this checkout's `rootfs/` and package onto the built initrd, makes
an exFAT + FAT stick image, serves an ISO from the host and checks the
`BEASTNET:` lines, the file on the exFAT partition and `bb_oneshot` in the grubenv.
