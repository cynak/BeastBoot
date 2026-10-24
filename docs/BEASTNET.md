# beast-net: download and boot an ISO from a link

Contract for the network-download feature. Owned by the lead; builders
implement it and propose changes in their reports instead of editing it.

## 1. What the user sees

1. In the boot menu, tools section: **Download an ISO from a link** (shown only
   when `($bb_esp)/beast-net/vmlinuz` exists).
2. A small Linux environment starts: it brings up Ethernet automatically (DHCP)
   or lets the user pick a WiFi network and type the passphrase, then asks for
   a URL (HTTPS by default) and an optional SHA-256 (or a checksum-file URL).
3. It downloads the ISO onto the data partition, under `/downloads/`, with
   progress and resume. It verifies the TLS certificate (Ubuntu's CA bundle) and,
   when given, the SHA-256. A plain `http://` URL is refused unless a SHA-256 is
   given.
4. **Boot it now**: it writes a one-shot entry for the beast-booter menu and
   reboots; the menu boots that ISO once, through the normal recipes (so Secure
   Boot verification works exactly as for any other ISO). The ISO stays on the
   stick for next time.

Missing WiFi firmware is reported by driver name, with the pack to install from
the desktop app ("Install the Intel WiFi firmware pack").

## 2. Principles

- **Secure Boot stays intact.** The helper kernel is Ubuntu's Canonical-signed
  kernel, unmodified, verified by shim like any distro kernel; its modules are
  the unmodified Canonical-signed `.ko` files of that same kernel build. The
  helper never kexecs into another kernel when Secure Boot is on; the hand-off
  is always "reboot into the menu".
- **No closed firmware by default.** Firmware packs are optional, installed by
  the user from the desktop app (or CLI), downloaded from the named upstream
  source, and every file is checked against a SHA-256 pinned in the catalog.
- **Transparent.** Every file in `beast-net/` comes from a named Ubuntu package
  or from this repo and is listed in `dist/manifest.json` and the SBOM.

## 3. Files on the ESP (layout version 2: 512 MiB FAT32 ESP)

```
beast-net/vmlinuz                 Ubuntu signed kernel (linux-image-<kver>), unmodified
beast-net/initrd.img              base initramfs (compressed cpio; see §5)
beast-net/VERSION                 "beast-net <bb version> kernel <kver>"
beast-net/catalog.json            firmware pack catalog (§6)
beast-net/firmware/<id>.cpio      installed firmware packs (uncompressed newc cpio)
beast-net/firmware/installed.json installed packs (§6)
grub/grubenv                      1024-byte GRUB environment block, created by the installer
```

## 4. GRUB entry and hand-off (menu side)

```
linux  ($bb_esp)/beast-net/vmlinuz beastnet.data=UUID=$bb_data_uuid_linux \
       beastnet.esp=UUID=<ESP volume id> beastnet.sb=$bb_sb [beastnet.debug=1] \
       console=tty0 [console=ttyS0,115200 when bb_serial=1] quiet
initrd ($bb_esp)/beast-net/initrd.img ($bb_esp)/beast-net/firmware/<every installed .cpio>
```

One-shot hand-off: the helper sets `bb_oneshot=<ISO path on the data partition>`
in `ESP:/grub/grubenv` (standard GRUB environment block format: the line
`# GRUB Environment Block`, then `key=value` lines, padded with `#` to exactly
1024 bytes). At start-up the menu runs `load_env -f ($bb_esp)/grub/grubenv bb_oneshot`;
if it is set, the menu clears it with `save_env` and then boots it exactly
like `bb_autoboot`. If `save_env` fails, the menu must not loop: it does not boot the ISO, prints
`BEAST: error oneshot-not-cleared <path>` (debug) and a message that the ISO is
under `/downloads/`, and shows the normal menu. The tools entry is
**Download an ISO from a link** (`BEAST: boot beast-net recipe=beast-net`),
shown only when `beast-net/vmlinuz` and `beast-net/initrd.img` are on the ESP;
installed packs are passed as extra initrds via `beast-net/firmware/*.cpio`.

## 5. The helper environment (initramfs)

Built by `build/beastnet/` from pinned Ubuntu 26.04 packages, all versions
recorded in the manifest:

- kernel `linux-image-<kver>-generic` + `linux-modules-<kver>-generic` (module
  subset: wired NICs incl. USB adapters, WiFi drivers, cfg80211/mac80211,
  crypto deps, USB/xhci/usb-storage/uas/sd_mod, exfat/vfat/ntfs3/iso9660/loop,
  nls, virtio + e1000 for tests, mac80211_hwsim for tests), resolved with modules.dep;
- `busybox-static` (sh, mount, udhcpc, ip, mdev, findfs …), `kmod` (modprobe),
  `wpasupplicant` (wpa_supplicant, wpa_cli), `iw`, `ca-certificates`,
  `python3.14-minimal` + the stdlib modules the app needs (ssl, hashlib,
  curses + ncurses terminfo, json, urllib, socket, subprocess) and their shared
  libraries (resolved with the packages' dependencies / ldd).

The app sources come from this repo's `beastnet/` directory:

- `beastnet/rootfs/` is copied verbatim into the initramfs root. It contains
  `init` (PID 1, busybox sh): mount proc/sys/dev/run, coldplug modules from
  `/sys/**/modalias`, mount the data and ESP partitions from `beastnet.data` /
  `beastnet.esp`, then `exec python3 -m beastnet` on tty1 (and on ttyS0 when
  given). If anything fails it drops to a busybox shell with the error.
- `beastnet/python/beastnet/` is installed as a Python package
  (`/usr/lib/python3/dist-packages/beastnet`).

Kernel command line parameters read by the helper:

| Parameter | Meaning |
|---|---|
| `beastnet.data=UUID=…` | data partition (mounted read-write at `/mnt/data`) |
| `beastnet.esp=UUID=…` | ESP (mounted read-write at `/mnt/esp`) |
| `beastnet.sb=0/1` | Secure Boot state reported by the menu |
| `beastnet.debug=1` | print `BEASTNET:` lines (below) on the console and serial |
| `beastnet.script=/path` | non-interactive run from a JSON file on the data partition (tests, power users); the menu passes it when `/beast-booter/config.cfg` sets `bb_beastnet_script=/path` |
| `beastnet.ui=plain` | line-based prompts instead of the curses screens (serial consoles) |

Script file (`beastnet.script`):
```json
{"network": {"type": "ethernet"} ,
 "url": "https://example.org/x.iso", "sha256": "<hex or null>", "sha256_url": null,
 "dest": "/downloads/x.iso", "then": "reboot" }
```
`network` may instead be `{"type": "wifi", "ssid": "...", "psk": "..."}`;
`then` is `reboot`, `poweroff` or `stay` (the one-shot hand-off is written only
for `reboot`); optional `"on_error"`: `stay` (default), `reboot`, `poweroff` or
`shell`; optional `"overwrite": true` to replace an existing file at `dest`.

Machine-readable output with `beastnet.debug=1` (prefix exactly `BEASTNET: `):
```
BEASTNET: ready kernel=<kver> sb=<0|1> firmware=<comma list or none>
BEASTNET: nic <iface> type=<ethernet|wifi> driver=<module> state=<up|down|no-firmware>
BEASTNET: firmware missing driver=<module> pack=<pack id or unknown>
BEASTNET: net up iface=<iface> type=<ethernet|wifi> ip=<addr>
BEASTNET: download start url=<url> dest=<path>
BEASTNET: download progress pct=<0-100>
BEASTNET: download done path=<path> bytes=<n> sha256=<hex>
BEASTNET: verify ok sha256=<hex>
BEASTNET: verify fail expected=<hex> got=<hex>
BEASTNET: handoff oneshot=<path>
BEASTNET: error <code> <text>
```
Error codes: `no-network`, `wifi-auth`, `dhcp`, `tls`, `http`, `refused-plain-http`
(also for an HTTPS -> HTTP redirect), `checksum-mismatch`, `no-space`, `mount`,
`grubenv`, `script`, `exists`, `internal`.

Initramfs notes: `/lib` is a real directory, not a symlink (the kernel replaces
a `/lib` symlink when a firmware pack cpio brings `lib/`); busybox applets shadow
`$PATH`, so kmod is always called as `/usr/sbin/modprobe` (softdeps such as
r8169 -> realtek PHY need it).

## 6. Firmware packs

Source: the upstream **linux-firmware** git repository on kernel.org, pinned to
one tag. Per-file URL:
`https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/<path>?h=<tag>`.
Every file has a SHA-256 in the catalog; a download that doesn't match is
discarded. Download `source_path` when present (WHENCE `Link:` aliases, e.g. all
iwlwifi files), and install it as `path`. Pinned tag: 20261019. The catalog is generated at build time (`build/beastnet/`) from
`modinfo -F firmware` of the bundled modules, resolved against the pinned tag
(including `Link:` entries in WHENCE), and ships at `ESP:/beast-net/catalog.json`
and in the portable app's payload.

`catalog.json`:
```json
{"v": 1, "kernel": "<kver>",
 "source": {"name": "linux-firmware", "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git",
            "tag": "<tag>", "url_template": "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/{path}?h={tag}"},
 "packs": [{"id": "intel-wifi", "title": "Intel WiFi", "description": "...",
            "modules": ["iwlwifi", "iwlmvm", "iwlmld"], "licenses": ["..."],
            "size": 12345678,
            "files": [{"path": "iwlwifi-....ucode", "sha256": "<hex>", "size": 123, "license": "...",
                       "source_path": "<optional: path to download when the file is installed
                                       under a WHENCE Link: name; default = path>"}]}]}
```
Initial packs: `intel-wifi`, `realtek-wifi`, `mediatek-wifi`, `qualcomm-atheros-wifi`,
`broadcom-wifi`, `realtek-ethernet`.

A pack file `<id>.cpio` is an uncompressed newc cpio with entries
`lib/firmware/<path>` (directories 0755, files 0644, uid/gid 0, mtime 0, sorted),
so GRUB can pass it as an extra initrd.

`installed.json`:
```json
{"v": 1, "packs": [{"id": "intel-wifi", "catalog_tag": "<tag>",
  "cpio_sha256": "<hex>", "files": [{"path": "...", "sha256": "...", "size": 1}]}]}
```

Installer CLI (installer/beastbooter, implemented with the cross-platform installer):
```
beast-booter firmware catalog [--dist DIR] [--json]
beast-booter firmware fetch --pack ID [--pack ID ...] --out DIR [--catalog FILE] [--progress-file F]
                            [--for-image P | --for-device X]
     # unprivileged: download each file from the catalog source, verify SHA-256,
     # write DIR/<id>.cpio + DIR/<id>.json (the installed.json entry);
     # --for-*: first check that the packs fit on that target (see "Room" below)
beast-booter firmware install (--device X | --image P) --from DIR [--progress-file F]
     # elevated for devices: re-verify every file inside each cpio against the
     # catalog, check the free space, then write beast-net/firmware/<id>.cpio and
     # update installed.json
beast-booter firmware remove (--device X | --image P) --pack ID
beast-booter firmware list (--device X | --image P) [--json]
```
The desktop GUI shows each pack's title, chips/modules, size, licences, the
exact source URL and tag, and the SHA-256s, before anything is downloaded.

`list --json` (and the `done` event of `install`/`remove`, as `info.installed`)
is installed.json plus: per pack `cpio_size` (or `missing: true` when its .cpio
is gone), `unlisted` .cpio files, `esp_free`, `esp_cluster`, `esp_label`,
`installed_json_size`, and the drive's `catalog_tag` and `kernel`.

**Room on the ESP.** One formula (installer/beastbooter/esp.py `fw_space`): each
pack's .cpio and the new installed.json in whole clusters, plus two clusters for
new directories, must fit in the free space plus what the write replaces (the
old .cpio of a pack being re-installed, the old installed.json). The size of a
pack's .cpio follows exactly from the catalog's file list (`fw_archive_size`),
so it is checked before anything is downloaded:
* `firmware install` always checks with the real files (error `no-space`);
* `firmware fetch --for-image P` reads the image and refuses with `no-space`
  before the first request. `--for-device X` does the same when it can read
  the drive, which needs administrator rights; without them (fetch itself never
  needs them) the check is skipped with a warning, and `install` still checks;
* the GUI reads the target first (`firmware list`; for a drive this is one more
  administrator prompt) unless an earlier list/install/remove of that target
  told it, shows "Selected: X of Y free on BEAST-EFI" as packs are ticked, and
  disables **Download and install** with "Needs X, Y free on BEAST-EFI.
  Deselect packs or remove installed ones." when they don't fit.

**Unmounting.** Writing to a drive (`install`, `update`, `firmware install`,
`firmware remove`) unmounts every volume of that drive first and reports a
`prepare` step naming the mountpoints it unmounted. Linux unmounts each mount
of the drive (desktop auto-mounts and mounts made by hand alike), macOS runs
`diskutil unmountDisk force`, Windows locks and dismounts each volume. A volume
that a program keeps busy fails with error code `busy`, naming the mountpoint.
Still refused, mounted or not: a disk holding the running system, /boot or
the live-boot medium, active swap, device-mapper/LVM/LUKS/RAID holders, a
loop device backed by a file on it, and the drive beast-booter runs from.
