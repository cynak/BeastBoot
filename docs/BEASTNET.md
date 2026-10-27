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
4. **Boot it now**: it writes a one-shot entry for the BeastBoot menu and
   reboots; the menu boots that ISO once, through the normal recipes (so Secure
   Boot verification works exactly as for any other ISO). The ISO stays on the
   stick for next time.

Missing WiFi firmware is reported by driver name, with the pack to install from
the desktop app ("Install the Intel WiFi firmware pack").

The helper also runs **Trust Ubuntu's Secure Boot key** (UEFI only): from its
own **More** menu, or straight away when the boot menu's Tools entry of that
name starts it ([§8](#8-trust-ubuntus-secure-boot-key)).

## 2. Principles

- **Secure Boot stays intact.** The helper kernel is Ubuntu's kernel with its
  code unchanged; the build checks Canonical's signature, then replaces it with
  the beast-boot key's (§5), and shim verifies it like `grubx64.efi`. Its
  modules are the unmodified Canonical-signed `.ko` files of that same kernel
  build. The
  helper never kexecs into another kernel when Secure Boot is on; the hand-off
  is always "reboot into the menu".
- **No closed firmware by default.** Firmware packs are optional, installed by
  the user from the desktop app (or CLI), downloaded from the named upstream
  source, and every file is checked against a SHA-256 pinned in the catalog.
- **Transparent.** Every file in `beast-net/` comes from a named Ubuntu package
  or from this repo and is listed in `dist/manifest.json` and the SBOM.

## 3. Files on the ESP (layout version 2: 512 MiB FAT32 ESP)

```
beast-net/vmlinuz                 Ubuntu's kernel (linux-image-<kver>), re-signed with the beast-boot key (code unchanged)
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
       console=tty0 [console=ttyS0,115200 when bb_serial=1] beastnet.ui=[plain when bb_serial=1] \
       beastnet.script=[$bb_beastnet_script] [beastnet.action=trust-ubuntu] quiet
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

The next Tools entry, **Trust Ubuntu's Secure Boot key** (UEFI only, also only
with the helper on the ESP), runs the same `bb_beastnet` with the argument
`trust-ubuntu`: the command line is the same plus `beastnet.action=trust-ubuntu`,
and GRUB logs `BEAST: boot beast-net recipe=beast-net action=trust-ubuntu`.
When GRUB refuses a kernel under Secure Boot, the error text names this entry
as the first remedy for Ubuntu-signed kernels (`bb_fail`, `bb_sb_help` in
`grub/beast/lib.cfg`).

## 5. The helper environment (initramfs)

Built by `build/beastnet/` from pinned Ubuntu 26.04 packages, except the
kernel, which comes from Ubuntu 26.10 (released pockets only; its fixes for
the kernel CVEs that 26.04's 7.0 kernel still has open, see sbom/README.md),
all versions recorded in the manifest:

- kernel `linux-image-<kver>-generic` + `linux-modules-<kver>-generic` (module
  subset: wired NICs incl. USB adapters, WiFi drivers, cfg80211/mac80211,
  crypto deps, USB/xhci/usb-storage/uas/sd_mod, exfat/vfat/ntfs3/iso9660/loop,
  nls, virtio + e1000 for tests, mac80211_hwsim for tests), resolved with modules.dep;
  The drive's shim (Debian's) trusts Debian's key, not Canonical's, so
  `build/build.sh` treats the kernel like `grubx64.efi`: it checks that the
  kernel is signed through Canonical's Master CA and not by a certificate or
  hash Ubuntu revoked (`build/trust/canonical/`), removes every signature
  (`sbattach --remove`) and signs it with the beast-boot key. The code is
  unchanged: the Authenticode digest is the same before and after. An
  existing `dist/` copy is kept when ours is its only signature and the
  unsigned image is unchanged; `BB_RESIGN=1` forces a fresh signature. The
  manifest records `secure_boot.beastnet_kernel_source`
  (`deb:<pkg>=<ver>:/boot/vmlinuz-...`), `beastnet_kernel_authenticode_sha256`,
  `beastnet_kernel_unsigned_sha256` and `beastnet_kernel_replaced_signers`;
  the build id counts the kernel by its unsigned hash. `build/verify-dist.sh`
  checks that the kernel carries only the beast-boot signature and that its
  digest matches the manifest (and the kernel in the `.deb`, when that is in
  the beast-net cache). The SBOM lists it under its `linux-image` package,
  marked re-signed.
- `busybox` (sh, mount, udhcpc, ip, mdev, findfs …; the dynamic build, linked
  against the shipped libc6), `kmod` (modprobe),
  `wpasupplicant` (wpa_supplicant, wpa_cli), `iw`, `ca-certificates`,
  `python3.14-minimal` + the stdlib modules the app needs (ssl, hashlib,
  curses + ncurses terminfo, json, urllib, socket, subprocess) and their shared
  libraries (resolved with the packages' dependencies / ldd).

Left out on purpose because they carry open CVEs and nothing in beast-net uses
them (build/beastnet/userland.list; the evidence per CVE is in
sbom/vex.userland.openvex.json):

- Python modules outside the app's import set: tarfile, zipfile, configparser,
  csv, xml (+ plistlib, xmlrpc), urllib.request (+ robotparser), tempfile,
  uuid + `_uuid` (so libuuid1 is no longer shipped). The build's import smoke
  test (REQUIRED_PY + runtime.json) still passes.
- busybox applet links nothing calls: tar, cpio, unzip, rpm, rpm2cpio, dpkg,
  dpkg-deb, ar, wget, ssl_client, httpd, netstat, udhcpc6, awk. The code stays
  inside /usr/bin/busybox, but busybox sh runs only applets that have a link,
  so the rescue shell cannot start them either (except as `busybox <applet>`).

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
| `beastnet.script=/path` | non-interactive run from a JSON file on the data partition (tests, power users); the menu passes it when `/beast-booter/config.env` (or, with Secure Boot off, `config.cfg`) sets `bb_beastnet_script=/path`; in `config.env` the path may hold only letters, digits and `._/-` |
| `beastnet.ui=plain` | line-based prompts instead of the curses screens (serial consoles) |
| `beastnet.action=trust-ubuntu` | open "Trust Ubuntu's Secure Boot key" first (§8; set by the Tools menu entry). Other values are ignored. Its "Download an ISO from a link" item then leads to the normal screens |
| `beastnet.action=disk` | open Disk tools first (recovery and cloning, RAID-aware; set by the "Disk tools: recovery and cloning" Tools menu entry; see [DISK_TOOLS.md](DISK_TOOLS.md)). Every beast-net boot gets `raid=noautodetect md_mod.start_ro=1` on the kernel command line, so no RAID array starts on its own or writes before Disk tools set it read-only |
| `beastnet.action=winboot` | prepare a Windows ISO for Secure Boot (set by the menu's "Prepare this Windows ISO for Secure Boot" entry, which first saves `bb_wb_iso` to the ESP `grub/grubenv`). Copies the ISO's `sources/boot.wim` to `/beast-booter/winboot/<iso>/` on the data partition (exFAT or FAT32 only), shows progress, then sets `bb_oneshot` to the ISO and reboots. Error code `winboot`. Spec: [WINDOWS_SECURE_BOOT.md](WINDOWS_SECURE_BOOT.md) |

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
BEASTNET: trust state=<state> sb=<0|1|unknown> ca=<0|1> revoked=<n>/<total> pending=<vars or none>
BEASTNET: trust request step=<revocations|ca|delete> var=<MokXNew|MokNew|MokDel> certs=<n> hashes=<n>
BEASTNET: trust requested step=<step> var=<var>
BEASTNET: error <code> <text>
```
Error codes: `no-network`, `wifi-auth`, `dhcp`, `tls`, `http`, `refused-plain-http`
(also for an HTTPS -> HTTP redirect), `checksum-mismatch`, `no-space`, `mount`,
`grubenv`, `script`, `exists`, `internal`, `trust` ("Trust Ubuntu's Secure Boot
key" refused or failed, §8).

Initramfs notes: `/lib` is a real directory, not a symlink (the kernel replaces
a `/lib` symlink when a firmware pack cpio brings `lib/`); busybox finds programs
through `$PATH` (no applet link where a package ships the program), and kmod is
called as `/usr/sbin/modprobe` all the same (softdeps such as r8169 -> realtek
PHY need it).

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
{"v": 1, "packs": [{"id": "intel-wifi", "catalog_tag": "<tag>", "kernel": "<kver>",
  "cpio_sha256": "<hex>", "files": [{"path": "...", "sha256": "...", "size": 1}]}]}
```

A pack is made for one catalog: its linux-firmware tag and the helper kernel
whose modules chose the files. `firmware install` refuses a pack fetched for
another tag or kernel than the target's catalog (`pack-mismatch`: fetch it
again with that catalog, or update the drive first). `update` keeps installed
packs; it warns, naming them, about each kept pack the new catalog no longer
matches: made for another tag or kernel, or holding other files than the
catalog now lists for it (installer/beastbooter/firmware.py `stale_reason`).
0.1.2 moved the kernel from 7.0 to 7.3 with the same tag, so packs installed
with 0.1.1 still load but hold the files the 7.0 drivers asked for: the update
warns, `firmware list` and the GUI mark them stale ("made for kernel X -
reinstall"), and installing them again (fetched with the new catalog)
replaces them.

Installer CLI (installer/beastbooter, implemented with the cross-platform installer):
```
beast-boot firmware catalog [--dist DIR] [--json]
beast-boot firmware fetch --pack ID [--pack ID ...] --out DIR [--catalog FILE] [--progress-file F]
                            [--for-image P | --for-device X]
     # unprivileged: download each file from the catalog source, verify SHA-256,
     # write DIR/<id>.cpio + DIR/<id>.json (the installed.json entry);
     # --for-*: first check that the packs fit on that target (see "Room" below)
beast-boot firmware install (--device X | --image P) --from DIR [--progress-file F]
     # elevated for devices: re-verify every file inside each cpio against the
     # catalog, check the free space, then write beast-net/firmware/<id>.cpio and
     # update installed.json
beast-boot firmware remove (--device X | --image P) --pack ID
beast-boot firmware list (--device X | --image P) [--json]
```
The desktop GUI shows each pack's title, chips/modules, size, licences, the
exact source URL and tag, and the SHA-256s, before anything is downloaded.

`list --json` (and the `done` event of `install`/`remove`, as `info.installed`)
is installed.json plus: per pack `cpio_size` (or `missing: true` when its .cpio
is gone), `stale: true` and `stale_reason` when the pack no longer matches the
drive's catalog, `unlisted` .cpio files, `esp_free`, `esp_cluster`, `esp_label`,
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
loop device backed by a file on it, and the drive BeastBoot runs from.

## 7. Downloading from official sources

### What beast-net sends

Every request is a plain HTTP/1.1 `GET` with:

```
User-Agent: beast-net/<version> (beast-boot)
Accept: */*
Accept-Encoding: identity
Connection: close
```

plus `Range` / `If-Range` when a download resumes. beast-net always says who
it is; it never pretends to be a browser or another tool. Redirects are
followed (at most 10, never from HTTPS back to plain HTTP), certificates are
checked against the CA bundle in the helper (Ubuntu's `ca-certificates`), and
checksum files in the usual formats are understood: `SHA256SUMS` (Ubuntu,
Debian) and the BSD style `SHA256 (file) = ...` (Fedora `CHECKSUM`).

### Checked sources

[tests/e2e/live_sources.json](../tests/e2e/live_sources.json) lists official
links: Ubuntu (releases.ubuntu.com and cdimage.ubuntu.com), Debian and Fedora
(both redirect to a mirror), and Microsoft's Evaluation Center links for
Windows 11 Enterprise and Windows Server 2025 (`go.microsoft.com/fwlink`,
redirecting to `software-static.download.prss.microsoft.com`). Two checks use
it; both need the internet and are not part of `make e2e`:

| Check | Command | What it proves |
|---|---|---|
| quick, on this computer | `make net-sources` (`scripts/check_iso_sources.py`) | beast-net's own downloader code, headers and CA bundle (taken from the built initramfs) get a `200` from every link after its redirects, a `206` for a ranged request (resume works), bytes that start like an ISO 9660 image, and the ISO's SHA-256 from the vendor's checksum file. Seconds. |
| full, in the QEMU lab | `make e2e-live` (`tests/e2e/test_e2e_beastnet_live.py`) | the helper boots in QEMU, gets an address from QEMU's user networking (which reaches the internet through this computer), downloads the whole ISO onto a 16 GiB exFAT drive, checks it, hands it to the menu, and the menu opens it and detects its recipe. Gigabytes; minutes per ISO. |

When a server refuses beast-net (`401`, `403`, `406`, `429`), the quick check
repeats the request with other `User-Agent` values and says whether the
refusal is about the header or not, so a block shows up as exactly that
instead of a vague download error. Check any other link, for example a
personal Windows 11 link from microsoft.com/software-download/windows11 (valid
for 24 hours), with:

```sh
make net-sources ARGS="--url 'https://...'"                    # add --sha256-url or --sha256 if there is one
BB_LIVE_URL='https://...' BB_LIVE_RECIPE=windows make e2e-live    # the full download in the lab
```

`make e2e-live` downloads the entries marked `"vm": true` (Ubuntu Desktop and
Windows 11 Enterprise); `BB_LIVE_SOURCE=id,id` picks others. The links name
exact releases, so they go stale: a `gone (404)` result means the link in
the catalog needs updating, not that beast-net is broken.

Windows ISOs download fine and boot with Secure Boot off or on
([ISO_SUPPORT.md](ISO_SUPPORT.md#windows); with it on, they need the one-time `winboot` preparation); they are larger than 4 GiB, so
the drive needs exFAT or NTFS for them.

## 8. Trust Ubuntu's Secure Boot key

The user side and the reasons: [SECURE_BOOT.md](SECURE_BOOT.md#trust-ubuntus-secure-boot-key-optional);
the interface between the parts: `build/trust/README.md`.

Code: `beastnet/python/beastnet/trust.py` (screens in `flow.py`). Data:
`/usr/share/beastnet/trust/canonical/` in the initramfs, copied by
`build/beastnet/mkinitrd.py` from `build/trust/canonical/`. Every file is
checked against `trust.json` at build time and again before use; any mismatch
is refused (error code `trust`).

**State** comes from shim's runtime copies `MokListRT` and `MokListXRT` (from
`/sys/firmware/efi/mok-variables/`, otherwise efivarfs, including split
`NAME1`, `NAME2`... variables) and from the pending `MokNew`, `MokXNew`,
`MokDel` and `MokXDel`. The states: not trusted, revocations only (step 1 of 2
done), trusted, partly set up, built into this drive's shim (a shim with
Canonical's CA built in, such as Ubuntu's: nothing to enroll), and cannot be
checked here (legacy BIOS, or no efivarfs). With Secure Boot off the action
still works, and the screen says the keys matter only with Secure Boot on.
`/init` mounts efivarfs at `/sys/firmware/efi/efivars` on UEFI machines, and
the app mounts it if it is missing.

**Requests.** Step 1 requests every revoked certificate (and hash) missing
from MokListX with `mokutil --mokx --import`; step 2, only once all are
there, Canonical's Master CA with `mokutil --import`; "Stop trusting Ubuntu's
key" the CA's deletion with `mokutil --delete` (the revocations stay).
Nothing is requested while an earlier request still waits for MokManager.
Each request is read back from its EFI variable and cancelled unless it holds
exactly the requested files.

**Password.** The user types a one-time password (4-32 letters or digits)
twice. The helper hashes it with `mokutil --generate-hash` on stdin and passes
`--hash-file` (a 0600 file in `/run/beastnet`, deleted afterwards), so the
password never appears on a command line or in `commands.log`. mokutil is
called with `--ignore-keyring`, because the helper kernel's built-in keyring
says nothing about MokList.

**Script mode** (tests only: the password sits in plain text on the data
partition):
```json
{"action": "trust-ubuntu", "step": "next", "password": "1234abcd", "then": "poweroff", "on_error": "poweroff"}
```
`step` is `next` (the one request the two-step rule allows now) or `delete`.

**Tests:** `beastnet/tests/test_trust.py` (a fake efivarfs folder and a stub
mokutil, `beastnet/tests/stub_mokutil.py`) and
`tests/e2e/test_e2e_trust_ubuntu.py`. The e2e test boots the helper under OVMF
with Secure Boot, powers off, and reads the VM's variable store with
`virt-fw-vars`; it needs KVM. On a drive whose shim has Canonical's CA built in
(the 0.1.1 chain), set `BB_E2E_DEBIAN_SHIM` to Debian's pinned
`shimx64.efi.signed` so the test can run the two-step check.
