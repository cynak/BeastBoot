# Real-ISO boot checks (0.2.0)

Goal: prove that real, official ISOs of each supported family **really boot**
from a BeastBoot drive: the ISO's own system starts, from the ISO file on
the data partition. Modes: UEFI and BIOS, Secure Boot off. ESXi is out of
scope.

This file is the contract between the parts built in parallel. Keep it in
sync with the code.

## Running

```
BB_REAL_ISO=1 pytest -q tests/e2e/test_e2e_real_isos.py            # every catalog entry
BB_REAL_ISO=1 BB_REAL_IDS=fedora-ws-live,win11-eval pytest -q ...  # a subset
BB_ISO_<ID>=/path/to.iso                                           # use a local copy (ID upper-case, other chars -> _)
BB_REAL_PARALLEL=2                                                 # drives booted at the same time (default 2)
```

Without `BB_REAL_ISO=1` the tests skip, like the `BB_LIVE_NET=1` tests.
Downloads go to `.tools/cache/real-isos/<id>/` (resumable, one at a time,
`flock` on `<id>/.download.lock` so runs can share the cache) and are
verified against the vendor's checksum before every use; a local copy
(`BB_ISO_<ID>`) is verified the same way. They need KVM. `BB_REAL_CACHE` and
`BB_REAL_OUT` move the cache and `out/real`; `BB_E2E_KEEP=1` keeps the drives.

How a case runs (`tests/e2e/bbe2e/realiso.py`): one drive per (ISO, fs),
installed with `--serial-console` (msdos layout, sparse image of ISO size +
2 GiB), the ISO copied to the root of the data partition, `config.cfg` with
`bb_debug=1`, `bb_kargs` and `timeout=5` (exported, so an ISO's own
`loopback.cfg` menu boots its default entry), and `bb_oneshot` in grubenv.
Each mode boots a QEMU snapshot of that drive (KVM, `-cpu host`, `smp` 2,
`ram_mb`), so both modes start from the same drive.

## Catalog: `tests/e2e/real_isos.json`

```json
{"v": 1, "isos": [{
  "id": "fedora-ws-live",            "family": "dracut",
  "name": "Fedora Workstation 44 Live", "version": "44",
  "url": "https://...iso",
  "sha256": "<hex>" | null, "sha256_url": "https://...CHECKSUM" | null,
  "sha512_url": "https://...sha512",   // optional: vendors that publish only SHA-512 (Leap 16)
  "file": "name.iso",                  // optional: file name when the URL does not end in it (fwlink)
  "sha256_source": "...",              // optional: where a pinned "sha256" was published
  "unverifiable": "reason",            // instead of a checksum: the vendor publishes none, case = skip
  "size": 2400000000,
  "recipe": "dracut-live",             // what the menu must detect (BEAST: boot ... recipe=); null: not decided yet
  "modes": ["uefi", "bios"],          // BIOS only where the ISO supports BIOS
  "fs": ["exfat"],                     // data filesystems to test; "ntfs" too for Windows
  "ram_mb": 4096, "timeout_s": 600,
  "recipe_fs": {"fat32": "loopback"}, // optional: recipe per data fs where it differs (exFAT uses the menu's add-on route, so casper/live-boot there but the ISO's loopback.cfg on FAT32/NTFS)
  "kargs": "console=ttyS0,115200",    // appended through bb_kargs (Linux only)
  "success": ["regex", ...],           // ALL must appear on the serial log (Linux), or
  "result": ["^winpe-ok\\s*$"],          // regexes (multi-line mode), ALL must match RESULT.TXT on BBTEST (Windows)
  "fail": ["regex"], "smp": 2          // optional: extra fail-fast regexes, CPUs
}]}
```

A checksum file (`sha256_url`, `sha512_url`) is fetched on every run, so a
re-released ISO under the same link is caught; offline, the value recorded at
the last download (`<id>/meta.json`) is used. The line for the ISO is picked
by file name; a file with a single line applies to the download (Tumbleweed
`-Current` links: the line names the snapshot, which is also the cache name).

`success` must prove the ISO's **own userspace or installer started from the
ISO**, not just a kernel: for example a live system's systemd "Reached
target" line plus its login prompt, Anaconda's "Starting installer" after
stage2 was found, debian-installer's or Agama/linuxrc's first screen after
the medium was found. A kernel banner alone never counts, and neither does a product name: the
ISO's own GRUB menu is drawn after `BEAST: boot`, so a bare "SystemRescue"
matches its menu entries. Anchor markers to what only the running system
prints (a getty banner such as `^Arch Linux \S+ \(ttyS0\)`, a login prompt,
installer text).

Oracle (Linux), in this order; any failed step is a `fail`:

1. A `BEAST: ready` record must exist, with the case's platform (`efi` or
   `pc`), `sb=0` and `fs=` equal to the case's data filesystem. No record:
   "no BEAST: ready record".
2. Exactly one `BEAST: boot <iso> recipe=<r>`. Two or more: "booted more than
   once" (the config exports `timeout=5`, so a failed attempt re-boots).
3. `recipe` in the catalog must be set and equal `<r>`; `null` fails with
   "recipe not pinned" (a recipe must be decided before an ISO can pass).
4. Every success regex must match in the text after the boot record, with all
   `BEAST:` records, kernel `Command line:` echoes and GRUB menu redraw lines
   ("Press enter to boot the selected OS", "automatically in", "Use the ^ and
   v keys") removed.
5. No fail-fast match (and no `BEAST: error`) may start before the end of the
   last required success match. Fail-fast: `Kernel panic - not syncing`,
   `Entering emergency mode`, `(initramfs)` prompt, casper's or live-boot's
   "Unable to find a ... live file system", linuxrc's "No repository found.",
   shim's "Aborted. Press any key to exit.", GRUB's "Failed to boot both
   default and fallback entries", "can't find command" or its command shell,
   plus `fail`. Before all markers matched, any of them ends the case at once.

No success within `timeout_s` is `timeout`. A checksum file that no longer
lists the ISO is `fail` ("catalog stale"); only an explicit `unverifiable`
reason skips. FAT32 cases skip for ISOs over 4 GiB. The ISO is copied once
more to a private file while its SHA-256 is checked again, and that copy goes
on the drive.

Windows oracle: the `result` regexes must match RESULT.TXT in the order
listed (each after the end of the previous match), plus steps 1-3 above. Marker
names the start-up script writes: `iso-mounted <L>: ... install.(wim|esd)` only
after `<L>:\sources\install.wim|esd` was checked to exist, and `setup-running`
only after `tasklist` shows `setup.exe` running from that mounted letter
(`setup-started` only says it was launched).

Serial output from ISOs started with their own `loopback.cfg`: GRUB cannot
add `bb_kargs` there (a command always wins over a function of the same
name, so `linux` cannot be wrapped). The harness therefore passes the
systemd credential `getty.ttys.serial=ttyS0` as an SMBIOS type 11 string
(`-smbios type=11,value=io.systemd.credential:getty.ttys.serial=ttyS0`):
systemd 254+ then starts a login prompt on ttyS0, which proves the ISO's own
systemd came up even without `console=ttyS0`. If that ISO's GRUB menu still
waits without a countdown after 30 s, the harness presses Enter once (QMP).

## Menu hooks (grub/beast)

- `bb_oneshot` in `($esp)/grub/grubenv` (exists): the harness writes the
  ISO path; the menu boots it once (`bb_autoboot`).
- `bb_kargs` (new): words appended to the kernel command line of every ISO
  recipe that GRUB starts itself (casper, live-boot, archiso, dracut-live,
  anaconda, suse), not to an ISO's own `loopback.cfg` (see the oracle above),
  Windows, EFI chainloading or beast-net. Set in a test config only; empty
  by default (docs/MENU.md).
- `bb_debug=1` (exists) keeps the `BEAST:` lines on the serial console;
  the drive is installed with `--serial-console`.

## Windows (wimboot)

What the build ships (build/wimboot/, build/winpe/; `BB_SKIP_WIMBOOT=1` leaves it out):

| ESP file | what |
|---|---|
| `beast-booter/wimboot` | iPXE wimboot 2.9.0 + our patches (`2.9.0+bb1`), built from pinned source. One x86_64 hybrid image: GRUB `linux16` on BIOS, `linux` on UEFI. Unsigned. |
| `beast-booter/winpe/winpeshl.ini` | injected: makes Windows PE run `beastboot.cmd` instead of its default shell |
| `beast-booter/winpe/beastboot.cmd` | injected: the start-up script (below) |
| `beast-booter/winpe/beastmount.exe` | injected (setup mode): attaches the ISO read-only. **Not built yet**: source in `build/winpe/beastmount.c`, needs a pinned MinGW-w64 build step (decision pending) |

Why the patches: upstream wimboot on UEFI reads its files only from the
file system of its own device. GRUB 2.12+ `linux` starts an EFI image from
memory (no such device) and passes the `initrd newc:` files through
`EFI_LOAD_FILE2_PROTOCOL`, and only for images with PE `MajorImageVersion >= 1`;
otherwise it uses its legacy loader, which exits boot services. Patch 0001
reads the LoadFile2 initrd, 0002 sets the image version, 0003 adds an SBAT
vendor line. BIOS works unpatched (`linux16` + `initrd16`).

Secure Boot: wimboot is unsigned, so with Secure Boot on the recipe must not
try it; it shows `BEAST: error windows-sb` ("turn Secure Boot off to boot
this Windows ISO") instead. (Upstream's Microsoft-signed release binary is
unpatched, so it cannot boot from GRUB on UEFI either.)

### Recipe (phase 2, grub/beast/lib.cfg)

Detection stays as now: `/sources/boot.wim` (case-insensitive). Official
Microsoft ISOs are UDF bridges whose ISO9660 view holds only `README.TXT`:
GRUB must read them with `udf` (both platforms already have it; with
`iso9660` and `udf` both present GRUB picked UDF in the check below).
BIOS: add `linux16` to the `insmod` list in main.cfg.

Two menu variants: **setup** (default for install media) and **pe**.
`index=` picks the image in boot.wim: none = the WIM's boot index (Windows
install media: 2, "Microsoft Windows Setup"); `index=1` = "Microsoft Windows
PE". WinPE/WinRE ISOs with one image boot as is: no injected files (their
own winpeshl.ini/startnet.cmd run). Tests may inject in pe mode to get
`winpe-ok`.

```
# $bb_iso = ISO path on ($bb_data), e.g. /Win11.iso; bb_sb = 1 under Secure Boot
if [ "$bb_sb" = "1" ]; then bb_err windows-sb "$bb_iso"; return; fi
set bb_winpe_iso="$bb_iso"
set bb_winpe_mode="setup"                 # or "pe"
# the start-up script reads both from the env block GRUB injects as beastboot.txt
if ! save_env --file "($bb_esp)/grub/grubenv" bb_winpe_iso bb_winpe_mode; then
  bb_err grubenv-not-writable "$bb_iso"; return
fi
loopback loop "($bb_data)$bb_iso"
set bb_w="($bb_esp)/beast-booter"
set bb_w_args=""                          # setup
if [ "$bb_winpe_mode" = "pe" ]; then set bb_w_args="index=1"; fi
set bb_w_inj="newc:winpeshl.ini:$bb_w/winpe/winpeshl.ini newc:beastboot.cmd:$bb_w/winpe/beastboot.cmd newc:beastboot.txt:($bb_esp)/grub/grubenv newc:beastmount.exe:$bb_w/winpe/beastmount.exe"
if [ "$grub_platform" = "pc" ]; then
  linux16 $bb_w/wimboot $bb_w_args
  initrd16 newc:boot.wim:(loop)/sources/boot.wim $bb_w_inj
else
  linux $bb_w/wimboot $bb_w_args
  initrd newc:boot.wim:(loop)/sources/boot.wim $bb_w_inj
fi
boot
```

- Only `boot.wim` is passed: wimboot 2.9.0 takes bootmgr (BIOS:
  `\Windows\Boot\PXE\bootmgr.exe`), bootmgfw(_EX).efi, BCD
  (`\Windows\Boot\DVD\{PCAT,EFI}\BCD`), boot.sdi, boot.stl and the fonts from
  the WIM itself (seen with Windows 11 26H2). For a WIM without them, add the
  ISO's files: BIOS `newc:bootmgr:(loop)/bootmgr newc:bcd:(loop)/boot/bcd
  newc:boot.sdi:(loop)/boot/boot.sdi`; UEFI `newc:bootx64.efi:(loop)/efi/boot/bootx64.efi
  newc:bcd:(loop)/efi/microsoft/boot/bcd newc:boot.sdi:(loop)/boot/boot.sdi`.
- Words in `$bb_w_inj` are split by GRUB, so ESP paths must not contain
  spaces (they do not). `bb_kargs` does not apply (wimboot rejects unknown
  arguments); debug mode may add `pause`. wimboot prints to ConOut: the
  screen, and on OVMF also the serial console (on BIOS: screen only).
- `save_env` needs `grub/grubenv` on the ESP (the installer creates it,
  `update` keeps it); it rewrites that 1 KiB block on each Windows boot.
- Memory: GRUB reads boot.wim into RAM, wimboot keeps it there and bootmgr
  copies it into its RAM disk: about 2 x boot.wim + 1 GB. Windows 11 26H2
  (boot.wim 610 MB) ran with 4 GB (pe) and 6 GB (setup); use `ram_mb` >= 4096.

### Start-up script (`beastboot.cmd`)

1. Reads `bb_winpe_iso` and `bb_winpe_mode` from `X:\Windows\System32\beastboot.txt`
   (the GRUB env block: `name=value` lines, `#` padding). No file: pe mode.
2. Looks for a disk labelled `BBTEST`; if there is one, appends lines to
   `\RESULT.TXT` on it.
3. **pe**: logs `winpe-ok`, runs `X:\sources\recovery\recenv.exe` if the image
   has it, then always a shell (`cmd /k startnet.cmd`), because Windows PE
   restarts the PC when the script ends.
4. **setup**: runs `wpeinit` (a custom winpeshl.ini skips it), logs
   `winpe-ok`, finds the data partition as the drive letter where the ISO
   path exists (retries 40 s for slow USB), runs
   `beastmount.exe <letter>:\path\to.iso`, waits for the new drive with
   `sources\install.wim|esd|swm`, logs `iso-mounted <letter>:`, logs
   `setup-started` and runs `<letter>:\setup.exe` (Microsoft's documented
   way to install from WinPE). When Setup ends, a command prompt opens.
5. Any failure: logs `fail <reason>: <plain words>`, shows the same text and
   opens a command prompt. Reasons: `no-iso-path`, `iso-not-found`,
   `no-mount-tool`, `attach-failed`, `no-media`, `no-setup`, `unknown-mode`.

It never writes to the data partition. Names with `&`, `%`, `!`, `(`, `)`
are handled (quoted, no delayed expansion on user data); non-ASCII names
rely on `chcp 65001` (untested).

**Attaching the ISO: no built-in way in Setup's Windows PE.** Checked in
Windows 11 26H2 boot.wim index 2: `diskpart` `select vdisk file=X:\..\win.iso`
fails with "The parameter is incorrect" (diskpart opens only VHD/VHDX; a VHD
on the same exFAT data partition attaches fine, and diskpart still exits 0
after the failure); there is no PowerShell (`Mount-DiskImage`), no `wmic`,
and the `root\Microsoft\Windows\Storage` WMI namespace has no
`MSFT_DiskImage` class (cscript exists, but VBScript cannot call the API).
`virtdisk.dll` and `vhdmp.sys` are there, so the VirtDisk API
(`OpenVirtualDisk(VIRTUAL_STORAGE_TYPE_DEVICE_ISO, VIRTUAL_DISK_ACCESS_READ)`
+ `AttachVirtualDisk(READ_ONLY | PERMANENT_LIFETIME)`) works: that is
`beastmount.exe` (about 90 lines of C; Ventoy's vtoyjump does the same).
Without it, setup mode stops with `fail no-mount-tool`.

### Manual chain check (2026-10-25, worktree build, test image only)

Windows 11 Enterprise 26H2 evaluation, x64 en-US
(`26300.9457.260913-1737...CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso`,
8 225 329 152 bytes, SHA-256 `bc3f2408...0e38` = Microsoft's value on
aka.ms/VerifyWindowsISO). GPT drive, exFAT data partition, the ISO at
`/Win11_26H2_eval.iso`, the recipe above in `/beast-booter/config.cfg`,
QEMU q35 + KVM, drive and BBTEST on AHCI, Secure Boot off, `beastmount.exe`
built from `build/winpe/beastmount.c` (MinGW-w64 13) put on the ESP by hand.

| firmware | mode | RAM | RESULT.TXT | reached |
|---|---|---|---|---|
| UEFI (OVMF) | setup | 6 GB | `winpe-ok`, `iso-mounted E:`, `setup-started` | Windows 11 Setup "Select language", then "Select setup option" |
| BIOS (SeaBIOS) | setup | 6 GB | `winpe-ok`, `iso-mounted E:`, `setup-started` | Windows 11 Setup "Select language" |
| UEFI (OVMF) | pe (`index=1`) | 4 GB | `winpe-ok` | the Windows PE shell (startnet.cmd ran wpeinit). A first version looped: index 1 has `recenv.exe`, which returns at once there, the script ended and Windows PE restarted; now a shell always follows |
| UEFI, diskpart instead of beastmount | setup | 6 GB | `winpe-ok` | stops at the attach: "The parameter is incorrect" |

UEFI serial log: GRUB found `(loop)/sources/boot.wim` through UDF;
`wimboot v2.9.0+bb1`, `...loaded initrd at [...] via LoadFile2`, WIM patched
(injected files), `Loaded bootmgfw_EX.efi as BOOTX64.EFI`, then bootmgr's
"Loading files...".

### Test disk `BBTEST`

A test attaches a small MBR disk with one FAT32 partition labelled `BBTEST`
(128 MiB: `sfdisk` + `mformat -F -v BBTEST`). Windows PE has no virtio
drivers: attach it, and the BeastBoot drive, on AHCI (q35 `ide-hd`) or USB.
The script appends CRLF lines to `\RESULT.TXT`; read it with
`mtype -i bbtest.img@@1M ::RESULT.TXT` (after power-off, or while running:
Windows writes it within seconds). Without that disk, nothing is written.

Harness side of the test disk:

- Test disk `BBTEST` (harness side, fixed): 64 MiB, MBR, one FAT32 partition
  at 1 MiB labelled `BBTEST`, on AHCI (`ide-hd`, bus `ide.2`); `\ID.TXT` holds
  the case id `<id>-<mode>-<fs>`. The case ends when QEMU powers off (or at
  `timeout_s`); then the harness reads `\RESULT.TXT`.

## Results

Each case (id, mode, fs) appends one JSON line to `out/real/results.jsonl`:
`{"id", "mode", "fs", "status": "pass|fail|timeout|skip", "recipe", "matched": [...], "reason", "log", "seconds", "iso_sha256", "beastboot_version", "expected_recipe", "when"}`.
The serial log of a case is `out/real/logs/<id>-<mode>-<fs>.log` (plus
`.qemu.txt` with the command line and `.screen.txt`, and a `.png` screendump
when the case did not end by itself).
Summaries use `realiso.latest_results()` (`python -m bbe2e.realiso` from tests/e2e): the
latest row per (id, mode, fs) for the current beastboot_version and ISO hash.
docs/ISO_SUPPORT.md marks an ISO "tested (real ISO)" only from a pass here.
