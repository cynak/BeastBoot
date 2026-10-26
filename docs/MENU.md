# The boot menu

When you boot a BeastBoot drive you get a graphical GRUB menu in the
project's dark theme (see [Graphical menu](#graphical-menu)); where graphics
are not available, or with `bb_gfx=0`, the same menu appears as a plain GRUB
text menu. It works the same on legacy BIOS and UEFI (with or without Secure
Boot), on a normal screen and over a serial console. The menu is GRUB script only:
[`grub/grub.cfg`](../grub/grub.cfg) and [`grub/beast/`](../grub/beast/).
The runtime contract it implements is section 5 of
[ARCHITECTURE.md](ARCHITECTURE.md); how each ISO is booted is in
[ISO_SUPPORT.md](ISO_SUPPORT.md).

## Layout

The menu lists what is on the data partition (partition 1), starting at its
root folder.

Root menu, top to bottom:

1. folders, titled `<name>/`
2. ISO files, titled with the file name
3. tools:
   - `System: <manufacturer> <product> · UEFI · Secure Boot on` (or
     `· Legacy BIOS`): opens the [System information](#system-information)
     page. The title is built at boot from the firmware's SMBIOS data; it is
     always the first tool entry, right after the ISO files. Where a terminal
     cannot show `·` (serial console, text menu) the separator is ` - `.
   - `Download an ISO from a link`: starts the network helper (Ethernet or
     WiFi, HTTPS + checksum) that saves an ISO under `/downloads/` and boots it
     once; shown only when the helper is on the boot partition. See
     [BEASTNET.md](BEASTNET.md).
   - `Trust Ubuntu's Secure Boot key` (UEFI only, and only when the helper is
     on the boot partition): starts the same helper with
     `beastnet.action=trust-ubuntu`. In two steps, each confirmed in
     MokManager after a reboot, it adds Ubuntu's revoked keys to MokListX and
     then Ubuntu's key (Canonical's Master CA) to MokList, so Ubuntu-signed
     kernels boot with Secure Boot on. See
     [SECURE_BOOT.md](SECURE_BOOT.md#trust-ubuntus-secure-boot-key-optional).
   - `Secure Boot status / help`: whether Secure Boot is on and what that
     means for booting ISOs
   - `Enroll a key (MokManager)` (UEFI only): starts shim's MokManager
     (`EFI/BOOT/mmx64.efi` on the boot partition) so you can enroll a
     distribution's signing key
   - `UEFI firmware settings` (UEFI only): reboots into the firmware setup
     screen, if the firmware supports that
   - `Reboot`
   - `Power off`

A folder's menu, top to bottom:

1. `..` (back to the parent folder)
2. folders, `<name>/`
3. ISO files

Esc (and Backspace, the hotkey of `..`) also goes back to the parent folder.
The tools appear only in the root menu.

Within each group, entries are sorted by name in byte order (so `Zorin.iso`
comes before `arch.iso`). Files count as ISOs when the name ends in `.iso`,
in any letter case. Other files are not shown.

Never listed:

- anything whose name starts with `.`
- `beast-booter`, `System Volume Information`, `$RECYCLE.BIN`, `$Extend`
  (NTFS metadata) and `lost+found` (in any letter case, in any folder). The
  list is
  `DATA_HIDDEN_DIRS` in
  [`installer/beastbooter/layout.py`](../installer/beastbooter/layout.py)

Choosing an ISO boots it with the matching recipe. If that is not possible
(no recipe matches, a Windows ISO, or Secure Boot rejects the kernel), you
get a short explanation. Press Esc to return to the menu; when GRUB itself
printed an error, it asks you to "Press any key to continue..." instead.

A large folder takes a moment to open. The sort is done in GRUB script and
needs roughly one pass over the folder for every entry shown, so keep a few
hundred entries per folder at most. Other files (photos, documents) cost
time too, even though they are not listed.

## User configuration: `/beast-booter/config.cfg`

You can create `beast-booter/config.cfg` on the data partition (the folder
itself is hidden from the menu). It is GRUB script and is sourced after the
data partition has been found and before the menu is built, so plain `set`
lines are all you need:

```sh
# /beast-booter/config.cfg
set timeout=10                      # boot the first entry after 10 seconds
set default=2                       # ...which is the third entry (0-based)
set bb_autoboot="/linux/ubuntu-24.04.iso"
set bb_serial=1
```

| Setting | Effect |
|---|---|
| `timeout=N` | standard GRUB menu timeout for the root menu, in seconds. Default: none, the menu waits for you. GRUB then runs the `default` entry (the first one unless `default` is set); if that entry is a folder, GRUB opens it. |
| `default=N` or `default="title"` | standard GRUB default entry of the root menu |
| `bb_autoboot=/path/x.iso` | skip the menu and boot that ISO straight away. If that fails, or it is a dry run, you get the menu afterwards. The path is relative to the data partition root; a missing leading `/` is added. |
| `bb_serial=1` | also show the menu on serial port 0 (COM1) at 115200 8N1 and accept keys from it. The installer can set this for you with `--serial-console`. |
| `bb_debug=1` | print machine-readable `BEAST:` lines (for tests and bug reports), see below |
| `bb_dryrun=1` | do everything except actually starting the kernel or boot loader: print what would be run and return to the menu |
| `bb_gfx=0` | no graphics: the plain text menu, exactly as on a console without graphics |
| `bb_gfxmode=WxH` | screen mode(s) for the graphical menu, a GRUB `gfxmode` list such as `1280x720` or `1024x768,auto`. Default: `1920x1080,1280x720,1024x768,auto` (the first mode the firmware offers) |
| `bb_theme=/path/theme.txt` | use your own GRUB theme file from the data partition instead of BeastBoot's (see [Changing the look](#changing-the-look)) |
| `bb_fs_addon=0` | do not use the [exFAT add-on](ISO_SUPPORT.md#the-exfat-add-on): casper and live-boot ISOs on an exFAT drive are started exactly as on FAT32 (with the ISO's own `loopback.cfg`). Default: on |
| `bb_kargs="word ..."` | extra kernel parameters added at the end of the command line of every ISO started by one of BeastBoot's own Linux recipes (casper, live-boot, archiso, dracut-live, anaconda, suse), for example `bb_kargs="console=ttyS0,115200"`. Not added for an ISO started with its own `loopback.cfg` (GRUB cannot change those lines), for Windows or EFI loaders, or for the network helper. Default: empty. Used by the real-ISO tests ([tests/e2e/REAL_ISOS.md](../tests/e2e/REAL_ISOS.md)) |
| `bb_windows=pe` | for `bb_autoboot` of a Windows installation ISO: start its Windows PE command prompt instead of Windows Setup. From the menu you choose in a small menu instead. Default: `setup` |
| `bb_beastnet_script=/path/plan.json` | start the network helper in script mode with this JSON plan (a path on the data partition) instead of asking questions; see [BEASTNET.md](BEASTNET.md) §5 |

The same `bb_*` settings may also be put in `grub/beast/device.cfg` on the
boot partition (it is GRUB script too, sourced before the menu starts). That
is the only way to get `bb_debug` output when the data partition itself is
missing; values from `config.cfg` win when both set one.

The file is GRUB script, so a syntax error there shows up as a GRUB error
at boot. Anything not listed above is passed through to GRUB unchanged. It is
your file: BeastBoot's installer and updater never write to the data
partition.

## Debug output (`bb_debug=1`)

With `bb_debug=1` the menu prints one machine-readable line per event. Every
line starts with exactly `BEAST: `:

```
BEAST: ready version=0.1.2 platform=efi sb=0 esp=hd0,msdos2 data=hd0,msdos1 fs=exfat
BEAST: dir /
BEAST: item dir /Some Folder
BEAST: item iso /ubuntu-24.04.iso
BEAST: boot /ubuntu-24.04.iso recipe=loopback
BEAST: error no-recipe /mystery.iso
```

- `ready` is printed once, after the data partition was looked up and the
  user configuration read. Without a data partition it says `data=none fs=none`
  and is followed by `BEAST: error no-data-partition ...`.
- `dir <path>` followed by its `item` lines is printed every time a menu for
  that folder is shown, including when you come back to it with `..` or Esc.
  The root menu is `/`. Items come in menu order (`..` and the tools are not
  listed). A blank line is printed before `ready`, `dir` and `boot`, so the
  line never shares a raw serial line with the escape codes of the screen
  GRUB just cleared.
- GRUB word-wraps output at the terminal width. On a serial console
  (`bb_serial=1`) BeastBoot sets the width to 1024 columns when
  `bb_debug=1`, so `BEAST:` lines stay on one line; on the UEFI console the
  width is whatever the firmware offers (160 columns in QEMU/OVMF), so very
  long paths can still wrap there.
- `boot <iso path> recipe=<id>` is printed when an ISO is chosen, after
  detection. The id is one of the recipe ids in
  [ISO_SUPPORT.md](ISO_SUPPORT.md), or `none`.
- `fsmod exfat <module path>` follows `boot` when the
  [exFAT add-on](ISO_SUPPORT.md#the-exfat-add-on) is used; the module path is
  inside the ISO's squashfs, for example
  `(bbsq)/usr/lib/modules/7.0.0-30-generic/kernel/fs/exfat/exfat.ko.zst`.
  `fsmod none <reason>` says why it is not used: `disabled` (`bb_fs_addon=0`),
  `hook-missing`, `no-squashfs`, `squashfs-unreadable <squashfs>` (for example
  zstd-compressed) or `no-exfat-module <squashfs>`. Nothing is printed when the
  data partition is not exFAT or the ISO is not a casper / live-boot ISO.
- `error <code> <text>` codes: `no-data-partition`, `iso-not-found`,
  `loopback-failed`, `no-recipe`, `ntfs-unsupported`, `windows-sb` (Secure Boot is on: Windows
  ISOs need it off), `windows-no-wimboot`, `grubenv-not-writable`,
  `sb-verify-failed`, `boot-failed`. The text after the code is for people, not parsers. Under
  Secure Boot, any failure of `linux`, `initrd`, `chainloader` or `boot` is
  reported as `sb-verify-failed`; without Secure Boot it is `boot-failed`.

## Dry runs (`bb_dryrun=1`)

A dry run stops just before the hand-off and prints what it would have run,
then returns to the menu (or, with `bb_autoboot`, shows the menu). These
lines are printed whenever `bb_dryrun=1`, even without `bb_debug`:

```
BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper "iso-scan/filename=/Some Folder/My Distro.iso" quiet splash ---
BEAST: dryrun initrd (loop)/casper/initrd
BEAST: dryrun configfile (loop)/boot/grub/loopback.cfg
BEAST: dryrun chainloader (loop)/EFI/BOOT/BOOTX64.EFI
```

The kernel is shown as the GRUB path that would be loaded, followed by the
complete kernel command line. A parameter that contains spaces is shown in
double quotes, exactly as GRUB hands it to the kernel. For the loopback
recipe the ISO's own `loopback.cfg` is not run in a dry run. "Enroll a key
(MokManager)" also honours `bb_dryrun`.

## Display and serial console

In text mode (`bb_gfx=0`, or when the graphical menu could not start) the
menu needs no fonts or graphics, so it works on any console. The graphical
menu replaces only the firmware console: the serial console keeps showing
the text menu. With `bb_serial=1` (from `device.cfg` or the user configuration)
the menu runs `serial --unit=0 --speed=115200` and, only if that succeeds,
`terminal_input console serial` and `terminal_output console serial`.

On UEFI the firmware itself often mirrors its console to the serial port
(QEMU's OVMF does), so in text mode you may see the menu on serial even
without `bb_serial` (the graphical menu does not use the firmware console). Turning `bb_serial` on there as well can show every character
twice.

## Graphical menu

When the firmware offers a graphics mode, `main.cfg` switches to GRUB's
graphical terminal and theme (`bb_gfx_init` in `lib.cfg`) after reading the
user configuration and after a `bb_autoboot` attempt, just before the menu
is built:

- dark grey background with a soft red glow (colours:
  [assets/BRAND.md](assets/BRAND.md)), the logo, the name (`beast-booter`) and
  version at the top, and badges for the firmware mode and Secure Boot
  state (`UEFI` + `Secure Boot on` / `off`, or `Legacy BIOS`). A theme file
  cannot show variables, so there is one theme per badge set
  (`theme-efi-sb.txt`, `theme-efi.txt`, `theme-pc.txt`) and the menu picks
  one by `bb_platform` and `bb_sb`;
- the entries in a rounded panel with a highlighted selection and an icon
  per entry: folders, `..`, discs for ISO files (tinted for Ubuntu, Debian,
  Fedora/RHEL, Arch, openSUSE, Mint and other Linux names; Windows gets its
  own icon), and the tools. The icon is chosen from the file name only;
  how an ISO is booted does not depend on it;
- a progress bar and "The highlighted entry starts in N s" while a
  `timeout` runs, and key hints at the bottom (↑ ↓ select, Enter boot /
  open, Esc back, c GRUB console);
- pages such as System information, Secure Boot help and error messages,
  and the GRUB console, appear in a box in place of the panel.

The layout is in percentages and fits 1024x768 to 1920x1080 (the panel is
a centred card, at least as wide as GRUB's 80-column console window). The
screen mode is the first of `1920x1080,1280x720,1024x768,auto` the firmware
offers; `bb_gfxmode` changes that. `gfxpayload` is not set, so a kernel is
started the way GRUB does by default: in text mode on legacy BIOS (as
without graphics) and, on UEFI, in the menu's graphics mode (UEFI has no
text mode; the kernel's EFI framebuffer driver takes it over).

If any step fails - theme or font missing, a GRUB module that does not
load, no usable graphics mode - the menu stays the text menu and nothing
else changes. To switch graphics off yourself:

```sh
# /beast-booter/config.cfg
set bb_gfx=0
```

What is on the boot partition, all listed in `manifest.json`:

- `grub/themes/beast/`: the theme files, `console.cfg` (console colours)
  and the images. Every image is drawn at build time by
  [`build/theme/mktheme.py`](../build/theme/mktheme.py) (Python standard
  library: a small vector rasteriser and a zlib PNG writer, no randomness,
  no timestamps), so every pixel can be reproduced from source; two builds
  give byte-identical files.
- `grub/fonts/NotoSans-*.pf2`, `NotoSansMono-Regular-16.pf2`: made with
  `grub-mkfont` from Noto Sans / Noto Sans Mono in Ubuntu's
  `fonts-noto-core` / `fonts-noto-mono` (SIL Open Font License 1.1). Text
  inside images (name, badges, key hints) is drawn with the same glyphs.
- The same Noto fonts are also in a memdisk inside the signed
  `EFI/BOOT/grubx64.efi`: with Secure Boot on, Ubuntu's GRUB refuses font
  files from disk (they are not signed) and loads fonts only from the
  memdisk of its own image, which shim has verified. The copies in
  `grub/fonts/` are for legacy BIOS. The memdisk is a deterministic tar
  made by [`build/theme/mkmemdisk.py`](../build/theme/mkmemdisk.py) from
  those files (manifest: `build.efi_memdisk`, `build.efi_memdisk_sha256`).
  Theme files and images are not fonts and load from disk in every mode.
- Characters the Noto fonts lack (other scripts in file names) come from
  GRUB's `unicode.pf2`, except with Secure Boot on, where it cannot be
  loaded from disk; such characters then show as boxes.

### Changing the look

- Colours: edit `PALETTE` at the top of `build/theme/mktheme.py` (hex
  colours; `console_text` is a GRUB colour name such as `white` or
  `light-gray`) and rebuild with `make build`. Sizes and layout are the
  constants below it and `theme_text()`.
- Your own theme without rebuilding: put a GRUB theme on the data partition
  and set `bb_theme`, for example `set bb_theme=/beast-booter/mytheme/theme.txt`.
  Its images are found relative to the theme file. Fonts available to it:
  `Noto Sans Regular 16`, `Noto Sans Regular 20`, `Noto Sans Bold 20`,
  `Noto Sans Mono Regular 16` (and `GNU Unifont Regular 16` without Secure
  Boot). GRUB parses that theme and its PNG files like any other file it
  reads; nothing about Secure Boot verification changes.

## System information

The `System: ...` entry shows what GRUB can read about the machine, mostly
from the firmware's SMBIOS tables:

- system manufacturer, product, version, family, serial number and UUID
  (SMBIOS type 1), baseboard (type 2, if the firmware provides one),
  firmware vendor, version and release date (type 0);
- each populated processor socket: its version string (type 4), cores,
  threads and current / maximum speed, and whether the CPU can run 64-bit
  code (`cpuid -l`);
- each populated memory slot (type 17, up to 8 listed): size, type
  (DDR4, DDR5, ...), speed and manufacturer, and the total over all
  modules with the number of used slots. GRUB script has no arithmetic, so
  the total is added up digit by digit (`bb_add` in `lib.cfg`);
- boot mode (UEFI or legacy BIOS), Secure Boot / GRUB lockdown state, the
  firmware clock (`date`, usually UTC), and whether the graphical menu or
  the text console is used (GRUB cannot report the exact screen mode it
  picked, so the page shows the `gfxmode` list it picked from);
- BeastBoot version and build id, the data partition (device,
  filesystem, label, UUID) and the boot partition with its partition table.

Values the firmware does not report show as `unknown`, never as errors:
GRUB prints an error for every failed `smbios` lookup, so the scripts walk
the SMBIOS table by position and check each structure's length and each
string's index before reading a field. Real firmware often fills unused
fields with placeholders such as `To be filled by O.E.M.` or `Default
string`; the page shows them as they are, the entry title leaves them out.
Esc returns to the menu.

## How navigation works (for people changing the scripts)

- `main.cfg` finds the devices, reads the user configuration and builds the
  root menu (it is part of `grub.cfg`'s own menu).
- Choosing a folder calls `bb_enter`, which runs `normal level.cfg`: one
  GRUB normal-mode level deeper. `level.cfg` loads `browse.cfg` with
  `configfile`, which gives the folder its own menu and variables and makes
  Esc return.
- `..` calls `normal_exit`, which makes GRUB close every menu of the current
  normal-mode level, so `..` and Esc both land on the parent menu and the
  nesting never gets deeper than the folder you are in. `nav-exit.cfg` and
  `nav-up.cfg` redefine `bb_after_menu`, which tells `level.cfg` whether it
  still has to call `normal_exit` itself (after Esc) or `..` already did.
  (In GRUB a `function` definition takes effect when it is parsed, so the
  only way to swap it at run time is to `source` a file.)
- A Windows installation ISO chosen in the menu opens `windows.cfg` with
  `configfile` (Install Windows / Windows PE command prompt); Esc returns
  to the folder. `bb_r_windows` exports `bb_iso` for it, and the ISO stays
  open as `(loop)`.
- Functions are global in GRUB but variables are per `configfile` context,
  so everything the scripts need is exported (`bb_*`).
- File names come from GRUB's `*` wildcard (the `regexp` module), which
  returns names in on-disk order and the pattern itself when a folder is
  empty; `bb_scan` sorts and filters.
- Entry icons come from `--class`: the first class of an entry that has an
  icon (`grub/themes/beast/icons/<class>.png`) is used, so ISO entries are
  `--class=<family> --class=iso` (`bb_iso_class`). The text menu ignores
  classes.
- `menuentry` passes the entry title as `$1`, so the path given to an entry
  is `$2`. Titles and `regexp` subjects are passed after `--`, so a file
  name that starts with `-` is not taken for an option.
