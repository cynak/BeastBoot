# Windows ISOs with Secure Boot on (0.4.0 interface)

Source of truth for the menu (grub/), the beast-net helper (beastnet/) and the
host tool (installer/). Change it only together with all three.

## Why

With Secure Boot on, GRUB runs in lockdown and GRUB 2.14 disables its UDF driver
(`grub-core/fs/udf.c`). Microsoft ISOs are UDF bridges whose ISO9660 view holds
only `README.TXT`, so the menu cannot see `sources/boot.wim`. The fix: copy
`sources/boot.wim` once to the data partition (FAT32 or exFAT, which GRUB reads
in lockdown) and boot that copy with the BeastBoot-signed wimboot. The copy needs
no trust of its own: the firmware verifies the boot manager wimboot finds inside
`boot.wim`, and Windows verifies what it loads. Windows Setup still reads the ISO
itself in Windows PE (beastmount), so only `boot.wim` is copied.

With Secure Boot off nothing changes: the menu reads the ISO directly over UDF.

## Layout on the data partition

For an ISO at data-partition path `<iso>` (absolute, as the menu's `$bb_iso`,
e.g. `/isos/Win11.iso`):

```
/beast-booter/winboot<iso>/boot.wim    copy of the ISO's sources/boot.wim (looked up case-insensitively)
/beast-booter/winboot<iso>/iso-head.bin  the ISO's bytes 32768..98303 (64 KiB: volume descriptors), its identity
/beast-booter/winboot<iso>/stamp.env   GRUB environment block, written LAST (the copy counts only once it exists)
```

e.g. `/beast-booter/winboot/isos/Win11.iso/boot.wim`.

`stamp.env` is a standard 1024-byte GRUB environment block (`# GRUB Environment
Block` header, `key=value` lines, `#` padding; the format of
`beastnet/python/beastnet/grubenv.py`). Keys:

| key | value |
|---|---|
| `bb_wb_iso` | `<iso>` (the path it was made for) |
| `bb_wb_kind` | `setup` if the ISO has `sources/install.wim`, `.esd` or `.swm` (any case), else `native` |
| `bb_wb_size` | size of `boot.wim` in bytes (decimal) |
| `bb_wb_by` | `helper <version>` or `host <version>` |

Writers: write `boot.wim.part`, fsync, rename to `boot.wim`; same for
`iso-head.bin` (`.part`); then write `stamp.env.tmp`, fsync, rename to
`stamp.env`; fsync the directory. Before writing, delete an existing `stamp.env`
first, then the old `iso-head.bin` and `boot.wim`. Never write
outside `/beast-booter/winboot/`.

The drive's contents are untrusted. Both writers use one implementation
(`installer/beastbooter/safedir.py`, shipped byte-identical as
`beastnet/python/beastnet/safedir.py`): every folder below the data root is
opened from its parent's descriptor with `O_DIRECTORY|O_NOFOLLOW` and created
with `mkdir` relative to it; temp files are created with
`O_CREAT|O_EXCL|O_NOFOLLOW`, renamed and deleted relative to the folder's
descriptor; a final check confirms the folder is where the path says. On
Windows (no `dir_fd`), each component is checked with `lstat` and refused if it
is a reparse point. A link, reparse point or non-regular file (e.g. a FIFO) in
the way stops the writer with nothing written there; a stale regular `.part`
or `.tmp` is deleted first (and its space counts as free).

### ISO identity

`iso-head.bin` = the ISO's bytes 32768 to 98303 (2048-byte sectors 16-47: the
ISO9660 volume descriptors with the volume size and dates, the UDF volume
recognition sequence and, on Microsoft ISOs, the UDF volume descriptors with their
recording time and volume set id). ISOs smaller than 98304 bytes are refused. The
menu compares it with `cmp "(loop)64+128" "<dir>/iso-head.bin"` (a GRUB blocklist
in 512-byte sectors; lockdown allows both). Not `probe --fs-uuid`: Microsoft ISOs
have an all-zero ISO9660 modification date, so GRUB returns no UUID for them.
The writers read these bytes themselves; nothing is passed from the menu.

## Menu (grub/)

When `bb_sb=1` and an ISO's recipe would be `none`:

1. If `($bb_data)/beast-booter/winboot$bb_iso/stamp.env` exists, read it with
   `load_env -f <file> bb_wb_iso bb_wb_kind` (an explicit variable list, never
   `source`). If `bb_wb_iso` = `$bb_iso`, `boot.wim` exists and
   `cmp "(loop)64+128" "<dir>/iso-head.bin"` succeeds: recipe `windows`, with
   `bb_wb_dir` set to that directory. (`cmp` is embedded via
   build/modules-efi.lst.)
2. Otherwise, if the ISO looks like a UDF bridge (`(loop)/README.TXT` exists and the
   ISO9660 view has no other recipe) and the helper is on the drive: the menu offers
   **Prepare this Windows ISO for Secure Boot**, record `BEAST: windows-prepare
   <iso>`. Choosing it writes `bb_wb_iso` to the ESP `grub/grubenv` (`save_env`) and runs `bb_beastnet winboot`. Without the helper:
   explain, error `windows-sb-no-helper`.
3. Otherwise `no-recipe` as today.

`bb_r_windows`: no Secure Boot refusal any more (`windows-sb` is removed). If
`bb_wb_dir` is set, install media = (`bb_wb_kind` = `setup`), and `bb_win_boot`
passes `newc:boot.wim:$bb_wb_dir/boot.wim` instead of
`(loop)/sources/boot.wim`; everything else (winpe files, grubenv hand-off with
`bb_winpe_iso`, setup/pe/native) is unchanged. If wimboot is refused (`linux`
fails), the usual `sb-verify-failed` explanation. If the firmware refuses the
ISO's boot manager, wimboot prints `Could not load …`; the menu cannot see it
(`boot-failed` at best), so docs explain it.

## Helper action `winboot` (beastnet/)

`beastnet.action=winboot`. Input from the ESP `grub/grubenv`: `bb_wb_iso`
(required; missing -> error screen, no writes). The helper reads `iso-head.bin`'s
bytes from the ISO file itself.

1. Validate `bb_wb_iso` as a string: absolute, no `..`, no control characters
   (`\x00-\x1f`, `\x7f`), `"`, backslash or non-UTF-8 bytes.
2. The data partition must be vfat or exfat (GRUB cannot read ntfs in lockdown):
   otherwise explain and stop. This comes before anything on the partition is
   looked at. `init` mounts it `nosuid,nodev,noexec`.
3. The ISO's real path must be inside `/mnt/data` and a regular file (not a
   link). Read it in userspace with the host tool's UDF reader
   (`installer/beastbooter/udf.py`, shipped byte-identical as
   `beastnet/python/beastnet/udf.py`, bounds-checked and fuzzed): no loop
   device, no kernel `udf`/`iso9660` mount, so nothing inside the ISO can point
   outside it. Find `sources/boot.wim` case-insensitively; none (or not UDF) ->
   "not a Windows ISO" / "cannot read the ISO", stop. Kind from
   `sources/install.{wim,esd,swm}`.
4. Space: `boot.wim` size + 16 MiB must fit (an old `boot.wim`/`.part` counts as
   free); on vfat `boot.wim` must be < 4 GiB.
5. Copy with progress per the writer rules; stamp with `bb_wb_by=helper <version>`.
6. Remove `winboot/` directories whose ISO no longer exists (only inside
   `/beast-booter/winboot/`, only directories holding a `stamp.env`).
7. On success: set `bb_oneshot` to `<iso>` (the menu boots it next); reboot.
   `--dry-run` skips the reboot.
8. `bb_wb_iso` is unset on every exit: success, error, Back and cancel.

## Host tool (installer/)

`beast-boot prepare-windows ISO [--data-root DIR] [--force]`: for an ISO already on
a mounted BeastBoot data partition. Data root: `--data-root` (must be a mount
point), else the mount point of the filesystem holding the ISO, which must have
`beast-booter/` at its root (discovery never looks above the mount point). The
ISO must be inside the data root (not a link), its path UTF-8 without control
characters or `"`. The data partition must be FAT32 or exFAT, also with
`--data-root`: Linux `/proc/mounts` `vfat`/`msdos`/`exfat` (`fuseblk` only if
`lsblk`/`blkid` say `exfat`), macOS `statfs` `f_fstypename` (`msdos`/`exfat`,
else `diskutil info`), Windows `GetVolumeInformationW` (`FAT32`/`FAT`/`exFAT`);
anything else or unknown is refused. Reads the ISO with a read-only
pure-Python UDF reader (no mounting, no root, works on any OS; running as root
gets a warning), copies the identity bytes, writes the same layout with
`bb_wb_by=host <version>`. Skips (unless `--force`) when a stamp for this path exists and `iso-head.bin` matches.
Same space and 4 GiB checks.

## Records and errors (new)

| | meaning |
|---|---|
| `BEAST: windows-prepare <iso>` | menu offers preparation |
| `BEAST: windows mode=<m> copy=<dir>` | Windows boot from the prepared copy |
| `BEAST: error windows-sb-no-helper` | Secure Boot, unprepared Windows ISO, no helper on the drive |
| `windows-sb` | removed |
