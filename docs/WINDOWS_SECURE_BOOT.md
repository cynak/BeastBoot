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
/beast-booter/winboot<iso>/stamp.env   GRUB environment block, written LAST (the copy counts only once it exists)
```

e.g. `/beast-booter/winboot/isos/Win11.iso/boot.wim`.

`stamp.env` is a standard 1024-byte GRUB environment block (`# GRUB Environment
Block` header, `key=value` lines, `#` padding; the format of
`beastnet/python/beastnet/grubenv.py`). Keys:

| key | value |
|---|---|
| `bb_wb_iso` | `<iso>` (the path it was made for) |
| `bb_wb_uuid` | the ISO's identity: exactly what `probe --fs-uuid (loop)` returns for the ISO in GRUB with Secure Boot on (see below) |
| `bb_wb_label` | what `probe --label (loop)` returns (may be empty) |
| `bb_wb_kind` | `setup` if the ISO has `sources/install.wim`, `.esd` or `.swm` (any case), else `native` |
| `bb_wb_size` | size of `boot.wim` in bytes (decimal) |
| `bb_wb_by` | `helper <version>` or `host <version>` |

Writers: write `boot.wim.part`, fsync, rename to `boot.wim`; then write
`stamp.env.tmp`, fsync, rename to `stamp.env`; fsync the directory. Before
writing, delete an existing `stamp.env` first, then the old `boot.wim`. Never write
outside `/beast-booter/winboot/`.

### ISO identity

GRUB's iso9660 UUID (grub-core/fs/iso9660.c `grub_iso9660_uuid`): read the volume
descriptors from sector 16 (2048-byte sectors) up to the terminator (type 255);
the selected descriptor is the LAST one that is either the primary (type 1) or a
Joliet supplementary (type 2, escape `%/@`, `%/C` or `%/E`), Rock Ridge ISOs
aside (Microsoft ISOs have none). Its volume *modification* date (descriptor
bytes 830-846, ASCII digits) gives `YYYY-MM-DD-hh-mm-ss-cc`. All zero means no
identity: the menu cannot match it, so writers refuse such ISOs.

The helper does not compute it: the menu passes its own `probe` results (below).
The host tool computes it with the rule above. If the two ever disagree, the menu
only sees an unprepared ISO and offers to prepare it again with the helper.

## Menu (grub/)

When `bb_sb=1` and an ISO's recipe would be `none`:

1. `probe --set=… --fs-uuid (loop)` and `--label`. If
   `($bb_data)/beast-booter/winboot$bb_iso/stamp.env` exists, read it with
   `load_env -f <file> bb_wb_iso bb_wb_uuid bb_wb_label bb_wb_kind` (an explicit
   variable list, never `source`). If `bb_wb_iso` = `$bb_iso`, `bb_wb_uuid` = the
   probed UUID (non-empty) and `boot.wim` exists: recipe `windows`, with
   `bb_wb_dir` set to that directory.
2. Otherwise, if the ISO looks like a UDF bridge (`(loop)/README.TXT` exists and the
   ISO9660 view has no other recipe) and the helper is on the drive: the menu offers
   **Prepare this Windows ISO for Secure Boot**, record `BEAST: windows-prepare
   <iso>`. Choosing it writes `bb_wb_iso`, `bb_wb_uuid` and `bb_wb_label` to the ESP
   `grub/grubenv` (`save_env`) and runs `bb_beastnet winboot`. Without the helper:
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

`beastnet.action=winboot`. Inputs from the ESP `grub/grubenv`: `bb_wb_iso`,
`bb_wb_uuid`, `bb_wb_label` (all required; missing -> error screen, no writes).

1. Validate `bb_wb_iso`: absolute, no `..`, no NUL/newline, a regular file on the
   data partition (`/mnt/data`).
2. The data partition must be vfat or exfat (GRUB cannot read ntfs in lockdown):
   otherwise explain and stop.
3. Attach read-only (loop, `ro`), mount `udf` read-only (fall back to `iso9660`),
   find `sources/boot.wim` case-insensitively; none -> "not a Windows ISO", stop.
   Kind from `sources/install.{wim,esd,swm}`.
4. Space: `boot.wim` size + 16 MiB must fit; on vfat `boot.wim` must be < 4 GiB.
5. Copy with progress per the writer rules; stamp with `bb_wb_by=helper <version>`.
6. Unmount and detach always (also on error or interruption).
7. Remove `winboot/` directories whose ISO no longer exists (only inside
   `/beast-booter/winboot/`, only directories holding a `stamp.env`).
8. On success: unset `bb_wb_iso`, `bb_wb_uuid`, `bb_wb_label`; set `bb_oneshot` to
   `<iso>` (the menu boots it next); reboot. `--dry-run` skips the reboot.

## Host tool (installer/)

`beast-boot prepare-windows ISO [--data-root DIR] [--force]`: for an ISO already on
a mounted BeastBoot data partition. Data root: `--data-root`, else the nearest
parent directory of ISO containing `beast-booter/`. Reads the ISO with a
read-only pure-Python UDF reader (no mounting, no root, works on any OS), computes
the identity by the rule above, writes the same layout with
`bb_wb_by=host <version>`. Skips (unless `--force`) when a matching stamp exists.
Same space and 4 GiB checks (from the data root's free space and filesystem,
where the OS tells it).

## Records and errors (new)

| | meaning |
|---|---|
| `BEAST: windows-prepare <iso>` | menu offers preparation |
| `BEAST: windows mode=<m> copy=<dir>` | Windows boot from the prepared copy |
| `BEAST: error windows-sb-no-helper` | Secure Boot, unprepared Windows ISO, no helper on the drive |
| `windows-sb` | removed |
