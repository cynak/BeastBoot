# 0.4.0 security review (2026-10-27)

Scope: what 0.4.0 adds for Windows ISOs with Secure Boot on: the BeastBoot-signed
wimboot, the menu's prepared-copy path, the helper action `winboot` and the host
command `beast-boot prepare-windows`. Four read-only reviews (wimboot; menu and
helper; host tool and UDF reader, with 7 M fuzz cases; SBOM and vulnerability
scan). Status: **fixes in progress**.

## Findings to fix before release

| id | sev | where | finding | fix |
|---|---|---|---|---|
| W1 | high | wimboot `wim.c` `wim_chunk`/`wim_chunk_offset` | Chunk offsets from `boot.wim` are only checked against the resource length: decreasing offsets wrap `len`, and any `len` becomes a stack VLA (`uint8_t zbuf[len]`) that `file->read` then fills. Memory corruption in a BeastBoot-signed binary = possible Secure Boot bypass on PCs that trust the key. Same code in upstream's signed 2.9.0. | patch: offsets must not decrease, `len <= WIM_CHUNK_LEN`, static buffer; fuzz wim/lzx/xca/huffman/cpio; report upstream |
| W2 | low | wimboot `cpio.c` (+ patch 0001) | name NUL/length not bounds-checked (read overrun) | check `namesize` and the terminator |
| W3 | low | wimboot `efimain.c` | command line copied into a VLA sized by LoadOptionsSize | cap the size |
| H1 | high | host `winboot.py` | follows symlinks on every write: a crafted drive overwrites any file the user (or root under sudo) can write (PoC) | `O_NOFOLLOW`/`dir_fd` walk, `O_EXCL` temp files, containment check, refuse links |
| H2 | medium | host `winboot.py` | filesystem check lets through NTFS-3G (`fuseblk`), ext4, tmpfs; none on macOS/Windows | allow only FAT32/exFAT on every OS |
| H3 | low | host `winboot.py` | data-root discovery accepts any parent with `beast-booter/` (e.g. a source checkout) | stop at the mount point, require a drive marker |
| H4 | low | host | non-UTF-8 file names crash after the copy | validate the path first |
| H5 | low | host | a FIFO `.part` blocks; stale `.part` not counted for space | `O_EXCL`, remove stale parts |
| N1 | medium | helper `winboot.py` | the ISO is mounted with the kernel udf/isofs drivers: links inside the ISO are followed (copies files from outside the ISO, PoC; `/proc/kmsg` hangs), and a kernel parser bug would run in the signed lockdown kernel (suspected) | read the ISO in userspace with the host tool's UDF reader (fuzzed); no mount |
| N2 | low | helper | path checks before the fs-type check; control characters accepted; `bb_wb_iso` left in grubenv on failure | reorder, reject `[\x00-\x1f\x7f"]`, unset on every exit |
| N3 | low | helper `rootfs/init` | data partition mounted without `nosuid,nodev,noexec` | add them |
| S1 | medium | `scripts/scan_vulns.py`, `gen_sbom.py` | the scan selects `*.efi` only, so the signed wimboot has no SBAT/signer/dbx coverage | select signed PE files by manifest origin |

## Checked and fine

- wimboot hands over with `LoadImage(BootPolicy=FALSE, SourceBuffer)` on unmodified bytes; firmware/shim policy applies. No EFI-side patching of Microsoft binaries; options only change display, BCD or image choice.
- Menu: both `load_env` calls use explicit variable lists; the stamp cannot set GRUB or `bb_*` variables; the quoted `initrd` argument keeps paths with spaces to one file.
- Helper cleanup never deletes outside `/beast-booter/winboot/` (crafted stamps tried).
- UDF reader: bounds-checked reads, capped extents/depth/sizes; 7.07 M fuzz cases, no crash, hang or memory blow-up.
- Signature reuse in `build.sh` is sound (strip, compare with the fresh build, one signer, sbverify).
- No new high/critical CVEs; the `cmp` module adds none.

## By design / documented

- The copy (`boot.wim`, `iso-head.bin`, `stamp.env`) is not a security boundary: an attacker who controls the drive controls the ISO too. Security rests on the firmware verifying Windows' boot manager and Windows verifying the rest. A tampered `boot.wim` can run anything as SYSTEM in Windows PE, as a tampered ISO can.
- Rollback: the drive is writable, so an older signed wimboot or GRUB could be put back. 0.4.0 is the first signed wimboot.
- Revocation: SbatLevel comes only from shim's built-in policy; with Debian's shim we cannot push `wimboot.beastboot,2`. Per-binary revocation is `mokutil --mokx --import-hash <authenticode hash>` (physical presence per PC); key compromise means rotating the key.

## Decisions for the maintainer

- D1 (existing since 0.1): `config.cfg` on the data partition is sourced as GRUB script, also under Secure Boot. Lockdown holds, but untrusted script controls `linux`/`initrd` arguments. **Decided: fix in 0.4.0.** With Secure Boot on, the menu reads only `config.env` (GRUB environment block) through `load_env` with an allow-list of settings, and ignores `config.cfg`.
- D2: sign wimboot with its own leaf certificate (BeastBoot CA enrolled once), so one MokListX entry revokes every wimboot build without touching GRUB. Changes enrollment for existing users. **Decided: 0.5.0.** 0.4.0 keeps one key; a bad wimboot is revoked by hash (MokListX).
- D3: the menu scripts, hooks and themes on the ESP are unsigned, so the `config.env` allow-list protects only the data partition. **Decided: 0.5.0** ([ROADMAP-0.5.0.md](ROADMAP-0.5.0.md)).
