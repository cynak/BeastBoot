# wimboot (Windows PE loader)

[iPXE's wimboot](https://ipxe.org/wimboot) (GPL-2.0-or-later) boots a
Windows PE `boot.wim` (Windows Setup, WinRE, WinPE) from RAM. beast-boot
builds it from the pinned release source and ships one file,
`esp/beast-booter/wimboot`, with the Windows PE start-up files from
`build/winpe/` next to it (`esp/beast-booter/winpe/`).

```
python3 -I build/wimboot/wimbootsrc.py build      # prints .tools/cache/wimboot/out/<key>
python3 -I build/wimboot/wimbootsrc.py verify DIR
```

`build/build.sh` runs the build (seconds; cached by key = source + patches +
this script + toolchain) and records `build.wimboot_*` in the manifest.
`build/verify-dist.sh` checks the shipped file; `--rebuild` rebuilds and
compares it byte for byte.

## Inputs

- `source.lock.json`: the release tag's GitHub source archive (SHA-256, size,
  and the commit id GitHub embeds in it). The upstream tree also contains
  prebuilt binaries; the build deletes them before it starts, so only code
  compiled here can reach the output. Two URLs, same bytes (checked): the tag archive and its
  codeload mirror, both on GitHub. Upstream publishes no release tarball elsewhere (ipxe.org and
  boot.ipxe.org only serve the signed binary), so the SHA-256 pin is what protects the build.
- `patches/series`: our patches, each with its reason in its header:
  1. `0001` UEFI: take the files from the initrd that GRUB's `linux`/`initrd`
     pass through `EFI_LOAD_FILE2_PROTOCOL` (the Linux EFI stub convention).
     Upstream wimboot reads its files only from its own device's file system,
     which an image GRUB starts from memory does not have.
  2. `0002` PE `MajorImageVersion = 1`: GRUB 2.12+ uses that LoadFile2 path
     only for such images; otherwise it uses its legacy loader, which wimboot
     cannot run under.
  3. `0003` an SBAT vendor line for our modified build.
  4. `0004`-`0007` memory-safety fixes for input from the boot medium
     (signing wimboot makes them Secure Boot relevant): WIM chunk table
     and resource bounds (a crafted `boot.wim` could write over the stack),
     the XCA/LZX/Huffman decoders, the CPIO initrd parser and the EFI
     command line. Found by review and fuzzing, see [fuzz/](fuzz/README.md).

  Without a LoadFile2 initrd, the patched wimboot behaves exactly like
  upstream on valid input. 0001, 0002 and 0004-0007 are candidates for
  upstream.

## One binary for BIOS and UEFI

The x86_64 image is a hybrid: a bzImage header, so GRUB's `linux16` loads it
on BIOS (wimboot then reads the `initrd16 newc:` files from memory), and a
PE32+ EFI entry point, so GRUB's `linux` starts it on 64-bit UEFI.
`wimbootsrc.py` checks both headers, the image version, the SBAT lines and
that the unsigned build is unsigned (the dist copy is signed by build.sh).

## Secure Boot

Since 0.4.0 `build/build.sh` signs our wimboot with the BeastBoot key, the key
that signs GRUB and that users already enroll, so shim accepts it and no new
trust is needed. (Upstream's release binary is Microsoft-signed, but it is
unpatched and cannot boot from GRUB on UEFI, so it would not help.) The
manifest records `secure_boot.wimboot_unsigned_sha256`, the hash of the image
without its signature; `build/verify-dist.sh` checks the signature and that
hash. The SBAT vendor line (patch 0003) lets a vulnerable build be revoked.
Windows' own boot manager is verified by the firmware (`db`/`dbx`). With
Secure Boot on, the menu boots a copy of `boot.wim` on the data partition,
see [docs/WINDOWS_SECURE_BOOT.md](../../docs/WINDOWS_SECURE_BOOT.md).

## Updating

New tag: update `tag`, `upstream_version`, `commit`, `source` (url, sha256,
size) and `source_date_epoch` in `source.lock.json`, reset `patch_level` to 1,
and build. `patch -F0` fails the build if a patch no longer applies. Check the
upstream CHANGELOG for anything that changes the BIOS or EFI file handling.

## The Windows PE files next to it (build/winpe/)

`winpeshl.ini` and `beastboot.cmd` (shipped with CRLF line endings) and
`beastmount.exe`, which attaches the ISO read-only in Windows PE (Setup's
Windows PE has no built-in way to attach an ISO). beastmount is our own
program (`beastmount.c`, GPL-3.0-or-later), built by

```
python3 -I build/winpe/beastmountsrc.py build      # prints .tools/cache/beastmount/out/<key>
python3 -I build/winpe/beastmountsrc.py verify DIR
```

with Ubuntu 26.04's MinGW-w64 cross compiler, pinned as the exact .deb files
in `build/winpe/mingw-w64.lock.json` (SHA-256 and size checked, unpacked into
the cache and run from there, so the host's own packages do not matter; the
docker builder of `build/grub/source.lock.json` provides the compiler's
shared libraries where the host lacks them). Each build compiles twice in two
directories and fails unless both outputs are identical; the image carries no
time stamp, symbols or build path. `build/verify-dist.sh` checks the shipped
file (and `--rebuild` rebuilds and compares it). To update the compiler: new
versions, SHA-256 and sizes from `apt-cache show`, and a new snapshot time.
