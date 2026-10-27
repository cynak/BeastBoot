# Debian's shim and MokManager

The ESP boots through Debian's signed shim (`EFI/BOOT/BOOTX64.EFI`) and Debian's
MokManager (`EFI/BOOT/mmx64.efi`), both unmodified. Deliberately no `fbx64.efi`
(docs/ARCHITECTURE.md section 4).

| File | What it is |
|---|---|
| `debian-shim.lock` | the two pinned packages: version, SHA-256 of the `.deb`, purl distro, URLs (deb.debian.org pool first, then snapshot.debian.org) |
| `fetch.py` | downloads, verifies and unpacks them (stdlib only); also gives `build.sh` the manifest origin of each file |
| `microsoft-uefi-ca-2011.pem` | Microsoft Corporation UEFI CA 2011 (SHA-256 `48e99b99...00248507`) |
| `microsoft-uefi-ca-2023.pem` | Microsoft UEFI CA 2023 (SHA-256 `f6124e34...11dad901`) |

## Why Debian's shim

Ubuntu's shim-signed 1.59+15.8-0ubuntu2 is signed only through Microsoft UEFI CA
2011, so PCs whose db trusts only Microsoft UEFI CA 2023 refuse it. Debian's shim
16.1 carries two Microsoft signatures over the same Authenticode digest, one
chaining to each CA, so it boots on both.

- **sid** `shim-signed 1.51+16.1-2` (pinned): signed through both CAs, NX_COMPAT set.
- **trixie** `shim-signed 1.51~1+deb13u1+16.1-2~deb13u1`: also signed through both
  CAs, but without NX_COMPAT. That is why sid is pinned and not stable.
- MokManager: `shim-helpers-amd64-signed 1+16.1+2` (`mmx64.efi.signed`), signed with
  Debian's shim key (the vendor certificate built into that shim).

shim's built-in key is Debian's, not Canonical's. Our GRUB and the beast-net helper
kernel are signed with the beast-boot MOK key. Ubuntu-signed kernels need the
opt-in "Trust Ubuntu's Secure Boot key" (`build/trust/README.md`).

## What is checked, and where

- `fetch.py fetch [DIR]`: the SHA-256 of each `.deb` against the lock, its control
  fields (Package, Version, Architecture), unpacked with `dpkg-deb -x` (no
  maintainer scripts), every unpacked file against the package's `md5sums`.
- `build/build.sh`: `BOOTX64.EFI` must carry a signature chaining to each Microsoft
  CA above, both over the image's own Authenticode digest
  (`scripts/efi_inspect.py require --chains ...`, an `openssl` check of each
  PKCS#7). `mmx64.efi` must be signed through shim's vendor certificate and not be
  in shim's vendor_dbx. Both must be byte-identical to the files in the locked
  `.deb`s (`fetch.py origin`), which is the provenance the manifest records.
- `build/verify-dist.sh` repeats the signature checks on `dist/`.

Callers: `scripts/bootstrap-tools.sh` (into `.tools/debian`), `build/Containerfile`,
`.github/workflows/release.yml`. `scripts/dev-env.sh` sets `BB_DEBIAN_DIR` and
points `BB_SHIM_DIR` at `$BB_DEBIAN_DIR/root/usr/lib/shim`.

## Updating the pin

1. Pick the new `shim-signed` and the matching `shim-helpers-amd64-signed` (same
   shim upstream version) from `dists/<suite>/main/binary-amd64/Packages.xz`. Take
   the SHA-256 from that file, whose own hash is in the suite's `InRelease`, signed
   by the Debian archive keys.
2. Put both in `debian-shim.lock`, with the pool URL and a snapshot.debian.org URL
   of the same file (`https://snapshot.debian.org/mr/binary/<pkg>/<version>/binfiles`
   gives the hash, and `/mr/file/<sha1>/info` the archive timestamp).
3. `python3 -I build/shim/fetch.py fetch`, `make build`, `build/verify-dist.sh`,
   `make e2e` (the Secure Boot tests include a 2023-only db), `make sbom vulns`.
   The build refuses a shim whose SBAT revocation level is above our GRUB's SBAT.
