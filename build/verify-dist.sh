#!/usr/bin/env bash
# beast-booter: check a dist/ directory (or an unpacked release) for yourself.
#
# Usage: build/verify-dist.sh [DIST] [--cert FILE] [--rebuild]
#   DIST        the dist/ directory to check (default: $BB_ROOT/dist)
#   --cert F    a beast-booter certificate you obtained independently (PEM or
#               DER); grubx64.efi must verify against it and the certificate
#               shipped in DIST must be the same one
#   --rebuild   rebuild the unsigned GRUB EFI image and the BIOS core.img from
#               your installed GRUB packages and compare them byte for byte
#               (needs the same package versions as recorded in the manifest)
#
# What it checks:
#   1. every file in DIST is listed in manifest.json with the right SHA-256
#   2. shim (BOOTX64.EFI) is signed by Microsoft, MokManager is signed
#   3. grubx64.efi carries exactly one signature, which verifies with the
#      beast-booter certificate; without that signature it is exactly the image
#      recorded in the manifest (grub_unsigned_sha256)
#   4. the SBAT embedded in grubx64.efi equals the manifest's
# and prints the SBAT and the certificate fingerprints. MokManager shows the
# SHA-1 fingerprint when you choose "View key" - compare it before enrolling.
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BB_ROOT="${BB_ROOT:-$(cd "$HERE/.." && pwd)}"
bbtool() { python3 -I "$HERE/bbtool.py" "$@"; }

DIST="$BB_ROOT/dist"; CERT=""; REBUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cert) CERT="${2:?--cert needs a file}"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "verify-dist: unknown option $1" >&2; exit 2 ;;
    *) DIST="$1"; shift ;;
  esac
done

fails=0
ok()   { echo "  ok    $*"; }
bad()  { echo "  FAIL  $*"; fails=$((fails + 1)); }
info() { echo "  info  $*"; }
for t in python3 openssl sbverify sbattach objcopy sha256sum; do
  command -v "$t" >/dev/null || { echo "verify-dist: missing tool $t (packages: sbsigntool binutils openssl python3)" >&2; exit 2; }
done
[ -f "$DIST/manifest.json" ] || { echo "verify-dist: $DIST/manifest.json not found" >&2; exit 2; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mget() { bbtool manifest-get "$DIST" "$1"; }
sha() { local s; s="$(sha256sum < "$1")"; echo "${s%% *}"; }

ESP="$DIST/esp"
GRUB="$ESP/EFI/BOOT/grubx64.efi"; SHIM="$ESP/EFI/BOOT/BOOTX64.EFI"; MM="$ESP/EFI/BOOT/mmx64.efi"
CER="$ESP/ENROLL_THIS_KEY_IN_MOKMANAGER.cer"

echo "beast-booter $(mget version) build $(mget build_id) in $DIST"
echo
echo "[1] file hashes (manifest.json)"
# shellcheck disable=SC2001  # indent every line; ${var//} cannot anchor at line starts
if out="$(bbtool manifest-verify "$DIST" 2>&1)"; then ok "$out"; else echo "$out" | sed 's/^/        /'; bad "manifest check failed"; fi
if [ ! -e "$ESP/EFI/BOOT/fbx64.efi" ]; then ok "no fbx64.efi (no firmware boot entries are ever created)"; else bad "fbx64.efi present"; fi

echo
echo "[2] beast-booter certificate"
openssl x509 -inform DER -in "$CER" -out "$T/dist.pem" 2>/dev/null || { bad "cannot parse $CER"; cp /dev/null "$T/dist.pem"; }
if [ -s "$T/dist.pem" ]; then
  subj="$(openssl x509 -in "$T/dist.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  info "subject:  $subj"
  info "valid:    $(openssl x509 -in "$T/dist.pem" -noout -startdate | cut -d= -f2) .. $(openssl x509 -in "$T/dist.pem" -noout -enddate | cut -d= -f2)"
  info "SHA-256:  $(openssl x509 -in "$T/dist.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
  info "SHA-1:    $(openssl x509 -in "$T/dist.pem" -noout -fingerprint -sha1 | cut -d= -f2)   <- MokManager 'View key' shows this"
  if [ "$(sha "$CER")" = "$(mget secure_boot.cert_sha256)" ]; then ok "matches manifest cert_sha256"; else bad "differs from manifest cert_sha256"; fi
fi
VERIFY_PEM="$T/dist.pem"
if [ -n "$CERT" ]; then
  if openssl x509 -in "$CERT" -out "$T/given.pem" 2>/dev/null || openssl x509 -inform DER -in "$CERT" -out "$T/given.pem" 2>/dev/null; then
    if cmp -s <(openssl x509 -in "$T/given.pem" -outform DER) "$CER"; then ok "same certificate as --cert $CERT"; else bad "the shipped certificate is NOT the one given with --cert"; fi
    VERIFY_PEM="$T/given.pem"
  else
    bad "cannot read --cert $CERT"
  fi
else
  info "tip: compare the fingerprints above with the ones published by whoever built this dist/ (or pass --cert)"
fi

echo
echo "[3] signatures"
sigs="$(sbverify --list "$SHIM" 2>/dev/null)" || true
if grep -q 'issuer:.*O=Microsoft Corporation/CN=Microsoft Corporation UEFI CA' <<<"$sigs"; then
  ok "BOOTX64.EFI (shim) signed by: $(grep -m1 'issuer:.*Microsoft Corporation UEFI CA' <<<"$sigs" | sed 's/.*CN=//')"
else
  bad "BOOTX64.EFI is not signed by the Microsoft UEFI CA"
fi
sigs="$(sbverify --list "$MM" 2>/dev/null)" || true
if grep -q '^signature 1' <<<"$sigs"; then ok "mmx64.efi (MokManager) signed by: $(grep -m1 'subject:' <<<"$sigs" | sed 's/.*CN=//')"; else bad "mmx64.efi is not signed"; fi
sigs="$(sbverify --list "$GRUB" 2>/dev/null)" || true
n="$(grep -c '^signature ' <<<"$sigs" || true)"
if [ "$n" = 1 ]; then ok "grubx64.efi has exactly one signature"; else bad "grubx64.efi has $n signatures (expected 1)"; fi
if sbverify --cert "$VERIFY_PEM" "$GRUB" >/dev/null 2>&1; then ok "grubx64.efi signature verifies with the beast-booter certificate"; else bad "grubx64.efi signature does NOT verify"; fi
cp "$GRUB" "$T/grub-unsigned.efi"
if sbattach --remove "$T/grub-unsigned.efi" >/dev/null 2>&1 && [ "$(sha "$T/grub-unsigned.efi")" = "$(mget secure_boot.grub_unsigned_sha256)" ]; then
  ok "grubx64.efi without its signature = manifest grub_unsigned_sha256 $(mget secure_boot.grub_unsigned_sha256 | cut -c1-16)..."
else
  bad "grubx64.efi without its signature does not match grub_unsigned_sha256"
fi

echo
echo "[4] SBAT (what shim uses to revoke GRUB builds)"
objcopy -O binary --only-section=.sbat "$GRUB" "$T/sbat.raw"
tr -d '\000' < "$T/sbat.raw" > "$T/sbat.csv"
mget secure_boot.sbat > "$T/sbat.manifest"
sed 's/^/        /' "$T/sbat.csv"
if cmp -s "$T/sbat.csv" "$T/sbat.manifest"; then ok "embedded SBAT equals the manifest's"; else bad "embedded SBAT differs from the manifest"; fi
info "SBAT check at build time: $(mget secure_boot.sbat_version_check)"
info "shim's own revocation level: $(mget secure_boot.shim_sbat_level_latest)"

if [ "$REBUILD" = 1 ]; then
  echo
  echo "[5] rebuild from your installed packages"
  [ -f "$BB_ROOT/scripts/dev-env.sh" ] && [ -z "${BB_GRUB_EFI_DIR:-}" ] && source "$BB_ROOT/scripts/dev-env.sh"
  EFI_DIR="${BB_GRUB_EFI_DIR:-/usr/lib/grub/x86_64-efi}"; BIOS_DIR="${BB_GRUB_BIOS_DIR:-/usr/lib/grub/i386-pc}"
  info "manifest grubx64.efi origin: $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["esp/EFI/BOOT/grubx64.efi"]["origin"])' "$DIST/manifest.json")"
  mapfile -t mods < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["build"]["efi_modules"]))' "$DIST/manifest.json")
  if grub-mkimage -O x86_64-efi -d "$EFI_DIR" -p "$(mget build.efi_prefix)" --sbat "$T/sbat.manifest" -o "$T/rebuilt.efi" "${mods[@]}" 2>"$T/mk.log"; then
    if [ "$(sha "$T/rebuilt.efi")" = "$(mget secure_boot.grub_unsigned_sha256)" ]; then
      ok "unsigned grubx64.efi rebuilt from $EFI_DIR is byte-identical"
    else
      bad "rebuilt unsigned grubx64.efi differs (different grub-efi-amd64-bin version installed?)"
    fi
  else
    bad "grub-mkimage (x86_64-efi) failed: $(head -n1 "$T/mk.log")"
  fi
  mapfile -t bmods < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["build"]["bios_core_modules"]))' "$DIST/manifest.json")
  sed -e 's/^[[:space:]]*#.*//' "$HERE/early-bios.cfg" | grep -v '^[[:space:]]*$' > "$T/early.cfg"
  if grub-mkimage -O i386-pc -d "$BIOS_DIR" -p "$(mget build.bios_core_prefix)" -c "$T/early.cfg" -o "$T/core.img" "${bmods[@]}" 2>"$T/mk.log"; then
    if cmp -s "$T/core.img" "$DIST/bios/core.img"; then ok "core.img rebuilt from $BIOS_DIR is byte-identical"
    else bad "rebuilt core.img differs (different grub-pc-bin version, or build/early-bios.cfg changed?)"; fi
  else
    bad "grub-mkimage (i386-pc) failed: $(head -n1 "$T/mk.log")"
  fi
fi

echo
if [ "$fails" -eq 0 ]; then echo "verify-dist: all checks passed"; else echo "verify-dist: $fails check(s) FAILED"; exit 1; fi
