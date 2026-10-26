#!/usr/bin/env bash
# beast-booter: check a dist/ directory (or an unpacked release) for yourself.
#
# Usage: build/verify-dist.sh [DIST] [--cert FILE] [--rebuild]
#   DIST        the dist/ directory to check (default: $BB_ROOT/dist)
#   --cert F    a beast-booter certificate you obtained independently (PEM or
#               DER); grubx64.efi must verify against it and the certificate
#               shipped in DIST must be the same one
#   --rebuild   build GRUB, wimboot and beastmount.exe from the pinned source
#               (build/grub/grubsrc.py: a few minutes the first time, then
#               cached; build/wimboot/wimbootsrc.py: seconds), then compare the
#               i386-pc modules, boot.img, core.img, the unsigned grubx64.efi
#               and wimboot with DIST byte for byte (needs a toolchain like the
#               one recorded in the manifest, build.grub_toolchain and
#               build.wimboot_toolchain)
#
# What it checks:
#   1. every file in DIST is listed in manifest.json with the right SHA-256
#   2. shim (BOOTX64.EFI) carries a signature chaining to Microsoft UEFI CA 2011
#      and one chaining to Microsoft UEFI CA 2023, both over its own Authenticode
#      digest (checked with openssl against build/shim/microsoft-uefi-ca-*.pem);
#      MokManager is signed through shim's built-in (Debian) vendor key
#   3. grubx64.efi carries exactly one signature, which verifies with the
#      beast-booter certificate; without that signature it is exactly the image
#      recorded in the manifest (grub_unsigned_sha256). The beast-net helper
#      kernel likewise carries only our signature, and its Authenticode digest
#      is the manifest's, which is that of the Ubuntu kernel package it came
#      from (compared with the .deb itself when it is in the beast-net cache)
#   4. the SBAT embedded in grubx64.efi equals the manifest's
#   5. wimboot (Windows PE loader) is a hybrid BIOS/UEFI image of the
#      manifest's version, unsigned, with its SBAT lines, from the manifest's
#      wimboot build (compared with that build when it is in the local cache);
#      the Windows PE start-up files have CRLF line endings; beastmount.exe
#      (attaches the ISO in Windows PE) is a PE32+ x86_64 console program
#      without time stamp or signature that imports only KERNEL32/msvcrt, from
#      the manifest's beastmount build (--rebuild: rebuilt with the pinned
#      MinGW-w64 .debs of build/winpe/mingw-w64.lock.json and compared)
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
    -h|--help) sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
efi_inspect() { python3 -I "$BB_ROOT/scripts/efi_inspect.py" "$@"; }
MS_CA_2011="Microsoft Corporation UEFI CA 2011=$HERE/shim/microsoft-uefi-ca-2011.pem"
MS_CA_2023="Microsoft UEFI CA 2023=$HERE/shim/microsoft-uefi-ca-2023.pem"
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
# shellcheck disable=SC2001  # indent every line
if out="$(efi_inspect require "$SHIM" --chains "$MS_CA_2011" --chains "$MS_CA_2023" 2>&1)"; then
  ok "BOOTX64.EFI (shim) signed through Microsoft UEFI CA 2011 and Microsoft UEFI CA 2023, over one Authenticode digest"
else
  echo "$out" | sed 's/^/        /'
  bad "BOOTX64.EFI lacks a signature chaining to Microsoft UEFI CA 2011 or to Microsoft UEFI CA 2023 over its own digest"
fi
info "shim: $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["esp/EFI/BOOT/BOOTX64.EFI"]["origin"])' "$DIST/manifest.json")"
# shellcheck disable=SC2001
if out="$(efi_inspect require "$MM" --vendor-of "$SHIM" 2>&1)"; then
  ok "mmx64.efi (MokManager) signed through shim's built-in vendor key: $(sbverify --list "$MM" 2>/dev/null | grep -m1 'subject:' | sed 's/.*CN=//')"
else
  echo "$out" | sed 's/^/        /'; bad "mmx64.efi is not signed through shim's vendor key (or is in its vendor_dbx)"
fi
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
BN_K="$ESP/beast-net/vmlinuz"
if [ -f "$BN_K" ]; then
  sigs="$(sbverify --list "$BN_K" 2>/dev/null)" || true
  n="$(grep -c '^signature ' <<<"$sigs" || true)"
  if [ "$n" = 1 ]; then ok "beast-net/vmlinuz has exactly one signature (sbverify)"; else bad "beast-net/vmlinuz has $n signatures (expected 1)"; fi
  if efi_inspect require "$BN_K" --only "beast-booter=$VERIFY_PEM" >/dev/null 2>&1; then
    ok "beast-net/vmlinuz has exactly one signature, which verifies with the beast-booter certificate"
  else
    bad "beast-net/vmlinuz is not signed by the beast-booter certificate alone"
  fi
  bn_auth="$(efi_inspect authenticode "$BN_K")"
  bn_src="$(mget secure_boot.beastnet_kernel_source)" || bn_src=""
  if [ "$bn_auth" = "$(mget secure_boot.beastnet_kernel_authenticode_sha256)" ]; then
    ok "beast-net/vmlinuz Authenticode digest = manifest beastnet_kernel_authenticode_sha256 ${bn_auth:0:16}... ($bn_src)"
  else
    bad "beast-net/vmlinuz Authenticode digest differs from the manifest's"
  fi
  cp "$BN_K" "$T/vmlinuz-unsigned"
  if sbattach --remove "$T/vmlinuz-unsigned" >/dev/null 2>&1 && [ "$(sha "$T/vmlinuz-unsigned")" = "$(mget secure_boot.beastnet_kernel_unsigned_sha256)" ]; then
    ok "beast-net/vmlinuz without its signature = manifest beastnet_kernel_unsigned_sha256"
  else
    bad "beast-net/vmlinuz without its signature does not match beastnet_kernel_unsigned_sha256"
  fi
  # deb:<package>=<version>:<path>; the .deb is in the beast-net cache after a build
  if [[ "$bn_src" =~ ^deb:([^=]+)=([^:]+(:[^:/]+)?):(/.+)$ ]]; then
    bn_pkg="${BASH_REMATCH[1]}"; bn_ver="${BASH_REMATCH[2]}"; bn_path="${BASH_REMATCH[4]}"
    bn_deb="${BB_BEASTNET_CACHE:-$BB_ROOT/.tools/cache/beastnet}/debs/${bn_pkg}_${bn_ver//:/%3a}_amd64.deb"
    if [ -f "$bn_deb" ] && command -v dpkg-deb >/dev/null; then
      dpkg-deb --fsys-tarfile "$bn_deb" | tar -xO ".$bn_path" > "$T/vmlinuz-deb" 2>/dev/null || true
      if [ -s "$T/vmlinuz-deb" ] && [ "$(efi_inspect authenticode "$T/vmlinuz-deb")" = "$bn_auth" ]; then
        ok "beast-net/vmlinuz is the kernel of $(basename "$bn_deb") (same Authenticode digest, signature replaced)"
      else
        bad "beast-net/vmlinuz is not the kernel $bn_path of $(basename "$bn_deb")"
      fi
    else
      info "$(basename "$bn_deb") not found locally: kernel compared with the manifest only"
    fi
  else
    bad "manifest secure_boot.beastnet_kernel_source is not a package origin: '$bn_src'"
  fi
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

echo
echo "[5] wimboot (Windows PE loader, built from source by build/wimboot/wimbootsrc.py; unsigned)"
WIM="$ESP/beast-booter/wimboot"
WIM_VER="$(mget build.wimboot_version 2>/dev/null || true)"
WIMSRC=(python3 -I "$HERE/wimboot/wimbootsrc.py")
BMSRC=(python3 -I "$HERE/winpe/beastmountsrc.py")

# --rebuild builds every component from scratch: a fresh cache directory per component, so a warm
# cache cannot hand back the old output. Only the downloaded, hash-checked inputs (dl/) are copied
# in from the normal cache; everything derived (unpacked toolchains, work trees, out/) is rebuilt.
rb_cache() {  # rb_cache <name> <normal cache dir>
  local d="$T/rebuild/$1"; mkdir -p "$d"
  [ -d "$2/dl" ] && cp -a "$2/dl" "$d/dl"
  echo "$d"
}
if [ -z "$WIM_VER" ] && [ ! -e "$WIM" ]; then
  info "this build has no wimboot (built with BB_SKIP_WIMBOOT=1): Windows ISOs are refused"
elif [ -z "$WIM_VER" ] || [ ! -f "$WIM" ]; then
  bad "wimboot and the manifest's build.wimboot_version must come together (file: $([ -f "$WIM" ] && echo yes || echo no), version: '${WIM_VER}')"
else
  if facts="$("${WIMSRC[@]}" check "$WIM" "$WIM_VER" 2>"$T/wim.err")"; then
    ok "beast-booter/wimboot $WIM_VER: bzImage header (BIOS, linux16), PE32+ x86_64 (UEFI, linux) with MajorImageVersion >= 1, no signature, upstream + beast-booter SBAT lines"
    info "wimboot facts: $facts"
  else
    bad "beast-booter/wimboot: $(sed 's/^wimboot: error: //' "$T/wim.err")"
  fi
  wo="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["esp/beast-booter/wimboot"]["origin"])' "$DIST/manifest.json")"
  if [ "$wo" = "wimboot-src:wimboot=$WIM_VER:/wimboot" ]; then ok "manifest origin: $wo"; else bad "manifest origin of beast-booter/wimboot is '$wo'"; fi
  wkey="$(mget build.wimboot_build_key)"
  winfo="${BB_WIMBOOT_CACHE:-$BB_ROOT/.tools/cache/wimboot}/out/$wkey/build-info.json"
  if [ -f "$winfo" ] && [ "$(sha "$winfo")" = "$(mget build.wimboot_build_info_sha256)" ]; then
    if [ "$("${WIMSRC[@]}" info "$(dirname "$winfo")" files.wimboot)" = "$(sha "$WIM")" ]; then
      ok "beast-booter/wimboot is the file of wimboot build $wkey (its build-info.json is the manifest's)"
    else
      bad "beast-booter/wimboot differs from the file of wimboot build $wkey"
    fi
  else
    info "wimboot build $wkey is not in the local cache: --rebuild builds it and compares"
  fi
  for f in winpeshl.ini beastboot.cmd; do
    wf="$ESP/beast-booter/winpe/$f"
    if [ ! -f "$wf" ]; then bad "beast-booter/winpe/$f missing"
    elif [ "$(grep -c $'\r$' "$wf")" = "$(wc -l < "$wf")" ]; then
      ok "beast-booter/winpe/$f has CRLF line endings"
    else
      bad "beast-booter/winpe/$f does not have CRLF line endings throughout"
    fi
  done
  # beastmount.exe: our own program, built reproducibly by build/winpe/beastmountsrc.py
  BM="$ESP/beast-booter/winpe/beastmount.exe"
  BM_VER="$(mget build.beastmount_version 2>/dev/null || true)"
  if [ -z "$BM_VER" ] || [ ! -f "$BM" ]; then
    bad "beast-booter/winpe/beastmount.exe and the manifest's build.beastmount_version must come with wimboot (file: $([ -f "$BM" ] && echo yes || echo no), version: '${BM_VER}')"
  else
    if bfacts="$("${BMSRC[@]}" check "$BM" 2>"$T/bm.err")"; then
      ok "beast-booter/winpe/beastmount.exe $BM_VER: PE32+ x86_64 console program, TimeDateStamp 0, no signature, imports only KERNEL32/msvcrt"
      info "beastmount facts: $bfacts"
    else
      bad "beast-booter/winpe/beastmount.exe: $(sed 's/^beastmount: error: //' "$T/bm.err")"
    fi
    bo="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["esp/beast-booter/winpe/beastmount.exe"]["origin"])' "$DIST/manifest.json")"
    if [ "$bo" = "beastmount-src:beastmount=$BM_VER:/beastmount.exe" ]; then ok "manifest origin: $bo"; else bad "manifest origin of beast-booter/winpe/beastmount.exe is '$bo'"; fi
    bkey="$(mget build.beastmount_build_key)"
    binfo="${BB_BEASTMOUNT_CACHE:-$BB_ROOT/.tools/cache/beastmount}/out/$bkey/build-info.json"
    if [ -f "$binfo" ] && [ "$(sha "$binfo")" = "$(mget build.beastmount_build_info_sha256)" ]; then
      if [ "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["beastmount.exe"])' "$binfo")" = "$(sha "$BM")" ]; then
        ok "beast-booter/winpe/beastmount.exe is the file of beastmount build $bkey (its build-info.json is the manifest's)"
      else
        bad "beast-booter/winpe/beastmount.exe differs from the file of beastmount build $bkey"
      fi
    else
      info "beastmount build $bkey is not in the local cache: --rebuild builds it and compares"
    fi
  fi
fi

if [ "$REBUILD" = 1 ] && [ -f "$ESP/beast-booter/winpe/beastmount.exe" ]; then
  echo
  echo "[6b] rebuild beastmount.exe from source (build/winpe/beastmountsrc.py, pinned MinGW-w64) and compare"
  if BOUT="$("${BMSRC[@]}" build --quiet --force --cache "$(rb_cache beastmount "${BB_BEASTMOUNT_CACHE:-$BB_ROOT/.tools/cache/beastmount}")" 2>"$T/beastmount.log")"; then
    BOUT="${BOUT##*$'\n'}"
    if cmp -s "$BOUT/beastmount.exe" "$ESP/beast-booter/winpe/beastmount.exe"; then ok "beast-booter/winpe/beastmount.exe is byte-identical to the rebuilt one"
    else bad "beast-booter/winpe/beastmount.exe differs from the rebuilt one"; fi
  else
    tail -n 5 "$T/beastmount.log" | sed 's/^/        /'
    bad "beastmount.exe source build failed (python3 -I build/winpe/beastmountsrc.py build)"
  fi
fi

if [ "$REBUILD" = 1 ] && [ -f "$WIM" ]; then
  echo
  echo "[6] rebuild wimboot from source (build/wimboot/wimbootsrc.py) and compare"
  if WOUT="$("${WIMSRC[@]}" build --quiet --force --cache "$(rb_cache wimboot "${BB_WIMBOOT_CACHE:-$BB_ROOT/.tools/cache/wimboot}")" 2>"$T/wimboot.log")"; then
    WOUT="${WOUT##*$'\n'}"
    if [ "$("${WIMSRC[@]}" info "$WOUT" version)" = "$WIM_VER" ]; then ok "wimboot $WIM_VER built from source in $WOUT"
    else bad "this checkout builds wimboot $("${WIMSRC[@]}" info "$WOUT" version), the manifest says $WIM_VER"; fi
    if [ "$("${WIMSRC[@]}" info "$WOUT" key)" != "$(mget build.wimboot_build_key)" ]; then
      info "wimboot build key differs from the manifest's (other toolchain?); comparing the output anyway"
    fi
    if cmp -s "$WOUT/wimboot" "$WIM"; then ok "beast-booter/wimboot is byte-identical to the rebuilt one"
    else bad "beast-booter/wimboot differs from the rebuilt one (other toolchain, see the build key above?)"; fi
  else
    tail -n 5 "$T/wimboot.log" | sed 's/^/        /'
    bad "wimboot source build failed (python3 -I build/wimboot/wimbootsrc.py build)"
  fi
fi

if [ "$REBUILD" = 1 ]; then
  echo
  echo "[7] rebuild GRUB from source (build/grub/grubsrc.py) and compare"
  info "manifest grubx64.efi origin: $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"]["esp/EFI/BOOT/grubx64.efi"]["origin"])' "$DIST/manifest.json")"
  # Always a from-scratch build in a temporary cache (only the verified downloads are reused).
  if GOUT="$(python3 -I "$HERE/grub/grubsrc.py" build --quiet --force --cache "$(rb_cache grub "${BB_GRUB_CACHE:-$BB_ROOT/.tools/cache/grub-src}")" 2>"$T/grub.log")"; then
    GOUT="${GOUT##*$'\n'}"
    gver="$(python3 -I "$HERE/grub/grubsrc.py" info "$GOUT" version)"
    gkey="$(python3 -I "$HERE/grub/grubsrc.py" info "$GOUT" key)"
    if [ "$gver" = "$(mget build.grub_version)" ]; then ok "GRUB $gver built from source in $GOUT"
    else bad "this checkout builds GRUB $gver, the manifest says $(mget build.grub_version)"; fi
    if [ "$gkey" = "$(mget build.grub_build_key)" ]; then info "same GRUB build key as the manifest ($gkey: same source, patches and toolchain)"
    else info "GRUB build key $gkey differs from the manifest's $(mget build.grub_build_key) (other toolchain?); comparing the output anyway"; fi
    # i386-pc modules on the drive vs. the ones just built
    nbad=0; nmod=0
    for f in "$ESP"/grub/i386-pc/*; do
      nmod=$((nmod + 1))
      cmp -s "$f" "$GOUT/i386-pc/$(basename "$f")" || { nbad=$((nbad + 1)); [ "$nbad" -le 5 ] && info "differs: grub/i386-pc/$(basename "$f")"; }
    done
    if [ "$nbad" -eq 0 ]; then ok "all $nmod files in grub/i386-pc/ are byte-identical to the rebuilt ones"
    else bad "$nbad of $nmod files in grub/i386-pc/ differ from the rebuilt GRUB"; fi
    if cmp -s "$DIST/bios/boot.img" "$GOUT/i386-pc/boot.img"; then ok "bios/boot.img is byte-identical"; else bad "bios/boot.img differs"; fi
    # grubx64.efi: same modules, memdisk (rebuilt from the dist/ fonts) and SBAT
    mapfile -t mods < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["build"]["efi_modules"]))' "$DIST/manifest.json")
    mapfile -t memd < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["build"]["efi_memdisk"]))' "$DIST/manifest.json")
    margs=(); for e in "${memd[@]}"; do margs+=("${e%%=*}=$DIST/${e#*=}"); done
    if python3 -I "$HERE/theme/mkmemdisk.py" --out "$T/memdisk.tar" "${margs[@]}" >/dev/null \
       && [ "$(sha "$T/memdisk.tar")" = "$(mget build.efi_memdisk_sha256)" ]; then
      ok "memdisk rebuilt from the dist/ fonts matches efi_memdisk_sha256"
    else
      bad "memdisk rebuilt from the dist/ fonts does not match efi_memdisk_sha256"
    fi
    if "$GOUT/bin/grub-mkimage" -O x86_64-efi -d "$GOUT/x86_64-efi" -m "$T/memdisk.tar" -p "$(mget build.efi_prefix)" \
         --sbat "$T/sbat.manifest" -o "$T/rebuilt.efi" "${mods[@]}" 2>"$T/mk.log"; then
      if [ "$(sha "$T/rebuilt.efi")" = "$(mget secure_boot.grub_unsigned_sha256)" ]; then
        ok "unsigned grubx64.efi rebuilt from source is byte-identical"
      else
        bad "rebuilt unsigned grubx64.efi differs (other toolchain, see the build key above?)"
      fi
    else
      bad "grub-mkimage (x86_64-efi) failed: $(head -n1 "$T/mk.log")"
    fi
    mapfile -t bmods < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["build"]["bios_core_modules"]))' "$DIST/manifest.json")
    sed -e 's/^[[:space:]]*#.*//' "$HERE/early-bios.cfg" | grep -v '^[[:space:]]*$' > "$T/early.cfg"
    if "$GOUT/bin/grub-mkimage" -O i386-pc -d "$GOUT/i386-pc" -p "$(mget build.bios_core_prefix)" -c "$T/early.cfg" \
         -o "$T/core.img" "${bmods[@]}" 2>"$T/mk.log"; then
      if cmp -s "$T/core.img" "$DIST/bios/core.img"; then ok "core.img rebuilt from source is byte-identical"
      else bad "rebuilt core.img differs (other GRUB build, or build/early-bios.cfg changed?)"; fi
    else
      bad "grub-mkimage (i386-pc) failed: $(head -n1 "$T/mk.log")"
    fi
  else
    tail -n 5 "$T/grub.log" | sed 's/^/        /'
    bad "GRUB source build failed (python3 -I build/grub/grubsrc.py build)"
  fi
fi

echo
if [ "$fails" -eq 0 ]; then echo "verify-dist: all checks passed"; else echo "verify-dist: $fails check(s) FAILED"; exit 1; fi
