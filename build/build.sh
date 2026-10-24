#!/usr/bin/env bash
# beast-booter: build dist/ - every file that goes on a beast-booter drive.
# Run via `make build` (which sources scripts/dev-env.sh first).
#
# Output (docs/ARCHITECTURE.md section 4):
#   dist/manifest.json            origin + SHA-256 of every file below
#   dist/bios/boot.img            stock GRUB i386-pc boot.img
#   dist/bios/core.img            GRUB i386-pc core image (prefix (,msdos2)/grub + early-bios.cfg)
#   dist/esp/...                  copied verbatim into the ESP root
#
# Every file is either copied unmodified from a named Debian/Ubuntu package
# (and checked against that package's md5sums), built here from such files
# plus repo inputs, or copied from the repo. Only build/beastnet/ downloads,
# on a cold cache: pinned, hash-checked .debs and linux-firmware catalog data.
#
# Inputs (environment):
#   BB_MENU_DIR        menu scripts            (default: $BB_ROOT/grub)
#   BB_KEY_DIR         signing key             (default: $BB_ROOT/keys; create with `make keys`)
#   BB_DIST_DIR        output directory        (default: $BB_ROOT/dist)
#   BB_PROJECT_URL     URL in our SBAT line    (default: https://github.com/cynak/BeastBoot)
#   SOURCE_DATE_EPOCH  timestamp for the manifest and file mtimes
#                      (default: last git commit time, else mtime of VERSION)
#   BB_ALLOW_SBAT_MISMATCH=1  continue although the signed Ubuntu GRUB (SBAT
#                      source) and the module package versions differ; recorded
#                      in the manifest. Only for development builds.
#   BB_RESIGN=1        always make a fresh signature (see "Signing" below)
#   BB_NOTO_DIR        directory with the Noto .ttf fonts of the graphical menu
#                      (default: /usr/share/fonts/truetype/noto, then .tools)
#   BB_GRUB_EFI_DIR BB_GRUB_EFI_SIGNED_DIR BB_GRUB_BIOS_DIR BB_SHIM_DIR
#                      package directories (set by scripts/dev-env.sh)
#
# Secure Boot rules this script follows (ARCHITECTURE section 1.2):
#   - grub-mkimage is never given --disable-shim-lock: our GRUB keeps asking
#     shim to verify every kernel / EFI binary it loads.
#   - only unmodified, currently non-revoked signed binaries are shipped
#     (shim's own SBAT revocation level is checked against our SBAT).
#   - the SBAT section truthfully describes the code (see "SBAT" below).
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BB_ROOT="${BB_ROOT:-$(cd "$HERE/.." && pwd)}"
if [ -z "${BB_GRUB_EFI_DIR:-}" ] && [ -f "$BB_ROOT/scripts/dev-env.sh" ]; then
  # shellcheck source=/dev/null
  source "$BB_ROOT/scripts/dev-env.sh"
fi

log()  { echo "build: $*"; }
warn() { echo "build: WARNING: $*" >&2; }
die()  { echo "build: error: $*" >&2; exit 1; }
bbtool() { python3 -I "$HERE/bbtool.py" "$@"; }

# ---------------------------------------------------------------------------
# Inputs and preflight
# ---------------------------------------------------------------------------
for t in grub-mkimage grub-mkfont sbsign sbverify sbattach objcopy openssl python3 dpkg-query dpkg-deb \
         sha256sum md5sum install; do
  command -v "$t" >/dev/null || die "required tool not found: $t (see scripts/bootstrap-tools.sh)"
done
for v in BB_GRUB_EFI_DIR BB_GRUB_EFI_SIGNED_DIR BB_GRUB_BIOS_DIR BB_SHIM_DIR; do
  [ -n "${!v:-}" ] && [ -d "${!v}" ] || die "$v is not set or not a directory (source scripts/dev-env.sh)"
done

VERSION="$(tr -d ' \t\r\n' < "$BB_ROOT/VERSION")"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || die "VERSION has an unexpected format: '$VERSION'"

KEY_DIR="${BB_KEY_DIR:-$BB_ROOT/keys}"
KEY="$KEY_DIR/beast-booter.key"; CRT="$KEY_DIR/beast-booter.crt"; CER="$KEY_DIR/beast-booter.cer"
for f in "$KEY" "$CRT" "$CER"; do
  [ -f "$f" ] || die "signing key not found: $f
       Run 'make keys' to create a local key (or set BB_KEY_DIR)."
done
[ "$(openssl x509 -in "$CRT" -outform DER | sha256sum)" = "$(sha256sum < "$CER")" ] \
  || die "$CRT and $CER are not the same certificate"
[ "$(openssl x509 -in "$CRT" -noout -pubkey | sha256sum)" = \
  "$(openssl pkey -in "$KEY" -pubout 2>/dev/null | sha256sum)" ] \
  || die "$KEY does not belong to $CRT"
eku="$(openssl x509 -in "$CRT" -noout -ext extendedKeyUsage 2>/dev/null)" || true
grep -q 'Code Signing' <<<"$eku" || die "$CRT lacks extendedKeyUsage=codeSigning"
CERT_SUBJECT="$(openssl x509 -in "$CRT" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"

MENU_DIR="${BB_MENU_DIR:-$BB_ROOT/grub}"
[ -f "$MENU_DIR/grub.cfg" ] && [ -f "$MENU_DIR/beast/main.cfg" ] \
  || die "menu scripts not found: need $MENU_DIR/grub.cfg and $MENU_DIR/beast/main.cfg (BB_MENU_DIR)"
MENU_DIR="$(cd "$MENU_DIR" && pwd)"

PROJECT_URL="${BB_PROJECT_URL:-https://github.com/cynak/BeastBoot}"
[[ "$PROJECT_URL" =~ ^https?://[^,[:space:]\"\']+$ ]] || die "BB_PROJECT_URL must be an http(s) URL without commas or spaces"

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  SDE_FROM="SOURCE_DATE_EPOCH"
elif SOURCE_DATE_EPOCH="$(git -C "$BB_ROOT" log -1 --format=%ct 2>/dev/null)" && [ -n "$SOURCE_DATE_EPOCH" ]; then
  SDE_FROM="last git commit"
else
  SOURCE_DATE_EPOCH="$(stat -c %Y "$BB_ROOT/VERSION")"; SDE_FROM="mtime of VERSION"
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"
export SOURCE_DATE_EPOCH

DIST="${BB_DIST_DIR:-$BB_ROOT/dist}"
mkdir -p "$(dirname "$DIST")"
DIST="$(cd "$(dirname "$DIST")" && pwd)/$(basename "$DIST")"
WORK="$(mktemp -d)"
STAGE="$(mktemp -d "$(dirname "$DIST")/.dist-staging.XXXXXX")"
trap 'rm -rf "$WORK" "$STAGE"' EXIT
chmod 0755 "$STAGE"
ORIGINS="$WORK/origins.tsv"; : > "$ORIGINS"
EXTRA="$WORK/extra.tsv"; : > "$EXTRA"

log "beast-booter $VERSION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($SDE_FROM)"
log "menu: $MENU_DIR   key: $CRT"

# ---------------------------------------------------------------------------
# Package provenance: which .deb shipped a file, and is the file unmodified?
# Files under $BB_ROOT/.tools/root were unpacked from .tools/debs/*.deb by
# scripts/bootstrap-tools.sh; anything else must be known to dpkg.
# ---------------------------------------------------------------------------
TOOLS_ROOT="$BB_ROOT/.tools/root"
TOOLS_DEBS="$BB_ROOT/.tools/debs"
declare -A MD5DB=()      # "<pkg>=<ver>|/path" -> md5
declare -A DIRPKG=()     # "/dir" -> "<pkg>=<ver>" (lookup cache)
declare -A DEB_OF=()     # "/path" -> .deb file (for .tools/root)
declare -A LOADED=()     # "<pkg>=<ver>" -> 1 once its md5sums are in MD5DB
TOOLS_INDEXED=0

md5db_load() {  # <pkgkey> <md5sums file>
  local sum path
  while read -r sum path; do MD5DB["$1|/$path"]="$sum"; done < "$2"
  LOADED[$1]=1
}

tools_index() {
  [ "$TOOLS_INDEXED" = 1 ] && return
  local deb p
  for deb in "$TOOLS_DEBS"/*.deb; do
    [ -e "$deb" ] || continue
    while read -r p; do DEB_OF["${p#.}"]="$deb"; done < <(dpkg-deb -c "$deb" | awk '{print $6}')
  done
  TOOLS_INDEXED=1
}

# pkg_lookup FILE: sets P_KEY ("<pkg>=<version>") and P_PATH (the path inside
# the package) and checks the file against the package's md5sums. Returns 1
# with P_ERR set if the file is unknown or modified. Must not run in a
# subshell (it fills the caches above).
pkg_lookup() {
  local f="$1" dir key deb name ver line sum
  P_KEY=""; P_ERR=""
  if [[ "$f" == "$TOOLS_ROOT"/* ]]; then P_PATH="${f#"$TOOLS_ROOT"}"; else P_PATH="$f"; fi
  dir="${P_PATH%/*}"
  key="${DIRPKG[$dir]:-}"
  if [ -z "$key" ] || [ -z "${MD5DB["$key|$P_PATH"]:-}" ]; then
    if [[ "$f" == "$TOOLS_ROOT"/* ]]; then
      tools_index
      deb="${DEB_OF[$P_PATH]:-}"
      [ -n "$deb" ] || { P_ERR="no .deb in $TOOLS_DEBS ships $P_PATH"; return 1; }
      name="$(dpkg-deb -f "$deb" Package)"; ver="$(dpkg-deb -f "$deb" Version)"
      key="$name=$ver"
      if [ -z "${LOADED[$key]:-}" ]; then
        dpkg-deb -I "$deb" md5sums > "$WORK/md5sums" 2>/dev/null || { P_ERR="$deb has no md5sums"; return 1; }
        md5db_load "$key" "$WORK/md5sums"
      fi
    else
      line="$(dpkg-query -S -- "$P_PATH" 2>/dev/null | grep -v '^diversion' | head -n1)" || true
      [ -n "$line" ] || { P_ERR="not shipped by any installed package (dpkg-query -S)"; return 1; }
      name="${line%%: *}"; name="${name%%, *}"
      ver="$(dpkg-query -W -f='${Version}' "$name")"
      key="${name%%:*}=$ver"
      if [ -z "${LOADED[$key]:-}" ]; then
        line="$(dpkg-query --control-path "$name" md5sums 2>/dev/null)" || true
        [ -n "$line" ] && [ -f "$line" ] || { P_ERR="no md5sums for package $name"; return 1; }
        md5db_load "$key" "$line"
      fi
    fi
    DIRPKG[$dir]="$key"
  fi
  P_KEY="$key"
  [ -n "${MD5DB["$key|$P_PATH"]:-}" ] || { P_ERR="not listed in the md5sums of $key"; return 1; }
  sum="$(md5sum < "$f")"; sum="${sum%% *}"
  [ "$sum" = "${MD5DB["$key|$P_PATH"]}" ] \
    || { P_ERR="differs from the file shipped in $key (modified or corrupted)"; return 1; }
}
pkg_resolve() { pkg_lookup "$1" || die "$1: $P_ERR"; }

# verify_files FILE...: every existing FILE must be unmodified package content; sets VERIFIED
verify_files() {
  local f; VERIFIED=0
  for f in "$@"; do
    [ -e "$f" ] || continue
    pkg_resolve "$f"; VERIFIED=$((VERIFIED + 1))
  done
}

# add_file SRC DEST-RELPATH ORIGIN : copy into the staging dist/ and record its origin
add_file() {
  local src="$1" rel="$2" origin="$3"
  [ ! -e "$STAGE/$rel" ] || die "two sources for dist/$rel"
  install -D -m 0644 "$src" "$STAGE/$rel"
  printf '%s\t%s\n' "$rel" "$origin" >> "$ORIGINS"
}
add_deb_file() { pkg_resolve "$1"; add_file "$1" "$2" "deb:$P_KEY:$P_PATH"; }
extra() { printf '%s\t%s\n' "$1" "$2" >> "$EXTRA"; }

# Origin of a non-package input: repo:<path in repo> or <prefix>:<absolute path>.
path_origin() {  # <prefix-outside-repo> <file>
  case "$2" in
    "$BB_ROOT"/*) echo "repo:${2#"$BB_ROOT"/}" ;;
    *) echo "$1:$2" ;;
  esac
}

list_modules() {  # strip comments/blank lines from a module list
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$1" | grep -v '^$'
}

tool_origin() {  # <tool>: sets T_ORIGIN to "<pkg>=<ver>:<path>" (or unpackaged:<path>)
  local t; t="$(command -v "$1")"
  if pkg_lookup "$t"; then T_ORIGIN="deb:$P_KEY:$P_PATH"; else T_ORIGIN="unpackaged:$t"; fi
}

tool_origin grub-mkimage
extra build.grub_mkimage "$T_ORIGIN ($(grub-mkimage --version | head -n1))"
tool_origin sbsign
extra build.sbsign "$T_ORIGIN ($(sbsign --version 2>&1 | head -n1))"

# ---------------------------------------------------------------------------
# EFI GRUB inputs: modules from grub-efi-amd64-bin, SBAT from the signed build
# ---------------------------------------------------------------------------
[ -f "$BB_GRUB_EFI_DIR/kernel.img" ] || die "$BB_GRUB_EFI_DIR/kernel.img not found"
pkg_resolve "$BB_GRUB_EFI_DIR/kernel.img"; EFI_PKG="$P_KEY"     # grub-efi-amd64-bin=<ver>
GRUB_VERSION="${EFI_PKG#*=}"
mapfile -t EFI_MODULES < <(list_modules "$HERE/modules-efi.lst")
[ "${#EFI_MODULES[@]}" -gt 0 ] || die "build/modules-efi.lst is empty"
missing=()
for m in "${EFI_MODULES[@]}"; do [ -f "$BB_GRUB_EFI_DIR/$m.mod" ] || missing+=("$m"); done
[ "${#missing[@]}" -eq 0 ] || die "modules in build/modules-efi.lst missing from $BB_GRUB_EFI_DIR: ${missing[*]}"
verify_files "$BB_GRUB_EFI_DIR"/kernel.img "$BB_GRUB_EFI_DIR"/*.lst "$BB_GRUB_EFI_DIR"/*.mod
log "x86_64-efi: all $VERIFIED module/image files in $BB_GRUB_EFI_DIR are unmodified $EFI_PKG"

SIGNED_EFI="$BB_GRUB_EFI_SIGNED_DIR/grubx64.efi.signed"
[ -f "$SIGNED_EFI" ] || die "$SIGNED_EFI not found (package grub-efi-amd64-signed)"
pkg_resolve "$SIGNED_EFI"; SIGNED_PKG="$P_KEY"
objcopy -O binary --only-section=.sbat "$SIGNED_EFI" "$WORK/sbat.raw"
tr -d '\000' < "$WORK/sbat.raw" > "$WORK/sbat-ubuntu.csv"
[ -s "$WORK/sbat-ubuntu.csv" ] || die "$SIGNED_EFI has no .sbat section"
bbtool sbat-validate "$WORK/sbat-ubuntu.csv"

# --- SBAT -------------------------------------------------------------------
# Our grubx64.efi contains exactly Ubuntu's GRUB code (kernel.img and modules
# from grub-efi-amd64-bin, built from the same source package as Ubuntu's
# signed grubx64.efi), so it must carry Ubuntu's SBAT lines verbatim: when
# Ubuntu's GRUB is revoked through SBAT (grub, grub.ubuntu, grub.peimage ...
# generations), ours is revoked with it. That only holds if the signed build
# and the module package are the same version - checked here. The extra
# grub.beastbooter line lets beast-booter-specific problems (for example in
# the module selection or a bad signing) be revoked separately.
sbat_problems=()
signed_ver="${SIGNED_PKG#*=}"                       # e.g. 1.215+2.14-2ubuntu1
[ "${signed_ver##*+}" = "$GRUB_VERSION" ] \
  || sbat_problems+=("signed package $SIGNED_PKG is not built from $GRUB_VERSION")
if [ -f "$BB_GRUB_EFI_SIGNED_DIR/version" ]; then
  v="$(tr -d '[:space:]' < "$BB_GRUB_EFI_SIGNED_DIR/version")"
  [ "$v" = "$GRUB_VERSION" ] || sbat_problems+=("$BB_GRUB_EFI_SIGNED_DIR/version says $v")
fi
upstream="${GRUB_VERSION#*:}"; upstream="${upstream%%-*}"
while IFS=, read -r comp _gen _vendor _pkg ver _url; do
  case "$comp" in
    sbat) ;;
    grub) [[ "$upstream" == "$ver"* ]] || sbat_problems+=("SBAT 'grub' version $ver vs upstream $upstream") ;;
    *)    [ "$ver" = "$GRUB_VERSION" ] || sbat_problems+=("SBAT '$comp' version $ver") ;;
  esac
done < "$WORK/sbat-ubuntu.csv"
sbat_why=""; for p in "${sbat_problems[@]}"; do sbat_why+="${sbat_why:+; }$p"; done
if [ "${#sbat_problems[@]}" -eq 0 ]; then
  extra secure_boot.sbat_version_check "ok: $SIGNED_PKG matches deb:$EFI_PKG"
elif [ "${BB_ALLOW_SBAT_MISMATCH:-0}" = 1 ]; then
  warn "SBAT source does not match the GRUB modules ($sbat_why); continuing because BB_ALLOW_SBAT_MISMATCH=1"
  extra secure_boot.sbat_version_check "MISMATCH overridden by BB_ALLOW_SBAT_MISMATCH=1: modules deb:$EFI_PKG, SBAT from $SIGNED_PKG: $sbat_why"
else
  die "the signed Ubuntu GRUB ($SIGNED_PKG) is not the same build as the GRUB modules ($EFI_PKG):
       $sbat_why
       Its SBAT lines would not truthfully describe our GRUB. Install matching
       grub-efi-amd64-bin / grub-efi-amd64-signed versions (or, for a local
       development build only, set BB_ALLOW_SBAT_MISMATCH=1)."
fi
extra secure_boot.sbat_source "deb:$SIGNED_PKG:${SIGNED_EFI#"$TOOLS_ROOT"}"

grep -v '^[[:space:]]*#' "$HERE/sbat-beastbooter.csv" | grep -v '^[[:space:]]*$' \
  | sed -e "s|@GRUB_VERSION@|$GRUB_VERSION|g" -e "s|@VERSION@|$VERSION|g" -e "s|@PROJECT_URL@|$PROJECT_URL|g" \
  > "$WORK/sbat-bb.csv"
[ "$(wc -l < "$WORK/sbat-bb.csv")" -eq 1 ] || die "build/sbat-beastbooter.csv must contain exactly one SBAT line"
! grep -q '@' "$WORK/sbat-bb.csv" || die "unfilled placeholder in build/sbat-beastbooter.csv"
cat "$WORK/sbat-ubuntu.csv" "$WORK/sbat-bb.csv" > "$WORK/sbat.csv"
bbtool sbat-validate "$WORK/sbat.csv"

# ---------------------------------------------------------------------------
# shim + MokManager (Ubuntu shim-signed), unmodified
# ---------------------------------------------------------------------------
SHIM="$BB_SHIM_DIR/shimx64.efi.signed.latest"
MM="$BB_SHIM_DIR/mmx64.efi"
[ -f "$SHIM" ] && [ -f "$MM" ] || die "shim not found in $BB_SHIM_DIR (package shim-signed)"
sigs="$(sbverify --list "$SHIM" 2>/dev/null)" || true
grep -q 'issuer:.*O=Microsoft Corporation/CN=Microsoft Corporation UEFI CA' <<<"$sigs" \
  || die "$SHIM is not signed by the Microsoft UEFI CA"
sigs="$(sbverify --list "$MM" 2>/dev/null)" || true
grep -q '^signature 1' <<<"$sigs" || die "$MM is not signed"
if [ -x "$BB_SHIM_DIR/is-not-revoked" ]; then   # Ubuntu's list of revoked Canonical signing keys
  "$BB_SHIM_DIR/is-not-revoked" "$SHIM" "$MM" 2>"$WORK/revoked.log" \
    || { grep -v '^warning: data remaining' "$WORK/revoked.log" >&2; die "shim/MokManager signed with a revoked key"; }
fi
objcopy -O binary --only-section=.sbatlevel "$SHIM" "$WORK/sbatlevel.raw"
[ -s "$WORK/sbatlevel.raw" ] || die "$SHIM has no .sbatlevel section"
objcopy -O binary --only-section=.sbat "$SHIM" "$WORK/shim-sbat.raw"
tr -d '\000' < "$WORK/shim-sbat.raw" > "$WORK/shim-sbat.csv"
# Never ship something shim itself would refuse once its latest revocations apply.
lvl="$(bbtool sbat-vs-level "$WORK/sbat.csv" "$WORK/sbatlevel.raw")" \
  || die "our GRUB's SBAT is below shim's revocation level"
bbtool sbat-vs-level "$WORK/shim-sbat.csv" "$WORK/sbatlevel.raw" >/dev/null \
  || die "shim's own SBAT is below its revocation level"
log "SBAT generations are at or above shim's latest revocation level ($lvl)"
extra secure_boot.shim_sbat_level_latest "$(bbtool sbatlevel "$WORK/sbatlevel.raw" | tr '\n' ' ' | sed 's/ $//')"

add_deb_file "$SHIM" esp/EFI/BOOT/BOOTX64.EFI
add_deb_file "$MM"   esp/EFI/BOOT/mmx64.efi
# Deliberately no fbx64.efi (ARCHITECTURE section 4).
o="$(path_origin key "$CER")"
add_file "$CER" esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer "key:${o#*:}"

# ---------------------------------------------------------------------------
# Graphical menu (docs/MENU.md): fonts made with grub-mkfont from the Noto
# fonts of Ubuntu's fonts-noto-core / fonts-noto-mono (SIL Open Font License
# 1.1), and the theme, every image of which build/theme/mktheme.py draws.
# The menu falls back to the text menu if any of this is missing at boot.
# ---------------------------------------------------------------------------
tool_origin grub-mkfont
extra build.grub_mkfont "$T_ORIGIN ($(grub-mkfont --version | head -n1))"
NOTO_DIR=""
for d in "${BB_NOTO_DIR:-}" /usr/share/fonts/truetype/noto "$TOOLS_ROOT/usr/share/fonts/truetype/noto"; do
  [ -n "$d" ] && [ -f "$d/NotoSans-Regular.ttf" ] && [ -f "$d/NotoSansMono-Regular.ttf" ] && { NOTO_DIR="$d"; break; }
done
[ -n "$NOTO_DIR" ] || die "Noto fonts not found (packages fonts-noto-core and fonts-noto-mono, or set BB_NOTO_DIR)"
# Latin, Latin-1, Latin Extended-A/B, Greek, Cyrillic, punctuation, euro sign,
# arrows, box drawing, geometric shapes. Other characters (in file names) come
# from unicode.pf2, which GRUB uses as a fallback.
FONT_RANGES="0x20-0x7E,0xA0-0x24F,0x370-0x3FF,0x400-0x4FF,0x2000-0x206F,0x20AC-0x20AC,0x2190-0x21FF,0x2500-0x257F,0x25A0-0x25FF"
# .ttf name, size, mktheme.py keys, shipped (1) or only drawn into images (0),
# extra grub-mkfont options. The console font's ascent + descent must not
# exceed its tallest glyph (GRUB's console line height), or descenders are cut.
FONT_SPECS=(
  "NotoSans-Regular 20        item          1"
  "NotoSans-Bold 20           item_sel      1"
  "NotoSans-Regular 16        small,label   1"
  "NotoSansMono-Regular 16    term          1   -c 16 -d 4"
  "NotoSans-Bold 32           title         0"
  "NotoSans-Bold 16           key           0"
)
mkdir -p "$WORK/fonts"
font_args=()
font_origins=()
for spec in "${FONT_SPECS[@]}"; do
  read -r fname fsize fkeys fship fopts <<<"$spec"
  ttf="$NOTO_DIR/$fname.ttf"
  [ -f "$ttf" ] || die "font not found: $ttf"
  pkg_resolve "$ttf"
  # The licence we record must be the one the package states.
  copyright="/usr/share/doc/${P_KEY%%=*}/copyright"
  [[ "$ttf" == "$TOOLS_ROOT"/* ]] && copyright="$TOOLS_ROOT$copyright"
  grep -qx 'License: OFL-1.1' "$copyright" 2>/dev/null \
    || die "$ttf: $copyright does not state 'License: OFL-1.1'"
  origin="deb:$P_KEY:$P_PATH (OFL-1.1)"
  out="$WORK/fonts/$fname-$fsize.pf2"
  # shellcheck disable=SC2086  # fopts is a list of options
  grub-mkfont -s "$fsize" ${fopts:-} -r "$FONT_RANGES" -o "$out" "$ttf" 2>"$WORK/mkfont.log" \
    || { cat "$WORK/mkfont.log" >&2; die "grub-mkfont failed for $ttf"; }
  IFS=, read -r -a keys <<<"$fkeys"
  for k in "${keys[@]}"; do font_args+=(--font "$k=$out"); done
  case " ${font_origins[*]} " in *" deb:$P_KEY "*) ;; *) font_origins+=("deb:$P_KEY") ;; esac
  if [ "$fship" = 1 ]; then
    add_file "$out" "esp/grub/fonts/$fname-$fsize.pf2" "built:grub-mkfont -s $fsize${fopts:+ $fopts} from $origin"
  fi
done
extra build.font_ranges "$FONT_RANGES"

# The menu's fonts also go into a memdisk inside grubx64.efi: under Secure
# Boot, GRUB (Ubuntu patch "Enforce verification of font files") only loads
# fonts from the memdisk of its own signed image, never from the disk. The
# copies in esp/grub/fonts/ are for legacy BIOS. build/theme/mkmemdisk.py
# writes a deterministic tar that can be rebuilt from those dist/ files.
memdisk_args=()
memdisk_list=()
for f in "$WORK"/fonts/*.pf2; do
  rel="esp/grub/fonts/$(basename "$f")"
  [ -f "$STAGE/$rel" ] || continue                     # build-only fonts stay out
  memdisk_args+=("fonts/$(basename "$f")=$STAGE/$rel")
  memdisk_list+=("fonts/$(basename "$f")=$rel")
done
MEMDISK="$WORK/memdisk.tar"
python3 -I "$HERE/theme/mkmemdisk.py" --out "$MEMDISK" "${memdisk_args[@]}" || die "build/theme/mkmemdisk.py failed"
MEMDISK_SHA="$(sha256sum < "$MEMDISK")"; MEMDISK_SHA="${MEMDISK_SHA%% *}"
extra build.efi_memdisk[] "${memdisk_list[*]}"
extra build.efi_memdisk_sha256 "$MEMDISK_SHA"

THEME_OUT="$WORK/theme"
python3 -I "$HERE/theme/mktheme.py" --out "$THEME_OUT" --version "$VERSION" "${font_args[@]}" \
  || die "build/theme/mktheme.py failed"
theme_origin="built:build/theme/mktheme.py (text in images drawn with the grub-mkfont fonts above, from ${font_origins[*]})"
ntheme=0
while IFS= read -r -d '' f; do
  add_file "$f" "esp/grub/themes/beast/${f#"$THEME_OUT"/}" "$theme_origin"
  ntheme=$((ntheme + 1))
done < <(find "$THEME_OUT" -type f -print0 | sort -z)
log "theme: $ntheme files, $(du -sk "$THEME_OUT" | cut -f1) KiB; fonts: $(du -ck "$WORK"/fonts/*.pf2 | tail -n1 | cut -f1) KiB (all sizes)"

# ---------------------------------------------------------------------------
# EFI GRUB: build, sign, verify
# ---------------------------------------------------------------------------
UNSIGNED="$WORK/grubx64.unsigned.efi"
# NB: no --disable-shim-lock, ever.
# -m must come before -p: a memdisk implies the prefix (memdisk)/boot/grub
# unless -p follows it. Our prefix stays /grub on the ESP the image came from.
grub-mkimage -O x86_64-efi -d "$BB_GRUB_EFI_DIR" -m "$MEMDISK" -p /grub --sbat "$WORK/sbat.csv" \
  -o "$UNSIGNED" "${EFI_MODULES[@]}"
objcopy -O binary --only-section=.sbat "$UNSIGNED" "$WORK/check.sbat"
cmp -s <(tr -d '\000' < "$WORK/check.sbat") "$WORK/sbat.csv" || die "SBAT section of the built GRUB is not what we asked for"
UNSIGNED_SHA="$(sha256sum < "$UNSIGNED")"; UNSIGNED_SHA="${UNSIGNED_SHA%% *}"

# Signing. sbsign puts the current time into the signature (a PKCS#7
# signingTime attribute), so a fresh signature changes the file's hash. To keep
# rebuilds byte-identical, an existing dist/ grubx64.efi is reused when its
# signature verifies with our certificate and, with the signature removed, it
# is byte-identical to the image we just built. The manifest records the
# unsigned hash, which anyone can reproduce with grub-mkimage.
SIGNED="$WORK/grubx64.efi"
PREV="$DIST/esp/EFI/BOOT/grubx64.efi"
reused=0
if [ "${BB_RESIGN:-0}" != 1 ] && [ -f "$PREV" ]; then
  cp "$PREV" "$WORK/prev.efi"; cp "$PREV" "$WORK/prev-stripped.efi"
  if sbattach --remove "$WORK/prev-stripped.efi" >/dev/null 2>&1 \
     && cmp -s "$WORK/prev-stripped.efi" "$UNSIGNED" \
     && sbverify --cert "$CRT" "$WORK/prev.efi" >/dev/null 2>&1 \
     && [ "$(sbverify --list "$WORK/prev.efi" 2>/dev/null | grep -c '^signature ')" = 1 ]; then
    cp "$WORK/prev.efi" "$SIGNED"; reused=1
    log "grubx64.efi: unsigned image unchanged, keeping the existing signature (BB_RESIGN=1 to re-sign)"
  fi
fi
if [ "$reused" = 0 ]; then
  sbsign --key "$KEY" --cert "$CRT" --output "$SIGNED" "$UNSIGNED" >/dev/null 2>"$WORK/sbsign.log" \
    || { cat "$WORK/sbsign.log" >&2; die "sbsign failed"; }
  log "grubx64.efi: signed with $CERT_SUBJECT"
fi
sbverify --cert "$CRT" "$SIGNED" >/dev/null 2>&1 || die "sbverify failed for the signed GRUB"
add_file "$SIGNED" esp/EFI/BOOT/grubx64.efi "built:grub-mkimage from deb:$EFI_PKG + memdisk (build.efi_memdisk), signed:beast-booter"
extra secure_boot.grub_unsigned_sha256 "$UNSIGNED_SHA"
extra build.efi_modules[] "${EFI_MODULES[*]}"
extra build.efi_prefix "/grub"

# ---------------------------------------------------------------------------
# BIOS: boot.img + core.img + i386-pc modules for normal mode
# ---------------------------------------------------------------------------
for f in boot.img diskboot.img kernel.img lzma_decompress.img moddep.lst normal.mod; do
  [ -f "$BB_GRUB_BIOS_DIR/$f" ] || die "$BB_GRUB_BIOS_DIR/$f not found (package grub-pc-bin)"
done
pkg_resolve "$BB_GRUB_BIOS_DIR/boot.img"; BIOS_PKG="$P_KEY"     # grub-pc-bin=<ver>
verify_files "$BB_GRUB_BIOS_DIR"/*.img "$BB_GRUB_BIOS_DIR"/*.lst "$BB_GRUB_BIOS_DIR"/*.mod
log "i386-pc: all $VERIFIED module/image files in $BB_GRUB_BIOS_DIR are unmodified $BIOS_PKG"
[ "$(stat -c %s "$BB_GRUB_BIOS_DIR/boot.img")" = 512 ] || die "boot.img is not 512 bytes"
add_deb_file "$BB_GRUB_BIOS_DIR/boot.img" bios/boot.img

mapfile -t BIOS_MODULES < <(list_modules "$HERE/modules-bios-core.lst")
for m in "${BIOS_MODULES[@]}"; do
  [ -f "$BB_GRUB_BIOS_DIR/$m.mod" ] || die "module $m (build/modules-bios-core.lst) missing from $BB_GRUB_BIOS_DIR"
done
# GRUB's rescue parser (used for embedded configs) has no comments: strip them.
sed -e 's/^[[:space:]]*#.*//' "$HERE/early-bios.cfg" | grep -v '^[[:space:]]*$' > "$WORK/early-bios.cfg"
grub-mkimage -O i386-pc -d "$BB_GRUB_BIOS_DIR" -p '(,msdos2)/grub' -c "$WORK/early-bios.cfg" \
  -o "$WORK/core.img" "${BIOS_MODULES[@]}"
core_size="$(stat -c %s "$WORK/core.img")"
core_sectors=$(( (core_size + 511) / 512 ))
max_sectors="$(bbtool layout GPT_CORE_MAX_SECTORS)"
[ "$core_sectors" -le "$max_sectors" ] || die "core.img is $core_sectors sectors, more than $max_sectors (GPT BIOS boot partition)"
# Sanity-check the diskboot.img blocklist that the installer patches (ARCHITECTURE section 3):
# u64 start @0x1F4, u16 count @0x1FC (grub-mkimage fills in sectors-1), u16 segment @0x1FE.
read -r bl_count bl_seg < <(od -An -t u2 -j $((0x1FC)) -N 4 "$WORK/core.img")
[ "$bl_seg" = $((0x820)) ] || die "core.img blocklist segment is $bl_seg, expected 0x820"
[ "$bl_count" = $((core_sectors - 1)) ] || die "core.img blocklist count $bl_count != sectors-1 ($((core_sectors - 1)))"
add_file "$WORK/core.img" bios/core.img \
  "built:grub-mkimage from deb:$BIOS_PKG + repo:build/early-bios.cfg + repo:build/modules-bios-core.lst"
log "core.img: $core_size bytes ($core_sectors sectors, limit $max_sectors)"
extra build.bios_core_modules[] "${BIOS_MODULES[*]}"
extra build.bios_core_prefix "(,msdos2)/grub"

for f in "$BB_GRUB_BIOS_DIR"/*.mod "$BB_GRUB_BIOS_DIR"/*.lst; do
  add_deb_file "$f" "esp/grub/i386-pc/$(basename "$f")"
done

# ---------------------------------------------------------------------------
# Font, menu scripts, version.cfg
# ---------------------------------------------------------------------------
FONT=""
for f in "${BB_GRUB_FONT:-}" /usr/share/grub/unicode.pf2 "$TOOLS_ROOT/usr/share/grub/unicode.pf2"; do
  [ -n "$f" ] && [ -f "$f" ] && { FONT="$f"; break; }
done
[ -n "$FONT" ] || die "unicode.pf2 not found (package grub2-common / grub-common)"
add_deb_file "$FONT" esp/grub/fonts/unicode.pf2


nmenu=0
while IFS= read -r -d '' f; do
  rel="${f#"$MENU_DIR"/}"
  base="$(basename "$rel")"
  case "/$rel" in */.*) continue ;; esac                         # dotfiles, .git, swap files
  case "$base" in
    *~|*.swp|*.swo|*.bak|*.orig|*.rej|\#*\#|*.md) continue ;;     # editor backups, docs
    version.cfg|device.cfg) continue ;;                           # generated by build / installer
  esac
  [ -L "$f" ] && die "symlink in menu dir: $f (copy real files only)"
  case "$rel" in i386-pc/*|x86_64-efi/*|fonts/*.pf2|themes/beast/*) die "menu dir must not provide $rel (build output)";; esac
  add_file "$f" "esp/grub/$rel" "$(path_origin local "$f")"
  nmenu=$((nmenu + 1))
done < <(find "$MENU_DIR" \( -type f -o -type l \) -print0 | sort -z)
log "menu: $nmenu files from $MENU_DIR"

# ---------------------------------------------------------------------------
# beast-net: the "download an ISO from a link" helper (docs/BEASTNET.md).
# Ubuntu's signed kernel + initramfs, built reproducibly by build/beastnet/.
# BB_SKIP_BEASTNET=1 leaves it out (the menu then hides its entry).
# ---------------------------------------------------------------------------
if [ "${BB_SKIP_BEASTNET:-0}" != 1 ]; then
  log "beast-net helper (build/beastnet/build.sh)"
  bash "$HERE/beastnet/build.sh" "$WORK/bn" || die "beast-net build failed (BB_SKIP_BEASTNET=1 builds without it)"
  for f in vmlinuz initrd.img VERSION catalog.json; do
    o="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["beast-net/" + sys.argv[2]])' \
          "$WORK/bn/beast-net.origins.json" "$f")" || die "no origin for beast-net/$f"
    add_file "$WORK/bn/beast-net/$f" "esp/beast-net/$f" "$o"
  done
fi

# version.cfg last: its build id covers everything else, the beast-net helper included
# (grubx64.efi by its unsigned hash), so a drive with other helper files is another build.
BUILD_ID="$(bbtool build-id "$STAGE" "$VERSION" "$UNSIGNED_SHA")"
cat > "$WORK/version.cfg" <<EOF
# Generated by build/build.sh - do not edit.
set bb_version="$VERSION"
set bb_build_id="$BUILD_ID"
EOF
add_file "$WORK/version.cfg" esp/grub/beast/version.cfg "built:build/build.sh"

# ---------------------------------------------------------------------------
# Checks, timestamps, manifest, install
# ---------------------------------------------------------------------------
while read -r req; do
  [ -f "$STAGE/esp/$req" ] || die "required ESP file missing: $req (layout.REQUIRED_ESP_FILES)"
done < <(bbtool layout REQUIRED_ESP_FILES)
[ ! -e "$STAGE/esp/EFI/BOOT/fbx64.efi" ] || die "fbx64.efi must not be shipped"

find "$STAGE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
bbtool manifest-write --dist "$STAGE" --origins "$ORIGINS" --out "$STAGE/manifest.json" \
  --version "$VERSION" --source-date-epoch "$SOURCE_DATE_EPOCH" --build-id "$BUILD_ID" \
  --cert-der "$CER" --cert-subject "$CERT_SUBJECT" --sbat "$WORK/sbat.csv" --extra "$EXTRA"
touch -d "@$SOURCE_DATE_EPOCH" "$STAGE/manifest.json"
bbtool manifest-verify "$STAGE" >/dev/null

if [ -e "$DIST" ]; then
  OLD="$(mktemp -d "$(dirname "$DIST")/.dist-old.XXXXXX")"
  mv "$DIST" "$OLD/dist"
  mv "$STAGE" "$DIST"
  rm -rf "$OLD"
else
  mv "$STAGE" "$DIST"
fi

nfiles="$(grep -c . "$ORIGINS")"
log "wrote $DIST ($nfiles files + manifest.json), build id $BUILD_ID"
log "certificate: $CERT_SUBJECT, SHA-256 $(sha256sum < "$CER" | cut -d' ' -f1)"
log "SBAT embedded in esp/EFI/BOOT/grubx64.efi:"
sed 's/^/  /' "$WORK/sbat.csv"
