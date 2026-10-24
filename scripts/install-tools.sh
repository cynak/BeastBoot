#!/usr/bin/env bash
# sbom-vuln: install the pinned SBOM / vulnerability toolchain, rootless.
#
#   .tools/bin/syft          SBOM generator (cross-check of our own SBOM)
#   .tools/bin/grype         vulnerability matcher (Anchore DB)
#   .tools/bin/osv-scanner   vulnerability matcher (OSV.dev)
#   .tools/cache/schemas/    CycloneDX 1.6 + SPDX 2.3 JSON schemas for validation
#
# Every download is pinned to an exact version and verified twice:
#   1. the publisher's checksum file must hash to the value pinned here, and
#   2. the artifact must hash to the value pinned here AND to the entry for it
#      in the publisher's checksum file.
# A mismatch aborts; nothing unverified is installed. Re-running is cheap: files
# that are already present and verified are kept.
#
# Usage: install-tools.sh [--force]      (--force re-downloads everything)
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${BB_ROOT:-$(cd "$HERE/.." && pwd)}"
BIN="$ROOT/.tools/bin"
CACHE="$ROOT/.tools/cache"
DL="$CACHE/downloads"
SCHEMAS="$CACHE/schemas"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) echo "install-tools: only linux/amd64 is pinned here (got $(uname -s)/$(uname -m))" >&2; exit 1 ;;
esac

# --- pins --------------------------------------------------------------------
# Chosen: newest release that was at least two weeks old on 2026-10-23.
# Values copied from the publishers' checksum files and cross-checked against
# the GitHub release asset digests.
SYFT_VERSION=1.54.1
SYFT_TGZ=syft_${SYFT_VERSION}_linux_amd64.tar.gz
SYFT_SHA256=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47
SYFT_SUMS=syft_${SYFT_VERSION}_checksums.txt
SYFT_SUMS_SHA256=7577f0d0b3fb16f65a2e56b413862f69aa5eaa2379d5760cb73d691ca7986059
SYFT_URL=https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}

GRYPE_VERSION=0.120.1
GRYPE_TGZ=grype_${GRYPE_VERSION}_linux_amd64.tar.gz
GRYPE_SHA256=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
GRYPE_SUMS=grype_${GRYPE_VERSION}_checksums.txt
GRYPE_SUMS_SHA256=c25b6095265b44fd9bbb9dbe76aca8daa394c5f0490793d2b52b16be4f5b71b1
GRYPE_URL=https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}

OSV_VERSION=2.6.0
OSV_BIN=osv-scanner_linux_amd64
OSV_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
OSV_SUMS=osv-scanner_SHA256SUMS
OSV_SUMS_SHA256=29f6fbc8bdd02d977df4b0987705d046233c36b70469a7021c623e8c155c9ddc
OSV_URL=https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}

# CycloneDX specification, tag 1.6.2 (commit below), directory schema/.
CDX_COMMIT=e833d732337dd33aceb45ff1991f896796f1e5e7
CDX_RAW=https://raw.githubusercontent.com/CycloneDX/specification/${CDX_COMMIT}/schema
CDX_SCHEMAS=(
  "bom-1.6.schema.json 18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d"
  "spdx.schema.json c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6"
  "jsf-0.82.schema.json 8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"
)
# SPDX specification, tag v2.3 (commit below), schemas/spdx-schema.json.
SPDX_COMMIT=aadf3b0b8dbbabdb4d880b0fc714255fea436ff7
SPDX_URL=https://raw.githubusercontent.com/spdx/spdx-spec/${SPDX_COMMIT}/schemas/spdx-schema.json
SPDX_SHA256=239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b

# --- helpers -----------------------------------------------------------------
log() { echo "install-tools: $*"; }
die() { echo "install-tools: error: $*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# fetch URL DEST SHA256: download unless DEST already has that hash.
fetch() {
  local url="$1" dest="$2" want="$3"
  if [ "$FORCE" = 0 ] && [ -f "$dest" ] && [ "$(sha "$dest")" = "$want" ]; then
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  log "downloading $url"
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$dest.part" "$url" \
    || { rm -f "$dest.part"; die "download failed: $url"; }
  local got; got="$(sha "$dest.part")"
  [ "$got" = "$want" ] || { rm -f "$dest.part"; die "SHA-256 mismatch for $url
    expected $want
    got      $got"; }
  mv "$dest.part" "$dest"
}

# sums_entry SUMSFILE NAME -> the publisher's SHA-256 for NAME
sums_entry() { awk -v n="$2" '$2 == n || $2 == "*"n { print $1 }' "$1"; }

verify_against_sums() {   # SUMSFILE NAME PINNED
  local e; e="$(sums_entry "$1" "$2")"
  [ -n "$e" ] || die "$2 is not listed in $(basename "$1")"
  [ "$e" = "$3" ] || die "pinned SHA-256 of $2 ($3) differs from the publisher's ($e)"
}

installed_version() {     # TOOL -> version string it reports, or empty
  local t="$BIN/$1"
  [ -x "$t" ] || return 0
  case "$1" in
    syft|grype) "$t" version -o json 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true ;;
    osv-scanner) "$t" --version 2>/dev/null | sed -n 's/^osv-scanner version: *//p' | head -n1 ;;
  esac
}

install_tgz_tool() {      # NAME VERSION URLBASE TGZ SHA SUMS SUMS_SHA
  local name="$1" ver="$2" base="$3" tgz="$4" want="$5" sums="$6" sums_sha="$7"
  if [ "$FORCE" = 0 ] && [ "$(installed_version "$name")" = "$ver" ]; then
    log "$name $ver already installed"; return 0
  fi
  fetch "$base/$sums" "$DL/$sums" "$sums_sha"
  verify_against_sums "$DL/$sums" "$tgz" "$want"
  fetch "$base/$tgz" "$DL/$tgz" "$want"
  local x; x="$(mktemp -d "$DL/x.XXXXXX")"
  tar -xzf "$DL/$tgz" -C "$x" --no-same-owner "$name"
  install -m 0755 "$x/$name" "$BIN/$name"
  rm -rf "$x"
  log "installed $name $ver -> $BIN/$name"
}

# --- main --------------------------------------------------------------------
mkdir -p "$BIN" "$DL" "$SCHEMAS" "$CACHE/grype" "$CACHE/osv-scanner"

install_tgz_tool syft  "$SYFT_VERSION"  "$SYFT_URL"  "$SYFT_TGZ"  "$SYFT_SHA256"  "$SYFT_SUMS"  "$SYFT_SUMS_SHA256"
install_tgz_tool grype "$GRYPE_VERSION" "$GRYPE_URL" "$GRYPE_TGZ" "$GRYPE_SHA256" "$GRYPE_SUMS" "$GRYPE_SUMS_SHA256"

if [ "$FORCE" = 0 ] && [ "$(installed_version osv-scanner)" = "$OSV_VERSION" ]; then
  log "osv-scanner $OSV_VERSION already installed"
else
  fetch "$OSV_URL/$OSV_SUMS" "$DL/$OSV_SUMS" "$OSV_SUMS_SHA256"
  verify_against_sums "$DL/$OSV_SUMS" "$OSV_BIN" "$OSV_SHA256"
  fetch "$OSV_URL/$OSV_BIN" "$DL/$OSV_BIN" "$OSV_SHA256"
  install -m 0755 "$DL/$OSV_BIN" "$BIN/osv-scanner"
  log "installed osv-scanner $OSV_VERSION -> $BIN/osv-scanner"
fi

for entry in "${CDX_SCHEMAS[@]}"; do
  read -r schema_file schema_sha256 <<<"$entry"
  fetch "$CDX_RAW/$schema_file" "$SCHEMAS/cyclonedx-1.6/$schema_file" "$schema_sha256"
done
fetch "$SPDX_URL" "$SCHEMAS/spdx-2.3/spdx-schema.json" "$SPDX_SHA256"

# Record what is installed; the scan report quotes this file.
cat > "$ROOT/.tools/sbom-vuln-tools.json" <<EOF
{
  "syft": {"version": "$SYFT_VERSION", "asset": "$SYFT_TGZ", "sha256": "$SYFT_SHA256"},
  "grype": {"version": "$GRYPE_VERSION", "asset": "$GRYPE_TGZ", "sha256": "$GRYPE_SHA256"},
  "osv-scanner": {"version": "$OSV_VERSION", "asset": "$OSV_BIN", "sha256": "$OSV_SHA256"},
  "cyclonedx-schema": {"commit": "$CDX_COMMIT", "tag": "1.6.2"},
  "spdx-schema": {"commit": "$SPDX_COMMIT", "tag": "v2.3", "sha256": "$SPDX_SHA256"}
}
EOF

for t in syft grype osv-scanner; do
  v="$(installed_version "$t")"
  [ -n "$v" ] || die "$t does not run after install"
  log "ok: $t $v"
done
log "ok: schemas in $SCHEMAS"
