#!/usr/bin/env bash
# beast-boot: sign the boot images of a build, and nothing else.
#
# The release workflow runs this in its own small job, so the signing keys are never
# on a disk next to the GRUB build, the tests or the scanners (docs/RELEASING.md,
# "Signing in its own job"). It only runs openssl, sbsign, sbverify and sbattach.
# Each file is signed with its own component's leaf key (build/sbkeys.sh); the CA's
# private key is not used here and must not be on this machine.
#
# Usage: build/sign.sh UNSIGNED_DIR OUT_DIR
#   UNSIGNED_DIR  what `BB_UNSIGNED_OUT=DIR build/build.sh` wrote: grubx64.efi and,
#                 when the build has them, vmlinuz and wimboot. Any other file, or a
#                 file that already carries a signature, is refused.
#   OUT_DIR       receives the signed files under the same names, plus the
#                 certificates (never a key): beast-boot.crt and beast-boot.cer (the
#                 CA) and beast-boot-<component>.crt of every file signed.
#                 Pass it to the build as BB_PRESIGNED_DIR and BB_KEY_DIR.
# Environment:
#   BB_KEY_DIR    beast-boot.crt (the CA certificate) and, for every file to sign,
#                 beast-boot-<component>.key and .crt (default: $BB_ROOT/keys)
set -euo pipefail
export LC_ALL=C

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BB_ROOT="${BB_ROOT:-$(cd -- "$HERE/.." && pwd)}"
# shellcheck source=build/sbkeys.sh
source "$HERE/sbkeys.sh"
NAMES=(grubx64.efi vmlinuz wimboot)

log() { echo "sign: $*"; }
die() { echo "sign: error: $*" >&2; exit 1; }

signatures() {  # FILE: how many signatures it carries
  local s
  s="$(sbverify --list "$1" 2>/dev/null)" || true
  grep -c '^signature ' <<<"$s" || true
}

sign_one() {  # NAME: sign $IN/NAME with its component's leaf key into $OUT/NAME and check the result
  local name="$1" stripped="$TMP/stripped" comp key crt p
  comp="$(bb_component_of "$name")"
  key="$KEY_DIR/beast-boot-$comp.key"; crt="$KEY_DIR/beast-boot-$comp.crt"
  p="$(bb_leaf_problem "$CA" "$crt" "$comp")"; [ -z "$p" ] || die "$p"
  [ -f "$key" ] || die "signing key not found: $key"
  [ "$(openssl x509 -in "$crt" -noout -pubkey | sha256sum)" = \
    "$(openssl pkey -in "$key" -pubout 2>/dev/null | sha256sum)" ] || die "$key does not belong to $crt"
  [ "$(signatures "$IN/$name")" = 0 ] || die "$IN/$name already carries a signature"
  sbsign --key "$key" --cert "$crt" --output "$OUT/$name" "$IN/$name" >/dev/null 2>"$TMP/sbsign.log" \
    || { cat "$TMP/sbsign.log" >&2; die "sbsign failed for $name"; }
  # the CA as trust anchor: the signature's own certificate (the leaf) must chain to it
  sbverify --cert "$CA" "$OUT/$name" >/dev/null 2>&1 || die "sbverify failed for the signed $name"
  [ "$(signatures "$OUT/$name")" = 1 ] || die "the signed $name does not carry exactly one signature"
  cp "$OUT/$name" "$stripped"
  { sbattach --remove "$stripped" >/dev/null 2>&1 && cmp -s "$stripped" "$IN/$name"; } \
    || die "the signed $name without its signature is not the file that was given"
  openssl x509 -in "$crt" -out "$OUT/beast-boot-$comp.crt"
  log "$name: signed by $(bb_cert_subject "$crt") ($(sha256sum < "$IN/$name" | cut -d' ' -f1) unsigned)"
}

main() {
  [ "$#" = 2 ] || { sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
  IN="$1"; OUT="$2"
  local t f name known n=0
  for t in openssl sbsign sbverify sbattach sha256sum cmp; do
    command -v "$t" >/dev/null || die "required tool not found: $t"
  done
  [ -d "$IN" ] || die "not a directory: $IN"
  KEY_DIR="${BB_KEY_DIR:-$BB_ROOT/keys}"
  CA="$KEY_DIR/beast-boot.crt"
  [ -f "$CA" ] || die "CA certificate not found: $CA"
  f="$(bb_ca_problem "$CA")"; [ -z "$f" ] || die "$f"
  [ ! -e "$KEY_DIR/beast-boot-ca.key" ] || log "WARNING: $KEY_DIR holds the CA's private key; a release CA key belongs offline, not where files are signed"

  for f in "$IN"/* "$IN"/.[!.]* "$IN"/..?*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    name="$(basename "$f")"; known=0
    for t in "${NAMES[@]}"; do if [ "$t" = "$name" ]; then known=1; fi; done
    [ "$known" = 1 ] || die "unexpected file in $IN: $name (only ${NAMES[*]} are signed)"
    [ -f "$f" ] && [ ! -L "$f" ] || die "$f is not a regular file"
  done
  [ -f "$IN/grubx64.efi" ] || die "$IN has no grubx64.efi"

  mkdir -p "$OUT"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  for name in "${NAMES[@]}"; do
    if [ -f "$IN/$name" ]; then sign_one "$name"; n=$((n + 1)); fi
  done
  # the certificate only: the next job checks the signatures and ships the .cer
  openssl x509 -in "$CA" -out "$OUT/beast-boot.crt"
  openssl x509 -in "$CA" -outform DER -out "$OUT/beast-boot.cer"
  log "$n file(s) signed, each with its own certificate from $(bb_cert_subject "$CA")"
}

main "$@"
