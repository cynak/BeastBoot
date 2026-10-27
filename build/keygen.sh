#!/usr/bin/env bash
# beast-boot: create a local Secure Boot signing key (run via `make keys`).
#
# Writes, into ${BB_KEY_DIR:-$BB_ROOT/keys}:
#   beast-boot.key   RSA-2048 private key, PEM, mode 0600. NEVER share or commit it.
#   beast-boot.crt   self-signed X.509 certificate, PEM (used by sbsign)
#   beast-boot.cer   the same certificate, DER (shipped on the drive as
#                      ENROLL_THIS_KEY_IN_MOKMANAGER.cer for MokManager)
#
# The certificate carries extendedKeyUsage=codeSigning only. In particular it
# does NOT carry 1.3.6.1.4.1.2312.16.1.2 ("kernel module signing only"):
# shim refuses certificates with that OID for verifying boot loaders.
#
# Usage: build/keygen.sh [--force]
#   --force       overwrite an existing key (machines that enrolled the old
#                 certificate will no longer trust newly signed builds)
# Environment:
#   BB_KEY_DIR    output directory          (default: $BB_ROOT/keys)
#   BB_KEY_CN     certificate common name   (default: "beast-boot Secure Boot key (local)")
#   BB_KEY_DAYS   validity in days          (default: 3650, about 10 years;
#                 firmware and shim do not check certificate dates)
set -euo pipefail
export LC_ALL=C

BB_ROOT="${BB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KEY_DIR="${BB_KEY_DIR:-$BB_ROOT/keys}"
CN="${BB_KEY_CN:-beast-boot Secure Boot key (local)}"
DAYS="${BB_KEY_DAYS:-3650}"

die() { echo "keygen: error: $*" >&2; exit 1; }

force=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $arg (try --help)" ;;
  esac
done

command -v openssl >/dev/null || die "openssl not found"
case "$CN" in */*|*,*|*=*|*+*|*\\*) die "BB_KEY_CN must not contain / , = + or \\" ;; esac
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "BB_KEY_DAYS must be a number of days"

KEY="$KEY_DIR/beast-boot.key"
CRT="$KEY_DIR/beast-boot.crt"
CER="$KEY_DIR/beast-boot.cer"

existing=()
for f in "$KEY" "$CRT" "$CER"; do [ -e "$f" ] && existing+=("$f"); done
if [ "${#existing[@]}" -gt 0 ] && [ "$force" != 1 ]; then
  die "refusing to overwrite existing key files: ${existing[*]}
       Machines that enrolled the current certificate trust only builds signed
       with this key. Re-run with --force if you really want a new key."
fi

mkdir -p "$KEY_DIR"
tmp="$(mktemp -d "$KEY_DIR/.keygen.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/openssl.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions    = ext
string_mask        = utf8only
prompt             = no

[ dn ]
CN = $CN

[ ext ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = codeSigning
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

(
  umask 077
  openssl req -config "$tmp/openssl.cnf" -new -x509 -sha256 \
    -newkey rsa:2048 -nodes -days "$DAYS" \
    -keyout "$tmp/key" -out "$tmp/crt" 2>"$tmp/log" \
    || { cat "$tmp/log" >&2; exit 1; }
)
openssl x509 -in "$tmp/crt" -outform DER -out "$tmp/cer"

# Sanity checks on what we just made.
openssl x509 -in "$tmp/crt" -noout -ext extendedKeyUsage | grep -q "Code Signing" \
  || die "generated certificate lacks the codeSigning EKU"
[ "$(openssl x509 -in "$tmp/crt" -noout -modulus | sha256sum)" = \
  "$(openssl rsa -in "$tmp/key" -noout -modulus 2>/dev/null | sha256sum)" ] \
  || die "generated key and certificate do not match"

install -m 0600 "$tmp/key" "$KEY"
install -m 0644 "$tmp/crt" "$CRT"
install -m 0644 "$tmp/cer" "$CER"

echo "keygen: wrote $KEY (private, mode 0600 - keep it secret)"
echo "keygen: wrote $CRT"
echo "keygen: wrote $CER"
echo "keygen: subject: $(openssl x509 -in "$CRT" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
echo "keygen: valid:   $(openssl x509 -in "$CRT" -noout -startdate | cut -d= -f2) .. $(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2)"
echo "keygen: SHA-256 fingerprint: $(openssl x509 -in "$CRT" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "keygen: SHA-1 fingerprint (shown by MokManager and mokutil): $(openssl x509 -in "$CRT" -noout -fingerprint -sha1 | cut -d= -f2)"
echo "keygen: now run 'make build' to sign the boot files with this key."
