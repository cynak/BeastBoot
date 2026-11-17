#!/usr/bin/env bash
# beast-boot: create the Secure Boot keys: a CA, and one signing ("leaf")
# certificate per signed component, issued by that CA.
#
#   grub     signs EFI/BOOT/grubx64.efi
#   kernel   signs beast-net/vmlinuz (the helper's kernel)
#   wimboot  signs beast-booter/wimboot
#
# Users enroll the CA certificate once (it is shipped on the drive as
# ENROLL_THIS_KEY_IN_MOKMANAGER.cer). Each component can then be revoked on
# its own, with one MokListX entry (its leaf certificate), and replaced with a
# new leaf from the same CA without anyone enrolling anything again
# (docs/SECURE_BOOT.md section 7, docs/RELEASING.md section 3).
#
# Usage:
#   build/keygen.sh [--force]            everything for local development, in one
#                                        directory: the CA and the three leaves
#                                        (`make keys`)
#   build/keygen.sh ca [--force]         only the CA, into BB_CA_DIR
#   build/keygen.sh leaf COMPONENT|all [--force]
#                                        issue the leaf of grub, kernel or wimboot
#                                        (or all three) with the CA in BB_CA_DIR,
#                                        into BB_KEY_DIR
#   --force   replace existing files. A new CA means every computer must enroll
#             again; a new leaf does not (the old leaf's signatures stay valid
#             until that leaf is revoked).
#
# Files:
#   BB_CA_DIR/beast-boot-ca.key       the CA's private key, PEM, mode 0600. For a
#                                     release CA: offline, never on a build host
#                                     or in CI. Only `leaf` reads it.
#   BB_CA_DIR/beast-boot.crt, .cer    the CA certificate, PEM and DER
#   BB_KEY_DIR/beast-boot.crt, .cer   a copy of the CA certificate (the build
#                                     ships the .cer; nothing here is secret)
#   BB_KEY_DIR/beast-boot-<component>.key   leaf private key, PEM, mode 0600
#   BB_KEY_DIR/beast-boot-<component>.crt   leaf certificate, PEM
#
# Certificates (what shim 16.1 accepts was checked by test,
# tests/e2e/test_e2e_ca_chain.py):
#   CA    basicConstraints critical CA:TRUE pathlen:0, keyUsage critical
#         keyCertSign cRLSign, no extendedKeyUsage
#   leaf  basicConstraints critical CA:FALSE, keyUsage critical digitalSignature,
#         extendedKeyUsage codeSigning; subject OU = the component (the build
#         refuses a file signed with another component's leaf)
# No certificate carries 1.3.6.1.4.1.2312.16.1.2 ("kernel module signing
# only"): shim refuses to trust an enrolled certificate with that OID for
# boot loaders (it does not look for it on a leaf under an enrolled CA).
#
# Environment:
#   BB_KEY_DIR    leaves (and a copy of the CA certificate)   (default: $BB_ROOT/keys)
#   BB_CA_DIR     the CA                                      (default: BB_KEY_DIR)
#   BB_KEY_CN     the CA's common name (default: "beast-boot Secure Boot CA (local)")
#   BB_CA_DAYS    validity of the CA in days     (default: 7300, about 20 years)
#   BB_KEY_DAYS   validity of a leaf in days     (default: 3650, about 10 years)
#                 Firmware and shim do not check certificate dates; the build's
#                 own tools do (see docs/SECURE_BOOT.md, "Certificate dates").
set -euo pipefail
export LC_ALL=C

BB_ROOT="${BB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KEY_DIR="${BB_KEY_DIR:-$BB_ROOT/keys}"
CA_DIR="${BB_CA_DIR:-$KEY_DIR}"
CN="${BB_KEY_CN:-beast-boot Secure Boot CA (local)}"
CA_DAYS="${BB_CA_DAYS:-7300}"
DAYS="${BB_KEY_DAYS:-3650}"
COMPONENTS=(grub kernel wimboot)

die() { echo "keygen: error: $*" >&2; exit 1; }
say() { echo "keygen: $*"; }

describe() {  # CRT: subject, validity and fingerprints of a certificate
  say "  subject: $(openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  say "  valid:   $(openssl x509 -in "$1" -noout -startdate | cut -d= -f2) .. $(openssl x509 -in "$1" -noout -enddate | cut -d= -f2)"
  say "  SHA-256: $(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"
  say "  SHA-1:   $(openssl x509 -in "$1" -noout -fingerprint -sha1 | cut -d= -f2)   (what MokManager and mokutil show)"
}

refuse_existing() {  # FILE...: stop if one exists and --force was not given
  local f existing=()
  for f in "$@"; do if [ -e "$f" ]; then existing+=("$f"); fi; done
  if [ "${#existing[@]}" -gt 0 ] && [ "$force" != 1 ]; then
    die "refusing to overwrite: ${existing[*]}
       Re-run with --force if you really want new ones (a new CA: every computer
       must enroll again; a new leaf: nobody has to)."
  fi
}

make_ca() {
  local key="$CA_DIR/beast-boot-ca.key" crt="$CA_DIR/beast-boot.crt" cer="$CA_DIR/beast-boot.cer"
  refuse_existing "$key" "$crt" "$cer"
  mkdir -p "$CA_DIR"
  cat > "$tmp/ca.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions    = ext
string_mask        = utf8only
prompt             = no
[ dn ]
CN = $CN
[ ext ]
basicConstraints     = critical,CA:TRUE,pathlen:0
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  ( umask 077
    openssl req -config "$tmp/ca.cnf" -new -x509 -sha256 -newkey rsa:2048 -nodes -days "$CA_DAYS" \
      -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>"$tmp/log" || { cat "$tmp/log" >&2; exit 1; } )
  openssl x509 -in "$tmp/ca.crt" -outform DER -out "$tmp/ca.cer"
  install -m 0600 "$tmp/ca.key" "$key"
  install -m 0644 "$tmp/ca.crt" "$crt"
  install -m 0644 "$tmp/ca.cer" "$cer"
  say "CA: wrote $key (private, mode 0600: keep it offline and backed up)"
  say "CA: wrote $crt and $cer (the certificate users enroll)"
  describe "$crt"
}

make_leaf() {  # COMPONENT
  local c="$1" ca_key="$CA_DIR/beast-boot-ca.key" ca_crt="$CA_DIR/beast-boot.crt"
  local key="$KEY_DIR/beast-boot-$c.key" crt="$KEY_DIR/beast-boot-$c.crt"
  [ -f "$ca_key" ] && [ -f "$ca_crt" ] || die "no CA in $CA_DIR (beast-boot-ca.key, beast-boot.crt): run 'build/keygen.sh ca' or set BB_CA_DIR"
  refuse_existing "$key" "$crt"
  mkdir -p "$KEY_DIR"
  # The leaf's O is the name of the CA that issues it, read from the CA certificate (not from
  # BB_KEY_CN: a leaf issued later, without that variable, must not get the default name).
  local ca_cn
  ca_cn="$(openssl x509 -in "$ca_crt" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p' | head -n 1)"
  [ -n "$ca_cn" ] || die "the CA certificate in $CA_DIR has no common name"
  # The date in the name tells a replaced leaf from its successor in MokManager's lists.
  cat > "$tmp/leaf.cnf" <<EOF
[ req ]
distinguished_name = dn
string_mask        = utf8only
prompt             = no
[ dn ]
O  = $ca_cn
OU = $c
CN = beast-boot $c signer $(date -u +%Y-%m-%d)
[ ext ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = codeSigning
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
  ( umask 077
    openssl req -config "$tmp/leaf.cnf" -new -sha256 -newkey rsa:2048 -nodes \
      -keyout "$tmp/$c.key" -out "$tmp/$c.csr" 2>"$tmp/log" || { cat "$tmp/log" >&2; exit 1; } )
  openssl x509 -req -sha256 -days "$DAYS" -in "$tmp/$c.csr" -CA "$ca_crt" -CAkey "$ca_key" \
    -set_serial "0x$(openssl rand -hex 16)" -extfile "$tmp/leaf.cnf" -extensions ext -out "$tmp/$c.crt" 2>"$tmp/log" \
    || { cat "$tmp/log" >&2; die "the CA could not sign the $c leaf"; }
  openssl verify -CAfile "$ca_crt" "$tmp/$c.crt" >/dev/null 2>&1 || die "the new $c leaf does not verify against the CA"
  openssl x509 -in "$tmp/$c.crt" -noout -ext extendedKeyUsage | grep -q "Code Signing" \
    || die "the new $c leaf lacks the codeSigning EKU"
  [ "$(openssl x509 -in "$tmp/$c.crt" -noout -pubkey | sha256sum)" = \
    "$(openssl pkey -in "$tmp/$c.key" -pubout 2>/dev/null | sha256sum)" ] || die "the new $c key and certificate do not match"
  install -m 0600 "$tmp/$c.key" "$key"
  install -m 0644 "$tmp/$c.crt" "$crt"
  if [ "$CA_DIR" != "$KEY_DIR" ]; then   # the build needs the CA certificate next to the leaves
    install -m 0644 "$ca_crt" "$KEY_DIR/beast-boot.crt"
    openssl x509 -in "$ca_crt" -outform DER -out "$KEY_DIR/beast-boot.cer"
  fi
  say "$c: wrote $key (private, mode 0600) and $crt"
  describe "$crt"
}

cmd=all force=0 what=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    ca) cmd=ca ;;
    leaf) cmd=leaf; what="${2:-}"; [ -n "$what" ] || die "leaf needs a component: ${COMPONENTS[*]} or all"; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

command -v openssl >/dev/null || die "openssl not found"
case "$CN" in */*|*,*|*=*|*+*|*\\*) die "BB_KEY_CN must not contain / , = + or \\" ;; esac
[[ "$DAYS" =~ ^[0-9]+$ ]] && [[ "$CA_DAYS" =~ ^[0-9]+$ ]] || die "BB_KEY_DAYS and BB_CA_DAYS must be numbers of days"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$cmd" in
  ca) make_ca ;;
  leaf)
    if [ "$what" = all ]; then for c in "${COMPONENTS[@]}"; do make_leaf "$c"; done
    else
      case " ${COMPONENTS[*]} " in *" $what "*) make_leaf "$what" ;; *) die "unknown component '$what' (${COMPONENTS[*]} or all)" ;; esac
    fi ;;
  all)
    [ "$CA_DIR" = "$KEY_DIR" ] || die "without a command the CA and the leaves go into one directory (BB_KEY_DIR); for a separate CA use 'ca' and 'leaf'"
    files=("$KEY_DIR/beast-boot-ca.key" "$KEY_DIR/beast-boot.crt" "$KEY_DIR/beast-boot.cer")
    for c in "${COMPONENTS[@]}"; do files+=("$KEY_DIR/beast-boot-$c.key" "$KEY_DIR/beast-boot-$c.crt"); done
    refuse_existing "${files[@]}"
    force=1
    make_ca
    for c in "${COMPONENTS[@]}"; do make_leaf "$c"; done
    say "now run 'make build' to sign the boot files with these keys." ;;
esac
