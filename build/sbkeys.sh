#!/usr/bin/env bash
# beast-boot: the Secure Boot key layout, shared by build/build.sh and build/sign.sh
# (sourced; it only defines functions and runs openssl).
#
# BB_KEY_DIR holds the CA certificate users enroll (beast-boot.crt, beast-boot.cer) and
# one signing certificate per signed file, issued by that CA (build/keygen.sh):
#   grubx64.efi -> beast-boot-grub.{key,crt}     vmlinuz -> beast-boot-kernel.{key,crt}
#   wimboot     -> beast-boot-wimboot.{key,crt}
# A leaf certificate names its component in the subject's OU, so a file signed with
# another component's leaf is refused, also when the files were renamed.

bb_component_of() {  # FILE NAME (grubx64.efi | vmlinuz | wimboot): prints its component
  case "$1" in
    grubx64.efi) echo grub ;;
    vmlinuz) echo kernel ;;
    wimboot) echo wimboot ;;
    *) return 1 ;;
  esac
}

bb_cert_subject() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'; }
bb_cert_sha256() { openssl x509 -in "$1" -outform DER | sha256sum | cut -d' ' -f1; }

# bb_ca_problem CA_CRT: prints why CA_CRT cannot be the BeastBoot CA (nothing if it can).
bb_ca_problem() {
  local t
  t="$(openssl x509 -in "$1" -noout -ext basicConstraints,extendedKeyUsage 2>/dev/null)" || true
  if ! grep -q 'CA:TRUE' <<<"$t"; then echo "$1 is not a CA certificate (basicConstraints CA:TRUE): build/keygen.sh makes the CA and its leaves"; return 0; fi
  if grep -q '1\.3\.6\.1\.4\.1\.2312\.16\.1\.2' <<<"$t"; then echo "$1 carries the kernel-module-signing-only EKU, which shim refuses"; fi
}

# bb_leaf_problem CA_CRT LEAF_CRT COMPONENT: prints why LEAF_CRT cannot sign COMPONENT
# (nothing if it can): it must be issued by the CA and be valid today, be a code-signing
# end-entity certificate, and name COMPONENT in its subject's OU.
bb_leaf_problem() {
  local ca="$1" crt="$2" comp="$3" t subj
  [ -f "$crt" ] || { echo "$crt not found (build/keygen.sh leaf $comp)"; return 0; }
  if ! openssl verify -CAfile "$ca" "$crt" >/dev/null 2>&1; then
    echo "$crt is not a valid certificate issued by $(bb_cert_subject "$ca") (wrong CA, or expired: issue a new one with build/keygen.sh leaf $comp)"; return 0
  fi
  t="$(openssl x509 -in "$crt" -noout -ext basicConstraints,extendedKeyUsage 2>/dev/null)" || true
  if grep -q 'CA:TRUE' <<<"$t"; then echo "$crt is a CA certificate, not a signing certificate"; return 0; fi
  if ! grep -q 'Code Signing' <<<"$t"; then echo "$crt lacks extendedKeyUsage=codeSigning"; return 0; fi
  if grep -q '1\.3\.6\.1\.4\.1\.2312\.16\.1\.2' <<<"$t"; then echo "$crt carries the kernel-module-signing-only EKU, which shim refuses"; return 0; fi
  subj="$(bb_cert_subject "$crt")"
  case ",$subj," in
    *",OU=$comp,"*) ;;
    *) echo "$crt is not the $comp signing certificate (its subject is $subj; expected OU=$comp)" ;;
  esac
}
