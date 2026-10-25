# shellcheck shell=bash
# Source this file (bash or zsh):  source scripts/dev-env.sh
# Puts the local toolchain (.tools/bin) and the installer package on the path,
# and exports the directories the build uses. Safe to source more than once.

if [ -n "${ZSH_VERSION:-}" ]; then
  eval '_bb_src="${(%):-%x}"'
else
  _bb_src="${BASH_SOURCE[0]}"
fi
BB_ROOT="$(cd "$(dirname "$_bb_src")/.." && pwd)"
export BB_ROOT
unset _bb_src

if [ -d "$BB_ROOT/.tools/bin" ]; then
  case ":$PATH:" in
    *":$BB_ROOT/.tools/bin:"*) ;;
    *) export PATH="$BB_ROOT/.tools/bin:$PATH" ;;
  esac
fi

case ":${PYTHONPATH:-}:" in
  *":$BB_ROOT/installer:"*) ;;
  *) export PYTHONPATH="$BB_ROOT/installer${PYTHONPATH:+:$PYTHONPATH}" ;;
esac

# Firmware / GRUB directories: system install preferred, .tools fallback.
# _bb_pick <current value> <file that must exist> <dir>...
#   -> the current value when it is set and either is not one of these dirs
#      (the user chose it: it always wins) or holds the file; otherwise the
#      first dir that holds the file, else the first dir.
# A current value that is one of these dirs but lacks the file is a fallback
# from an earlier source, e.g. before scripts/bootstrap-tools.sh unpacked
# .tools/root, so it is picked again instead of kept.
_bb_pick() {
  _cur="$1"; _f="$2"; shift 2
  if [ -n "$_cur" ]; then
    _own=0
    for d in "$@"; do [ "$d" = "$_cur" ] && _own=1; done
    if [ "$_own" = 0 ] || [ -e "$_cur/$_f" ]; then echo "$_cur"; return; fi
  fi
  for d in "$@"; do [ -e "$d/$_f" ] && { echo "$d"; return; }; done
  echo "$1"
}
_bb_t="$BB_ROOT/.tools/root"
# GRUB modules: our source build first (build/grub/grubsrc.py keeps
# .tools/cache/grub-src/current pointing at the last one; it is what dist/
# ships, with kernel.exec + *.module for gdb next to the modules). build.sh
# itself never reads these variables: it always uses the source build.
_bb_g="${BB_GRUB_CACHE:-$BB_ROOT/.tools/cache/grub-src}/current"
BB_GRUB_EFI_DIR="$(_bb_pick "${BB_GRUB_EFI_DIR:-}" kernel.img "$_bb_g/x86_64-efi" /usr/lib/grub/x86_64-efi "$_bb_t/usr/lib/grub/x86_64-efi")"
# Ubuntu's signed GRUB: only the e2e stub images use it (its SBAT)
BB_GRUB_EFI_SIGNED_DIR="$(_bb_pick "${BB_GRUB_EFI_SIGNED_DIR:-}" grubx64.efi.signed /usr/lib/grub/x86_64-efi-signed "$_bb_t/usr/lib/grub/x86_64-efi-signed")"
BB_GRUB_BIOS_DIR="$(_bb_pick "${BB_GRUB_BIOS_DIR:-}" boot.img "$_bb_g/i386-pc" /usr/lib/grub/i386-pc "$_bb_t/usr/lib/grub/i386-pc")"
unset _bb_g
# shim + MokManager: Debian's, pinned in build/shim/debian-shim.lock and unpacked
# by scripts/bootstrap-tools.sh into BB_DEBIAN_DIR. A host /usr/lib/shim only
# counts when it holds Debian's files (on Ubuntu it is Ubuntu's shim: never used).
# The last candidate is where Ubuntu's shim was unpacked before (.tools/root): it
# has no mmx64.efi.signed, so a value left from then is replaced, not kept.
: "${BB_DEBIAN_DIR:=$BB_ROOT/.tools/debian}"
BB_SHIM_DIR="$(_bb_pick "${BB_SHIM_DIR:-}" mmx64.efi.signed "$BB_DEBIAN_DIR/root/usr/lib/shim" /usr/lib/shim "$_bb_t/usr/lib/shim")"
BB_OVMF_DIR="$(_bb_pick "${BB_OVMF_DIR:-}" OVMF_CODE_4M.secboot.fd /usr/share/OVMF "$_bb_t/usr/share/OVMF")"
BB_SEABIOS_DIR="$(_bb_pick "${BB_SEABIOS_DIR:-}" bios-256k.bin /usr/share/seabios "$_bb_t/usr/share/seabios")"
unset _bb_t
export BB_GRUB_EFI_DIR BB_GRUB_EFI_SIGNED_DIR BB_GRUB_BIOS_DIR BB_SHIM_DIR BB_DEBIAN_DIR BB_OVMF_DIR BB_SEABIOS_DIR
unset -f _bb_pick

# GRUB debug symbols for `bb-dev gdb` (kernel.exec + *.module, same build as
# the modules above). Our source build has them next to the modules, as does a
# system grub-pc-dbg / grub-efi-amd64-dbg (dpkg ties it to the same version); otherwise
# scripts/bootstrap-tools.sh unpacks version-matched copies into BB_GRUB_DBG_DIR.
: "${BB_GRUB_DBG_DIR:=$BB_ROOT/.tools/grub-dbg}"
if [ -z "${BB_GRUB_PC_DBG_DIR:-}" ]; then
  if [ -e "$BB_GRUB_BIOS_DIR/kernel.exec" ]; then BB_GRUB_PC_DBG_DIR="$BB_GRUB_BIOS_DIR"
  else BB_GRUB_PC_DBG_DIR="$BB_GRUB_DBG_DIR/usr/lib/grub/i386-pc"; fi
fi
if [ -z "${BB_GRUB_EFI_DBG_DIR:-}" ]; then
  if [ -e "$BB_GRUB_EFI_DIR/kernel.exec" ]; then BB_GRUB_EFI_DBG_DIR="$BB_GRUB_EFI_DIR"
  else BB_GRUB_EFI_DBG_DIR="$BB_GRUB_DBG_DIR/usr/lib/grub/x86_64-efi"; fi
fi
export BB_GRUB_DBG_DIR BB_GRUB_PC_DBG_DIR BB_GRUB_EFI_DBG_DIR
