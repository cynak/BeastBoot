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
BB_GRUB_EFI_DIR="$(_bb_pick "${BB_GRUB_EFI_DIR:-}" kernel.img /usr/lib/grub/x86_64-efi "$_bb_t/usr/lib/grub/x86_64-efi")"
BB_GRUB_EFI_SIGNED_DIR="$(_bb_pick "${BB_GRUB_EFI_SIGNED_DIR:-}" grubx64.efi.signed /usr/lib/grub/x86_64-efi-signed "$_bb_t/usr/lib/grub/x86_64-efi-signed")"
BB_GRUB_BIOS_DIR="$(_bb_pick "${BB_GRUB_BIOS_DIR:-}" boot.img /usr/lib/grub/i386-pc "$_bb_t/usr/lib/grub/i386-pc")"
BB_SHIM_DIR="$(_bb_pick "${BB_SHIM_DIR:-}" mmx64.efi /usr/lib/shim "$_bb_t/usr/lib/shim")"
BB_OVMF_DIR="$(_bb_pick "${BB_OVMF_DIR:-}" OVMF_CODE_4M.secboot.fd /usr/share/OVMF "$_bb_t/usr/share/OVMF")"
BB_SEABIOS_DIR="$(_bb_pick "${BB_SEABIOS_DIR:-}" bios-256k.bin /usr/share/seabios "$_bb_t/usr/share/seabios")"
unset _bb_t
export BB_GRUB_EFI_DIR BB_GRUB_EFI_SIGNED_DIR BB_GRUB_BIOS_DIR BB_SHIM_DIR BB_OVMF_DIR BB_SEABIOS_DIR
unset -f _bb_pick

# GRUB debug symbols for `bb-dev gdb` (kernel.exec + *.module, same build as
# the modules above). A system grub-pc-dbg / grub-efi-amd64-dbg installs them
# next to the modules (dpkg ties it to the same version); otherwise
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
