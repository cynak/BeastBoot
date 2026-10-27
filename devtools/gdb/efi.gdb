# gdb init for beast-boot's UEFI GRUB (x86_64-efi). Normally loaded by
#   bin/bb-dev gdb --platform efi
# which first sets $BB_GDB_DBG_DIR, $BB_GDB_MOD_DIR, $BB_GDB_TARGET and
# $BB_GDB_STATE and sources bbgrub.py. See devtools/gdb/README.md.
set confirm off
set pagination off
set breakpoint pending on
set print frame-arguments scalars
# No `file`: GRUB's load address is only known once it runs; bb-attach-efi
# finds it and loads kernel.exec there.
bb-connect
bb-attach-efi
