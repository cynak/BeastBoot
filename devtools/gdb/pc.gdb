# gdb init for beast-booter's BIOS GRUB (i386-pc). Normally loaded by
#   bin/bb-dev gdb --platform pc
# which first sets $BB_GDB_DBG_DIR, $BB_GDB_MOD_DIR and $BB_GDB_TARGET and
# sources bbgrub.py. See devtools/gdb/README.md.
set confirm off
set pagination off
set breakpoint pending on
set print frame-arguments scalars
# kernel.exec is linked at its run-time address (0x9000): symbols need no relocation.
eval "file %s/kernel.exec", $BB_GDB_DBG_DIR
bb-connect
bb-attach-pc
