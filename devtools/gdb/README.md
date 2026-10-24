# Debugging GRUB with gdb (`bb-dev gdb`)

Source-level gdb on the beast-booter GRUB running in QEMU: breakpoints in GRUB
functions (kernel and modules), backtraces, arguments and locals, on BIOS and
UEFI (with or without Secure Boot).

```sh
# BIOS: VM paused at reset, gdb stops in grub_main, then runs to your breakpoint
bin/bb-dev vm --mode bios --gdb --wait-gdb          # terminal 1
bin/bb-dev gdb --platform pc --break grub_cmd_linux # terminal 2
(gdb) continue

# UEFI: boot to the menu, then attach (works the same with --mode sb / sb-enrolled)
bin/bb-dev vm --gdb                                 # terminal 1, wait for the menu
bin/bb-dev gdb --platform efi                       # terminal 2: finds GRUB in memory
(gdb) bb-break grub_cmd_linux
(gdb) continue                                      # pick an ISO in the VM window
```

Without `--platform`, `bb-dev gdb` uses the mode of the last `bb-dev vm` run
on the image (`out/vm/<image>/qemu-<mode>.cmd`), and its gdb port. In gdb,
`bb-help` lists the helper commands. `bb-dev gdb --print-cmd` shows the gdb
command line; `--batch --ex CMD ... -x FILE` scripts a session.

A complete scripted demonstration (boots throwaway VMs, checks the transcript):

```sh
devtools/gdb/demo.py                    # BIOS: break in normal.mod, full backtrace
devtools/gdb/demo.py --platform efi     # UEFI: attach at the menu, then from reset
devtools/gdb/demo.py --bbdev-vm         # BIOS through `bb-dev vm` (see limits below)
BB_DEV_GDB_DEMO=1 pytest -q devtools/tests/test_gdb.py   # the same, as a test (~10 s with KVM)
```

## Where the symbols come from

| | BIOS (`pc`) | UEFI (`efi`) |
|---|---|---|
| shipped code | `grub-pc-bin` (`$BB_GRUB_BIOS_DIR`): `core.img` + `/grub/i386-pc/*.mod` | `grub-efi-amd64-bin` (`$BB_GRUB_EFI_DIR`): every module embedded in `grubx64.efi` |
| debug package | `grub-pc-dbg`, same version | `grub-efi-amd64-dbg`, same version |
| unpacked to | `$BB_GRUB_PC_DBG_DIR` | `$BB_GRUB_EFI_DBG_DIR` |

The `-dbg` packages ship, per platform directory, `kernel.exec` (the kernel
with DWARF), `NAME.module` for every `NAME.mod` (unstripped), the `*.image`
boot sectors (BIOS) and GRUB's own helpers `gdb_grub` and `gdb_helper.py`.

`scripts/bootstrap-tools.sh` (`make tools`) downloads them with
`apt-get download PKG=VERSION`, where VERSION is the version of the module
package the build uses (from dpkg, or from the `.deb` in `.tools/debs`), into
`.tools/debs-dbg/`, and unpacks them into `.tools/grub-dbg/` (not
`.tools/root/`, so build provenance never sees them). A system-wide
`grub-pc-dbg` / `grub-efi-amd64-dbg` (installed next to the modules, tied to
the same version by dpkg) is used instead when present. A matching version
string is not enough: `devtools/gdb/grubsyms.py verify` compares the code
(`kernel.exec` vs `kernel.img` `.text`/`.data`, every `.module` vs `.mod`
`.text`); bootstrap, `bb-dev doctor` and `bb-dev gdb` all refuse a mismatch.
If apt no longer has the matching version, bootstrap says so and exits 3
(everything else is still installed).

GRUB's sources are not fetched, so gdb cannot list source lines (`bt`, `info
args`, `info locals`, `p`, `ptype` all work). If you have the matching GRUB
source tree, `info source` shows the build's compilation directory
(e.g. `/build/grub2-XXXXXX/grub2-2.14/obj/grub-pc/grub-core`); map it with
`set substitute-path /build/grub2-XXXXXX/grub2-2.14 /path/to/grub2-2.14`.

## How module symbols are loaded

`bbgrub.py` (sourced by the session file that `bb-dev gdb` writes to
`out/vm/<image>/gdb-<platform>.gdb`, then `pc.gdb` / `efi.gdb`) puts an
internal breakpoint on `grub_dl_add`, which GRUB calls for every module it
loads (the ones embedded in `core.img` / `grubx64.efi` and the ones read from
`/grub/i386-pc/`). It reads the module's `grub_dl_segment` list (section
number and address of each loaded section), maps section numbers to names with
the stripped `.mod` (the numbers index the `.mod`, not the `.module`), and runs
`add-symbol-file NAME.module -s .text ADDR -s .data ADDR ...`. Pending
breakpoints in that module (`bb-break grub_cmd_linux` before `linux.mod` is
loaded) resolve at that moment. `bb-modules` lists what is loaded and
`bb-load-modules` catches up after attaching to a running GRUB.

This replaces GRUB's `gdb_grub`/`gdb_helper.py`, which need `objdump` and
`readelf`, a writable current directory with `.mod`, `.module` and
`kernel.exec` side by side, and drive module loading with breakpoint
`commands ... cont` blocks (these do not work under `gdb -batch`). For
x86_64-efi, `gdb_helper.py` also places `kernel.exec`'s `.bss` in ELF order,
but `grub-mkimage` puts NOBITS sections after all data sections (2.14:
`.bss` comes before `.rodata.str1.1` and `.module_license` in the ELF), so
`grub_dl_head` and every other `.bss` variable would be read from the wrong
address. `grubsyms.efi_kernel_layout()` follows `grub-mkimagexx.c`.

## BIOS (`--platform pc`)

`kernel.exec` is linked at its run-time address (`0x9000`), so its symbols
need no relocation. `lzma_decompress.img` unpacks the kernel at 1 MiB and
jumps there; `_start` then copies it to `0x9000` and continues at its link
address, so a breakpoint on `_start`/`0x9000` never hits. When the VM is
paused at reset (`--wait-gdb`), `bb-attach-pc` runs to `grub_main` with a
hardware breakpoint (it survives the code being written later) and stops
there. When GRUB is already running it just loads the symbols.

What works depends on how QEMU runs:

| VM | breakpoints | backtrace |
|---|---|---|
| `qemu-system-i386`, TCG | any number, `break` | full (module -> kernel) |
| `qemu-system-i386`, KVM | prefer hardware (`hbreak`/`bb-break`, 4, bb-grub uses 1); `break` usually works, stepping over it is unreliable | full |
| `qemu-system-x86_64` (what `bb-dev vm` runs today) | as above for TCG/KVM | frame #0 only |

- **64-bit register layout.** `qemu-system-x86_64`'s gdb stub always sends
  64-bit registers, even while the CPU runs 32-bit code, and gdb rejects an
  i386 target with it ("Remote 'g' packet reply is too long").
  `bb-connect` then switches gdb to `i386:x86-64`: breakpoints, frame #0,
  `info args` and memory work, but unwinding 32-bit frames with 64-bit
  register sizes fails after frame #0. `qemu-system-i386` (in the same
  `qemu-system-x86` package, `.tools/bin/qemu-system-i386`) reports i386
  registers and gives full backtraces; booting Linux ISOs needs x86_64 QEMU,
  GRUB itself does not.
- **KVM and software breakpoints.** With KVM, QEMU implements a software
  breakpoint by writing `int3` into guest memory and has to remove and
  re-insert it to step over it. In BIOS GRUB that is unreliable: in one
  session, after stepping over one, GRUB jumped into data and KVM stopped the
  VM ("KVM internal error ... emulation failure"). That was not reproducible
  later: a second check had `break grub_normal_execute`, `stepi`, `next` and
  `continue` all work under KVM on both QEMU binaries, except that `stepi`
  reported the same breakpoint again instead of advancing. So `break` often
  works, but stepping over a software breakpoint under KVM is not to be
  trusted. Hardware breakpoints are reliable under KVM, and under TCG (no
  memory patching) everything works. Under KVM, `bb-grub` uses a hardware
  breakpoint for its own `grub_dl_add` hook and `bb-break` /
  `bb-dev gdb --break` become `hbreak`; plain `break` is still yours to use.

So for BIOS debugging run QEMU as `qemu-system-i386 -accel tcg ... -s -S`
(that is what `devtools/gdb/demo.py` does; GRUB boots in under a second under
TCG), or use `bb-dev vm --mode bios --gdb --wait-gdb` with the limits above.

## UEFI (`--platform efi`)

The firmware decides where GRUB lands: shim allocates memory, loads
`grubx64.efi` with its own PE loader, relocates it and jumps to it. There is no
fixed address, and GRUB's `.text` must be found at run time:

1. `EFI_SYSTEM_TABLE_POINTER` (signature `IBI SYST`) sits on a 4 MiB boundary
   near the top of RAM (OVMF's DXE core puts it there for debuggers).
2. Its system table lists `EFI_DEBUG_IMAGE_INFO_TABLE`, which points to the
   `EFI_LOADED_IMAGE_PROTOCOL` of every image the firmware loaded.
3. shim rewrites its *own* loaded-image protocol to describe GRUB
   (`ImageBase`/`ImageSize`) before starting it, so while GRUB runs the entry
   of `\EFI\BOOT\BOOTX64.EFI` points at GRUB's PE image.
4. The PE header gives `.text`; its first 256 bytes are compared with
   `kernel.exec` (bytes patched by relocations masked out), so only this exact
   GRUB build is accepted. `kernel.exec` is loaded with the
   `grub-mkimage` section layout, then all modules (all embedded) and the
   `grub_dl_add` hook.

That makes **attaching to a running GRUB** (for example at the menu) fully
reliable. Software breakpoints work under KVM here. Secure Boot changes
nothing: verified with `bb-dev vm --mode sb-enrolled --gdb` (the stub is
outside the guest; nothing in the boot chain is modified).

**Attaching at reset** (`bb-dev vm --gdb --wait-gdb`): GRUB is not in memory
yet. `bb-attach-efi` sets a hardware breakpoint on the entry point seen in an
earlier session (cached in `out/vm/<image>/gdb-efi.json`) and, in parallel,
interrupts the VM every 0.2 s to look for GRUB (each poll prints a SIGINT
stop). With the same memory size, firmware and UEFI variables shim allocates
the same address, so from the second session on gdb stops on GRUB's first
instruction. On a first session, or after the variables changed (the first
boot of persistent `uefi`/`sb` vars adds boot entries; MokManager enrolment),
the poll finds GRUB a fraction of a second after it started: early kernel
init may already have run, `grub_normal_execute` and the menu have not. The
address is then cached for the next boot. `--mode sb-fresh` and `sb-enrolled`
rebuild their vars every run, so they are always deterministic.

Manual fallback: at a GRUB command line (if you can reach one; lockdown does
not remove it) type `gdbinfo`; it prints `dynamic_load_symbols 0x...`; in gdb
run `bb-load-kernel 0x...`.

## Limits

- gdb follows GRUB only. After GRUB hands off to a kernel (or chainloads),
  the symbols no longer describe the running code.
- No GRUB source listing out of the box (see above).
- QEMU only; the helpers rely on QEMU's gdb stub and OVMF's debug tables.
- BIOS under KVM: at most 3 user hardware breakpoints; software ones work
  but stepping over them is unreliable (see above).

## Files

| file | |
|---|---|
| `bbgrub.py` | gdb Python helpers: `bb-connect`, `bb-attach-pc`, `bb-attach-efi`, `bb-efi-find`, `bb-load-kernel`, `bb-break`, `bb-modules`, `bb-load-modules`, `bb-autoload`, `bb-quiet`, `bb-help` |
| `grubsyms.py` | gdb-free ELF/PE parsing, debug-symbol verification (`grubsyms.py verify DBG MOD [--all]`), EFI kernel layout |
| `pc.gdb`, `efi.gdb` | per-platform gdb init (sourced after the session settings) |
| `demo.py` | the scripted demonstration above |
