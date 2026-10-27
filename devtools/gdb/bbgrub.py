"""gdb helpers for debugging beast-boot's GRUB under QEMU (`bb-dev gdb`).

Sourced by the session file `bb-dev gdb` writes, before pc.gdb / efi.gdb.
A Python-only replacement for GRUB's own gdb_grub + gdb_helper.py from
grub-*-dbg: those need objdump/readelf and a writable current directory with
*.mod, *.module and kernel.exec side by side, drive module loading with
breakpoint `commands ... cont` (which does not work under `gdb -batch`), and
on x86_64-efi place kernel.exec's .bss at the wrong address.

Settings (gdb convenience variables, set by the session file):
  $BB_GDB_DBG_DIR  kernel.exec + *.module (grub-pc-dbg / grub-efi-amd64-dbg,
                   the same build as the shipped modules)
  $BB_GDB_MOD_DIR  the stripped *.mod files (grub-pc-bin / grub-efi-amd64-bin):
                   GRUB's in-memory section numbers index the .mod, not the .module
  $BB_GDB_TARGET   gdb stub, e.g. 127.0.0.1:1234
  $BB_GDB_STATE    JSON file caching where GRUB EFI was loaded (per image)

Commands: run `bb-help`.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from struct import error as struct_error

import gdb  # type: ignore  # provided by gdb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grubsyms

PC_KERNEL_ADDR = 0x9000            # GRUB_KERNEL_I386_PC_LINK_ADDR
# i386-pc: lzma_decompress.img unpacks the kernel at 1 MiB and jumps there;
# _start copies it to 0x9000 and continues at its link address. So the first
# kernel code that runs at its linked address is grub_main, not _start.
PC_FIRST_FUNCTION = "grub_main"
# How much of the kernel's .text identifies it. i386-pc's startup.S stores
# three pointers into its own code (offset 0x41 on) once it runs, so only the
# first 64 bytes are constant; on EFI relocated bytes are masked out.
SIGNATURE_LEN = {"pc": 64, "efi": 256}

HELP = """\
bb-grub commands (devtools/gdb/bbgrub.py):
  bb-connect [HOST:PORT]  connect to QEMU's gdb stub; detects KVM and a 64-bit
                          register layout (qemu-system-x86_64) on BIOS
  bb-attach-pc            BIOS GRUB: kernel.exec symbols (fixed at 0x9000); if GRUB
                          is not in memory yet, run to grub_main first
  bb-attach-efi           UEFI GRUB: find it in memory (bb-efi-find); at reset, run
                          to the entry point cached from an earlier session
  bb-efi-find             UEFI: locate GRUB through the firmware's
                          EFI_DEBUG_IMAGE_INFO_TABLE and load its symbols
  bb-load-kernel ADDR     UEFI: GRUB's .text is at ADDR (GRUB's `gdbinfo` command
                          prints `dynamic_load_symbols ADDR`)
  bb-break LOCATION       the reliable kind of breakpoint here (hbreak on BIOS under KVM)
  bb-modules              modules GRUB has loaded, and whether symbols are loaded
  bb-load-modules         load symbols for every module loaded so far
  bb-autoload on|off      load a module's symbols when GRUB loads it (default on)
  bb-quiet on|off         silence these helpers"""


def _setting(name: str) -> str:
    v = gdb.convenience_variable(name)
    if v is not None:
        try:
            return v.string()
        except gdb.error:
            pass
    return os.environ.get(name, "")


class State:
    def __init__(self):
        self.loaded: dict[str, int] = {}     # module name -> .text address
        self.kernel_loaded_at: int | None = None
        self.autoload_bp = None
        self.verbose = True
        self.platform = ""
        self.kvm: bool | None = None
        self.wide_regs = False               # i386 code seen through a 64-bit stub
        self._sig = None
        self._sig_for = None

    @property
    def dbg_dir(self) -> str:
        return _setting("BB_GDB_DBG_DIR")

    @property
    def mod_dir(self) -> str:
        return _setting("BB_GDB_MOD_DIR") or self.dbg_dir

    @property
    def kernel_exec(self) -> str:
        return os.path.join(self.dbg_dir, "kernel.exec")

    @property
    def hw_only(self) -> bool:
        """BIOS GRUB under KVM: prefer hardware breakpoints. QEMU writes int3
        into guest memory for software ones, and stepping over them is
        unreliable (seen once to derail GRUB: KVM "emulation failure"; at
        other times `stepi` re-reports the same breakpoint)."""
        return self.platform == "pc" and bool(self.kvm)


STATE = State()


def say(msg: str) -> None:
    if STATE.verbose:
        gdb.write(f"bb-grub: {msg}\n")
        gdb.flush()


def read_mem(addr: int, size: int) -> bytes:
    return bytes(gdb.selected_inferior().read_memory(addr, size))


def u64(addr: int) -> int:
    return int.from_bytes(read_mem(addr, 8), "little")


def u32(addr: int) -> int:
    return int.from_bytes(read_mem(addr, 4), "little")


def kernel_signature() -> tuple[bytes, bytes]:
    key = (STATE.kernel_exec, STATE.platform)
    if STATE._sig_for != key:
        STATE._sig = grubsyms.text_signature(STATE.kernel_exec, SIGNATURE_LEN.get(STATE.platform, 64))
        STATE._sig_for = key
    return STATE._sig


def code_matches(addr: int) -> bool:
    """Is this GRUB's kernel code (the build kernel.exec describes) at ADDR?"""
    sig = kernel_signature()
    try:
        return grubsyms.matches_signature(read_mem(addr, len(sig[0])), sig)
    except gdb.MemoryError:
        return False


# ---------------------------------------------------------------------------
# Connecting
# ---------------------------------------------------------------------------

class BbConnect(gdb.Command):
    """bb-connect [HOST:PORT]: connect to QEMU's gdb stub (default $BB_GDB_TARGET)."""

    def __init__(self):
        super().__init__("bb-connect", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        target = arg.strip() or _setting("BB_GDB_TARGET") or "127.0.0.1:1234"
        try:
            gdb.execute(f"target remote {target}")
        except gdb.error as exc:
            if "too long" not in str(exc):
                raise gdb.GdbError(f"cannot connect to {target}: {exc}\n"
                                   "Is the VM running with a gdb stub (`bb-dev vm --gdb`)?")
            # i386 symbols, but qemu-system-x86_64 always sends 64-bit registers.
            gdb.execute("set architecture i386:x86-64")
            gdb.execute(f"target remote {target}")
            STATE.wide_regs = True
        try:
            STATE.kvm = "enabled" in gdb.execute("monitor info kvm", to_string=True)
        except gdb.error:
            STATE.kvm = None
        say(f"connected to {target} ({'KVM' if STATE.kvm else 'TCG' if STATE.kvm is False else 'accelerator unknown'})")


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------

def module_segments(mod) -> list[tuple[int, int]]:
    out = []
    seg = mod["segment"]
    n = 0
    while int(seg) != 0 and n < 64:
        out.append((int(seg["section"]), int(seg["addr"])))
        seg = seg["next"]
        n += 1
    return out


def module_symbol_cmd(name: str, segments) -> tuple[str, int] | None:
    module_path = os.path.join(STATE.dbg_dir, f"{name}.module")
    mod_path = os.path.join(STATE.mod_dir, f"{name}.mod")
    if not os.path.exists(module_path):
        say(f"no debug file for module {name}: {module_path}")
        return None
    if not os.path.exists(mod_path):
        say(f"no {mod_path}: cannot map the sections of {name}")
        return None
    names = grubsyms.section_names(mod_path)
    text = None
    extra = []
    for idx, addr in segments:
        sec = names.get(idx)
        if not sec:
            continue
        if sec == ".text":
            text = addr
        else:
            extra.append(f"-s {sec} {addr:#x}")
    if text is None:
        return None
    return " ".join([f"add-symbol-file {module_path} -s .text {text:#x}"] + extra), text


def load_module(mod) -> bool:
    name = mod["name"].string()
    r = module_symbol_cmd(name, module_segments(mod))
    if r is None:
        return False
    cmd, text = r
    if STATE.loaded.get(name) == text:
        return False
    if name in STATE.loaded:   # GRUB restarted and loaded it elsewhere
        try:
            gdb.execute(f"remove-symbol-file -a {STATE.loaded[name]:#x}", to_string=True)
        except gdb.error:
            pass
    gdb.execute(cmd, to_string=True)
    STATE.loaded[name] = text
    say(f"symbols for {name}.mod at {text:#x}")
    return True


def iter_modules():
    try:
        mod = gdb.parse_and_eval("grub_dl_head")
    except gdb.error as exc:
        raise gdb.GdbError(f"grub_dl_head is not readable (kernel.exec symbols not loaded?): {exc}")
    n = 0
    while int(mod) != 0 and n < 4096:
        yield mod
        mod = mod["next"]
        n += 1


def load_all_modules() -> int:
    n = 0
    for mod in iter_modules():
        try:
            n += int(load_module(mod))
        except (gdb.error, gdb.MemoryError) as exc:
            say(f"skipping a module: {exc}")
    return n


class DlAddBreakpoint(gdb.Breakpoint):
    """Internal breakpoint on grub_dl_add: load the module's symbols, never stop."""

    def __init__(self, hardware: bool):
        kw = {"internal": True}
        if hardware:
            kw["type"] = gdb.BP_HARDWARE_BREAKPOINT
        super().__init__("grub_dl_add", **kw)
        self.silent = True

    def stop(self):
        try:
            load_module(gdb.parse_and_eval("mod"))
        except Exception as exc:  # a helper failure must never stop the session  # noqa: BLE001
            gdb.write(f"bb-grub: could not load module symbols: {exc}\n")
        return False


def autoload(enable: bool) -> None:
    if enable and STATE.autoload_bp is None:
        STATE.autoload_bp = DlAddBreakpoint(hardware=STATE.hw_only)
    elif not enable and STATE.autoload_bp is not None:
        STATE.autoload_bp.delete()
        STATE.autoload_bp = None


def run_to(addr: int, what: str) -> bool:
    """Continue to ADDR with a temporary hardware breakpoint (it survives the
    code being written to memory after it was set). True if we stopped there."""
    bp = gdb.Breakpoint(f"*{addr:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=True, temporary=True)
    bp.silent = True
    say(f"running to {what} at {addr:#x} (hardware breakpoint; Ctrl-C to stop waiting)")
    try:
        gdb.execute("continue")
    finally:
        if bp.is_valid():
            bp.delete()
    try:
        return int(gdb.parse_and_eval("$pc")) == addr
    except gdb.error:
        return False


# ---------------------------------------------------------------------------
# BIOS (i386-pc)
# ---------------------------------------------------------------------------

class BbAttachPc(gdb.Command):
    """Set up symbols for BIOS GRUB (after `file kernel.exec` and bb-connect)."""

    def __init__(self):
        super().__init__("bb-attach-pc", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        STATE.platform = "pc"
        STATE.kernel_loaded_at = PC_KERNEL_ADDR
        if STATE.wide_regs:
            say("warning: this stub reports 64-bit registers (qemu-system-x86_64): breakpoints, "
                "`info args` and frame #0 work, but backtraces through 32-bit GRUB code do not. "
                "Run the VM with qemu-system-i386 for full backtraces (devtools/gdb/README.md).")
        if STATE.hw_only:
            say("KVM: in BIOS GRUB prefer hardware breakpoints (4 in total, bb-grub uses 1): `hbreak` "
                "or bb-break. Stepping over a software `break` is unreliable under KVM; run the VM "
                "without KVM for any number of reliable breakpoints")
        if not code_matches(PC_KERNEL_ADDR):
            say("GRUB is not in memory yet (VM paused at reset?)")
            addr = int(gdb.parse_and_eval(f"&{PC_FIRST_FUNCTION}"))
            run_to(addr, PC_FIRST_FUNCTION)
            if not code_matches(PC_KERNEL_ADDR):
                raise gdb.GdbError("the code at 0x9000 is not the GRUB build these debug symbols are for "
                                   "(image built from another dist/? run `make build` and rebuild the image)")
            say(f"stopped in {PC_FIRST_FUNCTION}")
        n = load_all_modules()
        autoload(True)
        say(f"GRUB i386-pc: kernel.exec + {n} module(s) with symbols, module autoload on")


# ---------------------------------------------------------------------------
# UEFI (x86_64-efi)
# ---------------------------------------------------------------------------

EFI_SYSTEM_TABLE_SIGNATURE = 0x5453595320494249     # "IBI SYST"
# EFI_DEBUG_IMAGE_INFO_TABLE_GUID 49152E77-1ADA-4764-B7A2-7AFEFED95E8B (mixed-endian bytes)
DEBUG_IMAGE_INFO_GUID = bytes.fromhex("772e1549da1a6447b7a27afefed95e8b")


def efi_system_table() -> int | None:
    """EFI_SYSTEM_TABLE, via the EFI_SYSTEM_TABLE_POINTER that the DXE core
    places on a 4 MiB boundary, as high as possible below 4 GiB."""
    step = 4 * 1024 * 1024
    for addr in range(0x100000000 - step, 0, -step):
        try:
            if u64(addr) == EFI_SYSTEM_TABLE_SIGNATURE:
                return u64(addr + 8)
        except gdb.MemoryError:
            continue
    return None


def efi_loaded_images() -> list[tuple[int, int]]:
    """[(ImageBase, ImageSize)] of every image in EFI_DEBUG_IMAGE_INFO_TABLE.

    shim loads GRUB with its own PE loader and then points its *own*
    EFI_LOADED_IMAGE_PROTOCOL at GRUB (ImageBase/ImageSize), so GRUB shows up
    here as the entry of \\EFI\\BOOT\\BOOTX64.EFI while it runs."""
    st = efi_system_table()
    if not st:
        return []
    n_cfg = u64(st + 0x68)       # EFI_SYSTEM_TABLE.NumberOfTableEntries
    cfg = u64(st + 0x70)         # EFI_SYSTEM_TABLE.ConfigurationTable
    table = None
    for i in range(min(n_cfg, 256)):
        ent = cfg + i * 24       # EFI_CONFIGURATION_TABLE {GUID, VOID *}
        if read_mem(ent, 16) == DEBUG_IMAGE_INFO_GUID:
            table = u64(ent + 16)
            break
    if not table:
        return []
    count = u32(table + 4)       # EFI_DEBUG_IMAGE_INFO_TABLE_HEADER.TableSize
    entries = u64(table + 8)
    out = []
    for i in range(min(count, 4096)):
        p = u64(entries + i * 8)
        if not p or u32(p) != 1:  # EFI_DEBUG_IMAGE_INFO_TYPE_NORMAL
            continue
        li = u64(p + 8)          # LoadedImageProtocolInstance
        out.append((u64(li + 0x40), u64(li + 0x48)))   # ImageBase, ImageSize
    return out


def efi_grub_text_candidates() -> list[int]:
    out = []
    for base, _size in efi_loaded_images():
        try:
            _info, secs = grubsyms.parse_pe_sections(read_mem(base, 4096))
        except (ValueError, gdb.MemoryError, IndexError, struct_error):
            continue
        text = next((s for s in secs if s["name"] == ".text"), None)
        if text and code_matches(base + text["rva"]):
            out.append(base + text["rva"])
    return out


def efi_load_kernel(text_addr: int) -> None:
    if STATE.kernel_loaded_at == text_addr:
        return
    if STATE.kernel_loaded_at is not None:
        try:
            gdb.execute(f"remove-symbol-file -a {STATE.kernel_loaded_at:#x}", to_string=True)
        except gdb.error:
            pass
        STATE.loaded.clear()
    gdb.execute(grubsyms.efi_add_symbol_file_cmd(STATE.kernel_exec, text_addr), to_string=True)
    STATE.kernel_loaded_at = text_addr
    say(f"kernel.exec symbols at .text={text_addr:#x}")
    try:
        head = gdb.parse_and_eval("grub_dl_head")
        if int(head) != 0:
            raw = read_mem(int(head["name"]), 64).split(b"\0", 1)[0]
            if not (raw and raw.isascii() and raw.decode().isprintable()):
                say("warning: grub_dl_head does not look valid with these symbols")
    except (gdb.error, gdb.MemoryError):
        say("warning: cannot read grub_dl_head with these symbols")


def save_state(text_addr: int) -> None:
    path = _setting("BB_GDB_STATE")
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            # PE entry point == start of .text for GRUB (AddressOfEntryPoint == .text RVA)
            json.dump({"text": text_addr, "entry": text_addr}, f)
    except OSError:
        pass


def load_state() -> dict:
    try:
        with open(_setting("BB_GDB_STATE")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def efi_find() -> int | None:
    cands = efi_grub_text_candidates()
    if not cands:
        return None
    text = cands[-1]
    efi_load_kernel(text)
    save_state(text)
    return text


def _efi_ready(text: int, how: str) -> None:
    n = load_all_modules()
    autoload(True)
    say(f"GRUB x86_64-efi {how}: .text at {text:#x}, kernel.exec + {n} module(s) with symbols, "
        "module autoload on")


class BbEfiFind(gdb.Command):
    """Find GRUB in UEFI memory and load kernel.exec + module symbols."""

    def __init__(self):
        super().__init__("bb-efi-find", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        STATE.platform = "efi"
        text = efi_find()
        if text is None:
            raise gdb.GdbError("GRUB is not in the firmware's loaded-image list (not started yet?). "
                               "`continue` until the menu shows, press Ctrl-C, then bb-efi-find again; "
                               "or type `gdbinfo` at the GRUB command line and run bb-load-kernel ADDRESS.")
        _efi_ready(text, "found")


class BbLoadKernel(gdb.Command):
    """bb-load-kernel ADDR: load kernel.exec for a GRUB EFI whose .text is at ADDR."""

    def __init__(self):
        super().__init__("bb-load-kernel", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not arg.strip():
            raise gdb.GdbError("usage: bb-load-kernel ADDRESS  (GRUB's `gdbinfo` prints: dynamic_load_symbols ADDRESS)")
        STATE.platform = "efi"
        addr = int(gdb.parse_and_eval(arg.split()[-1]))
        if not code_matches(addr):
            say(f"warning: the code at {addr:#x} does not look like this GRUB build's kernel")
        efi_load_kernel(addr)
        save_state(addr)
        _efi_ready(addr, "at the given address")


def _interrupt_soon(interval: float) -> threading.Timer:
    def fire():
        def ev():
            try:
                gdb.execute("interrupt", to_string=True)
            except gdb.error:
                pass   # already stopped
        gdb.post_event(ev)
    t = threading.Timer(interval, fire)
    t.daemon = True
    t.start()
    return t


def efi_wait_for_grub(cached: int | None, interval: float = 0.2, limit: float = 300.0) -> tuple[int | None, bool]:
    """From reset (or anywhere before GRUB), run until GRUB is in memory.

    A hardware breakpoint sits on the entry point cached from an earlier
    session (shim's allocation is the same as long as memory size, firmware
    and vars do not change), and every INTERVAL seconds the VM is interrupted
    to look for GRUB in the firmware's image table. Returns (.text, at_entry).
    """
    bp = None
    if cached:
        bp = gdb.Breakpoint(f"*{cached:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
        bp.silent = True
    say("running until GRUB starts" + (f" (hardware breakpoint at the cached entry {cached:#x})" if cached else "")
        + f"; polling every {interval}s (each poll prints a SIGINT stop); Ctrl-C to stop waiting")
    deadline = time.monotonic() + limit
    try:
        while time.monotonic() < deadline:
            timer = _interrupt_soon(interval)
            try:
                gdb.execute("continue", to_string=True)
            finally:
                timer.cancel()
            try:
                pc = int(gdb.parse_and_eval("$pc"))
            except gdb.error:
                return None, False   # target gone
            if cached and pc == cached and code_matches(cached):
                return cached, True
            text = efi_grub_text_candidates()
            if text:
                return text[-1], False
    finally:
        if bp is not None and bp.is_valid():
            bp.delete()
    return None, False


class BbAttachEfi(gdb.Command):
    """Set up symbols for UEFI GRUB (after bb-connect)."""

    def __init__(self):
        super().__init__("bb-attach-efi", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        STATE.platform = "efi"
        text = efi_find()
        if text is not None:
            _efi_ready(text, "is running")
            return
        say("GRUB has not started yet")
        cached = load_state().get("entry")
        text, at_entry = efi_wait_for_grub(int(cached) if cached else None)
        if text is None:
            say("GRUB did not start. `continue` until the menu shows, press Ctrl-C, then run bb-efi-find.")
            return
        efi_load_kernel(text)
        save_state(text)
        if at_entry:
            _efi_ready(text, "stopped at its entry point")
        else:
            _efi_ready(text, "found while starting (its first instructions may have run already; "
                       "the load address is cached, so the next boot with the same VM settings stops at the entry)")


# ---------------------------------------------------------------------------
# Misc commands
# ---------------------------------------------------------------------------

class BbBreak(gdb.Command):
    """bb-break LOCATION: `break`, or `hbreak` where software breakpoints are unreliable."""

    def __init__(self):
        super().__init__("bb-break", gdb.COMMAND_BREAKPOINTS)

    def invoke(self, arg, from_tty):
        if not arg.strip():
            raise gdb.GdbError("usage: bb-break LOCATION")
        gdb.execute(("hbreak " if STATE.hw_only else "break ") + arg)


class BbModules(gdb.Command):
    """List modules GRUB has loaded (name, .text address, symbols loaded?)."""

    def __init__(self):
        super().__init__("bb-modules", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        for mod in iter_modules():
            name = mod["name"].string()
            text = None
            mod_path = os.path.join(STATE.mod_dir, f"{name}.mod")
            if os.path.exists(mod_path):
                names = grubsyms.section_names(mod_path)
                for idx, addr in module_segments(mod):
                    if names.get(idx) == ".text":
                        text = addr
            where = f"{text:#x}" if text is not None else "?"
            gdb.write(f"  {name:<20} {where:<12} {'symbols' if name in STATE.loaded else '-'}\n")


class BbLoadModules(gdb.Command):
    """Load debug symbols for every module GRUB has loaded so far."""

    def __init__(self):
        super().__init__("bb-load-modules", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        n = load_all_modules()
        say(f"{n} module(s) newly loaded, {len(STATE.loaded)} in total")


class BbAutoload(gdb.Command):
    """bb-autoload on|off: load module symbols whenever GRUB loads a module."""

    def __init__(self):
        super().__init__("bb-autoload", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = (arg or "on").strip()
        if arg not in ("on", "off"):
            raise gdb.GdbError("usage: bb-autoload on|off")
        autoload(arg == "on")
        say(f"module symbol autoload {arg}")


class BbQuiet(gdb.Command):
    """bb-quiet on|off: silence the helpers' progress messages."""

    def __init__(self):
        super().__init__("bb-quiet", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        STATE.verbose = (arg or "on").strip() == "off"


class BbHelp(gdb.Command):
    """List the bb-grub commands."""

    def __init__(self):
        super().__init__("bb-help", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.write(HELP + "\n")


for _cmd in (BbConnect, BbAttachPc, BbAttachEfi, BbEfiFind, BbLoadKernel, BbBreak, BbModules,
             BbLoadModules, BbAutoload, BbQuiet, BbHelp):
    _cmd()
