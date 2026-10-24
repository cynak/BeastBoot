"""bb-dev gdb: attach gdb to GRUB running in QEMU, with GRUB's debug symbols.

  bb-dev vm --mode bios --gdb --wait-gdb      (terminal 1: VM paused at reset)
  bb-dev gdb --platform pc                    (terminal 2: stops in grub_main)
  (gdb) bb-break grub_cmd_linux
  (gdb) continue

  bb-dev vm --gdb                             (UEFI; wait for the menu)
  bb-dev gdb --platform efi                   (finds GRUB in memory)

Symbols come from grub-pc-dbg / grub-efi-amd64-dbg at exactly the version of
the module packages dist/ is built from (scripts/bootstrap-tools.sh fetches
and verifies them; this command re-checks the code matches before starting).
Module symbols load automatically as GRUB loads modules
(devtools/gdb/bbgrub.py). What works on BIOS vs UEFI, and why:
devtools/gdb/README.md.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from ..msg import Failure, note, rel, run_guarded, warn

CMD = "gdb"
GDB_DIR = paths.REPO / "devtools" / "gdb"
DEFAULT_PORT = 1234


@dataclass(frozen=True)
class Platform:
    name: str
    target: str          # GRUB platform directory name
    mod_var: str         # env var: module directory
    dbg_var: str         # env var: debug-symbol directory
    bin_pkg: str
    dbg_pkg: str
    init: str            # gdb init script in devtools/gdb/


PLATFORMS = {
    "pc": Platform("pc", "i386-pc", "BB_GRUB_BIOS_DIR", "BB_GRUB_PC_DBG_DIR", "grub-pc-bin", "grub-pc-dbg", "pc.gdb"),
    "efi": Platform("efi", "x86_64-efi", "BB_GRUB_EFI_DIR", "BB_GRUB_EFI_DBG_DIR", "grub-efi-amd64-bin",
                    "grub-efi-amd64-dbg", "efi.gdb"),
}
MODE_PLATFORM = {"bios": "pc", "uefi": "efi", "sb": "efi", "sb-enrolled": "efi", "sb-fresh": "efi"}


@dataclass
class VmInfo:
    """What the last `bb-dev vm` run on an image looked like (from its state dir)."""
    mode: str = ""
    port: int | None = None
    host: str = ""
    qemu: str = ""
    kvm: bool = False
    running: bool = False


def state_dir(image: Path) -> Path:
    return paths.VM_OUT / Path(image).stem


def _pid_alive(pidfile: Path) -> bool:
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def parse_qemu_cmd(text: str) -> VmInfo:
    try:
        argv = shlex.split(text)
    except ValueError:
        argv = text.split()
    info = VmInfo()
    if argv:
        info.qemu = os.path.basename(argv[0])
    for i, a in enumerate(argv[:-1]):
        nxt = argv[i + 1]
        if a == "-gdb":
            m = re.match(r"tcp:([^:]*):(\d+)$", nxt)
            if m:
                info.host, info.port = m.group(1) or "127.0.0.1", int(m.group(2))
        elif a == "-s":
            info.port = DEFAULT_PORT
        elif a == "-accel" and nxt.split(",")[0] == "kvm" or a == "-enable-kvm":
            info.kvm = True
    if argv and argv[-1] == "-s":
        info.port = DEFAULT_PORT
    return info


def detect_vm(image: Path) -> VmInfo | None:
    """The newest qemu-<mode>.cmd that `bb-dev vm` left for IMAGE."""
    d = state_dir(image)
    cmds = sorted(d.glob("qemu-*.cmd"), key=lambda p: p.stat().st_mtime, reverse=True) if d.is_dir() else []
    if not cmds:
        return None
    info = parse_qemu_cmd(cmds[0].read_text())
    info.mode = cmds[0].stem[len("qemu-"):]
    info.running = _pid_alive(d / "qemu.pid")
    return info


def _grubsyms():
    spec = importlib.util.spec_from_file_location("bb_grubsyms", GDB_DIR / "grubsyms.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_symbols(plat: Platform, env: dict) -> tuple[Path, Path]:
    """(debug dir, module dir), or Failure with the fix."""
    mod_dir = Path(env.get(plat.mod_var, ""))
    dbg_dir = Path(env.get(plat.dbg_var, ""))
    if not (mod_dir / "kernel.img").is_file():
        raise Failure(f"GRUB {plat.target} modules not found ({plat.mod_var}={mod_dir})",
                      f"run `make tools` (package {plat.bin_pkg})")
    if not (dbg_dir / "kernel.exec").is_file():
        raise Failure(f"GRUB {plat.target} debug symbols not found ({plat.dbg_var}={dbg_dir})",
                      f"run `make tools`: it fetches {plat.dbg_pkg} matching {plat.bin_pkg} into .tools/grub-dbg")
    problems, missing = _grubsyms().verify(dbg_dir, mod_dir)
    if problems:
        raise Failure(f"{dbg_dir} is not the same GRUB build as {mod_dir}: {problems[0]}",
                      "run `make tools` (it fetches the matching version or explains why it cannot)")
    if missing:
        warn(CMD, f"debug symbols incomplete: {missing[0]}")
    return dbg_dir, mod_dir


def gdb_string(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def session_text(plat: Platform, *, dbg_dir: Path, mod_dir: Path, target: str, state_file: Path,
                 breaks: list[str]) -> str:
    lines = [
        "# Written by `bb-dev gdb`; regenerated on every run.",
        f"set $BB_GDB_DBG_DIR = {gdb_string(dbg_dir)}",
        f"set $BB_GDB_MOD_DIR = {gdb_string(mod_dir)}",
        f"set $BB_GDB_TARGET = {gdb_string(target)}",
        f"set $BB_GDB_STATE = {gdb_string(state_file)}",
        f"source {GDB_DIR / 'bbgrub.py'}",
        f"source {GDB_DIR / plat.init}",
    ]
    lines += [f"bb-break {b}" for b in breaks]
    return "\n".join(lines) + "\n"


def gdb_argv(gdb: str, session: Path, *, batch: bool, ex: list[str], scripts: list[str]) -> list[str]:
    argv = [gdb, "-q", "-nx"]
    if batch:
        argv.append("-batch")
    argv += ["-x", str(session)]
    for e in ex:
        argv += ["-ex", e]
    for s in scripts:
        argv += ["-x", s]
    return argv


def register(sub) -> None:
    p = sub.add_parser(
        "gdb", help="attach gdb to GRUB running in QEMU (bb-dev vm --gdb)",
        description="Attach gdb to GRUB in a VM started with `bb-dev vm --gdb [--wait-gdb]`, with GRUB's "
                    "debug symbols; module symbols load as GRUB loads modules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="in gdb: bb-help lists the helper commands (bb-break, bb-modules, bb-efi-find, ...).\n"
               "BIOS vs UEFI details and limits: devtools/gdb/README.md")
    p.add_argument("--port", type=int, help=f"gdb stub port (default: the VM's, else {DEFAULT_PORT})")
    p.add_argument("--host", help="gdb stub host (default: the VM's, else 127.0.0.1)")
    p.add_argument("--platform", choices=tuple(PLATFORMS),
                   help="GRUB platform: pc (BIOS) or efi (default: from the last `bb-dev vm` on --image, else efi)")
    p.add_argument("--image", type=Path, default=paths.DEFAULT_IMAGE, metavar="PATH",
                   help=f"the VM's image; selects its state dir (default: {rel(paths.DEFAULT_IMAGE)})")
    p.add_argument("--break", dest="breaks", action="append", default=[], metavar="FUNC",
                   help="set a breakpoint after attaching (repeatable; hbreak where needed)")
    p.add_argument("--ex", action="append", default=[], metavar="CMD", help="run a gdb command after attaching (repeatable)")
    p.add_argument("-x", dest="scripts", action="append", default=[], metavar="FILE",
                   help="source a gdb script after attaching (repeatable)")
    p.add_argument("--batch", action="store_true", help="gdb -batch: run --ex/-x commands, then exit")
    p.add_argument("--print-cmd", action="store_true", help="print the gdb command line and exit")
    p.set_defaults(func=run)


def run(args) -> int:
    return run_guarded(CMD, _run, args)


def _run(args) -> int:
    env = paths.load_env()
    vm = detect_vm(args.image)
    platform = args.platform or (MODE_PLATFORM.get(vm.mode) if vm else None) or "efi"
    plat = PLATFORMS[platform]
    port = args.port or (vm.port if vm and vm.port else DEFAULT_PORT)
    host = args.host or (vm.host if vm and vm.host else "127.0.0.1")
    if not 1 <= port <= 65535:
        raise Failure(f"--port must be 1-65535, not {port}")
    gdb = shutil.which("gdb", path=env.get("PATH"))
    if not gdb:
        raise Failure("gdb not found", "sudo apt install gdb")
    dbg_dir, mod_dir = check_symbols(plat, env)

    if vm and not args.platform:
        note(CMD, f"platform {platform} (last `bb-dev vm` on {rel(args.image)} used --mode {vm.mode})")
    if vm and vm.running and vm.port is None:
        warn(CMD, "the VM for this image runs without a gdb stub: restart it with `bb-dev vm --gdb`")
    if platform == "pc" and vm and vm.mode == "bios" and vm.qemu.startswith("qemu-system-x86_64"):
        warn(CMD, "BIOS VM runs qemu-system-x86_64: its gdb stub sends 64-bit registers, so backtraces "
                  "through 32-bit GRUB are wrong (frame #0, args and breakpoints are fine). "
                  "devtools/gdb/README.md shows how to run it with qemu-system-i386.")
    if platform == "pc" and vm and vm.mode == "bios" and vm.kvm:
        note(CMD, "KVM: in BIOS GRUB prefer hardware breakpoints (bb-break / hbreak, at most 3 free); "
                  "stepping over a software `break` is unreliable under KVM")

    state = state_dir(args.image)
    state.mkdir(parents=True, exist_ok=True)
    session = state / f"gdb-{platform}.gdb"
    session.write_text(session_text(plat, dbg_dir=dbg_dir, mod_dir=mod_dir, target=f"{host}:{port}",
                                    state_file=state / "gdb-efi.json", breaks=args.breaks))
    argv = gdb_argv(gdb, session, batch=args.batch, ex=args.ex, scripts=args.scripts)
    if args.print_cmd:
        print(shlex.join(argv))
        return 0
    note(CMD, f"GRUB {plat.target}, stub {host}:{port}, symbols {rel(dbg_dir)} (bb-help in gdb)")
    os.execve(gdb, argv, env)
    return 0  # not reached
