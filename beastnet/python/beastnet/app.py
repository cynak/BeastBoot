"""Command line entry point: ``python3 -m beastnet``."""

from __future__ import annotations

import argparse
import os
import sys
import traceback

from . import __version__
from .cmdline import read_cmdline
from .context import Context, Quit
from .download import Downloader, mount_fs_type
from .errors import INTERNAL, MOUNT, BeastNetError
from .events import Reporter
from .firmware import installed_packs, load_catalog
from .flow import Interactive
from .net import LinuxNetwork, NetworkService
from .paths import DEFAULT_CA_FILE, Paths
from .script import run_script
from .system import Runner, System
from .ui import UIClosed

EPILOG = """\
Inside beast-net this is started by /init with no options; everything comes
from the kernel command line (beastnet.data=, beastnet.esp=, beastnet.sb=,
beastnet.debug=1, beastnet.script=,
beastnet.action=trust-ubuntu). The options below exist for testing on a
developer machine. Outside beast-net (no /etc/beast-net-release) it never
touches the network configuration and never reboots: --dry-run and --no-net
are implied unless --live is given.

Example (host dry run of script mode):
  python3 -m beastnet --root /tmp/bn --script /plan.json --ca-file my-ca.pem
"""


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m beastnet",
        description="beast-net: download an ISO onto the beast-boot stick and boot it once.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", default="/", metavar="DIR",
                   help="look for proc/, sys/, dev/, etc/, run/, mnt/data and mnt/esp under DIR")
    p.add_argument("--cmdline", metavar="FILE", help="kernel command line (default ROOT/proc/cmdline)")
    p.add_argument("--sys", metavar="DIR", help="sysfs (default ROOT/sys)")
    p.add_argument("--data", metavar="DIR", help="data partition mount point (default ROOT/mnt/data)")
    p.add_argument("--esp", metavar="DIR", help="ESP mount point (default ROOT/mnt/esp)")
    p.add_argument("--run", metavar="DIR", help="scratch directory (default ROOT/run/beastnet)")
    p.add_argument("--ca-file", metavar="FILE", default=DEFAULT_CA_FILE,
                   help=f"trusted CA certificates (default {DEFAULT_CA_FILE})")
    p.add_argument("--kernel-log", metavar="FILE", help="read the kernel log from FILE instead of /dev/kmsg")
    p.add_argument("--script", metavar="PATH",
                   help="run this JSON plan, a path on the data partition (like beastnet.script=)")
    p.add_argument("--debug", action="store_true", help="print BEASTNET: lines (like beastnet.debug=1)")
    p.add_argument("--plain", action="store_true", help="line-based interface instead of curses")
    p.add_argument("--no-net", action="store_true",
                   help="do not configure the network; use it as it is")
    p.add_argument("--dry-run", action="store_true", help="never unmount, reboot or power off")
    p.add_argument("--live", action="store_true",
                   help="act on this system even outside beast-net (configure network, reboot)")
    p.add_argument("--version", action="version", version=f"beast-net {__version__}")
    return p.parse_args(argv)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def serial_port(paths: Paths, name: str | None) -> str | None:
    """/dev/ttyS0 (or the console= one) if a UART is really there."""
    name = name or "ttyS0"
    port_type = _read(os.path.join(paths.sys, "class", "tty", name, "type"))
    if port_type in ("", "0"):
        return None
    dev = os.path.join(paths.dev, name)
    return dev if os.path.exists(dev) else None


def _same_tty(stream, path: str) -> bool:
    try:
        return os.fstat(stream.fileno()).st_rdev == os.stat(path).st_rdev
    except (OSError, ValueError, AttributeError):
        return False


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = Paths(root=args.root, cmdline=args.cmdline or "", sys=args.sys or "",
                  data=args.data or "", esp=args.esp or "", run=args.run or "",
                  ca_file=args.ca_file, kernel_log=args.kernel_log)
    params = read_cmdline(paths.cmdline)
    live = paths.is_beast_net() or args.live
    dry_run = args.dry_run or not live
    no_net = args.no_net or not live
    if not live:
        print("beast-net: not inside beast-net: dry run, the network is used as it is.",
              file=sys.stderr)
    debug = args.debug or params.debug
    script = args.script or params.script
    serial = serial_port(paths, params.serial_console) if debug else None
    log_path = os.path.join(paths.run, "events.log")

    ui = None
    if script:
        reporter = Reporter(stream=sys.stdout, serial=serial, log_path=log_path)
    else:
        if not args.plain and params.ui != "plain":
            from .ui.tui import open_tui
            ui = open_tui("Secure Boot: on" if params.sb else "")
        # With curses on the console, the lines only go to the serial port and the log
        # (and not even to the serial port when curses is drawing on it).
        stream = sys.stdout if (debug and ui is None) else None
        if ui is not None and serial and _same_tty(sys.stdout, serial):
            serial = None
        reporter = Reporter(stream=stream, serial=serial, log_path=log_path)

    try:
        return _run(args, paths, params, reporter, ui, script, live, dry_run, no_net)
    finally:
        if ui is not None:
            ui.close()


def _run(args, paths: Paths, params, reporter: Reporter, ui, script, live: bool, dry_run: bool,
         no_net: bool) -> int:
    kernel = _read(os.path.join(paths.proc, "sys", "kernel", "osrelease")) or os.uname().release
    reporter.ready(kernel, params.sb, installed_packs(paths.installed))
    runner = Runner(log_path=os.path.join(paths.run, "commands.log"))
    notes: list[str] = []
    system = System(paths, runner, dry_run=dry_run, say=notes.append)
    catalog = load_catalog(paths.catalog)
    net = None if no_net else NetworkService(LinuxNetwork(paths, runner, catalog), reporter)

    def downloader() -> Downloader:
        return Downloader(paths.data, paths.ca_file, reporter=reporter,
                          fs_type=mount_fs_type(paths.proc))

    ctx = Context(paths, params, reporter, system, net, catalog, downloader, kernel, dry_run, notes)
    try:
        if live and not args.data:
            for what, mnt in (("data partition", paths.data), ("ESP", paths.esp)):
                if not os.path.ismount(mnt):
                    raise BeastNetError(MOUNT, f"the {what} is not mounted at {mnt}")
        result = None
        if script:
            outcome, result = run_script(ctx, script)
            if outcome == "done":
                return 0
            if outcome == "shell":
                return 1
        if ui is None:
            from .ui.plain import LineUI
            ui_obj = LineUI()
        else:
            ui_obj = ui
        # beastnet.action= (a tool entry of the boot menu) opens that action first;
        # after a script, "stay" goes on with the normal screens.
        Interactive(ctx, ui_obj).run(result, action=None if script else params.action)
        return 0
    except Quit:
        return 0
    except (UIClosed, EOFError):
        return 0
    except BeastNetError as e:
        reporter.error(e.code, e.text)
        _late_print(ui, f"beast-net: {e.text}")
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 - report it, then let init offer a shell
        reporter.error(INTERNAL, f"{e.__class__.__name__}: {e}")
        if ui is not None:
            ui.close()
        traceback.print_exc()
        return 70
    finally:
        for note in notes:
            _late_print(ui, note)


def _late_print(ui, text: str) -> None:
    if ui is not None:
        ui.close()
    print(text, file=sys.stderr, flush=True)
