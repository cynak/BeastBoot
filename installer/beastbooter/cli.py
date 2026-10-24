"""Command line interface (ARCHITECTURE.md §7, interfaces.py "CLI additions")."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading

from . import __version__
from .commands import (
    STEP_ERROR_CODES,
    InstallOptions,
    format_devices,
    format_info,
    info,
    install_device,
    install_image,
    list_devices,
    update,
)
from . import firmware
from .distsource import ENV_DIST, resolve_dist
from .errors import BeastError, Cancelled
from .events import ProgressFile, find_progress_file
from .layout import DATA_LABEL_DEFAULT, DEFAULT_FS, DEFAULT_LAYOUT, FILESYSTEMS, LAYOUTS
from .util import Reporter


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that also reports usage errors to the progress file."""

    def __init__(self, *args, on_error=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_error = on_error

    def error(self, message: str):
        if self._on_error is not None:
            self._on_error(f"{self.prog}: {message}")
        super().error(message)


def build_parser(on_error=None) -> argparse.ArgumentParser:
    p = _Parser(
        prog="beast-booter",
        description="Create and update beast-booter multi-boot USB drives and images.",
        on_error=on_error,
    )
    p.add_argument("--version", action="version", version=f"beast-booter {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def target(sp, *, size: bool) -> None:
        g = sp.add_mutually_exclusive_group(required=True)
        g.add_argument("--device", metavar="DEV",
                       help="whole-disk device: /dev/sdX (Linux), /dev/diskN (macOS), "
                            "\\\\.\\PhysicalDriveN or N (Windows); see list-devices")
        g.add_argument("--image", metavar="PATH", help="disk image file")
        if size:
            sp.add_argument("--size", metavar="SIZE", help="image size: 256M, 8G or a byte count (with --image)")

    def common(sp) -> None:
        sp.add_argument("--dist", metavar="DIR|ZIP", default=None,
                        help=f"boot files: a dist/ directory or a .zip of one "
                             f"(default: ${ENV_DIST}, else <repo>/dist)")
        sp.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
        sp.add_argument("--allow-fixed-disk", action="store_true",
                        help="allow a non-removable disk as --device target")
        sp.add_argument("--quiet", "-q", action="store_true", help="no progress output")
        sp.add_argument("--progress-file", metavar="PATH",
                        help="append JSON-lines progress events to PATH (for the GUI)")
        sp.add_argument("--cancel-file", metavar="PATH",
                        help="stop cleanly once PATH exists, checked between steps and while writing "
                             "(error event 'cancelled', exit 130); SIGTERM and SIGINT do the same")

    sp = sub.add_parser("install", help="make a drive or image into a beast-booter drive (erases it)",
                        on_error=on_error)
    target(sp, size=True)
    sp.add_argument("--layout", choices=LAYOUTS, default=DEFAULT_LAYOUT, help="partition table (default: %(default)s)")
    sp.add_argument("--fs", choices=FILESYSTEMS, default=DEFAULT_FS, help="data filesystem (default: %(default)s)")
    sp.add_argument("--label", default=DATA_LABEL_DEFAULT, help="data partition label (default: %(default)s)")
    sp.add_argument("--serial-console", action="store_true", help="also show the menu on serial port 0")
    common(sp)

    sp = sub.add_parser("update", help="replace the boot files, keeping partition 1 untouched", on_error=on_error)
    target(sp, size=False)
    common(sp)

    sp = sub.add_parser("info", help="show the layout of a beast-booter drive or image", on_error=on_error)
    target(sp, size=False)
    sp.add_argument("--json", action="store_true", help="machine-readable output")

    sp = sub.add_parser("list-devices", help="list the drives beast-booter can write to", on_error=on_error)
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--all", action="store_true", help="also list fixed and system disks (not eligible)")
    sp.add_argument("--check-installed", action="store_true",
                    help="also show which beast-booter version each drive has (may mount its boot "
                         "partition read-only for a moment)")

    fw = sub.add_parser("firmware", help="optional firmware packs for beast-net (docs/BEASTNET.md section 6)",
                        on_error=on_error)
    fws = fw.add_subparsers(dest="fw_command", metavar="ACTION", required=True)

    def fw_dist(sp, what: str) -> None:
        sp.add_argument("--dist", metavar="DIR|ZIP", default=None,
                        help=f"boot files whose esp/beast-net/catalog.json {what} "
                             f"(default: ${ENV_DIST}, else <repo>/dist)")

    def fw_run(sp, *, cancel: bool = True) -> None:
        sp.add_argument("--quiet", "-q", action="store_true", help="no progress output")
        sp.add_argument("--progress-file", metavar="PATH",
                        help="append JSON-lines progress events to PATH (for the GUI)")
        if cancel:
            sp.add_argument("--cancel-file", metavar="PATH",
                            help="stop cleanly once PATH exists (error event 'cancelled', exit 130)")

    def fw_write(sp) -> None:
        sp.add_argument("--yes", "-y", action="store_true",
                        help="accepted for symmetry: firmware commands never ask (they erase nothing)")
        sp.add_argument("--allow-fixed-disk", action="store_true",
                        help="allow a non-removable disk as --device target")

    sp = fws.add_parser("catalog", help="show the firmware packs the catalog offers", on_error=on_error)
    fw_dist(sp, "to show")
    sp.add_argument("--catalog", metavar="FILE", help="a catalog.json file instead of the dist's")
    sp.add_argument("--json", action="store_true", help="the catalog as JSON, with each file's download URL")

    sp = fws.add_parser("fetch", help="download and verify packs into a folder (no admin rights needed)",
                        on_error=on_error)
    sp.add_argument("--pack", metavar="ID", action="append", required=True, help="pack id (repeatable)")
    sp.add_argument("--out", metavar="DIR", required=True, help="folder for <id>.cpio and <id>.json")
    sp.add_argument("--catalog", metavar="FILE", help="catalog.json (default: the one in the boot files)")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--for-image", metavar="PATH",
                   help="first check that the packs fit on this image's boot partition (error no-space, "
                        "nothing downloaded)")
    g.add_argument("--for-device", metavar="DEV",
                   help="the same for a drive; reading it needs administrator rights, without them the "
                        "check is skipped with a warning (firmware install still checks)")
    fw_dist(sp, "is used without --catalog")
    fw_run(sp)

    sp = fws.add_parser("install", help="write fetched packs to a beast-booter drive or image", on_error=on_error)
    target(sp, size=False)
    sp.add_argument("--from", dest="from_dir", metavar="DIR", required=True, help="the folder fetch wrote")
    fw_dist(sp, "is used when the drive has no catalog")
    fw_write(sp)
    fw_run(sp)

    sp = fws.add_parser("remove", help="remove an installed pack", on_error=on_error)
    target(sp, size=False)
    sp.add_argument("--pack", metavar="ID", required=True, help="pack id")
    fw_write(sp)
    fw_run(sp)

    sp = fws.add_parser("list", help="show the packs installed on a drive or image", on_error=on_error)
    target(sp, size=False)
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    fw_run(sp, cancel=False)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    events = None
    progress_path = find_progress_file(argv)
    if progress_path:
        try:
            events = ProgressFile(progress_path)
        except BeastError as e:
            print(f"beast-booter: error: {e}", file=sys.stderr)
            return 1
    try:
        def usage_error(message: str) -> None:
            if events is not None:
                events.emit("error", code="usage", message=message)

        parser = build_parser(on_error=usage_error)
        args = parser.parse_args(argv)
        rep = Reporter(getattr(args, "quiet", False), events=events,
                       cancel_file=getattr(args, "cancel_file", None))
        stoppable = args.command in ("install", "update") or (
            args.command == "firmware" and args.fw_command in ("fetch", "install", "remove"))
        with _StopSignals(stoppable) as stop:
            return _run(parser, args, rep, stop)
    finally:
        if events is not None:
            events.close()


class _StopSignals:
    """While installing/updating, SIGTERM (what the GUI sends to stop a run it
    started without elevation) and SIGINT (Ctrl+C) stop the run cleanly: the
    exception unwinds through every `with`, so targets are closed and a
    half-made image is removed, and the progress file gets a "cancelled" error
    event, exactly as for --cancel-file. `received` names the signal."""

    SIGNALS = ("SIGTERM", "SIGINT")

    def __init__(self, active: bool):
        self.active = active and threading.current_thread() is threading.main_thread()
        self.old: dict = {}
        self.received: str | None = None

    def _handler(self, signum, frame):
        self.received = signal.Signals(signum).name
        raise KeyboardInterrupt

    def __enter__(self):
        if self.active:
            for name in self.SIGNALS:
                sig = getattr(signal, name, None)
                if sig is None:
                    continue
                try:
                    self.old[sig] = signal.signal(sig, self._handler)
                except (ValueError, OSError):
                    pass
        return self

    def __exit__(self, *exc):
        for sig, old in self.old.items():
            signal.signal(sig, old)


def _run(parser: argparse.ArgumentParser, args: argparse.Namespace, rep: Reporter,
         stop: _StopSignals | None = None) -> int:
    def code_for(e: Exception) -> str:
        explicit = getattr(e, "code", None)
        if isinstance(explicit, str) and explicit:
            return explicit
        return STEP_ERROR_CODES.get(rep.current_step or "", "error")

    try:
        return _dispatch(parser, args, rep)
    except Cancelled as e:
        print(f"beast-booter: {e}", file=sys.stderr)
        rep.error("cancelled", str(e))
        return 130
    except BeastError as e:
        print(f"beast-booter: error: {e}", file=sys.stderr)
        rep.error(code_for(e), str(e))
        return 1
    except KeyboardInterrupt:
        sig = (stop.received if stop else None) or "SIGINT"
        print(f"beast-booter: interrupted ({sig})", file=sys.stderr)
        rep.error("cancelled", f"stopped by {sig}" + (f" during step {rep.current_step}" if rep.current_step else ""))
        return 130
    except OSError as e:
        where = f": {e.filename}" if e.filename else ""
        msg = f"{e.strerror or e}{where}"
        print(f"beast-booter: error: {msg}", file=sys.stderr)
        rep.error(STEP_ERROR_CODES.get(rep.current_step or "", "error"), msg)
        return 1
    except Exception as e:  # a bug: keep the traceback, but tell the GUI too
        rep.error("internal-error", f"internal error: {type(e).__name__}: {e}")
        raise


def _dispatch(parser: argparse.ArgumentParser, args: argparse.Namespace, rep: Reporter) -> int:
    if args.command == "install":
        opts = InstallOptions(
            layout=args.layout, fs=args.fs, label=args.label, dist_dir=resolve_dist(args.dist),
            serial=args.serial_console, yes=args.yes, allow_fixed=args.allow_fixed_disk,
        )
        if args.image:
            if not args.size:
                parser.error("install --image needs --size")
            d = install_image(args.image, args.size, opts, rep)
        else:
            if args.size:
                parser.error("--size is only valid with --image")
            d = install_device(args.device, opts, rep)
        rep.done(d)
        return 0
    if args.command == "update":
        d = update(args.image, args.device, resolve_dist(args.dist), yes=args.yes,
                   allow_fixed=args.allow_fixed_disk, rep=rep)
        rep.done(d)
        return 0
    if args.command == "info":
        d = info(args.image, args.device)
        if args.json:
            print(json.dumps(d))
        else:
            print(format_info(d, args.image or args.device))
        return 0
    if args.command == "list-devices":
        d = list_devices(args.all, args.check_installed)
        if args.json:
            print(json.dumps(d, default=str))
        else:
            print(format_devices(d, args.all))
        return 0
    if args.command == "firmware":
        return _firmware(args, rep)
    parser.error(f"unknown command {args.command}")
    return 2


def _firmware(args: argparse.Namespace, rep: Reporter) -> int:
    c = args.fw_command
    if c == "catalog":
        cat = firmware.load_catalog(args.catalog) if args.catalog else firmware.dist_catalog(resolve_dist(args.dist))
        print(json.dumps(firmware.catalog_json(cat)) if args.json else firmware.format_catalog(cat))
        return 0
    if c == "fetch":
        rep.start("firmware-fetch", args.out)
        cat = firmware.load_catalog(args.catalog) if args.catalog else firmware.dist_catalog(resolve_dist(args.dist))
        rep.done(firmware.fetch(args.pack, args.out, cat, rep, for_image=args.for_image,
                                for_device=args.for_device))
        return 0
    if c == "install":
        dist = resolve_dist(args.dist)
        rep.done(firmware.install(args.image, args.device, args.from_dir, dist,
                                  allow_fixed=args.allow_fixed_disk, rep=rep))
        return 0
    if c == "remove":
        rep.done(firmware.remove(args.image, args.device, args.pack, allow_fixed=args.allow_fixed_disk, rep=rep))
        return 0
    if c == "list":
        d = firmware.list_installed(args.image, args.device, rep)
        print(json.dumps(d) if args.json else firmware.format_installed(d))
        rep.done({"installed": d})
        return 0
    raise BeastError(f"unknown firmware command {c}")
