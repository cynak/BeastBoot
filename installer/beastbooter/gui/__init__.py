"""beast-booter desktop GUI (Tkinter/ttk; Tk ships with the portable Python runtime).

    python beast_booter_launch.py --gui [--dist DIR] [--demo] [--scale FACTOR] [--theme dark|light]
    python beast_booter_launch.py --gui --selftest

Modules:
    controller.py  all decisions (drive eligibility, options, CLI command line,
                   progress, state machine); no tkinter, unit-tested
    progress.py    follows the CLI's JSON-lines --progress-file
    distinfo.py    finds the boot files, shows their manifest, re-verifies them
    localproc.py   runs the CLI without elevation (image files)
    firmware.py    firmware packs for the network helper: catalog, fetch/install runs; no tkinter
    app.py         the window; displays the controllers' state, nothing more
    fwpage.py      the window's "Firmware packs" section
    theme.py       dark / light ttk theme; images generated in code (raster.py, no tkinter)
    widgets.py     reusable window pieces
    demo.py        simulated drives for --demo (nothing is written)
    fake_cli.py    stand-in CLI used by --demo and the tests

This file must not import tkinter: the controller tests run on Pythons without it.
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="beast-booter --gui",
        description="Make a beast-booter multi-boot USB drive (graphical).",
    )
    p.add_argument("--dist", metavar="DIR",
                   help="boot files directory (default: $BEAST_BOOTER_DIST, the portable "
                        "package's payload/dist, or <repo>/dist)")
    p.add_argument("--demo", action="store_true",
                   help="simulated drives and installer; nothing is written anywhere")
    p.add_argument("--scale", type=float, metavar="FACTOR",
                   help="override the display scaling, e.g. 1.5 for 150%% (default: from the system)")
    p.add_argument("--theme", choices=("dark", "light"), default="dark",
                   help="colours: dark (default) or light")
    p.add_argument("--selftest", action="store_true",
                   help="build the window, draw it once and exit 0 (for CI); touches no drive")
    return p


def main(argv: list[str] | None = None) -> int:
    # Modules imported from here on (tkinter, the window, the platform backend)
    # must not leave .pyc files in the portable package, whatever flags the
    # launcher used (docs/PORTABLE.md: the folder stays exactly as unpacked).
    sys.dont_write_bytecode = True
    args = build_parser().parse_args(argv)
    if args.scale is not None and not 0.5 <= args.scale <= 4.0:
        print("beast-booter: error: --scale must be between 0.5 and 4", file=sys.stderr)
        return 2
    try:
        import tkinter  # noqa: F401
    except ImportError as e:
        print(
            "beast-booter: error: the graphical interface needs Tkinter, which this Python "
            f"does not have ({e}).\n  Use the portable beast-booter package (its Python includes Tk), "
            "install your distribution's python3-tk package, or use the command line: "
            "beast-booter --help",
            file=sys.stderr,
        )
        return 1
    from .app import run

    return run(args)
