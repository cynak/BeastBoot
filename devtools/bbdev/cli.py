"""bb-dev: development and debugging helpers for beast-booter.

Each subcommand lives in bbdev/commands/<name>.py and exposes:

    def register(sub) -> None   # add its parser to `sub` (argparse subparsers),
                                # with parser.set_defaults(func=run)
    def run(args) -> int        # exit code

A command module that is missing or fails to import is skipped with a warning,
so one broken helper never blocks the others.
"""

from __future__ import annotations

import argparse
import importlib
import sys

from . import __version__

# Order here is the order shown in --help.
COMMANDS = (
    "setup",         # one-shot dev environment setup
    "doctor",        # diagnose the environment
    "image",         # build a dev drive image
    "vm",            # boot an image in QEMU (BIOS / UEFI / Secure Boot)
    "menu_sync",     # push edited grub/ files into an image's ESP
    "debug_config",  # toggle menu debug settings on an image
    "gdb",           # attach gdb to GRUB running in QEMU
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bb-dev",
        description="Development and debugging helpers for beast-booter.",
    )
    parser.add_argument("--version", action="version", version=f"bb-dev {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name in COMMANDS:
        try:
            module = importlib.import_module(f".commands.{name}", __package__)
        except ImportError as exc:
            print(f"bb-dev: warning: command '{name}' unavailable: {exc}", file=sys.stderr)
            continue
        module.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
