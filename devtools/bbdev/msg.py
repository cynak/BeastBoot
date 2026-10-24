"""Uniform terminal output for bb-dev commands.

Results go to stdout; progress, notes and warnings go to stderr, so
`bb-dev vm --print-cmd` and `bb-dev debug-config --print` stay pipeable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import paths


class Failure(Exception):
    """A user-facing error: printed as `bb-dev <cmd>: error: <msg>`, exit 1."""

    def __init__(self, msg: str, hint: str = ""):
        super().__init__(msg)
        self.hint = hint


def _color(code: str, text: str, stream) -> str:
    if os.environ.get("NO_COLOR") or not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{code}m{text}\033[0m"


def note(cmd: str, text: str) -> None:
    print(f"bb-dev {cmd}: {text}", file=sys.stderr, flush=True)


def warn(cmd: str, text: str) -> None:
    print(f"bb-dev {cmd}: " + _color("33", "warning: ", sys.stderr) + text, file=sys.stderr, flush=True)


def error(cmd: str, text: str, hint: str = "") -> None:
    print(f"bb-dev {cmd}: " + _color("31", "error: ", sys.stderr) + text, file=sys.stderr, flush=True)
    if hint:
        print(f"  hint: {hint}", file=sys.stderr, flush=True)


def kv(key: str, value: str, width: int = 8, stream=None) -> None:
    """One aligned `key  value` line of a summary block."""
    print(f"  {key:<{width}} {value}", file=stream or sys.stderr, flush=True)


def rel(p: Path | str) -> str:
    """A path relative to the repo when it is inside it (shorter output)."""
    p = Path(p)
    try:
        return str(p.resolve().relative_to(paths.REPO))
    except (ValueError, OSError):
        return str(p)


def confirm(question: str) -> bool:
    """Ask y/N on the terminal; False when stdin is not interactive."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(question + " [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def run_guarded(cmd: str, fn, args) -> int:
    """Run fn(args), turning Failure into a one-line error and exit code 1."""
    try:
        return int(fn(args) or 0)
    except Failure as e:
        error(cmd, str(e), e.hint)
        return 1
