"""Small helpers: running tools, parsing sizes, progress output, sparse file copies."""

from __future__ import annotations

import errno
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence

from .errors import BeastError, Cancelled
from .layout import MIB

# Which package provides a tool, for "not found" messages (Debian/Ubuntu names).
# The installer itself only runs mkfs.ntfs (NTFS on Linux) and, through the
# Linux backend, umount / partx / udevadm; FAT, exFAT and the partition tables
# are written in pure Python.
TOOL_PACKAGES = {
    "blockdev": "util-linux",
    "partx": "util-linux",
    "umount": "util-linux",
    "mkfs.ntfs": "ntfs-3g",
}

COPY_CHUNK = 4 * MIB


def tool_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for external tools: stable C locale, plus extras."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    if extra:
        env.update(extra)
    return env


def run(
    cmd: Sequence[str],
    *,
    input: str | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    what: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a tool, capturing output. Raises BeastError on failure (if check)."""
    cmd = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            cmd,
            input=input,
            stdin=subprocess.DEVNULL if input is None else None,
            capture_output=True,
            text=True,
            errors="replace",
            env=tool_env(env),
        )
    except FileNotFoundError:
        pkg = TOOL_PACKAGES.get(os.path.basename(cmd[0]))
        hint = f" (install the {pkg} package)" if pkg else ""
        raise BeastError(f"required tool '{cmd[0]}' was not found{hint}") from None
    if check and proc.returncode != 0:
        lines = [line for line in (proc.stderr + "\n" + proc.stdout).splitlines() if line.strip()]
        detail = "; ".join(lines[-4:]) if lines else "no output"
        label = what or os.path.basename(cmd[0])
        raise BeastError(f"{label} failed (exit {proc.returncode}): {detail}")
    return proc


_SIZE_RE = re.compile(r"^\s*(\d+)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)
_SIZE_MULT = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}


def parse_size(text: str) -> int:
    """Parse '256M', '8G', '1T', '512K' (binary units) or a plain byte count."""
    m = _SIZE_RE.match(text)
    if not m:
        raise BeastError(
            f"invalid size {text!r}: use a byte count or a number with K, M, G or T (e.g. 8G)"
        )
    value = int(m.group(1)) * _SIZE_MULT[m.group(2).lower()]
    if value <= 0:
        raise BeastError(f"invalid size {text!r}: must be greater than zero")
    return value


def human_size(n: int) -> str:
    for unit, div in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


class Reporter:
    """Progress for people (short lines on stderr; stdout stays clean for --json)
    and, with --progress-file, for the GUI (events.ProgressFile).

    step(msg, step_id, pct) starts a step: it prints "==> msg", sends a "step"
    event and first checks the --cancel-file. progress() sends a step event
    only (intermediate percentages). The step that is running is kept in
    `current_step`, so an error can be given a code (commands.STEP_ERROR_CODES).
    """

    def __init__(self, quiet: bool = False, stream=None, *, events=None, cancel_file: str | None = None):
        self.quiet = quiet
        self.stream = stream
        self.events = events
        self.cancel_file = cancel_file
        self.current_step: str | None = None

    def _print(self, line: str) -> None:
        print(line, file=self.stream or sys.stderr, flush=True)

    def _emit(self, event: str, **fields) -> None:
        if self.events is not None:
            self.events.emit(event, **fields)

    def check_cancel(self, *, within: bool = False) -> None:
        """Raise Cancelled if the --cancel-file exists (before a step, or `within` one)."""
        if self.cancel_file and os.path.exists(self.cancel_file):
            where = f" {'during' if within else 'before'} step {self.current_step}" if self.current_step else ""
            raise Cancelled(f"stopped on request{where}")

    def start(self, action: str, target: str) -> None:
        self._emit("start", action=action, target=target)

    def step(self, msg: str, step: str | None = None, pct: float | None = None) -> None:
        if step is not None:
            self.check_cancel()
            self.current_step = step
            self._emit("step", step=step, message=msg, pct=_pct(pct))
        if not self.quiet:
            self._print(f"==> {msg}")

    def progress(self, step: str, msg: str, pct: float | None) -> None:
        """A step event without a line on stderr (e.g. "12 of 40 MiB written")."""
        self._emit("step", step=step, message=msg, pct=_pct(pct))

    def note(self, msg: str) -> None:
        if not self.quiet:
            self._print(f"    {msg}")

    def warn(self, msg: str) -> None:
        # Warnings are shown even with --quiet.
        self._print(f"beast-boot: warning: {msg}")
        self._emit("warning", message=msg)

    def done(self, info: dict) -> None:
        self._emit("done", ok=True, info=info)

    def error(self, code: str, msg: str) -> None:
        self._emit("error", code=code, message=msg)


def _pct(pct: float | None):
    if pct is None:
        return None
    pct = min(100.0, max(0.0, float(pct)))
    return int(pct) if pct == int(pct) else round(pct, 1)


def data_ranges(fd: int, size: int) -> list[tuple[int, int]]:
    """Data extents of a (sparse) file as [(start, end), ...] using SEEK_DATA/SEEK_HOLE."""
    if not hasattr(os, "SEEK_DATA"):
        return [(0, size)] if size else []
    ranges: list[tuple[int, int]] = []
    pos = 0
    try:
        while pos < size:
            try:
                start = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError as e:
                if e.errno == errno.ENXIO:  # no more data
                    break
                raise
            end = os.lseek(fd, start, os.SEEK_HOLE)
            end = min(end, size)
            if end > start:
                ranges.append((start, end))
            pos = end
    except OSError as e:
        if e.errno in (errno.EINVAL, errno.EOPNOTSUPP):
            return [(0, size)] if size else []
        raise
    return ranges


def copy_file_to_target(src_path: str, t, offset: int, *, skip_holes: bool) -> int:
    """Copy a whole file into the BlockTarget `t` at `offset`. Returns bytes written.

    skip_holes=True is only correct when the destination range is known to be
    zero (a freshly created sparse image): holes are then left untouched.
    """
    written = 0
    with open(src_path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if offset < 0 or offset + size > t.size:
            raise BeastError(f"{src_path} ({size} bytes) does not fit at byte {offset} of the target")
        ranges = data_ranges(f.fileno(), size) if skip_holes else ([(0, size)] if size else [])
        for start, end in ranges:
            f.seek(start)
            pos = start
            while pos < end:
                buf = f.read(min(COPY_CHUNK, end - pos))
                if not buf:
                    raise OSError(errno.EIO, f"unexpected end of file: {src_path}")
                t.write(offset + pos, buf)
                pos += len(buf)
                written += len(buf)
    return written


def confirm(prompt: str) -> str:
    """Ask the user for a line of input. Raises BeastError if there is no terminal."""
    if not sys.stdin or not sys.stdin.isatty():
        raise BeastError("confirmation needed but stdin is not a terminal; pass --yes to skip it")
    try:
        return input(prompt)
    except EOFError:
        raise BeastError("aborted (no confirmation)", code="aborted") from None
