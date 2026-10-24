"""The JSON-lines progress file the GUI follows (`install/update --progress-file PATH`,
and the `firmware` commands).

One JSON object per line, "v": 1 in each (schema in interfaces.py). The
firmware commands add the actions firmware-fetch / firmware-install /
firmware-remove / firmware-list and the steps in FIRMWARE_STEPS. Every line
is written with a single write() and flushed at once, so a reader that polls
the file never waits for buffered output; gui/progress.py copes with a line
that is still being written.

The file is appended to, never truncated: the GUI creates it (as the user,
before starting the CLI elevated) and may already be reading it.

Writing progress is best effort: if the file cannot be written any more (disk
full, removed), the install carries on and reports on stderr as always.
"""

from __future__ import annotations

import json

from .errors import BeastError
from .interfaces import PROGRESS_SCHEMA_VERSION, PROGRESS_STEPS

EVENTS = ("start", "step", "warning", "done", "error")
# Steps of the firmware commands, besides interfaces.PROGRESS_STEPS
# (check-target, prepare, flush, rescan, verify-write):
#   download        fetch: downloading the pack files and checking each one's
#                   SHA-256 and size (pct follows the bytes)
#   verify-packs    install: re-parsing each cpio, re-checking every file
#                   against the catalog
#   write-firmware  fetch: writing DIR/<id>.cpio + DIR/<id>.json;
#                   install/remove: writing beast-net/firmware/ on the ESP
FIRMWARE_STEPS = ("download", "verify-packs", "write-firmware")
STEPS = PROGRESS_STEPS + FIRMWARE_STEPS


class ProgressFile:
    def __init__(self, path: str):
        self.path = path
        try:
            self._f = open(path, "a", encoding="utf-8")
        except OSError as e:
            raise BeastError(f"cannot open the progress file {path}: {e.strerror or e}") from None
        self.broken = False

    def emit(self, event: str, **fields) -> None:
        if event not in EVENTS:
            raise ValueError(f"unknown progress event {event!r}")
        if event == "step" and fields.get("step") not in STEPS:
            raise ValueError(f"unknown progress step {fields.get('step')!r}")
        if self.broken or self._f is None:
            return
        line = json.dumps({"v": PROGRESS_SCHEMA_VERSION, "event": event, **fields}, default=str)
        try:
            self._f.write(line + "\n")
            self._f.flush()
        except (OSError, ValueError):
            self.broken = True

    def close(self) -> None:
        if self._f is not None:
            try:
                self._f.close()
            except OSError:
                pass
            self._f = None


def find_progress_file(argv: list[str]) -> str | None:
    """The --progress-file value in a raw command line, found without argparse,
    so that even a usage error (which argparse reports by exiting) can be sent
    to the GUI. Accepts "--progress-file PATH", "--progress-file=PATH" and the
    abbreviations argparse accepts ("--progress PATH")."""
    name = "--progress-file"
    found = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            break
        opt, eq, value = arg.partition("=")
        if len(opt) > 3 and name.startswith(opt):
            if eq:
                found = value
            elif i + 1 < len(argv):
                found = argv[i + 1]
                i += 1
        i += 1
    return found or None
