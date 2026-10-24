"""Follow the JSON-lines progress file that the CLI writes (`--progress-file`).

The CLI runs in another process (often elevated), so the GUI cannot share
memory with it. It appends one JSON object per line to a file instead; this
module reads whatever has been appended since the last call, keeps a partial
last line for the next call, and turns each complete line into a
ProgressEvent. ProgressState folds the events into what the window shows.

Event schema (interfaces.py, "v": 1):
    {"v":1,"event":"start","action":"install"|"update","target":"..."}
    {"v":1,"event":"step","step":"<id>","message":"<text>","pct":<0-100>}
    {"v":1,"event":"warning","message":"..."}
    {"v":1,"event":"done","ok":true,"info":{...}}
    {"v":1,"event":"error","code":"<id>","message":"<text>"}

Anything else (unknown events, newer schema versions, garbage) is kept in the
log but never changes the outcome: only the process exit code, an "error"
event and a "done" event do that (see controller.py).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from ..interfaces import PROGRESS_SCHEMA_VERSION, PROGRESS_STEPS

KNOWN_EVENTS = ("start", "step", "warning", "done", "error")
# A line longer than this is not progress output; drop it instead of buffering forever.
MAX_LINE_BYTES = 1 << 20
READ_CHUNK = 1 << 16

# What each step does, for when the CLI sends a step without a message.
STEP_TITLES = {
    "verify-dist": "Checking the boot files",
    "check-target": "Checking the drive",
    "prepare": "Unmounting the drive",
    "partition": "Writing the partition table",
    "format-data": "Creating the storage partition",
    "write-esp": "Writing the boot partition",
    "boot-code": "Writing the BIOS boot code",
    "flush": "Flushing data to the drive",
    "rescan": "Letting the system re-read the drive",
    "verify-write": "Checking what was written",
    # firmware commands (docs/BEASTNET.md section 6)
    "download": "Downloading the firmware files",
    "verify-packs": "Checking the firmware packs",
    "write-firmware": "Writing the firmware packs",
}
assert set(STEP_TITLES) == set(PROGRESS_STEPS)

# Steps that change the target. Used to tell the user what state a failed or
# cancelled target is in. "prepare" only unmounts.
WRITING_STEPS = ("partition", "format-data", "write-esp", "boot-code", "flush", "rescan", "verify-write")


@dataclass(frozen=True)
class ProgressEvent:
    kind: str  # one of KNOWN_EVENTS, or "unknown" / "invalid"
    data: dict
    raw: str  # the line as received (for the log)
    note: str = ""  # why it was "unknown" / "invalid"


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def parse_line(line: bytes | str) -> ProgressEvent:
    """Parse one line of the progress file. Never raises."""
    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="replace")
    else:
        text = line
    text = text.strip()
    try:
        obj = json.loads(text)
    except ValueError as e:
        return ProgressEvent("invalid", {}, text, f"not JSON ({e.msg})")
    if not isinstance(obj, dict):
        return ProgressEvent("invalid", {}, text, "not a JSON object")
    kind = obj.get("event")
    if not isinstance(kind, str):
        return ProgressEvent("invalid", obj, text, 'no "event" field')
    if kind not in KNOWN_EVENTS:
        return ProgressEvent("unknown", obj, text, f"unknown event {kind!r}")
    data = dict(obj)
    if kind == "step":
        step = data.get("step")
        data["step"] = step if isinstance(step, str) else ""
        msg = data.get("message")
        data["message"] = msg if isinstance(msg, str) and msg else STEP_TITLES.get(data["step"], data["step"])
        pct = data.get("pct")
        data["pct"] = min(100.0, max(0.0, float(pct))) if _is_number(pct) else None
    elif kind in ("warning", "error"):
        msg = data.get("message")
        data["message"] = msg if isinstance(msg, str) and msg else "(no message)"
        if kind == "error":
            code = data.get("code")
            data["code"] = code if isinstance(code, str) and code else "error"
    elif kind == "done":
        data["ok"] = data.get("ok") is True
        info = data.get("info")
        data["info"] = info if isinstance(info, dict) else None
    note = ""
    v = obj.get("v")
    if v != PROGRESS_SCHEMA_VERSION:
        note = f"progress schema version {v!r}, this GUI knows {PROGRESS_SCHEMA_VERSION}"
    return ProgressEvent(kind, data, text, note)


class ProgressReader:
    """Read new complete lines from a file another process appends to.

    The file may not exist yet (the elevated process has not started), may
    end in the middle of a line (the writer is mid-write), or may end in the
    middle of a UTF-8 sequence. Lines are split on b"\\n" before decoding, so
    none of these produce garbage.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = os.fspath(path)
        self._offset = 0
        self._partial = b""
        self._skipping = False  # inside an over-long line

    def read_new(self) -> list[ProgressEvent]:
        try:
            with open(self.path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if size < self._offset:  # truncated or replaced: start over
                    self._offset, self._partial, self._skipping = 0, b"", False
                f.seek(self._offset)
                chunks = []
                while chunk := f.read(READ_CHUNK):
                    chunks.append(chunk)
        except FileNotFoundError:
            return []
        data = b"".join(chunks)
        self._offset += len(data)
        return self._feed(data)

    def finish(self) -> list[ProgressEvent]:
        """Read what is left after the writer exited, including an unterminated last line."""
        events = self.read_new()
        rest, self._partial = self._partial, b""
        if rest.strip() and not self._skipping:
            events.append(parse_line(rest))
        return events

    def _feed(self, data: bytes) -> list[ProgressEvent]:
        events = []
        buf = self._partial + data
        *lines, self._partial = buf.split(b"\n")
        for line in lines:
            if self._skipping:  # the tail of an over-long line
                self._skipping = False
                continue
            if line.strip():
                events.append(parse_line(line))
        if len(self._partial) > MAX_LINE_BYTES:
            events.append(ProgressEvent("invalid", {}, "", f"line longer than {MAX_LINE_BYTES} bytes dropped"))
            self._partial, self._skipping = b"", True
        return events


@dataclass
class LogLine:
    level: str  # "info" | "warning" | "error" | "debug"
    text: str


@dataclass
class ProgressState:
    """Everything the progress page shows, built from events."""

    started: bool = False
    action: str = ""
    target: str = ""
    step: str = ""
    message: str = ""
    pct: float = 0.0
    steps_seen: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    log: list[LogLine] = field(default_factory=list)
    done_seen: bool = False  # a "done" event arrived
    done_ok: bool = False  # ... and it said "ok": true
    done_info: dict | None = None
    error_code: str | None = None
    error_message: str | None = None
    _version_noted: bool = False

    @property
    def wrote_to_target(self) -> bool:
        return any(s in WRITING_STEPS for s in self.steps_seen)

    def note(self, text: str, level: str = "info") -> None:
        self.log.append(LogLine(level, text))

    def apply(self, ev: ProgressEvent) -> None:
        if ev.note and ev.kind in KNOWN_EVENTS and not self._version_noted:
            self._version_noted = True
            self.note(f"note: {ev.note}", "debug")
        d = ev.data
        if ev.kind == "start":
            self.started = True
            self.action = str(d.get("action") or "")
            self.target = str(d.get("target") or "")
            self.note(f"started {self.action} on {self.target}".strip())
        elif ev.kind == "step":
            self.started = True
            self.step, self.message = d["step"], d["message"]
            if d["step"] and d["step"] not in self.steps_seen:
                self.steps_seen.append(d["step"])
            if d["pct"] is not None:
                self.pct = max(self.pct, d["pct"])  # never move the bar backwards
            self.note(self.message)
        elif ev.kind == "warning":
            self.warnings.append(d["message"])
            self.note(f"warning: {d['message']}", "warning")
        elif ev.kind == "done":
            self.done_seen, self.done_ok, self.done_info = True, d["ok"], d["info"]
            if self.done_ok:
                self.pct = 100.0
            self.note("finished" if self.done_ok else "finished, but the installer reported it is not ok")
        elif ev.kind == "error":
            self.error_code, self.error_message = d["code"], d["message"]
            self.note(f"error [{d['code']}]: {d['message']}", "error")
        else:  # unknown / invalid: keep it visible, change nothing
            self.note(f"ignored progress line ({ev.note}): {ev.raw[:200]}", "debug")
