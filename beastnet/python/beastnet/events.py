"""The machine-readable ``BEASTNET:`` lines of BEASTNET.md section 5.

One Reporter per run. Lines go to the chosen stream (normally stdout = the
console) and, when debugging, also to the serial port if one is present and it
is not already that stream. Every line is also appended to a log file so a
user can look at it from the shell. Writes never block and never raise:
reporting must not be able to break a download.
"""

from __future__ import annotations

import os
import threading
import time
from typing import IO

PREFIX = "BEASTNET: "


def _clean(value: object) -> str:
    text = str(value)
    # One event per line, whatever the value contains.
    return " ".join(text.replace("\r", " ").replace("\n", " ").split()) if text else text


class Reporter:
    def __init__(
        self,
        *,
        stream: IO[str] | None = None,
        serial: str | None = None,
        log_path: str | None = None,
    ) -> None:
        self.stream = stream  # None: do not print on the console (TUI owns it)
        self.serial = serial  # e.g. "/dev/ttyS0"; written only if distinct from stream
        self.log_path = log_path
        self.lines: list[str] = []  # everything emitted, for tests and the UI
        self._lock = threading.Lock()
        self._last_pct: int | None = None
        self._last_pct_time = 0.0

    # -- plumbing ---------------------------------------------------------
    def _serial_is_stream(self) -> bool:
        if not self.serial or self.stream is None:
            return False
        try:
            a = os.fstat(self.stream.fileno())
            b = os.stat(self.serial)
        except (OSError, ValueError, AttributeError):
            return False
        return a.st_rdev == b.st_rdev and a.st_rdev != 0

    def _write_serial(self, line: str) -> None:
        if not self.serial or self._serial_is_stream():
            return
        try:
            fd = os.open(self.serial, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError:
            return
        try:
            os.write(fd, (line + "\r\n").encode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            os.close(fd)

    def emit(self, *words: object) -> str:
        line = PREFIX + " ".join(_clean(w) for w in words if w is not None and str(w) != "")
        with self._lock:
            self.lines.append(line)
            if self.stream is not None:
                try:
                    self.stream.write(line + "\n")
                    self.stream.flush()
                except (OSError, ValueError):
                    pass
            self._write_serial(line)
            if self.log_path:
                try:
                    os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(time.strftime("%H:%M:%S ") + line + "\n")
                except OSError:
                    pass
        return line

    # -- the events -------------------------------------------------------
    def ready(self, kernel: str, sb: bool, firmware: list[str]) -> None:
        self.emit("ready", f"kernel={kernel}", f"sb={1 if sb else 0}",
                  f"firmware={','.join(firmware) if firmware else 'none'}")

    def nic(self, iface: str, type_: str, driver: str, state: str) -> None:
        self.emit("nic", iface, f"type={type_}", f"driver={driver}", f"state={state}")

    def firmware_missing(self, driver: str, pack: str | None) -> None:
        self.emit("firmware missing", f"driver={driver}", f"pack={pack or 'unknown'}")

    def net_up(self, iface: str, type_: str, ip: str) -> None:
        self.emit("net up", f"iface={iface}", f"type={type_}", f"ip={ip}")

    def download_start(self, url: str, dest: str) -> None:
        self._last_pct = None
        self.emit("download start", f"url={url}", f"dest={dest}")

    def download_progress(self, done: int, total: int | None, *, force: bool = False) -> None:
        """Emit ``download progress pct=N`` when N changes, at most once a second
        (100 is always emitted)."""
        if not total:
            return
        pct = max(0, min(100, done * 100 // total))
        now = time.monotonic()
        if pct == self._last_pct:
            return
        if not force and pct != 100 and now - self._last_pct_time < 1.0:
            return
        self._last_pct = pct
        self._last_pct_time = now
        self.emit("download progress", f"pct={pct}")

    def download_done(self, path: str, size: int, sha256: str) -> None:
        self.emit("download done", f"path={path}", f"bytes={size}", f"sha256={sha256}")

    def verify_ok(self, sha256: str) -> None:
        self.emit("verify ok", f"sha256={sha256}")

    def verify_fail(self, expected: str, got: str) -> None:
        self.emit("verify fail", f"expected={expected}", f"got={got}")

    def handoff(self, path: str) -> None:
        self.emit("handoff", f"oneshot={path}")

    def error(self, code: str, text: str) -> None:
        self.emit("error", code, text)
