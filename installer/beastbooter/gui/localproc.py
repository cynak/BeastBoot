"""Run the CLI as a normal child process (same interface as ElevatedProcess).

Used when no administrator rights are needed (creating an image file) or the
GUI already has them. Output goes to a file so the GUI can show it on failure.
"""

from __future__ import annotations

import os
import signal
import subprocess


class LocalProcess:
    """A child process with poll()/wait()/cancel(), like interfaces.ElevatedProcess."""

    def __init__(self, argv: list[str], output_path: str):
        self.output_path = output_path
        self._out = open(output_path, "wb")
        kwargs: dict = {}
        if os.name == "nt":
            # No console window flashing up when the GUI runs under pythonw.exe.
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self._proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=self._out, stderr=subprocess.STDOUT, **kwargs
            )
        except BaseException:
            self._out.close()
            raise
        self._cancels = 0

    @property
    def pid(self) -> int:
        return self._proc.pid

    def poll(self) -> int | None:
        rc = self._proc.poll()
        if rc is not None:
            self._out.close()
        return rc

    def wait(self, timeout: float | None = None) -> int:
        rc = self._proc.wait(timeout)
        self._out.close()
        return rc

    def cancel(self) -> None:
        """First call: ask the CLI to stop (SIGINT -> it cleans up); later calls: kill it."""
        if self._proc.poll() is not None:
            return
        self._cancels += 1
        try:
            if self._cancels == 1 and os.name != "nt":
                self._proc.send_signal(signal.SIGINT)
            elif self._cancels == 1:
                self._proc.terminate()
            else:
                self._proc.kill()
        except OSError:
            pass  # it exited in the meantime

    def output_tail(self, max_lines: int = 20) -> list[str]:
        try:
            with open(self.output_path, "rb") as f:
                text = f.read()[-64 * 1024 :].decode("utf-8", errors="replace")
        except OSError:
            return []
        return [line for line in text.splitlines() if line.strip()][-max_lines:]
