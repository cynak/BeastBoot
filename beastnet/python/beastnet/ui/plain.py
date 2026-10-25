"""Line-based interface for dumb terminals and serial consoles without curses."""

from __future__ import annotations

import sys
import textwrap
import threading
import time
from typing import IO, Any
from collections.abc import Callable

from ..download import Progress, human_size
from . import UI, Field, Item, UIClosed, Worker, bars_text, human_time, lock_text


class LineUI(UI):
    def __init__(self, inp: IO[str] | None = None, out: IO[str] | None = None,
                 width: int = 78) -> None:
        super().__init__()
        self.inp = inp or sys.stdin
        self.out = out or sys.stdout
        self.width = width

    # -- I/O helpers ----------------------------------------------------------
    def _p(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def _wrap(self, text: str) -> None:
        for para in text.split("\n"):
            self._p(textwrap.fill(para, self.width) if para.strip() else "")

    def _readline(self, prompt: str, secret: bool = False) -> str:
        self.out.write(prompt)
        self.out.flush()
        restore = None
        if secret:
            try:
                import termios
                fd = self.inp.fileno()
                old = termios.tcgetattr(fd)
                new = termios.tcgetattr(fd)
                new[3] &= ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                restore = (termios, fd, old)
            except (ImportError, OSError, ValueError, AttributeError):
                restore = None
        try:
            line = self.inp.readline()
        except KeyboardInterrupt:
            line = "back\n"
        finally:
            if restore:
                termios_mod, fd, old = restore
                termios_mod.tcsetattr(fd, termios_mod.TCSADRAIN, old)
                self._p()
        if line == "":
            raise UIClosed()
        return line.rstrip("\r\n")

    def _header(self, title: str, kind: str = "") -> None:
        mark = {"error": "!! ", "warn": "! ", "ok": ""}.get(kind, "")
        steps = "  ".join(f"[{s}]" if i == self.step else s for i, s in enumerate(self.steps))
        self._p()
        self._p("=" * self.width)
        self._p(f"beast-booter / beast-net    {steps or self.subtitle}")
        self._p(f"{mark}{title}")
        self._p("-" * self.width)

    # -- screens --------------------------------------------------------------
    def menu(self, title: str, text: str, items: list[Item], *, kind: str = "",
             back: bool = True) -> Any:
        while True:
            self._header(title, kind)
            if text:
                self._wrap(text)
                self._p()
            for i, it in enumerate(items, 1):
                extra = " ".join(x for x in (bars_text(it.bars), lock_text(it.lock), it.detail) if x)
                self._p(f"  {i:2d}) {it.label}" + (f"   {extra}" if extra else ""))
            if len(items) == 1 and back:
                self._readline("Press Enter to continue: ")
                return items[0].value
            prompt = f"Choose 1-{len(items)}" + (", or b to go back" if back else "") + ": "
            ans = self._readline(prompt).strip().lower()
            if back and ans in ("b", "back", "q"):
                return None
            if ans.isdigit() and 1 <= int(ans) <= len(items):
                return items[int(ans) - 1].value

    def form(self, title: str, text: str, fields: list[Field], *, error: str = "") -> dict | None:
        self._header(title, "error" if error else "")
        if text:
            self._wrap(text)
        if error:
            self._p()
            self._wrap("!! " + error)
        self._p("(Type 'back' to go back.)")
        values = {}
        for fld in fields:
            if fld.hint:
                self._wrap(f"  {fld.hint}")
            default = "" if fld.secret else fld.value
            prompt = f"{fld.label}" + (f" [{default}]" if default else "") + ": "
            ans = self._readline(prompt, secret=fld.secret)
            if ans.strip().lower() == "back":
                return None
            values[fld.name] = ans if ans != "" else (fld.value if not fld.secret else "")
        return values

    def task(self, title: str, text: str, fn: Callable[[], Any]) -> Any:
        self._p(f"... {text}")
        return Worker(fn).result()

    def download(self, title: str, lines: list[str], job: Callable[..., Any]) -> Any:
        self._header(title)
        for line in lines:
            self._p(line)
        self._p("(Ctrl-C cancels; the partial file is kept for resuming.)")
        state: dict[str, Progress | None] = {"p": None}
        cancel = threading.Event()
        w = Worker(lambda: job(lambda p: state.__setitem__("p", p), cancel))
        tty = hasattr(self.out, "isatty") and self.out.isatty()
        last_line, last_time = "", 0.0
        while not w.done():
            try:
                time.sleep(0.25)
            except KeyboardInterrupt:
                cancel.set()
                continue
            p = state["p"]
            if p is None:
                continue
            line = progress_line(p)
            now = time.monotonic()
            if tty:
                self.out.write("\r" + line[: self.width].ljust(self.width))
                self.out.flush()
            elif line != last_line and now - last_time >= 5:
                self._p(line)
                last_line, last_time = line, now
        if tty:
            self._p()
        return w.result()


def progress_line(p: Progress) -> str:
    if p.phase == "connect":
        return "Connecting..."
    if p.phase == "check":
        return f"Checking data already on the stick: {human_size(p.done)}"
    if p.phase == "verify":
        return "Verifying the SHA-256..."
    if p.phase == "retry":
        return f"Connection lost, resuming ({p.note})"
    if p.total:
        pct = p.done * 100 // p.total
        return (f"{pct:3d}%  {human_size(p.done)} of {human_size(p.total)}  "
                f"{human_size(p.speed)}/s  {human_time(p.eta)} left")
    return f"{human_size(p.done)}  {human_size(p.speed)}/s"
