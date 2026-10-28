"""User interfaces: a curses TUI for the Linux console and a line-based fallback.

Both implement the same small set of screens (``UI``), so the flow in
``beastnet.flow`` does not care which one is in front of the user:

- ``menu``: a title, some text, a list to choose from (also used for messages)
- ``form``: a few text fields (URL, checksum, passphrase)
- ``task``: run a function in a worker thread while showing that we are busy
- ``download``: run the download job with a progress bar, speed and ETA
- ``shell``: leave the screen to the user's shell for a while
- ``document``: a longer text that scrolls, with a few buttons under it

``set_mode`` switches the header and the step bar, e.g. for "Trust Ubuntu's
Secure Boot key", which is not part of the download steps.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

STEPS = ("Network", "Link", "Download", "Done")
SUBTITLE = "beast-net: download an ISO from a link"


@dataclass
class Item:
    label: str
    value: Any
    detail: str = ""  # right-hand column, e.g. "WPA2  5 GHz"
    bars: int | None = None  # WiFi signal 0..4
    lock: bool | None = None  # True: secured, False: open, None: not a network
    hint: str = ""  # shown under the list while this item is highlighted
    kind: str = ""  # "" | "warn" | "muted"


@dataclass
class Field:
    name: str
    label: str
    value: str = ""
    secret: bool = False
    hint: str = ""


def bars_text(bars: int | None) -> str:
    if bars is None:
        return ""
    return "[" + "|" * bars + "." * (4 - bars) + "]"


def lock_text(lock: bool | None) -> str:
    return "" if lock is None else ("[#]" if lock else "[ ]")


def human_time(seconds: float | None) -> str:
    if seconds is None or seconds < 0 or seconds > 99 * 3600:
        return "--"
    s = int(seconds + 0.5)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"


class Worker:
    """Run ``fn`` in a thread; ``result()`` returns its value or re-raises."""

    def __init__(self, fn: Callable[[], Any]) -> None:
        self._fn = fn
        self._value: Any = None
        self._exc: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            self._value = self._fn()
        except BaseException as e:  # noqa: BLE001 - handed to the UI thread
            self._exc = e

    def done(self) -> bool:
        return not self.thread.is_alive()

    def result(self) -> Any:
        self.thread.join()
        if self._exc is not None:
            raise self._exc
        return self._value


class UIClosed(Exception):
    """The terminal went away (EOF on input)."""


class UI:
    """Base class; see the module docstring."""

    brand_right = ""

    def __init__(self) -> None:
        self.step = 0
        self.subtitle = SUBTITLE
        self.steps: tuple[str, ...] = STEPS

    def set_step(self, step: int) -> None:
        self.step = step

    def set_mode(self, subtitle: str = SUBTITLE, steps: tuple[str, ...] = STEPS) -> tuple[str, tuple[str, ...]]:
        """Change the header text and the step bar (no steps: no bar). Returns the old ones."""
        old = (self.subtitle, self.steps)
        self.subtitle, self.steps = subtitle, tuple(steps)
        return old

    def menu(self, title: str, text: str, items: list[Item], *, kind: str = "",
             back: bool = True) -> Any:
        raise NotImplementedError

    def form(self, title: str, text: str, fields: list[Field], *, error: str = "") -> dict | None:
        raise NotImplementedError

    def task(self, title: str, text: str, fn: Callable[[], Any]) -> Any:
        raise NotImplementedError

    def download(self, title: str, lines: list[str], job: Callable[..., Any], *,
                 what: str = "download") -> Any:
        """Progress screen for ``job(on_progress, cancel_event)``; ``what`` names
        the job in the cancel texts ("download" or "copy": resumable; anything else,
        e.g. "boot.wim copy", is deleted when cancelled)."""
        raise NotImplementedError

    def document(self, title: str, text: str, items: list[Item], *, kind: str = "") -> Any:
        """A text too long for ``menu`` (it scrolls), then a choice; None = back."""
        return self.menu(title, text, items, kind=kind)

    def shell(self, fn: Callable[[], Any]) -> Any:
        return fn()

    def close(self) -> None:
        pass

    # Convenience built on menu().
    def message(self, title: str, text: str, *, kind: str = "", button: str = "OK") -> None:
        self.menu(title, text, [Item(button, True)], kind=kind, back=True)

    def confirm(self, title: str, text: str, yes: str = "Yes", no: str = "No", *,
                kind: str = "") -> bool:
        return self.menu(title, text, [Item(yes, True), Item(no, False)], kind=kind) is True
