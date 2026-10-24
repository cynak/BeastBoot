"""curses interface for the Linux console (80x25 and larger) and serial terminals.

Only ASCII text plus curses line-drawing characters (ACS_*), which the Linux
VT font and every VT100-style terminal can show. Colours when available,
reverse video otherwise. All drawing happens on the main thread; long work
runs in a Worker thread while the screen keeps updating.
"""

from __future__ import annotations

import curses
import locale
import os
import sys
import textwrap
import threading
from typing import Any
from collections.abc import Callable

from ..download import Progress, human_size
from . import STEPS, UI, Field, Item, Worker, bars_text, human_time, lock_text

MIN_W, MIN_H = 40, 14
SPINNER = "|/-\\"


def wrap(text: str, width: int) -> list[str]:
    out: list[str] = []
    for para in text.split("\n"):
        if not para.strip():
            out.append("")
            continue
        out.extend(textwrap.wrap(para, max(10, width), break_on_hyphens=False) or [""])
    return out


def _keymap() -> dict[int, str]:
    names = {
        "KEY_UP": "up", "KEY_DOWN": "down", "KEY_LEFT": "left", "KEY_RIGHT": "right",
        "KEY_HOME": "home", "KEY_END": "end", "KEY_PPAGE": "pgup", "KEY_NPAGE": "pgdn",
        "KEY_BACKSPACE": "bs", "KEY_DC": "del", "KEY_ENTER": "enter", "KEY_BTAB": "btab",
        "KEY_RESIZE": "resize",
    }
    m = {getattr(curses, k): v for k, v in names.items() if hasattr(curses, k)}
    m[curses.KEY_F0 + 2] = "f2"
    return m


class TUI(UI):
    def __init__(self, scr, *, real: bool = True, brand_right: str = "") -> None:
        super().__init__()
        self.scr = scr
        self.real = real
        self.brand_right = brand_right
        self.keys = _keymap()
        R, B = curses.A_REVERSE, curses.A_BOLD
        self.a = {"header": R, "accent": B, "ok": B, "warn": B, "error": B, "sel": R,
                  "bar": R, "dim": 0, "title": B}
        if real:
            self._init_curses()

    def _init_curses(self) -> None:
        self.scr.keypad(True)
        self._cursor(False)
        if not curses.has_colors():
            return
        try:
            curses.start_color()
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = curses.COLOR_BLACK
            # beast-booter's grey and red (docs/assets/BRAND.md) in the console's 8 colours:
            # white on red for the title bar and the selection, red accents, light grey text.
            pairs = [(curses.COLOR_WHITE, curses.COLOR_RED), (curses.COLOR_RED, bg),
                     (curses.COLOR_GREEN, bg), (curses.COLOR_YELLOW, bg), (curses.COLOR_RED, bg),
                     (curses.COLOR_WHITE, curses.COLOR_RED), (curses.COLOR_WHITE, bg)]
            for i, (fg, b) in enumerate(pairs, 1):
                curses.init_pair(i, fg, b)
            cp, B = curses.color_pair, curses.A_BOLD
            self.a = {"header": cp(1) | B, "accent": cp(2) | B, "ok": cp(3) | B, "warn": cp(4) | B,
                      "error": cp(5) | B, "sel": cp(6) | B, "bar": cp(6), "dim": cp(7), "title": cp(7) | B}
        except curses.error:
            pass

    # -- low level ----------------------------------------------------------------
    def _cursor(self, on: bool) -> None:
        if self.real:
            try:
                curses.curs_set(1 if on else 0)
            except curses.error:
                pass

    def _key(self, timeout_ms: int = -1) -> str | None:
        self.scr.timeout(timeout_ms)
        try:
            k = self.scr.get_wch()
        except curses.error:
            return None
        except KeyboardInterrupt:
            return "esc"
        if isinstance(k, str):
            special = {"\n": "enter", "\r": "enter", "\x1b": "esc", "\t": "tab", "\x7f": "bs",
                       "\x08": "bs", "\x03": "esc", "\x15": "ctrl-u"}
            if k in special:
                return special[k]
            return k if k.isprintable() else None
        return self.keys.get(k)

    def _acs(self, name: str, fallback: str) -> int:
        return getattr(curses, name, ord(fallback)) if self.real else ord(fallback)

    def _put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        room = w - x - (1 if y == h - 1 else 0)  # the bottom-right cell cannot be written
        text = text[:max(0, room)]
        if not text:
            return
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass
        except UnicodeEncodeError:
            try:
                self.scr.addstr(y, x, text.encode("ascii", "replace").decode("ascii"), attr)
            except curses.error:
                pass

    def _box(self, y: int, x: int, h: int, w: int, title: str, attr: int) -> None:
        hl, vl = self._acs("ACS_HLINE", "-"), self._acs("ACS_VLINE", "|")
        try:
            self.scr.addch(y, x, self._acs("ACS_ULCORNER", "+"), attr)
            self.scr.hline(y, x + 1, hl | attr, w - 2)
            self.scr.addch(y, x + w - 1, self._acs("ACS_URCORNER", "+"), attr)
            self.scr.vline(y + 1, x, vl | attr, h - 2)
            self.scr.vline(y + 1, x + w - 1, vl | attr, h - 2)
            self.scr.addch(y + h - 1, x, self._acs("ACS_LLCORNER", "+"), attr)
            self.scr.hline(y + h - 1, x + 1, hl | attr, w - 2)
            self.scr.addch(y + h - 1, x + w - 1, self._acs("ACS_LRCORNER", "+"), attr)
        except curses.error:
            pass
        if title:
            t = title if len(title) <= w - 6 else title[: w - 9] + "..."
            self._put(y, x + 2, f" {t} ", attr | curses.A_BOLD)

    def _frame(self, title: str, help_: str, kind: str = "") -> tuple[int, int, int, int] | None:
        """Header, step bar, content box, key help. Returns the box inside
        (top, left, height, width), or None if the terminal is too small."""
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < MIN_H or w < MIN_W:
            self._put(0, 0, "Terminal too small for beast-net.")
            self._put(1, 0, f"Need {MIN_W}x{MIN_H}, have {w}x{h}.")
            return None
        a = self.a
        self._put(0, 0, " " * w, a["header"])
        self._put(0, 1, "beast-booter", a["header"])
        self._put(0, 14, "| beast-net: download an ISO from a link"[: max(0, w - 16 - len(self.brand_right))],
                  a["header"])  # bright white on red: readable on the console
        if self.brand_right:
            self._put(0, w - len(self.brand_right) - 1, self.brand_right, a["header"])
        x = 2
        for i, name in enumerate(STEPS):
            label = f" {i + 1} {name} "
            if i == self.step:
                attr = a["sel"] | curses.A_BOLD
            elif i < self.step:
                attr = a["ok"]
            else:
                attr = a["dim"]
            self._put(2, x, label, attr)
            x += len(label)
            if i < len(STEPS) - 1:
                self._put(2, x, " > ", a["dim"])
                x += 3
        box_attr = {"error": a["error"], "warn": a["warn"], "ok": a["ok"]}.get(kind, a["accent"])
        self._box(4, 1, h - 6, w - 2, title, box_attr)
        self._put(h - 1, 1, help_, a["dim"])
        return 5, 3, h - 8, w - 6

    def _wait_resize(self) -> str | None:
        self.scr.refresh()
        return self._key()

    # -- screens ------------------------------------------------------------------
    def menu(self, title: str, text: str, items: list[Item], *, kind: str = "",
             back: bool = True) -> Any:
        if not items:
            raise ValueError("menu without items")
        sel, top = 0, 0
        help_ = "Up/Down move   Enter select" + ("   Esc back" if back else "")
        while True:
            area = self._frame(title, help_, kind)
            if area is None:
                k = self._wait_resize()
                if k == "esc" and back:
                    return None
                continue
            y0, x0, ah, aw = area
            hint_rows = 2 if any(it.hint for it in items) else 0
            lines = wrap(text, aw) if text else []
            room_for_text = max(0, ah - hint_rows - min(len(items), 4) - 1)
            if len(lines) > room_for_text:
                lines = lines[:max(0, room_for_text - 1)] + ["..."]
            text_attr = self.a["error"] if kind == "error" else 0
            for i, line in enumerate(lines):
                self._put(y0 + i, x0, line, text_attr if i == 0 else 0)
            ly = y0 + len(lines) + (1 if lines else 0)
            rows = max(1, y0 + ah - hint_rows - ly)
            if sel < top:
                top = sel
            if sel >= top + rows:
                top = sel - rows + 1
            for r, idx in enumerate(range(top, min(len(items), top + rows))):
                self._item(ly + r, x0, aw, items[idx], idx == sel)
            if top > 0:
                self._put(ly, x0 + aw - 6, " more^", self.a["dim"])
            if top + rows < len(items):
                self._put(ly + rows - 1, x0 + aw - 6, " morev", self.a["dim"])
            if items[sel].hint:
                for i, line in enumerate(wrap(items[sel].hint, aw)[:hint_rows]):
                    self._put(y0 + ah - hint_rows + i, x0, line, self.a["dim"])
            self.scr.refresh()
            k = self._key()
            if k in ("up", "btab") and sel > 0:
                sel -= 1
            elif k in ("down", "tab") and sel < len(items) - 1:
                sel += 1
            elif k == "home":
                sel = 0
            elif k == "end":
                sel = len(items) - 1
            elif k == "pgup":
                sel = max(0, sel - rows)
            elif k == "pgdn":
                sel = min(len(items) - 1, sel + rows)
            elif k == "enter":
                return items[sel].value
            elif k == "esc" and back:
                return None
            elif k and len(k) == 1 and k.isdigit() and 1 <= int(k) <= min(9, len(items)):
                sel = int(k) - 1

    def _item(self, y: int, x: int, w: int, it: Item, selected: bool) -> None:
        a = self.a
        attr = a["sel"] if selected else {"warn": a["warn"], "muted": a["dim"]}.get(it.kind, 0)
        bars, lock = bars_text(it.bars), lock_text(it.lock)
        right = "  ".join(t for t in (bars, lock, it.detail) if t)
        marker = "> " if selected else "  "
        label_w = max(4, w - len(marker) - len(right) - 2)
        label = it.label if len(it.label) <= label_w else it.label[: label_w - 3] + "..."
        line = (marker + label).ljust(w - len(right) - 1) + right
        self._put(y, x, line.ljust(w)[:w], attr)
        if bars and not selected:
            col = a["ok"] if (it.bars or 0) >= 3 else a["warn"] if it.bars == 2 else a["error"]
            self._put(y, x + w - len(right) - 1, bars, col)

    def form(self, title: str, text: str, fields: list[Field], *, error: str = "") -> dict | None:
        bufs = [list(f.value) for f in fields]
        pos = [len(b) for b in bufs]
        reveal = [False] * len(fields)
        cur = 0
        help_ = "Enter next/OK   Up/Down field   Esc back"
        if any(f.secret for f in fields):
            help_ += "   F2 show"
        while True:
            area = self._frame(title, help_, "error" if error else "")
            if area is None:
                if self._wait_resize() == "esc":
                    return None
                continue
            y0, x0, ah, aw = area
            lines = wrap(text, aw) if text else []
            err_lines = wrap(error, aw)[:3] if error else []
            for i, line in enumerate(lines[: max(0, ah - 4 * len(fields) - len(err_lines))]):
                self._put(y0 + i, x0, line)
            y = y0 + len(lines) + (1 if lines else 0)
            cursor = None
            fw = aw - 2
            for i, f in enumerate(fields):
                active = i == cur
                self._put(y, x0, f.label, curses.A_BOLD if active else 0)
                shown = "*" * len(bufs[i]) if (f.secret and not reveal[i]) else "".join(bufs[i])
                start = max(0, pos[i] - fw + 1) if active else 0
                self._put(y + 1, x0, "[" + shown[start:start + fw].ljust(fw) + "]",
                          self.a["sel"] if active else self.a["accent"])
                if active:
                    cursor = (y + 1, x0 + 1 + pos[i] - start)
                y += 2
                if f.hint:
                    self._put(y, x0, f.hint[:aw], self.a["dim"])
                    y += 1
                y += 1
            for i, line in enumerate(err_lines):
                self._put(y0 + ah - len(err_lines) + i, x0, line, self.a["error"])
            if cursor:
                try:
                    self.scr.move(*cursor)
                except curses.error:
                    pass
            self._cursor(True)
            self.scr.refresh()
            k = self._key()
            b, p = bufs[cur], pos[cur]
            if k == "enter":
                if cur < len(fields) - 1:
                    cur += 1
                    continue
                self._cursor(False)
                return {f.name: "".join(bb) for f, bb in zip(fields, bufs)}
            if k == "esc":
                self._cursor(False)
                return None
            if k in ("down", "tab"):
                cur = (cur + 1) % len(fields)
            elif k in ("up", "btab"):
                cur = (cur - 1) % len(fields)
            elif k == "left":
                pos[cur] = max(0, p - 1)
            elif k == "right":
                pos[cur] = min(len(b), p + 1)
            elif k == "home":
                pos[cur] = 0
            elif k == "end":
                pos[cur] = len(b)
            elif k == "bs" and p > 0:
                del b[p - 1]
                pos[cur] = p - 1
            elif k == "del" and p < len(b):
                del b[p]
            elif k == "ctrl-u":
                b.clear()
                pos[cur] = 0
            elif k == "f2":
                reveal[cur] = not reveal[cur]
            elif k and len(k) == 1:
                b.insert(p, k)
                pos[cur] = p + 1
                error = ""  # typing clears the old complaint

    def task(self, title: str, text: str, fn: Callable[[], Any]) -> Any:
        w = Worker(fn)
        i = 0
        while not w.done():
            area = self._frame(title, "Please wait...")
            if area is not None:
                y0, x0, ah, aw = area
                lines = wrap(text, aw - 4)
                for j, line in enumerate(lines[:ah]):
                    self._put(y0 + j, x0, line)
                self._put(y0 + min(len(lines), ah - 1), x0 + min(len(lines[-1]) + 1 if lines else 0, aw - 3),
                          f"({SPINNER[i % len(SPINNER)]})", self.a["accent"])
            self.scr.refresh()
            self._key(150)
            i += 1
        return w.result()

    def download(self, title: str, lines: list[str], job: Callable[..., Any]) -> Any:
        state: dict[str, Progress | None] = {"p": None}
        cancel = threading.Event()
        w = Worker(lambda: job(lambda p: state.__setitem__("p", p), cancel))
        confirm = False
        while not w.done():
            area = self._frame(title, "Esc cancel (the partial download is kept for resuming)")
            if area is not None:
                self._draw_progress(area, lines, state["p"], confirm, cancel.is_set())
            self.scr.refresh()
            k = self._key(200)
            if cancel.is_set():
                continue
            if not confirm and k == "esc":
                confirm = True
            elif confirm and k in ("y", "Y"):
                cancel.set()
                confirm = False
            elif confirm and k in ("n", "N", "esc", "enter"):
                confirm = False
        return w.result()

    def _draw_progress(self, area, lines: list[str], p: Progress | None, confirm: bool,
                       cancelling: bool) -> None:
        y0, x0, ah, aw = area
        for i, line in enumerate(lines[: max(0, ah - 6)]):
            self._put(y0 + i, x0, line if len(line) <= aw else line[: aw - 3] + "...")
        y = y0 + len(lines) + 1
        bw = max(10, aw - 7)
        frac = (p.done / p.total) if (p and p.total) else 0.0
        frac = max(0.0, min(1.0, frac))
        filled = int(bw * frac)
        self._put(y, x0, "[")
        self._put(y, x0 + 1, " " * filled, self.a["bar"])
        self._put(y, x0 + 1 + filled, "." * (bw - filled), self.a["dim"])
        self._put(y, x0 + 1 + bw, "]")
        self._put(y, x0 + bw + 3, f"{int(frac * 100):3d}%" if (p and p.total) else "  ?%", curses.A_BOLD)
        status, note = "Connecting...", ""
        if p is not None:
            if p.phase == "check":
                status = f"Checking what is already on the stick: {human_size(p.done)}"
            elif p.phase == "verify":
                status = "Verifying the SHA-256..."
            elif p.phase == "connect":
                status = "Connecting..."
            else:
                total = f" of {human_size(p.total)}" if p.total else ""
                status = (f"{human_size(p.done)}{total}    {human_size(p.speed)}/s    "
                          f"{human_time(p.eta)} left")
                if p.resumed_from:
                    note = f"Resumed at {human_size(p.resumed_from)}."
            if p.phase == "retry":
                note = f"Connection problem, resuming: {p.note}"
        self._put(y + 2, x0, status)
        if note:
            self._put(y + 3, x0, note[:aw], self.a["warn"] if p and p.phase == "retry" else self.a["dim"])
        if cancelling:
            self._put(y + 5, x0, "Cancelling...", self.a["warn"])
        elif confirm:
            self._put(y + 5, x0, "Cancel the download? The partial file is kept.  y = yes, n = no",
                      self.a["warn"])

    def shell(self, fn: Callable[[], Any]) -> Any:
        if self.real:
            curses.def_prog_mode()
            curses.endwin()
        try:
            return fn()
        finally:
            if self.real:
                curses.reset_prog_mode()
                self.scr.clear()
                self.scr.refresh()
                self._cursor(False)

    def close(self) -> None:
        if self.real:
            try:
                curses.endwin()
            except curses.error:
                pass


def open_tui(brand_right: str = "") -> TUI | None:
    """Start curses on the terminal, or return None if that cannot work."""
    term = os.environ.get("TERM", "")
    if not term or term == "dumb" or not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    os.environ.setdefault("ESCDELAY", "25")
    try:
        scr = curses.initscr()
    except Exception:  # noqa: BLE001 - no terminfo entry etc.
        return None
    try:
        curses.noecho()
        curses.raw()  # Ctrl-C arrives as a key (treated as Esc), not as a signal
        return TUI(scr, real=True, brand_right=brand_right)
    except Exception:  # noqa: BLE001
        try:
            curses.endwin()
        except curses.error:
            pass
        return None
