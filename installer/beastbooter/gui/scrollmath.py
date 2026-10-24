"""Wheel and touchpad scrolling arithmetic for widgets.ScrollArea.

No tkinter here, so this module is unit-tested on any Python.

Wheel events come in bursts (X11 sends one per notch, often several per
frame; touchpads send many small ones), and applying each one at once moves
the page in big uneven jumps. ScrollArea instead adds every event's distance
to a Smoother and moves the view at most once per frame: wheel notches glide
there over about a tenth of a second (an ease-out), touchpad deltas (already
smoothed by the system) are applied as they are, one frame at a time.
"""

from __future__ import annotations

import math

FRAME_MS = 16  # one frame at 60 Hz: the view moves at most this often
EASE_MS = 36.0  # time constant of the ease-out: ~90% of the way in 80 ms
SETTLE_MS = 150  # quiet time after the last move before hover effects come back


def wheel_pixels(delta: int, num: int, *, notch: float, windowing: str, tk_version: float) -> float:
    """Distance in pixels (positive: down the page) for one wheel event.

    notch: pixels per wheel notch. Tk 8.7+ reports MouseWheel deltas in 1/120
    notch on every platform (high-resolution wheels and Windows precision
    touchpads send fractions of that); Tk 8.6 on X11 sends buttons 4 and 5,
    and on macOS deltas in lines (half a notch each).
    """
    if num == 4:
        return -notch
    if num == 5:
        return notch
    if not delta:
        return 0.0
    if windowing == "aqua" and tk_version < 8.7:
        return -delta * notch / 2
    return -delta * notch / 120


def touchpad_pixels(packed: int) -> tuple[int, int]:
    """(dx, dy) in pixels from Tk 9's <TouchpadScroll> %D (dx << 16 | dy & 0xffff,
    both signed; see tk::PreciseScrollDeltas). The page moves by -dy."""
    dx = packed >> 16
    low = packed & 0xFFFF
    return dx, (low if low < 0x8000 else low - 0x10000)


class Smoother:
    """Where the view is (`pos`) and where wheel input wants it (`target`), in
    pixels from the top, both within 0..limit."""

    def __init__(self, ease_ms: float = EASE_MS):
        self.ease_ms = ease_ms
        self.pos = self.target = 0.0
        self.limit = 0.0
        self._snap = False

    def reset(self, pos: float, limit: float) -> None:
        """Start from the view as it is (nothing moving)."""
        self.limit = max(0.0, float(limit))
        self.pos = self.target = min(max(0.0, float(pos)), self.limit)
        self._snap = False

    def set_limit(self, limit: float) -> None:
        self.limit = max(0.0, float(limit))
        self.target = min(self.target, self.limit)
        self.pos = min(self.pos, self.limit)

    def add(self, pixels: float, *, smooth: bool = True) -> None:
        """Queue a move; smooth=False (touchpads) gets there on the next frame."""
        self.target = min(max(0.0, self.target + pixels), self.limit)
        if not smooth:
            self._snap = True

    @property
    def moving(self) -> bool:
        return self.pos != self.target

    def step(self, dt_ms: float, max_step: float | None = None) -> float:
        """Advance one frame of dt_ms, by at most max_step pixels (a big burst
        glides instead of redrawing a whole new screen in one frame); returns
        the new position."""
        rest = self.target - self.pos
        if (self._snap or abs(rest) <= 1.0) and (max_step is None or abs(rest) <= max_step):
            self.pos, self._snap = self.target, False
        else:
            move = rest if self._snap else rest * (1.0 - math.exp(-max(0.0, dt_ms) / self.ease_ms))
            if abs(move) < 1.0:
                move = math.copysign(1.0, rest)
            if max_step is not None and abs(move) > max_step:
                move = math.copysign(max_step, rest)
            self.pos += move
        return self.pos
