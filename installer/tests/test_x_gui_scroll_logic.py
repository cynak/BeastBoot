"""Smooth scrolling arithmetic (gui/scrollmath.py) and opaque theme images (raster.flatten).

Pure Python: runs on any interpreter, no tkinter or display needed.
"""

from __future__ import annotations

import pytest

from beastbooter.gui import raster
from beastbooter.gui.scrollmath import FRAME_MS, Smoother, touchpad_pixels, wheel_pixels

NOTCH = 34.0


# ---------------------------------------------------------------------------
# wheel / touchpad deltas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ws", ["x11", "win32", "aqua"])
def test_tk9_wheel_delta_is_120_per_notch_everywhere(ws):
    kw = dict(notch=NOTCH, windowing=ws, tk_version=9.0)
    assert wheel_pixels(-120, 0, **kw) == NOTCH  # wheel towards the user: down the page
    assert wheel_pixels(120, 0, **kw) == -NOTCH
    assert wheel_pixels(-360, 0, **kw) == 3 * NOTCH  # Windows: several notches in one event


def test_high_resolution_deltas_scroll_proportionally():
    """Precision touchpads (Windows) and free-spinning wheels send fractions of a notch.
    Each must move a fraction of a notch, not a whole step (that made touchpads jumpy)."""
    kw = dict(notch=NOTCH, windowing="win32", tk_version=9.0)
    assert wheel_pixels(-8, 0, **kw) == pytest.approx(NOTCH * 8 / 120)
    assert sum(wheel_pixels(-8, 0, **kw) for _ in range(15)) == pytest.approx(NOTCH)


def test_tk86_x11_buttons_and_macos_lines():
    assert wheel_pixels(0, 4, notch=NOTCH, windowing="x11", tk_version=8.6) == -NOTCH
    assert wheel_pixels(0, 5, notch=NOTCH, windowing="x11", tk_version=8.6) == NOTCH
    # Tk 8.6 on macOS: delta counts lines, half a notch each
    assert wheel_pixels(-1, 0, notch=NOTCH, windowing="aqua", tk_version=8.6) == NOTCH / 2
    assert wheel_pixels(3, 0, notch=NOTCH, windowing="aqua", tk_version=8.6) == -1.5 * NOTCH
    assert wheel_pixels(0, 0, notch=NOTCH, windowing="x11", tk_version=9.0) == 0


@pytest.mark.parametrize("dx,dy", [(0, 0), (0, 5), (0, -5), (3, -40), (-7, 12), (-1, -1), (200, -300)])
def test_touchpad_deltas_unpack_like_tk(dx, dy):
    packed = (dx << 16) | (dy & 0xFFFF)  # how Tk 9 packs %D for <TouchpadScroll>
    assert touchpad_pixels(packed) == (dx, dy)


# ---------------------------------------------------------------------------
# Smoother: coalescing and easing
# ---------------------------------------------------------------------------


def frames(s: Smoother, limit: int = 200) -> list[float]:
    out = []
    while s.moving and len(out) < limit:
        out.append(s.step(FRAME_MS))
    return out


def test_a_burst_coalesces_into_one_target():
    s = Smoother()
    s.reset(0, 10_000)
    for _ in range(60):  # 60 wheel events before the next frame
        s.add(NOTCH)
    assert s.target == 60 * NOTCH
    assert s.pos == 0  # nothing moved yet: the frame applies them all at once


def test_target_stays_within_the_page():
    s = Smoother()
    s.reset(100, 500)
    for _ in range(60):
        s.add(NOTCH)
    assert s.target == 500
    for _ in range(60):
        s.add(-NOTCH)
    assert s.target == 0
    s.reset(900, 500)  # the page got shorter than the old position
    assert s.pos == s.target == 500


def test_one_notch_glides_monotonically_and_lands_exactly():
    s = Smoother()
    s.reset(0, 1000)
    s.add(NOTCH)
    path = frames(s)
    assert 4 <= len(path) <= 10, path  # ~0.1 s at 60 Hz
    assert path[-1] == NOTCH
    steps = [b - a for a, b in zip([0.0, *path], path)]
    assert all(st > 0 for st in steps), steps  # never overshoots or goes back
    assert max(steps) <= NOTCH / 2  # no frame jumps a whole notch
    assert steps[0] == max(steps)  # ease-out: fastest first (responsive)


def test_easing_is_time_based():
    """A late frame moves further, so the motion keeps its speed when frames drop."""
    a, b = Smoother(), Smoother()
    for s in (a, b):
        s.reset(0, 1000)
        s.add(100)
    a.step(2 * FRAME_MS)
    b.step(FRAME_MS)
    b.step(FRAME_MS)
    assert a.pos == pytest.approx(b.pos, abs=1.0)


def test_a_big_burst_glides_at_a_bounded_speed():
    """60 notches at once: no frame moves more than max_step (a whole new screen
    in one frame is the slowest kind of frame), and it still lands exactly."""
    s = Smoother()
    s.reset(0, 10_000)
    s.add(60 * NOTCH)
    path = []
    while s.moving and len(path) < 500:
        path.append(s.step(FRAME_MS, 120))
    steps = [b - a for a, b in zip([0.0, *path], path)]
    assert path[-1] == 60 * NOTCH
    assert max(steps) <= 120
    assert len(path) < 40  # ~0.6 s for ~2000 px
    s.add(-5, smooth=False)  # snapping respects the bound too
    assert s.step(FRAME_MS, 120) == 60 * NOTCH - 5


def test_direct_input_snaps_on_the_next_frame():
    s = Smoother()
    s.reset(0, 1000)
    s.add(7, smooth=False)  # touchpad: already smoothed by the system
    s.add(5, smooth=False)
    assert s.step(FRAME_MS) == 12
    assert not s.moving


def test_reversing_direction_mid_glide():
    s = Smoother()
    s.reset(500, 1000)
    s.add(3 * NOTCH)
    s.step(FRAME_MS)
    s.step(FRAME_MS)
    s.add(-6 * NOTCH)
    path = frames(s)
    assert path[-1] == 500 - 3 * NOTCH
    assert min(path) >= 500 - 3 * NOTCH  # no overshoot past the new target


def test_limit_shrinking_while_moving():
    s = Smoother()
    s.reset(0, 1000)
    s.add(800)
    s.step(FRAME_MS)
    s.set_limit(200)
    assert s.target == 200 and s.pos <= 200
    assert frames(s)[-1:] in ([], [200])


# ---------------------------------------------------------------------------
# raster.flatten: opaque images that look exactly like Tk's blending
# ---------------------------------------------------------------------------


def test_flatten_matches_tk_integer_blend():
    c = raster.Canvas(3, 1)
    c.px = [1.0, 0.0, 0.0, 128 / 255,  # half red
            0.2, 0.4, 0.6, 1.0,  # opaque: unchanged
            0.0, 0.0, 0.0, 0.0]  # transparent: the background
    out = raster.flatten(c, "#102030")
    q = [round(v * 255) for v in out.px]
    # Tk: (bg * (255 - a) + src * a) / 255, in integers
    assert q[0:4] == [(16 * 127 + 255 * 128) // 255, (32 * 127) // 255, (48 * 127) // 255, 255]
    assert q[4:8] == [51, 102, 153, 255]
    assert q[8:12] == [16, 32, 48, 255]
    assert all(out.px[i] == 1.0 for i in range(3, 12, 4))


def test_flatten_then_expand_is_the_same_as_expand_then_flatten():
    c = raster.box(5, "#334455", border="#8899AA", margin=3)
    a = raster.expand(raster.flatten(c, "#0B1020"), 8, 8, 40, 20)
    b = raster.flatten(raster.expand(c, 8, 8, 40, 20), "#0B1020")
    assert a.png() == b.png()
