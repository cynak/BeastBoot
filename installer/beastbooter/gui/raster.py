"""Tiny anti-aliased rasterizer and PNG encoder for the window's images.

Every image the window shows (rounded cards, buttons, fields, the progress
bar, check boxes, drive icons, the logo) is generated here at start-up, at the
current display scaling: no image files, no third-party packages. Shapes are
described by signed distance functions, so their edges are smoothly
anti-aliased; the result is a straight-alpha RGBA PNG that Tk's photo images
show with real transparency on every platform (Tk 8.6+ reads PNG natively).

No tkinter here, so this module is unit-tested on any Python.
"""

from __future__ import annotations

import math
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

RGBA = tuple[float, float, float, float]  # 0..1 each, straight alpha


def rgba(color: str, alpha: float = 1.0) -> RGBA:
    """'#rrggbb' (or '#rrggbbaa') -> (r, g, b, a) in 0..1."""
    c = color.lstrip("#")
    if len(c) == 8:
        alpha *= int(c[6:8], 16) / 255
        c = c[:6]
    if len(c) != 6:
        raise ValueError(f"not a #rrggbb colour: {color!r}")
    return (int(c[0:2], 16) / 255, int(c[2:4], 16) / 255, int(c[4:6], 16) / 255, alpha)


def mix(a: str, b: str, t: float) -> str:
    """The colour t of the way from a to b (both '#rrggbb')."""
    ca, cb = rgba(a), rgba(b)
    return "#" + "".join(f"{round((x + (y - x) * t) * 255):02x}" for x, y in zip(ca[:3], cb[:3]))


# ---------------------------------------------------------------------------
# Signed distance functions (negative inside, in pixels)
# ---------------------------------------------------------------------------

Sdf = Callable[[float, float], float]


def sd_round_rect(x0: float, y0: float, x1: float, y1: float, r: float) -> Sdf:
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hw, hh = (x1 - x0) / 2, (y1 - y0) / 2
    r = max(0.0, min(r, hw, hh))

    def f(x: float, y: float) -> float:
        qx, qy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
        return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r

    return f


def sd_circle(cx: float, cy: float, r: float) -> Sdf:
    return lambda x, y: math.hypot(x - cx, y - cy) - r


def sd_segment(ax: float, ay: float, bx: float, by: float, half_width: float) -> Sdf:
    """A line from a to b with round caps."""
    dx, dy = bx - ax, by - ay
    ll = dx * dx + dy * dy or 1e-9

    def f(x: float, y: float) -> float:
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / ll))
        return math.hypot(x - ax - t * dx, y - ay - t * dy) - half_width

    return f


def sd_polyline(points: list[tuple[float, float]], half_width: float) -> Sdf:
    segs = [sd_segment(*a, *b, half_width) for a, b in zip(points, points[1:])]
    return lambda x, y: min(s(x, y) for s in segs)


def sd_polygon(points: list[tuple[float, float]], rounding: float = 0.0) -> Sdf:
    """A closed polygon (any winding), optionally with rounded corners."""
    n = len(points)

    def f(x: float, y: float) -> float:
        d = float("inf")
        inside = False
        for i in range(n):
            ax, ay = points[i]
            bx, by = points[(i + 1) % n]
            ex, ey = bx - ax, by - ay
            ll = ex * ex + ey * ey or 1e-9
            t = max(0.0, min(1.0, ((x - ax) * ex + (y - ay) * ey) / ll))
            d = min(d, math.hypot(x - ax - t * ex, y - ay - t * ey))
            if (ay > y) != (by > y) and x < ax + (y - ay) * ex / (ey or 1e-9):
                inside = not inside
        return (-d if inside else d) - rounding

    return f


def sd_subtract(a: Sdf, b: Sdf) -> Sdf:
    return lambda x, y: max(a(x, y), -b(x, y))


# ---------------------------------------------------------------------------
# Canvas
# ---------------------------------------------------------------------------


@dataclass
class Gradient:
    """A vertical (or diagonal) two-colour gradient for a fill."""
    top: str
    bottom: str
    diagonal: bool = False


class Canvas:
    """An RGBA pixel buffer; shapes are composited with "over"."""

    def __init__(self, width: int, height: int):
        self.w, self.h = int(width), int(height)
        self.px = [0.0] * (self.w * self.h * 4)

    def fill(self, sdf: Sdf, color: str | Gradient, alpha: float = 1.0,
             bbox: tuple[float, float, float, float] | None = None) -> None:
        x0, y0, x1, y1 = bbox or (0, 0, self.w, self.h)
        xs = range(max(0, int(x0) - 1), min(self.w, int(math.ceil(x1)) + 1))
        ys = range(max(0, int(y0) - 1), min(self.h, int(math.ceil(y1)) + 1))
        if isinstance(color, Gradient):
            top, bot = rgba(color.top, alpha), rgba(color.bottom, alpha)
            span = max(1.0, (y1 - y0) + ((x1 - x0) if color.diagonal else 0))
        else:
            top = bot = rgba(color, alpha)
            span = 1.0
        px, w = self.px, self.w
        for y in ys:
            for x in xs:
                cov = 0.5 - sdf(x + 0.5, y + 0.5)
                if cov <= 0:
                    continue
                if cov > 1:
                    cov = 1.0
                if top is bot:
                    sr, sg, sb, sa = top
                else:
                    t = ((y - y0) + ((x - x0) if color.diagonal else 0)) / span
                    t = min(1.0, max(0.0, t))
                    sr, sg, sb, sa = (top[i] + (bot[i] - top[i]) * t for i in range(4))
                sa *= cov
                i = (y * w + x) * 4
                dr, dg, db, da = px[i], px[i + 1], px[i + 2], px[i + 3]
                oa = sa + da * (1 - sa)
                if oa <= 0:
                    continue
                k = da * (1 - sa)
                px[i] = (sr * sa + dr * k) / oa
                px[i + 1] = (sg * sa + dg * k) / oa
                px[i + 2] = (sb * sa + db * k) / oa
                px[i + 3] = oa

    def png(self) -> bytes:
        rows = bytearray()
        px = self.px
        for y in range(self.h):
            rows.append(0)  # filter: none
            base = y * self.w * 4
            rows.extend(min(255, max(0, round(v * 255))) for v in px[base: base + self.w * 4])
        return encode_png(self.w, self.h, bytes(rows))


def encode_png(width: int, height: int, filtered_rows: bytes) -> bytes:
    """An 8-bit RGBA PNG from rows that each start with their filter byte."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(filtered_rows, 9))
            + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# Widget pieces (stretchable: ttk image elements keep `border` pixels at each
# side and stretch the middle)
# ---------------------------------------------------------------------------


def box(radius: int, fill: str | Gradient | None, *, border: str | None = None, border_width: float = 1.0,
        ring: str | None = None, ring_width: float = 2.0, margin: int = 0, center: int = 2,
        width: int | None = None, height: int | None = None, fill_alpha: float = 1.0) -> Canvas:
    """A rounded rectangle with an optional border and an optional focus ring
    outside it. `margin` pixels around the shape are left for the ring (and
    stay transparent without one), so every state of a widget has the same
    size; the ring sits at the outer edge of the margin. The canvas is
    (2 * (margin + radius) + center) pixels square unless width/height are given."""
    w = width or 2 * (margin + radius) + center
    h = height or 2 * (margin + radius) + center
    c = Canvas(w, h)
    m = margin
    shape = sd_round_rect(m, m, w - m, h - m, radius)
    if ring and m > 0:
        rw = min(ring_width, m)
        gap = m - rw
        c.fill(lambda x, y: max(shape(x, y) - gap - rw, gap - shape(x, y)), ring)
    if border:
        c.fill(lambda x, y: max(shape(x, y), -(shape(x, y) + border_width)), border)
        if fill is not None:
            c.fill(lambda x, y: shape(x, y) + border_width, fill, fill_alpha)
    elif fill is not None:
        c.fill(shape, fill, fill_alpha)
    return c


def expand(c: Canvas, bx: int, by: int, center_w: int, center_h: int) -> Canvas:
    """Repeat the uniform middle column and row of c (just inside borders bx / by)
    to make a centre of center_w x center_h pixels.

    ttk image elements tile an image's centre and edges across the widget; with
    a centre of a few pixels a large card is drawn in thousands of tiles, each
    alpha-blended (slow on X11). A large centre keeps it to a handful."""
    w = c.w
    out = Canvas(2 * bx + center_w, 2 * by + center_h)
    rows = []
    for y in range(out.h):
        sy = y if y < by else (c.h - (out.h - y) if y >= out.h - by else by)
        row = c.px[sy * w * 4: (sy + 1) * w * 4]
        rows.append(row[: bx * 4] + row[bx * 4: (bx + 1) * 4] * center_w + row[(w - bx) * 4:])
    out.px = [v for r in rows for v in r]
    return out


def flatten(c: Canvas, background: str) -> Canvas:
    """c composited over the opaque colour `background`: a fully opaque image.

    Tk draws a photo image that has partly transparent pixels by reading the
    pixels under it back from the X server, blending and writing them out again
    (one round trip per tile; on XWayland/glamor a GPU read-back), while an
    opaque image is a plain server-side copy, many times faster. Use it for
    images drawn over a known single colour (a ttk element over its style's
    background). The blend is done on the 8-bit values with Tk's own integer
    formula, so the result looks exactly like Tk blending the original."""
    br, bgr, bb, _ = (round(v * 255) for v in rgba(background))
    out = Canvas(c.w, c.h)
    src, dst = c.px, out.px
    for i in range(0, len(src), 4):
        a = min(255, max(0, round(src[i + 3] * 255)))
        if a == 255:
            dst[i:i + 3] = (min(255, max(0, round(v * 255))) / 255 for v in src[i:i + 3])
        else:
            ua = 255 - a
            dst[i:i + 3] = ((b * ua + min(255, max(0, round(v * 255))) * a) // 255 / 255
                            for b, v in zip((br, bgr, bb), src[i:i + 3]))
        dst[i + 3] = 1.0
    return out


def pill(length: int, thickness: int, fill: str, *, vertical: bool = False) -> Canvas:
    """A capsule (scrollbar thumb, progress bar)."""
    w, h = (thickness, length) if vertical else (length, thickness)
    c = Canvas(w, h)
    c.fill(sd_round_rect(0, 0, w, h, thickness / 2), fill)
    return c
