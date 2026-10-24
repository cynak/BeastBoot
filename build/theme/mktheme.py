#!/usr/bin/env python3
"""beast-booter: generate the graphical boot menu theme (called by build/build.sh).

Every image of the theme is drawn by this script, pixel by pixel, from the
geometry and colours below (Python standard library only: a tiny vector
rasteriser and a zlib PNG writer). Text in images is drawn with the glyph
bitmaps of the PF2 fonts that build.sh made with grub-mkfont, so it looks
exactly like the text GRUB draws itself. The output depends only on this file,
its arguments and those fonts: no timestamps, no randomness, fixed zlib level.

    mktheme.py --out DIR --version VERSION --font KEY=FILE.pf2 ...

Font keys: item (menu entries), item_sel (selected entry), small (timeout
text), term (console/terminal, monospace) - these are loaded by GRUB at boot -
and title, label, key, which are only used to draw text into images here.

Writes into DIR (the theme directory, esp/grub/themes/beast/ on the drive):

    theme-pc.txt theme-efi.txt theme-efi-sb.txt   one theme per state badge
    console.cfg                                   console colours (GRUB script)
    background.png header.png footer.png badge-*.png
    menu_*.png select_*.png sb_frame_*.png sb_thumb_*.png
    bar_*.png bar_hl_*.png term_*.png             9-slice boxes (GRUB styled boxes)
    icons/<class>.png                             entry icons, by menuentry --class

To change the colours, edit PALETTE below and rebuild (docs/MENU.md).
"""

from __future__ import annotations

import argparse
import math
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# Colours. Taken from docs/assets/BRAND.md (dark greys, one red accent).
# Values are "#RRGGBB"; alpha, where needed, is given where a colour is used.
# ---------------------------------------------------------------------------
PALETTE = {
    "bg_from": "#0F0F10",        # background gradient, top left (grey-950)
    "bg_to": "#1C1517",          # background gradient, bottom right (red-tinted grey)
    "glow": "#D62839",           # soft light behind the menu (red-600)
    "glow2": "#7A1622",          # second, fainter light, bottom left (red-800)
    "dots": "#7A1622",           # dot pattern, right side (red-800)
    "panel": "#141415",          # menu panel fill (translucent; grey-900)
    "panel_edge": "#2F2F33",     # their 1 px border (grey-700)
    "console": "#0F0F10",        # console box and text background (opaque; grey-950)
    "console_text": "white",     # console text: a GRUB colour name (see docs/MENU.md)
    "accent": "#F0505E",         # selection border, progress bar, "-" in the name (red-400)
    "accent_fill": "#D62839",    # selection fill (translucent; red-600)
    "accent_deep": "#7A1622",    # red-800
    "item": "#CFCFD4",           # entry text (grey-300)
    "item_sel": "#FFFFFF",       # selected entry text
    "muted": "#9A9AA2",          # footer and timeout text (grey-400)
    "title": "#F2F2F3",          # "beast-booter" (grey-100)
    "eyebrow": "#FF8A93",        # version, tagline accents (red-300)
    "pill_fill": "#1A1A1C",      # badges and key caps (grey-850)
    "pill_edge": "#7A1622",      # red-800
    "pill_text": "#F2F2F3",      # grey-100
    "on": "#34D399",             # badge dot: Secure Boot on (OK)
    "off": "#FBBF24",            # badge dot: Secure Boot off (warning)
    "neutral": "#9A9AA2",        # badge dot: firmware mode (grey-400)
    "folder": "#FBBF24",
    "folder_dark": "#D97706",
    "disc_hole": "#141415",
    "line": "#CFCFD4",           # line icons (grey-300)
}

# Linux families and Windows: tint of the disc icon (menuentry --class).
# The distributions' own colours; generic Linux is neutral grey.
FAMILIES = {
    "ubuntu": "#E95420",
    "debian": "#D70A53",
    "fedora": "#3C6EB4",
    "arch": "#1793D1",
    "suse": "#73BA25",
    "mint": "#87CF3E",
    "linux": "#CFCFD4",
}

# Geometry (pixels; the theme positions are percentages plus these offsets).
ICON = 32                 # entry icon size (icon_width/icon_height)
ITEM_H = 32               # boot_menu item_height
ITEM_GAP = 12             # boot_menu item_spacing
SEL_PAD = 10              # selection box border (= corner size of select_*.png)
SEL_R = 10                # selection corner radius
PANEL_PAD = 20            # menu panel border (= corner size of menu_*.png)
PANEL_R = 16
TERM_PAD = 20             # console box border
LOGO = 56                 # logo size in the header
PANEL_PCT = 40            # menu panel width: this share of the screen + a fixed part

TAGLINE = "One USB drive. Many ISOs. Secure Boot intact."
BADGES = {                # theme variant -> (dot colour key, text) pills, left to right
    "pc": [("neutral", "Legacy BIOS")],
    "efi": [("neutral", "UEFI"), ("off", "Secure Boot off")],
    "efi-sb": [("neutral", "UEFI"), ("on", "Secure Boot on")],
}
KEYS = [                  # footer: key caps, then what they do
    (["up", "down"], "select"),
    (["Enter"], "boot / open"),
    (["Esc"], "back"),
    (["c"], "GRUB console"),
]
TIMEOUT_TEXT = "The highlighted entry starts in %d s"


def rgb(name_or_hex: str) -> tuple[float, float, float]:
    h = PALETTE.get(name_or_hex, name_or_hex).lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4))


def hexcol(name: str) -> str:
    return PALETTE.get(name, name).upper()


# ---------------------------------------------------------------------------
# PNG writer (8-bit RGB or RGBA, non-interlaced: what GRUB's png module reads)
# ---------------------------------------------------------------------------

def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _filter_rows(raw: bytes, w: int, h: int, bpp: int, fast: bool) -> bytes:
    stride = w * bpp
    out = bytearray()
    prev = bytes(stride)
    for y in range(h):
        row = raw[y * stride:(y + 1) * stride]
        if fast:  # big images: always "Up" (smooth gradients compress well)
            out.append(2)
            out += bytes((a - b) & 0xFF for a, b in zip(row, prev))
        else:     # small images: per row the filter with the smallest sum
            cands = []
            left = bytes(bpp) + row[:-bpp]
            upleft = bytes(bpp) + prev[:-bpp]
            cands.append((0, row))
            cands.append((1, bytes((a - b) & 0xFF for a, b in zip(row, left))))
            cands.append((2, bytes((a - b) & 0xFF for a, b in zip(row, prev))))
            cands.append((3, bytes((a - ((lt + u) >> 1)) & 0xFF for a, lt, u in zip(row, left, prev))))
            cands.append((4, bytes((a - _paeth(lt, u, ul)) & 0xFF
                                   for a, lt, u, ul in zip(row, left, prev, upleft))))
            best = min(cands, key=lambda c: (sum(v if v < 128 else 256 - v for v in c[1]), c[0]))
            out.append(best[0])
            out += best[1]
        prev = row
    return bytes(out)


def png_bytes(w: int, h: int, raw: bytes, alpha: bool, fast: bool = False) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    bpp = 4 if alpha else 3
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6 if alpha else 2, 0, 0, 0)
    idat = zlib.compress(_filter_rows(raw, w, h, bpp, fast), 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# ---------------------------------------------------------------------------
# Canvas: straight (non-premultiplied) RGBA floats, source-over blending
# ---------------------------------------------------------------------------

class Canvas:
    def __init__(self, w: int, h: int, fill=(0.0, 0.0, 0.0, 0.0)):
        self.w, self.h = w, h
        self.px = [list(fill) for _ in range(w * h)]

    def blend(self, x: int, y: int, c, a: float) -> None:
        if a <= 0.0 or not (0 <= x < self.w and 0 <= y < self.h):
            return
        p = self.px[y * self.w + x]
        da = p[3]
        oa = a + da * (1.0 - a)
        if oa <= 0.0:
            return
        k = da * (1.0 - a)
        p[0] = (c[0] * a + p[0] * k) / oa
        p[1] = (c[1] * a + p[1] * k) / oa
        p[2] = (c[2] * a + p[2] * k) / oa
        p[3] = oa

    def shape(self, sdf, paint, alpha: float = 1.0, box=None) -> None:
        """Fill where the signed distance (pixels, <0 inside) says so, anti-aliased.
        paint is an (r,g,b) tuple or a function (x, y) -> (r,g,b)."""
        x0, y0, x1, y1 = box if box else (0, 0, self.w, self.h)
        x0, y0 = max(0, int(x0)), max(0, int(y0))
        x1, y1 = min(self.w, int(math.ceil(x1))), min(self.h, int(math.ceil(y1)))
        fixed = not callable(paint)
        for y in range(y0, y1):
            fy = y + 0.5
            for x in range(x0, x1):
                cov = 0.5 - sdf(x + 0.5, fy)
                if cov <= 0.0:
                    continue
                if cov > 1.0:
                    cov = 1.0
                self.blend(x, y, paint if fixed else paint(x + 0.5, fy), alpha * cov)

    def crop(self, x: int, y: int, w: int, h: int) -> Canvas:
        c = Canvas(w, h)
        for j in range(h):
            for i in range(w):
                c.px[j * w + i] = list(self.px[(y + j) * self.w + x + i])
        return c

    def rgba_bytes(self) -> bytes:
        out = bytearray()
        for p in self.px:
            if p[3] <= 0.0:
                out += b"\0\0\0\0"
                continue
            out += bytes(max(0, min(255, int(v * 255.0 + 0.5))) for v in p)
        return bytes(out)

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(png_bytes(self.w, self.h, self.rgba_bytes(), alpha=True))


# ---------------------------------------------------------------------------
# Signed distance functions (pixels; negative inside)
# ---------------------------------------------------------------------------

def sd_circle(cx, cy, r):
    return lambda x, y: math.hypot(x - cx, y - cy) - r


def sd_rrect(x0, y0, x1, y1, r):
    cx, cy, hw, hh = (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) / 2, (y1 - y0) / 2

    def f(x, y):
        qx = abs(x - cx) - hw + r
        qy = abs(y - cy) - hh + r
        return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r
    return f


def _seg_dist(x, y, ax, ay, bx, by):
    pax, pay, bax, bay = x - ax, y - ay, bx - ax, by - ay
    den = bax * bax + bay * bay
    t = 0.0 if den == 0 else max(0.0, min(1.0, (pax * bax + pay * bay) / den))
    return math.hypot(pax - bax * t, pay - bay * t)


def sd_polyline(pts, width):
    segs = list(zip(pts, pts[1:]))
    return lambda x, y: min(_seg_dist(x, y, a[0], a[1], b[0], b[1]) for a, b in segs) - width / 2


def sd_polygon(pts):
    n = len(pts)

    def f(x, y):
        d = min(_seg_dist(x, y, pts[i][0], pts[i][1], pts[(i + 1) % n][0], pts[(i + 1) % n][1]) for i in range(n))
        inside = False
        j = n - 1
        for i in range(n):
            xi, yi, xj, yj = pts[i][0], pts[i][1], pts[j][0], pts[j][1]
            if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
                inside = not inside
            j = i
        return -d if inside else d
    return f


def sd_arc(cx, cy, r, a0, a1, width):
    """Stroke of a circle arc from angle a0 to a1 (degrees, clockwise on screen, 0 = right)."""
    e0 = (cx + r * math.cos(math.radians(a0)), cy + r * math.sin(math.radians(a0)))
    e1 = (cx + r * math.cos(math.radians(a1)), cy + r * math.sin(math.radians(a1)))
    span = (a1 - a0) % 360

    def f(x, y):
        ang = math.degrees(math.atan2(y - cy, x - cx))
        if (ang - a0) % 360 <= span:
            d = abs(math.hypot(x - cx, y - cy) - r)
        else:
            d = min(math.hypot(x - e0[0], y - e0[1]), math.hypot(x - e1[0], y - e1[1]))
        return d - width / 2
    return f


def sd_ring(cx, cy, r, width):
    return lambda x, y: abs(math.hypot(x - cx, y - cy) - r) - width / 2


def sd_union(*fs):
    return lambda x, y: min(f(x, y) for f in fs)


def sd_subtract(a, b):
    return lambda x, y: max(a(x, y), -b(x, y))


def scaled(sdf_units, s):
    """An SDF written in icon units (24 per icon) evaluated on pixels."""
    return lambda x, y: sdf_units(x / s, y / s) * s


def lerp3(a, b, t):
    return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t)


def grad(c0, c1, x0, y0, x1, y1):
    """Linear gradient paint from (x0,y0) to (x1,y1)."""
    dx, dy = x1 - x0, y1 - y0
    den = dx * dx + dy * dy

    def f(x, y):
        t = max(0.0, min(1.0, ((x - x0) * dx + (y - y0) * dy) / den))
        return lerp3(c0, c1, t)
    return f


# ---------------------------------------------------------------------------
# PF2 fonts (GRUB's bitmap font format): metrics and glyph bitmaps
# ---------------------------------------------------------------------------

class PF2:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        self.index: dict[int, int] = {}
        sec: dict[str, bytes] = {}
        pos = 0
        if self.data[:12] != b"FILE\0\0\0\x04PFF2":
            raise ValueError(f"{path}: not a PF2 font")
        while pos + 8 <= len(self.data):
            name = self.data[pos:pos + 4].decode("ascii")
            ln = struct.unpack(">I", self.data[pos + 4:pos + 8])[0]
            pos += 8
            if name == "DATA":
                break
            body = self.data[pos:pos + ln]
            sec[name] = body
            if name == "CHIX":
                for i in range(0, ln, 9):
                    cp, _flags, off = struct.unpack(">IBI", body[i:i + 9])
                    self.index[cp] = off
            pos += ln
        self.name = sec["NAME"].rstrip(b"\0").decode("utf-8")
        self.ascent = struct.unpack(">H", sec["ASCE"])[0]
        self.descent = struct.unpack(">H", sec["DESC"])[0]

    def glyph(self, ch: str):
        off = self.index.get(ord(ch))
        if off is None:
            raise ValueError(f"font {self.name!r} has no glyph for {ch!r}")
        w, h, xo, yo, dw = struct.unpack(">HHhhh", self.data[off:off + 10])
        return w, h, xo, yo, dw, self.data[off + 10:off + 10 + (w * h + 7) // 8]

    def width(self, text: str) -> int:
        return sum(self.glyph(c)[4] for c in text)

    def ink(self, text: str) -> tuple[int, int]:
        """(top, bottom) of the inked pixels relative to the baseline (y down)."""
        top, bot = 0, 0
        for c in text:
            w, h, xo, yo, dw, bits = self.glyph(c)
            if w and h:
                top = min(top, -yo - h)
                bot = max(bot, -yo)
        return top, bot

    def draw(self, cv: Canvas, x: int, baseline: int, text: str, color) -> int:
        for c in text:
            w, h, xo, yo, dw, bits = self.glyph(c)
            gx, gy = x + xo, baseline - yo - h
            for j in range(h):
                for i in range(w):
                    b = j * w + i
                    if bits[b >> 3] & (0x80 >> (b & 7)):
                        cv.blend(gx + i, gy + j, color, 1.0)
            x += dw
        return x


# ---------------------------------------------------------------------------
# Icons (drawn on a 24-unit grid, line style like common UI icon sets)
# ---------------------------------------------------------------------------

STROKE = 2.0


def icon_canvas():
    return Canvas(ICON, ICON), ICON / 24.0


def ic_line(cv, s, sdf_units, colour, alpha=1.0):
    cv.shape(scaled(sdf_units, s), rgb(colour), alpha)


def icon_folder(up: bool = False):
    cv, s = icon_canvas()
    back = sd_union(sd_rrect(2, 4.5, 11, 9, 1.6), sd_rrect(2, 6.5, 22, 20, 2))
    cv.shape(scaled(back, s), grad(rgb("folder_dark"), rgb("folder"), 0, 4 * s, 0, 20 * s))
    front = sd_rrect(2, 9, 22, 20, 2)
    cv.shape(scaled(front, s), grad(rgb("folder"), rgb("#FCD34D"), 0, 9 * s, 0, 20 * s))
    if up:
        arrow = sd_union(sd_polyline([(12, 18), (12, 11.5)], 2.2), sd_polyline([(9, 14.2), (12, 11.2), (15, 14.2)], 2.2))
        cv.shape(scaled(arrow, s), rgb("#78350F"))
    return cv


def icon_disc(tint: str | None = None):
    cv, s = icon_canvas()
    face = grad(rgb("#F2F2F3"), rgb("#CFCFD4"), 3 * s, 3 * s, 21 * s, 21 * s)
    if tint:
        t = rgb(FAMILIES[tint])
        face = grad(lerp3(t, (1, 1, 1), 0.35), t, 3 * s, 3 * s, 21 * s, 21 * s)
    cv.shape(scaled(sd_circle(12, 12, 10), s), face)
    if not tint:  # a red label ring (the accent), so ISOs stand out from grey Linux
        cv.shape(scaled(sd_ring(12, 12, 7.2, 3.2), s),
                 grad(rgb("accent_fill"), rgb("accent_deep"), 4 * s, 20 * s, 20 * s, 4 * s), 0.85)
    cv.shape(scaled(sd_ring(12, 12, 8.4, 0.6), s), (1, 1, 1), 0.45)
    shine = sd_subtract(sd_polygon([(12, 12), (3.5, 6.5), (8, 2.5)]), sd_circle(12, 12, 3.6))
    cv.shape(scaled(sd_union(shine), s), (1, 1, 1), 0.45)
    cv.shape(scaled(sd_circle(12, 12, 3.6), s), (0.97, 0.98, 0.99))
    cv.shape(scaled(sd_circle(12, 12, 1.6), s), rgb("disc_hole"))
    return cv


def icon_windows():
    cv, s = icon_canvas()
    c0, c1 = rgb("#38BDF8"), rgb("#2563EB")
    for (x, y) in ((3, 3), (12.5, 3), (3, 12.5), (12.5, 12.5)):
        cv.shape(scaled(sd_rrect(x, y, x + 8.5, y + 8.5, 1.2), s), grad(c0, c1, 3 * s, 3 * s, 21 * s, 21 * s))
    return cv


def icon_up():
    cv, s = icon_canvas()
    col = "line"
    path = sd_union(
        sd_polyline([(20, 20), (20, 13)], STROKE),
        sd_arc(16, 13, 4, 270, 360, STROKE),
        sd_polyline([(16, 9), (5, 9)], STROKE),
        sd_polyline([(9.5, 4.5), (5, 9), (9.5, 13.5)], STROKE),
    )
    ic_line(cv, s, path, col)
    return cv


def icon_info():
    cv, s = icon_canvas()
    cv.shape(scaled(sd_circle(12, 12, 10), s), grad(rgb("accent_fill"), rgb("accent_deep"), 0, 0, 24 * s, 24 * s))
    cv.shape(scaled(sd_circle(12, 7.6, 1.45), s), (1, 1, 1))
    cv.shape(scaled(sd_polyline([(12, 11), (12, 17.2)], 2.4), s), (1, 1, 1))
    return cv


def icon_help():
    cv, s = icon_canvas()
    cv.shape(scaled(sd_circle(12, 12, 10), s), grad(rgb("accent_fill"), rgb("accent_deep"), 0, 0, 24 * s, 24 * s))
    q = sd_union(sd_arc(12, 9.3, 3.1, 180, 45, 2.2), sd_polyline([(14.2, 11.5), (12, 13.2), (12, 14.4)], 2.2))
    cv.shape(scaled(q, s), (1, 1, 1))
    cv.shape(scaled(sd_circle(12, 17.6, 1.35), s), (1, 1, 1))
    return cv


SHIELD = [(12, 1.8), (20.5, 5), (20.5, 11.2), (19.4, 15.2), (16.6, 18.8), (12, 22.2),
          (7.4, 18.8), (4.6, 15.2), (3.5, 11.2), (3.5, 5)]


def shield(cv, s, check=True):
    cv.shape(scaled(sd_polygon(SHIELD), s), grad(rgb("accent_fill"), rgb("accent_deep"), 0, 0, 24 * s, 24 * s))
    cv.shape(scaled(sd_polygon([(12, 4.2), (18.4, 6.6), (18.4, 11.2), (12, 11.2)]), s), (1, 1, 1), 0.12)
    if check:
        cv.shape(scaled(sd_polyline([(8.2, 12), (11, 14.8), (16, 9.4)], 2.4), s), (1, 1, 1))


def icon_shield():
    cv, s = icon_canvas()
    shield(cv, s)
    return cv


def icon_key():
    cv, s = icon_canvas()
    col = rgb("#FBBF24")
    body = sd_union(sd_ring(7.5, 16.5, 4.2, 2.4), sd_polyline([(10.6, 13.4), (20.5, 3.5)], 2.4),
                    sd_polyline([(16.2, 7.8), (19, 10.6)], 2.4), sd_polyline([(18.6, 5.4), (21, 7.8)], 2.4))
    cv.shape(scaled(body, s), col)
    return cv


def icon_chip():
    cv, s = icon_canvas()
    col = "line"
    pins = []
    for p in (8.5, 12, 15.5):
        pins += [sd_polyline([(p, 2), (p, 5)], 1.6), sd_polyline([(p, 19), (p, 22)], 1.6),
                 sd_polyline([(2, p), (5, p)], 1.6), sd_polyline([(19, p), (22, p)], 1.6)]
    ic_line(cv, s, sd_union(*pins), col)
    cv.shape(scaled(sd_rrect(5, 5, 19, 19, 2.2), s), grad(rgb("accent_fill"), rgb("accent_deep"), 0, 0, 24 * s, 24 * s))
    cv.shape(scaled(sd_rrect(9, 9, 15, 15, 1), s), rgb("line"))
    return cv


def icon_gear():
    cv, s = icon_canvas()
    col = "line"
    teeth = []
    for k in range(8):
        a = math.radians(k * 45)
        teeth.append(sd_polyline([(12 + 7 * math.cos(a), 12 + 7 * math.sin(a)),
                                  (12 + 10 * math.cos(a), 12 + 10 * math.sin(a))], 3.2))
    ic_line(cv, s, sd_union(sd_ring(12, 12, 6.2, 2.6), *teeth), col)
    return cv


def icon_reboot():
    cv, s = icon_canvas()
    col = "line"
    ic_line(cv, s, sd_arc(12, 12.5, 8, 320, 250, STROKE), col)
    head = sd_polygon([(19.8, 3.2), (20.6, 10.6), (13.4, 8.6)])
    ic_line(cv, s, head, col)
    return cv


def icon_power():
    cv, s = icon_canvas()
    col = "eyebrow"
    ic_line(cv, s, sd_union(sd_arc(12, 13, 8.5, 300, 240, STROKE + 0.2), sd_polyline([(12, 2.5), (12, 12)], STROKE + 0.2)), col)
    return cv


def icons() -> dict[str, Canvas]:
    out = {
        "folder": icon_folder(),
        "up": icon_up(),
        "iso": icon_disc(),
        "windows": icon_windows(),
        "info": icon_info(),
        "help": icon_help(),
        "shield": icon_shield(),
        "key": icon_key(),
        "firmware": icon_chip(),
        "tool": icon_gear(),
        "reboot": icon_reboot(),
        "shutdown": icon_power(),
    }
    for fam in FAMILIES:
        out[fam] = icon_disc(fam)
    return out


# ---------------------------------------------------------------------------
# 9-slice boxes (GRUB "styled boxes": <name>_{nw,n,ne,w,c,e,sw,s,se}.png)
# ---------------------------------------------------------------------------

def nine_slice(prefix: str, pad: int, radius: float, fill, fill_alpha: float,
               edge=None, edge_alpha: float = 1.0, edge_w: float = 1.0, mid: int = 1,
               fill_paint=None) -> dict[str, Canvas]:
    """Draw a (2*pad+mid)^2 rounded box and cut it into 9 pieces. GRUB scales the
    edge and centre pieces, so they are uniform along the direction they stretch
    in (a horizontal fill gradient over `mid` pixels is stretched with them)."""
    n = 2 * pad + mid
    cv = Canvas(n, n)
    outer = sd_rrect(0, 0, n, n, radius)
    cv.shape(outer, fill_paint or fill, fill_alpha)
    if edge is not None:
        inner = sd_rrect(edge_w, edge_w, n - edge_w, n - edge_w, max(0.0, radius - edge_w))
        cv.shape(sd_subtract(outer, inner), edge, edge_alpha)
    cut = {"nw": (0, 0, pad, pad), "n": (pad, 0, mid, pad), "ne": (pad + mid, 0, pad, pad),
           "w": (0, pad, pad, mid), "c": (pad, pad, mid, mid), "e": (pad + mid, pad, pad, mid),
           "sw": (0, pad + mid, pad, pad), "s": (pad, pad + mid, mid, pad), "se": (pad + mid, pad + mid, pad, pad)}
    return {f"{prefix}_{k}.png": cv.crop(*v) for k, v in cut.items()}


def cut9(prefix: str, cv: Canvas, left: int, top: int, right: int, bottom: int) -> dict[str, Canvas]:
    """Cut a drawn box into GRUB's 9 pieces; the pads are the outer pieces' sizes."""
    mw, mh = cv.w - left - right, cv.h - top - bottom
    xs, ws = (0, left, left + mw), (left, mw, right)
    ys, hs = (0, top, top + mh), (top, mh, bottom)
    names = (("nw", "n", "ne"), ("w", "c", "e"), ("sw", "s", "se"))
    return {f"{prefix}_{names[j][i]}.png": cv.crop(xs[i], ys[j], ws[i], hs[j]) for j in range(3) for i in range(3)}


# GRUB's progress_bar is never drawn less than 28 px high, so the bar pieces
# are 28 px high with the visible 6 px line in the middle.
BAR_H, BAR_T = 28, 6


def bar_box(prefix: str, colour, alpha: float) -> dict[str, Canvas]:
    r = BAR_T / 2
    top = (BAR_H - BAR_T) // 2
    cv = Canvas(2 * 3 + 8, BAR_H)
    cv.shape(sd_rrect(0, top, cv.w, top + BAR_T, r), colour, alpha)
    return cut9(prefix, cv, 3, top + 2, 3, BAR_H - top - BAR_T + 2)


def boxes() -> dict[str, Canvas]:
    out = {}
    out.update(nine_slice("menu", PANEL_PAD, PANEL_R, rgb("panel"), 0.70, rgb("panel_edge"), 0.9))
    out.update(nine_slice("term", TERM_PAD, PANEL_R, rgb("console"), 1.0, rgb("panel_edge"), 1.0))
    # Selection: fill fades from left to right (stretched with the box).
    w = 2 * SEL_PAD + 64
    out.update(nine_slice("select", SEL_PAD, SEL_R, None, 0.42, rgb("accent"), 0.9, mid=64,
                          fill_paint=grad(rgb("accent_fill"), rgb("#B01E2E"), SEL_PAD, 0, w - SEL_PAD, 0)))
    out.update(nine_slice("sb_frame", 3, 3, rgb("#FFFFFF"), 0.07))
    out.update(nine_slice("sb_thumb", 3, 3, rgb("accent"), 0.75))
    out.update(bar_box("bar", rgb("accent"), 0.16))
    out.update(bar_box("bar_hl", rgb("accent"), 1.0))
    # Unselected entries get an invisible box with the selection's border, so
    # their text sits exactly where it is when they are selected.
    out.update(nine_slice("item", SEL_PAD, 0, rgb("#000000"), 0.0, mid=1))
    return out


# ---------------------------------------------------------------------------
# Background
# ---------------------------------------------------------------------------

BG_W, BG_H = 1920, 1080


def background() -> bytes:
    """Opaque RGB: diagonal gradient, two soft lights, faint dot pattern."""
    c0, c1, g1, g2 = rgb("bg_from"), rgb("bg_to"), rgb("glow"), rgb("glow2")
    W, H = BG_W, BG_H
    # light 1: behind the top of the menu; light 2: bottom left, fainter
    l1x, l1y, l1r, l1a = 0.62 * W, 0.30 * H, 0.55 * W, 0.34
    l2x, l2y, l2r, l2a = 0.08 * W, 1.02 * H, 0.42 * W, 0.16
    gx = [x / (W - 1) * 0.6 for x in range(W)]
    d1x = [((x + 0.5 - l1x) / l1r) ** 2 for x in range(W)]
    d2x = [((x + 0.5 - l2x) / l2r) ** 2 for x in range(W)]
    rows = []
    for y in range(H):
        ty = y / (H - 1) * 0.4
        d1y = ((y + 0.5 - l1y) / (l1r * 0.75)) ** 2
        d2y = ((y + 0.5 - l2y) / l2r) ** 2
        row = []
        for x in range(W):
            t = gx[x] + ty
            r = c0[0] + (c1[0] - c0[0]) * t
            g = c0[1] + (c1[1] - c0[1]) * t
            b = c0[2] + (c1[2] - c0[2]) * t
            q = d1x[x] + d1y
            if q < 1.0:
                a = (1.0 - q) * (1.0 - q) * l1a
                r += (g1[0] - r) * a
                g += (g1[1] - g) * a
                b += (g1[2] - b) * a
            q = d2x[x] + d2y
            if q < 1.0:
                a = (1.0 - q) * (1.0 - q) * l2a
                r += (g2[0] - r) * a
                g += (g2[1] - g) * a
                b += (g2[2] - b) * a
            row.append([r, g, b])
        rows.append(row)
    # Dot grid on the right, fading in from 55% of the width (like the banner).
    dc = rgb("dots")
    step, rad = 22, 1.6
    for cy in range(step // 2, H, step):
        for cx in range(step // 2, W, step):
            fx = (cx / W - 0.55) / 0.45
            if fx <= 0:
                continue
            fade = min(1.0, fx) * 0.55 * (1.0 - 0.5 * abs(cy / H - 0.5))
            for y in range(cy - 3, cy + 4):
                for x in range(cx - 3, cx + 4):
                    if not (0 <= x < W and 0 <= y < H):
                        continue
                    cov = 0.5 - (math.hypot(x + 0.5 - cx, y + 0.5 - cy) - rad)
                    if cov <= 0:
                        continue
                    a = min(1.0, cov) * fade
                    p = rows[y][x]
                    p[0] += (dc[0] - p[0]) * a
                    p[1] += (dc[1] - p[1]) * a
                    p[2] += (dc[2] - p[2]) * a
    raw = bytearray()
    for row in rows:
        for p in row:
            raw += bytes(max(0, min(255, int(v * 255.0 + 0.5))) for v in p)
    return png_bytes(W, H, bytes(raw), alpha=False, fast=True)


# ---------------------------------------------------------------------------
# Header, badges, footer (text drawn with the PF2 glyphs)
# ---------------------------------------------------------------------------

def logo(cv: Canvas, ox: float, oy: float, size: float) -> None:
    """The banner's USB stick with a shield, upright."""
    s = size / 24.0
    off = lambda f: (lambda x, y: f(x - ox, y - oy))  # noqa: E731
    metal = grad(rgb("#5C5C63"), rgb("#F2F2F3"), ox + 8 * s, 0, ox + 16 * s, 0)
    cv.shape(off(scaled(sd_rrect(8.6, 0.6, 15.4, 6.2, 0.8), s)), metal)
    cv.shape(off(scaled(sd_rrect(9.9, 2.2, 11.3, 3.4, 0.3), s)), rgb("#1F1F22"))
    cv.shape(off(scaled(sd_rrect(12.7, 2.2, 14.1, 3.4, 0.3), s)), rgb("#1F1F22"))
    body = grad(rgb("accent_fill"), rgb("accent_deep"), ox + 6 * s, oy + 5 * s, ox + 18 * s, oy + 24 * s)
    cv.shape(off(scaled(sd_rrect(6, 5.6, 18, 23.6, 2.6), s)), body)
    cv.shape(off(scaled(sd_rrect(7, 6.8, 8, 21.6, 0.5), s)), rgb("line"), 0.35)
    sh = [(12 + (px - 12) * 0.42, 9 + (py - 2) * 0.42) for px, py in SHIELD]
    cv.shape(off(scaled(sd_polygon(sh), s)), (1, 1, 1), 0.95)
    chk = [(12 + (px - 12) * 0.42, 9 + (py - 2) * 0.42) for px, py in [(8.2, 12), (11, 14.8), (16, 9.4)]]
    cv.shape(off(scaled(sd_polyline(chk, 1.1), s)), rgb("accent_deep"))
    cv.shape(off(scaled(sd_circle(12, 20.6, 1.0), s)), rgb("accent_deep"))


def header(f_title: PF2, f_label: PF2, version: str) -> Canvas:
    name = [("beast", "title"), ("-", "accent"), ("booter", "title")]
    ver = f"v{version}"
    tw = sum(f_title.width(t) for t, _ in name)
    w = LOGO + 16 + max(tw + 12 + f_label.width(ver), f_label.width(TAGLINE)) + 4
    h = LOGO
    cv = Canvas(w, h)
    logo(cv, 0, 0, LOGO)
    tx = LOGO + 16
    top, _ = f_title.ink("beast-booter")
    base = -top + 2                        # cap tops 2 px below the header top
    x = tx
    for t, col in name:
        x = f_title.draw(cv, x, base, t, rgb(col))
    f_label.draw(cv, x + 12, base, ver, rgb("eyebrow"))
    _, lbot = f_label.ink(TAGLINE)
    f_label.draw(cv, tx, h - 1 - lbot, TAGLINE, rgb("muted"))
    return cv


def pill(f: PF2, items: list[tuple[str, str]], height: int = 30) -> Canvas:
    pad, dot, gap, between = 14, 8, 8, 10
    widths = [pad + dot + gap + f.width(t) + pad for _, t in items]
    w = sum(widths) + between * (len(items) - 1)
    cv = Canvas(w, height)
    x = 0
    for (dk, text), pw in zip(items, widths):
        outer = sd_rrect(x + 0.5, 0.5, x + pw - 0.5, height - 0.5, height / 2 - 0.5)
        inner = sd_rrect(x + 2, 2, x + pw - 2, height - 2, height / 2 - 2)
        cv.shape(outer, rgb("pill_fill"), 0.8)
        cv.shape(sd_subtract(outer, inner), rgb("pill_edge"))
        cv.shape(sd_circle(x + pad + dot / 2, height / 2, dot / 2), rgb(dk))
        top, bot = f.ink(text)
        base = round((height - (bot - top)) / 2 - top)
        f.draw(cv, x + pad + dot + gap, base, text, rgb("pill_text"))
        x += pw + between
    return cv


def footer(f_key: PF2, f_label: PF2) -> Canvas:
    kh, kpad, kgap, tgap, group = 26, 9, 6, 9, 30
    arrow_w = 26

    def cap_w(k):
        return arrow_w if k in ("up", "down") else max(kh, f_key.width(k) + 2 * kpad)
    w = 0
    for keys, text in KEYS:
        w += sum(cap_w(k) for k in keys) + kgap * (len(keys) - 1) + tgap + f_label.width(text) + group
    w -= group
    h = kh
    cv = Canvas(w, h)
    x = 0
    ltop, lbot = f_label.ink("boot / open GRUB")
    lbase = round((h - (lbot - ltop)) / 2 - ltop)
    for keys, text in KEYS:
        for i, k in enumerate(keys):
            cw = cap_w(k)
            outer = sd_rrect(x + 0.5, 0.5, x + cw - 0.5, h - 0.5, 6)
            inner = sd_rrect(x + 1.5, 1.5, x + cw - 1.5, h - 2.5, 5)
            cv.shape(outer, rgb("pill_edge"))
            cv.shape(inner, rgb("pill_fill"))
            cx = x + cw / 2
            if k in ("up", "down"):
                d = -1 if k == "up" else 1
                cy = h / 2 - 0.5
                tri = [(cx - 5, cy - 2.5 * d), (cx + 5, cy - 2.5 * d), (cx, cy + 3.5 * d)] if d > 0 else \
                      [(cx - 5, cy + 2.5), (cx + 5, cy + 2.5), (cx, cy - 3.5)]
                cv.shape(sd_polygon(tri), rgb("pill_text"))
            else:
                top, bot = f_key.ink("E")      # one baseline for every key cap
                base = round((h - 1 - (bot - top)) / 2 - top)
                f_key.draw(cv, round(cx - f_key.width(k) / 2), base, k, rgb("pill_text"))
            x += cw + (kgap if i < len(keys) - 1 else 0)
        x += tgap
        x = f_label.draw(cv, x, lbase, text, rgb("muted"))
        x += group
    return cv


# ---------------------------------------------------------------------------
# Theme files
# ---------------------------------------------------------------------------

def theme_text(variant: str, fonts: dict[str, PF2], sizes: dict[str, tuple[int, int]]) -> str:
    """One theme file. The menu panel is a centred card, 40% of the screen
    plus a fixed part: at 1024 px it is exactly as wide as GRUB's console window
    (which GRUB never makes narrower than 80 columns) plus the console box
    border, so the console box covers the panel at every width."""
    hw, hh = sizes["header.png"]
    bw, bh = sizes[f"badge-{variant}.png"]
    fw, fh = sizes["footer.png"]
    term, small = fonts["term"], fonts["small"]
    cell = max(term.glyph(chr(c))[4] for c in range(0x20, 0x7F))
    pct = PANEL_PCT
    wpx = math.ceil(80 * cell + 2 * TERM_PAD - pct * 1024 / 100)
    half = wpx // 2
    left, right = f"{50 - pct // 2}%-{half}", f"{50 + pct // 2}%+{half}"
    width = f"{pct}%+{wpx}"
    # Vertical: header at 3%, panel below it down to 96 px above the bottom
    # (timeout bar, timeout text, key hints). At 720 px that leaves the console
    # its minimum of 24 lines; GRUB would enlarge and re-centre it otherwise.
    top = f"3%+{hh + 22}"
    height = f"97%-{hh + 22 + 96}"
    lines = [
        "# beast-booter boot menu theme. Generated by build/theme/mktheme.py - do not edit;",
        "# change the script (PALETTE) and rebuild instead. See docs/MENU.md.",
        f"# Variant: {variant}",
        'title-text: ""',
        'desktop-image: "background.png"',
        'desktop-image-scale-method: "crop"',
        'desktop-image-h-align: "center"',
        'desktop-image-v-align: "center"',
        f'desktop-color: "{hexcol("bg_from")}"',
        f'terminal-font: "{term.name}"',
        'terminal-box: "term_*.png"',
        f'terminal-left: "{50 - pct // 2}%-{half - TERM_PAD}"',
        f'terminal-top: "{top}+{TERM_PAD}"',
        f'terminal-width: "{pct}%+{wpx - 2 * TERM_PAD}"',
        f'terminal-height: "{height}-{2 * TERM_PAD}"',
        'terminal-border: "0"',
        "",
        "+ image {",
        f"  left = {left}",
        "  top = 3%",
        f"  width = {hw}",
        f"  height = {hh}",
        '  file = "header.png"',
        "}",
        "+ image {",
        f"  left = {right}-{bw}",
        f"  top = 3%+{(hh - bh) // 2}",
        f"  width = {bw}",
        f"  height = {bh}",
        f'  file = "badge-{variant}.png"',
        "}",
        "+ boot_menu {",
        f"  left = {left}",
        f"  top = {top}",
        f"  width = {width}",
        f"  height = {height}",
        f'  item_font = "{fonts["item"].name}"',
        f'  selected_item_font = "{fonts["item_sel"].name}"',
        f'  item_color = "{hexcol("item")}"',
        f'  selected_item_color = "{hexcol("item_sel")}"',
        f"  icon_width = {ICON}",
        f"  icon_height = {ICON}",
        f"  item_height = {ITEM_H}",
        "  item_padding = 6",
        "  item_icon_space = 14",
        f"  item_spacing = {ITEM_GAP}",
        '  menu_pixmap_style = "menu_*.png"',
        '  item_pixmap_style = "item_*.png"',
        '  selected_item_pixmap_style = "select_*.png"',
        "  scrollbar = true",
        "  scrollbar_width = 8",
        "  scrollbar_thumb_overlay = true",
        '  scrollbar_frame = "sb_frame_*.png"',
        '  scrollbar_thumb = "sb_thumb_*.png"',
        "  scrollbar_left_pad = 6",
        "  scrollbar_right_pad = 2",
        "}",
        "+ progress_bar {",
        '  id = "__timeout__"',
        f"  left = {left}+{PANEL_PAD}",
        "  top = 100%-94",
        f"  width = {width}-{2 * PANEL_PAD}",
        f"  height = {BAR_H}",
        "  show_text = false",
        '  bar_style = "bar_*.png"',
        '  highlight_style = "bar_hl_*.png"',
        "  highlight_overlay = true",
        "}",
        "+ label {",
        '  id = "__timeout__"',
        "  left = 0",
        "  top = 100%-66",
        "  width = 100%",
        f"  height = {small.ascent + small.descent}",
        '  align = "center"',
        f'  font = "{small.name}"',
        f'  color = "{hexcol("muted")}"',
        f'  text = "{TIMEOUT_TEXT}"',
        "}",
        "+ image {",
        f"  left = 50%-{fw // 2}",
        "  top = 100%-38",
        f"  width = {fw}",
        f"  height = {fh}",
        '  file = "footer.png"',
        "}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--font", action="append", default=[], metavar="KEY=FILE")
    a = ap.parse_args(argv)
    fonts = {}
    for spec in a.font:
        k, _, p = spec.partition("=")
        fonts[k] = PF2(p)
    need = {"item", "item_sel", "small", "term", "title", "label", "key"}
    if need - set(fonts):
        ap.error(f"missing --font for: {', '.join(sorted(need - set(fonts)))}")

    os.makedirs(os.path.join(a.out, "icons"), exist_ok=True)
    images: dict[str, Canvas] = {}
    images["header.png"] = header(fonts["title"], fonts["label"], a.version)
    images["footer.png"] = footer(fonts["key"], fonts["label"])
    for v, items in BADGES.items():
        images[f"badge-{v}.png"] = pill(fonts["label"], items)
    images.update(boxes())
    for name, cv in icons().items():
        images[f"icons/{name}.png"] = cv
    sizes = {}
    for name, cv in sorted(images.items()):
        cv.save(os.path.join(a.out, name))
        sizes[name] = (cv.w, cv.h)
    with open(os.path.join(a.out, "background.png"), "wb") as f:
        f.write(background())
    for v in BADGES:
        with open(os.path.join(a.out, f"theme-{v}.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(theme_text(v, fonts, sizes))
    with open(os.path.join(a.out, "console.cfg"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated by build/theme/mktheme.py - do not edit. Sourced by lib.cfg\n"
                "# (bb_gfx_init): console colours, which a theme file cannot set.\n"
                f'set bb_console_bg="{hexcol("console")}"\n'
                f'set bb_console_fg="{PALETTE["console_text"]}"\n')
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
