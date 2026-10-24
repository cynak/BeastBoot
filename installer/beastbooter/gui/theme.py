"""The window's look: a dark (default) or light ttk theme built on 'clam'.

Colours follow docs/assets/BRAND.md (dark grey surfaces, one red accent: the
same palette as the boot menu and the README hero cards). Rounded cards,
buttons, fields, check boxes, the progress bar and scroll bars are ttk image
elements whose images are drawn in code at start-up (raster.py) at the
current display scaling: no image files, no third-party theme package.
Every interactive element has hover, pressed, disabled and a visible
keyboard-focus ring.

Widgets sit on one of a few backgrounds ("contexts"): the page, a card, a
selectable card (drive / firmware pack: "Pick", its colour follows its state),
a tinted notice card or the top bar. Styles exist per context (e.g.
"Muted.TLabel", "Muted.Card.TLabel", "Muted.Pick.TLabel") so that the
transparent corners of the images always blend into the right colour.
"""

from __future__ import annotations

import base64
import sys
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from . import raster
from .raster import Gradient, box

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#141415", "bar": "#1A1A1C", "card": "#1F1F22", "card_border": "#2F2F33",
        "pick_hover": "#26262A", "pick_sel": "#2A1215", "pick_sel_border": "#D62839", "pick_dis": "#19191B",
        "field": "#0F0F10", "field_border": "#3D3D42", "field_focus": "#F0505E",
        "fg": "#F2F2F3", "fg2": "#CFCFD4", "muted": "#9A9AA2", "disabled": "#5C5C63",
        "accent": "#D62839", "accent_hover": "#DD3344", "accent_pressed": "#B01E2E", "accent_fg": "#FFFFFF",
        "accent_text": "#FF8A93", "accent_hi": "#F0505E", "ring": "#FF8A93",
        "danger": "#B42318", "danger_hover": "#C6362A", "danger_pressed": "#8F1C13", "danger_text": "#FF8A80",
        "danger_bg": "#2B1311", "danger_border": "#7A1F1A",
        "ok": "#10B981", "ok_text": "#34D399", "warn": "#F59E0B", "warn_text": "#FBBF24",
        "warn_bg": "#261D0E", "warn_border": "#92400E",
        "info_bg": "#231A1C", "info_border": "#42282C",
        "btn": "#26262A", "btn_hover": "#2E2E33", "btn_pressed": "#37373C", "btn_border": "#3D3D42",
        "btn_dis": "#1C1C1F", "btn_dis_fg": "#5C5C63",
        "seg_sel": "#3A151B", "seg_sel_border": "#D62839",
        "trough": "#26262A", "thumb": "#3D3D42", "thumb_hover": "#56565D",
        "select_bg": "#7A1622", "select_fg": "#FFFFFF", "log_bg": "#0F0F10",
        "metal": "#CFCFD4", "metal_dark": "#6B6B73", "body": "#D62839", "body_dark": "#7A1622",
    },
    "light": {
        "bg": "#F5F5F6", "bar": "#FFFFFF", "card": "#FFFFFF", "card_border": "#E1E1E4",
        "pick_hover": "#FAFAFB", "pick_sel": "#FEF1F2", "pick_sel_border": "#D62839", "pick_dis": "#F5F5F6",
        "field": "#FFFFFF", "field_border": "#C6C6CC", "field_focus": "#D62839",
        "fg": "#18181B", "fg2": "#3F3F46", "muted": "#63636B", "disabled": "#A1A1AA",
        "accent": "#D62839", "accent_hover": "#B01E2E", "accent_pressed": "#951927", "accent_fg": "#FFFFFF",
        "accent_text": "#B01E2E", "accent_hi": "#F0505E", "ring": "#F0505E",
        "danger": "#B42318", "danger_hover": "#9F1F15", "danger_pressed": "#8F1C13", "danger_text": "#B42318",
        "danger_bg": "#FEF3F2", "danger_border": "#FDA29B",
        "ok": "#059669", "ok_text": "#047857", "warn": "#D97706", "warn_text": "#B45309",
        "warn_bg": "#FFFBEB", "warn_border": "#FCD34D",
        "info_bg": "#FCF4F5", "info_border": "#F3D9DC",
        "btn": "#FFFFFF", "btn_hover": "#F4F4F5", "btn_pressed": "#E6E6E9", "btn_border": "#C6C6CC",
        "btn_dis": "#F5F5F6", "btn_dis_fg": "#A1A1AA",
        "seg_sel": "#FDECEE", "seg_sel_border": "#D62839",
        "trough": "#E6E6E9", "thumb": "#C6C6CC", "thumb_hover": "#A1A1AA",
        "select_bg": "#F9D2D7", "select_fg": "#18181B", "log_bg": "#FAFAFB",
        "metal": "#D4D4D8", "metal_dark": "#71717A", "body": "#D62839", "body_dark": "#7A1622",
    },
}

# Preferred UI fonts on X11, where Tk can't ask the desktop which one it uses.
X11_UI_FONTS = ("Ubuntu Sans", "Adwaita Sans", "Cantarell", "Ubuntu", "Noto Sans", "Inter", "DejaVu Sans")
CONTEXTS = ("", "Card.", "Pick.", "Info.", "Danger.", "Bar.")
BUTTON_CONTEXTS = ("", "Card.", "Pick.", "Bar.", "Info.", "Danger.")


def photo(root: tk.Misc, canvas: raster.Canvas) -> tk.PhotoImage:
    return tk.PhotoImage(master=root, data=base64.b64encode(canvas.png()).decode("ascii"), format="png")


class Theme:
    def __init__(self, root: tk.Tk, name: str = "dark"):
        if name not in PALETTES:
            raise ValueError(f"unknown theme {name!r}")
        self.root, self.name = root, name
        self.p = PALETTES[name]
        self.ws = str(root.tk.call("tk", "windowingsystem"))
        self.images: dict[str, tk.PhotoImage] = {}  # keep references: Tk drops unreferenced images
        self.fonts = self._fonts()
        self.style = ttk.Style(root)
        self.style.theme_use("clam")
        self._build()

    # -- units -------------------------------------------------------------

    def px(self, points: float) -> int:
        return max(1, round(self.root.winfo_fpixels(f"{points}p")))

    @property
    def ring_width(self) -> int:
        return max(2, self.px(1.4))

    @property
    def margin(self) -> int:
        """Transparent space around buttons and fields, for the focus ring."""
        return self.ring_width + max(1, self.px(1))

    def img(self, key: str, make, grow: tuple[int, int, int, int] | None = None, bg: str | None = None) -> str:
        """A generated image, cached. grow=(border_x, border_y, centre_w, centre_h)
        widens the stretchable middle (see raster.expand). bg: the colour the
        image is always drawn over (its element's style background); the image
        is then made opaque (raster.flatten), which Tk draws far faster."""
        if key not in self.images:
            c = make()
            if bg:
                c = raster.flatten(c, bg)  # before expand: same pixels, far fewer to blend
            if grow:
                c = raster.expand(c, *grow)
            self.images[key] = photo(self.root, c)
        return str(self.images[key])

    def grown(self, border: int, w: int = 160, h: int = 64) -> tuple[int, int, int, int]:
        return (border, border, w, h)

    # -- fonts -------------------------------------------------------------

    def _fonts(self) -> dict[str, tkfont.Font]:
        root = self.root
        for n in ("TkDefaultFont", "TkTextFont", "TkFixedFont", "TkHeadingFont", "TkMenuFont",
                  "TkSmallCaptionFont", "TkTooltipFont", "TkCaptionFont", "TkIconFont"):
            f = tkfont.nametofont(n, root=root)
            size = int(f.cget("size"))
            if size < 0:  # pixels -> points (at 96 dpi), so that scaling applies
                f.configure(size=max(8, round(-size * 0.75)))
        base = tkfont.nametofont("TkDefaultFont", root=root)
        family = base.cget("family")
        if self.ws == "x11":
            have = {f.lower(): f for f in tkfont.families(root)}
            family = next((have[f.lower()] for f in X11_UI_FONTS if f.lower() in have), family)
        size = int(base.cget("size"))
        if self.ws != "aqua":
            size = max(size, 9) + 1  # a little larger than the classic 9 pt dialog font
        for n in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            tkfont.nametofont(n, root=root).configure(family=family, size=size)
        mono = tkfont.nametofont("TkFixedFont", root=root).cget("family")

        def f(sz: float, weight: str = "normal", fam: str = family, **kw) -> tkfont.Font:
            return tkfont.Font(root=root, family=fam, size=max(8, round(sz)), weight=weight, **kw)

        return {
            "base": base, "display": f(size * 1.9, "bold"), "title": f(size * 1.55, "bold"),
            "heading": f(size * 1.3, "bold"), "sub": f(size * 1.1, "bold"), "bold": f(size, "bold"),
            "small": f(size - 1), "eyebrow": f(size - 1, "bold"), "mono": f(size - 0.5, fam=mono),
            "mono_small": f(size - 1, fam=mono), "link": f(size, underline=True),
            "button": f(size, "bold"), "big_button": f(size * 1.08, "bold"),
        }

    # -- styles ------------------------------------------------------------

    def ctx_bg(self, ctx: str) -> str:
        p = self.p
        return {"": p["bg"], "Card.": p["card"], "Pick.": p["card"], "Info.": p["info_bg"],
                "Danger.": p["danger_bg"], "Bar.": p["bar"]}[ctx]

    def pick_map(self) -> list:
        p = self.p
        # Widgets inside a selectable card follow the card through user states,
        # set by widgets.PickCard: user2 = card selected, user1 = card hovered or focused.
        return [("disabled", p["pick_dis"]), ("user2", p["pick_sel"]), ("user1", p["pick_hover"])]

    def _build(self) -> None:
        s, p, fonts, root = self.style, self.p, self.fonts, self.root
        root.configure(background=p["bg"])
        s.configure(".", background=p["bg"], foreground=p["fg"], bordercolor=p["card_border"],
                    darkcolor=p["bg"], lightcolor=p["bg"], troughcolor=p["trough"],
                    selectbackground=p["select_bg"], selectforeground=p["select_fg"],
                    fieldbackground=p["field"], focuscolor=p["ring"], insertcolor=p["fg"],
                    arrowcolor=p["fg2"], font=fonts["base"])
        s.map(".", foreground=[("disabled", p["disabled"])], background=[])
        for cls in ("TButton", "TCheckbutton", "TRadiobutton", "TEntry", "TFrame", "TLabel", "TScrollbar",
                    "Horizontal.TScrollbar", "Vertical.TScrollbar"):
            s.map(cls, background=[], foreground=[("disabled", p["disabled"])])
        # Classic Tk widgets: Text, the combobox drop-down list, menus
        for opt, val in (("*Text.background", p["log_bg"]), ("*Text.foreground", p["fg"]),
                         ("*Text.selectBackground", p["select_bg"]), ("*Text.selectForeground", p["select_fg"]),
                         ("*Text.insertBackground", p["fg"]), ("*TCombobox*Listbox.background", p["card"]),
                         ("*TCombobox*Listbox.foreground", p["fg"]),
                         ("*TCombobox*Listbox.selectBackground", p["select_bg"]),
                         ("*TCombobox*Listbox.selectForeground", p["select_fg"]),
                         ("*Menu.background", p["card"]), ("*Menu.foreground", p["fg"])):
            root.option_add(opt, val)
        self._frames()
        self._labels()
        self._buttons()
        self._segments()
        self._checks()
        self._fields()
        self._progress()
        self._scrollbars()

    def _frames(self) -> None:
        s, p, px, m, rw = self.style, self.p, self.px, self.margin, self.ring_width
        r = px(7)
        for ctx in CONTEXTS:
            s.configure(f"{ctx}TFrame", background=self.ctx_bg(ctx))
        # Cards: rounded panels with a 1 px border
        for name, fill, border in (("Card", p["card"], p["card_border"]), ("Info", p["info_bg"], p["info_border"]),
                                   ("Danger", p["danger_bg"], p["danger_border"]),
                                   ("Warn", p["warn_bg"], p["warn_border"])):
            for ctx in ("", "Card."):
                # One element per background, so its image can be opaque
                el = f"BB{name}{ctx.rstrip('.')}.card"
                s.element_create(el, "image", self.img(f"card-{name}-{ctx}", lambda f=fill, b=border: box(r, f, border=b),
                                                       self.grown(r, 240, 120), bg=self.ctx_bg(ctx)),
                                 border=r, sticky="nsew", width=2 * r + 2, height=2 * r + 2)
                style = f"{name}Panel.{ctx}TFrame"
                s.layout(style, [("Frame.background", {"sticky": "nsew", "children": [(el, {"sticky": "nsew"})]})])
                s.configure(style, background=self.ctx_bg(ctx))

        # Selectable cards (drives, firmware packs): hover, selected, disabled, focus ring
        def pick(fill, border, ring=None, bw=1.0):
            return lambda: box(r, fill, border=border, border_width=bw, ring=ring, ring_width=rw, margin=m)

        el = "BBPick.card"
        s.element_create(
            el, "image", self.img("pick", pick(p["card"], p["card_border"]), self.grown(r + m, 240, 80), bg=p["bg"]),
            ("disabled", "focus", self.img("pick-dis-f", pick(p["pick_dis"], p["card_border"], p["ring"]), self.grown(r + m, 240, 80), bg=p["bg"])),
            ("disabled", self.img("pick-dis", pick(p["pick_dis"], p["card_border"]), self.grown(r + m, 240, 80), bg=p["bg"])),
            ("selected", "focus", self.img("pick-sel-f", pick(p["pick_sel"], p["pick_sel_border"], p["ring"], 1.5), self.grown(r + m, 240, 80), bg=p["bg"])),
            ("selected", self.img("pick-sel", pick(p["pick_sel"], p["pick_sel_border"], None, 1.5), self.grown(r + m, 240, 80), bg=p["bg"])),
            ("focus", self.img("pick-f", pick(p["pick_hover"], p["card_border"], p["ring"]), self.grown(r + m, 240, 80), bg=p["bg"])),
            ("active", self.img("pick-h", pick(p["pick_hover"], p["field_border"]), self.grown(r + m, 240, 80), bg=p["bg"])),
            border=r + m, sticky="nsew", width=2 * (r + m) + 2, height=2 * (r + m) + 2)
        s.layout("Pick.TFrame", [("Frame.background", {"sticky": "nsew", "children": [(el, {"sticky": "nsew"})]})])
        s.configure("Pick.TFrame", background=p["bg"])
        s.configure("PickInner.TFrame", background=p["card"])
        s.map("PickInner.TFrame", background=self.pick_map())

    def _labels(self) -> None:
        s, p, f = self.style, self.p, self.fonts
        variants = {
            "": (p["fg"], f["base"]), "Muted.": (p["muted"], f["base"]), "Small.": (p["muted"], f["small"]),
            "Sub.": (p["fg"], f["sub"]), "Heading.": (p["fg"], f["heading"]), "Title.": (p["fg"], f["title"]),
            "Display.": (p["fg"], f["display"]), "Bold.": (p["fg"], f["bold"]), "Body.": (p["fg2"], f["base"]),
            "Error.": (p["danger_text"], f["base"]), "ErrorBold.": (p["danger_text"], f["bold"]),
            "Warn.": (p["warn_text"], f["base"]), "Ok.": (p["ok_text"], f["base"]),
            "Mono.": (p["fg"], f["mono"]), "MonoSmall.": (p["fg2"], f["mono_small"]),
            "Link.": (p["accent_text"], f["link"]), "Eyebrow.": (p["accent_text"], f["eyebrow"]),
            "Badge.": (p["ok_text"], f["eyebrow"]),
        }
        for ctx in CONTEXTS:
            for var, (fg, font) in variants.items():
                name = f"{var}{ctx}TLabel"
                s.configure(name, background=self.ctx_bg(ctx), foreground=fg, font=font)
                if ctx == "Pick.":
                    s.map(name, background=self.pick_map(),
                          foreground=[] if var in ("Error.", "Warn.") else [("disabled", p["disabled"])])
        s.configure("Demo.Bar.TLabel", background=p["warn_bg"], foreground=p["warn_text"], font=f["eyebrow"],
                    padding=(self.px(8), self.px(3)))

    def _buttons(self) -> None:
        s, p, px, f, m, rw = self.style, self.p, self.px, self.fonts, self.margin, self.ring_width
        r = px(5)
        kinds = {
            "": (p["btn"], p["btn_hover"], p["btn_pressed"], p["btn_border"], p["fg"], p["field_border"]),
            "Accent.": (Gradient(p["accent_hover"], p["accent"]), p["accent_hover"], p["accent_pressed"],
                        p["accent"], p["accent_fg"], None),
            "Danger.": (p["danger"], p["danger_hover"], p["danger_pressed"], p["danger"], "#FFFFFF", None),
            "Ghost.": (None, p["btn_hover"], p["btn_pressed"], None, p["accent_text"], None),
        }

        def mk(fl, bd, ring=None):
            return lambda: box(r, fl, border=bd, ring=ring, ring_width=rw, margin=m)

        for kind, (fill, hover, pressed, border, fg, bhover) in kinds.items():
            key, bh = kind or "Btn.", bhover or border
            dis_border = p["card_border"] if kind in ("", "Ghost.") else p["btn_dis"]
            el = f"BB{key}border"
            s.element_create(
                el, "image", self.img(f"{key}n", mk(fill, border), self.grown(r + m, 120, 32)),
                ("disabled", self.img(f"{key}d", mk(None if kind == "Ghost." else p["btn_dis"],
                                                    None if kind == "Ghost." else dis_border), self.grown(r + m, 120, 32))),
                ("pressed", "focus", self.img(f"{key}pf", mk(pressed, bh, p["ring"]), self.grown(r + m, 120, 32))),
                ("pressed", self.img(f"{key}p", mk(pressed, bh), self.grown(r + m, 120, 32))),
                ("focus", "active", self.img(f"{key}fh", mk(hover, bh, p["ring"]), self.grown(r + m, 120, 32))),
                ("focus", self.img(f"{key}f", mk(fill, border, p["ring"]), self.grown(r + m, 120, 32))),
                ("active", self.img(f"{key}h", mk(hover, bh), self.grown(r + m, 120, 32))),
                border=r + m, sticky="nsew", width=2 * (r + m) + 2, height=2 * (r + m) + 2)
            for ctx in BUTTON_CONTEXTS:
                for size in ("", "Big."):
                    name = f"{size}{kind}{ctx}TButton"
                    s.layout(name, [("Button.background", {"sticky": "nsew", "children": [
                        (el, {"sticky": "nsew", "children": [("Button.padding", {"sticky": "nsew", "children": [
                            ("Button.label", {"sticky": "nsew"})]})]})]})])
                    big = size == "Big."
                    font = f["big_button"] if big else (f["button"] if kind in ("Accent.", "Danger.") else f["base"])
                    s.configure(name, background=self.ctx_bg(ctx), foreground=fg, anchor="center", font=font,
                                padding=(px(16 if big else 11) + m, px(7 if big else 4) + m))
                    s.map(name, foreground=[("disabled", p["btn_dis_fg"])],
                          background=self.pick_map() if ctx == "Pick." else [])

    def _segments(self) -> None:
        """Radio buttons drawn as toggle buttons (MBR | GPT, the page tabs)."""
        s, p, px, f, m, rw = self.style, self.p, self.px, self.fonts, self.margin, self.ring_width
        r = px(5)

        def mk(fl, bd, ring=None, bw=1.0):
            return lambda: box(r, fl, border=bd, border_width=bw, ring=ring, ring_width=rw, margin=m)

        for name, off, off_border, hover, sel, sel_border in (
            ("Seg", p["field"], p["btn_border"], p["btn_hover"], p["seg_sel"], p["seg_sel_border"]),
            ("Nav", None, None, p["btn_hover"], p["seg_sel"], None),
        ):
            el = f"BB{name}.border"
            s.element_create(
                el, "image", self.img(f"{name}-n", mk(off, off_border), self.grown(r + m, 80, 24)),
                ("disabled", "selected", self.img(f"{name}-ds", mk(p["btn_dis"], p["card_border"]), self.grown(r + m, 80, 24))),
                ("disabled", self.img(f"{name}-d", mk(None if off is None else p["btn_dis"],
                                                      None if off is None else p["card_border"]), self.grown(r + m, 80, 24))),
                ("selected", "focus", self.img(f"{name}-sf", mk(sel, sel_border, p["ring"], 1.5), self.grown(r + m, 80, 24))),
                ("selected", self.img(f"{name}-s", mk(sel, sel_border, None, 1.5), self.grown(r + m, 80, 24))),
                ("focus", self.img(f"{name}-f", mk(hover if off is None else off, off_border, p["ring"]), self.grown(r + m, 80, 24))),
                ("active", self.img(f"{name}-h", mk(hover, off_border), self.grown(r + m, 80, 24))),
                border=r + m, sticky="nsew", width=2 * (r + m) + 2, height=2 * (r + m) + 2)
            for ctx in ("", "Card.", "Bar."):
                style = f"{name}.{ctx}TRadiobutton"
                s.layout(style, [("Radiobutton.background", {"sticky": "nsew", "children": [
                    (el, {"sticky": "nsew", "children": [("Radiobutton.padding", {"sticky": "nsew", "children": [
                        ("Radiobutton.label", {"sticky": "nsew"})]})]})]})])
                s.configure(style, background=self.ctx_bg(ctx), foreground=p["fg2"], anchor="center",
                            font=f["base"], padding=(px(11) + m, px(4) + m))
                s.map(style, foreground=[("disabled", p["disabled"]), ("selected", p["fg"])])

    def _checks(self) -> None:
        s, p, px, m, rw = self.style, self.p, self.px, self.margin, self.ring_width
        size, r = px(11.5), px(3)

        def mk(fill, border, check=None, ring=None):
            def draw():
                c = box(r, fill, border=border, border_width=max(1.0, px(1)), ring=ring, ring_width=rw, margin=m,
                        width=size + 2 * m, height=size + 2 * m)
                if check:
                    o, k = m, size
                    pts = [(o + k * 0.26, o + k * 0.52), (o + k * 0.43, o + k * 0.69), (o + k * 0.75, o + k * 0.33)]
                    c.fill(raster.sd_polyline(pts, max(1.0, k * 0.075)), check)
                return c
            return draw

        el = "BBCheck.indicator"
        s.element_create(
            el, "image", self.img("chk", mk(p["field"], p["field_border"])),
            ("disabled", "selected", self.img("chk-ds", mk(p["btn_dis"], p["card_border"], p["disabled"]))),
            ("disabled", self.img("chk-d", mk(p["btn_dis"], p["card_border"]))),
            ("selected", "focus", self.img("chk-sf", mk(p["accent"], p["accent"], "#FFFFFF", p["ring"]))),
            ("selected", "active", self.img("chk-sh", mk(p["accent_hover"], p["accent_hover"], "#FFFFFF"))),
            ("selected", self.img("chk-s", mk(p["accent"], p["accent"], "#FFFFFF"))),
            ("focus", self.img("chk-f", mk(p["field"], p["field_focus"], None, p["ring"]))),
            ("active", self.img("chk-h", mk(p["field"], p["field_focus"]))),
            sticky="")
        for ctx in ("", "Card.", "Pick.", "Info.", "Danger."):
            name = f"{ctx}TCheckbutton"
            s.layout(name, [("Checkbutton.background", {"sticky": "nsew", "children": [
                ("Checkbutton.padding", {"sticky": "nsew", "children": [
                    (el, {"side": "left", "sticky": ""}),
                    ("Checkbutton.label", {"side": "left", "sticky": "nsew"})]})]})])
            for sub in ("", "Sub."):
                if sub:
                    s.layout(sub + name, s.layout(name))
                s.configure(sub + name, background=self.ctx_bg(ctx), foreground=p["fg"], padding=(0, 0, px(4), 0),
                            font=self.fonts["sub"] if sub else self.fonts["base"])
                s.map(sub + name, background=self.pick_map() if ctx == "Pick." else [],
                      foreground=[("disabled", p["disabled"])])

    def _fields(self) -> None:
        s, p, px, m, rw = self.style, self.p, self.px, self.margin, self.ring_width
        r = px(4.5)

        def mk(fill, border, ring=None, bw=1.0):
            return lambda: box(r, fill, border=border, border_width=bw, ring=ring, ring_width=rw, margin=m)

        el = "BBEntry.field"
        s.element_create(
            el, "image", self.img("ent", mk(p["field"], p["field_border"]), self.grown(r + m, 120, 24)),
            ("invalid", "focus", self.img("ent-if", mk(p["field"], p["danger"], p["danger_text"], 1.5), self.grown(r + m, 120, 24))),
            ("invalid", self.img("ent-i", mk(p["field"], p["danger"], None, 1.5), self.grown(r + m, 120, 24))),
            ("disabled", self.img("ent-d", mk(p["btn_dis"], p["card_border"]), self.grown(r + m, 120, 24))),
            ("focus", self.img("ent-f", mk(p["field"], p["field_focus"], p["ring"], 1.5), self.grown(r + m, 120, 24))),
            ("active", self.img("ent-h", mk(p["field"], p["field_focus"]), self.grown(r + m, 120, 24))),
            border=r + m, sticky="nsew", width=2 * (r + m) + 2, height=2 * (r + m) + 2)
        for ctx in ("", "Card."):
            name = f"{ctx}TEntry"
            s.layout(name, [("Entry.background", {"sticky": "nsew", "children": [
                (el, {"sticky": "nsew", "children": [("Entry.padding", {"sticky": "nsew", "children": [
                    ("Entry.textarea", {"sticky": "nsew"})]})]})]})])
            s.configure(name, background=self.ctx_bg(ctx), foreground=p["fg"], insertcolor=p["fg"],
                        padding=(px(7) + m, px(4) + m))
        # Read-only values that can be selected and copied (fingerprints): no frame
        for ctx in ("", "Card.", "Info."):
            name = f"Value.{ctx}TEntry"
            s.layout(name, [("Entry.background", {"sticky": "nsew", "children": [
                ("Entry.padding", {"sticky": "nsew", "children": [("Entry.textarea", {"sticky": "nsew"})]})]})])
            s.configure(name, background=self.ctx_bg(ctx), foreground=p["fg"], padding=(0, 0))
        s.configure("TCombobox", foreground=p["fg"], fieldbackground=p["field"], background=p["btn"],
                    bordercolor=p["field_border"], lightcolor=p["field"], darkcolor=p["field"],
                    arrowcolor=p["fg2"], padding=(px(6), px(4)), arrowsize=px(9))
        s.map("TCombobox", fieldbackground=[("readonly", p["field"]), ("disabled", p["btn_dis"])],
              foreground=[("disabled", p["disabled"])], bordercolor=[("focus", p["field_focus"])],
              lightcolor=[("focus", p["field_focus"])], background=[("active", p["btn_hover"])],
              selectbackground=[("readonly", p["field"])], selectforeground=[("readonly", p["fg"])])

    def _progress(self) -> None:
        s, p, px = self.style, self.p, self.px
        th = px(7)
        s.element_create("BBBar.trough", "image",
                         self.img("trough", lambda: box(th // 2, p["trough"], width=th + 240, height=th)),
                         border=(th // 2, 0), sticky="nsew", width=th + 2, height=th)
        s.element_create("BBBar.pbar", "image",
                         self.img("pbar", lambda: box(th // 2, Gradient(p["accent_hi"], p["accent"]),
                                                      width=th + 240, height=th)),
                         border=(th // 2, 0), sticky="nsew", width=th + 2, height=th)
        layout = [("Progressbar.background", {"sticky": "nsew", "children": [
            ("BBBar.trough", {"sticky": "nsew", "children": [("BBBar.pbar", {"side": "left", "sticky": "ns"})]})]})]
        for ctx in ("", "Card."):
            s.layout(f"BB.{ctx}Horizontal.TProgressbar", layout)
            s.configure(f"BB.{ctx}Horizontal.TProgressbar", background=self.ctx_bg(ctx))

    def _scrollbars(self) -> None:
        s, p, px = self.style, self.p, self.px
        w, pad = px(6), max(1, px(1.5))

        def thumb(color, vertical):
            def draw():
                length = w * 2 + 24
                c = raster.Canvas(w + 2 * pad if vertical else length, length if vertical else w + 2 * pad)
                if vertical:
                    c.fill(raster.sd_round_rect(pad, 0, pad + w, length, w / 2), color)
                else:
                    c.fill(raster.sd_round_rect(0, pad, length, pad + w, w / 2), color)
                return c
            return draw

        for orient, vertical in (("Vertical", True), ("Horizontal", False)):
            b = (0, w // 2) if vertical else (w // 2, 0)
            for ctx in ("", "Card."):
                # Per background, opaque over the trough (redrawn on every scroll step)
                el, bg, k = f"BB{orient}{ctx.rstrip('.')}.thumb", self.ctx_bg(ctx), f"thumb-{orient}-{ctx}"
                s.element_create(el, "image", self.img(k, thumb(p["thumb"], vertical), bg=bg),
                                 ("pressed", self.img(f"{k}-p", thumb(p["thumb_hover"], vertical), bg=bg)),
                                 ("active", self.img(f"{k}-h", thumb(p["thumb_hover"], vertical), bg=bg)),
                                 border=b, sticky="nsew", **({"height": w + 2} if vertical else {"width": w + 2}))
                name = f"{ctx}{orient}.TScrollbar"
                s.layout(name, [(f"{orient}.Scrollbar.trough", {"sticky": "nsew", "children": [
                    (el, {"expand": "1", "sticky": "nsew"})]})])
                s.configure(name, troughcolor=bg, background=bg, bordercolor=bg, lightcolor=bg, darkcolor=bg,
                            gripcount=0, arrowsize=w + 2 * pad)

    # -- icons -------------------------------------------------------------

    def icon(self, kind: str, points: float, *, disabled: bool = False) -> str:
        size = self.px(points)
        return self.img(f"icon-{kind}-{size}-{disabled}", lambda: draw_icon(kind, size, self.p, disabled))

    def step_badge(self, state: str) -> str:
        """The circles of the step header: 'done', 'current' or 'todo'."""
        size = self.px(17)
        return self.img(f"step-{state}-{size}", lambda: draw_step(size, state, self.p))

    def app_icons(self) -> list[tk.PhotoImage]:
        out = []
        for size in (64, 32, 16):
            key = f"appicon-{size}"
            self.img(key, lambda s=size: draw_icon("logo", s, self.p))
            out.append(self.images[key])
        return out

    # -- native window chrome ---------------------------------------------

    def native_chrome(self, window: tk.Misc) -> None:
        """A dark (or light) title bar where the OS lets an app choose. Best effort."""
        dark = self.name == "dark"
        try:
            if self.ws == "win32":
                _windows_title_bar(window, dark)
            elif self.ws == "aqua":
                window.tk.call("::tk::unsupported::MacWindowStyle", "appearance", window._w,
                               "darkaqua" if dark else "aqua")
            elif self.ws == "x11":
                _x11_theme_variant(window, dark)
        except Exception:  # noqa: BLE001 - cosmetic only
            pass


def _windows_title_bar(window: tk.Misc, dark: bool) -> None:
    import ctypes

    window.update_idletasks()
    hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
    value = ctypes.c_int(1 if dark else 0)
    for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 20H1+), and its older number
        if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
            break


def _x11_theme_variant(window: tk.Misc, dark: bool) -> None:
    """_GTK_THEME_VARIANT on the toplevel: GNOME (mutter), KDE and others then draw a matching title bar."""
    if not sys.platform.startswith(("linux", "freebsd")):
        return
    import ctypes
    import ctypes.util

    x = ctypes.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XInternAtom.restype = ctypes.c_ulong
    x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    x.XFlush.argtypes = [ctypes.c_void_p]
    x.XCloseDisplay.argtypes = [ctypes.c_void_p]
    display = x.XOpenDisplay(window.winfo_screen().encode())
    if not display:
        return
    try:
        window.update_idletasks()
        wid = int(window.wm_frame(), 16)  # the toplevel's wrapper window, which the window manager sees
        prop = x.XInternAtom(display, b"_GTK_THEME_VARIANT", 0)
        utf8 = x.XInternAtom(display, b"UTF8_STRING", 0)
        value = b"dark" if dark else b"light"
        x.XChangeProperty(display, wid, prop, utf8, 8, 0, value, len(value))  # 0: PropModeReplace
        x.XFlush(display)
    finally:
        x.XCloseDisplay(display)


# ---------------------------------------------------------------------------
# Icons (vector shapes, rasterized with anti-aliasing)
# ---------------------------------------------------------------------------


def draw_icon(kind: str, s: int, p: dict, disabled: bool = False) -> raster.Canvas:
    c = raster.Canvas(s, s)
    rr, circle, seg, poly = raster.sd_round_rect, raster.sd_circle, raster.sd_polyline, raster.sd_polygon
    alpha = 0.45 if disabled else 1.0

    def fill(sdf, color, a=1.0):
        c.fill(sdf, color, a * alpha)

    if kind in ("usb", "logo"):  # a USB stick, plug up
        fill(rr(s * 0.35, s * 0.03, s * 0.65, s * 0.34, s * 0.04), Gradient(p["metal"], p["metal_dark"]))
        fill(rr(s * 0.41, s * 0.11, s * 0.48, s * 0.19, s * 0.01), "#1F1F22")
        fill(rr(s * 0.52, s * 0.11, s * 0.59, s * 0.19, s * 0.01), "#1F1F22")
        fill(rr(s * 0.22, s * 0.30, s * 0.78, s * 0.97, s * 0.12), Gradient(p["body"], p["body_dark"], True))
        if kind == "logo":  # the hero's shield with a check mark
            shield = poly([(s * 0.5, s * 0.42), (s * 0.67, s * 0.49), (s * 0.65, s * 0.72), (s * 0.5, s * 0.86),
                           (s * 0.35, s * 0.72), (s * 0.33, s * 0.49)], s * 0.015)
            fill(shield, "#F2F2F3")
            fill(seg([(s * 0.42, s * 0.64), (s * 0.48, s * 0.71), (s * 0.59, s * 0.56)], max(0.7, s * 0.032)),
                 p["body_dark"])
        else:
            fill(rr(s * 0.34, s * 0.80, s * 0.66, s * 0.86, s * 0.03), "#F2F2F3", 0.85)
    elif kind == "sd":  # an SD card with a cut corner
        fill(poly([(s * 0.22, s * 0.05), (s * 0.62, s * 0.05), (s * 0.80, s * 0.23), (s * 0.80, s * 0.95),
                   (s * 0.22, s * 0.95)], s * 0.04), Gradient(p["body"], p["body_dark"], True))
        for i in range(4):
            x = s * (0.30 + i * 0.11)
            fill(rr(x, s * 0.12, x + s * 0.06, s * 0.30, s * 0.015), "#F2F2F3", 0.9)
    elif kind == "disk":  # an internal disk with its platter
        fill(rr(s * 0.14, s * 0.08, s * 0.86, s * 0.92, s * 0.10), Gradient(p["metal"], p["metal_dark"], True))
        fill(circle(s * 0.5, s * 0.43, s * 0.25), "#E4E4E7")
        fill(circle(s * 0.5, s * 0.43, s * 0.07), p["metal_dark"])
        fill(seg([(s * 0.5, s * 0.43), (s * 0.69, s * 0.76)], s * 0.04), "#3F3F46")
        fill(circle(s * 0.76, s * 0.83, s * 0.035), p["ok"])
    elif kind == "nvme":  # an M.2 module with chips
        fill(rr(s * 0.04, s * 0.30, s * 0.96, s * 0.70, s * 0.05), Gradient("#1F7A5C", "#0F4C3A", True))
        for i in range(3):
            x = s * (0.12 + i * 0.25)
            fill(rr(x, s * 0.38, x + s * 0.19, s * 0.62, s * 0.02), "#1F1F22")
        fill(rr(s * 0.88, s * 0.38, s * 0.96, s * 0.62, 0), "#FBBF24")
    elif kind in ("ok", "error", "warning", "info"):
        color = {"ok": p["ok"], "error": p["danger"], "warning": p["warn"], "info": p["accent"]}[kind]
        w = s * 0.085
        if kind == "warning":
            fill(poly([(s * 0.5, s * 0.08), (s * 0.95, s * 0.88), (s * 0.05, s * 0.88)], s * 0.05), color)
            fill(seg([(s * 0.5, s * 0.36), (s * 0.5, s * 0.6)], w * 0.8), "#1F1F22")
            fill(circle(s * 0.5, s * 0.74, w * 0.85), "#1F1F22")
        else:
            fill(circle(s / 2, s / 2, s * 0.46), color)
            if kind == "ok":
                fill(seg([(s * 0.29, s * 0.52), (s * 0.44, s * 0.67), (s * 0.72, s * 0.37)], w), "#FFFFFF")
            elif kind == "error":
                fill(seg([(s * 0.34, s * 0.34), (s * 0.66, s * 0.66)], w), "#FFFFFF")
                fill(seg([(s * 0.66, s * 0.34), (s * 0.34, s * 0.66)], w), "#FFFFFF")
            else:
                fill(seg([(s * 0.5, s * 0.46), (s * 0.5, s * 0.72)], w), "#FFFFFF")
                fill(circle(s * 0.5, s * 0.30, w * 1.05), "#FFFFFF")
    elif kind == "chip":  # firmware: a chip with pins
        for i in range(4):
            t = s * (0.26 + i * 0.16)
            fill(rr(s * 0.08, t, s * 0.92, t + s * 0.06, s * 0.02), p["metal_dark"])
            fill(rr(t, s * 0.08, t + s * 0.06, s * 0.92, s * 0.02), p["metal_dark"])
        fill(rr(s * 0.2, s * 0.2, s * 0.8, s * 0.8, s * 0.08), Gradient(p["body"], p["body_dark"], True))
        fill(rr(s * 0.36, s * 0.36, s * 0.64, s * 0.64, s * 0.04), "#F2F2F3", 0.9)
    elif kind == "image":  # a disk image file: a page with a folded corner
        fill(poly([(s * 0.2, s * 0.05), (s * 0.62, s * 0.05), (s * 0.82, s * 0.25), (s * 0.82, s * 0.95),
                   (s * 0.2, s * 0.95)], s * 0.03), Gradient(p["metal"], p["metal_dark"], True))
        fill(poly([(s * 0.62, s * 0.05), (s * 0.82, s * 0.25), (s * 0.62, s * 0.25)], s * 0.01), "#E4E4E7")
        fill(rr(s * 0.32, s * 0.52, s * 0.70, s * 0.80, s * 0.05), Gradient(p["body"], p["body_dark"], True))
    else:
        raise ValueError(f"unknown icon {kind!r}")
    return c


def draw_step(s: int, state: str, p: dict) -> raster.Canvas:
    c = raster.Canvas(s, s)
    r = s / 2
    ring = raster.sd_circle(r, r, r - 0.5)
    if state == "done":
        c.fill(ring, p["accent"])
        c.fill(raster.sd_polyline([(s * 0.3, s * 0.52), (s * 0.44, s * 0.66), (s * 0.7, s * 0.38)], s * 0.065),
               "#FFFFFF")
    elif state == "current":
        c.fill(ring, p["accent"])
    else:
        c.fill(lambda x, y: max(ring(x, y), -(ring(x, y) + max(1.2, s * 0.08))), p["field_border"])
    return c
