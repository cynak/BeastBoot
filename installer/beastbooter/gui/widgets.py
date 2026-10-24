"""Reusable pieces of the window, all on top of theme.py's styles.

UI text stays plain ASCII plus Latin-1 (e.g. the middle dot): some Tk builds
on X11 can't show other characters such as the ellipsis.
"""

from __future__ import annotations

import time
import tkinter as tk
import weakref
import tkinter.font as tkfont
from collections.abc import Callable
from tkinter import ttk

from . import scrollmath
from .theme import Theme

DOT = " · "  # separator in one-line summaries


class WrapLabel(ttk.Label):
    """A label that wraps its text to the width it is given (not to a fixed length).

    It always asks for the same width (`min_chars` characters) and only its
    height follows the text; otherwise the width a label gets and the way it
    wraps would feed back into each other.
    """

    def __init__(self, master, *, min_chars: int = 30, **kw):
        kw.setdefault("width", min_chars)
        super().__init__(master, **kw)
        font = self.cget("font") or "TkDefaultFont"
        try:
            f = tkfont.nametofont(str(font), root=self)
        except tk.TclError:
            f = tkfont.Font(root=self, font=font)
        self._minimum = self._wrap = f.measure("0") * min_chars
        self.configure(wraplength=self._wrap)
        # A plain Tcl binding passing just the width: a Tkinter event object
        # costs ~20 Tcl calls to build, and a resize sends hundreds of these
        self.tk.call("bind", self._w, "<Configure>", f"+{self.register(self._rewrap)} %w")

    def _rewrap(self, width) -> None:
        width = max(self._minimum // 3, int(width) - 2)
        if abs(self._wrap - width) > 3:
            self._wrap = width
            self.configure(wraplength=width)


class ScrollArea(ttk.Frame):
    """Vertical scrolling for a page that may not fit a small screen.

    The content frame (`body`) gets the full visible width and at least the
    visible height. The scrollbar appears only while the content is taller
    than the view, in a column that is reserved even while hidden, so the
    content's width never depends on whether it scrolls. Keyboard focus moving
    out of view scrolls it back; the mouse wheel scrolls the page except over
    widgets that scroll themselves (a list, a log, a drop-down), unless the page
    is already being scrolled: then it carries on (the wheel "latches" to the
    page for a moment), so a drop-down passing under the pointer doesn't stop
    the page and change its value.

    Wheel and touchpad input is collected and applied at most once per frame,
    pixel by pixel with a short ease-out (scrollmath.Smoother), and cards don't
    change their hover look while the content moves under a still pointer.
    """

    SELF_SCROLLING = ("Text", "TCombobox", "Listbox")

    def __init__(self, master, theme: Theme, *, ctx: str = "", step: int | None = None):
        super().__init__(master, style=f"{ctx}TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        # yscrollincrement 1: the view can stop at any pixel (wheel steps are done here)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0, background=theme.ctx_bg(ctx),
                                takefocus=0, yscrollincrement=1)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self._on_scrollbar, takefocus=0,
                                 style=f"{ctx}Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.gutter = self.vsb.winfo_reqwidth() + theme.px(2)
        self.columnconfigure(1, minsize=self.gutter)
        self.body = ttk.Frame(self.canvas, style=f"{ctx}TFrame")
        self._item = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self.scrolling = False
        self.notch = 2 * (step or theme.px(12))  # pixels per wheel notch
        self._pending: str | None = None
        self._size = (0, 0)  # (width, height) last given to the body and the scroll region
        self._body_size = ("", "")
        self._smooth = scrollmath.Smoother()
        self._frame_job: str | None = None
        self._settle_job: str | None = None
        self._last_frame = 0.0
        self._due = 0.0  # when the next frame should start
        self._shown = 0  # the pixel row at the top of the view, as last set here
        self._latched_until = 0.0  # wheel input over self-scrolling widgets scrolls the page until then
        self._tk_version = float(self.tk.getvar("tk_version"))
        self._ws = str(self.tk.call("tk", "windowingsystem"))
        self.tag = f"BBScroll{id(self)}"
        self.latch_tag = f"BBScrollLatch{id(self)}"  # on self-scrolling widgets, before their class
        # Every widget in the body reports here; a plain Tcl binding (no Tkinter
        # event object) keeps the hundreds of events of a resize cheap
        self.tk.call("bind", self.tag, "<Configure>", f"+{self.register(self._on_configure)} %W %w %h")
        self.bind_class(self.tag, "<FocusIn>", self._on_focus, add="+")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_class(self.tag, seq, self._on_wheel, add="+")
            self.bind_class(self.latch_tag, seq, lambda e: self._on_latched(e, self._wheel), add="+")
        try:  # Tk 9: precise touchpad deltas (macOS)
            self.bind_class(self.tag, "<TouchpadScroll>", self._on_touchpad, add="+")
            self.bind_class(self.latch_tag, "<TouchpadScroll>", lambda e: self._on_latched(e, self._touchpad),
                            add="+")
        except tk.TclError:
            pass
        self.bind("<Destroy>", self._on_destroy, add="+")
        self.track(self.canvas)

    def track(self, widget: tk.Misc | None = None) -> None:
        """Watch `widget` (default: the body) and everything in it; call again after adding widgets."""
        widget = widget or self.body
        tags = widget.bindtags()
        if self.tag not in tags:
            if widget.winfo_class() in self.SELF_SCROLLING:
                tags = (tags[0], self.latch_tag, *tags[1:])
            widget.bindtags(tags + (self.tag,))
        for child in widget.winfo_children():
            self.track(child)

    def _on_configure(self, path: str, width: str, height: str) -> None:
        if path == self.body._w:
            # The body moves on every scroll step; only a new size matters
            if (width, height) == self._body_size:
                return
            self._body_size = (width, height)
        self.schedule()

    def schedule(self) -> None:
        if self._pending is None:
            self._pending = self.after_idle(self._relayout)

    def _relayout(self) -> None:
        self._pending = None
        try:
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            if cw <= 1 or ch <= 1:
                return
            need = self.body.winfo_reqheight()
            height = max(need, ch)
            if (cw, height) != self._size:
                self._size = (cw, height)
                self.canvas.itemconfigure(self._item, width=cw, height=height)
                self.canvas.configure(scrollregion=(0, 0, cw, height))
            scrolling = need > ch
            if scrolling != self.scrolling:
                self.scrolling = scrolling
                if scrolling:
                    self.vsb.grid(row=0, column=1, sticky="ns")
                else:
                    self.vsb.grid_remove()
                    self._stop()
                    self.canvas.yview_moveto(0)
        except tk.TclError:  # being destroyed
            pass

    def see(self, w: tk.Misc) -> None:
        if not self.scrolling:
            return
        top = w.winfo_rooty() - self.body.winfo_rooty()
        bottom = top + w.winfo_height()
        view_top, view_h = self.canvas.canvasy(0), self.canvas.winfo_height()
        total = max(1, self.body.winfo_height())
        if top < view_top:
            self._stop()
            self.canvas.yview_moveto(max(0, top - 8) / total)
        elif bottom > view_top + view_h:
            self._stop()
            self.canvas.yview_moveto((bottom - view_h + 8) / total)

    def _on_focus(self, event) -> None:
        w = event.widget
        if not isinstance(w, tk.Misc) or w is self.canvas:
            return
        try:
            if str(self.tk.call("focus")) != str(w):
                # Focus moving into a widget sends FocusIn to all its containers as
                # well; scrolling to each in turn made the page jump to the end and back
                return
        except tk.TclError:
            return
        card = w
        while card is not None and card is not self.body and not isinstance(card, PickCard):
            card = card.master
        # Inside a card: show the whole card when it fits
        if isinstance(card, PickCard) and card.winfo_height() <= self.canvas.winfo_height() - 16:
            w = card
        self.see(w)

    # -- wheel, touchpad and scroll bar ----------------------------------------

    def _wheel_target_ok(self, event) -> bool:
        w = event.widget
        return self.scrolling and not (isinstance(w, tk.Misc) and w.winfo_class() in self.SELF_SCROLLING)

    def _on_wheel(self, event) -> None:
        if self._wheel_target_ok(event):
            self._wheel(event)

    def _on_touchpad(self, event) -> None:
        if self._wheel_target_ok(event):
            self._touchpad(event)

    def _on_latched(self, event, handle):
        """Wheel over a self-scrolling widget while the page is being scrolled: scroll the page."""
        if self.scrolling and time.monotonic() < self._latched_until:
            handle(event)
            return "break"  # not the widget's own wheel binding
        return None

    def _wheel(self, event) -> None:
        num = event.num if isinstance(event.num, int) else 0
        self._latch()
        self.scroll_by(scrollmath.wheel_pixels(event.delta, num, notch=self.notch, windowing=self._ws,
                                               tk_version=self._tk_version))

    def _touchpad(self, event) -> None:
        _dx, dy = scrollmath.touchpad_pixels(int(event.delta))
        if dy:
            self._latch()
            self.scroll_by(-dy, smooth=False)

    def _latch(self) -> None:
        self._latched_until = time.monotonic() + scrollmath.SETTLE_MS / 1000

    def scroll_by(self, pixels: float, *, smooth: bool = True) -> None:
        """Scroll the view (positive: down); applied on the next frame, so a burst of events costs one redraw."""
        if not pixels or not self.scrolling:
            return
        if self._frame_job is None:
            self._smooth.reset(self._top(), self._limit())
            self._due = time.perf_counter()  # the first frame: now
            self._last_frame = self._due - scrollmath.FRAME_MS / 1000
            # Once the events already queued are handled: they all go into this frame
            self._frame_job = self.after_idle(self._frame)
            self._shown = round(self._smooth.pos)
        self._smooth.add(pixels, smooth=smooth)
        self._hold_hover()

    def _top(self) -> int:
        return round(self.canvas.canvasy(0))

    def _limit(self) -> int:
        return max(0, self._size[1] - self.canvas.winfo_height())

    def _frame(self) -> None:
        self._frame_job = None
        try:
            now = time.perf_counter()
            dt = min(50.0, (now - self._last_frame) * 1000)
            self._last_frame = now
            top = self._top()
            if top != self._shown:
                # Something else moved the view meanwhile (or the content shrank): that wins
                self._smooth.reset(top, self._limit())
            self._smooth.set_limit(self._limit())
            y = round(self._smooth.step(dt, max(self.notch, self.canvas.winfo_height() // 4)))
            if y != top:
                self.canvas.yview_scroll(y - top, "units")
            self._shown = y
            if self._smooth.moving:
                # Frames start every FRAME_MS (not FRAME_MS after the last one's work);
                # when drawing is slower than that, they run back to back
                self._due += scrollmath.FRAME_MS / 1000
                delay = (self._due - time.perf_counter()) * 1000
                if delay < 1:
                    self._due, delay = time.perf_counter(), 1
                self._frame_job = self.after(int(delay), self._frame)
            else:
                self._settle()
        except tk.TclError:  # being destroyed
            pass

    def _stop(self) -> None:
        if self._frame_job is not None:
            self.after_cancel(self._frame_job)
            self._frame_job = None
            self._settle()

    def _on_scrollbar(self, *args) -> None:
        self._stop()
        self._hold_hover()
        self.canvas.yview(*args)
        self._settle()

    def _hold_hover(self) -> None:
        PickCard.hold(self)
        if self._settle_job is not None:
            self.after_cancel(self._settle_job)
            self._settle_job = None

    def _settle(self) -> None:
        if self._settle_job is not None:
            self.after_cancel(self._settle_job)
        self._settle_job = self.after(scrollmath.SETTLE_MS, self._settled)

    def _settled(self) -> None:
        self._settle_job = None
        if self._frame_job is None:
            PickCard.release(self)

    def _on_destroy(self, event) -> None:
        if event.widget is self:
            for job in (self._pending, self._frame_job, self._settle_job):
                if job is not None:
                    self.after_cancel(job)
            self._pending = self._frame_job = self._settle_job = None
            PickCard.release(self, rehover=False)


def card(master, theme: Theme, *, kind: str = "Card", ctx: str = "", padding: float = 14) -> ttk.Frame:
    """A rounded panel: kind is Card, Info, Danger or Warn."""
    return ttk.Frame(master, style=f"{kind}Panel.{ctx}TFrame", padding=theme.px(padding))


def set_text(widget: tk.Text, lines: list[tuple[str, str]], *, append_from: int = 0) -> None:
    widget.configure(state="normal")
    if append_from == 0:
        widget.delete("1.0", "end")
    for text, tag in lines[append_from:]:
        widget.insert("end", text + "\n", tag)
    widget.configure(state="disabled")
    widget.see("end")


def text_box(master, theme: Theme, *, height: int = 8, wrap: str = "word", ctx: str = "Card.",
             hscroll: bool = False) -> tuple[ttk.Frame, tk.Text]:
    """A read-only, selectable text area with themed scroll bars."""
    p = theme.p
    frame = ttk.Frame(master, style=f"{ctx}TFrame")
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)
    t = tk.Text(frame, height=height, wrap=wrap, font=theme.fonts["mono_small"], relief="flat", borderwidth=0,
                highlightthickness=1, highlightbackground=p["card_border"], highlightcolor=p["field_focus"],
                background=p["log_bg"], foreground=p["fg"], selectbackground=p["select_bg"],
                selectforeground=p["select_fg"], insertbackground=p["fg"], padx=theme.px(6), pady=theme.px(4),
                state="disabled", takefocus=1)
    t.tag_configure("warning", foreground=p["warn_text"])
    t.tag_configure("error", foreground=p["danger_text"])
    t.tag_configure("debug", foreground=p["muted"])
    t.tag_configure("head", foreground=p["fg"], font=theme.fonts["bold"])
    t.tag_configure("url", foreground=p["accent_text"])
    vsb = ttk.Scrollbar(frame, orient="vertical", command=t.yview, style=f"{ctx}Vertical.TScrollbar")
    t.configure(yscrollcommand=vsb.set)
    t.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    if hscroll:
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=t.xview, style=f"{ctx}Horizontal.TScrollbar")
        t.configure(xscrollcommand=hsb.set)
        hsb.grid(row=1, column=0, sticky="ew")
    # Read-only, but keyboard users can still select and copy
    t.bind("<1>", lambda e: t.focus_set())
    return frame, t


# ---------------------------------------------------------------------------
# Step header: (1) Drive -- (2) Options -- (3) Install
# ---------------------------------------------------------------------------


class StepHeader(ttk.Frame):
    def __init__(self, master, theme: Theme, steps: list[str], on_click: Callable[[int], None]):
        super().__init__(master)
        self.theme, self.on_click = theme, on_click
        self.badges, self.labels, self.lines = [], [], []
        px = theme.px
        for i, text in enumerate(steps):
            col = i * 3
            b = ttk.Label(self, compound="center", font=theme.fonts["eyebrow"], cursor="hand2")
            b.grid(row=0, column=col, padx=(0, px(6)))
            lbl = ttk.Label(self, text=text, style="Muted.TLabel", cursor="hand2")
            lbl.grid(row=0, column=col + 1, sticky="w")
            for w in (b, lbl):
                w.bind("<Button-1>", lambda e, i=i: self.on_click(i))
            self.badges.append(b)
            self.labels.append(lbl)
            if i < len(steps) - 1:
                line = tk.Frame(self, height=max(1, px(1.2)), background=theme.p["field_border"])
                line.grid(row=0, column=col + 2, sticky="ew", padx=px(10))
                self.columnconfigure(col + 2, weight=1, minsize=px(18))
                self.lines.append(line)

    def show(self, current: int, done: set[int]) -> None:
        p = self.theme.p
        for i, (b, lbl) in enumerate(zip(self.badges, self.labels)):
            state = "done" if i in done and i != current else "current" if i == current else "todo"
            b.configure(image=self.theme.step_badge(state), text="" if state == "done" else str(i + 1),
                        foreground="#FFFFFF" if state == "current" else p["muted"])
            lbl.configure(style="Bold.TLabel" if i == current else ("TLabel" if i in done else "Muted.TLabel"))
        for i, line in enumerate(self.lines):
            line.configure(background=p["accent"] if i < current else p["field_border"])


# ---------------------------------------------------------------------------
# Selectable cards (drives, firmware packs)
# ---------------------------------------------------------------------------


class PickCard(ttk.Frame):
    """A card that can be hovered, selected, disabled and focused; its children
    follow its state (their "Pick." styles map the background to it).

    While a ScrollArea moves its content (hold/release), cards ignore the
    pointer crossing them; afterwards only the card under the pointer is
    hovered. Restyling the cards that slide under a still pointer on every
    scroll step would cost redraws and look like flicker."""

    _holders: set[int] = set()  # ScrollAreas currently moving their content
    _hovered: weakref.WeakSet[PickCard] = weakref.WeakSet()

    @classmethod
    def hold(cls, owner: tk.Misc) -> None:
        cls._holders.add(id(owner))

    @classmethod
    def release(cls, owner: tk.Misc, *, rehover: bool = True) -> None:
        cls._holders.discard(id(owner))
        if rehover and not cls._holders:
            try:
                cls._rehover(owner)
            except tk.TclError:
                pass

    @classmethod
    def _rehover(cls, any_widget: tk.Misc) -> None:
        x, y = any_widget.winfo_pointerxy()
        w = any_widget.winfo_containing(x, y)
        while w is not None and not isinstance(w, PickCard):
            w = w.master
        for c in list(cls._hovered):
            if c is not w:
                c._hover = False
                cls._hovered.discard(c)
                if c.winfo_exists():
                    c._sync()
        if w is not None and not w._hover:
            w._enter()

    def __init__(self, master, theme: Theme, *, padding: float = 10, takefocus: bool = True):
        super().__init__(master, style="Pick.TFrame", padding=theme.px(padding) + theme.margin,
                         takefocus=takefocus)
        self.theme = theme
        self._hover = False
        self.bind("<Enter>", self._enter, add="+")
        self.bind("<Leave>", self._leave, add="+")
        self.bind("<FocusIn>", lambda e: self._sync(), add="+")
        self.bind("<FocusOut>", lambda e: self._sync(), add="+")

    def adopt(self, widget: tk.Misc) -> None:
        """Make `widget` (inside the card) follow the card's state, and pass clicks on."""
        widget.bind("<Enter>", self._enter, add="+")
        widget.bind("<Leave>", self._leave, add="+")

    def _enter(self, _e=None) -> None:
        if PickCard._holders:
            return
        self._hover = True
        PickCard._hovered.add(self)
        self._sync()

    def _leave(self, _e=None) -> None:
        if PickCard._holders:
            return

        def check():
            try:
                x, y = self.winfo_pointerxy()
                inside = (self.winfo_rootx() <= x < self.winfo_rootx() + self.winfo_width()
                          and self.winfo_rooty() <= y < self.winfo_rooty() + self.winfo_height())
            except tk.TclError:
                return
            if not inside and not PickCard._holders:
                self._hover = False
                PickCard._hovered.discard(self)
                self._sync()
        self.after_idle(check)

    def set_flags(self, *, selected: bool | None = None, disabled: bool | None = None) -> None:
        if selected is not None:
            self.state(["selected" if selected else "!selected"])
        if disabled is not None:
            self.state(["disabled" if disabled else "!disabled"])
        self._sync()

    def _sync(self) -> None:
        try:
            focused = self.focus_get() is self
        except (tk.TclError, KeyError):
            focused = False
        self.state(["active" if self._hover else "!active", "focus" if focused else "!focus"])
        selected, disabled = self.instate(["selected"]), self.instate(["disabled"])
        spec = ["user2" if selected else "!user2", "user1" if (self._hover or focused) else "!user1"]
        for w in self._descendants(self):
            if not isinstance(w, ttk.Widget):
                continue
            own = spec if isinstance(w, (ttk.Button, ttk.Checkbutton, ttk.Entry)) else \
                spec + ["disabled" if disabled else "!disabled"]
            try:
                w.state(own)
            except tk.TclError:
                pass

    @staticmethod
    def _descendants(w):
        for ch in w.winfo_children():
            yield ch
            yield from PickCard._descendants(ch)


def icon_for_bus(bus: str) -> str:
    return {"usb": "usb", "sd": "sd", "nvme": "nvme"}.get(bus, "disk" if bus in ("sata", "scsi") else "usb")


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------


class Dialog(tk.Toplevel):
    """A modal dialog: Escape and the close button cancel, focus stays inside."""

    def __init__(self, app, title: str):
        super().__init__(app.root)
        self.app = app
        self.withdraw()
        self.title(title)
        self.transient(app.root)
        self.resizable(False, False)
        self.configure(background=app.theme.p["bg"])
        self.body = ttk.Frame(self, padding=app.px(18))
        self.body.pack(fill="both", expand=True)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.bind("<Escape>", lambda e: self.on_cancel())

    def show(self, focus: tk.Widget) -> None:
        self.update_idletasks()
        root = self.app.root
        x = root.winfo_rootx() + (root.winfo_width() - self.winfo_reqwidth()) // 2
        y = root.winfo_rooty() + max(0, (root.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.app.theme.native_chrome(self)
        self.deiconify()
        self.wait_visibility()
        self.grab_set()
        focus.focus_set()

    def on_cancel(self) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()


def button_row(parent, app, buttons: list[tuple[str, object, str]], *, ctx: str = "") -> list[ttk.Button]:
    """Right-aligned buttons; Return activates the focused one."""
    row = ttk.Frame(parent, style=f"{ctx}TFrame")
    out = []
    for i, (text, cmd, style) in enumerate(buttons):
        b = ttk.Button(row, text=text, command=cmd, style=style)
        b.grid(row=0, column=i, padx=(app.px(4) if i else 0, 0))
        b.bind("<Return>", lambda e, b=b: b.invoke())
        out.append(b)
    return out
