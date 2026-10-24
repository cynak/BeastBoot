"""The beast-booter window (Tkinter/ttk).

It shows the Controller's state and forwards the user's actions to it; it
makes no decisions of its own (those live in controller.py and firmware.py).

    header       logo, name, the two sections: "Make a drive" | "Firmware packs"
    Make a drive (1) Drive -> (2) Options -> (3) Install, one page per step:
                 drive cards | format options + boot files | progress, then the result
    Firmware     firmware packs for the network helper (fwpage.py)
    status bar   version, platform, privilege note

Each page scrolls when the screen is too small, with its action buttons always
visible below it. Everything is drawn in code (theme.py, raster.py): no image
files. Sizes are in points, so the window follows the system's display scaling.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..errors import BeastError
from ..fs import LABEL_MAX
from ..installed import CURRENT, NEWER, OTHER_BUILD, OUTDATED, REINSTALL
from ..interfaces import DiskInfo
from ..util import human_size
from . import distinfo
from .controller import (
    CANNOT_STOP,
    DEFAULT_IMAGE_SIZE,
    FS_TEXT,
    IMAGE_SIZES,
    LAYOUT_TEXT,
    ConfirmRequest,
    Controller,
    DriveRow,
    JobSpec,
    Options,
    Outcome,
    Phase,
    check_image_size,
    ntfs_supported,
    problem_detail,
)
from .firmware import FirmwareController, FwPhase
from .progress import ProgressState
from .theme import Theme
from .widgets import DOT, Dialog, PickCard, ScrollArea, StepHeader, WrapLabel, button_row, card, icon_for_bus, \
    set_text, text_box

POLL_MS = 100
APP_NAME = "beast-booter"
STEPS = ["Drive", "Options", "Install"]
TAGLINE = "One USB drive. Many ISOs. Secure Boot intact."
# The line on a drive card that says which beast-booter it has (installed.Freshness):
# state -> (badge style, icon). Unknown versions get the muted style and no icon.
FRESHNESS_BADGES = {
    OUTDATED: ("AccentBadge", "info"), OTHER_BUILD: ("AccentBadge", "info"), CURRENT: ("OkBadge", "ok"),
    NEWER: ("WarnBadge", "warning"), REINSTALL: ("WarnBadge", "warning"),
}


def enable_windows_dpi_awareness() -> None:
    """Without this, Windows bitmap-stretches the window at 125-200% scaling (blurry).

    "System DPI aware" (1) rather than per-monitor (2): Tk does not re-layout
    when a window moves to a monitor with another scaling, Windows then scales it.
    """
    if sys.platform != "win32":
        return
    import ctypes

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------


class ConfirmDialog(Dialog):
    """Install: a warning that names the drive's model and size; "Erase and install"
    stays disabled until "I understand all data on it will be erased" is ticked.
    Update: a plain question."""

    def __init__(self, app: App, req: ConfirmRequest, on_answer):
        super().__init__(app, req.title)
        self.req, self.on_answer = req, on_answer
        px, b = app.px, self.body
        b.columnconfigure(1, weight=1)
        ttk.Label(b, image=app.theme.icon("warning" if req.needs_ack else "info", 34)).grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(0, px(14)))
        ttk.Label(b, text=req.title, style="Title.TLabel").grid(row=0, column=1, sticky="w")
        disk = req.spec.disk
        drive = card(b, app.theme, kind="Danger" if req.needs_ack else "Card", padding=12)
        drive.grid(row=1, column=1, sticky="ew", pady=(px(10), 0))
        drive.columnconfigure(1, weight=1)
        ctx = "Danger." if req.needs_ack else "Card."
        if disk is not None:
            row = DriveRow(disk, None)
            ttk.Label(drive, image=app.theme.icon(icon_for_bus(disk.bus), 26), style=f"{ctx}TLabel").grid(
                row=0, column=0, rowspan=2, padx=(0, px(10)))
            ttk.Label(drive, text=row.title, style=f"Sub.{ctx}TLabel").grid(row=0, column=1, sticky="w")
            ttk.Label(drive, text=row.size_text, style=f"Sub.{ctx}TLabel").grid(row=0, column=2, sticky="e")
            ttk.Label(drive, text=f"{row.bus_text}{DOT}{disk.id}", style=f"Muted.{ctx}TLabel").grid(
                row=1, column=1, columnspan=2, sticky="w")
        else:
            WrapLabel(drive, text=req.drive, style=f"Bold.{ctx}TLabel", min_chars=50).grid(sticky="ew")
        for i, text in enumerate(req.details):
            WrapLabel(b, text=text, style="Body.TLabel" if i else "Bold.TLabel", min_chars=58).grid(
                row=2 + i, column=1, sticky="ew", pady=(px(8 if i else 12), 0))
        row = 2 + len(req.details)
        self.ack = tk.BooleanVar(value=False)
        first: tk.Widget
        if req.needs_ack:
            cb = ttk.Checkbutton(b, text=req.ack_text, variable=self.ack, command=self._update)
            cb.grid(row=row, column=1, sticky="w", pady=(px(14), 0))
            cb.bind("<Return>", lambda e: cb.invoke())
            first = cb
        btns = button_row(b, app, [("Cancel", self.on_cancel, "TButton"),
                                   (req.confirm_label, self._ok, "Danger.TButton" if req.needs_ack else "Accent.TButton")])
        btns[0].master.grid(row=row + 1, column=0, columnspan=2, sticky="e", pady=(px(18), 0))
        self.ok_button = btns[1]
        if not req.needs_ack:
            first = btns[1]
        self._update()
        self.show(first)

    def _update(self) -> None:
        enabled = self.ack.get() or not self.req.needs_ack
        self.ok_button.state(["!disabled"] if enabled else ["disabled"])

    def _ok(self) -> None:
        if self.req.needs_ack and not self.ack.get():
            return
        self.close()
        self.on_answer(True, self.ack.get())

    def on_cancel(self) -> None:
        self.close()
        self.on_answer(False, False)


class ImageDialog(Dialog):
    """Size (and file) for "Create image file"."""

    def __init__(self, app: App, path: str, options: Options, on_create):
        super().__init__(app, "Create an image file")
        self.on_create = on_create
        px, b = app.px, self.body
        b.columnconfigure(1, weight=1)
        self.path = tk.StringVar(value=path)
        ttk.Label(b, image=app.theme.icon("image", 30)).grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, px(12)))
        ttk.Label(b, text="Create an image file", style="Title.TLabel").grid(row=0, column=1, columnspan=2, sticky="w")
        WrapLabel(b, min_chars=52, style="Body.TLabel", text=(
            "An image file needs no administrator rights. It gets the options you chose: storage partition "
            f"{FS_TEXT.get(options.fs, options.fs)} with label {options.label}, "
            f"partition table {LAYOUT_TEXT.get(options.layout, options.layout)}."
        )).grid(row=1, column=1, columnspan=2, sticky="ew", pady=(px(6), px(12)))
        ttk.Label(b, text="File", style="Bold.TLabel").grid(row=2, column=1, columnspan=2, sticky="w")
        WrapLabel(b, textvariable=self.path, min_chars=40, style="Mono.TLabel").grid(row=3, column=1, sticky="ew")
        ttk.Button(b, text="Change...", command=self._browse).grid(row=3, column=2, padx=(px(8), 0))
        ttk.Label(b, text="Size", style="Bold.TLabel").grid(row=4, column=1, sticky="w", pady=(px(10), 0))
        self.size = tk.StringVar(value=DEFAULT_IMAGE_SIZE)
        self.size_box = ttk.Combobox(b, textvariable=self.size, values=IMAGE_SIZES, width=10)
        self.size_box.grid(row=5, column=1, sticky="w")
        self.size_box.bind("<Return>", lambda e: self._ok())
        self.msg = ttk.Label(b, text="", style="Small.TLabel")
        self.msg.grid(row=6, column=1, columnspan=2, sticky="w", pady=(px(4), 0))
        self.size.trace_add("write", lambda *a: self._validate())
        btns = button_row(b, app, [("Cancel", self.on_cancel, "TButton"), ("Create", self._ok, "Accent.TButton")])
        btns[0].master.grid(row=7, column=0, columnspan=3, sticky="e", pady=(px(16), 0))
        self.ok_button = btns[1]
        self._validate()
        self.show(self.size_box)

    def _validate(self) -> bool:
        try:
            size = check_image_size(self.size.get())
        except BeastError as e:
            self.msg.configure(text=f"{str(e)[:1].upper()}{str(e)[1:]}. Examples: 4G, 512M.", style="Error.TLabel")
            self.ok_button.state(["disabled"])
            return False
        self.msg.configure(text=f"{human_size(size)} ({size:,} bytes)", style="Small.TLabel")
        self.ok_button.state(["!disabled"])
        return True

    def _browse(self) -> None:
        path = self.app.ask_image_path(self.path.get(), parent=self)
        if path:
            self.path.set(path)

    def _ok(self) -> None:
        if self._validate():
            path, size = self.path.get(), self.size.get()
            self.close()
            self.on_create(path, size)


# ---------------------------------------------------------------------------
# Drive cards
# ---------------------------------------------------------------------------


class DriveList(ttk.Frame):
    """The drives as selectable cards. Unusable ones (system, internal, write-
    protected, too small) are greyed and can't be selected; clicking one says why.
    One card is in the Tab order; the arrow keys move between cards."""

    def __init__(self, master, app: App):
        super().__init__(master)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.cards: dict[str, PickCard] = {}
        self.version = -1
        self.compact = False

    def set_compact(self, compact: bool) -> None:
        self.compact = compact
        for c in self.cards.values():
            c.configure(padding=self.app.px(6 if compact else 9) + self.app.theme.margin)

    def rebuild(self, rows: list[DriveRow]) -> None:
        px, th = self.app.px, self.app.theme
        had_focus = any(self.focus_get() is w for w in self.cards.values()) if self.cards else False
        for w in self.winfo_children():
            w.destroy()
        self.cards = {}
        for i, row in enumerate(rows):
            c = PickCard(self, th, padding=6 if self.compact else 9)
            c.grid(row=i, column=0, sticky="ew", pady=(0, px(2)))
            c.columnconfigure(1, weight=1)
            kind = icon_for_bus(row.disk.bus)
            icon = ttk.Label(c, image=th.icon(kind, 26, disabled=not row.eligible), style="Pick.TLabel")
            icon.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, px(12)))
            title = ttk.Label(c, text=row.title, style="Sub.Pick.TLabel")
            title.grid(row=0, column=1, sticky="w")
            size = ttk.Label(c, text=row.size_text, style="Sub.Pick.TLabel")
            size.grid(row=0, column=2, sticky="e", padx=(px(10), 0))
            parts = [row.bus_text, row.id]
            if row.eligible and row.disk.mountpoints:
                parts.append("In use: " + ", ".join(row.disk.mountpoints))
            line = WrapLabel(c, text=DOT.join(parts), style="Muted.Pick.TLabel", min_chars=30)
            line.grid(row=1, column=1, sticky="ew")
            widgets = [icon, title, size, line]
            if not row.eligible:
                why = ttk.Label(c, text=f"Not usable: {row.problem}", style="Warn.Pick.TLabel")
                why.grid(row=1, column=2, sticky="e", padx=(px(10), 0))
                widgets.append(why)
            elif row.freshness is not None:  # it has beast-booter: which, and is it up to date?
                # Where "Not usable" goes on other cards, so that every card keeps the same height
                style, kind = FRESHNESS_BADGES.get(row.freshness.state, ("MutedBadge", None))
                badge = ttk.Label(c, text=" " + row.freshness.summary, style=f"{style}.Pick.TLabel",
                                  image=th.icon(kind, 11) if kind else "", compound="left")
                badge.grid(row=1, column=2, sticky="e", padx=(px(10), 0))
                widgets.append(badge)
            for w in [c, *widgets]:
                c.adopt(w)
                w.bind("<Button-1>", lambda e, d=row.id: self.click(d), add="+")
                w.bind("<Double-Button-1>", lambda e, d=row.id: self.app.next_step(), add="+")
            for key in ("<space>", "<Return>"):
                c.bind(key, lambda e, d=row.id: self.click(d))
            c.bind("<Down>", lambda e, i=i: self.move(i, 1))
            c.bind("<Up>", lambda e, i=i: self.move(i, -1))
            c.set_flags(disabled=not row.eligible)
            self.cards[row.id] = c
        self.sync()
        if had_focus:
            self.focus_card()

    def sync(self) -> None:
        sel = self.app.c.selected_id
        ids = list(self.cards)
        rover = sel if sel in self.cards else (ids[0] if ids else None)
        for did, c in self.cards.items():
            c.set_flags(selected=did == sel)
            c.configure(takefocus=1 if did == rover else 0)

    def focus_card(self) -> bool:
        for c in self.cards.values():
            if str(c.cget("takefocus")) == "1":
                c.focus_set()
                return True
        return False

    def click(self, drive_id: str) -> None:
        self.app.select_drive(drive_id)
        card = self.cards.get(drive_id)
        if card is not None:
            card.focus_set()

    def move(self, index: int, delta: int):
        ids = list(self.cards)
        j = index + delta
        if 0 <= j < len(ids):
            card = self.cards[ids[j]]
            for c in self.cards.values():
                c.configure(takefocus=0)
            card.configure(takefocus=1)
            card.focus_set()
            if self.app.c.rows and next(r for r in self.app.c.rows if r.id == ids[j]).eligible:
                self.app.select_drive(ids[j])
            else:
                self.app.explain_drive(ids[j])
        return "break"


# ---------------------------------------------------------------------------
# The main window
# ---------------------------------------------------------------------------


class App:
    def __init__(self, root: tk.Tk, controller: Controller, *, demo: bool = False, theme: str = "dark"):
        self.root, self.c, self.demo = root, controller, demo
        self.theme = Theme(root, theme)
        self.ws = self.theme.ws
        self.fonts = self.theme.fonts
        self.style = self.theme.style
        self._badge_styles()
        self.fw = FirmwareController(controller)
        title = f"{APP_NAME} {__version__}" + (" (demo)" if demo else "")
        root.title(title)
        try:
            root.iconphoto(True, *self.theme.app_icons())
        except tk.TclError:
            pass
        self.section = tk.StringVar(value="install")
        self.view = "drive"  # drive | options | run
        self.target_kind = "drive"  # drive | image
        self._drive_hint = ("", "Muted.TLabel")
        self._log_shown = 0
        self._log_owner: object = None
        self._shown_outcome: Outcome | None = None
        self._details_open = False
        self._quit_when_idle = False
        self._dialog_open = False
        self._sha256_text = "-"
        self._sha256_lines = 2
        self._stacked: bool | None = None
        self._compact = False  # a short window: less chrome, more room for the page
        self.compact_hide: list[tk.Widget] = []  # hidden in compact mode
        self.big_buttons: list[ttk.Button] = []  # normal size in compact mode
        self.page_heads: list[ttk.Frame] = []
        self._build()
        self._bind_keys()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        if self.ws == "aqua":
            root.createcommand("tk::mac::Quit", self.on_close)
        self.render()
        self._fit_to_screen()
        self.theme.native_chrome(root)
        self.drives.focus_card() or self.next_button.focus_set()
        self._after = root.after(POLL_MS, self._tick)

    # -- helpers ------------------------------------------------------------

    def _badge_styles(self) -> None:
        """Small bold text in a state colour, on a drive card (FRESHNESS_BADGES)."""
        p = self.theme.p
        for name, fg in (("AccentBadge", "accent_text"), ("OkBadge", "ok_text"), ("WarnBadge", "warn_text"),
                         ("MutedBadge", "muted")):
            style = f"{name}.Pick.TLabel"
            self.style.configure(style, background=p["card"], foreground=p[fg], font=self.fonts["eyebrow"])
            self.style.map(style, background=self.theme.pick_map())

    def px(self, points: float) -> int:
        return self.theme.px(points)

    def _fit_to_screen(self) -> None:
        """A comfortable size, never larger than the screen (125% on a 1366x768
        laptop leaves about 1050x540 points); pages scroll when they must."""
        root = self.root
        root.update_idletasks()
        max_w, max_h = int(root.winfo_screenwidth() * 0.96), int(root.winfo_screenheight() * 0.88)
        w = max(self.px(740), root.winfo_reqwidth())
        h = max(self.px(600), min(root.winfo_reqheight(), self.px(680)))
        w, h = min(w, max_w), min(h, max_h)
        root.minsize(min(w, self.px(470)), min(h, self.px(360)))
        root.geometry(f"{w}x{h}")
        self._set_compact(h < self.px(540))
        root.bind("<Configure>", self._on_resize, add="+")

    def _on_resize(self, event) -> None:
        if event.widget is self.root:
            h = event.height
            if (not self._compact and h < self.px(530)) or (self._compact and h > self.px(560)):
                self._set_compact(not self._compact)

    def _set_compact(self, compact: bool) -> None:
        """Short windows (a small screen, or large display scaling): hide the
        tagline, the status bar and secondary subtitles, tighten the spacing and
        use normal-size buttons, so the pages keep room for their content."""
        if compact == self._compact:
            return
        self._compact = compact
        px = self.px
        for w in [self.tagline, self.status_bar, *self.compact_hide]:
            if compact:
                w.grid_remove()
            else:
                w.grid()
        self.header.configure(padding=(px(18), px(5 if compact else 10), px(18), px(5 if compact else 10)))
        self.content.configure(padding=(px(18), px(6 if compact else 12), px(18), px(6 if compact else 6)))
        self.steps.grid_configure(pady=(0, px(6 if compact else 12)))
        for head in self.page_heads:
            head.grid_configure(pady=(0, px(5 if compact else 10)))
        for b in self.big_buttons:
            style = str(b.cget("style"))
            b.configure(style=style.replace("Big.", "") if compact else ("Big." + style.replace("Big.", "")))
        self.drives.set_compact(compact)
        self.render()

    # -- building -----------------------------------------------------------

    def _build(self) -> None:
        root, px, th = self.root, self.px, self.theme
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        bar = self.header = ttk.Frame(root, style="Bar.TFrame", padding=(px(18), px(10), px(18), px(10)))
        bar.grid(row=0, column=0, sticky="ew")
        bar.columnconfigure(1, weight=1)
        ttk.Label(bar, image=th.icon("logo", 30), style="Bar.TLabel").grid(row=0, column=0, rowspan=2,
                                                                         padx=(0, px(10)))
        ttk.Label(bar, text=APP_NAME, style="Title.Bar.TLabel").grid(row=0, column=1, sticky="sw")
        self.tagline = WrapLabel(bar, text=TAGLINE, style="Muted.Bar.TLabel", min_chars=18)
        self.tagline.grid(row=1, column=1, sticky="new")
        nav = ttk.Frame(bar, style="Bar.TFrame")
        nav.grid(row=0, column=2, rowspan=2, sticky="e", padx=(px(12), 0))
        self.nav_buttons = {}
        for i, (value, text) in enumerate((("install", "Make a drive"), ("firmware", "Firmware packs"))):
            b = ttk.Radiobutton(nav, text=text, value=value, variable=self.section, style="Nav.Bar.TRadiobutton",
                                command=self._on_section)
            b.grid(row=0, column=i, padx=(px(2) if i else 0, 0))
            self.nav_buttons[value] = b
        if self.demo:
            ttk.Label(bar, text="DEMO: simulated drives, nothing is written", style="Demo.Bar.TLabel").grid(
                row=0, column=3, rowspan=2, sticky="e", padx=(px(12), 0))
        tk.Frame(root, height=1, background=th.p["card_border"]).grid(row=1, column=0, sticky="ew")

        content = self.content = ttk.Frame(root, padding=(px(18), px(12), px(18), px(6)))
        content.grid(row=2, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)

        flow = self.flow = ttk.Frame(content)
        flow.columnconfigure(0, weight=1)
        flow.rowconfigure(1, weight=1)
        self.steps = StepHeader(flow, th, STEPS, self._on_step_click)
        self.steps.grid(row=0, column=0, sticky="ew", pady=(0, px(12)))
        self.pages = ttk.Frame(flow)
        self.pages.grid(row=1, column=0, sticky="nsew")
        self.pages.columnconfigure(0, weight=1)
        self.pages.rowconfigure(0, weight=1)
        self.drive_page = self._build_drive_page(self.pages)
        self.options_page = self._build_options_page(self.pages)
        self.run_page = self._build_run_page(self.pages)

        from .fwpage import FirmwarePage

        self.fw_page = FirmwarePage(content, self)

        self.status_bar = WrapLabel(root, style="Small.TLabel", min_chars=40, padding=(px(18), px(2), px(18), px(8)))
        self.status_bar.grid(row=3, column=0, sticky="ew")

    def _page(self, parent) -> tuple[ttk.Frame, ttk.Frame, ScrollArea, ttk.Frame]:
        """A page: a fixed head, a scrolling body, a fixed action bar."""
        px = self.px
        page = ttk.Frame(parent)
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        head = ttk.Frame(page)
        head.grid(row=0, column=0, sticky="ew", pady=(0, px(10)))
        head.columnconfigure(0, weight=1)
        self.page_heads.append(head)
        scroll = ScrollArea(page, self.theme)
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.body.columnconfigure(0, weight=1)
        bar = ttk.Frame(page)
        bar.grid(row=3, column=0, sticky="ew", pady=(px(10), 0))
        bar.columnconfigure(1, weight=1)
        return page, head, scroll, bar

    def _build_drive_page(self, parent) -> ttk.Frame:
        px = self.px
        page, head, scroll, bar = self._page(parent)
        self.drive_scroll = scroll
        ttk.Label(head, text="Choose the USB drive", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        sub = WrapLabel(head, style="Muted.TLabel", min_chars=40,
                        text="Everything on it will be erased. Then copy ISO files onto it and boot any of them.")
        sub.grid(row=1, column=0, sticky="ew")
        self.compact_hide.append(sub)
        # A short window has no room for the notice card above the list: one line here instead
        self.head_notice = WrapLabel(head, style="Eyebrow.TLabel", min_chars=40, cursor="hand2",
                                     image=self.theme.icon("info", 13), compound="left")
        self.head_notice.grid(row=1, column=0, sticky="ew")
        self.head_notice.grid_remove()
        self.head_notice.bind("<Button-1>", lambda e: self._select_notice_drive())
        ttk.Button(head, text="Refresh", underline=0, command=self.refresh).grid(row=0, column=1, rowspan=2,
                                                                               sticky="e", padx=(px(10), 0))
        self.drives = DriveList(scroll.body, self)
        self.drives.grid(row=1, column=0, sticky="ew")
        # Listed drives with older boot files (shown by _render_drives; above the list, created
        # after it so that Tab still starts at the drive cards)
        notice = self.notice = card(scroll.body, self.theme, kind="Info", padding=12)
        notice.columnconfigure(1, weight=1)
        ttk.Label(notice, image=self.theme.icon("info", 22), style="Info.TLabel").grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(0, px(10)))
        self.notice_title = ttk.Label(notice, style="Sub.Info.TLabel")
        self.notice_title.grid(row=0, column=1, sticky="w")
        self.notice_text = WrapLabel(notice, style="Body.Info.TLabel", min_chars=30)
        self.notice_text.grid(row=1, column=1, sticky="ew")
        self.notice_button = ttk.Button(notice, text="Select it", style="Info.TButton",
                                        command=self._select_notice_drive)
        self.notice_button.grid(row=0, column=2, rowspan=2, sticky="e", padx=(px(10), 0))
        self.notice_button.bind("<Return>", lambda e: self.notice_button.invoke())
        self.drive_empty = card(scroll.body, self.theme, kind="Info", padding=16)
        self.drive_empty.columnconfigure(1, weight=1)
        ttk.Label(self.drive_empty, image=self.theme.icon("usb", 30), style="Info.TLabel").grid(
            row=0, column=0, rowspan=2, padx=(0, px(12)))
        self.drive_empty_title = ttk.Label(self.drive_empty, style="Sub.Info.TLabel")
        self.drive_empty_title.grid(row=0, column=1, sticky="w")
        self.drive_empty_text = WrapLabel(self.drive_empty, style="Body.Info.TLabel", min_chars=40)
        self.drive_empty_text.grid(row=1, column=1, sticky="ew")

        below = ttk.Frame(page)
        below.grid(row=2, column=0, sticky="ew", pady=(px(8), 0))
        below.lower(bar)  # Tab order: the list, "Show all disks", then the action buttons
        below.columnconfigure(1, weight=1)
        self.show_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(below, text="Show all disks", variable=self.show_all, underline=5,
                        command=lambda: self._act(self.c.set_show_all, self.show_all.get())).grid(row=0, column=0,
                                                                                                  sticky="nw")
        self.drive_hint = WrapLabel(below, style="Muted.TLabel", min_chars=30)
        self.drive_hint.grid(row=0, column=1, sticky="ew", padx=(px(12), 0))

        self.image_button = ttk.Button(bar, text="Make an image file instead", style="Ghost.TButton",
                                       command=lambda: self.next_step("image"))
        self.image_button.grid(row=0, column=0, sticky="w")
        self.update_button = ttk.Button(bar, text="Update boot files...", underline=0, command=self.update)
        self.update_button.grid(row=0, column=2, sticky="e", padx=(0, px(4)))
        self.next_button = ttk.Button(bar, text="Next: options", underline=0, style="Big.Accent.TButton",
                                      command=self.next_step)
        self.next_button.grid(row=0, column=3, sticky="e")
        for b in (self.update_button, self.next_button, self.image_button):
            b.bind("<Return>", lambda e, b=b: b.invoke())
        scroll.track()  # (Next and Update: their size and style follow the drive, see _render_drives)
        return page

    def _build_options_page(self, parent) -> ttk.Frame:
        px, th = self.px, self.theme
        page, head, scroll, bar = self._page(parent)
        self.options_scroll = scroll
        ttk.Label(head, text="Options", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        self.options_target = WrapLabel(head, style="Muted.TLabel", min_chars=40)
        self.options_target.grid(row=1, column=0, sticky="ew")
        body = self.options_body = scroll.body
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        # Format of the storage partition
        fmt = self.fmt_card = card(body, th)
        fmt.columnconfigure(0, weight=1)
        ttk.Label(fmt, text="STORAGE PARTITION", style="Eyebrow.Card.TLabel").grid(row=0, column=0, sticky="w")
        self.layout = tk.StringVar(value=self.c.options.layout)
        self.fs = tk.StringVar(value=self.c.options.fs)
        self.label = tk.StringVar(value=self.c.options.label)
        r = 1
        ttk.Label(fmt, text="Partition table", style="Bold.Card.TLabel").grid(row=r, column=0, sticky="w",
                                                                              pady=(px(8), px(3)))
        lay = self.layout_row = ttk.Frame(fmt, style="Card.TFrame")
        lay.grid(row=r + 1, column=0, sticky="w")
        for i, (value, text) in enumerate((("msdos", "MBR (recommended)"), ("gpt", "GPT"))):
            ttk.Radiobutton(lay, text=text, value=value, variable=self.layout, style="Seg.Card.TRadiobutton",
                            command=lambda: self._set_option("layout", self.layout.get())).grid(row=0, column=i)
        self.layout_note = WrapLabel(fmt, style="Small.Card.TLabel", min_chars=34)
        self.layout_note.grid(row=r + 2, column=0, sticky="ew", pady=(px(3), 0))
        r += 3
        ttk.Label(fmt, text="File system", style="Bold.Card.TLabel").grid(row=r, column=0, sticky="w",
                                                                          pady=(px(10), px(3)))
        fsrow = self.fs_row = ttk.Frame(fmt, style="Card.TFrame")
        fsrow.grid(row=r + 1, column=0, sticky="w")
        self.fs_buttons = {}
        for i, (value, text) in enumerate((("exfat", "exFAT (recommended)"), ("fat32", "FAT32"), ("ntfs", "NTFS"))):
            rb = ttk.Radiobutton(fsrow, text=text, value=value, variable=self.fs, style="Seg.Card.TRadiobutton",
                                 command=lambda: self._set_option("fs", self.fs.get()))
            rb.grid(row=0, column=i)
            self.fs_buttons[value] = rb
        self.fs_note = WrapLabel(fmt, style="Small.Card.TLabel", min_chars=34)
        self.fs_note.grid(row=r + 2, column=0, sticky="ew", pady=(px(3), 0))
        r += 3
        ttk.Label(fmt, text="Volume label", style="Bold.Card.TLabel").grid(row=r, column=0, sticky="w",
                                                                           pady=(px(10), px(3)))
        lrow = ttk.Frame(fmt, style="Card.TFrame")
        lrow.grid(row=r + 1, column=0, sticky="w")
        self.label_entry = ttk.Entry(lrow, textvariable=self.label, width=18, style="Card.TEntry",
                                     font=self.fonts["base"])
        self.label_entry.grid(row=0, column=0, sticky="w")
        self.label_count = ttk.Label(lrow, style="Small.Card.TLabel")
        self.label_count.grid(row=0, column=1, sticky="w", padx=(px(8), 0))
        self.label.trace_add("write", lambda *a: self._set_option("label", self.label.get()))
        self.label_note = WrapLabel(fmt, style="Small.Card.TLabel", min_chars=34)
        self.label_note.grid(row=r + 2, column=0, sticky="ew", pady=(px(3), 0))

        # Boot files
        bf = self.bf_card = card(body, th)
        bf.columnconfigure(1, weight=1)
        ttk.Label(bf, text="BOOT FILES", style="Eyebrow.Card.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        self.dist_rows = {}
        self.bf_labels = []
        for i, (key, text) in enumerate((("version", "Version"), ("location", "Location"),
                                         ("subject", "Secure Boot key"))):
            lbl = ttk.Label(bf, text=text, style="Muted.Card.TLabel")
            lbl.grid(row=i + 1, column=0, sticky="nw", padx=(0, px(10)), pady=(px(6 if i == 0 else 3), 0))
            self.bf_labels.append(lbl)
            value = WrapLabel(bf, min_chars=26, style="Card.TLabel")
            value.grid(row=i + 1, column=1, sticky="ew", pady=(px(6 if i == 0 else 3), 0))
            self.dist_rows[key] = value
        # Key fingerprints: SHA-1 in two rows of 10 pairs, exactly as MokManager's
        # "View key" shows it; SHA-256 in 2 rows, or 4 when the card is narrow.
        mono = self.fonts["mono_small"]
        self.fp_vars = {k: tk.StringVar() for k in ("sha1a", "sha1b")}
        sha1_label = ttk.Label(bf, text="SHA-1", style="Muted.Card.TLabel")
        sha1_label.grid(row=4, column=0, sticky="nw", padx=(0, px(10)), pady=(px(6), 0))
        sha1_box = ttk.Frame(bf, style="Card.TFrame")
        sha1_box.grid(row=4, column=1, sticky="w", pady=(px(6), 0))
        for j, k in enumerate(("sha1a", "sha1b")):
            e = ttk.Entry(sha1_box, textvariable=self.fp_vars[k], state="readonly", width=30,
                          style="Value.Card.TEntry", takefocus=False, font=mono)
            e.grid(row=j, column=0, sticky="w")
        self._entry_pad = e.winfo_reqwidth() - 30 * mono.measure("0")
        sha256_label = ttk.Label(bf, text="SHA-256", style="Muted.Card.TLabel")
        sha256_label.grid(row=5, column=0, sticky="nw", padx=(0, px(10)), pady=(px(4), 0))
        self.sha256_box = ttk.Frame(bf, style="Card.TFrame")
        self.sha256_box.grid(row=5, column=1, sticky="ew", pady=(px(4), 0))
        self.sha256_box.columnconfigure(0, weight=1)
        self.sha256_vars = [tk.StringVar() for _ in range(4)]
        self.sha256_entries = [
            ttk.Entry(self.sha256_box, textvariable=v, state="readonly", width=24, style="Value.Card.TEntry",
                      takefocus=False, font=mono)
            for v in self.sha256_vars
        ]
        self.sha256_box.bind("<Configure>", self._fit_sha256, add="+")
        self._show_sha256()
        self.bf_labels += [sha1_label, sha256_label]
        verify_row = ttk.Frame(bf, style="Card.TFrame")
        verify_row.grid(row=6, column=0, columnspan=2, sticky="w", pady=(px(10), 0))
        self.verify_button = ttk.Button(verify_row, text="Verify boot files", underline=0, style="Card.TButton",
                                        command=self.verify)
        self.verify_button.grid(row=0, column=0, sticky="w")
        self.verify_msg = WrapLabel(bf, style="Small.Card.TLabel", min_chars=26)
        self.verify_msg.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
        self.dist_warn = WrapLabel(bf, style="Warn.Card.TLabel", min_chars=26)
        self.dist_warn.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
        body.bind("<Configure>", self._arrange_options, add="+")
        self._arrange_options()

        back = ttk.Button(bar, text="Back", underline=0, command=self.back)
        back.grid(row=0, column=0, sticky="w")
        self.action_hint = WrapLabel(bar, style="Muted.TLabel", anchor="e", justify="right", min_chars=16)
        self.action_hint.grid(row=0, column=1, sticky="ew", padx=px(10))
        self.install_button = ttk.Button(bar, text="Install...", underline=0, style="Big.Accent.TButton",
                                         command=self.primary_action)
        self.install_button.grid(row=0, column=2, sticky="e")
        for b in (back, self.install_button):
            b.bind("<Return>", lambda e, b=b: b.invoke())
        self.big_buttons.append(self.install_button)
        scroll.track()
        return page

    def _arrange_options(self, _event=None) -> None:
        """Side by side when the page is wide enough, else one above the other."""
        width = self.options_body.winfo_width()
        need = self.fmt_card.winfo_reqwidth() + self.bf_card.winfo_reqwidth() + self.px(12)
        stacked = width > 1 and width < need
        if stacked == self._stacked:
            return
        self._stacked = stacked
        gap = self.px(12)
        if stacked:
            self.fmt_card.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=0, pady=(0, gap))
            self.bf_card.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=0, pady=0)
        else:
            self.fmt_card.grid(row=0, column=0, columnspan=1, sticky="nsew", padx=(0, gap // 2), pady=0)
            self.bf_card.grid(row=0, column=1, columnspan=1, sticky="nsew", padx=(gap // 2, 0), pady=0)

    def _build_run_page(self, parent) -> ttk.Frame:
        px, th = self.px, self.theme
        page, head, scroll, bar = self._page(parent)
        self.run_scroll = scroll
        head.columnconfigure(0, weight=0)
        head.columnconfigure(1, weight=1)
        self.status_icon = ttk.Label(head)
        self.status_icon.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, px(12)))
        self.status_title = ttk.Label(head, style="Title.TLabel")
        self.status_title.grid(row=0, column=1, sticky="w")
        self.status_target = WrapLabel(head, style="Muted.TLabel", min_chars=40)
        self.status_target.grid(row=1, column=1, sticky="ew")
        body = scroll.body
        body.rowconfigure(2, weight=1)

        # Progress (while running)
        box = self.progress_box = card(body, th, padding=16)
        box.columnconfigure(0, weight=1)
        self.step_label = WrapLabel(box, style="Sub.Card.TLabel", min_chars=40)
        self.step_label.grid(row=0, column=0, sticky="ew")
        self.pct_label = ttk.Label(box, style="Sub.Card.TLabel", width=5, anchor="e")
        self.pct_label.grid(row=0, column=1, sticky="e", padx=(px(8), 0))
        self.bar = ttk.Progressbar(box, orient="horizontal", mode="determinate", maximum=100,
                                   style="BB.Card.Horizontal.TProgressbar")
        self.bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(10), 0))
        self.progress_note = WrapLabel(box, style="Warn.Card.TLabel", min_chars=40)
        self.progress_note.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(px(8), 0))

        # Result (after running): rebuilt for each outcome
        self.result_box = ttk.Frame(body)
        self.result_box.columnconfigure(0, weight=1)

        # The details log (shared by both), collapsible
        self.log_frame, self.log = text_box(body, th, height=9, ctx="")

        self.details_button = ttk.Button(bar, text="Show details", underline=5, style="Ghost.TButton",
                                         command=self.toggle_details)
        self.details_button.grid(row=0, column=0, sticky="w")
        buttons = ttk.Frame(bar)
        buttons.grid(row=0, column=2, sticky="e")
        self.cancel_button = ttk.Button(buttons, text="Cancel", command=self.cancel)
        self.done_button = ttk.Button(buttons, text="Done", style="Big.Accent.TButton", command=self.dismiss)
        for b in (self.cancel_button, self.done_button, self.details_button):
            b.bind("<Return>", lambda e, b=b: b.invoke())
        self.big_buttons.append(self.done_button)
        scroll.track()
        return page

    def _bind_keys(self) -> None:
        r = self.root
        r.bind("<F5>", lambda e: self.refresh())

        def when_idle(fn):
            def handler(_event):
                if self.c.phase is Phase.IDLE and not self._dialog_open and self.section.get() == "install":
                    fn()
                return "break"
            return handler

        for key, fn in (("r", self.refresh), ("n", self.next_step), ("b", self.back), ("i", self.primary_action),
                        ("u", self.update), ("v", self.verify),
                        ("a", lambda: (self.show_all.set(not self.show_all.get()),
                                       self._act(self.c.set_show_all, self.show_all.get())))):
            r.bind(f"<Alt-{key}>", when_idle(fn))

        def details(_event):
            if self.c.phase is not Phase.IDLE and self.section.get() == "install":
                self.toggle_details()
            return "break"

        r.bind("<Alt-d>", details)

    # -- actions ------------------------------------------------------------

    def _act(self, fn, *args):
        """Run a controller action; show a BeastError as a message box."""
        try:
            return fn(*args)
        except BeastError as e:
            messagebox.showerror(APP_NAME, str(e), parent=self.root)
            return None
        finally:
            self.render()

    def _on_section(self) -> None:
        if self.c.phase is Phase.RUNNING or self.fw.phase is FwPhase.RUNNING:
            self.section.set("install" if self.c.phase is Phase.RUNNING else "firmware")
        self.render()
        if self.section.get() == "firmware":
            self.fw_page.focus_first()

    def _on_step_click(self, index: int) -> None:
        if self.c.phase is not Phase.IDLE or self._dialog_open:
            return
        if index == 0:
            self.back()
        elif index == 1:
            self.next_step(self.target_kind)

    def refresh(self) -> None:
        if self.c.phase is Phase.IDLE:
            self._drive_hint = ("", "Muted.TLabel")
            self._act(self.c.refresh_drives)

    def select_drive(self, drive_id: str) -> None:
        if self.c.phase is not Phase.IDLE:
            return
        problem = self.c.select_drive(drive_id)
        if problem:
            self.explain_drive(drive_id)
        else:
            self._drive_hint = ("", "Muted.TLabel")
        self.render()

    def _select_notice_drive(self) -> None:
        n = self.c.update_notice
        if n is not None and n.drive_id:
            self.select_drive(n.drive_id)
            card = self.drives.cards.get(n.drive_id)
            if card is not None:
                card.focus_set()

    def explain_drive(self, drive_id: str) -> None:
        row = next((r for r in self.c.rows if r.id == drive_id), None)
        if row is not None and row.problem:
            self._drive_hint = (f"Can't use {row.title}: {problem_detail(row.problem)}", "Warn.TLabel")
            self.render()

    def next_step(self, kind: str = "drive") -> None:
        """Drive page -> options, for the selected drive or for an image file."""
        if self.c.phase is not Phase.IDLE:
            return
        if kind == "drive" and self.c.selected_row is None:
            self._drive_hint = ("Select the USB drive to use first.", "Warn.TLabel")
            self.render()
            return
        self.target_kind, self.view = kind, "options"
        self.render()
        self.install_button.focus_set()

    def back(self) -> None:
        if self.c.phase is Phase.IDLE:
            self.view = "drive"
            self.render()
            self.drives.focus_card() or self.next_button.focus_set()

    def _set_option(self, name: str, value: str) -> None:
        if self.c.phase is Phase.IDLE:
            self.c.set_option(name, value)
            self.render()

    def verify(self) -> None:
        self._act(self.c.verify_dist)

    def primary_action(self) -> None:
        if self.view != "options":
            return
        if self.target_kind == "image":
            self.create_image()
        else:
            self.install()

    def install(self) -> None:
        if self.c.install_blocker() is not None:
            return
        req = self._act(self.c.request_install)
        if req:
            self._open_confirm(req)

    def update(self) -> None:
        if self.c.update_blocker() is not None:
            return
        req = self._act(self.c.request_update)
        if req:
            self._open_confirm(req)

    def _open_confirm(self, req: ConfirmRequest) -> None:
        self._dialog_open = True

        def answer(ok: bool, ack: bool) -> None:
            self._dialog_open = False
            if not ok:
                self._act(self.c.cancel_confirm)
                return
            self.root.configure(cursor="watch")
            self.root.update_idletasks()
            try:
                self._act(self.c.confirm, ack)  # re-checks the drive, then starts the CLI
            finally:
                self.root.configure(cursor="")

        ConfirmDialog(self, req, answer)

    def ask_image_path(self, current: str = "", parent=None) -> str:
        initial_dir = os.path.dirname(current) if current else os.path.expanduser("~")
        return filedialog.asksaveasfilename(
            parent=parent or self.root, title="Save the beast-booter image as",
            initialdir=initial_dir, initialfile=os.path.basename(current) or "beast-booter.img",
            defaultextension=".img", filetypes=[("Disk images", "*.img"), ("All files", "*")],
        ) or ""

    def create_image(self) -> None:
        if self.c.image_blocker() is not None:
            return
        path = self.ask_image_path()
        if not path:
            return
        self._dialog_open = True

        def create(p: str, size: str) -> None:
            self._dialog_open = False
            self._act(self.c.start_image, p, size)

        dlg = ImageDialog(self, path, Options(self.c.options.layout, self.c.options.fs,
                                              self.c.options_check.label or self.c.options.label), create)
        dlg.bind("<Destroy>", lambda e: setattr(self, "_dialog_open", False) if e.widget is dlg else None, add="+")

    def cancel(self) -> None:
        c = self.c
        if c.phase is not Phase.RUNNING or c.cancel_requested:
            return
        if not c.can_cancel:
            messagebox.showinfo("The installer can't be stopped", CANNOT_STOP, parent=self.root)
            return
        when = "\n\nIt stops after the step it is working on." if c.job is not None and c.job.elevated else ""
        if messagebox.askyesno("Stop the installer?", "Stop now?\n\n" + c.cancel_warning() + when,
                               icon="warning", default="no", parent=self.root) and c.phase is Phase.RUNNING:
            self._act(c.cancel)

    def dismiss(self) -> None:
        if self.c.phase in (Phase.DONE, Phase.FAILED):
            self.view = "drive"
            self._act(self.c.dismiss)

    def toggle_details(self) -> None:
        self._details_open = not self._details_open
        self._render_details()

    def on_close(self) -> None:
        running = self.c.phase is Phase.RUNNING
        if self.fw.phase is FwPhase.RUNNING and not running:
            if not messagebox.askyesno("Close the window?", "beast-booter is still working on the firmware packs. "
                                       "Close the window anyway?", icon="warning", default="no", parent=self.root):
                return
            self.fw.shutdown()
            self.quit()
            return
        if running and not self.c.can_cancel:
            if messagebox.askyesno(
                "Close the window?",
                CANNOT_STOP + "\n\nIf you close this window, the installer keeps running and finishes "
                "on its own, but you won't see whether it worked.\n\nClose the window anyway?",
                icon="warning", default="no", parent=self.root,
            ):
                self.quit()
            return
        if running:
            if self.c.cancel_requested:
                return
            if not messagebox.askyesno(
                "Stop the installer and quit?",
                "beast-booter is still working.\n\n" + self.c.cancel_warning()
                + "\n\nThe window closes when the installer has stopped.",
                icon="warning", default="no", parent=self.root,
            ):
                return
            self._quit_when_idle = True
            self._act(self.c.cancel)
            return
        self.quit()

    def quit(self) -> None:
        try:
            self.root.after_cancel(self._after)
        except (tk.TclError, ValueError, AttributeError):
            pass
        self.root.destroy()

    # -- the loop -----------------------------------------------------------

    def _tick(self) -> None:
        try:
            changed = self.c.poll()
            changed |= self.fw.poll()
            if changed:
                self.render()
            if self._quit_when_idle and self.c.phase is not Phase.RUNNING:
                self.quit()
                return
        except Exception as e:  # noqa: BLE001 - keep the window alive and say what happened
            self._report_bug(e)
        self._after = self.root.after(POLL_MS, self._tick)

    def _report_bug(self, e: BaseException) -> None:
        import traceback

        traceback.print_exc()
        messagebox.showerror(APP_NAME, f"Unexpected error in the window: {type(e).__name__}: {e}", parent=self.root)

    # -- rendering ----------------------------------------------------------

    def _show(self, frame: ttk.Frame, siblings) -> None:
        """Only the visible page is mapped, so Tab never moves into a hidden one."""
        for other in siblings:
            if other is not frame and other.winfo_manager():
                other.grid_remove()
        if not frame.winfo_manager():
            frame.grid(row=0, column=0, sticky="nsew")

    def render(self) -> None:
        c, f = self.c, self.fw
        if c.phase in (Phase.RUNNING, Phase.DONE, Phase.FAILED):
            self.section.set("install")
            self.view = "run"
        elif f.phase in (FwPhase.RUNNING, FwPhase.DONE, FwPhase.FAILED):
            self.section.set("firmware")
        elif self.view == "run":
            self.view = "drive"
        busy = c.phase is Phase.RUNNING or f.phase is FwPhase.RUNNING
        for b in self.nav_buttons.values():
            b.state(["disabled"] if busy or self._dialog_open else ["!disabled"])
        if self.section.get() == "firmware":
            self._show(self.fw_page, (self.flow, self.fw_page))
            self.fw_page.render()
        else:
            self._show(self.flow, (self.flow, self.fw_page))
            self._render_flow()
        self._render_status_bar()

    def _render_flow(self) -> None:
        c = self.c
        pages = {"drive": self.drive_page, "options": self.options_page, "run": self.run_page}
        if self.view == "options" and self.target_kind == "drive" and c.selected_row is None and \
                c.phase is Phase.IDLE:
            self.view = "drive"  # the drive went away
        self._show(pages[self.view], pages.values())
        current = {"drive": 0, "options": 1, "run": 2}[self.view]
        done = set(range(current))
        if self.view == "run" and c.phase is Phase.DONE:
            done.add(2)
            current = -1
        self.steps.show(current, done)
        if self.view == "drive":
            self._render_drives()
            self.drive_scroll.schedule()
        elif self.view == "options":
            self._render_options()
            self._render_dist()
            self._render_actions()
            self.options_scroll.schedule()
        else:
            job = c.job
            if c.phase is Phase.RUNNING and job is not None:
                self.render_progress(job.spec, job.state, elevated=job.elevated, cancelling=job.cancel_requested)
            elif c.outcome is not None:
                self.render_outcome(c.outcome)
            self.run_scroll.schedule()

    def _render_status_bar(self) -> None:
        names = {"linux": "Linux", "windows": "Windows", "darwin": "macOS"}
        text = f"{APP_NAME} {__version__} on {names.get(self.c.platform, self.c.platform)}{DOT}"
        if self.c.backend_error:
            text += self.c.backend_error + " Image files can still be created."
        else:
            text += "Drives are listed without administrator rights; you are asked for them only to write to a drive."
        self.status_bar.configure(text=text)

    def _render_drives(self) -> None:
        c = self.c
        if self.drives.version != c.rows_version:
            self.drives.version = c.rows_version
            self.drives.rebuild(c.rows)
            self.drive_scroll.track()
        else:
            self.drives.sync()
        if c.loading and not c.rows:
            empty = ("Looking for drives...", "")
        elif c.list_error:
            empty = ("Drives can't be listed", c.list_error)
        elif not c.rows:
            empty = (("No disks found", "") if c.show_all else
                     ("No USB drive found", "Plug one in, then press Refresh. Image files can be made without one."))
        else:
            empty = None
        if empty:
            self.drive_empty_title.configure(text=empty[0])
            self.drive_empty_text.configure(text=empty[1])
            if empty[1]:
                self.drive_empty_text.grid()
            else:
                self.drive_empty_text.grid_remove()
            self.drive_empty.grid(row=2, column=0, sticky="ew")
        else:
            self.drive_empty.grid_remove()
        notice = c.update_notice if c.rows else None
        if notice is not None and self._compact:
            self.head_notice.configure(text=" " + notice.short)
            self.head_notice.grid()
        else:
            self.head_notice.grid_remove()
        if notice is not None and not self._compact:
            self.notice_title.configure(text=notice.title)
            self.notice_text.configure(text=notice.text)
            if notice.drive_id:
                self.notice_button.grid()
                self.notice_button.state(["disabled"] if notice.drive_id == c.selected_id else ["!disabled"])
            else:
                self.notice_button.grid_remove()
            m = self.theme.margin  # line up with the drive cards' borders
            self.notice.grid(row=0, column=0, sticky="ew", padx=m, pady=(0, self.px(8)))
        else:
            self.notice.grid_remove()
        text, style = self._drive_hint
        row = c.selected_row
        if not text:
            style = "Muted.TLabel"
            if c.loading and c.rows:
                text = "Refreshing..."
            elif row is not None and row.freshness is not None and row.freshness.advice:
                text = row.freshness.advice
                style = "Warn.TLabel" if row.freshness.state in (NEWER, REINSTALL) else "TLabel"
            elif row is not None:
                text = f"Selected: {row.describe()}"
                style = "TLabel"
            elif not c.show_all:
                text = "Only removable drives are listed."
        self.drive_hint.configure(text=text, style=style)
        has = row is not None and c.phase is Phase.IDLE
        # A drive with older boot files: Update is the main action, Next (erase and install) the other one
        big = "" if self._compact else "Big."
        update_first = c.suggest_update
        self.update_button.configure(style=f"{big}Accent.TButton" if update_first else "TButton")
        self.next_button.configure(style="TButton" if update_first else f"{big}Accent.TButton")
        self.next_button.state(["!disabled"] if has else ["disabled"])
        self.update_button.state(["!disabled"] if c.update_blocker() is None else ["disabled"])
        self.image_button.state(["!disabled"] if c.image_blocker() is None else ["disabled"])

    def _render_options(self) -> None:
        c = self.c
        chk = c.options_check
        if self.target_kind == "image":
            self.options_target.configure(text="For a new image file. No administrator rights are needed.")
        elif c.selected_row is not None:
            self.options_target.configure(text=f"For {c.selected_row.describe()}. Everything on it will be erased.")
        self.layout_note.configure(text=chk.notes.get("layout", chk.errors.get("layout", "")))
        if "fs" in chk.errors:
            self.fs_note.configure(text=chk.errors["fs"], style="Error.Card.TLabel")
        else:
            self.fs_note.configure(text=chk.notes.get("fs", ""),
                                   style="Warn.Card.TLabel" if c.options.fs == "ntfs" else "Small.Card.TLabel")
        if not ntfs_supported(c.platform):
            self.fs_buttons["ntfs"].configure(text="NTFS (not on macOS)")
            self.fs_buttons["ntfs"].state(["disabled"])
        limit = LABEL_MAX.get(c.options.fs, 11)
        n = len(c.options.label)
        self.label_count.configure(text=f"{n} / {limit}", style="Error.Card.TLabel" if n > limit else "Small.Card.TLabel")
        if "label" in chk.errors:
            self.label_note.configure(text=chk.errors["label"], style="Error.Card.TLabel")
            self.label_entry.state(["invalid"])
        else:
            self.label_entry.state(["!invalid"])
            hint = (f"The name the drive shows on computers. {FS_TEXT[c.options.fs]} labels have up to {limit} "
                    "characters: letters, digits, spaces, - and _.") if c.options.fs in FS_TEXT else ""
            self.label_note.configure(text=chk.notes.get("label", hint), style="Small.Card.TLabel")

    def _render_dist(self) -> None:
        s, loc = self.c.dist_summary, self.c.dist
        if s.ok:
            build = f"{DOT}build {s.build_id}" if s.build_id else ""
            self.dist_rows["version"].configure(text=f"{s.version}{build}", style="Bold.Card.TLabel")
        else:
            self.dist_rows["version"].configure(text=s.error or "unavailable", style="Error.Card.TLabel")
        where = f"{loc.path}  ({loc.source})" if loc.path else "not found"
        self.dist_rows["location"].configure(text=where)
        self.dist_rows["subject"].configure(text=s.cert_subject or "-")
        try:
            a, b = distinfo.mok_fingerprint(s.cert_sha1) if s.cert_sha1 else ("-", "")
        except ValueError:
            a, b = s.cert_sha1, ""
        self.fp_vars["sha1a"].set(a)
        self.fp_vars["sha1b"].set(b)
        sha256 = distinfo.colon_hex(s.cert_sha256) if s.cert_sha256 else "-"
        if sha256 != self._sha256_text:
            self._sha256_text = sha256
            self._show_sha256()
        v = self.c.verify_result
        if self.c.verifying:
            self.verify_msg.configure(text="Checking every file against manifest.json...", style="Small.Card.TLabel")
        elif v is None:
            self.verify_msg.configure(text="The installer also checks them before writing.", style="Small.Card.TLabel")
        else:
            self.verify_msg.configure(text=v.message, style="Ok.Card.TLabel" if v.ok else "Error.Card.TLabel")
        self.verify_button.state(["disabled"] if self.c.verifying or loc.path is None or not s.ok else ["!disabled"])
        self.dist_warn.configure(text="\n".join(f"Warning: {w}" for w in s.warnings))

    def _sha256_parts(self, lines: int) -> list[str]:
        pairs = self._sha256_text.split(":")
        per = -(-len(pairs) // lines)
        return [":".join(pairs[i: i + per]) for i in range(0, len(pairs), per)]

    def _fit_sha256(self, _event=None) -> None:
        """Two rows of 16 pairs when they fit, else four rows of 8: never cut off."""
        width = self.sha256_box.winfo_width()
        if width <= 1:
            return
        mono = self.fonts["mono_small"]
        need = max(mono.measure(part) for part in self._sha256_parts(2)) + self._entry_pad
        lines = 4 if width < need else 2 if width >= need + mono.measure("0") // 2 else self._sha256_lines
        if lines != self._sha256_lines:
            self._sha256_lines = lines
            self._show_sha256()

    def _show_sha256(self) -> None:
        parts = self._sha256_parts(self._sha256_lines)
        for i, (entry, var) in enumerate(zip(self.sha256_entries, self.sha256_vars)):
            var.set(parts[i] if i < len(parts) else "")
            if i < len(parts):
                entry.grid(row=i, column=0, sticky="ew")
            else:
                entry.grid_remove()

    def _render_actions(self) -> None:
        c = self.c
        image = self.target_kind == "image"
        blocker = c.image_blocker() if image else c.install_blocker()
        self.install_button.configure(text="Create image file..." if image else "Install...", underline=0)
        self.install_button.state(["disabled"] if blocker else ["!disabled"])
        self.action_hint.configure(text="" if blocker in (None, "Select a USB drive.") else blocker)

    def render_progress(self, spec: JobSpec, st: ProgressState, *, elevated: bool, cancelling: bool) -> None:
        self._shown_outcome = None
        self.result_box.grid_forget()
        self.progress_box.grid(row=0, column=0, sticky="ew")
        self.status_icon.configure(image=self.theme.icon("image" if spec.kind == "image" else "usb", 34))
        if spec.kind == "image":
            title = "Creating the image file"
        else:
            title = "Updating the boot files" if spec.action == "update" else "Installing beast-booter"
        self.status_title.configure(text=title)
        self.status_target.configure(text=spec.target_text)
        if not st.started:
            self.step_label.configure(text="Finishing a check of the drives first..." if self.c.waiting_for_probe else
                                      "Waiting for administrator permission..." if elevated else "Starting...")
            if str(self.bar.cget("mode")) != "indeterminate":
                self.bar.configure(mode="indeterminate")
                self.bar.start(15)
            self.pct_label.configure(text="")
        else:
            if str(self.bar.cget("mode")) != "determinate":
                self.bar.stop()
                self.bar.configure(mode="determinate")
            self.step_label.configure(text=st.message or "Working...")
            self.bar.configure(value=st.pct)
            self.pct_label.configure(text=f"{st.pct:.0f}%")
        notes = []
        if cancelling:
            notes.append(self.c.stopping_text())
        notes += [f"Warning: {w}" for w in st.warnings[-3:]]
        self.progress_note.configure(text="\n".join(notes))
        if notes:
            self.progress_note.grid()
        else:
            self.progress_note.grid_remove()
        self.cancel_button.pack(side="right")
        self.done_button.pack_forget()
        self.cancel_button.state(["disabled"] if cancelling else ["!disabled"])
        self.cancel_button.configure(text="Stopping..." if cancelling else "Cancel")
        self._render_log(st)
        self._render_details()

    def render_outcome(self, o: Outcome) -> None:
        if str(self.bar.cget("mode")) == "indeterminate":
            self.bar.stop()
        self.progress_box.grid_forget()
        self.result_box.grid(row=0, column=0, sticky="nsew")
        self.cancel_button.pack_forget()
        self.done_button.pack(side="right")
        self.done_button.configure(text="Done" if o.ok else "Back")
        self._render_log(None)
        if self._shown_outcome is o:
            self._render_details()
            return
        self._shown_outcome = o
        if not o.ok and not o.cancelled:
            self._details_open = False  # the summary card shows the installer's own words
        self._render_details()
        px, th = self.px, self.theme
        self.status_icon.configure(image=th.icon("ok" if o.ok else ("warning" if o.cancelled else "error"), 34))
        self.status_title.configure(text=o.title)
        self.status_target.configure(text=o.spec.target_text)
        for w in self.result_box.winfo_children():
            w.destroy()
        box = self.result_box
        if o.ok:
            WrapLabel(box, text=o.message, style="Body.TLabel", min_chars=50).grid(row=0, column=0, sticky="ew")
            steps = card(box, th, padding=16)
            steps.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
            steps.columnconfigure(1, weight=1)
            ttk.Label(steps, text="NEXT STEPS", style="Eyebrow.Card.TLabel").grid(row=0, column=0, columnspan=2,
                                                                                 sticky="w")
            r = 1
            for i, step in enumerate(self.c.next_steps(o), 1):
                ttk.Label(steps, image=th.step_badge("current"), text=str(i), compound="center",
                          foreground="#FFFFFF", font=self.fonts["eyebrow"], style="Card.TLabel").grid(
                    row=r, column=0, sticky="nw", pady=(px(8), 0), padx=(0, px(10)))
                WrapLabel(steps, text=step, style="Card.TLabel", min_chars=46).grid(row=r, column=1, sticky="ew",
                                                                                   pady=(px(8), 0))
                r += 1
            s = self.c.dist_summary
            if s.cert_sha1:
                fp = card(steps, th, kind="Info", ctx="Card.", padding=10)
                fp.grid(row=r, column=1, sticky="w", pady=(px(8), 0))
                ttk.Label(fp, text="Key fingerprint (SHA-1), as MokManager shows it", style="Small.Info.TLabel").grid(
                    sticky="w")
                try:
                    a, b = distinfo.mok_fingerprint(s.cert_sha1)
                except ValueError:
                    a, b = s.cert_sha1, ""
                for line in (a, b):
                    e = ttk.Entry(fp, width=31, style="Value.Info.TEntry", font=self.fonts["mono"], takefocus=False)
                    e.insert(0, line)
                    e.state(["readonly"])
                    e.grid(sticky="w")
                r += 1
            docs = self.c.docs_path()
            if docs is not None:
                link = ttk.Label(steps, text="Secure Boot guide: how to check and remove the key", style="Link.Card.TLabel",
                                 cursor="hand2", takefocus=True)
                link.grid(row=r, column=1, sticky="w", pady=(px(10), 0))
                for seq in ("<Button-1>", "<Return>", "<space>"):
                    link.bind(seq, lambda e, p=docs: webbrowser.open(p.as_uri()))
        else:
            kind = "Card" if o.cancelled else "Danger"
            ctx = f"{kind}."
            summary = card(box, th, kind=kind, padding=16)
            summary.grid(row=0, column=0, sticky="ew")
            summary.columnconfigure(0, weight=1)
            WrapLabel(summary, text=o.message, style=f"Sub.{ctx}TLabel", min_chars=50).grid(row=0, column=0,
                                                                                           sticky="ew")
            if o.code and not o.cancelled:
                exit_text = f"{DOT}exit code {o.exit_code}" if o.exit_code not in (None, 0) else ""
                ttk.Label(summary, text=f"Error code: {o.code}{exit_text}", style=f"Muted.{ctx}TLabel").grid(
                    row=1, column=0, sticky="w", pady=(px(4), 0))
            if o.target_state:
                WrapLabel(summary, text=o.target_state, style=f"Bold.{ctx}TLabel", min_chars=50).grid(
                    row=2, column=0, sticky="ew", pady=(px(10), 0))
            lines = list(o.output_tail) or [line.text for line in self.c.log if line.level != "debug"][-12:]
            if lines and not o.cancelled:
                out = card(box, th, padding=12)
                out.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
                out.columnconfigure(0, weight=1)
                ttk.Label(out, text="THE INSTALLER'S OUTPUT" if o.output_tail else "WHAT THE INSTALLER REPORTED",
                          style="Eyebrow.Card.TLabel").grid(sticky="w")
                frame, text = text_box(out, th, height=min(8, max(3, len(lines))), wrap="word")
                frame.grid(sticky="ew", pady=(px(6), 0))
                set_text(text, [(ln, "error" if "error" in ln.lower() else "") for ln in lines[-12:]])
            WrapLabel(box, text="Show details for everything the installer reported.", style="Muted.TLabel",
                      min_chars=40).grid(row=2, column=0, sticky="ew", pady=(px(10), 0))
        self.run_scroll.track(self.result_box)
        self.run_scroll.schedule()
        self.done_button.focus_set()

    def _render_log(self, st: ProgressState | None) -> None:
        log = st.log if st is not None else self.c.log
        if log is not self._log_owner:
            self._log_owner, self._log_shown = log, 0
        lines = [(line.text, line.level) for line in log]
        if len(lines) != self._log_shown:
            set_text(self.log, lines, append_from=self._log_shown)
            self._log_shown = len(lines)

    def _render_details(self) -> None:
        if self._details_open:
            self.log_frame.grid(row=2, column=0, sticky="nsew", pady=(self.px(12), 0))
            self.details_button.configure(text="Hide details")
        else:
            self.log_frame.grid_forget()
            self.details_button.configure(text="Show details")
        self.run_scroll.schedule()

    # -- self-test ----------------------------------------------------------

    def selftest(self) -> int:
        """Draw every page once with sample data; no drive, no process, no dialog left open."""
        root = self.root
        root.update()
        disk = DiskInfo(id="/dev/sdx", path="/dev/sdx", model="Self-test drive", size=32 * 10**9,
                        sector_size=512, bus="usb", removable=True, system=False, read_only=False)
        spec = JobSpec("install", "device", disk.id, disk=disk, options=Options())
        self.view = "options"
        self._render_flow()
        root.update()
        self.view = "run"
        self._show(self.run_page, (self.drive_page, self.options_page, self.run_page))
        st = ProgressState()
        self.render_progress(spec, st, elevated=True, cancelling=False)
        root.update()
        st.started, st.message, st.pct = True, "Writing the boot partition", 42.0
        st.warnings.append("self-test warning")
        self._details_open = True
        self.render_progress(spec, st, elevated=True, cancelling=True)
        root.update()
        for ok in (True, False):
            o = Outcome(ok, spec, "Self-test result", "Sample message.", code=None if ok else "selftest",
                        exit_code=0 if ok else 1, target_state="" if ok else "Sample target state.",
                        output_tail=() if ok else ("beast-booter: error: sample",))
            self.render_outcome(o)
            root.update()
        req = ConfirmRequest(spec, True, "Erase this drive?", "Self-test drive (29.8 GiB, USB, /dev/sdx)",
                             ("Sample detail.",), "I understand all data on it will be erased", "Erase and install")
        dlg = ConfirmDialog(self, req, lambda ok, ack: None)
        root.update()
        dlg.close()
        self.fw_page.selftest()
        root.update()
        self._shown_outcome = None
        self._details_open = False
        self.view = "drive"
        self.section.set("install")
        self.render()
        root.update()
        info = (f"beast-booter GUI self-test ok: Tk {root.tk.call('info', 'patchlevel')}, "
                f"windowing {self.ws}, theme {self.theme.name}, "
                f"scaling {float(root.tk.call('tk', 'scaling')):.2f}, "
                f"window {root.winfo_width()}x{root.winfo_height()}, "
                f"boot files: {self.c.dist.path or 'not found'}, "
                f"firmware packs: {len(self.fw.catalog.packs) if self.fw.catalog else 'none'}")
        print(info)
        self.quit()
        return 0


# ---------------------------------------------------------------------------
# Entry point (called by beastbooter.gui.main)
# ---------------------------------------------------------------------------


def run(args) -> int:
    enable_windows_dpi_awareness()
    try:
        root = tk.Tk(className=APP_NAME)
    except tk.TclError as e:
        print(f"beast-booter: error: cannot open a window: {e}", file=sys.stderr)
        return 1
    if args.scale:
        root.tk.call("tk", "scaling", args.scale * 96 / 72)
    dist = distinfo.find_dist(args.dist)
    if args.demo:
        from . import demo

        controller = Controller(backend_factory=demo.DemoBackend, dist=dist, launcher=demo.FAKE_CLI)
    else:
        controller = Controller(dist=dist)
    app = App(root, controller, demo=args.demo, theme=getattr(args, "theme", None) or "dark")
    if args.selftest:
        return app.selftest()
    controller.refresh_drives()
    app.render()
    root.mainloop()
    return 0
