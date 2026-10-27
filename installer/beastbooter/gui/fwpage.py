"""The "Firmware packs" section of the window (docs/BEASTNET.md section 6).

    list      what the packs are (closed-source firmware from linux-firmware,
              only for WiFi / some Ethernet in the network helper), the target
              drive or image and what is installed on it, one card per pack
    details   one pack: source repository, tag, and every file with its
              SHA-256 and exact download URL, before anything is downloaded
    run       download, then install (or remove / read), with progress, then the result

All decisions are in firmware.FirmwareController; this only shows its state.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from ..util import human_size
from .controller import DriveRow
from .firmware import ABOUT, CLOSED_SOURCE, FwOutcome, FwPack, FwPhase, FwRequest
from .progress import ProgressState
from .widgets import DOT, Dialog, PickCard, WrapLabel, button_row, card, icon_for_bus, set_text, \
    text_box

# "Installed packs: ..." when they are not known, by FirmwareController.unknown_why
UNKNOWN_TEXTS = {
    "checking": "Installed packs: checking...",
    "stale": "Installed packs: not known since the last run. Check installed packs reads them again.",
    "no-rights": "Installed packs: its boot partition can't be read without administrator rights. "
                 "Check installed packs asks for them.",
    "unreadable": "The drive's list of installed packs could not be read. Check installed packs reads it again.",
    "not-read": "Installed packs: not read yet. Check installed packs reads them (it asks for administrator rights).",
    "image": "Installed packs: not checked yet.",
}


class FwConfirmDialog(Dialog):
    def __init__(self, app, req: FwRequest, on_answer):
        super().__init__(app, req.title)
        self.on_answer = on_answer
        px, b, th = app.px, self.body, app.theme
        b.columnconfigure(1, weight=1)
        ttk.Label(b, image=th.icon("warning" if req.danger else "chip", 34)).grid(row=0, column=0, rowspan=2,
                                                                                 sticky="n", padx=(0, px(14)))
        WrapLabel(b, text=req.title, style="Title.TLabel", min_chars=40).grid(row=0, column=1, sticky="ew")
        tgt = card(b, th, padding=12)
        tgt.grid(row=1, column=1, sticky="ew", pady=(px(10), 0))
        tgt.columnconfigure(1, weight=1)
        icon = icon_for_bus(req.target.disk.bus) if req.target.disk else "image"
        ttk.Label(tgt, image=th.icon(icon, 24), style="Card.TLabel").grid(row=0, column=0, rowspan=2,
                                                                         padx=(0, px(10)))
        ttk.Label(tgt, text=req.target.short, style="Sub.Card.TLabel").grid(row=0, column=1, sticky="w")
        if req.target.disk is not None:
            row = DriveRow(req.target.disk, None)
            detail = DOT.join((row.size_text, row.bus_text, row.id))
        else:
            detail = req.target.target
        WrapLabel(tgt, text=detail, style="Muted.Card.TLabel", min_chars=44).grid(row=1, column=1, sticky="ew")
        r = 2
        if req.action == "install":
            for p in req.packs:
                ttk.Label(b, text=f"{p.title}{DOT}{p.describe_files()}", style="Bold.TLabel").grid(
                    row=r, column=1, sticky="w", pady=(px(8 if r == 2 else 2), 0))
                r += 1
        for text in req.details:
            WrapLabel(b, text=text, style="Body.TLabel", min_chars=56).grid(row=r, column=1, sticky="ew",
                                                                            pady=(px(8), 0))
            r += 1
        btns = button_row(b, app, [("Cancel", self.on_cancel, "TButton"),
                                   (req.confirm_label, self._ok, "Danger.TButton" if req.danger else "Accent.TButton")])
        btns[0].master.grid(row=r, column=0, columnspan=2, sticky="e", pady=(px(18), 0))
        self.ok_button = btns[1]
        self.show(btns[1])

    def _ok(self) -> None:
        self.close()
        self.on_answer(True)

    def on_cancel(self) -> None:
        self.close()
        self.on_answer(False)


class FirmwarePage(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app, self.fw = app, app.fw
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.sub = "list"  # list | details
        self.detail_id: str | None = None
        self._cards_sig = None
        self._details_sig = None
        self._shown_outcome: FwOutcome | None = None
        self._log_owner, self._log_shown = None, 0
        self._details_open = False
        self._target_map: dict[str, tuple[str, str]] = {}
        self.list_page = self._build_list()
        self.details_page = self._build_details()
        self.run_page = self._build_run()
        self.na_page = self._build_unavailable()

    # -- building -----------------------------------------------------------

    def _build_list(self) -> ttk.Frame:
        app, px, th = self.app, self.app.px, self.app.theme
        page, head, scroll, bar = app._page(self)
        self.list_scroll = scroll
        ttk.Label(head, text="Firmware packs", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        sub = WrapLabel(head, style="Muted.TLabel", min_chars=40, text=(
            "Optional. For the network helper, which downloads an ISO from a link right from the boot menu."))
        sub.grid(row=1, column=0, sticky="ew")
        app.compact_hide.append(sub)
        body = scroll.body
        about = card(body, th, kind="Info", padding=12)
        about.grid(row=0, column=0, sticky="ew")
        about.columnconfigure(1, weight=1)
        ttk.Label(about, image=th.icon("chip", 28), style="Info.TLabel").grid(row=0, column=0, rowspan=3,
                                                                             sticky="n", padx=(0, px(12)))
        ttk.Label(about, text=CLOSED_SOURCE, style="Sub.Info.TLabel").grid(row=0, column=1, sticky="w")
        WrapLabel(about, text=ABOUT, style="Body.Info.TLabel", min_chars=44).grid(row=1, column=1, sticky="ew",
                                                                                  pady=(px(4), 0))
        self.source_label = WrapLabel(about, style="Small.Info.TLabel", min_chars=44)
        self.source_label.grid(row=2, column=1, sticky="ew", pady=(px(6), 0))

        tgt = card(body, th, padding=11)
        tgt.grid(row=1, column=0, sticky="ew", pady=(px(10), 0))
        tgt.columnconfigure(1, weight=1)
        ttk.Label(tgt, text="Install to", style="Bold.Card.TLabel").grid(row=0, column=0, sticky="w",
                                                                         padx=(0, px(10)))
        self.target_var = tk.StringVar()
        self.target_box = ttk.Combobox(tgt, textvariable=self.target_var, state="readonly", width=34)
        self.target_box.grid(row=0, column=1, sticky="ew")
        self.target_box.bind("<<ComboboxSelected>>", self._on_target)
        ttk.Button(tgt, text="Image file...", style="Ghost.Card.TButton", command=self._choose_image).grid(
            row=0, column=2, sticky="e", padx=(px(6), 0))
        self.installed_label = WrapLabel(tgt, style="Muted.Card.TLabel", min_chars=36)
        self.installed_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
        self.check_button = ttk.Button(tgt, text="Check installed packs", style="Ghost.Card.TButton",
                                       command=self._check_installed)
        self.check_button.grid(row=1, column=2, sticky="e", padx=(px(6), 0), pady=(px(4), 0))

        self.packs_frame = ttk.Frame(body)
        self.packs_frame.grid(row=2, column=0, sticky="ew", pady=(px(10), 0))
        self.packs_frame.columnconfigure(0, weight=1)
        self.pack_cards: dict[str, PickCard] = {}
        self.pack_vars: dict[str, tk.BooleanVar] = {}

        self.summary = WrapLabel(bar, style="Muted.TLabel", min_chars=24)
        self.summary.grid(row=0, column=0, columnspan=2, sticky="ew", padx=(0, px(10)))
        self.space_label = WrapLabel(bar, style="Muted.TLabel", min_chars=24)  # "Selected: X of Y free"
        self.space_label.grid(row=1, column=0, columnspan=2, sticky="ew", padx=(0, px(10)), pady=(px(2), 0))
        self.install_button = ttk.Button(bar, text="Download and install...", style="Big.Accent.TButton",
                                         command=self._install)
        self.install_button.grid(row=0, column=2, rowspan=2, sticky="e")
        self.install_button.bind("<Return>", lambda e: self.install_button.invoke())
        app.big_buttons.append(self.install_button)
        scroll.track()
        return page

    def _build_details(self) -> ttk.Frame:
        app, px, th = self.app, self.app.px, self.app.theme
        page, head, scroll, bar = app._page(self)
        self.details_scroll = scroll
        self.d_title = ttk.Label(head, style="Heading.TLabel")
        self.d_title.grid(row=0, column=0, sticky="w")
        self.d_desc = WrapLabel(head, style="Muted.TLabel", min_chars=40)
        self.d_desc.grid(row=1, column=0, sticky="ew")
        body = scroll.body
        body.rowconfigure(1, weight=1)
        info = card(body, th, padding=14)
        info.grid(row=0, column=0, sticky="ew")
        info.columnconfigure(1, weight=1)
        self.d_rows = {}
        for i, key in enumerate(("Source", "Repository", "Tag", "Kernel", "Drivers", "Size", "Licences")):
            ttk.Label(info, text=key, style="Muted.Card.TLabel").grid(row=i, column=0, sticky="nw",
                                                                     padx=(0, px(12)), pady=(px(2), 0))
            v = WrapLabel(info, style="Mono.Card.TLabel" if key in ("Repository", "Tag") else "Card.TLabel",
                          min_chars=36)
            v.grid(row=i, column=1, sticky="ew", pady=(px(2), 0))
            self.d_rows[key] = v
        files = card(body, th, padding=12)
        files.grid(row=1, column=0, sticky="nsew", pady=(px(12), 0))
        files.columnconfigure(0, weight=1)
        files.rowconfigure(1, weight=1)
        self.d_files_title = ttk.Label(files, style="Eyebrow.Card.TLabel")
        self.d_files_title.grid(row=0, column=0, sticky="w")
        frame, self.d_text = text_box(files, th, height=12, wrap="none", hscroll=True)
        frame.grid(row=1, column=0, sticky="nsew", pady=(px(6), 0))
        WrapLabel(files, style="Small.Card.TLabel", min_chars=40, text=(
            "Each file is downloaded from exactly this URL and must match this SHA-256, or it is discarded. "
            "It is installed in the helper as lib/firmware/<name>.")).grid(row=2, column=0, sticky="ew",
                                                                         pady=(px(6), 0))
        back = ttk.Button(bar, text="All packs", style="TButton", command=self._back, underline=0)
        back.grid(row=0, column=0, sticky="w")
        self.d_select = ttk.Button(bar, style="Big.Accent.TButton", command=self._toggle_detail)
        self.d_select.grid(row=0, column=2, sticky="e")
        for b in (back, self.d_select):
            b.bind("<Return>", lambda e, b=b: b.invoke())
        app.big_buttons.append(self.d_select)
        scroll.track()
        return page

    def _build_run(self) -> ttk.Frame:
        app, px, th = self.app, self.app.px, self.app.theme
        page, head, scroll, bar = app._page(self)
        self.run_scroll = scroll
        head.columnconfigure(0, weight=0)
        head.columnconfigure(1, weight=1)
        self.r_icon = ttk.Label(head)
        self.r_icon.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, px(12)))
        self.r_title = ttk.Label(head, style="Title.TLabel")
        self.r_title.grid(row=0, column=1, sticky="w")
        self.r_target = WrapLabel(head, style="Muted.TLabel", min_chars=40)
        self.r_target.grid(row=1, column=1, sticky="ew")
        body = scroll.body
        box = self.r_progress = card(body, th, padding=16)
        box.columnconfigure(0, weight=1)
        self.r_stage = ttk.Label(box, style="Eyebrow.Card.TLabel")
        self.r_stage.grid(row=0, column=0, columnspan=2, sticky="w")
        self.r_step = WrapLabel(box, style="Sub.Card.TLabel", min_chars=40)
        self.r_step.grid(row=1, column=0, sticky="ew", pady=(px(4), 0))
        self.r_pct = ttk.Label(box, style="Sub.Card.TLabel", width=5, anchor="e")
        self.r_pct.grid(row=1, column=1, sticky="e")
        self.r_bar = ttk.Progressbar(box, orient="horizontal", mode="determinate", maximum=100,
                                     style="BB.Card.Horizontal.TProgressbar")
        self.r_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(px(10), 0))
        self.r_note = WrapLabel(box, style="Warn.Card.TLabel", min_chars=40)
        self.r_note.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(px(8), 0))
        self.r_result = ttk.Frame(body)
        self.r_result.columnconfigure(0, weight=1)
        self.r_log_frame, self.r_log = text_box(body, th, height=9, ctx="")
        self.r_details = ttk.Button(bar, text="Show details", style="Ghost.TButton", command=self._toggle_log)
        self.r_details.grid(row=0, column=0, sticky="w")
        btns = ttk.Frame(bar)
        btns.grid(row=0, column=2, sticky="e")
        self.r_cancel = ttk.Button(btns, text="Cancel", command=self._cancel)
        self.r_done = ttk.Button(btns, text="Done", style="Big.Accent.TButton", command=self._dismiss)
        for b in (self.r_cancel, self.r_done, self.r_details):
            b.bind("<Return>", lambda e, b=b: b.invoke())
        app.big_buttons.append(self.r_done)
        scroll.track()
        return page

    def _build_unavailable(self) -> ttk.Frame:
        app, px, th = self.app, self.app.px, self.app.theme
        page, head, scroll, bar = app._page(self)
        ttk.Label(head, text="Firmware packs", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        box = card(scroll.body, th, kind="Info", padding=18)
        box.grid(row=0, column=0, sticky="ew")
        box.columnconfigure(1, weight=1)
        ttk.Label(box, image=th.icon("chip", 34, disabled=True), style="Info.TLabel").grid(
            row=0, column=0, rowspan=3, sticky="n", padx=(0, px(14)))
        ttk.Label(box, text="Not available in this build", style="Sub.Info.TLabel").grid(row=0, column=1, sticky="w")
        self.na_text = WrapLabel(box, style="Body.Info.TLabel", min_chars=44)
        self.na_text.grid(row=1, column=1, sticky="ew", pady=(px(4), 0))
        WrapLabel(box, style="Small.Info.TLabel", min_chars=44, text=(
            "Firmware packs are optional: they are only needed for WiFi and some Ethernet adapters in the network "
            "helper. Everything else works without them.")).grid(row=2, column=1, sticky="ew", pady=(px(8), 0))
        return page

    # -- rendering ----------------------------------------------------------

    def _pages(self):
        return (self.list_page, self.details_page, self.run_page, self.na_page)

    def render(self) -> None:
        f, app = self.fw, self.app
        if f.phase in (FwPhase.RUNNING, FwPhase.DONE, FwPhase.FAILED):
            app._show(self.run_page, self._pages())
            self._render_run()
            return
        if not f.available:
            app._show(self.na_page, self._pages())
            self.na_text.configure(text=f.catalog_error or "This build has no firmware packs.")
            return
        if f.target is None and app.c.selected_row is not None and f.phase is FwPhase.IDLE:
            f.set_target_drive(app.c.selected_id)
        f.sync_target()
        if self.sub == "details" and self.detail_id and f.catalog.pack(self.detail_id):
            app._show(self.details_page, self._pages())
            self._render_details(f.catalog.pack(self.detail_id))
        else:
            self.sub = "list"
            app._show(self.list_page, self._pages())
            self._render_list()

    def _render_list(self) -> None:
        f, cat = self.fw, self.fw.catalog
        self.source_label.configure(text=f"Source: {cat.repo}{DOT}tag {cat.tag}"
                                    + (f"{DOT}for kernel {cat.kernel}" if cat.kernel else ""))
        # Target choices: the usable drives, plus the image file if one was chosen
        self._target_map = {}
        for r in f.target_choices():
            self._target_map[r.describe()] = ("device", r.id)
        if f.target is not None and f.target.kind == "image":
            self._target_map[f"Image file: {f.target.target}"] = ("image", f.target.target)
        values = list(self._target_map)
        self.target_box.configure(values=values)
        current = next((k for k, v in self._target_map.items() if f.target and v == (f.target.kind, f.target.target)),
                       "")
        if self.target_var.get() != current:
            self.target_var.set(current)
        if not values:
            self.target_var.set("")
        installed = f.installed_on_target
        if f.target is None:
            text = "Choose the beast-boot drive, or an image file, to install the packs to."
        elif installed is None:
            text = UNKNOWN_TEXTS.get(f.unknown_why or "", UNKNOWN_TEXTS["not-read"])
        elif installed:
            names = [(f.catalog.pack(p.id).title if f.catalog.pack(p.id) else p.id)
                     + (f" ({p.stale_note[:1].lower()}{p.stale_note[1:]})" if p.stale_note else "") for p in installed]
            text = "Installed: " + ", ".join(names) + "."
        else:
            text = "No firmware packs are installed on it yet."
        self.installed_label.configure(text=text)
        self.check_button.state(["!disabled"] if f.list_blocker() is None else ["disabled"])

        sig = (id(cat), tuple((p.id, p.stale) for p in (installed or ())), f.target.key if f.target else None)
        if sig != self._cards_sig:
            self._cards_sig = sig
            self._rebuild_cards()
        for pid, c in self.pack_cards.items():
            on = pid in f.selected
            if self.pack_vars[pid].get() != on:
                self.pack_vars[pid].set(on)
            c.set_flags(selected=on)
        n, size = len(f.selected_packs), f.download_size
        blocker = f.install_blocker()
        check = f.space_check
        over = bool(f.selected) and check is not None and not check.fits
        if n:
            files = sum(len(p.files) for p in f.selected_packs)
            text = f"{n} pack{'s' if n > 1 else ''} selected{DOT}{files} files, {human_size(size)} from {cat.host}"
            if blocker and blocker != "Busy." and not over:  # "doesn't fit" goes on the line below
                text += f". {blocker}"
        else:
            text = "Select the packs your network adapters need."
        self.summary.configure(text=text)
        # The live "Selected: X of Y free" line; the reason Install is disabled when they don't fit.
        space = f.space_text()
        if f.target is None:
            space = ""
        elif over:
            space = f.no_room_text(check)
        elif space is None:
            space = "Free space on the boot partition: checked before anything is downloaded" + (
                " (that asks for administrator rights)." if f.target.kind == "device" else ".")
        self.space_label.configure(text=space, style="Error.TLabel" if over else "Muted.TLabel")
        self.install_button.state(["disabled"] if blocker else ["!disabled"])
        self.list_scroll.schedule()

    def _rebuild_cards(self) -> None:
        f, px, th = self.fw, self.app.px, self.app.theme
        for w in self.packs_frame.winfo_children():
            w.destroy()
        self.pack_cards, self.pack_vars = {}, {}
        for i, p in enumerate(f.catalog.packs):
            c = PickCard(self.packs_frame, th, padding=10, takefocus=False)
            c.grid(row=i, column=0, sticky="ew", pady=(0, px(2)))
            c.columnconfigure(0, weight=1)
            var = tk.BooleanVar(value=p.id in f.selected)
            cb = ttk.Checkbutton(c, text=p.title, variable=var, style="Sub.Pick.TCheckbutton",
                                 command=lambda pid=p.id, v=var: self._toggle(pid, v.get()))
            cb.grid(row=0, column=0, sticky="w")
            ttk.Label(c, text=p.size_text, style="Sub.Pick.TLabel").grid(row=0, column=1, sticky="e")
            WrapLabel(c, text=p.description, style="Body.Pick.TLabel", min_chars=40).grid(
                row=1, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
            WrapLabel(c, text=f"Drivers: {p.modules_text or '-'}", style="Small.Pick.TLabel", min_chars=40).grid(
                row=2, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
            lic = "; ".join(p.licenses) or "see the details"
            WrapLabel(c, text=f"{p.describe_files()}{DOT}Licence: {lic}", style="Small.Pick.TLabel",
                      min_chars=40).grid(row=3, column=0, columnspan=2, sticky="ew")
            row = ttk.Frame(c, style="PickInner.TFrame")
            row.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(px(6), 0))
            row.columnconfigure(1, weight=1)
            ttk.Button(row, text="Details and files", style="Ghost.Pick.TButton",
                       command=lambda pid=p.id: self._open_details(pid)).grid(row=0, column=0, sticky="w")
            if f.is_installed(p.id):
                ttk.Label(row, text="INSTALLED", style="Badge.Pick.TLabel").grid(row=0, column=2, sticky="e",
                                                                                 padx=(0, px(6)))
                ttk.Button(row, text="Remove...", style="Ghost.Pick.TButton",
                           command=lambda pid=p.id: self._remove(pid)).grid(row=0, column=3, sticky="e")
            if note := f.stale_note(p.id):  # made for the helper before an update: select it and install again
                WrapLabel(c, text=note, style="ErrorBold.Pick.TLabel", min_chars=40).grid(
                    row=5, column=0, columnspan=2, sticky="ew", pady=(px(4), 0))
            for w in PickCard._descendants(c):
                c.adopt(w)
            c.adopt(c)
            self.pack_cards[p.id] = c
            self.pack_vars[p.id] = var
        self.list_scroll.track()

    def _render_details(self, p: FwPack) -> None:
        f, cat = self.fw, self.fw.catalog
        self.d_title.configure(text=p.title)
        self.d_desc.configure(text=p.description)
        vals = {"Source": f"{cat.source_name}{DOT}{CLOSED_SOURCE.lower()}", "Repository": cat.repo, "Tag": cat.tag,
                "Kernel": cat.kernel or "-", "Drivers": p.modules_text or "-", "Size": p.describe_files(),
                "Licences": "\n".join(p.licenses) or "-"}
        for k, v in vals.items():
            self.d_rows[k].configure(text=v)
        self.d_files_title.configure(text=f"{len(p.files)} FILES, WITH THEIR SHA-256 AND DOWNLOAD URL")
        sig = (id(cat), p.id)
        if sig != self._details_sig:
            self._details_sig = sig
            t = self.d_text
            t.configure(state="normal")
            t.delete("1.0", "end")
            for fe in p.files:
                t.insert("end", fe.path, "head")
                t.insert("end", f"  ({human_size(fe.size)})\n")
                t.insert("end", f"  SHA-256  {fe.sha256}\n")
                t.insert("end", "  URL      ")
                t.insert("end", fe.url + "\n", "url")
                if fe.license:
                    t.insert("end", f"  Licence  {fe.license}\n", "debug")
                t.insert("end", "\n")
            t.configure(state="disabled")
            t.yview_moveto(0)
        on = p.id in f.selected
        self.d_select.configure(text="Don't install this pack" if on else "Select this pack")
        self.d_select.state(["disabled"] if f.phase is not FwPhase.IDLE else ["!disabled"])
        self.details_scroll.schedule()

    def _render_run(self) -> None:
        f, th = self.fw, self.app.theme
        job = f.job
        if f.phase is FwPhase.RUNNING and job is not None:
            self._shown_outcome = None
            self.r_result.grid_forget()
            self.r_progress.grid(row=0, column=0, sticky="ew")
            self.r_icon.configure(image=th.icon("chip", 34))
            titles = {"install": "Installing firmware packs", "remove": "Removing a firmware pack",
                      "list": "Reading the installed packs"}
            self.r_title.configure(text=titles[job.action])
            self.r_target.configure(text=job.target.text)
            self.r_stage.configure(text=f.stage_text().upper())
            st: ProgressState = job.state
            if not st.started:
                self.r_step.configure(text="Finishing a check of the drives first..." if f.waiting_for_probe else
                                      "Waiting for administrator permission..." if job.elevated else "Starting...")
                if str(self.r_bar.cget("mode")) != "indeterminate":
                    self.r_bar.configure(mode="indeterminate")
                    self.r_bar.start(15)
                self.r_pct.configure(text="")
            else:
                if str(self.r_bar.cget("mode")) != "determinate":
                    self.r_bar.stop()
                    self.r_bar.configure(mode="determinate")
                self.r_step.configure(text=st.message or "Working...")
                self.r_bar.configure(value=f.overall_pct)
                self.r_pct.configure(text=f"{f.overall_pct:.0f}%")
            notes = (["Stopping..."] if job.cancel_requested else []) + [f"Warning: {w}" for w in st.warnings[-3:]]
            self.r_note.configure(text="\n".join(notes))
            (self.r_note.grid if notes else self.r_note.grid_remove)()
            self.r_cancel.pack(side="right")
            self.r_done.pack_forget()
            self.r_cancel.state(["!disabled"] if f.can_cancel else ["disabled"])
        elif f.outcome is not None:
            self._render_outcome(f.outcome)
        self._render_log()
        self.run_scroll.schedule()

    def _render_outcome(self, o: FwOutcome) -> None:
        th, px = self.app.theme, self.app.px
        if str(self.r_bar.cget("mode")) == "indeterminate":
            self.r_bar.stop()
        self.r_progress.grid_forget()
        self.r_result.grid(row=0, column=0, sticky="ew")
        self.r_cancel.pack_forget()
        self.r_done.pack(side="right")
        self.r_done.configure(text="Done" if o.ok else "Back")
        if self._shown_outcome is o:
            return
        self._shown_outcome = o
        self.r_icon.configure(image=th.icon("ok" if o.ok else ("warning" if o.cancelled else "error"), 34))
        self.r_title.configure(text=o.title)
        self.r_target.configure(text=o.target.text)
        for w in self.r_result.winfo_children():
            w.destroy()
        kind = "Card" if o.ok or o.cancelled else "Danger"
        box = card(self.r_result, th, kind=kind, padding=16)
        box.grid(row=0, column=0, sticky="ew")
        box.columnconfigure(0, weight=1)
        ctx = f"{kind}."
        WrapLabel(box, text=o.message, style=f"Sub.{ctx}TLabel", min_chars=50).grid(row=0, column=0, sticky="ew")
        if not o.ok and o.code and not o.cancelled:
            exit_text = f"{DOT}exit code {o.exit_code}" if o.exit_code not in (None, 0) else ""
            ttk.Label(box, text=f"Error code: {o.code}{exit_text}", style=f"Muted.{ctx}TLabel").grid(
                row=1, column=0, sticky="w", pady=(px(4), 0))
        if o.ok and o.action == "install":
            WrapLabel(box, style=f"Body.{ctx}TLabel", min_chars=50, text=(
                "Start the computer from the drive and choose \"Download an ISO from a link\" in the tools section: "
                "WiFi adapters with this firmware now show up there.")).grid(row=2, column=0, sticky="ew",
                                                                           pady=(px(8), 0))
        lines = list(o.output_tail) or [ln.text for ln in self.fw.log if ln.level != "debug"][-10:]
        if not o.ok and not o.cancelled and lines:
            out = card(self.r_result, th, padding=12)
            out.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
            out.columnconfigure(0, weight=1)
            ttk.Label(out, text="WHAT THE COMMAND REPORTED", style="Eyebrow.Card.TLabel").grid(sticky="w")
            frame, text = text_box(out, th, height=min(8, max(3, len(lines))))
            frame.grid(sticky="ew", pady=(px(6), 0))
            set_text(text, [(ln, "error" if "error" in ln.lower() else "") for ln in lines])
        self.run_scroll.track(self.r_result)
        self.r_done.focus_set()

    def _render_log(self) -> None:
        log = self.fw.log
        if log is not self._log_owner:
            self._log_owner, self._log_shown = log, 0
        if len(log) != self._log_shown:
            set_text(self.r_log, [(ln.text, ln.level) for ln in log], append_from=self._log_shown)
            self._log_shown = len(log)
        if self._details_open:
            self.r_log_frame.grid(row=2, column=0, sticky="nsew", pady=(self.app.px(12), 0))
            self.r_details.configure(text="Hide details")
        else:
            self.r_log_frame.grid_forget()
            self.r_details.configure(text="Show details")

    # -- actions ------------------------------------------------------------

    def focus_first(self) -> None:
        if self.list_page.winfo_manager():
            self.target_box.focus_set()

    def _toggle(self, pid: str, on: bool) -> None:
        self.app._act(self.fw.set_selected, pid, on)

    def _on_target(self, _e=None) -> None:
        kind, value = self._target_map.get(self.target_var.get(), (None, None))
        if kind == "device":
            self.fw.set_target_drive(value)
        self.app.render()

    def _choose_image(self) -> None:
        path = filedialog.askopenfilename(parent=self.app.root, title="Choose a beast-boot image file",
                                          filetypes=[("Disk images", "*.img"), ("All files", "*")])
        if path:
            self.app._act(self.fw.set_target_image, path)

    def _check_installed(self) -> None:
        self.app._act(self.fw.refresh_installed)

    def _open_details(self, pid: str) -> None:
        self.sub, self.detail_id = "details", pid
        self.app.render()
        self.d_select.focus_set()

    def _back(self) -> None:
        self.sub = "list"
        self.app.render()
        card = self.pack_cards.get(self.detail_id or "")
        if card is not None:
            for w in PickCard._descendants(card):
                if isinstance(w, ttk.Checkbutton):
                    w.focus_set()

    def _toggle_detail(self) -> None:
        if self.detail_id:
            self.app._act(self.fw.set_selected, self.detail_id, self.detail_id not in self.fw.selected)

    def _confirm(self, req: FwRequest) -> None:
        self.app._dialog_open = True

        def answer(ok: bool) -> None:
            self.app._dialog_open = False
            if not ok:
                self.app._act(self.fw.cancel_request)
                return
            self.sub = "list"
            self.app._act(self.fw.confirm)

        FwConfirmDialog(self.app, req, answer)
        self.app.render()

    def _install(self) -> None:
        if self.fw.install_blocker() is None:
            req = self.app._act(self.fw.request_install)
            if req:
                self._confirm(req)

    def _remove(self, pid: str) -> None:
        req = self.app._act(self.fw.request_remove, pid)
        if req:
            self._confirm(req)

    def _cancel(self) -> None:
        if self.fw.can_cancel:
            self.app._act(self.fw.cancel)

    def _dismiss(self) -> None:
        if self.fw.phase in (FwPhase.DONE, FwPhase.FAILED):
            self.app._act(self.fw.dismiss)

    def _toggle_log(self) -> None:
        self._details_open = not self._details_open
        self._render_log()
        self.run_scroll.schedule()

    # -- self-test ----------------------------------------------------------

    def selftest(self) -> None:
        """Draw the list, the details and the unavailable state once."""
        root, f = self.app.root, self.fw
        self.app.section.set("firmware")
        self.app.render()
        root.update()
        if f.available:
            self._open_details(f.catalog.packs[0].id)
            root.update()
            self._back()
            root.update()
        self.app._show(self.na_page, self._pages())
        root.update()
        self.app.section.set("install")
