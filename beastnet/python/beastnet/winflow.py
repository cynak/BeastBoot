"""Screens of the ``winboot`` action (beastnet.action=winboot)."""

from __future__ import annotations

import time
from typing import Any
from collections.abc import Callable

from . import winboot
from .download import Progress, human_size
from .errors import BeastNetError

TITLE = "Prepare a Windows ISO for Secure Boot"


class WinbootScreens:
    def __init__(self, flow: Any, wb: winboot.WinBoot | None = None) -> None:
        self.f = flow
        self.ui = flow.ui
        self.wb = wb or winboot.WinBoot(flow.ctx.paths, flow.ctx.system.runner)

    def run(self) -> None:
        try:
            plan = self.ui.task(TITLE, "Reading the ISO...", self.wb.plan)
        except BeastNetError as e:
            self.f.show_error(e, TITLE)
            return
        text = (f"{plan.iso}\n\nWith Secure Boot on, the menu cannot read Windows ISOs directly. "
                f"This copies one file from it (boot.wim, {human_size(plan.size)}) to the drive so "
                f"the ISO can start. The ISO itself is not changed.\n\n"
                f"Space needed: {human_size(plan.needed)}    Free: {human_size(plan.free)}")
        if not self.ui.confirm(TITLE, text, "Copy and boot", "Back"):
            return

        def job(on_progress: Callable[[Progress], None], cancel: Any) -> winboot.WinResult:
            on_progress(Progress("copy", done=0, total=plan.size))
            start = time.monotonic()

            def step(done: int, total: int) -> None:
                secs = time.monotonic() - start
                speed = done / secs if secs > 0.5 else 0.0
                eta = (total - done) / speed if speed > 0 else None
                on_progress(Progress("copy", done=done, total=total, speed=speed, eta=eta))

            return self.wb.run(plan, step, cancel.is_set)

        try:
            res = self.ui.download(TITLE, [f"ISO: {plan.iso}", "Copying boot.wim to the drive"],
                                   job, what="boot.wim copy")
            if not res.ok:
                self.ui.message(TITLE, "Stopped. Nothing was kept; the ISO is unchanged.", kind="warn")
                return
            self.wb.finish()
            self.f.ctx.reporter.emit("winboot", f"iso={plan.iso}", f"size={plan.size}", f"kind={plan.kind}")
        except BeastNetError as e:
            self.f.show_error(e, TITLE)
            return
        self.ui.message(TITLE, f"Done. The menu will now start {plan.iso}.", kind="ok",
                        button="Reboot")
        self.f.common("reboot")
