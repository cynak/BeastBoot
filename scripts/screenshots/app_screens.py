#!/usr/bin/env python3
"""Screenshots of the desktop app for README.md (run by scripts/make_screenshots.sh).

Runs the real window under a virtual X display (xvfb-run) and steps through it
the way the window tests do (installer/tests/test_x_gui_window.py). The drives
are the simulated ones of `--gui --demo` (gui/demo.py) and the installer is the
fake CLI, so nothing is written anywhere. Only the "DEMO" badge is left out.

usage: app_screens.py INSTALLER_DIR DIST_DIR OUT_DIR [--scale FACTOR]
DIST_DIR is shown as the boot files of a portable package (make_screenshots.sh
mounts a copy with an example Secure Boot certificate there).
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import tkinter as tk
from pathlib import Path

from PIL import ImageGrab

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("installer", type=Path)
ap.add_argument("dist", type=Path)
ap.add_argument("out", type=Path)
ap.add_argument("--scale", type=float, default=1.25)
args = ap.parse_args()
sys.path.insert(0, str(args.installer))
os.environ.setdefault("BEAST_BOOTER_FAKE_FW_STATE", os.path.join(tempfile.mkdtemp(), "fw-state.json"))

from beastbooter.gui import app as appmod  # noqa: E402
from beastbooter.gui import demo, distinfo  # noqa: E402
from beastbooter.gui.controller import Controller, Phase  # noqa: E402

KEEP = ("SanDisk Ultra Fit", "Kingston DataTraveler Max", "Generic SD/MMC card", "Samsung Portable SSD T7")


class ShotBackend(demo.DemoBackend):
    """The demo drives minus the ones that exist to test failures."""

    def __init__(self) -> None:
        super().__init__("linux", list_delay=0.05, step_delay=0.5)
        self._disks = [d for d in self._disks if d.model in KEEP]


def settle(root: tk.Tk, seconds: float = 0.5) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update_idletasks()
        root.update()
        time.sleep(0.02)


def wait(root: tk.Tk, cond, timeout: float = 60) -> None:
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise SystemExit("app_screens: timed out")
        root.update()
        time.sleep(0.01)


def dialogs(root: tk.Tk) -> list[tk.Toplevel]:
    return [w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.winfo_ismapped()]


def center(root: tk.Tk, dlg: tk.Toplevel) -> None:
    """No window manager here: put a dialog over the middle of the window."""
    settle(root, 0.2)
    x = root.winfo_rootx() + (root.winfo_width() - dlg.winfo_width()) // 2
    y = root.winfo_rooty() + (root.winfo_height() - dlg.winfo_height()) // 3
    dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    settle(root, 0.3)


def close(root: tk.Tk) -> None:
    for job in root.tk.splitlist(root.tk.call("after", "info")):
        root.after_cancel(job)  # the window's timers would fire into a destroyed interpreter
    root.destroy()


def shot(root: tk.Tk, name: str) -> None:
    settle(root, 0.6)
    x0, y0 = root.winfo_rootx(), root.winfo_rooty()
    img = ImageGrab.grab(bbox=(x0, y0, x0 + root.winfo_width(), y0 + root.winfo_height()),
                         xdisplay=os.environ["DISPLAY"])
    path = args.out / f"{name}.png"
    img.save(path, optimize=True)
    print(f"app_screens: {path.name} {img.width}x{img.height}")


def session(theme: str):
    root = tk.Tk(className="BeastBooter")
    root.tk.call("tk", "scaling", args.scale * 96 / 72)
    c = Controller(backend_factory=ShotBackend, dist=distinfo.DistLocation(args.dist, "portable package"),
                   launcher=demo.FAKE_CLI)
    a = appmod.App(root, c, demo=False, theme=theme)
    root.geometry("+0+0")
    c.refresh_drives()
    a.render()
    wait(root, lambda: c.rows and not c.loading)
    sandisk = next(r.id for r in c.rows if "SanDisk" in r.title)
    a.select_drive(sandisk)
    settle(root, 1.5)  # the drives' boot-files check runs in a worker thread
    return root, c, a, sandisk


def drive_id(c, part: str) -> str:
    return next(r.id for r in c.rows if part in r.title)


args.out.mkdir(parents=True, exist_ok=True)

# Dark theme: the whole install, then the firmware packs.
root, c, a, sandisk = session("dark")
shot(root, "app-drive")
a.select_drive(drive_id(c, "Kingston"))  # older beast-boot on it: the update is offered
shot(root, "app-update-available")
a.select_drive(sandisk)
settle(root)
a.next_step()
shot(root, "app-options")
a.install()
dlg = dialogs(root)[-1]
dlg.ack.set(True)
dlg._update()
center(root, dlg)
shot(root, "app-confirm")  # the dialog lies over the window, so it is in the picture
dlg.ok_button.invoke()
wait(root, lambda: c.phase is Phase.RUNNING and c.progress.started and c.progress.pct >= 45)
shot(root, "app-installing")
wait(root, lambda: c.phase is not Phase.RUNNING)
shot(root, "app-done")
a.dismiss()
settle(root)
a.section.set("firmware")
a._on_section()
a.fw.set_target_drive(drive_id(c, "Kingston"))  # its installed packs show without a password
a.render()
settle(root, 1.0)
page = a.fw_page
for pid in ("intel-wifi", "realtek-ethernet"):
    if pid in page.pack_vars:
        page.pack_vars[pid].set(True)
        page._toggle(pid, True)
shot(root, "app-firmware")
page._open_details("intel-wifi")
shot(root, "app-firmware-details")
close(root)

# Light theme: the first screen.
root, c, a, sandisk = session("light")
shot(root, "app-drive-light")
close(root)
