"""Scrolling in the real window: a burst of wheel events is coalesced into
frames, triggers no relayout and no hover restyling, glides pixel by pixel,
and leaves only the card under the pointer hovered.

Needs a Python with tkinter and a display, like test_x_gui_window.py.
"""

from __future__ import annotations

import json
import subprocess
import textwrap

import pytest
from test_x_gui_window import ENV, INSTALLER, PYTHON

pytestmark = pytest.mark.skipif(
    PYTHON is None or ENV is None,
    reason="needs a Python with tkinter and (on Linux) BB_GUI_TEST_DISPLAY, e.g. an Xvfb display",
)

SCRIPT = textwrap.dedent(r"""
    import faulthandler, json, sys, time, tkinter as tk
    faulthandler.dump_traceback_later(90, exit=True)
    sys.path.insert(0, sys.argv[1])
    from pathlib import Path
    from beastbooter.gui import app as appmod, demo, distinfo, widgets
    from beastbooter.interfaces import DiskInfo

    GB = 1000**3
    demo.demo_disks = lambda platform: [
        DiskInfo(id=f"/dev/sdz{n}", path=f"/dev/sdz{n}", model=f"Drive {n:02d}", size=(8 + n) * GB,
                 sector_size=512, bus="usb", removable=True, system=False, read_only=False)
        for n in range(25)]
    counts = {"relayout": 0, "sync": 0}
    for cls, meth, key in ((widgets.ScrollArea, "_relayout", "relayout"), (widgets.PickCard, "_sync", "sync")):
        def counting(self, *a, _orig=getattr(cls, meth), _key=key, **k):
            counts[_key] += 1
            return _orig(self, *a, **k)
        setattr(cls, meth, counting)

    from beastbooter.gui.controller import Controller
    root = tk.Tk()
    c = Controller(backend_factory=lambda: demo.DemoBackend(list_delay=0.0),
                   dist=distinfo.DistLocation(Path(sys.argv[2]), "--dist"), launcher=demo.FAKE_CLI)
    a = appmod.App(root, c, demo=True)
    c.refresh_drives()

    def pump(sec):
        end = time.monotonic() + sec
        while time.monotonic() < end:
            root.update()
            time.sleep(0.003)

    end = time.monotonic() + 30
    while len(a.drives.cards) < 25 and time.monotonic() < end:
        pump(0.05)
    root.geometry("860x640+0+0")
    pump(0.6)
    sa = a.drive_scroll
    cv = sa.canvas
    cards = list(a.drives.cards.values())
    out = {"scrolling": sa.scrolling, "notch": sa.notch}

    def warp(w, fx, fy):
        root.event_generate("<Motion>", warp=True, x=w.winfo_rootx() - root.winfo_rootx() + int(w.winfo_width() * fx),
                            y=w.winfo_rooty() - root.winfo_rooty() + int(w.winfo_height() * fy))

    positions = []
    def hook(first, last):
        positions.append(round(cv.canvasy(0)))
        sa.vsb.set(first, last)
    cv.configure(yscrollcommand=hook)

    def under_pointer():
        x, y = root.winfo_pointerxy()
        w = root.winfo_containing(x, y)
        return w, x - w.winfo_rootx(), y - w.winfo_rooty()

    def wheel(delta, n=1):
        for _ in range(n):
            w, x, y = under_pointer()
            w.event_generate("<MouseWheel>", delta=delta, x=x, y=y, when="tail")

    def settle():
        end = time.monotonic() + 5
        pump(0.05)
        while (sa._frame_job or sa._settle_job) and time.monotonic() < end:
            pump(0.02)
        pump(0.1)

    warp(cards[2], 0.3, 0.5)
    pump(0.3)
    limit = sa._limit()
    out["limit"] = limit

    # 1. a burst of 60 notches, all queued before the loop runs
    counts.update(relayout=0, sync=0)
    positions.clear()
    wheel(-120, 60)
    settle()
    out["burst"] = {"relayouts": counts["relayout"], "syncs": counts["sync"], "paints": len(positions),
                    "final": round(cv.canvasy(0))}
    hovered = [i for i, card in enumerate(cards) if card._hover]
    under = under_pointer()[0]
    while under is not None and not isinstance(under, widgets.PickCard):
        under = under.master
    out["hover"] = {"hovered": hovered, "under": cards.index(under) if under in cards else None,
                    "active": [i for i, card in enumerate(cards) if card.instate(["active"])]}

    # 2. three slow notches from the top: eased, pixel by pixel
    cv.yview_moveto(0)
    pump(0.2)
    positions.clear()
    for _ in range(3):
        wheel(-120)
        pump(0.1)
    settle()
    steps = [abs(b - a) for a, b in zip([0, *positions], positions)]
    out["slow"] = {"final": round(cv.canvasy(0)), "paints": len(positions), "max_step": max(steps) if steps else 0}

    # 3. Tk 9 touchpad deltas (packed dx << 16 | dy) move the page by exactly -dy
    out["touchpad"] = None
    if tk.TkVersion >= 9.0:
        cv.yview_moveto(0)
        pump(0.2)
        try:
            for _ in range(4):
                w, x, y = under_pointer()
                w.event_generate("<TouchpadScroll>", delta=(-10) & 0xFFFF, x=x, y=y, when="tail")
            settle()
            out["touchpad"] = round(cv.canvasy(0))
        except tk.TclError as e:
            out["touchpad"] = str(e)

    # 4. the wheel stays with the page while it scrolls: a drop-down sliding under
    #    the pointer must not take it over (and change its value); later it may
    from tkinter import ttk
    cb = ttk.Combobox(sa.body, values=["a", "b"])
    sa.track(cb)
    tags = cb.bindtags()
    class Ev:
        delta, num, widget = -120, "??", cb
    sa._latch()
    first = sa._on_latched(Ev, sa._wheel)
    time.sleep(0.2)
    out["latch"] = {"before_class": tags.index(sa.latch_tag) < tags.index("TCombobox"),
                    "while_scrolling": first, "later": sa._on_latched(Ev, sa._wheel),
                    "own_wheel_ignored": sa._wheel_target_ok(Ev) is False}
    settle()
    cb.destroy()

    # 5. the scroll bar still works
    sa._on_scrollbar("moveto", 0.5)
    pump(0.2)
    out["scrollbar"] = round(cv.canvasy(0)) / max(1, sa._size[1])
    print(json.dumps(out))
    root.destroy()
""")


def test_wheel_burst_is_coalesced_smooth_and_cheap(fake_dist, tmp_path):
    script = tmp_path / "scroll.py"
    script.write_text(SCRIPT)
    proc = subprocess.run([PYTHON, "-s", "-E", "-B", str(script), str(INSTALLER), str(fake_dist)], env=ENV,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    r = json.loads(proc.stdout.strip().splitlines()[-1])
    assert r["scrolling"], r
    notch, limit = r["notch"], r["limit"]
    burst = r["burst"]
    assert burst["final"] == min(limit, 60 * notch), r
    assert burst["relayouts"] <= 2, r  # was one per scroll step
    assert burst["syncs"] <= 4, r  # cards sliding under a still pointer are not restyled
    assert burst["paints"] <= 40, r  # at most one view update per frame (~16 ms)
    # Afterwards exactly the card under the pointer shows as hovered
    h = r["hover"]
    assert h["under"] is not None and h["hovered"] == [h["under"]] and h["active"] == [h["under"]], r
    slow = r["slow"]
    assert slow["final"] == 3 * notch, r
    assert slow["max_step"] <= notch / 2, r  # glides instead of jumping a notch per event
    assert slow["paints"] >= 9, r
    if r["touchpad"] is not None:
        assert r["touchpad"] == 40, r
    assert r["latch"] == {"before_class": True, "while_scrolling": "break", "later": None,
                          "own_wheel_ignored": True}, r
    assert r["scrollbar"] == pytest.approx(0.5, abs=0.01), r
