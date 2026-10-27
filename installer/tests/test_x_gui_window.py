"""The real Tk window: --selftest, scripted demo runs (drive install, firmware packs), layout on small screens.

Needs a Python with tkinter and a display:
  * a Python with Tk: this interpreter if it has tkinter, else BB_GUI_PYTHON, else the
    portable runtime in .tools/pbs-linux (python-build-standalone, includes Tk);
  * Linux: set BB_GUI_TEST_DISPLAY (e.g. ":99" for an Xvfb) so the test never pops
    windows up on a desktop by surprise. Windows and macOS CI use their own desktop.
Skipped otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
import json
import textwrap
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1]
REPO = INSTALLER.parent
LAUNCH = INSTALLER / "beast_booter_launch.py"


def _has_tk(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", "import tkinter"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tk_python() -> str | None:
    candidates = [sys.executable, os.environ.get("BB_GUI_PYTHON", ""),
                  str(REPO / ".tools/pbs-linux/python/bin/python3")]
    for c in candidates:
        if c and Path(c).is_file() and _has_tk(c):
            return c
    return None


def _env() -> dict | None:
    env = dict(os.environ)
    if sys.platform.startswith("linux"):
        display = os.environ.get("BB_GUI_TEST_DISPLAY")
        if not display:
            return None
        env["DISPLAY"] = display
        env.pop("WAYLAND_DISPLAY", None)
    return env


PYTHON = _tk_python()
ENV = _env()
pytestmark = pytest.mark.skipif(
    PYTHON is None or ENV is None,
    reason="needs a Python with tkinter and (on Linux) BB_GUI_TEST_DISPLAY, e.g. an Xvfb display",
)


def run_gui(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run([PYTHON, "-s", "-E", "-B", str(LAUNCH), "--gui", *args], env=ENV,
                          capture_output=True, text=True, timeout=timeout)


@pytest.fixture
def fw_dist(dist_copy) -> Path:
    """The fake boot files plus a firmware catalog (esp/beast-net/catalog.json)."""
    from test_x_gui_firmware import catalog_obj

    p = dist_copy / "esp/beast-net/catalog.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(catalog_obj()))
    return dist_copy


@pytest.mark.parametrize("extra", [[], ["--scale", "1.5"], ["--scale", "2"], ["--demo"], ["--theme", "light"],
                                   ["--theme", "light", "--scale", "2", "--demo"]])
def test_selftest(extra, fw_dist):
    proc = run_gui("--selftest", "--dist", str(fw_dist), *extra)
    assert proc.returncode == 0, proc.stderr
    assert "self-test ok" in proc.stdout and "firmware packs: 2" in proc.stdout
    assert f"theme {'light' if '--theme' in extra else 'dark'}" in proc.stdout
    if "--scale" in extra:
        want = float(extra[extra.index("--scale") + 1]) * 96 / 72
        got = float(proc.stdout.split("scaling ", 1)[1].split(",", 1)[0])
        assert abs(got - want) < 0.02, proc.stdout  # Tk rounds to whole dots per inch


def test_selftest_without_boot_files(tmp_path):
    proc = run_gui("--selftest", "--dist", str(tmp_path / "missing"))
    assert proc.returncode == 0, proc.stderr  # the window still renders, with an explanation
    assert "firmware packs: none" in proc.stdout


def test_selftest_without_firmware_catalog(fake_dist):
    proc = run_gui("--selftest", "--dist", str(fake_dist))
    assert proc.returncode == 0, proc.stderr
    assert "firmware packs: none" in proc.stdout


COMMON = r"""
import os, sys, time, tkinter as tk
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from beastbooter.gui import app as appmod, demo, distinfo
from beastbooter.gui.controller import Controller, Phase
from beastbooter.gui.firmware import FwPhase

root = tk.Tk()
c = Controller(backend_factory=lambda: demo.DemoBackend(list_delay=0.05, step_delay=0.02),
               dist=distinfo.DistLocation(Path(sys.argv[2]), "--dist"), launcher=demo.FAKE_CLI)
a = appmod.App(root, c, demo=True)
c.refresh_drives()

def wait(cond, timeout=30):
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise SystemExit("timeout")
        root.update()
        time.sleep(0.01)

def dialog(cls=appmod.Dialog):
    return [w for w in root.winfo_children() if isinstance(w, cls)][-1]

def drive(part):
    wait(lambda: c.rows and not c.loading)
    return next(r.id for r in c.rows if part in r.title)
"""

DRIVER = textwrap.dedent(COMMON + r"""
results = []

def install(model):
    a.select_drive(drive(model))
    root.update()
    a.next_step()
    root.update()
    assert a.view == "options"
    a.install()
    root.update()
    dlg = dialog(appmod.ConfirmDialog)
    assert dlg.ok_button.instate(["disabled"]), "Erase enabled before ticking"
    assert c.phase is Phase.CONFIRMING
    dlg.ok_button.invoke()  # disabled: nothing happens
    root.update()
    assert c.phase is Phase.CONFIRMING
    dlg.ack.set(True); dlg._update(); root.update()
    dlg.ok_button.invoke()
    wait(lambda: c.phase is Phase.RUNNING and c.progress.started)
    assert a.step_label.cget("text"), "no step shown while running"
    assert a.nav_buttons["firmware"].instate(["disabled"]), "sections can be switched while installing"
    wait(lambda: c.phase is not Phase.RUNNING)
    root.update()
    results.append((c.phase.value, c.outcome.code, a.status_title.cget("text")))
    a.dismiss()
    root.update()

# an unusable drive can't be selected, and says why
a.show_all.set(True); a._act(c.set_show_all, True)
system = drive("990 PRO")
a.drives.click(system)
root.update()
assert c.selected_id != system and "running operating system" in a.drive_hint.cget("text"), a.drive_hint.cget("text")
# a drive with older boot files: a notice above the list, a badge on its card, Update as the main action
old = drive(demo.OLD_BEAST)
wait(lambda: a.drives.version == c.rows_version and c.update_notice
     and (a.notice.winfo_manager() or a.head_notice.winfo_manager()))  # a card, or one line in a short window
shown = a.notice_text if a.notice.winfo_manager() else a.head_notice
assert "has beast-boot 0.0.9" in shown.cget("text"), shown.cget("text")
badges = [w.cget("text") for w in a.drives.cards[old].winfo_children() if w.winfo_class() == "TLabel"]
assert any("0.0.9" in t and "update available" in t for t in badges), badges
a.notice_button.invoke() if a.notice.winfo_manager() else a._select_notice_drive()
root.update()
assert c.selected_id == old and (a.notice_button.instate(["disabled"]) or not a.notice.winfo_manager())
assert "Click Update boot files" in a.drive_hint.cget("text"), a.drive_hint.cget("text")
assert "Accent" in str(a.update_button.cget("style")) and "Accent" not in str(a.next_button.cget("style"))
install("SanDisk")
install("fails while writing")
for r in results:
    print("RESULT", *r)
root.destroy()
""")


def test_demo_run_success_and_failure(tmp_path, fake_dist):
    script = tmp_path / "driver.py"
    script.write_text(DRIVER)
    proc = subprocess.run([PYTHON, "-s", "-E", "-B", str(script), str(INSTALLER), str(fake_dist)],
                          env=ENV, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = [line.split(" ", 3)[1:] for line in proc.stdout.splitlines() if line.startswith("RESULT")]
    assert lines == [["done", "None", "beast-boot is ready"],
                     ["failed", "write-failed", "Installation failed"]]


FW_DRIVER = textwrap.dedent(COMMON + r"""
a.section.set("firmware"); a._on_section(); root.update()
page = a.fw_page
assert page.list_page.winfo_ismapped()
a.fw.set_target_drive(drive("SanDisk")); a.render(); root.update()
page.pack_vars["intel-wifi"].set(True); page._toggle("intel-wifi", True); root.update()
page._open_details("intel-wifi"); root.update()
text = page.d_text.get("1.0", "end")
assert "?h=20261019" in text and "ab" * 32 in text, "details lack the URL / SHA-256"
page._back(); root.update()
page._install(); root.update()
dlg = dialog()
dlg.ok_button.invoke()
wait(lambda: a.fw.phase is not FwPhase.RUNNING, 60)
root.update()
print("FW", a.fw.phase.value, page.r_title.cget("text"))
page._dismiss(); root.update()
print("INSTALLED", page.installed_label.cget("text"))
root.destroy()
""")


def test_firmware_packs_install_through_the_window(tmp_path, fw_dist):
    script = tmp_path / "fw.py"
    script.write_text(FW_DRIVER)
    env = dict(ENV, BEAST_BOOTER_FAKE_FW_STATE=str(tmp_path / "fw-state.json"))
    proc = subprocess.run([PYTHON, "-s", "-E", "-B", str(script), str(INSTALLER), str(fw_dist)],
                          env=env, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FW done Firmware installed" in proc.stdout
    assert "INSTALLED Installed: Intel WiFi." in proc.stdout


SMALL_SCREEN = textwrap.dedent(r"""
    # usage: script INSTALLER DIST WIDTH HEIGHT SCALE THEME  -- a fake screen of WIDTH x HEIGHT pixels
    import faulthandler, sys, time, tkinter as tk
    faulthandler.dump_traceback_later(90, exit=True)  # a hang shows where, instead of a bare timeout
    sys.path.insert(0, sys.argv[1])
    width, height, scale, theme = int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), sys.argv[6]
    tk.Misc.winfo_screenwidth = lambda self: width
    tk.Misc.winfo_screenheight = lambda self: height
    from pathlib import Path
    from beastbooter.gui import app as appmod, demo, distinfo
    from beastbooter.gui.controller import Controller

    root = tk.Tk()
    root.tk.call("tk", "scaling", scale * 96 / 72)
    asked = []  # the sizes the app sets with root.geometry()
    _geometry = tk.Wm.wm_geometry

    def geometry(self, new=None):
        if new:
            asked.append(new)
        return _geometry(self, new)

    tk.Wm.wm_geometry = tk.Wm.geometry = geometry
    c = Controller(backend_factory=lambda: demo.DemoBackend(list_delay=0.0),
                   dist=distinfo.DistLocation(Path(sys.argv[2]), "--dist"), launcher=demo.FAKE_CLI)
    a = appmod.App(root, c, demo=True, theme=theme)
    c.refresh_drives()
    a.show_all.set(True)
    a._act(c.set_show_all, True)

    def pump(sec=0.4):
        end = time.monotonic() + sec
        while time.monotonic() < end:
            root.update()
            time.sleep(0.01)

    def box(w):
        return w.winfo_rootx(), w.winfo_rooty(), w.winfo_rootx() + w.winfo_width(), w.winfo_rooty() + w.winfo_height()

    problems = []
    pump()
    if asked:  # Windows and macOS keep a window inside the real screen; X11 does not
        aw, ah = (int(n) for n in asked[-1].split("+")[0].split("x"))
        if root.winfo_width() < aw - 1 or root.winfo_height() < ah - 1:
            real = root.tk.call("winfo", "screenwidth", "."), root.tk.call("winfo", "screenheight", ".")
            print(f"SKIP the window manager made the {aw}x{ah} window {root.winfo_width()}x{root.winfo_height()}: "
                  f"the real screen ({real[0]}x{real[1]}) is smaller than the simulated {width}x{height}")
            root.destroy()
            sys.exit(77)
    if root.winfo_width() > width or root.winfo_height() > height:
        problems.append(f"window {root.winfo_width()}x{root.winfo_height()} larger than the screen")
    wx0, wy0, wx1, wy1 = box(root)

    def walk(w, where):
        for ch in w.winfo_children():
            if not ch.winfo_ismapped():
                continue
            x0, y0, x1, y1 = box(ch)
            if x0 < wx0 - 1 or x1 > wx1 + 1:
                problems.append(f"{where}: {ch} ({ch.winfo_class()}) sticks out at the side")
            if ch.winfo_class() in ("TRadiobutton", "TCheckbutton", "TButton") and ch.winfo_width() < ch.winfo_reqwidth():
                problems.append(f"{where}: {ch} {ch.cget('text')!r} narrower than its text")
            walk(ch, where)

    def visible(btn, where):
        x0, y0, x1, y1 = box(btn)
        if not btn.winfo_ismapped() or y1 > wy1 + 1 or x1 > wx1 + 1:
            problems.append(f"{where}: {btn.cget('text')!r} not visible")

    sandisk = next(r.id for r in c.rows if "SanDisk" in r.title)
    a.select_drive(sandisk)
    pump()
    walk(root, "drives")
    visible(a.next_button, "drives")
    canvas = a.drive_scroll.canvas
    cy0, cy1 = canvas.winfo_rooty(), canvas.winfo_rooty() + canvas.winfo_height()
    shown = sum(1 for card in a.drives.cards.values() if box(card)[1] >= cy0 - 1 and box(card)[3] <= cy1 + 1)
    if shown < 3:
        problems.append(f"only {shown} drive cards visible")
    if c.update_notice and not (a.notice.winfo_ismapped() or a.head_notice.winfo_ismapped()):
        problems.append("the update notice is not shown")  # demo.OLD_BEAST has older boot files
    a.next_step()
    pump()
    walk(root, "options")
    visible(a.install_button, "options")
    mono = a.fonts["mono_small"]
    for e in a.sha256_entries:
        if e.winfo_ismapped() and mono.measure(e.get()) + a._entry_pad > e.winfo_width() + 1:
            problems.append(f"SHA-256 line {e.get()!r} cut off")
    if a.options_scroll.scrolling:  # keyboard focus scrolls a hidden widget into view
        a.verify_button.focus_set()
        pump(0.3)
        oc = a.options_scroll.canvas
        y0, y1 = box(a.verify_button)[1::2]
        if y0 < oc.winfo_rooty() - 1 or y1 > oc.winfo_rooty() + oc.winfo_height() + 1:
            problems.append("focus did not scroll the Verify button into view")
    a.section.set("firmware"); a._on_section()
    pump()
    walk(root, "firmware")
    visible(a.fw_page.install_button, "firmware")
    a.fw_page._open_details(a.fw.catalog.packs[0].id)
    pump()
    walk(root, "firmware details")
    visible(a.fw_page.d_select, "firmware details")
    print("LAYOUT", "stacked" if a._stacked else "side by side", f"{root.winfo_width()}x{root.winfo_height()}")
    for p in problems:
        print("PROBLEM", p)
    root.destroy()
    sys.exit(1 if problems else 0)
""")


@pytest.mark.parametrize("width, height, scale, theme", [
    (1920, 1080, 1.0, "dark"), (1280, 720, 1.0, "light"), (1366, 768, 1.25, "dark"), (1920, 1080, 1.5, "light"),
    (1920, 1080, 1.75, "dark"), (1920, 1080, 2.0, "dark"), (1920, 1080, 2.0, "light"),
])
def test_small_screens_cut_nothing(tmp_path, fw_dist, width, height, scale, theme):
    """From 100% to 200%: the window fits the screen, nothing sticks out at the side or is
    narrower than its text, the main button of every page is visible, the drive page shows
    at least 3 drive cards, the SHA-256 wraps instead of being cut, and what does not fit scrolls."""
    script = tmp_path / "small.py"
    script.write_text(SMALL_SCREEN)
    proc = subprocess.run([PYTHON, "-s", "-E", "-B", str(script), str(INSTALLER), str(fw_dist),
                           str(width), str(height), str(scale), theme],
                          env=ENV, capture_output=True, text=True, timeout=150)
    if proc.returncode == 77:
        pytest.skip(proc.stdout.strip().splitlines()[-1].removeprefix("SKIP "))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "LAYOUT" in proc.stdout
