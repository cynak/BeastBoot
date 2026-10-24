import curses
import io
import os
import select
import sys
import threading
import time

import pytest

from beastnet import grubenv
from beastnet.context import Quit
from beastnet.download import Progress
from beastnet.flow import Interactive
from beastnet.ui import UI, Field, Item, bars_text, human_time
from beastnet.ui.plain import LineUI, progress_line
from beastnet.ui.tui import TUI
from test_script import ISO, SHA, context, make_root
from test_wifi import FakeWpa

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "python")


class FakeScreen:
    """Just enough of a curses window to render the TUI into a character grid."""

    def __init__(self, keys=(), h=25, w=80):
        self.h, self.w = h, w
        self.keys = list(keys)
        self.frames = []
        self._timeout = -1
        self.erase()

    def getmaxyx(self):
        return self.h, self.w

    def erase(self):
        self.grid = [[" "] * self.w for _ in range(self.h)]

    clear = erase

    def addstr(self, y, x, s, attr=0):
        if not (0 <= y < self.h and 0 <= x < self.w) or x + len(s) > self.w:
            raise curses.error("out of the window")
        for i, ch in enumerate(s):
            self.grid[y][x + i] = ch

    def addch(self, y, x, ch, attr=0):
        self.grid[y][x] = chr(ch & 0xFF) if isinstance(ch, int) else ch

    def hline(self, y, x, ch, n):
        for i in range(n):
            self.addch(y, x + i, ch)

    def vline(self, y, x, ch, n):
        for i in range(n):
            self.addch(y + i, x, ch)

    def move(self, y, x):
        self.cursor = (y, x)

    def refresh(self):
        self.frames.append(self.dump())

    def keypad(self, flag):
        pass

    def timeout(self, ms):
        self._timeout = ms

    def get_wch(self):
        if self.keys:
            return self.keys.pop(0)
        if self._timeout >= 0:
            time.sleep(min(self._timeout, 20) / 1000)
            raise curses.error("no input")
        raise EOFError("test ran out of keys")

    def dump(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)


def nets():
    return [Item("HomeNet", "home", detail="WPA2/3   5 GHz", bars=4, lock=True),
            Item("Cafe Free WiFi", "cafe", detail="open   2.4 GHz", bars=1, lock=False,
                 hint="Open network: no password."),
            Item("Scan again", "rescan")]


def test_tui_menu_renders_and_selects():
    scr = FakeScreen([curses.KEY_DOWN, "\n"])
    ui = TUI(scr, real=False, brand_right="Secure Boot: on")
    ui.set_step(0)
    assert ui.menu("Choose a WiFi network", "3 networks found on wlan0.", nets()) == "cafe"
    first = scr.frames[0]
    assert "beast-booter" in first and "Secure Boot: on" in first
    assert "1 Network  >  2 Link  >  3 Download  >  4 Done" in first
    assert "Choose a WiFi network" in first and "3 networks found on wlan0." in first
    row = [line for line in first.splitlines() if "HomeNet" in line][0]
    assert row.lstrip("| ").startswith("> HomeNet") and "[||||]  [#]  WPA2/3   5 GHz" in row
    assert "[|...]  [ ]  open" in first
    assert "Open network: no password." in scr.frames[-1]  # hint of the highlighted item
    assert all(len(line) <= 80 for line in first.splitlines())


def test_tui_menu_digits_escape_and_scroll():
    many = [Item(f"Network {i}", i) for i in range(40)]
    scr = FakeScreen([curses.KEY_END, "\n"])
    assert TUI(scr, real=False).menu("Long", "", many) == 39
    assert "Network 39" in scr.frames[-1] and "more^" in scr.frames[-1]
    assert TUI(FakeScreen(["3", "\n"]), real=False).menu("t", "", many) == 2
    assert TUI(FakeScreen(["\x1b"]), real=False).menu("t", "", many) is None
    assert TUI(FakeScreen(["\x1b", "\n"]), real=False).menu("t", "", many, back=False) == 0


def test_tui_form_typing_and_secret():
    keys = list("example.org/x.iso") + ["\n"] + list(SHA[:8]) + [curses.KEY_BACKSPACE, "\n"]
    scr = FakeScreen(keys)
    ui = TUI(scr, real=False)
    v = ui.form("Link", "Type the link.", [Field("url", "ISO link", "https://"),
                                           Field("checksum", "SHA-256 (optional)")])
    assert v == {"url": "https://example.org/x.iso", "checksum": SHA[:7]}
    scr = FakeScreen(list("s3cret!!") + ["\n"])
    v = TUI(scr, real=False).form("Join HomeNet", "", [Field("psk", "Passphrase", secret=True)],
                                  error="The passphrase was not accepted.")
    assert v == {"psk": "s3cret!!"}
    assert "********" in scr.frames[-1] and "s3cret" not in "".join(scr.frames)
    assert "The passphrase was not accepted." in scr.frames[0]
    scr = FakeScreen(list("abc") + [curses.KEY_F0 + 2, "\n"])
    TUI(scr, real=False).form("t", "", [Field("psk", "Passphrase", secret=True)])
    assert "[abc" in scr.frames[-1]  # F2 shows it
    assert TUI(FakeScreen(["\x1b"]), real=False).form("t", "", [Field("a", "A")]) is None


def test_tui_editing_keys():
    keys = [curses.KEY_HOME, "X", curses.KEY_END, "Y", curses.KEY_LEFT, curses.KEY_DC, "\x15", "Z", "\n"]
    assert TUI(FakeScreen(keys), real=False).form("t", "", [Field("a", "A", "mid")]) == {"a": "Z"}
    keys = [curses.KEY_HOME, "X", curses.KEY_END, "Y", "\n"]
    assert TUI(FakeScreen(keys), real=False).form("t", "", [Field("a", "A", "mid")]) == {"a": "XmidY"}


def test_tui_download_progress_and_task():
    scr = FakeScreen()
    ui = TUI(scr, real=False)
    ui.set_step(2)

    def job(progress, cancel):
        progress(Progress("download", 3 * 2 ** 30, 4 * 2 ** 30, 12.5 * 2 ** 20, 81.0, 2 ** 30))
        time.sleep(0.3)
        return "done"
    assert ui.download("Downloading", ["From: https://example.org/x.iso", "To:   /downloads/x.iso"], job) == "done"
    frame = [f for f in scr.frames if "75%" in f][-1]
    assert "3.0 GiB of 4.0 GiB    12.5 MiB/s    1 min 21 s left" in frame
    assert "Resumed at 1.0 GiB." in frame and "To:   /downloads/x.iso" in frame
    assert ui.task("Network", "Asking for an address (DHCP)...", lambda: time.sleep(0.2) or 42) == 42
    assert any("(|)" in f or "(/)" in f for f in scr.frames)


def test_tui_download_cancel():
    scr = FakeScreen(["\x1b", "y"])
    ui = TUI(scr, real=False)

    def job(progress, cancel):
        for _ in range(200):
            if cancel.is_set():
                raise RuntimeError("cancelled")
            time.sleep(0.01)
        return "finished"
    with pytest.raises(RuntimeError):
        ui.download("Downloading", [], job)
    assert any("Cancel the download?" in f for f in scr.frames)


def test_tui_too_small():
    scr = FakeScreen(["\x1b"], h=10, w=30)
    assert TUI(scr, real=False).menu("t", "", nets()) is None
    assert "Terminal too small" in scr.frames[0]


def test_tui_in_a_real_terminal():
    """Real curses (TERM=linux, 80x25) in a pseudo-terminal: draw a menu, press Down, Enter."""
    import pty
    code = (
        "import fcntl, struct, sys, termios\n"
        "fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 25, 80, 0, 0))\n"
        f"sys.path.insert(0, {PKG!r})\n"
        "from beastnet.ui.tui import open_tui\n"
        "from beastnet.ui import Item\n"
        "ui = open_tui('Secure Boot: on')\n"
        "assert ui is not None\n"
        "ui.set_step(0)\n"
        "v = ui.menu('Choose a WiFi network', '2 networks found.', ["
        "Item('HomeNet', 'a', detail='WPA2/3', bars=4, lock=True),"
        "Item('Cafe', 'b', detail='open', bars=1, lock=False)])\n"
        "ui.close()\n"
        "print('RESULT=' + str(v))\n")
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.environ["TERM"] = "linux"
        os.environ["LANG"] = "C.UTF-8"
        os.execv(sys.executable, [sys.executable, "-c", code])
    out = b""

    def read_until(marker, timeout=15.0):
        nonlocal out
        end = time.monotonic() + timeout
        while marker not in out and time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    break
        return marker in out
    try:
        assert read_until(b"Choose a WiFi network"), out[-500:]
        os.write(fd, b"\x1b[B")
        time.sleep(0.2)
        os.write(fd, b"\r")
        assert read_until(b"RESULT="), out[-500:]
        read_until(b"\n", 2)
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)
    assert b"RESULT=b" in out
    assert b"beast-booter" in out and b"HomeNet" in out and b"[||||]" in out
    assert os.waitstatus_to_exitcode(status) == 0


# -- line-based UI --------------------------------------------------------------------

def test_line_ui():
    out = io.StringIO()
    ui = LineUI(io.StringIO("9\n2\n"), out)
    assert ui.menu("Choose a WiFi network", "3 networks.", nets()) == "cafe"
    text = out.getvalue()
    assert " 1) HomeNet   [||||] [#] WPA2/3   5 GHz" in text and "Choose 1-3" in text
    ui = LineUI(io.StringIO("example.org/x.iso\n\n"), io.StringIO())
    assert ui.form("Link", "", [Field("url", "ISO link"), Field("c", "Checksum", "keep")]) == {
        "url": "example.org/x.iso", "c": "keep"}
    assert LineUI(io.StringIO("back\n"), io.StringIO()).form("t", "", [Field("a", "A")]) is None
    assert LineUI(io.StringIO("b\n"), io.StringIO()).menu("t", "", nets()) is None


def test_line_ui_download_and_eof():
    out = io.StringIO()
    ui = LineUI(io.StringIO(""), out)

    def job(progress, cancel):
        progress(Progress("download", 50, 100, 10.0, 5.0))
        time.sleep(0.3)
        return 7
    assert ui.download("Downloading", ["From: x"], job) == 7
    from beastnet.ui import UIClosed
    with pytest.raises(UIClosed):
        ui.menu("t", "", nets())


def test_progress_text_helpers():
    assert bars_text(2) == "[||..]" and bars_text(None) == ""
    assert human_time(5) == "5 s" and human_time(125) == "2 min 05 s" and human_time(None) == "--"
    assert progress_line(Progress("download", 512, 1024, 2048.0, 3.0)).startswith(" 50%")


# -- the interactive flow, with a scripted UI ----------------------------------------------

class ScriptedUI(UI):
    """Answers screens from a list; records what was shown."""

    def __init__(self, answers):
        super().__init__()
        self.answers = list(answers)
        self.shown = []

    def _next(self, kind, title, payload):
        self.shown.append((kind, title, payload))
        assert self.answers, f"no answer left for {kind} {title!r}"
        ans = self.answers.pop(0)
        return ans(payload) if callable(ans) else ans

    def menu(self, title, text, items, *, kind="", back=True):
        return self._next("menu", title, {"text": text, "items": items, "kind": kind})

    def form(self, title, text, fields, *, error=""):
        return self._next("form", title, {"text": text, "fields": fields, "error": error})

    def task(self, title, text, fn):
        self.shown.append(("task", title, text))
        return fn()

    def download(self, title, lines, job):
        self.shown.append(("download", title, lines))
        return job(lambda p: None, threading.Event())


def pick(label):
    def choose(payload):
        for it in payload["items"]:
            if it.label.startswith(label):
                return it.value
        raise AssertionError(f"{label!r} not in {[i.label for i in payload['items']]}")
    return choose


def test_flow_wired_download_and_boot(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/isos/distro.iso", ISO)
    ctx, rep, notes = context(tmp_path, root, certs)
    ui = ScriptedUI([
        {"url": https.url("/isos/distro.iso"), "checksum": SHA},  # Link
        pick("Boot it now"),  # Done
    ])
    with pytest.raises(Quit):
        Interactive(ctx, ui).run()
    done = [s for s in ui.shown if s[0] == "menu" and s[1] == "Done"][0]
    assert "SHA-256 verified" in done[2]["text"] and done[2]["kind"] == "ok"
    assert "does not look like an ISO" not in done[2]["text"]
    assert grubenv.load(str(root / "mnt/esp/grub/grubenv")).get("bb_oneshot") == "/downloads/distro.iso"
    assert "BEASTNET: handoff oneshot=/downloads/distro.iso" in rep.lines
    assert notes[-1] == "[dry-run] would reboot now"
    assert ui.step == 3


def test_flow_plain_http_refused_then_poweroff(tmp_path, http, certs):
    root = make_root(tmp_path)
    ctx, rep, notes = context(tmp_path, root, certs)
    ui = ScriptedUI([
        {"url": http.url("/x.iso"), "checksum": ""},  # refused
        lambda p: None if "refused" in p["error"] else {"url": "?", "checksum": ""},  # Esc
        pick("Power off"),  # More menu
    ])
    with pytest.raises(Quit):
        Interactive(ctx, ui).run()
    assert any(x.startswith("BEASTNET: error refused-plain-http") for x in rep.lines)
    assert notes[-1] == "[dry-run] would poweroff now"


def test_flow_existing_file_keep_both(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    (root / "mnt/data/downloads").mkdir()
    (root / "mnt/data/downloads/x.iso").write_bytes(b"older")
    ctx, rep, notes = context(tmp_path, root, certs)
    ui = ScriptedUI([
        {"url": https.url("/x.iso"), "checksum": ""},
        pick("Keep both"),
        pick("Power off"),
    ])
    with pytest.raises(Quit):
        Interactive(ctx, ui).run()
    assert (root / "mnt/data/downloads/x.iso").read_bytes() == b"older"
    assert (root / "mnt/data/downloads/x-1.iso").read_bytes() == ISO
    done = [s for s in ui.shown if s[1] == "Done"][0]
    assert "Not verified" in done[2]["text"]


def test_flow_wifi(tmp_path, https, site, certs, fast_events):
    from bn_helpers import FakeSys
    from test_net import Clock
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    ctx, rep, notes = context(tmp_path, root, certs, wired=False)
    fs = FakeSys(ctx.paths.sys)
    fs.netdev("wlan0", fs.device("pci", "0000:00:14.3", "iwlwifi", pci_class="0x028000"), wifi=True)
    backend = ctx.net.backend
    backend.runner.iw_output = open(os.path.join(HERE, "data", "iw_scan_mixed.txt")).read()
    backend.clock = Clock()
    fast_events.append(backend.clock)
    fake = FakeWpa(os.path.join(ctx.paths.run, "wpa", "wlan0"),
                   ["<3>CTRL-EVENT-CONNECTED - Connection to 3c:84:6a:12:34:56 completed"])
    ui = ScriptedUI([
        pick("HomeNet"),  # WiFi list
        {"psk": "short"},  # rejected locally
        lambda p: {"psk": "longenough"} if "8 to 63" in p["error"] else None,
        {"url": https.url("/x.iso"), "checksum": SHA},
        pick("Power off"),
    ])
    try:
        with pytest.raises(Quit):
            Interactive(ctx, ui).run()
    finally:
        fake.close()
    wifi_menu = [s for s in ui.shown if s[1] == "Choose a WiFi network"][0]
    labels = [i.label for i in wifi_menu[2]["items"]]
    assert labels[0] == "HomeNet" and "Other network (hidden name)..." in labels
    assert "BEASTNET: net up iface=wlan0 type=wifi ip=10.0.2.15" in rep.lines


def test_flow_no_adapter_menu(tmp_path, certs):
    root = make_root(tmp_path)
    ctx, rep, notes = context(tmp_path, root, certs, wired=False)
    ctx.net.backend.paths.kernel_log = os.path.join(HERE, "data", "kmsg_iwlwifi.txt")
    ui = ScriptedUI([pick("Power off")])
    with pytest.raises(Quit):
        Interactive(ctx, ui).run()
    menu = [s for s in ui.shown if s[0] == "menu"][0]
    assert menu[1] == "Network" and menu[2]["kind"] == "warn"
    assert "No network adapter was found" in menu[2]["text"]
    assert 'install the "Intel WiFi" pack' in menu[2]["text"]
    assert "BEASTNET: firmware missing driver=iwlwifi pack=intel-wifi" in rep.lines


@pytest.fixture
def fast_events(monkeypatch):
    import beastnet.wifi as w
    real = w.WpaCtrl.event
    clocks = []

    def event(self, timeout):
        for c in clocks:
            c.t += 1.0
        return real(self, 0.02)
    monkeypatch.setattr(w.WpaCtrl, "event", event)
    return clocks
