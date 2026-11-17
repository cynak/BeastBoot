"""beast-net add-ons end to end (beastnet/README.md "Add-ons"): the delivery path.

An add-on reaches the helper as one more initrd archive that the boot loader passes after
the helper's own `initrd.img`; the kernel unpacks it over the initramfs, and the helper
starts what it finds in /usr/lib/beastnet/addons/. Here BeastBoot's own menu is the boot
loader: it passes every ESP:/beast-net/firmware/*.cpio as an extra initrd (firmware packs
use that), so the test puts a toy add-on there. The toy add-on prints marker lines through
the helper's reporter and wraps the screen; the test reads them on the serial console.

BeastBoot itself ships no add-on and no way to add kernel parameters to the helper's
command line, so parameters for add-ons are covered by the unit tests
(beastnet/tests/test_addons.py), not here.
"""

from __future__ import annotations

import re

import pytest

from bbe2e import beastnet as bn
from bbe2e import env

pytestmark = [pytest.mark.slow, pytest.mark.beastnet]

MODES = [pytest.param("uefi", marks=pytest.mark.uefi, id="uefi"),
         pytest.param("uefi-sb", marks=pytest.mark.secureboot, id="uefi-sb-enrolled")]
HELPER_TIMEOUT = 180
ADDON_DIR = "usr/lib/beastnet/addons"
HELPER_VERSION = re.search(r'__version__ = "([^"]+)"',
                           (env.BB_ROOT / "beastnet/python/beastnet/__init__.py").read_text()).group(1)

TOY = b'''\
"""A toy add-on for tests/e2e/test_e2e_addons.py."""
from beastnet.ui import UI


class Toy(UI):
    """Passes every screen on to the local UI and says so once."""

    def __init__(self, local, say):
        super().__init__()
        self.local, self.say, self.said = local, say, False
        self.subtitle, self.steps, self.step = local.subtitle, local.steps, local.step

    def _seen(self, kind):
        if not self.said:
            self.said = True
            self.say("toy-addon screen", f"kind={kind}", f"local={type(self.local).__name__}")

    def set_step(self, step):
        super().set_step(step)
        self.local.set_step(step)

    def set_mode(self, *a, **kw):
        old = super().set_mode(*a, **kw)
        self.local.set_mode(*a, **kw)
        return old

    def menu(self, *a, **kw):
        self._seen("menu")
        return self.local.menu(*a, **kw)

    def form(self, *a, **kw):
        self._seen("form")
        return self.local.form(*a, **kw)

    def task(self, *a, **kw):
        self._seen("task")
        return self.local.task(*a, **kw)

    def download(self, *a, **kw):
        self._seen("download")
        return self.local.download(*a, **kw)

    def document(self, *a, **kw):
        self._seen("document")
        return self.local.document(*a, **kw)

    def shell(self, fn):
        return self.local.shell(fn)

    def close(self):
        self.local.close()


def start(params, ui, ctx, version):
    from . import part
    ctx.reporter.emit("toy-addon start", f"version={version}", f"sb={int(params.sb)}",
                      f"file={__file__}", f"part={part.VALUE}", f"extra={len(params.extra)}")
    return Toy(ui, ctx.reporter.emit)
'''

BROKEN = b"def start(params, ui, ctx, version):\n    raise RuntimeError('this add-on is broken')\n"


@pytest.fixture
def addon_drive(base_drives, workdir, dist_dir):
    d = dist_dir / "esp" / "beast-net"
    missing = env.missing_files([d / "vmlinuz", d / "initrd.img", d / "VERSION"])
    if missing:
        pytest.skip("dist/ has no beast-net helper (make build): " + ", ".join(missing))
    drive = bn.empty_drive(base_drives("browse"), workdir / "addon.img", bn.config())
    # two add-ons in one archive: "broken" raises (and must not stop the helper), "toy" runs
    bn.install_extra_initrd(drive, "addons", {
        f"{ADDON_DIR}/broken/__init__.py": BROKEN,
        f"{ADDON_DIR}/toy/__init__.py": TOY,
        f"{ADDON_DIR}/toy/part.py": b"VALUE = 'second-file'\n",
    })
    # the same toy on the data partition, where the helper must never look
    with drive.data_writer() as w:
        w.mkdir("/usr")
        w.mkdir("/usr/lib")
        w.mkdir("/usr/lib/beastnet")
        w.mkdir("/usr/lib/beastnet/addons")
        w.mkdir("/usr/lib/beastnet/addons/fromdata")
        w.put("/usr/lib/beastnet/addons/fromdata/__init__.py", TOY.replace(b"toy-addon", b"data-addon"))
    return drive


@pytest.mark.parametrize("mode", MODES)
def test_an_addon_in_a_second_initrd_is_started(addon_drive, vm_factory, request, mode):
    drive = addon_drive
    kw = {"memory": 1536, "hard_timeout": 420}
    if mode == "uefi-sb":
        request.getfixturevalue("secureboot_ok")
        kw["mok_certs"] = [request.getfixturevalue("mok_cert")]
    vm = vm_factory(mode, drive.path, **kw)
    boot = bn.select_entry(vm)
    ready = bn.fields(bn.wait_line(vm, "ready ", timeout=HELPER_TIMEOUT, after=boot.end))
    assert ready.get("sb") == ("1" if mode == "uefi-sb" else "0"), ready
    # the broken one first (name order): one line, and the helper goes on
    failed = bn.wait_line(vm, "addon broken ", timeout=60, after=boot.end)
    assert failed == "addon broken failed RuntimeError: this add-on is broken", failed
    start = bn.fields(bn.wait_line(vm, "toy-addon start ", timeout=60, after=boot.end))
    assert start.get("file") == f"/{ADDON_DIR}/toy/__init__.py", start
    assert start.get("part") == "second-file" and start.get("extra") == "0", start
    assert start.get("sb") == ready.get("sb"), start
    assert start.get("version") == HELPER_VERSION, start
    assert bn.wait_line(vm, "addon toy started", timeout=60, after=boot.end) == "addon toy started ui=wrapped"
    # the helper's screens go through the UI the add-on returned
    screen = bn.fields(bn.wait_line(vm, "toy-addon screen ", timeout=120, after=boot.end))
    assert screen.get("local") == "LineUI", screen
    assert not [x for x in bn.lines(vm, boot.end) if "data-addon" in x or "fromdata" in x], bn.lines(vm, boot.end)
