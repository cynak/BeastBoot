"""GUI controller: drive eligibility, options, CLI command line, state machine, cancel.

No tkinter needed: the controller is plain Python. Device operations go to a
FakeBackend whose run_elevated() returns a FakeProcess the test controls; the
test plays the CLI's part by appending lines to the --progress-file.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from beastbooter.errors import BeastError
from beastbooter.gui import controller as ctl
from beastbooter.gui import distinfo
from beastbooter.gui.controller import (
    ACK_TEXT,
    Controller,
    JobSpec,
    Options,
    Phase,
    StateError,
    build_cli_argv,
    check_image_size,
    check_options,
    drive_problem,
    drive_rows,
)
from beastbooter.interfaces import DiskInfo
from beastbooter.layout import MIN_DISK_MIB

GB = 1000**3


def disk(id="/dev/sdb", model="SanDisk Ultra", size=32 * GB, bus="usb", removable=True,
         system=False, read_only=False, mountpoints=()) -> DiskInfo:
    return DiskInfo(id=id, path=id, model=model, size=size, sector_size=512, bus=bus,
                    removable=removable, system=system, read_only=read_only, mountpoints=mountpoints)


STICK = disk(mountpoints=("/media/u/STICK",))
STICK2 = disk("/dev/sdc", "Kingston DataTraveler", 16 * GB)
SDCARD_RO = disk("/dev/sdd", "SD card", 8 * GB, bus="sd", read_only=True)
TINY = disk("/dev/sde", "Promo stick", 128 * 1024 * 1024)
EMPTY_READER = disk("/dev/sdi", "Card reader", 0, bus="sd")
USB_SSD = disk("/dev/sdf", "Samsung T7", 500 * GB, removable=False)
SATA = disk("/dev/sdg", "WDC WD20", 2000 * GB, bus="sata", removable=False)
SYSTEM = disk("/dev/nvme0n1", "Samsung 990", 1000 * GB, bus="nvme", removable=False, system=True,
              mountpoints=("/", "/boot/efi"))
ALL = [SYSTEM, STICK, SDCARD_RO, TINY, USB_SSD, SATA, STICK2, EMPTY_READER]


class FakeProcess:
    def __init__(self, argv):
        self.argv = argv
        self.rc = None
        self.cancels = 0

    @property
    def progress_file(self) -> str:
        return self.argv[self.argv.index("--progress-file") + 1]

    def emit(self, raw: str) -> None:
        with open(self.progress_file, "a", encoding="utf-8") as f:
            f.write(raw)

    def event(self, **ev) -> None:
        self.emit(json.dumps({"v": 1, **ev}) + "\n")

    def poll(self):
        return self.rc

    def wait(self, timeout=None):
        return self.rc

    def cancel(self):
        self.cancels += 1


class FakeBackend:
    name = "linux"

    def __init__(self, disks=ALL, elevated=False):
        self.disks = {d.id: d for d in disks}
        self.elevated = elevated
        self.list_calls = []
        self.procs: list[FakeProcess] = []
        self.list_error: Exception | None = None
        self.elevate_error: Exception | None = None

    def list_disks(self, *, include_fixed=False):
        self.list_calls.append(include_fixed)
        if self.list_error:
            raise self.list_error
        return [d for d in self.disks.values()
                if include_fixed or ((d.removable or d.bus in ("usb", "sd")) and not d.system)]

    def get_disk(self, device):
        try:
            return self.disks[device]
        except KeyError:
            raise BeastError(f"{device}: no such disk") from None

    def is_elevated(self):
        return self.elevated

    def run_elevated(self, argv):
        if self.elevate_error:
            raise self.elevate_error
        p = FakeProcess(argv)
        self.procs.append(p)
        return p


@pytest.fixture
def dist_loc(fake_dist) -> distinfo.DistLocation:
    return distinfo.DistLocation(fake_dist, "--dist")


@pytest.fixture
def backend():
    return FakeBackend()


@pytest.fixture
def make(dist_loc, backend, tmp_path):
    launcher = tmp_path / "app" / "beast_booter_launch.py"
    launcher.parent.mkdir()
    launcher.write_text("# stand-in launcher\n")

    def _make(**kw) -> Controller:
        kw.setdefault("backend_factory", lambda: backend)
        kw.setdefault("dist", dist_loc)
        kw.setdefault("launcher", launcher)
        kw.setdefault("python", sys.executable)
        kw.setdefault("tmp_root", str(tmp_path))
        return Controller(spawn=ctl.inline_spawn, **kw)

    return _make


def ready(c: Controller, drive_id=STICK.id) -> Controller:
    c.refresh_drives()
    c.poll()
    assert c.select_drive(drive_id) is None
    return c


# ---------------------------------------------------------------------------
# drive eligibility and filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("d, problem", [
    (STICK, None),
    (STICK2, None),
    (SYSTEM, "holds the running system"),
    (SDCARD_RO, "write-protected"),
    (USB_SSD, None),  # USB SSDs report removable=0 but are external: eligible, like the CLI
    (SATA, "internal disk"),
    (TINY, f"too small (min. {MIN_DISK_MIB} MiB)"),
    (EMPTY_READER, "no medium"),
    (disk(size=MIN_DISK_MIB * 1024 * 1024), None),  # exactly the minimum
    (disk(size=MIN_DISK_MIB * 1024 * 1024 - 512), f"too small (min. {MIN_DISK_MIB} MiB)"),
])
def test_drive_problem(d, problem):
    assert drive_problem(d) == problem


def test_system_wins_over_everything():
    # a removable system disk (live USB the OS runs from) is never eligible
    assert drive_problem(disk(system=True, removable=True)) == "holds the running system"


def test_problem_details_explain_each_reason():
    for d in ALL:
        if p := drive_problem(d):
            assert len(ctl.problem_detail(p)) > len(p)
    assert "internal" in ctl.problem_detail("internal disk")


def test_default_view_hides_internal_and_system_even_if_backend_returns_them():
    rows = drive_rows(ALL, show_all=False)
    ids = [r.id for r in rows]
    assert SYSTEM.id not in ids and SATA.id not in ids
    # external (removable or USB/SD) drives are listed; unusable ones greyed out after the usable ones
    assert ids == [STICK.id, USB_SSD.id, STICK2.id, SDCARD_RO.id, TINY.id, EMPTY_READER.id]
    assert [r.eligible for r in rows] == [True, True, True, False, False, False]


def test_show_all_lists_everything_but_internal_stay_ineligible():
    rows = drive_rows(ALL, show_all=True)
    assert {r.id for r in rows} == {d.id for d in ALL}
    for r in rows:
        assert r.eligible == (r.id in (STICK.id, USB_SSD.id, STICK2.id))
    assert rows[0].eligible and rows[1].eligible and rows[2].eligible  # usable first, backend order kept
    assert [r.id for r in rows if not r.eligible][0] == SYSTEM.id


def test_row_texts():
    row = drive_rows([STICK], show_all=False)[0]
    assert row.title == "SanDisk Ultra"
    assert row.size_text == "29.8 GiB"
    assert row.bus_text == "USB"
    assert row.notes == "In use: /media/u/STICK"
    assert row.describe() == "SanDisk Ultra (29.8 GiB, USB, /dev/sdb)"
    nameless = drive_rows([disk(model="  ")], show_all=False)[0]
    assert nameless.title == "Unknown drive"
    assert drive_rows([SATA], show_all=True)[0].notes == "Not usable: internal disk"


def test_refresh_and_show_all_pass_include_fixed(make, backend):
    c = make()
    c.refresh_drives()
    c.poll()
    assert backend.list_calls == [False]
    assert {r.id for r in c.rows} == {STICK.id, USB_SSD.id, STICK2.id, SDCARD_RO.id, TINY.id, EMPTY_READER.id}
    v = c.rows_version
    c.set_show_all(True)
    c.poll()
    assert backend.list_calls == [False, True]
    assert len(c.rows) == len(ALL) and c.rows_version > v
    c.set_show_all(True)  # unchanged: no extra listing
    assert backend.list_calls == [False, True]


def test_ineligible_drive_cannot_be_selected(make):
    c = make()
    c.set_show_all(True)
    c.poll()
    for d in (SYSTEM, SATA, SDCARD_RO, TINY):
        assert c.select_drive(d.id) == drive_problem(d)
        assert c.selected_id is None
        assert c.install_blocker() == "Select a USB drive."
        with pytest.raises(BeastError):
            c.request_install()
    assert c.select_drive("/dev/nope") is None and c.selected_id is None
    assert c.select_drive(STICK.id) is None and c.selected_id == STICK.id


def test_single_usable_drive_is_preselected(make, backend):
    backend.disks = {d.id: d for d in (STICK, SDCARD_RO, SYSTEM)}
    c = make()
    c.refresh_drives()
    c.poll()
    assert c.selected_id == STICK.id


def test_two_usable_drives_are_not_preselected(make):
    c = make()
    c.refresh_drives()
    c.poll()
    assert c.selected_id is None


def test_selection_survives_refresh_unless_drive_disappears(make, backend):
    c = ready(make(), STICK2.id)
    c.refresh_drives()
    c.poll()
    assert c.selected_id == STICK2.id
    del backend.disks[STICK2.id]
    del backend.disks[USB_SSD.id]
    c.refresh_drives()
    c.poll()
    assert c.selected_id == STICK.id  # now the only usable drive


def test_listing_error_is_shown_not_raised(make, backend):
    backend.list_error = OSError(5, "Input/output error")
    c = make()
    c.refresh_drives()
    c.poll()
    assert c.rows == [] and not c.loading
    assert c.list_error.startswith("Could not list drives: Input/output error")
    backend.list_error = None
    c.refresh_drives()
    c.poll()
    assert c.list_error is None and c.rows


def test_backend_unavailable_still_allows_images(make):
    def broken():
        raise ImportError("No module named 'beastbooter.platforms'")

    c = make(backend_factory=broken)
    c.refresh_drives()
    assert "Drive access is not available" in c.list_error
    assert "beastbooter.platforms" in c.backend_error
    assert c.image_blocker() is None
    assert c.platform in ("linux", "windows", "darwin")


def test_stale_listing_result_is_ignored(make, backend):
    tasks = []
    c = make()
    c._spawn = tasks.append  # run background work by hand
    c.refresh_drives()  # show_all=False
    c.set_show_all(True)  # a second listing starts before the first finished
    second, first = tasks[1], tasks[0]
    second.run()
    c.poll()
    assert len(c.rows) == len(ALL)
    first.run()
    c.poll()  # the older result arrives late: ignored
    assert len(c.rows) == len(ALL) and not c.loading


# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------


def test_default_options_are_valid():
    chk = check_options(Options(), "linux")
    assert chk.ok and chk.label == "BEASTBOOTER"
    assert Options() == Options("msdos", "exfat", "BEASTBOOTER")
    assert set(chk.notes) == {"layout", "fs"}


@pytest.mark.parametrize("label, fs, error", [
    ("", "exfat", "Enter a volume label."),
    ("my drive!", "exfat", "use letters, digits"),
    (" lead", "exfat", "use letters, digits"),
    ("trail ", "exfat", "use letters, digits"),
    ("ABCDEFGHIJKL", "fat32", "too long for fat32 (max 11"),
    ("ABCDEFGHIJKL", "exfat", "too long for exfat (max 11"),
    ("A" * 33, "ntfs", "too long for ntfs (max 32"),
    ("Ünïcode", "exfat", "use letters, digits"),
    ('a"b', "exfat", "use letters, digits"),
])
def test_label_validation_uses_cli_rules(label, fs, error):
    chk = check_options(Options("msdos", fs, label), "linux")
    assert not chk.ok
    assert error in chk.errors["label"]
    assert chk.label == ""


def test_label_limits_differ_per_fs():
    assert check_options(Options("gpt", "exfat", "ABCDEFGHIJK"), "linux").ok  # exFAT: up to 11
    assert not check_options(Options("gpt", "exfat", "ABCDEFGHIJKL"), "linux").ok
    assert check_options(Options("gpt", "ntfs", "A" * 32), "linux").ok


def test_fat32_label_is_upper_cased_with_a_note():
    chk = check_options(Options("msdos", "fat32", "usb-multi"), "linux")
    assert chk.ok and chk.label == "USB-MULTI"
    assert "USB-MULTI" in chk.notes["label"]
    assert check_options(Options("msdos", "exfat", "usb-multi"), "linux").label == "usb-multi"


def test_label_may_start_with_dash():
    assert check_options(Options("msdos", "exfat", "-x-"), "linux").ok


def test_ntfs_note_and_macos_refusal():
    chk = check_options(Options("msdos", "ntfs", "X"), "linux")
    assert chk.ok and "Secure Boot" in chk.notes["fs"]
    for platform in ("windows", "linux"):
        assert check_options(Options("msdos", "ntfs", "X"), platform).ok
    mac = check_options(Options("msdos", "ntfs", "X"), "darwin")
    assert not mac.ok and "macOS" in mac.errors["fs"]


def test_unknown_layout_and_fs():
    chk = check_options(Options("bsd", "zfs", "X"), "linux")
    assert set(chk.errors) == {"layout", "fs"}


def test_set_option_only_when_idle(make):
    c = ready(make())
    c.set_option("fs", "fat32")
    c.set_option("label", "abc")
    assert c.options == Options("msdos", "fat32", "abc")
    assert c.options_check.label == "ABC"
    with pytest.raises(ValueError):
        c.set_option("size", "1")
    c.request_install()
    with pytest.raises(StateError):
        c.set_option("fs", "exfat")


def test_invalid_options_block_install_and_image_but_not_update(make):
    c = ready(make())
    c.set_option("label", "bad label!")
    assert c.install_blocker() == "Fix the options first."
    assert c.image_blocker() == "Fix the options first."
    assert c.update_blocker() is None
    with pytest.raises(BeastError):
        c.request_install()


def test_macos_controller_refuses_ntfs(make, backend):
    backend.name = "darwin"
    c = ready(make())
    c.set_option("fs", "ntfs")
    assert not c.options_check.ok
    assert c.install_blocker() == "Fix the options first."


@pytest.mark.parametrize("text, size", [("4G", 4 << 30), ("1024M", 1 << 30), (" 1g ", 1 << 30),
                                        (str(1_500_000_001), 1_500_000_001), ("2GiB", 2 << 30)])
def test_image_size(text, size):
    assert check_image_size(text) == size


@pytest.mark.parametrize("text", ["", "100M", "1023M", "abc", "-4G", "0", "4X"])
def test_image_size_rejected(text):
    with pytest.raises(BeastError):
        check_image_size(text)


# ---------------------------------------------------------------------------
# the CLI command line
# ---------------------------------------------------------------------------

R = "C:" if os.name == "nt" else ""  # an absolute path needs a drive on Windows
PY = R + "/opt/bb/python/bin/python3"
LAUNCH = R + "/opt/bb/app/beast_booter_launch.py"
PF = R + "/tmp/bb-gui-x/progress.jsonl"
DIST = R + "/opt/bb/payload/dist"


def test_install_device_argv():
    spec = JobSpec("install", "device", "/dev/sdb", disk=STICK, options=Options("gpt", "fat32", "MY DRIVE"))
    argv = build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST)
    assert argv == [PY, "-s", "-E", "-B", LAUNCH, "install", "--device", "/dev/sdb", "--yes",
                    "--progress-file", PF, "--dist", DIST, "--layout", "gpt", "--fs", "fat32",
                    "--label=MY DRIVE"]
    assert "--allow-fixed-disk" not in argv  # the GUI never overrides the safety checks
    assert "--cancel-file" not in argv  # only when asked for: the real CLI does not know it yet


def test_argv_with_cancel_file():
    spec = JobSpec("update", "device", "/dev/sdb", disk=STICK)
    argv = build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST,
                          cancel_file=R + "/tmp/bb-gui-x/cancel")
    i = argv.index("--cancel-file")
    assert argv[i + 1] == R + "/tmp/bb-gui-x/cancel"
    with pytest.raises(BeastError, match="absolute"):
        build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST, cancel_file="cancel")


def test_cli_cancel_file_is_on_now_that_the_cli_has_it():
    assert ctl.CLI_HAS_CANCEL_FILE is True


def test_update_device_argv_has_no_install_options():
    spec = JobSpec("update", "device", r"\\.\PhysicalDrive2", disk=STICK)
    argv = build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST)
    assert argv[5:8] == ["update", "--device", r"\\.\PhysicalDrive2"]
    assert not any(a.startswith(("--layout", "--fs", "--label", "--size")) for a in argv)


def test_image_argv_uses_byte_size():
    spec = JobSpec("install", "image", R + "/home/u/my images/bb 'test'.img", options=Options(), image_size=4 << 30)
    argv = build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST)
    i = argv.index("--image")
    assert argv[i + 1] == R + "/home/u/my images/bb 'test'.img"  # one element, unquoted
    assert argv[i + 2 : i + 4] == ["--size", str(4 << 30)]


def test_argv_is_quoting_safe():
    nasty = 'a b"c;$(rm -rf ~)`x`'
    spec = JobSpec("install", "image", R + f"/tmp/{nasty}.img", options=Options(label="-x y"), image_size=1 << 30)
    argv = build_cli_argv(spec, python=PY, launcher=LAUNCH, progress_file=PF, dist=R + "/d i s t")
    assert R + f"/tmp/{nasty}.img" in argv and R + "/d i s t" in argv
    assert "--label=-x y" in argv  # a label starting with "-" can't be taken for an option
    assert all(isinstance(a, str) for a in argv)


@pytest.mark.parametrize("field", ["python", "launcher", "progress_file", "dist"])
def test_argv_requires_absolute_paths(field):
    kw = dict(python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST)
    kw[field] = "relative/path"
    with pytest.raises(BeastError, match="absolute"):
        build_cli_argv(JobSpec("update", "device", "/dev/sdb"), **kw)
    kw[field] = ""
    with pytest.raises(BeastError):
        build_cli_argv(JobSpec("update", "device", "/dev/sdb"), **kw)


def test_argv_rejects_bad_jobs():
    kw = dict(python=PY, launcher=LAUNCH, progress_file=PF, dist=DIST)
    with pytest.raises(BeastError):
        build_cli_argv(JobSpec("install", "image", "rel.img", options=Options(), image_size=1 << 30), **kw)
    with pytest.raises(BeastError):
        build_cli_argv(JobSpec("install", "image", "/a.img", options=Options()), **kw)
    with pytest.raises(BeastError):
        build_cli_argv(JobSpec("install", "device", "/dev/sdb"), **kw)
    with pytest.raises(BeastError):
        build_cli_argv(JobSpec("format", "device", "/dev/sdb"), **kw)


def test_controller_passes_absolute_paths_to_run_elevated(make, backend, dist_loc):
    c = ready(make())
    c.set_option("label", "my stick")
    c.request_install()
    c.confirm(True)
    argv = backend.procs[0].argv
    assert argv[:4] == [sys.executable, "-s", "-E", "-B"]  # -B: no root-owned __pycache__ in the package
    assert os.path.isabs(argv[4]) and argv[4].endswith("beast_booter_launch.py")
    cf = argv[argv.index("--cancel-file") + 1]  # the default now: the CLI has --cancel-file
    assert os.path.isabs(cf) and not os.path.exists(cf) and os.path.dirname(cf) == os.path.dirname(
        argv[argv.index("--progress-file") + 1])
    pf = argv[argv.index("--progress-file") + 1]
    assert os.path.isabs(pf) and os.path.isfile(pf)  # created by the GUI, before elevation
    assert argv[argv.index("--dist") + 1] == str(dist_loc.path) and os.path.isabs(str(dist_loc.path))
    assert "--label=my stick" in argv and "--yes" in argv


def test_already_elevated_runs_cli_directly(make, backend, monkeypatch):
    started = []

    class Local(FakeProcess):
        def __init__(self, argv, output):
            super().__init__(argv)
            started.append(argv)

    monkeypatch.setattr(ctl, "LocalProcess", Local)
    backend.elevated = True
    c = ready(make())
    c.request_install()
    c.confirm(True)
    assert started and not backend.procs
    assert c.job.elevated is False


# ---------------------------------------------------------------------------
# state machine: idle -> confirming -> running -> done / failed
# ---------------------------------------------------------------------------

def run_to_running(c: Controller, backend: FakeBackend) -> FakeProcess:
    req = c.request_install()
    assert c.phase is Phase.CONFIRMING and c.confirm_request is req
    c.confirm(True)
    assert c.phase is Phase.RUNNING
    return backend.procs[-1]


def test_confirmation_names_the_drive_and_needs_the_checkbox(make, backend):
    c = ready(make())
    req = c.request_install()
    assert req.needs_ack and req.ack_text == ACK_TEXT == "I understand all data on it will be erased"
    assert req.drive == "SanDisk Ultra (29.8 GiB, USB, /dev/sdb)"
    text = " ".join(req.details)
    assert "erased" in text and "exFAT" in text and "BEASTBOOTER" in text and "MBR" in text
    assert "/media/u/STICK" in text  # its mounted volume will be unmounted
    assert req.confirm_label == "Erase and install"
    with pytest.raises(BeastError, match="Tick"):
        c.confirm(False)
    assert c.phase is Phase.CONFIRMING and not backend.procs  # nothing started
    c.cancel_confirm()
    assert c.phase is Phase.IDLE and c.confirm_request is None


def test_full_success(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    assert c.poll() is False and c.progress.started is False  # waiting for the password prompt
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="step", step="verify-dist", message="Checking", pct=3)
    p.event(event="step", step="partition", message="Partitioning", pct=20)
    assert c.poll() is True
    assert c.progress.started and c.progress.pct == 20 and c.progress.message == "Partitioning"
    p.event(event="warning", message="slow drive")
    p.emit('{"v":1,"event":"step","step":"write-esp","mess')  # half a line
    c.poll()
    assert c.progress.step == "partition"
    p.emit('age":"Writing","pct":60}\n')
    c.poll()
    assert c.progress.step == "write-esp" and c.progress.warnings == ["slow drive"]
    info = {"layout": "msdos", "version": "0.1.0", "data": {"label": "BEASTBOOTER", "fs": "exfat"}}
    p.event(event="done", ok=True, info=info)
    p.rc = 0
    assert c.poll() is True
    assert c.phase is Phase.DONE
    o = c.outcome
    assert o.ok and o.info == info and o.title == "beast-booter is ready"
    assert "SanDisk Ultra" in o.message and "0.1.0" in o.message
    assert not os.path.exists(os.path.dirname(p.progress_file))  # temp dir cleaned up
    steps = c.next_steps(o)
    assert "BEASTBOOTER" in steps[0]
    assert "ENROLL_THIS_KEY_IN_MOKMANAGER.cer" in steps[-1] and "MokManager" in steps[-1]
    assert any("slow drive" in line.text for line in c.log)
    c.dismiss()
    assert c.phase is Phase.IDLE and c.outcome is None


def test_failure_with_error_event(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="step", step="check-target", message="Checking", pct=5)
    p.event(event="error", code="unsafe-target", message="refusing: /dev/sdb1 is mounted")
    p.rc = 1
    c.poll()
    assert c.phase is Phase.FAILED
    o = c.outcome
    assert not o.ok and o.code == "unsafe-target" and o.message == "refusing: /dev/sdb1 is mounted"
    assert o.exit_code == 1 and o.title == "Installation failed"
    assert "nothing was written" in o.target_state
    c.dismiss()
    assert c.phase is Phase.IDLE


def test_failure_after_writing_says_drive_needs_reinstall(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="step", step="format-data", pct=30)
    p.event(event="error", code="write-failed", message="I/O error")
    p.rc = 1
    c.poll()
    assert "install beast-booter on it again" in c.outcome.target_state


def test_update_failure_after_writing_keeps_user_files_message(make, backend):
    c = ready(make())
    req = c.request_update()
    assert not req.needs_ack and "not touched" in " ".join(req.details)
    c.confirm()
    p = backend.procs[-1]
    assert p.argv[5] == "update"
    p.event(event="start", action="update", target="/dev/sdb")
    p.event(event="step", step="write-esp", pct=50)
    p.rc = 7  # crashed: no error event
    c.poll()
    o = c.outcome
    assert c.phase is Phase.FAILED and o.code == "exit-7" and "unexpectedly" in o.message
    assert o.title == "Update failed" and "run Update again" in o.target_state


def test_elevation_prompt_cancelled(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.rc = ctl.ELEVATION_CANCELLED  # the user dismissed the password / UAC dialog
    c.poll()
    o = c.outcome
    assert c.phase is Phase.FAILED and o.code == "elevation-cancelled" and o.cancelled
    assert o.target_state == "Nothing was written."


def test_elevation_failed(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.rc = ctl.ELEVATION_FAILED
    c.poll()
    assert c.outcome.code == "elevation-failed" and "polkit" in c.outcome.message


def test_elevation_codes_match_the_platform_backends():
    platforms = pytest.importorskip("beastbooter.platforms")
    assert (ctl.ELEVATION_CANCELLED, ctl.ELEVATION_FAILED) == (platforms.ELEVATION_CANCELLED,
                                                             platforms.ELEVATION_FAILED)


def test_exit_126_after_start_is_a_cli_failure(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.rc = 126
    c.poll()
    assert c.outcome.code == "exit-126"


def test_not_started_without_elevation_code(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.rc = 2  # e.g. an argparse error in an older CLI
    c.poll()
    o = c.outcome
    assert o.code == "not-started" and "exit code 2" in o.message
    assert o.target_state == "Nothing was written."


def test_virtual_disks_sort_last():
    loop = disk("/dev/loop0", "", 500 * 1024 * 1024, bus="virtual", read_only=True, removable=False)
    rows = drive_rows([loop, SATA, STICK], show_all=True)
    assert [r.id for r in rows] == [STICK.id, SATA.id, loop.id]


def test_run_elevated_error(make, backend):
    backend.elevate_error = BeastError("pkexec not found")
    c = ready(make())
    c.request_install()
    c.confirm(True)
    assert c.phase is Phase.FAILED
    assert c.outcome.code == "start-failed" and c.outcome.message == "pkexec not found"
    assert not list(Path(c._tmp_root).glob("beast-booter-gui-*"))  # temp dir removed


def test_missing_launcher_fails_cleanly(make, backend, tmp_path):
    c = ready(make(launcher=tmp_path / "nowhere" / "beast_booter_launch.py"))
    c.request_install()
    c.confirm(True)
    assert c.phase is Phase.FAILED and "missing" in c.outcome.message
    assert not backend.procs


def test_success_requires_exit_code_zero(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="done", ok=True, info={})
    p.rc = 1
    c.poll()
    assert c.phase is Phase.FAILED and c.outcome.code == "exit-1"


def test_done_not_ok_is_a_failure(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="done", ok=False, info=None)
    p.rc = 0
    c.poll()
    assert c.phase is Phase.FAILED and c.outcome.code == "not-ok"


def test_exit_zero_without_done_event_is_success_with_note(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.rc = 0
    c.poll()
    assert c.phase is Phase.DONE
    assert any("did not report a result" in line.text for line in c.log)


def test_unterminated_last_line_is_read_after_exit(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.emit(json.dumps({"v": 1, "event": "error", "code": "boom", "message": "no newline"}))
    c.poll()
    assert c.progress.error_code is None  # still a partial line while running
    p.rc = 1
    c.poll()
    assert c.outcome.code == "boom"


def test_unknown_and_garbage_lines_do_not_change_the_outcome(make, backend):
    c = ready(make())
    p = run_to_running(c, backend)
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="telemetry", foo=1)
    p.emit("Traceback (most recent call last):\n")
    p.event(event="step", step="partition", pct=200)
    p.rc = 0
    c.poll()
    assert c.phase is Phase.DONE
    assert any("unknown event 'telemetry'" in line.text for line in c.log)
    assert any("not JSON" in line.text for line in c.log)


def test_wrong_phase_actions_raise(make, backend):
    c = ready(make())
    with pytest.raises(StateError):
        c.confirm(True)
    with pytest.raises(StateError):
        c.cancel()
    with pytest.raises(StateError):
        c.dismiss()
    with pytest.raises(StateError):
        c.cancel_confirm()
    run_to_running(c, backend)
    for action in (c.request_install, c.request_update, c.dismiss, c.cancel_confirm):
        with pytest.raises(StateError):
            action()
    with pytest.raises(StateError):
        c.start_image("/tmp/x.img", "1G")
    assert c.install_blocker() == "Busy."


def test_busy_reports_running_job(make, backend):
    c = ready(make())
    assert not c.busy()
    p = run_to_running(c, backend)
    assert c.busy()
    p.rc = 0
    c.poll()
    assert not c.busy()


# ---------------------------------------------------------------------------
# the drive changed between listing and confirming
# ---------------------------------------------------------------------------


def test_swapped_drive_is_refused_at_confirm(make, backend):
    c = ready(make())
    c.request_install()
    # unplugged, and another stick got the same name
    backend.disks[STICK.id] = replace(STICK, model="Other stick", size=8 * GB)
    with pytest.raises(BeastError, match="has changed.*Nothing was written"):
        c.confirm(True)
    assert c.phase is Phase.IDLE and not backend.procs


def test_unplugged_drive_is_refused_at_confirm(make, backend):
    c = ready(make())
    c.request_install()
    del backend.disks[STICK.id]
    with pytest.raises(BeastError, match="no longer available"):
        c.confirm(True)
    assert c.phase is Phase.IDLE and not backend.procs


def test_drive_that_became_ineligible_is_refused(make, backend):
    c = ready(make())
    c.request_update()
    backend.disks[STICK.id] = replace(STICK, read_only=True)
    with pytest.raises(BeastError, match="write-protected"):
        c.confirm()
    assert not backend.procs


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------


def test_elevated_run_without_cancel_channel_cannot_be_stopped(make, backend):
    """The elevated CLI runs as root / with an elevated token: signalling the
    elevation wrapper does nothing (pkexec) or loses track of it (osascript).
    So the GUI does not pretend: cancel() refuses and the run goes on."""
    c = ready(make(cancel_file=False))
    p = run_to_running(c, backend)
    assert c.job.elevated and not c.can_cancel
    with pytest.raises(BeastError, match="can't stop it"):
        c.cancel()
    assert p.cancels == 0 and not c.cancel_requested
    c.shutdown()  # closing the window leaves it running too
    assert p.cancels == 0 and c.phase is Phase.RUNNING
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="done", ok=True, info={})
    p.rc = 0
    c.poll()
    assert c.phase is Phase.DONE and c.outcome.ok


def test_cancel_file_asks_the_elevated_cli_to_stop(make, backend):
    c = ready(make(cancel_file=True))
    p = run_to_running(c, backend)
    cancel_file = p.argv[p.argv.index("--cancel-file") + 1]
    assert os.path.isabs(cancel_file) and not os.path.exists(cancel_file)
    assert os.path.dirname(cancel_file) == os.path.dirname(p.progress_file)  # the private temp dir
    if os.name == "posix":
        assert os.stat(os.path.dirname(cancel_file)).st_mode & 0o077 == 0  # nobody else can create it
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="step", step="write-esp", pct=50)
    c.poll()
    assert c.can_cancel
    assert "unusable until you install" in c.cancel_warning()
    c.cancel()
    assert os.path.exists(cancel_file) and c.cancel_requested
    assert p.cancels == 0  # the elevated process is never signalled
    assert c.stopping_text() == "Stopping after the current step..."
    assert c.phase is Phase.RUNNING  # still running until the process exits
    p.event(event="error", code="cancelled", message="stopped on request")
    p.rc = 130
    c.poll()
    o = c.outcome
    assert c.phase is Phase.FAILED and o.cancelled and o.code == "cancelled"
    assert "install beast-booter on it again" in o.target_state
    assert not os.path.exists(os.path.dirname(cancel_file))  # temp dir cleaned up


def test_cancel_before_writing(make, backend):
    c = ready(make(cancel_file=True))
    p = run_to_running(c, backend)
    c.cancel()
    p.rc = 130
    c.poll()
    assert c.outcome.cancelled
    assert "nothing was written" in c.outcome.target_state.lower()


def test_cancel_too_late_still_reports_success(make, backend):
    c = ready(make(cancel_file=True))
    p = run_to_running(c, backend)
    c.cancel()
    p.event(event="start", action="install", target="/dev/sdb")
    p.event(event="done", ok=True, info={})
    p.rc = 0
    c.poll()
    assert c.phase is Phase.DONE and c.outcome.ok  # the truth, not what was asked for
    assert any("finished before it could stop" in line.text for line in c.log)


def test_cancel_warning_texts(make, backend):
    c = ready(make())
    c.request_update()
    c.confirm()
    assert "run Update again" in c.cancel_warning() and "not touched" in c.cancel_warning()


class LocalFake(FakeProcess):
    """Stands in for LocalProcess (the CLI as our own child process)."""

    started: list = []

    def __init__(self, argv, output):
        super().__init__(argv)
        LocalFake.started.append(self)


@pytest.fixture
def local(monkeypatch):
    LocalFake.started = []
    monkeypatch.setattr(ctl, "LocalProcess", LocalFake)
    return LocalFake.started


def test_unelevated_run_is_stopped_by_signal(make, local, tmp_path):
    c = make()
    c.start_image(str(tmp_path / "x.img"), "1G")
    p = local[0]
    assert not c.job.elevated and c.can_cancel
    assert "incomplete" in c.cancel_warning()
    c.cancel()
    assert p.cancels == 1 and c.stopping_text() == "Stopping..."
    p.event(event="error", code="interrupted", message="interrupted")
    p.rc = 130
    c.poll()
    assert c.outcome.cancelled and c.outcome.code == "cancelled"


def test_already_elevated_gui_can_stop_its_cli(make, backend, local):
    backend.elevated = True  # the GUI itself runs as administrator: the CLI is our own child
    c = ready(make())
    c.request_install()
    c.confirm(True)
    assert c.can_cancel
    c.cancel()
    assert local[0].cancels == 1


def test_cancel_error_from_process_is_logged(make, local, tmp_path):
    c = make()
    c.start_image(str(tmp_path / "x.img"), "1G")

    def boom():
        raise OSError(1, "Operation not permitted")

    local[0].cancel = boom
    c.cancel()
    assert any("could not stop" in line.text for line in c.log)


def test_cancel_file_that_cannot_be_created_is_logged(make, backend, tmp_path):
    c = ready(make(cancel_file=True))
    run_to_running(c, backend)
    c.job.cancel_path = str(tmp_path / "missing dir" / "cancel")
    c.cancel()
    assert any("could not ask the installer to stop" in line.text for line in c.log)


def test_shutdown_stops_what_it_can(make, backend, local, tmp_path):
    c = make()
    c.start_image(str(tmp_path / "x.img"), "1G")
    c.shutdown()
    assert local[0].cancels == 1
    c.shutdown()  # a second close does not escalate to kill
    assert local[0].cancels == 1

    c2 = ready(make(cancel_file=True))
    p = run_to_running(c2, backend)
    c2.shutdown()
    assert os.path.exists(p.argv[p.argv.index("--cancel-file") + 1]) and p.cancels == 0


# ---------------------------------------------------------------------------
# images (no elevation)
# ---------------------------------------------------------------------------


def test_image_runs_unelevated(make, backend, monkeypatch, tmp_path):
    started = []

    class Local(FakeProcess):
        def __init__(self, argv, output):
            super().__init__(argv)
            started.append(self)

    monkeypatch.setattr(ctl, "LocalProcess", Local)
    c = make()
    c.set_option("layout", "gpt")
    c.start_image(str(tmp_path / "out.img"), "1G")
    assert c.phase is Phase.RUNNING  # no confirmation step for images
    assert not backend.procs  # never elevated
    argv = started[0].argv
    assert argv[argv.index("--image") + 1] == str(tmp_path / "out.img")
    assert argv[argv.index("--size") + 1] == str(1 << 30)
    assert argv[argv.index("--layout") + 1] == "gpt"
    started[0].event(event="start", action="install", target=str(tmp_path / "out.img"))
    started[0].rc = 0
    c.poll()
    assert c.outcome.title == "Image file created"
    assert "out.img" in c.next_steps(c.outcome)[0]


def test_image_relative_path_made_absolute(make, monkeypatch, tmp_path):
    started = []
    monkeypatch.setattr(ctl, "LocalProcess", lambda argv, out: started.append(argv) or FakeProcess(argv))
    monkeypatch.chdir(tmp_path)
    c = make()
    c.start_image("rel.img", "1G")
    assert started[0][started[0].index("--image") + 1] == str(tmp_path / "rel.img")


def test_image_errors(make, tmp_path):
    c = make()
    with pytest.raises(BeastError, match="at least"):
        c.start_image(str(tmp_path / "x.img"), "10M")
    with pytest.raises(BeastError, match="folder"):
        c.start_image(str(tmp_path), "1G")
    c.set_option("label", "")
    with pytest.raises(BeastError, match="options"):
        c.start_image(str(tmp_path / "x.img"), "1G")
    assert c.phase is Phase.IDLE


# ---------------------------------------------------------------------------
# boot files in the controller
# ---------------------------------------------------------------------------


def test_missing_dist_blocks_everything(make, tmp_path):
    c = ready(make(dist=distinfo.DistLocation(tmp_path / "nope", "--dist")))
    assert not c.dist_summary.ok
    for blocker in (c.install_blocker(), c.update_blocker(), c.image_blocker()):
        assert blocker and "not found" in blocker


def test_verify_dist_ok_and_failed(make, dist_copy):
    c = make(dist=distinfo.DistLocation(dist_copy, "--dist"))
    c.verify_dist()
    c.poll()
    assert c.verify_result.ok and "match manifest.json" in c.verify_result.message
    (dist_copy / "esp/grub/grub.cfg").write_text("tampered\n")
    c.verify_dist()
    c.poll()
    assert not c.verify_result.ok and "sha256 mismatch" in c.verify_result.message
    assert c.image_blocker() == "The boot files failed verification."
