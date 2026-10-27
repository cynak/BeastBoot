"""GUI controller against a real child process: the fake CLI (beastbooter/gui/fake_cli.py).

The fake CLI takes exactly the command line the controller builds for the real
CLI and writes a realistic progress sequence (each line in two halves, to
exercise partial-line handling), but touches no device and creates no file.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from beastbooter.gui import controller as ctl
from beastbooter.gui import demo, distinfo
from beastbooter.gui.controller import Controller, JobSpec, Options, Phase, build_cli_argv
from beastbooter.gui.localproc import LocalProcess

INSTALLER = Path(__file__).resolve().parents[1]


class Backend(demo.DemoBackend):
    """The demo backend with extra fake-CLI options per test."""

    def __init__(self, extra=(), step_delay=0.0):
        super().__init__("linux", list_delay=0.0, step_delay=step_delay)
        self.extra = list(extra)
        self.argvs = []

    def run_elevated(self, argv):
        self.argvs.append(argv)
        return super().run_elevated(argv + self.extra)


def make(fake_dist, tmp_path, backend=None, **kw) -> Controller:
    backend = backend or Backend()
    return Controller(backend_factory=lambda: backend, dist=distinfo.DistLocation(fake_dist, "--dist"),
                      launcher=demo.FAKE_CLI, spawn=ctl.inline_spawn, tmp_root=str(tmp_path), **kw)


def wait_for_step(c: Controller, step: str, timeout: float = 20.0) -> None:
    end = time.monotonic() + timeout
    while not (c.progress.steps_seen and step in c.progress.steps_seen):
        assert time.monotonic() < end, f"step {step} not reached"
        c.poll()
        time.sleep(0.01)


def run_until_finished(c: Controller, timeout: float = 30.0) -> None:
    end = time.monotonic() + timeout
    while c.phase is Phase.RUNNING:
        assert time.monotonic() < end, "fake CLI did not finish"
        c.poll()
        time.sleep(0.01)


def select(c: Controller, model_part: str) -> None:
    c.refresh_drives()
    c.poll()
    row = next(r for r in c.rows if model_part in r.title)
    assert c.select_drive(row.id) is None


def test_install_device_success(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path)
    select(c, "SanDisk")
    c.set_option("fs", "fat32")
    c.set_option("label", "multi")
    c.request_install()
    c.confirm(True)
    seen_pcts = []
    while c.phase is Phase.RUNNING:
        c.poll()
        if c.progress and c.progress.started:
            seen_pcts.append(c.progress.pct)
        time.sleep(0.005)
    assert c.phase is Phase.DONE, c.outcome
    o = c.outcome
    assert o.ok and o.exit_code == 0
    assert o.info["layout"] == "msdos" and o.info["data"]["label"] == "MULTI" and o.info["data"]["fs"] == "fat32"
    assert seen_pcts == sorted(seen_pcts)
    texts = [line.text for line in c.log]
    assert any("Creating the FAT32 storage partition MULTI" in t for t in texts)
    assert not any(line.level == "debug" and "ignored" in line.text for line in c.log)  # no half lines parsed
    assert "MULTI" in c.next_steps(o)[0]


def test_install_device_failure(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path)
    select(c, "fails while writing")  # the demo backend makes this one fail at write-esp
    c.request_install()
    c.confirm(True)
    run_until_finished(c)
    o = c.outcome
    assert c.phase is Phase.FAILED and o.code == "write-failed" and o.exit_code == 1
    assert "Input/output error" in o.message
    assert "install beast-boot on it again" in o.target_state


def test_update_success(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path)
    select(c, "SanDisk")
    c.request_update()
    c.confirm()
    run_until_finished(c)
    assert c.phase is Phase.DONE and c.outcome.title == "Boot files updated"


def test_crash_without_error_event(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path, Backend(["--fake-crash-at", "format-data"]))
    select(c, "SanDisk")
    c.request_install()
    c.confirm(True)
    run_until_finished(c)
    o = c.outcome
    assert c.phase is Phase.FAILED and o.code == "exit-3"
    assert "install beast-boot on it again" in o.target_state  # partition was already written


def test_image_unelevated_with_output_tail(fake_dist, tmp_path):
    backend = Backend()
    c = make(fake_dist, tmp_path, backend)
    img = tmp_path / "out dir" / "beast booter.img"
    c.start_image(str(img), "1500000001")  # not a whole number of MiB: the fake CLI warns
    assert isinstance(c.job.proc, LocalProcess) and not c.job.elevated
    run_until_finished(c)
    assert c.phase is Phase.DONE
    assert backend.argvs == []  # images never go through run_elevated
    assert c.outcome.info["disk_sectors"] == 1500000001 // 512
    assert any("rounded down" in line.text for line in c.log)
    assert not img.exists()  # the fake CLI writes nothing


def test_image_failure_shows_cli_output(fake_dist, tmp_path, monkeypatch):
    c = make(fake_dist, tmp_path)
    real = ctl.LocalProcess
    monkeypatch.setattr(ctl, "LocalProcess",
                        lambda argv, out: real(argv + ["--fake-crash-at", "write-esp"], out))
    c.start_image(str(tmp_path / "x.img"), "1G")
    run_until_finished(c)
    assert c.outcome.code == "exit-3"
    assert any("output: RuntimeError: fake crash at write-esp" in line.text for line in c.log)


def test_wrong_cli_arguments_mean_not_started(fake_dist, tmp_path, monkeypatch):
    # e.g. an older CLI without --progress-file: argparse exits 2 before any event
    c = make(fake_dist, tmp_path)
    real = ctl.LocalProcess
    monkeypatch.setattr(ctl, "LocalProcess", lambda argv, out: real(argv + ["--no-such-option"], out))
    c.start_image(str(tmp_path / "x.img"), "1G")
    run_until_finished(c)
    o = c.outcome
    assert o.code == "not-started" and o.exit_code == 2 and o.target_state == "Nothing was written."
    assert any("unrecognized arguments" in line.text for line in c.log)


def test_cancel_file_stops_the_elevated_cli_between_steps(fake_dist, tmp_path):
    """The way an elevated CLI is stopped: the GUI creates the --cancel-file and
    the CLI stops before its next step (the fake CLI does what the real one will)."""
    backend = Backend(step_delay=0.3)
    c = make(fake_dist, tmp_path, backend, cancel_file=True)
    select(c, "SanDisk")
    c.request_install()
    c.confirm(True)
    assert "--cancel-file" in backend.argvs[0]
    wait_for_step(c, "partition")
    c.cancel()
    run_until_finished(c)
    o = c.outcome
    assert o.cancelled and o.code == "cancelled" and o.exit_code == 130
    assert "install beast-boot on it again" in o.target_state
    steps = c.final_log  # it stopped at a step boundary, long before the end
    assert not any("Reading back what was written" in line.text for line in steps)


def test_elevated_cli_without_cancel_channel_runs_to_the_end(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path, Backend(step_delay=0.05), cancel_file=False)
    select(c, "SanDisk")
    c.request_install()
    c.confirm(True)
    assert "--cancel-file" not in c.job.argv and not c.can_cancel
    wait_for_step(c, "partition")
    with pytest.raises(ctl.BeastError, match="can't stop it"):
        c.cancel()
    run_until_finished(c)
    assert c.phase is Phase.DONE and c.outcome.ok  # and the window says so


@pytest.mark.skipif(os.name == "nt", reason="SIGINT delivery to a child is POSIX-only")
def test_cancel_interrupts_an_unelevated_cli(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path)
    c.start_image(str(tmp_path / "x.img"), "1G")  # no elevation: our own child, stopped by signal
    wait_for_step(c, "partition")
    c.cancel()
    run_until_finished(c)
    o = c.outcome
    assert o.cancelled and o.code == "cancelled" and o.exit_code == 130
    assert "image file is incomplete" in o.target_state


def test_fake_cli_honours_an_existing_cancel_file(tmp_path):
    from beastbooter.gui import fake_cli

    pf, cancel = tmp_path / "p.jsonl", tmp_path / "cancel"
    cancel.touch()
    rc = fake_cli.main(["install", "--image", "/x.img", "--size", str(1 << 30), "--yes", "--progress-file",
                        str(pf), "--cancel-file", str(cancel), "--dist", str(tmp_path), "--fake-delay", "0"])
    assert rc == 130
    events = [line for line in pf.read_text().splitlines()]
    assert '"code": "cancelled"' in events[-1] and '"event": "start"' in events[0]


def _pycache_dirs(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("__pycache__"))


def test_cli_command_line_writes_no_bytecode_into_the_package(tmp_path):
    """The elevated CLI must not leave (root-owned) __pycache__ folders in the
    portable package: start the CLI exactly as build_cli_argv does, from an
    unpacked copy of the app, and check that the folder is unchanged."""
    app = tmp_path / "pkg" / "app"
    shutil.copytree(INSTALLER / "beastbooter", app / "beastbooter",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(INSTALLER / "beast_booter_launch.py", app / "beast_booter_launch.py")
    spec = JobSpec("install", "image", str(tmp_path / "x.img"), options=Options(), image_size=1 << 30)
    argv = build_cli_argv(spec, python=sys.executable, launcher=str(app / "beast_booter_launch.py"),
                          progress_file=str(tmp_path / "p.jsonl"), dist=str(tmp_path / "dist"))
    interpreter = argv[: argv.index(str(app / "beast_booter_launch.py")) + 1]
    assert "-B" in interpreter
    env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
    proc = subprocess.run(interpreter + ["--version"], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0 and "beast-boot" in proc.stdout, proc.stderr
    assert _pycache_dirs(app) == []
    # No negative control ("without -B it writes bytecode"): the launcher itself now
    # sets sys.dont_write_bytecode as well, so -B is a second, independent guard.


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_local_process_second_cancel_kills(tmp_path):
    script = tmp_path / "stubborn.py"
    script.write_text("import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                      "print('ready', flush=True)\ntime.sleep(60)\n")
    out = tmp_path / "out.txt"
    p = LocalProcess([sys.executable, str(script)], str(out))
    end = time.monotonic() + 10
    while "ready" not in out.read_text():
        assert time.monotonic() < end
        time.sleep(0.01)
    p.cancel()  # SIGINT: ignored
    time.sleep(0.2)
    assert p.poll() is None
    p.cancel()  # kill
    assert p.wait(10) == -signal.SIGKILL
    assert p.output_tail() == ["ready"]
    p.cancel()  # after exit: no-op


def test_gui_package_does_not_import_tkinter():
    code = ("import sys; import beastbooter.gui, beastbooter.gui.controller, beastbooter.gui.demo; "
            "assert 'tkinter' not in sys.modules, 'tkinter imported'; print('ok')")
    proc = subprocess.run([sys.executable, "-c", code], cwd=INSTALLER, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_gui_main_without_tkinter_explains(tmp_path):
    """On a Python without Tk (like this host's), --gui fails with a clear message."""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("this Python has tkinter")
    proc = subprocess.run([sys.executable, "-s", "-E", str(INSTALLER / "beast_booter_launch.py"), "--gui"],
                          capture_output=True, text=True)
    assert proc.returncode == 1
    assert "needs Tkinter" in proc.stderr and "portable" in proc.stderr


def test_gui_main_rejects_bad_scale(monkeypatch):
    from beastbooter.gui import main

    monkeypatch.setattr(sys, "dont_write_bytecode", False)  # restored after the test
    assert main(["--scale", "9"]) == 2
    assert sys.dont_write_bytecode  # the GUI never writes .pyc files into the package either


def test_fake_cli_requires_yes(tmp_path):
    from beastbooter.gui import fake_cli

    pf = tmp_path / "p.jsonl"
    assert fake_cli.main(["install", "--image", "/x.img", "--progress-file", str(pf), "--dist", "/d"]) == 2
    assert not pf.exists()


def test_demo_drive_with_old_boot_files_is_current_after_an_update(fake_dist, tmp_path):
    c = make(fake_dist, tmp_path)
    select(c, demo.OLD_BEAST)
    c.poll()  # the drive check
    rows = {r.title: r for r in c.rows}
    f = rows[demo.OLD_BEAST].freshness
    assert f.state == "outdated" and f.installed.version == "0.0.9" and f.installed.build_id == "0000demo0000"
    assert all(r.freshness is None for r in c.rows if r.title != demo.OLD_BEAST)
    assert c.update_notice.text.startswith(f"{demo.OLD_BEAST} has beast-boot 0.0.9; this app has 0.1.0.")
    assert c.suggest_update
    c.request_update()
    c.confirm()
    run_until_finished(c)
    assert c.phase is Phase.DONE, c.outcome
    c.dismiss()
    c.poll(), c.poll()
    assert c.selected_row.freshness.state == "current" and c.update_notice is None
