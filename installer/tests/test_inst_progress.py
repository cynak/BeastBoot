"""--progress-file events, --cancel-file, dist resolution ($BEAST_BOOTER_DIST, --dist .zip)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import zipfile

import pytest
from conftest import HERE, info_json, needs_tools, read_events, run_cli, step_ids

from beastbooter import commands
from beastbooter.events import find_progress_file
from beastbooter.gui.progress import ProgressReader, ProgressState
from beastbooter.interfaces import PROGRESS_STEPS

IMAGE_STEPS = ["verify-dist", "check-target", "partition", "format-data", "write-esp", "boot-code", "flush",
               "verify-write"]
LAUNCHER = HERE.parent / "beast_booter_launch.py"


def install(img, dist, progress, *extra):
    return run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet",
                   "--progress-file", progress, "--dist", dist, *extra)


def gui_state(progress) -> ProgressState:
    """Feed the file through the GUI's own reader, as the window would."""
    reader, state = ProgressReader(progress), ProgressState()
    for ev in reader.finish():
        assert ev.kind not in ("invalid", "unknown") and not ev.note, ev
        state.apply(ev)
    return state


@needs_tools
@pytest.mark.parametrize("fs", ["exfat", "fat32"])
def test_image_install_events(tmp_path, fake_dist, fs):
    img, progress = tmp_path / "x.img", tmp_path / "p.jsonl"
    progress.write_text("")  # the GUI creates it before starting the CLI
    assert install(img, fake_dist, progress, "--fs", fs, "--layout", "gpt") == 0
    events = read_events(progress)
    assert all(e["v"] == 1 for e in events)
    assert events[0] == {"v": 1, "event": "start", "action": "install", "target": str(img)}
    assert step_ids(events) == IMAGE_STEPS
    steps = [e for e in events if e["event"] == "step"]
    assert all(e["step"] in PROGRESS_STEPS and e["message"] for e in steps)
    pcts = [e["pct"] for e in steps]
    assert pcts == sorted(pcts) and 0 < pcts[0] and pcts[-1] < 100
    assert events[-1] == {"v": 1, "event": "done", "ok": True, "info": info_json(img)}
    assert [e["event"] for e in events].count("done") == 1
    state = gui_state(progress)
    assert state.done_ok and state.error_code is None and state.done_info == info_json(img)


@needs_tools
def test_update_events_and_warning(tmp_path, fake_dist, fake_dist_v2):
    img = tmp_path / "u.img"
    assert install(img, fake_dist, tmp_path / "i.jsonl") == 0
    progress = tmp_path / "u.jsonl"
    # A FAT32 ESP marker is kept, device.cfg removed: update recreates it, with a warning.
    subprocess.run(["mdel", "-i", f"{img}@@{info_json(img)['esp']['start_lba'] * 512}",
                    "::/grub/beast/device.cfg"], check=True,
                   env={**os.environ, "MTOOLS_SKIP_CHECK": "1", "MTOOLSRC": "/dev/null"})
    assert run_cli("update", "--image", img, "--quiet", "--progress-file", progress, "--dist", fake_dist_v2) == 0
    events = read_events(progress)
    assert events[0] == {"v": 1, "event": "start", "action": "update", "target": str(img)}
    assert step_ids(events) == ["verify-dist", "check-target", "write-esp", "boot-code", "flush", "verify-write"]
    warnings = [e["message"] for e in events if e["event"] == "warning"]
    assert warnings == ["device.cfg was missing; recreating it from partition 1"]
    assert events[-1]["event"] == "done" and events[-1]["info"]["version"] == "0.2.0"


@pytest.mark.parametrize("args,needle", [
    (["install", "--image", "{img}", "--size", "1G", "--fs", "ext4"], "invalid choice"),
    (["install", "--image", "{img}", "--size", "1G", "--bogus"], "unrecognized arguments: --bogus"),
    (["install", "--image", "{img}"], "install --image needs --size"),
    (["install", "--device", "/dev/x", "--size", "1G"], "--size is only valid with --image"),
    (["update", "--image", "{img}", "--device", "/dev/x"], "not allowed with argument"),
    (["info", "--image", "{img}"], "unrecognized arguments: --progress-file"),
])
@pytest.mark.parametrize("form", ["separate", "equals"])
def test_usage_error_event(tmp_path, capsys, args, needle, form):
    img, progress = tmp_path / "x.img", tmp_path / "p.jsonl"
    argv = [a.replace("{img}", str(img)) for a in args]
    argv += ["--progress-file", str(progress)] if form == "separate" else [f"--progress-file={progress}"]
    with pytest.raises(SystemExit) as exc:
        run_cli(*argv)
    assert exc.value.code == 2
    assert needle in capsys.readouterr().err
    events = read_events(progress)
    assert len(events) == 1 and events[0]["event"] == "error" and events[0]["code"] == "usage"
    assert needle in events[0]["message"]
    assert not img.exists()


def test_usage_error_event_via_launcher(tmp_path):
    """The GUI's failure from the field: an option the CLI does not know reaches the window."""
    progress = tmp_path / "p.jsonl"
    p = subprocess.run([sys.executable, "-s", "-E", "-B", str(LAUNCHER), "install", "--device", "/dev/sdz",
                        "--yes", "--progress-file", str(progress), "--frobnicate", "--dist", str(tmp_path)],
                       capture_output=True, text=True)
    assert p.returncode == 2 and "unrecognized arguments: --frobnicate" in p.stderr
    (ev,) = read_events(progress)
    assert ev["code"] == "usage" and "--frobnicate" in ev["message"]
    state = gui_state(progress)
    assert state.error_code == "usage" and not state.started


def test_missing_dist_event(tmp_path, capsys):
    img, progress = tmp_path / "x.img", tmp_path / "p.jsonl"
    assert install(img, tmp_path / "no-such-dist", progress) == 1
    err = capsys.readouterr().err
    assert "dist directory not found" in err and "no-such-dist" in err
    events = read_events(progress)
    assert events[0]["event"] == "start"
    assert step_ids(events) == ["verify-dist"]
    assert events[-1]["event"] == "error" and events[-1]["code"] == "dist-missing"
    assert "no-such-dist" in events[-1]["message"]
    assert not img.exists()


@needs_tools
def test_bad_dist_and_bad_label_codes(tmp_path, dist_copy):
    (dist_copy / "esp/grub/grub.cfg").write_text("tampered")
    progress = tmp_path / "p.jsonl"
    assert install(tmp_path / "x.img", dist_copy, progress) == 1
    assert read_events(progress)[-1]["code"] == "dist-invalid"
    progress = tmp_path / "q.jsonl"
    assert install(tmp_path / "x.img", dist_copy, progress, "--label=ABCDEFGHIJKL") == 1  # exFAT: max 11
    ev = read_events(progress)[-1]
    assert ev["code"] == "invalid-argument" and "too long" in ev["message"]
    assert not (tmp_path / "x.img").exists()


@needs_tools
def test_each_line_is_flushed_immediately(tmp_path, fake_dist, monkeypatch):
    progress = tmp_path / "p.jsonl"
    seen = {}
    real = commands.write_partition_table

    def peek(*a, **kw):  # runs inside the "partition" step: what can a reader see right now?
        seen["events"] = read_events(progress)
        return real(*a, **kw)

    monkeypatch.setattr(commands, "write_partition_table", peek)
    assert install(tmp_path / "x.img", fake_dist, progress) == 0
    assert seen["events"][-1]["event"] == "step" and seen["events"][-1]["step"] == "partition"


@needs_tools
def test_cancel_file(tmp_path, fake_dist, monkeypatch, capsys):
    img, progress, cancel = tmp_path / "x.img", tmp_path / "p.jsonl", tmp_path / "cancel"
    real = commands.write_partition_table

    def then_cancel(*a, **kw):  # the user presses Stop while the table is written
        real(*a, **kw)
        cancel.write_text("")

    monkeypatch.setattr(commands, "write_partition_table", then_cancel)
    assert install(img, fake_dist, progress, "--cancel-file", cancel) == 130
    assert "stopped on request" in capsys.readouterr().err
    events = read_events(progress)
    assert step_ids(events)[-1] == "partition"
    assert events[-1] == {"v": 1, "event": "error", "code": "cancelled",
                          "message": "stopped on request before step partition"}
    assert not img.exists()  # a half-made image is removed
    assert gui_state(progress).error_code == "cancelled"


@needs_tools
def test_cancel_file_inside_esp_copy(tmp_path, fake_dist, monkeypatch):
    """The ESP copy is the longest loop: the cancel file is honoured inside it."""
    img, progress, cancel = tmp_path / "x.img", tmp_path / "p.jsonl", tmp_path / "cancel"
    real = commands.copy_written
    chunks = []

    def copy_then_cancel(src, dst, offset, *, on_progress=None, **kw):
        def progress_hook(done, total):
            chunks.append(done)
            cancel.write_text("")
            on_progress(done, total)
        return real(src, dst, offset, on_progress=progress_hook, **kw)

    monkeypatch.setattr(commands, "copy_written", copy_then_cancel)
    assert install(img, fake_dist, progress, "--cancel-file", cancel) == 130
    ev = read_events(progress)[-1]
    assert ev["code"] == "cancelled" and ev["message"] == "stopped on request during step write-esp"
    assert 0 < len(chunks) < 4  # stopped within the first progress interval, not at the end
    assert not img.exists()


@needs_tools
@pytest.mark.parametrize("sig", ["SIGINT", "SIGTERM"])
def test_signal_stops_cleanly(tmp_path, fake_dist, monkeypatch, capsys, sig):
    """Ctrl+C and SIGTERM (the GUI's stop for an unelevated run) end like --cancel-file."""
    img, progress = tmp_path / "x.img", tmp_path / "p.jsonl"
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def signal_self(*a, **kw):
        os.kill(os.getpid(), getattr(signal, sig))
        time.sleep(5)  # the handler interrupts this
        raise AssertionError("the signal did not stop the install")

    monkeypatch.setattr(commands, "_format_data", signal_self)
    assert install(img, fake_dist, progress) == 130
    assert f"interrupted ({sig})" in capsys.readouterr().err
    assert read_events(progress)[-1] == {"v": 1, "event": "error", "code": "cancelled",
                                         "message": f"stopped by {sig} during step format-data"}
    assert not img.exists()
    assert {s: signal.getsignal(s) for s in handlers} == handlers  # the CLI restored them


@needs_tools
def test_esp_times_come_from_the_manifest(tmp_path, fake_dist):
    """ESP entries are dated with the dist's SOURCE_DATE_EPOCH (fakedist: 2025-10-09)."""
    img = tmp_path / "t.img"
    assert install(img, fake_dist, tmp_path / "p.jsonl", "--fs", "fat32") == 0
    off = info_json(img)["esp"]["start_lba"] * 512
    out = subprocess.run(["mdir", "-i", f"{img}@@{off}", "::/"], capture_output=True, text=True, check=True,
                         env={**os.environ, "MTOOLS_SKIP_CHECK": "1", "MTOOLSRC": "/dev/null"}).stdout
    dated = [line for line in out.splitlines() if line.startswith(("EFI ", "GRUB ", "BEAST-~1"))]
    assert dated and all("2025-10-09" in line for line in dated), out


@needs_tools
def test_write_error_event(tmp_path, fake_dist, monkeypatch):
    progress = tmp_path / "p.jsonl"

    def fail(*a, **kw):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(commands, "_format_data", fail)
    assert install(tmp_path / "x.img", fake_dist, progress) == 1
    ev = read_events(progress)[-1]
    assert ev == {"v": 1, "event": "error", "code": "write-failed", "message": "Input/output error"}


def test_unwritable_progress_file(tmp_path, capsys):
    assert run_cli("install", "--image", tmp_path / "x.img", "--size", "1G",
                   "--progress-file", tmp_path / "nodir" / "p.jsonl") == 1
    assert "cannot open the progress file" in capsys.readouterr().err


def test_find_progress_file():
    assert find_progress_file(["install", "--progress-file", "a"]) == "a"
    assert find_progress_file(["install", "--progress-file=b"]) == "b"
    assert find_progress_file(["install", "--progress", "c"]) == "c"
    assert find_progress_file(["install", "--progress-file"]) is None
    assert find_progress_file(["install", "--", "--progress-file", "d"]) is None
    assert find_progress_file(["install", "--image", "x"]) is None


# --------------------------------------------------------------------------- dist resolution


@needs_tools
def test_dist_from_environment(tmp_path, fake_dist, monkeypatch, capsys):
    monkeypatch.setenv("BEAST_BOOTER_DIST", str(fake_dist))
    img = tmp_path / "env.img"
    assert run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet") == 0
    assert info_json(img)["version"] == "0.1.0"
    # --dist wins over the environment.
    monkeypatch.setenv("BEAST_BOOTER_DIST", str(tmp_path / "missing"))
    assert run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet", "--dist", fake_dist) == 0
    assert run_cli("update", "--image", img, "--quiet") == 1
    assert str(tmp_path / "missing") in capsys.readouterr().err
    monkeypatch.delenv("BEAST_BOOTER_DIST")
    monkeypatch.setattr("beastbooter.distsource.default_dist_dir", lambda: tmp_path / "repo-dist")
    assert run_cli("update", "--image", img, "--quiet") == 1
    assert "repo-dist" in capsys.readouterr().err


def make_zip(src_dir, zip_path, prefix="dist/", extra=()):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src_dir.rglob("*")):
            if p.is_file():
                z.write(p, prefix + p.relative_to(src_dir).as_posix())
        for name, data in extra:
            z.writestr(name, data)
    return zip_path


@needs_tools
@pytest.mark.parametrize("prefix", ["dist/", ""])
def test_dist_zip(tmp_path, fake_dist, prefix):
    z = make_zip(fake_dist, tmp_path / "beast-boot-dist.zip", prefix)
    img = tmp_path / "z.img"
    assert install(img, z, tmp_path / "p.jsonl") == 0
    assert info_json(img)["version"] == "0.1.0"
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".beast-boot-")]
    assert leftovers == []  # the extracted copy is removed


@needs_tools
@pytest.mark.parametrize("extra,needle", [
    ([("dist/../evil.txt", b"x")], "unsafe path"),
    ([("/abs.txt", b"x")], "unsafe path"),
    ([("dist/esp/extra.bin", b"not in the manifest")], "not listed in manifest"),
])
def test_dist_zip_refused(tmp_path, fake_dist, extra, needle, capsys):
    z = make_zip(fake_dist, tmp_path / "bad.zip", "dist/", extra)
    img, progress = tmp_path / "z.img", tmp_path / "p.jsonl"
    assert install(img, z, progress) == 1
    assert needle in capsys.readouterr().err
    assert read_events(progress)[-1]["code"] == "dist-invalid"
    assert not img.exists() and not (tmp_path / "evil.txt").exists()


def test_dist_zip_symlink_and_garbage(tmp_path, capsys):
    z = tmp_path / "link.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("dist/manifest.json")
        info.external_attr = 0o120777 << 16  # a symlink
        zf.writestr(info, "/etc/passwd")
    assert install(tmp_path / "a.img", z, tmp_path / "p.jsonl") == 1
    assert "not a regular file" in capsys.readouterr().err
    bad = tmp_path / "garbage.zip"
    bad.write_bytes(b"not a zip")
    assert install(tmp_path / "a.img", bad, tmp_path / "q.jsonl") == 1
    assert "not a readable zip archive" in capsys.readouterr().err
    empty = tmp_path / "empty.zip"
    zipfile.ZipFile(empty, "w").close()
    assert install(tmp_path / "a.img", empty, tmp_path / "r.jsonl") == 1
    assert "does not contain a beast-boot dist directory" in capsys.readouterr().err


# --------------------------------------------------------------------------- the GUI's argv, minimal environment


@needs_tools
def test_gui_argv_minimal_environment(tmp_path, fake_dist):
    """What pkexec runs: `python -s -E -B launcher install ...` with almost no environment
    and no mtools/mkfs on PATH (exFAT + msdos needs no external tool at all)."""
    img, progress = tmp_path / "gui.img", tmp_path / "gui.jsonl"
    progress.write_text("")
    env = {"PATH": str(tmp_path / "empty-bin")}
    (tmp_path / "empty-bin").mkdir()
    p = subprocess.run([sys.executable, "-s", "-E", "-B", str(LAUNCHER), "install", "--image", str(img),
                        "--size", str(1 << 30), "--yes", "--progress-file", str(progress),
                        "--dist", str(fake_dist), "--layout", "msdos", "--fs", "exfat", "--label=BEASTBOOTER"],
                       capture_output=True, text=True, env=env, cwd="/")
    assert p.returncode == 0, p.stderr
    events = read_events(progress)
    assert events[-1]["event"] == "done" and events[-1]["info"] == info_json(img)


@needs_tools
def test_ntfs_image_needs_mkfs_ntfs(tmp_path, fake_dist):
    """Without mkfs.ntfs an NTFS image is refused before anything is created."""
    progress = tmp_path / "n.jsonl"
    (tmp_path / "empty-bin").mkdir()
    p = subprocess.run([sys.executable, "-s", "-E", "-B", str(LAUNCHER), "install", "--image", str(tmp_path / "n.img"),
                        "--size", "1G", "--yes", "--progress-file", str(progress), "--dist", str(fake_dist),
                        "--fs", "ntfs"], capture_output=True, text=True, env={"PATH": str(tmp_path / "empty-bin")})
    assert p.returncode == 1 and "needs mkfs.ntfs" in p.stderr
    assert read_events(progress)[-1]["code"] == "unsupported"
    assert not (tmp_path / "n.img").exists()
