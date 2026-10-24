"""install / update on a drive that stops responding, and re-running an update
that was interrupted: through a fake backend whose drive is a file and can
"vanish" (its writes fail, medium_gone() says so), with a fake kernel log and
a recovery directory in tmp. Nothing here touches a real device."""

from __future__ import annotations

import errno
import io
import json
import os
import time

import pytest
from conftest import info_json, read_events, run_cli, sha_region
from fakebackend import FakeBackend

from beastbooter import commands
from beastbooter.blockio import ImageTarget
from beastbooter.errors import BeastError
from beastbooter.fatfs import FatVolume
from beastbooter.layout import SECTOR_SIZE
from beastbooter.plan import make_plan
from beastbooter.util import Reporter

PACK = "beast-net/firmware/test-pack.cpio"
KERNEL_LINE = "[5.1] fakesdz: detected capacity change from 2252800 to 0"


class FakeLog:
    def __init__(self):
        self.closed = False

    def lines(self):
        return ["[5.0] usb 2-1: new SuperSpeed USB device", KERNEL_LINE]

    def close(self):
        self.closed = True


class Flaky(ImageTarget):
    """The drive file; with backend.fail_after set, the n-th write fails and the drive is gone."""

    def __init__(self, path, *, writable, backend):
        super().__init__(path, writable=writable)
        self.backend = backend

    def write(self, offset, data):
        b = self.backend
        if b.gone:
            raise OSError(errno.ENOSPC, "No space left on device")  # its size is 0 now
        b.writes += 1
        if b.fail_after is not None and b.writes > b.fail_after:
            b.gone = True
            raise OSError(errno.EIO, "Input/output error")
        super().write(offset, data)

    def read(self, offset, length):
        self.backend.events.append(("read", id(self)))
        if self.backend.gone:
            raise BeastError(f"unexpected end of {self.path} at byte {offset}")
        return super().read(offset, length)


class VanishingBackend(FakeBackend):
    def __init__(self, tmp_path, **kw):
        super().__init__(tmp_path, **kw)
        self.state = tmp_path / "state"
        self.gone = False
        self.fail_after: int | None = None
        self.writes = 0
        self.events: list[tuple] = []
        self.logs: list[FakeLog] = []
        self.released = 0

    def release(self, disk=None):
        self.released += 1

    def open_raw(self, disk, *, writable):
        self.calls.append(("open_raw", writable))
        if self.gone:
            raise BeastError(f"cannot open {disk.path}: No medium found")
        t = Flaky(disk.path, writable=writable, backend=self)
        self.opened.append(t)
        return t

    def medium_gone(self, disk):
        return self.gone

    def kernel_log(self, disk):
        self.logs.append(FakeLog())
        return self.logs[-1]

    def state_dir(self):
        return str(self.state)

    def replug(self):
        self.gone, self.fail_after, self.writes = False, None, 0

    def fail_at(self, n: int) -> None:
        """Writes from now on: the n-th fails and the drive is gone."""
        self.fail_after, self.writes = n - 1, 0


@pytest.fixture
def backend(tmp_path, monkeypatch) -> VanishingBackend:
    b = VanishingBackend(tmp_path)
    monkeypatch.setattr(commands, "get_backend", lambda: b)
    return b


def install(backend, dist, layout="gpt"):
    assert run_cli("install", "--device", backend.disk.id, "--yes", "--quiet", "--dist", dist,
                   "--layout", layout, "--fs", "exfat") == 0


def update(backend, dist, progress):
    return run_cli("update", "--device", backend.disk.id, "--yes", "--quiet", "--progress-file", progress,
                   "--dist", dist)


def esp_offset(backend, layout="gpt"):
    return make_plan(backend.disk.size // SECTOR_SIZE, layout).esp.offset


def add_pack(backend, data=b"070701 fake firmware pack"):
    with ImageTarget(str(backend.disk_file), writable=True) as t:
        FatVolume(t, esp_offset(backend)).write_file(PACK, data)


def read_pack(backend):
    with ImageTarget(str(backend.disk_file), writable=False) as t:
        vol = FatVolume(t, esp_offset(backend))
        return vol.read_file(PACK) if vol.exists(PACK) else None


def data_hash(backend):
    d = info_json(backend.disk_file)["data"]
    return d, sha_region(backend.disk_file, d["start_lba"], d["size_lba"])


def error_and_warnings(progress):
    events = read_events(progress)
    return events[-1], [e["message"] for e in events if e["event"] == "warning"]


def records(backend):
    d = backend.state / "update-recovery"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def test_vanish_while_writing_then_rerun_finishes(backend, fake_dist, fake_dist_v2, tmp_path):
    install(backend, fake_dist)
    add_pack(backend)
    d, before = data_hash(backend)
    backend.fail_at(4)  # the zeroed ESP boot sector, two chunks of the ESP, then the stick is gone
    progress = tmp_path / "u1.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    err, warnings = error_and_warnings(progress)
    assert err["event"] == "error" and err["code"] == "device-vanished"
    msg = err["message"]
    assert msg.startswith("/dev/fakesdz stopped responding while it was being written: the system now sees it "
                          "as empty (no medium). This is the drive, not beast-booter")
    assert "Unplug it, plug it back in and run Update again; the update starts over and completes" in msg
    assert "partition 1 (your files) is not touched" in msg
    assert f"kernel: {KERNEL_LINE}" in warnings and backend.logs[-1].closed
    assert sha_region(backend.disk_file, d["start_lba"], d["size_lba"]) == before
    with ImageTarget(str(backend.disk_file), writable=False) as t:  # recognisably unfinished
        assert not any(t.read(esp_offset(backend), SECTOR_SIZE))
    assert len(records(backend)) == 1
    with pytest.raises(BeastError, match="not a beast-booter drive"):
        commands.info(str(backend.disk_file), None)

    backend.replug()
    progress = tmp_path / "u2.jsonl"
    assert update(backend, fake_dist_v2, progress) == 0
    events = read_events(progress)
    assert any("did not finish; finishing it now with the settings and files it saved" in e.get("message", "")
               for e in events if e["event"] == "warning")
    assert events[-1]["event"] == "done" and events[-1]["info"]["version"] == "0.2.0"
    assert read_pack(backend) == b"070701 fake firmware pack"  # carried over from the record
    assert sha_region(backend.disk_file, d["start_lba"], d["size_lba"]) == before
    assert records(backend) == []  # a verified update removes its record


def test_interrupted_update_without_record_is_rebuilt(backend, fake_dist, fake_dist_v2, tmp_path):
    """Re-run on another computer (no record): the ESP is rebuilt from partition 1."""
    install(backend, fake_dist)
    add_pack(backend)
    uuid_before = info_json(backend.disk_file)["data"]
    backend.fail_at(3)
    assert update(backend, fake_dist_v2, tmp_path / "u1.jsonl") == 1
    for p in (backend.state / "update-recovery").iterdir():
        p.unlink()
    backend.replug()
    progress = tmp_path / "u2.jsonl"
    assert update(backend, fake_dist_v2, progress) == 0
    _done, warnings = error_and_warnings(progress)
    assert any("is incomplete (an update did not finish); it is rebuilt" in w for w in warnings)
    assert read_pack(backend) is None
    after = info_json(backend.disk_file)
    assert after["version"] == "0.2.0" and after["data"] == uuid_before


def test_image_with_unfinished_esp_is_rebuilt(tmp_path, fake_dist, fake_dist_v2):
    img = tmp_path / "x.img"
    assert run_cli("install", "--image", img, "--size", "1100M", "--yes", "--quiet", "--dist", fake_dist) == 0
    off = make_plan(img.stat().st_size // SECTOR_SIZE, "msdos").esp.offset
    with ImageTarget(str(img), writable=True) as t:
        t.write(off, bytes(SECTOR_SIZE))  # what an interrupted update leaves
    assert run_cli("update", "--image", img, "--yes", "--quiet", "--dist", fake_dist_v2) == 0
    assert info_json(img)["version"] == "0.2.0"
    with ImageTarget(str(img), writable=True) as t:
        t.write(off + SECTOR_SIZE * 64, bytes(SECTOR_SIZE))  # damage elsewhere: not "unfinished", still refused
        t.write(off, bytes(SECTOR_SIZE))
        t.write(0x1BE, bytes(64))  # and no partition table
    assert run_cli("update", "--image", img, "--yes", "--quiet", "--dist", fake_dist_v2) == 1


def test_vanish_before_writing(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    install(backend, fake_dist)
    whole = sha_region(backend.disk_file, 0, backend.disk.size // SECTOR_SIZE)

    def prepare(disk):
        backend.gone = True
        raise BeastError(f"{disk.id} stopped responding (the kernel sees no medium)", code="device-vanished")

    monkeypatch.setattr(backend, "prepare", prepare)
    progress = tmp_path / "u.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    err, warnings = error_and_warnings(progress)
    assert err["code"] == "device-vanished"
    assert "stopped responding before anything was written" in err["message"]
    assert err["message"].endswith("the update starts over and completes; nothing was changed.")
    assert f"kernel: {KERNEL_LINE}" in warnings
    assert sha_region(backend.disk_file, 0, backend.disk.size // SECTOR_SIZE) == whole
    assert records(backend) == []


def test_open_fails_no_medium(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    install(backend, fake_dist)
    monkeypatch.setattr(backend, "prepare", lambda disk: setattr(backend, "gone", True))
    progress = tmp_path / "u.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    err, _w = error_and_warnings(progress)
    assert err["code"] == "device-vanished" and "before anything was written" in err["message"]


def test_vanish_after_writing(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    install(backend, fake_dist)

    real_rescan = backend.rescan

    def rescan(disk):
        monkeypatch.setattr(backend, "rescan", real_rescan)  # once
        backend.gone = True
        raise BeastError("the kernel did not accept the new partition table on /dev/fakesdz")

    monkeypatch.setattr(backend, "rescan", rescan)
    progress = tmp_path / "u.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    err, _w = error_and_warnings(progress)
    assert err["code"] == "device-vanished"
    assert "after it was written, before it could be checked" in err["message"]
    backend.replug()
    assert update(backend, fake_dist_v2, tmp_path / "u2.jsonl") == 0  # the ESP is complete: a normal update
    assert records(backend) == []


def test_ordinary_write_error_is_not_vanished(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    install(backend, fake_dist)
    monkeypatch.setattr(backend, "medium_gone", lambda disk: False)  # still there: a bad sector, say
    backend.fail_at(3)
    progress = tmp_path / "u.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    err, warnings = error_and_warnings(progress)
    assert err["code"] == "write-failed" and "Input/output error" in err["message"]
    assert f"kernel: {KERNEL_LINE}" in warnings  # the evidence is shown for any failure


def test_install_vanish_while_writing(backend, fake_dist, tmp_path):
    backend.fail_at(6)
    progress = tmp_path / "i.jsonl"
    assert run_cli("install", "--device", backend.disk.id, "--yes", "--quiet", "--progress-file", progress,
                   "--dist", fake_dist) == 1
    err, _w = error_and_warnings(progress)
    assert err["code"] == "device-vanished"
    assert "while it was being written" in err["message"]
    assert "run Install again; the installation starts over and completes." in err["message"]


def test_page_cache_dropped_before_reads(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    """Every target update reads is first cleared of cached blocks (BLKFLSBUF on Linux),
    and the drive is read again after prepare() before anything is written."""
    install(backend, fake_dist)
    backend.events.clear()
    backend.opened.clear()
    monkeypatch.setattr(commands, "_drop_cache",
                        lambda b, t: backend.events.append(("drop", id(getattr(t, "inner", t)))))
    real_prepare = backend.prepare
    monkeypatch.setattr(backend, "prepare", lambda disk: (backend.events.append(("prepare", 0)),
                                                          real_prepare(disk))[1])
    assert update(backend, fake_dist_v2, tmp_path / "u.jsonl") == 0
    targets = [id(t) for t in backend.opened]
    assert len(targets) == 3  # read, write (read again first), verify
    for tid in targets:
        mine = [kind for kind, t in backend.events if t == tid]
        assert mine and mine[0] == "drop" and "read" in mine
    kinds = [k for k, t in backend.events if t in (0, targets[1])]
    assert kinds[:3] == ["prepare", "drop", "read"]  # after unmounting: drop, then read the state again


def test_changed_after_first_read_uses_fresh_state(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    """A pack added between the first read (drive mounted) and prepare() is carried over too."""
    install(backend, fake_dist)
    monkeypatch.setattr(backend, "prepare", lambda disk: add_pack(backend, b"070701 added later"))
    assert run_cli("update", "--device", backend.disk.id, "--yes", "--dist", fake_dist_v2) == 0
    assert read_pack(backend) == b"070701 added later"


def test_vanished_message_wording():
    m = commands.vanished_message("/dev/sda", "update", "before")
    assert m == ("/dev/sda stopped responding before anything was written: the system now sees it as empty (no "
                 "medium). This is the drive, not beast-booter: some USB sticks do this when they are warm or after "
                 "long use. Unplug it, plug it back in and run Update again; the update starts over and completes; "
                 "nothing was changed.")
    assert "after it was written, before it could be checked" in commands.vanished_message("x", "install", "written")


# --------------------------------------------------------------------------- review fixes


def zero_data_boot_sector(path, layout):
    off = make_plan(os.path.getsize(path) // SECTOR_SIZE, layout).data.offset
    with ImageTarget(str(path), writable=True) as t:
        t.write(off, bytes(SECTOR_SIZE))  # partition 1 no longer recognisable (ext4, LUKS, ... for probe_fs)


def test_record_found_without_a_readable_partition_1(backend, fake_dist, fake_dist_v2, tmp_path):
    install(backend, fake_dist)
    add_pack(backend)
    zero_data_boot_sector(backend.disk_file, "gpt")
    assert update(backend, fake_dist_v2, tmp_path / "u0.jsonl") == 0  # keeps the device.cfg values
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u1.jsonl") == 1
    backend.replug()
    progress = tmp_path / "u2.jsonl"
    assert update(backend, fake_dist_v2, progress) == 0
    _done, warnings = error_and_warnings(progress)
    assert any("did not finish; finishing it now" in w for w in warnings)
    assert read_pack(backend) == b"070701 fake firmware pack" and records(backend) == []


def test_rebuild_without_record_or_readable_partition_1(tmp_path, fake_dist, fake_dist_v2):
    img = tmp_path / "x.img"
    assert run_cli("install", "--image", img, "--size", "1100M", "--yes", "--quiet", "--dist", fake_dist) == 0
    zero_data_boot_sector(img, "msdos")
    assert run_cli("update", "--image", img, "--yes", "--quiet", "--dist", fake_dist_v2) == 0
    off = make_plan(img.stat().st_size // SECTOR_SIZE, "msdos").esp.offset
    with ImageTarget(str(img), writable=True) as t:
        t.write(off, bytes(SECTOR_SIZE))
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--image", img, "--yes", "--quiet", "--progress-file", progress,
                   "--dist", fake_dist_v2) == 0
    _done, warnings = error_and_warnings(progress)
    assert any("placeholder values" in w for w in warnings)
    with ImageTarget(str(img), writable=False) as t:
        cfg = commands.read_esp_text(FatVolume(t, off), commands.DEVICE_CFG_PATH)
    assert 'set bb_data_uuid="unknown"' in cfg
    assert run_cli("update", "--image", img, "--yes", "--quiet", "--dist", fake_dist_v2) == 0  # and again


def test_stale_record_is_not_applied(backend, fake_dist, fake_dist_v2, tmp_path):
    """The drive was written elsewhere since the record was made (its boot code differs)."""
    install(backend, fake_dist)
    add_pack(backend)
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u1.jsonl") == 1
    assert len(records(backend)) == 1
    with open(backend.disk_file, "r+b") as f:  # another computer's update wrote other boot code
        f.write(b"\xeb\x63\x90other boot code")
    backend.replug()
    progress = tmp_path / "u2.jsonl"
    assert update(backend, fake_dist_v2, progress) == 0
    _done, warnings = error_and_warnings(progress)
    assert any("is not used: the drive was written since" in w for w in warnings)
    assert any("it is rebuilt" in w for w in warnings)
    assert read_pack(backend) is None and records(backend) == []


def test_record_removed_once_the_esp_is_complete(backend, fake_dist, fake_dist_v2, tmp_path):
    install(backend, fake_dist)
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u1.jsonl") == 1
    assert run_cli("update", "--image", backend.disk_file, "--yes", "--quiet", "--dist", fake_dist_v2) == 0
    assert len(records(backend)) == 1  # finished elsewhere (here: as an image, without records)
    rec = commands._UpdateRecords(str(backend.state))
    with ImageTarget(str(backend.disk_file), writable=False) as t:
        commands._read_drive_state(t, "x", Reporter(quiet=True, stream=io.StringIO()), rec)
    assert records(backend) == []


def test_failed_save_leaves_no_record(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    install(backend, fake_dist)
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u1.jsonl") == 1
    assert len(records(backend)) == 1
    backend.replug()

    def no_replace(a, b):
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(commands.os, "replace", no_replace)
    backend.fail_at(4)
    progress = tmp_path / "u2.jsonl"
    assert update(backend, fake_dist_v2, progress) == 1
    _err, warnings = error_and_warnings(progress)
    assert any("could not keep a copy of the drive's settings" in w for w in warnings)
    assert records(backend) == []  # neither the .tmp nor the older record is left


def test_old_records_are_pruned(backend, fake_dist, fake_dist_v2, tmp_path):
    install(backend, fake_dist)
    d = backend.state / "update-recovery"
    d.mkdir(parents=True)
    old = d / "update-0123.json"
    old.write_text(json.dumps({"v": 2}))
    t = time.time() - 40 * 24 * 3600
    os.utime(old, (t, t))
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u.jsonl") == 1
    assert len(records(backend)) == 1 and not old.exists()


def test_no_medium_at_open_is_retried_once(backend, fake_dist, fake_dist_v2, tmp_path, monkeypatch):
    """Gone right after prepare (before anything was written): prepare() runs again, which
    waits for the drive; here it is back, and the update completes."""
    install(backend, fake_dist)
    preps = []

    def prepare(disk):
        preps.append(disk)
        backend.gone = len(preps) == 1

    monkeypatch.setattr(backend, "prepare", prepare)
    progress = tmp_path / "u.jsonl"
    assert update(backend, fake_dist_v2, progress) == 0
    _done, warnings = error_and_warnings(progress)
    assert len(preps) == 2 and any("before anything was written" in w and "checking it again" in w
                                   for w in warnings)


def test_released_on_failure(backend, fake_dist, fake_dist_v2, tmp_path):
    install(backend, fake_dist)
    released = backend.released
    backend.fail_at(4)
    assert update(backend, fake_dist_v2, tmp_path / "u.jsonl") == 1
    assert backend.released == released + 1


class Prepared:
    name = "linux"
    notes = ["/dev/sdz stopped responding (the kernel sees no medium); asking the kernel to check it again",
             "/dev/sdz is back (1.1 GiB)"]
    medium_returned = True

    def prepare(self, disk):
        return []


@pytest.mark.parametrize("written, said", [(False, "continuing: nothing had been written to it yet"),
                                           (True, "continuing: what was written before it stopped is checked")])
def test_prepare_device_words_a_return_by_phase(backend, written, said):
    out = io.StringIO()
    commands.prepare_device(Prepared(), backend.disk, Reporter(quiet=True, stream=out), 26, written=written)
    lines = out.getvalue().splitlines()
    assert len(lines) == 3 and said in lines[2] and "stopped responding" in lines[0]
