"""install / update / info --device end to end, through a fake PlatformBackend
whose drive is a file (open_raw returns an ImageTarget on it). Nothing here
touches a real device; the argv is the one the GUI sends."""

from __future__ import annotations

import pytest
from conftest import (
    info_json,
    needs_fsck,
    needs_tools,
    read_events,
    run_cli,
    sha_region,
    step_ids,
    validate_drive,
)
from fakebackend import STALE, FakeBackend

from beastbooter import commands
from beastbooter.errors import BeastError
from beastbooter.layout import MIB, SECTOR_SIZE
from beastbooter.plan import make_plan

pytestmark = needs_tools

INSTALL_STEPS = ["verify-dist", "check-target", "prepare", "partition", "format-data", "write-esp",
                 "boot-code", "flush", "rescan", "verify-write"]


@pytest.fixture
def backend(tmp_path, monkeypatch) -> FakeBackend:
    b = FakeBackend(tmp_path)
    monkeypatch.setattr(commands, "get_backend", lambda: b)
    return b


def gui_install(backend, dist, progress, layout="msdos", fs="exfat", label="BEASTBOOTER", *extra):
    """The command line the GUI builds (controller.build_cli_argv) for a drive."""
    return run_cli("install", "--device", backend.disk.id, "--yes", "--progress-file", progress,
                   "--dist", dist, "--layout", layout, "--fs", fs, f"--label={label}", *extra)


@needs_fsck
@pytest.mark.parametrize("layout", ["msdos", "gpt"])
@pytest.mark.parametrize("fs", ["exfat", "fat32"])
def test_device_install(backend, fake_dist, tmp_path, layout, fs):
    progress = tmp_path / "progress.jsonl"
    assert gui_install(backend, fake_dist, progress, layout, fs) == 0
    # The backend was used in the right order, and the drive opened for writing once.
    assert backend.calls == [("get_disk", "/dev/fakesdz"), ("check_safe", False), ("prepare",),
                             ("open_raw", True), ("rescan",), ("open_raw", False)]
    assert all(t.fd == -1 for t in backend.opened)  # every target was closed
    img = backend.disk_file
    j = validate_drive(img, layout, fs, "BEASTBOOTER", tmp_path)
    events = read_events(progress)
    assert events[0] == {"v": 1, "event": "start", "action": "install", "target": "/dev/fakesdz"}
    assert step_ids(events) == INSTALL_STEPS
    assert events[-1] == {"v": 1, "event": "done", "ok": True, "info": j}
    # Old partition tables and boot code are gone: only core.img is left in the first MiB.
    raw = img.read_bytes()
    plan = make_plan(len(raw) // SECTOR_SIZE, layout)
    core_end = plan.core_lba * SECTOR_SIZE + -(-(fake_dist / "bios/core.img").stat().st_size // SECTOR_SIZE) * SECTOR_SIZE
    assert raw[core_end:MIB] == bytes(MIB - core_end)
    assert raw[0x5C:0x64] == plan.core_lba.to_bytes(8, "little")
    assert STALE * 16 not in raw[-MIB:]


@needs_fsck
def test_device_install_ntfs(backend, fake_dist, tmp_path):
    progress = tmp_path / "progress.jsonl"
    assert gui_install(backend, fake_dist, progress, "gpt", "ntfs") == 0
    # NTFS is made by the OS formatter on the new partition: re-read first, unmount again after.
    assert backend.names() == ["get_disk", "check_safe", "prepare", "open_raw", "rescan", "format_ntfs",
                               "prepare", "open_raw", "rescan", "open_raw"]
    assert ("format_ntfs", 1, "BEASTBOOTER") in backend.calls
    j = info_json(backend.disk_file)
    assert j["data"]["fs"] == "ntfs" and len(j["data"]["uuid"]) == 16
    events = read_events(progress)
    assert step_ids(events) == ["verify-dist", "check-target", "prepare", "partition", "flush", "rescan",
                                "format-data", "prepare", "write-esp", "boot-code", "flush", "rescan",
                                "verify-write"]
    assert events[-1]["event"] == "done" and events[-1]["info"] == j


def test_device_install_ntfs_refused_on_macos(backend, fake_dist, tmp_path, capsys):
    backend.name = "darwin"
    before = backend.disk_file.read_bytes()
    progress = tmp_path / "p.jsonl"
    assert gui_install(backend, fake_dist, progress, "msdos", "ntfs") == 1
    assert "macOS cannot create NTFS" in capsys.readouterr().err
    assert backend.disk_file.read_bytes() == before
    assert read_events(progress)[-1]["code"] == "unsupported"


def test_device_refusal_writes_nothing(backend, fake_dist, tmp_path, capsys):
    backend.set_disk(removable=False, bus="sata")
    before = backend.disk_file.read_bytes()
    progress = tmp_path / "p.jsonl"
    assert gui_install(backend, fake_dist, progress) == 1
    assert "--allow-fixed-disk" in capsys.readouterr().err
    assert backend.names() == ["get_disk", "check_safe"]
    assert backend.disk_file.read_bytes() == before
    events = read_events(progress)
    assert events[-1] == {"v": 1, "event": "error", "code": "target-refused", "message": events[-1]["message"]}
    assert "--allow-fixed-disk" in events[-1]["message"]
    # ... and with the override it goes ahead.
    assert gui_install(backend, fake_dist, tmp_path / "p2.jsonl", "msdos", "exfat", "BEASTBOOTER",
                       "--allow-fixed-disk") == 0


def test_device_confirmation(backend, fake_dist, monkeypatch, capsys):
    before = backend.disk_file.read_bytes()
    monkeypatch.setattr(commands, "confirm", lambda prompt: "sdz")
    assert run_cli("install", "--device", "/dev/fakesdz", "--dist", fake_dist) == 1
    assert "not confirmed" in capsys.readouterr().err
    assert "prepare" not in backend.names() and backend.disk_file.read_bytes() == before
    prompts = []
    monkeypatch.setattr(commands, "confirm", lambda prompt: prompts.append(prompt) or "fakesdz")
    assert run_cli("install", "--device", "/dev/fakesdz", "--quiet", "--dist", fake_dist) == 0
    out = capsys.readouterr().out
    assert "ACME Fake Stick" in out and "ALL DATA on /dev/fakesdz will be destroyed" in out
    assert prompts == ["Type the device name (fakesdz) to continue: "]


def test_device_esp_too_big_fails_before_writing(backend, dist_copy, tmp_path, capsys):
    from fakedist import write_manifest

    with open(dist_copy / "esp/grub/huge.bin", "wb") as f:  # sparse: larger than the 512 MiB ESP
        f.truncate(513 * MIB)
    write_manifest(dist_copy)
    sectors = backend.disk.size // 512
    before = sha_region(backend.disk_file, 0, sectors)
    assert run_cli("install", "--device", "/dev/fakesdz", "--yes", "--dist", dist_copy) == 1
    assert "do not fit" in capsys.readouterr().err
    assert "prepare" not in backend.names() and sha_region(backend.disk_file, 0, sectors) == before


def test_device_update_and_info(backend, fake_dist, fake_dist_v2, tmp_path, capsys):
    assert gui_install(backend, fake_dist, tmp_path / "i.jsonl", "gpt", "fat32") == 0
    img = backend.disk_file
    before = info_json(img)
    d = before["data"]
    data_hash = sha_region(img, d["start_lba"], d["size_lba"])
    backend.calls.clear()
    progress = tmp_path / "u.jsonl"
    assert run_cli("update", "--device", "/dev/fakesdz", "--yes", "--progress-file", progress,
                   "--dist", fake_dist_v2) == 0
    assert backend.calls == [("get_disk", "/dev/fakesdz"), ("check_safe", False), ("open_raw", False),
                             ("prepare",), ("open_raw", True), ("rescan",), ("open_raw", False)]
    assert sha_region(img, d["start_lba"], d["size_lba"]) == data_hash
    after = info_json(img)
    assert after["version"] == "0.2.0"
    assert {k: v for k, v in after.items() if k != "version"} == {k: v for k, v in before.items() if k != "version"}
    events = read_events(progress)
    assert events[0] == {"v": 1, "event": "start", "action": "update", "target": "/dev/fakesdz"}
    assert step_ids(events) == ["verify-dist", "check-target", "prepare", "write-esp", "boot-code", "flush",
                                "rescan", "verify-write"]
    assert events[-1] == {"v": 1, "event": "done", "ok": True, "info": after}
    capsys.readouterr()
    assert run_cli("info", "--device", "fakesdz", "--json") == 0
    assert __import__("json").loads(capsys.readouterr().out) == after
    validate_drive(img, "gpt", "fat32", "BEASTBOOTER", tmp_path)


def test_device_update_cannot_write_partition_1(backend, fake_dist, fake_dist_v2, monkeypatch):
    assert gui_install(backend, fake_dist, backend.disk_file.with_suffix(".jsonl")) == 0
    img = backend.disk_file
    d = info_json(img)["data"]
    data_hash = sha_region(img, d["start_lba"], d["size_lba"])
    real = commands._write_esp_and_boot

    def rogue(t, plan, *a, **kw):
        t.write(plan.data.offset, b"oops")  # a bug that aims at partition 1
        real(t, plan, *a, **kw)

    monkeypatch.setattr(commands, "_write_esp_and_boot", rogue)
    with pytest.raises(AssertionError, match="outside the allowed areas"):
        run_cli("update", "--device", "/dev/fakesdz", "--yes", "--quiet", "--dist", fake_dist_v2)
    assert sha_region(img, d["start_lba"], d["size_lba"]) == data_hash


def test_device_missing(backend, fake_dist, tmp_path, capsys):
    progress = tmp_path / "p.jsonl"
    assert run_cli("install", "--device", "/dev/nope", "--yes", "--progress-file", progress,
                   "--dist", fake_dist) == 1
    assert "/dev/nope does not exist" in capsys.readouterr().err
    assert read_events(progress)[-1]["event"] == "error"


def test_device_size_changed_is_refused(backend, fake_dist, monkeypatch, capsys):
    real_open = backend.open_raw

    def shrunk(disk, *, writable):
        t = real_open(disk, writable=writable)
        t.size -= MIB
        return t

    monkeypatch.setattr(backend, "open_raw", shrunk)
    assert run_cli("install", "--device", "/dev/fakesdz", "--yes", "--dist", fake_dist) == 1
    assert "size changed" in capsys.readouterr().err


def test_list_devices(tmp_path, monkeypatch, capsys):
    from dataclasses import replace

    b = FakeBackend(tmp_path, elevated=False)
    internal = replace(b.disk, id="/dev/nvme9n1", path="/dev/nvme9n1", model="Fast SSD", size=512 << 30,
                       bus="nvme", removable=False, system=True, partitions=(),
                       extra={"system_reason": "holds the system's / filesystem (/dev/nvme9n1p2)"})
    tiny = replace(b.disk, id="/dev/sdy", path="/dev/sdy", model="Old Card", size=128 * MIB, bus="sd",
                   partitions=(), extra={})
    b.extra_disks = [internal, tiny]
    monkeypatch.setattr(commands, "get_backend", lambda: b)

    assert run_cli("list-devices", "--json") == 0
    j = __import__("json").loads(capsys.readouterr().out)
    assert (j["v"], j["platform"], j["elevated"]) == (1, "fake", False)
    assert [d["id"] for d in j["disks"]] == ["/dev/fakesdz", "/dev/sdy"]
    stick = j["disks"][0]
    assert list(stick) == ["id", "path", "model", "size", "sector_size", "bus", "removable", "system",
                           "read_only", "mountpoints", "partitions", "extra", "eligible", "reason"]
    assert (stick["eligible"], stick["reason"], stick["partitions"]) == (True, None, ["/dev/fakesdz1"])
    assert j["disks"][1]["eligible"] is False and "too small" in j["disks"][1]["reason"]
    assert b.calls[-1] == ("list_disks", False)

    assert run_cli("list-devices", "--json", "--all") == 0
    j = __import__("json").loads(capsys.readouterr().out)
    assert b.calls[-1] == ("list_disks", True)
    nvme = [d for d in j["disks"] if d["id"] == "/dev/nvme9n1"][0]
    assert nvme["eligible"] is False and nvme["reason"].startswith("/dev/nvme9n1 holds the system's /")

    assert run_cli("list-devices", "--all") == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].split()[:3] == ["DEVICE", "SIZE", "BUS"]
    row = [line for line in lines if line.startswith("/dev/fakesdz")][0]
    assert "1.1 GiB" in row and "usb" in row and row.endswith("eligible")
    row = [line for line in lines if line.startswith("/dev/nvme9n1")][0]
    assert "not eligible: /dev/nvme9n1 holds the system's /" in row
    assert "administrator" in out

    b.extra_disks, b.disk = [], replace(b.disk, removable=False, bus="sata")
    assert run_cli("list-devices") == 0
    assert "No removable drives found" in capsys.readouterr().out


@pytest.mark.parametrize("bus,eligible", [("usb", True), ("sd", True), ("sata", False), ("nvme", False),
                                          ("scsi", False), ("virtual", False)])
def test_list_devices_external_bus_is_eligible(tmp_path, monkeypatch, capsys, bus, eligible):
    """USB SSDs/HDDs often report removable=0: the bus decides, as in the backends."""
    from dataclasses import replace

    b = FakeBackend(tmp_path)
    b.disk = replace(b.disk, removable=False, bus=bus)
    monkeypatch.setattr(commands, "get_backend", lambda: b)
    assert run_cli("list-devices", "--json", "--all") == 0
    (d,) = __import__("json").loads(capsys.readouterr().out)["disks"]
    assert d["eligible"] is eligible
    assert d["removable"] is False  # the backend's own value is reported unchanged
    if not eligible:
        assert "--allow-fixed-disk" in d["reason"]
    b.disk = replace(b.disk, read_only=True)
    assert commands.disk_problem(b.disk).endswith("is read-only (write-protect switch?)")
    b.disk = replace(b.disk, read_only=False, system=True, extra={"system_reason": "holds swap"})
    assert commands.disk_problem(b.disk) == "/dev/fakesdz holds swap"


def test_list_devices_unsupported_platform(monkeypatch, capsys):
    def unsupported():
        raise BeastError("writing drives is not supported on this platform ('plan9')")

    monkeypatch.setattr(commands, "get_backend", unsupported)
    assert run_cli("list-devices") == 1
    assert "not supported on this platform" in capsys.readouterr().err
