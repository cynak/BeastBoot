"""installed.py (version compare, assess, marker / version.cfg parsing) and
installed_probe.py (the unprivileged Linux / macOS / Windows probes).

The probes run against fake trees in tmp_path: device.SYS / DEV / PROC_MOUNTINFO
and installed_probe.UDEV_DATA / DEV_DISK point there, udisksctl and diskutil
are fakes that "mount" by adding a mountinfo line (or a MountPoint) for a
folder that holds the boot files. Nothing touches a real device.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys

import pytest

from beastbooter import device as devmod
from beastbooter import installed as installed_mod
from beastbooter import installed_probe as probe
from beastbooter.errors import BeastError
from beastbooter.esp import render_marker
from beastbooter.installed import (
    CURRENT, NEWER, OTHER_BUILD, OUTDATED, REINSTALL, UNKNOWN, InstalledBoot, ProbeResult, assess,
    compare_versions, from_texts, read_from_dir, version_key,
)
from beastbooter.interfaces import DiskInfo
from beastbooter.layout import ESP_MARKER_PATH, LAYOUT_VERSION
from beastbooter.platforms.darwin import DISKUTIL, DarwinBackend
from beastbooter.platforms.linux import LinuxBackend
from beastbooter.platforms.windows import WindowsBackend

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake sysfs / mount trees: POSIX only")

VERSION_CFG = 'set bb_version="0.2.0"\nset bb_build_id="82bc2b6c9502"\n'


def write_esp(root, *, marker=None, version_cfg=VERSION_CFG):
    root.mkdir(parents=True, exist_ok=True)
    (root / ESP_MARKER_PATH).write_text(render_marker("abcd1234", "0.2.0") if marker is None else marker)
    if version_cfg is not None:
        (root / "grub" / "beast").mkdir(parents=True, exist_ok=True)
        (root / "grub" / "beast" / "version.cfg").write_text(version_cfg)
    return root


def disk_info(id_, *, partitions=(), extra=None) -> DiskInfo:
    return DiskInfo(id=id_, path=id_, model="Stick", size=16 << 30, sector_size=512, bus="usb",
                    removable=True, system=False, read_only=False, partitions=tuple(partitions),
                    extra=dict(extra or {}))


# ---------------------------------------------------------------------------
# installed.py
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, want", [
    ("0.10.0", "0.9.0", 1),
    ("0.2.0-rc1", "0.2.0", -1),
    ("0.2.0rc1", "0.2.0-rc1", 0),
    ("0.2.0-rc2", "0.2.0-rc10", -1),
    ("0.2.0-alpha", "0.2.0-beta", -1),
    ("1.0.0+git5", "1.0.0", 0),
    ("v1.0", "1.0.0", 0),
    ("1.0", "1.0.0.0", 0),
    ("garbage", "0.0.1", -1),
    ("0.1.0", "0.1.0", 0),
    ("0.1.1", "0.1.0", 1),
])
def test_compare_versions(a, b, want):
    assert compare_versions(a, b) == want
    assert compare_versions(b, a) == -want


def test_version_key_sorts():
    vs = ["1.0.0", "0.2.0", "0.2.0-rc1", "0.10.0", "junk", "0.9.1"]
    assert sorted(vs, key=version_key) == ["junk", "0.2.0-rc1", "0.2.0", "0.9.1", "0.10.0", "1.0.0"]


def inst(version="0.2.0", build="b1", layout=LAYOUT_VERSION):
    return InstalledBoot(version=version, build_id=build, layout_version=layout)


@pytest.mark.parametrize("installed, app, build, state, needs", [
    (None, "0.2.0", "", UNKNOWN, False),
    (inst(layout=LAYOUT_VERSION - 1), "0.2.0", "", REINSTALL, False),
    (inst(version=""), "0.2.0", "", OUTDATED, True),
    (inst(version="0.1.0"), "0.2.0", "", OUTDATED, True),
    (inst(version="0.3.0"), "0.2.0", "", NEWER, False),
    (inst(build="b1"), "0.2.0", "b2", OTHER_BUILD, True),
    (inst(build="b1"), "0.2.0", "b1", CURRENT, False),
    (inst(build=""), "0.2.0", "b2", CURRENT, False),  # a build id unknown on one side: same version is current
    (inst(build="b1"), "0.2.0", "", CURRENT, False),
    (inst(layout=None, version="0.1.0"), "0.2.0", "", REINSTALL, False),  # unknown layout: update would refuse
    (inst(layout=LAYOUT_VERSION + 1, version="0.1.0"), "0.2.0", "", NEWER, False),  # layout-too-new
])
def test_assess(installed, app, build, state, needs):
    f = assess(installed, app, build)
    assert f.state == state
    assert f.needs_update is needs
    assert f.app_version == app
    assert f.summary
    assert bool(f.advice) == (state != CURRENT)


def test_assess_texts_name_versions():
    f = assess(inst(version="0.1.0"), "0.2.0")
    assert "0.1.0" in f.summary and "0.2.0" in f.summary
    assert "administrator" in assess(None, "0.2.0").advice


def test_from_texts():
    marker = render_marker("abcd1234", "0.1.9")
    i = from_texts(marker, VERSION_CFG, "here")
    assert i == InstalledBoot("0.2.0", "82bc2b6c9502", LAYOUT_VERSION, "abcd1234", "here")
    assert from_texts(marker, None).version == "0.1.9"  # no version.cfg: the marker's version
    assert from_texts(marker, "# nothing\n").build_id == ""
    assert from_texts("beast-booter\n", None) == InstalledBoot("", "", 1, "", "")  # old marker: layout 1
    assert from_texts("beast-booter\nlayout_version=x\n", None).layout_version is None
    assert from_texts(None, VERSION_CFG) is None
    assert from_texts("", VERSION_CFG) is None
    assert from_texts("something else\nversion=1\n", VERSION_CFG) is None


def test_read_from_dir(tmp_path):
    esp = write_esp(tmp_path / "esp")
    i = read_from_dir(esp)
    assert (i.version, i.build_id, i.how) == ("0.2.0", "82bc2b6c9502", f"mounted at {esp}")
    assert read_from_dir(esp, "udisks").how == "udisks"
    assert read_from_dir(tmp_path / "missing") is None
    (tmp_path / "empty").mkdir()
    assert read_from_dir(tmp_path / "empty") is None


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

class FakeLinux:
    """sysfs / dev / mountinfo / udev database in tmp_path; udisksctl is self.udisks."""

    def __init__(self, tmp_path, monkeypatch):
        root = tmp_path / "fake"
        self.sys, self.dev, self.udev, self.bydisk = root / "sys", root / "dev", root / "udev", root / "disk"
        for d in (self.sys / "block", self.dev, self.udev, self.bydisk):
            d.mkdir(parents=True)
        self.mountinfo = root / "mountinfo"
        self.mountinfo.write_text("22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n")
        self.media = tmp_path / "media"
        self.esp_files = write_esp(tmp_path / "espfiles")  # what the fake mount shows
        self.commands: list[list[str]] = []
        self.mount_rc, self.mount_out = 0, None
        self.mount_appears: int | None = 0  # after how many mountinfo reads the mount shows (None: never)
        self.info_mountpoint = ""  # what `udisksctl info` shows when mountinfo does not
        self._pending: list = []
        self.unmount_results: list[tuple[int, str]] = []
        monkeypatch.setattr(devmod, "SYS", str(self.sys))
        monkeypatch.setattr(devmod, "DEV", str(self.dev))
        monkeypatch.setattr(devmod, "PROC_MOUNTINFO", str(self.mountinfo))
        monkeypatch.setattr(devmod, "_stat_block", lambda p: None)
        monkeypatch.setattr(probe, "UDEV_DATA", str(self.udev))
        monkeypatch.setattr(probe, "DEV_DISK", str(self.bydisk))
        monkeypatch.setattr(probe, "UNMOUNT_RETRY_DELAY", 0)
        monkeypatch.setattr(probe, "LATE_MOUNT_WATCH", 0.2)
        monkeypatch.setattr(probe, "LATE_MOUNT_POLL", 0.01)
        real_read_mounts = devmod.read_mounts

        def read_mounts():
            if self._pending:
                self._pending[0] -= 1
                if self._pending[0] <= 0:
                    self.mount(*self._pending[1:])
                    self._pending = []
            return real_read_mounts()
        monkeypatch.setattr(devmod, "read_mounts", read_mounts)
        monkeypatch.setattr(probe, "_run", self.run)
        self.which = "/usr/bin/udisksctl"
        monkeypatch.setattr(probe.shutil, "which", lambda name: self.which if name == "udisksctl" else None)

    def add_disk(self, name, parts):
        """parts: {index: (devnum, udev E: lines or None for no database entry)}"""
        sysdir = self.sys / "devices" / name
        sysdir.mkdir(parents=True)
        os.symlink(sysdir, self.sys / "block" / name)
        for index, (devnum, props) in parts.items():
            pname = f"{name}p{index}" if name[-1].isdigit() else f"{name}{index}"
            (sysdir / pname).mkdir()
            (sysdir / pname / "partition").write_text(f"{index}\n")
            (sysdir / pname / "dev").write_text(f"{devnum}\n")
            (self.dev / pname).write_text("")
            if props is not None:
                (self.udev / f"b{devnum}").write_text("".join(f"E:{k}={v}\n" for k, v in props.items()) + "G:x\n")
        return disk_info(str(self.dev / name), extra={"name": name})

    def mount(self, devnum, node, mnt):
        with open(self.mountinfo, "a") as f:
            f.write(f"40 22 {devnum} / {mnt} ro,relatime shared:9 - vfat {node} ro,fmask=0022\n")

    def mounted(self, devnum) -> list[str]:
        return [line for line in self.mountinfo.read_text().splitlines() if f" {devnum} " in line]

    def run(self, argv, timeout=probe.TOOL_TIMEOUT):
        self.commands.append(argv[1:])
        node = argv[argv.index("-b") + 1]
        devnum = next((self.sys / "devices").glob(f"*/{os.path.basename(node)}/dev")).read_text().strip()
        if argv[1] == "mount":
            if self.mount_appears == 0:
                self.mount(devnum, node, self.esp_files)
            elif self.mount_appears is not None:
                self._pending = [self.mount_appears, devnum, node, self.esp_files]
            if self.mount_rc == 0:
                return 0, self.mount_out or f"Mounted {node} at {self.esp_files}"
            return self.mount_rc, self.mount_out or "Error mounting: Not authorized to perform operation"
        if argv[1] == "info":
            mnt = self.info_mountpoint or "".join(m.split()[4] for m in self.mounted(devnum))
            return 0, f"  org.freedesktop.UDisks2.Filesystem:\n    MountPoints:        {mnt}\n    Size: 1\n"
        if self.unmount_results:
            rc, out = self.unmount_results.pop(0)
        else:
            rc, out = 0, ""
        if rc == 0:
            self.mountinfo.write_text("".join(line + "\n" for line in self.mountinfo.read_text().splitlines()
                                              if f" {devnum} " not in line))
        return rc, out


ESP_PROPS = {"ID_FS_TYPE": "vfat", "ID_FS_LABEL": "BEAST-EFI", "ID_PART_ENTRY_NAME": "BEAST-EFI",
             "ID_PART_ENTRY_TYPE": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "UDISKS_IGNORE": "1"}
DATA_PROPS = {"ID_FS_TYPE": "exfat", "ID_FS_LABEL": "BEASTBOOTER"}


@pytest.fixture
def fl(tmp_path, monkeypatch):
    return FakeLinux(tmp_path, monkeypatch)


@posix_only
def test_linux_mounts_reads_and_unmounts(fl):
    disk = fl.add_disk("sdb", {1: ("8:17", DATA_PROPS), 2: ("8:18", ESP_PROPS)})
    r = LinuxBackend().probe_installed(disk)  # the backend delegates to probe_linux
    assert r.installed.version == "0.2.0" and r.installed.build_id == "82bc2b6c9502"
    assert r.note == "" and "udisks" in r.installed.how
    node = str(fl.dev / "sdb2")
    assert fl.commands == [["mount", "-b", node, "--options", "ro", "--no-user-interaction"],
                           ["unmount", "-b", node, "--no-user-interaction"]]
    assert fl.mounted("8:18") == []


@posix_only
def test_linux_already_mounted_is_read_in_place(fl):
    disk = fl.add_disk("sdb", {1: ("8:17", DATA_PROPS), 2: ("8:18", ESP_PROPS)})
    fl.mount("8:18", "/dev/sdb2", fl.esp_files)
    r = probe.probe_linux(None, disk)
    assert r.installed.version == "0.2.0" and r.installed.how == f"mounted at {fl.esp_files}"
    assert fl.commands == [] and fl.mounted("8:18")  # left as it was


@posix_only
@pytest.mark.parametrize("props", [
    {"ID_FS_TYPE": "vfat", "ID_FS_LABEL": "EFI"},                       # someone else's ESP
    {"ID_FS_TYPE": "vfat"},                                             # no label
    {"ID_FS_TYPE": "ext4", "ID_FS_LABEL": "BEAST-EFIX"},
])
def test_linux_not_ours_mounts_nothing(fl, props):
    disk = fl.add_disk("sdb", {1: ("8:17", DATA_PROPS), 2: ("8:18", props)})
    assert probe.probe_linux(None, disk) is None
    assert fl.commands == []


@posix_only
def test_linux_no_partition_two_or_no_sysfs(fl):
    assert probe.probe_linux(None, fl.add_disk("sdb", {1: ("8:17", ESP_PROPS)})) is None
    assert probe.probe_linux(None, disk_info(str(fl.dev / "sdz"), extra={"name": "sdz"})) is None
    assert fl.commands == []


@posix_only
def test_linux_partition_name_alone_and_nvme_names(fl):
    disk = fl.add_disk("nvme1n1", {1: ("259:5", DATA_PROPS),
                                   2: ("259:6", {"ID_FS_TYPE": "vfat", "ID_PART_ENTRY_NAME": "BEAST-EFI"})})
    assert probe.probe_linux(None, disk).installed.version == "0.2.0"
    assert fl.commands[0][2] == str(fl.dev / "nvme1n1p2")


@posix_only
def test_linux_without_udev_database_uses_by_label_links(fl):
    disk = fl.add_disk("sdb", {1: ("8:17", None), 2: ("8:18", None)})
    assert probe.probe_linux(None, disk) is None  # nothing says it is ours
    (fl.bydisk / "by-label").mkdir()
    os.symlink(fl.dev / "sdb2", fl.bydisk / "by-label" / "BEAST-EFI")
    assert probe.probe_linux(None, disk).installed.version == "0.2.0"


@posix_only
def test_linux_mount_refused(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.mount_rc, fl.mount_appears = 1, None
    r = probe.probe_linux(None, disk)
    assert r.installed is None and "Not authorized" in r.note
    assert [c[0] for c in fl.commands] == ["mount", "info"]  # one look; nothing to unmount


@posix_only
def test_linux_mount_finds_it_already_mounted_elsewhere(fl, monkeypatch):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.mount_rc, fl.mount_appears = 1, None

    def racing_mount(argv, timeout=0):  # someone mounted it between our check and udisksctl
        fl.commands.append(argv[1:])
        fl.mount("8:18", "/dev/sdb2", fl.esp_files)
        return 1, "Error mounting /dev/sdb2: Device is already mounted"
    monkeypatch.setattr(probe, "_run", racing_mount)
    r = probe.probe_linux(None, disk)
    assert r.installed.version == "0.2.0" and r.installed.how.startswith("mounted at")
    assert [c[0] for c in fl.commands] == ["mount"] and fl.mounted("8:18")  # not ours: not unmounted


@posix_only
def test_linux_mount_timeout_still_unmounts(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.mount_rc, fl.mount_appears = 124, None  # timed out and never mounted: watched, then asked udisks
    r = probe.probe_linux(None, disk)
    assert r.installed is None and "did not mount" in r.note
    assert [c[0] for c in fl.commands] == ["mount", "info"]


@posix_only
@pytest.mark.parametrize("rc, out", [(124, "udisksctl did not finish within 4 s"),
                                     (1, "Error mounting /dev/sdb2: Timeout was reached")])
@pytest.mark.parametrize("appears", [0, 5])  # at once / a few polls later
def test_linux_late_mount_after_timeout_is_unmounted(fl, rc, out, appears):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.mount_rc, fl.mount_out, fl.mount_appears = rc, out, appears
    r = probe.probe_linux(None, disk)
    assert r.installed.version == "0.2.0" and "udisks" in r.installed.how
    assert [c[0] for c in fl.commands] == ["mount", "unmount"]
    assert fl.mounted("8:18") == []


@posix_only
def test_linux_late_mount_seen_only_by_udisks_is_unmounted(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})  # e.g. a sandbox with its own mount namespace
    fl.mount_rc, fl.mount_appears, fl.info_mountpoint = 124, None, str(fl.esp_files)
    r = probe.probe_linux(None, disk)
    assert r.installed.version == "0.2.0"
    assert [c[0] for c in fl.commands] == ["mount", "info", "unmount"]


@posix_only
def test_linux_should_stop_before_mounting(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    r = probe.probe_linux(None, disk, should_stop=lambda: True)
    assert r.installed is None and "stopped" in r.note and fl.commands == []


@posix_only
def test_linux_stop_after_mounting_still_cleans_up(fl, monkeypatch):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    stop: list[bool] = []
    fl.mount_rc, fl.mount_appears = 124, 3  # times out, shows up on the 3rd mountinfo read
    fl.unmount_results = [(1, "target is busy")]
    real = fl.run

    def run(argv, timeout=0):
        if argv[1] == "mount":
            stop.append(True)  # the GUI asks to stop while the mount is running
        return real(argv, timeout)
    slept: list[float] = []
    monkeypatch.setattr(probe, "_run", run)
    monkeypatch.setattr(probe, "UNMOUNT_RETRY_DELAY", 0.5)
    monkeypatch.setattr(probe.time, "sleep", slept.append)
    r = probe.probe_linux(None, disk, should_stop=lambda: bool(stop))
    assert r.installed.version == "0.2.0"
    assert [c[0] for c in fl.commands] == ["mount", "unmount", "unmount"] and fl.commands[-1][-1] == "--force"
    assert fl.mounted("8:18") == [] and 0.5 not in slept  # watched for the late mount; no pause before --force


def test_linux_worst_case_is_bounded():
    worst = (probe.MOUNT_TIMEOUT + probe.LATE_MOUNT_WATCH + probe.INFO_TIMEOUT
             + 2 * probe.UNMOUNT_TIMEOUT + probe.UNMOUNT_RETRY_DELAY)
    assert worst < 13


@posix_only
def test_linux_no_udisksctl(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.which = None
    r = probe.probe_linux(None, disk)
    assert r == ProbeResult(None, r.note) and "udisksctl" in r.note
    assert fl.commands == []


@posix_only
def test_linux_not_fat(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", {"ID_FS_TYPE": "ntfs", "ID_PART_ENTRY_NAME": "BEAST-EFI"})})
    r = probe.probe_linux(None, disk)
    assert r.installed is None and "ntfs" in r.note and fl.commands == []


@posix_only
def test_linux_label_but_no_marker_is_not_ours(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    (fl.esp_files / ESP_MARKER_PATH).unlink()
    assert probe.probe_linux(None, disk) is None
    assert [c[0] for c in fl.commands] == ["mount", "unmount"] and fl.mounted("8:18") == []


@posix_only
def test_linux_unmount_retries_then_forces(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.unmount_results = [(1, "target is busy"), (0, "")]
    assert probe.probe_linux(None, disk).note == ""
    assert [c[0] for c in fl.commands] == ["mount", "unmount", "unmount"]
    assert fl.commands[-1][-1] == "--force"

    fl.commands.clear()
    fl.unmount_results = [(1, "busy"), (1, "busy")]
    r = probe.probe_linux(None, disk)
    assert r.installed.version == "0.2.0" and "could not be unmounted" in r.note
    assert len(fl.commands) == 3


@posix_only
def test_linux_unmount_not_mounted_counts_as_done(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.unmount_results = [(1, "Error unmounting: Device `/dev/sdb2' is not mounted")]
    assert probe.probe_linux(None, disk).note == ""
    assert len(fl.commands) == 2


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads anything")
def test_linux_mounted_but_unreadable(fl):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})
    fl.mount("8:18", "/dev/sdb2", fl.esp_files)
    fl.esp_files.chmod(0)
    try:
        r = probe.probe_linux(None, disk)
    finally:
        fl.esp_files.chmod(0o755)
    assert r.installed is None and "administrator" in r.note


@posix_only
def test_linux_unexpected_error_after_identifying_is_a_note(fl, monkeypatch):
    disk = fl.add_disk("sdb", {2: ("8:18", ESP_PROPS)})

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(probe, "_linux_mountpoint", boom)
    r = probe.probe_linux(None, disk)
    assert r.installed is None and "boom" in r.note


def test_run_reports_missing_tool_and_timeout(tmp_path):
    assert probe._run([str(tmp_path / "nope")])[0] == 127
    rc, out = probe._run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
    assert rc == 124 and "did not finish" in out
    assert probe._run([sys.executable, "-c", "print('hi')"]) == (0, "hi")


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

class FakeDiskutil:
    def __init__(self, mnt, info):
        self.mnt, self.info = str(mnt), dict(info)
        self.calls: list[list[str]] = []
        self.fail: set[str] = set()

    def __call__(self, argv):
        assert argv[0] == DISKUTIL
        self.calls.append(argv[1:])
        verb = argv[1]
        if verb in self.fail:
            raise BeastError(f"diskutil {verb} failed: nope")
        if verb == "info":
            assert argv[2:] == ["-plist", "disk4s2"]
            return b"junk before\n" + plistlib.dumps(self.info)
        if verb == "mount":
            assert argv[2:] == ["readOnly", "/dev/disk4s2"]
            self.info["MountPoint"] = self.mnt
        elif verb == "unmount":
            assert argv[2:] == ["/dev/disk4s2"]
            self.info["MountPoint"] = ""
        return b"ok\n"


ESP_INFO = {"DeviceIdentifier": "disk4s2", "VolumeName": "BEAST-EFI", "Content": "EFI",
            "FilesystemType": "msdos", "MountPoint": ""}
MAC_DISK = disk_info("/dev/disk4", partitions=("/dev/disk4s1", "/dev/disk4s2"), extra={"bsd_name": "disk4"})


def test_darwin_mounts_reads_and_unmounts(tmp_path):
    du = FakeDiskutil(write_esp(tmp_path / "Volumes" / "BEAST-EFI"), ESP_INFO)
    r = DarwinBackend(runner=du).probe_installed(MAC_DISK)
    assert r.installed.version == "0.2.0" and r.note == "" and "diskutil" in r.installed.how
    assert [c[0] for c in du.calls] == ["info", "mount", "info", "unmount"]
    assert du.info["MountPoint"] == ""


def test_darwin_already_mounted(tmp_path):
    mnt = write_esp(tmp_path / "Volumes" / "BEAST-EFI")
    du = FakeDiskutil(mnt, {**ESP_INFO, "MountPoint": str(mnt)})
    r = probe.probe_darwin(DarwinBackend(runner=du), MAC_DISK)
    assert r.installed.how == f"mounted at {mnt}" and du.calls == [["info", "-plist", "disk4s2"]]


def test_darwin_by_partition_name(tmp_path):
    info = {**ESP_INFO, "VolumeName": "", "MediaName": "BEAST-EFI"}
    du = FakeDiskutil(write_esp(tmp_path / "m"), info)
    assert probe.probe_darwin(DarwinBackend(runner=du), MAC_DISK).installed.version == "0.2.0"


def test_darwin_not_ours_or_no_slice_two(tmp_path):
    du = FakeDiskutil(tmp_path, {**ESP_INFO, "VolumeName": "EFI"})
    backend = DarwinBackend(runner=du)
    assert probe.probe_darwin(backend, MAC_DISK) is None
    assert du.calls == [["info", "-plist", "disk4s2"]]
    one = disk_info("/dev/disk4", partitions=("/dev/disk4s1",), extra={"bsd_name": "disk4"})
    assert probe.probe_darwin(backend, one) is None and len(du.calls) == 1
    du.fail.add("info")
    assert probe.probe_darwin(backend, MAC_DISK) is None


def test_darwin_mount_fails(tmp_path):
    du = FakeDiskutil(tmp_path, ESP_INFO)
    du.fail.add("mount")
    r = probe.probe_darwin(DarwinBackend(runner=du), MAC_DISK)
    assert r.installed is None and "nope" in r.note
    assert [c[0] for c in du.calls] == ["info", "mount"]


def test_darwin_unmount_fails_keeps_version(tmp_path):
    du = FakeDiskutil(write_esp(tmp_path / "m"), ESP_INFO)
    du.fail.add("unmount")
    r = probe.probe_darwin(DarwinBackend(runner=du), MAC_DISK)
    assert r.installed.version == "0.2.0" and "unmounted" in r.note


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def win_disk(*volumes):
    return disk_info(r"\\.\PhysicalDrive2", partitions=(r"\\.\PhysicalDrive2\1", r"\\.\PhysicalDrive2\2"),
                     extra={"number": 2, "volumes": list(volumes)})


@pytest.fixture
def roots(monkeypatch):
    """_read_root on fake drive roots: {root: ProbeResult | None}; records what was read."""
    table: dict[str, ProbeResult | None] = {}
    seen: list[str] = []

    def fake(root, how):
        seen.append(root)
        return table.get(root)
    monkeypatch.setattr(probe, "_read_root", fake)
    return table, seen


DATA_VOL = {"partition": 1, "letter": "E", "label": "BEASTBOOTER", "fs": "exFAT"}
ESP_VOL = {"partition": 2, "letter": None, "label": "BEAST-EFI", "fs": "FAT32"}


def test_windows_reads_the_drive_letter(roots):
    table, seen = roots
    table["F:\\"] = ProbeResult(inst())
    r = WindowsBackend().probe_installed(win_disk(DATA_VOL, {**ESP_VOL, "letter": "F"}))
    assert r.installed == inst() and seen == ["F:\\"]


def test_windows_volume_path_when_listed(roots):
    table, seen = roots
    path = "\\\\?\\Volume{1234}\\"
    table[path] = ProbeResult(inst())
    r = probe.probe_windows(None, win_disk(DATA_VOL, {**ESP_VOL, "path": path[:-1]}))
    assert r.installed == inst() and seen == [path]


def test_windows_no_letter(roots):
    _table, seen = roots
    assert probe.probe_windows(None, win_disk(DATA_VOL, ESP_VOL)) == ProbeResult(None, "the boot partition has no drive letter")
    assert probe.probe_windows(None, win_disk(DATA_VOL)).note == "the boot partition has no drive letter"  # ESP not listed
    assert probe.probe_windows(None, win_disk({**ESP_VOL, "label": "beast-efi"})).installed is None
    assert seen == []


def test_windows_not_ours(roots):
    _table, seen = roots
    assert probe.probe_windows(None, win_disk({**DATA_VOL, "label": "KINGSTON"})) is None
    assert probe.probe_windows(None, win_disk()) is None
    assert probe.probe_windows(None, disk_info(r"\\.\PhysicalDrive3")) is None
    # a BEAST-EFI volume we can read that has no marker: not a beast-boot drive
    assert probe.probe_windows(None, win_disk(DATA_VOL, {**ESP_VOL, "letter": "F"})) is None
    assert seen == ["F:\\"]


@posix_only
def test_read_root_unreadable_and_missing(tmp_path):
    assert probe._read_root(str(tmp_path), "x") is None  # readable, no marker
    esp = write_esp(tmp_path / "esp")
    assert probe._read_root(str(esp), "x").installed.how == "x"


# -- installed firmware packs, read from a mounted boot partition -------------------

def _esp(tmp_path, installed=None, cpios=()):
    root = tmp_path / "esp"
    (root / "grub" / "beast").mkdir(parents=True)
    (root / "BEAST-BOOTER.ID").write_text("beast-booter\ninstall_id=x\nlayout_version=2\nversion=0.1.0\n")
    (root / "grub" / "beast" / "version.cfg").write_text('set bb_version="0.1.0"\nset bb_build_id="abc"\n')
    fw = root / "beast-net" / "firmware"
    fw.mkdir(parents=True)
    if installed is not None:
        (fw / "installed.json").write_text(installed if isinstance(installed, str) else json.dumps(installed))
    for name, size in cpios:
        (fw / name).write_bytes(b"\0" * size)
    return root


def test_firmware_none_installed(tmp_path):
    fw = installed_mod.read_from_dir(_esp(tmp_path)).firmware
    assert fw["v"] == 1 and fw["packs"] == [] and fw["esp_label"] == "BEAST-EFI"
    assert fw["installed_json_size"] == 0 and fw["esp_free"] > 0


def test_firmware_packs_sizes_and_missing(tmp_path):
    from beastbooter.gui.firmware import parse_installed, parse_space

    doc = {"v": 1, "packs": [{"id": "realtek-wifi", "files": []},
                             {"id": "intel-wifi", "catalog_tag": "20261019", "cpio_sha256": "ab",
                              "files": [{"path": "iwlwifi-x.ucode", "size": 3}]}]}
    fw = installed_mod.read_from_dir(_esp(tmp_path, doc, [("Intel-WiFi.cpio", 5000)])).firmware
    assert [p["id"] for p in fw["packs"]] == ["intel-wifi", "realtek-wifi"]  # sorted, like `firmware list`
    assert fw["packs"][0]["cpio_size"] == 5000 and fw["packs"][1]["missing"] is True
    assert [p.id for p in parse_installed(fw)] == ["intel-wifi", "realtek-wifi"]
    space = parse_space(fw)
    assert space.files["intel-wifi.cpio"] == 5000 and space.files["installed.json"] == fw["installed_json_size"]


@pytest.mark.parametrize("bad", ["{broken", json.dumps({"v": 2, "packs": []}), json.dumps({"v": 1, "packs": [{"no": "id"}]})])
def test_firmware_unreadable_installed_json_is_unknown(tmp_path, bad):
    boot = installed_mod.read_from_dir(_esp(tmp_path, bad))
    assert boot is not None and boot.version == "0.1.0" and boot.firmware is None


@pytest.mark.parametrize("layout,state", [(None, "reinstall"), (1, "reinstall"), (3, "newer")])
def test_assess_never_offers_an_update_the_cli_refuses(layout, state):
    from beastbooter.installed import InstalledBoot, assess

    f = assess(InstalledBoot("0.0.1", "aaa", layout), "0.1.0", "bbb")
    assert f.state == state and not f.needs_update
