"""Device safety checks (device.py) and the CLI's device refusals through the
Linux backend, against a fake sysfs/proc/dev tree.

Nothing here opens a real block device: SYS, DEV, PROC_* point into tmp_path,
_stat_block is a dict lookup and _exclusive_probe is recorded. The full device
install flow is in test_inst_device_flow.py (fake backend, file as the drive).
"""

from __future__ import annotations

import errno
import os

import pytest

from beastbooter import commands
from beastbooter import device as dev
from beastbooter import fs as fsmod
from beastbooter.errors import BeastError
from conftest import run_cli

GIB = 1 << 30


class FakeSystem:
    def __init__(self, tmp_path, monkeypatch):
        self.root = tmp_path / "fake"
        self.sys = self.root / "sys"
        self.dev = self.root / "dev"
        self.dev.mkdir(parents=True)
        (self.sys / "dev" / "block").mkdir(parents=True)
        (self.sys / "block").mkdir(parents=True)
        self.mountinfo = self.root / "mountinfo"
        self.swaps = self.root / "swaps"
        self.mountinfo.write_text("")
        self.swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n")
        self.blockmap: dict[str, str] = {}
        self.probed: list[str] = []
        self.sysdirs: dict[str, object] = {}
        monkeypatch.setattr(dev, "SYS", str(self.sys))
        monkeypatch.setattr(dev, "DEV", str(self.dev))
        monkeypatch.setattr(dev, "PROC_MOUNTINFO", str(self.mountinfo))
        monkeypatch.setattr(dev, "PROC_SWAPS", str(self.swaps))
        monkeypatch.setattr(dev, "_stat_block", lambda p: self.blockmap.get(os.path.realpath(p)))
        monkeypatch.setattr(dev, "_exclusive_probe", self.probed.append)

    def node(self, name: str) -> str:
        return str(self.dev / name)

    def add_disk(self, name, devnum, *, size=16 * GIB, removable=True, parts=(), model="Fake Stick",
                 ro=False, lbs=512, holders=()):
        sysdir = self.sys / "devices" / "fake" / "block" / name
        (sysdir / "queue").mkdir(parents=True)
        (sysdir / "device").mkdir()
        (sysdir / "holders").mkdir()
        (sysdir / "size").write_text(f"{size // 512}\n")
        (sysdir / "removable").write_text("1\n" if removable else "0\n")
        (sysdir / "ro").write_text("1\n" if ro else "0\n")
        (sysdir / "dev").write_text(devnum + "\n")
        (sysdir / "queue" / "logical_block_size").write_text(f"{lbs}\n")
        (sysdir / "device" / "vendor").write_text("ACME    \n")
        (sysdir / "device" / "model").write_text(model + "\n")
        for h in holders:
            (sysdir / "holders" / h).mkdir()
        (self.sys / "dev" / "block" / devnum).symlink_to(sysdir)
        (self.sys / "block" / name).symlink_to(sysdir)
        self._node(name, devnum)
        self.sysdirs[name] = sysdir
        for i, (pname, pdn) in enumerate(parts, 1):
            pdir = sysdir / pname
            (pdir / "holders").mkdir(parents=True)
            (pdir / "partition").write_text(f"{i}\n")
            (pdir / "dev").write_text(pdn + "\n")
            (self.sys / "dev" / "block" / pdn).symlink_to(pdir)
            self._node(pname, pdn)
            self.sysdirs[pname] = pdir
        return sysdir

    def add_dm(self, name, devnum, slaves):
        sysdir = self.sys / "devices" / "virtual" / "block" / name
        (sysdir / "slaves").mkdir(parents=True)
        (sysdir / "dm").mkdir()
        (sysdir / "dev").write_text(devnum + "\n")
        for s in slaves:
            (sysdir / "slaves" / s).symlink_to(self.sysdirs[s])
            (self.sysdirs[s] / "holders" / name).mkdir()
        (self.sys / "dev" / "block" / devnum).symlink_to(sysdir)
        self._node(name, devnum)
        self.sysdirs[name] = sysdir

    def _node(self, name, devnum):
        (self.dev / name).write_text("")
        self.blockmap[str(self.dev / name)] = devnum

    def mount(self, devnum, source, mountpoint, fstype="ext4"):
        with open(self.mountinfo, "a") as f:
            mp = mountpoint.replace(" ", "\\040")
            f.write(f"30 1 {devnum} / {mp} rw,relatime shared:1 - {fstype} {source} rw\n")

    def swap(self, source):
        with open(self.swaps, "a") as f:
            f.write(f"{source}\tpartition\t1048572\t0\t-2\n")


@pytest.fixture
def fake(tmp_path, monkeypatch):
    fs = FakeSystem(tmp_path, monkeypatch)
    # A typical machine: NVMe system disk, plus a USB stick sdb with one partition.
    fs.add_disk("nvme0n1", "259:0", size=512 * GIB, removable=False, model="Fast SSD",
                parts=[("nvme0n1p1", "259:1"), ("nvme0n1p2", "259:2")])
    fs.mount("259:2", fs.node("nvme0n1p2"), "/")
    fs.mount("259:1", fs.node("nvme0n1p1"), "/boot/efi", "vfat")
    fs.add_disk("sdb", "8:16", parts=[("sdb1", "8:17")])
    return fs


def test_inspect_whole_disk(fake):
    d = dev.inspect_disk(fake.node("sdb"))
    assert (d.name, d.node, d.devnum, d.size_bytes, d.removable) == ("sdb", fake.node("sdb"), "8:16", 16 * GIB, True)
    assert d.model == "ACME Fake Stick" and d.partitions == {"sdb1": "8:17"}
    assert "16.0 GiB" in d.describe() and "removable" in d.describe()


def test_clean_removable_disk_passes(fake):
    d = dev.inspect_disk(fake.node("sdb"))
    dev.check_safe(d, allow_fixed=False)
    assert fake.probed == [fake.node("sdb")]


def test_partition_refused(fake):
    with pytest.raises(BeastError, match=r"is a partition; pass the whole disk .*sdb\)"):
        dev.inspect_disk(fake.node("sdb1"))


def test_not_block_device(fake, tmp_path):
    f = tmp_path / "file.img"
    f.write_bytes(b"")
    with pytest.raises(BeastError, match="not a block device"):
        dev.inspect_disk(str(f))
    with pytest.raises(BeastError, match="does not exist"):
        dev.inspect_disk(str(tmp_path / "nope"))


def test_virtual_devices_refused(fake):
    fake.add_dm("dm-0", "253:0", ["sdb1"])
    with pytest.raises(BeastError, match="not a physical disk"):
        dev.inspect_disk(fake.node("dm-0"))


def test_mounted_partition_refused(fake):
    fake.mount("8:17", fake.node("sdb1"), "/media/me/MY STICK", "vfat")
    with pytest.raises(BeastError, match=r"sdb1 is mounted at /media/me/MY STICK"):
        dev.check_safe(dev.inspect_disk(fake.node("sdb")), allow_fixed=False)
    assert fake.probed == []


def test_mounted_by_source_only_refused(fake):
    # btrfs reports an anonymous device number; the source path still identifies it.
    fake.mount("0:45", fake.node("sdb1"), "/mnt/data", "btrfs")
    with pytest.raises(BeastError, match="mounted at /mnt/data"):
        dev.check_safe(dev.inspect_disk(fake.node("sdb")), allow_fixed=False)


def test_whole_disk_mounted_refused(fake):
    fake.mount("8:16", fake.node("sdb"), "/mnt/raw", "vfat")
    with pytest.raises(BeastError, match="sdb is mounted at /mnt/raw"):
        dev.check_safe(dev.inspect_disk(fake.node("sdb")), allow_fixed=False)


def test_system_disk_refused(fake):
    d = dev.inspect_disk(fake.node("nvme0n1"))
    with pytest.raises(BeastError, match=r"holds the system's / filesystem"):
        dev.check_safe(d, allow_fixed=True)


def test_system_disk_behind_lvm_refused(fake):
    fake.add_disk("sda", "8:0", size=1024 * GIB, removable=False, parts=[("sda1", "8:1"), ("sda2", "8:2")])
    fake.add_dm("dm-0", "253:0", ["sda2"])
    fake.mount("253:0", "/dev/mapper/vg-home", "/boot")
    with pytest.raises(BeastError, match=r"holds the system's /boot filesystem"):
        dev.check_safe(dev.inspect_disk(fake.node("sda")), allow_fixed=True)


def test_boot_efi_on_usb_refused(fake):
    fake.add_disk("sdc", "8:32", parts=[("sdc1", "8:33")])
    fake.mount("8:33", fake.node("sdc1"), "/boot/efi", "vfat")
    with pytest.raises(BeastError, match="/boot/efi"):
        dev.check_safe(dev.inspect_disk(fake.node("sdc")), allow_fixed=False)


def test_swap_refused(fake):
    fake.swap(fake.node("sdb1"))
    with pytest.raises(BeastError, match="swap"):
        dev.check_safe(dev.inspect_disk(fake.node("sdb")), allow_fixed=False)


def test_holders_refused(fake):
    fake.add_dm("dm-3", "253:3", ["sdb1"])  # e.g. an open LUKS container, not mounted
    with pytest.raises(BeastError, match="in use by dm-3"):
        dev.check_safe(dev.inspect_disk(fake.node("sdb")), allow_fixed=False)


def test_fixed_disk_needs_override(fake):
    fake.add_disk("sdd", "8:48", removable=False, model="USB HDD")
    d = dev.inspect_disk(fake.node("sdd"))
    with pytest.raises(BeastError, match="not a removable drive.*--allow-fixed-disk"):
        dev.check_safe(d, allow_fixed=False)
    assert fake.probed == []
    dev.check_safe(d, allow_fixed=True)
    assert fake.probed == [fake.node("sdd")]


def test_readonly_and_4k_refused(fake):
    fake.add_disk("sde", "8:64", ro=True)
    fake.add_disk("sdf", "8:80", lbs=4096)
    with pytest.raises(BeastError, match="read-only"):
        dev.check_safe(dev.inspect_disk(fake.node("sde")), allow_fixed=False)
    with pytest.raises(BeastError, match="4096-byte sectors"):
        dev.check_safe(dev.inspect_disk(fake.node("sdf")), allow_fixed=False)


def test_exclusive_probe_busy_and_permission(monkeypatch):
    def busy(*a, **k):
        raise OSError(errno.EBUSY, "busy")

    monkeypatch.setattr(dev.os, "open", busy)
    with pytest.raises(BeastError, match="in use by the system"):
        dev._exclusive_probe("/nonexistent/sdx")

    def denied(*a, **k):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(dev.os, "open", denied)
    with pytest.raises(BeastError, match="run as root"):
        dev._exclusive_probe("/nonexistent/sdx")


def test_partition_node_naming(fake):
    fake.add_disk("mmcblk0", "179:0", parts=[("mmcblk0p1", "179:1")])
    assert dev.partition_node(dev.inspect_disk(fake.node("sdb")), 1) == fake.node("sdb1")
    assert dev.partition_node(dev.inspect_disk(fake.node("nvme0n1")), 2) == fake.node("nvme0n1p2")
    assert dev.partition_node(dev.inspect_disk(fake.node("mmcblk0")), 1) == fake.node("mmcblk0p1")
    # Not yet in sysfs (right after partitioning): naming rule.
    assert dev.partition_node(dev.inspect_disk(fake.node("sdb")), 2) == fake.node("sdb2")
    assert dev.partition_node(dev.inspect_disk(fake.node("nvme0n1")), 3) == fake.node("nvme0n1p3")
    assert dev.partition_node(dev.inspect_disk(fake.node("mmcblk0")), 2) == fake.node("mmcblk0p2")


# --------------------------------------------------------------------------- install --device (Linux backend)
#
# The CLI goes through platforms.get_backend(): on Linux that is LinuxBackend,
# which builds on device.py, so the fake sysfs tree above drives it. These
# tests stop before anything is written; NoWriteBackend makes sure of it.


class NoWriteBackend:
    """The real (Linux) backend, except that preparing or opening for writing fails the test."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def prepare(self, disk):
        raise AssertionError("must not unmount/prepare the target")

    def open_raw(self, disk, *, writable):
        if writable:
            raise AssertionError("must not open the target for writing")
        return self._inner.open_raw(disk, writable=writable)

    def format_ntfs(self, disk, index, label):
        raise AssertionError("must not format")


@pytest.fixture
def no_writes(monkeypatch):
    from beastbooter.platforms import get_backend

    monkeypatch.setattr(commands, "get_backend", lambda: NoWriteBackend(get_backend("linux")))

    def no_tools(cmd, **kw):
        raise AssertionError(f"must not run {cmd}")

    monkeypatch.setattr(fsmod, "run", no_tools)


@pytest.mark.parametrize("setup,match", [
    # mounted alone is no refusal (prepare() unmounts it), but swap and device-mapper are
    (lambda f: (f.mount("8:17", f.node("sdb1"), "/mnt/x"), f.swap(f.node("sdb1"))), "in use as swap"),
    (lambda f: (f.mount("8:17", f.node("sdb1"), "/mnt/x"), f.add_dm("dm-7", "253:7", ["sdb1"])), "in use by dm-7"),
    (lambda f: None, "holds the system"),
])
def test_cli_device_refusals_write_nothing(fake, fake_dist, no_writes, capsys, setup, match):
    setup(fake)
    target = "nvme0n1" if match == "holds the system" else "sdb"
    extra = ["--allow-fixed-disk"] if target == "nvme0n1" else []
    assert run_cli("install", "--device", fake.node(target), "--yes", "--dist", fake_dist, *extra) == 1
    err = capsys.readouterr().err
    assert match in err and "Traceback" not in err


def test_cli_fixed_disk_refused(fake, fake_dist, no_writes, capsys):
    fake.add_disk("sdd", "8:48", removable=False)
    assert run_cli("install", "--device", fake.node("sdd"), "--yes", "--dist", fake_dist) == 1
    assert "--allow-fixed-disk" in capsys.readouterr().err


def test_cli_partition_refused(fake, fake_dist, no_writes, capsys):
    assert run_cli("install", "--device", fake.node("sdb1"), "--yes", "--dist", fake_dist) == 1
    assert "is a partition" in capsys.readouterr().err


def test_device_confirmation_must_match(fake, fake_dist, no_writes, monkeypatch, capsys):
    monkeypatch.setattr(commands, "confirm", lambda prompt: "sdc")
    assert run_cli("install", "--device", fake.node("sdb"), "--dist", fake_dist) == 1
    assert "not confirmed" in capsys.readouterr().err


def test_device_bad_dist_writes_nothing(fake, dist_copy, no_writes, capsys):
    (dist_copy / "esp/grub/grub.cfg").write_text("x")
    assert run_cli("install", "--device", fake.node("sdb"), "--yes", "--dist", dist_copy) == 1
    assert "sha256 mismatch" in capsys.readouterr().err


def test_device_info_and_update_refusals(fake, fake_dist, no_writes, capsys):
    assert run_cli("update", "--device", fake.node("nvme0n1"), "--yes", "--allow-fixed-disk",
                   "--dist", fake_dist) == 1
    assert "holds the system" in capsys.readouterr().err
    assert run_cli("info", "--device", fake.node("sdb1")) == 1
    assert "is a partition" in capsys.readouterr().err
