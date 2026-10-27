"""Linux backend against a fake sysfs / procfs / dev tree.

device.SYS, DEV, PROC_MOUNTINFO and PROC_SWAPS point into tmp_path,
device._stat_block is a dict lookup, device._exclusive_probe and settle are
recorded, and commands (umount, udisksctl, partx, mkfs.ntfs) are faked; linux.PROC
is a fake /proc (no processes unless a test adds them) and the busy retries do
not sleep. Nothing opens a real block device; raw I/O is tested on a regular file.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from beastbooter import device as devmod
from beastbooter import fs as fsmod
from beastbooter.errors import BeastError
from beastbooter.interfaces import DiskInfo
from beastbooter.platforms import common, linux
from beastbooter.platforms.linux import LinuxBackend, elevation_command

# The backend modules import on Windows (test_x_platforms_common); these tests need a POSIX host.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake sysfs tree, flock and euid: POSIX only")

FIXTURES = Path(__file__).parent / "fixtures" / "platforms" / "linux"
GIB = 1 << 30


class FakeLinux:
    def __init__(self, tmp_path, monkeypatch):
        root = tmp_path / "fake"
        self.sys = root / "sys"
        self.dev = root / "dev"
        self.dev.mkdir(parents=True)
        (self.sys / "dev" / "block").mkdir(parents=True)
        (self.sys / "block").mkdir(parents=True)
        self.mountinfo = root / "mountinfo"
        self.swaps = root / "swaps"
        shutil.copy(FIXTURES / "mountinfo", self.mountinfo)
        shutil.copy(FIXTURES / "swaps", self.swaps)
        self.blockmap: dict[str, str] = {}
        self.sysdirs: dict[str, Path] = {}
        self.probed: list[str] = []
        self.settled = 0
        self.commands: list[list[str]] = []
        monkeypatch.setattr(devmod, "SYS", str(self.sys))
        monkeypatch.setattr(devmod, "DEV", str(self.dev))
        monkeypatch.setattr(devmod, "PROC_MOUNTINFO", str(self.mountinfo))
        monkeypatch.setattr(devmod, "PROC_SWAPS", str(self.swaps))
        monkeypatch.setattr(devmod, "_stat_block", lambda p: self.blockmap.get(os.path.realpath(p)))
        monkeypatch.setattr(devmod, "_exclusive_probe", self.probed.append)
        monkeypatch.setattr(devmod, "_exclusive_open", self._exclusive_open)
        monkeypatch.setattr(devmod, "settle", self._settle)
        monkeypatch.setattr(common, "program_paths", lambda: ["/opt/beast-boot/app"])
        self.files: dict[str, str] = {}  # path -> st_dev "major:minor" (others: found by mount prefix)
        monkeypatch.setattr(linux, "_file_devnum", self.files.get)
        self.proc = root / "proc"
        (self.proc / "self" / "ns").mkdir(parents=True)
        (self.proc / "self" / "ns" / "mnt").symlink_to("mnt:[4026531841]")
        monkeypatch.setattr(linux, "PROC", str(self.proc))
        monkeypatch.setattr(linux, "BUSY_RETRY_DELAYS", (0, 0))
        monkeypatch.setattr(linux, "_which", lambda tool: None)  # no udisksctl unless a test says so

    def _settle(self):
        self.settled += 1

    def _exclusive_open(self, node):
        self.probed.append(node)
        return os.open(os.devnull, os.O_RDONLY)

    def add_process(self, pid, comm, *, cwd="/home/user", fds=(), ns="mnt:[4026531841]", mountinfo=""):
        """A fake /proc/<pid>: comm, cwd, fd/N links, its mount namespace and mountinfo."""
        d = self.proc / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "ns").mkdir()
        (d / "comm").write_text(comm + "\n")
        (d / "cwd").symlink_to(cwd)
        (d / "ns" / "mnt").symlink_to(ns)
        (d / "mountinfo").write_text(mountinfo)
        for i, target in enumerate(fds, 3):
            (d / "fd" / str(i)).symlink_to(target)

    def set_size(self, name, size_bytes):
        (self.sysdirs[name] / "size").write_text(f"{size_bytes // 512}\n")

    def node(self, name):
        return str(self.dev / name)

    def add_disk(self, name, devnum, devpath, *, size=16 * GIB, removable=False, parts=(), vendor="",
                 model="", ro=False, lbs=512, mmc_type=None):
        sysdir = self.sys / "devices" / devpath
        (sysdir / "queue").mkdir(parents=True)
        (sysdir / "device").mkdir()
        (sysdir / "holders").mkdir()
        (sysdir / "size").write_text(f"{size // 512}\n")
        (sysdir / "removable").write_text("1\n" if removable else "0\n")
        (sysdir / "ro").write_text("1\n" if ro else "0\n")
        (sysdir / "dev").write_text(devnum + "\n")
        (sysdir / "queue" / "logical_block_size").write_text(f"{lbs}\n")
        if vendor:
            (sysdir / "device" / "vendor").write_text(vendor.ljust(8) + "\n")
        if model:
            (sysdir / "device" / "model").write_text(model.ljust(16) + "\n")
        if mmc_type:
            (sysdir / "device" / "type").write_text(mmc_type + "\n")
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

    def add_dm(self, name, devnum, slaves):
        sysdir = self.sys / "devices" / "virtual" / "block" / name
        (sysdir / "slaves").mkdir(parents=True)
        (sysdir / "dev").write_text(devnum + "\n")
        (sysdir / "size").write_text("1000\n")
        for s in slaves:
            (sysdir / "slaves" / s).symlink_to(self.sysdirs[s])
            (self.sysdirs[s] / "holders" / name).mkdir()
        (self.sys / "dev" / "block" / devnum).symlink_to(sysdir)
        (self.sys / "block" / name).symlink_to(sysdir)
        self._node(name, devnum)
        self.sysdirs[name] = sysdir

    def attach_loop(self, name, backing_file):
        """Attach an existing fake loop device to a file (/sys/block/loopN/loop/backing_file)."""
        (self.sysdirs[name] / "loop").mkdir()
        (self.sysdirs[name] / "loop" / "backing_file").write_text(backing_file + "\n")

    def add_swap_file(self, path):
        escaped = path.replace(" ", "\\040")  # /proc/swaps escapes like mountinfo
        with open(self.swaps, "a") as f:
            f.write(f"{escaped}\tfile\t\t1048572\t\t0\t\t-3\n")

    def _node(self, name, devnum):
        (self.dev / name).write_text("")
        self.blockmap[str(self.dev / name)] = devnum

    def mount(self, devnum, source, mountpoint, fstype="ext4"):
        with open(self.mountinfo, "a") as f:
            mp = mountpoint.replace(" ", "\\040")
            f.write(f"900 30 {devnum} / {mp} rw,relatime shared:900 - {fstype} {source} rw\n")

    def unmount(self, mountpoint):
        mp = mountpoint.replace(" ", "\\040")
        lines = self.mountinfo.read_text().splitlines(keepends=True)
        self.mountinfo.write_text("".join(line for line in lines if line.split()[4] != mp))


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = FakeLinux(tmp_path, monkeypatch)
    # The machine described by fixtures/platforms/linux/mountinfo.
    f.add_disk("nvme0n1", "259:0", "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1", size=512 * GIB,
               model="Samsung SSD 980 PRO 1TB", parts=[("nvme0n1p1", "259:1"), ("nvme0n1p2", "259:2")])
    f.add_disk("sda", "8:0", "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0/block/sda",
               size=2000 * GIB, vendor="ATA", model="ST2000DM008-2FR1", parts=[("sda1", "8:1")])
    f.add_disk("sdb", "8:16", "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb",
               removable=True, vendor="SanDisk", model="Cruzer Blade", parts=[("sdb1", "8:17")])
    f.add_disk("sdc", "8:32", "pci0000:00/0000:00:14.0/usb4/4-2/4-2:1.0/host7/target7:0:0/7:0:0:0/block/sdc",
               size=1000 * GIB, vendor="Samsung", model="PSSD T7")
    f.add_disk("mmcblk0", "179:0", "pci0000:00/0000:00:14.5/mmc_host/mmc0/mmc0:aaaa/block/mmcblk0",
               size=32 * GIB, mmc_type="SD", parts=[("mmcblk0p1", "179:1")])
    f.add_disk("mmcblk1", "179:8", "platform/fe330000.mmc/mmc_host/mmc1/mmc1:0001/block/mmcblk1",
               size=64 * GIB, mmc_type="MMC")
    f.add_disk("loop0", "7:0", "virtual/block/loop0", size=0)
    f.add_disk("loop1", "7:1", "virtual/block/loop1", size=77 << 20, ro=True)
    f.add_disk("sr0", "11:0", "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sr0", size=0)
    return f


@pytest.fixture
def backend():
    return LinuxBackend()


def ids(disks):
    return [os.path.basename(d.id) for d in disks]


# --------------------------------------------------------------------------- listing


def test_list_default_shows_removable_and_external(fake, backend):
    assert ids(backend.list_disks()) == ["mmcblk0", "sdb", "sdc"]


def test_list_all(fake, backend):
    assert ids(backend.list_disks(include_fixed=True)) == ["loop1", "mmcblk0", "mmcblk1", "nvme0n1", "sda", "sdb", "sdc"]


def test_disk_fields(fake, backend):
    disks = {os.path.basename(d.id): d for d in backend.list_disks(include_fixed=True)}
    sdb = disks["sdb"]
    assert sdb == DiskInfo(
        id=fake.node("sdb"), path=fake.node("sdb"), model="SanDisk Cruzer Blade", size=16 * GIB, sector_size=512,
        bus="usb", removable=True, system=False, read_only=False, mountpoints=("/media/user/MY STICK",),
        partitions=(fake.node("sdb1"),),
        extra={"name": "sdb", "devnum": "8:16", "removable_media": True, "system_reason": None},
    )
    assert (disks["sdc"].bus, disks["sdc"].removable, disks["sdc"].extra["removable_media"]) == ("usb", True, False)
    assert (disks["mmcblk0"].bus, disks["mmcblk0"].removable) == ("sd", True)
    assert (disks["mmcblk1"].bus, disks["mmcblk1"].removable) == ("unknown", False)  # soldered eMMC
    assert (disks["nvme0n1"].bus, disks["nvme0n1"].system) == ("nvme", True)
    assert "holds the system's / filesystem" in disks["nvme0n1"].extra["system_reason"]
    assert set(disks["nvme0n1"].mountpoints) == {"/", "/boot/efi"}
    assert disks["nvme0n1"].partitions == (fake.node("nvme0n1p1"), fake.node("nvme0n1p2"))
    assert (disks["sda"].bus, disks["sda"].model, disks["sda"].system) == ("sata", "ATA ST2000DM008-2FR1", False)
    assert (disks["loop1"].bus, disks["loop1"].read_only, disks["loop1"].mountpoints) == \
        ("virtual", True, ("/snap/core22/1380",))


def test_swap_partition_makes_system(fake, backend):
    with open(fake.swaps, "a") as f:
        f.write(f"{fake.node('sda1')}                               partition\t8388604\t0\t-3\n")
    sda = backend.get_disk("sda")
    assert sda.system and "swap" in sda.extra["system_reason"]


def test_boot_on_lvm_makes_system(fake, backend):
    fake.add_dm("dm-0", "253:0", ["sda1"])
    fake.mount("253:0", "/dev/mapper/vg-boot", "/boot")
    sda = backend.get_disk("sda")
    assert sda.system and "/boot" in sda.extra["system_reason"]
    assert "dm-0" not in ids(backend.list_disks(include_fixed=True))


def test_get_disk_forms_and_errors(fake, backend):
    assert backend.get_disk("sdb").id == fake.node("sdb")
    assert backend.get_disk(fake.node("sdb")).id == fake.node("sdb")
    with pytest.raises(BeastError, match="is a partition"):
        backend.get_disk("sdb1")
    with pytest.raises(BeastError, match="does not exist"):
        backend.get_disk("sdz")


# --------------------------------------------------------------------------- safety


def test_check_safe_mounted_stick_ok_unelevated(fake, backend, monkeypatch):
    monkeypatch.setattr(backend, "is_elevated", lambda: False)
    backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)  # prepare() will unmount it
    assert fake.probed == []  # O_EXCL needs root: skipped


def test_check_safe_probe_when_elevated(fake, backend, monkeypatch):
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)
    assert fake.probed == []  # mounted: the probe would only report EBUSY; prepare() probes later
    backend.check_safe(backend.get_disk("sdc"), allow_fixed=False)
    assert fake.probed == [fake.node("sdc")]


def test_check_safe_refusals(fake, backend):
    with pytest.raises(BeastError, match=r"nvme0n1 holds the system's / filesystem \(.*nvme0n1p2\)"):
        backend.check_safe(backend.get_disk("nvme0n1"), allow_fixed=True)
    with pytest.raises(BeastError, match="not a removable or external drive.*--allow-fixed-disk"):
        backend.check_safe(backend.get_disk("sda"), allow_fixed=False)
    backend.check_safe(backend.get_disk("sda"), allow_fixed=True)
    with pytest.raises(BeastError, match="loop1 is read-only"):  # a snap's squashfs: mounted, and read-only
        backend.check_safe(backend.get_disk("loop1"), allow_fixed=True)
    fake.add_disk("mmcblk2", "179:16", "pci0000:00/0000:00:14.5/mmc_host/mmc2/mmc2:bbbb/block/mmcblk2",
                  mmc_type="SD", ro=True)  # write-protect switch on
    with pytest.raises(BeastError, match="read-only"):
        backend.check_safe(backend.get_disk("mmcblk2"), allow_fixed=False)


def test_check_safe_swap_holders_sector_size(fake, backend):
    fake.add_disk("sdd", "8:48", "pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host8/target8:0:0/8:0:0:0/block/sdd",
                  removable=True, parts=[("sdd1", "8:49"), ("sdd2", "8:50")])
    fake.add_disk("sde", "8:64", "pci0000:00/0000:00:14.0/usb2/2-3/2-3:1.0/host9/target9:0:0/9:0:0:0/block/sde",
                  removable=True, lbs=4096)
    fake.add_dm("dm-3", "253:3", ["sdd2"])  # an unlocked LUKS container, not mounted
    with pytest.raises(BeastError, match=r"sdd2 is in use by dm-3 \(device-mapper"):
        backend.check_safe(backend.get_disk("sdd"), allow_fixed=False)
    with pytest.raises(BeastError, match="4096-byte sectors"):
        backend.check_safe(backend.get_disk("sde"), allow_fixed=False)
    with open(fake.swaps, "a") as f:
        f.write(f"{fake.node('sdb1')}\tpartition\t1048572\t0\t-2\n")
    with pytest.raises(BeastError, match="swap"):
        backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)


def test_check_safe_refuses_disk_we_run_from(fake, backend, monkeypatch):
    monkeypatch.setattr(common, "program_paths", lambda: ["/media/user/MY STICK/beast-boot/python/bin/python3"])
    with pytest.raises(BeastError, match="beast-boot itself is running from"):
        backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)


# --------------------------------------------------------------------------- in use: mounts, swap files, live media


@pytest.mark.parametrize("mnt", ["/home", "/var", "/usr", "/srv", "/opt", "/efi", "/boot/firmware"])
def test_system_filesystem_on_usb_ssd_is_system(fake, backend, fake_run, mnt):
    """A USB SSD (removable=0, counts as external) holding /home etc. is the running system."""
    fake.mount("8:32", fake.node("sdc"), mnt)
    sdc = backend.get_disk("sdc")
    assert sdc.system and sdc.removable and f"holds the system's {mnt} filesystem" in sdc.extra["system_reason"]
    assert "sdc" not in ids(backend.list_disks())
    with pytest.raises(BeastError, match=f"refusing: .*sdc holds the system's {mnt} filesystem"):
        backend.check_safe(sdc, allow_fixed=True)
    with pytest.raises(BeastError, match="holds the system's"):
        backend.prepare(sdc)
    assert fake.commands == []  # nothing was unmounted


@pytest.mark.parametrize("mnt", ["/mnt/data", "/srv/backup", "/home/user/usb", "/media"])
def test_manual_mount_is_unmounted_too(fake, backend, fake_run, mnt):
    """Every mount of the selected drive comes off, not only the desktop's auto-mounts."""
    fake.mount("8:32", fake.node("sdc"), mnt)
    sdc = backend.get_disk("sdc")
    assert not sdc.system and sdc.mountpoints == (mnt,)
    backend.check_safe(sdc, allow_fixed=True)
    assert backend.prepare(sdc) == [mnt]
    assert fake.commands == [["umount", mnt]]
    assert fake.probed == [fake.node("sdc")] and backend.get_disk("sdc").mountpoints == ()


def test_mixed_auto_and_manual_mounts(fake, backend, fake_run):
    fake.mount("8:17", fake.node("sdb1"), "/mnt/stick")  # sdb1 also mounted by hand
    fake.mount("8:17", fake.node("sdb1"), "/mnt/stick/bind")  # and a nested bind mount of it
    backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK", "/mnt/stick", "/mnt/stick/bind"]
    assert fake.commands == [["umount", "/mnt/stick/bind"], ["umount", "/media/user/MY STICK"],
                             ["umount", "/mnt/stick"]]  # deepest first


def test_run_media_is_an_automount(fake, backend, fake_run):
    fake.mount("8:32", fake.node("sdc"), "/run/media/user/T7 Shield", fstype="exfat")  # Fedora's udisks2
    backend.check_safe(backend.get_disk("sdc"), allow_fixed=False)
    assert backend.prepare(backend.get_disk("sdc")) == ["/run/media/user/T7 Shield"]
    assert fake.commands == [["umount", "/run/media/user/T7 Shield"]]


def test_mounted_but_in_use_is_still_refused(fake, backend, fake_run):
    """Unmounting automatically never extends to swap, device-mapper/RAID holders or
    live-boot media: those stay refusals, and nothing is unmounted."""
    fake.mount("8:16", fake.node("sdb"), "/mnt/stick")
    with open(fake.swaps, "a") as f:
        f.write(f"{fake.node('sdb1')}\tpartition\t1048572\t0\t-2\n")
    with pytest.raises(BeastError, match="in use as swap"):
        backend.prepare(backend.get_disk("sdb"))
    fake.swaps.write_text(fake.swaps.read_text().splitlines(keepends=True)[0])
    fake.add_dm("dm-4", "253:4", ["sdb1"])  # LVM / LUKS on the stick
    with pytest.raises(BeastError, match=r"sdb1 is in use by dm-4 \(device-mapper"):
        backend.prepare(backend.get_disk("sdb"))
    fake.mount("8:32", fake.node("sdc"), "/media/user/T7")
    fake.mount("8:32", fake.node("sdc"), "/run/live/medium", fstype="iso9660")  # booted from it
    with pytest.raises(BeastError, match="holds the system's /run/live/medium"):
        backend.check_safe(backend.get_disk("sdc"), allow_fixed=True)
    with pytest.raises(BeastError, match="holds the system's /run/live/medium"):
        backend.prepare(backend.get_disk("sdc"))
    assert fake.commands == []


def test_swap_file_on_stick_is_system(fake, backend):
    fake.add_swap_file("/media/user/MY STICK/swapfile")  # found through the mount it lives under
    sdb = backend.get_disk("sdb")
    assert sdb.system and sdb.extra["system_reason"] == "holds an active swap file (/media/user/MY STICK/swapfile)"
    with pytest.raises(BeastError, match="holds an active swap file"):
        backend.check_safe(sdb, allow_fixed=False)
    assert "sdb" not in ids(backend.list_disks())


def test_swap_file_found_by_st_dev_even_on_btrfs(fake, backend):
    """stat() gives the filesystem's device; btrfs reports an anonymous 0:N device,
    which mountinfo maps back to the partition."""
    fake.add_swap_file("/data/swap/swapfile")
    fake.files["/data/swap/swapfile"] = "0:57"
    fake.mount("0:57", fake.node("sdb1"), "/data", fstype="btrfs")
    assert "swap file (/data/swap/swapfile)" in backend.get_disk("sdb").extra["system_reason"]
    assert not backend.get_disk("sda").system
    fake.files["/data/swap/swapfile"] = "8:1"  # ext4 on sda1: st_dev is the partition itself
    assert backend.get_disk("sda").system and not backend.get_disk("sdb").system


def test_existing_swap_file_on_root_does_not_flag_others(fake, backend):
    # fixtures/platforms/linux/swaps has /swap.img (on "/"), so only the NVMe disk is affected.
    assert [os.path.basename(d.id) for d in backend.list_disks(include_fixed=True) if d.system] == ["nvme0n1"]


@pytest.mark.parametrize("mnt", ["/cdrom", "/isodevice", "/run/live/medium", "/run/initramfs/live",
                                 "/run/archiso/bootmnt"])
def test_live_medium_is_system(fake, backend, mnt):
    """Booted a live system from the stick: its medium stays mounted there."""
    fake.mount("8:17", fake.node("sdb1"), mnt, fstype="iso9660")
    sdb = backend.get_disk("sdb")
    assert sdb.system and f"holds the system's {mnt} filesystem" in sdb.extra["system_reason"]
    with pytest.raises(BeastError, match="refusing: .*sdb holds the system's"):
        backend.check_safe(sdb, allow_fixed=False)


def test_live_iso_booted_from_a_file_on_the_stick(fake, backend):
    """Ventoy-style boot: the ISO is a file on the stick, loop-mounted at /cdrom; the
    squashfs inside it is another loop device. Both chains lead back to the stick."""
    fake.add_disk("loop2", "7:2", "virtual/block/loop2", size=5 << 30, ro=True)
    fake.add_disk("loop3", "7:3", "virtual/block/loop3", size=2 << 30, ro=True)
    fake.attach_loop("loop2", "/media/user/MY STICK/iso/ubuntu-24.04-desktop-amd64.iso")
    fake.attach_loop("loop3", "/cdrom/casper/minimal.squashfs")
    fake.mount("7:2", "/dev/loop2", "/cdrom", fstype="iso9660")
    fake.mount("7:3", "/dev/loop3", "/rofs", fstype="squashfs")
    sdb = backend.get_disk("sdb")
    assert sdb.system and "/cdrom" in sdb.extra["system_reason"]
    assert set(sdb.mountpoints) == {"/media/user/MY STICK", "/cdrom", "/rofs"}
    assert not backend.get_disk("sdc").system


def test_loop_device_using_a_file_on_the_stick(fake, backend, fake_run):
    """An ISO opened from the stick in the file manager (udisks loop device)."""
    fake.add_disk("loop5", "7:5", "virtual/block/loop5", size=6 << 30, ro=True)
    fake.attach_loop("loop5", "/media/user/MY STICK/debian-12.iso")
    sdb = backend.get_disk("sdb")
    assert not sdb.system  # not the running system, but in use:
    with pytest.raises(BeastError, match=r"loop5 uses /media/user/MY STICK/debian-12.iso, a file on .*sdb.*"
                                         r"detach .*loop5 first"):
        backend.check_safe(sdb, allow_fixed=False)
    with pytest.raises(BeastError, match="loop5 uses"):
        backend.prepare(sdb)
    assert fake.commands == []
    fake.mount("7:5", "/dev/loop5", "/media/user/Debian 12", fstype="iso9660")
    assert set(backend.get_disk("sdb").mountpoints) == {"/media/user/MY STICK", "/media/user/Debian 12"}


def test_deleted_loop_backing_file(fake, backend):
    fake.add_disk("loop6", "7:6", "virtual/block/loop6", size=1 << 20)
    fake.attach_loop("loop6", "/media/user/MY STICK/old.img (deleted)")
    with pytest.raises(BeastError, match="loop6 uses /media/user/MY STICK/old.img,"):
        backend.check_safe(backend.get_disk("sdb"), allow_fixed=False)


def test_snap_loops_are_attributed_to_the_root_disk(fake, backend):
    fake.attach_loop("loop1", "/var/lib/snapd/snaps/core22_1380.snap")
    nvme = backend.get_disk("nvme0n1")
    assert "/snap/core22/1380" in nvme.mountpoints and nvme.system


# --------------------------------------------------------------------------- prepare


@pytest.fixture
def fake_run(fake, monkeypatch):
    results: dict[str, subprocess.CompletedProcess] = {}

    def run(cmd, **kw):
        fake.commands.append(list(cmd))
        if cmd[0] in results:
            return results[cmd[0]]
        if cmd[0] == "umount":
            fake.unmount(cmd[1])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(linux, "run", run)
    monkeypatch.setattr(linux, "_run_quiet", lambda cmd, timeout: run(cmd))
    return results


def test_prepare_unmounts_then_probes(fake, backend, fake_run):
    fake.mount("8:16", fake.node("sdb"), "/media/user/MY STICK/nested")  # nested mount comes off first
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK", "/media/user/MY STICK/nested"]
    assert fake.commands == [["umount", "/media/user/MY STICK/nested"], ["umount", "/media/user/MY STICK"]]
    assert fake.probed == [fake.node("sdb")]
    assert backend.get_disk("sdb").mountpoints == ()


def test_prepare_busy_mount(fake, backend, fake_run):
    fake.unmount("/media/user/MY STICK")
    fake.mount("8:17", fake.node("sdb1"), "/mnt/stick")  # a manual mount, busy: a shell sits in it
    fake_run["umount"] = subprocess.CompletedProcess([], 32, "", "umount: /mnt/stick: target is busy.\n")
    with pytest.raises(BeastError, match="cannot unmount /mnt/stick: it is busy.*close the programs") as e:
        backend.prepare(backend.get_disk("sdb"))
    assert e.value.code == "busy" and fake.probed == []


def test_prepare_other_unmount_failure(fake, backend, fake_run):
    fake_run["umount"] = subprocess.CompletedProcess([], 32, "", "umount: /media/user/MY STICK: must be superuser "
                                                                 "to unmount.\n")
    with pytest.raises(BeastError, match="cannot unmount /media/user/MY STICK.*must be superuser") as e:
        backend.prepare(backend.get_disk("sdb"))
    assert e.value.code is None  # the CLI reports the step's code (prepare-failed)


def test_prepare_still_mounted(fake, backend, fake_run):
    fake_run["umount"] = subprocess.CompletedProcess([], 0, "", "")  # "succeeds" but nothing changes
    with pytest.raises(BeastError, match="still mounted at /media/user/MY STICK") as e:
        backend.prepare(backend.get_disk("sdb"))
    assert e.value.code == "busy"


def test_prepare_refuses_system_disk(fake, backend, fake_run):
    with pytest.raises(BeastError, match="holds the system"):
        backend.prepare(backend.get_disk("nvme0n1"))
    assert fake.commands == []


# --------------------------------------------------------------------------- raw I/O


def file_disk(tmp_path, size=8 << 20) -> DiskInfo:
    p = tmp_path / "disk.bin"
    with open(p, "wb") as f:
        f.truncate(size)
    return DiskInfo(id=str(p), path=str(p), model="file", size=size, sector_size=512, bus="usb",
                    removable=True, system=False, read_only=False)


def test_open_raw_roundtrip_and_lock(tmp_path, backend, monkeypatch):
    d = file_disk(tmp_path)
    monkeypatch.setattr(linux, "LOCK_TIMEOUT", 0.2)
    with backend.open_raw(d, writable=True) as t:
        t.write(511, b"hello")
        t.flush()
        assert t.read(510, 7) == b"\0hello\0"
        with pytest.raises(BeastError, match="locked by another program"):
            backend.open_raw(d, writable=True)  # flock(LOCK_EX) held by the first one
        with backend.open_raw(d, writable=False) as r:  # readers do not lock
            assert r.read(511, 5) == b"hello"
    with backend.open_raw(d, writable=True) as t:  # lock released on close
        assert t.read(511, 5) == b"hello"


def test_open_raw_size_mismatch(tmp_path, backend):
    d = file_disk(tmp_path)
    bigger = DiskInfo(**{**d.__dict__, "size": d.size + 512})
    with pytest.raises(BeastError, match="size changed"):
        backend.open_raw(bigger, writable=False)


def test_open_raw_permission_hint(tmp_path, backend):
    d = file_disk(tmp_path)
    os.chmod(d.path, 0o400)
    if os.geteuid() != 0:
        with pytest.raises(BeastError, match="permission denied.*run as root"):
            backend.open_raw(d, writable=True)


# --------------------------------------------------------------------------- rescan


def test_rescan_blkrrpart(fake, backend, fake_run, monkeypatch):
    calls = []
    monkeypatch.setattr(linux, "_blkrrpart", calls.append)
    backend.rescan(backend.get_disk("sdb"))
    assert calls == [fake.node("sdb")] and fake.commands == [] and fake.settled == 2


def test_rescan_busy_then_ok(fake, backend, fake_run, monkeypatch):
    attempts = []

    def busy_twice(path):
        attempts.append(path)
        if len(attempts) < 3:
            raise OSError(errno.EBUSY, "Device or resource busy")

    monkeypatch.setattr(linux, "_blkrrpart", busy_twice)
    monkeypatch.setattr(linux.time, "sleep", lambda s: None)
    backend.rescan(backend.get_disk("sdb"))
    assert len(attempts) == 3 and fake.commands == []


def test_rescan_falls_back_to_partx(fake, backend, fake_run, monkeypatch):
    def fail(path):
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(linux, "_blkrrpart", fail)
    backend.rescan(backend.get_disk("sdb"))
    assert fake.commands == [["partx", "-u", fake.node("sdb")]]
    fake_run["partx"] = subprocess.CompletedProcess([], 1, "", "partx: /dev/sdb: failed to read partition table\n")
    with pytest.raises(BeastError, match="did not accept the new partition table.*BLKRRPART: Invalid argument"
                                         ".*partx: partx: /dev/sdb: failed.*unplug and reconnect"):
        backend.rescan(backend.get_disk("sdb"))


def test_blkrrpart_ioctl_number():
    assert linux.BLKRRPART == (0x12 << 8) | 95  # _IO(0x12, 95) from <linux/fs.h>


# --------------------------------------------------------------------------- partitions / NTFS


def test_partition_paths(fake, backend):
    assert backend.partition_path(backend.get_disk("sdb"), 1) == fake.node("sdb1")
    assert backend.partition_path(backend.get_disk("sdb"), 2) == fake.node("sdb2")  # not in sysfs yet
    assert backend.partition_path(backend.get_disk("nvme0n1"), 3) == fake.node("nvme0n1p3")
    assert backend.partition_path(backend.get_disk("mmcblk0"), 1) == fake.node("mmcblk0p1")
    assert backend.partition_path(backend.get_disk("mmcblk0"), 2) == fake.node("mmcblk0p2")


def test_format_ntfs_runs_mkfs_ntfs_on_partition_node(fake, backend, monkeypatch):
    cmds = []
    monkeypatch.setattr(fsmod, "run", lambda cmd, **kw: cmds.append(cmd))
    backend.format_ntfs(backend.get_disk("sdb"), 1, "BEASTBOOTER")
    assert cmds == [["mkfs.ntfs", "-q", "-Q", "-L", "BEASTBOOTER", fake.node("sdb1")]]


def test_format_ntfs_waits_for_node(fake, backend, monkeypatch):
    monkeypatch.setattr(devmod.time, "sleep", lambda s: None)
    with pytest.raises(BeastError, match="partition device nodes did not appear.*sdc1"):
        backend.wait_partitions(backend.get_disk("sdc"), [1], timeout=0)


# --------------------------------------------------------------------------- elevation


def which_from(tools):
    return lambda name: tools.get(name)


def test_elevation_pkexec_in_graphical_session():
    w = which_from({"pkexec": "/usr/bin/pkexec", "sudo": "/usr/bin/sudo", "python3": "/usr/bin/python3"})
    argv = ["python3", "/opt/bb/app/beast_booter_launch.py", "install", "--device", "/dev/sdb",
            "--progress-file", "/tmp/p file.jsonl"]
    assert elevation_command(argv, env={"WAYLAND_DISPLAY": "wayland-0"}, which=w) == \
        ["/usr/bin/pkexec", "/usr/bin/python3", *argv[1:]]
    assert elevation_command(argv, env={"DISPLAY": ":0"}, which=w)[0] == "/usr/bin/pkexec"


def test_elevation_sudo_without_display():
    w = which_from({"pkexec": "/usr/bin/pkexec", "sudo": "/usr/bin/sudo"})
    assert elevation_command(["/usr/bin/python3", "-V"], env={}, which=w) == ["/usr/bin/sudo", "--", "/usr/bin/python3", "-V"]
    assert elevation_command(["/usr/bin/python3", "-V"], env={"SUDO_ASKPASS": "/usr/bin/ssh-askpass"}, which=w) == \
        ["/usr/bin/sudo", "-A", "--", "/usr/bin/python3", "-V"]
    no_pkexec = which_from({"sudo": "/usr/bin/sudo"})
    assert elevation_command(["/x"], env={"DISPLAY": ":0"}, which=no_pkexec)[0] == "/usr/bin/sudo"
    with pytest.raises(BeastError, match="neither pkexec nor sudo"):
        elevation_command(["/x"], env={}, which=which_from({}))
    with pytest.raises(ValueError):
        elevation_command([], env={}, which=w)


def test_run_elevated_process(backend, monkeypatch):
    script = "import sys; sys.exit(int(sys.argv[1]))"
    monkeypatch.setattr(linux, "elevation_command", lambda argv: [sys.executable, "-c", script, *argv])
    p = backend.run_elevated(["5"])
    assert p.wait(10) == 5 and p.poll() == 5
    assert p.argv == [sys.executable, "-c", script, "5"]


def test_is_elevated(backend, monkeypatch):
    monkeypatch.setattr(linux.os, "geteuid", lambda: 0)
    assert backend.is_elevated()
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000)
    assert not backend.is_elevated()


def test_check_safe_refuses_swapped_drive(fake, backend):
    selected = backend.get_disk("sdb")
    (fake.sysdirs["sdb"] / "device" / "model").write_text("Other Stick\n")  # a different stick is now sdb
    with pytest.raises(BeastError, match="changed since it was selected.*select the drive again"):
        backend.check_safe(selected, allow_fixed=False)


def test_blkrrpart_on_a_non_disk_fails(tmp_path):
    f = tmp_path / "plain"
    f.write_bytes(b"\0" * 512)
    with pytest.raises(OSError) as e:
        linux._blkrrpart(str(f))
    assert e.value.errno == errno.ENOTTY


# --------------------------------------------------------------------------- busy drives: retries, holders


def test_prepare_busy_retries_then_names_the_holders(fake, backend, fake_run):
    fake.unmount("/media/user/MY STICK")
    fake.mount("8:17", fake.node("sdb1"), "/mnt/stick")
    fake.add_process(4321, "bash", cwd="/mnt/stick/photos")
    fake.add_process(999, "vlc", fds=["/dev/null", "/mnt/stick/movie.mkv"])
    fake.add_process(55, "sshd", fds=["/var/log/auth.log"])  # not ours
    fake_run["umount"] = subprocess.CompletedProcess([], 32, "", "umount: /mnt/stick: target is busy.\n")
    with pytest.raises(BeastError) as e:
        backend.prepare(backend.get_disk("sdb"))
    msg = str(e.value)
    assert e.value.code == "busy" and msg.startswith("cannot unmount /mnt/stick: it is busy")
    assert "process 999 (vlc) has /mnt/stick/movie.mkv open" in msg
    assert "process 4321 (bash) has its current folder in /mnt/stick/photos" in msg
    assert "sshd" not in msg and "close the programs" in msg
    assert fake.commands == [["umount", "/mnt/stick"]] * (len(linux.BUSY_RETRY_DELAYS) + 1)
    assert fake.probed == []


def test_prepare_busy_once_then_unmounted(fake, backend, fake_run, monkeypatch):
    attempts = []

    def run(cmd, **kw):
        fake.commands.append(list(cmd))
        attempts.append(cmd)
        if len(attempts) == 1:
            return subprocess.CompletedProcess(cmd, 32, "", "umount: target is busy.\n")
        fake.unmount(cmd[1])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(linux, "run", run)
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK"]
    assert len(attempts) == 2 and fake.probed == [fake.node("sdb")]


def test_exclusive_probe_retried_then_ok(fake, backend, fake_run, monkeypatch):
    tries = []

    def probe(node):
        tries.append(node)
        if len(tries) < 3:
            raise BeastError(f"{node} is in use", code="busy")
        return os.open(os.devnull, os.O_RDONLY)

    monkeypatch.setattr(devmod, "_exclusive_open", probe)
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK"]
    assert tries == [fake.node("sdb")] * 3


def busy_probe(node):
    raise BeastError(f"{node} is in use by the system or a program", code="busy")


def test_exclusive_probe_busy_names_loop_and_other_namespace(fake, backend, fake_run, monkeypatch):
    """Unmounted here, but a loop device still uses an ISO on it (it was lazily unmounted)
    and a snap's own mount namespace still has the stick mounted."""
    fake.add_disk("loop5", "7:5", "virtual/block/loop5", size=6 << 30, ro=True)
    real_run = linux.run

    def umount_and_attach(cmd, **kw):
        proc = real_run(cmd, **kw)
        fake.attach_loop("loop5", "/media/user/MY STICK/debian-12.iso")
        return proc

    monkeypatch.setattr(linux, "run", umount_and_attach)
    fake.add_process(777, "snap-app", ns="mnt:[4026532999]",
                     mountinfo="40 30 8:17 / /media/user/MY\\040STICK rw - vfat /dev/sdb1 rw\n")
    monkeypatch.setattr(devmod, "_exclusive_open", busy_probe)
    with pytest.raises(BeastError) as e:
        backend.prepare(backend.get_disk("sdb"))
    msg = str(e.value)
    assert e.value.code == "busy" and "is still in use after unmounting its volumes" in msg
    assert "loop5 uses /media/user/MY STICK/debian-12.iso" in msg and "udisksctl loop-delete -b" in msg
    assert "process 777 (snap-app) still has it mounted at /media/user/MY STICK in its own mount namespace" in msg


def test_exclusive_probe_busy_device_node_open(fake, backend, fake_run, monkeypatch):
    fake.add_process(3141, "gparted", fds=[fake.node("sdb")])
    monkeypatch.setattr(devmod, "_exclusive_open", busy_probe)
    with pytest.raises(BeastError, match=r"process 3141 \(gparted\) has .*/sdb open; close the programs"):
        backend.prepare(backend.get_disk("sdb"))


def test_exclusive_probe_busy_nobody_named(fake, backend, fake_run, monkeypatch):
    monkeypatch.setattr(devmod, "_exclusive_open", busy_probe)
    with pytest.raises(BeastError, match="no program could be named") as e:
        backend.prepare(backend.get_disk("sdb"))
    assert e.value.code == "busy"


def test_exclusive_probe_errors(monkeypatch):
    def fail(no):
        def open_(*a):
            raise OSError(no, os.strerror(no))
        return open_

    monkeypatch.setattr(os, "open", fail(errno.EBUSY))
    with pytest.raises(BeastError, match="in use by the system or a program") as e:
        devmod._exclusive_probe("/nonexistent/sdx")
    assert e.value.code == "busy"
    # ENOMEDIUM is Linux-only (these tests also run on macOS / Windows CI); ENXIO counts too
    monkeypatch.setattr(os, "open", fail(getattr(errno, "ENOMEDIUM", errno.ENXIO)))
    with pytest.raises(BeastError, match="stopped responding") as e:
        devmod._exclusive_probe("/nonexistent/sdx")
    assert e.value.code == "device-vanished"


def test_udisksctl_unmounts_automounts(fake, backend, fake_run, monkeypatch):
    monkeypatch.setattr(linux, "_which", lambda tool: "/usr/bin/" + tool)
    fake.mount("8:17", fake.node("sdb1"), "/mnt/stick")  # by hand: umount
    real_run = linux.run

    def run(cmd, **kw):
        if cmd[0].endswith("udisksctl"):
            fake.commands.append(list(cmd))
            fake.unmount("/media/user/MY STICK")
            return subprocess.CompletedProcess(cmd, 0, "Unmounted /dev/sdb1.\n", "")
        return real_run(cmd, **kw)

    monkeypatch.setattr(linux, "_run_quiet", lambda cmd, timeout: run(cmd))
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK", "/mnt/stick"]
    assert fake.commands == [["/usr/bin/udisksctl", "unmount", "-b", fake.node("sdb1"), "--no-user-interaction"],
                             ["umount", "/mnt/stick"]]


def test_udisksctl_refusal_falls_back_to_umount(fake, backend, fake_run, monkeypatch):
    monkeypatch.setattr(linux, "_which", lambda tool: "/usr/bin/" + tool)
    fake_run["/usr/bin/udisksctl"] = subprocess.CompletedProcess([], 1, "", "Error connecting to the udisks daemon")
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK"]
    assert [c[0] for c in fake.commands] == ["/usr/bin/udisksctl", "umount"]


# --------------------------------------------------------------------------- a drive that stops responding


def test_medium_vanishes_after_unmount_and_comes_back(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")
    rescans = []

    def unmount_then_vanish(cmd, **kw):  # the stick says "no medium" right after the unmount
        fake.commands.append(list(cmd))
        fake.unmount(cmd[1])
        fake.set_size("sdb", 0)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def rescan(name):
        rescans.append(name)
        fake.set_size("sdb", sdb.size)  # the kernel's second look finds it again
        return True

    monkeypatch.setattr(linux, "run", unmount_then_vanish)
    monkeypatch.setattr(devmod, "request_rescan", rescan)
    monkeypatch.setattr(linux, "MEDIUM_TIMEOUT", 2.0)
    assert backend.prepare(sdb) == ["/media/user/MY STICK"]
    assert rescans == ["sdb"] and fake.probed == [fake.node("sdb")]
    assert "stopped responding" in backend.notes[0] and "is back" in backend.notes[1] and backend.medium_returned


def test_medium_vanishes_and_stays_gone(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")
    fake.set_size("sdb", 0)
    monkeypatch.setattr(devmod, "request_rescan", lambda name: True)
    monkeypatch.setattr(linux, "MEDIUM_TIMEOUT", 0.05)
    with pytest.raises(BeastError, match="stopped responding") as e:
        backend.prepare(sdb)
    assert e.value.code == "device-vanished" and fake.probed == []


def test_medium_comes_back_with_another_size(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")
    fake.set_size("sdb", 0)
    monkeypatch.setattr(devmod, "request_rescan", lambda name: fake.set_size("sdb", 8 * GIB) or True)
    with pytest.raises(BeastError, match="came back with another size") as e:
        backend.prepare(sdb)
    assert e.value.code == "device-vanished" and fake.probed == []


def test_size_changed_without_vanishing(fake, backend, fake_run):
    sdb = backend.get_disk("sdb")
    fake.set_size("sdb", 8 * GIB)  # another card in the reader
    with pytest.raises(BeastError, match="size changed") as e:
        backend.prepare(sdb)
    assert e.value.code is None


def test_medium_gone(fake, backend):
    sdb = backend.get_disk("sdb")
    assert not backend.medium_gone(sdb)
    fake.set_size("sdb", 0)
    assert backend.medium_gone(sdb)
    assert backend.medium_gone(DiskInfo(**{**sdb.__dict__, "extra": {"name": "sdq"}}))  # unplugged: no sysfs


def test_medium_sysfs_helpers(fake, monkeypatch):
    assert devmod.medium_sectors("sdb") == 16 * GIB // 512 and devmod.medium_sectors("sdq") is None
    assert devmod.request_rescan("sdb")  # writes "1" to .../device/rescan
    assert (fake.sysdirs["sdb"] / "device" / "rescan").read_text() == "1"
    assert not devmod.request_rescan("sdq")
    fake.set_size("sdb", 0)
    ident = devmod.disk_identity("sdb")
    assert ident["model"] == "SanDisk Cruzer Blade" and ident["dev"] == "8:16"
    assert devmod.wait_for_medium("sdb", ident, timeout=0.05, poll=0.01) == 0
    fake.set_size("sdb", 16 * GIB)
    assert devmod.wait_for_medium("sdb", ident, timeout=0.05, poll=0.01) == 16 * GIB // 512
    assert devmod.wait_for_medium("sdb", {**ident, "serial": "other"}, timeout=5, poll=0.01) is None
    assert devmod.disk_identity("sdq") is None


def test_check_safe_probe_retries_and_names(fake, backend, monkeypatch):
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    monkeypatch.setattr(devmod, "_exclusive_open", busy_probe)
    with pytest.raises(BeastError, match="is still in use: .*no program could be named") as e:
        backend.check_safe(backend.get_disk("sdc"), allow_fixed=False)
    assert e.value.code == "busy"


# --------------------------------------------------------------------------- kernel log (evidence)


SDB_SYSDIR = "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb"


def test_kernel_patterns_and_log_filter():
    pats = linux.kernel_patterns("sdb", SDB_SYSDIR)
    r, w = os.pipe()
    os.set_blocking(r, False)
    records = [
        "6,1001,5000000,-;sd 6:0:0:0: [sdb] 240253440 512-byte logical blocks",
        " SUBSYSTEM=scsi",
        " DEVICE=+scsi:6:0:0:0",
        "6,1002,5100000,-;sdb: detected capacity change from 240253440 to 0",
        "6,1003,5200000,-;sda: detected capacity change from 100 to 0",  # another disk
        "6,1004,5300000,-;usb 2-1: USB disconnect, device number 7",
        "6,1005,5400000,-;usb 2-1.4: new high-speed USB device number 8",  # a device behind a hub on 2-1
        "6,1006,5500000,-;scsi host6: usb-storage 2-1:1.0",
        "6,1007,5600000,-;sdb: sdb1 sdb2 sdb3",
        "4,1008,5700000,-;EXT4-fs (sdbb1): mounted",  # another disk whose name starts the same
    ]
    os.write(w, ("\n".join(records) + "\n").encode())
    log = linux.KernelLog(r, pats)
    assert log.lines() == [
        "[5.0] sd 6:0:0:0: [sdb] 240253440 512-byte logical blocks",
        "[5.1] sdb: detected capacity change from 240253440 to 0",
        "[5.3] usb 2-1: USB disconnect, device number 7",
        "[5.5] scsi host6: usb-storage 2-1:1.0",
        "[5.6] sdb: sdb1 sdb2 sdb3",
    ]
    assert len(log.lines()) == 5  # kept, nothing new
    log.close()
    os.close(w)
    assert len(log.lines()) == 5


def test_kernel_log_open_is_best_effort(tmp_path, backend, monkeypatch):
    assert linux.KernelLog.open(["x"], str(tmp_path / "no-kmsg")) is None
    monkeypatch.setattr(backend, "is_elevated", lambda: False)
    assert backend.kernel_log(file_disk(tmp_path)) is None


def test_kernel_log_for_disk(fake, backend, monkeypatch, tmp_path):
    kmsg = tmp_path / "kmsg"
    kmsg.write_text("6,1,1,-;sdb: old message\n")
    monkeypatch.setattr(linux, "KMSG", str(kmsg))
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    log = backend.kernel_log(backend.get_disk("sdb"))
    assert log is not None and log.lines() == []  # starts at the end: only what comes after
    log.close()


def test_state_dir(backend, monkeypatch, tmp_path):
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    assert backend.state_dir() == "/var/lib/beast-booter"
    monkeypatch.setattr(backend, "is_elevated", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert backend.state_dir() == str(tmp_path / "beast-booter")


def test_mounted_again_while_probing_is_unmounted(fake, backend, fake_run, monkeypatch):
    """The desktop mounts the stick again (it does after a drive comes back): prepare unmounts that too."""
    tries = []

    def probe(node):
        tries.append(node)
        if len(tries) == 1:
            fake.mount("8:17", fake.node("sdb1"), "/media/user/MY STICK1")
            raise BeastError(f"{node} is in use", code="busy")
        return os.open(os.devnull, os.O_RDONLY)

    monkeypatch.setattr(devmod, "_exclusive_open", probe)
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK", "/media/user/MY STICK1"]
    assert fake.commands == [["umount", "/media/user/MY STICK"], ["umount", "/media/user/MY STICK1"]]
    assert len(tries) == 2


# --------------------------------------------------------------------------- review: identity, exclusive hold


def vanish_after_unmount(fake, monkeypatch):
    def run(cmd, **kw):
        fake.commands.append(list(cmd))
        fake.unmount(cmd[1])
        fake.set_size("sdb", 0)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(linux, "run", run)
    monkeypatch.setattr(linux, "MEDIUM_TIMEOUT", 2.0)


@pytest.mark.parametrize("swap", ["model", "serial", "devnum", "unplugged"])
def test_another_drive_under_the_same_name_is_never_written(fake, backend, fake_run, monkeypatch, swap):
    """Unplugged and another stick of the same size plugged in while we wait: refused at once."""
    usb = fake.sysdirs["sdb"].parents[5]  # .../usb2/2-1, the USB device
    (usb / "idVendor").write_text("0781\n")
    (usb / "serial").write_text("4C530001\n")
    sdb = backend.get_disk("sdb")
    vanish_after_unmount(fake, monkeypatch)

    def replaced(name):
        if swap == "model":
            (fake.sysdirs["sdb"] / "device" / "model").write_text("Ultra Fit\n")
        elif swap == "serial":
            (usb / "serial").write_text("4C530002\n")
        elif swap == "devnum":
            (fake.sysdirs["sdb"] / "dev").write_text("8:48\n")
        else:
            (fake.sys / "block" / "sdb").unlink()
        fake.set_size("sdb", sdb.size)
        return True

    monkeypatch.setattr(devmod, "request_rescan", replaced)
    with pytest.raises(BeastError, match="disconnected or replaced") as e:
        backend.prepare(sdb)
    assert e.value.code == "device-vanished" and fake.probed == [] and backend._held is None


def test_prepare_holds_the_disk_until_rescan(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")
    backend.prepare(sdb)
    held = backend._held
    assert held is not None and os.fstat(held)  # O_EXCL fd kept: nothing can mount a partition meanwhile
    seen = []
    monkeypatch.setattr(linux, "_blkrrpart", lambda path: seen.append(backend._held))
    backend.rescan(sdb)
    assert seen == [None] and backend._held is None  # released before BLKRRPART
    with pytest.raises(OSError):
        os.fstat(held)
    backend.prepare(sdb)  # install's second prepare (NTFS) takes it again
    assert backend._held is not None
    monkeypatch.setattr(linux, "make_data_fs", lambda *a, **kw: seen.append(backend._held))
    monkeypatch.setattr(backend, "wait_partitions", lambda disk, idx, timeout=15.0: {1: fake.node("sdb1")})
    backend.format_ntfs(sdb, 1, "DATA")
    assert seen[-1] is None
    backend.prepare(sdb)
    backend.prepare(sdb)  # a new prepare lets go of the old hold first
    backend.release()
    backend.release()
    assert backend._held is None


def test_check_safe_does_not_keep_the_disk(fake, backend, monkeypatch):
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    backend.check_safe(backend.get_disk("sdc"), allow_fixed=False)
    assert fake.probed == [fake.node("sdc")] and backend._held is None


def test_no_medium_at_the_exclusive_open_is_checked_again(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")
    tries = []

    def probe(node):
        tries.append(node)
        if len(tries) == 1:
            fake.set_size("sdb", 0)
            raise BeastError(f"{node} stopped responding (No medium found)", code="device-vanished")
        return os.open(os.devnull, os.O_RDONLY)

    monkeypatch.setattr(devmod, "_exclusive_open", probe)
    monkeypatch.setattr(devmod, "request_rescan", lambda name: fake.set_size("sdb", sdb.size) or True)
    assert backend.prepare(sdb) == ["/media/user/MY STICK"]
    assert len(tries) == 2 and backend.medium_returned and backend._held is not None


def test_no_medium_at_the_exclusive_open_twice_fails(fake, backend, fake_run, monkeypatch):
    sdb = backend.get_disk("sdb")

    def probe(node):
        raise BeastError(f"{node} stopped responding (No medium found)", code="device-vanished")

    monkeypatch.setattr(devmod, "_exclusive_open", probe)
    monkeypatch.setattr(devmod, "request_rescan", lambda name: True)
    with pytest.raises(BeastError, match="stopped responding") as e:
        backend.prepare(sdb)
    assert e.value.code == "device-vanished"


def test_remount_found_on_the_last_pass_is_probed_again(fake, backend, fake_run, monkeypatch):
    monkeypatch.setattr(linux, "BUSY_RETRY_DELAYS", ())
    tries = []

    def probe(node):
        tries.append(node)
        if len(tries) == 1:
            fake.mount("8:17", fake.node("sdb1"), "/media/user/MY STICK")
            raise BeastError(f"{node} is in use", code="busy")
        return os.open(os.devnull, os.O_RDONLY)

    monkeypatch.setattr(devmod, "_exclusive_open", probe)
    assert backend.prepare(backend.get_disk("sdb")) == ["/media/user/MY STICK"]
    assert len(tries) == 2


def test_prepare_refuses_a_drive_swapped_since_check_safe(fake, backend, fake_run, monkeypatch):
    monkeypatch.setattr(backend, "is_elevated", lambda: True)
    fake.unmount("/media/user/MY STICK")
    sdb = backend.get_disk("sdb")
    backend.check_safe(sdb, allow_fixed=False)
    (fake.sysdirs["sdb"] / "dev").write_text("8:48\n")  # unplugged; another stick got the name
    with pytest.raises(BeastError, match="another device than the drive that was selected") as e:
        backend.prepare(sdb)
    assert e.value.code == "device-vanished" and backend._held is None
