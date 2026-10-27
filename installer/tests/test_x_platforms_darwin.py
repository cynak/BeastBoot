"""macOS backend against recorded-format diskutil plists (fixtures/platforms/darwin).

diskutil is replaced by FakeDiskutil, which serves the fixture plists and
applies `unmountDisk` to its state. The raw target runs on a regular file with
alignment-checking wrappers around os.pwrite / os.readv. The elevation quoting
is checked by decoding the AppleScript literal and running it with /bin/sh.
Untested here: real diskutil output on current macOS releases, /dev/rdiskN
behaviour, F_FULLFSYNC / DKIOC* ioctls, osascript's dialog.
"""

from __future__ import annotations

import ctypes
import json
import mmap
import os
import plistlib
import random
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from beastbooter.errors import BeastError
from beastbooter.interfaces import DiskInfo
from beastbooter.platforms import ELEVATION_CANCELLED, ELEVATION_FAILED, common, darwin
from beastbooter.platforms.darwin import DarwinBackend, DarwinRawTarget, osascript_exit_code, parse_plist

# The backend modules import on Windows (test_x_platforms_common); these tests need a POSIX host.
pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="/bin/sh, POSIX signals and fake device files: POSIX only")

FIXTURES = Path(__file__).parent / "fixtures" / "platforms" / "darwin"


def load(name: str) -> dict:
    return plistlib.loads((FIXTURES / name).read_bytes())


class FakeDiskutil:
    def __init__(self):
        self.listing = load("diskutil-list.plist")
        self.apfs = load("diskutil-apfs-list.plist")
        self.root: dict | Exception = load("diskutil-info-root.plist")
        self.info = {n: load(f"diskutil-info-{n}.plist") for n in ("disk0", "disk4", "disk5", "disk7")}
        self.calls: list[tuple[str, ...]] = []
        self.unmount_works = True
        self.apfs_fails = False
        self.per_disk_listings: list[dict] = []  # successive answers to `list -plist /dev/diskN`

    def __call__(self, argv):
        assert argv[0] == "/usr/sbin/diskutil"
        args = tuple(argv[1:])
        self.calls.append(args)
        if args == ("list", "-plist"):
            return plistlib.dumps(self.listing)
        if args[:2] == ("list", "-plist"):
            return plistlib.dumps(self.per_disk_listings.pop(0) if len(self.per_disk_listings) > 1
                                  else self.per_disk_listings[0])
        if args == ("apfs", "list", "-plist"):
            if self.apfs_fails:
                raise BeastError("diskutil apfs list failed: Unrecognized verb")
            return plistlib.dumps(self.apfs)
        if args == ("info", "-plist", "/"):
            if isinstance(self.root, Exception):
                raise self.root
            return plistlib.dumps(self.root)
        if args[:2] == ("info", "-plist"):
            if args[2] not in self.info:
                raise BeastError(f"diskutil info -plist failed: Could not find disk: {args[2]}")
            return plistlib.dumps(self.info[args[2]])
        if args[:2] == ("unmountDisk", "force"):
            if self.unmount_works:
                self._unmount(args[2].removeprefix("/dev/"))
            return f"Forced unmount of all volumes on {args[2]} was successful\n".encode()
        raise AssertionError(f"unexpected diskutil call {args}")

    def _unmount(self, name):
        for e in self.listing["AllDisksAndPartitions"]:
            if e["DeviceIdentifier"] == name:
                for p in e.get("Partitions", []):
                    p.pop("MountPoint", None)
                for v in e.get("APFSVolumes", []):
                    v.pop("MountPoint", None)


@pytest.fixture
def du():
    return FakeDiskutil()


@pytest.fixture
def backend(du, monkeypatch):
    monkeypatch.setattr(common, "program_paths", lambda: ["/Applications/beast-boot/app"])
    return DarwinBackend(runner=du)


def by_id(disks):
    return {d.id: d for d in disks}


# --------------------------------------------------------------------------- listing


def test_list_default_and_all(backend, du):
    assert [d.id for d in backend.list_disks()] == ["/dev/disk4", "/dev/disk5"]
    assert [d.id for d in backend.list_disks(include_fixed=True)] == ["/dev/disk0", "/dev/disk4", "/dev/disk5"]
    infos = {c[2] for c in du.calls if c[:2] == ("info", "-plist")}
    assert infos == {"/", "disk0", "disk4", "disk5", "disk7"}  # APFS containers are never queried


def test_usb_stick_fields(backend):
    stick = by_id(backend.list_disks())["/dev/disk4"]
    assert stick == DiskInfo(
        id="/dev/disk4", path="/dev/rdisk4", model="Cruzer Blade", size=31914983424, sector_size=512, bus="usb",
        removable=True, system=False, read_only=False, mountpoints=("/Volumes/STICK",),
        partitions=("/dev/disk4s1",),
        extra={"bsd_name": "disk4", "bus_protocol": "USB", "internal": False, "removable_media": True,
               "ejectable": True, "content": "FDisk_partition_scheme", "system_reason": None,
               "member_of": None},
    )


def test_internal_ssd_is_system(backend):
    ssd = by_id(backend.list_disks(include_fixed=True))["/dev/disk0"]
    assert (ssd.system, ssd.removable, ssd.bus, ssd.sector_size) == (True, False, "nvme", 4096)
    assert ssd.extra["system_reason"] == 'holds the running macOS ("/")'
    assert ssd.partitions == ("/dev/disk0s1", "/dev/disk0s2", "/dev/disk0s3")
    assert {"/", "/System/Volumes/Data", "/System/Volumes/VM", "/System/Volumes/iSCPreboot"} <= set(ssd.mountpoints)


def test_external_ssd_with_apfs_container(backend):
    t7 = by_id(backend.list_disks())["/dev/disk5"]
    assert (t7.removable, t7.extra["removable_media"], t7.extra["internal"]) == (True, False, False)
    assert t7.mountpoints == ("/Volumes/Backups",)  # a volume of APFS container disk6 on disk5s2
    assert t7.partitions == ("/dev/disk5s1", "/dev/disk5s2")


def test_root_not_traceable_marks_internal_disks(backend, du):
    du.root = BeastError("diskutil info -plist / failed")
    disks = by_id(backend.list_disks(include_fixed=True))
    assert disks["/dev/disk0"].system  # still found through the container mounted at "/"
    du.listing["AllDisksAndPartitions"][3]["APFSVolumes"][0].pop("MountedSnapshots")
    for v in du.listing["AllDisksAndPartitions"][3]["APFSVolumes"] + du.listing["AllDisksAndPartitions"][1]["APFSVolumes"]:
        v.pop("MountPoint", None)
    disks = by_id(backend.list_disks(include_fixed=True))
    assert disks["/dev/disk0"].system and "could not be identified" in disks["/dev/disk0"].extra["system_reason"]
    assert not disks["/dev/disk4"].system and not disks["/dev/disk5"].system  # external disks unaffected


def test_booted_from_external_disk(backend, du):
    du.root.update({"DeviceIdentifier": "disk6s1", "ParentWholeDisk": "disk6", "APFSContainerReference": "disk6",
                    "APFSPhysicalStores": [{"APFSPhysicalStore": "disk5s2"}], "BooterDeviceIdentifier": ""})
    disks = by_id(backend.list_disks(include_fixed=True))
    assert disks["/dev/disk5"].system
    assert "/dev/disk5" not in by_id(backend.list_disks())


def test_containers_from_listing_when_apfs_list_fails(backend, du):
    du.apfs_fails = True
    disks = by_id(backend.list_disks(include_fixed=True))
    assert disks["/dev/disk0"].system and not disks["/dev/disk5"].system
    assert disks["/dev/disk5"].mountpoints == ("/Volumes/Backups",)


def test_get_disk_forms_and_errors(backend):
    for form in ("/dev/disk4", "disk4", "/dev/rdisk4", " /dev/disk4 "):
        assert backend.get_disk(form).id == "/dev/disk4"
    with pytest.raises(BeastError, match=r"is a partition; pass the whole disk \(/dev/disk4\)"):
        backend.get_disk("/dev/disk4s1")
    with pytest.raises(BeastError, match="is a partition"):
        backend.get_disk("disk3s1s1")
    with pytest.raises(BeastError, match="APFS container"):
        backend.get_disk("disk3")
    with pytest.raises(BeastError, match="virtual disk"):
        backend.get_disk("/dev/disk7")
    with pytest.raises(BeastError, match="does not exist"):
        backend.get_disk("disk9")
    with pytest.raises(BeastError, match="not a macOS disk"):
        backend.get_disk("/dev/sdb")


def test_check_safe(backend, du):
    backend.check_safe(backend.get_disk("disk4"), allow_fixed=False)
    backend.check_safe(backend.get_disk("disk5"), allow_fixed=False)  # external = eligible
    with pytest.raises(BeastError, match=r'refusing: /dev/disk0 holds the running macOS \("/"\)'):
        backend.check_safe(backend.get_disk("disk0"), allow_fixed=True)
    du.info["disk4"]["WritableMedia"] = False
    with pytest.raises(BeastError, match="read-only"):
        backend.check_safe(backend.get_disk("disk4"), allow_fixed=False)


def test_check_safe_running_from_stick(backend, monkeypatch):
    monkeypatch.setattr(common, "program_paths", lambda: ["/Volumes/STICK/beast-boot/python/bin/python3"])
    with pytest.raises(BeastError, match="running from /dev/disk4"):
        backend.check_safe(backend.get_disk("disk4"), allow_fixed=False)


# --------------------------------------------------------------------------- AppleRAID / CoreStorage members


def add_member_disks(du, content="Apple_RAID"):
    """Two USB disks (disk8, disk9) whose second partitions form a set, disk10 (virtual,
    mounted at /Volumes/Mirror) - as `diskutil appleRAID create mirror` leaves them."""
    for n in (8, 9):
        name = f"disk{n}"
        du.listing["AllDisksAndPartitions"].append({
            "Content": "GUID_partition_scheme", "DeviceIdentifier": name, "OSInternal": False, "Size": 64023257088,
            "Partitions": [
                {"Content": "EFI", "DeviceIdentifier": f"{name}s1", "Size": 209715200, "VolumeName": "EFI"},
                {"Content": content, "DeviceIdentifier": f"{name}s2", "Size": 63677841408},
            ]})
        du.listing["WholeDisks"].append(name)
        info = dict(du.info["disk4"], DeviceIdentifier=name, DeviceNode=f"/dev/{name}", MediaName="Extreme",
                    Size=64023257088, TotalSize=64023257088, IOKitSize=64023257088, Content="GUID_partition_scheme")
        du.info[name] = info
    du.listing["AllDisksAndPartitions"].append({
        "Content": "Apple_HFS", "DeviceIdentifier": "disk10", "MountPoint": "/Volumes/Mirror", "OSInternal": False,
        "Size": 63543623680, "VolumeName": "Mirror"})
    du.listing["WholeDisks"].append("disk10")
    du.info["disk10"] = dict(du.info["disk7"], DeviceIdentifier="disk10", VirtualOrPhysical="Virtual",
                             RAIDMaster=True, BusProtocol="Disk Image", MediaName="Mirror")


@pytest.mark.parametrize("content,what", [
    ("Apple_RAID", "a member of an AppleRAID set (disk8s2)"),
    ("52414944-0000-11AA-AA11-00306543ECAC", "a member of an AppleRAID set (disk8s2)"),
    ("Apple_RAID_Offline", "a member of an AppleRAID set (offline) (disk8s2)"),
    ("Apple_CoreStorage", "a CoreStorage physical volume (Fusion Drive or encrypted volume) (disk8s2)"),
])
def test_raid_and_corestorage_members_refused(backend, du, content, what):
    add_member_disks(du, content)
    disks = by_id(backend.list_disks())
    assert "/dev/disk10" not in disks  # the set itself is virtual
    member = disks["/dev/disk8"]
    assert member.extra["member_of"] == what
    with pytest.raises(BeastError, match=r"refusing: /dev/disk8 is a .*; remove it from the set"):
        backend.check_safe(member, allow_fixed=True)
    with pytest.raises(BeastError, match="remove it from the set"):
        backend.prepare(member)
    assert not [c for c in du.calls if c[0] == "unmountDisk"]  # the set stays mounted, untouched


def test_raid_slice_flag_on_whole_disk(backend, du):
    du.info["disk4"]["RAIDSlice"] = True  # an unpartitioned whole-disk member
    with pytest.raises(BeastError, match=r"/dev/disk4 is a member of an AppleRAID set \(disk4\)"):
        backend.check_safe(backend.get_disk("disk4"), allow_fixed=False)


def test_ordinary_disks_are_not_members(backend):
    assert all(d.extra["member_of"] is None for d in backend.list_disks(include_fixed=True))


# --------------------------------------------------------------------------- prepare


def test_mounted_stick_is_not_refused(backend, du):
    """Mounted volumes are no reason to refuse: prepare() unmounts them and returns where they were."""
    stick = backend.get_disk("disk4")
    assert stick.mountpoints == ("/Volumes/STICK",)
    backend.check_safe(stick, allow_fixed=False)
    assert backend.prepare(stick) == ["/Volumes/STICK"]
    assert backend.get_disk("disk4").mountpoints == ()


def test_prepare_busy(backend, du, monkeypatch):
    real = backend._run

    def run(argv):
        if argv[1] == "unmountDisk":
            raise BeastError("diskutil unmountDisk force failed: Forced unmount of disk4 failed: at least one "
                             "volume could not be unmounted")
        return real(argv)

    monkeypatch.setattr(backend, "_run", run)
    with pytest.raises(BeastError, match=r"cannot unmount /Volumes/STICK \(.*could not be unmounted\); close the "
                                         "programs") as e:
        backend.prepare(backend.get_disk("disk4"))
    assert e.value.code == "busy"


def test_prepare_unmounts_containers_then_disk(backend, du):
    assert backend.prepare(backend.get_disk("disk5")) == ["/Volumes/Backups"]
    unmounts = [c for c in du.calls if c[0] == "unmountDisk"]
    assert unmounts == [("unmountDisk", "force", "/dev/disk6"), ("unmountDisk", "force", "/dev/disk5")]
    assert backend.get_disk("disk5").mountpoints == ()


def test_prepare_still_mounted(backend, du):
    du.unmount_works = False
    with pytest.raises(BeastError, match="still mounted at /Volumes/STICK") as e:
        backend.prepare(backend.get_disk("disk4"))
    assert e.value.code == "busy"


# --------------------------------------------------------------------------- raw target


class OsProxy:
    """The os module with some functions replaced (only inside darwin.py)."""

    def __init__(self, real, **override):
        self._real = real
        self.__dict__.update(override)

    def __getattr__(self, name):
        return getattr(self._real, name)


def address(buf) -> int:
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))


RAW_SIZE = 4 << 20


@pytest.fixture
def raw_file(tmp_path):
    p = tmp_path / "rdisk4"
    p.write_bytes(random.Random(4).randbytes(RAW_SIZE))
    return p


@pytest.fixture
def aligned_os(monkeypatch):
    """Fail like /dev/rdiskN would on unaligned offsets, lengths or buffers."""
    log = []
    pos = {}

    def lseek(fd, off, how):
        pos[fd] = off
        return os.lseek(fd, off, how)

    def readv(fd, bufs):
        (buf,) = bufs
        assert pos[fd] % 512 == 0 and len(buf) % 512 == 0, (pos[fd], len(buf))
        assert address(buf) % mmap.PAGESIZE == 0
        log.append(("r", pos[fd], len(buf)))
        return os.readv(fd, bufs)

    def pwrite(fd, buf, off):
        assert off % 512 == 0 and len(buf) % 512 == 0, (off, len(buf))
        assert address(buf) % mmap.PAGESIZE == 0
        log.append(("w", off, len(buf)))
        return os.pwrite(fd, buf, off)

    monkeypatch.setattr(darwin, "os", OsProxy(os, lseek=lseek, readv=readv, pwrite=pwrite))
    return log


def test_raw_target_unaligned_io_is_aligned_underneath(raw_file, aligned_os):
    model = bytearray(raw_file.read_bytes())
    with DarwinRawTarget(str(raw_file), writable=True, sector_size=512, size=RAW_SIZE) as t:
        t.write(1000, b"beast")
        model[1000:1005] = b"beast"
        assert aligned_os == [("r", 512, 512), ("w", 512, 512)]
        big = os.urandom((5 << 20) // 2 + 77)  # 2.5 MiB: three passes through the 1 MiB bounce buffer
        t.write(4097, big)
        model[4097:4097 + len(big)] = big
        assert max(n for _, _, n in aligned_os) == 1 << 20
        assert t.read(999, len(big)) == bytes(model[999:999 + len(big)])
        t.flush()
    assert raw_file.read_bytes() == model


def test_raw_target_geometry_checks(raw_file, monkeypatch):
    monkeypatch.setattr(darwin, "_ioctl_geometry", lambda fd: (512, RAW_SIZE // 512))
    DarwinRawTarget(str(raw_file), writable=False, sector_size=512, size=RAW_SIZE).close()
    monkeypatch.setattr(darwin, "_ioctl_geometry", lambda fd: (512, 4096))
    with pytest.raises(BeastError, match="size changed"):
        DarwinRawTarget(str(raw_file), writable=False, sector_size=512, size=RAW_SIZE)
    monkeypatch.setattr(darwin, "_ioctl_geometry", lambda fd: (4096, 256))
    with pytest.raises(BeastError, match="block size changed"):
        DarwinRawTarget(str(raw_file), writable=False, sector_size=512, size=RAW_SIZE)


def test_raw_target_flush_uses_f_fullfsync(raw_file, monkeypatch):
    calls = []

    class Fcntl:
        F_FULLFSYNC = 51

        @staticmethod
        def fcntl(fd, cmd):
            calls.append(cmd)
            return 0

        @staticmethod
        def ioctl(fd, request, *arg):  # raw_file is a regular file: macOS answers ENOTTY
            raise OSError(25, "Inappropriate ioctl for device")

    monkeypatch.setitem(sys.modules, "fcntl", Fcntl)  # darwin.py imports fcntl where it uses it
    with DarwinRawTarget(str(raw_file), writable=True, sector_size=512, size=RAW_SIZE) as t:
        t.flush()
    assert calls == [51]

    class Failing(Fcntl):
        @staticmethod
        def fcntl(fd, cmd):
            raise OSError(25, "Inappropriate ioctl for device")

    synced = []
    monkeypatch.setitem(sys.modules, "fcntl", Failing)
    monkeypatch.setattr(darwin, "os", OsProxy(os, fsync=synced.append))
    with DarwinRawTarget(str(raw_file), writable=True, sector_size=512, size=RAW_SIZE) as t:
        t.flush()
        assert synced == [t.fd]


def test_ioctl_numbers():
    def _ior(group, num, size):
        return 0x40000000 | ((size & 0x1FFF) << 16) | (ord(group) << 8) | num

    assert darwin.DKIOCGETBLOCKSIZE == _ior("d", 24, 4)
    assert darwin.DKIOCGETBLOCKCOUNT == _ior("d", 25, 8)
    assert darwin.DKIOCSYNCHRONIZECACHE == 0x20000000 | (ord("d") << 8) | 22


def test_open_raw_uses_rdisk(backend, monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, path, **kw):
            seen.update(path=path, **kw)

    monkeypatch.setattr(darwin, "DarwinRawTarget", Fake)
    backend.open_raw(backend.get_disk("disk4"), writable=True)
    assert seen == {"path": "/dev/rdisk4", "writable": True, "sector_size": 512, "size": 31914983424}


# --------------------------------------------------------------------------- rescan


def mbr_disk(path: Path, size: int, parts: list[tuple[int, int, int]]) -> None:
    mbr = bytearray(512)
    for i, (ptype, start, count) in enumerate(parts):
        struct.pack_into("<B3xB3xII", mbr, 0x1BE + 16 * i, 0x80 if i == 0 else 0, ptype, start, count)
    mbr[510:512] = b"\x55\xaa"
    with open(path, "wb") as f:
        f.write(mbr)
        f.truncate(size)


def per_disk_listing(name: str, sizes: list[int]) -> dict:
    return {"AllDisksAndPartitions": [{
        "Content": "FDisk_partition_scheme", "DeviceIdentifier": name, "OSInternal": False, "Size": 1,
        "Partitions": [{"Content": "DOS_FAT_32", "DeviceIdentifier": f"{name}s{i}", "Size": s}
                       for i, s in enumerate(sizes, 1)]}],
        "AllDisks": [name], "VolumesFromDisks": [], "WholeDisks": [name]}


def test_rescan_waits_for_new_partitions(backend, du, tmp_path, monkeypatch):
    size = 64 << 20
    img = tmp_path / "rdisk4"
    mbr_disk(img, size, [(0x07, 2048, 98304), (0xEF, 100352, 30720)])
    disk = DiskInfo(id="/dev/disk4", path=str(img), model="x", size=size, sector_size=512, bus="usb",
                    removable=True, system=False, read_only=False)
    du.per_disk_listings = [per_disk_listing("disk4", [66060288]),  # old table, not re-probed yet
                            per_disk_listing("disk4", [66060288]),
                            per_disk_listing("disk4", [98304 * 512, 30720 * 512])]
    monkeypatch.setattr(darwin.time, "sleep", lambda s: None)
    backend.rescan(disk)
    assert [c for c in du.calls if c[:2] == ("list", "-plist")] == [("list", "-plist", "/dev/disk4")] * 3


def test_rescan_timeout(backend, du, tmp_path, monkeypatch):
    size = 64 << 20
    img = tmp_path / "rdisk4"
    mbr_disk(img, size, [(0x07, 2048, 98304), (0xEF, 100352, 30720)])
    disk = DiskInfo(id="/dev/disk4", path=str(img), model="x", size=size, sector_size=512, bus="usb",
                    removable=True, system=False, read_only=False)
    du.per_disk_listings = [per_disk_listing("disk4", [66060288])]
    with pytest.raises(BeastError, match=r"did not pick up the new partition table.*1 of 2.*unplug and reconnect"):
        backend.rescan(disk, timeout=0)


# --------------------------------------------------------------------------- misc


def test_partition_path_and_ntfs(backend):
    disk = backend.get_disk("disk4")
    assert backend.partition_path(disk, 1) == "/dev/disk4s1"
    assert backend.partition_path(disk, 2) == "/dev/disk4s2"
    with pytest.raises(BeastError, match="macOS cannot create NTFS.*exFAT"):
        backend.format_ntfs(disk, 1, "BEASTBOOTER")


def test_parse_plist_tolerates_leading_text():
    data = b"Some warning from diskutil\n" + plistlib.dumps({"a": 1})
    assert parse_plist(data) == {"a": 1}
    with pytest.raises(BeastError, match="could not parse"):
        parse_plist(b"not a plist")
    with pytest.raises(BeastError, match="not a dictionary"):
        parse_plist(plistlib.dumps([1, 2]))


# --------------------------------------------------------------------------- elevation

NASTY = [
    "/Volumes/My Stick/beast booter/app/beast_booter_launch.py",
    "install", "--device", "/dev/disk4",
    "--progress-file", "/private/var/folders/x/T/bb progress.jsonl",
    "it's", "'", '"', 'say "hi"', "back\\slash\\", "\\\"", "\\n", "$HOME `id` $(id)", "a;b&&c|d>e<f",
    "new\nline", "cr\rreturn", "tab\there", "ünïcødé ✓ 🚀", "", " ", "-e",
    '" with administrator privileges --', "'; rm -rf ~; '", "*", "~", "!", "%s",
]


def parse_literal(s: str, i: int) -> tuple[str, int]:
    """Parse an AppleScript string literal at s[i] (escapes: \\\\ \\" \\n \\r \\t)."""
    assert s[i] == '"'
    i += 1
    out = []
    escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
    while s[i] != '"':
        if s[i] == "\\":
            out.append(escapes[s[i + 1]])
            i += 2
        else:
            assert s[i] not in "\n\r", "raw line break inside the AppleScript literal"
            out.append(s[i])
            i += 1
    return "".join(out), i + 1


def decode_script(script: str) -> tuple[str, str]:
    head = "do shell script "
    assert script.startswith(head)
    command, i = parse_literal(script, len(head))
    assert script[i:].startswith(" with prompt ")
    prompt, j = parse_literal(script, i + len(" with prompt "))
    assert script[j:] == " with administrator privileges"
    return command, prompt


def test_osascript_command_shape(tmp_path):
    cmd = darwin.elevation_command(["/usr/bin/true"])
    assert cmd[:2] == ["/usr/bin/osascript", "-e"] and len(cmd) == 3
    command, prompt = decode_script(cmd[2])
    assert command == "exec /usr/bin/true"
    assert "administrator" in prompt
    files = darwin.ElevationFiles(str(tmp_path))
    command, _ = decode_script(darwin.elevation_command(["/usr/bin/true"], files)[2])
    assert command.startswith(f"mkdir {files.started} 2>/dev/null; /usr/bin/true </dev/null >{files.output} 2>&1 & ")
    assert f'wait "$pid"; rc=$?; mkdir {files.dir}/exit-"$rc" 2>/dev/null;' in command
    assert command.endswith('kill "$watcher" 2>/dev/null; exit "$rc"')
    assert oct(os.stat(files.dir).st_mode & 0o777) == "0o700"
    with pytest.raises(ValueError):
        darwin.elevation_command([])


SHELLS = [sh for sh in ("/bin/sh", "/bin/dash", "/bin/bash") if os.path.exists(sh)]  # macOS /bin/sh: bash 3.2 or dash


@pytest.mark.parametrize("shell", SHELLS)
def test_osascript_quoting_survives_sh(tmp_path, shell):
    """Decode the AppleScript literal like AppleScript does, run it with /bin/sh like
    `do shell script` does, and check the program receives exactly our argv."""
    echo = [sys.executable, "-c", "import json, sys; print(json.dumps(sys.argv[1:]))"]
    script = darwin.elevation_command(echo + NASTY)[2]
    assert "\n" not in script and "\r" not in script
    command, _ = decode_script(script)
    proc = subprocess.run([shell, "-c", command], capture_output=True, text=True, check=True)
    assert json.loads(proc.stdout) == NASTY
    # The same through the supervised form (output goes to the output file).
    files = darwin.ElevationFiles(str(tmp_path))
    nasty_dir = tmp_path / "it's \"x\" $(id) `id` \\ dir"
    nasty_dir.mkdir()
    files_nasty = darwin.ElevationFiles(str(nasty_dir))  # the temp dir path itself may need quoting
    for f in (files, files_nasty):
        script = darwin.elevation_command(echo + NASTY, f)[2]
        assert "\n" not in script and "\r" not in script
        command, _ = decode_script(script)
        proc = subprocess.run([shell, "-c", command], capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0 and proc.stdout == ""
        assert json.loads(Path(f.output).read_text()) == NASTY
        assert os.path.isdir(f.started) and f.marker("exit-") == 0 and f.marker("pid-") > 1


@pytest.mark.parametrize("shell", SHELLS)
def test_supervised_command_exit_status_and_signals(tmp_path, shell):
    def run(code, files, marker=None):
        cmd = decode_script(darwin.elevation_command([sys.executable, "-c", code], files)[2])[0]
        p = subprocess.Popen([shell, "-c", cmd])
        if marker:
            wait_for(lambda: os.path.exists(files.output) and "ready" in Path(files.output).read_text())
            Path(marker).touch()
        return p.wait(30)

    f = darwin.ElevationFiles(str(tmp_path))
    assert run("import sys; print('x'); sys.exit(7)", f) == 7 and f.marker("exit-") == 7
    f = darwin.ElevationFiles(str(tmp_path))
    assert run("import time; print('ready', flush=True); time.sleep(60)", f, f.cancel) == 128 + 15
    f = darwin.ElevationFiles(str(tmp_path))
    ignore_term = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                   "print('ready', flush=True); time.sleep(60)")
    assert run(ignore_term, f, f.kill) == 128 + 9


@pytest.mark.parametrize("rc,stderr,expected", [
    (0, "", 0),
    (1, "0:96: execution error: beast-boot: error: refusing: /dev/disk0 holds the running macOS (1)", 1),
    (1, "0:96: execution error: some output (with parentheses) and more (2)\n", 2),
    (1, "0:132: execution error: User canceled. (-128)", ELEVATION_CANCELLED),
    (1, "0:132: execution error: The administrator user name or password was incorrect. (-60007)", ELEVATION_FAILED),
    (1, "osascript: something unexpected", ELEVATION_FAILED),
    (-15, "", ELEVATION_FAILED),
])
def test_osascript_exit_codes(rc, stderr, expected):
    assert osascript_exit_code(rc, stderr) == expected


FAKE_OSASCRIPT = r"""
import os, subprocess, sys, time

# Behaves like `osascript -e 'do shell script "..." with administrator privileges'`:
# decodes the AppleScript literal, shows the "dialog" (sleeps), runs the command
# with /bin/sh -c and reports a failure the way osascript does.
script = sys.argv[2]
assert sys.argv[1] == "-e" and script.startswith("do shell script ")
ESC = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
i, out = len("do shell script ") + 1, []
while script[i] != '"':
    if script[i] == "\\":
        out.append(ESC[script[i + 1]]); i += 2
    else:
        out.append(script[i]); i += 1
command = "".join(out)
time.sleep(float(os.environ.get("FAKE_DIALOG_SECONDS", "0")))
if os.environ.get("FAKE_DIALOG") == "cancel":
    sys.stderr.write("0:10: execution error: User canceled. (-128)\n")
    sys.exit(1)
proc = subprocess.run([os.environ.get("FAKE_SH", "/bin/sh"), "-c", command], capture_output=True, text=True)
if proc.returncode:
    err = proc.stderr.strip() or "The command exited with a non-zero status."
    sys.stderr.write(f"0:{len(script)}: execution error: {err} ({proc.returncode})\n")
    sys.exit(1)
sys.stdout.write(proc.stdout.replace("\n", "\r"))
"""


@pytest.fixture
def osascript(tmp_path, monkeypatch):
    path = tmp_path / "osascript"
    path.write_text(f"#!{sys.executable}\n{FAKE_OSASCRIPT}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(darwin, "OSASCRIPT", str(path))
    monkeypatch.setenv("TMPDIR", str(tmp_path))  # ElevationFiles go here
    return path


def wait_for(cond, timeout=20.0):
    import time

    deadline = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_run_elevated_reports_command_exit_code(backend, osascript):
    p = backend.run_elevated(py("import sys; print('partial output', flush=True); print('bad', file=sys.stderr); "
                                "sys.exit(3)"))
    assert p.wait(30) == 3 and p.poll() == 3
    assert p.output.splitlines() == ["partial output", "bad"]
    assert p.output_tail() == ["partial output", "bad",
                               f"0:{len(p.argv[2])}: execution error: The command exited with a non-zero status. (3)"]
    assert not os.path.exists(p.files.dir)  # cleaned up once the command has exited
    ok = backend.run_elevated(py("print('fine')"))
    assert ok.wait(30) == 0 and ok.output == "fine\n"


def test_run_elevated_dialog_cancelled(backend, osascript, monkeypatch):
    monkeypatch.setenv("FAKE_DIALOG", "cancel")
    p = backend.run_elevated(["/usr/bin/true"])
    assert p.wait(30) == ELEVATION_CANCELLED and not p.started()


def test_cancel_stops_the_root_command_not_osascript(backend, osascript, tmp_path):
    """The reviewer's case: cancel() must stop the installer itself, and poll() must not
    report the end before the installer has really exited."""
    pidfile = tmp_path / "cli.pid"
    code = (f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); "
            "print('working', flush=True); time.sleep(60)")
    p = backend.run_elevated(py(code))
    wait_for(lambda: pidfile.exists() and pidfile.read_text())
    cli_pid = int(pidfile.read_text())
    assert p.started() and p.poll() is None
    p.cancel()
    assert p.wait(30) == 128 + 15  # the installer's own status: ended by SIGTERM
    assert p._p.returncode == 1  # osascript exited by itself (reporting the error), it was not killed
    with pytest.raises(ProcessLookupError):
        os.kill(cli_pid, 0)  # the installer is gone
    assert p.output_tail()[0] == "working"


def test_second_cancel_kills(backend, osascript):
    code = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)")
    p = backend.run_elevated(py(code))
    wait_for(lambda: "ready" in Path(p.files.output).read_text())
    p.cancel()
    with pytest.raises(TimeoutError):
        p.wait(0.8)  # SIGTERM ignored: still running, and still reported as running
    assert p.poll() is None
    p.cancel()
    assert p.wait(30) == 128 + 9


def test_cancel_at_password_dialog(backend, osascript, monkeypatch, tmp_path):
    """Nothing runs as root yet: osascript (the dialog) is stopped, the command never runs."""
    monkeypatch.setenv("FAKE_DIALOG_SECONDS", "30")
    ran = tmp_path / "ran"
    p = backend.run_elevated(py(f"open({str(ran)!r}, 'w')"))
    assert p.poll() is None and not p.started()
    p.cancel()
    assert p.wait(30) == ELEVATION_CANCELLED
    assert not ran.exists() and not os.path.exists(p.files.dir)


def test_command_survives_osascript_dying(backend, osascript, tmp_path):
    """The installer's output does not go through osascript: if osascript dies (killed from
    outside), the installer is not killed by a broken pipe halfway through a write, and
    poll() does not report the end before the installer has really exited."""
    done = tmp_path / "done"
    code = (f"import sys, time\nfor i in range(40):\n    print('line', i, flush=True)\n    time.sleep(0.02)\n"
            f"open({str(done)!r}, 'w').write('ok')\nsys.exit(5)")
    p = backend.run_elevated(py(code))
    wait_for(lambda: "line 3" in Path(p.files.output).read_text())
    p._p.kill()  # osascript gone
    p._p.wait(10)
    assert p.poll() is None and not done.exists()  # still running: not reported as finished
    assert p.wait(30) == 5  # the status the root shell recorded, once the installer exited
    assert done.read_text() == "ok"
    assert "line 39" in p.output and not os.path.exists(p.files.dir)


def test_is_elevated(backend, monkeypatch):
    monkeypatch.setattr(darwin.os, "geteuid", lambda: 0)
    assert backend.is_elevated()


def test_check_safe_refuses_swapped_drive(backend, du):
    selected = backend.get_disk("disk4")
    du.info["disk4"]["MediaName"] = "Another Stick"
    with pytest.raises(BeastError, match="changed since it was selected"):
        backend.check_safe(selected, allow_fixed=False)


def test_prepare_refuses_system_disk(backend, du):
    disk = DiskInfo(id="/dev/disk0", path="/dev/rdisk0", model="APPLE SSD AP0512Z", size=500277792768,
                    sector_size=4096, bus="nvme", removable=False, system=False, read_only=False)
    with pytest.raises(BeastError, match="holds the running macOS"):
        backend.prepare(disk)
    assert not [c for c in du.calls if c[0] == "unmountDisk"]


def test_disk_vanishing_during_listing(backend, du):
    del du.info["disk5"]  # unplugged between `diskutil list` and `diskutil info`
    assert [d.id for d in backend.list_disks()] == ["/dev/disk4"]
    with pytest.raises(BeastError, match="Could not find disk: disk5"):
        backend.get_disk("disk5")
