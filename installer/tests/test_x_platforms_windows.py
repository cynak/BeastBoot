"""Windows backend on Linux: recorded-format PowerShell JSON + a stub windll.

FakePowerShell serves fixtures/platforms/windows/*.json in the section format
of windows.LIST_SCRIPT. FakeWindll stands in for kernel32/shell32: physical
drives are bytearrays, volumes have extents and lock state, and it enforces
what real Windows enforces (unbuffered I/O must be sector aligned in offset,
length and buffer address; writes inside a mounted, unlocked volume fail with
ERROR_ACCESS_DENIED). Untested here: real Windows (UAC, Get-Disk output on
current releases, FSCTL/IOCTL behaviour on real drives, Format-Volume).
"""

from __future__ import annotations

import base64
import ctypes
import json
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from beastbooter.errors import BeastError
from beastbooter.interfaces import DiskInfo
from beastbooter.platforms import ELEVATION_CANCELLED, windows as win
from beastbooter.platforms.windows import (
    FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_UPDATE_PROPERTIES,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, Win32, WindowsBackend, json_list, parse_disk_number, ps_quote,
)

FIXTURES = Path(__file__).parent / "fixtures" / "platforms" / "windows"
STICK_GUID = "\\\\?\\Volume{d1c2b3a4-9e8f-11ef-a5b6-c7d8e9f0a1b2}"
MIB = 1 << 20


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def listing(disks="get-disk.json", parts="get-partition.json", vols="get-volume.json", env=None) -> str:
    env_text = fixture("env.json") if env is None else json.dumps(env)
    out = ["##BEAST:disks", fixture(disks) if disks else "", "##BEAST:partitions", fixture(parts) if parts else "",
           "##BEAST:volumes", fixture(vols) if vols else "", "##BEAST:env", env_text]
    return "\r\n".join(out) + "\r\n"  # PowerShell writes CRLF


class FakePowerShell:
    def __init__(self):
        self.list_output = listing()
        self.partition_answers: list[list[dict]] = []
        self.ntfs_answer = json.dumps({"FileSystem": "NTFS", "FileSystemLabel": "BEASTBOOTER", "Size": 1})
        self.scripts: list[tuple[str, str]] = []

    def __call__(self, script, what):
        self.scripts.append((script, what))
        if "Format-Volume" in script:
            return "##BEAST:result\r\n" + self.ntfs_answer + "\r\n"
        if "Get-Partition -DiskNumber" in script:
            answer = self.partition_answers.pop(0) if len(self.partition_answers) > 1 else self.partition_answers[0]
            return "##BEAST:partitions\r\n" + json.dumps(answer[0] if len(answer) == 1 else answer) + "\r\n"
        if "Get-Disk" in script:
            return self.list_output
        raise AssertionError(f"unexpected script {script!r}")


# --------------------------------------------------------------------------- stub windll


class Fn:
    """A stub DLL function: accepts restype/argtypes like a ctypes function pointer."""

    def __init__(self, impl):
        self.impl = impl
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        return self.impl(*args)


class Volume:
    def __init__(self, disk: int, start: int, end: int, busy: int = 0):
        self.disk, self.start, self.end = disk, start, end
        self.mounted = True
        self.locked_by = None
        self.busy = busy  # this many lock attempts fail (programs have files open)
        self.forced = False


class FakeWindll:
    def __init__(self):
        self.disks: dict[int, bytearray] = {}
        self.volumes: dict[str, Volume] = {}
        self.letters: dict[str, list[int]] = {}  # "C" -> disks its volume has extents on (\\.\C:)
        self.handles: dict[int, dict] = {}
        self.next_handle = 0x100
        self.err = 0
        self.admin = True
        self.log: list[tuple] = []
        self.uac = "yes"  # "yes" | "no" | "missing"
        self.sei = None
        self.waits: list[int] = []
        self.exit_code = 0
        self.terminated = False
        k = {name: Fn(getattr(self, name)) for name in (
            "CreateFileW", "ReadFile", "WriteFile", "SetFilePointerEx", "FlushFileBuffers", "DeviceIoControl",
            "CloseHandle", "WaitForSingleObject", "GetExitCodeProcess", "TerminateProcess")}
        self.kernel32 = SimpleNamespace(**k)
        self.shell32 = SimpleNamespace(IsUserAnAdmin=Fn(lambda: int(self.admin)),
                                       ShellExecuteExW=Fn(self.ShellExecuteExW))
        self.get_last_error = lambda: self.err

    def _fail(self, code):
        self.err = code
        return 0

    def _new(self, **state):
        h = self.next_handle
        self.next_handle += 4
        self.handles[h] = state
        return h

    # kernel32 -------------------------------------------------------------
    def CreateFileW(self, path, access, share, sa, disposition, flags, template):
        assert disposition == win.OPEN_EXISTING and share == win.FILE_SHARE_READ | win.FILE_SHARE_WRITE
        assert sa is None and template is None
        self.log.append(("open", path, access, flags))
        if path.startswith("\\\\.\\PhysicalDrive"):
            n = int(path[len("\\\\.\\PhysicalDrive"):])
            if n not in self.disks:
                self._fail(win.ERROR_FILE_NOT_FOUND)
                return win.INVALID_HANDLE_VALUE
            if not self.admin:
                self._fail(win.ERROR_ACCESS_DENIED)
                return win.INVALID_HANDLE_VALUE
            return self._new(kind="disk", n=n, pos=0, access=access, flags=flags)
        if path in self.volumes:
            return self._new(kind="volume", path=path, access=access, flags=flags)
        if path.startswith("\\\\.\\") and path[4:5] in self.letters and path[5:] == ":":
            return self._new(kind="letter", path=path, letter=path[4], access=access, flags=flags)
        self._fail(win.ERROR_FILE_NOT_FOUND)
        return win.INVALID_HANDLE_VALUE

    def _io_checks(self, st, address, length):
        if st["flags"] & win.FILE_FLAG_NO_BUFFERING:
            assert st["pos"] % 512 == 0 and length % 512 == 0, (st["pos"], length)
            assert address % 512 == 0, hex(address)

    def ReadFile(self, h, address, length, count, overlapped):
        st = self.handles[h]
        self._io_checks(st, address, length)
        data = bytes(self.disks[st["n"]][st["pos"]:st["pos"] + length])
        ctypes.memmove(address, data, len(data))
        count._obj.value = len(data)
        st["pos"] += len(data)
        self.log.append(("read", st["pos"] - len(data), len(data)))
        return 1

    def WriteFile(self, h, address, length, count, overlapped):
        st = self.handles[h]
        self._io_checks(st, address, length)
        if not st["access"] & win.GENERIC_WRITE:
            return self._fail(win.ERROR_ACCESS_DENIED)
        start, end = st["pos"], st["pos"] + length
        for v in self.volumes.values():
            if v.disk == st["n"] and v.mounted and v.locked_by is None and start < v.end and v.start < end:
                return self._fail(win.ERROR_ACCESS_DENIED)  # Windows protects mounted volumes
        self.disks[st["n"]][start:end] = ctypes.string_at(address, length)
        count._obj.value = length
        st["pos"] = end
        self.log.append(("write", start, length))
        return 1

    def SetFilePointerEx(self, h, offset, new_pos, how):
        assert how == win.FILE_BEGIN and new_pos is None
        self.handles[h]["pos"] = offset
        return 1

    def FlushFileBuffers(self, h):
        self.log.append(("flush", h))
        return 1

    def DeviceIoControl(self, h, code, inbuf, insize, outbuf, outsize, returned, overlapped):
        st = self.handles[h]
        self.log.append(("ioctl", st.get("path") or st.get("n"), code))
        if code == FSCTL_LOCK_VOLUME:
            v = self.volumes[st["path"]]
            if v.busy > 0:
                v.busy -= 1
                return self._fail(win.ERROR_ACCESS_DENIED)
            if v.locked_by not in (None, h):
                return self._fail(win.ERROR_ACCESS_DENIED)
            v.locked_by = h
            return 1
        if code == FSCTL_DISMOUNT_VOLUME:
            v = self.volumes[st["path"]]
            v.forced = v.forced or v.locked_by is None
            v.mounted = False
            v.busy = 0 if v.busy < 1000 else v.busy  # a forced dismount closes the other programs' handles
            return 1
        if code == IOCTL_DISK_GET_LENGTH_INFO:
            assert outsize == 8
            outbuf._obj.value = len(self.disks[st["n"]])
            return 1
        if code == IOCTL_DISK_UPDATE_PROPERTIES:
            assert st["access"] & win.GENERIC_WRITE
            return 1
        if code == IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
            assert st["kind"] == "letter" and outsize == ctypes.sizeof(win.VOLUME_DISK_EXTENTS)
            disks = self.letters[st["letter"]]
            outbuf._obj.NumberOfDiskExtents = len(disks)
            for i, n in enumerate(disks):
                outbuf._obj.Extents[i].DiskNumber = n
                outbuf._obj.Extents[i].ExtentLength = 1 << 30
            return 1
        raise AssertionError(hex(code))

    def CloseHandle(self, h):
        st = self.handles.pop(h)
        if st["kind"] == "volume":
            v = self.volumes[st["path"]]
            if v.locked_by == h:
                v.locked_by = None
        self.log.append(("close", h))
        return 1

    def WaitForSingleObject(self, h, ms):
        assert h == 0x4242
        self.log.append(("wait", ms))
        return self.waits.pop(0)

    def GetExitCodeProcess(self, h, code):
        code._obj.value = self.exit_code
        return 1

    def TerminateProcess(self, h, code):
        self.terminated = True
        return 1

    # shell32 ----------------------------------------------------------------
    def ShellExecuteExW(self, psei):
        sei = psei._obj
        self.sei = {"cbSize": sei.cbSize, "fMask": sei.fMask, "verb": sei.lpVerb, "file": sei.lpFile,
                    "params": sei.lpParameters, "dir": sei.lpDirectory, "show": sei.nShow}
        if self.uac == "no":
            return self._fail(win.ERROR_CANCELLED)
        if self.uac == "missing":
            return self._fail(win.ERROR_FILE_NOT_FOUND)
        self.handles[0x4242] = {"kind": "process"}
        sei.hProcess = 0x4242
        return 1


@pytest.fixture
def ps():
    return FakePowerShell()


@pytest.fixture
def dll():
    return FakeWindll()


@pytest.fixture
def backend(ps, dll):
    b = WindowsBackend(api=Win32(dll), powershell=ps, sleep=lambda s: None)
    b.program_paths = [r"C:\Users\me\Downloads\beast-booter\python\python.exe"]
    return b


def small_stick(dll, size=8 * MIB) -> DiskInfo:
    """Disk 2 of the fixture machine, shrunk to 8 MiB so the stub can hold it."""
    dll.disks[2] = bytearray(size)
    dll.volumes[STICK_GUID] = Volume(2, MIB, size)
    return DiskInfo(id="\\\\.\\PhysicalDrive2", path="\\\\.\\PhysicalDrive2", model="SanDisk Ultra", size=size,
                    sector_size=512, bus="usb", removable=True, system=False, read_only=False)


# --------------------------------------------------------------------------- listing


def test_list_default_and_all(backend):
    assert [d.id for d in backend.list_disks()] == ["\\\\.\\PhysicalDrive2"]
    assert [d.extra["number"] for d in backend.list_disks(include_fixed=True)] == [0, 1, 2]


def test_usb_stick_fields(backend):
    (stick,) = backend.list_disks()
    assert stick == DiskInfo(
        id="\\\\.\\PhysicalDrive2", path="\\\\.\\PhysicalDrive2", model="SanDisk Ultra", size=30752636928,
        sector_size=512, bus="usb", removable=True, system=False, read_only=False, mountpoints=("E:\\",),
        partitions=("\\\\?\\GLOBALROOT\\Device\\Harddisk2\\Partition1",),
        extra={"number": 2, "bus_type": "USB", "is_boot": False, "is_system": False, "is_offline": False,
               "partition_style": "MBR", "serial": "4C530001090820116024",
               "volumes": [{"partition": 1, "letter": "E", "label": "STICK", "fs": "FAT32"}],
               "dynamic": False, "system_reason": None},
    )


def test_system_disks(backend):
    disks = {d.extra["number"]: d for d in backend.list_disks(include_fixed=True)}
    nvme, hdd = disks[0], disks[1]
    assert (nvme.system, nvme.bus, nvme.removable, nvme.mountpoints) == (True, "nvme", False, ("C:\\",))
    assert nvme.extra["system_reason"] == "holds the running Windows (boot volume)"
    assert len(nvme.partitions) == 4 and {v["fs"] for v in nvme.extra["volumes"]} == {"FAT32", "NTFS"}
    assert (hdd.system, hdd.bus) == (True, "sata")
    assert hdd.extra["system_reason"] == "holds a page file (D:\\pagefile.sys)"
    assert hdd.mountpoints == ("D:\\", "C:\\Archive\\")  # drive letter + folder mount point


def test_windows_directory_and_vhd_host(backend, ps):
    disks = json.loads(fixture("get-disk.json"))
    for d in disks:
        d["IsBoot"] = d["IsSystem"] = False
    disks.append({"Number": 3, "FriendlyName": "Msft Virtual Disk", "Size": 64 << 30, "LogicalSectorSize": 512,
                  "BusType": "File Backed Virtual", "IsBoot": True, "IsSystem": True, "IsReadOnly": False,
                  "IsOffline": False, "PartitionStyle": "GPT", "Location": "D:\\VHD\\win11.vhdx"})
    ps.list_output = listing(env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": True}).replace(
        fixture("get-disk.json"), json.dumps(disks))
    got = {d.extra["number"]: d for d in backend.list_disks(include_fixed=True)}
    assert got[0].extra["system_reason"] == "holds the Windows directory (C:)"
    assert got[1].extra["system_reason"] == "holds the virtual disk the running Windows uses (D:\\VHD\\win11.vhdx)"
    assert (got[3].bus, got[3].system) == ("virtual", True)
    assert not got[2].system


def test_single_object_json(backend, ps):
    ps.list_output = listing("get-disk-single.json", "get-partition-single.json", None,
                             env={"SystemRoot": "C:\\Windows", "PageFiles": ["C:\\pagefile.sys"],
                                  "PageFilesKnown": True})
    (d,) = backend.list_disks(include_fixed=True)
    assert (d.id, d.bus, d.system, d.mountpoints) == ("\\\\.\\PhysicalDrive0", "nvme", True, ("C:\\",))
    assert d.extra["bus_type"] == "NVMe" and d.extra["partition_style"] == "GPT"  # from 17 and 2
    assert backend.list_disks() == []


@pytest.mark.parametrize("text,expected", [
    ("", []),
    ("  \r\n", []),
    ("null", []),
    ('{"Number":  1}', [{"Number": 1}]),
    ('[{"Number":  1}, {"Number":  2}]', [{"Number": 1}, {"Number": 2}]),
    ('{"value": [{"Number": 1}], "Count": 1}', [{"Number": 1}]),  # Windows PowerShell 5.1 array wrapper
    ('\ufeff{"Number": 3}', [{"Number": 3}]),
])
def test_json_list(text, expected):
    assert json_list(text) == expected


def test_json_list_garbage():
    with pytest.raises(BeastError, match="could not parse PowerShell JSON"):
        json_list("Get-Disk : Access denied")


def test_missing_section_is_an_error(backend, ps):
    ps.list_output = "##BEAST:disks\r\n[]\r\n"
    with pytest.raises(BeastError, match="no partitions section"):
        backend.list_disks()


@pytest.mark.parametrize("text", ["2", " 2 ", "PhysicalDrive2", "physicaldrive2", "\\\\.\\PhysicalDrive2",
                                  "\\\\?\\PhysicalDrive2", "//./PhysicalDrive2", "\\\\.\\PHYSICALDRIVE2"])
def test_disk_number_forms(text):
    assert parse_disk_number(text) == 2


@pytest.mark.parametrize("text", ["E:", "/dev/sdb", "\\\\.\\2", "PhysicalDrive", "disk2", "-1", "2a"])
def test_disk_number_rejects(text):
    with pytest.raises(BeastError, match="is not a Windows disk"):
        parse_disk_number(text)


def test_get_disk(backend):
    assert backend.get_disk("2") == backend.get_disk("\\\\.\\PhysicalDrive2") == backend.list_disks()[0]
    with pytest.raises(BeastError, match="there is no disk 7"):
        backend.get_disk("7")


# --------------------------------------------------------------------------- system disks: extents, LDM, page files

LDM_METADATA = "{5808c8aa-7e8f-42e0-85d2-e1e90434cfb3}"
LDM_DATA = "{af9b60a0-1431-4f62-bc68-3311714a69ad}"


def edited_listing(ps, *, disks=None, parts=None, vols=None, env=None):
    """The fixture listing with edited copies of its JSON sections."""
    d = json.loads(fixture("get-disk.json")) if disks is None else disks
    p = json.loads(fixture("get-partition.json")) if parts is None else parts
    v = json.loads(fixture("get-volume.json")) if vols is None else vols
    e = json.loads(fixture("env.json")) if env is None else env
    ps.list_output = "\r\n".join(["##BEAST:disks", json.dumps(d), "##BEAST:partitions", json.dumps(p),
                                  "##BEAST:volumes", json.dumps(v), "##BEAST:env", json.dumps(e)]) + "\r\n"


def dynamic_mirror(ps, env=None):
    """C: and D: became dynamic volumes (C: mirrored onto disk 1): Get-Partition shows LDM
    partitions without drive letters, and only disk 0 carries IsBoot/IsSystem."""
    parts = [p for p in json.loads(fixture("get-partition.json")) if p["DiskNumber"] == 2]
    for n in (0, 1):
        parts += [{"DiskNumber": n, "PartitionNumber": 1, "DriveLetter": "\u0000", "Offset": 17408, "Size": 1 << 20,
                   "Type": "Unknown", "MbrType": None, "GptType": LDM_METADATA, "AccessPaths": None},
                  {"DiskNumber": n, "PartitionNumber": 2, "DriveLetter": "\u0000", "Offset": 2 << 20, "Size": 900 << 30,
                   "Type": "Unknown", "MbrType": None, "GptType": LDM_DATA, "AccessPaths": None}]
    disks = json.loads(fixture("get-disk.json"))
    disks[1]["IsBoot"] = disks[1]["IsSystem"] = False
    edited_listing(ps, disks=disks, parts=parts, env=env)


def test_dynamic_mirror_found_through_volume_extents(backend, ps, dll):
    dynamic_mirror(ps)
    dll.letters = {"C": [0, 1], "D": [1]}  # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS of \\.\C: and \\.\D:
    got = {d.extra["number"]: d for d in backend.list_disks(include_fixed=True)}
    assert got[1].system and got[1].extra["system_reason"] == "holds the Windows directory (C:)"
    assert got[1].extra["dynamic"] and got[0].extra["dynamic"] and not got[2].extra["dynamic"]
    assert not got[2].system
    assert ("open", "\\\\.\\C:", 0, 0) in dll.log  # queried with no access rights (works unelevated)
    with pytest.raises(BeastError, match="PhysicalDrive1 holds the Windows directory"):
        backend.check_safe(got[1], allow_fixed=True)


def test_windows_directory_not_mappable_marks_fixed_disks(backend, ps, dll):
    """Neither the extents (IOCTL refused) nor Get-Partition tell where C: is: every fixed
    disk is a system disk, external ones stay eligible."""
    dynamic_mirror(ps)
    got = {d.extra["number"]: d for d in backend.list_disks(include_fixed=True)}
    assert got[1].system and "disk holding Windows could not be identified" in got[1].extra["system_reason"]
    assert not got[2].system
    backend.check_safe(got[2], allow_fixed=False)


def test_dynamic_disk_refused(backend, ps, dll):
    """A dynamic disk that holds nothing of the running system is still refused: its
    volumes do not map to partitions, so prepare() could not lock them."""
    parts = json.loads(fixture("get-partition.json"))
    for p in parts:
        if p["DiskNumber"] == 1:
            p.update(DriveLetter="\u0000", AccessPaths=None, Type="Unknown", GptType=LDM_DATA)
    edited_listing(ps, parts=parts, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": True})
    hdd = backend.get_disk("1")
    assert hdd.extra["dynamic"] and not hdd.system
    with pytest.raises(BeastError, match=r"PhysicalDrive1 is a dynamic disk \(Logical Disk Manager\)"):
        backend.check_safe(hdd, allow_fixed=True)


def test_prepare_refuses_ldm_partition_on_disk(backend, dll):
    """Get-Partition shows nothing unusual, but the disk's MBR has an LDM (0x42) partition."""
    disk = small_stick(dll)
    write_mbr(dll.disks[2], [(0x42, 63, 8000)])
    with pytest.raises(BeastError, match="is a dynamic disk"):
        backend.prepare(disk)
    assert dll.volumes[STICK_GUID].locked_by is None and dll.handles == {}


def test_is_ldm_type():
    assert win.is_ldm_type(66, None) and win.is_ldm_type("0x42", None)
    assert win.is_ldm_type(None, LDM_DATA) and win.is_ldm_type(None, LDM_METADATA.upper().strip("{}"))
    assert not win.is_ldm_type(12, None) and not win.is_ldm_type(None, "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}")
    assert not win.is_ldm_type(None, None) and not win.is_ldm_type("0x07", "0x07")


def test_pagefile_on_usb_disk_with_ps51_wrapper(backend, ps):
    """Windows PowerShell 5.1 may print a nested array as {"value": [...], "Count": n}."""
    edited_listing(ps, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": {"value": ["E:\\pagefile.sys"], "Count": 1},
                            "PageFilesKnown": True})
    stick = backend.get_disk("2")
    assert stick.system and stick.extra["system_reason"] == "holds a page file (E:\\pagefile.sys)"
    assert backend.list_disks() == []


def test_pagefile_in_registry_format_and_on_dynamic_volume(backend, ps, dll):
    """D: is a dynamic volume on disk 1 (no drive letter in Get-Partition, no IsBoot): its
    page file, spelled as in the registry (\\??\\D:\\...), is found through the extents."""
    dynamic_mirror(ps, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": ["\\??\\D:\\pagefile.sys"],
                            "PageFilesKnown": True})
    dll.letters = {"C": [0], "D": [1]}
    hdd = backend.get_disk("1")
    assert not hdd.extra["is_boot"] and hdd.extra["system_reason"] == "holds a page file (D:\\pagefile.sys)"


def test_pagefiles_unknown_marks_disks_with_fixed_volumes(backend, ps):
    edited_listing(ps, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": False})
    got = {d.extra["number"]: d for d in backend.list_disks(include_fixed=True)}
    assert got[1].extra["system_reason"] == "may hold a page file (the page files could not be identified)"
    assert not got[2].system  # E: is a Removable volume: Windows never puts a page file there
    vols = json.loads(fixture("get-volume.json"))
    vols[-1]["DriveType"] = "Fixed"  # a USB SSD shows up as a Fixed volume
    edited_listing(ps, vols=vols, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": False})
    assert backend.get_disk("2").system
    edited_listing(ps, vols=vols, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": []})  # no marker: unknown too
    assert backend.get_disk("2").system


def test_pagefile_on_unmapped_volume_marks_disks_with_fixed_volumes(backend, ps):
    vols = json.loads(fixture("get-volume.json"))
    vols[-1]["DriveType"] = 3  # numeric DriveType (Fixed)
    edited_listing(ps, vols=vols, env={"SystemRoot": "C:\\WINDOWS", "PageFiles": ["F:\\pagefile.sys"],
                                       "PageFilesKnown": True})
    assert "may hold a page file" in backend.get_disk("2").extra["system_reason"]


def test_access_paths_ps51_wrapper(backend, ps):
    parts = json.loads(fixture("get-partition.json"))
    parts[-1]["AccessPaths"] = {"value": parts[-1]["AccessPaths"], "Count": 2}
    edited_listing(ps, parts=parts)
    stick = backend.get_disk("2")
    assert stick.mountpoints == ("E:\\",) and stick.extra["volumes"][0]["label"] == "STICK"


def test_volume_disks_struct_and_errors(dll):
    assert IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS == 0x00560000
    assert ctypes.sizeof(win.DISK_EXTENT) == 24 and win.DISK_EXTENT.StartingOffset.offset == 8
    assert win.VOLUME_DISK_EXTENTS.Extents.offset == 8
    api = Win32(dll)
    dll.letters = {"C": [0, 3]}
    assert api.volume_disks("\\\\.\\C:") == {0, 3}
    assert dll.handles == {}
    with pytest.raises(BeastError, match="Windows error 2"):
        api.volume_disks("\\\\.\\Q:")


# --------------------------------------------------------------------------- safety


def test_check_safe(backend):
    backend.check_safe(backend.get_disk("2"), allow_fixed=False)
    with pytest.raises(BeastError, match=r"PhysicalDrive0 holds the running Windows"):
        backend.check_safe(backend.get_disk("0"), allow_fixed=True)
    with pytest.raises(BeastError, match=r"PhysicalDrive1 holds a page file"):
        backend.check_safe(backend.get_disk("1"), allow_fixed=True)


def test_mounted_stick_is_not_refused(backend, dll):
    """A drive with a mounted volume (E:) is a valid target: prepare() dismounts it and
    says which mount points it took away."""
    disk = backend.get_disk("2")
    assert disk.mountpoints == ("E:\\",)
    backend.check_safe(disk, allow_fixed=False)
    assert backend.prepare(small_stick(dll)) == ["E:\\"]
    assert not dll.volumes[STICK_GUID].mounted


def test_check_safe_running_from_stick(backend):
    backend.program_paths = [r"E:\beast-booter\python\python.exe"]
    with pytest.raises(BeastError, match=r"running from \\\\.\\PhysicalDrive2 \(E:\\\)"):
        backend.check_safe(backend.get_disk("2"), allow_fixed=False)


def test_check_safe_fixed_and_read_only(backend, ps):
    disks = json.loads(fixture("get-disk.json"))
    disks[1]["BusType"] = "SATA"
    disks[2]["BusType"] = "SCSI"  # e.g. a UAS enclosure some drivers report as SCSI
    disks[2]["IsReadOnly"] = False
    ps.list_output = listing(env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": True}).replace(
        fixture("get-disk.json"), json.dumps(disks))
    with pytest.raises(BeastError, match="not a removable or external drive.*--allow-fixed-disk"):
        backend.check_safe(backend.get_disk("2"), allow_fixed=False)
    backend.check_safe(backend.get_disk("2"), allow_fixed=True)
    disks[2]["IsReadOnly"] = True
    ps.list_output = listing(env={"SystemRoot": "C:\\WINDOWS", "PageFiles": [], "PageFilesKnown": True}).replace(
        fixture("get-disk.json"), json.dumps(disks))
    with pytest.raises(BeastError, match="read-only"):
        backend.check_safe(backend.get_disk("2"), allow_fixed=True)


# --------------------------------------------------------------------------- prepare + raw I/O


def test_mounted_volume_blocks_writes_without_prepare(backend, dll):
    disk = small_stick(dll)
    with backend.open_raw(disk, writable=True) as t:
        t.write(0, b"\x55\xaa")  # the MBR is outside every volume: allowed
        with pytest.raises(BeastError, match=r"access denied \(Windows error 5\).*mounted volumes"):
            t.write(MIB + 3, b"data")


def test_prepare_locks_dismounts_and_keeps_handles_until_close(backend, dll):
    disk = small_stick(dll)
    backend.prepare(disk)
    vol = dll.volumes[STICK_GUID]
    opens = [e for e in dll.log if e[0] == "open" and "Volume{" in e[1]]
    assert opens == [("open", STICK_GUID, win.GENERIC_READ | win.GENERIC_WRITE, 0)]  # no trailing backslash
    codes = [e[2] for e in dll.log if e[0] == "ioctl" and e[1] == STICK_GUID]
    assert codes == [FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME]
    # Before locking, the disk's own partition table was read (read-only) to look for LDM partitions.
    assert ("open", "\\\\.\\PhysicalDrive2", win.GENERIC_READ,
            win.FILE_FLAG_NO_BUFFERING | win.FILE_FLAG_WRITE_THROUGH) in dll.log
    assert vol.locked_by is not None and not vol.mounted and not vol.forced

    t = backend.open_raw(disk, writable=True)
    assert dll.log[-2][:2] == ("open", "\\\\.\\PhysicalDrive2")
    assert dll.log[-2][3] == win.FILE_FLAG_NO_BUFFERING | win.FILE_FLAG_WRITE_THROUGH
    assert dll.log[-1] == ("ioctl", 2, IOCTL_DISK_GET_LENGTH_INFO)
    t.write(MIB + 3, b"beast")  # inside the (now locked) volume, unaligned: read-modify-write
    t.write(0, bytes(range(256)) * 2)
    t.flush()
    assert vol.locked_by is not None  # still held while the target is open
    t.close()
    assert vol.locked_by is None and dll.handles == {}  # volume handle closed with the target
    assert dll.disks[2][MIB:MIB + 8] == b"\0\0\0beast"
    assert dll.disks[2][:512] == bytes(range(256)) * 2
    writes = [e for e in dll.log if e[0] == "write"]
    assert writes == [("write", MIB, 512), ("write", 0, 512)]
    assert ("read", MIB, 512) in dll.log  # the partial block was read before being rewritten
    assert any(e[0] == "flush" for e in dll.log)


def test_lock_retries_then_succeeds(backend, dll):
    disk = small_stick(dll)
    dll.volumes[STICK_GUID].busy = 3
    sleeps = []
    backend._sleep = sleeps.append
    backend.prepare(disk)
    assert len(sleeps) == 3 and not dll.volumes[STICK_GUID].forced
    backend.release(disk)
    assert dll.handles == {}


def test_lock_busy_forces_dismount(backend, dll):
    disk = small_stick(dll)
    dll.volumes[STICK_GUID].busy = win.LOCK_ATTEMPTS  # every normal attempt fails
    backend.prepare(disk)
    v = dll.volumes[STICK_GUID]
    assert v.forced and v.locked_by is not None and not v.mounted


def test_lock_impossible_raises_and_closes(backend, dll):
    disk = small_stick(dll)
    dll.volumes[STICK_GUID].busy = 10**6  # even a forced dismount does not help
    with pytest.raises(BeastError, match=r"cannot lock volume E:\\; close the programs") as e:
        backend.prepare(disk)
    assert e.value.code == "busy" and dll.handles == {}


def test_prepare_refuses_system_disk(backend, dll):
    disk = DiskInfo(id="\\\\.\\PhysicalDrive0", path="\\\\.\\PhysicalDrive0", model="x", size=MIB, sector_size=512,
                    bus="nvme", removable=False, system=True, read_only=False)
    with pytest.raises(BeastError, match="holds the running Windows"):
        backend.prepare(disk)
    assert [e for e in dll.log if e[0] == "open" and not e[1].endswith(":")] == []  # no disk or volume opened
    assert not [e for e in dll.log if e[0] == "ioctl" and e[2] in (FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME)]


def test_open_raw_errors(backend, dll):
    disk = small_stick(dll)
    wrong = DiskInfo(**{**disk.__dict__, "size": disk.size + 512})
    with pytest.raises(BeastError, match="size changed"):
        backend.open_raw(wrong, writable=False)
    assert dll.handles == {}
    dll.admin = False
    with pytest.raises(BeastError, match=r"cannot open \\\\.\\PhysicalDrive2: access denied.*administrator"):
        backend.open_raw(disk, writable=True)
    missing = DiskInfo(**{**disk.__dict__, "id": "\\\\.\\PhysicalDrive9", "path": "\\\\.\\PhysicalDrive9"})
    with pytest.raises(BeastError, match="Windows error 2"):
        backend.open_raw(missing, writable=False)


def test_read_only_target_cannot_write(backend, dll):
    disk = small_stick(dll)
    with backend.open_raw(disk, writable=False) as t:
        assert t.read(5, 3) == b"\0\0\0"
        with pytest.raises(AssertionError, match="read-only"):
            t.write(0, b"x")


# --------------------------------------------------------------------------- rescan / partitions / NTFS


def write_mbr(buf: bytearray, parts):
    for i, (ptype, start, count) in enumerate(parts):
        struct.pack_into("<B3xB3xII", buf, 0x1BE + 16 * i, 0, ptype, start, count)
    buf[510:512] = b"\x55\xaa"


def test_rescan(backend, dll, ps):
    disk = small_stick(dll)
    write_mbr(dll.disks[2], [(0x07, 2048, 10240), (0xEF, 12288, 2048)])
    backend.prepare(disk)
    ps.partition_answers = [[{"PartitionNumber": 1, "Size": 7340032}],  # old layout, single object
                            [{"PartitionNumber": 1, "Size": 10240 * 512}, {"PartitionNumber": 2, "Size": MIB}]]
    backend.rescan(disk)
    assert dll.volumes[STICK_GUID].locked_by is None  # rescan releases what prepare() still held
    assert ("ioctl", 2, IOCTL_DISK_UPDATE_PROPERTIES) in dll.log
    scripts = [s for s, _ in ps.scripts if "Get-Partition -DiskNumber 2" in s]
    assert len(scripts) == 2 and "Update-HostStorageCache" in scripts[0]
    assert dll.handles == {}


def test_rescan_timeout(backend, dll, ps):
    disk = small_stick(dll)
    write_mbr(dll.disks[2], [(0x07, 2048, 10240), (0xEF, 12288, 2048)])
    ps.partition_answers = [[]]
    with pytest.raises(BeastError, match="did not pick up the new partition table.*0 of 2"):
        backend.rescan(disk, timeout=0)


def test_partition_path(backend):
    disk = backend.get_disk("2")
    assert backend.partition_path(disk, 1) == "\\\\?\\GLOBALROOT\\Device\\Harddisk2\\Partition1"


def test_format_ntfs_script(backend, ps):
    disk = backend.get_disk("2")
    backend.format_ntfs(disk, 1, "BEASTBOOTER")
    script, what = ps.scripts[-1]
    assert "Get-Partition -DiskNumber 2 -PartitionNumber 1" in script
    assert "Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel 'BEASTBOOTER' -Force -Confirm:$false" \
        in script
    ps.ntfs_answer = json.dumps({"FileSystem": "RAW"})
    with pytest.raises(BeastError, match="did not create NTFS"):
        backend.format_ntfs(disk, 1, "BEASTBOOTER")


@pytest.mark.parametrize("text,expected", [
    ("BEASTBOOTER", "'BEASTBOOTER'"),
    ("it's", "'it''s'"),
    ("\u2018smart\u2019 \u201alow\u201b", "'\u2018\u2018smart\u2019\u2019 \u201a\u201alow\u201b\u201b'"),
    ("$(Remove-Item C:\\) `n \"x\"", "'$(Remove-Item C:\\) `n \"x\"'"),  # literal inside single quotes
    ("", "''"),
])
def test_ps_quote(text, expected):
    assert ps_quote(text) == expected


def test_powershell_argv_encodes_script():
    argv = win.powershell_argv("Get-Disk | ConvertTo-Json")
    assert argv[1:6] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]
    assert argv[0].lower().endswith("powershell.exe")
    script = base64.b64decode(argv[6]).decode("utf-16-le")
    assert script.startswith(win.PS_PREAMBLE)
    assert "$ErrorActionPreference = 'Stop'" in script and "Get-Disk | ConvertTo-Json" in script
    assert "[Console]::Error.WriteLine($_.Exception.Message)" in script and "exit 1" in script


def test_run_powershell(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, 0, "\ufeff##BEAST:disks\r\n[]\r\n".encode("utf-8"), b"")

    monkeypatch.setattr(win.subprocess, "run", fake_run)
    assert win.run_powershell("Get-Disk").startswith("##BEAST:disks")
    assert seen["creationflags"] == 0 and seen["stdin"] == subprocess.DEVNULL  # CREATE_NO_WINDOW only on Windows

    def failing(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, b"", b"Access denied.\r\n")

    monkeypatch.setattr(win.subprocess, "run", failing)
    with pytest.raises(BeastError, match="listing failed: Access denied."):
        win.run_powershell("Get-Disk", "listing")


def test_run_powershell_error_prefers_stderr(monkeypatch):
    """A script that printed a section before failing: the message is the error, not the JSON."""
    out = b"##BEAST:disks\r\n[\r\n    {\r\n        \"Number\":  0\r\n    }\r\n]\r\n##BEAST:partitions\r\n"
    monkeypatch.setattr(win.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 1, out, b"Get-Partition : Access denied\r\n"))
    with pytest.raises(BeastError, match=r"^listing failed: Get-Partition : Access denied$"):
        win.run_powershell("x", "listing")
    monkeypatch.setattr(win.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 1, b"only on stdout\r\n", b""))
    with pytest.raises(BeastError, match="listing failed: only on stdout"):
        win.run_powershell("x", "listing")
    monkeypatch.setattr(win.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 3, b"", b""))
    with pytest.raises(BeastError, match="listing failed: exit 3"):
        win.run_powershell("x", "listing")


def test_format_ntfs_ignores_stray_output(backend, ps):
    disk = backend.get_disk("2")
    backend._ps = lambda script, what: "WARNING: The volume was mounted\r\n" + ps(script, what)
    backend.format_ntfs(disk, 1, "BEASTBOOTER")  # the warning line is outside the result section
    assert "Write-Output '##BEAST:result'" in WindowsBackend.ntfs_script(2, 1, "X")


def test_close_refreshes_layout_before_releasing_locks(backend, dll):
    disk = small_stick(dll)
    backend.prepare(disk)
    vol_handle = dll.volumes[STICK_GUID].locked_by
    with backend.open_raw(disk, writable=True) as t:
        t.write(0, b"\x55\xaa")
    assert t.layout_refreshed
    refresh = dll.log.index(("ioctl", 2, IOCTL_DISK_UPDATE_PROPERTIES))
    unlock = dll.log.index(("close", vol_handle))
    assert refresh < unlock  # the partition manager re-read the table while the volume was locked
    assert dll.volumes[STICK_GUID].locked_by is None and dll.handles == {}


def test_close_without_writes_does_not_refresh(backend, dll):
    disk = small_stick(dll)
    with backend.open_raw(disk, writable=True) as t:
        t.read(0, 512)
    with backend.open_raw(disk, writable=False) as r:
        r.read(0, 512)
    assert not t.layout_refreshed and ("ioctl", 2, IOCTL_DISK_UPDATE_PROPERTIES) not in dll.log


def test_list_script_shape():
    for cmdlet in ("Get-Disk", "Get-Partition", "Get-Volume", "Win32_PageFileUsage"):
        assert cmdlet in win.LIST_SCRIPT
    assert win.LIST_SCRIPT.count("ConvertTo-Json -Depth 4") == 4
    for name in ("disks", "partitions", "volumes", "env"):
        assert f"'##BEAST:{name}'" in win.LIST_SCRIPT


# --------------------------------------------------------------------------- elevation


def parse_windows_args(s: str) -> list[str]:
    """Argument parsing of the Microsoft C runtime (what python.exe does with its command line)."""
    args, i, n = [], 0, len(s)
    while True:
        while i < n and s[i] in " \t":
            i += 1
        if i >= n:
            return args
        arg, quoted = [], False
        while i < n:
            c = s[i]
            if c == "\\":
                j = i
                while j < n and s[j] == "\\":
                    j += 1
                count = j - i
                if j < n and s[j] == '"':
                    arg.append("\\" * (count // 2))
                    if count % 2:
                        arg.append('"')
                        j += 1
                    i = j
                else:
                    arg.append("\\" * count)
                    i = j
            elif c == '"':
                if quoted and i + 1 < n and s[i + 1] == '"':
                    arg.append('"')
                    i += 2
                else:
                    quoted = not quoted
                    i += 1
            elif c in " \t" and not quoted:
                break
            else:
                arg.append(c)
                i += 1
        args.append("".join(arg))


WIN_NASTY = [
    "C:\\Users\\Zoë O'Brien\\Downloads\\beast-booter 0.1\\app\\beast_booter_launch.py",
    "install", "--device", "\\\\.\\PhysicalDrive2",
    "--progress-file", "C:\\Users\\Zoë O'Brien\\AppData\\Local\\Temp\\bb progress.jsonl",
    "trailing\\", "C:\\Program Files\\x\\", 'q"uote', 'say "hi" ', "", " ", "\t", "a\\\\\"b", "\\\\server\\share",
    "%PATH%", "^&|<>()", "ünïcødé ✓",
]


def test_run_elevated_shell_execute(backend, dll, monkeypatch):
    monkeypatch.setattr(win.os, "getcwd", lambda: "C:\\Users\\me")
    exe = "C:\\Users\\Zoë O'Brien\\Downloads\\beast-booter 0.1\\python\\python.exe"
    dll.waits = [win.WAIT_TIMEOUT, win.WAIT_TIMEOUT, win.WAIT_OBJECT_0]
    dll.exit_code = 0
    p = backend.run_elevated([exe, *WIN_NASTY])
    s = dll.sei
    assert (s["verb"], s["file"], s["dir"], s["show"]) == ("runas", exe, "C:\\Users\\me", win.SW_HIDE)
    assert s["fMask"] & win.SEE_MASK_NOCLOSEPROCESS and s["cbSize"] == ctypes.sizeof(win.SHELLEXECUTEINFOW)
    assert s["params"] == subprocess.list2cmdline(WIN_NASTY)
    assert parse_windows_args(s["params"]) == WIN_NASTY  # python.exe gets exactly our argv
    assert p.poll() is None
    with pytest.raises(TimeoutError):
        p.wait(0.5)
    assert p.wait() == 0 and p.poll() == 0
    assert [e for e in dll.log if e[0] == "wait"] == [("wait", 0), ("wait", 500), ("wait", win.INFINITE)]
    assert ("close", 0x4242) in dll.log


def test_run_elevated_declined_and_errors(backend, dll):
    dll.uac = "no"
    p = backend.run_elevated(["C:\\python\\python.exe", "-V"])
    assert p.poll() == ELEVATION_CANCELLED and p.wait(1) == ELEVATION_CANCELLED
    p.cancel()  # nothing to cancel
    dll.uac = "missing"
    with pytest.raises(BeastError, match="cannot start C:.*as administrator.*Windows error 2"):
        backend.run_elevated(["C:\\python\\python.exe", "-V"])
    with pytest.raises(ValueError):
        backend.run_elevated([])


def test_cancel_terminates(backend, dll):
    dll.waits = [win.WAIT_TIMEOUT, win.WAIT_OBJECT_0]
    dll.exit_code = 1
    p = backend.run_elevated(["C:\\python\\python.exe"])
    assert p.poll() is None
    p.cancel()
    assert dll.terminated and p.wait() == 1


def test_is_elevated(backend, dll):
    assert backend.is_elevated()
    dll.admin = False
    assert not backend.is_elevated()


# --------------------------------------------------------------------------- ctypes declarations


def test_ctl_codes_match_winioctl():
    assert FSCTL_LOCK_VOLUME == 0x00090018
    assert FSCTL_DISMOUNT_VOLUME == 0x00090020
    assert IOCTL_DISK_GET_LENGTH_INFO == 0x0007405C
    assert IOCTL_DISK_UPDATE_PROPERTIES == 0x00070140


def test_shellexecuteinfo_layout():
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(win.SHELLEXECUTEINFOW) == 112  # sizeof(SHELLEXECUTEINFOW) on x64
        assert win.SHELLEXECUTEINFOW.hProcess.offset == 104


def test_declarations_set_on_dll(dll):
    Win32(dll)
    assert dll.kernel32.CreateFileW.restype is win.HANDLE  # a HANDLE must not be truncated to a C int
    assert dll.kernel32.SetFilePointerEx.argtypes[1] is win.LARGE_INTEGER
    assert dll.kernel32.DeviceIoControl.argtypes[1] is win.DWORD
    assert dll.shell32.ShellExecuteExW.argtypes[0]._type_ is win.SHELLEXECUTEINFOW


def test_no_windows_api_on_linux():
    if hasattr(ctypes, "WinDLL"):
        pytest.skip("running on Windows")
    b = WindowsBackend()
    with pytest.raises(BeastError, match="only available on Windows"):
        b.is_elevated()


def test_check_safe_refuses_swapped_drive(backend):
    selected = backend.get_disk("2")
    other = DiskInfo(**{**selected.__dict__, "size": 16008609792, "model": "Kingston DataTraveler 3.0"})
    with pytest.raises(BeastError, match=r"PhysicalDrive2 changed since it was selected \(was Kingston"):
        backend.check_safe(other, allow_fixed=False)


# --------------------------------------------------------------------------- with real PowerShell (pwsh)
# PowerShell 7 on Linux has no Storage module (no Get-Disk), but it checks the
# scripts' syntax and runs the real -EncodedCommand / ConvertTo-Json / quoting
# path. Windows PowerShell 5.1 (what the backend uses on Windows) formats JSON
# slightly differently; the fixtures above cover that.


def find_pwsh() -> str | None:
    import glob
    import os
    import shutil

    if os.environ.get("BB_PWSH"):
        return os.environ["BB_PWSH"]
    repo = Path(__file__).resolve().parents[2]
    found = sorted(glob.glob(str(repo / ".tools" / "platforms" / "pwsh-*" / "pwsh")))
    return found[-1] if found else shutil.which("pwsh")


PWSH = find_pwsh()
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="PowerShell (pwsh) not found; see .tools/platforms")


@pytest.fixture
def with_pwsh(monkeypatch):
    monkeypatch.setattr(win, "powershell_exe", lambda: PWSH)


def parse_errors(tmp_path: Path, script: str) -> list[str]:
    target = tmp_path / "script.ps1"
    target.write_text(script, encoding="utf-8")
    checker = tmp_path / "check.ps1"
    checker.write_text(
        "param($Path)\n$errors = $null\n"
        "[void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)\n"
        "foreach ($e in $errors) { Write-Output $e.ToString() }\n", encoding="utf-8")
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(checker), str(target)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return [line for line in proc.stdout.splitlines() if line.strip()]


@needs_pwsh
def test_pwsh_scripts_parse(tmp_path):
    scripts = {
        "list": win.LIST_SCRIPT,
        "partitions": WindowsBackend.partitions_script(2),
        "ntfs": WindowsBackend.ntfs_script(2, 1, "BEAST BOOTER"),
    }
    for name, script in scripts.items():
        body = base64.b64decode(win.powershell_argv(script)[-1]).decode("utf-16-le")
        assert parse_errors(tmp_path, body) == [], name


@needs_pwsh
def test_pwsh_sections_and_single_object_json(with_pwsh):
    out = win.run_powershell(
        "Write-Output '##BEAST:one'\n"
        "[pscustomobject]@{ Number = 1; DriveLetter = [char]0; Letter = [char]'E' } | ConvertTo-Json -Depth 4\n"
        "Write-Output '##BEAST:many'\n"
        "1..3 | ForEach-Object { [pscustomobject]@{ Number = $_ } } | ConvertTo-Json -Depth 4\n"
        "Write-Output '##BEAST:none'\n"
        "@() | ConvertTo-Json -Depth 4\n"
        "Write-Output '##BEAST:text'\n"
        "[pscustomobject]@{ Name = 'Zoë ✓' } | ConvertTo-Json -Depth 4\n")
    sec = win.split_sections(out)
    (one,) = json_list(sec["one"])
    assert one["Number"] == 1 and win._letter(one["DriveLetter"]) is None and win._letter(one["Letter"]) == "E"
    assert [d["Number"] for d in json_list(sec["many"])] == [1, 2, 3]
    assert json_list(sec["none"]) == []
    assert json_list(sec["text"]) == [{"Name": "Zoë ✓"}]  # UTF-8 output encoding


@needs_pwsh
def test_pwsh_errors_become_beast_errors(with_pwsh):
    with pytest.raises(BeastError, match="listing disks failed: Access to the disk was denied"):
        win.run_powershell("throw 'Access to the disk was denied'", "listing disks")


@needs_pwsh
@pytest.mark.parametrize("text", ["BEASTBOOTER", "it's", "\u2018smart\u2019 \u201alow\u201b", "$(Get-Date) `n $env:PATH",
                                  'say "hi"', "back\\slash\\", "multi\nline", "", "Zoë ✓"])
def test_pwsh_ps_quote_roundtrip(with_pwsh, text):
    out = win.run_powershell(f"$s = {ps_quote(text)}\n"
                             "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)))")
    assert base64.b64decode(out.strip()).decode("utf-8") == text


STUB_CMDLETS = r"""
$env:SystemRoot = 'C:\WINDOWS'
function Get-Disk {
    [pscustomobject]@{ Number = [uint32]2; FriendlyName = 'SanDisk Ultra'; Model = 'Ultra'; SerialNumber = '4C53';
        Size = [uint64]30752636928; LogicalSectorSize = [uint32]512; PhysicalSectorSize = [uint32]512;
        BusType = 'USB'; IsBoot = $false; IsSystem = $false; IsReadOnly = $false; IsOffline = $false;
        PartitionStyle = 'MBR'; Location = 'Integrated : Bus 0 : Device 20'; Path = '\\?\usbstor#disk&ven_sandisk';
        NotSelected = 'dropped by Select-Object' }
}
function Get-Partition {
    [pscustomobject]@{ DiskNumber = [uint32]2; PartitionNumber = [uint32]1; DriveLetter = [char]'E';
        Offset = [uint64]1048576; Size = [uint64]30751588352; Type = 'FAT32 XINT13'; IsBoot = $false;
        IsSystem = $false; AccessPaths = [string[]]@('E:\', '\\?\Volume{d1c2b3a4-9e8f-11ef-a5b6-c7d8e9f0a1b2}\') }
}
function Get-Volume {
    [pscustomobject]@{ DriveLetter = [char]'E'; FileSystemLabel = 'STICK'; FileSystem = 'FAT32';
        DriveType = 'Removable'; Path = '\\?\Volume{d1c2b3a4-9e8f-11ef-a5b6-c7d8e9f0a1b2}\';
        Size = [uint64]30735056896 }
}
function Get-CimInstance { param($ClassName) [pscustomobject]@{ Name = 'C:\pagefile.sys' } }
"""


@needs_pwsh
def test_pwsh_list_script_end_to_end(with_pwsh):
    """LIST_SCRIPT through real PowerShell, with stub cmdlets that return one disk, one partition
    and one volume: exercises Select-Object -Property, single-object JSON and the env section."""
    b = WindowsBackend(powershell=lambda script, what: win.run_powershell(STUB_CMDLETS + script, what))
    (d,) = b.list_disks()
    assert (d.id, d.model, d.size, d.bus, d.removable, d.mountpoints) == \
        ("\\\\.\\PhysicalDrive2", "SanDisk Ultra", 30752636928, "usb", True, ("E:\\",))
    assert d.extra["volumes"] == [{"partition": 1, "letter": "E", "label": "STICK", "fs": "FAT32"}]
    assert d.partitions == ("\\\\?\\GLOBALROOT\\Device\\Harddisk2\\Partition1",)
    snap = b._snapshot()
    assert snap.env == {"SystemRoot": "C:\\WINDOWS", "PageFiles": ["C:\\pagefile.sys"], "PageFilesKnown": True}
    assert "NotSelected" not in snap.disks[0]
    assert WindowsBackend.volume_paths(snap, 2) == ["\\\\?\\Volume{d1c2b3a4-9e8f-11ef-a5b6-c7d8e9f0a1b2}"]


@needs_pwsh
def test_pwsh_error_after_output_reports_the_error(with_pwsh):
    """The reviewer's case: a section was printed, then Get-Partition failed."""
    with pytest.raises(BeastError, match=r"listing disks \(Get-Disk\) failed: Get-Partition : Access denied"):
        win.run_powershell("Write-Output '##BEAST:disks'\n"
                           "@([pscustomobject]@{ Number = 1 }) | ConvertTo-Json -Depth 4\n"
                           "Write-Output '##BEAST:partitions'\n"
                           "throw 'Get-Partition : Access denied (the real error)'\n", "listing disks (Get-Disk)")


PAGEFILE_STUBS = {
    "cim": "function Get-CimInstance { param($ClassName) [pscustomobject]@{ Name = 'C:\\pagefile.sys' } }\n",
    "cim-fails": "function Get-CimInstance { param($ClassName) throw 'WMI repository is broken' }\n",
    "registry": ("function Get-ItemProperty { param($Path, $Name)\n"
                 "    $key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management'\n"
                 "    if ($Path -ne $key -or $Name -ne 'ExistingPageFiles') { throw 'wrong key' }\n"
                 "    $files = [string[]]@('\\??\\C:\\pagefile.sys', '\\??\\D:\\swapfile.sys')\n"
                 "    [pscustomobject]@{ ExistingPageFiles = $files } }\n"),
    "registry-fails": "function Get-ItemProperty { param($Path, $Name) throw 'access denied' }\n",
}


@needs_pwsh
@pytest.mark.parametrize("stubs,expected", [
    (("cim",), {"PageFiles": ["C:\\pagefile.sys"], "PageFilesKnown": True}),
    (("cim-fails", "registry"), {"PageFiles": ["C:\\pagefile.sys", "D:\\swapfile.sys"], "PageFilesKnown": True}),
    (("cim-fails", "registry-fails"), {"PageFiles": [], "PageFilesKnown": False}),
])
def test_pwsh_pagefile_sources(with_pwsh, stubs, expected):
    env_part = win.LIST_SCRIPT[win.LIST_SCRIPT.index("Write-Output '##BEAST:env'"):]
    out = win.run_powershell("$env:SystemRoot = 'C:\\WINDOWS'\n" + "".join(PAGEFILE_STUBS[k] for k in stubs) + env_part)
    (env,) = json_list(win.split_sections(out)["env"])
    assert env == {"SystemRoot": "C:\\WINDOWS", **expected}
