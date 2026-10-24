"""Windows backend: PowerShell storage cmdlets for listing, Win32 API (ctypes) for I/O.

Listing
  One PowerShell run (-NoProfile -NonInteractive, script passed as
  -EncodedCommand so no quoting can go wrong) prints Get-Disk, Get-Partition and
  Get-Volume as JSON, plus the Windows directory and page files. ConvertTo-Json
  prints a single object (not an array) when there is one item and nothing when
  there are none; json_list() normalizes all of that.

System disk
  IsBoot (holds the running Windows) or IsSystem (holds the boot manager / ESP),
  or a disk under the volume of the Windows directory or of a page file, or
  the host disk of a virtual disk (VHD) that is itself a system disk. Volumes
  are mapped to disks with IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS on \\\\.\\X:
  (this also covers spanned / mirrored dynamic volumes, which have no drive
  letter in Get-Partition), plus the drive letters Get-Partition shows. When
  the Windows directory cannot be mapped, every fixed disk counts as a system
  disk; when the page files cannot be read or mapped, every disk with a
  lettered fixed volume does. Dynamic disks (Logical Disk Manager) are refused:
  their volumes cannot be locked through their partitions.

Raw I/O (Win32 API through ctypes)
  prepare(): every volume on the disk is opened (\\\\?\\Volume{GUID} or \\\\.\\X:)
  and locked (FSCTL_LOCK_VOLUME, retried; if programs keep files open the
  volume is force-dismounted first, like `format /X`) and dismounted
  (FSCTL_DISMOUNT_VOLUME). The handles stay open, keeping the locks, until the
  writable raw target is closed: Windows refuses writes inside a mounted
  volume, and must not remount the old filesystems while we write.
  open_raw(): CreateFileW(\\\\.\\PhysicalDriveN, GENERIC_READ|GENERIC_WRITE,
  FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING,
  FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH). Unbuffered I/O must be
  sector aligned in offset, length and buffer address: AlignedTarget does the
  read-modify-write, and a page-aligned ctypes buffer is used for every
  SetFilePointerEx + ReadFile/WriteFile. flush() = FlushFileBuffers.
  close() of a written target sends IOCTL_DISK_UPDATE_PROPERTIES (the
  partition manager drops its cached table and re-enumerates) while the volume
  locks are still held, and only then releases them, so Windows never sees the
  old volumes unlocked over the new filesystems. rescan() sends it again (in
  case the table was written some other way) and waits until Get-Partition
  shows the partitions now on the disk.

NTFS: PowerShell Format-Volume on the partition object (Get-Partition -DiskNumber
N -PartitionNumber 1), so no drive letter is needed.

Elevation: ShellExecuteExW, verb "runas" (the UAC prompt), SEE_MASK_NOCLOSEPROCESS
to get a process handle (WaitForSingleObject / GetExitCodeProcess /
TerminateProcess), arguments quoted with subprocess.list2cmdline (the MS C
runtime rules python.exe parses), window hidden (SW_HIDE). Declining the UAC
prompt gives exit code ELEVATION_CANCELLED (126).

Nothing here touches ctypes.WinDLL until a Windows API call is made, so this
module imports on Linux and the tests drive it with a stub windll.
"""

from __future__ import annotations

import base64
import ctypes
import json
import ntpath
import os
import re
import subprocess
import time
from types import SimpleNamespace

from ..blockio import AlignedTarget
from ..disk import read_partition_table
from ..errors import BeastError
from ..interfaces import DiskInfo
from .common import ELEVATION_CANCELLED, check_common, check_same_drive

# ---------------------------------------------------------------------------
# Win32 constants and types (ctypes.wintypes is avoided: it does not import on
# every non-Windows Python, and these few are clearer spelled out)
# ---------------------------------------------------------------------------

DWORD = ctypes.c_uint32
ULONG = ctypes.c_uint32
UINT = ctypes.c_uint
BOOL = ctypes.c_int
HANDLE = ctypes.c_void_p
LPVOID = ctypes.c_void_p
LPCWSTR = ctypes.c_wchar_p
LARGE_INTEGER = ctypes.c_int64

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_BEGIN = 0
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 0x102
SEE_MASK_NOCLOSEPROCESS = 0x40
SEE_MASK_NOASYNC = 0x100
SW_HIDE = 0
CREATE_NO_WINDOW = 0x08000000

ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_WRITE_PROTECT = 19
ERROR_NOT_READY = 21
ERROR_SHARING_VIOLATION = 32
ERROR_CANCELLED = 1223
_ERROR_TEXT = {
    ERROR_FILE_NOT_FOUND: "not found",
    ERROR_ACCESS_DENIED: "access denied",
    ERROR_WRITE_PROTECT: "the media is write protected",
    ERROR_NOT_READY: "the device is not ready",
    ERROR_SHARING_VIOLATION: "in use by another process",
    ERROR_CANCELLED: "cancelled by the user",
}


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    """CTL_CODE macro from winioctl.h."""
    return (device_type << 16) | (access << 14) | (function << 2) | method


FILE_DEVICE_DISK = 0x07
FILE_DEVICE_FILE_SYSTEM = 0x09
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FSCTL_LOCK_VOLUME = ctl_code(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)  # 0x00090018
FSCTL_DISMOUNT_VOLUME = ctl_code(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)  # 0x00090020
IOCTL_DISK_GET_LENGTH_INFO = ctl_code(FILE_DEVICE_DISK, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS)  # 0x0007405C
IOCTL_DISK_UPDATE_PROPERTIES = ctl_code(FILE_DEVICE_DISK, 0x50, METHOD_BUFFERED, FILE_ANY_ACCESS)  # 0x00070140
IOCTL_VOLUME_BASE = 0x56  # 'V'
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = ctl_code(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)  # 0x00560000

# Partition types of dynamic disks (Logical Disk Manager): MBR 0x42, GPT LDM metadata / data.
LDM_MBR_TYPE = 0x42
LDM_GPT_TYPES = frozenset({"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", "AF9B60A0-1431-4F62-BC68-3311714A69AD"})

LOCK_ATTEMPTS = 20
LOCK_RETRY_DELAY = 0.25  # seconds
RESCAN_TIMEOUT = 20.0


class DISK_EXTENT(ctypes.Structure):
    _fields_ = [("DiskNumber", DWORD), ("StartingOffset", LARGE_INTEGER), ("ExtentLength", LARGE_INTEGER)]


MAX_EXTENTS = 32  # a volume spanning more disks than this is not worth supporting


class VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [("NumberOfDiskExtents", DWORD), ("Extents", DISK_EXTENT * MAX_EXTENTS)]


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("fMask", ULONG),
        ("hwnd", HANDLE),
        ("lpVerb", LPCWSTR),
        ("lpFile", LPCWSTR),
        ("lpParameters", LPCWSTR),
        ("lpDirectory", LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", HANDLE),
        ("lpIDList", LPVOID),
        ("lpClass", LPCWSTR),
        ("hkeyClass", HANDLE),
        ("dwHotKey", DWORD),
        ("hIconOrMonitor", HANDLE),
        ("hProcess", HANDLE),
    ]


def _declare(k32, sh32) -> None:
    """argtypes/restype for every function we call (HANDLE must not be truncated to int)."""

    def sig(fn, restype, *argtypes):
        fn.restype = restype
        fn.argtypes = list(argtypes)

    P = ctypes.POINTER
    sig(k32.CreateFileW, HANDLE, LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)
    sig(k32.ReadFile, BOOL, HANDLE, LPVOID, DWORD, P(DWORD), LPVOID)
    sig(k32.WriteFile, BOOL, HANDLE, LPVOID, DWORD, P(DWORD), LPVOID)
    sig(k32.SetFilePointerEx, BOOL, HANDLE, LARGE_INTEGER, P(LARGE_INTEGER), DWORD)
    sig(k32.FlushFileBuffers, BOOL, HANDLE)
    sig(k32.DeviceIoControl, BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, P(DWORD), LPVOID)
    sig(k32.CloseHandle, BOOL, HANDLE)
    sig(k32.WaitForSingleObject, DWORD, HANDLE, DWORD)
    sig(k32.GetExitCodeProcess, BOOL, HANDLE, P(DWORD))
    sig(k32.TerminateProcess, BOOL, HANDLE, UINT)
    sig(sh32.IsUserAnAdmin, BOOL)
    sig(sh32.ShellExecuteExW, BOOL, P(SHELLEXECUTEINFOW))


def _load_windll():
    """kernel32 + shell32 with use_last_error (only possible on Windows)."""
    if not hasattr(ctypes, "WinDLL"):
        raise BeastError("the Windows API is only available on Windows")
    return SimpleNamespace(
        kernel32=ctypes.WinDLL("kernel32", use_last_error=True),
        shell32=ctypes.WinDLL("shell32", use_last_error=True),
        get_last_error=ctypes.get_last_error,
    )


def _error_text(code: int) -> str:
    fmt = getattr(ctypes, "FormatError", None)
    if fmt is not None:
        try:
            return fmt(code).strip()
        except Exception:  # pragma: no cover - FormatError failing is not worth more
            pass
    return _ERROR_TEXT.get(code, "error")


class Win32:
    """The kernel32/shell32 calls this backend makes, failures turned into BeastError."""

    def __init__(self, windll=None):
        windll = windll or _load_windll()
        self.k32 = windll.kernel32
        self.sh32 = windll.shell32
        self._get_last_error = getattr(windll, "get_last_error", None) or ctypes.get_last_error
        _declare(self.k32, self.sh32)

    def last_error(self) -> int:
        return int(self._get_last_error())

    def fail(self, what: str, code: int | None = None) -> BeastError:
        code = self.last_error() if code is None else code
        hint = ""
        if code == ERROR_ACCESS_DENIED:
            hint = " (run beast-booter as administrator; Windows also refuses writes into mounted volumes)"
        elif code == ERROR_SHARING_VIOLATION:
            hint = " (close the programs using the drive)"
        return BeastError(f"{what}: {_error_text(code)} (Windows error {code}){hint}")

    def open(self, path: str, access: int, flags: int = 0) -> int:
        h = self.k32.CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, flags, None)
        if h is None or h == INVALID_HANDLE_VALUE:
            raise self.fail(f"cannot open {path}")
        return h

    def close(self, h: int) -> None:
        self.k32.CloseHandle(h)

    def ioctl(self, h: int, code: int, out=None) -> bool:
        """DeviceIoControl without input; `out` is a ctypes object filled in. True on success."""
        returned = DWORD(0)
        ok = self.k32.DeviceIoControl(h, code, None, 0, ctypes.byref(out) if out is not None else None,
                                      ctypes.sizeof(out) if out is not None else 0, ctypes.byref(returned), None)
        return bool(ok)

    def volume_disks(self, path: str) -> set[int]:
        """Numbers of the disks a volume (\\\\.\\X:) has extents on; works without admin rights."""
        h = self.open(path, 0)  # no access rights needed for this query
        try:
            extents = VOLUME_DISK_EXTENTS()
            if not self.ioctl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, extents):
                raise self.fail(f"cannot find the disks of volume {path}")
            n = min(int(extents.NumberOfDiskExtents), MAX_EXTENTS)
            return {int(extents.Extents[i].DiskNumber) for i in range(n)}
        finally:
            self.close(h)

    def seek(self, h: int, offset: int, path: str) -> None:
        if not self.k32.SetFilePointerEx(h, offset, None, FILE_BEGIN):
            raise self.fail(f"cannot seek to byte {offset} of {path}")

    def read(self, h: int, address: int, length: int, path: str) -> int:
        done = DWORD(0)
        if not self.k32.ReadFile(h, address, length, ctypes.byref(done), None):
            raise self.fail(f"read from {path} failed")
        return done.value

    def write(self, h: int, address: int, length: int, path: str) -> int:
        done = DWORD(0)
        if not self.k32.WriteFile(h, address, length, ctypes.byref(done), None):
            raise self.fail(f"write to {path} failed")
        return done.value

    def flush(self, h: int, path: str) -> None:
        if not self.k32.FlushFileBuffers(h):
            raise self.fail(f"flushing {path} failed")

    def is_admin(self) -> bool:
        return bool(self.sh32.IsUserAnAdmin())

    def shell_execute_runas(self, file: str, parameters: str, directory: str | None) -> int | None:
        """Start `file parameters` elevated (UAC). Process handle, or None if the user declined."""
        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = file
        sei.lpParameters = parameters
        sei.lpDirectory = directory
        sei.nShow = SW_HIDE
        if not self.sh32.ShellExecuteExW(ctypes.byref(sei)):
            code = self.last_error()
            if code == ERROR_CANCELLED:
                return None
            raise self.fail(f"cannot start {file} as administrator", code)
        if not sei.hProcess:
            raise BeastError(f"started {file} as administrator but got no process handle")
        return sei.hProcess

    def wait(self, h: int, ms: int) -> int:
        return int(self.k32.WaitForSingleObject(h, ms))

    def exit_code(self, h: int) -> int:
        code = DWORD(0)
        if not self.k32.GetExitCodeProcess(h, ctypes.byref(code)):
            raise self.fail("cannot read the exit code of the elevated process")
        return code.value

    def terminate(self, h: int, code: int = 1) -> bool:
        return bool(self.k32.TerminateProcess(h, code))


class _AlignedBuffer:
    """A ctypes buffer whose address is a multiple of `alignment` (unbuffered I/O needs it)."""

    def __init__(self, size: int, alignment: int):
        self._raw = ctypes.create_string_buffer(size + alignment)
        base = ctypes.addressof(self._raw)
        self.address = base + (-base) % alignment
        self.size = size

    def put(self, data) -> None:
        data = bytes(data)
        if len(data) > self.size:
            raise ValueError("data larger than the I/O buffer")
        ctypes.memmove(self.address, data, len(data))

    def get(self, length: int) -> bytes:
        return ctypes.string_at(self.address, length)


class WindowsRawTarget(AlignedTarget):
    """\\\\.\\PhysicalDriveN opened unbuffered; aligned SetFilePointerEx + ReadFile/WriteFile."""

    def __init__(self, api: Win32, path: str, *, writable: bool, sector_size: int, size: int,
                 on_close=None):
        access = GENERIC_READ | (GENERIC_WRITE if writable else 0)
        h = api.open(path, access, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
        try:
            length = LARGE_INTEGER(0)
            if api.ioctl(h, IOCTL_DISK_GET_LENGTH_INFO, length) and length.value != size:
                raise BeastError(f"{path}: size changed (expected {size} bytes, device has {length.value})")
            super().__init__(path, size=size, sector_size=sector_size, writable=writable)
        except BaseException:
            api.close(h)
            raise
        self._api = api
        self._h = h
        self._buf = _AlignedBuffer(self.max_io, max(4096, sector_size))
        self._on_close = on_close
        self._written = False
        self.layout_refreshed = False  # IOCTL_DISK_UPDATE_PROPERTIES succeeded on close

    def _read_aligned(self, offset: int, length: int) -> bytes:
        self._api.seek(self._h, offset, self.path)
        n = self._api.read(self._h, self._buf.address, length, self.path)
        if n != length:
            raise BeastError(f"short read from {self.path} at byte {offset} ({n} of {length})")
        return self._buf.get(length)

    def _write_aligned(self, offset: int, data) -> None:
        self._written = True
        self._buf.put(data)
        self._api.seek(self._h, offset, self.path)
        n = self._api.write(self._h, self._buf.address, len(data), self.path)
        if n != len(data):
            raise BeastError(f"short write to {self.path} at byte {offset} ({n} of {len(data)})")

    def flush(self) -> None:
        if self.writable:
            self._api.flush(self._h, self.path)

    def close(self) -> None:
        """After writing: make Windows re-read the partition table while the volume
        locks (prepare()) are still held, then close and release the locks (on_close)."""
        if self._h is None:
            return
        try:
            if self._written:
                self.layout_refreshed = self._api.ioctl(self._h, IOCTL_DISK_UPDATE_PROPERTIES)
        finally:
            self._api.close(self._h)
            self._h = None
            if self._on_close:
                self._on_close()


class WindowsElevatedProcess:
    """ElevatedProcess for a ShellExecuteExW process handle."""

    def __init__(self, api: Win32, handle: int | None, argv: list[str], returncode: int | None = None):
        self._api = api
        self._h = handle
        self.argv = list(argv)
        self.returncode = returncode

    def _done(self) -> int:
        self.returncode = self._api.exit_code(self._h)
        self._api.close(self._h)
        self._h = None
        return self.returncode

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        r = self._api.wait(self._h, 0)
        if r == WAIT_TIMEOUT:
            return None
        if r != WAIT_OBJECT_0:
            raise self._api.fail("waiting for the elevated process failed")
        return self._done()

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        ms = INFINITE if timeout is None else min(max(int(timeout * 1000), 0), INFINITE - 1)
        r = self._api.wait(self._h, ms)
        if r == WAIT_TIMEOUT:
            raise TimeoutError(f"elevated process still running after {timeout} s")
        if r != WAIT_OBJECT_0:
            raise self._api.fail("waiting for the elevated process failed")
        return self._done()

    def cancel(self) -> None:
        if self._h is not None and self.returncode is None:
            self._api.terminate(self._h, 1)  # may be refused for an elevated process: best effort


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------

PS_PREAMBLE = """\
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
"""

LIST_SCRIPT = r"""
$diskProps = 'Number','FriendlyName','Model','SerialNumber','Size','LogicalSectorSize','PhysicalSectorSize','BusType','IsBoot','IsSystem','IsReadOnly','IsOffline','PartitionStyle','Location','Path'
$partProps = 'DiskNumber','PartitionNumber','DriveLetter','Offset','Size','Type','MbrType','GptType',
    'IsBoot','IsSystem','AccessPaths'
$volProps = 'DriveLetter','FileSystemLabel','FileSystem','DriveType','Path','Size'
Write-Output '##BEAST:disks'
Get-Disk | Select-Object -Property $diskProps | ConvertTo-Json -Depth 4
Write-Output '##BEAST:partitions'
Get-Partition | Select-Object -Property $partProps | ConvertTo-Json -Depth 4
Write-Output '##BEAST:volumes'
Get-Volume | Select-Object -Property $volProps | ConvertTo-Json -Depth 4
Write-Output '##BEAST:env'
$pf = $null
try { $pf = @(Get-CimInstance -ClassName Win32_PageFileUsage | ForEach-Object { [string]$_.Name }) } catch { }
if ($null -eq $pf) {
    # The page files the memory manager reports ('\??\C:\pagefile.sys'), readable without admin rights.
    try {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        $mm = Get-ItemProperty -Path $key -Name ExistingPageFiles
        $pf = @($mm.ExistingPageFiles | ForEach-Object { ([string]$_) -replace '^\\\?\?\\', '' })
    } catch { }
}
# PageFilesKnown = $false: neither source could be read (the backend then assumes the worst).
[pscustomobject]@{
    SystemRoot = $env:SystemRoot
    PageFiles = @($pf | Where-Object { $_ })
    PageFilesKnown = ($null -ne $pf)
} | ConvertTo-Json -Depth 4
"""

# MSFT_Disk.BusType numbers, for when PowerShell prints the raw value.
BUS_TYPE_NAMES = {
    0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA", 6: "Fibre Channel",
    7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
    15: "File Backed Virtual", 16: "Storage Spaces", 17: "NVMe", 18: "SCM", 19: "UFS",
}
BUS_MAP = {
    "usb": "usb", "sata": "sata", "ata": "sata", "atapi": "sata", "nvme": "nvme", "scm": "nvme",
    "sd": "sd", "mmc": "sd", "ufs": "unknown", "scsi": "scsi", "sas": "scsi", "iscsi": "scsi",
    "fibre channel": "scsi", "raid": "scsi", "ssa": "scsi", "virtual": "virtual",
    "file backed virtual": "virtual", "storage spaces": "virtual", "spaces": "virtual",
}
EXTERNAL_BUSES = ("usb", "sd", "mmc", "1394")  # BusType values we treat as removable/external
PARTITION_STYLES = {0: "RAW", 1: "MBR", 2: "GPT"}

_ID_RE = re.compile(r"^(?:(?:\\\\|//)[.?][\\/])?physicaldrive(\d+)$", re.IGNORECASE)
_VOLUME_GUID_RE = re.compile(r"^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\?$")


def ps_quote(s: str) -> str:
    """A PowerShell single-quoted string. PowerShell also treats the typographic
    quotes U+2018..U+201B as single quotes, so those are doubled too."""
    return "'" + re.sub("(['\u2018\u2019\u201a\u201b])", r"\1\1", s) + "'"


def powershell_exe() -> str:
    """Windows PowerShell 5.1 by absolute path (not whatever is first on PATH)."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    path = ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.exists(path) else "powershell.exe"


def powershell_argv(script: str) -> list[str]:
    body = PS_PREAMBLE + "try {\n" + script + "\n} catch {\n" \
        "[Console]::Error.WriteLine($_.Exception.Message)\nexit 1\n}\n"
    encoded = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
    return [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encoded]


def run_powershell(script: str, what: str = "PowerShell") -> str:
    argv = powershell_argv(script)
    try:
        proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL,
                              creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
    except FileNotFoundError:
        raise BeastError("Windows PowerShell (powershell.exe) was not found") from None
    out = proc.stdout.decode("utf-8-sig", "replace")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8-sig", "replace")
        # The error is on stderr (see powershell_argv); stdout may hold earlier sections' JSON.
        lines = _lines(err) or _lines(out)
        raise BeastError(f"{what} failed: {'; '.join(lines[-3:]) or f'exit {proc.returncode}'}")
    return out


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def split_sections(text: str) -> dict[str, str]:
    """'##BEAST:name' lines start sections; returns name -> text."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("##BEAST:"):
            current = line[len("##BEAST:"):].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def json_list(text: str) -> list:
    """ConvertTo-Json output as a list: '' -> [], {...} -> [{...}], [...] -> [...]."""
    text = text.strip().lstrip("\ufeff")
    if not text:
        return []
    try:
        value = json.loads(text)
    except ValueError as e:
        raise BeastError(f"could not parse PowerShell JSON output: {e}") from None
    return as_list(value)


def as_list(value) -> list:
    """A JSON value that PowerShell meant as an array: null -> [], x -> [x], and
    Windows PowerShell 5.1's {"value": [...], "Count": n} wrapper -> [...]."""
    if value is None:
        return []
    if isinstance(value, dict) and set(value) == {"value", "Count"}:
        value = value["value"]
    return list(value) if isinstance(value, list) else [value]


def _letter(value) -> str | None:
    """DriveLetter as JSON shows it ("E", "\\u0000", 69, null) -> 'E' or None."""
    if isinstance(value, int):
        value = chr(value) if 0 < value < 0x110000 else ""
    if isinstance(value, str) and len(value) == 1 and value.isascii() and value.isalpha():
        return value.upper()
    return None


def _bus_type(value) -> str:
    if isinstance(value, int):
        return BUS_TYPE_NAMES.get(value, "Unknown")
    return str(value or "Unknown")


def _style(value) -> str:
    if isinstance(value, int):
        return PARTITION_STYLES.get(value, "RAW")
    return str(value or "RAW")


def parse_disk_number(device: str) -> int:
    """'2', 'PhysicalDrive2', '\\\\.\\PhysicalDrive2' (also // and \\\\?\\ forms) -> 2."""
    s = str(device).strip()
    if s.isdigit():
        return int(s)
    m = _ID_RE.match(s)
    if not m:
        raise BeastError(
            f"{device!r} is not a Windows disk: use the disk number (e.g. 2) or \\\\.\\PhysicalDrive2 "
            "(see Disk Management or `Get-Disk`)"
        )
    return int(m.group(1))


def physical_drive(n: int) -> str:
    return f"\\\\.\\PhysicalDrive{n}"


class _Snapshot:
    def __init__(self, text: str):
        sections = split_sections(text)
        for name in ("disks", "partitions", "volumes"):
            if name not in sections:
                raise BeastError(f"unexpected PowerShell output: no {name} section")
        self.disks = json_list(sections["disks"])
        self.partitions = json_list(sections["partitions"])
        self.volumes = json_list(sections["volumes"])
        env = json_list(sections.get("env", ""))
        self.env = env[0] if env else {}

    def parts_of(self, n: int) -> list[dict]:
        ps = [p for p in self.partitions if p.get("DiskNumber") == n]
        return sorted(ps, key=lambda p: int(p.get("PartitionNumber") or 0))

    def disks_of_letter(self, letter: str, volume_disks=None) -> set[int]:
        """Disks under drive `letter`: the volume's extents (volume_disks(letter), None if
        unknown; also finds dynamic volumes) plus the partitions Get-Partition gives that letter."""
        found = set((volume_disks(letter) if volume_disks else None) or ())
        found |= {p.get("DiskNumber") for p in self.partitions if _letter(p.get("DriveLetter")) == letter}
        found.discard(None)
        return found

    def is_dynamic(self, n: int) -> bool:
        """Disk n holds Logical Disk Manager partitions (a dynamic disk)."""
        return any(is_ldm_type(p.get("MbrType"), p.get("GptType")) for p in self.parts_of(n))

    def fixed_letter_disks(self) -> set[int]:
        """Disks with a drive-lettered volume that Windows calls Fixed (or that has no volume info)."""
        out = set()
        for p in self.partitions:
            if _letter(p.get("DriveLetter")):
                v = self.volume(p)
                drive_type = v.get("DriveType") if v else None
                if drive_type in (None, "Fixed", 3):
                    out.add(p.get("DiskNumber"))
        out.discard(None)
        return out

    def volume(self, part: dict) -> dict | None:
        paths = {a.rstrip("\\").lower() for a in as_list(part.get("AccessPaths"))}
        letter = _letter(part.get("DriveLetter"))
        for v in self.volumes:
            vp = (v.get("Path") or "").rstrip("\\").lower()
            if (vp and vp in paths) or (letter and _letter(v.get("DriveLetter")) == letter):
                return v
        return None

    def system_reasons(self, volume_disks=None) -> dict[int, str]:
        """disk number -> why it is a system disk. volume_disks(letter) -> disk numbers
        (from the volume's extents) or None; without it only Get-Partition letters count."""
        reasons: dict[int, str] = {}
        for d in self.disks:
            n = d.get("Number")
            if d.get("IsBoot"):
                reasons.setdefault(n, "holds the running Windows (boot volume)")
            if d.get("IsSystem"):
                reasons.setdefault(n, "holds the Windows system partition (boot manager)")
        fixed = [d.get("Number") for d in self.disks if _bus_type(d.get("BusType")).lower() not in EXTERNAL_BUSES]

        root = _letter((self.env.get("SystemRoot") or "")[:1])
        root_disks = self.disks_of_letter(root, volume_disks) if root else set()
        for n in root_disks:
            reasons.setdefault(n, f"holds the Windows directory ({root}:)")
        if not root_disks:  # cannot tell which disk Windows runs from: none of the fixed ones is safe
            for n in fixed:
                reasons.setdefault(n, "is a fixed disk, and the disk holding Windows could not be identified")

        pagefiles_known = self.env.get("PageFilesKnown") is True
        for pf in as_list(self.env.get("PageFiles")):
            pf = str(pf).removeprefix("\\??\\")
            letter = _letter(pf[:1])
            disks = self.disks_of_letter(letter, volume_disks) if letter else set()
            pagefiles_known = pagefiles_known and bool(disks)
            for n in disks:
                reasons.setdefault(n, f"holds a page file ({pf})")
        if not pagefiles_known:  # the page-file list could not be read, or a page file not mapped
            for n in self.fixed_letter_disks():
                reasons.setdefault(n, "may hold a page file (the page files could not be identified)")

        # A system disk that is a VHD(X) lives in a file on another disk: that disk is system too.
        for d in self.disks:
            loc = str(d.get("Location") or "")
            if d.get("Number") in reasons and re.match(r"^[A-Za-z]:\\", loc):
                for host in self.disks_of_letter(loc[0].upper(), volume_disks):
                    reasons.setdefault(host, f"holds the virtual disk the running Windows uses ({loc})")
        return reasons


def is_ldm_type(mbr_type, gpt_type) -> bool:
    """MbrType / GptType (Get-Partition) or a disk.py PartEntry type ("0x42", GUID) of an LDM partition."""
    if isinstance(mbr_type, int) and mbr_type == LDM_MBR_TYPE:
        return True
    if isinstance(mbr_type, str) and mbr_type.lower() == "0x42":
        return True
    return isinstance(gpt_type, str) and gpt_type.strip("{}").upper() in LDM_GPT_TYPES


class WindowsBackend:
    name = "windows"

    def __init__(self, api: Win32 | None = None, powershell=None, sleep=time.sleep):
        self._api = api
        self._ps = powershell or run_powershell  # powershell(script, what) -> stdout text
        self._sleep = sleep
        self._locks: dict[int, list[tuple[str, int]]] = {}  # disk number -> [(volume path, handle)]
        self.program_paths = None  # override for tests (see common.running_from)

    @property
    def api(self) -> Win32:
        if self._api is None:
            self._api = Win32()
        return self._api

    # -- listing ---------------------------------------------------------------
    def _snapshot(self) -> _Snapshot:
        return _Snapshot(self._ps(LIST_SCRIPT, "listing disks (Get-Disk)"))

    def _make_info(self, d: dict, snap: _Snapshot, reason: str | None) -> DiskInfo:
        n = int(d["Number"])
        bus_type = _bus_type(d.get("BusType"))
        mounts: list[str] = []
        volumes = []
        parts = snap.parts_of(n)
        for p in parts:
            letter = _letter(p.get("DriveLetter"))
            if letter:
                mounts.append(f"{letter}:\\")
            for a in as_list(p.get("AccessPaths")):
                if not _VOLUME_GUID_RE.match(a) and not re.fullmatch(r"[A-Za-z]:\\", a) and a not in mounts:
                    mounts.append(a)  # folder mount point, e.g. C:\mnt\stick\
            v = snap.volume(p)
            if v:
                volumes.append({"partition": p.get("PartitionNumber"), "letter": letter,
                                "label": v.get("FileSystemLabel") or "", "fs": v.get("FileSystem") or ""})
        return DiskInfo(
            id=physical_drive(n),
            path=physical_drive(n),
            model=(d.get("FriendlyName") or d.get("Model") or "").strip(),
            size=int(d.get("Size") or 0),
            sector_size=int(d.get("LogicalSectorSize") or 512),
            bus=BUS_MAP.get(bus_type.lower(), "unknown"),
            removable=bus_type.lower() in EXTERNAL_BUSES,
            system=reason is not None,
            read_only=bool(d.get("IsReadOnly")),
            mountpoints=tuple(mounts),
            partitions=tuple(self._partition_path(n, int(p["PartitionNumber"])) for p in parts
                             if p.get("PartitionNumber")),
            extra={"number": n, "bus_type": bus_type, "is_boot": bool(d.get("IsBoot")),
                   "is_system": bool(d.get("IsSystem")), "is_offline": bool(d.get("IsOffline")),
                   "partition_style": _style(d.get("PartitionStyle")),
                   "serial": (d.get("SerialNumber") or "").strip(), "volumes": volumes,
                   "dynamic": snap.is_dynamic(n), "system_reason": reason},
        )

    def _volume_disks(self, letter: str) -> set[int] | None:
        """Disks under drive letter's volume from its extents; None when that cannot be asked
        (no such volume, not on Windows)."""
        try:
            return self.api.volume_disks(f"\\\\.\\{letter}:")
        except BeastError:
            return None

    def _system_reasons(self, snap: _Snapshot) -> dict[int, str]:
        return snap.system_reasons(self._volume_disks)

    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]:
        snap = self._snapshot()
        reasons = self._system_reasons(snap)
        out = []
        for d in sorted(snap.disks, key=lambda d: int(d.get("Number") or 0)):
            if d.get("Number") is None or not d.get("Size"):
                continue  # card reader without a card
            info = self._make_info(d, snap, reasons.get(d["Number"]))
            if include_fixed or (info.removable and not info.system):
                out.append(info)
        return out

    def get_disk(self, device: str) -> DiskInfo:
        n = parse_disk_number(device)
        snap = self._snapshot()
        for d in snap.disks:
            if d.get("Number") == n:
                return self._make_info(d, snap, self._system_reasons(snap).get(n))
        raise BeastError(f"there is no disk {n} ({physical_drive(n)}); see Disk Management or `Get-Disk`")

    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None:
        fresh = self.get_disk(disk.id)  # things may have changed since listing
        check_same_drive(disk, fresh)
        check_common(fresh, allow_fixed=allow_fixed, paths=self.program_paths, pathmod=ntpath)
        if fresh.extra.get("dynamic"):
            raise BeastError(_dynamic_refusal(fresh.id))

    # -- volumes -----------------------------------------------------------------
    @staticmethod
    def volumes(snap: _Snapshot, n: int) -> list[tuple[str, str]]:
        """(device path, what to call it) for the volumes on disk n: \\\\?\\Volume{GUID} or
        \\\\.\\X:, shown as its drive letter (E:\\) when it has one."""
        out = []
        for p in snap.parts_of(n):
            guid = next((a for a in as_list(p.get("AccessPaths")) if _VOLUME_GUID_RE.match(a)), None)
            letter = _letter(p.get("DriveLetter"))
            shown = f"{letter}:\\" if letter else ""
            if guid:
                out.append((guid.rstrip("\\"), shown))  # CreateFileW wants it without the trailing backslash
            elif letter:
                out.append((f"\\\\.\\{letter}:", shown))
        return out

    @classmethod
    def volume_paths(cls, snap: _Snapshot, n: int) -> list[str]:
        """Device paths of the volumes on disk n: \\\\?\\Volume{GUID} or \\\\.\\X:."""
        return [path for path, _shown in cls.volumes(snap, n)]

    def _lock_volume(self, path: str, shown: str = "") -> int:
        api = self.api
        h = api.open(path, GENERIC_READ | GENERIC_WRITE)
        try:
            locked = False
            for _ in range(LOCK_ATTEMPTS):
                if api.ioctl(h, FSCTL_LOCK_VOLUME):
                    locked = True
                    break
                self._sleep(LOCK_RETRY_DELAY)
            if not locked:
                # Programs keep files open: force the dismount (their handles become invalid), then lock.
                api.ioctl(h, FSCTL_DISMOUNT_VOLUME)
                if not api.ioctl(h, FSCTL_LOCK_VOLUME):
                    e = api.fail(f"cannot lock volume {shown or path}; close the programs and windows using "
                                 "the drive")
                    e.code = "busy"
                    raise e
            if not api.ioctl(h, FSCTL_DISMOUNT_VOLUME):
                raise api.fail(f"cannot dismount volume {path}")
        except BaseException:
            api.close(h)
            raise
        return h

    def prepare(self, disk: DiskInfo) -> list[str]:
        """Refuse system and dynamic disks, then lock and dismount every volume on the disk.
        The locks are held until the writable raw target is closed (or release()).
        Returns the drive letters and folder mount points that were dismounted."""
        n = parse_disk_number(disk.id)
        snap = self._snapshot()
        reason = self._system_reasons(snap).get(n)
        if reason:
            raise BeastError(f"refusing: {disk.id} {reason}")
        if snap.is_dynamic(n) or self._ldm_on_disk(disk):
            raise BeastError(_dynamic_refusal(disk.id))
        self.release(disk)
        held: list[tuple[str, int]] = []
        try:
            for path, shown in self.volumes(snap, n):
                held.append((path, self._lock_volume(path, shown)))
        except BaseException:
            for _path, h in held:
                self.api.close(h)
            raise
        self._locks[n] = held
        return [m for d in snap.disks if d.get("Number") == n for m in self._make_info(d, snap, None).mountpoints]

    def _ldm_on_disk(self, disk: DiskInfo) -> bool:
        """The partition table on the disk itself has LDM partitions (in case Get-Partition
        does not show them). A disk without a readable table has none."""
        try:
            with self.open_raw(disk, writable=False) as t:
                table = read_partition_table(t.read, t.size // t.sector_size)
        except BeastError:
            return False
        return any(is_ldm_type(e.type, e.type) for e in table.entries.values())

    def release(self, disk: DiskInfo) -> None:
        """Close the volume handles prepare() kept (this unlocks the volumes)."""
        for _path, h in self._locks.pop(parse_disk_number(disk.id), []):
            self.api.close(h)

    # -- I/O ---------------------------------------------------------------------
    def open_raw(self, disk: DiskInfo, *, writable: bool) -> WindowsRawTarget:
        on_close = (lambda: self.release(disk)) if writable else None
        return WindowsRawTarget(self.api, disk.path, writable=writable, sector_size=disk.sector_size,
                                size=disk.size, on_close=on_close)

    def rescan(self, disk: DiskInfo, timeout: float = RESCAN_TIMEOUT) -> None:
        """IOCTL_DISK_UPDATE_PROPERTIES, then wait until Windows lists the new partitions."""
        self.release(disk)
        n = parse_disk_number(disk.id)
        api = self.api
        h = api.open(disk.path, GENERIC_READ | GENERIC_WRITE)
        try:
            if not api.ioctl(h, IOCTL_DISK_UPDATE_PROPERTIES):
                raise api.fail(f"Windows did not re-read the partition table of {disk.path}")
        finally:
            api.close(h)
        with self.open_raw(disk, writable=False) as t:
            table = read_partition_table(t.read, t.size // t.sector_size)
            expected = sorted(e.size * t.sector_size for e in table.entries.values())
        script = self.partitions_script(n)
        deadline = time.monotonic() + timeout
        while True:
            parts = json_list(split_sections(self._ps(script, "Get-Partition")).get("partitions", ""))
            seen = sorted(int(p.get("Size") or 0) for p in parts)
            if seen == expected:
                return
            if time.monotonic() > deadline:
                raise BeastError(
                    f"Windows did not pick up the new partition table on {disk.path} "
                    f"({len(seen)} of {len(expected)} partitions visible); unplug and reconnect the drive"
                )
            self._sleep(0.5)

    @staticmethod
    def partitions_script(n: int) -> str:
        """Partition numbers and sizes of disk n, after refreshing the storage cache."""
        return (f"Update-HostStorageCache -ErrorAction SilentlyContinue\n"
                f"Write-Output '##BEAST:partitions'\n"
                f"@(Get-Partition -DiskNumber {n} -ErrorAction SilentlyContinue) | "
                f"Select-Object -Property PartitionNumber, Size | ConvertTo-Json -Depth 4\n")

    @staticmethod
    def _partition_path(n: int, index: int) -> str:
        return f"\\\\?\\GLOBALROOT\\Device\\Harddisk{n}\\Partition{index}"

    def partition_path(self, disk: DiskInfo, index: int) -> str:
        return self._partition_path(parse_disk_number(disk.id), index)

    @staticmethod
    def ntfs_script(n: int, index: int, label: str) -> str:
        return f"""\
$deadline = (Get-Date).AddSeconds(30)
while ($true) {{
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $p = Get-Partition -DiskNumber {n} -PartitionNumber {index} -ErrorAction SilentlyContinue
    if ($p) {{ break }}
    if ((Get-Date) -gt $deadline) {{ throw 'partition {index} of disk {n} did not appear' }}
    Start-Sleep -Milliseconds 500
}}
$v = Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel {ps_quote(label)} -Force -Confirm:$false
Write-Output '##BEAST:result'
$v | Select-Object FileSystem, FileSystemLabel, Size | ConvertTo-Json -Depth 4
"""

    def format_ntfs(self, disk: DiskInfo, index: int, label: str) -> None:
        n = parse_disk_number(disk.id)
        out = self._ps(self.ntfs_script(n, index, label), "Format-Volume (NTFS)")
        result = json_list(split_sections(out).get("result", ""))
        if not result or str(result[0].get("FileSystem", "")).upper() != "NTFS":
            raise BeastError(f"Format-Volume did not create NTFS on partition {index} of disk {n}")

    # -- elevation ---------------------------------------------------------------
    def probe_installed(self, disk: DiskInfo, *, should_stop=None):
        """interfaces.PlatformBackend.probe_installed (installed_probe.py)."""
        from ..installed_probe import probe_windows

        return probe_windows(self, disk, should_stop=should_stop)

    def is_elevated(self) -> bool:
        return self.api.is_admin()

    def run_elevated(self, argv: list[str]):
        if not argv:
            raise ValueError("empty command")
        params = subprocess.list2cmdline(argv[1:])
        h = self.api.shell_execute_runas(argv[0], params, os.getcwd())
        if h is None:  # the user answered "No" to the UAC prompt
            return WindowsElevatedProcess(self.api, None, argv, returncode=ELEVATION_CANCELLED)
        return WindowsElevatedProcess(self.api, h, argv)


def _dynamic_refusal(disk_id: str) -> str:
    return (f"refusing: {disk_id} is a dynamic disk (Logical Disk Manager): its volumes cannot be "
            "locked safely; delete its volumes in Disk Management (or convert it to a basic disk) first")


__all__ = ["WindowsBackend", "Win32", "WindowsRawTarget", "parse_disk_number", "ps_quote", "json_list"]
