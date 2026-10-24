"""Simulated drives for `--gui --demo`: try the whole window without touching any disk.

DemoBackend implements interfaces.PlatformBackend with a fixed set of
realistic drives (a usable USB stick, one that fails while writing, a
write-protected SD card, internal disks, ...). Its run_elevated() does not ask
for administrator rights; it starts the command as a normal process. The demo
controller points the command at fake_cli.py instead of the real CLI, so
nothing is ever written.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from ..errors import BeastError
from ..interfaces import DiskInfo
from ..layout import MIB
from .localproc import LocalProcess

GB = 1000**3
FAKE_CLI = Path(__file__).resolve().with_name("fake_cli.py")


def _ids(platform: str) -> list[tuple[str, str]]:
    if platform == "windows":
        return [(rf"\\.\PhysicalDrive{n}", rf"\\.\PhysicalDrive{n}") for n in range(1, 8)]
    if platform == "darwin":
        return [(f"/dev/disk{n}", f"/dev/rdisk{n}") for n in range(4, 11)]
    return [(f"/dev/sd{c}", f"/dev/sd{c}") for c in "bcdefgh"]


def demo_disks(platform: str) -> list[DiskInfo]:
    ids = _ids(platform)
    media = {"windows": "E:\\", "darwin": "/Volumes/USB DISK"}.get(platform, "/media/you/USB DISK")
    specs = [
        # model, size, bus, removable, system, read_only, mountpoints
        ("SanDisk Ultra Fit", 32 * GB, "usb", True, False, False, (media,)),
        ("Kingston DataTraveler (fails while writing)", 16 * GB, "usb", True, False, False, ()),
        ("Generic SD/MMC card", 8 * GB, "sd", True, False, True, ()),
        ("Old promo stick", 128 * MIB, "usb", True, False, False, ()),
        ("Samsung Portable SSD T7", 500 * GB, "usb", False, False, False, ()),
        ("WDC WD20EZRZ", 2000 * GB, "sata", False, False, False, ()),
        ("Samsung SSD 990 PRO", 1000 * GB, "nvme", False, True, False, ("/", "/boot/efi")),
    ]
    return [
        DiskInfo(id=i, path=p, model=m, size=s, sector_size=512, bus=b, removable=r,
                 system=sy, read_only=ro, mountpoints=mp)
        for (i, p), (m, s, b, r, sy, ro, mp) in zip(ids, specs)
    ]


class DemoBackend:
    def __init__(self, platform: str | None = None, list_delay: float = 0.4, step_delay: float = 0.35):
        self.name = platform or {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
        self._disks = demo_disks(self.name)
        self.list_delay = list_delay
        self.step_delay = step_delay

    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]:
        time.sleep(self.list_delay)  # real backends take a moment too
        return [d for d in self._disks if include_fixed or (d.removable and not d.system)]

    def get_disk(self, device: str) -> DiskInfo:
        for d in self._disks:
            if device in (d.id, d.path):
                return d
        raise BeastError(f"no such disk: {device}")

    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None:
        from .controller import drive_problem

        if problem := drive_problem(disk):
            raise BeastError(f"refusing: {disk.model} {problem}")

    def _no_device_access(self, *_a, **_k):
        raise BeastError("demo mode: no device access")

    prepare = open_raw = rescan = partition_path = format_ntfs = _no_device_access

    def is_elevated(self) -> bool:
        return False

    def run_elevated(self, argv: list[str]) -> LocalProcess:
        """No elevation: run the (fake) CLI as a normal process."""
        extra = ["--fake-delay", str(self.step_delay)]
        if "--device" in argv:
            disk = self.get_disk(argv[argv.index("--device") + 1])
            if "fails" in disk.model:
                extra += ["--fake-fail-at", "write-firmware" if "firmware" in argv else "write-esp"]
        return LocalProcess(argv + extra, os.devnull)
