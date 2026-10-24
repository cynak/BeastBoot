"""A PlatformBackend whose "drive" is a file: proves the device code path end
to end (safety checks, prepare, raw I/O, rescan, NTFS formatter) without ever
opening a real device.

    backend = FakeBackend(tmp_path)          # 1100 MiB "USB stick" with stale data
    monkeypatch.setattr(commands, "get_backend", lambda: backend)
    run_cli("install", "--device", backend.disk.id, ...)
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path

from beastbooter.blockio import ImageTarget
from beastbooter.disk import read_partition_table
from beastbooter.errors import BeastError
from beastbooter.interfaces import DiskInfo
from beastbooter.layout import MIB, SECTOR_SIZE
from beastbooter.platforms.common import check_common

STALE = b"\xaa"


class FakeBackend:
    name = "fake"

    def __init__(self, tmp_path: Path, size: int = 1100 * MIB, *, removable: bool = True,
                 extra_disks: tuple[DiskInfo, ...] = (), elevated: bool = True):
        self.disk_file = Path(tmp_path) / "fake-disk.bin"
        with open(self.disk_file, "wb") as f:  # stale data at both ends, like a used stick
            f.write(STALE * (2 * MIB))
            f.truncate(size)
            f.seek(size - MIB)
            f.write(STALE * MIB)
        self.disk = DiskInfo(
            id="/dev/fakesdz", path=str(self.disk_file), model="ACME Fake Stick", size=size,
            sector_size=SECTOR_SIZE, bus="usb", removable=removable, system=False, read_only=False,
            mountpoints=(), partitions=("/dev/fakesdz1",), extra={"name": "fakesdz"},
        )
        self.extra_disks = list(extra_disks)
        self.elevated = elevated
        self.calls: list[tuple] = []
        self.opened: list[ImageTarget] = []

    # -- PlatformBackend -----------------------------------------------------
    def list_disks(self, *, include_fixed: bool = False) -> list[DiskInfo]:
        self.calls.append(("list_disks", include_fixed))
        disks = [self.disk] + self.extra_disks
        return [d for d in disks if include_fixed or (d.removable and not d.system)]

    def get_disk(self, device: str) -> DiskInfo:
        self.calls.append(("get_disk", device))
        for d in [self.disk] + self.extra_disks:
            if device in (d.id, d.extra.get("name")):
                return d
        raise BeastError(f"{device} does not exist")

    def check_safe(self, disk: DiskInfo, *, allow_fixed: bool) -> None:
        self.calls.append(("check_safe", allow_fixed))
        check_common(disk, allow_fixed=allow_fixed, paths=[])

    def prepare(self, disk: DiskInfo) -> None:
        self.calls.append(("prepare",))

    def open_raw(self, disk: DiskInfo, *, writable: bool) -> ImageTarget:
        self.calls.append(("open_raw", writable))
        t = ImageTarget(disk.path, writable=writable)
        self.opened.append(t)
        return t

    def rescan(self, disk: DiskInfo) -> None:
        self.calls.append(("rescan",))

    def partition_path(self, disk: DiskInfo, index: int) -> str:
        return f"{disk.id}{index}"

    def format_ntfs(self, disk: DiskInfo, index: int, label: str) -> None:
        """What the OS formatter does: mkfs.ntfs on the partition (here a temp file copied in)."""
        self.calls.append(("format_ntfs", index, label))
        with ImageTarget(disk.path, writable=False) as t:
            e = read_partition_table(t.read, t.size // SECTOR_SIZE).entries[index]
        part = self.disk_file.with_suffix(".part")
        with open(part, "wb") as f:
            f.truncate(e.size * SECTOR_SIZE)
        subprocess.run(["mkfs.ntfs", "-q", "-Q", "-F", "-L", label, "-p", str(e.start), "-H", "255", "-S", "63",
                        str(part)], check=True, capture_output=True)
        with open(part, "rb") as src, open(self.disk_file, "r+b") as dst:
            dst.seek(e.start * SECTOR_SIZE)
            while chunk := src.read(4 * MIB):
                dst.write(chunk)
        os.unlink(part)

    def is_elevated(self) -> bool:
        return self.elevated

    def run_elevated(self, argv):  # pragma: no cover - the CLI never elevates itself
        raise AssertionError("the CLI must not start elevated processes")

    # -- helpers for tests -----------------------------------------------------
    def set_disk(self, **changes) -> FakeBackend:
        self.disk = replace(self.disk, **changes)
        return self

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]
