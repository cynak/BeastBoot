"""Per-OS disk access behind one interface (interfaces.PlatformBackend).

    from beastbooter.platforms import get_backend
    b = get_backend()                     # LinuxBackend, DarwinBackend or WindowsBackend
    disk = b.get_disk("/dev/sdb")         # or /dev/disk4, or 2 / \\\\.\\PhysicalDrive2
    b.check_safe(disk, allow_fixed=False) # refuses system / read-only / fixed disks
    b.prepare(disk)                       # unmount (Linux, macOS) / lock + dismount (Windows)
    with b.open_raw(disk, writable=True) as t:   # a blockio BlockTarget
        ...write partition table + filesystems...
        t.flush()
    b.rescan(disk)                        # the OS re-reads the new partition table

Each backend module imports on every OS: Windows API calls are only made when
used, and POSIX-only modules (fcntl) are imported inside the functions that
need them. So the unit tests exercise all three backends on Linux with
recorded outputs, and the Windows build can import (and test) all of them.
"""

from __future__ import annotations

import sys

from ..errors import BeastError
from .common import ELEVATION_CANCELLED, ELEVATION_FAILED  # noqa: F401  (re-exported)

SUPPORTED = ("linux", "darwin", "win32")


def get_backend(platform: str | None = None):
    """The PlatformBackend for this OS (or for `platform`, a sys.platform value)."""
    plat = sys.platform if platform is None else platform
    if plat.startswith("linux"):
        from .linux import LinuxBackend

        return LinuxBackend()
    if plat == "darwin":
        from .darwin import DarwinBackend

        return DarwinBackend()
    if plat == "win32":
        from .windows import WindowsBackend

        return WindowsBackend()
    raise BeastError(
        f"writing drives is not supported on this platform ({plat!r}); beast-boot supports "
        "Linux, Windows and macOS (image files work everywhere: use --image)"
    )
