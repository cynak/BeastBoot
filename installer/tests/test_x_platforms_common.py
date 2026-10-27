"""platforms/__init__.py and platforms/common.py: backend choice, shared rules, PopenProcess."""

from __future__ import annotations

import ntpath
import subprocess
import sys

import pytest

from beastbooter.errors import BeastError
from beastbooter.interfaces import DiskInfo
from beastbooter.platforms import ELEVATION_CANCELLED, ELEVATION_FAILED, get_backend
from beastbooter.platforms.common import PopenProcess, check_common, natural_key, running_from

GIB = 1 << 30


def disk(**kw) -> DiskInfo:
    base = dict(id="/dev/sdx", path="/dev/sdx", model="ACME Stick", size=16 * GIB, sector_size=512,
                bus="usb", removable=True, system=False, read_only=False)
    base.update(kw)
    return DiskInfo(**base)


@pytest.mark.parametrize("plat,cls", [("linux", "LinuxBackend"), ("darwin", "DarwinBackend"),
                                      ("win32", "WindowsBackend")])
def test_get_backend_by_platform(plat, cls):
    b = get_backend(plat)
    assert type(b).__name__ == cls
    assert b.name == {"linux": "linux", "darwin": "darwin", "win32": "windows"}[plat]


def test_get_backend_current_and_unsupported():
    assert get_backend().name == "linux" if sys.platform.startswith("linux") else True
    with pytest.raises(BeastError, match=r"not supported on this platform \('sunos5'\).*--image"):
        get_backend("sunos5")


def test_elevation_codes():
    assert (ELEVATION_CANCELLED, ELEVATION_FAILED) == (126, 127)  # pkexec's documented codes


def test_check_common_passes_and_refuses():
    check_common(disk(), allow_fixed=False, paths=["/opt/app"])
    cases = [
        (dict(system=True, extra={"system_reason": "holds the system's / filesystem"}), "holds the system's /"),
        (dict(system=True), "holds the running operating system"),
        (dict(read_only=True), "read-only"),
        (dict(sector_size=4096), "4096-byte sectors"),
        (dict(size=0), "no medium"),
        (dict(removable=False), "not a removable or external drive.*--allow-fixed-disk"),
    ]
    for kw, match in cases:
        with pytest.raises(BeastError, match=match):
            check_common(disk(**kw), allow_fixed=False, paths=["/opt/app"])
    check_common(disk(removable=False), allow_fixed=True, paths=["/opt/app"])
    with pytest.raises(BeastError, match="holds the"):
        check_common(disk(system=True, removable=False), allow_fixed=True, paths=["/opt/app"])


def test_running_from_the_target_is_refused():
    d = disk(mountpoints=("/media/me/MY STICK",))
    with pytest.raises(BeastError, match=r"running from /dev/sdx \(/media/me/MY STICK\)"):
        check_common(d, allow_fixed=False, paths=["/media/me/MY STICK/beast-boot/python/bin/python3"])
    check_common(d, allow_fixed=False, paths=["/media/me/MY STICK2/app"])  # prefix but not inside


def test_running_from_windows_paths():
    paths = [r"E:\beast-boot\python\python.exe"]
    assert running_from(["E:\\"], paths, pathmod=ntpath) == "E:\\"
    assert running_from(["e:\\"], paths, pathmod=ntpath) == "e:\\"  # case-insensitive
    assert running_from(["F:\\", "C:\\Archive\\"], paths, pathmod=ntpath) is None
    assert running_from(["E:\\"], ["/home/me/app"], pathmod=ntpath) is None  # mixed drives: no crash


def test_natural_key():
    assert sorted(["disk10", "disk2", "disk1"], key=natural_key) == ["disk1", "disk2", "disk10"]
    assert sorted(["sdb", "nvme0n1", "sda"], key=natural_key) == ["nvme0n1", "sda", "sdb"]


def test_popen_process_wait_poll_timeout_cancel():
    p = PopenProcess(subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(3)"]), ["x"])
    assert p.wait(10) == 3 and p.poll() == 3 and p.returncode == 3
    slow = PopenProcess(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]), ["y"])
    assert slow.poll() is None
    with pytest.raises(TimeoutError):
        slow.wait(0.05)
    slow.cancel()
    assert slow.wait(10) != 0
    slow.cancel()  # already gone: no error


WINDOWS_LIKE_IMPORT = r"""
import sys
for name in ("fcntl", "termios", "grp", "pwd", "resource"):
    sys.modules[name] = None  # what Windows Python lacks: `import fcntl` raises ImportError
sys.path.insert(0, sys.argv[1])
import beastbooter.blockio
import beastbooter.platforms.common
import beastbooter.platforms.linux
import beastbooter.platforms.darwin
import beastbooter.platforms.windows
from beastbooter.platforms import get_backend
print(sorted(type(get_backend(p)).__name__ for p in ("linux", "darwin", "win32")))
"""


def test_every_backend_module_imports_without_fcntl():
    """platforms/__init__.py promises every backend module imports on every OS (Windows has
    no fcntl): fcntl is imported only inside the POSIX functions that use it."""
    from pathlib import Path

    installer = str(Path(__file__).resolve().parents[1])
    proc = subprocess.run([sys.executable, "-I", "-c", WINDOWS_LIKE_IMPORT, installer],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "['DarwinBackend', 'LinuxBackend', 'WindowsBackend']"
