"""Simulated drives for `--gui --demo`: try the whole window without touching any disk.

DemoBackend implements interfaces.PlatformBackend with a fixed set of
realistic drives (a usable USB stick, one that fails while writing, a
write-protected SD card, internal disks, one with an older beast-booter on it, ...). Its run_elevated() does not ask
for administrator rights; it starts the command as a normal process. The demo
controller points the command at fake_cli.py instead of the real CLI, so
nothing is ever written.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from ..errors import BeastError
from ..installed import InstalledBoot, ProbeResult
from ..interfaces import DiskInfo
from ..layout import LAYOUT_VERSION, MIB
from . import distinfo, fake_cli
from .localproc import LocalProcess

GB = 1000**3
FAKE_CLI = Path(__file__).resolve().with_name("fake_cli.py")
# A drive that already has an older beast-booter: the window offers Update boot files.
OLD_BEAST = "Kingston DataTraveler Max"
OLD_BOOT = InstalledBoot("0.0.9", "0000demo0000", 2, install_id="demo", how="demo")
# ... with a firmware pack on it (an installed.json entry, as `firmware install` writes it)
OLD_BEAST_PACKS = [{
    "id": "intel-wifi", "catalog_tag": "20260915", "kernel": "",
    "cpio_sha256": "6f1c0d5a9e3b47c28d1e5f60a7b9c3d2e4f5061728394a5b6c7d8e9f0a1b2c3d",
    "files": [{"path": p, "sha256": h * 64, "size": s} for p, h, s in (
        ("LICENSES/LICENCE.iwlwifi_firmware", "1", 2046), ("iwlwifi-ty-a0-gf-a0-89.ucode", "2", 1_819_296),
        ("iwlwifi-so-a0-gf-a0-89.ucode", "3", 1_822_092), ("iwlwifi-cc-a0-77.ucode", "4", 1_571_516),
        ("intel/iwlwifi/iwlwifi-gl-c0-fm-c0-c101.ucode", "5", 2_092_308))],
}]


def _ids(platform: str) -> list[tuple[str, str]]:
    if platform == "windows":
        return [(rf"\\.\PhysicalDrive{n}", rf"\\.\PhysicalDrive{n}") for n in range(1, 9)]
    if platform == "darwin":
        return [(f"/dev/disk{n}", f"/dev/rdisk{n}") for n in range(4, 12)]
    return [(f"/dev/sd{c}", f"/dev/sd{c}") for c in "bcdefghi"]


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
        (OLD_BEAST, 64 * GB, "usb", True, False, False, ()),
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
        # What probe_installed reports, by disk id; a successful (simulated) install or update changes it.
        self.installed: dict[str, InstalledBoot] = {d.id: OLD_BOOT for d in self._disks if d.model == OLD_BEAST}

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

    def probe_installed(self, disk: DiskInfo, *, should_stop=None) -> ProbeResult | None:
        boot = self.installed.get(disk.id)
        if boot is None:
            return None
        if should_stop is not None and should_stop():
            return ProbeResult(None, "stopped before mounting")
        time.sleep(self.list_delay / 2)  # real probes may mount the boot partition for a moment
        return ProbeResult(dataclasses.replace(boot, firmware=self._firmware(disk)))

    # The fake CLI keeps the drives' firmware packs in a state file; the probe reads the same.
    @staticmethod
    def _fw_state() -> tuple[str, dict]:
        path = fake_cli._fw_state_path(SimpleNamespace(fake_state=None))
        return path, fake_cli._fw_load(path)

    def _firmware(self, disk: DiskInfo) -> dict:
        _, state = self._fw_state()
        packs = state.get(disk.id, OLD_BEAST_PACKS if disk.model == OLD_BEAST else [])
        return fake_cli._fw_result(packs, disk.id)

    def _set_fw_state(self, disk: DiskInfo, packs: list | None) -> None:
        """Write the packs the fake CLI will see on `disk` (None: those the probe reports)."""
        path, state = self._fw_state()
        if packs is None:
            if disk.id in state:
                return
            packs = self._firmware(disk)["packs"]
        state[disk.id] = [{k: v for k, v in p.items() if k != "cpio_size"} for p in packs]
        try:
            fake_cli._fw_save(path, state)
        except OSError:
            pass  # demo only: the fake CLI then sees no packs

    def run_elevated(self, argv: list[str]) -> LocalProcess:
        """No elevation: run the (fake) CLI as a normal process."""
        extra = ["--fake-delay", str(self.step_delay)]
        on_ok = None
        if "--device" in argv:
            disk = self.get_disk(argv[argv.index("--device") + 1])
            if "fails" in disk.model:
                extra += ["--fake-fail-at", "write-firmware" if "firmware" in argv else "write-esp"]
            if len(argv) > 5 and argv[5] in ("install", "update") and "--dist" in argv:
                dist = Path(argv[argv.index("--dist") + 1])
                on_ok = functools.partial(self._installed_now, disk, dist, argv[5])
            elif len(argv) > 5 and argv[5] == "firmware" and disk.id in self.installed:
                self._set_fw_state(disk, None)  # `firmware list` agrees with what the probe showed
        return _DemoRun(argv + extra, os.devnull, on_ok)

    def _installed_now(self, disk: DiskInfo, dist: Path, action: str) -> None:
        s = distinfo.read_summary(distinfo.DistLocation(dist, "demo"))
        self.installed[disk.id] = InstalledBoot(s.version, s.build_id, LAYOUT_VERSION, install_id="demo", how="demo")
        if action == "install":
            self._set_fw_state(disk, [])  # erased: no packs any more


class _DemoRun(LocalProcess):
    """The fake CLI's process; when it succeeds, the drive "has" this app's boot files."""

    def __init__(self, argv: list[str], output_path: str, on_ok):
        super().__init__(argv, output_path)
        self._on_ok = on_ok

    def _done(self, rc: int | None) -> int | None:
        if rc == 0 and self._on_ok is not None:
            on_ok, self._on_ok = self._on_ok, None
            on_ok()
        return rc

    def poll(self) -> int | None:
        return self._done(super().poll())

    def wait(self, timeout: float | None = None) -> int:
        rc = super().wait(timeout)
        self._done(rc)
        return rc
