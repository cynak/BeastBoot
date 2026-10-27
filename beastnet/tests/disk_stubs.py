"""Stand-ins for the storage tools (no root, no device-mapper) in the disk tests."""

from __future__ import annotations

import os
import subprocess
import types

from beastnet.events import Reporter
from beastnet.paths import Paths


class DiskRunner:
    """Answers losetup/dmsetup/mdadm/blockdev/mount like the real tools, records argv+env."""

    def __init__(self, paths: Paths, sizes: dict[str, int] | None = None) -> None:
        self.paths = paths
        self.sizes = sizes or {}
        self.calls: list[list[str]] = []
        self.envs: list[dict | None] = []
        self.rc: dict[str, int] = {}          # argv[0] (or "dmsetup create") -> exit code
        self.status: dict[str, str] = {}      # dm name -> `dmsetup status` line
        self.dm: dict[str, str] = {}          # dm name -> table
        self.knames: dict[str, str] = {}
        self.loops = 0
        self.mount_ok = True

    def _mounts(self) -> str:
        return os.path.join(self.paths.proc, "mounts")

    def run(self, argv, *, timeout=60, env=None, input=None):
        argv = list(argv)
        self.calls.append(argv)
        self.envs.append(env)
        ok = subprocess.CompletedProcess(argv, 0, "", "")
        key = " ".join(argv[:2]) if argv[0] in ("dmsetup", "mdadm") else argv[0]
        if key in self.rc:
            return subprocess.CompletedProcess(argv, self.rc[key], "", f"{key} failed")
        if argv[:2] == ["blockdev", "--getsize64"]:
            return subprocess.CompletedProcess(argv, 0, f"{self.sizes.get(argv[2], 64 << 20)}\n", "")
        if argv[:3] == ["losetup", "--find", "--show"]:
            self.loops += 1
            return subprocess.CompletedProcess(argv, 0, f"/dev/loop{self.loops - 1}\n", "")
        if argv[:2] == ["dmsetup", "create"]:
            name = argv[2]
            self.dm[name] = argv[argv.index("--table") + 1]
            self.knames[name] = f"dm-{len(self.knames)}"
            sz = int(self.dm[name].splitlines()[-1].split()[0]) + int(self.dm[name].splitlines()[-1].split()[1])
            self.sizes[f"/dev/mapper/{name}"] = sz * 512
            return ok
        if argv[:2] == ["dmsetup", "info"]:
            return subprocess.CompletedProcess(argv, 0, self.knames.get(argv[-1], "") + "\n", "")
        if argv[:2] == ["dmsetup", "status"]:
            line = self.status.get(argv[2], "0 131072 snapshot 16/131072 16")
            return subprocess.CompletedProcess(argv, 0, line + "\n", "")
        if argv[:2] == ["dmsetup", "remove"]:
            self.dm.pop(argv[-1], None)
            return ok
        if argv[0] == "mount" and argv[2] == "tmpfs":
            if not self.mount_ok:
                return subprocess.CompletedProcess(argv, 32, "", "mount: permission denied")
            with open(self._mounts(), "a") as f:
                f.write(f"bbcow {os.path.realpath(argv[-1])} tmpfs rw 0 0\n")
            return ok
        if argv[0] == "umount":
            path = os.path.realpath(argv[-1])
            with open(self._mounts()) as f:
                lines = [ln for ln in f if ln.split()[1] != path]
            with open(self._mounts(), "w") as f:
                f.writelines(lines)
            return ok
        return ok

    def names(self, prog: str) -> list[list[str]]:
        return [c for c in self.calls if c[0] == prog]


def disk_ctx(tmp_path, sizes=None):
    root = tmp_path / "root"
    (root / "proc").mkdir(parents=True)
    (root / "proc" / "mounts").write_text("rootfs / rootfs rw 0 0\n")
    (root / "proc" / "meminfo").write_text("MemTotal: 4000000 kB\nMemAvailable: 2000000 kB\n")
    (root / "sys" / "block").mkdir(parents=True)
    (root / "run" / "beastnet").mkdir(parents=True)
    paths = Paths(root=str(root))
    runner = DiskRunner(paths, sizes)
    ctx = types.SimpleNamespace(paths=paths, system=types.SimpleNamespace(runner=runner, dry_run=False),
                                reporter=Reporter())
    return ctx, runner
