"""Running programs and the few system actions: sync, unmount, reboot, shell."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Sequence

from .paths import Paths


class Runner:
    """subprocess.run with captured text output that never raises for a
    missing program or a timeout (it returns exit codes 127 and 124)."""

    def __init__(self, log_path: str | None = None) -> None:
        self.log_path = log_path

    def _log(self, argv: Sequence[str], rc: int, out: str, err: str) -> None:
        if not self.log_path:
            return
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%H:%M:%S')} $ {' '.join(argv)} -> {rc}\n")
                for text in (out, err):
                    if text.strip():
                        f.write("    " + text.strip().replace("\n", "\n    ") + "\n")
        except OSError:
            pass

    def run(self, argv: Sequence[str], *, timeout: float = 60, env: dict | None = None,
            input: str | None = None) -> subprocess.CompletedProcess:
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        try:
            cp = subprocess.run(list(argv), capture_output=True, text=True, errors="replace",
                                timeout=timeout, env=full_env, input=input,
                                stdin=None if input is not None else subprocess.DEVNULL)
        except FileNotFoundError:
            cp = subprocess.CompletedProcess(list(argv), 127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            cp = subprocess.CompletedProcess(list(argv), 124, out, f"{argv[0]}: timed out")
        except OSError as e:
            cp = subprocess.CompletedProcess(list(argv), 126, "", f"{argv[0]}: {e.strerror}")
        self._log(argv, cp.returncode, cp.stdout, cp.stderr)
        return cp


def modaliases(sys_root: str) -> list[str]:
    """Every device's modalias under /sys/devices (for coldplug)."""
    out: set[str] = set()
    for dirpath, _dirs, files in os.walk(os.path.join(sys_root, "devices")):
        if "modalias" in files:
            try:
                with open(os.path.join(dirpath, "modalias"), encoding="ascii", errors="replace") as f:
                    alias = f.read().strip()
            except OSError:
                continue
            if alias:
                out.add(alias)
    return sorted(out)


class System:
    def __init__(self, paths: Paths, runner: Runner, *, dry_run: bool,
                 say: Callable[[str], None] | None = None) -> None:
        self.paths = paths
        self.runner = runner
        self.dry_run = dry_run
        self.say = say or (lambda text: None)

    def sync(self) -> None:
        try:
            os.sync()
        except OSError:
            pass

    def rescan_hardware(self, rounds: int = 2) -> None:
        """Load drivers for devices that appeared late (USB adapters)."""
        if self.dry_run:
            return
        for _ in range(rounds):
            aliases = modaliases(self.paths.sys)
            for i in range(0, len(aliases), 200):
                self.runner.run(["modprobe", "-qab", *aliases[i:i + 200]], timeout=120)
            self.runner.run(["mdev", "-s"], timeout=60)
            time.sleep(0.5)

    def unmount(self) -> None:
        for mnt in (self.paths.esp, self.paths.data):
            if self.dry_run:
                self.say(f"[dry-run] would unmount {mnt}")
                continue
            if self.runner.run(["umount", mnt], timeout=60).returncode != 0:
                self.runner.run(["mount", "-o", "remount,ro", mnt], timeout=60)

    def _halt(self, how: str) -> None:
        self.sync()
        self.unmount()
        self.sync()
        if self.dry_run:
            self.say(f"[dry-run] would {how} now")
            return
        # -f: call reboot(2) directly. We are not PID 1 (the init script is),
        # and everything that matters is already synced and unmounted.
        self.runner.run([how, "-f"], timeout=30)
        time.sleep(30)
        raise RuntimeError(f"{how} did not happen")

    def reboot(self) -> None:
        self._halt("reboot")

    def poweroff(self) -> None:
        self._halt("poweroff")

    def shell(self) -> int:
        """An interactive shell on our terminal; returns when the user exits."""
        env = dict(os.environ)
        env["PS1"] = "beast-net# "
        print("\nbeast-net shell. Type 'exit' to go back to beast-net.\n", flush=True)
        for sh in ("/bin/sh", "/usr/bin/sh"):
            if os.path.exists(sh):
                try:
                    return subprocess.call([sh], env=env)
                except OSError:
                    continue
        print("no shell found", flush=True)
        return 127

    def set_clock(self, utc: str) -> bool:
        """Set the system clock from 'YYYY-MM-DD HH:MM' (UTC), for this session
        only: the hardware clock is left alone (Windows may keep it in local time)."""
        if self.dry_run:
            self.say(f"[dry-run] would set the clock to {utc} UTC")
            return True
        return self.runner.run(["date", "-u", "-s", utc], timeout=10).returncode == 0
