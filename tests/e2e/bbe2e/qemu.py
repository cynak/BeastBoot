"""QEMU launcher for the e2e tests.

Modes:
  bios      SeaBIOS (-bios bios-256k.bin)
  uefi      OVMF_CODE_4M.fd (read-only pflash) + per-VM copy of OVMF_VARS_4M.fd
  uefi-sb   OVMF_CODE_4M.secboot.fd, q35 with SMM, secure pflash, vars derived
            from OVMF_VARS_4M.ms.fd (Microsoft keys, Secure Boot enabled)

The serial port is QEMU's stdio; a reader thread appends everything to
`<log_dir>/<name>.log` as it arrives, feeds a VT100 screen emulator, and wakes
up waiters. A watchdog kills QEMU after `hard_timeout` seconds no matter what.

The command line itself (firmware, vars, disk bus, KVM flags, -L dirs) comes
from devtools/bbdev/qemu.py, which `bb-dev vm` uses too.
"""

from __future__ import annotations

import codecs
import os
import re
import shutil
import signal
import subprocess
import threading
import tempfile
import time
from pathlib import Path

from . import env
from .env import bbqemu
from .serial import Record, Screen, clean_text, parse_records, plain_text

QMP = bbqemu.QMP  # re-exported: tests use bbe2e.qemu.QMP

MODES = ("bios", "uefi", "uefi-sb")

SERIAL_KEYS = {
    "up": b"\x1b[A",
    "down": b"\x1b[B",
    "right": b"\x1b[C",
    "left": b"\x1b[D",
    "enter": b"\r",
    "esc": b"\x1b",
    "home": b"\x1b[H",
    "end": b"\x1b[F",
}
QMP_KEYS = {"up": "up", "down": "down", "right": "right", "left": "left", "enter": "ret",
            "esc": "esc", "home": "home", "end": "end"}


class WaitTimeout(AssertionError):
    pass


class QemuExited(AssertionError):
    pass


def make_vars(mode: str, dest: Path, mok_certs: list[Path] | tuple = ()) -> Path | None:
    """Create the writable UEFI variable store for one VM."""
    dest = Path(dest)
    if mode == "bios":
        return None
    if mode not in ("uefi", "uefi-sb"):
        raise ValueError(f"unknown mode {mode!r}")
    kind = bbqemu.default_vars_kind(mode, enrolled=bool(mok_certs))
    return bbqemu.make_vars(kind, dest, firmware=env.firmware(), mok_certs=list(mok_certs),
                            owner_guid=env.MOK_OWNER_GUID, env=env.tool_env())


class VM:
    def __init__(
        self,
        name: str,
        *,
        mode: str,
        disk: Path,
        workdir: Path,
        log_dir: Path = env.LOG_DIR,
        vars_file: Path | None = None,
        mok_certs: list[Path] | tuple = (),
        memory: int = 1024,
        smp: int = 1,
        hard_timeout: float = 300,
        disk_if: str | None = None,
        key_method: str | None = None,
        extra_args: list[str] | tuple = (),
        snapshot: bool = False,
    ):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.name = name
        self.mode = mode
        self.disk = Path(disk)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_dir / f"{name}.log"
        self.meta_path = log_dir / f"{name}.qemu.txt"
        self.screen_path = log_dir / f"{name}.screen.txt"
        self.memory = memory
        self.smp = str(smp)
        self.hard_timeout = env.t(hard_timeout)
        self.disk_if = disk_if or env.disk_interface()
        self.key_method = key_method or env.key_method(mode)
        self.extra_args = list(extra_args)
        self.snapshot = snapshot  # writes go to a temporary overlay; `disk` stays unchanged
        if mode != "bios":
            self.vars_file = Path(vars_file) if vars_file else make_vars(mode, self.workdir / f"{name}.vars.fd", mok_certs)
        else:
            self.vars_file = None
        self._sockdir: Path | None = None
        self.qmp_path: Path | None = None
        self.qmp: QMP | None = None
        self.proc: subprocess.Popen | None = None
        self._raw = bytearray()
        self._text = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._lock = threading.Condition()
        self._last_rx = time.monotonic()
        self._clean_cache = (0, "")
        self.screen = Screen()
        self._reader: threading.Thread | None = None
        self._watchdog: threading.Timer | None = None
        self._log = None
        self.hard_timeout_hit = False
        self.started_at = 0.0

    # -- command line ---------------------------------------------------
    def command(self) -> list[str]:
        qemu = env.qemu_binary()
        if not qemu:
            raise RuntimeError("qemu-system-x86_64 not found (source scripts/dev-env.sh)")
        spec = bbqemu.QemuSpec(
            qemu=qemu,
            name=self.name,
            firmware=self.mode,
            files=env.firmware(),
            vars_file=self.vars_file,
            disk=self.disk,
            bus=self.disk_if,
            snapshot=self.snapshot,
            memory=self.memory,
            smp=self.smp,
            kvm=env.kvm_usable(),
            data_dirs=env.qemu_data_dirs(),
            display="none",
            monitor=None,
            qmp=self.qmp_path,
            serial=bbqemu.Serial("stdio"),
            no_reboot=True,
            extra=self.extra_args,
        )
        return spec.argv()

    # -- lifecycle --------------------------------------------------------
    def start(self) -> VM:
        # Unix socket paths are limited to ~107 bytes, so keep it out of the (deep) workdir.
        self._sockdir = Path(tempfile.mkdtemp(prefix="bbe2e-qmp-"))
        self.qmp_path = self._sockdir / "qmp.sock"
        self.qmp = QMP(self.qmp_path)
        cmd = self.command()
        self._log = open(self.log_path, "wb")
        self.meta_path.write_text("command: " + " ".join(cmd) + "\n")
        self.started_at = time.monotonic()
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self._reader = threading.Thread(target=self._read_loop, name=f"serial-{self.name}", daemon=True)
        self._reader.start()
        self._stderr_buf = bytearray()
        threading.Thread(target=self._stderr_loop, daemon=True).start()
        self._watchdog = threading.Timer(self.hard_timeout, self._hard_kill)
        self._watchdog.daemon = True
        self._watchdog.start()
        return self

    def __enter__(self) -> VM:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def _read_loop(self) -> None:
        fd = self.proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            with self._lock:
                self._raw += chunk
                text = self._decoder.decode(chunk)
                self._text += text
                self.screen.feed(text)
                self._last_rx = time.monotonic()
                try:
                    self._log.write(chunk)
                    self._log.flush()
                except (ValueError, OSError):
                    pass
                self._lock.notify_all()
        with self._lock:
            self._lock.notify_all()

    def _stderr_loop(self) -> None:
        for line in self.proc.stderr:
            self._stderr_buf += line

    def _hard_kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.hard_timeout_hit = True
            self._kill()

    def _kill(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc is None:
            return
        if self._watchdog:
            self._watchdog.cancel()
        if self.qmp:
            self.qmp.close()
        if self.proc.poll() is None:
            self._kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if self._reader:
            self._reader.join(timeout=5)
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        with self._lock:
            if self._log:
                self._log.close()
                self._log = None
        if self._sockdir:
            shutil.rmtree(self._sockdir, ignore_errors=True)
        elapsed = time.monotonic() - self.started_at
        with open(self.meta_path, "a") as f:
            f.write(f"exit code: {self.proc.returncode}\nelapsed: {elapsed:.1f}s\n")
            if self.hard_timeout_hit:
                f.write(f"HARD TIMEOUT after {self.hard_timeout:.0f}s: QEMU was killed\n")
            f.write("--- stderr ---\n" + bytes(self._stderr_buf).decode(errors="replace"))
        self.screen_path.write_text(self.screen.text() + "\n")

    def save_failure_artifacts(self) -> list[Path]:
        """Screendump (PNG) while QEMU still runs, plus the emulated serial screen."""
        out = []
        self.screen_path.write_text(self.screen.text() + "\n")
        out.append(self.screen_path)
        if self.running:
            png = self.log_path.with_suffix(".png")
            try:
                self.qmp.cmd("screendump", filename=str(png), format="png")
                out.append(png)
            except Exception as e:  # noqa: BLE001 - best effort
                with open(self.meta_path, "a") as f:
                    f.write(f"screendump failed: {e}\n")
        return out

    # -- input ----------------------------------------------------------
    def send(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        if not self.running:
            raise QemuExited(f"{self.name}: QEMU is not running")
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def key(self, name: str) -> None:
        if self.key_method == "qmp":
            self.qmp.cmd("send-key", keys=[{"type": "qcode", "data": QMP_KEYS[name]}])
        else:
            self.send(SERIAL_KEYS[name])

    def keys(self, *names: str, gap: float = 0.25) -> None:
        for i, n in enumerate(names):
            if i:
                time.sleep(gap)
            self.key(n)

    # -- output ---------------------------------------------------------
    @property
    def raw(self) -> bytes:
        with self._lock:
            return bytes(self._raw)

    def clean(self) -> str:
        with self._lock:
            n = len(self._text)
            if self._clean_cache[0] != n:
                self._clean_cache = (n, clean_text(self._text))
            return self._clean_cache[1]

    def text(self) -> str:
        """Escape-stripped serial output (positioning sequences become newlines)."""
        with self._lock:
            return plain_text(self._text)

    def mark(self) -> int:
        """Position in the cleaned output; pass as `after=` to only see newer output."""
        return len(self.clean())

    def records(self, kind: str | None = None, prefix: str = "BEAST", after: int = 0) -> list[Record]:
        recs = parse_records(self.clean(), final=True)
        return [r for r in recs if r.prefix == prefix and r.start >= after and (kind is None or r.kind == kind)]

    def _idle(self) -> float:
        with self._lock:
            return time.monotonic() - self._last_rx

    def _wait(self, probe, timeout: float, what: str):
        deadline = time.monotonic() + env.t(timeout)
        while True:
            exited = not self.running
            result = probe(final=exited or self._idle() > 0.4)
            if result is not None:
                return result
            if exited:
                time.sleep(0.2)  # let the reader drain
                result = probe(final=True)
                if result is not None:
                    return result
                raise QemuExited(f"{self.name}: QEMU exited (code {self.proc.returncode}) while waiting for {what}"
                                 f"{' [hard timeout]' if self.hard_timeout_hit else ''}\n{self._tail()}")
            if time.monotonic() > deadline:
                raise WaitTimeout(f"{self.name}: timed out after {env.t(timeout):.0f}s waiting for {what}\n{self._tail()}")
            with self._lock:
                self._lock.wait(0.1)

    def _tail(self, n: int = 2500) -> str:
        t = self.text()
        recs = "\n".join(str(r) for r in self.records()[-15:])
        return (f"--- last BEAST records ---\n{recs}\n--- serial tail (escape-stripped) ---\n{t[-n:]}\n"
                f"--- log: {self.log_path}")

    def wait_for(self, pattern: str | re.Pattern, timeout: float = 60, after: int = 0) -> re.Match:
        """Wait for a regex in the escape-stripped output."""
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern

        def probe(final: bool):
            return rx.search(plain_text_from_clean(self.clean()[after:]))

        return self._wait(probe, timeout, f"/{rx.pattern}/")

    def wait_record(self, kind: str | None = None, pattern: str | None = None, *, timeout: float = 60,
                    prefix: str = "BEAST", after: int = 0) -> Record:
        """Wait for the first record of `kind` whose text matches `pattern` (re.search)."""
        rx = re.compile(pattern) if pattern else None

        def probe(final: bool):
            for r in parse_records(self.clean(), final=final):
                if r.prefix != prefix or r.start < after:
                    continue
                if kind is not None and r.kind != kind:
                    continue
                if rx is None or r.matches(rx):
                    return r
            return None

        desc = f"{prefix} record kind={kind!r}" + (f" /{pattern}/" if pattern else "")
        return self._wait(probe, timeout, desc)

    def wait_any_record(self, kinds: tuple[str, ...], *, timeout: float = 60, after: int = 0) -> Record:
        def probe(final: bool):
            for r in parse_records(self.clean(), final=final):
                if r.prefix == "BEAST" and r.start >= after and r.kind in kinds:
                    return r
            return None

        return self._wait(probe, timeout, f"BEAST record of kind {kinds}")

    def wait_menu(self, first_entry: str | None = None, timeout: float = 60, settle: float = 0.5):
        """Wait until a menu box is on the (emulated) screen, optionally with a given first entry."""

        def probe(final: bool):
            with self._lock:
                m = self.screen.menu()
            if m and m.entries and (first_entry is None or m.entries[0] == first_entry):
                return m
            return None

        self._wait(probe, timeout, f"menu (first entry {first_entry!r})")
        # GRUB starts polling for keys once it has finished drawing: wait for the
        # output to go quiet (bounded, a countdown keeps redrawing).
        end = time.monotonic() + 5
        while self._idle() < settle and time.monotonic() < end:
            time.sleep(0.05)
        with self._lock:
            return self.screen.menu()

    def menu(self):
        """The GRUB menu on the emulated serial screen right now, or None."""
        with self._lock:
            return self.screen.menu()

    def expect_absent(self, pattern: str, *, within: float, after: int = 0) -> None:
        """Assert a regex does NOT appear in the output for `within` seconds (or until QEMU exits)."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + within
        while time.monotonic() < deadline and self.running:
            if rx.search(plain_text_from_clean(self.clean()[after:])):
                break
            time.sleep(0.1)
        m = rx.search(plain_text_from_clean(self.clean()[after:]))
        if m:
            raise AssertionError(f"{self.name}: unexpected output /{pattern}/: {m.group(0)!r}\n{self._tail()}")

    def wait_exit(self, timeout: float = 60) -> int:
        try:
            return self.proc.wait(timeout=env.t(timeout))
        except subprocess.TimeoutExpired:
            raise WaitTimeout(f"{self.name}: QEMU did not exit within {env.t(timeout):.0f}s\n{self._tail()}")


def plain_text_from_clean(clean: str) -> str:
    from .serial import BOUNDARY

    return clean.replace(BOUNDARY, "\n")
