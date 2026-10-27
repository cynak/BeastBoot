"""QEMU command lines for beast-boot VMs: the one place that knows the flags.

Used by `bb-dev vm` (bbdev/commands/vm.py) and by the e2e harness
(tests/e2e/bbe2e/qemu.py). Building a command is pure: nothing here starts
QEMU. Only make_vars() (copies firmware vars, runs virt-fw-vars) and
display_backends() (runs `qemu -display help`) touch the outside world.

Firmware profiles
  bios     SeaBIOS: -bios bios-256k.bin
  uefi     OVMF_CODE_4M.fd (read-only pflash 0) + a writable copy of
           OVMF_VARS_4M.fd (pflash 1)
  uefi-sb  OVMF_CODE_4M.secboot.fd, q35 with SMM, secure pflash, vars from
           OVMF_VARS_4M.ms.fd (Microsoft keys, Secure Boot on). "Enrolled"
           vars also carry the beast-boot certificate in MokList
           (virt-fw-vars --add-mok), which is exactly what enrolling it in
           MokManager does. Nothing here disables or bypasses verification.

Variable stores (make_vars kinds)
  plain    copy of OVMF_VARS_4M.fd              (uefi)
  ms       copy of OVMF_VARS_4M.ms.fd           (uefi-sb, key not enrolled)
  ms+mok   OVMF_VARS_4M.ms.fd + MokList entries (uefi-sb, key enrolled)

Flags that matter on the development host (tests/e2e/README.md has the story)
  - KVM: `-machine ...,kernel-irqchip=split` and `-cpu host`. With KVM's
    in-kernel IOAPIC, OVMF hangs in BDS on most boots from AHCI/USB/NVMe
    disks (kernel 7.0); a userspace IOAPIC is reliable and faster.
  - `-nodefaults -device VGA`: no empty CD-ROM, floppy or NIC for the
    firmware to try booting from.
  - `-L .tools/root/usr/share/seabios -L .tools/root/usr/share/qemu`: the
    relocated .tools QEMU otherwise looks for vgabios-*.bin and option ROMs in
    the host's /usr/share/qemu, which lacks the SeaBIOS files.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping, Sequence

FIRMWARES = ("bios", "uefi", "uefi-sb")
BUSES = ("usb", "sata", "virtio", "nvme")
BUS_ALIASES = {"ide": "sata", "ahci": "sata"}
VARS_KINDS = ("plain", "ms", "ms+mok")
SERIAL_BACKENDS = ("stdio", "pty", "file", "none")

DRIVE_ID = "bbdisk"
CDROM_ID = "bbcd"
SERIAL_ID = "ser0"
DEBUGCON_IOBASE = "0x402"  # OVMF and SeaBIOS both write their debug log to this port
DEFAULT_GDB_PORT = 1234
VNC_BASE_PORT = 5900

# Unix socket paths are limited to 108 bytes including the NUL (sun_path).
MAX_UNIX_PATH = 107


class QemuError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Firmware files and search paths
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Firmware:
    """Where the firmware images live (BB_OVMF_DIR / BB_SEABIOS_DIR)."""

    ovmf_dir: Path
    seabios_dir: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Firmware:
        env = os.environ if env is None else env
        return cls(Path(env.get("BB_OVMF_DIR") or "/usr/share/OVMF"),
                   Path(env.get("BB_SEABIOS_DIR") or "/usr/share/seabios"))

    @property
    def seabios(self) -> Path:
        return self.seabios_dir / "bios-256k.bin"

    @property
    def ovmf_code(self) -> Path:
        return self.ovmf_dir / "OVMF_CODE_4M.fd"

    @property
    def ovmf_code_secboot(self) -> Path:
        return self.ovmf_dir / "OVMF_CODE_4M.secboot.fd"

    @property
    def ovmf_vars(self) -> Path:
        return self.ovmf_dir / "OVMF_VARS_4M.fd"

    @property
    def ovmf_vars_ms(self) -> Path:
        return self.ovmf_dir / "OVMF_VARS_4M.ms.fd"

    def code(self, firmware: str) -> Path:
        check_firmware(firmware)
        if firmware == "bios":
            return self.seabios
        return self.ovmf_code_secboot if firmware == "uefi-sb" else self.ovmf_code

    def vars_template(self, kind: str) -> Path:
        if kind == "plain":
            return self.ovmf_vars
        if kind in ("ms", "ms+mok"):
            return self.ovmf_vars_ms
        raise ValueError(f"unknown vars kind {kind!r} (expected one of {VARS_KINDS})")

    def missing(self, firmware: str, vars_kind: str | None = None) -> list[Path]:
        need = [self.code(firmware)]
        if firmware != "bios":
            need.append(self.vars_template(vars_kind or default_vars_kind(firmware)))
        return [p for p in need if not p.exists()]


def check_firmware(firmware: str) -> None:
    if firmware not in FIRMWARES:
        raise ValueError(f"unknown firmware {firmware!r} (expected one of {FIRMWARES})")


def default_vars_kind(firmware: str, enrolled: bool = False) -> str | None:
    check_firmware(firmware)
    if firmware == "bios":
        return None
    if firmware == "uefi":
        return "plain"
    return "ms+mok" if enrolled else "ms"


def data_dirs(root: Path, seabios_dir: Path) -> list[Path]:
    """Directories passed to QEMU with -L, in search order (existing ones only).

    The .tools seabios package has vgabios-*.bin / bios-256k.bin, the .tools
    qemu data dir has the NIC and EFI option ROMs.
    """
    tools = Path(root) / ".tools" / "root" / "usr" / "share"
    cands = [tools / "seabios", Path(seabios_dir), tools / "qemu", Path("/usr/share/seabios"), Path("/usr/share/qemu")]
    out: list[Path] = []
    for c in cands:
        if c.is_dir() and c not in out:
            out.append(c)
    return out


def kvm_usable(dev: str = "/dev/kvm") -> bool:
    return os.access(dev, os.R_OK | os.W_OK)


def find_qemu(env: Mapping[str, str] | None = None) -> str | None:
    env = os.environ if env is None else env
    return shutil.which("qemu-system-x86_64", path=env.get("PATH"))


# ---------------------------------------------------------------------------
# UEFI variable stores
# ---------------------------------------------------------------------------

def make_vars(kind: str, dest: Path, *, firmware: Firmware, mok_certs: Sequence[Path] = (),
              owner_guid: str = "", env: Mapping[str, str] | None = None, timeout: float = 60) -> Path:
    """Create a writable UEFI variable store at `dest`.

    kind "ms+mok" pre-enrolls `mok_certs` in MokList with virt-fw-vars, under
    `owner_guid` (any GUID works; shim only looks at the certificate).
    """
    dest = Path(dest)
    template = firmware.vars_template(kind)
    if kind != "ms+mok":
        shutil.copyfile(template, dest)
        return dest
    if not mok_certs:
        raise ValueError("vars kind 'ms+mok' needs at least one certificate")
    if not owner_guid:
        raise ValueError("vars kind 'ms+mok' needs an owner GUID")
    cmd = ["virt-fw-vars", "--input", str(template), "--output", str(dest)]
    for cert in mok_certs:
        cmd += ["--add-mok", owner_guid, str(cert)]
    env = dict(os.environ if env is None else env)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError:
        raise QemuError("virt-fw-vars not found (source scripts/dev-env.sh; scripts/bootstrap-tools.sh installs it)")
    if p.returncode != 0:
        raise RuntimeError(
            f"command failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
            f"--- stdout ---\n{p.stdout}\n--- stderr ---\n{p.stderr}"
        )
    return dest


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def normalise_bus(bus: str) -> str:
    bus = BUS_ALIASES.get(bus, bus)
    if bus not in BUSES:
        raise ValueError(f"unknown bus {bus!r} (expected one of {BUSES})")
    return bus


def qopt(value) -> str:
    """Escape a value for a QEMU option list (a comma is written as ',,')."""
    return str(value).replace(",", ",,")


@dataclass(frozen=True)
class Serial:
    """Where serial port 0 goes.

    stdio  QEMU's stdin/stdout. mux=True adds QEMU's Ctrl-A escape keys
           (Ctrl-A x quits, Ctrl-A h lists them).
    pty    a new pseudo terminal (QEMU prints its /dev/pts path)
    file   output only, written to `path`
    none   no serial port
    logfile (stdio, pty): a copy of everything the guest writes.
    """

    backend: str = "stdio"
    path: Path | None = None
    logfile: Path | None = None
    mux: bool = False

    def args(self) -> list[str]:
        b = self.backend
        if b not in SERIAL_BACKENDS:
            raise ValueError(f"unknown serial backend {b!r} (expected one of {SERIAL_BACKENDS})")
        if b == "none":
            return ["-serial", "none"]
        if b == "file":
            if not self.path:
                raise ValueError("serial backend 'file' needs a path")
            spec = f"file,id={SERIAL_ID},path={qopt(self.path)}"
        else:
            spec = f"{b},id={SERIAL_ID}"
            if b == "stdio":
                if self.mux:
                    spec += ",mux=on"
                spec += ",signal=off"
            if self.logfile:
                spec += f",logfile={qopt(self.logfile)},logappend=off"
        return ["-chardev", spec, "-serial", f"chardev:{SERIAL_ID}"]


def bus_devices(bus: str, drive_id: str = DRIVE_ID) -> list[str]:
    bus = normalise_bus(bus)
    if bus == "usb":
        return ["-device", "qemu-xhci,id=xhci",
                "-device", f"usb-storage,bus=xhci.0,drive={drive_id},removable=on,bootindex=0"]
    if bus == "sata":  # q35's built-in ICH9 AHCI controller
        return ["-device", f"ide-hd,drive={drive_id},bootindex=0"]
    if bus == "nvme":
        return ["-device", f"nvme,serial=beastbooter,drive={drive_id},bootindex=0"]
    return ["-device", f"virtio-blk-pci,drive={drive_id},bootindex=0"]


@dataclass
class QemuSpec:
    """Everything that decides a beast-boot QEMU command line.

    `argv()` emits the options in a fixed order, so the same spec always gives
    the same command (the e2e harness relies on this).
    """

    qemu: str
    disk: Path
    firmware: str = "uefi"
    files: Firmware | None = None
    vars_file: Path | None = None
    name: str | None = None
    bus: str = "usb"
    memory: int = 1024
    smp: int = 1
    kvm: bool = False
    data_dirs: Sequence[Path] = ()
    cache: str = "unsafe"
    snapshot: bool = False
    cdrom: Path | None = None
    display: str = "none"  # none | gtk | vnc=HOST:N (passed to -display as is)
    monitor: Path | None = None  # HMP on a unix socket; None = -monitor none
    qmp: Path | None = None  # QMP on a unix socket
    serial: Serial = Serial()
    no_reboot: bool = False
    fw_debug_log: Path | None = None  # isa-debugcon at 0x402 -> file
    gdb_port: int | None = None
    gdb_host: str = "127.0.0.1"
    wait_gdb: bool = False  # start paused (-S)
    pidfile: Path | None = None
    extra: Sequence[str] = ()

    @property
    def secure_boot(self) -> bool:
        return self.firmware == "uefi-sb"

    def machine(self) -> str:
        m = "q35,smm=on" if self.secure_boot else "q35"
        if self.kvm:
            m += ",kernel-irqchip=split"
        return m

    def firmware_args(self) -> list[str]:
        check_firmware(self.firmware)
        files = self.files or Firmware.from_env()
        if self.firmware == "bios":
            return ["-bios", str(files.seabios)]
        if not self.vars_file:
            raise ValueError(f"firmware {self.firmware!r} needs a vars file")
        out = []
        if self.secure_boot:
            out += ["-global", "driver=cfi.pflash01,property=secure,value=on"]
        out += [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={qopt(files.code(self.firmware))}",
            "-drive", f"if=pflash,format=raw,unit=1,file={qopt(self.vars_file)}",
        ]
        return out

    def disk_args(self) -> list[str]:
        drive = f"if=none,id={DRIVE_ID},format=raw,cache={self.cache}"
        if self.snapshot:
            drive += ",snapshot=on"
        drive += f",file={qopt(self.disk)}"
        out = ["-drive", drive] + bus_devices(self.bus)
        if self.cdrom:
            out += ["-drive", f"if=none,id={CDROM_ID},media=cdrom,format=raw,readonly=on,file={qopt(self.cdrom)}",
                    "-device", f"ide-cd,drive={CDROM_ID},bootindex=1"]
        return out

    def argv(self) -> list[str]:
        cmd = [self.qemu]
        if self.name:
            cmd += ["-name", qopt(self.name)]
        # -nodefaults: only the devices asked for below.
        cmd += ["-nodefaults", "-machine", self.machine(), "-m", str(self.memory), "-smp", str(self.smp)]
        cmd += ["-accel", "kvm", "-cpu", "host"] if self.kvm else ["-accel", "tcg"]
        for d in self.data_dirs:
            cmd += ["-L", str(d)]
        cmd += self.firmware_args()
        cmd += self.disk_args()
        cmd += ["-device", "VGA", "-display", self.display]
        cmd += ["-monitor", f"unix:{qopt(self.monitor)},server=on,wait=off" if self.monitor else "none"]
        if self.qmp:
            cmd += ["-qmp", f"unix:{qopt(self.qmp)},server=on,wait=off"]
        cmd += self.serial.args()
        if self.no_reboot:
            cmd.append("-no-reboot")
        if self.fw_debug_log:
            cmd += ["-debugcon", f"file:{self.fw_debug_log}", "-global", f"isa-debugcon.iobase={DEBUGCON_IOBASE}"]
        if self.gdb_port is not None:
            cmd += ["-gdb", f"tcp:{self.gdb_host}:{int(self.gdb_port)}"]
        if self.wait_gdb:
            cmd.append("-S")
        if self.pidfile:
            cmd += ["-pidfile", str(self.pidfile)]
        cmd += [str(a) for a in self.extra]
        return cmd


# ---------------------------------------------------------------------------
# Displays
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=8)
def _display_help(qemu: str, path: str, ld_path: str) -> tuple[str, ...]:
    env = dict(os.environ, PATH=path)
    if ld_path:
        env["LD_LIBRARY_PATH"] = ld_path
    try:
        p = subprocess.run([qemu, "-display", "help"], capture_output=True, text=True, timeout=20, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if p.returncode != 0:
        return ()
    names = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if re.fullmatch(r"[a-z][a-z0-9-]*", line):
            names.append(line)
    return tuple(names)


def display_backends(qemu: str, env: Mapping[str, str] | None = None) -> set[str]:
    """Display backends this QEMU can load (`-display help` only lists UI
    modules that actually load, e.g. gtk needs the qemu-system-gui module)."""
    env = os.environ if env is None else env
    return set(_display_help(qemu, env.get("PATH", ""), env.get("LD_LIBRARY_PATH", "")))


def gui_session(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def gtk_status(qemu: str | None, env: Mapping[str, str] | None = None) -> tuple[bool, str]:
    """(usable, reason) for -display gtk."""
    env = os.environ if env is None else env
    if not qemu:
        return False, "qemu-system-x86_64 not found"
    if not gui_session(env):
        return False, "no graphical session (DISPLAY and WAYLAND_DISPLAY are unset)"
    if "gtk" not in display_backends(qemu, env):
        return False, ("this QEMU cannot load its GTK UI module (package qemu-system-gui; "
                       "scripts/bootstrap-tools.sh installs it into .tools)")
    conflict = gtk3_gsettings_conflict(env)
    if conflict:
        return False, conflict
    return True, ""


def gtk3_gsettings_conflict(env: Mapping[str, str] | None = None) -> str:
    """Why GTK 3 would abort on this desktop, or "" if it should be fine.

    GNOME 50 removed the 'antialiasing' key from the
    org.gnome.settings-daemon.plugins.xsettings schema, but GTK 3 (which QEMU's
    GTK window uses) still reads it and aborts with
    "Settings schema ... does not contain a key named 'antialiasing'".
    """
    env = os.environ if env is None else env
    gs = shutil.which("gsettings", path=env.get("PATH"))
    if not gs:
        return ""
    try:
        out = subprocess.run([gs, "list-keys", "org.gnome.settings-daemon.plugins.xsettings"],
                             capture_output=True, text=True, timeout=5, env=dict(env))
    except (OSError, subprocess.SubprocessError):
        return ""
    if out.returncode != 0:  # schema not installed: GTK 3 does not look for the key
        return ""
    if "antialiasing" in out.stdout.split():
        return ""
    return ("GTK 3 aborts on this desktop: GNOME's xsettings schema no longer has the "
            "'antialiasing' key GTK reads")


def sdl_status(qemu: str | None, env: Mapping[str, str] | None = None) -> tuple[bool, str]:
    """(usable, reason) for -display sdl."""
    env = os.environ if env is None else env
    if not qemu:
        return False, "qemu-system-x86_64 not found"
    if not gui_session(env):
        return False, "no graphical session (DISPLAY and WAYLAND_DISPLAY are unset)"
    if "sdl" not in display_backends(qemu, env):
        return False, "this QEMU cannot load its SDL UI module (package qemu-system-gui)"
    return True, ""


def free_vnc_display(host: str = "127.0.0.1", first: int = 0, last: int = 99) -> int:
    """First VNC display number N (TCP port 5900+N) nobody listens on."""
    for n in range(first, last + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, VNC_BASE_PORT + n))
            return n
        except PermissionError:
            return n  # cannot probe (sandbox): take the first one
        except OSError:
            continue
    raise QemuError(f"no free VNC display on {host} (ports {VNC_BASE_PORT + first}-{VNC_BASE_PORT + last})")


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Can QEMU listen on host:port? (SO_REUSEADDR like QEMU, so TIME_WAIT leftovers do not count.)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        return True
    except PermissionError:
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Talking to a running QEMU
# ---------------------------------------------------------------------------

class QMP:
    """Minimal QMP client on a unix socket (connects on first use)."""

    def __init__(self, path: Path):
        self.path = str(path)
        self.sock: socket.socket | None = None
        self._buf = b""

    def _connect(self, timeout: float = 5.0) -> None:
        end = time.monotonic() + timeout
        while True:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(self.path)
                self.sock = s
                break
            except OSError:
                if time.monotonic() > end:
                    raise
                time.sleep(0.05)
        self._read_msg()  # greeting
        self.cmd("qmp_capabilities")

    def _read_msg(self) -> dict:
        assert self.sock is not None
        while b"\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("QMP connection closed")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line)

    def cmd(self, name: str, **args) -> dict:
        if self.sock is None:
            self._connect()
        msg = {"execute": name}
        if args:
            msg["arguments"] = args
        self.sock.sendall(json.dumps(msg).encode() + b"\n")
        while True:
            r = self._read_msg()
            if "return" in r:
                return r["return"]
            if "error" in r:
                raise RuntimeError(f"QMP {name}: {r['error']}")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class Monitor:
    """Human monitor (HMP) on a unix socket: `Monitor(path).cmd("sendkey ret")`."""

    PROMPT = b"(qemu) "

    def __init__(self, path: Path, timeout: float = 5.0):
        self.path = str(path)
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def _read_prompt(self) -> str:
        assert self.sock is not None
        buf = b""
        while not buf.endswith(self.PROMPT):
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        return buf.decode(errors="replace")

    def _connect(self) -> None:
        end = time.monotonic() + self.timeout
        while True:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(self.path)
                self.sock = s
                break
            except OSError:
                if time.monotonic() > end:
                    raise
                time.sleep(0.05)
        self._read_prompt()  # banner

    def cmd(self, line: str) -> str:
        if self.sock is None:
            self._connect()
        self.sock.sendall(line.encode() + b"\n")
        out = self._read_prompt()
        # Drop the echoed command and the trailing prompt.
        out = out[: -len(self.PROMPT)] if out.endswith(self.PROMPT.decode()) else out
        out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out).replace("\r", "")
        lines = out.split("\n")
        if lines and lines[0].strip().endswith(line.strip()):
            lines = lines[1:]
        return "\n".join(lines).strip()

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> Monitor:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
