"""Paths, tool discovery and timing for the e2e suite.

Everything is derived from the environment that `source scripts/dev-env.sh`
sets up; the BB_E2E_* variables below are optional overrides.

  BB_E2E_OUT            output directory (default: $BB_ROOT/out/e2e)
  BB_E2E_DIST           dist/ directory to install from (default: $BB_ROOT/dist)
  BB_E2E_KVM            1 = require KVM, 0 = never use it (default: use if usable)
  BB_E2E_TIMEOUT_SCALE  multiply every timeout (default 1, or 4 without KVM)
  BB_E2E_DISK_IF        how the drive is attached: usb (default), ide, virtio
  BB_E2E_KEYS           how keys are sent: serial or qmp (PS/2 via QMP send-key); default
                        qmp for UEFI modes and serial for BIOS (see key_method())
  BB_E2E_KEEP           1 = keep per-test work directories (disk copies, vars) even on success
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from pathlib import Path

E2E_DIR = Path(__file__).resolve().parents[1]

# QEMU flags live in devtools/bbdev/qemu.py, shared with `bb-dev vm`.
DEVTOOLS_DIR = E2E_DIR.parents[1] / "devtools"
if str(DEVTOOLS_DIR) not in sys.path:
    sys.path.append(str(DEVTOOLS_DIR))

from bbdev import qemu as bbqemu  # noqa: E402


def _root() -> Path:
    env = os.environ.get("BB_ROOT")
    if env:
        return Path(env).resolve()
    return E2E_DIR.parents[1]


BB_ROOT = _root()
OUT = Path(os.environ.get("BB_E2E_OUT", BB_ROOT / "out" / "e2e")).resolve()
LOG_DIR = OUT / "logs"
WORK_DIR = OUT / "work"
IMAGE_DIR = OUT / "images"
FIXTURE_DIR = OUT / "fixtures"
SELFTEST_DIR = OUT / "selftest"

DIST = Path(os.environ.get("BB_E2E_DIST", BB_ROOT / "dist")).resolve()
KEYS_DIR = BB_ROOT / "keys"
INSTALLER_DIR = BB_ROOT / "installer"

OVMF_DIR = Path(os.environ.get("BB_OVMF_DIR", "/usr/share/OVMF"))
SEABIOS_DIR = Path(os.environ.get("BB_SEABIOS_DIR", "/usr/share/seabios"))
GRUB_EFI_DIR = Path(os.environ.get("BB_GRUB_EFI_DIR", "/usr/lib/grub/x86_64-efi"))
GRUB_EFI_SIGNED_DIR = Path(os.environ.get("BB_GRUB_EFI_SIGNED_DIR", "/usr/lib/grub/x86_64-efi-signed"))
GRUB_BIOS_DIR = Path(os.environ.get("BB_GRUB_BIOS_DIR", "/usr/lib/grub/i386-pc"))
# Debian's shim + MokManager (build/shim/debian-shim.lock, unpacked by scripts/bootstrap-tools.sh)
SHIM_DIR = Path(os.environ.get("BB_SHIM_DIR", BB_ROOT / ".tools" / "debian" / "root" / "usr" / "lib" / "shim"))

OVMF_CODE = OVMF_DIR / "OVMF_CODE_4M.fd"
OVMF_CODE_SECBOOT = OVMF_DIR / "OVMF_CODE_4M.secboot.fd"
OVMF_VARS = OVMF_DIR / "OVMF_VARS_4M.fd"
OVMF_VARS_MS = OVMF_DIR / "OVMF_VARS_4M.ms.fd"
SEABIOS_BIN = SEABIOS_DIR / "bios-256k.bin"

# Owner GUID used for the MokList entry we pre-seed (any GUID works; shim only
# looks at the certificate). This one is arbitrary and identifies the test suite.
MOK_OWNER_GUID = "a5a1b0c3-7e57-4bee-b007-e2e000000001"


def qemu_data_dirs() -> list[Path]:
    """Directories passed to QEMU with -L, in search order.

    The .tools QEMU is a relocated Debian build; it looks for option ROMs and
    VGA BIOS files in the host's /usr/share/qemu, which on this host lacks the
    SeaBIOS-provided files (vgabios-*.bin, bios-256k.bin symlinks). The .tools
    seabios package has them, the .tools qemu data dir has the NIC/EFI ROMs.
    """
    return bbqemu.data_dirs(BB_ROOT, SEABIOS_DIR)


def firmware() -> bbqemu.Firmware:
    """The firmware files (BB_OVMF_DIR / BB_SEABIOS_DIR) as bbdev.qemu sees them."""
    return bbqemu.Firmware(OVMF_DIR, SEABIOS_DIR)


def which(name: str) -> str | None:
    return shutil.which(name)


def qemu_binary() -> str | None:
    return which("qemu-system-x86_64")


@functools.cache
def kvm_usable() -> bool:
    forced = os.environ.get("BB_E2E_KVM")
    if forced == "0":
        return False
    ok = os.access("/dev/kvm", os.R_OK | os.W_OK)
    if forced == "1" and not ok:
        raise RuntimeError("BB_E2E_KVM=1 but /dev/kvm is not usable")
    return ok


def timeout_scale() -> float:
    env = os.environ.get("BB_E2E_TIMEOUT_SCALE")
    if env:
        return float(env)
    return 1.0 if kvm_usable() else 4.0


def t(seconds: float) -> float:
    """Scale a timeout for the current machine (TCG is much slower than KVM)."""
    return seconds * timeout_scale()


def disk_interface() -> str:
    v = os.environ.get("BB_E2E_DISK_IF", "usb")
    if v not in ("usb", "ide", "virtio"):
        raise RuntimeError(f"BB_E2E_DISK_IF must be usb, ide or virtio, not {v!r}")
    return v


def key_method(mode: str | None = None) -> str:
    """How VM.key() sends keys: BB_E2E_KEYS, else qmp for UEFI modes, serial for BIOS.

    Under OVMF two readers poll COM1: the firmware's own serial terminal
    (TerminalDxe, part of ConIn) and GRUB's ns8250 driver. A multi-byte
    escape sequence (an arrow key, ESC [ B) can be split between them; when
    TerminalDxe is left holding ESC [ it also eats the next byte as the end
    of a broken sequence, so Down + Enter can both vanish. Measured with the
    self-test stub menu: 2 of 720 arrow keys lost over serial, 0 of 600 over
    QMP. QMP send-key types on the emulated PS/2 keyboard, which reaches GRUB
    only through ConIn (GRUB's terminal_input always includes console). BIOS
    has no firmware reader on the serial port after boot (0 of 720 lost).
    """
    v = os.environ.get("BB_E2E_KEYS") or ("serial" if mode == "bios" else "qmp")
    if v not in ("serial", "qmp"):
        raise RuntimeError(f"BB_E2E_KEYS must be serial or qmp, not {v!r}")
    return v


def keep_work() -> bool:
    return os.environ.get("BB_E2E_KEEP") == "1"


def tool_env() -> dict[str, str]:
    """Environment for helper processes (installer, mtools)."""
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    pp = env.get("PYTHONPATH", "")
    if str(INSTALLER_DIR) not in pp.split(os.pathsep):
        env["PYTHONPATH"] = str(INSTALLER_DIR) + (os.pathsep + pp if pp else "")
    tools_bin = BB_ROOT / ".tools" / "bin"
    if tools_bin.is_dir() and str(tools_bin) not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = str(tools_bin) + os.pathsep + env.get("PATH", "")
    return env


def run(cmd: list[str], *, check: bool = True, timeout: float = 300, **kw) -> subprocess.CompletedProcess:
    """Run a helper command, capturing output; raise with the output on failure."""
    kw.setdefault("env", tool_env())
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=timeout, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"command failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
            f"--- stdout ---\n{p.stdout}\n--- stderr ---\n{p.stderr}"
        )
    return p


def python() -> str:
    return sys.executable or "python3"


def missing_files(paths) -> list[str]:
    return [str(p) for p in paths if not Path(p).exists()]


def read_version() -> str:
    try:
        return (BB_ROOT / "VERSION").read_text().strip()
    except OSError:
        return ""
