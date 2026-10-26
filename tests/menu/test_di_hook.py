"""grub/beast/hooks/d-i-iso.sh, console part: one debian-installer when the
command line preseeds, as d-i itself does for /preseed.cfg (two installers
started by reopen-console race in anna). Run against a fake root."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[2] / "grub" / "beast" / "hooks" / "d-i-iso.sh"
SH = shutil.which("busybox") and [shutil.which("busybox"), "sh"] or ([shutil.which("dash")] if shutil.which("dash") else None)

# From the Debian 13 netinst initrd (etc/preseed_aliases, etc/inittab up to the installer lines).
PRESEED_ALIASES = """priority	debconf/priority
fb	debian-installer/framebuffer
language	debian-installer/language
country	debian-installer/country
locale	debian-installer/locale
theme	debian-installer/theme
auto	auto-install/enable
classes	auto-install/classes
file	preseed/file
url	preseed/url
domain	netcfg/get_domain
hostname	netcfg/get_hostname
interface	netcfg/choose_interface
protocol	mirror/protocol
suite	mirror/suite
modules	anna/choose_modules
recommends	base-installer/install-recommends
tasks	tasksel:tasksel/first
desktop	tasksel:tasksel/desktop
dmraid	disk-detect/dmraid/enable
keymap keyboard-configuration/xkb-keymap
preseed-md5 preseed/file/checksum
firmware	hw-detect/firmware-lookup
"""
INITTAB = """# /etc/inittab
# busybox init configuration for debian-installer

# main rc script
::sysinit:/sbin/reopen-console /sbin/debian-installer-startup

# convenience shells
tty2::askfirst:-/bin/sh
tty3::askfirst:-/bin/sh

# logging
tty4::respawn:/usr/bin/tail -f /var/log/syslog

# Stuff to do before rebooting
::ctrlaltdel:/sbin/shutdown > /dev/null 2>&1

# re-exec init on receipt of SIGHUP/SIGUSR1
::restart:/sbin/init

# main setup program
"""
LINE = "::respawn:/sbin/debian-installer"


def run(tmp_path: Path, cmdline: str, consoles: list[str], *, source: bool = False) -> tuple[list[str], str, str]:
    root = tmp_path / "root"
    for d in ("proc", "etc", "var/run", "tmp", "dev"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "proc" / "cmdline").write_text(cmdline + "\n")
    (root / "etc" / "preseed_aliases").write_text(PRESEED_ALIASES)
    (root / "etc" / "inittab").write_text(INITTAB + "".join(f"{c}{LINE}\n" for c in consoles))
    (root / "var" / "run" / "console-devices").write_text("".join(f"/dev/{c} \n" for c in consoles))
    (root / "var" / "run" / "console-preferred").write_text(f"/dev/{consoles[0]} \n")
    (root / "dev" / "kmsg").write_text("")
    text = HOOK.read_text()
    for a, b in (("/tmp/bb-", f"{root}/tmp/bb-"), ("/proc/cmdline", f"{root}/proc/cmdline"),
                 ("/etc/", f"{root}/etc/"), ("/var/run/", f"{root}/var/run/"),
                 ("/dev/kmsg", f"{root}/dev/kmsg"), ("/beast-booter/", f"{root}/bb/")):
        text = text.replace(a, b)
    hook = tmp_path / "hook.sh"
    hook.write_text(text)
    script = f'. "{hook}"; echo after=$?; set | grep -c "^bb_di" || true' if source else f'"{SH[-1] if len(SH) == 1 else SH[0]}" {"sh " if len(SH) == 2 else ""}"{hook}"; echo after=$?'
    r = subprocess.run([*SH, "-c", script], capture_output=True, text=True, timeout=30)
    lines = [ln for ln in (root / "etc" / "inittab").read_text().splitlines() if ln.endswith(LINE)]
    return lines, (root / "dev" / "kmsg").read_text(), r.stdout


pytestmark = pytest.mark.skipif(SH is None, reason="needs busybox or dash")
HARNESS = "BOOT_IMAGE=(loop)/install.amd/vmlinuz --- console=ttyS0,115200 priority=critical locale=en_US.UTF-8 keymap=us"


@pytest.mark.parametrize("cmdline", [
    HARNESS,
    "BOOT_IMAGE=/x --- console=ttyS0 debian-installer/locale=en_US.UTF-8",
    "BOOT_IMAGE=/x --- console=ttyS0 tasksel:tasksel/first=standard",
    "BOOT_IMAGE=/x --- console=ttyS0 file=/cdrom/p.cfg",
])
def test_preseeded_command_line_keeps_one_installer(tmp_path, cmdline):
    lines, kmsg, out = run(tmp_path, cmdline, ["ttyS0", "tty1"])
    assert lines == ["ttyS0" + LINE], (lines, out)
    assert "debian-installer on ttyS0 only" in kmsg


@pytest.mark.parametrize("cmdline", [
    "BOOT_IMAGE=(loop)/install.amd/vmlinuz ---",
    "BOOT_IMAGE=/x --- console=ttyS0,115200",
    "BOOT_IMAGE=/x --- console=ttyS0 usbcore.autosuspend=-1 quiet",
    "BOOT_IMAGE=/x --- console=ttyS0 a.b*=c [=x =y",
])
def test_not_preseeded_keeps_every_installer(tmp_path, cmdline):
    lines, kmsg, _ = run(tmp_path, cmdline, ["ttyS0", "tty1"])
    assert lines == ["ttyS0" + LINE, "tty1" + LINE] and kmsg == ""


def test_single_console_is_left_alone(tmp_path):
    lines, kmsg, _ = run(tmp_path, "BOOT_IMAGE=/x --- priority=critical", ["tty1"])
    assert lines == ["tty1" + LINE] and kmsg == ""


def test_sourced_hook_returns_and_cleans_up(tmp_path):
    lines, _, out = run(tmp_path, HARNESS, ["ttyS0", "tty1"], source=True)
    assert lines == ["ttyS0" + LINE]
    assert "after=0" in out and out.strip().splitlines()[-1] == "0", out  # no bb_di* variables left
