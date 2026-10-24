"""bb-dev vm: planning for every mode/bus/display, --print-cmd, vars handling.
No QEMU is started: the host (QEMU path, KVM, GTK) is faked."""

from __future__ import annotations

import argparse
import contextlib
import itertools
import os
import shlex
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev import cli, diskimg, paths, qemu  # noqa: E402
from bbdev.commands import vm  # noqa: E402
from bbdev.msg import Failure  # noqa: E402


def host(gtk: bool = True, kvm: bool = True, fw: qemu.Firmware | None = None, sdl: bool = False) -> vm.Host:
    return vm.Host("/q/qemu-system-x86_64", kvm, gtk, "" if gtk else "no GTK module",
                   fw or qemu.Firmware(Path("/fw/ovmf"), Path("/fw/seabios")), [Path("/d1")], sdl)


def parse(*argv: str) -> argparse.Namespace:
    return cli.build_parser().parse_args(["vm", *argv])


def opt_after(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


MODES = vm.MODES
BUSES = qemu.BUSES
DISPLAYS = (None,) + vm.DISPLAYS


@pytest.mark.parametrize("mode,bus,display", list(itertools.product(MODES, BUSES, DISPLAYS)))
def test_every_combination_gives_a_sane_command(mode, bus, display, monkeypatch):
    monkeypatch.setattr(qemu, "gui_session", lambda env=None: True)
    argv = ["--mode", mode, "--bus", bus] + (["--display", display] if display else [])
    plan = vm.build_plan(parse(*argv), host(gtk=True), vnc_display=7)
    a = plan.argv()
    image = paths.DEFAULT_IMAGE.absolute()
    state = paths.VM_OUT / image.stem
    assert a[0] == "/q/qemu-system-x86_64"
    assert opt_after(a, "-m") == [str(vm.DEFAULT_MEM)]
    # firmware
    if mode == "bios":
        assert opt_after(a, "-bios") == ["/fw/seabios/bios-256k.bin"] and plan.vars_file is None
    else:
        drives = opt_after(a, "-drive")
        code = "OVMF_CODE_4M.secboot.fd" if mode.startswith("sb") else "OVMF_CODE_4M.fd"
        assert drives[0].endswith(f"readonly=on,file=/fw/ovmf/{code}")
        assert drives[1].endswith(f"file={state / (mode + '.vars')}")
    machine = opt_after(a, "-machine")[0]
    assert machine == ("q35,smm=on" if mode.startswith("sb") else "q35") + ",kernel-irqchip=split"
    assert ("driver=cfi.pflash01,property=secure,value=on" in opt_after(a, "-global")) == mode.startswith("sb")
    # disk on the requested bus
    assert f"if=none,id=bbdisk,format=raw,cache=unsafe,file={image}" in opt_after(a, "-drive")
    devices = " ".join(opt_after(a, "-device"))
    assert {"usb": "usb-storage", "sata": "ide-hd", "virtio": "virtio-blk-pci", "nvme": "nvme,"}[bus] in devices
    # display: gtk by default when available; vnc on 127.0.0.1
    want = display or "gtk"
    assert opt_after(a, "-display") == (["vnc=127.0.0.1:7"] if want == "vnc" else [want])
    assert plan.vnc == ("127.0.0.1:5907" if want == "vnc" else None)
    # sockets (in the state dir, or a short per-image dir when the checkout path
    # is too long for a unix socket), serial log, pidfile; MokManager needs reboots to work
    assert opt_after(a, "-monitor") == [f"unix:{vm.socket_path(state, 'monitor.sock')},server=on,wait=off"]
    assert opt_after(a, "-qmp") == [f"unix:{vm.socket_path(state, 'qmp.sock')},server=on,wait=off"]
    assert opt_after(a, "-chardev") == [f"stdio,id=ser0,mux=on,signal=off,logfile={state / f'serial-{mode}.log'},logappend=off"]
    assert opt_after(a, "-pidfile") == [str(state / "qemu.pid")]
    assert "-no-reboot" not in a and "-gdb" not in a and "-S" not in a and "-debugcon" not in a
    # the line survives a shell round trip
    assert shlex.split(shlex.join(a)) == a


def test_default_display_without_gtk_is_none_with_stdio_serial(monkeypatch):
    monkeypatch.setattr(qemu, "gui_session", lambda env=None: False)
    plan = vm.build_plan(parse(), host(gtk=False))
    assert plan.display == "none"
    assert plan.spec.serial.backend == "stdio"
    assert not plan.warnings


def test_gtk_requested_but_missing_falls_back_to_vnc():
    plan = vm.build_plan(parse("--display", "gtk"), host(gtk=False), vnc_display=2)
    assert plan.display == "vnc" and plan.vnc == "127.0.0.1:5902"
    assert opt_after(plan.argv(), "-display") == ["vnc=127.0.0.1:2"]
    assert any("using VNC" in w for w in plan.warnings)


@pytest.mark.parametrize("serial,chardev", [
    ("pty", "pty,id=ser0,logfile={log},logappend=off"),
    ("file", "file,id=ser0,path={log}"),
])
def test_serial_choices_always_log(serial, chardev):
    plan = vm.build_plan(parse("--serial", serial, "--mode", "bios"), host())
    log = plan.state / "serial-bios.log"
    assert plan.serial_log == log
    assert opt_after(plan.argv(), "-chardev") == [chardev.format(log=log)]


def test_debug_options():
    plan = vm.build_plan(parse("--gdb", "--fw-debug", "--snapshot", "--mem", "512"), host())
    a = plan.argv()
    assert opt_after(a, "-gdb") == ["tcp:127.0.0.1:1234"] and "-S" not in a
    assert opt_after(a, "-debugcon") == [f"file:{plan.state / 'ovmf-debug.log'}"]
    assert "snapshot=on" in opt_after(a, "-drive")[-1]
    assert opt_after(a, "-m") == ["512"]
    bios = vm.build_plan(parse("--mode", "bios", "--fw-debug", "--wait-gdb"), host()).argv()
    assert opt_after(bios, "-debugcon")[0].endswith("seabios-debug.log")
    assert opt_after(bios, "-gdb") == ["tcp:127.0.0.1:1234"] and "-S" in bios
    assert opt_after(vm.build_plan(parse("--gdb", "4444"), host()).argv(), "-gdb") == ["tcp:127.0.0.1:4444"]


def test_tcg_without_kvm():
    a = vm.build_plan(parse(), host(kvm=False)).argv()
    assert opt_after(a, "-accel") == ["tcg"] and "kernel-irqchip" not in " ".join(a)


def test_image_option_and_state_dir(tmp_path):
    img = tmp_path / "other.img"
    plan = vm.build_plan(parse("--image", str(img), "--mode", "sb"), host())
    assert plan.state == paths.VM_OUT / "other"
    assert plan.vars_file == paths.VM_OUT / "other" / "sb.vars"
    assert f"file={img}" in opt_after(plan.argv(), "-drive")[-1]


def test_extra_args_after_double_dash():
    plan = vm.build_plan(parse("--mode", "bios", "--", "-d", "int", "-D", "/tmp/x"), host())
    assert plan.argv()[-4:] == ["-d", "int", "-D", "/tmp/x"]
    with pytest.raises(Failure, match="unexpected argument"):
        vm.build_plan(parse("typo"), host())


def test_cdrom(tmp_path):
    iso = tmp_path / "x.iso"
    iso.write_bytes(b"iso")
    a = vm.build_plan(parse("--cdrom", str(iso)), host()).argv()
    assert f"if=none,id=bbcd,media=cdrom,format=raw,readonly=on,file={iso}" in opt_after(a, "-drive")
    with pytest.raises(Failure):
        vm.build_plan(parse("--cdrom", str(tmp_path / "missing.iso")), host())


def test_bad_values():
    with pytest.raises(Failure):
        vm.build_plan(parse("--gdb", "70000"), host())
    with pytest.raises(Failure):
        vm.build_plan(parse("--mem", "16"), host())


def test_long_state_dir_gets_short_sockets(tmp_path):
    long_state = tmp_path / ("x" * 120)
    p = vm.socket_path(long_state, "qmp.sock")
    assert len(str(p)) < qemu.MAX_UNIX_PATH and p.name == "qmp.sock"
    assert vm.socket_path(Path("/short"), "qmp.sock") == Path("/short/qmp.sock")


def test_print_cmd_through_the_cli(monkeypatch, capsys):
    monkeypatch.setattr(vm.Host, "detect", classmethod(lambda cls, env: host(gtk=False)))
    monkeypatch.setattr(qemu, "gui_session", lambda env=None: False)
    rc = cli.main(["vm", "--print-cmd", "--mode", "sb-enrolled", "--bus", "nvme", "--", "-d", "int"])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0 and len(out) == 1
    a = shlex.split(out[0])
    assert a[0] == "/q/qemu-system-x86_64" and a[-2:] == ["-d", "int"]
    assert "nvme,serial=beastbooter,drive=bbdisk,bootindex=0" in a


def test_print_cmd_writes_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vm.Host, "detect", classmethod(lambda cls, env: host()))
    monkeypatch.setattr(paths, "VM_OUT", tmp_path / "vm")
    assert cli.main(["vm", "--print-cmd", "--image", str(tmp_path / "x.img")]) == 0
    assert not (tmp_path / "vm").exists()


# ---------------------------------------------------------------------------
# Vars
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_fw(tmp_path, monkeypatch):
    d = tmp_path / "ovmf"
    d.mkdir()
    (d / "OVMF_VARS_4M.fd").write_bytes(b"plain")
    (d / "OVMF_VARS_4M.ms.fd").write_bytes(b"ms")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "virt-fw-vars"
    tool.write_text("#!/usr/bin/env python3\nimport shutil, sys\na = sys.argv[1:]\n"
                    "open(sys.argv[0] + '.calls', 'a').write('x')\n"
                    "shutil.copyfile(a[a.index('--input') + 1], a[a.index('--output') + 1])\n"
                    "open(a[a.index('--output') + 1], 'ab').write(b'+mok')\n")
    tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(paths, "VM_OUT", tmp_path / "vm")
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "beast-booter.cer").write_bytes(b"cert")
    monkeypatch.setattr(paths, "KEYS", keys)
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return qemu.Firmware(d, d), env, tool


def planned(mode, fw, tmp_path):
    plan = vm.build_plan(parse("--mode", mode, "--image", str(tmp_path / "img.img")), host(fw=fw))
    plan.state.mkdir(parents=True, exist_ok=True)
    return plan


def test_uefi_and_sb_vars_persist(fake_fw, tmp_path):
    fw, env, _ = fake_fw
    for mode, content in (("uefi", b"plain"), ("sb", b"ms")):
        plan = planned(mode, fw, tmp_path)
        assert "created" in vm.prepare_vars(plan, host(fw=fw), env, reset=False)
        assert plan.vars_file.read_bytes() == content
        plan.vars_file.write_bytes(b"enrolled by hand")
        assert "persistent" in vm.prepare_vars(plan, host(fw=fw), env, reset=False)
        assert plan.vars_file.read_bytes() == b"enrolled by hand"
        assert "recreated" in vm.prepare_vars(plan, host(fw=fw), env, reset=True)
        assert plan.vars_file.read_bytes() == content


def test_sb_fresh_is_fresh_every_run(fake_fw, tmp_path):
    fw, env, _ = fake_fw
    plan = planned("sb-fresh", fw, tmp_path)
    vm.prepare_vars(plan, host(fw=fw), env, reset=False)
    plan.vars_file.write_bytes(b"changed")
    vm.prepare_vars(plan, host(fw=fw), env, reset=False)
    assert plan.vars_file.read_bytes() == b"ms"


def test_sb_enrolled_uses_a_cached_template(fake_fw, tmp_path):
    fw, env, tool = fake_fw
    plan = planned("sb-enrolled", fw, tmp_path)
    desc = vm.prepare_vars(plan, host(fw=fw), env, reset=False)
    assert "MokList" in desc and plan.vars_file.read_bytes() == b"ms+mok"
    plan.vars_file.write_bytes(b"changed")
    vm.prepare_vars(plan, host(fw=fw), env, reset=False)
    assert plan.vars_file.read_bytes() == b"ms+mok"
    assert Path(str(tool) + ".calls").read_text() == "x"  # virt-fw-vars ran once


def test_sb_enrolled_needs_a_certificate(fake_fw, tmp_path, monkeypatch):
    fw, env, _ = fake_fw
    (paths.KEYS / "beast-booter.cer").unlink()
    monkeypatch.setattr(paths, "DIST", tmp_path / "nodist")
    with pytest.raises(Failure, match="certificate"):
        vm.prepare_vars(planned("sb-enrolled", fw, tmp_path), host(fw=fw), env, reset=False)


class _Data:
    def __init__(self, user: bytes):
        self.user = user

    def read(self, path: str) -> bytes | None:
        return self.user if path == diskimg.USER_CONFIG else None


class FakeImage:
    """device.cfg on the ESP and config.cfg on the data partition, for
    check_bios_serial; exFAT/NTFS reads go through a fake udisks mount."""

    def __init__(self, monkeypatch, fs: str, device: bytes = b"", user: bytes | None = None,
                 udisks: tuple[bool, str] = (True, "")):
        self.mounts: list[bool] = []
        info = diskimg.ImageInfo(Path("/x.img"), "msdos", "0", fs, 2048, 1, 4096, 1, {})
        monkeypatch.setattr(diskimg, "image_info", lambda image: info)

        def fat_read(fat, path):
            if fat.offset == info.esp_offset:
                return device if path == "/grub/beast/device.cfg" else None
            assert fs == "fat32", "mtools on a non-FAT data partition"
            return user if path == diskimg.USER_CONFIG else None
        monkeypatch.setattr(diskimg.Fat, "read", fat_read)
        monkeypatch.setattr(diskimg, "udisks_status", lambda: udisks)

        @contextlib.contextmanager
        def data_access(info_, *, readonly=False):
            assert udisks[0], "mounted although udisks is not usable"
            self.mounts.append(readonly)
            yield diskimg.MountedData(Path("/nonexistent")) if user is None else _Data(user)
        monkeypatch.setattr(diskimg, "data_access", data_access)


def bios_plan(display="none"):
    plan = vm.build_plan(parse("--mode", "bios", "--display", display), host())
    vm.check_bios_serial(plan)
    return plan


SERIAL_ON, SERIAL_OFF = b'set bb_serial="1"\n', b'set bb_serial="0"\n'
NOT_SET = "BIOS: bb_serial is not set (device.cfg or /beast-booter/config.cfg), so after SeaBIOS the menu is"
FIX = "`bb-dev debug-config --set bb_serial=1` turns it on"


@pytest.mark.parametrize("fs", ["fat32", "exfat", "ntfs"])
def test_bios_serial_hint(monkeypatch, fs):
    # set nowhere: a warning with --display none, naming both files and the fix
    img = FakeImage(monkeypatch, fs, device=SERIAL_OFF, user=None)
    plan = bios_plan()
    assert len(plan.warnings) == 1 and plan.warnings[0].startswith(NOT_SET), plan.warnings
    assert "nowhere you can see (--display none)" in plan.warnings[0] and FIX in plan.warnings[0]
    assert img.mounts == ([] if fs == "fat32" else [True])   # exFAT/NTFS: one read-only mount
    # with a window it is only a note
    FakeImage(monkeypatch, fs, device=b"", user=b"set timeout=5\n")
    plan = bios_plan("vnc")
    assert not plan.warnings and len(plan.notes) == 1 and "on the display only" in plan.notes[0]
    # what `bb-dev debug-config --set bb_serial=1` writes (config.cfg) silences it ...
    FakeImage(monkeypatch, fs, device=SERIAL_OFF, user=SERIAL_ON)
    assert not bios_plan().warnings
    # ... and so does the installer's --serial-console (device.cfg), without a mount
    img = FakeImage(monkeypatch, fs, device=SERIAL_ON, user=None)
    assert not bios_plan().warnings and img.mounts == []


@pytest.mark.parametrize("fs", ["exfat", "ntfs"])
def test_bios_serial_hint_when_config_cfg_is_unreadable(monkeypatch, fs):
    img = FakeImage(monkeypatch, fs, device=b"", user=SERIAL_ON, udisks=(False, "udisksctl is not installed"))
    plan = bios_plan()
    assert img.mounts == []
    assert len(plan.warnings) == 1, plan.warnings
    w = plan.warnings[0]
    assert w.startswith(f"BIOS: bb_serial is not set in device.cfg, and /beast-booter/config.cfg on the {fs} "
                        "data partition could not be read (udisksctl is not installed); unless it sets "
                        "bb_serial=1"), w
    assert FIX in w


def test_running_vm_ignores_reused_pids(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "VM_OUT", tmp_path / "vm")
    img = tmp_path / "x.img"
    assert diskimg.running_vm(img) is None
    pf = diskimg.pidfile(img)
    pf.parent.mkdir(parents=True)
    pf.write_text(f"{os.getpid()}\n")  # alive, but not a QEMU started with this pidfile
    assert diskimg.running_vm(img) is None
    pf.write_text("not a pid\n")
    assert diskimg.running_vm(img) is None


def test_default_display_uses_sdl_when_gtk_unusable(monkeypatch):
    monkeypatch.setattr(qemu, "gui_session", lambda env=None: True)
    plan = vm.build_plan(parse(), host(gtk=False, sdl=True))
    assert plan.display == "sdl" and opt_after(plan.argv(), "-display") == ["sdl"]
    assert any("SDL window" in n for n in plan.notes)


def test_gtk_requested_but_unusable_falls_back_to_sdl():
    plan = vm.build_plan(parse("--display", "gtk"), host(gtk=False, sdl=True))
    assert plan.display == "sdl" and plan.vnc is None
    assert any("using an SDL window" in w for w in plan.warnings)


def test_sdl_can_be_requested():
    plan = vm.build_plan(parse("--display", "sdl"), host(sdl=True))
    assert opt_after(plan.argv(), "-display") == ["sdl"]


def test_refuses_an_image_attached_read_write_on_the_host(monkeypatch):
    rw = diskimg.Attachment("/dev/loop7", False, False, "/run/media/u/BEASTBOOTER")
    ro = diskimg.Attachment("/dev/loop8", True, True, None)
    monkeypatch.setattr(diskimg, "attachments", lambda image: [rw])
    plan = vm.build_plan(parse("--display", "none"), host())
    with pytest.raises(Failure) as e:
        vm.check_host_mounts(plan)
    assert "/dev/loop7 (read-write" in str(e.value)
    assert "udisksctl unmount -b /dev/loop7 && udisksctl loop-delete -b /dev/loop7" in e.value.hint
    plan = vm.build_plan(parse("--display", "none", "--snapshot"), host())
    vm.check_host_mounts(plan)  # the image is not written: a warning
    assert any("--snapshot" in w for w in plan.warnings)
    monkeypatch.setattr(diskimg, "attachments", lambda image: [ro])
    plan = vm.build_plan(parse("--display", "none"), host())
    vm.check_host_mounts(plan)
    assert any("read-only" in w and "udisksctl loop-delete -b /dev/loop8" in w for w in plan.warnings)
    monkeypatch.setattr(diskimg, "attachments", lambda image: [])
    plan = vm.build_plan(parse("--display", "none"), host())
    vm.check_host_mounts(plan)
    assert not plan.warnings
