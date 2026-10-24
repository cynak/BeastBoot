"""bbdev.qemu: command construction for every firmware profile, bus and
serial backend, vars creation, display detection, and the e2e harness using it.
Pure: nothing here starts QEMU."""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer", ROOT / "tests" / "e2e"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev import qemu  # noqa: E402

FW = qemu.Firmware(Path("/fw/ovmf"), Path("/fw/seabios"))


def spec(**kw) -> qemu.QemuSpec:
    base = dict(qemu="qemu-system-x86_64", disk=Path("/img/d.img"), files=FW, vars_file=Path("/st/v.fd"))
    base.update(kw)
    return qemu.QemuSpec(**base)


def opt_after(argv: list[str], flag: str) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


# ---------------------------------------------------------------------------
# Firmware profiles
# ---------------------------------------------------------------------------

def test_bios_profile():
    a = spec(firmware="bios", vars_file=None).argv()
    assert opt_after(a, "-bios") == ["/fw/seabios/bios-256k.bin"]
    assert "if=pflash" not in " ".join(a)
    assert opt_after(a, "-machine") == ["q35"]


def test_uefi_profile():
    a = spec(firmware="uefi").argv()
    drives = opt_after(a, "-drive")
    assert drives[0] == "if=pflash,format=raw,unit=0,readonly=on,file=/fw/ovmf/OVMF_CODE_4M.fd"
    assert drives[1] == "if=pflash,format=raw,unit=1,file=/st/v.fd"
    assert "-bios" not in a
    assert not any("secure" in g for g in opt_after(a, "-global"))


def test_secure_boot_profile():
    a = spec(firmware="uefi-sb").argv()
    assert opt_after(a, "-machine") == ["q35,smm=on"]
    assert "driver=cfi.pflash01,property=secure,value=on" in opt_after(a, "-global")
    assert opt_after(a, "-drive")[0].endswith("file=/fw/ovmf/OVMF_CODE_4M.secboot.fd")


def test_uefi_needs_vars():
    with pytest.raises(ValueError):
        spec(firmware="uefi", vars_file=None).argv()
    with pytest.raises(ValueError):
        spec(firmware="nope").argv()


@pytest.mark.parametrize("firmware,expect", [("bios", "q35,kernel-irqchip=split"),
                                             ("uefi", "q35,kernel-irqchip=split"),
                                             ("uefi-sb", "q35,smm=on,kernel-irqchip=split")])
def test_kvm_uses_split_irqchip_and_host_cpu(firmware, expect):
    a = spec(firmware=firmware, kvm=True).argv()
    assert opt_after(a, "-machine") == [expect]
    assert opt_after(a, "-accel") == ["kvm"] and opt_after(a, "-cpu") == ["host"]
    t = spec(firmware=firmware, kvm=False).argv()
    assert opt_after(t, "-accel") == ["tcg"] and "-cpu" not in t
    assert "kernel-irqchip" not in opt_after(t, "-machine")[0]


def test_firmware_files_and_missing(tmp_path):
    fw = qemu.Firmware(tmp_path, tmp_path)
    assert fw.code("bios") == tmp_path / "bios-256k.bin"
    assert fw.vars_template("ms+mok") == tmp_path / "OVMF_VARS_4M.ms.fd"
    assert set(fw.missing("uefi-sb", "ms")) == {tmp_path / "OVMF_CODE_4M.secboot.fd", tmp_path / "OVMF_VARS_4M.ms.fd"}
    (tmp_path / "bios-256k.bin").write_bytes(b"x")
    assert fw.missing("bios") == []
    env_fw = qemu.Firmware.from_env({"BB_OVMF_DIR": "/a", "BB_SEABIOS_DIR": "/b"})
    assert env_fw == qemu.Firmware(Path("/a"), Path("/b"))
    with pytest.raises(ValueError):
        fw.vars_template("bogus")


def test_default_vars_kind():
    assert qemu.default_vars_kind("bios") is None
    assert qemu.default_vars_kind("uefi") == "plain"
    assert qemu.default_vars_kind("uefi-sb") == "ms"
    assert qemu.default_vars_kind("uefi-sb", enrolled=True) == "ms+mok"


# ---------------------------------------------------------------------------
# Disk, buses, serial, extras
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bus,devices", [
    ("usb", ["qemu-xhci,id=xhci", "usb-storage,bus=xhci.0,drive=bbdisk,removable=on,bootindex=0"]),
    ("sata", ["ide-hd,drive=bbdisk,bootindex=0"]),
    ("ide", ["ide-hd,drive=bbdisk,bootindex=0"]),
    ("virtio", ["virtio-blk-pci,drive=bbdisk,bootindex=0"]),
    ("nvme", ["nvme,serial=beastbooter,drive=bbdisk,bootindex=0"]),
])
def test_bus_devices(bus, devices):
    a = spec(bus=bus).argv()
    assert opt_after(a, "-device")[:-1] == devices  # the last one is VGA
    assert opt_after(a, "-device")[-1] == "VGA"
    assert "if=none,id=bbdisk,format=raw,cache=unsafe,file=/img/d.img" in opt_after(a, "-drive")


def test_unknown_bus():
    with pytest.raises(ValueError):
        spec(bus="scsi").argv()


def test_snapshot_and_cdrom():
    a = spec(snapshot=True, cdrom=Path("/iso/x.iso")).argv()
    drives = opt_after(a, "-drive")
    assert "if=none,id=bbdisk,format=raw,cache=unsafe,snapshot=on,file=/img/d.img" in drives
    assert "if=none,id=bbcd,media=cdrom,format=raw,readonly=on,file=/iso/x.iso" in drives
    assert "ide-cd,drive=bbcd,bootindex=1" in opt_after(a, "-device")


def test_commas_in_paths_are_escaped():
    a = spec(disk=Path("/img/a,b.img"), name="x,y").argv()
    assert "file=/img/a,,b.img" in opt_after(a, "-drive")[-1]
    assert opt_after(a, "-name") == ["x,,y"]


@pytest.mark.parametrize("serial,expect", [
    (qemu.Serial("stdio"), ["-chardev", "stdio,id=ser0,signal=off", "-serial", "chardev:ser0"]),
    (qemu.Serial("stdio", logfile=Path("/l/s.log"), mux=True),
     ["-chardev", "stdio,id=ser0,mux=on,signal=off,logfile=/l/s.log,logappend=off", "-serial", "chardev:ser0"]),
    (qemu.Serial("pty", logfile=Path("/l/s.log")),
     ["-chardev", "pty,id=ser0,logfile=/l/s.log,logappend=off", "-serial", "chardev:ser0"]),
    (qemu.Serial("file", path=Path("/l/s.log")), ["-chardev", "file,id=ser0,path=/l/s.log", "-serial", "chardev:ser0"]),
    (qemu.Serial("none"), ["-serial", "none"]),
])
def test_serial_backends(serial, expect):
    assert serial.args() == expect
    a = spec(serial=serial).argv()
    i = a.index(expect[0])
    assert a[i:i + len(expect)] == expect


def test_serial_validation():
    with pytest.raises(ValueError):
        qemu.Serial("file").args()
    with pytest.raises(ValueError):
        qemu.Serial("telnet").args()


def test_monitor_qmp_debugcon_gdb_pidfile_extra():
    a = spec(monitor=Path("/s/m.sock"), qmp=Path("/s/q.sock"), fw_debug_log=Path("/s/ovmf-debug.log"),
             gdb_port=4321, wait_gdb=True, pidfile=Path("/s/qemu.pid"), no_reboot=True,
             display="vnc=127.0.0.1:3", extra=["-d", "int"]).argv()
    assert opt_after(a, "-monitor") == ["unix:/s/m.sock,server=on,wait=off"]
    assert opt_after(a, "-qmp") == ["unix:/s/q.sock,server=on,wait=off"]
    assert opt_after(a, "-debugcon") == ["file:/s/ovmf-debug.log"]
    assert "isa-debugcon.iobase=0x402" in opt_after(a, "-global")
    assert opt_after(a, "-gdb") == ["tcp:127.0.0.1:4321"]
    assert "-S" in a and "-no-reboot" in a
    assert opt_after(a, "-pidfile") == ["/s/qemu.pid"]
    assert opt_after(a, "-display") == ["vnc=127.0.0.1:3"]
    assert a[-2:] == ["-d", "int"]


def test_defaults_have_no_optional_flags():
    a = spec().argv()
    for flag in ("-qmp", "-debugcon", "-gdb", "-S", "-pidfile", "-no-reboot", "-name"):
        assert flag not in a
    assert opt_after(a, "-monitor") == ["none"]
    assert a[1:3] == ["-nodefaults", "-machine"]


def test_e2e_command_is_unchanged():
    """The exact command the e2e harness built before it moved to bbdev.qemu."""
    a = spec(name="t", firmware="uefi-sb", bus="ide", memory=1024, smp=1, kvm=True,
             data_dirs=[Path("/d1"), Path("/d2")], qmp=Path("/q/qmp.sock"), no_reboot=True,
             serial=qemu.Serial("stdio"), extra=["-x"]).argv()
    assert a == [
        "qemu-system-x86_64", "-name", "t", "-nodefaults", "-machine", "q35,smm=on,kernel-irqchip=split",
        "-m", "1024", "-smp", "1", "-accel", "kvm", "-cpu", "host", "-L", "/d1", "-L", "/d2",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/fw/ovmf/OVMF_CODE_4M.secboot.fd",
        "-drive", "if=pflash,format=raw,unit=1,file=/st/v.fd",
        "-drive", "if=none,id=bbdisk,format=raw,cache=unsafe,file=/img/d.img",
        "-device", "ide-hd,drive=bbdisk,bootindex=0",
        "-device", "VGA", "-display", "none", "-monitor", "none",
        "-qmp", "unix:/q/qmp.sock,server=on,wait=off",
        "-chardev", "stdio,id=ser0,signal=off", "-serial", "chardev:ser0", "-no-reboot", "-x",
    ]


def test_bbe2e_vm_builds_its_command_with_bbdev(monkeypatch, tmp_path):
    from bbe2e import env, qemu as e2eqemu

    monkeypatch.setattr(env, "qemu_binary", lambda: "qemu-system-x86_64")
    monkeypatch.setattr(env, "kvm_usable", lambda: True)
    vm = e2eqemu.VM("n", mode="uefi", disk=tmp_path / "d.img", workdir=tmp_path / "w", log_dir=tmp_path / "l",
                    vars_file=tmp_path / "v.fd", disk_if="usb")
    vm.qmp_path = tmp_path / "qmp.sock"
    a = vm.command()
    assert opt_after(a, "-machine") == ["q35,kernel-irqchip=split"]
    assert "usb-storage,bus=xhci.0,drive=bbdisk,removable=on,bootindex=0" in a
    assert a[-1] == "-no-reboot"
    assert e2eqemu.QMP is qemu.QMP


def test_data_dirs(tmp_path):
    share = tmp_path / ".tools" / "root" / "usr" / "share"
    (share / "seabios").mkdir(parents=True)
    (share / "qemu").mkdir()
    sb = tmp_path / "sys-seabios"
    sb.mkdir()
    dirs = qemu.data_dirs(tmp_path, sb)
    assert dirs[:3] == [share / "seabios", sb, share / "qemu"]
    assert qemu.data_dirs(tmp_path, share / "seabios")[:2] == [share / "seabios", share / "qemu"]


# ---------------------------------------------------------------------------
# Vars
# ---------------------------------------------------------------------------

def fake_firmware(tmp_path) -> qemu.Firmware:
    d = tmp_path / "ovmf"
    d.mkdir()
    (d / "OVMF_VARS_4M.fd").write_bytes(b"plain-vars")
    (d / "OVMF_VARS_4M.ms.fd").write_bytes(b"ms-vars")
    return qemu.Firmware(d, d)


def fake_tool(bindir: Path, name: str, body: str) -> None:
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text("#!/usr/bin/env python3\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def test_make_vars_copies(tmp_path):
    fw = fake_firmware(tmp_path)
    assert qemu.make_vars("plain", tmp_path / "a", firmware=fw).read_bytes() == b"plain-vars"
    assert qemu.make_vars("ms", tmp_path / "b", firmware=fw).read_bytes() == b"ms-vars"


def test_make_vars_add_mok_runs_virt_fw_vars(tmp_path):
    fw = fake_firmware(tmp_path)
    fake_tool(tmp_path / "bin", "virt-fw-vars", (
        "import json, shutil, sys\n"
        "a = sys.argv[1:]\n"
        "shutil.copyfile(a[a.index('--input') + 1], a[a.index('--output') + 1])\n"
        "open(a[a.index('--output') + 1], 'ab').write(json.dumps(a).encode())\n"))
    env = dict(os.environ, PATH=f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    cert = tmp_path / "k.cer"
    cert.write_bytes(b"der")
    out = qemu.make_vars("ms+mok", tmp_path / "e.fd", firmware=fw, mok_certs=[cert], owner_guid="G", env=env)
    data = out.read_bytes()
    assert data.startswith(b"ms-vars")
    args = json.loads(data[len(b"ms-vars"):])
    assert args[args.index("--add-mok") + 1:args.index("--add-mok") + 3] == ["G", str(cert)]
    with pytest.raises(ValueError):
        qemu.make_vars("ms+mok", tmp_path / "f.fd", firmware=fw, owner_guid="G", env=env)


def test_make_vars_reports_failures(tmp_path):
    fw = fake_firmware(tmp_path)
    fake_tool(tmp_path / "bin", "virt-fw-vars", "import sys\nprint('boom', file=sys.stderr)\nsys.exit(3)\n")
    env = dict(os.environ, PATH=f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    with pytest.raises(RuntimeError, match="boom"):
        qemu.make_vars("ms+mok", tmp_path / "e.fd", firmware=fw, mok_certs=[tmp_path], owner_guid="G", env=env)


# ---------------------------------------------------------------------------
# Displays and ports
# ---------------------------------------------------------------------------

def test_display_detection(tmp_path, monkeypatch):
    monkeypatch.setattr(qemu, "gtk3_gsettings_conflict", lambda env=None: "")  # ignore this desktop
    fake_tool(tmp_path / "bin", "fakeqemu", (
        "print('Available display backends:')\nprint('none')\nprint('gtk')\nprint('curses')\n"
        "print()\nprint('Some display backends support suboptions, ...')\n"))
    q = str(tmp_path / "bin" / "fakeqemu")
    env = {"PATH": os.environ["PATH"], "DISPLAY": ":0"}
    assert qemu.display_backends(q, env) == {"none", "gtk", "curses"}
    assert qemu.gtk_status(q, env) == (True, "")
    ok, reason = qemu.gtk_status(q, {"PATH": os.environ["PATH"]})
    assert not ok and "graphical session" in reason
    assert qemu.gtk_status(None, env)[0] is False


def test_display_detection_without_gtk(tmp_path):
    fake_tool(tmp_path / "bin", "fakeqemu2", "print('Available display backends:')\nprint('none')\n")
    ok, reason = qemu.gtk_status(str(tmp_path / "bin" / "fakeqemu2"), {"PATH": os.environ["PATH"], "WAYLAND_DISPLAY": "w"})
    assert not ok and "qemu-system-gui" in reason


def test_free_vnc_display_skips_busy_ports():
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
    except PermissionError:
        pytest.skip("cannot bind sockets here")
    port = s.getsockname()[1]
    try:
        assert not qemu.port_free(port)
        if qemu.VNC_BASE_PORT <= port <= qemu.VNC_BASE_PORT + 99:
            n = port - qemu.VNC_BASE_PORT
            assert qemu.free_vnc_display(first=n, last=n + 1) == n + 1
    finally:
        s.close()
    assert isinstance(qemu.free_vnc_display(), int)


# ---------------------------------------------------------------------------
# Monitor / QMP clients against fake servers
# ---------------------------------------------------------------------------

def _serve(path: Path, handler):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)

    def loop():
        conn, _ = srv.accept()
        with conn:
            handler(conn)
        srv.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def short_sock_dir():
    import tempfile
    return Path(tempfile.mkdtemp(prefix="bbq-"))


def test_monitor_client():
    d = short_sock_dir()
    path = d / "m.sock"

    def handler(conn):
        conn.sendall(b"QEMU 10.2 monitor - type 'help'\r\n(qemu) ")
        buf = b""
        while not buf.endswith(b"\n"):
            buf += conn.recv(100)
        conn.sendall(b"info status\r\nVM status: running\r\n(qemu) ")

    t = _serve(path, handler)
    with qemu.Monitor(path) as m:
        assert m.cmd("info status") == "VM status: running"
    t.join(2)


def test_qmp_client():
    d = short_sock_dir()
    path = d / "q.sock"

    def handler(conn):
        conn.sendall(json.dumps({"QMP": {"version": {}}}).encode() + b"\n")
        f = conn.makefile("rb")
        for _ in range(2):
            msg = json.loads(f.readline())
            reply = {"return": {}} if msg["execute"] == "qmp_capabilities" else {"return": {"status": "running"}}
            if msg["execute"] == "query-status":
                conn.sendall(json.dumps({"event": "X"}).encode() + b"\n")
            conn.sendall(json.dumps(reply).encode() + b"\n")

    t = _serve(path, handler)
    q = qemu.QMP(path)
    assert q.cmd("query-status") == {"status": "running"}
    q.close()
    t.join(2)


@pytest.mark.parametrize("keys,rc,conflict", [
    ("disabled-gtk-modules enabled-gtk-modules overrides", 0, True),   # GNOME 50+: key removed
    ("antialiasing hinting rgba-order overrides", 0, False),           # older GNOME
    ("", 1, False),                                                     # schema not installed
])
def test_gtk3_gsettings_conflict(tmp_path, keys, rc, conflict):
    fake_tool(tmp_path / "bin", "gsettings", f"import sys\nprint({keys!r}.replace(' ', '\\n'))\nsys.exit({rc})\n")
    env = {"PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}"}  # fake gsettings first
    reason = qemu.gtk3_gsettings_conflict(env)
    assert bool(reason) is conflict
    if conflict:
        assert "antialiasing" in reason


def test_gtk_status_reports_gsettings_conflict(tmp_path, monkeypatch):
    fake_tool(tmp_path / "bin", "fakeqemu3", "print('Available display backends:')\nprint('gtk')\nprint('sdl')\n")
    monkeypatch.setattr(qemu, "gtk3_gsettings_conflict", lambda env=None: "GTK 3 aborts on this desktop")
    env = {"PATH": os.environ["PATH"], "DISPLAY": ":0"}
    q = str(tmp_path / "bin" / "fakeqemu3")
    assert qemu.gtk_status(q, env) == (False, "GTK 3 aborts on this desktop")
    assert qemu.sdl_status(q, env) == (True, "")
    assert qemu.sdl_status(q, {"PATH": os.environ["PATH"]})[0] is False
