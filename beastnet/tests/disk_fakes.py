"""Fakes for the Disk tools tests: a sysfs/dev/proc tree in a temp folder and a scripted Runner."""

from __future__ import annotations

import os
import subprocess

from beastnet.cmdline import BootParams
from beastnet.context import Context
from beastnet.events import Reporter
from beastnet.firmware import Catalog
from beastnet.paths import Paths
from beastnet.system import System

GPT_SS = "e75caf8f-f680-4cee-afa3-b001e56efc2d"


def cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


class FakeRunner:
    """Records every command. ``on(match, reply)``: match is a program name, a tuple prefix of
    argv, or a function(argv) -> bool; reply is a CompletedProcess or function(argv, env, input).
    Unknown programs answer 127 (not installed)."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.inputs: list[str | None] = []
        self.handlers = []

    def on(self, match, reply):
        self.handlers.insert(0, (match, reply))

    def run(self, argv, *, timeout=60, env=None, input=None):
        argv = list(argv)
        self.calls.append(argv)
        self.envs.append(dict(env or {}))
        self.inputs.append(input)
        for match, reply in self.handlers:
            if callable(match):
                ok = match(argv)
            elif isinstance(match, str):
                ok = argv[0] == match
            else:
                ok = tuple(argv[:len(match)]) == tuple(match)
            if ok:
                return reply(argv, env or {}, input) if callable(reply) else reply
        return cp(127, "", f"{argv[0]}: not found")

    def ran(self, prog):
        return [c for c in self.calls if c[0] == prog]


class Env:
    """A fake machine under tmp_path: /sys, /dev, /proc and a Context."""

    def __init__(self, tmp_path):
        self.root = str(tmp_path / "root")
        for d in ("sys/block", "sys/class/block", "sys/class/nvme", "sys/bus/pci/devices", "dev", "proc",
                  "mnt/data", "mnt/esp", "sys/module/md_mod/parameters"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        with open(os.path.join(self.root, "sys/module/md_mod/parameters/start_ro"), "w") as f:
            f.write("0\n")  # the kernel default; assemble must set 1 before starting arrays
        self.paths = Paths(root=self.root)
        self.runner = FakeRunner()
        self.rep = Reporter()
        self.ctx = Context(self.paths, BootParams(), self.rep, System(self.paths, self.runner, dry_run=False),
                           None, Catalog(), lambda: None)
        self.blk: dict[str, dict] = {}
        self.runner.on("blkid", self._blkid)
        self.mounts: list[str] = []

    # -- paths
    def sys(self, *p):
        return os.path.join(self.root, "sys", *p)

    def dev(self, name):
        return os.path.join(self.root, "dev", name)

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w" if isinstance(text, str) else "wb") as f:
            f.write(text)

    # -- devices
    def add_disk(self, name, mib, *, transport="sata", model="FAKE DISK", serial="", wwid="", rotational=0,
                 removable=0, lss=512, pss=4096, vpd=False, content=b"\x01" * 4096):
        tdir = {
            "sata": "devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/",
            "nvme": "devices/pci0000:00/0000:00:1d.0/0000:01:00.0/nvme/nvme0/",
            "usb": "devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/host6/target6:0:0/6:0:0:0/block/",
            "virtio": "devices/pci0000:00/0000:00:03.0/virtio0/block/",
            "sas": "devices/pci0000:00/0000:00:02.0/host2/port-2:0/end_device-2:0/target2:0:0/2:0:0:0/block/",
        }[transport]
        real = self.sys(tdir, name)
        os.makedirs(real, exist_ok=True)
        os.symlink(real, self.sys("block", name))
        self.write(os.path.join(real, "size"), f"{mib * 2048}\n")
        self.write(os.path.join(real, "removable"), f"{removable}\n")
        self.write(os.path.join(real, "queue", "logical_block_size"), f"{lss}\n")
        self.write(os.path.join(real, "queue", "physical_block_size"), f"{pss}\n")
        self.write(os.path.join(real, "queue", "rotational"), f"{rotational}\n")
        self.write(os.path.join(real, "ro"), "0\n")
        dev = os.path.join(real, "device")
        os.makedirs(dev, exist_ok=True)
        self.write(os.path.join(dev, "model"), model + "\n")
        if wwid:
            self.write(os.path.join(real, "wwid"), wwid + "\n")
        if transport == "nvme":
            self.write(self.sys("class", "nvme", "nvme0", "serial"), serial + "\n")
        elif vpd and serial:
            b = serial.encode()
            self.write(os.path.join(dev, "vpd_pg80"), bytes([0, 0x80, 0, len(b)]) + b)
        elif serial:
            self.write(os.path.join(dev, "serial"), serial + "\n")
        self.write(self.dev(name), content)
        return real

    def add_part(self, disk, num, start_mib, size_mib, **blk):
        base = self.sys("block", disk)
        name = f"{disk}p{num}" if disk[-1].isdigit() else f"{disk}{num}"
        pdir = os.path.join(os.path.realpath(base), name)
        self.write(os.path.join(pdir, "partition"), f"{num}\n")
        self.write(os.path.join(pdir, "start"), f"{start_mib * 2048}\n")
        self.write(os.path.join(pdir, "size"), f"{size_mib * 2048}\n")
        self.write(self.dev(name), b"")
        if blk:
            self.blk[self.dev(name)] = blk
        return name

    def add_virtual(self, name, mib, *, slaves=(), meta=None, uuid=None, ro=0, state=None, holders=()):
        """An md or dm device; ``slaves`` are existing kernel names."""
        d = self.sys("devices", "virtual", "block", name)
        os.makedirs(d, exist_ok=True)
        os.symlink(d, self.sys("block", name))
        self.write(os.path.join(d, "size"), f"{mib * 2048}\n")
        self.write(os.path.join(d, "ro"), f"{ro}\n")
        for s in slaves:
            os.makedirs(os.path.join(d, "slaves"), exist_ok=True)
            os.symlink(os.path.realpath(self.sys("block", s)), os.path.join(d, "slaves", s))
        os.makedirs(os.path.join(d, "holders"), exist_ok=True)
        for h in holders:
            open(os.path.join(d, "holders", h), "w").close()
        if meta:
            self.write(os.path.join(d, "md", "metadata_version"), meta + "\n")
        if state:
            self.write(os.path.join(d, "md", "array_state"), state + "\n")
        if uuid:
            self.write(os.path.join(d, "dm", "uuid"), uuid + "\n")
        self.write(self.dev(name), b"")
        return d

    def fake_overlays(self, first_dm=50):
        """Answer overlay.create/remove (blockdev, losetup, dmsetup create/info/remove, the
        tmpfs mount) against this tree: each overlay is a dm-N over its member, with its dm
        name in sysfs. Returns {dm name: kname}; removed overlays leave /sys/block."""
        made: dict[str, str] = {}

        def reply(argv, env, input):
            if argv[:2] == ["blockdev", "--getsize64"]:
                return cp(0, f"{100 << 20}\n")
            if argv[:3] == ["losetup", "--find", "--show"]:
                return cp(0, f"/dev/loop{sum(c[:3] == argv[:3] for c in self.runner.calls) - 1}\n")
            if argv[:2] == ["dmsetup", "create"]:
                name, origin = argv[2], argv[argv.index("--table") + 1].split()[3]
                k = f"dm-{first_dm + len(made)}"
                made[name] = k
                self.add_virtual(k, 100, slaves=[os.path.basename(origin)])
                self.write(self.sys("block", k, "dm", "name"), name + "\n")
                return cp(0)
            if argv[:2] == ["dmsetup", "info"]:
                return cp(0, made.get(argv[-1], "") + "\n")
            if argv[:2] == ["dmsetup", "status"]:
                return cp(0, "0 204800 snapshot 16/204800 16\n")
            if argv[:2] == ["dmsetup", "remove"]:
                k = made.get(argv[-1])
                if k and os.path.lexists(self.sys("block", k)):
                    os.unlink(self.sys("block", k))
                return cp(0)
            if argv[0] == "mount" and "tmpfs" in argv:
                with open(os.path.join(self.root, "proc", "mounts"), "a") as f:
                    f.write(f"bbcow {os.path.realpath(argv[-1])} tmpfs rw 0 0\n")
                return cp(0)
            if argv[0] == "umount":
                mp = os.path.join(self.root, "proc", "mounts")
                with open(mp) as f:
                    keep = [ln for ln in f if ln.split()[1:2] != [os.path.realpath(argv[-1])]]
                with open(mp, "w") as f:
                    f.writelines(keep)
                return cp(0)
            return cp(0)
        self.runner.on(lambda a: a[0] in ("blockdev", "losetup", "mount", "umount") or a[:2] in (
            ["dmsetup", "create"], ["dmsetup", "info"], ["dmsetup", "status"], ["dmsetup", "remove"]), reply)
        return made

    def set_mounts(self, *lines):
        self.write(os.path.join(self.root, "proc", "mounts"), "\n".join(lines) + "\n")

    def add_pci(self, addr, vendor, device, cls):
        d = self.sys("bus", "pci", "devices", addr)
        self.write(os.path.join(d, "vendor"), f"0x{vendor:04x}\n")
        self.write(os.path.join(d, "device"), f"0x{device:04x}\n")
        self.write(os.path.join(d, "class"), f"0x{cls:06x}\n")

    def _blkid(self, argv, env, input):
        out = []
        for p in argv[4:]:
            info = self.blk.get(p)
            if info:
                out.append("\n".join([f"DEVNAME={p}"] + [f"{k}={v}" for k, v in info.items()]) + "\n")
        return cp(0 if out else 2, "\n".join(out))
