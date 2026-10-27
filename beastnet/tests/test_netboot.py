"""Network boot (beastnet.netboot=1, started by BeastServer): no stick, no data
partition and no ESP; /init mounts RAM filesystems in their place. Disk tools
work the same; what needs the stick degrades (beastnet/README.md, "Network boot")."""

import os
import subprocess
from types import SimpleNamespace

import pytest

from beastnet.cmdline import netboot, parse_cmdline
from beastnet.context import Quit
from beastnet.diskflow import ABOUT, ABOUT_NETBOOT
from beastnet.disks import copy as C
from beastnet.disks import session as S
from beastnet.errors import DISK_REFUSED, BeastNetError
from beastnet.ui import Item
from test_disks_copy import env, mk  # noqa: F401 - the fixture
from test_disks_session import Parts, flow_for, inventory  # noqa: F401
from test_disks_session import ctx as session_ctx  # noqa: F401
from test_disks_session import DiskUI
from test_ui import ScriptedUI, pick

INIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rootfs", "init")
SERVER = ("BOOT_IMAGE=(http,10.0.0.5:8080)/files/assets/beastnet-vmlinuz beastnet.netboot=1 "
          "beastnet.server=http://10.0.0.5:8080 beastnet.sb=0 beastnet.debug=1 console=tty0 "
          "beastnet.ui= beastnet.script=/plan.json beastnet.action=disk raid=noautodetect quiet")


def test_cmdline_netboot():
    p = parse_cmdline(SERVER)
    assert p.netboot and p.server == "http://10.0.0.5:8080" and p.action == "disk"
    assert p.data is None and p.esp is None and p.script == "/plan.json"
    assert netboot(SimpleNamespace(params=p))
    assert not parse_cmdline("beastnet.data=UUID=1 beastnet.esp=UUID=2").netboot
    assert not parse_cmdline("beastnet.netboot=0").netboot
    assert not netboot(SimpleNamespace())  # tests' bare contexts: the stick


def test_init_mounts_ram_instead_of_the_stick():
    text = open(INIT, encoding="utf-8").read()
    assert 'NETBOOT=$(param beastnet.netboot)' in text
    assert "mount -t tmpfs -o nosuid,nodev,noexec,mode=0755,size=64m beastnet-data /mnt/data" in text
    assert "cp -R /netboot/. /mnt/data/" in text
    assert 'if [ "$NETBOOT" = 1 ]; then\n\tuntil mount_ram; do shell; done\nelse\n\tuntil mount_all' in text
    assert subprocess.run(["sh", "-n", INIT]).returncode == 0


# -- copies: the ddrescue mapfile ---------------------------------------------------------
def _ram_data(env):  # noqa: F811
    """The data partition is not on a disk (RAM), as on a network boot."""
    env.mounts[:] = [m for m in env.mounts if m[1] != str(env.tmp / "data")]
    env.write_mounts()


def test_clone_on_the_stick_still_refuses_a_mapfile_in_ram(env):  # noqa: F811
    _ram_data(env)
    with pytest.raises(BeastNetError) as ei:
        mk(env, mapfile_dir=str(env.tmp / "data" / "maps"))
    assert ei.value.code == DISK_REFUSED and "mapfile" in ei.value.text


def test_netboot_clone_keeps_the_mapfile_in_ram_and_says_so(env):  # noqa: F811
    _ram_data(env)
    env.ctx.params = SimpleNamespace(netboot=True)
    p = mk(env, mapfile_dir=str(env.tmp / "data" / "maps"))
    assert p.mapfile.startswith(str(env.tmp / "data" / "maps"))
    assert C.RAM_MAP_NOTE in p.notes
    # a disk place still wins over RAM, and the safety rules are unchanged
    p = mk(env, mapfile_dir=str(env.tmp / "ext"))
    assert p.mapfile.startswith(str(env.tmp / "ext")) and C.RAM_MAP_NOTE not in p.notes
    with pytest.raises(BeastNetError) as ei:
        mk(env, target="SRC000001", mapfile_dir=str(env.tmp / "data" / "maps"))
    assert ei.value.code == DISK_REFUSED


def test_netboot_image_mapfile_goes_next_to_the_image(env):  # noqa: F811
    _ram_data(env)
    env.ctx.params = SimpleNamespace(netboot=True)
    p = mk(env, "image", target=str(env.tmp / "ext" / "ok.img"),
           mapfile_dir=str(env.tmp / "data" / "maps"))
    assert p.mapfile == str(env.tmp / "ext" / "ok.img.map") and C.RAM_MAP_NOTE not in p.notes


# -- session and screens ------------------------------------------------------------------
def test_netboot_image_paths_need_another_disk(session_ctx):  # noqa: F811
    session_ctx.params = SimpleNamespace(netboot=True)
    with pytest.raises(BeastNetError) as ei:
        S.run_plan(session_ctx, [{"op": "image", "source": "nvme0n1", "dest": "/images/a.img"}],
                   modules=Parts())
    assert ei.value.code == DISK_REFUSED and "no BeastBoot drive" in ei.value.text
    # with "on" (a disk opened by use_disk) it works as on the stick
    parts = Parts()
    S.run_plan(session_ctx, [{"op": "use_disk", "disk": "TGT0000CCC333", "confirm": "CCC333"},
                             {"op": "image", "source": "nvme0n1", "dest": "/images/n0.img",
                              "on": "TGT0000CCC333"}], modules=parts)
    assert any(c[0] == "plan" for c in parts.calls)


def test_netboot_screens_offer_no_stick_place(session_ctx):  # noqa: F811
    session_ctx.params = SimpleNamespace(netboot=True)
    ui = DiskUI([
        pick("Model nvme0n1"),                  # home: a source disk
        pick("Save this one disk as an image"),  # one disk of the md set
        None,                                   # back from "Save the image where?"
        None,                                   # back from the disk
        pick("What is safe here?"), True,       # the netboot text
        pick("Power off"),
    ])
    screens, flow = flow_for(session_ctx, ui, Parts())
    flow.common_items = lambda: [Item("Power off", "poweroff")]
    flow.common = lambda c: (_ for _ in ()).throw(Quit(c))
    with pytest.raises(Quit):
        screens.run(entry=True)
    where = [s for s in ui.shown if s[1] == "Save the image where?"][0][2]
    assert not any("BeastBoot" in i.label for i in where["items"])
    assert any("sdb" in str(i.value) for i in where["items"])   # the exFAT disk is offered
    home = [s for s in ui.shown if s[0] == "menu" and s[1] == "Disk tools"][0][2]
    assert not any(i.label.startswith("Download an ISO") for i in home["items"])
    doc = [s for s in ui.shown if s[1] == "What is safe here?"][0][2]
    assert ABOUT_NETBOOT != ABOUT and "Started over the network" in ABOUT_NETBOOT
    assert doc["text"] == ABOUT_NETBOOT


def test_netboot_flow_is_disk_tools_only(monkeypatch):
    from beastnet import diskflow
    from beastnet.flow import Interactive
    opened = []
    monkeypatch.setattr(diskflow.DiskScreens, "run", lambda self, entry=False: opened.append(entry))
    ui = ScriptedUI([pick("Disk tools"), pick("Power off")])
    ctx = SimpleNamespace(net=object(), params=SimpleNamespace(netboot=True), notes=[],
                          system=SimpleNamespace(poweroff=lambda: None))
    with pytest.raises(Quit):
        Interactive(ctx, ui).run(action="disk")
    assert opened == [True, True]   # never the network or the link screens
    menu = [s for s in ui.shown if s[0] == "menu"][0][2]
    labels = [i.label for i in menu["items"]]
    assert "Reboot" in labels and not any("beast-boot menu" in x for x in labels)
    assert ("task", "Powering off", "Powering off...") in ui.shown
