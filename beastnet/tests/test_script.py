import hashlib
import json
import os
import subprocess
import sys

import pytest

from beastnet import grubenv
from beastnet.cmdline import parse_cmdline
from beastnet.context import Context
from beastnet.download import Downloader
from beastnet.errors import BeastNetError
from beastnet.events import Reporter
from beastnet.firmware import load_catalog
from beastnet.net import LinuxNetwork, NetworkService
from beastnet.paths import Paths
from beastnet.script import parse_plan, run_script
from beastnet.system import System
from bn_helpers import FakeRunner, FakeSys, have
from test_net import Clock

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
PKG = os.path.join(os.path.dirname(HERE), "python")
ISO = b"\x00" * 0x8001 + b"CD001" + os.urandom(200_000)
SHA = hashlib.sha256(ISO).hexdigest()
CMDLINE = ("BOOT_IMAGE=/beast-net/vmlinuz beastnet.data=UUID=1A2B-3C4D beastnet.esp=UUID=ABCD-1234 "
           "beastnet.sb=1 beastnet.debug=1 console=tty0 quiet\n")


def make_root(tmp_path):
    root = tmp_path / "root"
    for d in ("proc", "mnt/data", "mnt/esp/grub", "mnt/esp/beast-net/firmware"):
        (root / d).mkdir(parents=True)
    (root / "proc" / "cmdline").write_text(CMDLINE)
    env = root / "mnt/esp/grub/grubenv"
    if have("grub-editenv"):
        subprocess.run(["grub-editenv", str(env), "create"], check=True)
        subprocess.run(["grub-editenv", str(env), "set", "saved_entry=0"], check=True)
    else:
        env.write_bytes(grubenv.GrubEnv().to_bytes())
    (root / "mnt/esp/beast-net/catalog.json").write_bytes(open(os.path.join(DATA, "catalog.json"), "rb").read())
    (root / "mnt/esp/beast-net/firmware/installed.json").write_text(json.dumps(
        {"v": 1, "packs": [{"id": "intel-wifi", "catalog_tag": "20260918", "cpio_sha256": "00", "files": []}]}))
    return root


def write_plan(root, **plan):
    (root / "mnt/data/plan.json").write_text(json.dumps(plan))


def oneshot(root):
    return grubenv.load(str(root / "mnt/esp/grub/grubenv")).get("bb_oneshot")


def context(tmp_path, root, certs, *, wired=True):
    fs = FakeSys(str(tmp_path / "sys"))
    if wired:
        fs.netdev("eth0", fs.device("pci", "0000:00:03.0", "e1000", pci_class="0x020000"), carrier=True)
    paths = Paths(root=str(root), sys=fs.root, ca_file=certs.ca,
                  kernel_log=os.path.join(DATA, "dmesg_clean.txt"))
    rep = Reporter()
    runner = FakeRunner(fs)
    clock = Clock()
    catalog = load_catalog(paths.catalog)
    net = NetworkService(LinuxNetwork(paths, runner, catalog, sleep=clock.sleep, clock=clock), rep)
    notes = []
    system = System(paths, runner, dry_run=True, say=notes.append)

    def downloader():
        return Downloader(paths.data, paths.ca_file, reporter=rep, timeout=5, retry_delays=(0,),
                          sleep=lambda s: None)
    ctx = Context(paths, parse_cmdline(CMDLINE), rep, system, net, catalog, downloader,
                  "7.0.0-10-generic", True, notes)
    return ctx, rep, notes


def test_script_end_to_end_with_fake_network(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/isos/distro.iso", ISO)
    write_plan(root, network={"type": "ethernet"}, url=https.url("/isos/distro.iso"), sha256=SHA,
               sha256_url=None, dest="/downloads/distro.iso", then="reboot")
    ctx, rep, notes = context(tmp_path, root, certs)
    outcome, result = run_script(ctx, "/plan.json")
    assert outcome == "done" and result.verified
    lines = [x for x in rep.lines if "progress" not in x]
    assert lines == [
        "BEASTNET: nic eth0 type=ethernet driver=e1000 state=up",
        "BEASTNET: net up iface=eth0 type=ethernet ip=10.0.2.15",
        f"BEASTNET: download start url={https.url('/isos/distro.iso')} dest=/downloads/distro.iso",
        f"BEASTNET: download done path=/downloads/distro.iso bytes={len(ISO)} sha256={SHA}",
        f"BEASTNET: verify ok sha256={SHA}",
        "BEASTNET: handoff oneshot=/downloads/distro.iso",
    ]
    assert "BEASTNET: download progress pct=100" in rep.lines
    assert oneshot(root) == "/downloads/distro.iso"
    assert (root / "mnt/data/downloads/distro.iso").read_bytes() == ISO
    assert notes[-1] == "[dry-run] would reboot now"
    if have("grub-editenv"):
        out = subprocess.run(["grub-editenv", str(root / "mnt/esp/grub/grubenv"), "list"],
                             capture_output=True, text=True, check=True).stdout
        assert out.splitlines() == ["saved_entry=0", "bb_oneshot=/downloads/distro.iso"]


def test_script_stay_and_poweroff(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), then="stay")
    ctx, rep, notes = context(tmp_path, root, certs)
    outcome, result = run_script(ctx, "plan.json")
    assert outcome == "stay" and result.path == "/downloads/x.iso" and not result.verified
    assert oneshot(root) is None  # only "reboot" hands off
    write_plan(root, url=https.url("/x.iso"), sha256=SHA, then="poweroff")
    outcome, result = run_script(ctx, "/plan.json")
    assert outcome == "done" and result.reused  # same file already there: verified, reused
    assert notes[-1] == "[dry-run] would poweroff now"


def test_script_checksum_mismatch(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), sha256="0" * 64, then="reboot", on_error="poweroff")
    ctx, rep, notes = context(tmp_path, root, certs)
    outcome, result = run_script(ctx, "/plan.json")
    assert (outcome, result) == ("done", None)
    assert rep.lines[-2] == f"BEASTNET: verify fail expected={'0' * 64} got={SHA}"
    assert rep.lines[-1].startswith("BEASTNET: error checksum-mismatch ")
    assert oneshot(root) is None
    assert not os.listdir(root / "mnt/data/downloads")
    assert notes[-1] == "[dry-run] would poweroff now"


def test_script_no_cable(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    write_plan(root, url=https.url("/x.iso"), then="reboot")
    ctx, rep, notes = context(tmp_path, root, certs, wired=False)
    outcome, _ = run_script(ctx, "/plan.json")
    assert outcome == "stay"
    assert rep.lines[-1] == "BEASTNET: error no-network no wired network adapter found"


def test_script_missing_grubenv(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    (root / "mnt/esp/grub/grubenv").unlink()
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), then="reboot", on_error="shell")
    ctx, rep, notes = context(tmp_path, root, certs)
    outcome, _ = run_script(ctx, "/plan.json")
    assert outcome == "shell"
    assert rep.lines[-1].startswith("BEASTNET: error grubenv ")
    assert (root / "mnt/data/downloads/x.iso").exists()  # the ISO is kept


def test_script_bad_plans(tmp_path, certs):
    root = make_root(tmp_path)
    ctx, rep, _ = context(tmp_path, root, certs)
    assert run_script(ctx, "/missing.json") == ("stay", None)
    assert rep.lines[-1].startswith("BEASTNET: error script cannot read /missing.json")
    (root / "mnt/data/plan.json").write_text("{not json")
    run_script(ctx, "/plan.json")
    assert rep.lines[-1].startswith("BEASTNET: error script /plan.json is not valid JSON")
    run_script(ctx, "/../etc/passwd")
    assert rep.lines[-1].startswith("BEASTNET: error script ")


@pytest.mark.parametrize("plan,msg", [
    ([], "JSON object"),
    ({"url": "https://x/y.iso", "network": {"type": "carrier-pigeon"}}, "network.type"),
    ({"url": "https://x/y.iso", "network": {"type": "wifi"}}, "ssid"),
    ({"network": {"type": "ethernet"}}, "url"),
    ({"url": "https://x/y.iso", "sha256": "abc"}, "sha256"),
    ({"url": "https://x/y.iso", "dest": "/boot/x.iso"}, "dest"),
    ({"url": "https://x/y.iso", "then": "explode"}, "then"),
    ({"url": "https://x/y.iso", "on_error": "panic"}, "on_error"),
    ({"url": "https://x/y.iso", "overwrite": "yes"}, "overwrite"),
])
def test_parse_plan_rejects(plan, msg):
    with pytest.raises(BeastNetError) as e:
        parse_plan(plan)
    assert e.value.code == "script" and msg in e.value.text


def test_parse_plan_contract_example():
    p = parse_plan({"network": {"type": "ethernet"}, "url": "https://example.org/x.iso",
                    "sha256": None, "sha256_url": None, "dest": "/downloads/x.iso", "then": "reboot"})
    assert (p.then, p.on_error, p.request.dest, p.request.sha256) == ("reboot", "stay", "/downloads/x.iso", None)
    p = parse_plan({"network": {"type": "wifi", "ssid": "Home", "psk": "secret123"},
                    "url": "https://example.org/x.iso", "sha256": "A" * 64})
    assert p.network["ssid"] == "Home" and p.request.sha256 == "a" * 64


def test_host_dry_run_subprocess(tmp_path, https, site, certs):
    """python3 -m beastnet on the host: --root overrides, no network changes, no reboot."""
    root = make_root(tmp_path)
    site.add("/isos/distro.iso", ISO)
    site.add("/isos/SHA256SUMS", f"{SHA}  distro.iso\n".encode())
    write_plan(root, network={"type": "ethernet"}, url=https.url("/isos/distro.iso"),
               sha256_url=https.url("/isos/SHA256SUMS"), then="reboot")
    env = dict(os.environ, PYTHONPATH=PKG)
    cp = subprocess.run([sys.executable, "-m", "beastnet", "--root", str(root), "--script", "/plan.json",
                         "--ca-file", certs.ca, "--kernel-log", os.path.join(DATA, "dmesg_mixed.txt")],
                        capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL)
    assert cp.returncode == 0, cp.stderr
    lines = [x for x in cp.stdout.splitlines() if "progress" not in x]
    kernel = os.uname().release
    assert lines == [
        f"BEASTNET: ready kernel={kernel} sb=1 firmware=intel-wifi",
        f"BEASTNET: download start url={https.url('/isos/distro.iso')} dest=/downloads/distro.iso",
        f"BEASTNET: download done path=/downloads/distro.iso bytes={len(ISO)} sha256={SHA}",
        f"BEASTNET: verify ok sha256={SHA}",
        "BEASTNET: handoff oneshot=/downloads/distro.iso",
    ]
    assert "dry run" in cp.stderr and "would reboot" in cp.stderr
    assert oneshot(root) == "/downloads/distro.iso"
    assert (root / "run/beastnet/events.log").exists()


def test_help_runs():
    cp = subprocess.run([sys.executable, "-m", "beastnet", "--help"], capture_output=True, text=True,
                        env=dict(os.environ, PYTHONPATH=PKG), timeout=30)
    assert cp.returncode == 0 and "--script" in cp.stdout
