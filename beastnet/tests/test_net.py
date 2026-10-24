import os

import pytest

from beastnet.errors import BeastNetError
from beastnet.events import Reporter
from beastnet.firmware import load_catalog, parse_firmware_failures, read_kernel_log
from beastnet.net import LinuxNetwork, NetworkService, detect, list_nics
from beastnet.paths import Paths
from bn_helpers import FakeRunner, FakeSys

DATA = os.path.join(os.path.dirname(__file__), "data")


def log(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read()


@pytest.fixture
def catalog():
    return load_catalog(os.path.join(DATA, "catalog.json"))


@pytest.fixture
def laptop(tmp_path):
    """A machine with a working wired NIC, a few WiFi chips missing firmware and a GPU."""
    fs = FakeSys(str(tmp_path / "sys"))
    fs.netdev("eth0", fs.device("pci", "0000:00:03.0", "e1000", pci_class="0x020000"),
              carrier=True, operstate="up")
    fs.netdev("enp3s0", fs.device("pci", "0000:03:00.0", "r8169", pci_class="0x020000"))
    fs.device("pci", "0000:00:14.3", "iwlwifi", pci_class="0x028000")  # no netdev: no firmware
    fs.device("pci", "0000:02:00.0", "rtw88_8822ce", driver="rtw_8822ce", pci_class="0x028000")
    fs.device("pci", "0000:00:02.0", "i915", pci_class="0x030000")
    fs.netdev("wlp4s0", fs.device("pci", "0000:04:00.0", "mt7921e", pci_class="0x028000"), wifi=True)
    fs.device("pci", "0000:05:00.0", "foo_wifi", pci_class="0x028000")
    fs.netdev("docker0", None)  # virtual: ignored
    return fs


def test_list_nics(laptop):
    nics = {n.name: n for n in list_nics(laptop.root)}
    assert sorted(nics) == ["enp3s0", "eth0", "wlp4s0"]
    assert (nics["eth0"].type, nics["eth0"].driver, nics["eth0"].state) == ("ethernet", "e1000", "up")
    assert (nics["wlp4s0"].type, nics["wlp4s0"].driver) == ("wifi", "mt7921e")
    assert nics["enp3s0"].state == "down"


def test_parse_kmsg_and_dmesg_formats():
    ff = parse_firmware_failures(log("kmsg_iwlwifi.txt"))
    assert [(f.driver, f.device, f.files) for f in ff] == [
        ("iwlwifi", "0000:00:14.3", ["iwlwifi-so-a0-gf-a0-89"])]
    ff = {f.driver: f for f in parse_firmware_failures(log("dmesg_mixed.txt"))}
    assert ff["rtw_8822ce"].files == ["rtw88/rtw8822c_fw.bin"]
    assert ff["r8169"].files == ["rtl_nic/rtl8168h-2.fw"]
    assert ff["foo_wifi"].files == ["foo/unknown-fw.bin"]
    assert ff["bluetooth"].device == "hci0"
    assert "e1000" not in ff


def test_detect_missing_firmware(laptop, catalog):
    rep = detect(laptop.root, log("kmsg_iwlwifi.txt") + log("dmesg_mixed.txt"), catalog)
    got = {(m.module, m.pack_id) for m in rep.missing}
    assert got == {("iwlwifi", "intel-wifi"),  # matched by version prefix and module
                   ("rtw88_8822ce", "realtek-wifi"),  # module from sysfs, not the driver name
                   ("foo_wifi", None)}  # a network device no pack covers
    # The GPU, bluetooth and the working r8169 / mt7921e interfaces are not reported.
    adv = {m.module: m.advice() for m in rep.missing}
    assert '"Intel WiFi" pack' in adv["iwlwifi"]
    assert "no beast-booter firmware pack" in adv["foo_wifi"]


def test_failed_link_means_no_firmware(laptop, catalog):
    rep = detect(laptop.root, log("dmesg_mixed.txt"), catalog,
                 failed_links={"wlp4s0": "RTNETLINK answers: No such file or directory"})
    nic = {n.name: n for n in rep.nics}["wlp4s0"]
    assert nic.state == "no-firmware"
    m = [m for m in rep.missing if m.module == "mt7921e"][0]
    assert (m.pack_id, m.nic) == ("mediatek-wifi", "wlp4s0")


def test_empty_catalog_still_reports(laptop):
    from beastnet.firmware import Catalog
    rep = detect(laptop.root, log("kmsg_iwlwifi.txt"), Catalog())
    assert [(m.module, m.pack_id) for m in rep.missing] == [("iwlwifi", None)]


def test_kernel_log_from_file(tmp_path):
    p = tmp_path / "log"
    p.write_text("hello\n")
    assert read_kernel_log(str(p)) == "hello\n"


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def service(tmp_path, fake_sys, runner, kernel_log="dmesg_mixed.txt", catalog=None):
    paths = Paths(root=str(tmp_path / "root"), sys=fake_sys.root,
                  kernel_log=os.path.join(DATA, kernel_log))
    clock = Clock()
    backend = LinuxNetwork(paths, runner, catalog or load_catalog(os.path.join(DATA, "catalog.json")),
                           sleep=clock.sleep, clock=clock)
    rep = Reporter()
    return NetworkService(backend, rep), rep, paths


def test_probe_emits_lines(tmp_path, laptop):
    runner = FakeRunner(laptop, link_errors={"wlp4s0": "RTNETLINK answers: No such file or directory"})
    svc, rep, _ = service(tmp_path, laptop, runner)
    svc.probe()
    assert rep.lines == [
        "BEASTNET: nic enp3s0 type=ethernet driver=r8169 state=down",
        "BEASTNET: nic eth0 type=ethernet driver=e1000 state=up",
        "BEASTNET: nic wlp4s0 type=wifi driver=mt7921e state=no-firmware",
        "BEASTNET: firmware missing driver=rtw88_8822ce pack=realtek-wifi",
        "BEASTNET: firmware missing driver=mt7921e pack=mediatek-wifi",
        "BEASTNET: firmware missing driver=foo_wifi pack=unknown",
    ]
    assert ["ip", "link", "set", "dev", "eth0", "up"] in runner.calls
    svc.probe()  # firmware lines are not repeated
    assert sum("firmware missing" in x for x in rep.lines) == 3


def test_connect_ethernet_dhcp(tmp_path, laptop):
    runner = FakeRunner(laptop)
    svc, rep, paths = service(tmp_path, laptop, runner)
    info = svc.connect_ethernet()
    assert (info.iface, info.type, info.ip) == ("eth0", "ethernet", "10.0.2.15")
    assert rep.lines[-1] == "BEASTNET: net up iface=eth0 type=ethernet ip=10.0.2.15"
    udhcpc = [c for c in runner.calls if c[0] == "udhcpc"][0]
    assert udhcpc[:3] == ["udhcpc", "-i", "eth0"] and "-q" in udhcpc and "-n" in udhcpc
    assert udhcpc[udhcpc.index("-s") + 1] == paths.dhcp_script


def test_connect_ethernet_no_cable(tmp_path, laptop):
    laptop.set_carrier("eth0", False)
    svc, rep, _ = service(tmp_path, laptop, FakeRunner(laptop))
    with pytest.raises(BeastNetError) as e:
        svc.connect_ethernet()
    assert e.value.code == "no-network" and "cable" in e.value.text


def test_connect_ethernet_dhcp_fails(tmp_path, laptop):
    svc, rep, _ = service(tmp_path, laptop, FakeRunner(laptop, dhcp_ip=None))
    with pytest.raises(BeastNetError) as e:
        svc.connect_ethernet()
    assert e.value.code == "dhcp"


def test_no_adapters(tmp_path):
    fs = FakeSys(str(tmp_path / "sys"))
    svc, rep, _ = service(tmp_path, fs, FakeRunner(fs), kernel_log="kmsg_iwlwifi.txt")
    r = svc.probe()
    # No interface at all, but the log names a driver a pack covers: say which pack.
    assert r.nics == []
    assert rep.lines == ["BEASTNET: firmware missing driver=iwlwifi pack=intel-wifi"]
    with pytest.raises(BeastNetError) as e:
        svc.connect_ethernet()
    assert e.value.code == "no-network"
    with pytest.raises(BeastNetError) as e:
        svc.connect_wifi(None, "x", "password1")
    assert e.value.code == "no-network" and "Intel WiFi" in e.value.hint


def test_udhcpc_script_configures(tmp_path):
    """Run the real udhcpc event script with fake ip/mv tools on PATH."""
    import shutil
    import subprocess
    if not shutil.which("sh"):
        pytest.skip("no POSIX sh")
    script = os.path.join(os.path.dirname(DATA), "..", "rootfs", "usr", "share", "beastnet",
                          "udhcpc.script")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "ip").write_text(f'#!/bin/sh\necho "ip $*" >> {tmp_path}/ip.log\n')
    (bindir / "ip").chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "interface": "eth0", "ip": "10.0.2.15", "mask": "24",
           "router": "10.0.2.2", "dns": "10.0.2.3 10.0.2.4", "domain": "lan",
           "RESOLV_CONF": str(tmp_path / "resolv.conf"), "BEASTNET_RUN": str(tmp_path / "run")}
    # Plain sh, not busybox sh: busybox runs its own ip applet instead of our fake.
    subprocess.run(["sh", script, "bound"], env=env, check=True)
    assert (tmp_path / "resolv.conf").read_text() == "search lan\nnameserver 10.0.2.3\nnameserver 10.0.2.4\n"
    assert "ip=10.0.2.15" in (tmp_path / "run" / "dhcp-eth0").read_text()
    iplog = (tmp_path / "ip.log").read_text()
    assert "ip -4 addr add 10.0.2.15/24 dev eth0" in iplog
    assert "ip -4 route add default via 10.0.2.2 dev eth0" in iplog
