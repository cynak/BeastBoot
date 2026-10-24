import os
import shutil
import socket
import subprocess
import threading

import pytest

from beastnet.errors import BeastNetError
from beastnet.wifi import (OPEN, OWE, PSK, PSK_SAE, SAE, WifiNetwork, check_passphrase,
                           classify_event, parse_iw_scan, wpa_config, wpa_psk)
from bn_helpers import FakeRunner, FakeSys
from test_net import Clock, service

DATA = os.path.join(os.path.dirname(__file__), "data")


def scan(name):
    with open(os.path.join(DATA, name)) as f:
        return parse_iw_scan(f.read())


def test_parse_mixed_scan():
    nets = scan("iw_scan_mixed.txt")
    by = {n.ssid_bytes: n for n in nets}
    # one entry per SSID, the strongest BSS, sorted by signal; hidden ones dropped
    assert [n.ssid for n in nets] == ["HomeNet", "Mesh-PSK256", "Neighbour-WPA3", "Corp", "a\\b:c",
                                      "Cafe Free WiFi", "Café ☕ ", "Very Old", "Old Router"]
    home = by[b"HomeNet"]
    assert (home.security, home.signal, home.freq, home.bssid) == (PSK_SAE, -48.0, 5180, "3c:84:6a:12:34:56")
    assert home.bars == 4 and home.band == "5 GHz"
    assert by[b"Cafe Free WiFi"].security == OPEN
    assert by[b"Corp"].security == "eap" and not by[b"Corp"].supported
    assert by[b"Neighbour-WPA3"].security == SAE and by[b"Neighbour-WPA3"].band == "6 GHz"
    assert by[b"Old Router"].security == PSK and by[b"Old Router"].bars == 0
    assert by[b"Very Old"].security == "wep" and not by[b"Very Old"].supported
    assert by[b"a\\b:c"].security == OWE
    assert by[b"Mesh-PSK256"].security == PSK
    assert by["Café ☕ ".encode()].freq == 5745  # \x escapes decoded to UTF-8 bytes


def test_parse_prefers_associated():
    nets = scan("iw_scan_associated.txt")
    assert len(nets) == 1 and nets[0].associated and nets[0].bssid == "aa:aa:aa:aa:aa:01"


def test_parse_garbage():
    assert parse_iw_scan("") == []
    assert parse_iw_scan("command failed: Operation not permitted (-1)\n") == []


def test_psk_test_vector():
    # IEEE 802.11i-2004, Annex H.4: "password" / "IEEE"
    assert wpa_psk("password", b"IEEE") == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"


@pytest.mark.skipif(not shutil.which("wpa_passphrase"), reason="wpa_passphrase not installed")
def test_psk_matches_wpa_passphrase():
    out = subprocess.run(["wpa_passphrase", "My Net", "correct horse"], capture_output=True,
                         text=True, check=True).stdout
    psk = [x.split("=", 1)[1] for x in out.split() if x.startswith("psk=")][0]
    assert wpa_psk("correct horse", b"My Net") == psk


def test_wpa_config_psk():
    conf = wpa_config(b"My \"Net\"", PSK, 'pa$$ "word"\\', ctrl_dir="/run/beastnet/wpa")
    lines = conf.splitlines()
    assert "ctrl_interface=/run/beastnet/wpa" in lines
    ssid = b'My "Net"'
    assert f"\tssid={ssid.hex()}" in lines
    assert "\tkey_mgmt=WPA-PSK WPA-PSK-SHA256" in lines
    psk = wpa_psk('pa$$ "word"' + chr(92), ssid)
    assert f"\tpsk={psk}" in lines
    assert "word" not in conf  # the passphrase itself is never written


def test_wpa_config_sae_transition_open_owe_hidden():
    sae = wpa_config(b"x", SAE, "päss", ctrl_dir="/c")
    assert "\tkey_mgmt=SAE" in sae and f"\tsae_password={'päss'.encode().hex()}" in sae
    assert "\tieee80211w=2" in sae and "sae_pwe=2" in sae
    both = wpa_config(b"x", PSK_SAE, "longenough", ctrl_dir="/c")
    assert "\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE" in both and "\tpsk=" in both and "\tieee80211w=1" in both
    raw = wpa_config(b"x", PSK_SAE, "ab" * 32, ctrl_dir="/c")
    assert "SAE" not in raw.split("network={")[1]  # a raw key only works for WPA2
    assert "\tkey_mgmt=NONE" in wpa_config(b"x", OPEN, ctrl_dir="/c")
    assert "\tkey_mgmt=OWE" in wpa_config(b"x", OWE, ctrl_dir="/c")
    hidden = wpa_config(b"secret", "auto", "longenough", ctrl_dir="/c", hidden=True)
    assert "\tscan_ssid=1" in hidden and "SAE" in hidden
    with pytest.raises(ValueError):
        wpa_config(b"x", "wep", "k", ctrl_dir="/c")


def test_check_passphrase():
    assert check_passphrase(PSK, "short") is not None
    assert check_passphrase(PSK, "x" * 64) is not None  # 64 chars but not hex
    assert check_passphrase(PSK, "ab" * 32) is None
    assert check_passphrase(PSK, "good passphrase") is None
    assert check_passphrase(PSK, "ünïcode pass") is not None
    assert check_passphrase(SAE, "") is not None and check_passphrase(SAE, "k") is None
    assert check_passphrase(OPEN, "") is None


def test_classify_events():
    assert classify_event("<3>CTRL-EVENT-CONNECTED - Connection to 3c:84:6a:12:34:56 completed [id=0 id_str=]") == "connected"
    assert classify_event('<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="HomeNet" auth_failures=1 duration=10 reason=WRONG_KEY') == "auth-failed"
    assert classify_event('<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="HomeNet" auth_failures=1 duration=10 reason=CONN_FAILED') is None
    assert classify_event("<3>WPA: 4-Way Handshake failed - pre-shared key may be incorrect") == "auth-failed"
    assert classify_event("<3>CTRL-EVENT-NETWORK-NOT-FOUND") == "not-found"
    assert classify_event("<3>CTRL-EVENT-SCAN-RESULTS ") is None


class FakeWpa:
    """A wpa_supplicant control socket that plays back events."""

    def __init__(self, path, events, status="SCANNING"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(path)
        self.events, self.status = events, status
        self.commands = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            cmd = data.decode()
            self.commands.append(cmd)
            if cmd == "ATTACH":
                self.sock.sendto(b"OK\n", addr)
                for ev in self.events:
                    self.sock.sendto(ev.encode(), addr)
            elif cmd == "STATUS":
                self.sock.sendto(f"bssid=x\nwpa_state={self.status}\n".encode(), addr)

    def close(self):
        self.sock.close()


def wifi_service(tmp_path, iw="iw_scan_mixed.txt"):
    fs = FakeSys(str(tmp_path / "sys"))
    fs.netdev("wlan0", fs.device("pci", "0000:00:14.3", "iwlwifi", pci_class="0x028000"), wifi=True)
    with open(os.path.join(DATA, iw)) as f:
        runner = FakeRunner(fs, iw_output=f.read())
    svc, rep, paths = service(tmp_path, fs, runner, kernel_log="kmsg_iwlwifi.txt")
    return svc, rep, paths, runner


@pytest.fixture
def fast_events(monkeypatch):
    """Each wait for an event advances the backend's fake clock by one second."""
    import beastnet.wifi as w
    real = w.WpaCtrl.event
    clocks = []

    def event(self, timeout):
        for c in clocks:
            c.t += 1.0
        return real(self, 0.02)
    monkeypatch.setattr(w.WpaCtrl, "event", event)
    return clocks


@pytest.mark.parametrize("events,status,code", [
    (["<3>CTRL-EVENT-SCAN-RESULTS ", "<3>CTRL-EVENT-CONNECTED - Connection to 3c:84 completed"], "SCANNING", None),
    ([], "COMPLETED", None),  # missed the event: STATUS says we are in
    (['<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="HomeNet" auth_failures=1 duration=10 reason=WRONG_KEY'],
     "DISCONNECTED", "wifi-auth"),
    (["<3>CTRL-EVENT-NETWORK-NOT-FOUND"], "SCANNING", "no-network"),
    ([], "SCANNING", "no-network"),  # nothing happens: timeout
])
def test_connect_wifi(tmp_path, fast_events, events, status, code):
    svc, rep, paths, runner = wifi_service(tmp_path)
    svc.backend.clock = Clock()
    fast_events.append(svc.backend.clock)
    fake = FakeWpa(os.path.join(paths.run, "wpa", "wlan0"), events, status)
    try:
        if code is None:
            info = svc.connect_wifi(None, "HomeNet", "longenough")
            assert (info.iface, info.type, info.ip) == ("wlan0", "wifi", "10.0.2.15")
            assert rep.lines[-1] == "BEASTNET: net up iface=wlan0 type=wifi ip=10.0.2.15"
        else:
            with pytest.raises(BeastNetError) as e:
                svc.connect_wifi(None, "HomeNet", "longenough")
            assert e.value.code == code
    finally:
        fake.close()
    assert "ATTACH" in fake.commands
    wpa = [c for c in runner.calls if c[0] == "wpa_supplicant"][0]
    assert wpa[:4] == ["wpa_supplicant", "-B", "-i", "wlan0"]
    conf = open(os.path.join(paths.run, "wpa_supplicant.conf")).read()
    assert "key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE" in conf  # HomeNet is WPA2/WPA3
    assert oct(os.stat(os.path.join(paths.run, "wpa_supplicant.conf")).st_mode & 0o777) == "0o600"


def test_connect_wifi_rejects_short_passphrase(tmp_path):
    svc, *_ = wifi_service(tmp_path)
    with pytest.raises(BeastNetError) as e:
        svc.connect_wifi(None, "Old Router", "short")
    assert e.value.code == "wifi-auth"


def test_connect_wifi_unsupported(tmp_path):
    svc, *_ = wifi_service(tmp_path)
    with pytest.raises(BeastNetError) as e:
        svc.connect_wifi(None, "Corp", "whatever")
    assert e.value.code == "no-network" and "cannot join" in e.value.text


def test_hidden_network_when_not_in_scan(tmp_path, fast_events):
    svc, rep, paths, runner = wifi_service(tmp_path)
    svc.backend.clock = Clock()
    fast_events.append(svc.backend.clock)
    fake = FakeWpa(os.path.join(paths.run, "wpa", "wlan0"), [], "COMPLETED")
    try:
        svc.connect_wifi(None, "NotInScan", "longenough")
    finally:
        fake.close()
    conf = open(os.path.join(paths.run, "wpa_supplicant.conf")).read()
    assert "scan_ssid=1" in conf and b"NotInScan".hex() in conf


def test_network_properties():
    n = WifiNetwork(b"\x00\x00")
    assert n.hidden and n.bars == 0 and n.band == ""
