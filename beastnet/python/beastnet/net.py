"""Network adapters: listing, missing firmware, wired and WiFi bring-up, DHCP.

``detect()`` is pure (a sysfs tree, the kernel log, the catalog) so it can be
tested against fake trees. ``LinuxNetwork`` runs the tools (ip, udhcpc, iw,
wpa_supplicant) through a Runner. ``NetworkService`` holds the policy shared by
the interactive screens and script mode, and emits the BEASTNET: lines.
"""

from __future__ import annotations

import os
import re
import signal
import time
from dataclasses import dataclass, field

from .errors import DHCP, NO_NETWORK, WIFI_AUTH, BeastNetError
from .events import Reporter
from .firmware import Catalog, Pack, parse_firmware_failures, read_kernel_log
from .paths import Paths
from .system import Runner
from .wifi import (OPEN, WifiNetwork, WpaCtrl, check_passphrase, classify_event,
                   parse_iw_scan, wpa_config)


@dataclass
class Nic:
    name: str
    type: str  # "ethernet" | "wifi"
    driver: str  # kernel module, "unknown" if it cannot be found
    device: str  # resolved sysfs device directory
    mac: str = ""
    carrier: bool = False
    operstate: str = "unknown"
    state: str = "down"  # "up" | "down" | "no-firmware"
    error: str = ""  # last bring-up error


@dataclass
class MissingFirmware:
    module: str
    device: str
    files: list[str] = field(default_factory=list)
    pack: Pack | None = None
    nic: str | None = None

    @property
    def pack_id(self) -> str | None:
        return self.pack.id if self.pack else None

    def advice(self) -> str:
        what = f"The {self.module} driver" + (f" ({self.nic})" if self.nic else "")
        if self.pack:
            return (f'{what} needs firmware that is not installed. On another computer, open '
                    f'the beast-booter app, choose Firmware and install the "{self.pack.title}" '
                    f"pack onto this stick, then start beast-net again.")
        return (f"{what} needs firmware that no beast-booter firmware pack provides "
                f"({', '.join(self.files[:2]) or 'unknown file'}). Use a wired or USB adapter.")


@dataclass
class HardwareReport:
    nics: list[Nic] = field(default_factory=list)
    missing: list[MissingFirmware] = field(default_factory=list)
    rfkill_hard: bool = False

    @property
    def ethernet(self) -> list[Nic]:
        return [n for n in self.nics if n.type == "ethernet"]

    @property
    def wifi(self) -> list[Nic]:
        return [n for n in self.nics if n.type == "wifi"]


@dataclass
class NetInfo:
    iface: str
    type: str
    ip: str


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return None


def module_of(device: str | None) -> str:
    """Kernel module bound to a sysfs device directory."""
    if not device:
        return "unknown"
    for link in ("driver/module", "driver"):
        p = os.path.join(device, link)
        if os.path.exists(p):
            return os.path.basename(os.path.realpath(p))
    return "unknown"


def list_nics(sys_root: str) -> list[Nic]:
    base = os.path.join(sys_root, "class", "net")
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return []
    nics = []
    for name in names:
        d = os.path.join(base, name)
        dev = os.path.join(d, "device")
        if name == "lo" or not os.path.exists(dev):
            continue  # loopback and virtual interfaces (bridges, tun, ...)
        if _read(os.path.join(d, "type")) not in (None, "1"):
            continue  # not Ethernet-like
        is_wifi = os.path.exists(os.path.join(d, "wireless")) or os.path.exists(os.path.join(d, "phy80211"))
        device = os.path.realpath(dev)
        carrier = _read(os.path.join(d, "carrier")) == "1"
        oper = _read(os.path.join(d, "operstate")) or "unknown"
        nics.append(Nic(name, "wifi" if is_wifi else "ethernet", module_of(device), device,
                        _read(os.path.join(d, "address")) or "", carrier, oper,
                        "up" if (oper == "up" or carrier) else "down"))
    return nics


def find_device(sys_root: str, name: str) -> str | None:
    """sysfs directory of a device named in a log line (any bus)."""
    bus_dir = os.path.join(sys_root, "bus")
    try:
        buses = sorted(os.listdir(bus_dir))
    except OSError:
        return None
    for bus in buses:
        p = os.path.join(bus_dir, bus, "devices", name)
        if os.path.exists(p):
            return os.path.realpath(p)
    return None


def _is_network_device(device: str | None) -> bool:
    cls = _read(os.path.join(device, "class")) if device else None
    return bool(cls and cls.lower().startswith("0x02"))  # PCI class 02: network controller


def detect(sys_root: str, log: str, catalog: Catalog, *,
           failed_links: dict[str, str] | None = None) -> HardwareReport:
    """NICs and missing firmware. ``failed_links``: interfaces whose bring-up
    failed (name -> error), which turns their state into no-firmware when the
    kernel also logged a firmware failure for their device."""
    nics = list_nics(sys_root)
    by_dev = {n.device: n for n in nics}
    report = HardwareReport(nics)
    seen = set()
    for ff in parse_firmware_failures(log):
        device = find_device(sys_root, ff.device)
        module = module_of(device)
        if module == "unknown":
            module = ff.driver
        nic = by_dev.get(device) if device else None
        pack = catalog.find(module, ff.files) or catalog.find(ff.driver, ff.files)
        if nic is not None:
            if not failed_links or nic.name not in failed_links:
                continue  # the interface exists and works: the firmware was optional
            nic.state = "no-firmware"
            nic.error = failed_links[nic.name]
        elif pack is None and not _is_network_device(device):
            continue  # not a network device (GPU, bluetooth, ...)
        key = (module, device or ff.device)
        if key in seen:
            continue
        seen.add(key)
        report.missing.append(MissingFirmware(module, ff.device, ff.files, pack,
                                              nic.name if nic else None))
    return report


class LinuxNetwork:
    """The real thing: talks to the kernel through ip, udhcpc, iw, wpa_supplicant."""

    def __init__(self, paths: Paths, runner: Runner, catalog: Catalog, *,
                 sleep=time.sleep, clock=time.monotonic) -> None:
        self.paths = paths
        self.runner = runner
        self.catalog = catalog
        self.sleep = sleep
        self.clock = clock

    # -- hardware -------------------------------------------------------------
    def report(self, failed_links: dict[str, str] | None = None) -> HardwareReport:
        log = read_kernel_log(self.paths.kernel_log, self.paths.dev)
        rep = detect(self.paths.sys, log, self.catalog, failed_links=failed_links)
        rep.rfkill_hard = self.rfkill_hard_blocked()
        return rep

    def rfkill_hard_blocked(self) -> bool:
        base = os.path.join(self.paths.sys, "class", "rfkill")
        try:
            names = os.listdir(base)
        except OSError:
            return False
        return any(_read(os.path.join(base, n, "type")) == "wlan"
                   and _read(os.path.join(base, n, "hard")) == "1" for n in names)

    def unblock_rfkill(self) -> None:
        """Clear soft blocks on WiFi (a laptop's "airplane mode")."""
        base = os.path.join(self.paths.sys, "class", "rfkill")
        try:
            names = os.listdir(base)
        except OSError:
            return
        for n in names:
            if _read(os.path.join(base, n, "type")) == "wlan" and _read(os.path.join(base, n, "soft")) == "1":
                try:
                    with open(os.path.join(base, n, "soft"), "w") as f:
                        f.write("0")
                except OSError:
                    pass

    def link_up(self, iface: str) -> str:
        """Set the link up; returns "" or the error text."""
        cp = self.runner.run(["ip", "link", "set", "dev", iface, "up"], timeout=20)
        return "" if cp.returncode == 0 else (cp.stderr.strip() or f"exit code {cp.returncode}")

    def carrier(self, iface: str) -> bool:
        return _read(os.path.join(self.paths.sys, "class", "net", iface, "carrier")) == "1"

    def wait_carrier(self, ifaces: list[str], timeout: float) -> list[str]:
        deadline = self.clock() + timeout
        while True:
            up = [i for i in ifaces if self.carrier(i)]
            if up or self.clock() >= deadline:
                return up
            self.sleep(0.25)

    # -- addresses ------------------------------------------------------------
    def ip_of(self, iface: str) -> str | None:
        cp = self.runner.run(["ip", "-4", "-o", "addr", "show", "dev", iface], timeout=10)
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", cp.stdout or "")
        return m.group(1) if m else None

    def flush(self, iface: str) -> None:
        self.runner.run(["ip", "-4", "addr", "flush", "dev", iface], timeout=10)

    def dhcp(self, iface: str, *, tries: int = 4, wait: int = 3) -> str:
        state = os.path.join(self.paths.run, f"dhcp-{iface}")
        os.makedirs(self.paths.run, exist_ok=True)
        try:
            os.unlink(state)
        except OSError:
            pass
        cp = self.runner.run(
            ["udhcpc", "-i", iface, "-q", "-n", "-t", str(tries), "-T", str(wait),
             "-s", self.paths.dhcp_script, "-x", "hostname:beast-net"],
            timeout=tries * wait + 30,
            env={"BEASTNET_RUN": self.paths.run, "RESOLV_CONF": self.paths.resolv_conf})
        if cp.returncode != 0:
            raise BeastNetError(DHCP, f"no DHCP answer on {iface}",
                                "No router handed out an address. Check the cable or the "
                                "WiFi network, or try another one.")
        ip = None
        text = _read(state) or ""
        m = re.search(r"\bip=(\S+)", text)
        if m:
            ip = m.group(1)
        ip = ip or self.ip_of(iface)
        if not ip:
            raise BeastNetError(DHCP, f"DHCP on {iface} finished without an address")
        return ip

    # -- WiFi -------------------------------------------------------------------
    def wifi_scan(self, iface: str, attempts: int = 4) -> list[WifiNetwork]:
        self.wifi_stop()
        self.unblock_rfkill()
        err = self.link_up(iface)
        if err and "rf-kill" in err.lower():
            raise BeastNetError(NO_NETWORK, "WiFi is switched off by a hardware switch or key",
                                "Turn WiFi on with the laptop's switch or Fn key, then rescan.")
        last = err
        for i in range(attempts):
            cp = self.runner.run(["iw", "dev", iface, "scan"], timeout=40)
            if cp.returncode == 0:
                nets = parse_iw_scan(cp.stdout)
                if nets or i == attempts - 1:
                    return nets
            else:
                last = (cp.stderr or cp.stdout).strip() or f"exit code {cp.returncode}"
                if "not supported" in last.lower():
                    break
            self.sleep(1.0)
        raise BeastNetError(NO_NETWORK, f"WiFi scan on {iface} failed: {last}")

    def _wpa_pid(self) -> int | None:
        text = _read(os.path.join(self.paths.run, "wpa_supplicant.pid"))
        return int(text) if text and text.isdigit() else None

    def wifi_stop(self) -> None:
        pid = self._wpa_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                for _ in range(20):
                    os.kill(pid, 0)
                    self.sleep(0.1)
            except OSError:
                pass
            try:
                os.unlink(os.path.join(self.paths.run, "wpa_supplicant.pid"))
            except OSError:
                pass

    def wifi_connect(self, iface: str, ssid: bytes, security: str, passphrase: str, *,
                     hidden: bool = False, timeout: float = 45.0) -> None:
        self.wifi_stop()
        self.unblock_rfkill()
        self.link_up(iface)
        run = self.paths.run
        os.makedirs(run, mode=0o700, exist_ok=True)
        ctrl_dir = os.path.join(run, "wpa")
        conf = os.path.join(run, "wpa_supplicant.conf")
        text = wpa_config(ssid, security, passphrase, ctrl_dir=ctrl_dir, hidden=hidden)
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        cp = self.runner.run(["wpa_supplicant", "-B", "-i", iface, "-D", "nl80211,wext",
                              "-c", conf, "-P", os.path.join(run, "wpa_supplicant.pid")],
                             timeout=30)
        if cp.returncode != 0:
            msg = (cp.stderr or cp.stdout).strip().splitlines()
            raise BeastNetError(NO_NETWORK, f"wpa_supplicant did not start on {iface}: "
                                + (msg[-1] if msg else f"exit code {cp.returncode}"))
        ctrl_path = os.path.join(ctrl_dir, iface)
        deadline = self.clock() + 10
        while not os.path.exists(ctrl_path) and self.clock() < deadline:
            self.sleep(0.1)
        name = ssid.decode("utf-8", "replace")
        try:
            outcome = wait_for_association(WpaCtrl(ctrl_path, run), timeout, self.clock)
        except OSError as e:
            self.wifi_stop()
            raise BeastNetError(NO_NETWORK, f"cannot talk to wpa_supplicant: {e}") from None
        if outcome == "connected":
            return
        self.wifi_stop()
        if outcome == "auth-failed":
            raise BeastNetError(WIFI_AUTH, f"{name} did not accept the passphrase",
                                "Check the passphrase (it is case-sensitive) and try again.")
        if outcome == "not-found":
            raise BeastNetError(NO_NETWORK, f"{name} is not in range",
                                "Move closer to the access point, or rescan.")
        raise BeastNetError(NO_NETWORK, f"could not join {name} (no answer in {timeout:.0f} s)")


def wait_for_association(ctrl: WpaCtrl, timeout: float, clock=time.monotonic) -> str:
    """Follow wpa_supplicant events until connected, a wrong key, or the timeout.
    Returns "connected", "auth-failed", "not-found" or "timeout"."""
    not_found = False
    handshake_failures = 0
    next_status = clock() + 2.0
    deadline = clock() + timeout
    try:
        ctrl.attach()
        while clock() < deadline:
            ev = ctrl.event(0.5)
            if ev:
                outcome = classify_event(ev)
                if outcome == "connected":
                    return outcome
                if outcome == "auth-failed":
                    if "TEMP-DISABLED" in ev:
                        return outcome
                    handshake_failures += 1
                    if handshake_failures >= 2:
                        return outcome
                if outcome == "not-found":
                    not_found = True
            if clock() >= next_status:
                next_status = clock() + 2.0
                if ctrl.status().get("wpa_state") == "COMPLETED":
                    return "connected"
        return "not-found" if not_found else "timeout"
    finally:
        ctrl.close()


class NetworkService:
    """Policy shared by the screens and script mode; emits BEASTNET: lines."""

    def __init__(self, backend: LinuxNetwork, reporter: Reporter) -> None:
        self.backend = backend
        self.reporter = reporter
        self._reported: set[tuple[str, str]] = set()
        self.report: HardwareReport | None = None

    def probe(self, carrier_wait: float = 4.0) -> HardwareReport:
        """Bring every adapter's link up, wait briefly for a cable, report."""
        first = self.backend.report()
        self.backend.unblock_rfkill()
        failed = {}
        for nic in first.nics:
            err = self.backend.link_up(nic.name)
            if err:
                failed[nic.name] = err
        eth = [n.name for n in first.ethernet if n.name not in failed]
        if eth:
            self.backend.wait_carrier(eth, carrier_wait)
        rep = self.backend.report(failed)
        for nic in rep.nics:
            nic.error = nic.error or failed.get(nic.name, "")
            self.reporter.nic(nic.name, nic.type, nic.driver, nic.state)
        for mf in rep.missing:
            key = (mf.module, mf.device)
            if key not in self._reported:
                self._reported.add(key)
                self.reporter.firmware_missing(mf.module, mf.pack_id)
        self.report = rep
        return rep

    def connect_ethernet(self, iface: str | None = None, carrier_wait: float = 6.0) -> NetInfo:
        rep = self.report or self.probe()
        nics = [n for n in rep.ethernet if iface in (None, n.name)]
        if not nics:
            raise BeastNetError(NO_NETWORK, f"no wired adapter {iface}" if iface else
                                "no wired network adapter found")
        for n in nics:
            self.backend.link_up(n.name)
        up = self.backend.wait_carrier([n.name for n in nics], carrier_wait)
        if not up:
            raise BeastNetError(NO_NETWORK, "no network cable connected ("
                                + ", ".join(n.name for n in nics) + " have no link)",
                                "Plug in a network cable, or use WiFi.")
        last: BeastNetError | None = None
        for name in up:
            try:
                ip = self.backend.dhcp(name)
            except BeastNetError as e:
                last = e
                continue
            self.reporter.net_up(name, "ethernet", ip)
            return NetInfo(name, "ethernet", ip)
        assert last is not None
        raise last

    def scan(self, iface: str) -> list[WifiNetwork]:
        return self.backend.wifi_scan(iface)

    def connect_wifi(self, iface: str | None, ssid: str | bytes, passphrase: str = "", *,
                     network: WifiNetwork | None = None, hidden: bool = False) -> NetInfo:
        rep = self.report or self.probe()
        if iface is None:
            if not rep.wifi:
                hint = " ".join(m.advice() for m in rep.missing) or \
                    "This computer has no WiFi adapter that beast-net can use."
                raise BeastNetError(NO_NETWORK, "no WiFi adapter found", hint)
            iface = rep.wifi[0].name
        raw = ssid.encode("utf-8") if isinstance(ssid, str) else ssid
        if network is None and not hidden:
            for n in self.scan(iface):
                if n.ssid_bytes == raw:
                    network = n
                    break
            else:
                hidden = True  # not seen: maybe a hidden network, try it anyway
        security = network.security if network else ("auto" if passphrase else OPEN)
        if network is not None and not network.supported:
            raise BeastNetError(NO_NETWORK, f"{network.ssid} uses {network.security.upper()}, "
                                "which beast-net cannot join")
        problem = check_passphrase(security, passphrase) if security != "auto" else None
        if problem:
            raise BeastNetError(WIFI_AUTH, problem)
        self.backend.wifi_connect(iface, raw, security, passphrase, hidden=hidden)
        ip = self.backend.dhcp(iface)
        self.reporter.net_up(iface, "wifi", ip)
        return NetInfo(iface, "wifi", ip)
