"""WiFi: ``iw`` scan parsing, wpa_supplicant configuration and control socket.

Security handled: open (with a warning), WPA/WPA2-Personal (PSK), WPA3-Personal
(SAE), the WPA2/WPA3 transition mode, and OWE ("Enhanced Open"). WEP and
802.1X (enterprise) networks are listed but cannot be joined.

The configuration never contains the passphrase in a form that needs quoting:
the SSID is written in hex, the WPA2 key as the 256-bit PSK derived from the
passphrase (PBKDF2, as wpa_passphrase does), and the WPA3 password in hex.
"""

from __future__ import annotations

import hashlib
import os
import re
import select
import socket
import time
from dataclasses import dataclass

OPEN, WEP, PSK, SAE, PSK_SAE, OWE, EAP = "open", "wep", "psk", "sae", "psk-sae", "owe", "eap"
SECURITY_LABEL = {OPEN: "open", WEP: "WEP", PSK: "WPA2", SAE: "WPA3", PSK_SAE: "WPA2/3",
                  OWE: "OWE", EAP: "802.1X"}


@dataclass
class WifiNetwork:
    ssid_bytes: bytes
    bssid: str = ""
    signal: float | None = None  # dBm
    freq: int | None = None  # MHz
    security: str = OPEN
    associated: bool = False

    @property
    def ssid(self) -> str:
        return self.ssid_bytes.decode("utf-8", "replace")

    @property
    def hidden(self) -> bool:
        return not self.ssid_bytes or set(self.ssid_bytes) == {0}

    @property
    def supported(self) -> bool:
        return self.security not in (WEP, EAP)

    @property
    def needs_passphrase(self) -> bool:
        return self.security in (PSK, SAE, PSK_SAE)

    @property
    def bars(self) -> int:
        s = self.signal
        if s is None:
            return 0
        return 4 if s >= -55 else 3 if s >= -67 else 2 if s >= -75 else 1 if s >= -85 else 0

    @property
    def band(self) -> str:
        f = self.freq or 0
        return "6 GHz" if f >= 5925 else "5 GHz" if f >= 4900 else "2.4 GHz" if f else ""


def _unescape_iw(text: str) -> bytes:
    """iw prints SSID bytes that are not printable (and edge spaces, ``\\``) as \\xNN."""
    out = bytearray()
    i = 0
    raw = text.encode("utf-8", "surrogateescape")
    while i < len(raw):
        if raw[i:i + 2] == b"\\x" and i + 4 <= len(raw):
            try:
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        out.append(raw[i])
        i += 1
    return bytes(out)


def _security(rsn: list[str], wpa: list[str], privacy: bool) -> str:
    suites = " ".join(rsn + wpa)
    has_sae = bool(re.search(r"\bSAE\b|SAE-EXT-KEY|FT/SAE", suites))
    has_psk = bool(re.search(r"(?<![\w/])PSK\b|PSK/SHA-256|FT/PSK", suites))
    if "802.1X" in suites and not (has_sae or has_psk):
        return EAP
    if has_sae and has_psk:
        return PSK_SAE
    if has_sae:
        return SAE
    if has_psk:
        return PSK
    if re.search(r"\bOWE\b", suites):
        return OWE
    return WEP if privacy else OPEN


def parse_iw_scan(text: str) -> list[WifiNetwork]:
    """Parse ``iw dev <if> scan``: one entry per SSID (strongest BSS), strongest
    first. Hidden networks (empty SSID) are dropped."""
    found: list[WifiNetwork] = []
    cur: WifiNetwork | None = None
    section = ""
    suites: dict[str, list[str]] = {}
    privacy = False

    def finish() -> None:
        if cur is not None:
            cur.security = _security(suites.get("RSN", []), suites.get("WPA", []), privacy)
            found.append(cur)

    for line in text.splitlines():
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", line)
        if m:
            finish()
            cur = WifiNetwork(b"", bssid=m.group(1).lower(), associated="associated" in line)
            section, suites, privacy = "", {}, False
            continue
        if cur is None:
            continue
        top = re.match(r"^\t(\S[^:]*):\s?(.*)$", line)
        if top:
            key, value = top.group(1), top.group(2)
            section = key
            if key == "SSID":
                cur.ssid_bytes = _unescape_iw(value)
            elif key == "signal":
                m2 = re.match(r"(-?\d+(?:\.\d+)?)", value.strip())
                cur.signal = float(m2.group(1)) if m2 else None
            elif key == "freq":
                m2 = re.match(r"(\d+)", value.strip())
                cur.freq = int(m2.group(1)) if m2 else None
            elif key == "capability":
                privacy = "Privacy" in value.split()
            # "RSN:\t * Version: 1" puts the first item on the same line
            item = re.search(r"\* Authentication suites: (.*)$", value)
            if item and key in ("RSN", "WPA"):
                suites.setdefault(key, []).append(item.group(1))
            continue
        item = re.match(r"^\t\t?\s*\* Authentication suites: (.*)$", line)
        if item and section in ("RSN", "WPA"):
            suites.setdefault(section, []).append(item.group(1).strip())
    finish()

    best: dict[bytes, WifiNetwork] = {}
    for n in found:
        if n.hidden:
            continue
        old = best.get(n.ssid_bytes)
        if old is None or (n.signal or -999) > (old.signal or -999) or n.associated:
            if old is not None and old.associated and not n.associated:
                continue
            best[n.ssid_bytes] = n
    return sorted(best.values(), key=lambda n: (-(n.signal if n.signal is not None else -999), n.ssid))


# -- wpa_supplicant ------------------------------------------------------------

def check_passphrase(security: str, passphrase: str) -> str | None:
    """None if acceptable, else a message for the user."""
    if security in (PSK, PSK_SAE):
        if re.fullmatch(r"[0-9a-fA-F]{64}", passphrase):
            return None  # a raw WPA2 key
        if not 8 <= len(passphrase) <= 63:
            return "A WPA2 passphrase has 8 to 63 characters"
        if any(not 32 <= ord(c) <= 126 for c in passphrase):
            return "A WPA2 passphrase uses plain ASCII characters only"
    if security == SAE and not passphrase:
        return "Enter the network's password"
    return None


def wpa_psk(passphrase: str, ssid: bytes) -> str:
    """The 256-bit PSK for a WPA2 passphrase (same as wpa_passphrase)."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", passphrase):
        return passphrase.lower()
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid, 4096, 32).hex()


def wpa_config(ssid: bytes, security: str, passphrase: str = "", *, ctrl_dir: str,
               hidden: bool = False) -> str:
    """wpa_supplicant.conf for one network. ``security`` may also be "auto" for
    a hidden network typed in by hand (PSK or SAE, whichever the AP offers)."""
    lines = [
        f"ctrl_interface={ctrl_dir}",
        "update_config=0",
        "ap_scan=1",
        "sae_pwe=2",  # WPA3: hunting-and-pecking and hash-to-element
        "",
        "network={",
        f"\tssid={ssid.hex()}",
    ]
    if hidden:
        lines.append("\tscan_ssid=1")
    sec = security
    if sec == "auto":
        sec = PSK_SAE if passphrase else OPEN
    if sec == PSK_SAE and re.fullmatch(r"[0-9a-fA-F]{64}", passphrase):
        sec = PSK  # a raw 256-bit key only works for WPA2
    if sec == OPEN:
        lines.append("\tkey_mgmt=NONE")
    elif sec == OWE:
        lines += ["\tkey_mgmt=OWE", "\tieee80211w=2"]
    elif sec == PSK:
        lines += ["\tkey_mgmt=WPA-PSK WPA-PSK-SHA256", f"\tpsk={wpa_psk(passphrase, ssid)}",
                  "\tieee80211w=1"]
    elif sec == SAE:
        lines += ["\tkey_mgmt=SAE", f"\tsae_password={passphrase.encode('utf-8').hex()}",
                  "\tieee80211w=2"]
    elif sec == PSK_SAE:
        lines += ["\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE"]
        if check_passphrase(PSK, passphrase) is None:
            lines.append(f"\tpsk={wpa_psk(passphrase, ssid)}")
        lines += [f"\tsae_password={passphrase.encode('utf-8').hex()}", "\tieee80211w=1"]
    else:
        raise ValueError(f"cannot join {SECURITY_LABEL.get(sec, sec)} networks")
    lines += ["}", ""]
    return "\n".join(lines)


# Events on the control socket -> outcome.
def classify_event(msg: str) -> str | None:
    """'connected', 'auth-failed', 'not-found' or None for a wpa_supplicant event."""
    msg = re.sub(r"^<\d+>", "", msg.strip())
    if msg.startswith("CTRL-EVENT-CONNECTED"):
        return "connected"
    if msg.startswith("CTRL-EVENT-SSID-TEMP-DISABLED") and re.search(
            r"reason=(WRONG_KEY|AUTH_FAILED)", msg):
        return "auth-failed"
    if "4-Way Handshake failed" in msg or "pre-shared key may be incorrect" in msg:
        return "auth-failed"
    if msg.startswith("CTRL-EVENT-SAE-UNKNOWN-PASSWORD-IDENTIFIER"):
        return "auth-failed"
    if msg.startswith("CTRL-EVENT-NETWORK-NOT-FOUND"):
        return "not-found"
    return None


class WpaCtrl:
    """Minimal client for wpa_supplicant's UNIX datagram control socket."""

    _counter = 0

    def __init__(self, ctrl_path: str, local_dir: str) -> None:
        WpaCtrl._counter += 1
        self.local = os.path.join(local_dir, f"wpa_ctrl_{os.getpid()}_{WpaCtrl._counter}")
        try:
            os.unlink(self.local)
        except OSError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.sock.bind(self.local)
            self.sock.connect(ctrl_path)
        except OSError:
            self.close()
            raise

    def close(self) -> None:
        try:
            self.sock.close()
        finally:
            try:
                os.unlink(self.local)
            except OSError:
                pass

    def request(self, cmd: str, timeout: float = 5.0) -> str:
        """Send a command; skip unsolicited events ("<N>...") until the reply."""
        self.sock.send(cmd.encode())
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"wpa_supplicant did not answer {cmd}")
            r, _, _ = select.select([self.sock], [], [], left)
            if not r:
                continue
            data = self.sock.recv(8192).decode("utf-8", "replace")
            if not data.startswith("<"):
                return data

    def attach(self) -> None:
        if self.request("ATTACH").strip() != "OK":
            raise OSError("wpa_supplicant refused ATTACH")

    def event(self, timeout: float) -> str | None:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        if not r:
            return None
        return self.sock.recv(8192).decode("utf-8", "replace")

    def status(self) -> dict[str, str]:
        out = {}
        for line in self.request("STATUS").splitlines():
            k, sep, v = line.partition("=")
            if sep:
                out[k] = v
        return out
