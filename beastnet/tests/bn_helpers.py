"""Test helpers: a local HTTP(S) site, a throwaway CA, fake sysfs, fake runner."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAST_MODIFIED = "Wed, 21 Oct 2026 07:28:00 GMT"


# -- certificates ------------------------------------------------------------------

@dataclass
class Certs:
    ca: str  # CA certificate (PEM): what the client trusts
    good_cert: str  # for localhost / 127.0.0.1
    good_key: str
    wrong_cert: str  # for wrong.example only
    wrong_key: str


def _openssl(*args: str, cwd: str) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def make_certs(d: str) -> Certs:
    """A throwaway CA and two server certificates (strict-X.509 clean)."""
    with open(os.path.join(d, "ca.cnf"), "w") as f:
        f.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=beast-net test CA\n"
                "[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\n")
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3", "-config", "ca.cnf",
             "-extensions", "ext", cwd=d)
    out = {}
    for name, san in (("good", "DNS:localhost,IP:127.0.0.1"), ("wrong", "DNS:wrong.example")):
        with open(os.path.join(d, f"{name}.ext"), "w") as f:
            f.write(f"basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n"
                    f"subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}", cwd=d)
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                 "-CAcreateserial", "-out", f"{name}.pem", "-days", "2", "-extfile", f"{name}.ext",
                 cwd=d)
        out[name] = (os.path.join(d, f"{name}.pem"), os.path.join(d, f"{name}.key"))
    return Certs(os.path.join(d, "ca.pem"), *out["good"], *out["wrong"])


# -- a tiny web site ---------------------------------------------------------------

@dataclass
class Site:
    files: dict[str, bytes] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, dict[str, str]] = field(default_factory=dict)
    cut_once: set[str] = field(default_factory=set)  # first full GET stops halfway
    no_range: set[str] = field(default_factory=set)  # ignore Range for these
    etags: dict[str, str] = field(default_factory=dict)  # override ETag
    fake_length: dict[str, int] = field(default_factory=dict)  # headers only, no body
    status: dict[str, int] = field(default_factory=dict)
    refuse_agent: dict[str, str] = field(default_factory=dict)  # path -> User-Agent prefix answered 403
    stall: dict[str, float] = field(default_factory=dict)  # path -> seconds to hang after the headers
    requests: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def add(self, path: str, data: bytes, **headers: str) -> str:
        self.files[path] = data
        if headers:
            self.extra_headers[path] = {k.replace("_", "-"): v for k, v in headers.items()}
        return hashlib.sha256(data).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # quiet
        pass

    def do_GET(self) -> None:  # noqa: N802
        site: Site = self.server.site  # type: ignore[attr-defined]
        path = self.path
        site.requests.append((path, {k: v for k, v in self.headers.items()}))
        if path in site.status:
            self._simple(site.status[path], b"nope")
            return
        if path in site.stall:
            self.send_response(200)
            self.send_header("Content-Length", str(10 ** 6))
            self.end_headers()
            self.wfile.flush()
            time.sleep(site.stall[path])
            self.close_connection = True
            return
        prefix = site.refuse_agent.get(path)
        if prefix is not None and self.headers.get("User-Agent", "").startswith(prefix):
            self._simple(403, b"not for you")
            return
        if path in site.redirects:
            self.send_response(302)
            self.send_header("Location", site.redirects[path])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in site.fake_length:
            self.send_response(200)
            self.send_header("Content-Length", str(site.fake_length[path]))
            self.end_headers()
            self.close_connection = True
            return
        data = site.files.get(path)
        if data is None:
            self._simple(404, b"not found")
            return
        etag = site.etags.get(path, '"' + hashlib.sha256(data).hexdigest()[:16] + '"')
        start = 0
        rng = self.headers.get("Range")
        partial = False
        if rng and path not in site.no_range:
            if_range = self.headers.get("If-Range")
            if if_range is None or if_range in (etag, LAST_MODIFIED):
                m = re.match(r"bytes=(\d+)-$", rng)
                if m:
                    start = int(m.group(1))
                    if start >= len(data):
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{len(data)}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    partial = True
        body = data[start:]
        self.send_response(206 if partial else 200)
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", LAST_MODIFIED)
        self.send_header("Accept-Ranges", "bytes")
        for k, v in site.extra_headers.get(path, {}).items():
            self.send_header(k, v)
        self.end_headers()
        if path in site.cut_once and not partial:
            site.cut_once.discard(path)
            self.wfile.write(body[: len(body) // 2])
            self.wfile.flush()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.close_connection = True
            return
        self.wfile.write(body)

    def _simple(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server:
    def __init__(self, site: Site, cert: tuple[str, str] | None = None) -> None:
        self.site = site
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda request, address: None  # clients hang up early on purpose
        self.httpd.site = site  # type: ignore[attr-defined]
        self.scheme = "http"
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True)
        self.thread.start()

    def url(self, path: str, host: str = "127.0.0.1") -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# -- fake sysfs ----------------------------------------------------------------------

class FakeSys:
    """Builds a sysfs-like tree with the symlinks beast-net follows."""

    def __init__(self, root: str) -> None:
        self.root = root
        os.makedirs(os.path.join(root, "class", "net"), exist_ok=True)

    def _p(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def _write(self, path: str, text: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text + "\n")

    def device(self, bus: str, name: str, module: str | None, *, driver: str | None = None,
               pci_class: str | None = None, parent: str = "pci0000:00") -> str:
        """A device under /sys/devices, listed in /sys/bus/<bus>/devices, bound to a driver."""
        dev = self._p("devices", parent, name)
        os.makedirs(dev, exist_ok=True)
        bus_devs = self._p("bus", bus, "devices")
        os.makedirs(bus_devs, exist_ok=True)
        link = os.path.join(bus_devs, name)
        if not os.path.lexists(link):
            os.symlink(os.path.relpath(dev, bus_devs), link)
        if pci_class:
            self._write(os.path.join(dev, "class"), pci_class)
        if module:
            drv_name = driver or module
            drv = self._p("bus", bus, "drivers", drv_name)
            os.makedirs(drv, exist_ok=True)
            mod = self._p("module", module)
            os.makedirs(mod, exist_ok=True)
            if not os.path.lexists(os.path.join(drv, "module")):
                os.symlink(os.path.relpath(mod, drv), os.path.join(drv, "module"))
            os.symlink(os.path.relpath(drv, dev), os.path.join(dev, "driver"))
        self._write(os.path.join(dev, "modalias"), f"{bus}:fake{name}")
        return dev

    def netdev(self, iface: str, dev: str | None, *, wifi: bool = False, carrier: bool = False,
               operstate: str = "down", mac: str = "52:54:00:12:34:56") -> None:
        base = os.path.join(dev, "net", iface) if dev else self._p("devices", "virtual", "net", iface)
        os.makedirs(base, exist_ok=True)
        if dev:
            os.symlink(os.path.relpath(dev, base), os.path.join(base, "device"))
        if wifi:
            os.makedirs(os.path.join(base, "wireless"), exist_ok=True)
        self._write(os.path.join(base, "type"), "1")
        self._write(os.path.join(base, "carrier"), "1" if carrier else "0")
        self._write(os.path.join(base, "operstate"), operstate)
        self._write(os.path.join(base, "address"), mac)
        cls = self._p("class", "net")
        os.symlink(os.path.relpath(base, cls), os.path.join(cls, iface))

    def set_carrier(self, iface: str, on: bool) -> None:
        self._write(self._p("class", "net", iface, "carrier"), "1" if on else "0")


# -- fake programs ---------------------------------------------------------------------

class FakeRunner:
    """Stands in for system.Runner: records commands, answers like the tools."""

    def __init__(self, fake_sys: FakeSys | None = None, *, dhcp_ip: str | None = "10.0.2.15",
                 iw_output: str = "", link_errors: dict[str, str] | None = None) -> None:
        self.fake_sys = fake_sys
        self.dhcp_ip = dhcp_ip
        self.iw_output = iw_output
        self.link_errors = link_errors or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout=60, env=None, input=None):
        argv = list(argv)
        self.calls.append(argv)
        ok = subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["ip", "link", "set"]:
            iface = argv[4]
            if iface in self.link_errors:
                return subprocess.CompletedProcess(argv, 2, "", self.link_errors[iface])
            return ok
        if argv[0] == "udhcpc":
            iface = argv[argv.index("-i") + 1]
            if not self.dhcp_ip:
                return subprocess.CompletedProcess(argv, 1, "", "udhcpc: no lease, failing")
            run = (env or {}).get("BEASTNET_RUN")
            if run:
                os.makedirs(run, exist_ok=True)
                with open(os.path.join(run, f"dhcp-{iface}"), "w") as f:
                    f.write(f"ip={self.dhcp_ip} mask=24 router=10.0.2.2 dns=10.0.2.3\n")
            return ok
        if argv[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(argv, 0, self.iw_output, "")
        return ok


def have(tool: str) -> bool:
    return shutil.which(tool) is not None
