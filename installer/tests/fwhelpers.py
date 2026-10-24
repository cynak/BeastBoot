"""Helpers for the firmware-pack tests: a fake catalog, a dist with beast-net,
fetched pack folders built without a network, and a local HTTPS server (a
self-signed certificate that the client trusts through SSL_CERT_FILE, so
certificate verification stays on)."""

from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import fakedist
from beastbooter import firmware
from beastbooter.cpio import build_pack

TAG = "20990101"
KERNEL = "9.9.9-1-generic"

# Firmware files the fake upstream serves: {upstream path: contents}.
UPSTREAM = {
    "acme/fw-a.bin": b"firmware A " * 300,
    "acme/sub/fw-b.bin": b"\x00\x01\x02 firmware B",
    "real/c-1.bin": b"the real C, installed under a WHENCE Link: name\n",
    "LICENSES/LICENCE.acme": b"Redistributable.\n",
    "odd/name with space.txt": b"spaces are fine\n",
    "z.bin": b"",
}
# Packs: {id: [(installed path, upstream path or None)]}
PACKS = {
    "acme-wifi": [("acme/fw-a.bin", None), ("acme/sub/fw-b.bin", None), ("acme/c.bin", "real/c-1.bin"),
                  ("LICENSES/LICENCE.acme", None), ("odd/name with space.txt", None)],
    "tiny-eth": [("z.bin", None), ("LICENSES/LICENCE.acme", None)],
}


def contents(pack_id: str) -> dict[str, bytes]:
    return {path: UPSTREAM[src or path] for path, src in PACKS[pack_id]}


def make_catalog(url_template: str, tag: str = TAG, kernel: str = KERNEL) -> dict:
    packs = []
    for pid, files in PACKS.items():
        entries = []
        for path, src in files:
            data = UPSTREAM[src or path]
            e = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "license": "test"}
            if src:
                e["source_path"] = src
            entries.append(e)
        packs.append({"id": pid, "title": pid.title(), "description": "test pack", "modules": ["acme"],
                      "licenses": ["test"], "size": sum(e["size"] for e in entries), "files": entries})
    return {"v": 1, "kernel": kernel,
            "source": {"name": "linux-firmware", "repo": "https://example.invalid/linux-firmware.git",
                       "tag": tag, "url_template": url_template},
            "packs": packs}


def write_catalog(path: Path, catalog: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog), encoding="utf-8")
    return path


def make_bn_dist(dist: Path, catalog: dict | None, version: str = "0.1.0") -> Path:
    """A fake dist/ with beast-net files (and the catalog, unless None)."""
    fakedist.make_fake_dist(dist, version)
    bn = dist / "esp/beast-net"
    bn.mkdir(parents=True, exist_ok=True)
    (bn / "vmlinuz").write_bytes(b"MZ fake kernel" * 100)
    (bn / "initrd.img").write_bytes(b"fake initrd")
    (bn / "VERSION").write_text(f"beast-net {version} kernel {KERNEL}\n")
    if catalog is not None:
        write_catalog(bn / "catalog.json", catalog)
    fakedist.write_manifest(dist, version)
    return dist


def make_fetched(out: Path, catalog: dict, pack_id: str, files: dict[str, bytes] | None = None,
                 cpio: bytes | None = None) -> Path:
    """What `firmware fetch` writes for a pack, built without a network."""
    out.mkdir(parents=True, exist_ok=True)
    cat = firmware.parse_catalog(json.dumps(catalog).encode(), "test")
    data = cpio if cpio is not None else build_pack(files if files is not None else contents(pack_id))
    (out / f"{pack_id}.cpio").write_bytes(data)
    entry = firmware.pack_entry(cat.packs[pack_id], cat, hashlib.sha256(data).hexdigest())
    (out / f"{pack_id}.json").write_text(json.dumps(entry), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# HTTPS server
# ---------------------------------------------------------------------------


def make_cert(d: Path) -> tuple[Path, Path]:
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return cert, key


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


class FwServer:
    """Serves UPSTREAM at /plain/<path>?h=<tag> over HTTPS (or HTTP with tls=False).

    files      what is served (tests may change it)
    requests   the paths asked for, in order
    fail       {path: [status, ...]}: answer with these statuses first
    redirect   {path: location}
    on_request callback(path) before answering
    """

    def __init__(self, cert: Path | None, key: Path | None, *, tls: bool = True):
        self.files = dict(UPSTREAM)
        self.requests: list[str] = []
        self.fail: dict[str, list[int]] = {}
        self.redirect: dict[str, str] = {}
        self.on_request = None
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parts = urllib.parse.urlsplit(self.path)
                path = urllib.parse.unquote(parts.path.removeprefix("/plain/"))
                server.requests.append(path)
                if server.on_request:
                    server.on_request(path)
                if server.fail.get(path):
                    self.send_error(server.fail[path].pop(0))
                    return
                if path in server.redirect:
                    self.send_response(302)
                    self.send_header("Location", server.redirect[path])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                data = server.files.get(path)
                if data is None or urllib.parse.parse_qs(parts.query).get("h") != [TAG]:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if tls else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def template(self) -> str:
        return f"{self.scheme}://localhost:{self.port}/plain/{{path}}?h={{tag}}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
