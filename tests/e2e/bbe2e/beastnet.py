"""Helpers for the beast-net e2e tests (docs/BEASTNET.md).

- `BEASTNET:` lines: the helper is Linux, so its lines are not wrapped by GRUB;
  they are matched as whole lines in the escape-stripped serial text.
- Network: QEMU user networking (slirp). The guest is 10.0.2.15 and reaches the
  host's 127.0.0.1 as 10.0.2.2, so a test HTTP server binds to 127.0.0.1 only.
- The ESP is written and read with mtools, like the FAT32 data partition.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import re
import shutil
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path

from . import env, images, trees
from .qemu import VM
from .serial import Record

ENTRY = "Download an ISO from a link"
TRUST_ENTRY = "Trust Ubuntu's Secure Boot key"
GUEST_HOST = "10.0.2.2"
GUEST_IP = "10.0.2.15"
PLAN_PATH = "/beast-booter/plan.json"
ESP_GPT_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"

# A virtio NIC on slirp. romfile= drops the PXE option ROM; the drive keeps bootindex=0.
NET_ARGS = ("-netdev", "user,id=bn0", "-device", "virtio-net-pci,netdev=bn0,romfile=")

_LINE_RE = re.compile(r"BEASTNET: ([^\n]*)")


# ---------------------------------------------------------------------------
# BEASTNET: lines
# ---------------------------------------------------------------------------

def lines(vm: VM, after: int = 0) -> list[str]:
    """Every complete BEASTNET line (text after the prefix) seen so far."""
    text = _plain(vm, after)
    return [m.group(1).rstrip() for m in _LINE_RE.finditer(text) if m.end() < len(text)]


def _plain(vm: VM, after: int) -> str:
    from .qemu import plain_text_from_clean

    return plain_text_from_clean(vm.clean()[after:])


def wait_line(vm: VM, pattern: str, *, timeout: float = 120, after: int = 0) -> str:
    """Wait for a complete `BEASTNET: <pattern...>` line; returns the text after the prefix."""
    rx = re.compile(r"BEASTNET: (" + pattern + r"[^\n]*)\n")
    m = vm.wait_for(rx, timeout=timeout, after=after)
    return m.group(1).rstrip()


def fields(line: str) -> dict[str, str]:
    return dict(t.split("=", 1) for t in line.split() if "=" in t)


def confirm_script(vm: VM, *, timeout: float = 180, after: int = 0) -> str:
    """Under Secure Boot the helper shows a script plan and waits for a
    confirmation on the console before it runs it (docs/BEASTNET.md section 5):
    wait for its `script confirm` line, then press Enter on the serial console."""
    line = wait_line(vm, "script confirm ", timeout=timeout, after=after)
    vm.send("\r")
    return line


# ---------------------------------------------------------------------------
# Drives
# ---------------------------------------------------------------------------

def esp_partition(drive: images.Drive) -> images.Partition:
    _, parts = images.partitions(drive.path)
    for p in parts:
        if p.type in ("0xef", ESP_GPT_TYPE):
            return p
    raise AssertionError(f"{drive.path}: no ESP in the partition table: {parts}")


def esp_uuid(drive: images.Drive) -> str:
    fs, vid = images.volume_id(drive.path, esp_partition(drive).offset)
    assert fs == "fat32", f"ESP is {fs}, expected FAT32 (layout v2)"
    return vid


def esp_writer(drive: images.Drive) -> images.FatWriter:
    return images.FatWriter(drive.path, esp_partition(drive).offset)


def empty_drive(base: images.Drive, dest: Path, config: str) -> images.Drive:
    """A copy of a "browse" base image (trees.browse_tree, FAT32 or exFAT) with
    its ISOs removed, so the root menu holds only the tool entries."""
    drive = base.copy(dest)
    top = "/" + trees.BROWSE_DIR_TITLE.rstrip("/")
    with drive.data_writer() as w:
        if isinstance(w, images.FatWriter):
            env.run(["mdeltree", "-i", w.spec, f"::{top}"], timeout=60)
            env.run(["mdel", "-i", w.spec, f"::/{trees.BROWSE_ROOT_ISO}"], timeout=60)
        elif isinstance(w, images.ExfatWriter):
            w.remove_tree(top)
            w.remove_tree(trees.BROWSE_ROOT_ISO)
        else:
            shutil.rmtree(w.root / top.lstrip("/"))
            (w.root / trees.BROWSE_ROOT_ISO).unlink()
    drive.write_config(config)
    return drive


def config(*, dryrun: bool = False, script: str | None = None, debug: bool = True) -> str:
    extra = ""
    if script:
        extra = f'set bb_beastnet_script="{script}"\nexport bb_beastnet_script'
    return images.user_config(debug=debug, dryrun=dryrun, extra=extra)


def write_plan(drive: images.Drive, plan: dict, path: str = PLAN_PATH) -> None:
    with drive.data_writer() as w:
        w.put(path, json.dumps(plan))


def read_grubenv(drive: images.Drive, path: str = "/grub/grubenv") -> dict[str, str]:
    """The values of a GRUB environment block on the ESP (grubenv, or the installer's device.env)."""
    raw = esp_writer(drive).read(path)
    assert len(raw) == 1024, f"{path} is {len(raw)} bytes, expected 1024"
    text = raw.decode("utf-8", "replace")
    assert text.startswith("# GRUB Environment Block\n"), text[:80]
    out = {}
    for ln in text.split("\n")[1:]:
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            out[k] = v
    return out


def write_grubenv(drive: images.Drive, values: dict[str, str], path: str = "/grub/grubenv") -> None:
    """Write ESP:/grub/grubenv as the helper does (1024 bytes, `#`-padded), or another
    environment block on the ESP. Values are written as given (no escaping)."""
    body = "# GRUB Environment Block\n" + "".join(f"{k}={v}\n" for k, v in values.items())
    raw = body.encode()
    assert len(raw) <= 1024
    esp_writer(drive).put(path, raw + b"#" * (1024 - len(raw)))


def data_file(drive: images.Drive, path: str) -> bytes | None:
    """Contents of a file on the data partition, or None if it does not exist."""
    with drive.data_writer() as w:
        return w.read(path) if w.exists(path) else None


def install_fake_pack(drive: images.Drive, pack_id: str, files: dict[str, bytes]) -> bytes:
    """Write <pack_id>.cpio (built by the installer's own cpio module) and an
    installed.json entry to the ESP, as `firmware install` would. Returns the cpio."""
    import sys

    sys.path.insert(0, str(env.INSTALLER_DIR))
    try:
        from beastbooter import cpio
    finally:
        sys.path.pop(0)
    blob = cpio.build_pack(files)
    w = esp_writer(drive)
    w.mkdir("/beast-net/firmware")
    w.put(f"/beast-net/firmware/{pack_id}.cpio", blob)
    installed = {"v": 1, "packs": [{
        "id": pack_id, "catalog_tag": "e2e-test", "cpio_sha256": hashlib.sha256(blob).hexdigest(),
        "files": [{"path": p, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)} for p, b in sorted(files.items())],
    }]}
    w.put("/beast-net/firmware/installed.json", json.dumps(installed, indent=1))
    return blob



def install_extra_initrd(drive: images.Drive, name: str, files: dict[str, bytes]) -> bytes:
    """Write an initrd archive (uncompressed newc cpio) with `files` ({path in the initramfs:
    contents}) as ESP:/beast-net/firmware/<name>.cpio. The menu passes every .cpio there to the
    helper as one more initrd after its own (grub/beast/lib.cfg bb_beastnet), so the kernel
    unpacks `files` over the helper's initramfs. Returns the archive."""
    import sys

    sys.path.insert(0, str(env.INSTALLER_DIR))
    try:
        from beastbooter import cpio
    finally:
        sys.path.pop(0)
    names: dict[str, bytes | None] = {}
    for path, data in files.items():
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            names["/".join(parts[:i])] = None  # every parent directory
        names["/".join(parts)] = data
    out = []
    for ino, (path, data) in enumerate(sorted(names.items()), start=1):
        if data is None:
            out.append(cpio.header(path, ino=ino, mode=cpio.DIR_MODE, nlink=2, filesize=0))
        else:
            out.append(cpio.header(path, ino=ino, mode=cpio.FILE_MODE, nlink=1, filesize=len(data)))
            out.append(data + b"\0" * (-len(data) % 4))
    blob = b"".join(out) + cpio.trailer()
    w = esp_writer(drive)
    w.mkdir("/beast-net/firmware")
    w.put(f"/beast-net/firmware/{name}.cpio", blob)
    return blob

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def select_entry(vm: VM, *, timeout: float = 120) -> Record:
    """Root menu with no ISOs: "System: ..." then ENTRY. Select it; returns the
    `BEAST: boot beast-net` record."""
    vm.wait_record("dir", r"^dir /$", timeout=timeout)
    menu = vm.wait_menu(timeout=timeout)
    # folders on the data partition come first (e.g. disk-tools/, where Disk tools keep their
    # ddrescue mapfiles after a stopped copy); the tool entries follow
    folders = 0
    while folders < len(menu.entries) and menu.entries[folders].endswith("/"):
        folders += 1
    rest = menu.entries[folders:]
    assert len(rest) >= 2 and rest[0].startswith("System:") and rest[1] == ENTRY, \
        f"root menu (no ISOs) must start with System: ..., {ENTRY!r}:\n{menu}\n--- screen ---\n{vm.screen.text()}"
    mark = vm.mark()
    vm.keys(*(["down"] * (folders + 1)), "enter")
    return vm.wait_record("boot", r"^boot beast-net recipe=beast-net$", timeout=60, after=mark)


# ---------------------------------------------------------------------------
# Host-side HTTP server
# ---------------------------------------------------------------------------

class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet; keep a record for assertions
        self.server.requests.append(self.requestline)


@contextmanager
def http_server(root: Path, *, tls_dir: Path | None = None):
    """Serve `root` on 127.0.0.1:<free port> (the guest uses 10.0.2.2:<port>).
    With `tls_dir`: HTTPS with a fresh self-signed certificate for 10.0.2.2,
    which the helper must not trust."""
    handler = functools.partial(_Handler, directory=str(root))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.requests = []
    if tls_dir is not None:
        cert, key = self_signed_cert(tls_dir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def self_signed_cert(d: Path) -> tuple[Path, Path]:
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "cert.pem", d / "key.pem"
    env.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={GUEST_HOST}",
             "-addext", f"subjectAltName=IP:{GUEST_HOST}"], timeout=60)
    return cert, key


def guest_url(srv, name: str) -> str:
    scheme = "https" if isinstance(srv.socket, ssl.SSLSocket) else "http"
    return f"{scheme}://{GUEST_HOST}:{srv.server_address[1]}/{name}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
