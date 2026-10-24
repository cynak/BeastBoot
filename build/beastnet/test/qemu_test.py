#!/usr/bin/env python3
"""Boot a built beast-net in QEMU and check the environment.

    source scripts/dev-env.sh
    python3 -I build/beastnet/test/qemu_test.py OUT_DIR [--inet URL] [--app] [--keep]

OUT_DIR is what build/beastnet/build.sh wrote (OUT_DIR/beast-net/vmlinuz,
initrd.img). Nothing in OUT_DIR is modified: the test boots the kernel directly
(-kernel/-initrd, KVM, serial console) with a COPY of initrd.img followed by
  - a test overlay cpio: test-init as /init, check.py, a throwaway CA;
  - a firmware-pack-format cpio (docs/BEASTNET.md section 6) with one file;
and three NICs (e1000, e1000e, virtio-net, each on its own QEMU user network
10.0.2.0/24, so the host is 10.0.2.2 whichever one routes), two USB
disks (exFAT on usb-storage, FAT32 on UAS) and an HTTPS server on the host
whose certificate is issued by the throwaway CA (10.0.2.2 from the guest).
The kernel runs with module.sig_enforce=1, so every module that loads is a
correctly signed one.

--app additionally boots the real /init from beastnet/rootfs with
beastnet.debug=1 (no data partition attached) and shows its BEASTNET: lines.
--inet URL also fetches a public HTTPS URL with the default (shipped) CA bundle.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def newc(entries: list[tuple[str, int, bytes | None]], mtime: int = 0) -> bytes:
    """entries: (path, mode incl. type bits, data or None for dirs); sorted, uid/gid 0."""
    out = bytearray()
    for ino, (name, mode, data) in enumerate(sorted(entries, key=lambda e: e[0].encode()), 1):
        nb = name.encode() + b"\0"
        data = data or b""
        hdr = b"070701" + b"".join(b"%08X" % v for v in
                                   [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, mtime, len(data),
                                    0, 0, 0, 0, len(nb), 0])
        out += hdr + nb + b"\0" * (-(110 + len(nb)) % 4) + data + b"\0" * (-len(data) % 4)
    nb = b"TRAILER!!!\0"
    out += b"070701" + b"".join(b"%08X" % v for v in [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nb), 0])
    out += nb + b"\0" * (-(110 + len(nb)) % 4)
    out += b"\0" * (-len(out) % 512)
    return bytes(out)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def make_certs(d: str) -> None:
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.pem", "-days", "2",
         "-subj", "/CN=beast-net throwaway test CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"], capture_output=True)
    run(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", f"{d}/server.key", "-out", f"{d}/server.csr", "-subj", "/CN=10.0.2.2"], capture_output=True)
    with open(f"{d}/ext.cnf", "w") as f:
        f.write("subjectAltName=IP:10.0.2.2\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
    run(["openssl", "x509", "-req", "-in", f"{d}/server.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
         "-CAcreateserial", "-out", f"{d}/server.pem", "-days", "2", "-extfile", f"{d}/ext.cnf"],
        capture_output=True)


def start_server(d: str, body: bytes) -> tuple[int, list[str]]:
    seen: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{d}/server.pem", f"{d}/server.key")

    class TLSServer(threading.Thread):
        def run(self):
            while True:
                try:
                    conn, addr = srv.socket.accept()
                except OSError:
                    return
                try:
                    s = ctx.wrap_socket(conn, server_side=True)
                    srv.process_request(s, addr)
                except (ssl.SSLError, OSError) as e:
                    seen.append(f"handshake-failed:{type(e).__name__}")
                    conn.close()

    TLSServer(daemon=True).start()
    return srv.server_address[1], seen


def qemu_base(vmlinuz: str, initrd: str, append: str) -> list[str]:
    q = shutil.which("qemu-system-x86_64") or sys.exit("qemu-system-x86_64 not found (source scripts/dev-env.sh)")
    cmd = [q, "-machine", "q35", "-m", "1024", "-smp", "2", "-nographic", "-no-reboot",
           "-kernel", vmlinuz, "-initrd", initrd, "-append", append, "-nodefaults", "-serial", "stdio"]
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        cmd[1:1] = ["-accel", "kvm", "-cpu", "host"]
    return cmd


def boot(cmd: list[str], log: str, timeout: int, stop: str | None = None) -> str:
    out = []
    with open(log, "w") as lf:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        t0 = time.time()

        def killer():
            while p.poll() is None:
                if time.time() - t0 > timeout:
                    p.kill()
                    return
                time.sleep(0.5)
        threading.Thread(target=killer, daemon=True).start()
        for raw in iter(p.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            out.append(line)
            lf.write(line + "\n")
            lf.flush()
            if stop and stop in line:
                time.sleep(1)
                p.kill()
                break
        p.wait()
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out_dir")
    ap.add_argument("--inet", default="")
    ap.add_argument("--app", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args()
    bn = os.path.join(a.out_dir, "beast-net")
    vmlinuz, initrd = os.path.join(bn, "vmlinuz"), os.path.join(bn, "initrd.img")
    work = tempfile.mkdtemp(prefix="bn-qemu.")
    try:
        make_certs(work)
        body = os.urandom(200_000)
        port, seen = start_server(work, body)
        server_line = f"10.0.2.2 {port} {hashlib.sha256(body).hexdigest()} {a.inet}".strip()

        def rd(n):
            return open(os.path.join(HERE, n), "rb").read()
        overlay = newc([
            ("init", stat.S_IFREG | 0o755, rd("test-init")),
            ("test", stat.S_IFDIR | 0o755, None),
            ("test/check.py", stat.S_IFREG | 0o644, rd("check.py")),
            ("test/udhcpc.script", stat.S_IFREG | 0o755, rd("udhcpc.script")),
            ("test/ca.pem", stat.S_IFREG | 0o644, open(f"{work}/ca.pem", "rb").read()),
            ("test/server", stat.S_IFREG | 0o644, server_line.encode() + b"\n"),
        ], mtime=int(time.time()))
        pack = newc([("lib", stat.S_IFDIR | 0o755, None), ("lib/firmware", stat.S_IFDIR | 0o755, None),
                     ("lib/firmware/bntest", stat.S_IFDIR | 0o755, None),
                     ("lib/firmware/bntest/hello.bin", stat.S_IFREG | 0o644, b"hello from a firmware pack\n")])
        tinitrd = os.path.join(work, "initrd-test.img")
        with open(tinitrd, "wb") as f:
            f.write(open(initrd, "rb").read() + overlay + pack)

        exfat, vfat = os.path.join(work, "exfat.img"), os.path.join(work, "vfat.img")
        for img in (exfat, vfat):
            with open(img, "wb") as f:
                f.truncate(96 << 20)
        run(["mkfs.exfat", "-n", "BNEXFAT", exfat], capture_output=True)
        run(["mkfs.vfat", "-F", "32", "-n", "BNVFAT", vfat], capture_output=True)
        with open(os.path.join(work, "marker.txt"), "w") as f:
            f.write("vfat-marker\n")
        run(["mcopy", "-i", vfat, os.path.join(work, "marker.txt"), "::marker.txt"])

        cmd = qemu_base(vmlinuz, tinitrd, "console=ttyS0,115200 module.sig_enforce=1 panic=-1 loglevel=4")
        cmd += ["-netdev", "user,id=n1", "-device", "e1000,netdev=n1",
                "-netdev", "user,id=n2", "-device", "e1000e,netdev=n2",
                "-netdev", "user,id=n3", "-device", "virtio-net-pci,netdev=n3",
                "-device", "qemu-xhci,id=xhci",
                "-drive", f"if=none,id=d1,file={exfat},format=raw",
                "-device", "usb-storage,bus=xhci.0,drive=d1",
                "-drive", f"if=none,id=d2,file={vfat},format=raw",
                "-device", "usb-uas,id=uas,bus=xhci.0", "-device", "scsi-hd,bus=uas.0,drive=d2"]
        log = os.path.join(work, "serial.log")
        t0 = time.time()
        text = boot(cmd, log, a.timeout)
        dt = time.time() - t0
        lines = ["BNTEST: " + ln.split("BNTEST: ", 1)[1] for ln in text.splitlines() if "BNTEST: " in ln]
        print("\n".join(lines))
        print(f"--- boot to poweroff: {dt:.1f}s; host server saw: {seen}")
        vfat_out = subprocess.run(["mtype", "-i", vfat, "::out.txt"], capture_output=True, text=True).stdout.strip()
        fsck = subprocess.run(["fsck.exfat", "-n", exfat], capture_output=True, text=True)
        print(f"--- host: vfat out.txt={vfat_out!r}; fsck.exfat rc={fsck.returncode}")

        j = "\n".join(lines)
        checks = {
            "init runs as PID 1": "init pid=1 " in j,
            "e1000 autoloaded": bool(re.search(r"nic eth\d driver=e1000 ", j)),
            "e1000e autoloaded": bool(re.search(r"nic eth\d driver=e1000e ", j)),
            "virtio_net present": bool(re.search(r"nic eth\d driver=virtio_net", j)),
            "dhcp on all 3 NICs": len(re.findall(r"dhcp ok iface=", j)) == 3,
            "python + curses": "curses ok" in j,
            "TLS: shipped bundle rejects test CA": "tls untrusted rejected ok" in j,
            "TLS: test-only bundle copy accepts": "tls trusted ok" in j,
            "TLS: hostname mismatch rejected": "tls hostname mismatch rejected ok" in j,
            "mac80211_hwsim wlan0/wlan1": bool(re.search(r"hwsim loaded: .*wlan=wlan0 wlan1", j)),
            "WPA2 association (wpa_supplicant)": "wifi station: wpa_state=COMPLETED" in j,
            "exfat mount+write (usb-storage)": bool(re.search(r"fs /dev/sd\w type=exfat .*write=ok", j)),
            "vfat mount+write (uas)": bool(re.search(r"fs /dev/sd\w type=vfat marker=vfat-marker write=ok", j)),
            "host sees guest's vfat write": vfat_out == "written by beast-net test",
            "exfat clean after guest write": fsck.returncode == 0,
            "firmware pack cpio layering": "firmware pack ok" in j,
            "module.sig_enforce=1, kernel not tainted": "sig_enforce=Y" in j and "tainted=0" in j,
            "completed": "BNTEST: done" in j,
        }
        if a.inet:
            checks["TLS: public site with shipped bundle"] = "tls internet ok" in j
        failed = [k for k, v in checks.items() if not v]
        for k, v in checks.items():
            print(f"{'PASS' if v else 'FAIL'}  {k}")

        if a.app:
            cmd = qemu_base(vmlinuz, initrd, "console=ttyS0,115200 beastnet.debug=1 module.sig_enforce=1")
            cmd += ["-netdev", "user,id=n1", "-device", "e1000,netdev=n1"]
            text = boot(cmd, os.path.join(work, "app.log"), 90, stop="BEASTNET: error")
            app_lines = [ln for ln in text.splitlines() if "BEASTNET:" in ln or "beast-net" in ln]
            print("--- real /init (beastnet/rootfs) with beastnet.debug=1, no data partition:")
            print("\n".join(app_lines[:20]))
        if a.keep:
            print(f"--- kept {work}")
        return 1 if failed else 0
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
