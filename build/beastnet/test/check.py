"""Test-only: run inside beast-net by test-init. HOST PORT SHA256 [INTERNET_URL]."""
import hashlib
import json
import socket
import ssl
import struct
import subprocess
import select
import fcntl
import sys
import urllib.error
import urllib.request
import curses


def t(msg):
    print("BNTEST: " + msg, flush=True)


host, port, want = sys.argv[1], int(sys.argv[2]), sys.argv[3]
inet = sys.argv[4] if len(sys.argv) > 4 else ""
url = f"https://{host}:{port}/hello"
paths = ssl.get_default_verify_paths()
t(f"python {sys.version.split()[0]} {ssl.OPENSSL_VERSION} hashes={len(hashlib.algorithms_available)}")
t(f"default verify paths: {paths.cafile} (openssl {paths.openssl_cafile})")
curses.setupterm("linux", 1)
t(f"curses ok: linux clear={curses.tigetstr('clear')!r} json={json.dumps({'a': 1})} struct={struct.calcsize('<Q')}")

# 1. the shipped CA bundle (default context) must reject the throwaway CA
try:
    urllib.request.urlopen(url, timeout=15).read()
    t("tls untrusted ACCEPTED (BAD)")
except urllib.error.URLError as e:
    r = e.reason
    if isinstance(r, ssl.SSLCertVerificationError):
        t(f"tls untrusted rejected ok: {r.verify_message}")
    else:
        t(f"tls untrusted FAIL other error: {r!r}")

# 2. a test-only copy of the bundle plus the throwaway CA must accept it
bundle = open("/etc/ssl/certs/ca-certificates.crt").read() + open("/test/ca.pem").read()
with open("/tmp/test-bundle.pem", "w") as f:
    f.write(bundle)
ctx = ssl.create_default_context(cafile="/tmp/test-bundle.pem")
try:
    body = urllib.request.urlopen(url, context=ctx, timeout=15).read()
    got = hashlib.sha256(body).hexdigest()
    t(f"tls trusted {'ok' if got == want else 'FAIL'}: {len(body)} bytes sha256={got}")
except Exception as e:  # noqa: BLE001
    t(f"tls trusted FAIL: {e!r}")

# 3. wrong host name with the trusted CA must still fail (hostname check)
try:
    with socket.create_connection((host, port), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname="not-the-server.example") as ss:
            ss.recv(1)
    t("tls hostname ACCEPTED (BAD)")
except ssl.SSLCertVerificationError as e:
    t(f"tls hostname mismatch rejected ok: {e.verify_message}")

# 4. optional: a real public HTTPS server through slirp, default context only
if inet:
    try:
        req = urllib.request.Request(inet, headers={"User-Agent": "beast-net-test/1"})
        body = urllib.request.urlopen(req, timeout=30).read()
        t(f"tls internet ok: {inet} {len(body)} bytes sha256={hashlib.sha256(body).hexdigest()[:16]}")
    except urllib.error.HTTPError as e:
        t(f"tls internet ok (certificate verified; HTTP {e.code}): {inet}")
    except Exception as e:  # noqa: BLE001
        t(f"tls internet unavailable: {e!r}")

out = subprocess.run(["busybox", "true"], capture_output=True)
r, _, _ = select.select([], [], [], 0)
fcntl.fcntl(0, fcntl.F_GETFD)
t(f"subprocess/select/fcntl ok rc={out.returncode}")
