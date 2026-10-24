#!/usr/bin/env python3
"""Boot beast-net in QEMU against a throwaway stick image and check the result.

Not collected by pytest (it needs QEMU and the beast-net kernel/initrd built by
build/beastnet). Usage, from the repository root:

    source scripts/dev-env.sh
    python3 beastnet/tests/qemu_smoke.py [--scenario NAME ...] [--work DIR]

What it does, per scenario:
  1. initrd = out/beastnet/beast-net/initrd.img + an uncompressed cpio overlay
     holding the current beastnet/rootfs and beastnet/python/beastnet (so the
     app under test is this checkout, whatever the built initrd contains);
  2. a 160 MiB MBR disk image: partition 1 exFAT "BEASTBOOTER" (serial
     1A2B-3C4D) with /plan.json, partition 2 FAT "BEAST-EFI" (ABCD-1234) with
     grub/grubenv (made by grub-editenv) and beast-net/catalog.json;
  3. serves a fake ISO over HTTP/HTTPS on the host (QEMU user networking
     reaches it as 10.0.2.2), boots the kernel with beastnet.script=/plan.json
     beastnet.debug=1 and the serial console, waits for QEMU to exit (the
     helper reboots; -no-reboot turns that into an exit);
  4. prints the BEASTNET: lines and checks them, the downloaded file on the
     exFAT partition and bb_oneshot in the grubenv (read back with grub-editenv).

Scenarios: plain-http-sha (download over http:// with a SHA-256, verify, hand
off), tls-untrusted (https:// with a certificate from a throwaway CA: must be
refused by the real CA bundle), internet (https:// from a public server;
needs Internet access).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BN = os.path.dirname(HERE)
ROOT = os.path.dirname(BN)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "installer"))

from bn_helpers import Server, Site, make_certs  # noqa: E402

OUT = os.path.join(ROOT, "out", "beastnet", "beast-net")
MIB = 1024 * 1024
DATA_START, DATA_SIZE = 1 * MIB, 128 * MIB
ESP_START, ESP_SIZE = DATA_START + DATA_SIZE, 31 * MIB
DATA_UUID, ESP_UUID = "1A2B-3C4D", "ABCD-1234"


def run(*argv, **kw):
    return subprocess.run(list(argv), check=True, **kw)


def overlay_initrd(work: str) -> str:
    """Built initrd + a newc cpio of this checkout's app (later entries win)."""
    stage = os.path.join(work, "overlay")
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(os.path.join(BN, "rootfs"), stage, symlinks=True)
    pkg = os.path.join(stage, "usr/lib/python3/dist-packages/beastnet")
    shutil.copytree(os.path.join(BN, "python", "beastnet"), pkg,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    names = []
    for dirpath, dirs, files in os.walk(stage):
        dirs.sort()
        rel = os.path.relpath(dirpath, stage)
        if rel != ".":
            names.append(rel)
        names += [os.path.normpath(os.path.join(rel, f)) for f in sorted(files)]
    cpio = run("cpio", "-o", "-H", "newc", "-R", "0:0", "--quiet", cwd=stage,
               input="\n".join(names).encode() + b"\n", capture_output=True).stdout
    out = os.path.join(work, "initrd-test.img")
    with open(os.path.join(OUT, "initrd.img"), "rb") as f:
        base = f.read()
    with open(out, "wb") as f:
        f.write(base + b"\0" * (-len(base) % 4) + cpio)
    return out


def make_disk(work: str, plan: dict) -> str:
    from beastbooter.blockio import ImageTarget
    from beastbooter.exfatfs import ExfatVolume, format_exfat
    disk = os.path.join(work, "stick.img")
    t = ImageTarget.create(disk, ESP_START + ESP_SIZE + MIB)
    format_exfat(t, DATA_START, DATA_SIZE, label="BEASTBOOTER",
                 volume_serial=int(DATA_UUID.replace("-", ""), 16))
    vol = ExfatVolume(t, DATA_START)
    vol.write_file("/plan.json", json.dumps(plan, indent=1).encode())
    t.close()
    layout = (f"label: dos\nstart={DATA_START // 512}, size={DATA_SIZE // 512}, type=7, bootable\n"
              f"start={ESP_START // 512}, size={ESP_SIZE // 512}, type=ef\n")
    run("sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", disk, input=layout.encode())
    esp = os.path.join(work, "esp.img")
    if os.path.exists(esp):
        os.unlink(esp)
    run("mkfs.fat", "-C", "-i", ESP_UUID.replace("-", ""), "-n", "BEAST-EFI", esp,
        str(ESP_SIZE // 1024), capture_output=True)
    env = os.path.join(work, "grubenv")
    if os.path.exists(env):
        os.unlink(env)
    run("grub-editenv", env, "create")
    run("grub-editenv", env, "set", "bb_theme=default")
    run("mmd", "-i", esp, "::/grub", "::/beast-net")
    run("mcopy", "-i", esp, env, "::/grub/grubenv")
    run("mcopy", "-i", esp, os.path.join(OUT, "catalog.json"), "::/beast-net/catalog.json")
    run("dd", f"if={esp}", f"of={disk}", "bs=1M", f"seek={ESP_START // MIB}", "conv=notrunc",
        "status=none")
    return disk


def read_back(work: str, disk: str, iso_path: str | None) -> tuple[list[str], bytes | None]:
    from beastbooter.blockio import ImageTarget
    from beastbooter.exfatfs import ExfatVolume
    esp = os.path.join(work, "esp-after.img")
    run("dd", f"if={disk}", f"of={esp}", "bs=1M", f"skip={ESP_START // MIB}",
        f"count={ESP_SIZE // MIB}", "status=none")
    env = os.path.join(work, "grubenv-after")
    if os.path.exists(env):
        os.unlink(env)
    run("mcopy", "-i", esp, "::/grub/grubenv", env)
    listing = run("grub-editenv", env, "list", capture_output=True, text=True).stdout.splitlines()
    data = None
    if iso_path:
        t = ImageTarget(disk, writable=False)
        try:
            vol = ExfatVolume(t, DATA_START)
            if vol.exists(iso_path):
                data = vol.read_file(iso_path)
        finally:
            t.close()
    return listing, data


def boot(work: str, initrd: str, disk: str, timeout: float) -> list[str]:
    log = os.path.join(work, "serial.log")
    cmdline = (f"beastnet.data=UUID={DATA_UUID} beastnet.esp=UUID={ESP_UUID} beastnet.sb=0 "
               "beastnet.debug=1 beastnet.script=/plan.json console=tty0 console=ttyS0,115200 quiet")
    qemu = [shutil.which("qemu-system-x86_64") or "qemu-system-x86_64", "-m", "1536", "-smp", "2",
            "-kernel", os.path.join(OUT, "vmlinuz"), "-initrd", initrd, "-append", cmdline,
            "-drive", f"file={disk},format=raw,if=virtio",
            "-netdev", "user,id=n0", "-device", "e1000,netdev=n0",
            "-display", "none", "-monitor", "none", "-serial", f"file:{log}", "-no-reboot"]
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        qemu[1:1] = ["-enable-kvm", "-cpu", "host"]
    t0 = time.monotonic()
    p = subprocess.Popen(qemu)
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        print(f"  (QEMU still running after {timeout:.0f} s: killed)")
    print(f"  QEMU ran {time.monotonic() - t0:.1f} s")
    with open(log, encoding="utf-8", errors="replace") as f:
        text = f.read()
    return [line.strip() for line in text.splitlines() if "BEASTNET: " in line]


def scenario(name: str, work: str, initrd: str, certs, timeout: float) -> bool:
    print(f"== {name}")
    iso = b"\0" * 0x8001 + b"CD001" + os.urandom(6 * MIB)
    sha = hashlib.sha256(iso).hexdigest()
    site = Site()
    site.add("/isos/beast-test.iso", iso)
    srv = Server(site) if name != "tls-untrusted" else Server(site, (certs.good_cert, certs.good_key))
    try:
        if name == "plain-http-sha":
            url = f"http://10.0.2.2:{srv.port}/isos/beast-test.iso"
            plan = {"network": {"type": "ethernet"}, "url": url, "sha256": sha, "sha256_url": None,
                    "dest": "/downloads/beast-test.iso", "then": "reboot", "on_error": "poweroff"}
        elif name == "tls-untrusted":
            url = f"https://10.0.2.2:{srv.port}/isos/beast-test.iso"
            plan = {"network": {"type": "ethernet"}, "url": url, "then": "reboot",
                    "on_error": "poweroff"}
        else:  # internet
            url = "https://cdimage.ubuntu.com/ubuntu/releases/24.04/release/SHA256SUMS"
            plan = {"network": {"type": "ethernet"}, "url": url, "dest": "/downloads/SHA256SUMS.iso",
                    "then": "reboot", "on_error": "poweroff"}
        disk = make_disk(work, plan)
        lines = boot(work, initrd, disk, timeout)
    finally:
        srv.close()
    for line in lines:
        print("  " + line)
    listing, data = read_back(work, disk, plan.get("dest"))
    print("  grubenv:", listing)
    ok = True

    def check(cond: bool, what: str) -> None:
        nonlocal ok
        print(f"  [{'ok' if cond else 'FAIL'}] {what}")
        ok = ok and cond
    check(any(x.startswith("BEASTNET: ready kernel=") for x in lines), "ready line")
    check(any(x.startswith("BEASTNET: nic ") and "type=ethernet driver=e1000" in x for x in lines),
          "e1000 NIC reported")
    check(any(x.startswith("BEASTNET: net up iface=") and "ip=10.0.2." in x for x in lines),
          "DHCP address from QEMU")
    if name == "plain-http-sha":
        check(f"BEASTNET: verify ok sha256={sha}" in lines, "SHA-256 verified")
        check("BEASTNET: handoff oneshot=/downloads/beast-test.iso" in lines, "hand-off line")
        check("bb_oneshot=/downloads/beast-test.iso" in listing and "bb_theme=default" in listing,
              "grubenv has bb_oneshot (and kept bb_theme)")
        check(data == iso, "ISO on the exFAT partition is byte-identical")
    elif name == "tls-untrusted":
        check(any(x.startswith("BEASTNET: error tls ") for x in lines), "untrusted certificate refused")
        check(not any("bb_oneshot" in x for x in listing), "no hand-off")
    else:
        check(any(x.startswith("BEASTNET: download done ") for x in lines), "downloaded over real TLS")
        check(any(x.startswith("BEASTNET: handoff ") for x in lines), "hand-off line")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", action="append",
                    choices=["plain-http-sha", "tls-untrusted", "internet"])
    ap.add_argument("--work", help="keep the images and logs here")
    ap.add_argument("--timeout", type=float, default=240)
    a = ap.parse_args()
    for need in ("vmlinuz", "initrd.img", "catalog.json"):
        if not os.path.exists(os.path.join(OUT, need)):
            print(f"{OUT}/{need} missing: build it with build/beastnet first")
            return 2
    work = a.work or tempfile.mkdtemp(prefix="beastnet-qemu-")
    os.makedirs(work, exist_ok=True)
    initrd = overlay_initrd(work)
    certs = make_certs(tempfile.mkdtemp(dir=work, prefix="certs-"))
    results = {s: scenario(s, work, initrd, certs, a.timeout)
               for s in (a.scenario or ["plain-http-sha", "tls-untrusted"])}
    print("== results:", ", ".join(f"{k}: {'ok' if v else 'FAIL'}" for k, v in results.items()))
    print(f"   work dir: {work}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
