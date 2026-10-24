#!/usr/bin/env python3
"""Scripted gdb demonstration: break in a GRUB *module* function, with symbols.

  devtools/gdb/demo.py                     BIOS: qemu-system-i386 (TCG), paused at reset
  devtools/gdb/demo.py --platform efi      UEFI: attach to the running menu, then
                                           a second boot paused at reset
  devtools/gdb/demo.py --bbdev-vm          BIOS through `bb-dev vm --mode bios --gdb --wait-gdb`
                                           (qemu-system-x86_64 + KVM: frame #0 only, see README)
  devtools/gdb/demo.py --kvm               BIOS with qemu-system-i386 + KVM (hardware breakpoints)

It boots a throwaway image (out/dev/gdb-demo.img, built from dist/ by the
installer if it is missing or not current: an older installer layout or another
dist/ build id, see bbdev/freshness.py; --image to use
another one, always with snapshot=on so the image is never changed), runs
`bb-dev gdb --batch` against it, prints the transcript and checks it.
Exit 0 = PASS.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for _p in ("installer", "devtools"):   # bbdev.freshness needs beastbooter.layout
    sys.path.insert(0, str(REPO / _p))
from bbdev import paths
from bbdev.commands.setup import image_stale

BB_DEV = REPO / "bin" / "bb-dev"
DEMO_IMAGE = paths.DEV_OUT / "gdb-demo.img"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def kvm_ok() -> bool:
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


def ensure_image(image: Path, env: dict) -> Path:
    """--image as given; the demo image (re)built when missing, of an older layout or
    from another dist/ build (image_stale: layout version and build id)."""
    if image != DEMO_IMAGE:
        if not image.exists():
            raise SystemExit(f"demo: {image} does not exist")
        return image
    if not (paths.DIST / "manifest.json").exists():
        if image.exists():
            return image
        raise SystemExit("demo: dist/ is not built (make build)")
    why = image_stale(image) if image.exists() else "missing"
    if not why:
        return image
    image.parent.mkdir(parents=True, exist_ok=True)
    image.unlink(missing_ok=True)   # a running demo VM (snapshot=on) keeps the old inode
    print(f"demo: building {image.relative_to(REPO)} from dist/ (FAT32, 1G; {why})", flush=True)
    subprocess.run([sys.executable, "-m", "beastbooter", "install", "--image", str(image), "--size", "1G",
                    "--fs", "fat32", "--yes"], env=env, check=True, stdout=subprocess.DEVNULL)
    return image


def data_dirs(env: dict) -> list[str]:
    out = []
    for d in (REPO / ".tools/root/usr/share/seabios", Path(env.get("BB_SEABIOS_DIR", "/usr/share/seabios")),
              REPO / ".tools/root/usr/share/qemu", Path("/usr/share/qemu")):
        if d.is_dir() and str(d) not in out:
            out.append(str(d))
    return out


def qemu_cmd(qemu: str, image: Path, port: int, env: dict, *, efi: bool, kvm: bool, paused: bool,
             state: Path) -> list[str]:
    machine = "q35,kernel-irqchip=split" if kvm else "q35"
    cmd = [qemu, "-name", "bb gdb demo", "-nodefaults", "-machine", machine, "-m", "1024"]
    cmd += ["-accel", "kvm", "-cpu", "host"] if kvm else ["-accel", "tcg"]
    for d in data_dirs(env):
        cmd += ["-L", d]
    if efi:
        ovmf = Path(env["BB_OVMF_DIR"])
        # Fresh vars every boot: same firmware state, so shim loads GRUB at the
        # same address and the cached entry point is exact.
        vars_file = state / "demo-uefi.vars"
        shutil.copyfile(ovmf / "OVMF_VARS_4M.fd", vars_file)
        cmd += ["-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={ovmf / 'OVMF_CODE_4M.fd'}",
                "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}"]
    else:
        cmd += ["-bios", str(Path(env["BB_SEABIOS_DIR"]) / "bios-256k.bin")]
    cmd += ["-drive", f"if=none,id=bbdisk,format=raw,snapshot=on,file={image}",
            "-device", "qemu-xhci,id=xhci", "-device", "usb-storage,bus=xhci.0,drive=bbdisk,removable=on,bootindex=0",
            "-device", "VGA", "-display", "none", "-monitor", "none",
            "-serial", f"file:{state / ('demo-serial-efi.log' if efi else 'demo-serial-pc.log')}",
            "-gdb", f"tcp:127.0.0.1:{port}"]
    if paused:
        cmd.append("-S")
    return cmd


class Vm:
    def __init__(self, cmd: list[str], env: dict):
        self.proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, start_new_session=True)

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()


def bbgdb(platform: str, image: Path, port: int, ex: list[str], breaks=(), timeout: float = 180) -> str:
    cmd = [str(BB_DEV), "gdb", "--platform", platform, "--image", str(image), "--port", str(port), "--batch"]
    for b in breaks:
        cmd += ["--break", b]
    for e in ex:
        cmd += ["--ex", e]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, check=False)
    return p.stdout + p.stderr


def wait_port(port: int, vm: Vm, timeout: float = 20) -> None:
    """Wait until QEMU listens. (Does not connect: a connection would pause the VM.)"""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if vm.proc.poll() is not None:
            raise SystemExit(f"demo: QEMU exited: {vm.proc.stderr.read().decode(errors='replace')}")
        with open("/proc/net/tcp") as f:
            if any(f":{port:04X} " in line and " 0A " in line for line in f):
                return
        time.sleep(0.1)
    raise SystemExit("demo: QEMU did not open its gdb port")


def show(title: str, out: str) -> None:
    print(f"----- {title} -----")
    print("\n".join(line for line in out.splitlines() if "symbols for " not in line or "normal.mod" in line))


def demo_pc(args, env, image: Path, state: Path) -> bool:
    port = free_port()
    if args.bbdev_vm:
        cmd = [str(BB_DEV), "vm", "--image", str(image), "--mode", "bios", "--gdb", str(port), "--wait-gdb",
               "--display", "none", "--serial", "file", "--snapshot"]
        label = "bb-dev vm --mode bios --gdb --wait-gdb"
    else:
        kvm = args.kvm and kvm_ok()
        cmd = qemu_cmd("qemu-system-i386", image, port, env, efi=False, kvm=kvm, paused=True, state=state)
        label = f"qemu-system-i386 ({'KVM' if kvm else 'TCG'}), paused at reset"
    print(f"demo: BIOS: {label}, gdb stub :{port}", flush=True)
    vm = Vm(cmd, env)
    try:
        wait_port(port, vm, 60)
        out = bbgdb("pc", image, port, ["continue", "bt 6", "info args", "bb-modules", "kill"],
                    breaks=["grub_normal_execute"])
    finally:
        vm.stop()
    show("bb-dev gdb --platform pc --batch --break grub_normal_execute --ex continue --ex 'bt 6' ...", out)
    hit = re.search(r"Breakpoint \d+, grub_normal_execute \(config=", out)
    full_bt = re.search(r"#1 .* in grub_enter_normal_mode .* at \S*normal/main\.c", out)
    ok = bool(hit) and (bool(full_bt) or args.bbdev_vm)
    print(f"demo: BIOS: breakpoint in normal.mod {'hit' if hit else 'NOT hit'}"
          + ("" if args.bbdev_vm else f", backtrace through module + kernel {'ok' if full_bt else 'MISSING'}"))
    return ok


def demo_efi(args, env, image: Path, state: Path) -> bool:
    kvm = not args.tcg and kvm_ok()
    cache = paths.VM_OUT / image.stem / "gdb-efi.json"
    cache.unlink(missing_ok=True)
    port = free_port()
    print(f"demo: UEFI 1/2: qemu-system-x86_64 ({'KVM' if kvm else 'TCG'}), attach once the menu runs", flush=True)
    vm = Vm(qemu_cmd("qemu-system-x86_64", image, port, env, efi=True, kvm=kvm, paused=False, state=state), env)
    try:
        wait_port(port, vm)
        end = time.monotonic() + (60 if kvm else 240)
        while True:
            time.sleep(2)
            probe = bbgdb("efi", image, port, ["detach"], timeout=60)
            if "GRUB x86_64-efi is running" in probe:
                break
            if time.monotonic() > end:
                show("probe", probe)
                return False
        out1 = bbgdb("efi", image, port, ["continue", "bt 5", "kill"], breaks=["grub_menu_get_timeout"])
    finally:
        vm.stop()
    show("bb-dev gdb --platform efi --batch --break grub_menu_get_timeout (attached at the menu)", out1)
    hit1 = re.search(r"Breakpoint \d+, grub_menu_get_timeout \(\)", out1)

    port = free_port()
    print("demo: UEFI 2/2: same VM paused at reset; the cached load address gets a hardware breakpoint", flush=True)
    vm = Vm(qemu_cmd("qemu-system-x86_64", image, port, env, efi=True, kvm=kvm, paused=True, state=state), env)
    try:
        wait_port(port, vm)
        out2 = bbgdb("efi", image, port, ["continue", "bt 4", "kill"], breaks=["grub_normal_execute"])
    finally:
        vm.stop()
    show("bb-dev gdb --platform efi --batch --break grub_normal_execute (attached at reset)", out2)
    hit2 = re.search(r"Breakpoint \d+, grub_normal_execute \(config=", out2)
    print(f"demo: UEFI: at the menu {'hit' if hit1 else 'NOT hit'}; from reset {'hit' if hit2 else 'NOT hit'}")
    return bool(hit1 and hit2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--platform", choices=("pc", "efi", "both"), default="pc")
    ap.add_argument("--image", type=Path, default=DEMO_IMAGE)
    ap.add_argument("--bbdev-vm", action="store_true", help="BIOS: run the VM with `bb-dev vm` instead")
    ap.add_argument("--kvm", action="store_true", help="BIOS: qemu-system-i386 with KVM (default TCG)")
    ap.add_argument("--tcg", action="store_true", help="UEFI: no KVM")
    args = ap.parse_args(argv)
    env = paths.load_env()
    image = ensure_image(args.image.resolve(), env)
    state = paths.vm_state_dir(image)
    results = []
    if args.platform in ("pc", "both"):
        results.append(demo_pc(args, env, image, state))
    if args.platform in ("efi", "both"):
        results.append(demo_efi(args, env, image, state))
    ok = all(results)
    print("demo: PASS" if ok else "demo: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
