#!/usr/bin/env python3
"""Build the fixture ISOs used by the beast-booter e2e tests.

Each fixture is a tiny ISO 9660 image (xorriso -as mkisofs) that contains just
the files a boot recipe in docs/ARCHITECTURE.md §6 detects, with dummy
kernel/initrd bytes and a distinct volume label. Nothing in them is bootable
except:

  loopback       /boot/grub/loopback.cfg prints `BEAST_FIXTURE loopback iso_path=$iso_path`, then halts
  efi-chainload  /EFI/BOOT/BOOTX64.EFI is a small *unsigned* GRUB (x86_64-efi) whose embedded
                 config prints `BEAST_FIXTURE chainload`, then halts. It must run under UEFI
                 without Secure Boot and must be refused with Secure Boot on.
  ubuntu-layered /casper/minimal.squashfs is a real (xz) squashfs holding a dummy
                 usr/lib/modules/<FIXTURE_KVER>/kernel/fs/exfat/exfat.ko.zst, like
                 Ubuntu 24.04+ media: on an exFAT data partition the menu adds that
                 module to the initrd (bb_addon_prepare in grub/beast/lib.cfg).

Outputs are cached in out/e2e/fixtures/<name>.iso; a fixture is rebuilt only
when its definition (or the tool versions) change.

Usage:  python3 tests/e2e/fixtures/build_fixtures.py [--out DIR] [--force] [NAME...]
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
from pathlib import Path

BUILDER_VERSION = 4

HERE = Path(__file__).resolve().parent
BB_ROOT = Path(os.environ.get("BB_ROOT", HERE.parents[2])).resolve()
DEFAULT_OUT = Path(os.environ.get("BB_E2E_OUT", BB_ROOT / "out" / "e2e")) / "fixtures"
GRUB_EFI_DIR = Path(os.environ.get("BB_GRUB_EFI_DIR", "/usr/lib/grub/x86_64-efi"))

EFI_PAYLOAD = "@efi-payload"  # placeholder: the unsigned chainload test binary
SQUASHFS_EXFAT = "@squashfs-exfat"  # placeholder: squashfs with a dummy exfat module
FIXTURE_KVER = "0.0.0-beast-fixture"
SQUASHFS_EXFAT_FILES = {
    f"usr/lib/modules/{FIXTURE_KVER}/kernel/fs/exfat/exfat.ko.zst": b"beast-booter e2e fixture: dummy exfat module\n",
    f"usr/lib/modules/{FIXTURE_KVER}/kernel/fs/isofs/isofs.ko.zst": b"beast-booter e2e fixture: dummy isofs module\n",
}

# The chainloaded payload: rescue-mode embedded config, no normal.mod needed.
# It prints on the EFI console only; OVMF mirrors that to the serial port.
# (A second, serial terminal would interleave the output character by
# character, because rescue-mode GRUB writes each character to every terminal.)
EFI_PAYLOAD_CFG = """\
echo BEAST_FIXTURE chainload
halt
"""
EFI_PAYLOAD_MODULES = ["echo", "halt"]

LOOPBACK_CFG = """\
echo "BEAST_FIXTURE loopback iso_path=$iso_path"
halt
"""


def dummy(what: str) -> bytes:
    return (f"beast-booter e2e fixture: dummy {what} (not bootable)\n" * 16).encode()


# name -> spec. "files" maps ISO paths to bytes (or EFI_PAYLOAD).
# "rockridge": False builds a plain ISO 9660 + Joliet image like Windows media.
FIXTURES: dict[str, dict] = {
    "loopback": {
        "label": "BB_LOOPBACK",
        "files": {
            "/boot/grub/loopback.cfg": LOOPBACK_CFG.encode(),
            # Ubuntu-style: loopback.cfg AND casper. Recipe 1 must win.
            "/casper/vmlinuz": dummy("casper kernel"),
            "/casper/initrd": dummy("casper initrd"),
        },
    },
    "casper": {
        "label": "BB_CASPER",
        "files": {"/casper/vmlinuz": dummy("casper kernel"), "/casper/initrd": dummy("casper initrd")},
    },
    "ubuntu-layered": {
        # Like Ubuntu 24.04+ desktop media: loopback.cfg, casper and a layered
        # squashfs that carries the kernel modules (exfat among them).
        "label": "BB_UBUNTU_LAYERED",
        "files": {
            "/boot/grub/loopback.cfg": LOOPBACK_CFG.encode(),
            "/casper/vmlinuz": dummy("casper kernel"),
            "/casper/initrd": dummy("casper initrd"),
            "/casper/minimal.squashfs": SQUASHFS_EXFAT,
        },
    },
    "casper-lz": {
        # Only the later initrd names: the first existing one (initrd.lz) must be used.
        "label": "BB_CASPER_LZ",
        "files": {
            "/casper/vmlinuz": dummy("casper kernel"),
            "/casper/initrd.lz": dummy("casper initrd.lz"),
            "/casper/initrd.gz": dummy("casper initrd.gz"),
            "/casper/initrd.img": dummy("casper initrd.img"),
        },
    },
    "live-boot": {
        "label": "BB_LIVE",
        "files": {"/live/vmlinuz": dummy("live kernel"), "/live/initrd.img": dummy("live initrd")},
    },
    "archiso": {
        "label": "ARCH_202610",
        "files": {
            "/arch/boot/x86_64/vmlinuz-linux": dummy("arch kernel"),
            "/arch/boot/x86_64/initramfs-linux.img": dummy("arch initramfs"),
        },
    },
    "dracut-live": {
        "label": "BB-Dracut-Live",  # mixed case on purpose: must reach the cmdline unchanged
        "files": {
            "/LiveOS/squashfs.img": dummy("squashfs"),
            "/images/pxeboot/vmlinuz": dummy("fedora kernel"),
            "/images/pxeboot/initrd.img": dummy("fedora initrd"),
        },
    },
    "anaconda": {
        "label": "BB-Anaconda",
        "files": {
            "/images/pxeboot/vmlinuz": dummy("anaconda kernel"),
            "/images/pxeboot/initrd.img": dummy("anaconda initrd"),
            "/images/install.img": dummy("anaconda stage2"),
        },
    },
    "dracut-kiwi": {
        # Fedora 44+ and openSUSE Tumbleweed live ISOs: KIWI layout, dracut initrd.
        "label": "BB-Kiwi-Live",
        "files": {
            "/LiveOS/squashfs.img": dummy("squashfs"),
            "/boot/x86_64/loader/linux": dummy("kiwi kernel"),
            "/boot/x86_64/loader/initrd": dummy("kiwi initrd"),
        },
    },
    "kiwi-installer": {
        # openSUSE Leap 16 (Agama) installer: no LiveOS, but a boot/grub2 tree.
        "label": "Install-Kiwi-16",
        "files": {
            "/boot/x86_64/loader/linux": dummy("kiwi kernel"),
            "/boot/x86_64/loader/initrd": dummy("kiwi initrd"),
            "/boot/grub2/grub.cfg": dummy("grub cfg"),
        },
    },
    "suse": {
        "label": "BB_SUSE",
        "files": {
            "/boot/x86_64/loader/linux": dummy("suse kernel"),
            "/boot/x86_64/loader/initrd": dummy("suse initrd"),
        },
    },
    "debian-installer": {
        "label": "BB_DI",
        "files": {
            "/install.amd/vmlinuz": dummy("d-i kernel"),
            "/install.amd/initrd.gz": dummy("d-i initrd"),
            "/.disk/info": b"BeastBoot fixture netinst\n",
            "/pool/main/l/linux-signed-amd64/loop-modules-6.12.0-amd64-di_6.12.0-1_amd64.udeb": dummy("loop udeb"),
        },
    },
    "debian-installer-nokernelmods": {
        # no loop-modules udeb: the menu must say so instead of booting a dead installer
        "label": "BB_DI_NOLOOP",
        "files": {
            "/install.amd/vmlinuz": dummy("d-i kernel"),
            "/install.amd/initrd.gz": dummy("d-i initrd"),
            "/.disk/info": b"BeastBoot fixture netinst\n",
        },
    },
    "alpine": {
        "label": "BB_ALPINE",
        "files": {
            "/.alpine-release": b"3.24.0\n",
            "/apks/.boot_repository": b"",
            "/boot/vmlinuz-lts": dummy("alpine kernel"),
            "/boot/initramfs-lts": dummy("alpine initramfs"),
        },
    },
    "windows": {
        # Like real Windows media: no Rock Ridge, lower-case names, and an EFI
        # loader too (windows must win over efi-chainload).
        "label": "BB_WIN",
        "rockridge": False,
        "files": {
            "/sources/boot.wim": dummy("boot.wim"),
            "/sources/install.wim": dummy("install.wim"),
            "/bootmgr": dummy("bootmgr"),
            "/efi/microsoft/boot/bcd": dummy("bcd"),
            "/efi/boot/bootx64.efi": dummy("windows efi loader"),
        },
    },
    "winpe": {
        # A Windows PE / WinRE ISO: boot.wim but no install image, booted as it is.
        "label": "BB_WINPE",
        "rockridge": False,
        "files": {
            "/sources/boot.wim": dummy("boot.wim"),
            "/bootmgr": dummy("bootmgr"),
            "/efi/microsoft/boot/bcd": dummy("bcd"),
        },
    },
    "efi-chainload": {
        "label": "BB_EFI",
        "files": {"/EFI/BOOT/BOOTX64.EFI": EFI_PAYLOAD},
    },
    "efi-chainload-lower": {
        # Rock Ridge keeps the lower case, so a case-sensitive lookup of
        # /EFI/BOOT/BOOTX64.EFI fails: the menu must match "any case".
        "label": "BB_EFI_LOWER",
        "files": {"/efi/boot/bootx64.efi": EFI_PAYLOAD},
    },
    "none": {
        "label": "BB_NONE",
        "files": {"/README.TXT": b"no boot recipe matches this image\n", "/data/blob.bin": dummy("blob")},
    },
}


def _tool_version(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (p.stdout + p.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "unknown"


def _need(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise RuntimeError(f"{tool} not found on PATH (source scripts/dev-env.sh)")
    return path


def _stamp_ok(target: Path, key: str) -> bool:
    stamp = target.with_name(target.name + ".stamp")
    return target.exists() and stamp.exists() and stamp.read_text().strip() == key


def _write_stamp(target: Path, key: str) -> None:
    target.with_name(target.name + ".stamp").write_text(key + "\n")


def build_efi_payload(out_dir: Path = DEFAULT_OUT, force: bool = False) -> Path:
    """The unsigned x86_64-efi GRUB that prints `BEAST_FIXTURE chainload`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "chainload-payload.efi"
    key = hashlib.sha256(
        json.dumps([BUILDER_VERSION, EFI_PAYLOAD_CFG, EFI_PAYLOAD_MODULES, str(GRUB_EFI_DIR),
                    _tool_version(["grub-mkimage", "--version"])]).encode()
    ).hexdigest()
    if not force and _stamp_ok(target, key):
        return target
    with tempfile.TemporaryDirectory(dir=out_dir) as tmp:
        cfg = Path(tmp) / "embedded.cfg"
        cfg.write_text(EFI_PAYLOAD_CFG)
        tmp_out = Path(tmp) / target.name
        subprocess.run(
            [_need("grub-mkimage"), "-O", "x86_64-efi", "-d", str(GRUB_EFI_DIR), "-p", "/nonexistent",
             "-c", str(cfg), "-o", str(tmp_out), *EFI_PAYLOAD_MODULES],
            check=True, capture_output=True, text=True,
        )
        os.replace(tmp_out, target)
    _write_stamp(target, key)
    return target


def _squashfs_key() -> str:
    blob = json.dumps([{k: hashlib.sha256(v).hexdigest() for k, v in SQUASHFS_EXFAT_FILES.items()},
                       _tool_version(["mksquashfs", "-version"])], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def build_squashfs_exfat(dest: Path) -> None:
    """xz squashfs (as on Ubuntu media) with SQUASHFS_EXFAT_FILES, reproducible."""
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        tree = Path(tmp) / "tree"
        for rel, data in SQUASHFS_EXFAT_FILES.items():
            f = tree / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        subprocess.run([_need("mksquashfs"), str(tree), str(dest), "-noappend", "-quiet", "-no-progress",
                        "-comp", "xz", "-all-root", "-mkfs-time", "1760000000", "-all-time", "1760000000"],
                       check=True, capture_output=True, text=True)


def _spec_key(name: str, spec: dict, payload_hash: str) -> str:
    files = {}
    for path, content in sorted(spec["files"].items()):
        if content == EFI_PAYLOAD:
            files[path] = payload_hash
        elif content == SQUASHFS_EXFAT:
            files[path] = _squashfs_key()
        else:
            files[path] = hashlib.sha256(content).hexdigest()
    blob = json.dumps(
        [BUILDER_VERSION, name, spec["label"], spec.get("rockridge", True), files,
         _tool_version(["xorriso", "-version"])],
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def iso_volume_label(iso: Path) -> str:
    """Volume identifier from the primary volume descriptor (LBA 16)."""
    with open(iso, "rb") as f:
        f.seek(16 * 2048)
        pvd = f.read(2048)
    if pvd[1:6] != b"CD001":
        raise ValueError(f"{iso}: not an ISO 9660 image")
    return pvd[40:72].decode("ascii", "replace").rstrip()


def build_fixture(name: str, out_dir: Path = DEFAULT_OUT, force: bool = False) -> Path:
    spec = FIXTURES[name]
    out_dir.mkdir(parents=True, exist_ok=True)
    needs_payload = EFI_PAYLOAD in spec["files"].values()
    payload = build_efi_payload(out_dir, force=force) if needs_payload else None
    payload_hash = hashlib.sha256(payload.read_bytes()).hexdigest() if payload else ""
    target = out_dir / f"{name}.iso"
    key = _spec_key(name, spec, payload_hash)
    if not force and _stamp_ok(target, key):
        return target
    with tempfile.TemporaryDirectory(dir=out_dir) as tmp:
        root = Path(tmp) / "root"
        for path, content in spec["files"].items():
            dest = root / path.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if content == EFI_PAYLOAD:
                shutil.copyfile(payload, dest)
            elif content == SQUASHFS_EXFAT:
                build_squashfs_exfat(dest)
            else:
                dest.write_bytes(content)
        tmp_iso = Path(tmp) / f"{name}.iso"
        cmd = [_need("xorriso"), "-as", "mkisofs", "-quiet", "-V", spec["label"], "-J", "-joliet-long"]
        if spec.get("rockridge", True):
            cmd += ["-R"]
        else:
            cmd += ["-iso-level", "3"]
        cmd += ["-o", str(tmp_iso), str(root)]
        env = dict(os.environ, SOURCE_DATE_EPOCH="1760000000")
        subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
        label = iso_volume_label(tmp_iso)
        if label != spec["label"]:
            raise RuntimeError(f"{name}: xorriso wrote volume label {label!r}, expected {spec['label']!r}")
        os.replace(tmp_iso, target)
    _write_stamp(target, key)
    return target


def build_all(out_dir: Path = DEFAULT_OUT, names=None, force: bool = False) -> dict[str, Path]:
    names = list(names or FIXTURES)
    return {n: build_fixture(n, out_dir, force=force) for n in names}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--force", action="store_true", help="rebuild even if cached")
    ap.add_argument("names", nargs="*", help=f"fixtures to build (default: all): {', '.join(FIXTURES)}")
    args = ap.parse_args(argv)
    unknown = [n for n in args.names if n not in FIXTURES]
    if unknown:
        ap.error(f"unknown fixture(s): {', '.join(unknown)}")
    for name, path in build_all(args.out, args.names, args.force).items():
        print(f"{name:20s} {path}  label={FIXTURES[name]['label']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
