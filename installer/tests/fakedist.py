"""Build a fake dist/ directory for tests (and manual runs).

    python3 installer/tests/fakedist.py OUT_DIR [--version 0.1.0]

Dummy files at every REQUIRED_ESP_FILES path, the real stock GRUB boot.img
from $BB_GRUB_BIOS_DIR, a real core.img from grub-mkimage when available
(otherwise synthetic bytes with a GRUB-like diskboot sector), and a manifest
with correct sha256 values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from beastbooter.layout import (  # noqa: E402
    CORE_BLOCKLIST_OFFSET,
    CORE_BLOCKLIST_SEGMENT,
    DIST_BOOT_IMG,
    DIST_CORE_IMG,
    DIST_ESP_DIR,
    DIST_MANIFEST,
    REQUIRED_ESP_FILES,
)

EXTRA_ESP_FILES = {
    "grub/beast/menu.cfg": b"# fake menu helper\n",
    "grub/i386-pc/fat.mod": b"\x7fELF fake fat module\n",
    "grub/i386-pc/command.lst": b"*fake: fake\n",
    "grub/fonts/unicode.pf2": b"PFF2 fake font\n",
}


def grub_bios_dir() -> Path | None:
    d = os.environ.get("BB_GRUB_BIOS_DIR")
    cands = [Path(d)] if d else []
    root = Path(__file__).resolve().parents[2]
    cands += [Path("/usr/lib/grub/i386-pc"), root / ".tools/root/usr/lib/grub/i386-pc"]
    for c in cands:
        if (c / "boot.img").is_file():
            return c
    return None


def synthetic_core(sectors: int = 40) -> bytes:
    core = bytearray(os.urandom(sectors * 512 - 100))  # not a whole number of sectors
    struct.pack_into("<QHH", core, CORE_BLOCKLIST_OFFSET, 2, 0, CORE_BLOCKLIST_SEGMENT)
    return bytes(core)


def make_core(bios_dir: Path | None, out: Path) -> None:
    if bios_dir and shutil.which("grub-mkimage"):
        proc = subprocess.run(
            ["grub-mkimage", "-O", "i386-pc", "-d", str(bios_dir), "-p", "(,msdos2)/grub",
             "-o", str(out), "biosdisk", "part_msdos", "part_gpt", "fat"],
            capture_output=True,
        )
        if proc.returncode == 0:
            return
    out.write_bytes(synthetic_core())


def write_manifest(dist: Path, version: str = "0.1.0") -> None:
    files = {}
    for p in sorted(dist.rglob("*")):
        if p.is_file() and p.name != DIST_MANIFEST:
            rel = p.relative_to(dist).as_posix()
            data = p.read_bytes()
            files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                          "origin": "test:fakedist"}
    manifest = {
        "schema": 1, "name": "beast-boot", "version": version, "source_date_epoch": 1760000000,
        "secure_boot": {"cert_sha256": "0" * 64, "cert_subject": "CN=fake", "sbat": "sbat,1\n"},
        "files": files,
    }
    (dist / DIST_MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")


def make_fake_dist(dist: Path, version: str = "0.1.0", core: bytes | None = None) -> Path:
    dist = Path(dist)
    if dist.exists():
        shutil.rmtree(dist)
    esp = dist / DIST_ESP_DIR
    for rel in REQUIRED_ESP_FILES:
        f = esp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(f"fake {rel} {version}\n".encode())
    (esp / "grub/beast/version.cfg").write_text(f'set bb_version="{version}"\nset bb_build_id="test"\n')
    for rel, data in EXTRA_ESP_FILES.items():
        f = esp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
    bios = dist / "bios"
    bios.mkdir(parents=True)
    bdir = grub_bios_dir()
    if bdir:
        shutil.copyfile(bdir / "boot.img", dist / DIST_BOOT_IMG)
    else:  # minimal stand-in: 512 bytes with a boot signature
        (dist / DIST_BOOT_IMG).write_bytes(b"\xeb\x63\x90" + b"\0" * 507 + b"\x55\xaa")
    if core is None:
        make_core(bdir, dist / DIST_CORE_IMG)
    else:
        (dist / DIST_CORE_IMG).write_bytes(core)
    write_manifest(dist, version)
    return dist


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--version", default="0.1.0")
    a = ap.parse_args()
    print(make_fake_dist(Path(a.out), a.version))
