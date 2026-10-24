"""Load and verify a dist/ directory (ARCHITECTURE.md §4).

Every file that will be written to a drive is copied into a private staging
directory while its SHA-256 is computed, and only the staged, verified copy is
used afterwards. Nothing is written to the target unless verification passes.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import BeastError
from .layout import (
    BOOT_IMG_SIZE,
    DEVICE_CFG_PATH,
    DIST_BOOT_IMG,
    DIST_CORE_IMG,
    DIST_ESP_DIR,
    DIST_MANIFEST,
    ESP_MARKER_PATH,
    REQUIRED_ESP_FILES,
)

MANIFEST_SCHEMA = 1
# Directories under dist/ whose contents end up on the drive.
WRITTEN_DIRS = (DIST_ESP_DIR, "bios")
# Must never be shipped: shim would run it and create firmware boot entries.
FORBIDDEN_ESP_FILES = ("efi/boot/fbx64.efi",)
# Files the installer itself writes into the ESP.
INSTALLER_ESP_FILES = (DEVICE_CFG_PATH, ESP_MARKER_PATH)


@dataclass
class Dist:
    root: Path  # the dist/ directory given by the user
    staging: Path  # verified copies, same relative layout
    version: str
    manifest: dict
    boot_img: bytes
    core_img: bytes

    @property
    def esp_dir(self) -> Path:
        return self.staging / DIST_ESP_DIR

    def esp_files(self) -> list[str]:
        """Paths (relative to the ESP root, '/'-separated) of the staged ESP files."""
        out = []
        for dirpath, _dirs, files in os.walk(self.esp_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(dirpath, f), self.esp_dir)
                out.append(rel.replace(os.sep, "/"))
        return sorted(out)


def default_dist_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "dist"


def _check_relpath(p: str) -> None:
    norm = posixpath.normpath(p)
    if (
        not p
        or p.startswith("/")
        or "\\" in p
        or norm != p
        or norm == ".."
        or norm.startswith("../")
        or "\0" in p
    ):
        raise BeastError(f"manifest.json: invalid file path {p!r}")


def _files_on_disk(root: Path) -> list[str]:
    out = []
    for top in WRITTEN_DIRS:
        base = root / top
        if not base.is_dir():
            continue
        for dirpath, dirs, files in os.walk(base):
            for name in dirs + files:
                full = os.path.join(dirpath, name)
                if name in dirs and os.path.islink(full):
                    raise BeastError(f"dist: symlinked directory not allowed: {full}")
            for name in files:
                full = os.path.join(dirpath, name)
                out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(out)


def load_dist(dist_dir: str | os.PathLike, staging: str | os.PathLike) -> Dist:
    """Verify dist_dir against its manifest and stage verified copies under `staging`."""
    root = Path(dist_dir)
    if not root.is_dir():
        raise BeastError(
            f"dist directory not found: {root} (run `make build`, or pass --dist DIR)"
        )
    mpath = root / DIST_MANIFEST
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BeastError(f"{mpath} is missing; is {root} a beast-booter dist directory?") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BeastError(f"cannot read {mpath}: {e}") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise BeastError(f"{mpath}: unsupported manifest (expected \"schema\": {MANIFEST_SCHEMA})")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise BeastError(f"{mpath}: \"files\" must be a non-empty object")

    problems: list[str] = []
    for p, meta in files.items():
        _check_relpath(p)
        if not isinstance(meta, dict) or not isinstance(meta.get("sha256"), str):
            problems.append(f"{p}: no sha256 in manifest")
    required = [DIST_BOOT_IMG, DIST_CORE_IMG] + [f"{DIST_ESP_DIR}/{f}" for f in REQUIRED_ESP_FILES]
    for p in required:
        if p not in files:
            problems.append(f"{p}: required file not listed in manifest")
    for p in _files_on_disk(root):
        if p not in files:
            problems.append(f"{p}: present in dist but not listed in manifest")
        rel_esp = p[len(DIST_ESP_DIR) + 1 :] if p.startswith(DIST_ESP_DIR + "/") else None
        if rel_esp is not None and rel_esp.lower() in FORBIDDEN_ESP_FILES:
            problems.append(f"{p}: must not be shipped (shim fallback loader)")
    if problems:
        raise _verification_error(root, problems)

    staging = Path(staging)
    staging.mkdir(parents=True, exist_ok=True)
    for p, meta in sorted(files.items()):
        src = root / p
        try:
            st = os.stat(src)
        except FileNotFoundError:
            problems.append(f"{p}: missing")
            continue
        except OSError as e:
            problems.append(f"{p}: {e.strerror}")
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{p}: not a regular file")
            continue
        top = p.split("/", 1)[0]
        dst = staging / p if top in WRITTEN_DIRS else None
        digest = _stage_file(src, dst)
        if digest != meta["sha256"].lower():
            problems.append(f"{p}: sha256 mismatch (manifest {meta['sha256'][:12]}..., file {digest[:12]}...)")
    if problems:
        shutil.rmtree(staging, ignore_errors=True)
        raise _verification_error(root, problems)

    for p in INSTALLER_ESP_FILES:  # installer-owned; never take these from dist
        try:
            (staging / DIST_ESP_DIR / p).unlink()
        except FileNotFoundError:
            pass

    boot_img = (staging / DIST_BOOT_IMG).read_bytes()
    core_img = (staging / DIST_CORE_IMG).read_bytes()
    if len(boot_img) != BOOT_IMG_SIZE:
        raise BeastError(f"{root / DIST_BOOT_IMG}: must be exactly {BOOT_IMG_SIZE} bytes")
    version = str(manifest.get("version") or "unknown")
    return Dist(root, staging, version, manifest, boot_img, core_img)


def _stage_file(src: Path, dst: Path | None) -> str:
    h = hashlib.sha256()
    out = None
    try:
        if dst is not None:
            dst.parent.mkdir(parents=True, exist_ok=True)
            out = open(dst, "wb")
        with open(src, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
                if out:
                    out.write(chunk)
    finally:
        if out:
            out.close()
    return h.hexdigest()


def _verification_error(root: Path, problems: list[str]) -> BeastError:
    shown = problems[:6]
    more = f"\n  ... and {len(problems) - len(shown)} more" if len(problems) > len(shown) else ""
    lines = "\n  ".join(shown)
    return BeastError(
        f"dist verification failed for {root} (nothing was written):\n  {lines}{more}"
    )
