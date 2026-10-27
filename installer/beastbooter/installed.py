"""Which beast-boot a drive already has, and whether this app should update it.

The installed version is on the drive's boot partition (BEAST-EFI):
  BEAST-BOOTER.ID           marker: "beast-boot", install_id=, layout_version=, version=
  grub/beast/version.cfg    set bb_version="0.1.0" / set bb_build_id="82bc2b6c9502" (from the build)

Reading it needs no administrator rights when the platform can show that
partition as a folder (platforms/installed_probe.py: an existing mount, a
temporary read-only udisks mount on Linux, ...); `beast-boot info` reads it
from the raw device instead. This module only parses and compares; it never
touches a drive.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .esp import marker_layout_version, parse_marker, parse_set_lines
from .layout import ESP_LABEL, ESP_MARKER_PATH, FIRMWARE_DIR, FIRMWARE_INSTALLED_PATH, LAYOUT_VERSION

VERSION_CFG = "grub/beast/version.cfg"

# Freshness.state values
CURRENT = "current"          # same version (and the same build, when both builds are known)
OUTDATED = "outdated"        # the drive has an older version: Update boot files
OTHER_BUILD = "other-build"  # same version number, different build (development builds)
NEWER = "newer"              # the drive is newer than this app: don't downgrade
REINSTALL = "reinstall"      # older drive layout: update refuses, a reinstall is needed
UNKNOWN = "unknown"          # a beast-boot drive whose version could not be read


@dataclass(frozen=True)
class InstalledBoot:
    """What the drive's boot partition says about the installed beast-boot."""

    version: str            # "" when neither version.cfg nor the marker has one
    build_id: str = ""      # bb_build_id from version.cfg, "" if unknown
    layout_version: int | None = None
    install_id: str = ""
    how: str = ""           # how it was read, for logs: "mounted at /run/...", "udisks", "raw device"
    # Installed firmware packs and the boot partition's free space, in the shape of
    # `firmware list`'s "done" info (gui/firmware.py parse_installed / parse_space
    # read it): {"v": 1, "packs": [installed.json entries + "cpio_size" or
    # "missing"], "esp_free", "esp_cluster", "esp_label", "installed_json_size"}.
    # None when it could not be read (from_texts: not looked at).
    firmware: dict | None = None


@dataclass(frozen=True)
class ProbeResult:
    """What PlatformBackend.probe_installed found on a drive that looks like a
    beast-boot drive. installed None: it does, but the version could not be
    read (no administrator rights, partition not reachable)."""

    installed: InstalledBoot | None
    note: str = ""          # why it could not be read, for logs ("" when read)


def from_texts(marker_text: str | None, version_cfg_text: str | None, how: str = "") -> InstalledBoot | None:
    """InstalledBoot from the two files' contents; None if the marker is missing or not ours."""
    marker = parse_marker(marker_text) if marker_text else None
    if marker is None:
        return None
    cfg = parse_set_lines(version_cfg_text or "")
    return InstalledBoot(
        version=(cfg.get("bb_version") or marker.get("version") or "").strip(),
        build_id=(cfg.get("bb_build_id") or "").strip(),
        layout_version=marker_layout_version(marker),
        install_id=(marker.get("install_id") or "").strip(),
        how=how,
    )


def firmware_from_dir(root: str | Path) -> dict | None:
    """The installed firmware packs of a mounted boot partition (see
    InstalledBoot.firmware). A missing installed.json means no packs; an
    unreadable one gives None (the elevated `firmware list` then says more)."""
    root = Path(root)
    packs: list = []
    jpath = root / FIRMWARE_INSTALLED_PATH
    json_size = 0
    if jpath.is_file():
        try:
            raw = jpath.read_bytes()[: 4 * 1024 * 1024]
            d = json.loads(raw)
            packs = d["packs"] if d.get("v") == 1 and isinstance(d.get("packs"), list) else None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            packs = None
        if packs is None or not all(isinstance(p, dict) and isinstance(p.get("id"), str) for p in packs):
            return None
        json_size = len(raw)
    sizes: dict[str, int] = {}
    try:
        with os.scandir(root / FIRMWARE_DIR) as it:
            for e in it:
                if e.is_file():
                    sizes[e.name.lower()] = e.stat().st_size
    except OSError:
        pass
    out_packs = []
    for p in sorted(packs, key=lambda p: p["id"]):
        p = dict(p)
        size = sizes.get(f"{p['id']}.cpio".lower())
        if size is None:
            p["missing"] = True
        else:
            p["cpio_size"] = size
        out_packs.append(p)
    info: dict = {"v": 1, "packs": out_packs, "esp_label": ESP_LABEL, "installed_json_size": json_size}
    try:
        info["esp_free"] = shutil.disk_usage(root).free
    except OSError:
        pass
    try:
        info["esp_cluster"] = os.statvfs(root).f_bsize  # FAT: the cluster size
    except (OSError, AttributeError):  # no statvfs on Windows: parse_space assumes 4 KiB
        pass
    return info


def read_from_dir(root: str | Path, how: str = "") -> InstalledBoot | None:
    """Read a mounted boot partition (the folder that holds BEAST-BOOTER.ID):
    version, build and installed firmware packs. None if it is not a
    beast-boot boot partition or cannot be read."""
    root = Path(root)

    def text(rel: str, limit: int = 64 * 1024) -> str | None:
        try:
            with open(root / rel, "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    boot = from_texts(text(ESP_MARKER_PATH), text(VERSION_CFG), how or f"mounted at {root}")
    if boot is None:
        return None
    return dataclasses.replace(boot, firmware=firmware_from_dir(root))


_VERSION = re.compile(r"(\d+(?:\.\d+)*)(.*)")
_PART = re.compile(r"(\d+)|([A-Za-z]+)")


def version_key(version: str) -> tuple:
    """Sort key for versions like 0.1.0, 0.2.0-rc1, 0.2.0rc1, 1.0.0+git5: numbers
    compare as numbers (0.10 > 0.9), a pre-release suffix sorts before the
    release, "+build" metadata is ignored, unparsable versions sort first."""
    v = version.strip().lstrip("vV").split("+", 1)[0]
    m = _VERSION.fullmatch(v)
    if not m:
        return ((), 0, ((1, v.lower()),))
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums += (0,) * (4 - len(nums))
    tail = m.group(2).lstrip("-._")
    if not tail:
        return (nums, 1, ())
    return (nums, 0, tuple((0, int(n)) if n else (1, w.lower()) for n, w in _PART.findall(tail)))


def compare_versions(a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b (see version_key)."""
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


@dataclass(frozen=True)
class Freshness:
    state: str                       # CURRENT, OUTDATED, OTHER_BUILD, NEWER, REINSTALL, UNKNOWN
    installed: InstalledBoot | None  # None for UNKNOWN
    app_version: str
    summary: str                     # short, for a drive row: "beast-boot 0.1.0 · update available (0.2.0)"
    advice: str                      # a sentence for the hint under the list ("" when nothing to do)

    @property
    def needs_update(self) -> bool:
        return self.state in (OUTDATED, OTHER_BUILD)


def assess(installed: InstalledBoot | None, app_version: str, app_build_id: str = "") -> Freshness:
    """Compare what a beast-boot drive has with what this app would install.

    `installed` None means: the drive looks like a beast-boot drive but its
    version could not be read (UNKNOWN). Callers that know a drive is not a
    beast-boot drive should not call this at all."""
    if installed is None:
        return Freshness(UNKNOWN, None, app_version, "beast-boot drive",
                         "Its boot files' version can't be read without administrator rights; "
                         f"Update boot files makes sure it has {app_version}.")
    have = installed.version or "unknown version"
    # The same rules as `update` (commands.check_layout_version): only drives of
    # this layout can be updated, so never offer an update the CLI would refuse.
    if installed.layout_version is None:
        return Freshness(REINSTALL, installed, app_version, f"beast-boot {have} · unknown layout",
                         "This drive's boot partition has a layout this beast-boot doesn't know, so it "
                         "can't be updated in place: copy your files off it, then install again.")
    if installed.layout_version > LAYOUT_VERSION:
        return Freshness(NEWER, installed, app_version, f"beast-boot {have} · newer than this app",
                         f"This drive was made by a newer beast-boot (layout {installed.layout_version}); "
                         "use that version to update it.")
    if installed.layout_version < LAYOUT_VERSION:
        return Freshness(REINSTALL, installed, app_version, f"beast-boot {have} · needs a reinstall",
                         f"This drive uses an older layout that {app_version} can't update in place: "
                         "copy your files off it, then install again.")
    if not installed.version:
        return Freshness(OUTDATED, installed, app_version, f"beast-boot (unknown version) · update available ({app_version})",
                         f"Click Update boot files to put beast-boot {app_version} on it; your files stay.")
    c = compare_versions(installed.version, app_version)
    if c < 0:
        return Freshness(OUTDATED, installed, app_version, f"beast-boot {have} · update available ({app_version})",
                         f"This drive has beast-boot {have}. Click Update boot files to update it to "
                         f"{app_version}; your files on it are not touched.")
    if c > 0:
        return Freshness(NEWER, installed, app_version, f"beast-boot {have} · newer than this app",
                         f"This drive has beast-boot {have}, newer than this app ({app_version}). "
                         "Use the newer app; updating would downgrade it.")
    if installed.build_id and app_build_id and installed.build_id != app_build_id:
        return Freshness(OTHER_BUILD, installed, app_version, f"beast-boot {have} · different build",
                         f"Same version, different build ({installed.build_id} on the drive, {app_build_id} here). "
                         "Update boot files if you want this build.")
    return Freshness(CURRENT, installed, app_version, f"beast-boot {have} · up to date", "")
