"""Is a dev image built from the current dist/ and installer layout? Image recipes.

An image is current when its ESP marker's layout_version is the installer's
LAYOUT_VERSION and the bb_build_id in its /grub/beast/version.cfg is the
build_id of dist/manifest.json (menu-sync never rewrites version.cfg). If not:

  same layout, other build id  UPDATE: `bin/beast-boot update --image` swaps
                               the boot code and the ESP and keeps partition 1
                               (the ISOs and /beast-booter/config.cfg)
  older layout (layout 1)      REBUILD: update refuses it (it never moves
                               partitions); `bb-dev image --force` again, with
                               the options from the image's recipe

The recipe is out/dev/<image stem>.bbdev.json, written by `bb-dev image`: the
options the image was built with plus the dist build id and layout version.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from beastbooter import layout

from . import diskimg, menufiles, paths
from .msg import Failure, rel

CURRENT, UPDATE, REBUILD, UNKNOWN = "current", "update", "rebuild", "unknown"
VERSION_CFG = "/grub/beast/version.cfg"
RECIPE_SUFFIX = ".bbdev.json"
RECIPE_VERSION = 1
BEAST_BOOTER = paths.REPO / "bin" / "beast-boot"
BB_DEV = paths.REPO / "bin" / "bb-dev"
# `bb-dev setup` builds the default image with --fixtures --debug; images from
# before recipes existed are rebuilt with these options.
DEFAULT_OPTIONS = {"size": "4G", "layout": layout.DEFAULT_LAYOUT, "fs": None, "fs_auto": True,
                   "fixtures": True, "isos": None, "debug": True, "dryrun": False, "autoboot": None,
                   "serial_console": False}

_BUILD_ID = re.compile(r'^\s*set\s+bb_build_id="?([0-9A-Za-z._-]+)"?\s*$', re.MULTILINE)


def parse_build_id(data: bytes | None) -> str | None:
    m = _BUILD_ID.search(data.decode("utf-8", "replace")) if data else None
    return m.group(1) if m else None


@dataclass
class ImageState:
    layout_version: int | None = None
    build_id: str | None = None
    error: str = ""          # why something could not be read


def read_state(image: Path, info: diskimg.ImageInfo | None = None) -> ImageState:
    """Layout version (installer `info --json`) and bb_build_id (ESP version.cfg)."""
    try:
        info = info or diskimg.image_info(image)
    except (Failure, OSError, ValueError, KeyError) as e:
        return ImageState(error=f"cannot read it: {e}")
    try:
        lv = int(info.raw["layout_version"])
    except (KeyError, TypeError, ValueError):
        lv = None
    try:
        data = info.esp().read(VERSION_CFG)
    except (Failure, OSError) as e:
        return ImageState(lv, None, f"cannot read {VERSION_CFG}: {e}")
    return ImageState(lv, parse_build_id(data))


def dist_build_id(dist: Path | None = None) -> str | None:
    manifest = menufiles.load_manifest(dist)
    return (str(manifest.get("build_id") or "") or None) if manifest else None


@dataclass
class Verdict:
    action: str              # CURRENT | UPDATE | REBUILD | UNKNOWN
    reason: str
    state: ImageState
    dist_build: str | None = None

    @property
    def stale(self) -> bool:
        return self.action in (UPDATE, REBUILD)


def judge(state: ImageState, dist_build: str | None, want_layout: int = layout.LAYOUT_VERSION) -> Verdict:
    lv = state.layout_version
    if lv is None:
        return Verdict(UNKNOWN, state.error or "the installer reports no layout version", state, dist_build)
    if lv < want_layout:
        return Verdict(REBUILD, f"it has layout {lv}, the installer writes layout {want_layout} "
                                f"({layout.ESP_SIZE_MIB} MiB FAT32 ESP)", state, dist_build)
    if lv > want_layout:
        return Verdict(UNKNOWN, f"it has layout {lv}, newer than this installer's {want_layout}", state, dist_build)
    if not dist_build:
        return Verdict(UNKNOWN, "dist/ is not built (no build id to compare with)", state, dist_build)
    if state.build_id is None:
        return Verdict(UPDATE, "no bb_build_id readable on its ESP" + (f" ({state.error})" if state.error else ""),
                       state, dist_build)
    if state.build_id != dist_build:
        return Verdict(UPDATE, f"it was installed from build {state.build_id}, dist/ is build {dist_build}",
                       state, dist_build)
    return Verdict(CURRENT, f"layout {lv}, build {dist_build} (= dist/)", state, dist_build)


def check(image: Path, info: diskimg.ImageInfo | None = None, dist: Path | None = None) -> Verdict:
    return judge(read_state(image, info), dist_build_id(dist))


# ---------------------------------------------------------------------------
# Recipes
# ---------------------------------------------------------------------------

def recipe_path(image: Path) -> Path:
    image = Path(image)
    return image.with_name(image.stem + RECIPE_SUFFIX)


def write_recipe(image: Path, options: dict, *, build_id: str | None, layout_version: int | None) -> Path:
    p = recipe_path(image)
    data = {"recipe": RECIPE_VERSION, "image": Path(image).name,
            "written": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "options": {**DEFAULT_OPTIONS, **options},
            "dist_build_id": build_id, "layout_version": layout_version}
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, p)
    return p


def read_recipe(image: Path) -> dict | None:
    """The recipe next to `image`, or None (missing, unreadable or not a recipe)."""
    try:
        data = json.loads(recipe_path(image).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("options"), dict):
        return None
    return data


def recipe_argv(options: dict | None, out: Path) -> list[str]:
    """`bb-dev image` arguments that rebuild `out` with these recipe options."""
    o = {**DEFAULT_OPTIONS, **(options or {})}
    argv = ["--out", str(out), "--size", str(o["size"]), "--layout", str(o["layout"])]
    if o.get("fs") and not o.get("fs_auto"):
        argv += ["--fs", str(o["fs"])]
    for key, flag in (("fixtures", "--fixtures"), ("debug", "--debug"), ("dryrun", "--dryrun"),
                      ("serial_console", "--serial-console")):
        if o.get(key):
            argv.append(flag)
    if o.get("isos"):
        argv += ["--isos", str(o["isos"])]
    if o.get("autoboot"):
        argv += ["--autoboot", str(o["autoboot"])]
    return argv + ["--force"]


def rebuild_command(image: Path) -> str:
    """The shell command that rebuilds `image` (from its recipe, else the setup defaults)."""
    recipe = read_recipe(image)
    argv = recipe_argv(recipe["options"] if recipe else None, Path(rel(image)))
    return "bin/bb-dev image " + shlex.join(argv)


# ---------------------------------------------------------------------------
# Refreshing
# ---------------------------------------------------------------------------

def ensure_modifiable(image: Path) -> None:
    """Refuse to change an image a VM runs on or that is attached on this host."""
    pid = diskimg.running_vm(image)
    if pid:
        raise Failure(f"a VM is running on {rel(image)} (pid {pid}); its boot files cannot be refreshed now",
                      "quit it first (monitor command `quit`), or boot with --snapshot / --refresh never")
    atts = diskimg.attachments(image)
    if atts:
        raise Failure(f"{rel(image)} is attached on this host: {', '.join(a.describe() for a in atts)}; "
                      "refreshing it now can corrupt it", diskimg.release_hint(atts)
                      + " (or boot it as it is: --snapshot / --refresh never)")


def update_command(image: Path) -> list[str]:
    return [str(BEAST_BOOTER), "update", "--image", str(image), "--dist", str(paths.DIST), "--yes"]


def run_update(image: Path, env: dict) -> Verdict:
    """`bin/beast-boot update --image` (boot code + ESP from dist/, partition 1 kept)."""
    image = Path(image).absolute()
    ensure_modifiable(image)
    log = image.with_name(image.stem + ".update.log")
    cmd = update_command(image)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900, stdin=subprocess.DEVNULL)
    log.write_text("$ " + shlex.join(cmd) + "\n" + p.stdout + p.stderr)
    if p.returncode != 0:
        raise Failure(f"`bin/beast-boot update` failed ({p.returncode}); log: {rel(log)}\n"
                      + (p.stderr or p.stdout).strip()[-1200:], f"rebuild it: {rebuild_command(image)}")
    after = check(image)
    recipe = read_recipe(image)
    if recipe is not None:
        write_recipe(image, recipe["options"], build_id=after.state.build_id,
                     layout_version=after.state.layout_version)
    return after
