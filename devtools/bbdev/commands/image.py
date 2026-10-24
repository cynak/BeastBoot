"""bb-dev image: build a dev drive image from dist/ with the real installer.

  bb-dev image --fixtures --debug          the standard dev image
  bb-dev image --isos ~/isos --force       your own ISO collection (tree kept)
  bb-dev image --fs fat32 --out out/dev/fat.img --fixtures --dryrun

The image is installed to <out>.partial, filled, and only then renamed over
<out>, so a failed build never leaves a half-written image behind (and a VM
still running on the old image keeps its file). The options are saved next to
the image as <name>.bbdev.json (its recipe), so `bb-dev vm` can rebuild it the
same way when the installer's layout changes.

On an existing image without --force, it offers a refresh instead: `beast-booter
update` (boot files only, data partition kept) when just the build differs, a
rebuild when the layout is older, nothing when it is current.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from beastbooter import layout
from beastbooter.errors import BeastError
from beastbooter.util import human_size, parse_size

from .. import diskimg, freshness, menufiles, paths, userconfig
from ..msg import Failure, confirm, note, rel, run_guarded, warn

CMD = "image"
FIXTURE_DIR_ON_IMAGE = "/recipes"  # same paths as the e2e trees (bbe2e/trees.py RECIPE_DIR)
FIXTURE_CACHE = paths.OUT / "e2e" / "fixtures"
FIXTURE_BUILDER = paths.REPO / "tests" / "e2e" / "fixtures" / "build_fixtures.py"
FAT32_MAX_FILE = (4 << 30) - 1


def register(sub) -> None:
    p = sub.add_parser("image", help="build a dev drive image from dist/",
                       description="Build a beast-booter drive image from dist/ with the installer, "
                                   "optionally filled with ISOs and a /beast-booter/config.cfg.")
    p.add_argument("--out", type=Path, metavar="PATH", help=f"image file (default: {rel(paths.DEFAULT_IMAGE)})")
    p.add_argument("--size", default="4G", help="image size: 1G (minimum), 8G or bytes (default: 4G; sparse)")
    p.add_argument("--layout", choices=layout.LAYOUTS, default=layout.DEFAULT_LAYOUT, help="partition table (default: msdos)")
    p.add_argument("--fs", choices=layout.FILESYSTEMS,
                   help="data filesystem (default: exfat when udisks works, else fat32)")
    p.add_argument("--isos", type=Path, metavar="DIR", help="copy this directory tree onto the data partition")
    p.add_argument("--fixtures", action="store_true",
                   help=f"add the e2e fixture ISOs under {FIXTURE_DIR_ON_IMAGE}/ (built and cached in out/e2e/fixtures)")
    p.add_argument("--debug", action="store_true", help="config.cfg: bb_debug=1 (BEAST: lines)")
    p.add_argument("--dryrun", action="store_true", help="config.cfg: bb_dryrun=1 (print the hand-off, do not boot)")
    p.add_argument("--autoboot", metavar="PATH", help="config.cfg: bb_autoboot=PATH (an ISO on the data partition)")
    p.add_argument("--serial-console", action="store_true", help="installer --serial-console (device.cfg bb_serial=1)")
    p.add_argument("--force", action="store_true", help="replace an existing image")
    p.add_argument("--yes", "-y", action="store_true",
                   help="existing image: refresh (or rebuild) it without asking")
    p.set_defaults(func=run)


def run(args) -> int:
    return run_guarded(CMD, _run, args)


def make_build(env: dict) -> None:
    note(CMD, "running `make build` ...")
    if subprocess.run(["make", "build"], cwd=paths.REPO, env=env).returncode != 0:
        raise Failure("`make build` failed")


def check_dist(env: dict) -> None:
    st = menufiles.dist_state()
    if not st.present:
        if confirm("bb-dev image: dist/ is missing. Run `make build` now?"):
            make_build(env)
            return
        raise Failure("dist/ is not built (dist/manifest.json missing)", "run `make build` (after `make keys`)")
    if st.stale:
        warn(CMD, f"dist/ does not match the sources: {st.describe()}")
        if confirm("bb-dev image: run `make build` first?"):
            make_build(env)
        else:
            warn(CMD, "building from the existing dist/ (run `make build`, or `bb-dev menu-sync` to push grub/ edits)")


def fixture_files(env: dict) -> list[tuple[str, Path]]:
    """Build (or reuse) the e2e fixture ISOs; [(path on image, file)]."""
    p = subprocess.run([sys.executable, str(FIXTURE_BUILDER), "--out", str(FIXTURE_CACHE)],
                       capture_output=True, text=True, env=env, timeout=900)
    if p.returncode != 0:
        raise Failure("building the fixture ISOs failed:\n" + (p.stderr or p.stdout).strip()[-1500:],
                      "needs xorriso and grub-mkimage: `bb-dev doctor`")
    out = []
    for line in p.stdout.splitlines():
        m = re.match(r"^(\S+)\s+(.+?)\s+label=", line)
        if m:
            src = Path(m.group(2))
            out.append((f"{FIXTURE_DIR_ON_IMAGE}/{src.name}", src))
    if not out:
        raise Failure(f"fixture builder printed no ISOs:\n{p.stdout[-500:]}")
    return out


def tree_files(src: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    """--isos: ([(path on image, file)], [empty directories on image])."""
    src = Path(src)
    if not src.is_dir():
        raise Failure(f"--isos: {src} is not a directory")
    found, empty = diskimg.walk_tree(src)
    files = [("/" + r, p) for r, p in found]
    dirs = ["/" + d for d in empty]
    broken = sorted(p for p in src.rglob("*") if p.is_symlink() and not p.exists())
    if broken:
        warn(CMD, "--isos: skipping broken symlinks: " + ", ".join(str(p.relative_to(src)) for p in broken[:5]))
    if not files:
        warn(CMD, f"--isos: {src} contains no files")
    return files, dirs


def choose_fs(requested: str | None, needs_writer: bool) -> str:
    if requested == "fat32" or (requested and not needs_writer):
        return requested
    ok, reason = diskimg.udisks_status()
    if requested:
        if not ok:
            raise Failure(f"cannot fill an {requested} data partition: {reason}", "use --fs fat32")
        return requested
    if ok:
        return "exfat"
    warn(CMD, f"udisks is not usable ({reason}); using FAT32, which cannot hold files of 4 GiB or more")
    return "fat32"


def describe_contents(files: list[tuple[str, Path]], sizes: dict[str, int],
                      dirs: list[str] | None = None) -> list[str]:
    dirs = dirs or []
    groups: dict[str, list[int]] = {}
    for dest, _src in files:
        top = dest.strip("/").split("/", 1)
        key = "/" + top[0] + ("/" if len(top) > 1 else "")
        groups.setdefault(key, []).append(sizes[dest])
    for d in dirs:
        groups.setdefault("/" + d.strip("/").split("/", 1)[0] + "/", [])
    lines = []
    for key in sorted(groups):
        n, total = len(groups[key]), sum(groups[key])
        if not n:
            lines.append(f"{key}  (empty)")
        else:
            lines.append(f"{key}  ({n} file{'s' if n != 1 else ''}, {human_size(total)})" if key.endswith("/")
                         else f"{key}  ({human_size(total)})")
    if dirs:
        lines.append(f"({len(dirs)} empty folder{'s' if len(dirs) != 1 else ''} kept from --isos)")
    return lines


def _run(args) -> int:
    env = diskimg.tool_env()
    out = Path(args.out or paths.DEFAULT_IMAGE).absolute()
    try:
        size = parse_size(args.size)
    except BeastError as e:
        raise Failure(str(e))
    if size < layout.MIN_DISK_MIB * layout.MIB:
        raise Failure(f"--size {args.size} is too small (minimum {layout.MIN_DISK_MIB}M)")
    if out.exists() and not args.force:
        done = offer_refresh(args, out, env)
        if done is not None:
            return done
    if out.exists() and diskimg.running_vm(out):
        warn(CMD, f"a VM is running on {rel(out)}; it keeps using the old image until it is restarted")

    if not getattr(args, "dist_checked", False):
        check_dist(env)

    autoboot = None
    if args.autoboot:
        autoboot = userconfig.normalise("bb_autoboot", args.autoboot)
    config = userconfig.render(debug=args.debug, dryrun=args.dryrun, autoboot=autoboot)

    files: list[tuple[str, Path]] = []
    dirs: list[str] = []
    if args.fixtures:
        files += fixture_files(env)
    if args.isos:
        tree, dirs = tree_files(args.isos)
        files += tree
    # a later entry for the same destination wins
    files = list({d: (d, s) for d, s in files}.values())
    sizes = {d: s.stat().st_size for d, s in files}

    fs = choose_fs(args.fs, bool(files or dirs or config))
    if fs == "fat32":
        big = [d for d in sizes if sizes[d] > FAT32_MAX_FILE]
        if big:
            raise Failure(f"FAT32 cannot hold files of 4 GiB or more: {', '.join(big[:3])}", "use --fs exfat")
    data_room = size - (layout.ESP_SIZE_MIB + 3) * layout.MIB
    total = sum(sizes.values())
    if total > data_room * 0.97:
        raise Failure(f"{human_size(total)} of files do not fit on a {args.size} image", "use a bigger --size")
    if autoboot and files and autoboot.lower() not in {d.lower() for d, _ in files}:
        warn(CMD, f"--autoboot {autoboot}: no such file among the files copied to the image")

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".partial")
    log = out.with_name(out.stem + ".install.log")
    cmd = [sys.executable, "-m", "beastbooter", "install", "--image", str(tmp), "--size", args.size,
           "--layout", args.layout, "--fs", fs, "--dist", str(paths.DIST), "--yes"]
    if args.serial_console:
        cmd.append("--serial-console")
    note(CMD, f"installing {rel(out)} ({args.size}, {args.layout}, {fs}) from {rel(paths.DIST)} ...")
    try:
        if tmp.exists():
            tmp.unlink()
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
        log.write_text("$ " + " ".join(cmd) + "\n" + p.stdout + p.stderr)
        if p.returncode != 0:
            raise Failure(f"the installer failed ({p.returncode}); log: {rel(log)}\n"
                          + (p.stderr or p.stdout).strip()[-1200:])
        info = diskimg.image_info(tmp)
        if config or files or dirs:
            if files:
                note(CMD, f"copying {len(files)} file{'s' if len(files) != 1 else ''} ({human_size(total)}) "
                          f"to the {fs} data partition ...")
            with diskimg.data_access(info) as w:
                if config:
                    w.write(diskimg.USER_CONFIG, config.encode())
                w.copy_files(files)
                for d in dirs:
                    w.mkdirs(d)
        os.replace(tmp, out)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    info.path = out
    recipe = freshness.write_recipe(out, {
        "size": args.size, "layout": args.layout, "fs": fs, "fs_auto": args.fs is None,
        "fixtures": bool(args.fixtures), "isos": str(Path(args.isos).absolute()) if args.isos else None,
        "debug": bool(args.debug), "dryrun": bool(args.dryrun), "autoboot": autoboot,
        "serial_console": bool(args.serial_console),
    }, build_id=freshness.dist_build_id(), layout_version=info.raw.get("layout_version"))
    print(f"image   {rel(out)}  {human_size(size)} (sparse), {info.layout}, beast-booter {info.version}")
    print(f"data    partition 1: LBA {info.data_start_lba} = byte offset {info.data_offset}, "
          f"{human_size(info.data_size)}, {fs}")
    print(f"esp     partition 2: LBA {info.esp_start_lba} = byte offset {info.esp_offset}, {human_size(info.esp_size)}")
    if fs == "fat32":
        print(f"access  mdir -i '{rel(out)}@@{info.data_offset}' ::/    (or bb-dev debug-config)")
    else:
        print(f"access  udisksctl loop-setup -f {rel(out)} -o {info.data_offset} -s {info.data_size}"
              "    (or bb-dev debug-config)")
    if config:
        settings = userconfig.UserConfig(config).settings()
        print("config  " + diskimg.USER_CONFIG + ": " + " ".join(f"{k}={v}" for k, v in settings.items()))
    else:
        print(f"config  none (bb-dev debug-config --set bb_debug=1 adds {diskimg.USER_CONFIG})")
    contents = describe_contents(files, sizes, dirs)
    if contents:
        print("files   " + contents[0])
        for line in contents[1:]:
            print("        " + line)
        if args.fixtures:
            print(f"        (fixture ISOs: {FIXTURE_DIR_ON_IMAGE}/<name>.iso, the same paths as in the e2e tests)")
    else:
        print("files   none")
    print(f"log     {rel(log)}")
    print(f"recipe  {rel(recipe)}    (bb-dev vm rebuilds the image from it when its layout is outdated)")
    default = out == paths.DEFAULT_IMAGE.absolute()
    img = "" if default else f" --image {rel(out)}"
    print(f"next    bb-dev vm{img}    (--mode bios|uefi|sb|sb-enrolled|sb-fresh; make vm MODE=...)")
    return 0


def offer_refresh(args, out: Path, env: dict) -> int | None:
    """`out` exists and there is no --force: refresh it, or None to rebuild it (as --force)."""
    v = freshness.check(out)
    if v.action == freshness.CURRENT:
        print(f"image   {rel(out)} is current: {v.reason}")
        note(CMD, "nothing to do; --force rebuilds it with the given options")
        return 0
    if v.action == freshness.UNKNOWN:
        raise Failure(f"{rel(out)} already exists ({v.reason})", "add --force to replace it")
    if v.action == freshness.UPDATE:
        if not (args.yes or confirm(f"bb-dev image: {rel(out)} exists, {v.reason}. Refresh its boot files "
                                    "with `beast-booter update` (its data partition is kept)?")):
            raise Failure(f"{rel(out)} already exists ({v.reason})",
                          "--yes refreshes its boot files, --force rebuilds it (`bb-dev vm` refreshes it too)")
        note(CMD, f"refreshing {rel(out)}: bin/beast-booter update --image {rel(out)} --yes "
                  "(data partition kept; the options given here are not applied)")
        after = freshness.run_update(out, env)
        print(f"image   {rel(out)} updated: {after.reason}")
        return 0
    if not (args.yes or confirm(f"bb-dev image: {rel(out)} exists, {v.reason}, so it must be rebuilt. "
                                "Rebuild it with these options (its data partition is recreated)?")):
        raise Failure(f"{rel(out)} already exists ({v.reason})", "add --force (or --yes) to rebuild it")
    freshness.ensure_modifiable(out)
    return None


def rebuild(out: Path, recipe: dict | None) -> int:
    """`bb-dev image --force` with a recipe's options (the setup defaults without one).
    The caller has looked at dist/ already."""
    parser = argparse.ArgumentParser(prog="bb-dev")
    register(parser.add_subparsers())
    args = parser.parse_args(["image", *freshness.recipe_argv(recipe["options"] if recipe else None, out)])
    args.dist_checked = True
    return _run(args)
