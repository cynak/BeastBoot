"""bb-dev menu-sync: push grub/ into an image's ESP for the edit -> reboot loop.

Copies the menu files (same selection as build/build.sh) into /grub/ on the
image's ESP with mtools, at the ESP offset from `beast-boot info --json`.
The ESP then mirrors grub/: changed files are rewritten, new ones added, and
menu files that are no longer in grub/ removed. Never touched: version.cfg,
device.cfg, grubenv and everything else the build puts under /grub/ from other
sources (dist/manifest.json: the theme from build/theme, fonts, i386-pc/).
BB_MENU_DIR overrides the source directory, as for build.sh.

The image no longer matches dist/manifest.json afterwards: `make build` and
`bb-dev image --force` (or `bin/beast-boot update --image ...`) restore it.

An image whose boot files are older than dist/ (another build id, or an older
layout such as the 64 MiB FAT16 ESP of layout 1) is refused with the command
that fixes it, so menu edits are never tested on an outdated bootloader.
"""

from __future__ import annotations

import os
import signal
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import diskimg, freshness, menufiles, paths
from ..msg import Failure, error, note, rel, run_guarded, warn

CMD = "menu-sync"


def register(sub) -> None:
    p = sub.add_parser("menu-sync", help="push edited grub/ files into an image's ESP",
                       description="Copy grub/ (menu scripts) into the image's ESP /grub/, so a reboot of "
                                   "the VM shows the change without `make build` and a reinstall.")
    p.add_argument("--image", type=Path, metavar="PATH", help=f"drive image (default: {rel(paths.DEFAULT_IMAGE)})")
    p.add_argument("--watch", action="store_true", help="keep running and re-sync whenever grub/ changes")
    p.add_argument("--interval", type=float, default=1.0, metavar="SECONDS",
                   help="--watch poll interval (default: 1)")
    p.set_defaults(func=run)


@dataclass
class SyncResult:
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: int = 0
    differs_from_dist: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.removed)


def esp_menu_state(esp: diskimg.Fat, built: set[str] | frozenset = frozenset()) -> tuple[set[str], set[str]]:
    """(files, dirs) under the ESP's /grub/, relative, excluding protected ones
    and those in `built` (build output from outside grub/)."""
    files, dirs = set(), set()
    for entry in esp.listing("/grub", recursive=True):
        if not entry.startswith("/grub/"):
            continue
        r = entry[len("/grub/"):]
        if r.endswith("/"):
            dirs.add(r.rstrip("/"))
        elif not menufiles.protected(r) and not menufiles.skipped(r) and r not in built:
            files.add(r)
    return files, dirs


def sync(info: diskimg.ImageInfo, src: Path) -> SyncResult:
    wanted = menufiles.menu_files(src)  # raises on symlinks / forbidden files
    esp = info.esp()
    if not esp.exists("/" + diskimg.ESP_MARKER):
        raise Failure(f"{rel(info.path)}: the ESP has no {diskimg.ESP_MARKER}; not a beast-boot drive?")
    manifest = menufiles.load_manifest()
    built = menufiles.manifest_built(manifest) - set(wanted)
    on_esp, esp_dirs = esp_menu_state(esp, built)
    res = SyncResult()
    paths.OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bbdev-sync-", dir=paths.OUT) as tmp:
        tops = sorted({r.split("/", 1)[0] for r in on_esp})
        esp.copy_out([f"/grub/{t}" for t in tops], Path(tmp))
        put: dict[str, list[Path]] = {}
        for r, path in wanted.items():
            data = path.read_bytes()
            current = Path(tmp) / r
            old = current.read_bytes() if r in on_esp and current.is_file() else None
            if old == data:
                res.unchanged += 1
                continue
            (res.updated if old is not None else res.added).append(r)
            put.setdefault(r.rsplit("/", 1)[0] if "/" in r else "", []).append(path)
    for d, srcs in sorted(put.items()):
        esp.put_files("/grub" + (f"/{d}" if d else ""), srcs)
    for r in sorted(on_esp - set(wanted)):
        esp.delete(f"/grub/{r}")
        res.removed.append(r)
    if res.removed:
        remaining = (on_esp - set(res.removed)) | set(wanted)
        for d in sorted(esp_dirs, key=lambda x: -x.count("/")):
            if (menufiles.protected(d + "/x") or any(f.startswith(d + "/") for f in remaining)
                    or any(b.startswith(d + "/") for b in built)):
                continue
            if any(r.startswith(d + "/") for r in res.removed):
                esp.rmdir(f"/grub/{d}")
    shipped = menufiles.manifest_menu(manifest)
    for r, path in wanted.items():
        if shipped.get(r) != menufiles.sha256(path.read_bytes()):
            res.differs_from_dist.append(r)
    res.differs_from_dist += [r for r in shipped if r not in wanted]
    return res


def report(res: SyncResult, info: diskimg.ImageInfo, src: Path, stamp: bool = False) -> None:
    prefix = time.strftime("[%H:%M:%S] ") if stamp else ""
    label = rel(src) if src != paths.GRUB_SRC else "grub"
    if not res.changed:
        print(f"{prefix}up to date: {res.unchanged} menu files in {rel(info.path)} match {label}/", flush=True)
        return
    print(f"{prefix}{rel(info.path)} ESP /grub/ <- {label}/", flush=True)
    for kind, items in (("updated", res.updated), ("added", res.added), ("removed", res.removed)):
        for r in items:
            print(f"  {kind:<8} /grub/{r}", flush=True)
    if res.unchanged:
        print(f"  ({res.unchanged} unchanged)", flush=True)
    pid = diskimg.running_vm(info.path)
    if pid:
        note(CMD, f"a VM is running on this image (pid {pid}): reboot it to load the change "
                  f"(monitor: system_reset)")


def warn_dist(res: SyncResult) -> None:
    if res.differs_from_dist:
        n = len(res.differs_from_dist)
        warn(CMD, f"the image's menu no longer matches dist/manifest.json ({n} file{'s' if n != 1 else ''}); "
                  "`make build` + `bb-dev image --force` (or `bin/beast-boot update`) restores a shipped state")


def check_fresh(info: diskimg.ImageInfo) -> None:
    """Refuse an image with older boot files than dist/ (other build or older layout)."""
    img = info.path
    v = freshness.check(img, info)
    opt = "" if Path(img).absolute() == paths.DEFAULT_IMAGE.absolute() else f" --image {rel(img)}"
    if v.action == freshness.UPDATE:
        raise Failure(f"{rel(img)} has older boot files than dist/ ({v.reason}); grub/ edits would be tested "
                      "on an outdated bootloader",
                      f"refresh it first: `bin/beast-boot update --image {rel(img)} --yes` "
                      f"(`bin/bb-dev vm{opt}` does that too), then menu-sync again")
    if v.action == freshness.REBUILD:
        raise Failure(f"{rel(img)} must be rebuilt ({v.reason}); grub/ edits would be tested on an outdated "
                      "bootloader", f"`{freshness.rebuild_command(img)}` (or `bin/bb-dev vm{opt} --yes`, which "
                      "rebuilds it from its recipe), then menu-sync again")
    if v.action == freshness.UNKNOWN:
        warn(CMD, f"cannot tell whether {rel(img)} has the boot files of dist/: {v.reason}")


def signature(src: Path) -> tuple:
    sig = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for f in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            p = os.path.join(dirpath, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            sig.append((p, st.st_mtime_ns, st.st_size, st.st_mode))
    return tuple(sig)


def run(args) -> int:
    return run_guarded(CMD, _run, args)


def _run(args) -> int:
    image = Path(args.image or paths.DEFAULT_IMAGE).absolute()
    src = menufiles.menu_dir()
    info = diskimg.image_info(image)
    check_fresh(info)
    if not args.watch:
        res = sync(info, src)
        report(res, info, src)
        warn_dist(res)
        return 0

    if args.interval <= 0:
        raise Failure("--interval must be greater than 0")
    stop = {"flag": False}

    def _stop(*_):
        stop["flag"] = True

    old = {s: signal.signal(s, _stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        note(CMD, f"watching {rel(src)}/ every {args.interval:g}s -> {rel(image)} (Ctrl-C stops)")
        sig = signature(src)
        warned = False
        try:
            res = sync(info, src)
            report(res, info, src, stamp=True)
            warn_dist(res)
            warned = bool(res.differs_from_dist)
        except Failure as e:
            error(CMD, str(e), e.hint)
        while not stop["flag"]:
            time.sleep(args.interval)
            if stop["flag"]:
                break
            new = signature(src)
            if new == sig:
                continue
            time.sleep(min(0.2, args.interval))  # let the editor finish writing
            settled = signature(src)
            if settled != new:
                continue
            sig = settled
            try:
                res = sync(info, src)
            except Failure as e:
                error(CMD, str(e), e.hint)
                continue
            report(res, info, src, stamp=True)
            if res.differs_from_dist and not warned:
                warn_dist(res)
            warned = bool(res.differs_from_dist)
    finally:
        for s, h in old.items():
            signal.signal(s, h)
    note(CMD, "stopped")
    return 0
