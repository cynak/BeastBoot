"""bb-dev debug-config: edit /beast-booter/config.cfg on an image's data partition.

  bb-dev debug-config                              show it (same as --show)
  bb-dev debug-config --set bb_debug=1 bb_serial=1 --show
  bb-dev debug-config --unset bb_autoboot
  bb-dev debug-config --clear                      remove the file
  bb-dev debug-config --set bb_debug=1 --print     content for a real USB stick

FAT32 data partitions are edited with mtools, exFAT and NTFS through a udisks
loop mount. --print writes nothing: it prints the file for you to copy to
/beast-booter/config.cfg on a real stick (bb-dev never writes real devices).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import diskimg, paths, userconfig
from ..msg import Failure, note, rel, run_guarded, warn

CMD = "debug-config"


def _known_help() -> str:
    lines = ["known settings (docs/MENU.md):"]
    for k, (_kind, text) in userconfig.KNOWN.items():
        lines.append(f"  {k:<12} {text}")
    lines.append("Other names are written as given and passed to GRUB unchanged.")
    return "\n".join(lines)


def register(sub) -> None:
    p = sub.add_parser("debug-config", help="toggle menu debug settings on an image",
                       description="Show or edit /beast-booter/config.cfg on the image's data partition.",
                       epilog=_known_help(), formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--image", type=Path, metavar="PATH", help=f"drive image (default: {rel(paths.DEFAULT_IMAGE)})")
    p.add_argument("--show", action="store_true", help="print the settings and the file (after any change)")
    p.add_argument("--set", nargs="+", action="extend", default=[], metavar="KEY=VALUE", help="set settings")
    p.add_argument("--unset", nargs="+", action="extend", default=[], metavar="KEY", help="remove settings")
    p.add_argument("--clear", action="store_true", help="start from an empty file (alone: delete the file)")
    p.add_argument("--print", action="store_true",
                   help="print the resulting file instead of writing it (for a real USB stick)")
    p.set_defaults(func=run)


def apply(cfg: userconfig.UserConfig, args) -> list[str]:
    """Apply --clear/--unset/--set; returns warnings."""
    warnings = []
    pairs = [userconfig.parse_assignment(a) for a in args.set]
    for k in args.unset:
        if not k or "=" in k:
            raise Failure(f"--unset takes a setting name, not {k!r}")
    if args.clear:
        cfg.clear()
    for k in args.unset:
        cfg.unset(k)
    for k, v in pairs:
        if k not in userconfig.KNOWN:
            warnings.append(f"{k} is not a beast-boot setting; GRUB gets it as is")
        cfg.set(k, v)
    return warnings


def show(text: str | None, where: str) -> None:
    print(f"{diskimg.USER_CONFIG} on {where}")
    if not text:
        print("  (no config.cfg: the menu uses its defaults)")
        return
    settings = userconfig.UserConfig(text).settings()
    if settings:
        width = max(len(k) for k in settings)
        for k, v in settings.items():
            desc = userconfig.KNOWN.get(k, ("", "(passed to GRUB)"))[1]
            print(f"  {k:<{width}} = {v:<10} {desc}")
    else:
        print("  (no settings)")
    print("--- file ---")
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def run(args) -> int:
    return run_guarded(CMD, _run, args)


def _run(args) -> int:
    changes = bool(args.set or args.unset or args.clear)

    if args.print:
        base = ""
        if args.image:
            info = diskimg.image_info(args.image)
            with diskimg.data_access(info, readonly=True) as d:
                base = (d.read(diskimg.USER_CONFIG) or b"").decode(errors="replace")
        cfg = userconfig.UserConfig(base)
        for w in apply(cfg, args):
            warn(CMD, w)
        if not cfg.lines:
            cfg.lines = [userconfig.HEADER]
        sys.stdout.write(cfg.text)
        note(CMD, f"copy this to {diskimg.USER_CONFIG} on the stick's data partition (partition 1, "
                  "the one with your ISOs); bb-dev does not write real devices")
        return 0

    image = Path(args.image or paths.DEFAULT_IMAGE).absolute()
    info = diskimg.image_info(image)
    where = f"{rel(image)} (data partition: {info.data_fs}, offset {info.data_offset})"
    if changes and diskimg.running_vm(image):
        warn(CMD, "a VM is running on this image: the menu reads config.cfg at boot, so reboot it "
                  "(monitor: system_reset) to see the change")
    with diskimg.data_access(info, readonly=not changes) as d:
        old = (d.read(diskimg.USER_CONFIG) or b"").decode(errors="replace")
        if changes:
            cfg = userconfig.UserConfig(old)
            for w in apply(cfg, args):
                warn(CMD, w)
            if cfg.is_empty():
                if d.remove(diskimg.USER_CONFIG):
                    print(f"removed {diskimg.USER_CONFIG} from {rel(image)}")
                else:
                    print(f"no {diskimg.USER_CONFIG} on {rel(image)}; nothing to remove")
            elif cfg.text != old:
                d.write(diskimg.USER_CONFIG, cfg.text.encode())
                print(f"wrote {diskimg.USER_CONFIG} on {rel(image)}: "
                      + " ".join(f"{k}={v}" for k, v in cfg.settings().items()))
            else:
                print(f"{diskimg.USER_CONFIG} on {rel(image)} already has these settings")
        if args.show or not changes:
            now = d.read(diskimg.USER_CONFIG)  # read back from the image
            show(now.decode(errors="replace") if now is not None else None, where)
    return 0
