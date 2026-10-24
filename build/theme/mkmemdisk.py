#!/usr/bin/env python3
"""beast-booter: build the memdisk embedded in grubx64.efi (called by build/build.sh).

With UEFI Secure Boot on, Ubuntu's GRUB refuses font files from disk (they are
not signed); it loads fonts only from the memdisk inside its own, signed EFI
image, as (memdisk)/fonts/NAME.pf2. So the graphical menu's fonts are put into
a memdisk that grub-mkimage embeds in our grubx64.efi, which our key signs.

    mkmemdisk.py --out memdisk.tar PATH-IN-MEMDISK=FILE ...

The archive is a plain ustar file and a deterministic function of the inputs:
entries sorted by name, directories listed before their contents, mtime 0,
owner 0:0 without names, modes 0755 / 0644. Anyone can rebuild it from the
files in dist/ (manifest build.efi_memdisk) and compare.
"""

from __future__ import annotations

import argparse
import io
import sys
import tarfile


def build(out: str, entries: dict[str, str]) -> None:
    dirs = set()
    for name in entries:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    with tarfile.open(out, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(dirs | set(entries)):
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if name in dirs:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
                continue
            with open(entries[name], "rb") as f:
                data = f.read()
            info.mode = 0o644
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("entry", nargs="+", metavar="PATH-IN-MEMDISK=FILE")
    a = ap.parse_args(argv)
    entries = {}
    for e in a.entry:
        name, sep, src = e.partition("=")
        if not sep or not name or name.startswith("/") or ".." in name.split("/"):
            ap.error(f"bad entry {e!r} (want relative/path=FILE)")
        entries[name] = src
    build(a.out, entries)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
