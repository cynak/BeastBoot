"""beast-boot prepare-windows: copy sources/boot.wim of a Windows ISO to the
data partition so the Secure Boot menu can boot it (docs/WINDOWS_SECURE_BOOT.md).

Layout: <data root>/beast-booter/winboot<iso>/{boot.wim,iso-head.bin,stamp.env}. The stamp is
a GRUB environment block (same bytes as beastnet/grubenv.py writes) and goes
last. Reads the ISO with the pure-Python UDF reader: no mounting, no root.
"""

from __future__ import annotations

import os
import shutil
import sys

from . import __version__
from .errors import BeastError
from .udf import UdfError, open_udf
from .util import Reporter, human_size

HEADROOM = 16 << 20
FAT_LIMIT = 4 << 30
BLOCK = 1024
SIGNATURE = b"# GRUB Environment Block\n"
CHUNK = 4 << 20
HEAD_START, HEAD_END = 32768, 98304


def _escape(value: str) -> bytes:
    out = bytearray()
    for ch in value.encode("utf-8"):
        if ch in (0x5C, 0x0A):
            out.append(0x5C)
        out.append(ch)
    return bytes(out)


def stamp_bytes(items: list[tuple[str, str]]) -> bytes:
    out = bytearray(SIGNATURE)
    for k, v in items:
        out += k.encode() + b"=" + _escape(v) + b"\n"
    if len(out) > BLOCK:
        raise BeastError("the stamp does not fit into a GRUB environment block (path too long?)",
                         code="windows-path")
    return bytes(out) + b"#" * (BLOCK - len(out))


def parse_stamp(data: bytes) -> dict[str, str]:
    if len(data) != BLOCK or not data.startswith(SIGNATURE):
        return {}
    body = data[len(SIGNATURE):].rstrip(b"#")
    out: dict[str, str] = {}
    for line in body.split(b"\n"):
        k, sep, v = line.partition(b"=")
        if sep and not k.startswith(b"#"):
            out.setdefault(k.decode("utf-8", "replace"), v.replace(b"\\\\", b"\\").decode("utf-8", "replace"))
    return out


def find_data_root(iso: str) -> str:
    d = os.path.realpath(os.path.dirname(os.path.abspath(iso)))
    while True:
        if os.path.isdir(os.path.join(d, "beast-booter")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise BeastError("no beast-booter/ folder found above the ISO; is it on the BeastBoot data "
                             "partition? Use --data-root to name the partition's mount point",
                             code="windows-data-root")
        d = parent


def _fs_type(path: str) -> str | None:
    """Filesystem type of the mount holding `path`, where the OS says (Linux)."""
    try:
        best = ("", None)
        with open("/proc/mounts", encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) < 3:
                    continue
                mp = p[1].replace("\\040", " ")
                if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best[0]):
                    best = (mp, p[2])
        return best[1]
    except OSError:
        return None


def _fsync_dir(path: str) -> None:
    if sys.platform == "win32":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def prepare(iso: str, data_root: str | None, force: bool, rep: Reporter) -> dict:
    if not os.path.isfile(iso):
        raise BeastError(f"{iso}: not a file", code="windows-iso")
    root = os.path.realpath(data_root) if data_root else find_data_root(iso)
    if not os.path.isdir(os.path.join(root, "beast-booter")):
        raise BeastError(f"{root}: no beast-booter/ folder; is this the BeastBoot data partition?",
                         code="windows-data-root")
    real = os.path.join(os.path.realpath(os.path.dirname(os.path.abspath(iso))), os.path.basename(iso))
    rel = os.path.relpath(real, root)
    if rel.startswith("..") or os.path.isabs(rel):
        raise BeastError(f"{iso} is not inside the data root {root}", code="windows-data-root")
    iso_path = "/" + rel.replace(os.sep, "/")
    if "\n" in iso_path or "\0" in iso_path:
        raise BeastError("the ISO path contains a newline or NUL", code="windows-path")
    out_dir = os.path.join(root, "beast-booter", "winboot", *iso_path.strip("/").split("/"))
    wim, stamp = os.path.join(out_dir, "boot.wim"), os.path.join(out_dir, "stamp.env")
    rep.start("prepare-windows", iso)

    fstype = _fs_type(root)
    if fstype in ("ntfs", "ntfs3", "ntfs-3g"):
        raise BeastError(f"the data partition is {fstype}; GRUB cannot read it with Secure Boot on. "
                         "Use a FAT32 or exFAT data partition", code="windows-fs")

    rep.step("Reading the ISO", "windows-read", 0)
    with open(iso, "rb") as f:
        head = f.read(HEAD_END)[HEAD_START:]
        if len(head) != HEAD_END - HEAD_START:
            raise BeastError("the ISO is smaller than 98304 bytes; it cannot be identified",
                             code="windows-identity")
        try:
            vol = open_udf(f)
            src = vol.lookup("sources/boot.wim")
            if src is None or src.is_dir:
                raise BeastError("not a Windows ISO: sources/boot.wim not found", code="windows-not-windows")
            kind = "native"
            for n in ("install.wim", "install.esd", "install.swm"):
                if vol.lookup("sources/" + n) is not None:
                    kind = "setup"
                    break
        except UdfError as e:
            raise BeastError(f"cannot read the ISO as UDF: {e}", code="windows-udf") from None
        size = src.size
        rep.note(f"boot.wim {human_size(size)}, kind {kind}")

        headfile = os.path.join(out_dir, "iso-head.bin")
        if not force and os.path.isfile(stamp) and os.path.isfile(wim) and os.path.isfile(headfile):
            try:
                with open(stamp, "rb") as sf:
                    old = parse_stamp(sf.read(BLOCK + 1))
                with open(headfile, "rb") as hf:
                    same_head = hf.read(len(head) + 1) == head
            except OSError:
                old, same_head = {}, False
            if (old.get("bb_wb_iso") == iso_path and same_head
                    and old.get("bb_wb_size") == str(size) and os.path.getsize(wim) == size):
                rep.note("already prepared (use --force to copy again)")
                return {"iso": iso_path, "dir": out_dir, "kind": kind,
                        "size": size, "skipped": True}

        if fstype in ("vfat", "msdos", "fat", "fat32") and size >= FAT_LIMIT:
            raise BeastError(f"boot.wim is {human_size(size)}; FAT32 holds files below 4 GiB. "
                             "Use an exFAT data partition", code="windows-fs")
        os.makedirs(out_dir, exist_ok=True)
        free = shutil.disk_usage(out_dir).free
        old_size = os.path.getsize(wim) if os.path.isfile(wim) else 0
        if size + HEADROOM > free + old_size:
            raise BeastError(f"not enough space on the data partition: need {human_size(size + HEADROOM)}, "
                             f"{human_size(free + old_size)} free", code="no-space")

        _remove(stamp)
        _remove(headfile)
        _remove(wim)
        part = wim + ".part"
        rep.step("Copying boot.wim", "windows-copy", 0)
        done = 0
        try:
            with open(part, "wb") as out:
                for chunk in src.read_chunks(CHUNK):
                    out.write(chunk)
                    done += len(chunk)
                    rep.check_cancel(within=True)
                    rep.progress("windows-copy", f"{human_size(done)} of {human_size(size)}", 100 * done / max(size, 1))
                out.flush()
                os.fsync(out.fileno())
            if done != size:
                raise BeastError("boot.wim copy is incomplete", code="windows-udf")
            os.replace(part, wim)
            hpart = headfile + ".part"
            with open(hpart, "wb") as hf:
                hf.write(head)
                hf.flush()
                os.fsync(hf.fileno())
            os.replace(hpart, headfile)
        except (UdfError, BaseException) as e:
            _remove(part)
            _remove(headfile + ".part")
            if isinstance(e, UdfError):
                raise BeastError(f"cannot read boot.wim from the ISO: {e}", code="windows-udf") from None
            raise

    rep.step("Writing the stamp", "windows-stamp", 100)
    data = stamp_bytes([("bb_wb_iso", iso_path), ("bb_wb_kind", kind), ("bb_wb_size", str(size)), ("bb_wb_by", f"host {__version__}")])
    tmp = stamp + ".tmp"
    with open(tmp, "wb") as sf:
        sf.write(data)
        sf.flush()
        os.fsync(sf.fileno())
    os.replace(tmp, stamp)
    _fsync_dir(out_dir)
    return {"iso": iso_path, "dir": out_dir, "kind": kind, "size": size,
            "skipped": False}
