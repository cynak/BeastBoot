"""beast-boot prepare-windows: copy sources/boot.wim of a Windows ISO to the
data partition so the Secure Boot menu can boot it (docs/WINDOWS_SECURE_BOOT.md).

Layout: <data root>/beast-booter/winboot<iso>/{boot.wim,iso-head.bin,stamp.env}. The stamp is
a GRUB environment block (same bytes as beastnet/grubenv.py writes) and goes
last. Reads the ISO with the pure-Python UDF reader: no mounting, no root.
The drive is untrusted: writes go through safedir.SafeDir (no links followed),
and only a FAT32/exFAT data partition's mount point is accepted as the data root.
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys

from . import __version__
from .errors import BeastError
from .safedir import SafeDir, UnsafePath, check_name, is_link
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


# -- where the data partition is and what it is ----------------------------------------
MARKER = "beast-booter"  # folder at the root of a BeastBoot data partition (menu, helper, user config)
OK_FS = ("fat", "exfat")  # GRUB reads only these with Secure Boot on
_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f"]')


def is_mount(path: str) -> bool:
    return os.path.ismount(path)


def check_iso_path(iso_path: str) -> str:
    """The ISO's data-partition path must be UTF-8 and free of control characters and
    double quotes (GRUB's menu and stamp.env carry it); each component a plain name."""
    try:
        iso_path.encode("utf-8")
    except UnicodeEncodeError:
        raise BeastError(f"{ascii(iso_path)}: the file or folder name is not valid UTF-8; "
                         "rename it", code="windows-path") from None
    if _BAD_CHARS.search(iso_path):
        raise BeastError(f"{ascii(iso_path)}: the path contains a control character or a double "
                         "quote; rename it", code="windows-path")
    try:
        for p in iso_path.strip("/").split("/"):
            check_name(p)
    except UnsafePath as e:
        raise BeastError(str(e), code="windows-path") from None
    return iso_path


def find_data_root(iso: str) -> str:
    """The mount point of the filesystem holding ``iso``, if it has beast-booter/ at its
    root. Never looks above that mount point (a beast-booter/ folder elsewhere, e.g. a
    source checkout, is not a drive)."""
    d = os.path.realpath(os.path.dirname(os.path.abspath(iso)))
    while not is_mount(d):
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    try:
        st = os.lstat(os.path.join(d, MARKER))
        ok = stat.S_ISDIR(st.st_mode) and not is_link(st)
    except OSError:
        ok = False
    if not ok:
        raise BeastError(f"{d} (the partition holding the ISO) has no {MARKER}/ folder at its root; "
                         "is it the BeastBoot data partition? If it is, name its mount point with "
                         f"--data-root {d}", code="windows-data-root")
    return d


def _unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def _probe_dev_fs(dev: str) -> str | None:
    """Filesystem on a block device as udev/blkid see it (no root needed for lsblk)."""
    if not dev.startswith("/dev/"):
        return None
    for argv in (["lsblk", "-dno", "FSTYPE", dev], ["blkid", "-o", "value", "-s", "TYPE", dev]):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        v = r.stdout.strip()
        if r.returncode == 0 and v:
            return v
    return None


def _linux_fs(path: str, mounts: str = "/proc/mounts") -> str | None:
    best: tuple[str, str, str] | None = None
    try:
        with open(mounts, encoding="utf-8", errors="surrogateescape") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    for line in lines:
        p = line.split()
        if len(p) < 3:
            continue
        mp = _unescape_mount(p[1])
        if (path == mp or path.startswith(mp.rstrip("/") + "/")) and (best is None or len(mp) >= len(best[0])):
            best = (mp, _unescape_mount(p[0]), p[2])
    if best is None:
        return None
    _, dev, t = best
    if t in ("vfat", "msdos"):
        return "fat"
    if t == "exfat":
        return "exfat"
    if t == "fuseblk" or t.startswith("fuse."):  # exfat-fuse, or NTFS-3G: ask the device
        probed = _probe_dev_fs(dev)
        return "exfat" if probed == "exfat" else f"{t} ({probed or 'unknown'})"
    return t


def _darwin_fs(path: str) -> str | None:
    name = None
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        try:
            fn = libc["statfs$INODE64"]  # x86_64: the 64-bit-inode struct statfs
        except AttributeError:
            fn = libc["statfs"]  # arm64 has only that one
        fn.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        fn.restype = ctypes.c_int
        buf = ctypes.create_string_buffer(4096)
        if fn(os.fsencode(path), buf) == 0:
            # struct statfs: 4+4 + 5*8 + 8 (fsid) + 4*4 = 72, then char f_fstypename[16]
            name = buf.raw[72:88].split(b"\0")[0].decode("ascii", "replace") or None
    except (OSError, AttributeError, ValueError):
        name = None
    if not name:
        try:
            r = subprocess.run(["diskutil", "info", "-plist", path], capture_output=True, timeout=20, check=False)
            name = plistlib.loads(r.stdout).get("FilesystemType") if r.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError, plistlib.InvalidFileException):
            name = None
    return {"msdos": "fat", "exfat": "exfat"}.get(name or "", name)


def _windows_fs(path: str) -> str | None:
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        vol = ctypes.create_unicode_buffer(300)
        if not k32.GetVolumePathNameW(ctypes.c_wchar_p(path), vol, 300):
            return None
        name = ctypes.create_unicode_buffer(300)
        if not k32.GetVolumeInformationW(vol, None, 0, None, None, None, name, 300):
            return None
        v = name.value
    except (OSError, AttributeError):
        return None
    return {"FAT32": "fat", "FAT": "fat", "exFAT": "exfat"}.get(v, v or None)


def fs_type(path: str) -> str | None:
    """'fat', 'exfat', another filesystem name, or None when the OS does not say."""
    if sys.platform.startswith("linux"):
        return _linux_fs(path)
    if sys.platform == "darwin":
        return _darwin_fs(path)
    if sys.platform == "win32":
        return _windows_fs(path)
    return None


# -- the copy --------------------------------------------------------------------------
WIM, HEAD, STAMP = "boot.wim", "iso-head.bin", "stamp.env"


def _unsafe(e: UnsafePath) -> BeastError:
    return BeastError(f"{e}. The drive's contents look tampered with; nothing was written there",
                      code="windows-unsafe")


def _open_iso(path: str):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise BeastError(f"{path}: cannot open the ISO: {e.strerror}", code="windows-iso") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise BeastError(f"{path}: not a regular file", code="windows-iso")
    return os.fdopen(fd, "rb")


def _already(root: str, parts: list[str], iso_path: str, head: bytes, size: int) -> bool:
    try:
        with SafeDir(root, parts, create=False) as sd:
            old = parse_stamp(sd.read(STAMP, BLOCK + 1) or b"")
            same_head = sd.read(HEAD, len(head) + 1) == head
            st = sd.lstat(WIM)
            wim_ok = st is not None and stat.S_ISREG(st.st_mode) and st.st_size == size
    except FileNotFoundError:
        return False
    return old.get("bb_wb_iso") == iso_path and same_head and old.get("bb_wb_size") == str(size) and wim_ok


def _write(sd: SafeDir, name: str, chunks, size: int, rep: Reporter | None = None) -> None:
    """name.part (O_EXCL, fsync), renamed to name."""
    part = name + ".part"
    sd.remove(part)
    done = 0
    try:
        with sd.create(part) as out:
            for chunk in chunks:
                out.write(chunk)
                done += len(chunk)
                if rep is not None:
                    rep.check_cancel(within=True)
                    rep.progress("windows-copy", f"{human_size(done)} of {human_size(size)}", 100 * done / max(size, 1))
            out.flush()
            os.fsync(out.fileno())
        if done != size:
            raise BeastError(f"{name} copy is incomplete", code="windows-udf")
        sd.replace(part, name)
    except BaseException:
        try:
            sd.remove(part)
        except (OSError, UnsafePath):
            pass
        raise


def prepare(iso: str, data_root: str | None, force: bool, rep: Reporter, *, staging: bool = False) -> dict:
    """Copy the Windows ISO's boot.wim for Secure Boot (docs/WINDOWS_SECURE_BOOT.md).
    staging=True: data_root is a folder a drive image is built from (the real-ISO test
    harness), not a mounted drive, so the mount-point and FAT32/exFAT checks are skipped;
    everything else, the link-safe writing included, is the same. Never set from the
    command line."""
    if os.path.islink(iso):
        raise BeastError(f"{iso} is a link; give the ISO file itself", code="windows-iso")
    real = os.path.realpath(iso)
    try:
        st = os.stat(real)
    except OSError:
        st = None
    if st is None or not stat.S_ISREG(st.st_mode):
        raise BeastError(f"{iso}: not a file", code="windows-iso")
    if data_root:
        root = os.path.realpath(data_root)
        if not staging and not is_mount(root):
            raise BeastError(f"{root} is not a mount point; --data-root must be where the BeastBoot "
                             "data partition is mounted", code="windows-data-root")
    elif staging:
        raise BeastError("staging needs the data root", code="windows-data-root")
    else:
        root = find_data_root(iso)
    try:
        rel = os.path.relpath(real, root)
    except ValueError:  # another drive (Windows)
        rel = os.pardir
    if rel in (os.curdir, os.pardir) or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
        raise BeastError(f"{ascii(iso)} is not inside the data root {ascii(root)}", code="windows-data-root")
    iso_path = check_iso_path("/" + rel.replace(os.sep, "/"))
    parts = [MARKER, "winboot", *iso_path.strip("/").split("/")]
    out_dir = os.path.join(root, *parts)

    fstype = None if staging else fs_type(root)
    if not staging and fstype not in OK_FS:
        raise BeastError(f"the data partition {root} is {fstype or 'of a type this system does not report'}; "
                         "only FAT32 or exFAT can be prepared (with Secure Boot on, GRUB reads only those)",
                         code="windows-fs")
    rep.start("prepare-windows", iso)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        rep.warn("running as root is not needed (the data partition only has to be writable); "
                 "the drive's contents are not trusted")

    rep.step("Reading the ISO", "windows-read", 0)
    with _open_iso(real) as f:
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

        try:
            if not force and _already(root, parts, iso_path, head, size):
                rep.note("already prepared (use --force to copy again)")
                return {"iso": iso_path, "dir": out_dir, "kind": kind,
                        "size": size, "skipped": True}
            if fstype == "fat" and size >= FAT_LIMIT:
                raise BeastError(f"boot.wim is {human_size(size)}; FAT32 holds files below 4 GiB. "
                                 "Use an exFAT data partition", code="windows-fs")
            with SafeDir(root, parts) as sd:
                free = shutil.disk_usage(sd.path).free
                old = sd.regular_size(WIM) + sd.regular_size(WIM + ".part") + sd.regular_size(HEAD + ".part")
                if size + HEADROOM > free + old:
                    raise BeastError(f"not enough space on the data partition: need {human_size(size + HEADROOM)}, "
                                     f"{human_size(free + old)} free", code="no-space")
                for n in (STAMP, HEAD, WIM, STAMP + ".tmp"):
                    sd.remove(n)
                rep.step("Copying boot.wim", "windows-copy", 0)
                try:
                    _write(sd, WIM, src.read_chunks(CHUNK), size, rep)
                except UdfError as e:
                    raise BeastError(f"cannot read boot.wim from the ISO: {e}", code="windows-udf") from None
                _write(sd, HEAD, [head], len(head))
                rep.step("Writing the stamp", "windows-stamp", 100)
                data = stamp_bytes([("bb_wb_iso", iso_path), ("bb_wb_kind", kind), ("bb_wb_size", str(size)),
                                    ("bb_wb_by", f"host {__version__}")])
                tmp = STAMP + ".tmp"
                try:
                    with sd.create(tmp) as sf:
                        sf.write(data)
                        sf.flush()
                        os.fsync(sf.fileno())
                    sd.replace(tmp, STAMP)
                except BaseException:
                    sd.remove(tmp)
                    raise
                sd.fsync()
        except UnsafePath as e:
            raise _unsafe(e) from None
    return {"iso": iso_path, "dir": out_dir, "kind": kind, "size": size,
            "skipped": False}
