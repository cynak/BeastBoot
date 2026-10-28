"""The ``winboot`` action: copy a Windows ISO's sources/boot.wim to the data partition.

With Secure Boot on, GRUB cannot read UDF, so the menu boots a copy of boot.wim kept
on the (FAT32 or exFAT) data partition. Layout, stamp.env keys and writer rules:
docs/WINDOWS_SECURE_BOOT.md. The ISO is read in userspace with the UDF reader the
host tool uses (udf.py, vendored byte-identical): no loop device, no kernel
udf/iso9660 mount, so links inside the ISO mean nothing and a crafted image only
meets bounds-checked Python. Writes go through safedir.SafeDir (no links followed).
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
from dataclasses import dataclass
from collections.abc import Callable, Iterable, Sequence
from typing import BinaryIO

from . import __version__, grubenv
from .errors import COPY, GRUBENV, NO_SPACE, WINBOOT, BeastNetError
from .safedir import SafeDir, UnsafePath
from .udf import UdfError, UdfFile, open_udf

WINBOOT_DIR = "/beast-booter/winboot"
WIM = "boot.wim"
STAMP = "stamp.env"
MARGIN = 16 * 1024 * 1024
VFAT_LIMIT = 4 * 1024 ** 3  # boot.wim must be smaller than this on FAT32
CHUNK = 4 * 1024 * 1024
OK_FS = ("vfat", "exfat", "msdos")
KEYS = ("bb_wb_iso",)
HEAD = "iso-head.bin"
HEAD_START, HEAD_END = 32768, 98304
INSTALL_NAMES = ("install.wim", "install.esd", "install.swm")
_BAD = re.compile(r'[\x00-\x1f\x7f"\\\ufffd]')  # controls, quote, backslash, undecodable (non-UTF-8) bytes


def validate_iso(iso: str | None) -> str:
    """The data-partition path of the ISO: absolute, no '..', no control characters,
    double quote, backslash or non-UTF-8 bytes (grubenv decodes those to U+FFFD)."""
    if not iso or not iso.startswith("/") or _BAD.search(iso) or ".." in iso.split("/"):
        raise BeastNetError(WINBOOT, f"the ISO path {iso!r} is not valid",
                            "Pick the ISO again in the menu.")
    parts = [p for p in iso.split("/") if p not in ("", ".")]
    if not parts:
        raise BeastNetError(WINBOOT, "the ISO path is empty")
    return "/" + "/".join(parts)


def iso_local(data_root: str, iso: str) -> str:
    return os.path.join(data_root, iso.lstrip("/"))


def dest_dir(data_root: str, iso: str) -> str:
    return os.path.join(data_root, WINBOOT_DIR.lstrip("/"), iso.lstrip("/"))


def check_fs(fstype: str) -> None:
    if fstype not in OK_FS:
        raise BeastNetError(WINBOOT, f"the data partition is {fstype or 'of an unknown type'}, "
                            "not FAT32 or exFAT",
                            "With Secure Boot on, the menu can only read FAT32 or exFAT. "
                            "Windows ISOs cannot be prepared on this drive; turn Secure Boot "
                            "off or use a drive with a FAT32 or exFAT data partition.")


def _iso_error(e: Exception) -> BeastNetError:
    return BeastNetError(WINBOOT, f"cannot read the ISO: {e}",
                         "The file may be damaged or not a Windows ISO.")


def inspect_iso(f: BinaryIO) -> tuple[UdfFile, str]:
    """(sources/boot.wim, kind) of an open ISO, read as UDF in userspace; BeastNetError if
    it is not a Windows ISO."""
    try:
        vol = open_udf(f)
        wim = vol.lookup("sources/boot.wim")
        if wim is None or wim.is_dir:
            raise BeastNetError(WINBOOT, "this is not a Windows ISO (no sources/boot.wim)",
                                "Only Windows install or Windows PE ISOs can be prepared.")
        kind = "setup" if any(vol.lookup("sources/" + n) is not None for n in INSTALL_NAMES) else "native"
    except UdfError as e:
        raise _iso_error(e) from None
    return wim, kind


def check_space(size: int, free: int, fstype: str) -> None:
    if fstype == "vfat" and size >= VFAT_LIMIT:
        raise BeastNetError(WINBOOT, f"boot.wim is {size // 1024 ** 2} MiB, over the 4 GiB limit of FAT32",
                            "Format the data partition as exFAT, or turn Secure Boot off.")
    if size + MARGIN > free:
        raise BeastNetError(NO_SPACE, f"not enough free space: {(size + MARGIN) // 1024 ** 2} MiB "
                            f"needed, {free // 1024 ** 2} MiB free",
                            "Free some space on the data partition and try again.")


def open_iso(data_root: str, iso: str) -> BinaryIO:
    """The ISO for reading: a regular file whose real path is inside ``data_root``."""
    local = iso_local(data_root, iso)
    root = os.path.realpath(data_root)
    real = os.path.realpath(local)
    if os.path.islink(local) or os.path.commonpath([root, real]) != root or real == root:
        raise BeastNetError(WINBOOT, f"{iso} is not a file on the data partition")
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise BeastNetError(WINBOOT, f"{iso} is not a file on the data partition") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise BeastNetError(WINBOOT, f"{iso} is not a file on the data partition")
    return os.fdopen(fd, "rb")


def read_head(f: BinaryIO) -> bytes:
    """The ISO's bytes 32768..98303 (its identity), read from the file itself."""
    try:
        f.seek(HEAD_START)
        data = f.read(HEAD_END - HEAD_START)
    except OSError as e:
        raise BeastNetError(WINBOOT, f"cannot read the ISO: {e.strerror}") from None
    if len(data) != HEAD_END - HEAD_START:
        raise BeastNetError(WINBOOT, f"the ISO is smaller than {HEAD_END} bytes",
                            "This is not a usable disc image.")
    return data


def stamp_bytes(iso: str, kind: str, size: int, by: str | None = None) -> bytes:
    env = grubenv.GrubEnv()
    for k, v in (("bb_wb_iso", iso),
                 ("bb_wb_kind", kind), ("bb_wb_size", str(size)),
                 ("bb_wb_by", by or f"helper {__version__}")):
        env.set(k, v)
    data = env.to_bytes()
    assert len(data) == grubenv.SIZE
    return data


def winboot_parts(iso: str) -> list[str]:
    return [*WINBOOT_DIR.strip("/").split("/"), *iso.strip("/").split("/")]


def write_copy(chunks: Iterable[bytes], total: int, data_root: str, iso: str, stamp: bytes,
               head: bytes = b"", progress: Callable[[int, int], None] | None = None,
               cancelled: Callable[[], bool] | None = None) -> bool:
    """Write ``chunks`` (``total`` bytes) as boot.wim of ``iso``, stamp last. False if cancelled.

    Order: delete stamp.env, iso-head.bin, boot.wim; write boot.wim.part (fsync), rename;
    iso-head.bin.part (fsync), rename; write stamp.env.tmp (fsync), rename, fsync the
    directory. Every folder is reached and every file created without following links
    (safedir); a link or non-regular file in the way stops the copy.
    """
    iso = validate_iso(iso)
    sd = None
    try:
        sd = SafeDir(data_root, winboot_parts(iso))
        for n in (STAMP, HEAD, WIM, WIM + ".part", HEAD + ".part", STAMP + ".tmp"):
            sd.remove(n)
        done = 0
        with sd.create(WIM + ".part") as fo:
            for buf in chunks:
                if cancelled and cancelled():
                    break
                fo.write(buf)
                done += len(buf)
                if progress:
                    progress(done, total)
            if done == total and not (cancelled and cancelled()):
                fo.flush()
                os.fsync(fo.fileno())
        if done != total or (cancelled and cancelled()):
            sd.remove(WIM + ".part")
            return False
        sd.replace(WIM + ".part", WIM)
        for name, tmp, data in ((HEAD, HEAD + ".part", head), (STAMP, STAMP + ".tmp", stamp)):
            with sd.create(tmp) as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            sd.replace(tmp, name)
        sd.fsync()
        return True
    except (OSError, UnsafePath, UdfError) as e:
        if sd is not None:
            for n in (WIM + ".part", HEAD + ".part", STAMP + ".tmp"):
                with contextlib.suppress(OSError, UnsafePath):
                    sd.remove(n)
        if isinstance(e, UnsafePath):
            raise BeastNetError(WINBOOT, f"refusing to write: {e}",
                                "The drive's winboot folder holds a link or a special file; "
                                "nothing was written there.") from None
        if isinstance(e, UdfError):
            raise _iso_error(e) from None
        code = NO_SPACE if e.errno == 28 else COPY
        raise BeastNetError(code, f"copying boot.wim failed: {e.strerror or e}",
                            "The data partition may be full or damaged.") from None
    finally:
        if sd is not None:
            sd.close()


def _unlink(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def cleanup_stale(data_root: str, keep: str | None = None) -> list[str]:
    """Remove winboot directories whose ISO is gone. Only below /beast-booter/winboot/,
    only directories holding a readable stamp.env whose bb_wb_iso maps to that very
    directory, and only our own file names. Returns the removed directories."""
    base = os.path.join(data_root, WINBOOT_DIR.lstrip("/"))
    removed: list[str] = []
    if os.path.islink(base) or not os.path.isdir(base):
        return removed
    for cur, dirs, files in os.walk(base, topdown=True, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(cur, d))]
        if STAMP not in files or cur == base:
            continue
        stamp = os.path.join(cur, STAMP)
        if os.path.islink(stamp):
            continue
        try:
            iso = validate_iso(grubenv.load(stamp).get("bb_wb_iso"))
        except (BeastNetError, OSError):
            continue
        if dest_dir(data_root, iso) != cur or iso == keep or os.path.isfile(iso_local(data_root, iso)):
            continue
        _unlink(stamp)  # first: the copy stops counting
        for n in (HEAD, HEAD + ".part", WIM, WIM + ".part", STAMP + ".tmp"):
            _unlink(os.path.join(cur, n))
        removed.append(cur)
    for cur in sorted(removed, key=len, reverse=True):  # empty parents up to winboot/
        p = cur
        while p != base and p.startswith(base + os.sep):
            try:
                os.rmdir(p)
            except OSError:
                break
            p = os.path.dirname(p)
    return removed


# -- the side-effecting part -------------------------------------------------------------
def data_fstype(runner, data_root: str) -> str:
    cp = runner.run(["findmnt", "-n", "-o", "FSTYPE", "--target", data_root], timeout=10)
    return (cp.stdout or "").strip().splitlines()[0] if cp.returncode == 0 and cp.stdout.strip() else ""


@dataclass
class WinPlan:
    iso: str
    fstype: str
    size: int
    kind: str
    free: int

    @property
    def needed(self) -> int:
        return self.size + MARGIN


@dataclass
class WinResult:
    ok: bool
    removed: list[str]


class WinBoot:
    def __init__(self, paths, runner, *, esp_env: str | None = None) -> None:
        self.paths = paths
        self.runner = runner
        self.env_path = esp_env or paths.grubenv

    def read_inputs(self) -> str:
        env = grubenv.load(self.env_path)
        val = env.get("bb_wb_iso")
        if val is None:
            raise BeastNetError(GRUBENV, "the menu did not say which ISO to prepare",
                                "Choose the Windows ISO in the menu and pick "
                                "'Prepare this Windows ISO for Secure Boot' again.")
        return validate_iso(val)

    def plan(self) -> WinPlan:
        iso = self.read_inputs()
        data = self.paths.data
        fstype = data_fstype(self.runner, data)
        check_fs(fstype)  # before anything on the data partition is looked at
        with open_iso(data, iso) as f:
            read_head(f)
            wim, kind = inspect_iso(f)
            size = wim.size
        st = os.statvfs(data)
        free = st.f_bavail * st.f_frsize
        try:
            with SafeDir(data, winboot_parts(iso), create=False) as sd:
                free += sd.regular_size(WIM) + sd.regular_size(WIM + ".part")  # replaced by the new copy
        except FileNotFoundError:
            pass
        except UnsafePath as e:
            raise BeastNetError(WINBOOT, f"refusing to write: {e}") from None
        check_space(size, free, fstype)
        return WinPlan(iso, fstype, size, kind, free)

    def run(self, plan: WinPlan, progress: Callable[[int, int], None] | None = None,
            cancelled: Callable[[], bool] | None = None) -> WinResult:
        data = self.paths.data
        check_fs(data_fstype(self.runner, data))
        with open_iso(data, plan.iso) as f:
            head = read_head(f)
            wim, kind = inspect_iso(f)
            stamp = stamp_bytes(plan.iso, kind, wim.size)
            ok = write_copy(wim.read_chunks(CHUNK), wim.size, data, plan.iso, stamp, head,
                            progress, cancelled)
        if not ok:
            return WinResult(False, [])
        removed = cleanup_stale(data, keep=plan.iso)
        return WinResult(True, removed)

    def finish(self) -> None:
        """Success: unset the inputs and point the menu's one-shot at the ISO."""
        iso = self.read_inputs()
        env = grubenv.load(self.env_path)
        for k in KEYS:
            env.unset(k)
        env.set(grubenv.ONESHOT_KEY, iso)
        grubenv.save(self.env_path, env)

    def clear_inputs(self) -> None:
        """Unset bb_wb_iso (every exit: error, cancel, back), so a stale request is never
        acted on again. Best effort; writes only if the key is there."""
        with contextlib.suppress(BeastNetError, OSError):
            env = grubenv.load(self.env_path)
            if any(env.get(k) is not None for k in KEYS):
                for k in KEYS:
                    env.unset(k)
                grubenv.save(self.env_path, env)


__all__: Sequence[str] = ("WinBoot", "WinPlan", "WinResult", "validate_iso", "inspect_iso", "open_iso",
                          "check_space", "stamp_bytes", "write_copy", "cleanup_stale")
