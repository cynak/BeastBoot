"""The ``winboot`` action: copy a Windows ISO's sources/boot.wim to the data partition.

With Secure Boot on, GRUB cannot read UDF, so the menu boots a copy of boot.wim kept
on the (FAT32 or exFAT) data partition. Layout, stamp.env keys and writer rules:
docs/WINDOWS_SECURE_BOOT.md. The pure functions here are tested directly; the
side-effecting part (loop device, mounts) goes through an injectable runner.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from collections.abc import Callable, Iterator, Sequence

from . import __version__, grubenv
from .errors import COPY, GRUBENV, MOUNT, NO_SPACE, WINBOOT, BeastNetError

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


def validate_iso(iso: str | None) -> str:
    """The data-partition path of the ISO: absolute, no '..', no NUL/newline/backslash."""
    if (not iso or not iso.startswith("/") or "\0" in iso or "\n" in iso or "\\" in iso
            or ".." in iso.split("/")):
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


def find_ci(root: str, *parts: str) -> str | None:
    """Walk ``parts`` below ``root`` matching names case-insensitively."""
    cur = root
    for part in parts:
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        hit = next((n for n in sorted(names) if n.lower() == part.lower()), None)
        if hit is None:
            return None
        cur = os.path.join(cur, hit)
    return cur


def find_wim(mount: str) -> tuple[str, str]:
    """(path of sources/boot.wim, kind) in a mounted ISO; BeastNetError if it is not Windows."""
    wim = find_ci(mount, "sources", "boot.wim")
    if wim is None or not os.path.isfile(wim):
        raise BeastNetError(WINBOOT, "this is not a Windows ISO (no sources/boot.wim)",
                            "Only Windows install or Windows PE ISOs can be prepared.")
    src = find_ci(mount, "sources")
    kind = "native"
    if src:
        with contextlib.suppress(OSError):
            if any(n.lower() in INSTALL_NAMES for n in os.listdir(src)):
                kind = "setup"
    return wim, kind


def check_space(size: int, free: int, fstype: str) -> None:
    if fstype == "vfat" and size >= VFAT_LIMIT:
        raise BeastNetError(WINBOOT, f"boot.wim is {size // 1024 ** 2} MiB, over the 4 GiB limit of FAT32",
                            "Format the data partition as exFAT, or turn Secure Boot off.")
    if size + MARGIN > free:
        raise BeastNetError(NO_SPACE, f"not enough free space: {(size + MARGIN) // 1024 ** 2} MiB "
                            f"needed, {free // 1024 ** 2} MiB free",
                            "Free some space on the data partition and try again.")


def read_head(iso_file: str) -> bytes:
    """The ISO's bytes 32768..98303 (its identity), read from the file itself."""
    try:
        with open(iso_file, "rb") as f:
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


def _fsync_dir(path: str) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _unlink(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def write_copy(src: str, data_root: str, iso: str, stamp: bytes, head: bytes = b"",
               progress: Callable[[int, int], None] | None = None,
               cancelled: Callable[[], bool] | None = None) -> bool:
    """Copy ``src`` to the winboot directory of ``iso``, stamp last. False if cancelled.

    Order: delete stamp.env, iso-head.bin, boot.wim; write boot.wim.part (fsync), rename;
    iso-head.bin.part (fsync), rename; write stamp.env.tmp (fsync), rename, fsync the directory.
    """
    base = os.path.join(data_root, WINBOOT_DIR.lstrip("/"))
    d = dest_dir(data_root, iso)
    if os.path.commonpath([base, d]) != base or d == base:
        raise BeastNetError(WINBOOT, "refusing to write outside the winboot folder")
    total = os.path.getsize(src)
    try:
        os.makedirs(d, exist_ok=True)
        _unlink(os.path.join(d, STAMP))
        _unlink(os.path.join(d, HEAD))
        _unlink(os.path.join(d, WIM))
        part = os.path.join(d, WIM + ".part")
        done = 0
        with open(src, "rb") as fi, open(part, "wb") as fo:
            while True:
                if cancelled and cancelled():
                    break
                buf = fi.read(CHUNK)
                if not buf:
                    break
                fo.write(buf)
                done += len(buf)
                if progress:
                    progress(done, total)
            else:
                pass
            if done == total:
                fo.flush()
                os.fsync(fo.fileno())
        if done != total:
            _unlink(part)
            return False
        os.rename(part, os.path.join(d, WIM))
        hpart = os.path.join(d, HEAD + ".part")
        with open(hpart, "wb") as f:
            f.write(head)
            f.flush()
            os.fsync(f.fileno())
        os.rename(hpart, os.path.join(d, HEAD))
        tmp = os.path.join(d, STAMP + ".tmp")
        with open(tmp, "wb") as f:
            f.write(stamp)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, os.path.join(d, STAMP))
        _fsync_dir(d)
        return True
    except OSError as e:
        for n in (WIM + ".part", HEAD + ".part", STAMP + ".tmp"):
            _unlink(os.path.join(d, n))
        code = NO_SPACE if e.errno == 28 else COPY
        raise BeastNetError(code, f"copying boot.wim failed: {e.strerror or e}",
                            "The data partition may be full or damaged.") from None


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
@contextlib.contextmanager
def mounted_iso(runner, iso_file: str, mnt: str) -> Iterator[str]:
    """Attach ``iso_file`` read-only and mount it (udf, else iso9660); always undone."""
    dev = ""
    mounted = False
    try:
        cp = runner.run(["losetup", "-r", "-f", "--show", iso_file], timeout=30)
        dev = (cp.stdout or "").strip()
        if cp.returncode != 0 or not dev.startswith("/dev/"):
            raise BeastNetError(MOUNT, "could not attach the ISO", (cp.stderr or "").strip())
        os.makedirs(mnt, exist_ok=True)
        for fs in ("udf", "iso9660"):
            cp = runner.run(["mount", "-t", fs, "-o", "ro", dev, mnt], timeout=60)
            if cp.returncode == 0:
                mounted = True
                break
        if not mounted:
            raise BeastNetError(MOUNT, "could not open the ISO as a disc image",
                                "The file may be damaged or not an ISO.")
        yield mnt
    finally:
        if mounted:
            runner.run(["umount", mnt], timeout=60)
        if dev:
            runner.run(["losetup", "-d", dev], timeout=30)


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
        self.mnt = os.path.join(paths.run, "winiso")
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
        local = iso_local(data, iso)
        if not os.path.isfile(local) or os.path.islink(local):
            raise BeastNetError(WINBOOT, f"{iso} is not a file on the data partition")
        read_head(local)
        fstype = data_fstype(self.runner, data)
        check_fs(fstype)
        with mounted_iso(self.runner, local, self.mnt) as m:
            wim, kind = find_wim(m)
            size = os.path.getsize(wim)
        st = os.statvfs(data)
        free = st.f_bavail * st.f_frsize
        old = os.path.join(dest_dir(data, iso), WIM)
        if os.path.isfile(old):
            free += os.path.getsize(old)  # replaced by the new copy
        check_space(size, free, fstype)
        return WinPlan(iso, fstype, size, kind, free)

    def run(self, plan: WinPlan, progress: Callable[[int, int], None] | None = None,
            cancelled: Callable[[], bool] | None = None) -> WinResult:
        data = self.paths.data
        with mounted_iso(self.runner, iso_local(data, plan.iso), self.mnt) as m:
            wim, kind = find_wim(m)
            size = os.path.getsize(wim)
            stamp = stamp_bytes(plan.iso, kind, size)
            head = read_head(iso_local(data, plan.iso))
            ok = write_copy(wim, data, plan.iso, stamp, head, progress, cancelled)
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


__all__: Sequence[str] = ("WinBoot", "WinPlan", "WinResult", "validate_iso", "find_wim", "check_space",
                          "stamp_bytes", "write_copy", "cleanup_stale", "mounted_iso")
