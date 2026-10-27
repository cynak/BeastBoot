"""Write files below a directory on an untrusted drive without following links.

One implementation, kept byte-identical in the host tool
(installer/beastbooter/safedir.py) and the beast-net helper
(beastnet/python/beastnet/safedir.py); a test in each suite fails if they differ.

POSIX: every path component is opened from the root's descriptor with
O_DIRECTORY | O_NOFOLLOW, and every file operation goes through that descriptor
(dir_fd), so a symlink anywhere below the root is refused, never followed, even
if it appears while we work. New files are created with O_CREAT | O_EXCL |
O_NOFOLLOW. Windows (no dir_fd or O_NOFOLLOW): each component is checked with
lstat for links and reparse points (junctions, mount points) before it is used.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Sequence
from typing import BinaryIO

_CLOEXEC = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
HAVE_DIRFD = bool(_NOFOLLOW and _DIRECTORY) and os.open in os.supports_dir_fd \
    and os.unlink in os.supports_dir_fd and os.stat in os.supports_dir_fd \
    and os.rename in os.supports_dir_fd


class UnsafePath(Exception):
    """A link, reparse point or non-regular file where a plain folder or file belongs."""


def check_name(name: str) -> str:
    """One path component: not empty, '.', '..', and without separators or NUL."""
    if (not name or name in (".", "..") or "/" in name or "\0" in name
            or os.sep in name or (os.altsep and os.altsep in name)):
        raise UnsafePath(f"invalid path component {name!r}")
    return name


def is_link(st: os.stat_result) -> bool:
    """A symlink, or on Windows any reparse point (symlink, junction, mount point)."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


class SafeDir:
    """``root``/``parts...``, reached without following links (made if ``create``).

    ``root`` is trusted (the caller resolved it); ``parts`` are not. Raises
    UnsafePath for a link or non-folder on the way, FileNotFoundError for a
    missing folder when not ``create``.
    """

    def __init__(self, root: str, parts: Sequence[str], create: bool = True) -> None:
        self.root = os.path.realpath(root)
        self.path = self.root
        self.fd: int | None = None
        for p in parts:
            check_name(p)
        if HAVE_DIRFD:
            fd = os.open(self.root, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
            try:
                for p in parts:
                    if create:
                        try:
                            os.mkdir(p, 0o755, dir_fd=fd)
                        except FileExistsError:
                            pass
                    try:
                        nfd = os.open(p, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=fd)
                    except OSError as e:
                        if e.errno in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EMLINK", -1)):
                            raise UnsafePath(f"{os.path.join(self.path, p)} is a link or not a folder; "
                                             "refusing to follow it") from None
                        raise
                    os.close(fd)
                    fd = nfd
                    self.path = os.path.join(self.path, p)
            except BaseException:
                os.close(fd)
                raise
            self.fd = fd
        else:
            for p in parts:
                nxt = os.path.join(self.path, p)
                try:
                    st = os.lstat(nxt)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(nxt)
                    st = os.lstat(nxt)
                if is_link(st) or not stat.S_ISDIR(st.st_mode):
                    raise UnsafePath(f"{nxt} is a link, reparse point or not a folder; refusing to follow it")
                self.path = nxt
        try:
            self._contained()
        except BaseException:
            self.close()
            raise

    def _contained(self) -> None:
        real = os.path.realpath(self.path)
        if os.path.normcase(real) != os.path.normcase(self.path):
            raise UnsafePath(f"{self.path} resolves to {real}; refusing to write there")
        if self.fd is not None and not os.path.samestat(os.fstat(self.fd), os.stat(self.path)):
            raise UnsafePath(f"{self.path} changed while it was opened")

    # -- helpers -------------------------------------------------------------------
    def join(self, name: str) -> str:
        return os.path.join(self.path, check_name(name))

    def lstat(self, name: str) -> os.stat_result | None:
        """lstat of ``name`` in this folder, None if missing."""
        check_name(name)
        try:
            if self.fd is not None:
                return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return os.lstat(self.join(name))
        except FileNotFoundError:
            return None

    def regular_size(self, name: str) -> int:
        """Size of the regular file ``name``, 0 if missing; UnsafePath for anything else."""
        st = self.lstat(name)
        if st is None:
            return 0
        if is_link(st) or not stat.S_ISREG(st.st_mode):
            raise UnsafePath(f"{self.join(name)} is not a regular file; refusing to touch it")
        return st.st_size

    def remove(self, name: str) -> None:
        """Delete the regular file ``name`` (missing is fine); UnsafePath for anything else."""
        self.regular_size(name)
        try:
            if self.fd is not None:
                os.unlink(name, dir_fd=self.fd)
            else:
                os.unlink(self.join(name))
        except FileNotFoundError:
            pass

    def create(self, name: str) -> BinaryIO:
        """A new file ``name`` for writing; fails if anything (also a link) has that name."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
        if self.fd is not None:
            fd = os.open(check_name(name), flags, 0o644, dir_fd=self.fd)
        else:
            fd = os.open(self.join(name), flags, 0o644)
        return os.fdopen(fd, "wb")

    def read(self, name: str, limit: int) -> bytes | None:
        """Up to ``limit`` bytes of the regular file ``name``; None if missing, a link,
        not a regular file (FIFOs are not waited on) or unreadable."""
        flags = os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC
        try:
            if self.fd is not None:
                fd = os.open(check_name(name), flags, dir_fd=self.fd)
            else:
                st = self.lstat(name)
                if st is None or is_link(st) or not stat.S_ISREG(st.st_mode):
                    return None
                fd = os.open(self.join(name), flags)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            out = bytearray()
            while len(out) < limit:
                b = os.read(fd, limit - len(out))
                if not b:
                    break
                out += b
            return bytes(out)
        except OSError:
            return None
        finally:
            os.close(fd)

    def replace(self, src: str, dst: str) -> None:
        """Rename ``src`` over ``dst`` inside this folder (a link named ``dst`` is replaced,
        not followed)."""
        if self.fd is not None:
            # POSIX rename(2) replaces atomically (os.replace has no dir_fd entry in supports_dir_fd)
            os.rename(check_name(src), check_name(dst), src_dir_fd=self.fd, dst_dir_fd=self.fd)
            return
        st = self.lstat(dst)
        if st is not None and (is_link(st) or not stat.S_ISREG(st.st_mode)):
            raise UnsafePath(f"{self.join(dst)} is not a regular file; refusing to replace it")
        os.replace(self.join(src), self.join(dst))

    def fsync(self) -> None:
        if self.fd is not None:
            try:
                os.fsync(self.fd)
            except OSError:
                pass

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> SafeDir:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
