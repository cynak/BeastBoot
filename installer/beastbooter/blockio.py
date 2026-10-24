"""Byte-addressed block targets: disk image files and raw whole-disk devices.

Every disk format writer in this package (partition tables, FAT, exFAT) talks
to a BlockTarget (see interfaces.py): read(offset, length), write(offset, data),
flush(), close(), plus `size` and `sector_size`. This module provides:

  ImageTarget    a disk image file. Created sparse; any offset and length work.
  FdTarget       the same for any POSIX file descriptor path that accepts
                 unaligned I/O, e.g. a Linux block device (/dev/sdb goes through
                 the page cache, which does the read-modify-write for us).
  AlignedTarget  base class for devices that only accept I/O at multiples of the
                 sector size (macOS /dev/rdiskN, Windows \\\\.\\PhysicalDriveN).
                 It turns any read/write into aligned ones, doing
                 read-modify-write of the partial first/last sector.
                 Subclasses implement _read_aligned() and _write_aligned().

All targets check bounds (nothing is ever written past the end), refuse writes
when opened read-only, and can be restricted to a set of byte ranges
(restrict_writes), so an "update" can be made physically unable to touch the
user's data partition.
"""

from __future__ import annotations

import errno
import os
import stat

from .errors import BeastError
from .layout import MIB, SECTOR_SIZE

# Largest single transfer handed to an aligned device (a multiple of any sector size).
MAX_IO = 1 * MIB


def _round_up(n: int, a: int) -> int:
    return -(-n // a) * a


def merge_ranges(ranges) -> list[tuple[int, int]]:
    """[start, end) ranges sorted, with overlapping or touching ones joined; empty ones dropped."""
    out: list[tuple[int, int]] = []
    for a, b in sorted((int(a), int(b)) for a, b in ranges):
        if b <= a:
            continue
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


# os.pread / os.pwrite exist only on Unix. On Windows (image files work there
# too) a seek followed by read / write does the same for one target.
def _pread(fd: int, length: int, offset: int) -> bytes:
    if hasattr(os, "pread"):
        return os.pread(fd, length, offset)
    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, length)


def _pwrite(fd: int, data, offset: int) -> int:
    if hasattr(os, "pwrite"):
        return os.pwrite(fd, data, offset)
    os.lseek(fd, offset, os.SEEK_SET)
    return os.write(fd, data)


class _TargetBase:
    """Bounds checks, write restriction and context-manager support."""

    path: str
    size: int
    sector_size: int
    writable: bool

    def __init__(self, path: str, *, size: int, sector_size: int, writable: bool):
        if sector_size <= 0 or sector_size & (sector_size - 1):
            raise ValueError(f"sector size must be a power of two, not {sector_size}")
        self.path = path
        self.size = size
        self.sector_size = sector_size
        self.writable = writable
        self.allowed: list[tuple[int, int]] | None = None  # [(start, end)) byte ranges

    @property
    def sectors(self) -> int:
        return self.size // self.sector_size

    def restrict_writes(self, ranges: list[tuple[int, int]] | None) -> None:
        """Only allow writes inside these [start, end) byte ranges (None: no restriction).

        Overlapping and touching ranges are merged, so a write may span two
        neighbouring areas (e.g. a partition table followed by the ESP).
        """
        self.allowed = None if ranges is None else merge_ranges(ranges)

    def _check_read(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise BeastError(f"read outside {self.path} (bytes {offset}..{offset + length}, size {self.size})")

    def _check_write(self, offset: int, length: int) -> None:
        if not self.writable:
            raise AssertionError(f"{self.path} was opened read-only")
        end = offset + length
        if offset < 0 or end > self.size:
            raise BeastError(f"write outside {self.path} (bytes {offset}..{end}, size {self.size})")
        if self.allowed is not None and length and not any(a <= offset and end <= b for a, b in self.allowed):
            raise AssertionError(f"refusing write to bytes {offset}..{end} of {self.path}: outside the allowed areas")

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


# ---------------------------------------------------------------------------
# POSIX file descriptor targets (any offset)
# ---------------------------------------------------------------------------


def _open_fd(path: str, writable: bool, *, create: bool = False, device_hint: str = "") -> int:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if create:
        flags |= os.O_CREAT
    try:
        return os.open(path, flags, 0o644)
    except PermissionError:
        raise BeastError(f"permission denied opening {path}{device_hint}") from None
    except FileNotFoundError:
        raise BeastError(f"{path} does not exist") from None
    except OSError as e:
        if e.errno == errno.EBUSY:
            raise BeastError(f"{path} is busy (in use by the system or another program)") from None
        raise BeastError(f"cannot open {path}: {e.strerror}") from None


class FdTarget(_TargetBase):
    """A path opened with os.open, read and written at any offset (pread/pwrite)."""

    def __init__(self, path: str, *, writable: bool, sector_size: int = SECTOR_SIZE,
                 size: int | None = None, _fd: int | None = None, device_hint: str = ""):
        fd = _fd if _fd is not None else _open_fd(path, writable, device_hint=device_hint)
        try:
            real_size = os.lseek(fd, 0, os.SEEK_END)
        except OSError as e:
            os.close(fd)
            raise BeastError(f"cannot determine the size of {path}: {e.strerror}") from None
        self.fd = fd
        super().__init__(path, size=real_size if size is None else size, sector_size=sector_size,
                         writable=writable)

    def read(self, offset: int, length: int) -> bytes:
        self._check_read(offset, length)
        out = bytearray()
        while len(out) < length:
            chunk = _pread(self.fd, length - len(out), offset + len(out))
            if not chunk:
                raise BeastError(f"unexpected end of {self.path} at byte {offset + len(out)}")
            out += chunk
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        self._check_write(offset, len(data))
        view = memoryview(data)
        while view:
            n = _pwrite(self.fd, view, offset)
            if n <= 0:
                raise BeastError(f"short write to {self.path} at byte {offset}")
            view = view[n:]
            offset += n

    def flush(self) -> None:
        if self.writable:
            os.fsync(self.fd)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class ImageTarget(FdTarget):
    """A disk image file (regular file).

    ImageTarget.create(path, size) makes a new sparse image (an existing file is
    emptied first, so every byte reads as zero); ImageTarget(path, writable=...)
    opens an existing one. The image size does not have to be a multiple of the
    sector size (the partition plan rounds down).
    """

    def __init__(self, path: str, *, writable: bool, sector_size: int = SECTOR_SIZE, _fd: int | None = None):
        fd = _fd if _fd is not None else _open_fd(path, writable)
        try:
            mode = os.fstat(fd).st_mode
        except OSError as e:
            os.close(fd)
            raise BeastError(f"cannot stat {path}: {e.strerror}") from None
        if not stat.S_ISREG(mode):
            os.close(fd)
            raise BeastError(f"{path} is not a regular file (use --device for disks)")
        super().__init__(path, writable=writable, sector_size=sector_size, _fd=fd)

    @classmethod
    def create(cls, path: str, size: int, *, sector_size: int = SECTOR_SIZE) -> ImageTarget:
        if size <= 0:
            raise BeastError(f"invalid image size {size}")
        fd = _open_fd(path, True, create=True)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BeastError(f"{path} exists and is not a regular file")
            os.ftruncate(fd, 0)  # drop old contents: the new image reads as all zeros
            _make_sparse(fd)  # Windows only (see there)
            os.ftruncate(fd, size)  # sparse: no blocks allocated until written
        except OSError as e:
            os.close(fd)
            raise BeastError(f"cannot create {path}: {e.strerror}") from None
        except BaseException:
            os.close(fd)
            raise
        return cls(path, writable=True, sector_size=sector_size, _fd=fd)


FSCTL_SET_SPARSE = 0x000900C4  # CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


def _make_sparse(fd: int, *, windll=None, get_osfhandle=None) -> None:
    """Windows: mark a new, empty image file sparse (FSCTL_SET_SPARSE) before it is
    extended. Otherwise NTFS reserves the whole size, and the first write near the end
    (the backup GPT) makes it write zeros over everything before it. POSIX files are
    sparse anyway. Best effort: on FAT/exFAT the call fails and the image just is not sparse."""
    if os.name != "nt" and windll is None:
        return
    import ctypes

    try:
        if get_osfhandle is None:
            import msvcrt

            get_osfhandle = msvcrt.get_osfhandle
        k32 = windll.kernel32 if windll is not None else ctypes.WinDLL("kernel32", use_last_error=True)
        fn = k32.DeviceIoControl
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        returned = ctypes.c_uint32(0)
        fn(get_osfhandle(fd), FSCTL_SET_SPARSE, None, 0, None, 0, ctypes.byref(returned), None)
    except (ImportError, OSError, AttributeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# Aligned devices (read-modify-write)
# ---------------------------------------------------------------------------


class AlignedTarget(_TargetBase):
    """Base for devices that need offset and length to be multiples of `alignment`.

    Subclasses implement:
        _read_aligned(offset, length) -> bytes       offset, length aligned; length <= max_io
        _write_aligned(offset, data) -> None         same rules
        flush(), close()

    write() of an unaligned range reads only the partial first and last
    alignment blocks, merges the new bytes in and writes whole blocks back.
    """

    def __init__(self, path: str, *, size: int, sector_size: int, writable: bool,
                 alignment: int | None = None, max_io: int = MAX_IO):
        super().__init__(path, size=size, sector_size=sector_size, writable=writable)
        self.alignment = alignment or sector_size
        a = self.alignment
        if a & (a - 1) or a % sector_size:
            raise ValueError(f"alignment {a} must be a power-of-two multiple of the sector size {sector_size}")
        if size % a:
            raise BeastError(f"{path}: size {size} is not a multiple of the {a}-byte I/O block")
        if max_io < a or max_io % a:
            raise ValueError(f"max_io {max_io} must be a multiple of the alignment {a}")
        self.max_io = max_io

    # -- to implement -------------------------------------------------------
    def _read_aligned(self, offset: int, length: int) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def _write_aligned(self, offset: int, data: bytes | memoryview) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- BlockTarget ----------------------------------------------------------
    def read(self, offset: int, length: int) -> bytes:
        self._check_read(offset, length)
        if length == 0:
            return b""
        a = self.alignment
        start = offset - offset % a
        end = _round_up(offset + length, a)
        out = bytearray()
        pos = start
        while pos < end:
            n = min(self.max_io, end - pos)
            chunk = self._read_aligned(pos, n)
            if len(chunk) != n:
                raise BeastError(f"short read from {self.path} at byte {pos} ({len(chunk)} of {n})")
            out += chunk
            pos += n
        skip = offset - start
        return bytes(out[skip:skip + length])

    def write(self, offset: int, data: bytes) -> None:
        self._check_write(offset, len(data))
        if not data:
            return
        a = self.alignment
        view = memoryview(data).cast("B")
        end = offset + len(view)
        pos = offset
        while pos < end:
            block_start = pos - pos % a
            chunk_end = min(end, block_start + self.max_io)
            block_end = _round_up(chunk_end, a)
            piece = view[pos - offset:chunk_end - offset]
            if pos == block_start and chunk_end == block_end:
                self._write_aligned(block_start, piece)  # fully aligned: no read needed
            else:
                buf = bytearray(block_end - block_start)
                head_read = False
                if pos != block_start:  # partial first block: keep its leading bytes
                    buf[:a] = self._read_block(block_start)
                    head_read = True
                last_block = block_end - a
                if chunk_end != block_end and not (head_read and last_block == block_start):
                    buf[-a:] = self._read_block(last_block)  # partial last block: keep its tail
                buf[pos - block_start:chunk_end - block_start] = piece
                self._write_aligned(block_start, bytes(buf))
            pos = chunk_end

    def _read_block(self, offset: int) -> bytes:
        block = self._read_aligned(offset, self.alignment)
        if len(block) != self.alignment:
            raise BeastError(f"short read from {self.path} at byte {offset}")
        return block
