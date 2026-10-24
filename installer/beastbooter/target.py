"""BlockTarget helpers the commands build on (images and raw devices come from
blockio.ImageTarget and the platform backends).

GuardedTarget  restricts writes to byte ranges, whatever the wrapped target
               is: `update` (boot area + ESP only) can never reach partition 1,
               even through a backend's raw device.
MemoryTarget   a zero-filled in-memory volume that remembers which bytes were
               written (an anonymous mapping: only the pages written to use
               memory, so the 512 MiB ESP costs about what is on it). The ESP is built in one first (so "the boot files do
               not fit" fails before the drive is touched), then copy_written()
               replays exactly those bytes onto the drive.
"""

from __future__ import annotations

import mmap
from collections.abc import Callable

from .blockio import merge_ranges
from .errors import BeastError
from .layout import MIB, SECTOR_SIZE

# Writes copied from a MemoryTarget are widened to this alignment (whole flash
# pages; no read-modify-write on raw devices that need sector-aligned I/O).
COPY_ALIGN = 4096
COPY_CHUNK = 1 * MIB


class GuardedTarget:
    """A BlockTarget that refuses (AssertionError) writes outside `allowed`
    [start, end) byte ranges; None allows everything."""

    def __init__(self, inner, allowed: list[tuple[int, int]] | None = None):
        self.inner = inner
        self.size = inner.size
        self.sector_size = inner.sector_size
        self.path = getattr(inner, "path", "target")
        self.allowed: list[tuple[int, int]] | None = None
        self.restrict_writes(allowed)

    def restrict_writes(self, ranges: list[tuple[int, int]] | None) -> None:
        self.allowed = None if ranges is None else merge_ranges(ranges)

    def read(self, offset: int, length: int) -> bytes:
        return self.inner.read(offset, length)

    def write(self, offset: int, data) -> None:
        end = offset + len(data)
        if self.allowed is not None and len(data) and not any(a <= offset and end <= b for a, b in self.allowed):
            raise AssertionError(f"refusing write to bytes {offset}..{end} of {self.path}: outside the allowed areas")
        self.inner.write(offset, data)

    def flush(self) -> None:
        self.inner.flush()

    def close(self) -> None:
        self.inner.close()

    def __enter__(self) -> GuardedTarget:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MemoryTarget:
    """A zero-filled BlockTarget in memory that records the ranges written to it."""

    def __init__(self, size: int, sector_size: int = SECTOR_SIZE):
        if size <= 0 or size % sector_size:
            raise ValueError(f"memory target size {size} is not a positive multiple of {sector_size}")
        self.size = size
        self.sector_size = sector_size
        self.path = "memory"
        self.buf = mmap.mmap(-1, size)  # zero-filled; pages are allocated when first written
        self._written: list[tuple[int, int]] = []

    def _check(self, offset: int, length: int, what: str) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise BeastError(f"{what} outside the {self.size}-byte volume (bytes {offset}..{offset + length})")

    def read(self, offset: int, length: int) -> bytes:
        self._check(offset, length, "read")
        return bytes(self.buf[offset : offset + length])

    def write(self, offset: int, data) -> None:
        n = len(data)
        self._check(offset, n, "write")
        if n:
            self.buf[offset : offset + n] = data
            self._written.append((offset, offset + n))
            if len(self._written) > 4096:
                self._written = merge_ranges(self._written)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass  # the mapping goes with the object (copy_written may still need it)

    def written_ranges(self, align: int = 1) -> list[tuple[int, int]]:
        """Merged [start, end) ranges that were written, widened to `align` bytes."""
        widened = ((a - a % align, min(self.size, -(-b // align) * align)) for a, b in self._written)
        return merge_ranges(widened)

    def written_bytes(self, align: int = COPY_ALIGN) -> int:
        return sum(b - a for a, b in self.written_ranges(align))


def copy_written(src: MemoryTarget, dst, offset: int, *,
                 on_progress: Callable[[int, int], None] | None = None,
                 flush_every: int | None = None) -> int:
    """Write every range written to `src` onto `dst` at `offset`. Returns bytes copied.

    on_progress(done, total) is called after each chunk; with flush_every, dst
    is flushed after every that many bytes, so progress follows the device and
    not the page cache.
    """
    ranges = src.written_ranges(COPY_ALIGN)
    total = sum(b - a for a, b in ranges)
    done = since_flush = 0
    for a, b in ranges:
        pos = a
        while pos < b:
            n = min(COPY_CHUNK, b - pos)
            dst.write(offset + pos, bytes(src.buf[pos : pos + n]))
            pos += n
            done += n
            since_flush += n
            if flush_every and since_flush >= flush_every:
                dst.flush()
                since_flush = 0
            if on_progress:
                on_progress(done, total)
    return done
