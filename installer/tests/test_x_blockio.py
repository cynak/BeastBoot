"""blockio: ImageTarget (sparse image files) and AlignedTarget read-modify-write."""

from __future__ import annotations

import os
import random

import pytest
from conftest import allocated_bytes

from beastbooter.blockio import AlignedTarget, FdTarget, ImageTarget, merge_ranges
from beastbooter.errors import BeastError
from beastbooter.interfaces import BlockTarget

MIB = 1 << 20


# --------------------------------------------------------------------------- ImageTarget


def test_create_is_sparse_and_zero(tmp_path):
    p = tmp_path / "disk.img"
    with ImageTarget.create(str(p), 64 * MIB) as t:
        assert isinstance(t, BlockTarget)
        assert (t.size, t.sector_size, t.sectors) == (64 * MIB, 512, 64 * MIB // 512)
        assert t.read(5 * MIB + 3, 100) == b"\0" * 100
    st = os.stat(p)
    assert st.st_size == 64 * MIB
    assert allocated_bytes(p) < MIB  # nothing allocated


def test_any_offset_roundtrip(tmp_path):
    p = tmp_path / "disk.img"
    with ImageTarget.create(str(p), 4 * MIB) as t:
        t.write(1, b"abc")
        t.write(511, b"XY")  # straddles a sector boundary
        t.write(4 * MIB - 1, b"!")  # last byte
        t.write(1000, b"")  # empty write is fine
        t.flush()
        assert t.read(0, 5) == b"\0abc\0"
        assert t.read(510, 4) == b"\0XY\0"
        assert t.read(4 * MIB - 2, 2) == b"\0!"
    data = p.read_bytes()
    assert data[1:4] == b"abc" and data[511:513] == b"XY" and data[-1:] == b"!"


def test_odd_size_image(tmp_path):
    p = tmp_path / "odd.img"
    with ImageTarget.create(str(p), 300000001) as t:
        assert t.size == 300000001 and t.sectors == 300000001 // 512
        t.write(300000000, b"z")
        assert t.read(299999999, 2) == b"\0z"


def test_bounds_and_read_only(tmp_path):
    p = tmp_path / "disk.img"
    ImageTarget.create(str(p), MIB).close()
    with ImageTarget(str(p), writable=False) as t:
        assert t.size == MIB
        with pytest.raises(BeastError, match="read outside"):
            t.read(MIB - 1, 2)
        with pytest.raises(BeastError, match="read outside"):
            t.read(-1, 1)
        with pytest.raises(AssertionError, match="read-only"):
            t.write(0, b"x")
    with ImageTarget(str(p), writable=True) as t:
        with pytest.raises(BeastError, match="write outside"):
            t.write(MIB - 1, b"xy")
        with pytest.raises(BeastError, match="write outside"):
            t.write(-1, b"x")


def test_restrict_writes(tmp_path):
    p = tmp_path / "disk.img"
    with ImageTarget.create(str(p), MIB) as t:
        t.restrict_writes([(0, 512), (4096, 8192)])
        t.write(0, b"a" * 512)
        t.write(5000, b"b" * 100)
        with pytest.raises(AssertionError, match="outside the allowed areas"):
            t.write(510, b"cc" * 2)  # crosses the end of the first range
        with pytest.raises(AssertionError, match="outside the allowed areas"):
            t.write(9000, b"d")
        t.restrict_writes(None)
        t.write(9000, b"d")


def test_restrict_writes_merges_touching_and_overlapping_ranges(tmp_path):
    p = tmp_path / "disk.img"
    with ImageTarget.create(str(p), MIB) as t:
        t.restrict_writes([(512, 1024), (0, 512), (2048, 2048), (4096, 6000), (5000, 8192)])
        assert t.allowed == [(0, 1024), (4096, 8192)]  # sorted, joined, empty range dropped
        t.write(0, b"x" * 1024)  # spans the two touching ranges
        t.write(4000 + 96, b"y" * 4096)  # spans the two overlapping ones
        with pytest.raises(AssertionError, match="outside the allowed areas"):
            t.write(1000, b"z" * 48)  # runs past 1024
    assert merge_ranges([]) == [] and merge_ranges([(5, 9), (1, 3), (3, 4)]) == [(1, 4), (5, 9)]


def test_image_target_without_pread_like_windows(tmp_path, monkeypatch):
    """Windows Python has no os.pread / os.pwrite: seek + read / write is used instead."""
    monkeypatch.delattr(os, "pread", raising=False)
    monkeypatch.delattr(os, "pwrite", raising=False)
    p = tmp_path / "disk.img"
    with ImageTarget.create(str(p), MIB) as t:
        t.write(MIB - 5, b"tail!")
        t.write(3, b"head")
        assert t.read(0, 8) == b"\0\0\0head\0"
        assert t.read(MIB - 6, 6) == b"\0tail!"
    assert p.read_bytes()[3:7] == b"head"


def test_create_marks_windows_images_sparse_before_extending(tmp_path, monkeypatch):
    from beastbooter import blockio

    sizes = []
    monkeypatch.setattr(blockio, "_make_sparse", lambda fd: sizes.append(os.fstat(fd).st_size))
    p = tmp_path / "disk.img"
    p.write_bytes(b"old")
    ImageTarget.create(str(p), MIB).close()
    assert sizes == [0]  # marked while empty, then extended


def test_make_sparse_calls_fsctl_set_sparse():
    from types import SimpleNamespace

    from beastbooter import blockio

    calls = []

    class Fn:
        def __call__(self, *args):
            calls.append(args)
            return 1

    dll = SimpleNamespace(kernel32=SimpleNamespace(DeviceIoControl=Fn()))
    blockio._make_sparse(7, windll=dll, get_osfhandle=lambda fd: 0x1234 + fd)
    (args,) = calls
    assert args[:6] == (0x123B, 0x000900C4, None, 0, None, 0)
    assert blockio.FSCTL_SET_SPARSE == (0x09 << 16) | (49 << 2)  # CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, ...)
    assert dll.kernel32.DeviceIoControl.restype is not None  # declared before the call
    blockio._make_sparse(7)  # not Windows: nothing to do, no error


def test_set_size_on_windows_sets_end_of_file_without_writing_zeros(tmp_path):
    """Windows' os.ftruncate writes zeros to grow a file (allocating a sparse image):
    blockio sets the end of file with SetFileInformationByHandle(FileEndOfFileInfo)."""
    from types import SimpleNamespace

    from beastbooter import blockio

    calls = []

    def fn(*args):
        calls.append((args[0], args[1], args[2]._obj.value, args[3]))
        return 1

    dll = SimpleNamespace(kernel32=SimpleNamespace(SetFileInformationByHandle=fn))
    blockio._set_size(7, 3 << 40, windll=dll, get_osfhandle=lambda fd: 0x1234 + fd)
    assert calls == [(0x123B, 6, 3 << 40, 8)]
    with open(tmp_path / "f", "wb") as f:  # not Windows: plain ftruncate
        blockio._set_size(f.fileno(), 12345)
    assert (tmp_path / "f").stat().st_size == 12345


def test_create_empties_existing_file(tmp_path):
    p = tmp_path / "disk.img"
    p.write_bytes(b"\xff" * 8192)
    with ImageTarget.create(str(p), 4096) as t:
        assert t.size == 4096
        assert t.read(0, 4096) == b"\0" * 4096


def test_open_errors(tmp_path):
    with pytest.raises(BeastError, match="does not exist"):
        ImageTarget(str(tmp_path / "missing.img"), writable=False)
    with pytest.raises(BeastError, match="not a regular file"):
        ImageTarget(os.devnull, writable=False)  # NUL on Windows: a character device too
    with pytest.raises(BeastError, match="invalid image size"):
        ImageTarget.create(str(tmp_path / "x.img"), 0)
    (tmp_path / "ro.img").write_bytes(b"\0" * 512)
    os.chmod(tmp_path / "ro.img", 0o444)
    if getattr(os, "geteuid", lambda: 1)() != 0:  # root ignores the mode; Windows: read-only attribute
        with pytest.raises(BeastError, match="permission denied"):
            ImageTarget(str(tmp_path / "ro.img"), writable=True)


def test_fd_target_short_read_is_an_error(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 1000)
    with FdTarget(str(p), writable=False, size=2000) as t:  # claims more than the file holds
        with pytest.raises(BeastError, match="unexpected end"):
            t.read(900, 200)


# --------------------------------------------------------------------------- AlignedTarget


class FakeDevice(AlignedTarget):
    """An in-memory 'raw device' that only accepts aligned I/O, like /dev/rdiskN."""

    def __init__(self, size, *, sector_size=512, alignment=None, max_io=1 * MIB, writable=True):
        super().__init__("fake", size=size, sector_size=sector_size, writable=writable,
                         alignment=alignment, max_io=max_io)
        self.data = bytearray(random.Random(size).randbytes(size))
        self.reads: list[tuple[int, int]] = []
        self.writes: list[tuple[int, int]] = []
        self.flushed = 0

    def _check_aligned(self, offset, length):
        a = self.alignment
        assert offset % a == 0 and length % a == 0, (offset, length, a)
        assert 0 < length <= self.max_io
        assert offset + length <= self.size

    def _read_aligned(self, offset, length):
        self._check_aligned(offset, length)
        self.reads.append((offset, length))
        return bytes(self.data[offset:offset + length])

    def _write_aligned(self, offset, data):
        self._check_aligned(offset, len(data))
        self.writes.append((offset, len(data)))
        self.data[offset:offset + len(data)] = data

    def flush(self):
        self.flushed += 1

    def close(self):
        pass


GEOMETRIES = [(512, 512), (4096, 4096), (512, 4096)]  # (sector size, I/O alignment)


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_rmw_single_byte_reads_one_block(sector, align):
    dev = FakeDevice(64 * align, sector_size=sector, alignment=align)
    before = bytes(dev.data)
    dev.write(3 * align + 7, b"Q")
    assert dev.reads == [(3 * align, align)]
    assert dev.writes == [(3 * align, align)]
    expect = bytearray(before)
    expect[3 * align + 7] = ord("Q")
    assert dev.data == expect


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_rmw_reads_only_partial_head_and_tail(sector, align):
    dev = FakeDevice(64 * align, sector_size=sector, alignment=align)
    model = bytearray(dev.data)
    payload = os.urandom(5 * align)
    off = 2 * align + 100  # unaligned start, unaligned end
    dev.write(off, payload)
    model[off:off + len(payload)] = payload
    assert dev.reads == [(2 * align, align), (7 * align, align)]  # first and last block only
    assert dev.writes == [(2 * align, 6 * align)]
    assert dev.data == model


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_aligned_write_needs_no_read(sector, align):
    dev = FakeDevice(64 * align, sector_size=sector, alignment=align)
    dev.write(4 * align, b"\x5a" * (3 * align))
    assert dev.reads == []
    assert dev.writes == [(4 * align, 3 * align)]


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_aligned_head_unaligned_tail(sector, align):
    dev = FakeDevice(16 * align, sector_size=sector, alignment=align)
    model = bytearray(dev.data)
    dev.write(align, b"t" * 10)
    model[align:align + 10] = b"t" * 10
    assert dev.reads == [(align, align)]
    assert dev.data == model


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_chunked_large_unaligned_write(sector, align):
    max_io = 4 * align
    dev = FakeDevice(128 * align, sector_size=sector, alignment=align, max_io=max_io)
    model = bytearray(dev.data)
    payload = os.urandom(23 * align + 333)
    off = 5 * align + 17
    dev.write(off, payload)
    model[off:off + len(payload)] = payload
    assert dev.data == model
    assert all(n <= max_io for _, n in dev.writes)
    assert len(dev.reads) == 2  # still only the partial first and last block
    got = dev.read(off - 3, len(payload) + 6)
    assert got == bytes(model[off - 3:off + len(payload) + 3])
    assert all(n <= max_io for _, n in dev.reads)


@pytest.mark.parametrize("sector,align", GEOMETRIES)
def test_random_io_matches_model(sector, align):
    rng = random.Random(align * 7 + sector)
    size = 32 * align
    dev = FakeDevice(size, sector_size=sector, alignment=align, max_io=8 * align)
    model = bytearray(dev.data)
    for _ in range(300):
        off = rng.randrange(size)
        n = rng.randrange(0, min(size - off, 10 * align) + 1)
        if rng.random() < 0.6:
            payload = rng.randbytes(n)
            dev.write(off, payload)
            model[off:off + n] = payload
        else:
            assert dev.read(off, n) == bytes(model[off:off + n])
    assert dev.data == model


def test_edges_and_errors():
    dev = FakeDevice(8 * 512)
    dev.write(8 * 512 - 1, b"E")  # last byte of the device
    assert dev.read(8 * 512 - 1, 1) == b"E"
    assert dev.read(100, 0) == b""
    dev.write(0, b"")
    with pytest.raises(BeastError, match="write outside"):
        dev.write(8 * 512 - 1, b"EE")
    with pytest.raises(BeastError, match="read outside"):
        dev.read(8 * 512, 1)
    ro = FakeDevice(8 * 512, writable=False)
    with pytest.raises(AssertionError, match="read-only"):
        ro.write(0, b"x")
    with pytest.raises(BeastError, match="not a multiple"):
        FakeDevice(8 * 512 + 512, alignment=4096)
    with pytest.raises(ValueError):
        FakeDevice(8192, sector_size=512, alignment=768)
    with pytest.raises(ValueError):
        FakeDevice(8192, sector_size=1000)


def test_restrict_writes_applies_to_aligned_targets():
    dev = FakeDevice(16 * 512)
    dev.restrict_writes([(0, 512)])
    dev.write(10, b"ok")
    with pytest.raises(AssertionError):
        dev.write(511, b"no")
    assert dev.writes == [(0, 512)]  # the refused write never reached the device
