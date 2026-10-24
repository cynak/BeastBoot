"""Firmware pack archives: deterministic "newc" cpio (docs/BEASTNET.md section 6).

A pack is an uncompressed newc archive (the format the Linux kernel unpacks
from an initrd, see the kernel's Documentation/driver-api/early-userspace/
buffer-format.rst) that GRUB passes as an extra initrd after the helper's own:

  * entries `lib/firmware/<path>` for every file, plus every parent directory
    (`lib`, `lib/firmware`, ...), sorted by name (UTF-8 bytes), so a parent
    always comes before its children;
  * directories mode 040755 (nlink 2), files 0100644 (nlink 1); uid, gid,
    mtime, device numbers and the check field 0; inode numbers 1, 2, ... in
    archive order;
  * each header (110 bytes) + name + NUL is padded to a multiple of 4 bytes,
    as is each file's data; the archive ends with the usual "TRAILER!!!" entry
    (nlink 1, everything else 0) and is a multiple of 4 bytes long.

The same file contents always give the same bytes, so `firmware install` can
re-encode what it parsed and compare: anything but the canonical form is
refused.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from .errors import BeastError

MAGIC = b"070701"
HEADER_SIZE = 110
TRAILER = "TRAILER!!!"
FIRMWARE_ROOT = "lib/firmware"
DIR_MODE = 0o040755
FILE_MODE = 0o100644
S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
CHUNK = 1024 * 1024

_FIELDS = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize",
           "devmajor", "devminor", "rdevmajor", "rdevminor", "namesize", "check")


def _pad4(n: int) -> int:
    return -n % 4


def header(name: str, *, ino: int, mode: int, nlink: int, filesize: int) -> bytes:
    """One newc header + NUL-terminated name, padded to 4 bytes."""
    raw = name.encode("utf-8") + b"\0"
    values = (ino, mode, 0, 0, nlink, 0, filesize, 0, 0, 0, 0, len(raw), 0)
    head = MAGIC + b"".join(b"%08X" % v for v in values) + raw
    return head + b"\0" * _pad4(len(head))


def trailer() -> bytes:
    return header(TRAILER, ino=0, mode=0, nlink=1, filesize=0)


def archive_names(paths) -> list[tuple[str, bool]]:
    """(archive name, is_dir) for firmware `paths` (relative to lib/firmware),
    with every parent directory, in archive order."""
    names: dict[str, bool] = {"lib": True, FIRMWARE_ROOT: True}
    for p in paths:
        parts = p.split("/")
        for i in range(1, len(parts)):
            d = f"{FIRMWARE_ROOT}/{'/'.join(parts[:i])}"
            if names.get(d) is False:
                raise BeastError(f"firmware path {d!r} is both a file and a directory in the pack")
            names[d] = True
        full = f"{FIRMWARE_ROOT}/{p}"
        if names.get(full) is True:
            raise BeastError(f"firmware path {full!r} is both a file and a directory in the pack")
        names[full] = False
    return sorted(names.items(), key=lambda item: item[0].encode("utf-8"))


def iter_pack(files: Mapping[str, bytes | str | os.PathLike]) -> Iterator[bytes]:
    """The pack archive for {firmware path: contents or a file to read}, in chunks."""
    for ino, (name, is_dir) in enumerate(archive_names(files), start=1):
        if is_dir:
            yield header(name, ino=ino, mode=DIR_MODE, nlink=2, filesize=0)
            continue
        src = files[name[len(FIRMWARE_ROOT) + 1:]]
        if isinstance(src, (bytes, bytearray, memoryview)):
            size = len(src)
            yield header(name, ino=ino, mode=FILE_MODE, nlink=1, filesize=size)
            yield bytes(src)
        else:
            size = os.path.getsize(src)
            yield header(name, ino=ino, mode=FILE_MODE, nlink=1, filesize=size)
            done = 0
            with open(src, "rb") as f:
                while chunk := f.read(CHUNK):
                    done += len(chunk)
                    yield chunk
            if done != size:
                raise BeastError(f"{src} changed while it was being packed")
        yield b"\0" * _pad4(size)
    yield trailer()


def build_pack(files: Mapping[str, bytes]) -> bytes:
    return b"".join(iter_pack(files))


@dataclass(frozen=True)
class Entry:
    name: str
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    devmajor: int
    devminor: int
    rdevmajor: int
    rdevminor: int
    check: int
    data: bytes

    @property
    def is_dir(self) -> bool:
        return self.mode & S_IFMT == S_IFDIR

    @property
    def is_file(self) -> bool:
        return self.mode & S_IFMT == S_IFREG


def read_newc(data: bytes, where: str = "archive") -> list[Entry]:
    """Every entry of a newc archive up to (not including) its trailer.

    Strict: the "070702" (crc) variant, short or non-hex headers, names
    without their NUL, entries past the end, non-zero padding and anything
    but zero bytes after the trailer are errors."""
    def bad(msg: str) -> BeastError:
        return BeastError(f"{where} is not a valid newc cpio archive: {msg}")

    entries: list[Entry] = []
    pos, end = 0, len(data)
    while True:
        if pos + HEADER_SIZE > end:
            raise bad(f"truncated header at byte {pos} (no {TRAILER} entry)")
        head = data[pos : pos + HEADER_SIZE]
        if head[:6] != MAGIC:
            raise bad(f"bad magic {bytes(head[:6])!r} at byte {pos}")
        values = {}
        for i, field in enumerate(_FIELDS):
            text = head[6 + 8 * i : 14 + 8 * i]
            if any(c not in b"0123456789abcdefABCDEF" for c in text):
                raise bad(f"field {field} is not 8 hex digits at byte {pos}")
            values[field] = int(text, 16)
        namesize = values.pop("namesize")
        filesize = values.pop("filesize")
        if namesize < 2:
            raise bad(f"empty name at byte {pos}")
        name_end = pos + HEADER_SIZE + namesize
        if name_end > end or data[name_end - 1] != 0:
            raise bad(f"name at byte {pos} is truncated or not NUL-terminated")
        raw_name = bytes(data[pos + HEADER_SIZE : name_end - 1])
        if b"\0" in raw_name:
            raise bad(f"name at byte {pos} contains a NUL byte")
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            raise bad(f"name at byte {pos} is not UTF-8") from None
        data_start = name_end + _pad4(HEADER_SIZE + namesize)
        if any(data[name_end:data_start]):
            raise bad(f"non-zero padding after the name {name!r}")
        data_end = data_start + filesize
        if data_end > end:
            raise bad(f"{name!r} is truncated ({filesize} bytes announced)")
        pos = data_end + _pad4(filesize)
        if pos > end or any(data[data_end:pos]):
            raise bad(f"bad padding after the data of {name!r}")
        if name == TRAILER:
            break
        entries.append(Entry(name=name, data=bytes(data[data_start:data_end]), **values))
    if any(data[pos:]):
        raise bad(f"data after the {TRAILER} entry")
    return entries
