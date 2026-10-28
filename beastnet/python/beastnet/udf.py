"""Read-only UDF reader (ECMA-167 / UDF 1.02 - 2.50) (the ISO identity is just the first 64 KiB of volume descriptors; see winboot.py).

Just enough to find and stream a file out of a Microsoft Windows ISO (a UDF
"bridge" image) without mounting it: anchor volume descriptor at sector 256,
partition and logical volume descriptors, file set descriptor, file entries
(tag 261) and extended file entries (266), short/long allocation descriptors
(and continuation extents), inline data, case-insensitive path lookup.

The image is untrusted: every offset and length is bounds-checked against the
image size and counts (extents, directory entries, recursion, descriptor
sequences) are capped. Anything unexpected raises UdfError. Not supported:
virtual (VAT) and metadata partitions, strategy 4096 ICBs, multiple volumes.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import BinaryIO

SECTOR = 2048
MAX_EXTENTS = 1 << 16
MAX_DIR_BYTES = 64 << 20
MAX_DIR_DEPTH = 32
MAX_VDS_DESCRIPTORS = 256
MAX_AED_CHAIN = 64


class UdfError(Exception):
    """The image is not (a supported) UDF image, or is damaged."""


def _tag(buf: bytes, want: int | None = None) -> int:
    """Validate a descriptor tag (checksum) and return its identifier."""
    if len(buf) < 16:
        raise UdfError("truncated descriptor")
    ident = struct.unpack_from("<H", buf, 0)[0]
    if (sum(buf[:4]) + sum(buf[5:16])) & 0xFF != buf[4]:
        raise UdfError("descriptor tag checksum mismatch")
    if want is not None and ident != want:
        raise UdfError(f"unexpected descriptor {ident} (wanted {want})")
    return ident


def _dstring(raw: bytes) -> str:
    if not raw:
        return ""
    comp, body = raw[0], raw[1:]
    if comp == 8:
        return body.decode("latin-1")
    if comp == 16:
        return body[: len(body) & ~1].decode("utf-16-be", "replace")
    raise UdfError("bad name compression id")


class _Extent:
    __slots__ = ("pos", "length", "zero")

    def __init__(self, pos: int, length: int, zero: bool) -> None:
        self.pos, self.length, self.zero = pos, length, zero


class UdfFile:
    """A file inside the image: .size, .is_dir, streaming read()."""

    def __init__(self, vol: UdfVolume, is_dir: bool, size: int,
                 extents: list[_Extent] | None, inline: bytes | None) -> None:
        self.vol, self.is_dir, self.size = vol, is_dir, size
        self._extents, self._inline = extents or [], inline

    def read_chunks(self, chunk: int = 1 << 20) -> Iterator[bytes]:
        if self._inline is not None:
            yield self._inline[: self.size]
            return
        left = self.size
        for ex in self._extents:
            n = min(ex.length, left)
            off = 0
            while off < n:
                m = min(n - off, chunk)
                yield bytes(m) if ex.zero else self.vol._pread(ex.pos + off, m)
                off += m
            left -= n
            if left <= 0:
                return
        if left > 0:
            raise UdfError("file data is shorter than its size")

    def read_all(self, limit: int = MAX_DIR_BYTES) -> bytes:
        if self.size > limit:
            raise UdfError("object too large")
        return b"".join(self.read_chunks())


class UdfVolume:
    def __init__(self, f: BinaryIO) -> None:
        self.f = f
        f.seek(0, 2)
        self.size = f.tell()
        self._parts: dict[int, tuple[int, int]] = {}  # number -> (start byte, length bytes)
        self._maps: list[int] = []  # partition reference -> partition number
        self.bs = SECTOR
        self._open()

    def _pread(self, pos: int, n: int) -> bytes:
        if pos < 0 or n < 0 or pos + n > self.size:
            raise UdfError("read outside the image")
        self.f.seek(pos)
        b = self.f.read(n)
        if len(b) != n:
            raise UdfError("short read")
        return b

    def _sector(self, n: int) -> bytes:
        return self._pread(n * SECTOR, SECTOR)

    # -- volume structures ---------------------------------------------
    def _open(self) -> None:
        if self.size < 257 * SECTOR:
            raise UdfError("too small to be a UDF image")
        avdp = self._sector(256)
        _tag(avdp, 2)
        extents = [struct.unpack_from("<II", avdp, 16), struct.unpack_from("<II", avdp, 24)]
        last: Exception | None = None
        for length, loc in extents:
            try:
                self._read_vds(length, loc)
                break
            except UdfError as e:
                last = e
                self._parts, self._maps = {}, []
        else:
            raise last or UdfError("no volume descriptor sequence")
        self._open_fsd()

    def _read_vds(self, length: int, loc: int) -> None:
        count = min(length // SECTOR, MAX_VDS_DESCRIPTORS)
        if count == 0:
            raise UdfError("empty volume descriptor sequence")
        pds: dict[int, tuple[int, int, int]] = {}  # number -> (seq, start sector, len sectors)
        lvd: tuple[int, bytes] | None = None
        for i in range(count):
            sec = self._sector(loc + i)
            try:
                ident = _tag(sec)
            except UdfError:
                continue
            if ident == 8:  # terminating descriptor
                break
            seq = struct.unpack_from("<I", sec, 16)[0]
            if ident == 5:
                num, start, plen = struct.unpack_from("<H", sec, 22)[0], *struct.unpack_from("<II", sec, 188)
                if num not in pds or seq >= pds[num][0]:
                    pds[num] = (seq, start, plen)
            elif ident == 6:
                if lvd is None or seq >= lvd[0]:
                    lvd = (seq, sec)
        if lvd is None or not pds:
            raise UdfError("no logical volume / partition descriptor")
        sec = lvd[1]
        self.bs = struct.unpack_from("<I", sec, 212)[0]
        if self.bs != SECTOR:
            raise UdfError(f"unsupported logical block size {self.bs}")
        self._fsd_loc = struct.unpack_from("<IH", sec, 248 + 4)  # (lbn, partition reference)
        self._fsd_len = struct.unpack_from("<I", sec, 248)[0]
        mt_len, nmaps = struct.unpack_from("<II", sec, 264)
        if nmaps == 0 or nmaps > 16 or 440 + mt_len > SECTOR:
            raise UdfError("bad partition maps")
        p = 440
        for _ in range(nmaps):
            if p + 2 > 440 + mt_len:
                raise UdfError("bad partition map table")
            mtype, mlen = sec[p], sec[p + 1]
            if mlen < 2 or p + mlen > 440 + mt_len:
                raise UdfError("bad partition map")
            if mtype == 1 and mlen >= 6:
                num = struct.unpack_from("<H", sec, p + 4)[0]
            elif mtype == 2 and mlen >= 40:
                ident = sec[p + 5:p + 28]
                if b"Sparable" not in ident:  # virtual / metadata partitions
                    raise UdfError("unsupported partition map (" + ident.strip(b"\0").decode("latin-1") + ")")
                num = struct.unpack_from("<H", sec, p + 38)[0]
            else:
                raise UdfError("unsupported partition map type")
            self._maps.append(num)
            p += mlen
        for num, (_s, start, plen) in pds.items():
            if start * SECTOR > self.size:
                raise UdfError("partition starts outside the image")
            self._parts[num] = (start * SECTOR, plen * SECTOR)

    def _block(self, ref: int, lbn: int) -> int:
        if ref >= len(self._maps) or self._maps[ref] not in self._parts:
            raise UdfError("bad partition reference")
        start, plen = self._parts[self._maps[ref]]
        pos = lbn * SECTOR
        if plen and pos >= plen:
            raise UdfError("block outside its partition")
        return start + pos

    def _open_fsd(self) -> None:
        lbn, ref = self._fsd_loc
        fsd = self._pread(self._block(ref, lbn), SECTOR)
        _tag(fsd, 256)
        rlen, rlbn, rref = struct.unpack_from("<IIH", fsd, 400)
        self._root = (rref, rlbn)

    # -- file entries ----------------------------------------------------
    def _entry(self, ref: int, lbn: int) -> UdfFile:
        buf = self._pread(self._block(ref, lbn), SECTOR)
        ident = _tag(buf)
        if ident not in (261, 266):
            raise UdfError("not a file entry")
        strategy = struct.unpack_from("<H", buf, 20)[0]
        if strategy != 4:
            raise UdfError(f"unsupported ICB strategy {strategy}")
        ftype = buf[27]
        flags = struct.unpack_from("<H", buf, 34)[0]
        info = struct.unpack_from("<Q", buf, 56)[0]
        if ident == 261:
            lea, lad = struct.unpack_from("<II", buf, 168)
            base = 176
        else:
            lea, lad = struct.unpack_from("<II", buf, 208)
            base = 216
        if lea > SECTOR or lad > SECTOR or base + lea + lad > SECTOR:
            raise UdfError("bad file entry lengths")
        ads = buf[base + lea: base + lea + lad]
        kind = flags & 7
        is_dir = ftype == 4
        if kind == 3:
            if info > len(ads):
                raise UdfError("bad inline data size")
            return UdfFile(self, is_dir, info, None, ads)
        if kind not in (0, 1):
            raise UdfError("unsupported allocation descriptor type")
        return UdfFile(self, is_dir, info, self._extents(ads, kind, ref, info), None)

    def _extents(self, ads: bytes, kind: int, ref: int, info: int) -> list[_Extent]:
        size = 8 if kind == 0 else 16
        out: list[_Extent] = []
        total = 0
        chain = 0
        while True:
            nxt: tuple[int, int, int] | None = None
            for p in range(0, len(ads) - size + 1, size):
                raw = struct.unpack_from("<I", ads, p)[0]
                etype, elen = raw >> 30, raw & 0x3FFFFFFF
                lbn = struct.unpack_from("<I", ads, p + 4)[0]
                eref = ref if kind == 0 else struct.unpack_from("<H", ads, p + 8)[0]
                if etype == 3:
                    nxt = (eref, lbn, elen)
                    break
                if elen == 0:
                    break
                if len(out) >= MAX_EXTENTS:
                    raise UdfError("too many extents")
                if etype == 0:
                    pos = self._block(eref, lbn)
                    if pos + elen > self.size:
                        raise UdfError("extent outside the image")
                    out.append(_Extent(pos, elen, False))
                else:
                    out.append(_Extent(0, elen, True))
                total += elen
                if total >= info:
                    return out
            if nxt is None:
                return out
            chain += 1
            if chain > MAX_AED_CHAIN or nxt[2] < 24 or nxt[2] > (1 << 20):
                raise UdfError("bad allocation extent chain")
            aed = self._pread(self._block(nxt[0], nxt[1]), min(nxt[2], SECTOR))
            _tag(aed, 258)
            n = struct.unpack_from("<I", aed, 20)[0]
            if n > len(aed) - 24:
                raise UdfError("bad allocation extent descriptor")
            ads = aed[24:24 + n]
            ref = nxt[0]

    def _list(self, d: UdfFile) -> Iterator[tuple[str, bool, int, int]]:
        data = d.read_all()
        p, n = 0, 0
        while p + 38 <= len(data):
            n += 1
            if n > 1_000_000:
                raise UdfError("directory too large")
            try:
                ident = _tag(data[p:p + 16])
            except UdfError:
                break
            if ident != 257:
                break
            chars, lfi = data[p + 18], data[p + 19]
            lbn, ref = struct.unpack_from("<I", data, p + 24)[0], struct.unpack_from("<H", data, p + 28)[0]
            liu = struct.unpack_from("<H", data, p + 36)[0]
            end = p + 38 + liu + lfi
            if end > len(data):
                raise UdfError("directory entry runs past the directory")
            if not chars & 0x0C:  # skip deleted and parent entries
                yield _dstring(data[p + 38 + liu:end]), bool(chars & 2), ref, lbn
            p = (end + 3) & ~3

    def lookup(self, path: str) -> UdfFile | None:
        """Find a file or directory by '/'-separated path, case-insensitively."""
        cur = self._entry(*self._root)
        parts = [x for x in path.split("/") if x]
        if len(parts) > MAX_DIR_DEPTH:
            raise UdfError("path too deep")
        for part in parts:
            if not cur.is_dir:
                return None
            want = part.casefold()
            for name, _isdir, ref, lbn in self._list(cur):
                if name.casefold() == want:
                    cur = self._entry(ref, lbn)
                    break
            else:
                return None
        return cur


def open_udf(f: BinaryIO) -> UdfVolume:
    return UdfVolume(f)
