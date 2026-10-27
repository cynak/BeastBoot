"""Filesystem walkers for the generic RAID reconstruction (raidmath.py).

A walker reads a logical volume through one reconstruction hypothesis and counts
the on-disk structures that check out (magic numbers, self-references, checksums,
parent/child links). A right hypothesis passes almost every check; a wrong chunk
size, member order, layout or data offset makes the walker read the wrong bytes
and checks fail. Read-only and pure Python: ``read(offset, length) -> bytes`` is
the only way in, and it may raise SlotUnknown (the hypothesis has not placed the
member this read needs yet) or BudgetExceeded; both stop the walk.

Understood: GPT, MBR, ext2/3/4 (incl. metadata_csum/gdt_csum checksums), NTFS
(boot sector, MFT records with fixups and record numbers, directory INDX
blocks), XFS (AG headers, v5 self-describing btree blocks and inodes), btrfs
(superblock copies), LVM2 (label, first LV at pe_start), and the signatures of
LUKS, BitLocker, FAT/exFAT and ReFS (one check each: their contents cannot be
walked).
"""

from __future__ import annotations

import binascii
import functools
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

KiB = 1024
MiB = 1024 * KiB


class SlotUnknown(Exception):
    """A read needs an array slot whose member the hypothesis has not placed yet."""

    def __init__(self, slot: int) -> None:
        super().__init__(slot)
        self.slot = slot


class BudgetExceeded(Exception):
    """The per-member read budget is spent."""


class WalkDone(Exception):
    """The walk reached its check limit."""


# -- checksums (pure Python; results memoised because walks are replayed) ----------------

def _crc_table(poly: int) -> tuple[int, ...]:
    out = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        out.append(c)
    return tuple(out)


_T32C = _crc_table(0x82F63B78)
_T16 = _crc_table(0xA001)


@functools.lru_cache(maxsize=4096)
def crc32c_raw(crc: int, data: bytes) -> int:
    """CRC32C update without the pre/post inversion (what ext4 stores)."""
    t = _T32C
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def crc32c(data: bytes) -> int:
    """Standard CRC32C (iSCSI, btrfs)."""
    return crc32c_raw(0xFFFFFFFF, bytes(data)) ^ 0xFFFFFFFF


@functools.lru_cache(maxsize=4096)
def crc16(crc: int, data: bytes) -> int:
    """Linux lib/crc16 (poly 0x8005 reflected, no inversion): ext4 gdt_csum."""
    t = _T16
    for b in data:
        crc = (crc >> 8) ^ t[(crc ^ b) & 0xFF]
    return crc


def is_zero_bytes(b: bytes) -> bool:
    return b.count(0) == len(b)


def _popcount(b: bytes, nbits: int) -> int:
    x = int.from_bytes(b[:(nbits + 7) // 8], "little") & ((1 << nbits) - 1)
    return bin(x).count("1")


def le(b: bytes, o: int, n: int) -> int:
    return int.from_bytes(b[o:o + n], "little")


def be(b: bytes, o: int, n: int) -> int:
    return int.from_bytes(b[o:o + n], "big")


# -- the walk ----------------------------------------------------------------------------

@dataclass
class WalkResult:
    passed: float = 0.0
    failed: float = 0.0
    unknown: int | None = None      # slot that stopped the walk
    budget: bool = False            # the read budget stopped the walk
    kinds: list[str] = field(default_factory=list)   # "ext4@0", "gpt", ...
    tally: dict[str, list[float]] = field(default_factory=dict)  # check -> [passed, failed]
    hints: dict[str, int] = field(default_factory=dict)  # chunk/data-disk/volume-size hints

    @property
    def score(self) -> float:
        return self.passed - 2.0 * self.failed

    def summary(self, top: int = 6) -> str:
        parts = [f"{k} {int(v[0])}/{int(v[0] + v[1])}" for k, v in
                 sorted(self.tally.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:top]]
        return ", ".join(parts)


class Walk:
    def __init__(self, read: Callable[[int, int], bytes], size: int, limit: float) -> None:
        self._read = read
        self.size = size
        self.limit = limit
        self.res = WalkResult()
        self._unknown = 0   # reads since the last check that needed an unplaced slot

    def read(self, off: int, n: int) -> bytes | None:
        """The bytes, or None when out of range or when the hypothesis has not placed
        the member yet (the next check then counts neither way, the walk goes on, and
        the first such slot is reported for the search to branch on)."""
        if off < 0 or n <= 0 or off + n > self.size:
            return None
        try:
            return self._read(off, n)
        except SlotUnknown as e:
            if self.res.unknown is None:
                self.res.unknown = e.slot
            self._unknown += 1
            return None

    def _neutral(self) -> bool:
        if self._unknown:
            self._unknown = 0
            return True
        return False

    def ok(self, cat: str, weight: float = 1.0) -> None:
        if self._neutral():
            return
        r = self.res
        r.passed += weight
        r.tally.setdefault(cat, [0.0, 0.0])[0] += weight
        if r.passed + r.failed >= self.limit:
            raise WalkDone

    def bad(self, cat: str, weight: float = 1.0) -> None:
        if self._neutral():
            return
        r = self.res
        r.failed += weight
        r.tally.setdefault(cat, [0.0, 0.0])[1] += weight
        if r.passed + r.failed >= self.limit:
            raise WalkDone

    def check(self, cond: bool, cat: str, weight: float = 1.0) -> bool:
        if cond:
            self.ok(cat, weight)
        else:
            self.bad(cat, 1.0)
        return cond


def run(read: Callable[[int, int], bytes], size: int, limit: float = 800) -> WalkResult:
    """Walk the volume read through ``read``; never raises for bad data."""
    w = Walk(read, size, limit)
    try:
        walk_volume(w)
    except WalkDone:
        pass
    except SlotUnknown as e:
        w.res.unknown = e.slot
    except BudgetExceeded:
        w.res.budget = True
    return w.res


def walk_volume(w: Walk) -> None:
    head = w.read(0, 8 * KiB)
    if head is None:
        return
    for lbs in (512, 4096):
        if head[lbs:lbs + 8] == b"EFI PART":
            _gpt(w, head, lbs)
            return
    if mbr_entries(head):
        _mbr(w, head)
        return
    _fs(w, 0, head)


# -- signatures (also used by raidmath to find data offsets) ------------------------------

_BOOT_OEM = (b"NTFS    ", b"EXFAT   ", b"-FVE-FS-", b"MSWIN4.1", b"MSDOS5.0", b"mkfs.fat", b"ReFS\0\0\0\0")


def mbr_entries(b: bytes) -> list[tuple[int, int, int]]:
    """Primary partitions (type, start LBA, sectors) if ``b`` is a plausible MBR."""
    if len(b) < 512 or b[510:512] != b"\x55\xaa" or b[3:11] in _BOOT_OEM:
        return []
    out = []
    for i in range(4):
        e = b[446 + 16 * i:462 + 16 * i]
        status, ptype = e[0], e[4]
        start, count = le(e, 8, 4), le(e, 12, 4)
        if status not in (0, 0x80):
            return []
        if ptype == 0:
            if start or count:
                return []
            continue
        if start == 0 or count == 0:
            return []
        out.append((ptype, start, count))
    return out


def start_kind(b: bytes) -> str:
    """What starts at the beginning of ``b`` (8 KiB): "" if nothing we know."""
    if len(b) < 8 * KiB:
        b = b + bytes(8 * KiB - len(b))
    if b[512:520] == b"EFI PART" or b[4096:4104] == b"EFI PART":
        return "gpt"
    if b[3:11] == b"NTFS    " and b[510:512] == b"\x55\xaa":
        return "ntfs"
    if b[1080:1082] == b"\x53\xef" and le(b, 1024 + 90, 2) == 0 and le(b, 1024 + 24, 4) <= 6:
        return "ext"
    if b[:4] == b"XFSB" and be(b, 4, 4) in (512 << i for i in range(8)):
        return "xfs"
    if b[:6] == b"LUKS\xba\xbe":
        return "luks"
    if b[512:520] == b"LABELONE":
        return "lvm"
    if b[3:11] == b"-FVE-FS-":
        return "bitlocker"
    if b[3:11] == b"EXFAT   ":
        return "exfat"
    if b[3:11] == b"ReFS\0\0\0\0":
        return "refs"
    if b[510:512] == b"\x55\xaa" and (b[82:87] == b"FAT32" or b[54:57] == b"FAT"):
        return "fat"
    if mbr_entries(b):
        return "mbr"
    return ""


def btrfs_super(b: bytes) -> bool:
    return len(b) >= 72 and b[64:72] == b"_BHRfS_M"


# -- partition tables ---------------------------------------------------------------------

def gpt_partitions(head: bytes) -> list[tuple[int, int]]:
    """(start, size) in bytes of GPT partitions whose entries are in ``head`` (>= 32 KiB),
    else of MBR primaries; used by reconstruct.validate (no tool needed)."""
    for lbs in (512, 4096):
        h = head[lbs:lbs + 512]
        if h[:8] != b"EFI PART":
            continue
        elba, ne, es = le(h, 72, 8), le(h, 80, 4), le(h, 84, 4)
        out = []
        for i in range(min(ne, 128)):
            e = head[elba * lbs + i * es: elba * lbs + (i + 1) * es]
            if len(e) < 48 or not any(e[:16]):
                continue
            first, last = le(e, 32, 8), le(e, 40, 8)
            if last >= first > 0:
                out.append((first * lbs, (last - first + 1) * lbs))
        return out
    return [(s * 512, c * 512) for t, s, c in mbr_entries(head) if t not in (0x05, 0x0F, 0x85, 0xEE)]


def _gpt(w: Walk, head: bytes, lbs: int) -> None:
    h = head[lbs:lbs + 512]
    hsize = le(h, 12, 4)
    if not 92 <= hsize <= 512:
        w.bad("gpt-header")
        return
    calc = binascii.crc32(h[:16] + b"\0\0\0\0" + h[20:hsize])
    if not w.check(calc == le(h, 16, 4), "gpt-header", 2.0):
        return
    w.res.kinds.append("gpt")
    alt, elba, ne, es = le(h, 32, 8), le(h, 72, 8), le(h, 80, 4), le(h, 84, 4)
    if not (128 <= es <= 1024 and 0 < ne <= 1024):
        w.bad("gpt-entries")
        return
    ents = w.read(elba * lbs, ne * es)
    if ents is None or not w.check(binascii.crc32(ents) == le(h, 88, 4), "gpt-entries", 2.0):
        return
    w.res.hints["volume_size"] = (alt + 1) * lbs
    if (alt + 1) * lbs <= w.size:
        b = w.read(alt * lbs, 512)
        w.check(b is not None and b[:8] == b"EFI PART" and le(b, 24, 8) == alt, "gpt-backup", 2.0)
    parts = []
    for i in range(ne):
        e = ents[i * es:(i + 1) * es]
        if not any(e[:16]):
            continue
        first, last = le(e, 32, 8), le(e, 40, 8)
        if last >= first > 0:
            parts.append(first * lbs)
    for start in parts[:8]:
        _fs(w, start)


def _mbr(w: Walk, head: bytes) -> None:
    w.res.kinds.append("mbr")
    for ptype, start, count in mbr_entries(head):
        if not w.check(start * 512 < w.size, "mbr-entry"):
            continue
        if ptype not in (0x05, 0x0F, 0x85, 0xEE):
            _fs(w, start * 512)


# -- one filesystem -----------------------------------------------------------------------

def _fs(w: Walk, base: int, head: bytes | None = None) -> None:
    if head is None:
        head = w.read(base, 8 * KiB)
        if head is None:
            return
    if head[1080:1082] == b"\x53\xef":
        _ext(w, base, head[1024:2048])
    elif head[3:11] == b"NTFS    ":
        _ntfs(w, base, head)
    elif head[:4] == b"XFSB":
        _xfs(w, base, head)
    elif head[512:520] == b"LABELONE":
        _lvm(w, base, head)
    else:
        kind = start_kind(head)
        if kind in ("luks", "bitlocker", "exfat", "refs", "fat"):
            w.res.kinds.append(f"{kind}@{base}")
            w.ok(kind)
            return
        sb = w.read(base + 64 * KiB, 4 * KiB)
        if sb is not None and btrfs_super(sb):
            _btrfs(w, base, sb)


# ext2/3/4 ------------------------------------------------------------------------------

EXT_EXTENTS_FL = 0x80000
EXT_INDEX_FL = 0x1000
EXT_INLINE_FL = 0x10000000


@dataclass
class _ExtDesc:
    bb: int
    ib: int
    it: int
    flags: int
    bb_csum: int
    ib_csum: int
    valid: bool
    free_b: int = 0
    free_i: int = 0


def _sparse_groups(groups: int, sparse: bool) -> list[int]:
    if not sparse:
        return list(range(1, groups))
    out = {1}
    for p in (3, 5, 7):
        x = p
        while x < groups:
            out.add(x)
            x *= p
    return sorted(g for g in out if g < groups)


def _ext(w: Walk, base: int, sb: bytes) -> None:
    log_bs = le(sb, 24, 4)
    bpg, ipg, isz = le(sb, 32, 4), le(sb, 40, 4), le(sb, 88, 2) if le(sb, 76, 4) else 128
    fdb, ninodes = le(sb, 20, 4), le(sb, 0, 4)
    if log_bs > 6:
        w.bad("ext-superblock")
        return
    bs = 1024 << log_bs
    compat, incompat, ro = le(sb, 92, 4), le(sb, 96, 4), le(sb, 100, 4)
    blocks = le(sb, 4, 4) | ((le(sb, 336, 4) << 32) if incompat & 0x80 else 0)
    if not (0 < bpg <= 8 * bs and 0 < ipg <= 8 * bs and isz in (128, 256, 512, 1024)
            and blocks > fdb and ninodes > 0 and le(sb, 90, 2) == 0):
        w.bad("ext-superblock")
        return
    w.ok("ext-superblock", 2.0)
    w.res.kinds.append(f"{'ext4' if incompat & 0x40 else 'ext2/3'}@{base}")
    stride, width = le(sb, 356, 2), le(sb, 368, 4)
    if stride:
        w.res.hints.setdefault("chunk", stride * bs)
        if width and width % stride == 0:
            w.res.hints.setdefault("data_disks", width // stride)
    w.check(blocks * bs <= w.size - base + MiB, "ext-size")
    metacsum = bool(ro & 0x400)
    gdtcsum = bool(ro & 0x10)
    uuid = sb[104:120]
    seed = 0
    if metacsum:
        seed = le(sb, 624, 4) if incompat & 0x2000 else crc32c_raw(0xFFFFFFFF, bytes(uuid))
        w.check(crc32c_raw(0xFFFFFFFF, bytes(sb[:1020])) == le(sb, 1020, 4), "ext-sb-csum", 2.0)
    filetype = bool(incompat & 0x2)
    groups = (blocks - fdb + bpg - 1) // bpg
    dsz = le(sb, 254, 2) if incompat & 0x80 else 32
    if dsz not in (32, 64):
        dsz = 32
    per = bs // dsz
    ng = min(groups, 4096)
    descs: list[_ExtDesc] = []
    gdt = base + (fdb + 1) * bs
    for gb in range((ng + per - 1) // per):
        blk = w.read(gdt + gb * bs, bs)
        if blk is None:
            w.bad("ext-gdt")
            return
        good = total = 0
        for i in range(per):
            g = gb * per + i
            if g >= ng:
                break
            d = blk[i * dsz:(i + 1) * dsz]
            hi = dsz >= 64
            bb = le(d, 0, 4) | ((le(d, 32, 4) << 32) if hi else 0)
            ib = le(d, 4, 4) | ((le(d, 36, 4) << 32) if hi else 0)
            it = le(d, 8, 4) | ((le(d, 40, 4) << 32) if hi else 0)
            valid = 0 < bb < blocks and 0 < ib < blocks and 0 < it < blocks
            if valid and (metacsum or gdtcsum):
                lg = g.to_bytes(4, "little")
                if metacsum:
                    c = crc32c_raw(crc32c_raw(seed, lg), bytes(d[:30]) + b"\0\0" + bytes(d[32:])) & 0xFFFF
                else:
                    c = crc16(crc16(0xFFFF, bytes(uuid)), lg + bytes(d[:30]) + bytes(d[32:]))
                valid = c == le(d, 30, 2)
            good += valid
            total += 1
            descs.append(_ExtDesc(bb, ib, it, le(d, 18, 2),
                                  le(d, 24, 2) | ((le(d, 56, 2) << 16) if hi else 0),
                                  le(d, 26, 2) | ((le(d, 58, 2) << 16) if hi else 0), valid,
                                  le(d, 12, 2) | ((le(d, 44, 2) << 16) if hi else 0),
                                  le(d, 14, 2) | ((le(d, 46, 2) << 16) if hi else 0)))
        if not w.check(total > 0 and good >= 0.9 * total, "ext-gdt", 2.0 if (metacsum or gdtcsum) else 1.0):
            return
    if not compat & 0x200:  # sparse_super2 keeps backups elsewhere: skip
        for g in _sparse_groups(groups, bool(ro & 0x1))[:12]:
            b = w.read(base + (g * bpg + fdb) * bs, 1024)
            w.check(b is not None and b[56:58] == b"\x53\xef" and le(b, 90, 2) == g and b[104:120] == uuid,
                    "ext-backup-sb", 2.0)

    def inode(i: int) -> bytes | None:
        g, idx = divmod(i - 1, ipg)
        if i < 1 or g >= len(descs) or not descs[g].valid:
            return None
        return w.read(base + descs[g].it * bs + idx * isz, isz)

    def inode_ok(raw: bytes | None, i: int, want: int = 0) -> bool:
        if raw is None or not any(raw):
            return False
        mode = le(raw, 0, 2) & 0xF000
        if mode not in (0x1000, 0x2000, 0x4000, 0x6000, 0x8000, 0xA000, 0xC000) or (want and mode != want):
            return False
        if le(raw, 26, 2) == 0:
            return False
        flags = le(raw, 32, 4)
        if flags & EXT_EXTENTS_FL and not flags & EXT_INLINE_FL:
            if le(raw, 40, 2) != 0xF30A or le(raw, 42, 2) > le(raw, 44, 2) or le(raw, 44, 2) > 4 \
                    or le(raw, 46, 2) > 5:
                return False
        if metacsum:
            gen = raw[100:104]
            iseed = crc32c_raw(crc32c_raw(seed, i.to_bytes(4, "little")), bytes(gen))
            body = bytearray(raw)
            body[124:126] = b"\0\0"
            hi = isz > 128 and le(raw, 128, 2) >= 4
            if hi:
                body[130:132] = b"\0\0"
            c = crc32c_raw(iseed, bytes(body))
            stored = le(raw, 124, 2) | ((le(raw, 130, 2) << 16) if hi else 0)
            if (c if hi else c & 0xFFFF) != stored:
                return False
        return True

    def iseed_of(raw: bytes, i: int) -> int:
        return crc32c_raw(crc32c_raw(seed, i.to_bytes(4, "little")), bytes(raw[100:104]))

    def file_blocks(raw: bytes, ino: int, want: int) -> list[int]:
        """The first ``want`` physical blocks of a file (extents or block map)."""
        flags = le(raw, 32, 4)
        out: list[int] = []
        if flags & EXT_INLINE_FL:
            return out
        if not flags & EXT_EXTENTS_FL:
            for k in range(12):
                b = le(raw, 40 + 4 * k, 4)
                if b:
                    out.append(b)
                if len(out) >= want:
                    break
            return out
        node, depth_left = bytes(raw[40:100]), 6
        while depth_left:
            depth_left -= 1
            entries, depth = le(node, 2, 2), le(node, 6, 2)
            if depth == 0:
                for k in range(entries):
                    e = node[12 + 12 * k:24 + 12 * k]
                    ln = le(e, 4, 2)
                    if ln > 32768:  # unwritten extent
                        continue
                    start = le(e, 8, 4) | (le(e, 6, 2) << 32)
                    for j in range(min(ln, want - len(out))):
                        out.append(start + j)
                    if len(out) >= want:
                        break
                return out
            if entries == 0:
                return out
            leaf = le(node, 12 + 4, 4) | (le(node, 12 + 8, 2) << 32)
            if not 0 < leaf < blocks:
                w.bad("ext-extent-node")
                return out
            blk = w.read(base + leaf * bs, bs)
            if blk is None or le(blk, 0, 2) != 0xF30A:
                w.bad("ext-extent-node")
                return out
            mx = le(blk, 4, 2)
            if metacsum and 12 + 12 * mx + 4 <= bs:
                w.check(crc32c_raw(iseed_of(raw, ino), bytes(blk[:12 + 12 * mx])) == le(blk, 12 + 12 * mx, 4),
                        "ext-extent-node", 2.0)
            else:
                w.ok("ext-extent-node")
            node = blk
        return out

    def dir_entries(blk: bytes) -> list[tuple[int, int, bytes]] | None:
        out = []
        pos = 0
        end = bs - 12 if metacsum and le(blk, bs - 12, 4) == 0 and le(blk, bs - 8, 2) == 12 \
            and blk[bs - 5] == 0xDE else bs
        while pos < end:
            ino, rl = le(blk, pos, 4), le(blk, pos + 4, 2)
            nl = blk[pos + 6] if filetype else le(blk, pos + 6, 2)
            ft = blk[pos + 7] if filetype else 0
            if rl < 8 or rl % 4 or pos + rl > end or (ino and 8 + nl > rl) or ino > ninodes:
                return None
            if ino:
                out.append((ino, ft, bytes(blk[pos + 8:pos + 8 + nl])))
            pos += rl
        return out if pos == end else None

    def block_at(raw: bytes, ino: int, lblk: int) -> int | None:
        """Physical block of logical block ``lblk`` (None: a hole or unreadable)."""
        flags = le(raw, 32, 4)
        if flags & EXT_INLINE_FL:
            return None
        if not flags & EXT_EXTENTS_FL:
            return (le(raw, 40 + 4 * lblk, 4) or None) if lblk < 12 else None
        node = bytes(raw[40:100])
        for _ in range(6):
            entries, depth = le(node, 2, 2), le(node, 6, 2)
            if depth == 0:
                for k in range(entries):
                    e = node[12 + 12 * k:24 + 12 * k]
                    first, ln = le(e, 0, 4), le(e, 4, 2)
                    if ln > 32768:
                        continue
                    if first <= lblk < first + ln:
                        return (le(e, 8, 4) | (le(e, 6, 2) << 32)) + lblk - first
                return None
            leaf = None
            for k in range(entries):
                e = node[12 + 12 * k:24 + 12 * k]
                if le(e, 0, 4) <= lblk:
                    leaf = le(e, 4, 4) | (le(e, 8, 2) << 32)
            if leaf is None or not 0 < leaf < blocks:
                return None
            blk = w.read(base + leaf * bs, bs)
            if blk is None or le(blk, 0, 2) != 0xF30A:
                return None
            node = blk
        return None

    def eof_slack(raw: bytes, ino: int) -> None:
        """The bytes after the end of a file, in its last block, are zero."""
        size = le(raw, 4, 4) | (le(raw, 108, 4) << 32)
        if not size or size % bs == 0 or le(raw, 32, 4) & EXT_INLINE_FL or size < 60:
            return
        pb = block_at(raw, ino, (size - 1) // bs)
        if pb is None or not 0 < pb < blocks:
            return
        blk = w.read(base + pb * bs, bs)
        if blk is not None and is_zero_bytes(blk[size % bs:]) and not is_zero_bytes(blk[:size % bs]):
            w.ok("ext-file-tail")  # only a pass: some writers leave junk after EOF

    # The journal superblock (the journal sits in the middle of the filesystem).
    jino = le(sb, 224, 4)
    if jino and compat & 0x4:
        raw = inode(jino)
        if raw is not None and inode_ok(raw, jino, 0x8000):
            jb = file_blocks(raw, jino, 1)
            if jb:
                j = w.read(base + jb[0] * bs, 12)
                w.check(j is not None and be(j, 0, 4) == 0xC03B3998, "ext-journal", 2.0)

    # Directory walk from the root: inodes, "." and "..", entries, checksums.
    queue: deque[tuple[int, int]] = deque([(2, 2)])
    seen = {2}
    files = 0
    while queue:
        ino, parent = queue.popleft()
        raw = inode(ino)
        if not w.check(inode_ok(raw, ino, 0x4000), "ext-dir-inode", 2.0 if metacsum else 1.0):
            continue
        assert raw is not None
        if le(raw, 32, 4) & EXT_INLINE_FL:
            continue
        indexed = bool(le(raw, 32, 4) & EXT_INDEX_FL)
        for bi, pb in enumerate(file_blocks(raw, ino, 4)):
            if not 0 < pb < blocks:
                w.bad("ext-dir-block")
                continue
            blk = w.read(base + pb * bs, bs)
            if blk is None:
                w.bad("ext-dir-block")
                continue
            if bi == 0:
                r0 = le(blk, 4, 2)
                dot_ok = (le(blk, 0, 4) == ino and blk[8:9] == b"." and 12 <= r0 <= bs - 12
                          and le(blk, r0, 4) == parent and blk[r0 + 8:r0 + 10] == b"..")
                if not w.check(dot_ok, "ext-dir-dots", 2.0):
                    continue
                if indexed:
                    continue
            elif indexed and le(blk, 0, 4) == 0 and le(blk, 4, 2) == bs:
                continue  # htree internal node
            ents = dir_entries(blk)
            if ents is None:
                w.bad("ext-dir-block")
                continue
            if metacsum and le(blk, bs - 8, 2) == 12 and blk[bs - 5] == 0xDE:
                w.check(crc32c_raw(iseed_of(raw, ino), bytes(blk[:bs - 12])) == le(blk, bs - 4, 4),
                        "ext-dir-csum", 2.0)
            else:
                w.ok("ext-dir-block")
            for child, ft, name in ents:
                if name in (b".", b".."):
                    continue
                if ft == 2 and child not in seen:
                    seen.add(child)
                    queue.append((child, ino))
                elif ft in (1, 7) and files < 4000:
                    files += 1
                    raw2 = inode(child)
                    if w.check(inode_ok(raw2, child, 0x8000 if ft == 1 else 0xA000), "ext-file-inode") and ft == 1:
                        assert raw2 is not None
                        eof_slack(raw2, child)
                elif ft == 0 and child not in seen:
                    raw2 = inode(child)
                    if raw2 is not None and le(raw2, 0, 2) & 0xF000 == 0x4000:
                        seen.add(child)
                        queue.append((child, ino))
                    else:
                        w.check(inode_ok(raw2, child), "ext-file-inode")

    # Bitmaps: the free counts of the group descriptors (and, with metadata_csum, the
    # bitmap checksums), spread over the groups.
    hi = dsz >= 64
    for g, d in enumerate(descs[:256]):
        if not d.valid:
            continue
        in_group = min(bpg, blocks - fdb - g * bpg)
        if not d.flags & 0x2:
            b = w.read(base + d.bb * bs, bs)
            if b is None:
                w.bad("ext-bitmap")
            elif metacsum:
                c = crc32c_raw(seed, bytes(b[:bpg // 8]))
                w.check((c if hi else c & 0xFFFF) == d.bb_csum, "ext-bitmap", 2.0)
            else:
                w.check(in_group - _popcount(b, in_group) == d.free_b, "ext-bitmap")
        if not d.flags & 0x1:
            b = w.read(base + d.ib * bs, bs)
            if b is None:
                w.bad("ext-bitmap")
            elif metacsum:
                c = crc32c_raw(seed, bytes(b[:ipg // 8]))
                w.check((c if hi else c & 0xFFFF) == d.ib_csum, "ext-bitmap", 2.0)
            else:
                w.check(ipg - _popcount(b, ipg) == d.free_i, "ext-bitmap")


# NTFS ----------------------------------------------------------------------------------

def ntfs_fixup(rec: bytes) -> bytes | None:
    """Apply the update sequence array; None if a sector does not carry the USN."""
    if len(rec) < 48:
        return None
    uo, uc = le(rec, 4, 2), le(rec, 6, 2)
    if uc < 2 or uo + 2 * uc > len(rec) or (uc - 1) * 512 > len(rec):
        return None
    usn = rec[uo:uo + 2]
    out = bytearray(rec)
    for i in range(1, uc):
        end = i * 512
        if rec[end - 2:end] != usn:
            return None
        out[end - 2:end] = rec[uo + 2 * i:uo + 2 * i + 2]
    return bytes(out)


def ntfs_runlist(b: bytes, pos: int) -> list[tuple[int, int]] | None:
    """Decode mapping pairs into (lcn, clusters); lcn -1 for sparse runs."""
    out = []
    lcn = 0
    for _ in range(4096):
        if pos >= len(b):
            return None
        h = b[pos]
        if h == 0:
            return out
        ln, ofs = h & 0xF, h >> 4
        if ln == 0 or ln > 8 or ofs > 8 or pos + 1 + ln + ofs > len(b):
            return None
        count = le(b, pos + 1, ln)
        if ofs:
            delta = int.from_bytes(b[pos + 1 + ln:pos + 1 + ln + ofs], "little", signed=True)
            lcn += delta
            out.append((lcn, count))
        else:
            out.append((-1, count))
        pos += 1 + ln + ofs
    return None


def ntfs_attrs(rec: bytes) -> list[tuple[int, bytes]]:
    """(type, attribute bytes) of a fixed-up FILE record."""
    out = []
    pos = le(rec, 20, 2)
    used = min(le(rec, 24, 4), len(rec))
    while 0 < pos and pos + 8 <= used:
        t, ln = le(rec, pos, 4), le(rec, pos + 4, 4)
        if t == 0xFFFFFFFF or ln < 16 or pos + ln > used:
            break
        out.append((t, rec[pos:pos + ln]))
        pos += ln
    return out


def _ntfs(w: Walk, base: int, bs: bytes) -> None:
    bps, spc = le(bs, 11, 2), bs[13]
    if spc > 0x80:
        spc = 1 << (256 - spc)
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc & (spc - 1) or bs[510:512] != b"\x55\xaa":
        w.bad("ntfs-boot")
        return
    cl = bps * spc
    total, mft, mirr = le(bs, 40, 8), le(bs, 48, 8), le(bs, 56, 8)
    c = int.from_bytes(bs[64:65], "little", signed=True)
    rs = cl * c if c > 0 else 1 << -c
    c = int.from_bytes(bs[68:69], "little", signed=True)
    ixs = cl * c if c > 0 else 1 << -c
    if not (256 <= rs <= 65536 and 0 < mft and 0 < mirr and total > 0):
        w.bad("ntfs-boot")
        return
    w.ok("ntfs-boot", 2.0)
    w.res.kinds.append(f"ntfs@{base}")
    w.check(total * bps <= w.size - base + MiB, "ntfs-size")

    def record_at(pos: int, k: int | None) -> bytes | None:
        raw = w.read(pos, rs)
        if raw is None or raw[:4] != b"FILE":
            return None
        rec = ntfs_fixup(raw)
        if rec is None or le(rec, 28, 4) != rs:
            return None
        if k is not None and le(rec, 4, 2) >= 0x30 and le(rec, 44, 4) != k \
                and not (le(rec, 44, 4) == 0 and not le(rec, 22, 2) & 1):  # mkntfs: reserved, unnumbered
            return None
        return rec

    rec0 = record_at(base + mft * cl, 0)
    if not w.check(rec0 is not None, "ntfs-mft", 2.0):
        return
    assert rec0 is not None
    runs = None
    init = 0
    for t, a in ntfs_attrs(rec0):
        if t == 0x80 and a[8] == 1 and a[9] == 0:
            runs = ntfs_runlist(a, le(a, 32, 2))
            init = le(a, 56, 8)
            break
    if not w.check(bool(runs), "ntfs-mft-runlist"):
        return
    assert runs is not None
    extents = []  # (first record, record count, byte position)
    k0 = 0
    for lcn, count in runs:
        n = count * cl // rs
        if lcn >= 0:
            extents.append((k0, n, base + lcn * cl))
        k0 += n
    nrec = min(k0, init // rs if init else k0)

    def rec_pos(k: int) -> int | None:
        for first, n, pos in extents:
            if first <= k < first + n:
                return pos + (k - first) * rs
        return None

    def record(k: int) -> bytes | None:
        pos = rec_pos(k)
        return None if pos is None else record_at(pos, k)

    def data_tail(rec: bytes) -> None:
        """Bytes after the end of a file's data, in its last cluster, are zero (a pass only)."""
        for t, a in ntfs_attrs(rec):
            if t != 0x80 or a[9] != 0 or a[8] != 1:
                continue
            size = le(a, 48, 8)
            fr = ntfs_runlist(a, le(a, 32, 2))
            if not fr or size % cl == 0 or size < 64:
                return
            vcn, v = (size - 1) // cl, 0
            for lcn, count in fr:
                if v <= vcn < v + count:
                    if lcn >= 0:
                        blk = w.read(base + (lcn + vcn - v) * cl, cl)
                        if blk is not None and is_zero_bytes(blk[size % cl:]) and \
                                not is_zero_bytes(blk[:size % cl]):
                            w.ok("ntfs-file-tail")
                    return
                v += count
            return

    # MFT mirror: the first records again.
    w.check(record_at(base + mirr * cl, 0) is not None, "ntfs-mftmirr", 2.0)

    # Directories from the root (record 5): index blocks and the records they name.
    checked: set[int] = {0}
    queue = deque([5])
    seen_dirs = {5}
    while queue:
        k = queue.popleft()
        rec = record(k)
        if not w.check(rec is not None and le(rec, 22, 2) & 0x3 == 0x3, "ntfs-dir-record", 2.0):
            continue
        assert rec is not None
        checked.add(k)
        refs: list[int] = []
        for t, a in ntfs_attrs(rec):
            if t == 0x90 and a[8] == 0:      # $INDEX_ROOT
                v = a[le(a, 20, 2):]
                refs += _ntfs_index_refs(v, 16)
            elif t == 0xA0 and a[8] == 1:    # $INDEX_ALLOCATION
                ir = ntfs_runlist(a, le(a, 32, 2))
                if not w.check(ir is not None, "ntfs-index-runlist"):
                    continue
                vcn = 0
                assert ir is not None
                for lcn, count in ir[:16]:
                    if lcn < 0:
                        vcn += count
                        continue
                    for j in range(min(count * cl // ixs, 8)):
                        blk = w.read(base + lcn * cl + j * ixs, ixs)
                        at = vcn * cl + j * ixs
                        vb = at // cl if ixs >= cl else at // 512
                        fx = ntfs_fixup(blk) if blk is not None and blk[:4] == b"INDX" else None
                        if not w.check(fx is not None and le(fx, 16, 8) == vb, "ntfs-indx", 2.0):
                            continue
                        assert fx is not None
                        refs += _ntfs_index_refs(fx, 24)
                    vcn += count
        for r in refs:
            if r in checked or r < 16 or r >= nrec:
                continue
            checked.add(r)
            rr = record(r)
            if not w.check(rr is not None and le(rr, 22, 2) & 0x1, "ntfs-file-record"):
                continue
            assert rr is not None
            if le(rr, 22, 2) & 0x2 and r not in seen_dirs:
                seen_dirs.add(r)
                queue.append(r)
            elif not le(rr, 22, 2) & 0x2:
                data_tail(rr)
    # A spread of MFT records (they carry their own record number).
    step = max(1, nrec // 200)
    for k in range(1, nrec, step):
        if k in checked:
            continue
        pos = rec_pos(k)
        raw = w.read(pos, rs) if pos is not None else None
        if raw is None or not any(raw):
            continue  # never formatted
        w.check(record_at(pos, k) is not None, "ntfs-mft-record")


def _ntfs_index_refs(b: bytes, hdr: int) -> list[int]:
    """MFT record numbers named by the entries of an index header at ``hdr``."""
    out = []
    pos = hdr + le(b, hdr, 4)
    end = min(len(b), hdr + le(b, hdr + 4, 4))
    for _ in range(1024):
        if pos + 16 > end:
            break
        ref, ln, flags = le(b, pos, 6), le(b, pos + 8, 2), le(b, pos + 12, 2)
        if ln < 16:
            break
        if not flags & 0x2:
            out.append(ref)
        else:
            break
        pos += ln
    return out


# XFS -----------------------------------------------------------------------------------

def _xfs(w: Walk, base: int, sb: bytes) -> None:
    bsz, dblocks, rootino = be(sb, 4, 4), be(sb, 8, 8), be(sb, 56, 8)
    agblocks, agcount = be(sb, 84, 4), be(sb, 88, 4)
    ver, sect, isz = be(sb, 100, 2), be(sb, 102, 2), be(sb, 104, 2)
    inopblog, agblklog = sb[123], sb[124]
    if not (bsz in (512 << i for i in range(8)) and sect in (512 << i for i in range(4)) and 0 < agcount < 1 << 20
            and 0 < agblocks and 256 <= isz <= 2048 and dblocks > 0):
        w.bad("xfs-superblock")
        return
    v5 = ver & 0xF == 5
    w.ok("xfs-superblock", 2.0)
    w.res.kinds.append(f"xfs@{base}")
    if be(sb, 184, 4):
        w.res.hints.setdefault("chunk", be(sb, 184, 4) * bsz)
        if be(sb, 188, 4) % be(sb, 184, 4) == 0:
            w.res.hints.setdefault("data_disks", be(sb, 188, 4) // be(sb, 184, 4))
    w.check(dblocks * bsz <= w.size - base + MiB, "xfs-size")
    hdr = 56 if v5 else 16
    ag = agblocks * bsz
    ino_bits = agblklog + inopblog

    def inode_check(ino: int) -> None:
        agno, agino = ino >> ino_bits, ino & ((1 << ino_bits) - 1)
        pos = base + agno * ag + (agino >> inopblog) * bsz + (agino & ((1 << inopblog) - 1)) * isz
        raw = w.read(pos, 176)
        good = raw is not None and raw[:2] == b"IN" and raw[4] in (1, 2, 3)
        if good and v5 and raw is not None:
            good = raw[4] == 3 and be(raw, 152, 8) == ino
        w.check(good, "xfs-inode", 2.0 if v5 else 1.0)

    def btree(agno: int, agbno: int, magics: tuple[bytes, ...], cat: str) -> bytes | None:
        if not 0 < agbno < agblocks:
            w.bad(cat)
            return None
        blk = w.read(base + agno * ag + agbno * bsz, bsz)
        good = blk is not None and blk[:4] in magics
        if good and v5 and blk is not None:
            good = be(blk, 16, 8) == (agno * ag + agbno * bsz) // 512
        w.check(good, cat, 2.0 if v5 else 1.0)
        return blk if good else None

    inode_check(rootino)
    for g in range(min(agcount, 256)):
        off = base + g * ag
        if g:
            s = w.read(off, 4)
            w.check(s == b"XFSB", "xfs-ag-super")
        agf = w.read(off + sect, 64)
        if w.check(agf is not None and agf[:4] == b"XAGF" and be(agf, 8, 4) == g, "xfs-agf", 2.0):
            assert agf is not None
            btree(g, be(agf, 16, 4), (b"AB3B", b"ABTB"), "xfs-bnobt")
            btree(g, be(agf, 20, 4), (b"AB3C", b"ABTC"), "xfs-cntbt")
        agi = w.read(off + 2 * sect, 64)
        if w.check(agi is not None and agi[:4] == b"XAGI" and be(agi, 8, 4) == g, "xfs-agi", 2.0):
            assert agi is not None
            blk = btree(g, be(agi, 20, 4), (b"IAB3", b"IABT"), "xfs-inobt")
            if blk is not None and be(blk, 4, 2) == 0:
                for r in range(min(be(blk, 6, 2), 16)):
                    start = be(blk, hdr + 16 * r, 4)
                    for i in range(0, 64, 16):
                        inode_check((g << ino_bits) | (start + i))


# btrfs, LVM ------------------------------------------------------------------------------

def _btrfs(w: Walk, base: int, sb: bytes) -> None:
    w.res.kinds.append(f"btrfs@{base}")
    good = le(sb, 48, 8) == 64 * KiB
    if good and le(sb, 0xC4, 2) == 0:
        good = crc32c(sb[32:4096]) == le(sb, 0, 4)
    if not w.check(good, "btrfs-super", 2.0):
        return
    for mirror in (64 * MiB, 256 * 1024 * MiB):
        if base + mirror + 4 * KiB <= w.size:
            m = w.read(base + mirror, 4 * KiB)
            w.check(m is not None and btrfs_super(m) and le(m, 48, 8) == mirror and m[32:48] == sb[32:48],
                    "btrfs-super", 2.0)


def _lvm(w: Walk, base: int, head: bytes) -> None:
    lab = head[512:1024]
    if not w.check(lab[24:32] == b"LVM2 001", "lvm-label"):
        return
    w.res.kinds.append(f"lvm@{base}")
    pv = 512 + le(lab, 20, 4)
    pos = pv + 32 + 8
    das = []
    while pos + 16 <= len(head):
        off = le(head, pos, 8)  # (offset, size) pairs: the data areas
        pos += 16
        if off == 0:
            break
        das.append(off)
    if das and das[0] < w.size - base:
        _fs(w, base + das[0])
