"""Generic RAID reconstruction: the pure-Python analysis (docs/DISK_TOOLS.md, rule 2).

No I/O of its own, no programs, no numpy: reconstruct.py hands it read-only member
readers; the tests hand it member images built in memory. Clean-room: the DFRWS 2016
paper on generic RAID reassembly was background only.

How detect works
1. Level, from 4 KiB rows sampled at the same position on every member: all equal
   (raid1), equal in fixed pairs (raid10 near-2), XOR zero (raid5), XOR equal to exactly
   one member's block (raid6: that member holds Q). Otherwise raid0 or linear, or raid5
   with one member missing.
2. Data offset, from where a volume-start structure (GPT, MBR, ext, NTFS, XFS, btrfs,
   LVM, LUKS, BitLocker, FAT/exFAT, ReFS) sits on some member: probed at 0, small
   reserves and every MiB up to 256 MiB (md 1.2 puts data at 1-128 MiB; AMD RAIDXpert2,
   Intel IMSM, DDF and md 0.90/1.0 at 0).
3. Chunk size, layout and order: every geometry (level x chunk 4 KiB-1 MiB x layout x
   offset) is scored by a filesystem walk (fswalk.py) through it. The member order comes
   slot by slot: when the walk needs a slot nobody fills yet, every free member (and,
   for raid5 with a member missing, "missing", rebuilt from parity) is tried there and
   the best few continue (beam search). A quick pass ranks the geometries; the best go
   through a full walk.
"""

from __future__ import annotations

import functools
import math
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from . import fswalk
from .fswalk import BudgetExceeded, SlotUnknown, WalkResult, crc32c, crc32c_raw  # noqa: F401 (re-exported)

KiB = 1024
MiB = 1024 * KiB
SECTOR = 512
ROW = 4 * KiB
CHUNKS = tuple(4 * KiB << i for i in range(9))  # 4 KiB .. 1 MiB
LAYOUTS = ("left-symmetric", "left-asymmetric", "right-symmetric", "right-asymmetric")
LEVELS = ("raid0", "raid1", "raid5", "raid6", "raid10", "linear")
MISSING = -1
# Tie-break only: md's 512 KiB, Intel/AMD 64/128 KiB, Storage Spaces 256 KiB first.
CHUNK_PRIOR = (512 * KiB, 64 * KiB, 128 * KiB, 256 * KiB, 32 * KiB, 16 * KiB, 1 * MiB, 8 * KiB, 4 * KiB)
# Where data can start on a member: 0 (AMD, IMSM, DDF, md 0.90/1.0), small reserves,
# then every MiB to 256 MiB (md 1.1/1.2, NAS partitions).
OFFSET_GRID = (0, 4 * KiB, 8 * KiB, 64 * KiB, 128 * KiB, 256 * KiB, 512 * KiB) + \
    tuple(k * MiB for k in range(1, 257))


# -- bytes ---------------------------------------------------------------------------------

def xor_blocks(blocks: Sequence[bytes]) -> bytes:
    """XOR of equally long blocks (big-integer XOR: fast in CPython)."""
    acc = 0
    for b in blocks:
        acc ^= int.from_bytes(b, "little")
    return acc.to_bytes(len(blocks[0]) if blocks else 0, "little")


def is_zero(b: bytes) -> bool:
    return b.count(0) == len(b)


def entropy(b: bytes) -> float:
    """Shannon entropy in bits per byte (0 for empty or constant data)."""
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


# -- geometry -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Geometry:
    level: str          # raid0 raid1 raid5 raid6 raid10 linear
    n: int              # array slots (raid devices), a missing member included
    chunk: int = 0      # bytes; linear: rounding of each member (0 = none); raid1: 0
    layout: str = ""    # raid5/raid6: md layout name
    offset: int = 0     # data offset on every member, bytes

    @property
    def data_slots(self) -> int:
        return {"raid5": self.n - 1, "raid6": self.n - 2, "raid10": self.n // 2,
                "raid1": 1}.get(self.level, self.n)


@functools.lru_cache(maxsize=4096)
def raid5_map(layout: str, n: int, row: int) -> tuple[int, tuple[int, ...]]:
    """(parity slot, data slot for each data index) of a raid5 row (md raid5.c)."""
    r = row % n
    left = layout.startswith("left")
    p = n - 1 - r if left else r
    if layout.endswith("asymmetric"):
        data = tuple(d if d < p else d + 1 for d in range(n - 1))
    else:
        data = tuple((p + 1 + d) % n for d in range(n - 1))
    return p, data


@functools.lru_cache(maxsize=4096)
def raid6_map(layout: str, n: int, row: int) -> tuple[int, int, tuple[int, ...]]:
    """(P slot, Q slot, data slots) of a raid6 row (md raid5.c, RAID6 algorithms)."""
    r = row % n
    left = layout.startswith("left")
    p = n - 1 - r if left else r
    if layout.endswith("asymmetric"):
        if p == n - 1:
            q, data = 0, tuple(d + 1 for d in range(n - 2))
        else:
            q, data = p + 1, tuple(d if d < p else d + 2 for d in range(n - 2))
    else:
        q, data = (p + 1) % n, tuple((p + 2 + d) % n for d in range(n - 2))
    return p, q, data


def usable_size(geom: Geometry, sizes: Sequence[int]) -> int:
    """Bytes of each member a striped geometry uses (the smallest member, whole chunks)."""
    u = min(sizes) - geom.offset if sizes else 0
    if geom.chunk and geom.level != "linear":
        u -= u % geom.chunk
    return max(u, 0)


def logical_size(geom: Geometry, sizes: Sequence[int]) -> int:
    if geom.level == "linear":
        return sum(_linear_len(geom, s) for s in sizes)
    return usable_size(geom, sizes) * geom.data_slots


def _linear_len(geom: Geometry, size: int) -> int:
    u = max(size - geom.offset, 0)
    return u - u % geom.chunk if geom.chunk else u


# -- reading ----------------------------------------------------------------------------

class Source:
    """Read-only, cached access to the members, with a byte budget per member.

    ``readers[m](offset, length) -> bytes`` must only read. Reads past the end give zeros.
    """

    def __init__(self, readers: Sequence[Callable[[int, int], bytes]], sizes: Sequence[int], *,
                 budget: int | None = None, page: int = 32 * KiB, cache: int = 96 * MiB) -> None:
        self.readers = list(readers)
        self.sizes = list(sizes)
        self.budget = budget
        self.page = page
        self.cache_pages = max(16, cache // page)
        self.bytes_read = [0] * len(self.readers)
        self._cache: OrderedDict[tuple[int, int], bytes] = OrderedDict()

    @property
    def n(self) -> int:
        return len(self.readers)

    def _page(self, m: int, p: int) -> bytes:
        key = (m, p)
        data = self._cache.get(key)
        if data is not None:
            self._cache.move_to_end(key)
            return data
        if self.budget is not None and self.bytes_read[m] >= self.budget:
            raise BudgetExceeded(m)
        start = p * self.page
        want = min(self.page, self.sizes[m] - start)
        data = bytes(self.readers[m](start, want))
        if len(data) < want:
            data += bytes(want - len(data))
        self.bytes_read[m] += want
        self._cache[key] = data
        if len(self._cache) > self.cache_pages:
            self._cache.popitem(last=False)
        return data

    def read(self, m: int, off: int, n: int) -> bytes:
        size = self.sizes[m]
        if n <= 0:
            return b""
        if off >= size or off < 0:
            return bytes(n)
        end = min(off + n, size)
        pg = self.page
        p0, p1 = off // pg, (end - 1) // pg
        if p0 == p1:
            s = off - p0 * pg
            out = self._page(m, p0)[s:s + end - off]
        else:
            parts = []
            for p in range(p0, p1 + 1):
                d = self._page(m, p)
                a = max(off, p * pg) - p * pg
                b = min(end, (p + 1) * pg) - p * pg
                parts.append(d[a:b])
            out = b"".join(parts)
        if end - off < n:
            out += bytes(n - (end - off))
        return out


class LogicalReader:
    """The logical volume of one hypothesis: ``order[slot]`` is a member index,
    MISSING (rebuilt from parity / the mirror) or None (not placed yet: SlotUnknown)."""

    def __init__(self, src: Source, geom: Geometry, order: Sequence[int | None]) -> None:
        self.src = src
        self.g = geom
        self.order = tuple(order)
        present = [m for m in range(src.n)]
        sizes = [src.sizes[m] for m in present]
        self.usable = usable_size(geom, sizes)
        self.size = logical_size(geom, sizes)

    def read(self, off: int, n: int) -> bytes:
        if n <= 0:
            return b""
        end = min(off + n, self.size)
        parts = []
        pos = off
        while pos < end:
            data = self._piece(pos, end - pos)
            parts.append(data)
            pos += len(data)
        out = b"".join(parts)
        if len(out) < n:
            out += bytes(n - len(out))
        return out

    def _slot(self, slot: int, pos: int, n: int, row: int) -> bytes:
        m = self.order[slot]
        if m is None:
            raise SlotUnknown(slot)
        if m != MISSING:
            return self.src.read(m, pos, n)
        g = self.g
        if g.level == "raid5" and self.order.count(MISSING) == 1 and len(self.order) == self.src.n + 1:
            # The missing chunk is the XOR of every other member at this position,
            # whatever slots they sit in: no need to have placed them.
            return xor_blocks([self.src.read(m2, pos, n) for m2 in range(self.src.n)])
        skip = {slot}
        if g.level == "raid6":
            skip.add(raid6_map(g.layout, g.n, row)[1])
        elif g.level not in ("raid5",):
            return bytes(n)
        blocks = []
        for s in range(g.n):
            if s in skip:
                continue
            m2 = self.order[s]
            if m2 is None:
                raise SlotUnknown(s)
            if m2 == MISSING:
                return bytes(n)  # two members missing: nothing to rebuild from
            blocks.append(self.src.read(m2, pos, n))
        return xor_blocks(blocks)

    def _piece(self, L: int, left: int) -> bytes:
        g = self.g
        c = g.chunk
        lv = g.level
        if lv == "raid1":
            for s, m in enumerate(self.order):
                if m is None:
                    raise SlotUnknown(s)
                if m != MISSING:
                    return self.src.read(m, g.offset + L, min(left, 4 * MiB))
            return bytes(min(left, 4 * MiB))
        if lv == "linear":
            start = 0
            for s, m in enumerate(self.order):
                if m is None:
                    raise SlotUnknown(s)
                ln = _linear_len(g, self.src.sizes[m]) if m != MISSING else 0
                if L < start + ln:
                    take = min(left, start + ln - L, 4 * MiB)
                    return self.src.read(m, g.offset + L - start, take)
                start += ln
            return bytes(min(left, 4 * MiB))
        k, w = divmod(L, c)
        take = min(c - w, left)
        if lv == "raid0":
            row, slot = divmod(k, g.n)
        elif lv == "raid5":
            row, d = divmod(k, g.n - 1)
            slot = raid5_map(g.layout, g.n, row)[1][d]
        elif lv == "raid6":
            row, d = divmod(k, g.n - 2)
            slot = raid6_map(g.layout, g.n, row)[2][d]
        elif lv == "raid10":  # md near-2
            row, slot = divmod(2 * k, g.n)
            if self.order[slot] is not None and self.order[slot] == MISSING:
                row, slot = divmod(2 * k + 1, g.n)
        else:
            raise ValueError(f"unknown level {lv}")
        return self._slot(slot, g.offset + row * c + w, take, row)


# -- level statistics --------------------------------------------------------------------

@dataclass
class LevelStats:
    rows: int = 0        # sampled rows with some non-zero block
    multi: int = 0       # rows with at least two non-zero blocks
    equal: int = 0       # rows where every member holds the same (non-zero) block
    xor0: int = 0        # multi rows whose XOR is zero
    qmatch: int = 0      # multi rows whose XOR equals exactly one member's block
    pair_equal: dict[tuple[int, int], int] = field(default_factory=dict)
    pair_rows: dict[tuple[int, int], int] = field(default_factory=dict)
    # (member offset, bit mask of members whose block is zero) of rows where some
    # blocks are zero and at least two are not: a zero block there cannot be parity.
    zero_rows: list[tuple[int, int]] = field(default_factory=list)

    @property
    def mirror(self) -> float:
        return self.equal / self.rows if self.rows else 0.0

    @property
    def parity(self) -> float:
        return self.xor0 / self.multi if self.multi else 0.0

    @property
    def q(self) -> float:
        return self.qmatch / self.multi if self.multi else 0.0

    def pairs(self, n: int, threshold: float = 0.95) -> list[tuple[int, int]] | None:
        """A perfect matching of identical members (raid10 near-2), or None."""
        good = {k for k, v in self.pair_equal.items()
                if self.pair_rows.get(k, 0) >= 3 and v >= threshold * self.pair_rows[k]}
        out, used = [], set()
        for a in range(n):
            if a in used:
                continue
            mates = [b for b in range(n) if b != a and b not in used and (min(a, b), max(a, b)) in good]
            if len(mates) != 1:
                return None
            used |= {a, mates[0]}
            out.append((a, mates[0]))
        return out


def sample_positions(size: int, *, windows: int = 128, win: int = 64 * KiB) -> list[int]:
    """Window starts: a quarter in the first 64 MiB (where metadata gathers), the rest
    spread over the member; never in the first MiB nor the last few (where AMD, IMSM,
    DDF and md 0.90/1.0 keep their metadata). Small members are read whole."""
    top = max(size - win - min(4 * MiB, size // 8), 0)
    if size <= windows * win + MiB:
        return list(range(MiB, top + 1, win))
    head = [MiB + i * 2 * MiB for i in range(windows // 4)]
    rest = windows - len(head)
    spread = [(top * (i + 1) // (rest + 1)) // win * win for i in range(rest)]
    return sorted({p for p in head + spread if MiB <= p <= top})


def level_stats(src: Source, *, windows: int = 128, win: int = 64 * KiB) -> LevelStats:
    st = LevelStats()
    n = src.n
    if src.budget is not None:
        windows = max(4, min(windows, src.budget // 4 // win))   # a quarter of the budget at most
    for pos in sample_positions(min(src.sizes), windows=windows, win=win):
        try:
            bufs = [src.read(m, pos, win) for m in range(n)]
        except BudgetExceeded:
            break
        for o in range(0, win, ROW):
            blocks = [b[o:o + ROW] for b in bufs]
            nz = [not is_zero(b) for b in blocks]
            cnt = sum(nz)
            if not cnt:
                continue
            st.rows += 1
            for a in range(n):
                for b in range(a + 1, n):
                    if nz[a] or nz[b]:
                        st.pair_rows[(a, b)] = st.pair_rows.get((a, b), 0) + 1
                        if blocks[a] == blocks[b]:
                            st.pair_equal[(a, b)] = st.pair_equal.get((a, b), 0) + 1
            if cnt == n and all(b == blocks[0] for b in blocks):
                st.equal += 1
            if cnt >= 2:
                st.multi += 1
                if cnt < n and len(st.zero_rows) < 8192:
                    st.zero_rows.append((pos + o, sum(1 << m for m in range(n) if not nz[m])))
                x = xor_blocks(blocks)
                if is_zero(x):
                    st.xor0 += 1
                elif x in blocks:  # raid6: XOR of everything is Q
                    st.qmatch += 1
    return st


# -- data offsets --------------------------------------------------------------------------

@dataclass(frozen=True)
class Start:
    offset: int
    member: int
    kind: str


def probe_starts(src: Source, grid: Sequence[int] = OFFSET_GRID) -> list[Start]:
    """Volume-start structures at the usual data offsets of every member."""
    out = []
    try:
        for m in range(src.n):
            for o in grid:
                if o + 8 * KiB > src.sizes[m]:
                    break
                head = src.read(m, o, 8 * KiB)
                kind = fswalk.start_kind(head)
                if not kind and is_zero(head) and o + 68 * KiB <= src.sizes[m] \
                        and fswalk.btrfs_super(src.read(m, o + 64 * KiB, 72)):
                    kind = "btrfs"   # btrfs leaves its first 64 KiB empty
                if kind:
                    out.append(Start(o, m, kind))
    except BudgetExceeded:
        pass
    return out


def choose_offsets(starts: Sequence[Start], limit: int = 4) -> list[int]:
    """The data offsets worth trying: where volume starts were found (partition tables
    first, smallest first), else 0."""
    rank = {"gpt": 0, "mbr": 1, "lvm": 2, "luks": 2, "bitlocker": 2}
    best: dict[int, int] = {}
    for s in starts:
        best[s.offset] = min(best.get(s.offset, 9), rank.get(s.kind, 3))
    offs = sorted(best, key=lambda o: (best[o], o))[:limit]
    return sorted(offs) or [0]


# -- the search ----------------------------------------------------------------------------

@dataclass
class Hypothesis:
    geom: Geometry
    order: tuple[int, ...]          # member index per slot, MISSING for a missing member
    result: WalkResult
    unplaced: int = 0               # slots the data never needed (filled in member order)
    prior: float = 0.0
    violations: int = 0             # sampled rows where parity would sit on a zero block
    evidence: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return self.result.score

    @property
    def confidence(self) -> float:
        """0..1: share of checks that passed, discounted for few checks or unplaced slots."""
        r = self.result
        tot = r.passed + r.failed
        if tot <= 0:
            return 0.0
        c = r.passed / tot * min(1.0, r.passed / 24.0)
        if self.unplaced:
            c *= 0.8
        return round(c, 3)


@dataclass
class Analysis:
    stats: LevelStats
    starts: list[Start]
    hypotheses: list[Hypothesis]
    bytes_read: list[int]
    seconds: float
    notes: list[str] = field(default_factory=list)


def walk_with(src: Source, geom: Geometry, order: Sequence[int | None], limit: float) -> WalkResult:
    rd = LogicalReader(src, geom, order)
    return fswalk.run(rd.read, rd.size, limit)


def discover(src: Source, geom: Geometry, members: Sequence[int], *, limit: float, beam: int = 3,
             allow_missing: bool = False, max_walks: int = 4000) -> list[tuple[tuple[int | None, ...], WalkResult]]:
    """Place members in slots, guided by the walk (see the module docstring)."""
    n = geom.n
    start: tuple[int | None, ...] = (None,) * n
    frontier = [(start, walk_with(src, geom, start, limit))]
    done: list[tuple[tuple[int | None, ...], WalkResult]] = []
    seen = {start}
    walks = 1
    while frontier and walks < max_walks:
        nxt = []
        for order, res in frontier:
            if res.unknown is None or res.budget:
                done.append((order, res))
                continue
            j = res.unknown
            used = {x for x in order if x is not None}
            cands = [m for m in members if m not in used]
            if allow_missing and MISSING not in used:
                cands.append(MISSING)
            for m in cands:
                o2 = order[:j] + (m,) + order[j + 1:]
                if o2 in seen:
                    continue
                seen.add(o2)
                walks += 1
                r2 = walk_with(src, geom, o2, limit)
                if r2.unknown is None or r2.budget:
                    done.append((o2, r2))      # finished: does not take a place in the beam
                else:
                    nxt.append((o2, r2))
        nxt.sort(key=lambda t: -t[1].score)
        if len(nxt) > beam:
            cut = nxt[beam - 1][1].score
            nxt = [t for i, t in enumerate(nxt) if i < beam or t[1].score >= cut][:max(beam, 4 * n)]
        frontier = nxt
    done.extend(frontier)
    done.sort(key=lambda t: -t[1].score)
    return done


def _fill(order: tuple[int | None, ...], members: Sequence[int], allow_missing: bool) -> tuple[tuple[int, ...], int]:
    free = [m for m in members if m not in order]
    if allow_missing and MISSING not in order:
        free.append(MISSING)
    out, unplaced = [], 0
    holes = order.count(None)
    for x in order:
        if x is None:
            out.append(free.pop(0) if free else MISSING)
            unplaced += 1
        else:
            out.append(x)
    if holes == 1 and len(free) == 0:
        unplaced = 0  # the last member into the last slot: forced, not guessed
    return tuple(out), unplaced


def _prior(g: Geometry, hints: dict[str, int]) -> float:
    p = 0.0
    if g.chunk and g.chunk in CHUNK_PRIOR:
        p += 0.1 * (len(CHUNK_PRIOR) - CHUNK_PRIOR.index(g.chunk)) / len(CHUNK_PRIOR)
    if hints.get("chunk") and hints["chunk"] == g.chunk:
        p += 0.5
    if hints.get("data_disks") and hints["data_disks"] == g.data_slots:
        p += 0.3
    if g.layout == "left-symmetric":
        p += 0.05
    if g.level == "raid0":
        p += 0.02  # raid0 before "raid5 with a member missing" when the data cannot tell
    p -= g.offset / (1 << 40)
    return p


def level_plans(st: LevelStats, n: int, levels: Sequence[str] | None, allow_missing: bool
                ) -> list[tuple[str, int, bool]]:
    """(level, slots, a member missing) to try, most likely first."""
    want = set(levels or LEVELS)
    plans: list[tuple[str, int, bool]] = []
    informative = st.rows >= 16
    if n >= 2 and "raid1" in want and (st.mirror >= 0.97 or (not informative and st.rows and st.mirror == 1)):
        return [("raid1", n, False)]
    if n >= 4 and n % 2 == 0 and "raid10" in want and st.pairs(n):
        return [("raid10", n, False)]
    if n >= 3 and "raid5" in want and st.multi >= 16 and st.parity >= 0.95:
        # A member of a bigger raid5 may be missing and mostly zero where sampled: the
        # rest then XOR to zero too. The walk tells the two apart.
        return [("raid5", n, False)] + ([("raid5", n + 1, True)] if allow_missing else [])
    if n >= 4 and "raid6" in want and st.multi >= 16 and st.q >= 0.9:
        return [("raid6", n, False)]
    for lv in ("raid0", "linear"):
        if lv in want:
            plans.append((lv, n, False))
    if not informative:
        if n >= 3 and "raid5" in want:
            plans.append(("raid5", n, False))
        if n >= 4 and "raid6" in want:
            plans.append(("raid6", n, False))
        if n >= 2 and "raid1" in want:
            plans.append(("raid1", n, False))
    if allow_missing and n >= 2 and "raid5" in want:
        plans.append(("raid5", n + 1, True))
    return plans


def analyse(src: Source, *, levels: Sequence[str] | None = None, chunks: Sequence[int] = CHUNKS,
            layouts: Sequence[str] = LAYOUTS, offsets: Sequence[int] | None = None,
            allow_missing: bool = True, quick: float = 160, full: float = 2000, beam: int = 3,
            keep: int = 8, top: int = 8) -> Analysis:
    """Rank reconstruction hypotheses for the members behind ``src`` (best first)."""
    t0 = time.monotonic()
    n = src.n
    notes: list[str] = []
    st = level_stats(src)
    starts = probe_starts(src) if offsets is None else []
    offs = list(offsets) if offsets is not None else choose_offsets(starts)
    members = list(range(n))
    plans = level_plans(st, n, levels, allow_missing)
    geoms: list[tuple[Geometry, bool]] = []
    for lv, slots, missing in plans:
        for off in offs:
            if lv == "raid1":
                geoms.append((Geometry("raid1", slots, 0, "", off), False))
            elif lv == "linear":
                for r in (0, 64 * KiB):
                    geoms.append((Geometry("linear", slots, r, "", off), False))
            elif lv in ("raid5", "raid6"):
                for c in chunks:
                    for lay in layouts:
                        geoms.append((Geometry(lv, slots, c, lay, off), missing))
            else:
                for c in chunks:
                    geoms.append((Geometry(lv, slots, c, "", off), missing))
    pairs = st.pairs(n) if any(p[0] == "raid10" for p in plans) else None

    def run(g: Geometry, missing: bool, limit: float, bm: int) -> list[Hypothesis]:
        if g.level == "raid1":
            res = walk_with(src, g, tuple(members), limit)
            return [Hypothesis(g, tuple(members), res)]
        if g.level == "raid10" and pairs:
            half = Geometry("raid0", n // 2, g.chunk, "", g.offset)
            reps = [a for a, _ in pairs]
            mate = dict(pairs)
            out = []
            for order, res in discover(src, half, reps, limit=limit, beam=bm):
                full_o, unplaced = _fill(order, reps, False)
                o10: list[int] = []
                for m in full_o:
                    o10 += [m, mate.get(m, MISSING)]
                out.append(Hypothesis(g, tuple(o10), res, unplaced))
            return out
        out = []
        for order, res in discover(src, g, members, limit=limit, beam=bm, allow_missing=missing):
            full_o, unplaced = _fill(order, members, missing)
            if missing and MISSING not in full_o:
                continue
            out.append(Hypothesis(g, full_o, res, unplaced))
        return out

    # Free pre-filter (no reads): complete raid5/6 geometries that would put parity on
    # zero blocks in the sampled rows, whatever the member order.
    if len(st.zero_rows) >= 32:
        allowed = max(2, min(len(st.zero_rows), 2048) // 100)
        kept = [(g, m) for g, m in geoms
                if m or g.level not in ("raid5", "raid6") or min_violations(st, g) <= allowed]
        if kept:
            dropped = len(geoms) - len(kept)
            if dropped:
                notes.append(f"{dropped} geometries ruled out by parity on sampled rows")
            geoms = kept

    # Successive halving: short walks for every geometry, longer ones for the best.
    hints: dict[str, int] = {}
    pool = [(g, m) for g, m in geoms]
    quick_hyps: list[tuple[Hypothesis, bool]] = []
    for limit, survivors in ((min(24.0, quick), max(3 * keep, 24)), (quick, keep)):
        quick_hyps = []
        for g, missing in pool:
            hs = run(g, missing, limit, 1)
            if hs:
                quick_hyps.append((hs[0], missing))
        if not hints:
            for h, _ in sorted(quick_hyps, key=lambda t: -t[0].score):
                if h.result.hints:
                    hints = dict(h.result.hints)
                    break
        for h, _ in quick_hyps:
            h.prior = _prior(h.geom, hints)
        quick_hyps.sort(key=lambda t: (-t[0].score, -t[0].prior))
        chosen = quick_hyps[:survivors]
        if len(quick_hyps) > survivors:
            cut = quick_hyps[survivors - 1][0].score
            chosen += [t for t in quick_hyps[survivors:] if t[0].score >= cut][:3 * survivors]
        pool = [(h.geom, m) for h, m in chosen]
    final: list[Hypothesis] = []
    for h, missing in chosen:
        for h2 in run(h.geom, missing, full, beam)[:beam]:
            h2.prior = _prior(h2.geom, hints)
            final.append(h2)
    uniq: dict[tuple[Geometry, tuple[int, ...]], Hypothesis] = {}
    for h in final:
        k = (h.geom, h.order)
        if k not in uniq or uniq[k].score < h.score:
            uniq[k] = h
    for h in uniq.values():
        h.violations = parity_violations(st, h.geom, h.order)
    ranked = sorted(uniq.values(), key=lambda h: (-h.score, h.unplaced, h.violations, -h.prior))[:top]
    for h in ranked:
        _explain(h, st, starts, hints)
    def same(a: Hypothesis, b: Hypothesis) -> bool:
        return (a.score, a.unplaced, a.violations) == (b.score, b.unplaced, b.violations)

    if len(ranked) > 1 and same(ranked[0], ranked[1]):
        ties = sum(1 for h in ranked if same(h, ranked[0]))
        msg = (f"{ties} candidates read the checked data identically (it lies in few stripes); "
               "the first is the most common choice")
        ranked[0].evidence.append(msg)
        notes.append(msg)
    if hints:
        notes.append("filesystem hints: " + ", ".join(f"{k}={v}" for k, v in sorted(hints.items())))
    return Analysis(st, starts, ranked, list(src.bytes_read), time.monotonic() - t0, notes)


def _parity_slots(g: Geometry, row: int) -> tuple[int, ...]:
    if g.level == "raid5":
        return (raid5_map(g.layout, g.n, row)[0],)
    return raid6_map(g.layout, g.n, row)[:2]


def min_violations(st: LevelStats, g: Geometry, rows: int = 2048) -> int:
    """The fewest sampled rows putting parity on a zero block, over every member order
    (an assignment of members to slots, solved over bit masks: n <= 8 is cheap)."""
    n = g.n
    cost = [[0] * n for _ in range(n)]   # cost[member][slot]
    for pos, zmask in st.zero_rows[:rows]:
        q = pos - g.offset
        if q < 0:
            continue
        for s in _parity_slots(g, q // g.chunk):
            z, m = zmask, 0
            while z:
                if z & 1:
                    cost[m][s] += 1
                z >>= 1
                m += 1
    best = {0: 0}
    for s in range(n):
        nxt: dict[int, int] = {}
        for mask, c in best.items():
            for m in range(n):
                if not mask >> m & 1:
                    nm, nc = mask | 1 << m, c + cost[m][s]
                    if nc < nxt.get(nm, 1 << 60):
                        nxt[nm] = nc
        best = nxt
    return best.get((1 << n) - 1, 0)


def parity_violations(st: LevelStats, g: Geometry, order: Sequence[int]) -> int:
    """Sampled rows where ``g`` puts parity (P or Q) on a zero block although other
    blocks of the row hold data: impossible in a complete raid5/raid6."""
    if g.level not in ("raid5", "raid6") or MISSING in order or not g.chunk:
        return 0
    bad = 0
    for pos, zmask in st.zero_rows:
        q = pos - g.offset
        if q < 0:
            continue
        row = q // g.chunk
        if g.level == "raid5":
            par = (raid5_map(g.layout, g.n, row)[0],)
        else:
            par = raid6_map(g.layout, g.n, row)[:2]
        if any(zmask >> order[s] & 1 for s in par):
            bad += 1
    return bad


def _explain(h: Hypothesis, st: LevelStats, starts: Sequence[Start], hints: dict[str, int]) -> None:
    r = h.result
    ev = h.evidence
    if r.kinds:
        ev.append("found " + ", ".join(dict.fromkeys(r.kinds)))
    ev.append(f"{int(r.passed)} checks passed, {int(r.failed)} failed ({r.summary()})")
    if h.geom.level in ("raid5", "raid6") and st.multi:
        frac = st.parity if h.geom.level == "raid5" else st.q
        if h.geom.n == len(set(h.order) - {MISSING}):
            ev.append(f"parity consistent in {frac:.0%} of {st.multi} sampled rows")
    if h.geom.level in ("raid1", "raid10") and st.rows:
        ev.append(f"mirrored data in {st.mirror if h.geom.level == 'raid1' else 1:.0%} of sampled rows")
    at = [s for s in starts if s.offset == h.geom.offset]
    if at:
        ev.append(f"volume start ({at[0].kind}) at offset {h.geom.offset} on member {at[0].member}")
    if hints.get("chunk") == h.geom.chunk:
        ev.append(f"the filesystem was made for a {h.geom.chunk // KiB} KiB chunk")
    if h.unplaced:
        ev.append(f"{h.unplaced} member position(s) not checked by the data (guessed)")
    if r.budget:
        ev.append("read budget reached")
