"""Synthetic RAID members for the reconstruction tests (no tools, no root).

make_ext() / make_ntfs() write small but format-correct ext4 / NTFS volumes (the
structures fswalk.py checks, with files and directories spread over the volume);
stripe() cuts a logical volume into member images the way md does. stripe() is an
independent implementation (straight from md's raid5.c switch statements), so the
tests do not check raidmath against itself.
"""

from __future__ import annotations

import random
import struct

KiB = 1024
MiB = 1024 * KiB


# -- md layouts, written out independently of raidmath -----------------------------------

def _raid5_row(layout: str, n: int, row: int) -> tuple[int, list[int]]:
    data_disks = n - 1
    stripe2 = row % n
    if layout == "left-asymmetric":
        pd = data_disks - stripe2
        slots = [d + 1 if d >= pd else d for d in range(data_disks)]
    elif layout == "right-asymmetric":
        pd = stripe2
        slots = [d + 1 if d >= pd else d for d in range(data_disks)]
    elif layout == "left-symmetric":
        pd = data_disks - stripe2
        slots = [(pd + 1 + d) % n for d in range(data_disks)]
    elif layout == "right-symmetric":
        pd = stripe2
        slots = [(pd + 1 + d) % n for d in range(data_disks)]
    else:
        raise ValueError(layout)
    return pd, slots


def _raid6_row(layout: str, n: int, row: int) -> tuple[int, int, list[int]]:
    stripe2 = row % n
    out = []
    if layout in ("left-asymmetric", "right-asymmetric"):
        pd = n - 1 - stripe2 if layout == "left-asymmetric" else stripe2
        for d in range(n - 2):
            if pd == n - 1:
                qd, dd = 0, d + 1
            else:
                qd = pd + 1
                dd = d + 2 if d >= pd else d
            out.append(dd)
        qd = 0 if pd == n - 1 else pd + 1
    else:
        pd = n - 1 - stripe2 if layout == "left-symmetric" else stripe2
        qd = (pd + 1) % n
        out = [(pd + 2 + d) % n for d in range(n - 2)]
    return pd, qd, out


def _xor(blocks: list[bytes]) -> bytes:
    acc = 0
    for b in blocks:
        acc ^= int.from_bytes(b, "little")
    return acc.to_bytes(len(blocks[0]), "little")


def _gf_mul2(b: bytes) -> bytes:
    n = len(b)
    x = int.from_bytes(b, "little")
    hi = x & int.from_bytes(b"\x80" * n, "little")
    lo = (x & int.from_bytes(b"\x7f" * n, "little")) << 1
    return (lo ^ ((hi >> 7) * 0x1D)).to_bytes(n, "little")


def stripe(vol: bytes, level: str, n: int, chunk: int = 64 * KiB, layout: str = "left-symmetric",
           offset: int = 0, tail: int = 0, sizes: list[int] | None = None, junk: int = 0) -> list[bytearray]:
    """Member images holding ``vol``. ``offset`` bytes before the data and ``tail`` after
    it (filled with seeded junk when ``junk`` is set: metadata nobody understands)."""
    rng = random.Random(junk or 1)

    def blank(size: int) -> bytearray:
        m = bytearray(size)
        if junk:
            if offset >= 8 * KiB:
                m[4096:4096 + 512] = rng.randbytes(512)      # a wiped-but-not-quite superblock
            if tail:
                m[size - tail:] = rng.randbytes(tail)
        return m

    if level == "linear":
        assert sizes and len(sizes) == n
        members = [blank(offset + s + tail) for s in sizes]
        pos = 0
        for m, s in zip(members, sizes):
            m[offset:offset + s] = vol[pos:pos + s].ljust(s, b"\0")
            pos += s
        return members
    data = {"raid0": n, "raid1": 1, "raid10": n // 2, "raid5": n - 1, "raid6": n - 2}[level]
    if level == "raid1":
        return [_with(blank(offset + len(vol) + tail), offset, vol) for _ in range(n)]
    assert len(vol) % (chunk * data) == 0, "volume must be whole stripes"
    rows = len(vol) // (chunk * data) if level != "raid10" else len(vol) // chunk * 2 // n
    per = rows * chunk
    members = [blank(offset + per + tail) for _ in range(n)]
    nchunks = len(vol) // chunk
    if level == "raid0":
        for k in range(nchunks):
            row, dev = divmod(k, n)
            members[dev][offset + row * chunk:offset + (row + 1) * chunk] = vol[k * chunk:(k + 1) * chunk]
    elif level == "raid10":
        for k in range(nchunks):
            for a in (2 * k, 2 * k + 1):
                row, dev = divmod(a, n)
                members[dev][offset + row * chunk:offset + (row + 1) * chunk] = vol[k * chunk:(k + 1) * chunk]
    else:
        for row in range(rows):
            ks = range(row * data, (row + 1) * data)
            ds = [bytes(vol[k * chunk:(k + 1) * chunk]) for k in ks]
            if level == "raid5":
                pd, slots = _raid5_row(layout, n, row)
                qd = None
            else:
                pd, qd, slots = _raid6_row(layout, n, row)
            at = offset + row * chunk
            for d, s in zip(ds, slots):
                members[s][at:at + chunk] = d
            members[pd][at:at + chunk] = _xor(ds)
            if qd is not None:
                q = ds[-1]
                for d in reversed(ds[:-1]):
                    q = _xor([_gf_mul2(q), d])
                members[qd][at:at + chunk] = q
    return members


def _with(m: bytearray, offset: int, vol: bytes) -> bytearray:
    m[offset:offset + len(vol)] = vol
    return m


# -- a small ext4 ----------------------------------------------------------------------------

def _tree(rng: random.Random, dirs: int, files: int) -> list[tuple[str, int, bytes]]:
    """(path, kind 1=file 2=dir, data) in creation order."""
    out = []
    paths: list[str] = []
    for i in range(dirs):
        parent = "" if i < 3 else paths[rng.randrange(0, i)] + "/"
        paths.append(parent + f"d{i:02d}")
        out.append((paths[-1], 2, b""))
    for i in range(files):
        parent = rng.choice([""] + paths)
        size = rng.choice((300, 2000, 5000, 9000, 20000, 40000))
        if rng.random() < 0.5:
            data = rng.randbytes(size)
        else:
            words = [rng.choice(("disk", "array", "beast", "boot", "stripe", "parity", "chunk", "data"))
                     for _ in range(size // 5 + 1)]
            data = " ".join(words).encode()[:size]
        out.append(((parent + "/" if parent else "") + f"f{i:03d}.bin", 1, data))
    return out


class _Alloc:
    def __init__(self, rng: random.Random, lo: int, hi: int, reserved: set[int]) -> None:
        self.rng, self.lo, self.hi = rng, lo, hi
        self.used = set(reserved)

    def run(self, k: int) -> int:
        for _ in range(10000):
            s = self.rng.randrange(self.lo, self.hi - k)
            if all(b not in self.used for b in range(s, s + k)):
                self.used.update(range(s, s + k))
                return s
        raise RuntimeError("volume full")


def make_ext(size: int, *, bs: int = 4096, bpg: int = 2048, ipg: int = 256, isz: int = 256,
             dirs: int = 12, files: int = 60, seed: int = 1, stride: int = 0, width: int = 0) -> bytes:
    rng = random.Random(seed)
    blocks = size // bs
    fdb = 1 if bs == 1024 else 0
    groups = (blocks - fdb + bpg - 1) // bpg
    itb = ipg * isz // bs
    img = bytearray(blocks * bs)
    backups = {0, 1} | {p ** k for p in (3, 5, 7) for k in range(1, 12) if p ** k < groups}
    reserved = set(range(0, fdb + 2))
    for g in backups:
        if g < groups:
            reserved |= {fdb + g * bpg, fdb + g * bpg + 1}
    meta = fdb + 2
    bb0, ib0, it0 = meta, meta + groups, meta + 2 * groups
    data0 = it0 + groups * itb
    reserved |= set(range(meta, data0))
    alloc = _Alloc(rng, data0, blocks, reserved)
    uuid = rng.randbytes(16)
    inodes: dict[int, bytes] = {}
    next_idx = {g: 0 for g in range(groups)}
    next_idx[0] = 11  # 1..11 taken (root 2, journal 8, lost+found 11)

    def new_ino(g: int) -> int:
        for k in range(groups):
            gg = (g + k) % groups
            if next_idx[gg] < ipg:
                next_idx[gg] += 1
                return gg * ipg + next_idx[gg]
        raise RuntimeError("no inodes")

    def extents(nblk: int) -> list[tuple[int, int, int]]:
        parts = 1 if nblk < 3 else rng.choice((1, 2, 3))
        out, lb = [], 0
        sizes = [nblk // parts] * parts
        sizes[-1] += nblk - sum(sizes)
        for s in sizes:
            out.append((lb, s, alloc.run(s)))
            lb += s
        return out

    def make_inode(mode: int, links: int, length: int, ext: list[tuple[int, int, int]]) -> bytes:
        ino = bytearray(isz)
        struct.pack_into("<HHI", ino, 0, mode, 0, length & 0xFFFFFFFF)
        struct.pack_into("<H", ino, 26, links)
        struct.pack_into("<I", ino, 28, sum(e[1] for e in ext) * (bs // 512))
        struct.pack_into("<I", ino, 32, 0x80000)
        struct.pack_into("<HHHHI", ino, 40, 0xF30A, len(ext), 4, 0, 0)
        for i, (lb, ln, pb) in enumerate(ext):
            struct.pack_into("<IHHI", ino, 52 + 12 * i, lb, ln, pb >> 32, pb & 0xFFFFFFFF)
        struct.pack_into("<I", ino, 100, rng.getrandbits(32))
        if isz > 128:
            struct.pack_into("<H", ino, 128, 32)
        return bytes(ino)

    def dir_block(entries: list[tuple[int, int, bytes]]) -> bytes:
        blk = bytearray(bs)
        pos = 0
        for i, (ino, ft, name) in enumerate(entries):
            rl = (8 + len(name) + 3) // 4 * 4
            if i == len(entries) - 1:
                rl = bs - pos
            struct.pack_into("<IHBB", blk, pos, ino, rl, len(name), ft)
            blk[pos + 8:pos + 8 + len(name)] = name
            pos += rl
        return bytes(blk)

    # journal (inode 8) in the middle, allocated first
    jlen = min(1024, blocks // 16)
    alloc.lo = blocks // 2 - jlen
    jstart = alloc.run(jlen)
    alloc.lo = data0
    tree = _tree(rng, dirs, files)
    dir_ino = {"": 2}
    children: dict[str, list[tuple[int, int, bytes]]] = {"": []}
    subdirs: dict[str, int] = {"": 1}
    for k, (path, kind, data) in enumerate(tree):
        parent, _, name = path.rpartition("/")
        pino = dir_ino[parent]
        if kind == 2:
            ino = new_ino((k * 5 + 1) % groups)
            dir_ino[path] = ino
            children[path] = []
            subdirs[path] = 0
            subdirs[parent] += 1
        else:
            ino = new_ino((pino - 1) // ipg)
            nblk = max(1, (len(data) + bs - 1) // bs)
            ext = extents(nblk)
            buf = data.ljust(nblk * bs, b"\0")
            pos = 0
            for lb, ln, pb in ext:
                img[pb * bs:(pb + ln) * bs] = buf[pos:pos + ln * bs]
                pos += ln * bs
            inodes[ino] = make_inode(0x81A4, 1, len(data), ext)
        children[parent].append((ino, kind, name.encode()))
    # lost+found and the directories themselves
    lf = alloc.run(1)
    img[lf * bs:(lf + 1) * bs] = dir_block([(11, 2, b"."), (2, 2, b"..")])
    inodes[11] = make_inode(0x41C0, 2, bs, [(0, 1, lf)])
    children[""].insert(0, (11, 2, b"lost+found"))
    for path, ino in dir_ino.items():
        parent = path.rpartition("/")[0] if path else ""
        pino = dir_ino[parent] if path else 2
        blk = alloc.run(1)
        img[blk * bs:(blk + 1) * bs] = dir_block([(ino, 2, b"."), (pino, 2, b"..")] + children[path])
        inodes[ino] = make_inode(0x41ED, 2 + subdirs[path] + (1 if not path else 0), bs, [(0, 1, blk)])
    struct.pack_into(">III", img, jstart * bs, 0xC03B3998, 4, 0)
    struct.pack_into(">III", img, jstart * bs + 12, bs, jlen, 1)
    inodes[8] = make_inode(0x8180, 1, jlen * bs, [(0, jlen, jstart)])
    # inode tables and bitmaps
    for ino, raw in inodes.items():
        g, idx = divmod(ino - 1, ipg)
        at = (it0 + g * itb) * bs + idx * isz
        img[at:at + isz] = raw
    free_b: dict[int, int] = {}
    for g in range(groups):
        bm = bytearray(bs)
        used = 0
        for b in alloc.used:
            if fdb + g * bpg <= b < min(fdb + (g + 1) * bpg, blocks):
                i = b - fdb - g * bpg
                bm[i // 8] |= 1 << (i % 8)
                used += 1
        free_b[g] = min(bpg, blocks - fdb - g * bpg) - used
        img[(bb0 + g) * bs:(bb0 + g + 1) * bs] = bm
        im = bytearray(bs)
        for i in range(next_idx[g]):
            im[i // 8] |= 1 << (i % 8)
        img[(ib0 + g) * bs:(ib0 + g + 1) * bs] = im
    # superblock + GDT copies
    gdt = bytearray(bs)
    for g in range(groups):
        struct.pack_into("<IIIHHHH", gdt, g * 32, bb0 + g, ib0 + g, it0 + g * itb, free_b[g], ipg - next_idx[g], 0, 0)
    for g in sorted(backups):
        if g >= groups:
            continue
        sb = bytearray(1024)
        struct.pack_into("<IIIIIIIIIII", sb, 0, groups * ipg, blocks, 0, 0, 0, fdb, bs.bit_length() - 11,
                         bs.bit_length() - 11, bpg, bpg, ipg)
        struct.pack_into("<HHHH", sb, 56, 0xEF53, 1, 1, 0)
        struct.pack_into("<I", sb, 76, 1)
        struct.pack_into("<IHH", sb, 84, 11, isz, g)
        struct.pack_into("<III", sb, 92, 0x4, 0x2 | 0x40, 0x1 | 0x2)
        sb[104:120] = uuid
        struct.pack_into("<I", sb, 224, 8)
        struct.pack_into("<H", sb, 356, stride)
        struct.pack_into("<I", sb, 368, width)
        at = (fdb + g * bpg) * bs + (1024 if (g == 0 and bs > 1024) else 0)
        img[at:at + 1024] = sb
        img[(fdb + g * bpg + 1) * bs:(fdb + g * bpg + 2) * bs] = gdt
    return bytes(img)


# -- a small NTFS ------------------------------------------------------------------------------

def _runlist(runs: list[tuple[int, int]]) -> bytes:
    out = bytearray()
    prev = 0
    for lcn, count in runs:
        ln = (count.bit_length() + 7) // 8 or 1
        delta = lcn - prev
        ob = 1
        while not -(1 << (8 * ob - 1)) <= delta < (1 << (8 * ob - 1)):
            ob += 1
        out.append(ln | (ob << 4))
        out += count.to_bytes(ln, "little") + delta.to_bytes(ob, "little", signed=True)
        prev = lcn
    return bytes(out + b"\0")


def _attr_resident(t: int, value: bytes, name: str = "") -> bytes:
    nm = name.encode("utf-16-le")
    voff = (24 + len(nm) + 7) // 8 * 8
    ln = (voff + len(value) + 7) // 8 * 8
    a = bytearray(ln)
    struct.pack_into("<IIBBHHH", a, 0, t, ln, 0, len(name), 24 if name else 0, 0, 0)
    struct.pack_into("<IH", a, 16, len(value), voff)
    a[24:24 + len(nm)] = nm
    a[voff:voff + len(value)] = value
    return bytes(a)


def _attr_nonres(t: int, runs: list[tuple[int, int]], size: int, cl: int, name: str = "") -> bytes:
    nm = name.encode("utf-16-le")
    mp = (64 + len(nm) + 7) // 8 * 8
    rl = _runlist(runs)
    ln = (mp + len(rl) + 7) // 8 * 8
    clusters = sum(c for _, c in runs)
    a = bytearray(ln)
    struct.pack_into("<IIBBHHH", a, 0, t, ln, 1, len(name), 64 if name else 0, 0, 0)
    struct.pack_into("<QQH", a, 16, 0, clusters - 1, mp)
    struct.pack_into("<QQQ", a, 40, clusters * cl, size, size)
    a[64:64 + len(nm)] = nm
    a[mp:mp + len(rl)] = rl
    return bytes(a)


def _fixup(buf: bytearray, usa_ofs: int, usn: int = 1) -> None:
    count = len(buf) // 512 + 1
    struct.pack_into("<HH", buf, 4, usa_ofs, count)
    struct.pack_into("<H", buf, usa_ofs, usn)
    for i in range(1, count):
        end = i * 512
        buf[usa_ofs + 2 * i:usa_ofs + 2 * i + 2] = buf[end - 2:end]
        struct.pack_into("<H", buf, end - 2, usn)


def _fname(parent: int, name: str, size: int = 0, is_dir: bool = False) -> bytes:
    nm = name.encode("utf-16-le")
    v = bytearray(66 + len(nm))
    struct.pack_into("<Q", v, 0, parent | (1 << 48))
    struct.pack_into("<QQI", v, 40, size, size, 0x10000000 if is_dir else 0x20)
    v[64] = len(name)
    v[65] = 1
    v[66:] = nm
    return bytes(v)


def _index_entries(entries: list[tuple[int, bytes]], end_vcn: int | None) -> bytes:
    out = bytearray()
    for ref, key in entries:
        ln = (16 + len(key) + 7) // 8 * 8
        e = bytearray(ln)
        struct.pack_into("<QHHI", e, 0, ref | (1 << 48), ln, len(key), 0)
        e[16:16 + len(key)] = key
        out += e
    if end_vcn is None:
        out += struct.pack("<QHHI", 0, 16, 0, 2)
    else:
        out += struct.pack("<QHHIQ", 0, 24, 0, 3, end_vcn)
    return bytes(out)


def make_ntfs(size: int, *, cluster: int = 4096, dirs: int = 10, files: int = 60, seed: int = 2) -> bytes:
    rng = random.Random(seed)
    rs, ixs = 1024, 4096
    ncl = size // cluster
    img = bytearray(ncl * cluster)
    tree = _tree(rng, dirs, files)
    nrec = (24 + len(tree) + 16 + 3) // 4 * 4
    mft_clusters = nrec * rs // cluster + (1 if nrec * rs % cluster else 0)
    alloc = _Alloc(rng, 8, ncl, {0, 1, 2, 3})
    half = mft_clusters // 2 or 1
    mft_lcn = max(16, ncl // 3)
    alloc.used.update(range(mft_lcn, mft_lcn + half))
    runs = [(mft_lcn, half)]
    if mft_clusters - half:
        runs.append((alloc.run(mft_clusters - half), mft_clusters - half))
    mirr = 4
    alloc.used.update(range(mirr, mirr + max(1, 4 * rs // cluster)))
    records: dict[int, bytearray] = {}

    def record(k: int, flags: int, attrs: list[bytes]) -> None:
        r = bytearray(rs)
        r[0:4] = b"FILE"
        struct.pack_into("<HHHH", r, 16, 1, 1, 0x38, flags)  # sequence, links, first attribute, flags
        struct.pack_into("<I", r, 28, rs)
        struct.pack_into("<I", r, 44, k)
        pos = 0x38
        for a in attrs:
            r[pos:pos + len(a)] = a
            pos += len(a)
        struct.pack_into("<I", r, pos, 0xFFFFFFFF)
        struct.pack_into("<I", r, 24, pos + 8)
        records[k] = r

    si = bytes(72)
    dir_rec = {"": 5}
    kids: dict[str, list[tuple[int, bytes]]] = {"": []}
    k = 24
    for path, kind, data in tree:
        parent, _, name = path.rpartition("/")
        pk = dir_rec[parent]
        fn = _fname(pk, name, len(data), kind == 2)
        if kind == 2:
            dir_rec[path] = k
            kids[path] = []
        else:
            if len(data) <= 600:
                attrs = [_attr_resident(0x10, si), _attr_resident(0x30, fn), _attr_resident(0x80, data)]
            else:
                nc = (len(data) + cluster - 1) // cluster
                lcn = alloc.run(nc)
                img[lcn * cluster:lcn * cluster + len(data)] = data
                attrs = [_attr_resident(0x10, si), _attr_resident(0x30, fn),
                         _attr_nonres(0x80, [(lcn, nc)], len(data), cluster)]
            record(k, 0x1, attrs)
        kids[parent].append((k, fn))
        k += 1
    for path, rk in dir_rec.items():
        parent = path.rpartition("/")[0]
        name = path.rpartition("/")[2] if path else "."
        ents = sorted(kids[path], key=lambda e: e[1][66:])
        per = 40
        blocks = [ents[i:i + per] for i in range(0, max(len(ents), 1), per)]
        nblk = len(blocks)
        lcn = alloc.run(nblk * ixs // cluster or 1)
        for vb, chunk in enumerate(blocks):
            ix = bytearray(ixs)
            ix[0:4] = b"INDX"
            vcn = vb * ixs // cluster if ixs >= cluster else vb * ixs // 512
            struct.pack_into("<Q", ix, 16, vcn)
            body = _index_entries(chunk, None)
            struct.pack_into("<IIIB", ix, 24, 0x28, 0x28 + len(body), ixs - 24, 0)
            ix[0x40:0x40 + len(body)] = body
            _fixup(ix, 0x28)
            at = lcn * cluster + vb * ixs
            img[at:at + ixs] = ix
        root_ents = _index_entries([], 0)
        ir = bytearray(16 + 16)
        struct.pack_into("<IIIB", ir, 0, 0x30, 1, ixs, max(1, ixs // cluster))
        struct.pack_into("<IIIB", ir, 16, 16, 16 + len(root_ents), 16 + len(root_ents), 1)
        ir = bytes(ir) + root_ents
        attrs = [_attr_resident(0x10, si), _attr_resident(0x30, _fname(dir_rec.get(parent, 5), name, 0, True)),
                 _attr_resident(0x90, ir, "$I30"),
                 _attr_nonres(0xA0, [(lcn, nblk * ixs // cluster or 1)], nblk * ixs, cluster, "$I30"),
                 _attr_resident(0xB0, b"\xff" * 8, "$I30")]
        record(rk, 0x3, attrs)
    record(0, 0x1, [_attr_resident(0x10, si), _attr_resident(0x30, _fname(5, "$MFT")),
                    _attr_nonres(0x80, runs, nrec * rs, cluster)])
    record(1, 0x1, [_attr_resident(0x10, si), _attr_resident(0x30, _fname(5, "$MFTMirr")),
                    _attr_nonres(0x80, [(mirr, max(1, 4 * rs // cluster))], 4 * rs, cluster)])
    for i in range(2, 24):
        if i != 5:
            record(i, 0x1 if i < 16 else 0, [_attr_resident(0x10, si), _attr_resident(0x30, _fname(5, f"$S{i}"))])
    for i in range(k, nrec):
        record(i, 0, [])
    pos_of = []
    for lcn, count in runs:
        for c in range(count * cluster // rs):
            pos_of.append(lcn * cluster + c * rs)
    for i in range(nrec):
        r = bytearray(records[i])
        _fixup(r, 0x30)
        img[pos_of[i]:pos_of[i] + rs] = r
        if i < 4:
            img[mirr * cluster + i * rs:mirr * cluster + (i + 1) * rs] = r
    bs = bytearray(512)
    bs[0:3] = b"\xeb\x52\x90"
    bs[3:11] = b"NTFS    "
    struct.pack_into("<HB", bs, 11, 512, cluster // 512)
    bs[21] = 0xF8
    struct.pack_into("<QQQ", bs, 40, size // 512 - 1, mft_lcn, mirr)
    bs[64] = 0xF6                                    # 2**10 = 1024-byte records
    bs[68] = 1 if cluster == 4096 else 0xF4          # 4096-byte index blocks
    bs[72:80] = rng.randbytes(8)
    bs[510:512] = b"\x55\xaa"
    img[0:512] = bs
    img[len(img) - 512:] = bs
    return bytes(img)


def with_gpt(vol_size: int, part: bytes, start: int = MiB) -> bytes:
    """A GPT disk image of ``vol_size`` bytes with one partition holding ``part``."""
    import binascii
    img = bytearray(vol_size)
    lbas = vol_size // 512
    first, last = start // 512, start // 512 + len(part) // 512 - 1
    ent = bytearray(128 * 128)
    ent[0:16] = bytes.fromhex("A2A0D0EBE5B9334487C068B6B72699C7")  # Microsoft basic data
    ent[16:32] = random.Random(7).randbytes(16)
    struct.pack_into("<QQ", ent, 32, first, last)
    ecrc = binascii.crc32(bytes(ent))

    def header(my: int, alt: int, elba: int) -> bytes:
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", h, 8, 0x10000, 92, 0, 0, my, alt, 34, lbas - 34)
        h[56:72] = random.Random(8).randbytes(16)
        struct.pack_into("<QIII", h, 72, elba, 128, 128, ecrc)
        struct.pack_into("<I", h, 16, binascii.crc32(bytes(h)))
        return bytes(h)

    img[446 + 4] = 0xEE
    struct.pack_into("<II", img, 446 + 8, 1, min(lbas - 1, 0xFFFFFFFF))
    img[510:512] = b"\x55\xaa"
    img[512:512 + 92] = header(1, lbas - 1, 2)
    img[1024:1024 + len(ent)] = ent
    img[(lbas - 33) * 512:(lbas - 33) * 512 + len(ent)] = ent
    img[(lbas - 1) * 512:(lbas - 1) * 512 + 92] = header(lbas - 1, 1, lbas - 33)
    img[start:start + len(part)] = part
    return bytes(img)


# -- whole cases ---------------------------------------------------------------------------------

DATA_SLOTS = {"raid0": lambda n: n, "raid1": lambda n: 1, "raid10": lambda n: n // 2,
              "raid5": lambda n: n - 1, "raid6": lambda n: n - 2, "linear": lambda n: n}


def build_case(level: str, n: int, chunk: int = 64 * KiB, layout: str = "", *, fs: str = "ext",
               offset: int = MiB, size: int = 24 * MiB, missing: int | None = None, tail: int = 0,
               junk: int = 0, seed: int = 1, gpt: bool = False):
    """Members (shuffled; the member in slot ``missing`` dropped) and the truth:
    dict(level, n, chunk, layout, offset, order), order = member index per slot (-1: dropped)."""
    rng = random.Random(seed)
    data = DATA_SLOTS[level](n)
    unit = (chunk or 4 * KiB) * data if level not in ("raid1", "linear") else 64 * KiB
    vsize = size // unit * unit
    inner = vsize - 2 * MiB if gpt else vsize
    if fs == "ext":
        vol = make_ext(inner, seed=seed)
    elif fs == "ntfs":
        vol = make_ntfs(inner, seed=seed)
    else:
        vol = rng.randbytes(inner)
    if gpt:
        vol = with_gpt(vsize, vol)
    sizes = None
    if level == "linear":
        cut = [vsize // n // 4096 * 4096 + rng.randrange(0, 64) * 4096 for _ in range(n - 1)]
        sizes = cut + [vsize - sum(cut)]
    members = stripe(vol, level, n, chunk, layout, offset=offset, tail=tail, sizes=sizes, junk=junk)
    perm = list(range(n))
    rng.shuffle(perm)
    shuffled = [members[p] for p in perm]
    order = [perm.index(s) for s in range(n)]
    if missing is not None:
        gone = order[missing]
        shuffled.pop(gone)
        order = [-1 if o == gone else (o - 1 if o > gone else o) for o in order]
    truth = dict(level=level, n=n, chunk=chunk if level not in ("raid1", "linear") else 0,
                 layout=layout if level in ("raid5", "raid6") else "", offset=offset, order=order)
    return shuffled, truth, vol


def matches(h, truth) -> bool:
    """Is hypothesis ``h`` (raidmath.Hypothesis) the truth? raid1: any order; raid10: the
    pairs in order, either copy first."""
    g = h.geom
    if (g.level, g.n, g.chunk, g.layout, g.offset) != (truth["level"], truth["n"], truth["chunk"],
                                                      truth["layout"], truth["offset"]):
        return False
    if g.level == "raid1":
        return True
    if g.level == "raid10":
        a = [frozenset(h.order[i:i + 2]) for i in range(0, g.n, 2)]
        b = [frozenset(truth["order"][i:i + 2]) for i in range(0, g.n, 2)]
        return a == b
    return list(h.order) == list(truth["order"])
