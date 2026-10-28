"""Synthetic Windows-like UDF bridge images for the UDF reader tests.

Pure (struct only), so the beast-net helper's tests (beastnet/tests) import it too.
"""

from __future__ import annotations

import struct

S = 2048
PART = 270  # first sector of the partition


def tag(ident: int, body: bytes, loc: int = 0) -> bytes:
    """A descriptor: 16-byte tag + body, padded to a sector."""
    raw = bytearray(struct.pack("<HHBBHHHI", ident, 2, 0, 0, 0, 0, len(body), loc))
    raw += body
    raw += bytes(S - len(raw))
    raw[4] = (sum(raw[:4]) + sum(raw[5:16])) & 0xFF
    return bytes(raw)


def fid(name: str, is_dir: bool, lbn: int) -> bytes:
    nm = b"\x08" + name.encode("latin-1")
    long_ad = struct.pack("<IIH6x", S, lbn, 0)
    ent = bytearray(struct.pack("<H", 1) + bytes([2 if is_dir else 0, len(nm)]) + long_ad + struct.pack("<H", 0) + nm)
    full = bytearray(16) + ent  # tag room
    full[0:16] = tag(257, b"")[:16]
    while len(full) % 4:
        full.append(0)
    # fix tag id/checksum for the FID (length irrelevant to the reader)
    t = bytearray(struct.pack("<HHBBHHHI", 257, 2, 0, 0, 0, 0, 0, 0))
    t[4] = (sum(t[:4]) + sum(t[5:16])) & 0xFF
    full[0:16] = t
    return bytes(full)


def fe(is_dir: bool, size: int, ads: bytes, kind: int, ident: int = 261) -> bytes:
    body = bytearray(S)
    icb = struct.pack("<IHHHBB", 0, 4, 0, 1, 0, 4 if is_dir else 5)
    body[16:16 + len(icb)] = icb
    struct.pack_into("<H", body, 34, kind)
    struct.pack_into("<Q", body, 56, size)
    if ident == 261:
        struct.pack_into("<II", body, 168, 0, len(ads))
        base = 176
    else:
        struct.pack_into("<II", body, 208, 0, len(ads))
        base = 216
    body[base:base + len(ads)] = ads
    t = bytearray(struct.pack("<HHBBHHHI", ident, 2, 0, 0, 0, 0, 0, 0))
    body[0:16] = t
    body[4] = (sum(body[:4]) + sum(body[5:16])) & 0xFF
    return bytes(body)


def build_image(wim: bytes, with_install: bool = True) -> bytes:
    n_total = 400 + (len(wim) + S - 1) // S
    img = bytearray(n_total * S)

    def put(sector: int, data: bytes) -> None:
        img[sector * S:sector * S + len(data)] = data

    pvd = bytearray(S)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[40:72] = b"CCCOMA_X64FRE_EN-US_DV9".ljust(32)
    pvd[813:829] = b"0000000000000000"
    pvd[830:846] = b"2026091412345678"
    put(16, bytes(pvd))
    term = bytearray(S)
    term[0], term[1:6], term[6] = 255, b"CD001", 1
    put(17, bytes(term))

    # layout (partition-relative blocks): 0 FSD, 1 root FE, 2 root dir, 3 sources FE, 4 sources dir,
    # 5 boot.wim FE, 6 install.wim FE, 7 readme FE, 8.. data
    avdp = struct.pack("<IIII", 3 * S, 257, 3 * S, 257) + b""
    put(256, tag(2, avdp[0:0] + bytes(0), 256)[:16] + struct.pack("<II", 3 * S, 257) + struct.pack("<II", 3 * S, 257)
        + bytes(S - 32))
    # fix AVDP checksum (tag body was empty, rebuild properly)
    a = bytearray(img[256 * S:257 * S])
    a[4] = (sum(a[:4]) + sum(a[5:16])) & 0xFF
    put(256, bytes(a))

    pd = bytearray(S)
    struct.pack_into("<H", pd, 22, 0)
    struct.pack_into("<II", pd, 188, PART, n_total - PART)
    put(257, tag(5, b"")[:16] + bytes(pd[16:]))
    lv = bytearray(S)
    struct.pack_into("<I", lv, 212, S)
    struct.pack_into("<IH", lv, 248, S, 0)  # placeholder, fixed next
    struct.pack_into("<IIH", lv, 248, S, 0, 0)  # long_ad: length, lbn 0, partition ref 0
    struct.pack_into("<II", lv, 264, 6, 1)
    lv[440:446] = bytes([1, 6]) + struct.pack("<HH", 1, 0)
    put(258, tag(6, b"")[:16] + bytes(lv[16:]))
    put(259, tag(8, b""))
    for sec in (257, 258, 259):
        a = bytearray(img[sec * S:(sec + 1) * S])
        a[4] = (sum(a[:4]) + sum(a[5:16])) & 0xFF
        put(sec, bytes(a))
    # the descriptors above were built with tag().. but seq number zero is fine

    def pb(b: int) -> int:
        return PART + b

    fsd = bytearray(S)
    struct.pack_into("<IIH", fsd, 400, S, 1, 0)
    fsd[0:16] = tag(256, b"")[:16]
    put(pb(0), bytes(fsd))
    root_dir = fid("README.TXT", False, 7) + fid("Sources", True, 3)
    put(pb(2), root_dir)
    put(pb(1), fe(True, len(root_dir), struct.pack("<II", len(root_dir), 2), 0))
    src = fid("boot.WIM", False, 5) + (fid("install.wim", False, 6) if with_install else b"")
    put(pb(4), src)
    put(pb(3), fe(True, len(src), struct.pack("<II", len(src), 4), 0))
    # boot.wim in two short extents (first one split mid-way), data from block 10
    half = (len(wim) // 2) // S * S
    def nb(n: int) -> int:
        return (n + S - 1) // S

    first = struct.pack("<II", half, 10)
    second = struct.pack("<II", len(wim) - half, 10 + nb(half) + 3)  # gap of 3 blocks
    put(pb(10), wim[:half])
    put(pb(10 + nb(half) + 3), wim[half:])
    put(pb(5), fe(False, len(wim), first + second, 0, ident=266))
    # install.wim: long ad with a not-recorded (zero) extent
    zero_ext = struct.pack("<IIH6x", (1 << 30) | 4096, 0, 0)
    put(pb(6), fe(False, 4096, zero_ext, 1))
    put(pb(7), fe(False, 5, b"hello", 3))  # inline
    return bytes(img)


def wim_bytes(n: int = 70000) -> bytes:
    return b"MSWIM\0\0\0" + bytes((i * 7) & 0xFF for i in range(n - 8))
