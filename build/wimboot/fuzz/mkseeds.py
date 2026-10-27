#!/usr/bin/env python3
"""Make seed inputs for the wimboot fuzz harnesses (build/wimboot/fuzz/).

Writes OUT/{wim,lzx,xca,cpio}/. The WIM seeds are small but complete
images with \\Windows\\Boot\\EFI\\bootmgfw.efi and \\Windows\\System32, in
three flavours: uncompressed, XPRESS Huffman (XCA) compressed with a small
encoder below, and LZX. wimlib is not needed. LZX needs real compressed
chunks: pass --from-wim PATH (any LZX WIM, e.g. sources/boot.wim of a
Windows ISO) and the LZX seeds are chunks copied out of it; without it the
LZX corpus starts from the WIM seeds' raw chunks only.

Usage: mkseeds.py OUT [--from-wim boot.wim]
"""
import argparse
import hashlib
import struct
from pathlib import Path

CHUNK = 32768
RES_METADATA, RES_COMPRESSED = 0x02, 0x04
HDR_COMPRESSION, HDR_XPRESS, HDR_LZX = 0x00000002, 0x00020000, 0x00040000


# --- XPRESS Huffman (MS-XCA) encoder: every symbol has a 9-bit code -------

def xca_compress(data: bytes) -> bytes:
    """One block (<= 64 KiB). All 512 code lengths are 9, so the canonical
    code of a symbol is the symbol itself. Matches are 3..17 bytes long so
    that no extra length bytes are interleaved in the bit stream."""
    assert len(data) <= 65536
    syms = []  # (value, nbits)
    i, n = 0, len(data)
    while i < n:
        best_len, best_off = 0, 0
        for off in (1, 2, 3, 4, 8, 16, 32, 64, 100, 128, 256, 512, 1024):
            if off > i:
                break
            ln = 0
            while ln < 17 and i + ln < n and data[i + ln] == data[i + ln - off]:
                ln += 1
            if ln > best_len:
                best_len, best_off = ln, off
        if best_len >= 3:
            ob = best_off.bit_length() - 1
            syms.append((256 + (ob << 4) + (best_len - 3), 9))
            if ob:
                syms.append((best_off - (1 << ob), ob))
            i += best_len
        else:
            syms.append((data[i], 9))
            i += 1
    syms.append((256, 9))  # end marker
    bits = "".join(format(v, f"0{nb}b") for v, nb in syms)
    table = bytes([0x99]) * 256  # 512 nibbles of 9
    for extra in range(0, 4):
        nwords = (len(bits) + 15) // 16 + extra
        b = bits.ljust(nwords * 16, "0")
        words = b"".join(struct.pack("<H", int(b[k:k + 16], 2)) for k in range(0, len(b), 16))
        out = table + words
        if xca_decompress(out) == data:
            return out
    raise RuntimeError("XCA encoder: no padding decodes back")


def xca_decompress(src: bytes) -> bytes:
    """Python model of wimboot's xca_decompress() for one block of 9-bit codes."""
    end = len(src)
    pos = 256
    out = bytearray()

    def get16():
        nonlocal pos
        v = struct.unpack_from("<H", src, pos)[0] if pos + 2 <= end else 0
        pos += 2
        return v
    accum = (get16() << 16) | get16()
    extra = 16
    while pos < end:
        sym = accum >> 23
        accum = (accum << 9) & 0xFFFFFFFF
        extra -= 9
        if extra < 0:
            accum |= (get16() << -extra) & 0xFFFFFFFF
            extra += 16
        if sym < 256:
            out.append(sym)
        elif sym == 256 and pos >= end - 1:
            return bytes(out)
        else:
            sym -= 256
            ob, ln = sym >> 4, (sym & 15) + 3
            off = ((accum >> (32 - ob)) + (1 << ob)) if ob else 1
            accum = (accum << ob) & 0xFFFFFFFF
            extra -= ob
            if extra < 0:
                accum |= (get16() << -extra) & 0xFFFFFFFF
                extra += 16
            for _ in range(ln):
                out.append(out[-off])
    return bytes(out) if pos == end else None


# --- WIM builder ----------------------------------------------------------

def reshdr(zlen, flags, offset, length):
    return struct.pack("<QQQ", zlen | (flags << 56), offset, length)


def direntry(name: str, subdir: int = 0, sha1: bytes = b"\0" * 20, is_dir=False) -> bytes:
    wname = name.encode("utf-16-le")
    fixed = struct.pack("<QIIQ16sQQQ20s12sHHH", 0, 0x10 if is_dir else 0x80, 0xFFFFFFFF, subdir,
                        b"", 0, 0, 0, sha1, b"", 0, 0, len(wname))
    body = fixed + wname + b"\0\0"
    body += b"\0" * (-len(body) % 8)
    return struct.pack("<Q", len(body)) + body[8:]


def metadata(files: dict) -> bytes:
    """Security header + tree: \\Windows\\{Boot\\EFI\\bootmgfw.efi, System32\\config.txt}."""
    meta = bytearray(struct.pack("<II", 8, 0))
    # Lay out directories after the root entry; fill subdir offsets afterwards.
    def entries(lst):
        return b"".join(lst) + b"\0" * 8
    sha = {k: hashlib.sha1(v).digest() for k, v in files.items()}
    root_at = len(meta)
    root_len = len(direntry("", 0, is_dir=True))
    a = root_at + root_len  # \ : Windows
    win_len = len(entries([direntry("Windows", 0, is_dir=True)]))
    b = a + win_len  # \Windows : Boot, System32
    bdir = [direntry("Boot", 0, is_dir=True), direntry("System32", 0, is_dir=True)]
    c = b + len(entries(bdir))  # \Windows\Boot : EFI
    cdir_len = len(entries([direntry("EFI", 0, is_dir=True)]))
    d = c + cdir_len  # \Windows\Boot\EFI : bootmgfw.efi
    ddir = entries([direntry("bootmgfw.efi", 0, sha["bootmgfw.efi"])])
    e = d + len(ddir)  # \Windows\System32 : config.txt
    meta += direntry("", a, is_dir=True)
    meta += entries([direntry("Windows", b, is_dir=True)])
    meta += entries([direntry("Boot", c, is_dir=True), direntry("System32", e, is_dir=True)])
    meta += entries([direntry("EFI", d, is_dir=True)])
    meta += ddir
    meta += entries([direntry("config.txt", 0, sha["config.txt"])])
    return bytes(meta), sha


def chunked(data: bytes, compress):
    """Compressed resource: chunk offset table, then chunks (raw when not smaller)."""
    chunks = []
    for k in range(0, len(data), CHUNK):
        raw = data[k:k + CHUNK]
        z = compress(raw) if compress else None
        chunks.append(z if z is not None and len(z) < len(raw) else raw)
    table = b""
    off = 0
    for ch in chunks[:-1]:
        off += len(ch)
        table += struct.pack("<I", off)
    return table + b"".join(chunks)


def build_wim(hdr_flags, compress=None, file_chunks=None) -> bytes:
    boot = bytes((k * 7 + (k >> 9)) & 0xFF if (k // 600) % 2 else 0x41 + (k % 13) for k in range(40000))
    files = {"bootmgfw.efi": boot, "config.txt": b"config\n" * 20}
    meta, sha = metadata(files)
    out = bytearray(208)
    lookup = b""

    def add(data, extra_flags, comp):
        nonlocal out
        off = len(out)
        if comp is not None:
            blob = chunked(data, comp)
            flags = extra_flags | RES_COMPRESSED
        else:
            blob, flags = data, extra_flags
        out += blob
        out += b"\0" * (-len(out) % 8)
        return reshdr(len(blob), flags, off, len(data))
    meta_hdr = add(meta, RES_METADATA, compress)
    lookup += meta_hdr + struct.pack("<HI", 1, 1) + hashlib.sha1(meta).digest()
    for name, data in files.items():
        if name == "bootmgfw.efi" and file_chunks:
            # Real compressed chunks (LZX): the content is whatever they hold
            table, blob, off = b"", b"", 0
            for ch in file_chunks[:-1]:
                off += len(ch)
                table += struct.pack("<I", off)
            blob = table + b"".join(file_chunks)
            o = len(out)
            out += blob + b"\0" * (-len(blob) % 8)
            h = reshdr(len(blob), RES_COMPRESSED, o, CHUNK * len(file_chunks))
        else:
            h = add(data, 0, compress)
        lookup += h + struct.pack("<HI", 1, 1) + sha[name]
    lk_off = len(out)
    out += lookup
    hdr = struct.pack("<8sIIII16sHHI", b"MSWIM\0\0\0", 208, 0x10D00, hdr_flags, CHUNK, b"beast-boot-fuzz!",
                      1, 1, 1)
    hdr += reshdr(len(lookup), 0, lk_off, len(lookup))
    hdr += reshdr(0, 0, 0, 0)  # xml
    hdr += meta_hdr  # boot metadata
    hdr += struct.pack("<I", 1)
    hdr += reshdr(0, 0, 0, 0)  # integrity
    hdr += b"\0" * (208 - len(hdr))
    out[:208] = hdr
    return bytes(out)


def real_lzx_chunks(path: Path, limit=24):
    """Copy compressed chunks out of a real LZX WIM (its lookup table)."""
    with open(path, "rb") as f:
        h = f.read(208)
        flags = struct.unpack_from("<I", h, 16)[0]
        if not flags & HDR_LZX:
            raise SystemExit(f"{path}: not an LZX WIM")
        zf, lo, ll = struct.unpack_from("<QQQ", h, 48)
        f.seek(lo)
        lookup = f.read(zf & 0x00FFFFFFFFFFFFFF)
        seeds, groups = [], []
        for k in range(0, len(lookup) - 49, 50):
            zf, off, ln = struct.unpack_from("<QQQ", lookup, k)
            zlen = zf & 0x00FFFFFFFFFFFFFF
            if not (zf >> 56) & RES_COMPRESSED or ln == 0 or ln > 0xFFFFFFFF:
                continue
            nchunks = (ln + CHUNK - 1) // CHUNK
            f.seek(off)
            table = f.read(4 * (nchunks - 1))
            offs = [0] + [struct.unpack_from("<I", table, 4 * i)[0] for i in range(nchunks - 1)] + [zlen - len(table)]
            got = []
            for i in range(min(nchunks, 3)):
                f.seek(off + len(table) + offs[i])
                ch = f.read(offs[i + 1] - offs[i])
                expected = min(CHUNK, ln - i * CHUNK)
                if len(ch) != expected:
                    got.append(ch)
            if got:
                seeds.extend(got)
                if nchunks >= 3 and len(got) >= 2 and len(groups) < 2:
                    groups.append(got[:2])
            if len(seeds) >= limit:
                break
        return seeds, groups


def cpio_newc(files: dict) -> bytes:
    out = b""
    ino = 1
    for name, data in list(files.items()) + [("TRAILER!!!", b"")]:
        nm = name.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in (
            ino, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        rec = hdr + nm
        rec += b"\0" * (-len(rec) % 4)
        rec += data + b"\0" * (-len(data) % 4)
        out += rec
        ino += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("--from-wim", help="LZX WIM to copy real compressed chunks from")
    a = ap.parse_args()
    out = Path(a.out)
    for d in ("wim", "lzx", "xca", "cpio"):
        (out / d).mkdir(parents=True, exist_ok=True)

    (out / "wim/plain.wim").write_bytes(build_wim(0))
    (out / "wim/xpress.wim").write_bytes(build_wim(HDR_COMPRESSION | HDR_XPRESS, xca_compress))
    samples = [b"A" * 5000, bytes(range(256)) * 40, b"wimboot " * 3000,
               bytes((k * k) & 0xFF for k in range(32768))]
    for k, s in enumerate(samples):
        (out / f"xca/sample{k}.xca").write_bytes(xca_compress(s))
    if a.from_wim:
        chunks, groups = real_lzx_chunks(Path(a.from_wim))
        for k, ch in enumerate(chunks):
            (out / f"lzx/real{k:02d}.lzx").write_bytes(ch)
        for k, g in enumerate(groups):
            (out / f"wim/lzx{k}.wim").write_bytes(build_wim(HDR_COMPRESSION | HDR_LZX, None, g))
    cp = {"BCD": b"regf" + b"\0" * 60, "bootmgfw.efi": b"MZ" + b"\0" * 100,
          "boot.wim": (out / "wim/plain.wim").read_bytes()[:512]}
    (out / "cpio/initrd.cpio").write_bytes(cpio_newc(cp))
    (out / "cpio/one.cpio").write_bytes(cpio_newc({"a": b"x"}))
    print(f"seeds in {out}: " + ", ".join(f"{d}={len(list((out / d).iterdir()))}"
                                           for d in ("wim", "lzx", "xca", "cpio")))


if __name__ == "__main__":
    main()
