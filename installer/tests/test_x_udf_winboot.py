"""UDF reader, ISO9660 identity and `prepare-windows`, on a synthetic UDF bridge image."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from beastbooter import cli, udf, winboot
from beastbooter.udf import UdfError

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


@pytest.fixture
def image() -> bytes:
    return build_image(wim_bytes())


def test_read_files(image):
    vol = udf.open_udf(io.BytesIO(image))
    f = vol.lookup("SOURCES/Boot.Wim")
    assert f is not None and not f.is_dir and f.size == 70000
    assert f.read_all(1 << 30) == wim_bytes()
    assert vol.lookup("sources/install.wim").read_all() == bytes(4096)
    assert vol.lookup("readme.txt").read_all() == b"hello"
    assert vol.lookup("sources/nope") is None
    assert vol.lookup("readme.txt/x") is None


def test_bad_images_raise_cleanly(image):
    for bad in (bytes(300 * S), image[:100 * S]):
        with pytest.raises(UdfError):
            udf.open_udf(io.BytesIO(bad))
    # damaged: file entry points outside the image
    img = bytearray(image)
    off = (PART + 5) * S
    struct.pack_into("<II", img, off + 216, 70000, 10_000_000)
    vol = udf.open_udf(io.BytesIO(bytes(img)))
    with pytest.raises(UdfError):
        vol.lookup("sources/boot.wim")


def test_stamp_format():
    b = winboot.stamp_bytes([("bb_wb_iso", "/a\\b"), ("bb_wb_label", "")])
    assert len(b) == 1024
    assert b.startswith(b"# GRUB Environment Block\nbb_wb_iso=/a\\\\b\nbb_wb_label=\n#")
    assert set(b[len(b"# GRUB Environment Block\nbb_wb_iso=/a\\\\b\nbb_wb_label=\n"):]) == {0x23}
    assert winboot.parse_stamp(b) == {"bb_wb_iso": "/a\\b", "bb_wb_label": ""}


def make_root(tmp_path: Path, image: bytes) -> tuple[Path, Path]:
    root = tmp_path / "data"
    (root / "beast-booter").mkdir(parents=True)
    (root / "isos").mkdir()
    iso = root / "isos" / "Win11.iso"
    iso.write_bytes(image)
    return root, iso


def test_prepare_cli(tmp_path, image, capsys):
    root, iso = make_root(tmp_path, image)
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    d = root / "beast-booter" / "winboot" / "isos" / "Win11.iso"
    assert (d / "boot.wim").read_bytes() == wim_bytes()
    st = winboot.parse_stamp((d / "stamp.env").read_bytes())
    assert st["bb_wb_iso"] == "/isos/Win11.iso"
    assert (d / "iso-head.bin").read_bytes() == image[32768:98304]
    assert "bb_wb_uuid" not in st
    assert st["bb_wb_kind"] == "setup" and st["bb_wb_size"] == "70000"
    assert st["bb_wb_by"].startswith("host ")
    assert not list(d.glob("*.part")) and not list(d.glob("*.tmp"))
    # second run skips; --force copies again
    mtime = (d / "boot.wim").stat().st_mtime_ns
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    assert (d / "boot.wim").stat().st_mtime_ns == mtime
    (d / "iso-head.bin").write_bytes(b"x")  # stale identity: copied again
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    assert (d / "boot.wim").stat().st_mtime_ns != mtime or (d / "iso-head.bin").read_bytes() == image[32768:98304]
    assert cli.main(["prepare-windows", "-q", "--force", "--data-root", str(root), str(iso)]) == 0


def test_prepare_native_and_errors(tmp_path, capsys):
    root, iso = make_root(tmp_path, build_image(wim_bytes(), with_install=False))
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    st = winboot.parse_stamp((root / "beast-booter/winboot/isos/Win11.iso/stamp.env").read_bytes())
    assert st["bb_wb_kind"] == "native"

    r2, iso2 = make_root(tmp_path / "b", bytes(90000))
    assert cli.main(["prepare-windows", "-q", str(iso2)]) == 1
    assert not (r2 / "beast-booter" / "winboot").exists()

    out = tmp_path / "elsewhere.iso"
    out.write_bytes(b"x")
    assert cli.main(["prepare-windows", "-q", str(out)]) == 1  # no beast-booter/ above
    assert cli.main(["prepare-windows", "-q", "--data-root", str(root), str(out)]) == 1  # outside root
    junk = root / "isos" / "junk.iso"
    junk.write_bytes(bytes(300 * S))
    assert cli.main(["prepare-windows", "-q", str(junk)]) == 1


REAL = Path("/home/cynak/Downloads/Windows11_Client_x64_en-us_26300_9457.iso")


@pytest.mark.skipif(not REAL.exists(), reason="real Windows ISO not present")
def test_real_iso_boot_wim():
    with open(REAL, "rb") as f:
        vol = udf.open_udf(f)
        w = vol.lookup("sources/boot.wim")
        assert w is not None and w.size > 1 << 20
        assert next(w.read_chunks())[:8] == b"MSWIM\0\0\0"
        assert vol.lookup("sources/install.wim") or vol.lookup("sources/install.esd")
