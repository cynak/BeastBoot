"""Generic RAID reconstruction analysis (disks/raidmath.py, disks/fswalk.py).

Member images are made here, in memory: a small ext4 or NTFS (raid_synth.py) cut into
members the way md does (an independent implementation of md's layouts), metadata
absent or replaced by junk, members shuffled, sometimes one dropped. detect must rank
the true parameters first.
"""

import os
import random
import shutil
import subprocess

import pytest

from beastnet.disks import fswalk, raidmath as rm

import raid_synth as rs

KiB = 1024
MiB = 1024 * KiB
LAY = rm.LAYOUTS


def source(members, budget=None):
    return rm.Source([(lambda o, n, m=m: bytes(m[o:o + n])) for m in members], [len(m) for m in members],
                     budget=budget)


# -- bytes and checksums ------------------------------------------------------------------------

def test_checksums_match_published_check_values():
    assert rm.crc32c(b"123456789") == 0xE3069283                      # CRC-32C/iSCSI
    assert fswalk.crc16(0, b"123456789") == 0xBB3D                    # CRC-16/ARC (Linux crc16)
    assert fswalk.crc16(0xFFFF, b"123456789") == 0x4B37               # CRC-16/MODBUS


def test_xor_entropy_zero():
    a, b = os.urandom(4096), os.urandom(4096)
    assert rm.xor_blocks([a, b, rm.xor_blocks([a, b])]) == bytes(4096)
    assert rm.is_zero(bytes(512)) and not rm.is_zero(b"\0" * 511 + b"\1")
    assert rm.entropy(bytes(100)) == 0.0
    assert rm.entropy(bytes(range(256)) * 4) == pytest.approx(8.0)


# -- layouts -------------------------------------------------------------------------------------

@pytest.mark.parametrize("layout", LAY)
@pytest.mark.parametrize("n", [3, 4, 5, 8])
def test_raid5_and_raid6_maps_match_md(layout, n):
    for row in range(3 * n):
        assert rm.raid5_map(layout, n, row) == (rs._raid5_row(layout, n, row)[0],
                                                 tuple(rs._raid5_row(layout, n, row)[1]))
        if n >= 4:
            p, q, d = rs._raid6_row(layout, n, row)
            assert rm.raid6_map(layout, n, row) == (p, q, tuple(d))
            assert len({p, q, *d}) == n


@pytest.mark.parametrize("level,n,layout", [
    ("raid0", 3, ""), ("raid1", 2, ""), ("raid10", 4, ""), ("raid5", 4, "left-symmetric"),
    ("raid5", 3, "right-asymmetric"), ("raid6", 5, "left-asymmetric"), ("raid6", 4, "right-symmetric"),
])
def test_logical_reader_reads_back_the_volume(level, n, layout):
    chunk = 16 * KiB
    vol = random.Random(1).randbytes(chunk * rs.DATA_SLOTS[level](n) * 12)
    members = rs.stripe(vol, level, n, chunk, layout, offset=64 * KiB)
    rd = rm.LogicalReader(source(members), rm.Geometry(level, n, chunk, layout, 64 * KiB), range(n))
    assert rd.size == len(vol)
    assert rd.read(0, len(vol)) == vol
    assert rd.read(chunk - 100, 3 * chunk) == vol[chunk - 100:4 * chunk - 100]


def test_linear_reader_and_sizes():
    vol = random.Random(2).randbytes(300 * KiB)
    members = rs.stripe(vol, "linear", 3, sizes=[100 * KiB, 120 * KiB, 80 * KiB], offset=8 * KiB)
    rd = rm.LogicalReader(source(members), rm.Geometry("linear", 3, 0, "", 8 * KiB), (0, 1, 2))
    assert rd.read(0, len(vol)) == vol


@pytest.mark.parametrize("level,n", [("raid5", 4), ("raid6", 5)])
def test_missing_member_is_rebuilt_from_parity(level, n):
    chunk = 8 * KiB
    vol = random.Random(3).randbytes(chunk * rs.DATA_SLOTS[level](n) * 10)
    members = rs.stripe(vol, level, n, chunk, "left-symmetric")
    gone = 1
    rest = [m for i, m in enumerate(members) if i != gone]
    order = [i if i < gone else i - 1 for i in range(n)]
    order[gone] = rm.MISSING
    rd = rm.LogicalReader(source(rest), rm.Geometry(level, n, chunk, "left-symmetric", 0), order)
    assert rd.read(0, len(vol)) == vol


def test_unplaced_slot_raises_slot_unknown():
    members = rs.stripe(bytes(64 * KiB * 3), "raid0", 3, 64 * KiB)
    rd = rm.LogicalReader(source(members), rm.Geometry("raid0", 3, 64 * KiB), (0, None, 2))
    rd.read(0, 64 * KiB)
    with pytest.raises(rm.SlotUnknown) as e:
        rd.read(64 * KiB, 10)
    assert e.value.slot == 1


# -- signatures and walkers ---------------------------------------------------------------------

def test_start_kinds():
    ext = rs.make_ext(8 * MiB)
    ntfs = rs.make_ntfs(8 * MiB)
    assert fswalk.start_kind(ext[:8192]) == "ext"
    assert fswalk.start_kind(ntfs[:8192]) == "ntfs"
    assert fswalk.start_kind(rs.with_gpt(16 * MiB, ntfs)[:8192]) == "gpt"
    assert fswalk.start_kind(b"XFSB" + (4096).to_bytes(4, "big") + bytes(8184)) == "xfs"
    assert fswalk.start_kind(b"LUKS\xba\xbe" + bytes(8186)) == "luks"
    assert fswalk.start_kind(os.urandom(8192)[:510] + bytes(7682)) == ""
    # an ext backup superblock (group 3) is not a volume start
    backup = bytearray(ext[:8192])
    backup[1024 + 90] = 3
    assert fswalk.start_kind(bytes(backup)) == ""


@pytest.mark.parametrize("fs", ["ext", "ntfs"])
def test_walkers_pass_good_volumes_and_fail_scrambled_ones(fs):
    vol = rs.make_ext(16 * MiB) if fs == "ext" else rs.make_ntfs(16 * MiB)
    good = fswalk.run(lambda o, n: vol[o:o + n], len(vol), 10000)
    assert good.failed == 0 and good.passed > 100, good.summary()
    # swap two 64 KiB pieces in the middle: a wrong member order in miniature
    c = 64 * KiB
    bad = bytearray(vol)
    for k in range(4, len(vol) // c - 1, 2):
        bad[k * c:(k + 1) * c], bad[(k + 1) * c:(k + 2) * c] = vol[(k + 1) * c:(k + 2) * c], vol[k * c:(k + 1) * c]
    r = fswalk.run(lambda o, n: bytes(bad[o:o + n]), len(bad), 10000)
    assert r.score < good.score - 20


def test_gpt_partitions_and_walk_into_them():
    vol = rs.with_gpt(24 * MiB, rs.make_ext(20 * MiB))
    assert fswalk.gpt_partitions(vol[:64 * KiB]) == [(MiB, 20 * MiB)]
    r = fswalk.run(lambda o, n: vol[o:o + n], len(vol), 10000)
    assert r.failed == 0 and "gpt" in r.kinds and f"ext4@{MiB}" in r.kinds
    assert r.tally["gpt-backup"][0] > 0


def test_ntfs_fixups_and_runlists():
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    rec[510:512] = b"ab"
    rec[1022:1024] = b"cd"
    rs._fixup(rec, 0x30)
    assert rec[510:512] == rec[0x30:0x32] == rec[1022:1024]
    fixed = fswalk.ntfs_fixup(bytes(rec))
    assert fixed[510:512] == b"ab" and fixed[1022:1024] == b"cd"
    rec[1022] ^= 1
    assert fswalk.ntfs_fixup(bytes(rec)) is None
    runs = [(100, 8), (40, 300), (70000, 1)]
    assert fswalk.ntfs_runlist(rs._runlist(runs), 0) == runs


# -- level statistics ---------------------------------------------------------------------------

def test_level_stats_tell_levels_apart():
    vol = rs.make_ext(12 * MiB)
    st = rm.level_stats(source(rs.stripe(vol, "raid1", 3)))
    assert st.mirror == 1.0
    st = rm.level_stats(source(rs.stripe(vol[:12 * MiB], "raid5", 4, 64 * KiB, "left-symmetric")))
    assert st.parity == 1.0 and st.multi > 16
    st = rm.level_stats(source(rs.stripe(vol, "raid6", 4, 64 * KiB, "left-symmetric")))
    assert st.q == 1.0
    st = rm.level_stats(source(rs.stripe(vol, "raid10", 4, 64 * KiB)))
    assert st.pairs(4) == [(0, 1), (2, 3)]
    st = rm.level_stats(source(rs.stripe(vol, "raid0", 3, 64 * KiB)))
    assert st.mirror == 0 and st.parity < 0.5


def test_probe_starts_finds_the_data_offset():
    members = rs.stripe(rs.make_ext(12 * MiB), "raid0", 3, 64 * KiB, offset=2 * MiB)
    starts = rm.probe_starts(source(members))
    assert [(s.offset, s.member, s.kind) for s in starts] == [(2 * MiB, 0, "ext")]
    assert rm.choose_offsets(starts) == [2 * MiB]
    assert rm.choose_offsets([]) == [0]


# -- detection: the true parameters come first --------------------------------------------------

CASES = [
    dict(level="raid0", n=2, chunk=64 * KiB),
    dict(level="raid0", n=3, chunk=4 * KiB, fs="ntfs"),
    dict(level="raid0", n=4, chunk=512 * KiB, size=32 * MiB),
    dict(level="raid0", n=3, chunk=1 * MiB, fs="ntfs", size=32 * MiB),
    dict(level="raid1", n=2, chunk=0),
    dict(level="raid1", n=3, chunk=0, fs="ntfs", offset=0, tail=MiB, junk=3),
    dict(level="raid10", n=4, chunk=64 * KiB, size=32 * MiB),
    dict(level="raid10", n=6, chunk=512 * KiB, fs="ntfs", size=48 * MiB),
    dict(level="raid5", n=3, chunk=16 * KiB, layout="left-symmetric"),
    dict(level="raid5", n=3, chunk=64 * KiB, layout="right-asymmetric", fs="ntfs"),
    dict(level="raid5", n=4, chunk=128 * KiB, layout="left-asymmetric", size=24 * MiB),
    dict(level="raid5", n=5, chunk=512 * KiB, layout="right-symmetric", size=32 * MiB),
    dict(level="raid5", n=4, chunk=64 * KiB, layout="left-symmetric", missing=0, size=24 * MiB),
    dict(level="raid5", n=3, chunk=32 * KiB, layout="right-symmetric", missing=2, fs="ntfs"),
    dict(level="raid6", n=4, chunk=64 * KiB, layout="left-symmetric", size=16 * MiB),
    dict(level="raid6", n=5, chunk=64 * KiB, layout="right-asymmetric", fs="ntfs", size=24 * MiB),
    dict(level="linear", n=2, chunk=0, offset=0),
    dict(level="linear", n=3, chunk=0, fs="ntfs", offset=0),
    # AMD RAIDXpert2-like: data from 0, unknown metadata at the end, Windows GPT + NTFS
    dict(level="raid0", n=2, chunk=128 * KiB, fs="ntfs", gpt=True, offset=0, tail=MiB, junk=5, size=32 * MiB),
    # NAS-like: md 1.2 data offset, superblock remnants
    dict(level="raid5", n=4, chunk=64 * KiB, layout="left-symmetric", offset=2 * MiB, junk=8, size=48 * MiB),
    dict(level="raid0", n=8, chunk=64 * KiB, size=64 * MiB),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: "{level}x{n}-{k}K-{lay}{fs}{miss}".format(
    level=c["level"], n=c["n"], k=c["chunk"] // KiB, lay=c.get("layout", "")[:7], fs=c.get("fs", "ext"),
    miss="-missing" if c.get("missing") is not None else ""))
def test_detect_ranks_the_true_parameters_first(case):
    case = dict(case)
    level, n, chunk = case.pop("level"), case.pop("n"), case.pop("chunk")
    layout = case.pop("layout", "")
    members, truth, _ = rs.build_case(level, n, chunk, layout, seed=n * 7 + chunk // KiB, **case)
    src = source(members, budget=64 * MiB)
    a = rm.analyse(src)
    top = a.hypotheses[0]
    assert rs.matches(top, truth), (top.geom, top.order, truth, top.evidence)
    assert top.confidence > 0.8
    assert max(a.bytes_read) <= 64 * MiB + src.page


def test_random_data_gives_no_confident_candidate():
    rng = random.Random(9)
    members = [bytearray(rng.randbytes(8 * MiB)) for _ in range(3)]
    a = rm.analyse(source(members))
    assert all(h.confidence == 0 for h in a.hypotheses)


def test_budget_stops_reading():
    members, truth, _ = rs.build_case("raid0", 3, 64 * KiB, seed=4)
    src = source(members, budget=2 * MiB)
    a = rm.analyse(src)
    assert max(a.bytes_read) <= 2 * MiB + src.page


# -- real filesystems (made by the real tools, striped here) ------------------------------------

def _mkfs(tmp_path, kind):
    tree = tmp_path / "tree"
    rng = random.Random(5)
    for i in range(6):
        d = tree / f"dir{i}" / ("sub" if i % 2 else "")
        d.mkdir(parents=True, exist_ok=True)
        for j in range(10):
            (d / f"f{j}.dat").write_bytes(rng.randbytes(rng.choice((100, 3000, 70000))))
    img = tmp_path / "fs.img"
    with open(img, "wb") as f:
        f.truncate(48 * MiB)
    if kind == "ext4":
        subprocess.run(["mkfs.ext4", "-F", "-q", "-b", "4096", "-d", str(tree), str(img)], check=True)
    else:
        subprocess.run(["mkntfs", "-F", "-Q", "-q", "-c", "4096", str(img)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for j, p in enumerate(sorted(tree.rglob("*.dat"))[:30]):
            subprocess.run(["ntfscp", "-q", "-f", str(img), str(p), f"file{j:02d}.dat"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return img.read_bytes()


@pytest.mark.parametrize("kind,tool", [("ext4", "mkfs.ext4"), ("ntfs", "ntfscp")])
def test_real_filesystems_walk_clean_and_are_detected(tmp_path, kind, tool):
    if not shutil.which(tool) or (kind == "ntfs" and not shutil.which("mkntfs")):
        pytest.skip(f"{tool} not installed")
    vol = _mkfs(tmp_path, kind)
    r = fswalk.run(lambda o, n: vol[o:o + n], len(vol), 100000)
    assert r.failed == 0 and r.passed > 50, r.summary()
    level, n, chunk, layout = ("raid5", 4, 64 * KiB, "left-symmetric") if kind == "ext4" else ("raid0", 3, 32 * KiB, "")
    data = rs.DATA_SLOTS[level](n)
    vol = vol[:len(vol) // (chunk * data) * chunk * data]
    members = rs.stripe(vol, level, n, chunk, layout, offset=MiB)
    perm = [2, 0, 3, 1][:n] if n == 4 else [1, 2, 0]
    shuffled = [members[p] for p in perm]
    truth = dict(level=level, n=n, chunk=chunk, layout=layout, offset=MiB, order=[perm.index(s) for s in range(n)])
    top = rm.analyse(source(shuffled)).hypotheses[0]
    assert rs.matches(top, truth), (top.geom, top.order, truth)
