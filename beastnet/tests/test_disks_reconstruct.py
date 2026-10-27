"""Generic RAID reconstruction (disks/reconstruct.py): detect on member files, build and
validate on stub tools, and the safety guard: nothing opens a member for writing."""

import builtins
import fcntl
import os

import pytest

from beastnet.disks import overlay, reconstruct
from beastnet.disks.model import Candidate, VolumeKind
from beastnet.errors import RECONSTRUCT, BeastNetError

import raid_synth as rs
from disk_stubs import disk_ctx

KiB = 1024
MiB = 1 << 20


@pytest.fixture(autouse=True)
def no_guard(monkeypatch):
    calls = []
    monkeypatch.setattr(overlay, "_guard_exempt", lambda *n: calls.append(("exempt", *n)))
    monkeypatch.setattr(overlay, "_guard_unexempt", lambda *n: calls.append(("unexempt", *n)))
    reconstruct._BUILT.clear()
    yield calls
    reconstruct._BUILT.clear()


def write_members(tmp_path, members, names=None):
    out = []
    for i, m in enumerate(members):
        p = tmp_path / (names[i] if names else f"member{i}.img")
        p.write_bytes(bytes(m))
        out.append(str(p))
    return out


class OpenSpy:
    """Records every os.open / open() / ioctl; maps fake device paths to image files."""

    def __init__(self, monkeypatch, redirect=None):
        self.opens = []
        self.redirect = redirect or {}
        real_os_open, real_open = os.open, builtins.open

        def fake_os_open(path, flags, *a, **k):
            self.opens.append((str(path), flags))
            return real_os_open(self.redirect.get(str(path), path), flags, *a, **k)

        def fake_open(path, mode="r", *a, **k):
            self.opens.append((str(path), mode))
            return real_open(path, mode, *a, **k)

        def fake_ioctl(*a, **k):
            raise AssertionError(f"ioctl called: {a}")

        monkeypatch.setattr(os, "open", fake_os_open)
        monkeypatch.setattr(builtins, "open", fake_open)
        monkeypatch.setattr(fcntl, "ioctl", fake_ioctl)

    def of(self, paths):
        return [(p, f) for p, f in self.opens if p in paths]


def writes(flags):
    if isinstance(flags, str):
        return any(c in flags for c in "wa+x")
    return flags & os.O_ACCMODE != os.O_RDONLY or flags & (os.O_TRUNC | os.O_CREAT | os.O_APPEND)


# -- detect ----------------------------------------------------------------------------------

def test_detect_ranks_and_reports_candidates(tmp_path, monkeypatch):
    members, truth, _ = rs.build_case("raid5", 4, 64 * KiB, "left-symmetric", seed=3, size=24 * MiB)
    devs = write_members(tmp_path, members)
    ctx, _ = disk_ctx(tmp_path)
    spy = OpenSpy(monkeypatch)
    cands = reconstruct.detect(ctx, devs, budget_bytes=64 * MiB)
    c = cands[0]
    assert (c.level, c.chunk, c.layout, c.data_offset) == ("raid5", 64 * KiB, "left-symmetric", MiB)
    assert c.order == [devs[i] for i in truth["order"]]
    assert c.score > 0.9 and any("checks passed" in e for e in c.evidence)
    line = ctx.reporter.lines[0]
    assert line == ("BEASTNET: reconstruct candidate rank=1 level=raid5 chunk=65536 order="
                    + ",".join(map(str, truth["order"])) + f" layout=left-symmetric offset={MiB} score={c.score:.3f}")
    member_opens = spy.of(devs)
    assert member_opens and not any(writes(f) for _, f in member_opens)


def test_detect_marks_a_missing_member(tmp_path):
    members, truth, _ = rs.build_case("raid5", 4, 64 * KiB, "left-symmetric", seed=5, size=24 * MiB, missing=1)
    devs = write_members(tmp_path, members)
    ctx, _ = disk_ctx(tmp_path)
    c = reconstruct.detect(ctx, devs)[0]
    assert c.order[1] == "" and c.level == "raid5" and len(c.order) == 4
    assert ",-," in ctx.reporter.lines[0] or "order=" in ctx.reporter.lines[0]


def test_detect_refuses_what_it_cannot_explain(tmp_path):
    devs = write_members(tmp_path, [os.urandom(4 * MiB) for _ in range(2)])
    ctx, _ = disk_ctx(tmp_path)
    with pytest.raises(BeastNetError) as e:
        reconstruct.detect(ctx, devs)
    assert e.value.code == RECONSTRUCT and "manual" in e.value.hint
    with pytest.raises(BeastNetError):
        reconstruct.detect(ctx, devs[:1])


# -- build -----------------------------------------------------------------------------------

DEVS = ["/dev/sdb", "/dev/sdc", "/dev/sdd"]


def member_args_are_only_snapshot_origins(runner, devs):
    for argv in runner.calls:
        for i, a in enumerate(argv):
            if any(d in a.split() or a == d for d in devs):
                if argv[:2] == ["blockdev", "--getsize64"]:
                    continue
                assert argv[:3] == ["dmsetup", "create", argv[2]] and argv[2].startswith("bbov_"), argv
                assert a.split()[2] == "snapshot", argv


def test_build_raid0_is_a_readonly_stripe_over_overlays(tmp_path, no_guard):
    ctx, run = disk_ctx(tmp_path, {d: 100 * MiB for d in DEVS})
    cand = Candidate("raid0", 64 * KiB, ["/dev/sdc", "/dev/sdb", "/dev/sdd"], MiB)
    vol = reconstruct.build(ctx, DEVS, cand, cap_bytes=64 * MiB)
    assert vol.kind == VolumeKind.OVERLAY_ARRAY and vol.readonly and vol.path == "/dev/mapper/bbrc0"
    usable = 99 * MiB
    assert vol.size == 3 * usable
    create = [c for c in run.calls if c[:3] == ["dmsetup", "create", "bbrc0"]][0]
    assert create == ["dmsetup", "create", "bbrc0", "--readonly", "--table",
                      f"0 {3 * usable // 512} striped 3 128 /dev/mapper/bbov_sdc 2048 /dev/mapper/bbov_sdb 2048 "
                      "/dev/mapper/bbov_sdd 2048"]
    member_args_are_only_snapshot_origins(run, DEVS)
    assert not run.names("mdadm")
    assert vol.disk_ids == ["sdb", "sdc", "sdd"]


def test_build_raid5_runs_md_on_views_never_on_members(tmp_path, no_guard):
    ctx, run = disk_ctx(tmp_path, {d: 100 * MiB for d in DEVS})
    cand = Candidate("raid5", 512 * KiB, ["/dev/sdd", "", "/dev/sdb", "/dev/sdc"], 2 * MiB,
                     layout="left-asymmetric")
    vol = reconstruct.build(ctx, DEVS, cand, cap_bytes=64 * MiB)
    usable = 98 * MiB
    assert vol.path == "/dev/md120" and vol.size == 3 * usable
    md = run.names("mdadm")
    assert md[0] == ["mdadm", "--create", "/dev/md120", "--run", "--force", "--assume-clean", "--bitmap=none",
                     "--metadata=1.2", "--data-offset=1024K", "--level=5", "--layout=left-asymmetric",
                     "--chunk=512K", "--raid-devices=4", f"--size={usable // KiB}K", "--name=bbrc0",
                     "/dev/mapper/bbrc0_v0", "missing", "/dev/mapper/bbrc0_v2", "/dev/mapper/bbrc0_v3"]
    assert md[1] == ["mdadm", "--readonly", "/dev/md120"]
    assert run.dm["bbrc0_v0"] == (f"0 2048 linear /dev/loop3 0\n2048 {usable // 512} linear /dev/mapper/bbov_sdd "
                                  f"{2 * MiB // 512}")
    member_args_are_only_snapshot_origins(run, DEVS)
    exempted = [c[1] for c in no_guard if c[0] == "exempt"]
    assert exempted == ["dm-0", "dm-1", "dm-2", "dm-3", "dm-4", "dm-5"]  # 3 overlays, then the md views
    views = [c for c in run.calls if c[:2] == ["dmsetup", "create"] and c[2].startswith("bbrc0_v")]
    assert all("--readonly" not in c for c in views)  # md writes its superblock into the RAM prefix


def test_teardown_goes_from_the_array_down_to_the_overlays(tmp_path, no_guard):
    ctx, run = disk_ctx(tmp_path, {d: 100 * MiB for d in DEVS})
    vol = reconstruct.build(ctx, DEVS, Candidate("raid5", 64 * KiB, list(DEVS), 0, layout="left-symmetric"),
                            cap_bytes=64 * MiB)
    run.calls.clear()
    reconstruct.teardown(ctx, vol)
    seq = [" ".join(c[:3]) for c in run.calls]
    assert seq[0] == "mdadm --stop /dev/md120"
    assert seq[1:4] == ["dmsetup remove --retry"] * 3 and run.calls[1][-1] == "bbrc0_v2"
    assert seq[4] == "losetup -d /dev/loop3"
    assert [c[-1] for c in run.calls if c[:2] == ["dmsetup", "remove"]][3:] == ["bbov_sdb", "bbov_sdc", "bbov_sdd"]
    assert run.calls[-1][0] == "umount"
    assert [c[1] for c in no_guard if c[0] == "unexempt"] == ["dm-3", "dm-4", "dm-5", "dm-0", "dm-1", "dm-2"]
    assert reconstruct.evidence(vol) == []
    reconstruct.teardown(ctx, vol)  # twice is harmless


def test_failed_md_create_tears_everything_down(tmp_path):
    ctx, run = disk_ctx(tmp_path, {d: 100 * MiB for d in DEVS})
    run.rc["mdadm --create"] = 2
    with pytest.raises(BeastNetError) as e:
        reconstruct.build(ctx, DEVS, Candidate("raid5", 64 * KiB, list(DEVS), 0, layout="left-symmetric"),
                          cap_bytes=64 * MiB)
    assert e.value.code == RECONSTRUCT
    assert run.dm == {} and overlay.overlays(ctx) == {} and reconstruct._BUILT == {}


@pytest.mark.parametrize("cand,why", [
    (Candidate("raid0", 64 * KiB, ["/dev/sdb", ""], 0), "missing"),
    (Candidate("raid0", 3000, ["/dev/sdb", "/dev/sdc"], 0), "power of two"),
    (Candidate("raid5", 64 * KiB, ["/dev/sdb", "/dev/sdb", "/dev/sdc"], 0, layout="left-symmetric"), "once"),
    (Candidate("raid5", 64 * KiB, ["/dev/sdb", "/dev/sdc", "/dev/sdd"], 0, layout="sideways"), "layout"),
    (Candidate("raid6", 64 * KiB, ["/dev/sdb", "/dev/sdc", "/dev/sdd"], 0, layout="left-symmetric"), "at least"),
    (Candidate("raid1", 0, ["/dev/sdb", "/dev/sdc"], 100), "multiple of 512"),
    (Candidate("raid7", 0, ["/dev/sdb", "/dev/sdc"], 0), "unknown"),
])
def test_manual_builder_refuses_impossible_parameters(tmp_path, cand, why):
    ctx, run = disk_ctx(tmp_path)
    with pytest.raises(BeastNetError) as e:
        reconstruct.build(ctx, DEVS, cand)
    assert why in e.value.text and run.calls == []


def test_manual_builder_builds_a_mirror_and_a_span(tmp_path):
    ctx, run = disk_ctx(tmp_path, {"/dev/sdb": 80 * MiB, "/dev/sdc": 60 * MiB})
    vol = reconstruct.manual(ctx, ["/dev/sdb", "/dev/sdc"], level="raid1", offset=0, cap_bytes=64 * MiB)
    assert run.dm["bbrc0"] == f"0 {60 * MiB // 512} linear /dev/mapper/bbov_sdb 0"
    reconstruct.teardown(ctx, vol)
    vol = reconstruct.manual(ctx, ["/dev/sdb", "/dev/sdc"], level="linear", order=["/dev/sdc", "/dev/sdb"],
                             offset=MiB, cap_bytes=64 * MiB)
    assert run.dm["bbrc0"] == (f"0 {59 * MiB // 512} linear /dev/mapper/bbov_sdc 2048\n"
                               f"{59 * MiB // 512} {79 * MiB // 512} linear /dev/mapper/bbov_sdb 2048")
    assert vol.size == 138 * MiB


# -- validate and the never-write guard -------------------------------------------------------

def test_build_and_validate_never_open_a_member_for_writing(tmp_path, monkeypatch):
    vol_img = rs.with_gpt(24 * MiB, rs.make_ext(20 * MiB))
    members = rs.stripe(vol_img, "raid0", 3, 64 * KiB, offset=MiB)
    devs = write_members(tmp_path, members, ["sdb.img", "sdc.img", "sdd.img"])
    (tmp_path / "vol.img").write_bytes(vol_img)
    (tmp_path / "part.img").write_bytes(vol_img[MiB:21 * MiB])
    ctx, run = disk_ctx(tmp_path, {d: len(members[0]) for d in devs})
    spy = OpenSpy(monkeypatch, {"/dev/mapper/bbrc0": str(tmp_path / "vol.img"),
                                "/dev/mapper/bbrc0p1": str(tmp_path / "part.img")})
    cand = reconstruct.detect(ctx, devs, budget_bytes=32 * MiB)[0]
    assert cand.order == devs and cand.data_offset == MiB and cand.chunk == 64 * KiB
    detect_opens = len(spy.opens)
    vol = reconstruct.build(ctx, devs, cand, cap_bytes=64 * MiB)
    assert vol.size == 24 * MiB
    score = reconstruct.validate(ctx, vol)
    assert score > 0.8
    ev = reconstruct.evidence(vol)
    assert any("mounts read-only" in e for e in ev) and any("e2fsck -n found no errors" in e for e in ev)
    mounts = [c for c in run.calls if c[0] == "mount" and c[2] != "tmpfs"]
    assert mounts == [["mount", "-t", "ext4", "-o", "ro,noatime,nodev,nosuid,noexec,noload", "/dev/mapper/bbrc0p1",
                       os.path.join(ctx.paths.run, "rc-mnt", "bbrc0p1")]]
    assert ["e2fsck", "-n", "-f", "/dev/mapper/bbrc0p1"] in run.calls
    assert run.dm["bbrc0p1"] == f"0 {20 * MiB // 512} linear /dev/mapper/bbrc0 2048"
    # the guard: detect read the members read-only; build and validate never opened them
    assert not any(writes(f) for _, f in spy.of(devs))
    assert spy.of(devs[:1]) and not [o for o in spy.opens[detect_opens:] if o[0] in devs]
    member_args_are_only_snapshot_origins(run, devs)
    run.calls.clear()
    reconstruct.teardown(ctx, vol)
    removes = [c[-1] for c in run.calls if c[:2] == ["dmsetup", "remove"]]
    assert removes[:2] == ["bbrc0p1", "bbrc0"]


def test_validate_scores_zero_when_nothing_reads(tmp_path, monkeypatch):
    (tmp_path / "vol.img").write_bytes(os.urandom(4 * MiB))
    ctx, run = disk_ctx(tmp_path, {d: 8 * MiB for d in DEVS[:2]})
    OpenSpy(monkeypatch, {"/dev/mapper/bbrc0": str(tmp_path / "vol.img")})
    vol = reconstruct.build(ctx, DEVS[:2], Candidate("raid0", 64 * KiB, DEVS[:2], 0), cap_bytes=64 * MiB)
    assert reconstruct.validate(ctx, vol) == 0
    assert "no filesystem on it reads" in reconstruct.evidence(vol)
    assert not [c for c in run.calls if c[0] in ("mount", "e2fsck") and "tmpfs" not in c]
