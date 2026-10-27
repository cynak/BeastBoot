"""Copy-on-write overlays (disks/overlay.py): command sequences against stub tools."""

import os
import types

import pytest

from beastnet.disks import overlay
from beastnet.errors import DISK_REFUSED, RECONSTRUCT, BeastNetError

from disk_stubs import disk_ctx

MiB = 1 << 20


def test_create_mounts_capped_tmpfs_and_snapshots_each_member(tmp_path):
    ctx, run = disk_ctx(tmp_path, {"/dev/sdb": 100 * MiB, "/dev/sdc1": 50 * MiB})
    exempted = []
    paths = overlay.create(ctx, ["/dev/sdb", "/dev/sdc1"], cap_bytes=256 * MiB, exempt=exempted.append)
    assert paths == ["/dev/mapper/bbov_sdb", "/dev/mapper/bbov_sdc1"]
    cow = overlay.cow_root(ctx)
    assert run.calls[0] == ["mount", "-t", "tmpfs", "-o", f"size={256 * MiB},mode=0700", "bbcow", cow]
    creates = [c for c in run.calls if c[:2] == ["dmsetup", "create"]]
    assert creates == [
        ["dmsetup", "create", "bbov_sdb", "--table", f"0 {100 * MiB // 512} snapshot /dev/sdb /dev/loop0 P 8"],
        ["dmsetup", "create", "bbov_sdc1", "--table", f"0 {50 * MiB // 512} snapshot /dev/sdc1 /dev/loop1 P 8"],
    ]
    assert [c for c in run.calls if c[0] == "losetup"] == [
        ["losetup", "--find", "--show", os.path.join(cow, "bbov_sdb.cow")],
        ["losetup", "--find", "--show", os.path.join(cow, "bbov_sdc1.cow")],
    ]
    assert all(e == overlay.DM_ENV for c, e in zip(run.calls, run.envs) if c[0] == "dmsetup")
    assert exempted == ["dm-0", "dm-1"]
    # the COW files are sparse and live in the tmpfs, never on a member
    assert os.path.getsize(os.path.join(cow, "bbov_sdb.cow")) == 256 * MiB
    # asking again reuses the overlay
    assert overlay.create(ctx, ["/dev/sdb"], cap_bytes=256 * MiB, exempt=exempted.append) == ["/dev/mapper/bbov_sdb"]
    assert len([c for c in run.calls if c[:2] == ["dmsetup", "create"]]) == 2


def test_remove_tears_down_in_order_and_unmounts_when_empty(tmp_path):
    ctx, run = disk_ctx(tmp_path)
    paths = overlay.create(ctx, ["/dev/sdb", "/dev/sdc"], cap_bytes=64 * MiB, exempt=lambda *a: None)
    cow = overlay.cow_root(ctx)
    run.calls.clear()
    gone = []
    overlay.remove(ctx, [paths[0]], unexempt=gone.append)
    assert run.calls == [["dmsetup", "remove", "--retry", "bbov_sdb"], ["losetup", "-d", "/dev/loop0"]]
    assert gone == ["dm-0"] and not os.path.exists(os.path.join(cow, "bbov_sdb.cow"))
    overlay.remove(ctx, [paths[1]], unexempt=gone.append)
    assert run.calls[-1] == ["umount", cow]
    assert overlay.overlays(ctx) == {}


def test_refuses_cow_on_the_stick_or_outside_ram(tmp_path):
    ctx, run = disk_ctx(tmp_path)
    with pytest.raises(BeastNetError) as e:
        overlay.create(ctx, ["/dev/sdb"], cow_dir=os.path.join(ctx.paths.data, "cow"), cap_bytes=64 * MiB)
    assert e.value.code == DISK_REFUSED and run.calls == []
    # the tmpfs cannot be mounted and the directory is on a disk filesystem
    run.mount_ok = False
    with open(os.path.join(ctx.paths.proc, "mounts"), "a") as f:
        f.write(f"/dev/sda2 {os.path.realpath(ctx.paths.root)} ext4 rw 0 0\n")
    with pytest.raises(BeastNetError) as e:
        overlay.create(ctx, ["/dev/sdb"], cap_bytes=64 * MiB)
    assert e.value.code == RECONSTRUCT
    assert not [c for c in run.calls if c[0] in ("losetup", "dmsetup")]


def test_refuses_when_ram_is_short(tmp_path):
    ctx, run = disk_ctx(tmp_path)
    with pytest.raises(BeastNetError) as e:
        overlay.create(ctx, ["/dev/sdb"], cap_bytes=8 * MiB)
    assert e.value.code == RECONSTRUCT and run.calls == []
    assert overlay.default_cap(ctx) == 2000000 * 1024 // 4


def test_failed_snapshot_undoes_the_loop(tmp_path):
    ctx, run = disk_ctx(tmp_path)
    run.rc["dmsetup create"] = 1
    with pytest.raises(BeastNetError):
        overlay.create(ctx, ["/dev/sdb"], cap_bytes=64 * MiB, exempt=lambda *a: None)
    assert ["losetup", "-d", "/dev/loop0"] in run.calls
    assert not os.path.exists(os.path.join(overlay.cow_root(ctx), "bbov_sdb.cow"))


def test_status_parsing_and_usage(tmp_path):
    assert overlay.parse_status("0 2097152 snapshot 16/2097152 16") == (16, 2097152, False)
    assert overlay.parse_status("0 2097152 snapshot 4096/2097152 24") == (4096, 2097152, False)
    assert overlay.parse_status("0 2097152 snapshot Invalid") == (0, 0, True)
    assert overlay.parse_status("0 2097152 snapshot Overflow") == (0, 0, True)
    assert overlay.parse_status("0 2097152 linear") is None
    ctx, run = disk_ctx(tmp_path)
    overlay.create(ctx, ["/dev/sdb"], cap_bytes=64 * MiB, exempt=lambda *a: None)
    run.status["bbov_sdb"] = "0 131072 snapshot 2048/131072 32"
    assert overlay.usage(ctx) == [overlay.Usage("bbov_sdb", 2048 * 512, 131072 * 512, False)]


def test_ensure_room_refuses_near_the_cap(tmp_path, monkeypatch):
    ctx, run = disk_ctx(tmp_path)
    overlay.create(ctx, ["/dev/sdb"], cap_bytes=64 * MiB, exempt=lambda *a: None)
    full = types.SimpleNamespace(f_blocks=1000, f_frsize=4096, f_bavail=100)
    monkeypatch.setattr(overlay, "_statvfs", lambda p: full)
    with pytest.raises(BeastNetError) as e:
        overlay.ensure_room(ctx)
    assert e.value.code == RECONSTRUCT and "90% full" in e.value.text
    # a new overlay is refused too
    with pytest.raises(BeastNetError):
        overlay.create(ctx, ["/dev/sdc"], cap_bytes=64 * MiB, exempt=lambda *a: None)
    roomy = types.SimpleNamespace(f_blocks=1000, f_frsize=4096, f_bavail=900)
    monkeypatch.setattr(overlay, "_statvfs", lambda p: roomy)
    overlay.ensure_room(ctx)
    run.status["bbov_sdb"] = "0 131072 snapshot Invalid"
    with pytest.raises(BeastNetError) as e:
        overlay.ensure_room(ctx)
    assert "overflowed" in e.value.text
