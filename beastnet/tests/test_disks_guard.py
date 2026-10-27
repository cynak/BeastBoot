"""The read-only guard: BLKROSET calls are recorded through the injectable ioctl."""

import os
import struct

import pytest

from beastnet.disks import discover, guard
from beastnet.errors import DISK_CHANGED, DISK_REFUSED, BeastNetError
from disk_fakes import Env


@pytest.fixture
def calls(monkeypatch):
    rec = []
    state = {}

    def fake(fd, req, arg):
        path = os.readlink(f"/proc/self/fd/{fd}")
        if req == guard.BLKROSET:
            state[path] = struct.unpack("i", arg)[0]
            rec.append((os.path.basename(path), req, state[path]))
            return 0
        return struct.pack("i", state.get(path, 0))

    monkeypatch.setattr(guard, "_ioctl", fake)
    monkeypatch.setattr(guard, "_writable", set())
    monkeypatch.setattr(guard, "_exempt", set())
    monkeypatch.setattr(guard, "_handles", [])
    return rec


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sda", 100, serial="SER-A")
    e.add_part("sda", 1, 1, 50)
    e.add_part("sda", 2, 51, 49)
    e.add_disk("sdb", 100, serial="SER-B")
    e.add_disk("sdc", 100, serial="STICK", removable=1)
    e.add_disk("loop0", 10)
    e.add_virtual("md127", 10, slaves=["sdb"])
    e.add_virtual("dm-0", 10)
    return e


def test_blkroset_value():
    assert guard.BLKROSET == 0x125D


def test_protect_all_sets_ro_on_disks_partitions_md_dm_but_not_loop(env, calls):
    done = guard.protect_all(env.ctx)
    names = {c[0] for c in calls}
    assert names == {"sda", "sda1", "sda2", "sdb", "sdc", "md127", "dm-0"}
    assert all(c[1] == 0x125D and c[2] == 1 for c in calls)
    assert set(done) == names
    assert "BEASTNET: disk ro id=sda1 ro=1" in env.rep.lines


def test_reapply_picks_up_new_nodes(env, calls):
    guard.protect_all(env.ctx)
    calls.clear()
    env.add_virtual("md126", 10)
    guard.reapply(env.ctx)
    assert "md126" in {c[0] for c in calls}


def test_exempt_overlay_stays_writable(env, calls):
    guard.exempt("dm-0")
    guard.protect_all(env.ctx)
    assert "dm-0" not in {c[0] for c in calls}


def test_failure_to_protect_stops_everything(env, monkeypatch, calls):
    def boom(fd, req, arg):
        raise OSError(1, "no")
    monkeypatch.setattr(guard, "_ioctl", boom)
    with pytest.raises(BeastNetError) as e:
        guard.protect_all(env.ctx)
    assert e.value.code == DISK_REFUSED
    assert "disk ro id=sda ro=0" in " ".join(env.rep.lines)


def test_status(env, calls):
    guard.protect_all(env.ctx)
    st = guard.status(env.ctx)
    assert st["sda"] is True and st["md127"] is True


def disk(env, ref):
    return discover.scan(env.ctx).disk(ref)


def test_make_writable_refuses_active_md_member(env, calls):
    d = disk(env, "SER-B")
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d, confirmed=True)
    assert e.value.code == DISK_REFUSED and "md127" in e.value.text
    assert not calls


def test_make_writable_target_and_close(env, calls):
    guard.protect_all(env.ctx)
    calls.clear()
    d = disk(env, "SER-A")
    with guard.make_writable(env.ctx, d, confirmed=True):
        assert [(n, v) for n, _r, v in calls] == [("sda", 0), ("sda1", 0), ("sda2", 0)]
        calls.clear()
        guard.reapply(env.ctx)  # the target is left alone while the handle is open
        assert "sda" not in {c[0] for c in calls} and "sdb" in {c[0] for c in calls}
        calls.clear()
    assert [(n, v) for n, _r, v in calls] == [("sda", 1), ("sda1", 1), ("sda2", 1)]
    assert "BEASTNET: disk ro id=sda ro=0" in env.rep.lines


def test_make_writable_refusals(env, calls):
    d = disk(env, "SER-A")
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d)  # not confirmed
    assert e.value.code == DISK_REFUSED
    d.is_boot_stick = True
    with pytest.raises(BeastNetError):
        guard.make_writable(env.ctx, d, confirmed=True)
    d.is_boot_stick = False
    d.serial = ""
    with pytest.raises(BeastNetError):
        guard.make_writable(env.ctx, d, confirmed=True)
    d.serial = "SER-A"
    env.set_mounts(f"{env.dev('sda2')} /mnt/x ext4 rw 0 0")
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d, confirmed=True)
    assert "mounted" in e.value.text
    env.set_mounts("")
    d.serial = "OTHER"  # identity changed since the plan
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d, confirmed=True)
    assert e.value.code == DISK_CHANGED
    assert not calls


def test_make_writable_partition_only_clears_the_disk_node_and_that_partition(env, calls):
    guard.protect_all(env.ctx)
    calls.clear()
    d = disk(env, "SER-A")
    env.set_mounts(f"{env.dev('sda1')} /mnt/x ext4 ro 0 0")  # a sibling in use does not matter
    with guard.make_writable(env.ctx, d, confirmed=True, partition="sda2") as h:
        assert h.partition == "sda2" and h.names == ["sda", "sda2"]
        assert [(n, v) for n, _r, v in calls] == [("sda", 0), ("sda2", 0)]
        calls.clear()
        guard.reapply(env.ctx)  # the sibling stays read-only, the target is left alone
        touched = {c[0]: c[2] for c in calls}
        assert touched.get("sda1") == 1 and "sda" not in touched and "sda2" not in touched
        calls.clear()
    assert [(n, v) for n, _r, v in calls] == [("sda", 1), ("sda2", 1)]


def test_make_writable_partition_accepts_a_path_and_refuses_others(env, calls):
    d = disk(env, "SER-A")
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d, confirmed=True, partition="sdb1")
    assert e.value.code == DISK_REFUSED and "not a partition of sda" in e.value.text
    env.set_mounts(f"{env.dev('sda2')} /mnt/x ext4 rw 0 0")
    with pytest.raises(BeastNetError) as e:
        guard.make_writable(env.ctx, d, confirmed=True, partition="/dev/sda2")
    assert "mounted" in e.value.text
    env.set_mounts(f"{env.dev('sda')} /mnt/x ext4 rw 0 0")  # the whole disk itself
    with pytest.raises(BeastNetError):
        guard.make_writable(env.ctx, d, confirmed=True, partition="sda2")
    env.set_mounts("")
    assert not calls
    guard.make_writable(env.ctx, d, confirmed=True, partition="/dev/sda2").close()


def test_two_partition_targets_share_the_disk_node(env, calls):
    d = disk(env, "SER-A")
    h1 = guard.make_writable(env.ctx, d, confirmed=True, partition="sda1")
    h2 = guard.make_writable(env.ctx, d, confirmed=True, partition="sda2")
    calls.clear()
    h1.close()  # sda stays writable: h2 still writes to sda2
    assert [(n, v) for n, _r, v in calls] == [("sda1", 1)]
    calls.clear()
    h2.close()
    assert [(n, v) for n, _r, v in calls] == [("sda", 1), ("sda2", 1)]
    assert not guard._handles
