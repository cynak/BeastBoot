"""Stack detection on fake machines: every stack kind, plus the AMD heuristics and their limits."""

import json

import pytest

from beastnet.disks import discover, probe
from beastnet.disks.model import StackKind, StackState, Support
from disk_fakes import GPT_SS, Env, cp

U = "11111111:22222222:33333333:44444444"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def stacks(env, kind=None):
    out = discover.scan(env.ctx).stacks
    return [s for s in out if kind is None or s.kind == kind]


def mdadm(env, table, text=""):
    """table: device path -> export text; ``text`` answers the non-export --examine (IMSM volumes)."""
    def reply(argv, e, i):
        if "--export" in argv:
            return cp(0, table.get(argv[-1], ""), "")
        return cp(0, text)
    env.runner.on("mdadm", reply)


def md_export(level="raid1", n=2, role=0, meta="1.2", uuid=U, name="host:0", dev="sdb"):
    return (f"MD_LEVEL={level}\nMD_DEVICES={n}\nMD_METADATA={meta}\nMD_UUID={uuid}\nMD_NAME={name}\n"
            f"MD_DEVICE_dev_{dev}_ROLE={role}\nMD_DEVICE_dev_{dev}_DEV=/dev/{dev}\n")


def raid_disks(env, n, typ, **extra):
    names = []
    for i in range(n):
        nm = "sd" + "bcdef"[i]
        env.add_disk(nm, 100, serial=f"S{i}")
        env.blk[env.dev(nm)] = {"TYPE": typ, "UUID": U, **extra}
        names.append(nm)
    return names


def test_md_clean_and_degraded_and_incomplete(env):
    names = raid_disks(env, 2, "linux_raid_member")
    mdadm(env, {env.dev(n): md_export(role=i, dev=n) for i, n in enumerate(names)})
    s, = stacks(env, StackKind.MD)
    assert (s.id, s.level, s.state, s.support, s.name) == (f"md:{U}", "raid1", StackState.CLEAN, Support.ASSEMBLE, "0")
    assert [m.index for m in s.members] == [0, 1]
    assert f"BEASTNET: stack found id=md:{U} kind=md level=raid1 members=2 state=clean support=assemble" in env.rep.lines


@pytest.mark.parametrize("level,n,present,state", [
    ("raid1", 2, 1, StackState.DEGRADED), ("raid5", 3, 2, StackState.DEGRADED),
    ("raid6", 4, 2, StackState.DEGRADED), ("raid0", 2, 1, StackState.INCOMPLETE),
    ("raid5", 4, 2, StackState.INCOMPLETE), ("linear", 2, 1, StackState.INCOMPLETE),
])
def test_md_member_counts(env, level, n, present, state):
    names = raid_disks(env, present, "linux_raid_member")
    mdadm(env, {env.dev(nm): md_export(level, n, i, dev=nm) for i, nm in enumerate(names)})
    s, = stacks(env, StackKind.MD)
    assert s.state == state


def test_md_spare_is_not_counted(env):
    names = raid_disks(env, 2, "linux_raid_member")
    mdadm(env, {env.dev(names[0]): md_export("raid1", 2, 0, dev=names[0]),
                env.dev(names[1]): md_export("raid1", 2, "spare", dev=names[1])})
    s, = stacks(env, StackKind.MD)
    assert s.state == StackState.DEGRADED and s.members[1].state == "spare"


def test_md_without_the_mdadm_tool_still_groups_by_blkid(env):
    raid_disks(env, 2, "linux_raid_member")
    s, = stacks(env, StackKind.MD)
    assert len(s.members) == 2 and s.state == StackState.UNKNOWN and any("mdadm" in n for n in s.notes)


def test_md_on_partitions(env):
    env.add_disk("sdb", 100, serial="A")
    p = env.add_part("sdb", 1, 1, 90, TYPE="linux_raid_member", UUID=U)
    mdadm(env, {env.dev(p): md_export(dev=p, n=1, level="linear")})
    s, = stacks(env, StackKind.MD)
    assert s.members[0].device == env.dev(p) and s.members[0].disk_id == "sdb"


def test_imsm_without_intel_controller_needs_no_platform(env):
    names = raid_disks(env, 2, "isw_raid_member")
    mdadm(env, {env.dev(n): md_export("container", 2, 0, "imsm", dev=n) for n in names},
          text="   Volume0\n   RAID Level : 1\n")
    s, = stacks(env, StackKind.IMSM)
    assert (s.level, s.support, s.state) == ("raid1", Support.ASSEMBLE, StackState.CLEAN)
    assert any("IMSM_NO_PLATFORM=1" in n for n in s.notes)
    assert all(e.get("IMSM_NO_PLATFORM") == "1" for e, c in zip(env.runner.envs, env.runner.calls) if c[0] == "mdadm")


def test_imsm_with_intel_raid_controller_does_not_set_the_variable(env):
    names = raid_disks(env, 2, "isw_raid_member")
    env.add_pci("0000:00:17.0", 0x8086, 0x2822, 0x010400)
    mdadm(env, {env.dev(n): md_export("container", 2, 0, "imsm", dev=n) for n in names}, text="RAID Level : 5\n")
    s, = stacks(env, StackKind.IMSM)
    assert s.level == "raid5" and not any("IMSM_NO_PLATFORM" in n for n in s.notes)
    assert all("IMSM_NO_PLATFORM" not in e for e in env.runner.envs)
    assert probe.intel_raid_present(env.ctx)


def test_ddf(env):
    names = raid_disks(env, 2, "ddf_raid_member")
    mdadm(env, {env.dev(n): md_export("container", 2, 0, "ddf", dev=n) for n in names}, text="RAID Level : 0\n")
    s, = stacks(env, StackKind.DDF)
    assert s.id == f"ddf:{U}" and s.level == "raid0" and s.support == Support.ASSEMBLE


LVM_PVS = {"report": [{"pv": [
    {"pv_name": "{a}", "pv_uuid": "p1", "vg_name": "vg0", "vg_uuid": "VGU", "pv_missing": ""},
    {"pv_name": "{b}", "pv_uuid": "p2", "vg_name": "vg0", "vg_uuid": "VGU", "pv_missing": ""}]}]}


def lvm(env, a, b, pv_count=2, missing=0):
    def reply(argv, e, i):
        assert "metadata_read_only=1" in " ".join(argv)  # detection never takes a writable view
        if argv[1] == "pvs":
            return cp(0, json.dumps(LVM_PVS).replace("{a}", a).replace("{b}", b))
        return cp(0, json.dumps({"report": [{"vg": [{"vg_name": "vg0", "vg_uuid": "VGU", "pv_count": str(pv_count),
                                                      "vg_missing_pv_count": str(missing)}]}]}))
    env.runner.on("lvm", reply)


def test_lvm(env):
    names = raid_disks(env, 2, "LVM2_member")
    lvm(env, env.dev(names[0]), env.dev(names[1]))
    s, = stacks(env, StackKind.LVM)
    assert (s.id, s.name, s.state, s.support) == ("lvm:VGU", "vg0", StackState.CLEAN, Support.ASSEMBLE)
    assert len(s.members) == 2


def test_lvm_missing_pv(env):
    names = raid_disks(env, 1, "LVM2_member")
    lvm(env, env.dev(names[0]), "[unknown]", pv_count=2, missing=1)
    s, = stacks(env, StackKind.LVM)
    assert s.state == StackState.INCOMPLETE and len(s.members) == 1


def test_lvm_without_the_tool_is_detect_only(env):
    raid_disks(env, 1, "LVM2_member")
    s, = stacks(env, StackKind.LVM)
    assert s.support == Support.DETECT


def test_lvm_on_an_assembled_md_device(env):
    env.add_disk("sdb", 100, serial="A")
    env.add_virtual("md127", 90, slaves=["sdb"], meta="1.2")
    env.blk[env.dev("md127")] = {"TYPE": "LVM2_member"}
    lvm(env, env.dev("md127"), "[unknown]", pv_count=1)
    s, = stacks(env, StackKind.LVM)
    assert s.members[0].device == env.dev("md127") and s.members[0].disk_id == "sdb"


def test_luks_and_bitlocker(env):
    env.add_disk("sdb", 100, serial="A")
    env.add_part("sdb", 1, 1, 40, TYPE="crypto_LUKS", UUID="lu-1", VERSION="2")
    env.add_part("sdb", 2, 41, 40, TYPE="BitLocker", UUID="bl-1")
    luks, = stacks(env, StackKind.LUKS)
    bl, = stacks(env, StackKind.BITLOCKER)
    assert (luks.id, luks.level, luks.support) == ("luks:lu-1", "luks2", Support.ASSEMBLE)
    assert bl.id == "bitlocker:bl-1" and "recovery key" in bl.notes[0]


def test_btrfs_multi_device_only(env):
    env.add_disk("sdb", 100, serial="A")
    env.add_disk("sdc", 100, serial="B")
    env.add_disk("sdd", 100, serial="C")
    env.blk[env.dev("sdb")] = {"TYPE": "btrfs", "UUID": "bt-1", "LABEL": "pool"}
    env.blk[env.dev("sdc")] = {"TYPE": "btrfs", "UUID": "bt-1"}
    env.blk[env.dev("sdd")] = {"TYPE": "btrfs", "UUID": "bt-2"}  # single device: a plain file system
    s, = stacks(env, StackKind.BTRFS)
    assert s.id == "btrfs:bt-1" and len(s.members) == 2 and s.name == "pool"


def test_zfs_needs_pack_until_zpool_exists(env):
    raid_disks(env, 2, "zfs_member", LABEL="tank")
    s, = stacks(env, StackKind.ZFS)
    assert s.support == Support.NEEDS_PACK and "pack" in " ".join(s.notes)
    env.runner.on("zpool", cp(0, "zfs 2.3"))
    s, = stacks(env, StackKind.ZFS)
    assert s.support == Support.ASSEMBLE and s.name == "tank"


def test_fakeraid(env):
    for nm, typ in (("sdb", "promise_fasttrack_raid_member"), ("sdc", "promise_fasttrack_raid_member"),
                    ("sdd", "via_raid_member")):
        env.add_disk(nm, 100, serial=nm)
        env.blk[env.dev(nm)] = {"TYPE": typ}
    out = {s.id: s for s in stacks(env, StackKind.FAKERAID_OTHER)}
    assert out["fakeraid:promise_fasttrack"].support == Support.RECONSTRUCT
    assert out["fakeraid:via"].support == Support.DETECT


def test_storage_spaces_by_gpt_type(env):
    for nm in ("sdb", "sdc"):
        env.add_disk(nm, 100, serial=nm)
        env.add_part(nm, 1, 1, 90, PART_ENTRY_TYPE=GPT_SS)
    s, = stacks(env, StackKind.STORAGE_SPACES)
    assert s.support == Support.RECONSTRUCT and len(s.members) == 2
    assert s.members[0].device.endswith("sdb1")


def test_ldm_by_partition_type_is_detect_only(env):
    env.add_disk("sdb", 100, serial="A")
    env.add_part("sdb", 1, 1, 90, PART_ENTRY_TYPE="0x42")
    env.add_disk("sdc", 100, serial="B")
    env.add_part("sdc", 1, 1, 90, PART_ENTRY_TYPE="5808c8aa-7e8f-42e0-85d2-e1e90434cfb3")
    s, = stacks(env, StackKind.LDM)
    assert s.support == Support.DETECT and [m.disk_id for m in s.members] == ["sdb", "sdc"]
    assert "image each disk" in s.notes[0]
    assert not [c for c in env.runner.calls if c[0] == "ldmtool"]  # not in the helper any more


# -- AMD heuristics -----------------------------------------------------------------------

def blank_disks(env, n, size=2048, content=b"\x5a" * 4096):
    for i in range(n):
        env.add_disk("sd" + "bcdef"[i], size, serial=f"S{i}", content=content)


def test_amd_controller_in_raid_mode_flags_unrecognised_disks(env):
    env.add_pci("0000:03:00.0", 0x1022, 0x7916, 0x010400)
    blank_disks(env, 2)
    env.add_disk("sdx", 2048, serial="Z")
    env.add_part("sdx", 1, 1, 100, TYPE="ntfs")
    env.blk[env.dev("sdx")] = {"PTTYPE": "gpt"}
    s, = stacks(env, StackKind.AMD_RAID)
    assert (s.support, len(s.members)) == (Support.RECONSTRUCT, 2)
    assert "may be an AMD RAID member; Linux cannot read AMD's metadata" in s.notes[0]
    assert any("AMD RAID-mode controller" in n for n in s.notes)


def test_amd_without_controller_needs_two_equal_nonzero_disks(env):
    blank_disks(env, 2)
    s, = stacks(env, StackKind.AMD_RAID)
    assert len(s.members) == 2 and any("No AMD RAID controller" in n for n in s.notes)


def test_amd_not_for_one_disk_blank_disks_usb_or_the_stick(env):
    blank_disks(env, 1)
    assert not stacks(env, StackKind.AMD_RAID)  # one unrecognised disk without a controller


def test_amd_blank_zero_disks_are_not_members_without_a_controller(env):
    blank_disks(env, 2, content=b"\0" * 4096)
    assert not stacks(env, StackKind.AMD_RAID)


def test_amd_skips_usb_removable_and_small(env):
    env.add_pci("0000:03:00.0", 0x1022, 0x7916, 0x010400)
    env.add_disk("sdb", 2048, transport="usb", serial="U", removable=1)
    env.add_disk("sdc", 10, serial="tiny")
    assert not stacks(env, StackKind.AMD_RAID)


def test_amd_skips_md_members(env):
    env.add_pci("0000:03:00.0", 0x1022, 0x7916, 0x010400)
    names = raid_disks(env, 2, "linux_raid_member")
    mdadm(env, {env.dev(n): md_export(dev=n, role=i) for i, n in enumerate(names)})
    assert not stacks(env, StackKind.AMD_RAID)
