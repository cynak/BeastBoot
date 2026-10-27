"""Read-only assembly: the command lines, the read-only checks, and the refusals."""

import json
import os
import shutil

import pytest

from beastnet.disks import assemble, guard
from beastnet.disks.model import Member, Stack, StackKind, StackState, Support, VolumeKind
from beastnet.errors import ASSEMBLE, BeastNetError
from disk_fakes import Env, cp

SECRET = "correct horse battery staple"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "_ioctl", lambda fd, req, arg: 0)
    monkeypatch.setattr(guard, "_writable", set())
    e = Env(tmp_path)
    for nm in ("sdb", "sdc"):
        e.add_disk(nm, 100, serial=nm)
    e.overlays = e.fake_overlays()
    return e


def mk(kind, devs=("sdb", "sdc"), support=Support.ASSEMBLE, state=StackState.CLEAN, name="", sid=None):
    return Stack(id=sid or f"{kind.value}:UU", kind=kind, members=[Member(f"/dev/{d}", d) for d in devs],
                 support=support, state=state, name=name)


def fix_members(env, stack):
    for m in stack.members:
        m.device = env.dev(m.device.rsplit("/", 1)[1])


IMSM_EXAMINE = """/dev/sdb:
          Magic : Intel Raid ISM Cfg Sig.
        Version : 1.3.00
[Volume0]:
     RAID Level : 5
  Migrate State : idle
      Map State : normal
    Dirty State : clean
     RWH Policy : {rwh}
"""


def md_assembler(env, state="readonly", ro=1, rwh="off"):
    """mdadm --assemble makes md127 on the devices it is given (overlays or members), and
    the volume under an IMSM container; --examine answers IMSM metadata."""
    def slaves(argv):
        devs = [a for a in argv[2:] if a.startswith("/") and "/md" not in a]
        return [env.overlays.get(os.path.basename(d), os.path.basename(d)) for d in devs] or ["sdb", "sdc"]

    def reply(argv, e, i):
        if "--assemble" in argv:
            name = next(a for a in argv if "/md" in a).rsplit("/", 1)[1]
            ext_flag["slaves"] = slaves(argv)
            if ext_flag["external"]:
                env.add_virtual(name, 0, slaves=ext_flag["slaves"], meta="external:imsm", state="inactive")
            else:
                env.add_virtual(name, 90, slaves=ext_flag["slaves"], meta="1.2", state=state, ro=ro)
        elif "--incremental" in argv:
            env.add_virtual("md126", 90, slaves=ext_flag["slaves"], meta="external:/md127/0", state=state, ro=ro)
        elif "--examine" in argv:
            return cp(0, IMSM_EXAMINE.format(rwh=rwh))
        return cp(0)
    ext_flag = {"external": False, "slaves": []}
    env.runner.on("mdadm", reply)
    return ext_flag


def test_md_start_is_readonly_and_reports(env):
    md_assembler(env)
    s = mk(StackKind.MD, sid="md:UU")
    fix_members(env, s)
    vols = assemble.start(env.ctx, s)
    call = env.runner.ran("mdadm")[0]
    assert call[:4] == ["mdadm", "--assemble", "--readonly", "--config=none"]
    # md starts on RAM overlays of the members: a bitmap or superblock write lands in the COW
    assert "--force" not in call and "--run" not in call
    assert call[-2:] == ["/dev/mapper/bbro_sdb", "/dev/mapper/bbro_sdc"]
    tables = [c[c.index("--table") + 1] for c in env.runner.calls if c[:2] == ["dmsetup", "create"]]
    assert [t.split()[2:4] for t in tables] == [["snapshot", env.dev("sdb")], ["snapshot", env.dev("sdc")]]
    assert env.runner.calls.index(call) > max(i for i, c in enumerate(env.runner.calls) if c[:2] == ["dmsetup", "create"])
    assert not guard._exempt & {"dm-50", "dm-51"}  # overlay nodes stay under the guard
    assert env.runner.envs[env.runner.calls.index(call)]["MDADM_NO_UDEV"] == "1"
    assert [(v.id, v.kind, v.readonly, v.from_stack, v.disk_ids) for v in vols] == \
        [("md127", VolumeKind.MD, True, "md:UU", ["sdb", "sdc"])]
    assert f"BEASTNET: assemble ok id=md:UU dev={env.dev('md127')} ro=1" in env.rep.lines
    assert env.runner.ran("mdev") == [["mdev", "-s"]]
    assert open(env.sys("module", "md_mod", "parameters", "start_ro")).read() == "1"
    assert env.runner.envs[env.runner.calls.index(call)]["MDADM_NO_MDMON"] == "1"


def test_md_refuses_to_start_when_start_ro_cannot_be_set(env):
    md_assembler(env)
    s = mk(StackKind.MD, sid="md:UU")
    fix_members(env, s)
    shutil.rmtree(env.sys("module", "md_mod"))  # no md in this kernel: nothing may start
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert e.value.code == "assemble" and not env.runner.ran("mdadm")


def test_md_degraded_uses_run_never_force(env):
    md_assembler(env)
    s = mk(StackKind.MD, devs=("sdb",), state=StackState.DEGRADED)
    fix_members(env, s)
    assemble.start(env.ctx, s)
    call = env.runner.ran("mdadm")[0]
    assert "--run" in call and "--force" not in call and "--readonly" in call


def test_md_that_did_not_start_readonly_is_stopped_and_fails(env):
    md_assembler(env, state="clean", ro=0)
    s = mk(StackKind.MD)
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert e.value.code == ASSEMBLE
    assert ["mdadm", "--stop", env.dev("md127")] in env.runner.calls
    assert "BEASTNET: assemble fail id=md:UU code=assemble" in env.rep.lines
    removed = [c[-1] for c in env.runner.calls if c[:2] == ["dmsetup", "remove"]]
    assert removed == ["bbro_sdb", "bbro_sdc"] and not assemble.overlay.overlays(env.ctx)


def test_md_read_auto_is_pushed_to_readonly(env):
    md_assembler(env, state="read-auto")
    s = mk(StackKind.MD)
    fix_members(env, s)

    def to_ro(argv, e, i):
        if argv[1] == "--readonly":
            env.write(env.sys("block", "md127", "md", "array_state"), "readonly\n")
        return cp(0)
    old = env.runner.handlers[0]
    env.runner.on(lambda a: a[:2] == ["mdadm", "--readonly"], to_ro)
    assert env.runner.handlers[0] is not old
    assert assemble.start(env.ctx, s)


def test_imsm_assembles_container_then_volumes_with_no_platform(env):
    flag = md_assembler(env)
    flag["external"] = True
    s = mk(StackKind.IMSM, sid="imsm:UU")
    fix_members(env, s)
    vols = assemble.start(env.ctx, s)
    kinds = [c[1] for c in env.runner.ran("mdadm")]
    assert kinds == ["--examine", "--examine", "--assemble", "--incremental"]
    # IMSM members are found by serial number, which an overlay lacks: no overlays here
    assert env.runner.ran("mdadm")[2][-2:] == [env.dev("sdb"), env.dev("sdc")]
    assert not [c for c in env.runner.calls if c[:2] == ["dmsetup", "create"]]
    inc = env.runner.ran("mdadm")[3]
    # --incremental takes no --readonly: start_ro=1 first, then each volume is set read-only
    assert "--run" in inc and "--force" not in inc
    assert open(env.sys("module", "md_mod", "parameters", "start_ro")).read() == "1"
    assert all(e.get("IMSM_NO_PLATFORM") == "1" for e, c in zip(env.runner.envs, env.runner.calls) if c[0] == "mdadm")
    assert [v.id for v in vols] == ["md126"]  # the container is not returned


@pytest.mark.parametrize("rwh", ["PPL distributed", "bitmap", "Multiple distributed PPLs"])
def test_imsm_with_a_bitmap_or_ppl_is_refused_before_anything_starts(env, rwh):
    md_assembler(env, rwh=rwh)
    s = mk(StackKind.IMSM, sid="imsm:UU")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert e.value.code == ASSEMBLE and "Image each member" in e.value.hint
    assert [c[1] for c in env.runner.ran("mdadm")] == ["--examine"]


def test_imsm_in_migration_is_refused(env):
    md_assembler(env)
    env.runner.on(lambda a: a[:2] == ["mdadm", "--examine"],
                  cp(0, IMSM_EXAMINE.format(rwh="off").replace("Migrate State : idle", "Migrate State : rebuild")))
    s = mk(StackKind.IMSM, sid="imsm:UU")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert "migration" in e.value.text and not [c for c in env.runner.ran("mdadm") if "--assemble" in c]


def test_ddf_starts_on_overlays(env):
    flag = md_assembler(env)
    flag["external"] = True
    s = mk(StackKind.DDF, sid="ddf:UU")
    fix_members(env, s)
    assert [v.id for v in assemble.start(env.ctx, s)] == ["md126"]
    asm = next(c for c in env.runner.ran("mdadm") if "--assemble" in c)
    assert asm[-2:] == ["/dev/mapper/bbro_sdb", "/dev/mapper/bbro_sdc"]
    env.runner.on(lambda a: a[:2] == ["mdadm", "--stop"], cp(0))
    assemble.stop(env.ctx, s)
    stops = [c[2] for c in env.runner.ran("mdadm") if c[1] == "--stop"]
    assert stops == [env.dev("md126"), env.dev("md127")]  # volume, container, then the overlays
    assert [c[-1] for c in env.runner.calls if c[:2] == ["dmsetup", "remove"]] == ["bbro_sdb", "bbro_sdc"]


def test_md_stop_finds_the_array_on_overlays_and_removes_them(env):
    md_assembler(env)
    s = mk(StackKind.MD, sid="md:UU")
    fix_members(env, s)
    assemble.start(env.ctx, s)
    assert set(assemble.overlay.overlays(env.ctx)) == {"/dev/mapper/bbro_sdb", "/dev/mapper/bbro_sdc"}
    env.runner.on(lambda a: a[:2] == ["mdadm", "--stop"], cp(0))
    assemble.stop(env.ctx, s)
    i = env.runner.calls.index(["mdadm", "--stop", env.dev("md127")])
    rm = [j for j, c in enumerate(env.runner.calls) if c[:2] == ["dmsetup", "remove"]]
    assert len(rm) == 2 and min(rm) > i and not assemble.overlay.overlays(env.ctx)


def test_reconstruction_overlays_are_not_shared(env):
    """A reconstruction of the same disks has its own overlays (bbov_*): the started
    stack's are neither reused nor removed by it."""
    from beastnet.disks import overlay
    md_assembler(env)
    s = mk(StackKind.MD, sid="md:UU")
    fix_members(env, s)
    assemble.start(env.ctx, s)
    rec = overlay.create(env.ctx, [env.dev("sdb")], exempt=lambda *a: None)
    assert rec == ["/dev/mapper/bbov_sdb"]
    overlay.remove(env.ctx, [env.dev("sdb")], unexempt=lambda *a: None)  # by device: its own only
    assert set(overlay.overlays(env.ctx)) == {"/dev/mapper/bbro_sdb", "/dev/mapper/bbro_sdc"}


def test_rescan_does_not_count_overlays_as_members(env):
    from beastnet.disks import probe
    md_assembler(env)
    s = mk(StackKind.MD, sid="md:UU")
    fix_members(env, s)
    assemble.start(env.ctx, s)
    vols = [v for v in assemble.assembled_volumes(env.ctx)]
    ids = {v.id for v in vols}
    assert "md127" in ids and not {"dm-50", "dm-51"} & ids  # overlays are not volumes
    seen = []
    env.runner.on("blkid", lambda a, e, i: (seen.extend(a[4:]), cp(2))[1])
    probe.detect(env.ctx, [], vols)
    assert env.dev("md127") in seen and not {env.dev("dm-50"), env.dev("dm-51")} & set(seen)


def test_unsupported_and_incomplete_stacks_are_refused(env):
    for kind, sup, state in ((StackKind.AMD_RAID, Support.RECONSTRUCT, StackState.UNKNOWN),
                             (StackKind.STORAGE_SPACES, Support.RECONSTRUCT, StackState.UNKNOWN),
                             (StackKind.FAKERAID_OTHER, Support.DETECT, StackState.UNKNOWN),
                             (StackKind.ZFS, Support.NEEDS_PACK, StackState.UNKNOWN),
                             (StackKind.MD, Support.ASSEMBLE, StackState.INCOMPLETE)):
        s = mk(kind, support=sup, state=state)
        fix_members(env, s)
        with pytest.raises(BeastNetError) as e:
            assemble.start(env.ctx, s)
        assert e.value.code == ASSEMBLE
    assert not env.runner.ran("mdadm") and not env.runner.ran("cryptsetup")
    assert sum("assemble fail" in line for line in env.rep.lines) == 5


def test_missing_member_node_is_refused(env):
    s = mk(StackKind.MD, devs=("sdq",))
    with pytest.raises(BeastNetError):
        assemble.start(env.ctx, s)


# -- LUKS / BitLocker ---------------------------------------------------------------------

def crypt_runner(env, ro=1, rc=0):
    def reply(argv, e, i):
        if argv[1] == "open" and rc == 0:
            env.add_virtual("dm-0", 80, slaves=["sdb"], uuid="CRYPT-LUKS2-x-bbluks", ro=ro)
        return cp(rc)
    env.runner.on("cryptsetup", reply)


def test_luks_needs_a_passphrase(env):
    s = mk(StackKind.LUKS, devs=("sdb",), sid="luks:abcd-1234")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert "passphrase" in e.value.text and not env.runner.ran("cryptsetup")


def test_luks_open_is_readonly_and_the_secret_only_goes_to_stdin(env):
    crypt_runner(env)
    s = mk(StackKind.LUKS, devs=("sdb",), sid="luks:abcd-1234")
    fix_members(env, s)
    vols = assemble.start(env.ctx, s, passphrase=SECRET)
    argv = [c for c in env.runner.calls if c[:2] == ["cryptsetup", "open"]][0]
    assert "--readonly" in argv and ["--type", "luks"] == argv[argv.index("--type"):argv.index("--type") + 2]
    assert not any(SECRET in a for c in env.runner.calls for a in c)
    assert not any(SECRET in str(v) for e in env.runner.envs for v in e.values())
    assert env.runner.inputs[env.runner.calls.index(argv)] == SECRET + "\n"
    assert not any(SECRET in line for line in env.rep.lines)
    assert [(v.id, v.kind) for v in vols] == [("dm-0", VolumeKind.CRYPT)]


def test_bitlocker_uses_bitlk_type(env):
    crypt_runner(env)
    s = mk(StackKind.BITLOCKER, devs=("sdb",), sid="bitlocker:x")
    fix_members(env, s)
    assemble.start(env.ctx, s, passphrase="111111-222222")
    argv = [c for c in env.runner.calls if c[:2] == ["cryptsetup", "open"]][0]
    assert argv[argv.index("--type") + 1] == "bitlk"


def test_wrong_passphrase_message_does_not_echo_it(env):
    crypt_runner(env, rc=2)
    s = mk(StackKind.LUKS, devs=("sdb",), sid="luks:abcd")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s, passphrase=SECRET)
    assert SECRET not in str(e.value) and "not accepted" in e.value.text


def test_unlocked_device_that_is_writable_is_closed_again(env):
    crypt_runner(env, ro=0)
    s = mk(StackKind.LUKS, devs=("sdb",), sid="luks:abcd")
    fix_members(env, s)
    with pytest.raises(BeastNetError):
        assemble.start(env.ctx, s, passphrase=SECRET)
    assert any(c[:2] == ["cryptsetup", "close"] for c in env.runner.calls)


# -- LVM / ZFS / btrfs --------------------------------------------------------------------

def lvs_json(*segtypes):
    return json.dumps({"report": [{"lv": [{"lv_name": f"lv{i}", "segtype": t} for i, t in enumerate(segtypes)]}]})


def lvm_runner(env, ro=1, segtypes=("linear", "striped")):
    def reply(argv, e, i):
        if argv[1] == "lvs":
            return cp(0, lvs_json(*segtypes))
        if argv[1] == "vgchange" and "-ay" in argv:
            env.add_virtual("dm-0", 40, slaves=["dm-50"], uuid="LVM-x", ro=ro, holders=())
            env.add_virtual("dm-1", 10, slaves=["dm-0"], uuid="LVM-y", ro=ro)  # an inner device
            env.write(env.sys("block", "dm-0", "holders", "dm-1"), "")
        return cp(0)
    env.runner.on("lvm", reply)


def test_lvm_activates_read_only_on_overlays_and_returns_top_level_volumes(env):
    lvm_runner(env)
    s = mk(StackKind.LVM, devs=("sdb",), name="vg0", sid="lvm:VGU")
    fix_members(env, s)
    vols = assemble.start(env.ctx, s)
    lvs, act = env.runner.ran("lvm")
    assert lvs[:3] == ["lvm", "lvs", "-a"] and lvs[lvs.index("--devices") + 1] == env.dev("sdb")
    assert act[:5] == ["lvm", "vgchange", "-ay", "--devices", "/dev/mapper/bbro_sdb"] and act[5] == "vg0"
    cfg = act[act.index("--config") + 1]
    assert 'read_only_volume_list=["vg0"]' in cfg and "metadata_read_only=1" in cfg
    assert [(v.id, v.kind, v.disk_ids) for v in vols] == [("dm-1", VolumeKind.LV, ["sdb"])]
    env.runner.calls.clear()
    assemble.stop(env.ctx, s)
    assert env.runner.calls[0][:5] == ["lvm", "vgchange", "-an", "--devices", "/dev/mapper/bbro_sdb"]
    assert ["dmsetup", "remove", "--retry", "bbro_sdb"] in env.runner.calls


def test_lvm_writable_activation_is_rolled_back(env):
    lvm_runner(env, ro=0)
    s = mk(StackKind.LVM, devs=("sdb",), name="vg0", sid="lvm:VGU")
    fix_members(env, s)
    with pytest.raises(BeastNetError):
        assemble.start(env.ctx, s)
    assert any(c[:3] == ["lvm", "vgchange", "-an"] for c in env.runner.calls)
    assert not assemble.overlay.overlays(env.ctx)


@pytest.mark.parametrize("seg", ["raid1", "raid5", "mirror", "thin-pool", "thin", "cache", "cache-pool", "writecache",
                                 "integrity", "vdo", "snapshot", "error"])
def test_lvm_with_lvs_that_write_on_activation_is_refused(env, seg):
    lvm_runner(env, segtypes=("linear", seg))
    s = mk(StackKind.LVM, devs=("sdb", "sdc"), name="vg0", sid="lvm:VGU")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert seg in e.value.text and e.value.hint == "Image the physical volumes instead."
    assert [c[1] for c in env.runner.ran("lvm")] == ["lvs"]
    assert not [c for c in env.runner.calls if c[:2] == ["dmsetup", "create"]]


def test_lvm_unreadable_lv_types_are_refused(env):
    env.runner.on("lvm", cp(5, "", "  Volume group not found"))
    s = mk(StackKind.LVM, devs=("sdb",), name="vg0", sid="lvm:VGU")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert "could not read the logical volumes" in e.value.text
    assert not [c for c in env.runner.ran("lvm") if c[1] == "vgchange"]


def test_zfs_imports_readonly_without_mounting_or_cachefile(env):
    env.write(env.sys("module", "zfs", "parameters", "zfs_arc_max"), "0")
    env.write(env.root + "/proc/meminfo", "MemTotal:        4194304 kB\n")
    env.runner.on("zpool", cp(0))
    s = mk(StackKind.ZFS, devs=("sdb", "sdc"), name="tank", sid="zfs:1234567890")
    fix_members(env, s)
    vols = assemble.start(env.ctx, s)
    argv = [c for c in env.runner.calls if c[:2] == ["zpool", "import"]][0]
    assert argv == ["zpool", "import", "-o", "readonly=on", "-N", "-o", "cachefile=none", "-d", env.paths.dev,
                    "1234567890"]
    with open(env.sys("module", "zfs", "parameters", "zfs_arc_max")) as f:
        assert int(f.read()) == 256 << 20
    assert vols[0].kind == VolumeKind.ZFS_DATASET and vols[0].readonly


def test_zfs_without_the_pack_fails_plainly(env):
    s = mk(StackKind.ZFS, name="tank", sid="zfs:1")
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert "ZFS pack" in e.value.text


def test_btrfs_needs_no_assembly(env):
    env.add_part("sdb", 1, 1, 50)
    s = mk(StackKind.BTRFS, devs=("sdb1", "sdc"), sid="btrfs:bt")
    s.members[0].disk_id = "sdb"
    fix_members(env, s)
    vols = assemble.start(env.ctx, s)
    assert [v.id for v in vols] == ["sdb1"] and vols[0].size == 50 << 20 and vols[0].disk_ids == ["sdb", "sdc"]


@pytest.mark.parametrize("support", [Support.ASSEMBLE, Support.DETECT])
def test_ldm_is_detect_only(env, support):
    s = mk(StackKind.LDM, devs=("sdb",), sid="ldm:G", support=support)
    fix_members(env, s)
    with pytest.raises(BeastNetError) as e:
        assemble.start(env.ctx, s)
    assert "Image each disk" in e.value.hint and not env.runner.calls


# -- stop ---------------------------------------------------------------------------------

def test_stop_md_refuses_while_mounted_then_stops_arrays_before_container(env):
    env.add_virtual("md127", 0, slaves=["sdb", "sdc"], meta="external:imsm")
    env.add_virtual("md126", 90, slaves=["sdb", "sdc"], meta="external:/md127/0")
    env.runner.on("mdadm", cp(0))
    s = mk(StackKind.IMSM)
    fix_members(env, s)
    env.set_mounts(f"{env.dev('md126')} /mnt/x ext4 ro 0 0")
    with pytest.raises(BeastNetError):
        assemble.stop(env.ctx, s)
    env.set_mounts("")
    assemble.stop(env.ctx, s)
    assert [c[2] for c in env.runner.ran("mdadm")] == [env.dev("md126"), env.dev("md127")]


def test_stop_luks_closes_the_mapping(env):
    env.runner.on("cryptsetup", cp(0))
    s = mk(StackKind.LUKS, devs=("sdb",), sid="luks:abcd-1234")
    assemble.stop(env.ctx, s)
    assert ["cryptsetup", "close", assemble.crypt_name(s)] in env.runner.calls


# -- the command filter -------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["mdadm", "--assemble", "--force", "--readonly", "/dev/md0", "/dev/sdb"],
    ["mdadm", "--assemble", "/dev/md0", "/dev/sdb"],  # no --readonly
    ["mdadm", "--assemble", "--readonly", "--update=resync", "/dev/md0"],
    ["mdadm", "--assemble", "--readonly", "-f", "/dev/md0"],
    ["mdadm", "--create", "/dev/md0", "--level=1"],
    ["mdadm", "/dev/md0", "--add", "/dev/sdb"],
    ["mdadm", "--grow", "/dev/md0"],
    ["mdadm", "--zero-superblock", "/dev/sdb"],
    ["mdadm", "--readwrite", "/dev/md0"],
    ["mdadm", "-w", "/dev/md0"],
    ["mdadm", "--action=repair", "/dev/md0"],
    ["mdadm", "--wait-clean", "/dev/md0"],
    ["mdadm", "--kill-subarray=0", "/dev/md127"],
    ["mdadm", "--update-subarray=0", "--update=name", "/dev/md127"],
    ["mdadm", "--set-faulty", "/dev/md0", "/dev/sdb"],
    ["mdadm", "/dev/md0", "-r", "/dev/sdb"],
    ["mdadm", "--assemble", "--readonly", "--scan"],
    ["mdadm", "--assemble", "--readonly", "--backup-file=/x", "/dev/md0", "/dev/sdb"],
    ["mdadm", "--assemble", "--readonly", "--config=/etc/mdadm.conf", "/dev/md0", "/dev/sdb"],
    ["mdadm", "--readonly", "/dev/md0", "/dev/md1"],
    ["mdadm", "--stop", "--scan"],
    ["mdadm", "--examine", "--update=resync", "/dev/sdb"],
    ["mdadm", "--detail", "--test", "/dev/md0"],
    ["mdadm", "--incremental", "--run", "/dev/sdb", "/dev/sdc"],
    ["mdadm", "--misc", "/dev/md0"],
    ["cryptsetup", "open", "--type", "luks", "/dev/sdb", "x"],  # no --readonly
    ["cryptsetup", "open", "--readonly", "--allow-discards", "--type", "luks", "/dev/sdb", "x"],
    ["cryptsetup", "open", "--readonly", "--type", "plain", "/dev/sdb", "x"],
    ["cryptsetup", "luksFormat", "/dev/sdb"],
    ["cryptsetup", "luksAddKey", "/dev/sdb"],
    ["cryptsetup", "erase", "/dev/sdb"],
    ["lvm", "vgchange", "-ay", "vg0"],  # no read-only config
    ["lvm", "vgchange", "-ay", "vg0", "--partial", "--config", "global{metadata_read_only=1} read_only_volume_list=[]"],
    ["lvm", "vgremove", "vg0"],
    ["lvm", "vgchange", "-ay", "--devices", "/dev/mapper/bbro_sdb", "vg0", "--config",
     "global{metadata_read_only=1} activation{read_only_volume_list=[]}"],  # an empty list protects nothing
    ["lvm", "vgchange", "-ay", "--devices", "/dev/sdb", "vg0", "--config", assemble.lvm_config("vg0")],  # not overlays
    ["lvm", "vgchange", "-ay", "vg0", "--config", assemble.lvm_config("vg0")],  # no --devices
    ["lvm", "vgchange", "-ay", "--activationmode", "partial", "--devices", "/dev/mapper/bbro_sdb", "vg0",
     "--config", assemble.lvm_config("vg0")],
    ["lvm", "vgchange", "-aay", "vg0"],
    ["lvm", "vgchange", "-ay", "--refresh", "vg0"],
    ["lvm", "vgchange", "-ay", "--devices", "/dev/mapper/bbro_sdb", "--select", "vg_name=~.*", "--config",
     assemble.lvm_config("vg0")],
    ["lvm", "lvs", "--foreign", "vg0"],
    ["ldmtool", "create", "all"],
    ["ldmtool", "scan", "/dev/sdb"],
    ["lvm", "lvchange", "-p", "rw", "vg0/lv"],
    ["lvm", "pvcreate", "/dev/sdb"],
    ["zpool", "import", "-N", "-o", "cachefile=none", "-d", "/dev", "tank"],  # not readonly
    ["zpool", "import", "-f", "-o", "readonly=on", "-N", "-o", "cachefile=none", "tank"],
    ["zpool", "import", "-F", "-o", "readonly=on", "-N", "-o", "cachefile=none", "tank"],
    ["zpool", "import", "-o", "readonly=on", "-o", "cachefile=none", "tank"],  # would mount datasets
    ["zpool", "destroy", "tank"],
    ["mdadm", "--incremental", "/dev/sdb"],  # only to start a container's volumes (--run)
    ["zpool", "scrub", "tank"],
    ["dmsetup", "remove", "x"],
    ["dmsetup", "create", "x"],
    ["ldmtool", "write", "x"],
    ["mdev"], ["mkfs.ext4", "/dev/sdb"], ["dd", "of=/dev/sdb"], ["modprobe", "dm-crypt"], [],
])
def test_unsafe_commands_are_refused(argv):
    with pytest.raises(BeastNetError) as e:
        assemble.check_argv(argv)
    assert e.value.code == ASSEMBLE


@pytest.mark.parametrize("argv", [
    ["mdadm", "--assemble", "--readonly", "--config=none", "--run", "/dev/md127", "/dev/sdb"],
    ["mdadm", "--incremental", "--run", "--config=none", "/dev/md127"],
    ["mdadm", "--stop", "/dev/md127"],
    ["mdadm", "--readonly", "/dev/md127"],
    ["cryptsetup", "open", "--readonly", "--type", "bitlk", "/dev/sdb", "x"],
    ["cryptsetup", "close", "x"],
    ["lvm", "vgchange", "-ay", "--devices", "/dev/mapper/bbro_sdb,/dev/mapper/bbro_sdc", "vg0",
     "--config", assemble.lvm_config("vg0")],
    ["lvm", "vgchange", "-ay", "--devices", "/dev/mapper/bbro_sdb", "--select",
     "vg_uuid=abcdef-1234-5678-90ab-cdef-1234-567890", "--config", assemble.lvm_config("vg0")],
    ["lvm", "vgchange", "-an", "vg0"],
    ["lvm", "lvs", "-a", "--reportformat", "json", "-o", "lv_name,segtype", "--devices", "/dev/sdb", "vg0"],
    ["mdadm", "--examine", "/dev/sdb"], ["mdadm", "--detail", "--export", "/dev/md127"],
    ["dmsetup", "mknodes"], ["mdev", "-s"], ["modprobe", "zfs", "zfs_arc_max=1"],
])
def test_read_only_commands_pass(argv):
    assemble.check_argv(argv)


def test_run_filters_before_anything_executes(env):
    with pytest.raises(BeastNetError):
        assemble._run(env.ctx, ["mdadm", "--assemble", "--force", "--readonly", "/dev/md0"])
    assert not env.runner.calls
