"""Disk tools session, script mode and screens, with the part modules faked
(their own tests cover them; this checks how they are driven)."""

import os
import threading
from types import SimpleNamespace

import pytest

from beastnet.cmdline import parse_cmdline
from beastnet.context import Quit
from beastnet.diskflow import DiskScreens
from beastnet.disks import session as S
from beastnet.disks.model import (Candidate, CopyKind, CopyPlan, CopyResult, Disk, Health,
                                  HealthStatus, Inventory, Member, Stack, StackKind, StackState,
                                  Partition, Support, Transport, Volume, VolumeKind)
from beastnet.errors import COPY, RECONSTRUCT, SCRIPT, BeastNetError
from beastnet.events import Reporter
from beastnet.paths import Paths
from beastnet.script import parse_plan
from test_ui import ScriptedUI, pick


def disk(i, serial, *, stick=False, size=10 << 30):
    return Disk(id=i, path=f"/dev/{i}", model=f"Model {i}", serial=serial, wwn="", size=size,
                logical_sector=512, physical_sector=4096, transport=Transport.NVME,
                rotational=False, removable=stick, is_boot_stick=stick)


def inventory():
    disks = [disk("sda", "STICK0001", stick=True), disk("nvme0n1", "SRC0000AAA111"),
             disk("nvme1n1", "SRC0000BBB222"), disk("sdb", "TGT0000CCC333", size=20 << 30),
             disk("sdc", "BARE000DDD444"), disk("sdd", "", size=20 << 30)]
    disks[3].partitions = [Partition("sdb1", "/dev/sdb1", 1, 1 << 20, (20 << 30) - (2 << 20), fs_type="exfat")]
    disks[5].fs_type = "ext4"
    md = Stack("md:1234", StackKind.MD, [Member("/dev/nvme0n1", "nvme0n1", 0, "active"),
                                         Member("/dev/nvme1n1", "nvme1n1", 1, "active")],
               Support.ASSEMBLE, "raid1", StackState.CLEAN, "data")
    amd = Stack("amd-raid:x", StackKind.AMD_RAID, [Member("/dev/nvme0n1", "nvme0n1"),
                                                   Member("/dev/nvme1n1", "nvme1n1")],
                Support.RECONSTRUCT, notes=["may be an AMD RAID member"])
    vols = [Volume(d.id, d.path, VolumeKind.DISK, d.size, disk_ids=[d.id]) for d in disks]
    return Inventory(disks, [md, amd], vols)


class Parts:
    """Fakes for discover/guard/health/assemble/reconstruct/copy; records calls."""

    def __init__(self, *, scores=(1.0,), copy_ok=True):
        self.calls = []
        self.scores = list(scores)
        self.copy_ok = copy_ok
        rec = self.calls.append
        P = self

        def scan(ctx):
            rec(("scan",))
            inv = inventory()
            for vols in P.started.values():
                inv.volumes += vols
            return inv
        self.started = {}
        self.discover = SimpleNamespace(scan=scan)
        def make_writable(ctx, d, *, confirmed=False):
            rec(("make_writable", d.id, confirmed))
            return SimpleNamespace(close=lambda: rec(("relock", d.id)))
        self.guard = SimpleNamespace(protect_all=lambda ctx: rec(("protect_all",)),
                                     reapply=lambda ctx: rec(("reapply",)), make_writable=make_writable,
                                     exempt=lambda *n: rec(("exempt", *n)), unexempt=lambda *n: rec(("unexempt", *n)))
        self.health = SimpleNamespace(read=lambda ctx, d: rec(("health", d.id)) or Health(
            d.id, HealthStatus.OK, "SMART says OK, 1200 hours"))

        def start(ctx, stack, *, passphrase=None):
            rec(("start", stack.id, passphrase))
            vols = [Volume("md127", "/dev/md127", VolumeKind.MD, 10 << 30, from_stack=stack.id,
                           disk_ids=[m.disk_id for m in stack.members])]
            P.started[stack.id] = vols
            return vols
        self.assemble = SimpleNamespace(start=start, stop=lambda ctx, st: rec(("stop", st.id)))

        def detect(ctx, devices):
            rec(("detect", tuple(devices)))
            return [Candidate("raid0", c, list(devices), 0) for c in (65536, 131072, 524288)]

        def build(ctx, devices, cand):
            rec(("build", cand.chunk, tuple(cand.order)))
            return Volume(f"ovl{cand.chunk}", f"/dev/mapper/ovl{cand.chunk}", VolumeKind.OVERLAY_ARRAY,
                          20 << 30, disk_ids=["nvme0n1", "nvme1n1"])

        def validate(ctx, vol):
            rec(("validate", vol.id))
            return P.scores.pop(0) if P.scores else 0.0
        def teardown(ctx, v):
            rec(("teardown", v.id))

        def auto(ctx, devices):  # same rules as reconstruct.auto
            best = None
            for cand in detect(ctx, devices):
                vol = build(ctx, devices, cand)
                score = validate(ctx, vol)
                if best is None or score > best[2]:
                    if best is not None:
                        teardown(ctx, best[0])
                    best = (vol, cand, score)
                else:
                    teardown(ctx, vol)
            if best is None or best[2] <= 0:
                if best is not None:
                    teardown(ctx, best[0])
                raise BeastNetError(RECONSTRUCT, "no reconstruction candidate validated")
            return best
        self.reconstruct = SimpleNamespace(detect=detect, build=build, validate=validate,
                                           teardown=teardown, auto=auto)

        def plan(ctx, inv, kind, source, target, *, confirm=None, mapfile_dir=None, verify=True,
                 member_of_set=False):
            rec(("plan", kind, source, target, confirm, mapfile_dir, member_of_set))
            p = CopyPlan(kind, source, target, 10 << 30, f"{mapfile_dir}/x.map",
                         erases="everything on Model sdb" if kind is not CopyKind.IMAGE else "")
            if kind is not CopyKind.IMAGE and confirm is not None:
                if confirm != "CCC333":
                    raise BeastNetError("disk-refused", "the typed serial does not match")
                p.confirmed = True
            return p

        def run(ctx, plan, on_progress, should_stop):
            rec(("run", plan.kind, plan.confirmed))
            if not P.copy_ok:
                return CopyResult(False, 0, 0, notes=["ddrescue failed"])
            return CopyResult(True, plan.size, 0, sha256="ab" * 32)
        self.copy = SimpleNamespace(plan=plan, run=run, confirmation_for=lambda inv, d: d.serial[-6:])

    def ops(self):
        return [c[0] for c in self.calls]


class FakeRun:
    def __init__(self):
        self.calls, self.fail = [], set()

    def run(self, argv, timeout=60, env=None, input=None):
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=1 if argv[0] in self.fail else 0, stdout="", stderr="busy")


@pytest.fixture
def ctx(tmp_path):
    root = tmp_path / "root"
    (root / "mnt/data").mkdir(parents=True)
    rep = Reporter()
    notes = []
    system = SimpleNamespace(reboot=lambda: None, poweroff=lambda: None, shell=lambda: None,
                             runner=FakeRun())
    return SimpleNamespace(paths=Paths(root=str(root)), reporter=rep, system=system,
                           dry_run=False, notes=notes, net=None)


# -- parse_steps ------------------------------------------------------------------------
def test_parse_steps_accepts_the_contract_plan():
    steps = [{"op": "scan"}, {"op": "health", "disk": "SRC0000AAA111"},
             {"op": "assemble", "stack": "md:1234"},
             {"op": "reconstruct", "members": ["SRC0000AAA111", "SRC0000BBB222"], "mode": "auto"},
             {"op": "image", "source": "md:1234", "dest": "/images/x.img"},
             {"op": "clone", "source": "md:1234", "target": "TGT0000CCC333", "confirm": "CCC333"},
             {"op": "restore", "image": "/images/x.img", "target": "TGT0000CCC333", "confirm": "CCC333"}]
    assert S.parse_steps(steps) is steps


@pytest.mark.parametrize("steps,why", [
    ([], "non-empty"),
    ([{"op": "format"}], "op must be"),
    ([{"op": "clone", "source": "a", "target": "b"}], "missing confirm"),
    ([{"op": "scan", "force": True}], "unknown force"),
    ([{"op": "image", "source": "a", "dest": "/../etc/x"}], "leaves the data partition"),
    ([{"op": "image", "source": "a", "dest": "/x.img", "verify": "yes"}], "true or false"),
    ([{"op": "reconstruct", "members": ["a"], "mode": "manual"}], "needs level"),
    ([{"op": "reconstruct", "members": ["a"], "chunk": 4096}], "for mode manual"),
    ([{"op": "reconstruct", "members": []}], "non-empty list"),
])
def test_parse_steps_refuses_bad_plans(steps, why):
    with pytest.raises(BeastNetError) as e:
        S.parse_steps(steps)
    assert e.value.code == SCRIPT and why in e.value.text


def test_script_plan_and_cmdline_know_the_disk_action():
    plan = parse_plan({"action": "disk", "steps": [{"op": "scan"}], "then": "poweroff"})
    assert plan.action == "disk" and plan.steps == [{"op": "scan"}] and plan.then == "poweroff"
    with pytest.raises(BeastNetError):
        parse_plan({"action": "disk", "steps": [{"op": "nope"}]})
    assert parse_cmdline("quiet beastnet.action=disk").action == "disk"


# -- session ----------------------------------------------------------------------------
def test_plan_guards_first_and_stops_what_it_started(ctx):
    parts = Parts()
    S.run_plan(ctx, [{"op": "scan"}, {"op": "assemble", "stack": "md:1234", "passphrase": "pw"},
                     {"op": "image", "source": "md:1234", "dest": "/images/a.img"}], modules=parts)
    assert parts.ops()[:3] == ["protect_all", "scan", "reapply"]
    assert ("start", "md:1234", "pw") in parts.calls
    plan = next(c for c in parts.calls if c[0] == "plan")
    assert plan[1] is CopyKind.IMAGE and plan[2] == "md127"
    assert plan[3] == ctx.paths.data_local("/images/a.img")
    assert plan[5] == ctx.paths.data_local(S.MAPS_DIR)
    i_run = parts.ops().index("run")
    assert parts.ops()[i_run + 1] == "reapply"  # guard back on after the copy
    assert parts.ops()[-1] == "stop"


def test_clone_by_serial_with_confirmation(ctx):
    parts = Parts()
    S.run_plan(ctx, [{"op": "clone", "source": "SRC0000AAA111", "target": "TGT0000CCC333",
                      "confirm": "CCC333", "member_of_set": True}], modules=parts)
    plan = next(c for c in parts.calls if c[0] == "plan")
    assert plan[1:5] == (CopyKind.CLONE, "nvme0n1", "TGT0000CCC333", "CCC333") and plan[6] is True
    assert ("run", CopyKind.CLONE, True) in parts.calls


def test_failed_copy_is_a_copy_error(ctx):
    with pytest.raises(BeastNetError) as e:
        S.run_plan(ctx, [{"op": "image", "source": "nvme0n1", "dest": "/a.img"}],
                   modules=Parts(copy_ok=False))
    assert e.value.code == COPY and "ddrescue failed" in e.value.text


def test_unknown_volume_is_named(ctx):
    with pytest.raises(BeastNetError) as e:
        S.run_plan(ctx, [{"op": "image", "source": "nvme9n9", "dest": "/a.img"}], modules=Parts())
    assert e.value.code == SCRIPT and "nvme9n9" in e.value.text


def test_auto_reconstruction_keeps_the_best_validated_layout(ctx):
    parts = Parts(scores=[0.0, 0.8, 0.5])
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    b = s.reconstruct_auto("r", ["SRC0000AAA111", "SRC0000BBB222"])
    assert b.score == 0.8 and b.volume.id == "ovl131072" and b.candidate.score == 0.8
    torn = [c[1] for c in parts.calls if c[0] == "teardown"]
    assert sorted(torn) == ["ovl524288", "ovl65536"]
    assert s.volume("r") is b.volume and any(v.id == "ovl131072" for v in s.inv.volumes)
    s.leave()
    assert parts.calls[-1] == ("teardown", "ovl131072")


def test_auto_reconstruction_without_a_readable_layout(ctx):
    parts = Parts(scores=[0.0, 0.0, 0.0])
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    with pytest.raises(BeastNetError) as e:
        s.reconstruct_auto("r", ["nvme0n1", "/dev/nvme1n1"])
    assert e.value.code == RECONSTRUCT
    assert sorted(c[1] for c in parts.calls if c[0] == "teardown") == ["ovl131072", "ovl524288", "ovl65536"]
    assert not s.built


def test_a_new_rebuild_of_the_same_disks_releases_the_old_one(ctx):
    parts = Parts(scores=[0.9, 0.7])
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    s.build("a", ["/dev/nvme0n1", "/dev/nvme1n1"], Candidate("raid0", 65536, ["/dev/nvme0n1", "/dev/nvme1n1"], 0),
            keep_bad=True)
    s.build("b", ["/dev/nvme1n1", "/dev/nvme0n1"], Candidate("raid0", 131072, ["/dev/nvme1n1", "/dev/nvme0n1"], 0),
            keep_bad=True)
    assert list(s.built) == ["b"] and ("teardown", "ovl65536") in parts.calls


def test_image_folder_on_the_stick_is_created(ctx):
    parts = Parts()
    S.run_plan(ctx, [{"op": "image", "source": "nvme0n1", "dest": "/images/sub/a.img"}], modules=parts)
    assert os.path.isdir(ctx.paths.data_local("/images/sub"))


def test_manual_builder_keeps_a_low_score_and_allows_a_missing_member(ctx):
    parts = Parts(scores=[0.0])
    S.run_plan(ctx, [{"op": "reconstruct", "members": ["SRC0000AAA111", "SRC0000BBB222"],
                      "mode": "manual", "level": "raid5", "chunk": 65536,
                      "order": ["SRC0000BBB222", "missing", "SRC0000AAA111"], "layout": "left-symmetric"}],
               modules=parts)
    assert ("build", 65536, ("/dev/nvme1n1", "", "/dev/nvme0n1")) in parts.calls
    with pytest.raises(BeastNetError):
        S.run_plan(ctx, [{"op": "reconstruct", "members": ["SRC0000AAA111"], "mode": "manual",
                          "level": "raid1", "chunk": 0, "order": ["TGT0000CCC333"]}], modules=Parts())


# -- screens ----------------------------------------------------------------------------
class DiskUI(ScriptedUI):
    def download(self, title, lines, job, *, what="download"):
        self.shown.append(("download", title, lines, what))
        return job(lambda p: None, threading.Event())


def flow_for(ctx, ui, parts):
    common = {"shell": None, "reboot": None, "poweroff": None}
    flow = SimpleNamespace(ui=ui, ctx=ctx, errors=[],
                           common_items=lambda: [],
                           common=lambda c: common[c],
                           show_error=lambda e, title="": flow.errors.append(e))
    return DiskScreens(flow, S.DiskSession(ctx, modules=parts)), flow


def test_screens_clone_needs_the_typed_serial(ctx):
    parts = Parts()
    ui = DiskUI([
        pick("Model nvme0n1"),                       # home: the source disk
        pick("Copy this one disk to another disk"),  # it is one disk of the md set
        pick("Model sdb"),                           # target (stick and source not offered)
        pick("Continue"),                            # plan screen
        {"serial": "XXXXXX"},                        # wrong: asked again with the reason
        {"serial": "CCC333"},
        True,                                        # result message
        None,                                        # back from the disk
        None,                                        # leave Disk tools
    ])
    screens, flow = flow_for(ctx, ui, parts)
    screens.run()
    targets = [s for s in ui.shown if s[1] == "Copy to which disk?"][0][2]["items"]
    labels = [i.label for i in targets]
    assert not any("sda" in x or "nvme0n1" in x for x in labels)
    plan_screen = [s for s in ui.shown if s[1] == "Plan: clone"][0]
    assert plan_screen[2]["kind"] == "warn" and "Erased: everything" in plan_screen[2]["text"]
    forms = [s for s in ui.shown if s[0] == "form"]
    assert forms[1][2]["error"] == "the typed serial does not match"
    assert ("run", CopyKind.CLONE, True) in parts.calls
    assert any(s[0] == "download" and s[3] == "copy" for s in ui.shown)
    assert [c for c in parts.calls if c[0] == "plan"][0][6] is True  # member_of_set
    done = [s for s in ui.shown if s[1] == "Copy finished"][0]
    assert "SHA-256" in done[2]["text"]


def test_screens_amd_set_offers_reconstruction(ctx):
    parts = Parts(scores=[0.9])
    ui = DiskUI([
        pick("May be an AMD RAID member"),
        pick("Work out its RAID layout"),
        pick("Try the best layouts"),
        False,      # back to the layouts
        None,       # back from the layouts
        None,       # back from the set
        None,       # leave
    ])
    screens, flow = flow_for(ctx, ui, parts)
    screens.run()
    home = [s for s in ui.shown if s[0] == "menu" and s[1] == "Disk tools"][0]
    amd = [i for i in home[2]["items"] if i.label.startswith("May be")][0]
    assert amd.kind == "warn" and "AMD" in amd.hint
    assert ("detect", ("/dev/nvme0n1", "/dev/nvme1n1")) in parts.calls
    rebuilt = [s for s in ui.shown if s[1].startswith("Rebuilt RAID")][0]
    assert rebuilt[2]["kind"] == "ok"
    assert parts.calls[-1][0] == "teardown"  # leaving stops the overlay array


def test_screens_report_errors_and_quit_cleanly(ctx):
    parts = Parts()
    parts.discover.scan = lambda c: (_ for _ in ()).throw(BeastNetError("disk-io", "sysfs unreadable"))
    ui = DiskUI([])
    screens, flow = flow_for(ctx, ui, parts)
    screens.run()
    assert flow.errors and flow.errors[0].code == "disk-io"


def test_flow_more_menu_opens_disk_tools(tmp_path, monkeypatch):
    from beastnet import diskflow
    from beastnet.flow import Interactive
    opened = []
    monkeypatch.setattr(diskflow.DiskScreens, "run", lambda self, entry=False: opened.append(entry))
    ui = ScriptedUI([pick("Disk tools"), pick("Power off")])
    ctx = SimpleNamespace(net=None, system=SimpleNamespace(poweroff=lambda: None), notes=[])
    with pytest.raises(Quit):
        Interactive(ctx, ui).more_menu() or Interactive(ctx, ui).more_menu()
    assert opened == [False]


# -- image destinations on other disks ------------------------------------------------------
def test_use_disk_mounts_after_confirmation_and_leave_releases(ctx):
    parts = Parts()
    S.run_plan(ctx, [{"op": "use_disk", "disk": "TGT0000CCC333", "confirm": "CCC333"},
                     {"op": "image", "source": "nvme0n1", "dest": "/images/n0.img", "on": "TGT0000CCC333"}],
               modules=parts)
    mp = os.path.join(ctx.paths.run, "dest", "sdb")
    run = ctx.system.runner.calls
    assert ["mount", "-t", "exfat", "-o", S.DEST_OPTS, "/dev/sdb1", mp] in run
    assert ("make_writable", "sdb", True) in parts.calls and ("exempt", "sdb", "sdb1") in parts.calls
    plan = next(c for c in parts.calls if c[0] == "plan")
    assert plan[3] == os.path.join(mp, "images/n0.img") and os.path.isdir(os.path.join(mp, "images"))
    assert run[-2:] == [["sync"], ["umount", mp]]
    assert parts.calls.index(("unexempt", "sdb", "sdb1")) < parts.calls.index(("relock", "sdb"))
    assert any(line.startswith("BEASTNET: disk dest id=sdb dev=/dev/sdb1 fs=exfat") for line in ctx.reporter.lines)


@pytest.mark.parametrize("ref,confirm,why", [
    ("STICK0001", "K0001", "already the default place"),
    ("SRC0000AAA111", "AAA111", "belongs to md set"),
    ("TGT0000CCC333", "XXXXXX", "typed serial does not match"),
    ("BARE000DDD444", "DDD444", "no exFAT, NTFS, ext4 or XFS"),
    ("sdd", "", "no serial"),
])
def test_use_disk_refusals(ctx, ref, confirm, why):
    parts = Parts()
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    with pytest.raises(BeastNetError) as e:
        s.use_disk(ref, confirm)
    assert e.value.code == "disk-refused" and why in e.value.text
    assert not any(c[0] == "make_writable" for c in parts.calls)


def test_use_disk_mount_failure_relocks(ctx):
    parts = Parts()
    ctx.system.runner.fail.add("mount")
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    with pytest.raises(BeastNetError):
        s.use_disk("TGT0000CCC333", "CCC333")
    assert ("relock", "sdb") in parts.calls and ("unexempt", "sdb", "sdb1") in parts.calls and not s.dests


def test_image_on_a_disk_that_was_not_opened(ctx):
    with pytest.raises(BeastNetError) as e:
        S.run_plan(ctx, [{"op": "image", "source": "nvme0n1", "dest": "/x.img", "on": "TGT0000CCC333"}],
                   modules=Parts())
    assert "use_disk" in e.value.text


def test_use_disk_refuses_two_disks_with_the_same_serial(ctx, monkeypatch):
    parts = Parts()
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    s.inv.disks[4].serial = "TGT0000CCC333"  # two identical USB bridges
    with pytest.raises(BeastNetError) as e:
        s.use_disk("sdb", "CCC333")
    assert "same serial" in e.value.text and not any(c[0] == "make_writable" for c in parts.calls)


def test_use_disk_any_error_after_mount_unmounts_and_relocks(ctx, monkeypatch):
    parts = Parts()
    s = S.DiskSession(ctx, modules=parts)
    s.enter()
    monkeypatch.setattr(S.os, "statvfs", lambda p: (_ for _ in ()).throw(OSError(5, "I/O error")))
    with pytest.raises(OSError):
        s.use_disk("TGT0000CCC333", "CCC333")
    assert ctx.system.runner.calls[-1][0] == "umount"
    assert ("relock", "sdb") in parts.calls and not s.dests


def test_restore_from_another_disk_opens_it_read_only(ctx):
    parts = Parts()
    S.run_plan(ctx, [{"op": "restore", "image": "/images/a.img", "on": "TGT0000CCC333",
                      "target": "SRC0000AAA111", "confirm": "CCC333"}], modules=parts)
    mount = next(c for c in ctx.system.runner.calls if c[0] == "mount")
    assert mount[2:4] == ["exfat", "-o"] and mount[4].startswith("ro,")
    assert not any(c[0] in ("make_writable", "exempt") for c in parts.calls)
    assert any("disk dest id=sdb" in x and "rw=0" in x for x in ctx.reporter.lines)
