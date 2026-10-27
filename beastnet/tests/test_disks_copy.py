import hashlib
import os
import sys
import textwrap
from types import SimpleNamespace

import pytest

from beastnet import errors as E
from beastnet.disks import copy as C
from beastnet.disks.model import (CopyKind, Disk, Inventory, Member, Partition, Stack,
                                  StackKind, Support, Transport, Volume, VolumeKind)
from beastnet.errors import BeastNetError
from beastnet.events import Reporter

MIB = 1 << 20
SIZE = 4 * MIB

STUB = textwrap.dedent('''\
    #!%(py)s
    import os, sys, time
    a = sys.argv[1:]
    log = os.environ.get("STUB_LOG")
    if log:
        open(log, "a").write(" ".join(a) + "\\n")
    src, dst, mp = a[-3:]
    flags = [x for x in a[:-3]]
    bad = os.environ.get("STUB_BAD")
    badr = tuple(int(x) for x in bad.split(":")) if bad else None
    size = os.path.getsize(src)
    pos = 0
    blocks = []
    if os.path.exists(mp):
        for line in open(mp):
            w = line.split()
            if line.startswith("#") or len(w) != 3 or w[1] in ("?", "c", "t", "+") and w[0] == "0x0" and False:
                continue
            if w[0].startswith("0x") and w[2] in "+-?*/" and len(w[2]) == 1 and len(w) == 3 and not w[1] in ("?","c"):
                blocks.append((int(w[0], 16), int(w[1], 16), w[2]))
    done = {}
    for p, s, st in blocks:
        if st == "+":
            for o in range(p, p + s, 65536):
                done[o] = 1
    out = open(dst, "r+b") if os.path.exists(dst) else open(dst, "w+b")
    inp = open(src, "rb")
    def write_map(st):
        offs = sorted(done)
        lines = ["# stub", "0x0 %%s 1" %% st, "# pos size status"]
        for o in range(0, size, 65536):
            n = min(65536, size - o)
            if o in done:
                s = "+"
            elif badr and badr[0] <= o < badr[0] + badr[1]:
                s = "-"
            else:
                s = "?"
            lines.append("0x%%X 0x%%X %%s" %% (o, n, s))
        open(mp, "w").write("\\n".join(lines) + "\\n")
    write_map("c")
    delay = float(os.environ.get("STUB_DELAY", "0"))
    for o in range(0, size, 65536):
        if o in done:
            continue
        if badr and badr[0] <= o < badr[0] + badr[1]:
            continue
        inp.seek(o); out.seek(o); out.write(inp.read(65536)); out.flush()
        done[o] = 1
        write_map("c")
        time.sleep(delay)
    write_map("+")
''')


def disk(i, serial, size=SIZE, stick=False, lss=512, parts=()):
    return Disk(id=i, path=f"/dev/{i}", model="M", serial=serial, wwn=f"wwn-{serial}", size=size,
                logical_sector=lss, physical_sector=lss, transport=Transport.SATA,
                rotational=False, removable=False, is_boot_stick=stick, partitions=list(parts))


class Env:
    pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = Env()
    e.tmp = tmp_path
    # real files stand in for devices
    e.files = {}
    for n in ("sda", "sdb", "sdc", "sdd", "sde"):
        p = tmp_path / n
        p.write_bytes((n.encode() * 1000)[:1000] * (SIZE // 1000) + b"\0" * (SIZE % 1000))
        e.files[n] = str(p)
    (tmp_path / "sdc").write_bytes(b"\xff" * SIZE)
    (tmp_path / "sys/block").mkdir(parents=True)
    (tmp_path / "proc/self").mkdir(parents=True)
    (tmp_path / "data").mkdir()
    (tmp_path / "ext").mkdir()
    (tmp_path / "esp").mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "ddrescue"
    stub.write_text(STUB % {"py": sys.executable})
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    e.log = tmp_path / "stub.log"
    monkeypatch.setenv("STUB_LOG", str(e.log))
    e.paths = SimpleNamespace(proc=str(tmp_path / "proc"), sys=str(tmp_path / "sys"),
                              data=str(tmp_path / "data"), esp=str(tmp_path / "esp"))
    e.runner_calls = []
    runner = SimpleNamespace(run=lambda argv, **k: (e.runner_calls.append(argv),
                                                    SimpleNamespace(returncode=0, stdout="", stderr=""))[1])
    e.ctx = SimpleNamespace(paths=e.paths, reporter=Reporter(), system=SimpleNamespace(runner=runner),
                            dry_run=False, notes=[])
    d = {
        "sda": disk("sda", "SRC000001", parts=[Partition("sda1", "/dev/sda1", 1, 0, SIZE, fs_type="ext4")]),
        "sdb": disk("sdb", "TGT123456"),
        "sdc": disk("sdc", "STICK00001", stick=True),
        "sdd": disk("sdd", "EXT000001"),
        "sde": disk("sde", "TGT923456"),
    }
    e.inv = Inventory(disks=list(d.values()), stacks=[], volumes=[
        Volume("sda", "/dev/sda", VolumeKind.DISK, SIZE, disk_ids=["sda"]),
        Volume("sda1", "/dev/sda1", VolumeKind.PARTITION, SIZE, disk_ids=["sda"])])
    e.mounts = []   # (source, mountpoint, fstype, opts)

    def write_mounts():
        (tmp_path / "proc/self/mountinfo").write_text("".join(
            f"1 0 8:0 / {mp} {o} - {fs} {src} rw\n" for src, mp, fs, o in e.mounts))
        (tmp_path / "proc/mounts").write_text("".join(f"{s} {m} {f} {o} 0 0\n" for s, m, f, o in e.mounts))
        (tmp_path / "proc/swaps").write_text("Filename Type Size Used Priority\n")
    e.write_mounts = write_mounts
    e.mounts = [("/dev/sdc2", str(tmp_path / "data"), "exfat", "rw"),
                ("/dev/sdc1", str(tmp_path / "esp"), "vfat", "rw"),
                ("/dev/sdd1", str(tmp_path / "ext"), "ext4", "rw")]
    e.inv.disks[3].partitions = [Partition("sdd1", "/dev/sdd1", 1, 0, SIZE, fs_type="ext4")]
    e.inv.disks[2].partitions = [Partition("sdc1", "/dev/sdc1", 1, 0, 1, fs_type="vfat"),
                                 Partition("sdc2", "/dev/sdc2", 2, 1, 1, fs_type="exfat")]
    write_mounts()
    e.calls = []
    e.rescan_inv = e.inv

    def make_writable(ctx, d, *, partition=None):
        e.calls.append(("writable", d.id) if partition is None else ("writable", d.id, partition))
        return SimpleNamespace(close=lambda: e.calls.append(("ro-again", d.id)))
    e.hooks = C.Hooks(
        rescan=lambda ctx: e.rescan_inv, make_writable=make_writable,
        relock=lambda ctx: e.calls.append(("relock",)),
        open_exclusive=lambda p: (e.calls.append(("excl", p)), os.open(p, os.O_RDONLY))[1],
        statvfs=lambda p: SimpleNamespace(f_bavail=10 ** 9, f_frsize=4096), poll=0.01)
    # map device-level paths to real files: plan and run use the path names directly,
    # so the inventory points at the files
    for dd in e.inv.disks:
        dd.path = e.files[dd.id]
    e.inv.disks[0].partitions[0].path = e.files["sda"]
    for v in e.inv.volumes:
        v.path = e.files["sda"]
    return e


def mk(env, kind="clone", **kw):
    kw.setdefault("hooks", env.hooks)
    if kind != "image":
        kw.setdefault("mapfile_dir", str(env.tmp / "data" / "maps"))
    if kind == "clone":
        return C.plan(env.ctx, env.inv, kind, "sda", kw.pop("target", "TGT123456"), **kw)
    return C.plan(env.ctx, env.inv, kind, "sda", kw.pop("target"), **kw)


def refused(env, match, kind="clone", **kw):
    with pytest.raises(BeastNetError) as ei:
        mk(env, kind, **kw)
    assert ei.value.code == E.DISK_REFUSED, ei.value
    assert match in ei.value.text.lower(), ei.value.text


# ---- refusals ------------------------------------------------------------

def test_refuses_stick(env):
    refused(env, "stick", target="STICK00001")


def test_refuses_source_as_target(env):
    refused(env, "source", target="SRC000001")


def test_refuses_source_stack_disk(env):
    env.inv.volumes.append(Volume("md0", "/dev/md0", VolumeKind.MD, SIZE, from_stack="md:x",
                                  disk_ids=["sda", "sdb"]))
    env.inv.stacks.append(Stack("md:x", StackKind.MD, [Member("/dev/sda1", "sda"), Member("/dev/sdb1", "sdb")],
                                Support.ASSEMBLE, level="raid1"))
    with pytest.raises(BeastNetError) as ei:
        C.plan(env.ctx, env.inv, "clone", "md0", "TGT123456", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data"))
    assert ei.value.code == E.DISK_REFUSED


def test_refuses_no_serial(env):
    env.inv.disks[1].serial = ""
    refused(env, "serial", target="sdb")


def test_refuses_smaller_and_sector(env):
    env.inv.disks[1].size = SIZE - 512
    refused(env, "smaller", target="TGT123456")
    env.inv.disks[1].size = SIZE
    env.inv.disks[1].logical_sector = 4096
    refused(env, "sector", target="TGT123456")


def test_refuses_mounted_target(env):
    env.mounts.append((env.inv.disks[1].path, "/mnt/x", "ext4", "rw"))
    env.write_mounts()
    refused(env, "mounted", target="TGT123456")


def test_refuses_holders(env):
    d = env.tmp / "sys/block/sdb/holders"
    d.mkdir(parents=True)
    (d / "md0").mkdir()
    refused(env, "in use", target="TGT123456")


def test_refuses_active_stack_volume(env):
    env.inv.volumes.append(Volume("md1", "/dev/md1", VolumeKind.MD, SIZE, from_stack="md:y",
                                  disk_ids=["sdb"]))
    refused(env, "running", target="TGT123456")


def test_refuses_target_holding_mapfile(env):
    # the mapfile directory sits on sdd (not mounted here); sdd as target must be refused
    env.mounts[:] = env.mounts[:2]
    env.write_mounts()
    env.hooks.locate = lambda ctx, inv, path: C.Location("ext4", ["sdd"])
    refused(env, "mapfile", target="EXT000001", mapfile_dir=str(env.tmp / "ext"))


def test_mapfile_rules(env):
    # on the source disk
    env.mounts.append((env.files["sda"], str(env.tmp / "srcmnt"), "ext4", "rw"))
    (env.tmp / "srcmnt").mkdir()
    env.write_mounts()
    refused(env, "mapfile", mapfile_dir=str(env.tmp / "srcmnt"))
    # in RAM: no mount entry other than "/" resolving to nothing
    env.mounts[:] = [m for m in env.mounts if m[1] != str(env.tmp / "data")]
    env.write_mounts()
    refused(env, "mapfile", mapfile_dir=str(env.tmp / "nowhere"))
    # a third disk is fine
    p = mk(env, mapfile_dir=str(env.tmp / "ext"))
    assert p.mapfile.startswith(str(env.tmp / "ext"))


def test_member_clone_refused_unless_asked(env):
    env.inv.stacks.append(Stack("md:x", StackKind.MD, [Member("/dev/sda1", "sda"), Member("/dev/sdb1", "sde")],
                                Support.ASSEMBLE, level="raid1"))
    refused(env, "member", target="TGT123456", kind="clone")
    p = mk(env, "image", target=str(env.tmp / "ext/m.img"), member_of_set=True)
    assert C.SET_NOTE in p.notes


def test_image_destination_rules(env):
    # FAT32 / ESP
    refused(env, "fat32", "image", target=str(env.tmp / "esp/x.img"))
    # unsupported fs
    env.mounts.append(("/dev/sde1", str(env.tmp / "ext/b"), "btrfs", "rw"))
    (env.tmp / "ext/b").mkdir()
    env.inv.disks[4].partitions = [Partition("sde1", "/dev/sde1", 1, 0, 1)]
    env.write_mounts()
    refused(env, "only be written", "image", target=str(env.tmp / "ext/b/x.img"))
    # same disk as the source
    env.mounts.append((env.files["sda"], str(env.tmp / "ext/s"), "ext4", "rw"))
    (env.tmp / "ext/s").mkdir()
    env.write_mounts()
    refused(env, "disk it is read from", "image", target=str(env.tmp / "ext/s/x.img"))
    # space
    env.hooks.statvfs = lambda p: SimpleNamespace(f_bavail=1, f_frsize=4096)
    refused(env, "free space", "image", target=str(env.tmp / "ext/x.img"))
    env.hooks.statvfs = lambda p: SimpleNamespace(f_bavail=10 ** 9, f_frsize=4096)
    # exists
    (env.tmp / "ext/y.img").write_bytes(b"x")
    with pytest.raises(BeastNetError) as ei:
        mk(env, "image", target=str(env.tmp / "ext/y.img"))
    assert ei.value.code == E.EXISTS
    # ok on ntfs
    p = mk(env, "image", target=str(env.tmp / "ext/ok.img"))
    assert p.mapfile.endswith("ok.img.map") and p.erases == ""
    for ok in ("exfat", "ntfs3", "xfs"):
        env.mounts[2] = ("/dev/sdd1", str(env.tmp / "ext"), ok, "rw")
        env.write_mounts()
        mk(env, "image", target=str(env.tmp / "ext/ok.img"))


def test_restore_rules(env):
    img = env.tmp / "ext/a.img"
    img.write_bytes(b"\1" * SIZE)
    env.inv.disks[3].size = SIZE
    # image disk cannot be the target
    refused(env, "mapfile", "restore", target="EXT000001", source=None) if False else None
    with pytest.raises(BeastNetError) as ei:
        C.plan(env.ctx, env.inv, "restore", str(img), "EXT000001", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data/maps"))
    assert ei.value.code == E.DISK_REFUSED and "source" in ei.value.text
    p = C.plan(env.ctx, env.inv, "restore", str(img), "TGT123456", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data/maps"))
    assert p.kind == CopyKind.RESTORE and p.size == SIZE


# ---- confirmation ---------------------------------------------------------

def test_confirmation(env):
    p = mk(env)
    assert not p.confirmed and p.expected_confirmation == "123456"
    with pytest.raises(BeastNetError) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.DISK_REFUSED
    with pytest.raises(BeastNetError):
        mk(env, confirm="000000")
    assert mk(env, confirm="123456").confirmed
    # ambiguous last 6: whole serial
    env.inv.disks[4].serial = "XXXX123456"
    env.inv.disks[1].serial = "TGT123456"
    p = mk(env)
    assert p.expected_confirmation == "TGT123456"
    with pytest.raises(BeastNetError):
        mk(env, confirm="123456")
    assert mk(env, confirm="TGT123456").confirmed


# ---- running --------------------------------------------------------------

def test_clone_runs_and_guards(env):
    p = mk(env, confirm="123456")
    prog = []
    r = C.run(env.ctx, p, prog.append, hooks=env.hooks)
    assert r.ok and r.errors == 0 and r.bytes == SIZE and r.sha256
    assert open(env.files["sdb"], "rb").read() == open(env.files["sda"], "rb").read()
    names = [c[0] for c in env.calls]
    assert names == ["excl", "writable", "ro-again", "relock"]  # the guard handle is closed
    assert env.calls[0][1] == env.files["sdb"]
    lines = env.ctx.reporter.lines
    assert any("copy start kind=clone" in x for x in lines) and any("copy done" in x for x in lines)
    # no command names the source as output
    for argv in (ln.split() for ln in env.log.read_text().splitlines()):
        assert argv[-3] == env.files["sda"] and argv[-2] == env.files["sdb"]
    assert os.path.exists(p.mapfile + ".done") and not os.path.exists(p.mapfile)
    assert any(x.phase for x in prog) or prog == []


def test_force_and_direct_flags_for_block_target(env):
    env.hooks.is_block = lambda p: p in (env.files['sda'], env.files['sdb'])
    p = mk(env, confirm="123456")
    assert "-f" in p.commands[0] and "-D" in p.commands[0] and "-d" in p.commands[0]
    C.run(env.ctx, p, hooks=env.hooks)
    first = env.log.read_text().splitlines()[0].split()
    assert "-f" in first and first.index("-f") < len(first) - 3
    img = mk(env, "image", target=str(env.tmp / "ext/i.img"))
    assert "-f" not in img.commands[0]


def test_identity_mismatch(env):
    p = mk(env, confirm="123456")
    import copy as pycopy
    inv2 = pycopy.deepcopy(env.inv)
    inv2.disks[1].serial = "OTHER"
    env.rescan_inv = inv2
    with pytest.raises(BeastNetError) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.DISK_CHANGED
    assert env.calls == []   # nothing opened, nothing made writable
    inv2.disks[1].serial = "TGT123456"
    inv2.disks[1].size = SIZE * 2
    with pytest.raises(BeastNetError) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.DISK_CHANGED
    env.rescan_inv = Inventory([d for d in env.inv.disks if d.id != "sdb"], [], [])
    with pytest.raises(BeastNetError) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.DISK_CHANGED


def test_exclusive_open_failure_writes_nothing(env):
    def busy(path):
        raise BeastNetError(E.DISK_REFUSED, "busy")
    env.hooks.open_exclusive = busy
    before = open(env.files["sdb"], "rb").read()
    with pytest.raises(BeastNetError):
        C.run(env.ctx, mk(env, confirm="123456"), hooks=env.hooks)
    assert open(env.files["sdb"], "rb").read() == before
    assert not env.log.exists() and env.calls == []


def test_stop_and_resume(env, monkeypatch):
    monkeypatch.setenv("STUB_DELAY", "0.05")
    p = mk(env, confirm="123456")
    n = []

    def stop():
        n.append(1)
        return len(n) > 2
    r = C.run(env.ctx, p, should_stop=stop, hooks=env.hooks)
    assert not r.ok and r.resumable
    assert any("copy stopped resumable=1" in x for x in env.ctx.reporter.lines)
    assert env.calls[-1] == ("relock",)
    assert os.path.exists(p.mapfile)
    monkeypatch.setenv("STUB_DELAY", "0")
    r2 = C.run(env.ctx, p, hooks=env.hooks)
    assert r2.ok and r2.errors == 0
    assert open(env.files["sdb"], "rb").read() == open(env.files["sda"], "rb").read()


def test_image_hash_and_bad_area(env, monkeypatch):
    dest = env.tmp / "ext/out.img"
    p = mk(env, "image", target=str(dest))
    r = C.run(env.ctx, p, hooks=env.hooks)
    want = hashlib.sha256(open(env.files["sda"], "rb").read()).hexdigest()
    assert r.ok and r.sha256 == want
    assert (env.tmp / "ext/out.img.sha256").read_text().startswith(want)
    assert env.calls == []   # image: no target device touched
    # bad area: errors reported, mapfile kept for another try
    monkeypatch.setenv("STUB_BAD", f"{MIB}:{131072}")
    p2 = mk(env, "image", target=str(env.tmp / "ext/bad.img"))
    r2 = C.run(env.ctx, p2, hooks=env.hooks)
    assert r2.ok and r2.errors == 131072 and not r2.sha256
    assert os.path.exists(p2.mapfile)


def test_readback_mismatch(env, monkeypatch):
    p = mk(env, confirm="123456")
    real = C._hash_range

    def corrupt(path, size, stop, tick, other=None):
        return real(path, size, stop, tick, other=None)[0], False
    monkeypatch.setattr(C, "_hash_range", corrupt)
    with pytest.raises(BeastNetError) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.DISK_IO


def test_larger_target_relocates_gpt(env):
    ss = 512
    src = bytearray(open(env.files["sda"], "rb").read())
    hdr = bytearray(92)
    hdr[:8] = b"EFI PART"
    hdr[32:40] = (SIZE // ss - 1).to_bytes(8, "little")
    src[ss:ss + 92] = hdr
    open(env.files["sda"], "wb").write(bytes(src))
    env.inv.disks[1].size = SIZE * 2
    open(env.files["sdb"], "ab").write(b"\0" * SIZE)
    p = mk(env, confirm="123456")
    assert p.commands[-1][:3] == ["sfdisk", "--relocate", "gpt-bak-std"]
    r = C.run(env.ctx, p, hooks=env.hooks)
    assert r.ok and ["sfdisk", "--relocate", "gpt-bak-std", env.files["sdb"]] in env.runner_calls


def test_partition_target(env):
    env.inv.disks[1].partitions = [Partition("sdb1", env.files["sdb"], 1, 0, SIZE)]
    p = mk(env, target="sdb1", confirm="123456")
    assert p.target_is_partition and p.expected_confirmation == "123456"
    C.run(env.ctx, p, hooks=env.hooks)
    # only that partition (and the disk node) is unlocked, not its siblings
    assert ("writable", "sdb", env.files["sdb"]) in env.calls


def test_dry_run(env):
    env.ctx.dry_run = True
    r = C.run(env.ctx, mk(env, confirm="123456"), hooks=env.hooks)
    assert r.ok and r.bytes == 0 and env.calls == [] and not env.log.exists()


def test_mapfile_parse(tmp_path):
    m = tmp_path / "m"
    m.write_text("# x\n0x100 t 1\n# pos size status\n0x0 0x100 +\n0x100 0x80 -\n0x180 0x80 ?\n")
    assert C.mapfile_state(str(m), 0x200) == (0x100, 1, 0x100, "trimming")
    assert C.mapfile_state(str(tmp_path / "none"), 10) == (0, 0, 10, "")


def test_default_locate_parses_mountinfo(env):
    loc = C.default_locate(env.ctx, env.inv, str(env.tmp / "ext/sub/file"))
    assert loc.fs_type == "ext4" and loc.disk_ids == ["sdd"]
    assert C.default_locate(env.ctx, env.inv, str(env.tmp / "esp/x")).esp


# ---- review fixes ---------------------------------------------------------

def test_failed_copy_also_sets_the_target_read_only_again(env, monkeypatch):
    p = mk(env, confirm="123456")
    monkeypatch.setattr(C, "_run_child", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        C.run(env.ctx, p, hooks=env.hooks)
    assert ("ro-again", "sdb") in env.calls and env.calls[-1] == ("relock",)


def test_restore_from_the_stick_keeps_its_mapfile_there(env):
    img = env.tmp / "data/images/a.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"\1" * SIZE)
    p = C.plan(env.ctx, env.inv, "restore", str(img), "TGT123456", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data/disk-tools"))
    assert p.mapfile.startswith(str(env.tmp / "data/disk-tools"))


def test_image_records_its_sector_size_and_restore_checks_it(env):
    dest = env.tmp / "ext/a.img"
    p = mk(env, "image", target=str(dest))
    assert C.run(env.ctx, p, hooks=env.hooks).ok
    assert C.read_info(str(dest))["logical_sector"] == 512
    env.inv.disks[1].logical_sector = 4096
    with pytest.raises(BeastNetError) as ei:
        C.plan(env.ctx, env.inv, "restore", str(dest), "TGT123456", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data/maps"))
    assert ei.value.code == E.DISK_REFUSED and "sector sizes" in ei.value.text


def test_default_guard_hook_reaches_the_guard(env, monkeypatch):
    """run() with the real default make_writable hook (only the guard itself faked)."""
    from beastnet.disks import guard
    seen = []

    def fake(ctx, d, *, confirmed=False, partition=None):
        seen.append((d.id, confirmed, partition))
        return SimpleNamespace(close=lambda: seen.append("closed"))
    monkeypatch.setattr(guard, "make_writable", fake)
    hooks = C.Hooks(rescan=env.hooks.rescan, relock=env.hooks.relock, open_exclusive=env.hooks.open_exclusive,
                    statvfs=env.hooks.statvfs, poll=0.01)
    p = mk(env, confirm="123456", hooks=hooks)
    assert C.run(env.ctx, p, hooks=hooks).ok
    assert seen == [("sdb", True, None), "closed"]


def test_partition_target_refused_while_a_sibling_is_mounted(env):
    env.inv.disks[1].partitions = [Partition("sdb1", env.files["sdb"], 1, 0, SIZE),
                                   Partition("sdb2", "/dev/sdb2", 2, SIZE, SIZE)]
    env.mounts.append(("/dev/sdb2", str(env.tmp / "esp"), "ext4", "rw"))
    env.write_mounts()
    refused(env, "in use", target="sdb1", confirm="123456")
