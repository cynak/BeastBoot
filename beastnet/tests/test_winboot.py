import os
import subprocess
import types

import pytest

from beastnet import grubenv, winboot
from beastnet.errors import GRUBENV, NO_SPACE, WINBOOT, BeastNetError
from beastnet.paths import Paths

ISO = "/isos/Win11.iso"


def test_validate_iso():
    assert winboot.validate_iso("/isos//Win11.iso") == ISO
    for bad in (None, "", "isos/x.iso", "/a/../b.iso", "/a\nb", "/a\0b", "/", "/a\\b"):
        with pytest.raises(BeastNetError) as e:
            winboot.validate_iso(bad)
        assert e.value.code == WINBOOT


def test_check_fs():
    winboot.check_fs("vfat")
    winboot.check_fs("exfat")
    for fs in ("ntfs3", "ext4", ""):
        with pytest.raises(BeastNetError):
            winboot.check_fs(fs)


def make_tree(root, sources="Sources", wim="BOOT.WIM", extra=()):
    d = os.path.join(root, sources)
    os.makedirs(d)
    if wim:
        with open(os.path.join(d, wim), "wb") as f:
            f.write(b"w" * 5000)
    for n in extra:
        open(os.path.join(d, n), "wb").close()


def test_find_wim_case_and_kind(tmp_path):
    make_tree(str(tmp_path), extra=("Install.ESD",))
    wim, kind = winboot.find_wim(str(tmp_path))
    assert wim.endswith("BOOT.WIM") and kind == "setup"
    t2 = tmp_path / "b"
    t2.mkdir()
    make_tree(str(t2), sources="sources", wim="boot.wim")
    assert winboot.find_wim(str(t2))[1] == "native"


def test_find_wim_missing(tmp_path):
    make_tree(str(tmp_path), wim=None)
    with pytest.raises(BeastNetError) as e:
        winboot.find_wim(str(tmp_path))
    assert "not a Windows ISO" in e.value.text


def test_space_and_4gib():
    winboot.check_space(100, 100 + winboot.MARGIN, "vfat")
    with pytest.raises(BeastNetError) as e:
        winboot.check_space(100, 100 + winboot.MARGIN - 1, "exfat")
    assert e.value.code == NO_SPACE
    with pytest.raises(BeastNetError) as e:
        winboot.check_space(4 * 1024 ** 3, 1 << 50, "vfat")
    assert e.value.code == WINBOOT
    winboot.check_space(4 * 1024 ** 3, 1 << 50, "exfat")


def test_stamp_bytes_parse():
    b = winboot.stamp_bytes(ISO, "setup", 123)
    assert len(b) == 1024
    env = grubenv.GrubEnv(b)
    assert env.get("bb_wb_iso") == ISO and env.get("bb_wb_uuid") is None
    assert env.get("bb_wb_kind") == "setup" and env.get("bb_wb_size") == "123"
    assert env.get("bb_wb_by").startswith("helper ")
    p = grubenv.GrubEnv(winboot.stamp_bytes(ISO, "native", 1, by="host 1"))
    assert p.get("bb_wb_by") == "host 1"


def stamp(root, iso):
    d = winboot.dest_dir(str(root), iso)
    os.makedirs(d, exist_ok=True)
    (open(os.path.join(d, "boot.wim"), "wb")).close()
    with open(os.path.join(d, "stamp.env"), "wb") as f:
        f.write(winboot.stamp_bytes(iso, "native", 0))
    return d


def test_write_copy_order(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    src = tmp_path / "src.wim"
    src.write_bytes(b"x" * (winboot.CHUNK + 10))
    old = stamp(root, ISO)
    seen = []

    def prog(done, total):
        d = winboot.dest_dir(str(root), ISO)
        seen.append(sorted(os.listdir(d)))
        assert total == src.stat().st_size

    st = winboot.stamp_bytes(ISO, "native", 1)
    assert winboot.write_copy(str(src), str(root), ISO, st, b"h" * 10, prog)
    assert all(s == ["boot.wim.part"] for s in seen)
    assert sorted(os.listdir(old)) == ["boot.wim", "iso-head.bin", "stamp.env"]  # old stamp and wim gone, no stamp yet
    assert open(os.path.join(old, "boot.wim"), "rb").read() == src.read_bytes()
    assert len(open(os.path.join(old, "stamp.env"), "rb").read()) == 1024


def test_write_copy_cancel(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    src = tmp_path / "s"
    src.write_bytes(b"x" * 100)
    assert not winboot.write_copy(str(src), str(root), ISO, b"", b"", None, lambda: True)
    assert os.listdir(winboot.dest_dir(str(root), ISO)) == []


def test_cleanup_safety(tmp_path):
    root = tmp_path / "d"
    (root / "isos").mkdir(parents=True)
    (root / "isos" / "Keep.iso").write_bytes(b"i")
    stamp(root, "/isos/Keep.iso")
    gone = stamp(root, "/isos/Gone.iso")
    nostamp = os.path.join(str(root), "beast-booter/winboot/other")
    os.makedirs(nostamp)
    open(os.path.join(nostamp, "boot.wim"), "w").close()
    outside = root / "precious"
    outside.mkdir()
    (outside / "stamp.env").write_bytes(winboot.stamp_bytes("/precious", "native", 0))
    (outside / "boot.wim").write_bytes(b"x")
    # stamp pointing to a different dir than where it lives: left alone
    liar = stamp(root, "/isos/Liar.iso")
    os.rename(liar, os.path.join(str(root), "beast-booter/winboot/liar"))
    removed = winboot.cleanup_stale(str(root))
    assert removed == [gone]
    assert not os.path.exists(gone)
    assert os.path.exists(os.path.join(nostamp, "boot.wim"))
    assert (outside / "boot.wim").exists() and (outside / "stamp.env").exists()
    assert os.path.exists(os.path.join(str(root), "beast-booter/winboot/liar/boot.wim"))
    assert os.path.exists(winboot.dest_dir(str(root), "/isos/Keep.iso"))
    assert winboot.cleanup_stale(str(tmp_path / "none")) == []


class FakeRunner:
    def __init__(self, tree, fstype="exfat", fail_mount=(), fail_all=False):
        self.tree, self.fstype, self.calls = tree, fstype, []
        self.fail_mount, self.fail_all = fail_mount, fail_all

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        rc, out = 0, ""
        if argv[0] == "findmnt":
            out = self.fstype + "\n"
        elif argv[0] == "losetup" and argv[1] == "-r":
            out = "/dev/loop7\n"
        elif argv[0] == "mount":
            if self.fail_all or argv[2] in self.fail_mount:
                rc = 32
            else:
                os.rmdir(argv[-1])
                os.symlink(self.tree, argv[-1])
        elif argv[0] == "umount":
            os.unlink(argv[1])
            os.mkdir(argv[1])
        return subprocess.CompletedProcess(argv, rc, out, "")


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "root"
    paths = Paths(root=str(root))
    os.makedirs(paths.data + "/isos")
    os.makedirs(paths.esp + "/grub")
    open(paths.data + ISO, "wb").write(bytes(range(256)) * 400)
    g = grubenv.GrubEnv()
    g.set("bb_wb_iso", ISO)
    g.set("bb_oneshot", "/old")
    open(paths.grubenv, "wb").write(g.to_bytes())
    tree = tmp_path / "tree"
    tree.mkdir()
    make_tree(str(tree), extra=("install.wim",))
    return paths, str(tree)


def test_plan_run_finish(env):
    paths, tree = env
    r = FakeRunner(tree)
    wb = winboot.WinBoot(paths, r)
    plan = wb.plan()
    assert (plan.kind, plan.size, plan.fstype) == ("setup", 5000, "exfat")
    res = wb.run(plan)
    assert res.ok
    d = winboot.dest_dir(paths.data, ISO)
    e = grubenv.load(os.path.join(d, "stamp.env"))
    assert e.get("bb_wb_size") == "5000"
    iso_bytes = open(paths.data + ISO, "rb").read()
    assert open(os.path.join(d, "iso-head.bin"), "rb").read() == iso_bytes[32768:98304]
    assert os.path.getsize(os.path.join(d, "boot.wim")) == 5000
    # the mount was always undone, both times
    assert [c[0] for c in r.calls].count("umount") == 2
    assert [c[:2] for c in r.calls].count(["losetup", "-d"]) == 2
    wb.finish()
    g = grubenv.load(paths.grubenv)
    assert g.get("bb_oneshot") == ISO and g.get("bb_wb_iso") is None 


def test_udf_falls_back_to_iso9660(env):
    paths, tree = env
    r = FakeRunner(tree, fail_mount=("udf",))
    winboot.WinBoot(paths, r).plan()
    assert [c[2] for c in r.calls if c[0] == "mount"] == ["udf", "iso9660"]


def test_mount_failure_detaches(env):
    paths, tree = env
    r = FakeRunner(tree, fail_all=True)
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, r).plan()
    assert ["losetup", "-d", "/dev/loop7"] in r.calls


def test_wrong_fs_stops_before_mount(env):
    paths, tree = env
    r = FakeRunner(tree, fstype="ntfs3")
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, r).plan()
    assert not any(c[0] == "losetup" for c in r.calls)


def test_missing_keys_no_writes(env):
    paths, tree = env
    g = grubenv.load(paths.grubenv)
    g.unset("bb_wb_iso")
    grubenv.save(paths.grubenv, g)
    before = open(paths.grubenv, "rb").read()
    r = FakeRunner(tree)
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, r).plan()
    assert e.value.code == GRUBENV
    assert r.calls == [] and open(paths.grubenv, "rb").read() == before
    assert not os.path.exists(os.path.join(paths.data, "beast-booter"))


def test_plan_not_a_file(env):
    paths, tree = env
    os.unlink(paths.data + ISO)
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, FakeRunner(tree)).plan()


def test_screens_success_and_cancel(env):
    from beastnet.winflow import WinbootScreens
    paths, tree = env
    msgs, quits = [], []

    class UI:
        def task(self, t, x, fn): return fn()
        def confirm(self, t, x, *a, **k):
            msgs.append(x)
            return True
        def message(self, t, x, **k): msgs.append(x)
        def download(self, t, lines, job, what=""):
            return job(lambda p: None, types.SimpleNamespace(is_set=lambda: False))

    flow = types.SimpleNamespace(
        ui=UI(), ctx=types.SimpleNamespace(paths=paths, system=types.SimpleNamespace(runner=FakeRunner(tree)),
                                           reporter=types.SimpleNamespace(emit=lambda *a: None)),
        common=lambda a: quits.append(a), show_error=lambda e, t: quits.append(e.code))
    WinbootScreens(flow).run()
    assert quits == ["reboot"] and ISO in msgs[0]
    assert grubenv.load(paths.grubenv).get("bb_oneshot") == ISO


def test_small_iso_refused(env):
    paths, tree = env
    open(paths.data + ISO, "wb").write(b"x" * 98303)
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, FakeRunner(tree)).plan()
    assert e.value.code == WINBOOT
