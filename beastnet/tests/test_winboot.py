import io
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from beastnet import grubenv, safedir, winboot
from beastnet.errors import GRUBENV, NO_SPACE, WINBOOT, BeastNetError
from beastnet.paths import Paths

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer" / "tests"))
from udf_synth import build_image, wim_bytes  # noqa: E402  (the host tool's synthetic UDF images)

ISO = "/isos/Win11.iso"


def test_validate_iso():
    assert winboot.validate_iso("/isos//Win11.iso") == ISO
    assert winboot.validate_iso("/..win.iso") == "/..win.iso"
    for bad in (None, "", "isos/x.iso", "/a/../b.iso", "/a\nb", "/a\0b", "/", "/a\\b",
                "/a\tb", "/a\rb", '/a"b', "/a\x7fb", "/a\x1bb", "/w\ufffdin.iso"):
        with pytest.raises(BeastNetError) as e:
            winboot.validate_iso(bad)
        assert e.value.code == WINBOOT


def test_check_fs():
    winboot.check_fs("vfat")
    winboot.check_fs("exfat")
    for fs in ("ntfs3", "ext4", ""):
        with pytest.raises(BeastNetError):
            winboot.check_fs(fs)


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


def chunks_of(data: bytes, n: int = winboot.CHUNK):
    return [data[i:i + n] for i in range(0, len(data), n)]


def test_write_copy_order(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    src = b"x" * (winboot.CHUNK + 10)
    old = stamp(root, ISO)
    seen = []

    def prog(done, total):
        d = winboot.dest_dir(str(root), ISO)
        seen.append(sorted(os.listdir(d)))
        assert total == len(src)

    st = winboot.stamp_bytes(ISO, "native", 1)
    assert winboot.write_copy(chunks_of(src), len(src), str(root), ISO, st, b"h" * 10, prog)
    assert all(s == ["boot.wim.part"] for s in seen)
    assert sorted(os.listdir(old)) == ["boot.wim", "iso-head.bin", "stamp.env"]  # old stamp and wim gone, no stamp yet
    assert open(os.path.join(old, "boot.wim"), "rb").read() == src
    assert len(open(os.path.join(old, "stamp.env"), "rb").read()) == 1024


def test_write_copy_cancel(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    assert not winboot.write_copy([b"x" * 100], 100, str(root), ISO, b"", b"", None, lambda: True)
    assert os.listdir(winboot.dest_dir(str(root), ISO)) == []


def victims(tmp_path):
    v = tmp_path / "victim"
    v.mkdir()
    for n in ("cfg", "head", "wim"):
        (v / n).write_bytes(b"precious")
    return v


@pytest.mark.parametrize("link", ["stamp.env", "iso-head.bin", "boot.wim", "boot.wim.part",
                                  "iso-head.bin.part", "stamp.env.tmp"])
def test_h1_write_copy_refuses_linked_files(tmp_path, link):
    root = tmp_path / "d"
    v = victims(tmp_path)
    d = Path(winboot.dest_dir(str(root), ISO))
    d.mkdir(parents=True)
    (d / link).symlink_to(v / "wim")
    with pytest.raises(BeastNetError) as e:
        winboot.write_copy([b"w" * 10], 10, str(root), ISO, winboot.stamp_bytes(ISO, "native", 10), b"h")
    assert e.value.code == WINBOOT
    assert all(p.read_bytes() == b"precious" for p in v.iterdir())
    assert not (d / "stamp.env").exists() or (d / "stamp.env").is_symlink()


@pytest.mark.parametrize("at", ["beast-booter", "beast-booter/winboot", "beast-booter/winboot/isos"])
def test_h1_write_copy_refuses_linked_folders(tmp_path, at):
    root = tmp_path / "d"
    out = tmp_path / "outside"
    out.mkdir()
    (root / at).parent.mkdir(parents=True, exist_ok=True)
    (root / at).symlink_to(out)
    with pytest.raises(BeastNetError):
        winboot.write_copy([b"w"], 1, str(root), ISO, winboot.stamp_bytes(ISO, "native", 1), b"h")
    assert list(out.iterdir()) == []


def test_write_copy_fifo_part_refused(tmp_path):
    root = tmp_path / "d"
    d = Path(winboot.dest_dir(str(root), ISO))
    d.mkdir(parents=True)
    os.mkfifo(d / "boot.wim.part")
    with pytest.raises(BeastNetError):  # at once: never opened
        winboot.write_copy([b"w"], 1, str(root), ISO, winboot.stamp_bytes(ISO, "native", 1), b"h")


def test_write_copy_iso_read_error_cleans_up(tmp_path):
    from beastnet.udf import UdfError
    root = tmp_path / "d"
    root.mkdir()

    def bad():
        yield b"x" * 10
        raise UdfError("extent outside the image")
    with pytest.raises(BeastNetError) as e:
        winboot.write_copy(bad(), 20, str(root), ISO, winboot.stamp_bytes(ISO, "native", 20), b"h")
    assert "cannot read the ISO" in e.value.text
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
    """Only findmnt is expected: the ISO is never attached or mounted (N1)."""

    def __init__(self, fstype="exfat"):
        self.fstype, self.calls = fstype, []

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        assert argv[0] == "findmnt", argv
        return subprocess.CompletedProcess(argv, 0, self.fstype + "\n", "")


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "root"
    paths = Paths(root=str(root))
    os.makedirs(paths.data + "/isos")
    os.makedirs(paths.esp + "/grub")
    open(paths.data + ISO, "wb").write(build_image(wim_bytes(5000)))
    g = grubenv.GrubEnv()
    g.set("bb_wb_iso", ISO)
    g.set("bb_oneshot", "/old")
    open(paths.grubenv, "wb").write(g.to_bytes())
    return paths


def test_inspect_iso():
    wim, kind = winboot.inspect_iso(io.BytesIO(build_image(wim_bytes(5000))))
    assert (wim.size, kind) == (5000, "setup")
    assert winboot.inspect_iso(io.BytesIO(build_image(wim_bytes(), with_install=False)))[1] == "native"
    with pytest.raises(BeastNetError) as e:
        winboot.inspect_iso(io.BytesIO(bytes(300 * 2048)))
    assert e.value.code == WINBOOT and "cannot read the ISO" in e.value.text


def test_plan_run_finish(env):
    paths = env
    r = FakeRunner()
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
    assert open(os.path.join(d, "boot.wim"), "rb").read() == wim_bytes(5000)
    assert {c[0] for c in r.calls} == {"findmnt"}  # no losetup, no mount (N1)
    wb.finish()
    g = grubenv.load(paths.grubenv)
    assert g.get("bb_oneshot") == ISO and g.get("bb_wb_iso") is None


def test_n1_links_on_the_data_partition_are_not_followed(env, tmp_path):
    """revB/poc: an ISO path that leads outside /mnt/data (here via a linked folder) is
    refused; inside the ISO there are no links to follow any more (userspace UDF)."""
    paths = env
    secret = tmp_path / "esp-secret"
    secret.mkdir()
    (secret / "Win11.iso").write_bytes(build_image(wim_bytes(5000)))
    os.rename(paths.data + "/isos", paths.data + "/isos.old")
    os.symlink(secret, paths.data + "/isos")
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, FakeRunner()).plan()
    assert "not a file on the data partition" in e.value.text
    os.unlink(paths.data + "/isos")
    os.mkdir(paths.data + "/isos")
    os.symlink(secret / "Win11.iso", paths.data + ISO)
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, FakeRunner()).plan()


def test_n2_fs_check_comes_first(env):
    paths = env
    os.unlink(paths.data + ISO)
    os.symlink("/proc/kmsg", paths.data + ISO)
    r = FakeRunner(fstype="ntfs3")
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, r).plan()
    assert "not FAT32 or exFAT" in e.value.text


def test_n2_run_rechecks_fs(env):
    paths = env
    plan = winboot.WinBoot(paths, FakeRunner()).plan()
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, FakeRunner(fstype="ext4")).run(plan)
    assert not os.path.exists(os.path.join(paths.data, "beast-booter"))


def test_wrong_fs_stops_before_reading(env):
    paths = env
    r = FakeRunner(fstype="ntfs3")
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, r).plan()
    assert r.calls == [["findmnt", "-n", "-o", "FSTYPE", "--target", paths.data]]


def test_plan_counts_old_copy_and_refuses_links(env, monkeypatch):
    paths = env
    monkeypatch.setattr(os, "statvfs", lambda p: types.SimpleNamespace(f_bavail=1 << 20, f_frsize=4096))
    wb = winboot.WinBoot(paths, FakeRunner())
    free = wb.plan().free
    d = Path(winboot.dest_dir(paths.data, ISO))
    d.mkdir(parents=True)
    (d / "boot.wim.part").write_bytes(b"x" * 4096)
    assert wb.plan().free == free + 4096
    os.unlink(d / "boot.wim.part")
    (d / "boot.wim").symlink_to("/etc/passwd")
    with pytest.raises(BeastNetError):
        wb.plan()


def test_missing_keys_no_writes(env):
    paths = env
    g = grubenv.load(paths.grubenv)
    g.unset("bb_wb_iso")
    grubenv.save(paths.grubenv, g)
    before = open(paths.grubenv, "rb").read()
    r = FakeRunner()
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, r).plan()
    assert e.value.code == GRUBENV
    assert r.calls == [] and open(paths.grubenv, "rb").read() == before
    assert not os.path.exists(os.path.join(paths.data, "beast-booter"))


def test_plan_not_a_file(env):
    paths = env
    os.unlink(paths.data + ISO)
    with pytest.raises(BeastNetError):
        winboot.WinBoot(paths, FakeRunner()).plan()


def screens(paths, runner=None, confirm=True, cancel=False):
    from beastnet.winflow import WinbootScreens
    msgs, quits = [], []
    runner = runner or FakeRunner()

    class UI:
        def task(self, t, x, fn): return fn()
        def confirm(self, t, x, *a, **k):
            msgs.append(x)
            return confirm
        def message(self, t, x, **k): msgs.append(x)
        def download(self, t, lines, job, what=""):
            return job(lambda p: None, types.SimpleNamespace(is_set=lambda: cancel))

    flow = types.SimpleNamespace(
        ui=UI(), ctx=types.SimpleNamespace(paths=paths, system=types.SimpleNamespace(runner=runner),
                                           reporter=types.SimpleNamespace(emit=lambda *a: None)),
        common=lambda a: quits.append(a), show_error=lambda e, t: quits.append(e.code))
    WinbootScreens(flow).run()
    return msgs, quits


def test_screens_success(env):
    paths = env
    msgs, quits = screens(paths)
    assert quits == ["reboot"] and ISO in msgs[0]
    g = grubenv.load(paths.grubenv)
    assert g.get("bb_oneshot") == ISO and g.get("bb_wb_iso") is None


@pytest.mark.parametrize("how", ["back", "cancel", "error", "not-windows"])
def test_n2_input_unset_on_every_exit(env, how):
    paths = env
    if how == "not-windows":
        open(paths.data + ISO, "wb").write(bytes(300 * 2048))
    msgs, quits = screens(paths, FakeRunner("ntfs3" if how == "error" else "exfat"),
                          confirm=how != "back", cancel=how == "cancel")
    assert "reboot" not in quits
    g = grubenv.load(paths.grubenv)
    assert g.get("bb_wb_iso") is None and g.get("bb_oneshot") == "/old"
    assert not os.path.exists(os.path.join(winboot.dest_dir(paths.data, ISO), "stamp.env"))


def test_vendored_modules_identical():
    """udf.py and safedir.py are the host tool's, byte for byte."""
    for name in ("udf.py", "safedir.py"):
        assert (REPO / "installer/beastbooter" / name).read_bytes() == \
            (REPO / "beastnet/python/beastnet" / name).read_bytes(), f"{name} diverged; copy it over"
    assert safedir.HAVE_DIRFD  # the helper (Linux) always takes the dir_fd path


def test_small_iso_refused(env):
    paths = env
    open(paths.data + ISO, "wb").write(b"x" * 98303)
    with pytest.raises(BeastNetError) as e:
        winboot.WinBoot(paths, FakeRunner()).plan()
    assert e.value.code == WINBOOT
