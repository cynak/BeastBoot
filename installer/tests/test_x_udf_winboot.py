"""UDF reader, ISO9660 identity and `prepare-windows`, on a synthetic UDF bridge image."""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path

import pytest

from beastbooter import cli, safedir, udf, winboot
from beastbooter.errors import BeastError
from beastbooter.udf import UdfError
from beastbooter.util import Reporter

from udf_synth import PART, S, build_image, fe, fid, tag, wim_bytes  # noqa: F401 (fuzzers import them from here)


@pytest.fixture
def image() -> bytes:
    return build_image(wim_bytes())


@pytest.fixture(autouse=True)
def drive(monkeypatch):
    """tmp dirs stand in for a mounted exFAT data partition: any folder named 'data'
    (or 'drive') is a mount point."""
    monkeypatch.setattr(winboot, "fs_type", lambda p: "exfat")
    monkeypatch.setattr(winboot, "is_mount", lambda p: os.path.basename(p) in ("data", "drive")
                        or p == os.path.dirname(p))


def test_read_files(image):
    vol = udf.open_udf(io.BytesIO(image))
    f = vol.lookup("SOURCES/Boot.Wim")
    assert f is not None and not f.is_dir and f.size == 70000
    assert f.read_all(1 << 30) == wim_bytes()
    assert vol.lookup("sources/install.wim").read_all() == bytes(4096)
    assert vol.lookup("readme.txt").read_all() == b"hello"
    assert vol.lookup("sources/nope") is None
    assert vol.lookup("readme.txt/x") is None


def test_bad_images_raise_cleanly(image):
    for bad in (bytes(300 * S), image[:100 * S]):
        with pytest.raises(UdfError):
            udf.open_udf(io.BytesIO(bad))
    # damaged: file entry points outside the image
    img = bytearray(image)
    off = (PART + 5) * S
    struct.pack_into("<II", img, off + 216, 70000, 10_000_000)
    vol = udf.open_udf(io.BytesIO(bytes(img)))
    with pytest.raises(UdfError):
        vol.lookup("sources/boot.wim")


def test_stamp_format():
    b = winboot.stamp_bytes([("bb_wb_iso", "/a\\b"), ("bb_wb_label", "")])
    assert len(b) == 1024
    assert b.startswith(b"# GRUB Environment Block\nbb_wb_iso=/a\\\\b\nbb_wb_label=\n#")
    assert set(b[len(b"# GRUB Environment Block\nbb_wb_iso=/a\\\\b\nbb_wb_label=\n"):]) == {0x23}
    assert winboot.parse_stamp(b) == {"bb_wb_iso": "/a\\b", "bb_wb_label": ""}


def make_root(tmp_path: Path, image: bytes) -> tuple[Path, Path]:
    root = tmp_path / "data"
    (root / "beast-booter").mkdir(parents=True)
    (root / "isos").mkdir()
    iso = root / "isos" / "Win11.iso"
    iso.write_bytes(image)
    return root, iso


def test_prepare_cli(tmp_path, image, capsys):
    root, iso = make_root(tmp_path, image)
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    d = root / "beast-booter" / "winboot" / "isos" / "Win11.iso"
    assert (d / "boot.wim").read_bytes() == wim_bytes()
    st = winboot.parse_stamp((d / "stamp.env").read_bytes())
    assert st["bb_wb_iso"] == "/isos/Win11.iso"
    assert (d / "iso-head.bin").read_bytes() == image[32768:98304]
    assert "bb_wb_uuid" not in st
    assert st["bb_wb_kind"] == "setup" and st["bb_wb_size"] == "70000"
    assert st["bb_wb_by"].startswith("host ")
    assert not list(d.glob("*.part")) and not list(d.glob("*.tmp"))
    # second run skips; --force copies again
    mtime = (d / "boot.wim").stat().st_mtime_ns
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    assert (d / "boot.wim").stat().st_mtime_ns == mtime
    (d / "iso-head.bin").write_bytes(b"x")  # stale identity: copied again
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    assert (d / "boot.wim").stat().st_mtime_ns != mtime or (d / "iso-head.bin").read_bytes() == image[32768:98304]
    assert cli.main(["prepare-windows", "-q", "--force", "--data-root", str(root), str(iso)]) == 0


def test_prepare_native_and_errors(tmp_path, capsys):
    root, iso = make_root(tmp_path, build_image(wim_bytes(), with_install=False))
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 0
    st = winboot.parse_stamp((root / "beast-booter/winboot/isos/Win11.iso/stamp.env").read_bytes())
    assert st["bb_wb_kind"] == "native"

    r2, iso2 = make_root(tmp_path / "b", bytes(90000))
    assert cli.main(["prepare-windows", "-q", str(iso2)]) == 1
    assert not (r2 / "beast-booter" / "winboot").exists()

    out = tmp_path / "elsewhere.iso"
    out.write_bytes(b"x")
    assert cli.main(["prepare-windows", "-q", str(out)]) == 1  # no beast-booter/ above
    assert cli.main(["prepare-windows", "-q", "--data-root", str(root), str(out)]) == 1  # outside root
    junk = root / "isos" / "junk.iso"
    junk.write_bytes(bytes(300 * S))
    assert cli.main(["prepare-windows", "-q", str(junk)]) == 1


REAL = Path("/home/cynak/Downloads/Windows11_Client_x64_en-us_26300_9457.iso")


@pytest.mark.skipif(not REAL.exists(), reason="real Windows ISO not present")
def test_real_iso_boot_wim():
    with open(REAL, "rb") as f:
        vol = udf.open_udf(f)
        w = vol.lookup("sources/boot.wim")
        assert w is not None and w.size > 1 << 20
        assert next(w.read_chunks())[:8] == b"MSWIM\0\0\0"
        assert vol.lookup("sources/install.wim") or vol.lookup("sources/install.esd")


# -- security regressions (docs/SECURITY_REVIEW-0.4.0.md H1-H5, F6) -----------------------
def prep(iso, data_root=None, force=False):
    return winboot.prepare(str(iso), str(data_root) if data_root else None, force, Reporter(quiet=True))


def make_victims(tmp_path: Path) -> dict[Path, bytes]:
    v = tmp_path / "victim"
    v.mkdir()
    out = {}
    for n in ("cfg", "headtarget", "bashrc"):
        (v / n).write_bytes(b"precious " + n.encode())
        out[v / n] = (v / n).read_bytes()
    return out


@pytest.mark.skipif(not safedir.HAVE_DIRFD, reason="POSIX symlinks")
@pytest.mark.parametrize("links", [("stamp.env", "iso-head.bin", "boot.wim.part"), ("boot.wim.part",),
                                   ("iso-head.bin.part",), ("stamp.env.tmp",)])
def test_h1_symlinked_files_are_not_followed(tmp_path, image, links):
    """revC/poc: links in the winboot folder must never redirect a write."""
    root, iso = make_root(tmp_path, image)
    victims = make_victims(tmp_path)
    d = root / "beast-booter/winboot/isos/Win11.iso"
    d.mkdir(parents=True)
    targets = {"stamp.env": "cfg", "iso-head.bin": "headtarget", "boot.wim.part": "bashrc",
               "iso-head.bin.part": "headtarget", "stamp.env.tmp": "cfg"}
    for n in links:
        (d / n).symlink_to(tmp_path / "victim" / targets[n])
    with pytest.raises(BeastError) as e:
        prep(iso)
    assert e.value.code == "windows-unsafe"
    for p, data in victims.items():
        assert p.read_bytes() == data


@pytest.mark.skipif(not safedir.HAVE_DIRFD, reason="POSIX symlinks")
@pytest.mark.parametrize("at", ["beast-booter/winboot", "beast-booter/winboot/isos", "beast-booter/winboot/isos/Win11.iso"])
def test_h1_symlinked_folder_is_not_followed(tmp_path, image, at):
    """revC/poc2: beast-booter/winboot (or a folder below) links outside the drive."""
    root, iso = make_root(tmp_path, image)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"k")
    link = root / at
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 1
    with pytest.raises(BeastError) as e:
        prep(iso, force=True)
    assert e.value.code == "windows-unsafe"
    assert [p.name for p in outside.rglob("*")] == ["keep"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_h5_fifo_part_refused_and_stale_part_counted(tmp_path, image, monkeypatch):
    root, iso = make_root(tmp_path, image)
    d = root / "beast-booter/winboot/isos/Win11.iso"
    d.mkdir(parents=True)
    os.mkfifo(d / "boot.wim.part")
    with pytest.raises(BeastError) as e:  # refused at once, not blocked on open()
        prep(iso)
    assert e.value.code == "windows-unsafe"
    os.unlink(d / "boot.wim.part")
    (d / "boot.wim.part").write_bytes(b"x" * 5000)  # stale, from an interrupted run
    free = 70000 + winboot.HEADROOM - 4000
    monkeypatch.setattr(winboot.shutil, "disk_usage", lambda p: type("U", (), {"free": free})())
    assert prep(iso)["skipped"] is False  # the stale part's space counts as free
    assert sorted(p.name for p in d.iterdir()) == ["boot.wim", "iso-head.bin", "stamp.env"]


def test_h4_non_utf8_name_refused_before_writing(tmp_path, image):
    """revC/poc3: a non-UTF-8 file name is refused up front (it used to crash after the copy)."""
    if os.name == "nt" or isinstance(os.fsdecode(b"\xff"), bytes):
        pytest.skip("POSIX byte file names")
    root, _ = make_root(tmp_path, image)
    try:
        iso = Path(os.path.join(str(root), os.fsdecode(b"w\xffin.iso")))
        iso.write_bytes(image)
    except (OSError, UnicodeError):
        pytest.skip("the filesystem refuses non-UTF-8 names")
    with pytest.raises(BeastError) as e:
        prep(iso)
    assert e.value.code == "windows-path"
    assert not (root / "beast-booter/winboot").exists()
    assert cli.main(["prepare-windows", "-q", str(iso)]) == 1


@pytest.mark.parametrize("name", ['a"b.iso', "a\tb.iso", "a\x7fb.iso", "a\x1bb.iso"])
def test_h4_control_chars_and_quotes_refused(tmp_path, image, name):
    root, _ = make_root(tmp_path, image)
    try:
        iso = root / name
        iso.write_bytes(image)
    except OSError:
        pytest.skip("the filesystem refuses this name")
    with pytest.raises(BeastError) as e:
        prep(iso)
    assert e.value.code == "windows-path"


def test_f6_dotdot_prefixed_name_accepted(tmp_path, image):
    """revC/poc4: '..win.iso' is inside the data root; only '..' components escape it."""
    root, _ = make_root(tmp_path, image)
    iso = root / "..win.iso"
    iso.write_bytes(image)
    assert prep(iso)["iso"] == "/..win.iso"
    assert (root / "beast-booter/winboot/..win.iso/stamp.env").is_file()


def test_h3_discovery_stops_at_the_mount_point(tmp_path, image):
    """revC/poc5: a source checkout's beast-booter/ above the ISO is not a data root."""
    home = tmp_path / "home"
    (home / "Code/beast-booter/.git").mkdir(parents=True)
    (home / "Code/dl").mkdir(parents=True)
    iso = home / "Code/dl/win.iso"
    iso.write_bytes(image)
    with pytest.raises(BeastError) as e:
        prep(iso)
    assert e.value.code == "windows-data-root"
    assert not (home / "Code/beast-booter/winboot").exists()
    # the mount point (a folder named 'drive' here) needs beast-booter/ at its root
    drv = tmp_path / "drive"
    (drv / "isos").mkdir(parents=True)
    (drv / "isos/w.iso").write_bytes(image)
    with pytest.raises(BeastError):
        prep(drv / "isos/w.iso")
    assert prep(drv / "isos/w.iso", data_root=drv)["iso"] == "/isos/w.iso"  # --data-root: no marker needed
    with pytest.raises(BeastError) as e:  # but it must be a mount point
        prep(drv / "isos/w.iso", data_root=drv / "isos")
    assert e.value.code == "windows-data-root"


@pytest.mark.skipif(not safedir.HAVE_DIRFD, reason="POSIX symlinks")
def test_symlinked_iso_refused(tmp_path, image):
    root, iso = make_root(tmp_path, image)
    (root / "link.iso").symlink_to(iso)
    with pytest.raises(BeastError) as e:
        prep(root / "link.iso")
    assert e.value.code == "windows-iso"


@pytest.mark.parametrize("fs", [None, "ext4", "tmpfs", "ntfs3", "fuseblk (ntfs)", "fuseblk (unknown)"])
def test_h2_only_fat_and_exfat(tmp_path, image, monkeypatch, fs):
    root, iso = make_root(tmp_path, image)
    monkeypatch.setattr(winboot, "fs_type", lambda p: fs)
    for data_root in (None, root):  # --data-root does not bypass the check
        with pytest.raises(BeastError) as e:
            prep(iso, data_root)
        assert e.value.code == "windows-fs"
    assert not (root / "beast-booter/winboot").exists()


def test_h2_linux_mounts(tmp_path, monkeypatch):
    m = tmp_path / "mounts"
    m.write_text("/dev/sda2 / ext4 rw 0 0\n"
                 "/dev/sdb1 /media/u/BEAST\\040BOOT exfat rw 0 0\n"
                 "/dev/sdc1 /media/u/FAT vfat rw 0 0\n"
                 "/dev/sdd1 /media/u/FUSE fuseblk rw 0 0\n"
                 "tmpfs /tmp tmpfs rw 0 0\n")
    probed = {"/dev/sdd1": "exfat"}
    monkeypatch.setattr(winboot, "_probe_dev_fs", lambda dev: probed.get(dev))
    fs = lambda p: winboot._linux_fs(p, str(m))  # noqa: E731
    assert fs("/media/u/BEAST BOOT") == "exfat"
    assert fs("/media/u/BEAST BOOT/isos") == "exfat"
    assert fs("/media/u/FAT") == "fat"
    assert fs("/media/u/FATTER") == "ext4"
    assert fs("/tmp/x") == "tmpfs"
    assert fs("/media/u/FUSE") == "exfat"
    probed["/dev/sdd1"] = "ntfs"
    assert fs("/media/u/FUSE") == "fuseblk (ntfs)"
    probed.clear()
    assert fs("/media/u/FUSE") == "fuseblk (unknown)"
    assert winboot._linux_fs("/x", str(tmp_path / "missing")) is None


def test_root_warning(tmp_path, image, monkeypatch, capsys):
    root, iso = make_root(tmp_path, image)
    monkeypatch.setattr(winboot.os, "geteuid", lambda: 0, raising=False)
    prep(iso)
    assert "running as root is not needed" in capsys.readouterr().err


@pytest.mark.skipif(not safedir.HAVE_DIRFD, reason="POSIX symlinks")
def test_safedir_unit(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "r").mkdir()
    (tmp_path / "r/l").symlink_to(tmp_path / "out")
    with pytest.raises(safedir.UnsafePath):
        safedir.SafeDir(str(tmp_path / "r"), ["l", "x"])
    for bad in ("..", ".", "", "a/b", "a\0b"):
        with pytest.raises(safedir.UnsafePath):
            safedir.SafeDir(str(tmp_path / "r"), [bad])
    with safedir.SafeDir(str(tmp_path / "r"), ["a", "b"]) as sd:
        (tmp_path / "r/a/b/dangling").symlink_to(tmp_path / "out/new")
        with pytest.raises(FileExistsError):
            sd.create("dangling")
        assert not (tmp_path / "out/new").exists()
        assert sd.read("dangling", 10) is None
        with sd.create("f") as f:
            f.write(b"hi")
        assert sd.read("f", 10) == b"hi" and sd.regular_size("f") == 2
        sd.replace("f", "dangling")  # replaces the link itself
        assert (tmp_path / "r/a/b/dangling").read_bytes() == b"hi" and not (tmp_path / "out/new").exists()
    with pytest.raises(FileNotFoundError):
        safedir.SafeDir(str(tmp_path / "r"), ["zz"], create=False)


def test_vendored_modules_identical():
    """The helper ships byte-identical copies of the UDF reader and the safe writer."""
    repo = Path(__file__).resolve().parents[2]
    if not (repo / "beastnet/python/beastnet").is_dir():
        # a copied test layout (portable smoke runs these tests with the bundled
        # runtime, without the repo); beastnet/tests checks the same in the repo
        pytest.skip("not run from the repository")
    for name in ("udf.py", "safedir.py"):
        assert (repo / "installer/beastbooter" / name).read_bytes() == \
            (repo / "beastnet/python/beastnet" / name).read_bytes(), f"{name} diverged; copy it over"


def test_staging_skips_only_the_drive_checks(tmp_path, image, monkeypatch):
    """staging=True (drive images built from a folder, tests/e2e real-ISO harness): no
    mount-point or FAT32/exFAT check, the same writes; the command line cannot set it."""
    monkeypatch.setattr(winboot, "is_mount", lambda p: False)
    monkeypatch.setattr(winboot, "fs_type", lambda p: "ext4")
    stage = tmp_path / "stage"
    (stage / "isos").mkdir(parents=True)
    (stage / "isos/w.iso").write_bytes(image)
    iso = stage / "isos/w.iso"
    with pytest.raises(BeastError):  # not staging: refused
        prep(iso, data_root=stage)
    with pytest.raises(BeastError) as e:  # staging needs the data root
        winboot.prepare(str(iso), None, False, Reporter(quiet=True), staging=True)
    assert e.value.code == "windows-data-root"
    r = winboot.prepare(str(iso), str(stage), False, Reporter(quiet=True), staging=True)
    assert r["iso"] == "/isos/w.iso"
    out = stage / "beast-booter/winboot/isos/w.iso"
    assert sorted(p.name for p in out.iterdir()) == ["boot.wim", "iso-head.bin", "stamp.env"]
    if safedir.HAVE_DIRFD:  # link-safe writing still applies
        out2 = tmp_path / "outside"
        out2.mkdir()
        (stage / "isos/x.iso").write_bytes(image)
        (stage / "beast-booter/winboot/isos/x.iso").symlink_to(out2)
        with pytest.raises(BeastError):
            winboot.prepare(str(stage / "isos/x.iso"), str(stage), False, Reporter(quiet=True), staging=True)
        assert not any(out2.iterdir())


def test_cli_has_no_staging_option():
    from beastbooter import cli
    assert "staging" not in (cli.__doc__ or "") and "--staging" not in open(cli.__file__).read()
