"""bb-dev image: filesystem choice, file selection, dist/ checks, and a real
FAT32 build with the installer (skipped without dist/). No QEMU."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from beastbooter import layout  # noqa: E402

from bbdev import cli, diskimg, freshness, menufiles, paths, userconfig  # noqa: E402
from bbdev.commands import image  # noqa: E402
from bbdev.msg import Failure  # noqa: E402

HAVE_DIST = (paths.DIST / "manifest.json").is_file()


def test_choose_fs(monkeypatch):
    monkeypatch.setattr(diskimg, "udisks_status", lambda: (True, ""))
    assert image.choose_fs(None, True) == "exfat"
    assert image.choose_fs("ntfs", True) == "ntfs"
    monkeypatch.setattr(diskimg, "udisks_status", lambda: (False, "no D-Bus"))
    assert image.choose_fs(None, True) == "fat32"
    assert image.choose_fs("fat32", True) == "fat32"
    assert image.choose_fs("exfat", False) == "exfat"  # nothing to copy: no udisks needed
    with pytest.raises(Failure, match="no D-Bus"):
        image.choose_fs("exfat", True)


def test_tree_files_keeps_structure_and_follows_links(tmp_path, capsys):
    src = tmp_path / "isos"
    (src / "linux" / "Some Folder").mkdir(parents=True)
    (src / "linux" / "Some Folder" / "My Distro.iso").write_bytes(b"a")
    (src / "top.iso").write_bytes(b"bb")
    (src / "link.iso").symlink_to(src / "top.iso")
    (src / "broken.iso").symlink_to(tmp_path / "missing")
    (src / "empty dir").mkdir()
    (src / "later" / "windows").mkdir(parents=True)  # only the leaf is needed: mkdir makes the parents
    (src / "linux" / "loop").symlink_to("..")  # a link back up the tree is not followed
    (src / "shared").symlink_to("linux/Some Folder")  # a link to a directory is
    files, dirs = image.tree_files(src)
    assert sorted(d for d, _ in files) == ["/link.iso", "/linux/Some Folder/My Distro.iso",
                                           "/shared/My Distro.iso", "/top.iso"]
    assert dirs == ["/empty dir", "/later/windows"]
    assert "broken symlinks: broken.iso" in capsys.readouterr().err
    with pytest.raises(Failure):
        image.tree_files(tmp_path / "nope")


def test_describe_contents():
    files = [("/recipes/a.iso", Path("a")), ("/recipes/b.iso", Path("b")), ("/top.iso", Path("t"))]
    sizes = {"/recipes/a.iso": 1024, "/recipes/b.iso": 1024, "/top.iso": 10}
    assert image.describe_contents(files, sizes) == ["/recipes/  (2 files, 2.0 KiB)", "/top.iso  (10 B)"]
    assert image.describe_contents(files, sizes, ["/recipes/empty", "/new/a"]) == [
        "/new/  (empty)", "/recipes/  (2 files, 2.0 KiB)", "/top.iso  (10 B)",
        "(2 empty folders kept from --isos)"]


def test_fixture_files_parses_the_builder(tmp_path, monkeypatch):
    builder = tmp_path / "build_fixtures.py"
    builder.write_text("import sys\nout = sys.argv[sys.argv.index('--out') + 1]\n"
                       "print(f\"casper               {out}/casper.iso  label=CASPER\")\n"
                       "print(f\"windows              {out}/with space/windows.iso  label=WIN\")\n")
    monkeypatch.setattr(image, "FIXTURE_BUILDER", builder)
    monkeypatch.setattr(image, "FIXTURE_CACHE", tmp_path / "cache")
    files = image.fixture_files(dict(os.environ))
    assert files == [("/recipes/casper.iso", tmp_path / "cache" / "casper.iso"),
                     ("/recipes/windows.iso", tmp_path / "cache" / "with space" / "windows.iso")]


def test_missing_dist_is_an_error(monkeypatch):
    monkeypatch.setattr(menufiles, "dist_state", lambda dist=None: menufiles.DistState(False))
    with pytest.raises(Failure, match="dist/"):
        image.check_dist({})


def test_stale_dist_warns(monkeypatch, capsys):
    monkeypatch.setattr(menufiles, "dist_state",
                        lambda dist=None: menufiles.DistState(True, 0, ["grub/beast/main.cfg"], []))
    image.check_dist({})  # stdin is not a tty: no prompt, just warnings
    err = capsys.readouterr().err
    assert "grub/beast/main.cfg" in err and "make build" in err


def test_refuses_to_overwrite_without_force(tmp_path, capsys):
    out = tmp_path / "x.img"
    out.write_bytes(b"old")
    assert cli.main(["image", "--out", str(out)]) == 1
    assert "--force" in capsys.readouterr().err
    assert out.read_bytes() == b"old"


def test_fat32_refuses_files_of_4_gib(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(image, "check_dist", lambda env: None)
    src = tmp_path / "isos"
    src.mkdir()
    with open(src / "huge.iso", "wb") as f:
        f.truncate(4 << 30)
    assert cli.main(["image", "--out", str(tmp_path / "x.img"), "--fs", "fat32", "--isos", str(src)]) == 1
    assert "4 GiB" in capsys.readouterr().err
    assert not (tmp_path / "x.img").exists()


def test_too_small_and_bad_size(tmp_path):
    assert cli.main(["image", "--out", str(tmp_path / "x.img"), "--size", "100M"]) == 1
    from beastbooter.layout import MIN_DISK_MIB
    assert cli.main(["image", "--out", str(tmp_path / "x.img"), "--size", f"{MIN_DISK_MIB - 1}M"]) == 1
    assert not (tmp_path / "x.img").exists()
    assert cli.main(["image", "--out", str(tmp_path / "x.img"), "--size", "lots"]) == 1


@pytest.mark.skipif(not HAVE_DIST, reason="dist/ not built (make build)")
def test_real_fat32_build(tmp_path, capsys):
    src = tmp_path / "isos"
    (src / "linux").mkdir(parents=True)
    (src / "linux" / "a.iso").write_bytes(b"iso-a")
    (src / "top.iso").write_bytes(b"iso-top")
    (src / "empty dir" / "inner").mkdir(parents=True)
    out = tmp_path / "dev.img"
    rc = cli.main(["image", "--out", str(out), "--size", "1G", "--fs", "fat32", "--isos", str(src),
                   "--debug", "--dryrun", "--autoboot", "linux/a.iso", "--serial-console"])
    stdout = capsys.readouterr().out
    assert rc == 0, stdout
    assert out.is_file() and not out.with_name("dev.img.partial").exists()
    assert (tmp_path / "dev.install.log").is_file()
    # the recipe: options as given, plus the build and layout it got
    recipe = freshness.read_recipe(out)
    assert recipe["options"] == {"size": "1G", "layout": "msdos", "fs": "fat32", "fs_auto": False,
                                 "fixtures": False, "isos": str(src), "debug": True, "dryrun": True,
                                 "autoboot": "/linux/a.iso", "serial_console": True}
    assert recipe["dist_build_id"] == freshness.dist_build_id() and recipe["layout_version"] == layout.LAYOUT_VERSION
    assert freshness.check(out).action == freshness.CURRENT
    assert "recipe  " in stdout
    info = diskimg.image_info(out)
    assert info.data_fs == "fat32"
    assert f"byte offset {info.data_offset}" in stdout
    fat = info.data_fat()
    assert fat.read("/linux/a.iso") == b"iso-a" and fat.read("/top.iso") == b"iso-top"
    assert fat.listing("/empty dir", recursive=True) == ["/empty dir/inner/"]
    assert "1 empty folder kept" in stdout
    cfg = userconfig.UserConfig(fat.read(diskimg.USER_CONFIG).decode())
    assert cfg.settings() == {"bb_debug": "1", "bb_dryrun": "1", "bb_autoboot": "/linux/a.iso"}
    device_cfg = info.esp().read("/grub/beast/device.cfg").decode()
    assert 'bb_serial="1"' in device_cfg
    # --force replaces it
    assert cli.main(["image", "--out", str(out), "--size", "1G", "--fs", "fat32", "--force"]) == 0
    assert diskimg.image_info(out).data_fat().read(diskimg.USER_CONFIG) is None
    assert freshness.read_recipe(out)["options"]["debug"] is False
    # without --force on a current image: nothing to do
    capsys.readouterr()
    assert cli.main(["image", "--out", str(out), "--size", "1G", "--fs", "fat32"]) == 0
    assert "is current" in capsys.readouterr().out
