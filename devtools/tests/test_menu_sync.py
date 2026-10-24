"""bb-dev menu-sync: build.sh's selection rules, syncing into a FAT ESP
(a small mformat image stands in for the drive), --watch, dist/ checks."""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev import cli, diskimg, menufiles, paths  # noqa: E402
from bbdev.commands import menu_sync  # noqa: E402
from bbdev.msg import Failure  # noqa: E402


def make_menu(root: Path) -> Path:
    (root / "beast").mkdir(parents=True)
    (root / "grub.cfg").write_text("source $prefix/beast/main.cfg\n")
    (root / "beast" / "main.cfg").write_text("echo main\n")
    (root / "beast" / "lib.cfg").write_text("function f { true; }\n")
    return root


def make_esp(tmp_path: Path, fat32: bool = False) -> diskimg.ImageInfo:
    """A small FAT16 ESP (layout 1), or with fat32=True the 512 MiB FAT32 ESP of
    layout 2 (sparse)."""
    img = tmp_path / "esp.img"
    if fat32:
        diskimg.run(["mformat", "-C", "-F", "-i", img, "-T", "1048576", "-h", "255", "-s", "63", "::"])
    else:
        diskimg.run(["mformat", "-C", "-i", img, "-T", "32768", "-h", "2", "-s", "32", "::"])
    fat = diskimg.Fat(img, 0)
    fat.put_bytes("/" + diskimg.ESP_MARKER, b"id\n")
    fat.put_bytes("/grub/grub.cfg", b"old grub.cfg\n")
    fat.put_bytes("/grub/beast/main.cfg", b"echo main\n")
    fat.put_bytes("/grub/beast/stale.cfg", b"from an older menu\n")
    fat.put_bytes("/grub/beast/version.cfg", b'set bb_version="0.1.0"\n')
    fat.put_bytes("/grub/beast/device.cfg", b'set bb_layout="msdos"\n')
    fat.put_bytes("/grub/i386-pc/normal.mod", b"\x7fELF")
    fat.put_bytes("/grub/fonts/unicode.pf2", b"PFF2")
    fat.put_bytes("/grub/oldtheme/theme.txt", b"gone\n")
    return diskimg.ImageInfo(img, "msdos", "0.1.0", "fat32", 0, 65536, 0, 65536, {})


# ---------------------------------------------------------------------------
# Selection rules (build/build.sh)
# ---------------------------------------------------------------------------

def test_menu_files_applies_build_sh_rules(tmp_path):
    src = make_menu(tmp_path / "grub")
    for name in ("main.cfg~", ".main.cfg.swp", "x.swo", "x.bak", "x.orig", "x.rej", "#x#", "README.md",
                 "version.cfg", "device.cfg"):
        (src / "beast" / name).write_text("skip\n")
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("skip\n")
    (src / "themes" / "dark").mkdir(parents=True)
    (src / "themes" / "dark" / "theme.txt").write_text("keep\n")
    assert list(menufiles.menu_files(src)) == ["beast/lib.cfg", "beast/main.cfg", "grub.cfg", "themes/dark/theme.txt"]


@pytest.mark.parametrize("bad", ["i386-pc/normal.mod", "x86_64-efi/x.mod", "fonts/unicode.pf2"])
def test_menu_files_rejects_build_output(tmp_path, bad):
    src = make_menu(tmp_path / "grub")
    (src / bad).parent.mkdir(parents=True, exist_ok=True)
    (src / bad).write_text("x")
    with pytest.raises(Failure, match="must not provide"):
        menufiles.menu_files(src)


def test_menu_files_rejects_symlinks(tmp_path):
    src = make_menu(tmp_path / "grub")
    (src / "beast" / "link.cfg").symlink_to(src / "beast" / "main.cfg")
    with pytest.raises(Failure, match="symlink"):
        menufiles.menu_files(src)
    (src / "beast" / "link.cfg").unlink()
    (src / "linkdir").symlink_to(src / "beast")
    with pytest.raises(Failure, match="symlink"):
        menufiles.menu_files(src)


def test_menu_files_needs_entry_points(tmp_path):
    with pytest.raises(Failure, match="grub.cfg"):
        menufiles.menu_files(tmp_path)


def test_protected():
    for p in ("beast/version.cfg", "beast/device.cfg", "i386-pc/normal.mod", "x86_64-efi/a.mod", "fonts/unicode.pf2"):
        assert menufiles.protected(p)
    for p in ("grub.cfg", "beast/main.cfg", "fonts/other.pf2"):
        assert not menufiles.protected(p)


def test_repo_menu_matches_the_shipped_selection():
    """The real grub/ is selectable (no symlinks / build output)."""
    files = menufiles.menu_files(paths.GRUB_SRC)
    assert "grub.cfg" in files and "beast/main.cfg" in files


def test_bb_menu_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv("BB_MENU_DIR", str(tmp_path))
    assert menufiles.menu_dir() == tmp_path.resolve()
    monkeypatch.delenv("BB_MENU_DIR")
    assert menufiles.menu_dir() == paths.GRUB_SRC


# ---------------------------------------------------------------------------
# Syncing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fat32", [False, True], ids=["fat16", "fat32"])
def test_sync_mirrors_grub_into_the_esp(tmp_path, fat32):
    info = make_esp(tmp_path, fat32)
    if fat32:
        assert b"FAT32" in diskimg.run(["minfo", "-i", info.path, "::"]).stdout
    src = make_menu(tmp_path / "grub")
    res = menu_sync.sync(info, src)
    assert res.updated == ["grub.cfg"]
    assert res.added == ["beast/lib.cfg"]
    assert sorted(res.removed) == ["beast/stale.cfg", "oldtheme/theme.txt"]
    assert res.unchanged == 1
    esp = info.esp()
    assert esp.read("/grub/grub.cfg") == b"source $prefix/beast/main.cfg\n"
    assert esp.read("/grub/beast/lib.cfg") == b"function f { true; }\n"
    assert esp.read("/grub/beast/stale.cfg") is None
    assert not esp.exists("/grub/oldtheme")
    # never touched
    assert esp.read("/grub/beast/version.cfg") == b'set bb_version="0.1.0"\n'
    assert esp.read("/grub/beast/device.cfg") == b'set bb_layout="msdos"\n'
    assert esp.read("/grub/i386-pc/normal.mod") == b"\x7fELF"
    assert esp.read("/grub/fonts/unicode.pf2") == b"PFF2"
    # second run: nothing to do
    again = menu_sync.sync(info, src)
    assert not again.changed and again.unchanged == 3


def test_sync_keeps_what_the_build_and_installer_put_in_grub(tmp_path, monkeypatch):
    """Layout 2: the theme (build/theme), fonts, i386-pc modules and grubenv
    live under /grub/ too; a sync must not remove them as 'not in grub/'."""
    info = make_esp(tmp_path, fat32=True)
    esp = info.esp()
    built = {"themes/beast/theme-efi.txt": b"theme", "themes/beast/icons/iso.png": b"\x89PNG",
             "fonts/NotoSans-Regular-16.pf2": b"PFF2"}
    for r, data in built.items():
        esp.put_bytes(f"/grub/{r}", data)
    esp.put_bytes("/grub/grubenv", b"# GRUB Environment Block\n")
    manifest = {"files": {f"esp/grub/{r}": {"origin": "built:build/theme/mktheme.py", "sha256": ""} for r in built}}
    manifest["files"]["esp/grub/beast/main.cfg"] = {"origin": "repo:grub/beast/main.cfg", "sha256": ""}
    monkeypatch.setattr(menufiles, "load_manifest", lambda dist=None: manifest)
    res = menu_sync.sync(info, make_menu(tmp_path / "grub"))
    assert sorted(res.removed) == ["beast/stale.cfg", "oldtheme/theme.txt"]
    for r, data in built.items():
        assert esp.read(f"/grub/{r}") == data, r
    assert esp.read("/grub/grubenv").startswith(b"# GRUB Environment Block")
    assert esp.exists("/grub/themes/beast/icons")


def test_sync_refuses_a_non_beast_booter_esp(tmp_path):
    info = make_esp(tmp_path)
    info.esp().delete("/" + diskimg.ESP_MARKER)
    with pytest.raises(Failure, match=diskimg.ESP_MARKER):
        menu_sync.sync(info, make_menu(tmp_path / "grub"))


def test_dist_mismatch_is_reported(tmp_path, monkeypatch):
    info = make_esp(tmp_path)
    src = make_menu(tmp_path / "grub")
    shipped = {f"esp/grub/{r}": {"sha256": menufiles.sha256(p.read_bytes()), "origin": f"repo:grub/{r}"}
               for r, p in menufiles.menu_files(src).items()}
    monkeypatch.setattr(menufiles, "load_manifest", lambda dist=None: {"files": shipped})
    assert menu_sync.sync(info, src).differs_from_dist == []
    (src / "beast" / "main.cfg").write_text("echo edited\n")
    assert menu_sync.sync(info, src).differs_from_dist == ["beast/main.cfg"]


def test_cli_one_shot(tmp_path, monkeypatch, capsys):
    info = make_esp(tmp_path)
    src = make_menu(tmp_path / "grub")
    monkeypatch.setenv("BB_MENU_DIR", str(src))
    monkeypatch.setattr(diskimg, "image_info", lambda image: info)
    assert cli.main(["menu-sync", "--image", str(info.path)]) == 0
    out = capsys.readouterr()
    assert "updated  /grub/grub.cfg" in out.out and "removed  /grub/beast/stale.cfg" in out.out
    assert "no longer matches dist/manifest.json" in out.err


def test_watch_resyncs_on_change(tmp_path, monkeypatch, capsys):
    info = make_esp(tmp_path)
    src = make_menu(tmp_path / "grub")
    monkeypatch.setenv("BB_MENU_DIR", str(src))
    monkeypatch.setattr(diskimg, "image_info", lambda image: info)

    def edit_then_stop():
        time.sleep(0.5)
        (src / "beast" / "main.cfg").write_text("echo edited\n")
        time.sleep(1.0)
        os.kill(os.getpid(), signal.SIGTERM)

    t = threading.Thread(target=edit_then_stop)
    t.start()
    old = signal.getsignal(signal.SIGTERM)
    rc = cli.main(["menu-sync", "--image", str(info.path), "--watch", "--interval", "0.05"])
    t.join()
    assert rc == 0
    assert signal.getsignal(signal.SIGTERM) == old
    out = capsys.readouterr()
    assert "updated  /grub/beast/main.cfg" in out.out
    assert "stopped" in out.err
    assert info.esp().read("/grub/beast/main.cfg") == b"echo edited\n"


def test_dist_state(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    assert not menufiles.dist_state(dist).present
    grub = make_menu(tmp_path / "grub")
    build = tmp_path / "repo" / "build"
    build.mkdir(parents=True)
    monkeypatch.setattr(paths, "GRUB_SRC", grub)
    monkeypatch.setattr(paths, "REPO", tmp_path / "repo")
    files = {f"esp/grub/{r}": {"sha256": menufiles.sha256(p.read_bytes()), "origin": f"repo:grub/{r}"}
             for r, p in menufiles.menu_files(grub).items()}
    dist.mkdir()
    (build / "build.sh").write_text("old\n")
    os.utime(build / "build.sh", (1, 1))
    import json
    (dist / "manifest.json").write_text(json.dumps({"files": files}))
    st = menufiles.dist_state(dist)
    assert st.present and not st.stale
    (grub / "beast" / "main.cfg").write_text("changed\n")
    (build / "build.sh").write_text("new\n")
    os.utime(build / "build.sh", (time.time() + 60, time.time() + 60))
    st = menufiles.dist_state(dist)
    assert st.menu_changed == ["grub/beast/main.cfg"] and st.build_newer == ["build/build.sh"]
    assert "grub/beast/main.cfg" in st.describe()
