"""Image freshness (layout version + build id vs dist/ and the installer), image
recipes, and what bb-dev vm / image / menu-sync / doctor do about a stale image.
No QEMU, no installer runs: the image state and the refresh steps are faked."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from beastbooter import layout  # noqa: E402

from bbdev import cli, diskimg, freshness, menufiles, paths, qemu  # noqa: E402
from bbdev.commands import doctor, image, menu_sync, vm  # noqa: E402
from bbdev.msg import Failure  # noqa: E402

LV = layout.LAYOUT_VERSION
State = freshness.ImageState


# -- judge ---------------------------------------------------------------------

@pytest.mark.parametrize("state, dist, action, text", [
    (State(LV, "b1"), "b1", freshness.CURRENT, "build b1 (= dist/)"),
    (State(LV, "b0"), "b1", freshness.UPDATE, "installed from build b0, dist/ is build b1"),
    (State(LV, None), "b1", freshness.UPDATE, "no bb_build_id"),
    (State(1, "b1"), "b1", freshness.REBUILD, "it has layout 1, the installer writes layout 2"),
    (State(1, "b0"), "b1", freshness.REBUILD, "512 MiB FAT32 ESP"),
    (State(None, None, "cannot read it: x"), "b1", freshness.UNKNOWN, "cannot read it"),
    (State(LV + 1, "b1"), "b1", freshness.UNKNOWN, "newer than this installer"),
    (State(LV, "b1"), None, freshness.UNKNOWN, "dist/ is not built"),
])
def test_judge(state, dist, action, text):
    v = freshness.judge(state, dist)
    assert v.action == action and text in v.reason
    assert v.stale == (action in (freshness.UPDATE, freshness.REBUILD))


def test_parse_build_id():
    assert freshness.parse_build_id(b'set bb_version="0.1.0"\nset bb_build_id="3152489d4313"\n') == "3152489d4313"
    assert freshness.parse_build_id(b"set bb_build_id=abc\n") == "abc"
    assert freshness.parse_build_id(b'set bb_version="0.1.0"\n') is None
    assert freshness.parse_build_id(None) is None


# -- recipes -------------------------------------------------------------------

def test_recipe_round_trip_and_argv(tmp_path):
    img = tmp_path / "dev.img"
    opts = {"size": "8G", "layout": "gpt", "fs": "fat32", "fs_auto": False, "fixtures": True,
            "isos": "/srv/isos", "debug": True, "dryrun": True, "autoboot": "/linux/a.iso", "serial_console": True}
    p = freshness.write_recipe(img, opts, build_id="b1", layout_version=LV)
    assert p == tmp_path / "dev.bbdev.json"
    data = json.loads(p.read_text())
    assert data["dist_build_id"] == "b1" and data["layout_version"] == LV and data["image"] == "dev.img"
    r = freshness.read_recipe(img)
    assert r["options"] == opts
    assert freshness.recipe_argv(r["options"], img) == [
        "--out", str(img), "--size", "8G", "--layout", "gpt", "--fs", "fat32", "--fixtures", "--debug",
        "--dryrun", "--serial-console", "--isos", "/srv/isos", "--autoboot", "/linux/a.iso", "--force"]
    # an automatically chosen filesystem is chosen again on a rebuild
    freshness.write_recipe(img, {**opts, "fs": "exfat", "fs_auto": True}, build_id="b1", layout_version=LV)
    assert "--fs" not in freshness.recipe_argv(freshness.read_recipe(img)["options"], img)


def test_no_or_broken_recipe_means_setup_defaults(tmp_path):
    img = tmp_path / "old.img"
    assert freshness.read_recipe(img) is None
    freshness.recipe_path(img).write_text("{not json")
    assert freshness.read_recipe(img) is None
    assert freshness.recipe_argv(None, img) == ["--out", str(img), "--size", "4G", "--layout", "msdos",
                                                 "--fixtures", "--debug", "--force"]
    assert freshness.rebuild_command(img).endswith("--fixtures --debug --force")


def test_recipe_options_round_trip_through_the_image_parser(tmp_path):
    """recipe_argv() must only produce options `bb-dev image` accepts."""
    argv = freshness.recipe_argv({"fs": "exfat", "fs_auto": False, "isos": "/i", "autoboot": "/a.iso",
                                  "dryrun": True, "serial_console": True}, tmp_path / "x.img")
    a = cli.build_parser().parse_args(["image", *argv])
    assert a.force and a.fixtures and a.debug and a.dryrun and a.serial_console
    assert a.fs == "exfat" and a.isos == Path("/i") and a.autoboot == "/a.iso" and a.out == tmp_path / "x.img"


# -- bb-dev vm: what happens before booting ------------------------------------

class World:
    """A fake image state plus records of update / rebuild / make build."""

    def __init__(self, tmp_path: Path, monkeypatch):
        self.img = tmp_path / "dev.img"
        self.img.write_bytes(b"img")
        self.state = State(LV, "b1")
        self.dist = "b1"
        self.dist_st = menufiles.DistState(True, 0.0)
        self.calls: list[str] = []
        self.answer = False
        self.mp = monkeypatch
        monkeypatch.setattr(freshness, "read_state", lambda img, info=None: self.state)
        monkeypatch.setattr(freshness, "dist_build_id", lambda dist=None: self.dist)
        monkeypatch.setattr(menufiles, "dist_state", lambda dist=None: self.dist_st)
        monkeypatch.setattr(diskimg, "running_vm", lambda img: None)
        monkeypatch.setattr(diskimg, "attachments", lambda img: [])

        def update(img, env):
            self.calls.append(f"update {Path(img).name}")
            self.state = State(LV, self.dist)
            return freshness.check(img)

        def rebuild(out, recipe):
            self.calls.append(f"rebuild {Path(out).name} " + " ".join(freshness.recipe_argv(
                recipe["options"] if recipe else None, Path(out).name)))
            self.state = State(LV, self.dist)
            return 0

        monkeypatch.setattr(freshness, "run_update", update)
        monkeypatch.setattr(image, "rebuild", rebuild)
        monkeypatch.setattr(image, "make_build", lambda env: self.calls.append("make build"))
        monkeypatch.setattr(vm, "confirm", lambda q: self.calls.append("asked") or self.answer)

    def freshen(self, *argv: str) -> vm.Plan:
        args = cli.build_parser().parse_args(["vm", "--image", str(self.img), *argv])
        h = vm.Host("/q/qemu", True, False, "", qemu.Firmware(Path("/fw/ovmf"), Path("/fw/seabios")), [])
        plan = vm.build_plan(args, h)
        vm.freshen(args, plan, {})
        return plan


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


def test_vm_current_image_is_booted_as_is(world, capsys):
    plan = world.freshen()
    assert world.calls == []
    assert any("boot files current" in n for n in plan.notes)
    assert capsys.readouterr().err == ""


def test_vm_build_id_mismatch_updates(world, capsys):
    world.state = State(LV, "b0")
    plan = world.freshen()
    assert world.calls == ["update dev.img"]
    err = capsys.readouterr().err
    assert "installed from build b0, dist/ is build b1" in err and "bin/beast-boot update --image" in err
    assert "ISOs and config.cfg" in err and any("updated" in n for n in plan.notes)


def test_vm_old_layout_is_rebuilt_from_its_recipe_after_asking(world, capsys):
    world.state = State(1, "b1")
    freshness.write_recipe(world.img, {"size": "2G", "fs": "fat32", "fs_auto": False, "fixtures": False,
                                       "debug": True}, build_id="b0", layout_version=1)
    world.freshen()                      # asked, said no -> booted as is
    assert world.calls == ["asked"]
    assert "not rebuilt" in capsys.readouterr().err
    world.calls.clear()
    world.answer = True
    world.freshen()
    assert world.calls == ["asked", "rebuild dev.img --out dev.img --size 2G --layout msdos --fs fat32 "
                                    "--debug --force"]
    assert "from its recipe" in capsys.readouterr().err
    world.calls.clear()
    world.state = State(1, "b1")
    world.freshen("--yes")               # --yes: no question
    assert world.calls[0].startswith("rebuild dev.img")


def test_vm_old_layout_without_recipe_uses_the_setup_defaults(world, capsys):
    world.state = State(1, "b0")
    world.freshen("--yes")
    assert world.calls == ["rebuild dev.img --out dev.img --size 4G --layout msdos --fixtures --debug --force"]
    assert "bb-dev setup` defaults (--fixtures --debug), as it has no recipe" in capsys.readouterr().err


@pytest.mark.parametrize("state", [State(LV, "b0"), State(1, "b0")])
def test_vm_snapshot_never_changes_the_image(world, capsys, state):
    world.state = state
    world.freshen("--snapshot", "--yes")
    assert world.calls == []
    err = capsys.readouterr().err
    assert "outdated boot files" in err and "--snapshot leaves the image unchanged" in err


def test_vm_refresh_never_and_always(world, capsys):
    world.state = State(LV, "b0")
    world.freshen("--refresh", "never")
    assert world.calls == [] and "--refresh never" in capsys.readouterr().err
    world.state = State(LV, "b1")
    world.freshen("--refresh", "always")
    assert world.calls == ["update dev.img"]


def test_vm_stale_dist_warns_and_builds_only_with_build(world, capsys):
    world.dist_st = menufiles.DistState(True, 0.0, ["grub/beast/main.cfg"], ["build/build.sh"])
    world.freshen()
    err = capsys.readouterr().err
    assert "dist/ is older than its sources" in err and "make build" in err and "grub/beast/main.cfg" in err
    assert "make build" not in world.calls
    world.freshen("--build")
    assert world.calls == ["make build"]
    world.calls.clear()
    world.dist_st = menufiles.DistState(False)
    world.dist = None
    world.freshen()
    assert world.calls == [] and "dist/ is not built" in capsys.readouterr().err


def test_vm_refuses_to_refresh_an_attached_or_busy_image(world, monkeypatch):
    world.state = State(LV, "b0")
    monkeypatch.setattr(freshness, "run_update", ORIG_RUN_UPDATE)   # the real one: it checks first
    att = diskimg.Attachment("/dev/loop7", False, True, "/media/x")
    monkeypatch.setattr(diskimg, "attachments", lambda img: [att])
    with pytest.raises(Failure, match="attached on this host") as e:
        world.freshen()
    assert "udisksctl unmount -b /dev/loop7" in e.value.hint and "--snapshot" in e.value.hint
    monkeypatch.setattr(diskimg, "attachments", lambda img: [])
    monkeypatch.setattr(diskimg, "running_vm", lambda img: 4242)
    with pytest.raises(Failure, match="pid 4242"):
        world.freshen()
    # an outdated layout: refused before the rebuild, after the question
    world.state = State(1, "b0")
    with pytest.raises(Failure, match="pid 4242"):
        world.freshen("--yes")
    assert not any(c.startswith("rebuild") for c in world.calls)


ORIG_RUN_UPDATE = freshness.run_update


def test_run_update_runs_the_installer_and_refreshes_the_recipe(tmp_path, monkeypatch):
    import subprocess
    img = tmp_path / "dev.img"
    img.write_bytes(b"img")
    state = {"now": State(LV, "b0")}
    monkeypatch.setattr(freshness, "read_state", lambda i, info=None: state["now"])
    monkeypatch.setattr(freshness, "dist_build_id", lambda dist=None: "b1")
    monkeypatch.setattr(diskimg, "running_vm", lambda i: None)
    monkeypatch.setattr(diskimg, "attachments", lambda i: [])
    freshness.write_recipe(img, {"debug": True, "fixtures": False}, build_id="b0", layout_version=LV)
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        state["now"] = State(LV, "b1")
        return subprocess.CompletedProcess(cmd, 0, "updated\n", "")
    monkeypatch.setattr(freshness.subprocess, "run", fake_run)
    after = freshness.run_update(img, {})
    assert seen[0][0].endswith("bin/beast-boot") and seen[0][1:4] == ["update", "--image", str(img)]
    assert "--yes" in seen[0]
    assert after.action == freshness.CURRENT
    r = freshness.read_recipe(img)
    assert r["dist_build_id"] == "b1" and r["options"]["debug"] is True and r["options"]["fixtures"] is False
    assert (tmp_path / "dev.update.log").read_text().startswith("$ ")

    def failing(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 3, "", "layout-unsupported")
    monkeypatch.setattr(freshness.subprocess, "run", failing)
    with pytest.raises(Failure, match="update` failed"):
        freshness.run_update(img, {})


# -- bb-dev image on an existing image -----------------------------------------

def test_image_on_an_existing_image_offers_a_refresh(world, monkeypatch, capsys):
    monkeypatch.setattr(image, "check_dist", lambda env: None)
    out = world.img
    # current: nothing to do, exit 0
    assert cli.main(["image", "--out", str(out)]) == 0
    assert "is current" in capsys.readouterr().out and out.read_bytes() == b"img"
    # other build: no terminal, no --yes -> refused with what to do
    world.state = State(LV, "b0")
    assert cli.main(["image", "--out", str(out)]) == 1
    assert "--yes refreshes" in capsys.readouterr().err and world.calls == []
    assert cli.main(["image", "--out", str(out), "--yes"]) == 0
    assert world.calls == ["update dev.img"] and "updated" in capsys.readouterr().out
    # older layout: --yes rebuilds (falls through to a normal build, here stopped early)
    world.state = State(1, "b1")
    monkeypatch.setattr(image, "fixture_files", lambda env: (_ for _ in ()).throw(Failure("stop here")))
    assert cli.main(["image", "--out", str(out)]) == 1
    assert "--force (or --yes)" in capsys.readouterr().err
    assert cli.main(["image", "--out", str(out), "--fixtures", "--yes"]) == 1
    assert "stop here" in capsys.readouterr().err


# -- menu-sync -----------------------------------------------------------------

@pytest.mark.parametrize("state, text, fix", [
    (State(LV, "b0"), "older boot files than dist/", "bin/beast-boot update --image"),
    (State(1, "b1"), "must be rebuilt", "--fixtures --debug --force"),
])
def test_menu_sync_refuses_outdated_boot_files(world, monkeypatch, capsys, state, text, fix):
    world.state = state
    info = diskimg.ImageInfo(world.img, "msdos", "0.1.0", "fat32", 0, 1, 0, 1, {})
    monkeypatch.setattr(diskimg, "image_info", lambda img: info)
    monkeypatch.setattr(menu_sync, "sync", lambda *a: pytest.fail("synced an outdated image"))
    assert cli.main(["menu-sync", "--image", str(world.img)]) == 1
    err = capsys.readouterr().err
    assert text in err and fix in err and "outdated bootloader" in err


# -- doctor --------------------------------------------------------------------

def test_doctor_reports_the_dev_image(world, monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "dist").mkdir(parents=True)
    (repo / "dist" / "manifest.json").write_text('{"build_id": "b1"}')
    ctx = doctor.Ctx({}, repo=repo)
    r = doctor.check_dev_image(ctx)
    assert r.status == doctor.WARN and "not built yet" in r.detail and "bb-dev image" in r.fix
    img = repo / "out" / "dev" / paths.DEFAULT_IMAGE.name
    img.parent.mkdir(parents=True)
    img.write_bytes(b"img")
    r = doctor.check_dev_image(ctx)
    assert r.status == doctor.OK and "current" in r.detail
    world.state = State(LV, "b0")
    r = doctor.check_dev_image(ctx)
    assert r.status == doctor.WARN and "build b0" in r.detail and "bb-dev vm" in r.fix
    world.state = State(1, "b1")
    r = doctor.check_dev_image(ctx)
    assert r.status == doctor.WARN and "layout 1" in r.detail and "--yes" in r.fix
