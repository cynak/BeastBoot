"""bb-dev debug-config: the config.cfg model, --print, and round trips on a
FAT32 partition (mtools) and, when udisks works, an exFAT image. No QEMU."""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev import cli, diskimg, paths, userconfig  # noqa: E402
from bbdev.msg import Failure  # noqa: E402
from bbdev.userconfig import UserConfig  # noqa: E402

GRUB_SCRIPT_CHECK = shutil.which("grub-script-check", path=diskimg.tool_env().get("PATH"))


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def test_parse_settings_and_quoting():
    cfg = UserConfig('set a=1\nset b="x y \\"q\\" \\$v"\nset c=\'lit $x\'\nset a=2 # later wins\n')
    assert cfg.settings() == {"b": 'x y "q" $v', "c": "lit $x", "a": "2"}


def test_set_replaces_in_place_and_keeps_other_lines():
    text = "# mine\nset timeout=3\nexport timeout bb_debug\nmenuentry x { true }\nset timeout=4\n"
    cfg = UserConfig(text)
    cfg.set("timeout", "10")
    assert cfg.lines == ["# mine", 'set timeout="10"', "export timeout", "export bb_debug",
                         "menuentry x { true }"]
    cfg.set("bb_debug", "on")
    assert cfg.lines[-2:] == ['set bb_debug="1"', "export bb_debug"]
    assert cfg.lines.count("export bb_debug") == 1


def test_unset_and_clear():
    cfg = UserConfig(userconfig.render(debug=True, dryrun=True))
    assert cfg.unset("bb_dryrun")
    assert not cfg.unset("bb_dryrun")
    assert cfg.settings() == {"bb_debug": "1"}
    cfg.unset("bb_debug")
    assert cfg.is_empty()
    cfg.clear()
    assert cfg.text == ""


def test_new_file_gets_a_header_and_exports():
    text = userconfig.render(debug=True, autoboot="linux/x.iso")
    assert text.splitlines() == [userconfig.HEADER, 'set bb_debug="1"', "export bb_debug",
                                 'set bb_autoboot="/linux/x.iso"', "export bb_autoboot"]
    assert userconfig.render() == ""


@pytest.mark.parametrize("key,value,expect", [
    ("bb_debug", "yes", "1"), ("bb_serial", "0", "0"), ("pager", "off", "0"),
    ("timeout", " 5 ", "5"), ("timeout", "-1", "-1"),
    ("bb_autoboot", "a b.iso", "/a b.iso"), ("debug", "linux,loader", "linux,loader"),
    ("default", "2", "2"),
])
def test_normalise(key, value, expect):
    assert userconfig.normalise(key, value) == expect


@pytest.mark.parametrize("key,value", [("bb_debug", "2"), ("timeout", "soon"), ("bb_autoboot", ""),
                                       ("1bad", "x"), ("debug", "a\nb")])
def test_normalise_rejects(key, value):
    with pytest.raises(Failure):
        userconfig.normalise(key, value)


def test_parse_assignment():
    assert userconfig.parse_assignment("debug=all") == ("debug", "all")
    with pytest.raises(Failure):
        userconfig.parse_assignment("bb_debug")


# ---------------------------------------------------------------------------
# --print (real USB sticks)
# ---------------------------------------------------------------------------

def test_print_outputs_a_config_and_writes_nothing(capsys, monkeypatch):
    monkeypatch.setattr(diskimg, "image_info", lambda image: pytest.fail("--print must not open an image"))
    rc = cli.main(["debug-config", "--set", "bb_debug=1", "bb_serial=1", "timeout=5", "debug=linux",
                   "bb_autoboot=/My ISOs/x.iso", "--print"])
    out, err = capsys.readouterr()
    assert rc == 0
    assert UserConfig(out).settings() == {"bb_debug": "1", "bb_serial": "1", "timeout": "5", "debug": "linux",
                                          "bb_autoboot": "/My ISOs/x.iso"}
    assert "/beast-booter/config.cfg" in err


@pytest.mark.skipif(not GRUB_SCRIPT_CHECK, reason="grub-script-check not installed")
def test_printed_config_is_valid_grub_script(capsys, tmp_path):
    cli.main(["debug-config", "--set", "bb_debug=1", "bb_dryrun=1", "pager=1", 'bb_autoboot=/a "b" $c.iso',
              "--print"])
    out = capsys.readouterr().out
    f = tmp_path / "config.cfg"
    f.write_text(out)
    p = subprocess.run([GRUB_SCRIPT_CHECK, str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert UserConfig(out).get("bb_autoboot") == '/a "b" $c.iso'


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

@pytest.fixture
def fat_image(tmp_path, monkeypatch):
    img = tmp_path / "data.img"
    diskimg.run(["mformat", "-C", "-i", img, "-T", "65536", "-h", "4", "-s", "32", "-F", "::"])
    info = diskimg.ImageInfo(img, "msdos", "0.1.0", "fat32", 0, 65536, 0, 65536, {})
    monkeypatch.setattr(diskimg, "image_info", lambda image: info)
    return info


def test_fat32_round_trip(fat_image, capsys):
    img = str(fat_image.path)
    assert cli.main(["debug-config", "--image", img, "--set", "bb_debug=1", "timeout=5", "--show"]) == 0
    out = capsys.readouterr().out
    assert "wrote /beast-booter/config.cfg" in out and "bb_debug = 1" in out and "--- file ---" in out
    stored = fat_image.data_fat().read(diskimg.USER_CONFIG).decode()
    assert UserConfig(stored).settings() == {"bb_debug": "1", "timeout": "5"}
    # a hand-written line survives an edit
    fat_image.data_fat().put_bytes(diskimg.USER_CONFIG, (stored + "set default=2\n").encode())
    assert cli.main(["debug-config", "--image", img, "--unset", "timeout", "--set", "bb_dryrun=1"]) == 0
    stored = fat_image.data_fat().read(diskimg.USER_CONFIG).decode()
    assert UserConfig(stored).settings() == {"bb_debug": "1", "default": "2", "bb_dryrun": "1"}
    capsys.readouterr()
    assert cli.main(["debug-config", "--image", img]) == 0  # default: show
    assert "bb_dryrun = 1" in capsys.readouterr().out
    assert cli.main(["debug-config", "--image", img, "--clear"]) == 0
    assert fat_image.data_fat().read(diskimg.USER_CONFIG) is None
    assert "removed" in capsys.readouterr().out
    assert cli.main(["debug-config", "--image", img, "--show"]) == 0
    assert "no config.cfg" in capsys.readouterr().out


def test_invalid_value_leaves_the_file_alone(fat_image, capsys):
    img = str(fat_image.path)
    cli.main(["debug-config", "--image", img, "--set", "bb_debug=1"])
    before = fat_image.data_fat().read(diskimg.USER_CONFIG)
    assert cli.main(["debug-config", "--image", img, "--set", "bb_debug=maybe"]) == 1
    assert fat_image.data_fat().read(diskimg.USER_CONFIG) == before
    assert "must be 0 or 1" in capsys.readouterr().err


def test_unknown_keys_warn(fat_image, capsys):
    assert cli.main(["debug-config", "--image", str(fat_image.path), "--set", "gfxmode=1024x768"]) == 0
    assert "not a beast-booter setting" in capsys.readouterr().err


def test_missing_image(tmp_path, capsys, monkeypatch):
    assert cli.main(["debug-config", "--image", str(tmp_path / "none.img"), "--show"]) == 1
    assert "image not found" in capsys.readouterr().err


@pytest.mark.skipif(not (paths.DIST / "manifest.json").is_file(), reason="dist/ not built")
def test_exfat_round_trip(tmp_path, capsys):
    ok, reason = diskimg.udisks_status()
    if not ok:
        pytest.skip(reason)
    img = tmp_path / "ex.img"
    assert cli.main(["image", "--out", str(img), "--size", "1G", "--fs", "exfat"]) == 0
    assert cli.main(["debug-config", "--image", str(img), "--set", "bb_debug=1", "bb_serial=1", "--show"]) == 0
    capsys.readouterr()
    assert cli.main(["debug-config", "--image", str(img), "--show"]) == 0  # a fresh mount
    out = capsys.readouterr().out
    assert "bb_debug  = 1" in out and "bb_serial = 1" in out and "exfat" in out


# ---------------------------------------------------------------------------
# udisks cleanup (exFAT/NTFS): simulated loop devices, automounter and sysfs
# ---------------------------------------------------------------------------

class FakeLoops:
    """udisksctl, findmnt and /sys/block for loop devices, in memory.

    remount: how often an "automounter" mounts the device again right after
    an unmount. busy: unmounts fail (a file manager holds the mount). Like the
    kernel, loop-delete on a mounted device only sets autoclear, and an
    autoclear device detaches itself on its last unmount."""

    def __init__(self, tmp_path: Path, remount: int = 0, busy: bool = False):
        self.sys = tmp_path / "sys"
        self.mnt = tmp_path / "mnt"
        self.mnt.mkdir()
        self.mounts: dict[str, str] = {}
        self.calls: list[str] = []
        self.remount, self.busy = remount, busy

    def attach(self, dev: str, image: Path, ro: bool = False) -> None:
        d = self.sys / Path(dev).name / "loop"
        d.mkdir(parents=True)
        (d / "backing_file").write_text(f"{image}\n")
        (d / "autoclear").write_text("0\n")
        (d.parent / "ro").write_text("1\n" if ro else "0\n")

    def attached(self, dev: str) -> bool:
        return (self.sys / Path(dev).name / "loop").exists()

    def udisksctl(self, *args, check=True, timeout=60):
        cmd = args[0]
        dev = args[args.index("-b") + 1] if "-b" in args else None
        self.calls.append(cmd)
        ok = lambda out="": subprocess.CompletedProcess(args, 0, out, "")  # noqa: E731
        if cmd == "loop-setup":
            image = args[args.index("-f") + 1]
            self.attach("/dev/loop9", image, "-r" in args)
            return ok(f"Mapped file {image} as /dev/loop9.\n")
        if cmd == "mount":
            self.mounts[dev] = str(self.mnt)
            return ok(f"Mounted {dev} at {self.mnt}\n")
        if cmd == "unmount":
            if self.busy:
                return subprocess.CompletedProcess(args, 1, "", "target is busy")
            self.mounts.pop(dev, None)
            loop = self.sys / Path(dev).name / "loop"
            if (loop / "autoclear").read_text().strip() == "1":
                shutil.rmtree(loop)
            elif self.remount:
                self.remount -= 1
                self.mounts[dev] = "/run/media/u/BEASTBOOTER"
            return ok(f"Unmounted {dev}.\n")
        if cmd == "loop-delete":
            loop = self.sys / Path(dev).name / "loop"
            if dev in self.mounts:
                (loop / "autoclear").write_text("1\n")  # LOOP_CLR_FD on a busy device: rc 0, still there
            elif loop.exists():
                shutil.rmtree(loop)
            return ok()
        raise AssertionError(cmd)


@pytest.fixture
def loops(tmp_path, monkeypatch):
    def make(**kw):
        fake = FakeLoops(tmp_path, **kw)
        monkeypatch.setattr(diskimg, "SYS_BLOCK", fake.sys)
        monkeypatch.setattr(diskimg, "_udisksctl", fake.udisksctl)
        monkeypatch.setattr(diskimg, "_mount_point", lambda dev: fake.mounts.get(dev))
        monkeypatch.setattr(diskimg, "udisks_status", lambda: (True, ""))
        monkeypatch.setattr(diskimg, "automount_inhibited", lambda env=None: contextlib.nullcontext(False))
        return fake
    img = tmp_path / "ex.img"
    img.write_bytes(b"")
    return make, img


def test_udisks_mount_releases_the_loop(loops):
    make, img = loops
    fake = make()
    with diskimg.udisks_mount(img, 0, 100) as mp:
        assert mp == fake.mnt
    assert fake.calls == ["loop-setup", "mount", "unmount", "loop-delete"]
    assert not fake.attached("/dev/loop9")


def test_udisks_mount_retries_after_an_automounter_remount(loops):
    # unmount -> automounter mounts it again -> loop-delete only sets autoclear
    # (rc 0) -> the loop must not be left behind: unmount again
    make, img = loops
    fake = make(remount=1)
    with diskimg.udisks_mount(img, 0, 100):
        pass
    assert fake.calls == ["loop-setup", "mount", "unmount", "loop-delete", "unmount"]
    assert not fake.attached("/dev/loop9") and not fake.mounts


def test_udisks_mount_reports_a_loop_it_cannot_release(loops, monkeypatch):
    make, img = loops
    fake = make(busy=True)
    monkeypatch.setattr(diskimg, "RELEASE_TIMEOUT", 0.6)
    with pytest.raises(Failure) as e, diskimg.udisks_mount(img, 0, 100):
        pass
    assert "/dev/loop9" in str(e.value) and "still attached" in str(e.value)
    assert "udisksctl unmount -b /dev/loop9" in e.value.hint  # autoclear is set: unmount alone frees it
    assert fake.calls.count("unmount") >= 2


def test_udisks_mount_keeps_the_original_error(loops, monkeypatch, capsys):
    make, img = loops
    make(busy=True)
    monkeypatch.setattr(diskimg, "RELEASE_TIMEOUT", 0.3)
    with pytest.raises(RuntimeError, match="copy failed"), diskimg.udisks_mount(img, 0, 100):
        raise RuntimeError("copy failed")
    assert "still attached" in capsys.readouterr().err


def test_udisks_mount_refuses_an_image_attached_read_write(loops):
    make, img = loops
    fake = make()
    fake.attach("/dev/loop3", img)
    fake.mounts["/dev/loop3"] = "/run/media/u/BEASTBOOTER"
    fake.attach("/dev/loop4", img.with_name("other.img"))  # another file: none of our business
    with pytest.raises(Failure) as e, diskimg.udisks_mount(img, 0, 100, readonly=True):
        pass
    assert "/dev/loop3 (read-write, mounted at /run/media/u/BEASTBOOTER)" in str(e.value)
    assert "/dev/loop4" not in str(e.value)
    assert "udisksctl unmount -b /dev/loop3 && udisksctl loop-delete -b /dev/loop3" in e.value.hint
    assert fake.calls == []  # nothing set up


def test_udisks_mount_warns_about_read_only_attachments(loops, capsys):
    make, img = loops
    fake = make()
    fake.attach("/dev/loop3", img, ro=True)
    with diskimg.udisks_mount(img, 0, 100):
        pass
    assert "/dev/loop3 (read-only, not mounted)" in capsys.readouterr().err
    assert fake.attached("/dev/loop3")  # not ours: left alone
    assert not fake.attached("/dev/loop9")


def _fake_tool(bin_dir: Path, name: str, body: str) -> None:
    bin_dir.mkdir(exist_ok=True)
    f = bin_dir / name
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(0o755)


def test_automount_inhibitor_is_held_and_ends(tmp_path):
    bin_dir = tmp_path / "bin"
    marker = tmp_path / "inhibited"
    # gnome-session-inhibit [options] COMMAND: hold the inhibition while COMMAND runs
    _fake_tool(bin_dir, "gnome-session-inhibit",
               f'touch {marker}; while [ "${{1#--}}" != "$1" ]; do shift 2; done; "$@"; rm -f {marker}')
    _fake_tool(bin_dir, "gdbus", f'[ -e {marker} ] && echo "(true,)" || echo "(false,)"')
    _fake_tool(bin_dir, "cat", "exec /bin/cat")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent"}
    with diskimg.automount_inhibited(env) as held:
        assert held and marker.exists()
    deadline = time.monotonic() + 3
    while marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not marker.exists()  # the helper ended with the block


def test_automount_inhibitor_is_best_effort(tmp_path):
    bin_dir = tmp_path / "bin"
    with diskimg.automount_inhibited({"PATH": str(tmp_path / "none")}) as held:
        assert held is False  # not installed
    _fake_tool(bin_dir, "gnome-session-inhibit", "exit 1")  # no GNOME session manager
    with diskimg.automount_inhibited({"PATH": str(bin_dir), "DBUS_SESSION_BUS_ADDRESS": "x"}) as held:
        assert held is False
