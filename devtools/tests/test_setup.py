"""bb-dev setup: the step flow (which steps run, idempotence, --minimal,
--no-image, failures), the pinned pip bootstrap and requirements-dev.txt.
Nothing is downloaded or built: doctor, commands and files are faked."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from beastbooter import layout  # noqa: E402

from bbdev import diskimg, freshness, paths
from bbdev.commands import doctor, setup
from bbdev.msg import Failure

REQ = ROOT / "requirements-dev.txt"
# build.sh sets every mtime in dist/, manifest.json included, to SOURCE_DATE_EPOCH
# (the last commit): always in the past. Only the ctime is the build time.
SOURCE_DATE_EPOCH = time.time() - 30 * 86400


def write_manifest(dist: Path, build_id: str = "b-new") -> Path:
    man = dist / "manifest.json"
    man.write_text(json.dumps({"schema": 1, "build_id": build_id}))
    os.utime(man, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    return man


# -- requirements-dev.txt and the pip pin -----------------------------------

def parse_requirements(text: str) -> dict[str, tuple[str, str, list[str]]]:
    out = {}
    joined = re.sub(r"\\\n", " ", text)
    for line in joined.splitlines():
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("--") else line
        if not line:
            continue
        m = re.match(r"([A-Za-z0-9_.-]+)==(\S+)\s*(?:;\s*([^-]+?))?\s*((?:--hash=sha256:[0-9a-f]{64}\s*)+)$", line)
        assert m, f"not pinned with hashes: {line}"
        out[m.group(1).lower()] = (m.group(2), (m.group(3) or "").strip(), re.findall(r"[0-9a-f]{64}", m.group(4)))
    return out


def test_requirements_pinned_and_hashed():
    reqs = parse_requirements(REQ.read_text())
    for p in ("pytest", "coverage", "debugpy", "ruff", "pip"):
        assert p in reqs
    for name, (ver, _marker, hashes) in reqs.items():
        assert re.fullmatch(r"[0-9][0-9A-Za-z.]*", ver), (name, ver)
        assert hashes, name
    # pytest's dependencies are pinned too (pip --require-hashes needs every one)
    for dep in ("iniconfig", "packaging", "pluggy", "pygments", "exceptiongroup", "tomli"):
        assert dep in reqs


def test_pip_wheel_pin_matches_requirements():
    ver, _m, hashes = parse_requirements(REQ.read_text())["pip"]
    assert setup.PIP_WHEEL == f"pip-{ver}-py3-none-any.whl"
    assert setup.PIP_WHEEL_SHA256 in hashes
    assert setup.PIP_WHEEL_URL.startswith("https://files.pythonhosted.org/") and setup.PIP_WHEEL_URL.endswith(setup.PIP_WHEEL)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_pip_wheel_checks_sha256(tmp_path, monkeypatch):
    payload = b"definitely a wheel"
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda url, timeout=0: FakeResponse(payload))
    with pytest.raises(Failure) as e:
        setup.fetch_pip_wheel(tmp_path)
    assert "refusing" in str(e.value)
    assert not list(tmp_path.glob("*.whl")) and not list(tmp_path.glob("*.part"))
    monkeypatch.setattr(setup, "PIP_WHEEL_SHA256", hashlib.sha256(payload).hexdigest())
    w = setup.fetch_pip_wheel(tmp_path)
    assert w.read_bytes() == payload
    # cached: no second download
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    assert setup.fetch_pip_wheel(tmp_path) == w


def test_venv_current(tmp_path, monkeypatch):
    venv = tmp_path / ".venv"
    req = tmp_path / "requirements-dev.txt"
    req.write_text("pytest==1 --hash=sha256:" + "a" * 64 + "\n")
    monkeypatch.setattr(setup, "VENV", venv)
    monkeypatch.setattr(setup, "VENV_STAMP", venv / ".bb-requirements.sha256")
    monkeypatch.setattr(setup, "REQUIREMENTS", req)
    assert not setup.venv_current()
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("")
    assert not setup.venv_current()
    setup.VENV_STAMP.write_text(setup.file_sha256(req) + "\n")
    assert setup.venv_current()
    req.write_text("pytest==2 --hash=sha256:" + "b" * 64 + "\n")
    assert not setup.venv_current()


def test_dev_setup_script_is_a_thin_wrapper():
    p = ROOT / "scripts" / "dev-setup.sh"
    assert p.stat().st_mode & stat.S_IXUSR
    text = p.read_text()
    assert 'bin/bb-dev" setup "$@"' in text and text.startswith("#!/usr/bin/env bash")


# -- the flow ---------------------------------------------------------------

def ok_results(**override):
    names = {"python": doctor.SYSTEM, "qemu": doctor.TOOLS, "mtools": doctor.TOOLS, "kvm": doctor.SYSTEM,
             "venv": doctor.VENV, "keys": doctor.KEYS, "dist": doctor.BUILD}
    out = []
    for n, action in names.items():
        status = override.get(n, doctor.OK)
        out.append(doctor.Check(n, status, f"{n} detail", "" if status == doctor.OK else f"fix {n}", action))
    return out


class World:
    """Fake repo state + recorded commands."""

    def __init__(self, tmp: Path, monkeypatch):
        self.tmp = tmp
        self.cmds: list[str] = []
        self.rc: dict[str, int] = {}
        self.results = ok_results()
        self.dist_ok = True
        self.venv_ok = True
        keys = tmp / "keys"
        keys.mkdir()
        for n in ("beast-boot.key", "beast-boot.crt", "beast-boot.cer"):
            (keys / n).write_text("x")
        self.keys = keys
        (tmp / "dist").mkdir()
        self.manifest = write_manifest(tmp / "dist", "b-new")
        self.image = tmp / "out" / "dev" / "beast-boot-dev.img"
        # what the image says: version.cfg's build id and the marker's layout (None: unreadable)
        self.image_build_id: str | None = "b-new"
        self.image_layout: int | None = layout.LAYOUT_VERSION
        self.image_error = ""
        monkeypatch.setattr(freshness, "read_state", lambda img, info=None: freshness.ImageState(
            self.image_layout, self.image_build_id, self.image_error))
        monkeypatch.setattr(paths, "KEYS", keys)
        monkeypatch.setattr(paths, "DIST", tmp / "dist")
        monkeypatch.setattr(paths, "DEFAULT_IMAGE", self.image)
        monkeypatch.setattr(setup, "TEST_STAMP", tmp / "out" / "dev" / ".setup-tests.ok")
        monkeypatch.setattr(setup, "VENV", tmp / ".venv")
        monkeypatch.setattr(setup, "env_now", lambda: {"PATH": "/x"})
        monkeypatch.setattr(setup, "test_fingerprint", lambda: "fp1")
        monkeypatch.setattr(setup.doctor, "collect", lambda: self.results)
        monkeypatch.setattr(setup.doctor, "check_dist", lambda ctx: doctor.Check(
            "dist", doctor.OK if self.dist_ok else doctor.WARN, "dist detail", "make build", doctor.BUILD))
        monkeypatch.setattr(setup, "venv_current", lambda: self.venv_ok)
        monkeypatch.setattr(setup, "make_venv", lambda s, env: self.cmds.append("make_venv") or "pytest 9")

        self.envs: dict[str, dict] = {}   # command line -> the env it ran with

        def sh(s_self, cmd, env, **kw):
            line = " ".join(os.path.basename(str(c)) if i == 0 or "/" in str(c) and i < 2 else str(c)
                            for i, c in enumerate(cmd))
            self.cmds.append(line)
            self.envs[line] = env
            for k, v in self.rc.items():
                if k in line:
                    return v
            if "bb-dev image" in line:
                self.image.parent.mkdir(parents=True, exist_ok=True)
                self.image.write_text("img")
            return 0
        monkeypatch.setattr(setup.Setup, "sh", sh)

    def run(self, **kw) -> tuple[int, str]:
        args = argparse.Namespace(minimal=False, no_venv=False, no_image=False, yes=True)
        for k, v in kw.items():
            setattr(args, k, v)
        out = io.StringIO()
        orig = setup.Setup.__init__

        def init(s, a, out_=None):
            orig(s, a, out)
        setup.Setup.__init__ = init
        try:
            rc = setup.run(args)
        finally:
            setup.Setup.__init__ = orig
        return rc, out.getvalue()


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


def test_fresh_then_noop(world):
    world.results = ok_results(qemu=doctor.FAIL, venv=doctor.WARN)
    world.venv_ok = False
    world.dist_ok = False
    (world.keys / "beast-boot.key").unlink()
    rc, out = world.run()
    assert rc == 0, out
    assert world.cmds == ["bash bootstrap-tools.sh", "make_venv", "make keys", "make build",
                          "pytest -q -p no:cacheprovider installer/tests",   # no .venv/bin/python in the fake
                          "bb-dev image --fixtures --debug"]
    assert "checklist" in out and "next steps" in out
    # second run: everything is there -> nothing runs
    world.cmds.clear()
    world.results = ok_results()
    world.venv_ok = True
    world.dist_ok = True
    (world.keys / "beast-boot.key").write_text("x")
    rc, out = world.run()
    assert rc == 0 and world.cmds == [], world.cmds
    assert "nothing changed" in out and "exists" in out


def test_minimal_and_no_image(world):
    rc, out = world.run(minimal=True)
    assert rc == 0 and world.cmds == []
    assert "[5/5]" in out and "installer unit tests" not in out and "] dev image" not in out
    assert "bin/bb-dev image --fixtures --debug   build the dev image first" in out
    rc, out = world.run(no_image=True)
    assert rc == 0
    assert not any("bb-dev image" in c for c in world.cmds)
    line = image_line(out)
    assert line.lstrip().startswith("[-]") and "skipped: --no-image" in line, line
    assert "bin/bb-dev image --fixtures --debug   build the dev image first" in out


def test_no_venv(world):
    world.venv_ok = False
    rc, out = world.run(no_venv=True, minimal=True)
    assert rc == 0 and "make_venv" not in world.cmds and "[4/4]" in out


def test_tests_rerun_when_something_changed(world):
    setup.TEST_STAMP.parent.mkdir(parents=True, exist_ok=True)
    setup.TEST_STAMP.write_text("fp1\n")
    world.dist_ok = False
    rc, _ = world.run()
    assert rc == 0 and any("pytest" in c for c in world.cmds)


def test_bootstrap_debug_symbols_only_failure_is_a_warning(world):
    world.results = ok_results(mtools=doctor.FAIL)
    world.rc["bootstrap-tools.sh"] = 3
    rc, out = world.run()
    assert rc == 0 and "GRUB debug symbols failed" in out


def test_bootstrap_runs_in_the_users_environment(world, monkeypatch):
    """Not env_now(): that was resolved before .tools/root existed, so its
    BB_GRUB_BIOS_DIR is the (empty) system dir and bootstrap would skip
    grub-pc-dbg. bootstrap sources dev-env.sh itself; the user's own dirs win."""
    stale = {"PATH": "/x", "BB_GRUB_BIOS_DIR": "/usr/lib/grub/i386-pc",
             "BB_GRUB_PC_DBG_DIR": "/repo/.tools/grub-dbg/usr/lib/grub/i386-pc"}
    monkeypatch.setattr(setup, "env_now", lambda: dict(stale))
    monkeypatch.delenv("BB_GRUB_BIOS_DIR", raising=False)
    monkeypatch.delenv("BB_GRUB_PC_DBG_DIR", raising=False)
    monkeypatch.setenv("BB_GRUB_EFI_DIR", "/opt/my-grub-efi")
    world.results = ok_results(qemu=doctor.FAIL)
    world.dist_ok = False
    rc, out = world.run(minimal=True)
    assert rc == 0, out
    env = world.envs["bash bootstrap-tools.sh"]
    assert "BB_GRUB_BIOS_DIR" not in env and "BB_GRUB_PC_DBG_DIR" not in env
    assert env["BB_GRUB_EFI_DIR"] == "/opt/my-grub-efi"
    assert env["PATH"] == os.environ["PATH"]
    # the later steps use the environment resolved after bootstrap
    assert world.envs["make build"] == stale


def test_failure_stops_and_still_prints_checklist(world, capsys):
    world.dist_ok = False
    world.rc["make build"] = 2
    rc, out = world.run()
    assert rc == 1
    assert "checklist" in out and "FAILED" in out
    assert "make build failed" in capsys.readouterr().err
    assert not any("pytest" in c or "bb-dev image" in c for c in world.cmds)


def test_system_problems_are_explained(world):
    world.results = ok_results(kvm=doctor.WARN)
    rc, out = world.run()
    assert rc == 0 and "not fetchable without root" in out and "fix kvm" in out


def test_old_python_fails_early(world):
    world.results = ok_results(python=doctor.FAIL)
    rc, _ = world.run()
    assert rc == 1 and world.cmds == []


def image_line(out: str) -> str:
    """The dev-image line of the final checklist."""
    return next(ln for ln in out.splitlines() if "] dev image" in ln and not ln.startswith("==>"))


def test_stale_image_is_flagged_and_left_alone(world):
    """The old check trusted an image whose build id matched dist/ even when it
    had an older layout, and an unreadable one by its file time (which every
    VM boot updates): both came out as `[x] ok`."""
    world.image.parent.mkdir(parents=True)
    world.image.write_text("old")
    os.utime(world.image)   # newer than the manifest: says nothing any more
    # nothing readable on the image -> flagged, not trusted by its time
    world.image_layout, world.image_build_id, world.image_error = None, None, "cannot read it: not an image"
    rc, out = world.run()
    assert rc == 0 and image_line(out).lstrip().startswith("[!]"), out
    assert "cannot tell whether it is current" in out and "--force" in out
    assert not any("bb-dev image" in c for c in world.cmds)
    # another build -> stale
    world.image_layout, world.image_build_id, world.image_error = layout.LAYOUT_VERSION, "b-old", ""
    rc, out = world.run()
    assert rc == 0 and image_line(out).lstrip().startswith("[!]")
    assert "installed from build b-old, dist/ is build b-new" in out and "bb-dev vm" in out
    # the same build but an older layout (64 MiB FAT16 ESP) -> stale, needs a rebuild
    world.image_layout, world.image_build_id = 1, "b-new"
    rc, out = world.run()
    assert rc == 0 and image_line(out).lstrip().startswith("[!]"), out
    assert "it has layout 1, the installer writes layout 2" in out
    assert "bin/bb-dev image --out" in out and "--fixtures --debug --force" in out
    # current layout and build id -> current
    world.image_layout = layout.LAYOUT_VERSION
    rc, out = world.run()
    assert rc == 0 and image_line(out).lstrip().startswith("[x]") and "current" in out
    assert not any("bb-dev image" in c for c in world.cmds)


def test_image_stale_without_dist(tmp_path, monkeypatch):
    img = tmp_path / "x.img"
    img.write_text("img")
    monkeypatch.setattr(setup, "image_build_id", lambda p: "b1")
    assert setup.image_stale(img, tmp_path / "nodist") is None


class FakeEsp:
    def __init__(self, data):
        self.data = data

    def read(self, path):
        assert path == "/grub/beast/version.cfg"
        return self.data


class FakeInfo:
    raw = {"layout_version": 2}

    def __init__(self, data):
        self.data = data

    def esp(self):
        return FakeEsp(self.data)


@pytest.mark.parametrize("data, want", [
    (b'# Generated by build/build.sh - do not edit.\nset bb_version="0.1.0"\nset bb_build_id="c3176a2b65f7"\n',
     "c3176a2b65f7"),
    (b'set bb_version="0.1.0"\n', None),
    (None, None),
])
def test_image_build_id(tmp_path, monkeypatch, data, want):
    monkeypatch.setattr(diskimg, "image_info", lambda img: FakeInfo(data))
    assert setup.image_build_id(tmp_path / "x.img") == want


def test_image_build_id_unreadable_image(tmp_path, monkeypatch):
    def boom(img):
        raise Failure("not a beast-boot image")
    monkeypatch.setattr(diskimg, "image_info", boom)
    assert setup.image_build_id(tmp_path / "x.img") is None


def test_needs_yes_without_terminal(world, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    rc, _ = world.run(yes=False)
    assert rc == 1 and world.cmds == []


def test_fingerprint_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "REPO", tmp_path)
    monkeypatch.setattr(paths, "DIST", tmp_path / "dist")
    (tmp_path / "installer").mkdir()
    f = tmp_path / "installer" / "a.py"
    f.write_text("1")
    a = setup.test_fingerprint()
    assert setup.test_fingerprint() == a
    f.write_text("22")
    b = setup.test_fingerprint()
    assert b != a
    # caches that pytest/ruff/pip write next to the code do not count
    for junk in ("installer/.pytest_cache/v/cache/nodeids", "installer/.ruff_cache/x",
                 "installer/__pycache__/a.cpython-314.pyc", "installer/beastbooter.egg-info/PKG-INFO",
                 "installer/a.py~", "build/.swp"):
        j = tmp_path / junk
        j.parent.mkdir(parents=True, exist_ok=True)
        j.write_text(junk)
    assert setup.test_fingerprint() == b
    (tmp_path / "installer" / "tests").mkdir()
    (tmp_path / "installer" / "tests" / "data.bin").write_text("fixture")
    assert setup.test_fingerprint() != b
