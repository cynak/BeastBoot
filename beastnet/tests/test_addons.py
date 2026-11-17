"""Add-ons (beastnet/python/beastnet/addons.py): a package in the one fixed directory is
started with (params, ui, ctx, version) and may wrap the UI; a failing one never stops the
helper; nothing is loaded from another place."""

import os
import sys
import textwrap
from types import SimpleNamespace

import pytest

from beastnet import __version__, addons, app, diskflow
from beastnet.cmdline import parse_cmdline
from beastnet.disks.model import CopyKind, CopyProgress
from beastnet.events import Reporter
from beastnet.ui import UI
from test_disks_session import DiskUI, Parts, flow_for, pick
from test_disks_session import ctx as disk_ctx  # noqa: F401 - a fixture
from test_script import make_root

WRAP = """
    from beastnet.ui import UI

    class Wrapped(UI):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner
            self.closed = 0

        def close(self):
            self.closed += 1
            self.inner.close()

    def start(params, ui, ctx, version):
        return Wrapped(ui)
"""


class Local(UI):
    def __init__(self):
        super().__init__()
        self.closed = 0

    def close(self):
        self.closed += 1


@pytest.fixture
def env(tmp_path):
    d = tmp_path / "addons"
    d.mkdir()
    ctx = SimpleNamespace(reporter=Reporter())
    yield SimpleNamespace(dir=d, ctx=ctx, root=str(tmp_path), tmp=tmp_path)
    for name in [m for m in sys.modules if m.startswith("beastnet_addon_")]:
        del sys.modules[name]


def put(directory, name, code, file="__init__.py"):
    pkg = directory / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / file).write_text(textwrap.dedent(code))
    return pkg


def load(env, ui=None, cmdline="", **kw):
    ui = ui or Local()
    got = addons.load_addons(parse_cmdline(cmdline), ui, env.ctx, "9.9", directory=str(env.dir),
                             root=env.root, **kw)
    return ui, got


def lines(env):
    return [x for x in env.ctx.reporter.lines if x.startswith("BEASTNET: addon")]


def test_no_directory_and_empty_directory_change_nothing(env):
    ui = Local()
    assert addons.load_addons(parse_cmdline(""), ui, env.ctx, "9.9", directory=str(env.tmp / "none"),
                              root=env.root) is ui
    assert load(env, ui)[1] is ui
    assert env.ctx.reporter.lines == []
    assert not [m for m in sys.modules if m.startswith("beastnet_addon_")]


def test_an_addon_gets_the_four_arguments_and_may_return_none(env):
    put(env.dir, "toy", """
        seen = []

        def start(params, ui, ctx, version):
            seen.append((params, ui, ctx, version))
    """)
    ui, got = load(env)
    assert got is ui
    (params, ui_, ctx, version), = sys.modules["beastnet_addon_toy"].seen
    assert ui_ is ui and ctx is env.ctx and version == "9.9" and params.extra == {}
    assert lines(env) == ["BEASTNET: addon toy started ui=local"]


def test_an_addon_may_wrap_the_ui_and_addons_chain_in_name_order(env):
    put(env.dir, "b_second", WRAP)
    put(env.dir, "a_first", WRAP)
    ui, got = load(env)
    assert type(got).__name__ == "Wrapped" and got.inner.inner is ui
    assert got.__class__.__module__ == "beastnet_addon_b_second"
    assert lines(env) == ["BEASTNET: addon a_first started ui=wrapped",
                          "BEASTNET: addon b_second started ui=wrapped"]
    addons.close_ui(got, ui, env.ctx)
    assert got.closed == 1 and got.inner.closed == 1 and ui.closed == 1


def test_unknown_parameters_reach_the_addon_and_known_ones_stay(env):
    p = parse_cmdline("beastnet.sb=1 beastnet.toy.url=http://h:1/x beastnet.flag beastnet.debug=1 "
                      "beastnet.toy.url=http://h:2/y other.thing=1")
    assert p.sb and p.debug
    assert p.extra == {"toy.url": "http://h:2/y", "flag": "1"}  # last one wins; a bare one is "1"
    assert p.raw == {"sb": "1", "debug": "1", **p.extra}
    put(env.dir, "toy", """
        def start(params, ui, ctx, version):
            ctx.got = dict(params.extra), params.sb
    """)
    load(env, cmdline="beastnet.sb=1 beastnet.toy.url=http://h:2/y")
    assert env.ctx.got == ({"toy.url": "http://h:2/y"}, True)


def test_unknown_parameters_are_not_logged(env):
    put(env.dir, "toy", "def start(params, ui, ctx, version): return None\n")
    load(env, cmdline="beastnet.toy.token=SECRETSECRET")
    assert not any("SECRET" in x for x in env.ctx.reporter.lines)


@pytest.mark.parametrize("code, reason", [
    ("def start(params, ui, ctx, version):\n    raise RuntimeError('boom')\n", "failed RuntimeError: boom"),
    ("import nothing_like_this_exists\n", "failed ModuleNotFoundError"),
    ("def start(:\n", "failed SyntaxError"),
    ("def start(params, ui, ctx, version):\n    return 'a string'\n", "failed TypeError: start() returned str"),
    ("def start(params, ui, ctx, version):\n    return object\n", "failed TypeError: start() returned type"),
    ("x = 1\n", "failed TypeError: no start() function"),
    ("start = 5\n", "failed TypeError: no start() function"),
    ("def start():\n    pass\n", "failed TypeError"),
    ("import sys\n\ndef start(params, ui, ctx, version):\n    sys.exit(3)\n", "failed SystemExit: 3"),
])
def test_a_failing_addon_is_logged_once_and_the_local_ui_is_used(env, code, reason):
    put(env.dir, "bad", code)
    put(env.dir, "good", WRAP)  # the next one still runs
    ui, got = load(env)
    assert got.inner is ui
    log = lines(env)
    assert len(log) == 2 and log[0].startswith(f"BEASTNET: addon bad {reason}"), log
    assert "\n" not in log[0] and log[1] == "BEASTNET: addon good started ui=wrapped"


def test_a_failing_close_is_logged_and_not_raised(env):
    class Bad(UI):
        def close(self):
            raise OSError("gone")
    local = Local()
    addons.close_ui(Bad(), local, env.ctx)
    addons.close_ui(local, local, env.ctx)  # the local UI is closed by app.main(), not here
    assert local.closed == 0
    assert lines(env) == ["BEASTNET: addon close failed OSError: gone"]


# -- nothing from outside the fixed directory -----------------------------------------------
def test_a_link_to_another_place_is_refused(env):
    outside = env.tmp / "data"
    outside.mkdir()
    real = put(outside, "evil", "raise SystemExit('ran code from outside')\n")
    os.symlink(real, env.dir / "evil")                      # the whole package is a link
    put(env.dir, "half", "")
    os.remove(env.dir / "half" / "__init__.py")
    os.symlink(real / "__init__.py", env.dir / "half" / "__init__.py")  # only its file is
    ui, got = load(env)
    assert got is ui
    assert lines(env) == ["BEASTNET: addon evil refused a link to another place",
                          "BEASTNET: addon half refused a link to another place"]


def test_the_directory_itself_as_a_link_out_of_the_initramfs_is_refused(env, monkeypatch):
    other = env.tmp / "mnt"
    put(other, "evil", "raise SystemExit('ran code from a mounted disk')\n")
    os.rmdir(env.dir)
    os.symlink(other, env.dir)
    real = addons._device
    monkeypatch.setattr(addons, "_device", lambda p: 99 if os.path.realpath(p).startswith(str(other)) else real(p))
    ui, got = load(env)
    assert got is ui
    assert lines(env) == [f"BEASTNET: addon refused {env.dir} not in the initramfs"]


def test_a_package_on_another_file_system_is_refused(env, monkeypatch):
    """Something mounted over (or inside) the directory: st_dev differs from the root's."""
    put(env.dir, "mounted", "raise SystemExit('ran code from a mounted disk')\n")
    put(env.dir, "ok", "def start(params, ui, ctx, version): return None\n")
    real = addons._device
    monkeypatch.setattr(addons, "_device", lambda p: 99 if "mounted" in p else real(p))
    load(env)
    assert lines(env) == ["BEASTNET: addon mounted refused not in the initramfs",
                          "BEASTNET: addon ok started ui=local"]


def test_other_entries_are_refused_and_sys_path_is_untouched(env):
    (env.dir / "README").write_text("x")
    (env.dir / "loose.py").write_text("raise SystemExit('ran a loose file')\n")
    (env.dir / "Bad-Name").mkdir()
    (env.dir / "empty").mkdir()
    put(env.dir, "..hidden", "raise SystemExit('ran')\n")
    put(env.dir, "pkg", "from . import helper\n\ndef start(params, ui, ctx, version):\n    ctx.v = helper.V\n")
    (env.dir / "pkg" / "helper.py").write_text("V = 7\n")
    before = list(sys.path)
    ui, got = load(env)
    assert got is ui and env.ctx.v == 7       # the package's own relative imports work
    assert sys.path == before and "pkg" not in sys.modules and "helper" not in sys.modules
    assert lines(env) == [
        "BEASTNET: addon ..hidden refused not a package name (a-z, 0-9, _)",
        "BEASTNET: addon Bad-Name refused not a package name (a-z, 0-9, _)",
        "BEASTNET: addon README refused not a package name (a-z, 0-9, _)",
        "BEASTNET: addon empty refused no __init__.py",
        "BEASTNET: addon loose.py refused not a package name (a-z, 0-9, _)",
        "BEASTNET: addon pkg started ui=local"]


def test_the_directory_is_fixed_and_no_parameter_moves_it():
    assert addons.ADDONS_DIR == "/usr/lib/beastnet/addons"
    assert addons.load_addons.__kwdefaults__ == {"directory": addons.ADDONS_DIR, "root": "/"}


def test_the_app_uses_the_fixed_directory_and_closes_the_wrapped_ui(tmp_path, monkeypatch):
    """app.main() passes (params, ui, ctx, version) and nothing else, whatever the command
    line says; the flow gets the UI the add-ons returned, and it is closed at the end."""
    root = make_root(tmp_path)
    (root / "proc" / "cmdline").write_text("beastnet.ui=plain beastnet.addons=/mnt/data/x beastnet.toy=1\n")
    calls, flows, closed = [], [], []

    class Wrapped(UI):
        def close(self):
            closed.append(self)
    wrapped = Wrapped()

    def fake_load(*a, **kw):
        calls.append((a, kw))
        return wrapped

    monkeypatch.setattr(app, "load_addons", fake_load)
    monkeypatch.setattr(app.Interactive, "run", lambda self, result=None, action=None: flows.append(self.ui))
    assert app.main(["--root", str(root), "--plain"]) == 0
    (args, kw), = calls
    params, ui, ctx, version = args
    assert kw == {} and version == __version__ and ctx.params is params
    assert params.extra == {"addons": "/mnt/data/x", "toy": "1"}
    assert flows == [wrapped] and closed == [wrapped]


def test_the_app_without_addons_uses_the_local_ui(tmp_path, monkeypatch):
    root = make_root(tmp_path)
    flows = []
    monkeypatch.setattr(app.Interactive, "run", lambda self, result=None, action=None: flows.append(self.ui))
    assert app.main(["--root", str(root), "--plain"]) == 0
    assert type(flows[0]).__name__ == "LineUI"


# -- the optional UI methods Disk tools call (README "Add-ons") -----------------------------
class Watching(DiskUI):
    def __init__(self, answers):
        super().__init__(answers)
        self.sessions, self.plans, self.progress = [], [], []

    def attach_disks(self, session):
        self.sessions.append(session)

    def write_plan(self, kind, plan, target, inv):
        self.plans.append((kind, plan, target, inv, len([s for s in self.shown if s[0] == "form"])))

    def copy_progress(self, cp):
        self.progress.append(cp)


def test_disk_tools_tell_a_wrapping_ui_about_the_session_the_write_and_the_progress(disk_ctx):  # noqa: F811
    parts = Parts()
    run = parts.copy.run

    def run_with_progress(ctx, plan, on_progress, should_stop):
        on_progress(CopyProgress(done=1, total=2, errors=3, rate=0.0))
        return run(ctx, plan, on_progress, should_stop)
    parts.copy.run = run_with_progress
    ui = Watching([pick("Model nvme0n1"), pick("Copy this one disk to another disk"), pick("Model sdb"),
                   pick("Continue"), {"serial": "CCC333"}, True, None, None])
    screens, flow = flow_for(disk_ctx, ui, parts)
    screens.run()
    assert ui.sessions == [screens.s]
    (kind, plan, target, inv, forms_before), = ui.plans
    assert kind == CopyKind.CLONE.value and target.serial == "TGT0000CCC333" and inv is screens.s.inv
    assert forms_before == 0          # told before the typed confirmation is shown
    form = [s for s in ui.shown if s[0] == "form"][0]
    assert form[1] == diskflow.CONFIRM_ERASE and form[1] in diskflow.WRITE_CONFIRMS
    assert [cp.errors for cp in ui.progress] == [3]
