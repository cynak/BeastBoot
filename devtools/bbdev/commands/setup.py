"""bb-dev setup: one command from a fresh clone to a working dev environment.

  bin/bb-dev setup --yes        (= make dev = scripts/dev-setup.sh --yes)

Steps (each one is skipped when it is already done, so a second run is a
quick check):
  1. doctor        what is missing; explains what needs the system (sudo)
  2. toolchain     scripts/bootstrap-tools.sh, if a tool is missing (no root)
  3. venv          .venv with requirements-dev.txt (pinned + hashed)
  4. keys          make keys, if keys/ has no signing key
  5. build         make build, if dist/ is missing or older than grub/, build/
  6. unit tests    pytest -q installer/tests, when something changed
  7. dev image     bb-dev image --fixtures --debug, if the image is missing
                  (an image of an older layout or dist/ build is flagged, not
                  replaced; `bb-dev vm` refreshes it)
Then a checklist and what to do next. Never needs root.

--minimal: steps 1-5 only (keys only because the build needs them).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .. import freshness, menufiles, paths
from ..msg import Failure, confirm, rel, run_guarded
from . import doctor

CMD = "setup"
VENV = paths.REPO / ".venv"
REQUIREMENTS = paths.REPO / "requirements-dev.txt"
VENV_STAMP = VENV / ".bb-requirements.sha256"
TEST_STAMP = paths.DEV_OUT / ".setup-tests.ok"
BOOTSTRAP = paths.REPO / "scripts" / "bootstrap-tools.sh"
BB_DEV = paths.REPO / "bin" / "bb-dev"

# pip for hosts without ensurepip (Debian/Ubuntu without python3-venv). Must be
# the pip==... wheel pinned (with this hash) in requirements-dev.txt.
PIP_WHEEL = "pip-26.2.1-py3-none-any.whl"
PIP_WHEEL_URL = ("https://files.pythonhosted.org/packages/f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
                 + PIP_WHEEL)
PIP_WHEEL_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"

DONE, SKIP, WARNED, FAILED, NOTRUN = "done", "ok", "warn", "FAILED", "not run"
SKIPPED = "skipped"   # left out on purpose (--no-image ...), not done
MARK = {DONE: "[x]", SKIP: "[x]", SKIPPED: "[-]", WARNED: "[!]", FAILED: "[ ]", NOTRUN: "[ ]"}


@dataclass
class Step:
    name: str
    status: str = NOTRUN
    detail: str = ""


class Setup:
    def __init__(self, args, out=None):
        self.args = args
        self.out = out or sys.stdout
        self.steps: list[Step] = []
        self.changed = False
        self.t0 = time.monotonic()

    # -- output -----------------------------------------------------------
    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    def head(self, n: int, total: int, title: str) -> Step:
        self.say(f"==> [{n}/{total}] {title}")
        st = Step(title)
        self.steps.append(st)
        return st

    def sh(self, cmd: list, env: dict, **kw) -> int:
        self.say("    $ " + " ".join(rel(c) if isinstance(c, Path) else str(c) for c in cmd))
        return subprocess.run([str(c) for c in cmd], cwd=paths.REPO, env=env, **kw, check=False).returncode


def env_now() -> dict:
    paths.load_env.cache_clear()
    return paths.load_env()


def bootstrap_env() -> dict:
    """The environment scripts/bootstrap-tools.sh runs in: the user's own.

    Not env_now(): that is resolved before bootstrap unpacks .tools/root, so
    its BB_GRUB_*_DIR would still point at the (empty) system directories and
    bootstrap would look for the GRUB modules there. bootstrap sources
    dev-env.sh itself once .tools/root is there; directories the user set
    still win.
    """
    return dict(os.environ)


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# venv
# ---------------------------------------------------------------------------

def venv_current() -> bool:
    try:
        return (VENV / "bin" / "python").exists() and VENV_STAMP.read_text().strip() == file_sha256(REQUIREMENTS)
    except OSError:
        return False


def has_ensurepip(python: str) -> bool:
    return subprocess.run([python, "-c", "import ensurepip"], capture_output=True, check=False).returncode == 0


def fetch_pip_wheel(dest_dir: Path) -> Path:
    """Download the pinned pip wheel and check its SHA-256."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / PIP_WHEEL
    if not dest.exists() or file_sha256(dest) != PIP_WHEEL_SHA256:
        tmp = dest.with_suffix(".part")
        try:
            with urllib.request.urlopen(PIP_WHEEL_URL, timeout=60) as r, open(tmp, "wb") as f:
                shutil.copyfileobj(r, f)
        except OSError as exc:
            raise Failure(f"cannot download {PIP_WHEEL}: {exc}", "check the network / proxy (PyPI)")
        got = file_sha256(tmp)
        if got != PIP_WHEEL_SHA256:
            tmp.unlink(missing_ok=True)
            raise Failure(f"{PIP_WHEEL} has SHA-256 {got}, expected {PIP_WHEEL_SHA256}: refusing it")
        tmp.replace(dest)
    return dest


def make_venv(s: Setup, env: dict) -> str:
    py = sys.executable
    vpy = VENV / "bin" / "python"
    if not vpy.exists():
        if VENV.exists():
            shutil.rmtree(VENV)
        if has_ensurepip(py):
            if s.sh([py, "-m", "venv", VENV], env) != 0:
                raise Failure("python3 -m venv failed")
        else:
            s.say("    (this Python has no ensurepip: creating the venv without pip and installing the "
                  "pinned pip wheel)")
            if s.sh([py, "-m", "venv", "--without-pip", VENV], env) != 0:
                raise Failure("python3 -m venv --without-pip failed", "sudo apt install python3-venv")
    if subprocess.run([vpy, "-m", "pip", "--version"], capture_output=True, check=False).returncode != 0:
        wheel = fetch_pip_wheel(VENV / ".bootstrap")
        if s.sh([vpy, f"{wheel}/pip", "install", "-q", "--no-index", "--no-deps", wheel], env) != 0:
            raise Failure("installing pip from its wheel failed")
    venv_env = dict(env, PIP_DISABLE_PIP_VERSION_CHECK="1")
    if s.sh([vpy, "-m", "pip", "install", "-q", "--require-hashes", "--only-binary", ":all:",
             "-r", REQUIREMENTS], venv_env) != 0:
        raise Failure("pip install -r requirements-dev.txt failed", "check the network; hashes are pinned")
    VENV_STAMP.write_text(file_sha256(REQUIREMENTS) + "\n")
    have = doctor.venv_versions(VENV)
    return ", ".join(f"{p} {have.get(p, '?')}" for p in doctor.VENV_PACKAGES)


# ---------------------------------------------------------------------------
# Tests fingerprint: rerun the unit tests only when something they test changed
# ---------------------------------------------------------------------------

def _fingerprinted(name: str) -> bool:
    """Part of what the tests test? Not caches (.pytest_cache, .ruff_cache, __pycache__,
    *.egg-info), dotfiles or editor backups, which pytest/ruff/editors change on their own."""
    return not (name.startswith(".") or name == "__pycache__" or name.endswith((".egg-info", ".pyc", "~")))


def _fingerprint_files(base: Path) -> list[Path]:
    if base.is_file():
        return [base]
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if _fingerprinted(d))
        out += [Path(dirpath) / f for f in sorted(filenames) if _fingerprinted(f)]
    return out


def test_fingerprint() -> str:
    h = hashlib.sha256()
    for top in ("installer", "build", "VERSION", "requirements-dev.txt"):
        for p in _fingerprint_files(paths.REPO / top):
            st = p.stat()
            h.update(f"{p.relative_to(paths.REPO)}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    man = paths.DIST / "manifest.json"
    if man.exists():
        h.update(man.read_bytes())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Dev image vs dist/
# ---------------------------------------------------------------------------

def image_build_id(img: Path) -> str | None:
    """bb_build_id of the dist/ an image was installed from (its ESP's
    /grub/beast/version.cfg; menu-sync never rewrites it). None if unreadable."""
    return freshness.read_state(img).build_id


def image_stale(img: Path, dist: Path | None = None) -> str | None:
    """Why `img` does not have the boot files of the current dist/ and installer
    (None: it does, or there is no dist/ to compare with).

    Both the layout version (an image of an older layout needs a rebuild) and
    the build id count. An image whose layout or build id cannot be read is
    reported too: its file time says nothing, since every VM boot writes to it.
    """
    if menufiles.load_manifest(dist) is None:
        return None
    v = freshness.check(img, dist=dist)
    if v.action == freshness.CURRENT:
        return None
    if v.action == freshness.UNKNOWN:
        return f"cannot tell whether it is current: {v.reason}"
    return v.reason


# ---------------------------------------------------------------------------
# The flow
# ---------------------------------------------------------------------------

def problems(results, actions) -> list:
    return [r for r in results if r.status != doctor.OK and r.action in actions]


def _run(args) -> int:
    s = Setup(args)
    try:
        return _flow(s, args)
    except Failure:
        if s.steps:
            final(s)
        raise


def _flow(s: Setup, args) -> int:
    minimal = args.minimal
    total = 5 if minimal else 7
    if args.no_venv:
        total -= 1
    s.say("bb-dev setup: beast-booter development environment (no root needed)")
    if not args.yes:
        if not sys.stdin.isatty():
            raise Failure("not a terminal: pass --yes to download the toolchain into .tools/ and .venv/")
        if not confirm("bb-dev setup: fetch missing tools into .tools/, create .venv/, build dist/ ...?"):
            return 1
    n = 0

    # 1. doctor
    n += 1
    st = s.head(n, total, "doctor: what is there")
    results = doctor.collect()
    c = doctor.counts(results)
    st.status, st.detail = SKIP, f"{c['OK']} OK, {c['WARN']} WARN, {c['FAIL']} FAIL"
    system = problems(results, (doctor.SYSTEM,))
    for r in system:
        s.say(f"    {r.status:<4} {r.name}: {r.detail}")
        s.say(f"         needs the system, not fetchable without root: {r.fix}")
    py = next((r for r in results if r.name == "python"), None)
    if py and py.status == doctor.FAIL:
        st.status = FAILED
        raise Failure(py.detail, py.fix)

    # 2. toolchain
    n += 1
    st = s.head(n, total, "toolchain (.tools)")
    need = problems(results, (doctor.TOOLS,))
    if need:
        s.say("    missing: " + ", ".join(r.name for r in need))
        rc = s.sh(["bash", BOOTSTRAP], bootstrap_env())
        if rc == 3:
            st.status, st.detail = WARNED, "ready, but GRUB debug symbols failed (see above; only bb-dev gdb needs them)"
        elif rc != 0:
            st.status = FAILED
            raise Failure("scripts/bootstrap-tools.sh failed", "read its output above; `make tools` reruns it")
        else:
            st.status, st.detail = DONE, "fetched into .tools/"
        s.changed = True
    else:
        st.status, st.detail = SKIP, "all tools present"
    env = env_now()

    # 3. venv
    if not args.no_venv:
        n += 1
        st = s.head(n, total, "Python venv (.venv, requirements-dev.txt)")
        if venv_current():
            st.status, st.detail = SKIP, "up to date"
        else:
            try:
                st.detail = make_venv(s, env)
            except Failure:
                st.status = FAILED
                raise
            st.status = DONE
            s.changed = True

    # 4. keys
    n += 1
    st = s.head(n, total, "signing key (keys/)")
    keys = paths.KEYS
    if all((keys / f).is_file() for f in ("beast-booter.key", "beast-booter.crt", "beast-booter.cer")):
        st.status, st.detail = SKIP, "keys/beast-booter.{key,crt,cer} present"
    else:
        if s.sh(["make", "keys"], env) != 0:
            st.status = FAILED
            raise Failure("make keys failed")
        st.status, st.detail = DONE, "created a local key (git-ignored; never share keys/beast-booter.key)"
        s.changed = True

    # 5. build
    n += 1
    st = s.head(n, total, "build (dist/)")
    dist = doctor.check_dist(doctor.Ctx(env))
    if dist.status == doctor.OK:
        st.status, st.detail = SKIP, dist.detail
    else:
        s.say(f"    {dist.detail}")
        if s.sh(["make", "build"], env) != 0:
            st.status = FAILED
            raise Failure("make build failed", "read the build output above")
        st.status, st.detail = DONE, "dist/ rebuilt"
        s.changed = True

    if not minimal:
        # 6. unit tests
        n += 1
        st = s.head(n, total, "installer unit tests")
        fp = test_fingerprint()
        try:
            last = TEST_STAMP.read_text().strip()
        except OSError:
            last = ""
        if last == fp and not s.changed:
            st.status, st.detail = SKIP, "passed before and nothing changed since (`make test` reruns them)"
        else:
            vpy = VENV / "bin" / "python"
            pytest = [vpy, "-m", "pytest"] if vpy.exists() else ["pytest"]
            if s.sh([*pytest, "-q", "-p", "no:cacheprovider", "installer/tests"], env) != 0:
                st.status = FAILED
                raise Failure("installer unit tests failed", "pytest -q installer/tests")
            TEST_STAMP.parent.mkdir(parents=True, exist_ok=True)
            TEST_STAMP.write_text(fp + "\n")
            st.status, st.detail = DONE, "passed"

        # 7. dev image
        n += 1
        st = s.head(n, total, f"dev image ({rel(paths.DEFAULT_IMAGE)})")
        img = paths.DEFAULT_IMAGE
        if args.no_image:
            st.status, st.detail = SKIPPED, "--no-image"
        elif img.exists():
            why = image_stale(img)
            if why:
                st.status = WARNED
                st.detail = (f"outdated boot files: {why}. Left as is; `bin/bb-dev vm` refreshes it before "
                             f"booting, or rebuild it: `{freshness.rebuild_command(img)}`")
            else:
                st.status, st.detail = SKIP, "exists, current (layout and build id of dist/)"
        else:
            if s.sh([BB_DEV, "image", "--fixtures", "--debug"], env) != 0:
                st.status = FAILED
                raise Failure("bb-dev image failed", "bin/bb-dev image --fixtures --debug")
            st.status, st.detail = DONE, "built with the e2e fixture ISOs and bb_debug=1"

    final(s)
    return 0


def final(s: Setup) -> None:
    results = doctor.collect()
    c = doctor.counts(results)
    s.say("")
    s.say(f"bb-dev setup: checklist ({time.monotonic() - s.t0:.0f} s)")
    for st in s.steps:
        s.say(f"  {MARK[st.status]} {st.name:<44} {st.status}{': ' + st.detail if st.detail else ''}")
    s.say(f"  doctor now: {c['OK']} OK, {c['WARN']} WARN, {c['FAIL']} FAIL")
    for r in results:
        if r.status != doctor.OK:
            s.say(f"    {r.status:<4} {r.name}: {r.detail}")
            if r.fix:
                s.say(f"         fix: {r.fix}")
    kvm = next((r for r in results if r.name == "kvm"), None)
    s.say("")
    s.say("next steps:")
    s.say("  source scripts/dev-env.sh && . .venv/bin/activate   tools + pytest/ruff on PATH (optional)")
    if not paths.DEFAULT_IMAGE.exists():
        s.say("  bin/bb-dev image --fixtures --debug   build the dev image first (the VM boots it)")
    s.say("  bin/bb-dev vm                     boot the dev image (UEFI; --mode bios | sb-enrolled | sb-fresh)")
    s.say("  bin/bb-dev menu-sync --watch      edit grub/, reboot the VM, see the change (no rebuild)")
    s.say("  bin/bb-dev debug-config --show    menu debug settings on the image (--set bb_dryrun=1 ...)")
    s.say("  bin/bb-dev vm --mode bios --gdb --wait-gdb   then: bin/bb-dev gdb --platform pc")
    s.say("  make test / make e2e              unit tests / QEMU end-to-end tests")
    if kvm and kvm.status != doctor.OK:
        s.say(f"  ! {kvm.fix}   (VMs are slow without KVM)")


def register(sub) -> None:
    p = sub.add_parser("setup", help="set up a complete dev environment (no root)",
                       description="From a fresh clone to a working dev environment: toolchain in .tools/, "
                                   ".venv, signing key, dist/, unit tests and a dev image. Idempotent; never "
                                   "needs root.")
    p.add_argument("--minimal", action="store_true", help="only toolchain, venv, keys (if missing) and build")
    p.add_argument("--no-venv", action="store_true", help="do not create .venv")
    p.add_argument("--no-image", action="store_true", help="do not build the dev image")
    p.add_argument("--yes", "-y", action="store_true", help="do not ask before downloading")
    p.set_defaults(func=run)


def run(args) -> int:
    return run_guarded(CMD, _run, args)
