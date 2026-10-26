"""pytest configuration for the beast-booter end-to-end suite (tests/e2e).

Run:  source scripts/dev-env.sh && pytest -q tests/e2e
See tests/e2e/README.md for markers and environment variables.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bbe2e import env, images, trees  # noqa: E402
from bbe2e.isos import builder as fixture_builder  # noqa: E402
from bbe2e.qemu import VM  # noqa: E402

MARKERS = {
    "bios": "boots under legacy BIOS (SeaBIOS)",
    "uefi": "boots under UEFI (OVMF) without Secure Boot",
    "secureboot": "boots under UEFI with Secure Boot (OVMF secboot + Microsoft keys)",
    "exfat": "uses an exFAT data partition (needs udisksctl; run outside the sandbox)",
    "fat32": "uses a FAT32 data partition",
    "ntfs": "uses an NTFS data partition (needs udisksctl; run outside the sandbox)",
    "selftest": "harness self-test (needs no dist/ or installer)",
    "beastnet": "beast-net download helper (docs/BEASTNET.md)",
    "live": "downloads real ISOs from the internet (opt-in: BB_LIVE_NET=1)",
    "slow": "boots QEMU (seconds per test with KVM)",
}


def pytest_configure(config):
    for name, doc in MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {doc}")


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    rep = yield
    setattr(item, f"rep_{rep.when}", rep)
    return rep


def test_name(nodeid: str) -> str:
    base = nodeid.split("/")[-1].replace(".py::", "__").replace("::", "__")
    return re.sub(r"[^A-Za-z0-9_.+-]+", "-", base).strip("-")[:150]


# ---------------------------------------------------------------------------
# Environment checks (each skips with a reason)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def qemu_ok():
    missing = []
    if not env.qemu_binary():
        missing.append("qemu-system-x86_64")
    missing += env.missing_files([env.SEABIOS_BIN, env.OVMF_CODE, env.OVMF_VARS])
    if missing:
        pytest.skip("QEMU/firmware missing (source scripts/dev-env.sh; make tools): " + ", ".join(missing))
    return True


@pytest.fixture(scope="session")
def secureboot_ok(qemu_ok):
    missing = env.missing_files([env.OVMF_CODE_SECBOOT, env.OVMF_VARS_MS])
    if not env.which("virt-fw-vars"):
        missing.append("virt-fw-vars")
    if missing:
        pytest.skip("Secure Boot firmware/tools missing: " + ", ".join(missing))
    return True


@pytest.fixture(scope="session")
def fixture_tools_ok():
    missing = [t for t in ("xorriso", "mksquashfs", "grub-mkimage", "mcopy", "mmd") if not env.which(t)]
    if missing:
        pytest.skip("fixture tools missing (source scripts/dev-env.sh): " + ", ".join(missing))
    return True


@pytest.fixture(scope="session")
def fixture_isos(fixture_tools_ok) -> dict[str, Path]:
    return fixture_builder().build_all(env.FIXTURE_DIR)


@pytest.fixture(scope="session")
def dist_dir() -> Path:
    d = env.DIST
    if not (d / "manifest.json").exists():
        pytest.skip(f"dist/ not built ({d}/manifest.json missing): run `make keys && make build` (task C)")
    sys.path.insert(0, str(env.INSTALLER_DIR))
    try:
        from beastbooter import layout
    finally:
        sys.path.pop(0)
    need = [d / layout.DIST_BOOT_IMG, d / layout.DIST_CORE_IMG] + [d / layout.DIST_ESP_DIR / f for f in layout.REQUIRED_ESP_FILES]
    missing = env.missing_files(need)
    if missing:
        pytest.skip("dist/ is incomplete: " + ", ".join(missing))
    return d


@pytest.fixture(scope="session")
def dist_version(dist_dir) -> str:
    try:
        return json.loads((dist_dir / "manifest.json").read_text())["version"]
    except (KeyError, ValueError):
        return env.read_version()


@pytest.fixture(scope="session")
def installer_ok(dist_dir):
    ok, reason = images.installer_status()
    if not ok:
        pytest.skip(reason)
    return True


@pytest.fixture(scope="session")
def mok_cert(dist_dir) -> Path:
    """The beast-booter certificate a user would enroll in MokManager."""
    for c in (env.KEYS_DIR / "beast-booter.cer", dist_dir / "esp" / "ENROLL_THIS_KEY_IN_MOKMANAGER.cer"):
        if c.exists():
            return c
    pytest.skip("no beast-booter certificate: keys/beast-booter.cer missing (run `make keys`)")


@pytest.fixture(scope="session")
def udisks_ok():
    ok, reason = images.udisks_status()
    if not ok:
        pytest.skip(reason)
    return True


# ---------------------------------------------------------------------------
# Per-test work dir and VM factory
# ---------------------------------------------------------------------------

@pytest.fixture
def workdir(request) -> Path:
    d = env.WORK_DIR / test_name(request.node.nodeid)
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    yield d
    rep = getattr(request.node, "rep_call", None)
    if rep is not None and rep.passed and not env.keep_work():
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def vm_factory(request, workdir, qemu_ok):
    """vm_factory(mode, disk, **kw) -> started VM; logs in out/e2e/logs/<test>[-N].log."""
    vms: list[VM] = []
    base = test_name(request.node.nodeid)
    env.LOG_DIR.mkdir(parents=True, exist_ok=True)

    def make(mode: str, disk: Path, *, start: bool = True, **kw) -> VM:
        name = base if not vms else f"{base}-{len(vms) + 1}"
        vm = VM(name, mode=mode, disk=disk, workdir=workdir, log_dir=env.LOG_DIR, **kw)
        vms.append(vm)
        return vm.start() if start else vm

    yield make
    rep = getattr(request.node, "rep_call", None)
    failed = rep is not None and rep.failed
    for vm in vms:
        if failed and vm.proc is not None:
            try:
                vm.save_failure_artifacts()
            except Exception:  # noqa: BLE001 - never mask the real failure
                pass
        vm.stop()
    if failed:
        logs = ", ".join(str(vm.log_path) for vm in vms)
        if logs:
            request.node.add_report_section("call", "e2e logs", logs)


# ---------------------------------------------------------------------------
# Base images (built once per session) and per-test drives
# ---------------------------------------------------------------------------

BASES = {
    # kind: (layout, fs, tree builder)
    "main": ("msdos", "fat32", trees.main_tree),
    "browse": ("msdos", "fat32", trees.browse_tree),
    "gpt": ("gpt", "fat32", trees.browse_tree),
    "exfat": ("msdos", "exfat", trees.exfat_tree),
    "ntfs": ("msdos", "ntfs", trees.browse_tree),
}


@pytest.fixture(scope="session")
def base_drives(installer_ok, dist_dir, fixture_isos):
    cache: dict[str, images.Drive] = {}

    def get(kind: str) -> images.Drive:
        if kind not in cache:
            layout, fs, tree = BASES[kind]
            if fs != "fat32":
                ok, reason = images.udisks_status()
                if not ok:
                    pytest.skip(reason)
            env.IMAGE_DIR.mkdir(parents=True, exist_ok=True)
            path = env.IMAGE_DIR / f"base-{kind}.img"
            images.install(path, layout=layout, fs=fs, size="2G", dist=dist_dir, serial=True)
            drive = images.Drive.open(path, layout, fs)
            drive.populate(tree(fixture_isos))
            cache[kind] = drive
        return cache[kind]

    return get


@pytest.fixture
def make_drive(base_drives, workdir):
    """make_drive(kind, config_text) -> per-test copy of a base image with config.cfg written."""

    def make(kind: str, config: str) -> images.Drive:
        base = base_drives(kind)
        drive = base.copy(workdir / f"{kind}.img")
        drive.write_config(config)
        return drive

    return make

