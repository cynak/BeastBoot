"""GUI firmware packs (docs/BEASTNET.md section 6): catalog, command lines, state machine.

No tkinter needed. The CLI side is played either by the test (FakeBackend /
FakeProcess from test_x_gui_controller) or by the fake CLI (gui/fake_cli.py),
which downloads nothing and keeps installed packs in a state file.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import time
from pathlib import Path

import pytest

from beastbooter.errors import BeastError
from beastbooter.gui import controller as ctl
from beastbooter.gui import demo, distinfo
from beastbooter.gui import firmware as fw
from beastbooter.gui.controller import Controller
from beastbooter.gui.firmware import FirmwareController, FwPhase, FwTarget, build_fw_argv
from beastbooter.gui.localproc import LocalProcess

from test_x_gui_controller import STICK, FakeBackend  # noqa: E402  (tests dir is on sys.path)

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/{path}?h={tag}"
H = "ab" * 32


def catalog_obj(**over) -> dict:
    obj = {
        "v": 1, "kernel": "7.0.0-38-generic",
        "source": {"name": "linux-firmware", "tag": "20261019", "url_template": TEMPLATE,
                   "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git"},
        "packs": [
            {"id": "intel-wifi", "title": "Intel WiFi", "description": "Intel adapters (AX210, ...).",
             "modules": ["iwlwifi", "iwlmvm"], "licenses": ["Redistributable. See LICENCE.iwlwifi_firmware"],
             "size": 3000, "files": [
                 {"path": "iwlwifi-100-5.ucode", "sha256": H, "size": 1000, "license": "Redistributable",
                  "source_path": "intel/iwlwifi/iwlwifi-100-5.ucode"},
                 {"path": "iwlwifi-ty-a0-gf-a0-89.ucode", "sha256": "cd" * 32, "size": 2000, "license": "x"}]},
            {"id": "realtek-ethernet", "title": "Realtek Ethernet", "description": "r8169 patches.",
             "modules": ["r8169"], "licenses": ["Redistributable. See LICENSE.r8169"], "size": 5,
             "files": [{"path": "rtl_nic/rtl8168h-2.fw", "sha256": "ef" * 32, "size": 5, "license": "r"}]},
        ],
    }
    obj.update(over)
    return obj


@pytest.fixture
def fw_dist(dist_copy) -> Path:
    p = dist_copy / fw.CATALOG_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(catalog_obj()))
    return dist_copy


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------


def test_catalog_urls_use_the_source_path_and_the_tag(tmp_path):
    cat = fw.parse_catalog(catalog_obj(), tmp_path / "c.json")
    intel = cat.pack("intel-wifi")
    assert intel.files[0].url == ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git"
                                  "/plain/intel/iwlwifi/iwlwifi-100-5.ucode?h=20261019")
    assert intel.files[0].path == "iwlwifi-100-5.ucode"  # installed under the link name
    assert intel.files[1].url.endswith("/plain/iwlwifi-ty-a0-gf-a0-89.ucode?h=20261019")
    assert cat.host == "git.kernel.org" and intel.modules_text == "iwlwifi, iwlmvm"
    assert intel.describe_files() == "2 files, 2.9 KiB"


def test_file_url_percent_encodes():
    assert fw.file_url(TEMPLATE, "2026 10", "a b/c+d.bin").endswith("/plain/a%20b/c%2Bd.bin?h=2026%2010")


def test_details_text_shows_everything_before_download(tmp_path):
    cat = fw.parse_catalog(catalog_obj(), tmp_path / "c.json")
    text = fw.details_text(cat, cat.pack("intel-wifi"))
    for want in ("Repository:  https://git.kernel.org/", "Tag:         20261019", H,
                 "/plain/intel/iwlwifi/iwlwifi-100-5.ucode?h=20261019", "LICENCE.iwlwifi_firmware"):
        assert want in text


@pytest.mark.parametrize("change, error", [
    (lambda o: o.update(v=2), "unknown version"),
    (lambda o: o["source"].update(url_template=TEMPLATE.replace("https", "http")), "https"),
    (lambda o: o["packs"][0]["files"][0].update(sha256="xyz"), "bad sha256"),
    (lambda o: o["packs"][0]["files"][0].update(path="../../etc/passwd"), "unsafe path"),
    (lambda o: o["packs"][1].update(id="intel-wifi"), "listed twice"),
    (lambda o: o["packs"][1].update(id="Bad Id"), "pack id"),
    (lambda o: o["packs"][1].update(files=[]), "no files"),
])
def test_bad_catalogs_are_refused(tmp_path, change, error):
    obj = catalog_obj()
    change(obj)
    with pytest.raises(fw.CatalogError, match=error):
        fw.parse_catalog(obj, tmp_path / "c.json")


def test_real_catalog_if_built():
    path = REPO / "out/beastnet/beast-net/catalog.json"
    if not path.is_file():
        pytest.skip("beast-net not built")
    cat = fw.load_catalog(path)
    assert cat.packs and all(f.url.startswith("https://git.kernel.org/") for p in cat.packs for f in p.files)


def test_parse_installed_variants():
    entry = {"id": "intel-wifi", "catalog_tag": "t", "cpio_sha256": H, "files": [{}, {}]}
    assert fw.parse_installed({"v": 1, "packs": [entry]})[0].files == 2
    assert fw.parse_installed({"installed": {"v": 1, "packs": [entry, {"id": "BAD"}]}})[0].id == "intel-wifi"
    assert fw.parse_installed({"installed": {"v": 1, "packs": []}}) == ()
    assert fw.parse_installed(None) is None and fw.parse_installed({"x": 1}) is None


# ---------------------------------------------------------------------------
# command lines
# ---------------------------------------------------------------------------

R = "C:" if os.name == "nt" else ""  # an absolute path needs a drive on Windows
PY, LAUNCH, PF = R + "/opt/bb/runtime/python3", R + "/opt/bb/app/beast_booter_launch.py", R + "/tmp/bb-fw/p.jsonl"
DEV = FwTarget("device", "/dev/sdb", STICK)


def test_fw_command_lines():
    common = dict(python=PY, launcher=LAUNCH, progress_file=PF)
    base = [PY, "-s", "-E", "-B", LAUNCH, "firmware"]
    assert build_fw_argv("fetch", packs=("intel-wifi", "realtek-ethernet"), out_dir=R + "/tmp/bb-fw/packs",
                         catalog=R + "/d/esp/beast-net/catalog.json", **common) == base + [
        "fetch", "--pack", "intel-wifi", "--pack", "realtek-ethernet", "--out", R + "/tmp/bb-fw/packs",
        "--catalog", R + "/d/esp/beast-net/catalog.json", "--progress-file", PF]
    assert build_fw_argv("install", target=DEV, from_dir=R + "/tmp/bb-fw/packs", **common) == base + [
        "install", "--device", "/dev/sdb", "--from", R + "/tmp/bb-fw/packs", "--progress-file", PF]
    assert build_fw_argv("remove", target=FwTarget("image", R + "/x/a.img"), packs=("intel-wifi",), **common) == base + [
        "remove", "--image", R + "/x/a.img", "--pack", "intel-wifi", "--progress-file", PF]
    assert build_fw_argv("list", target=DEV, **common) == base + [
        "list", "--device", "/dev/sdb", "--json", "--progress-file", PF]


@pytest.mark.parametrize("kw, error", [
    (dict(command="fetch", packs=("intel-wifi",), out_dir="rel/dir"), "absolute"),
    (dict(command="fetch", packs=("--evil",), out_dir=R + "/o"), "bad pack id"),
    (dict(command="install", from_dir=R + "/o"), "needs a target"),
    (dict(command="remove", target=DEV, packs=("a", "b")), "one pack"),
    (dict(command="list", target=FwTarget("image", "x.img")), "absolute"),
    (dict(command="format"), "unknown firmware command"),
])
def test_fw_command_line_refusals(kw, error):
    with pytest.raises(BeastError, match=error):
        build_fw_argv(python=PY, launcher=LAUNCH, progress_file=PF, **kw)


# ---------------------------------------------------------------------------
# controller, with the test playing the CLI
# ---------------------------------------------------------------------------


def space_info(free: int, packs=(), json_size: int = 0) -> dict:
    """A `firmware list` result as the CLI reports it (firmware._result)."""
    return {"installed": {"v": 1, "packs": list(packs), "target": STICK.id, "unlisted": [], "esp_free": free,
                          "esp_cluster": 4096, "esp_label": "BEAST-EFI", "installed_json_size": json_size,
                          "catalog_tag": "20261019", "kernel": "7.0.0-38-generic"}}


@pytest.fixture
def make(fw_dist, tmp_path):
    launcher = tmp_path / "app" / "beast_booter_launch.py"
    launcher.parent.mkdir()
    launcher.write_text("# stand-in launcher\n")

    def _make(backend=None, dist=None) -> tuple[Controller, FirmwareController, FakeBackend]:
        backend = backend or FakeBackend()
        c = Controller(backend_factory=lambda: backend, dist=distinfo.DistLocation(dist or fw_dist, "--dist"),
                       launcher=launcher, python=sys.executable, tmp_root=str(tmp_path), spawn=ctl.inline_spawn)
        c.refresh_drives()
        c.poll()
        return c, FirmwareController(c), backend

    return _make


def test_no_catalog_is_a_friendly_state(make, fw_dist):
    (fw_dist / fw.CATALOG_REL).unlink()  # a build without beast-net
    c, f, _ = make()
    assert not f.available and "not available in this build" in f.catalog_error
    assert f.install_blocker() == f.catalog_error


def test_invalid_catalog_is_explained(make, fw_dist):
    (fw_dist / fw.CATALOG_REL).write_text("{nope")
    _, f, _ = make()
    assert not f.available and "not valid JSON" in f.catalog_error


def test_blockers_in_order(make):
    c, f, _ = make()
    assert f.available and f.install_blocker() == "Choose the beast-booter drive or image first."
    f.set_target_drive(STICK.id)
    assert f.target.disk == STICK and f.install_blocker() == "Select the packs to install."
    f.set_selected("intel-wifi", True)
    assert f.install_blocker() is None and f.download_size == 3000
    with pytest.raises(BeastError):
        f.set_selected("no-such-pack", True)
    f.set_target_drive("/dev/nvme0n1")  # a system disk is never a target
    assert f.target is None


def test_install_runs_fetch_unprivileged_then_install_elevated(make, monkeypatch):
    started = []

    class Local:
        def __init__(self, argv, out):
            self.argv, self.rc = argv, None
            started.append(self)

        def poll(self):
            return self.rc

        def cancel(self):
            self.rc = 130

    monkeypatch.setattr(fw, "LocalProcess", Local)
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    req = f.request_install()
    assert f.phase is FwPhase.CONFIRMING and "git.kernel.org" in req.details[0] and "tag 20261019" in req.details[0]
    assert any("administrator rights twice" in d for d in req.details) and not req.danger
    assert "Its volumes are unmounted first: /media/u/STICK. Close any program that uses them." in req.details
    f.confirm()
    # The free space isn't known yet: it is read first (elevated for a drive), before any download.
    assert f.phase is FwPhase.RUNNING and f.job.stage == "check" and f.job.elevated and started == []
    check = backend.procs[0]
    assert check.argv[5:9] == ["firmware", "list", "--device", STICK.id]
    assert f.stage_text() == f"Checking the free space on {f.target.short}" and f.overall_pct == 0
    check.event(event="start", action="firmware-list", target=STICK.id)
    check.event(event="done", ok=True, info=space_info(50 << 20))
    check.rc = 0
    f.poll()
    assert f.phase is FwPhase.RUNNING and f.job.stage == "fetch" and not f.job.elevated
    assert len(backend.procs) == 1  # downloading never asks for rights
    fetch = started[0]
    assert fetch.argv[5:9] == ["firmware", "fetch", "--pack", "intel-wifi"]
    assert c.install_blocker() == "Busy."  # no drive install while firmware runs
    out = Path(fetch.argv[fetch.argv.index("--out") + 1])
    assert out.is_dir() and (os.name == "nt" or (out.parent.stat().st_mode & 0o077) == 0)
    (out / "intel-wifi.cpio").write_bytes(b"x")
    fetch.rc = 0
    f.poll()
    assert f.job.stage == "install" and f.job.elevated and f.overall_pct == 70.0
    inst = backend.procs[1]
    assert inst.argv[5:9] == ["firmware", "install", "--device", STICK.id]
    assert inst.argv[inst.argv.index("--from") + 1] == str(out)
    inst.event(event="start", action="firmware-install", target=STICK.id)
    inst.event(event="step", step="write-firmware", message="Writing", pct=50)
    f.poll()
    assert f.overall_pct == pytest.approx(85.0) and "Step 2 of 2" in f.stage_text()
    assert not f.can_cancel  # elevated: can't be reached
    inst.event(event="done", ok=True, info={"installed": {"v": 1, "packs": [
        {"id": "intel-wifi", "catalog_tag": "20261019", "cpio_sha256": H, "files": [{}]}]}})
    inst.rc = 0
    f.poll()
    assert f.phase is FwPhase.DONE and f.outcome.ok and "Intel WiFi is now on" in f.outcome.message
    assert f.is_installed("intel-wifi") and not out.exists()  # downloads removed
    f.dismiss()
    assert f.phase is FwPhase.IDLE and not f.selected and c.image_blocker() is None


def read_back(f: FirmwareController, backend, info: dict) -> None:
    """refresh_installed() with the elevated `firmware list` answering `info`."""
    f.refresh_installed()
    p = backend.procs[-1]
    assert p.argv[5:7] == ["firmware", "list"]
    p.event(event="start", action="firmware-list", target=f.target.target)
    p.event(event="done", ok=True, info=info)
    p.rc = 0
    f.poll()
    assert f.phase is FwPhase.DONE
    f.dismiss()


def test_space_unknown_until_read(make):
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    assert f.space_check is None and f.space_text() is None and f.install_blocker() is None
    read_back(f, backend, space_info(1 << 20))
    assert f.space_text() == "Selected: 16.0 KiB of 1.0 MiB free on BEAST-EFI."  # pack + installed.json + dirs
    f.set_selected("intel-wifi", False)
    assert f.space_text() == "1.0 MiB free on BEAST-EFI."
    f.set_target_image(__file__)  # another target: its space is unknown
    assert f.space_text() is None


def test_install_disabled_when_the_packs_dont_fit(make):
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    read_back(f, backend, space_info(8192))
    f.set_selected("realtek-ethernet", True)
    assert f.space_check.need == 4 * 4096 and f.space_check.available == 8192
    blocker = "Needs 16.0 KiB, 8.0 KiB free on BEAST-EFI. Deselect packs or remove installed ones."
    assert f.install_blocker() == blocker
    assert f.space_text() == "Selected: 16.0 KiB of 8.0 KiB free on BEAST-EFI."
    with pytest.raises(BeastError, match="Needs 16.0 KiB"):
        f.request_install()
    assert f.phase is FwPhase.IDLE and len(backend.procs) == 1  # only the list ran


def test_reinstalling_counts_the_space_it_frees(make):
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    intel = {"id": "intel-wifi", "catalog_tag": "20261019", "cpio_sha256": H, "cpio_size": 3600,
             "files": [{"path": "iwlwifi-100-5.ucode", "sha256": H, "size": 1000}]}
    read_back(f, backend, space_info(8192, [intel], json_size=900))
    f.set_selected("intel-wifi", True)  # its old copy and installed.json free 2 clusters: fits
    s = f.space_check
    assert (s.need, s.free, s.reclaimed, s.fits) == (16384, 8192, 8192, True)
    assert f.install_blocker() is None
    assert f.space_text() == ("Selected: 16.0 KiB of 16.0 KiB free on BEAST-EFI (with 8.0 KiB freed by replacing "
                              "installed packs).")
    f.set_selected("realtek-ethernet", True)  # a new pack on top: one cluster too many
    assert f.install_blocker() == ("Needs 20.0 KiB, 16.0 KiB free on BEAST-EFI. Deselect packs or remove "
                                   "installed ones.")
    # without "cpio_size" (an older result) the pack's size comes from its file list
    del intel["cpio_size"]
    sp = fw.parse_space(space_info(8192, [intel]))
    assert 1000 < sp.files["intel-wifi.cpio"] < 4096
    assert fw.parse_space({"installed": {"v": 1, "packs": []}}) is None  # no free space reported


def test_install_checks_the_space_before_downloading(make, monkeypatch):
    started = []
    monkeypatch.setattr(fw, "LocalProcess", lambda argv, out: started.append(argv))
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    f.request_install()
    f.confirm()
    check = backend.procs[0]
    assert f.job.stage == "check" and check.argv[5:9] == ["firmware", "list", "--device", STICK.id]
    check.event(event="start", action="firmware-list", target=STICK.id)
    check.event(event="done", ok=True, info=space_info(8192))
    check.rc = 0
    f.poll()
    o = f.outcome
    assert f.phase is FwPhase.FAILED and o.code == "no-space" and o.title == "Not enough space on the drive"
    assert o.message == ("Needs 16.0 KiB, 8.0 KiB free on BEAST-EFI. Deselect packs or remove installed ones. "
                         "Nothing was downloaded.")
    assert started == [] and len(backend.procs) == 1  # no download, no install
    f.dismiss()
    assert f.selected == {"intel-wifi"} and f.install_blocker().startswith("Needs 16.0 KiB")


def test_swapped_stick_forgets_what_was_read(make):
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    read_back(f, backend, space_info(8192))
    assert f.space_on_target is not None
    backend.disks[STICK.id] = dataclasses.replace(STICK, model="Another Stick")
    c.refresh_drives()
    c.poll()
    f.sync_target()
    assert f.target.disk.model == "Another Stick" and f.space_on_target is None and f.installed_on_target is None


def test_fetch_failure_shows_the_cli_message(make, monkeypatch):
    c, f, backend = make()
    f.set_target_image(__file__)
    f.set_selected("realtek-ethernet", True)
    f.request_install()
    f.confirm()
    job = f.job
    pf = job.argv[job.argv.index("--progress-file") + 1]
    with open(pf, "a") as fh:
        fh.write(json.dumps({"v": 1, "event": "error", "code": "checksum-mismatch",
                             "message": "rtl8168h-2.fw: SHA-256 mismatch"}) + "\n")
    job.proc.cancel()  # stand-in for the CLI exiting: our child, stopped by signal
    job.proc.wait(30)
    f.poll()
    assert f.phase is FwPhase.FAILED and f.outcome.code == "checksum-mismatch"
    assert "SHA-256 mismatch" in f.outcome.message and backend.procs == []


def test_elevation_cancelled_on_remove(make):
    c, f, backend = make()
    f.set_target_drive(STICK.id)
    f.installed[f.target.key] = fw.parse_installed({"packs": [{"id": "intel-wifi"}]})
    req = f.request_remove("intel-wifi")
    assert req.danger and req.confirm_label == "Remove"
    f.confirm()
    p = backend.procs[0]
    assert p.argv[5:] [:5] == ["firmware", "remove", "--device", STICK.id, "--pack"]
    p.rc = ctl.ELEVATION_CANCELLED
    f.poll()
    assert f.outcome.code == "elevation-cancelled" and f.outcome.cancelled
    assert f.is_installed("intel-wifi")  # nothing changed


def test_remove_needs_a_known_installed_pack(make):
    _, f, _ = make()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    with pytest.raises(BeastError, match="not installed"):
        f.request_remove("intel-wifi")


def test_swapped_drive_is_refused_before_anything_runs(make):
    from dataclasses import replace

    c, f, backend = make()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    f.request_install()
    backend.disks[STICK.id] = replace(STICK, model="Other stick")
    with pytest.raises(BeastError, match="has changed"):
        f.confirm()
    assert f.phase is FwPhase.IDLE and f.job is None


def test_firmware_waits_for_a_drive_install(make):
    c, f, backend = make()
    assert c.select_drive(STICK.id) is None
    c.request_install()
    f.set_target_drive(STICK.id)
    f.set_selected("intel-wifi", True)
    assert f.install_blocker() == "Busy."


# ---------------------------------------------------------------------------
# end to end with the fake CLI
# ---------------------------------------------------------------------------


class DemoBackend(demo.DemoBackend):
    def __init__(self):
        super().__init__("linux", list_delay=0.0, step_delay=0.0)


@pytest.fixture
def fake(fw_dist, tmp_path, monkeypatch):
    monkeypatch.setenv("BEAST_BOOTER_FAKE_FW_STATE", str(tmp_path / "fw-state.json"))
    backend = DemoBackend()
    c = Controller(backend_factory=lambda: backend, dist=distinfo.DistLocation(fw_dist, "--dist"),
                   launcher=demo.FAKE_CLI, spawn=ctl.inline_spawn, tmp_root=str(tmp_path))
    c.refresh_drives()
    c.poll()
    return c, FirmwareController(c)


def run(f: FirmwareController, timeout: float = 30) -> None:
    end = time.monotonic() + timeout
    while f.phase is FwPhase.RUNNING:
        assert time.monotonic() < end, "fake CLI did not finish"
        f.poll()
        time.sleep(0.01)


def drive(c: Controller, part: str) -> str:
    return next(r.id for r in c.rows if part in r.title)


def test_fake_cli_install_list_remove(fake):
    c, f = fake
    f.set_target_drive(drive(c, "SanDisk"))
    f.set_selected("intel-wifi", True)
    f.set_selected("realtek-ethernet", True)
    f.request_install()
    f.confirm()
    seen = set()
    while f.phase is FwPhase.RUNNING:
        f.poll()
        seen.add(f.job.stage if f.job else None)
        time.sleep(0.005)
    assert {"fetch", "install"} <= seen
    assert f.phase is FwPhase.DONE, f.outcome
    assert [p.id for p in f.installed_on_target] == ["intel-wifi", "realtek-ethernet"]
    assert any("Downloading intel-wifi" in line.text for line in f.log)
    f.dismiss()
    f.installed.clear()  # forget: read it back from the "drive"
    f.refresh_installed()
    run(f)
    assert f.outcome.action == "list" and [p.id for p in f.installed_on_target] == ["intel-wifi", "realtek-ethernet"]
    f.dismiss()
    f.request_remove("intel-wifi")
    f.confirm()
    run(f)
    assert f.outcome.ok and [p.id for p in f.installed_on_target] == ["realtek-ethernet"]


def test_fake_cli_write_failure(fake):
    c, f = fake
    f.set_target_drive(drive(c, "fails while writing"))
    f.set_selected("realtek-ethernet", True)
    f.request_install()
    f.confirm()
    run(f)
    o = f.outcome
    assert f.phase is FwPhase.FAILED and o.code == "write-failed" and "Input/output error" in o.message
    assert "install them again" in o.message


@pytest.mark.skipif(os.name == "nt", reason="SIGINT delivery to a child is POSIX-only")
def test_fake_cli_download_can_be_stopped(fake, monkeypatch):
    c, f = fake
    real = fw.LocalProcess
    monkeypatch.setattr(fw, "LocalProcess", lambda argv, out: real(argv + ["--fake-delay", "0.3"], out))
    f.set_target_drive(drive(c, "SanDisk"))
    f.set_selected("intel-wifi", True)
    f.request_install()
    f.confirm()
    end = time.monotonic() + 20
    while not (f.job and f.job.stage == "fetch" and f.progress.started):  # after the free-space check
        assert time.monotonic() < end
        f.poll()
        time.sleep(0.01)
    assert f.can_cancel
    f.cancel()
    run(f)
    assert f.outcome.cancelled and f.outcome.code == "cancelled" and not f.installed_on_target


def test_fake_cli_checksum_failure(fake, monkeypatch):
    c, f = fake
    real = fw.LocalProcess
    monkeypatch.setattr(fw, "LocalProcess", lambda argv, out: real(argv + ["--fake-fail-at", "download"], out))
    f.set_target_drive(drive(c, "SanDisk"))
    f.set_selected("intel-wifi", True)
    f.request_install()
    f.confirm()
    run(f)
    assert f.outcome.code == "checksum-mismatch" and "discarded" in f.outcome.message
    assert isinstance(real, type) and issubclass(real, LocalProcess)


def test_fake_cli_refuses_before_download_when_full(fake, monkeypatch):
    monkeypatch.setenv("BEAST_BOOTER_FAKE_ESP_FREE", "8192")
    c, f = fake
    f.set_target_drive(drive(c, "SanDisk"))
    f.set_selected("intel-wifi", True)
    f.request_install()
    f.confirm()
    run(f)
    assert f.outcome.code == "no-space" and "Nothing was downloaded" in f.outcome.message
    assert not any("Downloading" in line.text for line in f.log)
    f.dismiss()
    assert f.install_blocker().startswith("Needs 16.0 KiB, 8.0 KiB free on BEAST-EFI.")


# ---------------------------------------------------------------------------
# the window (needs Tk and a display: see test_x_gui_window)
# ---------------------------------------------------------------------------

FULL_DRIVER = r"""
a.section.set("firmware"); a._on_section(); root.update()
page = a.fw_page
a.fw.set_target_drive(drive("SanDisk")); a.render(); root.update()
print("UNKNOWN", page.space_label.cget("text"))
page._check_installed(); root.update()
wait(lambda: a.fw.phase is not FwPhase.RUNNING, 60)
page._dismiss(); root.update()
page.pack_vars["intel-wifi"].set(True); page._toggle("intel-wifi", True); root.update()
print("SPACE", page.space_label.cget("text"), "|", page.space_label.cget("style"))
print("SUMMARY", page.summary.cget("text"))
print("BUTTON", page.install_button.instate(["disabled"]))
page.pack_vars["intel-wifi"].set(False); page._toggle("intel-wifi", False); root.update()
print("NONE", page.space_label.cget("text"), "|", page.space_label.cget("style"))
root.destroy()
"""


def test_window_shows_the_free_space_and_blocks_install(tmp_path, fw_dist):
    import subprocess
    import textwrap

    import test_x_gui_window as win
    if win.PYTHON is None or win.ENV is None:
        pytest.skip("needs a Python with tkinter and (on Linux) BB_GUI_TEST_DISPLAY, e.g. an Xvfb display")
    script = tmp_path / "full.py"
    script.write_text(textwrap.dedent(win.COMMON + FULL_DRIVER))
    env = dict(win.ENV, BEAST_BOOTER_FAKE_FW_STATE=str(tmp_path / "fw-state.json"),
               BEAST_BOOTER_FAKE_ESP_FREE=str(3 * 4096))  # a pack needs 4 clusters here
    proc = subprocess.run([win.PYTHON, "-s", "-E", "-B", str(script), str(win.INSTALLER), str(fw_dist)],
                          env=env, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = dict(line.split(" ", 1) for line in proc.stdout.splitlines() if " " in line)
    assert out["UNKNOWN"] == ("Free space on the boot partition: checked before anything is downloaded (that asks "
                              "for administrator rights).")
    assert out["SPACE"] == ("Needs 16.0 KiB, 12.0 KiB free on BEAST-EFI. Deselect packs or remove installed ones. "
                            "| Error.TLabel")
    assert out["SUMMARY"] == "1 pack selected · 2 files, 2.9 KiB from git.kernel.org"
    assert out["BUTTON"] == "True"
    assert out["NONE"] == "12.0 KiB free on BEAST-EFI. | Muted.TLabel"


# ---------------------------------------------------------------------------
# installed packs from the unprivileged drive check (DriveRow.probe)
# ---------------------------------------------------------------------------

from beastbooter.installed import InstalledBoot, ProbeResult  # noqa: E402
from test_x_gui_controller import ProbingBackend  # noqa: E402

WIFI_ENTRY = {"id": "intel-wifi", "catalog_tag": "20261019", "cpio_sha256": "ab" * 32, "cpio_size": 9000,
              "files": [{"path": "iwlwifi-x.ucode", "sha256": "cd" * 32, "size": 8000}]}


def probed(firmware) -> ProbeResult:
    return ProbeResult(InstalledBoot("0.1.0", "", 2, firmware=firmware))


def test_checked_drive_shows_its_packs_without_a_job(make):
    b = ProbingBackend({STICK.id: probed(space_info(1 << 20, [WIFI_ENTRY], 400)["installed"])})
    c, f, _ = make(b)
    f.set_target_drive(STICK.id)  # chosen before the check is done
    assert f.installed_on_target is None and f.checking_installed  # the page says "checking..."
    c.poll()
    f.sync_target()  # the window does this whenever it draws the page
    assert f.is_installed("intel-wifi") and [p.id for p in f.installed_on_target] == ["intel-wifi"]
    assert f.space_text() == "1.0 MiB free on BEAST-EFI." and f.phase is FwPhase.IDLE and not b.procs
    assert f.list_blocker() is None  # Check installed packs stays as a manual re-check
    f.set_target_drive(None)
    f.set_target_drive(STICK.id)  # chosen after the check: known at once
    assert f.is_installed("intel-wifi")


def test_drive_without_packs_says_so(make):
    b = ProbingBackend({STICK.id: probed(space_info(1 << 20)["installed"])})
    c, f, _ = make(b)
    c.poll()
    f.set_target_drive(STICK.id)
    assert f.installed_on_target == () and f.space_on_target.free == 1 << 20


@pytest.mark.parametrize("result, why", [
    (None, "not-read"), (ProbeResult(None, "no rights"), "no-rights"), (probed(None), "unreadable"),
    (probed({"v": 1}), "unreadable"),
])
def test_unreadable_check_falls_back_to_the_elevated_list(make, result, why):
    b = ProbingBackend({STICK.id: result})
    c, f, _ = make(b)
    c.poll()
    f.set_target_drive(STICK.id)
    assert f.installed_on_target is None and f.space_on_target is None and not f.checking_installed
    assert f.unknown_why == why
    assert f.list_blocker() is None
    read_back(f, b, space_info(1 << 20, [WIFI_ENTRY]))
    assert f.is_installed("intel-wifi")


def test_checking_installed_while_the_check_runs(make):
    c, f, _ = make(ProbingBackend())
    f.set_target_drive(STICK.id)
    c.probing = True
    assert f.checking_installed
    f.set_target_image(__file__)
    assert not f.checking_installed


def test_a_run_wins_over_an_older_check(make):
    b = ProbingBackend({STICK.id: probed(space_info(1 << 20, [WIFI_ENTRY])["installed"])})
    c, f, _ = make(b)
    c.poll()
    f.set_target_drive(STICK.id)
    assert f.is_installed("intel-wifi")
    read_back(f, b, space_info(2 << 20))  # the elevated list: no packs (removed elsewhere)
    f.sync_target()
    assert f.installed_on_target == () and f.space_on_target.free == 2 << 20
    c.refresh_drives(), c.poll(), c.poll()  # a newer check: what the run said still stands
    f.sync_target()
    assert f.installed_on_target == ()
    read_back(f, b, {})  # a run that didn't say: unknown now ...
    f.sync_target()
    assert f.installed_on_target is None  # ... and the check from before that run is not taken again
    assert f.unknown_why == "stale"
    b.found[STICK.id] = probed(space_info(3 << 20)["installed"])
    c.refresh_drives(), c.poll(), c.poll()
    f.sync_target()
    assert f.installed_on_target == () and f.space_on_target.free == 3 << 20  # a check after it is


def test_demo_drive_has_a_pack_and_the_fake_cli_agrees(fake):
    c, f = fake
    c.poll()
    old = drive(c, demo.OLD_BEAST)
    f.set_target_drive(old)
    assert f.is_installed("intel-wifi") and f.space_on_target is not None
    f.refresh_installed()  # the (fake) elevated list reads the same packs
    run(f)
    assert f.phase is FwPhase.DONE and f.is_installed("intel-wifi")
    f.dismiss()
    f.set_target_drive(drive(c, "SanDisk"))  # not a beast-booter drive: nothing known without a run
    assert f.installed_on_target is None


def test_a_main_install_forgets_the_drives_packs(make):
    b = ProbingBackend({STICK.id: probed(space_info(1 << 20, [WIFI_ENTRY])["installed"])})
    c, f, _ = make(b)
    c.poll()
    f.set_target_drive(STICK.id)
    assert f.is_installed("intel-wifi")
    assert c.select_drive(STICK.id) is None
    c.request_install()
    c.confirm(True)
    p = b.procs[-1]
    p.event(event="done", ok=True, info={})
    p.rc = 0
    c.poll()
    assert c.phase is ctl.Phase.DONE
    f.sync_target()
    assert f.installed_on_target is None and f.space_on_target is None  # erased: not known any more
    b.found[STICK.id] = probed(space_info(2 << 20)["installed"])
    c.dismiss()  # lists and checks again
    c.poll(), c.poll()
    f.sync_target()
    assert f.installed_on_target == () and f.space_on_target.free == 2 << 20


def test_a_firmware_run_waits_for_a_running_check(fw_dist, tmp_path):
    b = ProbingBackend({STICK.id: probed(space_info(1 << 20)["installed"])})
    tasks = []
    launcher = tmp_path / "beast_booter_launch.py"
    launcher.write_text("# stand-in\n")
    c = Controller(backend_factory=lambda: b, dist=distinfo.DistLocation(fw_dist, "--dist"), launcher=launcher,
                   python=sys.executable, tmp_root=str(tmp_path), spawn=tasks.append)
    f = FirmwareController(c)
    c.refresh_drives()
    tasks.pop(0).run()
    c.poll()  # listed; the check is queued
    f.set_target_drive(STICK.id)
    assert f.unknown_why == "checking"
    f.refresh_installed()
    assert f.phase is FwPhase.RUNNING and f.waiting_for_probe and f.can_cancel and not b.procs
    f.poll()
    assert not b.procs
    tasks.pop(0).run()  # stopped before its first drive
    assert b.probed == []
    f.poll()
    assert len(b.procs) == 1 and b.procs[0].argv[5:7] == ["firmware", "list"] and not f.waiting_for_probe
