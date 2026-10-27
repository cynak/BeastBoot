"""A real Windows Setup ISO with Secure Boot on (docs/WINDOWS_SECURE_BOOT.md): the
0.4.0 release gate. Opt-in: BB_WIN_ISO=/path/to/a Microsoft Windows 10/11 or Server ISO
(any language; it needs sources/install.wim or .esd). The ISO is data: nothing from it
runs on the host, the host tool reads it with its own read-only UDF reader.

OVMF Secure Boot with the Microsoft keys, the BeastBoot key in MokList, an exFAT data
partition, the ISO at a path with a space:

* host: `beast-boot prepare-windows` -> one-shot boot -> Windows Setup runs from the ISO
* helper: unprepared -> the menu offers to prepare it -> beast-net copies boot.wim
  (confirm, copy, reboot) -> the one-shot boot -> Windows Setup runs
* stale copy (iso-head.bin of another ISO): the menu offers to prepare it again

Windows Setup is proven as in test_e2e_real_isos.py: beastboot.cmd writes RESULT.TXT
(winpe-ok, iso-mounted, setup-running) to a small BBTEST disk.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from bbe2e import beastnet as bn
from bbe2e import env, images, realiso

pytestmark = [pytest.mark.secureboot, pytest.mark.slow, pytest.mark.exfat]

WIN_ISO = Path(os.environ["BB_WIN_ISO"]) if os.environ.get("BB_WIN_ISO") else None
DEST = "/isos/Win 11.iso"
COPY = f"/beast-booter/winboot{DEST}"
ENTRY = {"id": "local-windows", "family": "windows", "recipe": "windows",
         "result": [r"^winpe-ok\s*$", r"^iso-mounted [A-Z]: [A-Z]:\\sources\\install\.(wim|esd)\s*$",
                    r"^setup-running\s*$"]}
PREPARE = "Prepare this Windows ISO for Secure Boot"
BOOT_TIMEOUT = 900  # seconds, from the menu to setup-running (about 35 s with KVM)


@pytest.fixture(scope="module")
def win_base(installer_ok, udisks_ok, dist_dir, tmp_path_factory):
    if WIN_ISO is None:
        pytest.skip("set BB_WIN_ISO=/path/to/a Windows Setup ISO (Secure Boot release gate)")
    if not env.kvm_usable():
        pytest.skip("needs KVM (/dev/kvm)")
    path = env.IMAGE_DIR / "base-windows-sb.img"
    env.IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    images.install(path, layout="msdos", fs="exfat", size=realiso.drive_size(WIN_ISO.stat().st_size),
                   dist=dist_dir, serial=True)
    drive = images.Drive.open(path, "msdos", "exfat")
    with drive.data_writer() as w:
        w.put(DEST, WIN_ISO)
        w.put(images.USER_CONFIG, images.user_config(debug=True, timeout=5))
    yield drive
    path.unlink(missing_ok=True)


def drive_copy(win_base, workdir, *, prepare: bool, oneshot: bool, mutate=None) -> images.Drive:
    drive = win_base.copy(workdir / "win.img")
    if prepare or mutate:
        with images.udisks_mount(drive.path, drive.data_offset, drive.data_size) as mp:
            if prepare:
                env.run([env.python(), "-m", "beastbooter", "prepare-windows", "--quiet", f"{mp}{DEST}",
                         "--data-root", str(mp)], timeout=1200)
            if mutate:
                mutate(Path(mp))
    if oneshot:
        bn.write_grubenv(drive, {"bb_oneshot": DEST})
    return drive


def copy_files(drive: images.Drive) -> dict[str, bytes]:
    with images.udisks_mount(drive.path, drive.data_offset, drive.data_size) as mp:
        d = Path(f"{mp}{COPY}")
        out = {n: (d / n).read_bytes() for n in ("iso-head.bin", "stamp.env")}
        out["boot.wim size"] = str((d / "boot.wim").stat().st_size).encode()
        with open(f"{mp}{DEST}", "rb") as f:
            out["iso head"] = f.read(98304)[32768:]
    return out


def boot_windows(vm_factory, workdir, drive, mok_cert, name: str):
    bbtest = realiso.make_bbtest(workdir / f"{name}.bbtest.img", name)
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert], memory=8192, smp=2,
                    hard_timeout=BOOT_TIMEOUT + 300,
                    extra_args=realiso.SMBIOS_GETTY + realiso.bbtest_args(bbtest), snapshot=True)
    return vm, bbtest


def assert_setup_runs(vm, bbtest):
    """Wait for the start-up script to power off, then judge RESULT.TXT."""
    o = realiso.Oracle(ENTRY, "uefi-sb", DEST, "exfat")
    try:
        vm.wait_exit(timeout=BOOT_TIMEOUT)
        timed_out = False
    except Exception:  # noqa: BLE001 - judged below
        timed_out = True
    v = realiso.judge_windows(o, vm.clean(), realiso.read_bbtest(bbtest), timed_out=timed_out)
    assert v.status == "pass", f"{v.status}: {v.reason} (log {vm.log_path})"
    rec = vm.wait_record("windows", r"^windows mode=setup copy=", timeout=1)
    assert rec.text.endswith(COPY), str(rec)
    vm.wait_for(r"Secure Boot is enabled", timeout=1)  # wimboot's own report


def test_host_prepared_iso_runs_setup(win_base, mok_cert, workdir, vm_factory):
    drive = drive_copy(win_base, workdir, prepare=True, oneshot=True)
    files = copy_files(drive)
    assert files["iso-head.bin"] == files["iso head"]
    assert re.search(rb"^bb_wb_iso=/isos/Win 11\.iso$", files["stamp.env"], re.M)
    assert re.search(rb"^bb_wb_kind=setup$", files["stamp.env"], re.M)
    assert_setup_runs(*boot_windows(vm_factory, workdir, drive, mok_cert, "host"))


def menu_pick(vm, label: str) -> None:
    menu = vm.wait_menu(timeout=120)
    assert label in menu.entries, f"{label!r} not in the menu:\n{menu}"
    i, sel = menu.entries.index(label), menu.selected or 0
    vm.keys(*(["down"] * (i - sel) if i >= sel else ["up"] * (sel - i)), "enter")


def test_helper_prepares_then_setup_runs(win_base, mok_cert, workdir, vm_factory):
    drive = drive_copy(win_base, workdir, prepare=False, oneshot=False)
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert], memory=2048, hard_timeout=900)
    vm.wait_record("ready", timeout=120)
    vm.wait_record("dir", r"^dir /$", timeout=60)
    mark = vm.mark()
    menu_pick(vm, "isos/")
    vm.wait_record("dir", r"^dir /isos$", timeout=60, after=mark)
    menu_pick(vm, os.path.basename(DEST))
    vm.wait_record("windows-prepare", rf"^windows-prepare {re.escape(DEST)}$", timeout=60)
    assert vm.wait_menu(timeout=60).entries == [PREPARE]
    mark = vm.mark()
    vm.keys("enter")
    boot = vm.wait_record("boot", r"^boot beast-net recipe=beast-net action=winboot$", timeout=60, after=mark)
    vm.wait_for(r"Copy and boot", timeout=300, after=boot.end)
    vm.wait_for(r"Choose 1-2", timeout=30, after=boot.end)
    vm.send("1\r")
    line = bn.wait_line(vm, "winboot ", timeout=900, after=boot.end)
    assert bn.fields(line).get("kind") == "setup", line
    vm.wait_for(r"Done\. The menu will now start", timeout=60, after=boot.end)
    vm.wait_for(r"Press Enter to continue", timeout=30, after=boot.end)
    vm.send("\r")
    vm.wait_exit(timeout=120)  # QEMU runs with -no-reboot: the helper's reboot ends it
    assert not [ln for ln in bn.lines(vm) if ln.startswith("error ")]
    genv = bn.read_grubenv(drive)
    assert genv.get("bb_oneshot") == DEST and "bb_wb_iso" not in genv, genv
    files = copy_files(drive)
    assert files["iso-head.bin"] == files["iso head"]
    assert re.search(rb"^bb_wb_by=helper ", files["stamp.env"], re.M), files["stamp.env"][:200]
    assert_setup_runs(*boot_windows(vm_factory, workdir, drive, mok_cert, "after-helper"))


def test_stale_copy_offers_prepare_again(win_base, mok_cert, workdir, vm_factory):
    def other_head(mp: Path) -> None:
        h = Path(f"{mp}{COPY}/iso-head.bin")
        b = bytearray(h.read_bytes())
        b[100] ^= 0xFF  # inside the primary volume descriptor: another ISO
        h.write_bytes(bytes(b))

    drive = drive_copy(win_base, workdir, prepare=True, oneshot=True, mutate=other_head)
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert], memory=2048)
    vm.wait_record("windows-prepare", rf"^windows-prepare {re.escape(DEST)}$", timeout=180)
    vm.wait_for(r"not prepared for Secure Boot yet", timeout=60)
    assert not vm.records("windows") and not vm.records("error")
