"""Interactive browse over the serial console (keys: Down = ESC [ B, Enter = CR).

Root: exactly `linux/` then `top.iso` (then tool entries). Enter opens /linux,
whose menu starts with `..` then `nested.iso`; `..` goes back; Down + Enter
on nested.iso (bb_dryrun=1) reports the boot and the would-be kernel."""

from __future__ import annotations

import pytest

from bbe2e import checks, images, trees

pytestmark = pytest.mark.slow

MODES = [
    pytest.param("bios", marks=pytest.mark.bios, id="bios"),
    pytest.param("uefi", marks=pytest.mark.uefi, id="uefi"),
]


@pytest.mark.parametrize("mode", MODES)
def test_browse_into_folder_and_boot(mode, make_drive, vm_factory):
    drive = make_drive("browse", images.user_config(dryrun=True))
    vm = vm_factory(mode, drive.path)
    checks.wait_ready(vm, timeout=120)
    boot = checks.browse_flow(vm, dir_title=trees.BROWSE_DIR_TITLE, root_iso=trees.BROWSE_ROOT_ISO,
                              nested_iso=trees.BROWSE_NESTED_ISO, nested_path=trees.BROWSE_NESTED_PATH)
    assert checks.recipe_of(boot) == "casper"
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert lin.has_token("(loop)/casper/vmlinuz") and lin.has_token(f"iso-scan/filename={trees.BROWSE_NESTED_PATH}"), str(lin)
    # Dry run: nothing is handed off and nothing fails.
    vm.expect_absent(r"BEAST: error", within=2, after=boot.start)
    assert vm.running
