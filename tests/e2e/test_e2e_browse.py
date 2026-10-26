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


WIN_MENU = ["Install Windows (start Windows Setup from the ISO)",
            "Windows PE command prompt (repair and tools, no Setup)"]


@pytest.mark.parametrize("mode", MODES)
def test_windows_iso_asks_setup_or_pe(mode, make_drive, vm_factory):
    """A Windows installation ISO picked in the menu opens a small menu (windows.cfg):
    Setup first, then Windows PE; Esc returns to the folder (dry run)."""
    path = trees.recipe_path("windows")
    vm = vm_factory(mode, make_drive("main", images.user_config(dryrun=True)).path)
    checks.wait_ready(vm, timeout=120)
    vm.wait_record("dir", r"^dir /$", timeout=60)
    menu = vm.wait_menu(timeout=60)
    mark = vm.mark()
    vm.keys(*["down"] * menu.entries.index("recipes/"), "enter")
    vm.wait_record("dir", r"^dir /recipes/?$", timeout=60, after=mark)
    vm.wait_menu(first_entry="..", timeout=60)
    # windows.iso is the last but one entry (winpe.iso sorts after it)
    mark = vm.mark()
    vm.keys("end", "up", "enter")
    boot = vm.wait_record("boot", rf"^boot {path} recipe=windows$", timeout=60, after=mark)
    vm.wait_record("windows-menu", rf"^windows-menu {path}$", timeout=60, after=boot.start)
    menu = vm.wait_menu(first_entry=WIN_MENU[0], timeout=60)
    assert menu.entries == WIN_MENU and menu.selected == 0, str(menu)
    mark = vm.mark()
    vm.keys("down", "enter")
    vm.wait_record("windows", r"^windows mode=pe$", timeout=60, after=mark)
    lin = vm.wait_record("dryrun", r"^dryrun linux(16)? ", timeout=60, after=mark)
    assert lin.has_token("index=1"), str(lin)
    # the dry run returns to the Windows menu; Esc goes back to the folder
    vm.wait_menu(first_entry=WIN_MENU[0], timeout=60)
    vm.key("esc")
    vm.wait_menu(first_entry="..", timeout=60)
    vm.expect_absent(r"BEAST: error", within=2, after=boot.start)
