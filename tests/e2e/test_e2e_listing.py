"""Listing: the root menu lists exactly the visible directories and ISOs of the
data partition (hidden dirs, dot-names and non-ISOs left out, `.iso` matched
case-insensitively), directories first; a folder with spaces can be opened."""

from __future__ import annotations

import pytest

from bbe2e import checks, images, trees

pytestmark = pytest.mark.slow

MODES = [
    pytest.param("bios", marks=pytest.mark.bios, id="bios"),
    pytest.param("uefi", marks=pytest.mark.uefi, id="uefi"),
]


@pytest.mark.parametrize("mode", MODES)
def test_root_listing(mode, make_drive, vm_factory):
    drive = make_drive("main", images.user_config())
    vm = vm_factory(mode, drive.path)
    checks.wait_ready(vm, timeout=120)
    dirs, isos = checks.listing(vm, "/")

    assert sorted(dirs) == sorted(set(dirs)) and sorted(isos) == sorted(set(isos)), "duplicate item lines"
    assert set(dirs) == trees.MAIN_ROOT_DIRS
    assert set(isos) == trees.MAIN_ROOT_ISOS
    leaked = trees.MAIN_HIDDEN & (set(dirs) | set(isos))
    assert not leaked, f"hidden entries listed: {leaked}"

    # The menu itself: directories (titled "<name>/") first, then ISOs (file name), then tools.
    menu = vm.wait_menu()
    want_dirs = {d.rsplit("/", 1)[1] + "/" for d in trees.MAIN_ROOT_DIRS}
    want_isos = {i.rsplit("/", 1)[1] for i in trees.MAIN_ROOT_ISOS}
    nd, ni = len(want_dirs), len(want_isos)
    assert set(menu.entries[:nd]) == want_dirs, f"menu:\n{menu}"
    assert set(menu.entries[nd : nd + ni]) == want_isos, f"menu:\n{menu}"
    hidden_titles = {h.lstrip("/") for h in trees.MAIN_HIDDEN} | {h.lstrip("/") + "/" for h in trees.MAIN_HIDDEN}
    assert not hidden_titles & set(menu.entries), f"menu:\n{menu}"

    # Open "Some Folder/" (a name with a space) from wherever it is in the list.
    folder = trees.SPACES_ISO.rsplit("/", 1)[0]  # "/Some Folder"
    idx = menu.entries.index(folder.lstrip("/") + "/")
    mark = vm.mark()
    vm.keys(*(["down"] * idx), "enter")
    sub_dirs, sub_isos = checks.listing(vm, folder, after=mark)
    assert (sub_dirs, sub_isos) == ([], [trees.SPACES_ISO])
    menu = vm.wait_menu(first_entry="..")
    assert menu.entries[:2] == ["..", trees.SPACES_ISO.rsplit("/", 1)[1]], f"menu:\n{menu}"
