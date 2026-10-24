"""Smoke: a fresh drive boots to the menu on BIOS, UEFI and UEFI + Secure Boot
(beast-booter key enrolled in MokList) and reports itself correctly."""

from __future__ import annotations

import pytest

from bbe2e import checks, images

pytestmark = pytest.mark.slow

MODES = [
    pytest.param("bios", marks=pytest.mark.bios, id="bios"),
    pytest.param("uefi", marks=pytest.mark.uefi, id="uefi"),
    pytest.param("uefi-sb", marks=pytest.mark.secureboot, id="uefi-sb-enrolled"),
]


@pytest.mark.parametrize("mode", MODES)
def test_ready_and_menu(request, mode, make_drive, vm_factory, dist_version):
    kw = {}
    if mode == "uefi-sb":
        request.getfixturevalue("secureboot_ok")
        kw["mok_certs"] = [request.getfixturevalue("mok_cert")]
    drive = make_drive("browse", images.user_config())
    vm = vm_factory(mode, drive.path, **kw)
    ready = checks.wait_ready(vm, timeout=120)
    checks.check_ready(ready, platform=checks.PLATFORM[mode], sb=checks.SB[mode], fs="fat32",
                       version=dist_version, **checks.expected_devs("msdos"))
    vm.wait_record("dir", r"^dir /$")
    menu = vm.wait_menu()
    assert menu.entries, f"no menu entries on screen:\n{vm.screen.text()}"
    assert not vm.records("error"), [str(r) for r in vm.records("error")]
