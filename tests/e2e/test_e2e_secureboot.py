"""Secure Boot is respected (ARCHITECTURE §1.2): untrusted code is refused,
trusted code runs. Nothing here weakens verification: the firmware is OVMF's
Secure Boot build with the Microsoft keys, and the only trust we add is the
beast-booter certificate in MokList, which is what MokManager enrollment does.

* key not enrolled: shim refuses our GRUB (verification failure / MokManager);
  the menu never starts
* key enrolled: the menu starts in lockdown (sb=1)
* key enrolled, ISO with an unsigned EFI loader: refused (sb-verify-failed)
  and the payload never runs (the same payload does run with Secure Boot
  off, see test_e2e_recipes.py::test_efi_chainload_runs_payload)
* key enrolled, ISO with an unsigned kernel: refused (sb-verify-failed)
"""

from __future__ import annotations

import pytest

from bbe2e import checks, images, trees

pytestmark = [pytest.mark.secureboot, pytest.mark.slow]

SHIM_REFUSAL = r"Verification failed|Security Violation|Shim UEFI key management|MOK management|MokManager"


def error_code(rec) -> str:
    parts = rec.text.split()
    return parts[1] if len(parts) > 1 else ""


def test_not_enrolled_shim_refuses_grub(secureboot_ok, make_drive, vm_factory):
    drive = make_drive("browse", images.user_config())
    vm = vm_factory("uefi-sb", drive.path)
    vm.wait_for(SHIM_REFUSAL, timeout=120)
    vm.expect_absent(r"BEAST: ready", within=5)


def test_enrolled_menu_runs_locked_down(secureboot_ok, mok_cert, make_drive, vm_factory, dist_version):
    drive = make_drive("browse", images.user_config())
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert])
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="efi", sb=1, fs="fat32",
                       version=dist_version, **checks.expected_devs("msdos"))
    vm.wait_menu()


def test_enrolled_unsigned_efi_loader_refused(secureboot_ok, mok_cert, make_drive, vm_factory):
    drive = make_drive("main", images.user_config(autoboot=trees.recipe_path("efi-chainload")))
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert])
    checks.wait_ready(vm, timeout=120)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "sb-verify-failed", str(err)
    vm.expect_absent(r"BEAST_FIXTURE chainload", within=5)


def test_enrolled_unsigned_kernel_refused(secureboot_ok, mok_cert, make_drive, vm_factory):
    drive = make_drive("main", images.user_config(autoboot=trees.recipe_path("casper")))
    vm = vm_factory("uefi-sb", drive.path, mok_certs=[mok_cert])
    checks.wait_ready(vm, timeout=120)
    err = vm.wait_record("error", timeout=120)
    assert error_code(err) == "sb-verify-failed", str(err)
