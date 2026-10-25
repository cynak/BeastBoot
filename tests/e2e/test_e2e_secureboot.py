"""Secure Boot is respected (ARCHITECTURE §1.2): untrusted code is refused,
trusted code runs. Nothing here weakens verification: the firmware is OVMF's
Secure Boot build with the Microsoft keys, the drive boots through Debian's
Microsoft-signed shim, and the only trust we add is what MokManager enrollment
stores (MokList / MokListX entries, pre-seeded in a per-VM variable store).

* key not enrolled: shim refuses our GRUB (verification failure / MokManager);
  the menu never starts
* key enrolled: the menu starts in lockdown (sb=1)
* a PC whose db holds only the Microsoft UEFI CA 2023 (no 2011 CA): the menu
  still starts in lockdown (Debian's shim is signed through both CAs)
* key enrolled, ISO with an unsigned EFI loader: refused (sb-verify-failed)
  and the payload never runs (the same payload does run with Secure Boot
  off, see test_e2e_recipes.py::test_efi_chainload_runs_payload)
* key enrolled, ISO with an unsigned kernel: refused (sb-verify-failed)
* Ubuntu's own Canonical-signed kernel (the helper's kernel as the linux-image
  .deb ships it): refused while Canonical's CA is not in MokList; boots once
  MokList holds Canonical's CA and MokListX Ubuntu's 8 revoked certificates
  (what "Trust Ubuntu's Secure Boot key" enrolls, build/trust/README.md)
* MokListX works: a kernel signed by a leaf of a CA in MokList boots, and is
  refused once that leaf is in MokListX
"""

from __future__ import annotations

import pytest

from bbe2e import beastnet as bn
from bbe2e import checks, images, sbtrust, trees

pytestmark = [pytest.mark.secureboot, pytest.mark.slow]

SHIM_REFUSAL = r"Verification failed|Security Violation|Shim UEFI key management|MOK management|MokManager"
# The helper boots a 35 MB initramfs with Python (test_e2e_beastnet.py).
HELPER_TIMEOUT = 180


def error_code(rec) -> str:
    parts = rec.text.split()
    return parts[1] if len(parts) > 1 else ""


@pytest.fixture(scope="session")
def sbvars_ok(secureboot_ok):
    ok, reason = sbtrust.vfv_status()
    if not ok:
        pytest.skip(reason)
    return True


@pytest.fixture(scope="session")
def helper_on_dist(dist_dir):
    k = dist_dir / "esp" / "beast-net" / "vmlinuz"
    if not k.exists() or not (dist_dir / "esp" / "beast-net" / "initrd.img").exists():
        pytest.skip("dist/ has no beast-net helper (make build)")
    return k


@pytest.fixture(scope="session")
def canonical_kernel(dist_dir, helper_on_dist, tmp_path_factory):
    path, why = sbtrust.canonical_kernel(dist_dir, tmp_path_factory.mktemp("canonical") / "vmlinuz")
    if path is None:
        pytest.skip("no Canonical-signed helper kernel: " + why)
    return path


def helper_drive(base_drives, workdir, kernel, name="bn.img"):
    """A "browse" drive without ISOs (root menu: System, Download ..., tools) whose
    ESP beast-net/vmlinuz is `kernel`."""
    drive = bn.empty_drive(base_drives("browse"), workdir / name, bn.config())
    bn.esp_writer(drive).put("/beast-net/vmlinuz", kernel)
    return drive


def boot_helper(vm_factory, drive, vars_file):
    return vm_factory("uefi-sb", drive.path, vars_file=vars_file, memory=1536, hard_timeout=420)


def assert_helper_refused(vm):
    boot = bn.select_entry(vm)
    err = vm.wait_record("error", timeout=120, after=boot.end)
    assert error_code(err) == "sb-verify-failed", str(err)
    vm.wait_for(r"Trust Ubuntu's Secure Boot key", timeout=30, after=boot.end)
    vm.expect_absent(r"BEASTNET: ready", within=5)


def assert_helper_boots(vm):
    boot = bn.select_entry(vm)
    line = bn.wait_line(vm, "ready ", timeout=HELPER_TIMEOUT, after=boot.end)
    assert bn.fields(line).get("sb") == "1", line
    assert not vm.records("error", after=boot.end), [str(r) for r in vm.records("error")]


# ---------------------------------------------------------------------------
# shim and our GRUB
# ---------------------------------------------------------------------------

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


def test_2023_only_db_menu_runs_locked_down(sbvars_ok, mok_cert, make_drive, vm_factory, workdir, dist_version):
    vars_file = sbtrust.make_vars(workdir / "2023only.vars.fd", workdir=workdir, db="2023-only", mok=[mok_cert])
    db = sbtrust.describe(vars_file).get("db", [])
    assert any(sbtrust.MS_UEFI_CA_2023 in s for s in db), db
    assert not any("UEFI CA 2011" in s for s in db), f"the 2011 CA must not be in db: {db}"
    drive = make_drive("browse", images.user_config())
    vm = vm_factory("uefi-sb", drive.path, vars_file=vars_file)
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="efi", sb=1, fs="fat32",
                       version=dist_version, **checks.expected_devs("msdos"))
    vm.wait_menu()


# ---------------------------------------------------------------------------
# ISOs
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Ubuntu's key (MokList) and its revocations (MokListX)
# ---------------------------------------------------------------------------

def test_canonical_kernel_refused_without_trust(sbvars_ok, mok_cert, canonical_kernel, base_drives,
                                                workdir, vm_factory):
    drive = helper_drive(base_drives, workdir, canonical_kernel)
    vars_file = sbtrust.make_vars(workdir / "vars.fd", workdir=workdir, mok=[mok_cert])
    assert_helper_refused(boot_helper(vm_factory, drive, vars_file))


def test_canonical_kernel_boots_when_trusted(sbvars_ok, mok_cert, canonical_kernel, base_drives,
                                             workdir, vm_factory):
    revoked = sorted((sbtrust.CANONICAL_DIR / "revoked").glob("*.der"))
    assert len(revoked) == 8, revoked
    vars_file = sbtrust.make_vars(workdir / "vars.fd", workdir=workdir,
                                  mok=[mok_cert, sbtrust.CANONICAL_DIR / "canonical-master-ca.der"], mokx=revoked)
    seen = sbtrust.describe(vars_file)
    assert len(seen.get("MokListX", [])) == 8, seen
    assert any("Canonical Ltd. Master Certificate Authority" in s for s in seen.get("MokList", [])), seen
    drive = helper_drive(base_drives, workdir, canonical_kernel)
    assert_helper_boots(boot_helper(vm_factory, drive, vars_file))


def test_moklistx_refuses_revoked_signer(sbvars_ok, mok_cert, helper_on_dist, base_drives, workdir, vm_factory):
    ca = sbtrust.make_test_ca(workdir / "ca")
    kernel = sbtrust.resign(helper_on_dist, workdir / "vmlinuz.leaf-signed", ca["leaf_key"], ca["leaf_crt"])
    # Control: the leaf's CA is in MokList, nothing in MokListX -> the kernel boots.
    trusted = sbtrust.make_vars(workdir / "trusted.vars.fd", workdir=workdir, mok=[mok_cert, ca["ca"]])
    vm = boot_helper(vm_factory, helper_drive(base_drives, workdir, kernel, "bn-trusted.img"), trusted)
    assert_helper_boots(vm)
    vm.stop()
    # The same, with the leaf in MokListX -> refused.
    revoked = sbtrust.make_vars(workdir / "revoked.vars.fd", workdir=workdir, mok=[mok_cert, ca["ca"]],
                                mokx=[ca["leaf"]])
    assert len(sbtrust.describe(revoked).get("MokListX", [])) == 1
    assert_helper_refused(boot_helper(vm_factory, helper_drive(base_drives, workdir, kernel, "bn-revoked.img"),
                                      revoked))
