"""The BeastBoot CA and its per-component leaf certificates (0.5.0;
docs/SECURE_BOOT.md "One CA, three signing certificates").

Users enroll the CA certificate once. grubx64.efi, the helper's kernel and
wimboot are each signed with their own leaf certificate from that CA. All
tests run under OVMF with Secure Boot on and the drive's own shim (Debian's
16.1); MokList and MokListX are pre-seeded the way MokManager stores them.

* only the CA in MokList: shim starts GRUB, and GRUB (through shim) starts
  the helper's kernel and wimboot; each carries one signature, by its own leaf
* a leaf in MokListX refuses exactly that component, the other two still
  start, although the CA is in MokList; a replacement leaf from the same CA
  works again with nothing new enrolled
* a PC that enrolled only a pre-0.5.0 certificate (self-signed, one key for
  everything) refuses the 0.5.0 GRUB exactly like a PC that enrolled nothing
* which certificate properties shim accepts and refuses (PROFILES): the facts
  build/keygen.sh's profile and the lifetimes rest on
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from bbe2e import beastnet as bn
from bbe2e import checks, env, images, sbtrust, trees

pytestmark = [pytest.mark.secureboot, pytest.mark.slow]

SHIM_REFUSAL = r"Verification failed|Security Violation|Shim UEFI key management|MOK management|MokManager"
WIMBOOT_BANNER = r"wimboot v[0-9][^ ]* -- Windows Imaging Format bootloader"
WINDOWS = trees.recipe_path("windows")
HELPER_TIMEOUT = 180
FILES = {"grub": "/EFI/BOOT/grubx64.efi", "kernel": "/beast-net/vmlinuz", "wimboot": "/beast-booter/wimboot"}


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
def components(dist_dir):
    """{component: its signed file in dist/}; skips when the build lacks one."""
    out = {c: dist_dir / "esp" / p.lstrip("/") for c, p in FILES.items()}
    missing = [c for c, p in out.items() if not p.exists()]
    if missing:
        pytest.skip("dist/ was built without: " + ", ".join(missing))
    return out


@pytest.fixture(scope="session")
def leaves(components, tmp_path_factory) -> dict[str, Path]:
    """{component: the certificate carried in its signature (DER)}: what a user revokes."""
    d = tmp_path_factory.mktemp("leaves")
    return {c: sbtrust.signer_cert(p, d / f"{c}.der") for c, p in components.items()}


def menu_starts(vm) -> None:
    checks.check_ready(checks.wait_ready(vm, timeout=120), platform="efi", sb=1)


def wimboot_outcome(vm) -> str:
    """bb_autoboot of the Windows fixture: "starts" (wimboot's banner) or "refused"."""
    rec = vm.wait_record("boot", rf"^boot {re.escape(WINDOWS)} recipe=windows", timeout=120)
    m = vm.wait_for(WIMBOOT_BANNER + r"|BEAST: error (\S+)\s", timeout=120, after=rec.end)
    if m.group(1) is None:
        return "starts"
    assert m.group(1) == "sb-verify-failed", m.group(0)
    return "refused"


def helper_outcome(vm) -> str:
    """The "Download an ISO from a link" entry: "starts" (the helper is up) or "refused"."""
    boot = bn.select_entry(vm)
    m = vm.wait_for(r"BEASTNET: ready [^\n]*sb=1|BEAST: error (\S+)\s", timeout=HELPER_TIMEOUT, after=boot.end)
    if m.group(1) is None:
        return "starts"
    assert m.group(1) == "sb-verify-failed", m.group(0)
    return "refused"


def windows_drive(make_drive):
    return make_drive("main", images.user_config(autoboot=WINDOWS))


def helper_drive(base_drives, workdir, name="bn.img"):
    return bn.empty_drive(base_drives("browse"), workdir / name, bn.config())


def helper_vm(vm_factory, drive, vars_file):
    return vm_factory("uefi-sb", drive.path, vars_file=vars_file, memory=1536, hard_timeout=420)


# ---------------------------------------------------------------------------
# What the build made
# ---------------------------------------------------------------------------

def test_each_component_has_its_own_leaf_from_the_ca(dist_dir, mok_cert, components, leaves, workdir):
    man = json.loads((dist_dir / "manifest.json").read_text())["secure_boot"]
    ca_pem = workdir / "ca.pem"
    env.run(["openssl", "x509", "-inform", "DER", "-in", dist_dir / "esp" / "ENROLL_THIS_KEY_IN_MOKMANAGER.cer",
             "-out", ca_pem])
    text = env.run(["openssl", "x509", "-in", ca_pem, "-noout", "-text"]).stdout
    assert "CA:TRUE" in text and "Certificate Sign" in text and "Code Signing" not in text, text
    assert hashlib.sha256((dist_dir / "esp" / "ENROLL_THIS_KEY_IN_MOKMANAGER.cer").read_bytes()).hexdigest() \
        == man["cert_sha256"]
    seen = set()
    for comp, der in leaves.items():
        digest = hashlib.sha256(der.read_bytes()).hexdigest()
        assert digest == man[f"signer_{comp}_cert_sha256"], comp
        assert f"OU={comp}," in man[f"signer_{comp}_subject"] + ",", man[f"signer_{comp}_subject"]
        leaf = env.run(["openssl", "x509", "-inform", "DER", "-in", der, "-noout", "-text"]).stdout
        assert "CA:FALSE" in leaf and "Code Signing" in leaf and sbtrust.MODSIGN_ONLY_OID not in leaf, leaf
        pem = workdir / f"{comp}.pem"
        env.run(["openssl", "x509", "-inform", "DER", "-in", der, "-out", pem])
        env.run(["openssl", "verify", "-CAfile", ca_pem, pem])  # issued by the CA
        seen.add(digest)
    assert len(seen) == 3, "three components, three certificates"


# ---------------------------------------------------------------------------
# (a) only the CA is enrolled
# ---------------------------------------------------------------------------

def test_ca_alone_in_moklist_starts_all_three(sbvars_ok, mok_cert, components, make_drive, base_drives, workdir,
                                              vm_factory):
    vars_file = sbtrust.make_vars(workdir / "ca.vars.fd", workdir=workdir, mok=[mok_cert])
    mok = sbtrust.describe(vars_file).get("MokList", [])
    assert len(mok) == 1 and "OU=" not in mok[0], f"MokList must hold the CA and nothing else: {mok}"
    vm = vm_factory("uefi-sb", windows_drive(make_drive).path, vars_file=vars_file)
    menu_starts(vm)                                  # shim verified grubx64.efi
    assert wimboot_outcome(vm) == "starts"           # GRUB, through shim, verified wimboot
    vm.stop()
    vars2 = sbtrust.make_vars(workdir / "ca2.vars.fd", workdir=workdir, mok=[mok_cert])
    vm = helper_vm(vm_factory, helper_drive(base_drives, workdir), vars2)
    assert helper_outcome(vm) == "starts"            # ... and the helper's kernel


# ---------------------------------------------------------------------------
# (c) one MokListX entry per component
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("revoked", ["kernel", "wimboot"])
def test_leaf_in_moklistx_refuses_only_that_component(revoked, sbvars_ok, mok_cert, leaves, make_drive,
                                                      base_drives, workdir, vm_factory):
    def store(name):
        return sbtrust.make_vars(workdir / name, workdir=workdir, mok=[mok_cert], mokx=[leaves[revoked]])

    assert len(sbtrust.describe(store("probe.vars.fd")).get("MokListX", [])) == 1
    vm = vm_factory("uefi-sb", windows_drive(make_drive).path, vars_file=store("w.vars.fd"))
    menu_starts(vm)                                  # GRUB's leaf is not the revoked one
    assert wimboot_outcome(vm) == ("refused" if revoked == "wimboot" else "starts")
    vm.stop()
    vm = helper_vm(vm_factory, helper_drive(base_drives, workdir), store("h.vars.fd"))
    assert helper_outcome(vm) == ("refused" if revoked == "kernel" else "starts")


def test_grub_leaf_in_moklistx_refuses_grub(sbvars_ok, mok_cert, leaves, make_drive, workdir, vm_factory):
    vars_file = sbtrust.make_vars(workdir / "g.vars.fd", workdir=workdir, mok=[mok_cert], mokx=[leaves["grub"]])
    vm = vm_factory("uefi-sb", make_drive("browse", images.user_config()).path, vars_file=vars_file)
    vm.wait_for(SHIM_REFUSAL, timeout=120)
    vm.expect_absent(r"BEAST: ready", within=5)


def test_replaced_leaf_works_without_new_enrolment(sbvars_ok, mok_cert, components, leaves, make_drive, workdir,
                                                   vm_factory):
    """The wimboot leaf is revoked (MokListX) and the owner issues a new one from the
    CA: wimboot signed with the new leaf starts, with MokList unchanged (the CA only)."""
    keys = Path(os.environ.get("BB_KEY_DIR") or env.KEYS_DIR)
    if not (keys / "beast-boot-ca.key").is_file():
        pytest.skip(f"no CA key in {keys} to issue a replacement leaf with (a development key set has one)")
    new = workdir / "new-leaf"
    env.run(["bash", str(env.BB_ROOT / "build" / "keygen.sh"), "leaf", "wimboot"],
            env={**env.tool_env(), "BB_CA_DIR": str(keys), "BB_KEY_DIR": str(new)})
    wimboot = sbtrust.resign(components["wimboot"], workdir / "wimboot.new", new / "beast-boot-wimboot.key",
                             new / "beast-boot-wimboot.crt")
    assert sbtrust.signer_cert(wimboot, workdir / "new.der").read_bytes() != leaves["wimboot"].read_bytes()

    def store(name):
        return sbtrust.make_vars(workdir / name, workdir=workdir, mok=[mok_cert], mokx=[leaves["wimboot"]])

    old = windows_drive(make_drive)
    vm = vm_factory("uefi-sb", old.path, vars_file=store("old.vars.fd"))
    menu_starts(vm)
    assert wimboot_outcome(vm) == "refused"          # the build's wimboot: its leaf is revoked
    vm.stop()
    bn.esp_writer(old).put(FILES["wimboot"], wimboot)
    vm = vm_factory("uefi-sb", old.path, vars_file=store("new.vars.fd"))
    menu_starts(vm)
    assert wimboot_outcome(vm) == "starts"


# ---------------------------------------------------------------------------
# (d) a PC that enrolled only the pre-0.5.0 certificate
# ---------------------------------------------------------------------------

def old_style_certificate(d: Path) -> Path:
    """A certificate as build/keygen.sh made them up to 0.4.x: self-signed, CA:FALSE,
    codeSigning, one key for GRUB, the kernel and wimboot."""
    d.mkdir(parents=True, exist_ok=True)
    env.run(["openssl", "req", "-new", "-x509", "-sha256", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
             "-subj", "/CN=beast-boot Secure Boot key (0.4.x style, throwaway)/", "-keyout", d / "old.key",
             "-out", d / "old.crt", "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=codeSigning"])
    env.run(["openssl", "x509", "-in", d / "old.crt", "-outform", "DER", "-out", d / "old.der"])
    return d / "old.der"


def test_pc_with_only_the_old_certificate_lands_in_first_time_enrolment(sbvars_ok, make_drive, workdir, vm_factory):
    """Not trusted: shim shows its verification error and MokManager, the same place a
    PC that never enrolled anything lands (test_e2e_secureboot.py
    test_not_enrolled_shim_refuses_grub), from where the new certificate is enrolled."""
    vars_file = sbtrust.make_vars(workdir / "old.vars.fd", workdir=workdir,
                                  mok=[old_style_certificate(workdir / "old")])
    assert len(sbtrust.describe(vars_file).get("MokList", [])) == 1
    vm = vm_factory("uefi-sb", make_drive("browse", images.user_config()).path, vars_file=vars_file)
    vm.wait_for(SHIM_REFUSAL, timeout=120)
    vm.expect_absent(r"BEAST: ready", within=5)


# ---------------------------------------------------------------------------
# (b) certificate properties: what shim 16.1 accepts
# ---------------------------------------------------------------------------

CA, LEAF = sbtrust.CA_EXT, sbtrust.LEAF_EXT
MODSIGN = sbtrust.MODSIGN_ONLY_OID
# name: (make_chain arguments, what is enrolled ("ca" | "leaf"), embed the CA in the signature, outcome)
PROFILES = {
    "keygen-profile": ({}, "ca", False, "starts"),
    "ca-embedded-in-signature": ({}, "ca", True, "starts"),
    "leaf-enrolled-instead-of-ca": ({}, "leaf", False, "starts"),
    "ca-with-codesigning-eku": ({"ca_ext": CA + "extendedKeyUsage=codeSigning\n"}, "ca", False, "starts"),
    "ca-without-keyusage": ({"ca_ext": "basicConstraints=critical,CA:TRUE\n"}, "ca", False, "starts"),
    "ca-without-pathlen": ({"ca_ext": "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n"},
                           "ca", False, "starts"),
    "issuer-is-not-a-ca": ({"ca_ext": "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"},
                           "ca", False, "refused"),
    "issuer-without-extensions": ({"ca_ext": ""}, "ca", False, "starts"),
    "ca-keyusage-without-certsign": ({"ca_ext": "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n"},
                                     "ca", False, "refused"),
    "ca-with-modsign-only-eku": ({"ca_ext": CA + f"extendedKeyUsage={MODSIGN}\n"}, "ca", False, "refused"),
    "leaf-without-eku": ({"leaf_ext": "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"},
                         "ca", False, "starts"),
    "leaf-with-serverauth-eku": ({"leaf_ext": "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"},
                                 "ca", False, "starts"),
    # shim looks for the "kernel module signing only" EKU on the certificate it trusts (the
    # MokList entry: ca-with-modsign-only-eku), not on the signer under it
    "leaf-with-modsign-only-eku": ({"leaf_ext": f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage={MODSIGN}\n"},
                                   "ca", False, "starts"),
    "modsign-only-leaf-enrolled": (
        {"leaf_ext": f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage={MODSIGN}\n"}, "leaf", False, "refused"),
    "leaf-without-extensions": ({"leaf_ext": ""}, "ca", False, "starts"),
    "leaf-expired": ({"leaf_dates": sbtrust.EXPIRED}, "ca", False, "starts"),
    "ca-expired": ({"ca_dates": sbtrust.EXPIRED, "leaf_dates": sbtrust.EXPIRED}, "ca", False, "starts"),
    "leaf-not-yet-valid": ({"leaf_dates": ("20900101000000Z", "20990101000000Z")}, "ca", False, "starts"),
}


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_certificate_profile_through_grub(profile, sbvars_ok, mok_cert, components, make_drive, workdir, vm_factory):
    """wimboot signed with a leaf of the given kind; the build's CA (for GRUB) and the
    test's certificate are in MokList. GRUB loads wimboot through shim's verification."""
    kwargs, enrolled, embed, outcome = PROFILES[profile]
    chain = sbtrust.make_chain(workdir / "chain", name=profile, **kwargs)
    signed = sbtrust.resign(components["wimboot"], workdir / "wimboot.signed", chain["leaf_key"], chain["leaf_crt"],
                            addcert=chain["ca_crt"] if embed else None)
    drive = windows_drive(make_drive)
    bn.esp_writer(drive).put(FILES["wimboot"], signed)
    vars_file = sbtrust.make_vars(workdir / "p.vars.fd", workdir=workdir, mok=[mok_cert, chain[enrolled]])
    vm = vm_factory("uefi-sb", drive.path, vars_file=vars_file)
    menu_starts(vm)
    assert wimboot_outcome(vm) == outcome


@pytest.mark.parametrize("profile", ["keygen-profile", "ca-embedded-in-signature", "leaf-expired", "ca-expired",
                                     "issuer-is-not-a-ca", "ca-with-modsign-only-eku"])
def test_certificate_profile_through_shim(profile, sbvars_ok, components, make_drive, workdir, vm_factory):
    """The same for the file shim itself loads: grubx64.efi signed with a leaf of the
    given kind, and only the test's certificate in MokList."""
    kwargs, enrolled, embed, outcome = PROFILES[profile]
    chain = sbtrust.make_chain(workdir / "chain", name=profile, **kwargs)
    signed = sbtrust.resign(components["grub"], workdir / "grubx64.signed", chain["leaf_key"], chain["leaf_crt"],
                            addcert=chain["ca_crt"] if embed else None)
    drive = make_drive("browse", images.user_config())
    bn.esp_writer(drive).put(FILES["grub"], signed)
    vars_file = sbtrust.make_vars(workdir / "s.vars.fd", workdir=workdir, mok=[chain[enrolled]])
    vm = vm_factory("uefi-sb", drive.path, vars_file=vars_file)
    if outcome == "starts":
        menu_starts(vm)
    else:
        vm.wait_for(SHIM_REFUSAL, timeout=120)
        vm.expect_absent(r"BEAST: ready", within=5)
