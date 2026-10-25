"""beast-net: "Trust Ubuntu's Secure Boot key" end to end (build/trust/README.md).

The helper boots under OVMF with Secure Boot on (Microsoft keys, the
beast-booter certificate in MokList), runs the action in script mode
(`{"action": "trust-ubuntu", ...}`), and powers off. The VM's variable store is
then read with virt-fw-vars: the request mokutil wrote must hold exactly the
files of build/trust/canonical/.

* step 1: nothing enrolled yet -> MokXNew holds exactly Ubuntu's 8 revoked
  certificates (and MokXAuth the password hash); no MokNew
* step 2: MokListX already holds them (as after "Enroll MOKX" in MokManager;
  shim mirrors it into MokListXRT) -> MokNew holds exactly Canonical's CA
* with Ubuntu's own shim on the drive (the 0.1.1 chain), MokListRT also lists
  that shim's built-in Canonical CA, which says nothing about MokList: the
  helper requests nothing. (shim 15.8 mirrors only MokListX into MokListXRT,
  not its vendor_dbx: 0 of 8 revocations show there.)

The two-step test needs the 0.1.2 chain (Debian's shim, the helper kernel
signed with the beast-booter key). If dist/ still has Ubuntu's shim, set
BB_E2E_DEBIAN_SHIM to Debian's shimx64.efi.signed (shim-signed 1.51+16.1-2,
SHA-256 pinned below): the test then puts it on its copy of the drive and
re-signs the helper kernel with keys/beast-booter.key (or $BB_KEY_DIR), as
build.sh does in 0.1.2. The boots need KVM; without it the tests skip.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import sys
from pathlib import Path

import pytest

from bbe2e import beastnet as bn
from bbe2e import env, qemu

sys.path.insert(0, str(env.BB_ROOT / "beastnet" / "python"))
from beastnet import trust  # noqa: E402

pytestmark = [pytest.mark.slow, pytest.mark.beastnet, pytest.mark.secureboot]

HELPER_TIMEOUT = 180
PASSWORD = "1234abcd"
PLAN = {"action": "trust-ubuntu", "password": PASSWORD, "then": "poweroff", "on_error": "poweroff"}
# Debian sid shim-signed_1.51+16.1-2_amd64.deb: /usr/lib/shim/shimx64.efi.signed
DEBIAN_SHIM_SHA256 = "637d7916c0b0b9cb505612f39e8c47b47894957f15a1e711b22a2ae5bbec286d"
TRUST = trust.load_trust(str(env.BB_ROOT / "build" / "trust" / "canonical"))
CANONICAL = {TRUST.ca.sha256} | {c.sha256 for c in TRUST.revoked}


@pytest.fixture
def trust_drive(base_drives, workdir, dist_dir):
    if not env.kvm_usable():
        pytest.skip("needs KVM (/dev/kvm): two Secure Boot boots of the helper are too slow without it")
    for f in ("vmlinuz", "initrd.img"):
        if not (dist_dir / "esp" / "beast-net" / f).exists():
            pytest.skip("dist/ has no beast-net helper (make build)")
    drive = bn.empty_drive(base_drives("browse"), workdir / "trust.img", bn.config(script=bn.PLAN_PATH))
    bn.write_plan(drive, PLAN)
    return drive


def drive_shim_has_canonical(drive, workdir: Path) -> bool:
    shim = workdir / "drive-shim.efi"
    shim.write_bytes(bn.esp_writer(drive).read("/EFI/BOOT/BOOTX64.EFI"))
    return bool(trust.shim_vendor_entries(str(shim)) & CANONICAL)


def use_debian_chain(drive, workdir: Path) -> None:
    """The 0.1.2 chain on this test's copy of the drive (see the module docstring)."""
    src = os.environ.get("BB_E2E_DEBIAN_SHIM", "")
    if not src:
        pytest.skip("the drive boots Ubuntu's shim (Canonical trust built in); the two-step test "
                    "needs Debian's shim: build 0.1.2 or set BB_E2E_DEBIAN_SHIM")
    data = Path(src).read_bytes()
    assert hashlib.sha256(data).hexdigest() == DEBIAN_SHIM_SHA256, f"{src} is not the pinned Debian shim"
    keys = Path(os.environ.get("BB_KEY_DIR") or env.KEYS_DIR)  # the key build.sh signs with
    key, crt = keys / "beast-booter.key", keys / "beast-booter.crt"
    missing = [t for t in ("sbsign", "sbattach") if not env.which(t)] + \
        [str(p) for p in (key, crt) if not p.exists()]
    if missing:
        pytest.skip("cannot re-sign the helper kernel: missing " + ", ".join(missing))
    esp = bn.esp_writer(drive)
    shim = workdir / "debian-shim.efi"
    shim.write_bytes(data)
    esp.put("/EFI/BOOT/BOOTX64.EFI", shim)
    kernel = workdir / "vmlinuz"
    kernel.write_bytes(esp.read("/beast-net/vmlinuz"))
    env.run(["sbattach", "--remove", str(kernel)])
    env.run(["sbsign", "--key", str(key), "--cert", str(crt), "--output", str(kernel) + ".signed", str(kernel)])
    esp.put("/beast-net/vmlinuz", Path(str(kernel) + ".signed"))
    assert not drive_shim_has_canonical(drive, workdir)


def run_helper(vm_factory, drive, vars_file: Path):
    vm = vm_factory("uefi-sb", drive.path, vars_file=vars_file, memory=1536, hard_timeout=420)
    boot = bn.select_entry(vm)
    state = bn.fields(bn.wait_line(vm, "trust state=", timeout=HELPER_TIMEOUT, after=boot.end))
    vm.wait_exit(timeout=120)  # then=poweroff / on_error=poweroff
    return vm, state, boot


def read_vars(vars_file: Path, workdir: Path) -> dict[str, bytes]:
    out = workdir / (vars_file.name + ".json")
    vfw = env.which("virt-fw-vars")
    env.run([vfw, "--input", str(vars_file), "--output-json", str(out)])
    return {v["name"]: bytes.fromhex(v["data"]) for v in json.loads(out.read_text())["variables"]
            if v["guid"] == trust.SHIM_GUID}


def esl_entries(blob: bytes) -> list[tuple[str, bytes]]:
    return sorted(trust.parse_esl(blob))


def make_vars(mok_cert: Path, dest: Path, *, mokx: list[bytes] = ()) -> Path:
    qemu.make_vars("uefi-sb", dest, [mok_cert])
    if mokx:
        blob = b"".join(trust.make_esl(trust.X509_GUID, der) for der in mokx)
        js = dest.with_suffix(".set.json")
        js.write_text(json.dumps({"version": 2, "variables": [
            {"name": "MokListX", "guid": trust.SHIM_GUID, "attr": 3, "data": blob.hex()}]}))
        env.run([env.which("virt-fw-vars"), "--inplace", str(dest), "--set-json", str(js)])
    return dest


def helper_errors(vm) -> list[str]:
    return [ln for ln in bn.lines(vm) if ln.startswith("error ")]


def test_two_steps_enroll_exactly_ubuntus_files(secureboot_ok, mok_cert, trust_drive, vm_factory, workdir):
    if drive_shim_has_canonical(trust_drive, workdir):
        use_debian_chain(trust_drive, workdir)

    # Step 1: nothing enrolled -> MokXNew = the 8 revoked certificates, nothing else.
    vars1 = make_vars(mok_cert, workdir / "step1.vars.fd")
    vm, state, boot = run_helper(vm_factory, trust_drive, vars1)
    assert state == {"state": "not-trusted", "sb": "1", "ca": "0", "revoked": "0/8", "pending": "none"}, state
    assert bn.wait_line(vm, "trust requested ", after=boot.end) == "trust requested step=revocations var=MokXNew"
    assert not helper_errors(vm), helper_errors(vm)
    v = read_vars(vars1, workdir)
    assert esl_entries(v["MokXNew"]) == sorted((trust.X509_GUID, c.der) for c in TRUST.revoked)
    assert v.get("MokXAuth"), "MokXAuth (the password hash) is missing"
    assert "MokNew" not in v and "MokDel" not in v, sorted(v)

    # Step 2: MokListX holds them (MokManager did "Enroll MOKX") -> MokNew = Canonical's CA only.
    vars2 = make_vars(mok_cert, workdir / "step2.vars.fd", mokx=[c.der for c in TRUST.revoked])
    vm2, state2, boot2 = run_helper(vm_factory, trust_drive, vars2)
    assert state2 == {"state": "revocations-only", "sb": "1", "ca": "0", "revoked": "8/8", "pending": "none"}, state2
    assert bn.wait_line(vm2, "trust requested ", after=boot2.end) == "trust requested step=ca var=MokNew"
    assert not helper_errors(vm2), helper_errors(vm2)
    v2 = read_vars(vars2, workdir)
    assert esl_entries(v2["MokNew"]) == [(trust.X509_GUID, TRUST.ca.der)]
    assert v2.get("MokAuth"), "MokAuth (the password hash) is missing"
    assert "MokXNew" not in v2, sorted(v2)


def test_ubuntu_shim_requests_nothing(secureboot_ok, mok_cert, trust_drive, vm_factory, workdir):
    if not drive_shim_has_canonical(trust_drive, workdir):
        pytest.skip("the drive boots a shim without Canonical's trust built in (0.1.2 chain)")
    vars1 = make_vars(mok_cert, workdir / "ubuntu-shim.vars.fd")
    vm, state, _ = run_helper(vm_factory, trust_drive, vars1)
    # shim adds its vendor certificate to MokListRT (its vendor_dbx does not show in MokListXRT)
    assert state == {"state": "shim-built-in", "sb": "1", "ca": "1", "revoked": "0/8", "pending": "none"}, state
    errs = helper_errors(vm)
    assert len(errs) == 1 and errs[0].startswith("error trust this drive's shim already has"), errs
    v = read_vars(vars1, workdir)
    assert not {"MokNew", "MokXNew", "MokDel", "MokXDel"} & set(v), sorted(v)


def read_newc(blob: bytes) -> dict[str, bytes]:
    """Regular files of a (possibly concatenated) newc cpio archive: path -> data."""
    files: dict[str, bytes] = {}
    p = 0
    while p + 110 <= len(blob):
        if blob[p:p + 6] != b"070701":
            if blob[p:p + 1] == b"\0":  # padding between concatenated archives
                p += 1
                continue
            raise AssertionError(f"not a newc header at offset {p}")
        f = [int(blob[p + 6 + 8 * i:p + 14 + 8 * i], 16) for i in range(13)]
        mode, size, namesize = f[1], f[6], f[11]
        name = blob[p + 110:p + 110 + namesize - 1].decode()
        p = (p + 110 + namesize + 3) & ~3
        if name != "TRAILER!!!" and mode & 0o170000 == 0o100000:
            files[name.removeprefix("./")] = blob[p:p + size]
        p = (p + size + 3) & ~3
    return files


def test_trust_files_in_initrd(dist_dir):
    """The initramfs ships build/trust/canonical/ byte for byte, and mokutil."""
    initrd = dist_dir / "esp" / "beast-net" / "initrd.img"
    if not initrd.exists():
        pytest.skip("dist/ has no beast-net helper (make build)")
    with lzma.open(initrd) as f:  # xz, possibly several streams
        files = read_newc(f.read())
    assert files.get("usr/bin/mokutil", b"").startswith(b"\x7fELF")
    src = env.BB_ROOT / "build" / "trust" / "canonical"
    want = {p.relative_to(src).as_posix(): p.read_bytes() for p in src.rglob("*") if p.is_file()}
    prefix = "usr/share/beastnet/trust/canonical/"
    shipped = {k.removeprefix(prefix): v for k, v in files.items() if k.startswith(prefix)}
    assert "trust.json" in want and len(want) == 1 + len(json.loads(want["trust.json"])["files"])
    assert sorted(shipped) == sorted(want)
    for rel, data in want.items():
        assert hashlib.sha256(shipped[rel]).hexdigest() == hashlib.sha256(data).hexdigest(), rel
