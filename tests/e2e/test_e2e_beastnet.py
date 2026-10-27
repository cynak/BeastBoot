"""beast-net: "Download an ISO from a link" end to end (docs/BEASTNET.md).

The chain: the root menu's tool entry -> the helper kernel (Ubuntu's, re-signed
with the beast-boot key by build.sh) boots through our GRUB (also under
Secure Boot, verified by shim) -> DHCP on a
virtio NIC (QEMU slirp) -> HTTP download from a host-side server with SHA-256
verification -> one-shot entry in ESP:/grub/grubenv -> reboot -> the menu
boots the downloaded ISO once (through the normal recipes) and clears the entry.

Images: the "browse" base (FAT32; exFAT for one download run) with its ISOs
removed, so the root menu holds only the tool entries.
The helper runs in script mode (`bb_beastnet_script` in config.cfg ->
`beastnet.script=`), so no questions are asked.
"""

from __future__ import annotations

import re
import shutil

import pytest

from bbe2e import beastnet as bn
from bbe2e import env

pytestmark = [pytest.mark.slow, pytest.mark.beastnet]

BOTH = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
        pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]
ALL = BOTH + [pytest.param("uefi-sb", marks=pytest.mark.secureboot, id="uefi-sb-enrolled")]
ISO = "/downloads/x.iso"
SPACES_ISO = "/downloads/My Distro (26.04).iso"

# (mode, base image, dest): "browse" has a FAT32 data partition, "exfat" an exFAT one (udisks).
DOWNLOAD_MODES = [
    pytest.param("uefi", "browse", ISO, marks=pytest.mark.uefi, id="uefi"),
    pytest.param("uefi-sb", "browse", ISO, marks=pytest.mark.secureboot, id="uefi-sb-enrolled"),
    pytest.param("uefi", "exfat", SPACES_ISO, marks=[pytest.mark.uefi, pytest.mark.exfat], id="uefi-exfat-spaces"),
]

FW_PACK = "e2etest"
FW_FILE = "beastbooter-test.bin"
FW_CONTENT = b"beastbooter-e2e-firmware-pack-ok\n"

# The helper boots a 35 MB initramfs with Python; generous, KVM makes it ~15 s.
HELPER_TIMEOUT = 180


@pytest.fixture(scope="module")
def helper_files(dist_dir):
    d = dist_dir / "esp" / "beast-net"
    missing = env.missing_files([d / "vmlinuz", d / "initrd.img", d / "VERSION"])
    if missing:
        pytest.skip("dist/ has no beast-net helper (make build): " + ", ".join(missing))
    m = re.search(r"kernel (\S+)", (d / "VERSION").read_text())
    assert m, (d / "VERSION").read_text()
    return {"kver": m.group(1)}


@pytest.fixture
def bn_drive(base_drives, workdir, helper_files):
    """bn_drive(config_text[, kind]) -> per-test copy of a "browse" base without ISOs."""

    def make(config: str, kind: str = "browse"):
        return bn.empty_drive(base_drives(kind), workdir / "bn.img", config)

    return make


def boot_vm(vm_factory, request, mode, drive, *, net=False):
    kw = {"memory": 1536, "hard_timeout": 420}
    if net:
        kw["extra_args"] = list(bn.NET_ARGS)
    if mode == "uefi-sb":
        request.getfixturevalue("secureboot_ok")
        kw["mok_certs"] = [request.getfixturevalue("mok_cert")]
    return vm_factory(mode, drive.path, **kw)


def token_value(rec, key: str) -> str:
    vals = {t.split("=", 1)[1] for v in rec.variants() for t in v.split() if t.startswith(key + "=")}
    assert len(vals) == 1, f"{key}= in {rec}: {vals}"
    return vals.pop()


def plan(url: str, *, sha256: str | None, dest: str = ISO, **kw) -> dict:
    p = {"network": {"type": "ethernet"}, "url": url, "sha256": sha256, "dest": dest, "then": "reboot"}
    p.update(kw)
    return p


# ---------------------------------------------------------------------------
# 1. Menu entry and the exact helper command line (dry run, GRUB only)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", BOTH)
def test_menu_entry_dryrun(mode, bn_drive, vm_factory, request):
    drive = bn_drive(bn.config(dryrun=True))
    vm = boot_vm(vm_factory, request, mode, drive)
    boot = bn.select_entry(vm)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert lin.tokens[2].endswith("/beast-net/vmlinuz"), str(lin)
    assert token_value(lin, "beastnet.data") == f"UUID={drive.data_uuid}", str(lin)
    assert token_value(lin, "beastnet.esp").upper() == f"UUID={bn.esp_uuid(drive)}".upper(), str(lin)
    for tok in ("beastnet.sb=0", "beastnet.debug=1", "console=ttyS0,115200", "beastnet.ui=plain"):
        assert lin.has_token(tok), f"missing {tok} in {lin}"
    assert not [t for t in lin.tokens if t.startswith("beastnet.action")], str(lin)
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert len(ini.tokens) == 3 and ini.tokens[2].endswith("/beast-net/initrd.img"), \
        f"no firmware packs installed: only the base initrd expected: {ini}"
    assert not vm.records("error", after=boot.start), [str(r) for r in vm.records("error")]


@pytest.mark.parametrize("mode", BOTH)
def test_trust_ubuntu_entry_dryrun(mode, bn_drive, vm_factory, request):
    """ "Trust Ubuntu's Secure Boot key" (UEFI only) boots the helper like the
    download entry, plus beastnet.action=trust-ubuntu (build/trust/README.md)."""
    drive = bn_drive(bn.config(dryrun=True))
    vm = boot_vm(vm_factory, request, mode, drive)
    vm.wait_record("dir", r"^dir /$", timeout=120)
    menu = vm.wait_menu(timeout=120)
    if mode == "bios":
        assert bn.TRUST_ENTRY not in menu.entries, f"no MokList under BIOS:\n{menu}"
        return
    assert menu.entries[1:3] == [bn.ENTRY, bn.TRUST_ENTRY], f"{menu}\n--- screen ---\n{vm.screen.text()}"
    mark = vm.mark()
    vm.keys("down", "down", "enter")
    boot = vm.wait_record("boot", r"^boot beast-net recipe=beast-net action=trust-ubuntu$", timeout=60, after=mark)
    lin = vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)
    assert lin.tokens[2].endswith("/beast-net/vmlinuz"), str(lin)
    assert token_value(lin, "beastnet.action") == "trust-ubuntu", str(lin)
    assert token_value(lin, "beastnet.data") == f"UUID={drive.data_uuid}", str(lin)
    for tok in ("beastnet.sb=0", "beastnet.debug=1", "console=ttyS0,115200", "beastnet.ui=plain"):
        assert lin.has_token(tok), f"missing {tok} in {lin}"
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert ini.tokens[2].endswith("/beast-net/initrd.img"), str(ini)
    assert not vm.records("error", after=boot.start), [str(r) for r in vm.records("error")]


# ---------------------------------------------------------------------------
# 2. The real helper boots (shim verifies the re-signed kernel under Secure Boot)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ALL)
def test_helper_boots(mode, bn_drive, vm_factory, request, helper_files):
    drive = bn_drive(bn.config())
    vm = boot_vm(vm_factory, request, mode, drive)
    ready_menu = vm.wait_record("ready", timeout=120)
    sb = 1 if mode == "uefi-sb" else 0
    assert ready_menu.fields.get("sb") == str(sb), str(ready_menu)
    boot = bn.select_entry(vm)
    line = bn.wait_line(vm, "ready ", timeout=HELPER_TIMEOUT, after=boot.end)
    f = bn.fields(line)
    assert f.get("kernel") == helper_files["kver"], line
    assert f.get("sb") == str(sb), line
    assert f.get("firmware") == "none", line
    assert not [ln for ln in bn.lines(vm) if ln.startswith("error ")], bn.lines(vm)


# ---------------------------------------------------------------------------
# 3. Download, verify, hand off, boot the ISO once
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode,kind,dest", DOWNLOAD_MODES)
def test_download_and_oneshot(mode, kind, dest, bn_drive, vm_factory, request, workdir, fixture_isos):
    src = fixture_isos["casper"]
    served = workdir / "www"
    served.mkdir()
    shutil.copyfile(src, served / "x.iso")
    digest = bn.sha256_file(src)
    drive = bn_drive(bn.config(script=bn.PLAN_PATH), kind)
    assert bn.read_grubenv(drive).get("bb_oneshot", "") == ""

    with bn.http_server(served) as srv:
        bn.write_plan(drive, plan(bn.guest_url(srv, "x.iso"), sha256=digest, dest=dest))
        vm = boot_vm(vm_factory, request, mode, drive, net=True)
        boot = bn.select_entry(vm)
        up = bn.fields(bn.wait_line(vm, "net up ", timeout=HELPER_TIMEOUT, after=boot.end))
        assert up.get("ip") == bn.GUEST_IP and up.get("type") == "ethernet", up
        done = bn.wait_line(vm, "download done ", timeout=120, after=boot.end)
        assert done == f"download done path={dest} bytes={src.stat().st_size} sha256={digest}", done
        assert bn.fields(bn.wait_line(vm, "verify ok ", after=boot.end)).get("sha256") == digest
        assert bn.wait_line(vm, "handoff ", after=boot.end) == f"handoff oneshot={dest}"
        vm.wait_exit(timeout=90)  # reboot -> QEMU exits (-no-reboot)
        assert any("GET /x.iso" in r for r in srv.requests), srv.requests
    assert not [ln for ln in bn.lines(vm) if ln.startswith("error ")], bn.lines(vm)
    assert bn.data_file(drive, dest) == src.read_bytes(), "downloaded file differs from the served one"
    assert bn.data_file(drive, dest + ".part") is None
    assert bn.read_grubenv(drive).get("bb_oneshot") == dest

    # Reboot: the menu boots the ISO once (dry run: report only) and clears the entry.
    drive.write_config(bn.config(dryrun=True))
    vm2 = boot_vm(vm_factory, request, mode, drive)
    ready = vm2.wait_record("ready", timeout=120)
    one = vm2.wait_record("oneshot", timeout=60, after=ready.start)
    assert one.contains(f"oneshot {dest}"), str(one)
    rec = vm2.wait_record("boot", rf"^boot {re.escape(dest)} recipe=", after=one.start)
    assert rec.fields.get("recipe") == "casper", str(rec)
    vm2.wait_record("dryrun", r"^dryrun linux ", after=rec.start)
    vm2.wait_record("dir", r"^dir /$", timeout=60, after=rec.start)
    vm2.stop()
    assert bn.read_grubenv(drive).get("bb_oneshot", "") == "", "bb_oneshot was not cleared"

    # And the boot after that is a normal one.
    vm3 = boot_vm(vm_factory, request, mode, drive)
    ready = vm3.wait_record("ready", timeout=120)
    vm3.wait_record("dir", r"^dir /$", timeout=60, after=ready.start)
    assert not vm3.records("oneshot") and not vm3.records("boot"), [str(r) for r in vm3.records()]


@pytest.mark.parametrize("mode", BOTH)
def test_oneshot_menu_side(mode, base_drives, workdir, vm_factory, request):
    """GRUB alone: a one-shot entry in grubenv (as the helper writes it) is
    booted once and cleared with save_env, also through BIOS disk writes."""
    path = "/linux/nested.iso"  # in the "browse" tree, casper fixture
    drive = base_drives("browse").copy(workdir / "browse.img")
    drive.write_config(bn.config(dryrun=True))
    bn.write_grubenv(drive, {"bb_oneshot": path})
    vm = boot_vm(vm_factory, request, mode, drive)
    one = vm.wait_record("oneshot", timeout=120)
    assert one.text == f"oneshot {path}", str(one)
    rec = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", after=one.start)
    assert rec.fields.get("recipe") == "casper", str(rec)
    vm.wait_record("dir", r"^dir /$", timeout=60, after=rec.start)
    vm.stop()
    env_after = bn.read_grubenv(drive)
    assert env_after.get("bb_oneshot", "") == "", env_after


# ---------------------------------------------------------------------------
# 4. Refusals: wrong checksum, plain HTTP without a checksum, untrusted TLS
# ---------------------------------------------------------------------------

def run_failing_plan(bn_drive, vm_factory, request, workdir, fixture_isos, *, sha256, tls=False):
    served = workdir / "www"
    served.mkdir()
    shutil.copyfile(fixture_isos["casper"], served / "x.iso")
    drive = bn_drive(bn.config(script=bn.PLAN_PATH))
    with bn.http_server(served, tls_dir=workdir / "tls" if tls else None) as srv:
        bn.write_plan(drive, plan(bn.guest_url(srv, "x.iso"), sha256=sha256, on_error="poweroff"))
        vm = boot_vm(vm_factory, request, "uefi", drive, net=True)
        boot = bn.select_entry(vm)
        err = bn.wait_line(vm, "error ", timeout=HELPER_TIMEOUT, after=boot.end)
        vm.wait_exit(timeout=90)  # on_error=poweroff
    assert not [ln for ln in bn.lines(vm) if ln.startswith("handoff")], bn.lines(vm)
    assert bn.data_file(drive, ISO) is None and bn.data_file(drive, ISO + ".part") is None, \
        "nothing may be left under /downloads after a refused download"
    assert bn.read_grubenv(drive).get("bb_oneshot", "") == ""
    return vm, err, srv


@pytest.mark.uefi
def test_wrong_checksum_refused(bn_drive, vm_factory, request, workdir, fixture_isos):
    wrong = "0" * 64
    vm, err, _ = run_failing_plan(bn_drive, vm_factory, request, workdir, fixture_isos, sha256=wrong)
    assert err.startswith("error checksum-mismatch"), err
    fail = bn.fields(next(ln for ln in bn.lines(vm) if ln.startswith("verify fail")))
    assert fail.get("expected") == wrong and fail.get("got") == bn.sha256_file(fixture_isos["casper"]), fail


@pytest.mark.uefi
def test_plain_http_without_checksum_refused(bn_drive, vm_factory, request, workdir, fixture_isos):
    _, err, srv = run_failing_plan(bn_drive, vm_factory, request, workdir, fixture_isos, sha256=None)
    assert err.startswith("error refused-plain-http"), err
    assert not srv.requests, f"nothing may be fetched over plain HTTP without a SHA-256: {srv.requests}"


@pytest.mark.uefi
def test_untrusted_certificate_refused(bn_drive, vm_factory, request, workdir, fixture_isos):
    """HTTPS is verified: a self-signed certificate (even one naming 10.0.2.2) is refused."""
    if not env.which("openssl"):
        pytest.skip("openssl not installed")
    digest = bn.sha256_file(fixture_isos["casper"])
    _, err, srv = run_failing_plan(bn_drive, vm_factory, request, workdir, fixture_isos, sha256=digest, tls=True)
    assert err.startswith("error tls"), err
    assert not srv.requests, f"no HTTP request may follow a failed TLS handshake: {srv.requests}"


# ---------------------------------------------------------------------------
# 5. Firmware packs ride along as extra initrds
# ---------------------------------------------------------------------------

@pytest.mark.uefi
def test_firmware_pack_dryrun(bn_drive, vm_factory, request):
    drive = bn_drive(bn.config(dryrun=True))
    bn.install_fake_pack(drive, FW_PACK, {FW_FILE: FW_CONTENT})
    vm = boot_vm(vm_factory, request, "uefi", drive)
    boot = bn.select_entry(vm)
    ini = vm.wait_record("dryrun", r"^dryrun initrd ", after=boot.start)
    assert len(ini.tokens) == 4, str(ini)
    assert ini.tokens[2].endswith("/beast-net/initrd.img"), str(ini)
    assert ini.tokens[3].endswith(f"/beast-net/firmware/{FW_PACK}.cpio"), str(ini)


@pytest.mark.uefi
def test_firmware_pack_loaded(bn_drive, vm_factory, request):
    """The helper lists the installed pack and its file is in /lib/firmware.
    The plan fails on purpose (nothing listens on port 1) and drops to the shell."""
    drive = bn_drive(bn.config(script=bn.PLAN_PATH))
    bn.install_fake_pack(drive, FW_PACK, {FW_FILE: FW_CONTENT})
    bn.write_plan(drive, plan(f"http://{bn.GUEST_HOST}:1/x.iso", sha256="1" * 64, on_error="shell"))
    vm = boot_vm(vm_factory, request, "uefi", drive, net=True)
    boot = bn.select_entry(vm)
    ready = bn.fields(bn.wait_line(vm, "ready ", timeout=HELPER_TIMEOUT, after=boot.end))
    assert ready.get("firmware") == FW_PACK, ready
    bn.wait_line(vm, "error ", timeout=120, after=boot.end)
    vm.wait_for(r"beast-net stopped", timeout=60, after=boot.end)
    mark = vm.mark()
    vm.send(f"cat /lib/firmware/{FW_FILE}; echo fw-rc=$?\r")
    m = vm.wait_for(r"fw-rc=(\d+)\n", timeout=30, after=mark)
    assert m.group(1) == "0", vm.text()[-800:]
    assert FW_CONTENT.decode().strip() in vm.text()[-2000:]


# ---------------------------------------------------------------------------
# 6. The interactive path: line UI on the serial console (no script)
# ---------------------------------------------------------------------------

@pytest.mark.uefi
def test_interactive_download_and_boot(bn_drive, vm_factory, request, workdir, fixture_isos):
    """What a user does on a serial console: Ethernet comes up by itself, type
    the link and the SHA-256, choose "Boot it now"; the next boot starts the ISO."""
    src = fixture_isos["casper"]
    served = workdir / "www"
    served.mkdir()
    shutil.copyfile(src, served / "x.iso")
    digest = bn.sha256_file(src)
    drive = bn_drive(bn.config())
    with bn.http_server(served) as srv:
        vm = boot_vm(vm_factory, request, "uefi", drive, net=True)
        boot = bn.select_entry(vm)
        bn.wait_line(vm, "net up ", timeout=HELPER_TIMEOUT, after=boot.end)
        vm.wait_for(r"ISO link \[https://\]: $", timeout=60, after=boot.end)
        mark = vm.mark()
        vm.send(bn.guest_url(srv, "x.iso") + "\r")
        vm.wait_for(r"checksum file link \(optional\): $", timeout=30, after=mark)
        vm.send(digest + "\r")
        assert bn.fields(bn.wait_line(vm, "verify ok ", timeout=120, after=mark)).get("sha256") == digest
        vm.wait_for(r"1\) Boot it now[\s\S]*Choose 1-\d+: $", timeout=60, after=mark)
        vm.send("1\r")
        assert bn.wait_line(vm, "handoff ", timeout=60, after=mark) == f"handoff oneshot={ISO}"
        vm.wait_exit(timeout=90)
    assert bn.data_file(drive, ISO) == src.read_bytes()
    drive.write_config(bn.config(dryrun=True))
    vm2 = boot_vm(vm_factory, request, "uefi", drive)
    rec = vm2.wait_record("boot", rf"^boot {re.escape(ISO)} recipe=", timeout=120)
    assert rec.fields.get("recipe") == "casper", str(rec)
