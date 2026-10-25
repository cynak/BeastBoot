"""Harness self-test: proves the plumbing without dist/ or the installer.

Unit tests for the serial parser and the screen emulator, plus real QEMU boots
of stand-in GRUB images (bbe2e/stubs.py) under SeaBIOS, OVMF and OVMF with
Secure Boot (Debian's real shim, a throwaway-signed GRUB stub, MOK pre-seeded
with virt-fw-vars).
"""

from __future__ import annotations

import time

import pytest

from bbe2e import checks, env, images, isos, stubs
from bbe2e.qemu import QemuExited, WaitTimeout
from bbe2e.serial import Screen, clean_text, parse_records

pytestmark = pytest.mark.selftest

SHIM_REFUSAL = r"Verification failed|Security Violation|Shim UEFI key management|MOK management|MokManager"


# ---------------------------------------------------------------------------
# Parser / screen unit tests (no QEMU)
# ---------------------------------------------------------------------------

# Captured from GRUB 2.14 i386-pc: terminfo word-wraps at 80 columns ("\n\r").
BIOS_WRAPPED = (
    "\x1b[H\x1b[J\x1b[1;1HBEAST: ready version=0.1.0 platform=pc sb=0 esp=hd0,msdos2 data=hd0,msdos1\n\r"
    "fs=fat32\n\r"
    "BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper\n\r"
    "iso-scan/filename=/recipes/some/long/path/casper-2.iso\n\r"
    "quiet splash --- END1\n\r"
    "BEAST: item iso /x.iso\n\r"
    "Press any key to continue...\n\r"
)

# Captured from OVMF: terminfo copy (wrapped) immediately followed by the console copy.
EFI_DOUBLED = (
    "BdsDxe: starting Boot0002\r\n\x1b[H\x1b[J\x1b[1;1H"
    "BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper\n\r"
    "iso-scan/filename=/recipes/some/long/path/casper-2.iso\n\r"
    "quiet splash --- END1"
    "BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper iso-scan/filename=/recipes/some/long/path/casper-2.iso quiet splash --- END1\n\r\n\r"
    "BEAST: item iso /x.isoBEAST: item iso /x.iso\n\r\n\r"
    "\x1b[?25l\x1b[m\x1b[H\x1b[J"
)


def test_parser_joins_grub_word_wrap():
    recs = parse_records(clean_text(BIOS_WRAPPED), final=True)
    texts = [r.text for r in recs]
    assert texts[0] == "ready version=0.1.0 platform=pc sb=0 esp=hd0,msdos2 data=hd0,msdos1 fs=fat32"
    assert recs[0].fields["fs"] == "fat32"
    assert texts[1] == ("dryrun linux (loop)/casper/vmlinuz boot=casper "
                        "iso-scan/filename=/recipes/some/long/path/casper-2.iso quiet splash --- END1")
    # A short record followed by unrelated text is not joined with it.
    assert texts[2] == "item iso /x.iso"
    assert len(recs) == 3


def test_parser_dedupes_ovmf_mirror():
    recs = parse_records(clean_text(EFI_DOUBLED), final=True)
    assert [r.kind for r in recs] == ["dryrun", "item"]
    assert recs[0].tokens[-1] == "END1" and "iso-scan/filename=/recipes/some/long/path/casper-2.iso" in recs[0].tokens
    assert len(recs[0].lines) == 1, "the unwrapped console copy must be kept"


def test_parser_hard_break_inside_a_word():
    # GRUB re-counts the overflowing partial word, so long words get split mid-word.
    raw = ("BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper\n\r"
           "iso-scan/filename=/a/rather/long/path/to/an/image/file\n\r"
           "-name.iso quiet splash ---\n\r\n\r")
    rec = parse_records(clean_text(raw), final=True)[0]
    assert rec.has_token("iso-scan/filename=/a/rather/long/path/to/an/image/file-name.iso")
    assert rec.has_token("boot=casper") and not rec.has_token("casper")
    ready = parse_records(clean_text(
        "BEAST: ready version=0.1.0 platform=pc sb=0 esp=hd0,msdos2 data=hd0,msdos1\n\rfs=fat32\n\r\n\r"), final=True)[0]
    assert ready.fields == {"version": "0.1.0", "platform": "pc", "sb": "0", "esp": "hd0,msdos2",
                            "data": "hd0,msdos1", "fs": "fat32"}


def test_parser_marker_broken_across_lines():
    # Captured: after the menu, GRUB left the cursor at column 78 and hard-wrapped the marker.
    raw = ("\x1b[23;1H" + " " * 76 + "BE\n\rAST: dir /\n\rBEAST: item dir /linux\n\rBEAST:\n\r"
           "item iso /top.iso\n\rBEAST_FIX\n\rTURE loopback iso_path=/x.iso\n\r\n\r")
    recs = parse_records(clean_text(raw), final=True)
    assert [(r.prefix, r.text) for r in recs] == [
        ("BEAST", "dir /"), ("BEAST", "item dir /linux"), ("BEAST", "item iso /top.iso"),
        ("BEAST_FIXTURE", "loopback iso_path=/x.iso")]


def test_parser_holds_back_incomplete_records():
    partial = clean_text("BEAST: boot /linux/nes")
    assert parse_records(partial, final=False) == []
    assert parse_records(partial, final=True)[0].text == "boot /linux/nes"
    # A complete line at the end of the buffer might still be followed by a wrap.
    line = clean_text("BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper iso-scan/filename=/x/y/z.iso\n\r")
    assert parse_records(line, final=False) == []


def test_screen_reads_grub_menu():
    s = Screen()
    s.feed("\x1b[m\x1b[4;2H+" + "-" * 76 + "+\x1b[5;2H|\x1b[5;79H|\x1b[6;2H|\x1b[6;79H|\x1b[7;2H|\x1b[7;79H|"
           "\x1b[8;2H+" + "-" * 76 + "+")
    s.feed("\x1b[7m\x1b[5;3H*linux/" + " " * 60 + "\x1b[m\x1b[6;3H top.iso" + " " * 60 + "\x1b[7;3H Power off")
    m = s.menu()
    assert m.entries == ["linux/", "top.iso", "Power off"]
    assert m.selected == 0
    # Selection moves: terminfo redraws both rows.
    s.feed("\x1b[m\x1b[5;3H linux/   \x1b[7m\x1b[6;3H*top.iso  \x1b[m")
    assert s.menu().selected == 1


def test_fixture_builder_is_cached(fixture_isos):
    build_fixtures = isos.builder()

    assert set(fixture_isos) == set(build_fixtures.FIXTURES)
    for name, iso in fixture_isos.items():
        assert build_fixtures.iso_volume_label(iso) == build_fixtures.FIXTURES[name]["label"]
    labels = [f["label"] for f in build_fixtures.FIXTURES.values()]
    assert len(set(labels)) == len(labels), "fixture volume labels must be distinct"
    mtimes = {n: p.stat().st_mtime_ns for n, p in fixture_isos.items()}
    again = build_fixtures.build_all(env.FIXTURE_DIR)
    assert {n: p.stat().st_mtime_ns for n, p in again.items()} == mtimes, "second build must hit the cache"


# ---------------------------------------------------------------------------
# QEMU boots of stub images
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def stub_dir():
    d = env.SELFTEST_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="session")
def efi_stub(stub_dir, qemu_ok, fixture_tools_ok):
    if not env.which("grub-mkstandalone") or not (env.GRUB_EFI_DIR / "kernel.img").exists():
        pytest.skip("grub-mkstandalone / x86_64-efi modules missing")
    return stubs.build_efi_stub(stub_dir)


@pytest.fixture(scope="session")
def bios_stub(stub_dir, qemu_ok, fixture_tools_ok):
    if not (env.GRUB_BIOS_DIR / "boot.img").exists():
        pytest.skip(f"GRUB i386-pc files missing in {env.GRUB_BIOS_DIR}")
    return stubs.build_bios_stub(stub_dir)


@pytest.fixture(scope="session")
def sb_stub(stub_dir, secureboot_ok, fixture_tools_ok):
    ok, reason = stubs.sb_stub_status()
    if not ok:
        pytest.skip(reason)
    payload = isos.builder().build_efi_payload(env.FIXTURE_DIR)
    return stubs.build_sb_stub(stub_dir / "sb", payload)


def _copy(src, workdir):
    return images.copy_image(src, workdir / src.name)


def _stub_menu_checks(vm, platform: str):
    ready = checks.wait_ready(vm, timeout=60)
    checks.check_ready(ready, platform=platform, sb=0)
    # The long dryrun line is word-wrapped by GRUB's terminfo; tokens survive.
    dry = vm.wait_record("dryrun", r"^dryrun linux ")
    assert dry.tokens[2] == "(loop)/casper/vmlinuz"
    assert dry.has_token("iso-scan/filename=/a/rather/long/path/to/an/image/file-name.iso"), dry.lines
    assert dry.tokens[-1] == "---"
    dirs, isos = checks.listing(vm, "/")
    assert (dirs, isos) == (["/linux"], ["/top.iso"])
    boot = checks.browse_flow(vm, dir_title="linux/", root_iso="top.iso", nested_iso="nested.iso",
                              nested_path="/linux/nested.iso")
    assert checks.recipe_of(boot) == "selftest"
    assert vm.log_path.stat().st_size > 0


@pytest.mark.uefi
@pytest.mark.slow
def test_uefi_stub_menu_and_keys(vm_factory, efi_stub, workdir):
    vm = vm_factory("uefi", _copy(efi_stub, workdir))
    _stub_menu_checks(vm, "efi")


@pytest.mark.bios
@pytest.mark.slow
def test_bios_stub_menu_and_keys(vm_factory, bios_stub, workdir):
    """Also proves the layout.py boot.img/core.img patch points boot under SeaBIOS."""
    vm = vm_factory("bios", _copy(bios_stub, workdir))
    _stub_menu_checks(vm, "pc")


@pytest.mark.uefi
@pytest.mark.slow
def test_wait_timeout_and_hard_timeout(vm_factory, efi_stub, workdir):
    disk = _copy(efi_stub, workdir)
    vm = vm_factory("uefi", disk)
    checks.wait_ready(vm)
    t0 = time.monotonic()
    with pytest.raises(WaitTimeout):
        vm.wait_for(r"THIS NEVER APPEARS", timeout=1.5 / env.timeout_scale())
    assert time.monotonic() - t0 < 10
    vm.expect_absent(r"THIS NEVER APPEARS", within=0.5)
    vm.stop()
    assert not vm.running

    # The watchdog kills a VM that outlives its hard timeout.
    vm2 = vm_factory("uefi", disk, hard_timeout=4 / env.timeout_scale())
    with pytest.raises(QemuExited):
        vm2.wait_for(r"THIS NEVER APPEARS", timeout=60)
    assert vm2.hard_timeout_hit and not vm2.running


@pytest.mark.uefi
@pytest.mark.slow
def test_uefi_unsigned_payload_runs_without_secure_boot(vm_factory, sb_stub, workdir):
    """Baseline for the Secure Boot tests: with SB off, shim -> stub GRUB ->
    chainload of the unsigned payload works and prints its line."""
    vm = vm_factory("uefi", _copy(sb_stub["esp"], workdir))
    checks.check_ready(checks.wait_ready(vm), platform="efi", sb=0)
    vm.wait_record("chainload", prefix="BEAST_FIXTURE", timeout=60)


@pytest.mark.secureboot
@pytest.mark.slow
def test_sb_firmware_refuses_unsigned_loader(vm_factory, sb_stub, workdir):
    vm = vm_factory("uefi-sb", _copy(sb_stub["unsigned_esp"], workdir))
    vm.wait_for(r"Access Denied|Security Violation", timeout=60)
    vm.expect_absent(r"BEAST_FIXTURE", within=2)


@pytest.mark.secureboot
@pytest.mark.slow
def test_sb_shim_refuses_unenrolled_key(vm_factory, sb_stub, workdir):
    vm = vm_factory("uefi-sb", _copy(sb_stub["esp"], workdir))
    vm.wait_for(SHIM_REFUSAL, timeout=60)
    vm.expect_absent(r"BEAST: ready", within=3)


@pytest.mark.secureboot
@pytest.mark.slow
def test_sb_enrolled_mok_trusts_stub_and_refuses_unsigned_chainload(vm_factory, sb_stub, workdir):
    vm = vm_factory("uefi-sb", _copy(sb_stub["esp"], workdir), mok_certs=[sb_stub["cert"]])
    checks.check_ready(checks.wait_ready(vm), platform="efi", sb=1)
    err = vm.wait_record("error", timeout=60)
    assert err.text.startswith("error sb-verify-failed"), str(err)
    vm.expect_absent(r"BEAST_FIXTURE chainload", within=2)
