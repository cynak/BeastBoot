"""Real, official ISOs boot from a BeastBoot drive (tests/e2e/REAL_ISOS.md).

    BB_REAL_ISO=1 pytest -q tests/e2e/test_e2e_real_isos.py
    BB_REAL_ISO=1 BB_REAL_IDS=arch,ubuntu-desktop pytest -q tests/e2e/test_e2e_real_isos.py

Each case (ISO x mode x data filesystem) appends a line to out/real/results.jsonl
and keeps its serial log in out/real/logs/. Without BB_REAL_ISO=1 the real
cases skip; the harness unit tests and the bb_kargs dry run below always run.
"""

from __future__ import annotations

import os
import re

import pytest

from bbe2e import checks, env, images, realiso, trees

ENABLED = os.environ.get("BB_REAL_ISO") == "1"


def _real_params():
    try:
        entries = realiso.select(realiso.load())
    except ValueError as e:
        raise pytest.UsageError(str(e)) from None
    return [pytest.param(e, mode, fs, id=realiso.case_id(e, mode, fs),
                         marks=[pytest.mark.slow, pytest.mark.live, getattr(pytest.mark, mode), getattr(pytest.mark, fs)])
            for e in entries for mode, fs in realiso.cases(e)]


@pytest.fixture(scope="session")
def real_runner(qemu_ok, installer_ok, udisks_ok):
    if not env.kvm_usable():
        pytest.skip("real ISOs need KVM (/dev/kvm)")
    runner = realiso.Runner(realiso.select(realiso.load())).start()
    yield runner
    runner.pool.shutdown(wait=False, cancel_futures=True)


@pytest.mark.parametrize("entry,mode,fs", _real_params())
def test_real_iso(entry, mode, fs, request):
    if not ENABLED:
        pytest.skip("real ISOs: set BB_REAL_ISO=1 (downloads tens of GB once, needs KVM)")
    row = request.getfixturevalue("real_runner").result(realiso.case_id(entry, mode, fs))
    if row["status"] == "skip":
        pytest.skip(row["reason"])
    assert row["status"] == "pass", f"{row['status']}: {row['reason']} (recipe={row['recipe']}; log {row['log']})"


# ---------------------------------------------------------------------------
# bb_kargs in a real GRUB (fixture ISOs, dry run)
# ---------------------------------------------------------------------------

KARGS = "console=ttyS0,115200 bb.test=kargs"
BOTH = [pytest.param("bios", marks=pytest.mark.bios, id="bios"),
        pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")]


def _linux_line(vm, path: str):
    boot = vm.wait_record("boot", rf"^boot {re.escape(path)} recipe=", timeout=120)
    return boot, vm.wait_record("dryrun", r"^dryrun linux ", after=boot.start)


@pytest.mark.slow
@pytest.mark.parametrize("mode", BOTH)
@pytest.mark.parametrize("fixture,tail", [("casper", "splash ---"), ("anaconda", "quiet")])
def test_kargs_dryrun(mode, fixture, tail, make_drive, vm_factory):
    """bb_kargs words come last on the kernel command line, as separate words."""
    path = trees.recipe_path(fixture)
    extra = f'set bb_kargs="{KARGS}"\nexport bb_kargs'
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=path, extra=extra))
    vm = vm_factory(mode, drive.path)
    boot, lin = _linux_line(vm, path)
    assert checks.recipe_of(boot) == fixture, str(boot)
    assert any(v.endswith(f"{tail} {KARGS}") for v in lin.variants()), str(lin)


@pytest.mark.slow
@pytest.mark.parametrize("mode", [pytest.param("uefi", marks=pytest.mark.uefi, id="uefi")])
def test_kargs_empty_by_default(mode, make_drive, vm_factory):
    path = trees.recipe_path("casper")
    drive = make_drive("main", images.user_config(dryrun=True, autoboot=path))
    vm = vm_factory(mode, drive.path)
    _, lin = _linux_line(vm, path)
    assert any(v.endswith("splash ---") for v in lin.variants()), str(lin)


# ---------------------------------------------------------------------------
# Harness unit tests (no QEMU, no network)
# ---------------------------------------------------------------------------

def test_catalog_is_valid():
    entries = realiso.load()
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    for e in entries:
        if e["family"] == "windows":
            assert "ntfs" in e["fs"] and "kargs" not in e
        else:
            assert "console=ttyS0" in e.get("kargs", ""), e["id"]


def test_validate_rejects():
    good = {"id": "x", "family": "dracut", "name": "X", "version": "1", "url": "https://e.org/x.iso",
            "sha256_url": "https://e.org/SUMS", "size": 1, "recipe": "anaconda", "modes": ["uefi"],
            "fs": ["exfat"], "ram_mb": 1024, "timeout_s": 60, "kargs": "console=ttyS0", "success": ["a"]}
    assert realiso.validate({"v": 1, "isos": [good]}) == []
    bad = [dict(good, url="http://e.org/x.iso"), dict(good, sha256_url=None), dict(good, modes=["uefi-sb"]),
           dict(good, success=[]), dict(good, success=["("]), dict(good, kargs='a="b"'),
           dict(good, family="windows"), dict(good, sha256="ABC")]
    for b in bad:
        assert realiso.validate({"v": 1, "isos": [b]}), b
    assert realiso.validate({"v": 1, "isos": [good, good]})


def test_env_name():
    assert realiso.env_name("fedora-ws-live") == "BB_ISO_FEDORA_WS_LIVE"
    assert realiso.env_name("mint-22.3") == "BB_ISO_MINT_22_3"


def test_select():
    es = [{"id": "a"}, {"id": "b"}]
    assert realiso.select(es, "") == es
    assert realiso.select(es, "b") == [{"id": "b"}]
    with pytest.raises(ValueError):
        realiso.select(es, "c")


H1, H2 = "a" * 64, "b" * 64


def test_parse_and_pick_checksums():
    gnu = f"{H1}  one.iso\n{H2} *two.iso\n"
    assert realiso.pick(realiso.parse_sums(gnu, "sha256"), ["two.iso"]) == (H2, "two.iso")
    bsd = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n# one.iso: 5 bytes\nSHA256 (One.ISO) = {H1.upper()}\n"
    assert realiso.pick(realiso.parse_sums(bsd, "sha256"), ["one.iso"]) == (H1, "One.ISO")
    # never guesses between entries for other files
    assert realiso.pick(realiso.parse_sums(gnu, "sha256"), ["three.iso"]) is None
    # one line for a rotating link (Tumbleweed -Current): it names the real file
    one = f"{H1}  openSUSE-Tumbleweed-NET-x86_64-Snapshot20261024-Media.iso\n"
    assert realiso.pick(realiso.parse_sums(one, "sha256"), ["openSUSE-Tumbleweed-NET-x86_64-Current.iso"]) == \
        (H1, "openSUSE-Tumbleweed-NET-x86_64-Snapshot20261024-Media.iso")
    s512 = "c" * 128
    both = f"{s512}  x.iso\n{H1}  x.iso\n"
    assert realiso.parse_sums(both, "sha512") == [(s512, "x.iso")]
    assert realiso.parse_sums(both, "sha256") == [(H1, "x.iso")]
    assert realiso.parse_sums(H1 + "\n", "sha256") == [(H1, None)]


def test_expected_uses_catalog_then_checksum_file():
    e = {"id": "x", "url": "https://e.org/d/x.iso", "sha256_url": "https://e.org/d/SUMS"}
    exp = realiso.expected(e, get=lambda url: f"{H2}  y.iso\n{H1}  x.iso\n")
    assert (exp.algo, exp.hex, exp.name) == ("sha256", H1, "x.iso")
    exp = realiso.expected(dict(e, sha256=H2), get=None)
    assert (exp.hex, exp.source) == (H2, "catalog")
    with pytest.raises(realiso.Stale, match="catalog stale"):  # listed no more: a failure, not a skip
        realiso.expected(e, get=lambda url: f"{H2}  y.iso\n{H1}  z.iso\n")
    with pytest.raises(realiso.Unverifiable):
        realiso.expected({"id": "nohash-unit-test", "url": "https://e.org/x.iso", "unverifiable": "none published"})


def test_config_and_sizes():
    cfg = realiso.config_text({"kargs": "console=ttyS0,115200 quiet"})
    assert 'set bb_kargs="console=ttyS0,115200 quiet"' in cfg and "export bb_kargs" in cfg
    assert 'set bb_debug="1"' in cfg and 'set timeout="5"' in cfg
    assert "bb_kargs" not in realiso.config_text({})
    assert realiso.drive_size(1) == "3G" and realiso.drive_size(6482409472) == "9G"
