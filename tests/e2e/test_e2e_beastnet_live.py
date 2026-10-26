"""Live: beast-net downloads real ISOs from official sources in the QEMU lab.

Opt-in (BB_LIVE_NET=1): each test downloads several GB over the internet.

The chain is the real one, nothing is served locally: the menu's "Download an
ISO from a link" entry -> the helper (script mode) gets an address from QEMU
user networking, which reaches the internet through this computer -> HTTPS
download from the official link, with beast-net's own headers, redirects and
CA bundle -> SHA-256 check against the vendor's checksum file (when there is
one) -> one-shot entry -> reboot -> the menu opens the downloaded ISO and
detects its recipe (dry run). The drive is a fresh 16 GiB exFAT image, so
ISOs over 4 GiB fit (Windows 11 is about 8 GiB).

Sources: tests/e2e/live_sources.json, the entries with "vm": true unless
  BB_LIVE_SOURCE=id[,id...]   picks entries by id, or
  BB_LIVE_URL=<link>          tests any link (plus BB_LIVE_SHA256_URL or
                              BB_LIVE_SHA256, BB_LIVE_RECIPE optional).
BB_LIVE_TIMEOUT: seconds allowed for one download (default 5400).
The quick check without a VM is scripts/check_iso_sources.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

import pytest

from bbe2e import beastnet as bn
from bbe2e import env, images

sys.path.insert(0, str(env.BB_ROOT / "beastnet" / "python"))
from beastnet.checksums import normalize_sha256  # noqa: E402

pytestmark = [pytest.mark.slow, pytest.mark.beastnet, pytest.mark.live, pytest.mark.exfat, pytest.mark.uefi]

CATALOG = Path(__file__).with_name("live_sources.json")
TIMEOUT = float(os.environ.get("BB_LIVE_TIMEOUT", "5400"))
IMAGE_SIZE = os.environ.get("BB_LIVE_IMAGE_SIZE", "16G")


def live_sources() -> list:
    if os.environ.get("BB_LIVE_URL"):
        try:
            sha = normalize_sha256(os.environ.get("BB_LIVE_SHA256") or None)  # as beast-net reads it
        except ValueError as e:
            raise pytest.UsageError(f"BB_LIVE_SHA256: {e}") from None
        src = {"id": "custom", "name": "BB_LIVE_URL", "url": os.environ["BB_LIVE_URL"],
               "sha256_url": os.environ.get("BB_LIVE_SHA256_URL") or None, "sha256": sha,
               "recipe": os.environ.get("BB_LIVE_RECIPE") or None}
        return [pytest.param(src, id="custom")]
    catalog = json.loads(CATALOG.read_text())["sources"]
    wanted = [s.strip() for s in os.environ.get("BB_LIVE_SOURCE", "").split(",") if s.strip()]
    if wanted:
        unknown = sorted(set(wanted) - {s["id"] for s in catalog})
        if unknown:
            raise pytest.UsageError(f"BB_LIVE_SOURCE: unknown id(s) {', '.join(unknown)} (see {CATALOG.name})")
        picked = [s for s in catalog if s["id"] in wanted]
    else:
        picked = [s for s in catalog if s.get("vm")]
    return [pytest.param(s, id=s["id"]) for s in picked]


@pytest.fixture(autouse=True)
def live_enabled():
    if os.environ.get("BB_LIVE_NET") != "1":
        pytest.skip("live download from the internet: set BB_LIVE_NET=1 (downloads several GB)")


@pytest.fixture
def helper(dist_dir):
    d = dist_dir / "esp" / "beast-net"
    missing = env.missing_files([d / "vmlinuz", d / "initrd.img", d / "VERSION"])
    if missing:
        pytest.skip("dist/ has no beast-net helper (make build): " + ", ".join(missing))


def file_on_drive(drive: images.Drive, path: str) -> tuple[int, str, bool] | None:
    """(size, SHA-256, starts like ISO 9660) of a file on the exFAT data partition."""
    with drive.data_writer() as w:
        f = w.root / path.lstrip("/")
        if not f.is_file():
            return None
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            head = fh.read(64 * 1024)
            h.update(head)
            for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
                h.update(chunk)
        return f.stat().st_size, h.hexdigest(), head[0x8001:0x8006] == b"CD001"


def part_exists(drive: images.Drive, path: str) -> bool:
    with drive.data_writer() as w:
        return (w.root / (path.lstrip("/") + ".part")).exists()


@pytest.mark.parametrize("src", live_sources())
def test_live_download_and_boot(src, udisks_ok, helper, dist_dir, workdir, vm_factory):
    dest = f"/downloads/{src['id']}.iso"
    image = workdir / "live.img"
    images.install(image, layout="msdos", fs="exfat", size=IMAGE_SIZE, dist=dist_dir, serial=True)
    drive = images.Drive.open(image, "msdos", "exfat")
    drive.write_config(bn.config(script=bn.PLAN_PATH))
    bn.write_plan(drive, {"network": {"type": "ethernet"}, "url": src["url"], "sha256": src.get("sha256"),
                          "sha256_url": src.get("sha256_url"), "dest": dest, "then": "reboot"})

    vm = vm_factory("uefi", drive.path, memory=1536, hard_timeout=TIMEOUT + 900, extra_args=list(bn.NET_ARGS))
    boot = bn.select_entry(vm)
    up = bn.fields(bn.wait_line(vm, "(?:net up|error) ", timeout=240, after=boot.end))
    assert "ip" in up, f"no network in the lab VM: {bn.lines(vm, boot.end)[-5:]}"
    start = bn.wait_line(vm, "(?:download start|error) ", timeout=600, after=boot.end)
    assert start.startswith("download start "), start  # an error here: link, TLS, checksum file
    end = bn.wait_line(vm, "(?:download done|error) ", timeout=TIMEOUT, after=boot.end)
    assert end.startswith("download done "), f"{src['name']}: {end}"
    done = bn.fields(end)
    assert done.get("path") == dest, done
    size, digest = int(done["bytes"]), done["sha256"]
    if src.get("sha256_url") or src.get("sha256"):
        ok = bn.wait_line(vm, "verify (?:ok|fail) ", timeout=300, after=boot.end)
        assert ok == f"verify ok sha256={digest}", ok
    assert bn.wait_line(vm, "handoff ", timeout=120, after=boot.end) == f"handoff oneshot={dest}"
    vm.wait_exit(timeout=180)
    assert not [ln for ln in bn.lines(vm) if ln.startswith("error ")], bn.lines(vm)[-10:]

    # What is on the drive is exactly what beast-net hashed (and the vendor published).
    # ...and it is an ISO image, not for example an HTML page a link led to.
    assert file_on_drive(drive, dest) == (size, digest, True)
    if src.get("sha256"):
        assert digest == src["sha256"]
    if src.get("min_bytes"):
        assert size >= src["min_bytes"], size
    assert not part_exists(drive, dest)
    assert bn.read_grubenv(drive).get("bb_oneshot") == dest

    # Reboot: the menu opens the downloaded ISO once and detects how it boots.
    drive.write_config(bn.config(dryrun=True))
    vm2 = vm_factory("uefi", drive.path, memory=1536, hard_timeout=600)
    ready = vm2.wait_record("ready", timeout=120)
    one = vm2.wait_record("oneshot", timeout=60, after=ready.start)
    assert one.contains(f"oneshot {dest}"), str(one)
    rec = vm2.wait_record("boot", rf"^boot {re.escape(dest)} recipe=", after=one.start)
    recipe = rec.fields.get("recipe")
    assert recipe not in (None, "", "none"), f"the menu found no way to boot the download: {rec}"
    if src.get("recipe"):
        assert recipe == src["recipe"], str(rec)
    if recipe == "casper":
        fsmod = vm2.wait_record("fsmod", after=rec.start)
        assert fsmod.has_token("exfat"), str(fsmod)  # Ubuntu: the exFAT add-on is used
        vm2.wait_record("dryrun", r"^dryrun initrd ", after=rec.start)
    elif recipe == "windows":
        vm2.wait_record("dryrun", r"^dryrun linux(16)? .*/beast-booter/wimboot", after=rec.start)
    vm2.stop()
    assert bn.read_grubenv(drive).get("bb_oneshot", "") == "", "bb_oneshot was not cleared"
