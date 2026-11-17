"""Disk tools end to end, clone/restore breadth and rescue with real read errors
(docs/DISK_TOOLS.md sections 1, 6, 7).

Every flow runs under the byte-exact gate (tests/e2e/bbe2e/disks.py): each source image
is hashed before and after; the result on the target is checked against the fixture
manifest's file hashes or by a byte compare with the source.

* clone/restore: MBR disk, a larger and an equal-size target (extra space, GPT backup
  header), 4Kn and 512e disks incl. the refusal of a sector-size mismatch, a USB target,
  an assembled md RAID1 / LVM LV / opened LUKS volume as the source (clone, and image to a
  file then restore to another disk), stop and resume of a clone (QEMU killed mid-copy);
* rescue: the helper's real ddrescue against a source whose reads fail on chosen
  sectors (QEMU blkdebug): start, middle, a large region; the mapfile, every readable
  byte, the bad-area count, stop and resume from the mapfile.

Fixtures: `python tests/e2e/fixtures/disks.py build` (sets mbr, gpt4k plus the existing
ones); random-data sources are made on the host.
"""

# ruff: noqa: F811  (the fixtures of test_e2e_disks.py are imported and used as arguments)
from __future__ import annotations

import time
from pathlib import Path

import pytest

from bbe2e import disks as dk
from bbe2e import env
from test_e2e_disks import (  # noqa: F401  (fixtures used by name)
    EVERY_MODE, PLAN_TIMEOUT, UEFI, Fw, attach, dt_drive, features, fw, kvm, manifest, match_stack, need, run_plan,
    scan_group,
)

pytestmark = [pytest.mark.slow, pytest.mark.beastnet]

MIB = dk.MIB
PATTERN = 0x5A           # what a blank target holds where the copy must not write
TAIL = 4 * MIB           # size of the patterned region checked behind the copied data


def copy_ok(vm, boot, kinds: list[str]) -> list[dict]:
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm, boot.boot_end)
    dones = dk.events(vm, "copy done", boot.boot_end)
    assert [d["kind"] for d in dones] == kinds, dones
    assert all(d["errors"] == "0" for d in dones), dones
    return dones


def patterned_target(path: Path, size: int, serial: str, **kw) -> dk.Attached:
    """A blank target with a recognisable pattern in its first MiB and in a region just
    behind `data_end` (set later with fill_range) so stray writes show."""
    return dk.blank_disk(path, size, serial, fill=PATTERN, **kw)


def ext4_files_ok(img: Path, offset: int, files: list[dict], workdir: Path) -> None:
    spec = f"{img}?offset={offset}" if offset else img
    for f in files:
        assert dk.ext4_sha256(spec, f["path"], workdir) == f["sha256"], (img.name, f["path"])


def vol(manifest, set_name: str, fs: str) -> dict:
    return next(v for v in manifest["sets"][set_name]["stacks"][0]["volumes"] if v["fs"] == fs)


# ---------------------------------------------------------------------------
# Whole disks: MBR, larger and equal targets, GPT backup header
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("set_name", ["mbr", "gpt"])
def test_clone_equal_size_target(set_name, manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    src = attach(manifest, set_name)[0]
    target = patterned_target(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    copy_ok(vm, boot, ["clone"])
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path), "equal-size clone differs from the source"


@pytest.mark.parametrize("set_name", ["mbr", "gpt"])
def test_clone_larger_target(set_name, manifest, dt_drive, vm_factory, features, workdir):
    """The source's bytes land at the start; the extra space stays as it was, except the GPT
    backup header and table, which move to the end of the larger disk (DISK_TOOLS.md s.6 note)."""
    need(features, "discover", "copy")
    src = attach(manifest, set_name)[0]
    size = src.path.stat().st_size
    tsize = size + 96 * MIB
    target = patterned_target(workdir / "target.img", tsize, dk.TARGET_SERIAL)
    dk.fill_range(target.path, size, TAIL, PATTERN)                   # just behind the copied data
    dk.fill_range(target.path, tsize - 40 * MIB, TAIL, PATTERN)       # well before the end
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    copy_ok(vm, boot, ["clone"])
    st = manifest["sets"][set_name]["stacks"][0]
    for v in st["volumes"]:  # every partition byte-exact
        off, n = v["start_sector"] * 512, v["sectors"] * 512
        assert dk.sha256_range(target.path, off, n) == dk.sha256_range(src.path, off, n), (set_name, v["partition"])
        if v["fs"] == "ext4":
            ext4_files_ok(target.path, off, v["files"], workdir)
    assert dk.read_range(target.path, tsize - 40 * MIB, TAIL) == bytes([PATTERN]) * TAIL, \
        "the copy wrote into the extra space of the larger target"
    if set_name == "mbr":
        assert dk.sha256_range(target.path, 0, size) == dk.sha256_file(src.path), "MBR clone differs in its first bytes"
        assert dk.read_range(target.path, size, TAIL) == bytes([PATTERN]) * TAIL
        return
    last = tsize // 512 - 1
    prim, back = dk.gpt_header(target.path, 1, 512), dk.gpt_header(target.path, last, 512)
    sprim = dk.gpt_header(src.path, 1, 512)
    assert prim and prim["alt"] == last, f"primary GPT header still points at the old backup: {prim}"
    assert back and back["my"] == last and back["alt"] == 1, f"no GPT backup header at the end of the target: {back}"
    assert prim["entries_crc"] == sprim["entries_crc"] == back["entries_crc"], (prim, back, sprim)


# ---------------------------------------------------------------------------
# Sector sizes: 4Kn and 512e
# ---------------------------------------------------------------------------

def test_clone_4kn_to_4kn(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    src = attach(manifest, "gpt4k")[0]
    assert src.lbs == 4096 and src.transport == "nvme", src
    target = patterned_target(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL, transport="nvme")
    target.lbs = 4096
    steps = [{"op": "scan"},
             {"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    found = dk.wait_disks(vm, [src.serial, target.serial], after=boot.boot_end)
    assert found[src.serial]["lss"] == "4096" and found[target.serial]["lss"] == "4096", found
    copy_ok(vm, boot, ["clone"])
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path)
    v = vol(manifest, "gpt4k", "ext4")
    ext4_files_ok(target.path, v["start_sector"] * 4096, v["files"], workdir)


@pytest.mark.parametrize("side", ["source", "target"])
def test_clone_512e(side, manifest, dt_drive, vm_factory, features, workdir):
    """512-byte logical, 4096-byte physical sectors on one side: same logical size, so allowed.
    The 512e disk is AHCI (QEMU's NVMe does not report a physical block size to Linux)."""
    need(features, "discover", "copy")
    src = attach(manifest, "gpt")[0]
    src.transport = "ahci" if side == "source" else "nvme"
    target = patterned_target(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL,
                              transport="ahci" if side == "target" else "nvme")
    (src if side == "source" else target).pbs = 4096
    steps = [{"op": "scan"},
             {"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    found = dk.wait_disks(vm, [src.serial, target.serial], after=boot.boot_end)
    e = found[src.serial if side == "source" else target.serial]
    assert e["lss"] == "512" and e["pss"] == "4096", e
    copy_ok(vm, boot, ["clone"])
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path)


@pytest.mark.parametrize("direction", ["4kn-to-512", "512-to-4kn"])
def test_refuse_clone_with_different_sector_size(direction, manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    src = attach(manifest, "gpt4k" if direction == "4kn-to-512" else "gpt")[0]
    src.transport = "nvme"
    target = patterned_target(workdir / "target.img", 256 * MIB, dk.TARGET_SERIAL, transport="nvme")
    target.lbs = 512 if direction == "4kn-to-512" else 4096
    before = dk.sha256_file(target.path)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    errs = dk.errors(vm, boot.boot_end)
    assert errs and errs[0].startswith("error disk-refused") and "sector" in errs[0], errs
    assert not dk.events(vm, "copy start", boot.boot_end)
    assert dk.sha256_file(target.path) == before, "the refused target was written"


def test_refuse_restore_of_4kn_image_to_512_disk(manifest, dt_drive, vm_factory, features, workdir):
    """The image records its sector size (.info.json); restoring it raw to another size is refused."""
    need(features, "discover", "copy")
    src = attach(manifest, "gpt4k")[0]
    images = dk.images_disk(workdir / "images.img", 1024, transport="nvme")
    target = patterned_target(workdir / "target.img", 256 * MIB, dk.TARGET_SERIAL)
    before = dk.sha256_file(target.path)
    steps = [{"op": "use_disk", "disk": dk.IMAGES_SERIAL, "confirm": dk.confirm(dk.IMAGES_SERIAL)},
             {"op": "image", "source": src.serial, "dest": "/images/gpt4k.img", "on": dk.IMAGES_SERIAL},
             {"op": "restore", "image": "/images/gpt4k.img", "on": dk.IMAGES_SERIAL, "target": target.serial,
              "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, images, target], steps)
    errs = dk.errors(vm, boot.boot_end)
    assert errs and errs[0].startswith("error disk-refused") and "sector" in errs[0], errs
    assert dk.sha256_file(target.path) == before, "the refused restore target was written"
    assert not [d for d in dk.events(vm, "copy start", boot.boot_end) if d["kind"] == "restore"]
    assert [d["kind"] for d in dk.events(vm, "copy done", boot.boot_end)] == ["image"]
    info = workdir / "info.json"
    assert dk.ext4_read(images.path, "/images/gpt4k.img.info.json", info) and '"logical_sector": 4096' in info.read_text()


# ---------------------------------------------------------------------------
# A USB target
# ---------------------------------------------------------------------------

def test_clone_to_usb_target(manifest, dt_drive, vm_factory, features, workdir):
    """A target on usb-storage (the usual external disk). QEMU gives it a serial (USB
    iSerial and SCSI VPD page 0x80)."""
    need(features, "discover", "copy")
    src = attach(manifest, "gpt")[0]
    target = patterned_target(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL, transport="usb")
    steps = [{"op": "scan"},
             {"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    copy_ok(vm, boot, ["clone"])
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path)


# ---------------------------------------------------------------------------
# Volumes as the source: md RAID1, LVM LV, opened LUKS
# ---------------------------------------------------------------------------

VOLUMES = {
    # name: (scan group, set, stack name in the manifest)
    "md-raid1": ("md-a", "md-a", "raid1"),
    "lvm-lv": ("lvm", "lvm", "datavg"),
    "luks": ("luks", "luks", "luks"),
}


def volume_source(name, manifest, vm_factory, dt_drive):
    group, set_name, stack = VOLUMES[name]
    st = next(s for s in manifest["sets"][set_name]["stacks"] if s["name"] == stack)
    scan = scan_group(group, manifest, vm_factory, dt_drive)
    f = match_stack(scan["stacks"], st)
    assert f, f"{stack} not detected; see test_stacks_detected"
    step = {"op": "assemble", "stack": f["id"]}
    if st["kind"] == "luks":
        step["passphrase"] = manifest["passphrase"]
    return st, f["id"], step, attach(manifest, *({"lvm": ["lvm", "lvm-dup"]}.get(group, [set_name])))


def check_volume_on(target: Path, st: dict, manifest, workdir: Path, size: int | None) -> None:
    v = st["volumes"][0]
    ext4_files_ok(target, 0, v["files"], workdir)
    if st["kind"] == "md" and st["level"] == "1" and size:
        md = manifest["sets"]["md-a"]
        member = next(d for d in md["disks"] if d["serial"] == st["slot_serials"][0])
        off = st["examine"]["data_offset_bytes"]
        assert dk.sha256_range(target, 0, size) == dk.sha256_range(Path(member["path"]), off, size), \
            "the cloned RAID1 volume differs from the member's data area"


@pytest.mark.parametrize("name", list(VOLUMES))
def test_clone_volume_to_disk(name, manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "assemble", "copy", {"md-raid1": "mdadm", "lvm-lv": "lvm", "luks": "cryptsetup"}[name])
    st, sid, assemble, members = volume_source(name, manifest, vm_factory, dt_drive)
    tsize = 256 * MIB
    target = patterned_target(workdir / "target.img", tsize, dk.TARGET_SERIAL)
    dk.fill_range(target.path, tsize - TAIL, TAIL, PATTERN)
    steps = [assemble, {"op": "clone", "source": sid, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate(members, manifest):
        vm, boot = run_plan(vm_factory, dt_drive, members + [target], steps)
    dones = copy_ok(vm, boot, ["clone"])
    size = int(dones[0]["bytes"])
    check_volume_on(target.path, st, manifest, workdir, size)
    assert dk.read_range(target.path, tsize - TAIL, TAIL) == bytes([PATTERN]) * TAIL, "wrote past the volume's size"


@pytest.mark.parametrize("name", list(VOLUMES))
def test_image_volume_then_restore_to_another_disk(name, manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "assemble", "copy", {"md-raid1": "mdadm", "lvm-lv": "lvm", "luks": "cryptsetup"}[name])
    st, sid, assemble, members = volume_source(name, manifest, vm_factory, dt_drive)
    images = dk.images_disk(workdir / "images.img", 1024, transport="nvme")
    target = patterned_target(workdir / "target.img", 256 * MIB, dk.TARGET_SERIAL)
    steps = [assemble,
             {"op": "use_disk", "disk": dk.IMAGES_SERIAL, "confirm": dk.confirm(dk.IMAGES_SERIAL)},
             {"op": "image", "source": sid, "dest": f"/images/{name}.img", "on": dk.IMAGES_SERIAL},
             {"op": "restore", "image": f"/images/{name}.img", "on": dk.IMAGES_SERIAL, "target": target.serial,
              "confirm": dk.confirm(target.serial)}]
    with dk.gate(members, manifest):
        vm, boot = run_plan(vm_factory, dt_drive, members + [images, target], steps)
    dones = copy_ok(vm, boot, ["image", "restore"])
    size = int(dones[0]["bytes"])
    dump = workdir / "volume.img"
    assert dk.ext4_read(images.path, f"/images/{name}.img", dump)
    assert dump.stat().st_size == size, (dump.stat().st_size, size)
    if dones[0].get("sha256", "-") != "-":
        assert dones[0]["sha256"] == dk.sha256_file(dump)
    assert dk.sha256_range(target.path, 0, size) == dk.sha256_file(dump), "restored target differs from the image"
    check_volume_on(target.path, st, manifest, workdir, size)


# ---------------------------------------------------------------------------
# Stop and resume (power cut mid-copy: QEMU is killed, the plan runs again)
# ---------------------------------------------------------------------------

def run_until_progress(vm_factory, drive, attached, steps, *, fraction: float, min_s: float, total: int,
                       fw: Fw = UEFI):
    """Boot, wait until the copy is at least `fraction` done and `min_s` seconds old (ddrescue
    saves its mapfile every 30 s; the page cache needs a few more), then kill QEMU."""
    dk.write_plan(drive, dk.plan(*steps))
    boot = dk.boot_helper(vm_factory, drive, attached, mode=fw.mode, mok_certs=fw.mok_certs)
    vm = boot.vm
    dk.wait_events(vm, "copy start", 1, after=boot.boot_end, timeout=240)
    t0 = time.monotonic()
    while True:
        prog = dk.events(vm, "copy progress", boot.boot_end)
        done = int(prog[-1]["done"]) if prog else 0
        if done >= fraction * total and time.monotonic() - t0 >= min_s:
            break
        assert vm.running and not dk.events(vm, "copy done", boot.boot_end), \
            "the copy finished before it could be stopped (raise the throttling)"
        assert time.monotonic() - t0 < env.t(PLAN_TIMEOUT), f"no progress: {prog[-1:]}"
        time.sleep(1)
    vm.stop()  # SIGKILL: a power cut
    return boot, done


def first_progress(vm, boot) -> int:
    prog = dk.wait_events(vm, "copy progress", 1, after=boot.boot_end, timeout=240)
    return int(prog[0]["done"])


def repaired_stick(vm, boot) -> None:
    """After the power cut the stick's FAT is dirty: Disk tools check it before the copy."""
    ev = dk.events(vm, "fs repair", boot.boot_end)
    assert ev and ev[0]["fs"] == "vfat" and ev[0]["result"] in ("fixed", "clean"), ev


def test_clone_stop_and_resume(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    size = 192 * MIB
    src = dk.random_disk(workdir / "source.img", size, "BBRND001", "resume-clone")
    target = patterned_target(workdir / "target.img", size, dk.TARGET_SERIAL)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    src.throttle_bps = 2 * MIB
    with dk.gate([src]):
        b1, done1 = run_until_progress(vm_factory, dt_drive, [src, target], steps, fraction=0.4, min_s=75, total=size)
        maps = dk.stick_mapfiles(dt_drive)
        src.throttle_bps = 0
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    assert len(maps) == 1, f"no ddrescue mapfile on the stick after the power cut: {maps}"
    copy_ok(vm, boot, ["clone"])
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path), "resumed clone differs from the source"
    resumed_at = first_progress(vm, boot)
    assert None not in maps.values(), "the mapfile was unreadable after the power cut (FAT clusters not written)"
    assert resumed_at > 0, f"the second run started from zero instead of the mapfile (first run reached {done1})"
    repaired_stick(vm, boot)


# ---------------------------------------------------------------------------
# Rescue: real ddrescue, real read errors (QEMU blkdebug on the source)
# ---------------------------------------------------------------------------

RESCUE_SIZE = 64 * MIB
BAD = [(0, 8), (65536, 16), (98304, 2048)]   # (first sector, count): start, middle, a 1 MiB region
BAD_BYTES = sum(n for _, n in BAD) * 512


def rescue_source(workdir: Path, seed: str) -> dk.Attached:
    src = dk.random_disk(workdir / "failing.img", RESCUE_SIZE, "BBBAD001", seed)
    src.blkdebug = dk.blkdebug_config(workdir / "blkdebug.conf", BAD)
    return src


def bad_ranges_bytes() -> list[tuple[int, int]]:
    return [(s * 512, n * 512) for s, n in BAD]


def check_rescued(target: Path, src: Path) -> None:
    """Every readable byte equals the source; the bad ranges keep the target's pattern."""
    pos = 0
    for off, n in bad_ranges_bytes():
        if off > pos:
            assert dk.sha256_range(target, pos, off - pos) == dk.sha256_range(src, pos, off - pos), \
                f"readable bytes {pos}..{off} differ"
        pos = off + n
    assert dk.sha256_range(target, pos, RESCUE_SIZE - pos) == dk.sha256_range(src, pos, RESCUE_SIZE - pos)


def check_mapfile(text: bytes) -> None:
    blocks = dk.parse_mapfile(text.decode("ascii", "replace"))
    bad = [(p, n) for p, n, s in blocks if s == "-"]
    assert bad == bad_ranges_bytes(), f"mapfile bad areas {bad} != injected {bad_ranges_bytes()}"
    assert sum(n for p, n, s in blocks if s == "+") == RESCUE_SIZE - BAD_BYTES, blocks
    assert sum(n for _, n, _s in blocks) == RESCUE_SIZE, blocks


def rescue_results(vm, boot) -> dict:
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm, boot.boot_end)
    done = dk.events(vm, "copy done", boot.boot_end)
    assert len(done) == 1, done
    prog = dk.events(vm, "copy progress", boot.boot_end)
    return {"done": done[0], "last_progress": prog[-1] if prog else {}}


def check_counts(r: dict) -> None:
    """errors= is the number of bad areas in both lines; unread= the bytes not recovered."""
    for line in (r["done"], r["last_progress"]):
        assert int(line["errors"]) == len(BAD) and int(line["unread"]) == BAD_BYTES, r


def test_rescue_clone_with_bad_sectors(dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy", "ddrescue")
    src = rescue_source(workdir, "rescue-clone")
    target = patterned_target(workdir / "target.img", RESCUE_SIZE, dk.TARGET_SERIAL)
    dk.fill_range(target.path, 0, RESCUE_SIZE, PATTERN)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src]):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    r = rescue_results(vm, boot)
    check_counts(r)
    check_rescued(target.path, src.path)
    for off, n in bad_ranges_bytes():
        assert dk.read_range(target.path, off, n) == bytes([PATTERN]) * n, f"bad area at {off} was filled in"
    maps = dk.stick_mapfiles(dt_drive)
    assert len(maps) == 1 and None not in maps.values(), f"one readable mapfile expected on the stick: {maps}"
    check_mapfile(next(iter(maps.values())))


def test_rescue_image_with_bad_sectors(dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy", "ddrescue")
    src = rescue_source(workdir, "rescue-image")
    images = dk.images_disk(workdir / "images.img", 256, transport="nvme")
    steps = [{"op": "use_disk", "disk": dk.IMAGES_SERIAL, "confirm": dk.confirm(dk.IMAGES_SERIAL)},
             {"op": "image", "source": src.serial, "dest": "/images/failing.img", "on": dk.IMAGES_SERIAL}]
    with dk.gate([src]):
        vm, boot = run_plan(vm_factory, dt_drive, [src, images], steps)
    r = rescue_results(vm, boot)
    check_counts(r)
    dump = workdir / "failing.dump"
    assert dk.ext4_read(images.path, "/images/failing.img", dump)
    check_rescued(dump, src.path)
    mf = workdir / "failing.map"
    if dk.ext4_read(images.path, "/images/failing.img.map", mf):
        text = mf.read_bytes()
    else:
        maps = dk.stick_mapfiles(dt_drive)
        assert len(maps) == 1 and None not in maps.values(), f"no mapfile next to the image or on the stick: {maps}"
        text = next(iter(maps.values()))
    check_mapfile(text)


@pytest.mark.parametrize("fw", EVERY_MODE, indirect=True)
def test_rescue_stop_and_resume(fw, dt_drive, vm_factory, features, workdir):
    """Power cut during a rescue; the second run continues from the mapfile and ends with
    the same result as an uninterrupted one. In every firmware mode: this one test covers
    real read errors, the mapfile on the stick, the stick's FAT check and the resume."""
    need(features, "discover", "copy", "ddrescue")
    src = rescue_source(workdir, "rescue-resume")
    target = patterned_target(workdir / "target.img", RESCUE_SIZE, dk.TARGET_SERIAL)
    dk.fill_range(target.path, 0, RESCUE_SIZE, PATTERN)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    src.throttle_bps = MIB // 2
    with dk.gate([src]):
        b1, done1 = run_until_progress(vm_factory, dt_drive, [src, target], steps, fraction=0.5, min_s=75,
                                       total=RESCUE_SIZE, fw=fw)
        maps = dk.stick_mapfiles(dt_drive)
        src.throttle_bps = 0
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps, fw=fw)
    assert len(maps) == 1, f"no mapfile on the stick after the power cut: {maps}"
    r = rescue_results(vm, boot)
    check_counts(r)
    check_rescued(target.path, src.path)
    repaired_stick(vm, boot)
    after = dk.stick_mapfiles(dt_drive)
    assert len(after) == 1 and None not in after.values(), after
    check_mapfile(next(iter(after.values())))
    first = next(iter(maps.values()))
    assert first is not None, "the mapfile was unreadable after the power cut (FAT clusters not written)"
    saved = sum(n for _p, n, s in dk.parse_mapfile(first.decode()) if s == "+")
    assert saved > 0, f"the mapfile saved before the power cut records nothing: {first[:400]!r}"
    resumed_at = first_progress(vm, boot)
    assert resumed_at >= saved, f"resume started at {resumed_at}, the mapfile had {saved} (first run reached {done1})"


def test_rescue_refuses_a_damaged_mapfile_and_starts_over(dt_drive, vm_factory, features, workdir):
    """A saved mapfile that does not match its own checksum is never used: the plan stops
    with `error copy ... cannot be trusted` before anything is written; with "restart": true
    the copy starts over and ends with the same result."""
    need(features, "discover", "copy", "ddrescue")
    src = rescue_source(workdir, "rescue-damaged")
    target = patterned_target(workdir / "target.img", RESCUE_SIZE, dk.TARGET_SERIAL)
    dk.fill_range(target.path, 0, RESCUE_SIZE, PATTERN)
    step = {"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}
    with dk.gate([src]):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], [step])
        check_counts(rescue_results(vm, boot))
        (name, text), = dk.stick_mapfiles(dt_drive).items()
        lines = text.decode().splitlines()
        i = next(n for n, x in enumerate(lines) if x.split()[2:3] == ["-"])
        lines[i] = lines[i][:-1] + "+"          # a bad area now claims to be copied
        with dt_drive.data_writer() as w:
            w.put(f"/disk-tools/{name}", "\n".join(lines) + "\n")
        before = dk.sha256_file(target.path)
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], [step])
        errs = dk.errors(vm, boot.boot_end)
        assert errs and errs[0].startswith("error copy") and "cannot be trusted" in errs[0], errs
        assert not dk.events(vm, "copy start", boot.boot_end)
        assert dk.sha256_file(target.path) == before, "the target was written with an untrusted map"
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], [{**step, "restart": True}])
    r = rescue_results(vm, boot)
    check_counts(r)
    with dt_drive.data_writer() as w:   # the damaged map is set aside, never used again
        names = [e.rsplit("/", 1)[-1] for e in w.listing("/disk-tools")]
    assert name + ".untrusted" in names, names
    check_rescued(target.path, src.path)
    maps = dk.stick_mapfiles(dt_drive)
    assert len(maps) == 1 and None not in maps.values(), maps
    check_mapfile(next(iter(maps.values())))
