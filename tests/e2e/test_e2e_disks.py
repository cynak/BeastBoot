"""Disk tools end to end (docs/DISK_TOOLS.md): QEMU boots the beast-net helper with
fixture disks attached (NVMe and AHCI), runs a script-mode plan (`"action": "disk"`)
and the host checks the BEASTNET: event lines, the files imaged out of the
volumes, and that no source image changed by a single byte (the gate).

Fixtures: `python tests/e2e/fixtures/disks.py build` (needs docker --privileged).
Tests skip with a reason when KVM, the fixtures or a helper feature is missing;
the harness parts that need no Disk tools run today (gate self-test, fixture
self-check, a helper boot with all the disks attached under the gate).

Contract points the tests ASSUME and which other engineers must confirm
(each is one constant or function below):
  * stack kinds are md / imsm / ddf / lvm / luks / btrfs (KIND_ALIASES), levels "raid5" or "5"
  * a degraded stack's `state` contains "degrad"
  * `image` accepts a stack id as `source` for a single-volume stack
  * `assemble` accepts "passphrase" for LUKS
  * `dest` / `image` paths are on the images disk (an ext4 disk, IMAGES_SERIAL)
  * `reconstruct candidate order=` lists, per true slot, the index into the given members
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from bbe2e import beastnet as bn
from bbe2e import disks as dk
from bbe2e import env

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import disks as fx  # noqa: E402

pytestmark = [pytest.mark.slow, pytest.mark.beastnet]

PLAN_TIMEOUT = 420
KIND_ALIASES = {"md": {"md", "mdraid", "raid"}, "imsm": {"imsm"}, "ddf": {"ddf"}, "lvm": {"lvm", "lvm2"},
                "luks": {"luks", "luks2"}, "btrfs": {"btrfs"}}
# fixture sets that are attached together; (group, features it needs, tools it needs)
GROUPS = {
    "md-a": (["md-a"], {"mdadm"}),
    "md-b": (["md-b"], {"mdadm"}),
    "md-c": (["md-c"], {"mdadm"}),
    "imsm": (["imsm"], {"mdadm"}),
    "ddf": (["ddf"], {"mdadm"}),
    "lvm": (["lvm", "lvm-dup"], {"lvm"}),
    "luks": (["luks"], {"cryptsetup"}),
    "btrfs": (["btrfs"], set()),
    "md-bitmap": (["md-bitmap"], {"mdadm"}),  # internal and stale write-intent bitmaps: md writes them
    "lvm-raid": (["lvm-raid"], {"lvm"}),      # a raid1 LV: the VG must be refused (REFUSED)
}
REFUSED = {"lvm-raid"}  # detected, but `assemble` must fail before anything starts
IMAGEABLE = ("md", "imsm", "ddf", "luks")  # single ext4 volume: imaged and read back with debugfs


# ---------------------------------------------------------------------------
# Fixtures and skips
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def manifest():
    ok, why = fx.status()
    if not ok:
        pytest.skip(why)
    return fx.load()


@pytest.fixture(scope="session")
def features(dist_dir):
    initrd = dist_dir / "esp" / "beast-net" / "initrd.img"
    if not initrd.exists():
        pytest.skip("dist/ has no beast-net helper (make build)")
    return dk.helper_features(dist_dir)


def need(features: set[str], *names: str) -> None:
    missing = sorted(n for n in names if n not in features)
    if missing:
        pytest.skip("helper has no Disk tools yet: initramfs lacks " + ", ".join(missing)
                    + " (modules beastnet/disks/<name>.py; tools mdadm, lvm, cryptsetup)")


@pytest.fixture
def kvm():
    if not env.kvm_usable():
        pytest.skip("needs KVM (/dev/kvm): the helper boots with 6+ disks")


@pytest.fixture
def dt_drive(base_drives, workdir, dist_dir, kvm):
    for f in ("vmlinuz", "initrd.img"):
        if not (dist_dir / "esp" / "beast-net" / f).exists():
            pytest.skip("dist/ has no beast-net helper (make build)")
    return bn.empty_drive(base_drives("browse"), workdir / "dt.img", bn.config(script=bn.PLAN_PATH))


def attach(manifest, *sets: str) -> list[dk.Attached]:
    return dk.from_manifest(manifest, *sets)


def run_plan(vm_factory, drive, attached, steps, *, timeout=PLAN_TIMEOUT):
    """Write the plan, boot the helper, wait for poweroff. Returns (vm, boot)."""
    dk.write_plan(drive, dk.plan(*steps))
    boot = dk.boot_helper(vm_factory, drive, attached)
    dk.wait_done(boot.vm, timeout, after=boot.boot_end)
    return boot.vm, boot


def kind_ok(found_kind: str, want: str) -> bool:
    return found_kind.lower() in KIND_ALIASES[want]


def level_norm(s: str | None) -> str:
    return (s or "").lower().removeprefix("raid")


def hexes(s: str) -> str:
    return re.sub(r"[^0-9a-f]", "", s.lower())


def match_stack(found: list[dict], st: dict) -> dict | None:
    """The `stack found` line for a manifest stack: by uuid when the id carries one, else kind+level."""
    cands = [f for f in found if kind_ok(f.get("kind", ""), st["kind"] if st["kind"] in KIND_ALIASES else "md")]
    if st["kind"] in ("md", "luks", "btrfs") and st.get("uuid"):
        u = hexes(st["uuid"])
        by_uuid = [f for f in cands if u in hexes(f.get("id", ""))]
        if by_uuid:
            return by_uuid[0]
    if st["kind"] == "lvm":
        by = [f for f in cands if st["vg_uuid"].replace("-", "").lower() in f.get("id", "").replace("-", "").lower()]
        return by[0] if by else None
    # btrfs: the RAID profile is only known once mounted, so the scan has no level
    if st.get("level") and st["kind"] in ("md", "imsm", "ddf"):
        cands = [f for f in cands if level_norm(f.get("level")) == level_norm(st["level"])]
    return cands[0] if cands else None


# ---------------------------------------------------------------------------
# Scan cache: one scan boot per group, shared by the tests that need stack ids
# ---------------------------------------------------------------------------

_SCANS: dict[str, dict] = {}


def scan_group(name, manifest, vm_factory, drive, extra: list[dk.Attached] | None = None) -> dict:
    sets, _ = GROUPS[name]
    key = name if not extra else name + "+x"
    if key not in _SCANS:
        attached = attach(manifest, *sets) + (extra or [])
        with dk.gate(attached, manifest):
            vm, boot = run_plan(vm_factory, drive, attached, [{"op": "scan"}])
        _SCANS[key] = {"disks": dk.events(vm, "disk found"), "stacks": dk.events(vm, "stack found"),
                       "ro": dk.events(vm, "disk ro"), "errors": dk.errors(vm), "serials": [a.serial for a in attached]}
    return _SCANS[key]


# ---------------------------------------------------------------------------
# Harness tests that need no Disk tools
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["no-change", "one-byte"])
def test_gate_selftest(mode, tmp_path):
    """The gate passes on untouched images and fails on a single changed byte (also in a hole)."""
    img = tmp_path / "a.img"
    with open(img, "wb") as f:
        f.truncate(64 * dk.MIB)
        f.seek(5 * dk.MIB)
        f.write(b"data")
    g = dk.Gate([img])
    g.start()
    if mode == "one-byte":
        with open(img, "r+b") as f:
            f.seek(60 * dk.MIB)  # inside a sparse hole
            f.write(b"\x01")
        with pytest.raises(dk.GateViolation, match="CHANGED"):
            g.check()
    else:
        g.check()


def test_qemu_args_nvme_and_ahci(tmp_path):
    ds = [dk.Attached(tmp_path / "a", "BB000001", "nvme"), dk.Attached(tmp_path / "b", "BB000002", "ahci"),
          dk.Attached(tmp_path / "c", "BB000003", "ahci", snapshot=True)]
    a = " ".join(dk.qemu_args(ds))
    assert "nvme,serial=BB000001,drive=fx0" in a
    assert "ide-hd,serial=BB000002,drive=fx1,bus=ide.5" in a and "ide-hd,serial=BB000003,drive=fx2,bus=ide.4" in a
    assert "id=fx2,file=" in a and "snapshot=on" in a.split("id=fx2")[1]
    assert a.count("snapshot=off") == 2 and "format=raw" in a


def test_fixture_manifest_is_the_oracle(manifest, workdir):
    """Files written by the builder are really on the images with the recorded hashes
    (debugfs on the raw image: ext4 partition of the GPT disk, md RAID1 member)."""
    gpt = manifest["sets"]["gpt"]
    img = Path(gpt["disks"][0]["path"])
    ext4 = next(v for v in gpt["stacks"][0]["volumes"] if v["fs"] == "ext4")
    spec = f"{img}?offset={ext4['start_sector'] * 512}"
    for f in ext4["files"]:
        assert dk.ext4_sha256(spec, f["path"], workdir) == f["sha256"], f["path"]
    md = manifest["sets"]["md-a"]
    r1 = next(s for s in md["stacks"] if s["name"] == "raid1")
    member = next(d for d in md["disks"] if d["serial"] == r1["slot_serials"][0])
    spec = f"{member['path']}?offset={r1['examine']['data_offset_bytes']}"
    for f in r1["volumes"][0]["files"]:
        assert dk.ext4_sha256(spec, f["path"], workdir) == f["sha256"], f["path"]
    # sanity of the oracle itself
    stale = next(s for s in manifest["sets"]["md-bitmap"]["stacks"] if s["bitmap"] == "stale")
    assert all(v["bitmap_now"] < v["superblock"] for v in stale["bitmap_events"].values()), stale
    w = manifest["sets"]["wiped"]
    for st in w["stacks"]:
        assert st["presented"] != st["slot_serials"], "member order must be shuffled"
    assert all(d["serial"].startswith("BB") and len(d["serial"]) == 8 for s in manifest["sets"].values() for d in s["disks"])
    serials = [d["serial"] for s in manifest["sets"].values() for d in s["disks"]]
    assert len({x[-6:] for x in serials}) == len(serials), "last-6 confirmations must be unique"


def test_helper_boots_with_all_disks_under_the_gate(manifest, dt_drive, vm_factory, features, workdir):
    """Attach NVMe + AHCI fixtures, boot the helper, run a Disk tools scan plan; every
    source image is byte-identical afterwards. With no Disk tools in the helper the plan
    ends in a clear error (and the gate still holds); with them, every disk is found."""
    attached = attach(manifest, "md-a", "gpt", "luks") + [dk.images_disk(workdir / "images.img", 64, transport="nvme")]
    assert {a.transport for a in attached} == {"nvme", "ahci"}
    with dk.gate(attached[:-1], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, [{"op": "scan"}])
    helper_lines = bn.lines(vm, boot.boot_end)
    assert helper_lines, "the helper printed no BEASTNET: lines (did script mode start?)"
    if "discover" in features:
        found = dk.wait_disks(vm, [a.serial for a in attached])
        assert sum(1 for e in found.values() if e.get("stick") == "1") == 1
    else:
        assert dk.errors(vm), "without Disk tools the plan must end with an error line:\n" + "\n".join(helper_lines[-10:])


# ---------------------------------------------------------------------------
# Scan and detection
# ---------------------------------------------------------------------------

def test_scan_finds_every_disk_and_marks_the_stick(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover")
    attached = attach(manifest, "md-a", "gpt", "luks") + [dk.images_disk(workdir / "images.img", 64, transport="nvme")]
    with dk.gate(attached[:-1], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, [{"op": "scan"}])
    found = dk.wait_disks(vm, [a.serial for a in attached], after=boot.boot_end)
    sizes = {d["serial"]: d["size"] for s in manifest["sets"].values() for d in s["disks"]}
    for a in attached[:-1]:
        e = found[a.serial]
        assert int(e["size"]) == sizes[a.serial], e
        assert e["stick"] == "0" and e["lss"] == "512", e
        want = "nvme" if a.transport == "nvme" else None
        if want:
            assert e["transport"] == "nvme", e
        else:
            assert e["transport"] in ("ata", "sata", "ahci"), e
    # every rescan reports the disks again: one entry per disk id
    sticks = list({e["id"]: e for e in dk.events(vm, "disk found", boot.boot_end) if e.get("stick") == "1"}.values())
    assert len(sticks) == 1 and sticks[0]["serial"] not in {a.serial for a in attached}, sticks
    ro = {e["id"] for e in dk.events(vm, "disk ro", boot.boot_end) if e.get("ro") == "1"}
    assert len(ro) >= len(attached), f"guard must set ro on every disk node: {sorted(ro)}"
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm)


@pytest.mark.parametrize("group", list(GROUPS))
def test_stacks_detected(group, manifest, dt_drive, vm_factory, features):
    need(features, "discover", *GROUPS[group][1])
    scan = scan_group(group, manifest, vm_factory, dt_drive)
    assert not scan["errors"], scan["errors"]
    sets = GROUPS[group][0]
    omitted = {d["serial"] for s in sets for d in manifest["sets"][s]["disks"] if d["omit"]}
    for s in sets:
        for st in manifest["sets"][s]["stacks"]:
            f = match_stack(scan["stacks"], st)
            assert f is not None, f"no 'stack found' for {st['name']} ({st['kind']} {st.get('level')}); saw {[e['_'] for e in scan['stacks']]}"
            if st.get("level") and st["kind"] in ("md", "imsm", "ddf"):
                assert level_norm(f["level"]) == level_norm(st["level"]), f
            degraded = bool(omitted & set(st["slot_serials"]))
            n = int(f["members"])
            if degraded:
                assert "degrad" in f["state"].lower(), f
                assert n in (len(st["slots"]) - 1, len(st["slots"])), f
            else:
                assert "degrad" not in f["state"].lower() and n == len(st["slots"]), f
            assert f["support"] == "assemble", f


def test_wiped_arrays_are_not_assembled(manifest, dt_drive, vm_factory, features):
    need(features, "discover")
    attached = attach(manifest, "wiped")
    with dk.gate(attached, manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, [{"op": "scan"}])
    dk.wait_disks(vm, [a.serial for a in attached], after=boot.boot_end)
    ser = {a.serial for a in attached}
    assembled = [e for e in dk.events(vm, "stack found", boot.boot_end) if e.get("support") == "assemble" and kind_ok(e.get("kind", ""), "md")]
    assert not assembled, f"wiped members must not look like assemblable md arrays: {assembled} ({ser})"


# ---------------------------------------------------------------------------
# Read-only assembly, imaging, files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("group", [g for g in GROUPS if g not in REFUSED])
def test_assemble_read_only_and_image(group, manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "assemble", "copy", *GROUPS[group][1])
    sets = GROUPS[group][0]
    scan = scan_group(group, manifest, vm_factory, dt_drive)
    stacks = [(s, st) for s in sets for st in manifest["sets"][s]["stacks"]]
    # images go to a separate ext4 disk, opened read-write by use_disk (typed confirmation)
    plan_steps, ids = [{"op": "use_disk", "disk": dk.IMAGES_SERIAL, "confirm": dk.confirm(dk.IMAGES_SERIAL)}], {}
    for set_name, st in stacks:
        f = match_stack(scan["stacks"], st)
        assert f, f"stack {st['name']} not detected; see test_stacks_detected"
        ids[(set_name, st["name"])] = f["id"]  # two sets may use the same VG name
        step = {"op": "assemble", "stack": f["id"]}
        if st["kind"] == "luks":
            step["passphrase"] = manifest["passphrase"]
        plan_steps.append(step)
        if st["kind"] in IMAGEABLE:
            plan_steps.append({"op": "image", "source": f["id"], "dest": f"/images/{st['name']}.img",
                               "on": dk.IMAGES_SERIAL})
    images = dk.images_disk(workdir / "images.img", 2048, transport="nvme")
    attached = attach(manifest, *sets) + [images]
    with dk.gate(attached[:-1], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, plan_steps)
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm)
    oks = dk.events(vm, "assemble ok", boot.boot_end)
    assert not dk.events(vm, "assemble fail", boot.boot_end)
    for set_name, st in stacks:
        mine = [e for e in oks if e["id"] == ids[(set_name, st["name"])]]
        assert len(mine) >= len(st["volumes"]), f"assemble ok for {st['name']}: {mine}"
        assert all(e.get("ro") == "1" for e in mine), mine
    dones = dk.events(vm, "copy done", boot.boot_end)
    imageable = [st for _, st in stacks if st["kind"] in IMAGEABLE]
    assert len(dones) == len(imageable), dones
    for st in imageable:
        dump = workdir / f"{st['name']}.img"
        assert dk.ext4_read(images.path, f"/images/{st['name']}.img", dump), f"{st['name']}.img not on the images disk"
        for f in st["volumes"][0]["files"]:
            assert dk.ext4_sha256(dump, f["path"], workdir) == f["sha256"], (st["name"], f["path"])


def test_lvm_vg_with_a_raid_lv_is_refused(manifest, dt_drive, vm_factory, features):
    """dm-raid marks a raid LV dirty and resyncs it on activation, even read-only: the VG is
    refused with a plain message (image the PVs), nothing is activated, no byte changes."""
    need(features, "discover", "assemble", "lvm")
    scan = scan_group("lvm-raid", manifest, vm_factory, dt_drive)
    st = manifest["sets"]["lvm-raid"]["stacks"][0]
    assert "raid1" in st["segtypes"], st
    f = match_stack(scan["stacks"], st)
    assert f, f"stack {st['name']} not detected; see test_stacks_detected"
    attached = attach(manifest, "lvm-raid")
    with dk.gate(attached, manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, [{"op": "assemble", "stack": f["id"]}])
    fails = dk.events(vm, "assemble fail", boot.boot_end)
    assert [e["id"] for e in fails] == [f["id"]], fails
    errs = dk.errors(vm, boot.boot_end)
    assert errs and errs[0].startswith("error assemble") and "raid1" in errs[0], errs
    assert not dk.events(vm, "assemble ok", boot.boot_end)


# ---------------------------------------------------------------------------
# Reconstruction of the wiped arrays
# ---------------------------------------------------------------------------

def expected_order(manifest, st) -> list[int | None]:
    omitted = {d["serial"] for d in manifest["sets"]["wiped"]["disks"] if d["omit"]}
    shipped = [s for s in st["presented"] if s not in omitted]
    return [shipped.index(s) if s in shipped else None for s in st["slot_serials"]]


@pytest.mark.parametrize("array", ["wiped-raid0", "wiped-raid5", "wiped-raid5-missing"])
def test_reconstruct_wiped(array, manifest, dt_drive, vm_factory, features):
    need(features, "discover", "reconstruct")
    w = manifest["sets"]["wiped"]
    st = next(s for s in w["stacks"] if s["name"] == array)
    omitted = {d["serial"] for d in w["disks"] if d["omit"]}
    shipped = [s for s in st["presented"] if s not in omitted]
    attached = [a for a in attach(manifest, "wiped") if a.serial in shipped]
    attached.sort(key=lambda a: shipped.index(a.serial))  # attach in the shuffled order
    with dk.gate(attached, manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached,
                            [{"op": "scan"}, {"op": "reconstruct", "members": shipped, "mode": "auto"}])
    cands = dk.wait_events(vm, "reconstruct candidate", 1, after=boot.boot_end, timeout=60)
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm)
    top = min(cands, key=lambda c: int(c["rank"]))
    assert int(top["rank"]) == 1, cands
    ex = st["examine"]
    assert level_norm(top["level"]) == level_norm(st["level"]), top
    assert int(top["chunk"]) == ex["chunk_kib"] * 1024, top
    assert int(top["offset"]) == ex["data_offset_bytes"], top
    if st["level"] != "0" and top.get("layout") not in (None, "", "-", "none"):
        assert top["layout"] == ex["layout"], top
    want = expected_order(manifest, st)
    toks = top["order"].split(",")
    if len(toks) == len(want):
        for i, (t, w_) in enumerate(zip(toks, want)):
            if w_ is not None:
                assert t == str(w_), f"slot {i}: {top['order']} vs expected {want}"
    else:
        assert toks == [str(x) for x in want if x is not None], f"{top['order']} vs expected {want}"


# ---------------------------------------------------------------------------
# Image + restore roundtrip, clone, refusals
# ---------------------------------------------------------------------------

def gpt_source(manifest) -> dk.Attached:
    return attach(manifest, "gpt")[0]


def test_image_restore_roundtrip(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    src = gpt_source(manifest)
    size = src.path.stat().st_size
    images = dk.images_disk(workdir / "images.img", 2048, transport="nvme")
    target = dk.blank_disk(workdir / "target.img", size, dk.TARGET_SERIAL, fill=0xA5)
    steps = [{"op": "use_disk", "disk": dk.IMAGES_SERIAL, "confirm": dk.confirm(dk.IMAGES_SERIAL)},
             {"op": "image", "source": src.serial, "dest": "/images/gpt.img", "on": dk.IMAGES_SERIAL},
             {"op": "restore", "image": "/images/gpt.img", "on": dk.IMAGES_SERIAL, "target": target.serial,
              "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, images, target], steps)
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm)
    dones = dk.events(vm, "copy done", boot.boot_end)
    assert [d["kind"] for d in dones] == ["image", "restore"], dones
    assert all(d["errors"] == "0" for d in dones), dones
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path), "restored target differs from the source"
    if dones[0].get("sha256", "-") != "-":
        assert dones[0]["sha256"] == dk.sha256_file(src.path)


def test_clone_disk(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    src = gpt_source(manifest)
    target = dk.blank_disk(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL, fill=0x5A)
    steps = [{"op": "clone", "source": src.serial, "target": target.serial, "confirm": dk.confirm(target.serial)}]
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, [src, target], steps)
    assert not dk.errors(vm, boot.boot_end), dk.errors(vm)
    assert dk.sha256_file(target.path) == dk.sha256_file(src.path)


def refusal(name, manifest, dt_drive, vm_factory, workdir, make_steps, extra=(), *, check_targets=()):
    """Run a plan whose step must be refused: `error disk-refused`, no copy, nothing written."""
    src = gpt_source(manifest)
    size = src.path.stat().st_size
    target = dk.blank_disk(workdir / "target.img", size, dk.TARGET_SERIAL, fill=0xC3)
    small = dk.blank_disk(workdir / "small.img", 8 * dk.MIB, dk.SMALL_TARGET_SERIAL, fill=0xC3)
    attached = [src, target, small, *extra]
    steps = make_steps(src, target, small)
    before = {t.path: dk.sha256_file(t.path) for t in (target, small)}
    with dk.gate([src], manifest):
        vm, boot = run_plan(vm_factory, dt_drive, attached, steps)
    errs = dk.errors(vm, boot.boot_end)
    assert errs and errs[0].startswith("error disk-refused"), f"{name}: expected disk-refused, got {errs}"
    assert not dk.events(vm, "copy start", boot.boot_end), f"{name}: a copy started"
    for p, h in before.items():
        assert dk.sha256_file(p) == h, f"{name}: {p.name} was written"
    return vm


def test_refuse_wrong_confirm(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    refusal("wrong confirm", manifest, dt_drive, vm_factory, workdir, lambda s, t, sm: [
        {"op": "clone", "source": s.serial, "target": t.serial, "confirm": "XXXXXX"}])


def test_refuse_smaller_target(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    refusal("smaller target", manifest, dt_drive, vm_factory, workdir, lambda s, t, sm: [
        {"op": "clone", "source": s.serial, "target": sm.serial, "confirm": dk.confirm(sm.serial)}])


def test_refuse_source_as_target(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "copy")
    refusal("source as target", manifest, dt_drive, vm_factory, workdir, lambda s, t, sm: [
        {"op": "clone", "source": s.serial, "target": s.serial, "confirm": dk.confirm(s.serial)}])


def test_refuse_stick_as_target(manifest, dt_drive, vm_factory, features, workdir):
    """The stick's serial comes from a scan (usb-storage has no configured serial)."""
    need(features, "discover", "copy")
    # the same disks as refusal() attaches, so the stick gets the same kernel name there
    src = gpt_source(manifest)
    target = dk.blank_disk(workdir / "target.img", src.path.stat().st_size, dk.TARGET_SERIAL, fill=0xC3)
    small = dk.blank_disk(workdir / "small.img", 8 * dk.MIB, dk.SMALL_TARGET_SERIAL, fill=0xC3)
    vm, boot = run_plan(vm_factory, dt_drive, [src, target, small], [{"op": "scan"}])
    # every rescan reports the disks again: one entry per disk id
    sticks = list({e["id"]: e for e in dk.events(vm, "disk found", boot.boot_end) if e.get("stick") == "1"}.values())
    assert len(sticks) == 1, sticks
    stick = sticks[0]["id"]  # the stick has no serial: name it by kernel id
    refusal("stick as target", manifest, dt_drive, vm_factory, workdir, lambda s, t, sm: [
        {"op": "clone", "source": s.serial, "target": stick, "confirm": dk.confirm(stick)}])


def test_refuse_member_of_source_stack_as_target(manifest, dt_drive, vm_factory, features, workdir):
    need(features, "discover", "assemble", "copy", "mdadm")
    scan = scan_group("md-a", manifest, vm_factory, dt_drive)
    r1 = next(s for s in manifest["sets"]["md-a"]["stacks"] if s["name"] == "raid1")
    sid = match_stack(scan["stacks"], r1)["id"]
    member = r1["slot_serials"][0]
    members = attach(manifest, "md-a")
    with dk.gate(members, manifest):
        dk.write_plan(dt_drive, dk.plan(
            {"op": "assemble", "stack": sid},
            {"op": "clone", "source": sid, "target": member, "confirm": dk.confirm(member)}))
        boot = dk.boot_helper(vm_factory, dt_drive, members)
        dk.wait_done(boot.vm, PLAN_TIMEOUT, after=boot.boot_end)
    errs = dk.errors(boot.vm, boot.boot_end)
    assert errs and errs[0].startswith("error disk-refused"), errs
    assert not dk.events(boot.vm, "copy start", boot.boot_end)
