"""Disk tools fixes found by the QEMU e2e run (tests/e2e/test_e2e_disks_copy.py), and
power-cut-safe progress: blkid fallback, USB serials, the final progress line, sealed
mapfile snapshots (disks/mapstore.py), the filesystem check (disks/fsrepair.py)."""

# ruff: noqa: F811  (the env fixture of test_disks_copy.py is imported and used as an argument)
import os
import struct

import pytest

from beastnet import errors as E
from beastnet.disks import copy as C
from beastnet.disks import discover, fsrepair, mapstore
from beastnet.errors import BeastNetError
from disk_fakes import Env, cp
from test_disks_copy import MIB, SIZE, env, mk  # noqa: F401  (env is a fixture)


# ---- blkid: one unreadable disk must not hide the others -------------------------------

def _stopping_blkid(fake: Env, bad: str):
    """Like util-linux blkid: probes in order and stops at the first device it cannot read."""
    def reply(argv, _env, _input):
        out = []
        for p in argv[4:]:
            if p == bad:
                return cp(2 if len(argv) == 5 else 4, "\n".join(out), f"blkid: error: {p}: Input/output error")
            info = fake.blk.get(p)
            if info:
                out.append("\n".join([f"DEVNAME={p}"] + [f"{k}={v}" for k, v in info.items()]) + "\n")
        return cp(0 if out else 2, "\n".join(out))
    return reply


def test_blkid_probes_the_rest_one_by_one_after_an_unreadable_disk(tmp_path):
    e = Env(tmp_path)
    e.add_disk("nvme0n1", 64, transport="nvme", serial="BAD1")     # failing disk, sorted first
    e.add_disk("sda", 64, serial="IMG1")
    e.add_disk("sdb", 64, serial="BLANK1")                          # nothing on it
    e.blk[e.dev("sda")] = {"TYPE": "ext4", "UUID": "u-img"}
    e.runner.on("blkid", _stopping_blkid(e, e.dev("nvme0n1")))
    out = discover.blkid_all(e.ctx, [e.dev("nvme0n1"), e.dev("sda"), e.dev("sdb")])
    assert out[e.dev("sda")]["TYPE"] == "ext4"
    assert out[e.dev("nvme0n1")] == {} and out[e.dev("sdb")] == {}  # the failing one fails alone too
    calls = e.runner.ran("blkid")
    assert len(calls[0]) == 7 and [c[4:] for c in calls[1:]] == [[e.dev("nvme0n1")], [e.dev("sda")], [e.dev("sdb")]]


def test_blkid_one_call_when_every_device_answers(tmp_path):
    e = Env(tmp_path)
    for n in ("sda", "sdb"):
        e.add_disk(n, 64, serial=n.upper())
        e.blk[e.dev(n)] = {"TYPE": "ext4"}
    out = discover.blkid_all(e.ctx, [e.dev("sda"), e.dev("sdb")])
    assert all(v["TYPE"] == "ext4" for v in out.values()) and len(e.runner.ran("blkid")) == 1


def test_scan_sees_the_images_disk_behind_a_failing_disk(tmp_path):
    e = Env(tmp_path)
    e.add_disk("nvme0n1", 64, transport="nvme", serial="BAD1")
    e.add_disk("sda", 64, serial="IMG1")
    e.blk[e.dev("sda")] = {"TYPE": "ext4"}
    e.runner.on("blkid", _stopping_blkid(e, e.dev("nvme0n1")))
    inv = discover.scan(e.ctx)
    assert {d.id: d.fs_type for d in inv.disks}["sda"] == "ext4"


# ---- USB serials ----------------------------------------------------------------------

USB_DEV = "devices/pci0000:00/0000:00:14.0/usb1/1-2"


def test_usb_serial_from_the_usb_device(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sdb", 64, transport="usb")              # no SCSI serial, no VPD page
    e.write(e.sys(USB_DEV, "idVendor"), "0bda\n")
    e.write(e.sys(USB_DEV, "serial"), "BRIDGE-0042\n")
    assert discover.serial_of(e.sys(), "sdb") == "BRIDGE-0042"


def test_usb_serial_missing(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sdb", 64, transport="usb")
    e.write(e.sys(USB_DEV, "idVendor"), "0bda\n")      # a USB device without iSerial
    assert discover.serial_of(e.sys(), "sdb") == ""


def test_usb_serial_not_used_for_a_sata_disk(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sda", 64)                               # SATA, no serial anywhere
    e.write(e.sys("devices", "idVendor"), "ffff\n")     # even with an idVendor above /sys/devices
    assert discover.serial_of(e.sys(), "sda") == ""


def test_scsi_serial_still_wins_over_the_usb_one(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sdb", 64, transport="usb", serial="DISK-OWN")
    e.write(e.sys(USB_DEV, "idVendor"), "0bda\n")
    e.write(e.sys(USB_DEV, "serial"), "BRIDGE-0042\n")
    assert discover.serial_of(e.sys(), "sdb") == "DISK-OWN"


# ---- the final progress line and errors= -------------------------------------------------

def _lines(env, kind):
    return [x for x in env.ctx.reporter.lines if f" {kind} " in x]


def test_final_progress_line_carries_the_last_bad_area_count(env, monkeypatch):
    monkeypatch.setenv("STUB_BAD", f"{MIB}:{131072}")   # two 64 KiB blocks (the stub: two bad areas)
    p = mk(env, "image", target=str(env.tmp / "ext/bad.img"))
    r = C.run(env.ctx, p, hooks=env.hooks)
    assert r.ok and r.errors == 131072
    last = _lines(env, "copy progress")[-1]
    assert "errors=2 " in last and "unread=131072 " in last, last
    done = _lines(env, "copy done")[-1]
    assert "errors=2 " in done and "unread=131072 " in done, done  # errors= is bad areas in both lines


# ---- sealed mapfile snapshots ------------------------------------------------------------

MAP = "# x\n0x0 + 1\n#  pos size status\n0x0 0x100 +\n0x100 0x80 -\n0x180 0x80 ?\n"


def test_seal_roundtrip_and_every_kind_of_damage():
    sealed = mapstore.seal(MAP, 0x200)
    assert mapstore.unseal(sealed, 0x200) == MAP
    assert mapstore.unseal(sealed, 0x400) is None                       # another source size
    assert mapstore.unseal(sealed.replace("0x80 -", "0x80 +"), 0x200) is None   # a bad area made "done"
    assert mapstore.unseal(sealed[:-10], 0x200) is None                 # torn
    assert mapstore.unseal(MAP, 0x200) is None                          # not sealed (old or foreign)
    resealed_gap = mapstore.seal(MAP.replace("0x100 0x80 -\n", ""), 0x200)
    assert mapstore.unseal(resealed_gap, 0x200) is None                 # a gap, even with a valid hash


def test_load_prefers_a_complete_tmp_and_reports_untrusted(tmp_path):
    m = str(tmp_path / "c.map")
    assert mapstore.load(m, 0x200).state == "absent"
    with open(m, "w") as f:
        f.write("garbage")
    got = mapstore.load(m, 0x200)
    assert got.state == "untrusted" and "c.map" in got.why
    with open(m + ".tmp", "w") as f:
        f.write(mapstore.seal(MAP, 0x200))
    got = mapstore.load(m, 0x200)
    assert got.state == "ok" and got.path.endswith(".tmp") and got.text == MAP


def test_write_atomic_leaves_no_tmp(tmp_path):
    m = str(tmp_path / "d" / "c.map")
    mapstore.write_atomic(m, "one\n")
    mapstore.write_atomic(m, "two\n")
    assert open(m).read() == "two\n" and not os.path.exists(m + ".tmp")


def test_keeper_skips_a_map_ddrescue_is_rewriting(tmp_path):
    work, m, tgt = str(tmp_path / "w.map"), str(tmp_path / "c.map"), str(tmp_path / "t")
    open(tgt, "wb").write(b"x")
    open(work, "w").write(MAP[:40])            # half written
    k = mapstore.Keeper(work, m, 0x200, tgt, interval=0)
    assert not k.save() and not os.path.exists(m)
    open(work, "w").write(MAP)
    assert k.save() and mapstore.load(m, 0x200).text == MAP
    assert not k.save()                         # unchanged: no write


def test_resume_uses_the_sealed_snapshot(env, monkeypatch):
    monkeypatch.setenv("STUB_DELAY", "0.05")
    p = mk(env, confirm="123456")
    n = []
    r = C.run(env.ctx, p, should_stop=lambda: n.append(1) or len(n) > 40, hooks=env.hooks)
    assert r.resumable and 0 < r.bytes < SIZE and mapstore.load(p.mapfile, p.size).state == "ok"
    first = open(p.mapfile).readline()
    assert first.startswith("# beastboot-mapfile v1 size=")
    monkeypatch.setenv("STUB_DELAY", "0")
    loaded = []
    real_load = mapstore.load
    monkeypatch.setattr(mapstore, "load", lambda m, t: loaded.append(real_load(m, t)) or loaded[-1])
    p = mk(env, confirm="123456")   # as the screens do: a resumed copy is planned again
    r2 = C.run(env.ctx, p, hooks=env.hooks)
    assert r2.ok and open(env.files["sdb"], "rb").read() == open(env.files["sda"], "rb").read()
    # the second run started from the snapshot (what ddrescue got as its mapfile)
    assert loaded[0].state == "ok"
    blocks = mapstore.parse_strict(loaded[0].text, SIZE)
    assert sum(n for _p, n, st in blocks if st == "+") == r.bytes


def test_untrusted_saved_map_is_never_used_and_restart_sets_it_aside(env):
    p = mk(env, confirm="123456")
    os.makedirs(os.path.dirname(p.mapfile), exist_ok=True)
    # a map that claims everything is done: trusting it would "finish" without copying
    with open(p.mapfile, "w") as f:
        f.write(f"# Mapfile\n0x0 + 1\n0x0 0x{SIZE:X} +\n")
    before = open(env.files["sdb"], "rb").read()
    with pytest.raises(C.MapfileUntrusted) as ei:
        C.run(env.ctx, p, hooks=env.hooks)
    assert ei.value.code == E.COPY and "cannot be trusted" in ei.value.text
    assert open(env.files["sdb"], "rb").read() == before
    assert not [c for c in env.calls if c[0] == "writable"]          # nothing was made writable
    assert not any(" copy start " in x for x in env.ctx.reporter.lines)
    p.restart = True
    r = C.run(env.ctx, p, hooks=env.hooks)
    assert r.ok and open(env.files["sdb"], "rb").read() == open(env.files["sda"], "rb").read()
    assert os.path.exists(p.mapfile + ".untrusted")


# ---- the filesystem check after a power cut --------------------------------------------

@pytest.fixture
def stick(tmp_path, monkeypatch):
    monkeypatch.setattr(fsrepair, "_REPAIRED", set())
    e = Env(tmp_path)
    e.paths.kernel_log = str(tmp_path / "kmsg.txt")
    e.klog = lambda text: open(e.paths.kernel_log, "w").write(text)
    e.klog("")
    e.set_mounts(f"/dev/sdc2 {e.paths.data} vfat rw,noatime 0 0", f"/dev/sdc1 {e.paths.esp} vfat rw 0 0")
    for prog in ("sync", "umount", "mount", "fsck.fat", "fsck.exfat"):
        e.runner.on(prog, cp(0))
    return e


def test_clean_stick_is_not_touched(stick):
    assert fsrepair.check_stick(stick.ctx) == ([], "")
    assert stick.runner.calls == []


def test_dirty_fat_stick_is_checked_before_use(stick):
    stick.klog("FAT-fs (sdc2): Volume was not properly unmounted. Some data may be corrupt. Please run fsck.\n")
    said = []
    notes, problem = fsrepair.check_stick(stick.ctx, said.append)
    assert problem == "" and notes and said and "fsck.fat" in said[0]
    assert stick.runner.calls == [["sync"], ["umount", stick.paths.data], ["fsck.fat", "-a", "-w", "/dev/sdc2"],
                                  ["mount", "-t", "vfat", "-o", fsrepair.STICK_OPTS, "/dev/sdc2", stick.paths.data]]
    assert "BEASTNET: fs repair dev=/dev/sdc2 fs=vfat result=clean" in stick.rep.lines
    assert fsrepair.check_stick(stick.ctx) == ([], "")                # once per boot


def test_read_only_exfat_stick_and_a_failed_repair(stick):
    stick.set_mounts(f"/dev/sdc2 {stick.paths.data} exfat ro,noatime 0 0")
    stick.runner.on("fsck.exfat", cp(4, "", "exfat: cannot fix"))
    notes, problem = fsrepair.check_stick(stick.ctx)
    assert notes == [] and "could not be repaired" in problem and "chkdsk" in problem
    assert ["mount", "-t", "exfat", "-o", fsrepair.STICK_OPTS, "/dev/sdc2", stick.paths.data] in stick.runner.calls
    assert "BEASTNET: fs repair dev=/dev/sdc2 fs=exfat result=failed" in stick.rep.lines


def test_dirty_ntfs_stick_is_refused_not_repaired(stick):
    stick.set_mounts(f"/dev/sdc2 {stick.paths.data} ntfs3 ro 0 0")
    notes, problem = fsrepair.check_stick(stick.ctx)
    assert notes == [] and "chkdsk" in problem
    assert not [c for c in stick.runner.calls if c[0].startswith("fsck")]


def test_other_disks_in_the_kernel_log_are_ignored(stick):
    stick.klog("FAT-fs (sdd1): Volume was not properly unmounted.\n")
    assert fsrepair.check_stick(stick.ctx) == ([], "") and stick.runner.calls == []


def _exfat_boot(dirty: bool) -> bytes:
    bs = bytearray(512)
    bs[3:11] = b"EXFAT   "
    struct.pack_into("<H", bs, 106, 0x0002 if dirty else 0)
    return bytes(bs)


def _fat32(state: int, fat1: int) -> bytes:
    bs = bytearray(512 * 33)
    struct.pack_into("<HH", bs, 11, 512, 32)   # bytes per sector, reserved sectors
    struct.pack_into("<H", bs, 22, 0)          # FAT32
    bs[65] = state
    struct.pack_into("<II", bs, 32 * 512, 0x0FFFFFF8, fat1)
    return bytes(bs)


def test_volume_dirty_flags(tmp_path):
    p = tmp_path / "dev"
    p.write_bytes(_exfat_boot(True))
    assert fsrepair.volume_dirty(str(p), "exfat")
    p.write_bytes(_exfat_boot(False))
    assert not fsrepair.volume_dirty(str(p), "exfat")
    p.write_bytes(_fat32(0, 0x0FFFFFFF))
    assert not fsrepair.volume_dirty(str(p), "vfat")
    p.write_bytes(_fat32(1, 0x0FFFFFFF))       # Linux dirty state byte
    assert fsrepair.volume_dirty(str(p), "vfat")
    p.write_bytes(_fat32(0, 0x07FFFFFF))       # Windows: clean-shutdown bit cleared
    assert fsrepair.volume_dirty(str(p), "vfat")


def test_dirty_confirmed_destination_is_checked(stick, tmp_path):
    dev = tmp_path / "sdd1"
    dev.write_bytes(_exfat_boot(True))
    notes = fsrepair.check_dest(stick.ctx, str(dev), "exfat", "sdd")
    assert notes and ["fsck.exfat", "-p", str(dev)] in stick.runner.calls
    dev2 = tmp_path / "sde1"
    dev2.write_bytes(_exfat_boot(False))
    assert fsrepair.check_dest(stick.ctx, str(dev2), "exfat", "sde") == []
    assert fsrepair.check_dest(stick.ctx, str(dev2), "ext4", "sde") == []   # the mount replays the journal


def test_session_refuses_a_copy_whose_map_would_sit_on_a_broken_stick(env):
    from beastnet.disks.session import DiskSession
    from types import SimpleNamespace
    s = DiskSession(env.ctx, modules=SimpleNamespace(copy=C, guard=SimpleNamespace(reapply=lambda ctx: None),
                                                      fsrepair=SimpleNamespace()))
    s.stick_problem = "The BeastBoot drive (/dev/sdc2) is read-only"
    p = mk(env, confirm="123456", mapfile_dir=str(env.tmp / "data" / "disk-tools"))
    with pytest.raises(BeastNetError) as ei:
        s.run_copy(p)
    assert ei.value.code == E.DISK_REFUSED and "read-only" in ei.value.text
