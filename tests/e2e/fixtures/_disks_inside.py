"""Runs INSIDE the fixture container (privileged): builds the disk images of
tests/e2e/fixtures/disks.py from the recipe JSON. Not meant to be run on the host.

usage: _disks_inside.py <recipe.json> <outdir> [set ...]
Writes <outdir>/<set>/<disk>.img (sparse) and <outdir>/<set>/manifest-part.json.
"""

import fcntl
import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

PASSPHRASE = "beastboot-test-passphrase"
LOOPS = []   # loop devices we attached (never touch others: the loop driver is host-global)
MNT = Path("/mnt/bbfx")
os.environ["DM_DISABLE_UDEV"] = "1"
os.environ["LVM_SUPPRESS_FD_WARNINGS"] = "1"
os.environ["IMSM_NO_PLATFORM"] = "1"
os.environ["IMSM_DEVNAME_AS_SERIAL"] = "1"  # loop devices have no serial; the metadata then records the device name


def sh(*cmd, check=True, input=None, cwd=None):
    p = subprocess.run([str(c) for c in cmd], input=input, capture_output=True, text=True, cwd=cwd)
    if check and p.returncode:
        raise SystemExit(f"FAILED {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}")
    return p.stdout


# --- loop devices ---------------------------------------------------------

def loop_attach(path, offset=0, size=None):
    with open("/dev/loop-control", "rb") as f:
        n = fcntl.ioctl(f, 0x4C82)  # LOOP_CTL_GET_FREE
    dev = f"/dev/loop{n}"
    if not os.path.exists(dev):
        os.mknod(dev, 0o660 | 0o060000, os.makedev(7, n))
    args = ["losetup"]
    if offset:
        args += ["-o", offset]
    if size:
        args += ["--sizelimit", size]
    sh(*args, dev, path)
    LOOPS.append(dev)
    return dev


def loop_detach(dev):
    sh("losetup", "-d", dev, check=False)
    if dev in LOOPS:
        LOOPS.remove(dev)


# --- files -----------------------------------------------------------------

def file_specs(seed):
    r = random.Random(seed)
    return [
        ("hello.txt", f"BeastBoot disk fixture {seed}\n".encode()),
        ("docs/readme.txt", (f"fixture {seed}\n" * 40).encode()),
        ("data/medium.bin", r.randbytes(300 * 1024)),
        ("data/big.bin", r.randbytes(3 * 1024 * 1024)),  # spans many chunks of any stripe size
    ]


def fill(mnt, seed):
    out = []
    for rel, data in file_specs(seed):
        p = Path(mnt) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        out.append({"path": "/" + rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    sh("sync")
    return out


def mkfs(dev, fs, label):
    if fs == "ext4":
        sh("mkfs.ext4", "-q", "-F", "-L", label, dev)
    elif fs == "xfs":
        sh("mkfs.xfs", "-q", "-f", "-L", label, dev)
    elif fs == "ntfs":
        sh("mkntfs", "-F", "-Q", "-q", "-L", label, dev)
    else:
        raise SystemExit(f"unknown fs {fs}")


def fill_fs(dev, fs, label, seed):
    mkfs(dev, fs, label)
    MNT.mkdir(parents=True, exist_ok=True)
    sh("mount", "-t", {"ntfs": "ntfs-3g"}.get(fs, fs), dev, MNT)
    try:
        files = fill(MNT, seed)
    finally:
        sh("umount", MNT)
    uuid = sh("blkid", "-o", "value", "-s", "UUID", dev).strip()
    return {"fs": fs, "label": label, "uuid": uuid, "files": files}


def dev_bytes(dev):
    return int(open(f"/sys/block/{Path(dev).resolve().name}/size").read()) * 512


# --- md --------------------------------------------------------------------

MDN = [200]


def next_md():
    MDN[0] += 1
    return f"/dev/md{MDN[0]}"


def md_examine(dev):
    out = sh("mdadm", "--examine", dev)

    def g(rx):
        m = re.search(rx, out)
        return m.group(1) if m else None

    return {
        "data_offset_bytes": int(g(r"Data Offset : (\d+) sectors") or 0) * 512,
        "chunk_kib": int(g(r"Chunk Size : (\d+)K") or 0),
        "layout": (g(r"Layout : (\S+)") or "").strip(),
        "raid_devices": int(g(r"Raid Devices : (\d+)") or 0),
    }


def md_stop(md):
    for _ in range(20):
        if subprocess.run(["mdadm", "--stop", md], capture_output=True).returncode == 0:
            return
        time.sleep(0.5)
    raise SystemExit(f"cannot stop {md}")


def build_md_array(out, a, seed, wiped):
    devs = [loop_attach(out / f"{n}.img") for n in a["disks"]]
    md = next_md()
    bitmap = "internal" if a.get("bitmap") in ("internal", "stale") else "none"
    cmd = ["mdadm", "--create", md, "--run", "--force", "--assume-clean", "--metadata=1.2", f"--level={a['level']}",
           f"--raid-devices={len(devs)}", f"--bitmap={bitmap}", f"--uuid={a['uuid']}", f"--name={a['name']}"]
    if a["level"] != "linear" and a["level"] != "1":
        cmd.append(f"--chunk={a['chunk_kib']}")
    if a.get("layout"):
        cmd.append(f"--layout={a['layout']}")
    sh(*cmd, *devs)
    rec = {"name": a["name"], "kind": "md", "level": a["level"], "uuid": a["uuid"], "slots": a["disks"],
           "bitmap": a.get("bitmap") or "none"}
    rec["volumes"] = [fill_fs(md, "ext4", "BB" + re.sub(r"[^A-Z0-9]", "", a["name"].upper())[:10], seed + a["name"])]
    rec["examine"] = md_examine(devs[0])
    rec["array_size_bytes"] = dev_bytes(md)
    if a.get("fail_slot") is not None:
        sh("mdadm", "--fail", md, devs[a["fail_slot"]])
        sh("mdadm", "--remove", md, devs[a["fail_slot"]])
    md_stop(md)
    if wiped:
        for d in devs:
            sh("mdadm", "--zero-superblock", "--force", d)
    for d in devs:
        loop_detach(d)
    if a.get("bitmap") == "stale":
        for n in a["disks"]:
            if n != (a["disks"][a["fail_slot"]] if a.get("fail_slot") is not None else None):
                rec.setdefault("bitmap_events", {})[n] = md_bitmap_make_stale(out / f"{n}.img")
    return rec


def md_bitmap_make_stale(path):
    """Set the internal bitmap's events and events_cleared to 1, below the superblock's: md
    then finds the bitmap out of date and rewrites it on assembly, read-only or not. The
    bitmap superblock has no checksum. Runs on the detached image file."""
    with open(path, "r+b") as f:
        f.seek(4096)  # metadata 1.2: the superblock is 4 KiB from the start
        sb = f.read(256)
        assert struct.unpack_from("<I", sb, 0)[0] == 0xA92B4EFC, "no md 1.2 superblock"
        off = struct.unpack_from("<i", sb, 96)[0]  # bitmap_offset, sectors from the superblock
        events = struct.unpack_from("<Q", sb, 200)[0]
        f.seek(4096 + off * 512)
        bm = bytearray(f.read(64))
        assert bm[:4] == b"bitm", "no internal bitmap"
        before = struct.unpack_from("<Q", bm, 24)[0]
        assert events > 1 and before == events, (events, before)
        struct.pack_into("<QQ", bm, 24, 1, 1)
        f.seek(4096 + off * 512)
        f.write(bm)
    return {"superblock": events, "bitmap_was": before, "bitmap_now": 1}


def build_md(out, s, seed):
    return [build_md_array(out, a, seed, wiped=False) for a in s["arrays"]]


def build_wiped(out, s, seed):
    return [build_md_array(out, a, seed, wiped=True) for a in s["arrays"]]


def build_container(out, s, seed, meta):
    a = s["arrays"][0]
    devs = [loop_attach(out / f"{n}.img") for n in a["disks"]]
    serials = {d['name']: d['serial'] for d in s['disks']}
    cont = next_md()
    sh("mdadm", "--create", cont, "--run", f"--metadata={meta}", f"--raid-devices={len(devs)}", *devs)
    vol = next_md()
    cmd = ["mdadm", "--create", vol, "--run", "--force", f"--level={a['level']}", f"--raid-devices={len(devs)}"]
    if a.get("chunk_kib"):
        cmd.append(f"--chunk={a['chunk_kib']}")
    sh(*cmd, cont)
    time.sleep(1)
    sh("mdadm", "--wait", vol, check=False)
    fsr = fill_fs(vol, "ext4", "BB" + meta.upper(), seed + a["name"])
    size = dev_bytes(vol)
    md_stop(vol)
    md_stop(cont)
    for d in devs:
        loop_detach(d)
    if meta == "imsm":
        imsm_fix_serials(out, a["disks"], devs, serials)
    return [{"name": a["name"], "kind": meta, "level": a["level"], "slots": a["disks"], "volumes": [fsr],
             "array_size_bytes": size, "chunk_kib": a.get("chunk_kib")}]


def imsm_fix_serials(out, names, devs, serials):
    """IMSM stores a serial per member; loop devices have none, so mdadm recorded
    the device name (IMSM_DEVNAME_AS_SERIAL). Rewrite them to the serials QEMU
    will give the disks, and fix the MPB checksum (sum of all dwords except the
    checksum field itself). Verified against the untouched checksum first."""
    import struct
    old = {dev.encode(): serials[n].encode() for n, dev in zip(names, devs)}
    for n in names:
        path = out / f"{n}.img"
        with open(path, "r+b") as f:
            size = f.seek(0, 2)
            f.seek(size - 1024)
            anchor = f.read(512)
            assert anchor[:24] == b"Intel Raid ISM Cfg Sig. ", anchor[:32]
            mpb_size = struct.unpack_from("<I", anchor, 36)[0]
            ext = (mpb_size + 511) // 512 - 1
            f.seek(size - 1024 - 512 * ext)
            mpb = bytearray(anchor + f.read(512 * ext))[:mpb_size]
            words = struct.unpack(f"<{len(mpb) // 4}I", bytes(mpb[:len(mpb) // 4 * 4]))
            stored = words[8]
            assert (sum(words) - stored) & 0xFFFFFFFF == stored, "unexpected IMSM checksum model"
            for o, new in old.items():
                i = mpb.find(o + b"\0")
                while i >= 0:
                    mpb[i:i + 16] = new.ljust(16, b"\0")
                    i = mpb.find(o + b"\0")
            words = struct.unpack(f"<{len(mpb) // 4}I", bytes(mpb[:len(mpb) // 4 * 4]))
            struct.pack_into("<I", mpb, 32, (sum(words) - words[8]) & 0xFFFFFFFF)
            f.seek(size - 1024)
            f.write(mpb[:512])
            if ext:
                f.seek(size - 1024 - 512 * ext)
                f.write(mpb[512:512 + 512 * ext])


# --- lvm -------------------------------------------------------------------

def build_lvm(out, s, seed):
    recs = []
    for vg in s["vgs"]:
        devs = [loop_attach(out / f"{n}.img") for n in vg["disks"]]
        for d in devs:
            sh("pvcreate", "-ff", "-y", d)
        sh("vgcreate", vg["name"], *devs)
        vols = []
        for lv in vg["lvs"]:
            kind = ["--type", lv["type"], "-m", "1"] if lv.get("type") == "raid1" else []
            sh("lvcreate", "-y", *kind, "-n", lv["name"], "-L", f"{lv['mib']}M", vg["name"])
            if kind:
                lv_wait_sync(f"{vg['name']}/{lv['name']}")
            path = f"/dev/{vg['name']}/{lv['name']}"
            if not os.path.exists(path):
                sh("vgmknodes", vg["name"])
            r = fill_fs(path, lv["fs"], "BB" + lv["name"].upper()[:8], seed + vg["name"] + lv["name"] + ",".join(vg["disks"]))
            r["lv"] = lv["name"]
            r["segtype"] = lv.get("type", "linear")
            if kind:
                lv_wait_sync(f"{vg['name']}/{lv['name']}")
            vols.append(r)
        vguuid = sh("vgs", "--noheadings", "-o", "vg_uuid", vg["name"]).strip()
        pvu = [sh("pvs", "--noheadings", "-o", "pv_uuid", d).strip() for d in devs]
        sh("vgchange", "-an", vg["name"])
        for d in devs:
            loop_detach(d)
        recs.append({"name": vg["name"], "kind": "lvm", "vg_uuid": vguuid, "pv_uuids": pvu, "slots": vg["disks"],
                     "volumes": vols, "segtypes": sorted({v["segtype"] for v in vols})})
    return recs


def lv_wait_sync(lv):
    for _ in range(240):
        pct = sh("lvs", "--noheadings", "-o", "sync_percent", lv).strip()
        if pct.startswith("100"):
            return
        time.sleep(0.5)
    raise SystemExit(f"{lv} did not finish its initial sync ({pct})")


# --- luks / btrfs / gpt -----------------------------------------------------

def build_luks(out, s, seed):
    d = s["disks"][0]["name"]
    dev = loop_attach(out / f"{d}.img")
    sh("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
       "--uuid", s["luks_uuid"], "--key-file", "-", dev, input=PASSPHRASE)
    sh("cryptsetup", "open", "--key-file", "-", dev, "bbfx-luks", input=PASSPHRASE)
    try:
        fsr = fill_fs("/dev/mapper/bbfx-luks", "ext4", "BBLUKS", seed + "luks")
    finally:
        sh("cryptsetup", "close", "bbfx-luks")
    loop_detach(dev)
    return [{"name": "luks", "kind": "luks", "uuid": s["luks_uuid"], "version": 2, "pbkdf": "pbkdf2",
             "passphrase": PASSPHRASE, "slots": [d], "volumes": [fsr]}]


def build_btrfs(out, s, seed):
    names = [d["name"] for d in s["disks"]]
    devs = [loop_attach(out / f"{n}.img") for n in names]
    # The kernel keeps scanned btrfs devices registered after their loop device is gone; a
    # registration from an earlier build (same fixed UUID, higher generation) makes this
    # mount fail with EEXIST. Forget unmounted ones (it never touches a mounted filesystem).
    sh("btrfs", "device", "scan", "--forget", check=False)
    sh("mkfs.btrfs", "-q", "-f", "-d", "raid1", "-m", "raid1", "-L", "BBBTRFS", "-U", s["btrfs_uuid"], *devs)
    sh("btrfs", "device", "scan", *devs, check=False)
    MNT.mkdir(parents=True, exist_ok=True)
    sh("mount", "-t", "btrfs", devs[0], MNT)
    try:
        files = fill(MNT, seed + "btrfs")
    finally:
        sh("umount", MNT)
    for d in devs:
        loop_detach(d)
    sh("btrfs", "device", "scan", "--forget", check=False)
    return [{"name": "btrfs-raid1", "kind": "btrfs", "level": "raid1", "uuid": s["btrfs_uuid"], "slots": names,
             "volumes": [{"fs": "btrfs", "label": "BBBTRFS", "uuid": s["btrfs_uuid"], "files": files}]}]


def build_gpt(out, s, seed):
    d = s["disks"][0]
    img = out / f"{d['name']}.img"
    sh("sgdisk", "-U", s["disk_guid"], "-n", "1:2048:+64M", "-t", "1:0700", "-u", f"1:{s['part_guids'][0]}", "-c", "1:BBNTFS",
       "-n", "2:0:+64M", "-t", "2:8300", "-u", f"2:{s['part_guids'][1]}", "-c", "2:BBEXT4", img)
    parts = []
    for i, (fs, label) in enumerate((("ntfs", "BBNTFS"), ("ext4", "BBEXT4")), 1):
        info = sh("sgdisk", "-i", str(i), img)
        first = int(re.search(r"First sector: (\d+)", info)[1])
        last = int(re.search(r"Last sector: (\d+)", info)[1])
        dev = loop_attach(img, offset=first * 512, size=(last - first + 1) * 512)
        r = fill_fs(dev, fs, label, seed + "gpt" + fs)
        if fs == "ntfs":
            with open(dev, "rb") as f:
                f.seek(72)
                r["ntfs_serial"] = f.read(8).hex()
        loop_detach(dev)
        r.update(partition=i, start_sector=first, sectors=last - first + 1, part_guid=s["part_guids"][i - 1].lower())
        parts.append(r)
    return [{"name": "gpt-ntfs-ext4", "kind": "gpt-disk", "disk_guid": s["disk_guid"].lower(), "slots": [d["name"]], "volumes": parts}]


BUILDERS = {
    "md": build_md, "wiped": build_wiped, "lvm": build_lvm, "luks": build_luks, "btrfs": build_btrfs, "gpt": build_gpt,
    "imsm": lambda o, s, sd: build_container(o, s, sd, "imsm"),
    "ddf": lambda o, s, sd: build_container(o, s, sd, "ddf"),
}


def main():
    recipe = json.loads(Path(sys.argv[1]).read_text())
    outdir = Path(sys.argv[2])
    only = sys.argv[3:]
    for i in range(0, 64):
        if not os.path.exists(f"/dev/loop{i}"):
            os.mknod(f"/dev/loop{i}", 0o660 | 0o060000, os.makedev(7, i))
    Path("/run/mdadm").mkdir(parents=True, exist_ok=True)
    # LVM in this container sees the host's /dev: let it scan and use our loop devices only
    Path("/etc/lvm/lvmlocal.conf").write_text(
        'devices {\n  global_filter = [ "a|^/dev/loop[0-9]+$|", "r|.*|" ]\n  use_devicesfile = 0\n}\n')
    for name, s in recipe["sets"].items():
        if only and name not in only:
            continue
        out = outdir / name
        out.mkdir(parents=True, exist_ok=True)
        for d in s["disks"]:
            with open(out / f"{d['name']}.img", "wb") as f:
                f.truncate(d["size"])
        try:
            stacks = BUILDERS[s["builder"]](out, s, recipe["seed"])
        finally:
            for dev in list(LOOPS):
                loop_detach(dev)
        for d in s["disks"]:
            h = hashlib.sha256()
            with open(out / f"{d['name']}.img", "rb") as f:
                for blk in iter(lambda: f.read(1 << 22), b""):
                    h.update(blk)
            d["image_sha256"] = h.hexdigest()
        (out / "manifest-part.json").write_text(json.dumps({"disks": s["disks"], "stacks": stacks}, indent=1))
        for d in s["disks"]:
            if d.get("omit"):  # failed / missing member: recorded but not shipped
                (out / f"{d['name']}.img").unlink()
        print("built", name, flush=True)


main()
