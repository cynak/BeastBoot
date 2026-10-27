"""Disk-image fixtures for the Disk tools tests (docs/DISK_TOOLS.md section 7).

Builds raw sparse images with RAID/volume stacks of known parameters (md with and
without write-intent bitmaps, IMSM, DDF, LVM incl. a raid1 LV, LUKS, btrfs) inside a
privileged Docker container (ubuntu:26.04 with pinned mdadm, lvm2, cryptsetup,
btrfs-progs, e2fsprogs, xfsprogs, ntfs-3g; needs loop devices), and writes one
manifest.json: the oracle for the tests (stack parameters, member order, the
SHA-256 of every file written inside, the SHA-256 of every image as built).

Cache: .tools/cache/disk-fixtures/<recipe-hash>/ . Same recipe, same parameters
(UUIDs and file contents are derived from the recipe); images are not
byte-identical between builds (filesystem timestamps), the manifest is the oracle.

CLI:
    python tests/e2e/fixtures/disks.py build [--set NAME ...]   build (or reuse) the fixtures
    python tests/e2e/fixtures/disks.py path                     print the cache directory
    python tests/e2e/fixtures/disks.py list                     sets, disks and stacks in the manifest
    python tests/e2e/fixtures/disks.py needs                    what is missing on this host

Not built: ZFS (needs the zfs kernel module on the Docker host; `zpool` is absent here).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid as uuidlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CACHE = Path(os.environ.get("BB_DISK_FIXTURE_CACHE", ROOT / ".tools" / "cache" / "disk-fixtures"))
PASSPHRASE = "beastboot-test-passphrase"
SEED = "beastboot-disk-fixtures-1"
MIB = 1024 * 1024
RECIPE_VERSION = 1


def _uuid(*parts: str) -> str:
    return str(uuidlib.uuid5(uuidlib.NAMESPACE_URL, "beastboot/" + "/".join(parts)))


def _md_uuid(name: str) -> str:
    """mdadm style (colon separated 4x8 hex), derived from the array name."""
    h = _uuid("md", name).replace("-", "")
    return ":".join(h[i:i + 8] for i in range(0, 32, 8))


def recipe() -> dict:
    """The build recipe: sets of disks and what to build on them. Serials are
    'BB' + 6 digits, unique across all sets (a confirmation is the last 6)."""
    sets: dict[str, dict] = {}
    counter = [0]

    def disk(setname: str, label: str, size_mib: int, omit: bool = False) -> dict:
        counter[0] += 1
        n = counter[0]
        return {"name": f"{setname}.{label}", "serial": f"BB{n:06d}", "size": size_mib * MIB,
                "transport": "nvme" if n % 2 else "ahci", "omit": omit}

    def md_set(setname, specs, *, builder="md", member_mib=96, wiped=False):
        disks, arrays = [], []
        for sp in specs:
            names = []
            for i in range(sp["n"]):
                omit = sp.get("fail_slot") == i
                d = disk(setname, f"{sp['name']}-{i}", sp.get("member_mib", member_mib), omit=omit)
                disks.append(d)
                names.append(d["name"])
            arrays.append({**{k: v for k, v in sp.items() if k not in ("n", "member_mib")},
                           "disks": names, "uuid": _md_uuid(sp["name"])})
        sets[setname] = {"builder": builder, "arrays": arrays, "disks": disks}

    md_set("md-a", [
        {"name": "raid0", "level": "0", "chunk_kib": 64, "n": 2},
        {"name": "raid1", "level": "1", "n": 2},
        {"name": "linear", "level": "linear", "chunk_kib": 0, "n": 2},
    ])
    md_set("md-b", [
        {"name": "raid5", "level": "5", "chunk_kib": 128, "layout": "left-symmetric", "n": 3},
        {"name": "raid10", "level": "10", "chunk_kib": 64, "layout": "n2", "n": 4},
    ])
    md_set("md-c", [
        {"name": "raid6", "level": "6", "chunk_kib": 64, "layout": "left-symmetric", "n": 4},
        {"name": "raid5-degraded", "level": "5", "chunk_kib": 64, "layout": "left-symmetric", "n": 3, "fail_slot": 2},
        {"name": "raid1-degraded", "level": "1", "n": 2, "fail_slot": 1},
    ])
    md_set("imsm", [{"name": "imsm-raid5", "level": "5", "chunk_kib": 64, "n": 3}], builder="imsm")
    md_set("ddf", [{"name": "ddf-raid1", "level": "1", "n": 2}], builder="ddf")

    # wiped: superblocks zeroed. Slot order is the true member order; the
    # shipped (presented) order is a seeded shuffle, never the identity.
    md_set("wiped", [
        {"name": "wiped-raid0", "level": "0", "chunk_kib": 64, "n": 3},
        {"name": "wiped-raid5", "level": "5", "chunk_kib": 128, "layout": "left-symmetric", "n": 3},
        {"name": "wiped-raid5-missing", "level": "5", "chunk_kib": 64, "layout": "left-asymmetric", "n": 3,
         "fail_slot": 1},
    ], builder="wiped")
    w = sets["wiped"]
    import random
    rng = random.Random(SEED)
    for a in w["arrays"]:
        slots = a["disks"]
        shuffled = slots[:]
        while shuffled == slots:
            rng.shuffle(shuffled)
        a["presented"] = shuffled
        # `order` as the reconstruct step sees it: for each true slot, the
        # index into the presented member list (None for the missing member).
        a["true_order"] = [shuffled.index(n) for n in slots]
    # presented order = disk order in the manifest
    pres = [n for a in w["arrays"] for n in a["presented"]]
    w["disks"].sort(key=lambda d: pres.index(d["name"]))
    # (serials stay with their disks; only the listing order changes)

    sets["lvm"] = {"builder": "lvm", "disks": [], "vgs": []}
    for vgname, npv, lvs in (("bbvg", 2, [{"name": "data", "fs": "ext4", "mib": 100}, {"name": "bulk", "fs": "xfs", "mib": 300}]),
                             ("datavg", 1, [{"name": "docs", "fs": "ext4", "mib": 64}])):
        names = []
        for i in range(npv):
            d = disk("lvm", f"{vgname}-{i}", 256 if vgname == "bbvg" else 128)
            sets["lvm"]["disks"].append(d)
            names.append(d["name"])
        sets["lvm"]["vgs"].append({"name": vgname, "disks": names, "lvs": lvs})
    d = disk("lvm-dup", "bbvg-0", 128)
    sets["lvm-dup"] = {"builder": "lvm", "disks": [d],
                       "vgs": [{"name": "bbvg", "disks": [d["name"]], "lvs": [{"name": "other", "fs": "ext4", "mib": 64}]}]}

    sets["luks"] = {"builder": "luks", "disks": [disk("luks", "d0", 128)], "luks_uuid": _uuid("luks")}
    sets["btrfs"] = {"builder": "btrfs", "disks": [disk("btrfs", "d0", 160), disk("btrfs", "d1", 160)],
                     "btrfs_uuid": _uuid("btrfs")}
    sets["gpt"] = {"builder": "gpt", "disks": [disk("gpt", "d0", 160)], "disk_guid": _uuid("gpt", "disk").upper(),
                   "part_guids": [_uuid("gpt", "p1").upper(), _uuid("gpt", "p2").upper()]}

    # md with a write-intent bitmap: md rewrites it when it loads and stops an array, also a
    # read-only one. "stale": the bitmap's event count is set below the superblock's after the
    # build, so md calls it out of date and rewrites it on assembly (a byte change on a member
    # unless the array runs on overlays). The gate covers all three.
    md_set("md-bitmap", [
        {"name": "bitmap-raid1", "level": "1", "n": 2, "bitmap": "internal"},
        {"name": "bitmap-raid5", "level": "5", "chunk_kib": 64, "layout": "left-symmetric", "n": 3,
         "bitmap": "internal"},
        {"name": "stale-bitmap-raid1", "level": "1", "n": 2, "bitmap": "stale"},
    ])
    # an LVM raid1 LV (dm-raid marks it dirty and resyncs on activation): the VG is refused
    names = []
    sets["lvm-raid"] = {"builder": "lvm", "disks": [], "vgs": []}
    for i in range(2):
        d = disk("lvm-raid", f"raidvg-{i}", 160)
        sets["lvm-raid"]["disks"].append(d)
        names.append(d["name"])
    sets["lvm-raid"]["vgs"].append({"name": "raidvg", "disks": names, "lvs": [
        {"name": "plain", "fs": "ext4", "mib": 32}, {"name": "mirror", "fs": "ext4", "mib": 48, "type": "raid1"}]})
    return {"version": RECIPE_VERSION, "seed": SEED, "passphrase": PASSPHRASE, "sets": sets}


def recipe_hash(r: dict | None = None) -> str:
    h = hashlib.sha256()
    h.update(json.dumps(r or recipe(), sort_keys=True).encode())
    for f in ("Dockerfile.disks", "_disks_inside.py"):
        h.update((HERE / f).read_bytes())
    return h.hexdigest()[:16]


def cache_dir() -> Path:
    return CACHE / recipe_hash()


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def docker_status() -> tuple[bool, str]:
    """(usable, reason): docker exists and `docker run --privileged` works."""
    docker = shutil.which("docker")
    if not docker:
        return False, "docker is not installed (the builder needs a privileged container with loop devices)"
    p = subprocess.run([docker, "info"], capture_output=True, text=True)
    if p.returncode:
        return False, "docker is not usable: " + (p.stderr.strip().splitlines() or ["docker info failed"])[-1]
    return True, ""


def complete(d: Path) -> bool:
    return (d / "manifest.json").exists()


def status() -> tuple[bool, str]:
    """(built, reason) for tests: fixtures present in the cache?"""
    d = cache_dir()
    if complete(d):
        return True, ""
    return False, f"disk fixtures not built ({d}): run  python tests/e2e/fixtures/disks.py build  (needs docker --privileged)"


def load(only: set[str] | None = None) -> dict:
    """The manifest (with each disk's absolute `path`)."""
    d = cache_dir()
    m = json.loads((d / "manifest.json").read_text())
    for sname, s in m["sets"].items():
        for dk in s["disks"]:
            dk["path"] = str(d / sname / f"{dk['name']}.img") if not dk["omit"] else None
    return m


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _docker_image(docker: str) -> str:
    tag = "beastboot-disk-fixtures:" + hashlib.sha256((HERE / "Dockerfile.disks").read_bytes()).hexdigest()[:12]
    if subprocess.run([docker, "image", "inspect", tag], capture_output=True).returncode:
        print(f"building docker image {tag} ...", flush=True)
        subprocess.run([docker, "build", "-q", "-t", tag, "-f", str(HERE / "Dockerfile.disks"), str(HERE)], check=True)
    return tag


def build(only: list[str] | None = None, *, force: bool = False) -> Path:
    r = recipe()
    final = cache_dir()
    if complete(final) and not force and not only:
        return final
    ok, why = docker_status()
    if not ok:
        raise RuntimeError(why)
    docker = shutil.which("docker")
    work = final.with_name(final.name + ".tmp")
    if only is None or not work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    (work / "recipe.json").write_text(json.dumps(r, sort_keys=True))
    tag = _docker_image(docker)
    names = [s for s in (only or r["sets"])]
    for s in names:
        if s not in r["sets"]:
            raise SystemExit(f"unknown set {s}; sets: {', '.join(r['sets'])}")
    cmd = [docker, "run", "--rm", "--privileged", "-v", f"{work}:/out", "-v", f"{HERE}:/fx:ro",
           "-e", f"HOST_UID={os.getuid()}", "-e", f"HOST_GID={os.getgid()}", tag,
           "sh", "-c", 'python3 /fx/_disks_inside.py /out/recipe.json /out "$@"; rc=$?; chown -R $HOST_UID:$HOST_GID /out; exit $rc',
           "sh", *names]
    p = subprocess.run(cmd)
    if p.returncode:
        raise RuntimeError(f"fixture build failed (exit {p.returncode}); partial output kept in {work}")
    if only and set(names) != set(r["sets"]):
        print(f"partial build of {names}: keeping {work}")
        return work
    manifest = {"version": RECIPE_VERSION, "recipe_hash": final.name, "passphrase": PASSPHRASE, "tools": _tool_versions(),
                "sets": {}}
    for sname, s in r["sets"].items():
        part = json.loads((work / sname / "manifest-part.json").read_text())
        entry = {"builder": s["builder"], "disks": part["disks"], "stacks": part["stacks"]}
        for k, v in s.items():
            if k not in ("builder", "disks", "arrays", "vgs"):
                entry[k] = v
        # reconstruction oracle: attach order and true member order per wiped array
        for st in entry["stacks"]:
            for a in s.get("arrays", []):
                if a["name"] == st["name"] and "presented" in a:
                    st["presented"] = [_serial(part["disks"], n) for n in a["presented"]]
                    st["true_order"] = a["true_order"]
        for st in entry["stacks"]:
            st["slot_serials"] = [_serial(part["disks"], n) for n in st["slots"]]
        manifest["sets"][sname] = entry
        (work / sname / "manifest-part.json").unlink()
    (work / "manifest.json").write_text(json.dumps(manifest, indent=1))
    shutil.rmtree(final, ignore_errors=True)
    work.rename(final)
    return final


def _serial(disks: list[dict], name: str) -> str:
    return next(d["serial"] for d in disks if d["name"] == name)


def _tool_versions() -> dict:
    return {"base": "ubuntu:26.04", "packages": "pinned in Dockerfile.disks"}


def needs() -> list[str]:
    out = []
    ok, why = docker_status()
    if not ok:
        out.append(why)
    if not shutil.which("zpool"):
        out.append("zfs: not built (host has no zfsutils/zfs kernel module)")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--set", action="append", dest="sets")
    b.add_argument("--force", action="store_true")
    sub.add_parser("path")
    sub.add_parser("list")
    sub.add_parser("needs")
    a = ap.parse_args(argv)
    if a.cmd == "path":
        print(cache_dir())
    elif a.cmd == "needs":
        print("\n".join(needs()) or "nothing missing")
    elif a.cmd == "build":
        try:
            print(build(a.sets, force=a.force))
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif a.cmd == "list":
        ok, why = status()
        if not ok:
            print(why, file=sys.stderr)
            return 1
        for sname, s in load()["sets"].items():
            print(f"{sname}: {len(s['disks'])} disks, {sum(d['size'] for d in s['disks']) // MIB} MiB virtual")
            for st in s["stacks"]:
                print(f"  {st['kind']:9} {st['name']:20} level={st.get('level', '-'):6} members={len(st['slots'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
