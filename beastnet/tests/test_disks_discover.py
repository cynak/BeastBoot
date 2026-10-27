"""Disk discovery: sysfs + blkid on a fake machine (nothing touches a real device)."""

import os

import pytest

from beastnet.disks import discover
from beastnet.disks.model import Transport, VolumeKind
from disk_fakes import Env


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.add_disk("sda", 1024, model="Samsung SSD 860", serial="S3Z9NB0K123456A", wwid="naa.5002538e00000001",
               vpd=True)
    e.add_part("sda", 1, 1, 512, TYPE="ntfs", LABEL="Win", UUID="AAAA-1111", PART_ENTRY_TYPE="ebd0a0a2-b9e5-4433")
    e.add_part("sda", 2, 513, 511, TYPE="ext4", UUID="u-2", PART_ENTRY_TYPE="0x83")
    e.add_disk("nvme0n1", 2048, transport="nvme", model="WD Black SN850", serial="WD-NVME-777", wwid="eui.0001")
    e.add_disk("sdb", 4096, transport="usb", model="Elements", serial="USB-SER-1", removable=1, rotational=1)
    e.add_disk("sdc", 256, transport="usb", model="Cruzer", serial="STICK-1", removable=1)
    e.add_part("sdc", 1, 1, 64, TYPE="vfat")
    e.add_part("sdc", 2, 65, 190, TYPE="ext4", LABEL="BEASTDATA")
    e.add_disk("vda", 128, transport="virtio", serial="VIRT-1")
    e.add_disk("loop0", 10)  # never listed
    e.blk[e.dev("sda")] = {"PTTYPE": "gpt"}
    e.blk[e.dev("sdc")] = {"PTTYPE": "gpt"}
    e.set_mounts(f"{e.dev('sdc2')} {e.paths.data} ext4 rw 0 0", f"{e.dev('sdc1')} {e.paths.esp} vfat rw 0 0")
    return e


def test_scan_finds_every_disk(env):
    inv = discover.scan(env.ctx)
    by = {d.id: d for d in inv.disks}
    assert sorted(by) == ["nvme0n1", "sda", "sdb", "sdc", "vda"]
    sda = by["sda"]
    assert (sda.serial, sda.wwn, sda.size) == ("S3Z9NB0K123456A", "naa.5002538e00000001", 1024 << 20)
    assert (sda.logical_sector, sda.physical_sector, sda.model) == (512, 4096, "Samsung SSD 860")
    assert sda.transport == Transport.SATA and not sda.rotational and not sda.removable
    assert by["nvme0n1"].transport == Transport.NVME and by["nvme0n1"].serial == "WD-NVME-777"
    assert by["sdb"].transport == Transport.USB and by["sdb"].rotational and by["sdb"].removable
    assert by["vda"].transport == Transport.VIRTIO
    assert [p.id for p in sda.partitions] == ["sda1", "sda2"]
    p1 = sda.partitions[0]
    assert (p1.fs_type, p1.label, p1.uuid, p1.start, p1.size) == ("ntfs", "Win", "AAAA-1111", 1 << 20, 512 << 20)
    assert sda.partitions[1].type == "0x83"


def test_stick_is_marked_from_the_data_and_esp_mounts(env):
    inv = discover.scan(env.ctx)
    assert [d.id for d in inv.disks if d.is_boot_stick] == ["sdc"]


def test_volumes_cover_disks_and_partitions(env):
    inv = discover.scan(env.ctx)
    ids = {v.id: v for v in inv.volumes}
    assert ids["sda"].kind == VolumeKind.DISK and ids["sda1"].kind == VolumeKind.PARTITION
    assert ids["sda1"].disk_ids == ["sda"] and ids["sda1"].fs_type == "ntfs"
    assert "loop0" not in ids


def test_assembled_devices_are_volumes_with_their_disks(env):
    env.add_virtual("md127", 100, slaves=["sda2"], meta="1.2")
    env.add_virtual("dm-0", 50, slaves=["md127"], uuid="CRYPT-LUKS2-abc-x")
    env.add_virtual("md126", 1, meta="external:imsm")  # a container is not data
    inv = discover.scan(env.ctx)
    ids = {v.id: v for v in inv.volumes}
    assert ids["md127"].kind == VolumeKind.MD and ids["md127"].disk_ids == ["sda"]
    assert ids["dm-0"].kind == VolumeKind.CRYPT and ids["dm-0"].disk_ids == ["sda"]
    assert "md126" not in ids


def test_events(env):
    discover.scan(env.ctx)
    lines = env.rep.lines
    assert ("BEASTNET: disk found id=sda serial=S3Z9NB0K123456A size=1073741824 lss=512 pss=4096 "
            "transport=sata stick=0") in lines
    assert any(line.startswith("BEASTNET: disk found id=sdc") and line.endswith("stick=1") for line in lines)


def test_disk_without_serial_gets_dash_in_event(env):
    env.add_disk("sdd", 64)
    discover.scan(env.ctx)
    assert any(line.startswith("BEASTNET: disk found id=sdd serial=- ") for line in env.rep.lines)


def test_nvme_multipath_serial_from_controller(tmp_path):
    e = Env(tmp_path)
    real = e.add_disk("nvme1n1", 64, transport="nvme", serial="")
    e.write(e.sys("class", "nvme", "nvme1", "serial"), "CTRL-SER\n")
    os.symlink(real, e.sys("class", "nvme", "nvme1", "nvme1n1"))
    assert discover.serial_of(e.sys(), "nvme1n1") == "CTRL-SER"


def test_blkid_is_asked_with_low_level_probe_only(env):
    discover.scan(env.ctx)
    for call in env.runner.ran("blkid"):
        assert call[:4] == ["blkid", "-p", "-o", "export"]
    assert not [c for c in env.runner.calls if c[0] not in ("blkid", "mdadm", "lvm", "zpool", "ldmtool")]
