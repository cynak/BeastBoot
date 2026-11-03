"""`update` reads beast-net/firmware/** from the old ESP (esp.read_kept_files).
A crafted ESP must give a clear error, not an endless loop (a directory entry
pointing back at its own directory) or unbounded memory (many entries sharing
one big cluster chain)."""

from __future__ import annotations

import struct
import threading

import pytest
from test_x_fatfs import new_volume

from beastbooter import fatfs
from beastbooter.errors import BeastError
from beastbooter.esp import FIRMWARE_DIR, read_kept_files
from beastbooter.fatfs import FatVolume
from beastbooter.layout import MIB


def _patch_entry(t, vol: FatVolume, parent: str, name: str, cluster: int, size: int | None = None) -> None:
    """Corrupt the volume: make directory entry parent/name start at `cluster` (and claim `size`)."""
    d = vol._walk(fatfs._split(parent))
    ent = d.lookup(name)
    raw = bytearray(d.data[ent.slot * 32 : (ent.slot + 1) * 32])
    struct.pack_into("<H", raw, 20, cluster >> 16)
    struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
    if size is not None:
        struct.pack_into("<I", raw, 28, size)
    cs = vol.cluster_size
    t.write(vol._cluster_offset(d.clusters[ent.slot * 32 // cs]) + ent.slot * 32 % cs, bytes(raw))


def _kept_within(vol: FatVolume, seconds: float = 20.0):
    """read_kept_files(vol) in a thread: (finished, result or exception)."""
    out: list = []

    def run() -> None:
        try:
            out.append(read_kept_files(vol))
        except BaseException as e:  # noqa: BLE001 - handed back to the test
            out.append(e)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(seconds)
    return (not th.is_alive()), (out[0] if out else None)


@pytest.mark.parametrize("bits,size,target", [(16, 20 * MIB, "self"), (32, 40 * MIB, "self"),
                                              (16, 20 * MIB, "parent")])
def test_directory_loop_in_firmware_dir_is_an_error(tmp_path, bits, size, target):
    t = new_volume(tmp_path, size, bits)
    vol = FatVolume(t, 0)
    vol.write_file(f"{FIRMWARE_DIR}/sub/a.bin", b"a")
    vol.write_file(f"{FIRMWARE_DIR}/sub/inner/b.bin", b"b")
    to = vol._walk(fatfs._split(f"{FIRMWARE_DIR}/sub")).key if target == "self" else \
        vol._walk(fatfs._split(FIRMWARE_DIR)).key
    _patch_entry(t, vol, f"{FIRMWARE_DIR}/sub", "inner", to)
    finished, result = _kept_within(FatVolume(t, 0))
    t.close()
    assert finished, "read_kept_files loops forever on a directory loop"
    assert isinstance(result, BeastError), result
    assert "loop" in str(result)


def test_entries_sharing_one_cluster_chain_are_an_error(tmp_path):
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    big = 2 * MIB
    vol.write_file(f"{FIRMWARE_DIR}/big.bin", b"\xaa" * big)
    for i in range(40):  # 40 x 2 MiB claimed on a 20 MiB volume
        vol.write_file(f"{FIRMWARE_DIR}/f{i:02d}.bin", b"x")
    cluster = vol._walk(fatfs._split(FIRMWARE_DIR)).lookup("big.bin").cluster
    for i in range(40):
        _patch_entry(t, vol, FIRMWARE_DIR, f"f{i:02d}.bin", cluster, big)
    finished, result = _kept_within(FatVolume(t, 0))
    t.close()
    assert finished
    assert isinstance(result, BeastError), "cross-linked files were read into memory"
    assert "cross-linked" in str(result) or "more than" in str(result)


def test_normal_firmware_dir_is_kept(tmp_path):
    t = new_volume(tmp_path, 20 * MIB, 16)
    vol = FatVolume(t, 0)
    files = {f"{FIRMWARE_DIR}/installed.json": b"{}", f"{FIRMWARE_DIR}/p.cpio": b"c" * 5000,
             f"{FIRMWARE_DIR}/d/e/empty": b"", f"{FIRMWARE_DIR}/d/empty2": b""}
    vol.write_files(files)
    assert read_kept_files(FatVolume(t, 0)) == files
    t.close()
