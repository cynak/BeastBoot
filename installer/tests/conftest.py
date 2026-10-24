"""Shared fixtures for the installer tests. Everything works on image files in tmp dirs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # installer/ -> import beastbooter
sys.path.insert(0, str(HERE))  # fakedist

import fakedist  # noqa: E402
from beastbooter import blockio, cli  # noqa: E402
from beastbooter.errors import BeastError  # noqa: E402
from beastbooter.esp import parse_set_lines  # noqa: E402
from beastbooter.layout import SECTOR_SIZE  # noqa: E402

# ---------------------------------------------------------------------------
# Big sparse image files
# ---------------------------------------------------------------------------

O_BINARY = getattr(os, "O_BINARY", 0)  # Windows: os.open is in text mode without it
pread, pwrite = blockio._pread, blockio._pwrite  # os.pread / os.pwrite do not exist on Windows

# Up to this size a test file is fine even where it cannot stay sparse. Above it
# the test is skipped on such a file system instead of filling the disk.
BIG_FILE = 4 << 30
_sparse_ok: dict[int, bool] = {}
_made: list[Path] = []


def allocated_bytes(path) -> int:
    """Disk space a file takes: st_blocks on POSIX, GetCompressedFileSizeW on Windows."""
    if os.name != "nt":
        return os.stat(path).st_blocks * 512
    import ctypes
    from ctypes import wintypes

    fn = ctypes.WinDLL("kernel32", use_last_error=True).GetCompressedFileSizeW
    fn.restype = wintypes.DWORD
    fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    high = wintypes.DWORD(0)
    low = fn(str(path), ctypes.byref(high))
    if low == 0xFFFFFFFF and ctypes.get_last_error():
        raise ctypes.WinError(ctypes.get_last_error())
    return (high.value << 32) | low


def keeps_sparse(directory) -> bool:
    """Can files in `directory` stay sparse? Probe: a 2*BIG_FILE file, one byte written at its end."""
    key = os.stat(directory).st_dev
    if key not in _sparse_ok:
        probe = Path(directory) / "sparse-probe.bin"
        ok = False
        try:
            with blockio.ImageTarget.create(str(probe), 2 * BIG_FILE) as t:
                # Not sparse: NTFS reserves the whole size at once; never write then.
                if allocated_bytes(probe) < BIG_FILE:
                    t.write(t.size - 1, b"\0")
                    t.flush()
                    ok = allocated_bytes(probe) < 64 << 20
        except (OSError, BeastError):
            ok = False
        finally:
            probe.unlink(missing_ok=True)
        _sparse_ok[key] = ok
    return _sparse_ok[key]


def sparse_file(path, size: int) -> Path:
    """A new all-zero file of `size` bytes that takes no disk space until written
    (blockio.ImageTarget.create: FSCTL_SET_SPARSE on Windows). Deleted after the test.
    Bigger than BIG_FILE: skipped where the file system cannot keep it sparse."""
    path = Path(path)
    if size > BIG_FILE and not keeps_sparse(path.parent):
        pytest.skip(f"{path.parent} cannot keep a {size / (1 << 30):.0f} GiB file sparse")
    blockio.ImageTarget.create(str(path), size).close()
    _made.append(path)
    return path


@pytest.fixture(autouse=True)
def _delete_sparse_files():
    """Delete what sparse_file made as soon as its test ends, so a run never piles up images."""
    yield
    while _made:
        try:
            _made.pop().unlink(missing_ok=True)
        except OSError:  # still open (Windows): left for pytest's tmp cleanup
            pass


# The installer itself needs no tools for exFAT/FAT32 (pure Python); mkfs.ntfs
# makes NTFS. The others are independent validators used by the tests.
TOOLS = ["sfdisk", "blkid", "mkfs.ntfs", "mcopy", "mmd", "mtype", "mdir"]
MISSING = [t for t in TOOLS if shutil.which(t) is None]
needs_tools = pytest.mark.skipif(bool(MISSING), reason=f"missing tools: {MISSING} (source scripts/dev-env.sh)")
FSCK_TOOLS = ["fsck.fat", "fsck.exfat", "sgdisk"]
MISSING_FSCK = [t for t in FSCK_TOOLS if shutil.which(t) is None]
needs_fsck = pytest.mark.skipif(bool(MISSING_FSCK), reason=f"missing validators: {MISSING_FSCK}")

# Not a whole number of MiB (and not even of sectors): 1100000001 bytes.
ODD_SIZE = "1100000001"
MTOOLS_ENV = {**os.environ, "MTOOLS_SKIP_CHECK": "1", "MTOOLSRC": "/dev/null"}


def run_cli(*args: str) -> int:
    return cli.main([str(a) for a in args])


def read_events(path: Path) -> list[dict]:
    """The progress file as a list of events (every line must be complete JSON)."""
    text = Path(path).read_text(encoding="utf-8")
    assert text == "" or text.endswith("\n"), "last progress line is unterminated"
    return [json.loads(line) for line in text.splitlines()]


def step_ids(events: list[dict]) -> list[str]:
    """Step ids in order, consecutive repeats (progress updates of one step) folded."""
    out: list[str] = []
    for e in events:
        if e["event"] == "step" and (not out or out[-1] != e["step"]):
            out.append(e["step"])
    return out


def sh(*cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, check=True, **kw)


def sfdisk_json(img: Path) -> dict:
    return json.loads(sh("sfdisk", "-J", img).stdout)["partitiontable"]


def blkid_at(img: Path, offset: int) -> dict:
    out = sh("blkid", "-p", "-O", offset, "-o", "export", img).stdout
    pairs = (line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {k: re.sub(r"\\(.)", r"\1", v) for k, v in pairs}  # export format escapes spaces


def mtype(img: Path, offset: int, path: str) -> str:
    return sh("mtype", "-i", f"{img}@@{offset}", f"::/{path}", env=MTOOLS_ENV).stdout


def mdir_files(img: Path, offset: int) -> set[str]:
    out = sh("mdir", "-i", f"{img}@@{offset}", "-/", "-b", "::/", env=MTOOLS_ENV).stdout
    return {line[3:] for line in out.splitlines() if line.startswith("::/") and not line.endswith("/")}


def extract(img: Path, offset: int, size: int, out: Path) -> Path:
    """Copy bytes [offset, offset+size) of img into a sparse file (for fsck tools)."""
    zero = bytes(1 << 20)
    with open(img, "rb") as src, open(out, "wb") as dst:
        src.seek(offset)
        left = size
        while left:
            chunk = src.read(min(left, len(zero)))
            assert chunk, "image shorter than the partition"
            if chunk == zero[: len(chunk)]:
                dst.seek(len(chunk), os.SEEK_CUR)
            else:
                dst.write(chunk)
            left -= len(chunk)
        dst.truncate(size)
    return out


def fsck(tool: str, img: Path, offset: int, size: int, tmp: Path) -> subprocess.CompletedProcess:
    """Run `tool -n` (fsck.fat / fsck.exfat: check only) on one partition of img."""
    part = extract(img, offset, size, tmp / f"part-{offset}.bin")
    try:
        return subprocess.run([tool, "-n", str(part)], capture_output=True, text=True)
    finally:
        part.unlink()


def info_json(img: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "beastbooter", "info", "--image", str(img), "--json"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(HERE.parent)},
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def sha_region(img: Path, start_lba: int, sectors: int) -> str:
    h = hashlib.sha256()
    with open(img, "rb") as f:
        f.seek(start_lba * SECTOR_SIZE)
        left = sectors * SECTOR_SIZE
        while left:
            chunk = f.read(min(left, 1 << 22))
            assert chunk
            h.update(chunk)
            left -= len(chunk)
    return h.hexdigest()


@pytest.fixture(scope="session")
def fake_dist(tmp_path_factory) -> Path:
    return fakedist.make_fake_dist(tmp_path_factory.mktemp("dist") / "dist", "0.1.0")


@pytest.fixture(scope="session")
def fake_dist_v2(tmp_path_factory) -> Path:
    return fakedist.make_fake_dist(tmp_path_factory.mktemp("dist2") / "dist", "0.2.0")


@pytest.fixture
def dist_copy(fake_dist, tmp_path) -> Path:
    """A private copy of the fake dist that a test may break."""
    d = tmp_path / "dist"
    shutil.copytree(fake_dist, d)
    return d


@pytest.fixture(scope="session")
def installed(tmp_path_factory, fake_dist):
    """installed(layout, fs) -> path of a fresh image (built once per combination)."""
    cache: dict[tuple[str, str], Path] = {}
    base = tmp_path_factory.mktemp("images")

    def get(layout: str, fs: str) -> Path:
        key = (layout, fs)
        if key not in cache:
            img = base / f"{layout}-{fs}.img"
            rc = run_cli("install", "--image", img, "--size", ODD_SIZE, "--layout", layout,
                         "--fs", fs, "--yes", "--quiet", "--dist", fake_dist)
            assert rc == 0
            cache[key] = img
        return cache[key]

    return get


def fresh_image(tmp_path: Path, dist: Path, layout="msdos", fs="exfat", size=ODD_SIZE, *extra) -> Path:
    img = tmp_path / f"{layout}-{fs}.img"
    rc = run_cli("install", "--image", img, "--size", size, "--layout", layout, "--fs", fs,
                 "--yes", "--quiet", "--dist", dist, *extra)
    assert rc == 0
    return img


def validate_drive(img: Path, layout: str, fs: str, label: str, tmp: Path) -> dict:
    """Check a finished drive with independent tools; returns its `info --json`.

    sfdisk -V (and sgdisk -v for GPT), fsck.fat -n on the ESP, fsck.exfat -n /
    fsck.fat -n on the data partition, and blkid's label and UUID of the data
    partition == device.cfg == info --json.
    """
    p = subprocess.run(["sfdisk", "-V", str(img)], capture_output=True, text=True)
    assert p.returncode == 0 and "No errors detected" in p.stdout, p.stdout + p.stderr
    if layout == "gpt":
        p = subprocess.run(["sgdisk", "-v", str(img)], capture_output=True, text=True)
        assert p.returncode == 0 and "No problems found" in p.stdout, p.stdout + p.stderr
    j = info_json(img)
    assert j["layout"] == layout
    esp_off, esp_size = j["esp"]["start_lba"] * SECTOR_SIZE, j["esp"]["size_lba"] * SECTOR_SIZE
    data_off, data_size = j["data"]["start_lba"] * SECTOR_SIZE, j["data"]["size_lba"] * SECTOR_SIZE
    p = fsck("fsck.fat", img, esp_off, esp_size, tmp)
    assert p.returncode == 0, p.stdout + p.stderr
    p = fsck("fsck.exfat" if fs == "exfat" else "fsck.fat", img, data_off, data_size, tmp)
    assert p.returncode == 0, p.stdout + p.stderr
    probe = blkid_at(img, data_off)
    assert probe["TYPE"] == {"exfat": "exfat", "fat32": "vfat", "ntfs": "ntfs"}[fs]
    cfg = parse_set_lines(mtype(img, esp_off, "grub/beast/device.cfg"))
    assert probe["LABEL"] == label == cfg["bb_data_label"] == j["data"]["label"]
    assert probe["UUID"] == cfg["bb_data_uuid_linux"] == j["data"]["uuid"]
    assert cfg["bb_data_uuid"] == probe["UUID"].upper()
    assert (cfg["bb_data_fs"], cfg["bb_layout"]) == (fs, layout) == (j["data"]["fs"], j["layout"])
    esp = blkid_at(img, esp_off)
    assert (esp["TYPE"], esp.get("VERSION"), esp["LABEL"]) == ("vfat", "FAT32", "BEAST-EFI")
    return j
