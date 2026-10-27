"""Drive images: installer wrapper, partition-table parsing, data-partition writers.

Data-partition trees are dicts mapping a path on the data partition to its
content: bytes, a Path to copy, or None for an (empty) directory. A trailing
"/" also marks a directory.

FAT32 images are written with mtools at the partition offset. exFAT has no
userspace writer, so exFAT images are populated through a loop device that
udisks sets up for us (no root needed): see UdisksMount. That path talks to
the system D-Bus and therefore only works outside a sandbox.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import env

SECTOR = 512
USER_CONFIG = "/beast-booter/config.cfg"


# ---------------------------------------------------------------------------
# Installer (task A) wrapper
# ---------------------------------------------------------------------------

def installer_status() -> tuple[bool, str]:
    """(usable, reason). Usable means `python3 -m beastbooter install --help` works."""
    if not (env.INSTALLER_DIR / "beastbooter" / "__main__.py").exists():
        return False, "installer not available yet: installer/beastbooter/__main__.py is missing (task A)"
    try:
        p = env.run([env.python(), "-m", "beastbooter", "install", "--help"], check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"installer not runnable: {e}"
    if p.returncode != 0:
        return False, f"`python3 -m beastbooter install --help` failed ({p.returncode}): {(p.stderr or p.stdout).strip()[-300:]}"
    return True, ""


def install(image: Path, *, layout: str = "msdos", fs: str = "fat32", size: str = "2G",
            dist: Path = env.DIST, serial: bool = True, extra: list[str] | tuple = ()) -> None:
    image = Path(image)
    if image.exists():
        image.unlink()
    cmd = [env.python(), "-m", "beastbooter", "install", "--image", str(image), "--size", size,
           "--layout", layout, "--fs", fs, "--dist", str(dist), "--yes"]
    if serial:
        cmd.append("--serial-console")
    cmd += list(extra)
    env.run(cmd, timeout=600)


def info(image: Path) -> dict:
    p = env.run([env.python(), "-m", "beastbooter", "info", "--image", str(image), "--json"], timeout=120)
    return json.loads(p.stdout)


def copy_image(src: Path, dst: Path) -> Path:
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "--sparse=always", str(src), str(dst)], check=True)
    return dst


# ---------------------------------------------------------------------------
# Partition tables and filesystem identifiers (read straight from the image)
# ---------------------------------------------------------------------------

@dataclass
class Partition:
    index: int
    start_lba: int
    size_lba: int
    type: str  # MBR: "0x0c"; GPT: upper-case type GUID
    active: bool = False  # MBR only
    name: str = ""  # GPT only

    @property
    def offset(self) -> int:
        return self.start_lba * SECTOR

    @property
    def size(self) -> int:
        return self.size_lba * SECTOR


def _guid(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


def read_mbr(image: Path) -> tuple[bytes, list[Partition]]:
    with open(image, "rb") as f:
        mbr = f.read(512)
    parts = []
    for i in range(4):
        e = mbr[446 + 16 * i : 446 + 16 * (i + 1)]
        ptype = e[4]
        start, count = struct.unpack_from("<II", e, 8)
        if ptype:
            parts.append(Partition(i + 1, start, count, f"0x{ptype:02x}", active=e[0] == 0x80))
    return mbr, parts


def read_gpt(image: Path) -> tuple[dict, list[Partition]]:
    with open(image, "rb") as f:
        f.seek(SECTOR)
        hdr = f.read(92)
        if hdr[:8] != b"EFI PART":
            raise ValueError(f"{image}: no GPT header at LBA 1")
        h = {
            "current_lba": struct.unpack_from("<Q", hdr, 24)[0],
            "backup_lba": struct.unpack_from("<Q", hdr, 32)[0],
            "first_usable": struct.unpack_from("<Q", hdr, 40)[0],
            "last_usable": struct.unpack_from("<Q", hdr, 48)[0],
            "entries_lba": struct.unpack_from("<Q", hdr, 72)[0],
            "num_entries": struct.unpack_from("<I", hdr, 80)[0],
            "entry_size": struct.unpack_from("<I", hdr, 84)[0],
        }
        f.seek(h["entries_lba"] * SECTOR)
        raw = f.read(h["num_entries"] * h["entry_size"])
    parts = []
    for i in range(h["num_entries"]):
        e = raw[i * h["entry_size"] : (i + 1) * h["entry_size"]]
        if e[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le").rstrip("\0")
        parts.append(Partition(i + 1, first, last - first + 1, _guid(e[:16]), name=name))
    return h, parts


def partitions(image: Path) -> tuple[str, list[Partition]]:
    """("msdos"|"gpt", partitions) from the image's own partition table."""
    _, mbr_parts = read_mbr(image)
    if any(p.type == "0xee" for p in mbr_parts):
        return "gpt", read_gpt(image)[1]
    return "msdos", mbr_parts


def volume_id(image: Path, offset: int) -> tuple[str, str]:
    """(fs, uuid as blkid prints it) read from the filesystem boot sector."""
    with open(image, "rb") as f:
        f.seek(offset)
        bs = f.read(512)
    if bs[3:11] == b"EXFAT   ":
        (serial,) = struct.unpack_from("<I", bs, 0x64)
        return "exfat", f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"
    if bs[3:11] == b"NTFS    ":
        (serial,) = struct.unpack_from("<Q", bs, 0x48)
        return "ntfs", f"{serial:016X}"
    if bs[0x52:0x5A] == b"FAT32   ":
        (serial,) = struct.unpack_from("<I", bs, 0x43)
        return "fat32", f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"
    if bs[0x36:0x3B] in (b"FAT16", b"FAT12"):
        (serial,) = struct.unpack_from("<I", bs, 0x27)
        return bs[0x36:0x3B].decode().lower(), f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"
    raise ValueError(f"{image}@{offset}: unrecognised filesystem")


# ---------------------------------------------------------------------------
# Writing to the data partition
# ---------------------------------------------------------------------------

def normalise_tree(tree: dict) -> tuple[list[str], dict[str, object]]:
    """-> (directories in creation order, {file path: content})."""
    dirs: list[str] = []
    files: dict[str, object] = {}

    def add_dir(d: str) -> None:
        parts = [p for p in d.strip("/").split("/") if p]
        for i in range(1, len(parts) + 1):
            sub = "/" + "/".join(parts[:i])
            if sub not in dirs:
                dirs.append(sub)

    for path, content in tree.items():
        if content is None or path.endswith("/"):
            add_dir(path)
        else:
            add_dir(path.rsplit("/", 1)[0])
            files["/" + path.strip("/")] = content
    return dirs, files


def _content_bytes(content) -> bytes:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode()
    return Path(content).read_bytes()


class FatWriter:
    """mtools access to a FAT partition inside an image."""

    def __init__(self, image: Path, offset: int):
        self.image, self.offset = Path(image), offset
        self.spec = f"{self.image}@@{offset}"

    def _m(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return env.run([args[0], "-i", self.spec, *args[1:]], check=check, timeout=120)

    def exists(self, path: str) -> bool:
        return self._m("mdir", "-b", f"::{path}", check=False).returncode == 0

    def mkdir(self, path: str) -> None:
        if not self.exists(path):
            self._m("mmd", f"::{path}")

    def put(self, path: str, content) -> None:
        if isinstance(content, (bytes, bytearray, str)):
            env.OUT.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=env.OUT, delete=False) as tf:
                tf.write(_content_bytes(content))
                src = tf.name
            try:
                self._m("mcopy", "-o", src, f"::{path}")
            finally:
                os.unlink(src)
        else:
            self._m("mcopy", "-o", str(content), f"::{path}")

    def read(self, path: str) -> bytes:
        return subprocess.run(["mtype", "-i", self.spec, f"::{path}"], capture_output=True, check=True,
                              env=env.tool_env()).stdout

    def listing(self, path: str = "/") -> list[str]:
        p = self._m("mdir", "-b", "-/", f"::{path}")
        return [line.strip() for line in p.stdout.splitlines() if line.strip()]

    def populate(self, tree: dict) -> None:
        dirs, files = normalise_tree(tree)
        for d in dirs:
            self.mkdir(d)
        for path, content in files.items():
            self.put(path, content)


# -- udisks (exFAT, NTFS) ----------------------------------------------------

_UDISKS_STATUS: tuple[bool, str] | None = None


def _udisksctl(*args: str, check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
    return env.run(["udisksctl", *args, "--no-user-interaction"], check=check, timeout=timeout)


def udisks_status() -> tuple[bool, str]:
    """Probe once whether we may set up (and delete) a loop device through udisks."""
    global _UDISKS_STATUS
    if _UDISKS_STATUS is not None:
        return _UDISKS_STATUS
    if not env.which("udisksctl"):
        _UDISKS_STATUS = (False, "udisksctl not installed")
        return _UDISKS_STATUS
    env.OUT.mkdir(parents=True, exist_ok=True)
    probe = env.OUT / "udisks-probe.img"
    try:
        with open(probe, "wb") as f:
            f.truncate(1024 * 1024)
        p = _udisksctl("loop-setup", "-f", str(probe), "--no-partition-scan", check=False, timeout=30)
        m = re.search(r"as (/dev/loop\d+)", p.stdout)
        if p.returncode != 0 or not m:
            reason = (p.stderr or p.stdout).strip().splitlines()
            _UDISKS_STATUS = (False, "udisksctl loop-setup is not usable here (needs the system D-Bus and "
                              "polkit; run outside the sandbox): " + (reason[-1] if reason else "no output"))
        else:
            _loop_delete(m.group(1), probe)
            _UDISKS_STATUS = (True, "")
    except (OSError, subprocess.TimeoutExpired) as e:
        _UDISKS_STATUS = (False, f"udisksctl probe failed: {e}")
    finally:
        try:
            probe.unlink()
        except OSError:
            pass
    return _UDISKS_STATUS


def _backing_file(dev: str) -> str:
    name = Path(dev).name
    try:
        return Path(f"/sys/block/{name}/loop/backing_file").read_text().strip()
    except OSError:
        return ""


def _loop_delete(dev: str, image: Path) -> None:
    # Only ever delete a loop device that is backed by the file we set up.
    bf = _backing_file(dev)
    if bf and os.path.realpath(bf) != os.path.realpath(image):
        raise RuntimeError(f"refusing to delete {dev}: backed by {bf}, not {image}")
    _udisksctl("loop-delete", "-b", dev, check=False)


def _mount_point(dev: str) -> str | None:
    p = subprocess.run(["findmnt", "-n", "-o", "TARGET", "--source", dev], capture_output=True, text=True)
    out = p.stdout.strip().splitlines()
    return out[0] if out else None


def udisks_mount(image: Path, offset: int, size: int):
    """Loop-mount one partition of an image via udisks; yields the mount point.

    Shared with bb-dev (devtools/bbdev/diskimg.py): it holds off the desktop
    automounter, handles AlreadyMounted, and always releases the loop device.
    """
    from bbdev.diskimg import udisks_mount as _udisks_mount

    return _udisks_mount(image, offset, size)


class MountedWriter:
    """Same interface as FatWriter, for a filesystem mounted at `root`."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def _p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def exists(self, path: str) -> bool:
        return self._p(path).exists()

    def mkdir(self, path: str) -> None:
        self._p(path).mkdir(parents=True, exist_ok=True)

    def put(self, path: str, content) -> None:
        dest = self._p(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, (bytes, bytearray, str)):
            dest.write_bytes(_content_bytes(content))
        else:
            shutil.copyfile(content, dest)

    def read(self, path: str) -> bytes:
        return self._p(path).read_bytes()

    def populate(self, tree: dict) -> None:
        dirs, files = normalise_tree(tree)
        for d in dirs:
            self.mkdir(d)
        for path, content in files.items():
            self.put(path, content)


# ---------------------------------------------------------------------------
# A beast-boot drive image
# ---------------------------------------------------------------------------

@dataclass
class Drive:
    path: Path
    layout: str
    fs: str  # installer name: exfat | fat32 | ntfs
    data_start_lba: int
    data_size_lba: int
    data_uuid: str  # as blkid shows it (bb_data_uuid_linux)
    info: dict

    @property
    def data_offset(self) -> int:
        return self.data_start_lba * SECTOR

    @property
    def data_size(self) -> int:
        return self.data_size_lba * SECTOR

    @classmethod
    def open(cls, path: Path, layout: str, fs: str) -> Drive:
        inf = info(path)
        data = inf["data"]
        start, size = int(data["start_lba"]), int(data["size_lba"])
        found_fs, uuid_ = volume_id(path, start * SECTOR)
        return cls(Path(path), layout, fs, start, size, uuid_, inf)

    def copy(self, dst: Path) -> Drive:
        copy_image(self.path, dst)
        return Drive(Path(dst), self.layout, self.fs, self.data_start_lba, self.data_size_lba, self.data_uuid, self.info)

    @contextmanager
    def data_writer(self):
        if self.fs == "fat32":
            yield FatWriter(self.path, self.data_offset)
        else:
            with udisks_mount(self.path, self.data_offset, self.data_size) as mp:
                yield MountedWriter(mp)

    def populate(self, tree: dict) -> None:
        with self.data_writer() as w:
            w.populate(tree)

    def write_config(self, text: str) -> None:
        with self.data_writer() as w:
            w.mkdir("/beast-booter")
            w.put(USER_CONFIG, text)


def user_config(*, debug: bool = True, dryrun: bool = False, autoboot: str | None = None,
                timeout: int | None = None, extra: str = "") -> str:
    """GRUB script for /beast-booter/config.cfg. Values are exported in case the
    menu loads the file with `configfile` rather than `source`."""
    lines = ["# written by tests/e2e"]

    def setvar(name: str, value: str) -> None:
        esc = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
        lines.append(f'set {name}="{esc}"')
        lines.append(f"export {name}")

    if debug:
        setvar("bb_debug", "1")
    if dryrun:
        setvar("bb_dryrun", "1")
    if autoboot:
        setvar("bb_autoboot", autoboot)
    if timeout is not None:
        setvar("timeout", str(timeout))
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"
