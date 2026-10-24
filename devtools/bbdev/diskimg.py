"""Dev drive images: installer `info --json`, FAT access with mtools, udisks mounts.

FAT partitions (the 512 MiB FAT32 ESP, FAT32 data partitions) are read and
written with mtools at the partition offset (`image@@offset`), no mounting.
exFAT and NTFS have no userspace writer, so those data partitions go through a
loop device that udisks sets up for us (no root needed). That talks to the
system D-Bus, so it only works outside a sandbox. Loop devices are always
unmounted, deleted and then checked to be gone (a desktop automounter can
mount them again in between; see release_loop), and only one backed by our own
image file is ever touched. An image that is still attached read-write
elsewhere is refused. bb-dev never writes to a real block device.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import paths
from .msg import Failure

SECTOR = 512
ESP_MARKER = "BEAST-BOOTER.ID"
USER_CONFIG = "/beast-booter/config.cfg"


def tool_env() -> dict[str, str]:
    """load_env() plus what mtools and the installer need."""
    env = dict(paths.load_env())
    env["MTOOLS_SKIP_CHECK"] = "1"
    pp = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    for d in (str(paths.REPO / "installer"), str(paths.REPO / "devtools")):
        if d not in pp:
            pp.insert(0, d)
    env["PYTHONPATH"] = os.pathsep.join(pp)
    return env


def run(cmd: list, *, check: bool = True, timeout: float = 300, **kw) -> subprocess.CompletedProcess:
    kw.setdefault("env", tool_env())
    kw.setdefault("capture_output", True)
    kw.setdefault("stdin", subprocess.DEVNULL)  # mtools must never wait for an answer
    try:
        p = subprocess.run([str(c) for c in cmd], timeout=timeout, check=False, **kw)
    except FileNotFoundError:
        raise Failure(f"{cmd[0]} not found", "run `bb-dev doctor`; scripts/bootstrap-tools.sh installs missing tools")
    if check and p.returncode != 0:
        out = p.stderr if isinstance(p.stderr, str) else (p.stderr or b"").decode(errors="replace")
        raise Failure(f"`{' '.join(map(str, cmd))}` failed ({p.returncode}): {out.strip()[-800:]}")
    return p


# ---------------------------------------------------------------------------
# Installer info
# ---------------------------------------------------------------------------

@dataclass
class ImageInfo:
    path: Path
    layout: str
    version: str
    data_fs: str
    data_start_lba: int
    data_size_lba: int
    esp_start_lba: int
    esp_size_lba: int
    raw: dict

    @property
    def data_offset(self) -> int:
        return self.data_start_lba * SECTOR

    @property
    def data_size(self) -> int:
        return self.data_size_lba * SECTOR

    @property
    def esp_offset(self) -> int:
        return self.esp_start_lba * SECTOR

    @property
    def esp_size(self) -> int:
        return self.esp_size_lba * SECTOR

    def esp(self) -> Fat:
        return Fat(self.path, self.esp_offset)

    def data_fat(self) -> Fat:
        if self.data_fs != "fat32":
            raise ValueError("data partition is not FAT32")
        return Fat(self.path, self.data_offset)


def image_info(image: Path) -> ImageInfo:
    """`beast-booter info --image P --json`, parsed."""
    image = Path(image)
    if not image.is_file():
        raise Failure(f"image not found: {image}", "build one with `bb-dev image --fixtures --debug`")
    p = run([sys.executable, "-m", "beastbooter", "info", "--image", image, "--json"], check=False,
            timeout=120, text=True)
    if p.returncode != 0:
        raise Failure(f"{image} is not a beast-booter image: {(p.stderr or p.stdout).strip()[-400:]}")
    d = json.loads(p.stdout)
    return ImageInfo(image, d.get("layout", ""), d.get("version", ""), d["data"].get("fs", ""),
                     int(d["data"]["start_lba"]), int(d["data"]["size_lba"]),
                     int(d["esp"]["start_lba"]), int(d["esp"]["size_lba"]), d)


# ---------------------------------------------------------------------------
# FAT via mtools
# ---------------------------------------------------------------------------

class Fat:
    """mtools access to one FAT partition inside an image. Paths are absolute
    inside the partition, '/'-separated."""

    def __init__(self, image: Path, offset: int):
        self.image = Path(image)
        self.offset = int(offset)
        self.spec = f"{self.image}@@{self.offset}"

    def _m(self, tool: str, *args, check: bool = True, timeout: float = 600) -> subprocess.CompletedProcess:
        return run([tool, "-i", self.spec, *args], check=check, timeout=timeout)

    def read(self, path: str) -> bytes | None:
        p = self._m("mtype", f"::{path}", check=False)
        return p.stdout if p.returncode == 0 else None

    def exists(self, path: str) -> bool:
        return self._m("mdir", "-b", f"::{path}", check=False).returncode == 0

    def listing(self, path: str = "/", recursive: bool = False) -> list[str]:
        """Entries below `path` as absolute paths; directories end with '/'."""
        args = ["-b"] + (["-/"] if recursive else [])
        p = self._m("mdir", *args, f"::{path}", check=False)
        if p.returncode != 0:
            return []
        out = []
        for line in p.stdout.decode(errors="surrogateescape").splitlines():
            line = line.strip()
            if line.startswith("::"):
                line = line[2:]
            if line and line not in (path, path.rstrip("/") + "/"):
                out.append(line)
        return out

    def mkdirs(self, path: str) -> list[str]:
        """Create `path` and its parents; returns the directories created."""
        made = []
        cur = ""
        for part in [p for p in path.split("/") if p]:
            cur += "/" + part
            if not self.exists(cur):
                self._m("mmd", f"::{cur}")
                made.append(cur)
        return made

    def put_bytes(self, path: str, data: bytes) -> None:
        self.mkdirs(str(PurePosixPath(path).parent))
        paths.OUT.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=paths.OUT, prefix=".bbdev-", delete=False) as tf:
            tf.write(data)
            src = tf.name
        try:
            self._m("mcopy", "-o", src, f"::{path}")
        finally:
            os.unlink(src)

    def put_files(self, dest_dir: str, sources: list[Path]) -> None:
        """Copy local files into `dest_dir` (keeping their names), one mcopy call."""
        if not sources:
            return
        self.mkdirs(dest_dir)
        self._m("mcopy", "-o", *[str(s) for s in sources], f"::{dest_dir.rstrip('/')}/")

    def delete(self, path: str) -> None:
        self._m("mdel", f"::{path}")

    def rmdir(self, path: str) -> bool:
        return self._m("mrd", f"::{path}", check=False).returncode == 0

    def copy_out(self, sources: list[str], dest: Path) -> None:
        """mcopy -s files/directories out of the partition into local `dest`."""
        if sources:
            self._m("mcopy", "-s", "-n", "-m", *[f"::{s}" for s in sources], str(dest) + "/", check=False)


# ---------------------------------------------------------------------------
# udisks (exFAT, NTFS)
# ---------------------------------------------------------------------------

_UDISKS: tuple[bool, str] | None = None
SYS_BLOCK = Path("/sys/block")
RELEASE_TIMEOUT = 6.0  # seconds to get a loop device unmounted and deleted
INHIBIT_REASON = "bb-dev: editing a dev drive image"
GNOME_AUTOMOUNT_INHIBIT = 16  # GsmInhibitorFlag AUTOMOUNT


def _udisksctl(*args: str, check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
    return run(["udisksctl", *args, "--no-user-interaction"], check=check, timeout=timeout, text=True)


def _sys_loop(dev: str, attr: str) -> str:
    try:
        return (SYS_BLOCK / Path(dev).name / attr).read_text().strip()
    except OSError:
        return ""


def _backing_file(dev: str) -> str:
    return _sys_loop(dev, "loop/backing_file")


def _is_ours(dev: str, image: Path) -> bool:
    """Is `dev` still a loop device backed by `image`? (False once it is
    deleted, or when its number has been reused for another file.)"""
    bf = _backing_file(dev)
    return bool(bf) and os.path.realpath(bf) == os.path.realpath(image)


def _loop_delete(dev: str, image: Path) -> None:
    # Only ever delete a loop device that is backed by the file we set up.
    bf = _backing_file(dev)
    if bf and os.path.realpath(bf) != os.path.realpath(image):
        raise Failure(f"refusing to delete {dev}: backed by {bf}, not {image}")
    _udisksctl("loop-delete", "-b", dev, check=False)


def _mount_point(dev: str) -> str | None:
    p = subprocess.run(["findmnt", "-n", "-o", "TARGET", "--source", dev], capture_output=True, text=True,
                       check=False)
    out = p.stdout.strip().splitlines()
    return out[0] if out else None


@dataclass
class Attachment:
    """A loop device backed by an image file (set up by anyone)."""
    dev: str
    read_only: bool
    autoclear: bool
    mount_point: str | None

    def describe(self) -> str:
        how = "read-only" if self.read_only else "read-write"
        return f"{self.dev} ({how}, " + (f"mounted at {self.mount_point})" if self.mount_point else "not mounted)")

    def release_cmd(self) -> str:
        if self.mount_point and self.autoclear:  # it detaches itself once unmounted
            return f"udisksctl unmount -b {self.dev}"
        if self.mount_point:
            return f"udisksctl unmount -b {self.dev} && udisksctl loop-delete -b {self.dev}"
        return f"udisksctl loop-delete -b {self.dev}"


def attachment(dev: str) -> Attachment:
    return Attachment(dev, _sys_loop(dev, "ro") == "1", _sys_loop(dev, "loop/autoclear") == "1", _mount_point(dev))


def attachments(image: Path) -> list[Attachment]:
    """Loop devices on this host backed by `image`, e.g. left behind by an
    interrupted run or opened by hand. Read from sysfs; nothing is changed."""
    real = os.path.realpath(image)
    found = []
    for bf in SYS_BLOCK.glob("loop*/loop/backing_file"):
        try:
            backing = bf.read_text().strip()
        except OSError:
            continue
        if backing and os.path.realpath(backing) == real:
            found.append("/dev/" + bf.parent.parent.name)
    found.sort(key=lambda d: int(re.sub(r"\D", "", d) or 0))
    return [attachment(d) for d in found]


def release_hint(atts: list[Attachment]) -> str:
    cmds = "; ".join(a.release_cmd() for a in atts)
    mounted = [a.mount_point for a in atts if a.mount_point]
    close = f"close anything using {', '.join(mounted)} (a file manager window?), then " if mounted else ""
    return f"{close}run: {cmds}"


@contextmanager
def automount_inhibited(env: dict[str, str] | None = None):
    """Hold a GNOME session "automount" inhibitor while we own a loop device.

    Without it the desktop automounter mounts our loop device as soon as it
    appears (and opens a file manager window on it), and mounts it again in
    the moment between our unmount and loop-delete, so the loop device stays
    behind, mounted. The inhibitor is the documented session API for this
    (`gnome-session-inhibit --inhibit automount`); no setting is changed, and
    it ends with our process: the helper exits when its stdin pipe closes,
    even if bb-dev is killed. Best effort: yields False outside GNOME; the
    release check in udisks_mount still catches a re-mount there.
    """
    env = env if env is not None else tool_env()
    exe = shutil.which("gnome-session-inhibit", path=env.get("PATH"))
    bus = env.get("DBUS_SESSION_BUS_ADDRESS") or (
        env.get("XDG_RUNTIME_DIR") and os.path.exists(os.path.join(env["XDG_RUNTIME_DIR"], "bus")))
    if not exe or not bus:
        yield False
        return
    try:
        helper = subprocess.Popen([exe, "--inhibit", "automount", "--app-id", "bb-dev", "--reason", INHIBIT_REASON,
                                   "cat"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    except OSError:
        yield False
        return
    try:
        yield _wait_inhibited(helper, env)
    finally:
        try:
            helper.stdin.close()
            helper.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            helper.kill()
            helper.wait()


def _wait_inhibited(helper: subprocess.Popen, env: dict[str, str]) -> bool:
    """Wait until the session manager reports automount as inhibited."""
    gdbus = shutil.which("gdbus", path=env.get("PATH"))
    end = time.monotonic() + 2
    while time.monotonic() < end:
        if helper.poll() is not None:
            return False  # no GNOME session manager
        if not gdbus:
            time.sleep(0.3)
            return helper.poll() is None
        try:
            r = subprocess.run([gdbus, "call", "--session", "--dest", "org.gnome.SessionManager",
                                "--object-path", "/org/gnome/SessionManager",
                                "--method", "org.gnome.SessionManager.IsInhibited", str(GNOME_AUTOMOUNT_INHIBIT)],
                               capture_output=True, text=True, env=env, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if "true" in r.stdout:
            time.sleep(0.15)  # gnome-shell picks the change up asynchronously
            return True
        time.sleep(0.02)
    return False


def release_loop(dev: str, image: Path, timeout: float | None = None) -> None:
    """Unmount `dev` and delete the loop device, and make sure it is gone.

    A zero exit status from `udisksctl loop-delete` is not proof: when the
    device is busy (an automounter mounted it again, udev is probing it) the
    kernel only sets autoclear and reports success. So poll sysfs until the
    loop device no longer points at `image`, unmounting and deleting again
    when it is (still or again) mounted. Raises Failure, naming the commands
    to run, when it is still there after `timeout` seconds.
    """
    end = time.monotonic() + (RELEASE_TIMEOUT if timeout is None else timeout)
    while _is_ours(dev, image):
        if _mount_point(dev):
            _udisksctl("unmount", "-b", dev, check=False)
        if _is_ours(dev, image):  # not gone with the unmount (no autoclear yet)
            _loop_delete(dev, image)  # on a busy device this only sets autoclear
        settle = min(end, time.monotonic() + 1.0)
        while _is_ours(dev, image) and time.monotonic() < settle:
            if _mount_point(dev):  # mounted again, or the unmount failed (busy): next round
                time.sleep(0.2)
                break
            time.sleep(0.05)  # udev may hold it for a moment; autoclear then frees it
        if time.monotonic() >= end and _is_ours(dev, image):
            a = attachment(dev)
            raise Failure(f"{a.describe()} is still attached to {image} after unmount and loop-delete",
                          release_hint([a]))


def udisks_status() -> tuple[bool, str]:
    """(usable, reason): may we set up and delete a loop device through udisks?"""
    global _UDISKS
    if _UDISKS is not None:
        return _UDISKS
    if not shutil.which("udisksctl", path=tool_env().get("PATH")):
        _UDISKS = (False, "udisksctl is not installed (package udisks2)")
        return _UDISKS
    paths.DEV_OUT.mkdir(parents=True, exist_ok=True)
    probe = paths.DEV_OUT / ".udisks-probe.img"
    try:
        with open(probe, "wb") as f:
            f.truncate(1024 * 1024)
        p = _udisksctl("loop-setup", "-f", str(probe), "--no-partition-scan", check=False, timeout=30)
        m = re.search(r"as (/dev/loop\d+)", p.stdout)
        if p.returncode != 0 or not m:
            reason = (p.stderr or p.stdout).strip().splitlines()
            _UDISKS = (False, "udisksctl loop-setup is not usable here (it needs the system D-Bus and polkit, "
                       "so run outside a sandbox): " + (reason[-1] if reason else "no output"))
        else:
            release_loop(m.group(1), probe)
            _UDISKS = (True, "")
    except (OSError, subprocess.TimeoutExpired) as e:
        _UDISKS = (False, f"udisksctl probe failed: {e}")
    except Failure as e:
        _UDISKS = (False, f"udisksctl probe: {e} ({e.hint})")
    finally:
        try:
            probe.unlink()
        except OSError:
            pass
    return _UDISKS


def check_attachments(image: Path) -> None:
    """Refuse to attach `image` again while a read-write loop device of it
    exists (two writers corrupt the filesystem); warn about read-only ones."""
    atts = attachments(image)
    if not atts:
        return
    desc = ", ".join(a.describe() for a in atts)
    if any(not a.read_only for a in atts):
        raise Failure(f"{image} is already attached on this host: {desc}; a second mount of it can "
                      "corrupt the filesystem", release_hint(atts))
    print(f"bb-dev: warning: {image} is also attached read-only: {desc}; those mounts do not show changes "
          f"made now. To remove them, {release_hint(atts)}", file=sys.stderr, flush=True)


@contextmanager
def udisks_mount(image: Path, offset: int, size: int, *, readonly: bool = False):
    """Loop-mount one partition of an image via udisks; yields the mount point.

    The desktop automounter is held off while we work (automount_inhibited),
    and on the way out the loop device is unmounted, deleted and checked to
    be gone (release_loop), even on error. Refuses an image that is already
    attached read-write elsewhere.
    """
    image = Path(image).resolve()
    ok, reason = udisks_status()
    if not ok:
        raise Failure(reason, "exFAT/NTFS images are written through udisks; use --fs fat32 inside a sandbox")
    check_attachments(image)
    with automount_inhibited():
        args = ["loop-setup", "-f", str(image), "-o", str(offset), "-s", str(size), "--no-partition-scan"]
        if readonly:
            args.append("-r")
        p = _udisksctl(*args)
        m = re.search(r"as (/dev/loop\d+)", p.stdout)
        if not m:
            raise Failure(f"cannot parse udisksctl loop-setup output: {p.stdout!r}")
        dev = m.group(1)
        try:
            bf = _backing_file(dev)
            if bf and os.path.realpath(bf) != str(image):
                raise Failure(f"{dev} is backed by {bf}, expected {image}")
            mp = _mount_point(dev)  # an automounter (outside GNOME) may have been quicker
            if not mp:
                margs = ["mount", "-b", dev] + (["-o", "ro"] if readonly else [])
                r = _udisksctl(*margs, check=False)
                if r.returncode == 0:
                    mm = re.search(r" at (.+?)\.?\s*$", r.stdout.strip())
                    mp = mm.group(1) if mm else _mount_point(dev)
                elif "AlreadyMounted" in (r.stderr or ""):
                    # The automounter got there between our check and our mount.
                    end = time.monotonic() + 5
                    while not mp and time.monotonic() < end:
                        mp = _mount_point(dev)
                        if not mp:
                            time.sleep(0.1)
                else:
                    raise Failure(f"udisksctl mount -b {dev} failed: {(r.stderr or r.stdout).strip()[-400:]}")
            if not mp or not os.path.isdir(mp):
                raise Failure(f"could not find where {dev} is mounted")
            yield Path(mp)
            subprocess.run(["sync", "-f", mp], check=False)
        except BaseException:
            try:
                release_loop(dev, image)
            except Failure as e:  # keep the original error; still say what is left behind
                print(f"bb-dev: error: {e}\n  hint: {e.hint}", file=sys.stderr, flush=True)
            raise
        release_loop(dev, image)


# ---------------------------------------------------------------------------
# Data partition access (any filesystem)
# ---------------------------------------------------------------------------

class FatData:
    """Data-partition writer for FAT32 (mtools)."""

    def __init__(self, fat: Fat):
        self.fat = fat

    def read(self, path: str) -> bytes | None:
        return self.fat.read(path)

    def write(self, path: str, data: bytes) -> None:
        self.fat.put_bytes(path, data)

    def remove(self, path: str) -> bool:
        if self.fat.exists(path):
            self.fat.delete(path)
            return True
        return False

    def mkdirs(self, path: str) -> None:
        self.fat.mkdirs(path)

    def copy_files(self, files: list[tuple[str, Path]]) -> None:
        """[(destination path, local source)], grouped per directory; names
        must match the source basenames."""
        by_dir: dict[str, list[Path]] = {}
        renamed: list[tuple[str, Path]] = []
        for dest, src in files:
            d = PurePosixPath(dest)
            if d.name != Path(src).name:
                renamed.append((dest, src))
            else:
                by_dir.setdefault(str(d.parent), []).append(Path(src))
        for d, srcs in by_dir.items():
            self.fat.put_files(d, srcs)
        for dest, src in renamed:
            self.fat.mkdirs(str(PurePosixPath(dest).parent))
            self.fat._m("mcopy", "-o", str(src), f"::{dest}")


class MountedData:
    """Data-partition writer for a mounted filesystem (exFAT, NTFS)."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def _p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def read(self, path: str) -> bytes | None:
        try:
            return self._p(path).read_bytes()
        except FileNotFoundError:
            return None

    def write(self, path: str, data: bytes) -> None:
        dest = self._p(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    def remove(self, path: str) -> bool:
        try:
            self._p(path).unlink()
            return True
        except FileNotFoundError:
            return False

    def mkdirs(self, path: str) -> None:
        self._p(path).mkdir(parents=True, exist_ok=True)

    def copy_files(self, files: list[tuple[str, Path]]) -> None:
        for dest, src in files:
            d = self._p(dest)
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, d)


@contextmanager
def data_access(info: ImageInfo, *, readonly: bool = False):
    """Yields a FatData or MountedData for the image's data partition."""
    if info.data_fs == "fat32":
        yield FatData(info.data_fat())
    elif info.data_fs in ("exfat", "ntfs"):
        with udisks_mount(info.path, info.data_offset, info.data_size, readonly=readonly) as mp:
            yield MountedData(mp)
    else:
        raise Failure(f"unsupported data filesystem {info.data_fs!r}")


# ---------------------------------------------------------------------------
# Who uses an image
# ---------------------------------------------------------------------------

def state_dir(image: Path) -> Path:
    """out/vm/<image stem>/ without creating it (paths.vm_state_dir creates it)."""
    return paths.VM_OUT / Path(image).stem


def pidfile(image: Path) -> Path:
    return state_dir(image) / "qemu.pid"


def running_vm(image: Path) -> int | None:
    """PID of a `bb-dev vm` QEMU still running on this image, if any."""
    pf = pidfile(image)
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    # Our QEMU has `-pidfile <this file>` on its command line; a reused PID does not.
    return pid if os.fsencode(str(pf.absolute())) in args else None


def walk_tree(root: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    """Everything below `root` that a copy has to recreate: (files, dirs).

    files: (relative posix path, path) of every regular file, sorted,
    following symlinks to files and directories; broken links are skipped.
    dirs: relative posix paths of the empty leaf directories, which copying
    the files would not create (their parents come with them). A directory
    link back into its own ancestors is not followed (it would recurse).
    """
    root = Path(root)
    files: list[tuple[str, Path]] = []
    dirs: list[str] = []
    chain: dict[str, frozenset[str]] = {str(root): frozenset([os.path.realpath(root)])}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        keep = []
        for d in sorted(dirnames):
            sub = os.path.join(dirpath, d)
            r = os.path.realpath(sub)
            if r not in chain[dirpath]:  # else: a link to itself or an ancestor
                chain[sub] = chain[dirpath] | {r}
                keep.append(d)
        dirnames[:] = keep
        found = False
        for f in sorted(filenames):
            fp = Path(dirpath) / f
            if fp.is_file():
                files.append((fp.relative_to(root).as_posix(), fp))
                found = True
        if not dirnames and not found and dirpath != str(root):
            dirs.append(Path(dirpath).relative_to(root).as_posix())
    return files, dirs


def walk_files(root: Path) -> Iterable[tuple[str, Path]]:
    """(relative posix path, path) of every regular file below root (walk_tree)."""
    return iter(walk_tree(root)[0])
