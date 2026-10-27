"""grub/beast/hooks/initramfs-tools.sh, run the way Ubuntu's /init runs it
(sourced by a POSIX sh), against a fake initramfs root (BB_HOOK_ROOT).

The real thing is covered by booting Ubuntu 26.04.1 from an exFAT drive in
QEMU (docs/ISO_SUPPORT.md); these tests pin the behaviour around it: which
insmod is used, what is logged, and that casper's filesystem list is only
widened when a module really loaded."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "grub" / "beast" / "hooks" / "initramfs-tools.sh"
# dash, not a host busybox: busybox sh may run its own insmod applet before
# looking at PATH, which would bypass the fakes below.
SH = [shutil.which("dash") or "/bin/sh"]

# Ubuntu's is_supported_fs (casper 1.5xx, scripts/casper-helpers), the part the hook replaces.
CASPER_HELPERS = """\
is_supported_fs(){
    [ -z "${1}" ] && return 1
    case ${1} in
        ext2|ext3|ext4|xfs|jfs|reiserfs|vfat|ntfs|iso9660|btrfs|udf)
            return 0
            ;;
    esac
    return 1
}
find_path() { :; }
"""
ORIGINAL_FS = "ext2 ext3 ext4 xfs jfs reiserfs vfat ntfs iso9660 btrfs udf".split()

KLIBC_INSMOD_FAILS = '#!/bin/sh\necho "insmod: error inserting \'$1\': -1 Invalid module format" >&2\nexit 1\n'
REFUSED = '#!/bin/sh\necho "insmod: ERROR: could not insert module $1: Key was rejected by service" >&2\nexit 1\n'


def loads(root: Path, *, only_as: str | None = None) -> str:
    """A fake insmod/kmod that 'loads' exfat by adding it to proc/filesystems."""
    guard = f'[ "${{0##*/}}" = {only_as} ] || {{ echo "kmod: unknown command" >&2; exit 1; }}\n' if only_as else ""
    return f'#!/bin/sh\n{guard}printf "\\texfat\\n" >> "{root}/proc/filesystems"\n'


def write_exe(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


@pytest.fixture
def initramfs(tmp_path):
    root = tmp_path / "root"
    for d in ("scripts", "proc", "dev", "beast-boot/modules"):
        (root / d).mkdir(parents=True)
    (root / "scripts" / "casper-helpers").write_text(CASPER_HELPERS)
    (root / "proc" / "filesystems").write_text("nodev\tsysfs\n\text4\n\tvfat\n")
    (root / "dev" / "kmsg").write_text("")
    (root / "beast-boot" / "modules" / "exfat.ko.zst").write_bytes(b"\x28\xb5\x2f\xfd fake module")
    return root


def source_hook(root: Path, path_insmod: str | None, tmp_path: Path) -> subprocess.CompletedProcess:
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir(exist_ok=True)
    if path_insmod is not None:
        write_exe(fakebin / "insmod", path_insmod)
    script = f'. "{HOOK}"; echo "after rc=$?"; set | grep -c "^bb_hook" || true'
    env = dict(os.environ, BB_HOOK_ROOT=str(root), PATH=f"{fakebin}:{os.environ['PATH']}")
    return subprocess.run([*SH, "-c", script], env=env, capture_output=True, text=True, timeout=30)


def accepts(root: Path, fstype: str) -> bool:
    helpers = root / "scripts" / "casper-helpers"
    r = subprocess.run([*SH, "-c", f'. "{helpers}"; is_supported_fs "{fstype}"'], capture_output=True, timeout=30)
    return r.returncode == 0


def kmsg(root: Path) -> list[str]:
    return (root / "dev" / "kmsg").read_text().splitlines()


def check_sourced_cleanly(r: subprocess.CompletedProcess) -> None:
    out = r.stdout.splitlines()
    assert out[:1] == ["after rc=0"], (r.stdout, r.stderr)  # sourced: the parent shell went on
    assert out[1:] == ["0"], r.stdout  # no bb_hook_* variables left behind


def test_ubuntu_kmod_loads_when_klibc_insmod_cannot(initramfs, tmp_path):
    write_exe(initramfs / "usr" / "bin" / "kmod", loads(initramfs, only_as="insmod"))
    r = source_hook(initramfs, KLIBC_INSMOD_FAILS, tmp_path)
    check_sourced_cleanly(r)
    assert kmsg(initramfs) == [
        "beast-boot: exfat support loaded (exfat.ko.zst from the ISO)",
        "beast-boot: casper may now search exfat partitions for the ISO",
    ]
    assert accepts(initramfs, "exfat")
    assert all(accepts(initramfs, fs) for fs in ORIGINAL_FS)
    assert not accepts(initramfs, "ntfs3") and not accepts(initramfs, "")


def test_without_kmod_uses_insmod_from_path(initramfs, tmp_path):
    r = source_hook(initramfs, loads(initramfs), tmp_path)
    check_sourced_cleanly(r)
    assert accepts(initramfs, "exfat")


def test_refused_module_changes_nothing(initramfs, tmp_path):
    before = (initramfs / "scripts" / "casper-helpers").read_text()
    r = source_hook(initramfs, REFUSED, tmp_path)
    check_sourced_cleanly(r)
    assert (initramfs / "scripts" / "casper-helpers").read_text() == before
    [line] = kmsg(initramfs)
    assert line.startswith("beast-boot: could not load exfat.ko.zst: ") and "Key was rejected" in line
    assert not accepts(initramfs, "exfat")


def test_built_in_exfat_still_widens_casper(initramfs, tmp_path):
    with open(initramfs / "proc" / "filesystems", "a") as f:
        f.write("\texfat\n")
    r = source_hook(initramfs, REFUSED, tmp_path)  # insmod fails: already there
    check_sourced_cleanly(r)
    assert accepts(initramfs, "exfat")


def test_no_modules_is_a_no_op(tmp_path):
    root = tmp_path / "root"
    (root / "dev").mkdir(parents=True)
    (root / "dev" / "kmsg").write_text("")
    r = source_hook(root, None, tmp_path)
    check_sourced_cleanly(r)
    assert kmsg(root) == [] and not (root / "scripts").exists()


def test_not_casper_loads_but_does_not_create_helpers(initramfs, tmp_path):
    (initramfs / "scripts" / "casper-helpers").unlink()
    r = source_hook(initramfs, loads(initramfs), tmp_path)
    check_sourced_cleanly(r)
    assert kmsg(initramfs) == ["beast-boot: exfat support loaded (exfat.ko.zst from the ISO)"]
    assert not (initramfs / "scripts" / "casper-helpers").exists()


# --- NTFS for live-boot (Debian): the ISO's ntfs3 module plus helpers ----------------

LOADS_NTFS3 = '#!/bin/sh\nprintf "\\tntfs3\\n" >> "{root}/proc/filesystems"\n'


def ntfs_root(tmp_path: Path, live_boot: bool) -> Path:
    root = tmp_path / "root"
    for d in ("proc", "dev", "beast-boot/modules"):
        (root / d).mkdir(parents=True)
    if live_boot:
        (root / "lib" / "live" / "boot").mkdir(parents=True)
    (root / "proc" / "filesystems").write_text("nodev\tsysfs\n\text4\n")
    (root / "dev" / "kmsg").write_text("")
    (root / "beast-boot" / "modules" / "ntfs3.ko.zst").write_bytes(b"\x28\xb5\x2f\xfd fake module")
    return root


def source_hook_clean_path(root: Path, tmp_path: Path, *, host_ntfs3g: bool = False) -> subprocess.CompletedProcess:
    """Like source_hook, but PATH holds only fakes and the few tools the hook needs, so a
    host ntfs-3g cannot hide the stand-in (and can be added on purpose)."""
    fakebin = tmp_path / "cleanbin"
    fakebin.mkdir(exist_ok=True)
    write_exe(fakebin / "insmod", LOADS_NTFS3.format(root=root))
    for tool in ("mkdir", "chmod", "grep", "ln", "cat"):
        found = shutil.which(tool)
        if found and not (fakebin / tool).exists():
            (fakebin / tool).symlink_to(found)
    if host_ntfs3g:
        write_exe(fakebin / "ntfs-3g", "#!/bin/sh\nexit 0\n")
    script = f'. "{HOOK}"; echo "after rc=$?"; set | grep -c "^bb_hook" || true'
    env = dict(os.environ, BB_HOOK_ROOT=str(root), PATH=str(fakebin))
    return subprocess.run([*SH, "-c", script], env=env, capture_output=True, text=True, timeout=30)


def test_ntfs3_gives_live_boot_its_helpers(tmp_path):
    root = ntfs_root(tmp_path, live_boot=True)
    r = source_hook_clean_path(root, tmp_path)
    check_sourced_cleanly(r)
    stand_in, helper = root / "bin" / "ntfs-3g", root / "sbin" / "mount.ntfs"
    assert stand_in.stat().st_mode & 0o111 and helper.stat().st_mode & 0o111
    assert subprocess.run([str(stand_in)], timeout=10).returncode == 1  # only for live-boot's `type ntfs-3g`
    assert 'exec mount -i -t ntfs3 "$@"' in helper.read_text()
    assert "beast-boot: live-boot may now search NTFS partitions for the ISO (ntfs3)" in kmsg(root)


def test_ntfs3_without_live_boot_adds_no_helpers(tmp_path):
    root = ntfs_root(tmp_path, live_boot=False)
    r = source_hook_clean_path(root, tmp_path)
    check_sourced_cleanly(r)
    assert not (root / "bin" / "ntfs-3g").exists() and not (root / "sbin" / "mount.ntfs").exists()


def test_real_ntfs3g_is_never_shadowed(tmp_path):
    root = ntfs_root(tmp_path, live_boot=True)
    r = source_hook_clean_path(root, tmp_path, host_ntfs3g=True)
    check_sourced_cleanly(r)
    assert not (root / "bin" / "ntfs-3g").exists() and not (root / "sbin" / "mount.ntfs").exists()
