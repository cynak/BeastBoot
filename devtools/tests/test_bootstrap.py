"""scripts/bootstrap-tools.sh + scripts/dev-env.sh: which GRUB module directory
the debug symbols are matched against.

The real scripts run in a throwaway repo root. Only the Debian tools are
stubs: dpkg-deb works on tar files, dpkg-query answers from a list, and
grubsyms.py "verifies" without looking. Nothing is downloaded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SYSTEM_BIOS_DIR = Path("/usr/lib/grub/i386-pc")
VER = "2.14-1"

STUBS = {
    # dpkg-deb -c / -x / -f on tar files named PKG_VERSION_ARCH.deb
    "dpkg-deb": r"""#!/bin/sh
case "$1" in
  -c) exec tar -tvf "$2" ;;
  -x) exec tar -xf "$2" -C "$3" ;;
  -f) b="$(basename "$2" .deb)"; v="${b#*_}"
      case "$3" in Package) echo "${b%%_*}" ;; Version) echo "${v%%_*}" ;; esac ;;
esac
""",
    # everything is installed on the "host" except what BB_TEST_NOT_INSTALLED lists
    "dpkg-query": r"""#!/bin/sh
for a; do pkg="$a"; done
case " $BB_TEST_NOT_INSTALLED " in *" $pkg "*) exit 1 ;; esac
case "$*" in *Version*) echo "@VER@" ;; *) echo "install ok installed" ;; esac
""".replace("@VER@", VER),
    "apt-get": "#!/bin/sh\necho \"apt-get stub: $*\" >&2\nexit 1\n",
    "apt-cache": "#!/bin/sh\nexit 1\n",
    "dpkg": "#!/bin/sh\nexit 0\n",
}


def make_deb(path: Path, files: dict[str, bytes]) -> None:
    src = path.parent / (path.name + ".src")
    for rel, data in files.items():
        f = src / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
    with tarfile.open(path, "w") as t:
        t.add(src, arcname=".")
    shutil.rmtree(src)


class FakeRepo:
    def __init__(self, tmp: Path):
        self.root = tmp / "repo"
        (self.root / "scripts").mkdir(parents=True)
        for s in ("bootstrap-tools.sh", "dev-env.sh"):
            shutil.copy2(ROOT / "scripts" / s, self.root / "scripts" / s)
        gdbdir = self.root / "devtools" / "gdb"
        gdbdir.mkdir(parents=True)
        (gdbdir / "grubsyms.py").write_text("import sys\nsys.exit(0)\n")
        (self.root / ".tools").mkdir()   # empty, as in a fresh clone
        self.stubs = tmp / "stubs"
        self.stubs.mkdir()
        for name, text in STUBS.items():
            p = self.stubs / name
            p.write_text(text)
            p.chmod(0o755)
        # EFI: modules with their debug symbols next to them, so that half is quiet
        self.efi = tmp / "efi"
        self.efi.mkdir()
        for f in ("kernel.img", "kernel.exec"):
            (self.efi / f).write_bytes(b"x")

    def base_env(self, **extra) -> dict:
        env = {"HOME": os.environ.get("HOME", "/tmp"), "LANG": "C",
               "PATH": f"{self.stubs}:/usr/bin:/bin",
               "BB_GRUB_EFI_DIR": str(self.efi),
               "BB_TEST_NOT_INSTALLED": "grub-pc-bin"}
        env.update(extra)
        return env

    def env_before_bootstrap(self, **extra) -> dict:
        """What bb-dev setup's env_now() held before the fix: dev-env.sh sourced
        while .tools/ is still empty."""
        out = subprocess.run(["bash", "-c", 'source scripts/dev-env.sh >/dev/null && env -0'],
                             cwd=self.root, env=self.base_env(**extra), check=True,
                             capture_output=True).stdout
        return dict(item.split("=", 1) for item in out.decode().split("\0") if "=" in item)

    def download_debs(self) -> None:
        """What apt-get download would have put into .tools/ (grub-pc-bin + its -dbg)."""
        debs = self.root / ".tools" / "debs"
        debs.mkdir(parents=True)
        mods = "usr/lib/grub/i386-pc/"
        make_deb(debs / f"grub-pc-bin_{VER}_amd64.deb",
                 {mods + "boot.img": b"b" * 512, mods + "kernel.img": b"k" * 100, mods + "normal.mod": b"n"})
        dbg = self.root / ".tools" / "debs-dbg"
        dbg.mkdir()
        make_deb(dbg / f"grub-pc-dbg_{VER}_amd64.deb",
                 {mods + "kernel.exec": b"e" * 100, mods + "normal.module": b"m"})

    def bootstrap(self, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.root / "scripts" / "bootstrap-tools.sh")], cwd=self.root,
                              env=env, capture_output=True, text=True, timeout=120, check=False)


@pytest.fixture
def repo(tmp_path):
    if not shutil.which("tar"):
        pytest.skip("needs tar")
    return FakeRepo(tmp_path)


def test_stale_system_dir_from_before_bootstrap_is_picked_again(repo):
    """Fresh clone: the env was resolved while .tools/ was empty, so it says
    BB_GRUB_BIOS_DIR=/usr/lib/grub/i386-pc (the first candidate, as a fallback).
    bootstrap must still match grub-pc-dbg against the grub-pc-bin it unpacked."""
    if (SYSTEM_BIOS_DIR / "boot.img").exists():
        pytest.skip("grub-pc-bin is installed on this host, so the system dir is not a stale fallback")
    env = repo.env_before_bootstrap()
    assert env["BB_GRUB_BIOS_DIR"] == str(SYSTEM_BIOS_DIR)   # the pre-resolved fallback
    repo.download_debs()
    p = repo.bootstrap(env)
    assert p.returncode == 0, p.stdout + p.stderr
    tools_mods = repo.root / ".tools" / "root" / "usr" / "lib" / "grub" / "i386-pc"
    assert (tools_mods / "kernel.img").is_file()
    assert "modules not found" not in p.stderr, p.stderr
    assert f"grub-pc-dbg {VER}: kernel.exec and all 1 .module files match {tools_mods}" in p.stdout, p.stdout
    assert (repo.root / ".tools" / "grub-dbg" / "usr" / "lib" / "grub" / "i386-pc" / "kernel.exec").is_file()
    # and dev-env.sh now points everything at .tools (sourced again with the same stale env)
    after = subprocess.run(["bash", "-c", 'source scripts/dev-env.sh && echo "$BB_GRUB_BIOS_DIR"'],
                           cwd=repo.root, env=env, capture_output=True, text=True, check=True).stdout.strip()
    assert after == str(tools_mods)


def test_a_directory_the_user_chose_wins_and_a_wrong_one_is_an_error(repo, tmp_path):
    """BB_GRUB_BIOS_DIR set by the user is never replaced; when it holds no
    modules although grub-pc-bin was unpacked, bootstrap exits 3 (debug
    symbols only) instead of skipping with a warning."""
    wrong = tmp_path / "my-grub"
    wrong.mkdir()
    repo.download_debs()
    p = repo.bootstrap(repo.base_env(BB_GRUB_BIOS_DIR=str(wrong)))
    assert p.returncode == 3, p.stdout + p.stderr
    assert f"BB_GRUB_BIOS_DIR={wrong} has no GRUB modules (kernel.img), although grub-pc-bin is " \
           "unpacked into .tools/root" in p.stderr, p.stderr
    assert not (repo.root / ".tools" / "grub-dbg" / "usr" / "lib" / "grub" / "i386-pc").exists()
    # the toolchain itself is complete
    assert (repo.root / ".tools" / "root" / "usr" / "lib" / "grub" / "i386-pc" / "kernel.img").is_file()


def test_dev_env_keeps_user_dirs_and_repicks_its_own_fallbacks(repo, tmp_path):
    tools_mods = repo.root / ".tools" / "root" / "usr" / "lib" / "grub" / "i386-pc"
    tools_mods.mkdir(parents=True)
    (tools_mods / "boot.img").write_bytes(b"b")

    def bios_dir(value: str | None) -> str:
        env = repo.base_env()
        if value is not None:
            env["BB_GRUB_BIOS_DIR"] = value
        for shell in ("bash", "zsh"):
            if shell == "zsh" and not shutil.which("zsh"):
                continue
            got = subprocess.run([shell, "-c", 'source scripts/dev-env.sh && echo "$BB_GRUB_BIOS_DIR"'],
                                 cwd=repo.root, env=env, capture_output=True, text=True, check=True).stdout.strip()
            if shell == "bash":
                first = got
            assert got == first, (shell, got, first)
        return first

    system_has_it = (SYSTEM_BIOS_DIR / "boot.img").exists()
    picked = str(SYSTEM_BIOS_DIR) if system_has_it else str(tools_mods)
    assert bios_dir(None) == picked
    assert bios_dir("") == picked
    assert bios_dir(str(SYSTEM_BIOS_DIR)) == picked                 # a fallback is picked again (or valid)
    assert bios_dir(str(tools_mods)) == str(tools_mods)             # a valid own candidate stays
    assert bios_dir(str(tmp_path / "custom")) == str(tmp_path / "custom")   # the user's choice, even if empty
