"""bb-dev doctor: every check's OK/WARN/FAIL logic and fix line, against fake
trees (tmp_path) with a fake PATH lookup and fake subprocess results."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import types
from collections import namedtuple
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev.commands import doctor
from bbdev.commands.doctor import FAIL, OK, WARN


def cp(stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class Fake:
    """A fake host: files under tmp, tools by name, canned command output."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.repo = tmp / "repo"
        self.repo.mkdir()
        self.tools: dict[str, str] = {}
        self.outputs: dict[str, subprocess.CompletedProcess] = {}
        self.env = {"PATH": "/nowhere"}

    def dir(self, var: str, *files: str) -> Path:
        d = self.tmp / var.lower()
        d.mkdir(exist_ok=True)
        for f in files:
            (d / f).write_text("x")
        self.env[var] = str(d)
        return d

    def tool(self, *names: str) -> None:
        for n in names:
            self.tools[n] = f"/fake/bin/{n}"

    def ctx(self, **kw) -> doctor.Ctx:
        def run(cmd, timeout=10):
            key = " ".join(map(str, cmd))
            for k, v in self.outputs.items():
                if key.startswith(k) or os.path.basename(str(cmd[0])) == k:
                    return v
            return None
        return doctor.Ctx(dict(self.env), repo=self.repo, which=self.tools.get, run=run, **kw)


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path)


def by_name(results, name):
    return next(r for r in results if r.name == name)


# -- core -------------------------------------------------------------------

def test_python_version(fake):
    assert doctor.check_python(fake.ctx(python=(3, 10, 0))).status == OK
    r = doctor.check_python(fake.ctx(python=(3, 9, 18)))
    assert r.status == FAIL and "3.10" in r.fix and r.action == doctor.SYSTEM


def test_grub_efi(fake):
    r = doctor.check_grub_efi(fake.ctx())
    assert r.status == FAIL and "make tools" in r.fix and "grub-efi-amd64-bin" in r.fix and r.action == doctor.TOOLS
    fake.dir("BB_GRUB_EFI_DIR", "kernel.img", "moddep.lst", "normal.mod", "linux.mod")
    (fake.repo / "build").mkdir()
    (fake.repo / "build" / "modules-efi.lst").write_text("# comment\nnormal\nlinux\n")
    assert doctor.check_grub_efi(fake.ctx()).status == OK
    (fake.repo / "build" / "modules-efi.lst").write_text("normal\nlinux\nluks2  # needed\n")
    r = doctor.check_grub_efi(fake.ctx())
    assert r.status == FAIL and "luks2" in r.detail


def test_grub_bios(fake):
    assert doctor.check_grub_bios(fake.ctx()).status == FAIL
    fake.dir("BB_GRUB_BIOS_DIR", "boot.img", "diskboot.img", "kernel.img", "lzma_decompress.img", "moddep.lst")
    r = doctor.check_grub_bios(fake.ctx())
    assert r.status == FAIL and "normal.mod" in r.detail and "grub-pc-bin" in r.fix
    (Path(fake.env["BB_GRUB_BIOS_DIR"]) / "normal.mod").write_text("x")
    assert doctor.check_grub_bios(fake.ctx()).status == OK


def test_grub_signed_version_must_match_modules(fake):
    assert doctor.check_grub_signed(fake.ctx()).status == FAIL
    d = fake.dir("BB_GRUB_EFI_SIGNED_DIR", "grubx64.efi.signed")
    fake.dir("BB_GRUB_EFI_DIR", "kernel.img")
    fake.outputs["dpkg-query"] = cp("2.14-2ubuntu1")
    (d / "version").write_text("2.14-2ubuntu1\n")
    assert doctor.check_grub_signed(fake.ctx()).status == OK
    (d / "version").write_text("2.14-2ubuntu3\n")
    r = doctor.check_grub_signed(fake.ctx())
    assert r.status == FAIL and "SBAT" in r.detail and "grub-efi-amd64-signed" in r.fix


def test_module_pkg_version_from_tools_debs(fake):
    d = fake.repo / ".tools" / "root" / "usr" / "lib" / "grub" / "i386-pc"
    d.mkdir(parents=True)
    debs = fake.repo / ".tools" / "debs"
    debs.mkdir()
    (debs / "grub-pc-bin_2.14-2ubuntu2.1_amd64.deb").write_text("")
    (debs / "qemu-system-x86_1%3a10.2.1+ds-1ubuntu3.3_amd64.deb").write_text("")
    assert doctor.module_pkg_version(fake.ctx(), d, "grub-pc-bin") == "2.14-2ubuntu2.1"
    assert doctor.module_pkg_version(fake.ctx(), d, "qemu-system-x86") == "1:10.2.1+ds-1ubuntu3.3"
    fake.outputs["dpkg-query"] = cp("", rc=1)
    assert doctor.module_pkg_version(fake.ctx(), Path("/usr/lib/grub/i386-pc"), "grub-pc-bin") == ""


def test_shim_ovmf_seabios(fake):
    assert doctor.check_shim(fake.ctx()).status == FAIL
    fake.dir("BB_SHIM_DIR", "shimx64.efi.signed.latest", "mmx64.efi")
    assert doctor.check_shim(fake.ctx()).status == OK
    r = doctor.check_ovmf(fake.ctx())
    assert r.status == FAIL and "ovmf" in r.fix
    fake.dir("BB_OVMF_DIR", "OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd")
    r = doctor.check_ovmf(fake.ctx())
    assert r.status == WARN and "Secure Boot" in r.detail
    fake.dir("BB_OVMF_DIR", "OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.ms.fd")
    assert doctor.check_ovmf(fake.ctx()).status == OK
    assert doctor.check_seabios(fake.ctx()).status == FAIL
    fake.dir("BB_SEABIOS_DIR", "bios-256k.bin")
    assert doctor.check_seabios(fake.ctx()).status == OK


def test_qemu_and_gtk(fake):
    rs = doctor.check_qemu(fake.ctx())
    assert by_name(rs, "qemu").status == FAIL and "qemu-system-x86" in by_name(rs, "qemu").fix
    fake.tool("qemu-system-x86_64")
    fake.outputs["/fake/bin/qemu-system-x86_64 --version"] = cp("QEMU emulator version 10.2.1 (Debian)\n")
    fake.outputs["/fake/bin/qemu-system-x86_64 -display"] = cp("Available display backend types:\nnone\nsdl\n")
    rs = doctor.check_qemu(fake.ctx())
    assert by_name(rs, "qemu").status == OK and "10.2.1" in by_name(rs, "qemu").detail
    gtk = by_name(rs, "qemu-gtk")
    assert gtk.status == WARN and "qemu-system-gui" in gtk.fix and "make tools" in gtk.fix
    fake.outputs["/fake/bin/qemu-system-x86_64 -display"] = cp("none\ngtk\n")
    assert by_name(doctor.check_qemu(fake.ctx()), "qemu-gtk").status == OK


def test_qemu_broken(fake):
    fake.tool("qemu-system-x86_64")
    fake.outputs["qemu-system-x86_64"] = cp("", rc=1, stderr="error while loading shared libraries: libfoo\n")
    r = by_name(doctor.check_qemu(fake.ctx()), "qemu")
    assert r.status == FAIL and "libfoo" in r.detail


def test_kvm(fake, tmp_path):
    r = doctor.check_kvm(fake.ctx(), dev=str(tmp_path / "nokvm"))
    assert r.status == WARN and "VT-x" in r.fix
    dev = tmp_path / "kvm"
    dev.write_text("")
    dev.chmod(0)
    if os.access(dev, os.R_OK | os.W_OK):
        pytest.skip("running as root")
    r = doctor.check_kvm(fake.ctx(), dev=str(dev))
    assert r.status == WARN and "kvm" in r.fix and "usermod" in r.fix
    dev.chmod(0o600)
    assert doctor.check_kvm(fake.ctx(), dev=str(dev)).status == OK


@pytest.mark.parametrize("check,names,status,apt", [
    (doctor.check_mtools, ("mcopy", "mformat", "mmd", "mdir"), FAIL, "mtools"),
    (doctor.check_xorriso, ("xorriso",), FAIL, "xorriso"),
    (doctor.check_mkfs_fat, ("mkfs.fat",), FAIL, "dosfstools"),
    (doctor.check_mkfs_exfat, ("mkfs.exfat",), FAIL, "exfatprogs"),
    (doctor.check_sbsign, ("sbsign", "sbverify"), FAIL, "sbsigntool"),
    (doctor.check_socat, ("socat",), WARN, "socat"),
])
def test_tools(fake, check, names, status, apt):
    r = check(fake.ctx())
    assert r.status == status and "make tools" in r.fix and apt in r.fix
    fake.tool(*names[:-1])
    r = check(fake.ctx())
    assert r.status == status and names[-1] in r.detail
    fake.tool(*names)
    assert check(fake.ctx()).status == OK


def test_system_tools(fake):
    r = doctor.check_sfdisk(fake.ctx())
    assert r.status == FAIL and r.action == doctor.SYSTEM and "apt install fdisk" in r.fix
    r = doctor.check_openssl(fake.ctx())
    assert r.status == FAIL and "openssl" in r.fix
    r = doctor.check_mkfs_ntfs(fake.ctx())
    assert r.status == WARN and "ntfs-3g" in r.fix
    fake.tool("mkntfs")
    assert doctor.check_mkfs_ntfs(fake.ctx()).status == OK


def test_virt_fw_vars(fake):
    assert doctor.check_virt_fw_vars(fake.ctx()).status == WARN
    fake.tool("virt-fw-vars")
    fake.outputs["/fake/bin/virt-fw-vars"] = cp("", rc=1, stderr="ModuleNotFoundError: No module named 'pefile'")
    r = doctor.check_virt_fw_vars(fake.ctx())
    assert r.status == WARN and "pefile" in r.detail
    fake.outputs["/fake/bin/virt-fw-vars"] = cp("usage: virt-fw-vars")
    assert doctor.check_virt_fw_vars(fake.ctx()).status == OK


def test_udisks(fake, monkeypatch):
    r = doctor.check_udisks(fake.ctx())
    assert r.status == WARN and "udisks2" in r.fix
    fake.tool("udisksctl")
    from bbdev import diskimg
    monkeypatch.setattr(diskimg, "udisks_status", lambda: (False, "Not authorized"))
    r = doctor.check_udisks(fake.ctx())
    assert r.status == WARN and "Not authorized" in r.detail and "FAT32" in r.detail
    monkeypatch.setattr(diskimg, "udisks_status", lambda: (True, ""))
    assert doctor.check_udisks(fake.ctx()).status == OK


def test_gdb(fake):
    r = doctor.check_gdb(fake.ctx())
    assert r.status == WARN and "apt install gdb" in r.fix
    fake.tool("gdb")
    fake.outputs["/fake/bin/gdb"] = cp("Python scripting is not supported in this copy of GDB.\n")
    assert "Python" in doctor.check_gdb(fake.ctx()).detail
    fake.outputs["/fake/bin/gdb"] = cp("bbpy\nGNU gdb (Ubuntu 17.1-2ubuntu1) 17.1\n")
    r = doctor.check_gdb(fake.ctx())
    assert r.status == OK and "gdb 17.1" in r.detail


def test_grub_dbg(fake, monkeypatch):
    fake.dir("BB_GRUB_BIOS_DIR", "kernel.img")
    fake.dir("BB_GRUB_EFI_DIR", "kernel.img")
    pc = fake.dir("BB_GRUB_PC_DBG_DIR")
    efi = fake.dir("BB_GRUB_EFI_DBG_DIR", "kernel.exec")
    fake.outputs["dpkg-query"] = cp("2.14-2ubuntu1")
    verdict = {"problems": [], "missing": []}
    monkeypatch.setattr(doctor, "_grubsyms", lambda ctx: types.SimpleNamespace(
        verify=lambda a, b: (verdict["problems"], verdict["missing"])))
    rs = doctor.check_grub_dbg(fake.ctx())
    assert by_name(rs, "grub-dbg-pc").status == WARN and "grub-pc-dbg 2.14-2ubuntu1" in by_name(rs, "grub-dbg-pc").fix
    assert by_name(rs, "grub-dbg-efi").status == OK
    verdict["problems"] = ["kernel.exec .text differs"]
    r = by_name(doctor.check_grub_dbg(fake.ctx()), "grub-dbg-efi")
    assert r.status == WARN and "does not match" in r.detail and "make tools" in r.fix
    assert pc and efi


def test_venv(fake):
    r = doctor.check_venv(fake.ctx())
    assert r.status == WARN and "bb-dev setup" in r.fix and r.action == doctor.VENV
    v = fake.repo / ".venv"
    (v / "bin").mkdir(parents=True)
    (v / "bin" / "python").write_text("")
    sp = v / "lib" / "python3.14" / "site-packages"
    sp.mkdir(parents=True)
    for n in ("pytest-9.1.1", "coverage-7.16.2", "debugpy-1.8.22"):
        (sp / f"{n}.dist-info").mkdir()
    r = doctor.check_venv(fake.ctx())
    assert r.status == WARN and "ruff" in r.detail
    (sp / "ruff-0.16.10.dist-info").mkdir()
    (fake.repo / "requirements-dev.txt").write_text(
        "pytest==9.1.1 \\\n    --hash=sha256:aa\nruff==0.16.11 ; python_version >= \"3.10\" \\\n    --hash=sha256:bb\n")
    r = doctor.check_venv(fake.ctx())
    assert r.status == WARN and "ruff 0.16.10 (want 0.16.11)" in r.detail
    (fake.repo / "requirements-dev.txt").write_text("ruff==0.16.10 \\\n    --hash=sha256:bb\n")
    assert doctor.check_venv(fake.ctx()).status == OK


def _keys(fake, mode=0o600):
    k = fake.repo / "keys"
    k.mkdir(exist_ok=True)
    for n in ("beast-booter.key", "beast-booter.crt", "beast-booter.cer"):
        (k / n).write_text("x")
    (k / "beast-booter.key").chmod(mode)


def test_keys(fake):
    r = doctor.check_keys(fake.ctx())
    assert r.status == FAIL and "make keys" in r.fix and r.action == doctor.KEYS
    _keys(fake, 0o644)
    r = doctor.check_keys(fake.ctx())
    assert r.status == WARN and "chmod 600" in r.fix
    _keys(fake)
    fake.tool("openssl")
    now = dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc)
    fake.outputs["openssl x509"] = cp("notAfter=Oct 20 21:05:14 2036 GMT\n")
    r = doctor.check_keys(fake.ctx(), now=now)
    assert r.status == OK and "2036-10-20" in r.detail
    fake.outputs["openssl x509"] = cp("notAfter=Dec  1 00:00:00 2026 GMT\n")
    r = doctor.check_keys(fake.ctx(), now=now)
    assert r.status == WARN and "expires" in r.detail and "keygen.sh --force" in r.fix
    fake.outputs["openssl x509"] = cp("notAfter=Jan  1 00:00:00 2020 GMT\n")
    r = doctor.check_keys(fake.ctx(), now=now)
    assert r.status == WARN and "expired" in r.detail


def test_dist(fake):
    r = doctor.check_dist(fake.ctx())
    assert r.status == FAIL and "make build" in r.fix and r.action == doctor.BUILD
    for d in ("grub", "build", "dist"):
        (fake.repo / d).mkdir()
    (fake.repo / "grub" / "grub.cfg").write_text("x")
    old = (fake.repo / "grub" / "grub.cfg").stat().st_mtime - 100
    os.utime(fake.repo / "grub" / "grub.cfg", (old, old))
    (fake.repo / "dist" / "manifest.json").write_text("{}")
    assert doctor.check_dist(fake.ctx()).status == OK
    newer = (fake.repo / "dist" / "manifest.json").stat().st_ctime + 100
    (fake.repo / "build" / "build.sh").write_text("x")
    os.utime(fake.repo / "build" / "build.sh", (newer, newer))
    r = doctor.check_dist(fake.ctx())
    assert r.status == WARN and "build/build.sh" in r.detail and "make build" in r.fix


def test_disk(fake):
    U = namedtuple("U", "total used free")
    g = 1 << 30
    assert doctor.check_disk(fake.ctx(), usage=lambda p: U(0, 0, g // 2)).status == FAIL
    assert doctor.check_disk(fake.ctx(), usage=lambda p: U(0, 0, 3 * g)).status == WARN
    assert doctor.check_disk(fake.ctx(), usage=lambda p: U(0, 0, 50 * g)).status == OK


# -- collect / output -------------------------------------------------------

def test_collect_order_crash_and_json(fake):
    def good(ctx):
        return doctor.Check("good", OK, "fine")

    def boom(ctx):
        raise RuntimeError("kaputt")

    def two(ctx):
        return [doctor.Check("a", WARN, "w", "fix a"), doctor.Check("b", FAIL, "f", "fix b")]

    rs = doctor.collect(fake.ctx(), checks=(good, boom, two))
    assert [r.name for r in rs] == ["good", "boom", "a", "b"]
    assert rs[1].status == WARN and "kaputt" in rs[1].detail
    data = json.loads(doctor.to_json(rs))
    assert data["ok"] is False and data["summary"] == {"OK": 1, "WARN": 2, "FAIL": 1}
    assert data["checks"][3] == {"name": "b", "status": FAIL, "detail": "f", "fix": "fix b", "action": "",
                                 "group": ""}


def test_every_problem_has_a_fix(fake):
    """On an empty host every non-OK check says how to fix it."""
    rs = doctor.collect(fake.ctx())
    bad = [r for r in rs if r.status != OK]
    assert bad, "an empty host should have problems"
    assert all(r.fix for r in bad), [r.name for r in bad if not r.fix]
    names = {r.name for r in rs}
    for required in ("python", "grub-efi", "grub-bios", "grub-signed", "shim", "ovmf", "seabios", "qemu",
                     "qemu-gtk", "kvm", "mtools", "xorriso", "sfdisk", "mkfs.fat", "mkfs.exfat", "mkfs.ntfs",
                     "sbsigntool", "openssl", "virt-fw-vars", "udisks", "gdb", "grub-dbg-pc", "grub-dbg-efi",
                     "venv", "keys", "dist", "disk"):
        assert required in names


def test_render(capsys):
    rs = [doctor.Check("x", OK, "fine"), doctor.Check("yy", FAIL, "broken", "do this")]
    doctor.render(rs)
    out = capsys.readouterr().out
    assert "OK    x   fine" in out and "FAIL  yy  broken" in out and "fix: do this" in out
    assert out.strip().endswith("1 OK, 0 WARN, 1 FAIL")


def test_run_exit_status(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "collect", lambda: [doctor.Check("a", WARN, "w", "f")])
    assert doctor.run(argparse.Namespace(json=False)) == 0
    capsys.readouterr()
    monkeypatch.setattr(doctor, "collect", lambda: [doctor.Check("a", FAIL, "w", "f")])
    assert doctor.run(argparse.Namespace(json=True)) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False and data["checks"][0]["status"] == FAIL
