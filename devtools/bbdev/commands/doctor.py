"""bb-dev doctor: check the development environment and say how to fix it.

Every check prints OK, WARN or FAIL with what it found and, when not OK, one
line saying how to fix it. Exit status 0 when nothing FAILs.

  bb-dev doctor            human-readable report
  bb-dev doctor --json     machine-readable (used by bb-dev setup and CI)

Checks run in parallel and take well under 5 s. They only read: the one
exception is the udisks probe, which sets up and deletes a 1 MiB loop device
backed by a file in out/dev/ (the same probe `bb-dev image` uses).
"""

from __future__ import annotations

import concurrent.futures
import datetime as _dt
import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import paths

CMD = "doctor"
OK, WARN, FAIL = "OK", "WARN", "FAIL"

# What fixes a problem; bb-dev setup acts on "tools", "venv", "keys", "build".
TOOLS, VENV, KEYS, BUILD, SYSTEM = "tools", "venv", "keys", "build", "system"

MIN_PYTHON = (3, 10)
DISK_FAIL_GIB = 1
DISK_WARN_GIB = 5
CERT_WARN_DAYS = 90
VENV_PACKAGES = ("pytest", "coverage", "debugpy", "ruff")
SYSTEM_PATH_EXTRA = ("/usr/sbin", "/sbin")


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""
    action: str = ""      # tools | venv | keys | build | system | "" (see above)
    group: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Ctx:
    """Everything a check looks at, so tests can point it at fake trees."""
    env: dict
    repo: Path = paths.REPO
    which: Callable[[str], str | None] | None = None
    run: Callable[..., subprocess.CompletedProcess | None] | None = None
    python: tuple = field(default_factory=lambda: tuple(sys.version_info[:3]))
    python_exe: str = sys.executable

    def __post_init__(self):
        if self.which is None:
            search = os.pathsep.join([self.env.get("PATH", os.defpath), *SYSTEM_PATH_EXTRA])
            self.which = lambda name: shutil.which(name, path=search)
        if self.run is None:
            self.run = self._run

    def _run(self, cmd: list, timeout: float = 10) -> subprocess.CompletedProcess | None:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=self.env,
                                  stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None

    def dir(self, var: str) -> Path:
        return Path(self.env.get(var, ""))


def short(p, ctx: Ctx) -> str:
    """A path relative to the repo when it is inside it."""
    try:
        return str(Path(p).relative_to(ctx.repo))
    except ValueError:
        return str(p)


def tools_fix(apt: str) -> str:
    return f"run `make tools` (fetches it into .tools without root; or: sudo apt install {apt})"


def ok(name, detail, group=""):
    return Check(name, OK, detail, group=group)


# ---------------------------------------------------------------------------
# Package versions (system dpkg, or the .deb that bootstrap-tools.sh unpacked)
# ---------------------------------------------------------------------------

def module_pkg_version(ctx: Ctx, directory: Path, pkg: str) -> str:
    tools_root = ctx.repo / ".tools" / "root"
    try:
        Path(directory).resolve().relative_to(tools_root.resolve())
        in_tools = True
    except (ValueError, OSError):
        in_tools = False
    if in_tools:
        debs = sorted((ctx.repo / ".tools" / "debs").glob(f"{pkg}_*.deb"))
        if not debs:
            return ""
        ver = debs[0].name.split("_")[1]
        return ver.replace("%3a", ":")
    p = ctx.run(["dpkg-query", "-W", "-f=${Version}", pkg], timeout=5)
    return p.stdout.strip() if p and p.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_python(ctx: Ctx) -> Check:
    v = ".".join(map(str, ctx.python))
    if tuple(ctx.python[:2]) >= MIN_PYTHON:
        return ok("python", f"Python {v} ({ctx.python_exe})", "core")
    return Check("python", FAIL, f"Python {v} is too old (need {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)",
                 "install Python 3.10 or newer (sudo apt install python3)", SYSTEM, "core")


def _missing(d: Path, names) -> list[str]:
    return [n for n in names if not (d / n).exists()]


GRUB_SRC_FIX = ("run `make build` (or `make tools`): build/grub/grubsrc.py builds GRUB from source into "
                ".tools/cache/grub-src (a few minutes the first time)")


def grub_src_version(d: Path) -> str:
    """'GRUB <version> built from source' when D is a platform dir of our GRUB source build."""
    try:
        info = json.loads((Path(d).parent / "build-info.json").read_text())
    except (OSError, ValueError):
        return ""
    return f"GRUB {info.get('version', '?')} built from source (key {info.get('key', '?')})"


def check_grub_efi(ctx: Ctx) -> Check:
    d = ctx.dir("BB_GRUB_EFI_DIR")
    miss = _missing(d, ("kernel.img", "moddep.lst", "normal.mod"))
    if miss or not d.is_dir():
        return Check("grub-efi", FAIL, f"GRUB x86_64-efi modules not found in {d} ({', '.join(miss) or 'no dir'})",
                     GRUB_SRC_FIX, TOOLS, "boot")
    lst = ctx.repo / "build" / "modules-efi.lst"
    absent = []
    if lst.is_file():
        for line in lst.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not (d / f"{line}.mod").exists():
                absent.append(line)
    if absent:
        return Check("grub-efi", FAIL, f"{d} lacks modules listed in build/modules-efi.lst: {' '.join(absent)}",
                     GRUB_SRC_FIX, TOOLS, "boot")
    src = grub_src_version(d)
    if src:
        return ok("grub-efi", f"{short(d, ctx)} ({src})", "boot")
    ver = module_pkg_version(ctx, d, "grub-efi-amd64-bin")
    return ok("grub-efi", f"{d} (grub-efi-amd64-bin {ver or '?'}; dist/ uses the source build, not these)", "boot")


def check_grub_bios(ctx: Ctx) -> Check:
    d = ctx.dir("BB_GRUB_BIOS_DIR")
    miss = _missing(d, ("boot.img", "diskboot.img", "kernel.img", "lzma_decompress.img", "moddep.lst", "normal.mod"))
    if miss or not d.is_dir():
        return Check("grub-bios", FAIL, f"GRUB i386-pc modules not found in {d} ({', '.join(miss) or 'no dir'})",
                     GRUB_SRC_FIX, TOOLS, "boot")
    src = grub_src_version(d)
    if src:
        return ok("grub-bios", f"{short(d, ctx)} ({src})", "boot")
    ver = module_pkg_version(ctx, d, "grub-pc-bin")
    return ok("grub-bios", f"{short(d, ctx)} (grub-pc-bin {ver or '?'}; dist/ uses the source build, not these)",
              "boot")


def check_grub_signed(ctx: Ctx) -> Check:
    """Ubuntu's signed GRUB: only the e2e stub images need it (their SBAT). dist/'s SBAT comes from
    the GRUB source build (build/grub/security-fixes.json), see check_grub_src."""
    d = ctx.dir("BB_GRUB_EFI_SIGNED_DIR")
    f = d / "grubx64.efi.signed"
    if not f.is_file():
        return Check("grub-signed", WARN, f"{f} not found (the e2e stub images use its SBAT)",
                     tools_fix("grub-efi-amd64-signed"), TOOLS, "test")
    vfile = d / "version"
    signed = vfile.read_text().strip() if vfile.is_file() else ""
    return ok("grub-signed", f"{f} ({signed or 'version ?'}; e2e stub images only)", "test")


def check_grub_src(ctx: Ctx) -> Check:
    """The GRUB source build dist/ is made from (build/grub/grubsrc.py, last build)."""
    cur = Path(ctx.env.get("BB_GRUB_CACHE") or ctx.repo / ".tools/cache/grub-src") / "current"
    try:
        info = json.loads((cur / "build-info.json").read_text())
    except (OSError, ValueError):
        return Check("grub-src", WARN, f"GRUB not built from source yet ({short(cur, ctx)} missing)",
                     GRUB_SRC_FIX, TOOLS, "boot")
    claims = [c for c in info.get("security_fixes", {}).get("sbat_claims", [])]
    bad = [f"{c['component']},{c['generation']}" for c in claims if not c.get("proven")]
    if bad:
        return Check("grub-src", FAIL, f"GRUB {info.get('version')}: SBAT claim(s) {', '.join(bad)} not proven",
                     "fix build/grub/security-fixes.json or the patches, then `make build`", TOOLS, "boot")
    sbat = ", ".join(f"{c['component']},{c['generation']}" for c in claims) or "no claim"
    nfix = sum(1 for f in info.get("security_fixes", {}).get("fixes", [])
               if f.get("present") and f.get("type") != "defect")
    return ok("grub-src", f"GRUB {info.get('version')} (key {info.get('key')}): SBAT {sbat} proven, "
                          f"{nfix} security fixes present", "boot")


# What the native source builds need on the host (build/grub/grubsrc.py, build/wimboot/wimbootsrc.py,
# build/winpe/beastmountsrc.py). WARN, not FAIL: docker can build instead (BB_*_BUILDER=docker).
BUILD_TOOLS = ("gcc", "ld", "as", "ar", "objcopy", "strip", "nm", "make", "patch", "dpkg-deb", "xz", "tar",
               "m4", "autoconf", "automake", "aclocal", "pkg-config")
BUILD_TOOLS_APT = ("build-essential binutils patch dpkg xz-utils m4 autoconf automake pkg-config "
                   "libfreetype-dev libc6-dev")


def check_build_tools(ctx: Ctx) -> Check:
    miss = [t for t in BUILD_TOOLS if not ctx.which(t)]
    if miss:
        return Check("build-tools", WARN,
                     f"not found: {' '.join(miss)} (native GRUB, wimboot and beastmount.exe source builds)",
                     f"sudo apt install {BUILD_TOOLS_APT} (or build in docker: BB_GRUB_BUILDER=docker "
                     "BB_WIMBOOT_BUILDER=docker)", SYSTEM, "build")
    return ok("build-tools", f"{', '.join(BUILD_TOOLS)} found (native source builds)", "build")


def check_build_caches(ctx: Ctx) -> list[Check]:
    """Info lines for the wimboot and beastmount source-build caches (a cold build downloads)."""
    out = []
    for name, var, sub, what in (
            ("wimboot-cache", "BB_WIMBOOT_CACHE", "wimboot", "iPXE wimboot source"),
            ("beastmount-cache", "BB_BEASTMOUNT_CACHE", "beastmount", "MinGW-w64 .deb files")):
        d = Path(ctx.env.get(var) or ctx.repo / ".tools/cache" / sub)
        n = len(list((d / "out").glob("*/build-info.json"))) if (d / "out").is_dir() else 0
        dl = len(list((d / "dl").glob("*"))) if (d / "dl").is_dir() else 0
        if n:
            out.append(ok(name, f"{short(d, ctx)}: {n} build(s), {dl} download(s) ({what})", "build"))
        else:
            out.append(Check(name, WARN, f"{short(d, ctx)}: nothing built yet ({dl} download(s) of the {what})",
                             "run `make build` (the first build downloads the pinned inputs, SHA-256 checked)",
                             BUILD, "build"))
    return out


def check_shim(ctx: Ctx) -> Check:
    d = ctx.dir("BB_SHIM_DIR")
    # Debian's shim-signed + shim-helpers-amd64-signed (build/shim/debian-shim.lock)
    miss = _missing(d, ("shimx64.efi.signed", "mmx64.efi.signed"))
    if miss:
        return Check("shim", FAIL, f"{d}: missing {', '.join(miss)}",
                     "run `make tools` (build/shim/fetch.py fetches Debian's pinned shim into .tools/debian)",
                     TOOLS, "boot")
    return ok("shim", f"{d} (Debian shimx64.efi.signed, mmx64.efi.signed)", "boot")


def check_ovmf(ctx: Ctx) -> Check:
    d = ctx.dir("BB_OVMF_DIR")
    miss = _missing(d, ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"))
    if miss:
        return Check("ovmf", FAIL, f"{d}: missing {', '.join(miss)} (UEFI VMs)", tools_fix("ovmf"), TOOLS, "vm")
    sb = _missing(d, ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.ms.fd"))
    if sb:
        return Check("ovmf", WARN, f"{d}: no {', '.join(sb)}: Secure Boot modes (sb, sb-enrolled, sb-fresh) unavailable",
                     tools_fix("ovmf"), TOOLS, "vm")
    return ok("ovmf", f"{d} (code + vars, secboot code + Microsoft-keys vars)", "vm")


def check_seabios(ctx: Ctx) -> Check:
    d = ctx.dir("BB_SEABIOS_DIR")
    if not (d / "bios-256k.bin").is_file():
        return Check("seabios", FAIL, f"{d}/bios-256k.bin not found (BIOS VMs)", tools_fix("seabios"), TOOLS, "vm")
    return ok("seabios", f"{d}/bios-256k.bin", "vm")


def check_qemu(ctx: Ctx) -> list[Check]:
    q = ctx.which("qemu-system-x86_64")
    if not q:
        return [Check("qemu", FAIL, "qemu-system-x86_64 not found", tools_fix("qemu-system-x86"), TOOLS, "vm"),
                Check("qemu-gtk", WARN, "no QEMU, so no GTK display", tools_fix("qemu-system-gui"), TOOLS, "vm")]
    p = ctx.run([q, "--version"], timeout=10)
    if not p or p.returncode != 0:
        err = (p.stderr.strip().splitlines() or ["?"])[-1] if p else "did not run"
        return [Check("qemu", FAIL, f"{q} does not run: {err}", tools_fix("qemu-system-x86"), TOOLS, "vm")]
    m = re.search(r"version (\S+)", p.stdout)
    out = [ok("qemu", f"QEMU {m.group(1) if m else '?'} ({short(q, ctx)})", "vm")]
    h = ctx.run([q, "-display", "help"], timeout=15)
    names = set(h.stdout.split()) if h and h.returncode == 0 else set()
    gui = bool(ctx.env.get("DISPLAY") or ctx.env.get("WAYLAND_DISPLAY"))
    if "gtk" in names:
        out.append(ok("qemu-gtk", "GTK display module loads" + ("" if gui else
                      " (no graphical session here: bb-dev vm uses VNC or serial)"), "vm"))
    else:
        out.append(Check("qemu-gtk", WARN, "QEMU cannot load its GTK display module (bb-dev vm falls back to VNC/serial)",
                         tools_fix("qemu-system-gui"), TOOLS, "vm"))
    return out


def check_kvm(ctx: Ctx, dev: str = "/dev/kvm") -> Check:
    if not os.path.exists(dev):
        return Check("kvm", WARN, f"{dev} does not exist: VMs run without acceleration (about 10x slower)",
                     "enable VT-x/AMD-V in the firmware setup and load kvm_intel or kvm_amd", SYSTEM, "vm")
    if not os.access(dev, os.R_OK | os.W_OK):
        return Check("kvm", WARN, f"{dev} is not accessible for this user: VMs run without KVM (slow)",
                     "sudo usermod -aG kvm \"$USER\", then log out and back in", SYSTEM, "vm")
    return ok("kvm", f"{dev} usable", "vm")


def _tool(ctx, name, names, apt, status=FAIL, action=TOOLS, why="", group="tools", fix=None) -> Check:
    found, missing = [], []
    for n in names:
        (found if ctx.which(n) else missing).append(n)
    if missing:
        return Check(name, status, f"not found: {' '.join(missing)}" + (f" ({why})" if why else ""),
                     fix or tools_fix(apt), action, group)
    where = [ctx.which(n) for n in names]
    dirs = {os.path.dirname(w) for w in where}
    if len(dirs) == 1:
        return ok(name, f"{short(dirs.pop(), ctx)}/: {', '.join(names)}", group)
    return ok(name, ", ".join(short(w, ctx) for w in where), group)


def check_mtools(ctx): return _tool(ctx, "mtools", ("mcopy", "mformat", "mmd", "mdir"), "mtools", why="ESP")
def check_xorriso(ctx): return _tool(ctx, "xorriso", ("xorriso",), "xorriso", why="fixture ISOs")
def check_mksquashfs(ctx): return _tool(ctx, "mksquashfs", ("mksquashfs",), "squashfs-tools", why="fixture ISOs")
def check_sfdisk(ctx): return _tool(ctx, "sfdisk", ("sfdisk",), "fdisk", action=SYSTEM, fix="sudo apt install fdisk")
def check_mkfs_fat(ctx): return _tool(ctx, "mkfs.fat", ("mkfs.fat",), "dosfstools", why="ESP and FAT32")
def check_mkfs_exfat(ctx): return _tool(ctx, "mkfs.exfat", ("mkfs.exfat",), "exfatprogs", why="default data fs")
def check_sbsign(ctx): return _tool(ctx, "sbsigntool", ("sbsign", "sbverify"), "sbsigntool", why="signing GRUB")
def check_socat(ctx): return _tool(ctx, "socat", ("socat",), "socat", status=WARN,
                                   why="talking to VM serial/monitor sockets")


def check_mkfs_ntfs(ctx: Ctx) -> Check:
    if ctx.which("mkfs.ntfs") or ctx.which("mkntfs"):
        return ok("mkfs.ntfs", short(ctx.which("mkfs.ntfs") or ctx.which("mkntfs"), ctx), "tools")
    return Check("mkfs.ntfs", WARN, "not found: mkfs.ntfs (only --fs ntfs needs it)", tools_fix("ntfs-3g"), TOOLS, "tools")


def check_openssl(ctx: Ctx) -> Check:
    return _tool(ctx, "openssl", ("openssl",), "openssl", action=SYSTEM, why="keys and signing",
                 fix="sudo apt install openssl")


def check_virt_fw_vars(ctx: Ctx) -> Check:
    exe = ctx.which("virt-fw-vars")
    if not exe:
        return Check("virt-fw-vars", WARN, "not found (sb-enrolled VMs and Secure Boot e2e tests need it)",
                     tools_fix("python3-virt-firmware"), TOOLS, "vm")
    p = ctx.run([exe, "--help"], timeout=10)
    if not p or p.returncode != 0:
        err = (p.stderr.strip().splitlines() or ["?"])[-1] if p else "did not run"
        return Check("virt-fw-vars", WARN, f"{exe} does not run: {err}", tools_fix("python3-virt-firmware"), TOOLS, "vm")
    return ok("virt-fw-vars", short(exe, ctx), "vm")


def check_udisks(ctx: Ctx) -> Check:
    if not ctx.which("udisksctl"):
        return Check("udisks", WARN, "udisksctl not found: exFAT/NTFS dev images cannot be filled rootless "
                     "(bb-dev image falls back to FAT32)", "sudo apt install udisks2", SYSTEM, "tools")
    try:
        from .. import diskimg
        usable, reason = diskimg.udisks_status()
    except Exception as exc:  # pragma: no cover - depends on the image helpers  # noqa: BLE001
        usable, reason = False, f"probe failed: {exc}"
    if not usable:
        return Check("udisks", WARN, f"udisks loop devices not usable: {reason} (bb-dev image falls back to FAT32)",
                     "run outside a sandbox, in a desktop session where polkit lets you set up loop devices",
                     SYSTEM, "tools")
    return ok("udisks", "udisksctl can set up loop devices (exFAT/NTFS images)", "tools")


def check_gdb(ctx: Ctx) -> Check:
    g = ctx.which("gdb")
    if not g:
        return Check("gdb", WARN, "gdb not found (only bb-dev gdb needs it)", "sudo apt install gdb", SYSTEM, "debug")
    p = ctx.run([g, "-nx", "-batch", "-ex", "python print('bbpy')", "-ex", "show version"], timeout=10)
    if not p or "bbpy" not in p.stdout:
        return Check("gdb", WARN, f"{g} has no Python support (bb-dev gdb needs it)",
                     "sudo apt install gdb (Ubuntu's gdb includes Python)", SYSTEM, "debug")
    m = re.search(r"GNU gdb (?:\([^)]*\) )?(\S+)", p.stdout)
    return ok("gdb", f"gdb {m.group(1) if m else '?'} with Python ({g})", "debug")


def _grubsyms(ctx: Ctx):
    path = paths.REPO / "devtools" / "gdb" / "grubsyms.py"   # bb-dev's own helper, not ctx.repo's
    spec = importlib.util.spec_from_file_location("bb_grubsyms", path)
    if not spec or not spec.loader:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_grub_dbg(ctx: Ctx) -> list[Check]:
    out = []
    try:
        gs = _grubsyms(ctx)
    except (OSError, ImportError) as exc:
        return [Check("grub-dbg", WARN, f"devtools/gdb/grubsyms.py unusable: {exc}", "restore devtools/gdb/", "", "debug")]
    for plat, mod_var, dbg_var, bin_pkg, dbg_pkg in (
            ("pc", "BB_GRUB_BIOS_DIR", "BB_GRUB_PC_DBG_DIR", "grub-pc-bin", "grub-pc-dbg"),
            ("efi", "BB_GRUB_EFI_DIR", "BB_GRUB_EFI_DBG_DIR", "grub-efi-amd64-bin", "grub-efi-amd64-dbg")):
        name = f"grub-dbg-{plat}"
        mod_dir, dbg_dir = ctx.dir(mod_var), ctx.dir(dbg_var)
        ver = module_pkg_version(ctx, mod_dir, bin_pkg) if mod_dir.is_dir() else ""
        want = f"{dbg_pkg} {ver}".strip()
        if not (dbg_dir / "kernel.exec").is_file():
            out.append(Check(name, WARN, f"no GRUB debug symbols in {dbg_dir} (bb-dev gdb --platform {plat})",
                             f"run `make tools` (fetches {want} into .tools/grub-dbg, matching {bin_pkg})", TOOLS, "debug"))
            continue
        try:
            problems, missing = gs.verify(dbg_dir, mod_dir)
        except Exception as exc:  # noqa: BLE001
            problems, missing = [f"cannot compare: {exc}"], []
        if problems:
            out.append(Check(name, WARN, f"{dbg_dir} does not match {mod_dir}: {problems[0]}",
                             f"run `make tools` (unpacks {want} again and re-checks; a real mismatch it explains)",
                             TOOLS, "debug"))
        elif missing:
            out.append(Check(name, WARN, f"{dbg_dir} incomplete: {missing[0]}",
                             f"run `make tools` (unpacks {want} again)", TOOLS, "debug"))
        else:
            out.append(ok(name, f"{want or dbg_pkg} in {short(dbg_dir, ctx)} matches {short(mod_dir, ctx)}", "debug"))
    return out


def _requirement_pins(req: Path) -> dict[str, str]:
    pins = {}
    try:
        for line in req.read_text().splitlines():
            m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)\s*(;\s*(.*?))?\s*\\?$", line)
            if m:
                pins[m.group(1).lower().replace("_", "-")] = (m.group(2), (m.group(4) or "").strip())
    except OSError:
        pass
    return pins


def venv_versions(venv: Path) -> dict[str, str]:
    """{normalised name: version} from the venv's *.dist-info dirs."""
    out = {}
    for d in glob.glob(str(venv / "lib" / "python*" / "site-packages" / "*.dist-info")):
        base = os.path.basename(d)[: -len(".dist-info")]
        name, _, ver = base.rpartition("-")
        out[name.lower().replace("_", "-")] = ver
    return out


def check_venv(ctx: Ctx) -> Check:
    venv = ctx.repo / ".venv"
    if not (venv / "bin" / "python").exists():
        return Check("venv", WARN, ".venv not found (pytest, coverage, debugpy, ruff)",
                     "run `bin/bb-dev setup` (or `make dev`)", VENV, "repo")
    have = venv_versions(venv)
    missing = [p for p in VENV_PACKAGES if p not in have]
    if missing:
        return Check("venv", WARN, f".venv lacks {' '.join(missing)}", "run `bin/bb-dev setup`", VENV, "repo")
    pins = _requirement_pins(ctx.repo / "requirements-dev.txt")
    stale = [f"{n} {have[n]} (want {pins[n][0]})" for n in VENV_PACKAGES if n in pins and have.get(n) != pins[n][0]]
    if stale:
        return Check("venv", WARN, f".venv out of date: {', '.join(stale)}", "run `bin/bb-dev setup`", VENV, "repo")
    return ok("venv", ".venv: " + ", ".join(f"{p} {have[p]}" for p in VENV_PACKAGES), "repo")


def _cert_end(ctx: Ctx, crt: Path) -> _dt.datetime | None:
    if not ctx.which("openssl"):
        return None
    p = ctx.run(["openssl", "x509", "-in", str(crt), "-noout", "-enddate"], timeout=10)
    if not p or p.returncode != 0:
        return None
    m = re.search(r"notAfter=(.+)", p.stdout)
    if not m:
        return None
    try:
        return _dt.datetime.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


def check_keys(ctx: Ctx, now: _dt.datetime | None = None) -> Check:
    k = ctx.repo / "keys"
    miss = [n for n in ("beast-boot.key", "beast-boot.crt", "beast-boot.cer") if not (k / n).is_file()]
    if miss:
        return Check("keys", FAIL, f"keys/: missing {', '.join(miss)} (the build signs GRUB with it)",
                     "run `make keys` (creates a local signing key; never commit it)", KEYS, "repo")
    mode = (k / "beast-boot.key").stat().st_mode & 0o777
    if mode & 0o077:
        return Check("keys", WARN, f"keys/beast-boot.key is readable by others (mode {mode:o})",
                     "chmod 600 keys/beast-boot.key", "", "repo")
    end = _cert_end(ctx, k / "beast-boot.crt")
    if end is None:
        return ok("keys", "keys/beast-boot.{key,crt,cer} (expiry unknown)", "repo")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    days = (end - now).days
    when = end.strftime("%Y-%m-%d")
    if days < 0:
        return Check("keys", WARN, f"certificate expired on {when} (shim ignores dates; other tools may not)",
                     "build/keygen.sh --force makes a new key (machines must enroll the new certificate)", "", "repo")
    if days < CERT_WARN_DAYS:
        return Check("keys", WARN, f"certificate expires on {when} ({days} days)",
                     "build/keygen.sh --force before then (machines must enroll the new certificate)", "", "repo")
    return ok("keys", f"keys/beast-boot.{{key,crt,cer}}; certificate valid until {when} ({days} days)", "repo")


def check_dist(ctx: Ctx) -> Check:
    dist = ctx.repo / "dist"
    if not (dist / "manifest.json").is_file():
        return Check("dist", FAIL, "dist/ is not built", "run `make build` (after `make keys`)", BUILD, "repo")
    try:
        from .. import menufiles
        if ctx.repo == paths.REPO:
            st = menufiles.dist_state(dist)
            if st.stale:
                return Check("dist", WARN, f"dist/ is older than its sources: {st.describe()}",
                             "run `make build` (or `bin/bb-dev menu-sync` to push grub/ edits into the dev image)",
                             BUILD, "repo")
            return ok("dist", "dist/ matches grub/ and build/", "repo")
    except Exception:  # pragma: no cover - fall back to plain mtimes below  # noqa: S110, BLE001
        pass
    built = (dist / "manifest.json").stat().st_ctime
    newer = []
    for src in ("grub", "build"):
        for dirpath, dirnames, filenames in os.walk(ctx.repo / src):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "__pycache__"]
            for f in filenames:
                p = Path(dirpath) / f
                if not f.startswith(".") and p.stat().st_mtime > built:
                    newer.append(p.relative_to(ctx.repo).as_posix())
    if newer:
        return Check("dist", WARN, f"dist/ is older than {', '.join(sorted(newer)[:3])}"
                     + (f" and {len(newer) - 3} more" if len(newer) > 3 else ""),
                     "run `make build`", BUILD, "repo")
    return ok("dist", "dist/ is newer than grub/ and build/", "repo")


def check_dev_image(ctx: Ctx) -> Check:
    """Is the default dev image current: the installer's layout and dist/'s build id?"""
    img = ctx.repo / "out" / "dev" / paths.DEFAULT_IMAGE.name
    name = "dev image"
    if not img.is_file():
        return Check(name, WARN, f"{short(img, ctx)} not built yet", "bin/bb-dev image --fixtures --debug", "", "repo")
    if not (ctx.repo / "dist" / "manifest.json").is_file():
        return Check(name, WARN, f"{short(img, ctx)}: dist/ is not built, nothing to compare with",
                     "run `make build`", BUILD, "repo")
    from .. import freshness
    v = freshness.check(img, dist=ctx.repo / "dist")
    if v.action == freshness.CURRENT:
        return ok(name, f"{short(img, ctx)} is current: {v.reason}", "repo")
    if v.action == freshness.UPDATE:
        fix = "bin/bb-dev vm updates it before booting (or bin/beast-boot update --image " \
              f"{short(img, ctx)} --yes)"
    elif v.action == freshness.REBUILD:
        fix = f"bin/bb-dev vm --yes rebuilds it, the same as: {freshness.rebuild_command(img)}"
    else:
        fix = freshness.rebuild_command(img)
    return Check(name, WARN, f"{short(img, ctx)} is outdated: {v.reason}" if v.stale
                 else f"{short(img, ctx)}: cannot tell whether it is current ({v.reason})", fix, "", "repo")


def check_disk(ctx: Ctx, usage=shutil.disk_usage) -> Check:
    try:
        free = usage(ctx.repo).free
    except OSError as exc:
        return Check("disk", WARN, f"cannot tell free space: {exc}", "", "", "repo")
    gib = free / (1 << 30)
    if gib < DISK_FAIL_GIB:
        return Check("disk", FAIL, f"{gib:.1f} GiB free in {ctx.repo}",
                     "free disk space (dev images, e2e copies and fixtures live in out/: `make clean`)", SYSTEM, "repo")
    if gib < DISK_WARN_GIB:
        return Check("disk", WARN, f"only {gib:.1f} GiB free (images are sparse but e2e copies add up)",
                     "free disk space (`make clean` removes out/ and dist/)", SYSTEM, "repo")
    return ok("disk", f"{gib:.0f} GiB free", "repo")


CHECKS = (
    check_python, check_grub_src, check_grub_efi, check_grub_bios, check_grub_signed, check_shim, check_ovmf,
    check_seabios,
    check_qemu, check_kvm, check_mtools, check_xorriso, check_mksquashfs, check_sfdisk, check_mkfs_fat, check_mkfs_exfat,
    check_mkfs_ntfs, check_sbsign, check_openssl, check_virt_fw_vars, check_udisks, check_socat, check_gdb,
    check_grub_dbg, check_build_tools, check_build_caches, check_venv, check_keys, check_dist, check_dev_image, check_disk,
)


def collect(ctx: Ctx | None = None, checks=CHECKS) -> list[Check]:
    """Run every check (in parallel) and return the results in CHECKS order."""
    ctx = ctx or Ctx(paths.load_env())
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(fn, ctx) for fn in checks]
        results: list[Check] = []
        for fn, fut in zip(checks, futures):
            try:
                r = fut.result()
            except Exception as exc:  # a broken check must not hide the others  # noqa: BLE001
                r = Check(fn.__name__.removeprefix("check_"), WARN, f"check crashed: {exc!r}", "report a bb-dev bug")
            results.extend(r if isinstance(r, list) else [r])
    return results


def counts(results: list[Check]) -> dict[str, int]:
    c = {OK: 0, WARN: 0, FAIL: 0}
    for r in results:
        c[r.status] += 1
    return c


def to_json(results: list[Check]) -> str:
    c = counts(results)
    return json.dumps({"ok": c[FAIL] == 0, "summary": c, "checks": [r.as_dict() for r in results]}, indent=2)


def _paint(status: str, stream) -> str:
    if os.environ.get("NO_COLOR") or not getattr(stream, "isatty", lambda: False)():
        return f"{status:<4}"
    code = {OK: "32", WARN: "33", FAIL: "31"}[status]
    return f"\033[{code}m{status:<4}\033[0m"


def render(results: list[Check], stream=None, only_problems: bool = False) -> None:
    stream = stream or sys.stdout
    width = max((len(r.name) for r in results), default=8)
    for r in results:
        if only_problems and r.status == OK:
            continue
        print(f"  {_paint(r.status, stream)}  {r.name:<{width}}  {r.detail}", file=stream)
        if r.status != OK and r.fix:
            print(f"        {'':<{width}}  fix: {r.fix}", file=stream)
    c = counts(results)
    print(f"{c[OK]} OK, {c[WARN]} WARN, {c[FAIL]} FAIL", file=stream)


def register(sub) -> None:
    p = sub.add_parser("doctor", help="check the dev environment and explain fixes",
                       description="Check everything beast-boot development needs; each problem comes "
                                   "with a one-line fix. Exit status 1 if any check FAILs.")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=run)


def run(args) -> int:
    results = collect()
    if args.json:
        print(to_json(results))
    else:
        print("bb-dev doctor: beast-boot development environment")
        render(results)
    return 1 if counts(results)[FAIL] else 0
