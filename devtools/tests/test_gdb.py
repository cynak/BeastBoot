"""bb-dev gdb + devtools/gdb: ELF/PE parsing, debug-symbol verification, the
x86_64-efi kernel layout, gdb session/command building and VM detection.

No QEMU here, except the end-to-end demonstration, which runs only with
BB_DEV_GDB_DEMO=1 (it boots BIOS and UEFI VMs: about 10 s with KVM).
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import struct
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "devtools", ROOT / "installer"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from bbdev import paths
from bbdev.commands import gdb as gdbcmd
from bbdev.msg import Failure

GDB_DIR = ROOT / "devtools" / "gdb"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


grubsyms = load("grubsyms_under_test", GDB_DIR / "grubsyms.py")

SHT_PROGBITS, SHT_STRTAB, SHT_RELA, SHT_NOBITS = 1, 3, 4, 8
A, AX, WA = 0x2, 0x6, 0x3


def make_elf(path: Path, sections: list[dict], *, is64: bool = True, etype: int = 1) -> Path:
    """Write a minimal little-endian ELF with the given sections.

    Each section: {"name", "type", "flags", "data" (bytes; NOBITS: size), "align",
    "addr", "info"}. Section 0 (NULL) and .shstrtab are added automatically."""
    names = b"\0"
    name_off = []
    for s in sections + [{"name": ".shstrtab"}]:
        name_off.append(len(names))
        names += s["name"].encode() + b"\0"
    ehsize, shentsize = (64, 64) if is64 else (52, 40)
    body = bytearray()
    offsets = []
    for s in sections:
        offsets.append(ehsize + len(body))
        if s.get("type", SHT_PROGBITS) != SHT_NOBITS:
            body += s["data"]
    shstr_off = ehsize + len(body)
    body += names
    while (ehsize + len(body)) % 8:
        body += b"\0"
    shoff = ehsize + len(body)
    shnum = len(sections) + 2
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1]) + b"\0" * 9
    if is64:
        hdr = ident + struct.pack("<HHIQQQIHHHHHH", etype, 62, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize,
                                  shnum, shnum - 1)
        fmt = "<IIQQQQIIQQ"
    else:
        hdr = ident + struct.pack("<HHIIIIIHHHHHH", etype, 3, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize,
                                  shnum, shnum - 1)
        fmt = "<IIIIIIIIII"
    shdrs = struct.pack(fmt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for i, s in enumerate(sections):
        typ = s.get("type", SHT_PROGBITS)
        size = s["data"] if typ == SHT_NOBITS else len(s["data"])
        shdrs += struct.pack(fmt, name_off[i], typ, s.get("flags", 0), s.get("addr", 0), offsets[i], size,
                             s.get("link", 0), s.get("info", 0), s.get("align", 1), s.get("entsize", 0))
    shdrs += struct.pack(fmt, name_off[-1], SHT_STRTAB, 0, 0, shstr_off, len(names), 0, 0, 1, 0)
    path.write_bytes(hdr + bytes(body) + shdrs)
    return path


def fake_grub_tree(tmp: Path, *, text=b"\x90" * 64, data=b"D" * 16, mod_text=b"\xc3" * 32,
                   dbg_text=None, dbg_mod_text=None, modules=("normal", "linux")):
    """(dbg_dir, mod_dir) with kernel.img/.exec and NAME.mod/.module files."""
    mod_dir, dbg_dir = tmp / "mods", tmp / "dbg"
    mod_dir.mkdir()
    dbg_dir.mkdir()
    def secs(t):
        return [{"name": ".text", "flags": AX, "data": t}, {"name": ".data", "flags": WA, "data": data}]

    make_elf(mod_dir / "kernel.img", secs(text), is64=False, etype=2)
    make_elf(dbg_dir / "kernel.exec", secs(dbg_text if dbg_text is not None else text)
             + [{"name": ".debug_info", "data": b"dwarf"}], is64=False, etype=2)
    for m in modules:
        make_elf(mod_dir / f"{m}.mod", [{"name": ".text", "flags": AX, "data": mod_text}], is64=False)
        make_elf(dbg_dir / f"{m}.module", [{"name": ".text", "flags": AX,
                                            "data": dbg_mod_text if dbg_mod_text is not None else mod_text},
                                           {"name": ".debug_info", "data": b"x"}], is64=False)
    return dbg_dir, mod_dir


# ---------------------------------------------------------------------------
# grubsyms: ELF
# ---------------------------------------------------------------------------

def test_elf_sections_and_bytes(tmp_path):
    p = make_elf(tmp_path / "a.o", [{"name": ".text", "flags": AX, "data": b"abc"},
                                    {"name": ".bss", "type": SHT_NOBITS, "flags": WA, "data": 64, "align": 32}])
    secs = grubsyms.elf_sections(p)
    assert [s.name for s in secs] == ["", ".text", ".bss", ".shstrtab"]
    assert secs[1].exec and secs[1].alloc and not secs[2].exec
    assert secs[2].size == 64 and secs[2].align == 32
    assert grubsyms.elf_section_bytes(p, ".text") == b"abc"
    assert grubsyms.elf_section_bytes(p, ".bss") is None       # NOBITS has no contents
    assert grubsyms.elf_section_bytes(p, ".nope") is None
    assert grubsyms.section_names(p)[1] == ".text"


def test_elf32_parses(tmp_path):
    p = make_elf(tmp_path / "b.o", [{"name": ".text", "flags": AX, "data": b"\x90\x90"}], is64=False)
    assert grubsyms.elf_section_bytes(p, ".text") == b"\x90\x90"


def test_not_elf(tmp_path):
    (tmp_path / "x").write_bytes(b"MZ\0\0")
    with pytest.raises(ValueError):
        grubsyms.elf_sections(tmp_path / "x")


def test_verify_match(tmp_path):
    dbg, mods = fake_grub_tree(tmp_path)
    assert grubsyms.verify(dbg, mods) == ([], [])
    assert grubsyms.verify(dbg, mods, all_modules=True) == ([], [])


def test_verify_kernel_mismatch(tmp_path):
    dbg, mods = fake_grub_tree(tmp_path, dbg_text=b"\xcc" * 64)
    problems, _ = grubsyms.verify(dbg, mods)
    assert problems and "kernel.exec .text" in problems[0]


def test_verify_module_mismatch_and_missing(tmp_path):
    dbg, mods = fake_grub_tree(tmp_path, dbg_mod_text=b"\x90" * 32)
    problems, _ = grubsyms.verify(dbg, mods)
    assert any("normal.module" in p for p in problems)
    (dbg / "linux.module").unlink()
    _, missing = grubsyms.verify(dbg, mods)
    assert any(m.endswith("linux.module") for m in missing)


def test_verify_cli_exit_codes(tmp_path):
    dbg, mods = fake_grub_tree(tmp_path)
    cli = [sys.executable, "-I", str(GDB_DIR / "grubsyms.py"), "verify", str(dbg), str(mods), "--all"]
    assert subprocess.run(cli, capture_output=True, check=False).returncode == 0
    make_elf(dbg / "normal.module", [{"name": ".text", "flags": AX, "data": b"\x00" * 32}], is64=False)
    r = subprocess.run(cli, capture_output=True, text=True, check=False)
    assert r.returncode == 1 and "MISMATCH" in r.stderr
    (dbg / "kernel.exec").unlink()
    assert subprocess.run(cli + ["--quiet"], capture_output=True, check=False).returncode in (1, 2)


def test_efi_layout_puts_bss_after_all_data(tmp_path):
    # ELF order: .text, .rodata, .bss, .data, .rodata.str1.1 - grub-mkimage puts
    # NOBITS after every PROGBITS data section, at the next page after .text.
    p = make_elf(tmp_path / "kernel.exec", [
        {"name": ".text", "flags": AX, "data": b"\x90" * 0x1234},
        {"name": ".rodata", "flags": A, "data": b"r" * 0x30, "align": 32},
        {"name": ".bss", "type": SHT_NOBITS, "flags": WA, "data": 0x100, "align": 32},
        {"name": ".data", "flags": WA, "data": b"d" * 0x21, "align": 32},
        {"name": ".rodata.str1.1", "flags": A | 0x30, "data": b"s" * 5, "align": 1},
        {"name": ".debug_info", "data": b"z"},
    ])
    lay = grubsyms.efi_kernel_layout(p, 0x10000)
    assert lay[".text"] == 0x10000
    assert lay["__pe_data__"] == 0x10000 + 0x2000           # alignup(0x1234, 4096)
    assert lay[".rodata"] == 0x12000
    assert lay[".data"] == 0x12000 + 0x40                   # after .rodata, 32-aligned
    assert lay[".rodata.str1.1"] == 0x12000 + 0x40 + 0x21
    assert lay[".bss"] == grubsyms.alignup(0x12000 + 0x40 + 0x21 + 5, 32)
    assert ".debug_info" not in lay
    cmd = grubsyms.efi_add_symbol_file_cmd(p, 0x10000)
    assert cmd.startswith(f"add-symbol-file {p} -s .text 0x10000")
    assert f"-s .bss {lay['.bss']:#x}" in cmd


def test_text_signature_masks_relocations(tmp_path):
    text = bytes(range(64))
    rela = struct.pack("<QQq", 3, (0 << 32) | 2, 0) + struct.pack("<QQq", 20, 1, 0)   # PC32 @3, R_X86_64_64 @20
    p = make_elf(tmp_path / "k.o", [
        {"name": ".text", "flags": AX, "data": text},
        {"name": ".rela.text", "type": SHT_RELA, "data": rela, "info": 1, "entsize": 24, "align": 8},
    ])
    code, mask = grubsyms.text_signature(p, 32)
    assert code == text[:32]
    assert [i for i, m in enumerate(mask) if m == 0] == [3, 4, 5, 6] + list(range(20, 28))
    mem = bytearray(text[:32])
    mem[4] = 0xAA          # relocated byte: ignored
    mem[21] = 0xBB
    assert grubsyms.matches_signature(bytes(mem), (code, mask))
    mem[0] = 0xFF          # real code difference
    assert not grubsyms.matches_signature(bytes(mem), (code, mask))
    assert not grubsyms.matches_signature(b"short", (code, mask))


def test_parse_pe_sections():
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x22)
    opt = 0x84 + 20
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<I", hdr, opt + 16, 0x1000)
    struct.pack_into("<I", hdr, opt + 56, 0x157000)
    sh = opt + 240
    struct.pack_into("<8sIIII", hdr, sh, b".text", 0xD000, 0x1000, 0xD000, 0x400)
    struct.pack_into("<8sIIII", hdr, sh + 40, b".data", 0x11000, 0xE000, 0x11000, 0xD400)
    info, secs = grubsyms.parse_pe_sections(bytes(hdr))
    assert info["entry_rva"] == 0x1000 and info["size_of_image"] == 0x157000
    assert [(s["name"], s["rva"]) for s in secs] == [(".text", 0x1000), (".data", 0xE000)]
    with pytest.raises(ValueError):
        grubsyms.parse_pe_sections(b"\x7fELF" + bytes(100))


# ---------------------------------------------------------------------------
# bbgrub.py loads inside a (fake) gdb and registers its commands
# ---------------------------------------------------------------------------

def test_bbgrub_registers_commands(monkeypatch):
    registered = []

    class Command:
        def __init__(self, name, *a, **k):
            registered.append(name)

    fake = types.SimpleNamespace(Command=Command, Breakpoint=object, COMMAND_USER=0, COMMAND_BREAKPOINTS=1,
                                 BP_HARDWARE_BREAKPOINT=2, error=RuntimeError, MemoryError=MemoryError,
                                 GdbError=RuntimeError, convenience_variable=lambda n: None)
    monkeypatch.setitem(sys.modules, "gdb", fake)
    mod = load("bbgrub_under_test", GDB_DIR / "bbgrub.py")
    for c in ("bb-connect", "bb-attach-pc", "bb-attach-efi", "bb-efi-find", "bb-load-kernel", "bb-break",
              "bb-modules", "bb-load-modules", "bb-autoload", "bb-help"):
        assert c in registered
    assert mod.PC_KERNEL_ADDR == 0x9000
    assert mod.DEBUG_IMAGE_INFO_GUID.hex() == "772e1549da1a6447b7a27afefed95e8b"


def test_init_scripts_use_helpers():
    pc = (GDB_DIR / "pc.gdb").read_text()
    efi = (GDB_DIR / "efi.gdb").read_text()
    assert "kernel.exec" in pc and "bb-connect" in pc and "bb-attach-pc" in pc
    assert "bb-connect" in efi and "bb-attach-efi" in efi and "file " not in efi.replace("No `file`", "")


# ---------------------------------------------------------------------------
# bb-dev gdb
# ---------------------------------------------------------------------------

QEMU_BIOS = ("/x/.tools/bin/qemu-system-x86_64 -name 'bb-dev img bios' -nodefaults -machine q35 -accel kvm "
             "-cpu host -bios /b/bios-256k.bin -gdb tcp:127.0.0.1:1240 -S -pidfile /s/qemu.pid")


def test_parse_qemu_cmd():
    i = gdbcmd.parse_qemu_cmd(QEMU_BIOS)
    assert (i.qemu, i.port, i.host, i.kvm) == ("qemu-system-x86_64", 1240, "127.0.0.1", True)
    j = gdbcmd.parse_qemu_cmd("qemu-system-i386 -accel tcg -s")
    assert (j.qemu, j.port, j.kvm) == ("qemu-system-i386", 1234, False)
    k = gdbcmd.parse_qemu_cmd("qemu-system-x86_64 -accel tcg")
    assert k.port is None


def test_detect_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "VM_OUT", tmp_path)
    assert gdbcmd.detect_vm(Path("/i/dev.img")) is None
    d = tmp_path / "dev"
    d.mkdir()
    (d / "qemu-uefi.cmd").write_text("qemu-system-x86_64 -accel kvm\n")
    os.utime(d / "qemu-uefi.cmd", (1, 1))
    (d / "qemu-bios.cmd").write_text(QEMU_BIOS + "\n")
    (d / "qemu.pid").write_text(str(os.getpid()))
    info = gdbcmd.detect_vm(Path("/i/dev.img"))
    assert info.mode == "bios" and info.port == 1240 and info.running


def test_session_and_argv(tmp_path):
    plat = gdbcmd.PLATFORMS["pc"]
    text = gdbcmd.session_text(plat, dbg_dir=Path('/d "q"'), mod_dir=Path("/m"), target="127.0.0.1:1234",
                               state_file=tmp_path / "s.json", breaks=["grub_cmd_linux"])
    assert 'set $BB_GDB_DBG_DIR = "/d \\"q\\""' in text
    assert f"source {GDB_DIR / 'bbgrub.py'}" in text and f"source {GDB_DIR / 'pc.gdb'}" in text
    assert text.index("bbgrub.py") < text.index("pc.gdb") < text.index("bb-break grub_cmd_linux")
    argv = gdbcmd.gdb_argv("gdb", Path("/s.gdb"), batch=True, ex=["continue", "bt"], scripts=["/u.gdb"])
    assert argv == ["gdb", "-q", "-nx", "-batch", "-x", "/s.gdb", "-ex", "continue", "-ex", "bt", "-x", "/u.gdb"]


def test_check_symbols_failures(tmp_path):
    plat = gdbcmd.PLATFORMS["pc"]
    with pytest.raises(Failure) as e:
        gdbcmd.check_symbols(plat, {"BB_GRUB_BIOS_DIR": str(tmp_path / "none"), "BB_GRUB_PC_DBG_DIR": str(tmp_path)})
    assert "make tools" in e.value.hint
    dbg, mods = fake_grub_tree(tmp_path)
    env = {"BB_GRUB_BIOS_DIR": str(mods), "BB_GRUB_PC_DBG_DIR": str(tmp_path / "nodbg")}
    with pytest.raises(Failure) as e:
        gdbcmd.check_symbols(plat, env)
    assert "grub-pc-dbg" in e.value.hint
    env["BB_GRUB_PC_DBG_DIR"] = str(dbg)
    assert gdbcmd.check_symbols(plat, env) == (dbg, mods)
    make_elf(dbg / "kernel.exec", [{"name": ".text", "flags": AX, "data": b"\x00" * 64}], is64=False, etype=2)
    with pytest.raises(Failure) as e:
        gdbcmd.check_symbols(plat, env)
    assert "not the same GRUB build" in str(e.value)


def _args(**kw):
    base = {"port": None, "host": None, "platform": None, "image": Path("/i/dev.img"), "breaks": [], "ex": [],
            "scripts": [], "batch": False, "print_cmd": True}
    base.update(kw)
    return argparse.Namespace(**base)


def test_print_cmd_and_platform_default(tmp_path, monkeypatch, capsys):
    dbg, mods = fake_grub_tree(tmp_path)
    env = {"PATH": os.environ.get("PATH", ""), "BB_GRUB_BIOS_DIR": str(mods), "BB_GRUB_PC_DBG_DIR": str(dbg),
           "BB_GRUB_EFI_DIR": str(mods), "BB_GRUB_EFI_DBG_DIR": str(dbg)}
    monkeypatch.setattr(paths, "load_env", lambda: env)
    monkeypatch.setattr(paths, "VM_OUT", tmp_path / "vm")
    monkeypatch.setattr(gdbcmd.shutil, "which", lambda name, path=None: "/usr/bin/gdb")
    assert gdbcmd.run(_args()) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("/usr/bin/gdb -q -nx -x ") and out.endswith("gdb-efi.gdb")   # default: efi
    state = tmp_path / "vm" / "dev"
    (state / "qemu-bios.cmd").write_text(QEMU_BIOS)
    assert gdbcmd.run(_args(breaks=["grub_cmd_linux"], batch=True)) == 0
    captured = capsys.readouterr()
    assert captured.out.strip().endswith("gdb-pc.gdb") and "-batch" in captured.out
    session = (state / "gdb-pc.gdb").read_text()
    assert '"127.0.0.1:1240"' in session and "bb-break grub_cmd_linux" in session
    assert "64-bit registers" in captured.err and "hardware breakpoints" in captured.err
    assert gdbcmd.run(_args(port=99999)) == 1


def test_real_debug_symbols_match_if_fetched():
    env = paths.load_env()
    for dbg_var, mod_var in (("BB_GRUB_PC_DBG_DIR", "BB_GRUB_BIOS_DIR"), ("BB_GRUB_EFI_DBG_DIR", "BB_GRUB_EFI_DIR")):
        dbg = Path(env.get(dbg_var, ""))
        if not (dbg / "kernel.exec").is_file():
            pytest.skip(f"{dbg_var}: no debug symbols (make tools)")
        assert grubsyms.verify(dbg, env[mod_var]) == ([], [])


@pytest.mark.skipif(os.environ.get("BB_DEV_GDB_DEMO") != "1", reason="boots VMs; set BB_DEV_GDB_DEMO=1")
def test_demo_bios_and_uefi():
    r = subprocess.run([sys.executable, str(GDB_DIR / "demo.py"), "--platform", "both"], capture_output=True,
                       text=True, timeout=900, check=False)
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
    assert "demo: PASS" in r.stdout


def test_demo_image_rebuilt_when_not_from_current_dist(tmp_path, monkeypatch):
    demo = load("demo_under_test", GDB_DIR / "demo.py")
    img = tmp_path / "gdb-demo.img"
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "manifest.json").write_text('{"build_id": "b-new"}')
    monkeypatch.setattr(demo, "DEMO_IMAGE", img)
    monkeypatch.setattr(demo, "REPO", tmp_path)
    monkeypatch.setattr(paths, "DIST", dist)
    installs = []

    def fake_run(cmd, **kw):
        installs.append(cmd)
        Path(cmd[cmd.index("--image") + 1]).write_text("new image")
        return subprocess.CompletedProcess(cmd, 0)
    monkeypatch.setattr(demo.subprocess, "run", fake_run)
    stale = {"why": None}
    monkeypatch.setattr(demo, "image_stale", lambda p: stale["why"])

    assert demo.ensure_image(img, {}) == img and len(installs) == 1           # missing -> built
    from beastbooter.layout import MIB, MIN_DISK_MIB
    from beastbooter.util import parse_size
    assert parse_size(installs[0][installs[0].index("--size") + 1]) >= MIN_DISK_MIB * MIB  # the installer accepts it
    assert demo.ensure_image(img, {}) == img and len(installs) == 1           # current -> kept
    img.write_text("old image")
    stale["why"] = "it was installed from build b-old, dist/ is build b-new"
    assert demo.ensure_image(img, {}) == img and len(installs) == 2           # other build -> rebuilt
    assert img.read_text() == "new image" and "install" in installs[-1]
    other = tmp_path / "mine.img"
    other.write_text("x")
    assert demo.ensure_image(other, {}) == other and len(installs) == 2       # --image: never touched
    with pytest.raises(SystemExit):
        demo.ensure_image(tmp_path / "nope.img", {})
