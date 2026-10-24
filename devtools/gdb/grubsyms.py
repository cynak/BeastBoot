#!/usr/bin/env python3
"""GRUB debug-symbol helpers that need no gdb (stdlib only).

Used by bbgrub.py (inside gdb), by `bb-dev gdb` / `bb-dev doctor`, and by
scripts/bootstrap-tools.sh to prove that the debug files (grub-pc-dbg,
grub-efi-amd64-dbg) belong to exactly the GRUB build that we ship:
kernel.exec must have the same code and data as kernel.img, and every
NAME.module the same .text as NAME.mod. A version string can lie (or two
builds can share one); identical code cannot.

Command line:
  grubsyms.py verify DBG_DIR MOD_DIR [--all] [--quiet]
      exit 0 if the debug files match the modules, 1 on any mismatch,
      2 if files are missing.
  grubsyms.py pe-sections FILE.efi
      print the PE sections of an EFI image (name, RVA, size).
"""

from __future__ import annotations

import os
import struct
import sys

SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Modules compared by a quick (non --all) verify: the kernel plus modules
# whose functions people usually break on.
QUICK_MODULES = ("normal", "linux", "loopback", "iso9660", "fat", "configfile", "search")


class ElfSection:
    __slots__ = ("addr", "align", "flags", "index", "name", "offset", "size", "type")

    def __init__(self, index, name, type_, flags, addr, offset, size, align):
        self.index = index
        self.name = name
        self.type = type_
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.align = align

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def exec(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    def __repr__(self):
        return f"ElfSection({self.index}, {self.name!r}, size={self.size:#x})"


def _read(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def parse_elf_sections(data: bytes, what: str = "ELF file") -> list[ElfSection]:
    """Section headers (with names) of a little-endian ELF32/ELF64 image."""
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{what}: not an ELF file")
    if data[5] != 1:
        raise ValueError(f"{what}: not little-endian")
    if data[4] == 2:
        (shoff,) = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        fmt = "<IIQQQQIIQQ"
    elif data[4] == 1:
        (shoff,) = struct.unpack_from("<I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        fmt = "<IIIIIIIIII"
    else:
        raise ValueError(f"{what}: unknown ELF class {data[4]}")
    if shoff == 0 or shnum == 0:
        return []
    raw = [struct.unpack_from(fmt, data, shoff + i * shentsize) for i in range(shnum)]
    str_off = raw[shstrndx][4] if shstrndx < shnum else 0

    def name_at(off: int) -> str:
        start = str_off + off
        end = data.index(b"\0", start)
        return data[start:end].decode("ascii", "replace")

    # raw: name, type, flags, addr, offset, size, link, info, addralign, entsize
    return [ElfSection(i, name_at(r[0]), r[1], r[2], r[3], r[4], r[5], r[8]) for i, r in enumerate(raw)]


def elf_sections(path) -> list[ElfSection]:
    return parse_elf_sections(_read(path), str(path))


def elf_section_bytes(path, name: str, data: bytes | None = None) -> bytes | None:
    """Contents of section NAME (None if absent or NOBITS)."""
    data = _read(path) if data is None else data
    for s in parse_elf_sections(data, str(path)):
        if s.name == name and s.type != SHT_NOBITS:
            return data[s.offset:s.offset + s.size]
    return None


def section_names(path) -> dict[int, str]:
    """{section index: name} - GRUB's grub_dl_segment.section indexes the stripped .mod."""
    return {s.index: s.name for s in elf_sections(path)}


def alignup(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) // align * align


# ---------------------------------------------------------------------------
# EFI: where grub-mkimage puts kernel.exec's sections inside the PE image
# ---------------------------------------------------------------------------

EFI_PAGE = 4096


def efi_kernel_layout(kernel_exec, text_addr: int) -> dict[str, int]:
    """Run-time address of each allocated section of x86_64-efi kernel.exec.

    Mirrors locate_sections() in GRUB's util/grub-mkimagexx.c: first the
    executable sections (PE .text), then, from the next page on (PE .data),
    the allocated PROGBITS sections, then the NOBITS ones (.bss) - each pass
    in ELF order, each section at its own alignment. (GRUB's gdb_helper.py
    keeps .bss in ELF order instead, which puts grub_dl_head and the other
    .bss variables at the wrong address for 2.14's kernel.exec.)
    """
    secs = [s for s in elf_sections(kernel_exec) if s.alloc]
    out: dict[str, int] = {}
    off = 0
    for s in secs:
        if s.exec:
            off = alignup(off, s.align)
            out[s.name] = text_addr + off
            off += s.size
    data_base = text_addr + alignup(off, EFI_PAGE)
    off = 0
    for nobits in (False, True):
        for s in secs:
            if s.exec or (s.type == SHT_NOBITS) != nobits:
                continue
            off = alignup(off, s.align)
            out[s.name] = data_base + off
            off += s.size
    out["__pe_data__"] = data_base
    return out


SHT_RELA = 4
SHT_REL = 9
# x86_64 relocation types and the number of bytes each one patches
_X86_64_RELOC_SIZE = {1: 8, 2: 4, 4: 4, 10: 4, 11: 4, 24: 8, 9: 4, 26: 4, 41: 4, 42: 4}
_I386_RELOC_SIZE = {1: 4, 2: 4, 4: 4}


def text_signature(elf_path, length: int = 256) -> tuple[bytes, bytes]:
    """(bytes, mask) of the first LENGTH bytes of .text, with every byte a
    relocation patches masked out (mask 0x00), so the result can be compared
    with the relocated code in memory."""
    data = _read(elf_path)
    secs = parse_elf_sections(data, str(elf_path))
    text = next(s for s in secs if s.name == ".text")
    length = min(length, text.size)
    code = data[text.offset:text.offset + length]
    mask = bytearray(b"\xff" * length)
    is64 = data[4] == 2
    sizes = _X86_64_RELOC_SIZE if is64 else _I386_RELOC_SIZE
    for s in secs:
        if s.type not in (SHT_RELA, SHT_REL):
            continue
        # sh_info of a relocation section = index of the section it patches
        hdr_fmt, ent_fmt = ("<IIQQQQIIQQ", "<QQ") if is64 else ("<IIIIIIIIII", "<II")
        shoff = struct.unpack_from("<Q", data, 0x28)[0] if is64 else struct.unpack_from("<I", data, 0x20)[0]
        shentsize = struct.unpack_from("<H", data, 0x3A if is64 else 0x2E)[0]
        raw = struct.unpack_from(hdr_fmt, data, shoff + s.index * shentsize)
        if raw[7] != text.index:
            continue
        entsize = raw[9] or (24 if is64 else 8)
        for off in range(s.offset, s.offset + s.size, entsize):
            r_offset, r_info = struct.unpack_from(ent_fmt, data, off)
            rtype = (r_info & 0xFFFFFFFF) if is64 else (r_info & 0xFF)
            n = sizes.get(rtype, 8 if is64 else 4)
            for i in range(r_offset, min(r_offset + n, length)):
                mask[i] = 0
    return code, bytes(mask)


def matches_signature(mem: bytes, sig: tuple[bytes, bytes]) -> bool:
    code, mask = sig
    if len(mem) < len(code):
        return False
    return all((m & mk) == (c & mk) for m, c, mk in zip(mem, code, mask))


def efi_add_symbol_file_cmd(kernel_exec, text_addr: int) -> str:
    layout = efi_kernel_layout(kernel_exec, text_addr)
    parts = [f"add-symbol-file {kernel_exec} -s .text {layout['.text']:#x}"]
    for name, addr in layout.items():
        if name not in (".text", "__pe_data__"):
            parts.append(f"-s {name} {addr:#x}")
    return " ".join(parts)


def parse_pe_sections(data: bytes) -> tuple[dict, list[dict]]:
    """(header info, sections) of a PE32+ image (file or in-memory headers)."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    (lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature)")
    coff = lfanew + 4
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    entry, = struct.unpack_from("<I", data, opt + 16)
    size_of_image, = struct.unpack_from("<I", data, opt + 56)
    info = {"machine": machine, "magic": magic, "entry_rva": entry, "size_of_image": size_of_image}
    sections = []
    sh = opt + opt_size
    for i in range(nsec):
        name, vsize, va, rawsize, rawptr = struct.unpack_from("<8sIIII", data, sh + i * 40)
        sections.append({"name": name.rstrip(b"\0").decode("ascii", "replace"),
                         "vsize": vsize, "rva": va, "rawsize": rawsize, "rawptr": rawptr})
    return info, sections


# ---------------------------------------------------------------------------
# Verification: do the debug files belong to the shipped modules?
# ---------------------------------------------------------------------------

def verify(dbg_dir, mod_dir, all_modules: bool = False) -> tuple[list[str], list[str]]:
    """Compare debug files with the modules. Returns (problems, missing)."""
    dbg_dir, mod_dir = str(dbg_dir), str(mod_dir)
    problems: list[str] = []
    missing: list[str] = []
    kexec = os.path.join(dbg_dir, "kernel.exec")
    kimg = os.path.join(mod_dir, "kernel.img")
    for p in (kexec, kimg):
        if not os.path.isfile(p):
            missing.append(p)
    if not missing:
        a, b = _read(kexec), _read(kimg)
        for sec in (".text", ".data"):
            x = elf_section_bytes(kexec, sec, a)
            y = elf_section_bytes(kimg, sec, b)
            if x is None or y is None or x != y:
                problems.append(f"kernel.exec {sec} differs from {kimg}")
    if all_modules and os.path.isdir(mod_dir):
        names = sorted(f[:-4] for f in os.listdir(mod_dir) if f.endswith(".mod"))
    else:
        names = list(QUICK_MODULES)
    for name in names:
        module = os.path.join(dbg_dir, f"{name}.module")
        mod = os.path.join(mod_dir, f"{name}.mod")
        if not os.path.isfile(mod):
            continue  # module not built for this platform
        if not os.path.isfile(module):
            missing.append(module)
            continue
        if elf_section_bytes(module, ".text") != elf_section_bytes(mod, ".text"):
            problems.append(f"{name}.module .text differs from {mod}")
    return problems, missing


def _main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "verify":
        all_modules = "--all" in argv
        quiet = "--quiet" in argv
        problems, missing = verify(argv[1], argv[2], all_modules)
        for m in missing:
            print(f"missing: {m}", file=sys.stderr)
        for p in problems:
            print(f"MISMATCH: {p}", file=sys.stderr)
        if not quiet and not problems and not missing:
            print(f"ok: debug files in {argv[1]} match {argv[2]}")
        return 1 if problems else (2 if missing else 0)
    if len(argv) == 2 and argv[0] == "pe-sections":
        info, secs = parse_pe_sections(_read(argv[1]))
        print(f"entry_rva={info['entry_rva']:#x} size_of_image={info['size_of_image']:#x}")
        for s in secs:
            print(f"{s['name']:<8} rva={s['rva']:#x} vsize={s['vsize']:#x}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
