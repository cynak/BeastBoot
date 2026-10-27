"""Stand-in boot images for the harness self-test (no dist/ or installer needed).

* EFI stub: grub-mkstandalone x86_64-efi with a menu that speaks the BEAST:
  protocol (ready line, a "linux/" directory entry, ISO entries), on a FAT ESP.
* BIOS stub: grub-mkimage i386-pc core.img with the same menu in a memdisk,
  written to a disk image exactly the way ARCHITECTURE §3 says the installer
  writes boot code (boot.img at LBA 0, core.img at LBA 1, the layout.py patch
  points). So this also checks those patch points boot under SeaBIOS.
* Secure Boot stub: Debian's Microsoft-signed shim + MokManager (the ones
  build/build.sh ships, build/shim/debian-shim.lock) + a GRUB with
  every module built in, SBAT copied from Ubuntu's signed GRUB, signed with a
  throwaway key generated here. Its menu reports `sb=` from GRUB's lockdown
  state and then tries to chainload the unsigned fixture payload.

The throwaway key only ever lands in a per-VM copy of the OVMF variable store.
"""

from __future__ import annotations

import io
import struct
import sys
import tarfile
from pathlib import Path

from . import env

STUB_MENU = r"""
serial --unit=0 --speed=115200
terminal_input --append serial
terminal_output --append serial
echo "BEAST: ready version=selftest platform=${grub_platform} sb=0 esp=stub data=stub fs=none"
echo "BEAST: dryrun linux (loop)/casper/vmlinuz boot=casper iso-scan/filename=/a/rather/long/path/to/an/image/file-name.iso quiet splash ---"
echo "BEAST: dir /"
echo "BEAST: item dir /linux"
echo "BEAST: item iso /top.iso"
menuentry "linux/" {
  configfile $prefix/linux.cfg
}
menuentry "top.iso" {
  echo "BEAST: boot /top.iso recipe=selftest"
}
menuentry "Power off" {
  halt
}
"""

STUB_SUBMENU = r"""
echo "BEAST: dir /linux"
echo "BEAST: item iso /linux/nested.iso"
menuentry ".." {
  configfile $prefix/grub.cfg
}
menuentry "nested.iso" {
  echo "BEAST: boot /linux/nested.iso recipe=selftest"
}
"""

SB_STUB_CFG = r"""
serial --unit=0 --speed=115200
terminal_input --append serial
terminal_output --append serial
if [ "$lockdown" = "y" ]; then set sb=1; else set sb=0; fi
echo "BEAST: ready version=selftest platform=${grub_platform} sb=${sb} esp=stub data=stub fs=none"
search --no-floppy --file --set=payload_dev /unsigned.efi
if chainloader ($payload_dev)/unsigned.efi; then
  boot
  echo "BEAST: error boot-failed the chainloaded image returned"
else
  echo "BEAST: error sb-verify-failed chainloader refused /unsigned.efi"
fi
sleep 2
halt
"""

SB_STUB_MODULES = [
    "part_msdos", "part_gpt", "fat", "normal", "echo", "serial", "terminfo", "terminal", "memdisk",
    "tar", "configfile", "test", "chain", "search", "search_fs_file", "halt", "sleep", "efi_gop",
]
STUB_BIOS_MODULES = [
    "biosdisk", "part_msdos", "memdisk", "tar", "normal", "serial", "terminfo", "terminal", "echo",
    "halt", "configfile", "test", "sleep",
]


def _memdisk_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1760000000
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _fat_image(path: Path, files: dict[str, Path | bytes], size_mib: int = 32) -> Path:
    """Disk image with one MBR partition (type 0xEF at 1 MiB) holding a FAT16 filesystem.

    (OVMF does not find the boot file on a partitionless USB "superfloppy".)
    """
    path = Path(path)
    fat = path.with_name(path.name + ".part")
    for p in (path, fat):
        if p.exists():
            p.unlink()
    env.run(["mkfs.fat", "-C", "-F", "16", "-n", "STUBESP", str(fat), str(size_mib * 1024)])
    made = set()
    for dest in files:
        parts = dest.strip("/").split("/")[:-1]
        for i in range(1, len(parts) + 1):
            d = "/" + "/".join(parts[:i])
            if d not in made:
                env.run(["mmd", "-i", str(fat), f"::{d}"])
                made.add(d)
    for dest, src in files.items():
        if isinstance(src, (bytes, bytearray)):
            tmp = path.with_name(path.name + ".tmpfile")
            tmp.write_bytes(src)
            env.run(["mcopy", "-o", "-i", str(fat), str(tmp), f"::{dest}"])
            tmp.unlink()
        else:
            env.run(["mcopy", "-o", "-i", str(fat), str(src), f"::{dest}"])
    start = 2048
    sectors = fat.stat().st_size // 512
    entry = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0xEF, b"\0\0\0", start, sectors)
    with open(path, "wb") as out, open(fat, "rb") as src:
        out.truncate((start + sectors + 2048) * 512)
        out.seek(446)
        out.write(entry)
        out.seek(510)
        out.write(b"\x55\xaa")
        pos = start * 512
        while chunk := src.read(1 << 16):
            if chunk.count(0) != len(chunk):  # keep the image sparse
                out.seek(pos)
                out.write(chunk)
            pos += len(chunk)
    fat.unlink()
    return path


def build_efi_stub(out: Path) -> Path:
    """FAT ESP image (superfloppy) whose BOOTX64.EFI is the stub menu."""
    out.mkdir(parents=True, exist_ok=True)
    cfg = out / "stub-grub.cfg"
    sub = out / "stub-linux.cfg"
    cfg.write_text(STUB_MENU)
    sub.write_text(STUB_SUBMENU)
    efi = out / "stub-menu.efi"
    env.run([
        "grub-mkstandalone", "-O", "x86_64-efi", "-d", str(env.GRUB_EFI_DIR), "-o", str(efi),
        "--install-modules=normal echo serial terminfo terminal halt configfile test sleep",
        "--modules=serial terminfo echo", "--locales=", "--fonts=", "--themes=",
        f"boot/grub/grub.cfg={cfg}", f"boot/grub/linux.cfg={sub}",
    ])
    return _fat_image(out / "stub-efi.img", {"/EFI/BOOT/BOOTX64.EFI": efi})


def _layout():
    sys.path.insert(0, str(env.INSTALLER_DIR))
    try:
        from beastbooter import layout  # the layout contract (exists from day one)
    finally:
        sys.path.pop(0)
    return layout


def write_bios_boot_code(image: Path, boot_img: bytes, core_img: bytes, core_lba: int) -> None:
    """Write GRUB boot.img + core.img as ARCHITECTURE §3 specifies (MBR layout)."""
    L = _layout()
    core = bytearray(core_img)
    if len(core) % L.SECTOR_SIZE:
        core += b"\0" * (L.SECTOR_SIZE - len(core) % L.SECTOR_SIZE)
    sectors = len(core) // L.SECTOR_SIZE
    if sectors > L.MBR_CORE_MAX_SECTORS:
        raise ValueError(f"core.img too large: {sectors} sectors")
    boot = bytearray(boot_img[: L.BOOT_IMG_SIZE])
    struct.pack_into("<Q", boot, L.BOOT_KERNEL_SECTOR_OFFSET, core_lba)
    boot[L.BOOT_DRIVE_CHECK_OFFSET : L.BOOT_DRIVE_CHECK_OFFSET + 2] = b"\x90\x90"
    struct.pack_into("<QHH", core, L.CORE_BLOCKLIST_OFFSET, core_lba + 1, sectors - 1, L.CORE_BLOCKLIST_SEGMENT)
    with open(image, "r+b") as f:
        f.seek(0)
        f.write(boot[: L.BOOT_IMG_CODE_LEN])
        f.seek(510)
        f.write(b"\x55\xaa")
        f.seek(core_lba * L.SECTOR_SIZE)
        f.write(core)


def build_bios_stub(out: Path) -> Path:
    """Raw disk image: boot.img + core.img (stub menu in a memdisk) in the MBR gap."""
    L = _layout()
    out.mkdir(parents=True, exist_ok=True)
    tar = out / "stub-memdisk.tar"
    tar.write_bytes(_memdisk_tar({"boot/grub/grub.cfg": STUB_MENU, "boot/grub/linux.cfg": STUB_SUBMENU}))
    early = out / "stub-early.cfg"
    early.write_text("set root=(memdisk)\nset prefix=(memdisk)/boot/grub\n")
    core = out / "stub-core.img"
    env.run([
        "grub-mkimage", "-O", "i386-pc", "-d", str(env.GRUB_BIOS_DIR), "-o", str(core),
        "-p", "(memdisk)/boot/grub", "-c", str(early), "-m", str(tar), *STUB_BIOS_MODULES,
    ])
    disk = out / "stub-bios.img"
    with open(disk, "wb") as f:
        f.truncate(16 * 1024 * 1024)
    write_bios_boot_code(disk, (env.GRUB_BIOS_DIR / "boot.img").read_bytes(), core.read_bytes(), L.MBR_CORE_LBA)
    return disk


def extract_sbat(pe: Path) -> bytes:
    """Contents of the .sbat section of a PE image."""
    data = pe.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError(f"{pe}: not a PE image")
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size
    for i in range(nsec):
        s = data[sec + 40 * i : sec + 40 * (i + 1)]
        name = s[:8].rstrip(b"\0")
        vsize, _vaddr, rawsize, rawptr = struct.unpack_from("<IIII", s, 8)
        if name == b".sbat":
            return data[rawptr : rawptr + min(vsize, rawsize)].rstrip(b"\0")
    raise ValueError(f"{pe}: no .sbat section")


def sb_stub_status() -> tuple[bool, str]:
    need = {
        "shim": env.SHIM_DIR / "shimx64.efi.signed",
        "MokManager": env.SHIM_DIR / "mmx64.efi.signed",
        "Ubuntu signed GRUB (for its SBAT)": env.GRUB_EFI_SIGNED_DIR / "grubx64.efi.signed",
        "OVMF secboot code": env.OVMF_CODE_SECBOOT,
        "OVMF MS vars": env.OVMF_VARS_MS,
    }
    missing = [f"{k} ({v})" for k, v in need.items() if not v.exists()]
    for tool in ("openssl", "sbsign", "virt-fw-vars", "grub-mkimage", "mkfs.fat", "mcopy"):
        if not env.which(tool):
            missing.append(tool)
    if missing:
        return False, "Secure Boot self-test needs: " + ", ".join(missing)
    return True, ""


def build_sb_stub(out: Path, payload: Path) -> dict[str, Path]:
    """-> {"esp": shim+signed stub ESP image, "cert": throwaway DER cert,
           "unsigned_esp": ESP whose BOOTX64.EFI is the unsigned payload}"""
    out.mkdir(parents=True, exist_ok=True)
    key, crt, cer = out / "throwaway.key", out / "throwaway.crt", out / "throwaway.cer"
    if not (key.exists() and crt.exists() and cer.exists()):
        env.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
                 "-subj", "/CN=beast-boot e2e self-test (throwaway, not for real use)/",
                 "-keyout", str(key), "-out", str(crt)])
        env.run(["openssl", "x509", "-in", str(crt), "-outform", "DER", "-out", str(cer)])
    sbat = out / "sbat.csv"
    sbat.write_bytes(extract_sbat(env.GRUB_EFI_SIGNED_DIR / "grubx64.efi.signed") + b"\n")
    tar = out / "sb-memdisk.tar"
    tar.write_bytes(_memdisk_tar({"boot/grub/grub.cfg": SB_STUB_CFG}))
    early = out / "sb-early.cfg"
    early.write_text("set root=(memdisk)\nset prefix=(memdisk)/boot/grub\n")
    unsigned = out / "sb-stub.unsigned.efi"
    env.run([
        "grub-mkimage", "-O", "x86_64-efi", "-d", str(env.GRUB_EFI_DIR), "-o", str(unsigned),
        "-p", "(memdisk)/boot/grub", "-c", str(early), "-m", str(tar), "--sbat", str(sbat), *SB_STUB_MODULES,
    ])
    signed = out / "sb-stub.signed.efi"
    env.run(["sbsign", "--key", str(key), "--cert", str(crt), "--output", str(signed), str(unsigned)])
    esp = _fat_image(out / "sb-esp.img", {
        "/EFI/BOOT/BOOTX64.EFI": env.SHIM_DIR / "shimx64.efi.signed",
        "/EFI/BOOT/mmx64.efi": env.SHIM_DIR / "mmx64.efi.signed",
        "/EFI/BOOT/grubx64.efi": signed,
        "/unsigned.efi": payload,
    })
    unsigned_esp = _fat_image(out / "unsigned-esp.img", {"/EFI/BOOT/BOOTX64.EFI": payload}, size_mib=16)
    return {"esp": esp, "cert": cer, "unsigned_esp": unsigned_esp}
