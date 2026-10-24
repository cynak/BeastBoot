"""Assertions shared by the real tests and the harness self-test."""

from __future__ import annotations

import re

from .qemu import VM
from .serial import Record

# The contract's fs vocabulary is bb_data_fs (exfat|fat32|ntfs); accept GRUB's
# own `probe --fs` names too, since §5 does not say which one `ready` prints.
FS_ALIASES = {"fat32": {"fat32", "fat", "vfat"}, "exfat": {"exfat"}, "ntfs": {"ntfs"}}


PLATFORM = {"bios": "pc", "uefi": "efi", "uefi-sb": "efi"}
SB = {"bios": 0, "uefi": 0, "uefi-sb": 1}


def expected_devs(layout: str) -> dict[str, str]:
    """GRUB device names of the ESP and data partition on the (only) disk."""
    return {"esp": f"hd0,{layout}2", "data": f"hd0,{layout}1"}


def dev(s: str) -> str:
    return s.strip().strip("()")


def wait_ready(vm: VM, timeout: float = 90) -> Record:
    return vm.wait_record("ready", timeout=timeout)


def check_ready(rec: Record, *, platform: str, sb: int, esp: str | None = None, data: str | None = None,
                fs: str | None = None, version: str | None = None) -> dict:
    f = rec.fields
    problems = []
    if f.get("platform") != platform:
        problems.append(f"platform={f.get('platform')!r}, expected {platform!r}")
    if f.get("sb") != str(sb):
        problems.append(f"sb={f.get('sb')!r}, expected {sb}")
    if esp is not None and dev(f.get("esp", "")) != esp:
        problems.append(f"esp={f.get('esp')!r}, expected {esp!r}")
    if data is not None and dev(f.get("data", "")) != data:
        problems.append(f"data={f.get('data')!r}, expected {data!r}")
    if fs is not None and f.get("fs") not in FS_ALIASES.get(fs, {fs}):
        problems.append(f"fs={f.get('fs')!r}, expected {fs!r}")
    if version is not None and f.get("version") != version:
        problems.append(f"version={f.get('version')!r}, expected {version!r}")
    assert not problems, f"bad ready line: {rec}\n  " + "\n  ".join(problems)
    return f


def item_path(rec: Record) -> str:
    """`item dir /x` / `item iso /x.iso` -> path (trailing slash dropped, root kept)."""
    m = re.match(r"item (dir|iso) (.+)$", rec.text)
    assert m, f"malformed item line: {rec}"
    p = m.group(2).strip()
    return p.rstrip("/") or "/"


def listing(vm: VM, path: str, *, timeout: float = 60, after: int = 0) -> tuple[list[str], list[str]]:
    """Wait for `dir <path>` and the menu, return (dirs, isos) from the item lines after it."""
    d = vm.wait_record("dir", rf"^dir {re.escape(path)}/?$", timeout=timeout, after=after)
    vm.wait_menu(timeout=timeout)
    dirs, isos = [], []
    for r in vm.records(after=d.end):
        if r.kind == "dir":
            break
        if r.kind == "item":
            (dirs if r.text.startswith("item dir ") else isos).append(item_path(r))
    return dirs, isos


def browse_flow(vm: VM, *, dir_title: str, root_iso: str, nested_iso: str, nested_path: str,
                timeout: float = 60) -> Record:
    """The interactive browse scenario (ARCHITECTURE menu structure contract).

    Root: exactly one directory entry, then one ISO, then tool entries.
    Enter on the first entry opens the directory; there `..` is first and goes
    back; the nested ISO is second; Down + Enter boots it. Returns the boot record.
    """
    vm.wait_record("dir", r"^dir /$", timeout=timeout)
    menu = vm.wait_menu(first_entry=dir_title, timeout=timeout)
    assert menu.entries[:2] == [dir_title, root_iso], f"root menu entries:\n{menu}\n--- screen ---\n{vm.screen.text()}"
    tools = menu.entries[2:]
    assert not [t for t in tools if t.endswith("/") or t.lower().endswith(".iso")], \
        f"root must hold exactly one dir and one ISO before the tool entries:\n{menu}"
    sub = "/" + dir_title.rstrip("/")

    # Enter on the directory -> its listing, with ".." first.
    mark = vm.mark()
    vm.key("enter")
    vm.wait_record("dir", rf"^dir {re.escape(sub)}/?$", timeout=timeout, after=mark)
    menu = vm.wait_menu(first_entry="..", timeout=timeout)
    assert menu.entries[:2] == ["..", nested_iso], f"{sub} menu entries:\n{menu}\n--- screen ---\n{vm.screen.text()}"

    # ".." goes back to the root.
    mark = vm.mark()
    vm.key("enter")
    vm.wait_record("dir", r"^dir /$", timeout=timeout, after=mark)
    vm.wait_menu(first_entry=dir_title, timeout=timeout)

    # Into the directory again, Down to the ISO, Enter.
    mark = vm.mark()
    vm.key("enter")
    vm.wait_record("dir", rf"^dir {re.escape(sub)}/?$", timeout=timeout, after=mark)
    vm.wait_menu(first_entry="..", timeout=timeout)
    mark = vm.mark()
    vm.keys("down", "enter")
    return vm.wait_record("boot", rf"^boot {re.escape(nested_path)} recipe=\S+", timeout=timeout, after=mark)


def recipe_of(rec: Record) -> str:
    m = re.search(r"recipe=(\S+)", rec.text)
    assert m, f"no recipe= in {rec}"
    return m.group(1)
