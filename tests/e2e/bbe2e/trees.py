"""Data-partition trees for the base test images, and what the menu must list."""

from __future__ import annotations

from pathlib import Path

RECIPE_DIR = "/recipes"
SPACES_ISO = "/Some Folder/My Distro.iso"


def recipe_path(fixture: str) -> str:
    return f"{RECIPE_DIR}/{fixture}.iso"


def main_tree(isos: dict[str, Path]) -> dict:
    """Everything: all recipe fixtures, a name with spaces, case variants and hidden things."""
    tree: dict = {
        # Hidden by name (layout.DATA_HIDDEN_DIRS), each with an ISO inside to be sure.
        "/beast-booter/hidden-inside.iso": isos["casper"],
        "/System Volume Information/IndexerVolumeGuid": b"{00000000-0000-0000-0000-000000000000}\n",
        "/System Volume Information/hidden.iso": isos["casper"],
        "/$RECYCLE.BIN/desktop.ini": b"[.ShellClassInfo]\n",
        "/$RECYCLE.BIN/hidden.iso": isos["casper"],
        "/lost+found/hidden.iso": isos["casper"],
        # Hidden because of the leading dot.
        "/.Trash-1000/files/trashed.iso": isos["casper"],
        "/._AppleDouble.iso": b"\0" * 4096,
        # Not ISOs.
        "/README.txt": b"beast-booter e2e test drive\n",
        "/not-an-iso.iso.txt": b"x\n",
        # Listed.
        SPACES_ISO: isos["casper"],
        "/UPPER-CASE.ISO": isos["casper"],
        "/Mixed.Iso": isos["live-boot"],
    }
    for name, path in isos.items():
        tree[recipe_path(name)] = path
    return tree


MAIN_ROOT_DIRS = {"/recipes", "/Some Folder"}
MAIN_ROOT_ISOS = {"/UPPER-CASE.ISO", "/Mixed.Iso"}
MAIN_HIDDEN = {
    "/beast-booter", "/System Volume Information", "/$RECYCLE.BIN", "/lost+found", "/.Trash-1000",
    "/._AppleDouble.iso", "/README.txt", "/not-an-iso.iso.txt",
}


def browse_tree(isos: dict[str, Path]) -> dict:
    """Minimal tree for the interactive test: exactly one dir and one ISO at the root."""
    return {
        "/linux/nested.iso": isos["casper"],
        "/top.iso": isos["live-boot"],
        "/beast-booter/": None,  # hidden; config.cfg is written per test
    }


EXFAT_ADDON_PATH = "/linux/ubuntu-layered.iso"


def exfat_tree(isos: dict[str, Path]) -> dict:
    """browse_tree plus an Ubuntu-style ISO whose squashfs carries exfat.ko
    (the root listing stays exactly `linux/` and `top.iso`)."""
    tree = browse_tree(isos)
    tree[EXFAT_ADDON_PATH] = isos["ubuntu-layered"]
    return tree


BROWSE_DIR_TITLE = "linux/"
BROWSE_ROOT_ISO = "top.iso"
BROWSE_NESTED_ISO = "nested.iso"
BROWSE_NESTED_PATH = "/linux/nested.iso"
