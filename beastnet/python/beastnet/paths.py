"""Where things live. Every path can be redirected for host testing (--root & co)."""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass

DEFAULT_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
RELEASE_MARKER = "etc/beast-net-release"  # present only inside the beast-net initramfs
DOWNLOADS = "/downloads"


@dataclass
class Paths:
    root: str = "/"
    proc: str = ""
    sys: str = ""
    dev: str = ""
    run: str = ""  # our scratch directory (wpa_supplicant config, sockets, logs)
    etc: str = ""
    data: str = ""  # data partition mount point
    esp: str = ""  # ESP mount point
    cmdline: str = ""
    kernel_log: str | None = None  # a file with the kernel log; None = /dev/kmsg, then dmesg
    ca_file: str = DEFAULT_CA_FILE
    dhcp_script: str = ""

    def __post_init__(self) -> None:
        r = self.root

        def under(p: str) -> str:
            return os.path.join(r, p.lstrip("/"))

        self.proc = self.proc or under("proc")
        self.sys = self.sys or under("sys")
        self.dev = self.dev or under("dev")
        self.run = self.run or under("run/beastnet")
        self.etc = self.etc or under("etc")
        self.data = self.data or under("mnt/data")
        self.esp = self.esp or under("mnt/esp")
        self.cmdline = self.cmdline or os.path.join(self.proc, "cmdline")
        self.dhcp_script = self.dhcp_script or under("usr/share/beastnet/udhcpc.script")

    # Files on the ESP (BEASTNET.md section 3).
    @property
    def grubenv(self) -> str:
        return os.path.join(self.esp, "grub", "grubenv")

    @property
    def catalog(self) -> str:
        return os.path.join(self.esp, "beast-net", "catalog.json")

    @property
    def installed(self) -> str:
        return os.path.join(self.esp, "beast-net", "firmware", "installed.json")

    @property
    def resolv_conf(self) -> str:
        return os.path.join(self.etc, "resolv.conf")

    def is_beast_net(self) -> bool:
        """True inside the real beast-net initramfs (not on a developer's host)."""
        return os.path.exists(os.path.join(self.root, RELEASE_MARKER))

    def data_local(self, data_path: str) -> str:
        """Map a path on the data partition ("/downloads/x.iso") to the local file."""
        clean = normalize_data_path(data_path)
        return os.path.join(self.data, clean.lstrip("/"))


def normalize_data_path(data_path: str, *, under: str | None = None) -> str:
    """Normalise a path on the data partition and refuse anything that escapes it.

    Returns an absolute POSIX path ("/downloads/x.iso"). With ``under``, the path
    must also be inside that directory. Raises ValueError otherwise.
    """
    if not data_path or "\0" in data_path or "\\" in data_path:
        raise ValueError(f"invalid path {data_path!r}")
    if not data_path.startswith("/"):
        data_path = "/" + data_path
    parts = []
    for part in data_path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError(f"path {data_path!r} leaves the data partition")
        parts.append(part)
    clean = "/" + "/".join(parts)
    if under is not None:
        base = posixpath.normpath(under)
        if clean != base and not clean.startswith(base.rstrip("/") + "/"):
            raise ValueError(f"path {clean!r} is not under {base}")
    return clean
