"""Missing-firmware detection and the firmware pack catalog (BEASTNET.md section 6).

The kernel logs a line when a driver asks for a firmware file that is not in
/lib/firmware. We read the kernel log, find those lines, work out the kernel
module behind the device, and look the module (or the file) up in
``ESP:/beast-net/catalog.json`` to tell the user which pack to install.
"""

from __future__ import annotations

import errno
import json
import os
import re
import subprocess
from dataclasses import dataclass, field

# "<driver> <device>: <message>" -- the dev_printk() prefix.
_PREFIX = r"(?P<drv>[A-Za-z0-9_.-]+) (?P<dev>[^\s:]+(?::[^\s:]+)*): "
_PATTERNS = [
    re.compile(_PREFIX + r"Direct firmware load for (?P<fw>\S+) failed with error (?P<err>-?\d+)"),
    re.compile(_PREFIX + r"firmware: failed to load (?P<fw>\S+) \((?P<err>-?\d+)\)"),
    # iwlwifi tries several versions quietly and then says this:
    re.compile(_PREFIX + r"no suitable firmware found!?"),
    re.compile(_PREFIX + r"maximum version supported: (?P<fw>\S+)"),
    # r8169 and friends: "Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)"
    re.compile(_PREFIX + r"[Uu]nable to load firmware (?:patch )?(?P<fw>\S+)"),
    re.compile(_PREFIX + r"[Ff]ailed to (?:load|request) firmware[: ]*(?P<fw>[A-Za-z][\w./-]*)?"),
]
_KMSG_PREFIX = re.compile(r"^\d+,\d+,\d+,[^;]*;")
_DMESG_PREFIX = re.compile(r"^(?:<\d+>)?\[\s*\d+\.\d+\]\s*")


@dataclass
class FirmwareFailure:
    driver: str  # driver name from the log line
    device: str  # e.g. "0000:00:14.3", "1-1:1.0", "mmc1:0001:1"
    files: list[str] = field(default_factory=list)


@dataclass
class Pack:
    id: str
    title: str
    modules: list[str]
    files: list[str]
    size: int | None = None


@dataclass
class Catalog:
    packs: list[Pack] = field(default_factory=list)
    tag: str = ""

    def by_id(self, pack_id: str) -> Pack | None:
        for p in self.packs:
            if p.id == pack_id:
                return p
        return None

    def find(self, module: str | None, files: list[str]) -> Pack | None:
        """The pack holding one of ``files``, else the one listing ``module``."""
        wanted = {_strip_compression(f) for f in files}
        for p in self.packs:
            have = {_strip_compression(f) for f in p.files}
            for w in wanted:
                # iwlwifi logs a name without extension ("iwlwifi-so-a0-gf-a0-89")
                if any(h == w or h.startswith(w + ".") for h in have):
                    return p
        if module:
            m = _norm(module)
            for p in self.packs:
                if m in (_norm(x) for x in p.modules):
                    return p
        return None


def _norm(module: str) -> str:
    return module.replace("-", "_")


def _strip_compression(path: str) -> str:
    for ext in (".zst", ".xz"):
        if path.endswith(ext):
            return path[: -len(ext)]
    return path


def load_catalog(path: str) -> Catalog:
    """Load catalog.json; a missing or broken catalog is an empty one."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return Catalog()
    packs = []
    for p in data.get("packs", []) if isinstance(data, dict) else []:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        packs.append(Pack(
            id=str(p["id"]),
            title=str(p.get("title") or p["id"]),
            modules=[str(m) for m in p.get("modules", []) if m],
            files=[str(f.get("path")) for f in p.get("files", []) if isinstance(f, dict) and f.get("path")],
            size=p.get("size") if isinstance(p.get("size"), int) else None,
        ))
    tag = ""
    if isinstance(data, dict) and isinstance(data.get("source"), dict):
        tag = str(data["source"].get("tag") or "")
    return Catalog(packs, tag)


def installed_packs(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    return [str(p["id"]) for p in data.get("packs", []) if isinstance(p, dict) and p.get("id")]


def read_kernel_log(path: str | None = None, dev_dir: str = "/dev") -> str:
    """The kernel log: from ``path`` (tests), else /dev/kmsg, else ``dmesg``."""
    if path:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""
    lines: list[str] = []
    try:
        fd = os.open(os.path.join(dev_dir, "kmsg"), os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        fd = -1
    if fd >= 0:
        try:
            while True:
                try:
                    rec = os.read(fd, 8192)
                except OSError as e:
                    if e.errno == errno.EAGAIN:
                        break
                    if e.errno == errno.EPIPE:  # overwritten while reading: skip
                        continue
                    raise
                if not rec:
                    break
                lines.append(rec.decode("utf-8", "replace").split("\n", 1)[0])
        except OSError:
            pass
        finally:
            os.close(fd)
        if lines:
            return "\n".join(lines) + "\n"
    try:
        return subprocess.run(["dmesg"], capture_output=True, text=True, timeout=10,
                              errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_firmware_failures(log: str) -> list[FirmwareFailure]:
    """Firmware load failures per device, in log order."""
    by_dev: dict[tuple[str, str], FirmwareFailure] = {}
    for raw in log.splitlines():
        line = _DMESG_PREFIX.sub("", _KMSG_PREFIX.sub("", raw.strip()))
        for pat in _PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            key = (m.group("drv"), m.group("dev"))
            ff = by_dev.setdefault(key, FirmwareFailure(*key))
            fw = m.groupdict().get("fw")
            if fw and fw not in ff.files:
                ff.files.append(fw)
            break
    return list(by_dev.values())
