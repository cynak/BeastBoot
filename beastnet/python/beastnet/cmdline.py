"""Kernel command line parsing (the beastnet.* parameters of BEASTNET.md section 5)."""

from __future__ import annotations

from dataclasses import dataclass, field

# beastnet.action=: open one of the helper's actions directly (the boot menu's tool entries).
ACTIONS = ("trust-ubuntu", "disk")  # Trust Ubuntu's key (build/trust/README.md); Disk tools


def split_cmdline(text: str) -> list[tuple[str, str | None]]:
    """Split a kernel command line into (name, value) pairs like the kernel does.

    Follows ``next_arg()`` in the kernel's lib/cmdline.c: words are separated
    by whitespace, a double quote toggles quoting anywhere in a word, and one
    pair of quotes around the value (or around the whole word) is removed.
    Everything after a lone ``--`` belongs to init and is not returned.
    """
    out: list[tuple[str, str | None]] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        in_quote = False
        while i < n and (in_quote or not text[i].isspace()):
            if text[i] == '"':
                in_quote = not in_quote
            i += 1
        word = text[start:i]
        if word == "--":
            break
        if word.startswith('"'):
            word = word[1:]
            if word.endswith('"'):
                word = word[:-1]
        name, sep, value = word.partition("=")
        if not sep:
            out.append((name, None))
            continue
        if value.startswith('"'):
            value = value[1:]
            if value.endswith('"'):
                value = value[:-1]
        out.append((name, value))
    return out


@dataclass
class BootParams:
    data: str | None = None  # "UUID=ABCD-1234"
    esp: str | None = None
    sb: bool = False
    debug: bool = False
    script: str | None = None  # path on the data partition
    ui: str | None = None  # "plain" forces the line-based interface (extension)
    action: str | None = None  # one of ACTIONS; anything else is ignored (kept in raw)
    # beastnet.netboot=1: started over the network (BeastServer), not from a stick: no data
    # partition and no ESP; /init mounts small RAM filesystems in their place.
    netboot: bool = False
    server: str | None = None  # beastnet.server=http://host:port (the BeastServer, for display)
    consoles: list[str] = field(default_factory=list)  # console= values, in order
    raw: dict[str, str] = field(default_factory=dict)  # every beastnet.* parameter

    @property
    def serial_console(self) -> str | None:
        """Device name of the first serial console= (``ttyS0``), if any."""
        for c in self.consoles:
            dev = c.split(",", 1)[0]
            if dev.startswith("ttyS") or dev.startswith("ttyUSB") or dev.startswith("ttyAMA"):
                return dev
        return None


def _truthy(value: str | None) -> bool:
    # "beastnet.debug" alone means on; "=0", "=no", "=off", "=false" mean off.
    if value is None:
        return True
    return value.strip().lower() not in ("", "0", "no", "off", "false")


def parse_cmdline(text: str) -> BootParams:
    p = BootParams()
    for name, value in split_cmdline(text):
        if name == "console" and value:
            p.consoles.append(value)
            continue
        if not name.startswith("beastnet."):
            continue
        key = name[len("beastnet."):]
        p.raw[key] = "1" if value is None else value  # last one wins, like the kernel
        if key == "data":
            p.data = value or None
        elif key == "esp":
            p.esp = value or None
        elif key == "sb":
            p.sb = _truthy(value)
        elif key == "debug":
            p.debug = _truthy(value)
        elif key == "script":
            p.script = value or None
        elif key == "ui":
            p.ui = value or None
        elif key == "action":
            p.action = value if value in ACTIONS else None
        elif key == "netboot":
            p.netboot = _truthy(value)
        elif key == "server":
            p.server = value or None
    return p


def netboot(ctx: object) -> bool:
    """True when this run has no BeastBoot stick (``beastnet.netboot=1``): the data
    partition and the ESP are RAM filesystems, so nothing written there survives."""
    return bool(getattr(getattr(ctx, "params", None), "netboot", False))


def read_cmdline(path: str) -> BootParams:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return parse_cmdline(f.read())
    except OSError:
        return BootParams()
