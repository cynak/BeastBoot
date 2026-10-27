"""The user configuration /beast-booter/config.cfg (docs/MENU.md).

It is GRUB script. bb-dev only rewrites `set KEY=...` and `export KEY`
lines of the keys it is asked to change; every other line (comments, other
commands, other settings) is kept verbatim. Values are written double-quoted
and exported, so they also apply inside folder menus (browse.cfg runs with
`configfile`, a new variable context).
"""

from __future__ import annotations

import re

from .msg import Failure

HEADER = "# beast-boot user configuration (docs/MENU.md), written by bb-dev"

# key -> (kind, help)
KNOWN = {
    "bb_debug": ("bool", "print machine-readable BEAST: lines"),
    "bb_dryrun": ("bool", "do everything except the final hand-off, then return to the menu"),
    "bb_autoboot": ("path", "skip the menu and boot this ISO (path on the data partition)"),
    "bb_serial": ("bool", "mirror the menu on serial port 0 (115200 8N1)"),
    "timeout": ("int", "GRUB menu timeout in seconds (-1 = wait)"),
    "debug": ("text", "GRUB's own debug facilities, e.g. linux,loader or all"),
    "pager": ("bool", "GRUB pager: pause after each screen of output"),
    "bb_gfx": ("bool", "graphical themed menu (0 = plain text menu)"),
    "bb_gfxmode": ("text", "screen mode list for the graphical menu, e.g. 1280x720,auto"),
    "bb_theme": ("path", "your own GRUB theme.txt on the data partition"),
    "bb_beastnet_script": ("path", "run the network helper with this JSON plan (path on the data partition)"),
}

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_SET_RE = re.compile(rf'^\s*set\s+({_NAME})=(.*)$')
_EXPORT_RE = re.compile(rf'^\s*export((?:\s+{_NAME})+)\s*(#.*)?$')
_TRUE = {"1", "on", "yes", "true", "y"}
_FALSE = {"0", "off", "no", "false", "n"}


def grub_quote(value: str) -> str:
    return '"' + re.sub(r'([\\"$])', r"\\\1", value) + '"'


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', raw)
        if m:
            return re.sub(r"\\(.)", r"\1", m.group(1))
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end > 0:
            return raw[1:end]
    return re.split(r"\s|;|#", raw, maxsplit=1)[0]


def normalise(key: str, value: str) -> str:
    """Validate a KEY=VALUE pair and return the value to write."""
    if not re.fullmatch(_NAME, key):
        raise Failure(f"invalid setting name {key!r}")
    if "\n" in value or "\r" in value:
        raise Failure(f"{key}: value must be a single line")
    kind = KNOWN.get(key, ("text", ""))[0]
    v = value.strip()
    if kind == "bool":
        if v.lower() in _TRUE:
            return "1"
        if v.lower() in _FALSE:
            return "0"
        raise Failure(f"{key} must be 0 or 1, not {value!r}")
    if kind == "int":
        if not re.fullmatch(r"-?\d+", v):
            raise Failure(f"{key} must be a whole number of seconds, not {value!r}")
        return str(int(v))
    if kind == "path":
        if not v:
            raise Failure(f"{key} needs a path, e.g. /linux/ubuntu.iso")
        return v if v.startswith("/") else "/" + v
    return value


def parse_assignment(text: str) -> tuple[str, str]:
    if "=" not in text:
        raise Failure(f"--set needs KEY=VALUE, not {text!r}")
    key, _, value = text.partition("=")
    key = key.strip()
    return key, normalise(key, value)


class UserConfig:
    def __init__(self, text: str = ""):
        self.lines = text.splitlines()
        self.existed = bool(text)

    @property
    def text(self) -> str:
        return "\n".join(self.lines) + "\n" if self.lines else ""

    def settings(self) -> dict[str, str]:
        """`set` assignments in file order (the last one of a key wins)."""
        out: dict[str, str] = {}
        for line in self.lines:
            m = _SET_RE.match(line)
            if m:
                out.pop(m.group(1), None)
                out[m.group(1)] = _unquote(m.group(2))
        return out

    def get(self, key: str) -> str | None:
        return self.settings().get(key)

    def _drop(self, key: str) -> int | None:
        """Remove `set key=` lines and `key` from export lines; return the
        index of the first removed set line."""
        first = None
        kept = []
        for line in self.lines:
            m = _SET_RE.match(line)
            if m and m.group(1) == key:
                if first is None:
                    first = len(kept)
                continue
            e = _EXPORT_RE.match(line)
            if e and key in e.group(1).split():
                names = [n for n in e.group(1).split() if n != key]
                if names:
                    kept.append("export " + " ".join(names) + (f" {e.group(2)}" if e.group(2) else ""))
                continue
            kept.append(line)
        self.lines = kept
        return first

    def set(self, key: str, value: str) -> None:
        value = normalise(key, value)
        at = self._drop(key)
        new = [f"set {key}={grub_quote(value)}", f"export {key}"]
        if at is None:
            if not self.lines:
                self.lines = [HEADER]
            self.lines += new
        else:
            self.lines[at:at] = new

    def unset(self, key: str) -> bool:
        before = list(self.lines)
        self._drop(key)
        return self.lines != before

    def clear(self) -> None:
        self.lines = []

    def is_empty(self) -> bool:
        return not any(line.strip() and line.strip() != HEADER for line in self.lines)


def render(*, debug: bool = False, dryrun: bool = False, autoboot: str | None = None,
           serial: bool = False, extra: dict[str, str] | None = None) -> str:
    """A fresh config.cfg ("" when nothing is set)."""
    cfg = UserConfig()
    if debug:
        cfg.set("bb_debug", "1")
    if dryrun:
        cfg.set("bb_dryrun", "1")
    if autoboot:
        cfg.set("bb_autoboot", autoboot)
    if serial:
        cfg.set("bb_serial", "1")
    for k, v in (extra or {}).items():
        cfg.set(k, v)
    return cfg.text
