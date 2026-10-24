"""Read and write the GRUB environment block exactly like GRUB and grub-editenv.

Format (grub-core/lib/envblk.c): the signature line ``# GRUB Environment Block``,
then ``name=value`` lines, then ``#`` padding up to the block size (1024 bytes
for a grubenv file). In a value, ``\\`` and newline are escaped with a
backslash. Lines starting with ``#`` are comments. ``set`` replaces the first
line with that name in place (other lines keep their order) or appends a new
line at the end; ``unset`` removes the first such line. Doing the same here
gives byte-identical results to grub-editenv, which the tests check.

The file is rewritten in place (same size, same clusters on the FAT ESP) and
fsynced: GRUB's ``save_env`` and the installer expect it to stay where it is.
"""

from __future__ import annotations

import os

from .errors import GRUBENV, BeastNetError

SIGNATURE = b"# GRUB Environment Block\n"
SIZE = 1024
ONESHOT_KEY = "bb_oneshot"


def _escape(value: str) -> bytes:
    out = bytearray()
    for ch in value.encode("utf-8"):
        if ch in (0x5C, 0x0A):  # backslash, newline
            out.append(0x5C)
        out.append(ch)
    return bytes(out)


def _unescape(raw: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0x5C and i + 1 < len(raw):
            i += 1
        out.append(raw[i])
        i += 1
    return out.decode("utf-8", "replace")


class GrubEnv:
    """An environment block: a list of lines (name/value pairs or comments)."""

    def __init__(self, data: bytes | None = None, size: int = SIZE) -> None:
        self.size = size
        # Each item: (name, value) for a variable, or (None, raw line bytes) for a comment.
        self._items: list[tuple[str | None, object]] = []
        if data is not None:
            self._parse(data)

    # -- parsing ----------------------------------------------------------
    def _parse(self, data: bytes) -> None:
        if len(data) != self.size:
            raise BeastNetError(GRUBENV, f"environment block is {len(data)} bytes, expected {self.size}")
        if not data.startswith(SIGNATURE):
            raise BeastNetError(GRUBENV, "not a GRUB environment block (bad signature)")
        # Free space = the trailing run of '#' after the last newline (as GRUB computes it).
        end = len(data)
        while end > 0 and data[end - 1] == 0x23:
            end -= 1
        if end < len(SIGNATURE) or data[end - 1] != 0x0A:
            raise BeastNetError(GRUBENV, "GRUB environment block is corrupt (no free space marker)")
        p = len(SIGNATURE)
        while p < end:
            q = p
            while q < end and data[q] != 0x0A:
                q += 2 if data[q] == 0x5C else 1
            line = data[p:min(q, end)]
            if line.startswith(b"#"):
                self._items.append((None, line))
            else:
                name, sep, value = line.partition(b"=")
                if not sep:
                    raise BeastNetError(GRUBENV, "GRUB environment block is corrupt (line without '=')")
                self._items.append((name.decode("utf-8", "replace"), _unescape(value)))
            p = q + 1

    # -- access -----------------------------------------------------------
    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self._items if k is not None]  # type: ignore[misc]

    def get(self, name: str) -> str | None:
        for k, v in self._items:
            if k == name:
                return v  # type: ignore[return-value]
        return None

    def set(self, name: str, value: str) -> None:
        if not name or "=" in name or "\n" in name or name.startswith("#"):
            raise ValueError(f"invalid variable name {name!r}")
        for i, (k, _v) in enumerate(self._items):
            if k == name:
                self._items[i] = (name, value)
                break
        else:
            self._items.append((name, value))
        self.to_bytes()  # raises if it no longer fits

    def unset(self, name: str) -> None:
        for i, (k, _v) in enumerate(self._items):
            if k == name:
                del self._items[i]
                return

    # -- output -----------------------------------------------------------
    def to_bytes(self) -> bytes:
        out = bytearray(SIGNATURE)
        for k, v in self._items:
            if k is None:
                out += v  # type: ignore[operator]
            else:
                out += k.encode("utf-8") + b"=" + _escape(v)  # type: ignore[arg-type]
            out += b"\n"
        if len(out) > self.size:
            raise BeastNetError(GRUBENV, "not enough space in the GRUB environment block")
        out += b"#" * (self.size - len(out))
        return bytes(out)


def load(path: str) -> GrubEnv:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise BeastNetError(GRUBENV, f"{path} is missing",
                            "The stick was set up without a GRUB environment block; "
                            "update it with the beast-booter app.") from None
    except OSError as e:
        raise BeastNetError(GRUBENV, f"cannot read {path}: {e.strerror}") from None
    if st.st_size != SIZE:
        raise BeastNetError(GRUBENV, f"{path} is {st.st_size} bytes, expected {SIZE}")
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise BeastNetError(GRUBENV, f"cannot read {path}: {e.strerror}") from None
    return GrubEnv(data)


def save(path: str, env: GrubEnv) -> None:
    """Rewrite the block in place (never truncates or reallocates the file)."""
    data = env.to_bytes()
    try:
        st = os.stat(path)
        if st.st_size != len(data):
            raise BeastNetError(GRUBENV, f"{path} is {st.st_size} bytes, expected {len(data)}")
        with open(path, "r+b") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with open(path, "rb") as f:
            if f.read() != data:
                raise BeastNetError(GRUBENV, f"{path} did not read back what was written")
    except FileNotFoundError:
        raise BeastNetError(GRUBENV, f"{path} is missing") from None
    except OSError as e:
        raise BeastNetError(GRUBENV, f"cannot write {path}: {e.strerror}") from None


def set_oneshot(path: str, iso_path: str) -> None:
    """Point the menu's one-shot entry at ``iso_path`` (a path on the data partition)."""
    if not iso_path.startswith("/") or "\n" in iso_path:
        raise ValueError(f"invalid ISO path {iso_path!r}")
    env = load(path)
    env.set(ONESHOT_KEY, iso_path)
    save(path, env)


def clear_oneshot(path: str) -> None:
    env = load(path)
    if env.get(ONESHOT_KEY) is not None:
        env.unset(ONESHOT_KEY)
        save(path, env)
