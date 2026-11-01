"""SHA-256 values and checksum files (SHA256SUMS, ``*.sha256``, BSD style)."""

from __future__ import annotations

import posixpath
import re

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
# GNU coreutils: "<hash>  <name>" (text mode) or "<hash> *<name>" (binary mode);
# a leading backslash means the name has \\ and \n escapes.
_GNU = re.compile(r"^(\\?)([0-9a-fA-F]{64})(?:[ \t]+\*?|\s*\*)(.+)$")
# BSD / "sha256sum --tag": "SHA256 (<name>) = <hash>"
_BSD = re.compile(r"^SHA-?256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})$", re.IGNORECASE)


def normalize_sha256(value: str | None) -> str | None:
    """Return a lower-case 64-digit hex SHA-256, or None if ``value`` is empty.

    Accepts surrounding whitespace and an optional ``sha256:`` / ``SHA256=``
    prefix. Raises ValueError for anything else.
    """
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    v = re.sub(r"^sha-?256\s*[:=]\s*", "", v, flags=re.IGNORECASE)
    if not _HEX64.fullmatch(v):
        raise ValueError("a SHA-256 is 64 hexadecimal digits")
    return v.lower()


def _unescape_gnu(name: str) -> str:
    out, i = [], 0
    while i < len(name):
        if name[i] == "\\" and i + 1 < len(name):
            nxt = name[i + 1]
            out.append("\n" if nxt == "n" else nxt)
            i += 2
            continue
        out.append(name[i])
        i += 1
    return "".join(out)


def parse_checksum_file(text: str) -> list[tuple[str, str | None]]:
    """Return (sha256, file name or None) for every SHA-256 line in ``text``.

    Understands GNU and BSD formats, a file that is just a hash, and the
    clear-signed variant (PGP armour lines and dash-escaping are skipped).
    Lines with other hash lengths (MD5, SHA-1, SHA-512) are ignored.
    """
    entries: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:]
        if not line or line.startswith("#"):
            continue
        m = _BSD.match(line)
        if m:
            entries.append((m.group(2).lower(), m.group(1)))
            continue
        if _HEX64.fullmatch(line):
            entries.append((line.lower(), None))
            continue
        m = _GNU.match(line)
        if m:  # (a SHA-512 line never matches: its 65th character is a digit)
            name = m.group(3).strip()
            if m.group(1):
                name = _unescape_gnu(name)
            entries.append((m.group(2).lower(), name))
    return entries


def _base(name: str) -> str:
    return posixpath.basename(name.replace("\\", "/").lstrip("*"))


def _match(named: list[tuple[str, str]], names: list[str]) -> str | None:
    """Exact match first, then case-insensitive."""
    for w in names:
        for h, n in named:
            if n == w:
                return h
    lw = [w.lower() for w in names]
    for h, n in named:
        if n.lower() in lw:
            return h
    return None


def pick_checksum(entries: list[tuple[str, str | None]], names: list[str],
                  server_names: list[str] | tuple[str, ...] = ()) -> str | None:
    """Pick the hash for our file. ``names`` are the file names the user
    controls (the link's file name, the destination they chose);
    ``server_names`` the ones the server sent (redirect target,
    Content-Disposition).

    The user's names decide (exact match first, then case-insensitive).
    Server names count only when the file lists a single hash: otherwise the
    server (or whoever answers a plain http:// download) could name another
    genuine file in the list and have that one accepted. A file holding a
    single nameless hash applies to whatever was downloaded. Never guesses
    between entries for other files.
    """
    wanted = [n for n in (_base(x) for x in names if x) if n]
    named = [(h, _base(n)) for h, n in entries if n]
    found = _match(named, wanted)
    if found:
        return found
    if len({h for h, _ in entries}) == 1:
        server = [n for n in (_base(x) for x in server_names if x) if n]
        found = _match(named, server)
        if found:
            return found
    nameless = {h for h, n in entries if not n}
    if nameless and not named and len(nameless) == 1:
        return nameless.pop()
    return None
