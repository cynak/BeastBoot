"""Serial console parsing: BEAST: records and a small VT100 screen emulator.

What arrives on the serial port is not a clean line-oriented log:

* GRUB's terminfo (serial) terminal word-wraps at 80 columns, and the
  inserted line break looks exactly like a real newline ("\\n\\r").
* Under OVMF the firmware console is mirrored to the same UART, so when the
  menu also enables GRUB's serial terminal every line arrives twice: first the
  80-column terminfo copy (possibly wrapped), then the wide console copy,
  often with no newline between them ("...fs=fat32BEAST: ready ...").
* Menus are drawn with cursor-positioning escape sequences.

`parse_records` therefore splits the cleaned stream at the record markers
(`BEAST: ` / `BEAST_FIXTURE `), ends a record at an escape-sequence boundary,
a blank line or the next marker, and re-joins physical lines that look like a
GRUB word wrap. Assertions should use tokens/regexes on `Record.text`, not
exact full-line comparisons.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

BOUNDARY = "\x1e"  # replaces cursor-positioning / clearing escape sequences


def _breakable(word: str) -> str:
    # GRUB hard-wraps a word that starts near the right edge (e.g. an echo right
    # after the menu leaves the cursor at column 78), so allow a line break
    # between any two characters of a marker.
    return "\n?".join(re.escape(c) for c in word)


# "BEAST: " / "BEAST_FIXTURE ", possibly broken across lines; a word wrap at the
# separating space drops the space.
MARKER_RE = re.compile(
    _breakable("BEAST") + r"\n?(?::(?: \n?|\n)|_\n?" + _breakable("FIXTURE") + r"(?: \n?|\n))"
)

# GRUB's terminfo terminal is 80 columns; it breaks before the line would exceed
# ~79 characters. Use a slightly lower bound so a real wrap is never missed.
WRAP_WIDTH = 76

_CSI_RE = re.compile(r"\x1b\[([0-?]*)([ -/]*)([@-~])")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ESC2_RE = re.compile(r"\x1b[()*+][0-9A-Za-z]|\x1b[@-Z\\^_=>78c]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1d\x1f\x7f]")


def _csi_to_clean(m: re.Match) -> str:
    final = m.group(3)
    params = m.group(1)
    if final in "HfJABCDGdt" or (final == "K" and params in ("1", "2")):
        return BOUNDARY
    return ""


def clean_text(raw: str) -> str:
    """Strip escape sequences; positioning/clearing becomes BOUNDARY; drop CR/NUL."""
    s = _OSC_RE.sub("", raw)
    s = _CSI_RE.sub(_csi_to_clean, s)
    s = _ESC2_RE.sub("", s)
    s = s.replace("\r", "").replace("\x1b", "")
    s = _CTRL_RE.sub("", s)
    return s


def plain_text(raw: str) -> str:
    """Human-readable approximation of the stream (for regex waits and logs)."""
    return clean_text(raw).replace(BOUNDARY, "\n")


@dataclass
class Record:
    """One BEAST record. `lines` are the physical lines as received; where GRUB
    wrapped, we cannot tell whether it dropped a space (word wrap) or split a
    word (hard break), so token/substring checks try both at every join."""

    prefix: str  # "BEAST" or "BEAST_FIXTURE"
    text: str  # everything after the marker, physical lines joined with a space
    start: int  # offsets in the cleaned text (for ordering / de-duplication)
    end: int
    lines: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return self.text.split(" ", 1)[0] if self.text else ""

    @property
    def args(self) -> str:
        parts = self.text.split(" ", 1)
        return parts[1] if len(parts) > 1 else ""

    def variants(self) -> list[str]:
        """Every way of re-joining the physical lines (" " or "" at each wrap)."""
        parts = [p.rstrip() for p in self.lines] or [self.text]
        n = len(parts) - 1
        if n <= 0:
            return [self.text]
        if n > 6:
            return [" ".join(parts).strip(), "".join(parts).strip()]
        out = []
        for mask in range(1 << n):
            v = parts[0]
            for i in range(n):
                v += ("" if mask >> i & 1 else " ") + parts[i + 1]
            out.append(v.strip())
        return out

    @property
    def tokens(self) -> list[str]:
        return [_unquote(t) for t in self.text.split()]

    def has_token(self, tok: str) -> bool:
        return any(tok in [_unquote(t) for t in v.split()] for v in self.variants())

    def contains(self, sub: str) -> bool:
        return any(sub in v for v in self.variants())

    def matches(self, rx) -> bool:
        rx = re.compile(rx) if isinstance(rx, str) else rx
        return any(rx.search(v) for v in self.variants())

    @property
    def fields(self) -> dict[str, str]:
        """key=value tokens (first occurrence wins). At a wrap, a fragment
        without "=" is taken to continue the previous value."""
        parts = [p.rstrip() for p in self.lines] or [self.text]
        v = parts[0]
        for p in parts[1:]:
            first = p.split(" ", 1)[0]
            v += ("" if first and "=" not in first else " ") + p
        out: dict[str, str] = {}
        for tok in v.split():
            tok = _unquote(tok)
            if "=" in tok:
                k, val = tok.split("=", 1)
                out.setdefault(k, val)
        return out

    def __str__(self) -> str:
        return f"{self.prefix}{': ' if self.prefix == 'BEAST' else ' '}{self.text}"


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[1:-1]
    return tok


def _first_word(s: str) -> str:
    return s.split(" ", 1)[0]


def _looks_wrapped(prev: str, nxt: str, prev_is_first: bool) -> bool:
    """Could `nxt` be the continuation of `prev` after a GRUB word wrap?"""
    if not nxt or nxt[0] == " " or MARKER_RE.search(nxt):
        return False
    # GRUB re-counts the partial word that overflowed when it starts the next
    # line, so continuation lines can break early by up to one word's width.
    slack = 0 if prev_is_first else len(_first_word(prev))
    return len(prev) + 1 + len(_first_word(nxt)) + slack > WRAP_WIDTH


def parse_records(clean: str, final: bool = False) -> list[Record]:
    """Parse BEAST records from cleaned text (see clean_text).

    With final=False, a record that might still be growing (it reaches the end
    of the buffer) is left out.
    """
    marks = list(MARKER_RE.finditer(clean))
    records: list[Record] = []
    for i, m in enumerate(marks):
        prefix = "BEAST" if m.group(0).replace("\n", "").startswith("BEAST:") else "BEAST_FIXTURE"
        body_start = m.end()
        limit = marks[i + 1].start() if i + 1 < len(marks) else len(clean)
        terminated = i + 1 < len(marks)
        seg = clean[body_start:limit]
        b = seg.find(BOUNDARY)
        if b >= 0:
            seg = seg[:b]
            terminated = True
        # Everything on the physical line where the record text starts.
        line_begin = max(clean.rfind("\n", 0, m.end()), clean.rfind(BOUNDARY, 0, m.end())) + 1
        phys = seg.split("\n")
        used = [phys[0]]
        width_line = clean[line_begin : m.end()] + phys[0]
        k = 1
        complete = None
        while k < len(phys):
            nxt = phys[k]
            is_last = k == len(phys) - 1
            if is_last and not terminated:
                # nxt is still being received (or empty because the buffer ends
                # with a newline): we cannot decide yet.
                complete = final
                if final and _looks_wrapped(width_line, nxt, k == 1):
                    used.append(nxt)
                break
            if _looks_wrapped(width_line, nxt, k == 1):
                used.append(nxt)
                width_line = nxt
                k += 1
                continue
            complete = True
            break
        else:
            complete = terminated or final
        if not complete:
            continue
        consumed = len("\n".join(used))
        text = " ".join(p.rstrip() for p in used).strip()
        records.append(Record(prefix, text, m.start(), body_start + consumed, list(used)))
    return dedupe(records, clean)


def _squash(s: str) -> str:
    return re.sub(r"\s+", "", s)


def dedupe(records: list[Record], clean: str) -> list[Record]:
    """Collapse a record printed twice back-to-back (GRUB serial terminal +
    OVMF console mirror), keeping the copy with the fewest wraps."""
    out: list[Record] = []
    for r in records:
        if out:
            p = out[-1]
            gap = clean[p.end : r.start]
            if (p.prefix == r.prefix and _squash(p.text) == _squash(r.text)
                    and BOUNDARY not in gap and gap.strip() == ""):
                if len(r.lines) < len(p.lines):
                    out[-1] = Record(p.prefix, r.text, p.start, r.end, r.lines)
                else:
                    out[-1] = Record(p.prefix, p.text, p.start, r.end, p.lines)
                continue
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# VT100 screen emulator (enough for GRUB's terminfo and OVMF's terminal output)
# ---------------------------------------------------------------------------

BOX_TOP_LEFT = "+┌╔"
BOX_HORIZ = "-─═"
BOX_VERT = "|│║"
BOX_BOTTOM_LEFT = "+└╚"


@dataclass
class MenuView:
    entries: list[str]
    selected: int | None

    def __str__(self) -> str:
        return "\n".join(
            ("> " if i == self.selected else "  ") + e for i, e in enumerate(self.entries)
        )


class Screen:
    """Minimal VT100 emulator. Large canvas, no autowrap (GRUB wraps itself)."""

    def __init__(self, rows: int = 64, cols: int = 256):
        self.rows, self.cols = rows, cols
        self.chars = [[" "] * cols for _ in range(rows)]
        self.hl = [[False] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.reverse = False
        self.bg: int | None = None
        self._esc = ""  # pending escape sequence

    # -- feeding ---------------------------------------------------------
    def feed(self, text: str) -> None:
        for ch in text:
            if self._esc:
                self._esc += ch
                self._try_escape()
                continue
            if ch == "\x1b":
                self._esc = ch
            elif ch == "\r":
                self.c = 0
            elif ch == "\n":
                self._linefeed()
            elif ch == "\b":
                self.c = max(0, self.c - 1)
            elif ch == "\t":
                self.c = min(self.cols - 1, (self.c // 8 + 1) * 8)
            elif ch < " " or ch == "\x7f":
                pass
            else:
                self._put(ch)

    def _put(self, ch: str) -> None:
        if 0 <= self.r < self.rows and 0 <= self.c < self.cols:
            self.chars[self.r][self.c] = ch
            self.hl[self.r][self.c] = self._highlight()
        if self.c < self.cols - 1:
            self.c += 1

    def _highlight(self) -> bool:
        light_bg = self.bg in (47, 107)
        return self.reverse != light_bg

    def _linefeed(self) -> None:
        if self.r < self.rows - 1:
            self.r += 1
        else:
            self.chars.pop(0)
            self.hl.pop(0)
            self.chars.append([" "] * self.cols)
            self.hl.append([False] * self.cols)

    def _try_escape(self) -> None:
        s = self._esc
        if len(s) == 2 and s[1] != "[" and s[1] != "]":
            if s[1] in "()*+":
                return  # needs one more char
            self._esc = ""
            return
        if len(s) == 3 and s[1] in "()*+":
            self._esc = ""
            return
        if s[1] == "]":
            if s.endswith("\x07") or s.endswith("\x1b\\"):
                self._esc = ""
            elif len(s) > 256:
                self._esc = ""
            return
        if s[1] == "[" and len(s) > 2 and "@" <= s[-1] <= "~":
            self._esc = ""
            self._csi(s[2:-1], s[-1])
        elif len(s) > 64:
            self._esc = ""

    def _csi(self, params: str, final: str) -> None:
        if params.startswith(("?", "=", ">")):
            return
        nums = [int(p) if p.isdigit() else None for p in params.split(";")] if params else []

        def n(i: int, default: int) -> int:
            return nums[i] if i < len(nums) and nums[i] is not None else default

        if final in "Hf":
            self.r = min(self.rows - 1, max(0, n(0, 1) - 1))
            self.c = min(self.cols - 1, max(0, n(1, 1) - 1))
        elif final == "A":
            self.r = max(0, self.r - n(0, 1))
        elif final == "B":
            self.r = min(self.rows - 1, self.r + n(0, 1))
        elif final == "C":
            self.c = min(self.cols - 1, self.c + n(0, 1))
        elif final == "D":
            self.c = max(0, self.c - n(0, 1))
        elif final == "G":
            self.c = min(self.cols - 1, max(0, n(0, 1) - 1))
        elif final == "d":
            self.r = min(self.rows - 1, max(0, n(0, 1) - 1))
        elif final == "J":
            mode = n(0, 0)
            if mode == 2 or mode == 3:
                for row in range(self.rows):
                    self._clear(row, 0, self.cols)
            elif mode == 0:
                self._clear(self.r, self.c, self.cols)
                for row in range(self.r + 1, self.rows):
                    self._clear(row, 0, self.cols)
            elif mode == 1:
                for row in range(self.r):
                    self._clear(row, 0, self.cols)
                self._clear(self.r, 0, self.c + 1)
        elif final == "K":
            mode = n(0, 0)
            if mode == 0:
                self._clear(self.r, self.c, self.cols)
            elif mode == 1:
                self._clear(self.r, 0, self.c + 1)
            else:
                self._clear(self.r, 0, self.cols)
        elif final == "m":
            for p in nums or [0]:
                p = 0 if p is None else p
                if p == 0:
                    self.reverse, self.bg = False, None
                elif p == 7:
                    self.reverse = True
                elif p == 27:
                    self.reverse = False
                elif 40 <= p <= 47 or 100 <= p <= 107:
                    self.bg = p
                elif p == 49:
                    self.bg = None

    def _clear(self, row: int, c0: int, c1: int) -> None:
        for c in range(max(0, c0), min(self.cols, c1)):
            self.chars[row][c] = " "
            self.hl[row][c] = False

    # -- reading ---------------------------------------------------------
    def lines(self) -> list[str]:
        return ["".join(r).rstrip() for r in self.chars]

    def text(self) -> str:
        ls = self.lines()
        while ls and not ls[-1]:
            ls.pop()
        return "\n".join(ls)

    def menu(self) -> MenuView | None:
        """Entries of the GRUB menu currently drawn, or None if no menu box is visible."""
        lines = [("".join(r)) for r in self.chars]
        top = col = None
        for ri, line in enumerate(lines):
            for ci, ch in enumerate(line[:-12]):
                if ch in BOX_TOP_LEFT and all(x in BOX_HORIZ for x in line[ci + 1 : ci + 11]):
                    top, col = ri, ci
                    break
            if top is not None:
                break
        if top is None:
            return None
        entries: list[str] = []
        selected = None
        for ri in range(top + 1, self.rows):
            line = lines[ri]
            if line[col] in BOX_BOTTOM_LEFT and line[col + 1 : col + 6] and all(
                x in BOX_HORIZ for x in line[col + 1 : col + 6]
            ):
                break
            body = line[col + 1 :]
            stripped = body.lstrip(" ")
            off = len(body) - len(stripped)
            marker = False
            if stripped[:1] in ("*", ">"):
                marker = True
                stripped = stripped[1:]
                off += 1
            title = re.split(r" {2,}|[|│║]", stripped, maxsplit=1)[0].strip()
            if not title:
                continue
            start = col + 1 + off + (len(stripped) - len(stripped.lstrip(" ")))
            cells = self.hl[ri][start : start + len(title)]
            if marker or (cells and sum(cells) * 2 > len(cells)):
                selected = len(entries)
            entries.append(title)
        return MenuView(entries, selected)
