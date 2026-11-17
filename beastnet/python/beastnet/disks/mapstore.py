"""Power-cut-safe keeping of ddrescue mapfiles (docs/DISK_TOOLS.md s.1 rule 5, s.6).

ddrescue writes its mapfile in place, so a power cut can tear it (on a FAT stick even
the file's clusters can be lost). So ddrescue works on a copy in RAM
(``/run/beastnet/disk-maps``), and the persistent mapfile (``plan.mapfile``: the stick's
data partition, a third disk or next to an image) is a *snapshot*:

* taken at most every SAVE_INTERVAL seconds, when a ddrescue pass ends, on a stop and at
  the end; only a snapshot that parses as a complete map of the whole source is taken;
* before it is written, the target (device or image file) is fsync'ed, so every area
  the snapshot calls finished is really on the target;
* written to ``<map>.tmp`` in the same directory, flushed and fsync'ed, renamed over
  ``<map>``, the file fsync'ed again under its new name (on FAT/exFAT the rename only
  marks the directory entry dirty), then the directory is fsync'ed: a power cut leaves
  the old or the new complete version (or, in the few milliseconds between rename and
  the second fsync on FAT, an entry the checksum rejects: then the copy offers to start
  over, it never trusts it);
* it carries its own SHA-256 and the source size in a first comment line
  (``# beastboot-mapfile v1 size=<bytes> sha256=<hex>``). A mapfile without it, with
  the wrong size, a bad hash, gaps, overlaps or unknown states is *untrusted*: it is
  never used (a wrong map could skip unread areas and report a complete copy). The
  caller says so and offers to start over.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass

SAVE_INTERVAL = 30.0       # seconds between snapshots (see the module docstring)
HEADER = "# beastboot-mapfile v1"
_HEAD_RX = re.compile(r"^# beastboot-mapfile v1 size=(\d+) sha256=([0-9a-f]{64})$")
_STATES = set("?*/-+")
_PHASES = set("?*/-FGr+") | set("cftsrg")


def parse_strict(text: str, total: int) -> list[tuple[int, int, str]] | None:
    """The blocks of a complete ddrescue mapfile covering [0, total), or None."""
    status_seen = False
    blocks: list[tuple[int, int, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        w = line.split()
        try:
            if not status_seen:
                if len(w) < 2:
                    return None
                int(w[0], 0)
                if w[1] not in _PHASES:
                    return None
                status_seen = True
                continue
            if len(w) != 3 or w[2] not in _STATES:
                return None
            blocks.append((int(w[0], 0), int(w[1], 0), w[2]))
        except ValueError:
            return None
    if not status_seen or not blocks:
        return None
    pos = 0
    for p, n, _st in blocks:
        if p != pos or n <= 0:
            return None
        pos += n
    return blocks if pos == total else None


def seal(text: str, total: int) -> str:
    body = text if text.endswith("\n") else text + "\n"
    digest = hashlib.sha256(body.encode()).hexdigest()
    return f"{HEADER} size={total} sha256={digest}\n{body}"


def unseal(data: str, total: int) -> str | None:
    """The ddrescue mapfile inside a sealed snapshot, or None if it cannot be trusted."""
    head, sep, body = data.partition("\n")
    m = _HEAD_RX.match(head)
    if not sep or not m or int(m.group(1)) != total:
        return None
    if hashlib.sha256(body.encode()).hexdigest() != m.group(2):
        return None
    return body if parse_strict(body, total) is not None else None


@dataclass
class Loaded:
    state: str          # "absent" | "ok" | "untrusted"
    text: str = ""      # the ddrescue mapfile (state ok)
    path: str = ""      # which file it came from
    why: str = ""       # untrusted: what is wrong


def load(mapfile: str, total: int) -> Loaded:
    """The newest trustworthy snapshot: ``<map>.tmp`` (fully written, rename not done) or
    ``<map>``. Untrusted when a file exists but none of them can be trusted."""
    found = False
    reasons = []
    for p in (mapfile + ".tmp", mapfile):
        try:
            with open(p, encoding="ascii", errors="strict") as f:
                data = f.read()
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError) as e:
            found = True
            reasons.append(f"{os.path.basename(p)}: cannot be read ({getattr(e, 'strerror', None) or e})")
            continue
        found = True
        body = unseal(data, total)
        if body is not None:
            return Loaded("ok", body, p)
        reasons.append(f"{os.path.basename(p)}: incomplete or damaged")
    if not found:
        return Loaded("absent")
    return Loaded("untrusted", why="; ".join(reasons))


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass  # some filesystems refuse fsync on a directory; the rename is still done
    finally:
        os.close(fd)


def write_atomic(path: str, data: str) -> None:
    """tmp file in the same directory, fsync, rename over, fsync the directory."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        view = data.encode()
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    # FAT/exFAT keep size and first cluster in the directory entry, which a rename only marks
    # dirty: fsync the file under its new name (writes that entry), then the directory
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(d)


def sync_target(target: str, fd: int | None = None) -> None:
    """Make what ddrescue wrote durable before a snapshot says it is done."""
    if fd is not None:
        os.fsync(fd)
        return
    try:
        tfd = os.open(target, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(tfd)
    except OSError:
        pass
    finally:
        os.close(tfd)


class Keeper:
    """Copies the RAM mapfile to the persistent place (see the module docstring)."""

    def __init__(self, work: str, mapfile: str, total: int, target: str, target_fd: int | None = None,
                 interval: float = SAVE_INTERVAL, clock=time.monotonic) -> None:
        self.work, self.mapfile, self.total = work, mapfile, total
        self.target, self.target_fd = target, target_fd
        self.interval, self.clock = interval, clock
        self.last = clock()
        self.saved = ""

    def tick(self) -> bool:
        if self.clock() - self.last < self.interval:
            return False
        return self.save()

    def save(self) -> bool:
        """One snapshot if the RAM map is complete and changed. True if written."""
        self.last = self.clock()
        try:
            with open(self.work, encoding="ascii", errors="replace") as f:
                text = f.read()
        except OSError:
            return False
        if text == self.saved or parse_strict(text, self.total) is None:
            return False   # unchanged, or ddrescue is rewriting it right now: next time
        sync_target(self.target, self.target_fd)
        write_atomic(self.mapfile, seal(text, self.total))
        self.saved = text
        return True


__all__ = ["SAVE_INTERVAL", "Keeper", "Loaded", "load", "parse_strict", "seal", "unseal", "write_atomic"]
