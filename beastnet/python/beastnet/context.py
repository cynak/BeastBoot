"""Everything a run needs, built once by app.main() (and by tests)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections.abc import Callable

from .checksums import normalize_sha256
from .cmdline import BootParams
from .download import DownloadRequest, Downloader, _err, check_url
from .errors import REFUSED_PLAIN_HTTP
from .events import Reporter
from .firmware import Catalog
from .net import NetworkService
from .paths import Paths
from .system import System


class Quit(Exception):
    """Stop the app (after a dry-run reboot or power-off)."""


@dataclass
class Context:
    paths: Paths
    params: BootParams
    reporter: Reporter
    system: System
    net: NetworkService | None  # None with --no-net: use the network as it is
    catalog: Catalog
    downloader: Callable[[], Downloader]
    kernel: str = ""
    dry_run: bool = False
    notes: list[str] = field(default_factory=list)  # dry-run messages, printed at exit


def make_request(url: str, checksum: str = "") -> DownloadRequest:
    """Turn what the user typed into a request. ``checksum`` is empty, a
    SHA-256, or the link to a checksum file. Raises BeastNetError/ValueError."""
    c = (checksum or "").strip()
    sha = sums = None
    if c:
        if re.match(r"^[a-z][a-z0-9+.-]*://", c, re.IGNORECASE):
            sums = c
            if not c.lower().startswith(("https://", "http://")):
                raise ValueError("the checksum link must start with https://")
            if c.lower().startswith("http://"):
                raise _err(REFUSED_PLAIN_HTTP, "the checksum file must come over https://",
                           "A checksum fetched over plain HTTP proves nothing; use its "
                           "https:// link or type the SHA-256.")
        else:
            try:
                sha = normalize_sha256(c)
            except ValueError:
                raise ValueError("The checksum must be a SHA-256 (64 hexadecimal digits) "
                                 "or the https:// link to a checksum file.") from None
    url = check_url(url, trusted_hash=bool(sha or sums))
    return DownloadRequest(url=url, sha256=sha, sha256_url=sums)
