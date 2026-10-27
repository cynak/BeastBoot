"""Download an ISO onto the data partition: verified TLS, checksums, resume.

Rules (BEASTNET.md sections 1 and 5):

- HTTPS with certificate and host name verification against one CA bundle
  (Ubuntu's ``ca-certificates``). Verification can not be turned off: there
  is no option for it, on purpose.
- Plain ``http://`` only when a SHA-256 is known from a trusted source: typed
  in, or read from a checksum file fetched over HTTPS.
- Redirects are followed (at most 10); once a hop was HTTPS, a redirect to
  plain HTTP is refused.
- The data goes to ``<dest>.part`` (resumed with ``Range`` / ``If-Range``),
  is hashed while streaming, fsynced, and renamed to ``<dest>`` only when it
  is complete and, if a SHA-256 was given, matches. A mismatch keeps nothing.
- An existing file is never replaced unless the caller says so.
"""

from __future__ import annotations

import base64
import collections
import errno
import hashlib
import http.client
import json
import os
import posixpath
import re
import socket
import ssl
import time
import unicodedata
from dataclasses import dataclass, field
from collections.abc import Callable
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from . import __version__
from .checksums import normalize_sha256, parse_checksum_file, pick_checksum
from .errors import (CHECKSUM_MISMATCH, EXISTS, HTTP, MOUNT, NO_SPACE, REFUSED_PLAIN_HTTP,
                     TLS, BeastNetError, Cancelled)
from .events import Reporter
from .paths import DEFAULT_CA_FILE, DOWNLOADS, normalize_data_path

CHUNK = 256 * 1024
MAX_REDIRECTS = 10
MAX_CHECKSUM_FILE = 1024 * 1024
SPACE_MARGIN = 8 * 1024 * 1024
FAT32_MAX_FILE = 4 * 1024 ** 3 - 1
USER_AGENT = f"beast-net/{__version__} (beast-boot)"
REDIRECT_CODES = (301, 302, 303, 307, 308)
RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504)

ProgressFn = Callable[["Progress"], None]


class _Retry(Exception):
    """Internal: a transfer was interrupted and can be resumed."""


def _err(code: str, text: str, hint: str = "", *, retryable: bool = False) -> BeastNetError:
    e = BeastNetError(code, text, hint)
    e.retryable = retryable  # type: ignore[attr-defined]
    return e


# -- TLS -------------------------------------------------------------------

def tls_context(ca_file: str) -> ssl.SSLContext:
    """A client context that trusts exactly the CAs in ``ca_file``."""
    if not os.path.isfile(ca_file):
        raise _err(TLS, f"CA bundle {ca_file} is missing; cannot check certificates")
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    except (ssl.SSLError, OSError) as e:
        raise _err(TLS, f"cannot load CA bundle {ca_file}: {e}") from None
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # create_default_context already does this; state it so nobody "simplifies" it away.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _clock_hint() -> str:
    now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return (f"The computer's clock says {now}. Certificates can only be checked when "
            "the clock is right: fix it in the firmware setup, or set it from the "
            "shell with: date -u -s 'YYYY-MM-DD HH:MM'.")


def _network_error(e: BaseException, host: str) -> BeastNetError:
    if isinstance(e, ssl.SSLCertVerificationError):
        msg = e.verify_message or str(e)
        hint = _clock_hint() if ("expired" in msg or "not yet valid" in msg) else (
            "The server's certificate is not signed by a certificate authority this "
            "system trusts, or it is for a different name. beast-net does not download "
            "from servers it cannot verify.")
        return _err(TLS, f"certificate of {host} rejected: {msg}", hint)
    if isinstance(e, ssl.SSLError):
        return _err(TLS, f"secure connection to {host} failed: {e.reason or e}", retryable=True)
    if isinstance(e, socket.gaierror):
        return _err(HTTP, f"cannot resolve {host} (DNS): {e.strerror or e}", retryable=True)
    if isinstance(e, TimeoutError):
        return _err(HTTP, f"{host} did not answer in time", retryable=True)
    if isinstance(e, ConnectionRefusedError):
        return _err(HTTP, f"{host} refused the connection", retryable=True)
    if isinstance(e, http.client.HTTPException):
        return _err(HTTP, f"bad answer from {host}: {e.__class__.__name__} {e}", retryable=True)
    if isinstance(e, OSError):
        return _err(HTTP, f"connection to {host} failed: {e.strerror or e}", retryable=True)
    return _err(HTTP, f"connection to {host} failed: {e}")


# -- URLs and names ----------------------------------------------------------

def check_url(url: str, *, trusted_hash: bool) -> str:
    """Validate and normalise a user-supplied link. ``trusted_hash``: a SHA-256
    from a trusted source is known, so plain http:// is acceptable."""
    u = (url or "").strip()
    if not u:
        raise _err(HTTP, "no link given")
    if "://" not in u:
        u = "https://" + u
    parts = urlsplit(u)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise _err(HTTP, f"{scheme}:// links are not supported; use https://")
    if not parts.hostname:
        raise _err(HTTP, "the link has no server name")
    try:
        parts.port
    except ValueError:
        raise _err(HTTP, "the link has an invalid port number") from None
    if any(ord(c) < 0x20 or c == "\x7f" for c in u):
        raise _err(HTTP, "the link contains control characters")
    if scheme == "http" and not trusted_hash:
        raise _err(REFUSED_PLAIN_HTTP,
                   "plain http:// downloads are refused without a SHA-256",
                   "Use the https:// link, or give the ISO's SHA-256 (or the https:// link "
                   "of its checksum file) so the download can be verified.")
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))


def _target(parts) -> str:
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parts.query:
        return path + "?" + quote(parts.query, safe="=&%:@!$'()*+,;/?-._~")
    return path


def name_from_url(url: str) -> str:
    try:
        return unquote(posixpath.basename(urlsplit(url).path))
    except ValueError:
        return ""


def filename_from_disposition(value: str | None) -> str | None:
    """File name from a Content-Disposition header (RFC 6266, incl. filename*)."""
    if not value:
        return None
    m = re.search(r"filename\*\s*=\s*([^;]+)", value, re.IGNORECASE)
    if m:
        v = m.group(1).strip().strip('"')
        charset, _, rest = v.partition("'")
        _lang, _, encoded = rest.partition("'")
        if encoded:
            try:
                return unquote(encoded, encoding=charset or "utf-8", errors="replace")
            except LookupError:
                return unquote(encoded, errors="replace")
    m = re.search(r'filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]+))', value, re.IGNORECASE)
    if not m:
        return None
    name = m.group(1) if m.group(1) is not None else m.group(2).strip()
    name = re.sub(r"\\(.)", r"\1", name)
    try:  # http.client decodes headers as Latin-1; most servers send UTF-8
        name = name.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return name


_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def sanitize_filename(name: str | None, default: str = "download.iso") -> str:
    """A file name that is safe on exFAT/FAT32/NTFS, in GRUB and on a kernel
    command line: ASCII letters, digits and ``._+-`` only, no leading dot,
    at most 200 bytes, extension kept."""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", name)
    name = re.sub(r"_{2,}", "_", name)
    name = re.sub(r"\.{2,}", ".", name)
    name = name.strip("._-+")
    if not name:
        return default
    stem, ext = posixpath.splitext(name)
    if len(ext) > 16:
        stem, ext = name, ""
    if stem.split(".")[0].upper() in _RESERVED:
        stem = "_" + stem
    stem = stem[: 200 - len(ext)].rstrip("._-+") or "download"
    return stem + ext


# -- data classes --------------------------------------------------------------

@dataclass
class DownloadRequest:
    url: str
    sha256: str | None = None
    sha256_url: str | None = None
    dest: str | None = None  # path on the data partition; None: /downloads/<name>
    overwrite: bool = False


@dataclass
class Progress:
    phase: str  # connect | check | download | retry | verify
    done: int = 0
    total: int | None = None
    speed: float = 0.0  # bytes per second
    eta: float | None = None  # seconds
    resumed_from: int = 0
    note: str = ""


@dataclass
class Plan:
    """What prepare() found out before any byte is written."""

    request: DownloadRequest
    url: str
    final_url: str
    dest: str  # path on the data partition
    local: str  # local file
    total: int | None
    etag: str | None
    last_modified: str | None
    accept_ranges: bool
    expected: str | None  # SHA-256 we must match, if any
    expected_from: str = ""  # "given" or the checksum file URL
    allow_http: bool = False
    names: list[str] = field(default_factory=list)

    @property
    def exists(self) -> bool:
        return os.path.exists(self.local)


@dataclass
class DownloadResult:
    path: str  # on the data partition
    local: str
    size: int
    sha256: str
    expected: str | None
    reused: bool = False

    @property
    def verified(self) -> bool:
        return self.expected is not None and self.expected == self.sha256


# -- HTTP ------------------------------------------------------------------

class Http:
    def __init__(self, ca_file: str, timeout: float = 30.0) -> None:
        self.ca_file = ca_file
        self.timeout = timeout
        self._ctx: ssl.SSLContext | None = None

    @property
    def ctx(self) -> ssl.SSLContext:
        if self._ctx is None:
            self._ctx = tls_context(self.ca_file)
        return self._ctx

    def get(self, url: str, headers: dict[str, str] | None = None, *,
            allow_http: bool = False) -> tuple[http.client.HTTPResponse, str]:
        """GET ``url`` following redirects; returns (response, final URL).
        The caller must close the response."""
        seen_https = False
        first_netloc = urlsplit(url).netloc
        for _hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            host = parts.hostname or ""
            if scheme == "https":
                seen_https = True
            elif scheme == "http":
                if seen_https:
                    raise _err(REFUSED_PLAIN_HTTP,
                               f"refused a redirect from HTTPS to plain HTTP ({host})")
                if not allow_http:
                    raise _err(REFUSED_PLAIN_HTTP, f"refused plain HTTP to {host} without a SHA-256")
            else:
                raise _err(HTTP, f"redirect to unsupported scheme {scheme or '(none)'}")
            if not host:
                raise _err(HTTP, "redirect to a link without a server name")
            try:
                port = parts.port
            except ValueError:
                raise _err(HTTP, f"invalid port in {url}") from None
            try:
                host_ascii = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise _err(HTTP, f"invalid server name {host!r}") from None
            conn: http.client.HTTPConnection
            if scheme == "https":
                conn = http.client.HTTPSConnection(host_ascii, port, timeout=self.timeout,
                                                   context=self.ctx)
            else:
                conn = http.client.HTTPConnection(host_ascii, port, timeout=self.timeout)
            hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*",
                    "Accept-Encoding": "identity", "Connection": "close"}
            if parts.username is not None and parts.netloc == first_netloc:
                cred = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
                hdrs["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
            hdrs.update(headers or {})
            try:
                conn.request("GET", _target(parts), headers=hdrs)
                resp = conn.getresponse()
            except BaseException as e:
                conn.close()
                if isinstance(e, (OSError, http.client.HTTPException, ssl.SSLError, ValueError)):
                    raise _network_error(e, host) from None
                raise
            if resp.status in REDIRECT_CODES:
                loc = resp.getheader("Location")
                resp.close()
                conn.close()
                if not loc:
                    raise _err(HTTP, f"{host} answered {resp.status} without a Location")
                url = urlunsplit(urlsplit(urljoin(url, loc.strip()))._replace(fragment=""))
                continue
            return resp, url
        raise _err(HTTP, f"more than {MAX_REDIRECTS} redirects")


def _status_error(resp: http.client.HTTPResponse, host: str) -> BeastNetError:
    reason = (resp.reason or "").strip()
    hint = {404: "Check the link: the file is not on that server (any more).",
            403: "The server refuses to hand out this file.",
            401: "The server wants a user name and password."}.get(resp.status, "")
    return _err(HTTP, f"{host} answered {resp.status} {reason}".rstrip(), hint,
                retryable=resp.status in RETRYABLE_STATUS)


# -- the downloader ------------------------------------------------------------

def _human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


human_size = _human


class _Meter:
    """Progress bookkeeping: speed over the last few seconds, ETA."""

    def __init__(self, fn: ProgressFn | None, reporter: Reporter | None, total: int | None,
                 start: int) -> None:
        self.fn, self.reporter, self.total = fn, reporter, total
        self.samples: collections.deque[tuple[float, int]] = collections.deque()
        self.resumed_from = start
        self.last_call = 0.0

    def update(self, done: int, phase: str = "download", force: bool = False) -> None:
        now = time.monotonic()
        self.samples.append((now, done))
        while len(self.samples) > 2 and now - self.samples[0][0] > 5.0:
            self.samples.popleft()
        if self.reporter is not None and phase == "download":
            self.reporter.download_progress(done, self.total, force=force)
        if self.fn is None or (not force and now - self.last_call < 0.1):
            return
        self.last_call = now
        t0, d0 = self.samples[0]
        speed = (done - d0) / (now - t0) if now > t0 else 0.0
        eta = (self.total - done) / speed if (self.total and speed > 0) else None
        self.fn(Progress(phase, done, self.total, speed, eta, self.resumed_from))


def _hash_file(path: str, hasher, limit: int | None, meter: _Meter | None,
               cancel=None) -> int:
    n = 0
    with open(path, "rb") as f:
        while limit is None or n < limit:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            buf = f.read(1024 * 1024 if limit is None else min(1024 * 1024, limit - n))
            if not buf:
                break
            hasher.update(buf)
            n += len(buf)
            if meter is not None:
                meter.update(n, "check")
    return n


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class Downloader:
    def __init__(
        self,
        data_root: str,
        ca_file: str = DEFAULT_CA_FILE,
        *,
        reporter: Reporter | None = None,
        timeout: float = 30.0,
        retries: int = 6,
        retry_delays: tuple[float, ...] = (1, 2, 4, 8, 15, 30),
        chunk: int = CHUNK,
        fs_type: Callable[[str], str | None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.data_root = data_root
        self.http = Http(ca_file, timeout)
        self.reporter = reporter
        self.retries = retries
        self.retry_delays = retry_delays or (0,)
        self.chunk = chunk
        self.fs_type = fs_type
        self.sleep = sleep

    # -- small helpers ------------------------------------------------------
    def local_path(self, dest: str) -> str:
        return os.path.join(self.data_root, dest.lstrip("/"))

    def fetch_text(self, url: str, limit: int = MAX_CHECKSUM_FILE) -> str:
        """Fetch a small text file (a checksum file) over HTTPS."""
        resp, _final = self.http.get(url)
        host = urlsplit(url).hostname or ""
        try:
            if resp.status != 200:
                raise _status_error(resp, host)
            try:
                data = resp.read(limit + 1)
            except (OSError, http.client.HTTPException) as e:
                raise _network_error(e, host) from None
        finally:
            resp.close()
        if len(data) > limit:
            raise _err(CHECKSUM_MISMATCH, f"checksum file {url} is larger than {limit} bytes")
        return data.decode("utf-8", "replace")

    def _retrying(self, what: Callable[[], object]):
        attempt = 0
        while True:
            try:
                return what()
            except BeastNetError as e:
                if not getattr(e, "retryable", False) or attempt >= min(2, self.retries):
                    raise
            self.sleep(self.retry_delays[min(attempt, len(self.retry_delays) - 1)])
            attempt += 1

    # -- phase 1: find out what we are about to download ---------------------
    def prepare(self, req: DownloadRequest) -> Plan:
        expected = normalize_sha256(req.sha256)  # ValueError: caller validates input
        sums_url = None
        if req.sha256_url and not expected:
            # A checksum file only counts when it comes over verified HTTPS.
            if req.sha256_url.strip().lower().startswith("http://"):
                raise _err(REFUSED_PLAIN_HTTP, "the checksum file must come over https://",
                           "A checksum fetched over plain HTTP proves nothing; use its "
                           "https:// link or type the SHA-256.")
            sums_url = check_url(req.sha256_url, trusted_hash=False)
        url = check_url(req.url, trusted_hash=bool(expected or sums_url))
        entries = None
        if sums_url:
            text = self._retrying(lambda: self.fetch_text(sums_url))
            entries = parse_checksum_file(text)  # type: ignore[arg-type]
            if not entries:
                raise _err(CHECKSUM_MISMATCH, f"no SHA-256 found in {sums_url}")
        allow_http = bool(expected or entries)
        host = urlsplit(url).hostname or ""

        def probe():
            resp, final = self.http.get(url, allow_http=allow_http)
            try:
                if resp.status != 200:
                    raise _status_error(resp, urlsplit(final).hostname or host)
                return final, dict((k.lower(), v) for k, v in resp.getheaders())
            finally:
                resp.close()

        final, headers = self._retrying(probe)  # type: ignore[misc]
        total = None
        try:
            if "content-length" in headers:
                total = int(headers["content-length"])
        except ValueError:
            total = None
        cd_name = filename_from_disposition(headers.get("content-disposition"))
        names = [n for n in (cd_name, name_from_url(final), name_from_url(url)) if n]
        if req.dest:
            try:
                dest = normalize_data_path(req.dest, under=DOWNLOADS)
            except ValueError as e:
                raise ValueError(f"destination must be under {DOWNLOADS}/: {e}") from None
            if dest == DOWNLOADS:
                raise ValueError(f"destination must be a file under {DOWNLOADS}/")
        else:
            dest = f"{DOWNLOADS}/{sanitize_filename(names[0] if names else None)}"
        names.append(posixpath.basename(dest))
        expected_from = "given" if expected else ""
        if entries is not None:
            expected = pick_checksum(entries, names)
            if expected is None:
                raise _err(CHECKSUM_MISMATCH,
                           f"{sums_url} has no SHA-256 for {names[0]}",
                           "The checksum file does not list this file name, so the "
                           "download could not be verified. Give the SHA-256 directly.")
            expected_from = sums_url or ""
        etag = headers.get("etag")
        return Plan(req, url, final, dest, self.local_path(dest), total, etag,
                    headers.get("last-modified"),
                    headers.get("accept-ranges", "").lower() == "bytes",
                    expected, expected_from, allow_http, names)

    def with_unique_name(self, plan: Plan) -> Plan:
        """Same plan, saved as name-1.iso, name-2.iso ... (keep both)."""
        stem, ext = posixpath.splitext(plan.dest)
        for i in range(1, 1000):
            dest = f"{stem}-{i}{ext}"
            local = self.local_path(dest)
            if not os.path.exists(local) and not os.path.exists(local + ".part"):
                plan.dest, plan.local = dest, local
                plan.names.append(posixpath.basename(dest))
                return plan
        raise _err(EXISTS, f"too many files named {plan.dest}")

    # -- phase 2a: the file is already there --------------------------------
    def check_existing(self, plan: Plan, progress: ProgressFn | None = None,
                       cancel=None) -> DownloadResult | None:
        """If the destination exists and matches the expected SHA-256, use it."""
        if not plan.expected or not plan.exists:
            return None
        hasher = hashlib.sha256()
        meter = _Meter(progress, None, os.path.getsize(plan.local), 0)
        size = _hash_file(plan.local, hasher, None, meter, cancel)
        digest = hasher.hexdigest()
        if digest != plan.expected:
            return None
        if self.reporter:
            self.reporter.download_start(plan.url, plan.dest)
            self.reporter.download_done(plan.dest, size, digest)
            self.reporter.verify_ok(digest)
        return DownloadResult(plan.dest, plan.local, size, digest, plan.expected, reused=True)

    # -- phase 2b: download --------------------------------------------------
    def _check_space(self, plan: Plan, need: int) -> None:
        folder = os.path.dirname(plan.local)
        if plan.total is not None and self.fs_type is not None:
            fs = self.fs_type(self.data_root)
            if fs in ("vfat", "msdos") and plan.total > FAT32_MAX_FILE:
                raise _err(NO_SPACE, f"{_human(plan.total)} is too big for a FAT32 data partition",
                           "FAT32 cannot hold files of 4 GiB or more. Reinstall the stick "
                           "with exFAT (the default) to use large ISOs.")
        if need <= 0:
            return
        try:
            st = os.statvfs(folder)
        except OSError:
            return
        free = st.f_bavail * st.f_frsize
        if free < need + SPACE_MARGIN:
            raise _err(NO_SPACE, f"needs {_human(need)}, only {_human(free)} free on the stick",
                       "Delete some files from the stick (from any computer) and try again.")

    def _read_meta(self, path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                meta = json.load(f)
            return meta if isinstance(meta, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_meta(self, path: str, plan: Plan) -> None:
        meta = {"url": plan.url, "etag": plan.etag, "last_modified": plan.last_modified,
                "total": plan.total}
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(meta, f)
        except OSError as e:
            raise self._write_error(e, path) from None

    @staticmethod
    def _write_error(e: OSError, path: str) -> BeastNetError:
        if e.errno in (errno.ENOSPC, errno.EFBIG, errno.EDQUOT):
            return _err(NO_SPACE, f"the stick is full ({os.strerror(e.errno)})")
        if e.errno == errno.EROFS:
            return _err(MOUNT, "the data partition is mounted read-only")
        return _err(MOUNT, f"cannot write {path}: {e.strerror or e}")

    def fetch(self, plan: Plan, progress: ProgressFn | None = None, cancel=None,
              *, overwrite: bool = False) -> DownloadResult:
        if plan.exists and not overwrite:
            raise _err(EXISTS, f"{plan.dest} already exists")
        part, meta_path = plan.local + ".part", plan.local + ".part.json"
        try:
            os.makedirs(os.path.dirname(plan.local), exist_ok=True)
        except OSError as e:
            raise self._write_error(e, os.path.dirname(plan.local)) from None
        if self.reporter:
            self.reporter.download_start(plan.url, plan.dest)
        if progress:
            progress(Progress("connect", 0, plan.total))

        hasher = hashlib.sha256()
        offset = 0
        meta = self._read_meta(meta_path)
        same_file = (meta.get("url") == plan.url and meta.get("total") == plan.total
                     and meta.get("etag") == plan.etag
                     and meta.get("last_modified") == plan.last_modified)
        if os.path.exists(part) and same_file:
            size = os.path.getsize(part)
            if plan.total is None or size <= plan.total:
                meter = _Meter(progress, None, size, 0)
                offset = _hash_file(part, hasher, size, meter, cancel)
        if offset == 0:
            hasher = hashlib.sha256()
        self._check_space(plan, (plan.total - offset) if plan.total is not None else 0)
        self._write_meta(meta_path, plan)
        meter = _Meter(progress, self.reporter, plan.total, offset)

        # If-Range needs a strong validator: a strong ETag, else Last-Modified.
        validator = plan.etag if plan.etag and not plan.etag.startswith("W/") else plan.last_modified
        url = plan.final_url
        attempt = 0
        tried_original = url == plan.url
        try:
            f = open(part, "r+b" if os.path.exists(part) else "w+b")
        except OSError as e:
            raise self._write_error(e, part) from None
        with f:
            f.seek(offset)
            f.truncate(offset)
            while True:
                try:
                    headers = {}
                    if offset:
                        headers["Range"] = f"bytes={offset}-"
                        if validator:
                            headers["If-Range"] = validator
                    resp, url = self.http.get(url, headers, allow_http=plan.allow_http)
                    try:
                        action = self._check_response(resp, plan, offset)
                        meter.total = plan.total
                        if action != "append":
                            offset = 0
                            hasher = hashlib.sha256()
                            f.seek(0)
                            f.truncate(0)
                            if action == "retry":
                                raise _Retry("the server could not resume; starting again")
                        self._stream(resp, plan, f, hasher, meter, cancel)
                    finally:
                        resp.close()
                    offset = f.tell()
                    if plan.total is not None and offset != plan.total:
                        raise _Retry(f"connection closed at {offset} of {plan.total} bytes")
                    break
                except (_Retry, BeastNetError) as e:
                    offset = f.tell()  # everything written so far is hashed and kept
                    if isinstance(e, BeastNetError) and not getattr(e, "retryable", False):
                        if e.code == HTTP and not tried_original:
                            # A redirect target can expire (signed mirror links): start over
                            # from the link the user gave.
                            tried_original, url = True, plan.url
                            continue
                        raise
                    attempt += 1
                    text = e.text if isinstance(e, BeastNetError) else str(e)
                    if attempt > self.retries:
                        raise _err(HTTP, f"download kept failing: {text}",
                                   "The partial download is kept; try again to resume it.") from None
                    if progress:
                        progress(Progress("retry", offset, plan.total, note=text))
                    self.sleep(self.retry_delays[min(attempt - 1, len(self.retry_delays) - 1)])
            meter.update(offset, force=True)
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError as e:
                raise self._write_error(e, part) from None

        digest = hasher.hexdigest()
        if self.reporter:
            self.reporter.download_done(plan.dest, offset, digest)
        if plan.expected:
            if progress:
                progress(Progress("verify", offset, plan.total))
            if digest != plan.expected:
                if self.reporter:
                    self.reporter.verify_fail(plan.expected, digest)
                for p in (part, meta_path):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
                raise _err(CHECKSUM_MISMATCH,
                           f"SHA-256 of {plan.dest} does not match: expected {plan.expected}, got {digest}",
                           "The file was deleted. Check that the checksum belongs to this "
                           "ISO; if it does, the download was damaged or tampered with.")
            if self.reporter:
                self.reporter.verify_ok(digest)
        try:
            os.replace(part, plan.local)
        except OSError as e:
            raise self._write_error(e, plan.local) from None
        _fsync_dir(os.path.dirname(plan.local))
        try:
            os.unlink(meta_path)
        except OSError:
            pass
        return DownloadResult(plan.dest, plan.local, offset, digest, plan.expected)

    def _check_response(self, resp, plan: Plan, offset: int) -> str:
        """What to do with a data response: "append" its body at ``offset``,
        "restart" (store its body from byte 0) or "retry" (start again with a
        new request)."""
        host = urlsplit(plan.final_url).hostname or ""
        if offset and resp.status == 206:
            m = re.match(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", resp.getheader("Content-Range") or "")
            total = None if not m or m.group(3) == "*" else int(m.group(3))
            if m and int(m.group(1)) == offset and (plan.total is None or total == plan.total):
                return "append"
            return "retry"
        if resp.status == 200:
            length = resp.getheader("Content-Length")
            if length is not None and length.isdigit() and int(length) != plan.total:
                plan.total = int(length)  # the file changed on the server
                self._check_space(plan, plan.total)
            return "restart" if offset else "append"
        if resp.status == 416 and offset:
            return "retry"
        raise _status_error(resp, host)

    def _stream(self, resp, plan: Plan, f, hasher, meter: _Meter, cancel) -> None:
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            try:
                buf = resp.read(self.chunk)
            except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                if isinstance(e, http.client.IncompleteRead) and e.partial:
                    self._write(f, e.partial, hasher)
                raise _Retry(f"{e.__class__.__name__}: {e}") from None
            if not buf:
                return
            self._write(f, buf, hasher)
            done = f.tell()
            if plan.total is not None and done > plan.total:
                raise _err(HTTP, "the server sent more data than it announced")
            meter.update(done)

    def _write(self, f, buf: bytes, hasher) -> None:
        try:
            f.write(buf)
        except OSError as e:
            raise self._write_error(e, f.name) from None
        hasher.update(buf)

    # -- everything, for script mode ------------------------------------------
    def download(self, req: DownloadRequest, progress: ProgressFn | None = None,
                 cancel=None) -> DownloadResult:
        plan = self.prepare(req)
        if plan.exists:
            reused = self.check_existing(plan, progress, cancel)
            if reused is not None:
                return reused
            if not req.overwrite:
                raise _err(EXISTS, f"{plan.dest} already exists and is not the requested file",
                           'Set "overwrite": true in the plan to replace it.')
        return self.fetch(plan, progress, cancel, overwrite=True)


def mount_fs_type(proc_dir: str) -> Callable[[str], str | None]:
    """fs_type callback for Downloader: the filesystem type mounted at a path."""
    def fs_type(path: str) -> str | None:
        best, best_type = "", None
        try:
            with open(os.path.join(proc_dir, "mounts"), encoding="utf-8") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 3:
                        continue
                    mnt = fields[1].replace("\\040", " ")
                    if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
                        best, best_type = mnt, fields[2]
        except OSError:
            return None
        return best_type
    return fs_type
