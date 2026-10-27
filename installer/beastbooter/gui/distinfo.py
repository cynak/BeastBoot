"""Find the boot files (dist/), summarise their manifest, and re-verify them.

Where the boot files are looked for, first match wins:

1. the GUI's --dist argument
2. the BEAST_BOOTER_DIST environment variable
3. payload/dist next to the app folder (the portable package:
   <package>/app/beast_booter_launch.py and <package>/payload/dist/)
4. <repo>/dist (a source checkout: <repo>/installer/beast_booter_launch.py)

An explicit choice (1 or 2) that does not exist is reported as missing; the
GUI does not silently fall back to some other copy of the boot files.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..layout import DIST_ESP_DIR, DIST_MANIFEST

ENV_DIST = "BEAST_BOOTER_DIST"
CERT_FILE = "ENROLL_THIS_KEY_IN_MOKMANAGER.cer"


def app_dir() -> Path:
    """The folder holding beast_booter_launch.py and the beastbooter package."""
    return Path(__file__).resolve().parents[2]


def launcher_path() -> Path:
    """Absolute path of the self-contained CLI entry point the GUI runs."""
    return app_dir() / "beast_booter_launch.py"


@dataclass(frozen=True)
class DistLocation:
    path: Path | None  # None: nothing found
    source: str  # "--dist", ENV_DIST, "portable package", "source checkout", "not found"
    searched: tuple[Path, ...] = ()

    @property
    def exists(self) -> bool:
        return self.path is not None and self.path.exists()


def find_dist(cli_value: str | None, environ: dict | None = None, base: Path | None = None) -> DistLocation:
    environ = os.environ if environ is None else environ
    base = app_dir() if base is None else Path(base)
    if cli_value:
        return DistLocation(Path(cli_value).expanduser().resolve(), "--dist")
    env_value = environ.get(ENV_DIST)
    if env_value:
        return DistLocation(Path(env_value).expanduser().resolve(), ENV_DIST)
    candidates = (
        (base.parent / "payload" / "dist", "portable package"),
        (base.parent / "dist", "source checkout"),
    )
    for path, source in candidates:
        if path.is_dir():
            return DistLocation(path.resolve(), source, tuple(p for p, _ in candidates))
    return DistLocation(None, "not found", tuple(p for p, _ in candidates))


def mok_fingerprint(sha1_hex: str) -> tuple[str, str]:
    """The SHA-1 fingerprint as MokManager's "View key" shows it: 20 hex pairs in two rows."""
    h = sha1_hex.replace(":", "").replace(" ", "").upper()
    if len(h) != 40 or any(c not in "0123456789ABCDEF" for c in h):
        raise ValueError(f"not a SHA-1 hex digest: {sha1_hex!r}")
    pairs = [h[i : i + 2] for i in range(0, 40, 2)]
    return " ".join(pairs[:10]), " ".join(pairs[10:])


def colon_hex(hex_digest: str) -> str:
    """'c7ad96...' -> 'C7:AD:96:...' (the openssl -fingerprint format)."""
    h = hex_digest.upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


@dataclass(frozen=True)
class DistSummary:
    path: Path | None
    ok: bool  # manifest readable
    error: str | None = None
    version: str = ""
    build_id: str = ""
    file_count: int = 0
    cert_subject: str = ""
    cert_sha1: str = ""  # lowercase hex, "" if unknown
    cert_sha256: str = ""
    cert_from_file: bool = False  # fingerprints computed from the .cer file itself
    warnings: tuple[str, ...] = field(default_factory=tuple)


def read_summary(loc: DistLocation) -> DistSummary:
    """Read version, build id and Secure Boot key fingerprints. Never raises."""
    if loc.path is None:
        looked = ", ".join(str(p) for p in loc.searched)
        return DistSummary(None, False, f"Boot files not found (looked in {looked}). "
                                        "Pass --dist DIR or set BEAST_BOOTER_DIST.")
    root = loc.path
    if root.is_file():
        return DistSummary(root, False, f"{root} is a file; the GUI needs an unpacked dist directory.")
    if not root.is_dir():
        return DistSummary(root, False, f"Boot files not found: {root} does not exist ({loc.source}).")
    mpath = root / DIST_MANIFEST
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return DistSummary(root, False, f"{mpath} is missing: is {root} a beast-boot dist directory?")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return DistSummary(root, False, f"Cannot read {mpath}: {e}")
    if not isinstance(manifest, dict):
        return DistSummary(root, False, f"{mpath}: not a JSON object")

    warnings: list[str] = []
    sb = manifest.get("secure_boot") if isinstance(manifest.get("secure_boot"), dict) else {}
    m_sha1 = str(sb.get("cert_sha1") or "").lower()
    m_sha256 = str(sb.get("cert_sha256") or "").lower()
    # The fingerprint the user must compare is that of the certificate file that
    # will be copied to the drive, so compute it from that file when we can.
    cert = root / DIST_ESP_DIR / CERT_FILE
    try:
        der = cert.read_bytes()
    except OSError:
        der = None
    if der is not None:
        sha1 = hashlib.sha1(der).hexdigest()  # noqa: S324 - a fingerprint, not a security hash
        sha256 = hashlib.sha256(der).hexdigest()
        if m_sha256 and m_sha256 != sha256:
            warnings.append(f"{CERT_FILE} does not match secure_boot.cert_sha256 in the manifest")
        if m_sha1 and m_sha1 != sha1:
            warnings.append(f"{CERT_FILE} does not match secure_boot.cert_sha1 in the manifest")
    else:
        sha1, sha256 = m_sha1, m_sha256
        warnings.append(f"{CERT_FILE} not found; fingerprints are taken from the manifest")
    files = manifest.get("files")
    return DistSummary(
        path=root,
        ok=True,
        version=str(manifest.get("version") or "unknown"),
        build_id=str(manifest.get("build_id") or ""),
        file_count=len(files) if isinstance(files, dict) else 0,
        cert_subject=str(sb.get("cert_subject") or ""),
        cert_sha1=sha1,
        cert_sha256=sha256,
        cert_from_file=der is not None,
        warnings=tuple(warnings),
    )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    message: str


def verify(path: Path) -> VerifyResult:
    """Check every file against manifest.json, exactly as the installer does before writing.

    Reuses dist.load_dist(); its verified copies go to a throw-away directory.
    The dist directory itself is only read.
    """
    from ..dist import load_dist
    from ..errors import BeastError

    with tempfile.TemporaryDirectory(prefix="beast-boot-verify-") as tmp:
        try:
            d = load_dist(path, os.path.join(tmp, "staging"))
        except BeastError as e:
            return VerifyResult(False, str(e))
        except OSError as e:
            return VerifyResult(False, f"cannot read the boot files: {e}")
        n = len(d.manifest.get("files", {}))
    return VerifyResult(True, f"All {n} files match manifest.json (version {d.version}).")
