"""beast-booter installer: create and update beast-booter USB drives and images."""

from pathlib import Path as _Path


def _read_version() -> str:
    version_file = _Path(__file__).resolve().parents[2] / "VERSION"
    try:
        return version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


__version__ = _read_version()
