"""bb-dev: development and debugging helpers for beast-boot."""

from pathlib import Path as _Path

try:
    __version__ = (_Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
except OSError:
    __version__ = "0.0.0"
