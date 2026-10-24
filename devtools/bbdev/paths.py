"""Repo paths and the development environment for bb-dev commands.

scripts/dev-env.sh is the single source of truth for the environment
(PATH with .tools/bin, BB_* firmware and GRUB directories). load_env() sources
it in bash and returns the resulting environment, so bb-dev works without the
user sourcing anything first.
"""

from __future__ import annotations

import functools
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "out"
DEV_OUT = OUT / "dev"          # dev images: out/dev/<name>.img
VM_OUT = OUT / "vm"            # per-image VM state: out/vm/<image stem>/
DEFAULT_IMAGE = DEV_OUT / "beast-booter-dev.img"
DIST = REPO / "dist"
KEYS = REPO / "keys"
GRUB_SRC = REPO / "grub"


@functools.lru_cache(maxsize=1)
def load_env() -> dict[str, str]:
    """Environment after `source scripts/dev-env.sh`, as a dict."""
    script = REPO / "scripts" / "dev-env.sh"
    out = subprocess.run(
        ["bash", "-c", f'source "{script}" >/dev/null && env -0'],
        check=True, capture_output=True,
    ).stdout
    env = {}
    for item in out.split(b"\0"):
        if b"=" in item:
            key, _, value = item.partition(b"=")
            env[key.decode()] = value.decode(errors="surrogateescape")
    return env


def vm_state_dir(image: Path) -> Path:
    """Directory holding firmware vars and logs for one image."""
    d = VM_OUT / Path(image).stem
    d.mkdir(parents=True, exist_ok=True)
    return d
