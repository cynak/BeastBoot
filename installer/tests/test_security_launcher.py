"""bin/beast-boot runs as root (sudo) from any folder: Python must not import
modules from the current directory (a planted json.py on a USB stick or in
Downloads would run as root)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
LAUNCHER = REPO / "bin" / "beast-boot"

pytestmark = pytest.mark.skipif(os.name == "nt" or shutil.which("sh") is None or shutil.which("python3") is None,
                                reason="POSIX sh launcher with python3 on PATH")


@pytest.mark.parametrize("planted", ["json.py", "argparse.py", "beastbooter/__init__.py"])
def test_launcher_ignores_modules_in_the_current_directory(tmp_path, planted):
    hostile = tmp_path / "usb-data"
    marker = tmp_path / "pwned"
    module = hostile / planted
    module.parent.mkdir(parents=True)
    module.write_text(f"open({str(marker)!r}, 'w').close()\nraise SystemExit(99)\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = str(hostile)  # sudo -E keeps it: must not count either
    p = subprocess.run(["sh", str(LAUNCHER), "--help"], cwd=hostile, env=env, capture_output=True, text=True,
                       timeout=60)
    assert not marker.exists(), f"{planted} from the current directory was imported"
    assert p.returncode == 0, p.stderr
    assert "beast-boot" in p.stdout
