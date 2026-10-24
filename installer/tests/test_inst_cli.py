"""CLI behaviour: sizes, usage errors, clean error output, --quiet."""

import os
import subprocess
import sys

import pytest

from beastbooter.errors import BeastError
from beastbooter.util import parse_size
from conftest import HERE, needs_tools, run_cli

ENV = {**os.environ, "PYTHONPATH": str(HERE.parent)}


def cli(*args):
    return subprocess.run([sys.executable, "-m", "beastbooter", *map(str, args)],
                          capture_output=True, text=True, env=ENV)


@pytest.mark.parametrize("text,value", [
    ("256M", 256 << 20), ("8G", 8 << 30), ("8g", 8 << 30), ("1T", 1 << 40), ("512K", 512 << 10),
    ("300000001", 300000001), ("2GiB", 2 << 30), ("64MB", 64 << 20), (" 1G ", 1 << 30),
])
def test_parse_size(text, value):
    assert parse_size(text) == value


@pytest.mark.parametrize("text", ["", "abc", "1.5G", "-1G", "0", "12X", "G"])
def test_parse_size_invalid(text):
    with pytest.raises(BeastError):
        parse_size(text)


def test_expected_errors_have_no_traceback(tmp_path):
    p = cli("install", "--image", tmp_path / "x.img", "--size", "10M", "--yes", "--dist", tmp_path)
    assert p.returncode == 1
    assert p.stderr.startswith("beast-booter: error:") and "Traceback" not in p.stderr
    assert len(p.stderr.strip().splitlines()) == 1


def test_usage_errors(tmp_path):
    p = cli("install", "--image", tmp_path / "x.img")
    assert p.returncode == 2 and "needs --size" in p.stderr
    p = cli("install", "--device", "/nonexistent/sdx", "--size", "1G")
    assert p.returncode == 2 and "only valid with --image" in p.stderr
    p = cli("install", "--device", "/a", "--image", "/b", "--size", "1G")
    assert p.returncode == 2
    p = cli("info")
    assert p.returncode == 2
    p = cli("install", "--image", tmp_path / "x.img", "--size", "1G", "--fs", "ext4")
    assert p.returncode == 2 and "invalid choice" in p.stderr
    assert not (tmp_path / "x.img").exists()


def test_version_and_help():
    p = cli("--version")
    assert p.returncode == 0 and p.stdout.startswith("beast-booter ")
    p = cli("install", "--help")
    assert p.returncode == 0 and "--allow-fixed-disk" in p.stdout and "--serial-console" in p.stdout


@needs_tools
def test_quiet_and_progress(tmp_path, fake_dist):
    p = cli("install", "--image", tmp_path / "a.img", "--size", "1G", "--yes", "--quiet", "--dist", fake_dist)
    assert p.returncode == 0, p.stderr
    assert p.stdout == "" and p.stderr == ""
    p = cli("install", "--image", tmp_path / "b.img", "--size", "1G", "--yes", "--dist", fake_dist)
    assert p.returncode == 0
    assert p.stdout == ""  # progress goes to stderr; stdout stays clean
    assert p.stderr.count("==> ") >= 5 and "done:" in p.stderr


def test_device_missing_is_clean_error(capsys):
    assert run_cli("info", "--device", "/nonexistent/sdx") == 1
    assert "does not exist" in capsys.readouterr().err


@needs_tools
def test_bin_wrapper(tmp_path, fake_dist):
    wrapper = HERE.parents[1] / "bin" / "beast-booter"
    p = subprocess.run(["sh", str(wrapper), "--version"], capture_output=True, text=True)
    assert p.returncode == 0 and "beast-booter" in p.stdout
