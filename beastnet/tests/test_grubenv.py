"""The grubenv writer must be byte-compatible with GRUB's own grub-editenv."""

import os
import subprocess

import pytest

from beastnet import grubenv
from beastnet.errors import BeastNetError
from bn_helpers import have

pytestmark = pytest.mark.skipif(not have("grub-editenv"), reason="grub-editenv not installed")


def editenv(path, *args):
    return subprocess.run(["grub-editenv", str(path), *args], check=True, capture_output=True,
                          text=True).stdout


def create(path):
    editenv(path, "create")
    return path


def ours(path, op, key, value=None):
    env = grubenv.load(str(path))
    if op == "set":
        env.set(key, value)
    else:
        env.unset(key)
    grubenv.save(str(path), env)


OPS = [
    ("set", "a", "1"),
    ("set", "saved_entry", "Ubuntu"),
    ("set", "a", "a much longer value than before"),
    ("set", "back", "C:\\path\\with\\backslashes"),
    ("set", "nl", "line one\nline two"),
    ("set", "a", "s"),
    ("unset", "saved_entry", None),
    ("set", "bb_oneshot", "/downloads/ubuntu-26.04-desktop-amd64.iso"),
    ("unset", "nl", None),
    ("set", "empty", ""),
    ("set", "utf8", "Café"),
    ("unset", "does_not_exist", None),
]


def test_same_bytes_as_grub_editenv(tmp_path):
    a, b = create(tmp_path / "a"), create(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()
    for op, key, value in OPS:
        if op == "set":
            editenv(a, "set", f"{key}={value}")
        else:
            editenv(a, "unset", key)
        ours(b, op, key, value)
        assert a.read_bytes() == b.read_bytes(), (op, key, value)
        assert len(b.read_bytes()) == 1024


def test_reads_what_grub_editenv_wrote(tmp_path):
    p = create(tmp_path / "env")
    for _op, key, value in OPS:
        if value is not None:
            editenv(p, "set", f"{key}={value}")
    env = grubenv.load(str(p))
    expected = {}
    for _op, key, value in OPS:
        if value is not None:
            expected[key] = value
    assert dict(env.items()) == expected


def test_round_trip_keeps_comment_lines(tmp_path):
    # GRUB 2.12+ writes a "# WARNING: ..." comment line after the signature.
    p = create(tmp_path / "env")
    assert grubenv.GrubEnv(p.read_bytes()).to_bytes() == p.read_bytes()
    assert grubenv.GrubEnv().to_bytes() == b"# GRUB Environment Block\n" + b"#" * 999


def test_set_oneshot_keeps_existing_keys(tmp_path):
    p = create(tmp_path / "grubenv")
    editenv(p, "set", "saved_entry=2", "bb_theme=dark")
    ino = os.stat(p).st_ino
    grubenv.set_oneshot(str(p), "/downloads/x.iso")
    assert os.stat(p).st_ino == ino  # rewritten in place
    assert editenv(p, "list").splitlines() == ["saved_entry=2", "bb_theme=dark",
                                               "bb_oneshot=/downloads/x.iso"]
    grubenv.set_oneshot(str(p), "/downloads/other.iso")
    assert "bb_oneshot=/downloads/other.iso" in editenv(p, "list").splitlines()
    grubenv.clear_oneshot(str(p))
    assert editenv(p, "list").splitlines() == ["saved_entry=2", "bb_theme=dark"]


def test_missing_file(tmp_path):
    with pytest.raises(BeastNetError) as e:
        grubenv.set_oneshot(str(tmp_path / "nope"), "/downloads/x.iso")
    assert e.value.code == "grubenv"


def test_wrong_size(tmp_path):
    p = tmp_path / "grubenv"
    p.write_bytes(b"# GRUB Environment Block\n" + b"#" * 100)
    with pytest.raises(BeastNetError) as e:
        grubenv.set_oneshot(str(p), "/downloads/x.iso")
    assert e.value.code == "grubenv" and "1024" in e.value.text
    assert p.read_bytes() == b"# GRUB Environment Block\n" + b"#" * 100


def test_bad_signature(tmp_path):
    p = tmp_path / "grubenv"
    p.write_bytes(b"x" * 1024)
    with pytest.raises(BeastNetError) as e:
        grubenv.load(str(p))
    assert e.value.code == "grubenv"


def test_full_block(tmp_path):
    p = create(tmp_path / "grubenv")
    editenv(p, "set", "filler=" + "x" * 900)
    with pytest.raises(BeastNetError) as e:
        grubenv.set_oneshot(str(p), "/downloads/" + "y" * 100 + ".iso")
    assert e.value.code == "grubenv"
    assert editenv(p, "list").startswith("filler=")  # untouched
