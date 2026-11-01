"""beast-boot runs as root: a path it writes (--image, --progress-file, the
.part files of `firmware fetch`) must not follow a symlink someone planted
there, or root truncates and overwrites whatever the link points to."""

from __future__ import annotations

import os

import pytest

from beastbooter import commands, firmware
from beastbooter.blockio import ImageTarget
from beastbooter.errors import BeastError
from beastbooter.events import ProgressFile

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt",
                                reason="needs unprivileged symlinks")

SECRET = b"root:secret-hash:19000:0:99999:7:::\n"


@pytest.fixture
def planted(tmp_path):
    """(victim file, symlink to it in a 'shared' folder)."""
    victim = tmp_path / "etc-shadow"
    victim.write_bytes(SECRET)
    shared = tmp_path / "shared"
    shared.mkdir()
    link = shared / "x.img"
    link.symlink_to(victim)
    return victim, link


def test_image_create_refuses_a_symlink(planted):
    victim, link = planted
    with pytest.raises(BeastError, match="link"):
        ImageTarget.create(str(link), 1 << 20)
    assert victim.read_bytes() == SECRET


def test_image_create_refuses_a_dangling_symlink(tmp_path):
    target = tmp_path / "new-file"
    link = tmp_path / "x.img"
    link.symlink_to(target)
    with pytest.raises(BeastError, match="link"):
        ImageTarget.create(str(link), 1 << 20)
    assert not target.exists()


def test_image_create_refuses_a_hard_link(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(SECRET)
    link = tmp_path / "x.img"
    os.link(victim, link)
    with pytest.raises(BeastError, match="link"):
        ImageTarget.create(str(link), 1 << 20)
    assert victim.read_bytes() == SECRET


def test_image_create_still_overwrites_a_regular_file(tmp_path):
    img = tmp_path / "x.img"
    img.write_bytes(b"old contents")
    with ImageTarget.create(str(img), 4096) as t:
        assert t.read(0, 12) == bytes(12)
    assert img.stat().st_size == 4096


@pytest.mark.parametrize("writable", [True, False])
def test_image_open_refuses_a_symlink(planted, writable):
    victim, link = planted
    with pytest.raises(BeastError, match="link"):
        ImageTarget(str(link), writable=writable)
    assert victim.read_bytes() == SECRET


def test_image_path_check_uses_lstat(planted):
    _victim, link = planted
    with pytest.raises(BeastError, match="link"):
        commands._image_path_check(str(link), True)
    with pytest.raises(BeastError, match="link"):
        commands._existing_image(str(link))


def test_install_image_on_a_symlink_leaves_the_target_alone(planted, fake_dist):
    from conftest import run_cli

    victim, link = planted
    assert run_cli("install", "--image", link, "--size", "1100000001", "--dist", fake_dist, "--yes") == 1
    assert victim.read_bytes() == SECRET
    assert link.is_symlink()


def test_progress_file_refuses_a_symlink(planted):
    victim, link = planted
    with pytest.raises(BeastError, match="link"):
        ProgressFile(str(link))
    assert victim.read_bytes() == SECRET


def test_progress_file_appends_to_a_regular_file(tmp_path):
    p = tmp_path / "progress.jsonl"
    p.write_text("x\n")
    f = ProgressFile(str(p))
    f.emit("warning", message="hi")
    f.close()
    assert p.read_text().startswith("x\n{")
    new = tmp_path / "new.jsonl"
    ProgressFile(str(new)).close()
    assert new.exists()


def test_fetch_part_file_does_not_follow_a_planted_link(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(SECRET)
    out = tmp_path / "out"
    out.mkdir()
    (out / "pack.cpio.part").symlink_to(victim)
    firmware._replace_atomically(str(out / "pack.cpio"), lambda f: f.write(b"cpio"))
    assert victim.read_bytes() == SECRET
    assert (out / "pack.cpio").read_bytes() == b"cpio"
    assert not (out / "pack.cpio").is_symlink()
    assert sorted(p.name for p in out.iterdir()) == ["pack.cpio"]
