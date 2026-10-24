"""dist/ manifest verification: any problem -> error, nothing written."""

import hashlib
import json

import pytest

from beastbooter.dist import load_dist
from beastbooter.errors import BeastError
from conftest import fresh_image, needs_tools, run_cli
from fakedist import write_manifest

pytestmark = needs_tools


def install(img, dist):
    return run_cli("install", "--image", img, "--size", "1G", "--yes", "--quiet", "--dist", dist)


def edit_manifest(dist, fn):
    m = json.loads((dist / "manifest.json").read_text())
    fn(m)
    (dist / "manifest.json").write_text(json.dumps(m))


def check_fails(tmp_path, dist, capsys, match):
    img = tmp_path / "out" / "x.img"
    assert install(img, dist) == 1
    err = capsys.readouterr().err
    assert match in err, err
    assert "Traceback" not in err
    assert not img.exists()
    return err


def test_good_dist_loads(fake_dist, tmp_path):
    d = load_dist(fake_dist, tmp_path / "stage")
    assert d.version == "0.1.0" and len(d.boot_img) == 512
    assert "EFI/BOOT/BOOTX64.EFI" in d.esp_files()


def test_missing_required_file(dist_copy, tmp_path, capsys):
    (dist_copy / "esp/EFI/BOOT/grubx64.efi").unlink()
    check_fails(tmp_path, dist_copy, capsys, "esp/EFI/BOOT/grubx64.efi: missing")


def test_required_file_not_in_manifest(dist_copy, tmp_path, capsys):
    edit_manifest(dist_copy, lambda m: m["files"].pop("esp/EFI/BOOT/mmx64.efi"))
    check_fails(tmp_path, dist_copy, capsys, "mmx64.efi: required file not listed")


def test_sha_mismatch(dist_copy, tmp_path, capsys):
    (dist_copy / "esp/grub/grub.cfg").write_text("tampered\n")
    err = check_fails(tmp_path, dist_copy, capsys, "esp/grub/grub.cfg: sha256 mismatch")
    assert "nothing was written" in err


def test_sha_mismatch_bios(dist_copy, tmp_path, capsys):
    p = dist_copy / "bios/core.img"
    p.write_bytes(p.read_bytes() + b"x")
    check_fails(tmp_path, dist_copy, capsys, "bios/core.img: sha256 mismatch")


def test_unlisted_file(dist_copy, tmp_path, capsys):
    (dist_copy / "esp/EFI/BOOT/extra.efi").write_bytes(b"unexplained binary")
    check_fails(tmp_path, dist_copy, capsys, "extra.efi: present in dist but not listed")


def test_fallback_loader_forbidden(dist_copy, tmp_path, capsys):
    (dist_copy / "esp/EFI/BOOT/fbx64.efi").write_bytes(b"fallback")
    write_manifest(dist_copy)
    check_fails(tmp_path, dist_copy, capsys, "fbx64.efi: must not be shipped")


@pytest.mark.parametrize("content,match", [("{not json", "cannot read"), ('{"schema": 2, "files": {}}', "unsupported manifest"),
                                           ('{"schema": 1, "files": {"../x": {"sha256": "0"}}}', "invalid file path")])
def test_bad_manifest(dist_copy, tmp_path, capsys, content, match):
    (dist_copy / "manifest.json").write_text(content)
    check_fails(tmp_path, dist_copy, capsys, match)


def test_missing_manifest_and_dir(dist_copy, tmp_path, capsys):
    (dist_copy / "manifest.json").unlink()
    check_fails(tmp_path, dist_copy, capsys, "manifest.json is missing")
    check_fails(tmp_path, tmp_path / "nope", capsys, "dist directory not found")


def test_core_too_big_for_gpt(dist_copy, tmp_path, capsys):
    (dist_copy / "bios/core.img").write_bytes(b"\1" * (2014 * 512 + 1))
    write_manifest(dist_copy)
    img = tmp_path / "g.img"
    assert run_cli("install", "--image", img, "--size", "1G", "--layout", "gpt", "--yes", "--dist", dist_copy) == 1
    assert "only 2014 fit" in capsys.readouterr().err
    assert not img.exists()
    assert install(img, dist_copy) == 0  # fits the MBR gap (2047 sectors)


def test_bad_dist_leaves_existing_image_untouched(dist_copy, tmp_path, capsys, fake_dist):
    img = fresh_image(tmp_path, fake_dist, "msdos", "exfat", "1G")
    before = hashlib.sha256(img.read_bytes()).hexdigest()
    (dist_copy / "esp/grub/beast/main.cfg").write_text("evil\n")
    assert install(img, dist_copy) == 1
    assert run_cli("update", "--image", img, "--quiet", "--dist", dist_copy) == 1
    assert "sha256 mismatch" in capsys.readouterr().err
    assert hashlib.sha256(img.read_bytes()).hexdigest() == before


def test_staging_uses_verified_copy(dist_copy, tmp_path):
    d = load_dist(dist_copy, tmp_path / "stage")
    (dist_copy / "esp/grub/grub.cfg").write_text("changed after verification\n")
    assert (d.esp_dir / "grub/grub.cfg").read_text() != "changed after verification\n"


def test_installer_owned_files_not_taken_from_dist(dist_copy, tmp_path):
    (dist_copy / "esp/grub/beast/device.cfg").write_text('set bb_data_uuid="evil"\n')
    write_manifest(dist_copy)
    d = load_dist(dist_copy, tmp_path / "stage")
    assert "grub/beast/device.cfg" not in d.esp_files()


def test_verification_error_type(dist_copy, tmp_path):
    (dist_copy / "bios/boot.img").unlink()
    with pytest.raises(BeastError):
        load_dist(dist_copy, tmp_path / "stage")
