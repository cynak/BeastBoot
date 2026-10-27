"""The rename beast-booter -> beast-boot must not orphan drives made by 0.1.x/0.2.0.

On-disk names keep the old spelling (marker file and magic, the user's config
folder on the data partition, esp/beast-booter/ for wimboot and WinPE, the
host's update-recovery folder). The marker parser also accepts the new spelling.
"""
from __future__ import annotations

from pathlib import Path

import fakedist
from conftest import fresh_image, info_json, run_cli, sha_region

from beastbooter import esp as esp_mod
from beastbooter.blockio import ImageTarget
from beastbooter.fatfs import FatVolume
from beastbooter.layout import DATA_HIDDEN_DIRS, ESP_MARKER_PATH, SECTOR_SIZE, USER_CONFIG_PATH
from beastbooter.platforms import linux

REPO = Path(__file__).resolve().parents[2]
# BEAST-BOOTER.ID exactly as 0.2.0 wrote it (esp.render_marker at v0.2.0).
MARKER_0_2_0 = "beast-booter\ninstall_id={id}\nlayout_version=2\nversion=0.2.0\n"


def test_on_disk_names_match_0_2_0():
    assert ESP_MARKER_PATH == "BEAST-BOOTER.ID"
    assert esp_mod.MARKER_MAGIC == "beast-booter"
    assert USER_CONFIG_PATH == "beast-booter/config.cfg"
    assert "beast-booter" in DATA_HIDDEN_DIRS
    assert linux.STATE_DIR == "/var/lib/beast-booter"
    # GRUB reads the same paths
    main = (REPO / "grub/beast/main.cfg").read_text()
    lib = (REPO / "grub/beast/lib.cfg").read_text()
    assert f'"($bb_data)/{USER_CONFIG_PATH}"' in main
    assert '"($bb_esp)/beast-booter/wimboot"' in lib and 'bb_w="($bb_esp)/beast-booter"' in lib
    assert "esp/beast-booter/wimboot" in (REPO / "build/build.sh").read_text()


def test_marker_render_and_parse_both_spellings():
    text = esp_mod.render_marker("abc", "0.3.0")
    assert text.splitlines()[0] == "beast-booter"
    assert esp_mod.parse_marker(MARKER_0_2_0.format(id="x"))["version"] == "0.2.0"
    assert esp_mod.parse_marker("beast-boot\ninstall_id=y\nlayout_version=2\n")["install_id"] == "y"
    assert esp_mod.parse_marker("beastboot\ninstall_id=y\n") is None


def _esp(t, img):
    return FatVolume(t, info_json(img)["esp"]["start_lba"] * SECTOR_SIZE)


def _mark(img, text: str) -> None:
    with ImageTarget(img, writable=True) as t:
        _esp(t, img).write_file(ESP_MARKER_PATH, text.encode())


def _update_keeps_drive(tmp_path, dist, magic: str) -> None:
    img = fresh_image(tmp_path, dist, "msdos", "exfat")  # dist: 0.2.0's version.cfg
    install_id = info_json(img)["install_id"]
    _mark(img, MARKER_0_2_0.format(id=install_id).replace("beast-booter", magic))
    j = info_json(img)
    assert (j["version"], j["layout_version"]) == ("0.2.0", 2)
    data = sha_region(img, j["data"]["start_lba"], j["data"]["size_lba"])
    new_dist = fakedist.make_fake_dist(tmp_path / "dist-0.3.0", "0.3.0")
    assert run_cli("update", "--image", img, "--dist", new_dist, "--yes", "--quiet") == 0
    assert info_json(img)["version"] == "0.3.0"
    assert sha_region(img, j["data"]["start_lba"], j["data"]["size_lba"]) == data
    with ImageTarget(img, writable=False) as t:
        new = esp_mod.parse_marker(_esp(t, img).read_file(ESP_MARKER_PATH).decode())
        raw = _esp(t, img).read_file(ESP_MARKER_PATH).decode()
    assert raw.startswith("beast-booter\n")
    assert new["install_id"] == install_id == info_json(img)["install_id"]


def test_update_a_0_2_0_drive(tmp_path, fake_dist_v2):
    _update_keeps_drive(tmp_path, fake_dist_v2, "beast-booter")


def test_update_a_drive_with_the_new_spelling(tmp_path, fake_dist_v2):
    _update_keeps_drive(tmp_path, fake_dist_v2, "beast-boot")
