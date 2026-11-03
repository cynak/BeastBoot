"""Strings read from a drive (marker, device.cfg, installed.json, device model)
must not reach the terminal with control characters: an escape sequence there
could write the clipboard (OSC 52), retitle the window or fake output."""

from __future__ import annotations

import io
import re

import pytest

from beastbooter import cli, firmware
from beastbooter.commands import format_devices, format_info
from beastbooter.errors import BeastError
from beastbooter.util import Reporter, printable

EVIL = "1.0\x1b]52;c;ZWNobyBwd25lZA==\x07\x9b2J\x7f\rfaked\x00"
CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def _clean(text: str) -> None:
    assert not CONTROL.search(text), repr(text)


def test_printable_replaces_control_characters():
    assert printable("ok äöü 日本") == "ok äöü 日本"
    assert printable("a\x1b[2Jb\x9bc\x7fd\ne\tf") == "a?[2Jb?c?d?e?f"


def test_format_info_escapes_drive_strings():
    d = {"version": EVIL, "build_id": EVIL, "install_id": EVIL, "layout": "msdos", "layout_version": EVIL,
         "disk_sectors": 2048, "bios_core_lba": 34,
         "data": {"index": 1, "start_lba": 2048, "size_lba": 2048, "fs": EVIL, "uuid": EVIL, "label": EVIL + "\nx"},
         "esp": {"index": 2, "start_lba": 4096, "size_lba": 2048}}
    out = format_info(d, "img")
    _clean(out)
    assert len(out.splitlines()) == 9  # a newline in a value adds no line


def test_format_installed_and_devices_escape_drive_strings():
    d = {"target": "img", "catalog_tag": EVIL, "kernel": EVIL, "esp_free": 0, "unlisted": [EVIL],
         "packs": [{"id": EVIL, "catalog_tag": EVIL, "files": [], "stale": True, "stale_reason": EVIL}]}
    _clean(firmware.format_installed(d))
    disk = {"id": "/dev/sdz", "size": 1 << 30, "bus": "usb", "removable": True, "model": EVIL,
            "eligible": False, "reason": EVIL, "installed": {"summary": EVIL}}
    devs = {"elevated": True, "disks": [disk]}
    _clean(format_devices(devs, False))


def test_reporter_warnings_and_notes_are_escaped():
    buf = io.StringIO()
    rep = Reporter(stream=buf)
    rep.warn(f"firmware packs {EVIL} are not in the new helper's catalog")
    rep.note(EVIL)
    rep.step(EVIL)
    _clean(buf.getvalue())


def test_cli_error_lines_are_escaped(monkeypatch, capsys):
    def boom(*_a, **_kw):
        raise BeastError(f"img: marker says version {EVIL}")

    monkeypatch.setattr(cli, "info", boom)
    assert cli.main(["info", "--image", "x.img"]) != 0
    err = capsys.readouterr().err
    assert "marker says version" in err
    _clean(err)


@pytest.mark.parametrize("value", ["\x1b", "\x9d", "\x7f"])
def test_single_characters(value):
    assert printable(value) == "?"
