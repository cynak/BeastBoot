"""GUI boot-files handling: discovery order, manifest summary, fingerprints, verification."""

from __future__ import annotations

import hashlib
import json

import pytest

from beastbooter.gui import distinfo
from beastbooter.gui.distinfo import DistLocation, colon_hex, find_dist, mok_fingerprint, read_summary, verify


@pytest.fixture
def tree(tmp_path):
    """A portable package and a source checkout side by side."""
    pkg_app = tmp_path / "pkg" / "app"
    pkg_app.mkdir(parents=True)
    repo_app = tmp_path / "repo" / "installer"
    repo_app.mkdir(parents=True)
    return tmp_path, pkg_app, repo_app


def test_cli_argument_wins(tree):
    root, app, _ = tree
    (app.parent / "payload" / "dist").mkdir(parents=True)
    loc = find_dist(str(root / "mine"), {"BEAST_BOOTER_DIST": str(root / "env")}, app)
    assert loc.path == (root / "mine").resolve() and loc.source == "--dist"
    assert not loc.exists  # an explicit choice is never replaced by another copy


def test_env_second(tree):
    root, app, _ = tree
    (app.parent / "payload" / "dist").mkdir(parents=True)
    loc = find_dist(None, {"BEAST_BOOTER_DIST": str(root / "env")}, app)
    assert loc.path == (root / "env").resolve() and loc.source == "BEAST_BOOTER_DIST"


def test_portable_payload_third(tree):
    _, app, _ = tree
    payload = app.parent / "payload" / "dist"
    payload.mkdir(parents=True)
    (app.parent / "dist").mkdir()  # would be the checkout location: payload wins
    loc = find_dist(None, {}, app)
    assert loc.path == payload.resolve() and loc.source == "portable package" and loc.exists


def test_source_checkout_last(tree):
    _, _, repo_app = tree
    (repo_app.parent / "dist").mkdir()
    loc = find_dist(None, {"BEAST_BOOTER_DIST": ""}, repo_app)  # empty env var = unset
    assert loc.path == (repo_app.parent / "dist").resolve() and loc.source == "source checkout"


def test_nothing_found_lists_where_it_looked(tree):
    _, app, _ = tree
    loc = find_dist(None, {}, app)
    assert loc.path is None and loc.source == "not found" and not loc.exists
    assert loc.searched == (app.parent / "payload" / "dist", app.parent / "dist")
    s = read_summary(loc)
    assert not s.ok and "payload" in s.error and "BEAST_BOOTER_DIST" in s.error


def test_relative_cli_value_is_resolved(tree, monkeypatch):
    root, app, _ = tree
    monkeypatch.chdir(root)
    assert find_dist("d", {}, app).path == (root / "d").resolve()


def test_default_app_dir_is_the_launcher_folder():
    assert (distinfo.app_dir() / "beastbooter" / "gui" / "distinfo.py").is_file()
    assert distinfo.launcher_path().name == "beast_booter_launch.py"
    assert distinfo.launcher_path().is_file()


def test_mok_fingerprint_format():
    a, b = mok_fingerprint("974c1de1a63522fa233c7a24b8851b62c359ba94")
    # as docs/SECURE_BOOT.md shows MokManager's "View key"
    assert a == "97 4C 1D E1 A6 35 22 FA 23 3C"
    assert b == "7A 24 B8 85 1B 62 C3 59 BA 94"
    assert mok_fingerprint("97:4C:1D:E1:A6:35:22:FA:23:3C:7A:24:B8:85:1B:62:C3:59:BA:94") == (a, b)
    with pytest.raises(ValueError):
        mok_fingerprint("abcd")
    with pytest.raises(ValueError):
        mok_fingerprint("z" * 40)


def test_colon_hex():
    assert colon_hex("c7ad96") == "C7:AD:96"


def test_summary_from_fake_dist(fake_dist):
    s = read_summary(DistLocation(fake_dist, "--dist"))
    der = (fake_dist / "esp" / distinfo.CERT_FILE).read_bytes()
    assert s.ok and s.version == "0.1.0" and s.file_count > 8
    assert s.cert_from_file
    assert s.cert_sha1 == hashlib.sha1(der).hexdigest()
    assert s.cert_sha256 == hashlib.sha256(der).hexdigest()
    # fakedist's manifest has a dummy cert_sha256: the mismatch is reported
    assert any("does not match secure_boot.cert_sha256" in w for w in s.warnings)


def test_summary_matching_manifest_has_no_warnings(dist_copy):
    der = (dist_copy / "esp" / distinfo.CERT_FILE).read_bytes()
    m = json.loads((dist_copy / "manifest.json").read_text())
    m["build_id"] = "c3176a2b65f7"
    m["secure_boot"].update(cert_sha256=hashlib.sha256(der).hexdigest(), cert_sha1=hashlib.sha1(der).hexdigest(),
                            cert_subject="CN=test key")
    (dist_copy / "manifest.json").write_text(json.dumps(m))
    s = read_summary(DistLocation(dist_copy, "--dist"))
    assert s.warnings == () and s.build_id == "c3176a2b65f7" and s.cert_subject == "CN=test key"


def test_summary_without_cert_file_uses_manifest(dist_copy):
    (dist_copy / "esp" / distinfo.CERT_FILE).unlink()
    m = json.loads((dist_copy / "manifest.json").read_text())
    m["secure_boot"]["cert_sha1"] = "AB" * 20
    (dist_copy / "manifest.json").write_text(json.dumps(m))
    s = read_summary(DistLocation(dist_copy, "--dist"))
    assert s.ok and not s.cert_from_file and s.cert_sha1 == "ab" * 20
    assert any("not found" in w for w in s.warnings)


@pytest.mark.parametrize("content, error", [
    (None, "is missing"),
    ("{not json", "Cannot read"),
    ("[]", "not a JSON object"),
])
def test_summary_bad_manifest(tmp_path, content, error):
    d = tmp_path / "dist"
    d.mkdir()
    if content is not None:
        (d / "manifest.json").write_text(content)
    s = read_summary(DistLocation(d, "--dist"))
    assert not s.ok and error in s.error


def test_summary_of_a_file(tmp_path):
    f = tmp_path / "dist.zip"
    f.write_bytes(b"PK")
    s = read_summary(DistLocation(f, "--dist"))
    assert not s.ok and "unpacked" in s.error


def test_real_dist_if_built():
    """The repo's own dist/ (after `make build`) has fingerprints in its manifest."""
    loc = find_dist(None, {})
    if loc.source != "source checkout" or not (loc.path / "manifest.json").is_file():
        pytest.skip("no built dist/ in this checkout")
    s = read_summary(loc)
    assert s.ok and len(s.cert_sha1) == 40 and len(s.cert_sha256) == 64
    assert s.warnings == ()


def test_verify_ok_and_read_only(dist_copy):
    before = sorted((p.relative_to(dist_copy), p.stat().st_mtime_ns) for p in dist_copy.rglob("*"))
    r = verify(dist_copy)
    assert r.ok and "match manifest.json" in r.message and "0.1.0" in r.message
    after = sorted((p.relative_to(dist_copy), p.stat().st_mtime_ns) for p in dist_copy.rglob("*"))
    assert before == after


def test_verify_detects_tampering(dist_copy):
    (dist_copy / "esp/EFI/BOOT/grubx64.efi").write_bytes(b"evil")
    r = verify(dist_copy)
    assert not r.ok and "sha256 mismatch" in r.message and "grubx64.efi" in r.message


def test_verify_detects_extra_file(dist_copy):
    (dist_copy / "esp/EFI/BOOT/fbx64.efi").write_bytes(b"fallback")
    r = verify(dist_copy)
    assert not r.ok and "fbx64.efi" in r.message


def test_verify_missing_dir(tmp_path):
    r = verify(tmp_path / "none")
    assert not r.ok and "not found" in r.message
