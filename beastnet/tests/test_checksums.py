import pytest

from beastnet.checksums import normalize_sha256, parse_checksum_file, pick_checksum

A, B, C = "a" * 64, "b" * 64, "c" * 64


def test_normalize():
    assert normalize_sha256(" " + A.upper() + "\n") == A
    assert normalize_sha256("sha256:" + A) == A
    assert normalize_sha256("SHA256=" + A) == A
    assert normalize_sha256("") is None and normalize_sha256(None) is None
    for bad in ("abc", "g" * 64, A + "0", "md5:" + A):
        with pytest.raises(ValueError):
            normalize_sha256(bad)


def test_gnu_formats():
    text = (f"{A}  ubuntu-26.04-desktop-amd64.iso\n"
            f"{B} *ubuntu-26.04-live-server-amd64.iso\n"
            f"{C}  ./sub/dir/other.iso\n"
            f"{'d' * 128}  sha512-line.iso\n"
            "d41d8cd98f00b204e9800998ecf8427e  md5-line.iso\n")
    entries = parse_checksum_file(text)
    assert entries == [(A, "ubuntu-26.04-desktop-amd64.iso"),
                       (B, "ubuntu-26.04-live-server-amd64.iso"),
                       (C, "./sub/dir/other.iso")]
    assert pick_checksum(entries, ["ubuntu-26.04-live-server-amd64.iso"]) == B
    assert pick_checksum(entries, ["other.iso"]) == C
    assert pick_checksum(entries, ["missing.iso"]) is None


def test_bsd_and_escaped_and_signed():
    text = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            f"SHA256 (Fedora-Workstation-Live-44.iso) = {A}\n"
            f"- {B}  dash-escaped.iso\n"
            f"\\{C}  back\\\\slash.iso\n"
            "-----BEGIN PGP SIGNATURE-----\nabcdef\n-----END PGP SIGNATURE-----\n")
    entries = parse_checksum_file(text)
    assert (A, "Fedora-Workstation-Live-44.iso") in entries
    assert (B, "dash-escaped.iso") in entries
    assert (C, "back\\slash.iso") in entries


def test_single_hash_file():
    assert pick_checksum(parse_checksum_file(A + "\n"), ["whatever.iso"]) == A
    # one named entry for another file: do not guess
    assert pick_checksum(parse_checksum_file(f"{A}  x.iso\n"), ["y.iso"]) is None
    # nameless and several different hashes: ambiguous
    assert pick_checksum(parse_checksum_file(f"{A}\n{B}\n"), ["y.iso"]) is None


def test_case_insensitive_fallback_and_candidates():
    entries = parse_checksum_file(f"{A}  Distro.ISO\n")
    assert pick_checksum(entries, ["distro.iso"]) == A
    assert pick_checksum(entries, ["", "nope.iso", "Distro.ISO"]) == A
