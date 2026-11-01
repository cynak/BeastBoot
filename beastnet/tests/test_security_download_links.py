"""Downloads never follow links planted on the data partition (security finding NET-1).

The data partition is untrusted: whoever had the stick can make /downloads, the
.part file or the destination a symlink (exFAT cannot, NTFS via ntfs3 can). A
download must refuse them instead of writing through them as root.
"""

import hashlib
import os

import pytest

from beastnet.download import DownloadRequest, Downloader
from beastnet.errors import BeastNetError
from beastnet.events import Reporter

ISO = os.urandom(200_000)
ISO_SHA = hashlib.sha256(ISO).hexdigest()


def make(data_root, certs):
    return Downloader(data_root, certs.ca, reporter=Reporter(), timeout=5, sleep=lambda s: None,
                      retry_delays=(0,), chunk=16 * 1024)


def test_downloads_folder_link_refused(https, site, data_root, certs, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, os.path.join(data_root, "downloads"))
    site.add("/x.iso", ISO)
    with pytest.raises(BeastNetError):
        make(data_root, certs).download(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    assert list(outside.iterdir()) == []


def test_part_file_link_refused(https, site, data_root, certs, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep me")
    os.makedirs(os.path.join(data_root, "downloads"))
    os.symlink(victim, os.path.join(data_root, "downloads", "x.iso.part"))
    site.add("/x.iso", ISO)
    with pytest.raises(BeastNetError):
        make(data_root, certs).download(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    assert victim.read_bytes() == b"keep me"


def test_part_meta_link_refused(https, site, data_root, certs, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep me")
    os.makedirs(os.path.join(data_root, "downloads"))
    os.symlink(victim, os.path.join(data_root, "downloads", "x.iso.part.json"))
    site.add("/x.iso", ISO)
    with pytest.raises(BeastNetError):
        make(data_root, certs).download(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    assert victim.read_bytes() == b"keep me"


def test_existing_link_not_reused_as_verified(https, site, data_root, certs, tmp_path):
    """A link to a matching file elsewhere is not "already downloaded and verified"."""
    elsewhere = tmp_path / "elsewhere.iso"
    elsewhere.write_bytes(ISO)
    os.makedirs(os.path.join(data_root, "downloads"))
    os.symlink(elsewhere, os.path.join(data_root, "downloads", "x.iso"))
    site.add("/x.iso", ISO)
    d = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    assert d.check_existing(plan) is None
