"""Security: the SHA256SUMS entry is picked by the names the user controls
(the link's file name, the chosen destination), never first by names the
server sends (Content-Disposition, the redirect target). Otherwise a mirror,
or a network attacker on a plain http:// download with an https:// checksum
file, could point at another genuine file in the list and swap that one in.
"""

import hashlib

import pytest

from beastnet.checksums import pick_checksum
from beastnet.download import DownloadRequest
from beastnet.errors import BeastNetError
from test_download import ISO, ISO_SHA, make

OLD = b"old, vulnerable release" * 1000
OLD_SHA = hashlib.sha256(OLD).hexdigest()
SUMS = f"{ISO_SHA}  ubuntu.iso\n{OLD_SHA}  old.iso\n".encode()


def _refused(d, req):
    with pytest.raises(BeastNetError) as e:
        d.download(req)
    assert e.value.code == "checksum-mismatch", e.value.text
    return e.value


def test_content_disposition_cannot_pick_another_entry(https, site, data_root, certs):
    site.add("/rel/SHA256SUMS", SUMS)
    site.add("/rel/ubuntu.iso", OLD, Content_Disposition='attachment; filename="old.iso"')
    d, _ = make(data_root, certs)
    _refused(d, DownloadRequest(https.url("/rel/ubuntu.iso"), sha256_url=https.url("/rel/SHA256SUMS")))


def test_redirect_target_cannot_pick_another_entry(https, site, data_root, certs):
    site.add("/rel/SHA256SUMS", SUMS)
    site.redirects["/rel/ubuntu.iso"] = "/rel/old.iso"
    site.add("/rel/old.iso", OLD)
    d, _ = make(data_root, certs)
    _refused(d, DownloadRequest(https.url("/rel/ubuntu.iso"), sha256_url=https.url("/rel/SHA256SUMS")))


def test_plain_http_mitm_cannot_pick_another_entry(http, https, site, data_root, certs):
    """http:// download, https:// checksum file: the on-path attacker answers
    for the http:// server with another listed file and its name."""
    site.add("/rel/SHA256SUMS", SUMS)
    site.add("/rel/ubuntu.iso", OLD, Content_Disposition="attachment; filename=old.iso")
    d, _ = make(data_root, certs)
    _refused(d, DownloadRequest(http.url("/rel/ubuntu.iso"), sha256_url=https.url("/rel/SHA256SUMS")))


def test_server_name_alone_cannot_choose_among_several(https, site, data_root, certs):
    site.add("/rel/SHA256SUMS", SUMS)
    site.add("/get?id=7", OLD, Content_Disposition="attachment; filename=old.iso")
    d, _ = make(data_root, certs)
    _refused(d, DownloadRequest(https.url("/get?id=7"), sha256_url=https.url("/rel/SHA256SUMS")))


def test_legit_user_names_still_work(https, site, data_root, certs):
    site.add("/rel/SHA256SUMS", SUMS)
    site.add("/get?id=7", ISO, Content_Disposition="attachment; filename=old.iso")
    d, _ = make(data_root, certs)
    # the chosen destination names the file
    r = d.download(DownloadRequest(https.url("/get?id=7"), sha256_url=https.url("/rel/SHA256SUMS"),
                                   dest="/downloads/ubuntu.iso"))
    assert r.verified and r.path == "/downloads/ubuntu.iso"


def test_redirect_only_link_with_a_single_entry(https, site, data_root, certs):
    """A "latest" link whose real name only the server knows: fine when the
    checksum file lists that one file (nothing to swap in)."""
    site.add("/rel/SHA256SUMS", f"{ISO_SHA}  distro-1.0.iso\n".encode())
    site.redirects["/latest"] = "/rel/distro-1.0.iso"
    site.add("/rel/distro-1.0.iso", ISO)
    d, _ = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/latest"), sha256_url=https.url("/rel/SHA256SUMS")))
    assert r.verified and r.path == "/downloads/distro-1.0.iso"


def test_pick_checksum_server_names_only_without_a_choice():
    entries = [(ISO_SHA, "ubuntu.iso"), (OLD_SHA, "old.iso")]
    assert pick_checksum(entries, ["get"], server_names=["old.iso"]) is None
    assert pick_checksum(entries, ["ubuntu.iso"], server_names=["old.iso"]) == ISO_SHA
    assert pick_checksum(entries[1:], ["get"], server_names=["old.iso"]) == OLD_SHA
