"""Security: user:password@ in a link is only ever sent over https://, never
in clear text over plain http:// (even when a SHA-256 allows http downloads)."""

import base64

import pytest

from beastnet.download import DownloadRequest
from beastnet.errors import BeastNetError
from test_download import ISO, ISO_SHA, make


def test_no_credentials_over_plain_http(http, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(http.url("/x.iso", host="me:secret@127.0.0.1"), sha256=ISO_SHA))
    assert e.value.code == "refused-plain-http"
    assert all("Authorization" not in h for _, h in site.requests), site.requests


def test_credentials_over_https(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/x.iso", host="me:secret@127.0.0.1"), sha256=ISO_SHA))
    assert r.verified
    want = "Basic " + base64.b64encode(b"me:secret").decode()
    assert site.requests and all(h.get("Authorization") == want for _, h in site.requests)
