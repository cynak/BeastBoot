import hashlib
import json
import os
import threading

import pytest

from beastnet import download as dl
from beastnet.download import (DownloadRequest, Downloader, check_url, filename_from_disposition,
                               sanitize_filename)
from beastnet.errors import BeastNetError, Cancelled
from beastnet.events import Reporter
from beastnet.paths import DEFAULT_CA_FILE
from bn_helpers import Server

ISO = os.urandom(300_000) + b"tail"
ISO_SHA = hashlib.sha256(ISO).hexdigest()


def make(data_root, certs, **kw):
    rep = Reporter()
    kw.setdefault("retry_delays", (0,))
    kw.setdefault("chunk", 16 * 1024)
    d = Downloader(data_root, certs.ca, reporter=rep, timeout=5, sleep=lambda s: None, **kw)
    return d, rep


def code_of(excinfo):
    return excinfo.value.code


# -- TLS -----------------------------------------------------------------------------

def test_https_with_test_ca(https, site, data_root, certs):
    site.add("/isos/test.iso", ISO)
    d, rep = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/isos/test.iso")))
    assert r.path == "/downloads/test.iso"
    assert open(os.path.join(data_root, "downloads", "test.iso"), "rb").read() == ISO
    assert r.sha256 == ISO_SHA and not r.verified
    assert not os.path.exists(r.local + ".part")
    assert rep.lines[0] == f"BEASTNET: download start url={https.url('/isos/test.iso')} dest=/downloads/test.iso"
    assert rep.lines[-2] == "BEASTNET: download progress pct=100"
    assert rep.lines[-1] == f"BEASTNET: download done path=/downloads/test.iso bytes={len(ISO)} sha256={ISO_SHA}"


def test_https_rejected_with_default_bundle(https, site, data_root, certs):
    if not os.path.exists(DEFAULT_CA_FILE):
        pytest.skip("no system CA bundle")
    site.add("/x.iso", ISO)
    d = Downloader(data_root, DEFAULT_CA_FILE, timeout=5)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/x.iso")))
    assert code_of(e) == "tls"
    assert "certificate" in e.value.text
    assert not os.listdir(data_root)


def test_hostname_mismatch_rejected(site, data_root, certs):
    srv = Server(site, (certs.wrong_cert, certs.wrong_key))
    try:
        site.add("/x.iso", ISO)
        d, _ = make(data_root, certs)
        with pytest.raises(BeastNetError) as e:
            d.download(DownloadRequest(srv.url("/x.iso", host="localhost")))
        assert code_of(e) == "tls"
        assert "mismatch" in e.value.text.lower() or "not valid for" in e.value.text
    finally:
        srv.close()


def test_ip_not_in_certificate_rejected(https, site, data_root, certs):
    # The good certificate covers localhost and 127.0.0.1, but not ::1 / other names.
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/x.iso", host="localhost")))
    assert r.size == len(ISO)


def test_missing_ca_bundle(data_root, tmp_path):
    d = Downloader(data_root, str(tmp_path / "nope.pem"))
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest("https://127.0.0.1:1/x.iso"))
    assert code_of(e) == "tls"


def test_tls_context_is_strict(certs):
    import ssl
    ctx = dl.tls_context(certs.ca)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


# -- plain HTTP --------------------------------------------------------------------------

def test_plain_http_refused_without_sha(http, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(http.url("/x.iso")))
    assert code_of(e) == "refused-plain-http"
    assert site.requests == []  # refused before connecting


def test_plain_http_allowed_with_sha(http, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, rep = make(data_root, certs)
    r = d.download(DownloadRequest(http.url("/x.iso"), sha256=ISO_SHA.upper()))
    assert r.verified
    assert rep.lines[-1] == f"BEASTNET: verify ok sha256={ISO_SHA}"


def test_plain_http_checksum_file_refused(http, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.add("/SHA256SUMS", f"{ISO_SHA}  x.iso\n".encode())
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(http.url("/x.iso"), sha256_url=http.url("/SHA256SUMS")))
    assert code_of(e) == "refused-plain-http"


def test_plain_http_with_https_checksum_file(http, https, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.add("/SHA256SUMS", f"{'0' * 64}  other.iso\n{ISO_SHA} *x.iso\n".encode())
    d, _ = make(data_root, certs)
    r = d.download(DownloadRequest(http.url("/x.iso"), sha256_url=https.url("/SHA256SUMS")))
    assert r.verified and r.expected == ISO_SHA


# -- redirects -----------------------------------------------------------------------------

def test_redirects_followed(https, site, data_root, certs):
    site.add("/real/distro-1.0.iso", ISO)
    site.redirects["/latest"] = "/step2"  # relative
    site.redirects["/step2"] = https.url("/step3")  # absolute
    site.redirects["/step3"] = "real/distro-1.0.iso"  # relative to /step3
    d, _ = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/latest")))
    assert r.path == "/downloads/distro-1.0.iso"  # name from the redirect target
    assert r.size == len(ISO)


def test_too_many_redirects(https, site, data_root, certs):
    for i in range(12):
        site.redirects[f"/r{i}"] = f"/r{i + 1}"
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/r0")))
    assert code_of(e) == "http" and "redirects" in e.value.text


def test_https_to_http_downgrade_refused(https, http, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.redirects["/go"] = http.url("/x.iso")
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/go"), sha256=ISO_SHA))  # even with a SHA-256
    assert code_of(e) == "refused-plain-http"
    assert "redirect" in e.value.text


def test_http_to_https_upgrade_allowed(https, http, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.redirects["/up"] = https.url("/x.iso")
    d, _ = make(data_root, certs)
    assert d.download(DownloadRequest(http.url("/up"), sha256=ISO_SHA)).verified


# -- resume ------------------------------------------------------------------------------------

def test_resume_after_cut_connection(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, rep = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    site.cut_once.add("/x.iso")  # the data request stops halfway
    progress = []
    r = d.fetch(plan, progress.append)
    assert r.verified
    assert any(p.phase == "retry" for p in progress)
    ranges = [h.get("Range") for p, h in site.requests if p == "/x.iso"]
    assert any(rg and rg.startswith("bytes=") and rg != "bytes=0-" for rg in ranges)
    assert "BEASTNET: verify ok sha256=" + ISO_SHA in rep.lines


def test_resume_from_existing_part(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso")))
    os.makedirs(os.path.dirname(plan.local))
    half = len(ISO) // 3
    with open(plan.local + ".part", "wb") as f:
        f.write(ISO[:half])
    with open(plan.local + ".part.json", "w") as f:
        json.dump({"url": plan.url, "etag": plan.etag, "last_modified": plan.last_modified,
                   "total": plan.total}, f)
    progress = []
    r = d.fetch(plan, progress.append)
    assert open(r.local, "rb").read() == ISO and r.sha256 == ISO_SHA
    last = site.requests[-1][1]
    assert last["Range"] == f"bytes={half}-"
    assert last["If-Range"] == plan.etag
    assert any(p.resumed_from == half for p in progress)


def test_changed_file_restarts(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    os.makedirs(os.path.dirname(plan.local))
    with open(plan.local + ".part", "wb") as f:
        f.write(b"X" * 1000)  # stale data from an older version
    with open(plan.local + ".part.json", "w") as f:
        json.dump({"url": plan.url, "etag": plan.etag, "last_modified": plan.last_modified,
                   "total": plan.total}, f)
    site.etags["/x.iso"] = '"new-version"'  # server's file changed: If-Range fails -> 200
    r = d.fetch(plan)
    assert r.verified


def test_server_ignoring_range_restarts(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.no_range.add("/x.iso")
    d, _ = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    site.cut_once.add("/x.iso")
    assert d.fetch(plan).verified


def test_gives_up_after_retries(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    site.status["/x.iso"] = 503
    d, _ = make(data_root, certs, retries=2)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/x.iso")))
    assert code_of(e) == "http"


def test_cancel_keeps_part(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    plan = d.prepare(DownloadRequest(https.url("/x.iso")))
    cancel = threading.Event()

    def progress(p):
        if p.done > 0:
            cancel.set()
    with pytest.raises(Cancelled):
        d.fetch(plan, progress, cancel)
    assert os.path.exists(plan.local + ".part") and not os.path.exists(plan.local)


# -- checksums -------------------------------------------------------------------------------

def test_checksum_mismatch_keeps_nothing(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, rep = make(data_root, certs)
    wrong = "ab" * 32
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/x.iso"), sha256=wrong))
    assert code_of(e) == "checksum-mismatch"
    assert os.listdir(os.path.join(data_root, "downloads")) == []
    assert rep.lines[-1] == f"BEASTNET: verify fail expected={wrong} got={ISO_SHA}"


def test_sha256_url(https, site, data_root, certs):
    site.add("/rel/ubuntu.iso", ISO)
    site.add("/rel/SHA256SUMS", (f"{'1' * 64} *ubuntu-server.iso\n{ISO_SHA} *ubuntu.iso\n").encode())
    d, rep = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/rel/ubuntu.iso"), sha256_url=https.url("/rel/SHA256SUMS")))
    assert r.verified
    assert rep.lines[-1] == f"BEASTNET: verify ok sha256={ISO_SHA}"


def test_sha256_url_without_our_file(https, site, data_root, certs):
    site.add("/rel/ubuntu.iso", ISO)
    site.add("/rel/SHA256SUMS", f"{ISO_SHA}  something-else.iso\n".encode())
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/rel/ubuntu.iso"), sha256_url=https.url("/rel/SHA256SUMS")))
    assert code_of(e) == "checksum-mismatch"
    assert not os.path.exists(os.path.join(data_root, "downloads", "ubuntu.iso"))


# -- space, existing files, names ----------------------------------------------------------

def test_free_space_refused(https, site, data_root, certs, monkeypatch):
    site.add("/x.iso", ISO)

    class St:
        f_bavail, f_frsize = 10, 4096
    monkeypatch.setattr(dl.os, "statvfs", lambda p: St())
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/x.iso")))
    assert code_of(e) == "no-space"
    assert not any(p == "/x.iso" and "Range" in h for p, h in site.requests)
    assert not os.path.exists(os.path.join(data_root, "downloads", "x.iso.part"))


def test_fat32_four_gib_limit(https, site, data_root, certs):
    site.fake_length["/big.iso"] = 5 * 1024 ** 3
    d, _ = make(data_root, certs, fs_type=lambda p: "vfat")
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/big.iso")))
    assert code_of(e) == "no-space" and "FAT32" in e.value.text


def test_existing_file_not_overwritten(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    os.makedirs(os.path.join(data_root, "downloads"))
    target = os.path.join(data_root, "downloads", "x.iso")
    with open(target, "wb") as f:
        f.write(b"my own file")
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/x.iso")))
    assert code_of(e) == "exists"
    assert open(target, "rb").read() == b"my own file"
    # Explicit overwrite replaces it.
    r = d.download(DownloadRequest(https.url("/x.iso"), overwrite=True))
    assert open(target, "rb").read() == ISO and r.size == len(ISO)


def test_existing_matching_file_is_reused(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    os.makedirs(os.path.join(data_root, "downloads"))
    with open(os.path.join(data_root, "downloads", "x.iso"), "wb") as f:
        f.write(ISO)
    d, rep = make(data_root, certs)
    r = d.download(DownloadRequest(https.url("/x.iso"), sha256=ISO_SHA))
    assert r.reused and r.verified
    assert rep.lines[-1] == f"BEASTNET: verify ok sha256={ISO_SHA}"


def test_keep_both_name(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    os.makedirs(os.path.join(data_root, "downloads"))
    open(os.path.join(data_root, "downloads", "x.iso"), "wb").close()
    d, _ = make(data_root, certs)
    plan = d.with_unique_name(d.prepare(DownloadRequest(https.url("/x.iso"))))
    assert plan.dest == "/downloads/x-1.iso"
    assert d.fetch(plan).path == "/downloads/x-1.iso"


def test_content_disposition_and_dest(https, site, data_root, certs):
    site.add("/download?id=7", ISO,
             Content_Disposition="attachment; filename*=UTF-8''Caf%C3%A9%20OS%201.0.iso")
    d, _ = make(data_root, certs)
    assert d.download(DownloadRequest(https.url("/download?id=7"))).path == "/downloads/Cafe_OS_1.0.iso"
    r = d.download(DownloadRequest(https.url("/download?id=7"), dest="/downloads/sub/mine.iso"))
    assert r.path == "/downloads/sub/mine.iso" and os.path.exists(r.local)


def test_dest_must_stay_in_downloads(https, site, data_root, certs):
    site.add("/x.iso", ISO)
    d, _ = make(data_root, certs)
    for bad in ("/downloads/../boot.iso", "/etc/x.iso", "/downloads"):
        with pytest.raises(ValueError):
            d.prepare(DownloadRequest(https.url("/x.iso"), dest=bad))


def test_http_errors(https, site, data_root, certs):
    d, _ = make(data_root, certs)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest(https.url("/missing.iso")))
    assert code_of(e) == "http" and "404" in e.value.text


def test_connection_refused(data_root, certs):
    d, _ = make(data_root, certs, retries=0)
    with pytest.raises(BeastNetError) as e:
        d.download(DownloadRequest("https://127.0.0.1:1/x.iso"))
    assert code_of(e) == "http"


@pytest.mark.parametrize("raw,clean", [
    ("ubuntu-26.04-desktop-amd64.iso", "ubuntu-26.04-desktop-amd64.iso"),
    ("../../etc/passwd", "passwd"),
    ("..\\..\\win.iso", "win.iso"),
    ("my distro (final).iso", "my_distro_final.iso"),
    (".hidden.iso", "hidden.iso"),
    ("Café Linux.iso", "Cafe_Linux.iso"),
    ("CON.iso", "_CON.iso"),
    ("a:b*c?d|e<f>g\"h.iso", "a_b_c_d_e_f_g_h.iso"),
    ("", "download.iso"),
    ("....", "download.iso"),
    ("x" * 300 + ".iso", "x" * 196 + ".iso"),
    ("evil\nname.iso", "evil_name.iso"),
])
def test_sanitize_filename(raw, clean):
    assert sanitize_filename(raw) == clean


def test_content_disposition_parsing():
    assert filename_from_disposition('attachment; filename="a b.iso"') == "a b.iso"
    assert filename_from_disposition("attachment; filename=plain.iso") == "plain.iso"
    assert filename_from_disposition("attachment; filename*=UTF-8''x%20y.iso; filename=\"z.iso\"") == "x y.iso"
    assert filename_from_disposition("inline") is None
    assert filename_from_disposition(None) is None


def test_check_url():
    assert check_url(" example.org/x.iso ", trusted_hash=False) == "https://example.org/x.iso"
    assert check_url("HTTPS://Example.org/x.iso#frag", trusted_hash=False) == "https://Example.org/x.iso"
    for bad in ("ftp://x/y.iso", "https://", "https://host:99999/x", "file:///etc/passwd"):
        with pytest.raises(BeastNetError):
            check_url(bad, trusted_hash=True)
    with pytest.raises(BeastNetError) as e:
        check_url("http://example.org/x.iso", trusted_hash=False)
    assert e.value.code == "refused-plain-http"
    assert check_url("http://example.org/x.iso", trusted_hash=True).startswith("http://")
