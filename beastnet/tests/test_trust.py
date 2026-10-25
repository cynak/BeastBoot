"""'Trust Ubuntu's Secure Boot key' (beastnet.trust, build/trust/README.md).

A fake efivarfs folder and a stub mokutil on PATH (stub_mokutil.py) stand in
for the firmware; the trust files are the repo's build/trust/canonical/."""

import curses
import json
import os
import re
import shutil
import stat
import io
import struct
import sys
from pathlib import Path

import pytest

from beastnet import trust
from beastnet.cmdline import parse_cmdline
from beastnet.context import Context, Quit
from beastnet.errors import BeastNetError
from beastnet.events import Reporter
from beastnet.firmware import load_catalog
from beastnet.flow import Interactive
from beastnet.paths import Paths
from beastnet.script import parse_plan, run_script
from beastnet.system import Runner, System
from beastnet.ui import Item
from beastnet.ui.plain import LineUI
from beastnet.ui.tui import TUI
from test_ui import FakeScreen, ScriptedUI, pick

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TRUST_SRC = os.path.join(ROOT, "build", "trust", "canonical")
SB_VAR = "SecureBoot-" + trust.GLOBAL_GUID
DEBIAN_CA = b"\x30\x82\x00\x04fake-debian-ca"  # stands in for shim's own vendor certificate
PW = "1234abcd"


# -- fixtures --------------------------------------------------------------------------

class Machine:
    """A fake UEFI machine: efivarfs folder, the helper's root, a stub mokutil."""

    def __init__(self, tmp_path, monkeypatch):
        self.root = tmp_path / "root"
        self.trust_dir = self.root / trust.TRUST_DIR.lstrip("/")
        shutil.copytree(TRUST_SRC, self.trust_dir)
        for d in ("mnt/data", "mnt/esp/grub", "run/beastnet", "proc"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.sys = tmp_path / "sys"
        self.efivars = self.sys / "firmware/efi/efivars"
        self.efivars.mkdir(parents=True)
        self.put("Boot0000", b"\x01\x00\x00\x00", guid=trust.GLOBAL_GUID)
        self.secure_boot(True)
        self.files = trust.load_trust(str(self.trust_dir))
        self.log = tmp_path / "mokutil.log"
        bindir = tmp_path / "bin"
        bindir.mkdir()
        stub = bindir / "mokutil"
        stub.write_text(f"#!/bin/sh\nexec {sys.executable} {os.path.join(HERE, 'stub_mokutil.py')} \"$@\"\n")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("STUB_MOKUTIL_LOG", str(self.log))
        self.paths = Paths(root=str(self.root), sys=str(self.sys))
        self.rep = Reporter()

    def put(self, name, data, guid=trust.SHIM_GUID, attrs=7):
        (self.efivars / f"{name}-{guid}").write_bytes(struct.pack("<I", attrs) + data)

    def var(self, name):
        p = self.efivars / f"{name}-{trust.SHIM_GUID}"
        return p.read_bytes()[4:] if p.exists() else None

    def secure_boot(self, on):
        self.put("SecureBoot", b"\x01" if on else b"\x00", guid=trust.GLOBAL_GUID, attrs=6)

    def lists(self, *, ca=False, revoked=0):
        """shim's runtime mirrors: its own vendor cert plus what MokList/MokListX hold."""
        mok = trust.make_esl(trust.X509_GUID, DEBIAN_CA)
        if ca:
            mok += trust.make_esl(trust.X509_GUID, self.files.ca.der)
        self.put("MokListRT", mok, attrs=6)
        mokx = trust.make_esl(trust.SHA256_GUID, b"\x11" * 32)  # shim's own vendor_dbx
        for c in self.files.revoked[:revoked]:
            mokx += trust.make_esl(trust.X509_GUID, c.der)
        self.put("MokListXRT", mokx, attrs=6)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(ln) for ln in self.log.read_text().splitlines()]

    def tool(self, **kw):
        kw.setdefault("runner", Runner())
        return trust.TrustUbuntu(self.paths, reporter=self.rep, **kw)


@pytest.fixture
def m(tmp_path, monkeypatch):
    return Machine(tmp_path, monkeypatch)


def entries(blob):
    return sorted(trust.parse_esl(blob or b""))


# -- formats -------------------------------------------------------------------------

def test_guid_and_esl_roundtrip():
    g = "605dab50-e046-4300-abb6-3dd810dd8b23"
    assert trust.guid_str(trust.guid_bytes(g)) == g
    assert trust.guid_bytes(g)[:4] == bytes.fromhex("50ab5d60")  # little endian first field
    blob = trust.make_esl(trust.X509_GUID, b"\x30abc") + trust.make_esl(trust.SHA256_GUID, b"\x22" * 32)
    assert trust.parse_esl(blob) == [(trust.X509_GUID, b"\x30abc"), (trust.SHA256_GUID, b"\x22" * 32)]
    with pytest.raises(ValueError):
        trust.parse_esl(blob[:-1])


def test_trust_files_load():
    f = trust.load_trust(TRUST_SRC)
    assert f.ca.name == "Canonical Ltd. Master Certificate Authority"
    assert f.ca.sha1 == "76a092065800bf376901c372cd55a90e1fded2e0"
    assert len(f.revoked) == 8 and f.revoked_hashes == []
    assert all(c.file == f"revoked/{c.sha256}.der" for c in f.revoked)
    assert "shim-signed" in f.source


@pytest.mark.parametrize("tamper", ["changed", "missing", "extra", "manifest", "subject"])
def test_tampered_trust_files_refused(m, tamper):
    d = m.trust_dir
    victim = d / m.files.revoked[3].file
    if tamper == "changed":
        victim.write_bytes(victim.read_bytes()[:-1] + b"\x00")
    elif tamper == "missing":
        victim.unlink()
    elif tamper == "extra":
        (d / "revoked" / "evil.der").write_bytes(b"\x30\x00")
    elif tamper == "subject":  # trust.json names another subject than the certificate has
        j = json.loads((d / "trust.json").read_text())
        j["vendor_cert"]["subject"] = "CN=Someone Else,O=Canonical Ltd."
        (d / "trust.json").write_text(json.dumps(j))
    else:  # the manifest lists a file under another certificate's hash
        j = json.loads((d / "trust.json").read_text())
        j["vendor_cert"]["sha256"] = j["vendor_dbx"]["x509"][0]["sha256"]
        (d / "trust.json").write_text(json.dumps(j))
    m.lists()
    with pytest.raises(BeastNetError) as e:
        m.tool().status()
    assert e.value.code == "trust" and "refused" in e.value.text
    with pytest.raises(BeastNetError):
        m.tool().request(trust.REVOCATIONS, PW)
    assert m.calls() == [] and m.var("MokXNew") is None


# -- state ------------------------------------------------------------------------------

@pytest.mark.parametrize("ca,revoked,state,step", [
    (False, 0, trust.NOT_TRUSTED, trust.REVOCATIONS),
    (False, 3, trust.PARTIAL, trust.REVOCATIONS),
    (False, 8, trust.REVOCATIONS_ONLY, trust.CA),
    (True, 8, trust.TRUSTED, None),
    (True, 5, trust.PARTIAL, trust.REVOCATIONS),  # trusted without all revocations: add them
])
def test_state_detection(m, ca, revoked, state, step):
    m.lists(ca=ca, revoked=revoked)
    st = m.tool().status()
    assert (st.state, st.next_step, st.ca_trusted, st.revoked_present) == (state, step, ca, revoked)
    assert st.can_delete == ca
    assert st.secure_boot is True and st.shim_lists
    assert f"BEASTNET: trust state={state} sb=1 ca={int(ca)} revoked={revoked}/8 pending=none" in m.rep.lines
    assert trust.state_text(st).startswith("Ubuntu's Secure Boot key: ")


def test_split_runtime_list_and_mok_variables(m):
    # MokListXRT split in two variables (shim does that for large lists)
    blob = b"".join(trust.make_esl(trust.X509_GUID, c.der) for c in m.files.revoked)
    m.put("MokListRT", trust.make_esl(trust.X509_GUID, DEBIAN_CA), attrs=6)
    cut = len(b"".join(trust.make_esl(trust.X509_GUID, c.der) for c in m.files.revoked[:4]))
    m.put("MokListXRT", blob[:cut], attrs=6)
    m.put("MokListXRT1", blob[cut:], attrs=6)
    assert m.tool().status().state == trust.REVOCATIONS_ONLY
    # Linux's mok-variables/ (shim's configuration table) wins when present
    mv = m.sys / "firmware/efi/mok-variables"
    mv.mkdir()
    (mv / "MokListXRT").write_bytes(b"")
    assert m.tool().status().state == trust.NOT_TRUSTED


def test_not_uefi(tmp_path, monkeypatch):
    mm = Machine(tmp_path, monkeypatch)
    shutil.rmtree(mm.sys / "firmware")
    st = mm.tool().status()
    assert st.state == trust.UNAVAILABLE and "BIOS" in st.problem and st.next_step is None
    with pytest.raises(BeastNetError) as e:
        mm.tool().request(trust.REVOCATIONS, PW)
    assert "BIOS" in e.value.hint


def test_no_efivarfs(m):
    shutil.rmtree(m.efivars)
    m.efivars.mkdir()  # the folder is there, nothing is mounted on it
    st = m.tool().status()
    assert st.state == trust.UNAVAILABLE and "efivarfs is not mounted" in st.problem


def test_secure_boot_off_still_allowed(m):
    m.secure_boot(False)
    m.lists()
    st = m.tool().status()
    assert st.secure_boot is False and st.next_step == trust.REVOCATIONS
    assert "Secure Boot is off" in trust.state_text(st)
    m.tool().request(trust.REVOCATIONS, PW)
    assert len(entries(m.var("MokXNew"))) == 8


def tiny_pe(vendor_cert: bytes) -> bytes:
    """A PE file with only a .vendor_cert section, like shim's."""
    rptr = 0x40 + 4 + 20 + 40
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    sec = b".vendor_" + struct.pack("<IIIIIIHHI", len(vendor_cert), 0x1000, len(vendor_cert), rptr, 0, 0, 0, 0, 0)
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(dos) + b"PE\0\0" + coff + sec + vendor_cert


def shim_with(auth: bytes, deauth: bytes) -> bytes:
    return tiny_pe(struct.pack("<IIII", len(auth), len(deauth), 16, 16 + len(auth)) + auth + deauth)


def test_drive_shim_with_canonical_built_in(m):
    """With Ubuntu's own shim, MokListRT/MokListXRT show its built-in trust,
    which says nothing about MokList/MokListX: no requests at all."""
    boot = m.root / "mnt/esp/EFI/BOOT"
    boot.mkdir(parents=True)
    deauth = b"".join(trust.make_esl(trust.X509_GUID, c.der) for c in m.files.revoked)
    (boot / "BOOTX64.EFI").write_bytes(shim_with(m.files.ca.der, deauth))
    assert trust.shim_vendor_entries(str(boot / "BOOTX64.EFI")) == \
        {m.files.ca.sha256} | {c.sha256 for c in m.files.revoked}
    m.lists(ca=True, revoked=8)
    st = m.tool().status()
    assert st.state == trust.BUILT_IN and st.next_step is None and not st.can_delete
    for step in (trust.REVOCATIONS, trust.CA, trust.DELETE):
        with pytest.raises(BeastNetError):
            m.tool().request(step, PW)
    assert m.calls() == []
    # Debian's shim (no Canonical entries built in) is not mistaken for it
    (boot / "BOOTX64.EFI").write_bytes(shim_with(DEBIAN_CA, trust.make_esl(trust.SHA256_GUID, b"\x11" * 32)))
    assert m.tool().status().state == trust.TRUSTED


# -- requests -----------------------------------------------------------------------------

def test_two_steps_in_order(m):
    m.lists()
    tool = m.tool()
    # step 2 first is refused while revocations are missing
    with pytest.raises(BeastNetError) as e:
        tool.request(trust.CA, PW)
    assert "refused" in e.value.text and "0 are" in e.value.text
    assert m.calls() == [] and m.var("MokNew") is None

    req = tool.request(trust.REVOCATIONS, PW)
    assert req.var == "MokXNew" and req.manager_item == "Enroll MOKX"
    assert entries(m.var("MokXNew")) == sorted((trust.X509_GUID, c.der) for c in m.files.revoked)
    assert m.var("MokXAuth") == b"$6$stubsalt$" + PW[::-1].encode()
    assert m.var("MokNew") is None
    calls = m.calls()
    assert calls[0] == ["--generate-hash"]
    argv = calls[1]
    assert argv[:2] == ["--mokx", "--hash-file"] and "--ignore-keyring" in argv
    files = argv[argv.index("--import") + 1:]
    assert sorted(os.path.basename(f) for f in files) == sorted(os.path.basename(c.file) for c in m.files.revoked)
    assert not os.path.exists(argv[2]), "the password hash file must be removed"
    assert "BEASTNET: trust request step=revocations var=MokXNew certs=8 hashes=0" in m.rep.lines
    assert "BEASTNET: trust requested step=revocations var=MokXNew" in m.rep.lines

    # pending: nothing more until MokManager ran
    st = tool.status()
    assert st.pending == ["MokXNew"] and st.next_step is None
    assert "Waiting for MokManager" in trust.state_text(st)
    with pytest.raises(BeastNetError) as e:
        tool.request(trust.CA, PW)
    assert "already waiting for MokManager" in e.value.text and "Reboot" in e.value.hint

    # MokManager enrolled them (shim mirrors MokListX into MokListXRT): step 2
    for n in ("MokXNew", "MokXAuth"):
        os.unlink(m.efivars / f"{n}-{trust.SHIM_GUID}")
    m.lists(revoked=8)
    req = tool.request(trust.CA, PW)
    assert req.var == "MokNew" and req.manager_item == "Enroll MOK"
    assert entries(m.var("MokNew")) == [(trust.X509_GUID, m.files.ca.der)]
    argv = m.calls()[-1]
    assert "--mokx" not in argv and argv[-2:] == ["--import", os.path.join(str(m.trust_dir), "canonical-master-ca.der")]


def test_only_missing_revocations_requested(m):
    m.lists(revoked=6)
    req = m.tool().request(trust.REVOCATIONS, PW)
    assert [c.sha256 for c in req.certs] == [c.sha256 for c in m.files.revoked[6:]]
    assert len(entries(m.var("MokXNew"))) == 2


@pytest.mark.parametrize("name", list(trust.PENDING))
def test_pending_request_refused(m, name):
    m.lists()
    m.put(name, trust.make_esl(trust.X509_GUID, b"\x30\x01x"))
    st = m.tool().status()
    assert st.pending == [name] and st.next_step is None
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert name in e.value.text
    assert m.calls() == []


def test_delete_flow(m):
    m.lists(ca=True, revoked=8)
    tool = m.tool()
    req = tool.request(trust.DELETE, PW)
    assert req.var == "MokDel" and req.manager_item == "Delete MOK"
    assert entries(m.var("MokDel")) == [(trust.X509_GUID, m.files.ca.der)]
    assert m.var("MokXNew") is None and m.var("MokXDel") is None, "the revocations stay"
    argv = m.calls()[-1]
    assert "--mokx" not in argv and "--delete" in argv and argv[-1].endswith("canonical-master-ca.der")
    # nothing to delete when the CA is not in MokList
    m.lists(revoked=8)
    os.unlink(m.efivars / f"MokDel-{trust.SHIM_GUID}")
    with pytest.raises(BeastNetError):
        tool.request(trust.DELETE, PW)


def test_mokutil_error(m, monkeypatch):
    m.lists()
    monkeypatch.setenv("STUB_MOKUTIL_FAIL", "1")
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert "mokutil failed (exit code 1): Failed to write the request" in e.value.text
    assert m.var("MokXNew") is None
    assert not [f for f in os.listdir(m.paths.run) if f.startswith("mok-password")]


def test_mokutil_missing(m, monkeypatch):
    m.lists()
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert "cannot run mokutil" in e.value.text


def test_unexpected_request_content_is_revoked(m, monkeypatch):
    m.lists()
    monkeypatch.setenv("STUB_MOKUTIL_EXTRA", "1")
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert "does not hold exactly" in e.value.text
    assert m.var("MokXNew") is None and m.var("MokXAuth") is None
    assert m.calls()[-1] == ["--mokx", "--revoke-import"]
    assert "nothing is waiting" in e.value.hint


@pytest.mark.parametrize("mode", ["1", "silent"])
def test_failed_cancellation_is_reported(m, monkeypatch, mode):
    """The request stays when mokutil cannot cancel it: the user is told not to confirm it."""
    m.lists()
    monkeypatch.setenv("STUB_MOKUTIL_EXTRA", "1")
    monkeypatch.setenv("STUB_MOKUTIL_REVOKE_FAIL", mode)
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert m.var("MokXNew") is not None and m.var("MokXAuth") is not None
    assert "still waiting (MokXNew, MokXAuth)" in e.value.text and "cancelled" not in e.value.text
    assert "Continue boot" in e.value.hint and "mokutil --mokx --revoke-import" in e.value.hint
    assert "Nothing was requested" not in e.value.hint and "Checked: nothing" not in e.value.hint


@pytest.mark.parametrize("revoke_fails", [False, True])
def test_partial_request_after_mokutil_error(m, monkeypatch, revoke_fails):
    m.lists()
    monkeypatch.setenv("STUB_MOKUTIL_FAIL", "after-write")
    if revoke_fails:
        monkeypatch.setenv("STUB_MOKUTIL_REVOKE_FAIL", "1")
    with pytest.raises(BeastNetError) as e:
        m.tool().request(trust.REVOCATIONS, PW)
    assert "mokutil failed (exit code 1)" in e.value.text
    if revoke_fails:
        assert m.var("MokXNew") is not None and "still waiting" in e.value.text
        assert "Continue boot" in e.value.hint and "Nothing was requested" not in e.value.hint
    else:
        assert m.var("MokXNew") is None and m.var("MokXAuth") is None
        assert "cancelled: nothing is waiting" in e.value.hint


def test_password_rules(m):
    assert trust.check_password(PW, PW) == ""
    assert "4 to 32" in trust.check_password("abc", "abc")
    assert "4 to 32" in trust.check_password("pass word", "pass word")
    assert "4 to 32" in trust.check_password("päss1234", "päss1234")
    assert "differ" in trust.check_password("abcd1234", "abcd1235")
    m.lists()
    with pytest.raises(BeastNetError):
        m.tool().request(trust.REVOCATIONS, "abcd1234", "abcd12345")
    assert m.calls() == []


def test_dry_run_runs_nothing(m):
    m.lists()
    notes = []
    req = m.tool(dry_run=True, say=notes.append).request(trust.REVOCATIONS, PW)
    assert req.step == trust.REVOCATIONS and m.calls() == [] and m.var("MokXNew") is None
    assert notes and notes[0].startswith("[dry-run] would run mokutil for MokXNew")


def test_texts_show_fingerprints(m):
    m.lists()
    st = m.tool().status()
    text = trust.request_text(m.tool().plan(st, trust.REVOCATIONS))
    for c in m.files.revoked:
        assert c.sha256 in text and trust.sha1_text(c.sha1) in text and c.name in text
        assert f"Subject {c.subject}" in text
    assert m.files.source in text and "View key" in text and "never trust" in text
    assert "checked against trust.json" not in text
    m.lists(revoked=8)
    req = m.tool().plan(m.tool().status(), trust.CA)
    ca_text = trust.request_text(req)
    assert "76 a0 92 06 58 00 bf 37 69 01 c3 72 cd 55 a9 0e 1f de d2 e0" in ca_text
    assert "Subject CN=Canonical Ltd. Master Certificate Authority,O=Canonical Ltd." in ca_text
    assert "published in the BeastBoot user guide" in ca_text
    nxt = trust.next_text(req)
    assert "Enroll MOK" in nxt and "password" in nxt and "Reboot" in nxt and "user guide" in nxt
    assert "boot loaders and kernels" in nxt and "boot loaders and kernels" in trust.ABOUT.lower()


def test_partial_text_warns_about_missing_revocations(m):
    m.lists(ca=True, revoked=5)
    st = m.tool().status()
    assert st.state == trust.PARTIAL and st.next_step == trust.REVOCATIONS
    assert "revoked Canonical certificates are trusted on this computer" in trust.state_text(st)
    m.lists(ca=False, revoked=5)
    assert "are trusted on this computer" not in trust.state_text(m.tool().status())


def test_subject_and_expiry_come_from_the_certificate():
    f = trust.load_trust(TRUST_SRC)
    j = json.loads((Path(TRUST_SRC) / "trust.json").read_text())
    assert f.ca.subject == j["vendor_cert"]["subject"] and f.ca.not_after == "Apr 11 11:12:51 2042 GMT"
    assert [c.subject for c in f.revoked] == [e["subject"] for e in j["vendor_dbx"]["x509"]]
    assert [c.not_after for c in f.revoked] == [e["not_after"] for e in j["vendor_dbx"]["x509"]]
    with pytest.raises(ValueError):
        trust.der_cert_info(b"\x30\x03\x02\x01\x00")


# -- entry points ------------------------------------------------------------------------

def test_cmdline_action():
    assert parse_cmdline("beastnet.action=trust-ubuntu quiet").action == "trust-ubuntu"
    p = parse_cmdline("beastnet.action=format-disk")
    assert p.action is None and p.raw["action"] == "format-disk"
    assert parse_cmdline("quiet").action is None


def context(m, *, dry_run=False):
    notes = []
    system = System(m.paths, Runner(), dry_run=True, say=notes.append)  # never reboots
    params = parse_cmdline("beastnet.action=trust-ubuntu beastnet.sb=1")
    ctx = Context(m.paths, params, m.rep, system, None, load_catalog(m.paths.catalog),
                  lambda: None, "7.0.0-10-generic", dry_run, notes)
    return ctx, notes


def test_script_plan_parsing():
    p = parse_plan({"action": "trust-ubuntu", "password": PW, "then": "poweroff"})
    assert (p.action, p.step, p.then, p.request) == ("trust-ubuntu", "next", "poweroff", None)
    for bad in ({"action": "trust-ubuntu"}, {"action": "trust-ubuntu", "password": "ab"},
                {"action": "trust-ubuntu", "password": PW, "step": "ca"}, {"action": "nope", "password": PW}):
        with pytest.raises(BeastNetError):
            parse_plan(bad)


def test_script_mode_two_runs(m):
    ctx, notes = context(m)
    m.lists()
    (m.root / "mnt/data/plan.json").write_text(json.dumps(
        {"action": "trust-ubuntu", "password": PW, "then": "poweroff", "on_error": "poweroff"}))
    assert run_script(ctx, "/plan.json") == ("done", None)
    assert len(entries(m.var("MokXNew"))) == 8 and m.var("MokNew") is None
    assert notes[-1] == "[dry-run] would poweroff now"
    # second run with the request still pending: refused, on_error=poweroff
    assert run_script(ctx, "/plan.json") == ("done", None)
    assert any(ln.startswith("BEASTNET: error trust a request is already waiting") for ln in m.rep.lines)
    # after MokManager: step 2
    os.unlink(m.efivars / f"MokXNew-{trust.SHIM_GUID}")
    m.lists(revoked=8)
    assert run_script(ctx, "/plan.json") == ("done", None)
    assert entries(m.var("MokNew")) == [(trust.X509_GUID, m.files.ca.der)]


def test_flow_from_menu_entry(m):
    """beastnet.action=trust-ubuntu: status -> step 1 -> fingerprints -> password
    (typed twice, a mismatch first) -> next steps -> back -> 'Download an ISO'."""
    ctx, notes = context(m)
    m.lists()
    ui = ScriptedUI([
        pick("Step 1 of 2"),  # status
        pick("Continue"),  # what will be enrolled
        {"pw": PW, "again": "nope1234"},  # password: mismatch
        {"pw": PW, "again": PW},
        pick("Back"),  # requested: reboot to confirm
        pick("Download an ISO from a link"),  # status again, now pending
    ])
    Interactive(ctx, ui).trust_ubuntu(entry=True)
    menus = [s for s in ui.shown if s[0] == "menu"]
    assert menus[0][1] == "Trust Ubuntu's Secure Boot key" and "not trusted" in menus[0][2]["text"]
    assert [i.label for i in menus[0][2]["items"]][:2] == ["Step 1 of 2: add Ubuntu's revocations",
                                                           "What does this do?"]
    assert m.files.revoked[0].sha256 in menus[1][2]["text"]
    forms = [s for s in ui.shown if s[0] == "form"]
    assert forms[1][2]["error"].startswith("The two passwords differ")
    assert menus[2][1] == "Requested: reboot to confirm" and "Enroll MOKX" in menus[2][2]["text"]
    labels = [i.label for i in menus[3][2]["items"]]
    assert "Reboot now to confirm it in MokManager" in labels and not any(lb.startswith("Step") for lb in labels)
    assert len(entries(m.var("MokXNew"))) == 8
    assert ui.subtitle == "beast-net: download an ISO from a link" and ui.steps, "mode restored"


def test_flow_run_with_action_then_reboot(m):
    ctx, notes = context(m)
    m.lists(ca=True, revoked=8)
    ui = ScriptedUI([pick("Stop trusting"), pick("Continue"), {"pw": PW, "again": PW}, pick("Reboot now")])
    with pytest.raises(Quit):
        Interactive(ctx, ui).run(action="trust-ubuntu")
    assert entries(m.var("MokDel")) == [(trust.X509_GUID, m.files.ca.der)]
    assert notes[-1] == "[dry-run] would reboot now"


def test_flow_from_more_menu_and_errors(m):
    ctx, _ = context(m)
    (m.trust_dir / "revoked-sha256.txt").write_text("00" * 32 + "\n")  # tampered
    ui = ScriptedUI([pick("Trust Ubuntu's Secure Boot key"), pick("OK")])
    Interactive(ctx, ui).more_menu()
    assert ui.shown[-1][1] == "Trust Ubuntu's Secure Boot key (trust)"
    assert ui.shown[-1][2]["kind"] == "error" and "refused" in ui.shown[-1][2]["text"]
    assert m.calls() == []


def test_script_mode_when_trusted_does_nothing(m):
    ctx, notes = context(m)
    m.lists(ca=True, revoked=8)
    (m.root / "mnt/data/plan.json").write_text(json.dumps({"action": "trust-ubuntu", "password": PW}))
    assert run_script(ctx, "/plan.json") == ("stay", None)
    assert m.calls() == [] and not [ln for ln in m.rep.lines if " error " in ln]


def test_tui_document_scrolls_and_hides_step_bar():
    scr = FakeScreen([curses.KEY_DOWN, curses.KEY_NPAGE, curses.KEY_RIGHT, "\n"])
    ui = TUI(scr, real=False)
    ui.set_mode("beast-net: Ubuntu's Secure Boot key", ())
    text = "\n".join(f"line {i}" for i in range(60))
    assert ui.document("Fingerprints", text, [Item("Continue", 1), Item("Back", 2)]) == 2
    screen = scr.dump()
    assert "beast-net: Ubuntu's Secure Boot key" in screen
    assert "1 Network" not in screen and "[ Continue ]" in screen and "[ Back ]" in screen
    assert not re.search(r"\bline 0$", screen, re.M) and "more^" in screen


def test_line_ui_document_and_header():
    out = io.StringIO()
    ui = LineUI(io.StringIO("2\n"), out)
    ui.set_mode("beast-net: Ubuntu's Secure Boot key", ())
    assert ui.document("Fingerprints", "SHA-256 abc", [Item("Continue", 1), Item("Back", 2)]) == 2
    assert "beast-booter / beast-net    beast-net: Ubuntu's Secure Boot key" in out.getvalue()
    assert "SHA-256 abc" in out.getvalue()
