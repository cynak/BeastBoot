"""Trust Ubuntu's Secure Boot key (build/trust/README.md).

The drive boots through Debian's shim, which trusts Microsoft's keys, Debian's
key and the user's BeastBoot MOK key, but not Canonical's. This module lets
the user opt in to exactly what Ubuntu's own shim trusts, in two steps, each
confirmed in MokManager after a reboot:

1. the certificates (and hashes) Ubuntu revoked go into MokListX
   (``mokutil --mokx --import``), then
2. only once all of them are in MokListX, Canonical's Master CA goes into
   MokList (``mokutil --import``).

"Stop trusting Ubuntu's key" asks MokManager to delete the CA from MokList
(``mokutil --delete``); the revocations stay. The trust files come from the
initramfs (/usr/share/beastnet/trust/canonical/) and are checked against
trust.json before anything is shown or requested. The state is read from what
shim publishes at runtime: MokListRT / MokListXRT, its copies of MokList /
MokListX (MokListRT also lists the running shim's own vendor certificate, so
a drive whose shim has Canonical's CA built in is reported as such and gets
no requests).

Nothing here touches the firmware's db/dbx, and nothing other than those
files is ever requested.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
from dataclasses import dataclass, field
from collections.abc import Callable

from .errors import TRUST, BeastNetError
from .events import Reporter
from .paths import Paths
from .system import Runner

TRUST_DIR = "/usr/share/beastnet/trust/canonical"
SHIM_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"  # SHIM_LOCK_GUID: Mok* variables
GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"  # EFI_GLOBAL_VARIABLE: SecureBoot
X509_GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"  # EFI_CERT_X509_GUID
SHA256_GUID = "c1c41626-504c-4092-aca9-41f936934328"  # EFI_CERT_SHA256_GUID
DEFAULT_EFIVARS = "/sys/firmware/efi/efivars"
SHIM_ON_ESP = ("EFI", "BOOT", "BOOTX64.EFI")

# Requests shim hands to MokManager on the next boot (mokutil writes them).
PENDING = {
    "MokNew": "enroll a key in MokList",
    "MokXNew": "enroll a key in MokListX",
    "MokDel": "delete a key from MokList",
    "MokXDel": "delete a key from MokListX",
}

NOT_TRUSTED = "not-trusted"
REVOCATIONS_ONLY = "revocations-only"
TRUSTED = "trusted"
PARTIAL = "partial"
BUILT_IN = "shim-built-in"  # the drive's own shim already embeds Canonical's trust
UNAVAILABLE = "unavailable"  # not UEFI, or no efivarfs

STATE_LABEL = {
    NOT_TRUSTED: "not trusted",
    REVOCATIONS_ONLY: "revocations only (step 1 of 2 done)",
    TRUSTED: "trusted",
    PARTIAL: "partly set up",
    BUILT_IN: "built into this drive's shim",
    UNAVAILABLE: "cannot be checked here",
}

REVOCATIONS, CA, DELETE = "revocations", "ca", "delete"
STEP_LABEL = {
    REVOCATIONS: "Step 1 of 2: add Ubuntu's revocations",
    CA: "Step 2 of 2: trust Ubuntu's Secure Boot key",
    DELETE: "Stop trusting Ubuntu's key",
}
STEP_VAR = {REVOCATIONS: "MokXNew", CA: "MokNew", DELETE: "MokDel"}
MANAGER_ITEM = {REVOCATIONS: "Enroll MOKX", CA: "Enroll MOK", DELETE: "Delete MOK"}
AUTH_VAR = {"MokNew": "MokAuth", "MokXNew": "MokXAuth", "MokDel": "MokDelAuth", "MokXDel": "MokXDelAuth"}

PASSWORD_RE = re.compile(r"[A-Za-z0-9]{4,32}")


def _err(text: str, hint: str = "") -> BeastNetError:
    return BeastNetError(TRUST, text, hint)


# -- EFI_GUID and EFI_SIGNATURE_LIST ------------------------------------------------

def guid_str(b: bytes) -> str:
    """The text form of a 16-byte EFI_GUID (mixed endian, like uuid.UUID(bytes_le=))."""
    if len(b) != 16:
        raise ValueError("a GUID is 16 bytes")
    d1, d2, d3 = struct.unpack_from("<IHH", b)
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def guid_bytes(s: str) -> bytes:
    p = s.split("-")
    if len(p) != 5 or [len(x) for x in p] != [8, 4, 4, 4, 12]:
        raise ValueError(f"not a GUID: {s!r}")
    return struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16)) + bytes.fromhex(p[3] + p[4])


def parse_esl(blob: bytes) -> list[tuple[str, bytes]]:
    """Every entry of a list of EFI_SIGNATURE_LISTs as (type GUID, data without the owner)."""
    out = []
    p = 0
    while p < len(blob):
        if p + 28 > len(blob):
            raise ValueError(f"truncated EFI_SIGNATURE_LIST at offset {p}")
        sig_type = guid_str(blob[p:p + 16])
        list_size, hdr_size, sig_size = struct.unpack_from("<III", blob, p + 16)
        if list_size < 28 + hdr_size or p + list_size > len(blob) or sig_size <= 16:
            raise ValueError(f"bad EFI_SIGNATURE_LIST at offset {p}")
        if (list_size - 28 - hdr_size) % sig_size:
            raise ValueError(f"EFI_SIGNATURE_LIST at offset {p}: size is not a multiple of {sig_size}")
        q = p + 28 + hdr_size
        while q < p + list_size:
            out.append((sig_type, blob[q + 16:q + sig_size]))
            q += sig_size
        p += list_size
    return out


def make_esl(sig_type: str, data: bytes, owner: str = SHIM_GUID) -> bytes:
    """One EFI_SIGNATURE_LIST holding one entry (what mokutil writes per key)."""
    return (guid_bytes(sig_type) + struct.pack("<III", 28 + 16 + len(data), 0, 16 + len(data))
            + guid_bytes(owner) + data)


# -- X.509 (only the subject and the expiry date, read from the DER) ------------------

_ATTR = {"2.5.4.3": "CN", "2.5.4.11": "OU", "2.5.4.10": "O", "2.5.4.7": "L", "2.5.4.8": "ST",
         "2.5.4.6": "C", "2.5.4.9": "street", "0.9.2342.19200300.100.1.25": "DC",
         "0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "emailAddress"}
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _tlv(b: bytes, p: int, end: int) -> tuple[int, int, int]:
    """(tag, start, end) of the contents of the DER element at ``p``."""
    if p + 2 > end:
        raise ValueError("truncated DER")
    tag, n = b[p], b[p + 1]
    p += 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or p + k > end:
            raise ValueError("bad DER length")
        n = int.from_bytes(b[p:p + k], "big")
        p += k
    if p + n > end:
        raise ValueError("truncated DER")
    return tag, p, p + n


def _kids(b: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, p = [], start
    while p < end:
        out.append(_tlv(b, p, end))
        p = out[-1][2]
    return out


def _oid(b: bytes) -> str:
    first = min(b[0] // 40, 2)
    parts, v = [first, b[0] - 40 * first], 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _escape(v: str) -> str:
    """RFC 4514 escaping, as openssl's -nameopt RFC2253 prints it."""
    out = "".join("\\" + ch if ch in '"+,;<>\\' else ch for ch in v)
    if out.startswith(("#", " ")):
        out = "\\" + out
    if out.endswith(" ") and not out.endswith("\\ "):
        out = out[:-1] + "\\ "
    return out


def _string(tag: int, data: bytes) -> str:
    if tag in (0x0C, 0x13, 0x16, 0x12, 0x1A):  # UTF8, Printable, IA5, Numeric, Visible
        return data.decode("utf-8")
    if tag == 0x14:  # T61String
        return data.decode("latin-1")
    if tag == 0x1E:  # BMPString
        return data.decode("utf-16-be")
    raise ValueError(f"unsupported string type {tag:#x} in the subject")


def _time(tag: int, data: bytes) -> str:
    t = data.decode("ascii")
    if tag == 0x17 and re.fullmatch(r"\d{12}Z", t):  # UTCTime
        y = int(t[:2])
        t = f"{1900 + y if y >= 50 else 2000 + y}{t[2:]}"
    elif not (tag == 0x18 and re.fullmatch(r"\d{14}Z", t)):  # GeneralizedTime
        raise ValueError("bad validity time")
    mon = int(t[4:6])
    if not 1 <= mon <= 12:
        raise ValueError("bad validity time")
    return f"{_MONTHS[mon - 1]} {int(t[6:8]):2d} {t[8:10]}:{t[10:12]}:{t[12:14]} {t[:4]} GMT"


def der_cert_info(der: bytes) -> tuple[str, str]:
    """(subject as RFC 4514 text, notAfter as openssl prints it) of a DER X.509
    certificate, read from the certificate itself."""
    try:
        tag, s, e = _tlv(der, 0, len(der))
        if tag != 0x30 or e != len(der):
            raise ValueError("not a DER SEQUENCE")
        tag, s, e = _tlv(der, s, e)  # tbsCertificate
        if tag != 0x30:
            raise ValueError("no tbsCertificate")
        tbs = _kids(der, s, e)
        if tbs and tbs[0][0] == 0xA0:  # [0] version
            tbs = tbs[1:]
        if len(tbs) < 6 or tbs[3][0] != 0x30 or tbs[4][0] != 0x30:
            raise ValueError("bad tbsCertificate")
        validity = _kids(der, tbs[3][1], tbs[3][2])
        if len(validity) != 2:
            raise ValueError("bad validity")
        not_after = _time(validity[1][0], der[validity[1][1]:validity[1][2]])
        rdns = []
        for tag, s, e in _kids(der, tbs[4][1], tbs[4][2]):
            if tag != 0x31:
                raise ValueError("bad subject")
            attrs = []
            for tag2, s2, e2 in _kids(der, s, e):
                kids = _kids(der, s2, e2)
                if tag2 != 0x30 or len(kids) != 2 or kids[0][0] != 0x06:
                    raise ValueError("bad subject attribute")
                (_t, os_, oe), (vt, vs, ve) = kids
                oid = _oid(der[os_:oe])
                if oid in _ATTR:
                    attrs.append(f"{_ATTR[oid]}={_escape(_string(vt, der[vs:ve]))}")
                else:
                    attrs.append(f"{oid}=#{der[oe:ve].hex()}")  # the whole value TLV
            rdns.append("+".join(attrs))
        return ",".join(reversed(rdns)), not_after
    except (IndexError, ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"not a DER X.509 certificate ({e})") from None


# -- the trust files ----------------------------------------------------------------

@dataclass
class Cert:
    file: str  # relative to the trust directory
    path: str
    der: bytes
    subject: str
    not_after: str = ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.der).hexdigest()

    @property
    def name(self) -> str:
        m = re.search(r"(?:^|,)CN=((?:[^,\\]|\\.)*)", self.subject)
        return m.group(1).replace("\\", "") if m else self.subject


def sha1_text(hexdigest: str) -> str:
    """SHA-1 as MokManager shows it ("Fingerprint (SHA1)"): bytes separated by spaces."""
    return " ".join(hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2))


@dataclass
class TrustFiles:
    dir: str
    source: str
    ca: Cert
    revoked: list[Cert]
    revoked_hashes: list[str]  # hex SHA-256 entries of Ubuntu shim's vendor_dbx


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_trust(d: str) -> TrustFiles:
    """Read the trust files and check every one against trust.json. Any
    difference (missing, changed or extra file, inconsistent manifest) refuses."""
    hint = ("The helper on this stick is damaged or was changed. Write the stick again "
            "with the BeastBoot installer.")
    try:
        with open(os.path.join(d, "trust.json"), encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError) as e:
        raise _err(f"cannot read {d}/trust.json ({e.__class__.__name__}): refused", hint) from None
    try:
        if m.get("schema") != 1:
            raise ValueError("unknown trust.json schema")
        files = m["files"]
        if not isinstance(files, dict) or not files:
            raise ValueError("trust.json lists no files")
        for rel, want in files.items():
            if not isinstance(rel, str) or rel.startswith("/") or ".." in rel.split("/"):
                raise ValueError(f"bad path {rel!r} in trust.json")
            p = os.path.join(d, rel)
            if not os.path.isfile(p) or os.path.islink(p):
                raise ValueError(f"{rel} is missing")
            if _sha256_file(p) != want:
                raise ValueError(f"{rel} does not match its SHA-256 in trust.json")
        extra = []
        for dirpath, _dirs, names in os.walk(d):
            for n in names:
                rel = os.path.relpath(os.path.join(dirpath, n), d).replace(os.sep, "/")
                if rel != "trust.json" and rel not in files:
                    extra.append(rel)
        if extra:
            raise ValueError(f"{', '.join(sorted(extra))} not listed in trust.json")

        def cert(entry: dict) -> Cert:
            rel = entry["file"]
            if files.get(rel) != entry["sha256"]:
                raise ValueError(f"{rel}: trust.json entries disagree")
            p = os.path.join(d, rel)
            with open(p, "rb") as f:
                der = f.read()
            try:
                subject, not_after = der_cert_info(der)
            except ValueError as e:
                raise ValueError(f"{rel}: {e}") from None
            # What is shown comes from the certificate; trust.json must agree with it.
            for key, real in (("subject", subject), ("not_after", not_after)):
                if entry.get(key) and entry[key] != real:
                    raise ValueError(f"{rel}: its {key} differs from the one in trust.json")
            return Cert(rel, p, der, subject, not_after)

        ca = cert(m["vendor_cert"])
        revoked = [cert(e) for e in m["vendor_dbx"]["x509"]]
        for c in revoked:
            if c.file != f"revoked/{c.sha256}.der":
                raise ValueError(f"{c.file} is not named after its SHA-256")
        if len({c.sha256 for c in revoked}) != len(revoked) or ca.sha256 in {c.sha256 for c in revoked}:
            raise ValueError("duplicate certificates in trust.json")
        hashes = [str(h).lower() for h in m["vendor_dbx"]["sha256"]]
        with open(os.path.join(d, "revoked-sha256.txt"), encoding="ascii") as f:
            listed = [ln.strip().lower() for ln in f if ln.strip()]
        if listed != hashes or any(not re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes):
            raise ValueError("revoked-sha256.txt and trust.json disagree")
        if not revoked and not hashes:
            raise ValueError("trust.json has no revocations")
        source = str(m.get("source", ""))
    except (KeyError, TypeError, ValueError, OSError, UnicodeDecodeError) as e:
        raise _err(f"the trust files in {d} do not match trust.json ({e}): refused", hint) from None
    return TrustFiles(d, source, ca, revoked, hashes)


# -- EFI variables ------------------------------------------------------------------

class EfiVars:
    """Read-only view of efivarfs (and of /sys/firmware/efi/mok-variables)."""

    def __init__(self, sys_root: str) -> None:
        self.efi = os.path.join(sys_root, "firmware", "efi")
        self.dir = os.path.join(self.efi, "efivars")
        self.mok_dir = os.path.join(self.efi, "mok-variables")

    def is_uefi(self) -> bool:
        return os.path.isdir(self.efi)

    def mounted(self) -> bool:
        """efivarfs is mounted (an empty efivars directory means it is not)."""
        try:
            return bool(os.listdir(self.dir))
        except OSError:
            return False

    def path(self, name: str, guid: str = SHIM_GUID) -> str:
        return os.path.join(self.dir, f"{name}-{guid}")

    def read(self, name: str, guid: str = SHIM_GUID) -> bytes | None:
        """The variable's data (without efivarfs' 4-byte attributes), None if absent."""
        try:
            with open(self.path(name, guid), "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            return None
        except OSError as e:
            raise _err(f"cannot read the EFI variable {name}: {e.strerror}") from None
        return raw[4:] if len(raw) >= 4 else b""

    def read_list(self, name: str) -> bytes | None:
        """A list shim mirrors at runtime (MokListRT, MokListXRT). Linux shows
        shim's configuration table under mok-variables/ (complete); otherwise
        efivarfs has it, split into NAME, NAME1, NAME2... when it is large."""
        try:
            with open(os.path.join(self.mok_dir, name), "rb") as f:
                return f.read()
        except OSError:
            pass
        first = self.read(name)
        if first is None:
            return None
        parts = [first]
        i = 1
        while (more := self.read(f"{name}{i}")) is not None:
            parts.append(more)
            i += 1
        return b"".join(parts)

    def secure_boot(self) -> bool | None:
        v = self.read("SecureBoot", GLOBAL_GUID)
        return None if not v else v[0] == 1


def shim_vendor_entries(path: str) -> set[str]:
    """SHA-256 of every certificate/hash a shim binary has built in (its
    .vendor_cert section: vendor_authorized and vendor_deauthorized)."""
    try:
        with open(path, "rb") as f:
            data = f.read(64 << 20)
    except OSError:
        return set()
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return set()
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        off = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
        section = None
        for _ in range(nsec):
            if data[off:off + 8].rstrip(b"\0") == b".vendor_":  # ".vendor_cert" is cut at 8 bytes
                vsize, _va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
                section = data[rptr:rptr + (min(vsize, rsize) if vsize else rsize)]
            elif data[off:off + 8].rstrip(b"\0").startswith(b"/"):
                symptr, nsym = struct.unpack_from("<II", data, pe + 12)
                idx = int(data[off + 1:off + 8].rstrip(b"\0"))
                name = data[symptr + nsym * 18 + idx:].split(b"\0", 1)[0]
                if name == b".vendor_cert":
                    vsize, _va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
                    section = data[rptr:rptr + (min(vsize, rsize) if vsize else rsize)]
            off += 40
        if section is None:
            return set()
        a_size, d_size, a_off, d_off = struct.unpack_from("<IIII", section, 0)
        out = set()
        auth = section[a_off:a_off + a_size]
        if auth.startswith(b"\x30"):
            out.add(hashlib.sha256(auth).hexdigest())
        elif auth:
            out |= {hashlib.sha256(e).hexdigest() if t == X509_GUID else e.hex() for t, e in parse_esl(auth)}
        deauth = section[d_off:d_off + d_size]
        if deauth:
            out |= {hashlib.sha256(e).hexdigest() if t == X509_GUID else e.hex() for t, e in parse_esl(deauth)}
        return out
    except (struct.error, ValueError):
        return set()


def _entries(blob: bytes | None, what: str) -> set[str]:
    """SHA-256 (hex) of each X.509 entry, and the hex of each SHA-256 entry."""
    if not blob:
        return set()
    try:
        items = parse_esl(blob)
    except ValueError as e:
        raise _err(f"{what} is malformed ({e})") from None
    out = set()
    for t, data in items:
        if t == X509_GUID:
            out.add(hashlib.sha256(data).hexdigest())
        elif t == SHA256_GUID and len(data) == 32:
            out.add(data.hex())
    return out


# -- state --------------------------------------------------------------------------

@dataclass
class Status:
    files: TrustFiles
    state: str
    problem: str = ""  # why it cannot be checked (state UNAVAILABLE)
    secure_boot: bool | None = None
    shim_lists: bool = False  # MokListRT / MokListXRT were found
    ca_trusted: bool = False
    revoked_missing: list[Cert] = field(default_factory=list)
    hashes_missing: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)  # MokNew, MokXNew, ...

    @property
    def revoked_total(self) -> int:
        return len(self.files.revoked) + len(self.files.revoked_hashes)

    @property
    def revoked_present(self) -> int:
        return self.revoked_total - len(self.revoked_missing) - len(self.hashes_missing)

    @property
    def next_step(self) -> str | None:
        """The one request the two-step rule allows now (None: nothing to request)."""
        if self.state in (UNAVAILABLE, BUILT_IN) or self.pending:
            return None
        if self.revoked_missing or self.hashes_missing:
            return REVOCATIONS
        if not self.ca_trusted:
            return CA
        return None

    @property
    def can_delete(self) -> bool:
        return self.state not in (UNAVAILABLE, BUILT_IN) and not self.pending and self.ca_trusted

    def event_words(self) -> list[str]:
        sb = "unknown" if self.secure_boot is None else str(int(self.secure_boot))
        return [f"state={self.state}", f"sb={sb}", f"ca={int(self.ca_trusted)}",
                f"revoked={self.revoked_present}/{self.revoked_total}",
                f"pending={','.join(self.pending) or 'none'}"]


@dataclass
class Request:
    step: str
    certs: list[Cert]
    hashes: list[str]
    source: str

    @property
    def var(self) -> str:
        return STEP_VAR[self.step]

    @property
    def manager_item(self) -> str:
        return MANAGER_ITEM[self.step]

    def expected(self) -> set[tuple[str, bytes]]:
        return ({(X509_GUID, c.der) for c in self.certs}
                | {(SHA256_GUID, bytes.fromhex(h)) for h in self.hashes})


def check_password(password: str, again: str) -> str:
    """'' if the one-time password is usable, else what is wrong with it."""
    if not PASSWORD_RE.fullmatch(password or ""):
        return "Use 4 to 32 letters (A-Z, a-z) or digits."
    if password != again:
        return "The two passwords differ. Type the same password twice."
    return ""


class TrustUbuntu:
    """State, two-step planning and the mokutil requests."""

    def __init__(self, paths: Paths, *, reporter: Reporter | None = None, dry_run: bool = False,
                 runner: Runner | None = None, trust_dir: str | None = None,
                 mokutil: str = "mokutil", say: Callable[[str], None] | None = None) -> None:
        self.paths = paths
        self.reporter = reporter or Reporter()
        self.dry_run = dry_run
        self.runner = runner or Runner(log_path=os.path.join(paths.run, "commands.log"))
        self.trust_dir = trust_dir or os.path.join(paths.root, TRUST_DIR.lstrip("/"))
        self.mokutil = mokutil
        self.say = say or (lambda text: None)
        self.vars = EfiVars(paths.sys)

    # -- reading ------------------------------------------------------------------
    def _mount_efivarfs(self) -> None:
        if self.dry_run or not self.paths.is_beast_net() or self.vars.mounted():
            return
        self.runner.run(["mount", "-t", "efivarfs", "-o", "nosuid,nodev,noexec", "efivarfs",
                         self.vars.dir], timeout=30)

    def status(self) -> Status:
        files = load_trust(self.trust_dir)
        if not self.vars.is_uefi():
            st = Status(files, UNAVAILABLE, problem=(
                "This computer started the stick in BIOS (legacy) mode. Secure Boot, shim and "
                "MokManager exist only when it starts in UEFI mode: choose the stick's UEFI "
                "entry in the boot menu."))
            self._report(st)
            return st
        self._mount_efivarfs()
        if not self.vars.mounted():
            st = Status(files, UNAVAILABLE, problem=(
                f"The EFI variables cannot be read: efivarfs is not mounted at {self.vars.dir}."))
            self._report(st)
            return st
        sb = self.vars.secure_boot()
        mok = self.vars.read_list("MokListRT")
        mokx = self.vars.read_list("MokListXRT")
        trusted = _entries(mok, "MokListRT")
        revoked = _entries(mokx, "MokListXRT")
        pending = [n for n in PENDING if self.vars.read(n) is not None]
        ca = files.ca.sha256 in trusted
        missing = [c for c in files.revoked if c.sha256 not in revoked]
        missing_h = [h for h in files.revoked_hashes if h not in revoked]
        n_missing = len(missing) + len(missing_h)
        total = len(files.revoked) + len(files.revoked_hashes)
        built_in = shim_vendor_entries(os.path.join(self.paths.esp, *SHIM_ON_ESP))
        ours = {files.ca.sha256} | {c.sha256 for c in files.revoked} | set(files.revoked_hashes)
        if built_in & ours:
            state = BUILT_IN
        elif ca and not n_missing:
            state = TRUSTED
        elif not ca and not n_missing:
            state = REVOCATIONS_ONLY
        elif not ca and n_missing == total:
            state = NOT_TRUSTED
        else:
            state = PARTIAL
        st = Status(files, state, secure_boot=sb, shim_lists=mok is not None or mokx is not None,
                    ca_trusted=ca, revoked_missing=missing, hashes_missing=missing_h, pending=pending)
        self._report(st)
        return st

    def _report(self, st: Status) -> None:
        self.reporter.emit("trust", *st.event_words())

    # -- requesting ---------------------------------------------------------------
    def plan(self, st: Status, step: str) -> Request:
        """The request for ``step``, or a refusal that explains why not now."""
        if st.state == UNAVAILABLE:
            raise _err("the Secure Boot key lists cannot be read here", st.problem)
        if st.state == BUILT_IN:
            raise _err("this drive's shim already has Ubuntu's key built in: nothing to enroll",
                       "This happens only with a shim that is not BeastBoot's.")
        if st.pending:
            raise _err(f"a request is already waiting for MokManager ({', '.join(st.pending)})",
                       "Reboot first: MokManager opens before the menu. Confirm or cancel the "
                       "request there, then open \"Trust Ubuntu's Secure Boot key\" again.")
        f = st.files
        if step == REVOCATIONS:
            if not (st.revoked_missing or st.hashes_missing):
                raise _err("Ubuntu's revocations are already in MokListX")
            return Request(REVOCATIONS, list(st.revoked_missing), list(st.hashes_missing),
                           f.source + " (vendor_dbx)")
        if step == CA:
            if st.revoked_missing or st.hashes_missing:
                raise _err(f"refused: Ubuntu's key is requested only after all {st.revoked_total} "
                           f"of Ubuntu's revocations are in MokListX ({st.revoked_present} are)",
                           "Do step 1 first: add Ubuntu's revocations, reboot and confirm "
                           "\"Enroll MOKX\" in MokManager.")
            if st.ca_trusted:
                raise _err("Ubuntu's key is already trusted")
            return Request(CA, [f.ca], [], f.source + " (vendor certificate)")
        if step == DELETE:
            if not st.ca_trusted:
                raise _err("Ubuntu's key is not in MokList: nothing to delete")
            return Request(DELETE, [f.ca], [], f.source + " (vendor certificate)")
        raise ValueError(f"unknown step {step!r}")

    def request(self, step: str, password: str, again: str | None = None) -> Request:
        """Check the state again, then ask mokutil for ``step`` with a one-time
        password, and verify the request it wrote. Raises BeastNetError(TRUST)."""
        problem = check_password(password, password if again is None else again)
        if problem:
            raise _err(f"the one-time password is not usable: {problem}")
        req = self.plan(self.status(), step)
        self.reporter.emit("trust request", f"step={req.step}", f"var={req.var}",
                           f"certs={len(req.certs)}", f"hashes={len(req.hashes)}")
        if self.dry_run:
            self.say(f"[dry-run] would run mokutil for {req.var}: "
                     + ", ".join([c.file for c in req.certs] + req.hashes))
            return req
        hash_file = self._hash_file(password)
        try:
            for argv in self.commands(req, hash_file):
                cp = self.runner.run(argv, timeout=60, env=self._env())
                if cp.returncode != 0:
                    msg = (cp.stderr or cp.stdout).strip().splitlines()
                    what = f"mokutil failed (exit code {cp.returncode}): {msg[-1] if msg else 'no output'}"
                    # raises if a partial request stays behind
                    cancelled = self._revoke(req, what)
                    raise _err(what, ("The part it had stored was cancelled: nothing is waiting "
                                      "for MokManager." if cancelled else "Nothing was requested.")
                               + " The details are in /run/beastnet/commands.log (Open a shell).")
        finally:
            try:
                os.unlink(hash_file)
            except OSError:
                pass
        self._verify(req)
        self.reporter.emit("trust requested", f"step={req.step}", f"var={req.var}")
        return req

    def commands(self, req: Request, hash_file: str) -> list[list[str]]:
        # --ignore-keyring: Ubuntu's kernel has Canonical certificates built into its
        # own keyring; that says nothing about MokList, so mokutil must not skip them.
        mokx = ["--mokx"] if req.step == REVOCATIONS else []
        out = []
        if req.certs:
            verb = "--delete" if req.step == DELETE else "--import"
            out.append([self.mokutil, *mokx, "--hash-file", hash_file, "--ignore-keyring", verb,
                        *[c.path for c in req.certs]])
        for h in req.hashes:
            out.append([self.mokutil, *mokx, "--hash-file", hash_file, "--import-hash", h])
        return out

    def _env(self) -> dict | None:
        # libefivar's EFIVARFS_PATH: only when the efivars are not the real ones (tests).
        if os.path.normpath(self.vars.dir) != DEFAULT_EFIVARS:
            return {"EFIVARFS_PATH": self.vars.dir.rstrip("/") + "/"}
        return None

    def _hash_file(self, password: str) -> str:
        """mokutil --generate-hash reads the password twice from stdin (no
        terminal dialogue, the password never appears on a command line)."""
        try:
            cp = subprocess.run([self.mokutil, "--generate-hash"], input=f"{password}\n{password}\n",
                                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise _err(f"cannot run mokutil: {e}", "mokutil is part of the helper; is the stick "
                       "complete?") from None
        crypt = [ln.strip() for ln in cp.stdout.splitlines() if ln.strip().startswith("$")]
        if cp.returncode != 0 or not crypt:
            raise _err(f"mokutil could not hash the password (exit code {cp.returncode})")
        os.makedirs(self.paths.run, exist_ok=True)
        path = os.path.join(self.paths.run, f"mok-password.{os.getpid()}")
        try:
            os.unlink(path)
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(crypt[-1])
        return path

    def _verify(self, req: Request) -> None:
        """The request variable must hold exactly what was asked for."""
        blob = self.vars.read(req.var)
        try:
            got = set(parse_esl(blob or b""))
        except ValueError:
            got = set()
        if got != req.expected():
            what = f"{req.var} does not hold exactly the requested entries"
            self._revoke(req, what)  # raises if the request stays
            raise _err(f"{what}: request cancelled",
                       "Checked: nothing is waiting for MokManager. Try again; if it happens "
                       "again, report it.")

    def _present(self, name: str) -> bool:
        try:
            return self.vars.read(name) is not None
        except BeastNetError:
            return True  # unreadable: assume it is still there

    def _revoke(self, req: Request, why: str) -> bool:
        """Cancel the request ``req`` wrote (its variable and the password hash).
        False if there was none, True once reading them back shows both gone;
        raises when either is still there, since MokManager would offer it."""
        names = [req.var, AUTH_VAR[req.var]]
        if not any(self._present(n) for n in names):
            return False
        mokx = ["--mokx"] if req.step == REVOCATIONS else []
        verb = "--revoke-delete" if req.step == DELETE else "--revoke-import"
        cp = self.runner.run([self.mokutil, *mokx, verb], timeout=60, env=self._env())
        left = [n for n in names if self._present(n)]
        if not left:
            return True
        self.reporter.emit("trust revoke-failed", f"var={req.var}", f"exit={cp.returncode}",
                           f"left={','.join(left)}")
        raise _err(f"{why}, and cancelling that request failed (mokutil exit code {cp.returncode}): "
                   f"a request BeastBoot did not intend is still waiting ({', '.join(left)})",
                   "Do not confirm it. On the next boot, at the blue \"Perform MOK management\" "
                   "screen, choose \"Continue boot\" (or let it time out). To cancel it now: "
                   f"Open a shell, run 'mokutil {' '.join(mokx + [verb])}', then open "
                   "\"Trust Ubuntu's Secure Boot key\" again to check that nothing is waiting.")


# -- texts for the screens ----------------------------------------------------------

def state_text(st: Status) -> str:
    """A short summary for the helper's screen."""
    lines = [f"Ubuntu's Secure Boot key: {STATE_LABEL[st.state]}."]
    if st.state == UNAVAILABLE:
        return "\n".join(lines + [st.problem])
    if st.state == BUILT_IN:
        return "\n".join(lines + ["This drive's shim already trusts Ubuntu's key by itself, so "
                                  "there is nothing to enroll."])
    if st.state == NOT_TRUSTED:
        lines.append("With Secure Boot on, boot loaders and kernels signed by Ubuntu (Canonical) "
                     "are refused: Ubuntu ISOs and many ISOs based on Ubuntu. Two steps change "
                     "that, each confirmed in MokManager after a reboot.")
    elif st.state == REVOCATIONS_ONLY:
        lines.append(f"All {st.revoked_total} of Ubuntu's revocations are in MokListX. Step 2 "
                     "adds Ubuntu's key (Canonical's Master CA) to MokList.")
    elif st.state == TRUSTED:
        lines.append(f"Canonical's Master CA is in MokList and Ubuntu's {st.revoked_total} "
                     "revocations are in MokListX: boot loaders and kernels signed by Ubuntu "
                     "(Canonical) boot.")
    else:
        lines.append(f"Ubuntu's key is {'in' if st.ca_trusted else 'not in'} MokList; "
                     f"{st.revoked_present} of Ubuntu's {st.revoked_total} revocations are in "
                     "MokListX. Adding the missing revocations is always safe.")
        if st.ca_trusted and (st.revoked_missing or st.hashes_missing):
            lines.append("Until the missing revocations are added, binaries signed with those "
                         "revoked Canonical certificates are trusted on this computer.")
    if st.pending:
        lines.append("Waiting for MokManager: " + ", ".join(f"{n} ({PENDING[n]})" for n in st.pending)
                     + ". Reboot to confirm it in MokManager.")
    if st.secure_boot is False:
        lines.append("Secure Boot is off on this computer, so nothing is refused now. The keys "
                     "matter only with Secure Boot on; you can still set them up.")
    elif not st.shim_lists:
        lines.append("shim published no MokListRT/MokListXRT: the helper was probably not "
                     "started through shim.")
    return "\n".join(lines)


ABOUT = """\
BeastBoot starts through Debian's shim. With Secure Boot on it trusts \
Microsoft's keys, Debian's key and your BeastBoot key, but not Ubuntu's key. \
Boot loaders and kernels signed by Ubuntu (Canonical), as on Ubuntu ISOs and \
the many ISOs that use Ubuntu's signed GRUB and kernels, are therefore \
refused, unless you trust Ubuntu's key here. Turning Secure Boot off in the \
firmware settings works too.

Trusting it takes two steps, each confirmed in MokManager after a reboot:

1. Ubuntu's revocations go into MokListX: the older Canonical signing \
certificates Ubuntu itself revoked, so binaries signed with them stay refused.

2. Then Ubuntu's key, Canonical's Master CA, goes into MokList. The helper \
requests it only once every revocation is in MokListX. From then on shim \
accepts every EFI program Canonical signed: GRUB builds, kernels, firmware \
tools such as fwupd. Only the certificates revoked in step 1 and shim's SBAT \
rules still refuse some of them.

The files were copied from Ubuntu's own signed shim when this helper was \
built. The helper checks them against trust.json, the list of their SHA-256 \
values on the stick: that catches a damaged stick, not one someone changed \
on purpose. So before you confirm in MokManager, choose "View key" and \
compare the Subject and the SHA-1 fingerprint of Canonical's Master CA with \
the ones published in the BeastBoot user guide and on its website. Nothing \
else is enrolled, and the firmware's own key databases are not touched.

MokList and MokListX belong to this computer, not to the stick: every shim \
on this computer (an installed Ubuntu, Fedora, Debian...) then trusts what \
Canonical signed too. "Stop trusting Ubuntu's key" removes the CA again \
(the revocations stay)."""


def request_text(req: Request) -> str:
    """What will be requested, with the fingerprints MokManager shows."""
    if req.step == REVOCATIONS:
        head = (f"These {len(req.certs) + len(req.hashes)} entries Ubuntu revoked will be added to "
                "MokListX, so they stay refused on this computer:")
    elif req.step == CA:
        head = "This certificate will be added to MokList: this computer then trusts it."
    else:
        head = "This certificate will be removed from MokList (the revocations stay in MokListX):"
    lines = [head, ""]
    for i, c in enumerate(req.certs, 1):
        lines += [f"{i}. {c.name}", f"   Subject {c.subject}"]
        if c.not_after:
            lines.append(f"   Expires {c.not_after}")
        lines += [f"   SHA-256 {c.sha256}", f"   SHA-1   {sha1_text(c.sha1)}"]
    for i, h in enumerate(req.hashes, len(req.certs) + 1):
        lines += [f"{i}. binary hash (SHA-256)", f"   {h}"]
    lines += ["", f"Source: {req.source}.",
              "In MokManager, \"View key\" shows each key's Subject and SHA-1 fingerprint: they "
              "must be the ones above."]
    if req.step == REVOCATIONS:
        lines.append("Entries in MokListX can only make shim refuse programs, never trust them.")
    else:
        lines.append("This screen and the files come from the stick, so they cannot show "
                     "whether someone changed it. Compare the SHA-1 with the one published in "
                     "the BeastBoot user guide and on its website before you confirm.")
    return "\n".join(lines)


def next_text(req: Request) -> str:
    """What to do after a request."""
    lines = [
        f"The request is stored ({req.var}). It takes effect only after you confirm it:",
        "",
        "1. Reboot and start from this stick again (or from any shim-based system on this computer).",
        "2. A blue \"Perform MOK management\" screen appears: press a key within 10 seconds.",
        f"3. Choose \"{req.manager_item}\", then \"View key\": the Subject and the SHA-1 fingerprint "
        "must match the ones shown before"
        + ("" if req.step == REVOCATIONS else " and the SHA-1 in the BeastBoot user guide")
        + ". Then choose \"Continue\" and \"Yes\".",
        "4. Type the one-time password you just chose.",
        "5. Choose \"Reboot\".",
    ]
    if req.step == REVOCATIONS:
        lines += ["", "Then open \"Trust Ubuntu's Secure Boot key\" again for step 2."]
    elif req.step == CA:
        lines += ["", "Then boot loaders and kernels signed by Ubuntu (Canonical) boot with "
                  "Secure Boot on."]
    lines += ["", "If the blue screen times out or you choose \"Continue boot\", nothing is "
              "enrolled. Open this screen again: it shows whether the request still waits."]
    return "\n".join(lines)
