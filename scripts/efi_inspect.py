"""PE/COFF + Authenticode + SBAT inspection for EFI binaries (python3 stdlib only).

Used by gen_sbom.py (signing facts as SBOM properties) and scan_vulns.py
(boot-chain checks). Certificate details come from `openssl x509`.

Authenticode digest: PE/COFF spec "Calculating the PE Image Hash" - the image is
hashed with the CheckSum field, the Certificate Table directory entry and the
certificate table itself excluded. The result is checked against the digest
stored in the image's own signature (SpcIndirectDataContent), so a bug here
shows up as `digest_matches_signature: false` instead of a silent wrong dbx check.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- PE


class PEError(ValueError):
    pass


@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int


@dataclass
class PE:
    data: bytes
    machine: int
    magic: int
    checksum_off: int
    certdir_off: int | None
    cert_off: int
    cert_size: int
    size_of_headers: int
    dll_characteristics: int
    sections: list[Section] = field(default_factory=list)

    def section(self, name: str) -> bytes | None:
        for s in self.sections:
            if s.name == name:
                n = min(s.raw_size, s.vsize) if s.vsize else s.raw_size
                return self.data[s.raw_ptr:s.raw_ptr + n]
        return None


MACHINES = {0x8664: "x86_64", 0x14c: "i386", 0xaa64: "aarch64", 0x1c2: "arm", 0x5064: "riscv64"}


def parse_pe(data: bytes) -> PE:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("not an MZ/PE file")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise PEError("PE signature missing")
    coff = pe_off + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        dd_off, nrva_off = opt + 112, opt + 108
    elif magic == 0x10B:
        dd_off, nrva_off = opt + 96, opt + 92
    else:
        raise PEError(f"unknown optional header magic 0x{magic:x}")
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    dllch = struct.unpack_from("<H", data, opt + 70)[0]
    nrva = struct.unpack_from("<I", data, nrva_off)[0]
    certdir_off = dd_off + 4 * 8 if nrva > 4 else None
    cert_off = cert_size = 0
    if certdir_off is not None:
        cert_off, cert_size = struct.unpack_from("<II", data, certdir_off)
    sec_tab = opt + opt_size
    sym_ptr, nsym = struct.unpack_from("<II", data, coff + 8)
    strtab = sym_ptr + 18 * nsym if sym_ptr else None
    sections = []
    for i in range(nsec):
        o = sec_tab + 40 * i
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        if name.startswith("/") and name[1:].isdigit() and strtab is not None:
            # long section name (e.g. ".sbatlevel"): offset into the COFF string table
            s = strtab + int(name[1:])
            name = data[s:data.index(b"\0", s)].decode("ascii", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
        sections.append(Section(name, vaddr, vsize, raw_ptr, raw_size))
    return PE(data, machine, magic, opt + 64, certdir_off, cert_off, cert_size,
              size_of_headers, dllch, sections)


def authenticode_digest(pe: PE, algo: str = "sha256") -> bytes:
    d = pe.data
    h = hashlib.new(algo)
    h.update(d[:pe.checksum_off])
    if pe.certdir_off is None:
        h.update(d[pe.checksum_off + 4:pe.size_of_headers])
    else:
        h.update(d[pe.checksum_off + 4:pe.certdir_off])
        h.update(d[pe.certdir_off + 8:pe.size_of_headers])
    hashed = pe.size_of_headers
    for s in sorted(pe.sections, key=lambda s: s.raw_ptr):
        if s.raw_size == 0:
            continue
        h.update(d[s.raw_ptr:s.raw_ptr + s.raw_size])
        hashed = max(hashed, s.raw_ptr + s.raw_size)
    end = pe.cert_off if pe.cert_size else len(d)
    if hashed < end:
        h.update(d[hashed:end])
    return h.digest()


def win_certificates(pe: PE) -> list[tuple[int, int, bytes]]:
    """[(wRevision, wCertificateType, bCertificate)] from the certificate table."""
    out = []
    if not pe.cert_size:
        return out
    off, end = pe.cert_off, pe.cert_off + pe.cert_size
    while off + 8 <= end:
        length, rev, ctype = struct.unpack_from("<IHH", pe.data, off)
        if length < 8:
            break
        out.append((rev, ctype, pe.data[off + 8:off + length]))
        off += (length + 7) & ~7
    return out


# --------------------------------------------------------------------------- SBAT


def parse_sbat_csv(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split(",")
        rows.append({
            "component": f[0],
            "generation": int(f[1]) if len(f) > 1 and f[1].isdigit() else None,
            "vendor": f[2] if len(f) > 2 else "",
            "package": f[3] if len(f) > 3 else "",
            "version": f[4] if len(f) > 4 else "",
            "url": f[5] if len(f) > 5 else "",
        })
    return rows


def sbat_text(pe: PE) -> str | None:
    raw = pe.section(".sbat")
    if raw is None:
        return None
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def sbatlevel(pe: PE) -> dict | None:
    """shim's .sbatlevel section: u32 version, u32 off(previous), u32 off(latest),
    offsets relative to byte 4; each payload is a NUL-terminated SbatLevel CSV."""
    raw = pe.section(".sbatlevel")
    if not raw or len(raw) < 12:
        return None
    _ver, p_off, l_off = struct.unpack_from("<III", raw, 0)

    def cstr(o: int) -> str:
        s = raw[4 + o:]
        return s.split(b"\0", 1)[0].decode("utf-8", "replace")
    return {"previous": cstr(p_off), "latest": cstr(l_off)}


def parse_sbat_level(text: str) -> dict:
    """'sbat,1,2024010900\nshim,4\ngrub,3' -> {'datestamp': '2024010900', 'components': {...}}"""
    comps, stamp = {}, None
    for line in text.replace(" ", "\n").splitlines():
        f = [x for x in line.strip().split(",") if x != ""]
        if not f:
            continue
        if f[0] == "sbat" and len(f) >= 3:
            stamp = f[2]
        elif len(f) >= 2 and f[1].isdigit():
            comps[f[0]] = int(f[1])
    return {"datestamp": stamp, "components": comps}


def parse_sbat_level_variable_txt(text: str) -> list[dict]:
    """All revocation levels in rhboot/shim SbatLevel_Variable.txt, oldest first."""
    levels, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        m = re.fullmatch(r"sbat,1,(\d{10})", s)
        if m:
            cur = {"datestamp": m.group(1), "components": {}}
            levels.append(cur)
            continue
        m = re.fullmatch(r"([A-Za-z0-9._-]+),(\d+)", s)
        if m and cur is not None:
            cur["components"][m.group(1)] = int(m.group(2))
        elif cur is not None and s == "":
            cur = None if cur["components"] else cur
    levels = [lv for lv in levels if lv["components"]]
    levels.sort(key=lambda lv: lv["datestamp"])
    return levels


# --------------------------------------------------------------------------- DER


def _tlv(b: bytes, off: int) -> tuple[int, int, int, int]:
    """(tag, content_start, content_end, header_start)"""
    start = off
    tag = b[off]
    off += 1
    if tag & 0x1F == 0x1F:
        while b[off] & 0x80:
            off += 1
        off += 1
    ln = b[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0:
            raise ValueError("indefinite length not supported")
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    return tag, off, off + ln, start


def _children(b: bytes, start: int, end: int):
    off = start
    while off < end:
        t, cs, ce, hs = _tlv(b, off)
        yield t, cs, ce, hs
        off = ce


def _oid(b: bytes) -> str:
    vals, v = [], 0
    for c in b:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            vals.append(v)
            v = 0
    first = 0 if vals[0] < 40 else 1 if vals[0] < 80 else 2
    return ".".join(str(x) for x in [first, vals[0] - 40 * first] + vals[1:])


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT = "1.3.6.1.4.1.311.2.1.4"
OID_NESTED_SIG = "1.3.6.1.4.1.311.2.4.1"
DIGEST_OIDS = {"2.16.840.1.101.3.4.2.1": "sha256", "1.3.14.3.2.26": "sha1",
               "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}


@dataclass
class Signature:
    digest_algo: str | None
    digest: bytes | None
    certs: list[bytes]                       # DER certificates carried in the PKCS#7
    signer_ids: list[tuple[bytes, bytes]]    # (issuer DER, serial bytes) per SignerInfo
    nested: list[Signature] = field(default_factory=list)
    raw: bytes = b""                         # the PKCS#7 SignedData (DER), without padding
    content: bytes = b""                     # signed content: SpcIndirectDataContent value octets
    unparsed_nested: int = 0                 # nested signatures that could not be parsed


def parse_pkcs7(blob: bytes) -> Signature:
    t, cs, ce, _ = _tlv(blob, 0)
    kids = list(_children(blob, cs, ce))
    if not kids or _oid(blob[kids[0][1]:kids[0][2]]) != OID_SIGNED_DATA:
        raise ValueError("not a PKCS#7 SignedData")
    _, scs, sce, _ = _tlv(blob, kids[1][1])            # [0] -> SignedData SEQUENCE
    sd = list(_children(blob, scs, sce))
    algo = digest = None
    certs: list[bytes] = []
    signer_ids: list[tuple[bytes, bytes]] = []
    nested: list[Signature] = []
    unparsed_nested = 0
    idx = 2                                              # version, digestAlgorithms, contentInfo
    ci = sd[idx]
    ci_kids = list(_children(blob, ci[1], ci[2]))
    content = b""
    if _oid(blob[ci_kids[0][1]:ci_kids[0][2]]) == OID_SPC_INDIRECT and len(ci_kids) > 1:
        _, ics, ice, _ = _tlv(blob, ci_kids[1][1])     # [0] -> SpcIndirectDataContent
        content = blob[ics:ice]          # Authenticode signs the value without its SEQUENCE header
        spc = list(_children(blob, ics, ice))
        dinfo = list(_children(blob, spc[1][1], spc[1][2]))
        alg = list(_children(blob, dinfo[0][1], dinfo[0][2]))
        algo = DIGEST_OIDS.get(_oid(blob[alg[0][1]:alg[0][2]]))
        digest = blob[dinfo[1][1]:dinfo[1][2]]
    for t, a, z, hs in sd[idx + 1:]:
        if t == 0xA0:                                    # certificates [0] IMPLICIT
            for _t, _a, cz, chs in _children(blob, a, z):
                certs.append(blob[chs:cz])
        elif t == 0x31:                                  # signerInfos
            for _t, sa, sz, _h in _children(blob, a, z):
                si = list(_children(blob, sa, sz))
                ias = list(_children(blob, si[1][1], si[1][2]))
                issuer = blob[ias[0][3]:ias[0][2]]
                serial = blob[ias[1][1]:ias[1][2]]
                signer_ids.append((issuer, serial))
                for st, sa2, sz2, _h2 in si:
                    if st == 0xA1:                       # unauthenticatedAttributes
                        for _t3, aa, az, _h3 in _children(blob, sa2, sz2):
                            attr = list(_children(blob, aa, az))
                            if _oid(blob[attr[0][1]:attr[0][2]]) == OID_NESTED_SIG:
                                for _t4, va, vz, vh in _children(blob, attr[1][1], attr[1][2]):
                                    try:
                                        nested.append(parse_pkcs7(blob[vh:vz]))
                                    except (ValueError, IndexError):
                                        unparsed_nested += 1
    return Signature(algo, digest, certs, signer_ids, nested, blob[:ce], content, unparsed_nested)


def verify_signature(sig: Signature, ca_pem: Path | str) -> bool:
    """Does `sig` verify cryptographically with the certificate in `ca_pem` as trust anchor?

    `openssl smime -verify` over the signed SpcIndirectDataContent, so the signer's key
    signed exactly the digest this signature carries, and the signer chains (through the
    certificates carried in the signature) to `ca_pem`. Like the firmware and shim: an
    intermediate CA may be the anchor (-partial_chain), certificate dates are not checked
    (-no_check_time) and any extended key usage is accepted. `ca_pem` is the only anchor:
    OpenSSL's default certificate directory and store (/etc/ssl/certs, $SSL_CERT_DIR) are
    not loaded (-no-CApath -no-CAstore), or with -partial_chain every certificate there
    would count as `ca_pem`. The image digest itself is compared separately
    (digest_matches_signature)."""
    if not sig.raw or not sig.content:
        return False
    with tempfile.TemporaryDirectory(prefix="efi-inspect-") as d:
        p7, content = Path(d, "sig.p7"), Path(d, "content.bin")
        p7.write_bytes(sig.raw)
        content.write_bytes(sig.content)
        r = subprocess.run(["openssl", "smime", "-verify", "-inform", "DER", "-in", str(p7), "-binary",
                            "-content", str(content), "-CAfile", str(ca_pem), "-no-CApath", "-no-CAstore",
                            "-partial_chain",
                            "-no_check_time", "-purpose", "any", "-out", os.devnull],
                           capture_output=True, text=True)
    return r.returncode == 0


def signatures(pe: PE) -> list[Signature]:
    """Every Authenticode signature: each WIN_CERTIFICATE of type PKCS_SIGNED_DATA, then
    the signatures nested inside them (older multi-signing). Unparseable entries are skipped
    (unparsed_entries() lists them; policy checks must treat them as problems)."""
    out = []
    for _rev, ctype, blob in win_certificates(pe):
        if ctype != 0x0002:
            continue
        try:
            sig = parse_pkcs7(blob)
        except (ValueError, IndexError):
            continue
        out.append(sig)
        out.extend(sig.nested)
    return out


def unparsed_entries(pe: PE) -> list[str]:
    """Certificate-table entries signatures() skips: other WIN_CERTIFICATE types, PKCS#7 our
    DER parser rejects (shim's OpenSSL also reads BER) and unparseable nested signatures."""
    out = []
    for i, (_rev, ctype, blob) in enumerate(win_certificates(pe)):
        if ctype != 0x0002:
            out.append(f"entry {i}: WIN_CERTIFICATE type {ctype:#06x}")
            continue
        try:
            sig = parse_pkcs7(blob)
        except (ValueError, IndexError) as e:
            out.append(f"entry {i}: unparseable PKCS#7 ({e})")
            continue
        stack = [sig]
        while stack:
            s = stack.pop()
            if s.unparsed_nested:
                out.append(f"entry {i}: {s.unparsed_nested} unparseable nested signature(s)")
            stack.extend(s.nested)
    return out


def cert_issuer_serial(der: bytes) -> tuple[bytes, bytes]:
    _, cs, ce, _ = _tlv(der, 0)
    tbs = next(_children(der, cs, ce))
    kids = list(_children(der, tbs[1], tbs[2]))
    i = 1 if kids[0][0] == 0xA0 else 0
    serial = der[kids[i][1]:kids[i][2]]
    issuer = der[kids[i + 2][3]:kids[i + 2][2]]
    return issuer, serial


# --------------------------------------------------------------------------- certs


def cert_info(der: bytes) -> dict:
    """Subject, issuer, validity, key and EKU of a DER certificate (via openssl)."""
    with tempfile.NamedTemporaryFile(suffix=".der") as f:
        f.write(der)
        f.flush()
        out = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", f.name, "-noout", "-nameopt", "RFC2253",
             "-subject", "-issuer", "-serial", "-startdate", "-enddate", "-text"],
            check=True, capture_output=True, text=True).stdout
    def grab(prefix: str) -> str:
        for line in out.splitlines():
            if line.startswith(prefix):
                return line[len(prefix):].strip()
        return ""
    not_before = _openssl_date(grab("notBefore="))
    not_after = _openssl_date(grab("notAfter="))
    m = re.search(r"Public Key Algorithm: (\S+)", out)
    key_alg = m.group(1) if m else ""
    m = re.search(r"Public-Key: \((\d+) bit\)", out)
    key_bits = int(m.group(1)) if m else None
    m = re.search(r"Signature Algorithm: (\S+)", out)
    sig_alg = m.group(1) if m else ""
    eku = ""
    m = re.search(r"X509v3 Extended Key Usage:.*?\n\s+(.+)", out)
    if m:
        eku = m.group(1).strip()
    subject = grab("subject=")
    return {
        "subject": subject,
        "issuer": grab("issuer="),
        "cn": _cn(subject),
        "issuer_cn": _cn(grab("issuer=")),
        "serial": grab("serial="),
        "not_before": not_before,
        "not_after": not_after,
        "key_algorithm": key_alg,
        "key_bits": key_bits,
        "signature_algorithm": sig_alg,
        "extended_key_usage": eku,
        "code_signing_eku": "Code Signing" in eku,
        "self_signed": subject == grab("issuer="),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
    }


def _cn(dn: str) -> str:
    m = re.search(r"(?:^|,)CN=((?:\\,|[^,])+)", dn)
    return m.group(1).replace("\\,", ",") if m else dn


def _openssl_date(s: str) -> str | None:
    if not s:
        return None
    s = re.sub(r"\s+", " ", s.replace(" GMT", "")).strip()
    dt = _dt.datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=_dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- facade


def inspect_efi(path: Path) -> dict:
    """Everything the SBOM and the boot-chain checks need about one EFI binary."""
    data = Path(path).read_bytes()
    pe = parse_pe(data)
    res: dict = {
        "machine": MACHINES.get(pe.machine, hex(pe.machine)),
        "nx_compat": bool(pe.dll_characteristics & 0x0100),
        "sbat": sbat_text(pe),
        "sbatlevel": sbatlevel(pe),
        "authenticode_sha256": authenticode_digest(pe, "sha256").hex(),
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "signatures": [],
    }

    def describe(sig: Signature) -> dict:
        certs = [cert_info(c) for c in sig.certs]
        by_id = {cert_issuer_serial(c): i for i, c in enumerate(sig.certs)}
        signer_idx = [by_id.get(sid) for sid in sig.signer_ids]
        signer = certs[signer_idx[0]] if signer_idx and signer_idx[0] is not None else None
        computed = authenticode_digest(pe, sig.digest_algo).hex() if sig.digest_algo else None
        return {
            "digest_algorithm": sig.digest_algo,
            "signed_digest": sig.digest.hex() if sig.digest else None,
            "digest_matches_signature": computed is not None and computed == (sig.digest or b"").hex(),
            "signer": signer,
            "certificates": certs,
            "cert_der": sig.certs,
        }
    for _rev, ctype, blob in win_certificates(pe):
        if ctype != 0x0002:                              # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            continue
        try:
            sig = parse_pkcs7(blob)
        except (ValueError, IndexError) as e:
            res["signatures"].append({"error": f"unparseable signature: {e}"})
            continue
        res["signatures"].append(describe(sig))
        for n in sig.nested:
            d = describe(n)
            d["nested"] = True
            res["signatures"].append(d)
    return res


def public_view(info: dict) -> dict:
    """inspect_efi() result without raw DER blobs (JSON-serialisable)."""
    out = dict(info)
    out["signatures"] = [{k: v for k, v in s.items() if k != "cert_der"} for s in info["signatures"]]
    return out


# --------------------------------------------------------------------------- shim vendor keys

EFI_CERT_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EFI_CERT_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"


def _guid(b: bytes) -> str:
    a, b2, c = struct.unpack_from("<IHH", b, 0)
    return f"{a:08x}-{b2:04x}-{c:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def parse_esl(data: bytes) -> dict:
    """EFI_SIGNATURE_LIST entries -> {"x509": [DER, ...], "sha256": [hex, ...], "other": n}."""
    out: dict = {"x509": [], "sha256": [], "other": 0}
    off = 0
    while off + 28 <= len(data):
        stype = _guid(data[off:off + 16])
        list_size, header_size, sig_size = struct.unpack_from("<III", data, off + 16)
        if list_size < 28 or sig_size < 16 or off + list_size > len(data):
            raise ValueError("malformed EFI_SIGNATURE_LIST")
        p = off + 28 + header_size
        while p + sig_size <= off + list_size:
            entry = data[p + 16:p + sig_size]           # after the owner GUID
            if stype == EFI_CERT_X509:
                out["x509"].append(entry)
            elif stype == EFI_CERT_SHA256:
                out["sha256"].append(entry.hex())
            else:
                out["other"] += 1
            p += sig_size
        off += list_size
    return out


def shim_vendor(pe: PE) -> dict | None:
    """shim's .vendor_cert section (struct cert_table): the built-in vendor key(s) and
    vendor_dbx. -> {"cert": [DER, ...], "dbx": parse_esl(...)}, or None if absent."""
    raw = pe.section(".vendor_cert")
    if not raw or len(raw) < 16:
        return None
    a_size, d_size, a_off, d_off = struct.unpack_from("<IIII", raw, 0)
    auth, deauth = raw[a_off:a_off + a_size], raw[d_off:d_off + d_size]
    certs = [auth] if auth[:1] == b"\x30" else parse_esl(auth)["x509"]   # one DER cert, or a vendor_db ESL
    return {"cert": certs, "dbx": parse_esl(deauth) if deauth else {"x509": [], "sha256": [], "other": 0}}


def der_to_pem(ders: list[bytes]) -> str:
    return "".join(subprocess.run(["openssl", "x509", "-inform", "DER"], input=c, capture_output=True,
                                  check=True).stdout.decode() for c in ders)


# --------------------------------------------------------------------------- signer checks


def check_signers(path: Path, cas: dict[str, Path]) -> dict:
    """Which of the named CA certificates (PEM files) each signature of `path` chains to.
    -> {"authenticode_sha256", "signatures": [{"signer", "digest_algorithm", "signed_digest",
        "digest_matches_signature", "chains_to": [names], "cert_sha256": [...]}]}"""
    pe = parse_pe(Path(path).read_bytes())
    out: dict = {"authenticode_sha256": authenticode_digest(pe).hex(), "signatures": [],
                 "win_certificates": len(win_certificates(pe)), "unparsed": unparsed_entries(pe)}
    for sig in signatures(pe):
        by_id = {cert_issuer_serial(c): c for c in sig.certs}
        signer = by_id.get(sig.signer_ids[0]) if sig.signer_ids else None
        computed = authenticode_digest(pe, sig.digest_algo).hex() if sig.digest_algo else None
        out["signatures"].append({
            "signer": cert_info(signer)["subject"] if signer else None,
            "digest_algorithm": sig.digest_algo,
            "signed_digest": sig.digest.hex() if sig.digest else None,
            "digest_matches_signature": computed is not None and computed == (sig.digest or b"").hex(),
            "chains_to": [n for n, pem in cas.items() if verify_signature(sig, pem)],
            "cert_sha256": [hashlib.sha256(c).hexdigest() for c in sig.certs],
            "signer_infos": len(sig.signer_ids),
        })
    return out


def _named(value: str) -> tuple[str, Path]:
    name, sep, pem = value.partition("=")
    if not sep or not Path(pem).is_file():
        raise SystemExit(f"efi_inspect: --ca/--chains/--only take NAME=FILE.pem, got {value!r}")
    return name, Path(pem)


def require(path: Path, chains: list[str], only: str | None, vendor_of: str | None,
            denied: list[str] = ()) -> list[str]:
    """The policy checks of `efi_inspect.py require` (see main()); prints one line per
    signature and returns the problems found."""
    cas = dict(_named(c) for c in [*chains, *([only] if only else []), *denied])
    with tempfile.TemporaryDirectory(prefix="efi-inspect-") as d:
        vendor = None
        if vendor_of:
            vendor = shim_vendor(parse_pe(Path(vendor_of).read_bytes()))
            if not vendor or not vendor["cert"]:
                return [f"{vendor_of} has no vendor certificate"]
            Path(d, "vendor.pem").write_text(der_to_pem(vendor["cert"]))
            cas["the vendor certificate of " + Path(vendor_of).name] = Path(d, "vendor.pem")
        info = check_signers(path, cas)
    problems = [f"cannot read every signature ({u}); refusing to judge what it does not see"
                for u in info["unparsed"]]
    good = [s for s in info["signatures"] if s["digest_matches_signature"]]
    for s in info["signatures"]:
        print(f"{path.name}: signature by {s['signer']} over {s['digest_algorithm']}:"
              f"{(s['signed_digest'] or '?')[:16]}... "
              f"({'= the image digest' if s['digest_matches_signature'] else 'NOT the image digest'}), "
              f"chains to: {', '.join(s['chains_to']) or 'none of the given CAs'}")
    for name in [_named(c)[0] for c in chains]:
        if not any(name in s["chains_to"] for s in good):
            problems.append(f"no signature over the image's Authenticode digest chains to {name}")
    if only:
        name = _named(only)[0]
        n = max(len(info["signatures"]), info["win_certificates"],
                sum(s["signer_infos"] for s in info["signatures"]))
        if n != 1:
            problems.append(f"{n} signatures, expected exactly one (by {name})")
        elif not (good and name in good[0]["chains_to"]):
            problems.append(f"its signature does not verify with {name}")
    for name in [_named(c)[0] for c in denied]:
        if any(name in s["chains_to"] for s in info["signatures"]):
            problems.append(f"signed through the denied certificate {name}")
    if vendor is not None:
        vname = "the vendor certificate of " + Path(vendor_of).name
        if not any(vname in s["chains_to"] for s in good):
            problems.append(f"not signed through {vname}")
        revoked = {hashlib.sha256(c).hexdigest() for c in vendor["dbx"]["x509"]}
        if info["authenticode_sha256"] in vendor["dbx"]["sha256"]:
            problems.append(f"its Authenticode SHA-256 is in the vendor_dbx of {Path(vendor_of).name}")
        if any(c in revoked for s in info["signatures"] for c in s["cert_sha256"]):
            problems.append(f"a certificate of its signature is in the vendor_dbx of {Path(vendor_of).name}")
    if not problems:
        print(f"{path.name}: ok, Authenticode sha256:{info['authenticode_sha256']}")
    return problems


def main(argv: list[str] | None = None) -> int:
    """CLI (build/build.sh, build/verify-dist.sh):

  signers FILE [--ca NAME=PEM]...   JSON: every signature, its digest, the given CAs it chains to
  require FILE [--chains NAME=PEM]... [--only NAME=PEM] [--vendor-of SHIM] [--denied NAME=PEM]...
      exit 1 unless every --chains CA has a signature over the image's own Authenticode
      digest that chains to it (so they all sign the same digest); with --only, the image
      has exactly one signature and it chains to that CA; with --vendor-of, a signature
      chains to SHIM's built-in vendor certificate and neither the image's digest nor a
      certificate of its signatures is in SHIM's vendor_dbx; no signature may chain to a
      --denied certificate (what shim does with MokListX / vendor_dbx certificates).
      Always exit 1 when a certificate-table entry cannot be read (unknown type, PKCS#7
      this parser rejects): what it cannot see it cannot vouch for.
  authenticode FILE                 print the Authenticode SHA-256 (signatures excluded)
"""
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="efi_inspect.py", description=main.__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("signers")
    p.add_argument("file", type=Path)
    p.add_argument("--ca", action="append", default=[])
    p = sub.add_parser("require")
    p.add_argument("file", type=Path)
    p.add_argument("--chains", action="append", default=[])
    p.add_argument("--only")
    p.add_argument("--vendor-of")
    p.add_argument("--denied", action="append", default=[])
    p = sub.add_parser("authenticode")
    p.add_argument("file", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "authenticode":
            print(authenticode_digest(parse_pe(a.file.read_bytes())).hex())
            return 0
        if a.cmd == "signers":
            print(json.dumps(check_signers(a.file, dict(_named(c) for c in a.ca)), indent=2))
            return 0
        problems = require(a.file, a.chains, a.only, a.vendor_of, a.denied)
    except (OSError, PEError, ValueError) as e:
        print(f"efi_inspect: {a.file}: {e}", file=sys.stderr)
        return 1
    for msg in problems:
        print(f"efi_inspect: {a.file}: {msg}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
