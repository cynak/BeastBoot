#!/usr/bin/env python3
"""Extract a shim's built-in trust (vendor certificate and vendor_dbx revocations).

beast-booter boots through Debian's shim, which trusts Debian's key, not
Canonical's. Ubuntu ISOs (and Ubuntu-based ones) keep booting with Secure Boot
on only after the user opts in to "Trust Ubuntu's key" in the beast-net
helper, which enrolls exactly what Ubuntu's own shim trusts and revokes:

  - its vendor certificate (Canonical's Master CA) as a MOK, and
  - every entry of its vendor_dbx (old Canonical signing certificates and
    hashes) in MokListX, so binaries Ubuntu revoked stay refused.

This script reads both from Ubuntu's signed shim and writes them, with a
manifest, to build/trust/canonical/:

  canonical-master-ca.der     the vendor certificate (DER)
  revoked/<sha256>.der        each X.509 entry of vendor_dbx (DER)
  revoked-sha256.txt          each SHA-256 entry of vendor_dbx (hex, one per line)
  trust.json                  what was extracted, from which file, with hashes

Usage:
  scripts/shim_trust.py extract SHIM.efi OUTDIR [--source TEXT]
  scripts/shim_trust.py check OUTDIR            (re-hash the files against trust.json)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import uuid
from pathlib import Path

EFI_CERT_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EFI_CERT_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"


def pe_section(data: bytes, name: str) -> bytes:
    """The raw bytes of the PE section called `name` (long names via the COFF string table)."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    symptr, nsym = struct.unpack_from("<II", data, pe + 12)
    off = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    for _ in range(nsec):
        raw = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        if raw.startswith("/"):
            strtab = symptr + nsym * 18
            raw = data[strtab + int(raw[1:]):].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, _va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        off += 40
        if raw == name:
            return data[rptr:rptr + min(vsize, rsize) if vsize else rsize]
    raise ValueError(f"no {name} section")


def signature_lists(blob: bytes):
    """Yield (type_guid, entry_bytes) for every entry of a list of EFI_SIGNATURE_LISTs."""
    p = 0
    while p + 28 <= len(blob):
        guid = str(uuid.UUID(bytes_le=blob[p:p + 16]))
        list_size, hdr_size, sig_size = struct.unpack_from("<III", blob, p + 16)
        if list_size < 28 or p + list_size > len(blob) or sig_size <= 16:
            raise ValueError(f"bad EFI_SIGNATURE_LIST at offset {p}")
        q = p + 28 + hdr_size
        while q + sig_size <= p + list_size:
            yield guid, blob[q + 16:q + sig_size]   # skip the 16-byte owner GUID
            q += sig_size
        p += list_size


def cert_info(der: bytes) -> dict:
    r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
                        "-startdate", "-enddate", "-nameopt", "RFC2253"],
                       input=der, capture_output=True, check=True)
    info = {}
    for line in r.stdout.decode().splitlines():
        k, _, v = line.partition("=")
        info[{"subject": "subject", "issuer": "issuer", "notBefore": "not_before",
              "notAfter": "not_after"}.get(k.strip(), k.strip())] = v.strip()
    return info


def extract(shim: Path, out: Path, source: str) -> dict:
    data = shim.read_bytes()
    vc = pe_section(data, ".vendor_cert")
    a_size, d_size, a_off, d_off = struct.unpack_from("<IIII", vc, 0)
    authorized = vc[a_off:a_off + a_size]
    deauthorized = vc[d_off:d_off + d_size]
    if not authorized.startswith(b"\x30"):
        raise ValueError("vendor_authorized is not a single DER certificate (vendor db lists are not handled)")
    out.mkdir(parents=True, exist_ok=True)
    (out / "revoked").mkdir(exist_ok=True)
    for old in (out / "revoked").glob("*.der"):
        old.unlink()
    (out / "canonical-master-ca.der").write_bytes(authorized)
    manifest = {
        "schema": 1,
        "generated_by": "scripts/shim_trust.py extract",
        "source": source,
        "source_file": shim.name,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "vendor_cert": {"file": "canonical-master-ca.der", "sha256": hashlib.sha256(authorized).hexdigest(),
                        **cert_info(authorized)},
        "vendor_dbx": {"x509": [], "sha256": []},
    }
    hashes = []
    for guid, entry in signature_lists(deauthorized):
        if guid == EFI_CERT_X509:
            h = hashlib.sha256(entry).hexdigest()
            (out / "revoked" / f"{h}.der").write_bytes(entry)
            manifest["vendor_dbx"]["x509"].append({"file": f"revoked/{h}.der", "sha256": h, **cert_info(entry)})
        elif guid == EFI_CERT_SHA256:
            if len(entry) != 32:
                raise ValueError("SHA-256 entry with a wrong size")
            hashes.append(entry.hex())
        else:
            raise ValueError(f"vendor_dbx entry type {guid} is not handled")
    manifest["vendor_dbx"]["sha256"] = hashes
    (out / "revoked-sha256.txt").write_text("".join(h + "\n" for h in hashes))
    manifest["files"] = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(out.rglob("*")) if p.is_file() and p.name != "trust.json"}
    (out / "trust.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def check(out: Path) -> list[str]:
    m = json.loads((out / "trust.json").read_text())
    problems = []
    for rel, want in m["files"].items():
        p = out / rel
        if not p.is_file():
            problems.append(f"missing {rel}")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != want:
            problems.append(f"changed {rel}")
    extra = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()} - set(m["files"]) - {"trust.json"}
    problems += [f"not in trust.json: {rel}" for rel in sorted(extra)]
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("shim", type=Path)
    e.add_argument("out", type=Path)
    e.add_argument("--source", default="", help="where the shim came from (package and version)")
    c = sub.add_parser("check")
    c.add_argument("out", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "extract":
        m = extract(args.shim, args.out, args.source)
        print(f"vendor cert: {m['vendor_cert']['subject']}")
        print(f"vendor_dbx: {len(m['vendor_dbx']['x509'])} certificates, {len(m['vendor_dbx']['sha256'])} hashes")
        return 0
    problems = check(args.out)
    for p in problems:
        print(f"shim_trust: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
