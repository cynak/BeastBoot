#!/usr/bin/env python3
"""Small helpers for build/build.sh and build/verify-dist.sh (stdlib only).

Kept separate from the bash scripts because JSON and binary parsing in bash
is error-prone. Every subcommand is read-only except `manifest-write`.

  layout NAME...                 print constants from installer/beastbooter/layout.py
  sbat-validate FILE             check SBAT CSV syntax (6 fields, unique names)
  sbatlevel FILE                 print the 'latest' revocation level of a raw
                                 .sbatlevel section dumped from shim
  sbat-vs-level SBAT LEVEL       fail if any SBAT generation is below the level
  build-id DIST VERSION UNSIGNED_SHA256 [--unsigned REL=SHA256]...
                                 deterministic short id of a staged dist/
  manifest-write ...             write dist/manifest.json (schema 1)
  manifest-verify DIST           re-hash every file listed in DIST/manifest.json
  manifest-get DIST KEY.PATH     print one value from the manifest
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYOUT_PY = ROOT / "installer" / "beastbooter" / "layout.py"
GRUB_ESP_EXCLUDE = ("grub/beast/version.cfg",)  # generated, excluded from build-id


def die(msg: str) -> None:
    print(f"bbtool: error: {msg}", file=sys.stderr)
    sys.exit(1)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dist_files(dist: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(dist):
        dirnames.sort()
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), dist).replace(os.sep, "/")
            if rel != "manifest.json":
                out.append(rel)
    return sorted(out)


# --------------------------------------------------------------------------- layout
def load_layout():
    # Load the file directly: importing the package would run its __init__.
    spec = importlib.util.spec_from_file_location("bb_layout", LAYOUT_PY)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def cmd_layout(args) -> None:
    lay = load_layout()
    for name in args.names:
        val = getattr(lay, name)
        if isinstance(val, (tuple, list)):
            print("\n".join(str(v) for v in val))
        else:
            print(val)


# --------------------------------------------------------------------------- SBAT
def parse_sbat(text: str) -> list[list[str]]:
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        fields = line.split(",")
        if len(fields) != 6:
            die(f"SBAT line {n} has {len(fields)} fields, expected 6: {line!r}")
        rows.append(fields)
    return rows


def cmd_sbat_validate(args) -> None:
    text = Path(args.file).read_text(encoding="ascii")
    if not text.endswith("\n"):
        die("SBAT CSV must end with a newline")
    rows = parse_sbat(text)
    if not rows or rows[0][:2] != ["sbat", "1"]:
        die("SBAT CSV must start with the 'sbat,1,...' header line")
    names = [r[0] for r in rows]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        die(f"duplicate SBAT component names: {sorted(dup)}")
    for r in rows:
        if not r[1].isdigit() or int(r[1]) < 1:
            die(f"bad SBAT generation for {r[0]}: {r[1]!r}")


def read_sbatlevel(raw: bytes) -> dict[str, str]:
    """shim .sbatlevel section: u32 version, u32 off_previous, u32 off_latest,
    offsets relative to the end of the version field, NUL-terminated CSVs."""
    if len(raw) < 12:
        die(".sbatlevel section too short")
    _ver, off_prev, off_latest = struct.unpack_from("<III", raw, 0)

    def at(off: int) -> str:
        return raw[4 + off:].split(b"\0", 1)[0].decode("ascii")

    return {"previous": at(off_prev), "latest": at(off_latest)}


def cmd_sbatlevel(args) -> None:
    levels = read_sbatlevel(Path(args.file).read_bytes())
    sys.stdout.write(levels[args.which])


def cmd_sbat_vs_level(args) -> None:
    rows = parse_sbat(Path(args.sbat).read_text(encoding="ascii"))
    ours = {r[0]: int(r[1]) for r in rows}
    level = read_sbatlevel(Path(args.level).read_bytes())[args.which]
    bad = []
    for line in level.splitlines():
        f = line.split(",")
        if len(f) < 2 or f[0] == "sbat":
            continue
        name, gen = f[0], int(f[1])
        if name in ours and ours[name] < gen:
            bad.append(f"{name}: ours {ours[name]} < required {gen}")
    if bad:
        die("SBAT generation(s) are revoked by shim's own revocation level: " + "; ".join(bad))
    print(level.splitlines()[0])


# --------------------------------------------------------------------------- build id
def cmd_build_id(args) -> None:
    dist = Path(args.dist)
    h = hashlib.sha256()
    h.update(f"beast-boot {args.version}\n".encode())
    # Files we sign count by their unsigned hash, so a fresh signature is the same build.
    unsigned = {"esp/EFI/BOOT/grubx64.efi": args.unsigned_sha256}
    for spec in args.unsigned or []:
        rel, sep, digest = spec.partition("=")
        if not sep or len(digest) != 64:
            die(f"--unsigned takes REL=SHA256, got {spec!r}")
        unsigned[rel] = digest
    for rel in dist_files(dist):
        if rel.endswith(GRUB_ESP_EXCLUDE):
            continue
        digest = unsigned.get(rel) or sha256_file(dist / rel)
        h.update(f"{digest}  {rel}\n".encode())
    print(h.hexdigest()[:12])


# --------------------------------------------------------------------------- manifest
def cmd_manifest_write(args) -> None:
    dist = Path(args.dist)
    origins: dict[str, str] = {}
    for line in Path(args.origins).read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        rel, origin = line.split("\t", 1)
        if rel in origins:
            die(f"two origins recorded for {rel}")
        origins[rel] = origin
    files = dist_files(dist)
    missing = [f for f in files if f not in origins]
    stale = [f for f in origins if f not in files]
    if missing:
        die("files without a recorded origin: " + ", ".join(missing))
    if stale:
        die("origins recorded for files that do not exist: " + ", ".join(stale))

    # Extra fields: TSV lines "section.key<TAB>value"; "section.key[]" = space-separated list.
    extra: dict[str, dict] = {"secure_boot": {}, "build": {}}
    for line in Path(args.extra).read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        key, value = line.split("\t", 1)
        section, name = key.split(".", 1)
        if name.endswith("[]"):
            extra[section][name[:-2]] = value.split()
        else:
            extra[section][name] = value
    cert = Path(args.cert_der).read_bytes()
    manifest = {
        "schema": 1,
        "name": "beast-boot",
        "version": args.version,
        "source_date_epoch": int(args.source_date_epoch),
        "build_id": args.build_id,
        "secure_boot": {
            "cert_sha256": hashlib.sha256(cert).hexdigest(),
            "cert_sha1": hashlib.sha1(cert).hexdigest(),  # what MokManager / mokutil display
            "cert_subject": args.cert_subject,
            "sbat": Path(args.sbat).read_text(encoding="ascii"),
            **extra["secure_boot"],
        },
        "build": extra["build"],
        "files": {
            rel: {
                "sha256": sha256_file(dist / rel),
                "size": (dist / rel).stat().st_size,
                "origin": origins[rel],
            }
            for rel in files
        },
    }
    out = Path(args.out)
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="ascii")


def load_manifest(dist: Path) -> dict:
    try:
        m = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        die(f"cannot read {dist}/manifest.json: {e}")
    if m.get("schema") != 1:
        die(f"unsupported manifest schema: {m.get('schema')!r}")
    return m


def cmd_manifest_verify(args) -> None:
    dist = Path(args.dist)
    m = load_manifest(dist)
    listed = m["files"]
    present = set(dist_files(dist))
    errors = 0
    for rel in sorted(listed):
        entry = listed[rel]
        p = dist / rel
        if not p.is_file():
            print(f"MISSING  {rel}")
            errors += 1
            continue
        digest = sha256_file(p)
        if digest != entry["sha256"] or p.stat().st_size != entry["size"]:
            print(f"BAD      {rel}")
            errors += 1
        elif args.verbose:
            print(f"ok       {rel}  {entry['origin']}")
    for rel in sorted(present - set(listed)):
        print(f"UNLISTED {rel}")
        errors += 1
    if errors:
        die(f"{errors} problem(s) in {dist}")
    print(f"manifest: {len(listed)} files, all SHA-256 hashes match")


def cmd_manifest_get(args) -> None:
    val = load_manifest(Path(args.dist))
    for part in args.key.split("."):
        if not isinstance(val, dict) or part not in val:
            die(f"manifest has no key {args.key}")
        val = val[part]
    if isinstance(val, (dict, list)):
        print(json.dumps(val, indent=2))
    else:
        sys.stdout.write(str(val) if str(val).endswith("\n") else f"{val}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("layout"); p.add_argument("names", nargs="+"); p.set_defaults(fn=cmd_layout)
    p = sub.add_parser("sbat-validate"); p.add_argument("file"); p.set_defaults(fn=cmd_sbat_validate)
    p = sub.add_parser("sbatlevel"); p.add_argument("file")
    p.add_argument("--which", choices=("latest", "previous"), default="latest"); p.set_defaults(fn=cmd_sbatlevel)
    p = sub.add_parser("sbat-vs-level"); p.add_argument("sbat"); p.add_argument("level")
    p.add_argument("--which", choices=("latest", "previous"), default="latest"); p.set_defaults(fn=cmd_sbat_vs_level)
    p = sub.add_parser("build-id"); p.add_argument("dist"); p.add_argument("version")
    p.add_argument("unsigned_sha256")
    p.add_argument("--unsigned", action="append", metavar="REL=SHA256",
                   help="another signed file, by the SHA-256 of its unsigned image"); p.set_defaults(fn=cmd_build_id)
    p = sub.add_parser("manifest-write")
    for opt in ("dist", "origins", "out", "version", "source-date-epoch", "build-id",
                "cert-der", "cert-subject", "sbat", "extra"):
        p.add_argument(f"--{opt}", required=True)
    p.set_defaults(fn=cmd_manifest_write)
    p = sub.add_parser("manifest-verify"); p.add_argument("dist")
    p.add_argument("-v", "--verbose", action="store_true"); p.set_defaults(fn=cmd_manifest_verify)
    p = sub.add_parser("manifest-get"); p.add_argument("dist"); p.add_argument("key"); p.set_defaults(fn=cmd_manifest_get)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
