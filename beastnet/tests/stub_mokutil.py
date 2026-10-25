"""A stand-in for mokutil 0.7 (only what beastnet.trust uses), for the unit tests.

It writes the request variables (MokNew/MokAuth, MokXNew/MokXAuth, MokDel/MokDelAuth)
into the efivarfs folder named by EFIVARFS_PATH, like the real one does through
libefivar. Every call is appended to $STUB_MOKUTIL_LOG as one JSON line.

STUB_MOKUTIL_FAIL=1            exit 1 instead of writing anything
STUB_MOKUTIL_FAIL=after-write  write the request, then exit 1 (a partial request)
STUB_MOKUTIL_EXTRA=1           also enroll one entry nobody asked for
STUB_MOKUTIL_REVOKE_FAIL=1     --revoke-import/--revoke-delete exit 1 and delete nothing
STUB_MOKUTIL_REVOKE_FAIL=silent  ... exit 0 and delete nothing
"""

from __future__ import annotations

import json
import os
import struct
import sys

SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"
X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
SHA256 = "c1c41626-504c-4092-aca9-41f936934328"
NV_BS_RT = 7


def guid_bytes(s: str) -> bytes:
    p = s.split("-")
    return struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16)) + bytes.fromhex(p[3] + p[4])


def esl(sig_type: str, data: bytes) -> bytes:
    return (guid_bytes(sig_type) + struct.pack("<III", 44 + len(data), 0, 16 + len(data))
            + guid_bytes(SHIM) + data)


def var_path(name: str) -> str:
    return os.path.join(os.environ["EFIVARFS_PATH"], f"{name}-{SHIM}")


def append_var(name: str, data: bytes) -> None:
    p = var_path(name)
    old = b""
    if os.path.exists(p):
        with open(p, "rb") as f:
            old = f.read()[4:]
    with open(p, "wb") as f:
        f.write(struct.pack("<I", NV_BS_RT) + old + data)


def set_var(name: str, data: bytes) -> None:
    with open(var_path(name), "wb") as f:
        f.write(struct.pack("<I", NV_BS_RT) + data)


def main(argv: list[str]) -> int:
    log = os.environ.get("STUB_MOKUTIL_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(argv) + "\n")
    if argv == ["--generate-hash"]:
        a, b = sys.stdin.readline().rstrip("\n"), sys.stdin.readline().rstrip("\n")
        print("input password: ")
        print("input password again: ")
        if a != b or not a:
            print("password doesn't match", file=sys.stderr)
            return 255
        print("$6$stubsalt$" + a[::-1])
        return 0
    if os.environ.get("STUB_MOKUTIL_FAIL") == "1":
        print("Failed to write the request", file=sys.stderr)
        return 1
    mokx = "--mokx" in argv
    hash_file = argv[argv.index("--hash-file") + 1] if "--hash-file" in argv else None
    if "--revoke-import" in argv or "--revoke-delete" in argv:
        fail = os.environ.get("STUB_MOKUTIL_REVOKE_FAIL")
        if fail:
            print("Failed to delete the request", file=sys.stderr)
            return 0 if fail == "silent" else 1
        base = ("MokX" if mokx else "Mok") + ("Del" if "--revoke-delete" in argv else "New")
        for n in (base, base.replace("New", "Auth").replace("Del", "DelAuth")):
            try:
                os.unlink(var_path(n))
            except FileNotFoundError:
                pass
        return 0
    if hash_file is None:
        print("this stub needs --hash-file", file=sys.stderr)
        return 2
    with open(hash_file, encoding="ascii") as f:
        auth = f.read().encode()
    entries = b""
    if "--import-hash" in argv:
        entries = esl(SHA256, bytes.fromhex(argv[argv.index("--import-hash") + 1]))
        req = "New"
    else:
        verb = "--delete" if "--delete" in argv else "--import"
        req = "Del" if verb == "--delete" else "New"
        for path in argv[argv.index(verb) + 1:]:
            with open(path, "rb") as f:
                entries += esl(X509, f.read())
    if os.environ.get("STUB_MOKUTIL_EXTRA") == "1":
        entries += esl(X509, b"\x30\x03\x02\x01\x00")
    prefix = "MokX" if mokx else "Mok"
    append_var(prefix + req, entries)
    set_var(prefix + ("Auth" if req == "New" else "DelAuth"), auth)
    if os.environ.get("STUB_MOKUTIL_FAIL") == "after-write":
        print("Failed to write the whole request", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
