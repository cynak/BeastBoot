"""build/winpe/beastmountsrc.py: the pinned MinGW-w64 lock, the version, and the checks of
the built image (PE32+ x86_64 console program, no time stamp, no signature, only KERNEL32 and
msvcrt imported). With the toolchain in the cache (any `make build`), the real build runs
too and must give the same bytes twice. The shipped file is checked by build/verify-dist.sh."""
from __future__ import annotations

import importlib.util
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "build" / "winpe" / "beastmountsrc.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bm = _load("bb_beastmountsrc", SRC)


def test_lock_and_version():
    lock = bm.load_lock()
    names = {p["name"] for p in lock["packages"]}
    assert {"gcc-mingw-w64-x86-64-win32", "binutils-mingw-w64-x86-64", "mingw-w64-x86-64-dev"} <= names
    for p in lock["packages"]:
        assert len(p["sha256"]) == 64 and p["size"] > 0 and p["file"].endswith(".deb")
    assert all(m.startswith("https://") for m in lock["mirrors"])
    assert "-Wl,--no-insert-timestamp" in lock["cflags"] and "-s" in lock["cflags"]
    assert bm.source_version()
    assert {p.name for p in bm.input_files()} == {"beastmount.c", "mingw-w64.lock.json", "beastmountsrc.py"}


def test_lock_rejects_unsafe_paths(tmp_path, monkeypatch):
    lock = bm.load_lock()
    lock["packages"][0]["file"] = "pool/../../etc/passwd.deb"
    bad = tmp_path / "lock.json"
    bad.write_text(__import__("json").dumps(lock))
    monkeypatch.setattr(bm, "LOCK", bad)
    with pytest.raises(bm.Fail, match="bad file"):
        bm.load_lock()


def _built() -> Path | None:
    """The real build, offline (skipped when the pinned .deb files are not in the cache)."""
    env = dict(os.environ, BB_OFFLINE="1")
    r = subprocess.run([sys.executable, "-I", str(SRC), "build", "--quiet"], capture_output=True, text=True,
                       env=env, timeout=600)
    if r.returncode != 0:
        return None
    return Path(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def built() -> Path:
    out = _built()
    if out is None:
        pytest.skip("MinGW-w64 .debs not in the cache (run `make build` once online)")
    return out


def test_real_build_checks_out(built):
    info = bm.verify(built, quiet=True)
    assert info["reproducible"].startswith("built twice")
    facts = info["facts"]
    assert facts["imports"] and {d.lower() for d in facts["imports"]} <= bm.ALLOWED_DLLS
    assert facts["timestamp"] == 0 and not facts["signed"] and facts["subsystem"] == 3


def _mutate(data: bytes, what: str) -> bytes:
    b = bytearray(data)
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if what == "timestamp":
        struct.pack_into("<I", b, pe + 8, 0x6543210F)
    elif what == "import":
        i = b.lower().index(b"msvcrt.dll")
        b[i:i + 10] = b"evil32.dll"
    elif what == "subsystem":
        struct.pack_into("<H", b, pe + 24 + 68, 2)
    elif what == "path":
        b += b"/home/someone/build"
    return bytes(b)


@pytest.mark.parametrize("what,msg", [("timestamp", "TimeDateStamp"), ("import", "evil32.dll"),
                                      ("subsystem", "console"), ("path", "build path")])
def test_check_rejects(built, tmp_path, what, msg):
    p = tmp_path / "beastmount.exe"
    p.write_bytes(_mutate((built / "beastmount.exe").read_bytes(), what))
    with pytest.raises(bm.Fail, match=msg):
        bm.check_output(p)


def test_check_rejects_non_pe(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"\x7fELF" + b"\0" * 1024)
    with pytest.raises(bm.Fail, match="not an MZ/PE"):
        bm.check_output(p)
