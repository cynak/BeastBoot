"""build/wimboot/wimbootsrc.py: the repo's wimboot inputs, the source archive checks, and
the checks of the built image (hybrid BIOS/UEFI headers, image version, unsigned, SBAT).
The full build is exercised by `make build` and build/verify-dist.sh."""
from __future__ import annotations

import importlib.util
import io
import struct
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WIM = ROOT / "build" / "wimboot"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ws = _load("bb_wimbootsrc", WIM / "wimbootsrc.py")
VERSION = ws.build_version(ws.load_lock())


def test_repo_inputs_load():
    lock = ws.load_lock()
    assert VERSION == f"{lock['upstream_version']}+bb{lock['patch_level']}"
    patches = ws.read_series()
    assert patches, "patches/series is empty"
    for p in patches:
        head = p.read_text().split("\n---\n", 1)[0]
        assert head.startswith("Subject: ") and len(head.splitlines()) > 3, f"{p.name}: explain the patch"
    assert {p.name for p in ws.input_files()} >= {"source.lock.json", "series", "wimbootsrc.py"}


def _pe(*, bzimage=True, machine=0x8664, image_version=1, signed=False, sbat=None) -> bytes:
    if sbat is None:
        sbat = ("sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
                "wimboot,1,iPXE,wimboot,v2.9.0+bb1,https://ipxe.org/wimboot\n"
                f"wimboot.beastboot,1,BeastBoot,wimboot,v{VERSION},https://github.com/cynak/BeastBoot\n")
    b = bytearray(0x1000)
    b[:2] = b"MZ"
    if bzimage:
        b[0x202:0x206] = b"HdrS"
    pe = 0x400
    struct.pack_into("<I", b, 0x3C, pe)
    b[pe:pe + 4] = b"PE\0\0"
    opt_size = 112 + 8 * 6
    struct.pack_into("<HHIIIHH", b, pe + 4, machine, 1, 0, 0, 0, opt_size, 0)
    oh = pe + 24
    struct.pack_into("<H", b, oh, 0x20B)
    struct.pack_into("<H", b, oh + 44, image_version)
    struct.pack_into("<I", b, oh + 108, 6)
    if signed:
        struct.pack_into("<II", b, oh + 112 + 8 * 4, 0xE00, 0x100)
    sh = oh + opt_size
    data = sbat.encode()
    b[sh:sh + 8] = b".sbat\0\0\0"
    struct.pack_into("<IIII", b, sh + 8, len(data), 0x2000, 0x200, 0x800)
    b[0x800:0x800 + len(data)] = data
    return bytes(b)


def test_check_output_accepts_our_image(tmp_path):
    p = tmp_path / "wimboot"
    p.write_bytes(_pe())
    f = ws.check_output(p, VERSION)
    assert f["bzimage"] and f["major_image_version"] == 1 and not f["signed"]


@pytest.mark.parametrize("kw, msg", [
    ({"bzimage": False}, "bzImage"),
    ({"machine": 0x14C}, "not x86_64"),
    ({"image_version": 0}, "MajorImageVersion 0"),
    ({"signed": True}, "signature"),
    ({"sbat": "sbat,1,SBAT Version,sbat,1,x\nwimboot,1,iPXE,wimboot,v2.9.0,https://ipxe.org/wimboot\n"},
     "vendor line"),
])
def test_check_output_refuses(tmp_path, kw, msg):
    p = tmp_path / "wimboot"
    p.write_bytes(_pe(**kw))
    with pytest.raises(ws.Fail, match=msg):
        ws.check_output(p, VERSION)


def _tar(path: Path, commit: str, members: dict[str, bytes | str]) -> Path:
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
        for name, content in members.items():
            ti = tarfile.TarInfo(name)
            if isinstance(content, str):            # a symlink
                ti.type, ti.linkname = tarfile.SYMTYPE, content
                tf.addfile(ti)
            else:
                ti.size = len(content)
                tf.addfile(ti, io.BytesIO(content))
    return path


def test_safe_extract_keeps_src_only_and_checks_the_commit(tmp_path):
    t = _tar(tmp_path / "w.tar.gz", "c0ffee", {"w-1/src/main.c": b"int x;", "w-1/LICENSE.txt": b"GPL",
                                               "w-1/test/wimboot": "../wimboot", "w-1/wimboot": b"MZ"})
    out = tmp_path / "out"
    out.mkdir()
    ws.safe_extract(t, out, "c0ffee")
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()) == ["LICENSE.txt", "src/main.c"]
    with pytest.raises(ws.Fail, match="commit"):
        ws.safe_extract(t, tmp_path / "out2", "deadbeef")


def test_safe_extract_refuses_links_out_of_the_tree(tmp_path):
    t = _tar(tmp_path / "w.tar.gz", "c0ffee", {"w-1/src/evil": "../../etc/passwd"})
    with pytest.raises(ws.Fail, match="unsafe link"):
        ws.safe_extract(t, tmp_path, "c0ffee")


def test_offline_never_downloads(tmp_path, monkeypatch):
    monkeypatch.setenv("BB_OFFLINE", "1")
    monkeypatch.setattr(ws.urllib.request, "urlopen", lambda *a, **k: pytest.fail("download attempted"))
    with pytest.raises(ws.Fail, match="BB_OFFLINE=1"):
        ws.fetch_source(ws.load_lock(), tmp_path)


def test_sbom_parses_wimboot_origins():
    sbom = _load("bb_gen_sbom", ROOT / "scripts" / "gen_sbom.py")
    o = sbom.parse_origin(f"wimboot-src:wimboot={VERSION}:/wimboot")
    assert o["kind"] == "wimboot-src"
    assert o["wimboot"] == [{"name": "wimboot", "version": VERSION, "path": "/wimboot"}]
    assert sbom.UPSTREAMS["wimboot"]["cpe_vendor"] == "ipxe"


def test_winpe_files_are_shipped_with_crlf_by_build_sh():
    text = (ROOT / "build" / "build.sh").read_text()
    for f in ("winpeshl.ini", "beastboot.cmd"):
        assert (ROOT / "build" / "winpe" / f).is_file()
    assert "for f in winpeshl.ini beastboot.cmd; do" in text and "s/$/\\r/" in text
