"""build/keygen.sh and build/sbkeys.sh: the BeastBoot CA, its three leaf
certificates, and the checks the build and build/sign.sh make before they use
them (docs/RELEASING.md section 3). Runs the real scripts with openssl."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
KEYGEN = ROOT / "build" / "keygen.sh"
SBKEYS = ROOT / "build" / "sbkeys.sh"
COMPONENTS = ("grub", "kernel", "wimboot")
MODSIGN_ONLY = "1.3.6.1.4.1.2312.16.1.2"

pytestmark = pytest.mark.skipif(not shutil.which("openssl") or not shutil.which("sha256sum"),
                                reason="needs openssl and sha256sum")


def keygen(*args: str, key_dir: Path, ca_dir: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    env = {**os.environ, "BB_KEY_DIR": str(key_dir), "BB_KEY_CN": "test CA"}
    env.pop("BB_CA_DIR", None)
    if ca_dir is not None:
        env["BB_CA_DIR"] = str(ca_dir)
    p = subprocess.run(["bash", str(KEYGEN), *args], capture_output=True, text=True, env=env)
    assert not check or p.returncode == 0, p.stdout + p.stderr
    return p


def text(crt: Path) -> str:
    return subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-text", "-nameopt", "RFC2253"],
                          capture_output=True, text=True, check=True).stdout


def sbkeys(func: str, *args: Path | str) -> str:
    """What a function of build/sbkeys.sh prints."""
    p = subprocess.run(["bash", "-c", 'source "$0"; "$@"', str(SBKEYS), func, *map(str, args)],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip()


@pytest.fixture(scope="module")
def keys(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("keys")
    keygen(key_dir=d)
    return d


def test_make_keys_writes_a_ca_and_three_leaves(keys):
    names = {p.name for p in keys.iterdir()}
    assert names == {"beast-boot-ca.key", "beast-boot.crt", "beast-boot.cer",
                     *(f"beast-boot-{c}.{ext}" for c in COMPONENTS for ext in ("key", "crt"))}
    for p in keys.glob("*.key"):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p
    der = subprocess.run(["openssl", "x509", "-in", str(keys / "beast-boot.crt"), "-outform", "DER"],
                         capture_output=True, check=True).stdout
    assert der == (keys / "beast-boot.cer").read_bytes()


def test_certificate_profiles(keys):
    ca = text(keys / "beast-boot.crt")
    assert "CA:TRUE, pathlen:0" in ca and "Certificate Sign" in ca and "Extended Key Usage" not in ca
    assert "Subject: CN=test CA" in ca and "Issuer: CN=test CA" in ca
    for c in COMPONENTS:
        leaf = text(keys / f"beast-boot-{c}.crt")
        assert "CA:FALSE" in leaf and "Digital Signature" in leaf and "Code Signing" in leaf
        assert "Certificate Sign" not in leaf and MODSIGN_ONLY not in leaf
        assert f"OU={c}," in leaf and "Issuer: CN=test CA" in leaf
        subprocess.run(["openssl", "verify", "-CAfile", str(keys / "beast-boot.crt"),
                        str(keys / f"beast-boot-{c}.crt")], check=True, capture_output=True)
        assert sbkeys("bb_leaf_problem", keys / "beast-boot.crt", keys / f"beast-boot-{c}.crt", c) == ""
    assert sbkeys("bb_ca_problem", keys / "beast-boot.crt") == ""
    assert len({(keys / f"beast-boot-{c}.key").read_text() for c in COMPONENTS}) == 3


def test_existing_keys_are_not_overwritten(keys):
    before = (keys / "beast-boot.cer").read_bytes()
    p = keygen(key_dir=keys, check=False)
    assert p.returncode != 0 and "refusing to overwrite" in p.stderr
    p = keygen("leaf", "grub", key_dir=keys, check=False)
    assert p.returncode != 0 and "refusing to overwrite" in p.stderr
    assert (keys / "beast-boot.cer").read_bytes() == before


def test_a_leaf_is_replaced_without_a_new_ca(tmp_path):
    keygen(key_dir=tmp_path)
    ca, old = (tmp_path / "beast-boot.cer").read_bytes(), (tmp_path / "beast-boot-wimboot.crt").read_text()
    grub = (tmp_path / "beast-boot-grub.crt").read_text()
    keygen("leaf", "wimboot", "--force", key_dir=tmp_path)
    assert (tmp_path / "beast-boot.cer").read_bytes() == ca, "the certificate users enroll must not change"
    assert (tmp_path / "beast-boot-wimboot.crt").read_text() != old
    assert (tmp_path / "beast-boot-grub.crt").read_text() == grub
    assert sbkeys("bb_leaf_problem", tmp_path / "beast-boot.crt", tmp_path / "beast-boot-wimboot.crt", "wimboot") == ""


def test_offline_ca_and_leaves_elsewhere(tmp_path):
    """The release layout: the CA key in one place, the leaves (and only public CA files) in another."""
    ca_dir, leaves = tmp_path / "ca", tmp_path / "leaves"
    keygen("ca", key_dir=leaves, ca_dir=ca_dir)
    assert {p.name for p in ca_dir.iterdir()} == {"beast-boot-ca.key", "beast-boot.crt", "beast-boot.cer"}
    assert not leaves.exists()
    keygen("leaf", "all", key_dir=leaves, ca_dir=ca_dir)
    assert "beast-boot-ca.key" not in {p.name for p in leaves.iterdir()}
    assert (leaves / "beast-boot.cer").read_bytes() == (ca_dir / "beast-boot.cer").read_bytes()
    p = keygen(key_dir=leaves, ca_dir=ca_dir, check=False)
    assert p.returncode != 0 and "one directory" in p.stderr
    p = keygen("leaf", "grub", key_dir=tmp_path / "x", ca_dir=tmp_path / "no-ca", check=False)
    assert p.returncode != 0 and "no CA in" in p.stderr
    p = keygen("leaf", "shim", key_dir=leaves, ca_dir=ca_dir, check=False)
    assert p.returncode != 0 and "unknown component" in p.stderr


def test_a_leaf_is_refused_for_another_component_or_another_ca(keys, tmp_path):
    ca = keys / "beast-boot.crt"
    assert "is not the wimboot signing certificate" in sbkeys("bb_leaf_problem", ca, keys / "beast-boot-grub.crt", "wimboot")
    assert "is a CA certificate" in sbkeys("bb_leaf_problem", ca, ca, "grub")
    assert "not found" in sbkeys("bb_leaf_problem", ca, keys / "none.crt", "grub")
    keygen(key_dir=tmp_path)
    assert "is not a valid certificate issued by" in sbkeys("bb_leaf_problem", ca, tmp_path / "beast-boot-grub.crt", "grub")
    assert "is not a CA certificate" in sbkeys("bb_ca_problem", keys / "beast-boot-grub.crt")


def test_an_expired_leaf_is_refused_by_the_build_checks(tmp_path):
    """shim ignores certificate dates; the build and build/sign.sh do not (bb_leaf_problem):
    an expired leaf is replaced with `keygen.sh leaf COMPONENT --force`, the CA stays."""
    keygen(key_dir=tmp_path)
    ca, leaf = tmp_path / "beast-boot.crt", tmp_path / "beast-boot-kernel.crt"
    (tmp_path / "ext").write_text("basicConstraints=critical,CA:FALSE\nextendedKeyUsage=codeSigning\n")
    subprocess.run(["openssl", "req", "-new", "-key", str(tmp_path / "beast-boot-kernel.key"),
                    "-subj", "/O=test CA/OU=kernel/CN=expired kernel signer", "-out", str(tmp_path / "csr")],
                   check=True, capture_output=True)
    p = subprocess.run(["openssl", "x509", "-req", "-in", str(tmp_path / "csr"), "-CA", str(ca),
                        "-CAkey", str(tmp_path / "beast-boot-ca.key"), "-set_serial", "7", "-extfile", str(tmp_path / "ext"),
                        "-not_before", "20200101000000Z", "-not_after", "20210101000000Z", "-out", str(leaf)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        pytest.skip("this openssl cannot set a certificate's dates (-not_after needs OpenSSL 3.4)")
    problem = sbkeys("bb_leaf_problem", ca, leaf, "kernel")
    assert "expired" in problem and "keygen.sh leaf kernel" in problem, problem
    keygen("leaf", "kernel", "--force", key_dir=tmp_path)
    assert sbkeys("bb_leaf_problem", ca, leaf, "kernel") == ""


def test_component_of_each_signed_file():
    assert [sbkeys("bb_component_of", n) for n in ("grubx64.efi", "vmlinuz", "wimboot")] == list(COMPONENTS)
