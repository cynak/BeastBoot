"""Secure Boot trust fixtures (test_e2e_secureboot.py): UEFI variable stores
with chosen db / MokList / MokListX contents, and signed kernel images.

Everything is pre-seeded with virt-fw-vars in a per-VM copy of the variable
store, the same way the other Secure Boot tests pre-enroll the beast-boot
certificate (what MokManager would store after the user confirmed it).

- "2023-only" store: a generated test PK, Microsoft KEK 2023 and only the
  Microsoft UEFI CA 2023 in db (no 2011 CA), Secure Boot on. That is a PC that
  trusts only the new Microsoft CA.
- MokListX: virt-fw-vars has --add-mok for MokList only. MokListX is the same
  EFI_SIGNATURE_LIST format under the same GUID and attributes, so it is built
  as a MokList in a scratch store, renamed in a JSON dump, and set with
  --set-json.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

from . import env

OWNER = env.MOK_OWNER_GUID
MS_UEFI_CA_2011 = "Microsoft Corporation UEFI CA 2011"
MS_UEFI_CA_2023 = "Microsoft UEFI CA 2023"
CANONICAL_DIR = env.BB_ROOT / "build" / "trust" / "canonical"


def vfv_status() -> tuple[bool, str]:
    """Can virt-fw-vars build the stores these tests need?"""
    if not env.which("virt-fw-vars"):
        return False, "virt-fw-vars not found (source scripts/dev-env.sh; scripts/bootstrap-tools.sh installs it)"
    p = env.run(["virt-fw-vars", "--help"], check=False, timeout=60)
    need = [o for o in ("--microsoft-db", "--microsoft-kek", "--enroll-generate", "--set-json", "--add-mok")
            if o not in p.stdout]
    if p.returncode != 0 or need:
        return False, "virt-fw-vars is too old for these tests (missing " + ", ".join(need or ["--help"]) + ")"
    return True, ""


def _mokx_json(certs: list[Path], workdir: Path) -> Path:
    scratch, dump = workdir / "mokx-scratch.fd", workdir / "mokx-scratch.json"
    cmd = ["virt-fw-vars", "--input", str(env.OVMF_VARS), "--output", str(scratch), "--output-json", str(dump)]
    for c in certs:
        cmd += ["--add-mok", OWNER, str(c)]
    env.run(cmd, timeout=60)
    data = json.loads(dump.read_text())
    mok = [v for v in data["variables"] if v["name"] == "MokList"]
    assert len(mok) == 1, f"no MokList in {dump}"
    mok[0]["name"] = "MokListX"
    out = workdir / "mokx.json"
    out.write_text(json.dumps({"version": data["version"], "variables": mok}, indent=1))
    return out


def make_vars(dest: Path, *, workdir: Path, db: str = "ms", mok: list[Path] = (),
              mokx: list[Path] = ()) -> Path:
    """A writable variable store for one VM.
    db "ms": OVMF's Microsoft store (2011 and 2023 CAs); "2023-only": see the module doc.
    mok / mokx: certificates (DER or PEM) pre-seeded in MokList / MokListX."""
    dest = Path(dest)
    if db == "ms":
        cmd = ["virt-fw-vars", "--input", str(env.OVMF_VARS_MS)]
    elif db == "2023-only":
        cmd = ["virt-fw-vars", "--input", str(env.OVMF_VARS), "--enroll-generate", "BeastBoot test PK",
               "--microsoft-kek", "2023", "--microsoft-db", "uefi23", "--sb"]
    else:
        raise ValueError(f"unknown db {db!r}")
    cmd += ["--output", str(dest)]
    if mokx:
        cmd += ["--set-json", str(_mokx_json(list(mokx), workdir))]
    for c in mok:
        cmd += ["--add-mok", OWNER, str(c)]
    env.run(cmd, timeout=60)
    return dest


def describe(vars_file: Path) -> dict[str, list[str]]:
    """{variable: [certificate subjects]} as `virt-fw-vars --print --verbose` shows them."""
    p = env.run(["virt-fw-vars", "--input", str(vars_file), "--print", "--verbose"], timeout=60)
    out: dict[str, list[str]] = {}
    cur = None
    for line in (p.stdout + p.stderr).splitlines():
        m = re.match(r"^name=(\S+) ", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        m = re.match(r"^\s+subject (.*)$", line)
        if m and cur:
            out[cur].append(m.group(1).strip())
    return out


# ---------------------------------------------------------------------------
# Kernel images
# ---------------------------------------------------------------------------

def authenticode(path: Path) -> str:
    return env.run([sys.executable, "-I", str(env.BB_ROOT / "scripts" / "efi_inspect.py"), "authenticode",
                    str(path)], timeout=60).stdout.strip()


def canonical_kernel(dist: Path, dest: Path) -> tuple[Path | None, str]:
    """The helper kernel exactly as Ubuntu ships it (Canonical's signature), from the
    linux-image .deb that dist/manifest.json names as its source (beast-net cache).
    -> (path, "") or (None, why not)."""
    sb = json.loads((dist / "manifest.json").read_text()).get("secure_boot", {})
    src = sb.get("beastnet_kernel_source", "")
    m = re.fullmatch(r"deb:([^=]+)=([^:]+(?::[^:/]+)?):(/.+)", src)
    if not m:
        return None, f"manifest secure_boot.beastnet_kernel_source is not a package origin: {src!r}"
    pkg, ver, member = m.groups()
    cache = Path(os.environ.get("BB_BEASTNET_CACHE") or env.BB_ROOT / ".tools" / "cache" / "beastnet")
    deb = cache / "debs" / f"{pkg}_{ver.replace(':', '%3a')}_amd64.deb"
    if not deb.is_file():
        return None, f"{deb} not found (make build downloads it)"
    tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as tf:
        member_info = next((i for i in tf if i.isfile() and i.name.lstrip("./") == member.lstrip("/")), None)
        if member_info is None:
            return None, f"{member} not in {deb.name}"
        Path(dest).write_bytes(tf.extractfile(member_info).read())
    if authenticode(dest) != sb.get("beastnet_kernel_authenticode_sha256"):
        return None, f"{deb.name}:{member} is not the kernel dist/ was built from"
    return Path(dest), ""


def make_test_ca(d: Path) -> dict[str, Path]:
    """A throwaway CA and a code-signing leaf it issued (PEM + DER)."""
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt, ca_der = d / "ca.key", d / "ca.crt", d / "ca.der"
    leaf_key, leaf_csr, leaf_crt, leaf_der = d / "leaf.key", d / "leaf.csr", d / "leaf.crt", d / "leaf.der"
    ext = d / "leaf.ext"
    env.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
             "-subj", "/CN=beast-boot e2e test CA (throwaway)/", "-keyout", ca_key, "-out", ca_crt,
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    env.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-subj", "/CN=beast-boot e2e test signer (throwaway)/", "-keyout", leaf_key, "-out", leaf_csr])
    ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n")
    env.run(["openssl", "x509", "-req", "-sha256", "-days", "3650", "-in", leaf_csr, "-CA", ca_crt,
             "-CAkey", ca_key, "-set_serial", "0x5eed", "-extfile", ext, "-out", leaf_crt])
    for pem, der in ((ca_crt, ca_der), (leaf_crt, leaf_der)):
        env.run(["openssl", "x509", "-in", pem, "-outform", "DER", "-out", der])
    return {"ca": ca_der, "leaf": leaf_der, "leaf_key": leaf_key, "leaf_crt": leaf_crt}


def resign(src: Path, dest: Path, key: Path, crt: Path) -> Path:
    """`src` with every signature removed, then signed with key/crt."""
    unsigned = Path(dest).with_suffix(".unsigned")
    unsigned.write_bytes(Path(src).read_bytes())
    for _ in range(8):
        if "signature " not in env.run(["sbverify", "--list", unsigned], check=False).stdout:
            break
        env.run(["sbattach", "--remove", unsigned])
    env.run(["sbsign", "--key", key, "--cert", crt, "--output", dest, unsigned])
    return Path(dest)
