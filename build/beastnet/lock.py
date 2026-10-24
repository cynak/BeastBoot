#!/usr/bin/env python3
"""Regenerate build/beastnet/packages.lock from packages.in.

    python3 -I build/beastnet/lock.py [--cache DIR] [--check]

1. Downloads every package of packages.in (`apt-get download`, so apt checks
   it against the signed archive index) into the beast-net .deb cache.
2. Works out which ELF files userland.list ships and which shared libraries
   they need (DT_NEEDED, recursively).
3. Finds the packages that provide those libraries by following the
   packages' Depends/Pre-Depends (never the host's installed files), and adds
   them with role "lib".
4. Writes packages.lock: one line per .deb with its exact version and SHA-256.

--check only verifies that packages.lock is what this would write (exit 1 if not).
--fetch only makes sure every .deb of packages.lock is in the cache with the
locked SHA-256 (what build.sh uses; offline when the cache is warm).
Development tool: needs apt-get and network unless the cache is warm.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import bnlib  # noqa: E402
from bnlib import BuildError  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
ROLE_ORDER = {r: i for i, r in enumerate(bnlib.ROLES)}


def log(msg: str) -> None:
    print(f"lock: {msg}", file=sys.stderr)


def read_in(path: str) -> list[tuple[str, str | None, str]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = bnlib.strip_comment(raw)
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2 or parts[1] not in bnlib.ROLES:
                raise BuildError(f"{path}:{n}: expected '<package>[=<version>] <role>'")
            name, _, ver = parts[0].partition("=")
            out.append((name, ver or None, parts[1]))
    return out


def provided_libs(tree: str) -> dict[str, str]:
    """soname -> relpath for libraries in the standard directories of TREE."""
    out = {}
    for d in bnlib.LIB_DIRS:
        full = os.path.join(tree, d)
        if not os.path.isdir(full):
            continue
        for fn in sorted(os.listdir(full)):
            if ".so" in fn:
                out.setdefault(fn, f"{d}/{fn}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", default=os.environ.get("BB_BEASTNET_CACHE",
                                                      os.path.join(ROOT, ".tools/cache/beastnet")))
    ap.add_argument("--in", dest="inp", default=os.path.join(HERE, "packages.in"))
    ap.add_argument("--userland", default=os.path.join(HERE, "userland.list"))
    ap.add_argument("--out", default=os.path.join(HERE, "packages.lock"))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--lock", default=os.path.join(HERE, "packages.lock"))
    a = ap.parse_args()

    debdir = os.path.join(a.cache, "debs")
    if a.fetch:
        offline = os.environ.get("BB_OFFLINE", "0") == "1"
        for e in bnlib.read_lock(a.lock):
            bnlib.fetch_deb(debdir, e.name, e.version, e.arch, e.sha256, log=log, offline=offline)
        return 0
    roots = read_in(a.inp)
    userland = bnlib.read_userland(a.userland)
    work = tempfile.mkdtemp(prefix="bn-lock.")
    try:
        pkgs: dict[str, dict] = {}     # name -> {deb, version, arch, role, tree}

        def add(name: str, version: str | None, role: str) -> dict:
            version = version or _candidate(name)
            deb = bnlib.fetch_deb(debdir, name, version, _arch_of(debdir, name, version), log=log)
            ver = bnlib.deb_field(deb, "Version")
            arch = bnlib.deb_field(deb, "Architecture")
            if version and ver != version:
                raise BuildError(f"{deb}: version {ver}, packages.in says {version}")
            tree = os.path.join(work, name)
            if role not in ("kernel", "modules"):
                bnlib.extract_deb(deb, tree)
            pkgs[name] = {"deb": deb, "version": ver, "arch": arch, "role": role, "tree": tree}
            return pkgs[name]

        for name, ver, role in roots:
            add(name, ver, role)

        # ELF files shipped from tool packages and explicitly listed lib files
        queue: list[tuple[str, str]] = []      # (package, relpath)
        for name, info in pkgs.items():
            for g in userland.takes.get(name, []):
                rx = bnlib.glob_regex(g)
                for rel, _is_link in bnlib.walk_files(info["tree"]):
                    if rx.match(rel):
                        queue.append((name, rel))
        provides: dict[str, tuple[str, str]] = {}
        for name, info in pkgs.items():
            if info["role"] in ("tool", "lib"):
                for so, rel in provided_libs(info["tree"]).items():
                    provides.setdefault(so, (name, rel))

        excl = [bnlib.glob_regex(g) for g in userland.excludes]
        seen_files: set[tuple[str, str]] = set()
        missing: dict[str, set[str]] = {}
        tried: set[str] = set(pkgs)
        while True:
            while queue:
                name, rel = queue.pop()
                if (name, rel) in seen_files or any(r.match(rel) for r in excl):
                    continue
                seen_files.add((name, rel))
                path = os.path.join(pkgs[name]["tree"], rel)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                info = bnlib.elf_info(path)
                if info is None:
                    continue
                wants = list(info.needed)
                if info.interp:
                    wants.append(os.path.basename(info.interp))
                for so in wants:
                    if so in provides:
                        pn, prel = provides[so]
                        target = bnlib.resolve_in_tree(pkgs[pn]["tree"], prel) or prel
                        queue.append((pn, target))
                    else:
                        missing.setdefault(so, set()).add(f"{name}:/{rel}")
            if not missing:
                break
            # candidates: Depends of the packages we have, not tried yet
            cands = []
            for _name, info in sorted(pkgs.items()):
                if info["role"] in ("tool", "lib"):
                    cands += [d for d in bnlib.first_depends(info["deb"]) if d not in tried]
            cands = sorted(set(cands))
            if not cands:
                raise BuildError("no package found for: " + "; ".join(
                    f"{so} (needed by {', '.join(sorted(v))})" for so, v in sorted(missing.items())))
            progress = False
            for c in cands:
                tried.add(c)
                try:
                    info = add(c, None, "lib")
                except (BuildError, subprocess.CalledProcessError) as e:
                    log(f"skipping candidate {c}: {e}")
                    continue
                got = {so: rel for so, rel in provided_libs(info["tree"]).items() if so in missing}
                if not got:
                    shutil.rmtree(info["tree"], ignore_errors=True)
                    del pkgs[c]
                    continue
                progress = True
                for so, rel in sorted(got.items()):
                    provides.setdefault(so, (c, rel))
                    log(f"{so} <- {c}={info['version']}")
                    target = bnlib.resolve_in_tree(info["tree"], rel) or rel
                    queue.append((c, target))
                    missing.pop(so, None)
                for so, rel in provided_libs(info["tree"]).items():
                    provides.setdefault(so, (c, rel))
            if not progress and not queue:
                # Debian's shlibs Depends always names the package of every
                # DT_NEEDED library directly, so one level is enough.
                raise BuildError("no Depends of the locked packages provides: " + ", ".join(sorted(missing)))

        lines = ["# beast-net package lock - generated by build/beastnet/lock.py from packages.in.",
                 "# Do not edit by hand. <package> <version> <arch> <sha256 of the .deb> <role>"]
        for name, info in sorted(pkgs.items(), key=lambda kv: (ROLE_ORDER[kv[1]["role"]], kv[0])):
            lines.append(f"{name} {info['version']} {info['arch']} {bnlib.sha256_file(info['deb'])} {info['role']}")
        text = "\n".join(lines) + "\n"
        if a.check:
            cur = open(a.out, encoding="utf-8").read() if os.path.exists(a.out) else ""
            if cur != text:
                log(f"{a.out} is out of date")
                return 1
            log(f"{a.out} is up to date")
            return 0
        with open(a.out + ".new", "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(a.out + ".new", a.out)
        log(f"wrote {a.out} ({len(pkgs)} packages)")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _candidate(name: str) -> str:
    r = subprocess.run(["apt-cache", "policy", name], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.strip().startswith("Candidate:"):
            v = line.split(":", 1)[1].strip()
            if v and v != "(none)":
                return v
    raise BuildError(f"apt knows no candidate version of {name}")


def _arch_of(debdir: str, name: str, version: str) -> str:
    for arch in ("amd64", "all"):
        if os.path.exists(os.path.join(debdir, bnlib.deb_filename(name, version, arch))):
            return arch
    r = subprocess.run(["apt-cache", "show", f"{name}={version}"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("Architecture:"):
            return line.split(":", 1)[1].strip()
    return "amd64"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as e:
        print(f"lock: error: {e}", file=sys.stderr)
        sys.exit(1)
