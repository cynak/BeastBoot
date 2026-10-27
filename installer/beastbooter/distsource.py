"""Where the boot files (dist/) come from: a directory or a .zip of one.

    --dist PATH  >  $BEAST_BOOTER_DIST  >  <repo>/dist

A .zip is extracted into a private temporary directory first; the manifest is
then verified as for a directory (dist.load_dist). The archive may hold the
dist files at its top level or inside one top-level folder (e.g. "dist/").
Extraction is strict: no absolute paths, no "..", no symlinks or special
files, no duplicate names, and size limits, so a hostile archive can only
fail verification.
"""

from __future__ import annotations

import os
import posixpath
import stat
import tempfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

from .dist import default_dist_dir
from .errors import BeastError
from .layout import DIST_MANIFEST, MIB

ENV_DIST = "BEAST_BOOTER_DIST"
MAX_ZIP_FILES = 20000
MAX_ZIP_BYTES = 2048 * MIB  # uncompressed total; a real dist/ is ~10 MiB
COPY_CHUNK = 1 * MIB


def resolve_dist(arg: str | None, environ: Mapping[str, str] | None = None) -> str:
    """The dist location to use: --dist, else $BEAST_BOOTER_DIST, else <repo>/dist."""
    environ = os.environ if environ is None else environ
    if arg:
        return arg
    env_value = environ.get(ENV_DIST)
    if env_value:
        return env_value
    return str(default_dist_dir())


def is_zip_path(path: str | os.PathLike) -> bool:
    return str(path).lower().endswith(".zip") and os.path.isfile(path)


def prepare_dist_dir(path: str | os.PathLike, workdir: str | os.PathLike) -> Path:
    """A directory holding the dist files: `path` itself, or (for a .zip) its
    contents extracted into a new directory under `workdir`."""
    p = Path(path)
    if not is_zip_path(p):
        if not p.exists():
            raise BeastError(
                f"dist directory not found: {p} (run `make build`, or pass --dist DIR)", code="dist-missing"
            )
        if not p.is_dir():
            raise BeastError(f"{p} is neither a dist directory nor a .zip of one", code="dist-invalid")
        return p
    dest = Path(tempfile.mkdtemp(prefix="dist-zip-", dir=workdir))
    extract_zip(p, dest)
    return find_dist_root(dest, p)


def _member_path(name: str, archive: Path) -> str:
    norm = posixpath.normpath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or "\0" in name
        or (len(name) > 1 and name[1] == ":")
        or ".." in name.split("/")
        or norm.startswith("../")
    ):
        raise BeastError(f"{archive}: unsafe path in the archive: {name!r}", code="dist-invalid")
    return norm


def extract_zip(archive: Path, dest: Path) -> None:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as e:
        raise BeastError(f"{archive} is not a readable zip archive ({e})", code="dist-invalid") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_FILES:
            raise BeastError(f"{archive}: too many entries ({len(infos)})", code="dist-invalid")
        total = 0
        seen: set[str] = set()
        for info in infos:
            name = info.filename
            rel = _member_path(name.rstrip("/") if info.is_dir() else name, archive)
            mode = info.external_attr >> 16
            if info.is_dir():
                (dest / rel).mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):  # Unix type bits: only plain files
                raise BeastError(f"{archive}: {name} is not a regular file (symlink?)", code="dist-invalid")
            if rel.lower() in seen:
                raise BeastError(f"{archive}: {name} appears twice", code="dist-invalid")
            seen.add(rel.lower())
            total += info.file_size
            if total > MAX_ZIP_BYTES:
                raise BeastError(f"{archive}: the archive is too large to be a dist directory", code="dist-invalid")
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info) as src, open(out, "xb") as dst:
                    while chunk := src.read(COPY_CHUNK):
                        written += len(chunk)
                        if written > info.file_size:
                            raise BeastError(f"{archive}: {name} is larger than the archive says",
                                             code="dist-invalid")
                        dst.write(chunk)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError, EOFError) as e:
                raise BeastError(f"{archive}: cannot extract {name} ({e})", code="dist-invalid") from None
            except FileExistsError:
                raise BeastError(f"{archive}: {name} appears twice", code="dist-invalid") from None


def find_dist_root(dest: Path, archive: Path) -> Path:
    """dest itself if it holds manifest.json, else its only top-level directory."""
    if (dest / DIST_MANIFEST).is_file():
        return dest
    entries = [e for e in dest.iterdir() if e.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir() and (entries[0] / DIST_MANIFEST).is_file():
        return entries[0]
    raise BeastError(
        f"{archive} does not contain a beast-boot dist directory ({DIST_MANIFEST} not found "
        "at the top level or in a single top-level folder)", code="dist-invalid"
    )
