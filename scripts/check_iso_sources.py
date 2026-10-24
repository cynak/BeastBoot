#!/usr/bin/env python3
"""Check that beast-net can download from official ISO sources (uses the internet).

Runs beast-net's own downloader code (beastnet/python/beastnet/download.py) on
this computer, with the same CA bundle the helper ships in its initramfs, so
the requests carry exactly the headers, TLS settings and redirect rules of a
real download. For every source in tests/e2e/live_sources.json (or --url):

  1. prepare(): GET with beast-net's headers, follow redirects, read the
     response headers only (size, name, ranges); fetch and parse the checksum
     file, find this ISO's SHA-256 in it.
  2. a ranged GET from the final link, the way a resumed download asks
     (``Range: bytes=0-``), reading only the first 64 KiB: expects 206 and
     the ISO 9660 signature ("CD001").

When a server refuses beast-net (401, 403, 406, 429 ...), the refused link
(the checksum file or the ISO) is found by repeating the request with
beast-net's own User-Agent, and then asked again with other User-Agent values,
only to tell whether the refusal is about the header. beast-net itself always
sends its own User-Agent.

Nothing is written outside a temporary directory. Exit status: 0 when every
source passed, 1 otherwise, 2 for usage errors.

Usage:
  scripts/check_iso_sources.py                    every source in the catalog
  scripts/check_iso_sources.py --only ubuntu-desktop,windows-11-enterprise-eval
  scripts/check_iso_sources.py --url LINK [--sha256-url LINK]   any link, e.g. a personal Windows 11 link
  scripts/check_iso_sources.py --json out.json    also write the results as JSON
"""

from __future__ import annotations

import argparse
import http.client
import json
import lzma
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "beastnet" / "python"))

from beastnet.download import USER_AGENT, Downloader, DownloadRequest, _network_error  # noqa: E402
from beastnet.errors import BeastNetError  # noqa: E402

CATALOG = ROOT / "tests" / "e2e" / "live_sources.json"
INITRD = ROOT / "dist" / "esp" / "beast-net" / "initrd.img"
CA_IN_INITRD = "etc/ssl/certs/ca-certificates.crt"
SYSTEM_CA = "/etc/ssl/certs/ca-certificates.crt"
HEAD_BYTES = 65536
# Only for telling whether a refusal is about the User-Agent; never used to download.
OTHER_AGENTS = {"curl": "curl/8.18.0", "empty User-Agent": None}
REFUSALS = (401, 403, 406, 429, 451)


def ca_from_initrd(initrd: Path, out_dir: Path) -> Path | None:
    """The CA bundle inside the helper's initramfs (xz-compressed newc cpio), or None."""
    try:
        with lzma.open(initrd) as f:
            return _ca_from_cpio(f, out_dir)
    except (lzma.LZMAError, EOFError, OSError, ValueError):
        return None


def _ca_from_cpio(f, out_dir: Path) -> Path | None:
    while True:
        hdr = f.read(110)
        if len(hdr) < 110 or hdr[:6] not in (b"070701", b"070702"):
            return None
        mode = int(hdr[14:22], 16)
        size = int(hdr[54:62], 16)
        namesize = int(hdr[94:102], 16)
        name = f.read(namesize)[:-1].decode("utf-8", "replace")
        f.read((4 - (110 + namesize) % 4) % 4)
        if name == "TRAILER!!!":
            return None
        data = f.read(size)
        f.read((4 - size % 4) % 4)
        if name.lstrip("./") == CA_IN_INITRD and (mode & 0o170000) == 0o100000:
            path = out_dir / "ca-certificates.crt"
            path.write_bytes(data)
            return path


def http_status(err: BeastNetError) -> int | None:
    words = str(err).split()
    for i, w in enumerate(words[:-1]):
        if w == "answered" and words[i + 1].isdigit():
            return int(words[i + 1])
    return None


def probe_with_agent(dl: Downloader, url: str, agent: str | None) -> str:
    """Status of one GET with this User-Agent (headers only), or the error code."""
    try:
        resp, _final = dl.http.get(url, {"User-Agent": agent or "", "Range": "bytes=0-"})
    except BeastNetError as e:
        return f"{e.code}"
    try:
        return str(resp.status)
    finally:
        resp.close()


def diagnose_refusal(dl: Downloader, src: dict) -> dict | None:
    """Which link refused beast-net (checked again with its own User-Agent),
    and how the same link answers other User-Agents. None: not reproduced."""
    for what, url in (("checksum file", src.get("sha256_url")), ("ISO link", src["url"])):
        if not url:
            continue
        mine = probe_with_agent(dl, url, USER_AGENT)
        if mine.isdigit() and int(mine) in REFUSALS:
            return {"refused": what, "url": url, "beast-net": mine,
                    "others": {k: probe_with_agent(dl, url, v) for k, v in OTHER_AGENTS.items()}}
    return None


def check(dl: Downloader, src: dict) -> dict:
    out = {"id": src["id"], "name": src.get("name", src["id"]), "url": src["url"], "ok": False}
    t0 = time.monotonic()
    try:
        plan = dl.prepare(DownloadRequest(url=src["url"], sha256=src.get("sha256"),
                                          sha256_url=src.get("sha256_url")))
    except BeastNetError as e:
        status = http_status(e)
        out.update(error=str(e), hint=getattr(e, "hint", ""), status=status)
        out["kind"] = ("blocked" if status in REFUSALS else "gone" if status in (404, 410)
                       else e.code)
        if status in REFUSALS:
            out["diagnosis"] = diagnose_refusal(dl, src)
        return out
    out.update(final_host=urlsplit(plan.final_url).hostname, bytes=plan.total, dest=plan.dest,
               ranges=plan.accept_ranges, sha256=plan.expected, sha256_from=plan.expected_from or None)
    host = urlsplit(plan.final_url).hostname or ""
    try:
        resp, _final = dl.http.get(plan.final_url, {"Range": "bytes=0-"}, allow_http=plan.allow_http)
        try:
            out["range_status"] = resp.status
            body = resp.read(HEAD_BYTES) if resp.status in (200, 206) else b""
        except (OSError, http.client.HTTPException) as e:  # stalled or cut off after the headers
            raise _network_error(e, host) from None
        finally:
            resp.close()
    except BeastNetError as e:
        out.update(error=f"ranged read: {e}", kind=e.code)
        return out
    out["iso9660"] = body[0x8001:0x8006] == b"CD001"
    problems = []
    if out["range_status"] != 206:
        problems.append(f"ranged read answered {out['range_status']} (resume would restart)")
    if not out["iso9660"]:
        problems.append("the data does not start like an ISO 9660 image")
    if src.get("min_bytes") and (plan.total or 0) < src["min_bytes"]:
        problems.append(f"size {plan.total} is below the expected {src['min_bytes']}")
    if src.get("sha256_url") and not plan.expected:
        problems.append("no SHA-256 for this file in the checksum file")
    out["seconds"] = round(time.monotonic() - t0, 1)
    if problems:
        out.update(error="; ".join(problems), kind="unexpected")
    else:
        out["ok"] = True
    return out


def show(r: dict) -> None:
    if r["ok"]:
        size = f"{r['bytes'] / 1e9:.2f} GB" if r.get("bytes") else "size ?"
        if r.get("sha256_from") == "given":
            sha = "sha256 given"
        elif r.get("sha256"):
            sha = f"sha256 {r['sha256'][:12]}... from the checksum file"
        else:
            sha = "no checksum file (HTTPS only)"
        print(f"  OK    {r['name']:36s} {size:>9s}  via {r['final_host']}  range=206 iso9660  {sha}")
        return
    print(f"  FAIL  {r['name']:36s} {r.get('kind', '?')}: {r['error']}")
    if r.get("hint"):
        print(f"        {r['hint']}")
    if "diagnosis" in r:
        d = r["diagnosis"]
        if d is None:
            print("        asked again with beast-net's User-Agent, the server did not refuse: a passing block, try again")
            return
        others = ", ".join(f"{k}: {v}" for k, v in d["others"].items())
        works = [k for k, v in d["others"].items() if v in ("200", "206")]
        verdict = (f"it accepts {', '.join(works)} but refuses beast-net's User-Agent" if works
                   else "refused for every User-Agent tried, so not a header problem")
        print(f"        the {d['refused']} refused beast-net ({d['beast-net']}); "
              f"with other User-Agents ({others}): {verdict}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--catalog", type=Path, default=CATALOG)
    ap.add_argument("--only", help="comma-separated source ids from the catalog")
    ap.add_argument("--url", help="check this link instead of the catalog")
    ap.add_argument("--sha256-url", help="with --url: its checksum file (https)")
    ap.add_argument("--sha256", help="with --url: its SHA-256")
    ap.add_argument("--ca", help=f"CA bundle (default: the one in {INITRD.relative_to(ROOT)}, else {SYSTEM_CA})")
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds per network operation (default 30)")
    ap.add_argument("--json", type=Path, help="also write the results to this file")
    args = ap.parse_args(argv)

    if args.url:
        sources = [{"id": "url", "name": urlsplit(args.url).hostname or args.url, "url": args.url,
                    "sha256_url": args.sha256_url, "sha256": args.sha256}]
    else:
        try:
            sources = json.loads(args.catalog.read_text())["sources"]
        except (OSError, ValueError, KeyError) as e:
            print(f"check_iso_sources: cannot read {args.catalog}: {e}", file=sys.stderr)
            return 2
        if args.only:
            want = [s.strip() for s in args.only.split(",") if s.strip()]
            unknown = sorted(set(want) - {s["id"] for s in sources})
            if unknown:
                print(f"check_iso_sources: unknown source id(s): {', '.join(unknown)}", file=sys.stderr)
                return 2
            sources = [s for s in sources if s["id"] in want]

    with tempfile.TemporaryDirectory(prefix="bb-sources-") as tmp:
        ca, ca_note = args.ca, "given"
        if not ca:
            found = ca_from_initrd(INITRD, Path(tmp)) if INITRD.is_file() else None
            ca, ca_note = (str(found), "from the beast-net initramfs") if found else (
                SYSTEM_CA, "this computer's (no dist/ beast-net build found)")
        print(f"beast-net download check: User-Agent {USER_AGENT!r}, CA bundle {ca_note}")
        dl = Downloader(os.path.join(tmp, "data"), ca, timeout=args.timeout, retries=1)
        results = []
        for src in sources:
            try:
                r = check(dl, src)
            except Exception as e:  # noqa: BLE001 - report it and go on with the other sources
                r = {"id": src["id"], "name": src.get("name", src["id"]), "url": src["url"], "ok": False,
                     "kind": "crash", "error": f"{type(e).__name__}: {e}"}
            show(r)
            results.append(r)
    failed = [r for r in results if not r["ok"]]
    print(f"{len(results) - len(failed)}/{len(results)} sources OK")
    if args.json:
        args.json.write_text(json.dumps({"user_agent": USER_AGENT, "results": results}, indent=2) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
