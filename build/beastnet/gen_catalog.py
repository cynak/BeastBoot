#!/usr/bin/env python3
"""Generate the beast-net firmware pack catalog (docs/BEASTNET.md section 6).

    gen_catalog.py --stage DIR --info info.json --lock firmware.lock --cache DIR
                   --out catalog.json [--report report.json] [--offline] [--reverify]

What a pack contains:
  1. the firmware names each bundled module can request: `modinfo` (the
     shipped kmod) `firmware:` fields of every module that belongs to the pack;
  2. resolved against the linux-firmware tree at the pinned tag:
     - exact file names, and WHENCE `Link:` names (installed under the link
       name, downloaded from the target: the file entry then carries
       "source_path");
     - globs (brcmfmac NVRAM, ath11k/ath12k directories) against files and links;
     - API-versioned names (iwlwifi-*-<api>.ucode, ath10k firmware-<api>.bin):
       the driver tries <api> downwards and loads the first file it finds, so the
       pack gets exactly that file: the highest version <= the module's maximum;
     - iwlwifi PNVM files (iwlwifi-<base>.pnvm) next to the chosen ucode, which
       the driver requests by that derived name;
  3. the LICENCE files named by the WHENCE licence lines of those files.

Integrity: the tree listing (path -> git blob id) comes from a blob-less fetch
of the tag from the GitLab mirror, and the tag must resolve to the commit pinned
in firmware.lock on both GitLab and git.kernel.org. Every file is then
downloaded twice - as a git object from GitLab (git checks the blob id) and
from the catalog's own kernel.org URL - and both copies must be identical
(SHA-256 and git blob id). Results are cached under --cache/<tag>/, so later
runs are offline. --reverify downloads every catalog file from kernel.org again.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import bnlib  # noqa: E402
from bnlib import BuildError  # noqa: E402

KERNEL_ORG_REPO = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git"
URL_TEMPLATE = KERNEL_ORG_REPO + "/plain/{path}?h={tag}"
GITLAB_REPO = "https://gitlab.com/kernel-firmware/linux-firmware.git"
USER_AGENT = "beast-booter-build/1 (+gen_catalog.py)"

# id, title, description, module path globs (relative to kernel/, no .ko suffix)
PACKS = [
    ("intel-wifi", "Intel WiFi",
     "Firmware for Intel wireless adapters: Wi-Fi 7/6E/6 (BE200, AX211, AX210, AX201, AX200), "
     "Wireless-AC (9560, 9260, 8265, 7265, 3168) and older WiFi Link cards (iwlwifi, iwlmvm, "
     "iwlmld, iwldvm, iwlegacy).",
     ["drivers/net/wireless/intel/**"]),
    ("realtek-wifi", "Realtek WiFi",
     "Firmware for Realtek wireless adapters, PCIe and USB: RTL8852/8851/8922 (rtw89), "
     "RTL8822/8821/8723 (rtw88), older RTL8188/8192/8723 chips (rtlwifi, rtl8xxxu).",
     ["drivers/net/wireless/realtek/**"]),
    ("mediatek-wifi", "MediaTek WiFi",
     "Firmware for MediaTek wireless adapters (MT7925, MT7922, MT7921, MT7915, MT7612U, "
     "MT7610U, MT7601U ...: mt76 drivers) and Ralink chips now owned by MediaTek "
     "(RT2800/RT3070/RT5370 ...: rt2x00 drivers).",
     ["drivers/net/wireless/mediatek/**", "drivers/net/wireless/ralink/**"]),
    ("qualcomm-atheros-wifi", "Qualcomm Atheros WiFi",
     "Firmware for Qualcomm/Atheros wireless adapters: WCN7850 (ath12k), WCN6855/QCA6390 "
     "(ath11k), QCA6174/QCA9377/QCA988x (ath10k), AR9271/AR7010 USB (ath9k_htc), "
     "AR6003/AR6004 (ath6kl), AR9170 (carl9170).",
     ["drivers/net/wireless/ath/**"]),
    ("broadcom-wifi", "Broadcom WiFi",
     "Firmware for Broadcom/Cypress FullMAC wireless chips (brcmfmac: BCM43xx PCIe, SDIO and "
     "USB, incl. board-specific NVRAM files) and brcmsmac.",
     ["drivers/net/wireless/broadcom/**"]),
    ("realtek-ethernet", "Realtek Ethernet",
     "Firmware patches for Realtek wired Ethernet: RTL8111/8168/8125/8126/8127 PCIe (r8169) "
     "and RTL8153/8156/8157 USB adapters (r8152). Most chips also work without it.",
     ["drivers/net/ethernet/realtek/**", "drivers/net/usb/r8152", "drivers/net/usb/r8153_ecm"]),
]

API_FALLBACK = [
    # (regex on the requested name, group with the API number); the driver
    # walks the API number down from the maximum it was built with
    re.compile(r"^(?P<pre>iwlwifi-.+-c?)(?P<api>\d+)(?P<suf>\.ucode)$"),
    re.compile(r"^(?P<pre>ath10k/.+/firmware-)(?P<api>\d+)(?P<suf>\.bin)$"),
]
MACRO = re.compile(r"IWL_[A-Z0-9_]+")   # unexpanded C macro in an iwlwifi MODULE_FIRMWARE() string
# iwlwifi-<mac>-<step>-<rf>-<step>-[c]<api>.ucode: the driver builds the name from
# the MAC/RF steppings it reads from the hardware, so for a listed MAC+RF pair
# every stepping variant in linux-firmware is requestable (e.g. MODULE_FIRMWARE
# says bz-a0-gf-a0, shipping hardware is bz-b0-gf-a0).
IWL_STEP = re.compile(r"^iwlwifi-(?P<mac>[A-Za-z]+)-[a-z]\d-(?P<rf>[a-z0-9]+)-[a-z]\d-(?P<c>c?)(?P<api>\d+)\.ucode$")


def log(msg: str) -> None:
    print(f"catalog: {msg}", file=sys.stderr)


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def run(cmd, **kw) -> subprocess.CompletedProcess:
    kw.setdefault("check", True)
    return subprocess.run(cmd, **kw)


# ---------------------------------------------------------------------------
# The pinned tree
# ---------------------------------------------------------------------------
def read_fw_lock(path: str) -> tuple[str, str]:
    vals = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = bnlib.strip_comment(line)
            if line:
                k, v = line.split(None, 1)
                vals[k] = v.strip()
    if not re.fullmatch(r"[0-9A-Za-z._-]+", vals.get("tag", "")) or \
            not re.fullmatch(r"[0-9a-f]{40}", vals.get("commit", "")):
        raise BuildError(f"{path}: need 'tag <tag>' and 'commit <40 hex>'")
    return vals["tag"], vals["commit"]


def remote_tag_commit(url: str, tag: str) -> str:
    r = run(["git", "ls-remote", url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
            capture_output=True, text=True, timeout=120)
    refs = dict(reversed(line.split("\t")) for line in r.stdout.splitlines() if "\t" in line)
    return refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}", "")


class Tree:
    """linux-firmware at one commit: path -> blob id, plus cached file contents."""

    def __init__(self, cache: str, tag: str, commit: str, offline: bool):
        self.dir = os.path.join(cache, tag)
        self.tag, self.commit, self.offline = tag, commit, offline
        self.git = os.path.join(self.dir, "git")
        self.files_dir = os.path.join(self.dir, "files")
        self.vfile = os.path.join(self.dir, "verified.json")
        os.makedirs(self.files_dir, exist_ok=True)
        self.verified: dict[str, dict] = json.load(open(self.vfile)) if os.path.exists(self.vfile) else {}
        self.blobs = self._listing()

    def _git(self, *args, **kw):
        env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
        return run(["git", "-C", self.git, *args], env=env, **kw)

    def _listing(self) -> dict[str, str]:
        listing = os.path.join(self.dir, "tree.tsv")
        if not os.path.exists(listing):
            if self.offline:
                raise BuildError(f"{listing} missing and --offline given")
            for name, url in (("GitLab mirror", GITLAB_REPO), ("git.kernel.org", KERNEL_ORG_REPO)):
                got = remote_tag_commit(url, self.tag)
                if got != self.commit:
                    raise BuildError(f"tag {self.tag} is {got or 'missing'} on the {name}, "
                                     f"firmware.lock says {self.commit}")
            if not os.path.isdir(self.git):
                run(["git", "init", "-q", "--bare", self.git])
                self._git("remote", "add", "origin", GITLAB_REPO)
            log(f"fetching the tree of {self.tag} (blob-less) from {GITLAB_REPO}")
            self._git("-c", "protocol.version=2", "fetch", "-q", "--filter=blob:none", "--depth", "1",
                      "--no-tags", "origin", f"+refs/tags/{self.tag}:refs/tags/{self.tag}", timeout=900)
            got = self._git("rev-parse", f"refs/tags/{self.tag}^{{commit}}",
                            capture_output=True, text=True).stdout.strip()
            if got != self.commit:
                raise BuildError(f"fetched tag {self.tag} is commit {got}, expected {self.commit}")
            out = self._git("ls-tree", "-r", "-z", "--full-tree", self.commit, capture_output=True).stdout
            rows = []
            for item in out.split(b"\0"):
                if not item:
                    continue
                meta, path = item.split(b"\t", 1)
                mode, typ, oid = meta.decode().split()
                if typ == "blob":
                    rows.append(f"{mode}\t{oid}\t{path.decode()}")
            with open(listing + ".tmp", "w", encoding="utf-8") as f:
                f.write(f"# linux-firmware {self.tag} {self.commit}: mode, git blob id, path\n")
                f.write("\n".join(sorted(rows)) + "\n")
            os.replace(listing + ".tmp", listing)
        blobs = {}
        with open(listing, encoding="utf-8") as f:
            head = f.readline()
            if self.commit not in head:
                raise BuildError(f"{listing} is not for commit {self.commit}")
            for line in f:
                mode, oid, path = line.rstrip("\n").split("\t", 2)
                if mode == "120000":
                    continue           # the repo has no symlinks; Links live in WHENCE
                blobs[path] = oid
        return blobs

    def local(self, path: str) -> str:
        return os.path.join(self.files_dir, path)

    def ensure(self, paths: list[str]) -> None:
        """Make sure every path is downloaded from both sources and identical."""
        todo = []
        for p in sorted(set(paths)):
            v = self.verified.get(p)
            lp = self.local(p)
            if v and v["oid"] == self.blobs[p] and os.path.isfile(lp):
                data = open(lp, "rb").read()
                if hashlib.sha256(data).hexdigest() == v["sha256"] and git_blob_id(data) == v["oid"]:
                    continue
            todo.append(p)
        if not todo:
            return
        if self.offline:
            raise BuildError(f"{len(todo)} firmware files not cached (e.g. {todo[0]}) and --offline given")
        log(f"downloading {len(todo)} files: git objects from GitLab, then the kernel.org URLs")
        oids = sorted({self.blobs[p] for p in todo})
        for i in range(0, len(oids), 500):
            self._git("-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "origin", "--no-tags",
                      "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin",
                      input="\n".join(oids[i:i + 500]).encode() + b"\n", timeout=1800)
        git_copy = {}
        for p in todo:
            data = self._git("cat-file", "blob", self.blobs[p], capture_output=True).stdout
            if git_blob_id(data) != self.blobs[p]:
                raise BuildError(f"{p}: git object does not match its id")
            git_copy[p] = data

        def https(p: str) -> tuple[str, bytes]:
            return p, http_get(URL_TEMPLATE.format(path=urllib.parse.quote(p), tag=self.tag))

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            for p, data in ex.map(https, todo):
                if data != git_copy[p]:
                    raise BuildError(f"{p}: kernel.org copy differs from the GitLab git object "
                                     f"({hashlib.sha256(data).hexdigest()} vs "
                                     f"{hashlib.sha256(git_copy[p]).hexdigest()})")
                lp = self.local(p)
                os.makedirs(os.path.dirname(lp), exist_ok=True)
                with open(lp + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(lp + ".tmp", lp)
                self.verified[p] = {"oid": self.blobs[p], "sha256": hashlib.sha256(data).hexdigest(),
                                    "size": len(data),
                                    "sources": ["git object from gitlab.com mirror", "https git.kernel.org plain"],
                                    "date": time.strftime("%Y-%m-%d", time.gmtime())}
        with open(self.vfile + ".tmp", "w", encoding="utf-8") as f:
            json.dump(self.verified, f, indent=0, sort_keys=True)
        os.replace(self.vfile + ".tmp", self.vfile)
        log(f"verified {len(todo)} files (both copies identical)")


def http_get(url: str, tries: int = 4) -> bytes:
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as r:
                if r.status != 200:
                    raise BuildError(f"{url}: HTTP {r.status}")
                return r.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                raise BuildError(f"{url}: 404") from e
            if attempt == tries - 1:
                raise BuildError(f"{url}: {e}") from e
            time.sleep(2 + 4 * attempt)
    raise AssertionError


# ---------------------------------------------------------------------------
# WHENCE
# ---------------------------------------------------------------------------
def unquote(s: str) -> str:
    """WHENCE paths are either "quoted" or use backslash-escaped spaces."""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s.replace("\\ ", " ")


def parse_whence(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return ({file: licence}, {link name: target path}) from WHENCE."""
    licence_of: dict[str, str] = {}
    links: dict[str, str] = {}
    for section in re.split(r"\n-{10,}\n", text):
        files, lic = [], None
        lines = section.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^(File|RawFile|Link|Licen[cs]e):\s*(.*)$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            if key in ("File", "RawFile"):
                files.append(unquote(val))
            elif key == "Link":
                name, _, target = val.partition("->")
                name, target = unquote(name), unquote(target)
                links[name] = os.path.normpath(os.path.join(os.path.dirname(name), target))
            elif lic is None:
                if not val:
                    val = next((x.strip() for x in lines[i + 1:] if x.strip()), "")
                lic = re.sub(r"\s+", " ", val)
        for f in files:
            licence_of[f] = lic or "unknown (no licence line in WHENCE)"
    return licence_of, links


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
class Resolver:
    def __init__(self, tree: Tree, links: dict[str, str]):
        self.files = set(tree.blobs)
        self.links = links
        self.names = sorted(self.files | set(links))

    def target(self, name: str) -> str | None:
        """Repo path that NAME refers to (following Link: chains)."""
        seen = 0
        while name not in self.files:
            name = self.links.get(name)
            seen += 1
            if name is None or seen > 10:
                return None
        return name

    def resolve(self, req: str, siblings: list[str]) -> tuple[list[str], str]:
        """Names (as installed) that request REQ can load; and how it was resolved."""
        why = ""
        if MACRO.search(req):
            cores = [int(m.group(1)) for x in siblings for m in [re.search(r"-c(\d+)\.ucode$", x)] if m]
            if not cores:
                return [], "unexpanded macro without a reference version"
            req = MACRO.sub(str(max(cores)), req)
            why = f"unexpanded macro read as {max(cores)}; "
        m = IWL_STEP.match(req)
        if m:
            api = int(m.group("api"))
            pat = re.compile(rf"^iwlwifi-{re.escape(m.group('mac'))}-[a-z]\d-{re.escape(m.group('rf'))}-[a-z]\d-"
                             rf"{m.group('c')}(\d+)\.ucode$")
            best: dict[str, tuple[int, str]] = {}
            for n in self.names:
                mm = pat.match(n)
                if mm and int(mm.group(1)) <= api and self.target(n):
                    base = n.rsplit("-", 1)[0]
                    if base not in best or int(mm.group(1)) > best[base][0]:
                        best[base] = (int(mm.group(1)), n)
            names = sorted(v[1] for v in best.values())
            return names, why + ("exact" if names == [req] else f"iwlwifi stepping/API <= {api}")
        if any(c in req for c in "*?["):
            rx = bnlib.glob_regex(req)
            hit = [n for n in self.names if rx.match(n) and self.target(n)]
            return hit, "glob"
        for rx in API_FALLBACK:
            m = rx.match(req)
            if m:
                api = int(m.group("api"))
                pat = re.compile("^" + re.escape(m.group("pre")) + r"(\d+)" + re.escape(m.group("suf")) + "$")
                best = None
                for n in self.names:
                    mm = pat.match(n)
                    if mm and int(mm.group(1)) <= api and self.target(n):
                        if best is None or int(mm.group(1)) > best[0]:
                            best = (int(mm.group(1)), n)
                if best:
                    return [best[1]], "exact" if best[1] == req else f"API fallback {api} -> {best[0]}"
                return [], "missing"
        if self.target(req):
            return [req], "exact" if req in self.files else "link"
        return [], "missing"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--info", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--reverify", action="store_true",
                    help="download every catalog file from its kernel.org URL again and compare")
    a = ap.parse_args()

    info = json.load(open(a.info, encoding="utf-8"))
    kver = info["kernel"]
    tag, commit = read_fw_lock(a.lock)
    tree = Tree(a.cache, tag, commit, a.offline)
    tree.ensure(["WHENCE"])
    licence_of, links = parse_whence(open(tree.local("WHENCE"), encoding="utf-8", errors="replace").read())
    res = Resolver(tree, links)

    # firmware: fields of every bundled module (one modinfo run with the shipped kmod)
    paths = {m["name"]: os.path.join(a.stage, m["path"]) for m in info["modules"]}
    mi = bnlib.modinfo_all(a.stage, list(paths.values()))
    fw_of = {name: mi[p].get("firmware", []) for name, p in paths.items()}
    relpath = {m["name"]: re.sub(r"\.ko(\.\w+)?$", "", m["path"].split("/kernel/", 1)[1]) for m in info["modules"]}

    packs_out, report_packs, claimed = [], [], {}
    missing_report: dict[str, list[str]] = {}
    for pid, title, desc, globs in PACKS:
        rxs = [bnlib.glob_regex(g) for g in globs]
        mods = sorted(n for n, rp in relpath.items() if any(r.match(rp) for r in rxs))
        if not mods:
            raise BuildError(f"pack {pid}: no bundled module matches {globs}")
        chosen: dict[str, str] = {}               # installed name -> repo path
        how: dict[str, str] = {}
        for mod in mods:
            reqs = fw_of[mod]
            for req in reqs:
                names, why = res.resolve(req, reqs)
                if not names:
                    missing_report.setdefault(mod, []).append(req)
                for n in names:
                    chosen[n] = res.target(n)
                    how[n] = why
        # iwlwifi PNVM next to each chosen ucode (requested by derived name)
        for n in list(chosen):
            m = re.match(r"^(iwlwifi-.+)-c?\d+\.ucode$", n)
            if m and res.target(m.group(1) + ".pnvm"):
                chosen[m.group(1) + ".pnvm"] = res.target(m.group(1) + ".pnvm")
                how.setdefault(m.group(1) + ".pnvm", "pnvm of a chosen ucode")
        if not chosen:
            raise BuildError(f"pack {pid}: no firmware file resolved")
        # licence files named by the licences of the chosen files
        lic_files = set()
        for src in chosen.values():
            lic = licence_of.get(src, "")
            for lf in re.findall(r"\b(LICEN[CS]E[\w.+-]*\w)", lic) + re.findall(r"\bSee (\S+?)\.? for details", lic):
                for cand in (lf, f"LICENSES/{lf}"):
                    if cand in tree.blobs:
                        lic_files.add(cand)
                        break
        for lf in lic_files:
            chosen.setdefault(lf, lf)
            how.setdefault(lf, "licence file")
        tree.ensure(sorted(set(chosen.values())))

        files, total, lics = [], 0, set()
        for name in sorted(chosen):
            src = chosen[name]
            v = tree.verified[src]
            lic = "licence text" if name in lic_files else licence_of.get(src, "unknown (not listed in WHENCE)")
            item = {"path": name, "sha256": v["sha256"], "size": v["size"], "license": lic}
            if src != name:
                item["source_path"] = src
            files.append(item)
            total += v["size"]
            if name not in lic_files:
                lics.add(lic)
            if name in claimed and claimed[name] != pid and name not in lic_files:
                log(f"note: {name} is in both {claimed[name]} and {pid}")
            claimed.setdefault(name, pid)
        packs_out.append({"id": pid, "title": title, "description": desc, "modules": mods,
                          "licenses": sorted(lics), "size": total, "files": files})
        report_packs.append({"id": pid, "files": len(files), "size": total,
                             "aliases": sum(1 for f in files if "source_path" in f),
                             "resolution": {k: sum(1 for v in how.values() if v.split(" ")[0] == k)
                                            for k in sorted({v.split(" ")[0] for v in how.values()})}})
        log(f"{pid:22s} {len(files):4d} files {total / 1048576:7.1f} MiB  ({len(mods)} modules)")

    in_pack = {m for p in packs_out for m in p["modules"]}
    unpacked = {m: fw_of[m] for m in sorted(fw_of) if fw_of[m] and m not in in_pack}

    if a.reverify:
        log("re-downloading every catalog file from its kernel.org URL")
        jobs = sorted({(f.get("source_path", f["path"]), f["sha256"]) for p in packs_out for f in p["files"]})

        def check(job):
            src, want = job
            data = http_get(URL_TEMPLATE.format(path=urllib.parse.quote(src), tag=tag))
            return src, hashlib.sha256(data).hexdigest() == want

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            bad = [s for s, ok in ex.map(check, jobs) if not ok]
        if bad:
            raise BuildError(f"re-download mismatch: {bad[:5]}")
        log(f"re-verified {len(jobs)} files: all SHA-256 match")

    catalog = {"v": 1, "kernel": kver,
               "source": {"name": "linux-firmware", "repo": KERNEL_ORG_REPO, "tag": tag,
                          "url_template": KERNEL_ORG_REPO + "/plain/{path}?h={tag}"},
               "packs": packs_out}
    validate(catalog)
    with open(a.out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=1, sort_keys=False, ensure_ascii=False)
        f.write("\n")
    os.replace(a.out + ".tmp", a.out)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump({"tag": tag, "commit": commit, "packs": report_packs,
                       "missing": missing_report, "modules_with_firmware_outside_packs": unpacked},
                      f, indent=1, sort_keys=True)
    nmiss = sum(len(v) for v in missing_report.values())
    log(f"catalog: {len(packs_out)} packs, {sum(len(p['files']) for p in packs_out)} files, "
        f"{sum(p['size'] for p in packs_out) / 1048576:.1f} MiB total; {nmiss} requested names not in "
        f"linux-firmware {tag}; {len(unpacked)} bundled modules with firmware outside the packs")
    return 0


def validate(c: dict) -> None:
    """The section 6 schema (plus the optional per-file "source_path")."""
    hexre = re.compile(r"[0-9a-f]{64}")

    def need(cond: bool, what: str) -> None:
        if not cond:
            raise BuildError(f"catalog does not match docs/BEASTNET.md section 6: {what}")

    need(set(c) == {"v", "kernel", "source", "packs"} and c["v"] == 1, "top-level keys")
    s = c["source"]
    need(set(s) == {"name", "repo", "tag", "url_template"} and s["name"] == "linux-firmware", "source")
    need(s["url_template"] == s["repo"] + "/plain/{path}?h={tag}", "url_template")
    ids = [p["id"] for p in c["packs"]]
    need(len(ids) == len(set(ids)), "duplicate pack ids")
    for p in c["packs"]:
        need(set(p) == {"id", "title", "description", "modules", "licenses", "size", "files"}, f"pack {p['id']} keys")
        need(re.fullmatch(r"[a-z0-9-]+", p["id"]) is not None, f"pack id {p['id']}")
        need(p["size"] == sum(f["size"] for f in p["files"]), f"pack {p['id']} size")
        paths = [f["path"] for f in p["files"]]
        need(paths == sorted(paths) and len(paths) == len(set(paths)), f"pack {p['id']} file order")
        for f in p["files"]:
            need(set(f) - {"source_path"} == {"path", "sha256", "size", "license"}, f"file keys {f}")
            need(bool(hexre.fullmatch(f["sha256"])) and isinstance(f["size"], int), f"file {f['path']}")
            for k in ("path", "source_path"):
                v = f.get(k, "x")
                need(not v.startswith("/") and ".." not in v.split("/") and "\\" not in v, f"unsafe path {v}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as e:
        print(f"catalog: error: {e}", file=sys.stderr)
        sys.exit(1)
