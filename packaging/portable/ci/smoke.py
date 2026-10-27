#!/usr/bin/env python3
"""Smoke-test an unpacked portable package by running its launchers.

    python3 -I packaging/portable/ci/smoke.py PACKAGE_DIR [options]

PACKAGE_DIR is the unpacked top folder (the one with PACKAGE-MANIFEST.json).
Checks, in order (each prints PASS/FAIL/WARN):
  cli-version     CLI launcher --version prints "beast-boot <VERSION>"
  cli-help        CLI launcher --help lists the commands
  hostile-env     --version still works with PYTHONHOME/PYTHONPATH/TCL_LIBRARY set
                  to junk (the launchers use -s -E -B -S and unset the Tcl variables)
  gui-selftest    (--gui) GUI launcher --selftest exits 0 (needs a display:
                  use xvfb-run on headless Linux)
  image-install   (--image) install --image ... --yes with the bundled
                  payload/dist, then info --image ... --json
  env-dist        (--image) the same install without --dist, relying on the
                  launcher's BEAST_BOOTER_DIST (WARN only, unless --strict-env-dist)

--clean-env runs every launcher with only HOME and PATH=/usr/bin:/bin (plus
--extra-path, and the display variables for --gui), like `env -i`. POSIX only.
Used by .github/workflows/portable-test.yml on Linux, Windows and macOS. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

DISPLAY_VARS = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR")


class Smoke:
    def __init__(self, pkg: Path, args: argparse.Namespace) -> None:
        self.pkg = pkg
        self.args = args
        self.manifest = json.loads((pkg / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
        self.os = self.manifest["target"].split("-", 1)[0]
        self.failed: list[str] = []
        layout = self.manifest["layout"]
        self.dist = pkg / layout["dist"]
        self.cli = [str(pkg / layout["cli"])]
        if self.os == "windows":
            # BeastBooter.cmd uses `start` and returns at once, so test the same
            # runtime + script directly to get the GUI's exit code and output.
            base = [str(pkg / "runtime" / "python.exe"), "-s", "-E", "-B", "-S",
                    str(pkg / "app" / "beast_booter_launch.py"), "--gui"]
            self.gui = [base, [str(pkg / "runtime" / "pythonw.exe"), *base[1:]]]
        else:
            self.gui = [[str(pkg / layout["gui"])]]

    # -- helpers ----------------------------------------------------------

    def env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        if self.args.clean_env and os.name != "nt":
            path = ":".join(["/usr/bin", "/bin", *self.args.extra_path])
            env = {"HOME": os.environ.get("HOME", "/"), "PATH": path}
            for v in DISPLAY_VARS:
                if v in os.environ:
                    env[v] = os.environ[v]
        else:
            env = dict(os.environ)
            if self.args.extra_path:
                env["PATH"] = os.pathsep.join([env.get("PATH", ""), *self.args.extra_path])
        env.update(extra or {})
        return env

    def run(self, argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 600):
        line = subprocess.list2cmdline(argv)
        print(f"  $ {line}", flush=True)
        cmd: list[str] | str = argv
        if os.name == "nt" and argv[0].lower().endswith(".cmd"):
            # What typing the line at a cmd prompt does: /s strips only the outer
            # quotes, so quoted paths with spaces in both program and arguments
            # survive. /d skips AutoRun commands from the registry.
            cmd = f'cmd.exe /d /s /c "{line}"'
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                               env=env or self.env(), timeout=timeout, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, str(e)
        return p, (p.stdout + p.stderr).strip()

    def check(self, name: str, ok: bool, detail: str = "", *, soft: bool = False) -> bool:
        status = "PASS" if ok else ("WARN" if soft else "FAIL")
        print(f"{status}: {name}" + (f"\n    {detail[-3000:]}" if detail and not ok else ""), flush=True)
        if not ok and not soft:
            self.failed.append(name)
        return ok

    # -- checks -----------------------------------------------------------

    def cli_version(self) -> None:
        p, out = self.run([*self.cli, "--version"])
        want = f"beast-boot {self.manifest['version']}"
        self.check("cli-version", p is not None and p.returncode == 0 and out == want,
                   f"expected {want!r}, got exit {p and p.returncode}: {out}")

    def cli_help(self) -> None:
        p, out = self.run([*self.cli, "--help"])
        self.check("cli-help", p is not None and p.returncode == 0 and "install" in out and "info" in out,
                   f"exit {p and p.returncode}: {out}")

    def hostile_env(self) -> None:
        junk = {"PYTHONHOME": os.path.join(tempfile.gettempdir(), "no-such-python-home"),
                "PYTHONPATH": os.path.join(tempfile.gettempdir(), "no-such-dir"),
                "PYTHONSTARTUP": os.path.join(tempfile.gettempdir(), "no-such-startup.py"),
                "TCL_LIBRARY": os.path.join(tempfile.gettempdir(), "no-such-tcl")}
        p, out = self.run([*self.cli, "--version"], env=self.env(junk))
        self.check("hostile-env", p is not None and p.returncode == 0, f"exit {p and p.returncode}: {out}")

    def gui_selftest(self) -> None:
        for argv in self.gui:
            p, out = self.run([*argv, "--selftest"], timeout=300)
            label = "gui-selftest" + (" (pythonw.exe)" if "pythonw" in argv[0] else "")
            self.check(label, p is not None and p.returncode == 0, f"exit {p and p.returncode}: {out}")
            if out and p is not None and p.returncode == 0:
                print("    " + out.replace("\n", "\n    ")[-1500:])

    def image_install(self, work: Path) -> None:
        img = work / "bb smoke.img"  # a space in the path on purpose
        p, out = self.run([*self.cli, "install", "--image", str(img), "--size", "1G", "--yes",
                           "--dist", str(self.dist)])
        if not self.check("image-install", p is not None and p.returncode == 0, f"exit {p and p.returncode}: {out}"):
            return
        p, out = self.run([*self.cli, "info", "--image", str(img), "--json"])
        try:
            info = json.loads(p.stdout) if p is not None and p.returncode == 0 else None
        except ValueError:
            info = None
        dist_version = json.loads((self.dist / "manifest.json").read_text(encoding="utf-8")).get("version")
        ok = (isinstance(info, dict) and info.get("version") == dist_version
              and isinstance(info.get("data"), dict) and isinstance(info.get("esp"), dict))
        self.check("image-info", ok, f"exit {p and p.returncode}: {out}")
        if ok:
            print(f"    {json.dumps(info)}")

    def env_dist(self, work: Path) -> None:
        img = work / "bb env-dist.img"
        p, out = self.run([*self.cli, "install", "--image", str(img), "--size", "1G", "--yes"])
        self.check("env-dist (install without --dist uses BEAST_BOOTER_DIST)",
                   p is not None and p.returncode == 0,
                   f"exit {p and p.returncode}: {out}\n    (TODO: CLI must default --dist to $BEAST_BOOTER_DIST)",
                   soft=not self.args.strict_env_dist)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Smoke-test an unpacked beast-boot portable package.")
    ap.add_argument("package", type=Path, help="unpacked package folder (has PACKAGE-MANIFEST.json)")
    ap.add_argument("--clean-env", action="store_true", help="run launchers with only HOME and a minimal PATH")
    ap.add_argument("--extra-path", action="append", default=[], help="append to PATH for the launchers")
    ap.add_argument("--gui", action="store_true", help="also run the GUI --selftest")
    ap.add_argument("--image", action="store_true", help="also make and inspect a disk image")
    ap.add_argument("--strict-env-dist", action="store_true", help="fail (not warn) if BEAST_BOOTER_DIST is ignored")
    ap.add_argument("--work", type=Path, help="scratch directory for images (default: a temp dir)")
    args = ap.parse_args(argv)

    pkg = args.package.resolve()
    s = Smoke(pkg, args)
    print(f"smoke: {s.manifest['name']} {s.manifest['version']} {s.manifest['target']} in {pkg}", flush=True)
    s.cli_version()
    s.cli_help()
    s.hostile_env()
    if args.gui:
        s.gui_selftest()
    if args.image:
        with tempfile.TemporaryDirectory(prefix="bb smoke ", dir=args.work) as tmp:
            s.image_install(Path(tmp))
            s.env_dist(Path(tmp))
    if s.failed:
        print(f"smoke: FAILED: {', '.join(s.failed)}")
        return 1
    print("smoke: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
