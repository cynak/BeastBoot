"""The initramfs leaves out stdlib modules and busybox applet links that carry
open CVEs (build/beastnet/userland.list, sbom/vex.userland.openvex.json).
These tests keep the app from starting to depend on them."""
import ast
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BEASTNET = os.path.dirname(HERE)
ROOT = os.path.dirname(BEASTNET)
APP = os.path.join(BEASTNET, "python", "beastnet")
USERLAND = os.path.join(ROOT, "build", "beastnet", "userland.list")


def _excludes() -> list[str]:
    out = []
    with open(USERLAND, encoding="utf-8") as f:
        for line in f:
            words = line.split("#", 1)[0].split()
            if words[:1] == ["exclude"]:
                out += words[1:]
    return out


def excluded_modules() -> set[str]:
    """usr/lib/python3.14/<a>/<b>.py and .../<pkg>/** excludes -> module names."""
    mods = set()
    for g in _excludes():
        m = re.fullmatch(r"usr/lib/python3\.14/([\w/]+?)(\.py|/\*\*)", g)
        if m:
            mods.add(m.group(1).replace("/", "."))
        m = re.fullmatch(r"usr/lib/python3\.14/lib-dynload/(\w+)\.\*", g)
        if m:
            mods.add(m.group(1))
    return mods


def excluded_applets() -> set[str]:
    return {m.group(1) for g in _excludes() if (m := re.fullmatch(r"usr/\*bin/([\w.-]+)", g))}


def app_files() -> list[str]:
    return sorted(os.path.join(d, f) for d, _, fs in os.walk(APP) for f in fs if f.endswith(".py"))


def _hits(name: str, mods: set[str]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in mods)


def test_userland_list_excludes_the_cve_modules():
    mods = excluded_modules()
    for m in ("tarfile", "zipfile", "configparser", "csv", "xml", "urllib.request", "tempfile",
              "uuid", "_uuid"):
        assert m in mods
    assert {"tar", "wget", "httpd", "awk", "udhcpc6", "dpkg"} <= excluded_applets()


def test_app_never_imports_an_excluded_module():
    """Every import statement, also inside functions (they would only fail at run time)."""
    mods = excluded_modules()
    bad = []
    for path in app_files():
        tree = ast.parse(open(path, encoding="utf-8").read(), path)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            bad += [f"{os.path.relpath(path, ROOT)}:{node.lineno}: {n}" for n in names if _hits(n, mods)]
    assert not bad, "the initramfs does not ship these modules (build/beastnet/userland.list):\n" + "\n".join(bad)


def test_importing_the_app_loads_no_excluded_module():
    """Module-level imports through the stdlib (e.g. a module that imports tempfile)."""
    app_mods = sorted("beastnet." + os.path.relpath(p, APP)[:-3].replace(os.sep, ".")
                      for p in app_files() if not p.endswith(("__init__.py", "__main__.py")))
    runtime = json.load(open(os.path.join(BEASTNET, "runtime.json"), encoding="utf-8"))
    code = ("import importlib, json, sys\n"
            f"sys.path.insert(0, {os.path.dirname(APP)!r})\n"
            f"for m in {app_mods + runtime['python_modules']!r}: importlib.import_module(m)\n"
            "print(json.dumps(sorted(sys.modules)))\n")
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                         check=True).stdout
    loaded = [m for m in json.loads(out) if _hits(m, excluded_modules())]
    assert not loaded


def test_runtime_binaries_are_not_excluded_applets():
    runtime = json.load(open(os.path.join(BEASTNET, "runtime.json"), encoding="utf-8"))
    assert not excluded_applets() & {os.path.basename(b) for b in runtime["binaries"]}
