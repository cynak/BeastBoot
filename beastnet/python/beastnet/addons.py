"""Add-ons: Python packages a boot loader adds to the helper (beastnet/README.md "Add-ons").

An add-on is a package in ``/usr/lib/beastnet/addons/<name>/`` of the initramfs. The boot
loader puts it there with one more initrd archive. Its ``__init__.py`` has one function::

    def start(params, ui, ctx, version):
        ...
        return None   # or a beastnet.ui.UI that wraps ``ui``

``params`` is the parsed kernel command line (cmdline.BootParams; ``params.extra`` holds the
``beastnet.*`` parameters the helper itself does not know), ``ui`` the screen the helper is
about to use, ``ctx`` the run's context.Context and ``version`` the helper's version string.
A returned UI is used for all the screens and closed at the end; it must close ``ui`` too.

Trust rule: code is loaded from that one directory of the initramfs and from nowhere else:
never from the data partition, the ESP, a mounted disk or the network. The boot loader's menu
decides which initrd archives are loaded, so an add-on is exactly as trusted as the rest of
the initramfs (/init, this package). An entry that is a link to another place, or that sits
on another file system than the initramfs root (something mounted over the directory), is
refused.

A failing add-on never stops the helper: one ``BEASTNET: addon ...`` line is logged and the
local screen is used. Without the directory nothing happens."""

from __future__ import annotations

import os
import re
import sys
from typing import Any

from .ui import UI

ADDONS_DIR = "/usr/lib/beastnet/addons"  # fixed; not configurable from the command line
ENTRY = "start"
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


def _say(ctx: Any, *words: object) -> None:
    emit = getattr(getattr(ctx, "reporter", None), "emit", None)
    if emit is not None:
        try:
            emit("addon", *words)
        except Exception:  # noqa: BLE001 - reporting must not break the run
            pass


def _device(path: str) -> int:
    return os.stat(path).st_dev


def _refusal(base: str, name: str, root_dev: int) -> str:
    """Why DIRECTORY/NAME is not loaded ("" when it may be)."""
    if not _NAME.fullmatch(name):
        return "not a package name (a-z, 0-9, _)"
    pkg = os.path.join(base, name)
    init = os.path.join(pkg, "__init__.py")
    if os.path.realpath(pkg) != pkg or os.path.realpath(init) != init:
        return "a link to another place"
    if not os.path.isfile(init):
        return "no __init__.py"
    if _device(pkg) != root_dev or _device(init) != root_dev:
        return "not in the initramfs"
    return ""


def _import(name: str, pkg: str) -> Any:
    """Import the package at PKG by its path. sys.path is not changed, so nothing else
    becomes importable; the package's own relative imports work."""
    from importlib import util

    mod_name = f"beastnet_addon_{name}"
    spec = util.spec_from_file_location(mod_name, os.path.join(pkg, "__init__.py"),
                                        submodule_search_locations=[pkg])
    if spec is None or spec.loader is None:
        raise ImportError("cannot be imported")
    module = util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(mod_name, None)
        raise
    return module


def load_addons(params: Any, ui: UI, ctx: Any, version: str, *, directory: str = ADDONS_DIR,
                root: str = "/") -> UI:
    """Start every add-on in DIRECTORY, in name order, and return the UI to use: ``ui``, or
    what the add-ons wrapped around it. ``directory`` and ``root`` exist for the tests; the
    app always uses the defaults."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return ui  # the normal case: no add-ons
    try:
        base = os.path.realpath(directory)
        root_dev = _device(root)
        if _device(base) != root_dev:
            raise OSError("not in the initramfs")
    except OSError as e:
        _say(ctx, "refused", directory, getattr(e, "strerror", None) or e)
        return ui
    for name in names:
        try:
            why = _refusal(base, name, root_dev)
        except OSError as e:
            why = e.strerror or str(e)
        if why:
            _say(ctx, name, "refused", why)
            continue
        try:
            start = getattr(_import(name, os.path.join(base, name)), ENTRY, None)
            if not callable(start):
                raise TypeError(f"no {ENTRY}() function")
            got = start(params, ui, ctx, version)
            if got is not None and not isinstance(got, UI):
                raise TypeError(f"{ENTRY}() returned {type(got).__name__}, not a UI or None")
        except (Exception, SystemExit) as e:  # noqa: BLE001 - an add-on never stops the helper
            _say(ctx, name, "failed", f"{e.__class__.__name__}: {e}")
            continue
        if got is not None:
            ui = got
        _say(ctx, name, "started", "ui=wrapped" if got is not None else "ui=local")
    return ui


def close_ui(shown: UI, local: UI, ctx: Any) -> None:
    """At the end of the run: close the UI an add-on returned (it closes ``local`` itself)."""
    if shown is local:
        return
    try:
        shown.close()
    except Exception as e:  # noqa: BLE001 - app.main() closes the local screen anyway
        _say(ctx, "close failed", f"{e.__class__.__name__}: {e}")
