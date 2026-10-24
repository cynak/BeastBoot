"""Access to the fixture ISO builder (tests/e2e/fixtures/build_fixtures.py)."""

from __future__ import annotations

import functools
import importlib.util
import sys

from . import env


@functools.cache
def builder():
    """The build_fixtures module, loaded by path (the name `fixtures` is too generic to import)."""
    path = env.E2E_DIR / "fixtures" / "build_fixtures.py"
    spec = importlib.util.spec_from_file_location("bb_build_fixtures", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bb_build_fixtures"] = mod
    spec.loader.exec_module(mod)
    return mod
