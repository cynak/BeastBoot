"""Self-contained entry point for the beast-booter CLI and GUI.

    python beast_booter_launch.py <cli args...>     # the CLI (same as python -m beastbooter)
    python beast_booter_launch.py --gui              # the GUI (beastbooter.gui)

It needs no environment variables: it puts its own directory on sys.path, so it
works from a source checkout (installer/), from the portable package (app/), and
when the GUI starts it elevated (sudo/pkexec/UAC/macOS authorization drop the
environment). The portable launchers pass --dist explicitly or set
BEAST_BOOTER_DIST to the bundled payload/dist.
"""

import os
import sys

# Never write __pycache__ into the (possibly read-only or shared) app folder,
# even if a launcher forgets to pass -B.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--gui"]:
        from beastbooter.gui import main as gui_main

        return int(gui_main(argv[1:]) or 0)
    from beastbooter.cli import main as cli_main

    return int(cli_main(argv) or 0)


if __name__ == "__main__":
    sys.exit(main())
