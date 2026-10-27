#!/bin/sh
# beast-boot portable (macOS): the command line interface.
#
#   ./beast-boot.command --help
#   sudo ./beast-boot.command install --device /dev/disk4   (writing a drive needs root)
#   ./beast-boot.command install --image my.img --size 8G   (image files: no root)
#
# Double-clicked in Finder it opens Terminal and shows the help.
# Uses the runtime, sources and boot files inside BeastBooter.app next to it.
#   -s  ignore ~/.local Python packages      -E  ignore PYTHON* variables
#   -B  write no .pyc files into the package -S  no site-packages, no .pth files
set -e

# Find this folder, also when started through a symlink.
self=$0
while [ -L "$self" ]; do
  link=$(readlink "$self")
  case $link in
    /*) self=$link ;;
    *) self=$(dirname -- "$self")/$link ;;
  esac
done
here=$(CDPATH='' cd -- "$(dirname -- "$self")" && pwd -P)
res=$here/BeastBooter.app/Contents/Resources

BEAST_BOOTER_DIST=$res/payload/dist
export BEAST_BOOTER_DIST
unset TCL_LIBRARY TK_LIBRARY
python=$res/runtime/bin/python3
launch=$res/app/beast_booter_launch.py

if [ "$#" -eq 0 ]; then
  "$python" -s -E -B -S "$launch" --help
  echo
  echo "Run commands from Terminal, for example:"
  echo "  \"$here/beast-boot.command\" install --help"
  echo "  sudo \"$here/beast-boot.command\" install --device /dev/diskN"
  exit 0
fi
exec "$python" -s -E -B -S "$launch" "$@"
