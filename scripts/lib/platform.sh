# shellcheck shell=bash
# Helpers for scripts that run on Linux and macOS. Source it; it defines
# functions only. Must parse in bash 3.2 (macOS /bin/bash), since
# bb_require_bash4 is what moves a script off that bash.

bb_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo macos ;;
    *) uname -s | tr '[:upper:]' '[:lower:]' ;;
  esac
}

# bb_require_bash4 "$0" "$@": re-exec the script under bash >= 4.4 (Homebrew's on
# macOS). Empty arrays under `set -u` (4.4), `declare -A`, mapfile, ${v,,} need it.
_bb_bash_ok() { [ "$1" -gt 4 ] || { [ "$1" -eq 4 ] && [ "$2" -ge 4 ]; }; }
bb_require_bash4() {
  _bb_bash_ok "${BASH_VERSINFO[0]:-0}" "${BASH_VERSINFO[1]:-0}" && return 0
  local b
  for b in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    # shellcheck disable=SC2046,SC2016  # the other bash prints "major minor"
    if [ -x "$b" ] && _bb_bash_ok $("$b" -c 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"'); then
      exec "$b" "$@"
    fi
  done
  echo "error: bash 4.4 or newer is needed (this is bash $BASH_VERSION); on macOS: brew install bash" >&2
  exit 1
}

bb_file_size() {  # FILE -> size in bytes
  stat -c %s "$1" 2>/dev/null || stat -f %z "$1"
}

bb_mtime() {  # FILE -> modification time (seconds since the epoch)
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"
}

# bb_drop_finder_files DIR: Finder writes .DS_Store into any folder it shows,
# and dist/ verification rejects files the manifest does not list.
bb_drop_finder_files() {
  [ -d "$1" ] || return 0
  find "$1" -name .DS_Store -type f -delete
}

bb_sha256() {  # [FILE] -> hex digest (stdin when no FILE)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@" | cut -d' ' -f1
  else shasum -a 256 "$@" | cut -d' ' -f1; fi
}

# bb_python: path of the first working python3 >= 3.10 (BB_PYTHON wins).
# macOS ships 3.9 in /usr/bin, and an activated venv on PATH may be broken.
bb_python() {
  local py
  for py in ${BB_PYTHON:-} python3 python3.14 python3.13 python3.12 python3.11 python3.10 \
            /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    command -v "$py" >/dev/null 2>&1 || continue
    if [ "$("$py" -I -c 'import sys; print(int(sys.version_info >= (3, 10)))' 2>/dev/null)" = 1 ]; then
      command -v "$py"
      return 0
    fi
  done
  echo "error: no working python3 >= 3.10 found (macOS: brew install python@3.12; or set BB_PYTHON)" >&2
  return 1
}
