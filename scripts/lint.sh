#!/usr/bin/env bash
# Code-quality checks for beast-booter, open-source tools only:
#   ruff        (MIT)    Python: settings in ruff.toml
#   ShellCheck  (GPL-3)  shell scripts: settings in .shellcheckrc
# See docs/CODE_QUALITY.md.
#
# Usage: scripts/lint.sh [--fix] [--ci] [--only ruff|shellcheck] [PATH...]
#   PATH...      files or directories to check (default: the whole repository).
#                Directories are searched; paths ruff.toml excludes stay excluded.
#   --fix        apply ruff's safe fixes (never --unsafe-fixes). ShellCheck
#                findings are always fixed by hand.
#   --ci         no colours; findings as GitHub Actions annotations.
#   --only TOOL  run one tool only (ruff or shellcheck).
# Exit status: 0 clean, 1 findings, 2 a tool is missing or bad usage.
#
# ruff comes from .venv (bin/bb-dev setup or `make dev`, pinned with hashes in
# requirements-dev.txt), else `python3 -m ruff`, else ruff on PATH.
# ShellCheck is a pinned static binary in .tools/bin, downloaded (rootless)
# and checked against the SHA-256 of the publisher's release asset below the
# first time it is needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/.tools"
cd "$ROOT"

# --- ShellCheck pin: koalaman/shellcheck v0.11.0 (released 2025-08-04) --------
# SHA-256 = the release asset digests GitHub publishes for these files.
SC_VERSION="0.11.0"
sc_asset() {  # prints "<file> <sha256>" for this host, or fails
  case "$(uname -s).$(uname -m)" in
    Linux.x86_64|Linux.amd64)
      echo "shellcheck-v$SC_VERSION.linux.x86_64.tar.xz 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198" ;;
    Linux.aarch64|Linux.arm64)
      echo "shellcheck-v$SC_VERSION.linux.aarch64.tar.xz 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588" ;;
    Darwin.x86_64)
      echo "shellcheck-v$SC_VERSION.darwin.x86_64.tar.xz 3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6" ;;
    Darwin.arm64|Darwin.aarch64)
      echo "shellcheck-v$SC_VERSION.darwin.aarch64.tar.xz 56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79" ;;
    *) return 1 ;;
  esac
}
# ------------------------------------------------------------------------------

FIX=0 CI=0 ONLY=""
PATHS=()
usage() { sed -n '7,14p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --fix) FIX=1 ;;
    --ci) CI=1 ;;
    --only) [ $# -ge 2 ] || { usage >&2; exit 2; }; ONLY="$2"; shift ;;
    --only=*) ONLY="${1#--only=}" ;;
    -h|--help) usage; exit 0 ;;
    --) shift; PATHS+=("$@"); break ;;
    -*) echo "lint: unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) PATHS+=("$1") ;;
  esac
  shift
done
case "$ONLY" in ""|ruff|shellcheck) ;; *) echo "lint: --only takes ruff or shellcheck" >&2; exit 2 ;; esac
for p in ${PATHS[@]+"${PATHS[@]}"}; do
  [ -e "$p" ] || { echo "lint: no such file or directory: $p" >&2; exit 2; }
done
if [ "$CI" = 1 ]; then export NO_COLOR=1; fi

log() { printf 'lint: %s\n' "$*"; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/bb-lint.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# --- tools --------------------------------------------------------------------
RUFF=()
find_ruff() {
  if [ -x "$ROOT/.venv/bin/ruff" ]; then RUFF=("$ROOT/.venv/bin/ruff")
  elif python3 -c 'import ruff' >/dev/null 2>&1; then RUFF=(python3 -m ruff)
  elif command -v ruff >/dev/null 2>&1; then RUFF=(ruff)
  else return 1; fi
}

SHELLCHECK=""
install_shellcheck() {
  local asset file sum url dl work
  asset="$(sc_asset)" || { log "no pinned ShellCheck build for $(uname -s) $(uname -m)"; return 1; }
  file="${asset% *}" sum="${asset#* }"
  url="https://github.com/koalaman/shellcheck/releases/download/v$SC_VERSION/$file"
  dl="$TOOLS/cache/lint/$file"
  mkdir -p "$TOOLS/cache/lint" "$TOOLS/bin"
  if [ ! -f "$dl" ] || [ "$(sha256_of "$dl")" != "$sum" ]; then
    log "downloading ShellCheck $SC_VERSION ($url)"
    rm -f "$dl.part"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$dl.part" "$url" || { rm -f "$dl.part"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$dl.part" "$url" || { rm -f "$dl.part"; return 1; }
    else
      log "need curl or wget to download ShellCheck"; return 1
    fi
    if [ "$(sha256_of "$dl.part")" != "$sum" ]; then
      rm -f "$dl.part"; log "ERROR: SHA-256 mismatch for $file (expected $sum)"; return 1
    fi
    mv -f "$dl.part" "$dl"
  fi
  work="$TMP/sc"; mkdir -p "$work"
  tar -xJf "$dl" -C "$work"
  install -m 0755 "$work/shellcheck-v$SC_VERSION/shellcheck" "$TOOLS/bin/shellcheck"
  log "installed ShellCheck $SC_VERSION -> .tools/bin/shellcheck (sha256 of $file verified)"
}
find_shellcheck() {
  local bin="$TOOLS/bin/shellcheck"
  if [ -x "$bin" ] && "$bin" --version 2>/dev/null | grep -qx "version: $SC_VERSION"; then
    SHELLCHECK="$bin"; return 0
  fi
  if install_shellcheck; then SHELLCHECK="$bin"; return 0; fi
  if command -v shellcheck >/dev/null 2>&1; then
    SHELLCHECK="$(command -v shellcheck)"
    log "WARNING: using $SHELLCHECK ($("$SHELLCHECK" --version | sed -n 's/^version: //p')), not the pinned $SC_VERSION"
    return 0
  fi
  return 1
}

# --- which files ----------------------------------------------------------------
# Every file git knows or would add (tracked + untracked, not ignored), or a
# plain find outside a git checkout; generated and downloaded trees are skipped.
list_files() {  # list_files DIR...  -> NUL-separated paths
  if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$ROOT" ls-files -z -co --exclude-standard -- "$@"
  else
    find "$@" \( -name .git -o -name .tools -o -name .venv -o -name out -o -name dist \
      -o -name __pycache__ -o -name .ruff_cache -o -name .pytest_cache \) -prune \
      -o -type f -print0
  fi
}
is_shell() {  # by extension or by a sh/bash/dash/ksh shebang; GRUB .cfg never
  [ -f "$1" ] || return 1
  case "$1" in
    .tools/*|*/.tools/*|out/*|dist/*|.venv/*|*/.venv/*) return 1 ;;
    *.cfg|*.lst|*.py|*.md|*.json|*.txt|*.toml|*.csv) return 1 ;;
    *.sh|*.bash) return 0 ;;
  esac
  head -n 1 "$1" 2>/dev/null | LC_ALL=C grep -qE '^#![[:space:]]*/[^[:space:]]*/(env[[:space:]]+)?(ba|da|k)?sh([[:space:]]|$)'
}

SH_FILES=()
collect_shell() {
  local f dirs=()
  if [ ${#PATHS[@]} -eq 0 ]; then dirs=(.)
  else
    for f in "${PATHS[@]}"; do
      if [ -d "$f" ]; then dirs+=("$f")
      elif is_shell "${f#./}"; then SH_FILES+=("${f#./}")
      fi
    done
  fi
  [ ${#dirs[@]} -gt 0 ] || return 0
  while IFS= read -r -d '' f; do
    is_shell "${f#./}" && SH_FILES+=("${f#./}")
  done < <(list_files "${dirs[@]}")
  return 0
}

# --- runs -------------------------------------------------------------------------
TOTAL=0 MISSING=0 SUMMARY=()

run_ruff() {
  if ! find_ruff; then
    log "ruff not found. Install the pinned dev tools with: bin/bb-dev setup --minimal  (or: make dev)"
    MISSING=1; SUMMARY+=("ruff: NOT RUN (not installed)"); return 0
  fi
  local args=(check --force-exclude) out="$TMP/ruff.txt" n rc=0
  [ "$FIX" = 1 ] && args+=(--fix)
  if [ "$CI" = 1 ]; then args+=(--output-format=github --no-cache); else args+=(--output-format=concise); fi
  log "ruff $("${RUFF[@]}" --version | sed 's/^ruff //') (${RUFF[*]})"
  if [ ${#PATHS[@]} -eq 0 ]; then
    "${RUFF[@]}" "${args[@]}" >"$out" 2>&1 || rc=$?
  else
    "${RUFF[@]}" "${args[@]}" -- "${PATHS[@]}" >"$out" 2>&1 || rc=$?
  fi
  cat "$out"
  if [ "$CI" = 1 ]; then n="$(grep -c '^::' "$out" || true)"
  else n="$(grep -cE '^[^[:space:]].*:[0-9]+:[0-9]+: ' "$out" || true)"; fi
  if [ "$rc" -gt 1 ]; then
    log "ruff failed (exit $rc)"; MISSING=1; SUMMARY+=("ruff: FAILED (exit $rc)"); return 0
  fi
  if [ "$rc" = 1 ] && [ "$n" = 0 ]; then n=1; fi
  TOTAL=$((TOTAL + n))
  if [ "$FIX" = 1 ]; then SUMMARY+=("ruff: $n finding(s) left after safe fixes")
  else SUMMARY+=("ruff: $n finding(s)"); fi
}

# gcc format -> GitHub annotation (::error/::warning/::notice).
sc_github() {
  sed -E \
    -e 's/^([^:]+):([0-9]+):([0-9]+): error: (.*) \[(SC[0-9]+)\]$/::error file=\1,line=\2,col=\3,title=ShellCheck \5::\4/' \
    -e 's/^([^:]+):([0-9]+):([0-9]+): warning: (.*) \[(SC[0-9]+)\]$/::warning file=\1,line=\2,col=\3,title=ShellCheck \5::\4/' \
    -e 's/^([^:]+):([0-9]+):([0-9]+): (note|style): (.*) \[(SC[0-9]+)\]$/::notice file=\1,line=\2,col=\3,title=ShellCheck \6::\5/'
}

run_shellcheck() {
  collect_shell
  if [ ${#SH_FILES[@]} -eq 0 ]; then SUMMARY+=("shellcheck: no shell scripts to check"); return 0; fi
  if ! find_shellcheck; then
    log "ShellCheck not available (download failed and none on PATH)"
    MISSING=1; SUMMARY+=("shellcheck: NOT RUN (not installed)"); return 0
  fi
  local out="$TMP/sc.txt" n rc=0
  log "shellcheck $("$SHELLCHECK" --version | sed -n 's/^version: //p') on ${#SH_FILES[@]} script(s)"
  # Settings (external-sources, source-path) come from .shellcheckrc.
  "$SHELLCHECK" -f gcc -- "${SH_FILES[@]}" >"$out" 2>&1 || rc=$?
  if [ "$CI" = 1 ]; then sc_github <"$out"; else cat "$out"; fi
  n="$(grep -cE ':[0-9]+:[0-9]+: (error|warning|note|style): ' "$out" || true)"
  if [ "$rc" -gt 1 ]; then
    log "shellcheck failed (exit $rc)"; MISSING=1; SUMMARY+=("shellcheck: FAILED (exit $rc)"); return 0
  fi
  if [ "$rc" = 1 ] && [ "$n" = 0 ]; then n=1; fi
  TOTAL=$((TOTAL + n))
  if [ "$FIX" = 1 ] && [ "$n" != 0 ]; then SUMMARY+=("shellcheck: $n finding(s) in ${#SH_FILES[@]} script(s) (fix by hand)")
  else SUMMARY+=("shellcheck: $n finding(s) in ${#SH_FILES[@]} script(s)"); fi
}

[ "$ONLY" = shellcheck ] || run_ruff
[ "$ONLY" = ruff ] || run_shellcheck

echo
for s in "${SUMMARY[@]}"; do log "$s"; done
if [ "$MISSING" = 1 ]; then exit 2; fi
if [ "$TOTAL" -gt 0 ]; then log "FAILED: $TOTAL finding(s)"; exit 1; fi
log "OK"
