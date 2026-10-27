#!/usr/bin/env bash
# The local pre-release routine (docs/RELEASING.md, "Before tagging"): everything a release
# must pass, including the checks build_release.sh does not run (real-ISO boots, GRUB/wimboot
# rebuilt from source and compared, kernel VEX regenerated against today's vulnerability data).
# Run it on the exact tree you are about to tag; it changes only dist/, sbom/ and out/.
#
#   scripts/release/prerelease.sh [--quick] [--skip-real-iso] [--skip-portable] [--out DIR]
#                                 [--progress SECONDS]
#
#   --quick          unit tests, lint and lock check only (no build, no QEMU, no scan)
#   --skip-real-iso  skip the real-ISO boots (BB_REAL_ISO=1; downloads tens of GB once)
#   --skip-portable  skip scripts/build_portable.sh --all
#   --out DIR        logs (default: out/prerelease); one <step>.log per step + summary.txt
#   --progress N     print a progress line (elapsed time, last log line) every N seconds
#                    while a step runs (default 30; 0 = only start/end lines)
#
# Each step has a time limit (in its `step` line below); a step that runs past it is
# stopped with its child processes and counted as TIMEOUT, so a hung test cannot block
# the run. Ctrl+C stops the running step and its children too.
# Every step runs even after a failure (so one run shows everything); the exit code is the
# number of failed steps (0 = ready to tag). Fails if the tree changes while it runs.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
QUICK=0 REAL_ISO=1 PORTABLE=1 OUT="$ROOT/out/prerelease" PROGRESS="${BB_PRERELEASE_PROGRESS:-30}"
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --skip-real-iso) REAL_ISO=0 ;;
    --skip-portable) PORTABLE=0 ;;
    --out) OUT="$2"; shift ;;
    --progress) PROGRESS="$2"; shift ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "prerelease: unknown option $1" >&2; exit 64 ;;
  esac
  shift
done
mkdir -p "$OUT"
# shellcheck source=scripts/dev-env.sh
. "$ROOT/scripts/dev-env.sh" >/dev/null 2>&1
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=python3

fingerprint() {  # tracked changes + untracked (not ignored) files: detects edits during the run
  # (sbom/ is left out: the scan and kernel_vex.py rewrite it on purpose)
  { git diff -- . ':!sbom'; git ls-files -o --exclude-standard -- . ':!sbom' | sort | xargs -r sha256sum; } \
    | sha256sum | cut -c1-16
}

FAILED=0
: > "$OUT/summary.txt"
CUR_PID=""  # the running step (a background subshell), for the timeout and Ctrl+C

fmt_dur() {  # fmt_dur SECONDS -> 45s, 3m05s, 1h02m
  local t=$1
  if [ "$t" -ge 3600 ]; then printf '%dh%02dm' $((t / 3600)) $((t % 3600 / 60))
  elif [ "$t" -ge 60 ]; then printf '%dm%02ds' $((t / 60)) $((t % 60))
  else printf '%ds' "$t"; fi
}
last_line() {  # last_line LOG: its last non-empty line, without colours, at most 100 characters
  tail -c 4000 "$1" 2>/dev/null | tr '\r' '\n' | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
    | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-100
}
kill_tree() {  # kill_tree PID SIGNAL: the process and every descendant
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c" "$2"; done
  kill "-$2" "$1" 2>/dev/null
}
stop_step() {  # TERM the running step's process tree, then KILL what is left
  [ -n "$CUR_PID" ] || return 0
  kill_tree "$CUR_PID" TERM; sleep 5; kill_tree "$CUR_PID" KILL
}
on_interrupt() {
  stop_step
  echo "prerelease: interrupted" | tee -a "$OUT/summary.txt"
  exit 130
}
trap on_interrupt INT TERM

step() {  # step NAME LIMIT_SECONDS CMD...: run with progress and a time limit, log, one summary line
  local name=$1 limit=$2; shift 2
  local log="$OUT/$name.log" start now next rc line result=""
  start=$(date +%s); next=$((start + PROGRESS))
  printf '%s %-12s started (limit %s, log %s)\n' "$(date +%H:%M:%S)" "$name" "$(fmt_dur "$limit")" "$log"
  "$@" > "$log" 2>&1 < /dev/null &
  CUR_PID=$!
  while kill -0 "$CUR_PID" 2>/dev/null; do
    sleep 1
    now=$(date +%s)
    if [ $((now - start)) -ge "$limit" ]; then
      echo "prerelease: $name ran past its limit of $(fmt_dur "$limit"); stopped" >> "$log"
      result=TIMEOUT
      stop_step
      break
    fi
    if [ "$PROGRESS" -gt 0 ] && [ "$now" -ge "$next" ]; then
      next=$((now + PROGRESS))
      printf '%s %-12s %7s  %s\n' "$(date +%H:%M:%S)" "$name" "$(fmt_dur $((now - start)))" "$(last_line "$log")"
    fi
  done
  wait "$CUR_PID"; rc=$?
  CUR_PID=""
  [ -n "$result" ] || result=$([ $rc = 0 ] && echo ok || echo FAIL)
  line=$(grep -E '[0-9]+ (passed|failed)' "$log" | tail -1)
  [ -n "$line" ] || line=$(tail -1 "$log")
  printf '%-12s %-7s %6s  %s\n' "$name" "$result" "$(fmt_dur $(( $(date +%s) - start )))" "${line:0:110}" \
    | tee -a "$OUT/summary.txt"
  [ "$result" = ok ] || FAILED=$((FAILED + 1))
  return 0
}
# shellcheck disable=SC2329  # called through step
pytest_q() { "$PY" -m pytest -q -p no:cacheprovider "$@"; }

# The scan must be complete (scan_vulns exits 4 when a scanner failed) and show no VEX problems.
# shellcheck disable=SC2329  # called through step
scan() {
  make vulns || return $?
  ! grep -q "VEX problems: [1-9]" "$OUT/scan.log" 2>/dev/null
}

FP=$(fingerprint)
echo "prerelease: beast-boot $(cat VERSION), commit $(git rev-parse --short HEAD), tree $FP; logs in $OUT"
echo "prerelease: started $(date '+%Y-%m-%d %H:%M'); progress every ${PROGRESS}s (--progress N, 0 = off)"

[ $QUICK = 1 ] || step build 7200 make build
step lint 900 make -s lint
step lock 600 python3 -I build/beastnet/lock.py --check
step installer 1800 pytest_q installer/tests
step menu 600 pytest_q tests/menu
step beastnet 900 env PYTHONPATH=beastnet/python "$PY" -m pytest -q -p no:cacheprovider beastnet/tests
step devtools 900 pytest_q devtools/tests
step selftest 1800 python3 -I scripts/selftest.py
if [ $QUICK = 0 ]; then
  step e2e 10800 pytest_q -rs tests/e2e
  # kernel_vex needs a fresh scan first, then the scan again with its statements
  step scan-pre 3600 make vulns
  step kernel-vex 3600 python3 -I scripts/kernel_vex.py
  step scan 3600 scan
  [ $REAL_ISO = 0 ] || step real-iso 22200 env BB_REAL_ISO=1 timeout 21600 "$PY" -m pytest -q -p no:cacheprovider \
    -rs --tb=short tests/e2e/test_e2e_real_isos.py
  step verify-dist 7200 build/verify-dist.sh --rebuild
  [ $PORTABLE = 0 ] || step portable 7200 scripts/build_portable.sh --all
fi

if [ "$(fingerprint)" != "$FP" ]; then
  echo "prerelease: FAIL: the tree changed while the routine ran (another editor or session?); re-run" \
    | tee -a "$OUT/summary.txt"
  FAILED=$((FAILED + 1))
fi
if [ $FAILED = 0 ]; then
  echo "prerelease: all steps passed: ready to tag v$(cat VERSION)" | tee -a "$OUT/summary.txt"
else
  echo "prerelease: $FAILED step(s) failed; see $OUT/<step>.log" | tee -a "$OUT/summary.txt"
fi
exit "$FAILED"
