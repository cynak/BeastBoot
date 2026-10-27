#!/usr/bin/env bash
# The local pre-release routine (docs/RELEASING.md, "Before tagging"): everything a release
# must pass, including the checks build_release.sh does not run (real-ISO boots, GRUB/wimboot
# rebuilt from source and compared, kernel VEX regenerated against today's vulnerability data).
# Run it on the exact tree you are about to tag; it changes only dist/, sbom/ and out/.
#
#   scripts/release/prerelease.sh [--quick] [--skip-real-iso] [--skip-portable] [--out DIR]
#
#   --quick          unit tests, lint and lock check only (no build, no QEMU, no scan)
#   --skip-real-iso  skip the real-ISO boots (BB_REAL_ISO=1; downloads tens of GB once)
#   --skip-portable  skip scripts/build_portable.sh --all
#   --out DIR        logs (default: out/prerelease); one <step>.log per step + summary.txt
#
# Every step runs even after a failure (so one run shows everything); the exit code is the
# number of failed steps (0 = ready to tag). Fails if the tree changes while it runs.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
QUICK=0 REAL_ISO=1 PORTABLE=1 OUT="$ROOT/out/prerelease"
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --skip-real-iso) REAL_ISO=0 ;;
    --skip-portable) PORTABLE=0 ;;
    --out) OUT="$2"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
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
step() {  # step NAME CMD...: run, log, one summary line
  local name=$1; shift
  local log="$OUT/$name.log" start rc line
  start=$(date +%s)
  "$@" > "$log" 2>&1
  rc=$?
  line=$(grep -E '[0-9]+ (passed|failed)' "$log" | tail -1)
  [ -n "$line" ] || line=$(tail -1 "$log")
  printf '%-12s %-4s %5ss  %s\n' "$name" "$([ $rc = 0 ] && echo ok || echo FAIL)" \
    "$(( $(date +%s) - start ))" "${line:0:110}" | tee -a "$OUT/summary.txt"
  [ $rc = 0 ] || FAILED=$((FAILED + 1))
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

[ $QUICK = 1 ] || step build make build
step lint make -s lint
step lock python3 -I build/beastnet/lock.py --check
step installer pytest_q installer/tests
step menu pytest_q tests/menu
step beastnet env PYTHONPATH=beastnet/python "$PY" -m pytest -q -p no:cacheprovider beastnet/tests
step devtools pytest_q devtools/tests
step selftest python3 -I scripts/selftest.py
if [ $QUICK = 0 ]; then
  step e2e pytest_q -rs tests/e2e
  # kernel_vex needs a fresh scan first, then the scan again with its statements
  step scan-pre make vulns
  step kernel-vex python3 -I scripts/kernel_vex.py
  step scan scan
  [ $REAL_ISO = 0 ] || step real-iso env BB_REAL_ISO=1 timeout 21600 "$PY" -m pytest -q -p no:cacheprovider \
    -rs --tb=short tests/e2e/test_e2e_real_isos.py
  step verify-dist build/verify-dist.sh --rebuild
  [ $PORTABLE = 0 ] || step portable scripts/build_portable.sh --all
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
