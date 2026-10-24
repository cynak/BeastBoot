#!/usr/bin/env bash
# sbom-vuln pipeline: install tools, generate + validate the SBOM, scan.
#
#   sbom-vuln.sh all   [scan options]   everything below, in order (default)
#   sbom-vuln.sh tools                  pinned syft/grype/osv-scanner + schemas -> .tools/
#   sbom-vuln.sh sbom                   sbom/beast-booter.{cdx,spdx}.json + sbom/validation.json
#   sbom-vuln.sh scan  [scan options]   sbom/vulnerabilities.json, VULNERABILITIES.md, vex.proposed.openvex.json
#
# scan options: --offline --refresh --no-ubuntu-tracker --fail-on critical|high --vex FILE
# Needs dist/ from `make build`. Never writes outside sbom/ and .tools/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${BB_ROOT:-$(cd "$HERE/.." && pwd)}"

step_tools() { bash "$HERE/install-tools.sh"; }
step_gen() {
  [ -f "$ROOT/dist/manifest.json" ] || { echo "sbom-vuln: dist/manifest.json missing - run 'make build' first" >&2; exit 2; }
  python3 -I "$HERE/gen_sbom.py" --root "$ROOT"
}
step_validate() { python3 -I "$HERE/validate_sbom.py" --root "$ROOT"; }
step_sbom() { step_gen; step_validate; }
step_scan() { python3 -I "$HERE/scan_vulns.py" --root "$ROOT" "$@"; }
# all: a failed validation (e.g. a shipped file that is not its package's file) still gets a
# report - the scan turns it into a boot-chain finding - but the run exits non-zero.
step_all() {
  step_tools
  step_gen
  local vrc=0 src=0
  step_validate || vrc=$?
  step_scan "$@" || src=$?
  if [ "$vrc" -ne 0 ]; then
    echo "sbom-vuln: SBOM validation FAILED (sbom/validation.json); the report was written anyway" >&2
    exit 1
  fi
  exit "$src"
}

cmd="${1:-all}"
[ $# -gt 0 ] && shift
case "$cmd" in
  tools) step_tools ;;
  sbom)  step_sbom ;;
  scan)  step_scan "$@" ;;
  all)   step_all "$@" ;;
  *) echo "usage: $0 [all|tools|sbom|scan] [scan options]" >&2; exit 2 ;;
esac
