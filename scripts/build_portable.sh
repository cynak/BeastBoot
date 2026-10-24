#!/usr/bin/env bash
# Build beast-booter's no-install portable packages.
#
#   scripts/build_portable.sh                  # this machine's target (e.g. linux-x86_64)
#   scripts/build_portable.sh --all            # linux-x86_64, windows-x86_64, macos-x86_64, macos-arm64
#   scripts/build_portable.sh --target windows-x86_64 --target macos-arm64
#
# Steps: refresh the boot files (make build) -> regenerate the SBOM so it
# matches dist/ (make sbom) -> packaging/portable/build.py -> verify every archive against its
# PACKAGE-MANIFEST.json -> print the results. Output: out/portable/ (or --out).
#
# Options:
#   --all               build every target
#   --target T          build target T (repeatable)
#   --skip-build        don't run `make build`; package the existing dist/
#   --keep-sbom         don't regenerate the SBOM (it must already match dist/)
#   --no-sbom           leave the SBOM out of the packages (and don't regenerate it)
#   --offline           use only cached runtimes (no downloads)
#   --out DIR           output directory (default: out/portable)
#   -h, --help          show this help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "build_portable: error: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

TARGETS=()
ALL=0 SKIP_BUILD=0 KEEP_SBOM=0 NO_SBOM=0 OFFLINE=0
OUT="$ROOT/out/portable"

while [ $# -gt 0 ]; do
  case "$1" in
    --all) ALL=1 ;;
    --target) [ $# -ge 2 ] || die "--target needs a value"; TARGETS+=("$2"); shift ;;
    --target=*) TARGETS+=("${1#*=}") ;;
    --skip-build) SKIP_BUILD=1 ;;
    --keep-sbom) KEEP_SBOM=1 ;;
    --no-sbom) NO_SBOM=1 ;;
    --offline) OFFLINE=1 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value"; OUT="$2"; shift ;;
    --out=*) OUT="${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

[ "$KEEP_SBOM" = 1 ] && [ "$NO_SBOM" = 1 ] && die "--keep-sbom and --no-sbom are mutually exclusive"
[ "$ALL" = 1 ] && [ "${#TARGETS[@]}" -gt 0 ] && die "use either --all or --target, not both"

# Default: the target matching this machine.
if [ "$ALL" = 0 ] && [ "${#TARGETS[@]}" -eq 0 ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) TARGETS=(linux-x86_64) ;;
    Darwin-x86_64) TARGETS=(macos-x86_64) ;;
    Darwin-arm64) TARGETS=(macos-arm64) ;;
    *) die "no default target for $(uname -s)-$(uname -m); pass --target or --all" ;;
  esac
fi

# shellcheck source-path=SCRIPTDIR source=dev-env.sh
source "$ROOT/scripts/dev-env.sh"

if [ "$SKIP_BUILD" = 0 ]; then
  step "Refreshing boot files (make build)"
  make -s -C "$ROOT" build || die "make build failed (no signing key yet? run: make keys)"
else
  [ -f "$ROOT/dist/manifest.json" ] || die "dist/ is missing; run without --skip-build"
fi

# The packager refuses an SBOM that describes a different dist/, so refresh it
# unless asked not to.
if [ "$NO_SBOM" = 0 ] && [ "$KEEP_SBOM" = 0 ]; then
  step "Regenerating the SBOM so it matches dist/ (make sbom)"
  make -s -C "$ROOT" sbom || die "make sbom failed (use --no-sbom to package without it)"
fi

ARGS=(--out "$OUT")
if [ "$ALL" = 1 ]; then ARGS+=(--all); else for t in "${TARGETS[@]}"; do ARGS+=(--target "$t"); done; fi
[ "$NO_SBOM" = 1 ] && ARGS+=(--no-sbom)
[ "$OFFLINE" = 1 ] && ARGS+=(--offline)

step "Building packages: ${ARGS[*]}"
python3 -I "$ROOT/packaging/portable/build.py" "${ARGS[@]}"

shopt -s nullglob
ARCHIVES=("$OUT"/beast-booter-*.tar.gz "$OUT"/beast-booter-*.zip)
[ "${#ARCHIVES[@]}" -gt 0 ] || die "no archives found in $OUT"

step "Verifying archives against their manifests"
python3 -I "$ROOT/packaging/portable/build.py" --verify "${ARCHIVES[@]}"

step "Done"
for a in "${ARCHIVES[@]}"; do
  printf '  %-60s %s\n' "${a#"$ROOT"/}" "$(du -h "$a" | cut -f1)"
done
[ -f "$OUT/SHA256SUMS" ] && echo "  checksums: ${OUT#"$ROOT"/}/SHA256SUMS"
