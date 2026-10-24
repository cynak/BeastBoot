#!/usr/bin/env bash
# Build, test, scan and check every release file of beast-booter (docs/RELEASING.md).
# The single entry point for CI and `make release`.
#
#   scripts/release/build_release.sh [--out DIR] [--official] [--skip-e2e] [--offline]
#
#   --out DIR     release directory (default: out/release). It ends up holding exactly the
#                 release files + SHA256SUMS; notes, gate result and logs go to DIR/_release/
#   --official    a real release: needs the release tag (v<VERSION>) and the project's signing
#                 key in BB_KEY_DIR; the vulnerability gate is enforced. Without it the build is
#                 marked "unofficial local build" (signed with whatever key BB_KEY_DIR/keys holds)
#   --skip-e2e    don't boot the QEMU end-to-end tests (also skipped without a usable /dev/kvm)
#   --offline     no downloads: cached runtimes, beast-net packages and vulnerability data only
#
# Environment:
#   BB_KEY_DIR                  signing key directory (beast-booter.key/.crt/.cer; default keys/)
#   BB_RELEASE_TAG              the tag being released (default: CI tag variables, else a v* tag on HEAD)
#   BB_RELEASE_CERT_SHA256      optional pin: the release certificate's SHA-256 (refuse any other key)
#   BB_RELEASE_GATE             enforce | warn | off (default: enforce with --official, else warn)
#   BB_RELEASE_GATE_SEVERITY    critical | high (default: critical)
#   BB_RELEASE_GATE_BASELINE    the previous release's vulnerabilities.json: findings already in it
#                               are not new and never block
#   BB_RELEASE_GATE_IGNORE_UNFIXED=1  (default) findings without a published fix never block; 0 = strict
#   BB_RELEASE_REPO, BB_RELEASE_ATTESTATIONS=1  owner/repo for the notes' attestation command (GitHub)
#   BB_PROJECT_URL              project URL for the SBAT entry (default with --official: from the CI)
#   BB_RELEASE_SKIP_TESTS=1     local troubleshooting only: skip the unit tests (refused with --official;
#                               recorded in _release/release.json)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOL=(python3 -I "$ROOT/scripts/release/release_tool.py")

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "build_release: error: $*" >&2; exit 1; }
note() {
  echo "build_release: NOTE: $*" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::notice::$*"; fi
}
step() { echo; echo "==> $*"; }

OUT="$ROOT/out/release" OFFICIAL=0 SKIP_E2E=0 OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || die "--out needs a value"; OUT="$2"; shift ;;
    --out=*) OUT="${1#*=}" ;;
    --official) OFFICIAL=1 ;;
    --skip-e2e) SKIP_E2E=1 ;;
    --offline) OFFLINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
case "$OUT" in "$ROOT"|"$ROOT/dist"|"$ROOT/sbom"|"$ROOT/out") die "--out must be a directory of its own" ;; esac
# Only ever clean a directory this script made (or an empty one).
if [ -n "$(ls -A "$OUT")" ]; then
  [ -f "$OUT/_release/release.json" ] || [ -f "$OUT/_release/started" ] \
    || die "$OUT is not empty and is not an earlier release directory; choose another --out"
  find "$OUT" -mindepth 1 -delete
fi
META="$OUT/_release"
LOGS="$META/logs"
mkdir -p "$LOGS"
date -u +%FT%TZ > "$META/started"

# run NAME CMD...: output to a log; on failure show its end and stop.
run() {
  local name="$1"; shift
  local log="$LOGS/$name.log"
  echo "    $* (log: ${log#"$ROOT"/})"
  if ! "$@" > "$log" 2>&1; then
    tail -n 40 "$log" >&2
    die "step '$name' failed (full log: $log)"
  fi
  tail -n 3 "$log" | sed 's/^/    | /'
}

# shellcheck source-path=SCRIPTDIR source=../dev-env.sh
source "$ROOT/scripts/dev-env.sh"
if [ "$OFFLINE" = 1 ]; then export BB_OFFLINE=1; fi

# ---------------------------------------------------------------------------
step "Version and tag"
TAG="${BB_RELEASE_TAG:-}"
if [ -z "$TAG" ] && [ "${GITHUB_REF_TYPE:-}" = tag ]; then TAG="${GITHUB_REF_NAME:-}"; fi
if [ -z "$TAG" ]; then TAG="${CI_COMMIT_TAG:-}"; fi
if [ -z "$TAG" ]; then TAG="$(git describe --tags --exact-match --match 'v*' HEAD 2>/dev/null || true)"; fi
vargs=(version)
if [ -n "$TAG" ]; then vargs+=(--tag "$TAG"); fi
if [ "$OFFICIAL" = 1 ]; then vargs+=(--require-tag); fi
VJSON="$("${TOOL[@]}" "${vargs[@]}")" || exit 1
VERSION="$(python3 -I -c 'import json, sys; print(json.loads(sys.argv[1])["version"])' "$VJSON")"
echo "    version $VERSION, tag ${TAG:-(none: not a tagged commit)}, official: $([ "$OFFICIAL" = 1 ] && echo yes || echo no)"

# ---------------------------------------------------------------------------
step "Signing key"
KEY_DIR="${BB_KEY_DIR:-$ROOT/keys}"
CER="$KEY_DIR/beast-booter.cer"
[ -f "$CER" ] || die "no signing certificate at $CER (official: write the release key there; local: make keys)"
if [ "$OFFICIAL" = 1 ]; then
  [ -n "${BB_KEY_DIR:-}" ] || die "--official needs BB_KEY_DIR pointing at the release key (never the dev key in keys/)"
  [ "$(cd "$KEY_DIR" && pwd)" != "$ROOT/keys" ] || die "--official refuses the local development key in keys/"
  if [ -z "${BB_PROJECT_URL:-}" ]; then
    if [ -n "${GITHUB_REPOSITORY:-}" ]; then export BB_PROJECT_URL="${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY"
    elif [ -n "${CI_PROJECT_URL:-}" ]; then export BB_PROJECT_URL="$CI_PROJECT_URL"
    fi
  fi
fi
CERT_SHA256="$(sha256sum < "$CER" | cut -d' ' -f1)"
if [ -n "${BB_RELEASE_CERT_SHA256:-}" ] && [ "${BB_RELEASE_CERT_SHA256,,}" != "$CERT_SHA256" ]; then
  die "the certificate in $KEY_DIR (SHA-256 $CERT_SHA256) is not the pinned release certificate ($BB_RELEASE_CERT_SHA256)"
fi
echo "    $(openssl x509 -inform DER -in "$CER" -noout -subject -nameopt RFC2253), SHA-256 $CERT_SHA256"
export BB_KEY_DIR="$KEY_DIR"

# ---------------------------------------------------------------------------
step "Boot files (make build)"
run 01-build make -s -C "$ROOT" build

step "Tests"
TESTS=run
if [ "${BB_RELEASE_SKIP_TESTS:-0}" = 1 ]; then
  [ "$OFFICIAL" = 0 ] || die "BB_RELEASE_SKIP_TESTS is refused for an official release"
  TESTS="skipped (BB_RELEASE_SKIP_TESTS=1)"
  note "unit tests skipped (BB_RELEASE_SKIP_TESTS=1): not a releasable build"
else
  run 02-test-installer pytest -q -p no:cacheprovider installer/tests
  run 03-test-devtools pytest -q -p no:cacheprovider devtools/tests
  run 04-test-beastnet pytest -q -p no:cacheprovider beastnet/tests
fi
if [ "$SKIP_E2E" = 1 ]; then
  E2E="skipped (--skip-e2e)"
  note "end-to-end QEMU tests skipped (--skip-e2e)"
elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  E2E="skipped (no usable /dev/kvm)"
  note "end-to-end QEMU tests skipped: no usable /dev/kvm on this machine"
else
  run 05-test-e2e pytest -q -p no:cacheprovider tests/e2e
  E2E=run
fi

# ---------------------------------------------------------------------------
step "SBOM and vulnerability scan"
if [ "$OFFLINE" = 0 ]; then
  run 07-sbom-tools bash scripts/sbom-vuln.sh tools
fi
run 08-sbom bash scripts/sbom-vuln.sh sbom
run 08b-test-sbom-tooling python3 -I scripts/selftest.py
scan_args=(scan --fail-on none)
if [ "$OFFLINE" = 1 ]; then scan_args+=(--offline); fi
run 09-scan bash scripts/sbom-vuln.sh "${scan_args[@]}"

GATE_MODE="${BB_RELEASE_GATE:-$([ "$OFFICIAL" = 1 ] && echo enforce || echo warn)}"
gate_args=(gate --report sbom/vulnerabilities.json --out "$META/gate.json" --mode "$GATE_MODE"
           --severity "${BB_RELEASE_GATE_SEVERITY:-critical}")
if [ -n "${BB_RELEASE_GATE_BASELINE:-}" ]; then gate_args+=(--baseline "$BB_RELEASE_GATE_BASELINE"); fi
if [ "${BB_RELEASE_GATE_IGNORE_UNFIXED:-1}" = 1 ]; then gate_args+=(--ignore-unfixed); fi
"${TOOL[@]}" "${gate_args[@]}" \
  || die "release blocked by the vulnerability gate (see $META/gate.json and docs/RELEASING.md, 'When the scan blocks')"

# ---------------------------------------------------------------------------
step "Portable packages"
port_args=(--all --skip-build --keep-sbom --out "$META/portable")
if [ "$OFFLINE" = 1 ]; then port_args+=(--offline); fi
run 10-portable scripts/build_portable.sh "${port_args[@]}"

# ---------------------------------------------------------------------------
step "Release files"
P="beast-booter-$VERSION"
for t in linux-x86_64.tar.gz windows-x86_64.zip macos-x86_64.zip macos-arm64.zip; do
  [ -f "$META/portable/$P-$t" ] || die "build_portable.sh did not produce $P-$t"
  mv "$META/portable/$P-$t" "$OUT/$P-$t"
done
"${TOOL[@]}" dist-zip --dist dist --out "$OUT/$P-dist.zip" --prefix "$P-dist"
cp sbom/beast-booter.cdx.json "$OUT/$P-sbom.cdx.json"
cp sbom/beast-booter.spdx.json "$OUT/$P-sbom.spdx.json"
cp sbom/vulnerabilities.json "$OUT/$P-vulnerabilities.json"
cp sbom/VULNERABILITIES.md "$OUT/$P-VULNERABILITIES.md"
DIST_CER="dist/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer"
cmp -s "$DIST_CER" "$CER" || die "$DIST_CER is not the certificate in $KEY_DIR"
cp "$DIST_CER" "$OUT/$P-ENROLL_THIS_KEY_IN_MOKMANAGER.cer"
cert_args=(cert --cer "$CER" --out "$OUT/$P-CERTIFICATE.txt" --version "$VERSION" --json "$META/certificate.json")
if [ "$OFFICIAL" = 1 ]; then cert_args+=(--official); fi
"${TOOL[@]}" "${cert_args[@]}"
"${TOOL[@]}" sums --dir "$OUT"

notes_args=(notes --dir "$OUT" --version "$VERSION" --out "$META/RELEASE_NOTES.md" --gate "$META/gate.json"
            --tag "${TAG:-v$VERSION}")
if [ "$OFFICIAL" = 1 ]; then notes_args+=(--official); fi
if [ -n "${BB_RELEASE_REPO:-}" ]; then notes_args+=(--repo "$BB_RELEASE_REPO"); fi
if [ "${BB_RELEASE_ATTESTATIONS:-0}" = 1 ]; then notes_args+=(--attestations); fi
"${TOOL[@]}" "${notes_args[@]}"

# ---------------------------------------------------------------------------
step "Self-verification"
(cd "$OUT" && sha256sum -c --quiet SHA256SUMS) || die "SHA256SUMS does not match the files"
"${TOOL[@]}" verify --dir "$OUT" --version "$VERSION" || die "release verification failed"
run 11-verify-archives python3 -I packaging/portable/build.py --verify \
  "$OUT/$P-linux-x86_64.tar.gz" "$OUT/$P-windows-x86_64.zip" "$OUT/$P-macos-x86_64.zip" "$OUT/$P-macos-arm64.zip"

PRERELEASE="$(python3 -I -c 'import json, sys; print(str(json.loads(sys.argv[1])["prerelease"]).lower())' "$VJSON")"
python3 -I - "$META/release.json" "$VERSION" "${TAG:-}" "$OFFICIAL" "$PRERELEASE" "$CERT_SHA256" "$OUT/SHA256SUMS" \
    "$TESTS" "$E2E" <<'EOF'
import json, sys
out, version, tag, official, pre, cert, sums, tests, e2e = sys.argv[1:]
files = [line.split("  ", 1)[1] for line in open(sums).read().splitlines()] + ["SHA256SUMS"]
json.dump({"version": version, "tag": tag or None, "official": official == "1", "prerelease": pre == "true",
           "certificate_sha256": cert, "unit_tests": tests, "e2e_tests": e2e, "files": files,
           "notes": "_release/RELEASE_NOTES.md"},
          open(out, "w"), indent=1)
open(out, "a").write("\n")
EOF
rm -rf "$META/portable" "$META/started"

step "Done: $([ "$OFFICIAL" = 1 ] && echo "release $VERSION" || echo "UNOFFICIAL local build $VERSION") in ${OUT#"$ROOT"/}"
while read -r _ f; do
  printf '  %12s  %s\n' "$(stat -c %s "$OUT/$f")" "$f"
done < "$OUT/SHA256SUMS"
printf '  %12s  %s\n' "$(stat -c %s "$OUT/SHA256SUMS")" SHA256SUMS
echo "  notes: ${META#"$ROOT"/}/RELEASE_NOTES.md, gate: ${META#"$ROOT"/}/gate.json, logs: ${LOGS#"$ROOT"/}/"
