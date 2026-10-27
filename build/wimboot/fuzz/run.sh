#!/usr/bin/env bash
# Fuzz wimboot's parsers on the host (see README.md).
#
#   run.sh [--patches N|all] [--time SECONDS] [--workers N] [--from-wim WIM]
#          [--targets "wim lzx xca cpio"] OUTDIR
#
# Unpacks the pinned wimboot source (build/wimboot/source.lock.json, from
# the wimboot build cache), applies the first N patches of patches/series
# (default: all), builds one ASan+UBSan binary per target, makes seeds and
# fuzzes every target with N workers for SECONDS each, restarting a worker
# after each crash. Crash inputs: OUTDIR/<target>/crashes; summary:
# OUTDIR/summary.txt (unique crash signatures per target).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WB="$(dirname "$HERE")"
ROOT="$(cd "$WB/../.." && pwd)"
PATCHES=all
TIME=300
WORKERS=4
FROM_WIM=
TARGETS="wim lzx xca cpio"
while [ $# -gt 1 ]; do
  case "$1" in
    --patches) PATCHES="$2"; shift 2 ;;
    --time) TIME="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --from-wim) FROM_WIM="$2"; shift 2 ;;
    --targets) TARGETS="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ $# -eq 1 ] || { sed -n '2,12p' "$0"; exit 2; }
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"

# --- source: pinned tarball + our patches -------------------------------
CACHE="${BB_WIMBOOT_CACHE:-$ROOT/.tools/cache/wimboot}"
read -r NAME SHA < <(python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1]))["source"]; print(s["name"], s["sha256"])' "$WB/source.lock.json")
TAR="$CACHE/dl/$NAME"
[ -f "$TAR" ] || { echo "$TAR missing: run 'make build' once (it downloads the source)" >&2; exit 1; }
echo "$SHA  $TAR" | sha256sum -c --quiet -
rm -rf "$OUT/src"; mkdir -p "$OUT/src"
tar -xzf "$TAR" -C "$OUT/src" --strip-components=1
mapfile -t SERIES < <(grep -v -E '^\s*(#|$)' "$WB/patches/series")
[ "$PATCHES" = all ] && PATCHES=${#SERIES[@]}
for ((i = 0; i < PATCHES; i++)); do
  patch -d "$OUT/src" -p1 -F0 -s < "$WB/patches/${SERIES[$i]}"
done
echo "source: wimboot + ${SERIES[*]:0:$PATCHES}" | tee "$OUT/summary.txt"

# --- build ----------------------------------------------------------------
SRC="$OUT/src/src"
SAN=("-fsanitize=address,undefined" "-fno-sanitize=alignment,shift-base" -fno-sanitize-recover=all -g -O1 -fno-omit-frame-pointer)
WCFLAGS=(-nostdinc -I"$SRC" -I"$HERE" -fshort-wchar -ffreestanding
         -DDEBUG=0 -DVERSION='"fuzz"' -DSBAT_GENERATION='"1"' -Wno-builtin-declaration-mismatch -Wno-address-of-packed-member)
declare -A UNITS=(
  [wim]="wim.c lzx.c xca.c huffman.c wimpatch.c sha1.c"
  [lzx]="lzx.c huffman.c"
  [xca]="xca.c huffman.c"
  [cpio]="cpio.c"
)
mkdir -p "$OUT/bin"
gcc "${SAN[@]}" -c "$HERE/engine.c" -o "$OUT/bin/engine.o"
for t in $TARGETS; do
  objs=("$OUT/bin/engine.o")
  for u in ${UNITS[$t]} "$HERE/shim.c" "$HERE/fuzz_$t.c"; do
    case "$u" in /*) src="$u" ;; *) src="$SRC/$u" ;; esac
    o="$OUT/bin/$t-$(basename "$u" .c).o"
    gcc "${SAN[@]}" -fsanitize-coverage=trace-pc "${WCFLAGS[@]}" -c "$src" -o "$o"
    objs+=("$o")
  done
  gcc "${SAN[@]}" "${objs[@]}" -o "$OUT/bin/fuzz_$t"
done
echo "built: $(cd "$OUT/bin" && echo fuzz_*)"

# --- seeds ----------------------------------------------------------------
python3 -I "$HERE/mkseeds.py" "$OUT/seeds" ${FROM_WIM:+--from-wim "$FROM_WIM"}

# --- fuzz -----------------------------------------------------------------
export ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:symbolize=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:abort_on_error=1"
worker() {  # target worker-number
  local t="$1" w="$2" end=$((SECONDS + TIME)) runs=0 crashes=0 left rc
  local dir="$OUT/$t"
  while :; do
    left=$((end - SECONDS)); [ "$left" -gt 0 ] || break
    runs=$((runs + 1))
    rc=0
    "$OUT/bin/fuzz_$t" -time "$left" -seed "$((w * 7919 + runs))" -max_len 65536 \
      -corpus "$dir/corpus" -crashes "$dir/crashes" "$OUT/seeds/$t" >> "$dir/log.$w" 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || crashes=$((crashes + 1))
  done
  echo "$crashes" > "$dir/crashcount.$w"
}
for t in $TARGETS; do
  mkdir -p "$OUT/$t"
  for ((w = 1; w <= WORKERS; w++)); do worker "$t" "$w" 2>/dev/null & done
done
wait

# --- summary --------------------------------------------------------------
set +e +o pipefail
{
  for t in $TARGETS; do
    execs=$(grep -h '^DONE' "$OUT/$t"/log.* 2>/dev/null | awk '{s+=$3} END {print s+0}')
    n=$(cat "$OUT/$t"/crashcount.* | awk '{s+=$1} END {print s+0}')
    edges=$(grep -h '^DONE' "$OUT/$t"/log.* 2>/dev/null | awk '{if ($7>m) m=$7} END {print m+0}')
    echo "== $t: ${WORKERS} workers x ${TIME}s, crashes $n, execs (clean exits) $execs, edges $edges, corpus $(find "$OUT/$t/corpus" -type f | wc -l)"
    awk -f "$HERE/triage.awk" "$OUT/$t"/log.* | sort | uniq -c | sort -rn | head -25
  done
} | tee -a "$OUT/summary.txt"
