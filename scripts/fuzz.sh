#!/usr/bin/env bash
# libFuzzer + ASan/UBSan on the two wire parsers and the whole engine.
#   fuzz.sh [seconds-per-target] [label]
set -euo pipefail
. "$(dirname "$0")/env.sh"
SECS=${1:-60}
LABEL=${2:-local}
OUT=$SRC/results/$LABEL
mkdir -p "$OUT"
bash "$SRC/scripts/build.sh" fuzz >/dev/null
C=$RUN/fuzz-corpus
mkdir -p "$C/iso" "$C/tlv" "$C/engine"
"$BUILD/fuzz/eah-admin" corpus "$C" >/dev/null
cp -n "$C/iso/"* "$C/engine/" 2>/dev/null || true
: > "$OUT/fuzz.txt"
for t in iso8583:iso tlv:tlv engine:engine; do
  name=${t%%:*}; dir=${t##*:}
  log=$RUN/fuzz_$name.log
  (cd "$RUN" && ASAN_OPTIONS=detect_leaks=1 "$BUILD/fuzz/fuzz_$name" -max_total_time="$SECS" -max_len=2048 \
     -print_final_stats=1 "$C/$dir" >"$log" 2>&1) || { echo "fuzz_$name: CRASH (see $log)" | tee -a "$OUT/fuzz.txt"; tail -40 "$log"; exit 1; }
  execs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$log" | grep -o '[0-9]*$')
  cov=$(grep -oE 'cov: [0-9]+' "$log" | tail -1)
  echo "fuzz_$name: ${SECS}s, $execs execs, $cov, 0 crashes" | tee -a "$OUT/fuzz.txt"
done
