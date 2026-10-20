#!/usr/bin/env bash
# Closed-loop load: C terminals, each with one request in flight.
# Matrix: group commit on/off x synchronous FULL/NORMAL x 1/8/32 connections.
#   bench.sh [label] [seconds]     results -> results/<label>/bench.txt
set -euo pipefail
. "$(dirname "$0")/env.sh"
LABEL=${1:-local}
SECS=${2:-8}
PORT=${PORT:-18584}
OUT=$SRC/results/$LABEL
mkdir -p "$OUT"
D=$RUN/bench
{
  echo "# $(date -u +%FT%TZ) $(uname -r) cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) nproc=$(nproc)"
  echo "# fs: $(df -T "$RUN" | awk 'NR==2{print $2}') ; ${SECS}s per cell; 1000 cards"
} > "$OUT/bench.txt"
for sync in full normal; do
  for gc in on off; do
    for conns in 1 8 32; do
      rm -rf "$D" && mkdir -p "$D"
      "$BIN/eah-admin" init --db "$D/host.db" --cards 1000 --balance 1000000000 --limit 100000 >/dev/null
      flags=(--db "$D/host.db" --port "$PORT" --sync "$sync" --log "$D/host.log")
      [ "$gc" = off ] && flags+=(--no-group-commit)
      "$BIN/eah-server" "${flags[@]}" 2>"$D/server.err" &
      PID=$!
      for _ in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.05; done
      line=$("$BIN/termsim" load --port "$PORT" --conns "$conns" --seconds "$SECS" --cards 1000)
      kill -TERM $PID; wait $PID 2>/dev/null || true
      stats=$(grep -o 'batches=[0-9]* msgs=[0-9]* max_batch=[0-9]*' "$D/server.err")
      echo "sync=$sync group_commit=$gc $line $stats" | tee -a "$OUT/bench.txt"
    done
  done
done
