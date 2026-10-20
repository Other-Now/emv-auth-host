#!/usr/bin/env bash
# Chaos: responses delayed past the terminal timeout or dropped (server-side
# fault injection, after commit), plus repeated kill -9 of the host. Then
# reconcile the host's database against what every terminal believes.
#   chaos.sh <safe|naive> [kills] [conns] [txns-per-conn] [label]
set -uo pipefail
. "$(dirname "$0")/env.sh"
POLICY=${1:-safe}
KILLS=${2:-10}
CONNS=${3:-16}
TXNS=${4:-500}
LABEL=${5:-local}
PORT=${PORT:-18585}
D=$RUN/chaos-$POLICY
OUT=$SRC/results/$LABEL
rm -rf "$D" && mkdir -p "$D" "$OUT"
"$BIN/eah-admin" init --db "$D/host.db" --cards 1000 --balance 1000000000 --limit 100000 >/dev/null

start() {
  "$BIN/eah-server" --db "$D/host.db" --port "$PORT" --log "$D/host.log" \
    --fault-delay 0.02:600 --fault-drop 0.01 --seed "$1" 2>>"$D/server.err" &
  PID=$!
}
start 1
"$BIN/termsim" chaos --port "$PORT" --conns "$CONNS" --txns "$TXNS" --cards 1000 --timeout-ms 300 \
  --policy "$POLICY" --ledger "$D/ledger.txt" > "$D/termsim.out" 2>&1 &
TS=$!

killed=0
while [ $killed -lt "$KILLS" ] && kill -0 $TS 2>/dev/null; do
  sleep "0.$((RANDOM % 9 + 3))"
  kill -9 $PID 2>/dev/null && killed=$((killed + 1))
  wait $PID 2>/dev/null
  sleep 0.2
  start $((killed + 1))
done
wait $TS; TS_RC=$?
kill -TERM $PID; wait $PID 2>/dev/null

{
  echo "# chaos policy=$POLICY kills=$killed conns=$CONNS txns/conn=$TXNS fault: 2% delayed 600ms (timeout 300ms), 1% dropped"
  cat "$D/termsim.out"
  "$BIN/eah-admin" recon --db "$D/host.db" --ledger "$D/ledger.txt"
  echo "recon_exit=$?"
} | tee "$OUT/chaos-$POLICY.txt"
[ $TS_RC -eq 0 ] || exit 1
