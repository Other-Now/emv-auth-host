#!/usr/bin/env bash
# Golden regression: fresh DB, fixed clock, scripted scenario; the transcript
# must match tests/golden/expected.txt byte for byte.
#   regress.sh            compare (exit 1 on any difference)
#   regress.sh --update   rewrite the expected transcript
set -euo pipefail
. "$(dirname "$0")/env.sh"
PORT=${PORT:-18583}
D=${RUN}/regress
rm -rf "$D" && mkdir -p "$D"
"$BIN/eah-admin" init --db "$D/host.db" --cards 8 --balance 100000 --limit 50000 >/dev/null
"$BIN/eah-admin" card --db "$D/host.db" --index 5 --status LOST
"$BIN/eah-admin" card --db "$D/host.db" --index 6 --status BLOCKED
"$BIN/eah-admin" card --db "$D/host.db" --index 7 --expiry 2401

# DOCKER_IMAGE=eah:ci runs the same suite against the container build.
if [ -n "${DOCKER_IMAGE:-}" ]; then
  docker run -d --rm --name eah-regress --network host --user "$(id -u):$(id -g)" -v "$D:/data" "$DOCKER_IMAGE"     --db /data/host.db --port "$PORT" --today 2610 --log /data/host.log >/dev/null
  trap 'docker stop eah-regress >/dev/null 2>&1 || true' EXIT
else
  "$BIN/eah-server" --db "$D/host.db" --port "$PORT" --today 2610 --log "$D/host.log" 2>"$D/server.err" &
  PID=$!
  trap 'kill $PID 2>/dev/null || true' EXIT
fi
for _ in $(seq 200); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.05; done

{
  "$BIN/termsim" golden --port "$PORT"
  echo "## reconciliation"
  "$BIN/eah-admin" recon --db "$D/host.db"
} > "$D/actual.txt" 2>&1 || true

if [ -n "${DOCKER_IMAGE:-}" ]; then docker stop eah-regress >/dev/null; else kill -TERM $PID; wait $PID 2>/dev/null || true; fi
trap - EXIT

if [ "${1:-}" = "--update" ]; then
  cp "$D/actual.txt" "$SRC/tests/golden/expected.txt"
  echo "updated tests/golden/expected.txt ($(grep -c '^## ' "$D/actual.txt") steps)"
  exit 0
fi
if diff -u "$SRC/tests/golden/expected.txt" "$D/actual.txt"; then
  echo "golden: $(grep -c '^## ' "$D/actual.txt") steps match"
else
  echo "golden: TRANSCRIPT DIFFERS"
  exit 1
fi
