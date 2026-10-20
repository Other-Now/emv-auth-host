#!/usr/bin/env bash
# PCI check: after a run, no full PAN may appear anywhere the host wrote —
# database, WAL, log. Searches for every seeded PAN as ASCII. A positive
# control (a file that does contain PANs) proves the scan can see them.
#   pan_scan.sh <run-dir> [cards]
set -euo pipefail
. "$(dirname "$0")/env.sh"
DIR=$1
N=${2:-1000}
"$BIN/eah-admin" pans "$N" > "$DIR/pans.txt"
files=$(ls "$DIR"/host.db* "$DIR"/host.log 2>/dev/null)
hits=$(cat $files | grep -a -o -F -f "$DIR/pans.txt" | wc -l || true)
control=$(grep -a -o -F -f "$DIR/pans.txt" "$DIR/pans.txt" | wc -l)
bytes=$(cat $files | wc -c)
masked=$(grep -c -E '476173\*{6}[0-9]{4}' "$DIR/host.log" || true)
echo "pan_scan: $N PANs searched in $(echo $files | wc -w) files ($bytes bytes): $hits full-PAN hits; masked PANs in log: $masked; positive control: $control/$N hits"
[ "$hits" -eq 0 ] && [ "$control" -eq "$N" ]
