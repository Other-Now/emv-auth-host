#!/usr/bin/env bash
# Local only (no sudo): unpack libsqlite3-dev into ~/eah-deps/root. The
# runtime libsqlite3.so.0 is already in /usr/lib. CI uses apt-get instead.
set -euo pipefail
ROOT=$HOME/eah-deps/root
mkdir -p "$ROOT" "$HOME/eah-deps/dl"
cd "$HOME/eah-deps/dl"
ls libsqlite3-dev_*.deb >/dev/null 2>&1 || apt-get download libsqlite3-dev
for d in *.deb; do dpkg-deb -x "$d" "$ROOT"; done
ln -sf /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 "$ROOT/usr/lib/x86_64-linux-gnu/libsqlite3.so"
ls "$ROOT/usr/include/sqlite3.h"
