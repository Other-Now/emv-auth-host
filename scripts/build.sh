#!/usr/bin/env bash
# build.sh [release|asan|fuzz]
set -euo pipefail
. "$(dirname "$0")/env.sh"
kind=${1:-release}
case $kind in
  release) cmake -S "$SRC" -B "$BUILD/release" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEAH_DEPS_ROOT="${EAH_DEPS_ROOT:-}" >/dev/null ;;
  asan)    cmake -S "$SRC" -B "$BUILD/asan" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DEAH_SANITIZE=ON -DEAH_DEPS_ROOT="${EAH_DEPS_ROOT:-}" >/dev/null ;;
  fuzz)    CC=$CLANG CXX=$CLANGXX cmake -S "$SRC" -B "$BUILD/fuzz" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
             -DEAH_FUZZ=ON -DEAH_SANITIZE=ON -DEAH_DEPS_ROOT="${EAH_DEPS_ROOT:-}" >/dev/null ;;
  *) echo "usage: build.sh [release|asan|fuzz]"; exit 2 ;;
esac
cmake --build "$BUILD/$kind"
