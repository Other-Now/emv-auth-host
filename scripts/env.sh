# Sourced by the other scripts. Locally (WSL, no sudo) the SQLite headers are
# unpacked into ~/eah-deps by deps.sh; in CI they are apt-installed.
export SRC=${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
export BUILD=${BUILD:-$HOME/eah-build}
export RUN=${RUN:-$HOME/eah-run}
if [ -f "$HOME/eah-deps/root/usr/include/sqlite3.h" ]; then
  export EAH_DEPS_ROOT=$HOME/eah-deps/root
fi
# clang 20 from unpacked LLVM debs (for libFuzzer), else the system clang
if [ -x "$HOME/llvm20/root/usr/lib/llvm-20/bin/clang++" ]; then
  export CLANG=$HOME/llvm20/root/usr/lib/llvm-20/bin/clang
  export CLANGXX=$HOME/llvm20/root/usr/lib/llvm-20/bin/clang++
  export LD_LIBRARY_PATH=$HOME/llvm20/root/usr/lib/x86_64-linux-gnu:$HOME/llvm20/root/usr/lib/llvm-20/lib:${LD_LIBRARY_PATH:-}
else
  export CLANG=${CLANG:-clang} CLANGXX=${CLANGXX:-clang++}
fi
BIN=${BIN:-$BUILD/release}
