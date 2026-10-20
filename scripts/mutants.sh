#!/usr/bin/env bash
# Does the regression suite actually catch regressions? Plant one bug at a
# time in a scratch copy of the source, rebuild, run unit + golden tests.
# A mutant "survives" if both still pass.
set -uo pipefail
. "$(dirname "$0")/env.sh"
WORK=$HOME/eah-mutants
OUT=$SRC/results/${1:-local}
mkdir -p "$OUT"

# name | file | sed expression
MUTANTS=(
  "skip duplicate detection|src/auth.cpp|s/if (auth_by_key_.step()) {/if (false \&\& auth_by_key_.step()) {/"
  "no ATC replay check|src/auth.cpp|s/if (atc <= last_atc) return/if (false) return/"
  "ARQC compare ignores last byte|src/auth.cpp|s/ct_equal(expect.data(), arqc.data(), 8)/ct_equal(expect.data(), arqc.data(), 7)/"
  "skip DE4 vs 9F02 check|src/auth.cpp|s/!= field(m, 4)) return finish/!= field(m, 4) \&\& false) return finish/"
  "reversal credits twice|src/auth.cpp|s/reason = \"ALREADY_REVERSED\";/reason = \"ALREADY_REVERSED\"; credit_.bind(1, amount).bind(2, account); credit_.step(); credit_.reset();/"
  "limit check off by one|src/auth.cpp|s/if (amount > limit)/if (amount > limit + 1)/"
  "Luhn not checked|src/auth.cpp|s/if (!luhn_valid(pan)) return/if (false) return/"
  "expiry check inverted boundary|src/auth.cpp|s/if (expiry < cfg_.today_yymm)/if (expiry < \"2401\")/"
  "TLV accepts duplicate tags|c/tlv.c|s/if (items\[i\].tag == tag) return TLV_E_DUP;/(void)0;/"
  "LLVAR max not enforced in decode (EQUIVALENT)|c/iso8583.c|s/if (flen > s->max) return ISO_E_LENGTH;//"
  "variable-length max not enforced anywhere|c/iso8583.c|s/len != s->max : len > s->max/len != s->max : 0/"
  "session key uses wrong ATC byte order|src/emv_crypto.cpp|s/Block rl{static_cast<uint8_t>(atc >> 8), static_cast<uint8_t>(atc)/Block rl{static_cast<uint8_t>(atc), static_cast<uint8_t>(atc >> 8)/"
  "never answer 0800|src/auth.cpp|s/r.f\[39\] = iso_has(\&m, 70) ? \"00\" : \"30\";/r.f[39] = \"30\";/"
)

killed=0; total=0; equiv=0
: > "$OUT/mutants.txt"
for m in "${MUTANTS[@]}"; do
  IFS='|' read -r name file expr <<<"$m"
  total=$((total + 1))
  rm -rf "$WORK/src" && mkdir -p "$WORK" && cp -r "$SRC" "$WORK/src"
  sed -i "$expr" "$WORK/src/$file"
  if cmp -s "$SRC/$file" "$WORK/src/$file"; then
    echo "MUTANT DID NOT APPLY: $name" | tee -a "$OUT/mutants.txt"; continue
  fi
  cmake -S "$WORK/src" -B "$WORK/build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEAH_DEPS_ROOT="${EAH_DEPS_ROOT:-}" >/dev/null
  if ! cmake --build "$WORK/build" >/dev/null 2>&1; then
    echo "MUTANT DID NOT BUILD: $name" | tee -a "$OUT/mutants.txt"; continue
  fi
  unit=pass; golden=pass
  "$WORK/build/unit_tests" >/dev/null 2>&1 || unit=FAIL
  SRC=$SRC BIN=$WORK/build PORT=18599 RUN=$WORK/run bash "$SRC/scripts/regress.sh" >/dev/null 2>&1 || golden=FAIL
  if [ $unit = FAIL ] || [ $golden = FAIL ]; then verdict=killed; killed=$((killed + 1));
  elif [[ $name == *EQUIVALENT* ]]; then verdict="survived (equivalent: check_value() re-checks the same bound)"; equiv=$((equiv + 1));
  else verdict=SURVIVED; fi
  printf '%-46s unit=%-4s golden=%-4s %s\n' "$name" $unit $golden "$verdict" | tee -a "$OUT/mutants.txt"
done
echo "mutants: $killed/$total killed, $equiv equivalent, $((total - killed - equiv)) survived" | tee -a "$OUT/mutants.txt"
[ $((killed + equiv)) -eq $total ]
