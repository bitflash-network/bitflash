#!/bin/bash
# One fuzz target under one engine, for the audit-campaign workflow (and for
# anyone who wants a single long run). The full local pass is run-audit.sh;
# this is the same build and the same engine settings, one pair at a time,
# so many runners can fuzz in parallel.
#
#   scripts/audit/ci-fuzz.sh <libfuzzer|afl|hfuzz> <target>
#
# Environment (all optional):
#   FUZZ_SECS=3600   how long to fuzz
#   CORPUS=/path     corpus directory for this target (default ./fuzz-out/corpus/<target>)
#   OUT=/path        crashes and logs (default ./fuzz-out)
#   RANDOMX_DIR=...  as for the normal build
#   J=$(nproc)       build jobs
#
# Exit status: 0 when the run finished, whatever it found; crashes are files in
# $OUT/crashes and the caller decides what to do with them.

set -u
engine=${1:?engine: libfuzzer, afl or hfuzz}
t=${2:?target, e.g. fuzz-p2p-payload}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$SRC/fuzz-out}
CORPUS=${CORPUS:-$OUT/corpus/$t}
FUZZ_SECS=${FUZZ_SECS:-3600}
RANDOMX_DIR=${RANDOMX_DIR:-$HOME/RandomX}
J=${J:-$(nproc)}
mkdir -p "$OUT/crashes" "$CORPUS"
OUT=$(cd "$OUT" && pwd)
CORPUS=$(cd "$CORPUS" && pwd)
# The harnesses make private data directories under TMPDIR; nothing here may
# reach the runner's real home.
export HOME="$OUT/home"
mkdir -p "$HOME"

case $engine in
    libfuzzer) fcxx=clang++;          flags="-fsanitize=fuzzer-no-link,address,undefined"; lflags="-fsanitize=fuzzer,address,undefined" ;;
    afl)       fcxx=afl-clang-fast++; flags="-fsanitize=fuzzer-no-link,address,undefined"; lflags="-fsanitize=fuzzer,address,undefined" ;;
    hfuzz)     fcxx=hfuzz-clang++;    flags="-fsanitize=address,undefined";                lflags="-fsanitize=fuzzer,address,undefined" ;;
    *) echo "unknown engine $engine" >&2; exit 2 ;;
esac

cd "$SRC/src"
if ! make -j "$J" RANDOMX_DIR="$RANDOMX_DIR" FUZZ_CXX="$fcxx" \
        FUZZ_CXXFLAGS="\$(filter-out -O2,\$(CXXFLAGS)) -O1 -g -fno-omit-frame-pointer $flags" \
        FUZZ_LDFLAGS="$lflags" "$t" > "$OUT/build-$engine-$t.log" 2>&1; then
    tail -40 "$OUT/build-$engine-$t.log" >&2
    echo "build of $t for $engine failed" >&2
    exit 1
fi
bin=$SRC/src/$t

# An empty corpus gets a starting point: the payload, deserializer, decoder,
# script and v4-templates harnesses write structured seeds of their own, the
# others start from one byte.
if [ -z "$(ls -A "$CORPUS")" ]; then
    if [ "$t" = fuzz-p2p-payload ] || [ "$t" = fuzz-deserialize ] || [ "$t" = fuzz-decoders ] ||
       [ "$t" = fuzz-script ] || [ "$t" = fuzz-v4-templates ]; then
        BITFLASH_FUZZ_WRITE_SEEDS="$CORPUS" "$bin" -runs=0 > "$OUT/seeds-$t.log" 2>&1 || true
    fi
    [ -n "$(ls -A "$CORPUS")" ] || printf '\000' > "$CORPUS/seed0"
fi

w=$OUT/work-$engine-$t
rm -rf "$w"; mkdir -p "$w"
log=$OUT/fuzz-$engine-$t.log
echo "fuzzing $t with $engine for $FUZZ_SECS s, corpus $(ls "$CORPUS" | wc -l) inputs"
case $engine in
    libfuzzer)
        # One worker per core; a crash is saved and the run goes on. Fork
        # mode keeps each worker's log in a temporary directory it deletes,
        # so a finding's stack is lost: FUZZ_FORK=0 runs one process that
        # stops at the first finding and prints its full report here.
        if [ "${FUZZ_FORK:-1}" = 0 ]; then
            (cd "$w" && "$bin" -max_total_time="$FUZZ_SECS" -timeout=20 -rss_limit_mb=4096 \
                -print_final_stats=1 -artifact_prefix="$OUT/crashes/libfuzzer-$t-" "$CORPUS") > "$log" 2>&1
        else
            (cd "$w" && "$bin" -fork="$(nproc)" -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
                -max_total_time="$FUZZ_SECS" -timeout=20 -rss_limit_mb=4096 \
                -print_final_stats=1 -artifact_prefix="$OUT/crashes/libfuzzer-$t-" "$CORPUS") > "$log" 2>&1
        fi ;;
    afl)
        # A main instance and one secondary per remaining core, sharing $w/out.
        export AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_AFFINITY=1
        n=$(nproc)
        for i in $(seq 2 "$n"); do
            (cd "$w" && timeout $((FUZZ_SECS + 300)) afl-fuzz -S "s$i" -V "$FUZZ_SECS" -t 20000 -m none \
                -i "$CORPUS" -o "$w/out" -- "$bin") > "$OUT/fuzz-afl-s$i-$t.log" 2>&1 &
        done
        (cd "$w" && timeout $((FUZZ_SECS + 300)) afl-fuzz -M main -V "$FUZZ_SECS" -t 20000 -m none \
            -i "$CORPUS" -o "$w/out" -- "$bin") > "$log" 2>&1
        wait
        for c in "$w"/out/*/crashes/id*; do [ -f "$c" ] && cp "$c" "$OUT/crashes/afl-$t-$(basename "$(dirname "$(dirname "$c")")")-$(basename "$c" | tr ',:' '__')"; done
        for q in "$w"/out/*/queue/id*; do [ -f "$q" ] && cp "$q" "$CORPUS/afl-$(sha1sum "$q" | cut -c1-40)"; done ;;
    hfuzz)
        (cd "$w" && honggfuzz --run_time "$FUZZ_SECS" --timeout 20 --rlimit_rss 4096 --threads "$(nproc)" \
            --input "$CORPUS" --output "$w/new" --crashdir "$w/crashes" --quiet -- "$bin") > "$log" 2>&1
        for c in "$w"/crashes/*; do [ -f "$c" ] && cp "$c" "$OUT/crashes/hfuzz-$t-$(basename "$c" | cut -c1-80)"; done
        for q in "$w"/new/*; do [ -f "$q" ] && cp "$q" "$CORPUS/hfuzz-$(sha1sum "$q" | cut -c1-40)"; done ;;
esac
tail -25 "$log"
n=$(ls "$OUT/crashes" | wc -l)
echo "done: corpus $(ls "$CORPUS" | wc -l) inputs, $n crash file(s)"
exit 0
