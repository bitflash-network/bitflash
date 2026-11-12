#!/bin/bash
# Full audit pass over a Bitflash checkout, on Linux. docs/AUDIT.md explains
# each tool, what it looks for and how to read what it finds.
#
#   scripts/audit/run-audit.sh [PHASE...]
#
# Phases, in the order they run when none is named:
#   secrets  gitleaks over the whole history, trivy over the tree
#   deps     osv-scanner (known vulnerabilities in what the tree pins or vendors)
#   static   cppcheck, flawfinder, semgrep, clang-tidy, Clang Static Analyzer
#   asan     every self-test, built with AddressSanitizer + UndefinedBehaviorSanitizer
#            (LeakSanitizer included)
#   tsan     every self-test, built with ThreadSanitizer
#   valgrind memcheck over the self-tests that do not need a sanitizer runtime
#   heap     heaptrack over the heaviest self-tests (peak memory, leaks)
#   fuzz     every fuzz target ($TARGETS) under libFuzzer, AFL++ and honggfuzz, one
#            corpus per target shared by the three engines
#   cov      line coverage of the self-tests and of every fuzz corpus (llvm-cov)
#   repro    reprotest: build twice under different time, locale, umask and
#            path, then diffoscope on any difference
#
# Environment (all optional):
#   OUT=/path         results (default: ./audit-out); SUMMARY.txt is the file to read first
#   CORPUS=/path      fuzz corpora, kept between runs (default: $OUT/../audit-corpus)
#   FUZZ_SECS=3600    seconds per target per engine
#   J=3               parallel jobs
#   RANDOMX_DIR=...   as for the normal build
#
# Nothing here touches a real data directory: HOME points at a scratch folder
# for the whole run, so every binary that would open ~/.bitflash opens an
# empty one under $OUT/home instead.
set -u
SRC=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$PWD/audit-out}
CORPUS=${CORPUS:-$(dirname "$OUT")/audit-corpus}
FUZZ_SECS=${FUZZ_SECS:-3600}
J=${J:-3}
RANDOMX_DIR=${RANDOMX_DIR:-$HOME/RandomX}
BUILD=$OUT/build
SUM=$OUT/SUMMARY.txt
TARGETS="fuzz-script fuzz-net-message fuzz-sigcheck fuzz-light-pow fuzz-p2p-payload fuzz-deserialize fuzz-decoders fuzz-v4-templates fuzz-p2pool fuzz-light-peer fuzz-tor-control fuzz-socks5 fuzz-rpc-preauth fuzz-rpc-postauth fuzz-http-client fuzz-chat-frame fuzz-chat-relay fuzz-nostr fuzz-swap"
# Harnesses that write a structured starting corpus of their own
# (BITFLASH_FUZZ_WRITE_SEEDS); the rest start from one byte.
SELF_SEEDING="fuzz-p2p-payload fuzz-deserialize fuzz-decoders fuzz-script fuzz-v4-templates fuzz-p2pool fuzz-light-peer fuzz-tor-control fuzz-socks5 fuzz-rpc-preauth fuzz-rpc-postauth fuzz-http-client fuzz-chat-frame fuzz-chat-relay fuzz-nostr fuzz-swap"

mkdir -p "$OUT" "$BUILD" "$CORPUS" "$OUT/crashes"
export HOME=$OUT/home
mkdir -p "$HOME"
# To stderr as well as the summary: functions whose stdout is captured call it too.
say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$SUM" >&2; }
have() { command -v "$1" > /dev/null 2>&1; }

# A copy of the tree per instrumented build, so builds never share objects.
tree() {
    rm -rf "$BUILD/$1"
    mkdir -p "$BUILD/$1"
    (cd "$SRC" && git archive --format=tar HEAD) | tar -x -C "$BUILD/$1"
    echo "$BUILD/$1/src"
}

# The self-test commands `make tests` runs, one per line.
selftest_cmds() { make -s -n -C "$1" tests RANDOMX_DIR="$RANDOMX_DIR" 2>/dev/null | grep '^\./'; }

# Builds the self-test binaries in $1 with clang and the flags $2, then runs every
# self-test with the prefix $3 (a wrapper such as valgrind, or nothing).
# Each self-test gets its own log; one failing does not stop the rest.
run_selftests() {
    dir=$1; flags=$2; wrap=$3; tag=$4
    (cd "$dir" && make -j "$J" CXX="clang++ $flags" CC="clang $flags" RANDOMX_DIR="$RANDOMX_DIR" \
        bitflash-node btfchat $(selftest_cmds "$dir" | sed -n 's|^\./\(test_[a-z0-9_]*\)$|\1|p' | sort -u) \
        > "$OUT/$tag-build.log" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then say "$tag build FAILED (exit $rc), see $tag-build.log"; return; fi
    mkdir -p "$OUT/$tag"
    fails=0; n=0
    while read -r cmd; do
        n=$((n + 1))
        name=$(echo "$cmd" | sed 's|^\./||; s|bitflash-node -selftest=||')
        (cd "$dir" && timeout 3600 $wrap $cmd) > "$OUT/$tag/$name.log" 2>&1
        r=$?
        if [ $r -ne 0 ] || grep -q 'ERROR: \(Address\|Leak\|Thread\)Sanitizer\|runtime error:\|WARNING: ThreadSanitizer\|ERROR SUMMARY: [1-9]' "$OUT/$tag/$name.log"; then
            fails=$((fails + 1))
            echo "$name exit=$r" >> "$OUT/$tag/FAILED.txt"
        fi
    done < <(selftest_cmds "$dir")
    say "$tag: $n self-tests, $fails with a failure or a sanitizer report (list: $tag/FAILED.txt)"
}

phase_secrets() {
    if have gitleaks; then
        gitleaks detect --source "$SRC" --redact --no-banner --report-format json \
            --report-path "$OUT/gitleaks.json" > "$OUT/gitleaks.log" 2>&1
        say "gitleaks exit=$? findings=$(grep -c '"RuleID"' "$OUT/gitleaks.json" 2>/dev/null)"
    fi
    if have trivy; then
        trivy fs --quiet --scanners vuln,secret,misconfig --format table \
            --skip-dirs src/imgui --output "$OUT/trivy.txt" "$SRC" > "$OUT/trivy.log" 2>&1
        say "trivy exit=$? $(grep -c 'Total:' "$OUT/trivy.txt" 2>/dev/null) report section(s), see trivy.txt"
    fi
}

phase_deps() {
    # The tree has no package manifest, so osv-scanner's own source scan finds
    # nothing to read; the pinned commits are asked about one by one instead.
    python3 -I "$SRC/scripts/audit/osv-query.py" "$SRC" > "$OUT/osv.txt" 2>&1
    say "osv (pinned commits) exit=$? (0 = nothing known), see osv.txt"
    # The system libraries a Linux build links, as installed on this host.
    if have trivy; then
        trivy rootfs --quiet --scanners vuln --pkg-types os --format json --output "$OUT/trivy-host.json" / > "$OUT/trivy-host.log" 2>&1
        python3 -I -c '
import json, sys
LINKED = ("libssl", "openssl", "libdb5.3", "libsodium", "libsqlite3", "libglfw", "tor", "libc6", "libstdc++", "zlib")
r = json.load(open(sys.argv[1]))
for res in r.get("Results", []):
    for v in res.get("Vulnerabilities", []) or []:
        if v["PkgName"].startswith(LINKED):
            print("%-22s %-14s %-9s %s fixed:%s" % (v["PkgName"], v["VulnerabilityID"], v.get("Severity", "?"), v["InstalledVersion"], v.get("FixedVersion", "-")))
' "$OUT/trivy-host.json" | sort -u > "$OUT/trivy-host.txt" 2>/dev/null
        say "trivy, linked system libraries on this host: $(wc -l < "$OUT/trivy-host.txt") advisories, see trivy-host.txt"
    fi
}

phase_static() {
    cd "$SRC/src" || return
    if have cppcheck; then
        timeout 3h cppcheck -j "$J" --enable=warning,portability --std=c++14 --max-configs=3 --quiet \
            --suppress=missingIncludeSystem -i imgui -i pow_vendor -i mlkem -i json \
            --template='{file}:{line}: [{severity}/{id}] {message}' . 2> "$OUT/cppcheck.txt"
        say "cppcheck exit=$? lines=$(wc -l < "$OUT/cppcheck.txt") errors=$(grep -c '\[error/' "$OUT/cppcheck.txt")"
    fi
    if have flawfinder; then
        # Our own files only: the vendored trees are the subdirectories.
        flawfinder --minlevel=4 --columns --context --quiet --dataonly ./*.cpp ./*.c ./*.h > "$OUT/flawfinder.txt" 2>&1
        say "flawfinder (level 4-5) hits=$(grep -c '^\./[^:]*:[0-9]*:' "$OUT/flawfinder.txt")"
    fi
    if have semgrep; then
        semgrep scan --metrics=off --quiet --config p/c --config p/secrets \
            --exclude imgui --exclude pow_vendor --exclude mlkem --exclude json \
            --json --output "$OUT/semgrep.json" . > "$OUT/semgrep.log" 2>&1
        rc=$?
        python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1]))["results"]; [print("%s:%d: [%s] %s" % (x["path"], x["start"]["line"], x["check_id"].split(".")[-1], x["extra"]["message"].splitlines()[0])) for x in r]' \
            "$OUT/semgrep.json" > "$OUT/semgrep.txt" 2>/dev/null
        say "semgrep exit=$rc findings=$(wc -l < "$OUT/semgrep.txt")"
    fi
    if have clang-tidy; then
        # The files that parse network or disk input, hold coins, or decide the chain.
        CORE="main.cpp net.cpp db.cpp script.cpp util.cpp rpc.cpp jsonrpc.cpp p2pool.cpp btclight.cpp btcswap.cpp tor.cpp nostr.cpp"
        CHECKS='-*,bugprone-*,cert-*,clang-analyzer-*,-bugprone-easily-swappable-parameters,-bugprone-narrowing-conversions,-bugprone-implicit-widening-of-multiplication-result,-cert-err58-cpp,-cert-dcl21-cpp,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-bugprone-macro-parentheses'
        : > "$OUT/clang-tidy.txt"
        for f in $CORE; do
            timeout 1h clang-tidy --quiet --checks="$CHECKS" "$f" -- -x c++ -std=gnu++14 -fpermissive \
                -DSECP256K1_STATIC -DBITFLASH_NODE_BUILD -DBITFLASH_NO_GUI -I/usr/local/include \
                -I"$RANDOMX_DIR/src" -I/usr/include/nlohmann -Iimgui >> "$OUT/clang-tidy.txt" 2>/dev/null
        done
        say "clang-tidy warnings=$(grep -c 'warning:' "$OUT/clang-tidy.txt") on: $CORE"
    fi
    if have scan-build; then
        d=$(tree scan-build)
        (cd "$d" && timeout 6h scan-build -o "$OUT/scan-build" make -j "$J" RANDOMX_DIR="$RANDOMX_DIR" bitflash-node) \
            > "$OUT/scan-build.log" 2>&1
        say "scan-build exit=$? $(grep -a 'bugs found\|No bugs found' "$OUT/scan-build.log" | tail -1)"
    fi
}

phase_asan() {
    d=$(tree asan)
    export ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:halt_on_error=0
    export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0
    run_selftests "$d" "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" "" asan
    unset ASAN_OPTIONS UBSAN_OPTIONS
}

phase_tsan() {
    d=$(tree tsan)
    export TSAN_OPTIONS="halt_on_error=0:second_deadlock_stack=1:suppressions=$SRC/scripts/audit/tsan.supp"
    run_selftests "$d" "-fsanitize=thread -g -O1" "" tsan
    unset TSAN_OPTIONS
}

phase_valgrind() {
    have valgrind || return
    d=$(tree valgrind)
    run_selftests "$d" "-g -O1" "valgrind --quiet --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --suppressions=$SRC/scripts/audit/valgrind.supp" valgrind
}

phase_heap() {
    have heaptrack || return
    d=$(tree heap)
    (cd "$d" && make -j "$J" RANDOMX_DIR="$RANDOMX_DIR" CXX="g++ -g" bitflash-node > "$OUT/heap-build.log" 2>&1) || { say "heap build FAILED"; return; }
    mkdir -p "$OUT/heap"
    for t in p2pool-chain btc-light rules-v4 explorer; do
        (cd "$OUT/heap" && heaptrack -o "$OUT/heap/$t" "$d/bitflash-node" -selftest=$t > "$OUT/heap/$t.run.log" 2>&1)
        heaptrack_print -f "$OUT/heap/$t".zst 2>/dev/null | grep -E '^(peak heap memory|total memory leaked|calls to allocation)' > "$OUT/heap/$t.txt"
        say "heaptrack $t: $(tr '\n' ';' < "$OUT/heap/$t.txt")"
    done
}

# Compiler wrapper and flag set per fuzzing engine. The harnesses only define
# LLVMFuzzerTestOneInput, which all three engines drive.
fuzz_build() {
    engine=$1
    d=$(tree "fuzz-$engine")
    case $engine in
        libfuzzer) fcxx=clang++;               flags="-fsanitize=fuzzer-no-link,address,undefined"; lflags="-fsanitize=fuzzer,address,undefined" ;;
        afl)       fcxx=afl-clang-fast++;      flags="-fsanitize=fuzzer-no-link,address,undefined"; lflags="-fsanitize=fuzzer,address,undefined" ;;
        hfuzz)     fcxx=hfuzz-clang++;         flags="-fsanitize=address,undefined";                lflags="-fsanitize=fuzzer,address,undefined" ;;
        cov)       fcxx=clang++;               flags="-fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"; lflags="-fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping" ;;
    esac
    for t in $TARGETS; do
        (cd "$d" && make -j "$J" RANDOMX_DIR="$RANDOMX_DIR" FUZZ_CXX="$fcxx" \
            FUZZ_CXXFLAGS="\$(filter-out -O2,\$(CXXFLAGS)) -O1 -g -fno-omit-frame-pointer $flags" \
            FUZZ_LDFLAGS="$lflags" "$t") > "$OUT/fuzz-build-$engine-$t.log" 2>&1
        rc=$?
        [ $rc -eq 0 ] || say "fuzz build $engine $t FAILED (exit $rc)"
    done
    echo "$d"
}

fuzz_seed() {
    t=$1
    mkdir -p "$CORPUS/$t"
    [ -n "$(ls -A "$CORPUS/$t")" ] || printf '\000' > "$CORPUS/$t/seed0"
}

fuzz_one() {
    engine=$1; d=$2; t=$3
    bin=$d/$t
    [ -x "$bin" ] || return
    w=$OUT/fuzz-work/$engine-$t
    rm -rf "$w"; mkdir -p "$w"
    case $engine in
        libfuzzer)
            (cd "$w" && "$bin" -max_total_time="$FUZZ_SECS" -timeout=20 -rss_limit_mb=4096 \
                -print_final_stats=1 -artifact_prefix="$OUT/crashes/libfuzzer-$t-" "$CORPUS/$t") > "$OUT/fuzz-libfuzzer-$t.log" 2>&1 ;;
        afl)
            (cd "$w" && AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
                timeout $((FUZZ_SECS + 300)) afl-fuzz -V "$FUZZ_SECS" -t 20000 -m none \
                -i "$CORPUS/$t" -o "$w/out" -- "$bin") > "$OUT/fuzz-afl-$t.log" 2>&1
            for c in "$w"/out/default/crashes/id*; do [ -f "$c" ] && cp "$c" "$OUT/crashes/afl-$t-$(basename "$c" | tr ',:' '__')"; done ;;
        hfuzz)
            (cd "$w" && honggfuzz --run_time "$FUZZ_SECS" --timeout 20 --rlimit_rss 4096 --threads 1 \
                --input "$CORPUS/$t" --output "$w/new" --crashdir "$w/crashes" --quiet -- "$bin") > "$OUT/fuzz-hfuzz-$t.log" 2>&1
            for c in "$w"/crashes/*; do [ -f "$c" ] && cp "$c" "$OUT/crashes/hfuzz-$t-$(basename "$c" | cut -c1-80)"; done ;;
    esac
}

phase_fuzz() {
    mkdir -p "$OUT/fuzz-work"
    for t in $TARGETS; do fuzz_seed "$t"; done
    LF=$(fuzz_build libfuzzer)
    # Some harnesses write structured seeds of their own: the payload one
    # (a block on genesis, a transaction, inv, ...), the deserializer one
    # (every type), the decoder one (a sample of every format), fuzz-script
    # (signed spends under each rule set) and fuzz-v4-templates (vault,
    # batch, inheritance), fuzz-p2pool (a line of shares) and fuzz-light-peer
    # (header chains with blocks), and the Tor, SOCKS5, RPC and HTTP client
    # ones (Tor replies, RPC calls, ...), and the chat, Nostr and swap ones. They join the corpus without
    # replacing anything.
    for t in $SELF_SEEDING; do
        [ -x "$LF/$t" ] || continue
        sd=$OUT/fuzz-seeds/$t
        rm -rf "$sd"; mkdir -p "$sd"
        if (cd "$OUT" && BITFLASH_FUZZ_WRITE_SEEDS="$sd" "$LF/$t" -runs=0 > "$OUT/fuzz-seeds-$t.log" 2>&1); then
            cp -n "$sd"/* "$CORPUS/$t/" 2>/dev/null || true
        else
            say "fuzz seeds for $t FAILED, see fuzz-seeds-$t.log"
        fi
    done
    have afl-clang-fast++ && AF=$(fuzz_build afl) || AF=""
    have hfuzz-clang++ && HF=$(fuzz_build hfuzz) || HF=""
    for engine in libfuzzer afl hfuzz; do
        case $engine in libfuzzer) d=$LF ;; afl) d=$AF ;; hfuzz) d=$HF ;; esac
        [ -n "$d" ] || continue
        n=0
        for t in $TARGETS; do
            fuzz_one "$engine" "$d" "$t" &
            n=$((n + 1)); if [ $n -ge "$J" ]; then wait; n=0; fi
        done
        wait
        # Fold what this engine found back into the shared corpus, minimised
        # by libFuzzer, so the next engine starts from it.
        for t in $TARGETS; do
            extra=""
            [ -d "$OUT/fuzz-work/$engine-$t/out/default/queue" ] && extra="$OUT/fuzz-work/$engine-$t/out/default/queue"
            [ -d "$OUT/fuzz-work/$engine-$t/new" ] && extra="$OUT/fuzz-work/$engine-$t/new"
            if [ -n "$extra" ] && [ -x "$LF/$t" ]; then
                (cd "$OUT/fuzz-work" && "$LF/$t" -merge=1 -timeout=20 -rss_limit_mb=4096 "$CORPUS/$t" "$extra") > "$OUT/fuzz-merge-$engine-$t.log" 2>&1
            fi
            say "fuzz $engine $t: corpus=$(ls "$CORPUS/$t" | wc -l) crashes=$(ls "$OUT/crashes" | grep -c "^$engine-$t-")"
        done
    done
}

phase_cov() {
    have llvm-profdata-19 && PD=llvm-profdata-19 || PD=llvm-profdata
    have llvm-cov-19 && LC=llvm-cov-19 || LC=llvm-cov
    d=$(tree cov)
    export LLVM_PROFILE_FILE="$OUT/cov-raw/selftest-%p.profraw"
    mkdir -p "$OUT/cov-raw"
    run_selftests "$d" "-fprofile-instr-generate -fcoverage-mapping -O0" "" cov-selftests
    unset LLVM_PROFILE_FILE
    $PD merge -sparse "$OUT"/cov-raw/selftest-*.profraw -o "$OUT/cov-selftests.profdata"
    $LC report "$d/bitflash-node" -instr-profile="$OUT/cov-selftests.profdata" \
        -ignore-filename-regex='imgui|pow_vendor|mlkem|json|/usr/' > "$OUT/cov-selftests.txt" 2>&1
    say "coverage, self-tests: $(tail -1 "$OUT/cov-selftests.txt" | awk '{print "regions " $4 ", lines " $10}')"
    FC=$(fuzz_build cov)
    for t in $TARGETS; do
        [ -x "$FC/$t" ] || continue
        (cd "$OUT" && LLVM_PROFILE_FILE="$OUT/cov-raw/$t-%p.profraw" \
            "$FC/$t" -runs=0 -timeout=20 -rss_limit_mb=4096 "$CORPUS/$t") > "$OUT/cov-$t.log" 2>&1
        $PD merge -sparse "$OUT"/cov-raw/$t-*.profraw -o "$OUT/cov-$t.profdata"
        $LC report "$FC/$t" -instr-profile="$OUT/cov-$t.profdata" \
            -ignore-filename-regex='imgui|pow_vendor|mlkem|json|/usr/|fuzz_' > "$OUT/cov-$t.txt" 2>&1
        say "coverage, $t corpus: $(tail -1 "$OUT/cov-$t.txt" | awk '{print "regions " $4 ", lines " $10}')"
    done
}

phase_repro() {
    have reprotest || return
    # Without these the varied build fails to start (exit 127) and nothing is
    # compared at all.
    for t in disorderfs faketime; do
        have "$t" || { say "repro skipped: $t is not installed"; return; }
    done
    d=$(tree repro)
    cd "$BUILD/repro" || return
    # Kernel, host name and user cannot vary without a VM or root namespaces
    # here; everything else that commonly breaks reproducibility does.
    timeout 4h reprotest --verbosity 1 --store-dir="$OUT/repro" \
        --variations=+all,-kernel,-domain_host,-user_group,-num_cpus,-exec_path \
        "make -C src -j $J RANDOMX_DIR=$RANDOMX_DIR bitflash-node" 'src/bitflash-node' > "$OUT/repro.log" 2>&1
    rc=$?
    say "reprotest exit=$rc ($( [ $rc -eq 0 ] && echo 'identical' || echo 'differences, diffoscope output in repro/'))"
}

PHASES=${*:-secrets deps static asan tsan valgrind heap fuzz cov repro}
echo "audit of $(cd "$SRC" && git rev-parse --short HEAD), phases: $PHASES, started $(date -u)" >> "$SUM"
for p in $PHASES; do
    say "--- $p"
    "phase_$p"
done
say "DONE"
