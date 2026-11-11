#!/bin/bash -eu
# ClusterFuzzLite / OSS-Fuzz build: the five fuzz targets with the engine and
# sanitizer flags the builder passes in $CXXFLAGS and $LIB_FUZZING_ENGINE.
cd "$SRC/bitflash/src"

# The builder asks for libc++, but Berkeley DB's C++ library and Boost come
# from the distribution, built against libstdc++. Address and undefined
# behaviour sanitizers do not need libc++ (only MemorySanitizer would).
CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"

make -j"$(nproc)" RANDOMX_DIR="$HOME/RandomX" FUZZ_CXX="$CXX" \
    FUZZ_CXXFLAGS="\$(filter-out -O2,\$(CXXFLAGS)) $CXXFLAGS -g" \
    FUZZ_LDFLAGS="$CXXFLAGS $LIB_FUZZING_ENGINE" \
    fuzz-script fuzz-net-message fuzz-sigcheck fuzz-light-pow fuzz-p2p-payload

# The runner image has none of the shared libraries the node links, so they
# travel with the targets and are found through $ORIGIN.
mkdir -p "$OUT/lib"
for t in fuzz-script fuzz-net-message fuzz-sigcheck fuzz-light-pow fuzz-p2p-payload; do
    cp "$t" "$OUT/"
    ldd "$t" | awk '/=> \// {print $3}' | grep -E 'libdb|libsqlite3|libsodium|libssl|libcrypto|libboost' | while read -r lib; do
        cp -L -n "$lib" "$OUT/lib/" || true
    done
    patchelf --set-rpath '$ORIGIN/lib' "$OUT/$t"
done

# Seeds: the same starting inputs the smoke targets use.
mk_seed() { t=$1; shift; d=$(mktemp -d); i=0; for s in "$@"; do printf "$s" > "$d/seed$i"; i=$((i + 1)); done; (cd "$d" && zip -q "$OUT/${t}_seed_corpus.zip" seed*); rm -rf "$d"; }
mk_seed fuzz-net-message '\277\040\134\375ping\000\000\000\000\000\000\000\000\000\000\000\000' '\277\040\134\375version\000\000\000\000\000\000\000\000\000'
mk_seed fuzz-script '\000\121' '\000\115\377\377'
mk_seed fuzz-sigcheck '\000\000\001\001' '\030\001\040\001'

# fuzz-p2p-payload writes its own seeds (a block on genesis, a transaction,
# inv, getdata, ...). Built for the fuzzing engine, it runs here as well.
d=$(mktemp -d)
if BITFLASH_FUZZ_WRITE_SEEDS="$d" ./fuzz-p2p-payload -runs=0 > /dev/null 2>&1 && [ -n "$(ls -A "$d")" ]; then
    (cd "$d" && zip -q "$OUT/fuzz-p2p-payload_seed_corpus.zip" ./*)
fi
rm -rf "$d"
