# Additional proof-module validation

The native Linux checks use a minimal Debian 13 userspace and Linux
6.12.107+deb13-amd64 under QEMU 11.1.0 TCG on this Windows host. CPU instructions
are emulated: this is execution in a real Linux kernel/userspace, not a native
Windows run or merely cross-compiling objects. These VM timings are not comparable
to the Windows hardware measurements in [light-pow.md](light-pow.md).

The standalone targets link the production proof objects, the original self-test
bodies and OpenSSL. They require no wallet, database, RandomX or secp256k1 library.
This validation covers the two modules; it does not establish a native build of
the complete bitflash-node executable or the complete Linux wallet test suite.
No native macOS execution is claimed.

## Reproduce the module checks on Linux

With GCC, Clang with compiler-rt/libFuzzer, Boost headers and OpenSSL headers/library:

```sh
make -C src -j2 CXX=g++ CC=gcc test_light_pow
./src/test_light_pow
make -C src -j2 FUZZ_CXX=clang++ test-light-pow-sanitize fuzz-light-pow
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./src/test-light-pow-sanitize
```

`test_light_pow.cpp` includes the same `test_light_pow.h` assertions as the
wallet's RunSelfTest dispatcher. All new C++ units and drivers compile without
`-fpermissive`; upstream C units remain C99. Sanitized objects use the existing
fuzz directory and `-fsanitize=fuzzer-no-link,address,undefined` flags. The fuzz
executable additionally links the libFuzzer main/runtime.

Generate eight real proof seeds directly from the committed offline fixtures:

```sh
python3 - <<'PY'
from pathlib import Path
import re
text = Path('src/test_light_pow_vectors.h').read_text()
rows = re.findall(r'\{(\d+), "[a-f0-9]{64}",\s*"([a-f0-9]+)"', text)
root = Path('work/light-pow-corpus')
root.mkdir(parents=True, exist_ok=True)
seen = set()
for height, hexdata in rows:
    height, raw = int(height), bytes.fromhex(hexdata)
    if len(raw) == 80 and height >= 24000000:
        algo = (int.from_bytes(raw[:4], 'little') >> 8) & 15
        epoch = int.from_bytes(raw[68:72], 'little') // 864000 if algo == 14 else 0
        key, kind = ('dgb', algo, epoch), 0
    elif len(raw) == 120 and height >= 4507490:
        key, kind = ('rvn', height // 7500), 1
    else:
        continue
    if key not in seen:
        (root / f'{kind}-{height}').write_bytes(bytes([kind]) + raw)
        seen.add(key)
assert len(seen) == 8
PY
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ./src/fuzz-light-pow work/light-pow-corpus -seed=20261029 -runs=5000 \
  -max_len=128 -timeout=600 -rss_limit_mb=1024 -max_total_time=300
```

The first byte selects the chain. The target checks raw header parsing, algorithm
hashing, full proof validation, compact targets, bounded synthetic retarget/work
histories and the two-cache resource invariant. Corpus seeds cover all five DGB
algorithms, two Odo keys and two RVN epochs. Synthetic histories deliberately
include invalid heights/algorithms/bits and extreme timing spans. Fuzzing is a
bounded bug search, not a proof that no defect remains.

## Independent DGB chainwork comparison

DigiScope's public `/api/explorer/status` advertised a mainnet Core
`/DigiByte:9.26.7/`. Its `/api/explorer/block/{height}` endpoint exposes Core-style
getblock data including chainwork, pow_algo and pow_hash. This was an independent
node comparison through the service's HTTP explorer proxy, not an authenticated
local JSON-RPC session.

Responses for heights 23,999,999--24,000,099 were saved with their source URLs and
capture time in [light-pow-dgb-core-check.json](light-pow-dgb-core-check.json).
For each of the 100 tested candidate heights, the block ID, previous ID and PoW
digest match the fixture, and

```
Core.chainwork(height) - Core.chainwork(height - 1) == fixture.work(height)
```

All 100 differences match exactly, spanning SHA256d, Scrypt, Skein, Qubit and
Odocrypt. The C++ offline test in turn compares the module's BlockProof output
with each fixture value. No offline self-test or wallet function contacts this service.

## Recorded results (2026-10-29)

- Native GCC 14.2.0-19: both offline self-tests PASS, 101 DGB proofs/100
  consecutive retargets and work values, and 32 RVN proofs/32 DGW values.
- Native Clang 19.1.7-3+b1 with ASan/UBSan and leak detection: both self-tests
  PASS, including two real RVN epochs and the third-epoch eviction/false-mix cases.
  No sanitizer error or leak was reported; the guest command returned zero.
- libFuzzer + ASan/UBSan: eight initial real seeds, seed 20261029, requested
  ceiling 5,000 runs and 300 seconds. The time ceiling ended the run at **144
  executions in 301 seconds**, 6,551 coverage edges / 12,457 features, corpus
  grown to 25 inputs, peak reported RSS 248 MiB. No crash or sanitizer error.
  The expensive RVN cold caches under CPU emulation consume much of this budget;
  this is a short smoke run, not an extended fuzz campaign or 5,000 completed runs.
- Independent advertised Core 9.26.7 through DigiScope's public HTTP proxy:
  all 100 consecutive work deltas and proof digests match, across all five algos.

The first real make-driven native sanitizer build exposed a missing `-c` in the
vendored C fuzz recipe. Both makefiles now compile those sources into objects.
The PoW implementation and vendored algorithm bytes are unchanged by this follow-up.
Native execution of the complete Linux wallet and any macOS execution remain
unverified. Host/VM setup scripts, full logs and binaries remain under `work/` and
are not shipped in the source commit.
