# Foreign-chain header proof modules

These are mainnet proof/difficulty helpers for a future light-client adapter.
They perform no I/O, networking or synchronization and do not change Bitflash
consensus, swaps or the existing Bitcoin light client. Hash/work byte arrays are
little endian; `DisplayHash` returns the conventional reversed hexadecimal form.

## Supported checkpoints and caller contract

| Chain | First supported height | Mainnet block ID |
|---|---:|---|
| DigiByte | 24,000,000 | `82fa126e82a287b121ba57b7d008624750b0d456e398746e9c0e8fe6f760eb72` |
| Ravencoin | 4,507,490 | `00000000000649b59adeddc9ed2e6be67d3c26482b29c175a51adf8779f3e419` |

DigiByte's anchor (2026-08-09 UTC) is well after Odocrypt and DigiSpeed activation.
Ravencoin's anchor (2026-08-24 UTC) is well after the 180-block KAWPOW transition,
and ten blocks before an epoch boundary, allowing compact real cross-epoch tests.
These heights delimit implemented rules; the helpers do not authenticate an
anchor themselves. The adapter must pin these hashes and authenticated parent
context before accepting descendants. Confirm both anchors independently during
integration, and recheck the upstream rules before the planned mainnet launch.

DigiByte parses exactly 80 bytes, rejects retired/unknown algorithm bits, and
checks SHA256d, Scrypt(1024,1,1), Skein512/SHA256, Qubit and timestamp-keyed
Odocrypt/Keccak-p[800]. Block IDs are SHA256d for every algorithm. MultiShield V4
uses 50-parent median-time intervals, damping, clamps and local algorithm
adjustment. Work uses Core's approximate fifth root of every active next target,
multiplies the roots and scales the inverse by 128. Historical fixed per-algorithm
multipliers and an exact mathematical fifth root would give different work.

For DigiByte difficulty/work, pass oldest-first consecutive parents from one
validated branch: at least 61, plus the latest parent of each active algorithm
if older. Missing context fails closed. The fixture supplies 100 context parents.
`BlockProof` also checks the candidate's actual height and expected difficulty;
call `CheckProofOfWork` separately before accepting its returned work.

Ravencoin parses exactly 120 bytes: embedded height, 64-bit nonce and mix hash.
The first 80 bytes are SHA256d-hashed and converted using Core's byte order.
KAWPOW verifies both the final target and the recomputed light mix; the cheap
`BlockHash` function alone is insufficient. DGW uses the newest 180 parents and
Core's weighted integer recurrence, a 179-gap observed span and a 180-minute
target span. Work is the usual inverse compact target without algorithm weights.

For Ravencoin, compare `NextWorkRequired` with the candidate's bits, require its
embedded height to equal its parent's height plus one, then check its full proof
before adding `BlockProof`. Both adapters must additionally validate chain links,
median/future-time rules, applicable header versions and cumulative-work branch
selection. Metadata passed as history must already belong to that branch.

Only Ravencoin's two-entry light-cache memo is mutable shared state. A single
owning worker must serialize verification and cache helper calls. Caches are
LRU-evicted **before** allocation; there is no full DAG, disk persistence or lock.
Each cache has a 128 MiB resource ceiling, including the 16 KiB L1 and context.
At epochs 600/601 they total 191,003,136 bytes (about 182.16 MiB). Epochs whose
cache estimate exceeds the ceiling return a resource error; this is a local
budget, not a consensus rejection, and will need review as the chain grows.

## Offline vectors and measurements

`src/test_light_pow_vectors.h` includes complete real P2P mainnet headers and a
height/block-ID comment for every vector. Tests never contact a network:

- DigiByte: 23,999,900--24,000,099 (100 context + 100 checked headers), plus
  24,033,741 for the next Odocrypt key. All five algorithms pass, all 101 nonce
  flips fail, all 100 consecutive difficulty/work values match. Epoch keys are
  1,785,888,000 and 1,786,752,000 seconds, including exact-boundary checks.
- Ravencoin: 4,507,310--4,507,521 (180 context + 32 checked headers) across epochs
  600/601. Every checked mix/proof, nonce/mix mutation and DGW value is tested.
  Two explicitly synthetic candidates meet their supplied final targets but have
  false mixes; both fail full verification. The second also exercises eviction
  while accessing a third epoch (602), retaining at most two caches.
- Both tests reject malformed sizes/compact targets and incomplete/gapped
  histories. DigiByte additionally checks retired algorithms and wrong work height.

Headers were collected from chain peers, with anchor/header fields cross-checked
against [DigiByte Explorer](https://digiexplorer.info/block/82fa126e82a287b121ba57b7d008624750b0d456e398746e9c0e8fe6f760eb72)
and [Ravencoin Explorer's block API](https://api.ravencoinexplorer.com/api/v1/block/4507490).
DigiByte's anchor was also checked using chainz's height-to-hash API; the next Odo
header and RVN height 4,507,500 were independently checked. Expected retarget/work
values were generated with an independent integer reference transcribed from the
pinned Core sources. RVN work at 4,507,490 additionally matches the explorer's
chainwork delta from 4,507,489. A subsequent independent Core 9.26.7 comparison through DigiScope's public
HTTP explorer proxy confirmed all 100 consecutive DGB chainwork deltas and proof
digests, covering all five algorithms. The captured responses and exact scope are
in [the validation report](light-pow-validation.md) and
[Core comparison data](light-pow-dgb-core-check.json).

On this Windows machine (Intel Core i7-8700 @ 3.20 GHz, 2 exposed logical CPUs),
UCRT64 GCC 16.1.0, `-O2`, the final-source wallet self-tests measured **PoW only**:

| Proof | Mean cost/header |
|---|---:|
| DGB SHA256d | 1.58 us |
| DGB Scrypt | 305.57 us |
| DGB Skein | 1.86 us |
| DGB Qubit | 16.34 us |
| DGB Odocrypt | 51.25 us |
| RVN KAWPOW, ready cache (30 headers) | 14.07 ms |
| RVN KAWPOW, new epoch cache (2 headers) | 3,457.67 ms |

Each self-test prints its own timings; CPU contention and instrumentation change
these numbers substantially. Cache generation is synchronous on the owning worker.
Parsing, difficulty, chainwork and test output are excluded from these timings.

## Sources, build and limits

Rules are pinned to DigiByte Core **v8.22.2**, commit
`cc529634484591e1ceb57b6168b93c3671e27335`, and Ravencoin **v4.6.1**, commit
`7864c39c2bbc85eadcc36cdf5b789d5f551ede7d`. Every rule source and vendored file
is listed in [the vendor provenance](../src/pow_vendor/README.md) and the
[file/SHA256 manifest](../src/pow_vendor/UPSTREAM.json). Licenses are beside the
copies; [dependencies.md](dependencies.md) records both dependencies.

Both makefiles register `dgb-pow` and `rvn-kawpow` in `tests`. New C++ sources
are compiled as C++14 without `-fpermissive`; original C units stay C99.
Use `make -f makefile.mingw -j2 tests` on MSYS2 UCRT64, or `make -C src tests`
on Linux. The self-test bodies are shared with a standalone diagnostic driver
so strict/sanitized builds need no wallet/database dependencies.

Verification includes the Windows wallet suite, native execution of both module
self-tests in a real Linux VM with GCC 14.2 and Clang 19.1, ASan/UBSan with leak
detection, and a five-minute libFuzzer/ASan/UBSan smoke run (144 executions under
CPU emulation). The makefile provides `test_light_pow`, `test-light-pow-sanitize`
and `fuzz-light-pow` targets. See [light-pow-validation.md](light-pow-validation.md)
for exact commands, outcomes and the independent DGB Core comparison. This does
not establish a native build/run of the complete Linux wallet or any macOS
execution. The UCRT64 Clang distribution still lacks a usable Windows ASan/fuzzer
runtime; the sanitizer runtime executions were performed on Linux.

Earlier DigiByte algorithms/retarget regimes, X16R/X16RV2, other networks,
transaction/block validity, filters, peer discovery, networking, reorg storage,
wallet integration and swap execution are outside this change. Future consensus
changes require an explicit source/rule update; these helpers are not a promise
to accept future forks without review.
