# Foreign-chain PoW provenance

Pinned source archives (no build-time downloads):

- DigiByte-Core/digibyte tag **v8.22.2**, commit
  `cc529634484591e1ceb57b6168b93c3671e27335`.
- RavenProject/Ravencoin tag **v4.6.1**, commit
  `7864c39c2bbc85eadcc36cdf5b789d5f551ede7d`.

`UPSTREAM.json` records every upstream path, local path and SHA256. The 40 source
and header copies occupy about 440 KiB. The original C files retain `.c` and
compile as C99. DigiByte's `aes_helper.cpp` is included by its hash sources;
it is not a separate translation unit. Ravencoin's `managed.cpp` (global locking
cache) is deliberately omitted. The wrappers use a bounded two-entry memo.

Two local patches: in ethash.cpp, the unused `find_epoch_number` convenience
function uses the original stateless seed search without its thread-local memo.
This keeps the wrapper epoch-context memo as the only mutable shared state.
The proof/cache paths never call this convenience function.

The portability patch: in DigiByte `simd.cpp`'s FFT16 macro, 14 left shifts
of potentially negative coefficients are replaced by multiplication by the same
power of two. The documented FFT8/FFT16 bounds fit signed 32 bits, so the products
are defined and identical to the intended arithmetic. This fixes a UBSan trap
in the real Qubit vectors without disabling any sanitizer. The manifest retains
both upstream and patched SHA256 for both patched files. All other copied bytes match
upstream. `SPH_UNALIGNED=0` selects portable byte loads, and `-fno-strict-aliasing`
retains the upstream hash code's aliasing assumptions.

## Rule sources (paths relative to the pinned repository)

DigiByte Core v8.22.2:

| File | Rules used |
|---|---|
| `src/primitives/block.h`, `src/primitives/block.cpp` | 80-byte layout, algorithm bits, block ID versus PoW, Odo key |
| `src/chainparams.cpp` | mainnet PoW limit, 10-day Odo interval, V4 timing/clamps/4% local adjustment |
| `src/pow.cpp` | GetNextWorkRequiredV4, last same-algorithm parent, compact target validation |
| `src/chain.cpp` | current GetBlockProof geometric target and scale 128 |
| `src/arith_uint256.cpp` | SetCompact/GetCompact and ApproxNthRoot(5) |
| `src/validation.cpp` | active post-Odo algorithm set |
| `src/crypto/scrypt.cpp` | N=1024, r=p=1, header as password/salt; wrapper uses existing OpenSSL |
| `src/crypto/hashskein.h` | Skein512 followed by single SHA256 |
| `src/crypto/hashqubit.h` | five 512-bit hash stages and first-256-bit result |
| `src/crypto/hashodo.h` | encryption, delimiter and Keccak-p[800]/12-round ordering |

Ravencoin v4.6.1:

| File | Rules used |
|---|---|
| `src/primitives/block.h`, `src/primitives/block.cpp` | 120-byte serialization, CKAWPOWInput, block ID |
| `src/hash.cpp` | KAWPOWHash/KAWPOWHash_OnlyMix and byte order conversions |
| `src/chainparams.cpp` | mainnet limit, spacing, KAWPOW activation time |
| `src/pow.cpp` | DGW's 180-parent recurrence, transition, timespan clamps |
| `src/chain.cpp`, `src/arith_uint256.cpp` | chainwork and compact arithmetic |
| `src/crypto/ethash/include/ethash/progpow.hpp` | revision 0.9.4, period 3, lanes/registers/cache/math sizes |
| `src/crypto/ethash/include/ethash/ethash.h` | epoch length 7500 and context API |
| `src/crypto/ethash/lib/ethash/ethash.cpp` | light cache sizing, prime adjustment, seed/dataset generation |
| `src/crypto/ethash/lib/ethash/progpow.cpp` | KAWPOW mixing/verification and final hash |

The manifest enumerates every additional hash implementation/header and supporting
file actually copied. The wrapper comments cite the named tags at the constants.

## Licenses

DigiByte copies retain all notices. `dgb/LICENSE.DigiByte` is upstream COPYING,
`dgb/LICENSE.sphlib` retains the MIT grant, `dgb/LICENSE.Keccak` retains the CC0
public-domain dedication, and `dgb/LICENSE.brg_endian` retains Brian Gladman's
notice/redistribution conditions. Ravencoin's ethash source copyright notices
specify Apache-2.0; `rvn/LICENSE` contains its full license text. There is no
additional system library dependency: Scrypt/SHA256 use the existing OpenSSL.
