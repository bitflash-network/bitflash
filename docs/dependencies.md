# Build Dependencies

Bitflash links consensus-adjacent cryptographic and proof-of-work code from
external repositories. Fresh builds must not follow upstream `master` silently:
a changed upstream branch can break reproducible builds or change behavior in
code that every node relies on.

The top-level `Makefile` pins source dependencies by full commit hash:

| dependency | repository | pinned commit |
|---|---|---|
| libsecp256k1 | https://github.com/bitcoin-core/secp256k1 | `7fecac74aed8e1fd9078380d67dd04663705c989` |
| RandomX | https://github.com/tevador/RandomX | `1e9d4b2df63fa6edf46b06789486e23c0fcaa55a` |

Vendored into `src/` as copied files, not fetched at build time:

| file | from | version | sha256 |
|---|---|---|---|
| `qrcodegen.hpp` | https://github.com/nayuki/QR-Code-generator (`cpp/`), MIT | `v1.8.0` | `b779c3b156cf7a57ce789d6fee4fc991ccc2913774d26c909d22bb8f26b2a793` |
| `qrcodegen.cpp` | same | `v1.8.0` | `1f3b3fcdac6954c32cf583ccd02ec9b5901f756a38c461acedc70be4a77d3757` |

The QR codes of payment links (`bip21.h`) in the wallet. Pure computation:
only the C++ standard library, no I/O. Kept byte for byte as released, so the
hashes above check it.

When updating either dependency, rebuild from a clean dependency directory and
run the full selftest suite before opening the PR. The PR should explain why the
dependency changed and whether the update can affect consensus, addresses,
signatures, proof-of-work validation, or mining.

Foreign-chain light-validation code is also vendored into `src/pow_vendor/`:

| dependency | repository / tag | pinned commit | licenses |
|---|---|---|---|
| DigiByte PoW primitives | https://github.com/DigiByte-Core/digibyte / `v8.22.2` | `cc529634484591e1ceb57b6168b93c3671e27335` | MIT (Core/sphlib/Odocrypt), CC0 (Keccak), Brian Gladman redistribution notice |
| Ravencoin KAWPOW / ethash | https://github.com/RavenProject/Ravencoin / `v4.6.1` | `7864c39c2bbc85eadcc36cdf5b789d5f551ede7d` | Apache-2.0 |

The complete source-path/SHA256 inventory is
[`src/pow_vendor/UPSTREAM.json`](../src/pow_vendor/UPSTREAM.json), with license
files beside the copies and documented SIMD signed-shift and unused seed-memo patches in
[the vendor README](../src/pow_vendor/README.md). No dependency is downloaded at
build time. Original C translation units are compiled as C99; the wrappers and
C++ copies compile as C++14 without `-fpermissive`. See [light-pow.md](light-pow.md)
for checkpoint scope, measurements, cache limits and integration requirements.
