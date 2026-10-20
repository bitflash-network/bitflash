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
