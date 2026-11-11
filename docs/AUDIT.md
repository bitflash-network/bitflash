# Auditing Bitflash

What checks the code, how to run each check yourself, and what the last full
run found. Everything here is free software or free for public repositories,
and none of it needs an account.

## Where each check runs

| when | what | where |
|---|---|---|
| every push and pull request | Linux and Windows self-test suites, Python tool regressions, short fuzz runs of six targets | `.github/workflows/ci.yml` |
| every pull request into `main` | CodeQL (C++, Python, workflows); ClusterFuzzLite, ten minutes on the code the change touches | `.github/workflows/codeql.yml`, `.github/workflows/cflite.yml` |
| every night (GitHub) | ClusterFuzzLite, one hour per sanitizer, corpus kept between runs | `.github/workflows/cflite.yml` |
| every Monday (GitHub) | CodeQL over `main` | `.github/workflows/codeql.yml` |
| before a release, or by hand | the full pass below: every tool, every sanitizer, three fuzzing engines | `scripts/audit/run-audit.sh` |
| by hand on GitHub (Actions, "Audit campaign") | every harness under every engine in parallel, up to 6 h a job, corpora kept between runs; coverage per harness; the self-tests under ASan+UBSan, TSan and Valgrind | `.github/workflows/audit-campaign.yml`, `scripts/audit/ci-fuzz.sh` |

CodeQL and ClusterFuzzLite report into the repository's **Security** tab
(code scanning alerts). The full pass writes to a directory of its own; read
`SUMMARY.txt` there first.

## The full pass

```bash
scripts/audit/run-audit.sh                  # every phase, in order
scripts/audit/run-audit.sh static asan      # some phases
OUT=/srv/audit FUZZ_SECS=7200 J=6 scripts/audit/run-audit.sh fuzz
```

It needs a Linux machine with the normal build dependencies (`make
deps-linux`) and the tools below. On Debian 13 all but four come from the
distribution:

```bash
apt-get install clang clang-tidy clang-tools cppcheck gitleaks afl++ valgrind \
    heaptrack ltrace strace llvm-19 lcov flawfinder diffoscope-minimal reprotest \
    iwyu strip-nondeterminism disorderfs faketime tcpdump python3-venv
```

The four that do not, each pinned and checked against its publisher's
checksum before it is installed:

| tool | how | why not Debian |
|---|---|---|
| honggfuzz | build tag `2.6` from https://github.com/google/honggfuzz (`make && make install`) | dropped from Debian 13 |
| Trivy | release tarball + `trivy_<v>_checksums.txt`, https://github.com/aquasecurity/trivy/releases | not packaged |
| OSV-Scanner | release binary + `osv-scanner_SHA256SUMS`, https://github.com/google/osv-scanner/releases | not packaged |
| Semgrep | `pip install semgrep==<v>` in a venv | not packaged |

Pick versions at least two weeks old: a compromised release is usually found
and pulled within days.

Nothing in the pass touches a real data directory. `HOME` points at a scratch
folder for the whole run, and the fuzz harnesses each make a private temporary
data directory before their first input (`src/fuzz_datadir.h`), so a machine
that also runs a node can run the audit.

## The tools

### Secrets and dependencies (`secrets`, `deps`)

- **Gitleaks** reads every commit for keys, tokens and passwords.
- **Trivy** (`trivy fs`) reads the tree for secrets, misconfigured container
  and infrastructure files, and manifests with known-vulnerable versions.
  `trivy rootfs` then lists advisories for the system libraries a Linux build
  links (OpenSSL, Berkeley DB, libsodium, SQLite, zlib, glibc, Tor) as
  installed on the auditing machine.
- **OSV** (`scripts/audit/osv-query.py`): the tree has no package manifest for
  scanners to read, so the commits it pins (libsecp256k1, RandomX, the vendored
  DigiByte and Ravencoin proof-of-work code) are sent to https://osv.dev one by
  one. Only public commit hashes leave the machine.

### Static analysis (`static`)

- **cppcheck**: undefined behaviour, out-of-bounds access, uninitialised
  members, misuse of the standard library.
- **flawfinder**: calls with a history (`system`, `strcpy`, `chmod` races,
  format strings); levels 4 and 5 only.
- **Semgrep**: the `p/c` and `p/secrets` rule packs.
- **clang-tidy**: `bugprone-*`, `cert-*` and `clang-analyzer-*` over the files
  that parse network or disk input, hold coins, or decide the chain.
- **Clang Static Analyzer** (`scan-build`): path-sensitive analysis of the
  whole node build (null dereferences, leaks, use after free, dead stores).
- **CodeQL** (on GitHub): data-flow queries, `security-extended` suite.

### Running the code under instruments (`asan`, `tsan`, `valgrind`, `heap`)

Every self-test that `make tests` runs, each in four builds:

- **AddressSanitizer + UndefinedBehaviorSanitizer + LeakSanitizer**: out-of-bounds
  and use-after-free accesses, integer overflow, misaligned and null access,
  leaks at exit.
- **ThreadSanitizer**: data races and lock-order inversions.
- **Valgrind memcheck**: the same class of memory errors on an uninstrumented
  build, including in the libraries the sanitizers cannot see into.
- **heaptrack**: peak memory and leaks of the heaviest self-tests.

A self-test passes only if it exits 0 *and* its log has no sanitizer report.

### Fuzzing (`fuzz`, and ClusterFuzzLite on GitHub)

Seven harnesses in `src/`:

| target | what it feeds |
|---|---|
| `fuzz-net-message` | raw bytes into the P2P receive buffer of a peer, through `ProcessMessages()` |
| `fuzz-script` | one script through the parser, the standard-form extractors and `EvalScript` |
| `fuzz-sigcheck` | signatures and keys into OpenSSL and libsecp256k1 side by side; any disagreement is a crash |
| `fuzz-light-pow` | headers and histories into the DigiByte and Ravencoin difficulty and proof-of-work checks |
| `fuzz-p2p-payload` | one message and its payload straight into `ProcessMessage()`, as from a peer past the version handshake: `block`, `tx`, `inv`, `getdata`, `getblocks`, the chat and P2Pool messages. The envelope checksum no fuzzer can forge is behind it, and a flag recomputes a block's merkle root. The node keeps its chain between inputs, and in this binary alone (`-DBITFLASH_FUZZ`, `fFuzzSkipPoW`) the RandomX comparison is skipped, so block acceptance, connection and reorganisation are reached; every other check runs as released |
| `fuzz-deserialize` | raw bytes into every record the node reads from a peer or from its own files, through the `CDataStream >>` the node uses: `CTransaction`, `CBlock` (full, header only, from disk), `CBlockLocator`, `CInv`, `CAddress`, `CMessageHeader`, the transaction parts, `CDiskBlockIndex`, `CTxIndex`, `CDiskTxPos`, `CMerkleTx`, `CWalletTx`, `CWalletMasterKey`, the P2Pool share, chat and marketplace records, and the length prefix on its own. Whatever reads must re-encode to bytes that read back to themselves, `GetSerializeSize` must match, and on every canonical type (all of the wire ones) the re-encoding must be the input byte for byte. Two differentials: a block's id against the hash of its first 80 bytes, and the light client's `btcswap::ParseTx` against the node's reader |
| `fuzz-decoders` | text into the decoders, each with its encoder where there is one: base58 and base58check, Bitflash key and script addresses (`AddressToHash160`, `DecodeAnyAddress`, which must agree), `.btf` names and onion endpoints, signed service descriptors (`VerifyDescriptor`), BIP39 phrases (checksum recomputed independently) and seeds, BIP32 derivation (path against step by step), payment links (`ParsePaymentLink`/`MakePaymentLink`), the three amount parsers against each other (`ParseMoney`, `ParseCoinAmount`, the payment link's), `ParseHex` and `uint256::SetHex`, the invoice webhook URL, cashaddr, and other chains' addresses (`btclight::Destination`) |

Each runs under **libFuzzer**, **AFL++** and **honggfuzz** in turn, all three
with AddressSanitizer and UndefinedBehaviorSanitizer. They share one corpus
per target: what one engine finds is minimised into the corpus
(`libFuzzer -merge=1`) before the next starts. Crashes land in
`crashes/<engine>-<target>-*`; replay one with `./<target> <file>`.

### Coverage (`cov`)

**llvm-cov** over the self-tests, and over each fuzz corpus replayed through a
coverage build. Low numbers point at the code no test reaches.

### Reproducible builds (`repro`)

**reprotest** builds the node twice, varying time, time zone, locale, umask,
environment and build path, and compares the binaries; on any difference
**diffoscope** shows where. Release builds have their own reproducibility
check (`docs/release-verification.md`).

## Not used, and why

| tool | reason |
|---|---|
| PVS-Studio, Snyk | need an account |
| MemorySanitizer | every library linked (OpenSSL, Berkeley DB, libsodium, SQLite, the C++ library) would have to be rebuilt with it; AddressSanitizer, Valgrind and the fuzzers cover the same bugs here |
| nmap, testssl.sh | the node speaks only through Tor onion services and has no TLS endpoint of its own to scan |
| tcpdump, tshark, scapy | installed for debugging; the P2P protocol is fuzzed at the parser instead of over a wire |
| Threat Dragon, threatspec | a threat model is a document, not a scan; the network's is spread over `docs/net-hardening.md`, `docs/tor.md` and `docs/rendezvous.md` |
| cosign, in-toto | come with signed reproducible release builds; releases are signed with the release key today (`docs/release-verification.md`) |
| bug bounty platforms | need an account and funds; reports go to the maintainers as described in the README |

## Last full run

November 2026, on `main` at `474ba27` plus this branch (Debian 13, 4 cores,
clang 19). Every finding below is fixed in the same pull request as this
document, or explained.

### Fixed

| found by | what | where |
|---|---|---|
| libFuzzer (`fuzz-net-message`), LeakSanitizer | A failed Berkeley DB open throws `DbException`; `CDB` only checked the return value, so the `Db` handle leaked and the file's use count stayed up for good, and `DBFlush` never closed that file again. The environment open had the same gap. | `db.cpp`, self-test `db-open-failure` |
| flawfinder | The RPC `.cookie` and the key dump were created with `fopen`, then `chmod`ed to 0600: in between, another local user could open them and keep reading. Now owner-only from the first byte, never through a symlink. | `util.cpp` `OpenPrivateFile`, self-test `private-file` |
| AddressSanitizer, ThreadSanitizer | The light clients' worker threads are detached; at exit the globals they read were destroyed under them (use after free, data races on `cs_socks5` and others). | `btclight.cpp` |
| ThreadSanitizer (same reports) | The Bitcoin light client started from argument parsing, so every self-test and one-shot command dialled Bitcoin peers and could write the light-client state of a node running from the same data directory. It starts with the node now. | `btcswap.cpp`, `main_gui.cpp` |
| ThreadSanitizer | Wallet loading took `cs_mapKeys` then `cs_mapWallet`; everything else takes them the other way (lock-order inversion, a potential deadlock). | `db.cpp` |
| UndefinedBehaviorSanitizer | Base64 decoding of the RPC `Authorization` header (and the client's encoding) shifted a signed `int` past its range. | `jsonrpc.cpp`, `rpcclient.cpp` |
| UndefinedBehaviorSanitizer | An out-of-range `MsgKind` was undefined; the enum has a fixed type now. | `btfchat.h` |
| Clang Static Analyzer | `delete` on memory from `new[]`. | `util.cpp` |
| CodeQL | `db.log` created without a mode; third-party actions referenced by tag. | `db.cpp`, workflows |
| (the audit itself) | `db.log` was written to the process's working directory. A fuzz harness on a machine running a node opened `~/.bitflash`. | `db.cpp`, `src/fuzz_datadir.h` |
| clang 19 | A conditional over two Boost expression-template types did not compile. | `btclight.cpp` |
| Trivy | The release packages carried Tor 0.4.9.11; 0.4.9.14 fixed high-severity client and onion-service bugs. Now Tor Expert Bundle 16.0 (tor 0.4.9.15). | release workflow, `scripts/` |

After the fixes: AddressSanitizer + UndefinedBehaviorSanitizer report nothing
in the self-tests that had a report, and ThreadSanitizer reports nothing in
any of the 52 node self-tests (Berkeley DB's own latches suppressed,
`scripts/audit/tsan.supp`).

### Checked and not a defect

- **Gitleaks**, 8 hits: the release key's public fingerprint in
  `scripts/verify-release.sh`, test vectors in
  `tests/fixtures/chain-tools/fair-launch-report.json`, and a line of
  `main.cpp` in an old commit that holds no secret.
- **OSV**: no advisory for any pinned commit (libsecp256k1, RandomX, the
  DigiByte and Ravencoin code). **Trivy** on the tree: nothing to report
  (no manifests, containers or secrets).
- **cppcheck** (23 "errors"): `(&x)[1]`-style end pointers (the `BEGIN`/`END`
  macros), an end iterator read after a size check (`base58.h`), two
  different structs both named `PastBlock`, a deliberate `memset` before a
  placement new in a self-test, `back()` behind a `? :` guard, and two files
  it cannot parse.
- **Clang Static Analyzer** (39 after the fix above): dead stores, and
  "stream in EOF state" on the usual read-until-EOF loop; `recv` inside a lock is
  always after `poll` said data is waiting; a division whose divisor is a
  sum of positive work values.
- **clang-tidy** (203): mostly unchecked `fclose`/`fwrite` results;
  `atoi` on strings already checked to be digits; widening casts of values
  bounded by the protocol.
- **flawfinder** (48, level 4 and 5): format functions with constant formats
  (the build fails on a format mismatch, `-Werror=format`), `system()` with
  an id that is 32 hex characters, `chmod` on the Tor data directory right
  after `mkdir` with mode 0700, `readlink` on `/proc`.
- **Semgrep** (`p/c`, `p/secrets`): nothing.
- **Linked system libraries** on the auditing host: everything with a
  published fix was updated (OpenSSL 3.5.7, zlib, SQLite, Tor 0.4.9.15); what
  remains has no fix yet in Debian.

- **CodeQL** on this branch: the alerts that pointed at real problems are in
  the table above. Three `cpp/path-injection` alerts were dismissed: the data
  directory comes from the operator's own `-datadir` or `HOME`, and the key
  dump path from an RPC caller who is already authenticated and controls the
  wallet; both files are now created owner-only, never through a symlink.

### Fuzzing

One hour per target per engine, twelve hours in all, with AddressSanitizer
and UndefinedBehaviorSanitizer. The corpus column is the shared corpus after
each engine finished and it was minimised.

| target | libFuzzer | AFL++ | honggfuzz | crashes |
|---|---|---|---|---|
| `fuzz-script` | 6444 | 6446 | 6446 | 0 |
| `fuzz-net-message` | 7745 | 7809 | 7811 | 1, the `Db` leak fixed above |
| `fuzz-sigcheck` | 52 | 52 | 53 | 0 |
| `fuzz-light-pow` | 318 | 318 | 318 | 0 |

The second and third engines added almost nothing, so for these harnesses the
corpus has stopped growing; more hours on the same harnesses buy little. The
leak no longer reproduces on the fixed build.

### Coverage

| what | lines covered |
|---|---|
| all self-tests, whole node | 55.0% (43.9% of regions) |
| `fuzz-script` corpus, `script.cpp` | 51.9% |
| `fuzz-sigcheck` corpus, `sigcheck.cpp` / `key.h` | 46.4% / 54.7% |
| `fuzz-light-pow` corpus, `dgb_pow.cpp` / `rvn_kawpow.cpp` | 80.6% / 58.6% |
| `fuzz-net-message` corpus, `ProcessMessages` / `ProcessMessage` | 89.3% / 57.7% |

**Gap:** under `fuzz-net-message`, `ProcessBlock`, `CheckBlock` and
`AlreadyHave` were never reached. Every P2P message carries a double SHA-256
checksum of its payload, which no fuzzer can forge, so almost every input stops
at the envelope; the handlers for `block`, `tx` and `inv` were not fuzzed. A
second harness that hands payloads to `ProcessMessage` directly, after the
version handshake, closes this and comes in its own pull request.

### Valgrind, heaptrack, reproducible build

- **Valgrind memcheck**, first pass: 14 of 65 self-tests reported. Twelve
  were Berkeley DB writing the unused bytes of its pages and log records to
  disk (suppressed with that reason, `scripts/audit/valgrind.supp`; the
  library's own `--enable-umrw` exists for exactly this). Two were the light
  client's worker threads reading freed globals at exit, fixed above. After
  both: **65 self-tests, 0 reports**.
- **heaptrack**: the heaviest self-tests peak at 41.5 MB (explorer), 9.5 MB
  (P2Pool chain), under 0.5 MB for the rest; each holds a few kilobytes at
  exit in one-time allocations, and neither LeakSanitizer nor Valgrind reports
  a definite leak.
- **reprotest**: the first attempt never built the varied copy (`disorderfs`
  and `faketime` were missing, now checked before the phase starts). With
  them: the node built twice, under a different time, time zone, locale,
  umask, environment, build path and directory order, is **bit for bit
  identical**.

### Final state

On the last commit of this branch, every self-test (65) under
AddressSanitizer + UndefinedBehaviorSanitizer + LeakSanitizer, under
ThreadSanitizer and under Valgrind: **0 failures, 0 reports**. The Windows
suite passes as well.

## Deserializers and decoders (`fuzz-deserialize`, `fuzz-decoders`)

November 2026, on `main` at `fa5b5db`. The two harnesses were first run
against the code as it was, then against the fixes below.

### What they found

| found by | what | where |
|---|---|---|
| `fuzz-deserialize`, within seconds, on most types | `ReadCompactSize` took any width for a length (5 as `fd 05 00`, `fe 05 00 00 00`, ...) and every caller kept the 64-bit result in an `unsigned int`, so a nine-byte length with any of its high 32 bits set read as its low half. The object read was the same either way -- ids, merkle roots and the disk copy all come from re-encoding it, and every release writes the shortest form -- but one transaction had many encodings on the wire. Now only the shortest form is read, and nothing above `MAX_SIZE` (Bitcoin made the same change in 0.9). Which blocks and transactions are valid is unchanged: the shortest encoding of each reads exactly as before, and a longer spelling, which no node writes, is refused as a malformed message. | `serialize.h`, self-test `serialize-canonical` |
| (the question the first finding raised: what does a node do with the bytes as they arrived?) | A `tx` message was relayed, and held if it was an orphan, as the whole payload, including any bytes after the transaction, which the reader leaves unread: what a node held per orphan and served per relayed transaction was bounded by the message size, not by the transaction's (which `IsStandard` limits). It now holds and relays the transaction re-encoded. | `main.cpp`, self-test `serialize-canonical` |
| `fuzz-deserialize`, UndefinedBehaviorSanitizer | `CDataStream` built from an empty `vector<unsigned char>` dereferenced its null `begin()`; `HexStr` did the same on an empty range. | `serialize.h`, `util.h` |
| `fuzz-decoders`, UndefinedBehaviorSanitizer, within seconds | `uint256::SetHex` indexed its digit table with a plain `char`: any byte from 0x80 up (an explorer search, a txid argument) read up to 128 bytes before the table. | `uint256.h`, self-test `decoder-canonical` |
| `fuzz-decoders` | `NormalizeOnionEndpoint` kept a port's leading zeros, so `:080` and `:80` were two normal forms of one endpoint. | `btfaddr.cpp`, self-test `decoder-canonical` |
| the round-trip check written for `fuzz-decoders` (`.btf` names) | A version-1 `.btf` name is 34 bytes in 55 base32 characters; the last character's low three bits are padding, which the decoder dropped whatever they were, so each key answered to eight names. Only the encoder's, with those bits zero, is the address now. | `btfaddr.cpp`, self-test `decoder-canonical` |
| the hex check written for `fuzz-decoders` (descriptors) | A service descriptor's key and signatures were read with `sscanf("%2x")`, which also takes white space, a sign and `0x`. Plain hex digits only now. | `btfaddr.cpp`, self-test `decoder-canonical` |
| review while writing `fuzz-decoders` | `EncodeBase58` of an empty vector indexed it; `DecodeBase58` and `ParseMoney` passed a possibly negative `char` to `isspace`/`isdigit`. | `base58.h`, `util.cpp` |
| honggfuzz (`fuzz-decoders`, on GitHub), through a payment link | The `std::string` overloads of `DecodeBase58`, `DecodeBase58Check`, `AddressToHash160`, `DecodeAnyAddress` and `IsValidBitcoinAddress` handed `c_str()` on, so an address followed by a NUL and anything else read as the address while the caller kept, and could show, the whole string. They refuse a NUL now. | `base58.h`, self-test `decoder-canonical` |
| independent review of the length-prefix change | The light client's saved state holds foreign blocks and pending transactions as the bytes that arrived; one that no longer reads under the stricter reader made the state load throw, and swaps in that coin could not start until the file was removed. A saved entry that does not read is now dropped with a line in the log (blocks are a cache the filter scan fetches again). | `btclight.cpp`, self-test `btc-light` |

### Not canonical, by design

The harness checks that every input a type accepts re-encodes to exactly
the bytes read. These types are exempt, and why:

- `CWalletTx`, `CReview`, `CProduct` and any other record holding a `map`:
  the reader takes keys in any order and keeps the first of a duplicate.
  Wallet records are only ever written by the node; the marketplace
  messages are relayed as received on purpose (0.1.0 design).
- `CTxIndex`, `CDiskBlockIndex`, `CBlockLocator`, `CAddress` on disk and
  `CUser` start with a version the reader puts in the stream, not the
  object; written back with that version, they are canonical.
- Base32 in general drops partial bits at the end (only a `.btf` name is
  checked for them); `uint256::SetHex` takes `0x`, white space, short and
  long strings; `ParsePaymentLink` carries the address as written and leaves
  checking it to the wallet; `ParseMoney` takes `,` thousands separators,
  white space, and reads an empty string or `.` as zero (every caller that
  needs a positive amount checks for one). The three amount parsers agree
  wherever two of them accept.

The node has no parser for BIP32 extended keys (xprv/xpub) or for
derivation paths written as text; keys come from a seed and a path of
numbers, which `fuzz-decoders` exercises.

### Runs and coverage

Before the fixes, two minutes of libFuzzer per harness reproduced every
finding above that names a harness (62 crash files for `fuzz-deserialize`,
every one the length prefix, on 13 entries; 30 for `fuzz-decoders`: 28 the
`SetHex` index, one the onion port, one a harness artefact, fixed). After the fixes, 20 minutes of libFuzzer per
harness with AddressSanitizer + UndefinedBehaviorSanitizer (Debian 13,
clang 19), no crash, leak or sanitizer report:

| target | executions | corpus | crashes |
|---|---|---|---|
| `fuzz-deserialize` | 2.1 M | 2647 | 0 |
| `fuzz-decoders` | 1.65 M | 3335 | 0 |

Line coverage of the corpora replayed through a coverage build:

| what | lines covered |
|---|---|
| `Unserialize` of every type in the table above (each `IMPLEMENT_SERIALIZE`) | 100% |
| `ReadCompactSize`, `CDataStream::read`, string/vector/map readers | 100%, 100%, 93-100% |
| `btcswap::ParseTxAt` / `ParseTx` / `ParseBlockTxs` / `ParseAuxPow` | 98.3% / 100% / 100% / 100% |
| `DecodeBase58` / `EncodeBase58` / `DecodeBase58Check` | 97.1% / 96.0% / 100% |
| `AddressToHash160` / `DecodeAnyAddress` | 83.3% / 83.3% (the misses: a checksum-valid payload of the wrong length) |
| `btf::ParseAddressVersion` / `Base32Decode` / `NormalizeOnionEndpoint` / `VerifyDescriptor` | 100% each |
| `BIP39ValidateMnemonic` / `BIP39EntropyToMnemonic` | 100% / 85.7% |
| `BIP32DeriveChild` / `BIP32MasterFromSeed` | 76.8% / 64.3% (the misses: keys at or above the curve order, odds 2^-127, and OpenSSL failures) |
| `ParsePaymentLink` / `MakePaymentLink` / its amount parser | 100% each |
| `ParseMoney` / `ParseCoinAmount` / `ParseHex` | 97.6% / 100% / 100% |
| `uint256::SetHex`, `uint160::SetHex` | 100% |
| `btcswap::CashDecode` / `CashEncode` / `btclight::Destination` | 96.3% / 100% / 89.7% |
| `invoice::ParseHttpUrl` | 100% |

On GitHub ("Audit campaign", 20 minutes per harness per engine, corpora
kept): libFuzzer, AFL++ and honggfuzz on both harnesses. The first round
found the NUL in a string address above (honggfuzz, `fuzz-decoders`); the
other five jobs found nothing, and the campaign's own coverage of the
corpora matched the table above (`serialize.h` 61.4%, `base58.h` 94.2%,
`btfaddr.cpp` 85.9%, `bip32.cpp` 77.3%, `bip21.cpp` 100%, whole files).
