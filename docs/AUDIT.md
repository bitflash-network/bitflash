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

The harnesses in `src/` (the full list is `TARGETS` in
`scripts/audit/run-audit.sh`):

| target | what it feeds |
|---|---|
| `fuzz-net-message` | raw bytes into the P2P receive buffer of a peer, through `ProcessMessages()` |
| `fuzz-script` | one script through the parser, the standard-form extractors, the sigop counts and `EvalScript`; then a spend: a fuzzed transaction (version, lock time, sequences, outputs) with scriptSig and scriptPubKey or redeem script, valid ECDSA and BIP340 signatures, keys and CTV hashes put in by placeholder, through `EvalScript`, `VerifyScriptP2SH` and `VerifySignature` under all eight combinations of rules v2, v3 and v4, under every rule with v5, and with the pool's relay policy. Aborts when v4 turns a pass into a failure or changes an answer with no v4 opcode in the script, when v3, strict signatures, v5 or the policy change an answer they cannot affect (or v5 or the policy let through what the rules alone refuse), when CLTV and `IsFinalAt` disagree, when `VerifySignature` disagrees with the path it delegates to, when the CTV hash misses a field it commits to or covers one it must not, or when a spend starts more signature checks than the block and the pool charge for it (a counter compiled only with `-DBITFLASH_FUZZ`) |
| `fuzz-v4-templates` | the vault, CTV batch and inheritance scripts built from fuzzed parameters by the wallet's own builders (`v4templates.h`) and spent as the RPCs spend them, through `VerifySignature`. Aborts when a vault or batch output can leave other than by its template, when the template rebuilt from the contracts file differs, when the honest spend fails or passes before v4, when the hot key or the heir passes outside the timelock or is refused inside it, when any other key or a scriptSig without the right key passes, when a third party's added pushes break a spend, or when `ParseInheritScript` accepts anything but an inheritance script |
| `fuzz-sigcheck` | signatures and keys into OpenSSL and libsecp256k1 side by side; any disagreement is a crash |
| `fuzz-light-pow` | headers and histories into the DigiByte and Ravencoin difficulty and proof-of-work checks |
| `fuzz-p2p-payload` | one message and its payload straight into `ProcessMessage()`, as from a peer past the version handshake: `block`, `tx`, `inv`, `getdata`, `getblocks`, the chat and P2Pool messages. The envelope checksum no fuzzer can forge is behind it, and a flag recomputes a block's merkle root. The node keeps its chain between inputs, and in this binary alone (`-DBITFLASH_FUZZ`, `fFuzzSkipPoW`) the RandomX comparison is skipped, so block acceptance, connection and reorganisation are reached; every other check runs as released |
| `fuzz-deserialize` | raw bytes into every record the node reads from a peer or from its own files, through the `CDataStream >>` the node uses: `CTransaction`, `CBlock` (full, header only, from disk), `CBlockLocator`, `CInv`, `CAddress`, `CMessageHeader`, the transaction parts, `CDiskBlockIndex`, `CTxIndex`, `CDiskTxPos`, `CMerkleTx`, `CWalletTx`, `CWalletMasterKey`, the P2Pool share, chat and marketplace records, and the length prefix on its own. Whatever reads must re-encode to bytes that read back to themselves, `GetSerializeSize` must match, and on every canonical type (all of the wire ones) the re-encoding must be the input byte for byte. Two differentials: a block's id against the hash of its first 80 bytes, and the light client's `btcswap::ParseTx` against the node's reader |
| `fuzz-decoders` | text into the decoders, each with its encoder where there is one: base58 and base58check, Bitflash key and script addresses (`AddressToHash160`, `DecodeAnyAddress`, which must agree), `.btf` names and onion endpoints, signed service descriptors (`VerifyDescriptor`), BIP39 phrases (checksum recomputed independently) and seeds, BIP32 derivation (path against step by step), payment links (`ParsePaymentLink`/`MakePaymentLink`), the three amount parsers against each other (`ParseMoney`, `ParseCoinAmount`, the payment link's), `ParseHex` and `uint256::SetHex`, the invoice webhook URL, cashaddr, and other chains' addresses (`btclight::Destination`) |
| `fuzz-p2pool` | every P2Pool message (`p2pshare`, `p2ppeers`, `p2pgetsh`, `p2psync`, `p2pshares`) through `P2PoolProcessMessage()` from an inbound or dialled peer, proven or not, with reconnects and history asks, and raw shares through the share chain's acceptance (`P2PoolSubmitShare`, `ShareChain::Add`/`AddHistory`/`AddTrusted`). Flags fix a share's link, payouts and commitment so mutated shares get past each check. The share chain, orphans and budgets live for the whole run; in this binary alone (`fFuzzShareWorkStandIn`) a rule on `nNonce` stands in for the RandomX comparison, after the shared work budget is asked. `ShareChain::CheckInvariants` (tip held and checked in full, byte counts, trusted index, caps) and the orphan cap are checked after every input |
| `fuzz-light-peer` | what a foreign chain's peer sends the light clients, per chain and network (Bitcoin, Litecoin, Dogecoin, DigiByte, Ravencoin, Bitcoin Cash, eCash; regtest, test and main): the handshake, `addr`, `headers` (AuxPoW included), `cfheaders`, `cfilter`, `block`, and unsolicited `ping`/`reject`/`notfound`, framed with a correct checksum or as raw bytes, through `Peer::Receive` into the worker's own `Round` (`PullHeaders`, `Headers::Add`, `ScanBlocks`, `VerifyBlock`, the filter checks) and then `Find`/`Call`. A merkle mode is a differential: a block `VerifyBlock` accepts must give the root Bitflash's `CBlock` computes, every branch must climb to it, its re-encoding must pass and a copy with a repeated tail (same root, CVE-2012-2459) must fail. A filter mode round-trips `EncodeFilter`/`MatchFilter` |
| `fuzz-tor-control` | what the node's own Tor answers: control-port replies through `BtfTorReadReply` (over a socketpair) and `BtfTorReadReplyBuffer`, which must agree; the bootstrap answer through `BtfTorParseBootstrap`, which may only report a real percentage from a positive reply; an onion service's hostname file through `BtfTorHostnameEndpoint`; bridge lines through `BtfParseBridgeLines` |
| `fuzz-socks5` | a SOCKS5 proxy's side of `BtfSocks5Handshake`, the function every proxied connection goes through: method selection, CONNECT replies with every address type, truncation. Checks that the node asks by name only, succeeds only on a full success reply, and reads nothing past it |
| `fuzz-rpc-preauth` | one connection to the JSON-RPC port from a caller without credentials: `JsonRpcRecvRequest` (request line, headers, Content-Length) over a socketpair, then `JsonRpcHandleRequest`, in cookie mode with a password the harness never sees. Any answer but 401 aborts; the socket reader must agree with `JsonRpcRequestLength` |
| `fuzz-rpc-postauth` | request bodies, correctly authenticated, through `JsonRpcHandleRequest`: the JSON parser, batches, the dispatcher, and the parameter decoding of the methods that take hex, amounts, addresses and objects (`createrawtransaction`, `signrawtransaction`, `decoderawtransaction`, `createmultisig`, `templatehash`, `swapauditcontract`, ...); swap-chain addresses through `btclight::Destination`. In this binary only, the dispatcher runs nothing outside an allowlist: no spending, no writes, no outgoing calls |
| `fuzz-http-client` | the answers to the node's own requests: `ParseLoopbackRpcResponse` (the wallet asking Bitcoin Core and the other swap chains' nodes, the chat asking the wallet), webhook answers, the IP echo service's answer (`ParseExternalIPResponse`), a Nostr relay's WebSocket upgrade and frames through the node's own `CWebSocket` (`BtfNostrReadRelayStream`, over a socketpair), the webhook URL |

The last five play the other end of a connection over a socketpair
(`src/fuzz_socket.h`), so the node's own socket loops run, and write their own
starting corpus (`BITFLASH_FUZZ_WRITE_SEEDS=<dir> ./<target> -runs=0`).
`make fuzz-io-smoke` runs all five briefly from those seeds; CI does on every
push. What they found is fixed with the self-test `reply-parsers`:

| found by | what | where |
|---|---|---|
| `fuzz-http-client` seed review | An IP echo answer of a bare `"\n\n\r"` made `substr()` throw `std::out_of_range` in a detached thread that catches nothing: the node exited. The answer comes over plain HTTP. | `net.cpp` `ParseExternalIPResponse` |
| (same) | `999.1.1.1` passed `CAddress`'s parser, `inet_addr` failed with `INADDR_NONE`, and 255.255.255.255 became the node's external address. Now only a public dotted quad. | `net.cpp` |
| `fuzz-tor-control` | A bootstrap percentage was read with `atoi` from any line that held `PROGRESS=`, even an error reply: negative, over 100, or overflowing numbers were taken, and 100 ends the bridge ladder. The summary went to the log and the screen with control characters. A positive reply was judged by its first line only, leaving the rest of a multi-line reply to be read as the next command's. | `tor.cpp` `BtfTorReplyParser`, `BtfTorParseBootstrap` |
| `fuzz-tor-control` | The chat's onion address was taken from Tor's hostname file unchecked (the node's own was checked). | `tor.cpp` `BtfTorHostnameEndpoint` |
| `fuzz-tor-control` | `Bridge # ...` in bridges.txt became a torrc line `Bridge #...` with no bridge, and Tor refused to start. | `tor.cpp` `BtfParseBridgeLines` |
| `fuzz-rpc-preauth` | `Content-Length: -1` wrapped the length sum and ended the read before the body; other non-numbers were read by `atoi`. The credentials were looked for anywhere in the headers, the request line included. A caller that connected and sent nothing held the single-threaded RPC server for good: no receive timeout. | `jsonrpc.cpp` `JsonRpcRequestLength`, `JsonRpcRecvRequest`, `Authorised` |
| `fuzz-rpc-postauth`, `fuzz-http-client` | JSON nested a few hundred thousand levels parses without recursion, but copying the request's `id` into the reply, and printing an error object from another node, recursed once per level and ran the stack out. Requests and answers nested deeper than 64 levels are refused before parsing. | `util.cpp` `JsonNestingWithin`, `jsonrpc.cpp`, `rpcclient.cpp` |
| `fuzz-rpc-postauth` (UBSan, 10 min run) | `signrawtransaction` read a prevtx's `vout` with `get<int>()`: a JSON float such as `1e70` is a double-to-int conversion out of range, undefined behaviour. Now only a non-negative integer that fits is taken. | `jsonrpc.cpp` `rpc_signrawtransaction` |
| `fuzz-http-client` | An error code from another node that does not fit an `int` was passed on truncated (4294967271 read as -25). | `rpcclient.cpp` |
| `fuzz-http-client` | A relay's upgrade counted as accepted when ` 101 ` appeared anywhere in the headers (a 403 page was then read as frames). Pings over 125 bytes were answered with a corrupt pong; reserved opcodes and RSV bits were taken as text; a relay sending only pings or pongs kept the reading thread forever. | `nostr.cpp` `CWebSocket` |
| `fuzz-http-client` | A webhook answer was quoted into the log with its control characters. | `invoice.cpp` `WebhookAnswerOk` |
| `fuzz-http-client`, AFL++ and honggfuzz on GitHub (17 inputs) | An error answer whose message was an empty string came back as a failure with an empty reason, which callers show as no error at all. It now says who failed. | `rpcclient.cpp` `ParseLoopbackRpcResponse` |
| independent review | The RPC receive timeout had no test; the websocket control-frame bound was per call and low enough to trip on an idle pooled socket (now 4096); the nesting check ran before the HTML fallback and hid the unknown-wallet hint. | `jsonrpc.cpp`, `nostr.cpp`, `rpcclient.cpp` |

Not reached by these, by design: the Nostr events inside a relay's frames
(JSON handled in the discovery loops of `nostr.cpp`), and the RPC methods
that spend, write, or call another chain's node (their parameter decoding is
the same `AmountFromValue`, `ScriptForAddress` and hex helpers the allowed
methods use). The node never sends Tor PROTOCOLINFO, AUTHCHALLENGE or
ADD_ONION, and subscribes to no events: cookie authentication, GETINFO and
SIGNAL are the whole conversation, and onion services come from the torrc.

Each runs under **libFuzzer**, **AFL++** and **honggfuzz** in turn, all three
with AddressSanitizer and UndefinedBehaviorSanitizer. They share one corpus
per target: what one engine finds is minimised into the corpus
(`libFuzzer -merge=1`) before the next starts. Crashes land in
`crashes/<engine>-<target>-*`; replay one with `./<target> <file>`.

LeakSanitizer settings shared by every harness that links the node are in
`src/fuzz_datadir.h`: the blocks Berkeley DB allocates internally
(`__os_malloc`) are suppressed, since a heap scan cannot see what
references them, and there is no leak check at exit, where the node's global
maps would all read as leaks. libFuzzer still checks after every input. A
`leak-*` file is replayed as a corpus, `./<target> -runs=0 <dir holding it>`,
not as a single file. The Actions campaign's `fork` input set to false runs
libFuzzer as one process that stops at the first finding with its whole
report (fork mode keeps going but loses the reports' stacks); it then uses
one core and may end hours before its time.

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
other five jobs found nothing. The round after every fix above found nothing
in any of the six jobs (corpora 6.0k and 9.2k inputs for `fuzz-deserialize`,
8.0k and 11.4k for `fuzz-decoders`, libFuzzer and honggfuzz), and the campaign's own coverage of the
corpora matched the table above (`serialize.h` 61.4%, `base58.h` 94.2%,
`btfaddr.cpp` 85.9%, `bip32.cpp` 77.3%, `bip21.cpp` 100%, whole files).

## The script engine under every rule set (`fuzz-script`, `fuzz-v4-templates`)

November 2026, on `main` at `c48f8c8`. `fuzz-script` runs each script and
each structured spend under eleven flag sets (rules v2, v3, v4 in every
combination, v5, and the relay policy) and aborts when one rule set changes
an answer it cannot affect, when rules v4 do more than add, when v5 or the
policy turn a failure into a pass, or when a spend checks more signatures
than the block and the pool charged for it. `fuzz-v4-templates` builds the
vault, CTV batch and inheritance scripts with the wallet's own functions and
spends them as the RPCs do.

### What they found

| found by | what | where |
|---|---|---|
| the signature-count invariant of `fuzz-script` | `OP_CHECKMULTISIG` is charged 20 signature operations but checks one signature per key it is handed, and the key count was bounded only by the stack, so a script that computes its count (say `OP_16 OP_9 OP_ADD`) checked more signatures than it paid for. Relay policy now refuses, in the pool and in the miner, an input whose script or redeem script runs `OP_CHECKMULTISIG(VERIFY)` without a literal `OP_0`..`OP_16` count right before it, before any signature is checked. Rules v5 (unscheduled) cap the keys at 20 in consensus. Blocks are judged as before. | `script.cpp`, `main.cpp`, self-tests `script-sigops`, `rules-v5` |
| reading `AcceptTransaction` for the above | The pool read the clock twice for one transaction's signature count, and the readings could fall either side of the rules v4 switch. One reading now. | `main.cpp` |
| independent review of the change | A transaction the pool refused for policy, a bad signature or a relative lock was reported as "missing inputs", so it went to the orphan pool, waiting for a parent it already had, and `spendscript` named the wrong cause. Missing inputs now means a parent neither the chain nor the pool knows; `spendscript` checks the key counts first. | `main.cpp`, `jsonrpc.cpp`, self-test `script-sigops` |

Checked and not a defect: rules v2 strict signatures are not monotone (a
non-DER signature makes `OP_CHECKSIG` return false, so `CHECKSIG NOT` can
pass), as in Bitcoin before NULLFAIL, already active consensus; any script
where that leads to a pass already passes with an empty signature. There is
no `MAX_SCRIPT_SIZE`; the work per operation grows with the script, bounded
by the block size (a candidate for a later rule set, not measured as a
problem).

### Runs and coverage

Actions "Audit campaign" run 43130125511, 2 h 10 min per job with
AddressSanitizer + UndefinedBehaviorSanitizer, no crash, leak or sanitizer
report:

| target | libFuzzer | AFL++ (4 instances) | honggfuzz |
|---|---|---|---|
| `fuzz-script` | 3.9 M executions, corpus 2572, 0/0/0 | 7.3k items, 0 crashes, 0 timeouts | 0 crashes; 345 processes killed at the 20 s limit (below) |
| `fuzz-v4-templates` | 30.4 M executions, corpus 1079, 0/0/0 | 4.4k items, 0 crashes, 0 timeouts | 0 crashes, 0 timeouts |

Under honggfuzz alone, `fuzz-script`'s time per input inside one persistent
process climbs, from about 0.1 s to as much as 14 s, until honggfuzz
restarts the process ("became too slow", 67 times) or kills one over its
20 s limit. Nothing in the node accumulates: honggfuzz's own corpus (8519
inputs) replayed through the libFuzzer build ran every input in under a
second (peak memory 884 MB with AddressSanitizer), AFL++ saw no timeout, and inputs built to be
the slowest (4 kB of signature operations) take at most 0.4 s in the
honggfuzz build run on its own. It is the cost of honggfuzz's comparison
hooks on a harness that evaluates each spend 33 times, each operation
copying and scanning the script; inputs are capped at 4 kB for it.

Line coverage of the merged corpora: `script.cpp` 71.6% (the rest is wallet
signing and solving, outside the target; `EvalScript` 81%, its misses mostly
the bodies of disabled opcodes), `CheckTemplateHash`, `GetP2SHSigOpCount` and
the key-count checks 100%. Measured on the 202 from the same corpora: the
template builders in `v4templates.h` (`VaultUnvaultScript`, `CtvScript`,
`TemplateHashFor`, `InheritSequence`, `InheritScript`, `ParseInheritScript`)
100% each, `OutputsFromParam` 87.5%, `CheckCtvSpendPolicy` 87.0%.

## P2Pool and the light clients (`fuzz-p2pool`, `fuzz-light-peer`)

November 2026, on `main` at `dc5fefb`. `fuzz-p2pool` is a peer of the share
chain: every P2Pool message, from an inbound or dialled peer, proven or not,
with reconnects, history asks and raw shares, against a chain, orphan queue,
budgets and held entries that live for the whole run (with a 256 kB byte cap
so eviction is reached); after every input the chain's invariants hold.
`fuzz-light-peer` is a foreign chain's peer of the light clients, for every
coin and network they speak, with a merkle differential against Bitflash's
own `CBlock` code and a filter round trip.

### What changed, and why

| from | what | where |
|---|---|---|
| DoS review H4 (share side) | Every share an unproven peer sent was hashed (RandomX) before anything else could refuse it, and a reconnect started the peer afresh. One shared budget (32 hashes, one more every 2 s) covers shares from unproven peers, asked right before the hash and after every cheap check (the payouts are checked first now). A share the budget refuses is held, one per connection, and hashed as the budget refills, the oldest connection first; a share arriving live waits behind one an older connection holds. Nobody is blamed for a refusal; a held share that turns out bad blames its sender. | `p2pool_net.cpp`, `p2pool_share.cpp`, self-test `p2pool-dos` |
| DoS review M6 | History serving and asking were re-armed on every reconnect, and the orphan-share backlog never shrank. Orphans expire on every share; an orphan already hashed no longer opens a history ask; asks of unproven peers and histories sent to them draw on shared budgets, one history per unproven connection, held when it must wait; the bytes queued to inbound peers together are capped at 64 MB (dialled peers are outside it), and an inbound peer still holding more than 4 MB of a history 15 minutes after it was sent is cut off while the cap is reached. | `p2pool_net.cpp`, self-test `p2pool-dos` |
| DoS review L6 | Fully checked shares were capped by count only. A byte cap over all shares held (128 MB), the lightest side lines evicted first; trusted shares indexed by parent. | `p2pool_chain.cpp`, self-tests `p2pool-dos`, `p2pool-chain` |
| independent review of the L6 fix | As first written, the byte cap could evict a share at the tip's height the moment it came, once the tip's own line passed the cap's target: its nephew was never taken and an overtaking line never won, so nodes would part ways. Eviction now keeps the tip's line and its uncles and the heaviest 64 lines still within 16 shares of the tip's work, and when what is kept passes the cap by itself the cap rises to that plus 64 MB, with eviction stopping 32 MB above it. | `p2pool_chain.cpp`, self-test `p2pool-dos` |
| independent review of the H4 and M6 fixes | The first versions dropped what the budgets refused, so whoever kept them spent starved honest unproven peers (a miner that only dials out is unproven everywhere); live messages could then take every refilled token before the held ones; the queued-bytes cap first counted every peer, dialled ones included, then left out proven inbound peers; slow readers could keep it full. All fixed as described above. | `p2pool_net.cpp`, self-test `p2pool-dos` |
| `fuzz-light-peer` seeds | Main and test networks' header rules are reached only past the proof-of-work comparison, which no fuzzer can pass: in this binary alone (`fFuzzLightSkipPoW`, `#ifdef BITFLASH_FUZZ`) an input may skip it; DigiByte and Ravencoin decide their headers in code `fuzz-light-pow` covers. A merged-mined Dogecoin header seed reaches the AuxPoW checks. | `btclight.cpp`, `fuzz_light_peer.cpp` |

Left as they are, and why: starving an honest unproven peer is bounded, not
impossible (each connection older than it that sends shares with no work
behind them buys about 10 s of the budget before it is cut off); "near the
tip" is measured by accumulated chain work, which is approximate for a line
whose deeper shares came from a history.

### Runs and coverage

Actions "Audit campaign", 2 h 10 min per job with AddressSanitizer +
UndefinedBehaviorSanitizer, no crash, timeout, leak or sanitizer report:

| target | run | libFuzzer | AFL++ (4 instances) | honggfuzz |
|---|---|---|---|---|
| `fuzz-p2pool` | 43275125594 | 6.9 M executions, corpus 1517 | 388 new items, 0 crashes, 0 timeouts | 0 crashes, 0 timeouts |
| `fuzz-light-peer` | 43246516215 | 20.2 M executions, corpus 1183 | 270 new items, 0 crashes, 0 timeouts | 0 crashes, 0 timeouts |

Under honggfuzz both harnesses slow down inside one persistent process, as
the share chain and the light clients' state grow, and honggfuzz restarts
the process ("became too slow"); no input ran past its 20 s limit.

Line coverage of the merged corpora: `p2pool_share.cpp` 90.6%,
`p2pool_net.cpp` 70.6%, `p2pool_chain.cpp` 70.0% (`P2PoolProcessMessage`
92%, `AcceptShare` 97%, `AddInContext` 93%, `AddHistory` 100%, `AddTrusted`
88%, `Evict` and `ByteCap` 100%, `Kept` 37%: the near-tip lines it keeps
need a line 16 shares deep, which the self-test `p2pool-dos` builds and a
fuzzed chain rarely reaches; `DropSlowestHistoryReader` is reached only
with tens of megabytes queued and is covered by `p2pool-dos`).
`btclight.cpp` 49.7% (the rest is the worker's network and disk side):
`Peer::Receive`, `VerifyBlock`, `EncodeFilter`/`MatchFilter` 100%,
`CheckAuxPow` 96%, `PullHeaders` 88%, `Find` 82%, `Headers::NextBits` 78%,
`Headers::Add` 69%. The first campaign showed `Kept` and `ByteCap` at 0%
(a 256 kB fuzz cap was never reached) and `NextBits` and `CheckAuxPow` near
0% (the seeds past the proof of work and the merged-mined header did not
reach a kept corpus); both were fixed and the harnesses run again.

Self-tests after the last change: Windows suite 83 "ALL TESTS PASSED", 0
failures; Linux (the 202) 81, 0 failures.
