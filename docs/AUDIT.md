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
| `fuzz-chat-frame` | what reaches a chat identity from strangers: frame JSON through `OpenFrame` and the whole inbound path (`Inbox::Deliver`, with the consent gate and the replay guard), sealed mailbox envelopes (`Mailbox::Open`, X25519 plus ML-KEM-1024), the encrypted link (the endpoint handshake, `Link::RecvFrame`, the frame cipher), epoch-key announcements (`VerifyEpochKeys`), the key store and roster JSON; and the vendored ML-KEM-1024 against OpenSSL's when it has one. Aborts on a replayed frame delivered twice, a changed envelope that opens, a decapsulation that differs from the reference |
| `fuzz-chat-relay` | `chatrec`, `chatput`, `chatget`, `getchatinv`, `getchatdir`, `inv` and `getdata` for chat records, through `ProcessMessage()` and `ChatRelayProcessMessage()` into the node's `ChatStore`, with records mined and signed from fields (the store takes 4 bits of work instead of 20 under `-DBITFLASH_FUZZ`). Aborts when an answer is longer than its caps, a record does not match what was asked or a store passes its budget |
| `fuzz-nostr` | what Nostr relays send: relay messages on the discovery, pool and descriptor subscriptions (`NostrIngestDiscovery`, `NostrIngestPool`, `NostrIngestDescriptor`, the OK reply), and events through `NostrVerifyEvent`, with the BIP-340 check against a reference on OpenSSL's arithmetic. Aborts when the two verifiers disagree, an event taken has not the id of its own serialization, or the peer table or pool list pass their caps |
| `fuzz-swap` | atomic-swap negotiation: offers and steps as text with a round trip through their formatters, contract scripts (`swap::ParseContract` against `BuildContract`), foreign transactions and blocks (`btcswap`), and the chat swap engine (`btfchat::SwapEngine`) driven through a whole swap as maker or taker with the counterparty's steps and the wallet's answers from the input. Aborts when a taker locks without an audit of the maker's contract, a maker shows its secret without one of the taker's, or the state does not read back to itself |

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

Runs: Actions "Audit campaign" 43236831520, 2 h 10 min per job on each of
the three engines with AddressSanitizer + UndefinedBehaviorSanitizer:
`fuzz-tor-control` (181.6 M libFuzzer executions), `fuzz-socks5` (443.9 M),
`fuzz-rpc-preauth` (379.4 M) and `fuzz-rpc-postauth` clean; `fuzz-http-client`
found the empty error message above, and 21 libFuzzer timeouts that were the
harness's own (it never read the node's pongs; in the node a full socket
fails at its send timeout, and `fuzz_socket.h` now does the same). After
those fixes, run 43313720157 ran `fuzz-http-client` again on the final commit, 2 h
10 min per engine: no crash file on any engine (corpus 8,862 inputs after
libFuzzer, 8,774 after AFL++, 10,768 after honggfuzz; 2,648 merged). Function
coverage of the corpora: `BtfTorReadReply`, `BtfTorParseBootstrap`,
`BtfTorHostnameEndpoint` and `BtfParseBridgeLines` 100%,
`BtfTorReadReplyBuffer` 95%, `BtfSocks5Handshake` 88%, `JsonRpcRecvRequest`
94%, `JsonRpcRequestLength` 96%, `JsonRpcHandleRequest` 92% (post-auth),
`ParseLoopbackRpcResponse` 98%, `CWebSocket::RecvText`,
`ParseExternalIPResponse` and `WebhookAnswerOk` 100%.

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

November 2026. Every input the node does not control was fuzzed under AddressSanitizer and UndefinedBehaviorSanitizer with libFuzzer, AFL++ and honggfuzz (the P2P envelope and payloads, scripts and signatures, serialized records, text decoders, light-client proof of work, the share chain, Tor control and SOCKS5 replies, the RPC server, the HTTP client, chat, Nostr and swap negotiation). Consensus, rules v4, denial of service, the wallet and cryptography, and swaps and the light clients were each reviewed by hand, line by line, on 10 November, and every review was followed by an independent review of the fix before it was merged (pull requests #56 to #66 and #69 to #73, merged between 10 and 12 November). Self-test coverage of the consensus files was raised, and a final full pass closes the run. Nothing was built or run for the manual reviews themselves; every finding was traced to code and every fix has a self-test that fails on the old code or, where it cannot (a race, a clock), says so.

Where each kind of result ran:

| what | where |
|---|---|
| builds, short fuzz runs, the instrumented self-test passes, reprotest | the Debian 13 server ("the 202", 4 cores, clang 19), one heavy job at a time |
| long fuzzing, 2 h or more per engine per harness, corpora kept between runs; coverage per harness; the self-tests under ASan+UBSan, TSan and Valgrind | GitHub Actions, "Audit campaign" |
| the self-test suites | the Windows UCRT64 bench and Linux (the 202, and the CI jobs) |
| sync compatibility between a release-equivalent node and the new one | testnet nodes on the 202, each with its own data directory and managed Tor |

Findings are named as in the review that raised them. "Self-test" is the test that pins the fix. Merge commits are shortened. Where a finding was judged not to be a defect, or is deferred, the row says so.

### Findings and fixes

#### Consensus

Review of `main.cpp`, `script.cpp`, `serialize.h`, `db.cpp` and the block, transaction and chain-selection paths. Findings 2, 4, 8 and 12 would change which blocks are valid, so they ship as rules v5, which is not scheduled (see "Open by design or deferred"). The rest change no block's validity on any live chain and ship without a switch.

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| 1 (High) | The difficulty walk at the first retarget went one block past genesis for a block dated after the rules v2 switch and hit an `assert`, which aborts the process. A branch from genesis could stop a node that did not yet hold the newest checkpoint. | #61 `4751977` | `consensus-safety` (old and new walk compared at every height of 40 made-up chains), `reorg-safety` |
| 2 (High) | The retarget timespan is unsigned: if the closing block of a window is dated before the window's first block, it wraps and the target gets four times easier instead of harder. | #58 `fa5b5db` (rules v5, soft-fork form: such a block is invalid; unscheduled) | `rules-v5` |
| 3 (High) | `Reorganize` deleted the index entries of a block that failed to connect and of the path to the new tip, leaving other branches pointing into freed memory. | #61 `4751977` (failed blocks are marked, with all descendants, not deleted) | `consensus-safety`, `reorg-safety` |
| 4 (Medium) | A transaction could spend the coinbase of its own block: the maturity walk never looked at the block being connected. | #58 `fa5b5db` (rules v5; unscheduled) | `rules-v5` |
| 5 (Medium) | Blocks on a side branch are stored after cheap checks only, and the branch's own timestamps set its difficulty, so a weak branch can take disk and index space. | Deferred (see M9 below). #61 adds a `-debug=net` line for such blocks. | `reorg-safety` (a much easier side block is stored, by design) |
| 6 (Medium) | Pay-to-script-hash was decided by each block's own time, so for the first blocks after the rules v3 switch a block dated just before it runs the old rules, where such an output needs no signature. The wallet and relay decided by the local clock and opened a few minutes early. | #60 `88ed995` (wallet and relay wait until the tip's median time has passed the switch) | `rules-v3` |
| 7 (Low) | The miner could build a template under one rule set and finish it under another across the v2 or v3 switch. | #61 `4751977` | `consensus-safety` |
| 8 (Low) | `nLockTime` is a signed `int`, so values from 2^31 up counted as already final. | #58 `fa5b5db` (rules v5, finality only; CLTV left as is and the limit documented) | `rules-v5` |
| 9 (Low) | The memory pool kept transactions that were not final. | #61 `4751977` | `reorg-safety` |
| 10 (Low) | Blocks reconnected by `Reorganize` were never re-checked, and the startup repair could be undone by the next child on the bad branch. | #61 `4751977` (the load check marks the first bad block and its descendants; the check ignores the local clock) | `reorg-safety` |
| 11 (Low) | The orphan-block pool was capped by count only. | #61 `4751977` (32 MB byte cap; once synced, an orphan far easier than the tip is not held; checked before the RandomX hash) | `consensus-safety` |
| 12 (Info) | The subsidy shift is undefined from 64 halvings (BIP42), height 13,440,000 and later. | #58 `fa5b5db` (subsidy is 0 from 64 halvings; identical for every earlier height, checked for all) | `rules-v5` |
| 13 (Info) | `OP_VER` and `OP_VERIF` stay version-dependent until rules v3 lock in. | Not a defect: a short, known window that ends at the v3 switch. Listed so the write-up is complete. | none |
| 14 (Info) | A zero or negative compact `nBits` passed the limit test in `CheckBlock`. | #61 `4751977` | `consensus-safety` |
| 15 (Info) | An overflow in `ReplacementPaysEnough` at fee levels no real transaction reaches. | #61 `4751977` (big-number comparison) | `consensus-safety` |
| 16 (Info) | Non-canonical CompactSize lengths were accepted and a 64-bit length was cut to 32 bits. | #64 `14564fc` (see "Found by the fuzz harnesses") | `serialize-canonical` |

Checked and found correct (no change): `CheckTransaction`, `GetValueOut`, the money checks in `ConnectInputs`, the coinbase value, BIP30, BIP34, BIP113 finality, BIP68 sequence locks, CLTV, CSV, CTV and CSFS rules, sigop counting, block size, the merkle tree (duplicate transactions rejected), timestamp rules, the retarget arithmetic apart from finding 2, compact `nBits`, chain work, the checkpoint at 68000, fork search in `Reorganize`, orphan handling, mempool and replacement rules, disconnect, and the activation helpers.

#### Rules v4 and v5

Review of CSV, CTV, CSFS and the vault, batch and inheritance templates built on them. No consensus bug: the code follows BIP68, BIP112, BIP340 and BIP348, and BIP119 without the scriptSigs field (documented). The defects were in the wallet layer. Rules v5 (#58) is the vehicle for the consensus tightenings above and for the CSFS sigop item below.

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| 1 (Medium) | The vault wallet trusted the stored unvault txid. If a miner confirmed a copy whose scriptSig had been altered (the CTV template does not commit to scriptSigs), recovery would build on a transaction that never confirms. | #62 `a9406ff` (the spender is resolved from the chain every time); #61 `4751977` (pool transactions that conflict with a connected block are removed) | `wallet-rpc-v4`, `reorg-safety` |
| 2 (Medium) | The fee and size frozen into a CTV template were never checked against relay policy, so a large batch could freeze for good. | #62 `a9406ff` (`vaultcreate` and `ctvbatch` build the exact spend and refuse an unrelayable size or a too-low fee before funding) | `wallet-rpc-v4` |
| 3 (Low) | No relay policy discouraged the v4 upgrade hooks: CSFS with a key that is not 32 bytes is satisfied by any non-empty signature. | #62 `a9406ff` (relay policy only, `spendscript` refuses such a redeem script; blocks and miners unaffected) | `wallet-rpc-v4` |
| 4 (Low) | CSFS in a bare output created before activation was never counted as a sigop. | #58 `fa5b5db` (rules v5: counted when spent; unscheduled) | `rules-v5` |
| 5 (Low) | An extra deposit to a vault or batch address is locked or goes to fees, with no warning. | #62 `a9406ff` (warning in RPC results, usage and docs) | none |
| 6 (Info) | Docs and RPC text said CSV and CTV are no-ops before v4; the code fails them. | #62 `a9406ff` (wording) | none |
| 7 (Info) | Activation follows each block's own time, not the median. | Not a defect: every v4 spend needs an opcode that fails before activation, so nothing locked can be released early. | none |

#### Denial of service

Review of everything a remote peer can make the node hold, write or compute. Fixed together in #59, which is wire compatible with 1.2.x (no new message; a two-way sync bench against a 1.2.32-equivalent node passed, see the PR).

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| C1 (Critical) | One `getdata` could name the same item hundreds of thousands of times and be answered in full into an unbounded send buffer, under the main lock. | #59 `c48f8c8` (cap on entries; served only while the send buffer is under 1 MB) | `p2p-dos` |
| H1 (High) | No per-peer receive or send limit, and one peer's backlog could starve the message thread. | #59 `c48f8c8` | `p2p-dos` |
| H2 (High) | `getblocks` answered with the whole chain. | #59 `c48f8c8` (500 per request; a tip hint ends every batch so older nodes keep syncing; locators over 101 hashes refused) | `p2p-dos`, sync bench |
| H3 (High) | An `inv` flood grew the global asked-for map, the peer's known set and the request queue without bound. | #59 `c48f8c8` | `p2p-dos` |
| H4 (High) | `Misbehaving()` only set a flag: the peer kept being processed for up to 60 s and every "N strikes" bound was unbounded in practice. | #59 `c48f8c8` (the peer is no longer read; a shared budget guards the RandomX hash for young inbound peers). The share side, where a peer's shares were each hashed before anything could refuse them, is #66 `134dc25`. | `p2p-dos`, `p2pool-dos` |
| H5 (High) | `debug.log` grew without limit from peer-triggered lines. | #59 `c48f8c8` (rotation at 50 MB; repeated lines collapsed) | `p2p-dos`, `debug-log-buffer` |
| M1 (Medium) | The orphan-block pool could be filled with floor-difficulty blocks. | #61 `4751977` (same fix as consensus 11) | `consensus-safety` |
| M2 (Medium) | Inbound slots could all be held by one party, with no eviction. | #59 `c48f8c8` (at most 117 inbound; a full node evicts the least useful peer) | `p2p-dos` |
| M3 (Medium) | A disconnected peer's buffers stayed allocated for at least five minutes. | #59 `c48f8c8` | `p2p-dos` |
| M4 (Medium) | Hearsay peer descriptors could push every verified peer out of the persistent cache. | #59 `c48f8c8` (separate room for each) | `p2p-dos` |
| M5 (Medium) | One RandomX verification VM serialised block, share and pool-submit work. | #59 `c48f8c8` (two more light VMs on the same cache). Penalties for bad pool submissions are left to the pool operator. | `p2p-dos` |
| M6 (Medium) | P2Pool history serving and asking could be re-armed on every reconnect; the orphan-share backlog never shrank. | #66 `134dc25` (see "P2Pool and the light clients") | `p2pool-dos` |
| M7 (Medium) | The chat store budget is cheap to fill network-wide, and per-connection rations reset on reconnect. | #70 `2c86386` (the work asked grows as a budget fills; node-wide rations; per-source sub-budgets are not done, see the chat section) | `chat-dos` |
| M8 (Medium) | Nostr peer discovery has no total cap, trusts the relay's timestamps and does not verify event signatures. | #70 `2c86386` | `nostr-relay` |
| M9 (Medium) | Side-branch blocks above the last checkpoint are written with no work check against the tip. | Deferred: see "Open by design or deferred". | |
| M10 (Medium) | The chat app listener starts one thread per inbound connection with no cap. | #70 `2c86386` | `chat-dos` |
| L1 (Low) | The legacy `review` message was still processed (signature check, file append). | #59 `c48f8c8` (now a no-op) | `p2p-dos` |
| L2 (Low) | Invalid transactions are re-verified every time, with no reject cache and no penalty. | Partly #65 `9133c5d`: a refused transaction is no longer reported as missing inputs, so it is not kept as an orphan. The reject cache is deferred (see below). | `script-sigops` |
| L3 (Low) | The light client keeps whole foreign blocks and rewrites them all on every save. | Deferred: it needs a new light-client state format (see below). | |
| L4 (Low) | The chat swap engine's state is never pruned. | #70 `2c86386` | `swap-prune` |
| L5 (Low) | A pre-switch block can force the v1 RandomX cache to be built on a node that has not allocated it. | Deferred: the fix is a timestamp check before the hash in `CheckBlock`, consensus code, not changed the day before a release (see below). | |
| L6 (Low) | Fully checked P2Pool shares are capped by count, not by bytes. | #66 `134dc25` | `p2pool-dos`, `p2pool-chain` |

Reviewed and found bounded (no change): orphan transactions, the mempool, `mapRelay`, wire message size, deserialization growth, block limits, `btfpeers`, `p2ppeers`, `p2pgetsh`, `p2pshare` and `p2pshares` sizes, share-chain pruning, chat record and query limits, light-client receive budgets, foreign block parsing, stratum line and miner limits, Nostr frame sizes, chat history limits, connection caps, and the legacy order messages.

The independent review of #59 found three further problems in the first version of the fix, all fixed before merge: the shared block budget could be drained by blocks that fail a cheap check (regression), our own `getdata` could still grow a peer's send buffer, and a replaced connection could stall an old node's sync mid-chain (fixed by the tip hint above). A refused block is now asked for again once there is budget.

#### Wallet and cryptography

Review of keys, encryption, coin selection, fees, restore, dump and import, locking, the random number generator, signing, zeroization, logging, and the hybrid chat cryptography. All fixed in #62.

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| H1 (High) | Installing or restoring a recovery phrase wrote the HD seed in plaintext into an encrypted wallet, and on a locked wallet failed after the writes while reporting that nothing changed. | #62 `a9406ff` (refused while locked, before any write; stored only encrypted; a plaintext seed left by older versions is taken out of use at load and encrypted or erased at the next unlock) | `wallet-encrypted-seed`, `wallet-encrypted-seed-sqlite`, `wallet-sqlite-rollback` |
| M1 (Medium) | Encrypting a BIP44 wallet rebuilt the key pool from receive index 0, so already-issued addresses were issued again. | #62 `a9406ff` (pool and counters kept; wallets damaged by releases up to 1.2.32 are repaired at the next unlock) | `wallet-encrypt-pool`, `wallet-encrypt-pool-sqlite` |
| M2 (Medium) | The GUI restore changed HD counters and the derivation schema without the key-pool lock while other threads derived keys. | #62 `a9406ff` | `wallet-restore-race` (probabilistic on old code) |
| M3 (Medium) | An unlocked wallet never locked again; `LockWallet` had no caller. | #62 `a9406ff` (`/walletunlocktimeout`, RPC `walletlock`; refused on a node that mines, runs a pool or renews an inheritance) | `wallet-relock` |
| M4 (Medium) | The recovery phrase was accepted only as a command-line literal. | #62 `a9406ff` (stdin with echo off, or `@FILE`) | `wallet-secret-args` |
| M5 (Medium) | On POSIX the SQLite wallet, backups, `swaps.log` and `nostr.key` were created readable by other local users. | #62 `a9406ff` (directories 0700, files 0600, existing files tightened at start) | `wallet-file-modes` |
| M6 (Medium) | `RAND_bytes` results were unchecked for secrets (swap secret, RPC cookie, invoice id, Nostr key). | #62 `a9406ff` (`GetStrongRandBytes` aborts on failure); swap secret in #63 | `wallet-file-modes` |
| M7 (Medium) | The flat transaction fee had no upper bound and sends had no fee confirmation. | #62 `a9406ff` (0 to 1 BTF, `/maxtxfee`, GUI review step) | `wallet-fee-limit` |
| M8 (Medium) | Invites from strangers could fill the chat replay table and block all inbound chat. | #62 `a9406ff` (strangers get their own share of the table) | `chat-replay-quota` |
| L1 (Low) | `signrawtransaction` cleanup unmapped the wallet's own encrypted keys and left redeem scripts behind. | #62 `a9406ff` | `wallet-rpc-v4` |
| L2 (Low) | `getbalance` at minconf 0 or 1 counted other people's unconfirmed payments. | #62 `a9406ff` | `wallet-rpc-v4` |
| L3 (Low) | Secrets were not wiped from several buffers. | #62 `a9406ff` (mostly fixed; the global seed copies and the `DumpWallet` temporaries are not, see below) | none |
| L4 (Low) | The passphrase prompt echoed to the terminal. | #62 `a9406ff` | none |
| L5 (Low) | BIP39 mnemonic and passphrase are not NFKD-normalised. | Deferred, warning only: see below. | none |
| L6 (Low) | Disk-full and write-failure paths: a failed pool erase, a silent fall back to random keys in an HD wallet, ignored commit writes. | #62 `a9406ff` | `wallet-encrypt-pool` (failed erase and commit writes cannot be simulated on Berkeley DB) |
| L7 (Low) | Legacy wallets returned change to a key taken from the first input, always at `vout[1]`. | #62 `a9406ff` (fresh pool key, random position) | `wallet-fee-limit` |
| I1 (Info) | Unlock accepted a candidate master key with no key to check it against. | #62 `a9406ff` | `wallet-encrypted-seed` |
| I2 (Info) | `AddKey` read the master key outside its lock. | #62 `a9406ff` (with M3) | `wallet-relock` |
| I3 (Info) | Coin selection used an unseeded generator. | #62 `a9406ff` | `wallet-encrypted-seed` |
| I4 (Info) | The hybrid chat channel authenticates the endpoint with X25519 only; the ML-KEM key is ephemeral. | Not a defect: the design protects against harvest-now-decrypt-later, not against an active quantum impersonator. | none |
| I5 (Info) | The encrypted HD seed uses a fixed IV per label. | Not a defect: each plaintext is encrypted once per master key. | none |
| I6 (Info) | No dust rule: change of any size becomes an output. | Deferred. | none |
| extra | `spendscript` signed from the plain key map only, so vaults in encrypted wallets could not be withdrawn. | #62 `a9406ff` | `wallet-rpc-v4` |

Checked and found correct (no change): signing (low-S, strict DER), BIP32 and BIP39 handling, the wallet key derivation and AES use, wrong-passphrase handling, `EncryptWallet`, dump and import, lock order, `CreateTransaction`, RPC authentication and cookie, secret logging, constant-time comparisons, and the whole hybrid chat construction (X25519 low-order rejection, ML-KEM-1024 with implicit rejection, the combiner, the ratchet, sealed envelopes, Argon2id identity, replay guard).

The independent review of #62 found that the first M1 fix helped only wallets encrypted from then on, that the relock timer could lock a node that had started mining, and that the SQLite paths were untested. All three were fixed before merge.

#### Swaps and light clients

Review of the atomic-swap engines, the embedded light clients, their proof-of-work and header rules, and the swap RPCs. Fixed in #63. No consensus change: the Bitflash time locks use rules v3 as they are.

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| H1 (High) | A taker giving BTF locked by block height while the maker's contract was locked by time, so a slowdown in Bitflash block production could let the maker refund and still redeem. | #63 `42ee3b3` (BTF contracts lock by median time, 48 h and 18 h; offers and takes carry `"v":2`) | `swap-timelock`, `swap-engine`, `swap-rpc` |
| H2 (High) | With an own-node wallet, coins were sent before the secret and contract were saved, and a later failure lost them for good. | #63 `42ee3b3` (an `intent` line is fsynced to `swaps.log` before any payment; new RPC `swaplookup`) | `swap-journal`, `swap-rpc`, `swap-engine` |
| M1 (Medium) | A counterparty-chosen lock time could make the light client rescan from its anchor and stall every swap on that chain. | #63 `42ee3b3` (the lock is checked before any audit; a first-time watch's rewind is limited). The per-contract scanning gate and expiry of unfunded watches are deferred, see below. | `swap-engine` |
| M2 (Medium) | Light-mode refunds were sent once at a fixed fee, and the taker's swap went final before its refund confirmed. | #63 `42ee3b3` | `swap-engine`, `swap-wait-payment` |
| M3 (Medium) | `SW_FAILED` was terminal while the maker's own contract could still be locked. | #63 `42ee3b3` (the maker goes on to refund) | `swap-engine` |
| M4 (Medium) | A malformed offer or step ended the chat mailbox thread, before the signature check. | #63 `42ee3b3` (type checks; the parsers never throw; catch per round) | `swap-parse`, `test_chatswap` |
| M5 (Medium) | The chat store, which holds swap secrets and state, was saved by delete-then-rename with no fsync and ignored failures. | #63 `42ee3b3` (atomic and durable save, mode 0600, failures reported, no lock made while the store cannot be saved) | `chat-store-save` |
| L1 (Low) | Unchecked `RAND_bytes` when making the swap secret. | #63 `42ee3b3` | `swap-journal` |
| L2 (Low) | No coinbase check on the counterparty's funding output. | #63 `42ee3b3` (refused) | `swap-engine` |
| L3 (Low) | No minimum contract value against the cost of spending it. | #63 `42ee3b3` (floors per coin) | `swap-parse` |
| L4 (Low) | Two payments to one's own light-mode contract freeze the swap. | Deferred: see below. | none |
| L5 (Low) | The destination address could change after the lock without validation. | #63 `42ee3b3` | `swap-engine` |
| L6 (Low) | `swaps.log` was readable by other local users on POSIX. | #63 `42ee3b3` (0600; existing files fixed at start) | `swap-journal` |
| I1 to I4 | Work-counted confirmations floor, one header peer for Bitcoin light, Dogecoin lock timing, `stepsSeen` and `watched` growth. | Not defects: design or documented. | none |
| I5 (Info) | Light mode kept superseded transactions and rebroadcast a spend that had lost. | #63 `42ee3b3` | `swap-engine` |
| found in review of #63 | A taker's refund was final after one block while the maker could still redeem; a time-locked refund was never counted as final by the wallet (a general wallet bug: balance, coin selection, `listunspent`). | #63 `42ee3b3` (final only at confirmation depth and with the maker's contract spent or past its lock; `IsFinalForWallet` at every wallet call site) | `swap-wait-payment`, `wallet-final`; testnet proof with coins (time-locked refund confirmed, listed, counted and spent) |
| found in review of #63 | A lock attempt was not written ahead; a peer's cancel could end a swap with an unresolved lock; an RPC failure was read as "not paid"; an output in a transaction the wallet cannot decode (MWEB) was not found; smaller items. | #63 `42ee3b3` | `swap-engine`, `swap-rpc` |

Checked and found correct (no change): the contract template, hash and preimage size on both chains, the order of checks before a secret is revealed, per-swap receive addresses, wrong-coin and wrong-network checks, replay and reorder handling, timeouts, refund transaction rules, the fee loop, CashTokens, merkle verification, witness handling, BIP157 filter checks, header-chain selection, and the difficulty and proof-of-work rules of the Bitcoin, Litecoin, Dogecoin (AuxPoW), Bitcoin Cash, eCash, DigiByte and Ravencoin clients.

#### Found by the fuzz harnesses

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| `fuzz-net-message`, LeakSanitizer | A failed Berkeley DB open threw `DbException` that `CDB` did not handle: the `Db` handle leaked and the file's use count stayed up. | #56 `3bb7c75` | `db-open-failure` |
| flawfinder | The RPC `.cookie` and key dump were created with `fopen`, then `chmod`ed: a window for another local user. | #56 `3bb7c75` (owner-only from the first byte, never through a symlink) | `private-file` |
| ASan, TSan, Valgrind | The light clients' detached threads read globals that were destroyed at exit. | #56 `3bb7c75` | the instrumented self-test passes |
| TSan | The Bitcoin light client started from argument parsing, so every self-test and one-shot command dialled peers and could write a running node's state file. | #56 `3bb7c75` (starts with the node) | the instrumented self-test passes |
| TSan | A lock-order inversion in wallet loading. | #56 `3bb7c75` | the instrumented self-test passes |
| UBSan, others | Signed shifts in Base64; an out-of-range enum; `delete` on `new[]`; `db.log` created without a mode and in the working directory; a clang 19 compile error. | #56 `3bb7c75` | the instrumented self-test passes |
| Trivy | The release packages carried Tor 0.4.9.11; 0.4.9.14 fixed high-severity bugs. | #56 `3bb7c75` (Tor Expert Bundle 16.0, tor 0.4.9.15) | release workflow |
| `fuzz-p2p-payload` | `ProcessBlock` leaked every duplicate block, and the pool freed refused blocks a second time. | #57 `a40e674` (`ProcessBlock` owns the block on every path) | `net-hardening` |
| `fuzz-net-message`, UBSan | `AddTimeData` overflowed on a peer's version time near the ends of the integer range. | #57 `a40e674` | `net-hardening` |
| `fuzz-deserialize` | `ReadCompactSize` took any width and callers kept the result in 32 bits, so one transaction had many wire encodings. | #64 `14564fc` (shortest form only, nothing above `MAX_SIZE`; validity of blocks and transactions unchanged) | `serialize-canonical` |
| `fuzz-deserialize` | A relayed or held orphan `tx` kept the whole payload, including bytes after the transaction. | #64 `14564fc` (held and relayed re-encoded) | `serialize-canonical` |
| `fuzz-deserialize`, UBSan | `CDataStream` from an empty vector and `HexStr` of an empty range dereferenced null. | #64 `14564fc` | `serialize-canonical` |
| `fuzz-decoders`, UBSan | `uint256::SetHex` indexed its table with a signed `char`. | #64 `14564fc` | `decoder-canonical` |
| `fuzz-decoders` | An onion endpoint kept a port's leading zeros (two normal forms). | #64 `14564fc` | `decoder-canonical` |
| `fuzz-decoders` | A `.btf` v1 name ignored three padding bits, so each key answered to eight names. | #64 `14564fc` | `decoder-canonical` |
| `fuzz-decoders` | Descriptor hex was read with `sscanf("%2x")`, which also takes white space, a sign and `0x`. | #64 `14564fc` | `decoder-canonical` |
| `fuzz-decoders`, review | `EncodeBase58` of an empty vector; `DecodeBase58` and `ParseMoney` passed a negative `char` to `isspace` and `isdigit`. | #64 `14564fc` | `decoder-canonical` |
| `fuzz-decoders`, honggfuzz on Actions | The `std::string` overloads of the address readers handed `c_str()` on, so an address followed by NUL and more bytes read as the address. | #64 `14564fc` (a NUL is refused) | `decoder-canonical` |
| independent review of #64 | The light client's saved state could fail to load under the stricter reader and stop swaps in that coin. | #64 `14564fc` (an unreadable saved entry is dropped and logged) | `btc-light` |
| `fuzz-net-message`, 711 leak reports in fork mode | Not a node defect: libdb's own region blocks, which a heap scan cannot trace to a pointer. A Berkeley DB handle the node leaks is still reported (that is how the first row was found). | #69 `dc5fefb` (one LeakSanitizer setting for every node harness; a `fork` input for the campaign) | none (no node code changed) |
| `fuzz-script` (signature-count invariant) | `OP_CHECKMULTISIG` is charged 20 signature operations but checks one signature per key, and the key count was bounded only by the stack, so a computed count checked more than was paid for. | #65 `9133c5d` (relay and mining policy: a literal `OP_0`..`OP_16` count, checked before any signature; rules v5, unscheduled: at most 20 keys) | `script-sigops`, `rules-v5` |
| reading `AcceptTransaction` for the above | The clock was read twice for one transaction's signature count, either side of the v4 switch. | #65 `9133c5d` | none (needs the clock to step between two calls) |
| independent review of #65 | A refused transaction was reported as missing inputs and kept as an orphan; `spendscript` named the wrong cause. | #65 `9133c5d` | `script-sigops` |
| `fuzz-p2pool`, `fuzz-light-peer` | No crash or sanitizer report from either harness. The share chain work came from the DoS review (H4 share side, M6, L6) and its independent reviews, which found that the first byte cap could split nodes (it could evict a share at the tip's height) and that the first budgets starved honest unproven peers; all fixed before merge. The light-client harness needed a fuzz-only switch to get past the proof-of-work comparison, in that binary alone. | #66 `134dc25` | `p2pool-dos`, `p2pool-chain`, `btc-light` |
| `fuzz-tor-control`, `fuzz-socks5`, `fuzz-rpc-preauth`, `fuzz-rpc-postauth`, `fuzz-http-client` | Tor control replies: a bootstrap percentage read from an error reply, a hostname file taken unchecked, a `Bridge #` comment turned into a bad torrc line. RPC: `Content-Length` wrapping, credentials looked for outside the `Authorization` header, a silent caller holding the single-threaded server, JSON nested hundreds of thousands of levels deep copied or printed recursively, a JSON float read as an integer in `signrawtransaction` (undefined conversion). HTTP client: a bare-newline IP echo answer that made `substr()` throw in a thread that catches nothing and ended the node, `999.1.1.1` accepted as an external address, a WebSocket upgrade accepted on ` 101 ` anywhere in the headers, oversized pings answered with a corrupt pong, an empty error message reported as no error. The full table is under "Fuzzing (`fuzz`, and ClusterFuzzLite on GitHub)". | #72 `ea6b54a` | `reply-parsers` |
| `fuzz-chat-frame`, `fuzz-chat-relay`, `fuzz-nostr`, `fuzz-swap` | No crash in production code from the harnesses; the DoS items M7, M8, M10 and L4 above are fixed in the same PR. Two parser defects came with them: integers in frames and epoch announcements read with `value()` cast an out-of-range float with undefined behaviour and truncated 1.9 to 1, and Nostr hex fields read with `sscanf("%2x")` took a sign and `0x`, so two spellings named one key. | #70 `2c86386` | `chat-dos`, `nostr-relay`, `swap-prune` |

#### Found while raising self-test coverage

Part C added self-tests for the orphan transaction and orphan block pools, every script opcode (`script-opcodes`, 488 rows) and the block index load path (#73, no production code). Writing and reviewing the opcode self-test found this:

| finding | what was wrong | fixed in | self-test |
|---|---|---|---|
| independent review of the `script-opcodes` self-test (High) | `CBigNum::getint()` kept OpenSSL's 64-bit word in an `unsigned long`, 32 bits on Windows: a script number of 2^32 read as 0 there and as `INT_MAX` on Linux. Script numbers have no 4-byte limit here, so `OP_PICK`, `OP_ROLL` and both `OP_CHECKMULTISIG` counts could be handed one, and a block spending such a script would have been valid on one operating system and invalid on the other. Windows nodes now read these numbers as Linux nodes always did. No script on either chain ever used such a value (225,066 mainnet and 28,446 testnet scripts scanned: no `OP_PICK` or `OP_ROLL`, every multisig count a literal), so the fix rejects nothing the network has accepted. | #71 `3980581` | `bignum-int` (6 checks fail on a Windows build of the old code) |


### Leak reports: which were bugs and which were not

Two of the leak reports in this run were real bugs, and both are fixed. The
rest (711 reports in one fuzz campaign) were Berkeley DB's own memory arena,
not leaks. Every report, with the evidence:

| report | verdict | evidence | where |
|---|---|---|---|
| `fuzz-net-message`, first pass: a `Db` handle and the file's use count after a failed Berkeley DB open | **real leak, fixed** | reproduced from its input; the stack runs through node code (`new Db` in `CDB::CDB`), and the fix makes it go away; a failed open threw `DbException` past the cleanup | #56 `3bb7c75`, self-test `db-open-failure` |
| `fuzz-p2p-payload`: every duplicate block given to `ProcessBlock` | **real leak, fixed** (with a double free of refused blocks in the orphan pool) | reproduced from its input; `ProcessBlock` returned without freeing a block it already had | #57 `a40e674`, self-test `net-hardening` |
| `fuzz-net-message` campaign 42967191269: 711 reports in fork mode | **not a leak** | fork mode keeps no stacks and none of the 711 inputs reproduces a leak alone. A 5.5-hour single-process run (43093941370, 22.7 M inputs) stopped on exactly one report: two blocks, 136 bytes, allocated once by `DbEnv::open` inside libdb (`__env_alloc` -> `__os_malloc`) when the environment opened, and the environment opened exactly once in the process. Berkeley DB references those regions by offset, which a heap scan cannot follow, so LeakSanitizer sees blocks with no pointer to them. The setting covers only allocations made inside libdb; a handle the node leaks is still reported (the first row shows it is). After the change the fork-mode campaign 43218776499 reported nothing | #69 `dc5fefb` (one LeakSanitizer setting in `fuzz_datadir.h` for every node harness; no node code changed) |
| self-tests under AddressSanitizer + LeakSanitizer, every pass of this run | none reported | [[FINAL: the final pass reports 0 leaks across every self-test; fill with the count]] | |

### Design differences from Bitcoin that the tests pin

These are not bugs. Bitflash descends from Bitcoin 0.1.0, and the self-tests
(`script-opcodes` has 488 rows) pin the behaviour as it is, so that a change
to any of them is deliberate and shows up as a failing test.

- **Unassigned NOPs fail the script.** There are no `OP_NOP1` to `OP_NOP10`
  here, so there is no NOP upgrade path: a new rule needs a new rule set, not
  a redefined NOP. Rules v4 is built that way (CSV, CTV and CSFS fail before
  activation).
- **No 4-byte limit on numeric operands.** Script numbers may be any length.
  That is why the width of the number reader matters: see the `getint` row
  under "Found while raising self-test coverage".
- **`OP_VERIF` and `OP_VERNOTIF` depend on the rule set.** Before rules v3
  they open a branch, even inside a branch that is not taken; from rules v3
  they fail the script.
- **`OP_CHECKMULTISIG` keys are not added to the 201-opcode count.** The
  operation is charged 20 signature operations whatever the key count. Relay
  policy now requires a literal key count, and rules v5 (unscheduled) cap it
  at 20 (see the script-engine section).
- **Strict signatures are not monotone under rules v2.** A non-DER signature
  makes `OP_CHECKSIG` return false rather than fail, so `CHECKSIG NOT` can
  pass, as in Bitcoin before NULLFAIL. Already active consensus.
- **BIP119 without the scriptSigs field**, and the signed `nLockTime` limit for
  CLTV, are documented and left as they are.
- **Rules v4 activate by each block's own time, not the median.** Safe,
  because every v4 spend needs an opcode that fails before activation.
- **No `MAX_SCRIPT_SIZE`.** See the script-engine section.

### Fuzzing

Every harness is described, with what it feeds and what it aborts on, in
"Fuzzing (`fuzz`, and ClusterFuzzLite on GitHub)" above, and the Tor,
SOCKS5, RPC and HTTP client harnesses and what they found are there too. The
results of each harness family are in its own section:

- Deserializers and decoders: "Deserializers and decoders" below (#64).
- Script engine and the v4 templates: "The script engine under every rule set" below (#65).
- P2Pool and the light clients: "P2Pool and the light clients" below (#66).
- Chat, Nostr and swap negotiation: "Chat, Nostr and swap negotiation" below (#70).

The first pass ran each of the four earliest targets (`fuzz-script`,
`fuzz-net-message`, `fuzz-sigcheck`, `fuzz-light-pow`) for an hour per engine,
twelve hours in all, and found the `Db` leak above and nothing else. The
second and third engine added almost nothing to a corpus the first had
grown, so for those harnesses more hours on the same code buy little.

The 2 h or more per engine of evidence for each harness is the per-PR
campaigns, run on the code each PR merged, with AddressSanitizer and
UndefinedBehaviorSanitizer: 42967191269 and 43093941370 (and 43218776499
after the LeakSanitizer setting) for the P2P envelope, 43130125511 for the
script engine and v4 templates, 43275125594 for P2Pool, 43246516215 for the
light-client peers, 43236831520 and 43313720157 for Tor control, SOCKS5, RPC
and the HTTP client, 43322910038 for chat, Nostr and swap negotiation, plus
the runs of #64 named in its section. The final full pass on `main` (below)
runs every harness for 30 minutes per engine as a regression pass on the
merged code; it is not a substitute for those.

### Coverage

Line coverage of the self-tests, measured with llvm-cov on Linux. Before is
audit run 3 (`12bedaa`); after is `main` at `097437e`, with the 97
self-tests then present, 0 failures. The per-harness coverage of the fuzz
corpora is in each harness's section.

| file | before | after |
|---|---|---|
| `main.cpp` | 35.77% | 62.06% |
| `script.cpp` | 62.70% | 85.41% |
| `serialize.h` | 69.33% | 73.95% |
| `db.cpp` | 50.17% | 61.15% |
| whole node | 54.96% | 64.89% |

The gain came from the self-tests of #73 (the orphan transaction and orphan
block pools, every script opcode in 488 rows, the block index load path) and
from the self-tests that pin the fixes above.
The first-pass gap, that `ProcessBlock`, `CheckBlock` and `AlreadyHave` were
never reached by `fuzz-net-message` because of the envelope checksum, is
closed by `fuzz-p2p-payload`. The final pass re-measures:
[[FINAL: whole-node and per-file self-test coverage on `2c86386`, same
llvm-cov command as above]].

### Checked and not a defect (first pass of the tools)

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
- **Clang Static Analyzer** (39 after the fixes): dead stores, and
  "stream in EOF state" on the usual read-until-EOF loop; `recv` inside a lock is
  always after `poll` said data is waiting; a division whose divisor is a
  sum of positive work values.
- **clang-tidy** (203): mostly unchecked `fclose`/`fwrite` results;
  `atoi` on strings already checked to be digits; widening casts of values
  bounded by the protocol.
- **flawfinder** (48, level 4 and 5): format functions with constant formats
  (the build fails on a format mismatch, `-Werror=format`), `system()` with
  an id that is 32 hex characters, `chmod` on the Tor data directory right
  after `mkdir` with mode 0700, `readlink` on `/proc`. The one real finding
  (the `.cookie` and key dump) is in the table above.
- **Semgrep** (`p/c`, `p/secrets`): nothing.
- **Linked system libraries** on the auditing host: everything with a
  published fix was updated (OpenSSL 3.5.7, zlib, SQLite, Tor 0.4.9.15); what
  remains has no fix yet in Debian.
- **CodeQL**: the alerts that pointed at real problems are in the table
  above. Three `cpp/path-injection` alerts were dismissed: the data
  directory comes from the operator's own `-datadir` or `HOME`, and the key
  dump path from an RPC caller who is already authenticated and controls the
  wallet; both files are now created owner-only, never through a symlink.

### Valgrind, heaptrack, reproducible build

First pass, before the later fixes:

- **Valgrind memcheck**: 14 of 65 self-tests reported. Twelve
  were Berkeley DB writing the unused bytes of its pages and log records to
  disk (suppressed with that reason, `scripts/audit/valgrind.supp`; the
  library's own `--enable-umrw` exists for exactly this). Two were the light
  client's worker threads reading freed globals at exit, fixed above. After
  both: 65 self-tests, 0 reports.
- **ThreadSanitizer**: no report in any of the 52 node self-tests then
  present, after the fixes above (Berkeley DB's own latches suppressed,
  `scripts/audit/tsan.supp`).
- **heaptrack**: the heaviest self-tests peak at 41.5 MB (explorer), 9.5 MB
  (P2Pool chain), under 0.5 MB for the rest; each holds a few kilobytes at
  exit in one-time allocations, and neither LeakSanitizer nor Valgrind reports
  a definite leak.
- **reprotest**: the node built twice, under a different time, time zone,
  locale, umask, environment, build path and directory order, is bit for bit
  identical.

The final pass repeats all of these on the last commit (next section).

### Open by design or deferred, and why

- **M9, side-branch storage (also consensus 5).** A block on a branch that is not the best is stored after cheap checks, and the branch's own timestamps set its difficulty, so a weak branch can take disk and index space. A first version of an admission rule was removed after review: without headers it judges a block by the work before it, never by what follows, so it could leave a node on the lighter chain for good, which is a reorganisation limit by another name. The real fix is headers-first sync (take a branch's headers, download a body only once its header chain has more work than ours), which is a larger change. Until then the space a weak branch can take is bounded by elapsed time, and rules v5 removes the timespan wrap.
- **L4 (swaps), several outputs to one contract.** Two payments to one light-mode contract make the audit throw, so the swap does not move on its own. Fixing it means tracking several outputs per contract. Nothing is lost: each payment can be refunded by hand from `swaps.log`.
- **BIP39 NFKD normalisation of non-ASCII passphrases.** Applying NFKD now would change the seed of every existing wallet whose passphrase has accents. The wallet warns when the phrase password is not ASCII. A change needs a migration that tries both forms.
- **Rules v5 is unscheduled by design.** It is a soft fork (retarget time, own-block coinbase, unsigned lock time, pre-v4 CSFS sigops, a 20-key multisig cap) that needs a date and miner signalling. `RULES_V5_TIME_*` is 0 (never) on both networks; nothing changes on mainnet or testnet until a release sets a date.
- **DoS L2, reject cache.** Invalid transactions are still verified again each time they arrive. The orphan part is fixed (#65: a refused transaction is no longer kept as an orphan); a cache of refused ids needs a policy for what to remember and for how long, and is not a change for the week of a release.
- **DoS L3, light-client block storage.** The light client keeps whole foreign blocks and rewrites them on every save. Fixing it needs a new state format for the light clients, the same change that the swaps M1 remainder below needs.
- **DoS L5, v1 RandomX cache check.** A pre-switch block can make a node that has not allocated the v1 cache build it. The fix is a timestamp check before the hash in `CheckBlock`; that is consensus code, and it is not touched this close to a release.
- **Swaps M1, remainder.** The per-contract "still scanning" gate and expiry of watches on contracts that were never funded need a change to the light client's state format. The remote trigger is closed.
- **Wallet: dust rule (I6)** and the secure allocator for the global seed copies and the `DumpWallet` hex temporaries (part of L3).
- **P2P, from the review of #59.** Per-command message size caps at the header (the effective receive bound is about 37 MB; it needs each owner's maximum message size); a cross-peer ceiling on queued bytes; identifying inbound onion peers by their rendezvous circuit (needs PROXY-header parsing in both listeners); penalties for bad pool submissions (pool operator code).
- **Script size.** There is no `MAX_SCRIPT_SIZE`; the work per operation is linear in script size, bounded by the block size. A candidate rule for a later rule set, not measured as a problem (see the script-engine section).
- **Chat, left for 1.2.34** (from the second review of #70; none is a way in, each serves an honest user worse than possible): an idempotent receipt for a frame refused only as a replay after a failed save; a "duplicate" answer instead of "slow down" for a record already held; a longer age (8 to 10 s) before a handshake can be evicted; a cut flag on a `chatget` cut by the answer ration; work for records put at a node under half full; per-source sub-budgets. The details are in "Chat, Nostr and swap negotiation" below.
- **Test gaps, swaps.** A paid-lock case in `swap-rpc` and an automated check of the "paid, unpaid or unknown" answer need a node that accepts inputs and a fake Core RPC server. The testnet proof with coins covers the paid case.

### Release notes

Pull requests with behaviour users notice. The full lists are in the PR bodies (#62, #63, #64 and #70 each have a section for release notes).

- **#60: P2SH only after rules v3 lock in.** The wallet's `C...` addresses, `script:` outputs and swap funding wait until the tip's median time passes the switch, and relay accepts P2SH outputs only then. **This must be in a release before 2026-11-21 12:00 UTC** (the rules v3 switch).
- **#71: script numbers read the same on Windows and Linux (consensus).** No visible change on any existing block, but Windows nodes read numbers of 2^32 and up in `OP_PICK`, `OP_ROLL` and `OP_CHECKMULTISIG` as Linux nodes always did. **This must also be in a release before 2026-11-21 12:00 UTC**, with #60; all Windows users should upgrade.
- **#62: wallet.** `-restorephrase=WORDS` is refused (stdin or `@FILE` instead); `getbalance` at the default `minconf=1` no longer counts other people's unconfirmed payments; GUI Send has a review step; `/maxtxfee` (default 1 BTF); `/walletunlocktimeout`, RPC `walletlock`, `unlocked_until` in `getinfo`; encrypted wallets: phrase install and restore refused while locked, and a plaintext seed or a damaged key pool left by older versions is repaired at the next unlock; `vaultcreate` and `ctvbatch` refuse templates that cannot be mined or relayed, and warn that their addresses take one deposit; upgrade-hook spends are not relayed by default; data files owner-only on POSIX.
- **#63: swaps.** BTF contracts lock by median time (48 h initiator, 18 h participant); offers and takes carry `"v":2` and old ones are refused, so both sides need the same release; every lock is journaled before it is paid; new RPC `swaplookup`; `swaps.log` and `btfchat.dat` owner-only.
- **#64: parsers.** Raw transaction hex whose lengths are not in the shortest form is refused (external tools must write the shortest form); a `.btf` name with non-zero padding bits is refused; onion ports are normalised; address strings with an embedded NUL are refused; the light client drops a saved entry that no longer reads.
- **#59: P2P.** Wire compatible. Sync serves 500 blocks per request and ends each batch with a tip hint; at most 117 inbound peers, with eviction when full; `debug.log` rotates at 50 MB; a misbehaving peer is dropped at once.
- **#61: consensus safety.** Failed blocks are marked instead of deleted; the memory pool refuses non-final transactions; orphan blocks are bounded by bytes.
- **#65: multisig key count (relay and mining policy).** A transaction whose script runs `OP_CHECKMULTISIG` on a computed key count is no longer relayed or mined (wallets here never build one), and a refused transaction is no longer kept as an orphan. Rules v5, which cap keys at 20, are unscheduled.
- **#66: P2Pool.** Shares and history requests from peers that have not yet sent an accepted share draw on shared budgets and are held and served later, oldest connection first; an inbound peer that leaves more than 4 MB of a history unread for 15 minutes is disconnected while inbound queues are full; the share chain is capped at 128 MB (more if the tip's own line needs it), and lines close to the tip are never evicted.
- **#70: chat, Nostr and swap negotiation.** A node asks more work for a chat record once its store is half full (4 and 6 bits more at three quarters and nine tenths), and the chat app of this release mines again to what the node asks. **Chat apps of 1.2.32 and before cannot store a record on a store at or above half full, and cannot replace their own descriptor in a full one**; this happens only while a store is being filled, and only while it stays that full (records are kept 26 hours). The chat app's listener has connection limits and timeouts; Nostr discovery checks event signatures and dates and has ceilings; swap offers are taken one at a time per peer and old finished swaps are pruned. Per-source sub-budgets are not part of this release, and the text says so.
- **#72: RPC and Tor parsers.** An RPC connection that sends nothing, or stops reading, is closed after 30 s; `Content-Length` must be a plain decimal number; JSON nested deeper than 64 levels is refused; `signrawtransaction` needs an integer prevtx `vout`; a `Bridge #...` line in `bridges.txt` is ignored.
- **#56: packaging.** Tor Expert Bundle 16.0 (tor 0.4.9.15) in the release packages; RPC cookie and key dump created owner-only.
- No visible change: #57, #58 (rules v5 unscheduled), #69, #73.

### Final pass

The final full pass on `main` at `2c86386` is GitHub Actions run 43352384854:
every harness for 30 minutes per engine as a regression pass, and the
self-tests under AddressSanitizer + UndefinedBehaviorSanitizer, ThreadSanitizer
and Valgrind; and on the Debian 13 server: secrets, dependencies, static
analysis, heap, coverage and the reproducible-build check. The 2 h or more per
engine of evidence per harness is the per-PR campaigns listed under "Fuzzing"
above; the final pass is a regression run on the merged code.

| phase | result |
|---|---|
| secrets (Gitleaks, Trivy) | [[FINAL: hits and verdicts, expected only the known entries listed above]] |
| dependencies (OSV, Trivy on system libraries) | [[FINAL: advisories, if any, and their status]] |
| static (cppcheck, flawfinder, Semgrep, clang-tidy, Clang Static Analyzer, CodeQL) | [[FINAL: counts per tool against the first-pass numbers above, new findings if any]] |
| ASan + UBSan + LSan, every self-test | [[FINAL: self-tests run, reports]] |
| TSan, every self-test | [[FINAL: self-tests run, reports]] |
| Valgrind memcheck, every self-test | [[FINAL: self-tests run, reports]] |
| heaptrack | [[FINAL: heaviest peaks, definite leaks]] |
| fuzz regression, every harness, 30 min per engine (libFuzzer, AFL++, honggfuzz) | [[FINAL: per harness: executions, corpus, crashes]] |
| reprotest | [[FINAL: bit for bit identical, or the differences]] |
| self-test suites | [[FINAL: Windows count, Linux count, failures]] |

### Final state

[[FINAL: on `main` at `2c86386`, every self-test under the three instruments, 0 failures and 0 reports; both platforms' suites pass; or what remains]]

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

## Chat, Nostr and swap negotiation (`fuzz-chat-frame`, `fuzz-chat-relay`, `fuzz-nostr`, `fuzz-swap`)

What strangers can hand the node, or the chat app, in the chat, in relay JSON
and in a swap negotiation. The harnesses feed the real entry points listed in
the table above; the DoS items below came from the manual resource review and
are fixed here, each with a self-test (`chat-dos`, `nostr-relay`,
`swap-prune`; `make tests` runs them).

| found by | what | fix |
|---|---|---|
| review M7, `chat-dos` | A chat store at its budget refuses everyone, and filling it cost the same work for the last record as for the first; the per-connection rations reset on every reconnect; a `chatrec` nobody announced was taken (and its work checked). | The work asked grows as a kind's budget fills (+2 bits from half, +4 from three quarters, +6 from nine tenths) and a refusal says how many bits it asks, so the chat app mines again (`btfchatnet.cpp`); `chatrec` is taken only for an id the same peer announced; chat puts and relayed records are rationed for the whole node as well as per connection, charged only for a record that shows the work the store asks and is kept (junk and replays cost the node nothing); a record relayed by another node needs the base work plus the fullness less one step (2 bits), so relayed records cannot fill a budget at the base price, though one source can still fill a budget at a rising price (no per-source sub-budgets); a connection that does not read its answers gets empty ones, and one that has been served its minute's bytes too (16 MB per connection, 256 MB for the node). |
| review M8, `nostr-relay` | Discovery believed the `pubkey` of any event a relay named, without checking its signature; a `created_at` in the future sorted first for good and was never pruned; the peer table, the pool list and the dial-state maps had no ceiling. | Every event is checked (id is the hash of the event, BIP-340 signature) before its key is used; dates more than ten minutes ahead, or older than the peer age limit, are refused; at most 50 new addresses per relay per round, 2000 peers, 200 pools, the oldest dropped to make room; a published pool name and dashboard URL are clamped to the size every node accepts; pool announcements must be signed by the key whose address they name, and the list is pruned when something is added; the backoff, failure and ever-connected maps follow the table. |
| review M10, `chat-dos` | The chat app's listener started a thread for every inbound connection, wrote two unconditional log lines each and saved the whole sealed store after every delivered frame. | 32 serving slots (when all are taken, the oldest connection still in its handshake, if it has had five seconds, is put out; if all have finished theirs the new one is closed), a 20 s handshake timeout, a 5-minute limit on a connection, a connection closed at its first refused frame, `LogPrint` for the per-connection lines, and the store saved before the receipt (no receipt if the save failed), at most once a second. |
| review L4, `swap-prune` | Every `take` with a fresh swap id from a contact created a swap that stayed for good, and the seen-step ids were never pruned; both are written out whole on every change. | One take of an offer at a time per peer, eight takes per peer; a finished swap is dropped after 30 days, and past the newest 100 only if it never locked anything of ours (one with a contract is kept the 30 days); the seen-step ids are cut to the ones a conversation still holds, and not while the chat is locked; a take older than the time to answer is ignored. |
| `fuzz-decoders`-style round trip (`chat-dos`) | Integers in frames and epoch announcements were read with nlohmann's `value()`, which casts a float out of range (1e300 as an int) with undefined behaviour and truncates 1.9 to 1. | `JsonIntValue` (`jsonsafe.h`): an integer that fits, or the same refusal as a field of the wrong type. |
| `fuzz-nostr` (review) | Hex fields were read with `sscanf("%2x")`, which also takes a sign and `0x`, so two spellings named one key. | Exactly two hex digits per byte. |

Left for 1.2.34, from the second independent review (none is a way in; each
is a case where an honest user is served worse than he could be):

- A frame accepted in memory whose store save then fails (a full disk, or the
  chat locked between delivery and save) gets no receipt; the sender sends it
  again, the replay guard refuses the copy, and the sender keeps retrying
  until the frame expires. The fix is an idempotent receipt for a verified
  frame refused only as a replay.
- A record the node already holds, put again after the node-wide ration is
  spent, is answered "slow down" instead of "already held", so the app may
  report a stored put as failed.
- The five seconds a handshake must have had before it can be put out may be
  short for three flights over a slow onion circuit (8 to 10 s is safer; the
  20 s handshake timeout still bounds it).
- A `chatget` cut by an answer-byte ration returns empty answers that the app
  cannot tell from an empty mailbox; a "cut" flag would let it ask again.
- A record put at a node under half full carries only the base work, so it no
  longer reaches a node three quarters full or more; the app could mine two
  bits over what its node asks.
- There are no per-source sub-budgets: one source can still fill a kind's
  budget, at a price that rises as it fills.

Runs: Actions "Audit campaign" 43322910038, on the final production code, 2 h
10 min per job on each of the three engines with AddressSanitizer +
UndefinedBehaviorSanitizer: no crash file for any target on any engine.
Corpus after each engine (libFuzzer, AFL++, honggfuzz) and merged:
`fuzz-chat-frame` 3,996 / 9,103 / 4,618, merged 2,309; `fuzz-chat-relay`
7,399 / 7,257 / 9,653, merged 2,621; `fuzz-nostr` 8,480 / 8,628 / 10,498,
merged 2,662; `fuzz-swap` 5,040 / 4,993 / 7,642, merged 2,120. Self-tests on
the final commit: Linux (the 202) `make tests` 90 passed, 0 failures, and the
four smokes; Windows through the CI job.
