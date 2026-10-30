# Consensus rules v4 (design)

Status: design, not scheduled on mainnet. Nothing here is live until a release
sets the switch times below and the founder announces it.

Rules v4 add three things a script can say, each the way Bitcoin says it or
has proposed to, so that a contract written for one chain reads the same on
the other wherever the two chains allow it:

| rule | what it lets a script say | Bitcoin |
|---|---|---|
| CSV, relative lock time | "not until N blocks (or N x 512 s) after the coin I spend was mined" | BIP68 + BIP112, live since 2016 |
| CTV, `OP_CHECKTEMPLATEVERIFY` | "only by a transaction shaped exactly like this" | BIP119, proposed |
| CSFS, `OP_CHECKSIGFROMSTACK` | "this key signed this message" (any message, not only this transaction) | BIP348, proposed |

What they are for, here: vaults (coins that can only move to a recovery key or
through a delay), inheritance (coins an heir can take once the owner has gone
quiet, `docs/inheritance.md`), payment channels and their penalty windows, swaps that do
not need an absolute deadline, congestion batching (one output that unfolds
into many payments later), and oracle-signed contracts. None of them changes
what a coin is or adds new money.

Not in v4: SegWit and Taproot. The work they would take goes into the
shielded pool instead (see the privacy roadmap). That choice shapes CTV below.

## Switch

| network | block time | UTC |
|---|---|---|
| testnet | `1798200000` | 2026-12-25 12:00:00 (at the latest; earlier if ready) |
| mainnet | `0` (never) | to be fixed, planned for May 2027 |

`RULES_V4_TIME_MAINNET = 0` means "never" in the code until the date is
decided. As with rules v2 and v3, every rule is checked against the time of
the block being connected (median time past for lock times), and everything on
either chain before the switch keeps its validity.

Rules v4 need rules v3 (P2SH and median-time-past finality) and switch only
after them.

## CSV: relative lock time (BIP68, BIP112)

### BIP68: nSequence as a relative lock

From the switch, in a transaction with `nVersion >= 2`, each input's
`nSequence` is a relative lock unless its bit 31 is set:

- bit 31 (`1 << 31`) set: no relative lock on this input (every transaction
  made so far has `nSequence` 0xffffffff, 0xfffffffe or 0xfffffffd, all with
  bit 31 set, so nothing existing is affected);
- bit 22 (`1 << 22`) set: the low 16 bits count units of 512 seconds of median
  time past; clear: they count blocks;
- the other bits mean nothing yet and are ignored.

An input with a height lock of `n` may be in a block at height `H` only if
`H >= coin height + n`. An input with a time lock of `n` may be in a block
whose parent's median time past is at least `MTP(block before the coin's
block) + n * 512`. Exactly Bitcoin's arithmetic (`CalculateSequenceLocks`).

Mempool and mining check the same thing for the next block. A transaction
spending an output of a mempool transaction counts that coin as mined in the
next block.

Implementation note: the coin's height comes from the block index entry whose
disk position the transaction index points to; a map from `(nFile,
nBlockPos)` to `CBlockIndex*` is kept next to `mapBlockIndex` for that.

### BIP112: `OP_CHECKSEQUENCEVERIFY` (0xb2)

The byte Bitcoin uses. It reads the number on top of the stack (up to 5
bytes) and fails the script unless:

- the number is not negative;
- if its bit 31 is set, it does nothing (reserved for later rules);
- otherwise: the transaction has `nVersion >= 2`, this input's `nSequence`
  has bit 31 clear, both use the same unit (bit 22), and the input's masked
  value is at least the script's.

It leaves the number on the stack (followed by `OP_DROP`), as Bitcoin does.
Before the switch the byte is unknown and fails any script that runs it,
exactly as `OP_CHECKLOCKTIMEVERIFY` did before rules v3.

## CTV: `OP_CHECKTEMPLATEVERIFY` (0xb3)

The byte Bitcoin's proposal uses. With a 32-byte value on top of the stack, it
fails the script unless that value equals the template hash of the spending
transaction for this input. With any other size on top it does nothing
(reserved, as in BIP119). Empty stack: fails. The value stays on the stack.

### The template hash, and the one change from BIP119

BIP119's hash is SHA-256 (single) of:

```
nVersion (4) | nLockTime (4) | [scriptSigs hash (32)] | input count (4) |
sequences hash (32) | output count (4) | outputs hash (32) | input index (4)
```

where the scriptSigs hash is present only if any input has a non-empty
scriptSig. Committing to the scriptSigs is what fixes the txid of a legacy
spend. It also makes CTV impossible inside pay-to-script-hash: the scriptSig
of a P2SH spend contains the redeem script, which contains the template hash,
which would have to cover itself. Bitcoin does not mind, because there CTV
lives in SegWit or Taproot, where scripts sit in the witness. Bitflash has no
witness, and P2SH is the only way a contract output is relayed and paid by the
wallet.

So Bitflash's template hash leaves the scriptSigs field out, always:

```
nVersion | nLockTime | input count | sequences hash | output count |
outputs hash | input index
```

Everything else is BIP119's: the same field order, sizes and encodings, so a
tool written for BIP119 needs only that one field dropped.

What that costs: the txid of a CTV spend is not fixed in advance, since
anyone relaying it can add a push to a scriptSig. CTV itself does not care,
because a template commits to outputs and sequences, never to the txids of
the coins being spent, so a tree of CTV transactions still unfolds whatever
the txids turn out to be. A contract that pre-signs a *non*-CTV child of a
CTV spend (signing commits to the parent's txid) must not rely on that txid.
The wallet's own contracts will not do that.

## CSFS: `OP_CHECKSIGFROMSTACK` (0xcc)

The byte BIP348 uses in Tapscript. It takes three items, the public key on
top, then the message, then the signature, and:

- fewer than three items: fails;
- an empty key: fails;
- a 32-byte key: a BIP340 Schnorr check of the signature over the message
  (any length, as BIP340 allows). An empty signature pushes false. A
  non-empty signature that is not 64 bytes, or does not verify, fails the
  script (the NULLFAIL rule: only an empty signature may be false);
- any other key size: pushes true without checking (reserved for later key
  types, as in BIP348).

It pushes true or false; scripts follow it with `OP_VERIFY` or use the result.
Each one counts as a signature operation against the block limit, when it sits
in a P2SH redeem script (counted the way rules v3 count `OP_CHECKSIG` there)
and, from the switch, in any script.

libsecp256k1, already linked and verifying every ECDSA signature, has the
BIP340 module built in.

## What old nodes see

As with `OP_CHECKLOCKTIMEVERIFY`, a node from before v4 never runs a P2SH
redeem script beyond checking its hash, so a contract in P2SH looks like any
P2SH spend to it. The relative-lock rule only removes transactions from what a
block may hold. A bare script with one of the new bytes fails on an old node
and is not relayed by anyone (non-standard). Miners must upgrade before the
switch; other nodes should.

## In the wallet: a vault and a batch

(Inheritance, the third use the wallet makes of these rules, has its own
page: `docs/inheritance.md`.)

**Vault** (`vaultcreate`, `vaultunvault`, `vaultwithdraw`, `vaultrecover`,
`docs/rpc.md`). Two scripts, both P2SH:

```
vault:    <template hash> OP_CHECKTEMPLATEVERIFY
unvault:  OP_IF
              <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
              OP_DUP OP_HASH160 <hot key hash> OP_EQUALVERIFY OP_CHECKSIG
          OP_ELSE
              OP_DUP OP_HASH160 <recovery key hash> OP_EQUALVERIFY OP_CHECKSIG
          OP_ENDIF
```

The template hash fixes the only transaction that can spend the vault: one
output, to the unvault script, of the amount less a fee paid in advance. So
the coins cannot go anywhere else, whoever holds which key; they can only be
unvaulted, in the open. From the unvault output the hot key can take them
`delay` blocks after it confirms, and the recovery key at once. A thief with
the hot key has to unvault first, and the owner, seeing it, has `delay` blocks
to recover everything with a key the thief does not have. The recovery key
belongs somewhere else than the wallet that makes the vault: on paper, a
hardware device, another machine.

**Batch** (`ctvbatch`, `ctvexpand`). `<template hash> OP_CHECKTEMPLATEVERIFY`
over a transaction paying many people: one output on the chain now, the
payments later, by a transaction anybody can broadcast and nobody can change.
What it is for: paying many people when fees are high, with the payments
already settled.

Both are refused while rules v4 are not in force: before them,
`OP_CHECKSEQUENCEVERIFY` and `OP_CHECKTEMPLATEVERIFY` do nothing, and coins
behind them could be taken by anybody. The scripts and keys are kept in
`v4contracts.json` beside the wallet, and every result carries the redeem
scripts, with which `spendscript` alone can spend them.

What CTV costs here: the fee of the transaction it fixes is fixed with it. It
cannot be raised later; pick it generously.

## Order of work

1. `consensus.h`: `RULES_V4_TIME_*`, `RulesV4Active`; the flag threaded
   through `VerifySignature`/`EvalScript` next to `fRulesV3`.
2. CSV: BIP68 in `ConnectInputs`, mempool and the miner; BIP112 in
   `EvalScript`. Self-test with Bitcoin's CSV test vectors.
3. CTV: the template hash, then the opcode. Self-test with BIP119's vectors,
   adjusted for the dropped field, plus hand-checked cases.
4. CSFS: the opcode and its sigop count. Self-test with BIP340's vectors and
   BIP348's.
5. Wallet and RPC: a timelocked vault and a CTV batch that the wallet can make
   and spend; `decodescript` names the new opcodes.
6. Testnet with coins: every path spent, every failure tried on a live chain,
   before any date is set on mainnet.

## Proven on an isolated testnet bench (2026-10-24)

Two nodes forked off the testnet at height 9642 with `-isolate` (no cached
peers, seeds, Nostr or peer exchange; each dials the other with
`-connectbtf=ADDRESS@HOST.onion:PORT`) and `-benchrulesv4=<time>`, which moves
the switch on that bench only and is refused on mainnet and without
`-isolate`. One mined, the other validated every block it was sent. Contracts
were built with `templatehash` and spent with `spendscript` (`docs/rpc.md`).

| case | result |
|---|---|
| CTV, outputs other than the template | refused |
| CTV, the template's outputs in a version 1 transaction | refused |
| CTV, exactly the template | in block 9643 |
| CSFS, BIP340 vector 0 with one bit of the signature flipped | refused |
| CSFS, BIP340 vector 0 | in block 9643 |
| CSV 2 blocks, input nSequence 1 | refused (script) |
| CSV 2 blocks, version 1 transaction | refused (script) |
| CSV 2 blocks, coin not mined yet | refused (relative lock) |
| CSV 2 blocks, coin in 9643, next block 9644 | refused (relative lock) |
| CSV 2 blocks, coin in 9643, next block 9645 | in block 9645 |

To run it again: copy two testnet data directories, delete `nostr.key`,
`btf_enc.key`, `btfpeers.json` and `managed-tor/` in each so they get new
identities, start each once with `-testnet -isolate` and a placeholder
`-connectbtf` to learn its address (it logs `isolated bench: this node is
...`) and onion, then start both pointed at each other with the same
`-benchrulesv4`. Give `-rpcport` a port other than `-port` and `-port`+1: those
two are published on the node's onion, and the node refuses to start an RPC
server on either.

### The wallet's vault and batch, on the same bench (2026-10-29)

Node C made and spent everything with the RPCs above; node D only validated
the blocks and received.

| case | result |
|---|---|
| vault, withdraw before the unvault | refused (not unvaulted) |
| vault, spend the vault output to another address with `spendscript` | refused (CTV) |
| vault (delay 3), withdraw at once after the unvault | refused (relative lock) |
| vault (delay 3), withdraw one block after the unvault confirmed | refused (relative lock) |
| vault (delay 3), withdraw three blocks after | accepted; D holds the 99.98 |
| vault (delay 10), recovery key right after the unvault | accepted |
| batch, spend it to other amounts with `spendscript` | refused (CTV) |
| batch, `ctvexpand` | accepted; D holds its 1 and 2 |

D followed C to block 10325 and refused none of its blocks. The run turned up
two defects, both fixed: an isolated bench refused every inbound connection,
so its two nodes never met; and an unvault (or expansion) pays no address of
the wallet that made it, so the wallet did not keep it and a restart before
it was mined lost it. The wallet now keeps the transaction and sends it again
when `vaultunvault` or `ctvexpand` is run a second time.
