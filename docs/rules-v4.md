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
through a delay), payment channels and their penalty windows, swaps that do
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
