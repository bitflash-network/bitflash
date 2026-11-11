# Consensus rules v5 (unscheduled)

Status: implemented, **not scheduled on either network**. The switch times are
0, which means never, on mainnet and on testnet. Nothing in this document
changes which blocks are valid until a release sets a date and the founder
announces it. Until then the rules run only on an isolated testnet bench
(`-testnet -isolate -benchrulesv5=TIME`) and in `-selftest=rules-v5`.

Rules v5 are a set of tightenings. Each one closes a gap that the 0.1.0 code
this chain descends from left open, and each one only *removes* blocks from
the valid set. A block that follows rules v5 is valid to every older node, so
the switch is a soft fork: what has to upgrade before the date is the
hashrate, as with rules v3.

| rule | what changes | why |
|---|---|---|
| retarget time | the block that closes a retarget window may not be timed before the window's first block | the retarget's unsigned timespan can no longer wrap to "four times easier" |
| own coinbase | a transaction may not spend the coinbase of the block it is in | coinbase maturity covered depths 1-99, never depth 0 |
| unsigned lock time | `nLockTime` is read as unsigned for finality | lock times of 2^31 and up (2038-2106) counted as already past |
| pre-v4 CSFS | `OP_CHECKSIGFROMSTACK` in a bare output made before rules v4 counts as a signature operation when it is spent | such outputs were never counted against any block's limit |
| multisig keys | an `OP_CHECKMULTISIG` takes at most 20 keys | it is charged 20 signature operations but checked one signature per key, up to the stack's 1000 |

Also in this release, with no switch (see below): no block subsidy after 64
halvings (BIP42).

## Switch

| network | parent's median time past | |
|---|---|---|
| testnet | `0` | not scheduled |
| mainnet | `0` | not scheduled |

Rules v2, v3 and v4 switch on by the time of the block being checked. A
block's time is its miner's choice, anywhere above the median of the last
eleven blocks and up to two hours ahead of the clock, so for a while around
the switch a miner can time a block on either side of it and pick the rules
it runs under.

Rules v5 switch on by the **median time past of the block's parent**: a block
runs under v5 when `parent.GetMedianTimePast() >= RULES_V5_TIME`. That median
never goes back, since every block must be timed above it, so once one block
runs under v5 every block after it does. There is no window, and a block
template built on a given tip runs under the same rules whatever time the
miner gives it.

Rules v5 never switch on before rules v4. The test is made on the parent's
median time; the block itself is timed above it, and v4 never switches off as
time goes forward, so v4 also holds for the block.

`-benchrulesv5=TIME` moves the switch to TIME on testnet only, and only
together with `-isolate`, as `-benchrulesv4` does for v4. Before the testnet
v4 date (2026-11-20 12:00 UTC) a bench also needs `-benchrulesv4`, or v5 waits
for v4.

The code: `RulesV5Time()`, `RulesV5ActiveAtMedianTime()` and
`RulesV5Active(pindexPrev)` in `src/randomx_pow.cpp`, constants in
`src/consensus.h`.

## Retarget time

`GetNextWorkRequired` measures a window as the closing block's time minus the
window's first block's time, in `unsigned int`. Only the 11-block median bounds
a block's time from below, and the first block is thirty blocks back, outside
that median. So the closing block may legally be timed earlier than the first
block (for example when the first block was timed near the two-hour limit). The
subtraction then wraps to about 4.29e9 seconds, which the clamp turns into
four windows, and the next target is four times **easier**. In Bitcoin the
timespan is signed and the same case makes the target four times harder.

Making the subtraction signed would change which `nBits` is valid in both
directions: a hard fork. Rules v5 take the soft-fork form instead, as BIP94
bounds timestamps: from the switch, a block at a retarget-closing height
(height 29 mod 30) is invalid if its `nTime` is below the `nTime` of the first
block of its window (the block `GetNextWorkRequired` subtracts, 30 blocks back
under rules v2). The subtraction can then never go negative, and the
arithmetic stays exactly as it is, bit for bit, for every block before and
after the switch.

Block builders (the solo miner, the pool and P2Pool templates) start a
block's time at `BlockTimeFloor(pindexPrev)`: the median time past plus one,
and under rules v5, for a closing block, the first block's time when that is
later. Before rules v5 it is the median time past plus one, as before.

An honest miner with a correct clock is not affected; the rule only binds
when the first block of a window was timed ahead of the closing one.

Misbehaviour score for a peer that sends such a block: 10, the score of the
rules-v3 finality rule, since a miner on an older release can produce one.

## A coinbase may not be spent in its own block

`ConnectInputs` refuses a coinbase spent at depth 1 to 99 by walking back from
the parent of the block being connected. It never compared against the block
itself. `ConnectBlock` indexes the coinbase first, so a later transaction in
the same block found it and passed: the coinbase's coins left their own block
as ordinary outputs, spendable at once. If that block is reorganized away,
every coin descending from it is gone, which is what maturity is for.

From the switch, a block whose transaction spends that block's own coinbase is
invalid. The mempool never holds a coinbase and is unaffected.

## nLockTime read as unsigned

`nLockTime` is a signed `int` in this code base. `IsFinalAt` decided whether
the value is a height or a time with an unsigned comparison (the threshold is
`unsigned int`), but then compared the value itself sign-extended. A lock time
of 2^31 or more, a time between 2038-01-19 and 2106, came out negative, below
any median time, and the transaction counted as final immediately. A
presigned transaction relying on such a lock alone could be mined at once.

From the switch, `IsFinalAt` reads `nLockTime` as the unsigned 32-bit value it
is on the wire, as Bitcoin does. Every value below 2^31 gives the same answer
as before. Mempool and block builders apply the same rule for the next block
(`IsFinalAfter`), so they never build a block that the rule would refuse.

### The limit that stays: OP_CHECKLOCKTIMEVERIFY

`OP_CHECKLOCKTIMEVERIFY` compares its argument with the same signed
`nLockTime`. A spending transaction with a lock time of 2^31 or more reads as
negative there, so a CLTV lock on a time at or after **2038-01-19 03:14:08 UTC
(unix 2147483648)** can never be satisfied: the branch it guards can never be
taken. Making CLTV accept those values would let through spends that every
current node refuses, which is a hard fork, so rules v5 leave CLTV as it is.

Do not lock coins with CLTV to a time at or after 2^31. Heights are not
affected (they are far below 2^31), and neither are relative locks (CSV).

## OP_CHECKSIGFROMSTACK in bare outputs made before rules v4

A script's signature operations are counted once, by the block that holds the
script, against that block's limit of 20,000. Bare output scripts are counted
by the block that creates the output; only P2SH redeem scripts are counted
when spent. Before rules v4, `OP_CHECKSIGFROMSTACK` did not count, so a bare
output created before v4 could carry up to about 200 of them at no cost to any
block. Once v4 gives the opcode meaning, spending many such outputs in one
block made each validating node do far more signature checks than the limit
intends.

It can be closed as a tightening. From the switch, when a transaction spends
an output whose script contains `OP_CHECKSIGFROMSTACK`, and the output was
created in a block where rules v4 did not hold, those operations count
against the spending block's limit (alongside the P2SH redeem-script count).
An output created under rules v4 was counted when created and is not counted
again. An output not yet in a block (a mempool parent) will be created under
v4, since v5 never holds without it. If the creating block cannot be found the
output is counted, since that is the side that never lets more through.

Counting only the outputs that were missed keeps the limit what it was meant
to be without changing what any ordinary transaction costs: standard scripts
contain no `OP_CHECKSIGFROMSTACK`.

## At most 20 keys in an OP_CHECKMULTISIG

An `OP_CHECKMULTISIG` (or `-VERIFY`) is charged 20 signature operations
against the block's limit, whatever it does. It pops a key count from the
stack and then checks signatures against up to that many keys, one check per
key tried. The 0.1.0 code never bounded the count except by the stack itself
(1000 items), so a script that computes its key count (`OP_16 OP_9 OP_ADD`
rather than a literal `OP_16`) could check many times more signatures than it
was charged for. `fuzz-script`, which holds the checks a spend starts to what
the block and the pool charge for it, aborts on such a spend.

Bitcoin has always capped the count at 20 (`MAX_PUBKEYS_PER_MULTISIG`), and so
do rules v5: an `OP_CHECKMULTISIG` handed more than 20 keys fails the script,
so its checks never exceed the 20 it is charged. No wallet here makes such a
script (the multisig and treasury scripts take at most 16 keys, as a literal).

Until v5 are scheduled, the relay policy does the same job for honest blocks:
the memory pool refuses a spend whose scriptPubKey or redeem script runs an
`OP_CHECKMULTISIG` without a literal `OP_0`..`OP_16` key count right before it
(`MultisigKeyCountsAreLiteral`), and miners build blocks from the pool.

## No subsidy after 64 halvings (BIP42)

`GetBlockValue` shifted 50 coins right by `nHeight / 210000`. From height
13,440,000 that is a shift of 64 or more, which is undefined behaviour in C++;
on x86 the count wraps and the subsidy would jump back to 50.

Now the subsidy is 0 once the halving count reaches 64. Below height
13,440,000 the halving count is at most 63 and the result is exactly what it
always was (`-selftest=rules-v5` compares every height below it), so the
change needs no switch: it only decides heights no chain has reached, where
the old behaviour was undefined.

## Tests

`-selftest=rules-v5` (in `make tests`) checks each rule with the switch off,
where the old behaviour is unchanged, and on, through `-benchrulesv5`'s
switch:

- the switch: 0 on both networks, a bench time never reaches mainnet, never
  before rules v4, decided once by the parent's median time;
- the subsidy at every height below 13,440,000, and 0 from there;
- lock times at 2^31 and above, and every lock time below it unchanged;
- the retarget-time rule on a made-up index, its exact window, and the old
  arithmetic it leaves untouched;
- on a real chain in a temporary data directory, through `AcceptBlock` and
  `ConnectBlock`: a block spending its own coinbase, a block spending 103
  pre-v4 CSFS outputs (20,085 operations), the same number made under v4 (not
  counted twice), a block holding a transaction locked to 2^31, a block
  spending a 25-key `OP_CHECKMULTISIG`, and a window-closing block timed
  before its window's first block. Each of the refused blocks is accepted
  with the switch off.
