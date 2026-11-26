# Everpool: the P2Pool that no one can delete, edit or shut down

Status: design done (Phase A); implemented (Phases B and C, section 16) and
proved on testnet with real coins (Phase D); not open on mainnet yet. The phases are at the end. The protocol is also published on its own, for
any chain to adopt, at https://github.com/bitflash-network/everpool. Main-chain consensus does not change: everything below is node
software and P2Pool protocol, and ships in an ordinary release.

**Everpool** is the name of the feature: pools that live on the chain and
travel between nodes. Inside the code and in the rest of this page it is the
*pool registry*, and its parts keep descriptive names (`poolrecord`,
`NODE_POOLREG`, `poolcreate`); the name is for people, not for identifiers.
It works the same on a network that blocks Tor, through the bridges the node
already uses there (section 17).

A pool can also be private: **P2Pool local** (section 18) uses the same share
rules for a group that wants nothing published, with no record on the chain,
no burn, and its share chain only on its members' nodes. At creation the user
picks one or the other; pool zero, the default P2Pool, stays as it is for
whoever picks neither.

## What it is for

P2Pool inside the node (`docs/p2pool.md`) removed the pool operator: no
custody, no central template, no company, no domain. One lever is left, and it
is the project's own. The rules of the share chain (a 2160-share window, 10 s
per share, uncles at 80%) live in the code, and whoever publishes a release can
change them for everybody. Alternative pools have nowhere to be found but a
website (`docs/pool-directory.md`).

The registry removes that lever. In plain words:

- **Anyone can create a pool.** Creating one is a transaction that burns 1 BTF
  into an `OP_RETURN` carrying the pool's rules.
- **Once created, it can never be deleted or edited**, not by its creator and
  not by the project. The pool's id is the hash of its rules. Changing one
  byte of them is a different pool with a different id; the first one stays
  exactly as it was, on the chain, for as long as the chain exists.
- **If its creator's PC goes offline, the pool keeps living.** The creator has
  no role after the burn: no key, no server, no vote. The pool is the record
  on the chain plus the share chain its miners keep.
- **It travels between nodes.** Every day a draw from block hashes picks a few
  nodes per pool to keep and relay its share chain, even if they do not mine
  it. When the day changes, the new set takes the chain from the old one. A
  pool nobody mines for a while sleeps with its guardians, and any miner can
  wake it.

Today's pool, the one every P2Pool miner already mines, becomes **pool zero**:
entry zero of the registry, fixed in the code with the rules it has today and
a fee of zero. It needs no registration, and nodes of 1.2.34 and earlier keep
mining it with no change.

## Contents

1. The record
2. Pool id
3. Indexing, confirmations and reorgs
4. Pool zero
5. Share rules v1
6. Share format for registered pools
7. The coinbase anchor
8. Network messages and version negotiation
9. Mining a chosen pool
10. Rotating replication: guardians
11. Storage and bandwidth bounds
12. Threat model, Sybil and DoS
13. What stays out of consensus, and why
14. Migration
15. Test plan
16. Phases
17. Networks where Tor is blocked
18. P2Pool local: a private pool

## 1. The record

A pool is created by a transaction with an output whose script is `OP_RETURN`
followed by **one direct push** (opcode equal to the length, 42 to 73 bytes) of
the record below, and whose value is **at least 1 BTF** (100,000,000 sat). The
value is burned: an `OP_RETURN` output can never be spent. `OP_RETURN` with up
to 80 bytes is standard since 1.2.28, so this is `sendburn`, the same call
that lists a public community (`docs/btfchat.md`, `src/community.h`).

All integers are little-endian, fixed width, unsigned.

| offset | bytes | field | allowed values |
|---|---|---|---|
| 0 | 4 | magic | `"BTFP"` |
| 4 | 1 | record format | `1` |
| 5 | 1 | share rules version | `1` (section 5) |
| 6 | 2 | share spacing, seconds | 20 to 120, and spacing x uncle depth at least 60 (section 17). Pool zero's 10 is valid only in pool zero's own record |
| 8 | 2 | PPLNS window, shares | 360 to 2160 |
| 10 | 2 | retarget window, shares | 120 to 720, and no more than the PPLNS window |
| 12 | 4 | share floor, compact target | canonical (below), above 0, no easier than the network floor `0x1f0fffff` |
| 16 | 1 | uncle depth | 1 to 3 (pool zero's 3) |
| 17 | 1 | uncle share, percent | 80 to 100 (pool zero's 80) |
| 18 | 2 | creator fee, basis points | 0 to 300 (3%) |
| 20 | 1 | fee script type | 0 none, 1 P2PKH, 2 P2SH |
| 21 | 20 | fee script hash | the HASH160 of the address; twenty zero bytes when the type is 0 |
| 41 | 1 to 32 | name | ASCII `A`-`Z`, `a`-`z`, `0`-`9`, `-` and `_`, tested as byte ranges (not with `isalnum`, which depends on the C locale) |

The name's length is what is left of the push: there is no length byte, so a
record is 42 to 73 bytes.

**Canonical encoding.** A record is read only if writing back what was read
gives the same bytes. Concretely, a record is ignored (it is not a registry
entry, and nothing about it is an error) when any of these holds:

- the push is not a single direct push, or the script has anything after it;
- the magic, the record format or the share rules version is not one this
  node knows (a later format is simply not read by this one);
- any field is outside its range above;
- the floor is not canonical: `SetCompact` then `GetCompact` does not give back
  the same four bytes (the compact form has several spellings of one target,
  and two spellings would be two ids for one pool);
- the fee is 0 and the fee type is not 0 or the hash is not all zero, or the
  fee is above 0 and the type is 0 (a fee with nowhere to go, or a destination
  with no fee, would also be two ids for one behaviour);
- the spacing is below 20 and the record is not pool zero's own (section 4);
- the spacing times the uncle depth is below 60 (so below 30 s the depth must
  be 3, from 30 to 59 s at least 2, from 60 s at least 1), pool zero's own
  record excepted;
- the name breaks the name rule.

So every pool has exactly one record, and every record exactly one pool.

**Why these ranges.** A short spacing multiplies orphaned shares over Tor's
latency, and over a bridge (Snowflake, meek) far more. Registered pools start
at 20 s, always keep uncles, keep them at least 60 s of shares deep, and pay
an uncle at least 80% of its work, so a miner behind a bridge is paid for a
late share rather than orphaned out; section 17 gives the loss each allowed
combination still has. Pool zero keeps its 10 s, which it cannot change;
above 120 s a share is as rare as a block. The window cap of 2160 is
pool zero's: every coinbase pays one output per distinct address in the
window, and the bounds on share size, block space for the coinbase and memory
(`MAX_SHARE_BYTES`, `P2POOL_COINBASE_BYTES`, `MAX_CHAIN_BYTES`) were all sized
for it. A pool that wants a longer PPLNS horizon takes a longer spacing: 2160
shares at 30 s is 18 hours. The 3% fee cap keeps a fee pool from being a trap;
nothing stops a 0% clone of it.

## 2. Pool id

```
poolId = SHA256d( "Bitflash/pool/1" || network magic (4 bytes) || record )
```

`SHA256d` is the double SHA-256 the node uses everywhere (`Hash`). The network
magic is the message start of the chain the record is on (`pchMessageStart`:
mainnet `bf 20 5c fd`, testnet `ce e2 c0 ff`), so the same rules on testnet and
mainnet are two different pools and no share can be replayed across them. The
id is a `uint256`, shown like a block hash (`GetHex`, byte-reversed); wallets
show its first 8 hex digits as the pool's fingerprint.

Consequences:

- **The same rules always mean the same id**, whoever registers them and
  however many times. Registering a record that is already registered changes
  nothing; the pool's age is the height of its first appearance.
- **Changing one byte makes a different pool.** "Editing" a pool is creating
  another one. The old one is untouched, and its miners stay on it or leave,
  each by their own choice.
- **The id does not depend on who paid or on the transaction.** There is
  nothing to front-run: copying someone's record from the mempool registers
  the same pool, with the same fee destination, for the copier's money.
- **A pool can always come back.** If the transaction that registered a pool
  is lost in a reorg and never mined again, anybody can burn the same bytes
  again and get the same id back.

## 3. Indexing, confirmations and reorgs

Every node reads the main chain for records, the way it reads it for community
listings (`src/chatdir.cpp`), with two differences: it follows reorgs, and an
entry counts only once it is buried.

**The registry is a pure function of the active main chain.** Fold the blocks
of the active chain from genesis, in order (block, then transaction, then
output); every output that is a valid record (section 1) with a value of at
least 1 BTF is an *appearance* of its pool id. A pool's *first appearance* is
the earliest one. The node's index (`pool-registry.dat`) is a cache of that
fold and nothing else; deleting it makes the node read the chain again and
reach the same registry.

**Confirmations.** A pool is **active** when its first appearance has at least
**30 confirmations** (about an hour of 120 s blocks): the block holding it and
29 on top. Before that the pool is *pending*: listed, not carried, not mined,
its shares not taken. 30 is far deeper than any reorg the network has seen and
costs a pool's creator an hour once, which nobody minds.

**Reorgs.** The index remembers the hash of the last block it read. On each
pass it walks back from that block to the first one still on the active chain
(the fork point), forgets every appearance above it, and reads forward again.
So:

- an appearance reorged out before 30 confirmations simply goes; if the same
  record appears again on the new branch, the pool is pending again from that
  height, with the same id;
- an appearance reorged out after 30 confirmations goes the same way: depth
  only decides when a pool starts counting, never that it can no longer be
  removed by the chain. A reorg that deep is an attack on the main chain, and
  the registry follows the main chain;
- if a pool's only appearance goes, the pool goes back to *unknown*: the node
  stops mining and announcing it, refuses its shares innocently (section 8),
  and **keeps its share chain on disk**, in case the record comes back.

**What a pool's state may decide, and what it may not.** Whether a pool is
active depends on this node's view of the main chain, which can differ for a
block or two between two honest nodes. So it decides only what a node
*carries* (mines, keeps, relays, announces), never whether a share of the pool
is valid. A share is judged on its pool's rules and its pool's share chain
alone, exactly as pool zero's are today (`docs/p2pool.md`: "a share is judged
on the share chain and itself alone"). In particular there is no rule like
"shares older than the registration are invalid": that would make validity
depend on when each node saw the registration, and two honest nodes would part
ways. Somebody who mines a pool's share chain before registering it has only
spent work.

**What the index also keeps.** Per pool: the first appearance (height, block
hash, txid, output, burn), the number of appearances, and the main-chain
anchors that name it (section 7): the last 64 (height, block hash, share data
hash) and the count over the last 720 blocks. All of it is undone by a reorg
the same way.

**Anchors that name no registered pool are kept only for a while.** A
`"p2x"` push costs nothing to write, so a miner could name a new made-up id in
every coinbase; kept forever, those claims would grow the index without any
burn, against section 11. So at every height that is a multiple of 144, an id
that is neither pool zero nor registered at that height loses its anchors
older than 2160 blocks. A dropped anchor stays in the file for 1440 more
blocks, so a reorg above the sweep restores it exactly; a reorg below an
anchor dropped for good is detected and the chain is read again. The sweep is
part of reading the chain, so a rebuild gives the same result. A pool whose
record appears later starts with the anchors of its last 2160 blocks before
the burn.

**The file and restarts.** The index lives in `pool-registry.dat`, written
atomically, with a checksum, and rebuildable from the block files: deleting
it and starting again gives the same registry. It keeps the hashes of the
last 64 blocks it read and one every 144 blocks, so a node whose block index
lost its last blocks in an unclean stop resumes from the newest one it still
has instead of reading from genesis. A rebuild from genesis (a damaged file,
a reorg deeper than the kept anchors allow) is read into a second registry
while the old one keeps answering, and takes over at the tip. The index has a
thread of its own, started once the node's network is up (never by a
one-shot command such as `-newaddress` or `-rescan`); on the way out the node
waits for its last save, best effort, for at most 30 s, and a save cut short
leaves the previous file.

**Cost.** One parse per `OP_RETURN` output of at least 1 BTF, a few hundred
bytes per pool on disk and in memory. There is no cap on the number of
entries: a cap would let whoever fills it stop everybody else from creating a
pool, which is deleting the registry by other means. Its size is bounded by
the burn instead (section 12).

## 4. Pool zero

Pool zero is the share chain every P2Pool node runs today. It becomes entry
zero of the registry with its current rules written as a record:

| field | value |
|---|---|
| record format, rules version | 1, 1 |
| share spacing | 10 s |
| PPLNS window | 2160 shares |
| retarget window | 720 shares |
| floor | `0x1f0fffff` (`bnProofOfWorkLimit`) |
| uncle depth, uncle share | 3, 80% |
| creator fee | 0, no fee script |
| name | `bitflash` |

```
record (49 bytes):
4254465001010a007008d002ffff0f1f03500000000000000000000000000000000000000000000000626974666c617368

pool zero id, mainnet
  shown (GetHex):  d925f36f20d98092d034dc083e46040fcb292c5f5437bc834130da088b197c8a
  internal order:  8a7c198b08da304183bc37545f2c29cb0f04463e08dc34d09280d9206ff325d9
pool zero id, testnet
  shown (GetHex):  a97d439cb065f828545a5b45f098297ca79adebba56a80a87cb0b095fddb2736
  internal order:  3627dbfd95b0b07ca8806aa5bbde9aa77c2998f0455b5a5428f865b09c437da9
```

(Computed from the definitions above and recomputed by the review; Phase B
pins all of them in a self-test, and the code and this page must agree before
anything merges.)

**The floor is the same target.** Pool zero today uses `bnProofOfWorkLimit`
(`~uint256(0) >> 12`) as its floor, not `SetCompact(0x1f0fffff)`, which is
slightly harder (`0x0fffff * 2^224`). No compact value lies strictly between
the two, and every share target and retarget result is compact, so the floor
check (`CheckShareCheap`) and the clamp in `NextShareBits` give identical
answers with either. v1 uses `SetCompact(record floor)`; Phase B pins this
equivalence in a self-test.

- It is **fixed in the code**, present at height zero on every node, and needs
  no burn. A record with exactly these bytes, if somebody burns it, is pool
  zero: nothing changes, and the index notes where it was published. Burning
  it on mainnet once, after the release, is a cheap public act worth doing:
  anyone can then check pool zero's rules against the chain.
- **Its share format does not change, ever.** Pool zero keeps the share and
  `ShareData` of `docs/p2pool.md` byte for byte, the `"p2p"` commitment, the
  `p2pshare`/`p2pgetsh`/`p2psync`/`p2pshares`/`p2ppeers` messages, and
  `p2pool.dat`. Its id is never written into its shares: the `"p2p"` tag is
  what names it. This is what keeps 1.2.34 nodes and new nodes on one pool
  zero share chain, with nothing to negotiate.
- **Its rules are share rules v1 with the parameters above** (section 5), and
  v1 is defined as exactly what the code does today. Phase B moves today's
  constants into a parameter set and must show, with the existing self-tests
  run through it, that pool zero behaves identically to 1.2.34.
- Every node that carries P2Pool keeps relaying pool zero, mining or not, as
  today. It is not part of the guardian draw (section 10): everybody already
  guards it.

What this changes for the project: from this release on, a release that wanted
other rules for pool zero cannot have them. It can only create another pool,
with another id, and miners choose. That is the point.

## 5. Share rules v1

A share rules version is a complete, frozen definition of share validity and
chain choice, given a record's parameters. **Version 1 is the code of
1.2.34 with its constants made parameters, plus the creator fee** (below), and
nothing else. With pool zero's parameters and no fee it is 1.2.34 exactly:

| today's constant | v1 parameter |
|---|---|
| `SHARE_SPACING = 10` | share spacing |
| `WINDOW_SHARES = 2160` | PPLNS window |
| `RETARGET_SHARES = 720` | retarget window |
| `bnProofOfWorkLimit` as the floor | share floor |
| `MAX_UNCLE_DEPTH = 3` | uncle depth (1 to 3) |
| uncle paid 80%, includer 20% | uncle share p%: the uncle is paid `floor(work * p / 100)` (computed as `work / 100 * p + (work % 100) * p / 100`, exact without overflow; for p = 80 it equals today's `work / 5 * 4 + (work % 5) * 4 / 5`), the includer the rest |
| `HISTORY_SHARES` | window + retarget + 2 x uncle depth + 10 |
| chain choice over lines that do not meet: last 2160 shares | last *window* shares |
| `TIP_MAX_AGE = 30 min` | 180 x spacing (30 min for pool zero) |
| coinbase outputs at most `3 * WINDOW_SHARES` (`CheckShareCheap`) | at most 3 x window, plus 1 when the fee is above 0 |
| `MAX_CHAIN_SHARES = 4 * HISTORY_SHARES` | 4 x the pool's `HISTORY_SHARES` |
| `NEAR_TIP_SHARES = 2 * MAX_UNCLE_DEPTH + 10` | 2 x uncle depth + 10 |
| `SYNC_GAP = 2 * MAX_UNCLE_DEPTH + 10` (`p2pool_net.cpp`) | 2 x uncle depth + 10 |
| history shares a peer may send, `3 * HISTORY_SHARES + 2 * SHARES_PER_MESSAGE` | `3 x HISTORY_SHARES + 2 x 100` with the pool's `HISTORY_SHARES` (registered parts hold at most 100 shares, section 17) |

Outside validity, the template reserve for the coinbase
(`P2POOL_COINBASE_SIGOPS`, `P2POOL_COINBASE_BYTES` in `rpc.cpp`) follows the
same output count, plus one for the fee.

Unchanged in v1, for every pool: at most 2 uncles; payout scripts are P2PKH or
P2SH only; 120 s of future time; the median-of-11 lower bound on time; the
first *retarget window* shares at the floor, then a retarget every share over
the last *retarget window*, by at most 4x either way, never easier than the
floor; most cumulative work as the chain choice; the coinbase meets every rule
a block's coinbase meets.

**The creator fee.** When the record's fee is above 0, a share's coinbase must
pay, out of its total value `T` (subsidy plus fees, at least the subsidy, as
today):

1. `fee = floor(T * bps / 10000)` to the fee script (P2PKH or P2SH of the
   record's hash), computed in 128-bit integers. A P2SH fee address is safe
   because rules v3 (P2SH spending) is active on mainnet from 2026-11-21,
   before this ships;
2. `T - fee` over the window with `ComputePayouts`, unchanged;
3. if the fee script is also in the window (the creator mines too), its two
   amounts are one output; otherwise the fee output takes its place in the
   order by script bytes. A fee that rounds to 0 is no output.

The coinbase must equal that list exactly, as today, so the fee is enforced by
share validity: a template that skips or shrinks it is not a share of the pool,
and its block, if it is one, earns no share credit. No covenant, no consensus
rule. The fee can never grow, because the record cannot change.

**The freeze.** Every share rules version is frozen forever, the way consensus
code never forgets old rules. A release may add version 2, 3, and so on for
new records; it may never stop validating version 1, nor change what version 1
means. If a version turns out to have a bug, the fix is a new version and new
pools; a release may refuse to *build templates* for a version known to be
broken, and say why, but it keeps validating it. The self-tests of a version
are frozen with it.

## 6. Share format for registered pools

Pool zero keeps its format (section 4). Every other pool uses **share format
1**, which differs in one field:

```
ShareDataX {
    uint256 poolId;               // the pool this share belongs to
    uint256 hashPrevShare;        // as ShareData
    vector<uint256> vUncles;
    unsigned int nShareHeight;
    unsigned int nShareBits;
    vector<unsigned char> payoutScript;
}
```

serialized in that order with the node's ordinary serialization, and hashed
with `SerializeHash`. A format 1 share (`ShareX`) is a pool zero `Share` with
`ShareDataX` in place of `ShareData`: the same header fields, coinbase and
merkle branch.

A local pool's share (section 18) adds one field to this, a random salt
after `poolId` that never goes on the chain; a registered pool's share has
none.

On top of the v1 rules, a format 1 share is valid only if:

- its `poolId` is the pool whose rules it is checked against, and is not pool
  zero's id;
- its whole coinbase scriptSig parses: it is read push by push with `GetOp`,
  exactly as `FindCommitment` reads it today, and any `GetOp` failure makes
  the share invalid. A push is recognised by its data alone, whatever opcode
  carried it (a direct push or `OP_PUSHDATA1` alike);
- its coinbase carries **exactly one** `"p2x"` commitment (section 7): a
  67-byte push starting `"p2x"`, whose pool id is `poolId` and whose hash is
  `SerializeHash(ShareDataX)`;
- its coinbase carries **no** `"p2p"` commitment (a 35-byte push starting
  `"p2p"`), no `"p2l"` commitment (a 35-byte push starting `"p2l"`, a local
  pool's anchor, section 18) and no second `"p2x"` push of any pool.

So one PoW counts on at most one share chain. Pool zero's frozen rule
(`FindCommitment` in 1.2.34) counts only 35-byte `"p2p"` pushes, so a pool
zero coinbase may also carry a `"p2x"` push; that is why the exclusion has to
sit on the format 1 side. A format 1 share cannot be a pool zero share, since
it has no `"p2p"` push, and a pool zero share cannot be a format 1 share,
since format 1 refuses any coinbase with a `"p2p"` push. Two registered pools
cannot share a PoW either, since the push names one pool id.

## 7. The coinbase anchor

Today every P2Pool coinbase carries, after the height, a 35-byte push: `"p2p"`
and the hash of the share's `ShareData`. Pool zero keeps it unchanged. A
registered pool's coinbase carries instead a **67-byte push**:

```
"p2x" (3 bytes) || poolId (32 bytes, internal byte order) || SerializeHash(ShareDataX) (32 bytes)
```

The template's scriptSig is then the height (at most 5 bytes with its push
opcode, up to `MAX_BLOCK_HEIGHT`), `nBits` (at most 6), the extra nonce (at
most 6), this push (68 with its opcode), and the stratum's `extranonce2`,
which `BuildMinerBlock` appends after it (at most 6): at most 91 bytes, inside
the 100 a coinbase scriptSig may have (`CheckTransaction`). A format 1 share
whose scriptSig would pass 100 bytes is no share, as for pool zero.

The anchor names the pool, so **anyone can count, from the main chain alone,
how many blocks each pool's template produced**: a `"p2p"` push is pool zero,
a `"p2x"` push names its pool in full. The count reads a coinbase the way a
share is read: the scriptSig must parse fully, and it counts for pool zero
with exactly one `"p2p"` push and no `"p2x"` push, for a registered pool with
exactly one `"p2x"` push and no `"p2p"` or `"p2l"` push; anything else counts for no pool (a `"p2l"` push is a local pool's, and counts for none, section 18). A `"p2x"` push naming pool zero's own id also counts for no pool: pool zero's shares never carry its id (section 6), so such a push cannot come from its template. The index keeps these counts (section
3). They are *claims*: anybody can put a `"p2x"` push in a solo block's
coinbase. Only a node that carries the pool can tell a real one (the coinbase
pays that pool's window, the share data is in its share chain) from a label,
and wallets must say which they show (section 12).

## 8. Network messages and version negotiation

**A new service bit**, `NODE_POOLREG = (1 << 3)`, says a node reads the
registry and speaks the messages below. Nodes of 1.2.34 and earlier do not set
it; nothing below is ever sent to them, and nothing changes in what they are
sent. Pool zero traffic stays on its own messages, to every `NODE_P2POOL`
peer, old or new, exactly as today.

New messages, only between `NODE_POOLREG` peers (an older node ignores unknown
commands, `ProcessMessage`, but they are not sent to it anyway):

| message | carries | what it does |
|---|---|---|
| `poolinv` | up to 32 pool ids | the registered pools this node can serve now (below). Sent after `version`, and again when the set changes (at most once a minute; a peer that sends them faster is not scored, since that is judged on the receiver's clock, and the receiver simply acts on the latest one at most once a minute) |
| `p2xshare` | pool id, `ShareX` | a share, as `p2pshare` |
| `p2xgetsh` | pool id, up to 500 share ids | ask for shares by id, as `p2pgetsh` |
| `p2xsync` | pool id, resume point (a share id, or 0) | ask for a line, as `p2psync`; with a resume point the server holds, its snapshot from where that share's branch meets its line, less the uncle depth (section 17) |
| `p2xshares` | pool id, the snapshot's tip height, an end flag, up to 100 shares and 256 x 1024 bytes | a part of a line, as `p2pshares` but smaller and paced, only in answer to `p2xsync` for that pool (section 17) |
| `p2xnone` | pool id | "I hold nothing of this pool": the answer to `p2xsync` or `p2xgetsh` for a pool this node does not carry, or carries with no shares |
| `pooltkt` | an epoch, the ticket seed hash the sender checked them against, up to 512 guardian tickets | tickets, relayed or in answer to `poolgettkt` (section 10, Phase C) |
| `poolgettkt` | an epoch | ask a peer for the tickets it holds for that epoch; answered with `pooltkt` parts, at most 4096 tickets in all (section 10, Phase C) |
| `poolwho` / `poolat` | a pool id / up to 32 `.btf` addresses | ask a peer who carries a pool; the answer is hints, as `p2ppeers` (Phase C) |

**What `poolinv` names.** Only active pools this node carries now (mines,
carries by `-poolcarry`, or guards) and holds shares of, plus the pool it mines
even before it has shares: at most 1 mined, 8 by `-poolcarry` and 8 guarded
with shares (section 11), so 17, within the 32 the message allows. A chain
kept on disk after a reorg or after a guard slot ended is not carried and not
announced. In what follows, "announced" and "carried" mean the same set. A guarded pool
with no shares is not announced: there is nothing to send for it, and
announcing every empty pool a node is drawn for would let cheap registrations
crowd real pools out of the message.

**Routing.**

- *Pushes* (`p2xshare` sent unasked) for pool P go only to peers whose latest
  `poolinv` names P. An honest node never pushes a share of a pool the
  receiver did not announce.
- *Requests* (`p2xsync`, `p2xgetsh`, `poolwho`) may go to any `NODE_POOLREG`
  peer: that is how a node finds a pool nobody announced to it. A request for
  a pool not announced (not carried, or a guarded or `-poolcarry` pool this
  node holds no shares of yet), or naming pool zero's id,
  gets `p2xnone`, at the cost of one map lookup, and scores nobody. Requests are rationed by the budgets
  below, as `p2psync` is today. The asking side keeps within them too: it
  sends one connection at most 3 `p2xsync` for a pool and 8 in all per
  interval (counted over `SYNC_SERVE_INTERVAL` plus 30 s, so the server's
  own count has always started over), and the same peer asked again for
  the same fetch spends from the history-ask budget even when this node
  dialled it. An ask whose first part has not come within 3 minutes leaves
  that peer alone for a minute, as a `p2xnone` would, and the fetch asks
  another announcer; the late answer is still taken within its window.
- *Answers* (`p2xshares`, and `p2xshare` sent in answer to `p2xgetsh`) are taken
  only for the pool asked, from the peer asked, soon after asking (the rule
  `p2pshares` has today, kept per pool; for `p2xshares` "soon" is the
  receiving window of section 17). An answer for a pool this node
  stopped carrying between the ask and the answer is dropped silently.

Every `p2x*` message starts with its pool id, so the receiver decides before reading
the rest. For a pushed `p2xshare`:

- pool id carried: the share goes through the same pipeline as pool zero's
  (cheap checks first, the RandomX budget for unproven peers, the orphan
  queue, scoring for invalid shares), on that pool's own share chain. The pool
  id at the head of the message must equal `ShareDataX.poolId`; a mismatch is
  an invalid share and scored as one;
- any other pool id, pool zero's included (pool zero travels only on its own
  messages): dropped unread, no hash, **nobody scored**. It costs this node
  one map lookup, which is cheaper than any score is worth, and scoring would
  punish honest races: a `poolinv` queued behind a large history over Tor can
  arrive long after the share it should have preceded.

A share of a carried pool refused because it waits on its parent, or on this
node's own clock, scores nobody (`InnocentRefusal`), as today. A share of a
carried pool that is invalid in itself is scored, as a pool zero share is:
validity never depends on the receiver's view, so an honest peer never sends
one.

**Per connection, per pool.** The per-connection P2Pool state of today
(`nP2PoolSyncAskedAt`, `nP2PoolHistoryRecv`, `nP2PoolSyncServed`, the deferred
asks, "one history in the life of an unproven connection",
`SYNC_SERVE_INTERVAL`) is kept per (connection, pool) for registered pools,
with at most 8 registered pools served per connection per
`SYNC_SERVE_INTERVAL`. One connection can then hand over several pools, which
handoff needs (section 10), and no pool's history counts against another's.
Registered histories are served paced, in smaller parts, and within these
limits (section 17, *Resumable fetches*). An *ask* here is a `p2xsync`, and
nothing else. Per (connection, pool this node carries): one serve in flight (a
new ask replaces it), at most 3 asks per `SYNC_SERVE_INTERVAL` (a fourth is
dropped silently), and at most one history's worth of shares sent per
interval, a resumed serve continuing the count. On an unproven inbound
connection that count is for the life of the connection, as "one history"
is today: resuming continues it, and more takes a new connection, through
the registered serve budget. Asks about pools this node does not carry, or
holds but has not completed, keep no per-pool state: one counter per
connection answers at most 8 of them per interval with `p2xnone`, and drops
the rest unread, unscored. `p2xgetsh` (single shares by id, for missing
parents and uncles) is not an ask and is limited as `p2pgetsh` is today, by
the send queue.

**Pool zero is isolated from everything registered pools do.** The rule is
that nothing an honest peer, or a 1.2.34 node, does with registered pools,
guardians or tickets may change how pool zero's traffic is treated, so that a
1.2.34 node asking an upgraded node for pool zero's line is served exactly as
a 1.2.34 node would serve it. (A peer that sends invalid registered shares or
forged tickets is scored, and like any scored peer it loses its standing for
pool zero too; only a dishonest peer can get there.) Every
piece of shared P2Pool state in `p2pool_net.cpp` is split into two classes,
*pool zero* and *registered*:

- **RandomX budgets.** Pool zero keeps `budgetShareWork`, `budgetHistoryServe`
  and `budgetHistoryAsk` for itself. All registered pools together get a second
  set of the same shape; tickets get a third RandomX budget of their own
  (section 10). Never one per pool.
- **Send queues.** Today `MAX_SEND_QUEUED`, `MAX_HISTORY_QUEUED` and
  `MAX_HISTORIES_QUEUED` measure the peer's whole send buffer (`SendQueued` is
  `vSend.size()`, `InboundQueued` sums every inbound peer's), so a second cap
  of the same shape would separate nothing. Instead each connection counts the
  bytes of registered-class messages it has queued and not yet sent (recorded
  as `vSend` offsets when queued, released as the buffer drains). Pool zero's
  three caps and its serve decisions are computed on the buffer **minus** those
  bytes, so registered traffic can never push pool zero past its caps;
  registered-class serves have their own caps, computed on the registered
  bytes, plus the guard bandwidth cap of section 11.
- **Slow readers.** The slowest-reader rule (`DropSlowestHistoryReader`) runs
  per class: a peer that requested registered histories and reads them slowly
  is dropped by the registered rule, judged on its registered bytes, and
  pool zero's rule never looks at those bytes.
- **Orphans.** Registered shares waiting on parents go into a second orphan
  queue (256 shares in all, for all registered pools), with its own backlog
  trigger; they never take a place in pool zero's queue or start a pool zero
  history ask.
- **Deferred slots.** The one deferred share and one deferred ask a connection
  may have (`DeferShare`, `DeferSync`) exist once for pool zero; a connection
  may have up to 8 deferred registered asks (one per pool, for handoff of
  several pools), counted under the registered class's own `MAX_DEFERRED`.
- **Proven peers.** Whether a peer is proven for pool zero
  (`P2PoolPeerProven`) stays exactly as in 1.2.34. Registered-class messages
  never score a peer for routing (above); a peer that sends an invalid share of
  a registered pool is scored, as it would be for an invalid pool zero share,
  because only a dishonest peer does that. A peer is proven for a registered
  pool as for pool zero (dialled, or it sent a share of that pool this node
  took), per (connection, pool); the shares a proven peer sends unasked are
  hashed on a budget of that (connection, pool) and one of the pool, as a
  local pool's members in session are (section 18), never on pool zero's.

The rule covers every other piece of shared state too, and Phase B lists each
in the code: the global cap on deferred entries (`MAX_DEFERRED`) and the
`OlderHeld` order used by `PeerWorkGate` and `HistoryServeDecision`;
`setOrphanSeen` and `setOrphanBadWork`; the history-waiting state
(`nFirstHistoryAsk`, `P2PoolAwaitingHistory`), which becomes per pool; and
`nP2PoolLastGood`, which only a pool zero share sets, so that a floor share of
some unmined registered pool never makes a peer proven for pool zero (the
registered class keeps its own "last good" per connection). Two limits stay
shared because they are the socket's: the hard send buffer cap
(`MAX_SEND_BUFFER_HARD`, 64 MB) is the whole `vSend`, so the registered caps
are set to keep pool zero's largest queue plus the registered one under it;
and a connection dropped by the registered slow-reader rule loses pool zero
on that connection too, which is acceptable (it was reading nothing).

The tip height and the seed hashes the ticket and registry checks need are
read without `cs_main`, from a snapshot updated under `cs_main` when the tip
changes and read under `cs_p2pool`, so the lock-free path stays lock-free.

The worst a peer can make an upgraded node hash or send is bounded by the sum
of the classes, a small constant multiple of today's, never by the number of
pools. Phase B carries a self-test for the rule: registered traffic that drains
every registered budget and fills the registered queues leaves a pool zero
history request served at once.

**The lock-free path.** Today `ProcessMessages` hands commands starting with
`"p2p"` to `P2PoolProcessMessage` without `cs_main` (`main.cpp`, near the
version check), because a RandomX check under `cs_main` stalls the node. The
`p2x*` and `pool*` commands must take the same path; Phase B
changes that test to the full list of P2Pool commands.

**Version of the protocol.** `NODE_POOLREG` with share rules version 1 is the
whole negotiation. A later format adds a later bit or a later record format;
a node announces in `poolinv` only pools whose record format and rules version
it can validate, so two nodes never exchange shares one of them cannot judge.

## 9. Mining a chosen pool

- `-p2pool` (or `/p2pool`, the other spelling the parser takes) alone, or with
  any value that is not a pool id, as today: pool zero. In 1.2.34 any `-p2pool=...` turns P2Pool on, `-p2pool=0` included, and
  existing configs keep that meaning.
- `-p2pool=<poolid>` (64 hex digits): that pool. Pool zero's own id means pool
  zero. A value of 40 to 80 hex digits that is not exactly 64 makes the node
  refuse to start, so a mistyped id does not quietly mine pool zero.
- `-p2pool=local:<name>`: the local pool of that name on this node (section
  18). A `local:` value naming no local pool here (a typo, a pool left with
  `poolleave`) makes the node refuse to start, for the same reason.
- A node downgraded to 1.2.34 with `-p2pool=<poolid>` or `-p2pool=local:<name>`
  on its command line mines pool zero (its parser sees only "-p2pool"). The
  release notes say so.
- One node mines one pool at a time; the stratum, the miner and
  `-p2poolpayto`/`-p2poolbind` do not change. Until the pool is active and its
  share chain is here, the stratum serves no template and the log says why
  (pending, unknown id, waiting for its line), as it does today while pool
  zero's history is on its way. A mined pool with nothing of it on this
  node starts its line here 2 minutes after it becomes active if no peer
  announces it, and in any case 10 minutes after it becomes active, whatever
  was asked meanwhile: peers that announce it but have no share of it yet
  answer `p2xnone`, and one that never answers holds nothing up (both are
  asked again a minute later, within what a peer answers, section 8); peers
  are asked `poolwho` meanwhile, the first ones that read the registry as
  soon as they connect. A carrier a peer names in its `poolat` answer is
  dialled (below, *Dialling guardians*) and counts as an announcer for the
  2 minutes while it is (named within the last 10 minutes); the 10 minutes
  hold whatever. An answer that comes after the line started here is still
  taken, and the line with more work wins.
- **Not on mainnet before the release that opens it.** Until
  `POOL_REGISTRY_MAINNET_OPEN` (`src/poolindex.h`) is true, a mainnet node
  refuses to start with `-p2pool=<poolid>` or `-poolcarry`, and no
  registered pool is ever live there whatever its status in the index
  (anyone can burn a record with `sendburn`): nothing of one is fetched,
  mined, carried, announced, relayed or served, its files are not read, and
  every `p2x*` and `pool*` message is dropped unread, nobody scored. One
  check in `p2pool_net.cpp` (`RegOpen`, the same `PoolBurnsOpen()` that
  closes `poolcreate everpool "send"`) gates all of it. Pool zero and local
  pools are not registered pools and are unaffected. Testnet is open.
- The node carries the pool it mines (keeps its chain in
  `pools/<poolid>.dat`, relays it, announces it), plus pool zero, plus what the
  draw gives it (section 10), plus any given with `-poolcarry=<poolid>`
  (at most 8).
- **A late share is named as soon as it arrives.** Today the job is rebuilt
  mainly when the share tip changes (`rpc.cpp`, step 1.5 of the stratum loop;
  also on a new block and every `JOB_REFRESH_SECS`), so a share that arrives
  late, as a sibling of the tip or of a share just below it, usually waits for
  the next tip before any template names it as an uncle, and loses one share
  interval of its uncle depth. The node also rebuilds the job when the uncles
  the next share on the tip could name differ from those of the current job:
  a share taken into the chain marks the job for a check, and the check
  (`UncleCandidates` of the tip, which scans the chain) runs at most once
  every 2 s; a mark inside the 2 s is kept for the next check, never dropped.
  The new job goes to miners without asking them to drop their current work
  (the old job stays valid). A peer that lacks the named uncle fetches it
  through its orphan queue and `p2pgetsh`/`p2xgetsh`, unscored, as for any
  share with a missing parent. This is local template building, not a share
  rule, so it applies to every pool, pool zero included, and needs no other
  node to upgrade.

RPC (in `src/jsonrpc.cpp`, with the other wallet calls):

| call | does |
|---|---|
| `poolcreate everpool {"name", "spacing", "window", "retarget", "floor", "uncledepth", "unclepct", "feebps", "feeaddress"} ["send" \| "dryrun" \| "publishzero"]` | builds the record, checks it canonically (the record's own check, the bytes read back as the same record, and the burn's script read back by the parser the index uses), and returns its hex, its id, its fingerprint, the fee and the burn, and whether the index already has it. Nothing is sent unless the third parameter is `"send"` or `"publishzero"`: then it burns 1 BTF into the record through the wallet's burn path (the one `sendburn` uses) and returns the txid too. The name is required; other unset fields take these defaults: window 2160, retarget 720, floor `0x1f0fffff`, uncle depth 3, uncle share 80, no fee (pool zero's values), and a spacing of 30 or `ceil(60 / depth)`, whichever is larger, so the defaults with any given depth make a valid record (pool zero alone may have 10). A record that breaks a rule of section 1 is refused with the rule it breaks, sent or not. `"send"` is refused for a pool the index already has (it would burn 1 BTF for nothing), for a burn of the same record already waiting to be mined or unconfirmed in the node's wallet, while the node is catching up and while the index is behind the node's tip (it could not tell); the checks and the burn run under one hold of the chain lock, so a block cannot land between them. The answer lists the other pools whose names look the same (`samename`). A record equal to pool zero's is refused with `"send"`; `"publishzero"` is the explicit word for the one-time publication of section 4. Until the release that carries and mines registered pools on mainnet, `"send"` and `"publishzero"` are refused there before any other check (one constant, `POOL_REGISTRY_MAINNET_OPEN` in `src/poolindex.h`, opens them), so nobody burns 1 BTF for a pool that cannot be mined; the preview works on mainnet and says so, and testnet is unchanged |
| `poolcreate local {...} [password]`, `pooljoin`, `poolpeers`, `poolleave` | a local pool, never on the chain (section 18). `poolcreate` with no mode is refused, naming the two, so nobody burns 1 BTF by default |
| `poollist` | pool zero first, then the recorded pools, pending and active, each with its status: id, fingerprint, name, rules, fee, first height, confirmations, appearances, anchors in the last 720 blocks (as `claims`), and, once pools are carried, whether carried and the share chain's height and work. Ordered by recent share work for carried pools, then by anchors, then by first appearance, never by name. Every entry lists the other pools named alike (case, `-` and `_` set aside), pool zero's "bitflash" included, by id and fingerprint; the answer carries the index's state and a note that names are not unique (section 12) |
| `poolinfo <poolid>` | one pool: the record decoded, its appearances, its last anchors, the index's height, its share chain if carried, its guardians this epoch (Phase C). An id nobody burned that blocks name shows as `unknown` with its claims only |

## 10. Rotating replication: guardians

The registry makes a pool permanent; the share chain still has to live
somewhere. Miners keep the chain of the pool they mine. Guardians keep it when
nobody does, and they are where a new miner finds it.

### What guardians are and are not

A guardian of pool P is a node that, for one epoch, keeps P's share chain
(the line behind the tip, `HISTORY_SHARES` deep, with its uncles), relays its
shares and serves `p2xsync`/`p2xgetsh` for it, whether or not it mines P.

**Guardians are availability, never trust.** Every share is PoW-valid on its
own, and a line is chosen by its work, so a guardian cannot forge a share,
cannot forge a lighter line into a heavier one, and cannot change a payout.
What a malicious guardian can do is **withhold**: not answer, or answer with an
old line. Everything below is built so that withholding by every guardian of a
pool at once costs that pool, at worst, a restart (see *Reviving*), and costs
nobody coins already paid: PPLNS pays a share in every block found while it is
in the window, and a block that was found has paid.

**Guardians do not vote and do not lead.** There is no leader among a pool's
guardians, no election and no threshold signature. Each one checks shares
against the pool's frozen rules version and follows the line with the most
work, exactly as every pool zero node does today. Two honest guardians cannot
disagree about a share's validity, and the old and new sets during a handoff
cannot either; a guardian that refuses a valid share is only withholding it,
and the miner sends it to every node that announces the pool.

**Guardians are not hidden.** Being a guardian is public by design: the
tickets are broadcast and a seeker computes a pool's sixteen so that it can
dial them. What stays private is what stays private for every node, its IP
address, which Tor hides. Cover traffic or padding to disguise guardian
traffic was considered and left out: it would cost every node bandwidth to
hide a role that does not need hiding, and a pool's share traffic is small (a
share every spacing, a few kilobytes) and paced (section 17).

**There is no minimum number of guardians.** A pool works with none while
somebody mines it, because its miners hold its line; guardians only keep it
when nobody does and give a new miner somewhere to find it. On a network with
fewer tickets than places, every node is drawn for every pool and the guard
budget (section 11) keeps the pools with the most work. As nodes join, the
next epoch's draw spreads the pools over them with no step of its own.

### Epochs and seeds

- An **epoch** is 720 blocks (about a day): epoch `e` is heights `720e` to
  `720e + 719`.
- The **ticket seed** of epoch `e` is the hash of block `720(e - 1)`, the first
  block of the epoch before. It is known a whole epoch in advance, so tickets
  for `e` are made during `e - 1`.
- The **ticket deadline** of epoch `e` is block `720e - 120`. Once a node has
  that block on its active chain it no longer takes tickets for `e` that a
  peer relays unasked (dropped innocently, nobody scored). Tickets that come
  in answer to its own `poolgettkt` are still taken (below).
- The **draw seed** of epoch `e` is the hash of block `720e - 60`, two hours
  before the epoch starts and sixty blocks after the deadline. The draw is
  *settled* when that block has 30 confirmations, at height `720e - 31`; a
  reorg deeper than that redraws, and both sets keep the chains (see
  *Handoff*).

Nothing in a ticket can prove when it was made, so the deadline is enforced by
each node on its own view, and the draw is built so that a ticket made after
the seed is known gains nothing for free: a ticket's score depends on its
RandomX work hash (see *The draw*), so every try at a good score costs a whole
ticket of work. Were the score to depend on the `.btf` key alone, an attacker
who saw the seed could generate keys for free until 16 of them topped one
pool, and pay for only those 16 tickets. The deadline matters for nodes that
were online before it; a node that starts later asks its peers for the
tickets they hold (`poolgettkt`), and the work in the score is what protects
it.

**Why not a VRF.** Algorand-style sortition, where each node evaluates a VRF
on the seed and keeps quiet unless it is selected, was considered and is not
used, for two reasons. A BIP340 signature is not a VRF: the signer picks the
nonce, so one key can produce many valid signatures over the same message and
keep the one that scores best. A real VRF (ECVRF, RFC 9381) would be new
cryptography and a new dependency for a property the ticket already has: its
work hash is fixed an epoch before the draw seed exists, one ticket per key
counts, and anyone can recompute the score. The second reason is that silent
self-selection does not fit what guardians are for. A guardian exists to be
found by a miner who needs a pool's line, so the seeker has to be able to
compute who guards the pool, which needs the tickets to be public. Tickets are
broadcast for that reason, not as a cost of the scheme.

### Who can be drawn: candidates and tickets

A **candidate** for epoch `e` is a node with a `.btf` identity (every node on
this network has one: the secp256k1 x-only key its address encodes, signed
with BIP340 Schnorr, `src/btfaddr.h`) that publishes a **guardian ticket** for
`e`:

A ticket is 118 bytes. Its body is the first 54:

| offset | bytes | field |
|---|---|---|
| 0 | 4 | network magic (`pchMessageStart`) |
| 4 | 4 | `"BTFG"` |
| 8 | 4 | epoch `e`, little-endian |
| 12 | 32 | the node's `.btf` public key, x-only, as its address encodes it |
| 44 | 2 | guard capacity in MB, little-endian (what it offers; informative) |
| 46 | 8 | nonce, little-endian |
| 54 | 64 | BIP340 Schnorr signature by that key over `SHA256("Bitflash/guard-ticket/1" \|\| the 54 bytes of the body)`, made and checked as descriptors are (`SignDescriptor`, `VerifyDescriptor`: `secp256k1_schnorrsig_sign32`, `secp256k1_xonly_pubkey_parse` and `secp256k1_schnorrsig_verify`) |

BIP340 verification is specified to the bit, so every node agrees on whether a
signature is valid; that matters because a bad signature is scored.

Its **work** is the main chain's PoW v2 RandomX hash (`GetPoWHash`, with no
new hash code) of this 80-byte header:

| header field | value |
|---|---|
| `nVersion` | `0x47465442` (the bytes `"BTFG"`), a domain tag. What actually keeps a ticket from being a share or a block is the merkle field: `SHA256d` of 54 bytes is neither a transaction id (a coinbase is longer) nor a merkle node (64 bytes) |
| `hashPrevBlock` | the ticket seed of epoch `e` |
| `hashMerkleRoot` | `SHA256d` of the 54-byte body |
| `nTime` | the network's PoW v2 switch time (`PoWV2Time()`), so the v2 key and layout are always the ones used |
| `nBits` | the ticket target, a fixed compact value per network |
| `nNonce` | the low 32 bits of the body's nonce |

The ticket is valid when that hash is at or under the ticket target, the
signature verifies, the magic is this network's and the epoch is the
previous, the current or the next one by this node's tip. The previous epoch
is needed only through handoff: with the tip in epoch `c`, tickets of epoch
`c - 1` are taken, held and served while the tip is below `720c + 180`, the
height at which that epoch's guardians let go, and are dropped and forgotten
from that height on. The **work hash** is that RandomX hash.

**Byte orders.** Hashes enter `SHA256d` in their internal byte order (as the
node serializes a `uint256`); the work hash and the score are compared as
`uint256` numbers, the way a block's PoW hash is compared with its target.
Phase C pins vectors for the body, the header, the work hash and the score.

- The **signature** proves the ticket belongs to that `.btf` identity, the one
  whose signed descriptor tells everybody which onion reaches it. Reaching the
  onion is the authentication of the node (`docs/rendezvous.md`), so a ticket
  names a node anyone can dial and check. (The signature is not part of the
  work or the score, so a second signature over the same body gains nothing.)
- The **ticket target** is the compact value `0x1f07ffff` on both networks:
  one hash in 8192 meets it, so a ticket takes about 8192 hashes to make and
  one to check. It was measured in Phase C on the verification (light)
  RandomX VM, on one core at idle priority on a busy four-core server: 33 to
  55 hashes a second, so 2.5 to 4 minutes of that core for a ticket, once a
  day. The aim was a few minutes of one core per node per day. The work makes
  a ticket cost something to make and something to check, so tickets cannot
  be minted by the million or used to flood.
- **One ticket per `.btf` key per epoch.** If a key has more than one valid
  ticket for an epoch, the one with the lowest work hash is the ticket; every
  node keeps that one, so views converge.
- Tickets travel in `pooltkt` between `NODE_POOLREG` peers. A node checks one
  in this order:
  1. framing and magic; a malformed message, another network's magic, or a
     ticket whose body epoch is not the message's epoch is the sender's fault
     and scored;
  2. **innocent drops, before any hash, nobody scored:** an epoch outside
     previous, current and next by this node's tip (the previous one counts
     only while the tip is below the current epoch's `720e + 180`); a ticket
     seed block this
     node does not have on its active chain with at least 30 confirmations
     (a syncing node, or one on the other side of a reorg at an epoch
     boundary, judges such a ticket on a view the sender may not share); a
     message whose stated seed hash is not that block's hash (the sender is on
     another branch, however deep the reorg); the deadline (unasked relays
     only); a body already in this epoch's checked set (below);
  3. the signature, then the work against the seed the message names, which
     step 2 made sure is also this node's, under a RandomX budget of its own,
     separate from both share budgets, and spent on older connections first
     (the `OlderHeld` order), so tickets from fresh connections cannot starve
     the answers this node asked for.

  **The checked set.** A body (`SHA256d` of its 54 bytes) enters this
  epoch's checked set **only once its signature has verified and its work has
  passed**, and stays whether the ticket is then kept or loses (outranked for
  its key, or past the cap). So:
  - a replay of a valid ticket never costs a second hash;
  - a copy of an honest body with a bad signature costs this node one
    signature check, scores its sender, and leaves nothing behind: it cannot
    keep the real ticket out;
  - a body whose work fails is not remembered: every copy of it can only come
    from a dishonest sender (failed work against the seed the sender named is
    never honest), so every copy is checked and scored again, and nothing
    about it needs room;
  - the set fills only with bodies that each cost a ticket of work. It holds
    up to 16384 per epoch; when full, the body with the highest work hash
    among those not in the held set leaves to make room for the newcomer, and
    a new body is never refused for want of room;
  - a body that leaves that way is still remembered, by a **replay tag**: 64
    bits of a hash of the body under a salt each node picks for itself. A
    body not in the held set can never enter it under the same seed (a key's
    ticket and the cap's cutoff only go down), so a body whose tag is
    remembered is dropped in step 2 like one in the checked set, before any
    hash, nobody scored. Without the tags, two such bodies sent in turn would
    each cost a signature check and a hash every time, unscored. Up to 65536
    tags are kept per epoch (a few megabytes); past that one tag is
    forgotten for each new one, and a body whose tag was forgotten is checked
    again when it comes again. Filling the tags takes that many bodies that
    each cost a ticket of work, and what is left is bounded by the ticket
    budget. The salt keeps anyone from aiming a body at another body's tag,
    and makes the tags mean nothing on another node;
  - the set and its tags belong to one seed: they are emptied with the held
    set when the epoch's seed block leaves the active chain.

  A ticket that passes and enters the held set is held and relayed; one that
  passes but is not held (outranked for its key, or past the cap) stays in
  the checked set and is not relayed. A connection whose relays keep coming back
  outranked or past the cap is not scored for it, and is served last from
  the ticket budget. Only a failure in step 1 or 3
  scores the sender, once per message: a `pooltkt` is read up to its first
  invalid ticket, and the rest of it is dropped. An unasked relay that finds
  the ticket budget empty is dropped, unscored (the ticket will come again,
  or in an answer). A bad signature is never honest, and neither is work that
  fails against the seed the sender itself named: whatever the two nodes'
  views of the chain, that check gives the same answer on both. Answered
  tickets that wait in the queue for budget go through step 2 again when they
  leave it, the queue is emptied when a seed changes, and a disconnected
  peer's queued tickets are dropped.
- **The ticket format and target are frozen**, like a share rules version.
  Work that fails the target is scored, so a release that changed the target
  would make old and new honest nodes score each other; a change is a new
  ticket version, carried in a new command (`pooltkt2` and so on), never in
  `pooltkt`, so it is never parsed as a malformed version 1 ticket. A node
  ignores the command of a version it does not know, as it ignores any unknown
  command, and stops sending, without scoring anyone, a version it no longer
  takes.
- **When a seed block leaves the active chain** (a reorg at least 30 blocks
  deep through height `720(e - 1)`), the node drops its held set and its
  checked set for `e`,
  makes its own ticket for `e` again on the new seed, and fills the set again
  by relay and `poolgettkt`. It never sends a ticket checked against a seed
  that is no longer its own. A ticket a node makes
  after its own deadline travels only in answers to `poolgettkt`; a node makes
  its ticket for `e` as soon as the seed is buried, well before.
- **Getting the set.** A node that starts, restarts, finds it holds few
  tickets for an epoch, or has just buried a seed it was dropping relays for
  (step 2), sends `poolgettkt` for the epochs concerned (previous, current and
  next at start) to a few `NODE_POOLREG` peers. The answer is the peer's held set for
  that epoch, at most 4096 tickets (about 480 KB) in parts of 512. A peer
  serves a given epoch to a given connection at most once per
  `SYNC_SERVE_INTERVAL`, from the ticket class's own budget. A `pooltkt` counts
  as an answer only for the epoch this node asked that peer for, within
  `SYNC_ANSWER_WINDOW` of asking; anything else is a relay. Every ticket in an
  answer is checked as above, except for the deadline, and the 4096 cap
  applies. Checking a full answer costs up to 4096 hashes per epoch, more than
  the ticket budget gives at once, so answered tickets wait in a queue and are
  checked as the budget refills. Each asked peer's answer has its own queue
  (at most 4096 tickets, and at most 4 peers asked per epoch at a time:
  about 1.9 MB per epoch, 5.8 MB at start when three epochs are asked for), deduplicated **only within that queue and against
  the checked set**, never against another peer's queue: a body two peers
  sent waits in both queues, and whichever copy is reached second is dropped
  for free by step 2 (the first one's body is in the checked set by then).
  So no answering peer can take ownership of tickets others sent too, and a
  peer that disconnects, or whose queue is dropped, takes only its own copies
  with it. The queues are drained in turn, one ticket from each; at the first
  invalid ticket in a peer's answer, that peer is scored once and its queue
  dropped. Tickets that arrive beyond a full queue are dropped, unscored. Phase C
  sizes the budget so a fresh node sees the draw within an hour.
- **Persistence.** A node keeps its own tickets and its held sets for the
  previous, current and next epochs, each with the seed hash it was checked
  against, in `pool-tickets.dat`, read back at start
  and checked again through the ticket budget queue like an answer (up to
  3 x 4096 hashes, never blocking the start), so a restart does not leave it
  blind for the rest of an epoch.
- **A ticket is not a coin.** It is never on the main chain, spends no output
  and is not held by the wallet. It cannot usefully be sold: it is signed by a
  node's `.btf` key and names that node's onion, so handing it over means
  handing over the node's identity, and it is worth one epoch, about a day.
  Buying tickets is buying RandomX work under someone else's name, which an
  attacker can do more simply by computing them, and what either buys is
  bounded the same way (section 12).
- **A drawn node that does not serve keeps its ticket.** There is no penalty
  and no "inactive" mark: such a mark would be a reputation under another
  name, and an attacker would pass it by answering the first dial and going
  quiet after. A drawn node that does not announce the pool simply receives
  none of its shares, and the reserve, the lingering set, the miners and every
  announcing peer are asked in its place.
- **At most 4096 tickets per epoch are held; past that, the 4096 with the
  lowest work hashes.** Arrival order would let whoever floods first fill the
  set; lowest hash makes every node converge on the same set whatever the
  order, and an attacker's place in it is proportional to the work spent, slot
  by slot, against honest tickets.

A node that does not listen on an onion cannot be dialled and does not make
tickets. A node with `-poolguard=0` makes none either.

### The draw

For every **active** registered pool P except pool zero, and every ticket t of
epoch `e`:

```
score(t, P) = SHA256d( "Bitflash/guard/1" || draw seed of e || poolId of P || work hash of t )
```

Lowest score first. The **guardians** of P in epoch `e` are the **8** tickets
with the lowest scores; ranks 9 to 16 are its **reserve**. With 16 tickets or
fewer, every candidate is a guardian or reserve of every pool, within its
budget.

This is rendezvous hashing: every pool gets its own random order of all
candidates, so an attacker cannot aim at one pool without winning that pool's
order, and a node's pools change completely every epoch. Each node computes
its own ranks only: pools times tickets SHA256d, about ten million for ten
thousand pools and a thousand tickets, a few seconds once a day.

**The draw is deterministic over the tickets a node holds**, and two nodes may
hold slightly different sets (a ticket still travelling). That is acceptable
because guardianship is availability, not agreement: no share and no payout
depends on who the guardians are. Disagreement at the edges means one guardian
more somewhere, never a share judged differently.

- A node **guards** P if its own ticket is among P's 8 in its view; it also
  guards P if it is in the reserve and has room in its budget (section 11).
- A node that **looks for** P (to mine it, to revive it, to carry it) computes
  P's 16 from the tickets it holds, resolves their `.btf` addresses the usual
  way (peer cache, descriptors from peers, Nostr only on a miss), and dials them
  as a P2Pool miner dials `NODE_P2POOL` peers today: up to 3 connections past
  its usual 8. It also asks its own peers (`poolwho`), which answer with nodes
  that announced P to them (`poolinv`).

**When a node is drawn for more pools than its budget holds,** it ranks them
by the work of the line it holds or was offered, over the pool's last window,
heaviest first, and keeps the top 8 that fit (section 11). It learns that work
by pulling at handoff, and a pool that turns out empty takes no slot. Pulls
are paced by the registered request budget (on a small network every node is
drawn for every pool, and pulls them all); a pool whose work is not known yet
ranks last. Anchors
and registration age do not rank: anyone mining a block can add an anchor, and
age would let old spam outrank a new real pool. Work cannot be faked: a spam
pool with a few floor shares (seconds of CPU each) ranks below any pool that
is really mined. A never-mined pool costs a guardian one `p2xsync` per epoch,
within the request budgets, and a `p2xnone` when somebody asks; a lightly
mined spam pool costs it that and a few shares, and loses its slot to any real
pool.

**A pool that starts mid-epoch.** A guardian of P that holds nothing of it
does not announce it, so nobody pushes it shares. So when a guardian sees a
`poolinv` naming a pool it guards and holds no line of, it sends that peer
`p2xsync` for it, within its budgets. Once it holds the line, it announces the
pool and shares are pushed to it like to any carrier. A pool started
the morning after a draw has guardian copies within minutes, not at the next
epoch.

**Nodes may disagree about who guards what.** Ticket sets differ at the edges,
reserve take-up depends on each node's room, and budgets rank on what each
node was offered, so there are no tie-breaks to agree on. That only changes
who keeps a copy, never a share's validity, and a seeker asks all 16 plus
every announcing peer.

### Handoff

- From the moment the draw for `e` is settled (height `720e - 31`), every new
  guardian of P **pulls** P's line: it sends `p2xsync` to the guardians of
  `e - 1` it can reach, and to any peer that announces P, and takes the
  heaviest line by the existing rules (`AddHistory`: the newest *retarget
  window* shares checked in full, the deeper ones on their work alone, a
  history only from a peer asked, soon after asking). Nobody pushes a history:
  a history is what a node asks for, never what a peer may send unasked
  (`docs/p2pool.md`).
- Old guardians **linger**: they keep P and keep serving it until height
  `720e + 180` (six hours into the new epoch), then drop it unless they mine
  it, carry it by `-poolcarry`, or were drawn again. A redraw after a deep
  reorg is handled the same way: every node drawn by either seed holds P until
  the later linger ends, which is the later of height `720e + 180` and 180
  blocks after the node saw the draw seed change.
- A guardian that leaves early, or never answers, is simply one guardian fewer;
  the reserve, the lingering set, the miners and every node that announces P
  are all asked.

### Reviving a dormant pool

A pool is dormant when nobody mines it: its newest share is older than its
`TIP_MAX_AGE`. To revive it, a miner starts the node with `-p2pool=<poolid>`:

1. The node looks for P (above) and asks every source for its line. It takes
   the heaviest; with no tip of its own, the dormant line is taken whatever its
   age (`Heavier`: an empty tip is replaced by anything checked in full).
2. **The anchors pick out the true line.** The index knows the main-chain
   blocks whose coinbase anchored P (section 7), each naming one share's data
   hash. A line containing the most recently anchored share is the line the
   pool's last block was found on. A node prefers, among histories of equal
   standing, one that contains it, and logs a warning when the heaviest line
   it was given does not: that is the sign of a guardian serving a stale or
   private line. (It is a preference, not a validity rule: an honest guardian
   may not hold a share that was a block on a side line.)
3. The node mines on the tip. The retarget is slow to ease after a long gap:
   the first share after it is at the old difficulty (its retarget window does
   not contain the gap), and from then on each share's target is the mean of
   the last *retarget window* targets times a factor clamped to 4, so the
   easing does not compound per share. A lone miner with 1% of the pool's old
   hashrate needs on the order of a day to bring the line back to its pace.
   That miner may instead start a new line from a first share (step 4): a
   live line replaces a dormant one (`Heavier`, `TIP_MAX_AGE`), its first
   *retarget window* shares are at the floor, and the pool is the same pool.
   Continuing pays the old window's miners from the reviver's blocks, starting
   over does not. This is not the reviver's choice alone: once a line is
   dormant, anybody can replace it with a cheap live one, since live beats
   dormant whatever the work (pool zero has the same rule today), and the
   anchor preference of step 2 does not stop it. A dormant window's value is
   the goodwill of whoever mines next; a pool whose miners want their window
   paid keeps mining it.
4. **If no copy is left anywhere,** the node waits as long as a starting pool
   zero node waits for history, then starts P's chain from a new first share
   (`hashPrevShare = 0`), exactly as a pool zero node does with no peers. The
   pool is the same pool: same id, same rules, same fee, same anchors on the
   chain. What is lost is the unpaid part of the old window, which had value
   only if somebody mined on it.

**Why the old window cannot be rebuilt from the chain.** A main-chain anchor
names one share's data hash, and the coinbase it sits in shows the payout list
at that moment, but not the shares behind it. Crediting that list to a new
chain would make share validity depend on main-chain data, which
`docs/p2pool.md` forbids for a reason the testnet proved: two honest nodes,
one holding a main block and one not, judged the same share differently and
parted ways for good. So "rebuilt from on-chain anchors" means what it can
mean safely: the record alone restarts the pool, and the anchors tell a
reviving node which offered line is the real one.

### Opting out

Guarding is **on by default** on every node of a release with the registry,
mining or not, because pools travel only if ordinary nodes carry them. It is
on through bridges too: a node on Snowflake or meek makes its ticket and
holds, serves and pulls pools like any other, at whatever speed its circuit
carries (section 17). What
that costs a node that never touches an option: one ticket a day (a few
minutes of one core at idle priority), at most 128 MB of guarded share chains,
at most 64 KB/s serving them, and the ticket traffic of section 11 (about
0.5 MB of tickets a day for each peer it relays them to, plus up to 1.9 MB
when it asks peers for a set, 5.8 MB at start).

`-poolguard=0`: no tickets, never drawn, carries only pool zero, the pool it
mines and `-poolcarry` pools. Mining is unaffected. Such a node also takes
no part in ticket traffic: it drops `pooltkt` and `poolgettkt` unread, as a
node where registered pools are closed does, and a pool it mines is found
through announcing peers and `poolwho` only. `-poolguardmb` sets the guard
budget in MB (default 128); `-poolguardkbps` sets the pace of each registered
history serve in KB/s (default 64, section 17).

### In the node (Phase C)

What the rules above leave to each node, as Phase C does it. None of it is a
rule another node checks; two nodes doing it differently disagree at most
about who keeps a copy.

- **Where the work is done.** Messages are read on the message thread with
  no hash: the stated epoch and seed of a `pooltkt` are judged before any
  ticket is read (an epoch not taken, a seed not buried here or another one,
  an unasked relay past the deadline: the whole message dropped, nobody
  scored), each ticket then goes through steps 1 and 2 (`Precheck`), and
  what passes waits in a queue. A thread of its own, with a RandomX light VM
  of its own (never the verification VM that blocks and shares wait on),
  takes one ticket per budget token, runs steps 1 and 2 again on the chain
  of that moment, checks the signature and the work with no lock held, and
  adds the ticket to the set under the pools' lock. The hashing (ticket
  checks, the node's own ticket, the draw's ranking, the file's bytes) runs
  on a worker at idle priority that takes no lock of the node; the ticket
  thread itself keeps the normal priority and holds the pools' lock only to
  pick and to copy, so the miners never hold up a thread that the message
  thread and stratum wait on (on Linux an unprivileged thread cannot raise
  its priority again once lowered). A work hash that could not be computed
  here drops the ticket unscored and pauses all checks for 60 s; an answer
  waits to be tried again, a relay is gone.
- **Caught up first.** While the node is in initial block download, or its
  tip is more than a day old, it makes no ticket of its own, draws nothing,
  changes nothing it guards and asks no peer for a set: a syncing node's tip
  walks through epochs long over, and would grind a ticket and draw itself
  into pools for each of them.
- **The ticket budget**: 4 hashes a second with a burst of 256, one budget
  for every peer and every pool. Three epochs of 4096 then fit in 51 minutes.
  The order: relays of connections in good standing (older connections
  first) and the answer queues (in turn, one ticket from each, the node's
  own file among them) take the tokens in turn while both wait, so relays
  from any number of new connections never starve the answers; then relays
  of connections in low standing, once no answer waits. Low standing: 8 or
  more relays in an interval that came back outranked or past the cap, and
  more than twice those held; a relay scored for a bad signature or failed
  work counts 8 at once. A relay that finds the budget empty is dropped, and
  every relay waiting with it; answers wait. Relays wait at most 512 per
  connection and 4096 in all; past that they are dropped, unscored.
- **Scoring**: 20 points, once per message. A relay is read up to its first
  ticket the sender is at fault for; when a later check finds a bad
  signature or failed work, the sender is scored once for that message and
  the rest of that message is dropped. An answer with one bad ticket loses
  its whole queue.
- **Asking for sets**: an epoch whose seed is buried is asked for when the
  node starts, when its seed is newly buried, after its seed was reorged out,
  and once an interval while fewer than 64 of its tickets are held. Peers
  that dialled out from this node come first, at most 4 answers wait per
  epoch, and a peer is asked an epoch once an interval. A set is served from
  a budget of its own (one every 30 s, 8 at once).
- **This node's own ticket**: made for the current epoch and the next as soon
  as each seed is buried, 16 nonces at a time between checks, only on a node
  that listens on an onion; the .btf key signs it where the key is kept,
  only if the work was ground for that key. Not made while the one read back
  from `pool-tickets.dat` still waits in the queue for a token. A ticket the
  file marks as this node's but of another key (an earlier identity) is
  held as anybody's, never as this node's own. A ticket made after its
  epoch's deadline (a node started late, a seed reorged out) travels only in
  answers.
- **The draw** is made again at most every 30 s when the tickets or the tip
  changed, and at least every 10 minutes for the index's new pools, over a
  copy of the tickets with no lock held. The draws in force are the previous
  epoch's until its linger end, the current epoch's, the next epoch's once
  settled (its guardians pull early), and each seed a redraw replaced, until
  its own linger end. A pool takes from them this node's best place and the
  latest linger end among them; a pool the draw no longer names (its tickets
  gone with a reorged ticket seed, or this node's place moved past 16 as
  tickets came in) keeps what it had and lingers to its end.
- **Pulls**: a drawn pool whose line is not known is pulled, at most 4 at
  once beside those kept, those a peer announces first; it is asked of
  announcing peers (`p2xsync`, through the fetch of section 17), and peers
  are asked `poolwho`. A pull with nothing fetched and nobody announcing the
  pool after 10 minutes takes the pool as having no shares (no slot), until a
  peer announces it. A pool let go for want of room keeps the size and work
  its line had, so it is not pulled again only to be let go again.
- **Letting go**: a guarded pool this node neither mines nor carries by
  `-poolcarry`, once no longer kept, gives back its line in memory and on
  disk (`pools/<id>.dat`), so a guardian holds what the guard budget allows
  and nothing more however many pools the draws name over the epochs. A
  pool this node mines or carries is carried at pool zero's caps and takes
  nothing of the guard budget.
- **Dialling guardians**: for the pool this node mines while its line is not
  here, and for pulls nobody announces, the draws in force name up to 16
  .btf addresses (this node aside); the dialler resolves them from its peer
  cache, through Nostr on a miss, and keeps up to 3 connections to them past
  its usual peers, 2 dials a round. Ahead of them come the carriers that
  peers named in answer to this node's `poolwho` for a pool it mines,
  carries or guards (the newest 8 a pool, each for 10 minutes after it was
  named, newest first), on a node with `-poolguard=0` too, which has no
  guardians to dial: each was seen announcing the pool, where a guardian may
  hold nothing of it. (Before this, the names went only into pool zero's
  peer cache, which marks addresses it already holds and is dialled from
  only while fewer than 3 pool zero peers are connected, so a node reached a
  carrier named to it only if its ordinary dialling happened to; on
  testnet's few nodes it usually does, on a larger network it would not.)
- **Files**: `pool-tickets.dat` is written when the sets changed, at most
  once a minute, and at exit; it is read at start and queued as an answer,
  never hashed where it stands. `pool-guards.dat` keeps the pools kept, each
  with its place, its linger end and its record, so a restart does not
  forget a pool held under a seed a redraw replaced: until that linger end a
  draw after the restart (which cannot see the replaced seed) does not
  replace the file's better place or later end. A pool read back from it is
  not taken as active until the index says so (section 17): one retired
  while the node was down is neither carried nor served. The file is copied
  under the pools' lock and its bytes made outside it.
- **`poolinfo`** lists a pool's 16 in this node's view and this node's own
  place, what it does with the pool and until when.

## 11. Storage and bandwidth bounds

| what | bound |
|---|---|
| registry index | a few hundred bytes per pool, on disk and in memory; grows only by burns of 1 BTF |
| pools carried | pool zero, the pool mined, up to 8 by `-poolcarry`, and guarded pools within the guard budget |
| guard budget, bytes | `-poolguardmb`, default 128 MB of share chains in all guarded pools, at most 64 MB of it for one pool. A pool whose whole line does not fit in what is left is not guarded by this node at all (not announced; the next in its ranking, and the reserve, hold it): a partial line is useless, since `AddHistory` needs a whole window behind the newest *retarget window* shares |
| guard budget, pools with shares | at most 8 at once, whatever the bytes (pools with no shares do not count) |
| on Snowflake or meek | exactly as every node: the same budgets, slots, rates and pulls; the circuit alone sets the speed (section 17) |
| a mined or `-poolcarry` pool | the caps pool zero has today (`MAX_CHAIN_SHARES`, `MAX_CHAIN_BYTES`, `MAX_TRUSTED_BYTES`), each pool on its own. The ceiling is the operator's choice: pool zero, the mined pool and 8 `-poolcarry` pools at 128 MB each is about 1.3 GB, plus the guard budget; a node with neither option holds pool zero and the guard budget only |
| guard bandwidth | `-poolguardkbps`, default 64 KB/s, pacing every registered history serve (guarded, mined and carried pools alike, section 17); past it a `p2xsync` waits (`DeferSync`), never refused for good. A local pool's serves (section 18) keep 64 KB/s whatever it says |
| share relay | as pool zero: one share per spacing on average (the retarget keeps it there), each at most `MAX_SHARE_BYTES`, sent only to peers that announced the pool |
| tickets | at most 4096 per epoch, 118 bytes each: about 0.5 MB a day for each peer they are relayed to; an asked set adds up to 4 answers of 480 KB, about 1.9 MB per epoch, 5.8 MB at start (section 10) |
| RandomX | three budgets: pool zero's (unchanged), one for all registered pools together, one for tickets; never one per pool |
| requests from one connection | at most 8 registered pools' histories per `SYNC_SERVE_INTERVAL`; per carried pool one paced serve in flight, 3 `p2xsync` asks and one history's worth of shares per interval, resumed asks included; asks about pools not carried, 8 per interval per connection, the rest dropped (section 8) |
| a fetch in progress | `pools/<poolid>.part`: only the shares the share chain took (never one it already held, whatever its bytes), written from the chain's own copies, and never past the pool's byte cap (`MAX_CHAIN_BYTES`; past it the fetch goes on in memory only, and a restart resumes from what the file holds); read back no further than that cap. Deleted once the line is complete and written to `pools/<poolid>.dat`, after 24 hours without a new share (shares already held do not count), or when the index, loaded and at its tip, says the pool is no longer active (section 17) |
| local pools (section 18) | at most 4 per node, each with pool zero's caps (`MAX_CHAIN_SHARES`, `MAX_CHAIN_BYTES`, `MAX_TRUSTED_BYTES`), 16 listed peers and 16 sessions; their traffic in the registered class |

What it costs in practice: an honest pool's line is about 2900 shares with
their uncles; with a few dozen miners a share is 1 to 3 KB, so a line is 3 to
9 MB, and the default budget holds a dozen or more such pools. A share every
spacing (10 s for pool zero, 20 s or more for others) of 2 KB to each of up to 8 peers that carry the pool is under 2 KB/s per
pool.

A line bigger than the 64 MB a guardian gives one pool (shares near
`MAX_SHARE_BYTES`, payouts to very many miners) is guarded by nobody on the
default settings. It lives with its miners and with `-poolcarry` nodes, at
pool zero's caps; if every one of them leaves, it restarts like any pool with
no copy left (section 10, *Reviving*), and no coins already paid are lost.

`-poolguard=0` brings all of it to zero.

## 12. Threat model, Sybil and DoS

What the registry protects: the rules of every pool, against everybody,
including its creator and the project. What guardians protect: the
availability of every pool's share chain, against ordinary churn and against
anybody short of capturing every copy. What neither protects: the main chain
against a hashrate majority (unchanged, as in `docs/p2pool.md`).

| threat | what happens | defence |
|---|---|---|
| spam registrations | the index grows; guardians are drawn for junk | 1 BTF burned per pool; a few hundred bytes each; a never-mined pool costs a guardian one request per epoch; guard slots are ranked by line work, so junk with a few floor shares never displaces a mined pool |
| a pool named like the default ("bitflash", "official") with a 3% fee | miners lured | wallets show the fingerprint (with the full id), the age, the fee and the work, never the name alone; pool zero is marked as entry zero; `poollist` and `poolinfo` list, on each entry, the other pools named alike, pool zero included, and say that names are not unique; the fee is capped and can never rise |
| fragmentation | a small network split into many small pools, each with more variance | pool zero stays the default; `poollist` orders by work; the choice is the miner's |
| a frozen bug in a rules version | a pool cannot be fixed | the fix is a new version and new pools; releases may refuse to build templates for a broken version, never stop validating it |
| a fake anchor (a solo block labelled `"p2x" + id`) | a pool looks more successful than it is | anchors are shown as claims; a node that carries the pool shows the blocks its share chain confirms, and orders by share work, not anchors |
| a malicious guardian withholds | a new miner cannot fetch the line from it | reserve, lingering set, miners, every announcing peer, `poolwho`; at worst a restart, no coins lost |
| all 16 guardians of a pool flooded at once while a miner M is active | a new miner N cannot reach the guardians | M announces the pool to its own peers (`poolinv`) whatever the guardians do, and N asks its peers (`poolwho`): one peer in common is enough for N to fetch M's line. Hints are not passed on (a lie costs one dial), so with no peer in common N waits and starts its own line; when the two meet, M's line has more work and wins, N's lone shares are orphaned, and M's window and the blocks it found are untouched. The attack costs flooding 16 onion services for the whole time and cutting every common peer, and buys an hour's delay for one newcomer |
| a malicious guardian serves an old or private line | a reviving node mines on the wrong line | chain choice by work, `TIP_MAX_AGE`, and the anchor check (section 10); a forged heavier line needs real PoW |
| a forged deep history | displaces an honest line | unchanged from pool zero: the deep end of a history is trusted on work alone, so a forgery needs as much work as the honest line, and is taken only from a peer this node asked: for pool zero within 5 minutes of asking, as today; for a registered pool the first part within 60 minutes of asking, each next one within 5 minutes of the one before, never more than 60 minutes after asking, and never more shares than one history (section 17) |
| Sybil: many tickets to capture a pool's guardians | the attacker holds all 8 and the reserve of one pool for one epoch | each ticket costs RandomX work, every epoch; the score depends on the work hash, so aiming at one pool after seeing the seed costs a ticket per try; the held set is the 4096 lowest work hashes, so an attacker's share of it, and of every pool's places, follows its share of all ticket work; and capture only buys withholding, which the rows above bound |
| Sybil: flooding the ticket set to switch guardians off everywhere | every node's 4096 places filled by attacker tickets | the attacker must out-work honest tickets slot by slot (lowest hash wins, not first arrival); honest guardians whose tickets fall out still hold what they held, miners hold their pools, `poolwho` still finds announcing peers |
| grinding the draw seed | a miner withholds a block to change the draw | the seed is one block two hours before the epoch; each retry costs a block reward and gives one random redraw; tickets are fixed a whole epoch before; and the prize is withholding |
| flooding `p2x*` for pools not carried | CPU, memory | dropped at the pool id, unread and unhashed, nobody scored (section 8: scoring would punish honest races and change how pool zero treats the peer); requests rationed by the registered budgets |
| flooding shares of a carried pool | CPU | the shared RandomX budget, the orphan queue cap, scoring of invalid shares, as pool zero |
| a pool whose shares are as big as rules allow | memory | per-pool and total guard caps (a line that does not fit is not guarded, never kept in part to be served); a fetch in progress is kept in part only by the node fetching it, within the pool's cap, and is not announced, served, relayed or mined on until complete (section 17); a pool's own miners carry it at pool zero's caps |
| flooding tickets | CPU, memory | the work, the signature, the deadline, the same-body check before any hash, one per key per epoch, 4096 per epoch, the tickets' own RandomX budget, scoring only for bad framing, bad signatures and failed work against a buried seed. Workless relays with valid signatures from throwaway keys over many new connections (each scored message costs a token) cannot starve the sets a node asked for, nor its own `pool-tickets.dat`: relays and answers take the tokens in turn while both wait, and a connection scored once waits behind every answer for the interval (section 10, *In the node*) |
| registered pools crowding out pool zero | a starting 1.2.34 node cannot get pool zero's line | pool zero keeps its 1.2.34 budgets and queues for itself alone (section 8) |
| lies in `poolinv` / `poolwho` | wasted dials | hints only, never passed on; a lie costs one dial, as `p2ppeers` |
| PoW reused on two chains | double credit | exactly one commitment, of one pool, per coinbase (section 6) |
| a share replayed across networks | double credit | the network magic is in the pool id |
| a dormant line replaced by a cheap live one | the dormant window goes unpaid | inherent, as in pool zero today (live beats dormant); only a dormant line is exposed, and its window is worth only what the next miner chooses to pay (section 10, *Reviving*) |
| the registration reorged out | the pool disappears | it comes back when the same bytes are mined again, by anybody, with the same id; its chain stays on disk meanwhile |
| main-chain miners refusing registrations | a pool cannot be created | any miner, solo or P2Pool with its own template, can include it; censoring it for good takes orphaning blocks, a majority attack on the main chain |
| the creator disappears | nothing | the creator has no role after the burn; the fee keeps going to the record's address, which nobody can change |

**Why the Sybil defence is enough.** No scheme that an honest node can afford
every day keeps a well-funded attacker from buying many identities; burning
coins for tickets or binding tickets to mining payouts would cost honest nodes
money or privacy and still only raise the price. What makes the guardian
scheme safe is that capture buys nothing but withholding of one pool for one
epoch, and withholding is bounded: miners hold their own pool's line, every
node that announces a pool is asked, and a pool that loses every copy restarts
with the same id and rules, losing no coins already paid. The ticket work is
there to make capture cost something and to bound the traffic, not to carry
safety.

**What capture costs, with the cap.** Say honest nodes make H tickets an epoch
and an attacker A, all at the same target. The held set is the 4096 lowest
work hashes of all H + A, so while H + A stays under 4096 everybody holds
everything, and past it the attacker's share of the set is about A / (H + A).
Each place of each pool then goes to the attacker with about that
probability, independently, so holding all 16 places of one chosen pool takes
about (A / (H + A))^16 per epoch: with A = H, one pool in 65,536 per epoch;
taking a chosen pool with even odds takes A around 22 times H. Aiming instead,
grinding tickets after the draw seed is known until 16 of them top one pool,
costs about 16 times H tickets for near-certain capture of that one pool: the
same order. Raising H is the honest answer: every guarding node makes one
ticket a day.

The estimate (A / (H + A))^16 treats the 16 places as independent. They are
drawn without replacement from the held set, so the true figure is a little
lower, and the difference shows only when the set is small: with 384 attacker
tickets among 512, the estimate gives 100 pools in 10,000 and the exact count
is 92.5. With thousands of tickets the two agree.

These counts are in tickets, and a ticket is a fixed number of hashes. Honest
nodes make theirs at idle priority on one core; a miner's rig in RandomX fast
mode makes many times more. In hashes: if a ticket costs W hashes, 22 H
tickets is 22 H W hashes, which for any miner is affordable, and filling all
4096 places is too. That is why this section does not rest on the cost: the
ticket work bounds traffic and makes capture cost something, and capture
still buys only withholding.

## 13. What stays out of consensus, and why

Nothing in this design needs rules v5 or any main-chain change:

- `OP_RETURN` outputs are valid and, since 1.2.28, standard. The registry is a
  reading of the chain, like the community directory.
- The `"p2x"` push lives in a coinbase scriptSig, which already takes any
  pushes up to 100 bytes.
- Share validity, chain choice, guardians and tickets are P2Pool protocol,
  which main-chain nodes never see.

Two things would need consensus and are deliberately left out:

- **Payouts enforced by the main chain** (a block marked with a pool id is
  invalid unless it pays that pool's window). Rejected in the research report
  and here: the PoW already binds the coinbase to the template, and the rule
  would tie every block's validity to share chain data many nodes do not have,
  so a share chain bug would stop the main chain.
- **A guarantee that registrations get mined.** Censoring transactions is a
  main-chain question for every transaction, not this one.

**A chain split.** Because nothing here is consensus, a split of the main
chain (a soft fork that some nodes do not follow, or an attack) needs no rule
of its own. Each node reads the registry from its own active chain, the one
with the most work. A record mined before the split exists on both sides with
the same id; one mined after exists only on the side that mined it. A share
commits to a template built on the node's own tip, so its payout lands on that
side only. When the split heals, the losing side's registrations and anchors
are undone like any reorg (section 3) and come back if mined again, and the
pool's share chain is kept on disk throughout. Nothing is re-anchored by hand.

## 14. Migration

- **The release.** P2Pool local (B1) may ship on its own once B1 is proven
  on testnet, since it needs no registry and no guardians; Everpool (B2 and
  C) ships together in a later release. Both come after 2026-12-25, unless
  fully proven earlier; nothing of this goes into
  the release carrying the swaps and rules v4. The work stays on branches until
  each phase is complete and proven.
- **Old and new nodes together.** 1.2.34 nodes mine and relay pool zero
  exactly as now. New nodes mine and relay pool zero exactly as now, plus
  anything else among themselves. A miner who never touches the new options
  sees no difference, and neither does a node that never upgrades.
- **Files.** `p2pool.dat` stays pool zero's. Registered pools live in
  `pools/<poolid>.dat`, the registry in `pool-registry.dat`, tickets in
  `pool-tickets.dat`. A node downgraded to 1.2.34 ignores all of them and
  mines pool zero.
- **Index start.** The index reads the chain from genesis on first start, once
  (records burned before the release are as valid as later ones).
- **Pool zero on the chain.** After the release, burn pool zero's record once
  on mainnet (section 4), so anyone can check its id against a block.
- **Docs.** `docs/p2pool.md` gets a section pointing here; `docs/rpc.md` the
  three calls; `docs/pool-directory.md` says the directory of pools is now the
  chain.

## 15. Test plan

### Self-tests and fuzzing (Phase B, every build)

- Record: encode and parse round-trip; every rule of section 1 rejected one at
  a time (non-canonical compact, fee with no destination, destination with no
  fee, bad name, push with `OP_PUSHDATA1`, trailing opcode, a later format, a
  burn under 1 BTF); the spacing rules (19 s refused, 20 s with depth 3
  taken and with depth 2 refused, 30 s with depth 2 taken, 59 s with depth 1
  refused, 60 s with depth 1 taken, depth 0 refused at any spacing, uncle
  share 79 refused, a copy of pool zero's record at 10 s with another name
  refused while pool zero's own is taken); `poolcreate`'s defaults make a
  valid record; pool zero's record and both ids above as fixed vectors.
- Index: synthetic chains with records at and around 30 confirmations; a
  reorg that removes an appearance before and after 30; a record appearing on
  both branches; a duplicate registration; deleting the index file and
  rebuilding gives the same registry.
- Pool zero unchanged: the existing P2Pool self-tests run through the v1
  parameter set with pool zero's parameters, unchanged and passing; a share
  built by the new code for pool zero is byte-identical to one built by 1.2.34
  for the same template.
- Format 1: the commitment rules of section 6 (missing `"p2x"`, two of them,
  wrong pool id, a `"p2p"` alongside), the 91-byte scriptSig bound, the fee
  split vectors (fee script in the window or not, rounding, fee 0).
- Routing: no `p2x*` message to a peer without `NODE_POOLREG`; no pushed share
  to a peer that did not announce the pool; a pushed share for an unannounced
  pool dropped before any hash and nobody scored, pool zero's id included;
  `p2xnone` for a request about a pool not carried or about pool zero's id; a
  share whose message pool id differs from `ShareDataX.poolId` scored as
  invalid.
- Pool zero isolation: registered-pool traffic that drains its own budgets
  leaves pool zero's budgets, queues, orphan and deferred state, history
  waiting state and per-connection state untouched (a 1.2.34-style history
  request is still served at once), and a peer that sent only registered
  shares is not proven for pool zero.
- The `p2x*` and `pool*` commands take the lock-free path.
- Late shares: a share that becomes an uncle candidate of the tip rebuilds the
  job (once per 2 s at most) and the next template names it.
- Resumable fetches (section 17): a resume point the server holds on its
  line, one it holds only as an uncle, and one it does not hold (the whole
  line, counted as a full serve), and one on a side branch (sent from where
  it meets the line, less the uncle depth); a fourth ask in an interval
  dropped silently; a second ask while a serve is in flight replacing it and
  counting as one of the 3; `p2xnone` answers counted; a resumed serve that
  would pass one history's worth cut there, and on an unproven connection
  the count kept for the life of the connection; the serve sending its
  snapshot even when the line moves or reorgs during it, with every uncle a
  part names sent in or before that part; a serve whose part has not drained
  in 5 minutes ended; unproven inbound serves held to half the slots; the
  receiving window restarted by each part, ended by an end flag, and closed
  at 60 minutes while parts keep coming; a serve cut short (a share of its
  snapshot pruned) flagged "ended early", leaving the chain not complete and
  resumed; "end of history" followed by the catch-up ask, the chain complete
  only after it (or 5 minutes without an answer); `AddHistory` reporting a
  part it stopped early on, so that part is not "taken in full"; a part of
  two shares over 256 x 1024 bytes refused, a single share over it taken; a
  slow serve older than 15 minutes under 1 KB/s ended when an ask waits; a
  partial fetch written to `pools/<poolid>.part`, read back after a restart
  through `AddHistory`, and resumed; no template, `poolinv` or serve before
  the chain is complete; the file deleted when it is. The partial file
  takes only shares the chain took (held ids resent with padded bodies add
  nothing), stops at the pool's byte cap with the fetch going on in memory,
  and goes a day after its last new share however many held ones keep
  coming; a part cut short at its end is cut off at start and the next part
  read back after the last whole one; a `.dat` that could not be written
  keeps it; a fetch read back at start keeps its file while the index has
  not loaded, is behind or is rebuilding, resumes once the ready index says
  active, and goes once it says otherwise. A silent announcer is left after
  3 minutes for another; a peer is asked at most 3 times a pool an interval;
  a mined pool whose only announcer never answers starts its line 10
  minutes after it became active.
- The mainnet gate: with registered pools closed, `-p2pool=<pool id>` and
  `-poolcarry` are refused, the mined pool has no template and takes no
  share, nothing is carried or announced, and a pushed share, a `p2xsync`,
  a `p2xgetsh`, a `poolwho` and a `poolinv` are dropped unread, nobody
  scored; opened again, all is as before.
- Transport (section 17): `gettorinfo` `transports` for bundled rungs and for
  user lines of each kind, `meek_lite` reported as meek, redone on a change
  of rung; and no pool behaviour reading it (budgets, slots, rate, pulls and
  ticket the same with any value).
- Phase C: ticket vectors (body, header, work hash, score), the lowest-hash
  rule for duplicates and for the 4096 cap, the deadline for relays and not
  for answers, the same-body check before the hash, a bad-signature copy
  arriving before the real ticket (the real one is still held), a checked set
  filled to its limit (no body refused), a failing body sent twice (checked
  and scored twice), answer queues drained in turn, an asked peer that
  disconnects before its queue is checked and one whose queue is dropped
  after a bad signature (in both, an honest peer's copies of the same tickets
  still end up held), a message naming another
  seed dropped unscored, a held set dropped and rebuilt when its seed is
  reorged out, a restart that reads
  `pool-tickets.dat` back and a fresh node that fills its set by
  `poolgettkt`, the draw over a fixed ticket set, guard ranking by line work,
  a guardian pulling a pool it sees announced mid-epoch, a guard budget full
  in bytes and one full in pools (the pool that does not fit is not announced,
  and the next node in its ranking holds it), a line over the per-pool guard
  cap (guarded by nobody, still held by its miners and carriers), and every
  guardian of both the old and the new set gone at once during a handoff (the
  new set pulls from miners and announcing peers, or the pool revives).
- P2Pool local: the self-tests of section 18.
- Fuzz targets for the record parser, for `ShareX` and for the `p2lhello` handler (`fuzz_p2pool` extended), and for the registered pools' messages (`fuzz_p2preg`).

### Testnet proof with real coins (Phase D)

On testnet blocks, with coins that mature and are spent, on at least two
machines (this bench and the 202, in private directories), plus a 1.2.34 node
on the same network the whole time:

1. **Two pools mined at once.** Register pool A (window 720, spacing 20 s) and
   pool B (window 1440, spacing 30 s, 1% fee to a fresh address); mine both,
   on different nodes, until each has found blocks. Check each coinbase to the
   satoshi against its share chain, the fee output to the satoshi, and that
   the 1.2.34 node kept mining pool zero alongside without a refused share.
2. **An "edit" makes a new pool.** Register A' (A with window 1080); show its
   id differs, A's record and share chain are untouched, and A keeps mining.
3. **The creator goes offline and the pool goes on.** Shut down the node that
   registered B, for good; B keeps finding blocks from other miners.
4. **Dormant and revived from guardians.** Stop every miner of A; wait past an
   epoch change; check the new guardians pulled A's line from the old ones;
   start a fresh node with `-p2pool=<A>` and an empty data directory; it fetches
   A's line from the guardians and its first block pays the old window. Then
   stop every guardian of A at once, old and new set, during the next handoff,
   with one node still carrying A by `-poolcarry`: a fresh node fetches A's
   line from that node through `poolwho`.
5. **Revived from the record alone.** Delete every copy of A's line
   everywhere; a fresh miner restarts A from a first share, same id, and finds
   a block.
6. **Reorg.** On the isolated bench pair (`-isolate`), register a pool, reorg
   it out before 30 confirmations, and show it disappears from `poollist` and
   comes back when re-mined.
7. **Through bridges.** Two testnet nodes run behind the bridge ladder for the
   whole proof, on hosts whose clocks are synced by NTP (offset logged under
   0.5 s), in this order:
   1. Neither node has a `bridges.txt`. Each is first started, runs
      `settorbridges "forget"` so no remembered rung changes where it starts,
      and is stopped; then both start with `-torbridges` (the bundled
      Snowflake rung); one stays there, the other is moved once with
      `settorbridges "now"` to the next rung, obfs4. `gettorinfo` confirms
      each: `transport` "snowflake" and "obfs4", and `transports` to match. (A user obfs4 line would show `transport` "user" and
      `transports` ["obfs4"]; that case is a Phase B self-test.)
   2. Pool A (spacing 20 s, depth 3) is mined by direct-Tor nodes holding at
      least 60% of its hashrate, and by each bridge node with at most 20%,
      until each bridge node has found at least 200 shares. For each of a
      bridge node's shares, its delay is measured: found in its log against
      arrival in a direct node's log, cross-checked against half the round
      trip of a `p2xgetsh` for a share the peer holds and its `p2xshare`
      answer, both logged with timestamps (`ping` has no reply to time); the
      reverse direction is measured the same way. **Pass mark:** each bridge node loses at most 5%
      of its shares (neither on the line nor named as an uncle), and its paid
      fraction (work credited, uncles at their share, over work found) is
      within 3 points of what the model of section 17 gives when fed each
      share's measured delays and the measured rate of the other miners'
      shares. The delays go into section 17.
   3. Both make tickets with default settings, and on testnet's few tickets
      both are drawn for A within an epoch or two (the step waits for that).
      Each holds and announces A like a direct guardian; the Snowflake node
      serves A's line to a fresh node, paced by its circuit, and the obfs4
      node serves it too.
   4. With A dormant, a fresh Snowflake node with an empty data directory
      fetches A's window from guardians; it announces nothing and builds no
      template while the chain is not complete; its managed Tor is killed
      halfway and the node restarted; it reloads `pools/<A>.part` and resumes
      from its newest share, the shares asked for again after the restart are
      at most one part's worth, and it starts mining once the chain is
      complete.
   5. The same with a live pool: while A is mined, a fresh obfs4 node fetches
      A's line, is restarted halfway, and resumes; the shares found on A
      meanwhile, and any reorg of its line, end up in its chain, and its
      first template is on the same tip as the miners'.
   6. Neither bridge node made a connection outside Tor: its firewall log, or
      `netstat` showing only the managed Tor's sockets, for the whole step.
8. **A local pool.** The proof of section 18 (*Tests and proof*): two
   members mine a password-protected local pool to a block whose coinbase
   pays both, a wrong-password peer gets nothing, nothing public names the
   pool, one member behind Snowflake.

Each step's proof goes into the PR with explorer links, and the public proofs
become text for the #dev channel.

### Mainnet

After the release: burn pool zero's record, and publish one real block found
through a registered pool, with the explorer link to its `"p2x"` anchor.

## 16. Phases

| phase | content | status |
|---|---|---|
| A | this design, reviewed | done (PR #82); bridges and the name (PR #84); P2Pool local (section 18, a follow-up) |
| B1 | the record checks (both magics), share rules v1 as parameters, the `ShareX` structure, the `"p2l"` anchor, the class split of section 8 (registered RandomX budget, orphan queue, send-queue accounting, slow-reader rule, deferred slots and last-good state, all apart from pool zero's) with its isolation self-test, `p2l*` on the lock-free command path, P2Pool local (section 18: code, password, id, keys, hello, `p2l*` messages, its RPCs), the job rebuild, paced snapshot serves and resumable fetches, mining a local pool on testnet with real coins (step 8); self-tests and fuzz. Lands first: no registry, no guardians | merged (#83) |
| B2 | the index with reorgs, `poolcreate everpool`/`poollist`/`poolinfo`, pool zero as entry zero, the `"p2x"` anchor, `NODE_POOLREG` and the `p2x*` messages, mining a chosen registered pool on testnet | part 1 (the index and its RPCs) merged (#87); part 2 (`NODE_POOLREG`, `poolinv`, the `p2x*` messages, `poolwho`/`poolat`, carried pools, `pools/<id>.dat` and `.part`, `-p2pool=<pool id>`, `-poolcarry`) merged (#91) |
| C | guardians: tickets, the draw, handoff, revival, budgets, the `transports` field of section 17 | part 1 (tickets, the draw, the guard budget, no network) merged (#89); part 2 (`pooltkt`/`poolgettkt`, the ticket thread, guarded pools, handoff and revival, `-poolguard*`, `poolinfo` guardians, self-test `p2pool-guardians`, `fuzz-pooltkt`) merged (#95); the `transports` field of section 17 done (`gettorinfo`, self-test `managed-tor`) |
| D | the testnet proof of section 15 | done on testnet, every step, payouts spent (PROOFS.md in the Everpool repository) |

## 17. Networks where Tor is blocked

Everpool has to work, in full, for a node that reaches Tor only through the
bridge ladder (`docs/censored-networks.md`: Snowflake, obfs4, webtunnel,
meek): mining a registered pool, relaying its shares, fetching a dormant
pool's window from guardians, and being a guardian. Nothing in the pool
protocol knows or needs to know how Tor reached the network; a bridge is below
it. This section is about what bridges cost, and how the design absorbs it.

### Latency

**What bridges add.** A message between two onion services already crosses six
relays. A bridge replaces the first hop of one side; obfs4 and webtunnel add
little, Snowflake adds a volunteer's WebRTC proxy, meek a CDN round trip, each
a second or more. This design plans for **10 s one way** between a bridge
user and the rest of the network in the worst case, and Phase D replaces that
figure with measurements (section 15, step 7).

**A bridge user is late twice.** It hears a new share `d` seconds after the
others, and keeps mining on the old tip meanwhile; then its own share reaches
the others `d` seconds after it is found. A share it finds can therefore meet
a competing share at the same height if another share appeared within about
`L = 2d` seconds around it (20 s in the planned worst case). With the other
miners' shares arriving at random at a rate `r`, that happens to a fraction
`1 - e^(-L r)` of its shares: this is the **contested** fraction. For a miner
with a small part of the pool's hashrate, `r` is about one share per `S`
seconds (spacing); for one with a fraction `f` of it, `r = (1 - f) / S`. The
table below takes `r = 1 / S`, the worst case.

**A contested share is an uncle, not a loss, if it is named in time.** It can
be named by a share on the line at most `D` (uncle depth) heights above it.
With the job rebuilt as soon as an uncle candidate arrives (section 9), the
next share found after it arrives names it, so it is lost only when the line
has already grown `D` or more shares past it by then. The delay from the
competing share to the late one's arrival is between 0 and `L` (taken as
uniform); with `N` the number of line shares found in that delay (Poisson,
mean delay times `r`), the share is lost when `N >= D`. Without the rebuild it would be lost at
`N >= D - 1`, since only a template built at the next tip change could name
it: for pool zero at the planned worst case that is 23% of a bridge user's
shares lost instead of 9%. (The 9% needs the nodes finding the next shares to
rebuild; while most of pool zero's hashrate runs 1.2.34, it stays near 23%.)
A rebuild every 2 s does not waste miners' work: the stratum keeps the last
`MAX_RECENT_JOBS` (8) jobs valid, at least 16 s of them.

**What it costs, at the planned worst case (`L` = 20 s) and at a typical
obfs4 or webtunnel link (`L` = 6 s), with the uncle share at 80%.** Lost
shares earn nothing; contested shares that are named earn 80% of their work;
the rest earn in full. "Paid" is the work credited over the work found. A
direct-Tor miner, at `L` of 2 to 3 s, is paid 97 to 99% at 20 s or more.

| spacing, depth | contested at 20 s | lost at 20 s | paid at 20 s | paid at 6 s |
|---|---|---|---|---|
| 10 s, 3 (pool zero) | 87% | 9.4% | 75% | 91% |
| 20 s, 3 | 63% | 1.5% | 86% | 95% |
| 30 s, 2 | 49% | 2.6% | 88% | 96% |
| 40 s, 2 | 39% | 1.3% | 91% | 97% |
| 60 s, 1 | 28% | 4.2% | 91% | 98% |
| 90 s, 1 | 20% | 2.1% | 94% | 98% |
| 120 s, 1 | 15% | 1.2% | 96% | 99% |

So the record rule (section 1) is set on the loss: **spacing times depth of
at least 60 s, no depth 0, uncle share of at least 80%** keeps a bridge user's
lost shares under 5% in the planned worst case, for every registered pool.
What remains is the uncle discount on contested shares. A creator who expects
many miners behind Snowflake or meek can lower it with a longer spacing, or
with a higher uncle share; the uncle share is also what an includer gives up
by naming uncles, and pool zero's 80% is a balance between the two. Pool zero
stays usable through bridges, at the cost the first row shows, and its rules
cannot change; a miner on a slow bridge does better in a pool with a longer
spacing, and `poollist` shows every pool's spacing and depth.

The model is approximate (a steady share rate, a uniform delay), and Phase D
checks it: the pass mark of step 7 is a lost fraction of at most 5%, and a
paid fraction within 3 points of what this model gives when it is fed, share
by share, the delay measured for that share and the rate of the other miners'
shares measured over the run.

The time rules need no change: a share may run 120 s ahead of a node's clock,
and a line counts as live for 180 share intervals. That clock is the later
of the node's own and the one its peers' version messages suggest. The peers'
clock alone does not do: over Tor those messages come in late, and only late,
so their median drifts behind (184 s measured on a Snowflake node in Phase D
while it caught up after its start, 39 to 62 s on direct nodes started beside
it), which put every fresh share past the 120 s and had it refused. The own
clock alone does not do either, on a node whose clock is slow and has no NTP;
the later of the two serves both, and peers still move it at most 70 minutes
ahead, as before. Keep the system clock right (NTP); a share's time is each
node's own policy, so no other node judges anything differently for it.

**Histories over slow links.** A line of 3 to 9 MB takes minutes over meek,
and a guardian behind Snowflake serves at whatever its circuit carries. Pool zero keeps its rules
as they are (section 8: `p2pshares` parts of 400 shares and up to 2 MB, the
whole history queued at once, taken within 5 minutes of asking,
`SYNC_ANSWER_WINDOW`). Registered pools have their own messages and are
served differently:

- **Small parts, the end flagged.** A `p2xshares` part holds at most 100
  shares, and at most 256 x 1024 bytes of shares (`MAX_SHARE_BYTES`, the
  same constant for sender and receiver) unless it is a single share, which
  may itself be that large. Every part carries the snapshot's tip height
  (below), not the live tip, and an end flag with three values: *more*,
  *end of history* (the snapshot is sent in full) and *ended early* (the
  serve stopped before that). A part that breaks these bounds is refused and
  its sender scored.
- **A snapshot, served paced.** When a serve starts, the server takes the
  list of share ids it would send (its `History()` from the resume point,
  oldest first, each uncle before the first share that names it) and serves
  that list, whatever its line does meanwhile; a share of the list pruned
  before it is sent ends the serve, flagged *ended early*, and the receiver
  resumes. It queues the next part only when the previous one has left the
  send queue and the guard rate allows it. The guard rate
  (`-poolguardkbps`, section 11) paces every registered history serve, of
  guarded, mined and carried pools alike; a local pool's serves (section 18)
  keep the default 64 KB/s whatever it says. A share held on its work alone
  (the deep end of a line read back from its file after a restart) is served
  like any other: the asker takes it on its work alone too.
- **Fixed slots, no stall.** Every node runs at most **8** registered serves
  at once, whatever its rate or transport, each getting an equal part of the
  rate (at least 8 KB/s at the default 64 KB/s, whatever the circuit allows below that); a further ask waits
  for a free slot (`DeferSync`). Unproven inbound connections hold at most 4
  of the 8, so they never block peers this node dialled or proven ones. A
  serve whose last queued part has not left the send queue within 5 minutes
  ends, which frees its slot; that is the receiver's own 5-minute limit, so
  an honest reader loses nothing it would have kept. A serve also ends when
  its last part is queued, 60 minutes after the ask by the server's clock, or
  when the same connection asks again for the same pool (the new ask replaces
  it and counts as an ask). A paced serve holds at most one part of the send
  queue, so the slow-reader rule (`DropSlowestHistoryReader`) has no queued
  history to drop it for; its job is done by the stall limit and by one more
  rule: when an ask waits for a slot, the slowest serve older than 15 minutes
  that averages under 1 KB/s ends, flagged *ended early* (its reader resumes
  later from where it stopped). So slow readers cannot keep the slots
  forever.
- **A receiving window with a ceiling.** The first part is taken up to 60
  minutes after asking, since it may wait for a free slot. After it, each part
  restarts a 5-minute wait for the next, and a part flagged *end of
  history* or *ended early* ends the window. Whatever arrives, the window closes 60 minutes after the ask; a
  fetch still moving then goes on with a new ask, from where it stopped
  (below). The shares taken for one ask stay under one history's worth
  (`3 x HISTORY_SHARES + 2 x 100`, with the pool's `HISTORY_SHARES`). The
  fetch itself does not sit out that hour on one peer: if no part has come
  3 minutes after the ask and another peer announces the pool, that one is
  asked (the first answer is still taken if it comes within its window),
  always within the 3 asks a pool and 8 in all a peer answers per interval
  (section 8).

So the slowest link a fetch survives moves a part every 5 minutes, about
1 KB/s, and a server at the default rate gives every serve at least 8 KB/s
of it, when its circuit carries that. A
stalled fetch ends 5 minutes after its last part, and no peer can keep a
window or a slot open longer than an hour, or push more than one history
into a window. A 9 MB line takes about 19 minutes at 8 KB/s; over a circuit
that carries only 2 KB/s it takes about 75 minutes and spans two asks, and
the resume point makes the second one cost only the rest.
A sliding window for pool zero would be local to the receiver and change
nothing a server sees; whether pool zero needs it is measured over meek in
Phase D before any change.

### Bandwidth

**What the node knows about its transport.** `BtfTorTransportMode()`
(`tor.cpp`) gives the rung for the bundled ladder, but only "user" for the
operator's own lines (`settorbridges`, `-torbridge`, `bridges.txt`), and
"direct" with an external Tor. So the node also classifies the bridge lines it
gave Tor, by their first word (`BtfBridgeTransport` over `g_torBridges`, read
under `cs_managedTor`, which `BtfSetTorBridges` then takes to write it too): `snowflake`, `obfs4`, `webtunnel`, `meek_lite`
reported as `meek`, and any other kind passed through as written.
`gettorinfo` gains a field **`transports`**: the sorted list of the kinds in
the lines Tor has now, empty when Tor runs without bridges; with an external
Tor the node cannot tell, and says so: `transports` is `null` and a
`transportsnote` explains why. The field is for the operator and for
Phase D, and is redone each time Tor is restarted on new lines (the ladder
climbs, the operator calls `settorbridges`). **Nothing in the pool protocol
depends on it**: every choice below is the same on every transport.

**Guarding through bridges is on, and looks the same.** Tickets are public,
the draw is deterministic, `poolinv` is seen by peers, and a peer can compare
how fast a node serves pool zero's history (queued whole, at the circuit's
speed) with how fast it serves a registered one. So anything a node on a
censored network did differently would point it out: stopping its ticket,
holding fewer pools than its ticket and the draw say it should, capping its
serving rate below what its circuit carries, or pulling fewer pools at once.
A node behind any bridge therefore does all of it exactly like any other: the
same ticket, the same byte and pool budgets (section 11), the same 8 serve
slots, the same default serving rate (64 KB/s, `-poolguardkbps`), and the
same handoff pulls (at most 2 pools at a time). A slow bridge needs no rule
of its own: paced serving queues the next part only when the previous one has
left the send queue, so the circuit itself sets the pace, which is what any
slow circuit looks like. A lower `-poolguardkbps` or `-poolguardmb`, or
`-poolguard=0`, stays an explicit operator choice, as on any node (an
operator on a metered link makes it; the budget shows in the ticket, or the
ticket is absent, as for anyone who chose so).

A pull goes to the announcing peer that serves fastest, and moves to another
(with its resume point) when a serve averages under 1 KB/s over 5 minutes; a
guarded line of up to 64 MB takes from about 20 minutes to a few hours, and
the old guardians, the reserve and the miners hold it meanwhile (section 10,
linger).

**No "low-bandwidth" flag on the wire.** A flag in tickets or in `poolinv`
would tell every node which nodes sit on censored networks. So a node never
says so: the ticket's capacity field carries only an explicit `-poolguardmb`,
or the same default for everybody, and a slow bridge changes only how fast
bytes move, which is what any slow circuit looks like.

**Bounded handoff.** A guarded line is at most 64 MB (section 11). Ticket
traffic is about 0.5 MB a day for each peer the node relays tickets to, plus
up to 1.9 MB per epoch when it asks peers for a set, 5.8 MB at start
(section 10).

**Resumable fetches.** A history arrives oldest first, in parts, and each part
is taken as it arrives (`AddHistory` per part).

- **Complete or not.** `AddHistory` checks in full every share above the
  stated tip height minus the retarget window, so a chain in progress has a
  tip long before the history ends. A registered pool's chain therefore has
  an explicit state. A part is *taken in full* when `AddHistory` took every
  share of it (today it returns true when it stops early on an innocent
  refusal, `p2pool_chain.cpp`; it is extended to report that). After a part
  flagged *end of history* is taken in full, the node asks the same peer once
  more, at once, with its new tip as the resume point (one of the 3 asks), to
  catch up with the shares found while the snapshot was sent, which on a live
  pool can be an hour of them. The chain is **complete** when that catch-up's
  *end of history* part is taken in full, or 5 minutes after the catch-up
  ask with no answer. *Ended early* never completes a chain. Until it is
  complete the node builds no template on it,
  does not announce it in `poolinv`, does not serve or relay it, and writes
  it only to the partial file below, never to `pools/<poolid>.dat`.
- **Kept across a restart.** The partial file, `pools/<poolid>.part`, holds
  the snapshot's tip height and the shares taken so far, oldest first;
  for each part, the shares `AddHistory` took from it (not those already
  held: a peer resending held ids with padded bodies adds nothing) are
  written, from the chain's own copies, where the last whole part ends, and
  flushed before the next is asked for, so a restart loses at most the part
  in transit. A part cut short in the file (a stop while writing, a failed
  write) is cut off when the file is read back, so the next part follows the
  last whole one. At start the file is read back
  through `AddHistory` with that height (clamped as a received part is), its
  shares checked through the registered RandomX budget like received ones,
  and the fetch resumes. It never grows past the pool's byte cap (past it
  the fetch goes on in memory only), and is read back no further than that.
  It is deleted once the chain is complete and written to
  `pools/<poolid>.dat` (a `.dat` that could not be written keeps it), after
  24 hours without a new share, or when the pool is no longer mined,
  carried or guarded. "No longer" is the index's word only once the index is
  ready: loaded, at the active chain's tip and not reading the chain again
  (it loads after the node starts); until then a pool it does not name
  keeps its partial file, carried by nobody meanwhile. This is not the
  "never kept in part" of section 12,
  which is about a guardian keeping part of a line to serve.
- **The resume point.** When a fetch breaks (a dropped circuit, a window
  closed, a restart), the node asks again with `p2xsync` naming its resume
  point: the newest share it holds of that history. A server that holds that
  share starts its snapshot where the share's branch meets the server's line
  (the share itself when it is on the line or names it as an uncle), less the
  pool's uncle depth, so a fork or an uncle below the resume point still
  comes; it builds only that part, never the whole history first. A server
  that does not hold it sends the whole line. Shares the receiver already
  has cost it nothing but the bytes (`AddHistory` skips them).
- **Request limits stay.** As section 8: an ask is a `p2xsync`; per
  (connection, carried pool) one serve in flight (a new ask replaces it), at
  most 3 asks per `SYNC_SERVE_INTERVAL` (a fourth dropped silently), and at
  most one history's worth of shares sent per interval, a resumed serve
  continuing the count of the serve it resumes; on an unproven inbound
  connection, one history's worth for its life. A whole-line answer to a
  resume point the server does not hold counts in full. Asks about pools not
  carried or not complete share one counter per connection. So resuming
  saves a peer the part already sent, and never lets anyone ask more often,
  or take more, than today.
- `poolgettkt` answers are resumable for free: asking again re-sends the set,
  and tickets already held are dropped before any hash.

**Metered links.** A node that only mines a pool pays for one history, then
each share of the pool in and out once for each peer that carries the pool
(the share relay sends it whole to each), plus the share relay of pool zero
as today. `-poolguard=0` and no `-poolcarry` keep it there.

### No new fingerprint

- An observer on the user's network sees the bridge transport and nothing
  else; Everpool adds no connection of its own. Inside Tor every message is
  carried in fixed 514-byte cells, so what shows is volume and timing.
- The messages and the behaviour are the same on every transport: every node
  makes its ticket, holds, announces, serves and pulls pools the same way,
  with the same defaults. A slow bridge shows only as a slow circuit.
- **Timing.** A node relays every share of every pool it carries, so a burst
  every share interval is the pattern of every carrier, not of a miner. That
  does not hide a miner's own shares from the peers it sends them to: a share
  that a node sends before it received it from anyone came from that node or
  from a miner behind it. What protects the miner is Tor, as for pool zero
  today: its peers see an onion, never an address. No padding beyond Tor's
  cells is added: it would cost bridge users the bandwidth they have least
  of, and would not change what a peer learns.
- **Bulk.** A history fetch looks like pool zero's line sync and like block
  download, which every node does.
- **Never the clear net.** The pool protocol has no path outside Tor: no DNS,
  no HTTP, no direct connection of any kind. (`-notorfallback` is a different
  thing: it stops the node from climbing to the bundled bridges; with or
  without it, nothing ever leaves Tor, `docs/censored-networks.md`.)
  Guardians are found from the peer cache and descriptors first, and a Nostr
  lookup, when needed, goes through Tor as it does today. The stratum stays
  on 127.0.0.1 and the private addresses of `-p2poolbind`, as today.

### Testing

Section 15: the Phase B self-tests for the spacing rules, the job rebuild,
resumable fetches, paced serving, the receiving window, the complete state
and `transports`; and Phase D step 7,
where a Snowflake node and an obfs4 node on testnet mine a registered pool
against the pass mark above, guard it, and fetch a dormant window and a live
line across a restart, with the measured delays written back here.

The delays are read from `sharetime.log`, which a node started with
`-sharetimelog` writes in its data directory: one line per registered share
event, `<unix ms> <event> <pool id, 16 hex> <share id> <share height> <peer>`,
for a share found on this node (`found`), received from a peer (`recv`),
sent to one (`send`) and asked for (`getsh`, `probe`). `debug.log` carries no
time and collapses share lines within 3 s of each other, so it cannot serve.
The `poolprobe <pool id>` RPC asks every connected peer that announced the
pool for this node's tip share; the `probe` line and the answer's `recv`
line give the round trip. The answer is a share already held: taken for
nothing, nobody scored. Both are off unless asked for, and change nothing in
the protocol.

## 18. P2Pool local: a private pool

Everpool is public on purpose: anyone can find a pool, join it and keep it
alive. Some groups want the opposite: the machines of one home, one office or
a few friends, mining together and paying each other fairly, with nothing
published anywhere. (Each payee runs a node of its own: the stratum pays
every share found through one node to that node's `-p2poolpayto`, so several
machines behind one node pay one person.) That is **P2Pool local**. At creation the user picks one
of the two:

| | Everpool | P2Pool local |
|---|---|---|
| where the pool is defined | an `OP_RETURN` record on the chain, 1 BTF burned | a pool code the members share among themselves; nothing on the chain, nothing burned |
| who can find it | everyone (`poollist`) | only who is given the code (and the password, if it has one) |
| who carries its share chain | its miners, guardians drawn at random, anyone with `-poolcarry` | only its members' nodes |
| who it talks to | every `NODE_POOLREG` peer that carries it | only the peers its members listed |
| when its nodes all go away | it lives on in guardians, and the record restarts it | it is gone, by design |

Pool zero, the default P2Pool, stays as it is for whoever picks neither.

### What a local pool is

A local pool has the same parameters as an Everpool pool and obeys the same
share rules v1 (section 5), and its shares have the `ShareX`/`ShareDataX`
structure of section 6 plus a salt, with the anchor rule below in place of
section 6's `"p2x"` rule: it is the same code with a different identity and
a different reach. A share whose `ShareDataX.poolId` is not the session's pool is
invalid, and its sender scored, as in section 8. Its parameters are a record
in the format of section 1, with three differences:

- the magic is `"BTFL"` instead of `"BTFP"`, so a local record can never be
  read as a registry entry (and nothing on the chain is read as a local
  record);
- it is never put on the chain: there is no burn and no confirmation, and
  the registry index never sees it;
- the name is a label for the members, and is part of the identity below
  (two groups with the same parameters and no password still get two pools).

Every other rule of section 1 applies unchanged, the canonical encoding
included (spacing 20 to 120, spacing times depth at least 60, uncle share 80
to 100, the fee rules), so the share rules code has one path, and a local
group whose members sit behind bridges gets the same latency margins as any
pool (section 17).

### Identity: the pool code and the password

- **The pool code** is what members share: the text `btfl1:` followed by the
  hex of the local record and the first 4 bytes of its SHA256d as a checksum.
  It holds the parameters and the name, never the password.
- **The password** is optional. It is stretched with Argon2id (libsodium
  `crypto_pwhash`, `ALG_ARGON2ID13`, 3 passes, 64 MiB), salted with the first
  16 bytes of `SHA256d("Bitflash/localpool/1/salt" || network magic ||
  record)`, into a 32-byte key `K`. With no password the same function runs
  on the empty string, so there is one path.
- **The local pool id** is `SHA256d("Bitflash/localpool/1/id" || network
  magic || record || K)`. It names the pool inside its shares
  (`ShareDataX.poolId`) and in the node's own files
  (`pools/local/<id>.conf`, `.dat` and `.part`), and is never sent to anyone
  who is not already a member. With the code, the id is a password oracle
  (one Argon2id run per guess), so it is kept out of places others may read:
  the operator names a local pool by its name (`-p2pool=local:<name>`,
  `poolinfo local:<name>`), and logs and `ps` show the name, never the id.
- **The pool keys** are `A = HMAC-SHA256(K, "Bitflash/localpool/1/auth" ||
  id)`, which authenticates members to each other (below), and `C =
  HMAC-SHA256(K, "Bitflash/localpool/1/anchor" || id)`, which keys the
  coinbase anchor.

A node stores the record, `K` and the listed peers in `pools/local/<id>.conf`,
never the password. Whoever reads that file can join the pool, as whoever
has the code and the password can: membership is the only thing it protects.

**What a password buys.** Without one, the pool is private only as long as
its code is: anyone who has the code, or guesses it (a default record with a
common name is easy to guess), computes the same id and key. With one, the
code can be shared openly and the pool is still closed. Precisely: someone
who holds the code but not the password can test a password guess offline
only against a hello sent to it, which a member sends only to a peer it
listed. Everything on the chain, and everything sent to anyone else, gives
it nothing to test against: the id and the shares go only to members in
session; the coinbase anchor (below) hashes a 256-bit random salt that never
goes on the chain, so checking a guess against it means guessing the salt as
well; and a hello is bound to the onion it was sent to, so only the listed
peer that receives it can check it, at one Argon2id run per guess. The salt
does this for the anchor, not the key `C`: whoever holds the code derives
`C` from each guess as easily as the id. Members can test guesses (they hold
shares, which carry the id and the salt), but they already hold `K`. The
operator's own copies of the id and password are kept out of argv and logs
(above, and *Using it*).

### The coinbase anchor

A local pool's share data is section 6's `ShareDataX` with one more field,
a **salt**, right after `poolId`:

```
ShareDataL {
    uint256 poolId;               // as ShareDataX
    uint256 salt;                 // 32 random bytes, fresh for every template
    uint256 hashPrevShare;        // and the rest as ShareDataX
    vector<uint256> vUncles;
    unsigned int nShareHeight;
    unsigned int nShareBits;
    vector<unsigned char> payoutScript;
}
```

serialized in that order, so a local share (`ShareL`) is a `ShareX` with 32
more bytes after the pool id. The node that builds a template draws the salt
from its strong random source; the share carries it to the members, in
`p2lshare` and `p2lshares` and in each member's `pools/local/<id>.dat`, and
nothing puts it on the chain. Pool zero's share bytes do not change, and a
registered pool's share has no salt.

The coinbase carries a **35-byte push**: `"p2l"` and `HMAC-SHA256(C,
SerializeHash(ShareDataL))` (the share data, `poolId` and `salt` included).
Members check it with `C`.

Why the salt. Everything else in the share data is often public or
guessable: `poolId` follows from the code and a guessed password,
`hashPrevShare` is 0 or the hash of a block on the chain, `vUncles` is often
empty, the height is small, `nShareBits` is the record's floor for the first
retarget window, and `payoutScript` is one of the coinbase outputs. The first
share of a chain, mined into a block, is all of that: `(id, 0, [], 0, floor,
the one output)`. Keying the hash with `C` adds nothing against someone who
holds the code, since `C` follows from the guess as the id does. Without the
salt, such a block would let them run a dictionary offline, one Argon2id run
per guess. With it, a guess can only be checked by also guessing 256 random
bits, so the block tells them nothing about the password (section *What a
password buys*). A restart from the same code and password, or a block whose
parent share was also a block, gets a fresh salt like any other.

It carries no pool id, so:

- each block of the pool shows a different hash, and nothing in the anchors
  ties one block of the pool to another;
- the members are linked by the coinbase outputs, which pay the PPLNS window,
  exactly as any P2Pool coinbase links the miners it pays (pool zero's
  included), and by nothing more;
- the tag says that the block came from some local pool, not which: that is
  as much as the `"p2p"` tag says about pool zero, and far less than a
  `"p2x"` anchor, which names its pool.

The share rules of section 6 extend to it, so that one PoW counts on at most
one share chain:

- a local share is valid only if it carries a salt, its coinbase parses
  fully and carries exactly one `"p2l"` push, whose 32 bytes are
  `HMAC-SHA256(C, SerializeHash(ShareDataL))` with `poolId` equal to this
  local pool's id, and no `"p2p"` push and no `"p2x"` push (the salt's value
  is not checked: it protects the members' own password);
- a registered pool's share (format 1) also refuses any `"p2l"` push (added
  to section 6's list);
- pool zero's frozen rule counts only `"p2p"` pushes, so a pool zero coinbase
  may carry a `"p2l"` push; the exclusion sits on the local side, as it does
  for `"p2x"`. Two local pools cannot share a PoW either, since the hash
  commits to one pool id.

The scriptSig is at most 59 bytes (the anchor is 32 bytes shorter than
`"p2x"`). The anchor counts of section 3 ignore `"p2l"` pushes: there is no
pool to count them for.

### Members find each other, and nobody else finds them

There is no discovery. A local pool is never announced in `poolinv`, never
named in `poolwho`, never given a ticket or drawn for guardians, never
relayed to a peer that did not prove membership, and never listed by
`poollist` on any node but its members' own. Members exchange, out of band:
the pool code, the password if any, and the onion addresses of the member
nodes that accept connections.

- **Listed peers.** Each member lists other members' nodes (`poolpeers`,
  below; at most 16 per local pool), in the form `/connectbtf` takes
  (`ADDR@HOST.onion`). The node keeps an ordinary outbound Bitflash
  connection to each listed peer that answers, through Tor, like any other
  peer: it relays blocks and transactions as usual, and nothing on the wire
  says it was dialled for a pool. These connections come on top of the
  node's ordinary outbound peers, within `MAX_CONNECTIONS`, never in their
  place, so the members of a pool can neither eclipse a node nor become its
  whole relay set.
- **The hello.** On a connection to or from a peer (inbound onion
  connections are anonymous, so the listing alone proves nothing), a member
  proves membership with three messages, after the version handshake. Every
  tag is bound to `O`, the onion the initiator dialled, written one way only:
  the 56 lowercase characters of the v3 name, without `.onion` or the
  `ADDR@` part. Tor guarantees that
  only the holder of that onion's key receives the connection, so a tag
  made for one node is worth nothing at another. A node that does not know
  its own onion (an external Tor whose onion service it was not told about)
  can send hellos but not answer them.
  1. `p2lhello`: a random 32-byte nonce `nA` and `tA = HMAC(A, "hello" || O
     || nA)`, first 16 bytes. Sent only to listed peers.
  2. The receiver tries `tA` with `O` set to its own onion (each of them, if
     it has several), against each local pool it is a member of (at most 4).
     On a match it answers `p2lhello` with its own nonce `nB` and `tB =
     HMAC(A, "reply" || O || nA || nB)`; on no match it answers nothing,
     which is what a node without local pools, or a 1.2.34 node that does
     not know the command, also does.
  3. The initiator checks `tB` and sends `p2lack` with `HMAC(A, "ack" || O ||
     nA || nB)`. Only then does either side send anything about the pool.

  So a non-member that a member listed by mistake (it receives that member's
  hellos) can neither replay one to another node (the tag names its own
  onion), nor relay a handshake between two members (the receiver checks the
  tag against its own onion, and the reply and ack are bound the same way),
  nor learn who the other members are. The session is named on that
  connection by `h = HMAC(A, "session" || O || nA || nB)`, first 8 bytes,
  and every later message of the pool carries `h`, never the pool id. A
  receiver checks at most one `p2lhello` per connection per minute and 8 in
  the life of a connection, and keeps the last 256 `nA` of each pool to drop
  a repeated one; a reply not acked within 30 s is forgotten and holds no
  session. A member's hello on a connection that already holds a session
  of that pool is answered, and its ack replaces that session: the other
  side has lost it (its operator took this node off the list and put it
  back). At most 16 sessions per local pool, inbound and outbound
  together; a hello beyond that gets the same silence as no match. Hellos
  over these limits are dropped unread, and nobody is scored for a hello that
  matches nothing (a non-member listing this node by mistake is not an
  attack).
- **The messages.** After the ack, the pool runs over `p2lshare`, `p2lgetsh`,
  `p2lsync` and `p2lshares`, which are `p2xshare`, `p2xgetsh`, `p2xsync` and
  `p2xshares` (sections 8 and 17) with `h` in place of the pool id: the same
  share relay, paced serves (at 64 KB/s, whatever `-poolguardkbps` says),
  resume points, receiving window, complete state and partial file. A message with an unknown `h` is dropped unread,
  unscored.
- **The LAN.** Machines on the same network do not need a node each: they
  mine through one member node's stratum with `-p2poolbind` (#81), whose
  limits stay as they are: 48 miners on the local network, 8 per address,
  login within 30 s, private addresses only. A second node on the LAN, for
  redundancy, is a member like any other and talks to the first through Tor,
  as every node does; nothing of a local pool ever leaves Tor or the
  private-address stratum.

### Limits

A local pool spends from the registered class of section 8, never from pool
zero's: its shares are checked through the registered RandomX budget (a
member in session is proven, and its shares still draw on budgets of their
own: one per session, twice the pool's share rate with a small burst, and
one per local pool for all its sessions together, one share every 8 s with
a burst of 16, so the members of one pool cannot spend another's; a share
over them is held, not hashed and not scored). Within a
pool the sessions take turns for the pool's budget: the session that wasted
fewer of its tokens lately goes first, then the one that had a token longer
ago, and a share that comes in live waits behind one held for a session
ahead of it. A token is wasted when the share it paid for is a side share:
it did not become this node's tip (judged after the orphans it lets in are
connected), it did not build on this node's tip when it came, and this node
did not ask for it in the last 10 minutes. A share whose line becomes the
tip pays one back; a share that built on the tip when it came (it lost a
race, or waited in this node's queue while the tip moved on) and a parent
or uncle this node asked for change nothing. A new session, a member's
reconnect among them, starts with as many wasted tokens as the session of
its pool that has the most, and its last token now: at the back. So a member
flooding side shares from many sessions falls behind every member whose
shares extend the pool's line; sessions it keeps idle get one turn each
ahead of such a member, no more, and the member loses no place for having
waited behind them. Its
orphans wait in the registered queue, its serves take the 8 registered slots
and the per-(connection, pool) limits of sections 8 and 17, with the session
in place of the pool. On top of that: at most 4 local pools per node, at most
16 listed peers and 16 sessions each (above), and the byte caps pool zero has
(`MAX_CHAIN_SHARES`, `MAX_CHAIN_BYTES`, `MAX_TRUSTED_BYTES`) for each.
A peer that sends an invalid share in a session is scored, as for any pool.

Sessions that are not proven yet (inbound ones whose peer has not sent a
share this node took) have no budgets of their own: they share the
registered class's pieces with the unproven peers of every local pool on
the node, and of every pool of that class later: the RandomX budget for
unproven peers (32 hashes, one more every 2 s), the orphan queue of 256
shares, and the 64 held slots (one share and one history ask per
connection). A member flooding from unproven sessions so delays the other
pools' unproven sessions too, never pool zero and never a proven session.
Only members hold such sessions (a message needs a session's handle), at
most 16 a pool, so the 64 held slots are always enough for one each. What
it costs an honest member: the first share of a member that has just
reconnected inbound (and is not proven again until a share of it is taken)
may wait behind the held shares of a flooding member's other sessions, at
most 15, served one every 2 s once the budget's burst is spent: up to about
32 s. An orphan of it may also lose its place in the queue of 256 to the
flooder's orphans (each of which cost the flooder a hash on the same
budget). Once one of its shares is taken, it is proven, and its own budgets
apply.

### When the members go away

The share chain lives in `pools/local/<id>.dat` (and a fetch in progress in
`pools/local/<id>.part`) on each member node. When every
member stops, the pool stops; when one comes back with its file, the pool
goes on from there, and when none has the file any more, starting again from
the same code and password gives the same id and a fresh chain. Nothing is
left anywhere else to clean up. The file starts with a format byte (1 in
this release); a node reads its own format only, and starts a pool whose
file has another one from its peers, saying so in its log. That file is set
aside first, as `pools/local/<id>.dat.other`, so nothing saved later writes
over it; it goes with the pool's other files when the pool is left.

### Using it

| call | does |
|---|---|
| `poolcreate everpool {params} ["send"]` | an Everpool pool: the record of section 1, burned on the chain with `"send"` (or `"publishzero"` for pool zero's own record), shown without it (section 9) |
| `poolcreate local {params} [password]` | a local pool: checks the record as section 1 does, with the defaults of section 9, derives the id, saves `pools/local/<id>.conf`, and returns the name, the pool code and the note below. A name already used by a local pool on this node is refused. Nothing is sent anywhere |
| `pooljoin "<pool code>" [password]` | joins a local pool from its code: checks the checksum and the record, derives the id, saves the file, returns the name and the note. A name already used by a local pool on this node is refused (after joining with a mistyped password, `poolleave` and join again) |
| `poolpeers local:<name> ["ADDR@HOST.onion", ...]` | sets the listed peers of a local pool (at most 16); with no list, shows each and its state: connected with a session, this node at its session cap, or no proof (not a member, a wrong password, or the peer at its own cap, which answers with silence) |
| `poolleave local:<name>` | forgets a local pool: closes its sessions and deletes its files. Refused while this node mines it: restart the node without `-p2pool=local:<name>` first |
| `poollist`, `poolinfo` | show this node's local pools too, marked `"local": true`, with their sessions; never any other node's |

`poolcreate` with no mode is refused with a message that names the two, so
nobody burns 1 BTF by default. Mining a local pool is `-p2pool=local:<name>`
(section 9 otherwise unchanged). The password is typed in the GUI's dialog,
or read by the RPC client from a prompt or from stdin, never passed as a
command-line argument, where other users of the machine, and the shell
history, would keep it.

The result of `poolcreate local` and `pooljoin`, the GUI, and the release
notes carry the same informative note, without alarm:

> A local pool finds blocks in proportion to your machines' hashrate: rarer
> but larger payouts; the average is the same as any pool.

### Tests and proof

- Self-tests (Phase B): the local record round-trip and every section 1 rule
  under `"BTFL"`; a `"BTFL"` record in an `OP_RETURN` not indexed; the code's
  checksum; fixed vectors for `K`, the id, `A` and `C` with and without a
  password; `-p2pool=local:<name>` with an unknown name refusing to start;
  the anchor rules (`"p2l"` with the wrong hash, an unkeyed hash, two of
  them, alongside a `"p2p"` or a `"p2x"`; a format 1 share refusing
  `"p2l"`; a local share with another salt or none refused); a block's
  anchor that cannot be checked from the code, the right password and the
  whole block without the salt, for the first share of a chain, and can be
  with the salt a member holds; the salt in no byte of the block, and fresh
  in each template; the hello (a match, no match answered by silence, a hello
  replayed to a third node and a handshake relayed between two members both
  failing, a repeated `nA` dropped, an unacked reply expiring, the session
  cap answered by silence, the rate limit, an unknown `h` dropped); the id
  never in logs or `ps`; a local pool never in
  `poolinv`, tickets or another node's `poollist`; the limits above.
- Testnet proof with real coins (Phase D, step 8): two nodes on different
  machines join one local pool with a password and list each other; a third
  node lists one of them with the wrong password and gets nothing; both mine
  until a block is found, its coinbase pays both to the satoshi, the coins
  mature and are spent; the block's anchor is a `"p2l"` push and nothing on
  the chain or in any other node's `poollist` names the pool; the code, the
  right password and the block do not check the anchor, and the salt from a
  member's share file does; one node goes
  away and comes back from its file; then both go away, and the pool is
  gone. One of the two runs behind Snowflake for the whole step.
