# P2Pool inside the node: pooled mining with no pool

Status: implemented (steps 1 to 6 below); being proven on testnet (step 7).
Mainnet consensus does not change; this ships in an ordinary release.

## Why

Today almost every Bitflash miner mines through one pool. Its operator receives
every coinbase and pays the miners afterwards with ordinary transactions. That
operator can:

- keep the coins (custody),
- see which onion submits how much work,
- pick the transactions in every block (censorship),
- disappear, and take the network's hashrate with it.

All of that sits on one machine. Pooled mining is still needed: alone, a small
miner waits weeks between blocks. What has to go is the pool.

## The idea in one paragraph

Every node that mines keeps a second, faster chain: the **share chain**. A
share is a block template whose RandomX hash meets a much easier target, one
share every ~10 seconds across all miners. Every template pays, in its own
coinbase, everyone who found a share in the recent window, in proportion to the
work of each. All participating nodes compute that payout list from the same
share chain, so they agree on it byte for byte. When some miner's share also
meets the real difficulty, that template is a valid Bitflash block, and it
already pays everyone. Nobody holds anybody's coins, and there is nobody to
ask.

This is the design of P2Pool for Bitcoin (2011) and for Monero (2021, also
RandomX), adapted to Bitflash.

## Shares

A share carries:

- the main-chain block header fields it was mined on (previous block, time,
  bits, merkle root, nonce);
- the coinbase transaction and the merkle branch to it, so a node can rebuild
  the header and check the RandomX hash;
- the previous share's id and up to 2 uncle ids;
- the miner's payout key hash;
- the share chain height and the share difficulty.

The coinbase commits to the share chain: its scriptSig, after the block height
(rules v2 / BIP34), carries `"p2p"` and the 32-byte id of the share's parent
data. The PoW therefore cannot be lifted from one share chain onto another.

**Valid share:** the header hashes (RandomX, the main chain's own PoW v2) under
the share target; the coinbase outputs equal the payout list computed from the
parent; the parent and uncles are known (a missing one is fetched, never
held against the sender); the timestamp is sane; the coinbase states its
block height (rules v2), which sets the subsidy it must pay, and meets every
rule a block's coinbase meets; the payout script is a P2PKH or P2SH address,
nothing else (every payout script of the window becomes an output of every
coinbase, so a script of signature operations would push every P2Pool block
over the block's limit).

A share is judged on the share chain and itself alone, never on the main
blocks a node holds. Its `nBits` decides only whether its work is also a
block, which is the main chain's business. Checking `nBits` against the main
block it was mined on made two honest nodes, one holding that block and one
not, judge the same share differently and part ways; taking `nBits` on the
share's word let anybody name an easy one.

How far behind the main tip a share was mined does **not** decide its
validity: that would depend on when the share arrived, and two honest nodes
would disagree about the same share. On testnet that is exactly what split two
nodes, over an uncle fetched minutes after it was mined. Work on an old main
block is still work the window pays; mining on the tip is the miner's own
interest, and a node's templates are always on its tip.

**Share target:** a chain's first 720 shares are at the floor (the network's
easiest target); from then on it retargets every share over the last 720 to
keep 10 seconds per share, never easier than the floor. It is not held to the
block target: when blocks are the easier of the two, the miner is given the
block target, and work that meets it but not the share target is a block and
not a share.

**Chain choice:** most cumulative share work, uncles included, between lines
that meet in the shares a node holds. Two lines that do not meet (a node that
mined alone before it heard the network, or was cut off for long) began their
sums at different shares, so a long run alone would outweigh the network for
good; those are weighed on the work of their last 2160 shares instead. The tip
is always a share checked in full (see *Starting*).

**Uncles:** a share found at the same time as another is not wasted. The next
share may reference it as an uncle (up to 3 shares back); the uncle is paid
80% of its work, the 20% going to the share that included it, so including
uncles pays.

## Payouts (PPLNS)

The coinbase of every template pays the last **2160 shares** (about 6 hours at
10 s), each in proportion to its difficulty, grouped by payout key:

- one output per distinct payout script, sorted by script bytes, so every
  node builds the identical transaction;
- each output is `floor(value x work / total work)`, in 128-bit integers, no
  floating point; the satoshis rounding leaves (fewer than one per output) go
  to the script with the most work. The outputs add up to the block value
  exactly (`p2pool::ComputePayouts`, `test_p2pool`);
- no dust floor is needed: at 50 BTF a block and 2160 shares, one share is
  worth about 0.023 BTF;
- the block finder gets no bonus. There is nothing to race for;
- a treasury share (see `treasury.md`), when the operator of a node chose one,
  is that node's own choice and comes out of its own shares only.

**Size:** 1 MB blocks hold the coinbase easily. 1000 distinct miners in a
window is ~34 KB of outputs.

**Maturity:** coinbase outputs mature after 100 blocks, as every coinbase.

## Network

- Share messages travel on the existing Bitflash peer-to-peer connections,
  which are Tor-only. Two new messages: `p2pshare` (a share) and `p2pgetsh`
  (ask for shares by id, to fill gaps). Nodes that do not run P2Pool ignore
  them; older nodes ignore unknown commands, as since 0.1.0.
- A node relays a share only after verifying it, and scores a peer that sends
  an invalid one (net-hardening). A share refused on this node's own view (its
  clock, its main chain) or waiting on shares not here yet scores nobody.
- A share whose parent has not arrived waits in a queue of 256, after its
  RandomX work is checked once; the same share sent again costs nothing. A
  parent that has not come in 20 minutes is not coming, and a full queue drops
  its oldest share, so the queue cannot be filled for good.

## Starting

A node that starts, or hears a share far past its own tip whose parent it
lacks, asks a peer for its line (`p2psync`) and takes the answer for five
minutes only. The answer is the line behind the peer's tip, about 2900 shares
with their uncles:

- the newest 720 have a whole window and a whole retarget behind them, and are
  checked in full, exactly as a fresh share;
- the deeper ones cannot be: their own windows reach shares nobody sends. They
  are taken on their work, commitment and merkle branch alone, and an uncle
  adds to a line's work only where the uncle rules can be seen to hold. Such a
  share is never the tip;
- a peer's history wins only by having more work than the others; every peer
  is asked while the chain is short.

The node keeps its line in `p2pool.dat` and reads it back the same way.

**Memory:** a node keeps the shares a window, a retarget and the uncle rules
can reach (about 2900 behind the tip). Past 11,584 shares it drops the lightest
side lines; it never refuses a share for want of room, since that would make a
share's validity depend on what else a node holds.

## Mining

- The node serves stratum on **127.0.0.1** only. XMRig, and the Bitflash
  Miner, point at the miner's own node: `127.0.0.1:3333`.
- `-p2pool` turns it on; `-p2poolpayto=ADDRESS` chooses where payouts go (by
  default a fresh address of the node's own wallet, changed every 24 hours).
- No pool onion, no pool directory, no operator fee.

## Privacy

| | central pool (today) | P2Pool in the node |
|---|---|---|
| who sees your hashrate | the operator | nobody: a share says nothing about who sent it, and arrives over Tor |
| who holds your coins | the operator, until he pays | nobody: the block pays you |
| your payout address | in the operator's payment | in the coinbase, public, as with any payment. A fresh address every 24 h, by default, unlinks the days |
| who picks the transactions | the operator | every miner's own node |

## What changes for whom

- **Miners:** run a node (the wallet is one), add `-p2pool`, point XMRig at
  `127.0.0.1:3333`. Payouts arrive in their own wallet, matured after 100
  blocks.
- **The central pool:** keeps running until P2Pool is proven on mainnet with
  real blocks paid to several miners. Then it is switched off.
- **Everyone else:** nothing. Main-chain rules do not change.

## Attacks considered

- **Spam shares:** each costs RandomX work at the share target, which the
  retarget sets from the line it builds on; invalid ones get the sender scored
  and banned. A coinbase must meet every rule a block's coinbase meets, so a
  share cannot be padded.
- **History forgery:** the deep end of a history is trusted on its work alone,
  so a forged one must carry as much real work as the honest one it means to
  displace; it cannot count an uncle twice, cannot become the tip on its own,
  and is only taken right after this node asked for it.
- **Withholding** (finding a block and not publishing it): the withholder loses
  his own share of it; same as in any pool.
- **Payout list forgery:** a template whose coinbase does not match the list
  every node computes is not a valid share, and its block, if it is one, still
  pays only what it says, with no share credit.
- **Eclipse through Tor:** same defences as block relay (several peers,
  scoring, seeds).
- **Main-chain 51%:** unchanged by P2Pool. A pool that cannot be seized or
  shut down makes hashrate harder to gather in one place.

## Implementation plan

1. Share data structure, serialization, id, verification (with selftests and a
   fuzz target for the share parser).
2. Payout list (PPLNS window, grouping, sorting, dust carry-over) as a pure
   function, tested against hand-computed cases.
3. Share chain store, chain choice, uncles, share retarget.
4. Gossip messages over the peer-to-peer network.
5. Local stratum serving templates that commit to the share chain.
6. Bitflash Miner wired to `127.0.0.1:3333`.
7. Testnet: several nodes on several machines, real blocks, payouts checked to
   the satoshi against the share chain.
8. Mainnet: release; the central pool stays up in parallel until P2Pool has
   paid real blocks to several miners; then it is switched off.
