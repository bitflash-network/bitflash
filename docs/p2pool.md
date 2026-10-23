# P2Pool inside the node: pooled mining with no pool

Status: design, not implemented. Mainnet consensus does not change; this ships
in an ordinary release.

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
parent; the parent is known; the timestamp is sane; the main-chain fields
point at a block the node has, at most a few blocks behind its tip.

**Share target:** retargets every share over the last 720 shares to keep 10
seconds per share, never below a floor (spam) nor above the main difficulty.

**Chain choice:** most cumulative share work, uncles included.

**Uncles:** a share found at the same time as another is not wasted. The next
share may reference it as an uncle (up to 3 shares back); the uncle is paid
80% of its work, the 20% going to the share that included it, so including
uncles pays.

## Payouts (PPLNS)

The coinbase of every template pays the last **2160 shares** (about 6 hours at
10 s), each in proportion to its difficulty, grouped by payout key:

- one output per distinct payout key, sorted by key, so every node builds the
  identical transaction;
- an amount under 0.001 BTF is not paid this block; it stays in the window
  and is paid by a later block. No coin is lost, nothing is held by anyone;
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
  an invalid one (net-hardening).
- New nodes download the share window from peers at start, then verify each
  share before using it.

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

- **Spam shares:** each costs RandomX work at the share target; invalid ones
  get the sender scored and banned.
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
