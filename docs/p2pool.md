# P2Pool inside the node: pooled mining with no pool

Status: implemented (steps 1 to 6 below) and proven on testnet (step 7): a
block found through it paid two miners, matured and was spent.
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
(rules v2 / BIP34), carries `"p2p"` and the 32-byte hash of the share's own
data (`ShareData`: its parent, uncles, share height, target and payout
script). The PoW therefore cannot be lifted from one share chain onto another.

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
good; those are weighed on the work of their last 2160 shares instead. Work
is summed share by share above the point where two lines meet. The tip is
always a share checked in full (see *Starting*), and a line whose newest share
is more than 30 minutes old by this node's clock does not replace a livelier
tip: a share's time has no lower bound, so the network's own line of some days
ago, when difficulty was higher, could otherwise be played back to a starting
node. This decides which line a node mines on, never whether a share is
valid.

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
- no treasury share: the coinbase must equal the payout list exactly, so a
  block found through P2Pool pays the miners and nothing else.

**Size:** 1 MB blocks hold the coinbase easily. 1000 distinct miners in a
window is ~34 KB of outputs.

**Maturity:** coinbase outputs can be spent after 100 blocks, as every
coinbase; the wallet counts them as balance after 120, as it does for any.

## Network

- Share messages travel on the existing Bitflash peer-to-peer connections,
  which are Tor-only: `p2pshare` (a share), `p2pgetsh` (ask for shares by id,
  to fill gaps), `p2psync`/`p2pshares` (a line, for a starting node) and
  `p2ppeers` (see below). Every node of a release with P2Pool holds and
  relays the share chain, mining or not, and says so with the service bit
  `NODE_P2POOL`; these messages go only to peers that say it. Older nodes
  would drop them unread.
- **Finding each other.** Until most of the network runs such a release, a
  miner's ordinary peers may all be older nodes, and it would hear no share.
  So a node mining with `-p2pool` keeps at least 3 peers that say
  `NODE_P2POOL`, dialling up to 3 past its usual 8 for them: first peers whose
  own version said so when it dialled them (remembered in its peer cache),
  then peers another P2Pool node named (`p2ppeers`, which carries only
  addresses the sender reached and saw say `NODE_P2POOL`, at most 32), then
  peers it knows nothing about. A name in `p2ppeers` is a hint, never passed
  on: a lie costs one dial. A peer counts toward the 3 only while it is new
  (10 minutes) or has passed on a share this node took in the last 10
  minutes: saying `NODE_P2POOL` costs nothing.
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
  are taken on their work, commitment, merkle branch and coinbase shape
  (addresses only) alone, and an uncle adds to a line's work only where the
  uncle rules can be seen to hold. Such a share is never the tip, never an
  uncle, never handed to a peer that asks for it by id, and never hangs on a
  share checked in full (one that did is dropped); a history arrives oldest
  first or is refused, and such shares are held to 64 MB in all;
- a peer's history wins only by having more work than the others; every peer
  is asked while the chain is short.

The node keeps its line in `p2pool.dat` and reads it back the same way.

**Memory:** a node keeps the shares a window, a retarget and the uncle rules
can reach (about 2900 behind the tip). Past 11,584 shares it drops the lightest
side lines; it never refuses a share for want of room, since that would make a
share's validity depend on what else a node holds.

## Mining

- The node serves stratum on **127.0.0.1**. XMRig, and the Bitflash Miner,
  point at the miner's own node: `127.0.0.1:3333`.
- No pool onion, no pool directory, no operator fee. The stratum is not part
  of the P2P network: miners reach it directly, never over Tor.

Options:

| option | what it does |
|---|---|
| `-p2pool` | turns P2Pool on |
| `-p2poolport=N` | the stratum port, 1025 to 65535 (default 3333) |
| `-p2poolpayto=ADDRESS` | where payouts go (default: a fresh address of the node's own wallet, changed every 24 hours) |
| `-p2poolbind=IP` | also serve the stratum on this private address, for miners on your local network (default: none, 127.0.0.1 only) |
| `-p2poolbridge` | bridge mode (below): the stratum on this node's onion at the P2P port + 1, every share paying the miner's own login |
| `-pooldrain` | pay out the pending rounds an operator pool left in this data directory, and start no new ones (below) |

### Mining from other machines on your local network

One node can take the hashrate of every machine in the house. On the node,
add `-p2poolbind` with the node machine's own address on the local network:

    bitflash-node -p2pool -p2poolbind=192.168.1.10

On each other machine, point the Bitflash Miner or XMRig at that address:

    Linux, macOS:   P2POOL_HOST=192.168.1.10 ./mine.sh p2pool
    Windows:        set P2POOL_HOST=192.168.1.10
                    mine.cmd p2pool
    XMRig by hand:  xmrig -a rx/0 -o 192.168.1.10:3333 -u p2pool -p x

The node keeps listening on 127.0.0.1 as well, so a miner on the node's own
machine needs no change. For an IPv6 address, put it in brackets for the
miner: `P2POOL_HOST=[fd00::10]`, `-o [fd00::10]:3333`.

What to know before turning it on:

- **The stratum has no login.** Anyone who can reach that address and port
  can mine to this node. What they mine pays this node's payout address
  (`-p2poolpayto`, or the node's own wallet): the name a miner logs in with
  is only a label in the log, and nothing a miner sends can change where the
  node is paid. (Bridge mode, below, is the one exception: there the login
  is the address paid.) A stranger on the network can add hashrate that pays you, or
  get in the way of your mining: take up the connection slots the local
  network gets (48 in all, 8 per address; 12 more are kept for 127.0.0.1, so
  the node's own machine always gets in) and make the node check bogus
  shares. A connection that does not log in within 30 s, or does not read
  what the node sends, is dropped.
- **Trust every private network this machine is on.** "Local network" means
  any network that reaches this machine from a private address: a VPN, a
  ZeroTier network, the IPv6 side of a Tailscale network, a Docker bridge, a
  guest Wi-Fi on the same router. On Linux a machine on any of them can reach the bound address
  through its own interface. Turn the option on only where you trust all of
  them.
- **Only private addresses are taken:** 10.0.0.0/8, 172.16.0.0/12,
  192.168.0.0/16, link-local 169.254.0.0/16, IPv6 unique local fc00::/7,
  link-local fe80::/10 (with its interface, as in `fe80::1%eth0`), and
  loopback. A public address, `0.0.0.0` and `::` make the node refuse to
  start: they would put an open stratum on the internet.
- **Every connection is checked too.** One that does not come from a private
  address is dropped, so a router forwarding a public port to the node does
  not open the stratum to the internet. A router that rewrites the source to
  its own private address defeats this check, so do not forward the stratum
  port.
- The connection is plain TCP on your network, not Tor. The miner sends work,
  never keys or coins, but anyone on the network can see that this machine
  mines.
- The stratum serves mining only: no wallet, no RPC, no P2P.

## Bridge mode: an operator pool's miners on pool zero

`-p2pool -p2poolbridge` turns an operator pool into a P2Pool node without
its miners changing anything. It is meant for one move, the central pool's
miners onto pool zero, until they run nodes of their own; it is not a way to
run a pool.

- **Same door.** The stratum listens where an operator pool listens: on the
  node's own onion at the P2P port + 1 (`-port=8435` means 8436). Run it in
  the operator pool's data directory and the onion, the port, the dialects
  (XMRig's `login`, the wallet's `mining.subscribe`), the job format and the
  algorithm are all the miners already use. `-p2poolport` and
  `-p2poolbind` do not apply and are refused with it; it mines pool zero
  only.
- **The login is the address paid.** Each miner gets a template of its own:
  the same transactions, parent share, uncles, share target and time as
  everyone's, with share data naming the P2PKH script of the address it
  logged in with, and the coinbase that share's window pays. A share that
  miner finds is a pool zero share paying that address, exactly as if the
  miner ran its own node with `-p2poolpayto`; every block pays the window,
  with no fee and no ledger.
- **What a login may be.** The address alone (what the Bitflash Miner and
  `xmrig -u ADDRESS` send), or with a rig name after a dot
  (`ADDRESS.rig1`, shown as the worker) or a `+` suffix
  (`ADDRESS+50000`), both cut off: neither character is part of an
  address. Surrounding spaces are ignored. Anything else, a `.btf` node
  address, `p2pool`, a typo or a pay-to-script-hash address, is refused,
  with the reason in the error XMRig prints. Paying such a login to the
  bridge instead would take the miner's work without a word; the operator
  pool refused a RandomX miner's bad login the same way.
- **What the miner sees.** Each connection keeps a difficulty of its own,
  retargeted to a share every 15 s as on the operator pool, so XMRig shows
  accepted shares and the dashboard a hashrate as before. The job's target
  is never harder than the share chain's, so every share reaches the
  bridge. Only work that meets the share chain's target becomes a share,
  and only shares are paid: the accepted shares on screen change nothing
  in what a miner earns.
- **What it does not change.** The bridge still sees each login's hashrate
  and picks the transactions, as the operator did; that ends when the
  miners run their own nodes. It never holds a coin. Every share and its
  payout script are on the share chain any node keeps, so whether a login's
  work was paid to it can be checked after the fact on any node's
  `p2pool.dat` (one block's coinbase against its window, to the satoshi).
- **Connections:** up to 1000, like the operator pool, all over Tor.

### The old ledger: `-pooldrain`

An operator pool owes its miners for every round it found until the round
matures (120 blocks). `-pooldrain`, with `-p2pool`, loads that ledger
(`pending_payouts.json`, `pool_rounds.json` in the data directory) and runs
the operator's payout thread on it: each round is paid from the node's
wallet once it matures, only if its block is still in the main chain, and
recorded and recovered after a restart exactly as before. P2Pool's blocks
pay their miners themselves, so no new round is ever added. The log says
how much is owed at start and when the ledger is empty; `pool_status.json`
keeps listing the pending rounds (`node.drainingLedger`), with
`node.pool` set to `p2pool-bridge` and a fee of 0.

## Privacy

| | central pool (today) | P2Pool in the node |
|---|---|---|
| who sees your hashrate | the operator | nobody: a share says nothing about who sent it, and arrives over Tor |
| who holds your coins | the operator, until he pays | nobody: the block pays you |
| your payout address | in the operator's payment | in the coinbase, public, as with any payment. A fresh address every 24 h, by default, unlinks the days |
| who picks the transactions | the operator | every miner's own node |

## What changes for whom

- **Miners:** run a node (the wallet is one), add `-p2pool`, point XMRig at
  `127.0.0.1:3333` (`-p2poolport` for another port, `-p2poolbind` for other
  machines on the local network). Payouts arrive in their own wallet,
  spendable 120 blocks later.
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
