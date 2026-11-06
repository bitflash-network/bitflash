# Atomic swaps: BTF for BTC, nobody in the middle

Two people who do not trust each other trade BTF for BTC without an exchange,
an escrow, a server or a custodian. Either both get paid, or both get their
coins back. Needs rules v3, which make pay-to-script-hash and
`OP_CHECKLOCKTIMEVERIFY` live: on testnet from 2026-10-20 01:00 UTC, on
mainnet from 2026-11-21 12:00 UTC. On mainnet, swaps open in the wallet and
in btfchat on **2026-12-25 12:00 UTC** (1.2.30 and later; see `consensus.h`).

There are three ways to do one, from easiest to most manual:

1. **In btfchat** -- post an offer in a community, someone takes it, the chat
   carries the swap through with both people's own wallets.
2. **With the Bitflash wallet's RPC, against a current Bitcoin Core** -- the
   wallet does both halves (`swap*` for Bitflash, `btc*` for Bitcoin).
3. **With Decred's `btcatomicswap`** on the Bitcoin side, for whoever already
   uses it. Same contract, so either side can use either tool.

## Why it works

Each side locks its coins in the same kind of contract:

```
OP_IF
    OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <secret hash> OP_EQUALVERIFY
    OP_DUP OP_HASH160 <recipient>
OP_ELSE
    <lock time> OP_CHECKLOCKTIMEVERIFY OP_DROP
    OP_DUP OP_HASH160 <refund address>
OP_ENDIF
OP_EQUALVERIFY OP_CHECKSIG
```

The recipient can take the coins by showing a 32-byte secret whose SHA-256 is
in the script. Whoever locked them can take them back after the lock time if
that never happens. Only the initiator knows the secret at first; the moment
they use it to take the other side's coins, it is on that chain for everybody
to read, and the other side uses it to take theirs.

The contract is **byte for byte the one Decred's
[atomicswap](https://github.com/decred/atomicswap) tools use** on every chain
they support, so a Bitflash user and a `btcatomicswap` user can swap with each
other.

The initiator's lock is 48 hours and the participant's 24, so that the
participant always has a day to redeem after the initiator has shown the
secret.

## Embedded Bitcoin light client (no Bitcoin Core)

Without explicit Core RPC settings or an existing Core cookie, the wallet uses
Bitcoin P2P directly. `btcswapinfo` reports `backend: light`, header height,
filter progress, number of filter peers and any network error. The first sync
starts at the embedded height-zero checkpoint and downloads headers and filter
hashes; it does not download historical Bitcoin blocks. Mainnet and testnet4
also require a minimum accumulated chain work before payments are usable.
Regtest needs `-btcchain=regtest -btcpeer=127.0.0.1:18444` on Bitflash testnet.
The peer must advertise `NODE_COMPACT_FILTERS` (Core nodes need
`-blockfilterindex -peerblockfilters` to serve these).

`-btcpeer=host:port` may be repeated; supplying peers disables DNS seeds.
Otherwise service-filtered Bitcoin DNS seeds (`x49.`) and discovered addresses
provide peers; an `-isolate` bench node uses only `-btcpeer` and makes no
Bitcoin connection without one. Connections use the wallet's `BtfConnectSocket` transport and
therefore its configured Tor proxy. Two available peers must agree on filter
headers before scanning proceeds. A disagreement stops audits rather than
choosing one peer's answer. With one peer, omission resistance depends on that
peer; compact filters are not committed by Bitcoin proof of work.

- `btcnewaddress` still creates the contract recipient key in Bitflash.
- `btcinitiate` / `btcparticipate` return `awaitingPayment`, `contractAddress`
  and `paymentInstructions`: pay the exact amount from your Bitcoin wallet.
  They do not send Bitcoin automatically.
- `btcauditcontract <contract> [ref]` watches the P2SH output script. An empty
  reference discovers its payment through filters; multiple payments require
  an explicit `txid:vout`. Until headers and watched filters catch up, the
  audit reports synchronization rather than asserting that coins are absent.
- `btcredeem <contract> <ref> <secret> <Bitcoin destination>` and
  `btcrefund <contract> <ref> <Bitcoin destination>` require a destination in
  light mode. Legacy, P2SH, SegWit v0 and Bech32m witness addresses are decoded
  locally and must match the selected Bitcoin network.
- `btcfindsecret` reads confirmed spending transactions from matched blocks.
  Light mode does not inspect the mempool or perform arbitrary historical
  transaction searches. New watches include a week of overlap at initial
  synchronization and 400 blocks when added to an already synchronized wallet.
- Signed spends are saved before returning and rebroadcast each round until
  included in an active-chain matched block. A reorg resumes rebroadcast.

In chat, save **your Bitcoin receiving address** before approving a light-mode
swap. It stays local to the saved swap, separate from its contract key address.
The chat displays **waiting for you to pay the contract**, the amount and a
copyable contract address; it announces a lock only after its payment confirms.
An unexpected funding amount is retained for refund, never accepted as the
agreed swap amount. Keep the chat open through completion or refund.

- **Cancel while waiting for the payment.** A swap still waiting for you to
  pay its contract can be cancelled. The contract is not forgotten: if a
  payment was already on its way, it comes back to your Bitcoin address at
  the lock. If nothing is paid by the lock the swap is called off by itself,
  and a day after the lock it ends. Never pay a cancelled contract.
- **A light-mode redeem is done only when it is in a block.** The light client
  sends but sees no memory pool, and once a redeem is sent the secret is
  public. A Bitcoin redeem still unconfirmed after an hour goes out again at
  twice the fee rate (the redeem signals BIP125), up to 0.01 BTC per 1000
  vbytes. With no fee estimate in light mode the first rate is `-btcfeerate`,
  10 sat/vB when unset; set it higher when Bitcoin's fees are high.
- **A taker's refund is watched to the end.** The maker holds the secret and
  could still redeem the taker's contract after the taker's refund was sent,
  outbidding its fee. Until the maker's own lock opens, the taker's chat keeps
  looking for that redeem, and if it appears it takes the maker's coins with
  the secret it shows. This holds with Bitcoin Core too.

State lives under `GetAppDir()` in `btc-light-<network>.headers`, `.filters`
and `.json`. Contracts, scan cursor, matched blocks and pending broadcasts
survive restarts. Store failures stop the light client instead of discarding
history. The `.json` file is replaced atomically; headers and filter headers use
validated append-only logs, with an atomic filter-log replacement after reorg.
A truncated log requires backup recovery.

Explicit `-btcdatadir`, `-btcrpcport`, `-btcwallet`, RPC credentials, or an
existing default Core cookie keep the original Core path below. A configured
Core RPC failure does not silently switch a running swap's backend.

## 1. In btfchat

Needs the chat linked to the Bitflash wallet (`-chatwallet`), and for the
Bitcoin side, the embedded light client above or Bitcoin Core on the same machine (below).

- **Offer**: in a community, under the posts, `swap: give 100 BTF for 0.001 BTC`
  and **offer**. It is a signed post: anybody in the community sees it with a
  **take** button. Posting locks nothing.
- **Take**: pressing **take** starts the swap in the conversation with whoever
  posted it (an invite first, if you have never talked).
- **Maker**: the chat shows **accept: lock 100 BTF**. Two presses: the coins go
  into the contract.
- **Taker**: the chat checks the maker's contract on the taker's own node --
  on the chain, unspent, confirmed, paying the taker's address the agreed
  amount, with at least 36 hours left -- and only then shows **go on: lock
  0.001 BTC**. Two presses.
- **Then nobody presses anything.** The maker's chat checks the taker's
  contract the same way (paying the maker, under the maker's secret hash, at
  least 6 hours left) and takes it, which shows the secret on that chain. The
  taker's chat reads the secret **off the chain** -- not from a message -- and
  takes the maker's.
- **If it does not finish**, each side's coins come back by themselves when
  their lock runs out, as long as the chat is open at some point after that.

A step from the other side is a claim; nothing is locked or redeemed on the
strength of a message alone. **Keep the chat open while a swap is running.**
The one way to lose is to be the taker and stay away for the whole day after
the maker has taken your side: then the maker can refund too.

## 2. The wallet's RPC, with a current Bitcoin Core

Decred's tool signs Bitcoin transactions with `dumpprivkey`, which only a
legacy wallet answers -- and Bitcoin Core removed legacy wallets in 30.0. So
here the Bitflash wallet holds the keys the Bitcoin contract pays to and signs
the Bitcoin transactions itself. Bitcoin Core is asked only for what any
current version does: pay to an address (funding the contract), give a fresh
address of its own (where redeemed or refunded coins go), the fee rate, the
chain, and relaying. Tested with Bitcoin Core 31.1 and its default descriptor
wallet.

The Bitflash wallet finds Bitcoin Core on 127.0.0.1 through Core's own
`.cookie`:

```
-btcchain=main            main (default), testnet4 (default on Bitflash testnet), test, signet, regtest
-btcdatadir=DIR           Core's data directory, if not the default
-btcrpcport=N             if not the chain's default
-btcwallet=NAME           which Core wallet, if Core has more than one loaded
-btcrpcuser=U -btcrpcpassword=P   instead of the cookie
-btcfeerate=BTC           per 1000 vbytes, when Core has no estimate (regtest)
```

**The networks must match**: mainnet BTF swaps only against Bitcoin's main
chain, testnet BTF only against a Bitcoin test chain. Otherwise somebody could
pay real BTF with regtest coins they minted for free; the wallet refuses.

Alice has BTF and wants BTC; Bob has BTC and wants BTF, both with this wallet:

| | Alice (BTF) | Bob (BTC) |
|---|---|---|
| 1 | gives Bob a BTF address (`getnewaddress`) | gives Alice a Bitcoin address of **his Bitflash wallet** (`btcnewaddress`) |
| 2 | | `btcinitiate <Alice's btcnewaddress> 0.001` -- Core pays the contract; prints the contract, txid, vout, the **secret** and its **hash** |
| 3 | `btcauditcontract <contract> <txid:vout>` -- on **her own** Core: unspent, confirmations, pays her, hash, time left | |
| 4 | `swapparticipate <Bob's BTF address> 100 <hash>` -- locks BTF for 24 h | |
| 5 | | `swapauditcontract <contract> <txid>`, then `swapredeem ... <secret>` -- takes the BTF, showing the secret |
| 6 | `swapfindsecret <her contract> <txid>` -- the secret, off the chain | |
| 7 | `btcredeem <Bob's contract> <txid:vout> <secret>` -- the BTC lands in her Core's wallet | |

Either side can be the initiator, on either chain. `btcfindsecret` does on
Bitcoin what `swapfindsecret` does here: it says whether a contract was spent,
and with which secret, from Core's memory pool and the last 400 blocks.

## 3. With btcatomicswap

For a Bitcoin Core up to 29.x with a legacy wallet. Bob runs `btcatomicswap`
against his Core; Alice uses the Bitflash wallet:

| | Alice (BTF) | Bob (BTC) |
|---|---|---|
| 1 | `swapinitiate <Bob's BTF address> <amount>` -- prints the contract, its txid, the secret and the hash; sends Bob the contract, txid and **hash** | |
| 2 | | `swapauditcontract <contract> <txid>` on a Bitflash node |
| 3 | | `btcatomicswap participate <Alice's BTC address> <amount> <hash>` |
| 4 | `btcauditcontract <contract> <contract tx>` (or `btcatomicswap auditcontract`) | |
| 5 | `btcredeem` (or `btcatomicswap redeem`) -- shows the secret on Bitcoin | |
| 6 | | `swapextractsecret <Alice's redeem tx, raw hex> <hash>`, then `swapredeem` |

## What to check, and why

- **Audit on your own node before locking anything.** A raw transaction the
  other side sends proves nothing; what counts is that YOUR node sees the
  contract output unspent, confirmed, paying YOUR address the agreed amount,
  with time left. `btcauditcontract` asks your Bitcoin Core (`unspent`,
  `confirmations`); `swapauditcontract` your Bitflash node.
- **The lock times are fixed on mainnet** (48 h / 24 h). A short lock is how a
  participant loses their coins: the initiator waits it out, refunds, and
  still redeems the other side. Test chains accept a shorter one as a last
  parameter, to try a refund in minutes.
- **The secret is written to `swaps.log`** in the data directory by
  `swapinitiate` and `btcinitiate`, because it is the one thing that cannot be
  recovered and an RPC answer scrolls away. Keep that file as private as the
  wallet. The keys a Bitcoin contract pays to are this wallet's keys: back the
  wallet up as you would for BTF.
- **Before rules v3 every swap command refuses.** Until then a script-hash
  output is anyone-can-spend: a funded contract could be taken by whoever read
  it off the chain. On mainnet they keep refusing until the launch on
  2026-12-25 12:00 UTC, the Bitcoin half included, and btfchat does not post
  or take offers before then.

## Reference

| call | does |
|---|---|
| `swapinitiate addr amount` | new secret; Bitflash contract paying `addr` with the secret, refundable to us after 48 h; funds it |
| `swapparticipate addr amount hash` | contract paying `addr` under `hash`, refundable to us after 24 h; funds it |
| `swapauditcontract contract txid` | terms, amount, `recipientIsMine`, `confirmations`, `unspent`, `blocksUntilRefund` |
| `swapredeem contract txid secret` | takes the coins with the secret, to a fresh address of ours |
| `swaprefund contract txid` | takes them back after the lock |
| `swapfindsecret contract txid` | was our contract spent, and with which secret (memory pool and chain) |
| `swapextractsecret txid\|hex hash` | the secret, from a redeem on this chain (txid) or Bitcoin's (raw hex, witness or not) |
| `btcswapinfo` | is Bitcoin Core reachable, which chain, balance, fee rate |
| `btcnewaddress` | a Bitcoin address whose key is in this wallet: where to be paid BTC in a swap |
| `btcinitiate addr amount` | new secret; Bitcoin contract paying `addr`, refundable to us after 48 h; Core funds it |
| `btcparticipate addr amount hash` | the same under `hash`, 24 h |
| `btcauditcontract contract ref` | as Core sees it: `unspent`, `confirmations`, amount, `recipientIsMine`, `secondsUntilRefund` |
| `btcredeem contract ref secret` | takes the BTC with the secret, into a fresh address of Core's wallet |
| `btcrefund contract ref` | takes it back once Bitcoin's median time passes the lock |
| `btcfindsecret contract ref [height]` | was it spent, and with which secret |

`ref` is the contract transaction's raw hex, a txid Core can find, or
`txid:vout`.

### Litecoin

Every `btc*` call has a twin that takes the chain first: `coinswapinfo ltc`,
`coinnewaddress ltc`, `coininitiate ltc addr amount`, `coinparticipate ltc
addr amount hash`, `coinauditcontract ltc contract ref`, `coinredeem ltc
contract ref secret`, `coinrefund ltc contract ref`, `coinfindsecret ltc
contract ref`, `coinvalidatedestination ltc addr` (`coin... btc` is the same
as `btc...`). The contract, the locks and the Bitflash half are the same.
Litecoin addresses in the contract are legacy key addresses (`L...` on main,
`m`/`n` on the test network).

In btfchat an offer names the chain: `swap: give 100 BTF for 2 LTC` in the
window (the coin next to the second amount), or in the terminal `offer 100 BTF
for 2 LTC` and `offer 2 LTC for 100`. One side is always BTF. On mainnet the
chat waits for 8 Litecoin confirmations, about the 20 minutes of Bitcoin's 2,
because what stops a private fork is the time it takes to mine, not the count.
A wallet from before this does not show a Litecoin offer. Proven with coins
by `-selftest=chat-swap` with `CHATSWAP_COIN=LTC` against Litecoin Core on
regtest with MWEB active, on Litecoin Core and on the light client: a swap
each way, and a maker who vanishes, with both sides' coins coming back alone.

Where the Litecoin side runs is chosen as for Bitcoin: a running Litecoin
Core (its cookie in the default data directory, or `-ltcdatadir`,
`-ltcrpcport`, `-ltcrpcuser`/`-ltcrpcpassword`, `-ltcwallet`), else the
embedded light client. `-ltcchain` is `main` (default), `test` (default on
Bitflash testnet) or `regtest`; `-ltcpeer=host:port` (repeatable) names its
peers, and `-ltcfeerate` the fee rate when there is no estimate.

The light client checks every header's scrypt proof of work and Litecoin's
retarget (the whole period, Litecoin's correction to Bitcoin's), and starts
from a run of twelve real headers at a recent retarget boundary instead of
genesis (see the table in `src/btclight.cpp` for where they were read and
how they were checked). Litecoin peers rarely serve BIP157 filters, so it
downloads the blocks inside a swap's window, from when the contract could first
be funded (its lock less the longest lock) to the tip, checks each against
its header's merkle root, and keeps the ones
that pay or spend the contract. Asked for a plain block, Litecoin Core sends
it without MWEB data, so the transactions read as Bitcoin's do. It dials only
after a Litecoin swap has been made once (its state file exists), and only
over the wallet's Tor. State: `ltc-light-<network>.headers` and `.json`.

`-selftest=ltc-light` checks the genesis hashes, the anchors and their scrypt
work, two retargets the chain made, the test network's minimum-difficulty
rule, scrypt (not the header hash) as the work, and Litecoin's addresses.

Proven with coins against Litecoin Core 0.21.4 on regtest and two isolated
Bitflash testnet nodes, one on Litecoin Core and one on the light client: a
swap each way (each side audited, redeemed, and read the secret off the
other chain), and a refund on each backend, refused before the lock and
confirmed after it, all of it with and without MWEB active on the chain. Live
on Litecoin's test network over Tor, the light
client followed the headers to the explorer's tip and scanned a contract's
window of real blocks, MWEB blocks included. A public swap on Litecoin's test
network and the Bitflash testnet, both wallets on the light client, was made
on 2026-11-04. One on the main network is still to do (docs/swaps-multicoin.md,
"Proof before opening").

### Bitcoin Cash and eCash

The same `coin*` calls with `bch` or `xec` first, the same contract, and
`offer 100 BTF for 2 BCH` in the chat. What differs from Bitcoin:

- **Addresses** are cashaddr with the chain's prefix: `bitcoincash:`,
  `bchtest:`, `bchreg:`, `ecash:`, `ectest:`, `ecregtest:`. A contract's key
  address is `...:q...`. An address of one chain is refused on the other,
  because the prefix is in its checksum. Base58 addresses are refused: they
  read the same on Bitcoin. A destination can be a key or a script, and on
  Bitcoin Cash a token-aware or 32-byte script form.
- **Signatures** are made with `SIGHASH_FORKID`, the BIP143 layout, which signs
  the amount spent. Bitflash's script interpreter does not run them, so
  before a spend is returned the wallet checks the key and secret against the
  contract, and the chain's own nodes check the rest.
- **XEC counts to two places.** One XEC is 100 of the chain's base units, not
  100000000. RPC and the chat speak XEC; amounts inside are base units.
- **Mainnet confirmations:** 4 on Bitcoin Cash and 6 on eCash, about 40 minutes
  and an hour. Their blocks take as long as Bitcoin's, but they run Bitcoin's
  SHA-256 with a sliver of its hash rate, so a block can be rented.
- **The fee** has no estimate there: 1 sat/byte, what everyone pays,
  unless `-bchfeerate` or `-xecfeerate` says otherwise (in the coin, per 1000
  bytes). A stuck redeem cannot be replaced, as these chains have no RBF, but
  blocks there have room.

Unlike Bitcoin Core and Litecoin Core, the own node is used only when named,
with `-bchdatadir`, `-bchrpcport`, `-bchrpcuser`/`-bchrpcpassword`, `-bchwallet`
and the same with `-xec`. Bitcoin Cash Node, Bitcoin ABC and Bitcoin Core share a data
directory and an RPC port, so a cookie found there says nothing about the
chain. For the same reason, and for Bitcoin too, the wallet asks the node to
validate an address only its own chain has, and refuses a node that does not
know it. A contract output carrying a CashToken is refused, as this wallet
could not redeem it. Otherwise it is the embedded light client. `-bchchain` is `main`, `test4` (default on Bitflash testnet) or
`regtest`; `-xecchain` is `main`, `test` or `regtest`; `-bchpeer` and
`-xecpeer` name peers.

The light client checks each header's SHA-256 and aserti3-2d, Bitcoin Cash's
and eCash's difficulty rule, with each network's half-life and test
minimum-difficulty rule, starting from twelve real headers. As for Litecoin
it fetches the blocks in a swap's window, up to 256 MB each, as these chains
have no BIP157 filters to ask. Bitcoin Cash and eCash share a network magic and
the first 661647 blocks; a peer on the other chain fails at the first header.
On a main network it reports nothing until the headers carry a sixteenth of
the work the chain did since the anchor, because aserti3-2d lets a private
fork claim the time passed and mine the rest almost free.
State: `bch-light-<network>.*`, `xec-light-<network>.*`.

`-selftest=cash-light` checks the genesis hashes, the anchors and the real
headers after them, the real chain's bits at five heights, one bit flipped
and the other chain's headers refused, the nodes' own cashaddr and signature
hash vectors, and the XEC unit. The anchors and the rule were also checked by
a second implementation of aserti3-2d against every header of the four
networks since the upgrade, about 1.25 million, with no mismatch.

Proven with coins against Bitcoin Cash Node 29.2.0 and Bitcoin ABC 0.34.3 on
regtest, on the node and on the light client: `-selftest=chat-swap` with
`CHATSWAP_COIN=BCH` and `XEC`, a swap each way and a maker who vanishes, and a
contract output carrying a token refused by a real node. A public swap on Bitcoin
Cash's testnet4 and the Bitflash testnet, both wallets on the light client, was
made on 2026-11-05.

Bitcoin ABC schedules a change of the fork value in its signature hash for
each next upgrade (`sandersActivationTime`, 2027-05-15 in v0.34.3), and each
release so far has moved the date. If it ever went through, eCash swaps would
need the new value in `ForkIdSignatureHash`.

### Dogecoin

The same `coin*` calls with `doge` first, the same contract, and
`offer 100 BTF for 5000 DOGE` in the chat. What differs from Bitcoin:

- **Addresses** are base58 only: `D...` on the main network, `n...` or `m...` on
  the test network. Dogecoin has no SegWit.
- **Mainnet confirmations:** 20, about 20 minutes, the time Bitcoin's two take.
- **The fee** is in its own coin: 0.01 DOGE per 1000 bytes, the rate Dogecoin
  Core recommends, unless `-dogefeerate` says otherwise (in the coin, per 1000
  bytes, up to 1 DOGE). An offer or a contract under 0.02 DOGE is refused, as its
  redeem would leave dust, and so is a spend that would leave under 0.01 DOGE.
- **The refund** waits for the median time of the last eleven blocks, as on
  every chain here. Dogecoin never activated BIP113, so its nodes judge the lock
  by the time of the next block: they would take the refund a little sooner than
  this wallet offers it.

As for Litecoin, a Dogecoin Core with a cookie in its data directory is found by
itself, or named with `-dogedatadir`, `-dogerpcport` and
`-dogerpcuser`/`-dogerpcpassword`; otherwise it is the embedded light client.
Dogecoin Core 1.14 has one wallet, so `-dogewallet` does not choose one.
`-dogechain` is `main`, `test` (default on Bitflash testnet) or `regtest`;
`-dogepeer` names a peer.
Dogecoin Core 1.14 answers `validateaddress`, not `getaddressinfo`, and takes a
boolean in `getblock`; the wallet speaks both.

The light client checks each header's DigiShield step and its proof of work:
scrypt on an old-style block, and on a merge-mined one the AuxPoW that Dogecoin's
`CAuxPow::check` asks for, with the parent's scrypt, the merkle branches, the
chain id, the slot and the marker in the coinbase. It starts from twelve real
headers, and the anchor plays the part of a checkpoint. As for Litecoin it
fetches the blocks in a swap's window, up to 32 MB each, with their AuxPoW
stepped over. On the main network it reports nothing until the headers carry a
sixteenth of the work the chain did since the anchor: DigiShield eases by half
a step on each block that claims a long gap, so a private fork that only paid
the rule would reach the minimum difficulty in about 65 blocks. Peers that
refuse a broadcast say so, and that stops nothing. State:
`doge-light-<network>.*`.

`-selftest=doge-light` checks the genesis hashes, the anchors and the real
headers after them, real DigiShield steps and their limits, a real AuxPoW and
each way of bending it (no proof, the parent changed, the wrong slot, another
coinbase, no block in it, a second marker), a block with an AuxPoW, the work
floor against a cheap fork, and the addresses of other chains refused. The
anchors came through a second implementation of DigiShield and AuxPoW: about
6000 headers on the main network and every one of the test network's since
its last checkpoint, 62 million, with no mismatch. The main anchor's hash was
checked against two explorers.

Proven with coins against Dogecoin Core 1.14.9 on regtest, on the node and on
the light client: `-selftest=chat-swap` with `CHATSWAP_COIN=DOGE`, a swap each
way and a maker who vanishes. A public swap on Dogecoin's test network and the
Bitflash testnet, both wallets on the light client, was made on 2026-11-05. Its
contract was paid by the coinbase of a mined block, so it also waited out the
240 blocks a coinbase takes to mature on that network.

### DigiByte

The same `coin*` calls with `dgb` first, the same contract, and
`offer 100 BTF for 50000 DGB` in the chat, through DigiByte Core or the embedded
light client. What differs from Bitcoin:

- **Addresses** in the contract are legacy keys: `D...` on the main network,
  `s...` or `t...` on the test network and regtest. `dgb1` and `dgbt1` cannot be
  in it.
- **Mainnet confirmations:** 160, about 40 minutes at 15 seconds a block. Two of
  its five algorithms, SHA-256 and scrypt, have hash rate for rent, so it gets
  the time Bitcoin Cash gets.
- **The fee** is what DigiByte Core estimates, at least 0.001 DGB per 1000 bytes,
  its minimum relay fee; `-dgbfeerate` sets it when there is no estimate. An
  offer or a contract under 0.1 DGB is refused, as DigiByte wallets pay
  0.1 DGB per 1000 bytes and a smaller contract could cost more to spend than it
  holds. A spend that would leave under 0.0001 DGB is refused too.
- **Dandelion:** DigiByte Core holds a new transaction apart for up to about 30
  seconds, and a restart in that time loses it. So a redeem or a refund counts
  only from a block, and goes out again after an hour without one.
- **Finding a secret** looks back up to 13000 blocks, a little more than a
  48-hour lock, one block at a time. A search that found nothing is not done
  again, so only the first one can take a minute or two.

DigiByte Core keeps its data in `DigiByte` under `%APPDATA%`, or `~/.digibyte`,
and a cookie there is found by itself, or named with `-dgbdatadir`,
`-dgbrpcport`, `-dgbwallet` and `-dgbrpcuser`/`-dgbrpcpassword`; otherwise it is
the embedded light client. `-dgbchain` is `main`, `test` (default on Bitflash
testnet) or `regtest`; `-dgbpeer` names a peer. Its test network was started
over in 2026 and lives in `testnet26`.

The light client starts from 240 real headers and checks every header after
them with `dgb_pow.h`: the proof of whichever of the five algorithms it names,
MultiShield's difficulty for that algorithm, and DigiByte's own measure of work,
which is what picks the best chain. Its peers want protocol 70017 or later, so it
says 70019. A default node serves no BIP157 filters: as for Litecoin, it reads
the blocks of the contract's window, here four times as many. Past the anchor a
chain has to show a sixteenth of the work the real one did since, as for the
chains that retarget every block. The anchor is a checkpoint: nothing forks from
inside it.

Blocks count for what they cost. MultiShield eases for a chain that claims time
has passed, and a private chain of 160 blocks can hold the work of about 40. So
the light client reports a contract's confirmations by the work over it, in steps
of the 240 blocks before it, and never more than the blocks there are. The last
two blocks are read a round later: a tip every 15 seconds would otherwise keep
asking a peer for a block it has not got.

The same checks took every real header of the main network from 24,000,401 to
24,516,451, 516,051 of them, and of the test network from 37,000 to 604,411, with
no mismatch. The test network's retarget stops at 810 seconds, not 870
(`nMaxActualTimespanV4` is worked out from a different limit there), and its
Odocrypt changes shape daily, not every ten days.

Proven with coins against DigiByte Core 9.26.7 on regtest, on the node and on the
light client: `-selftest=chat-swap` with `CHATSWAP_COIN=DGB`, a swap each way and
a maker who vanishes, on a chain of more than 3000 blocks. A public swap on
DigiByte's test network and the Bitflash testnet, both wallets on the light
client, was made on 2026-11-06. Its contract was paid by the coinbase of a block
mined on a CPU with Odocrypt, so it also waited out the 100 blocks a coinbase
takes to mature.

### Ravencoin

The same `coin*` calls with `rvn` first, the same contract, and
`offer 100 BTF for 5000 RVN` in the chat, through Ravencoin 4.8.0 or, on the main
network and regtest, the embedded light client. Its test network has only the node:
no peer of it answered on 2026-11-06, so the client has nowhere to start from. What
differs from Bitcoin:

- **Addresses** are base58 only: `R...` on the main network, `n...` or `m...` on
  the test network. No SegWit addresses.
- **Mainnet confirmations:** 60, about an hour. KAWPOW's hash rate can be rented,
  and past 60 blocks Ravencoin's nodes refuse a reorganization.
- **The fee** is what the node estimates, at least 0.01 RVN per 1000 bytes, its
  minimum relay fee; `-rvnfeerate` sets it when there is no estimate. An offer or
  a contract under 0.1 RVN is refused, and so is a spend that would leave under
  0.0001 RVN.
- **Blocks:** a KAWPOW header is 120 bytes, not 80, from May 2020 on. Ravencoin's
  regtest stays on the 80-byte header, as KAWPOW never activates there.
- **Amounts:** an offer holds at most 21 million, far under Ravencoin's supply of
  21 billion.

Ravencoin keeps its data in `Raven` under `%APPDATA%`, or `~/.raven`, and a
cookie there is found by itself, or named with `-rvndatadir`, `-rvnrpcport`,
`-rvnwallet` and `-rvnrpcuser`/`-rvnrpcpassword`; otherwise it is the embedded
light client. It answers `validateaddress`, not `getaddressinfo`. `-rvnchain` is
`main`, `test` (default on Bitflash testnet, in `testnet7`) or `regtest`;
`-rvnpeer` names a peer.

The light client starts from 200 real headers and checks every header after them
with `rvn_kawpow.h`: its height, DarkGravityWave over the last 180 blocks, then
KAWPOW. As for DigiByte, a contract's confirmations count by the work over it, and
past the anchor a chain has to show a sixteenth of the work the real one did since.
A block's name is the mix its header carries, trusted only once the proof has
recomputed it. On regtest, where KAWPOW never activates, blocks are named by
X16RV2 (`x16rv2.h`), which is there for that alone.

Proven with coins against Ravencoin 4.8.0 on regtest, on the node and on the light
client: `-selftest=chat-swap` with `CHATSWAP_COIN=RVN`, a swap each way and a maker
who vanishes. `-selftest=rvn-chain` reads a real main network block, and has
X16RV2 name a real regtest block. `rvnpow` took every main network header from
4,507,691 to 4,614,104, 106,414 of them, DGW and the full KAWPOW proof, with no
mismatch. Nothing on a public network yet: the eight test network peers its seeds
gave did not answer on 2026-11-06, so the first public swap will be on the main
network.

Checked by `-selftest=rules-v3` (the template byte for byte, redeem and
refund on the Bitflash side, the wrong secret or key, a refund before its
lock) and `-selftest=btc-swap` (Bitcoin addresses, reading Bitcoin's witness
serialization and raw blocks, the redeem and refund this wallet signs for
Bitcoin, the fee).
