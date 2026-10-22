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
provide peers. Connections use the wallet's `BtfConnectSocket` transport and
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

Checked by `-selftest=rules-v3` (the template byte for byte, redeem and
refund on the Bitflash side, the wrong secret or key, a refund before its
lock) and `-selftest=btc-swap` (Bitcoin addresses, reading Bitcoin's witness
serialization and raw blocks, the redeem and refund this wallet signs for
Bitcoin, the fee).
