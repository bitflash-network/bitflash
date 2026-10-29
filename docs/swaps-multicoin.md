# Swaps with more chains (design)

Status: design. Target: swaps with Litecoin, Dogecoin, Bitcoin Cash, eCash,
DigiByte and Ravencoin open on mainnet with Bitcoin's, on 2026-12-25 12:00
UTC; Zcash (transparent addresses) in January 2027.

## What does not change

The contract is the one every swap here uses (docs/atomic-swaps.md), byte for
byte Decred's atomicswap contract: SHA-256 hash lock, `OP_CHECKLOCKTIMEVERIFY`
refund, P2PKH both ways. All six chains run Bitcoin's script with P2SH and
CLTV, so the same contract, the same redeem and the same refund work on each.
The Bitflash side does not change at all. The initiator's lock is 48 hours and
the participant's 24, in median time past, on every chain.

The key the other chain's contract pays is a key of this wallet, as it is for
Bitcoin (btcswap.h): the same curve and the same Hash160 serve all of them.

## What changes per chain

Per chain, from that chain's own source at a named release tag, never from
memory:

- network magic, default port and DNS seeds;
- address versions (P2PKH, P2SH), a bech32 or cashaddr prefix where the chain
  has one;
- block interval, proof-of-work algorithm and difficulty rule;
- genesis block, minimum chain work, and a checkpoint to start from;
- the signature hash: legacy, or with `SIGHASH_FORKID` (Bitcoin Cash, eCash);
- whether its peers serve BIP157 filters.

| chain | source | PoW | difficulty | signature | addresses |
|---|---|---|---|---|---|
| Litecoin | litecoin-project/litecoin v0.21.4 | scrypt(1024,1,1) | Bitcoin's, 2016 blocks of 2.5 min | legacy | base58 48/50 (5 legacy), bech32 `ltc` |
| Dogecoin | dogecoin/dogecoin v1.14.9 | scrypt, merge-mined (AuxPoW, chain id 98) | DigiShield, every block | legacy | base58 30/22 |
| Bitcoin Cash | bitcoin-cash-node v29.2.0 | SHA-256d | ASERT (aserti3-2d) | FORKID | cashaddr `bitcoincash` (base58 0/5) |
| eCash | Bitcoin-ABC v0.34.3 | SHA-256d | ASERT | FORKID | cashaddr `ecash` |
| DigiByte | digibyte core (tag to name) | five algorithms by version bits | per-algo (MultiShield) | legacy | base58 |
| Ravencoin | ravencoin (tag to name) | KAWPOW | DarkGravityWave v3 | legacy (FORKID? to check) | base58 |

The DigiByte and Ravencoin proof-of-work and difficulty modules are written
separately (branch `light/dgb-rvn-pow`, docs/light-pow.md) and plugged in here.

## Two ways to watch a chain

**Own node.** As with Bitcoin Core today, the wallet asks the person's own
node (litecoind, dogecoind, Bitcoin Cash Node, Bitcoin ABC, digibyted,
ravend) over its RPC, on 127.0.0.1, for what any version answers: send to an
address, a fresh address, the chain, a raw transaction, relay. Available for
every chain from the first day.

**Embedded light client.** The client is Bitflash's own: Bitcoin's P2P
protocol, over Tor, to the chain's own peers, with no server of anyone's.
- **Headers.** It keeps the header chain from a checkpoint and checks every
  header: the chain's proof of work, and its difficulty rule. This is the
  security of the swap. A peer that could pass off a block it did not mine
  could show a payment that does not exist, and the wallet would give up the
  swap secret for it.
- **Payments.** Where the chain's peers serve BIP157 filters, it uses them, as
  for Bitcoin. Where they do not (most of these chains), it downloads whole
  blocks, but only those inside a swap's window, from when the contract can be
  funded to when the refund opens. These chains' blocks are small; a 48-hour
  window is a few hundred to a few thousand blocks.
- **Minimum work.** It reports nothing until the header chain carries the
  chain's own minimum chain work (from the chain's release), so a peer that
  isolates it cannot feed it a cheap fork.

Embedded on 2026-12-25: Litecoin, Dogecoin, Bitcoin Cash and eCash, whose
proof of work this client can check (scrypt, AuxPoW over scrypt, SHA-256d).
DigiByte and Ravencoin open that day with the own-node mode, and their
embedded client follows when their PoW modules are proven. Any chain whose
embedded client is not proven with coins by 2026-12-15 opens with the
own-node mode only. The date does not move.

## Structure in the code

- `altchains.{h,cpp}`: one `AltChain` per chain and network, every constant
  in the table above, with the file and tag it came from.
- The light client (`btclight`) becomes one instance per chain, each with its
  own state file, its own peers and its own worker thread. Bitcoin keeps
  exactly the behaviour it has.
- `btcswap` becomes chain-generic. The Bitcoin functions stay as they are,
  thin calls into the generic ones with the Bitcoin chain.
- RPC: the `btc*` commands stay. Each one gets a chain-generic twin that takes
  the chain first (`coininitiate ltc <address> <amount>`, `coinredeem ltc
  ...`, ...).
- btfchat: an offer names the chain. A node that does not know a chain says
  so, and refuses to take the offer.
- The networks must match, as for Bitcoin: Bitflash mainnet trades only with
  each chain's main network, Bitflash testnet only with its test network.

## Proof before opening

For each chain, before it opens:
1. The self-tests: real headers from the chain, checked by the PoW and
   difficulty code (passing, and failing with one bit flipped); the address
   and signature-hash vectors from the chain's own tests.
2. A swap on the chain's testnet, both ways, through redeem and through
   refund, with the embedded client and with the own-node mode.
3. A swap on the chain's main network with a small amount, both ways,
   watched by the embedded client.
