# Atomic swaps: BTF for BTC, nobody in the middle

Two people who do not trust each other trade BTF for BTC (or LTC, or any coin
with the same script) without an exchange, an escrow, a server or a custodian.
Either both get paid, or both get their coins back. Needs rules v3, which make
pay-to-script-hash and `OP_CHECKLOCKTIMEVERIFY` live (see `consensus.h`).

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

The contract is **byte for byte the one Decred's [atomicswap](https://github.com/decred/atomicswap)
tools use** on every chain they support. That is deliberate: the Bitcoin half
is done with `btcatomicswap`, which exists and has been used for years, and
nothing of ours touches Bitcoin.

## The steps

Alice has BTF and wants BTC. Bob has BTC and wants BTF. Each runs their own
wallet: Alice a Bitflash node with RPC, Bob Bitcoin Core with `btcatomicswap`.
They talk wherever they like -- btfchat is a good place, since the addresses
and hashes they exchange are then signed by who sent them.

| | Alice (BTF) | Bob (BTC) |
|---|---|---|
| 1 | gets Bob's BTC address for the refund side, and gives Bob a BTF address of hers |
| 2 | `swapinitiate <Bob's BTF address> <amount>` -- locks BTF for Bob for 48 h; prints the **contract**, its **txid**, the **secret** and its **hash** | |
| 3 | sends Bob the contract, the txid and the **hash** -- never the secret | |
| 4 | | `swapauditcontract <contract> <txid>` on a Bitflash node: checks it pays **him**, the amount, the hash, the lock |
| 5 | | `btcatomicswap participate <Alice's BTC address> <amount> <hash>` -- locks BTC for Alice for 24 h |
| 6 | `btcatomicswap auditcontract` on Bob's contract | |
| 7 | `btcatomicswap redeem <contract> <tx> <secret>` -- takes the BTC, **showing the secret on Bitcoin** | |
| 8 | | `swapextractsecret <Alice's redeem tx, raw hex> <hash>` -- reads the secret off it |
| 9 | | `swapredeem <contract> <txid> <secret>` -- takes the BTF |

If Bob never participates, Alice waits 48 h and runs `swaprefund`. If Alice
never redeems, Bob waits 24 h and refunds with `btcatomicswap refund`. Alice's
lock is the longer one so that Bob always has a day to redeem after she has
shown the secret.

## What to check, and why

- **Audit before locking anything.** `swapauditcontract` says whether the
  coins go to *your* address (`recipientIsMine`), how much, under which hash,
  and how many blocks until the other side can refund. A contract that pays
  somebody else, or whose lock leaves you no time, is not a swap.
- **The lock times are fixed on mainnet** (48 h / 24 h, in blocks). A short
  lock is how a participant loses their coins: the initiator waits it out,
  refunds, and still redeems the other side. Testnet accepts a shorter one as
  a last parameter, to try a refund in minutes.
- **The secret is written to `swaps.log`** in the data directory by
  `swapinitiate`, because it is the one thing that cannot be recovered and an
  RPC answer scrolls away. Keep that file as private as the wallet.
- **Before rules v3 every swap command refuses.** Until then a script-hash
  output is anyone-can-spend: a funded contract could be taken by whoever read
  it off the chain.

## Reference

| call | does |
|---|---|
| `swapinitiate addr amount` | new secret; contract paying `addr` with the secret, refundable to us after 48 h; funds it |
| `swapparticipate addr amount hash` | contract paying `addr` with the secret of `hash`, refundable to us after 24 h; funds it |
| `swapauditcontract contract txid` | the terms, the amount, `recipientIsMine`, `blocksUntilRefund` |
| `swapredeem contract txid secret` | takes the coins with the secret, to a fresh address of ours |
| `swaprefund contract txid` | takes them back after the lock |
| `swapextractsecret txid\|hex hash` | the secret, from a redeem on this chain (txid) or Bitcoin's (raw hex) |

Checked by `-selftest=rules-v3`: the template byte for byte, redeem and
refund, a wrong or short secret, the wrong key on either path, a refund dated
before its lock, and the contract being anyone-can-spend before the switch.
