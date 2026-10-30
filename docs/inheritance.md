# Inheritance

Coins that pass to an heir once the owner has gone quiet for a set time. No
third party, no server, no key handed over in advance: the heir holds their
own key and a package that says where the coins are, and the chain decides
when that key starts to count.

It needs rules v4 (`OP_CHECKSEQUENCEVERIFY` and BIP68, `docs/rules-v4.md`):
the wallet refuses to make one before they are in force, because before then
the heir's path could never be taken.

## The script

One pay-to-script-hash output:

```
OP_IF
  OP_DUP OP_HASH160 <owner> OP_EQUALVERIFY OP_CHECKSIG
OP_ELSE
  <period> OP_CHECKSEQUENCEVERIFY OP_DROP
  OP_DUP OP_HASH160 <heir> OP_EQUALVERIFY OP_CHECKSIG
OP_ENDIF
```

- The owner spends it at any time.
- The heir spends it only once the output has sat unspent for `<period>`.

`<period>` is a relative lock **in time**, not in blocks: BIP68 time units of
512 seconds, at most 65535 of them (about 388 days). A lock in blocks stops at
65535 blocks, which at two minutes a block is 91 days, too short for an
inheritance. Time is measured as BIP68 measures it, from the median time past
of the block before the coin's to the median time past of the chain tip, so
no single miner's clock moves it.

The heir's key is an ordinary address, given by the heir. The owner's key is
a fresh key of the owner's wallet.

## Renewal

The owner's wallet renews the inheritance by itself: once **half** the period
has passed since the output was mined, it spends the output back to the same
address, less a small fee. That starts the clock again. So an owner who opens
the wallet now and then never lets it open to the heir, and an owner who
stops for good lets it open one period after the last renewal.

- The address never changes. The heir's package (the script and the first
  transaction) stays good after any number of renewals: the heir's wallet
  follows the chain of renewals from the first transaction through the
  transaction index.
- The renewer runs in every node with a wallet, every five minutes, whether or
  not the RPC server is on.
- A renewal pays no address of the wallet, so the wallet would not keep it; it
  is kept beside the contract and broadcast again until it is mined.
- Renewing at half the period leaves the other half as slack: with a 180-day
  period, the wallet has to be open (and unlocked, if encrypted) at some point
  in a 90-day window. If renewal is due and the wallet is locked, the node logs
  how long is left before the heir can claim.
- Each renewal costs one fee (0.01 by default), taken from the inheritance.

On mainnet the period is at least 30 days: anything shorter, and a holiday
away from the wallet hands the coins over.

## Using it

Owner:

```
inheritcreate 1000 <heir address> 180
```

returns the inheritance address and a `heirPackage`. Hand the package to the
heir (a file, a QR code, paper). It holds no key; the heir also needs their
own wallet backup. `inheritpackage <address>` prints it again.
`inheritinfo <address>` says when the next renewal is due. `inheritcancel
<address> <to>` takes the coins back and ends it.

Heir, with the wallet that holds the heir address:

```
inheritimport '<package>'
inheritinfo <address>
inheritclaim <address> <to address>
```

`inheritimport` checks the script byte for byte against the template and
refuses a wallet that does not hold the heir key; everything is read from the
script, not from what the package claims. `inheritclaim` says how long is left
while the period runs; once it has passed, it takes the coins.

## What it does not protect against

- **The owner losing the wallet.** The coins are not lost: they go to the
  heir one period after the last renewal. That is by design.
- **The heir's key being stolen.** It only matters once the owner has gone
  quiet for the whole period; until then the thief can do nothing.
- **Privacy.** Renewals are public transactions to the same address, at a
  regular rhythm. Anybody who knows the address sees that the owner is alive.
  The script itself is revealed at the first renewal.
- **Coins sent to the address directly.** The wallet tracks one output per
  inheritance, the one it made and renewed. Do not use the address to
  receive payments; make another inheritance instead.

## Files and commands

Contracts are kept in `v4contracts.json` beside the wallet, with the vaults and
batches (`docs/rules-v4.md`); back it up with the wallet. The commands are in
`docs/rpc.md`. `-selftest=inheritance` checks the period arithmetic, the
script and its three ways to be spent.

## Proven on an isolated testnet bench (2026-10-30)

Two nodes on testnet, cut off from the public network (`-isolate`, each
`-connectbtf` to the other), with rules v4 in force from a bench height
(`-benchrulesv4`): C holds the owner's wallet, D holds the heir's. The period
was 4 time units (2048 seconds, `days` 0.0237), the shortest testnet allows
that still spans several blocks, so the whole life of an inheritance fits in
an afternoon. Every step was done with coins, through the RPC commands above.

| Case | Result |
|---|---|
| `inheritcreate 100 <heir> 0.0237` (#1) | `CYnANdUwxrwnUZbqAR6dHE9qQ9PLVYipVW`, sequence 4194308, funded by `608c2e0af699bd4907d723e429ce57210fb04521e17d1208ca006f3e242e9b86` |
| `inheritcreate 50 <heir> 0.0237` (#2) | `CSVSfNXjXoNBdGAm9ioZebp32pLjaqnXke`, funded by `6fa87d3945aa4970270464c62f54ef120c2ca180fc925366cecefecf2e05ebb4` |
| `inheritimport` on D, package as a JSON string and as an object | accepted, role heir |
| `inheritimport` on C (the owner's wallet) | refused: does not hold the heir key |
| package with one byte of the script changed | refused: not the inheritance template |
| package naming a script address as heir | refused |
| automatic renewal, half the period after each output was mined | #1 renewed by `76fc8f76296cedfbb09a498aed34c4d45753d998850b9ff0beb8d589f9566538`, #2 by `10488136a8027a56124ff196869ee26aa6cc4389c43ada5b61b724a1c7ec914b`, 0.01 fee each; D followed both (renewals 1, amounts 99.99 and 49.99) without a new package |
| `inheritclaim` on D right after the renewal | refused: not yet, opens in about 33 minutes (renewals so far: 1) |
| heir path by hand (`spendscript`) with the period's sequence, too early | refused by the node: the input is under a relative lock not over yet |
| heir path by hand with a final sequence (no lock) | refused: does not verify under the rules in force |
| owner path signed with the heir's key | refused: does not verify |
| `inheritcancel` of a third inheritance (`CTdULfRXsA5Ljr5XTQ7hfhkReAYz5TpvRN`) | coins back to the owner by `6b3fef3445ee91060b7739deef225edd38566a654c3e50af456e67e803850a48`, state closed |
| owner's node stopped; D mines alone until `heirCanClaim` | true one period after the renewal was mined |
| `inheritclaim` #1 and #2 on D | `5b4107d08b9b4e42b59412c3be8a7c009487474ca505052e38b1cd70ed7d8349` (99.98) and `fdcec9bcd357eb41e0ddee20a15a355b6e28740a58004669754793d7c993f50a` (49.98), both mined in block `eb42379941ea3b38b1725abf4ab26a4bc2f40362ff1b2e4461c800f021ee478a`; D's balance went from 1493.3644302 to 1643.3244302, exactly 149.96 more |
| `inheritclaim` #1 a second time | refused: closed, spent by `5b4107d0…` |
| owner's node started again after the claims | its renewer logged `closed by 5b4107d0…` and `closed by fdcec9bc…` on its first pass; `inheritinfo` says state closed, with the closing transaction |
| `inheritrenew` #1 on the owner's node, too late | refused: closed, spent by `5b4107d0…` |

The renewal came a little early on the bench, because the bench chain's tip
was a day old when the miners started and median time past caught up over
the first blocks; that is BIP68 measuring time as it should, and the reason
the clock is median time past and not the coin's own timestamp.
