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
