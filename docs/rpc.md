# JSON-RPC

The interface an exchange, a payment processor or a block explorer integrates a
coin through. It is shaped like `bitcoind`'s — same method names, same
arguments, same result fields — so an integration written for any
Bitcoin-derived coin works here unchanged.

Bitcoin 0.1.0 had no RPC; it arrived in 0.3.x and this tree never inherited it.
Until 1.2.23 there was no way for anybody else's software to run a Bitflash
wallet: no deposit address per user, no way to notice a deposit had landed, no
way to pay a withdrawal.

## Starting it

Nothing listens unless both credentials are given:

```bash
bitflash-node -nogui -datadir=/var/lib/bitflash \
  -rpcuser=exchange -rpcpassword='a long random string, sixteen characters at least'
```

- Binds **127.0.0.1 only**. There is no option to bind wider, on purpose: the
  daemon runs on the machine that talks to it, and a wallet that spends on
  command should not be reachable from the network.
- Port `8432` on mainnet, `18432` on testnet, or `-rpcport=N`.
- Every request needs HTTP Basic credentials. A wrong password gets `401` and a
  quarter-second pause, and the comparison is constant-time.
- `-rpcpassword` shorter than sixteen characters is refused.
- `-rpcpassword=@FILE` reads the secret from a file, so it never appears in
  the process list. Prefer it on any machine other people can log into.
- `-chatwallet`, with no `-rpcuser`/`-rpcpassword`: the same server, with a
  fresh random password written to `<datadir>/.cookie` as `__cookie__:<hex>`
  (bitcoind's cookie). It is how btfchat on the same machine pays and receives
  through this wallet (`docs/btfchat.md`). Anything running as the same user
  can read the cookie and spend; off unless asked for.

## Calling it

JSON-RPC 1.0 over HTTP `POST /`. Batches (a JSON array of requests) are
accepted and answered in order.

```bash
curl -u exchange:SECRET -H 'Content-Type: application/json' \
  -d '{"id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:8432/
```

```json
{"id":1,"result":31770,"error":null}
```

Errors come back as `{"code":-1,"message":"..."}` in `error`, with `result`
null.

## Methods

| method | arguments | returns |
|---|---|---|
| `getinfo` | — | version, protocol, `blocks`, `connections`, `balance`, `testnet`, `walletlocked` |
| `getblockcount` | — | height of the best chain |
| `getblockhash` | `height` | block hash at that height |
| `getblock` | `hash` | height, confirmations, time, merkle root, `tx` (txids), prev/next hash |
| `getnewaddress` | — | a fresh receiving address, one per call |
| `validateaddress` | `address` | `isvalid`, and `ismine` when it is |
| `getbalance` | `[minconf=1]` | spendable balance, excluding immature mining rewards |
| `sendtoaddress` | `address`, `amount` | txid of the transaction it created and broadcast |
| `gettransaction` | `txid` | amount, confirmations, block, `details` per output, `bip125-replaceable` |
| `createinvoice` | `amount`, [`description`], [`expirysecs`], [`orderid`] | an invoice for the shop's own gateway: fresh address, payment link, QR as SVG -- `docs/invoices.md` |
| `getinvoice` | `id` | its status (`waiting`, `partial`, `seen`, `paid`, `expired`, `cancelled`) and what arrived |
| `listinvoices` | [`status`] | all invoices, or those in one status |
| `cancelinvoice` | `id` | stop expecting it |
| `estimatefee` | -- | `feeRatePerKB` (BTF per 1000 bytes) to be in the next block, from what is waiting now; 0 when everything waiting fits and the minimum is enough |
| `settxfee` | `ratePerKB` | the rate this wallet pays per 1000 bytes; 0 is the minimum |
| `bumpfee` | `txid`, [`ratePerKB`] | speeds up a payment of ours still waiting: the same payment, a higher fee from its change (BIP125); `txid` of the replacement, `oldFee`, `newFee` |
| `listtransactions` | `[count=10]` | the last `count` wallet transactions, oldest first |
| `listsinceblock` | `[blockhash]` | every wallet transaction in blocks after that one, plus unconfirmed, and `lastblock` |
| `gettorinfo` | — | `transport` (`direct`, `user`, or a bundled rung such as `snowflake`), Tor's `bootstrap` percent and `bootstrapline`, the `ladder` of bundled rungs, `userbridges` count and file, `lastworking`, `connections` |
| `settorbridges` | `["line", ...]` \| `"now"` \| `"forget"` | lines: save to `bridges.txt` and switch Tor to them now; `now`: climb to the next bundled rung right away; `forget`: next start tries direct Tor first again |
| `gettreasuryinfo` | — | `configured`, `network`, `page`; when configured: `required`, `keys`, the `script` decoded, `howToPay`, this node's `treasuryShare` and `poolFeeTo` |
| `donate` | `amount` | txid of a transaction paying the treasury; the same as `sendtoaddress treasury <amount>` |
| `sendburn` | `amount`, `datahex` | txid of a transaction burning `amount` into an OP_RETURN carrying the data (1 to 80 bytes): a public community listing, for one |
| `swapinitiate` | `address`, `amount` | starts an atomic swap: contract, its address and txid, the **secret**, its hash, the lock -- `docs/atomic-swaps.md` |
| `swapparticipate` | `address`, `amount`, `secrethash` | the other half: contract under someone else's secret hash |
| `swapauditcontract` | `contract`, `txid` | the terms of a contract and whether it pays this wallet |
| `swapredeem` | `contract`, `txid`, `secret` | takes the coins with the secret |
| `swaprefund` | `contract`, `txid` | takes them back after the lock |
| `swapextractsecret` | `txid` \| `rawhex`, `secrethash` | the secret, from a redeem on this chain or on Bitcoin's |
| `swapfindsecret` | `contract`, `txid` | whether a contract of ours was spent, and the secret if the spend showed it |
| `btcswapinfo` | -- | the Bitcoin Core this wallet swaps against (`-btcchain`, `-btcdatadir`...): chain, height, balance, fee rate |
| `btcnewaddress` | -- | a Bitcoin address whose key is in THIS wallet, to be paid BTC to in a swap |
| `btcinitiate` | `address`, `amount` | starts a swap on Bitcoin: Core funds the contract; the keys and the secret are this wallet's |
| `btcparticipate` | `address`, `amount`, `secrethash` | the other half, on Bitcoin |
| `btcauditcontract` | `contract`, `rawhex` \| `txid` \| `txid:vout` | a Bitcoin contract as this machine's Core sees it: unspent, confirmations, amount, whether it pays us |
| `btcredeem` | `contract`, ref, `secret` | takes the BTC into a fresh address of Core's wallet |
| `btcrefund` | `contract`, ref | takes it back after the lock |
| `btcfindsecret` | `contract`, ref, [`fromheight`] | whether a Bitcoin contract was spent, and the secret |
| `templatehash` | `{address: amount}`, [`version`=2], [`sequence`], [`locktime`=0] | the hash `OP_CHECKTEMPLATEVERIFY` compares with, for a one-input transaction with these outputs (rules v4, `docs/rules-v4.md`) |
| `spendscript` | `redeemhex`, `txid`, `[items]`, `{address: amount}`, [`version`=2], [`sequence`], [`locktime`=0], [`maxfee`=1] | spends the P2SH output of `txid` paying that redeem script; `items` go on the stack below it, bottom first: hex data, `true`, `false`, or `"sig:<pubkey>"` for a signature by a key this wallet holds; what the outputs leave over is the fee, refused over `maxfee`; outputs go in address order, the same order `templatehash` uses |
| `vaultcreate` | `amount`, `delay` (blocks, 1-65535), [`recoveryaddress`], [`fee`=0.01] | locks `amount` in a vault (rules v4): it can leave only by one transaction fixed now, to an unvault output; from there the hot key (a fresh key of this wallet) can take it `delay` blocks later and the recovery key at once. Without `recoveryaddress` the recovery key is a fresh key of this wallet too, and the result warns. `fee` is what the unvault prepays. Refused while rules v4 are not in force. Returns both addresses and both redeem scripts |
| `vaultunvault` | `vaultaddress` | broadcasts the one way out of the vault; no key is needed, and anybody holding the redeem script could |
| `vaultwithdraw` | `vaultaddress`, `toaddress`, [`fee`=0.01] | the hot key takes the unvault output, once `delay` blocks have passed since the unvault confirmed |
| `vaultrecover` | `vaultaddress`, `toaddress`, [`fee`=0.01] | the recovery key takes the unvault output, at once; if that key is not in this wallet, says how to sign it elsewhere with `spendscript` |
| `ctvbatch` | `{address: amount}`, [`fee`=0.01] | one output now, which unfolds later into exactly these payments (rules v4); the fee of the unfolding is paid now. Refused while rules v4 are not in force |
| `ctvexpand` | `batchaddress` | broadcasts the payments a batch fixed; no key is needed |
| `listv4contracts` | | the vaults, batches and inheritances this wallet made or imports, as kept in `v4contracts.json` beside the wallet |
| `inheritcreate` | `amount`, `heiraddress`, `days`, [`renewalfee`=0.01] | locks `amount` so the owner (a fresh key of this wallet) can spend it at any time and the heir only once it has sat untouched for `days` (rules v4; `docs/inheritance.md`). The wallet renews it by itself. `days` is 30 to 388 on mainnet; on testnet any length down to one 512-second unit. `heiraddress` must be an ordinary address. Returns the address, the script and the `heirPackage` to hand over |
| `inheritinfo` | `address` | where an inheritance stands: active or closed, renewals so far, the output holding it, when it opens to the heir (`heirOpensIn`, `heirCanClaim`), and for the owner when the next renewal is due |
| `inheritrenew` | `address`, [`fee`] | renews now (what the wallet does by itself once half the period has gone); if the last renewal is not mined yet, broadcasts it again |
| `inheritcancel` | `address`, `toaddress`, [`fee`=0.01] | the owner takes the coins out; the inheritance is closed |
| `inheritpackage` | `address` | the package for the heir: script, first transaction, heir address, period, network. No key is in it |
| `inheritimport` | `package` (JSON object or string) | in the heir's wallet; refused unless the script is an inheritance script byte for byte and this wallet holds the heir key. Everything is read from the script, not from what the package says about it |
| `inheritclaim` | `address`, `toaddress`, [`fee`=0.01] | the heir takes the coins, once the period has passed since the last renewal; before that, says how long is left |

`amount` and `balance` are BTF as JSON numbers. `sendtoaddress` accepts the
amount as a number or as a string. The word `treasury` stands for the
treasury's multisig script wherever an address is taken (`sendtoaddress`,
`createrawtransaction` outputs); `docs/treasury.md`.

**Unconfirmed payments can change their txid.** From 1.2.29 the wallet sends
replaceable (BIP125) so a payment can be sped up, and the same holds for a
deposit someone makes to you: until it is in a block, its sender may replace
it with one paying more -- or paying somebody else. Credit deposits on
confirmations, never on the memory pool, and match a deposit by address and
amount rather than by the txid first seen. `gettransaction` says
`bip125-replaceable: yes` while that is possible.

## The loop an exchange runs

1. `getnewaddress` once per user, stored against the account.
2. `listsinceblock <last seen block>` on a timer. Credit each `receive` entry
   once `confirmations` reaches the number you trust; store the returned
   `lastblock` and pass it next time.
3. `sendtoaddress` for withdrawals; keep the txid and confirm it with
   `gettransaction`.

`details[].category` tells the kinds apart: `receive`, `send`, and for mining
rewards `immature` until they can be spent and `generate` after. An exchange
should not credit `immature`.

Change is never listed. In a transaction this wallet funded, its own outputs
are change, not receipts, and they do not appear under `receive` -- so summing
the `receive` entries to credit deposits is safe. The transaction's `amount` is
still the wallet's net, change included.

Addresses from `getnewaddress` come from the HD key pool and are covered by the
wallet's recovery phrase. A wallet restored from its phrase gets every deposit
address it ever handed out.

## Confirmations to trust

Blocks arrive every two minutes and the retarget is every thirty, so the chain
reacts fast to hashrate arriving or leaving. Ten confirmations is twenty
minutes; that is a reasonable floor for a young network. Coinbase maturity is
120 blocks.

## What it does not do

No `walletpassphrase` — if the wallet is encrypted, start the node with the
passphrase and the RPC spends from the unlocked wallet. No `listunspent`, no raw
transaction building, no `importprivkey`. Those can be added when somebody
needs them; the set above is what every exchange integration actually calls.
