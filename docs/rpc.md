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
| `getbalance` | `[minconf=1]` | spendable balance, excluding immature mining rewards. With `minconf` 1 (the default) a payment from somebody else counts once it is in a block; this wallet's own change counts at once. `minconf` 0 counts everything not yet spent |
| `getwalletinfo` | — | `balance` (same as `getbalance`), `unconfirmed_balance` (what `minconf` 0 adds), `immature_balance` (mining rewards not yet spendable), `txcount` (wallet transactions, the full set `listtransactions` can return), `keypoolsize`, `encrypted`, `locked`, `hdseed` (whether a recovery phrase is installed, never the phrase), `backend` (`bdb` or `sqlite`) |
| `walletlock` | — | locks an encrypted wallet now: the master key and the decrypted seed leave memory. Spending, new addresses and mining stop until the node is started again with `/walletpassphrase`. Refused while this node mines or runs a pool, or renews an inheritance by itself, all of which need wallet keys; the same applies to `/walletunlocktimeout` when it runs out (it then leaves the wallet unlocked and says so in debug.log) |
| `sendtoaddress` | `address`, `amount` | txid of the transaction it created and broadcast |
| `gettransaction` | `txid` | amount, confirmations, block, `details` per output, `bip125-replaceable` |
| `createinvoice` | `amount`, [`description`], [`expirysecs`], [`orderid`] | an invoice for the shop's own gateway: fresh address, payment link, QR as SVG -- `docs/invoices.md` |
| `getinvoice` | `id` | its status (`waiting`, `partial`, `seen`, `paid`, `expired`, `cancelled`) and what arrived |
| `listinvoices` | [`status`] | all invoices, or those in one status |
| `cancelinvoice` | `id` | stop expecting it |
| `estimatefee` | -- | `feeRatePerKB` (BTF per 1000 bytes) to be in the next block, from what is waiting now; 0 when everything waiting fits and the minimum is enough |
| `settxfee` | `ratePerKB` | the rate this wallet pays per 1000 bytes; 0 is the minimum |
| `bumpfee` | `txid`, [`ratePerKB`] | speeds up a payment of ours still waiting: the same payment, a higher fee from its change (BIP125); `txid` of the replacement, `oldFee`, `newFee` |
| `listtransactions` | `[count=10]` | the last `count` wallet transactions, oldest first; to export them to a spreadsheet see [Examples](#examples) |
| `listsinceblock` | `[blockhash]` | every wallet transaction in blocks after that one, plus unconfirmed, and `lastblock` |
| `gettorinfo` | — | `transport` (`direct`, `user`, or a bundled rung such as `snowflake`), `transports` (sorted kinds in the bridge lines Tor has now, e.g. `["obfs4"]`; `[]` without bridges; `null` plus `transportsnote` with an external Tor), Tor's `bootstrap` percent and `bootstrapline`, the `ladder` of bundled rungs, `userbridges` count and file, `lastworking`, `connections` |
| `settorbridges` | `["line", ...]` \| `"now"` \| `"forget"` | lines: save to `bridges.txt` and switch Tor to them now; `now`: climb to the next bundled rung right away; `forget`: next start tries direct Tor first again |
| `gettreasuryinfo` | — | `configured`, `network`, `page`; when configured: `required`, `keys`, the `script` decoded, `howToPay`, this node's `treasuryShare` and `poolFeeTo` |
| `donate` | `amount` | txid of a transaction paying the treasury; the same as `sendtoaddress treasury <amount>` |
| `sendburn` | `amount`, `datahex` | txid of a transaction burning `amount` into an OP_RETURN carrying the data (1 to 80 bytes): a public community listing, for one. `poolcreate everpool` sends through the same path |
| `swapinitiate` | `address`, `amount`, [`lockseconds` (testnet) \| null], [`tag`] | starts an atomic swap: contract, its address and txid, the **secret**, its hash, the lock (a time, 48 h on) -- written to `swaps.log` before it is paid; asked again under the same tag, the same lock -- `docs/atomic-swaps.md` |
| `swapparticipate` | `address`, `amount`, `secrethash`, [`lockseconds` \| null], [`tag`] | the other half: contract under someone else's secret hash (18 h) |
| `swaplookup` | `tag` | what `swaps.log` knows of the lock named `tag` on any chain: `none`, `intent`, `failed`, `unpaid`, `funded` or `made` |
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
| `coinswapinfo`, `coinnewaddress`, `coinvalidatedestination`, `coininitiate`, `coinparticipate`, `coinauditcontract`, `coinredeem`, `coinrefund`, `coinfindsecret` | `chain`, then what the `btc` call of the same name takes | the same calls on any chain the wallet swaps with: `chain` is `btc`, `ltc`, `doge`, `bch`, `xec`, `dgb` or `rvn` (`coininitiate ltc address amount`). Each goes to that chain's own node when one is configured (`-ltcrpcport`...), else to the embedded light client; `docs/atomic-swaps.md` |
| `templatehash` | `{address: amount}`, [`version`=2], [`sequence`], [`locktime`=0] | the hash `OP_CHECKTEMPLATEVERIFY` compares with, for a one-input transaction with these outputs (rules v4, `docs/rules-v4.md`) |
| `spendscript` | `redeemhex`, `txid`, `[items]`, `{address: amount}`, [`version`=2], [`sequence`], [`locktime`=0], [`maxfee`=1] | spends the P2SH output of `txid` paying that redeem script; `items` go on the stack below it, bottom first: hex data, `true`, `false`, or `"sig:<pubkey>"` for a signature by a key this wallet holds; what the outputs leave over is the fee, refused over `maxfee`; outputs go in address order, the same order `templatehash` uses |
| `vaultcreate` | `amount`, `delay` (blocks, 1-65535), [`recoveryaddress`], [`fee`=0.01] | locks `amount` in a vault (rules v4): it can leave only by one transaction fixed now, to an unvault output; from there the hot key (a fresh key of this wallet) can take it `delay` blocks later and the recovery key at once. Without `recoveryaddress` the recovery key is a fresh key of this wallet too, and the result warns. `fee` is what the unvault prepays. Refused while rules v4 are not in force. Refused, before any coin moves, when the unvault transaction would pay less than miners ask of its size. Returns both addresses and both redeem scripts. Send nothing else to `vaultAddress`: the vault releases exactly one deposit, and any other coin sent there is locked for good or lost to fees (`depositWarning` in the result) |
| `vaultunvault` | `vaultaddress` | broadcasts the one way out of the vault; no key is needed, and anybody holding the redeem script could. If somebody already did, says so (`unvaultedElsewhere`) and gives its txid |
| `vaultwithdraw` | `vaultaddress`, `toaddress`, [`fee`=0.01] | the hot key takes the unvault output, once `delay` blocks have passed since the unvault confirmed |
| `vaultrecover` | `vaultaddress`, `toaddress`, [`fee`=0.01] | the recovery key takes the unvault output, at once, whoever broadcast the unvault (a thief holding the hot key, say); if that key is not in this wallet, says how to sign it elsewhere with `spendscript` |
| `ctvbatch` | `{address: amount}`, [`fee`=0.01] | one output now, which unfolds later into exactly these payments (rules v4); the fee of the unfolding is paid now and fixed. Refused while rules v4 are not in force, and refused before any coin moves when the unfolding would be larger than nodes relay or pay less than miners ask of its size. Send nothing else to `batchAddress` (`depositWarning`) |
| `ctvexpand` | `batchaddress` | broadcasts the payments a batch fixed; no key is needed |
| `listv4contracts` | | the vaults, batches and inheritances this wallet made or imports, as kept in `v4contracts.json` beside the wallet (the version before the last change is `v4contracts.json.bak`; if a save fails after coins were locked, the call's answer carries `saveError` and is the only copy of the script) |
| `inheritcreate` | `amount`, `heiraddress`, `days`, [`renewalfee`=0.01] | locks `amount` so the owner (a fresh key of this wallet) can spend it at any time and the heir only once it has sat untouched for `days` (rules v4; `docs/inheritance.md`). The wallet renews it by itself. `days` is 30 to 388 on mainnet; on testnet any length down to one 512-second unit. `heiraddress` must be an ordinary address. Returns the address, the script and the `heirPackage` to hand over |
| `inheritinfo` | `address` | where an inheritance stands: active or closed, renewals so far, the output holding it, when it opens to the heir (`heirOpensIn`, `heirCanClaim`), and for the owner when the next renewal is due |
| `inheritrenew` | `address`, [`fee`] | renews now (what the wallet does by itself once half the period has gone); if the last renewal is not mined yet, broadcasts it again |
| `inheritcancel` | `address`, `toaddress`, [`fee`=0.01] | the owner takes the coins out; the inheritance is closed |
| `inheritpackage` | `address` | the package for the heir: script, first transaction, heir address, period, network. No key is in it |
| `inheritimport` | `package` (JSON object or string) | in the heir's wallet; refused unless the script is an inheritance script byte for byte and this wallet holds the heir key. Everything is read from the script, not from what the package says about it |
| `inheritclaim` | `address`, `toaddress`, [`fee`=0.01] | the heir takes the coins, once the period has passed since the last renewal; before that, says how long is left |
| `poolcreate` | `"local"`, `{"name", "spacing", "window", "retarget", "floor", "uncledepth", "unclepct", "feebps", "feeaddress"}`, [`password`] | a local pool (P2Pool local, `docs/pool-registry.md` section 18): a private pool of your own machines, nothing on the chain. The name is required; the rest default to window 2160, retarget 720, floor `0x1f0fffff`, uncle depth 3, uncle share 80, no fee, and a spacing of 30 or `ceil(60 / depth)`, whichever is larger. Returns `name`, `code` (the pool code to hand the other members), `mine` (the option that mines it) and `note`. With no mode it is refused, so nothing is ever burned by default |
| `poolcreate` | `"everpool"`, `{"name", "spacing", "window", "retarget", "floor", "uncledepth", "unclepct", "feebps", "feeaddress"}`, [`"send"` \| `"dryrun"` \| `"publishzero"`] | an Everpool pool: its record (`docs/pool-registry.md` section 1) burned on the chain. Same parameters and defaults as `local`. Every rule of section 1 is checked first: a record that breaks one is refused with the rule. Without `"send"` (or with `"dryrun"`) nothing is sent: it returns `id`, `fingerprint`, `fee` (`bps`, `percent`, `address`), `rules`, `burn` (1 BTF), `record` (hex), `poolzero`, `samename` (other pools named alike, as in `poollist`, with `note` when there are any), `index` (`height`, `synced`, `rebuilding`) and `recorded` (status, first height, appearances and claims if the pool is already on the chain, else null). With `"send"` it burns 1 BTF into the record through the same wallet path as `sendburn` and adds `txid` and `status` (pending until the burn has 30 confirmations). `"send"` is refused when the pool is already recorded (burning it again changes nothing), when the same burn (at least 1 BTF into the same record) is already waiting to be mined or sits unconfirmed in this wallet, while the node is still catching up with the network, and while the pool index has not read up to the tip; these checks and the send hold the chain lock together, so no block lands between them. A fourth parameter is refused. A send that fails says why (the wallet's balance, the memory pool's refusal). Pool zero's own record is refused with `"send"`; `"publishzero"` burns it, once, to publish pool zero's rules on the chain (section 4). On mainnet `"send"` and `"publishzero"` are refused in this release, since registered pools cannot yet be carried or mined there (they open in a later release); the preview works on both networks and testnet is unchanged |
| `pooljoin` | `code`, [`password`] | joins the local pool of that code (and password, if it has one); returns `name`, `mine` and `note`. A mistyped password joins another, empty pool: `poolleave` it and join again |
| `poolpeers` | `"local:NAME"`, [`["ADDRESS@HOST.onion[:PORT]", ...]`] | with a list (at most 16), the member nodes this one dials and says hello to; with none, each listed peer and its state (`in session`, `connected, no proof`, `not connected`, ...) and the sessions in all. Either way `self` is this node as the other members list it (`ADDRESS@HOST.onion:PORT`), null until Tor has published the onion |
| `poolleave` | `"local:NAME"` | forgets the local pool and deletes its files; refused while this node mines it |
| `poollist` | -- | an object: `index` (the registry index's `height`, `synced`: at this node's tip, and `rebuilding`: reading the chain again from genesis), `note` (names are not unique: a pool is its id, age, fee and work) and `pools`. `pools` is pool zero first (its share chain, and from the registry index its `status`, `firstheight`, `appearances` and `claims`), then every pool recorded on the chain, pending or active, the pools this node carries first (by the work of their share chain's tip line over the last window), then the rest by claims in the last 720 blocks and then by first appearance: `name`, `id`, `fingerprint` (the first 8 hex digits of the id, never shown without it), `samename`, `feebps`, `rules` (one line), `status` (`pending` or `active`), `firstheight`, `confirmations`, `appearances`, `claims`, `carried` (its shares taken, relayed and served here); for a pool this node mines (`-p2pool=<pool id>`) or carries (`-poolcarry`) also `mined`, `poolcarry` and `sharechain` (`state`: nothing yet, fetching its line, catching up or complete; `announced`, `shares`, `height`, `work`, `announcers`: peers whose `poolinv` names it, `serves`: paced serves of it in flight); then this node's local pools (`"local": true`), with sessions, shares and tip height. `samename`, on pool zero and every recorded pool, lists the other pools whose names are the same once case, `-` and `_` are set aside (`id`, `fingerprint`, `poolzero`): a pool called "Bit-Flash" lists pool zero ("bitflash"), and pool zero lists it. An id that blocks name but nobody burned is not a pool and is not listed |
| `poolinfo` | `"local:NAME"` \| pool id | one pool: its rules, and for a local pool its code, sessions and listed peers. For a recorded pool: `rules`, `record`, `status`, `firstappearance` (height, block, txid, output, burn), `appearancelist`, `lastanchors` (newest first, at most 64), `claims`, `samename`, `carried`, `guarded` and `sharechain` and `note` (as in `poollist`), `index` (the index's height, whether it is at this node's tip, whether it is rebuilding) and `guardians` (docs/pool-registry.md section 10: `enabled`, false where tickets are off; the epoch, whether its draw is settled, the tickets held for it, `list` of the pool's 16 in this node's view with each one's `btf`, `place`, `role` guardian or reserve, `capacitymb` and `self`; `draws`, one entry for each draw in force (the previous epoch's while its guardians linger, this epoch's, and the next one's once settled) with its `epoch`, `settled`, `until`, `tickets`, `list` and this node's `ownplace` in it or null; and `thisnode`: its best `place` over those draws, what it does with the pool and the latest `until` among them, so its place may be in another epoch's draw than `list`). Guardians are availability: nothing in the list decides a share or a payout. Pool zero's id shows its rules, claims, `samename` and `note`. For an id nobody burned that blocks name: `status` `unknown`, its `claims` and `lastanchors` only |
| `poolprobe` | pool id | asks every connected peer that announced the registered pool for this node's tip share (`p2xgetsh`): `share` (its id), `asked` (the peers, by the start of their `.btf` address), `logged` (whether `-sharetimelog` is on, so the ask and each answer are in `sharetime.log` for the round trip, docs/pool-registry.md section 17). The answer is a share already held: taken for nothing, nobody scored. An error when the pool is not carried here or nothing of it is held |

**Claims are not proof.** `claims` counts the main-chain blocks of the last
720 whose coinbase names the pool (section 7 of `docs/pool-registry.md`).
Anybody can name any id in a block they mine, so a claim says somebody
pointed a block at the pool, not that the pool's miners found it.

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

## Examples
### `listtransactions` - Export transactions to CSV
This example uses the `listtransactions` RPC call to save all wallet transactions to a `.json` file, then [jq](https://jqlang.org/) to turn it into a CSV file that any spreadsheet tool, such as [LibreOffice](https://www.libreoffice.org/), can open.

First save the transactions to a file, with the RPC credentials the node was started with (port 18432 on testnet). A count of 1000000 is more than any wallet holds, so it returns them all:
```bash
curl -s -u USER:PASSWORD -H 'Content-Type: application/json' \
  -d '{"id":1,"method":"listtransactions","params":[1000000]}' \
  http://127.0.0.1:8432/ > <filename>.json
```
*Replace `<filename>` to what you want it called.*

Then we use `jq` to convert the JSON to CSV formatted file and at the same time convert UNIX timestamps to ISO dates (UTC time)
```bash
  jq -r '
    def to_iso: if . == null then null else (. | todateiso8601) end;
    [
    "txid",
    "category",
    "address",
    "detail_amount",
    "vout",
    "tx_amount",
    "confirmations",
    "blockindex",
    "blockhash",
    "blocktime_iso",
    "time_iso",
    "timereceived_iso",
    "generated",
    "bip125_replaceable"
    ] as $cols |
    $cols,
    (
    .result[] as $tx |
    (if ($tx.details | length) > 0 then $tx.details else [{}] end)[] as $d |
    [
      $tx.txid,
      $d.category,
      $d.address,
      $d.amount,
      $d.vout,
      $tx.amount,
      $tx.confirmations,
      $tx.blockindex,
      $tx.blockhash,
      ($tx.blocktime | to_iso),
      ($tx.time | to_iso),
      ($tx.timereceived | to_iso),
      ($tx.generated // false),
      $tx["bip125-replaceable"]
    ]
      ) |
      @csv
      ' <filename>.json > <filename>.csv
```
*Replace `<filename>` to what you want it called.*

Each row is one entry of `details`, so a transaction with several outputs gives several rows that repeat its `tx_amount`: add up `detail_amount`, not `tx_amount`. For a payment you sent, `tx_amount` minus the sum of its `detail_amount` rows is the fee (negative). A payment between two addresses of the same wallet has one row with an empty category, and its `tx_amount` is just the fee.

## Local pools and their password

`poolcreate local` and `pooljoin` take the pool's password, if it has one, as
their last parameter. It travels in the request body to 127.0.0.1 and nowhere
else, and it must never be on a command line, where the process list and the
shell history keep it: read it from a prompt and send the body on stdin.

The RPC credential stays off the command line too: keep it in a netrc file
only you can read, `~/.bitflash-rpc.netrc` (mode 600), holding the one line
`machine 127.0.0.1 login exchange password SECRET`, and point curl at it.

```bash
read -rs -p 'Pool password: ' PW; echo
printf '{"id":1,"method":"pooljoin","params":["btfl1:...","%s"]}' "$PW" |
  curl -s --netrc-file ~/.bitflash-rpc.netrc -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8432/
unset PW
```

(`printf` is a shell builtin, so the password is in no process's arguments,
and curl reads the RPC credential from the file, so it is in none either.
A password with a `"` or a backslash in it has to be escaped for JSON.)
The node stretches it with Argon2id (64 MiB) into the pool's key, keeps that
key in `pools/local/<id>.conf` (owner-only) and never the password. No answer,
error or log line holds the password, the key or the pool's id; the pool is
named by its name everywhere (`-p2pool=local:NAME`, `poolinfo local:NAME`).

Once a call is answered, the node overwrites the copies of the request it
can reach: the bytes received, the headers and the decoded credential, the
body, and every string of the parsed request and of the call's parameters.
Some copies it cannot reach and does not overwrite: the JSON parser's own
token buffer, and the old buffers left behind when the received request
grew. Treat the password as possibly present in the node's memory until the
process ends; the node itself never writes it to a file.

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
passphrase (`/walletpassphrase`, from stdin or `@FILE`) and the RPC spends from
the unlocked wallet; `/walletunlocktimeout=SECS` locks it again by itself after
that many seconds, and `walletlock` locks it at once. The passphrase never
travels over RPC. No `listunspent`, no raw
transaction building, no `importprivkey`. Those can be added when somebody
needs them; the set above is what every exchange integration actually calls.
