# Invoices: a payment gateway that is only your own node

Take BTF in a shop, an app or a site with nothing in between: no gateway
company, no account, no server of ours. Your node makes an invoice — an
amount, what it is for, how long it stays open — and gives you a fresh
address of **your** wallet, the payment link to copy and paste, and its QR
code as SVG for your checkout page. It watches your wallet for the payment
and tells your system when the invoice changes. The money lands in your
wallet; the only thing that knows about the sale is your node.

## Turning it on

The invoice calls are part of the node's JSON-RPC (127.0.0.1 only):

```
bitflash -nogui -rpcuser=shop -rpcpassword=@/path/to/password \
  -invoicewebhook=http://127.0.0.1:8080/bitflash/webhook \
  -invoicewebhooksecret=SOME-LONG-RANDOM-STRING \
  -invoiceminconf=2
```

| flag | |
|---|---|
| `-invoicewebhook=URL` | POST every status change to `http://host[:port]/path`. Your shop's own machine (loopback is reached directly, anything else the way the node reaches everything — through Tor when it runs with it). `https` is not spoken: put the node next to the shop. |
| `-invoicewebhooksecret=S` | sign each POST: header `X-Bitflash-Signature: sha256=<HMAC-SHA256(S, body)>` |
| `-invoicenotify=CMD` | also run `CMD` on each change, `%s` replaced by the invoice id (32 hex characters) |
| `-invoiceminconf=N` | confirmations before an invoice is `paid`; default 2 on mainnet (about 4 minutes), 1 on testnet |

A webhook that fails is tried again, backing off, for about a day.
Invoices are kept in `invoices.json` in the data directory.

## The calls

| call | does |
|---|---|
| `createinvoice amount [description] [expiry seconds=3600] [order id]` | a new invoice: `id`, `address`, `link`/`copyPaste` (`bitflash:...?amount=...`), `qrSvg`, `expires`, `status` |
| `getinvoice id` | where it stands (below), with `received`, `receivedConfirmed`, `overpaid`, `confirmations` and each payment's `txid` |
| `listinvoices [status]` | all of them, or those in one status |
| `cancelinvoice id` | stop expecting it |

## Status

| status | means | what to show |
|---|---|---|
| `waiting` | nothing has arrived | the QR and the link |
| `partial` | some of it has, less than the amount | "x of y received" |
| `seen` | the whole amount, not yet confirmed enough | "payment received, confirming…" |
| `paid` | the whole amount with the confirmations asked for | **done: deliver** |
| `expired` | the time ran out first (a late payment is still received and reported) | "this invoice expired" |
| `cancelled` | you cancelled it | |

**Only `paid` is money.** Until a payment is in blocks, the payer can replace
it with one paying somebody else (BIP125 — the wallet sends replaceable so a
stuck payment can be sped up) or simply double-spend it. `seen` is for the
customer's screen; shipping waits for `paid`.

## The webhook

Each POST is `{"event":"invoice","invoice":{...}}` — the same object
`getinvoice` returns. Check the signature before you believe it:

```python
import hashlib, hmac
def genuine(body: bytes, header: str, secret: bytes) -> bool:
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

```php
$ok = hash_equals('sha256=' . hash_hmac('sha256', $body, $secret), $_SERVER['HTTP_X_BITFLASH_SIGNATURE']);
```

```js
const ok = crypto.timingSafeEqual(
  Buffer.from('sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex')),
  Buffer.from(req.headers['x-bitflash-signature']));
```

Answer with any `2xx`. The same status can arrive twice (a retry after a
lost answer): handle each `(id, status)` once. A `paid` invoice is also sent
again as its confirmations grow, up to six.

## A checkout, start to end

1. The customer clicks "pay with BTF". Your backend calls
   `createinvoice 25 "Order 1041" 1800 1041`.
2. The page shows `qrSvg` and `copyPaste` (a "copy" button), the amount and
   the time left.
3. The customer scans it with their phone, or pastes the link into their
   Bitflash wallet's Send.
4. Your webhook hears `seen`: the page says "received, confirming".
5. It hears `paid`: the order is paid.

Nothing in this asks the customer for anything but a wallet, and nothing
outside your machine sees the order.

## Prices in another currency

The amount is in BTF. Pricing in reais or dollars needs an exchange rate,
which needs a market; until BTF has one, set prices in BTF.

Checked by `-selftest=invoice` (the status rule, the signature, URLs, the QR,
an invoice's life in a wallet of its own) and on testnet with coins: paid in
one go, in two parts, and expired, every webhook signature checked.
