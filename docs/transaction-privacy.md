# How a transaction leaves your node

Every Bitflash connection runs over Tor, so no peer learns your IP address.
That is not the whole question, though. Every Bitflash node also has a
long-lived `.btf` identity, and a peer that is the first to hear a transaction
from a node it knows can say "this payment came from that node". Two payments
heard from the same node can be tied together the same way. Bitflash closes
both gaps in three layers.

## 1. Dandelion++ (the stem)

A new transaction does not go to everyone at once. It first walks a *stem*:
one peer at a time, and at each hop there is a 1 in 10 chance that the peer
*fluffs* it, announcing it to everyone the old way. A peer handed a stem
transaction cannot tell whether its neighbour wrote it or only passed it on.

- Each node picks 2 relays per 10-minute epoch, from outbound peers that said
  `stemok` after the version handshake. Inbound peers are never relays: an
  inbound peer chose us, and could have been placed there to catch what we send.
- Routes are fixed for the epoch: everything arriving from one neighbour leaves
  through the same relay, and never goes back to the neighbour it came from.
  A spy cannot learn the source by comparing routes.
- Every node that forwards a stem transaction keeps an *embargo* of 30 to 60
  seconds. If nobody has fluffed it by then (a relay dropped it, or went
  away), it fluffs it itself, so a transaction is never lost.
- Nodes from before Dandelion never say `stemok`, are never relays, and see
  nothing new on the wire.

This is the design of BIP156, as Monero runs it.

## 2. A connection and a Tor circuit for each transaction

The stem hides which node wrote a transaction from everyone *after* the first
hop. The first hop itself still sees it arrive over one of our long-lived
connections, and sees every transaction we write arrive the same way.

So, when the node runs over Tor (the default), your wallet's own transactions
do not leave over any connection the node keeps:

- A connection is opened for that transaction alone, to a peer picked at
  random from the peers the node has reached before. A peer we are not
  connected to is preferred, since one we are connected to already knows us.
- It runs on a Tor circuit of its own. The node gives Tor fresh, random SOCKS5
  credentials for it, and Tor never puts streams with different credentials
  on the same circuit (`IsolateSOCKSAuth`, on by default and in the managed
  torrc).
- On it go a version message, which every Bitflash connection starts with,
  and the transaction as a stem transaction. No descriptor, no peer list,
  nothing that names this node. Then the connection closes.
- To the peer, this is a stranger handing it a stem transaction, which is
  exactly what every stem hop looks like.
- A peer that predates Dandelion gets it as a plain `tx` and announces it.
- If the transaction spends outputs of transactions that are not confirmed
  yet, those go first on the same connection, in order, so the peer never
  sees the child before its parents. (They used to be announced straight from
  the node to every peer.)
- If no peer can be reached this way (three tries), the transaction goes into
  the ordinary stem through the node's own relays.
- If the peer it went to drops it, nobody else holds an embargo for it, and
  ours would announce it under this node's name. So when our embargo runs out
  it gets another connection of its own, to another peer, up to three rounds;
  only after that does the node announce it itself.
- The wallet offers its own unconfirmed transactions again every ten minutes,
  as Bitcoin's does. Each resend leaves at its own random moment within those
  ten minutes, so they do not go out together and tie each other to one
  wallet. Payments the wallet *received* are no longer resent at all: that
  told every peer which unconfirmed payments this node cared about.

Without Tor (plain SOCKS5 or a direct connection), credentials mean nothing to
the proxy, and the node uses the ordinary stem.

## Asking around does not find it

A spy that has a transaction can announce it (`inv`) to every node and watch
who does not ask for it: a node that already holds it would not. That would
find the stem, and its start. A node holding a transaction under an embargo
(in a stem, or on its way out on a connection of its own) asks for it like a
node that lacks it.

Hearing of it is not enough to end an embargo, either. Only the transaction
itself arriving as a plain `tx` does, and then the node passes it on. A relay
that drops a stem transaction and announces it only to the hops before it
cannot bury it that way.

A child spending an output of a transaction still under our embargo is not
passed on by us until the parent is out, since relaying it would show who
holds the parent.

## 3. A random delay

A transaction that appears on the network the instant someone clicks Send
says when they clicked. Your own transactions leave 2 to 12 seconds after the
wallet makes them, picked at random each time.

## What this does not hide

- Amounts and addresses are public on the chain, as in Bitcoin. This layer is
  about *where* a transaction came from, not *what* is in it.
- Spending outputs together still links them on the chain.
- A peer can see the time and best height in the version message, like on any
  connection. The one-shot connection sends the network-adjusted time, not
  this machine's clock, so a clock error a peer has measured on one of our
  long-lived connections does not show here.
- A stem hop keeps the transaction in its memory pool (BIP156 keeps a separate
  stem pool). Probing that pool needs a validly signed transaction spending
  the same coins or the outputs of this one, so only the payer or a payee can
  try it.

## For developers

- `src/dandelion.h`, `src/dandelion.cpp`: the router (pure, unit-tested by
  `test_dandelion`), the stem and embargo, and the one-shot connection.
- `src/proxy.cpp`: `BtfConnectSocketIsolated`, SOCKS5 with username/password
  (RFC 1929), Tor only.
- `bitflash -selftest=dandelion-oneshot` runs a mock Tor and peer in one:
  fresh credentials per connection, parents ahead of the child, `stemtx` to a
  Dandelion peer and `tx` to an older one.
- The `dandelion` log category (on by default) prints each step.
