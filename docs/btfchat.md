# btfchat — messaging that burns

*Design document, 2026-09-18. The first section says what 1.2.29 actually
ships; everything after it is the design the shipped part grows into. Status of
each phase is at the end.*

## What 1.2.29 ships

- **`btfchat`, a program of its own.** No chain, no wallet balance, no mining:
  a chat that happens to share the coin's network. Its identity is a `.btf`
  address grown from the same recovery phrase as the wallet, and its onion
  service is its own, never the node's.
- **Live messages go straight to the other person**, over Tor, to their chat
  onion, in a channel keyed by X25519 and ML-KEM together (`btfchan.cpp`) with
  a key that moves forward on every message.
- **Offline messages wait in the Bitflash nodes.** Sealed to the recipient's
  epoch keys (also X25519 + ML-KEM, rotated daily and destroyed after two
  days), filed under a tag only the two people can compute, held by every
  node running 1.2.29 or later for about a day (`chatstore.h`,
  `chatrelay.h`). If no node can take it, the message stays in the sender's
  own outbox and goes direct the moment the other side is seen online.
- **Finding someone needs no server.** A chat identity's signed descriptor
  (its onion and channel key) is held by the same nodes. The chat app reaches
  them the way a node does: the onion seeds pinned in the binary, then the
  signed peer lists every node hands out (`btfchatnet.h`). No Nostr relay, no
  VPS, nothing of ours or anybody's that has to stay up.
- **Spam costs work, not yet coin.** Every record a node stores carries about
  a second of proof of work, more for bigger ones; nodes ration each
  connection and cap the memory the chat may use. The burn stamp below is the
  real answer and has not shipped.

Not in 1.2.29, all described below: burn stamps, fixed-size envelopes, cover
traffic, ephemeral onions per conversation, the chain-anchored handshake,
money inside messages, groups.

## Known attacks on 1.2.29

Written down so nobody has to rediscover them, and so a fix can say which one
it closes. Each entry: what the attacker does, what stops it, what is left.
Numbers are from `test_chatstore` and the live runs.

**Flooding the nodes' memory with a GPU.** The work on each record is
SHA-256 at 20 bits, about 1.2 s on one laptop core, more for bigger records.
A graphics card pays that a million times over: filling the 8 MB descriptor
budget took 13,024 records in the test, seconds on a GPU. *Stops it:* a full
store **refuses** new records instead of evicting old ones, so nothing a node
already holds is erased. The sender is told at once, the message stays in
their outbox and goes direct when the other side is seen. *Left:* while the
flood lasts, and up to a day after (records expire after 26 h), new offline
messages do not get into the nodes. The per-connection ration (60 records a
minute) does not help, since Tor gives an attacker as many connections as it
wants. The fix is a stamp that costs coin (phase 1) or RandomX in place of
SHA-256.

**Many throwaway identities.** Keys are free, so somebody can publish
thousands of descriptors and epoch keys. *Stops it:* the same budget and the
same refusal; an identity already held can always replace its own record,
because the room its old one leaves is what the new one uses. *Left:* a
flood can stop **new** identities from being findable until it ages out.

**A node lying about who someone is.** It could answer a lookup with another
identity's descriptor or epoch keys and read everything sealed to them.
*Stops it:* both are signed by the identity, and both the node that stores
them and the client that receives them check the signature against the
address that was asked for. A node cannot forge one.

**Making an old descriptor win.** Rewrap a validly signed old descriptor with
a newer record time. *Stops it:* the record time must equal the signed time
inside (the descriptor's creation time, the epoch's start), so "newest" is
decided by what the owner signed.

**A node hiding what it holds.** It can answer "nothing" for a tag that has
envelopes waiting. *Stops it, partly:* every record spreads to every 1.2.29
node, the client asks two of them and merges, and a sender tries to leave
every record with two nodes (it counts as left once one has kept it). *Left:* if every node a client can reach
is the attacker's, it can withhold, though still not forge. A client starts
from the onion seeds pinned in the binary, so a dead or hostile seed slows
the first contact; after that the client knows every node the others told it
about.

**Pushing someone's envelopes out of their tag.** A tag holds at most 64
envelopes and the oldest goes first. *Stops it:* a tag is computed from the
two people's keys and changes every day; nobody else can name it, so only the
pair can fill it.

**What a node learns.** That somebody, over Tor, published or asked for a
descriptor, or wrote to or read a tag, when, and how big. Not who: the chat
never connects except through Tor, and a tag names a pair nobody can link to
addresses. The number of Tor circuits a client opens is countable by whoever
watches its connection; one circuit per two-minute round is the floor this
release keeps to.

**Inventory flood between nodes.** A peer announces thousands of record ids
it never delivers. *Stops it:* nothing new; it is the same exposure 0.1.0 has
for transactions (each asked-for id costs a little memory until it times
out). Records themselves are rationed at 6,000 a minute per peer and each
costs a signature check at most.

**Old nodes.** A 1.2.28 node never sees chat inventory, because it is offered
only to peers that advertise `NODE_CHAT`. An old node a client reaches still
hands over its peer list, which may lead to new ones.

**Clocks.** A record more than 2 h in the future is refused; a frame older
than a day is refused by the replay guard. A machine whose clock is far off
will see its records refused, and says so.

**A node restarting.** It forgets: the store is memory only, never the disk,
so a seized machine has nothing to give up. It gets the records back from its
peers when it reconnects (`getchatinv`). *Left:* a record that only one node
ever kept, lost before it spread, is gone -- which is why the sender tries two.

## What it is

A messenger inside the Bitflash wallet where the identity is a `.btf`
address, the transport is the Bitflash P2P network over Tor, and every message
**burns** a little BTF. No server, no phone number, no e-mail, no IP address
anywhere in the system — not even ours. Sending a message makes the coin
scarcer for everyone who holds it.

Why burn rather than pay the recipient: paying the recipient makes it
profitable to spam yourself, and makes the recipient a party with something
to hide. Burning benefits no one in particular and everyone a little, and the
burn transaction reveals nothing but "someone burned this much at this time".

## Threat model

Protect, in this order:

1. **Who talks to whom, and when.** End-to-end encryption is table stakes;
   every messenger has it, and every one of them still knows the graph. This
   design treats metadata as the secret.
2. **Content**, against anyone, now and after quantum computers.
3. **The past**, when a device or a key is taken later.
4. **Deniability**: a transcript proves nothing to a third party.

Not protected: an endpoint that is already compromised, and a user who
publishes their `.btf` address next to their name.

## Identity

The `.btf` address the node already generates (`btfaddr.cpp`): a public key
encoded as an address, self-certifying, nothing to register. A person is a
key. Reachability is separate from identity (below), so knowing someone's
address tells you nothing about where their node is.

## Transport

The node's existing encrypted channels between `.btf` addresses over Tor
(`btfchan.cpp`), extended with four properties:

- **Sealed sender.** The outer envelope names only the recipient's channel.
  Who sent it is inside the encrypted payload. Relaying nodes see a recipient
  and a burn stamp, nothing else.
- **Fixed size.** Every envelope on the wire is exactly 4,096 bytes, padded;
  a three-letter reply and a small image look the same. Longer messages are
  several envelopes with no visible relation between them.
- **Cover traffic.** Every participating node emits envelopes at a constant
  rate whether it has anything to say or not; real and dummy envelopes are
  indistinguishable to anyone but the recipient. An observer of the whole
  network sees a uniform hum (the Loopix/Nym idea, without the company).
- **Ephemeral onions.** Each conversation gets its own hidden service, created
  for it and discarded after. Even Tor cannot link one contact of yours to
  another; the node's main onion is never tied to chat.

Delivery to a peer that is offline is **store-and-forward by the nodes of the
network**, with the burn buying the time (next section). No mailbox server:
the same nodes that carry blocks carry envelopes.

## The burn stamp

Every envelope references a transaction with an `OP_RETURN` output — provably
unspendable, gone from the supply — of at least the network's minimum burn.
The stamp is what a node checks before it relays or stores: no valid stamp,
no relay. This is Hashcash paid in coin rather than in hashing, seventeen
years after the whitepaper cited it.

What the stamp buys, beyond relay:

- **Spam is priced out.** A fraction of a cent per message is nothing to a
  person and a fortune to a bot sending millions.
- **Your inbox has a price.** Each user sets the minimum burn required to
  reach them; approved contacts get a lower floor, strangers a higher one.
  Interrupting you costs.
- **Storage.** Nodes hold an envelope for an offline recipient for as long as
  the burn paid for, on a published price per byte-hour. Bigger burn, longer
  patience.
- **Key anchoring** (next section): the stamp of the first message in a
  conversation carries the hash of the handshake.

The minimum burn is a relay policy, not consensus: nodes agree on it the way
they agree on minimum fees, and it can move.

## Cryptography

Nothing invented. The strongest published components, combined under the
threat model above:

- **Handshake: PQXDH** — X25519 plus **ML-KEM-1024** (Kyber, NIST FIPS 203),
  hybrid, so that breaking either one alone breaks nothing. What Signal
  deployed in 2023, with the larger parameter set. Messages recorded today do
  not open on a quantum computer later.
- **Session: double ratchet** — a fresh key for every message, in both
  directions; compromise of a key opens neither the past nor the future.
- **Cipher: XChaCha20-Poly1305** from libsodium, which the node already links.
- **Authentication by MAC, not signature** (the OTR property). The recipient
  knows the message is from you; nobody can prove it to anyone else. The
  transcript is worthless as evidence.
- **Key verification against the chain.** The unsolved problem of every
  messenger is the first contact: whose key is this? Here the burn stamp of
  the first message carries `Hash(handshake public values)`. Both sides check
  the chain. An attacker in the middle would have to rewrite a block. The
  safety-number ritual becomes: look at a block. Optional QR verification
  stays for those who want it.
- **Nothing kept.** Ratchet keys are erased as they are used; nodes drop
  envelopes at their TTL; local history is encrypted under the wallet's
  passphrase and can be set to expire.

## Money is a message

An envelope may carry a transaction. "Here is 5" is a line of chat; the
payment travels inside the encrypted payload and is broadcast when the
recipient opens it, or by the sender at once, their choice. A 2-of-3 escrow
between buyer, seller and arbiter is negotiated in the conversation the three
share, with `createmultisig`/`signrawtransaction` (1.2.28) underneath. Not a
chat with payments: the wallet, talking.

## Communities

Public, many members, no secrecy of content among strangers — what is
protected is who writes and who reads. A community is a channel key; posting
to it is broadcasting an envelope to it.

- **Joining burns; posting burns.** The creator sets both prices. This is the
  only moderation that works without identities: an anonymous troll cannot
  be banned, but can be made to pay for every line.
- **Reputation without identity.** What an address has burned in a community
  is on the chain. Seniority is investment, not followers.
- **Nothing to take down.** No owner, no server, no terms of service. The
  community exists on the nodes for as long as someone burns to keep it.
- **Paid reading**, optionally: a channel may require a burn to read, and the
  author may require a payment to themselves besides. A newsletter, a leak, a
  paper, where neither writer nor readers are known.

## Groups

Private, up to about a thousand members, real secrecy. **MLS** (RFC 9420):
a key tree, membership changes rotate the key in O(log n), designed with
post-quantum in mind, the standard the large messengers have moved to. Each
group message is an envelope like any other — burn, fixed size, sealed sender;
a relaying node cannot tell a group message from a private one.

Administration is not an account: it is a **multisig key** of the founders.
Group rules change only with their signatures, and no server exists that could
remove an admin.

## Clients

One protocol, three faces:

- **The wallet window** (Windows, Linux, macOS): a `btfchat` tab beside the
  balance — contacts on the left, conversation on the right, "attach BTF"
  next to send. Installing the chat is installing the wallet.
- **RPC** for headless nodes, bots and Termux: `chatsend`, `chatlist`,
  `chatread`, `chatburn`.
- **Android**: the native app, on the ARM64 node that already runs on a phone
  (2026-09-18). No Google/Apple push — the node keeps its Tor circuit and
  receives directly.

No browser client, by design: a web page needs a server or a local one behind
it, and a browser leaks (cache, extensions, WebRTC).

## What is ours

Most of the above is assembly of proven parts. Three things exist nowhere
else and cannot be copied without rebuilding the project: the **burn
economy** (spam, inbox price, storage and scarcity from one mechanism), the
**key anchored in the chain**, and **the wallet that talks** (money inside the
envelope, escrow in the conversation). All three exist because the messenger
and the coin are the same program on a network that only speaks Tor.

## Phases

| phase | scope | depends on | status |
|---|---|---|---|
| 0 | `OP_RETURN` standard in relay policy; burn stamp format; `docs` | 1.2.28 (relay policy only, no consensus) | shipped in 1.2.28 |
| 1a | one-to-one over onion; hybrid post-quantum channel; sealed offline envelopes held by the nodes, paid in work; local outbox | 1.2.29 nodes for the offline half | **1.2.29** |
| 1 | the rest of one-to-one: fixed size, burn stamp, chain-anchored handshake, money in messages; wallet tab + RPC | rules v3 shipped | design |
| 2 | communities: channels, join/post burns, paid reading, reputation | phase 1 | design |
| 3 | cover traffic, ephemeral onions per conversation, node storage market | phase 1 | design |
| 4 | groups (MLS, multisig admins) | phase 1; OpenMLS or an equivalent integrated | design |
| 5 | Android client | the native app | design |

## Open questions

- The minimum burn, and how it moves: fixed in policy, or a median of recent
  stamps like fee estimation. Too low and spam returns; too high and nobody
  talks.
- Cover traffic costs bandwidth and, on phones, battery; the rate must be
  tunable per client, which weakens the guarantee for those who tune it down.
- Store-and-forward pricing: what a node charges per byte-hour, and how a
  sender learns it.
- ML-KEM-1024 handshakes are about 3 KB; that fits one envelope with room to
  spare, but a ratchet with post-quantum re-keying on every message does not.
  Hybrid re-keying on a schedule (Signal's approach) is the likely answer.
- Deniability and the chain anchor pull in opposite directions: the anchor
  proves a handshake happened, not who did it. Whether that is enough
  deniability is a question for the people who need it most.
