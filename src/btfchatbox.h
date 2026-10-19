// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat mailbox -- leaving a message for somebody who is not there.
//
// The live channel needs both sides online. This is the other case, and it is
// the uncomfortable one: the message has to rest somewhere that is not ours,
// where whoever runs that somewhere can count it, time it and keep it forever.
// Encryption handles the contents. What follows is about everything else.
//
// WHERE IT RESTS. Not under the recipient's `.btf`. Posting to an address is
// handing the relay a social graph: it would learn who writes to whom and how
// often, and it would learn it about everyone at once, which is worth more than
// any single message in it. Instead, each pair of people shares a TAG that only
// the two of them can compute -- keyed by the X25519 secret their two static
// chat keys agree on -- and that tag changes every epoch. The relay sees random
// 16-byte names appearing and disappearing. It cannot map a tag to a person, and
// it cannot tell that today's tag and tomorrow's belong to the same pair.
//
// The tag is the same in both directions on purpose. Both parties post under it
// and both poll it, so the relay cannot even tell which of the two is writing
// and which is reading. Each side can only open what was sealed to it, so your
// own envelopes simply fail to open and are skipped.
//
// WHAT IT DOES NOT HIDE. A relay still sees that a tag was written to, when, and
// how big. Someone watching one tag learns that two people it cannot name
// exchanged something. Someone watching the whole relay learns the shape of the
// traffic. That is the price of not requiring both people online at the same
// moment, and no amount of cryptography removes it -- only not using a relay
// does. This is written down here so nobody has to rediscover it later.
//
// FORWARD SECRECY, HONESTLY. The epoch keys are RANDOM and kept, never derived
// from the recovery phrase. That is deliberate and it is the whole mechanism: a
// key that can be re-derived can never be destroyed, so deriving them would make
// every envelope ever posted openable forever by whoever eventually gets the
// twelve words. Because they are random, Forget() actually ends them, and an
// envelope from an expired epoch is unreadable by everyone, the recipient
// included. The cost is that epoch secrets live in the sealed store and do not
// survive a restore from the phrase alone -- messages waiting for a machine that
// died are lost. That is the right trade for a chat and the wrong one for a
// wallet, which is why the wallet does the opposite.
//
// AND THE KEYS ARE SIGNED. The published epoch keys carry a signature from the
// chat identity. Without it a relay would simply answer a lookup with its own
// epoch keys, read everything sent to that person, and reseal it onward -- a
// complete man in the middle on every offline message, needing no key theft at
// all.

#ifndef BITFLASH_BTFCHATBOX_H
#define BITFLASH_BTFCHATBOX_H

#include "btfchat.h"
#include "btfchan.h"

#include <map>
#include <string>
#include <vector>
#include <stdint.h>

namespace btfchat
{

// One epoch, one set of mailbox keys. A day is long enough that rotating is not
// chatter on the relays, and short enough that what an old stolen key opens is
// one day of envelopes that were already delivered.
static const int64_t MAILBOX_EPOCH_SECONDS = 24 * 60 * 60;

// Epochs whose secrets are kept: the current one and the one before it, so a
// message posted at 23:59 still opens at 00:01. Older than that is destroyed.
static const size_t MAILBOX_KEEP_EPOCHS = 2;

// Tag length. 16 bytes is 128 bits of name space: no two pairs collide, and it
// carries no structure to recognize.
static const size_t MAILBOX_TAG_BYTES = 16;

// Cap on one envelope, so a relay cannot make a client allocate at will.
static const size_t MAX_ENVELOPE_BYTES = 64 * 1024;

// Which epoch a unix time falls in.
int64_t MailboxEpoch(int64_t nNow);

// The tag this pair shares for that epoch, as 32 hex characters. Symmetric:
// both sides compute the same value from their own secret and the other's
// public key, and neither needs anything else.
bool MailboxTag(const unsigned char my_chan_sk[btf::CHAN_KEYBYTES],
                const unsigned char their_chan_pub[btf::CHAN_KEYBYTES],
                int64_t nEpoch, std::string& tagHexOut);

// One epoch's keys. Holds secrets; Clear() zeroes them.
struct EpochKeys
{
    int64_t       epoch;
    unsigned char x_pk[btf::CHAN_KEYBYTES];
    unsigned char x_sk[btf::CHAN_KEYBYTES];
    unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES];
    unsigned char kem_sk[btf::CHAN_KEM_SECBYTES];

    EpochKeys() : epoch(0) {}
};

void EpochKeysClear(EpochKeys& k);

// Our own mailbox: the epoch keys we keep, and the envelopes we can open.
class Mailbox
{
public:
    Mailbox() {}
    ~Mailbox() { Wipe(); }

    // Make sure keys exist for the epoch `nNow` falls in, and destroy any that
    // are older than MAILBOX_KEEP_EPOCHS. Call it on unlock and once a day.
    bool Rotate(int64_t nNow, std::string& errOut);

    // The public halves for an epoch, to publish. False if we hold none.
    bool PublicFor(int64_t nEpoch, unsigned char x_pk[btf::CHAN_KEYBYTES],
                   unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES]) const;

    // Try to open an envelope with every epoch key we still hold. An envelope
    // we sealed ourselves fails here, which is how our own posts under a shared
    // tag get skipped.
    bool Open(const unsigned char* in, size_t n,
              std::vector<unsigned char>& out, std::string& errOut) const;

    // Destroy the secrets for every epoch before `nEpoch`. Irreversible, which
    // is the point.
    void Forget(int64_t nEpoch);

    // Destroy everything.
    void Wipe();

    size_t LiveEpochs() const { return mapKeys.size(); }
    bool   Has(int64_t nEpoch) const { return mapKeys.count(nEpoch) != 0; }

private:
    std::map<int64_t, EpochKeys> mapKeys;
};

// Seal one frame for an offline recipient, using THEIR published epoch keys.
// `frameJson` is what SignFrame produced: the signature inside is what tells the
// recipient who wrote it, so the envelope itself stays anonymous.
bool SealEnvelope(const unsigned char their_x_pk[btf::CHAN_KEYBYTES],
                  const unsigned char their_kem_pk[btf::CHAN_KEM_PUBBYTES],
                  const std::string& frameJson,
                  std::vector<unsigned char>& out, std::string& errOut);

// ---- published epoch keys --------------------------------------------------

// Sign the public halves of an epoch, to publish. Bound to the address, so the
// announcement cannot be moved onto another identity, and to the epoch, so an
// old one cannot be replayed as current.
bool SignEpochKeys(void* secpctx, const Identity& id, const EpochKeys& keys,
                   std::string& jsonOut, std::string& errOut);

// Verify a published announcement against the address it claims to come from.
// Refuses an epoch far from `nNow`, so a relay cannot hand back a stale
// announcement whose secrets the owner has already destroyed -- messages sealed
// to those keys would be undeliverable and silently lost.
bool VerifyEpochKeys(void* secpctx, const std::string& expectAddress,
                     const std::string& jsonStr, int64_t nNow,
                     int64_t& epochOut,
                     unsigned char x_pk[btf::CHAN_KEYBYTES],
                     unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES],
                     std::string& errOut);

} // namespace btfchat

#endif
