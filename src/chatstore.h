// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The chat's records, held by the Bitflash nodes themselves.
//
// WHY THIS EXISTS. The chat used to find people, and leave messages for them,
// through public Nostr relays. Those are somebody else's servers: they refused
// our event kinds, rate-limited us, and could be switched off without asking.
// The coin already works without any server -- pinned onion seeds, peers that
// hand each other signed descriptors -- and the chat now follows the same rule.
// What used to sit on a relay sits on every node instead, and spreads between
// them the way a transaction does.
//
// THREE KINDS OF RECORD, ALL SELF-CERTIFYING OR SEALED:
//
//   DESC      a chat identity's signed descriptor: its onion and channel key.
//             Keyed by the identity's x-only key. One per identity, newest wins.
//   EPOCH     its signed epoch keys, what offline messages are sealed to.
//             Same key, same rule.
//   ENVELOPE  a sealed message left for somebody offline, filed under the
//             rotating pair tag (btfchatbox.h). Opaque to the node.
//
// A node never has to trust whoever handed it a record. A descriptor or epoch
// announcement that does not verify against the key it is filed under is
// refused, and the ordering that decides "newest" is the SIGNED time inside it,
// not a field a relayer could raise. An envelope cannot be checked at all -- it
// is sealed -- which is why everything here also carries proof of work.
//
// PROOF OF WORK. Writing to every node on the network for free is a storage
// service open to anybody, running inside the program that holds people's
// money. Each record costs about a second of one CPU core to make, scaled up
// with its size, and a fraction of a millisecond to check. That is nothing to a
// person sending a message and real money to somebody filling the network's
// memory with a CPU. It is a speed bump, not a wall -- SHA-256 is what graphics
// cards are best at, and one of those pays it a million times over. What
// bounds the damage is that a full store refuses new records instead of
// evicting old ones, so a flood can delay offline delivery but never erase a
// message already held. A stamp paid in coin is the real answer
// (docs/btfchat.md, phase 1).
//
// MEMORY ONLY. Nothing here touches the disk. A node that restarts forgets, and
// gets the records back from its peers; a message that every node forgot was
// older than a day anyway, and the sender's own outbox still has it. Keeping it
// off the disk keeps it away from the wallet, and leaves nothing for a seized
// machine to give up.
//
// This file is pure logic -- no sockets, no node globals -- so the whole policy
// is tested without a network (test_chatstore.cpp).

#ifndef BITFLASH_CHATSTORE_H
#define BITFLASH_CHATSTORE_H

#include <map>
#include <set>
#include <string>
#include <vector>
#include <stdint.h>

namespace btfchat
{

enum
{
    CHATREC_DESC     = 1,
    CHATREC_EPOCH    = 2,
    CHATREC_ENVELOPE = 3,
};

// Key length per kind: an identity's x-only key, or a pair tag.
static const size_t CHATREC_IDENTITY_KEY_BYTES = 32;
static const size_t CHATREC_TAG_KEY_BYTES      = 16;

// Largest payload accepted. An envelope's own cap plus room for nothing else:
// a descriptor or an epoch announcement is a few kilobytes.
static const size_t CHATREC_MAX_PAYLOAD = 64 * 1024;

// Serialized record cap, for whoever reads one off a socket.
static const size_t CHATREC_MAX_BYTES = CHATREC_MAX_PAYLOAD + 128;

// Work, in leading zero bits of the record id. 20 bits is about a million
// double-SHA256 attempts: around a second on one core of an ordinary laptop.
// One more bit for every doubling of size past 4 KB, so the bytes somebody makes
// every node hold cost them in proportion.
static const unsigned int CHATREC_BASE_BITS = 20;
unsigned int ChatRecordBitsFor(size_t nPayload);

// How long a node keeps each kind, measured from the record's own time. An
// envelope lives a little longer than a frame is accepted (FRAME_MAX_AGE, a day)
// so one posted just before the cutoff is still there to be refused properly
// rather than vanishing. A descriptor is republished every few hours; a week
// covers a machine that was off over a weekend. Epoch keys stop mattering two
// epochs after they were made.
static const int64_t CHATREC_ENVELOPE_LIFETIME = 26 * 60 * 60;
static const int64_t CHATREC_DESC_LIFETIME     = 7 * 24 * 60 * 60;
static const int64_t CHATREC_EPOCH_LIFETIME    = 3 * 24 * 60 * 60;

// How far in the future a record's time may be. Clocks drift; two hours is what
// the chain itself tolerates.
static const int64_t CHATREC_MAX_FUTURE = 2 * 60 * 60;

// The memory a node gives the chat, per kind. Together about 64 MB at worst,
// which a machine that runs RandomX's 2 GB dataset does not notice. When a
// kind is full, new records of it are refused; nothing held is evicted to make
// room (see ChatStore::Accept for why that matters).
static const size_t CHATREC_ENVELOPE_BUDGET = 32 * 1024 * 1024;
static const size_t CHATREC_EPOCH_BUDGET    = 24 * 1024 * 1024;
static const size_t CHATREC_DESC_BUDGET     =  8 * 1024 * 1024;

// Envelopes kept under one tag. A pair that left more than this for each other
// in a day is a flood, not a conversation, and the oldest go first.
static const size_t CHATREC_MAX_PER_TAG = 64;

// Records a single query may return.
static const size_t CHATREC_MAX_QUERY = 64;

struct ChatRecord
{
    uint8_t                    kind;
    std::vector<unsigned char> key;
    int64_t                    nTime;
    std::vector<unsigned char> payload;
    uint64_t                   nNonce;

    ChatRecord() : kind(0), nTime(0), nNonce(0) {}

    // Double SHA-256 of the header, which commits to the payload through its
    // own hash -- so grinding the nonce never rehashes 64 KB.
    void Id(unsigned char out[32]) const;
    std::string IdHex() const;

    std::vector<unsigned char> Serialize() const;
    bool Parse(const unsigned char* p, size_t n);
};

// The record's shape alone: kind known, key the right length for it, payload
// within bounds. Says nothing about work, time or signatures.
bool ChatRecordWellFormed(const ChatRecord& r, std::string& whyOut);

// Leading zero bits of the id.
unsigned int ChatRecordWork(const ChatRecord& r);
bool ChatRecordHasWork(const ChatRecord& r, unsigned int nBitsOverride = 0);

// Find a nonce that pays the work for this record's size. `pfAbort`, if given,
// is checked every few thousand attempts. Returns false if aborted.
bool ChatRecordMine(ChatRecord& r, volatile bool* pfAbort = 0,
                    unsigned int nBitsOverride = 0);

// Signature and consistency checks for the two signed kinds. Exposed so the
// chat client applies the very same rules to what a node answers.
//   DESC:  the payload is a descriptor signed by `key`, it names an onion, and
//          the record time IS the descriptor's signed creation time.
//   EPOCH: the payload is an epoch announcement signed by the identity `key`
//          encodes, and the record time IS the start of that epoch.
bool ChatRecordVerifySigned(void* secpctx, const ChatRecord& r, int64_t nNow,
                            std::string& whyOut);

class ChatStore
{
public:
    enum Result
    {
        REJECTED  = 0,
        ACCEPTED  = 1,
        DUPLICATE = 2,   // already held, or superseded by a newer one we hold
    };

    // `nBits` other than 0 replaces the work rule -- for tests only, which is
    // why it is a constructor argument and not something a peer can reach.
    explicit ChatStore(unsigned int nBitsOverride = 0)
        : nBitsOverride(nBitsOverride) {}

    // Check everything and keep it if it passes. `secpctx` is a
    // secp256k1_context* able to verify. `idOut` gets the record id.
    Result Accept(void* secpctx, const ChatRecord& r, int64_t nNow,
                  std::string& whyOut, unsigned char idOut[32]);

    bool Has(const unsigned char id[32]) const;
    bool Get(const unsigned char id[32], ChatRecord& out) const;

    // Records filed under `key` of `kind`. For an envelope, those whose time is
    // at or after `nSince`, oldest first, at most `nMax`. For the signed kinds,
    // the one current record, if any.
    void Query(uint8_t kind, const std::vector<unsigned char>& key, int64_t nSince,
               size_t nMax, std::vector<ChatRecord>& out) const;

    // Every id held, newest first, at most `nMax`: what a node offers a peer
    // that just connected and has nothing.
    void Ids(size_t nMax, std::vector<std::vector<unsigned char> >& out) const;

    // Drop what has outlived its kind's lifetime.
    int Expire(int64_t nNow);

    size_t Count() const { return mapRec.size(); }
    size_t Bytes(uint8_t kind) const;

private:
    struct Entry
    {
        ChatRecord rec;
        std::string id;      // 32 raw bytes
        size_t      nBytes;
    };

    unsigned int nBitsOverride;

    // id -> record
    std::map<std::string, Entry> mapRec;
    // (kind, key) -> ids filed there, ordered by (time, id)
    std::map<std::pair<uint8_t, std::string>,
             std::set<std::pair<int64_t, std::string> > > mapByKey;
    // per kind: (time, id), so the oldest is always at the front
    std::map<uint8_t, std::set<std::pair<int64_t, std::string> > > mapByAge;
    std::map<uint8_t, size_t> mapBytes;

    // By value on purpose: callers pass ids that live inside the very sets this
    // erases from, and a reference would dangle halfway through.
    void Remove(std::string id);
    void Insert(const ChatRecord& r, const std::string& id);
    static size_t BudgetFor(uint8_t kind);
    static int64_t LifetimeFor(uint8_t kind);
    // What one record counts against its kind's budget.
    static size_t EntryBytes(const ChatRecord& r) { return r.payload.size() + r.key.size() + 64; }
};

} // namespace btfchat

#endif
