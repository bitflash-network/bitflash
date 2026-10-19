// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "chatstore.h"
#include "btfaddr.h"
#include "btfchatbox.h"

#include <sodium.h>

#include <cstring>

namespace btfchat
{

// Bumped if the wire form or the id ever changes. A record from another
// version is refused rather than misread.
static const unsigned char CHATREC_WIRE_VERSION = 1;

// Domain for the id, so a record id can never be some other structure's hash.
static const char CHATREC_ID_DOMAIN[] = "bitflash-chatrec-1";

static void Sha256(const unsigned char* p, size_t n, unsigned char out[32])
{
    crypto_hash_sha256(out, p, (unsigned long long)n);
}

static void PutU64(std::vector<unsigned char>& v, uint64_t x)
{
    for (int i = 0; i < 8; i++)
        v.push_back((unsigned char)(x >> (8 * i)));
}

static uint64_t GetU64(const unsigned char* p)
{
    uint64_t x = 0;
    for (int i = 7; i >= 0; i--)
        x = (x << 8) | p[i];
    return x;
}

static std::string ToHex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++)
    {
        s += h[p[i] >> 4];
        s += h[p[i] & 0x0f];
    }
    return s;
}

unsigned int ChatRecordBitsFor(size_t nPayload)
{
    unsigned int nBits = CHATREC_BASE_BITS;
    size_t nStep = 4096;
    while (nPayload > nStep && nBits < CHATREC_BASE_BITS + 8)
    {
        nBits++;
        nStep *= 2;
    }
    return nBits;
}

// The header the work is ground over. Everything that matters is in it: the
// payload through its hash, so the nonce loop hashes ~100 bytes, not 64 KB.
static void Header(const ChatRecord& r, const unsigned char payloadHash[32],
                   std::vector<unsigned char>& out)
{
    out.clear();
    out.insert(out.end(), CHATREC_ID_DOMAIN, CHATREC_ID_DOMAIN + sizeof(CHATREC_ID_DOMAIN) - 1);
    out.push_back(r.kind);
    out.push_back((unsigned char)r.key.size());
    out.insert(out.end(), r.key.begin(), r.key.end());
    PutU64(out, (uint64_t)r.nTime);
    out.insert(out.end(), payloadHash, payloadHash + 32);
    PutU64(out, r.nNonce);
}

static void IdFromHeader(const std::vector<unsigned char>& hdr, unsigned char out[32])
{
    unsigned char once[32];
    Sha256(hdr.empty() ? NULL : &hdr[0], hdr.size(), once);
    Sha256(once, 32, out);
}

void ChatRecord::Id(unsigned char out[32]) const
{
    unsigned char ph[32];
    Sha256(payload.empty() ? NULL : &payload[0], payload.size(), ph);
    std::vector<unsigned char> hdr;
    Header(*this, ph, hdr);
    IdFromHeader(hdr, out);
}

std::string ChatRecord::IdHex() const
{
    unsigned char id[32];
    Id(id);
    return ToHex(id, 32);
}

std::vector<unsigned char> ChatRecord::Serialize() const
{
    std::vector<unsigned char> v;
    v.reserve(1 + 1 + 1 + key.size() + 8 + 8 + 4 + payload.size());
    v.push_back(CHATREC_WIRE_VERSION);
    v.push_back(kind);
    v.push_back((unsigned char)key.size());
    v.insert(v.end(), key.begin(), key.end());
    PutU64(v, (uint64_t)nTime);
    PutU64(v, nNonce);
    uint32_t n = (uint32_t)payload.size();
    for (int i = 0; i < 4; i++)
        v.push_back((unsigned char)(n >> (8 * i)));
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

bool ChatRecord::Parse(const unsigned char* p, size_t n)
{
    // Every length is checked against what is actually there before it is used:
    // this is a stranger's bytes off a socket.
    if (!p || n < 3 || n > CHATREC_MAX_BYTES)
        return false;
    if (p[0] != CHATREC_WIRE_VERSION)
        return false;
    size_t nKey = p[2];
    size_t off = 3;
    if (nKey > CHATREC_IDENTITY_KEY_BYTES || n < off + nKey + 8 + 8 + 4)
        return false;
    ChatRecord r;
    r.kind = p[1];
    r.key.assign(p + off, p + off + nKey);
    off += nKey;
    r.nTime = (int64_t)GetU64(p + off);
    off += 8;
    r.nNonce = GetU64(p + off);
    off += 8;
    uint32_t nPay = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
                    ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
    off += 4;
    if (nPay > CHATREC_MAX_PAYLOAD || n != off + nPay)
        return false;
    r.payload.assign(p + off, p + off + nPay);
    *this = r;
    return true;
}

bool ChatRecordWellFormed(const ChatRecord& r, std::string& whyOut)
{
    switch (r.kind)
    {
    case CHATREC_DESC:
    case CHATREC_EPOCH:
        if (r.key.size() != CHATREC_IDENTITY_KEY_BYTES)
        {
            whyOut = "an identity record is filed under a 32-byte key";
            return false;
        }
        break;
    case CHATREC_ENVELOPE:
        if (r.key.size() != CHATREC_TAG_KEY_BYTES)
        {
            whyOut = "an envelope is filed under a 16-byte tag";
            return false;
        }
        break;
    default:
        whyOut = "unknown record kind";
        return false;
    }
    if (r.payload.empty())
    {
        whyOut = "empty record";
        return false;
    }
    if (r.payload.size() > CHATREC_MAX_PAYLOAD)
    {
        whyOut = "record too large";
        return false;
    }
    return true;
}

static unsigned int LeadingZeroBits(const unsigned char id[32])
{
    unsigned int n = 0;
    for (int i = 0; i < 32; i++)
    {
        if (id[i] == 0)
        {
            n += 8;
            continue;
        }
        unsigned char b = id[i];
        while (!(b & 0x80))
        {
            n++;
            b <<= 1;
        }
        break;
    }
    return n;
}

unsigned int ChatRecordWork(const ChatRecord& r)
{
    unsigned char id[32];
    r.Id(id);
    return LeadingZeroBits(id);
}

bool ChatRecordHasWork(const ChatRecord& r, unsigned int nBitsOverride)
{
    unsigned int nNeed = nBitsOverride ? nBitsOverride : ChatRecordBitsFor(r.payload.size());
    return ChatRecordWork(r) >= nNeed;
}

bool ChatRecordMine(ChatRecord& r, volatile bool* pfAbort, unsigned int nBitsOverride)
{
    unsigned int nNeed = nBitsOverride ? nBitsOverride : ChatRecordBitsFor(r.payload.size());
    unsigned char ph[32];
    Sha256(r.payload.empty() ? NULL : &r.payload[0], r.payload.size(), ph);

    // Start somewhere random, so two records with the same content mined at
    // the same second do not race each other through the same nonces.
    randombytes_buf(&r.nNonce, sizeof(r.nNonce));

    std::vector<unsigned char> hdr;
    Header(r, ph, hdr);
    const size_t nNonceAt = hdr.size() - 8;
    unsigned char id[32];
    for (uint64_t i = 0;; i++)
    {
        if (pfAbort && (i & 0x0fff) == 0 && *pfAbort)
            return false;
        uint64_t nonce = r.nNonce + i;
        for (int k = 0; k < 8; k++)
            hdr[nNonceAt + k] = (unsigned char)(nonce >> (8 * k));
        IdFromHeader(hdr, id);
        if (LeadingZeroBits(id) >= nNeed)
        {
            r.nNonce = nonce;
            return true;
        }
    }
}

bool ChatRecordVerifySigned(void* secpctx, const ChatRecord& r, int64_t nNow,
                            std::string& whyOut)
{
    if (r.key.size() != CHATREC_IDENTITY_KEY_BYTES)
    {
        whyOut = "an identity record is filed under a 32-byte key";
        return false;
    }
    std::string js(r.payload.begin(), r.payload.end());

    if (r.kind == CHATREC_DESC)
    {
        btf::Descriptor d;
        if (!btf::VerifyDescriptor(secpctx, js, &r.key[0], d))
        {
            whyOut = "the descriptor is not signed by the key it is filed under";
            return false;
        }
        std::string norm;
        if (d.onion.empty() || !btf::NormalizeOnionEndpoint(d.onion, norm))
        {
            whyOut = "the descriptor names no onion to reach it at";
            return false;
        }
        // The signed time IS the record time. Otherwise anybody could rewrap an
        // old, validly signed descriptor with a later record time and make it
        // win over the owner's current one.
        if ((int64_t)d.created != r.nTime)
        {
            whyOut = "the record time is not the descriptor's signed time";
            return false;
        }
        return true;
    }

    if (r.kind == CHATREC_EPOCH)
    {
        int64_t nEpoch = 0;
        unsigned char x[btf::CHAN_KEYBYTES];
        unsigned char kem[btf::CHAN_KEM_PUBBYTES];
        std::string err;
        if (!VerifyEpochKeys(secpctx, btf::Address(&r.key[0]), js, nNow, nEpoch, x, kem, err))
        {
            whyOut = "epoch keys refused: " + err;
            return false;
        }
        // Same reason as above: the ordering must come from what was signed.
        if (r.nTime != nEpoch * MAILBOX_EPOCH_SECONDS)
        {
            whyOut = "the record time is not the start of the signed epoch";
            return false;
        }
        return true;
    }

    whyOut = "not a signed record kind";
    return false;
}

size_t ChatStore::BudgetFor(uint8_t kind)
{
    switch (kind)
    {
    case CHATREC_DESC:     return CHATREC_DESC_BUDGET;
    case CHATREC_EPOCH:    return CHATREC_EPOCH_BUDGET;
    case CHATREC_ENVELOPE: return CHATREC_ENVELOPE_BUDGET;
    }
    return 0;
}

int64_t ChatStore::LifetimeFor(uint8_t kind)
{
    switch (kind)
    {
    case CHATREC_DESC:     return CHATREC_DESC_LIFETIME;
    case CHATREC_EPOCH:    return CHATREC_EPOCH_LIFETIME;
    case CHATREC_ENVELOPE: return CHATREC_ENVELOPE_LIFETIME;
    }
    return 0;
}

size_t ChatStore::Bytes(uint8_t kind) const
{
    std::map<uint8_t, size_t>::const_iterator it = mapBytes.find(kind);
    return it == mapBytes.end() ? 0 : it->second;
}

void ChatStore::Insert(const ChatRecord& r, const std::string& id)
{
    Entry e;
    e.rec = r;
    e.id = id;
    e.nBytes = EntryBytes(r);
    std::string k(r.key.begin(), r.key.end());
    mapByKey[std::make_pair(r.kind, k)].insert(std::make_pair(r.nTime, id));
    mapByAge[r.kind].insert(std::make_pair(r.nTime, id));
    mapBytes[r.kind] += e.nBytes;
    mapRec[id] = e;
}

void ChatStore::Remove(std::string id)
{
    std::map<std::string, Entry>::iterator it = mapRec.find(id);
    if (it == mapRec.end())
        return;
    const ChatRecord& r = it->second.rec;
    std::pair<uint8_t, std::string> k(r.kind, std::string(r.key.begin(), r.key.end()));
    std::map<std::pair<uint8_t, std::string>,
             std::set<std::pair<int64_t, std::string> > >::iterator bk = mapByKey.find(k);
    if (bk != mapByKey.end())
    {
        bk->second.erase(std::make_pair(r.nTime, id));
        if (bk->second.empty())
            mapByKey.erase(bk);
    }
    mapByAge[r.kind].erase(std::make_pair(r.nTime, id));
    mapBytes[r.kind] -= it->second.nBytes;
    mapRec.erase(it);
}

ChatStore::Result ChatStore::Accept(void* secpctx, const ChatRecord& r, int64_t nNow,
                                    std::string& whyOut, unsigned char idOut[32])
{
    whyOut.clear();
    r.Id(idOut);
    std::string id((const char*)idOut, 32);

    // Cheapest checks first: a flood should cost us as little as possible.
    if (!ChatRecordWellFormed(r, whyOut))
        return REJECTED;
    if (mapRec.count(id))
        return DUPLICATE;
    if (r.nTime > nNow + CHATREC_MAX_FUTURE)
    {
        whyOut = "record time is in the future";
        return REJECTED;
    }
    if (r.nTime + LifetimeFor(r.kind) < nNow)
    {
        whyOut = "record has expired";
        return REJECTED;
    }
    if (!ChatRecordHasWork(r, nBitsOverride))
    {
        whyOut = "not enough proof of work";
        return REJECTED;
    }

    Expire(nNow);

    std::pair<uint8_t, std::string> k(r.kind, std::string(r.key.begin(), r.key.end()));

    if (r.kind == CHATREC_DESC || r.kind == CHATREC_EPOCH)
    {
        // Signature last: it is the expensive check, and everything above
        // already turned away the records that do not deserve one.
        if (!ChatRecordVerifySigned(secpctx, r, nNow, whyOut))
            return REJECTED;

        // One current record per identity. Newer signed time wins; an equal or
        // older one changes nothing, and is not an error -- it is simply news
        // we already have.
        std::map<std::pair<uint8_t, std::string>,
                 std::set<std::pair<int64_t, std::string> > >::iterator bk = mapByKey.find(k);
        std::vector<std::string> old;
        size_t nFreed = 0;
        if (bk != mapByKey.end() && !bk->second.empty())
        {
            const std::pair<int64_t, std::string>& cur = *bk->second.rbegin();
            if (cur.first >= r.nTime)
                return DUPLICATE;
            for (std::set<std::pair<int64_t, std::string> >::const_iterator it = bk->second.begin();
                 it != bk->second.end(); ++it)
            {
                old.push_back(it->second);
                nFreed += mapRec[it->second].nBytes;
            }
        }
        // Replacing an identity's own record always fits in the room the old
        // one leaves, give or take; a NEW identity needs room of its own. See
        // the note on the budget below.
        if (Bytes(r.kind) - nFreed + EntryBytes(r) > BudgetFor(r.kind))
        {
            whyOut = "this node's chat store is full; try again later";
            return REJECTED;
        }
        for (size_t i = 0; i < old.size(); i++)
            Remove(old[i]);
        Insert(r, id);
        return ACCEPTED;
    }

    std::map<std::pair<uint8_t, std::string>,
             std::set<std::pair<int64_t, std::string> > >::iterator bk = mapByKey.find(k);
    bool fDropOldest = false;
    if (bk != mapByKey.end() && bk->second.size() >= CHATREC_MAX_PER_TAG)
    {
        // The tag is full. Keep the newest; if this one is older than all of
        // them it goes, not one of theirs. Only the two people who share a tag
        // can compute it, so nobody else can push anything out of it.
        if (r.nTime <= bk->second.begin()->first)
        {
            whyOut = "too many envelopes under that tag";
            return REJECTED;
        }
        fDropOldest = true;
    }

    // Over budget, the NEW record is refused -- nothing already held is pushed
    // out to make room. The other way round looked kinder and was the dangerous
    // one: the work here is SHA-256, which a graphics card does a million times
    // faster than a laptop, so anybody with one could fill the budget in
    // seconds and, by evicting, quietly erase messages whose senders had
    // already been told "left in their mailbox". Refusing instead means a flood
    // can block NEW offline messages until records expire, and the sender is
    // told at the moment it happens -- the message stays in their outbox and
    // goes direct when the other side is seen. A refusal is visible; an
    // eviction is a silent loss.
    size_t nFreed = fDropOldest ? mapRec[bk->second.begin()->second].nBytes : 0;
    if (Bytes(r.kind) - nFreed + EntryBytes(r) > BudgetFor(r.kind))
    {
        whyOut = "this node's chat store is full; try again later";
        return REJECTED;
    }
    if (fDropOldest)
        Remove(bk->second.begin()->second);
    Insert(r, id);
    return ACCEPTED;
}

bool ChatStore::Has(const unsigned char id[32]) const
{
    return mapRec.count(std::string((const char*)id, 32)) != 0;
}

bool ChatStore::Get(const unsigned char id[32], ChatRecord& out) const
{
    std::map<std::string, Entry>::const_iterator it =
        mapRec.find(std::string((const char*)id, 32));
    if (it == mapRec.end())
        return false;
    out = it->second.rec;
    return true;
}

void ChatStore::Query(uint8_t kind, const std::vector<unsigned char>& key, int64_t nSince,
                      size_t nMax, std::vector<ChatRecord>& out) const
{
    out.clear();
    if (nMax > CHATREC_MAX_QUERY)
        nMax = CHATREC_MAX_QUERY;
    std::pair<uint8_t, std::string> k(kind, std::string(key.begin(), key.end()));
    std::map<std::pair<uint8_t, std::string>,
             std::set<std::pair<int64_t, std::string> > >::const_iterator bk = mapByKey.find(k);
    if (bk == mapByKey.end() || bk->second.empty())
        return;

    if (kind == CHATREC_DESC || kind == CHATREC_EPOCH)
    {
        std::map<std::string, Entry>::const_iterator it = mapRec.find(bk->second.rbegin()->second);
        if (it != mapRec.end())
            out.push_back(it->second.rec);
        return;
    }

    for (std::set<std::pair<int64_t, std::string> >::const_iterator s =
             bk->second.lower_bound(std::make_pair(nSince, std::string()));
         s != bk->second.end() && out.size() < nMax; ++s)
    {
        std::map<std::string, Entry>::const_iterator it = mapRec.find(s->second);
        if (it != mapRec.end())
            out.push_back(it->second.rec);
    }
}

void ChatStore::Ids(size_t nMax, std::vector<std::vector<unsigned char> >& out) const
{
    out.clear();
    // Newest first across all kinds: a peer that can only take part of the
    // list gets what is most likely still wanted.
    std::set<std::pair<int64_t, std::string> > all;
    for (std::map<std::string, Entry>::const_iterator it = mapRec.begin(); it != mapRec.end(); ++it)
        all.insert(std::make_pair(it->second.rec.nTime, it->first));
    for (std::set<std::pair<int64_t, std::string> >::const_reverse_iterator it = all.rbegin();
         it != all.rend() && out.size() < nMax; ++it)
        out.push_back(std::vector<unsigned char>(it->second.begin(), it->second.end()));
}

int ChatStore::Expire(int64_t nNow)
{
    int n = 0;
    for (std::map<uint8_t, std::set<std::pair<int64_t, std::string> > >::iterator k = mapByAge.begin();
         k != mapByAge.end(); ++k)
    {
        int64_t nLife = LifetimeFor(k->first);
        while (!k->second.empty() && k->second.begin()->first + nLife < nNow)
        {
            std::string id = k->second.begin()->second;
            Remove(id);
            n++;
        }
    }
    return n;
}

} // namespace btfchat
