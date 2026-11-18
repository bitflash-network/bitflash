// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See poolticket.h.

#include "headers.h"
#include "poolticket.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
// See the note in nostr.cpp: the makefiles pass -DSECP256K1_STATIC too.
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

static const unsigned char TICKET_TAG[4] = { 'B', 'T', 'F', 'G' };
static const char* TICKET_SIG_DOMAIN = "Bitflash/guard-ticket/1";
static const char* DRAW_DOMAIN = "Bitflash/guard/1";

// The file: a version, the magic, the epochs, and the hash of all three.
static const int TICKET_FILE_VERSION = 1;
// Three epochs of 4096 tickets and one own ticket each are under 1.5 MB.
static const size_t TICKET_FILE_MAX = 4 * 1024 * 1024;
static const unsigned int TICKET_FILE_EPOCHS = 3;

// One context for signing and checking, as the chat and the relay keep theirs.
static secp256k1_context* TicketCtx()
{
    static secp256k1_context* ctx = NULL;
    static CCriticalSection cs_ctx;
    CRITICAL_BLOCK(cs_ctx)
        if (!ctx)
        {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            unsigned char rnd[32];
            // Blinding for the signing side only; a context that could not be
            // blinded still signs and checks the same bytes.
            if (ctx && RAND_bytes(rnd, sizeof(rnd)) == 1)
                (void)secp256k1_context_randomize(ctx, rnd);
        }
    return ctx;
}

// ---- epochs ---------------------------------------------------------------

namespace pooltkt
{

int EpochOf(int nHeight)
{
    if (nHeight < 0)
        return -1;
    return nHeight / GUARD_EPOCH_BLOCKS;
}

int64 EpochStart(int64 nEpoch) { return (int64)GUARD_EPOCH_BLOCKS * nEpoch; }
int64 TicketSeedHeight(int64 nEpoch) { return (int64)GUARD_EPOCH_BLOCKS * (nEpoch - 1); }
int64 TicketDeadlineHeight(int64 nEpoch) { return EpochStart(nEpoch) - GUARD_DEADLINE_BEFORE; }
int64 DrawSeedHeight(int64 nEpoch) { return EpochStart(nEpoch) - GUARD_DRAW_SEED_BEFORE; }
int64 DrawSettleHeight(int64 nEpoch)
{
    return DrawSeedHeight(nEpoch) + GUARD_SEED_CONFIRMATIONS - 1;
}
int64 LingerEndHeight(int64 nEpoch) { return EpochStart(nEpoch) + GUARD_LINGER_BLOCKS; }

bool TicketSeed(const CTicketChainView& view, int64 nEpoch, uint256& hashOut, bool& fBuriedOut)
{
    fBuriedOut = false;
    const int nTip = view.TipHeight();
    const int64 h = TicketSeedHeight(nEpoch);
    if (nEpoch < 1 || nTip < 0 || h > nTip)
        return false;
    if (!view.HashAt((int)h, hashOut))
        return false;
    fBuriedOut = ((int64)nTip - h + 1 >= GUARD_SEED_CONFIRMATIONS);
    return true;
}

bool PastDeadline(const CTicketChainView& view, int64 nEpoch)
{
    return (int64)view.TipHeight() >= TicketDeadlineHeight(nEpoch);
}

bool DrawSeed(const CTicketChainView& view, int64 nEpoch, uint256& hashOut, bool& fSettledOut)
{
    fSettledOut = false;
    const int nTip = view.TipHeight();
    const int64 h = DrawSeedHeight(nEpoch);
    if (nEpoch < 1 || nTip < 0 || h > nTip)
        return false;
    if (!view.HashAt((int)h, hashOut))
        return false;
    fSettledOut = ((int64)nTip >= DrawSettleHeight(nEpoch));
    return true;
}

bool EpochInRange(const CTicketChainView& view, int64 nEpoch)
{
    const int nCur = EpochOf(view.TipHeight());
    if (nCur < 0 || nEpoch < 1)
        return false;
    // The previous epoch only through handoff: its guardians let go at the
    // current epoch's 720e + 180, and nobody needs its tickets after.
    if (nEpoch == (int64)nCur - 1)
        return (int64)view.TipHeight() < LingerEndHeight(nCur);
    return nEpoch == (int64)nCur || nEpoch == (int64)nCur + 1;
}

} // namespace pooltkt

// ---- the ticket -----------------------------------------------------------

CTicketParams::CTicketParams() : nBits(0), nTime(0), fnWork(NULL)
{
    memset(magic, 0, sizeof(magic));
}

CTicketParams CTicketParams::Network()
{
    CTicketParams p;
    memcpy(p.magic, pchMessageStart, sizeof(p.magic));
    p.nBits = IsTestNet() ? GUARD_TICKET_BITS_TESTNET : GUARD_TICKET_BITS_MAINNET;
    p.nTime = PoWV2Time();
    p.fnWork = NULL;
    return p;
}

uint256 CTicketParams::Target() const
{
    return CBigNum().SetCompact(nBits).getuint256();
}

CGuardTicket::CGuardTicket()
{
    memset(body, 0, sizeof(body));
    memset(sig, 0, sizeof(sig));
}

std::vector<unsigned char> CGuardTicket::Bytes() const
{
    std::vector<unsigned char> v(body, body + sizeof(body));
    v.insert(v.end(), sig, sig + sizeof(sig));
    return v;
}

bool CGuardTicket::FromBytes(const unsigned char* p, size_t n)
{
    if (p == NULL || n != GUARD_TICKET_SIZE)
        return false;
    memcpy(body, p, sizeof(body));
    memcpy(sig, p + sizeof(body), sizeof(sig));
    return true;
}

void CGuardTicket::SetBody(const unsigned char magic[4], unsigned int nEpoch, const unsigned char pubkey[32],
                           unsigned short nCapacityMB, uint64 nNonce)
{
    memcpy(body, magic, 4);
    memcpy(body + 4, TICKET_TAG, 4);
    for (int i = 0; i < 4; i++)
        body[8 + i] = (unsigned char)((nEpoch >> (8 * i)) & 0xff);
    memcpy(body + 12, pubkey, 32);
    body[44] = (unsigned char)(nCapacityMB & 0xff);
    body[45] = (unsigned char)((nCapacityMB >> 8) & 0xff);
    SetNonce(nNonce);
}

void CGuardTicket::SetNonce(uint64 nNonce)
{
    for (int i = 0; i < 8; i++)
        body[46 + i] = (unsigned char)((nNonce >> (8 * i)) & 0xff);
}

bool CGuardTicket::HasMagic(const unsigned char magic[4]) const
{
    return memcmp(body, magic, 4) == 0;
}

bool CGuardTicket::HasTag() const
{
    return memcmp(body + 4, TICKET_TAG, 4) == 0;
}

unsigned int CGuardTicket::Epoch() const
{
    unsigned int n = 0;
    for (int i = 0; i < 4; i++)
        n |= (unsigned int)body[8 + i] << (8 * i);
    return n;
}

unsigned short CGuardTicket::CapacityMB() const
{
    return (unsigned short)(body[44] | (body[45] << 8));
}

uint64 CGuardTicket::Nonce() const
{
    uint64 n = 0;
    for (int i = 0; i < 8; i++)
        n |= (uint64)body[46 + i] << (8 * i);
    return n;
}

uint256 CGuardTicket::BodyHash() const
{
    return Hash(body, body + sizeof(body));
}

void CGuardTicket::SigHash(unsigned char out32[32]) const
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)TICKET_SIG_DOMAIN, strlen(TICKET_SIG_DOMAIN));
    SHA256_Update(&ctx, body, sizeof(body));
    SHA256_Final(out32, &ctx);
}

void CGuardTicket::WorkHeader(const CTicketParams& params, const uint256& hashSeed, unsigned char out80[80]) const
{
    // nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce: a block
    // header as the node serializes one, written out by hand so that nothing
    // here depends on CBlock.
    uint256 hashBody = BodyHash();
    uint256 hashPrev = hashSeed;   // begin() is not const
    const unsigned int nNonce32 = (unsigned int)(Nonce() & 0xffffffffULL);
    const unsigned int nVersion = (unsigned int)GUARD_TICKET_HEADER_VERSION;
    for (int i = 0; i < 4; i++)
        out80[i] = (unsigned char)((nVersion >> (8 * i)) & 0xff);
    memcpy(out80 + 4, hashPrev.begin(), 32);
    memcpy(out80 + 36, hashBody.begin(), 32);
    for (int i = 0; i < 4; i++)
    {
        out80[68 + i] = (unsigned char)((params.nTime >> (8 * i)) & 0xff);
        out80[72 + i] = (unsigned char)((params.nBits >> (8 * i)) & 0xff);
        out80[76 + i] = (unsigned char)((nNonce32 >> (8 * i)) & 0xff);
    }
}

uint256 CGuardTicket::WorkHash(const CTicketParams& params, const uint256& hashSeed) const
{
    unsigned char header[80];
    WorkHeader(params, hashSeed, header);
    if (params.fnWork)
        return params.fnWork(header);
    // PoWHashHeader answers all ones when RandomX is not available, which
    // reads as work over the target and would score an honest sender. The
    // checked form tells "not known" apart; zero is this file's sign for it
    // (TICKET_DROP_NO_HASH, nobody scored).
    uint256 hash;
    if (!PoWHashHeaderChecked(header, hash))
        return 0;
    return hash;
}

bool CGuardTicket::Sign(const unsigned char seckey[32])
{
    secp256k1_context* ctx = TicketCtx();
    if (!ctx)
        return false;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey))
        return false;
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp))
        return false;
    secp256k1_xonly_pubkey_serialize(ctx, body + 12, &xpub);
    unsigned char digest[32];
    SigHash(digest);
    // No auxiliary randomness, as SignDescriptor: one key and one body give
    // one signature.
    bool fOk = secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL) == 1;
    memset(&kp, 0, sizeof(kp));
    return fOk;
}

bool CGuardTicket::VerifySig() const
{
    secp256k1_context* ctx = TicketCtx();
    if (!ctx)
        return false;
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, body + 12))
        return false;
    unsigned char digest[32];
    SigHash(digest);
    return secp256k1_schnorrsig_verify(ctx, sig, digest, 32, &xpub) == 1;
}

namespace pooltkt
{

bool XOnlyPubKey(const unsigned char seckey[32], unsigned char pubkeyOut[32])
{
    secp256k1_context* ctx = TicketCtx();
    if (!ctx)
        return false;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey))
        return false;
    secp256k1_xonly_pubkey xpub;
    bool fOk = secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp) == 1 &&
               secp256k1_xonly_pubkey_serialize(ctx, pubkeyOut, &xpub) == 1;
    memset(&kp, 0, sizeof(kp));
    return fOk;
}

bool MakeTicket(const CTicketParams& params, const uint256& hashSeed, unsigned int nEpoch,
                const unsigned char seckey[32], unsigned short nCapacityMB,
                uint64 nNonceStart, uint64 nMaxTries,
                CGuardTicket& ticketOut, uint256& hashWorkOut, uint64& nTriesOut,
                const volatile bool* pfStop)
{
    nTriesOut = 0;
    unsigned char pubkey[32];
    if (!XOnlyPubKey(seckey, pubkey))
        return false;
    CGuardTicket t;
    uint256 hashWork = 0;
    if (!MakeTicketWork(params, hashSeed, nEpoch, pubkey, nCapacityMB, nNonceStart, nMaxTries, t, hashWork,
                        nTriesOut, pfStop))
        return false;
    if (!t.Sign(seckey) || !t.VerifySig())
        return false;
    ticketOut = t;
    hashWorkOut = hashWork;
    return true;
}

bool MakeTicketWork(const CTicketParams& params, const uint256& hashSeed, unsigned int nEpoch,
                    const unsigned char pubkey[32], unsigned short nCapacityMB,
                    uint64 nNonceStart, uint64 nMaxTries,
                    CGuardTicket& ticketOut, uint256& hashWorkOut, uint64& nTriesOut,
                    const volatile bool* pfStop)
{
    nTriesOut = 0;
    const uint256 hashTarget = params.Target();
    CGuardTicket t;
    t.SetBody(params.magic, nEpoch, pubkey, nCapacityMB, nNonceStart);
    for (uint64 i = 0; i < nMaxTries; i++)
    {
        if (pfStop && *pfStop)
            return false;
        t.SetNonce(nNonceStart + i);
        uint256 hashWork = t.WorkHash(params, hashSeed);
        // Zero is a hash that was not computed: under every target, and no
        // ticket. Not counted as a try.
        if (hashWork == 0)
            return false;
        nTriesOut = i + 1;
        if (hashWork <= hashTarget)
        {
            ticketOut = t;
            hashWorkOut = hashWork;
            return true;
        }
    }
    return false;
}

int VerifyTicket(const CTicketParams& params, const CGuardTicket& ticket, const uint256& hashSeed,
                 uint256& hashWorkOut)
{
    hashWorkOut = 0;
    if (!ticket.VerifySig())
        return TICKET_BAD_SIG;
    const uint256 hashWork = ticket.WorkHash(params, hashSeed);
    // A hash that could not be computed must not pass for the best work
    // there is, and is not the sender's fault either.
    if (hashWork == 0)
        return TICKET_DROP_NO_HASH;
    if (hashWork > params.Target())
        return TICKET_BAD_WORK;
    hashWorkOut = hashWork;
    return TICKET_VERIFIED;
}

} // namespace pooltkt

// ---- the tickets a node holds ---------------------------------------------

const char* TicketVerdictName(int v)
{
    switch (v)
    {
    case TICKET_HELD:            return "held";
    case TICKET_OUTRANKED:       return "outranked for its key";
    case TICKET_PAST_CAP:        return "past the cap";
    case TICKET_PRECHECK_OK:     return "to be checked";
    case TICKET_VERIFIED:        return "signature and work passed";
    case TICKET_DROP_NO_HASH:    return "work hash not computed";
    case TICKET_DROP_EPOCH:      return "epoch out of range";
    case TICKET_DROP_NO_SEED:    return "seed not buried here";
    case TICKET_DROP_OTHER_SEED: return "another seed";
    case TICKET_DROP_DEADLINE:   return "after the deadline";
    case TICKET_DROP_SEEN:       return "already checked";
    case TICKET_BAD_FRAMING:     return "bad framing";
    case TICKET_BAD_MAGIC:       return "another network";
    case TICKET_BAD_EPOCH:       return "epoch not the message's";
    case TICKET_BAD_SIG:         return "bad signature";
    case TICKET_BAD_WORK:        return "work over the target";
    }
    return "?";
}

CTicketBook::CTicketBook(const CTicketParams& paramsIn) : params(paramsIn), nMaxGone(GUARD_MAX_GONE)
{
    // Without random bytes the tags still work; they are only no longer
    // this node's secret.
    memset(salt, 0, sizeof(salt));
    (void)RAND_bytes(salt, sizeof(salt));
}

void CTicketBook::Clear()
{
    mapEpochs.clear();
    mapDrawnSeed.clear();
    mapOldDrawSeed.clear();
}

uint64 CTicketBook::GoneTag(const uint256& hashBody) const
{
    uint256 h = hashBody;   // begin() is not const
    unsigned char buf[32 + 32];
    memcpy(buf, salt, 32);
    memcpy(buf + 32, h.begin(), 32);
    uint256 hashTag = Hash(buf, buf + sizeof(buf));
    uint64 n = 0;
    for (int i = 0; i < 8; i++)
        n |= (uint64)(*(hashTag.begin() + i)) << (8 * i);
    return n;
}

// An epoch nobody takes tickets for any more: before the previous one, or the
// previous one after its linger (the rule of EpochInRange, for what is held).
static bool EpochOver(const CTicketChainView& view, unsigned int nEpoch)
{
    const int nCur = pooltkt::EpochOf(view.TipHeight());
    if (nCur < 0)
        return false;
    if ((int64)nEpoch < (int64)nCur - 1)
        return true;
    return (int64)nEpoch == (int64)nCur - 1 && (int64)view.TipHeight() >= pooltkt::LingerEndHeight(nCur);
}

int CTicketBook::Precheck(const CTicketChainView& view, const unsigned char* p, size_t n,
                          unsigned int nMsgEpoch, const uint256& hashMsgSeed, bool fAnswer,
                          CGuardTicket& ticketOut) const
{
    // Step 1: framing and magic, the sender's fault.
    if (!ticketOut.FromBytes(p, n))
        return TICKET_BAD_FRAMING;
    if (!ticketOut.HasMagic(params.magic))
        return TICKET_BAD_MAGIC;
    if (!ticketOut.HasTag())
        return TICKET_BAD_FRAMING;
    const unsigned int nEpoch = ticketOut.Epoch();
    if (nEpoch != nMsgEpoch)
        return TICKET_BAD_EPOCH;

    // Step 2: innocent drops, before any hash.
    if (!pooltkt::EpochInRange(view, nEpoch))
        return TICKET_DROP_EPOCH;
    uint256 hashSeed = 0;
    bool fBuried = false;
    if (!pooltkt::TicketSeed(view, nEpoch, hashSeed, fBuried) || !fBuried)
        return TICKET_DROP_NO_SEED;
    if (hashMsgSeed != hashSeed)
        return TICKET_DROP_OTHER_SEED;
    if (!fAnswer && pooltkt::PastDeadline(view, nEpoch))
        return TICKET_DROP_DEADLINE;
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    if (it != mapEpochs.end() && it->second.hashSeed == hashSeed)
    {
        const uint256 hashBody = ticketOut.BodyHash();
        if (it->second.mapChecked.count(hashBody))
            return TICKET_DROP_SEEN;
        // A loose body that left the full checked set: it passed once and
        // can never be held under this seed, so it is not hashed again.
        if (!it->second.setGone.empty() && it->second.setGone.count(GoneTag(hashBody)))
            return TICKET_DROP_SEEN;
    }
    return TICKET_PRECHECK_OK;
}

void CTicketBook::Unhold(CTicketEpoch& ep, const std::vector<unsigned char>& key)
{
    std::map<std::vector<unsigned char>, CHeldTicket>::iterator it = ep.mapHeld.find(key);
    if (it == ep.mapHeld.end())
        return;
    const std::pair<uint256, uint256> k(it->second.hashWork, it->second.hashBody);
    ep.mapHeldOrder.erase(k);
    // Still a checked body, now one that may leave when the checked set fills.
    if (ep.mapChecked.count(it->second.hashBody))
        ep.setLoose.insert(k);
    ep.mapHeld.erase(it);
}

void CTicketBook::RememberChecked(CTicketEpoch& ep, const uint256& hashBody, const uint256& hashWork, bool fHeld)
{
    // Room first, so the newcomer is never the one to leave: the body with
    // the highest work hash among those not held goes.
    while (ep.mapChecked.size() >= GUARD_MAX_CHECKED && !ep.setLoose.empty())
    {
        std::set<std::pair<uint256, uint256> >::iterator itLast = ep.setLoose.end();
        --itLast;
        // Remembered by its tag from here on. When the tags are full too
        // (65536 bodies that each cost a ticket of work), one of them goes:
        // the lowest, which the salt makes nobody's choice.
        if (nMaxGone > 0)
        {
            while (ep.setGone.size() >= nMaxGone)
                ep.setGone.erase(ep.setGone.begin());
            ep.setGone.insert(GoneTag(itLast->second));
        }
        ep.mapChecked.erase(itLast->second);
        ep.setLoose.erase(itLast);
    }
    ep.mapChecked[hashBody] = hashWork;
    if (!fHeld)
        ep.setLoose.insert(std::make_pair(hashWork, hashBody));
}

int CTicketBook::Verify(const CGuardTicket& ticket, const uint256& hashSeed, uint256& hashWorkOut) const
{
    return pooltkt::VerifyTicket(params, ticket, hashSeed, hashWorkOut);
}

int CTicketBook::Add(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashSeed,
                     const uint256& hashWork)
{
    // What Verify gives is never zero and never over the target.
    if (hashWork == 0)
        return TICKET_DROP_NO_HASH;
    if (hashWork > params.Target())
        return TICKET_BAD_WORK;

    // The chain may have moved while the ticket was hashed: the seed it was
    // checked against must still be its epoch's buried seed here.
    const unsigned int nEpoch = ticket.Epoch();
    if (!pooltkt::EpochInRange(view, nEpoch))
        return TICKET_DROP_EPOCH;
    uint256 hashChainSeed = 0;
    bool fBuried = false;
    if (!pooltkt::TicketSeed(view, nEpoch, hashChainSeed, fBuried) || !fBuried)
        return TICKET_DROP_NO_SEED;
    if (hashChainSeed != hashSeed)
        return TICKET_DROP_OTHER_SEED;

    std::map<unsigned int, CTicketEpoch>::iterator itEp = mapEpochs.find(nEpoch);
    // A set checked against another seed is Sync's to drop, not this
    // ticket's: until then the ticket waits (it comes again, or in an
    // answer), and never joins that set.
    if (itEp != mapEpochs.end() && itEp->second.hashSeed != hashSeed)
        return TICKET_DROP_OTHER_SEED;
    if (itEp == mapEpochs.end())
    {
        // Never more than three epochs. With three held and this a fourth,
        // one of them is over and Sync has not been run: not taken until it
        // is.
        if (mapEpochs.size() >= TICKET_FILE_EPOCHS)
            return TICKET_DROP_EPOCH;
        CTicketEpoch epNew;
        epNew.nEpoch = nEpoch;
        epNew.hashSeed = hashSeed;
        itEp = mapEpochs.insert(std::make_pair(nEpoch, epNew)).first;
    }
    CTicketEpoch& ep = itEp->second;

    const uint256 hashBody = ticket.BodyHash();
    if (ep.mapChecked.count(hashBody))
        return TICKET_DROP_SEEN;
    if (!ep.setGone.empty() && ep.setGone.count(GoneTag(hashBody)))
        return TICKET_DROP_SEEN;

    const std::vector<unsigned char> key = ticket.Key();
    const std::pair<uint256, uint256> kNew(hashWork, hashBody);
    int nVerdict = TICKET_HELD;
    std::map<std::vector<unsigned char>, CHeldTicket>::iterator itHeld = ep.mapHeld.find(key);
    if (itHeld != ep.mapHeld.end())
    {
        // One per key: the lowest work hash is the ticket.
        const std::pair<uint256, uint256> kOld(itHeld->second.hashWork, itHeld->second.hashBody);
        if (kNew < kOld)
            Unhold(ep, key);
        else
            nVerdict = TICKET_OUTRANKED;
    }
    else if (ep.mapHeld.size() >= GUARD_MAX_TICKETS)
    {
        // The lowest work hashes are held, whatever the order they came in.
        std::map<std::pair<uint256, uint256>, std::vector<unsigned char> >::iterator itWorst = ep.mapHeldOrder.end();
        --itWorst;
        if (kNew < itWorst->first)
        {
            const std::vector<unsigned char> keyWorst = itWorst->second;
            Unhold(ep, keyWorst);
        }
        else
            nVerdict = TICKET_PAST_CAP;
    }

    RememberChecked(ep, hashBody, hashWork, nVerdict == TICKET_HELD);
    if (nVerdict == TICKET_HELD)
    {
        CHeldTicket h;
        h.ticket = ticket;
        h.hashWork = hashWork;
        h.hashBody = hashBody;
        ep.mapHeld[key] = h;
        ep.mapHeldOrder[kNew] = key;
    }
    return nVerdict;
}

int CTicketBook::Accept(const CTicketChainView& view, const unsigned char* p, size_t n,
                        unsigned int nMsgEpoch, const uint256& hashMsgSeed, bool fAnswer)
{
    CGuardTicket ticket;
    int v = Precheck(view, p, n, nMsgEpoch, hashMsgSeed, fAnswer, ticket);
    if (v != TICKET_PRECHECK_OK)
        return v;
    uint256 hashWork = 0;
    v = Verify(ticket, hashMsgSeed, hashWork);
    if (v != TICKET_VERIFIED)
        return v;
    return Add(view, ticket, hashMsgSeed, hashWork);
}

int CTicketBook::Accept(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashMsgSeed, bool fAnswer)
{
    const std::vector<unsigned char> v = ticket.Bytes();
    return Accept(view, &v[0], v.size(), ticket.Epoch(), hashMsgSeed, fAnswer);
}

int CTicketBook::AddOwn(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashSeed)
{
    int v = Accept(view, ticket, hashSeed, true);
    if (TicketPassed(v) || v == TICKET_DROP_SEEN)
        MarkOwn(ticket, hashSeed);
    return v;
}

int CTicketBook::AddOwnVerified(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashSeed,
                                const uint256& hashWork)
{
    const std::vector<unsigned char> b = ticket.Bytes();
    CGuardTicket t;
    int v = Precheck(view, &b[0], b.size(), ticket.Epoch(), hashSeed, true, t);
    if (v == TICKET_PRECHECK_OK)
        v = ticket.VerifySig() ? Add(view, ticket, hashSeed, hashWork) : (int)TICKET_BAD_SIG;
    if (TicketPassed(v) || v == TICKET_DROP_SEEN)
        MarkOwn(ticket, hashSeed);
    return v;
}

void CTicketBook::MarkOwn(const CGuardTicket& ticket, const uint256& hashSeed)
{
    std::map<unsigned int, CTicketEpoch>::iterator it = mapEpochs.find(ticket.Epoch());
    if (it == mapEpochs.end() || it->second.hashSeed != hashSeed)
        return;
    CTicketEpoch& ep = it->second;
    std::map<uint256, uint256>::const_iterator itC = ep.mapChecked.find(ticket.BodyHash());
    if (itC == ep.mapChecked.end())
        return;
    // The lowest of this node's tickets for the epoch is its ticket.
    if (!ep.fOwn || itC->second < ep.hashOwnWork)
    {
        ep.fOwn = true;
        ep.own = ticket;
        ep.hashOwnWork = itC->second;
    }
}

bool CTicketBook::Own(unsigned int nEpoch, CGuardTicket& ticketOut, uint256& hashWorkOut) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    if (it == mapEpochs.end() || !it->second.fOwn)
        return false;
    ticketOut = it->second.own;
    hashWorkOut = it->second.hashOwnWork;
    return true;
}

void CTicketBook::Sync(const CTicketChainView& view, CTicketSync& out)
{
    out = CTicketSync();
    const int64 nTip = view.TipHeight();
    for (std::map<unsigned int, CTicketEpoch>::iterator it = mapEpochs.begin(); it != mapEpochs.end(); )
    {
        const unsigned int e = it->first;
        if (EpochOver(view, e))
        {
            out.vExpired.push_back(e);
            mapEpochs.erase(it++);
            continue;
        }
        uint256 hashSeed = 0;
        bool fBuried = false;
        if (!pooltkt::TicketSeed(view, e, hashSeed, fBuried) || hashSeed != it->second.hashSeed)
        {
            out.vSeedGone.push_back(e);
            mapEpochs.erase(it++);
            continue;
        }
        ++it;
    }
    // Seeds drawn with before a redraw: forgotten when their linger is over.
    for (std::map<unsigned int, std::vector<std::pair<uint256, int64> > >::iterator it = mapOldDrawSeed.begin();
         it != mapOldDrawSeed.end(); )
    {
        std::vector<std::pair<uint256, int64> >& v = it->second;
        for (size_t i = 0; i < v.size(); )
        {
            if (nTip >= v[i].second)
                v.erase(v.begin() + i);
            else
                i++;
        }
        if (v.empty())
            mapOldDrawSeed.erase(it++);
        else
            ++it;
    }
    for (std::map<unsigned int, uint256>::iterator it = mapDrawnSeed.begin(); it != mapDrawnSeed.end(); )
    {
        const unsigned int e = it->first;
        if (EpochOver(view, e))
        {
            mapDrawnSeed.erase(it++);
            continue;
        }
        uint256 hashSeed = 0;
        bool fSettled = false;
        if (!pooltkt::DrawSeed(view, e, hashSeed, fSettled) || hashSeed != it->second)
        {
            // Section 10, Handoff: every node drawn by either seed holds the
            // pool until the later linger ends. The old seed stays until the
            // epoch's own linger end, and never less than a linger's length
            // from here, so the nodes drawn by the new seed have the same
            // time to pull as at any handoff.
            int64 nUntil = pooltkt::LingerEndHeight(e);
            if (nUntil < nTip + GUARD_LINGER_BLOCKS)
                nUntil = nTip + GUARD_LINGER_BLOCKS;
            std::vector<std::pair<uint256, int64> >& v = mapOldDrawSeed[e];
            bool fKnown = false;
            for (size_t i = 0; i < v.size(); i++)
                if (v[i].first == it->second)
                {
                    if (v[i].second < nUntil)
                        v[i].second = nUntil;
                    fKnown = true;
                }
            if (!fKnown)
            {
                if (v.size() >= GUARD_MAX_OLD_DRAW_SEEDS)
                    v.erase(v.begin());
                v.push_back(std::make_pair(it->second, nUntil));
            }
            out.vRedraw.push_back(e);
            out.vRedrawOldSeed.push_back(it->second);
            out.vRedrawUntil.push_back(nUntil);
            mapDrawnSeed.erase(it++);
            continue;
        }
        ++it;
    }
}

void CTicketBook::OldDrawSeeds(unsigned int nEpoch, std::vector<uint256>& out) const
{
    out.clear();
    std::map<unsigned int, std::vector<std::pair<uint256, int64> > >::const_iterator it = mapOldDrawSeed.find(nEpoch);
    if (it == mapOldDrawSeed.end())
        return;
    for (size_t i = 0; i < it->second.size(); i++)
        out.push_back(it->second[i].first);
}

void CTicketBook::OldDrawSeedsUntil(unsigned int nEpoch, std::vector<std::pair<uint256, int64> >& out) const
{
    out.clear();
    std::map<unsigned int, std::vector<std::pair<uint256, int64> > >::const_iterator it = mapOldDrawSeed.find(nEpoch);
    if (it != mapOldDrawSeed.end())
        out = it->second;
}

size_t CTicketBook::Gone(unsigned int nEpoch) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    return it == mapEpochs.end() ? 0 : it->second.setGone.size();
}

bool CTicketBook::IsGone(unsigned int nEpoch, const uint256& hashBody) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    return it != mapEpochs.end() && it->second.setGone.count(GoneTag(hashBody)) != 0;
}

bool CTicketBook::Has(unsigned int nEpoch) const
{
    return mapEpochs.count(nEpoch) != 0;
}

size_t CTicketBook::Held(unsigned int nEpoch) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    return it == mapEpochs.end() ? 0 : it->second.mapHeld.size();
}

size_t CTicketBook::Checked(unsigned int nEpoch) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    return it == mapEpochs.end() ? 0 : it->second.mapChecked.size();
}

bool CTicketBook::Seed(unsigned int nEpoch, uint256& hashOut) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    if (it == mapEpochs.end())
        return false;
    hashOut = it->second.hashSeed;
    return true;
}

void CTicketBook::Tickets(unsigned int nEpoch, std::vector<CHeldTicket>& out) const
{
    out.clear();
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    if (it == mapEpochs.end())
        return;
    const CTicketEpoch& ep = it->second;
    out.reserve(ep.mapHeld.size());
    for (std::map<std::pair<uint256, uint256>, std::vector<unsigned char> >::const_iterator io = ep.mapHeldOrder.begin();
         io != ep.mapHeldOrder.end(); ++io)
    {
        std::map<std::vector<unsigned char>, CHeldTicket>::const_iterator ih = ep.mapHeld.find(io->second);
        if (ih != ep.mapHeld.end())
            out.push_back(ih->second);
    }
}

bool CTicketBook::HeldByKey(unsigned int nEpoch, const unsigned char pubkey[32], CHeldTicket& out) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    if (it == mapEpochs.end())
        return false;
    std::map<std::vector<unsigned char>, CHeldTicket>::const_iterator ih =
        it->second.mapHeld.find(std::vector<unsigned char>(pubkey, pubkey + 32));
    if (ih == it->second.mapHeld.end())
        return false;
    out = ih->second;
    return true;
}

bool CTicketBook::IsChecked(unsigned int nEpoch, const uint256& hashBody) const
{
    std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.find(nEpoch);
    return it != mapEpochs.end() && it->second.mapChecked.count(hashBody) != 0;
}

std::vector<unsigned int> CTicketBook::Epochs() const
{
    std::vector<unsigned int> v;
    for (std::map<unsigned int, CTicketEpoch>::const_iterator it = mapEpochs.begin(); it != mapEpochs.end(); ++it)
        v.push_back(it->first);
    return v;
}

bool CTicketBook::Draw(const CTicketChainView& view, unsigned int nEpoch, const uint256& poolId,
                       std::vector<CDrawPlace>& out, bool& fSettledOut)
{
    out.clear();
    uint256 hashDraw = 0;
    if (!pooltkt::DrawSeed(view, nEpoch, hashDraw, fSettledOut))
        return false;
    if (fSettledOut)
        mapDrawnSeed[nEpoch] = hashDraw;
    // Only tickets checked against the seed this chain has now.
    uint256 hashSeed = 0, hashHeldSeed = 0;
    bool fBuried = false;
    std::vector<CHeldTicket> vTickets;
    if (pooltkt::TicketSeed(view, nEpoch, hashSeed, fBuried) && Seed(nEpoch, hashHeldSeed) && hashSeed == hashHeldSeed)
        Tickets(nEpoch, vTickets);
    pooltkt::Draw(hashDraw, poolId, vTickets, GUARD_PLACES + GUARD_RESERVE, out);
    return true;
}

bool CTicketBook::NoteDrawSeed(const CTicketChainView& view, unsigned int nEpoch, uint256& hashDrawOut, bool& fSettledOut)
{
    hashDrawOut = 0;
    if (!pooltkt::DrawSeed(view, nEpoch, hashDrawOut, fSettledOut))
        return false;
    if (fSettledOut)
        mapDrawnSeed[nEpoch] = hashDrawOut;
    return true;
}

bool CTicketBook::OwnRanks(const CTicketChainView& view, unsigned int nEpoch, const std::vector<uint256>& vPools,
                           std::vector<int>& vRankOut, bool& fSettledOut)
{
    vRankOut.assign(vPools.size(), -1);
    uint256 hashDraw = 0;
    if (!pooltkt::DrawSeed(view, nEpoch, hashDraw, fSettledOut))
        return false;
    if (fSettledOut)
        mapDrawnSeed[nEpoch] = hashDraw;
    OwnRanksBySeed(view, nEpoch, hashDraw, vPools, vRankOut);
    return true;
}

void CTicketBook::OwnRanksBySeed(const CTicketChainView& view, unsigned int nEpoch, const uint256& hashDrawSeed,
                                 const std::vector<uint256>& vPools, std::vector<int>& vRankOut) const
{
    vRankOut.assign(vPools.size(), -1);
    uint256 hashSeed = 0, hashHeldSeed = 0;
    bool fBuried = false;
    if (!pooltkt::TicketSeed(view, nEpoch, hashSeed, fBuried) || !Seed(nEpoch, hashHeldSeed) || hashSeed != hashHeldSeed)
        return;
    // Only a ticket other nodes hold too can be drawn: this node's own, if
    // it is in the held set.
    CGuardTicket own;
    uint256 hashOwnWork = 0;
    CHeldTicket held;
    if (!Own(nEpoch, own, hashOwnWork) || !HeldByKey(nEpoch, own.PubKey(), held) || held.hashWork != hashOwnWork)
        return;
    std::vector<CHeldTicket> vTickets;
    Tickets(nEpoch, vTickets);
    const unsigned int nPlaces = GUARD_PLACES + GUARD_RESERVE;
    for (size_t i = 0; i < vPools.size(); i++)
    {
        unsigned int r = pooltkt::RankOf(hashDrawSeed, vPools[i], vTickets, hashOwnWork, nPlaces);
        vRankOut[i] = r < nPlaces ? (int)r : -1;
    }
}

// ---- the draw -------------------------------------------------------------

namespace pooltkt
{

uint256 Score(const uint256& hashDrawSeed, const uint256& poolId, const uint256& hashWork)
{
    uint256 a = hashDrawSeed, b = poolId, c = hashWork;   // begin() is not const
    unsigned char buf[16 + 32 * 3];
    memcpy(buf, DRAW_DOMAIN, 16);
    memcpy(buf + 16, a.begin(), 32);
    memcpy(buf + 48, b.begin(), 32);
    memcpy(buf + 80, c.begin(), 32);
    return Hash(buf, buf + sizeof(buf));
}

static bool PlaceBefore(const CDrawPlace& a, const CDrawPlace& b)
{
    if (a.hashScore != b.hashScore)
        return a.hashScore < b.hashScore;
    if (a.hashWork != b.hashWork)
        return a.hashWork < b.hashWork;
    return a.key < b.key;
}

void Draw(const uint256& hashDrawSeed, const uint256& poolId, const std::vector<CHeldTicket>& vTickets,
          unsigned int nPlaces, std::vector<CDrawPlace>& out)
{
    out.clear();
    out.reserve(vTickets.size());
    for (size_t i = 0; i < vTickets.size(); i++)
    {
        CDrawPlace p;
        p.hashWork = vTickets[i].hashWork;
        p.hashScore = Score(hashDrawSeed, poolId, p.hashWork);
        p.key = vTickets[i].ticket.Key();
        p.nCapacityMB = vTickets[i].ticket.CapacityMB();
        out.push_back(p);
    }
    if (out.size() > nPlaces)
    {
        std::partial_sort(out.begin(), out.begin() + nPlaces, out.end(), PlaceBefore);
        out.resize(nPlaces);
    }
    else
        std::sort(out.begin(), out.end(), PlaceBefore);
}

unsigned int RankOf(const uint256& hashDrawSeed, const uint256& poolId, const std::vector<CHeldTicket>& vTickets,
                    const uint256& hashWork, unsigned int nPlaces)
{
    const uint256 hashMine = Score(hashDrawSeed, poolId, hashWork);
    unsigned int nBelow = 0;
    for (size_t i = 0; i < vTickets.size() && nBelow < nPlaces; i++)
    {
        if (vTickets[i].hashWork == hashWork)
            continue;
        const uint256 s = Score(hashDrawSeed, poolId, vTickets[i].hashWork);
        if (s < hashMine || (s == hashMine && vTickets[i].hashWork < hashWork))
            nBelow++;
    }
    return nBelow;
}

// ---- the guard budget -----------------------------------------------------

static int GuardTier(const CGuardDecision& d)
{
    if (d.nRank < 0)
        return 2;
    return d.nRank < (int)GUARD_PLACES ? 0 : 1;
}

static bool GuardBefore(const CGuardDecision& a, const CGuardDecision& b)
{
    const int ta = GuardTier(a), tb = GuardTier(b);
    if (ta != tb)
        return ta < tb;
    if (a.line.fKnown != b.line.fKnown)
        return a.line.fKnown;
    if (a.line.fKnown && a.line.bnWork != b.line.bnWork)
        return a.line.bnWork > b.line.bnWork;
    return a.poolId < b.poolId;
}

void ChooseGuarded(const std::vector<uint256>& vPools, const std::vector<int>& vRanks,
                   GuardLineFn fnLine, void* pCtx,
                   int64 nBudgetBytes, int64 nMaxPoolBytes, unsigned int nMaxPools,
                   std::vector<CGuardDecision>& vOut)
{
    vOut.clear();
    vOut.reserve(vPools.size());
    for (size_t i = 0; i < vPools.size(); i++)
    {
        CGuardDecision d;
        d.poolId = vPools[i];
        d.nRank = i < vRanks.size() ? vRanks[i] : -1;
        if (d.nRank >= (int)(GUARD_PLACES + GUARD_RESERVE))
            d.nRank = -1;
        if (d.nRank >= 0 && fnLine)
            fnLine(pCtx, d.poolId, d.line);
        vOut.push_back(d);
    }
    std::sort(vOut.begin(), vOut.end(), GuardBefore);

    int64 nLeft = nBudgetBytes;
    unsigned int nKept = 0;
    for (size_t i = 0; i < vOut.size(); i++)
    {
        CGuardDecision& d = vOut[i];
        if (d.nRank < 0)
            d.nChoice = GUARD_NOT_DRAWN;
        else if (!d.line.fKnown)
            d.nChoice = GUARD_PULL;
        else if (d.line.nShares == 0)
            d.nChoice = GUARD_EMPTY;
        else if (nKept < nMaxPools && d.line.nBytes >= 0 && d.line.nBytes <= nMaxPoolBytes && d.line.nBytes <= nLeft)
        {
            d.nChoice = GUARD_KEEP;
            nKept++;
            nLeft -= d.line.nBytes;
        }
        else
            d.nChoice = GUARD_NO_ROOM;
    }
}

// ---- pool-tickets.dat -----------------------------------------------------

bool SaveTicketFile(const std::string& strPath, const CTicketBook& book)
{
    if (strPath.empty())
        return false;
    return WriteTicketFileData(strPath, TicketFileData(book));
}

bool WriteTicketFileData(const std::string& strPath, const std::string& data)
{
    std::string err;
    if (strPath.empty() || !WriteFileAtomicPrivate(strPath, data, err))
    {
        printf("pool tickets: %s\n", err.empty() ? "no path" : err.c_str());
        return false;
    }
    return true;
}

std::string TicketFileData(const CTicketBook& book)
{
    std::vector<CTicketFileEpoch> vEpochs;
    const std::map<unsigned int, CTicketEpoch>& all = book.All();
    for (std::map<unsigned int, CTicketEpoch>::const_iterator it = all.begin(); it != all.end(); ++it)
    {
        CTicketFileEpoch fe;
        fe.nEpoch = it->first;
        fe.hashSeed = it->second.hashSeed;
        if (it->second.fOwn)
            fe.vOwn.push_back(it->second.own);
        std::vector<CHeldTicket> vHeld;
        book.Tickets(it->first, vHeld);
        for (size_t i = 0; i < vHeld.size(); i++)
            fe.vTickets.push_back(vHeld[i].ticket);
        vEpochs.push_back(fe);
    }
    CDataStream ss(SER_DISK);
    ss << TICKET_FILE_VERSION << FLATDATA(book.Params().magic) << vEpochs;
    uint256 h = Hash(ss.begin(), ss.end());
    std::string data(ss.begin(), ss.end());
    data.append((const char*)h.begin(), 32);
    return data;
}

bool LoadTicketFile(const std::string& strPath, const CTicketParams& params,
                    std::vector<CTicketFileEpoch>& vOut, std::string& strWhyOut)
{
    vOut.clear();
    strWhyOut.clear();
    if (strPath.empty())
    {
        strWhyOut = "no path";
        return false;
    }
    FILE* f = fopen(strPath.c_str(), "rb");
    if (!f)
    {
        strWhyOut = "no file";
        return false;
    }
    std::vector<char> buf;
    char tmp[65536];
    size_t n;
    bool fTooBig = false;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
    {
        if (buf.size() + n > TICKET_FILE_MAX)
        {
            fTooBig = true;
            break;
        }
        buf.insert(buf.end(), tmp, tmp + n);
    }
    fclose(f);

    std::vector<CTicketFileEpoch> v;
    if (fTooBig)
        strWhyOut = "too large";
    else if (buf.size() < 4 + 4 + 1 + 32)
        strWhyOut = "too short";
    else
    {
        uint256 hashFile = 0;
        memcpy(hashFile.begin(), &buf[buf.size() - 32], 32);
        if (Hash(buf.begin(), buf.end() - 32) != hashFile)
            strWhyOut = "checksum";
        else
        {
            try
            {
                CDataStream ss(&buf[0], &buf[0] + buf.size() - 32, SER_DISK);
                int nVersion = 0;
                unsigned char magic[4];
                ss >> nVersion;
                if (nVersion != TICKET_FILE_VERSION)
                    strWhyOut = "another version";
                else
                {
                    ss >> FLATDATA(magic);
                    if (memcmp(magic, params.magic, 4) != 0)
                        strWhyOut = "another network";
                    else
                    {
                        ss >> v;
                        if (!ss.empty())
                            strWhyOut = "trailing bytes";
                    }
                }
            }
            catch (std::exception& e)
            {
                strWhyOut = "unreadable";
            }
        }
    }
    if (strWhyOut.empty())
    {
        // What a file of this node's own making always is; anything else was
        // not written by SaveTicketFile and none of it is used.
        if (v.size() > TICKET_FILE_EPOCHS)
            strWhyOut = "inconsistent: too many epochs";
        for (size_t i = 0; strWhyOut.empty() && i < v.size(); i++)
        {
            const CTicketFileEpoch& fe = v[i];
            if (i > 0 && fe.nEpoch <= v[i - 1].nEpoch)
                strWhyOut = "inconsistent: epochs out of order";
            else if (fe.vOwn.size() > 1)
                strWhyOut = "inconsistent: more than one own ticket";
            else if (fe.vTickets.size() > GUARD_MAX_TICKETS)
                strWhyOut = "inconsistent: too many tickets";
            for (size_t j = 0; strWhyOut.empty() && j < fe.vOwn.size() + fe.vTickets.size(); j++)
            {
                const CGuardTicket& t = j < fe.vOwn.size() ? fe.vOwn[j] : fe.vTickets[j - fe.vOwn.size()];
                if (!t.HasMagic(params.magic) || !t.HasTag() || t.Epoch() != fe.nEpoch)
                    strWhyOut = "inconsistent: a ticket of another epoch or network";
            }
        }
    }
    if (!strWhyOut.empty())
        return false;
    vOut.swap(v);
    return true;
}

size_t RestoreTickets(CTicketBook& book, const CTicketChainView& view, const std::vector<CTicketFileEpoch>& vFile)
{
    size_t nHeld = 0;
    for (size_t i = 0; i < vFile.size(); i++)
    {
        const CTicketFileEpoch& fe = vFile[i];
        for (size_t j = 0; j < fe.vOwn.size(); j++)
            book.AddOwn(view, fe.vOwn[j], fe.hashSeed);
        for (size_t j = 0; j < fe.vTickets.size(); j++)
            book.Accept(view, fe.vTickets[j], fe.hashSeed, true);
        uint256 hashSeed = 0;
        if (book.Seed(fe.nEpoch, hashSeed) && hashSeed == fe.hashSeed)
            nHeld += book.Held(fe.nEpoch);
    }
    return nHeld;
}

} // namespace pooltkt
