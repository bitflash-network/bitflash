// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See chatrelay.h.

#include "headers.h"
#include "chatrelay.h"
#include "chatstore.h"
#include "chatdir.h"

#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>

using btfchat::ChatRecord;
using btfchat::ChatStore;

// The ration, per peer, per minute. A person's chat app leaves a handful of
// records an hour; sixty a minute is a lot of conversation and very little
// flood. Nodes relaying to each other get far more, because a node that just
// connected may be catching up on thousands at once -- and a relayed record
// passed the same checks as any other, so volume from a node is not a threat
// to anything but CPU, which the work check keeps cheap.
static const int CHAT_PUTS_PER_MINUTE      = 60;
static const int CHAT_RELAYED_PER_MINUTE   = 6000;
static const int CHAT_QUERIES_PER_MINUTE   = 1200;
// How often a peer may ask for our whole inventory, and how much of it it gets.
static const int64 CHAT_INV_INTERVAL       = 10 * 60;
static const size_t CHAT_INV_OFFER         = 5000;

// The per-connection rations above live in CNode, so a peer that reconnects
// starts afresh, and an onion peer can reconnect as often as it likes. These
// are the same rations for all connections together: what the node takes in a
// minute, and what it serves, however many connections ask.
static const int CHAT_PUTS_PER_MINUTE_ALL     = 600;
static const int CHAT_RELAYED_PER_MINUTE_ALL  = 20000;
// Answer bytes per minute for one connection, and a generous figure for all of
// them together. One chatget can ask for CHAT_MAX_ANSWER_BYTES; a connection
// may not turn that into an unbounded stream by asking again before reading.
// The shared figure is far above what honest mailbox reads add up to (it is
// there so that many connections together cannot saturate the node's link); a
// tight one would let a few connections starve everybody's reads.
static const size_t CHAT_ANSWER_BYTES_PER_MINUTE     = 16 * 1024 * 1024;
static const size_t CHAT_ANSWER_BYTES_PER_MINUTE_ALL = 256 * 1024 * 1024;
// And never more than this waiting in one connection's send buffer: a peer
// that asks and does not read gets empty answers until it reads.
static const size_t CHAT_MAX_SEND_QUEUED = 2 * 1024 * 1024;
// Records announced to us by one peer that we have not received yet. A
// chatrec is taken only for an id the same peer announced (we asked it), so
// nothing arrives unsolicited. Entries older than this are forgotten.
static const size_t CHAT_MAX_ASKED_PER_PEER = CHAT_INV_OFFER + 1000;
static const int64  CHAT_ASKED_TTL          = 15 * 60;

static CCriticalSection cs_chatStore;
static ChatStore g_chatStore;

// The node-wide minute, see above.
static CCriticalSection cs_chatAll;
static int64  g_nChatAllWindowStart = 0;
static int    g_nChatAllPuts = 0;
static int    g_nChatAllRelayed = 0;
static size_t g_nChatAllAnswerBytes = 0;

static void RationAll(int64 nNow)
{
    if (nNow - g_nChatAllWindowStart >= 60 || nNow < g_nChatAllWindowStart)
    {
        g_nChatAllWindowStart = nNow;
        g_nChatAllPuts = 0;
        g_nChatAllRelayed = 0;
        g_nChatAllAnswerBytes = 0;
    }
}

// Is there room in a node-wide ration this minute (nothing is taken)?
static bool RationOpen(int64 nNow, int nCounter, int nMax)
{
    bool fOk = false;
    CRITICAL_BLOCK(cs_chatAll)
    {
        RationAll(nNow);
        fOk = nCounter < nMax;
    }
    return fOk;
}

// Take one from a node-wide ration; false once it is spent for this minute.
static bool TakeAll(int64 nNow, int& nCounter, int nMax)
{
    bool fOk = false;
    CRITICAL_BLOCK(cs_chatAll)
    {
        RationAll(nNow);
        fOk = ++nCounter <= nMax;
    }
    return fOk;
}

void ChatRelayRations(int& nPuts, int& nRelayed)
{
    CRITICAL_BLOCK(cs_chatAll)
    {
        nPuts = g_nChatAllPuts;
        nRelayed = g_nChatAllRelayed;
    }
}

// For the self-tests. They run from the release binary (-selftest=...), so this
// is not compiled out; it only ever empties a ration.
void ChatRelayExhaustRations()
{
    CRITICAL_BLOCK(cs_chatAll)
    {
        g_nChatAllWindowStart = GetTime();
        g_nChatAllPuts = CHAT_PUTS_PER_MINUTE_ALL;
        g_nChatAllRelayed = CHAT_RELAYED_PER_MINUTE_ALL;
    }
}

#ifdef BITFLASH_FUZZ
// Fuzzing only (never in a release build): records with real work cannot be
// made at fuzzing speed, so the harness replaces the store with one whose work
// rule is nBits, and resets the node-wide rations between inputs.
void ChatRelayFuzzReset(unsigned int nBits)
{
    CRITICAL_BLOCK(cs_chatStore)
        g_chatStore = ChatStore(nBits);
    CRITICAL_BLOCK(cs_chatAll)
        g_nChatAllWindowStart = 0;
}
#endif

static secp256k1_context* VerifyContext()
{
    // One context for the life of the process. Verification needs no secret,
    // so no blinding and nothing to wipe.
    static secp256k1_context* ctx = NULL;
    static CCriticalSection cs_ctx;
    CRITICAL_BLOCK(cs_ctx)
        if (!ctx)
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

static void Ration(CNode* pfrom, int64 nNow)
{
    if (nNow - pfrom->nChatWindowStart >= 60 || nNow < pfrom->nChatWindowStart)
    {
        pfrom->nChatWindowStart = nNow;
        pfrom->nChatPutsInWindow = 0;
        pfrom->nChatQueriesInWindow = 0;
        pfrom->nChatAnswerBytesInWindow = 0;
    }
}

void ChatRelayNoteAnnounced(CNode* pfrom, const uint256& hash)
{
    if (!pfrom)
        return;
    int64 nNow = GetTime();
    std::map<uint256, int64>& m = pfrom->mapChatAsked;
    if (m.size() >= CHAT_MAX_ASKED_PER_PEER)
    {
        // Full. Forget what this peer announced long ago and never sent, but
        // look through the list at most once a minute: an inv may name tens of
        // thousands of records, and each would otherwise rescan all of it.
        if (nNow - pfrom->nChatAskedPurged < 60 && pfrom->nChatAskedPurged <= nNow)
            return;
        pfrom->nChatAskedPurged = nNow;
        for (std::map<uint256, int64>::iterator it = m.begin(); it != m.end(); )
        {
            if (nNow - it->second > CHAT_ASKED_TTL || it->second > nNow)
                m.erase(it++);
            else
                ++it;
        }
        if (m.size() >= CHAT_MAX_ASKED_PER_PEER)
            return;   // still full: its chatrec for this id will be refused
    }
    m[hash] = nNow;
}

// Did this peer announce the record (so that we asked it for it)? Consumes
// the entry.
static bool WasAnnounced(CNode* pfrom, const std::vector<unsigned char>& blob)
{
    ChatRecord r;
    if (blob.empty() || !r.Parse(&blob[0], blob.size()))
        return false;
    unsigned char id[32];
    r.Id(id);
    uint256 h;
    memcpy(h.begin(), id, 32);
    std::map<uint256, int64>::iterator it = pfrom->mapChatAsked.find(h);
    if (it == pfrom->mapChatAsked.end())
        return false;
    pfrom->mapChatAsked.erase(it);
    return true;
}

static CInv InvFor(const unsigned char id[32])
{
    uint256 h;
    memcpy(h.begin(), id, 32);
    return CInv(MSG_CHATREC, h);
}

// Offer a record we just took to every other peer that holds chat records.
// Never to the one it came from, and never to a peer that did not say it holds
// them -- a node from before the chat would not know the inventory type.
static void Announce(const unsigned char id[32], CNode* pfrom)
{
    CInv inv = InvFor(id);
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
        {
            if (pnode == pfrom || pnode->nVersion == 0)
                continue;
            if (!(pnode->nServices & NODE_CHAT))
                continue;
            pnode->PushInventory(inv);
        }
}

// Check and keep one record. `pfrom` is where it came from, for the relay.
//
// The node-wide ration (pnAll against nAllMax) is charged only for a record
// that parses, shows the work the store asks and is kept: a junk record, or a
// replay of one already held, costs its sender a refusal and nobody else
// anything, so the ration cannot be spent for free.
// A record relayed by another node is judged by the base work, not by how
// full this node's own store is (fRelayed); a chat app's put is judged by both.
static int Take(CNode* pfrom, const std::vector<unsigned char>& blob,
                unsigned char idOut[32], std::string& whyOut, bool fRelayed, int* pnAll, int nAllMax)
{
    memset(idOut, 0, 32);
    ChatRecord r;
    if (blob.empty() || !r.Parse(&blob[0], blob.size()))
    {
        whyOut = "not a chat record";
        return ChatStore::REJECTED;
    }
    int nResult = ChatStore::REJECTED;
    bool fWorked = false;
    CRITICAL_BLOCK(cs_chatStore)
    {
        // What has expired no longer counts towards how full the store is.
        g_chatStore.Expire(GetAdjustedTime());
        fWorked = ChatRecordWork(r) >= g_chatStore.RequiredBits(r.kind, r.payload.size(), fRelayed);
        if (!fWorked)
            nResult = g_chatStore.Accept(VerifyContext(), r, GetAdjustedTime(), whyOut, idOut, fRelayed);
    }
    if (fWorked)
    {
        // Looked at before and charged after: only a record that is kept costs
        // the node's minute. A replay of one already held (a duplicate), an
        // expired or future-dated one, costs its sender a refusal and nobody
        // else anything.
        if (!RationOpen(GetTime(), *pnAll, nAllMax))
        {
            whyOut = "this node is taking too many records right now; slow down";
            return ChatStore::REJECTED;
        }
        CRITICAL_BLOCK(cs_chatStore)
            nResult = g_chatStore.Accept(VerifyContext(), r, GetAdjustedTime(), whyOut, idOut, fRelayed);
        if (nResult == ChatStore::ACCEPTED)
            TakeAll(GetTime(), *pnAll, nAllMax);
    }
    if (pfrom)
        pfrom->AddInventoryKnown(InvFor(idOut));
    if (nResult == ChatStore::ACCEPTED)
        Announce(idOut, pfrom);
    return nResult;
}

bool ChatRelayAlreadyHave(const CInv& inv)
{
    uint256 h = inv.hash;   // uint256::begin() is not const
    CRITICAL_BLOCK(cs_chatStore)
        return g_chatStore.Has(h.begin());
    return true;
}

bool ChatRelayServeGetData(CNode* pfrom, const CInv& inv)
{
    if (inv.type != MSG_CHATREC)
        return false;
    ChatRecord r;
    bool fHave = false;
    uint256 h = inv.hash;
    CRITICAL_BLOCK(cs_chatStore)
        fHave = g_chatStore.Get(h.begin(), r);
    if (fHave)
        pfrom->PushMessage("chatrec", r.Serialize());
    return true;
}

void ChatRelayOnVersion(CNode* pfrom)
{
#ifndef BITFLASH_CHAT_APP
    if ((pfrom->nServices & NODE_CHAT) && (nLocalServices & NODE_CHAT))
        pfrom->PushMessage("getchatinv");
#else
    (void)pfrom;
#endif
}

void ChatRelayStats(size_t& nRecords, size_t& nEnvelopeBytes)
{
    nRecords = 0;
    nEnvelopeBytes = 0;
    CRITICAL_BLOCK(cs_chatStore)
    {
        nRecords = g_chatStore.Count();
        nEnvelopeBytes = g_chatStore.Bytes(btfchat::CHATREC_ENVELOPE);
    }
}

bool ChatRelayProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
#ifdef BITFLASH_CHAT_APP
    // The app holds nothing and answers nothing. It speaks to nodes with its
    // own client (btfchatnet.cpp), not through this.
    (void)pfrom; (void)vRecv;
    return strCommand == "chatrec" || strCommand == "chatput" ||
           strCommand == "chatget" || strCommand == "getchatinv" ||
           strCommand == "getchatdir";
#else
    int64 nNow = GetTime();

    if (strCommand == "chatrec")
    {
        // A record another node is relaying, normally one we asked for.
        Ration(pfrom, nNow);
        if (++pfrom->nChatPutsInWindow > CHAT_RELAYED_PER_MINUTE)
            return true;
        std::vector<unsigned char> blob;
        vRecv >> blob;
        // Only what this peer announced and we asked for: an unsolicited
        // record costs its sender nothing to send and us a work check.
        if (!WasAnnounced(pfrom, blob))
        {
            LogPrint("net", "chatrec: not asked of %s, ignored\n", pfrom->addr.ToString().c_str());
            return true;
        }
        unsigned char id[32];
        std::string why;
        int n = Take(pfrom, blob, id, why, true, &g_nChatAllRelayed, CHAT_RELAYED_PER_MINUTE_ALL);
        if (n == ChatStore::REJECTED)
            LogPrint("net", "chatrec: refused from %s: %s\n",
                     pfrom->addr.ToString().c_str(), why.c_str());
        return true;
    }

    if (strCommand == "chatput")
    {
        // A record from somebody's chat app. It gets an answer either way: the
        // app has to know whether its message is somewhere, and a silent drop
        // looks exactly like success.
        unsigned int nReq = 0;
        std::vector<unsigned char> blob;
        vRecv >> nReq >> blob;
        Ration(pfrom, nNow);
        std::vector<unsigned char> vId(32, 0);
        int nResult = ChatStore::REJECTED;
        std::string why;
        if (++pfrom->nChatPutsInWindow > CHAT_PUTS_PER_MINUTE)
            why = "too many records from this connection; slow down";
        else
            nResult = Take(pfrom, blob, &vId[0], why, false, &g_nChatAllPuts, CHAT_PUTS_PER_MINUTE_ALL);
        pfrom->PushMessage("chatack", nReq, vId, nResult, why);
        return true;
    }

    if (strCommand == "chatget")
    {
        unsigned int nReq = 0;
        std::vector<CChatQuery> vQuery;
        vRecv >> nReq >> vQuery;
        Ration(pfrom, nNow);

        std::vector<std::vector<std::vector<unsigned char> > > vAnswer;
        size_t nBytes = 0;
        bool fCut = false;
        // What this answer may carry: the per-message cap, less what this
        // connection and (generously) the node have been served this minute,
        // and nothing while the peer has not read what it was sent.
        size_t nQueued = 0;
        CRITICAL_BLOCK(pfrom->cs_vSend)
            nQueued = pfrom->vSend.size();
        size_t nAllowed = CHAT_MAX_ANSWER_BYTES;
        if (nQueued >= CHAT_MAX_SEND_QUEUED)
            nAllowed = 0;
        size_t nConnLeft = pfrom->nChatAnswerBytesInWindow >= CHAT_ANSWER_BYTES_PER_MINUTE ? 0 :
                           CHAT_ANSWER_BYTES_PER_MINUTE - pfrom->nChatAnswerBytesInWindow;
        nAllowed = std::min(nAllowed, nConnLeft);
        CRITICAL_BLOCK(cs_chatAll)
        {
            RationAll(nNow);
            nAllowed = std::min(nAllowed, g_nChatAllAnswerBytes >= CHAT_ANSWER_BYTES_PER_MINUTE_ALL ? (size_t)0 :
                                          CHAT_ANSWER_BYTES_PER_MINUTE_ALL - g_nChatAllAnswerBytes);
        }
        if (nAllowed == 0)
            fCut = true;
        CRITICAL_BLOCK(cs_chatStore)
        {
            g_chatStore.Expire(GetAdjustedTime());
            for (size_t i = 0; i < vQuery.size() && i < CHAT_MAX_QUERIES_PER_MSG; i++)
            {
                std::vector<std::vector<unsigned char> > one;
                // Over the ration, or over the answer size, a question still
                // gets an answer -- an empty one -- so the app's answers stay
                // lined up with its questions.
                if (++pfrom->nChatQueriesInWindow <= CHAT_QUERIES_PER_MINUTE && !fCut)
                {
                    std::vector<ChatRecord> recs;
                    int nMax = vQuery[i].nMax;
                    if (nMax < 0) nMax = 0;
                    g_chatStore.Query(vQuery[i].kind, vQuery[i].key, vQuery[i].nSince,
                                      (size_t)nMax, recs);
                    for (size_t k = 0; k < recs.size(); k++)
                    {
                        std::vector<unsigned char> w = recs[k].Serialize();
                        if (nBytes + w.size() > nAllowed)
                        {
                            fCut = true;
                            break;
                        }
                        nBytes += w.size();
                        one.push_back(w);
                    }
                }
                vAnswer.push_back(one);
            }
        }
        pfrom->nChatAnswerBytesInWindow += nBytes;
        CRITICAL_BLOCK(cs_chatAll)
            g_nChatAllAnswerBytes += nBytes;
        pfrom->PushMessage("chatrecs", nReq, vAnswer);
        return true;
    }

    if (strCommand == "getchatdir")
    {
        // The public community directory as this node has read it off the
        // chain (chatdir.h). Public data; rationed like any question.
        unsigned int nReq = 0;
        vRecv >> nReq;
        Ration(pfrom, nNow);
        std::vector<CChatListing> v;
        if (++pfrom->nChatQueriesInWindow <= CHAT_QUERIES_PER_MINUTE)
        {
            ChatDirectoryListings(v);
            if (v.size() > CHAT_DIRECTORY_MAX)
                v.erase(v.begin(), v.end() - CHAT_DIRECTORY_MAX);   // the newest
        }
        pfrom->PushMessage("chatdir", nReq, ChatDirectoryHeight(), v);
        return true;
    }

    if (strCommand == "getchatinv")
    {
        if (nNow - pfrom->nLastChatInvAsked < CHAT_INV_INTERVAL)
            return true;
        pfrom->nLastChatInvAsked = nNow;
        std::vector<std::vector<unsigned char> > ids;
        CRITICAL_BLOCK(cs_chatStore)
        {
            g_chatStore.Expire(GetAdjustedTime());
            g_chatStore.Ids(CHAT_INV_OFFER, ids);
        }
        if (ids.empty())
            return true;
        std::vector<CInv> vInv;
        vInv.reserve(ids.size());
        for (size_t i = 0; i < ids.size(); i++)
            vInv.push_back(InvFor(&ids[i][0]));
        pfrom->PushMessage("inv", vInv);
        return true;
    }

    return false;
#endif
}
