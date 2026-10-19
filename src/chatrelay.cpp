// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See chatrelay.h.

#include "headers.h"
#include "chatrelay.h"
#include "chatstore.h"

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

static CCriticalSection cs_chatStore;
static ChatStore g_chatStore;

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
    if (nNow - pfrom->nChatWindowStart >= 60)
    {
        pfrom->nChatWindowStart = nNow;
        pfrom->nChatPutsInWindow = 0;
        pfrom->nChatQueriesInWindow = 0;
    }
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
static int Take(CNode* pfrom, const std::vector<unsigned char>& blob,
                unsigned char idOut[32], std::string& whyOut)
{
    memset(idOut, 0, 32);
    ChatRecord r;
    if (blob.empty() || !r.Parse(&blob[0], blob.size()))
    {
        whyOut = "not a chat record";
        return ChatStore::REJECTED;
    }
    int nResult = ChatStore::REJECTED;
    CRITICAL_BLOCK(cs_chatStore)
        nResult = g_chatStore.Accept(VerifyContext(), r, GetAdjustedTime(), whyOut, idOut);
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
           strCommand == "chatget" || strCommand == "getchatinv";
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
        unsigned char id[32];
        std::string why;
        int n = Take(pfrom, blob, id, why);
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
            nResult = Take(pfrom, blob, &vId[0], why);
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
                        if (nBytes + w.size() > CHAT_MAX_ANSWER_BYTES)
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
        pfrom->PushMessage("chatrecs", nReq, vAnswer);
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
