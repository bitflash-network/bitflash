// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_net.h"

using namespace p2pool;

CCriticalSection cs_p2pool;

// Shares whose parent has not arrived, by parent id; tried again when it does.
static map<uint256, vector<Share> > mapOrphanShares;
static const size_t MAX_ORPHAN_SHARES = 256;
static const size_t MAX_GETSH = 500;
static const size_t SHARES_PER_MESSAGE = 400;

ShareChain& P2PoolChain()
{
    static ShareChain* pChain = NULL;
    if (!pChain)
        pChain = new ShareChain(bnProofOfWorkLimit);
    return *pChain;
}

bool NodeMainView::BlockInfo(const uint256& hash, int& nHeightOut, unsigned int& nNextBitsOut) const
{
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi == mapBlockIndex.end() || !mi->second->IsInMainChain())
        return false;
    nHeightOut = mi->second->nHeight;
    nNextBitsOut = GetNextWorkRequired(mi->second);
    return true;
}

int NodeMainView::TipHeight() const
{
    return nBestHeight;
}

int64 NodeMainView::Now() const
{
    return GetAdjustedTime();
}

static void RelayShare(const Share& s, CNode* pfrom)
{
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom)
                pnode->PushMessage("p2pshare", s);
}

// Refusals that say nothing bad about the sender: it may simply be ahead of
// us, or a moment behind.
static bool Innocent(const string& err)
{
    return err == "already have this share" || err == "unknown parent share" ||
           err == "mined on a main block this node does not have" ||
           err == "mined on a stale main block" ||
           err == "the payout window reaches shares this node does not have";
}

// Add a share and whatever was waiting for it. Returns false only on a
// share that is bad in itself.
static bool AcceptShare(const Share& s, CNode* pfrom, bool fHistory)
{
    NodeMainView main;
    vector<Share> todo(1, s);
    bool fFirst = true, fGood = true;
    while (!todo.empty())
    {
        Share cur = todo.back();
        todo.pop_back();
        string err;
        bool fMissing = false, fBlock = false;
        bool fOk;
        CRITICAL_BLOCK(cs_p2pool)
            fOk = P2PoolChain().Add(cur, main, err, &fMissing, &fBlock, fHistory);
        if (fOk)
        {
            LogPrint("p2pool", "p2pool: share %s height %u accepted%s\n",
                     cur.GetId().ToString().substr(0, 12).c_str(), cur.data.nShareHeight,
                     fBlock ? " (it is a block)" : "");
            if (!fHistory)
                RelayShare(cur, pfrom);
            map<uint256, vector<Share> >::iterator it = mapOrphanShares.find(cur.GetId());
            if (it != mapOrphanShares.end())
            {
                todo.insert(todo.end(), it->second.begin(), it->second.end());
                mapOrphanShares.erase(it);
            }
        }
        else if (fMissing)
        {
            if (mapOrphanShares.size() < MAX_ORPHAN_SHARES)
                mapOrphanShares[cur.data.hashPrevShare].push_back(cur);
            if (pfrom)
                pfrom->PushMessage("p2pgetsh", vector<uint256>(1, cur.data.hashPrevShare));
        }
        else if (!Innocent(err))
        {
            LogPrint("p2pool", "p2pool: share %s refused: %s\n", cur.GetId().ToString().substr(0, 12).c_str(), err.c_str());
            if (fFirst)
                fGood = false;
        }
        fFirst = false;
    }
    return fGood;
}

bool P2PoolSubmitShare(const Share& share, string& errOut, bool* pfBlock)
{
    NodeMainView main;
    bool fOk;
    CRITICAL_BLOCK(cs_p2pool)
        fOk = P2PoolChain().Add(share, main, errOut, NULL, pfBlock);
    if (fOk)
        RelayShare(share, NULL);
    return fOk;
}

void P2PoolOnVersion(CNode* pfrom)
{
    bool fEmpty;
    CRITICAL_BLOCK(cs_p2pool)
        fEmpty = P2PoolChain().Size() == 0;
    if (fEmpty)
        pfrom->PushMessage("p2psync");
}

bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "p2pshare")
    {
        Share s;
        vRecv >> s;
        if (!AcceptShare(s, pfrom, false))
            pfrom->Misbehaving(20);
        return true;
    }

    if (strCommand == "p2pgetsh")
    {
        vector<uint256> vIds;
        vRecv >> vIds;
        if (vIds.size() > MAX_GETSH)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        vector<Share> vOut;
        CRITICAL_BLOCK(cs_p2pool)
        {
            vector<Share> history;
            P2PoolChain().History(history);
            map<uint256, const Share*> byId;
            for (size_t i = 0; i < history.size(); i++)
                byId[history[i].GetId()] = &history[i];
            for (size_t i = 0; i < vIds.size(); i++)
                if (byId.count(vIds[i]))
                    vOut.push_back(*byId[vIds[i]]);
        }
        foreach(const Share& s, vOut)
            pfrom->PushMessage("p2pshare", s);
        return true;
    }

    if (strCommand == "p2psync")
    {
        vector<Share> history;
        int nTipHeight;
        CRITICAL_BLOCK(cs_p2pool)
        {
            P2PoolChain().History(history);
            nTipHeight = P2PoolChain().Height(P2PoolChain().Tip());
        }
        for (size_t i = 0; i < history.size(); i += SHARES_PER_MESSAGE)
        {
            vector<Share> part(history.begin() + i,
                               history.begin() + std::min(history.size(), i + SHARES_PER_MESSAGE));
            pfrom->PushMessage("p2pshares", nTipHeight, part);
        }
        return true;
    }

    if (strCommand == "p2pshares")
    {
        int nTipHeight;
        vector<Share> part;
        vRecv >> nTipHeight >> part;
        if (part.size() > SHARES_PER_MESSAGE)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        NodeMainView main;
        string err;
        bool fOk = true;
        CRITICAL_BLOCK(cs_p2pool)
        {
            // Only while this node is starting: a history is what it asks
            // for, not something a peer may push on a running chain.
            if (P2PoolChain().Size() >= HISTORY_SHARES)
                return true;
            fOk = P2PoolChain().AddHistory(part, nTipHeight, main, err);
        }
        if (!fOk)
        {
            LogPrint("p2pool", "p2pool: history refused: %s\n", err.c_str());
            pfrom->Misbehaving(20);
        }
        return true;
    }

    return false;
}
