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

// The share chain lives in p2pool.dat between runs: what History() returns,
// oldest first, read back the way a peer's history is (work alone for the
// deep end, in full for the newest RETARGET_SHARES). Without it a restart
// started a new chain at height 0 until a peer answered.
static string P2PoolFile()
{
    return GetAppDir() + "/p2pool.dat";
}

static void LoadShares(ShareChain& chain)
{
    vector<Share> v;
    int nTipHeight = 0;
    try
    {
        CAutoFile file(fopen(P2PoolFile().c_str(), "rb"));
        if (!file)
            return;
        file >> nTipHeight >> v;
    }
    catch (std::exception& e)
    {
        printf("p2pool: %s unreadable (%s); starting from peers\n", P2PoolFile().c_str(), e.what());
        return;
    }
    NodeMainView main;   // the caller holds cs_main
    string err;
    if (!chain.AddHistory(v, nTipHeight, main, err))
        printf("p2pool: saved share chain refused (%s); starting from peers\n", err.c_str());
    printf("p2pool: %u shares loaded, tip at height %d\n", (unsigned)chain.Size(), chain.Height(chain.Tip()));
}

static void SaveShares(const ShareChain& chain)
{
    vector<Share> v;
    chain.History(v);
    int nTipHeight = chain.Height(chain.Tip());
    string tmp = P2PoolFile() + ".new";
    {
        CAutoFile file(fopen(tmp.c_str(), "wb"));
        if (!file)
            return;
        file << nTipHeight << v;
    }
    // Windows will not rename over an existing file.
    remove(P2PoolFile().c_str());
    rename(tmp.c_str(), P2PoolFile().c_str());
}

ShareChain& P2PoolChain()
{
    static ShareChain* pChain = NULL;
    if (!pChain)
        pChain = new ShareChain(bnProofOfWorkLimit);
    return *pChain;
}

void P2PoolInit()
{
    // cs_main before cs_p2pool, the order every other caller takes them in.
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
            LoadShares(P2PoolChain());
}

// Under cs_p2pool.
static void MaybeSaveShares()
{
    static int64 nLastSave = 0;
    if (GetTime() - nLastSave < 120)
        return;
    nLastSave = GetTime();
    SaveShares(P2PoolChain());
}

// A share that is also a block: what its coinbase pays, so every node -- not
// only the finder's -- can be audited against its own share chain.
static void LogBlockPayouts(const Share& s)
{
    int nHeight = 0;
    CoinbaseHeight(s.coinbase, nHeight);
    printf("p2pool: share %s is a block on main height %d; its coinbase pays:\n",
           s.GetId().ToString().substr(0, 12).c_str(), nHeight);
    foreach(const CTxOut& o, s.coinbase.vout)
    {
        uint160 h;
        vector<vector<unsigned char> > vSol;
        txnouttype type;
        string strTo = SolverTyped(o.scriptPubKey, type, vSol) && type == TX_PUBKEYHASH
                     ? Hash160ToAddress(uint160(vSol[0])) : HexStr(o.scriptPubKey.begin(), o.scriptPubKey.end());
        printf("p2pool:   %s %s\n", FormatMoney(o.nValue).c_str(), strTo.c_str());
    }
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
           err == "an unknown uncle" ||
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
        vector<uint256> vMissing;
        bool fBlock = false;
        bool fOk;
        CRITICAL_BLOCK(cs_p2pool)
            fOk = P2PoolChain().Add(cur, main, err, &vMissing, &fBlock, fHistory);
        if (fOk)
        {
            LogPrint("p2pool", "p2pool: share %s height %u accepted%s\n",
                     cur.GetId().ToString().substr(0, 12).c_str(), cur.data.nShareHeight,
                     fBlock ? " (it is a block)" : "");
            if (fBlock)
                LogBlockPayouts(cur);
            CRITICAL_BLOCK(cs_p2pool)
                MaybeSaveShares();
            if (!fHistory)
                RelayShare(cur, pfrom);
            map<uint256, vector<Share> >::iterator it = mapOrphanShares.find(cur.GetId());
            if (it != mapOrphanShares.end())
            {
                todo.insert(todo.end(), it->second.begin(), it->second.end());
                mapOrphanShares.erase(it);
            }
        }
        else if (!vMissing.empty())
        {
            // Waits on the first share it lacks; if more are missing when that
            // one comes, it waits again on the next. Every one is asked for now.
            if (mapOrphanShares.size() < MAX_ORPHAN_SHARES)
            {
                vector<Share>& v = mapOrphanShares[vMissing[0]];
                bool fQueued = false;
                for (size_t i = 0; i < v.size() && !fQueued; i++)
                    fQueued = v[i].GetId() == cur.GetId();
                if (!fQueued)
                    v.push_back(cur);
            }
            if (pfrom)
                pfrom->PushMessage("p2pgetsh", vMissing);
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
    bool fOk, fBlock = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = P2PoolChain().Add(share, main, errOut, NULL, &fBlock);
        if (fOk)
            MaybeSaveShares();
    }
    if (pfBlock)
        *pfBlock = fBlock;
    if (fOk && fBlock)
        LogBlockPayouts(share);
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
        // Any share held, on any line: what is asked for is usually an uncle
        // or a fork, which the tip's own line does not contain.
        vector<Share> vOut;
        CRITICAL_BLOCK(cs_p2pool)
        {
            Share s;
            for (size_t i = 0; i < vIds.size(); i++)
                if (P2PoolChain().GetShare(vIds[i], s))
                    vOut.push_back(s);
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
