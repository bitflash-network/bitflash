// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_net.h"

using namespace p2pool;

CCriticalSection cs_p2pool;

// Shares whose parent has not arrived, by parent id; tried again when it does.
// MAX_ORPHAN_SHARES caps the shares held, not the parents waited on: every
// one of them may be tried, with a RandomX hash, the moment its parent comes.
// Under cs_p2pool.
struct OrphanShare
{
    Share share;
    int64 nTime;   // when it came
};
static map<uint256, vector<OrphanShare> > mapOrphanShares;
static set<uint256> setOrphanIds;
static const size_t MAX_ORPHAN_SHARES = 256;
// A parent that has not come in this long is not coming: shares waiting on
// one that never existed would otherwise hold their places for good, and a
// full queue takes no more.
static const int64 ORPHAN_EXPIRY = 20 * 60;
static const size_t MAX_GETSH = 500;
static const size_t SHARES_PER_MESSAGE = 400;
// A share is a block header, a coinbase paying at most one output per share
// of the window, and a merkle branch; this is several times what that takes.
static const size_t MAX_SHARE_BYTES = 256 * 1024;
static const size_t MAX_MERKLE_BRANCH = 32;
// A peer gets our history once in this long; it is the biggest thing this
// code sends, and asking is cheap.
static const int64 SYNC_SERVE_INTERVAL = 10 * 60;
// How long after asking a peer for its history this node takes it. Deep
// shares in a history are taken on their work alone; a peer allowed to send
// one whenever it liked could slip such shares in at any time.
static const int64 SYNC_ANSWER_WINDOW = 5 * 60;
// A share this many heights past our tip, whose parent we lack, means a line
// we have not got: its history is asked for, not its shares one by one, which
// would take more orphans than the queue holds.
static const int SYNC_GAP = 2 * MAX_UNCLE_DEPTH + 10;
// This many shares waiting for parents means a line we lack whose heights
// kept pace with ours (two halves of a partition, each retargeted to 10 s):
// its history is asked for too.
static const size_t ORPHAN_BACKLOG = 32;
// A part of a history: at most this many bytes, whatever the share count, so
// no message nears the protocol's limit however many addresses a window pays.
static const size_t HISTORY_PART_BYTES = 2 * 1000 * 1000;

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

static void WriteShares(int nTipHeight, const vector<Share>& v)
{
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

// Not under cs_p2pool: the line is copied under it, and written after, so
// the few MB of a history do not go to disk with the share chain locked.
static void MaybeSaveShares()
{
    static int64 nLastSave = 0;
    vector<Share> v;
    int nTipHeight;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (GetTime() - nLastSave < 120)
            return;
        nLastSave = GetTime();
        P2PoolChain().History(v);
        nTipHeight = P2PoolChain().Height(P2PoolChain().Tip());
    }
    WriteShares(nTipHeight, v);
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

int64 NodeMainView::Now() const
{
    return GetAdjustedTime();
}

static void RelayShare(const Share& s, CNode* pfrom)
{
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            // Not before its version: the framing is not settled until then.
            // Not to a node that drops shares unread.
            if (pnode != pfrom && pnode->nVersion != 0 && (pnode->nServices & NODE_P2POOL))
                pnode->PushMessage("p2pshare", s);
}

// Cheap checks a share must pass before anything else is spent on it.
static bool ShareSane(const Share& s)
{
    return ::GetSerializeSize(s, SER_NETWORK) <= MAX_SHARE_BYTES &&
           s.vMerkleBranch.size() <= MAX_MERKLE_BRANCH;
}

// When this node first asked a peer for its line, this run.
static int64 nFirstHistoryAsk = 0;

static void AskHistory(CNode* pfrom)
{
    pfrom->nP2PoolSyncAskedAt = GetTime();
    pfrom->nP2PoolHistoryRecv = 0;
    CRITICAL_BLOCK(cs_p2pool)
        if (!nFirstHistoryAsk)
            nFirstHistoryAsk = GetTime();
    pfrom->PushMessage("p2psync");
}

// Templates wait for the first answers only. Measured from the latest ask,
// every new peer of a node still without a tip -- one fed nothing but shares
// taken on trust, say -- put mining off by another five minutes.
bool P2PoolAwaitingHistory()
{
    return P2PoolChain().Empty() && nFirstHistoryAsk && GetTime() - nFirstHistoryAsk < SYNC_ANSWER_WINDOW;
}

// Ids of shares whose parent was missing and whose work was checked lately,
// queued or not. The queue holds 256; without this a peer cycling 257
// precomputed orphans cost a RandomX hash per message, for nothing. A share
// seen here is hashed again only when its parent is here, and it is checked
// in full. Under cs_p2pool.
static set<uint256> setOrphanSeen;
static std::deque<uint256> qOrphanSeen;
static const size_t MAX_ORPHAN_SEEN = 20000;

static bool OrphanSeen(const uint256& id)
{
    return setOrphanSeen.count(id) != 0;
}

static void MarkOrphanSeen(const uint256& id)
{
    if (!setOrphanSeen.insert(id).second)
        return;
    qOrphanSeen.push_back(id);
    if (qOrphanSeen.size() > MAX_ORPHAN_SEEN)
    {
        setOrphanSeen.erase(qOrphanSeen.front());
        qOrphanSeen.pop_front();
    }
}

// And those whose work failed: the sender is blamed again without a hash.
static set<uint256> setOrphanBadWork;
static std::deque<uint256> qOrphanBadWork;

static bool OrphanBadWork(const uint256& id)
{
    return setOrphanBadWork.count(id) != 0;
}

static void MarkOrphanBadWork(const uint256& id)
{
    if (!setOrphanBadWork.insert(id).second)
        return;
    qOrphanBadWork.push_back(id);
    if (qOrphanBadWork.size() > MAX_ORPHAN_SEEN)
    {
        setOrphanBadWork.erase(qOrphanBadWork.front());
        qOrphanBadWork.pop_front();
    }
}

// Under cs_p2pool.
static void ForgetOrphan(const uint256& id)
{
    setOrphanIds.erase(id);
}

// Above this many bytes waiting to go to a peer, nothing big is added: a
// peer that asks and never reads would otherwise hold every answer in memory.
static const size_t MAX_SEND_QUEUED = 4 * 1000 * 1000;

static size_t SendQueued(CNode* pnode)
{
    size_t n;
    CRITICAL_BLOCK(pnode->cs_vSend)
        n = pnode->vSend.size();
    return n;
}

static bool SendQueueFull(CNode* pnode)
{
    return SendQueued(pnode) > MAX_SEND_QUEUED;
}

// A history may queue more, once per peer per SYNC_SERVE_INTERVAL: it is a
// few MB while windows pay a few hundred addresses.
static const size_t MAX_HISTORY_QUEUED = 32 * 1000 * 1000;

static bool HistoryQueueFull(CNode* pnode)
{
    return SendQueued(pnode) > MAX_HISTORY_QUEUED;
}

// Under cs_p2pool. Room for one more orphan: the expired go first, then, if
// the queue is still full, the oldest one.
static void MakeOrphanRoom()
{
    int64 nNow = GetTime();
    map<uint256, vector<OrphanShare> >::iterator itOldest = mapOrphanShares.end();
    size_t iOldest = 0;
    for (map<uint256, vector<OrphanShare> >::iterator it = mapOrphanShares.begin(); it != mapOrphanShares.end();)
    {
        vector<OrphanShare>& v = it->second;
        for (size_t i = 0; i < v.size();)
        {
            if (nNow - v[i].nTime > ORPHAN_EXPIRY)
            {
                ForgetOrphan(v[i].share.GetId());
                v.erase(v.begin() + i);
            }
            else
                i++;
        }
        if (v.empty())
        {
            mapOrphanShares.erase(it++);
            continue;
        }
        for (size_t i = 0; i < v.size(); i++)
            if (itOldest == mapOrphanShares.end() || v[i].nTime < itOldest->second[iOldest].nTime)
            {
                itOldest = it;
                iOldest = i;
            }
        ++it;
    }
    if (setOrphanIds.size() < MAX_ORPHAN_SHARES || itOldest == mapOrphanShares.end())
        return;
    ForgetOrphan(itOldest->second[iOldest].share.GetId());
    itOldest->second.erase(itOldest->second.begin() + iOldest);
    if (itOldest->second.empty())
        mapOrphanShares.erase(itOldest);
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
        uint256 id = cur.GetId();
        string err;
        vector<uint256> vMissing;
        bool fBlock = false;
        bool fOk;
        int nTipHeight;
        CBigNum bnTipNext;   // the target a share on our tip must meet
        CRITICAL_BLOCK(cs_p2pool)
        {
            fOk = P2PoolChain().Add(cur, main, err, &vMissing, &fBlock);
            nTipHeight = P2PoolChain().Height(P2PoolChain().Tip());
            bnTipNext.SetCompact(P2PoolChain().NextShareBits(P2PoolChain().Tip()));
        }
        if (fOk)
        {
            LogPrint("p2pool", "p2pool: share %s height %u accepted%s\n",
                     id.ToString().substr(0, 12).c_str(), cur.data.nShareHeight,
                     fBlock ? " (it is a block)" : "");
            if (fBlock)
                LogBlockPayouts(cur);
            MaybeSaveShares();
            CRITICAL_BLOCK(cs_p2pool)
            {
                map<uint256, vector<OrphanShare> >::iterator it = mapOrphanShares.find(id);
                if (it != mapOrphanShares.end())
                {
                    foreach(const OrphanShare& o, it->second)
                    {
                        todo.push_back(o.share);
                        ForgetOrphan(o.share.GetId());
                    }
                    mapOrphanShares.erase(it);
                }
            }
            if (pfrom)
                pfrom->nP2PoolLastGood = GetTime();   // it passes shares on (net.cpp)
            if (!fHistory)
                RelayShare(cur, pfrom);
        }
        else if (!vMissing.empty())
        {
            // Waits on the first share it lacks; if more are missing when that
            // one comes, it waits again on the next. Every one is asked for now.
            CBigNum bnCur;
            bnCur.SetCompact(cur.data.nShareBits);
            // Nothing is spent on a share too far below our tip to matter, or
            // far easier than one on it: an archive of old honest shares,
            // replayed, cost a RandomX hash each under cs_main.
            if (nTipHeight >= 0 &&
                ((int64)cur.data.nShareHeight + (int64)HISTORY_SHARES < (int64)nTipHeight || bnCur > bnTipNext * 4))
            {
                fFirst = false;
                continue;
            }
            // One whose work was checked lately is not hashed again; it waits
            // again, and what it lacks is asked for again. That check came
            // after the hash once, and the same share sent over and over cost
            // a RandomX hash each time; and dropping it instead left a child
            // whose uncle came after its parent waiting for good.
            bool fSeen, fBad;
            CRITICAL_BLOCK(cs_p2pool)
            {
                fSeen = OrphanSeen(id);
                fBad = !fSeen && OrphanBadWork(id);
            }
            if (fBad)
            {
                if (fFirst)
                    fGood = false;
                fFirst = false;
                continue;
            }
            if (!fSeen)
            {
                // Held only if its own work is real: a share's RandomX hash
                // needs nothing but the share, and without this check anybody
                // could queue shares by the thousand for free.
                bool fBlockW;
                string errWork;
                bool fWork = CheckShareWork(cur, bnProofOfWorkLimit, fBlockW, errWork);
                CRITICAL_BLOCK(cs_p2pool)
                {
                    if (fWork)
                        MarkOrphanSeen(id);
                    else
                        MarkOrphanBadWork(id);
                }
                if (!fWork)
                {
                    if (fFirst)
                        fGood = false;   // no work behind it: the sender made it up
                    fFirst = false;
                    continue;
                }
            }
            size_t nWaiting;
            CRITICAL_BLOCK(cs_p2pool)
            {
                if (!setOrphanIds.count(id))
                {
                    MakeOrphanRoom();
                    setOrphanIds.insert(id);
                    OrphanShare o;
                    o.share = cur;
                    o.nTime = GetTime();
                    mapOrphanShares[vMissing[0]].push_back(o);
                }
                nWaiting = setOrphanIds.size();
            }
            if (pfrom)
            {
                pfrom->PushMessage("p2pgetsh", vMissing);
                // A history is the one thing this node takes partly on trust,
                // so only a share with real work opens the door to one: as
                // hard as one on our tip when it claims to be far ahead, or
                // within a factor of four when shares pile up waiting for
                // parents -- the sign of a line we lack, after a partition,
                // whose heights kept pace with ours.
                bool fFar = (int64)cur.data.nShareHeight > (int64)nTipHeight + SYNC_GAP && bnCur <= bnTipNext;
                bool fPiling = nWaiting >= ORPHAN_BACKLOG && bnCur <= bnTipNext * 4;
                if ((nTipHeight < 0 || fFar || fPiling) &&
                    GetTime() - pfrom->nP2PoolSyncAskedAt >= SYNC_SERVE_INTERVAL)
                {
                    LogPrint("p2pool", "p2pool: share at height %u, our tip at %d, %u waiting: asking that peer for its line\n",
                             cur.data.nShareHeight, nTipHeight, (unsigned)nWaiting);
                    AskHistory(pfrom);
                }
            }
        }
        else if (!InnocentRefusal(err))
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
        fOk = P2PoolChain().Add(share, main, errOut, NULL, &fBlock);
    if (fOk)
        MaybeSaveShares();
    if (pfBlock)
        *pfBlock = fBlock;
    if (fOk && fBlock)
        LogBlockPayouts(share);
    if (fOk)
        RelayShare(share, NULL);
    return fOk;
}

// The P2Pool peers this node reached and names to another: at most this many.
static const size_t MAX_P2P_PEER_HINTS = 32;

void P2PoolOnVersion(CNode* pfrom)
{
    // A node from before P2Pool would leave the question unanswered, and the
    // wait for its answer would hold back this node's templates.
    if (!(pfrom->nServices & NODE_P2POOL))
        return;

    // Who else holds the share chain, as far as this node has seen: a miner
    // whose ordinary peers predate P2Pool learns where to look.
    vector<string> vKnown;
    BtfKnownP2PoolPeers(vKnown, MAX_P2P_PEER_HINTS);
    if (!vKnown.empty())
        pfrom->PushMessage("p2ppeers", vKnown);

    // Every peer while this node has no tip, and the first few in any case:
    // the line with the most work wins, so one peer's history -- honest or
    // not -- cannot keep out a better one, and a line saved hours ago is
    // brought up to date. This asked by how many shares were held, and the
    // first peers to answer could fill that count with lines of no work.
    static int nAskedOnVersion = 0;
    bool fAsk;
    CRITICAL_BLOCK(cs_p2pool)
        fAsk = P2PoolChain().Empty() || nAskedOnVersion < 4;
    if (fAsk)
    {
        nAskedOnVersion++;
        AskHistory(pfrom);
    }
}

bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "p2pshare")
    {
        Share s;
        vRecv >> s;
        if (!ShareSane(s) || !AcceptShare(s, pfrom, false))
            pfrom->Misbehaving(20);
        return true;
    }

    if (strCommand == "p2ppeers")
    {
        // Hints only: a name already in our peer cache that we know nothing
        // about moves up the list a P2Pool miner dials. A lie costs one dial;
        // whether a peer holds the share chain is still its own version's
        // word, and nothing here is passed on.
        vector<string> vAddr;
        vRecv >> vAddr;
        if (vAddr.size() > MAX_P2P_PEER_HINTS)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        // Once per connection: each one reads and rewrites the peer cache.
        if (pfrom->fP2PoolPeersRecv)
            return true;
        pfrom->fP2PoolPeersRecv = true;
        BtfNoteP2PoolHints(vAddr);
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
        // or a fork, which the tip's own line does not contain. Not while
        // this peer has not read what it was sent already.
        if (SendQueueFull(pfrom))
            return true;
        vector<Share> vOut;
        CRITICAL_BLOCK(cs_p2pool)
        {
            Share s;
            for (size_t i = 0; i < vIds.size(); i++)
                if (P2PoolChain().GetShare(vIds[i], s))
                    vOut.push_back(s);
        }
        foreach(const Share& s, vOut)
        {
            if (SendQueueFull(pfrom))
                break;
            pfrom->PushMessage("p2pshare", s);
        }
        return true;
    }

    if (strCommand == "p2psync")
    {
        // A few bytes in, a whole history out: once per peer per interval.
        if (pfrom->nP2PoolSyncServed && GetTime() - pfrom->nP2PoolSyncServed < SYNC_SERVE_INTERVAL)
            return true;
        if (SendQueueFull(pfrom))
            return true;
        pfrom->nP2PoolSyncServed = GetTime();
        vector<Share> history;
        int nTipHeight;
        CRITICAL_BLOCK(cs_p2pool)
        {
            P2PoolChain().History(history);
            nTipHeight = P2PoolChain().Height(P2PoolChain().Tip());
        }
        // In parts of at most SHARES_PER_MESSAGE shares and HISTORY_PART_BYTES
        // bytes: by count alone, a window paying a few thousand addresses
        // made a part bigger than any message may be, and the honest sender
        // was dropped and blamed for it.
        vector<Share> part;
        size_t nPartBytes = 0;
        for (size_t i = 0; i < history.size(); i++)
        {
            size_t n = ::GetSerializeSize(history[i], SER_NETWORK);
            if (!part.empty() && (part.size() >= SHARES_PER_MESSAGE || nPartBytes + n > HISTORY_PART_BYTES))
            {
                if (HistoryQueueFull(pfrom))
                    return true;
                pfrom->PushMessage("p2pshares", nTipHeight, part);
                part.clear();
                nPartBytes = 0;
            }
            part.push_back(history[i]);
            nPartBytes += n;
        }
        if (!part.empty() && !HistoryQueueFull(pfrom))
            pfrom->PushMessage("p2pshares", nTipHeight, part);
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
        // A history is what this node asks a peer for, not something a peer
        // may push: only from one we asked, soon after asking, and no more
        // than one history per asking.
        if (pfrom->nP2PoolSyncAskedAt == 0 || GetTime() - pfrom->nP2PoolSyncAskedAt > SYNC_ANSWER_WINDOW)
            return true;
        pfrom->nP2PoolHistoryRecv += part.size();
        // A history holds the line and the uncles it names, up to two a share.
        if (pfrom->nP2PoolHistoryRecv > 3 * HISTORY_SHARES + 2 * SHARES_PER_MESSAGE)
            return true;
        int64 nTop = 0;
        foreach(const Share& s, part)
        {
            if (!ShareSane(s))
            {
                pfrom->Misbehaving(20);
                return true;
            }
            nTop = std::max(nTop, (int64)s.data.nShareHeight);
        }
        // Which shares are deep enough to take on their work alone depends on
        // the tip height the peer states; it cannot state one further above
        // what it sends than a history reaches.
        nTipHeight = (int)std::min((int64)nTipHeight, std::min(nTop + (int64)HISTORY_SHARES, (int64)p2pool::MAX_SHARE_HEIGHT));
        NodeMainView main;
        string err;
        bool fOk = true;
        CRITICAL_BLOCK(cs_p2pool)
            fOk = P2PoolChain().AddHistory(part, nTipHeight, main, err);
        if (!fOk)
        {
            LogPrint("p2pool", "p2pool: history refused: %s\n", err.c_str());
            pfrom->Misbehaving(20);
        }
        return true;
    }

    return false;
}
