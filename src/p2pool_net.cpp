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

static ShareChain* pP2PoolChain = NULL;

ShareChain& P2PoolChain()
{
    if (!pP2PoolChain)
        pP2PoolChain = new ShareChain(bnProofOfWorkLimit);
    return *pP2PoolChain;
}

void P2PoolBudget::Refill(int64 nNow)
{
    if (nLast == 0 || nNow < nLast)
    {
        nLast = nNow;
        return;
    }
    int64 nNew = (nNow - nLast) / nSecsPerToken;
    if (nNew <= 0)
        return;
    if (nNew >= nCapacity - nTokens)
    {
        nTokens = nCapacity;
        nLast = nNow;
    }
    else
    {
        nTokens += (int)nNew;
        nLast += nNew * nSecsPerToken;
    }
}

bool P2PoolBudget::Take(int64 nNow)
{
    Refill(nNow);
    if (nTokens <= 0)
        return false;
    nTokens--;
    return true;
}

int P2PoolBudget::Tokens(int64 nNow)
{
    Refill(nNow);
    return nTokens;
}

// RandomX hashes of shares that unproven peers send unasked (H4 of the DoS
// review). An honest network makes a share every ten seconds; each reaches
// this node once over a proven peer in the usual case, and duplicates cost no
// hash. Under cs_p2pool.
static P2PoolBudget budgetShareWork(32, 2);
// Histories sent to unproven peers: the biggest thing this code sends, a few
// bytes asking for it, and a new connection resets every per-peer throttle.
static P2PoolBudget budgetHistoryServe(4, 60);
// Histories asked of unproven peers: each one is up to three histories of
// shares to hash. Peers this node dialled are asked as before.
static P2PoolBudget budgetHistoryAsk(2, 60);

// A peer that has since sent something wrong is not proven any more: the
// status is not otherwise taken back within a connection, and what it could
// cause before it is cut off is not worth a free pass.
bool P2PoolPeerProven(const CNode* pnode)
{
    return (!pnode->fInbound || pnode->nP2PoolLastGood != 0) && pnode->nMisbehavior == 0;
}

// Under cs_p2pool. Whether a connection older than this one has a share (or
// a history ask) held for the budgets (see the held entries below).
static bool OlderHeld(const CNode* pnode, bool fShare);

// The shared budget behind WorkGate, for one peer's share. A share that
// comes in live waits behind any held for an older connection: else whoever
// sends the most, on fresh connections, takes every token as it refills, and
// the held share of an honest peer that stayed is never reached.
class PeerWorkGate : public WorkGate
{
public:
    PeerWorkGate(const CNode* pnodeIn, bool fFromQueueIn) : pnode(pnodeIn), fFromQueue(fFromQueueIn) {}
    bool Allow()
    {
        bool f;
        CRITICAL_BLOCK(cs_p2pool)
            f = (fFromQueue || !OlderHeld(pnode, true)) && budgetShareWork.Take(GetTime());
        return f;
    }
private:
    const CNode* pnode;
    bool fFromQueue;
};

// Unproven peers go through the gate.
static bool NeedsGate(const CNode* pfrom)
{
    return pfrom && !P2PoolPeerProven(pfrom);
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

// Whether this node may ask that peer for its history now: always one it
// dialled or one that sent a share it took; an unproven peer only while the
// shared budget lasts. Each ask is up to three histories of shares to hash.
static bool HistoryAskAllowed(CNode* pfrom)
{
    if (P2PoolPeerProven(pfrom))
        return true;
    bool f;
    CRITICAL_BLOCK(cs_p2pool)
        f = budgetHistoryAsk.Take(GetTime());
    return f;
}

// Templates wait for the first answers only. Measured from the latest ask,
// every new peer of a node still without a tip -- one fed nothing but shares
// taken on trust, say -- put mining off by another five minutes.
bool P2PoolAwaitingHistory()
{
    return P2PoolChain().Empty() && nFirstHistoryAsk && GetTime() - nFirstHistoryAsk < SYNC_ANSWER_WINDOW;
}

// Shares, by the hash of the whole share, whose parent was missing and whose
// work was checked lately, queued or not. The queue holds 256; without this a
// peer cycling 257 precomputed orphans cost a RandomX hash per message, for
// nothing. A share
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

// Bytes waiting to go to inbound peers together: no history is started for
// an inbound peer past this (it waits, see the held asks below). Peers this
// node dialled are served as before, within their own per-peer caps:
// counting every byte queued to anybody let a few slow readers hold back the
// history a syncing peer this node dialled was asking for. Inbound peers
// that sent a share this node took count as well: one share relayed first
// makes a peer proven, and each would otherwise hold a history's worth.
static const size_t MAX_HISTORIES_QUEUED = 64 * 1000 * 1000;

static size_t InboundQueued()
{
    size_t n = 0;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->fInbound && !pnode->fDisconnect)
                n += SendQueued(pnode);
    return n;
}

// Under cs_p2pool. Orphans whose parent has not come in ORPHAN_EXPIRY go.
// Run on every share, not only when one is queued: the count of shares
// waiting decides whether this node asks a peer for its history, and with
// expiry only on queueing a full backlog stayed full for good, and every
// cached orphan sent again re-armed the ask on each new connection.
static int64 nLastOrphanExpiry = 0;

static void ExpireOrphans()
{
    int64 nNow = GetTime();
    if (nNow == nLastOrphanExpiry)
        return;   // at most one pass a second; a pass is at most 256 shares
    nLastOrphanExpiry = nNow;
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
            mapOrphanShares.erase(it++);
        else
            ++it;
    }
}

// Under cs_p2pool. Room for one more orphan: the expired go first, then, if
// the queue is still full, the oldest one.
static void MakeOrphanRoom()
{
    ExpireOrphans();
    map<uint256, vector<OrphanShare> >::iterator itOldest = mapOrphanShares.end();
    size_t iOldest = 0;
    for (map<uint256, vector<OrphanShare> >::iterator it = mapOrphanShares.begin(); it != mapOrphanShares.end(); ++it)
    {
        vector<OrphanShare>& v = it->second;
        for (size_t i = 0; i < v.size(); i++)
            if (itOldest == mapOrphanShares.end() || v[i].nTime < itOldest->second[iOldest].nTime)
            {
                itOldest = it;
                iOldest = i;
            }
    }
    if (setOrphanIds.size() < MAX_ORPHAN_SHARES || itOldest == mapOrphanShares.end())
        return;
    ForgetOrphan(itOldest->second[iOldest].share.GetId());
    itOldest->second.erase(itOldest->second.begin() + iOldest);
    if (itOldest->second.empty())
        mapOrphanShares.erase(itOldest);
}

// Add a share and whatever was waiting for it. Returns false only on a
// share that is bad in itself. *pfGateClosed (if given) says the peer's own
// share was not hashed because the shared budget was spent: nothing is known
// of it, and the caller may hold it for later (DeferShare).
static bool AcceptShare(const Share& s, CNode* pfrom, bool fHistory, bool* pfGateClosed = NULL,
                        bool fFromQueue = false)
{
    PeerWorkGate gate(pfrom, fFromQueue);
    NodeMainView main;
    vector<Share> todo(1, s);
    bool fFirst = true, fGood = true;
    if (pfGateClosed)
        *pfGateClosed = false;
    CRITICAL_BLOCK(cs_p2pool)
        ExpireOrphans();
    while (!todo.empty())
    {
        // The peer's own share draws on the shared budget if the peer is
        // unproven. Orphans it frees were hashed, through the same budget,
        // when they were queued; they are hashed again in full here without
        // asking it, at most once more each, and the queue holds 256.
        WorkGate* pGate = fFirst && NeedsGate(pfrom) ? &gate : NULL;
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
            nTipHeight = P2PoolChain().Height(P2PoolChain().Tip());
            bnTipNext.SetCompact(P2PoolChain().NextShareBits(P2PoolChain().Tip()));
        }
        // A share far easier than one on our tip is valid on its own line --
        // a new chain starts at the floor, about 4096 hashes -- but nothing
        // this node keeps or passes on: anybody could fill every node's share
        // chain with such lines, and send them again once evicted. Policy,
        // not validity: a history this node asked for is taken as it comes.
        if (!fHistory && nTipHeight >= 0)
        {
            CBigNum bnCur;
            bnCur.SetCompact(cur.data.nShareBits);
            if (bnCur > bnTipNext * 4)
            {
                LogPrint("p2pool", "p2pool: share %s is far easier than our tip's; not kept\n",
                         id.ToString().substr(0, 12).c_str());
                fFirst = false;
                continue;
            }
        }
        CRITICAL_BLOCK(cs_p2pool)
        {
            fOk = P2PoolChain().Add(cur, main, err, &vMissing, &fBlock, pGate);
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
            // replayed, cost a RandomX hash each.
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
            // Kept by the hash of the whole share, not its id: the id is the
            // header's, and the parts a work check looks at besides (the
            // commitment, the branch, the coinbase) are tied to it only once
            // that check passes. By id, a copy with its branch changed, sent
            // first, marked the real share bad, and its honest sender was
            // banned for it.
            uint256 hashWhole = SerializeHash(cur);
            bool fSeen, fBad;
            CRITICAL_BLOCK(cs_p2pool)
            {
                fSeen = OrphanSeen(hashWhole);
                fBad = !fSeen && OrphanBadWork(hashWhole);
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
                CBigNum bnFloor;
                bool fCheckPoW;
                CRITICAL_BLOCK(cs_p2pool)
                {
                    bnFloor = P2PoolChain().Floor();
                    fCheckPoW = P2PoolChain().CheckingPoW();
                }
                bool fWork = CheckShareWork(cur, bnFloor, fBlockW, errWork, fCheckPoW, pGate);
                // Over budget: not hashed, so nothing is known of it, and
                // nobody is blamed. The sender may offer it again later.
                if (!fWork && InnocentRefusal(errWork))
                {
                    if (fFirst && pfGateClosed && errWork == WORK_GATE_CLOSED)
                        *pfGateClosed = true;
                    fFirst = false;
                    continue;
                }
                CRITICAL_BLOCK(cs_p2pool)
                {
                    if (fWork)
                        MarkOrphanSeen(hashWhole);
                    else
                        MarkOrphanBadWork(hashWhole);
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
                // Only a share whose work was checked just now: one seen
                // before already had its chance to open that door, and sent
                // again on each new connection it re-armed the ask each time.
                bool fFar = (int64)cur.data.nShareHeight > (int64)nTipHeight + SYNC_GAP && bnCur <= bnTipNext;
                bool fPiling = nWaiting >= ORPHAN_BACKLOG && bnCur <= bnTipNext * 4;
                if (!fSeen && (nTipHeight < 0 || fFar || fPiling) &&
                    GetTime() - pfrom->nP2PoolSyncAskedAt >= SYNC_SERVE_INTERVAL && HistoryAskAllowed(pfrom))
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
        else if (fFirst && pfGateClosed && err == WORK_GATE_CLOSED)
            *pfGateClosed = true;
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
    // An inbound peer is asked only while the shared budget lasts: while
    // this node has no tip, every new inbound connection was asked, and each
    // could answer with three histories of shares to hash.
    static int nAskedOnVersion = 0;
    bool fAsk;
    CRITICAL_BLOCK(cs_p2pool)
        fAsk = P2PoolChain().Empty() || nAskedOnVersion < 4;
    if (fAsk && HistoryAskAllowed(pfrom))
    {
        nAskedOnVersion++;
        AskHistory(pfrom);
    }
}

// ---- History served, and what the shared budgets hold for later

// The peer counts as served (the interval, and an unproven connection's one
// history) only once a part of it was queued: an empty line, or a queue
// already full, gives it nothing.
static void ServeHistory(CNode* pfrom)
{
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
                return;
            pfrom->PushMessage("p2pshares", nTipHeight, part);
            pfrom->nP2PoolSyncServed = GetTime();
            part.clear();
            nPartBytes = 0;
        }
        part.push_back(history[i]);
        nPartBytes += n;
    }
    if (!part.empty() && !HistoryQueueFull(pfrom))
    {
        pfrom->PushMessage("p2pshares", nTipHeight, part);
        pfrom->nP2PoolSyncServed = GetTime();
    }
}

// An inbound peer that was sent a history this long ago and still has more
// than MAX_SEND_QUEUED waiting is reading too slowly to be honest about it:
// while inbound queues together are over MAX_HISTORIES_QUEUED, the slowest
// such peer is cut off. Else three of them reading a byte a second held
// every inbound peer, every new node syncing included, off a history for
// hours (the send-stall check sees them making progress).
static const int64 HISTORY_DRAIN_SECS = 15 * 60;

static void DropSlowestHistoryReader()
{
    CNode* pSlowest = NULL;
    size_t nMost = 0;
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            if (!pnode->fInbound || pnode->fDisconnect || !pnode->nP2PoolSyncServed ||
                nNow - pnode->nP2PoolSyncServed < HISTORY_DRAIN_SECS)
                continue;
            size_t n = SendQueued(pnode);
            if (n > MAX_SEND_QUEUED && n > nMost)
            {
                nMost = n;
                pSlowest = pnode;
            }
        }
        if (pSlowest)
        {
            LogPrint("p2pool", "p2pool: %s still has %u bytes of a history queued after %d s; dropping it\n",
                     pSlowest->addr.ToString().c_str(), (unsigned)nMost, (int)HISTORY_DRAIN_SECS);
            pSlowest->fDisconnect = true;
        }
    }
}

// A share the shared work budget refused an unproven peer, and a history ask
// that had to wait, are not dropped: an honest miner that dials out and
// listens for nobody is unproven at every node it reaches, and while somebody
// kept the budget spent its shares were lost, and with them its payout; a new
// node could not get a history. Each connection holds at most one share (its
// newest) and one ask. They are served as the budgets refill, the oldest
// connection first, and what comes in live waits behind what an older
// connection has held: a peer that spends the budget on shares with no work
// behind them is blamed for each one served (and cut off, see net.cpp), and
// back on a new connection it waits behind every peer that stayed. An
// unproven connection gets one history in its life, so an old one cannot
// keep a place by asking again. Each held connection is referenced (AddRef)
// until its entry goes.
struct P2PoolDeferred
{
    CNode* pnode;
    uint64 nSeq;          // order of arrival, for connections of the same age
    bool fShare;
    Share share;
    bool fSync;
};
static map<CNode*, P2PoolDeferred> mapDeferred;   // under cs_p2pool
static uint64 nDeferredSeq = 0;
static const size_t MAX_DEFERRED = 64;

// What a pass of P2PoolServeDeferred looks at: the share itself stays in the
// map until it is served (it may be 256 kB).
struct P2PoolDeferredRef
{
    CNode* pnode;
    uint64 nSeq;
    bool fShare;
    bool fSync;
};

template <typename A, typename B>
static bool DeferredOlder(const A& a, const B& b)
{
    if (a.pnode->nTimeConnected != b.pnode->nTimeConnected)
        return a.pnode->nTimeConnected < b.pnode->nTimeConnected;
    return a.nSeq < b.nSeq;
}

static bool OlderHeld(const CNode* pnode, bool fShare)
{
    map<CNode*, P2PoolDeferred>::const_iterator itOwn = mapDeferred.find(const_cast<CNode*>(pnode));
    for (map<CNode*, P2PoolDeferred>::const_iterator it = mapDeferred.begin(); it != mapDeferred.end(); ++it)
    {
        if (it->first == pnode || !(fShare ? it->second.fShare : it->second.fSync))
            continue;
        if (itOwn != mapDeferred.end() ? DeferredOlder(it->second, itOwn->second)
                                       : it->first->nTimeConnected <= pnode->nTimeConnected)
            return true;
    }
    return false;
}

// Under cs_p2pool. The entry for this connection, made if there is room:
// past MAX_DEFERRED the newest connection held makes way for an older one.
static P2PoolDeferred* DeferredEntry(CNode* pnode)
{
    map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.find(pnode);
    if (it != mapDeferred.end())
        return &it->second;
    P2PoolDeferred d;
    d.pnode = pnode;
    d.nSeq = nDeferredSeq++;
    d.fShare = false;
    d.fSync = false;
    if (mapDeferred.size() >= MAX_DEFERRED)
    {
        map<CNode*, P2PoolDeferred>::iterator itNewest = mapDeferred.begin();
        for (it = mapDeferred.begin(); it != mapDeferred.end(); ++it)
            if (DeferredOlder(itNewest->second, it->second))
                itNewest = it;
        if (!DeferredOlder(d, itNewest->second))
            return NULL;
        itNewest->first->Release();
        mapDeferred.erase(itNewest);
    }
    pnode->AddRef();
    return &mapDeferred.insert(make_pair(pnode, d)).first->second;
}

static void DeferShare(CNode* pnode, const Share& s)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        P2PoolDeferred* d = DeferredEntry(pnode);
        if (d)
        {
            d->fShare = true;
            d->share = s;
        }
    }
}

static void DeferSync(CNode* pnode)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        P2PoolDeferred* d = DeferredEntry(pnode);
        if (d)
            d->fSync = true;
    }
}

// Under cs_p2pool.
static void EraseDeferred(map<CNode*, P2PoolDeferred>::iterator it)
{
    it->first->Release();
    mapDeferred.erase(it);
}

// Under cs_p2pool: the held share (fShare) or ask is taken out of the entry.
// The share, if that is what was asked for, goes to *pShare.
static bool TakeDeferred(CNode* pnode, bool fShare, Share* pShare = NULL)
{
    map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.find(pnode);
    if (it == mapDeferred.end())
        return false;
    if (fShare)
    {
        if (!it->second.fShare)
            return false;
        it->second.fShare = false;
        if (pShare)
            *pShare = it->second.share;
        it->second.share = Share();
    }
    else
    {
        if (!it->second.fSync)
            return false;
        it->second.fSync = false;
    }
    return true;
}

// What to do with a history ask now.
enum { SERVE_NOW, SERVE_LATER, SERVE_NEVER };
static int HistoryServeDecision(CNode* pfrom, bool fFromQueue)
{
    // Once per peer per interval, and not into a full send queue: an ask
    // that comes too soon, or finds the queue full, is spent.
    if (pfrom->nP2PoolSyncServed && GetTime() - pfrom->nP2PoolSyncServed < SYNC_SERVE_INTERVAL)
        return SERVE_NEVER;
    if (SendQueueFull(pfrom))
        return SERVE_NEVER;
    if (!pfrom->fInbound)
        return SERVE_NOW;
    bool fProven = P2PoolPeerProven(pfrom);
    // One history in the life of an unproven connection.
    if (!fProven && pfrom->nP2PoolSyncServed)
        return SERVE_NEVER;
    bool fOlder;
    CRITICAL_BLOCK(cs_p2pool)
        fOlder = !fFromQueue && OlderHeld(pfrom, false);
    if (fOlder)
        return SERVE_LATER;
    if (InboundQueued() > MAX_HISTORIES_QUEUED)
    {
        DropSlowestHistoryReader();
        return SERVE_LATER;
    }
    if (!fProven)
    {
        bool fServe;
        CRITICAL_BLOCK(cs_p2pool)
            fServe = budgetHistoryServe.Take(GetTime());
        if (!fServe)
            return SERVE_LATER;
    }
    return SERVE_NOW;
}

void P2PoolServeDeferred()
{
    vector<P2PoolDeferredRef> v;
    bool fWorkLeft;
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.begin(); it != mapDeferred.end(); )
        {
            map<CNode*, P2PoolDeferred>::iterator itNext = it;
            ++itNext;
            if (it->first->fDisconnect || (!it->second.fShare && !it->second.fSync))
                EraseDeferred(it);
            it = itNext;
        }
        if (mapDeferred.empty())
            return;
        fWorkLeft = budgetShareWork.Tokens(GetTime()) > 0;
        for (map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.begin(); it != mapDeferred.end(); ++it)
        {
            P2PoolDeferredRef r;
            r.pnode = it->first;
            r.nSeq = it->second.nSeq;
            r.fShare = it->second.fShare;
            r.fSync = it->second.fSync;
            if ((r.fShare && fWorkLeft) || r.fSync)
                v.push_back(r);
        }
    }
    std::sort(v.begin(), v.end(), DeferredOlder<P2PoolDeferredRef, P2PoolDeferredRef>);
    bool fServeLeft = true;
    for (size_t i = 0; i < v.size() && (fWorkLeft || fServeLeft); i++)
    {
        CNode* pnode = v[i].pnode;
        if (v[i].fShare && fWorkLeft)
        {
            Share s;
            bool fTaken = false;
            CRITICAL_BLOCK(cs_p2pool)
            {
                fWorkLeft = budgetShareWork.Tokens(GetTime()) > 0;
                if (fWorkLeft)
                    fTaken = TakeDeferred(pnode, true, &s);
            }
            if (fTaken)
            {
                bool fGateClosed = false, fGood = true;
                try { fGood = AcceptShare(s, pnode, false, &fGateClosed, true); }
                catch (std::exception& e) { LogPrint("p2pool", "p2pool: held share: %s\n", e.what()); }
                if (!fGood)
                    pnode->Misbehaving(20);
                else if (fGateClosed)
                {
                    // Taken by somebody else in between: back in its place.
                    fWorkLeft = false;
                    CRITICAL_BLOCK(cs_p2pool)
                    {
                        map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.find(pnode);
                        if (it != mapDeferred.end() && !it->second.fShare)
                        {
                            it->second.fShare = true;
                            it->second.share = s;
                        }
                    }
                }
            }
        }
        if (v[i].fSync && fServeLeft && !pnode->fDisconnect)
        {
            int nDecision = HistoryServeDecision(pnode, true);
            if (nDecision == SERVE_LATER)
                fServeLeft = false;
            else
            {
                bool fTaken;
                CRITICAL_BLOCK(cs_p2pool)
                    fTaken = TakeDeferred(pnode, false);
                if (fTaken && nDecision == SERVE_NOW)
                    ServeHistory(pnode);
            }
        }
    }
    CRITICAL_BLOCK(cs_p2pool)
        for (map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.begin(); it != mapDeferred.end(); )
        {
            map<CNode*, P2PoolDeferred>::iterator itNext = it;
            ++itNext;
            if (!it->second.fShare && !it->second.fSync)
                EraseDeferred(it);
            it = itNext;
        }
}

void P2PoolForgetDeferred(CNode* pnode)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.find(pnode);
        if (it != mapDeferred.end())
            EraseDeferred(it);
    }
}

size_t P2PoolDeferredCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = mapDeferred.size();
    return n;
}

void P2PoolRefillBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        budgetShareWork.Reset();
        budgetHistoryServe.Reset();
        budgetHistoryAsk.Reset();
    }
}

void P2PoolDrainBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        int64 nNow = GetTime();
        budgetShareWork.Drain(nNow);
        budgetHistoryServe.Drain(nNow);
        budgetHistoryAsk.Drain(nNow);
    }
}

void P2PoolResetForTest(const CBigNum& bnFloor, bool fCheckPoW)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        // The tests own their peers and may have freed them already: the
        // entries go without touching the nodes.
        mapDeferred.clear();
        delete pP2PoolChain;
        pP2PoolChain = new ShareChain(bnFloor, fCheckPoW);
        mapOrphanShares.clear();
        setOrphanIds.clear();
        setOrphanSeen.clear();
        qOrphanSeen.clear();
        setOrphanBadWork.clear();
        qOrphanBadWork.clear();
        nLastOrphanExpiry = 0;
        nFirstHistoryAsk = 0;
        budgetShareWork.Reset();
        budgetHistoryServe.Reset();
        budgetHistoryAsk.Reset();
    }
}

size_t P2PoolOrphanCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = setOrphanIds.size();
    return n;
}

void P2PoolAgeOrphansForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<uint256, vector<OrphanShare> >::iterator it = mapOrphanShares.begin(); it != mapOrphanShares.end(); ++it)
            for (size_t i = 0; i < it->second.size(); i++)
                it->second[i].nTime -= nSecs;
        nLastOrphanExpiry = 0;
    }
}

int P2PoolShareWorkTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = budgetShareWork.Tokens(GetTime());
    return n;
}

int P2PoolHistoryServeTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = budgetHistoryServe.Tokens(GetTime());
    return n;
}

int P2PoolHistoryAskTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = budgetHistoryAsk.Tokens(GetTime());
    return n;
}

bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "p2pshare")
    {
        Share s;
        vRecv >> s;
        bool fGateClosed = false;
        if (!ShareSane(s) || !AcceptShare(s, pfrom, false, &fGateClosed))
            pfrom->Misbehaving(20);
        else if (fGateClosed)
            DeferShare(pfrom, s);
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
        // A few bytes in, a whole history out: once per peer per interval;
        // to an inbound peer not past what inbound peers together may hold
        // queued (the per-peer cap times every connection was the only
        // bound); to an unproven one once per connection and no more often
        // than the shared budget allows (the throttle is per connection, and
        // a new one starts it afresh). An ask that has to wait is held and
        // answered when there is room (DeferSync).
        int nDecision = HistoryServeDecision(pfrom, false);
        if (nDecision == SERVE_NOW)
            ServeHistory(pfrom);
        else if (nDecision == SERVE_LATER)
            DeferSync(pfrom);
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
