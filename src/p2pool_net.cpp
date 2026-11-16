// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_net.h"
#include "nostr.h"
#include <list>
#ifndef WIN32
#include <dirent.h>
#endif

using namespace p2pool;

CCriticalSection cs_p2pool;

// ---- Pools and their two classes (docs/pool-registry.md, section 8) --------
//
// This file once knew one pool. It now knows pool zero and, beside it, the
// pools of the registered class (a node's local pools today). Everything a
// peer can make this node spend is kept per class, never per pool: pool zero
// has the budgets, the orphan queue and the held entries it always had, to
// itself; every other pool draws on one second set of the same shape. Nothing
// done with a pool of the second class changes how pool zero's traffic is
// treated.

struct PoolState;

// Shares whose parent has not arrived, by parent id; tried again when it does.
// MAX_ORPHAN_SHARES caps the shares held, not the parents waited on: every
// one of them may be tried, with a RandomX hash, the moment its parent comes.
// Under cs_p2pool.
struct OrphanShare
{
    Share share;
    int64 nTime;       // when it came
    PoolState* pool;   // the pool it was sent for
};
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
// This many shares waiting for parents means a line we lack whose heights
// kept pace with ours (two halves of a partition, each retargeted to 10 s):
// its history is asked for too.
static const size_t ORPHAN_BACKLOG = 32;
// A part of a history: at most this many bytes, whatever the share count, so
// no message nears the protocol's limit however many addresses a window pays.
static const size_t HISTORY_PART_BYTES = 2 * 1000 * 1000;
// The same two for a pool of the registered class (section 17): smaller
// parts, so a slow path through a bridge sees progress and loses little.
static const size_t REG_SHARES_PER_MESSAGE = 100;
static const size_t REG_HISTORY_PART_BYTES = 256 * 1024;
// And the receiving window of such a pool's history: its parts come paced.
static const int64 REG_SYNC_ANSWER_WINDOW = 60 * 60;
static const size_t MAX_ORPHAN_SEEN = 20000;

// A share the shared work budget refused an unproven peer, and a history ask
// that had to wait (see "History served" below).
struct P2PoolDeferred
{
    CNode* pnode;
    uint64 nSeq;          // order of arrival, for connections of the same age
    bool fShare;
    Share share;
    PoolState* poolShare; // the pool that share was sent for
    bool fSync;
    // The pools whose history is asked for: pool zero's entry names pool
    // zero; a connection may wait for up to MAX_DEFERRED_ASKS other pools.
    vector<PoolState*> vSync;
};
static const size_t MAX_DEFERRED = 64;
static const size_t MAX_DEFERRED_ASKS = 8;

// One class of P2Pool traffic. Under cs_p2pool.
struct PoolClass
{
    bool fZero;
    // RandomX hashes of shares that unproven peers send unasked (H4 of the
    // DoS review). An honest network makes a share every ten seconds; each
    // reaches this node once over a proven peer in the usual case, and
    // duplicates cost no hash.
    P2PoolBudget budgetShareWork;
    // Histories sent to unproven peers: the biggest thing this code sends, a
    // few bytes asking for it, and a new connection resets every per-peer
    // throttle.
    P2PoolBudget budgetHistoryServe;
    // Histories asked of unproven peers: each one is up to three histories of
    // shares to hash. Peers this node dialled are asked as before.
    P2PoolBudget budgetHistoryAsk;

    map<uint256, vector<OrphanShare> > mapOrphanShares;
    set<uint256> setOrphanIds;
    // Shares, by the hash of the whole share, whose parent was missing and
    // whose work was checked lately, queued or not. The queue holds 256;
    // without this a peer cycling 257 precomputed orphans cost a RandomX hash
    // per message, for nothing. A share seen here is hashed again only when
    // its parent is here, and it is checked in full.
    set<uint256> setOrphanSeen;
    std::deque<uint256> qOrphanSeen;
    // And those whose work failed: the sender is blamed again without a hash.
    set<uint256> setOrphanBadWork;
    std::deque<uint256> qOrphanBadWork;
    int64 nLastOrphanExpiry;

    map<CNode*, P2PoolDeferred> mapDeferred;
    uint64 nDeferredSeq;

    explicit PoolClass(bool fZeroIn)
        : fZero(fZeroIn), budgetShareWork(32, 2), budgetHistoryServe(4, 60), budgetHistoryAsk(2, 60),
          nLastOrphanExpiry(0), nDeferredSeq(0) {}

    bool OrphanSeen(const uint256& id) const { return setOrphanSeen.count(id) != 0; }
    void MarkOrphanSeen(const uint256& id);
    bool OrphanBadWork(const uint256& id) const { return setOrphanBadWork.count(id) != 0; }
    void MarkOrphanBadWork(const uint256& id);
    void ForgetOrphan(const uint256& id) { setOrphanIds.erase(id); }
    void ExpireOrphans();
    void MakeOrphanRoom();
    // Whether a connection older than this one has a share (or a history
    // ask) held for the budgets.
    bool OlderHeld(const CNode* pnode, bool fShare) const;
    P2PoolDeferred* DeferredEntry(CNode* pnode);
    void EraseDeferred(map<CNode*, P2PoolDeferred>::iterator it);
    bool TakeDeferred(CNode* pnode, bool fShare, Share* pShare = NULL, PoolState** ppPool = NULL);
    // Every trace of a pool that is going away.
    void ForgetPool(PoolState* pool);
    void Reset();
};

static PoolClass classZero(true);
static PoolClass classReg(false);

// What a connection has done in one pool. Pool zero's lives in CNode, where
// it always was; every other pool keeps one of these per session.
struct PeerPool
{
    int64 nSyncServed;
    int64 nSyncAskedAt;
    unsigned int nHistoryRecv;
    int64 nLastGood;
    // History asks it made of this node: how many since when, the shares it
    // was sent for them, and where its last ask said to resume from.
    int64 nAsksSince;
    int nAsks;
    size_t nServedShares;
    uint256 hashResume;
    PeerPool() : nSyncServed(0), nSyncAskedAt(0), nHistoryRecv(0), nLastGood(0),
                 nAsksSince(0), nAsks(0), nServedShares(0), hashResume(0) {}
};

struct PeerRef
{
    int64& nSyncServed;
    int64& nSyncAskedAt;
    unsigned int& nHistoryRecv;
    int64& nLastGood;
    PeerRef(int64& a, int64& b, unsigned int& c, int64& d) : nSyncServed(a), nSyncAskedAt(b), nHistoryRecv(c), nLastGood(d) {}
};

// One pool on this node: its share chain, its file, and which class it
// spends from.
struct PoolState
{
    PoolClass* cls;
    bool fZero;
    ShareChain* chain;
    // The share chain lives in a file between runs: what History() returns,
    // oldest first, read back the way a peer's history is (work alone for the
    // deep end, in full for the newest retarget window). Without it a restart
    // started a new chain at height 0 until a peer answered. p2pool.dat for
    // pool zero.
    string strFile;
    // When this node first asked a peer for this pool's line, this run.
    int64 nFirstHistoryAsk;
    int64 nLastSave;
    int nAskedOnOpen;
    // Sessions of a pool other than zero, by connection (see "Local pools").
    map<CNode*, PeerPool> mapPeer;

    PoolState(PoolClass* clsIn, ShareChain* chainIn, const string& strFileIn)
        : cls(clsIn), fZero(clsIn->fZero), chain(chainIn), strFile(strFileIn),
          nFirstHistoryAsk(0), nLastSave(0), nAskedOnOpen(0) {}

    size_t SharesPerMessage() const { return fZero ? SHARES_PER_MESSAGE : REG_SHARES_PER_MESSAGE; }
    size_t PartBytes() const { return fZero ? HISTORY_PART_BYTES : REG_HISTORY_PART_BYTES; }
    int64 AnswerWindow() const { return fZero ? SYNC_ANSWER_WINDOW : REG_SYNC_ANSWER_WINDOW; }
};

static PoolState* pPoolZero = NULL;

static PoolState& PoolZero()
{
    if (!pPoolZero)
        pPoolZero = new PoolState(&classZero, new ShareChain(bnProofOfWorkLimit), GetAppDir() + "/p2pool.dat");
    return *pPoolZero;
}

ShareChain& P2PoolChain()
{
    return *PoolZero().chain;
}

// The pool this node's own miners work on: pool zero unless -p2pool=local:
// named another. Set once at startup.
static PoolState* pPoolMined = NULL;

static PoolState& PoolMined()
{
    return pPoolMined ? *pPoolMined : PoolZero();
}

ShareChain& P2PoolMinedChain()
{
    return *PoolMined().chain;
}

// Bumped under cs_p2pool whenever a share joins the mined pool's chain.
static uint64 nMinedChainSeq = 0;

uint64 P2PoolMinedChainSeq()
{
    uint64 n;
    CRITICAL_BLOCK(cs_p2pool)
        n = nMinedChainSeq;
    return n;
}

// Under cs_p2pool.
static void NoteChainGrew(PoolState& ps)
{
    if (&ps == &PoolMined())
        nMinedChainSeq++;
}

// The per-connection state of a pool: CNode's own fields for pool zero, the
// session's for any other. A connection with no session in that pool gets a
// scratch one, which nothing keeps.
static PeerRef Peer(PoolState& ps, CNode* pnode)
{
    if (ps.fZero)
        return PeerRef(pnode->nP2PoolSyncServed, pnode->nP2PoolSyncAskedAt, pnode->nP2PoolHistoryRecv, pnode->nP2PoolLastGood);
    static PeerPool scratch;
    PeerPool* p = &scratch;
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pnode);
        if (it != ps.mapPeer.end())
            p = &it->second;
        else
            scratch = PeerPool();
    }
    return PeerRef(p->nSyncServed, p->nSyncAskedAt, p->nHistoryRecv, p->nLastGood);
}

// The messages of a pool other than zero are queued through here, so the
// connection knows which stretches of its send stream are theirs.
static void NoteRegSpan(CNode* pnode, uint64 nFrom)
{
    // Under pnode->cs_vSend.
    uint64 nTo = pnode->nSendDrained + pnode->vSend.size();
    if (nTo <= nFrom)
        return;
    if (!pnode->vRegSpans.empty() && pnode->vRegSpans.back().second >= nFrom)
        pnode->vRegSpans.back().second = nTo;
    else
        pnode->vRegSpans.push_back(std::make_pair(nFrom, nTo));
    // Never more than a few hundred stretches: past that the two oldest
    // become one (and what lay between them counts with them).
    if (pnode->vRegSpans.size() > 512)
    {
        pnode->vRegSpans[1].first = pnode->vRegSpans[0].first;
        pnode->vRegSpans.pop_front();
    }
}

// Under pnode->cs_vSend: bytes of such messages still waiting to go.
static size_t RegQueuedLocked(CNode* pnode)
{
    uint64 nAt = pnode->nSendDrained;
    while (!pnode->vRegSpans.empty() && pnode->vRegSpans.front().second <= nAt)
        pnode->vRegSpans.pop_front();
    uint64 n = 0;
    for (size_t i = 0; i < pnode->vRegSpans.size(); i++)
        n += pnode->vRegSpans[i].second - std::max(pnode->vRegSpans[i].first, nAt);
    return (size_t)std::min(n, (uint64)pnode->vSend.size());
}

template <typename T1>
static void PushReg(CNode* pnode, const char* pszCommand, const T1& a1)
{
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        uint64 nFrom = pnode->nSendDrained + pnode->vSend.size();
        pnode->PushMessage(pszCommand, a1);
        NoteRegSpan(pnode, nFrom);
    }
}

template <typename T1, typename T2>
static void PushReg(CNode* pnode, const char* pszCommand, const T1& a1, const T2& a2)
{
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        uint64 nFrom = pnode->nSendDrained + pnode->vSend.size();
        pnode->PushMessage(pszCommand, a1, a2);
        NoteRegSpan(pnode, nFrom);
    }
}

template <typename T1, typename T2, typename T3, typename T4>
static void PushReg(CNode* pnode, const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
{
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        uint64 nFrom = pnode->nSendDrained + pnode->vSend.size();
        pnode->PushMessage(pszCommand, a1, a2, a3, a4);
        NoteRegSpan(pnode, nFrom);
    }
}

// What each of a pool's messages is on the wire. Pool zero's are the five it
// always had; a local pool's carry the session's handle (further down).
static void PushShare(PoolState& ps, CNode* pnode, const Share& s);
static void PushGetSh(PoolState& ps, CNode* pnode, const vector<uint256>& vIds);
static void PushSync(PoolState& ps, CNode* pnode);
static void PushShares(PoolState& ps, CNode* pnode, int nTipHeight, const vector<Share>& part, bool fEnd);

static void LoadShares(PoolState& ps)
{
    ShareChain& chain = *ps.chain;
    vector<Share> v;
    int nTipHeight = 0;
    try
    {
        CAutoFile file(fopen(ps.strFile.c_str(), "rb"));
        if (!file)
            return;
        if (ps.fZero)
            file >> nTipHeight >> v;
        else
        {
            vector<ShareX> vx;
            file >> nTipHeight >> vx;
            v.assign(vx.begin(), vx.end());
        }
    }
    catch (std::exception& e)
    {
        if (ps.fZero)
            printf("p2pool: %s unreadable (%s); starting from peers\n", ps.strFile.c_str(), e.what());
        else
            printf("p2pool: a local pool's saved share chain is unreadable (%s); starting from peers\n", e.what());
        return;
    }
    NodeMainView main;   // the caller holds cs_main
    string err;
    if (!chain.AddHistory(v, nTipHeight, main, err))
        printf("p2pool: saved share chain refused (%s); starting from peers\n", err.c_str());
    printf("p2pool: %u shares loaded, tip at height %d\n", (unsigned)chain.Size(), chain.Height(chain.Tip()));
}

// fPrivate: owner-only, for a local pool's file, whose shares carry the pool
// id (with the code, a password oracle; section 18).
static void WriteShares(const string& strFile, int nTipHeight, const vector<Share>& v, bool fPrivate)
{
    string tmp = strFile + ".new";
    {
        CAutoFile file(fPrivate ? OpenPrivateFile(tmp.c_str(), false) : fopen(tmp.c_str(), "wb"));
        if (!file)
            return;
        file << nTipHeight << v;
    }
    // Windows will not rename over an existing file.
    remove(strFile.c_str());
    rename(tmp.c_str(), strFile.c_str());
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

// A peer that has since sent something wrong is not proven any more: the
// status is not otherwise taken back within a connection, and what it could
// cause before it is cut off is not worth a free pass.
bool P2PoolPeerProven(const CNode* pnode)
{
    return (!pnode->fInbound || pnode->nP2PoolLastGood != 0) && pnode->nMisbehavior == 0;
}

// The same for any pool: a share taken in pool zero proves nothing in
// another pool, nor the other way round.
static bool PeerProven(PoolState& ps, CNode* pnode)
{
    if (ps.fZero)
        return P2PoolPeerProven(pnode);
    return (!pnode->fInbound || Peer(ps, pnode).nLastGood != 0) && pnode->nMisbehavior == 0;
}

// The shared budget behind WorkGate, for one peer's share. A share that
// comes in live waits behind any held for an older connection: else whoever
// sends the most, on fresh connections, takes every token as it refills, and
// the held share of an honest peer that stayed is never reached.
class PeerWorkGate : public WorkGate
{
public:
    PeerWorkGate(PoolClass& kIn, const CNode* pnodeIn, bool fFromQueueIn) : k(kIn), pnode(pnodeIn), fFromQueue(fFromQueueIn) {}
    bool Allow()
    {
        bool f;
        CRITICAL_BLOCK(cs_p2pool)
            f = (fFromQueue || !k.OlderHeld(pnode, true)) && k.budgetShareWork.Take(GetTime());
        return f;
    }
private:
    PoolClass& k;
    const CNode* pnode;
    bool fFromQueue;
};

// Unproven peers go through the gate.
static bool NeedsGate(PoolState& ps, CNode* pfrom)
{
    return pfrom && !PeerProven(ps, pfrom);
}

static void LocalPoolsInit();

void P2PoolInit()
{
    // cs_main before cs_p2pool, the order every other caller takes them in.
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
        {
            LoadShares(PoolZero());
            LocalPoolsInit();
        }
}

// Not under cs_p2pool: the line is copied under it, and written after, so
// the few MB of a history do not go to disk with the share chain locked.
static void MaybeSaveShares(PoolState& ps, bool fNow = false)
{
    vector<Share> v;
    int nTipHeight;
    string strFile;
    bool fPrivate;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (!fNow && GetTime() - ps.nLastSave < 120)
            return;
        ps.nLastSave = GetTime();
        ps.chain->History(v);
        nTipHeight = ps.chain->Height(ps.chain->Tip());
        strFile = ps.strFile;
        fPrivate = !ps.fZero;
    }
    if (!strFile.empty())
        WriteShares(strFile, nTipHeight, v, fPrivate);
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

static void RelayLocalShare(PoolState& ps, const Share& s, CNode* pfrom);

static void RelayShare(PoolState& ps, const Share& s, CNode* pfrom)
{
    if (!ps.fZero)
    {
        RelayLocalShare(ps, s, pfrom);
        return;
    }
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

static void AskHistory(PoolState& ps, CNode* pfrom)
{
    PeerRef peer = Peer(ps, pfrom);
    peer.nSyncAskedAt = GetTime();
    peer.nHistoryRecv = 0;
    CRITICAL_BLOCK(cs_p2pool)
        if (!ps.nFirstHistoryAsk)
            ps.nFirstHistoryAsk = GetTime();
    PushSync(ps, pfrom);
}

// Whether this node may ask that peer for its history now: always one it
// dialled or one that sent a share it took; an unproven peer only while the
// shared budget lasts. Each ask is up to three histories of shares to hash.
static bool HistoryAskAllowed(PoolState& ps, CNode* pfrom)
{
    if (PeerProven(ps, pfrom))
        return true;
    bool f;
    CRITICAL_BLOCK(cs_p2pool)
        f = ps.cls->budgetHistoryAsk.Take(GetTime());
    return f;
}

// Templates wait for the first answers only. Measured from the latest ask,
// every new peer of a node still without a tip -- one fed nothing but shares
// taken on trust, say -- put mining off by another five minutes. About the
// pool this node mines.
bool P2PoolAwaitingHistory()
{
    PoolState& ps = PoolMined();
    return ps.chain->Empty() && ps.nFirstHistoryAsk && GetTime() - ps.nFirstHistoryAsk < SYNC_ANSWER_WINDOW;
}

void PoolClass::MarkOrphanSeen(const uint256& id)
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

void PoolClass::MarkOrphanBadWork(const uint256& id)
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

// Above this many bytes waiting to go to a peer, nothing big is added: a
// peer that asks and never reads would otherwise hold every answer in memory.
static const size_t MAX_SEND_QUEUED = 4 * 1000 * 1000;

// What a connection has waiting to go, of one class: pool zero's count is
// the send buffer less the other pools' messages, and theirs is those alone,
// so neither can push the other past its caps (section 8, "Send queues").
// With no such message queued, pool zero's is the whole buffer, as it was.
static size_t SendQueued(PoolClass& k, CNode* pnode)
{
    size_t n;
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        size_t nReg = RegQueuedLocked(pnode);
        n = k.fZero ? pnode->vSend.size() - nReg : nReg;
    }
    return n;
}

static bool SendQueueFull(PoolClass& k, CNode* pnode)
{
    return SendQueued(k, pnode) > MAX_SEND_QUEUED;
}

// A history may queue more, once per peer per SYNC_SERVE_INTERVAL: it is a
// few MB while windows pay a few hundred addresses.
static const size_t MAX_HISTORY_QUEUED = 32 * 1000 * 1000;
// The other pools' histories go out paced, a part at a time, into a queue
// this small: together with pool zero's largest it stays far below the
// socket's hard cap.
static const size_t MAX_REG_HISTORY_QUEUED = 1000 * 1000;

static bool HistoryQueueFull(PoolClass& k, CNode* pnode)
{
    return SendQueued(k, pnode) > (k.fZero ? MAX_HISTORY_QUEUED : MAX_REG_HISTORY_QUEUED);
}

// Bytes waiting to go to inbound peers together: no history is started for
// an inbound peer past this (it waits, see the held asks below). Peers this
// node dialled are served as before, within their own per-peer caps:
// counting every byte queued to anybody let a few slow readers hold back the
// history a syncing peer this node dialled was asking for. Inbound peers
// that sent a share this node took count as well: one share relayed first
// makes a peer proven, and each would otherwise hold a history's worth.
static const size_t MAX_HISTORIES_QUEUED = 64 * 1000 * 1000;

static size_t InboundQueued(PoolClass& k)
{
    size_t n = 0;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->fInbound && !pnode->fDisconnect)
                n += SendQueued(k, pnode);
    return n;
}

// Under cs_p2pool. Orphans whose parent has not come in ORPHAN_EXPIRY go.
// Run on every share, not only when one is queued: the count of shares
// waiting decides whether this node asks a peer for its history, and with
// expiry only on queueing a full backlog stayed full for good, and every
// cached orphan sent again re-armed the ask on each new connection.
void PoolClass::ExpireOrphans()
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
void PoolClass::MakeOrphanRoom()
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
static bool AcceptShare(PoolState& ps, const Share& s, CNode* pfrom, bool fHistory, bool* pfGateClosed = NULL,
                        bool fFromQueue = false)
{
    PoolClass& k = *ps.cls;
    const int64 nHistoryShares = ps.chain->Rules().HistoryShares();
    const int nSyncGap = ps.chain->Rules().NearTipShares();
    PeerWorkGate gate(k, pfrom, fFromQueue);
    NodeMainView main;
    vector<Share> todo(1, s);
    bool fFirst = true, fGood = true;
    if (pfGateClosed)
        *pfGateClosed = false;
    CRITICAL_BLOCK(cs_p2pool)
        k.ExpireOrphans();
    while (!todo.empty())
    {
        // The peer's own share draws on the shared budget if the peer is
        // unproven. Orphans it frees were hashed, through the same budget,
        // when they were queued; they are hashed again in full here without
        // asking it, at most once more each, and the queue holds 256.
        WorkGate* pGate = fFirst && NeedsGate(ps, pfrom) ? &gate : NULL;
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
            nTipHeight = (*ps.chain).Height((*ps.chain).Tip());
            bnTipNext.SetCompact((*ps.chain).NextShareBits((*ps.chain).Tip()));
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
            fOk = (*ps.chain).Add(cur, main, err, &vMissing, &fBlock, pGate);
            nTipHeight = (*ps.chain).Height((*ps.chain).Tip());
            bnTipNext.SetCompact((*ps.chain).NextShareBits((*ps.chain).Tip()));
            if (fOk)
                NoteChainGrew(ps);
        }
        if (fOk)
        {
            LogPrint("p2pool", "p2pool: share %s height %u accepted%s\n",
                     id.ToString().substr(0, 12).c_str(), cur.data.nShareHeight,
                     fBlock ? " (it is a block)" : "");
            if (fBlock)
                LogBlockPayouts(cur);
            MaybeSaveShares(ps);
            CRITICAL_BLOCK(cs_p2pool)
            {
                map<uint256, vector<OrphanShare> >::iterator it = k.mapOrphanShares.find(id);
                if (it != k.mapOrphanShares.end())
                {
                    // Those sent for this pool; a share of another pool
                    // that names the same parent id goes on waiting.
                    vector<OrphanShare> vRest;
                    foreach(const OrphanShare& o, it->second)
                    {
                        if (o.pool != &ps)
                        {
                            vRest.push_back(o);
                            continue;
                        }
                        todo.push_back(o.share);
                        k.ForgetOrphan(o.share.GetId());
                    }
                    if (vRest.empty())
                        k.mapOrphanShares.erase(it);
                    else
                        it->second = vRest;
                }
            }
            if (pfrom)
                Peer(ps, pfrom).nLastGood = GetTime();   // it passes shares on (net.cpp)
            if (!fHistory)
                RelayShare(ps, cur, pfrom);
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
                ((int64)cur.data.nShareHeight + nHistoryShares < (int64)nTipHeight || bnCur > bnTipNext * 4))
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
                fSeen = k.OrphanSeen(hashWhole);
                fBad = !fSeen && k.OrphanBadWork(hashWhole);
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
                PoolRules rules;
                bool fCheckPoW;
                CRITICAL_BLOCK(cs_p2pool)
                {
                    rules = ps.chain->Rules();
                    fCheckPoW = ps.chain->CheckingPoW();
                }
                bool fWork = CheckShareWork(cur, rules, fBlockW, errWork, fCheckPoW, pGate);
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
                        k.MarkOrphanSeen(hashWhole);
                    else
                        k.MarkOrphanBadWork(hashWhole);
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
                if (!k.setOrphanIds.count(id))
                {
                    k.MakeOrphanRoom();
                    k.setOrphanIds.insert(id);
                    OrphanShare o;
                    o.share = cur;
                    o.nTime = GetTime();
                    o.pool = &ps;
                    k.mapOrphanShares[vMissing[0]].push_back(o);
                }
                nWaiting = k.setOrphanIds.size();
            }
            if (pfrom)
            {
                PushGetSh(ps, pfrom, vMissing);
                // A history is the one thing this node takes partly on trust,
                // so only a share with real work opens the door to one: as
                // hard as one on our tip when it claims to be far ahead, or
                // within a factor of four when shares pile up waiting for
                // parents -- the sign of a line we lack, after a partition,
                // whose heights kept pace with ours.
                // Only a share whose work was checked just now: one seen
                // before already had its chance to open that door, and sent
                // again on each new connection it re-armed the ask each time.
                bool fFar = (int64)cur.data.nShareHeight > (int64)nTipHeight + nSyncGap && bnCur <= bnTipNext;
                bool fPiling = nWaiting >= ORPHAN_BACKLOG && bnCur <= bnTipNext * 4;
                if (!fSeen && (nTipHeight < 0 || fFar || fPiling) &&
                    GetTime() - Peer(ps, pfrom).nSyncAskedAt >= SYNC_SERVE_INTERVAL && HistoryAskAllowed(ps, pfrom))
                {
                    LogPrint("p2pool", "p2pool: share at height %u, our tip at %d, %u waiting: asking that peer for its line\n",
                             cur.data.nShareHeight, nTipHeight, (unsigned)nWaiting);
                    AskHistory(ps, pfrom);
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
    PoolState& ps = PoolMined();
    NodeMainView main;
    bool fOk, fBlock = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = ps.chain->Add(share, main, errOut, NULL, &fBlock);
        if (fOk)
            NoteChainGrew(ps);
    }
    if (fOk)
        MaybeSaveShares(ps);
    if (pfBlock)
        *pfBlock = fBlock;
    if (fOk && fBlock)
        LogBlockPayouts(share);
    if (fOk)
        RelayShare(ps, share, NULL);
    return fOk;
}

// The P2Pool peers this node reached and names to another: at most this many.
static const size_t MAX_P2P_PEER_HINTS = 32;

static void LocalOnVersion(CNode* pfrom);

void P2PoolOnVersion(CNode* pfrom)
{
    // A listed peer of one of this node's local pools is told so, and nobody
    // else is told anything.
    LocalOnVersion(pfrom);

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
    if (fAsk && HistoryAskAllowed(PoolZero(), pfrom))
    {
        nAskedOnVersion++;
        AskHistory(PoolZero(), pfrom);
    }
}

// ---- History served, and what the shared budgets hold for later

// The peer counts as served (the interval, and an unproven connection's one
// history) only once a part of it was queued: an empty line, or a queue
// already full, gives it nothing. Pool zero's: the whole line at once.
static void ServeHistory(PoolState& ps, CNode* pfrom)
{
    PoolClass& k = *ps.cls;
    vector<Share> history;
    int nTipHeight;
    CRITICAL_BLOCK(cs_p2pool)
    {
        ps.chain->History(history);
        nTipHeight = ps.chain->Height(ps.chain->Tip());
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
        if (!part.empty() && (part.size() >= ps.SharesPerMessage() || nPartBytes + n > ps.PartBytes()))
        {
            if (HistoryQueueFull(k, pfrom))
                return;
            PushShares(ps, pfrom, nTipHeight, part, false);
            Peer(ps, pfrom).nSyncServed = GetTime();
            part.clear();
            nPartBytes = 0;
        }
        part.push_back(history[i]);
        nPartBytes += n;
    }
    if (!part.empty() && !HistoryQueueFull(k, pfrom))
    {
        PushShares(ps, pfrom, nTipHeight, part, false);
        Peer(ps, pfrom).nSyncServed = GetTime();
    }
}

// An inbound peer that was sent a history this long ago and still has more
// than MAX_SEND_QUEUED waiting is reading too slowly to be honest about it:
// while inbound queues together are over MAX_HISTORIES_QUEUED, the slowest
// such peer is cut off. Else three of them reading a byte a second held
// every inbound peer, every new node syncing included, off a history for
// hours (the send-stall check sees them making progress).
static const int64 HISTORY_DRAIN_SECS = 15 * 60;

// When each connection was last sent a part of a history of the other class.
static void RegServedTimes(map<CNode*, int64>& out);

// Run per class: each judges a peer on its own bytes and its own serves.
static void DropSlowestHistoryReader(PoolClass& k)
{
    CNode* pSlowest = NULL;
    size_t nMost = 0;
    int64 nNow = GetTime();
    // When each connection was last served a history of this class.
    map<CNode*, int64> mapServed;
    if (!k.fZero)
        RegServedTimes(mapServed);
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            int64 nServed = k.fZero ? pnode->nP2PoolSyncServed : mapServed[pnode];
            if (!pnode->fInbound || pnode->fDisconnect || !nServed ||
                nNow - nServed < HISTORY_DRAIN_SECS)
                continue;
            size_t n = SendQueued(k, pnode);
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
// until its entry goes. Each class holds its own (P2PoolDeferred, above).

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

bool PoolClass::OlderHeld(const CNode* pnode, bool fShare) const
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
P2PoolDeferred* PoolClass::DeferredEntry(CNode* pnode)
{
    map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.find(pnode);
    if (it != mapDeferred.end())
        return &it->second;
    P2PoolDeferred d;
    d.pnode = pnode;
    d.nSeq = nDeferredSeq++;
    d.fShare = false;
    d.poolShare = NULL;
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

static void DeferShare(PoolState& ps, CNode* pnode, const Share& s)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        P2PoolDeferred* d = ps.cls->DeferredEntry(pnode);
        if (d)
        {
            d->fShare = true;
            d->share = s;
            d->poolShare = &ps;
        }
    }
}

static void DeferSync(PoolState& ps, CNode* pnode)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        P2PoolDeferred* d = ps.cls->DeferredEntry(pnode);
        if (d && std::find(d->vSync.begin(), d->vSync.end(), &ps) == d->vSync.end() &&
            d->vSync.size() < (ps.fZero ? 1 : MAX_DEFERRED_ASKS))
        {
            d->fSync = true;
            d->vSync.push_back(&ps);
        }
    }
}

// Under cs_p2pool.
void PoolClass::EraseDeferred(map<CNode*, P2PoolDeferred>::iterator it)
{
    it->first->Release();
    mapDeferred.erase(it);
}

// Under cs_p2pool: the held share (fShare) or the oldest held ask is taken
// out of the entry. The share, if that is what was asked for, goes to
// *pShare; the pool it or the ask is for, to *ppPool.
bool PoolClass::TakeDeferred(CNode* pnode, bool fShare, Share* pShare, PoolState** ppPool)
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
        if (ppPool)
            *ppPool = it->second.poolShare;
        it->second.share = Share();
        it->second.poolShare = NULL;
    }
    else
    {
        if (!it->second.fSync || it->second.vSync.empty())
            return false;
        if (ppPool)
            *ppPool = it->second.vSync.front();
        it->second.vSync.erase(it->second.vSync.begin());
        it->second.fSync = !it->second.vSync.empty();
    }
    return true;
}

// Under cs_p2pool.
void PoolClass::ForgetPool(PoolState* pool)
{
    for (map<uint256, vector<OrphanShare> >::iterator it = mapOrphanShares.begin(); it != mapOrphanShares.end();)
    {
        vector<OrphanShare>& v = it->second;
        for (size_t i = 0; i < v.size();)
        {
            if (v[i].pool == pool)
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
    for (map<CNode*, P2PoolDeferred>::iterator it = mapDeferred.begin(); it != mapDeferred.end(); ++it)
    {
        P2PoolDeferred& d = it->second;
        if (d.fShare && d.poolShare == pool)
        {
            d.fShare = false;
            d.share = Share();
            d.poolShare = NULL;
        }
        d.vSync.erase(std::remove(d.vSync.begin(), d.vSync.end(), pool), d.vSync.end());
        d.fSync = !d.vSync.empty();
    }
}

// Self-tests: the entries go without touching the nodes, which the tests own
// and may have freed already.
void PoolClass::Reset()
{
    mapDeferred.clear();
    mapOrphanShares.clear();
    setOrphanIds.clear();
    setOrphanSeen.clear();
    qOrphanSeen.clear();
    setOrphanBadWork.clear();
    qOrphanBadWork.clear();
    nLastOrphanExpiry = 0;
    budgetShareWork.Reset();
    budgetHistoryServe.Reset();
    budgetHistoryAsk.Reset();
}

// A paced serve in flight for this (connection, pool), and whether one more
// may start (further down, with the local pools).
static bool RegServeSlotFree(PoolState& ps, CNode* pfrom, bool fProven);

// What to do with a history ask now.
enum { SERVE_NOW, SERVE_LATER, SERVE_NEVER };
static int HistoryServeDecision(PoolState& ps, CNode* pfrom, bool fFromQueue)
{
    PoolClass& k = *ps.cls;
    // Once per peer per interval, and not into a full send queue: an ask
    // that comes too soon, or finds the queue full, is spent.
    PeerRef peer = Peer(ps, pfrom);
    if (ps.fZero && peer.nSyncServed && GetTime() - peer.nSyncServed < SYNC_SERVE_INTERVAL)
        return SERVE_NEVER;
    if (SendQueueFull(k, pfrom))
        return SERVE_NEVER;
    bool fProven = PeerProven(ps, pfrom);
    // A pool of the other class is served paced, a few at a time: an ask
    // with no slot free waits its turn, whoever the peer is.
    if (!ps.fZero && !RegServeSlotFree(ps, pfrom, fProven))
        return SERVE_LATER;
    if (!pfrom->fInbound)
        return SERVE_NOW;
    // One history in the life of an unproven connection.
    if (ps.fZero && !fProven && peer.nSyncServed)
        return SERVE_NEVER;
    bool fOlder;
    CRITICAL_BLOCK(cs_p2pool)
        fOlder = !fFromQueue && k.OlderHeld(pfrom, false);
    if (fOlder)
        return SERVE_LATER;
    if (InboundQueued(k) > MAX_HISTORIES_QUEUED)
    {
        DropSlowestHistoryReader(k);
        return SERVE_LATER;
    }
    if (!fProven)
    {
        bool fServe;
        CRITICAL_BLOCK(cs_p2pool)
            fServe = k.budgetHistoryServe.Take(GetTime());
        if (!fServe)
            return SERVE_LATER;
    }
    return SERVE_NOW;
}

static void StartRegServe(PoolState& ps, CNode* pfrom);

static void ServeNow(PoolState& ps, CNode* pfrom)
{
    if (ps.fZero)
        ServeHistory(ps, pfrom);
    else
        StartRegServe(ps, pfrom);
}

static void ServeDeferredClass(PoolClass& k)
{
    vector<P2PoolDeferredRef> v;
    bool fWorkLeft;
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.begin(); it != k.mapDeferred.end(); )
        {
            map<CNode*, P2PoolDeferred>::iterator itNext = it;
            ++itNext;
            if (it->first->fDisconnect || (!it->second.fShare && !it->second.fSync))
                k.EraseDeferred(it);
            it = itNext;
        }
        if (k.mapDeferred.empty())
            return;
        fWorkLeft = k.budgetShareWork.Tokens(GetTime()) > 0;
        for (map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.begin(); it != k.mapDeferred.end(); ++it)
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
            PoolState* pool = NULL;
            bool fTaken = false;
            CRITICAL_BLOCK(cs_p2pool)
            {
                fWorkLeft = k.budgetShareWork.Tokens(GetTime()) > 0;
                if (fWorkLeft)
                    fTaken = k.TakeDeferred(pnode, true, &s, &pool);
            }
            if (fTaken && pool)
            {
                bool fGateClosed = false, fGood = true;
                try { fGood = AcceptShare(*pool, s, pnode, false, &fGateClosed, true); }
                catch (std::exception& e) { LogPrint("p2pool", "p2pool: held share: %s\n", e.what()); }
                if (!fGood)
                    pnode->Misbehaving(20);
                else if (fGateClosed)
                {
                    // Taken by somebody else in between: back in its place.
                    fWorkLeft = false;
                    CRITICAL_BLOCK(cs_p2pool)
                    {
                        map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.find(pnode);
                        if (it != k.mapDeferred.end() && !it->second.fShare)
                        {
                            it->second.fShare = true;
                            it->second.share = s;
                            it->second.poolShare = pool;
                        }
                    }
                }
            }
        }
        if (v[i].fSync && fServeLeft && !pnode->fDisconnect)
        {
            PoolState* pool = NULL;
            CRITICAL_BLOCK(cs_p2pool)
            {
                map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.find(pnode);
                if (it != k.mapDeferred.end() && !it->second.vSync.empty())
                    pool = it->second.vSync.front();
            }
            if (!pool)
                continue;
            int nDecision = HistoryServeDecision(*pool, pnode, true);
            if (nDecision == SERVE_LATER)
                fServeLeft = false;
            else
            {
                bool fTaken;
                CRITICAL_BLOCK(cs_p2pool)
                    fTaken = k.TakeDeferred(pnode, false);
                if (fTaken && nDecision == SERVE_NOW)
                    ServeNow(*pool, pnode);
            }
        }
    }
    CRITICAL_BLOCK(cs_p2pool)
        for (map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.begin(); it != k.mapDeferred.end(); )
        {
            map<CNode*, P2PoolDeferred>::iterator itNext = it;
            ++itNext;
            if (!it->second.fShare && !it->second.fSync)
                k.EraseDeferred(it);
            it = itNext;
        }
}

static void LocalTick();

void P2PoolServeDeferred()
{
    ServeDeferredClass(classZero);
    ServeDeferredClass(classReg);
    LocalTick();
}

static void LocalForgetNode(CNode* pnode);

void P2PoolForgetDeferred(CNode* pnode)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, P2PoolDeferred>::iterator it = classZero.mapDeferred.find(pnode);
        if (it != classZero.mapDeferred.end())
            classZero.EraseDeferred(it);
        it = classReg.mapDeferred.find(pnode);
        if (it != classReg.mapDeferred.end())
            classReg.EraseDeferred(it);
        LocalForgetNode(pnode);
    }
}

size_t P2PoolDeferredCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classZero.mapDeferred.size();
    return n;
}

void P2PoolRefillBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        classZero.budgetShareWork.Reset();
        classZero.budgetHistoryServe.Reset();
        classZero.budgetHistoryAsk.Reset();
    }
}

void P2PoolDrainBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        int64 nNow = GetTime();
        classZero.budgetShareWork.Drain(nNow);
        classZero.budgetHistoryServe.Drain(nNow);
        classZero.budgetHistoryAsk.Drain(nNow);
    }
}

void P2PoolDrainRegisteredBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        int64 nNow = GetTime();
        classReg.budgetShareWork.Drain(nNow);
        classReg.budgetHistoryServe.Drain(nNow);
        classReg.budgetHistoryAsk.Drain(nNow);
    }
}

static void LocalResetForTest(bool fCheckPoW);

void P2PoolResetForTest(const CBigNum& bnFloor, bool fCheckPoW)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        PoolState& ps = PoolZero();
        classZero.Reset();
        classReg.Reset();
        LocalResetForTest(fCheckPoW);
        delete ps.chain;
        ps.chain = new ShareChain(bnFloor, fCheckPoW);
        ps.nFirstHistoryAsk = 0;
    }
}

size_t P2PoolOrphanCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classZero.setOrphanIds.size();
    return n;
}

size_t P2PoolRegisteredOrphanCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classReg.setOrphanIds.size();
    return n;
}

void P2PoolAgeOrphansForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<uint256, vector<OrphanShare> >::iterator it = classZero.mapOrphanShares.begin(); it != classZero.mapOrphanShares.end(); ++it)
            for (size_t i = 0; i < it->second.size(); i++)
                it->second[i].nTime -= nSecs;
        classZero.nLastOrphanExpiry = 0;
    }
}

int P2PoolShareWorkTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classZero.budgetShareWork.Tokens(GetTime());
    return n;
}

int P2PoolHistoryServeTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classZero.budgetHistoryServe.Tokens(GetTime());
    return n;
}

int P2PoolHistoryAskTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classZero.budgetHistoryAsk.Tokens(GetTime());
    return n;
}

int P2PoolRegisteredShareWorkTokens()
{
    int n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classReg.budgetShareWork.Tokens(GetTime());
    return n;
}

// ---- Local pools (docs/pool-registry.md, section 18) -----------------------
//
// A private pool: its members prove membership to each other with a hello
// bound to the onion that was dialled, and from then on the pool's messages
// carry the session's handle, never the pool id. A node that is not a member
// sees nothing: no answer to a hello, no answer to a handle it does not hold.

struct LocalPool
{
    string strName;
    poolreg::PoolRecord rec;
    poollocal::Keys keys;
    vector<string> vPeers;              // ADDR@HOST.onion[:PORT], at most MAX_LISTED_PEERS
    poollocal::Sessions sessions;
    PoolState state;
    map<CNode*, uint64> mapHandle;      // the open sessions and their handles
    map<CNode*, int64> mapHelloAt;      // when this node last sent each connection a hello
    bool fLeaving;
    // pools/local/<id>.conf: the record, K and the listed peers, never the
    // password. Empty for a pool kept in memory only (self-tests).
    string strConf;

    LocalPool(const string& strNameIn, const poolreg::PoolRecord& recIn, const poollocal::Keys& keysIn,
              ShareChain* chainIn, const string& strFileIn)
        : strName(strNameIn), rec(recIn), keys(keysIn), sessions(keysIn),
          state(&classReg, chainIn, strFileIn), fLeaving(false) {}
    ~LocalPool() { OPENSSL_cleanse(&keys, sizeof(keys)); }
};

// Under cs_p2pool.
static vector<LocalPool*> vLocalPools;
// Self-tests: whether the pools made from files and RPCs check RandomX work
// (P2PoolResetForTest sets it; always true in a node).
static bool fLocalCheckPoW = true;

// What this node keeps for a connection that took part in a hello. Each
// holds a reference on its node until the connection is seen closed.
struct LocalConn
{
    uint64 nConn;                       // the connection's name for Sessions
    poollocal::HelloLimiter limiter;    // hellos read from it
    int64 nLastHelloSent;
    int nHellosSent;
    LocalConn() : nConn(0), nLastHelloSent(0), nHellosSent(0) {}
};
static map<CNode*, LocalConn> mapLocalConn;
static uint64 nNextLocalConn = 1;
// Hellos this node sends on one connection: one a minute, as the receiver
// reads them, a pool tried again after this long, and fewer in all than the
// receiver reads in a connection's life.
static const int64 HELLO_SEND_SPACING = poollocal::HELLO_INTERVAL + 5;
static const int64 HELLO_RETRY = 15 * 60;
static const int HELLO_SEND_MAX = poollocal::HELLO_LIFETIME - 2;

struct WireHello
{
    poollocal::Hello h;
    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(h.nonce));
        READWRITE(FLATDATA(h.tag));
    )
};

struct WireAck
{
    unsigned char ack[poollocal::ACK_BYTES];
    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(ack));
    )
};

// A history part's end flag: more parts follow, the line ends here, or the
// server stopped before the end (its limits; ask again later).
enum { PART_MORE = 0, PART_END = 1, PART_ENDED_EARLY = 2 };

// Self-tests: the onions this node answers hellos for, in place of Tor's.
static vector<string> vOwnOnionsForTest;

static void OwnOnions(vector<string>& out)
{
    out = vOwnOnionsForTest;
    if (!out.empty())
        return;
    string strEndpoint = BtfLocalOnionEndpoint(), o;
    size_t colon = strEndpoint.rfind(':');
    if (colon != string::npos)
        strEndpoint.resize(colon);
    if (poollocal::OnionName(strEndpoint, o))
        out.push_back(o);
}

// The onion this node dialled to make an outbound connection, if it dialled
// one directly (net.cpp writes "onion HOST.onion:PORT").
static bool DialledOnion(CNode* pnode, string& oOut)
{
    if (pnode->fInbound || pnode->strBtfMeeting.compare(0, 6, "onion ") != 0)
        return false;
    string s = pnode->strBtfMeeting.substr(6);
    size_t colon = s.rfind(':');
    if (colon != string::npos)
        s.resize(colon);
    return poollocal::OnionName(s, oOut);
}

// Whether a pool lists this peer: the same .btf address at the same onion.
static bool Listed(const LocalPool& lp, const string& strBtfAddr, const string& O)
{
    foreach(const string& strPeer, lp.vPeers)
    {
        size_t at = strPeer.find('@');
        if (at == string::npos || strPeer.compare(0, at, strBtfAddr) != 0 || at != strBtfAddr.size())
            continue;
        string s = strPeer.substr(at + 1), o;
        size_t colon = s.rfind(':');
        if (colon != string::npos)
            s.resize(colon);
        if (poollocal::OnionName(s, o) && o == O)
            return true;
    }
    return false;
}

// Under cs_p2pool.
static LocalConn& LocalConnOf(CNode* pnode)
{
    map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pnode);
    if (it != mapLocalConn.end())
        return it->second;
    pnode->AddRef();
    LocalConn c;
    c.nConn = nNextLocalConn++;
    return mapLocalConn.insert(make_pair(pnode, c)).first->second;
}

// Under cs_p2pool.
static LocalPool* LocalOf(PoolState& ps)
{
    foreach(LocalPool* lp, vLocalPools)
        if (&lp->state == &ps)
            return lp;
    return NULL;
}

static void RegServedTimes(map<CNode*, int64>& out)
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(LocalPool* lp, vLocalPools)
            for (map<CNode*, PeerPool>::iterator it = lp->state.mapPeer.begin(); it != lp->state.mapPeer.end(); ++it)
                out[it->first] = std::max(out[it->first], it->second.nSyncServed);
}

// Under cs_p2pool: the pool a handle names on a connection.
static LocalPool* LocalByHandle(CNode* pnode, uint64 h)
{
    foreach(LocalPool* lp, vLocalPools)
    {
        map<CNode*, uint64>::iterator it = lp->mapHandle.find(pnode);
        if (it != lp->mapHandle.end() && it->second == h && !lp->fLeaving)
            return lp;
    }
    return NULL;
}

static bool HandleOf(PoolState& ps, CNode* pnode, uint64& hOut)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalOf(ps);
        if (lp)
        {
            map<CNode*, uint64>::iterator it = lp->mapHandle.find(pnode);
            if (it != lp->mapHandle.end())
            {
                hOut = it->second;
                f = true;
            }
        }
    }
    return f;
}

static void PushShare(PoolState& ps, CNode* pnode, const Share& s)
{
    uint64 h;
    if (ps.fZero)
        pnode->PushMessage("p2pshare", s);
    else if (HandleOf(ps, pnode, h))
        PushReg(pnode, "p2lshare", h, s);
}

static void PushGetSh(PoolState& ps, CNode* pnode, const vector<uint256>& vIds)
{
    uint64 h;
    if (ps.fZero)
        pnode->PushMessage("p2pgetsh", vIds);
    else if (HandleOf(ps, pnode, h))
        PushReg(pnode, "p2lgetsh", h, vIds);
}

static void PushSync(PoolState& ps, CNode* pnode)
{
    uint64 h;
    if (ps.fZero)
        pnode->PushMessage("p2psync");
    else if (HandleOf(ps, pnode, h))
    {
        // The resume point: this node's tip, so the peer sends only what
        // lies past where the two lines meet (section 17).
        uint256 hashResume;
        CRITICAL_BLOCK(cs_p2pool)
            hashResume = ps.chain->Tip();
        PushReg(pnode, "p2lsync", h, hashResume);
    }
}

static void PushShares(PoolState& ps, CNode* pnode, int nTipHeight, const vector<Share>& part, bool fEnd)
{
    uint64 h;
    if (ps.fZero)
        pnode->PushMessage("p2pshares", nTipHeight, part);
    else if (HandleOf(ps, pnode, h))
        PushReg(pnode, "p2lshares", h, nTipHeight, (unsigned char)(fEnd ? PART_END : PART_MORE), part);
}

// To every member in session, and to nobody else.
static void RelayLocalShare(PoolState& ps, const Share& s, CNode* pfrom)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalOf(ps);
        if (!lp)
            return;
        for (map<CNode*, uint64>::iterator it = lp->mapHandle.begin(); it != lp->mapHandle.end(); ++it)
            if (it->first != pfrom && !it->first->fDisconnect)
                PushReg(it->first, "p2lshare", it->second, s);
    }
}

// ---- Paced serves: a local pool's history goes out a part at a time

struct RegServe
{
    PoolState* pool;
    CNode* pnode;
    vector<Share> v;        // the snapshot, oldest first
    size_t i;               // the next share to send
    int nTipHeight;
    int64 nStart;
    uint64 nSent;           // bytes
    int64 nLastSent;
    bool fProven;
};
static std::list<RegServe> lRegServes;      // under cs_p2pool
static const size_t MAX_REG_SERVES = 8;
static const size_t MAX_REG_SERVES_UNPROVEN = 4;
static const int64 REG_SERVE_RATE = 64 * 1000;     // bytes a second, whatever the transport
static const int64 REG_SERVE_STALL = 5 * 60;

static bool RegServeSlotFree(PoolState& ps, CNode* pfrom, bool fProven)
{
    size_t n = 0, nUnproven = 0;
    CRITICAL_BLOCK(cs_p2pool)
        foreach(const RegServe& r, lRegServes)
        {
            if (r.pool == &ps && r.pnode == pfrom)
                continue;   // a new ask takes its place
            n++;
            if (!r.fProven)
                nUnproven++;
        }
    return n < MAX_REG_SERVES && (fProven || nUnproven < MAX_REG_SERVES_UNPROVEN);
}

// Under cs_p2pool. The share count a (connection, pool) may be sent in one
// interval: a history and the uncles it names.
static size_t RegServeAllowance(PoolState& ps)
{
    return 3 * (size_t)ps.chain->Rules().HistoryShares();
}

static void PumpRegServes()
{
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_p2pool)
        for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
        {
            RegServe& r = *it;
            map<CNode*, PeerPool>::iterator itPeer = r.pool->mapPeer.find(r.pnode);
            if (r.pnode->fDisconnect || itPeer == r.pool->mapPeer.end())
            {
                it = lRegServes.erase(it);
                continue;
            }
            // Not before the last part has left, and not faster than the rate.
            if (SendQueued(classReg, r.pnode) > REG_HISTORY_PART_BYTES)
            {
                // A reader that takes nothing for this long loses its slot.
                if (nNow - r.nLastSent > REG_SERVE_STALL)
                    it = lRegServes.erase(it);
                else
                    ++it;
                continue;
            }
            if (r.nSent > (uint64)((nNow - r.nStart) * REG_SERVE_RATE))
            {
                ++it;
                continue;
            }
            vector<Share> part;
            size_t nPartBytes = 0;
            while (r.i < r.v.size())
            {
                size_t n = ::GetSerializeSize(r.v[r.i], SER_NETWORK);
                if (!part.empty() && (part.size() >= REG_SHARES_PER_MESSAGE || nPartBytes + n > REG_HISTORY_PART_BYTES))
                    break;
                part.push_back(r.v[r.i++]);
                nPartBytes += n;
            }
            PeerPool& peer = itPeer->second;
            uint64 h = 0;
            bool fSession = HandleOf(*r.pool, r.pnode, h);
            unsigned char nFlag = r.i >= r.v.size() ? PART_END : PART_MORE;
            if (peer.nServedShares + part.size() > RegServeAllowance(*r.pool))
            {
                part.clear();
                nFlag = PART_ENDED_EARLY;
            }
            if (fSession)
                PushReg(r.pnode, "p2lshares", h, r.nTipHeight, nFlag, part);
            peer.nServedShares += part.size();
            peer.nSyncServed = nNow;
            r.nSent += nPartBytes;
            r.nLastSent = nNow;
            if (nFlag != PART_MORE || !fSession)
                it = lRegServes.erase(it);
            else
                ++it;
        }
}

// The line from where the asker's resume point lies on it, less the uncle
// depth; the whole line when it names no share on it. Not under cs_p2pool.
static void StartRegServe(PoolState& ps, CNode* pfrom)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, PeerPool>::iterator itPeer = ps.mapPeer.find(pfrom);
        if (itPeer == ps.mapPeer.end())
            return;
        for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
            if (it->pool == &ps && it->pnode == pfrom)
                it = lRegServes.erase(it);
            else
                ++it;
        RegServe r;
        r.pool = &ps;
        r.pnode = pfrom;
        ps.chain->History(r.v);
        r.nTipHeight = ps.chain->Height(ps.chain->Tip());
        r.i = 0;
        uint256 hashResume = itPeer->second.hashResume;
        if (hashResume != 0)
            for (size_t i = 0; i < r.v.size(); i++)
                if (r.v[i].GetId() == hashResume)
                {
                    int64 nFrom = (int64)r.v[i].data.nShareHeight - ps.chain->Rules().nUncleDepth;
                    while (r.i < r.v.size() && (int64)r.v[r.i].data.nShareHeight < nFrom)
                        r.i++;
                    break;
                }
        r.nStart = GetTime();
        r.nSent = 0;
        r.nLastSent = r.nStart;
        r.fProven = PeerProven(ps, pfrom);
        lRegServes.push_back(r);
    }
    PumpRegServes();
}

// ---- The hello

// Under cs_p2pool: the session is open on both sides.
static void OpenSession(LocalPool* lp, CNode* pnode, const unsigned char h[poollocal::HANDLE_BYTES])
{
    uint64 n;
    memcpy(&n, h, sizeof(n));
    lp->mapHandle[pnode] = n;
    lp->state.mapPeer[pnode] = PeerPool();
    LogPrint("p2pool", "p2pool: local pool '%s': a member is in session (%u now)\n",
             lp->strName.c_str(), (unsigned)lp->mapHandle.size());
    // Its line, while this node has none, and from the first few members in
    // any case, as pool zero asks its first peers.
    bool fAsk = lp->state.chain->Empty() || lp->state.nAskedOnOpen < 4;
    if (fAsk && HistoryAskAllowed(lp->state, pnode))
    {
        lp->state.nAskedOnOpen++;
        AskHistory(lp->state, pnode);
    }
}

// Under cs_p2pool. A hello for the next pool that lists this peer and has no
// session with it, if one is due on this connection.
static void LocalSendHello(CNode* pnode)
{
    if (vLocalPools.empty() || pnode->fInbound || pnode->fDisconnect || pnode->nVersion == 0)
        return;
    string O;
    if (!DialledOnion(pnode, O))
        return;
    int64 nNow = GetTime();
    foreach(LocalPool* lp, vLocalPools)
    {
        if (lp->fLeaving || lp->mapHandle.count(pnode) || !Listed(*lp, pnode->strBtfAddr, O))
            continue;
        map<CNode*, int64>::iterator itAt = lp->mapHelloAt.find(pnode);
        if (itAt != lp->mapHelloAt.end() && nNow - itAt->second < HELLO_RETRY)
            continue;
        LocalConn& c = LocalConnOf(pnode);
        if (c.nHellosSent >= HELLO_SEND_MAX || (c.nLastHelloSent && nNow - c.nLastHelloSent < HELLO_SEND_SPACING))
            return;
        // One that went unanswered is forgotten before the next.
        lp->sessions.Close(c.nConn);
        WireHello w;
        unsigned char nA[poollocal::NONCE_BYTES];
        GetStrongRandBytes(nA, sizeof(nA));
        if (!lp->sessions.StartHello(c.nConn, O, nA, w.h))
            continue;
        PushReg(pnode, "p2lhello", w);
        lp->mapHelloAt[pnode] = nNow;
        c.nLastHelloSent = nNow;
        c.nHellosSent++;
        return;
    }
}

static void LocalOnVersion(CNode* pfrom)
{
    CRITICAL_BLOCK(cs_p2pool)
        LocalSendHello(pfrom);
}

// Under cs_p2pool: a connection is gone. Its sessions, serves and held
// entries go with it, and the reference this file held on it.
static void LocalForgetNode(CNode* pnode)
{
    map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pnode);
    for (std::list<RegServe>::iterator itS = lRegServes.begin(); itS != lRegServes.end();)
        if (itS->pnode == pnode)
            itS = lRegServes.erase(itS);
        else
            ++itS;
    foreach(LocalPool* lp, vLocalPools)
    {
        if (it != mapLocalConn.end())
            lp->sessions.Close(it->second.nConn);
        lp->mapHandle.erase(pnode);
        lp->mapHelloAt.erase(pnode);
        lp->state.mapPeer.erase(pnode);
    }
    if (it != mapLocalConn.end())
    {
        pnode->Release();
        mapLocalConn.erase(it);
    }
}

// Under cs_p2pool: a pool this node left.
static void LocalRemove(LocalPool* lp)
{
    classReg.ForgetPool(&lp->state);
    for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
        if (it->pool == &lp->state)
            it = lRegServes.erase(it);
        else
            ++it;
    vLocalPools.erase(std::remove(vLocalPools.begin(), vLocalPools.end(), lp), vLocalPools.end());
    if (!lp->state.strFile.empty())
    {
        remove(lp->state.strFile.c_str());
        remove((lp->state.strFile + ".new").c_str());
    }
    if (!lp->strConf.empty())
    {
        remove(lp->strConf.c_str());
        remove((lp->strConf + ".new").c_str());
    }
    LogPrint("p2pool", "p2pool: local pool '%s' left; its files are gone\n", lp->strName.c_str());
    delete lp->state.chain;
    delete lp;
}

// Once a second, on the message thread: hellos due, connections gone,
// replies nobody acked, serves in flight, pools left.
static void LocalTick()
{
    static int64 nLast = 0;
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_p2pool)
        if (vLocalPools.empty() && mapLocalConn.empty())
            return;
    if (nNow == nLast)
    {
        PumpRegServes();
        return;
    }
    nLast = nNow;
    // cs_vNodes before cs_p2pool; nothing takes them the other way round.
    CRITICAL_BLOCK(cs_vNodes)
        CRITICAL_BLOCK(cs_p2pool)
            foreach(CNode* pnode, vNodes)
                LocalSendHello(pnode);
    CRITICAL_BLOCK(cs_p2pool)
    {
        vector<CNode*> vGone;
        for (map<CNode*, LocalConn>::iterator it = mapLocalConn.begin(); it != mapLocalConn.end(); ++it)
            if (it->first->fDisconnect)
                vGone.push_back(it->first);
        foreach(CNode* pnode, vGone)
            LocalForgetNode(pnode);
        vector<LocalPool*> vLeft;
        foreach(LocalPool* lp, vLocalPools)
        {
            lp->sessions.Expire(nNow);
            if (lp->fLeaving && &lp->state != pPoolMined)
                vLeft.push_back(lp);
        }
        foreach(LocalPool* lp, vLeft)
            LocalRemove(lp);
    }
    PumpRegServes();
}

// Under cs_p2pool. Self-tests: no local pool, no session; the nodes are the
// tests' own and are not touched.
static void LocalResetForTest(bool fCheckPoW)
{
    fLocalCheckPoW = fCheckPoW;
    nMinedChainSeq = 0;
    lRegServes.clear();
    mapLocalConn.clear();
    foreach(LocalPool* lp, vLocalPools)
    {
        delete lp->state.chain;
        delete lp;
    }
    vLocalPools.clear();
    vOwnOnionsForTest.clear();
    pPoolMined = NULL;
}

static LocalPool* LocalByName(const string& strName)
{
    foreach(LocalPool* lp, vLocalPools)
        if (lp->strName == strName && !lp->fLeaving)
            return lp;
    return NULL;
}

// Under cs_p2pool.
static size_t LiveLocalPools()
{
    size_t n = 0;
    foreach(LocalPool* lp, vLocalPools)
        if (!lp->fLeaving)
            n++;
    return n;
}

// Under cs_p2pool. A new local pool, not yet in vLocalPools; NULL, with the
// reason, if its record or its name cannot be one here.
static LocalPool* LocalNew(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, const string& strFile,
                           const string& strConf, bool fCheckPoW, string& errOut)
{
    PoolRules rules;
    if (!rec.fLocal)
    {
        errOut = "not a local pool's record";
        return NULL;
    }
    if (!RulesForLocal(rec, keys, rules, errOut))
        return NULL;
    if (LocalByName(rec.name))
    {
        errOut = "a local pool with that name is already on this node";
        return NULL;
    }
    if (LiveLocalPools() >= poollocal::MAX_LOCAL_POOLS)
    {
        errOut = "this node is in as many local pools as it may be";
        return NULL;
    }
    LocalPool* lp = new LocalPool(rec.name, rec, keys, new ShareChain(rules, fCheckPoW), strFile);
    lp->strConf = strConf;
    return lp;
}

bool P2PoolLocalAdd(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, const string& strFile,
                    bool fCheckPoW, string& errOut)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalNew(rec, keys, strFile, "", fCheckPoW, errOut);
        if (!lp)
            return false;
        vLocalPools.push_back(lp);
    }
    return true;
}

// ---- The pool file: pools/local/<id>.conf
//
// One per local pool: "record=" and the record in hex, "k=" and K in hex,
// and a "peer=" line for each listed peer; never the password. Whoever reads
// it can join the pool, so it is written owner-only; and the id in its name
// (with the code, a password oracle) goes to no log line, no error and no
// RPC answer: those say "pools/local" and the pool's name.

static string LocalDir()
{
    return GetAppDir() + "/pools/local";
}

static bool MakeLocalDir()
{
    _mkdir((GetAppDir() + "/pools").c_str());
    _mkdir(LocalDir().c_str());
    struct stat st;
    return stat(LocalDir().c_str(), &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
}

// ADDRESS@HOST.onion[:PORT], the form /connectbtf takes.
static bool ListedPeerOk(const string& strPeer)
{
    size_t at = strPeer.find('@');
    if (at == string::npos || at == 0)
        return false;
    string s = strPeer.substr(at + 1), o;
    size_t colon = s.rfind(':');
    if (colon != string::npos)
        s.resize(colon);
    return poollocal::OnionName(s, o);
}

// Under cs_p2pool. The file with these listed peers; true at once for a pool
// kept in memory only.
static bool WriteLocalConf(const LocalPool& lp, const vector<string>& vPeers, string& errOut)
{
    if (lp.strConf.empty())
        return true;
    vector<unsigned char> r = lp.rec.Encode();
    string s = "# A local pool of this node (docs/pool-registry.md, section 18).\n"
               "# Whoever reads this file can join the pool.\n";
    s += "record=" + HexStr(r.begin(), r.end(), false) + "\n";
    s += "k=" + HexStr(lp.keys.K, lp.keys.K + sizeof(lp.keys.K), false) + "\n";
    foreach(const string& strPeer, vPeers)
        s += "peer=" + strPeer + "\n";
    string err;
    bool fOk = WriteFileAtomicPrivate(lp.strConf, s, err);
    OPENSSL_cleanse(&s[0], s.size());
    if (!fOk)
        errOut = "could not write the local pool's file under the data directory (pools/local)";
    return fOk;
}

// The ids that have a file in pools/local, each the 64 lowercase hex digits
// of a file's name before ".conf".
static void ListLocalConfs(vector<string>& out)
{
    vector<string> vNames;
#ifdef WIN32
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((LocalDir() + "/*.conf").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                vNames.push_back(fd.cFileName);
        while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    DIR* d = opendir(LocalDir().c_str());
    if (d)
    {
        struct dirent* e;
        while ((e = readdir(d)) != NULL)
            vNames.push_back(e->d_name);
        closedir(d);
    }
#endif
    foreach(const string& n, vNames)
    {
        if (n.size() != 64 + 5 || n.compare(64, 5, ".conf") != 0)
            continue;
        bool fHex = true;
        for (size_t i = 0; i < 64 && fHex; i++)
            fHex = (n[i] >= '0' && n[i] <= '9') || (n[i] >= 'a' && n[i] <= 'f');
        if (fHex)
            out.push_back(n.substr(0, 64));
    }
    std::sort(out.begin(), out.end());
}

// One file, read back: the record, K and the listed peers. False on anything
// that is not exactly a file this code writes.
static bool ReadLocalConf(const string& strPath, vector<unsigned char>& vRecord, unsigned char K[32],
                          vector<string>& vPeers)
{
    FILE* f = fopen(strPath.c_str(), "rb");
    if (!f)
        return false;
    // A record, a key and sixteen peers fit well inside this.
    char buf[16 * 1024];
    size_t n = fread(buf, 1, sizeof(buf), f);
    bool fWhole = feof(f) != 0;
    fclose(f);
    string s(buf, n);
    OPENSSL_cleanse(buf, sizeof(buf));
    bool fRecord = false, fK = false, fOk = fWhole;
    size_t pos = 0;
    while (fOk && pos < s.size())
    {
        size_t end = s.find('\n', pos);
        string line = s.substr(pos, end == string::npos ? string::npos : end - pos);
        pos = end == string::npos ? s.size() : end + 1;
        if (!line.empty() && line[line.size() - 1] == '\r')
            line.resize(line.size() - 1);
        if (line.empty() || line[0] == '#')
            continue;
        if (line.compare(0, 7, "record=") == 0 && !fRecord)
        {
            string h = line.substr(7);
            fOk = !h.empty() && h.size() % 2 == 0 && IsHex(h) && h.size() <= 2 * poolreg::MAX_RECORD_BYTES;
            if (fOk)
                vRecord = ParseHex(h);
            fRecord = true;
        }
        else if (line.compare(0, 2, "k=") == 0 && !fK)
        {
            string h = line.substr(2);
            fOk = h.size() == 64 && IsHex(h);
            if (fOk)
            {
                vector<unsigned char> v = ParseHex(h);
                memcpy(K, &v[0], 32);
                OPENSSL_cleanse(&v[0], v.size());
            }
            OPENSSL_cleanse(&line[0], line.size());
            fK = true;
        }
        else if (line.compare(0, 5, "peer=") == 0)
        {
            // A peer this build would not list is left out, not the pool.
            string p = line.substr(5);
            if (ListedPeerOk(p) && vPeers.size() < poollocal::MAX_LISTED_PEERS &&
                std::find(vPeers.begin(), vPeers.end(), p) == vPeers.end())
                vPeers.push_back(p);
        }
        else
            fOk = false;
    }
    OPENSSL_cleanse(&s[0], s.size());
    return fOk && fRecord && fK;
}

// Under cs_main and cs_p2pool (P2PoolInit): the local pools this node saved.
static void LocalPoolsInit()
{
    vector<string> vIds;
    ListLocalConfs(vIds);
    foreach(const string& strId, vIds)
    {
        string strBase = LocalDir() + "/" + strId;
        vector<unsigned char> vRecord;
        unsigned char K[32];
        vector<string> vPeers;
        poolreg::PoolRecord rec;
        poollocal::Keys keys;
        string err;
        bool fOk = ReadLocalConf(strBase + ".conf", vRecord, K, vPeers) &&
                   poolreg::Parse(vRecord, rec, err) && rec.fLocal &&
                   poollocal::DeriveFromK(vRecord, (const unsigned char*)pchMessageStart, K, keys, err) &&
                   poolreg::IdHex(keys.id) == strId;
        OPENSSL_cleanse(K, sizeof(K));
        if (!fOk)
        {
            OPENSSL_cleanse(&keys, sizeof(keys));
            printf("p2pool: a file in pools/local is not a local pool of this network; skipped\n");
            continue;
        }
        LocalPool* lp = LocalNew(rec, keys, strBase + ".dat", strBase + ".conf", fLocalCheckPoW, err);
        OPENSSL_cleanse(&keys, sizeof(keys));
        if (!lp)
        {
            printf("p2pool: local pool '%s' not loaded: %s\n", rec.name.c_str(), err.c_str());
            continue;
        }
        lp->vPeers = vPeers;
        vLocalPools.push_back(lp);
        LoadShares(lp->state);
        printf("p2pool: local pool '%s' is back, %u listed peer(s)\n", lp->strName.c_str(), (unsigned)vPeers.size());
    }
}

bool P2PoolLocalJoin(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, string& errOut)
{
    if (!MakeLocalDir())
    {
        errOut = "could not make the directory pools/local under the data directory";
        return false;
    }
    string strBase = LocalDir() + "/" + poolreg::IdHex(keys.id);
    // cs_main before cs_p2pool, as P2PoolInit: a share chain left in the
    // pool's file is read the way it is on start.
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
        {
            // Its files go when a pool that is being left is taken down: the
            // same name, and so the same files, is not reused until then.
            foreach(LocalPool* lp, vLocalPools)
                if (lp->fLeaving && lp->strName == rec.name)
                {
                    errOut = "a local pool with that name is being left; try again in a few seconds";
                    return false;
                }
            LocalPool* lp = LocalNew(rec, keys, strBase + ".dat", strBase + ".conf", fLocalCheckPoW, errOut);
            if (!lp)
                return false;
            if (!WriteLocalConf(*lp, lp->vPeers, errOut))
            {
                delete lp->state.chain;
                delete lp;
                return false;
            }
            vLocalPools.push_back(lp);
            LoadShares(lp->state);
            LogPrint("p2pool", "p2pool: local pool '%s' joined\n", lp->strName.c_str());
        }
    return true;
}

bool P2PoolLocalLoad(const string& strName)
{
    // cs_main before cs_p2pool, as P2PoolInit.
    bool f = false;
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
        {
            LocalPool* lp = LocalByName(strName);
            if (lp && !lp->state.strFile.empty())
            {
                LoadShares(lp->state);
                f = true;
            }
        }
    return f;
}

bool P2PoolLocalSetPeers(const string& strName, const vector<string>& vPeers, string& errOut)
{
    if (vPeers.size() > poollocal::MAX_LISTED_PEERS)
    {
        errOut = "a local pool lists at most 16 peers";
        return false;
    }
    foreach(const string& strPeer, vPeers)
        if (!ListedPeerOk(strPeer))
        {
            errOut = "a listed peer is ADDRESS@HOST.onion[:PORT]";
            return false;
        }
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (!lp)
        {
            errOut = "no local pool with that name on this node";
            return false;
        }
        if (!WriteLocalConf(*lp, vPeers, errOut))
            return false;
        lp->vPeers = vPeers;
        lp->mapHelloAt.clear();
    }
    return true;
}

bool P2PoolLocalLeave(const string& strName, string& errOut)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (!lp)
        {
            errOut = "no local pool with that name on this node";
            return false;
        }
        if (&lp->state == pPoolMined)
        {
            errOut = "this node is mining that pool; stop mining it first";
            return false;
        }
        lp->fLeaving = true;
    }
    return true;
}

bool P2PoolLocalMine(const string& strName, string& errOut)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (!lp)
        {
            errOut = "no local pool with that name on this node";
            return false;
        }
        pPoolMined = &lp->state;
        printf("p2pool: this node mines local pool '%s'\n", lp->strName.c_str());
    }
    return true;
}

bool P2PoolParseChoice(const string& strValue, string& strLocalOut, string& errOut)
{
    strLocalOut.clear();
    if (strValue.compare(0, 6, "local:") == 0)
    {
        string strName = strValue.substr(6);
        if (!poolreg::NameOk(strName))
        {
            errOut = "-p2pool=local: needs the name of a local pool on this node (1 to 32 of A-Z, a-z, 0-9, - and _)";
            return false;
        }
        strLocalOut = strName;
        return true;
    }
    size_t nHex = 0;
    while (nHex < strValue.size() && isxdigit((unsigned char)strValue[nHex]))
        nHex++;
    if (nHex != strValue.size() || nHex < 40 || nHex > 80)
        return true;    // "-p2pool", "-p2pool=1", "-p2pool=0": pool zero, as before
    if (nHex != 64)
    {
        errOut = "the value of -p2pool looks like a mistyped pool id: a pool id is 64 hex digits";
        return false;
    }
    unsigned char id[32];
    vector<unsigned char> vZero = poolreg::PoolZero().Encode();
    poolreg::PoolId(vZero, (const unsigned char*)pchMessageStart, id);
    string strLower = strValue;
    for (size_t i = 0; i < strLower.size(); i++)
        strLower[i] = (char)tolower((unsigned char)strLower[i]);
    if (strLower == poolreg::IdHex(id))
        return true;    // pool zero's own id
    errOut = "-p2pool=<pool id> names an Everpool pool, which this release cannot mine yet";
    return false;
}

bool P2PoolLocalStatus(const string& strName, P2PoolLocalStatusInfo& out)
{
    bool f = false;
    // cs_vNodes before cs_p2pool, as LocalTick.
    CRITICAL_BLOCK(cs_vNodes)
        CRITICAL_BLOCK(cs_p2pool)
        {
            LocalPool* lp = LocalByName(strName);
            if (lp)
            {
                out.rec = lp->rec;
                out.nSessions = lp->mapHandle.size();
                out.nPending = lp->sessions.Pending();
                out.nShares = lp->state.chain->Size();
                out.nTipHeight = lp->state.chain->Height(lp->state.chain->Tip());
                out.vPeers = lp->vPeers;
                out.fMined = &lp->state == pPoolMined;
                out.fAtCap = lp->mapHandle.size() >= poollocal::MAX_SESSIONS;
                out.nInboundSessions = 0;
                for (map<CNode*, uint64>::iterator it = lp->mapHandle.begin(); it != lp->mapHandle.end(); ++it)
                    if (it->first->fInbound)
                        out.nInboundSessions++;
                // Each listed peer: whether this node holds a connection it
                // dialled to that address at that onion, and what came of it.
                out.vPeerState.clear();
                foreach(const string& strPeer, lp->vPeers)
                {
                    int nState = P2PoolLocalStatusInfo::PEER_NOT_CONNECTED;
                    foreach(CNode* pnode, vNodes)
                    {
                        string O;
                        if (pnode->fDisconnect || !DialledOnion(pnode, O) || !Listed(*lp, pnode->strBtfAddr, O) ||
                            strPeer.compare(0, pnode->strBtfAddr.size() + 1, pnode->strBtfAddr + "@") != 0)
                            continue;
                        if (lp->mapHandle.count(pnode))
                            nState = P2PoolLocalStatusInfo::PEER_SESSION;
                        else if (out.fAtCap)
                            nState = P2PoolLocalStatusInfo::PEER_OUR_CAP;
                        else if (lp->mapHelloAt.count(pnode))
                            nState = P2PoolLocalStatusInfo::PEER_NO_PROOF;
                        else
                            nState = P2PoolLocalStatusInfo::PEER_CONNECTED;
                        break;
                    }
                    out.vPeerState.push_back(nState);
                }
                f = true;
            }
        }
    return f;
}

void P2PoolLocalNames(vector<string>& out)
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(LocalPool* lp, vLocalPools)
            if (!lp->fLeaving)
                out.push_back(lp->strName);
}

void P2PoolLocalDialList(vector<string>& out)
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(LocalPool* lp, vLocalPools)
            if (!lp->fLeaving)
                foreach(const string& strPeer, lp->vPeers)
                    if (std::find(out.begin(), out.end(), strPeer) == out.end())
                        out.push_back(strPeer);
}

void P2PoolSetOwnOnionsForTest(const vector<string>& v)
{
    CRITICAL_BLOCK(cs_p2pool)
        vOwnOnionsForTest = v;
}

size_t P2PoolRegisteredServesForTest()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = lRegServes.size();
    return n;
}

// ---- Messages

static void OnShare(PoolState& ps, CNode* pfrom, const Share& s)
{
    bool fGateClosed = false;
    if (!ShareSane(s) || !AcceptShare(ps, s, pfrom, false, &fGateClosed))
        pfrom->Misbehaving(20);
    else if (fGateClosed)
        DeferShare(ps, pfrom, s);
}

static void OnGetSh(PoolState& ps, CNode* pfrom, const vector<uint256>& vIds)
{
    PoolClass& k = *ps.cls;
    if (vIds.size() > MAX_GETSH)
    {
        pfrom->Misbehaving(20);
        return;
    }
    // Any share held, on any line: what is asked for is usually an uncle
    // or a fork, which the tip's own line does not contain. Not while
    // this peer has not read what it was sent already.
    if (SendQueueFull(k, pfrom))
        return;
    vector<Share> vOut;
    CRITICAL_BLOCK(cs_p2pool)
    {
        Share s;
        for (size_t i = 0; i < vIds.size(); i++)
            if (ps.chain->GetShare(vIds[i], s))
                vOut.push_back(s);
    }
    foreach(const Share& s, vOut)
    {
        if (SendQueueFull(k, pfrom))
            break;
        PushShare(ps, pfrom, s);
    }
}

static void OnSync(PoolState& ps, CNode* pfrom)
{
    // A few bytes in, a whole history out: once per peer per interval;
    // to an inbound peer not past what inbound peers together may hold
    // queued (the per-peer cap times every connection was the only
    // bound); to an unproven one once per connection and no more often
    // than the shared budget allows (the throttle is per connection, and
    // a new one starts it afresh). An ask that has to wait is held and
    // answered when there is room (DeferSync).
    int nDecision = HistoryServeDecision(ps, pfrom, false);
    if (nDecision == SERVE_NOW)
        ServeNow(ps, pfrom);
    else if (nDecision == SERVE_LATER)
        DeferSync(ps, pfrom);
}

static void OnShares(PoolState& ps, CNode* pfrom, int nTipHeight, const vector<Share>& part, int nFlag)
{
    const int64 nHistoryShares = ps.chain->Rules().HistoryShares();
    if (part.size() > ps.SharesPerMessage())
    {
        pfrom->Misbehaving(20);
        return;
    }
    // A history is what this node asks a peer for, not something a peer
    // may push: only from one we asked, soon after asking, and no more
    // than one history per asking.
    PeerRef peer = Peer(ps, pfrom);
    if (peer.nSyncAskedAt == 0 || GetTime() - peer.nSyncAskedAt > ps.AnswerWindow())
        return;
    peer.nHistoryRecv += part.size();
    // A history holds the line and the uncles it names, up to two a share.
    if (peer.nHistoryRecv > 3 * nHistoryShares + 2 * ps.SharesPerMessage())
        return;
    int64 nTop = 0;
    foreach(const Share& s, part)
    {
        if (!ShareSane(s))
        {
            pfrom->Misbehaving(20);
            return;
        }
        nTop = std::max(nTop, (int64)s.data.nShareHeight);
    }
    // Which shares are deep enough to take on their work alone depends on
    // the tip height the peer states; it cannot state one further above
    // what it sends than a history reaches.
    nTipHeight = (int)std::min((int64)nTipHeight, std::min(nTop + nHistoryShares, (int64)p2pool::MAX_SHARE_HEIGHT));
    NodeMainView main;
    string err;
    bool fOk = true;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = ps.chain->AddHistory(part, nTipHeight, main, err);
        NoteChainGrew(ps);
    }
    if (!fOk)
    {
        LogPrint("p2pool", "p2pool: history refused: %s\n", err.c_str());
        pfrom->Misbehaving(20);
    }
    // The last part: the answer is over, and this node may ask again.
    if (nFlag != PART_MORE)
        peer.nSyncAskedAt = 0;
    if (fOk && !ps.fZero)
        MaybeSaveShares(ps);
}

// The messages of local pools. Nothing here answers, scores or logs for a
// peer that is not a member: it is told nothing, as a node with no local
// pool, or one that does not know the commands, tells it nothing.
static bool LocalProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "p2lhello")
    {
        if (vRecv.size() != poollocal::NONCE_BYTES + poollocal::TAG_BYTES)
            return true;
        WireHello w;
        vRecv >> w;
        int64 nNow = GetTime();
        CRITICAL_BLOCK(cs_p2pool)
        {
            if (vLocalPools.empty())
                return true;
            if (!pfrom->fInbound)
            {
                // The answer to a hello of ours.
                map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pfrom);
                if (it == mapLocalConn.end())
                    return true;
                foreach(LocalPool* lp, vLocalPools)
                {
                    WireAck ack;
                    unsigned char h[poollocal::HANDLE_BYTES];
                    if (lp->fLeaving || !lp->sessions.OnReply(it->second.nConn, w.h, ack.ack, h))
                        continue;
                    PushReg(pfrom, "p2lack", ack);
                    OpenSession(lp, pfrom, h);
                    break;
                }
                return true;
            }
            LocalConn& c = LocalConnOf(pfrom);
            if (!c.limiter.Allow(nNow))
                return true;
            vector<string> vOwn;
            OwnOnions(vOwn);
            if (vOwn.empty())
                return true;
            unsigned char nB[poollocal::NONCE_BYTES];
            GetStrongRandBytes(nB, sizeof(nB));
            foreach(LocalPool* lp, vLocalPools)
            {
                WireHello reply;
                if (lp->fLeaving || !lp->sessions.OnHello(c.nConn, vOwn, w.h, nB, nNow, reply.h))
                    continue;
                PushReg(pfrom, "p2lhello", reply);
                break;
            }
        }
        return true;
    }

    if (strCommand == "p2lack")
    {
        if (vRecv.size() != poollocal::ACK_BYTES || !pfrom->fInbound)
            return true;
        WireAck ack;
        vRecv >> ack;
        CRITICAL_BLOCK(cs_p2pool)
        {
            map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pfrom);
            if (it == mapLocalConn.end())
                return true;
            foreach(LocalPool* lp, vLocalPools)
            {
                unsigned char h[poollocal::HANDLE_BYTES];
                if (lp->fLeaving || !lp->sessions.OnAck(it->second.nConn, ack.ack, GetTime(), h))
                    continue;
                OpenSession(lp, pfrom, h);
                break;
            }
        }
        return true;
    }

    if (strCommand != "p2lshare" && strCommand != "p2lgetsh" && strCommand != "p2lsync" && strCommand != "p2lshares")
        return false;

    // Every other message starts with the session's handle. One this node
    // does not hold on this connection: dropped unread, nobody scored.
    if (vRecv.size() < sizeof(uint64))
        return true;
    uint64 h;
    vRecv >> h;
    LocalPool* lp;
    CRITICAL_BLOCK(cs_p2pool)
        lp = LocalByHandle(pfrom, h);
    if (!lp)
        return true;
    // A pool is taken down on this thread only (LocalTick), so it lives
    // until this message is done.
    PoolState& ps = lp->state;

    if (strCommand == "p2lshare")
    {
        ShareX s;
        vRecv >> s;
        OnShare(ps, pfrom, s);
    }
    else if (strCommand == "p2lgetsh")
    {
        vector<uint256> vIds;
        vRecv >> vIds;
        OnGetSh(ps, pfrom, vIds);
    }
    else if (strCommand == "p2lsync")
    {
        uint256 hashResume;
        vRecv >> hashResume;
        // At most three asks an interval for a (connection, pool); a fourth
        // is dropped, silently.
        bool fDrop = false;
        CRITICAL_BLOCK(cs_p2pool)
        {
            map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pfrom);
            if (it == ps.mapPeer.end())
                fDrop = true;
            else
            {
                PeerPool& peer = it->second;
                int64 nNow = GetTime();
                if (nNow - peer.nAsksSince >= SYNC_SERVE_INTERVAL)
                {
                    peer.nAsksSince = nNow;
                    peer.nAsks = 0;
                    // One history's worth an interval; for an unproven
                    // inbound connection, in its life.
                    if (PeerProven(ps, pfrom))
                        peer.nServedShares = 0;
                }
                if (++peer.nAsks > 3 || peer.nServedShares >= RegServeAllowance(ps))
                    fDrop = true;
                else
                    peer.hashResume = hashResume;
            }
        }
        if (!fDrop)
            OnSync(ps, pfrom);
    }
    else
    {
        int nTipHeight;
        unsigned char nFlag;
        vector<ShareX> vx;
        vRecv >> nTipHeight >> nFlag >> vx;
        if (nFlag > PART_ENDED_EARLY)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        vector<Share> part(vx.begin(), vx.end());
        OnShares(ps, pfrom, nTipHeight, part, nFlag);
    }
    return true;
}

bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "p2pshare")
    {
        Share s;
        vRecv >> s;
        OnShare(PoolZero(), pfrom, s);
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
        OnGetSh(PoolZero(), pfrom, vIds);
        return true;
    }

    if (strCommand == "p2psync")
    {
        OnSync(PoolZero(), pfrom);
        return true;
    }

    if (strCommand == "p2pshares")
    {
        int nTipHeight;
        vector<Share> part;
        vRecv >> nTipHeight >> part;
        OnShares(PoolZero(), pfrom, nTipHeight, part, PART_MORE);
        return true;
    }

    if (strCommand.compare(0, 3, "p2l") == 0)
        return LocalProcessMessage(pfrom, strCommand, vRecv);

    return false;
}
