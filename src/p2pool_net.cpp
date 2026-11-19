// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_net.h"
#include "poolindex.h"
#include "poolticket.h"
#include "btfaddr.h"
#include "nostr.h"
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <list>
#include <mutex>
#include <thread>
#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <sys/resource.h>
#include <sys/syscall.h>
#endif

using namespace p2pool;

CCriticalSection cs_p2pool;

// ---- Share times (-sharetimelog) --------------------------------------------
//
// The delay of a registered pool's share between two nodes is measured from
// these lines (docs/pool-registry.md, sections 15 and 17): found here,
// received from a peer, sent to one, asked for. Each line carries the wall
// clock in milliseconds, on hosts whose clocks NTP keeps close, and goes to
// sharetime.log in the data directory, never collapsed the way debug.log
// lines are. Off by default.
bool fShareTimeLog = false;
static CCriticalSection cs_shareTimeLog;

std::string ShareTimeLine(int64 nMillis, const char* pszEvent, const uint256& idPool, const uint256& idShare,
                          int nHeight, const std::string& strPeer)
{
    return strprintf("%lld %s %s %s %d %s\n", (long long)nMillis, pszEvent, idPool.ToString().substr(0, 16).c_str(),
                     idShare.ToString().c_str(), nHeight, strPeer.empty() ? "-" : strPeer.c_str());
}

// A peer as the lines name it: the start of its .btf address, else its
// network address.
static std::string ShareTimePeer(CNode* pnode)
{
    if (!pnode)
        return "";
    if (!pnode->strBtfAddr.empty())
        return pnode->strBtfAddr.substr(0, 16);
    return pnode->addr.ToString();
}

static void ShareTimeLog(const char* pszEvent, const uint256& idPool, const uint256& idShare, int nHeight, CNode* pnode)
{
    if (!fShareTimeLog)
        return;
    int64 nMillis = (int64)std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string strLine = ShareTimeLine(nMillis, pszEvent, idPool, idShare, nHeight, ShareTimePeer(pnode));
    CRITICAL_BLOCK(cs_shareTimeLog)
    {
        // Binary: the same "\n" line ends on every platform.
        FILE* f = fopen((GetAppDir() + "/sharetime.log").c_str(), "ab");
        if (f)
        {
            fwrite(strLine.data(), 1, strLine.size(), f);
            fclose(f);
        }
    }
}

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
// And the receiving window of such a pool's history: its parts come paced,
// the first within the hour, each next within 5 minutes of the one before.
static const int64 REG_SYNC_ANSWER_WINDOW = 60 * 60;
static const int64 REG_PART_WAIT = 5 * 60;
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
    uint256 hashTipCame;  // that pool's tip when it came (pools other than zero)
    bool fSync;
    // The pools whose history is asked for: pool zero's entry names pool
    // zero; a connection may wait for up to MAX_DEFERRED_ASKS other pools.
    vector<PoolState*> vSync;
};
static const size_t MAX_DEFERRED = 64;
static const size_t MAX_DEFERRED_ASKS = 8;

// What proven peers may make this node hash in the registered class. A pool
// makes one share a spacing (20 s at the fastest a record allows), and each
// reaches a node once per session but is hashed once (a share already held
// costs no hash). A session: twice its pool's rate, with a burst for the
// parents and uncles asked for after a gap. All sessions of one pool
// together: one token every 8 s against one share every 20 s at the fastest
// spacing, with a burst; each pool has its own, so the members of one pool
// cannot spend another's (four pools, the most a node joins, get one token
// every 2 s in all).
static const int SESSION_WORK_BURST = 16;
static const int POOL_WORK_BURST = 16;
static const int64 POOL_WORK_SECS = 8;
static int64 SessionWorkSecs(unsigned int nSpacing)
{
    return std::max((int64)1, (int64)nSpacing / 2);
}
// Within a pool, the sessions take turns (ProvenBefore): the one that wasted
// fewer of its tokens lately first. A token spent on a side share (one that
// did not become this node's tip, did not build on it when it came, and was
// not asked for) is wasted; one whose share became the tip pays one back
// (NoteProvenWork). Capped, so a session that turns honest is back in line
// within a few dozen shares.
static const int MAX_WORK_DEBT = 64;
// The shares asked for that NoteProvenWork excuses: asked within this long,
// and at most this many remembered a pool (each ask is for the parent and
// uncles of a share that was hashed on these same budgets).
static const int64 ASKED_WINDOW = 10 * 60;
static const size_t MAX_ASKED_IDS = 4096;

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
    // Shares that proven peers of the registered class (members in session,
    // every connection this node dialled among them) send unasked are not
    // hashed on this class's budgets but on their pool's and their session's
    // (PoolState::budgetProvenWork, PeerPool::budgetWork). Pool zero's proven
    // peers draw on nothing, as in 1.2.34.

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
    bool TakeDeferred(CNode* pnode, bool fShare, Share* pShare = NULL, PoolState** ppPool = NULL,
                      uint256* pTipCame = NULL);
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
    // RandomX hashes of shares it sends unasked while proven (section 8,
    // PoolState::budgetProvenWork), sized from its pool's spacing; when it
    // last took one of its pool's, and how many it wasted lately (its place
    // in the pool's turns, ProvenBefore).
    P2PoolBudget budgetWork;
    int64 nLastWorkAt;
    int nWorkDebt;
    // When the last part of the history this node asked it for came: the
    // next must come within REG_PART_WAIT of it (section 17).
    int64 nLastPartAt;
    explicit PeerPool(unsigned int nSpacing = 0)
        : nSyncServed(0), nSyncAskedAt(0), nHistoryRecv(0), nLastGood(0),
          nAsksSince(0), nAsks(0), nServedShares(0), hashResume(0),
          budgetWork(SESSION_WORK_BURST, SessionWorkSecs(nSpacing)), nLastWorkAt(0), nWorkDebt(0),
          nLastPartAt(0) {}
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
    // An entry is erased on the message thread only, which holds references
    // into it (PeerRef) outside cs_p2pool.
    map<CNode*, PeerPool> mapPeer;
    // A pool other than zero: RandomX hashes of shares its proven peers send
    // unasked, all its sessions together. A member is a member only by
    // password: a dishonest one could otherwise make every member hash side
    // lines at a home pool's floor (about 4096 hashes a share) as fast as it
    // found them, on the thread that also serves pool zero. Unused for pool
    // zero.
    P2PoolBudget budgetProvenWork;
    // A pool other than zero: the shares this node asked its members for
    // lately (p2lgetsh), by id, and when. A token spent on one of them is
    // never wasted (NoteProvenWork): parents and uncles this node needed do
    // not count against the member that answered. Unused for pool zero.
    map<uint256, int64> mapAskedAt;

    PoolState(PoolClass* clsIn, ShareChain* chainIn, const string& strFileIn)
        : cls(clsIn), fZero(clsIn->fZero), chain(chainIn), strFile(strFileIn),
          nFirstHistoryAsk(0), nLastSave(0), nAskedOnOpen(0), budgetProvenWork(POOL_WORK_BURST, POOL_WORK_SECS) {}

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
    // Stretches already sent go first: messages queued here without a
    // SendQueued in between (a relay to every session) would otherwise pile
    // up old stretches until the merge below joined two of them across
    // whatever pool zero queued between, and counted those bytes as theirs.
    while (!pnode->vRegSpans.empty() && pnode->vRegSpans.front().second <= pnode->nSendDrained)
        pnode->vRegSpans.pop_front();
    // Never more than a few hundred stretches still waiting: past that the
    // two neighbours with the least between them become one, and what lay
    // between them (pool zero's bytes, if any) counts with them from then
    // on. A heuristic: the smallest gap is joined, so a pool zero history
    // queued between two stretches is joined across only once every other
    // gap waiting is at least as large.
    if (pnode->vRegSpans.size() > 512)
    {
        size_t iBest = 1;
        uint64 nBest = pnode->vRegSpans[1].first - pnode->vRegSpans[0].second;
        for (size_t i = 2; i < pnode->vRegSpans.size(); i++)
        {
            uint64 nGap = pnode->vRegSpans[i].first - pnode->vRegSpans[i - 1].second;
            if (nGap < nBest)
            {
                nBest = nGap;
                iBest = i;
            }
        }
        pnode->vRegSpans[iBest - 1].second = pnode->vRegSpans[iBest].second;
        pnode->vRegSpans.erase(pnode->vRegSpans.begin() + iBest);
    }
}

// Self-tests: n bytes queued as a message of a pool other than zero, and
// what such messages hold queued.
void P2PoolQueueRegBytesForTest(CNode* pnode, size_t n)
{
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        uint64 nFrom = pnode->nSendDrained + pnode->vSend.size();
        std::vector<char> v(n, 0x5a);
        if (n)
            pnode->vSend.write(&v[0], n);
        NoteRegSpan(pnode, nFrom);
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

size_t P2PoolRegQueuedForTest(CNode* pnode, size_t* pnSpans)
{
    size_t n;
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        if (pnSpans)
            *pnSpans = pnode->vRegSpans.size();
        n = RegQueuedLocked(pnode);
    }
    return n;
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

template <typename T1, typename T2, typename T3>
static void PushReg(CNode* pnode, const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
{
    CRITICAL_BLOCK(pnode->cs_vSend)
    {
        uint64 nFrom = pnode->nSendDrained + pnode->vSend.size();
        pnode->PushMessage(pszCommand, a1, a2, a3);
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

// Registered pools (further down): the pool a PoolState belongs to, if it is
// one, under cs_p2pool; and what its file starts with.
struct RegPool;
static RegPool* RegOf(PoolState& ps);
static uint256 RegZeroId();
static const vector<unsigned char>* RegRecordOf(PoolState& ps);
static bool RegSaveAllowed(PoolState& ps);
// Under cs_p2pool: whether a registered pool's p2xsync to this peer stays
// within what the peer answers (3 per pool, 8 in all, an interval), and the
// count of one sent. True, and nothing counted, for any other pool.
static bool RegAskRoomLocked(PoolState& ps, CNode* pnode);
static void RegNoteAskLocked(CNode* pnode, const uint256& id);
// Guardians and tickets (further down, docs/pool-registry.md section 10).
static bool TktActive();
static void TktTick(int64 nNow);
static void TktFlush();
static void TktResetForTest();
static void GuardApply(int64 nNow);
static void GuardNoteAnnouncedLocked(const uint256& id);
static bool TktProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv);
// Bytes a second each registered history serve is paced to (-poolguardkbps).
static int64 nRegServeRate = 64 * 1000;
// A registered pool's share files (pools/<id>.dat and .part) start with this
// byte, then the pool's record: a build reads its own format only, and a
// file of another pool is never read as this one's.
static const unsigned char REG_SHARES_FORMAT = 1;

// A local pool's share file starts with this byte, the version of what
// follows; a build reads its own version only. Pool zero's p2pool.dat has
// none, as in 1.2.34.
static const unsigned char LOCAL_SHARES_FORMAT = 1;
// A file of another format is set aside under this suffix before anything is
// saved over it (a build that reads it may come back), and goes with the
// pool's other files when the pool is left.
static const char* const LOCAL_SHARES_ASIDE = ".other";

static void LoadShares(PoolState& ps)
{
    ShareChain& chain = *ps.chain;
    vector<Share> v;
    int nTipHeight = 0;
    bool fOtherFormat = false;
    try
    {
        CAutoFile file(fopen(ps.strFile.c_str(), "rb"));
        if (!file)
            return;
        if (ps.fZero)
            file >> nTipHeight >> v;
        else
        {
            unsigned char nFormat = 0;
            file >> nFormat;
            if (nFormat != LOCAL_SHARES_FORMAT)
            {
                printf("p2pool: a local pool's saved share chain is in format %u, this build reads format %u only; "
                       "it is set aside, and the pool starts from peers\n", (unsigned)nFormat, (unsigned)LOCAL_SHARES_FORMAT);
                fOtherFormat = true;
            }
            else
            {
                vector<ShareL> vx;
                file >> nTipHeight >> vx;
                v.assign(vx.begin(), vx.end());
            }
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
    if (fOtherFormat)
    {
        // The file is closed by now (Windows renames no open file), and an
        // older one set aside makes way (nor over an existing one).
        string strAside = ps.strFile + LOCAL_SHARES_ASIDE;
        remove(strAside.c_str());
        rename(ps.strFile.c_str(), strAside.c_str());
        return;
    }
    NodeMainView main;   // the clock only: no lock needed for it
    string err;
    if (!chain.AddHistory(v, nTipHeight, main, err))
        printf("p2pool: saved share chain refused (%s); starting from peers\n", err.c_str());
    printf("p2pool: %u shares loaded, tip at height %d\n", (unsigned)chain.Size(), chain.Height(chain.Tip()));
}

// fPrivate: owner-only, for a local pool's file, whose shares carry the pool
// id (with the code, a password oracle; section 18).
// True once the file is in place. A registered pool's that could not be
// written is left as it was (RegComplete keeps the partial file then).
static bool WriteShares(const string& strFile, int nTipHeight, const vector<Share>& v, bool fPrivate,
                        const vector<unsigned char>* pRecord = NULL)
{
    string tmp = strFile + ".new";
    if (pRecord)
    {
        // A registered pool's, its record in front, in pools/ (made here: a
        // pool mined from its first share never wrote a partial file, which
        // made the directory before). Nothing secret in it, but owner-only
        // like every file this node writes for itself.
        _mkdir((GetAppDir() + "/pools").c_str());
        bool fWritten = false;
        try
        {
            CAutoFile file(OpenPrivateFile(tmp.c_str(), false));
            if (file)
            {
                file << REG_SHARES_FORMAT << *pRecord << nTipHeight << v;
                fWritten = fflush(file) == 0;
            }
        }
        catch (std::exception& e)
        {
            printf("p2pool: %s not written (%s)\n", tmp.c_str(), e.what());
        }
        if (!fWritten)
        {
            remove(tmp.c_str());
            return false;
        }
    }
    else if (fPrivate)
    {
        CAutoFile file(OpenPrivateFile(tmp.c_str(), false));
        if (!file)
            return false;
        file << LOCAL_SHARES_FORMAT << nTipHeight << v;
    }
    else
    {
        CAutoFile file(fopen(tmp.c_str(), "wb"));
        if (!file)
            return false;
        file << nTipHeight << v;
    }
    // Windows will not rename over an existing file.
    remove(strFile.c_str());
    return rename(tmp.c_str(), strFile.c_str()) == 0;
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

// Under cs_p2pool. The budgets for a proven peer's share in a pool other
// than zero: its session's and its pool's, both with a token left; fTake
// takes one of each. False for a connection with no session in that pool.
static bool ProvenWorkLocked(PoolState& ps, CNode* pnode, bool fTake)
{
    map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pnode);
    if (it == ps.mapPeer.end())
        return false;
    int64 nNow = GetTime();
    if (it->second.budgetWork.Tokens(nNow) <= 0 || ps.budgetProvenWork.Tokens(nNow) <= 0)
        return false;
    if (fTake)
    {
        it->second.budgetWork.Take(nNow);
        ps.budgetProvenWork.Take(nNow);
        it->second.nLastWorkAt = nNow;
    }
    return true;
}

// Under cs_p2pool. Whether session a goes before session b for its pool's
// next token: the one that wasted fewer lately, then the one that had a
// token longer ago, then the older connection. A connection opened again
// and again starts each time at the back of its turn (OpenSession), and a
// member that floods side shares from many sessions falls behind every
// member whose shares become the tip.
static bool ProvenBefore(const PeerPool& a, const CNode* na, const PeerPool& b, const CNode* nb)
{
    if (a.nWorkDebt != b.nWorkDebt)
        return a.nWorkDebt < b.nWorkDebt;
    if (a.nLastWorkAt != b.nLastWorkAt)
        return a.nLastWorkAt < b.nLastWorkAt;
    return na->nTimeConnected < nb->nTimeConnected;
}

// Under cs_p2pool: whether a connection has an open session in a pool other
// than zero (its handle; the state in mapPeer outlives it until the message
// thread takes it down, LocalFinishClosings).
static bool InSessionLocked(PoolState& ps, CNode* pnode);

// Under cs_p2pool. The session behind a held share of a pool other than
// zero that would be hashed on the proven budgets; NULL if the entry holds
// no such share, or its session has been closed since (a closed session's
// share is neither hashed nor passed on).
static PeerPool* HeldProvenSession(const P2PoolDeferred& d)
{
    if (!d.fShare || !d.poolShare || d.poolShare->fZero)
        return NULL;
    map<CNode*, PeerPool>::iterator it = d.poolShare->mapPeer.find(d.pnode);
    if (it == d.poolShare->mapPeer.end() || !InSessionLocked(*d.poolShare, d.pnode))
        return NULL;
    if ((d.pnode->fInbound && it->second.nLastGood == 0) || d.pnode->nMisbehavior != 0)
        return NULL;
    return &it->second;
}

// Under cs_p2pool. Whether another session of this pool holds a share that
// goes before this connection's (ProvenBefore) and that its own session's
// budget would let through: a share that comes in live waits behind it.
// Held shares of unproven peers, and of other pools, draw on other budgets
// and do not count.
static bool ProvenAheadHeld(PoolState& ps, CNode* pnode)
{
    map<CNode*, PeerPool>::iterator itOwn = ps.mapPeer.find(pnode);
    if (itOwn == ps.mapPeer.end())
        return false;
    int64 nNow = GetTime();
    for (map<CNode*, P2PoolDeferred>::iterator it = ps.cls->mapDeferred.begin(); it != ps.cls->mapDeferred.end(); ++it)
    {
        if (it->first == pnode || it->second.poolShare != &ps || it->first->fDisconnect)
            continue;
        PeerPool* p = HeldProvenSession(it->second);
        if (p && p->budgetWork.Tokens(nNow) > 0 && ProvenBefore(*p, it->first, itOwn->second, pnode))
            return true;
    }
    return false;
}

// Under cs_p2pool. Shares this node asked a member of a pool other than zero
// for: remembered for ASKED_WINDOW, at most MAX_ASKED_IDS (the expired go
// first, then the oldest).
static void NoteAskedLocked(PoolState& ps, const vector<uint256>& vIds)
{
    int64 nNow = GetTime();
    foreach(const uint256& id, vIds)
        ps.mapAskedAt[id] = nNow;
    if (ps.mapAskedAt.size() <= MAX_ASKED_IDS)
        return;
    for (map<uint256, int64>::iterator it = ps.mapAskedAt.begin(); it != ps.mapAskedAt.end();)
        if (nNow - it->second > ASKED_WINDOW)
            ps.mapAskedAt.erase(it++);
        else
            ++it;
    while (ps.mapAskedAt.size() > MAX_ASKED_IDS)
    {
        map<uint256, int64>::iterator itOldest = ps.mapAskedAt.begin();
        for (map<uint256, int64>::iterator it = ps.mapAskedAt.begin(); it != ps.mapAskedAt.end(); ++it)
            if (it->second < itOldest->second)
                itOldest = it;
        ps.mapAskedAt.erase(itOldest);
    }
}

// Under cs_p2pool.
static bool AskedLately(const PoolState& ps, const uint256& id)
{
    map<uint256, int64>::const_iterator it = ps.mapAskedAt.find(id);
    return it != ps.mapAskedAt.end() && GetTime() - it->second <= ASKED_WINDOW;
}

// What a token a proven member spent came to. Its share became this node's
// tip, or the tip is now a share it let in (an orphan waiting for it): one
// wasted token paid back. It did not, and it was a side share: one more
// wasted. It did not, but it was no side share when it came -- it built on
// this node's tip then (it lost a race, or waited in this node's own queue
// while the tip moved on), or this node had asked for it (a parent or an
// uncle this node lacked): nothing changes. So the turns of section 18 are
// not lost by waiting behind others, nor by answering this node's asks. A
// share without its work is excused all the same and scored as any: its
// sender is no longer proven, and draws on these budgets no more.
static void NoteProvenWork(PoolState& ps, CNode* pnode, bool fTip, bool fExcused)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pnode);
        if (it != ps.mapPeer.end())
        {
            int& n = it->second.nWorkDebt;
            if (fTip)
                n = std::max(0, n - 1);
            else if (!fExcused)
                n = std::min(MAX_WORK_DEBT, n + 1);
        }
    }
}

// The shared budget behind WorkGate, for one peer's share. A share that
// comes in live waits behind any held for an older connection: else whoever
// sends the most, on fresh connections, takes every token as it refills, and
// the held share of an honest peer that stayed is never reached. A proven
// member's share in a pool other than zero waits, the same way, behind one
// held for a session ahead of it in its pool's turns.
class PeerWorkGate : public WorkGate
{
public:
    PeerWorkGate(PoolState& psIn, CNode* pnodeIn, bool fFromQueueIn)
        : ps(psIn), k(*psIn.cls), pnode(pnodeIn), fFromQueue(fFromQueueIn), fTookProven(false) {}
    bool Allow()
    {
        bool f;
        CRITICAL_BLOCK(cs_p2pool)
        {
            if (!k.fZero && PeerProven(ps, pnode))
            {
                f = (fFromQueue || !ProvenAheadHeld(ps, pnode)) && ProvenWorkLocked(ps, pnode, true);
                fTookProven = fTookProven || f;
            }
            else
                f = (fFromQueue || !k.OlderHeld(pnode, true)) && k.budgetShareWork.Take(GetTime());
        }
        return f;
    }
    bool TookProven() const { return fTookProven; }
private:
    PoolState& ps;
    PoolClass& k;
    CNode* pnode;
    bool fFromQueue;
    bool fTookProven;
};

// Unproven peers go through the gate; in the registered class, proven ones
// too, on budgets of their own (ProvenWorkLocked).
static bool NeedsGate(PoolState& ps, CNode* pfrom)
{
    return pfrom && (!ps.fZero || !PeerProven(ps, pfrom));
}

static void LocalPoolsInit();
static void RegPoolsInit();

void P2PoolInit()
{
    // cs_main before cs_p2pool, the order every other caller takes them in.
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
        {
            LoadShares(PoolZero());
            LocalPoolsInit();
            RegPoolsInit();
        }
}

// Not under cs_p2pool: the line is copied under it, and written after, so
// the few MB of a history do not go to disk with the share chain locked.
// True when the file was written now, or the pool keeps none (memory only).
static bool MaybeSaveShares(PoolState& ps, bool fNow = false)
{
    vector<Share> v;
    int nTipHeight;
    string strFile;
    bool fPrivate;
    vector<unsigned char> vRecord;
    bool fReg = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (!fNow && GetTime() - ps.nLastSave < 120)
            return false;
        // A registered pool's line goes to pools/<id>.dat only once it is
        // complete; a fetch in progress has its own file (section 17).
        if (!RegSaveAllowed(ps))
            return false;
        ps.nLastSave = GetTime();
        ps.chain->History(v);
        nTipHeight = ps.chain->Height(ps.chain->Tip());
        strFile = ps.strFile;
        fPrivate = !ps.fZero;
        const vector<unsigned char>* pRecord = RegRecordOf(ps);
        if (pRecord)
        {
            vRecord = *pRecord;
            fReg = true;
        }
    }
    if (strFile.empty())
        return true;
    return WriteShares(strFile, nTipHeight, v, fPrivate, fReg ? &vRecord : NULL);
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
static bool RelayRegShare(PoolState& ps, const Share& s, CNode* pfrom);

static void RelayShare(PoolState& ps, const Share& s, CNode* pfrom)
{
    if (!ps.fZero)
    {
        if (!RelayRegShare(ps, s, pfrom))
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
    {
        if (!ps.nFirstHistoryAsk)
            ps.nFirstHistoryAsk = GetTime();
        // A new ask: its first part has the whole window to come.
        if (!ps.fZero)
        {
            map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pfrom);
            if (it != ps.mapPeer.end())
                it->second.nLastPartAt = 0;
        }
    }
    PushSync(ps, pfrom);
}

// Whether this node may ask that peer for its history now: always one it
// dialled or one that sent a share it took; an unproven peer only while the
// shared budget lasts. Each ask is up to three histories of shares to hash.
// A registered pool's ask also stays within what the peer answers; and the
// same peer asked again for the same fetch (fRepeat) spends from the budget
// whoever it is, so a peer this node dialled cannot have a fetch ask it over
// and over by ending each answer early.
static bool HistoryAskAllowed(PoolState& ps, CNode* pfrom, bool fRepeat = false)
{
    bool fRoom;
    CRITICAL_BLOCK(cs_p2pool)
        fRoom = RegAskRoomLocked(ps, pfrom);
    if (!fRoom)
        return false;
    if (!fRepeat && PeerProven(ps, pfrom))
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
// of it, and the caller may hold it for later (DeferShare). pTipCame: in a
// pool other than zero, the pool's tip when a held share came (the tip now,
// if not given).
static bool AcceptShare(PoolState& ps, const Share& s, CNode* pfrom, bool fHistory, bool* pfGateClosed = NULL,
                        bool fFromQueue = false, const uint256* pTipCame = NULL)
{
    PoolClass& k = *ps.cls;
    const int64 nHistoryShares = ps.chain->Rules().HistoryShares();
    const int nSyncGap = ps.chain->Rules().NearTipShares();
    PeerWorkGate gate(ps, pfrom, fFromQueue);
    NodeMainView main;
    vector<Share> todo(1, s);
    bool fFirst = true, fGood = true;
    // A pool other than zero: the shares this call takes, the peer's own
    // and those waiting for it, for whether the tip is one of them after.
    set<uint256> setTaken;
    uint256 hashTipCame = 0;
    if (pfGateClosed)
        *pfGateClosed = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        k.ExpireOrphans();
        if (!ps.fZero)
            hashTipCame = pTipCame ? *pTipCame : ps.chain->Tip();
    }
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
            if (fOk && !ps.fZero)
                setTaken.insert(id);
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
    if (gate.TookProven())
    {
        // Judged once the orphans it let in are in: a parent this node
        // asked for is the tip's ancestor, not the tip, until its child is.
        bool fTip, fExcused;
        CRITICAL_BLOCK(cs_p2pool)
        {
            fTip = setTaken.count(ps.chain->Tip()) != 0;
            fExcused = s.data.hashPrevShare == hashTipCame || AskedLately(ps, s.GetId());
        }
        NoteProvenWork(ps, pfrom, fTip, fExcused);
    }
    return fGood;
}

bool P2PoolSubmitShare(const Share& share, string& errOut, bool* pfBlock)
{
    NodeMainView main;
    bool fOk, fBlock = false;
    // A registered pool this node mines but cannot mine on now (pending, its
    // line not here yet): no share of it is kept, and never one of pool zero
    // in its place.
    CRITICAL_BLOCK(cs_p2pool)
        if (!P2PoolMinedReady(errOut))
            return false;
    PoolState& ps = PoolMined();
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = ps.chain->Add(share, main, errOut, NULL, &fBlock);
        if (fOk)
            NoteChainGrew(ps);
    }
    if (fOk && share.data.fX && !share.data.fSalt && fShareTimeLog)
        ShareTimeLog("found", share.data.poolId, share.GetId(), (int)share.data.nShareHeight, NULL);
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
static void RegOnVersion(CNode* pfrom);

void P2PoolOnVersion(CNode* pfrom)
{
    // A listed peer of one of this node's local pools is told so, and nobody
    // else is told anything.
    LocalOnVersion(pfrom);
    // A peer that reads the registry is told which registered pools this
    // node announces (poolinv), if any; nobody else hears of them.
    RegOnVersion(pfrom);

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

static void DeferShare(PoolState& ps, CNode* pnode, const Share& s, const uint256& hashTipCame)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        P2PoolDeferred* d = ps.cls->DeferredEntry(pnode);
        if (d)
        {
            d->fShare = true;
            d->share = s;
            d->poolShare = &ps;
            d->hashTipCame = hashTipCame;
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
bool PoolClass::TakeDeferred(CNode* pnode, bool fShare, Share* pShare, PoolState** ppPool, uint256* pTipCame)
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
        if (pTipCame)
            *pTipCame = it->second.hashTipCame;
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
// When an ask waits for a slot: the slowest serve older than 15 minutes that
// averages under 1 KB/s ends, flagged "ended early" (section 17). True if one
// did.
static bool RegEndSlowestServe();

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
    if (!ps.fZero && !RegServeSlotFree(ps, pfrom, fProven) &&
        !(RegEndSlowestServe() && RegServeSlotFree(ps, pfrom, fProven)))
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

// The registered class: the shares held for proven members, one at a time,
// each to the session first in its pool's turns (ProvenBefore) among those
// whose session and pool still have a token. The rest wait for the next
// pass.
static void ServeProvenHeld(PoolClass& k)
{
    for (size_t nServed = 0; nServed < MAX_DEFERRED; nServed++)
    {
        CNode* pnode = NULL;
        Share s;
        PoolState* pool = NULL;
        uint256 hashTipCame = 0;
        CRITICAL_BLOCK(cs_p2pool)
        {
            int64 nNow = GetTime();
            map<CNode*, P2PoolDeferred>::iterator itBest = k.mapDeferred.end();
            PeerPool* pBest = NULL;
            for (map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.begin(); it != k.mapDeferred.end(); ++it)
            {
                if (it->first->fDisconnect)
                    continue;
                PeerPool* p = HeldProvenSession(it->second);
                if (!p || p->budgetWork.Tokens(nNow) <= 0 || it->second.poolShare->budgetProvenWork.Tokens(nNow) <= 0)
                    continue;
                if (!pBest || ProvenBefore(*p, it->first, *pBest, itBest->first) ||
                    (!ProvenBefore(*pBest, itBest->first, *p, it->first) && it->second.nSeq < itBest->second.nSeq))
                {
                    pBest = p;
                    itBest = it;
                }
            }
            if (itBest != k.mapDeferred.end())
            {
                pnode = itBest->first;
                k.TakeDeferred(pnode, true, &s, &pool, &hashTipCame);
            }
        }
        if (!pnode || !pool)
            return;
        // The entry keeps its reference on the node until the pass after
        // this one, on this thread.
        bool fGateClosed = false, fGood = true;
        try { fGood = AcceptShare(*pool, s, pnode, false, &fGateClosed, true, &hashTipCame); }
        catch (std::exception& e) { LogPrint("p2pool", "p2pool: held share: %s\n", e.what()); }
        if (!fGood)
            pnode->Misbehaving(20);
        else if (fGateClosed)
        {
            CRITICAL_BLOCK(cs_p2pool)
            {
                map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.find(pnode);
                if (it != k.mapDeferred.end() && !it->second.fShare && pool->mapPeer.count(pnode))
                {
                    it->second.fShare = true;
                    it->second.share = s;
                    it->second.poolShare = pool;
                    it->second.hashTipCame = hashTipCame;
                }
            }
            return;
        }
    }
}

static void ServeDeferredClass(PoolClass& k)
{
    if (!k.fZero)
        ServeProvenHeld(k);
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
        // The registered class holds proven members' shares too, which wait
        // on their own budgets (PeerWorkGate): each held share is looked at.
        if (!k.fZero)
            fWorkLeft = true;
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
            uint256 hashTipCame = 0;
            bool fTaken = false;
            CRITICAL_BLOCK(cs_p2pool)
            {
                if (k.fZero)
                {
                    fWorkLeft = k.budgetShareWork.Tokens(GetTime()) > 0;
                    if (fWorkLeft)
                        fTaken = k.TakeDeferred(pnode, true, &s, &pool);
                }
                else
                {
                    // An unproven peer's share, on the class's budget. A
                    // proven member's waits for ServeProvenHeld (it was
                    // given its turn before this pass); one whose session
                    // has ended since (closed, or gone) goes.
                    map<CNode*, P2PoolDeferred>::iterator itD = k.mapDeferred.find(pnode);
                    PoolState* psHeld = itD != k.mapDeferred.end() && itD->second.fShare ? itD->second.poolShare : NULL;
                    bool fRoom = false;
                    if (psHeld && (!psHeld->mapPeer.count(pnode) || !InSessionLocked(*psHeld, pnode)))
                    {
                        itD->second.fShare = false;
                        itD->second.share = Share();
                        itD->second.poolShare = NULL;
                    }
                    else if (psHeld && !PeerProven(*psHeld, pnode))
                        fRoom = k.budgetShareWork.Tokens(GetTime()) > 0;
                    if (fRoom)
                        fTaken = k.TakeDeferred(pnode, true, &s, &pool, &hashTipCame);
                }
            }
            if (fTaken && pool)
            {
                bool fGateClosed = false, fGood = true;
                try { fGood = AcceptShare(*pool, s, pnode, false, &fGateClosed, true, k.fZero ? NULL : &hashTipCame); }
                catch (std::exception& e) { LogPrint("p2pool", "p2pool: held share: %s\n", e.what()); }
                if (!fGood)
                    pnode->Misbehaving(20);
                else if (fGateClosed)
                {
                    // Taken by somebody else in between: back in its place
                    // (a local pool's, only while its session lasts).
                    if (k.fZero)
                        fWorkLeft = false;
                    CRITICAL_BLOCK(cs_p2pool)
                    {
                        map<CNode*, P2PoolDeferred>::iterator it = k.mapDeferred.find(pnode);
                        if (it != k.mapDeferred.end() && !it->second.fShare && (k.fZero || pool->mapPeer.count(pnode)))
                        {
                            it->second.fShare = true;
                            it->second.share = s;
                            it->second.poolShare = pool;
                            it->second.hashTipCame = hashTipCame;
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
static void RegTick();

void P2PoolServeDeferred()
{
    ServeDeferredClass(classZero);
    ServeDeferredClass(classReg);
    LocalTick();
    RegTick();
}

static void LocalForgetNode(CNode* pnode);
static void RegForgetNode(CNode* pnode);

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
        RegForgetNode(pnode);
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
        classReg.budgetShareWork.Reset();
        classReg.budgetHistoryServe.Reset();
        classReg.budgetHistoryAsk.Reset();
    }
    P2PoolRefillProvenWorkForTest();
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

static void LocalDrainPoolWork(int64 nNow);

void P2PoolDrainRegisteredBudgetsForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        int64 nNow = GetTime();
        classReg.budgetShareWork.Drain(nNow);
        classReg.budgetHistoryServe.Drain(nNow);
        classReg.budgetHistoryAsk.Drain(nNow);
        LocalDrainPoolWork(nNow);
    }
}

static void LocalResetForTest(bool fCheckPoW);
static void RegResetForTest(bool fCheckPoW);

void P2PoolResetForTest(const CBigNum& bnFloor, bool fCheckPoW)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        PoolState& ps = PoolZero();
        classZero.Reset();
        classReg.Reset();
        LocalResetForTest(fCheckPoW);
        RegResetForTest(fCheckPoW);
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

// Sessions a poolpeers call ended on the RPC thread, for the message thread
// to finish (LocalFinishClosings): the message thread holds references into
// a pool's per-connection state (PeerRef) outside cs_p2pool, so only it may
// erase that state. No entry takes a reference on its node: a session is
// open only on a connection mapLocalConn holds one on, and LocalForgetNode
// drops a node's entries here before it lets that one go. (A reference
// taken here, on the RPC thread, raced the message thread's own: a node's
// count is a plain int, changed without a lock.) Under cs_p2pool.
struct LocalClosing
{
    LocalPool* lp;
    CNode* pnode;
};
static vector<LocalClosing> vLocalClosing;
// A list changed, or a pool was left: the message thread's next pass lets go
// of the pins the local pools took on connections no pool lists any more
// (LocalUnpinUnlisted). Under cs_p2pool.
static bool fLocalUnpinDue = false;
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
    // Answers to those read: at most two for each hello sent (the answer,
    // and one stray before it), so a peer this node dialled cannot make it
    // check answers it never asked for.
    int nRepliesRead;
    LocalConn() : nConn(0), nLastHelloSent(0), nHellosSent(0), nRepliesRead(0) {}
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
static bool ListedIn(const vector<string>& vPeers, const string& strBtfAddr, const string& O)
{
    foreach(const string& strPeer, vPeers)
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

static bool Listed(const LocalPool& lp, const string& strBtfAddr, const string& O)
{
    return ListedIn(lp.vPeers, strBtfAddr, O);
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

// A registered pool: its connection to a peer that reads the registry, while
// the pool is carried (further down).
static bool RegInSessionLocked(PoolState& ps, CNode* pnode);
static void RegServedTimesLocked(map<CNode*, int64>& out);

static bool InSessionLocked(PoolState& ps, CNode* pnode)
{
    LocalPool* lp = LocalOf(ps);
    if (lp)
        return lp->mapHandle.count(pnode) != 0;
    return RegInSessionLocked(ps, pnode);
}

static void RegServedTimes(map<CNode*, int64>& out)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        foreach(LocalPool* lp, vLocalPools)
            for (map<CNode*, PeerPool>::iterator it = lp->state.mapPeer.begin(); it != lp->state.mapPeer.end(); ++it)
                out[it->first] = std::max(out[it->first], it->second.nSyncServed);
        RegServedTimesLocked(out);
    }
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

// A registered pool's id, if ps is one and the peer reads the registry (its
// messages go to nobody else). fCarried: and only while the pool is carried.
static bool RegIdFor(PoolState& ps, CNode* pnode, uint256& idOut, bool fCarried);
// The resume point a registered pool's ask names (section 17): the newest
// share held of the history being fetched, else this node's tip.
static uint256 RegResumeLocked(PoolState& ps);

static void PushShare(PoolState& ps, CNode* pnode, const Share& s)
{
    uint64 h;
    uint256 id;
    if (ps.fZero)
        pnode->PushMessage("p2pshare", s);
    else if (HandleOf(ps, pnode, h))
        PushReg(pnode, "p2lshare", h, s);
    else if (RegIdFor(ps, pnode, id, true))
    {
        if (fShareTimeLog)
            ShareTimeLog("send", id, s.GetId(), (int)s.data.nShareHeight, pnode);
        PushReg(pnode, "p2xshare", id, ShareX(s));
    }
}

static void PushGetSh(PoolState& ps, CNode* pnode, const vector<uint256>& vIds)
{
    uint64 h;
    uint256 id;
    if (ps.fZero)
        pnode->PushMessage("p2pgetsh", vIds);
    else if (HandleOf(ps, pnode, h))
    {
        CRITICAL_BLOCK(cs_p2pool)
            NoteAskedLocked(ps, vIds);
        PushReg(pnode, "p2lgetsh", h, vIds);
    }
    else if (RegIdFor(ps, pnode, id, false))
    {
        CRITICAL_BLOCK(cs_p2pool)
            NoteAskedLocked(ps, vIds);
        for (size_t i = 0; i < vIds.size(); i++)
            ShareTimeLog("getsh", id, vIds[i], -1, pnode);
        PushReg(pnode, "p2xgetsh", id, vIds);
    }
}

static void PushSync(PoolState& ps, CNode* pnode)
{
    uint64 h;
    uint256 id;
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
    else if (RegIdFor(ps, pnode, id, false))
    {
        uint256 hashResume;
        CRITICAL_BLOCK(cs_p2pool)
        {
            hashResume = RegResumeLocked(ps);
            RegNoteAskLocked(pnode, id);
        }
        PushReg(pnode, "p2xsync", id, hashResume);
    }
}

// A part of a paced serve: false when the pool has no way to this peer any
// more (a local pool's session closed, a registered pool no longer carried).
static bool PushPart(PoolState& ps, CNode* pnode, int nTipHeight, unsigned char nFlag, const vector<Share>& part)
{
    uint64 h;
    uint256 id;
    if (HandleOf(ps, pnode, h))
    {
        PushReg(pnode, "p2lshares", h, nTipHeight, nFlag, part);
        return true;
    }
    if (RegIdFor(ps, pnode, id, true))
    {
        PushReg(pnode, "p2xshares", id, nTipHeight, nFlag, part);
        return true;
    }
    return false;
}

static void PushShares(PoolState& ps, CNode* pnode, int nTipHeight, const vector<Share>& part, bool fEnd)
{
    if (ps.fZero)
        pnode->PushMessage("p2pshares", nTipHeight, part);
    else
        PushPart(ps, pnode, nTipHeight, (unsigned char)(fEnd ? PART_END : PART_MORE), part);
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
    // The snapshot, oldest first: ids only, each share fetched as its part
    // goes out, so a slow serve of a large line holds kilobytes, not the
    // line (eight of them, at 64 kB/s, could otherwise hold a gigabyte).
    vector<uint256> vIds;
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
// Bytes a second, whatever the transport: for a registered pool
// nRegServeRate, -poolguardkbps (64 by default, section 11); for a local
// pool always 64 (section 18), whatever -poolguardkbps says.
static const int64 LOCAL_SERVE_RATE = 64 * 1000;
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
            const int64 nRate = RegOf(*r.pool) != NULL ? nRegServeRate : LOCAL_SERVE_RATE;
            if (r.nSent > (uint64)((nNow - r.nStart) * nRate))
            {
                ++it;
                continue;
            }
            vector<Share> part;
            size_t nPartBytes = 0;
            bool fGone = false;
            // A history holds the deep shares a line read back from its file
            // keeps on their work alone, as pool zero's History() does: the
            // asker takes them on their work alone too (AddHistory, the same
            // for registered and local pools). GetShare refuses those, so a
            // node that restarted served nothing but "ended early" (found on
            // testnet with a guardian pulling from a miner that had
            // restarted); GetHeld gives them, for both kinds of pool.
            while (r.i < r.vIds.size())
            {
                Share sh;
                if (!r.pool->chain->GetHeld(r.vIds[r.i], sh))
                {
                    // Pruned since the snapshot: the line from here is not
                    // what the asker would get, so the serve ends early
                    // and the asker asks again.
                    fGone = true;
                    break;
                }
                size_t n = ::GetSerializeSize(sh, SER_NETWORK);
                if (!part.empty() && (part.size() >= REG_SHARES_PER_MESSAGE || nPartBytes + n > REG_HISTORY_PART_BYTES))
                    break;
                part.push_back(sh);
                r.i++;
                nPartBytes += n;
            }
            PeerPool& peer = itPeer->second;
            unsigned char nFlag = fGone ? PART_ENDED_EARLY : r.i >= r.vIds.size() ? PART_END : PART_MORE;
            if (peer.nServedShares + part.size() > RegServeAllowance(*r.pool))
            {
                part.clear();
                nFlag = PART_ENDED_EARLY;
            }
            bool fSession = PushPart(*r.pool, r.pnode, r.nTipHeight, nFlag, part);
            // Ended by this node's own pruning, not by the asker: the ask
            // it made is not one of its three this interval.
            if (fGone && peer.nAsks > 0)
                peer.nAsks--;
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
        vector<int> vHeights;
        ps.chain->HistoryIds(r.vIds, vHeights);
        r.nTipHeight = ps.chain->Height(ps.chain->Tip());
        r.i = 0;
        // Where the resume point's branch meets the snapshot: the share
        // itself when it is on the line or an uncle the line names, else the
        // first of its ancestors that is (a fork below the resume point then
        // still comes). A resume point this node does not hold gets the
        // whole line.
        uint256 hashResume = itPeer->second.hashResume;
        if (hashResume != 0 && ps.chain->Has(hashResume))
        {
            map<uint256, size_t> mapAt;
            for (size_t i = 0; i < r.vIds.size(); i++)
                mapAt[r.vIds[i]] = i;
            // Walked by parent id: a copy of each share on the way, under
            // cs_p2pool, cost up to a line of them for nothing.
            uint256 cur = hashResume;
            for (size_t n = 0; cur != 0 && n <= ps.chain->Size(); n++)
            {
                map<uint256, size_t>::iterator itAt = mapAt.find(cur);
                if (itAt != mapAt.end())
                {
                    int64 nFrom = (int64)vHeights[itAt->second] - ps.chain->Rules().nUncleDepth;
                    while (r.i < r.vIds.size() && (int64)vHeights[r.i] < nFrom)
                        r.i++;
                    break;
                }
                uint256 prev;
                if (!ps.chain->ParentOf(cur, prev))
                    break;
                cur = prev;
            }
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
    uint64 n = poollocal::HandleValue(h);
    lp->mapHandle[pnode] = n;
    // A session opened again on a connection whose state this pool still
    // keeps (closed by poolpeers, the message thread not yet past it) keeps
    // that state: what it spent stays spent, and its asks stay counted. The
    // serves the old session asked for are not this one's (on this thread,
    // the message thread, as every serve change).
    for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
        if (it->pnode == pnode && it->pool == &lp->state)
            it = lRegServes.erase(it);
        else
            ++it;
    // A new one starts at the back of its pool's turns (ProvenBefore): with
    // as many wasted tokens as the session that has the most, and its last
    // token now. A member that closes a session and opens another so never
    // gets ahead of where it was, and sessions kept idle get one turn each
    // before a member whose shares extend the pool's line, no more: what
    // they then send for side lines is wasted, while the member's share
    // that waited behind them is not (NoteProvenWork).
    if (!lp->state.mapPeer.count(pnode))
    {
        PeerPool peer(lp->state.chain->Rules().nSpacing);
        peer.nLastWorkAt = GetTime();
        for (map<CNode*, PeerPool>::const_iterator it = lp->state.mapPeer.begin(); it != lp->state.mapPeer.end(); ++it)
            peer.nWorkDebt = std::max(peer.nWorkDebt, it->second.nWorkDebt);
        lp->state.mapPeer.insert(make_pair(pnode, peer));
    }
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
    for (size_t i = 0; i < vLocalClosing.size();)
        if (vLocalClosing[i].pnode == pnode)
            vLocalClosing.erase(vLocalClosing.begin() + i);
        else
            i++;
    if (it != mapLocalConn.end())
    {
        pnode->Release();
        mapLocalConn.erase(it);
    }
}

// Under cs_p2pool, on any thread: one pool's session with one connection
// ends (the peer was taken off the pool's list); the connection and its
// other pools stay. What the peer sends under the old handle is dropped
// unread from then on; the session's state, its serves and what it has held
// go on the message thread (LocalFinishClosings).
static void LocalCloseSession(LocalPool* lp, CNode* pnode)
{
    map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pnode);
    lp->mapHandle.erase(pnode);
    lp->mapHelloAt.erase(pnode);
    // Never without the entry that keeps the node alive (see vLocalClosing).
    if (it == mapLocalConn.end())
        return;
    lp->sessions.Close(it->second.nConn);
    LocalClosing c;
    c.lp = lp;
    c.pnode = pnode;
    vLocalClosing.push_back(c);
}

// Under cs_p2pool, on any thread: a hello in flight on a connection this
// node dialled, to a peer just taken off the pool's list, opens nothing.
static void LocalCloseHandshake(LocalPool* lp, CNode* pnode)
{
    map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pnode);
    if (it != mapLocalConn.end())
        lp->sessions.Close(it->second.nConn);
    lp->mapHelloAt.erase(pnode);
}

// Under cs_p2pool, on the message thread: the sessions poolpeers closed are
// taken down, unless one was opened again on the same connection since (the
// old session's serves went when it was, OpenSession).
static void LocalFinishClosings()
{
    vector<LocalClosing> v;
    v.swap(vLocalClosing);
    foreach(const LocalClosing& c, v)
    {
        LocalPool* lp = c.lp;
        CNode* pnode = c.pnode;
        if (!lp->mapHandle.count(pnode))
        {
            lp->state.mapPeer.erase(pnode);
            for (std::list<RegServe>::iterator itS = lRegServes.begin(); itS != lRegServes.end();)
                if (itS->pnode == pnode && itS->pool == &lp->state)
                    itS = lRegServes.erase(itS);
                else
                    ++itS;
            map<CNode*, P2PoolDeferred>::iterator itD = classReg.mapDeferred.find(pnode);
            if (itD != classReg.mapDeferred.end())
            {
                P2PoolDeferred& d = itD->second;
                if (d.fShare && d.poolShare == &lp->state)
                {
                    d.fShare = false;
                    d.share = Share();
                    d.poolShare = NULL;
                }
                d.vSync.erase(std::remove(d.vSync.begin(), d.vSync.end(), &lp->state), d.vSync.end());
                d.fSync = !d.vSync.empty();
                if (!d.fShare && !d.fSync)
                    classReg.EraseDeferred(itD);
            }
        }
    }
}

// A listed peer this node is connected to at an onion other than the one
// listed gets no hello there (a hello goes to the listed onion only: whoever
// else received one could test passwords against it), and that connection
// keeps the listed onion from being dialled (one connection per peer). After
// a grace with no session on it, it is dropped, at most once in this long per
// peer, and the dialler reaches the listed onion.
static const int64 WRONG_ONION_GRACE = 2 * 60;
static const int64 WRONG_ONION_DROP_INTERVAL = 30 * 60;
static const int64 WRONG_ONION_DROP_INTERVAL_FAILED = 4 * 60 * 60;
static map<string, int64> mapWrongOnionDropAt;

// Under cs_p2pool. True if the connection was dropped.
static bool LocalDropWrongOnion(CNode* pnode, int64 nNow)
{
    if (pnode->fInbound || pnode->fDisconnect || pnode->strBtfAddr.empty() ||
        nNow - pnode->nTimeConnected < WRONG_ONION_GRACE)
        return false;
    string O;
    if (!DialledOnion(pnode, O))
        return false;
    // Only for a listed onion worth reaching: one that answered last time,
    // every half hour at most; one whose last dial failed (gone, or moved)
    // only once its dial backoff has run out, and every few hours at most.
    // Dropping the connection that works every half hour for an onion that
    // is gone cost the member that peer for nothing; never dropping it left
    // the listed onion undialled for good after one failure (a peer already
    // connected is not dialled, so the failure was never tried again).
    bool fWorth = false, fWorthFresh = false;
    foreach(LocalPool* lp, vLocalPools)
    {
        if (lp->fLeaving)
            continue;
        if (lp->mapHandle.count(pnode) || Listed(*lp, pnode->strBtfAddr, O))
            return false;
        foreach(const string& strPeer, lp->vPeers)
        {
            if (strPeer.size() <= pnode->strBtfAddr.size() || strPeer[pnode->strBtfAddr.size()] != '@' ||
                strPeer.compare(0, pnode->strBtfAddr.size(), pnode->strBtfAddr) != 0)
                continue;
            if (!BtfListedDialFailed(strPeer))
                fWorth = fWorthFresh = true;
            else if (BtfListedDialDue(strPeer))
                fWorth = true;
        }
    }
    if (!fWorth)
        return false;
    map<string, int64>::iterator it = mapWrongOnionDropAt.find(pnode->strBtfAddr);
    int64 nInterval = fWorthFresh ? WRONG_ONION_DROP_INTERVAL : WRONG_ONION_DROP_INTERVAL_FAILED;
    if (it != mapWrongOnionDropAt.end() && nNow - it->second < nInterval)
        return false;
    mapWrongOnionDropAt[pnode->strBtfAddr] = nNow;
    LogPrint("p2pool", "p2pool: a listed peer is connected at another onion than the one listed; "
                       "dropping that connection so the listed onion is dialled\n");
    pnode->fDisconnect = true;
    return true;
}

bool P2PoolLocalDropWrongOnionForTest(CNode* pnode)
{
    bool f;
    CRITICAL_BLOCK(cs_p2pool)
        f = LocalDropWrongOnion(pnode, GetTime());
    return f;
}

void P2PoolLocalAgeWrongOnionDropsForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
        for (map<string, int64>::iterator it = mapWrongOnionDropAt.begin(); it != mapWrongOnionDropAt.end(); ++it)
            it->second -= nSecs;
}

// Under cs_p2pool: a pool this node left.
static void LocalRemove(LocalPool* lp)
{
    for (size_t i = 0; i < vLocalClosing.size();)
        if (vLocalClosing[i].lp == lp)
            vLocalClosing.erase(vLocalClosing.begin() + i);
        else
            i++;
    classReg.ForgetPool(&lp->state);
    for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
        if (it->pool == &lp->state)
            it = lRegServes.erase(it);
        else
            ++it;
    vLocalPools.erase(std::remove(vLocalPools.begin(), vLocalPools.end(), lp), vLocalPools.end());
    fLocalUnpinDue = true;
    if (!lp->state.strFile.empty())
    {
        remove(lp->state.strFile.c_str());
        remove((lp->state.strFile + ".new").c_str());
        remove((lp->state.strFile + LOCAL_SHARES_ASIDE).c_str());
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

// Under cs_vNodes and cs_p2pool, on the message thread: the pins the local
// pools took (fLocalPoolPin) on connections no pool lists any more go, and
// with them the reference each held. Only here: a node's reference count is
// changed without a lock, and this thread already changes it.
static void LocalUnpinUnlisted()
{
    foreach(CNode* pnode, vNodes)
    {
        string O;
        if (!pnode->fLocalPoolPin || pnode->fDisconnect || !DialledOnion(pnode, O))
            continue;
        bool fListed = false;
        foreach(LocalPool* lp, vLocalPools)
            if (!lp->fLeaving && Listed(*lp, pnode->strBtfAddr, O))
                fListed = true;
        if (fListed)
            continue;
        pnode->fLocalPoolPin = false;
        if (pnode->fNetworkNode)
        {
            pnode->fNetworkNode = false;
            pnode->Release();
        }
    }
}

// On the message thread, every pass: closings and pins to let go; once a
// second: pools left, hellos due, connections gone, replies nobody acked;
// serves in flight every pass.
static void LocalTick()
{
    static int64 nLast = 0;
    int64 nNow = GetTime();
    bool fUnpin;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (vLocalPools.empty() && mapLocalConn.empty() && !fLocalUnpinDue)
            return;
        LocalFinishClosings();
        fUnpin = fLocalUnpinDue;
    }
    // cs_vNodes before cs_p2pool; nothing takes them the other way round.
    if (fUnpin)
    {
        CRITICAL_BLOCK(cs_vNodes)
            CRITICAL_BLOCK(cs_p2pool)
            {
                LocalUnpinUnlisted();
                fLocalUnpinDue = false;
            }
    }
    if (nNow == nLast)
    {
        PumpRegServes();
        return;
    }
    nLast = nNow;
    CRITICAL_BLOCK(cs_p2pool)
    {
        vector<LocalPool*> vLeft;
        foreach(LocalPool* lp, vLocalPools)
            if (lp->fLeaving && &lp->state != pPoolMined)
                vLeft.push_back(lp);
        foreach(LocalPool* lp, vLeft)
            LocalRemove(lp);
    }
    CRITICAL_BLOCK(cs_vNodes)
        CRITICAL_BLOCK(cs_p2pool)
            foreach(CNode* pnode, vNodes)
            {
                LocalSendHello(pnode);
                LocalDropWrongOnion(pnode, nNow);
            }
    CRITICAL_BLOCK(cs_p2pool)
    {
        vector<CNode*> vGone;
        for (map<CNode*, LocalConn>::iterator it = mapLocalConn.begin(); it != mapLocalConn.end(); ++it)
            if (it->first->fDisconnect)
                vGone.push_back(it->first);
        foreach(CNode* pnode, vGone)
            LocalForgetNode(pnode);
        foreach(LocalPool* lp, vLocalPools)
            lp->sessions.Expire(nNow);
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
    vLocalClosing.clear();
    fLocalUnpinDue = false;
    mapWrongOnionDropAt.clear();
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

// Under cs_p2pool: whether a pool of this name may join now.
static bool LocalRoomFor(const string& strName, string& errOut)
{
    if (LocalByName(strName))
    {
        errOut = "a local pool with that name is already on this node";
        return false;
    }
    // Pools being left count until they are gone: their chains are still
    // in memory, and their files go only then.
    if (vLocalPools.size() >= poollocal::MAX_LOCAL_POOLS)
    {
        errOut = "this node is in as many local pools as it may be";
        return false;
    }
    return true;
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
    if (!LocalRoomFor(rec.name, errOut))
        return NULL;
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
    string strK = HexStr(lp.keys.K, lp.keys.K + sizeof(lp.keys.K), false);
    // Room for K and every peer line, so no reallocation leaves a copy of K.
    size_t nPeerBytes = 0;
    foreach(const string& strPeer, vPeers)
        nPeerBytes += 6 + strPeer.size();
    s.reserve(s.size() + 3 + strK.size() + nPeerBytes + 1);
    s += "k=";
    s += strK;
    s += "\n";
    OPENSSL_cleanse(&strK[0], strK.size());
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
            if (!h.empty())
                OPENSSL_cleanse(&h[0], h.size());
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
    // Its files go when a pool that is being left is taken down: the same
    // name, and so the same files, is not reused until then.
    LocalPool* lp = NULL;
    CRITICAL_BLOCK(cs_p2pool)
    {
        foreach(LocalPool* lpOld, vLocalPools)
            if (lpOld->fLeaving && lpOld->strName == rec.name)
            {
                errOut = "a local pool with that name is being left; try again in a few seconds";
                return false;
            }
        lp = LocalNew(rec, keys, strBase + ".dat", strBase + ".conf", fLocalCheckPoW, errOut);
    }
    if (!lp)
        return false;
    // A share chain left in the pool's file is read here, outside every
    // lock: its newest shares are checked in full, RandomX and all, and the
    // pool is nobody else's until it is added below. (The block index is
    // not needed: a share's validity rests on nothing of the main chain.)
    LoadShares(lp->state);
    bool fOk = true;
    CRITICAL_BLOCK(cs_p2pool)
    {
        foreach(LocalPool* lpOld, vLocalPools)
            if (lpOld->fLeaving && lpOld->strName == rec.name)
            {
                errOut = "a local pool with that name is being left; try again in a few seconds";
                fOk = false;
            }
        fOk = fOk && LocalRoomFor(rec.name, errOut) && WriteLocalConf(*lp, lp->vPeers, errOut);
        if (fOk)
        {
            vLocalPools.push_back(lp);
            LogPrint("p2pool", "p2pool: local pool '%s' joined\n", lp->strName.c_str());
        }
    }
    if (!fOk)
    {
        delete lp->state.chain;
        delete lp;
        return false;
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
    // The file first, with cs_p2pool alone: no disk write holds cs_vNodes.
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
    // A peer taken off the list: the session this node opened by dialling it
    // closes, and so does a hello still in flight to it (its answer opens
    // nothing). The connection is no longer kept for the pool, if this code
    // is what kept it and no other pool lists it: on the message thread's
    // next pass (LocalUnpinUnlisted), which lets the reference go there, not
    // here. cs_vNodes before cs_p2pool, as LocalTick.
    CRITICAL_BLOCK(cs_vNodes)
        CRITICAL_BLOCK(cs_p2pool)
        {
            LocalPool* lp = LocalByName(strName);
            foreach(CNode* pnode, vNodes)
            {
                string O;
                if (!lp || pnode->fDisconnect || !DialledOnion(pnode, O) || Listed(*lp, pnode->strBtfAddr, O))
                    continue;
                if (lp->mapHandle.count(pnode))
                    LocalCloseSession(lp, pnode);
                else
                    LocalCloseHandshake(lp, pnode);
            }
            fLocalUnpinDue = true;
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

bool P2PoolParseChoice(const string& strValue, string& strLocalOut, uint256& idRegOut, string& errOut)
{
    strLocalOut.clear();
    idRegOut = 0;
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
    // An Everpool pool: mined once the registry says it is active and its
    // line is here (section 9).
    idRegOut.SetHex(strLower);
    return true;
}

bool P2PoolParseCarry(const string& strValue, vector<uint256>& vOut, string& errOut)
{
    // Pool ids, separated by commas.
    size_t pos = 0;
    while (pos <= strValue.size())
    {
        size_t end = strValue.find(',', pos);
        string s = strValue.substr(pos, end == string::npos ? string::npos : end - pos);
        pos = end == string::npos ? strValue.size() + 1 : end + 1;
        for (size_t i = 0; i < s.size(); i++)
            s[i] = (char)tolower((unsigned char)s[i]);
        if (s.size() != 64 || !IsHex(s))
        {
            errOut = "-poolcarry takes pool ids of 64 hex digits, separated by commas";
            return false;
        }
        uint256 id;
        id.SetHex(s);
        if (id == RegZeroId())
        {
            errOut = "pool zero is always carried; -poolcarry is for the other pools";
            return false;
        }
        if (std::find(vOut.begin(), vOut.end(), id) == vOut.end())
            vOut.push_back(id);
    }
    if (vOut.size() > MAX_POOL_CARRY)
    {
        errOut = "at most 8 pools may be given with -poolcarry";
        return false;
    }
    return true;
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

bool P2PoolLocalStillListed(const string& strPeer)
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(LocalPool* lp, vLocalPools)
            if (!lp->fLeaving && std::find(lp->vPeers.begin(), lp->vPeers.end(), strPeer) != lp->vPeers.end())
                return true;
    return false;
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

// Under cs_p2pool. Self-tests: every local pool's budget for its proven
// peers emptied.
static void LocalDrainPoolWork(int64 nNow)
{
    foreach(LocalPool* lp, vLocalPools)
        lp->state.budgetProvenWork.Drain(nNow);
}

void P2PoolDrainProvenWorkForTest(bool fPools, bool fSessions)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        int64 nNow = GetTime();
        foreach(LocalPool* lp, vLocalPools)
        {
            if (fPools)
                lp->state.budgetProvenWork.Drain(nNow);
            if (fSessions)
                for (map<CNode*, PeerPool>::iterator it = lp->state.mapPeer.begin(); it != lp->state.mapPeer.end(); ++it)
                    it->second.budgetWork.Drain(nNow);
        }
    }
}

void P2PoolRefillProvenWorkForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(LocalPool* lp, vLocalPools)
        {
            lp->state.budgetProvenWork.Reset();
            for (map<CNode*, PeerPool>::iterator it = lp->state.mapPeer.begin(); it != lp->state.mapPeer.end(); ++it)
                it->second.budgetWork.Reset();
        }
}

bool P2PoolLocalSetPoolTokensForTest(const string& strName, int n)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (lp)
        {
            lp->state.budgetProvenWork.Drain(GetTime(), n);
            f = true;
        }
    }
    return f;
}

bool P2PoolLocalSetWorkDebtForTest(const string& strName, CNode* pnode, int nDebt)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        map<CNode*, PeerPool>::iterator it;
        if (lp && (it = lp->state.mapPeer.find(pnode)) != lp->state.mapPeer.end())
        {
            it->second.nWorkDebt = nDebt;
            f = true;
        }
    }
    return f;
}

int P2PoolLocalWorkDebtForTest(const string& strName, CNode* pnode)
{
    int n = -1;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        map<CNode*, PeerPool>::iterator it;
        if (lp && (it = lp->state.mapPeer.find(pnode)) != lp->state.mapPeer.end())
            n = it->second.nWorkDebt;
    }
    return n;
}

bool P2PoolLocalNoteAskedForTest(const string& strName, const uint256& id)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (lp)
        {
            NoteAskedLocked(lp->state, vector<uint256>(1, id));
            f = true;
        }
    }
    return f;
}

bool P2PoolLocalAskedForTest(const string& strName, const uint256& id)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        f = lp && AskedLately(lp->state, id);
    }
    return f;
}

int P2PoolLocalSessionTokensForTest(const string& strName, CNode* pnode)
{
    int n = -1;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        map<CNode*, PeerPool>::iterator it;
        if (lp && (it = lp->state.mapPeer.find(pnode)) != lp->state.mapPeer.end())
            n = it->second.budgetWork.Tokens(GetTime());
    }
    return n;
}

void P2PoolLocalAgeHelloForTest(CNode* pnode, int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, LocalConn>::iterator it = mapLocalConn.find(pnode);
        if (it != mapLocalConn.end())
        {
            it->second.nLastHelloSent -= nSecs;
            it->second.limiter.nLast -= nSecs;
        }
    }
}

size_t P2PoolLocalPeerEntriesForTest(const string& strName)
{
    size_t n = 0;
    CRITICAL_BLOCK(cs_p2pool)
    {
        LocalPool* lp = LocalByName(strName);
        if (lp)
            n = lp->state.mapPeer.size();
    }
    return n;
}

size_t P2PoolRegisteredDeferredCount()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = classReg.mapDeferred.size();
    return n;
}

size_t P2PoolRegServeHeldBytesForTest()
{
    size_t n = 0;
    CRITICAL_BLOCK(cs_p2pool)
        foreach(const RegServe& r, lRegServes)
            n += r.vIds.capacity() * sizeof(uint256);
    return n;
}

void P2PoolRegServeLoseNextForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(RegServe& r, lRegServes)
            if (r.i < r.vIds.size())
                r.vIds[r.i] = ~uint256(0);
}

// ---- Registered pools (docs/pool-registry.md, sections 8, 9, 11 and 17) ---
//
// A pool recorded on the chain that this node mines (-p2pool=<pool id>) or
// carries (-poolcarry=<pool id>, at most 8). Its messages start with its id
// and go only to peers that say NODE_POOLREG; its shares are pushed only to
// peers whose latest poolinv names it. Whether its record is active on this
// node's chain (the registry index) decides what is carried, mined and
// announced, and nothing else: a share of it is judged on its rules and its
// share chain alone. It spends from the registered class, as a local pool
// does, never from pool zero's.

// Where a registered pool's line stands on this node (section 17).
enum
{
    FETCH_IDLE = 0,     // nothing of its line here, nothing asked
    FETCH_RUNNING,      // a history on its way, kept in pools/<id>.part
    FETCH_CATCHUP,      // the snapshot taken in full; the catch-up asked
    FETCH_COMPLETE,     // the line is here: announced, served, relayed, mined on
};

struct RegPool
{
    uint256 id;
    poolreg::PoolRecord rec;
    vector<unsigned char> record;
    PoolState state;                // pools/<id>.dat, written once complete
    string strPart;                 // pools/<id>.part; empty: memory only
    bool fMined;                    // -p2pool=<id>
    bool fCarry;                    // -poolcarry=<id>
    // Guarded (section 10): the draw gave this node a place in it and the
    // guard budget keeps it, or its line is being pulled to learn its work.
    bool fGuard;
    int nStatus;                    // PoolStatus, from the registry index
    // Whether nStatus is the index's word yet: until the index is loaded,
    // at its tip and not reading the chain again, a pool it does not name
    // keeps what it has here (a restart's partial file among it).
    bool fStatusKnown;
    int nFetch;
    // The fetch: the peer asked (held by mapRegConn while it is there), when
    // the ask in flight went (0: none), when its last part came, when the
    // catch-up was asked, and no new ask before nRetryAt.
    CNode* pFetchPeer;
    int64 nAskAt;
    int64 nLastPartAt;
    int64 nCatchupAt;
    int64 nRetryAt;
    // The newest share held of the history being fetched: the resume point.
    uint256 hashResume;
    // When the fetch last took a share: a partial file this old goes.
    int64 nLastNewShare;
    // The partial file's length up to its last whole part, where the next
    // part is written (a part cut short by a stop or a failed write is
    // written over); and whether it reached the pool's byte cap, after which
    // the fetch goes on in memory only.
    uint64 nPartBytes;
    bool fPartFull;
    uint64 nPartCapForTest;         // self-tests: a smaller cap (0: none)
    // Since when the pool is active and wanted here (0: it is not).
    int64 nWantedSince;
    int64 nWhoAt;                   // when peers were last asked poolwho for it
    // Carriers a peer named in answer to this node's poolwho (poolat), each
    // with when it was named: dialled with the guardians for POOLAT_HINT_TTL
    // (P2PoolGuardDialList), whether or not the line has started here since,
    // since an answer that comes after that is still taken.
    vector<std::pair<string, int64> > vHintAt;

    RegPool(const uint256& idIn, const poolreg::PoolRecord& recIn, const vector<unsigned char>& recordIn,
            ShareChain* chainIn, const string& strFileIn, const string& strPartIn)
        : id(idIn), rec(recIn), record(recordIn), state(&classReg, chainIn, strFileIn), strPart(strPartIn),
          fMined(false), fCarry(false), fGuard(false), nStatus(POOL_UNKNOWN), fStatusKnown(false), nFetch(FETCH_IDLE),
          pFetchPeer(NULL), nAskAt(0), nLastPartAt(0), nCatchupAt(0), nRetryAt(0), hashResume(0), nLastNewShare(0),
          nPartBytes(0), fPartFull(false), nPartCapForTest(0), nWantedSince(0), nWhoAt(0) {}
};

// A guardian ticket waiting for the ticket budget (section 10): checked
// against hashSeed, the seed its message named (Precheck made sure it was
// this node's), and as an answer (no deadline) or a relay.
struct TktItem
{
    CGuardTicket t;
    unsigned int nEpoch;
    uint256 hashSeed;
    bool fOwn;          // this node's own, from pool-tickets.dat
    uint64 nMsg;        // the message it came in: a relay is scored once per message
};

// The tickets one source sent that wait for the ticket budget: its relays,
// and its answers to this node's poolgettkt, one queue per epoch, each
// deduplicated within itself only (another peer's copy of a body waits in
// that peer's queue, and whichever is checked second is dropped by Precheck
// for free).
struct TktQueues
{
    std::deque<TktItem> qRelay;
    map<unsigned int, std::deque<TktItem> > mapAnswer;
    map<unsigned int, set<uint256> > mapAnswerBodies;
    size_t Answers() const
    {
        size_t n = 0;
        for (map<unsigned int, std::deque<TktItem> >::const_iterator it = mapAnswer.begin(); it != mapAnswer.end(); ++it)
            n += it->second.size();
        return n;
    }
};

// What this node keeps for a connection to a peer that reads the registry.
// Each entry holds a reference on its node until the connection is seen
// closed (RegTick), on the message thread only.
struct RegConn
{
    // Tickets (section 10). A serial no other connection had, so the ticket
    // thread can tell this one from a later one at the same address.
    uint64 nTktSerial;
    TktQueues tq;
    uint64 nTktMsg;                         // pooltkt messages read from it
    uint64 nTktScoredMsg;                   // the last of them scored
    int nTktScore;                          // scored by the ticket thread, applied on this thread
    map<unsigned int, int64> mapTktAskedAt;     // poolgettkt sent it, by epoch
    map<unsigned int, size_t> mapTktAnswered;   // tickets taken as that answer
    map<unsigned int, int64> mapTktServedAt;    // poolgettkt it was answered
    // Its relays that passed and were not held, and those held, since
    // nTktTallySince: a connection whose relays keep coming back outranked
    // or past the cap is checked after the answers (unscored).
    int nTktWasted;
    int nTktHeld;
    int64 nTktTallySince;
    // Held tickets to relay to it, by epoch, sent from the message thread.
    map<unsigned int, vector<CGuardTicket> > mapTktOut;
    set<uint256> setInv;            // the peer's latest poolinv this node acted on
    vector<uint256> vInvPending;    // one that came within a minute of the last
    bool fInvPending;
    int64 nInvAppliedAt;
    vector<uint256> vInvSent;       // the last poolinv this node sent it
    int64 nInvSentAt;
    // Asks about pools this node does not announce, answered with p2xnone
    // (8 an interval, the rest dropped unread), and poolwho asks answered.
    int64 nNoneSince;
    int nNone;
    int64 nWhoSince;
    int nWho;
    map<uint256, int64> mapWhoAsked;    // poolwho this node sent it, by pool
    map<uint256, int64> mapNoneAt;      // pools it said it holds nothing of
    // The p2xsync this node sent it: since when and how many, in all and by
    // pool, so no ask goes past what it answers (RegAskRoomLocked).
    int64 nAskedSince;
    int nAsked;
    map<uint256, std::pair<int64, int> > mapAskedPool;
    RegConn() : nTktSerial(0), nTktMsg(0), nTktScoredMsg(0), nTktScore(0), nTktWasted(0), nTktHeld(0),
                nTktTallySince(0), fInvPending(false), nInvAppliedAt(0), nInvSentAt(0), nNoneSince(0), nNone(0),
                nWhoSince(0), nWho(0), nAskedSince(0), nAsked(0) {}
};

static const size_t MAX_POOL_INV = 32;
// poolinv goes out when the set changes, at most once a minute to a peer;
// one received is acted on at most once a minute (the latest one).
static const int64 POOL_INV_INTERVAL = 60;
static const int MAX_NONE_ANSWERS = 8;
static const size_t MAX_REG_SERVED_POOLS = 8;
// A mined pool that no peer announces and nothing of which is here: its
// line starts on this node after this long.
static const int64 REG_START_GRACE = 2 * 60;
static const int64 REG_START_LONGEST = 10 * 60;
static const int64 REG_CATCHUP_WAIT = 5 * 60;
static const int64 REG_PART_EXPIRY = 24 * 60 * 60;
// A peer that said it holds nothing of a pool is not asked for it again for
// this long. Short: a node announces the pool it mines before it has shares
// (section 8), so an announcer with nothing yet is the usual case at a
// pool's start, and it has shares a spacing or two later. Each ask costs it
// a p2xnone, 8 an interval at most.
static const int64 REG_NONE_FORGET = 60;
// An ask whose first part has not come this long after it: the fetch asks
// another announcer, and this one is left alone as if it had said p2xnone.
// Its answer is still taken if it comes within the receiving window
// (REG_SYNC_ANSWER_WINDOW); a server whose slots are all taken holds an ask
// that long, which a fetch with another announcer need not wait out.
static const int64 REG_FIRST_PART_WAIT = 3 * 60;
// What a server answers one connection (section 8): 3 p2xsync a pool an
// interval, and 8 p2xnone an interval for pools it does not announce or
// holds nothing of. This node asks no more often, counted over an interval
// a little longer than the server's, so the server's own count, which
// starts when the first ask arrives, has always started over too.
static const int REG_ASKS_PER_POOL = 3;
static const int REG_ASKS_PER_CONN = 8;
static const int64 REG_ASK_INTERVAL = SYNC_SERVE_INTERVAL + 30;
static const int64 REG_RETRY_SECS = 30;
static const int64 REG_STATUS_SECS = 10;
static const int64 POOLWHO_INTERVAL = 10 * 60;
static const size_t POOLWHO_PEERS = 4;
static const int64 POOLAT_WINDOW = 5 * 60;
// A carrier named in a poolat answer is dialled for this long, then
// forgotten (poolwho goes out again every POOLWHO_INTERVAL while the line is
// not here); a pool keeps the newest POOLAT_HINTS_KEPT names.
static const int64 POOLAT_HINT_TTL = 10 * 60;
static const size_t POOLAT_HINTS_KEPT = 8;

static bool HintNewer(const std::pair<string, int64>& a, const std::pair<string, int64>& b)
{
    return a.second > b.second;
}
// A paced serve older than this that averages under REG_SLOW_SERVE_RATE ends
// when an ask waits for a slot.
static const int64 REG_SLOW_SERVE_AGE = 15 * 60;
static const int64 REG_SLOW_SERVE_RATE = 1000;

// Under cs_p2pool. A RegPool is never freed in a node (its PoolState is
// pointed at by orphans, held entries and, for the mined one, pPoolMined);
// a pool whose record leaves the chain is only no longer carried.
static vector<RegPool*> vRegPools;
static map<CNode*, RegConn> mapRegConn;
// The pool mined (-p2pool=<id>; 0 for none) and those carried (-poolcarry).
static uint256 idMinedReg = 0;
static vector<uint256> vCarryReg;
// Self-tests: shares checked without RandomX, pools kept in memory only, and
// statuses set by the test instead of the index.
static bool fRegCheckPoW = true;
static bool fRegFiles = true;
static bool fRegStatusForTest = false;

static uint256 RegZeroId()
{
    uint256 id = 0;
    poolreg::PoolId(poolreg::PoolZero().Encode(), (const unsigned char*)pchMessageStart, id.begin());
    return id;
}

static RegPool* RegOf(PoolState& ps)
{
    foreach(RegPool* rp, vRegPools)
        if (&rp->state == &ps)
            return rp;
    return NULL;
}

// The same pools by id: guarded pools come and go by the draw, and the guard
// pass looks every drawn pool up once a second.
static map<uint256, RegPool*> mapRegById;

static RegPool* RegById(const uint256& id)
{
    map<uint256, RegPool*>::const_iterator it = mapRegById.find(id);
    return it == mapRegById.end() ? NULL : it->second;
}

// Under cs_p2pool, on the message thread between messages (no message holds
// it then): a pool that is neither mined nor carried leaves memory. What
// points at its state goes first: orphans and held entries (ForgetPool), its
// paced serves.
static void RegFree(RegPool* rp)
{
    classReg.ForgetPool(&rp->state);
    for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end();)
        if (it->pool == &rp->state)
            it = lRegServes.erase(it);
        else
            ++it;
    if (pPoolMined == &rp->state)
        pPoolMined = NULL;
    vector<RegPool*>::iterator it = std::find(vRegPools.begin(), vRegPools.end(), rp);
    if (it != vRegPools.end())
        vRegPools.erase(it);
    mapRegById.erase(rp->id);
    delete rp->state.chain;
    delete rp;
}

static const vector<unsigned char>* RegRecordOf(PoolState& ps)
{
    RegPool* rp = RegOf(ps);
    return rp ? &rp->record : NULL;
}

static bool RegWanted(const RegPool& rp)
{
    return rp.fMined || rp.fCarry || rp.fGuard;
}

// Registered pools on the network and in mining at all: testnet, and mainnet
// once a release opens them there (POOL_REGISTRY_MAINNET_OPEN, section 9).
// Until then anybody could burn a record on mainnet and the index would mark
// it active, so this is the one gate every use below passes: a pool is never
// live on a closed network, whatever its status, so nothing of it is fetched,
// mined, carried, announced, relayed or served. Pool zero and local pools
// are not registered pools, and never pass here.
static bool RegOpen()
{
    return PoolBurnsOpen();
}

// Its record active on this node's chain, on a network where registered
// pools are open.
static bool RegLive(const RegPool& rp)
{
    return RegOpen() && rp.nStatus == POOL_ACTIVE;
}

// Wanted and live: a fetch runs, answers to it are taken.
static bool RegActive(const RegPool& rp)
{
    return RegWanted(rp) && RegLive(rp);
}

// Carried: its shares taken, relayed and served, its line mined on.
static bool RegCarried(const RegPool& rp)
{
    return RegActive(rp) && rp.nFetch == FETCH_COMPLETE;
}

// Announced in poolinv: carried, and holding shares or mined (section 8).
static bool RegAnnounced(const RegPool& rp)
{
    return RegCarried(rp) && (rp.fMined || !rp.state.chain->Empty());
}

static bool RegSaveAllowed(PoolState& ps)
{
    RegPool* rp = RegOf(ps);
    return !rp || rp->nFetch == FETCH_COMPLETE;
}

static bool RegInSessionLocked(PoolState& ps, CNode* pnode)
{
    RegPool* rp = RegOf(ps);
    return rp && RegCarried(*rp) && rp->state.mapPeer.count(pnode) && mapRegConn.count(pnode);
}

static void RegServedTimesLocked(map<CNode*, int64>& out)
{
    foreach(RegPool* rp, vRegPools)
        for (map<CNode*, PeerPool>::iterator it = rp->state.mapPeer.begin(); it != rp->state.mapPeer.end(); ++it)
            out[it->first] = std::max(out[it->first], it->second.nSyncServed);
}

static bool RegIdFor(PoolState& ps, CNode* pnode, uint256& idOut, bool fCarried)
{
    if (ps.fZero || !(pnode->nServices & NODE_POOLREG))
        return false;
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegOf(ps);
        if (rp && (!fCarried || RegCarried(*rp)))
        {
            idOut = rp->id;
            f = true;
        }
    }
    return f;
}

static uint256 RegResumeLocked(PoolState& ps)
{
    RegPool* rp = RegOf(ps);
    if (rp && rp->nFetch == FETCH_RUNNING && rp->hashResume != 0 && ps.chain->Has(rp->hashResume))
        return rp->hashResume;
    return ps.chain->Tip();
}

// Under cs_p2pool, on the message thread.
static RegConn& RegConnOf(CNode* pnode)
{
    map<CNode*, RegConn>::iterator it = mapRegConn.find(pnode);
    if (it != mapRegConn.end())
        return it->second;
    pnode->AddRef();
    static uint64 nSerial = 0;
    RegConn c;
    c.nTktSerial = ++nSerial;
    c.nTktTallySince = GetTime();
    return mapRegConn.insert(make_pair(pnode, c)).first->second;
}

// Under cs_p2pool. The asks a connection was sent within the interval: in
// all (nAllOut) and for one pool (nPoolOut); counts of an interval that has
// run out are not counted.
static void RegAskedLocked(const RegConn& c, const uint256& id, int64 nNow, int& nAllOut, int& nPoolOut)
{
    nAllOut = nNow - c.nAskedSince < REG_ASK_INTERVAL ? c.nAsked : 0;
    nPoolOut = 0;
    map<uint256, std::pair<int64, int> >::const_iterator it = c.mapAskedPool.find(id);
    if (it != c.mapAskedPool.end() && nNow - it->second.first < REG_ASK_INTERVAL)
        nPoolOut = it->second.second;
}

static bool RegAskRoomLocked(PoolState& ps, CNode* pnode)
{
    RegPool* rp = RegOf(ps);
    if (!rp)
        return true;
    map<CNode*, RegConn>::const_iterator it = mapRegConn.find(pnode);
    if (it == mapRegConn.end())
        return true;
    int nAll, nPool;
    RegAskedLocked(it->second, rp->id, GetTime(), nAll, nPool);
    return nAll < REG_ASKS_PER_CONN && nPool < REG_ASKS_PER_POOL;
}

static void RegNoteAskLocked(CNode* pnode, const uint256& id)
{
    int64 nNow = GetTime();
    RegConn& c = RegConnOf(pnode);
    if (nNow - c.nAskedSince >= REG_ASK_INTERVAL)
    {
        c.nAskedSince = nNow;
        c.nAsked = 0;
    }
    c.nAsked++;
    std::pair<int64, int>& p = c.mapAskedPool[id];
    if (nNow - p.first >= REG_ASK_INTERVAL)
    {
        p.first = nNow;
        p.second = 0;
    }
    p.second++;
}

// Under cs_p2pool, on the message thread: what a connection has done in a
// registered pool, made as a local pool's session makes it (at the back of
// the pool's turns, OpenSession).
static PeerPool& RegPeerOf(RegPool& rp, CNode* pnode)
{
    RegConnOf(pnode);
    map<CNode*, PeerPool>::iterator it = rp.state.mapPeer.find(pnode);
    if (it != rp.state.mapPeer.end())
        return it->second;
    PeerPool peer(rp.rec.nSpacing);
    peer.nLastWorkAt = GetTime();
    for (map<CNode*, PeerPool>::const_iterator itP = rp.state.mapPeer.begin(); itP != rp.state.mapPeer.end(); ++itP)
        peer.nWorkDebt = std::max(peer.nWorkDebt, itP->second.nWorkDebt);
    return rp.state.mapPeer.insert(make_pair(pnode, peer)).first->second;
}

// Under cs_p2pool: a connection is gone.
static void RegForgetNode(CNode* pnode)
{
    for (std::list<RegServe>::iterator itS = lRegServes.begin(); itS != lRegServes.end();)
        if (itS->pnode == pnode)
            itS = lRegServes.erase(itS);
        else
            ++itS;
    foreach(RegPool* rp, vRegPools)
    {
        rp->state.mapPeer.erase(pnode);
        if (rp->pFetchPeer == pnode)
        {
            rp->pFetchPeer = NULL;
            rp->nAskAt = 0;
        }
    }
    map<CNode*, RegConn>::iterator it = mapRegConn.find(pnode);
    if (it != mapRegConn.end())
    {
        pnode->Release();
        mapRegConn.erase(it);
    }
}

static string RegDir()
{
    return GetAppDir() + "/pools";
}

// Under cs_p2pool. A registered pool joins this node from its record; NULL,
// with the reason, if the record is not that pool's.
static RegPool* RegNew(const uint256& id, const vector<unsigned char>& record, string& errOut)
{
    poolreg::PoolRecord rec;
    PoolRules rules;
    if (!poolreg::Parse(record, rec, errOut) ||
        !RulesForRegistered(rec, (const unsigned char*)pchMessageStart, rules, errOut))
        return NULL;
    if (rules.poolId != id)
    {
        errOut = "the record of another pool";
        return NULL;
    }
    string strBase = fRegFiles ? RegDir() + "/" + id.GetHex() : string();
    RegPool* rp = new RegPool(id, rec, record, new ShareChain(rules, fRegCheckPoW),
                              strBase.empty() ? string() : strBase + ".dat",
                              strBase.empty() ? string() : strBase + ".part");
    rp->fMined = id == idMinedReg;
    rp->fCarry = std::find(vCarryReg.begin(), vCarryReg.end(), id) != vCarryReg.end();
    vRegPools.push_back(rp);
    mapRegById[id] = rp;
    if (rp->fMined)
        pPoolMined = &rp->state;
    return rp;
}

typedef vector<std::pair<int, vector<ShareX> > > RegChunks;

// A partial file holds at most the pool's byte cap (section 11): what a fetch
// writes stops there, and what is read back stops there too.
static const uint64 REG_PART_MAX_BYTES = MAX_CHAIN_BYTES;

// A file cut back to n bytes, never through a link left in its place.
static bool RegTruncate(const string& strPath, uint64 n)
{
#ifdef WIN32
    int fd = _open(strPath.c_str(), _O_RDWR | _O_BINARY);
    if (fd < 0)
        return false;
    bool f = _chsize_s(fd, (__int64)n) == 0;
    _close(fd);
#else
    int fd = open(strPath.c_str(), O_WRONLY | O_NOFOLLOW);
    if (fd < 0)
        return false;
    bool f = ftruncate(fd, (off_t)n) == 0;
    close(fd);
#endif
    return f;
}

// A registered pool's file read back: pools/<id>.dat (one part: the line as
// History() gave it) or pools/<id>.part (the parts of a fetch, each with the
// tip height it came with). False for a file of another format.
// A partial file is read up to its last whole part, and no further than
// REG_PART_MAX_BYTES; whatever follows (a part cut short by a stop) is cut
// off the file, so the next part is written where the last whole one ends
// and is read back after it (*pnGoodOut, the length kept). One whose start
// is not readable goes.
static bool RegReadFile(const string& strPath, vector<unsigned char>& recordOut, RegChunks& vOut, bool fPart,
                        uint64* pnGoodOut = NULL)
{
    uint64 nGood = 0, nSize = 0;
    bool fHead = false;
    try
    {
        CAutoFile file(fopen(strPath.c_str(), "rb"));
        if (!file)
            return false;
        fseek(file, 0, SEEK_END);
        nSize = (uint64)std::max(0L, ftell(file));
        fseek(file, 0, SEEK_SET);
        unsigned char nFormat = 0;
        file >> nFormat;
        if (nFormat != REG_SHARES_FORMAT)
        {
            printf("p2pool: %s is in format %u, this build reads format %u only; not read\n",
                   strPath.c_str(), (unsigned)nFormat, (unsigned)REG_SHARES_FORMAT);
            if (!fPart)
                return false;
        }
        else
        {
            file >> recordOut;
            fHead = recordOut.size() <= poolreg::MAX_RECORD_BYTES;
            nGood = (uint64)std::max(0L, ftell(file));
        }
        while (fHead)
        {
            int nTip = 0;
            vector<ShareX> v;
            try
            {
                file >> nTip >> v;
            }
            catch (std::exception&)
            {
                break;
            }
            uint64 nAt = (uint64)std::max(0L, ftell(file));
            if (fPart && nAt > REG_PART_MAX_BYTES)
                break;
            vOut.push_back(std::make_pair(nTip, v));
            nGood = nAt;
            if (!fPart)
                break;
        }
    }
    catch (std::exception& e)
    {
        printf("p2pool: %s unreadable (%s)\n", strPath.c_str(), e.what());
    }
    if (!fHead)
    {
        // A partial file nothing can be appended to (its start cut short, or
        // of another format) would keep every later part unread: it goes.
        if (fPart)
            remove(strPath.c_str());
        return false;
    }
    // A line file whose line is not readable is no line.
    if (!fPart && vOut.empty())
        return false;
    if (fPart && nSize > nGood)
    {
        printf("p2pool: %s: %u bytes after its last whole part cut off\n", strPath.c_str(), (unsigned)(nSize - nGood));
        if (!RegTruncate(strPath, nGood))
        {
            // Not cut back: nothing more may be appended after it.
            remove(strPath.c_str());
            return false;
        }
    }
    if (pnGoodOut)
        *pnGoodOut = nGood;
    return true;
}

// Under cs_p2pool. The parts read back through AddHistory, each with its tip
// height clamped as a received part's is. For a fetch, the newest share of
// the last part taken in full becomes the resume point.
static void RegLoadChunks(RegPool* rp, const RegChunks& v, bool fPart)
{
    NodeMainView main;
    const int64 nHistoryShares = rp->state.chain->Rules().HistoryShares();
    for (size_t i = 0; i < v.size(); i++)
    {
        vector<Share> part(v[i].second.begin(), v[i].second.end());
        int64 nTop = 0;
        foreach(const Share& s, part)
            nTop = std::max(nTop, (int64)s.data.nShareHeight);
        int nTip = (int)std::min((int64)v[i].first, std::min(nTop + nHistoryShares, (int64)p2pool::MAX_SHARE_HEIGHT));
        string err;
        bool fWhole = false;
        if (!rp->state.chain->AddHistory(part, nTip, main, err, &fWhole))
        {
            printf("p2pool: registered pool %s: a saved part refused (%s)\n", rp->id.GetHex().c_str(), err.c_str());
            break;
        }
        if (fPart && fWhole && !part.empty())
            rp->hashResume = part.back().GetId();
    }
}

// Under cs_main and cs_p2pool (P2PoolInit): the wanted pools whose files are
// here come back from them, before the index has said anything: a complete
// line from pools/<id>.dat, a fetch in progress from pools/<id>.part.
static void RegPoolsInit()
{
    if (!RegOpen())
        return;
    vector<uint256> vWant;
    if (idMinedReg != 0)
        vWant.push_back(idMinedReg);
    vWant.insert(vWant.end(), vCarryReg.begin(), vCarryReg.end());
    foreach(const uint256& id, vWant)
    {
        if (RegById(id) || !fRegFiles)
            continue;
        string strBase = RegDir() + "/" + id.GetHex();
        vector<unsigned char> record;
        RegChunks v;
        bool fDat = RegReadFile(strBase + ".dat", record, v, false);
        bool fPart = false;
        uint64 nPartBytes = 0;
        if (!fDat)
        {
            record.clear();
            v.clear();
            fPart = RegReadFile(strBase + ".part", record, v, true, &nPartBytes);
        }
        if (!fDat && !fPart)
            continue;
        string err;
        RegPool* rp = RegNew(id, record, err);
        if (!rp)
        {
            printf("p2pool: pools/%s: %s; not read\n", id.GetHex().c_str(), err.c_str());
            continue;
        }
        RegLoadChunks(rp, v, fPart);
        if (fDat)
        {
            remove(rp->strPart.c_str());
            rp->nFetch = rp->state.chain->Empty() ? FETCH_IDLE : FETCH_COMPLETE;
        }
        else
        {
            rp->nFetch = FETCH_RUNNING;
            rp->nLastNewShare = GetTime();
            rp->nPartBytes = nPartBytes;
        }
        printf("p2pool: registered pool %s: %u shares read from its %s, tip at height %d\n", id.GetHex().c_str(),
               (unsigned)rp->state.chain->Size(), fDat ? "file" : "partial file (a fetch in progress)",
               rp->state.chain->Height(rp->state.chain->Tip()));
    }
}

// The outcome of writing a part to a partial file.
enum
{
    REG_PART_WRITTEN = 0,
    REG_PART_FULL,      // it would pass REG_PART_MAX_BYTES (or the pool's cap): not written
    REG_PART_FAILED,    // not written; the file is as long as it was
};

// Not under cs_p2pool, on the message thread: the shares a part of a fetch
// brought, written to pools/<id>.part at nAt (the end of its last whole
// part; 0 for a new file, which gets the format and the record first) and
// flushed before the next part is asked for. Only shares the chain took, as
// it keeps them, so the file grows only with the line, and never past nCap.
// *pnSizeOut: the file's length after it.
static int RegAppendPart(const string& strPart, const vector<unsigned char>& record, int nTipHeight,
                         const vector<Share>& vNew, uint64 nAt, uint64 nCap, uint64* pnSizeOut)
{
    *pnSizeOut = nAt;
    if (strPart.empty() || vNew.empty())
        return REG_PART_WRITTEN;
    CDataStream ss(SER_DISK, VERSION);
    if (nAt == 0)
        ss << REG_SHARES_FORMAT << record;
    vector<ShareX> vx(vNew.begin(), vNew.end());
    ss << nTipHeight << vx;
    if (nAt + ss.size() > std::min(nCap, REG_PART_MAX_BYTES))
        return REG_PART_FULL;
    _mkdir(RegDir().c_str());
#ifdef WIN32
    // The data directory's ACL already keeps other accounts out.
    FILE* f = fopen(strPart.c_str(), nAt == 0 ? "wb" : "r+b");
#else
    // Owner-only, and never through a link someone left in its place.
    int fd = open(strPart.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    FILE* f = fd < 0 ? NULL : fdopen(fd, "r+b");
    if (fd >= 0 && !f)
        close(fd);
#endif
    if (!f)
        return REG_PART_FAILED;
    // Written where the last whole part ends: a part a failed write left
    // half there is written over, and the file never ends in one.
    bool fOk = fseek(f, (long)nAt, SEEK_SET) == 0 && fwrite(&ss[0], 1, ss.size(), f) == ss.size() && fflush(f) == 0;
    fclose(f);
    if (!fOk)
    {
        RegTruncate(strPart, nAt);
        return REG_PART_FAILED;
    }
    // Whatever an older write left past it goes (and if it cannot, the next
    // start cuts it off: RegReadFile).
    RegTruncate(strPart, nAt + ss.size());
    *pnSizeOut = nAt + ss.size();
    return REG_PART_WRITTEN;
}

// Under cs_p2pool: a fetch in progress is given up (the pool is no longer
// active here, or its partial file has had no new share for a day). What it
// took goes with its file.
static void RegDropFetch(RegPool* rp)
{
    classReg.ForgetPool(&rp->state);
    PoolRules rules = rp->state.chain->Rules();
    delete rp->state.chain;
    rp->state.chain = new ShareChain(rules, fRegCheckPoW);
    rp->state.nFirstHistoryAsk = 0;
    if (!rp->strPart.empty())
        remove(rp->strPart.c_str());
    rp->nFetch = FETCH_IDLE;
    rp->pFetchPeer = NULL;
    rp->nAskAt = rp->nLastPartAt = rp->nCatchupAt = rp->nRetryAt = 0;
    rp->hashResume = 0;
    rp->nLastNewShare = 0;
    rp->nPartBytes = 0;
    rp->fPartFull = false;
}

// Not under cs_p2pool: the line is complete. It goes to pools/<id>.dat, the
// partial file goes, and from now on the pool is announced, served, relayed
// and mined on.
static void RegComplete(RegPool* rp)
{
    string strPart;
    size_t nShares;
    int nTip;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (rp->nFetch == FETCH_COMPLETE)
            return;
        rp->nFetch = FETCH_COMPLETE;
        rp->nAskAt = 0;
        strPart = rp->strPart;
        nShares = rp->state.chain->Size();
        nTip = rp->state.chain->Height(rp->state.chain->Tip());
        NoteChainGrew(rp->state);
    }
    // The partial file goes only once the line is in its .dat: a .dat that
    // could not be written leaves the fetch to resume from it at the next
    // start (and the next save tries the .dat again).
    bool fSaved = MaybeSaveShares(rp->state, true);
    if (fSaved && !strPart.empty())
        remove(strPart.c_str());
    CRITICAL_BLOCK(cs_p2pool)
        if (fSaved)
        {
            rp->nPartBytes = 0;
            rp->fPartFull = false;
        }
    printf("p2pool: registered pool %s: its line is complete here (%u shares, tip at height %d)%s\n",
           rp->id.GetHex().c_str(), (unsigned)nShares, nTip,
           fSaved ? "" : "; its file could not be written, its partial file is kept");
}

static bool RegPartInWindow(PoolState& ps, CNode* pfrom)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<CNode*, PeerPool>::iterator it = ps.mapPeer.find(pfrom);
        if (it != ps.mapPeer.end())
        {
            int64 nNow = GetTime();
            PeerPool& pp = it->second;
            f = pp.nLastPartAt == 0 || nNow - pp.nLastPartAt <= REG_PART_WAIT;
            if (f)
                pp.nLastPartAt = nNow;
        }
    }
    return f;
}

// After a part of a registered pool's history was read (OnShares). The
// shares it brought that the chain did not have (vNew, the chain's own
// copies) go to the partial file whoever sent them; only the peer the fetch
// asked moves the fetch on. Any other answer was asked for by a complete
// pool (its line brought up to date), or by the fetch of an announcer it
// has since moved on from, and is simply taken.
static void RegOnPart(PoolState& ps, CNode* pfrom, int nTipHeight, const vector<Share>& part,
                      const vector<Share>& vNew, int nFlag, bool fOk, bool fWhole)
{
    RegPool* rp = NULL;
    string strPart;
    vector<unsigned char> record;
    uint64 nAt = 0, nCap = 0;
    bool fAppend = false, fCatchup = false, fComplete = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        rp = RegOf(ps);
        if (!rp || (rp->nFetch != FETCH_RUNNING && rp->nFetch != FETCH_CATCHUP))
            return;
        int64 nNow = GetTime();
        // Only new shares keep a partial file alive (REG_PART_EXPIRY), and
        // only they are written: shares sent again, whatever their bytes,
        // cost the file nothing.
        if (!vNew.empty())
        {
            rp->nLastNewShare = nNow;
            if (!rp->fPartFull && !rp->strPart.empty())
            {
                fAppend = true;
                strPart = rp->strPart;
                record = rp->record;
                nAt = rp->nPartBytes;
                nCap = rp->nPartCapForTest ? rp->nPartCapForTest : (uint64)rp->state.chain->MaxBytes();
            }
        }
        if (rp->pFetchPeer == pfrom)
        {
            rp->nLastPartAt = nNow;
            if (!fOk)
            {
                // Scored already; another announcer is asked.
                RegConnOf(pfrom).mapNoneAt[rp->id] = nNow;
                rp->nAskAt = 0;
                rp->nRetryAt = nNow;
            }
            else
            {
                // Its answer is coming: no new ask while it does, even if its
                // first part was so late that the fetch had stopped waiting.
                if (nFlag == PART_MORE && !rp->nAskAt)
                    rp->nAskAt = nNow;
                if (fWhole && !part.empty() && rp->nFetch == FETCH_RUNNING)
                    rp->hashResume = part.back().GetId();
                if (nFlag == PART_END && fWhole)
                {
                    if (rp->nFetch == FETCH_RUNNING)
                        fCatchup = true;
                    else
                        fComplete = true;
                }
                else if (nFlag != PART_MORE || !fWhole)
                {
                    // Ended early by the server, or a share of it waits on
                    // others here: asked again shortly, from where the fetch
                    // is (within what the peer answers, RegCanAsk).
                    rp->nAskAt = 0;
                    rp->nRetryAt = nNow + REG_RETRY_SECS;
                }
            }
        }
    }
    if (fAppend)
    {
        uint64 nSize = nAt;
        int nWrote = RegAppendPart(strPart, record, nTipHeight, vNew, nAt, nCap, &nSize);
        CRITICAL_BLOCK(cs_p2pool)
        {
            // Unless the fetch was given up or completed meanwhile.
            if (rp->nFetch == FETCH_RUNNING || rp->nFetch == FETCH_CATCHUP)
            {
                rp->nPartBytes = nSize;
                if (nWrote == REG_PART_FULL)
                {
                    rp->fPartFull = true;
                    printf("p2pool: registered pool %s: its partial file is at the pool's byte cap; the fetch goes on "
                           "in memory only\n", rp->id.GetHex().c_str());
                }
            }
        }
    }
    if (fCatchup)
    {
        // The snapshot is here; what was found while it was sent comes with
        // one more ask of the same peer, from this node's tip, if the peer
        // answers one more now; if not, the catch-up counts as unanswered
        // and the line is complete after its 5 minutes.
        bool fAsk;
        CRITICAL_BLOCK(cs_p2pool)
        {
            fAsk = RegAskRoomLocked(ps, pfrom);
            rp->nFetch = FETCH_CATCHUP;
            rp->nCatchupAt = GetTime();
            rp->nAskAt = fAsk ? rp->nCatchupAt : 0;
            rp->nLastPartAt = 0;
        }
        LogPrint("p2pool", "p2pool: registered pool %s: history taken; %s\n", rp->id.GetHex().c_str(),
                 fAsk ? "asking for what came meanwhile" : "that peer is asked nothing more this interval");
        if (fAsk)
            AskHistory(ps, pfrom);
    }
    if (fComplete)
        RegComplete(rp);
}

// Under cs_p2pool: the pools this node announces, in id order.
static vector<uint256> RegAnnouncedIdsLocked()
{
    vector<uint256> v;
    foreach(RegPool* rp, vRegPools)
        if (RegAnnounced(*rp) && v.size() < MAX_POOL_INV)
            v.push_back(rp->id);
    std::sort(v.begin(), v.end());
    return v;
}

// Under cs_p2pool. Whether a connection may be asked for a pool's line:
// it reads the registry, it announced the pool, it has not said lately that
// it holds nothing of it (nor left an ask unanswered lately), and one more
// ask stays within what it answers (REG_ASKS_PER_POOL, REG_ASKS_PER_CONN).
static bool RegCanAsk(const RegPool& rp, CNode* pnode, const RegConn& c, int64 nNow)
{
    if (pnode->fDisconnect || pnode->nVersion == 0 || !(pnode->nServices & NODE_POOLREG) || !c.setInv.count(rp.id))
        return false;
    int nAll, nPool;
    RegAskedLocked(c, rp.id, nNow, nAll, nPool);
    if (nAll >= REG_ASKS_PER_CONN || nPool >= REG_ASKS_PER_POOL)
        return false;
    map<uint256, int64>::const_iterator it = c.mapNoneAt.find(rp.id);
    return it == c.mapNoneAt.end() || nNow - it->second >= REG_NONE_FORGET;
}

// Under cs_p2pool: the latest poolinv of a peer is acted on. A pool it names
// newly that this node carries complete is asked for, from this node's tip,
// while this node holds nothing of it and from its first few announcers in
// any case (as pool zero asks its first peers); a fetch in progress picks
// its peer in RegFetchStep.
static void RegApplyInvLocked(CNode* pnode, RegConn& c, int64 nNow)
{
    set<uint256> setOld;
    setOld.swap(c.setInv);
    c.setInv.insert(c.vInvPending.begin(), c.vInvPending.end());
    c.vInvPending.clear();
    c.fInvPending = false;
    c.nInvAppliedAt = nNow;
    foreach(const uint256& id, c.setInv)
    {
        if (setOld.count(id))
            continue;
        // A pool this node is drawn for and holds no line of, announced now:
        // pulled from that announcer (section 10, a pool that starts
        // mid-epoch).
        GuardNoteAnnouncedLocked(id);
        RegPool* rp = RegById(id);
        if (!rp || !RegCarried(*rp) || !RegCanAsk(*rp, pnode, c, nNow))
            continue;
        if ((rp->state.chain->Empty() || rp->state.nAskedOnOpen < 4) && HistoryAskAllowed(rp->state, pnode))
        {
            rp->state.nAskedOnOpen++;
            RegPeerOf(*rp, pnode);
            AskHistory(rp->state, pnode);
        }
    }
}

// Under cs_p2pool, on the message thread: one step of a fetch. True when
// the line has just become complete (RegComplete is the caller's, outside
// the lock).
static bool RegFetchStep(RegPool* rp, int64 nNow)
{
    // The catch-up unanswered for 5 minutes: the line is as complete as it
    // gets (section 17).
    if (rp->nFetch == FETCH_CATCHUP && rp->nLastPartAt == 0 && nNow - rp->nCatchupAt >= REG_CATCHUP_WAIT)
        return true;
    // A mined pool nothing of which has come yet starts its line on this
    // node after a grace, unless a peer announces it (it mines it and has no
    // share yet: its line is a spacing or two away), and in any case
    // REG_START_LONGEST after it became active here, whatever was asked
    // meanwhile: an announcer that never answers holds nothing up. An answer
    // that comes later is still taken, and the line with more work wins.
    bool fAnnounced = false;
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end() && !fAnnounced; ++it)
        fAnnounced = !it->first->fDisconnect && it->second.setInv.count(rp->id) != 0;
    // A carrier a peer named in answer to poolwho, being dialled, counts as
    // an announcer for the grace (one hop away); REG_START_LONGEST holds.
    for (size_t i = 0; i < rp->vHintAt.size() && !fAnnounced; i++)
        fAnnounced = nNow - rp->vHintAt[i].second <= POOLAT_HINT_TTL;
    if (rp->fMined && rp->nFetch != FETCH_CATCHUP && rp->state.chain->Size() == 0 && rp->hashResume == 0 &&
        ((!fAnnounced && nNow - rp->nWantedSince >= REG_START_GRACE) || nNow - rp->nWantedSince >= REG_START_LONGEST))
    {
        printf("p2pool: registered pool %s: no peer has given its line; it starts here\n", rp->id.GetHex().c_str());
        return true;
    }
    if (rp->nAskAt)
    {
        bool fOpen = false;
        CNode* pPeer = rp->pFetchPeer;
        if (pPeer && !pPeer->fDisconnect)
        {
            map<CNode*, PeerPool>::iterator it = rp->state.mapPeer.find(pPeer);
            if (it != rp->state.mapPeer.end() && it->second.nSyncAskedAt != 0 &&
                nNow - it->second.nSyncAskedAt <= REG_SYNC_ANSWER_WINDOW)
            {
                if (rp->nLastPartAt == 0 && nNow - rp->nAskAt > REG_FIRST_PART_WAIT)
                {
                    // Nothing yet: left alone a while, as if it had said
                    // p2xnone, and another announcer is asked. What it sends
                    // within its window is still taken.
                    map<CNode*, RegConn>::iterator itC = mapRegConn.find(pPeer);
                    if (itC != mapRegConn.end())
                        itC->second.mapNoneAt[rp->id] = nNow;
                    LogPrint("p2pool", "p2pool: registered pool %s: no answer in %d s; asking another announcer\n",
                             rp->id.GetHex().c_str(), (int)REG_FIRST_PART_WAIT);
                }
                else
                    fOpen = rp->nLastPartAt == 0 || nNow - rp->nLastPartAt <= REG_PART_WAIT;
            }
        }
        if (fOpen)
            return false;
        rp->nAskAt = 0;
    }
    // A catch-up whose peer went before answering waits out its 5 minutes.
    if (rp->nFetch == FETCH_CATCHUP && rp->nLastPartAt == 0)
        return false;
    if (nNow < rp->nRetryAt)
        return false;
    // The peer asked before, if it still announces the pool; else one this
    // node dialled; else any announcer.
    CNode* pAsk = NULL;
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
    {
        if (!RegCanAsk(*rp, it->first, it->second, nNow))
            continue;
        if (it->first == rp->pFetchPeer)
        {
            pAsk = it->first;
            break;
        }
        if (!pAsk || (pAsk->fInbound && !it->first->fInbound))
            pAsk = it->first;
    }
    if (pAsk)
    {
        // The same peer again for this fetch spends from the ask budget
        // whoever it is (HistoryAskAllowed).
        if (!HistoryAskAllowed(rp->state, pAsk, pAsk == rp->pFetchPeer))
            return false;
        RegPeerOf(*rp, pAsk);
        rp->pFetchPeer = pAsk;
        rp->nAskAt = nNow;
        rp->nLastPartAt = 0;
        if (rp->nFetch == FETCH_IDLE)
            rp->nFetch = FETCH_RUNNING;
        if (rp->nFetch == FETCH_CATCHUP)
            rp->nCatchupAt = nNow;
        if (rp->nFetch == FETCH_RUNNING && rp->nLastNewShare == 0)
            rp->nLastNewShare = nNow;
        LogPrint("p2pool", "p2pool: registered pool %s: asking a peer for its line%s\n", rp->id.GetHex().c_str(),
                 rp->nFetch == FETCH_CATCHUP ? " (the catch-up)" : rp->hashResume != 0 ? " (resuming)" : "");
        AskHistory(rp->state, pAsk);
        return false;
    }
    // Nobody to ask: peers are asked who carries it. With no peer that reads
    // the registry connected yet, the first one is asked as soon as it is,
    // not an interval later.
    if (nNow - rp->nWhoAt >= POOLWHO_INTERVAL)
    {
        size_t nAsked = 0;
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end() && nAsked < POOLWHO_PEERS; ++it)
        {
            CNode* p = it->first;
            if (p->fDisconnect || p->nVersion == 0 || !(p->nServices & NODE_POOLREG))
                continue;
            it->second.mapWhoAsked[rp->id] = nNow;
            PushReg(p, "poolwho", rp->id);
            nAsked++;
        }
        if (nAsked)
        {
            rp->nWhoAt = nNow;
            LogPrint("p2pool", "p2pool: registered pool %s: nobody to ask for its line; asked %u peer(s) who carries it\n",
                     rp->id.GetHex().c_str(), (unsigned)nAsked);
        }
    }
    return false;
}

// Not under cs_p2pool: what the index says of each wanted pool. A pool it
// names that this node has no file of joins from the record it reports.
// Self-tests: the registry index as RegRefreshStatus sees it, instead of the
// node's (fRegIndexForTest): whether it is ready, and the pools it names.
static bool fRegIndexForTest = false;
static bool fRegIndexReadyForTest = false;
static map<uint256, CPoolInfo> mapRegIndexForTest;

// Not under cs_p2pool or cs_main. Whether the index's word on a pool is
// final: it has been loaded or read from the chain, it is at the active
// chain's tip, and it is not reading the chain again from genesis. Before
// that (at every start, the index loads after the node does) a pool it does
// not name may simply not be read yet. cs_main only if free: busy, the
// answer is "not yet", and the next look comes 10 s later.
static bool RegIndexReady()
{
    if (fRegIndexForTest)
        return fRegIndexReadyForTest;
    int nHeight = -1;
    uint256 hash = 0;
    bool fRebuilding = false;
    PoolIndex().State(nHeight, hash, fRebuilding);
    if (nHeight < 0 || fRebuilding)
        return false;
    bool fSynced = false;
    TRY_CRITICAL_BLOCK(cs_main)
        fSynced = pindexBest && pindexBest->GetBlockHash() == hash;
    return fSynced;
}

static bool RegIndexLookup(const uint256& id, CPoolInfo& out)
{
    if (!fRegIndexForTest)
        return PoolIndexLookup(id, out);
    map<uint256, CPoolInfo>::const_iterator it = mapRegIndexForTest.find(id);
    if (it == mapRegIndexForTest.end())
        return false;
    out = it->second;
    return true;
}

// Not under cs_p2pool: what the index says of each wanted pool. A pool it
// names that this node has no file of joins from the record it reports.
// "Active" is taken whenever the index says it (it read that far); a pool
// it calls pending or does not name is taken as such only once the index is
// ready (RegIndexReady). Until then the pool keeps what it had: at a start
// that is "not known yet", which carries nothing and drops nothing, so the
// partial file read back at start is still there when the index has loaded.
static void RegRefreshStatus()
{
    vector<uint256> vWant;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (fRegStatusForTest)
            return;
        if (idMinedReg != 0)
            vWant.push_back(idMinedReg);
        vWant.insert(vWant.end(), vCarryReg.begin(), vCarryReg.end());
        // Guarded pools too: a record reorged out is no longer guarded.
        foreach(RegPool* rp, vRegPools)
            if (rp->fGuard && std::find(vWant.begin(), vWant.end(), rp->id) == vWant.end())
                vWant.push_back(rp->id);
    }
    if (vWant.empty())
        return;
    bool fReady = RegIndexReady();
    vector<CPoolInfo> vInfo(vWant.size());
    vector<bool> vKnown(vWant.size(), false);
    for (size_t i = 0; i < vWant.size(); i++)
        vKnown[i] = RegIndexLookup(vWant[i], vInfo[i]);
    CRITICAL_BLOCK(cs_p2pool)
        for (size_t i = 0; i < vWant.size(); i++)
        {
            RegPool* rp = RegById(vWant[i]);
            if (!rp && vKnown[i] && !vInfo[i].record.empty())
            {
                string err;
                rp = RegNew(vWant[i], vInfo[i].record, err);
                if (!rp)
                    printf("p2pool: registered pool %s: %s\n", vWant[i].GetHex().c_str(), err.c_str());
            }
            if (!rp)
                continue;
            int nStatus = vKnown[i] ? vInfo[i].nStatus : POOL_UNKNOWN;
            if (nStatus != POOL_ACTIVE && !fReady)
                continue;
            if (nStatus != rp->nStatus || !rp->fStatusKnown)
                printf("p2pool: registered pool %s is %s on this node's chain\n", rp->id.GetHex().c_str(),
                       nStatus == POOL_ACTIVE ? "active" : nStatus == POOL_PENDING ? "pending" : "not recorded");
            rp->nStatus = nStatus;
            rp->fStatusKnown = true;
        }
}

// ---- Guardians: tickets on the wire, the ticket thread, the draw, handoff
// (docs/pool-registry.md, sections 10 to 12)
//
// poolticket.{h,cpp} is the part with no network: the ticket, the book of
// held sets, the draw and the guard budget. This is its caller:
//
//   - pooltkt and poolgettkt between NODE_POOLREG peers, read only where
//     registered pools are open (RegOpen) and -poolguard is not 0; the stated
//     epoch and seed are judged before any ticket is read, every ticket goes
//     through Precheck (no hash) before it is queued, and nothing is hashed
//     on the message thread;
//   - the ticket thread, at idle priority with a RandomX VM of its own (never
//     the verification VM under csVerify, which blocks and shares need):
//     queued tickets checked one budget token at a time (Precheck again,
//     Verify with no lock, Add under cs_p2pool on the view of that moment),
//     this node's own ticket made once its seed is buried, the draw over the
//     held tickets, pool-tickets.dat saved;
//   - guarded pools: a RegPool with fGuard, carried by the machinery of
//     registered pools (poolinv, p2xsync, the .part file), kept, pulled or
//     let go by the guard budget, lingering until 720e + 180.
//
// Guardians are availability: nothing here, and nothing a guardian sends,
// reaches whether a share is valid or what a block pays. Everything is under
// cs_p2pool unless said otherwise.

// A pooltkt carries at most this many tickets; an asked set at most 4096.
static const size_t TKT_PER_MESSAGE = 512;
// Peers whose answers for one epoch may wait at once (section 10).
static const size_t TKT_ASKED_PEERS = 4;
// Relays waiting for the ticket budget: per connection and in all. Past
// them, and whenever the budget is empty, a relay is dropped unscored.
static const size_t TKT_RELAY_QUEUE = 512;
static const size_t TKT_RELAY_QUEUE_ALL = 4096;
// The ticket budget, one for all pools and all peers: a RandomX hash each.
// Four a second fill three epochs of 4096 within the hour a fresh node has
// to see the draw (section 10), on the ticket thread's own VM.
static const int TKT_BUDGET_BURST = 256;
static const int TKT_BUDGET_PER_SEC = 4;
// A hash that could not be computed here: nothing is checked for this long.
static const int64 TKT_NO_HASH_WAIT = 60;
static const int64 TKT_SAVE_INTERVAL = 60;
// Fewer held than this for an epoch: peers are asked again every interval.
static const size_t TKT_FEW = 64;
// The draw is made again at most this often when tickets or the tip
// changed, and at least this often for the index's new pools.
static const int64 TKT_DRAW_INTERVAL = 30;
static const int64 TKT_DRAW_REFRESH = 10 * 60;
// Relays that passed and were not held, per interval, before a connection's
// relays wait behind every answer.
static const int TKT_WASTE_LOW = 8;
// Sets served (poolgettkt), all peers together: one every 30 s, 8 at once.
static const int TKT_SERVE_BURST = 8;
static const int64 TKT_SERVE_SECS = 30;
// Nonces tried between two looks at the queue while making a ticket.
static const uint64 TKT_MAKE_SLICE = 16;
// Pools whose line is pulled at once to learn its work, beside those kept.
static const size_t GUARD_MAX_PULLS = 4;
// A pull with nobody announcing the pool and nothing fetched for this long:
// the pool is taken as having no shares (no slot; pulled again when a peer
// announces it).
static const int64 GUARD_PULL_WAIT = 10 * 60;
// .btf addresses of guardians handed to the dialler at once.
static const size_t GUARD_DIAL_MAX = 16;
// A tip older than this (or the node in initial block download): no own
// ticket, no draw, no guard decisions, no sets asked for. A syncing node's
// tip walks through epochs long over; tickets made and draws taken there
// would grind every old epoch and draw this node into pools on a stale view.
static const int64 TKT_TIP_STALE = 24 * 60 * 60;

// The tickets' view of the active chain: the tip and the hashes of the
// heights the ticket and draw seeds of the previous, current and next epochs
// sit at, taken under cs_main when the tip moves (section 8: read without
// cs_main on the lock-free path).
class CTktView : public CTicketChainView
{
public:
    int nTip;
    uint256 hashTip;
    map<int, uint256> mapHash;
    CTktView() : nTip(-1), hashTip(0) {}
    int TipHeight() const { return nTip; }
    bool HashAt(int nHeight, uint256& hashOut) const
    {
        map<int, uint256>::const_iterator it = mapHash.find(nHeight);
        if (it == mapHash.end())
            return false;
        hashOut = it->second;
        return true;
    }
};

// The heights a view at this tip keeps.
static void TktViewHeights(int nTip, set<int>& out)
{
    out.clear();
    int c = pooltkt::EpochOf(nTip);
    for (int e = c - 1; c >= 0 && e <= c + 1; e++)
    {
        if (e < 1)
            continue;
        int64 h1 = pooltkt::TicketSeedHeight(e), h2 = pooltkt::DrawSeedHeight(e);
        if (h1 >= 0 && h1 <= nTip)
            out.insert((int)h1);
        if (h2 >= 0 && h2 <= nTip)
            out.insert((int)h2);
    }
}

// The ticket budget: tokens a second, not a token every n seconds.
struct TktBudget
{
    int nTokens;
    int64 nLast;
    TktBudget() : nTokens(TKT_BUDGET_BURST), nLast(0) {}
    void Refill(int64 nNow)
    {
        if (nLast == 0 || nNow < nLast)
        {
            nLast = nNow;
            return;
        }
        int64 n = (nNow - nLast) * TKT_BUDGET_PER_SEC;
        nTokens = (int)std::min((int64)TKT_BUDGET_BURST, (int64)nTokens + n);
        nLast = nNow;
    }
    bool Take(int64 nNow)
    {
        Refill(nNow);
        if (nTokens <= 0)
            return false;
        nTokens--;
        return true;
    }
    int Tokens(int64 nNow)
    {
        Refill(nNow);
        return nTokens;
    }
};

// What the draw gives this node: its place among a pool's 16, and until
// which height the place holds (the linger end of the draw that gave it).
struct GuardDrawn
{
    uint256 id;
    int nRank;
    int64 nUntil;
    vector<unsigned char> record;
};

// What this node does with a pool it was drawn for.
struct GuardEntry
{
    int nRank;
    int64 nUntil;
    vector<unsigned char> record;
    bool fEmpty;            // pulled, and nobody had a share of it
    int64 nPullSince;       // when its pull began (0: not pulling)
    int nChoice;            // GuardChoice at the last decision
    // Its line as last held here: a pool let go for want of room keeps its
    // rank by work, and is not pulled again only to be let go again.
    CGuardLine line;
    // Named by a draw of this run, made over the index's active pools: the
    // index has called it active. One read back from pool-guards.dat only
    // has no status until the index says (#91's rule, RegRefreshStatus).
    bool fNamed;
    // The place and linger end pool-guards.dat gave it (-1: none). A draw
    // after a restart cannot see a seed a redraw replaced (the ticket book
    // keeps no old seed in its file): until that linger ends, the draw's
    // place and end do not replace a better place or a later end from it.
    int nFileRank;
    int64 nFileUntil;
    GuardEntry()
        : nRank(-1), nUntil(0), fEmpty(false), nPullSince(0), nChoice(GUARD_NOT_DRAWN), fNamed(false), nFileRank(-1),
          nFileUntil(0) {}
};

static bool fPoolGuard = true;                          // -poolguard
static int64 nGuardBudget = GUARD_DEFAULT_BYTES;        // -poolguardmb
static int64 nGuardMaxPoolBytes = GUARD_MAX_POOL_BYTES;
static unsigned int nGuardMaxPools = GUARD_MAX_POOLS;
static CTktView tktView;
static bool fTktViewForTest = false;
static CTicketBook* pTktBook = NULL;
static TktQueues tqFile;                                // pool-tickets.dat read back
static TktBudget tktBudget;
static P2PoolBudget tktServeBudget(TKT_SERVE_BURST, TKT_SERVE_SECS);
static int64 nTktNoHashUntil = 0;
static uint64 nTktTurn = 0;                             // answer queues, in turn
static bool fTktDirty = false;
static int64 nTktSavedAt = 0;
static bool fTktDrawDirty = true;
static int64 nTktDrawnAt = 0;
static map<unsigned int, int64> mapTktAskRound;         // when an epoch's set was last asked for
static set<unsigned int> setTktBuried;                  // epochs whose ticket seed was buried at the last tick
static unsigned int nTktMakeEpoch = 0;                  // this node's own ticket in the making
static uint256 hashTktMakeSeed = 0;
static uint64 nTktMakeNonce = 0;
static bool fTktKeyForTest = false;
static unsigned char tktKeyForTest[32];
static bool fTktPoolsForTest = false;
static vector<CPoolInfo> vTktPoolsForTest;
static vector<GuardDrawn> vGuardDrawn;
static uint64 nGuardDrawSeq = 0, nGuardAppliedSeq = 0;
static map<uint256, vector<string> > mapGuardSeekAddr;  // a looked-for pool: the .btf of its 16
static vector<uint256> vGuardSeek;                      // pools looked for
static map<uint256, GuardEntry> mapGuard;
static bool fGuardSaveDirty = false;
static volatile bool fTktThreadStop = false;
static volatile bool fTktThreadRunning = false;
static uint64 nTktVerifiedForTest = 0;
// The tip is old or the node is in initial block download (TKT_TIP_STALE).
static bool fTktBehind = false;
static bool fTktBehindForTest = false;
// Relays and answers both waiting: whose turn the next token is.
static bool fTktAnswerNext = false;
// This node's .btf key, as its own tickets carry it: a ticket of another
// key (pool-tickets.dat of an earlier identity) is never taken as its own.
static bool fTktOwnKey = false;
static unsigned char tktOwnKey[32];

static bool TktActive()
{
    return RegOpen() && fPoolGuard;
}

// The ticket thread's own light RandomX VM (section 10): ticket checks and
// this node's own ticket never wait on, nor delay, the verification VM that
// blocks and shares use. Zero, pooltkt's sign for "not computed", when no VM
// can be made here or RandomX is known not to work.
static CCriticalSection cs_tktVM;
static void* pTktVM = NULL;
static int64 nTktVMRetryAt = 0;

// The VM is made on the ticket thread at its normal priority (making it
// takes RandomX's own setup lock), never on the idle worker that hashes.
static void TktEnsureVM()
{
    if (RandomXVerifierKnownUnavailable(2))
        return;
    CRITICAL_BLOCK(cs_tktVM)
        if (!pTktVM && GetTime() >= nTktVMRetryAt)
        {
            pTktVM = RandomXCreateMinerVM(2);
            if (!pTktVM)
                nTktVMRetryAt = GetTime() + TKT_NO_HASH_WAIT;
        }
}

static uint256 TktWorkOwnVM(const unsigned char* pHeader80)
{
    uint256 h = 0;
    if (RandomXVerifierKnownUnavailable(2))
        return h;
    // cs_tktVM is the ticket thread's alone: the idle worker holds it only
    // while the ticket thread waits for that very hash.
    CRITICAL_BLOCK(cs_tktVM)
        if (pTktVM)
        {
            h = PoWHashHeaderWithVM(pTktVM, pHeader80);
            if (h == POW_HASH_UNAVAILABLE)
                h = 0;
        }
    return h;
}

// ---- Idle priority with no lock held at it
//
// The ticket work runs at idle priority so it takes only what the miners
// leave. On Linux an unprivileged thread cannot raise its priority again
// once lowered (nice 19 back to 0 needs CAP_SYS_NICE), and a thread at nice
// 19 that holds cs_p2pool behind miners at nice 0 stalls the message thread
// and stratum submits (priority inversion). So the ticket thread keeps the
// normal priority, takes cs_p2pool only for its picks and copies, and hands
// the long work (ticket hashes, its own ticket's nonces, the draw's ranking,
// the file's bytes and hash) to a worker that runs at idle priority and
// takes no lock but cs_tktVM. With no worker running (self-tests, fuzz) the
// work runs where it is called.
static std::mutex mtxTktIdle;
static std::condition_variable cvTktIdle;
static const std::function<void()>* pTktIdleJob = NULL;
static std::exception_ptr pTktIdleError;
static bool fTktIdleDone = false;
static bool fTktIdleQuit = false;
static bool fTktIdleRunning = false;    // set and read on the ticket thread only

static void TktLowerThisThread()
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
#ifdef __linux__
    setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), 19);
#endif
}

static void ThreadTktIdle()
{
    TktLowerThisThread();
    std::unique_lock<std::mutex> lk(mtxTktIdle);
    while (true)
    {
        cvTktIdle.wait(lk, [] { return pTktIdleJob != NULL || fTktIdleQuit; });
        if (!pTktIdleJob)
            break;
        const std::function<void()>* pJob = pTktIdleJob;
        lk.unlock();
        std::exception_ptr err;
        try
        {
            (*pJob)();
        }
        catch (...)
        {
            err = std::current_exception();
        }
        lk.lock();
        pTktIdleError = err;
        pTktIdleJob = NULL;
        fTktIdleDone = true;
        cvTktIdle.notify_all();
    }
}

// Runs fn at idle priority and waits for it. Never called with a lock held.
static void TktIdle(const std::function<void()>& fn)
{
    if (!fTktIdleRunning)
    {
        fn();
        return;
    }
    std::exception_ptr err;
    {
        std::unique_lock<std::mutex> lk(mtxTktIdle);
        pTktIdleJob = &fn;
        fTktIdleDone = false;
        cvTktIdle.notify_all();
        cvTktIdle.wait(lk, [] { return fTktIdleDone; });
        err = pTktIdleError;
        pTktIdleError = std::exception_ptr();
    }
    if (err)
        std::rethrow_exception(err);
}

static CTicketBook& TktBook()
{
    if (!pTktBook)
    {
        CTicketParams p = CTicketParams::Network();
        p.fnWork = TktWorkOwnVM;
        pTktBook = new CTicketBook(p);
    }
    return *pTktBook;
}

static string TktFilePath() { return GetAppDir() + "/pool-tickets.dat"; }
static string GuardFilePath() { return GetAppDir() + "/pool-guards.dat"; }

// Whether the seed this view gives an epoch is buried, and which it is.
static bool TktBuriedSeed(unsigned int nEpoch, uint256& hashOut)
{
    bool fBuried = false;
    return pooltkt::TicketSeed(tktView, nEpoch, hashOut, fBuried) && fBuried;
}

// The epochs whose sets this node takes, holds and asks for: previous (in
// its linger), current and next, each once its seed is buried.
static void TktEpochs(vector<unsigned int>& out)
{
    out.clear();
    int c = pooltkt::EpochOf(tktView.nTip);
    for (int e = c - 1; c >= 0 && e <= c + 1; e++)
    {
        uint256 h;
        if (e >= 1 && pooltkt::EpochInRange(tktView, e) && TktBuriedSeed(e, h))
            out.push_back((unsigned int)e);
    }
}

static void TktDropEpochQueues(TktQueues& q, unsigned int nEpoch)
{
    q.mapAnswer.erase(nEpoch);
    q.mapAnswerBodies.erase(nEpoch);
    for (std::deque<TktItem>::iterator it = q.qRelay.begin(); it != q.qRelay.end();)
        if (it->nEpoch == nEpoch)
            it = q.qRelay.erase(it);
        else
            ++it;
}

static void TktDropEpochAll(unsigned int nEpoch)
{
    TktDropEpochQueues(tqFile, nEpoch);
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
    {
        TktDropEpochQueues(it->second.tq, nEpoch);
        it->second.mapTktOut.erase(nEpoch);
    }
}

// The view moved: the book follows it before any Add (section 10).
static void TktSyncLocked()
{
    CTicketSync s;
    TktBook().Sync(tktView, s);
    foreach(unsigned int e, s.vSeedGone)
    {
        printf("p2pool: guardian tickets of epoch %u: their seed left the active chain; the set is asked for again\n", e);
        // Queued tickets were checked against the old seed: they go, and
        // the set is asked for again; this node's own ticket is made again.
        TktDropEpochAll(e);
        mapTktAskRound.erase(e);
        if (nTktMakeEpoch == e)
            nTktMakeEpoch = 0;
    }
    foreach(unsigned int e, s.vExpired)
    {
        TktDropEpochAll(e);
        mapTktAskRound.erase(e);
    }
    for (size_t i = 0; i < s.vRedraw.size(); i++)
        printf("p2pool: the draw of epoch %u changed seed after it settled (a deep reorg): nodes drawn by the old seed "
               "keep their pools until height %d\n", s.vRedraw[i], (int)s.vRedrawUntil[i]);
    if (!s.vSeedGone.empty() || !s.vExpired.empty())
        fTktDirty = true;
    // A seed buried since the last tick: its set is asked for (relays of it
    // were dropped until now).
    set<unsigned int> setNow;
    vector<unsigned int> vE;
    TktEpochs(vE);
    setNow.insert(vE.begin(), vE.end());
    foreach(unsigned int e, setNow)
        if (!setTktBuried.count(e))
            mapTktAskRound.erase(e);
    setTktBuried.swap(setNow);
    fTktDrawDirty = true;
}

// Every interval, the counts that rank a connection's relays start over. A
// relay that came back outranked or past the cap counts one; one scored for
// a bad signature or failed work counts TKT_WASTE_LOW at once.
static bool TktLowStanding(const RegConn& c)
{
    return c.nTktWasted >= TKT_WASTE_LOW && c.nTktWasted > 2 * c.nTktHeld;
}

// The sets asked of peers: at start, when a seed is newly buried or reorged
// out, and every interval while an epoch holds few. At most 4 peers' answers
// wait per epoch; a peer is asked an epoch at most once an interval.
static void TktAskLocked(int64 nNow)
{
    vector<unsigned int> vE;
    // Not while behind: the epochs of an old tip are long over. Asked for
    // once caught up (no round was recorded for them).
    if (!fTktBehind)
        TktEpochs(vE);
    foreach(unsigned int e, vE)
    {
        map<unsigned int, int64>::iterator itR = mapTktAskRound.find(e);
        bool fWant = itR == mapTktAskRound.end() ||
                     (TktBook().Held(e) < TKT_FEW && nNow - itR->second >= SYNC_SERVE_INTERVAL);
        if (!fWant)
            continue;
        size_t nOpen = 0;
        vector<std::pair<std::pair<int, int64>, CNode*> > vCand;
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            CNode* p = it->first;
            RegConn& c = it->second;
            if (p->fDisconnect || p->nVersion == 0 || !(p->nServices & NODE_POOLREG))
                continue;
            map<unsigned int, int64>::iterator itA = c.mapTktAskedAt.find(e);
            map<unsigned int, std::deque<TktItem> >::iterator itQ = c.tq.mapAnswer.find(e);
            if ((itA != c.mapTktAskedAt.end() && nNow - itA->second <= SYNC_ANSWER_WINDOW) ||
                (itQ != c.tq.mapAnswer.end() && !itQ->second.empty()))
            {
                nOpen++;
                continue;
            }
            if (itA != c.mapTktAskedAt.end() && nNow - itA->second < SYNC_SERVE_INTERVAL)
                continue;
            vCand.push_back(std::make_pair(std::make_pair(p->fInbound ? 1 : 0, p->nTimeConnected), p));
        }
        std::sort(vCand.begin(), vCand.end());
        size_t nAsked = 0;
        for (size_t i = 0; i < vCand.size() && nOpen + nAsked < TKT_ASKED_PEERS; i++)
        {
            CNode* p = vCand[i].second;
            RegConn& c = mapRegConn[p];
            PushReg(p, "poolgettkt", e);
            c.mapTktAskedAt[e] = nNow;
            c.mapTktAnswered[e] = 0;
            c.tq.mapAnswerBodies.erase(e);
            nAsked++;
        }
        if (nAsked)
        {
            mapTktAskRound[e] = nNow;
            LogPrint("p2pool", "p2pool: guardian tickets of epoch %u: %u held, asked %u peer(s) for their set\n", e,
                     (unsigned)TktBook().Held(e), (unsigned)nAsked);
        }
    }
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        if (nNow - it->second.nTktTallySince >= SYNC_SERVE_INTERVAL)
        {
            it->second.nTktTallySince = nNow;
            it->second.nTktWasted = it->second.nTktHeld = 0;
        }
}

// On the message thread, once a second.
static void TktTick(int64 nNow)
{
    if (!TktActive())
        return;
    CTktView v;
    bool fNew = false;
    bool fForTest;
    bool fBehindKnown = false, fBehind = false;
    uint256 hashKnown;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fForTest = fTktViewForTest;
        hashKnown = tktView.hashTip;
    }
    if (!fForTest)
    {
        // cs_main only if free, and never under cs_p2pool (the template code
        // takes cs_main first): busy, the view is taken a second later.
        TRY_CRITICAL_BLOCK(cs_main)
        {
            // Whether this node is caught up: the node's own notion (initial
            // block download, by its peers' heights), and a tip a day old
            // (a node alone, or with no peer heights yet, after a long stop).
            fBehindKnown = true;
            fBehind = !pindexBest || IsInitialBlockDownload() || (int64)pindexBest->nTime < nNow - TKT_TIP_STALE;
            if (pindexBest && pindexBest->GetBlockHash() != hashKnown)
            {
                v.nTip = pindexBest->nHeight;
                v.hashTip = pindexBest->GetBlockHash();
                set<int> setH;
                TktViewHeights(v.nTip, setH);
                int nLow = setH.empty() ? v.nTip : *setH.begin();
                for (CBlockIndex* p = pindexBest; p && p->nHeight >= nLow; p = p->pprev)
                    if (setH.count(p->nHeight))
                        v.mapHash[p->nHeight] = p->GetBlockHash();
                fNew = true;
            }
        }
    }
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (fTktViewForTest)
            fTktBehind = fTktBehindForTest;
        else if (fBehindKnown)
        {
            if (fTktBehind && !fBehind)
                fTktDrawDirty = true;
            fTktBehind = fBehind;
        }
        if (fNew && !fTktViewForTest)
        {
            tktView = v;
            TktSyncLocked();
        }
        if (tktView.nTip >= 0)
            TktAskLocked(nNow);
    }
}

// Under cs_p2pool: a held ticket goes to every peer that reads the registry
// but the one it came from, until its epoch's deadline (a ticket after the
// deadline travels only in answers).
static void TktRelayLocked(const CGuardTicket& t, unsigned int nEpoch, CNode* pfrom)
{
    if (pooltkt::PastDeadline(tktView, nEpoch))
        return;
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
    {
        CNode* p = it->first;
        if (p == pfrom || p->fDisconnect || p->nVersion == 0 || !(p->nServices & NODE_POOLREG))
            continue;
        vector<CGuardTicket>& v = it->second.mapTktOut[nEpoch];
        if (v.size() < GUARD_MAX_TICKETS)
            v.push_back(t);
    }
}

// On the message thread, every pass: what the ticket thread scored, and the
// held tickets it relays, in parts of 512, each with its seed (never one
// that is no longer this node's).
static void TktFlush()
{
    vector<std::pair<CNode*, int> > vScore;
    struct Out { CNode* p; unsigned int e; uint256 seed; vector<CGuardTicket> v; };
    vector<Out> vOut;
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            RegConn& c = it->second;
            if (c.nTktScore)
            {
                vScore.push_back(std::make_pair(it->first, c.nTktScore));
                c.nTktScore = 0;
            }
            for (map<unsigned int, vector<CGuardTicket> >::iterator itO = c.mapTktOut.begin(); itO != c.mapTktOut.end(); ++itO)
            {
                uint256 hashHeld, hashChain;
                if (itO->second.empty() || !TktActive() || !TktBook().Seed(itO->first, hashHeld) ||
                    !TktBuriedSeed(itO->first, hashChain) || hashHeld != hashChain ||
                    pooltkt::PastDeadline(tktView, itO->first))
                    continue;
                for (size_t i = 0; i < itO->second.size(); i += TKT_PER_MESSAGE)
                {
                    Out o;
                    o.p = it->first;
                    o.e = itO->first;
                    o.seed = hashHeld;
                    o.v.assign(itO->second.begin() + i, itO->second.begin() + std::min(itO->second.size(), i + TKT_PER_MESSAGE));
                    vOut.push_back(o);
                }
            }
            c.mapTktOut.clear();
        }
    }
    for (size_t i = 0; i < vScore.size(); i++)
        vScore[i].first->Misbehaving(vScore[i].second);
    for (size_t i = 0; i < vOut.size(); i++)
        if (!vOut[i].p->fDisconnect)
            PushReg(vOut[i].p, "pooltkt", vOut[i].e, vOut[i].seed, vOut[i].v);
}

// pooltkt and poolgettkt (section 10). Only between peers that read the
// registry, where registered pools are open and this node guards: elsewhere
// dropped unread, nobody scored, nothing answered.
static bool TktProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (!(pfrom->nServices & NODE_POOLREG) || !TktActive())
        return true;
    int64 nNow = GetTime();

    if (strCommand == "poolgettkt")
    {
        unsigned int nEpoch;
        vRecv >> nEpoch;
        // Not while this peer has not read what it was sent already.
        if (SendQueueFull(classReg, pfrom))
            return true;
        vector<CGuardTicket> v;
        uint256 hashSeed = 0;
        CRITICAL_BLOCK(cs_p2pool)
        {
            RegConn& c = RegConnOf(pfrom);
            uint256 hashChain;
            // The held set of an epoch this node takes, under the seed its
            // chain has now; once per connection and epoch an interval, from
            // the serve budget. Anything else: silence.
            if (!pooltkt::EpochInRange(tktView, nEpoch) || !TktBuriedSeed(nEpoch, hashChain) ||
                !TktBook().Seed(nEpoch, hashSeed) || hashSeed != hashChain || TktBook().Held(nEpoch) == 0)
                return true;
            map<unsigned int, int64>::iterator itS = c.mapTktServedAt.find(nEpoch);
            if (itS != c.mapTktServedAt.end() && nNow - itS->second < SYNC_SERVE_INTERVAL)
                return true;
            if (!tktServeBudget.Take(nNow))
                return true;
            c.mapTktServedAt[nEpoch] = nNow;
            vector<CHeldTicket> vHeld;
            TktBook().Tickets(nEpoch, vHeld);
            for (size_t i = 0; i < vHeld.size() && v.size() < GUARD_MAX_TICKETS; i++)
                v.push_back(vHeld[i].ticket);
        }
        for (size_t i = 0; i < v.size(); i += TKT_PER_MESSAGE)
        {
            vector<CGuardTicket> part(v.begin() + i, v.begin() + std::min(v.size(), i + TKT_PER_MESSAGE));
            PushReg(pfrom, "pooltkt", nEpoch, hashSeed, part);
        }
        return true;
    }

    // pooltkt: the epoch, the seed the sender checked them against, the
    // tickets. Framing is the sender's fault (step 1); nothing is read past it.
    unsigned int nEpoch;
    uint256 hashSeed;
    vRecv >> nEpoch >> hashSeed;
    uint64 n = ReadCompactSize(vRecv);
    if (n > TKT_PER_MESSAGE || vRecv.size() != n * GUARD_TICKET_SIZE)
    {
        pfrom->Misbehaving(20);
        return true;
    }
    bool fScore = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegConn& c = RegConnOf(pfrom);
        // The message's epoch and seed before any ticket is read (step 2):
        // an epoch this node does not take, a seed not buried here, another
        // seed, an unasked relay past the deadline. Nobody scored.
        uint256 hashChain;
        if (!pooltkt::EpochInRange(tktView, nEpoch) || !TktBuriedSeed(nEpoch, hashChain) || hashChain != hashSeed)
            return true;
        map<unsigned int, int64>::iterator itA = c.mapTktAskedAt.find(nEpoch);
        const bool fAnswer = itA != c.mapTktAskedAt.end() && nNow - itA->second <= SYNC_ANSWER_WINDOW;
        if (!fAnswer && pooltkt::PastDeadline(tktView, nEpoch))
            return true;
        // An unasked relay that finds the ticket budget empty is dropped
        // (it comes again, or in an answer).
        const bool fRelayRoom = fAnswer || tktBudget.Tokens(nNow) > 0;
        size_t nRelays = tqFile.qRelay.size();
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
            nRelays += it->second.tq.qRelay.size();
        const uint64 nMsg = ++c.nTktMsg;
        unsigned char buf[GUARD_TICKET_SIZE];
        for (uint64 i = 0; i < n && !fScore; i++)
        {
            vRecv.read((char*)buf, sizeof(buf));
            TktItem item;
            int v = TktBook().Precheck(tktView, buf, sizeof(buf), nEpoch, hashSeed, fAnswer, item.t);
            // Read up to the first ticket the sender is at fault for, and
            // scored once for the message.
            if (TicketScored(v))
            {
                fScore = true;
                continue;
            }
            if (v != TICKET_PRECHECK_OK)
                continue;
            item.nEpoch = nEpoch;
            item.hashSeed = hashSeed;
            item.fOwn = false;
            item.nMsg = nMsg;
            if (fAnswer)
            {
                // One set's worth an ask; deduplicated within this peer's
                // queue only. Beyond it, dropped unscored.
                size_t& nTaken = c.mapTktAnswered[nEpoch];
                set<uint256>& setBodies = c.tq.mapAnswerBodies[nEpoch];
                const uint256 hashBody = item.t.BodyHash();
                if (nTaken >= GUARD_MAX_TICKETS || setBodies.count(hashBody))
                    continue;
                nTaken++;
                setBodies.insert(hashBody);
                c.tq.mapAnswer[nEpoch].push_back(item);
            }
            else if (fRelayRoom && c.tq.qRelay.size() < TKT_RELAY_QUEUE && nRelays < TKT_RELAY_QUEUE_ALL)
            {
                c.tq.qRelay.push_back(item);
                nRelays++;
            }
        }
    }
    if (fScore)
        pfrom->Misbehaving(20);
    return true;
}

// ---- The ticket thread

// A ticket taken from a queue for its hash: where it came from (a connection
// by pointer and serial, or this node's file), and whether as an answer.
struct TktJob
{
    TktItem item;
    CNode* pnode;
    uint64 nSerial;
    bool fAnswer;
    bool fFile;
};

static void TktDropAllRelays()
{
    tqFile.qRelay.clear();
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        it->second.tq.qRelay.clear();
}

// Under cs_p2pool: whether a ticket from pool-tickets.dat marked as this
// node's own carries this node's key.
static bool TktOwnKeyLocked(const CGuardTicket& t)
{
    return fTktOwnKey && memcmp(t.PubKey(), tktOwnKey, 32) == 0;
}

// Under cs_p2pool: the next ticket to hash, with Precheck passed again on
// the view of now and a ticket budget token taken for it. Relays of
// connections in good standing (older connections first) and the answer
// queues (in turn, one ticket from each, this node's file among them) take
// the tokens in turn while both wait, so relays from however many new
// connections never starve the answers (section 12); then the relays of
// connections whose relays keep coming back outranked or past the cap, or
// were scored, once no answer waits. False: nothing to hash now.
static bool TktPickLocked(int64 nNow, TktJob& job)
{
    for (int nTry = 0; nTry < 256; nTry++)
    {
        vector<std::pair<int64, CNode*> > vGood, vLow;
        struct AnsQ { TktQueues* q; unsigned int e; CNode* p; uint64 nSerial; };
        vector<AnsQ> vAns;
        for (map<unsigned int, std::deque<TktItem> >::iterator itQ = tqFile.mapAnswer.begin(); itQ != tqFile.mapAnswer.end(); ++itQ)
            if (!itQ->second.empty())
            {
                AnsQ a = { &tqFile, itQ->first, NULL, 0 };
                vAns.push_back(a);
            }
        vector<std::pair<uint64, CNode*> > vBySerial;
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            RegConn& c = it->second;
            if (it->first->fDisconnect)
                continue;
            if (!c.tq.qRelay.empty())
                (TktLowStanding(c) ? vLow : vGood).push_back(std::make_pair(it->first->nTimeConnected, it->first));
            vBySerial.push_back(std::make_pair(c.nTktSerial, it->first));
        }
        std::sort(vBySerial.begin(), vBySerial.end());
        for (size_t i = 0; i < vBySerial.size(); i++)
        {
            RegConn& c = mapRegConn[vBySerial[i].second];
            for (map<unsigned int, std::deque<TktItem> >::iterator itQ = c.tq.mapAnswer.begin(); itQ != c.tq.mapAnswer.end(); ++itQ)
                if (!itQ->second.empty())
                {
                    AnsQ a = { &c.tq, itQ->first, vBySerial[i].second, c.nTktSerial };
                    vAns.push_back(a);
                }
        }
        std::sort(vGood.begin(), vGood.end());
        std::sort(vLow.begin(), vLow.end());
        TktQueues* q = NULL;
        std::deque<TktItem>* pq = NULL;
        job.fFile = false;
        job.pnode = NULL;
        job.nSerial = 0;
        const bool fRelay = !vGood.empty() ? (vAns.empty() || !fTktAnswerNext) : (vAns.empty() && !vLow.empty());
        if (fRelay)
        {
            CNode* p = !vGood.empty() ? vGood[0].second : vLow[0].second;
            RegConn& c = mapRegConn[p];
            q = &c.tq;
            pq = &q->qRelay;
            job.fAnswer = false;
            job.pnode = p;
            job.nSerial = c.nTktSerial;
        }
        else if (!vAns.empty())
        {
            const AnsQ& a = vAns[(size_t)(nTktTurn++ % vAns.size())];
            q = a.q;
            pq = &q->mapAnswer[a.e];
            job.fAnswer = true;
            job.fFile = a.p == NULL;
            job.pnode = a.p;
            job.nSerial = a.nSerial;
        }
        else
            return false;
        job.item = pq->front();
        pq->pop_front();
        // Step 2 again, on the view of now: the chain may have moved while it
        // waited. A drop costs no token.
        const vector<unsigned char> b = job.item.t.Bytes();
        CGuardTicket t;
        int v = TktBook().Precheck(tktView, &b[0], b.size(), job.item.nEpoch, job.item.hashSeed, job.fAnswer, t);
        // This node's own ticket from its file, whose body came in from a
        // peer first: already checked, it is still this node's own (no hash),
        // if it carries this node's key.
        if (v == TICKET_DROP_SEEN && job.item.fOwn && TktOwnKeyLocked(job.item.t))
            TktBook().AddOwnVerified(tktView, job.item.t, job.item.hashSeed, uint256(1), tktOwnKey);
        if (v != TICKET_PRECHECK_OK)
            continue;
        if (!tktBudget.Take(nNow))
        {
            if (!job.fAnswer)
            {
                // An unasked relay that finds the budget empty is dropped,
                // and so is every relay waiting; answers wait.
                TktDropAllRelays();
                continue;
            }
            pq->push_front(job.item);
            return false;
        }
        fTktAnswerNext = !job.fAnswer;
        return true;
    }
    return false;
}

// Under cs_p2pool: what the hash said.
static void TktApplyLocked(const TktJob& job, int v, const uint256& hashWork, int64 nNow)
{
    RegConn* pc = NULL;
    if (!job.fFile && job.pnode)
    {
        map<CNode*, RegConn>::iterator it = mapRegConn.find(job.pnode);
        if (it != mapRegConn.end() && it->second.nTktSerial == job.nSerial)
            pc = &it->second;
    }
    TktQueues* pq = job.fFile ? &tqFile : pc ? &pc->tq : NULL;
    const unsigned int e = job.item.nEpoch;
    if (v == TICKET_DROP_NO_HASH)
    {
        // This node could not hash: nobody scored, nothing remembered, and
        // nothing hashed for a while. An answer waits to be tried again.
        if (nNow >= nTktNoHashUntil)
            printf("p2pool: guardian tickets: RandomX gave no hash here; ticket checks wait %d s\n", (int)TKT_NO_HASH_WAIT);
        nTktNoHashUntil = nNow + TKT_NO_HASH_WAIT;
        if (job.fAnswer && pq)
            pq->mapAnswer[e].push_front(job.item);
        return;
    }
    if (TicketScored(v))
    {
        // A bad signature, or work that fails against the seed the sender
        // named itself: never honest. An answer's sender is scored once and
        // its queue dropped (another peer's copies of the same tickets wait
        // in their own queues); a relay's once per message, and the rest of
        // that message dropped.
        if (job.fAnswer)
        {
            if (pq)
            {
                pq->mapAnswer.erase(e);
                pq->mapAnswerBodies.erase(e);
            }
            if (pc)
                pc->nTktScore += 20;
        }
        else if (pc && pc->nTktScoredMsg != job.item.nMsg)
        {
            pc->nTktScore += 20;
            pc->nTktScoredMsg = job.item.nMsg;
            // Never honest: the connection's relays wait behind every answer
            // for the rest of the interval (TktLowStanding).
            pc->nTktWasted += TKT_WASTE_LOW;
            for (std::deque<TktItem>::iterator it = pc->tq.qRelay.begin(); it != pc->tq.qRelay.end();)
                if (it->nMsg == job.item.nMsg)
                    it = pc->tq.qRelay.erase(it);
                else
                    ++it;
        }
        LogPrint("p2pool", "p2pool: a guardian ticket of epoch %u refused: %s\n", e, TicketVerdictName(v));
        return;
    }
    nTktVerifiedForTest++;
    // A ticket the file marks as this node's own but of another key (an
    // earlier identity) is held as anybody's, never as this node's.
    int r = job.item.fOwn && TktOwnKeyLocked(job.item.t)
                ? TktBook().AddOwnVerified(tktView, job.item.t, job.item.hashSeed, hashWork, tktOwnKey)
                : TktBook().Add(tktView, job.item.t, job.item.hashSeed, hashWork);
    if (r == TICKET_HELD)
    {
        // Only a held ticket is relayed.
        TktRelayLocked(job.item.t, e, job.pnode);
        fTktDirty = true;
        fTktDrawDirty = true;
    }
    if (!job.fAnswer && pc)
    {
        if (r == TICKET_HELD)
            pc->nTktHeld++;
        else if (r == TICKET_OUTRANKED || r == TICKET_PAST_CAP)
            pc->nTktWasted++;
    }
}

// This node's own ticket for the current or the next epoch, a slice of
// nonces at a time (MakeTicketWork; the .btf key signs in nostr.cpp). Only
// on a node that listens on an onion, which is what makes it reachable as a
// guardian. Not while the node is behind (TKT_TIP_STALE), nor for an epoch
// whose own ticket from pool-tickets.dat still waits in the queue. True
// when it hashed.
static bool TktOwnPendingLocked(unsigned int nEpoch, const uint256& hashSeed)
{
    map<unsigned int, std::deque<TktItem> >::const_iterator itQ = tqFile.mapAnswer.find(nEpoch);
    if (itQ == tqFile.mapAnswer.end())
        return false;
    foreach(const TktItem& item, itQ->second)
        if (item.fOwn && item.hashSeed == hashSeed && TktOwnKeyLocked(item.t))
            return true;
    return false;
}

static bool TktMakeStep(int64 nNow)
{
    unsigned int nEpoch = 0;
    uint256 hashSeed = 0;
    uint64 nNonce = 0;
    unsigned short nCapacity = 0;
    CTicketParams params;
    bool fTestKey = false;
    unsigned char sk[32];
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (TktActive() && tktView.nTip >= 0 && nNow >= nTktNoHashUntil && !fTktBehind)
        {
            int c = pooltkt::EpochOf(tktView.nTip);
            for (int e = c; e <= c + 1 && nEpoch == 0; e++)
            {
                uint256 h, hashOwnSeed;
                CGuardTicket t;
                uint256 w;
                if (e < 1 || !TktBuriedSeed(e, h))
                    continue;
                if (TktBook().Own(e, t, w) && TktBook().Seed(e, hashOwnSeed) && hashOwnSeed == h)
                    continue;
                // Read back from the file and waiting behind relays for a
                // token: checked in its turn, not made again meanwhile.
                if (TktOwnPendingLocked((unsigned int)e, h))
                    continue;
                nEpoch = e;
                hashSeed = h;
            }
            if (nEpoch != 0)
            {
                if (nTktMakeEpoch != nEpoch || hashTktMakeSeed != hashSeed)
                {
                    nTktMakeEpoch = nEpoch;
                    hashTktMakeSeed = hashSeed;
                    nTktMakeNonce = GetRand(~(uint64)0);
                }
                nNonce = nTktMakeNonce;
                params = TktBook().Params();
                nCapacity = (unsigned short)std::min((int64)65535, nGuardBudget / (1024 * 1024));
                fTestKey = fTktKeyForTest;
                if (fTestKey)
                    memcpy(sk, tktKeyForTest, 32);
            }
        }
    }
    if (nEpoch == 0)
        return false;
    unsigned char pubkey[32];
    if (fTestKey)
    {
        if (!pooltkt::XOnlyPubKey(sk, pubkey))
            return false;
    }
    else
    {
        unsigned char encsk[32];
        bool fId = !BtfLocalOnionEndpoint().empty() && BtfGetIdentity(pubkey, encsk);
        memset(encsk, 0, sizeof(encsk));
        if (!fId)
            return false;
    }
    CRITICAL_BLOCK(cs_p2pool)
    {
        memcpy(tktOwnKey, pubkey, 32);
        fTktOwnKey = true;
    }
    if (params.fnWork == TktWorkOwnVM)
        TktEnsureVM();
    CGuardTicket t;
    uint256 hashWork = 0;
    uint64 nTries = 0;
    bool fFound = false;
    // The nonces at idle priority, with no lock held; the signature here
    // (the .btf key's lock is not taken at idle priority).
    TktIdle([&] {
        fFound = pooltkt::MakeTicketWork(params, hashSeed, nEpoch, pubkey, nCapacity, nNonce, TKT_MAKE_SLICE, t, hashWork,
                                         nTries, &fTktThreadStop);
    });
    // The work was ground for pubkey: a signature that put another key in
    // the body would make a ticket whose work is not its own.
    if (fFound)
        fFound = memcmp(t.PubKey(), pubkey, 32) == 0 &&
                 (fTestKey ? (t.Sign(sk) && t.VerifySig()) : BtfSignGuardTicket(t)) && memcmp(t.PubKey(), pubkey, 32) == 0;
    memset(sk, 0, sizeof(sk));
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (nTktMakeEpoch == nEpoch && hashTktMakeSeed == hashSeed)
            nTktMakeNonce = nNonce + std::max(nTries, (uint64)1);
        if (!fFound && nTries < TKT_MAKE_SLICE && !fTktThreadStop)
            nTktNoHashUntil = nNow + TKT_NO_HASH_WAIT;
        if (fFound)
        {
            int r = TktBook().AddOwnVerified(tktView, t, hashSeed, hashWork, pubkey);
            printf("p2pool: this node's guardian ticket for epoch %u made (%s)\n", nEpoch, TicketVerdictName(r));
            if (r == TICKET_HELD)
                TktRelayLocked(t, nEpoch, NULL);
            if (TicketPassed(r))
            {
                fTktDirty = true;
                fTktDrawDirty = true;
            }
            nTktMakeEpoch = 0;
        }
    }
    return true;
}

// The draw (section 10): this node's place among each active pool's 16 under
// every draw in force (the previous epoch's while it lingers, the current
// one's, the next one's once settled, and the seeds of a redraw until their
// linger ends), and the 16 of each pool this node looks for. Over a copy of
// the tickets, with no lock held: pools times tickets SHA256d.
static void TktDrawStep(int64 nNow)
{
    bool fGo = false;
    CRITICAL_BLOCK(cs_p2pool)
        fGo = TktActive() && tktView.nTip >= 0 && !fTktBehind &&
              ((fTktDrawDirty && nNow - nTktDrawnAt >= TKT_DRAW_INTERVAL) || nNow - nTktDrawnAt >= TKT_DRAW_REFRESH);
    if (!fGo)
        return;
    // Active registered pools, pool zero aside (the index has its own lock).
    vector<CPoolInfo> vInfo;
    bool fReady = true, fTest;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTest = fTktPoolsForTest;
        if (fTest)
            vInfo = vTktPoolsForTest;
    }
    if (!fTest)
    {
        fReady = RegIndexReady();
        if (fReady)
            PoolIndexList(vInfo);
    }
    if (!fReady)
    {
        CRITICAL_BLOCK(cs_p2pool)
            nTktDrawnAt = nNow - TKT_DRAW_INTERVAL + 10;
        return;
    }
    const uint256 idZero = RegZeroId();
    vector<uint256> vPools;
    vector<vector<unsigned char> > vRecords;
    foreach(const CPoolInfo& info, vInfo)
        if (info.nStatus == POOL_ACTIVE && !info.fZero && info.id != idZero && !info.record.empty())
        {
            vPools.push_back(info.id);
            vRecords.push_back(info.record);
        }
    struct Draw { unsigned int e; uint256 hashDraw; int64 nUntil; };
    vector<Draw> vDraw;
    map<unsigned int, vector<CHeldTicket> > mapTickets;
    map<unsigned int, uint256> mapOwnWork;
    vector<unsigned char> keyOwn;
    vector<uint256> vSeek;
    int c;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTktDrawDirty = false;
        nTktDrawnAt = nNow;
        c = pooltkt::EpochOf(tktView.nTip);
        for (int e = c - 1; e <= c + 1; e++)
        {
            if (e < 1 || (e == c - 1 && tktView.nTip >= pooltkt::LingerEndHeight(c)))
                continue;
            uint256 hashDraw, hashChain, hashHeld;
            bool fSettled = false;
            if (!TktBook().NoteDrawSeed(tktView, e, hashDraw, fSettled) || !fSettled)
                continue;
            Draw d = { (unsigned int)e, hashDraw, pooltkt::LingerEndHeight(e + 1) };
            vDraw.push_back(d);
            vector<std::pair<uint256, int64> > vOld;
            TktBook().OldDrawSeedsUntil(e, vOld);
            for (size_t i = 0; i < vOld.size(); i++)
            {
                Draw o = { (unsigned int)e, vOld[i].first, vOld[i].second };
                vDraw.push_back(o);
            }
            if (TktBuriedSeed(e, hashChain) && TktBook().Seed(e, hashHeld) && hashChain == hashHeld)
            {
                TktBook().Tickets(e, mapTickets[e]);
                CGuardTicket own;
                uint256 w;
                CHeldTicket held;
                if (TktBook().Own(e, own, w) && TktBook().HeldByKey(e, own.PubKey(), held) && held.hashWork == w)
                {
                    mapOwnWork[e] = w;
                    keyOwn = own.Key();
                }
            }
        }
        vSeek = vGuardSeek;
    }
    const unsigned int nPlaces = GUARD_PLACES + GUARD_RESERVE;
    map<uint256, std::pair<int, int64> > mapRank;
    map<uint256, vector<string> > mapSeek;
    // The ranking at idle priority, over the copies, with no lock held.
    TktIdle([&] {
        for (size_t k = 0; k < vDraw.size(); k++)
        {
            map<unsigned int, uint256>::const_iterator itOwn = mapOwnWork.find(vDraw[k].e);
            if (itOwn == mapOwnWork.end())
                continue;
            const vector<CHeldTicket>& vT = mapTickets[vDraw[k].e];
            for (size_t i = 0; i < vPools.size(); i++)
            {
                unsigned int r = pooltkt::RankOf(vDraw[k].hashDraw, vPools[i], vT, itOwn->second, nPlaces);
                if (r >= nPlaces)
                    continue;
                map<uint256, std::pair<int, int64> >::iterator it = mapRank.find(vPools[i]);
                if (it == mapRank.end())
                    mapRank[vPools[i]] = std::make_pair((int)r, vDraw[k].nUntil);
                else
                {
                    it->second.first = std::min(it->second.first, (int)r);
                    it->second.second = std::max(it->second.second, vDraw[k].nUntil);
                }
            }
        }
        // A pool looked for: the 16 of the current and the previous epoch's
        // draws, this node aside, as .btf addresses to dial.
        for (size_t j = 0; j < vSeek.size(); j++)
        {
            set<string> setAddr;
            for (size_t k = 0; k < vDraw.size(); k++)
            {
                vector<CDrawPlace> places;
                pooltkt::Draw(vDraw[k].hashDraw, vSeek[j], mapTickets[vDraw[k].e], nPlaces, places);
                for (size_t p = 0; p < places.size(); p++)
                    if (places[p].key.size() == 32 && places[p].key != keyOwn)
                        setAddr.insert(btf::Address(&places[p].key[0]));
            }
            mapSeek[vSeek[j]].assign(setAddr.begin(), setAddr.end());
        }
    });
    CRITICAL_BLOCK(cs_p2pool)
    {
        vGuardDrawn.clear();
        for (size_t i = 0; i < vPools.size(); i++)
        {
            map<uint256, std::pair<int, int64> >::iterator it = mapRank.find(vPools[i]);
            if (it == mapRank.end())
                continue;
            GuardDrawn g;
            g.id = vPools[i];
            g.nRank = it->second.first;
            g.nUntil = it->second.second;
            g.record = vRecords[i];
            vGuardDrawn.push_back(g);
        }
        mapGuardSeekAddr.swap(mapSeek);
        nGuardDrawSeq++;
    }
    LogPrint("p2pool", "p2pool: the draw: %u active pool(s), drawn for %u\n", (unsigned)vPools.size(), (unsigned)mapRank.size());
}

// pool-guards.dat: the pools this node keeps, each with its place and the
// height its linger ends, so a restart does not forget what it guards under
// a seed a redraw replaced (the book keeps no old seed in its file).
static const int GUARD_FILE_VERSION = 1;
static const size_t GUARD_FILE_MAX = 4 * 1024 * 1024;

struct GuardFileEntry
{
    uint256 id;
    int nRank;
    int64 nUntil;
    vector<unsigned char> record;
    IMPLEMENT_SERIALIZE
    (
        READWRITE(id);
        READWRITE(nRank);
        READWRITE(nUntil);
        READWRITE(record);
    )
};

// Under cs_p2pool: what the file keeps, copied.
static void GuardFileEntriesLocked(vector<GuardFileEntry>& v)
{
    v.clear();
    for (map<uint256, GuardEntry>::const_iterator it = mapGuard.begin(); it != mapGuard.end(); ++it)
        if (it->second.nChoice == GUARD_KEEP && v.size() < 4 * GUARD_MAX_POOLS)
        {
            GuardFileEntry f;
            f.id = it->first;
            f.nRank = it->second.nRank;
            f.nUntil = it->second.nUntil;
            f.record = it->second.record;
            v.push_back(f);
        }
}

// No lock: the bytes of that copy.
static string GuardFileBytes(const vector<GuardFileEntry>& v)
{
    CDataStream ss(SER_DISK);
    ss << GUARD_FILE_VERSION << FLATDATA(pchMessageStart) << v;
    uint256 h = Hash(ss.begin(), ss.end());
    string data(ss.begin(), ss.end());
    data.append((const char*)h.begin(), 32);
    return data;
}

static bool GuardFileRead(vector<GuardFileEntry>& out)
{
    out.clear();
    FILE* f = fopen(GuardFilePath().c_str(), "rb");
    if (!f)
        return false;
    std::vector<char> buf;
    char tmp[65536];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0 && buf.size() + n <= GUARD_FILE_MAX)
        buf.insert(buf.end(), tmp, tmp + n);
    fclose(f);
    if (buf.size() < 4 + 4 + 1 + 32)
        return false;
    uint256 hashFile = 0;
    memcpy(hashFile.begin(), &buf[buf.size() - 32], 32);
    if (Hash(buf.begin(), buf.end() - 32) != hashFile)
        return false;
    try
    {
        CDataStream ss(&buf[0], &buf[0] + buf.size() - 32, SER_DISK);
        int nVersion = 0;
        unsigned char magic[4];
        ss >> nVersion;
        if (nVersion != GUARD_FILE_VERSION)
            return false;
        ss >> FLATDATA(magic);
        if (memcmp(magic, pchMessageStart, 4) != 0)
            return false;
        ss >> out;
        if (!ss.empty() || out.size() > 4 * GUARD_MAX_POOLS)
        {
            out.clear();
            return false;
        }
    }
    catch (std::exception&)
    {
        out.clear();
        return false;
    }
    return true;
}

// Under cs_p2pool, at start: what pool-guards.dat kept. No status is taken
// from it (GuardNewPool); its place and linger end hold against the draws
// until that end (GuardApply).
static void GuardLoadLocked(const vector<GuardFileEntry>& v)
{
    foreach(const GuardFileEntry& g, v)
    {
        GuardEntry& ge = mapGuard[g.id];
        ge.nRank = g.nRank;
        ge.nUntil = g.nUntil;
        ge.record = g.record;
        ge.nFileRank = g.nRank;
        ge.nFileUntil = g.nUntil;
    }
}

// pool-tickets.dat and pool-guards.dat, when changed (at most once a
// minute) and at exit. cs_p2pool is held only to copy what they keep; the
// bytes and their hash (about 1.4 MB for three full epochs) are made at idle
// priority with no lock, and written outside.
static void TktSaveStep(int64 nNow, bool fForce)
{
    vector<CTicketFileEpoch> vTkt;
    vector<GuardFileEntry> vGuard;
    unsigned char magic[4];
    bool fTkt = false, fGuard = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (!TktActive() || !fRegFiles)
            return;
        if (fTktDirty && (fForce || nNow - nTktSavedAt >= TKT_SAVE_INTERVAL))
        {
            pooltkt::TicketFileEpochs(TktBook(), vTkt);
            memcpy(magic, TktBook().Params().magic, 4);
            fTkt = true;
            fTktDirty = false;
            nTktSavedAt = nNow;
        }
        if (fGuardSaveDirty)
        {
            GuardFileEntriesLocked(vGuard);
            fGuard = true;
            fGuardSaveDirty = false;
        }
    }
    if (!fTkt && !fGuard)
        return;
    string strTkt, strGuard;
    TktIdle([&] {
        if (fTkt)
            strTkt = pooltkt::TicketFileBytes(magic, vTkt);
        if (fGuard)
            strGuard = GuardFileBytes(vGuard);
    });
    if (fTkt)
        pooltkt::WriteTicketFileData(TktFilePath(), strTkt);
    string err;
    if (fGuard && !WriteFileAtomicPrivate(GuardFilePath(), strGuard, err))
        printf("p2pool: pool-guards.dat: %s\n", err.c_str());
}

// One pass of the ticket thread: up to nMaxVerify queued tickets hashed,
// the draw if due, a slice of this node's own ticket when nothing waited,
// the files if due. True when it hashed anything.
static bool TktStep(int64 nNow, int nMaxVerify, bool fMake)
{
    if (!TktActive())
        return false;
    int n = 0;
    bool fMore = true;
    while (fMore && n < nMaxVerify && !fTktThreadStop)
    {
        TktJob job;
        CTicketBook* pBook = NULL;
        bool fOwnVM = false;
        fMore = false;
        CRITICAL_BLOCK(cs_p2pool)
            if (tktView.nTip >= 0 && nNow >= nTktNoHashUntil && TktPickLocked(nNow, job))
            {
                pBook = &TktBook();
                fOwnVM = pBook->Params().fnWork == TktWorkOwnVM;
                fMore = true;
            }
        if (!fMore)
            break;
        if (fOwnVM)
            TktEnsureVM();
        // No lock across the hash, which runs at idle priority: the book's
        // parameters never change.
        uint256 hashWork = 0;
        int v = TICKET_DROP_NO_HASH;
        TktIdle([&] { v = pBook->Verify(job.item.t, job.item.hashSeed, hashWork); });
        CRITICAL_BLOCK(cs_p2pool)
            TktApplyLocked(job, v, hashWork, nNow);
        n++;
        if (v == TICKET_DROP_NO_HASH)
            break;
    }
    TktDrawStep(nNow);
    bool fMade = false;
    if (fMake && n == 0)
        fMade = TktMakeStep(nNow);
    TktSaveStep(nNow, false);
    return n > 0 || fMade;
}

static void ThreadPoolTickets(void* parg)
{
    // The ticket work is a few minutes of one core a day, and checks wait for
    // whatever the machine leaves: it runs on an idle-priority worker
    // (TktIdle), while this thread, at the normal priority, takes cs_p2pool
    // for its picks and copies only.
    std::thread worker;
    try
    {
        fTktIdleQuit = false;
        worker = std::thread(ThreadTktIdle);
        fTktIdleRunning = true;
    }
    catch (std::exception& e)
    {
        printf("p2pool: ticket thread: no idle worker (%s); the ticket work runs on this thread\n", e.what());
    }
    while (!fShutdown && !fTktThreadStop)
    {
        bool fBusy = false;
        try
        {
            fBusy = TktStep(GetTime(), 32, true);
        }
        catch (std::exception& e)
        {
            printf("p2pool: ticket thread: %s\n", e.what());
        }
        if (!fBusy)
            Sleep(250);
    }
    try
    {
        TktSaveStep(GetTime(), true);
    }
    catch (std::exception& e)
    {
        printf("p2pool: ticket thread: %s\n", e.what());
    }
    if (worker.joinable())
    {
        {
            std::lock_guard<std::mutex> lk(mtxTktIdle);
            fTktIdleQuit = true;
        }
        cvTktIdle.notify_all();
        worker.join();
    }
    fTktIdleRunning = false;
    fTktThreadRunning = false;
}

// ---- Guarded pools

// Under cs_p2pool: whether a peer announces the pool now.
static bool GuardAnnouncedLocked(const uint256& id)
{
    for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        if (!it->first->fDisconnect && it->second.setInv.count(id))
            return true;
    return false;
}

static void GuardNoteAnnouncedLocked(const uint256& id)
{
    map<uint256, GuardEntry>::iterator it = mapGuard.find(id);
    if (it != mapGuard.end() && it->second.fEmpty)
    {
        // It has shares now somewhere: pulled again, from that announcer.
        it->second.fEmpty = false;
        it->second.nPullSince = 0;
        it->second.line = CGuardLine();
        LogPrint("p2pool", "p2pool: guarded pool %s announced by a peer: pulling its line\n", id.GetHex().c_str());
    }
}

// Under cs_p2pool: a drawn pool joins this node to be pulled or kept. Its
// line left from an earlier run (pools/<id>.dat, a restart while it was
// guarded) is read back, so a lingering pool needs no pull. Active only if a
// draw of this run named it (the index called it active then); one known
// from pool-guards.dat alone waits for the index (RegRefreshStatus), so a
// pool retired while this node was down is neither carried nor served.
static RegPool* GuardNewPool(const uint256& id, const GuardEntry& ge)
{
    string err;
    RegPool* rp = RegNew(id, ge.record, err);
    if (!rp)
    {
        printf("p2pool: guarded pool %s: %s\n", id.GetHex().c_str(), err.c_str());
        return NULL;
    }
    if (ge.fNamed)
    {
        rp->nStatus = POOL_ACTIVE;
        rp->fStatusKnown = true;
    }
    const vector<unsigned char>& record = ge.record;
    if (fRegFiles && !rp->state.strFile.empty())
    {
        vector<unsigned char> rec;
        RegChunks v;
        if (RegReadFile(rp->state.strFile, rec, v, false) && rec == record)
        {
            RegLoadChunks(rp, v, false);
            if (!rp->state.chain->Empty())
                rp->nFetch = FETCH_COMPLETE;
        }
    }
    return rp;
}

// Under cs_p2pool, on the message thread: no longer guarded. A pool this
// node neither mines nor carries by -poolcarry gives its line back, memory
// and files, and leaves memory: what the guard budget bounds is all a
// guardian keeps, however many pools the draw names over the epochs. The
// pointer is not used after.
static void GuardRelease(RegPool* rp)
{
    if (!rp->fGuard)
        return;
    rp->fGuard = false;
    if (rp->fMined || rp->fCarry)
        return;
    LogPrint("p2pool", "p2pool: registered pool %s no longer guarded here: its line is let go\n", rp->id.GetHex().c_str());
    if (fRegFiles && !rp->state.strFile.empty())
        remove(rp->state.strFile.c_str());
    if (fRegFiles && !rp->strPart.empty())
        remove(rp->strPart.c_str());
    RegFree(rp);
}

struct GuardLineCtx
{
    map<uint256, CGuardLine> m;
};

static void GuardLineOf(void* pCtx, const uint256& id, CGuardLine& out)
{
    GuardLineCtx* ctx = (GuardLineCtx*)pCtx;
    map<uint256, CGuardLine>::const_iterator it = ctx->m.find(id);
    if (it != ctx->m.end())
        out = it->second;
}

// On the message thread, once a second: the latest draw taken in, places
// whose linger is over let go, and the guard budget run over what is known
// of each line (sections 10 and 11): kept, pulled (at most 4 at once, those
// a peer announces first), empty, or no room.
static void GuardApply(int64 nNow)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (!TktActive())
        {
            vector<RegPool*> vAll = vRegPools;
            foreach(RegPool* rp, vAll)
                GuardRelease(rp);
            mapGuard.clear();
            vGuardSeek.clear();
            return;
        }
        const int64 nTip = tktView.nTip;
        // Not while behind (TKT_TIP_STALE): the view is a syncing node's old
        // tip. What is guarded stays as it is until the node has caught up.
        if (nTip < 0 || fTktBehind)
            return;
        if (nGuardAppliedSeq != nGuardDrawSeq)
        {
            nGuardAppliedSeq = nGuardDrawSeq;
            // A pool the draw names takes its place and linger end from the
            // draws in force now (a redraw's old seed among them, until its
            // own linger end). One it no longer names keeps what it had: its
            // tickets may be gone with a reorged ticket seed, or its place
            // moved at the edge as tickets came in; it lingers to its end.
            // What pool-guards.dat gave a pool (a redraw's old seed this run
            // cannot see after a restart) holds against the draw until its
            // own linger end: the better place, the later end. Only a pool
            // the latest draw names counts as called active by the index.
            for (map<uint256, GuardEntry>::iterator it = mapGuard.begin(); it != mapGuard.end(); ++it)
                it->second.fNamed = false;
            foreach(const GuardDrawn& g, vGuardDrawn)
            {
                GuardEntry& ge = mapGuard[g.id];
                int nRank = g.nRank;
                int64 nUntil = g.nUntil;
                if (ge.nFileRank >= 0 && ge.nFileUntil > nTip)
                {
                    nRank = std::min(nRank, ge.nFileRank);
                    nUntil = std::max(nUntil, ge.nFileUntil);
                }
                ge.nRank = nRank;
                ge.nUntil = nUntil;
                ge.record = g.record;
                ge.fNamed = true;
            }
            fGuardSaveDirty = true;
        }
        // A place holds until its linger ends, whatever later draws say (a
        // redraw, a ticket set that moved at the edges): then it goes.
        for (map<uint256, GuardEntry>::iterator it = mapGuard.begin(); it != mapGuard.end();)
        {
            if (it->second.nUntil > nTip)
            {
                ++it;
                continue;
            }
            RegPool* rp = RegById(it->first);
            if (rp)
                GuardRelease(rp);
            mapGuard.erase(it++);
            fGuardSaveDirty = true;
        }
        // What is known of each line. A pool this node mines or carries by
        // -poolcarry is carried at pool zero's caps and takes nothing of the
        // guard budget.
        vector<uint256> vIds;
        vector<int> vRanks;
        GuardLineCtx ctx;
        for (map<uint256, GuardEntry>::iterator it = mapGuard.begin(); it != mapGuard.end(); ++it)
        {
            RegPool* rp = RegById(it->first);
            if (rp && (rp->fMined || rp->fCarry))
                continue;
            CGuardLine l;
            if (rp && rp->nFetch == FETCH_COMPLETE && RegLive(*rp))
            {
                l.fKnown = true;
                l.nShares = (unsigned int)rp->state.chain->Size();
                l.nBytes = (int64)rp->state.chain->Bytes();
                l.bnWork = CBigNum(rp->state.chain->TipLineWork());
                it->second.line = l;
            }
            else if (it->second.fEmpty)
                l.fKnown = true;
            else if (it->second.line.fKnown)
                l = it->second.line;
            ctx.m[it->first] = l;
            vIds.push_back(it->first);
            vRanks.push_back(it->second.nRank);
        }
        vector<CGuardDecision> vDec;
        pooltkt::ChooseGuarded(vIds, vRanks, GuardLineOf, &ctx, nGuardBudget, std::min(nGuardMaxPoolBytes, nGuardBudget),
                               nGuardMaxPools, vDec);
        size_t nPulls = 0;
        foreach(RegPool* rp, vRegPools)
            if (rp->fGuard && rp->nFetch != FETCH_COMPLETE)
                nPulls++;
        // Pulls: those a peer announces first, then the rest, at most 4 at
        // once; one nobody announces and nothing came of for 10 minutes is
        // taken as empty.
        for (int nPass = 0; nPass < 3; nPass++)
            foreach(const CGuardDecision& d, vDec)
            {
                GuardEntry& ge = mapGuard[d.poolId];
                RegPool* rp = RegById(d.poolId);
                if (nPass == 0)
                {
                    ge.nChoice = d.nChoice;
                    if (d.nChoice == GUARD_KEEP)
                    {
                        if (!rp)
                            rp = GuardNewPool(d.poolId, ge);
                        if (rp && !rp->fGuard)
                        {
                            rp->fGuard = true;
                            fGuardSaveDirty = true;
                        }
                        ge.nPullSince = 0;
                    }
                    else if (d.nChoice != GUARD_PULL && rp && rp->fGuard)
                    {
                        GuardRelease(rp);
                        fGuardSaveDirty = true;
                    }
                    else if (d.nChoice == GUARD_PULL && rp && rp->fGuard)
                    {
                        if (!ge.nPullSince)
                            ge.nPullSince = nNow;
                        if (rp->state.chain->Empty() && rp->nFetch == FETCH_IDLE && !GuardAnnouncedLocked(d.poolId) &&
                            nNow - ge.nPullSince >= GUARD_PULL_WAIT)
                        {
                            ge.fEmpty = true;
                            ge.nPullSince = 0;
                            GuardRelease(rp);
                            nPulls--;
                        }
                    }
                    continue;
                }
                if (d.nChoice != GUARD_PULL || ge.fEmpty || (rp && rp->fGuard) || nPulls >= GUARD_MAX_PULLS)
                    continue;
                if (nPass == 1 && !GuardAnnouncedLocked(d.poolId))
                    continue;
                if (!rp)
                    rp = GuardNewPool(d.poolId, ge);
                if (!rp)
                    continue;
                rp->fGuard = true;
                ge.nPullSince = nNow;
                nPulls++;
                LogPrint("p2pool", "p2pool: drawn for registered pool %s (place %d): pulling its line\n",
                         d.poolId.GetHex().c_str(), ge.nRank + 1);
            }
        // The pools this node looks for, whose 16 the draw names for the
        // dialler: the one it mines while its line is not here, and pulls
        // nobody announces.
        vector<uint256> vSeek;
        foreach(RegPool* rp, vRegPools)
            if (RegLive(*rp) && rp->nFetch != FETCH_COMPLETE &&
                (rp->fMined || rp->fCarry || (rp->fGuard && !GuardAnnouncedLocked(rp->id))))
                vSeek.push_back(rp->id);
        std::sort(vSeek.begin(), vSeek.end());
        if (vSeek != vGuardSeek)
        {
            vGuardSeek.swap(vSeek);
            fTktDrawDirty = true;
        }
    }
}

static bool fRegTickForce = false;

// On the message thread, every pass: paced serves; once a second: the
// connections gone, statuses (every 10 s), fetches, poolinv out and in.
static void RegTick()
{
    static int64 nLast = 0, nLastStatus = 0;
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_p2pool)
        if (vRegPools.empty() && mapRegConn.empty() && idMinedReg == 0 && vCarryReg.empty() && !TktActive())
            return;
    PumpRegServes();
    // Scores the ticket thread found, and the held tickets it relays, go
    // out from this thread on every pass.
    TktFlush();
    if (nNow == nLast && !fRegTickForce)
        return;
    nLast = nNow;
    CRITICAL_BLOCK(cs_p2pool)
    {
        vector<CNode*> vGone;
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
            if (it->first->fDisconnect)
                vGone.push_back(it->first);
        foreach(CNode* pnode, vGone)
            RegForgetNode(pnode);
    }
    // The chain as the tickets see it, the ticket book synced with it, and
    // the sets asked of peers (section 10).
    TktTick(nNow);
    if (nNow - nLastStatus >= REG_STATUS_SECS || fRegTickForce)
    {
        nLastStatus = nNow;
        RegRefreshStatus();
    }
    vector<RegPool*> vDone;
    CRITICAL_BLOCK(cs_p2pool)
    {
        foreach(RegPool* rp, vRegPools)
        {
            if (!RegWanted(*rp))
                continue;
            if (!RegLive(*rp))
            {
                // Not carried, not mined, not announced; a complete line
                // stays on disk in case the record comes back, a fetch in
                // progress goes once the index says the pool is not active
                // (not while it has not said yet: RegRefreshStatus).
                if (rp->nWantedSince)
                    printf("p2pool: registered pool %s is not active on this node's chain: not carried\n",
                           rp->id.GetHex().c_str());
                rp->nWantedSince = 0;
                if ((rp->nFetch == FETCH_RUNNING || rp->nFetch == FETCH_CATCHUP) && (rp->fStatusKnown || !RegOpen()))
                    RegDropFetch(rp);
                continue;
            }
            if (!rp->nWantedSince)
                rp->nWantedSince = nNow;
            if (rp->nFetch == FETCH_COMPLETE)
                continue;
            if (rp->nFetch == FETCH_RUNNING && rp->nLastNewShare && nNow - rp->nLastNewShare > REG_PART_EXPIRY)
            {
                printf("p2pool: registered pool %s: no new share for its fetch in a day; starting over\n",
                       rp->id.GetHex().c_str());
                RegDropFetch(rp);
            }
            if (RegFetchStep(rp, nNow))
                vDone.push_back(rp);
        }
    }
    foreach(RegPool* rp, vDone)
        RegComplete(rp);
    // Which drawn pools this node keeps, pulls or lets go (sections 10 and
    // 11), before poolinv says what it announces.
    GuardApply(nNow);
    CRITICAL_BLOCK(cs_p2pool)
    {
        vector<uint256> vAnn = RegAnnouncedIdsLocked();
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            CNode* p = it->first;
            RegConn& c = it->second;
            if (p->fDisconnect || p->nVersion == 0 || !(p->nServices & NODE_POOLREG))
                continue;
            if (c.fInvPending && nNow - c.nInvAppliedAt >= POOL_INV_INTERVAL)
                RegApplyInvLocked(p, c, nNow);
            if (c.vInvSent != vAnn && (c.nInvSentAt == 0 || nNow - c.nInvSentAt >= POOL_INV_INTERVAL))
            {
                PushReg(p, "poolinv", vAnn);
                c.vInvSent = vAnn;
                c.nInvSentAt = nNow;
            }
        }
    }
}

static void RegOnVersion(CNode* pfrom)
{
    if (!(pfrom->nServices & NODE_POOLREG) || pfrom->nVersion == 0 || !RegOpen())
        return;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegConn& c = RegConnOf(pfrom);
        vector<uint256> vAnn = RegAnnouncedIdsLocked();
        if (!vAnn.empty() && c.vInvSent != vAnn)
        {
            PushReg(pfrom, "poolinv", vAnn);
            c.vInvSent = vAnn;
            c.nInvSentAt = GetTime();
        }
    }
}

static bool RelayRegShare(PoolState& ps, const Share& s, CNode* pfrom)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegOf(ps);
        if (!rp)
            return false;
        if (!RegCarried(*rp))
            return true;
        ShareX x(s);
        const uint256 idShare = fShareTimeLog ? s.GetId() : uint256(0);
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            CNode* p = it->first;
            if (p != pfrom && !p->fDisconnect && p->nVersion != 0 && (p->nServices & NODE_POOLREG) &&
                it->second.setInv.count(rp->id))
            {
                ShareTimeLog("send", rp->id, idShare, (int)s.data.nShareHeight, p);
                PushReg(p, "p2xshare", rp->id, x);
            }
        }
    }
    return true;
}

bool P2PoolProbe(const uint256& idPool, vector<string>& vAskedOut, uint256& idShareOut)
{
    vAskedOut.clear();
    idShareOut = 0;
    if (!RegOpen() || idPool == RegZeroId())
        return false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegById(idPool);
        if (!rp || !RegCarried(*rp) || rp->state.chain->Empty())
            return false;
        idShareOut = rp->state.chain->Tip();
        const int nHeight = rp->state.chain->Height(idShareOut);
        vector<uint256> vIds(1, idShareOut);
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            CNode* p = it->first;
            if (p->fDisconnect || p->nVersion == 0 || !(p->nServices & NODE_POOLREG) || !it->second.setInv.count(idPool))
                continue;
            NoteAskedLocked(rp->state, vIds);
            ShareTimeLog("probe", idPool, idShareOut, nHeight, p);
            PushReg(p, "p2xgetsh", idPool, vIds);
            vAskedOut.push_back(ShareTimePeer(p));
        }
    }
    return true;
}

static bool RegEndSlowestServe()
{
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_p2pool)
    {
        std::list<RegServe>::iterator itSlow = lRegServes.end();
        int64 nSlowest = 0;
        for (std::list<RegServe>::iterator it = lRegServes.begin(); it != lRegServes.end(); ++it)
        {
            int64 nAge = nNow - it->nStart;
            if (nAge <= REG_SLOW_SERVE_AGE)
                continue;
            int64 nRate = (int64)(it->nSent / (uint64)nAge);
            if (nRate >= REG_SLOW_SERVE_RATE)
                continue;
            if (itSlow == lRegServes.end() || nRate < nSlowest)
            {
                itSlow = it;
                nSlowest = nRate;
            }
        }
        if (itSlow == lRegServes.end())
            return false;
        LogPrint("p2pool", "p2pool: a paced serve averaging %d B/s for %d s ends to free its slot\n",
                 (int)nSlowest, (int)(nNow - itSlow->nStart));
        PushPart(*itSlow->pool, itSlow->pnode, itSlow->nTipHeight, PART_ENDED_EARLY, vector<Share>());
        lRegServes.erase(itSlow);
    }
    return true;
}

// Under cs_p2pool: an ask about a pool this node does not announce, or holds
// nothing of: p2xnone, 8 an interval per connection, the rest dropped.
static void RegAnswerNoneLocked(CNode* pfrom, const uint256& id, int64 nNow)
{
    RegConn& c = RegConnOf(pfrom);
    if (nNow - c.nNoneSince >= SYNC_SERVE_INTERVAL)
    {
        c.nNoneSince = nNow;
        c.nNone = 0;
    }
    if (++c.nNone > MAX_NONE_ANSWERS)
        return;
    PushReg(pfrom, "p2xnone", id);
}

// Under cs_p2pool: other registered pools this connection was served within
// the interval.
static size_t RegServedPoolsLocked(CNode* pfrom, const RegPool* rpSelf, int64 nNow)
{
    size_t n = 0;
    foreach(RegPool* rp, vRegPools)
    {
        if (rp == rpSelf)
            continue;
        map<CNode*, PeerPool>::iterator it = rp->state.mapPeer.find(pfrom);
        if (it != rp->state.mapPeer.end() && it->second.nSyncServed && nNow - it->second.nSyncServed < SYNC_SERVE_INTERVAL)
            n++;
    }
    return n;
}

static void OnShare(PoolState& ps, CNode* pfrom, const Share& s);
static void OnGetSh(PoolState& ps, CNode* pfrom, const vector<uint256>& vIds);
static void OnSync(PoolState& ps, CNode* pfrom);
static void OnShares(PoolState& ps, CNode* pfrom, int nTipHeight, const vector<Share>& part, int nFlag);

// The registry's messages and the registered pools'. Every p2x* message,
// poolwho and poolat start with the pool id, and are decided on it before
// anything else is read: a pool this node does not carry costs one lookup
// and scores nobody (section 8).
static bool RegProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "pooltkt" || strCommand == "poolgettkt")
        return TktProcessMessage(pfrom, strCommand, vRecv);
    if (strCommand != "poolinv" && strCommand != "poolwho" && strCommand != "poolat" && strCommand != "p2xshare" &&
        strCommand != "p2xgetsh" && strCommand != "p2xsync" && strCommand != "p2xshares" && strCommand != "p2xnone")
        return false;
    // Only between peers that read the registry, and only where registered
    // pools are open (RegOpen): elsewhere every one is dropped unread, and
    // nobody is scored, answered or told who carries what.
    if (!(pfrom->nServices & NODE_POOLREG) || !RegOpen())
        return true;
    int64 nNow = GetTime();

    if (strCommand == "poolinv")
    {
        vector<uint256> v;
        vRecv >> v;
        if (v.size() > MAX_POOL_INV)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        CRITICAL_BLOCK(cs_p2pool)
        {
            RegConn& c = RegConnOf(pfrom);
            c.vInvPending = v;
            c.fInvPending = true;
            if (c.nInvAppliedAt == 0 || nNow - c.nInvAppliedAt >= POOL_INV_INTERVAL)
                RegApplyInvLocked(pfrom, c, nNow);
        }
        return true;
    }

    uint256 id;
    vRecv >> id;
    const uint256 idZero = RegZeroId();

    if (strCommand == "p2xshare")
    {
        // A pool not carried, pool zero's included (it travels on its own
        // messages only): dropped unread, unhashed, nobody scored.
        RegPool* rp = NULL;
        CRITICAL_BLOCK(cs_p2pool)
        {
            rp = RegById(id);
            if (!rp || id == idZero || !RegCarried(*rp))
                return true;
            RegPeerOf(*rp, pfrom);
        }
        ShareX s;
        vRecv >> s;
        // The id at the head must be the share's: a share naming another
        // pool than the one it is sent for is invalid, and scored as one.
        if (s.data.poolId != id)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        if (fShareTimeLog)
            ShareTimeLog("recv", id, s.GetId(), (int)s.data.nShareHeight, pfrom);
        OnShare(rp->state, pfrom, s);
        return true;
    }

    if (strCommand == "p2xgetsh" || strCommand == "p2xsync")
    {
        RegPool* rp = NULL;
        CRITICAL_BLOCK(cs_p2pool)
        {
            rp = RegById(id);
            if (!rp || id == idZero || !RegAnnounced(*rp) || rp->state.chain->Empty())
            {
                RegAnswerNoneLocked(pfrom, id, nNow);
                return true;
            }
            RegPeerOf(*rp, pfrom);
        }
        if (strCommand == "p2xgetsh")
        {
            vector<uint256> vIds;
            vRecv >> vIds;
            OnGetSh(rp->state, pfrom, vIds);
            return true;
        }
        uint256 hashResume;
        vRecv >> hashResume;
        // Per (connection, pool): at most three asks an interval, one
        // history's worth of shares (for an unproven inbound connection, in
        // its life), and at most 8 registered pools served a connection an
        // interval. Past them: dropped, silently.
        bool fDrop = false;
        CRITICAL_BLOCK(cs_p2pool)
        {
            PeerPool& peer = RegPeerOf(*rp, pfrom);
            if (nNow - peer.nAsksSince >= SYNC_SERVE_INTERVAL)
            {
                peer.nAsksSince = nNow;
                peer.nAsks = 0;
                if (PeerProven(rp->state, pfrom))
                    peer.nServedShares = 0;
            }
            if (++peer.nAsks > 3 || peer.nServedShares >= RegServeAllowance(rp->state) ||
                RegServedPoolsLocked(pfrom, rp, nNow) >= MAX_REG_SERVED_POOLS)
                fDrop = true;
            else
                peer.hashResume = hashResume;
        }
        if (!fDrop)
            OnSync(rp->state, pfrom);
        return true;
    }

    if (strCommand == "p2xshares")
    {
        // Only for a pool this node fetches or carries, from a peer it has
        // state for (OnShares then takes it only if it asked, in time); an
        // answer for a pool it stopped carrying is dropped, silently.
        RegPool* rp = NULL;
        CRITICAL_BLOCK(cs_p2pool)
        {
            rp = RegById(id);
            if (!rp || !RegActive(*rp) || !rp->state.mapPeer.count(pfrom))
                return true;
        }
        int nTipHeight;
        unsigned char nFlag;
        vector<ShareX> vx;
        vRecv >> nTipHeight >> nFlag >> vx;
        if (nFlag > PART_ENDED_EARLY)
        {
            pfrom->Misbehaving(20);
            return true;
        }
        foreach(const ShareX& s, vx)
            if (s.data.poolId != id)
            {
                pfrom->Misbehaving(20);
                return true;
            }
        // Each share of a history part as it arrives, whether or not it is
        // then taken: a fetch resumed after a restart shows here which
        // shares came again.
        if (fShareTimeLog)
            foreach(const ShareX& s, vx)
                ShareTimeLog("hist", id, s.GetId(), (int)s.data.nShareHeight, pfrom);
        vector<Share> part(vx.begin(), vx.end());
        OnShares(rp->state, pfrom, nTipHeight, part, nFlag);
        return true;
    }

    if (strCommand == "p2xnone")
    {
        CRITICAL_BLOCK(cs_p2pool)
        {
            RegPool* rp = RegById(id);
            if (!rp)
                return true;
            map<CNode*, PeerPool>::iterator it = rp->state.mapPeer.find(pfrom);
            if (it == rp->state.mapPeer.end() || it->second.nSyncAskedAt == 0)
                return true;
            // The ask is over; this peer is not asked for the pool again for
            // a while, and the fetch moves to another announcer.
            it->second.nSyncAskedAt = 0;
            RegConnOf(pfrom).mapNoneAt[id] = nNow;
            if (rp->pFetchPeer == pfrom)
            {
                rp->nAskAt = 0;
                // Nothing of the line taken yet: the fetch has not begun,
                // and a mined pool may still start its own line after its
                // grace if no announcer ever has shares.
                if (rp->nFetch == FETCH_RUNNING && rp->hashResume == 0 && rp->state.chain->Empty())
                    rp->nFetch = FETCH_IDLE;
            }
        }
        return true;
    }

    if (strCommand == "poolwho")
    {
        // Hints, as p2ppeers: the peers this node reached whose latest
        // poolinv names the pool. 8 answers an interval per connection.
        vector<string> vAt;
        CRITICAL_BLOCK(cs_p2pool)
        {
            RegConn& c = RegConnOf(pfrom);
            if (nNow - c.nWhoSince >= SYNC_SERVE_INTERVAL)
            {
                c.nWhoSince = nNow;
                c.nWho = 0;
            }
            if (++c.nWho > MAX_NONE_ANSWERS || id == idZero)
                return true;
            for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
                if (it->first != pfrom && !it->first->fDisconnect && !it->first->strBtfAddr.empty() &&
                    it->second.setInv.count(id) && vAt.size() < MAX_P2P_PEER_HINTS)
                    vAt.push_back(it->first->strBtfAddr);
            if (!vAt.empty())
                PushReg(pfrom, "poolat", id, vAt);
        }
        return true;
    }

    // poolat: only in answer to this node's poolwho for that pool, once, and
    // never passed on. A lie costs one dial.
    vector<string> vAddr;
    vRecv >> vAddr;
    if (vAddr.size() > MAX_P2P_PEER_HINTS)
    {
        pfrom->Misbehaving(20);
        return true;
    }
    bool fAsked = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegConn& c = RegConnOf(pfrom);
        map<uint256, int64>::iterator it = c.mapWhoAsked.find(id);
        if (it != c.mapWhoAsked.end())
        {
            fAsked = nNow - it->second <= POOLAT_WINDOW;
            c.mapWhoAsked.erase(it);
        }
    }
    if (fAsked && !vAddr.empty())
    {
        BtfNoteP2PoolHints(vAddr);
        // The carriers named go to the dialler for the pool this node looks
        // for (P2PoolGuardDialList), as its guardians do: the peer cache
        // above only marks addresses it already holds, and is dialled from
        // only while fewer than 3 pool zero peers are connected, so a fresh
        // node, or one with -poolguard=0, never reached a carrier named here.
        size_t nNoted = 0;
        CRITICAL_BLOCK(cs_p2pool)
        {
            RegPool* rp = RegById(id);
            if (rp && RegActive(*rp))
                foreach(const string& a, vAddr)
                {
                    if (a.empty() || a.size() > 128)
                        continue;
                    bool fHave = false;
                    for (size_t i = 0; i < rp->vHintAt.size() && !fHave; i++)
                        if (rp->vHintAt[i].first == a)
                        {
                            rp->vHintAt[i].second = nNow;
                            fHave = true;
                        }
                    if (!fHave)
                        rp->vHintAt.push_back(std::make_pair(a, nNow));
                    nNoted++;
                }
            if (rp && rp->vHintAt.size() > POOLAT_HINTS_KEPT)
            {
                std::stable_sort(rp->vHintAt.begin(), rp->vHintAt.end(), HintNewer);
                rp->vHintAt.resize(POOLAT_HINTS_KEPT);
            }
        }
        if (nNoted)
            LogPrint("p2pool", "p2pool: registered pool %s: a peer named %u carrier(s) of it; dialling them\n",
                     id.GetHex().c_str(), (unsigned)nNoted);
    }
    return true;
}

// Under cs_p2pool. Self-tests: no registered pool, no connection state; the
// nodes are the tests' own and are not touched.
static void RegResetForTest(bool fCheckPoW)
{
    fRegCheckPoW = fCheckPoW;
    fRegFiles = true;
    fRegStatusForTest = false;
    fRegTickForce = false;
    fRegIndexForTest = false;
    fRegIndexReadyForTest = false;
    mapRegIndexForTest.clear();
    foreach(RegPool* rp, vRegPools)
    {
        delete rp->state.chain;
        delete rp;
    }
    vRegPools.clear();
    mapRegById.clear();
    mapRegConn.clear();
    idMinedReg = 0;
    vCarryReg.clear();
    TktResetForTest();
}

bool P2PoolRegWant(const uint256& id, bool fMine, string& errOut)
{
    if (id == 0 || id == RegZeroId())
    {
        errOut = "pool zero is always carried, and -p2pool alone mines it";
        return false;
    }
    if (!RegOpen())
    {
        errOut = P2POOL_REG_CLOSED;
        return false;
    }
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (fMine)
            idMinedReg = id;
        else if (std::find(vCarryReg.begin(), vCarryReg.end(), id) == vCarryReg.end())
        {
            if (vCarryReg.size() >= MAX_POOL_CARRY)
            {
                errOut = "at most 8 pools may be given with -poolcarry";
                return false;
            }
            vCarryReg.push_back(id);
        }
        RegPool* rp = RegById(id);
        if (rp)
        {
            if (fMine)
            {
                rp->fMined = true;
                pPoolMined = &rp->state;
            }
            else
                rp->fCarry = true;
        }
    }
    return true;
}

void P2PoolRegWanted(vector<uint256>& out)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        out.clear();
        if (idMinedReg != 0)
            out.push_back(idMinedReg);
        out.insert(out.end(), vCarryReg.begin(), vCarryReg.end());
    }
}

bool P2PoolMinedReady(string& whyOut)
{
    bool f = true;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (idMinedReg == 0)
            return true;
        RegPool* rp = RegById(idMinedReg);
        if (!RegOpen())
        {
            whyOut = P2POOL_REG_CLOSED;
            f = false;
        }
        else if (!rp)
        {
            whyOut = "the pool this node mines is not recorded on the chain this node follows, "
                     "or the registry index has not read that far yet";
            f = false;
        }
        else if (rp->nStatus == POOL_PENDING)
        {
            whyOut = "the pool this node mines is pending: its record has fewer than 30 confirmations";
            f = false;
        }
        else if (rp->nStatus != POOL_ACTIVE)
        {
            whyOut = "the pool this node mines is not recorded on the chain this node follows";
            f = false;
        }
        else if (rp->nFetch != FETCH_COMPLETE)
        {
            whyOut = "waiting for the share chain of the pool this node mines from peers";
            f = false;
        }
    }
    return f;
}

bool P2PoolRegStatus(const uint256& id, P2PoolRegStatusInfo& out)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegById(id);
        if (rp)
        {
            out.fMined = rp->fMined;
            out.fCarry = rp->fCarry;
            out.fGuard = rp->fGuard;
            out.fCarried = RegCarried(*rp);
            out.fAnnounced = RegAnnounced(*rp);
            out.nStatus = rp->nStatus;
            out.nFetch = rp->nFetch;
            out.nShares = rp->state.chain->Size();
            out.nBytes = rp->state.chain->Bytes();
            out.nTipHeight = rp->state.chain->Height(rp->state.chain->Tip());
            out.work = rp->state.chain->TipLineWork();
            out.nAnnouncers = 0;
            for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
                if (!it->first->fDisconnect && it->second.setInv.count(id))
                    out.nAnnouncers++;
            out.nServes = 0;
            foreach(const RegServe& r, lRegServes)
                if (r.pool == &rp->state)
                    out.nServes++;
            f = true;
        }
    }
    return f;
}

bool P2PoolRegAddForTest(const poolreg::PoolRecord& rec, bool fMine, bool fCarry, bool fFiles, string& errOut)
{
    vector<unsigned char> record = rec.Encode();
    uint256 id = 0;
    poolreg::PoolId(record, (const unsigned char*)pchMessageStart, id.begin());
    if ((fMine && !P2PoolRegWant(id, true, errOut)) || (fCarry && !P2PoolRegWant(id, false, errOut)))
        return false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fRegStatusForTest = true;
        fRegFiles = fFiles;
        if (RegById(id))
            return true;
        RegPool* rp = RegNew(id, record, errOut);
        if (!rp)
            return false;
        rp->nStatus = POOL_ACTIVE;
        rp->fStatusKnown = true;
    }
    return true;
}

void P2PoolRegSetStatusForTest(const uint256& id, int nStatus)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegById(id);
        if (rp)
        {
            rp->nStatus = nStatus;
            rp->fStatusKnown = true;
        }
    }
}

void P2PoolRegIndexForTest(bool fReady, const vector<std::pair<uint256, int> >& vStatus)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fRegStatusForTest = false;
        fRegIndexForTest = true;
        fRegIndexReadyForTest = fReady;
        mapRegIndexForTest.clear();
        for (size_t i = 0; i < vStatus.size(); i++)
        {
            CPoolInfo& info = mapRegIndexForTest[vStatus[i].first];
            info.id = vStatus[i].first;
            info.nStatus = vStatus[i].second;
            RegPool* rp = RegById(vStatus[i].first);
            if (rp)
            {
                info.record = rp->record;
                info.rec = rp->rec;
            }
        }
    }
}

void P2PoolRegUseNodeIndexForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fRegStatusForTest = false;
        fRegIndexForTest = false;
    }
}

void P2PoolRegSetPartCapForTest(const uint256& id, uint64 n)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegById(id);
        if (rp)
            rp->nPartCapForTest = n;
    }
}

int P2PoolRegFetchForTest(const uint256& id)
{
    int n = -1;
    CRITICAL_BLOCK(cs_p2pool)
    {
        RegPool* rp = RegById(id);
        if (rp)
            n = rp->nFetch;
    }
    return n;
}

void P2PoolRegTickForTest()
{
    fRegTickForce = true;
    RegTick();
    fRegTickForce = false;
}

void P2PoolRegAgeForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        foreach(RegPool* rp, vRegPools)
        {
            if (rp->nAskAt) rp->nAskAt -= nSecs;
            if (rp->nLastPartAt) rp->nLastPartAt -= nSecs;
            if (rp->nCatchupAt) rp->nCatchupAt -= nSecs;
            if (rp->nRetryAt) rp->nRetryAt -= nSecs;
            if (rp->nLastNewShare) rp->nLastNewShare -= nSecs;
            if (rp->nWantedSince) rp->nWantedSince -= nSecs;
            if (rp->nWhoAt) rp->nWhoAt -= nSecs;
            for (size_t i = 0; i < rp->vHintAt.size(); i++)
                rp->vHintAt[i].second -= nSecs;
            for (map<CNode*, PeerPool>::iterator it = rp->state.mapPeer.begin(); it != rp->state.mapPeer.end(); ++it)
            {
                PeerPool& pp = it->second;
                if (pp.nSyncAskedAt) pp.nSyncAskedAt -= nSecs;
                if (pp.nLastPartAt) pp.nLastPartAt -= nSecs;
                if (pp.nSyncServed) pp.nSyncServed -= nSecs;
                if (pp.nAsksSince) pp.nAsksSince -= nSecs;
            }
        }
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            RegConn& c = it->second;
            if (c.nInvAppliedAt) c.nInvAppliedAt -= nSecs;
            if (c.nInvSentAt) c.nInvSentAt -= nSecs;
            if (c.nNoneSince) c.nNoneSince -= nSecs;
            if (c.nWhoSince) c.nWhoSince -= nSecs;
            if (c.nAskedSince) c.nAskedSince -= nSecs;
            for (map<uint256, std::pair<int64, int> >::iterator itA = c.mapAskedPool.begin(); itA != c.mapAskedPool.end(); ++itA)
                itA->second.first -= nSecs;
            for (map<uint256, int64>::iterator itW = c.mapWhoAsked.begin(); itW != c.mapWhoAsked.end(); ++itW)
                itW->second -= nSecs;
            for (map<uint256, int64>::iterator itN = c.mapNoneAt.begin(); itN != c.mapNoneAt.end(); ++itN)
                itN->second -= nSecs;
        }
        foreach(RegServe& r, lRegServes)
        {
            r.nStart -= nSecs;
            r.nLastSent -= nSecs;
        }
    }
}

void P2PoolRegAgeServeStartsForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
        foreach(RegServe& r, lRegServes)
            r.nStart -= nSecs;
}

bool P2PoolRegReloadForTest(const uint256& id, bool fForceActive)
{
    bool fWanted = false;
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_p2pool)
        {
            if (RegPool* rpOld = RegById(id))
                RegFree(rpOld);
            RegPoolsInit();
            RegPool* rp = RegById(id);
            if (rp)
            {
                // Without fForceActive, as at a real start: nothing known of
                // its status until the index says.
                if (fForceActive)
                {
                    rp->nStatus = POOL_ACTIVE;
                    rp->fStatusKnown = true;
                }
                fWanted = true;
            }
        }
    return fWanted;
}

// ---- Guardians: the node's side

void P2PoolGuardSetOptions(bool fGuard, int64 nMB, int64 nKBps)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fPoolGuard = fGuard;
        if (nMB > 0)
            nGuardBudget = nMB * 1024 * 1024;
        if (nKBps > 0)
            nRegServeRate = nKBps * 1000;
    }
}

bool P2PoolGuarding()
{
    return TktActive();
}

void P2PoolTicketsStart()
{
#ifdef BITFLASH_FUZZ
    return;
#else
    if (!TktActive() || fTktThreadRunning)
        return;
    // pool-tickets.dat is read here and checked through the ticket budget
    // like an answer, never hashed where it stands: up to 3 x 4096 hashes
    // would hold the start for minutes.
    vector<CTicketFileEpoch> vFile;
    string why;
    CTicketParams params;
    CRITICAL_BLOCK(cs_p2pool)
        params = TktBook().Params();
    bool fFile = pooltkt::LoadTicketFile(TktFilePath(), params, vFile, why);
    vector<GuardFileEntry> vGuards;
    bool fGuards = GuardFileRead(vGuards);
    // This node's .btf key: the file's own tickets are its own only if they
    // carry it (an earlier identity's are held as anybody's).
    unsigned char pubkey[32], encsk[32];
    bool fKey = BtfGetIdentity(pubkey, encsk);
    memset(encsk, 0, sizeof(encsk));
    size_t nQueued = 0;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (fKey)
        {
            memcpy(tktOwnKey, pubkey, 32);
            fTktOwnKey = true;
        }
        foreach(const CTicketFileEpoch& fe, vFile)
        {
            for (size_t j = 0; j < fe.vOwn.size() + fe.vTickets.size(); j++)
            {
                TktItem item;
                item.fOwn = j < fe.vOwn.size();
                item.t = item.fOwn ? fe.vOwn[j] : fe.vTickets[j - fe.vOwn.size()];
                item.nEpoch = fe.nEpoch;
                item.hashSeed = fe.hashSeed;
                item.nMsg = 0;
                tqFile.mapAnswer[fe.nEpoch].push_back(item);
                nQueued++;
            }
        }
        GuardLoadLocked(vGuards);
    }
    printf("p2pool: guardian tickets: %s; %u queued to be checked again; %u guarded pool(s) remembered\n",
           fFile ? "pool-tickets.dat read" : ("no pool-tickets.dat used (" + why + ")").c_str(), (unsigned)nQueued,
           fGuards ? (unsigned)vGuards.size() : 0);
    fTktThreadStop = false;
    fTktThreadRunning = true;
    if (_beginthread(ThreadPoolTickets, 0, NULL) == (uintptr_t)-1)
    {
        fTktThreadRunning = false;
        printf("Error: _beginthread(ThreadPoolTickets) failed\n");
    }
#endif
}

void P2PoolTicketsStop()
{
    fTktThreadStop = true;
    for (int i = 0; i < 300 && fTktThreadRunning; i++)
        Sleep(100);
    if (fTktThreadRunning)
        printf("p2pool: the ticket thread did not stop within 30 s\n");
}

void P2PoolGuardDialList(vector<string>& out)
{
    out.clear();
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_p2pool)
    {
        set<string> setSeen;
        // Carriers a peer named in answer to poolwho first, newest first, for
        // every pool this node wants and is live, whether or not it guards (a
        // node with -poolguard=0 finds the pool it mines through announcing
        // peers and poolwho only, section 10): each was seen announcing the
        // pool, where a guardian may hold nothing of it.
        foreach(RegPool* rp, vRegPools)
        {
            if (!RegActive(*rp))
                continue;
            vector<std::pair<string, int64> > v = rp->vHintAt;
            std::stable_sort(v.begin(), v.end(), HintNewer);
            for (size_t i = 0; i < v.size() && out.size() < GUARD_DIAL_MAX; i++)
                if (nNow - v[i].second <= POOLAT_HINT_TTL && setSeen.insert(v[i].first).second)
                    out.push_back(v[i].first);
        }
        if (!TktActive())
            return;
        foreach(const uint256& id, vGuardSeek)
        {
            map<uint256, vector<string> >::const_iterator it = mapGuardSeekAddr.find(id);
            if (it == mapGuardSeekAddr.end())
                continue;
            for (size_t i = 0; i < it->second.size() && out.size() < GUARD_DIAL_MAX; i++)
                if (setSeen.insert(it->second[i]).second)
                    out.push_back(it->second[i]);
        }
    }
}

bool P2PoolGuardians(const uint256& id, P2PoolGuardInfo& out)
{
    out = P2PoolGuardInfo();
    vector<CHeldTicket> vT;
    uint256 hashDraw = 0;
    vector<unsigned char> keyOwn;
    CRITICAL_BLOCK(cs_p2pool)
    {
        out.fGuarding = TktActive();
        if (!out.fGuarding || tktView.nTip < 0)
            return out.fGuarding;
        int c = pooltkt::EpochOf(tktView.nTip);
        out.nEpoch = c;
        uint256 hashChain, hashHeld;
        if (!pooltkt::DrawSeed(tktView, c, hashDraw, out.fSettled))
            return true;
        if (TktBuriedSeed(c, hashChain) && TktBook().Seed(c, hashHeld) && hashChain == hashHeld)
            TktBook().Tickets(c, vT);
        out.nTickets = vT.size();
        CGuardTicket own;
        uint256 w;
        if (TktBook().Own(c, own, w))
            keyOwn = own.Key();
        map<uint256, GuardEntry>::const_iterator it = mapGuard.find(id);
        if (it != mapGuard.end())
        {
            out.nOwnRank = it->second.nRank;
            out.nOwnUntil = it->second.nUntil;
            static const char* const vChoice[] = { "not drawn", "guarded", "drawn, no shares", "pulling its line",
                                                   "drawn, no room" };
            out.strOwn = vChoice[std::max(0, std::min(4, it->second.nChoice))];
            // A pool mined or carried here never enters the guard budget.
            RegPool* rp = RegById(id);
            if (rp && (rp->fMined || rp->fCarry))
                out.strOwn = "drawn; mined or carried here, outside the guard budget";
        }
    }
    vector<CDrawPlace> places;
    pooltkt::Draw(hashDraw, id, vT, GUARD_PLACES + GUARD_RESERVE, places);
    for (size_t i = 0; i < places.size(); i++)
    {
        P2PoolGuardianInfo g;
        g.strBtf = places[i].key.size() == 32 ? btf::Address(&places[i].key[0]) : string();
        g.nRank = (int)i;
        g.fSelf = !keyOwn.empty() && places[i].key == keyOwn;
        g.nCapacityMB = places[i].nCapacityMB;
        out.vGuardians.push_back(g);
    }
    return true;
}

// Self-tests and fuzz.
static void TktResetForTest()
{
    delete pTktBook;
    pTktBook = NULL;
    tktView = CTktView();
    fTktViewForTest = false;
    tqFile = TktQueues();
    tktBudget = TktBudget();
    tktServeBudget.Reset();
    nTktNoHashUntil = 0;
    nTktTurn = 0;
    fTktDirty = false;
    nTktSavedAt = 0;
    fTktDrawDirty = true;
    nTktDrawnAt = 0;
    mapTktAskRound.clear();
    setTktBuried.clear();
    nTktMakeEpoch = 0;
    hashTktMakeSeed = 0;
    nTktMakeNonce = 0;
    fTktKeyForTest = false;
    fTktPoolsForTest = false;
    vTktPoolsForTest.clear();
    vGuardDrawn.clear();
    nGuardDrawSeq = nGuardAppliedSeq = 0;
    mapGuardSeekAddr.clear();
    vGuardSeek.clear();
    mapGuard.clear();
    fGuardSaveDirty = false;
    fPoolGuard = true;
    nGuardBudget = GUARD_DEFAULT_BYTES;
    nGuardMaxPoolBytes = GUARD_MAX_POOL_BYTES;
    fTktBehind = false;
    fTktBehindForTest = false;
    fTktAnswerNext = false;
    fTktOwnKey = false;
    nGuardMaxPools = GUARD_MAX_POOLS;
    nRegServeRate = 64 * 1000;
    nTktVerifiedForTest = 0;
}

void P2PoolTicketParamsForTest(const CTicketParams& params)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        delete pTktBook;
        pTktBook = new CTicketBook(params);
    }
}

void P2PoolTicketViewForTest(const vector<uint256>& vHashes)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTktViewForTest = true;
        CTktView v;
        v.nTip = (int)vHashes.size() - 1;
        v.hashTip = vHashes.empty() ? uint256(0) : vHashes.back();
        set<int> setH;
        TktViewHeights(v.nTip, setH);
        foreach(int h, setH)
            v.mapHash[h] = vHashes[h];
        tktView = v;
        if (TktActive())
            TktSyncLocked();
    }
}

void P2PoolTicketKeyForTest(const unsigned char seckey[32])
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTktKeyForTest = seckey != NULL;
        if (seckey)
        {
            memcpy(tktKeyForTest, seckey, 32);
            fTktOwnKey = pooltkt::XOnlyPubKey(seckey, tktOwnKey);
        }
    }
}

void P2PoolTicketPoolsForTest(const vector<CPoolInfo>& v)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTktPoolsForTest = true;
        vTktPoolsForTest = v;
        fTktDrawDirty = true;
    }
}

int P2PoolTicketStepForTest(int nMaxVerify, bool fMake)
{
    uint64 nBefore;
    CRITICAL_BLOCK(cs_p2pool)
        nBefore = nTktVerifiedForTest;
    TktStep(GetTime(), nMaxVerify, fMake);
    uint64 nAfter;
    CRITICAL_BLOCK(cs_p2pool)
        nAfter = nTktVerifiedForTest;
    return (int)(nAfter - nBefore);
}

void P2PoolTicketAgeForTest(int64 nSecs)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        for (map<CNode*, RegConn>::iterator it = mapRegConn.begin(); it != mapRegConn.end(); ++it)
        {
            RegConn& c = it->second;
            for (map<unsigned int, int64>::iterator i = c.mapTktAskedAt.begin(); i != c.mapTktAskedAt.end(); ++i)
                i->second -= nSecs;
            for (map<unsigned int, int64>::iterator i = c.mapTktServedAt.begin(); i != c.mapTktServedAt.end(); ++i)
                i->second -= nSecs;
            c.nTktTallySince -= nSecs;
        }
        for (map<unsigned int, int64>::iterator i = mapTktAskRound.begin(); i != mapTktAskRound.end(); ++i)
            i->second -= nSecs;
        if (nTktNoHashUntil)
            nTktNoHashUntil -= nSecs;
        nTktDrawnAt -= nSecs;
        nTktSavedAt -= nSecs;
        tktBudget.nLast -= nSecs;
        for (map<uint256, GuardEntry>::iterator i = mapGuard.begin(); i != mapGuard.end(); ++i)
            if (i->second.nPullSince)
                i->second.nPullSince -= nSecs;
    }
}

void P2PoolTicketBudgetForTest(int nTokens)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        tktBudget.nTokens = nTokens;
        tktBudget.nLast = GetTime();
    }
}

size_t P2PoolTicketHeldForTest(unsigned int nEpoch)
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = TktBook().Held(nEpoch);
    return n;
}

bool P2PoolTicketIsHeldForTest(unsigned int nEpoch, const CGuardTicket& t)
{
    bool f = false;
    CRITICAL_BLOCK(cs_p2pool)
    {
        CHeldTicket h;
        f = TktBook().HeldByKey(nEpoch, t.PubKey(), h) && h.ticket == t;
    }
    return f;
}

bool P2PoolTicketOwnForTest(unsigned int nEpoch, CGuardTicket& out)
{
    bool f;
    uint256 w;
    CRITICAL_BLOCK(cs_p2pool)
        f = TktBook().Own(nEpoch, out, w);
    return f;
}

void P2PoolTicketQueuedForTest(CNode* pnode, unsigned int nEpoch, size_t& nRelayOut, size_t& nAnswerOut)
{
    nRelayOut = nAnswerOut = 0;
    CRITICAL_BLOCK(cs_p2pool)
    {
        const TktQueues* q = &tqFile;
        if (pnode)
        {
            map<CNode*, RegConn>::const_iterator it = mapRegConn.find(pnode);
            if (it == mapRegConn.end())
                return;
            q = &it->second.tq;
        }
        nRelayOut = q->qRelay.size();
        map<unsigned int, std::deque<TktItem> >::const_iterator itA = q->mapAnswer.find(nEpoch);
        if (itA != q->mapAnswer.end())
            nAnswerOut = itA->second.size();
    }
}

bool P2PoolTicketSaveForTest()
{
    string data;
    CRITICAL_BLOCK(cs_p2pool)
    {
        data = pooltkt::TicketFileData(TktBook());
        fTktDirty = false;
    }
    return pooltkt::WriteTicketFileData(TktFilePath(), data);
}

size_t P2PoolTicketLoadForTest()
{
    // As at a start: an empty book, the file's tickets queued as an answer.
    CTicketParams params;
    CRITICAL_BLOCK(cs_p2pool)
    {
        params = TktBook().Params();
        delete pTktBook;
        pTktBook = new CTicketBook(params);
        tqFile = TktQueues();
    }
    vector<CTicketFileEpoch> vFile;
    string why;
    if (!pooltkt::LoadTicketFile(TktFilePath(), params, vFile, why))
        return 0;
    size_t n = 0;
    CRITICAL_BLOCK(cs_p2pool)
    {
        TktSyncLocked();
        foreach(const CTicketFileEpoch& fe, vFile)
            for (size_t j = 0; j < fe.vOwn.size() + fe.vTickets.size(); j++)
            {
                TktItem item;
                item.fOwn = j < fe.vOwn.size();
                item.t = item.fOwn ? fe.vOwn[j] : fe.vTickets[j - fe.vOwn.size()];
                item.nEpoch = fe.nEpoch;
                item.hashSeed = fe.hashSeed;
                item.nMsg = 0;
                tqFile.mapAnswer[fe.nEpoch].push_back(item);
                n++;
            }
    }
    return n;
}

void P2PoolGuardLimitsForTest(int64 nBudget, int64 nMaxPoolBytes, unsigned int nMaxPools)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        nGuardBudget = nBudget;
        nGuardMaxPoolBytes = nMaxPoolBytes;
        nGuardMaxPools = nMaxPools;
    }
}

void P2PoolGuardEntriesForTest(vector<P2PoolGuardEntryInfo>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_p2pool)
        for (map<uint256, GuardEntry>::const_iterator it = mapGuard.begin(); it != mapGuard.end(); ++it)
        {
            P2PoolGuardEntryInfo e;
            e.id = it->first;
            e.nRank = it->second.nRank;
            e.nUntil = it->second.nUntil;
            e.nChoice = it->second.nChoice;
            e.fEmpty = it->second.fEmpty;
            RegPool* rp = RegById(it->first);
            e.fGuard = rp && rp->fGuard;
            out.push_back(e);
        }
}

void P2PoolGuardSaveForTest()
{
    bool fFiles;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fFiles = fRegFiles;
        fRegFiles = true;
        fGuardSaveDirty = true;
    }
    TktSaveStep(GetTime(), true);
    CRITICAL_BLOCK(cs_p2pool)
        fRegFiles = fFiles;
}

size_t P2PoolGuardLoadForTest()
{
    vector<GuardFileEntry> v;
    if (!GuardFileRead(v))
        return 0;
    CRITICAL_BLOCK(cs_p2pool)
        GuardLoadLocked(v);
    return v.size();
}

void P2PoolGuardRestartForTest()
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        // As at a start: guard-only pools leave memory (their files stay),
        // nothing drawn or remembered of the draws.
        vector<RegPool*> vAll = vRegPools;
        foreach(RegPool* rp, vAll)
        {
            if (!rp->fGuard)
                continue;
            rp->fGuard = false;
            if (!rp->fMined && !rp->fCarry)
                RegFree(rp);
        }
        mapGuard.clear();
        vGuardDrawn.clear();
        nGuardAppliedSeq = nGuardDrawSeq;
        vGuardSeek.clear();
        mapGuardSeekAddr.clear();
    }
}

void P2PoolGuardSetEntryForTest(const uint256& id, int nRank, int64 nUntil)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        map<uint256, GuardEntry>::iterator it = mapGuard.find(id);
        if (it == mapGuard.end())
            return;
        it->second.nRank = nRank;
        it->second.nUntil = nUntil;
        it->second.nChoice = GUARD_KEEP;
        fGuardSaveDirty = true;
    }
}

void P2PoolTicketBehindForTest(bool fBehind)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        fTktBehindForTest = fBehind;
        fTktBehind = fBehind;
    }
}

// ---- Messages

static void OnShare(PoolState& ps, CNode* pfrom, const Share& s)
{
    bool fGateClosed = false;
    // A pool other than zero: the tip it came to, kept with it if it is
    // held (NoteProvenWork).
    uint256 hashTipCame = 0;
    if (!ps.fZero)
    {
        CRITICAL_BLOCK(cs_p2pool)
            hashTipCame = ps.chain->Tip();
    }
    if (!ShareSane(s) || !AcceptShare(ps, s, pfrom, false, &fGateClosed, false, ps.fZero ? NULL : &hashTipCame))
        pfrom->Misbehaving(20);
    else if (fGateClosed)
        DeferShare(ps, pfrom, s, hashTipCame);
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
    // A pool other than zero: a part of at most 256 x 1024 bytes of shares,
    // unless it is a single share, which may itself be that large (section
    // 17), checked before anything of it is read further.
    if (!ps.fZero && part.size() > 1)
    {
        size_t nBytes = 0;
        foreach(const Share& s, part)
            nBytes += ::GetSerializeSize(s, SER_NETWORK);
        if (nBytes > REG_HISTORY_PART_BYTES)
        {
            pfrom->Misbehaving(20);
            return;
        }
    }
    // A history is what this node asks a peer for, not something a peer
    // may push: only from one we asked, soon after asking, and no more
    // than one history per asking.
    PeerRef peer = Peer(ps, pfrom);
    if (peer.nSyncAskedAt == 0 || GetTime() - peer.nSyncAskedAt > ps.AnswerWindow())
        return;
    // A pool other than zero comes paced: the first part within the hour,
    // then each within 5 minutes of the one before (section 17). A window
    // that has gone quiet is closed; the fetch asks again from where it is.
    if (!ps.fZero && !RegPartInWindow(ps, pfrom))
    {
        peer.nSyncAskedAt = 0;
        return;
    }
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
    bool fOk = true, fWhole = false;
    // What this part brought that was not here, as the chain keeps it: a
    // fetch writes these to its partial file, never the bytes as received.
    vector<Share> vNew;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (ps.fZero)
            fOk = ps.chain->AddHistory(part, nTipHeight, main, err);
        else
        {
            vector<uint256> vAdded;
            fOk = ps.chain->AddHistory(part, nTipHeight, main, err, &fWhole, RegOf(ps) ? &vAdded : NULL);
            Share sh;
            foreach(const uint256& id, vAdded)
                if (ps.chain->GetHeld(id, sh))
                    vNew.push_back(sh);
        }
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
    // A registered pool's fetch: the part kept in its partial file, the
    // catch-up asked after the snapshot, the line complete after that.
    if (!ps.fZero)
        RegOnPart(ps, pfrom, nTipHeight, part, vNew, nFlag, fOk, fWhole);
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
                if (it == mapLocalConn.end() || it->second.nRepliesRead >= 2 * it->second.nHellosSent)
                    return true;
                it->second.nRepliesRead++;
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
        ShareL s;
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
        vector<ShareL> vx;
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

    if (strCommand.compare(0, 3, "p2x") == 0 || strCommand.compare(0, 4, "pool") == 0)
        return RegProcessMessage(pfrom, strCommand, vRecv);

    return false;
}

bool P2PoolCommand(const string& strCommand)
{
    return strCommand.compare(0, 3, "p2p") == 0 || strCommand.compare(0, 3, "p2l") == 0 ||
           strCommand.compare(0, 3, "p2x") == 0 || strCommand.compare(0, 4, "pool") == 0;
}
