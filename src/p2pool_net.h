// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The share chain on the wire (docs/p2pool.md, step 4). Every node keeps and
// relays the share chain, mining or not: checking one share every ten seconds
// costs next to nothing, and shares then reach every miner however few of
// them happen to be connected to each other.
//
// Messages, over the same Tor-only connections as blocks:
//   p2pshare   one share, fresh off a miner or relayed
//   p2pgetsh   vector<uint256>: send me these shares
//   p2psync    (empty): send me your line, I am starting
//   p2pshares  int tip height, vector<Share>: part of a line, oldest first
//   p2ppeers   vector<string>: .btf addresses of peers we reached that hold
//              the share chain (hints for a miner looking for such peers)
// All of them go only to peers that say NODE_P2POOL; nodes from before P2Pool
// would ignore them, as they ignore every command they do not know.
#ifndef BITFLASH_P2POOL_NET_H
#define BITFLASH_P2POOL_NET_H

// Include headers.h first: it has no include guard.
#include "p2pool_chain.h"

// Handles a P2Pool message; false when strCommand is not one. Called from
// ProcessMessages without cs_main (it takes cs_p2pool, and never cs_main
// inside it: the template code takes cs_main first).
bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv);

// After the version handshake: ask the peer for its line if ours is empty.
void P2PoolOnVersion(CNode* pfrom);

// A share this node's own miner found: keep it and send it to every peer.
bool P2PoolSubmitShare(const p2pool::Share& share, string& errOut, bool* pfBlock = NULL);

// The share chain, under cs_p2pool. Created on first use.
extern CCriticalSection cs_p2pool;
p2pool::ShareChain& P2PoolChain();

// At startup, once the block index is loaded: read the share chain this node
// saved in p2pool.dat (every two minutes while it runs).
void P2PoolInit();

// What the share chain takes from the node: its adjusted clock.
class NodeMainView : public p2pool::MainView
{
public:
    int64 Now() const;
};

// Whether this node should hold back templates: it has no share chain yet
// and has just asked a peer for one. Mining meanwhile would start a chain of
// its own at height 0. Under cs_p2pool.
bool P2PoolAwaitingHistory();

// A token bucket: up to nCapacity tokens, one more every nSecsPerToken
// seconds. What this code spends on behalf of peers that have not shown
// they are honest -- a RandomX hash, a history sent or asked for -- is drawn
// from one of these, shared by every such peer: a budget per connection is
// reset by reconnecting, which an inbound onion peer does for free.
class P2PoolBudget
{
public:
    P2PoolBudget(int nCapacityIn, int64 nSecsPerTokenIn)
        : nCapacity(nCapacityIn), nSecsPerToken(nSecsPerTokenIn), nTokens(nCapacityIn), nLast(0) {}
    bool Take(int64 nNow);
    int Tokens(int64 nNow);
    void Reset() { nTokens = nCapacity; nLast = 0; }
    // Self-tests: nLeft tokens (none by default), the next one
    // nSecsPerToken from nNow.
    void Drain(int64 nNow, int nLeft = 0) { nTokens = nLeft; nLast = nNow; }
private:
    void Refill(int64 nNow);
    int nCapacity;
    int64 nSecsPerToken;
    int nTokens;
    int64 nLast;
};

// Whether a peer's word has been worth something on this connection: one we
// dialled, or one that sent a share this node took. Such peers do not draw
// on the shared budgets above.
bool P2PoolPeerProven(const CNode* pnode);

// Self-tests only: forget every share, orphan, budget and ask, and start an
// empty share chain with this floor (fCheckPoW false skips the RandomX hash,
// as ShareChain's own tests do).
void P2PoolResetForTest(const CBigNum& bnFloor, bool fCheckPoW);
// Self-tests and fuzz-p2pool: shares waiting for parents, the budgets'
// tokens left.
size_t P2PoolOrphanCount();
int P2PoolShareWorkTokens();
int P2PoolHistoryServeTokens();
int P2PoolHistoryAskTokens();
// Self-tests only: make every queued orphan this many seconds older.
void P2PoolAgeOrphansForTest(int64 nSecs);

// Shares and history asks of unproven peers that the shared budgets refused
// are held, one of each per connection, and served here as the budgets
// refill, the oldest connection first. Called on every pass of the message
// thread, after every peer's messages.
void P2PoolServeDeferred();
// Connections held for that (each referenced until served or cut off).
size_t P2PoolDeferredCount();
// Self-tests and fuzz-p2pool, whose peers are not in vNodes and are freed by
// the test: drop what is held for this one (and its reference).
void P2PoolForgetDeferred(CNode* pnode);
// Self-tests and fuzz-p2pool: every shared budget full again.
void P2PoolRefillBudgetsForTest();
// Self-tests: every shared budget empty, the next token a full period away.
void P2PoolDrainBudgetsForTest();

// ---- Pools other than pool zero (docs/pool-registry.md, sections 8 and 18)
//
// Pool zero keeps the budgets, the orphan queue and the held entries above
// to itself. Every other pool this node is in spends from one second set of
// the same shape, the registered class, so nothing done with those pools
// changes how pool zero's traffic is treated.
//
// A local pool's messages, between members only, after a hello that proves
// membership to the onion that was dialled:
//   p2lhello   32-byte nonce, 16-byte tag: the hello, and the answer to it
//   p2lack     32 bytes: the initiator's proof; the session is open
//   p2lshare   handle, ShareL (format 1 with the salt)
//   p2lgetsh   handle, vector<uint256>
//   p2lsync    handle, uint256 (a share to resume from, or 0)
//   p2lshares  handle, int tip height, end flag, vector<ShareL>
// The handle is the session's 8 bytes; the pool id is never on the wire. A
// hello that matches no pool of this node, and a handle it does not hold on
// that connection, get silence, and nobody is scored for them.

// The share chain this node's miners work on: pool zero's, or the local
// pool's that P2PoolLocalMine named. Under cs_p2pool.
p2pool::ShareChain& P2PoolMinedChain();
// A number that changes whenever a share joins that chain: the stratum
// checks then whether the uncles its job names are still the ones the next
// share could name (docs/pool-registry.md, section 9).
uint64 P2PoolMinedChainSeq();

// A local pool joins this node (at most poollocal::MAX_LOCAL_POOLS, one per
// name). strFile is where its share chain is kept between runs; empty keeps
// it in memory only. fCheckPoW false is for self-tests. Nothing is written:
// P2PoolLocalJoin is what poolcreate and pooljoin use.
bool P2PoolLocalAdd(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, const string& strFile,
                    bool fCheckPoW, string& errOut);
// A local pool joins this node for good: its file pools/local/<id>.conf is
// written owner-only (the record, K and the listed peers, never the
// password), it comes back from there on every start (P2PoolInit), and a
// share chain left in pools/local/<id>.dat is read. The keys come from
// poollocal::Derive, whose Argon2id run the caller makes before, outside
// every lock. Takes cs_p2pool only (never cs_main), and reads a share
// chain left in the file outside every lock. Errors name no file.
bool P2PoolLocalJoin(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, string& errOut);
// Read its saved share chain, once the block index is loaded.
bool P2PoolLocalLoad(const string& strName);
// The members' nodes this one dials and says hello to, each
// ADDRESS@HOST.onion[:PORT]; at most poollocal::MAX_LISTED_PEERS. Saved in
// the pool's file.
bool P2PoolLocalSetPeers(const string& strName, const vector<string>& vPeers, string& errOut);
// Forget a local pool: its sessions close and its files go on the next
// pass of the message thread. Refused while this node mines it.
bool P2PoolLocalLeave(const string& strName, string& errOut);
// Mine this local pool instead of pool zero (-p2pool=local:<name>); at
// startup, before any template is built.
bool P2PoolLocalMine(const string& strName, string& errOut);
// What -p2pool=<value> asks to mine (docs/pool-registry.md, section 9):
// pool zero (true, strLocalOut empty: no value, any value that is not a
// pool id, or pool zero's own id), a local pool (true, its name, from
// "local:<name>"), or nothing a node may start with (false, and why: an
// Everpool pool's id, which this release cannot mine yet, or 40 to 80 hex
// digits that are not 64, a mistyped id). The value is never echoed back.
bool P2PoolParseChoice(const string& strValue, string& strLocalOut, string& errOut);
struct P2PoolLocalStatusInfo
{
    enum
    {
        PEER_NOT_CONNECTED = 0, // no connection this node dialled to it
        PEER_CONNECTED,         // dialled, no hello sent on it yet
        PEER_NO_PROOF,          // a hello went, and no session came of it
        PEER_OUR_CAP,           // this node is at its session cap for the pool
        PEER_SESSION,           // in session
    };
    poolreg::PoolRecord rec;
    size_t nSessions;       // members in session with this node
    size_t nInboundSessions;
    size_t nPending;        // hellos answered and not acked yet
    size_t nShares;
    int nTipHeight;
    vector<string> vPeers;
    vector<int> vPeerState; // one of the above per listed peer
    bool fMined;
    bool fAtCap;
};
bool P2PoolLocalStatus(const string& strName, P2PoolLocalStatusInfo& out);
// The names of this node's local pools.
void P2PoolLocalNames(vector<string>& out);
// Every peer some local pool of this node lists, once each.
void P2PoolLocalDialList(vector<string>& out);
// Whether some local pool of this node (not one being left) still lists
// that peer. Takes cs_p2pool: callers may hold cs_vNodes, not the other way.
bool P2PoolLocalStillListed(const string& strPeer);

// Self-tests: the onions this node answers hellos for, the registered
// class's counters, and its budgets emptied.
void P2PoolSetOwnOnionsForTest(const vector<string>& v);
size_t P2PoolRegisteredOrphanCount();
int P2PoolRegisteredShareWorkTokens();
size_t P2PoolRegisteredServesForTest();
void P2PoolDrainRegisteredBudgetsForTest();
// Self-tests: n bytes queued on a connection as a message of a pool other
// than zero; the bytes of such messages still queued (and the stretches
// kept to count them).
void P2PoolQueueRegBytesForTest(CNode* pnode, size_t n);
size_t P2PoolRegQueuedForTest(CNode* pnode, size_t* pnSpans = NULL);
// Self-tests: the bytes the paced serves in flight hold for their snapshots,
// and the next share of each made to be one the chain no longer holds.
size_t P2PoolRegServeHeldBytesForTest();
void P2PoolRegServeLoseNextForTest();
// Self-tests: the budgets for proven peers' shares in local pools (each
// pool's and each session's) emptied or refilled, and the connections the
// registered class holds a share or an ask for.
void P2PoolDrainProvenWorkForTest(bool fPools, bool fSessions);
void P2PoolRefillProvenWorkForTest();
size_t P2PoolRegisteredDeferredCount();
// Self-tests: a local pool's budget for its proven peers set to n tokens; a
// session's count of wasted tokens set, and read (-1 with no session); a
// session's own tokens (-1 with no session); the connections a local pool
// keeps state for; whether this node asked a local pool's members for a
// share lately.
bool P2PoolLocalSetPoolTokensForTest(const string& strName, int n);
bool P2PoolLocalSetWorkDebtForTest(const string& strName, CNode* pnode, int nDebt);
int P2PoolLocalWorkDebtForTest(const string& strName, CNode* pnode);
int P2PoolLocalSessionTokensForTest(const string& strName, CNode* pnode);
size_t P2PoolLocalPeerEntriesForTest(const string& strName);
bool P2PoolLocalAskedForTest(const string& strName, const uint256& id);
bool P2PoolLocalNoteAskedForTest(const string& strName, const uint256& id);
// Self-tests: the hellos sent and read on a connection made nSecs older.
void P2PoolLocalAgeHelloForTest(CNode* pnode, int64 nSecs);
// Self-tests: the message thread's check of one connection for a listed
// peer reached at another onion than the one listed (true: dropped), and
// the drops made so far made nSecs older.
bool P2PoolLocalDropWrongOnionForTest(CNode* pnode);
void P2PoolLocalAgeWrongOnionDropsForTest(int64 nSecs);

#endif
