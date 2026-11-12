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
    // Self-tests: empty, the next token nSecsPerToken from nNow.
    void Drain(int64 nNow) { nTokens = 0; nLast = nNow; }
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

#endif
