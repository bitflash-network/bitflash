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
// Nodes from before P2Pool ignore all four, as they ignore every command they
// do not know.
#ifndef BITFLASH_P2POOL_NET_H
#define BITFLASH_P2POOL_NET_H

// Include headers.h first: it has no include guard.
#include "p2pool_chain.h"

// Handles a P2Pool message; false when strCommand is not one. Called from
// ProcessMessage, under cs_main.
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

// The main chain as the share chain sees it, from the block index. Callers
// hold cs_main.
class NodeMainView : public p2pool::MainView
{
public:
    bool BlockInfo(const uint256& hash, int& nHeightOut, unsigned int& nNextBitsOut) const;
    int TipHeight() const;
    int64 Now() const;
};

#endif
