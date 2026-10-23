// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The share chain (docs/p2pool.md, step 3): the shares a node holds, which
// line it mines on, the share target, uncles, and the payout window a new
// share must pay. Everything here is decided from the shares themselves, so
// every node holding the same shares reaches the same answers.
#ifndef BITFLASH_P2POOL_CHAIN_H
#define BITFLASH_P2POOL_CHAIN_H

// Include headers.h (or headers_core.h) first: they have no include guard.
#include "p2pool_share.h"

namespace p2pool
{

static const unsigned int SHARE_SPACING = 10;       // seconds per share, across all miners
static const unsigned int SHARES_PER_BLOCK = 12;    // 120 s blocks / 10 s shares
static const unsigned int RETARGET_SHARES = 720;    // the share target looks back this far
static const int MAX_UNCLE_DEPTH = 3;               // an uncle is at most 3 shares older
static const int64 MAX_SHARE_FUTURE = 120;          // seconds a share's time may run ahead
static const int MAX_MAIN_LAG = 3;                  // main blocks a share may be mined behind
// What a node hands a peer that is starting: enough of its line that the
// newest RETARGET_SHARES can be checked in full, with a whole window and a
// whole retarget behind each.
static const unsigned int HISTORY_SHARES = WINDOW_SHARES + RETARGET_SHARES + 2 * MAX_UNCLE_DEPTH + 10;

// What the share chain needs from the main chain. The node answers from its
// block index; tests answer from a table.
class MainView
{
public:
    virtual ~MainView() {}
    // A main-chain block the node has: its height, and the nBits the block
    // after it must carry.
    virtual bool BlockInfo(const uint256& hash, int& nHeightOut, unsigned int& nNextBitsOut) const = 0;
    virtual int TipHeight() const = 0;
    virtual int64 Now() const = 0;
};

// Expected hashes to meet a target, capped at 2^64-1: a share's weight.
uint64_t WorkOf(unsigned int nBits);

// The share target of a chain's first RETARGET_SHARES shares: the block
// target made SHARES_PER_BLOCK times easier, never easier than the floor.
unsigned int ShareBitsFromMain(unsigned int nMainBits, const CBigNum& bnFloor);

class ShareChain
{
public:
    // fCheckPoW false skips only the RandomX check, for tests of the chain
    // logic; CheckShare's own selftest covers the work.
    explicit ShareChain(const CBigNum& bnFloorIn, bool fCheckPoWIn = true)
        : bnFloor(bnFloorIn), fCheckPoW(fCheckPoWIn) {}

    // Verify a share in context and keep it. A share whose parent is not
    // here is refused with *pfMissingParent set, so the caller can ask a
    // peer for the parent and offer the share again.
    // fHistory: the share comes from a peer's history, not fresh off a
    // miner, so it may sit on a main block far behind the tip.
    bool Add(const Share& s, const MainView& main, string& errOut,
             bool* pfMissingParent = NULL, bool* pfBlock = NULL, bool fHistory = false);

    // A share too deep in a peer's history for its own window to be here:
    // kept on its work, commitment and merkle branch alone, never on a
    // payout it cannot check. Only while the chain is being filled from a
    // peer, below the shares that are checked in full.
    bool AddTrusted(const Share& s, string& errOut);

    // Part of a peer's history, oldest first, from a line whose tip is at
    // nTipHeight: the newest RETARGET_SHARES, which have a whole window and a
    // whole retarget behind them, are checked in full; the deeper ones on
    // their work alone. False on a share bad in itself.
    bool AddHistory(const vector<Share>& part, int nTipHeight, const MainView& main, string& errOut);

    // The line behind the tip, HISTORY_SHARES deep, with the uncles it names,
    // oldest first: what a starting peer is sent.
    void History(vector<Share>& out) const;

    bool Has(const uint256& id) const { return mapShares.count(id) != 0; }
    uint256 Tip() const { return hashTip; }
    int Height(const uint256& id) const;
    size_t Size() const { return mapShares.size(); }

    // The share target the child of 'parent' must carry (0: the first share).
    unsigned int NextShareBits(const uint256& parent, unsigned int nMainBits) const;

    // The payout window of a share with this data and its own work: itself,
    // its uncles, and the line behind it, WINDOW_SHARES deep. An uncle counts
    // 80% of its work and the share that included it gets the other 20%.
    bool WindowFor(const ShareData& d, uint64_t nOwnWork, vector<WindowShare>& out, string& errOut) const;

    // Shares a new child of 'parent' may name as uncles.
    vector<uint256> UncleCandidates(const uint256& parent) const;

private:
    struct Entry
    {
        Share share;
        int nHeight;
        uint64_t work;
        CBigNum bnChainWork;
    };
    map<uint256, Entry> mapShares;
    uint256 hashTip;
    CBigNum bnFloor;
    bool fCheckPoW;

    const Entry* Get(const uint256& id) const;
    bool OnLine(const uint256& id, const uint256& from, int nDepth) const;
    bool UncleTaken(const uint256& uncle, const uint256& from, int nDepth) const;
    bool CheckUncles(const ShareData& d, const uint256& parent, int nHeight, string& errOut) const;
    void Prune();
};

} // namespace p2pool

#endif
