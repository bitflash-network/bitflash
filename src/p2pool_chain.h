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
// What a node hands a peer that is starting: enough of its line that the
// newest RETARGET_SHARES can be checked in full, with a whole window and a
// whole retarget behind each.
static const unsigned int HISTORY_SHARES = WINDOW_SHARES + RETARGET_SHARES + 2 * MAX_UNCLE_DEPTH + 10;
// Shares held at most, every line counted: room for several histories. Past
// it the lightest side lines are dropped, never a share refused: refusing
// made a share's validity depend on what else a node held, and two nodes
// with different side lines would have parted ways (ShareChain::Evict).
static const size_t MAX_CHAIN_SHARES = 4 * HISTORY_SHARES;
// Bytes of shares held on their work alone (AddTrusted), whose payouts are
// never checked: an honest history is a few MB.
static const size_t MAX_TRUSTED_BYTES = 64 * 1000 * 1000;
// Bytes of all shares held, every line counted. MAX_CHAIN_SHARES alone let
// side lines of shares near the size a message allows reach gigabytes. Past
// it the lightest side lines go, as past MAX_CHAIN_SHARES. What Evict never
// drops (ShareChain::Kept: the tip's line, the uncles it names, and every line
// still close to the tip in work) can by itself pass this on a network whose
// windows pay thousands of addresses; the cap then rises to what that holds
// plus half of this, so a share near the tip is never evicted the moment
// it comes and two nodes never part ways over how many bytes they hold.
static const size_t MAX_CHAIN_BYTES = 128 * 1000 * 1000;
// A side line whose newest share has at least the chain work the tip's line
// had this many shares back is still in play: a share at the tip's height an
// uncle may name, or a line about to overtake. Evict keeps it whatever the
// caps say. Deeper than MAX_UNCLE_DEPTH with room for shares in flight.
static const int NEAR_TIP_SHARES = 2 * MAX_UNCLE_DEPTH + 10;
// At most this many such lines are kept that way, the heaviest first: an
// honest network has a handful at any time, and the caps must still hold.
static const size_t MAX_NEAR_TIP_LINES = 64;
// A line whose newest share is older than this, by this node's clock, does
// not replace a livelier tip (ShareChain::Heavier).
static const int64 TIP_MAX_AGE = 30 * 60;

// A refusal that says nothing bad about the sender: the share waits on
// others not here yet, or was judged on this node's own clock or main chain
// (those start "here:").
bool InnocentRefusal(const string& err);

// What the share chain takes from outside itself: the clock, and nothing of
// the main chain. A share's validity once rested on whether a node had the
// main block it was mined on; two honest nodes, one with that block and one
// without, then judged the same share differently and parted ways for good.
// The node answers from its adjusted time; tests answer from a table.
class MainView
{
public:
    virtual ~MainView() {}
    virtual int64 Now() const = 0;
};

// Expected hashes to meet a target, capped at 2^64-1: a share's weight.
uint64_t WorkOf(unsigned int nBits);

// The block height a coinbase states in its first push (rules v2, BIP34).
bool CoinbaseHeight(const CTransaction& coinbase, int& nHeightOut);

class ShareChain
{
public:
    // fCheckPoW false skips only the RandomX check, for tests of the chain
    // logic; CheckShare's own selftest covers the work.
    // hashTip spelled out: uint256 does not zero itself, and a chain with no
    // shares must answer 0 for its tip, not whatever the memory held.
    explicit ShareChain(const CBigNum& bnFloorIn, bool fCheckPoWIn = true)
        : hashTip(0), bnFloor(bnFloorIn), fCheckPoW(fCheckPoWIn), nLastPruneCut(-10), nTrustedBytes(0), nBytes(0), nMaxBytes(MAX_CHAIN_BYTES) {}

    // Verify a share in context and keep it. A share whose parent or uncles
    // are not here is refused with their ids in *pvMissing, so the caller
    // can ask a peer for them and offer the share again: a missing share is
    // something not received yet, not something wrong.
    // A refusal that rests on this node's own view -- its clock, its main
    // chain -- starts "here:", so a peer that saw it differently is not blamed.
    // pGate, if given, is asked right before the RandomX hash (WorkGate).
    bool Add(const Share& s, const MainView& main, string& errOut,
             vector<uint256>* pvMissing = NULL, bool* pfBlock = NULL, WorkGate* pGate = NULL);

    // A share this node holds, on any line: what a peer asking for it gets.
    bool GetShare(const uint256& id, Share& out) const;

    // A share too deep in a peer's history for its own window to be here:
    // kept on its work, commitment and merkle branch alone, never on a
    // payout it cannot check. Only while the chain is being filled from a
    // peer, below the shares that are checked in full. It is never the tip:
    // the line this node mines on ends in a share checked in full.
    bool AddTrusted(const Share& s, string& errOut);

    // Part of a peer's history, oldest first, from a line whose tip is at
    // nTipHeight: the newest RETARGET_SHARES, which have a whole window and a
    // whole retarget behind them, are checked in full; the deeper ones on
    // their work alone. False on a share bad in itself; a share refused on
    // innocent grounds ends the part there, since the rest builds on it.
    bool AddHistory(const vector<Share>& part, int nTipHeight, const MainView& main, string& errOut);

    // The line behind the tip, HISTORY_SHARES deep, with the uncles it names,
    // oldest first: what a starting peer is sent.
    void History(vector<Share>& out) const;

    bool Has(const uint256& id) const { return mapShares.count(id) != 0; }
    uint256 Tip() const { return hashTip; }
    int Height(const uint256& id) const;
    size_t Size() const { return mapShares.size(); }
    // Serialized bytes of every share held, and of those held on work alone.
    size_t Bytes() const { return nBytes; }
    size_t TrustedBytes() const { return nTrustedBytes; }
    // The floor a share target may not be easier than, and whether RandomX
    // work is checked (always, outside tests).
    const CBigNum& Floor() const { return bnFloor; }
    bool CheckingPoW() const { return fCheckPoW; }
    // Self-tests only: a smaller MAX_CHAIN_BYTES, so eviction by bytes can be
    // seen without a hundred megabytes of shares.
    void SetMaxBytesForTest(size_t n) { nMaxBytes = n; }

    // What must hold between any two calls, whatever was added: the tip held
    // and checked in full, byte counts true, every share checked in full one
    // past its parent if that is held, nothing over the caps but the tip's
    // own line. False with the first broken rule (self-tests, fuzz-p2pool).
    bool CheckInvariants(string& errOut) const;

    // The share target the child of 'parent' must carry (0: the first share):
    // the floor for a chain's first RETARGET_SHARES, then the retarget.
    unsigned int NextShareBits(const uint256& parent) const;

    // The earliest time a child of 'parent' may carry: one second past the
    // median of the last 11 shares (0 for the first share).
    unsigned int NextShareMinTime(const uint256& parent) const;

    // Whether this node is still to learn the share chain: it has no tip.
    bool Empty() const { return hashTip == 0; }

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
        CBigNum bnOwnWork;     // its work and its uncles', as counted in bnChainWork
        CBigNum bnChainWork;
        bool fTrusted;         // taken on its work alone (AddTrusted)
        size_t nSize;          // serialized bytes of the share
    };
    map<uint256, Entry> mapShares;
    uint256 hashTip;
    CBigNum bnFloor;
    bool fCheckPoW;
    int nLastPruneCut;     // the cut of the last Prune pass
    size_t nTrustedBytes;  // bytes of the shares held with fTrusted
    size_t nBytes;         // bytes of every share held
    size_t nMaxBytes;      // MAX_CHAIN_BYTES outside tests
    // Shares held with fTrusted, by parent: a share checked in full drops the
    // trusted children hung on it, found here instead of by a pass over all.
    multimap<uint256, uint256> mapTrustedByParent;
    // What Evict never drops: the tip's line and the uncles it names, and
    // every line whose newest share is near the tip in work (NEAR_TIP_SHARES)
    // with the uncles it names.
    void Kept(set<uint256>& keep) const;
    // The byte cap in force: MAX_CHAIN_BYTES (nMaxBytes), or what 'keep'
    // holds plus half of it if that is more (see MAX_CHAIN_BYTES).
    size_t ByteCap(const set<uint256>& keep) const;

    const Entry* Get(const uint256& id) const;
    bool OnLine(const uint256& id, const uint256& from, int nDepth) const;
    bool UncleTaken(const uint256& uncle, const uint256& from, int nDepth) const;
    // Why 'u' may not be an uncle of a child of 'parent' at nHeight; NULL if it may.
    const char* UncleProblem(const uint256& u, const uint256& parent, int nHeight) const;
    bool AddInContext(const Share& s, const MainView& main, string& errOut,
                      vector<uint256>* pvMissing, bool* pfBlock, WorkGate* pGate);
    bool CheckUncles(const ShareData& d, const uint256& parent, int nHeight, string& errOut) const;
    // Whether the line ending at 'id' should replace the tip.
    bool Heavier(const uint256& id, int64 nNow) const;
    bool LinesMeet(const uint256& a, const uint256& b, CBigNum& bnAOut, CBigNum& bnBOut) const;
    CBigNum LineWork(const Entry* e) const;
    uint256 RootOf(const uint256& id, map<uint256, uint256>& roots) const;
    void Prune();
    // Drop side lines until there is room for nRoom more shares (see below).
    void Evict(size_t nRoom = 0, size_t nRoomBytes = 0);
    // Every share comes in through Keep and leaves through Drop, so the byte
    // counts and the trusted index stay true.
    void Keep(const uint256& id, const Entry& e);
    void Drop(const uint256& id);
};

} // namespace p2pool

#endif
