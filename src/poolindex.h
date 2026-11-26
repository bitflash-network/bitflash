// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The pool registry index (docs/pool-registry.md, sections 3, 4 and 7).
//
// The registry is a pure function of the active main chain: fold its blocks
// from genesis, in order (block, then transaction, then output), and every
// output that is a valid record (poolrecord.h) burning at least 1 BTF is an
// appearance of its pool. A pool is pending until its first appearance has 30
// confirmations, then active. Coinbase anchors ("p2p" for pool zero, "p2x"
// naming a pool) are counted as claims.
//
// Anchors naming an id nobody burned cost their miner nothing, so they are
// not kept for ever: at every height that is a multiple of 144, each id that
// is neither pool zero nor registered at that height loses its anchors more
// than 2160 blocks old. That is part of the fold, so it is the same on every
// node and after every rebuild; a pool whose record appears later has only
// the anchors of its last 2160 blocks before it. The index then grows only by
// burns, plus a bounded number of recent claims.
//
// The index is a cache of that fold, kept in pool-registry.dat. It remembers
// the last block it read (and a few before it); on each pass it walks back
// from it to the active chain, forgets everything above the fork point, and
// reads forward again. Deleting the file makes the node read the chain again
// and reach the same registry.
//
// Nothing here decides whether a block is valid, and nothing here decides
// whether a share is valid: a pool's state decides only what a node carries.

#ifndef BITFLASH_POOLINDEX_H
#define BITFLASH_POOLINDEX_H

#include <atomic>
#include "poolrecord.h"

// pool-registry.dat: a version, the registry, and the hash of both. Version
// 2 added dropped anchors and the locator.
static const int POOL_INDEX_FILE_VERSION = 2;
// A pool counts once its first appearance has this many confirmations: the
// block holding it and 29 on top.
static const int POOL_ACTIVE_CONFIRMATIONS = 30;
// Anchors are counted over this many blocks, ending at the index's tip.
static const int POOL_ANCHOR_WINDOW = 720;
// The newest anchors kept for each pool, for showing.
static const unsigned int POOL_RECENT_ANCHORS = 64;
// What the index keeps beyond what it answers, so a reorg up to this depth is
// undone exactly in place. A deeper one that would leave an answer short
// makes the index read the chain again from genesis.
static const int POOL_INDEX_REORG_MARGIN = 1440;
// The anchors of an id that is not registered: the last 2160 blocks, swept
// every 144 blocks (at heights that are multiples of 144).
static const int POOL_UNREGISTERED_ANCHOR_BLOCKS = POOL_ANCHOR_WINDOW + POOL_INDEX_REORG_MARGIN;
static const int POOL_ANCHOR_SWEEP_INTERVAL = 144;
// Block hashes the file keeps besides its tip: the last 64, and one every 144
// blocks for the margin, so a node whose block index lost its last blocks in
// an unclean stop finds where to resume instead of starting from genesis.
static const int POOL_LOCATOR_RECENT = 64;

enum PoolStatus
{
    POOL_UNKNOWN = 0,   // no appearance on the active chain
    POOL_PENDING = 1,   // its first appearance has fewer than 30 confirmations
    POOL_ACTIVE = 2,    // 30 or more, or pool zero
};

enum PoolAnchorKind
{
    POOL_ANCHOR_NONE = 0,
    POOL_ANCHOR_ZERO = 1,         // exactly one "p2p" push and no "p2x" push
    POOL_ANCHOR_REGISTERED = 2,   // exactly one "p2x" push, no "p2p" or "p2l" push
};

// Where a record was burned.
class CPoolAppearance
{
public:
    int nHeight;
    uint256 hashBlock;
    unsigned int nTx;      // the transaction's position in the block
    uint256 txid;
    unsigned int nOut;
    int64 nBurn;

    CPoolAppearance() : nHeight(-1), hashBlock(0), nTx(0), txid(0), nOut(0), nBurn(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(hashBlock);
        READWRITE(nTx);
        READWRITE(txid);
        READWRITE(nOut);
        READWRITE(nBurn);
    )

    bool operator==(const CPoolAppearance& b) const
    {
        return nHeight == b.nHeight && hashBlock == b.hashBlock && nTx == b.nTx &&
               txid == b.txid && nOut == b.nOut && nBurn == b.nBurn;
    }
};

// A main-chain block whose coinbase names a pool. A claim: anybody can put a
// "p2x" push in a solo block's coinbase.
class CPoolAnchor
{
public:
    int nHeight;
    uint256 hashBlock;
    uint256 hashShareData;
    // -1 while it counts; otherwise the sweep height that dropped it (an id
    // not registered then). Kept a while after, so a reorg can bring it back.
    int nDroppedAt;

    CPoolAnchor() : nHeight(-1), hashBlock(0), hashShareData(0), nDroppedAt(-1) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(hashBlock);
        READWRITE(hashShareData);
        READWRITE(nDroppedAt);
    )

    bool operator==(const CPoolAnchor& b) const
    {
        return nHeight == b.nHeight && hashBlock == b.hashBlock && hashShareData == b.hashShareData &&
               nDroppedAt == b.nDroppedAt;
    }
};

// A registered pool: its record and every appearance, oldest first.
class CPoolEntry
{
public:
    std::vector<unsigned char> record;
    std::vector<CPoolAppearance> vAppear;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(record);
        READWRITE(vAppear);
    )
};

// The anchors naming one pool id, oldest first: the dropped ones (if any)
// first, then the ones that count. nTrimmedTop is the height of the newest
// anchor removed from the front while it still counted (-1 when none was):
// what lets a reorg tell whether what is left still answers exactly.
class CPoolAnchorSet
{
public:
    std::vector<CPoolAnchor> v;
    int nTrimmedTop;

    CPoolAnchorSet() : nTrimmedTop(-1) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(v);
        READWRITE(nTrimmedTop);
    )
};

// A block the index read: where to resume after an unclean stop.
class CPoolLocatorEntry
{
public:
    int nHeight;
    uint256 hash;

    CPoolLocatorEntry() : nHeight(-1), hash(0) {}
    CPoolLocatorEntry(int nHeightIn, const uint256& hashIn) : nHeight(nHeightIn), hash(hashIn) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(hash);
    )
};

// What the index says about one pool.
class CPoolInfo
{
public:
    uint256 id;
    std::vector<unsigned char> record;
    poolreg::PoolRecord rec;
    bool fZero;                       // entry zero, fixed in the code
    int nStatus;                      // PoolStatus
    int nConfirmations;               // of the first appearance; 0 with none
    int nAppearances;
    CPoolAppearance first;            // nHeight -1 with none (pool zero unburned)
    std::vector<CPoolAnchor> vRecentAnchors;   // newest first, at most 64
    int nAnchorsInWindow;             // over the last 720 blocks

    CPoolInfo() : id(0), fZero(false), nStatus(POOL_UNKNOWN), nConfirmations(0), nAppearances(0),
                  nAnchorsInWindow(0) {}
};

// Which pool a coinbase's anchor counts for (section 7). The whole scriptSig
// must parse; a push is known by its data alone, whatever opcode carried it.
// idOut is the pool id for POOL_ANCHOR_REGISTERED; hashOut the share data
// hash for both kinds.
int ClassifyPoolAnchor(const CTransaction& coinbase, uint256& idOut, uint256& hashOut);

// The fold itself, in memory. Not locked: CPoolIndex below locks it.
class CPoolRegistry
{
public:
    CPoolRegistry();

    // Empty, before genesis, on the network with this message start.
    void Reset(const unsigned char magic[4]);
    bool HasMagic(const unsigned char magic[4]) const;
    bool Initialized() const { return fInit; }

    int Height() const { return nHeight; }
    uint256 TipHash() const { return hashTip; }
    // Blocks read before the tip, oldest first (the tip itself included).
    const std::vector<CPoolLocatorEntry>& Locator() const { return vLocator; }

    // Read the next block of the active chain: nHeight must be Height() + 1.
    bool ConnectBlock(const CBlock& block, int nHeightIn, const uint256& hashBlock);
    // Forget every appearance and anchor above nHeightIn, which becomes the
    // tip. False when an answer would no longer be exact (a reorg deeper than
    // the margin): the caller then reads the chain again.
    bool DisconnectAbove(int nHeightIn, const uint256& hashAt);

    uint256 ZeroId() const;
    bool IsRegistered(const uint256& id) const;
    int Status(const uint256& id) const;
    bool Lookup(const uint256& id, CPoolInfo& out) const;
    // Pool zero first, then every pool on the chain by first appearance.
    void List(std::vector<CPoolInfo>& out) const;
    bool Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const;
    // The newest anchors naming id that count (newest first, at most 64) and
    // how many fall in the last 720 blocks. Any id, registered or not.
    void Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const;
    size_t PoolCount() const { return mapPools.size(); }
    // What is kept, for the bounds: anchors stored (counting or dropped but
    // still kept for a reorg), those that count, and the ids that have any.
    size_t AnchorsStored() const;
    size_t AnchorsCounted() const;
    size_t AnchorIds() const { return mapAnchors.size(); }

    // A hash of what the registry answers (sections 3 and 7), and nothing
    // of how it is kept: two registries of the same chain give the same one.
    uint256 Digest() const;
    // Whether what was read from a file holds together. A file that does not
    // is read again from the chain.
    bool CheckConsistent(std::string& whyOut) const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(magic));
        READWRITE(nHeight);
        READWRITE(hashTip);
        READWRITE(mapPools);
        READWRITE(mapAnchors);
        READWRITE(nPurgedTop);
        READWRITE(vLocator);
        if (fRead)
            const_cast<CPoolRegistry*>(this)->fInit = true;
    )

private:
    bool fInit;
    unsigned char magic[4];
    int nHeight;
    uint256 hashTip;
    std::map<uint256, CPoolEntry> mapPools;
    std::map<uint256, CPoolAnchorSet> mapAnchors;
    // The newest sweep height whose dropped anchors were then removed for
    // good (-1 when none): a reorg below it cannot be undone exactly.
    int nPurgedTop;
    std::vector<CPoolLocatorEntry> vLocator;

    void Fill(const uint256& id, const CPoolEntry* pEntry, CPoolInfo& out) const;
    void Sweep(int nSweepHeight);
    void TrimAnchors(const uint256& id, CPoolAnchorSet& set, int nTip);
};

// How the index reads a block of the chain: from disk in the node, from
// memory in the self-test. It may return false or throw; either is a block
// that could not be read, tried again later.
typedef bool (*PoolIndexReadFn)(const CBlockIndex* pindex, CBlock& block);

// The registry kept in step with the active chain (mapBlockIndex,
// pindexBest, pnext) and in a file.
class CPoolIndex
{
public:
    explicit CPoolIndex(PoolIndexReadFn fnReadIn = NULL);

    void SetPath(const std::string& strPathIn);
    // Read the file. False when there is none or it does not hold together;
    // either way the index then starts from what it has (or genesis).
    bool Load();
    bool Save();

    // One pass: find the fork point, forget above it, read up to nMaxBlocks
    // blocks forward. Takes cs_main briefly and never holds it while reading
    // a block; ends early when the chain moves under it, or on a stop.
    // Returns how much changed (0: nothing to do, -1: a block could not be
    // read); fSyncedOut says whether the index is at the tip.
    int Step(unsigned int nMaxBlocks, bool& fSyncedOut);

    // Ends Step's reading at the next block (the thread's stop).
    void RequestStop() { fStop = true; }
    void ClearStop() { fStop = false; }
    bool Stopping() const;

    // A copy of the registry, and queries under the lock.
    CPoolRegistry Snapshot() const;
    int Height() const;
    uint256 TipHash() const;
    void Tip(int& nHeightOut, uint256& hashOut) const;
    // Tip and Rebuilding under one hold of the lock.
    void State(int& nHeightOut, uint256& hashOut, bool& fRebuildingOut) const;
    bool Lookup(const uint256& id, CPoolInfo& out) const;
    void List(std::vector<CPoolInfo>& out) const;
    int Status(const uint256& id) const;
    bool Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const;
    void Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const;
    uint256 Digest() const;
    // How many times the index started reading the chain again from genesis,
    // and whether it is doing so now. While it is, the registry it answers
    // with is the one it had, not an empty one.
    int Rebuilds() const;
    bool Rebuilding() const;

private:
    mutable CCriticalSection cs;      // reg, shadow, fShadow, nRebuilds, strPath
    CCriticalSection csStep;          // one pass at a time
    CPoolRegistry reg;                // what is answered
    CPoolRegistry shadow;             // the chain read again, while fShadow
    bool fShadow;
    std::string strPath;
    PoolIndexReadFn fnRead;
    int nRebuilds;
    bool fReadFailLogged;
    std::atomic<bool> fStop;

    void EnsureInitLocked() const;
    void StartOverLocked(const unsigned char magic[4]);
};

// The node's index, read by a thread of its own, saved in
// GetAppDir()/pool-registry.dat. Started by the node once StartNode has
// succeeded, so every path the thread runs on is a path that stops it:
// LoadBlockIndex alone (the one-shot commands, the self-tests) never starts
// it. Once per process.
void PoolIndexStart();
// Ends the thread (it saves first) and waits for it, best effort: at most
// 30 s, then a line in the log. A no-op when it never started.
void PoolIndexStop();
// Whether the thread is running (the self-test).
bool PoolIndexRunning();
CPoolIndex& PoolIndex();

// For later callers (RPCs, the pool chooser); all take only the index's lock.
bool PoolIndexLookup(const uint256& id, CPoolInfo& out);
void PoolIndexList(std::vector<CPoolInfo>& out);
int PoolIndexStatus(const uint256& id);
bool PoolIndexAppearances(const uint256& id, std::vector<CPoolAppearance>& out);
void PoolIndexAnchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow);
int PoolIndexHeight();
// Whether the index has read up to the active chain's tip.
bool PoolIndexSynced();
// Whether an output is an appearance of a pool (at least 1 BTF into
// OP_RETURN <record>, the record valid): the test the fold makes, for anyone
// who must find the same burns elsewhere (the memory pool, the wallet).
bool PoolBurnedRecord(const CTxOut& out, std::vector<unsigned char>& recordOut, poolreg::PoolRecord& recOut);
// The index's height, whether it is at the active chain's tip, and whether
// it is reading the chain again from genesis, of one moment.
void PoolIndexState(int& nHeightOut, bool& fSyncedOut, bool& fRebuildingOut);

// Registered pools on mainnet (docs/pool-registry.md, section 9). Releases
// before 1.2.36 had this false: they could neither carry nor mine a registered
// pool there, so `poolcreate everpool` refused "send" and "publishzero" on
// mainnet, every registry message was dropped unread and NODE_POOLREG was not
// said. 1.2.36 opens them, after the testnet proof of section 15, the attack
// and scale runs and the pre-mainnet review; this constant is the only change.
// Setting it back to false closes mainnet again, nothing else. Testnet is
// always open.
static const bool POOL_REGISTRY_MAINNET_OPEN = true;
// Whether this node may burn a pool record now: testnet, or mainnet once
// POOL_REGISTRY_MAINNET_OPEN is true.
bool PoolBurnsOpen();
// The self-test only: opens mainnet in this process, so the checks behind
// the gate can run with the made-up mainnet registry.
void PoolBurnsOpenForTest(bool fOpen);

#endif
