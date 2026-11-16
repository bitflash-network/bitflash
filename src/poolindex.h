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
// naming a registered pool) are counted as claims.
//
// The index is a cache of that fold, kept in pool-registry.dat. It remembers
// the last block it read; on each pass it walks back from it to the active
// chain, forgets everything above the fork point, and reads forward again.
// Deleting the file makes the node read the chain again and reach the same
// registry.
//
// Nothing here decides whether a block is valid, and nothing here decides
// whether a share is valid: a pool's state decides only what a node carries.

#ifndef BITFLASH_POOLINDEX_H
#define BITFLASH_POOLINDEX_H

#include "poolrecord.h"

// A pool counts once its first appearance has this many confirmations: the
// block holding it and 29 on top.
static const int POOL_ACTIVE_CONFIRMATIONS = 30;
// Anchors are counted over this many blocks, ending at the index's tip.
static const int POOL_ANCHOR_WINDOW = 720;
// The newest anchors kept for each pool, for showing.
static const unsigned int POOL_RECENT_ANCHORS = 64;
// Anchors are kept this far beyond what is shown, so a reorg up to this
// depth is undone exactly in place. A deeper one that would leave a count
// short makes the index read the chain again from genesis.
static const int POOL_INDEX_REORG_MARGIN = 1440;

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

    CPoolAnchor() : nHeight(-1), hashBlock(0), hashShareData(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(hashBlock);
        READWRITE(hashShareData);
    )

    bool operator==(const CPoolAnchor& b) const
    {
        return nHeight == b.nHeight && hashBlock == b.hashBlock && hashShareData == b.hashShareData;
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

// The anchors naming one pool id, oldest first, and the height of the newest
// one dropped from the front (-1 when none was): what lets a reorg tell
// whether what is left still answers exactly.
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

    // Read the next block of the active chain: nHeight must be Height() + 1.
    bool ConnectBlock(const CBlock& block, int nHeightIn, const uint256& hashBlock);
    // Forget every appearance and anchor above nHeightIn, which becomes the
    // tip. False when an anchor count would no longer be exact (a reorg
    // deeper than the margin): the caller then reads the chain again.
    bool DisconnectAbove(int nHeightIn, const uint256& hashAt);

    uint256 ZeroId() const;
    int Status(const uint256& id) const;
    bool Lookup(const uint256& id, CPoolInfo& out) const;
    // Pool zero first, then every pool on the chain by first appearance.
    void List(std::vector<CPoolInfo>& out) const;
    bool Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const;
    // The newest anchors naming id (newest first, at most 64) and how many
    // fall in the last 720 blocks. Any id, registered or not.
    void Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const;
    size_t PoolCount() const { return mapPools.size(); }

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

    void Fill(const uint256& id, const CPoolEntry* pEntry, CPoolInfo& out) const;
};

// How the index reads a block of the chain: from disk in the node, from
// memory in the self-test.
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
    // a block. Returns how much changed (0: nothing to do, -1: a block could
    // not be read); fSyncedOut says whether the index reached the tip.
    int Step(unsigned int nMaxBlocks, bool& fSyncedOut);

    // A copy of the registry, and queries under the lock.
    CPoolRegistry Snapshot() const;
    int Height() const;
    uint256 TipHash() const;
    bool Lookup(const uint256& id, CPoolInfo& out) const;
    void List(std::vector<CPoolInfo>& out) const;
    int Status(const uint256& id) const;
    bool Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const;
    void Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const;
    uint256 Digest() const;
    // How many times the index started again from genesis (for the
    // self-test, and the log).
    int Rebuilds() const;

private:
    mutable CCriticalSection cs;      // reg, nRebuilds
    CCriticalSection csStep;          // one pass at a time
    CPoolRegistry reg;
    std::string strPath;
    PoolIndexReadFn fnRead;
    int nRebuilds;
    bool fReadFailLogged;

    void EnsureInitLocked() const;
};

// The node's index: started at the end of LoadBlockIndex, read by a thread
// of its own, saved in GetAppDir()/pool-registry.dat.
void PoolIndexStart();
// Ends the thread (it saves first) and waits for it, at most 30 s.
void PoolIndexStop();
CPoolIndex& PoolIndex();
// False keeps LoadBlockIndex from starting the thread: the self-tests load
// block indexes of their own, and drive the index by hand.
extern bool fPoolIndexAutoStart;

// For later callers (RPCs, the pool chooser); all take only the index's lock.
bool PoolIndexLookup(const uint256& id, CPoolInfo& out);
void PoolIndexList(std::vector<CPoolInfo>& out);
int PoolIndexStatus(const uint256& id);
bool PoolIndexAppearances(const uint256& id, std::vector<CPoolAppearance>& out);
void PoolIndexAnchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow);
int PoolIndexHeight();
// Whether the index has read up to the active chain's tip.
bool PoolIndexSynced();

#endif
