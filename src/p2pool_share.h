// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// A P2Pool share (docs/p2pool.md, step 1): a block template whose RandomX
// hash meets the share chain's easier target. Its coinbase commits to the
// share chain, so the work cannot be lifted onto another chain, and pays
// the window exactly as p2pool::ComputePayouts says.
#ifndef BITFLASH_P2POOL_SHARE_H
#define BITFLASH_P2POOL_SHARE_H

// Include headers.h (or headers_core.h) first: they have no include guard.
#include "p2pool.h"

namespace p2pool
{

// What the coinbase commits to: the share chain side of a share. Pool zero's
// shares have the first form, frozen; every other pool's (a registered or a
// local pool, docs/pool-registry.md sections 6 and 18) carry the pool's id in
// front, "ShareDataX", and a local pool's also a salt after the id. One
// struct holds all three: fX and fSalt say which, are set before a share is
// read and are not themselves on the wire, so a pool zero share is the bytes
// it always was.
//
// The salt: 32 random bytes, fresh for every template, that members receive
// with the share and that never go on the chain. A local pool's coinbase
// anchor is keyed with C, which anybody holding the pool code derives from a
// guessed password; the rest of the share data is often guessable from the
// chain (a first share is the pool id, 0, no uncles, height 0, the floor and
// the one output). The salt is what keeps the anchor from testing a guess.
struct ShareData
{
    bool fX;                          // format 1: poolId is part of the data
    bool fSalt;                       // a local pool's share: salt follows poolId
    uint256 poolId;                   // the pool this share belongs to (fX)
    uint256 salt;                     // (fSalt) random, never on the chain
    uint256 hashPrevShare;            // 0 for the first share of a chain
    vector<uint256> vUncles;          // at most MAX_UNCLES
    unsigned int nShareHeight;
    unsigned int nShareBits;          // compact share target
    vector<unsigned char> payoutScript;

    // uint256 does not zero itself: a default ShareData starts a chain.
    ShareData() : fX(false), fSalt(false), poolId(0), salt(0), hashPrevShare(0), nShareHeight(0), nShareBits(0) {}

    IMPLEMENT_SERIALIZE
    (
        if (fX)
            READWRITE(poolId);
        if (fSalt)
            READWRITE(salt);
        READWRITE(hashPrevShare);
        READWRITE(vUncles);
        READWRITE(nShareHeight);
        READWRITE(nShareBits);
        READWRITE(payoutScript);
    )

    uint256 GetHash() const { return SerializeHash(*this); }
};

static const unsigned int MAX_UNCLES = 2;
static const unsigned int MAX_PAYOUT_SCRIPT = 64;
// Far past anything real, and far below where an int or a subsidy halving
// count would overflow.
static const unsigned int MAX_SHARE_HEIGHT = 1 << 30;
static const int MAX_BLOCK_HEIGHT = 10000000;

// A payout script a share may name: a P2PKH or a P2SH address, nothing else.
bool IsPayoutScript(const vector<unsigned char>& script);

// The coinbase push that carries the commitment: "p2p" and 32 bytes.
vector<unsigned char> CommitmentPush(const uint256& hashShareData);
// The commitment a coinbase carries, if it carries exactly one.
bool FindCommitment(const CTransaction& coinbase, uint256& hashOut);

struct Share
{
    // The main-chain block header it was mined as.
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CTransaction coinbase;
    vector<uint256> vMerkleBranch;    // from the coinbase (index 0) to the root
    ShareData data;

    Share() : nVersion(1), hashPrevBlock(0), hashMerkleRoot(0), nTime(0), nBits(0), nNonce(0) {}

    IMPLEMENT_SERIALIZE
    (
        // this->: IMPLEMENT_SERIALIZE has its own nVersion (the stream's),
        // which a bare nVersion here would read and write instead.
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(coinbase);
        READWRITE(vMerkleBranch);
        READWRITE(data);
    )

    CBlock Header() const;
    // The share's id: the block id its header would have.
    uint256 GetId() const { return Header().GetHash(); }
};

// A format 1 share: a Share whose data is read and written with the pool id.
// Only the constructor differs, so a vector of these reads the p2x and p2l
// messages while a vector of Share reads pool zero's.
struct ShareX : public Share
{
    ShareX() { data.fX = true; data.fSalt = false; }
    ShareX(const Share& s) : Share(s) { data.fX = true; data.fSalt = false; }
};

// A local pool's share (section 18): format 1 with the salt after the pool
// id. What the p2l messages and a local pool's file carry.
struct ShareL : public Share
{
    ShareL() { data.fX = true; data.fSalt = true; }
    ShareL(const Share& s) : Share(s) { data.fX = true; data.fSalt = true; }
};

// Which commitment a pool's coinbase carries.
enum Anchor
{
    ANCHOR_P2P = 0,     // pool zero: "p2p" and the hash of ShareData
    ANCHOR_P2X = 1,     // a registered pool: "p2x", the pool id, the hash
    ANCHOR_P2L = 2,     // a local pool: "p2l" and the hash (salt included) keyed with C
};

// Share rules v1 (docs/pool-registry.md, section 5): the code of 1.2.34 with
// its constants made parameters, plus the creator fee. Zero() is pool zero,
// which is 1.2.34 exactly.
struct PoolRules
{
    unsigned int nSpacing;            // seconds per share
    unsigned int nWindow;             // PPLNS window, shares
    unsigned int nRetarget;           // retarget window, shares
    CBigNum bnFloor;                  // no share target easier than this
    int nUncleDepth;                  // an uncle is at most this many shares older
    unsigned int nUnclePct;           // what an uncle is paid of its work
    unsigned int nFeeBps;             // creator fee, basis points
    vector<unsigned char> feeScript;  // where it is paid; empty with no fee
    int nAnchor;                      // Anchor
    uint256 poolId;                   // ANCHOR_P2X, ANCHOR_P2L
    unsigned char anchorKey[32];      // ANCHOR_P2L: the pool's key C

    PoolRules();
    static PoolRules Zero(const CBigNum& bnFloorIn);

    bool IsZero() const { return nAnchor == ANCHOR_P2P; }
    unsigned int HistoryShares() const { return nWindow + nRetarget + 2 * nUncleDepth + 10; }
    size_t MaxChainShares() const { return 4 * (size_t)HistoryShares(); }
    int NearTipShares() const { return 2 * nUncleDepth + 10; }
    int64 TipMaxAge() const { return 180 * (int64)nSpacing; }
    // Coinbase outputs at most: a window of shares with two uncles each, and
    // one more for the fee.
    size_t MaxOutputs() const { return 3 * (size_t)nWindow + (nFeeBps ? 1 : 0); }
};

// What an uncle is paid of its work, floor(work * pct / 100), exact without
// overflow. For 80 it is pool zero's work / 5 * 4 + (work % 5) * 4 / 5.
uint64_t UnclePaid(uint64_t work, unsigned int nPct);

// The payouts a share's coinbase must carry: the creator fee, floor(nTotal *
// bps / 10000), to the fee script, and the rest over the window with
// ComputePayouts; if the fee script is also in the window its two amounts are
// one output, otherwise the fee output takes its place in the order by
// script bytes, and a fee that rounds to 0 is no output. With no fee this is
// ComputePayouts.
bool ComputePoolPayouts(const PoolRules& rules, const vector<WindowShare>& window, int64 nTotal,
                        vector<Payout>& out, string& errOut);

// The push a pool's coinbase carries for this share data: 35 bytes for pool
// zero and a local pool, 67 for a registered pool.
vector<unsigned char> AnchorPush(const PoolRules& rules, const ShareData& d);
// Whether a coinbase carries this pool's commitment to this share data, and
// nothing that would let the same work count on another share chain.
bool CheckAnchor(const PoolRules& rules, const CTransaction& coinbase, const ShareData& d);

// Asked once per share, right before its RandomX hash and after every cheap
// check has passed: false refuses the share with an error that starts
// "here:", so nobody is blamed for it (a budget this node keeps on hashes it
// spends on what peers send unasked, p2pool_net.cpp). NULL: always hash.
class WorkGate
{
public:
    virtual ~WorkGate() {}
    virtual bool Allow() = 0;
};

#ifdef BITFLASH_FUZZ
// Fuzz builds only (obj-fuzz, -DBITFLASH_FUZZ; never a node or a release).
// No fuzzer can find a RandomX hash under a share target, so fuzz-p2pool sets
// this and CheckShareWork stands a cheap rule in for the hash: the work holds
// when bit 0 of nNonce is clear, and the share is also a block when bit 1 is
// set. Both outcomes stay reachable, and everything around the hash -- the
// gate above, the checks before it, the window after it -- runs as released.
extern bool fFuzzShareWorkStandIn;
#endif

// Everything a share can be checked for on its own, given the payout window
// it claims to pay (the window ending with this share, step 3 builds it):
// the commitment, the merkle branch, the RandomX work against nShareBits, a
// share target no easier than bnFloor, and a coinbase paying exactly
// ComputePayouts(window, its own total) with a total of at least the subsidy
// at nBlockHeight. On success fBlockOut says whether the work also meets the
// nBits the share states, which would make it a Bitflash block; nothing else
// is checked against that nBits.
// The checks that need no window: share data bounds, the payout script, the
// coinbase's own rules, the commitment, the merkle branch, the target and the
// RandomX work (unless !fCheckPoW).
bool CheckShareWork(const Share& share, const PoolRules& rules, bool& fBlockOut, string& errOut,
                    bool fCheckPoW = true, WorkGate* pGate = NULL);

bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const PoolRules& rules, bool& fBlockOut, string& errOut, bool fCheckPoW = true,
                WorkGate* pGate = NULL);

// Pool zero's rules with this floor: what every caller meant before pools
// had parameters.
bool CheckShareWork(const Share& share, const CBigNum& bnFloor, bool& fBlockOut, string& errOut,
                    bool fCheckPoW = true, WorkGate* pGate = NULL);
bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const CBigNum& bnFloor, bool& fBlockOut, string& errOut, bool fCheckPoW = true,
                WorkGate* pGate = NULL);

// The refusal a closed WorkGate gives.
static const char* const WORK_GATE_CLOSED = "here: too many shares to hash from unproven peers just now";

} // namespace p2pool

#endif
