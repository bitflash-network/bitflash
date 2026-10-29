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

// What the coinbase commits to: the share chain side of a share.
struct ShareData
{
    uint256 hashPrevShare;            // 0 for the first share of a chain
    vector<uint256> vUncles;          // at most MAX_UNCLES
    unsigned int nShareHeight;
    unsigned int nShareBits;          // compact share target
    vector<unsigned char> payoutScript;

    // uint256 does not zero itself: a default ShareData starts a chain.
    ShareData() : hashPrevShare(0), nShareHeight(0), nShareBits(0) {}

    IMPLEMENT_SERIALIZE
    (
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

// Everything a share can be checked for on its own, given the payout window
// it claims to pay (the window ending with this share, step 3 builds it):
// the commitment, the merkle branch, the RandomX work against nShareBits, a
// share target no easier than bnFloor and no harder than the block's own,
// and a coinbase paying exactly ComputePayouts(window, its own total) with a
// total of at least the subsidy. On success fBlockOut says whether the work
// also meets nBits, which makes the share a Bitflash block.
// The checks that need no window: share data bounds, the commitment, the
// merkle branch, the targets and the RandomX work (unless !fCheckPoW).
bool CheckShareWork(const Share& share, const CBigNum& bnFloor, bool& fBlockOut, string& errOut,
                    bool fCheckPoW = true);

bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const CBigNum& bnFloor, bool& fBlockOut, string& errOut, bool fCheckPoW = true);

} // namespace p2pool

#endif
