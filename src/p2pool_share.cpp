// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_share.h"

namespace p2pool
{

static const unsigned char TAG[3] = { 'p', '2', 'p' };

static bool Fail(string& errOut, const char* why)
{
    errOut = why;
    return false;
}

vector<unsigned char> CommitmentPush(const uint256& hashShareData)
{
    vector<unsigned char> v(TAG, TAG + 3);
    v.insert(v.end(), hashShareData.begin(), hashShareData.end());
    return v;
}

bool FindCommitment(const CTransaction& coinbase, uint256& hashOut)
{
    if (!coinbase.IsCoinBase())
        return false;
    const CScript& s = coinbase.vin[0].scriptSig;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    vector<unsigned char> push;
    int nFound = 0;
    while (pc < s.end())
    {
        if (!s.GetOp(pc, op, push))
            return false;
        if (push.size() == 35 && memcmp(&push[0], TAG, 3) == 0)
        {
            memcpy(hashOut.begin(), &push[3], 32);
            nFound++;
        }
    }
    // Two commitments would let one PoW count on two share chains.
    return nFound == 1;
}

CBlock Share::Header() const
{
    CBlock b;
    b.nVersion = nVersion;
    b.hashPrevBlock = hashPrevBlock;
    b.hashMerkleRoot = hashMerkleRoot;
    b.nTime = nTime;
    b.nBits = nBits;
    b.nNonce = nNonce;
    return b;
}

bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const CBigNum& bnFloor, bool& fBlockOut, string& errOut)
{
    fBlockOut = false;
    errOut.clear();
    const ShareData& d = share.data;

    if (d.vUncles.size() > MAX_UNCLES)
        return Fail(errOut, "too many uncles");
    if (d.payoutScript.empty() || d.payoutScript.size() > MAX_PAYOUT_SCRIPT)
        return Fail(errOut, "bad payout script");
    if (!share.coinbase.IsCoinBase())
        return Fail(errOut, "not a coinbase");

    // The coinbase commits to this share's chain data, and only to it.
    uint256 hashCommit;
    if (!FindCommitment(share.coinbase, hashCommit) || hashCommit != d.GetHash())
        return Fail(errOut, "the coinbase does not commit to this share");

    // The coinbase is the first transaction of the block it claims.
    if (CBlock::CheckMerkleBranch(share.coinbase.GetHash(), share.vMerkleBranch, 0) != share.hashMerkleRoot)
        return Fail(errOut, "the coinbase is not in the merkle root");

    // Targets: the share's no easier than the floor, no harder than the block.
    CBigNum bnShare, bnBlock;
    bnShare.SetCompact(d.nShareBits);
    bnBlock.SetCompact(share.nBits);
    if (bnShare <= 0 || bnShare > bnFloor)
        return Fail(errOut, "share target easier than the floor");
    if (bnShare < bnBlock)
        return Fail(errOut, "share target harder than the block's");

    uint256 hashPoW = share.Header().GetPoWHash();
    if (CBigNum(hashPoW) > bnShare)
        return Fail(errOut, "RandomX work does not meet the share target");
    fBlockOut = CBigNum(hashPoW) <= bnBlock;

    // It pays the window exactly, and pays at least the subsidy.
    int64 nTotal = 0;
    foreach(const CTxOut& o, share.coinbase.vout)
    {
        if (!MoneyRange(o.nValue))
            return Fail(errOut, "an output out of range");
        nTotal += o.nValue;
    }
    if (!MoneyRange(nTotal) || nTotal < CBlock().GetBlockValue(nBlockHeight, 0))
        return Fail(errOut, "the coinbase pays less than the subsidy");

    vector<Payout> want;
    if (!ComputePayouts(window, nTotal, want, errOut))
        return false;
    if (want.size() != share.coinbase.vout.size())
        return Fail(errOut, "the coinbase does not pay the window");
    for (size_t i = 0; i < want.size(); i++)
    {
        const CTxOut& o = share.coinbase.vout[i];
        if (o.nValue != want[i].value ||
            vector<unsigned char>(o.scriptPubKey.begin(), o.scriptPubKey.end()) != want[i].script)
            return Fail(errOut, "the coinbase does not pay the window");
    }
    return true;
}

} // namespace p2pool
