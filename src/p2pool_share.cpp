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

bool CheckShareWork(const Share& share, const CBigNum& bnFloor, bool& fBlockOut, string& errOut,
                    bool fCheckPoW)
{
    fBlockOut = false;
    errOut.clear();
    const ShareData& d = share.data;

    if (d.vUncles.size() > MAX_UNCLES)
        return Fail(errOut, "too many uncles");
    // Counted once in the chain's work, not once per mention: a history taken
    // on work alone summed a doubled uncle twice, and outweighed honest lines.
    for (size_t i = 0; i < d.vUncles.size(); i++)
        for (size_t j = i + 1; j < d.vUncles.size(); j++)
            if (d.vUncles[i] == d.vUncles[j])
                return Fail(errOut, "an uncle named twice");
    // An address, nothing else. Every payout script of the window becomes an
    // output of every template's coinbase, so a script of 64 OP_CHECKMULTISIG
    // -- 1280 signature operations as a block counts them -- named by a few
    // shares put every P2Pool block over MAX_BLOCK_SIGOPS for six hours.
    if (!IsPayoutScript(d.payoutScript))
        return Fail(errOut, "bad payout script");
    // Heights far past anything real only make for arithmetic that overflows.
    if (d.nShareHeight > MAX_SHARE_HEIGHT)
        return Fail(errOut, "share height out of range");
    if (!share.coinbase.IsCoinBase())
        return Fail(errOut, "not a coinbase");
    // The rules any block's coinbase meets, the 100-byte scriptSig among
    // them: what the window fixes is the outputs, and a share padded
    // anywhere else would be kept at whatever size its sender chose.
    if (!share.coinbase.CheckTransaction())
        return Fail(errOut, "a coinbase no block could carry");

    // The coinbase commits to this share's chain data, and only to it.
    uint256 hashCommit;
    if (!FindCommitment(share.coinbase, hashCommit) || hashCommit != d.GetHash())
        return Fail(errOut, "the coinbase does not commit to this share");

    // The coinbase is the first transaction of the block it claims.
    if (CBlock::CheckMerkleBranch(share.coinbase.GetHash(), share.vMerkleBranch, 0) != share.hashMerkleRoot)
        return Fail(errOut, "the coinbase is not in the merkle root");

    // The share's target no easier than the floor. Nothing is checked against
    // nBits, which the share states for itself: a share whose validity rested
    // on it either let anybody pick an easy one, or rested on whether a node
    // had that main block -- and two honest nodes, one with it and one
    // without, parted ways for good.
    CBigNum bnShare, bnBlock;
    bnShare.SetCompact(d.nShareBits);
    bnBlock.SetCompact(share.nBits);
    if (bnShare <= 0 || bnShare > bnFloor)
        return Fail(errOut, "share target easier than the floor");

    if (fCheckPoW)
    {
        uint256 hashPoW = share.Header().GetPoWHash();
        if (CBigNum(hashPoW) > bnShare)
            return Fail(errOut, "RandomX work does not meet the share target");
        // A block only if it is one by its own nBits; whether the main chain
        // takes it is for the main chain to say.
        fBlockOut = bnBlock > 0 && CBigNum(hashPoW) <= bnBlock;
    }
    return true;
}

bool IsPayoutScript(const vector<unsigned char>& s)
{
    // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if (s.size() == 25 && s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 &&
        s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG)
        return true;
    // OP_HASH160 <20> OP_EQUAL (a treasury or other P2SH address)
    if (s.size() == 23 && s[0] == OP_HASH160 && s[1] == 20 && s[22] == OP_EQUAL)
        return true;
    return false;
}

bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const CBigNum& bnFloor, bool& fBlockOut, string& errOut, bool fCheckPoW)
{
    if (!CheckShareWork(share, bnFloor, fBlockOut, errOut, fCheckPoW))
        return false;
    if (nBlockHeight < 1 || nBlockHeight > MAX_BLOCK_HEIGHT)
        return Fail(errOut, "block height out of range");

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
