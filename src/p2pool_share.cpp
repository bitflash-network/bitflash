// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_share.h"
#include "poollocal.h"

namespace p2pool
{

static const unsigned char TAG[3] = { 'p', '2', 'p' };
static const unsigned char TAG_X[3] = { 'p', '2', 'x' };
static const unsigned char TAG_L[3] = { 'p', '2', 'l' };

static bool Fail(string& errOut, const char* why)
{
    errOut = why;
    return false;
}

vector<unsigned char> CommitmentPush(const uint256& hashShareData)
{
    // uint256's begin() is not const; clang will not call it on a const one.
    uint256 h = hashShareData;
    vector<unsigned char> v(TAG, TAG + 3);
    v.insert(v.end(), h.begin(), h.end());
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

PoolRules::PoolRules()
    : nSpacing(0), nWindow(0), nRetarget(0), bnFloor(0), nUncleDepth(0), nUnclePct(0), nFeeBps(0),
      nAnchor(ANCHOR_P2P), poolId(0)
{
    memset(anchorKey, 0, sizeof(anchorKey));
}

uint64_t UnclePaid(uint64_t work, unsigned int nPct)
{
    return work / 100 * nPct + (work % 100) * nPct / 100;
}

vector<unsigned char> AnchorPush(const PoolRules& rules, const ShareData& d)
{
    uint256 h = d.GetHash();
    if (rules.nAnchor == ANCHOR_P2L)
        return poollocal::AnchorData(rules.anchorKey, h.begin());
    if (rules.nAnchor == ANCHOR_P2X)
    {
        uint256 id = rules.poolId;
        vector<unsigned char> v(TAG_X, TAG_X + 3);
        v.insert(v.end(), id.begin(), id.end());
        v.insert(v.end(), h.begin(), h.end());
        return v;
    }
    return CommitmentPush(h);
}

// Sections 6 and 18: the whole scriptSig parses, it carries exactly one
// commitment of this pool to this share data, and no commitment of any other
// kind. A push is known by its data alone, whatever opcode carried it.
static bool CheckAnchorX(const PoolRules& rules, const CTransaction& coinbase, const ShareData& d)
{
    if (!coinbase.IsCoinBase())
        return false;
    const CScript& s = coinbase.vin[0].scriptSig;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    vector<unsigned char> push;
    int nOwn = 0;
    uint256 h = d.GetHash();
    uint256 id = rules.poolId;
    while (pc < s.end())
    {
        if (!s.GetOp(pc, op, push))
            return false;
        bool fP2P = push.size() == 35 && memcmp(&push[0], TAG, 3) == 0;
        bool fP2L = push.size() == 35 && memcmp(&push[0], TAG_L, 3) == 0;
        bool fP2X = push.size() == 67 && memcmp(&push[0], TAG_X, 3) == 0;
        if (fP2P)
            return false;
        if (rules.nAnchor == ANCHOR_P2L)
        {
            if (fP2X)
                return false;
            if (fP2L)
            {
                if (!poollocal::AnchorMatches(push, rules.anchorKey, h.begin()))
                    return false;
                nOwn++;
            }
        }
        else
        {
            if (fP2L)
                return false;
            if (fP2X)
            {
                if (memcmp(&push[3], id.begin(), 32) != 0 || memcmp(&push[35], h.begin(), 32) != 0)
                    return false;
                nOwn++;
            }
        }
    }
    return nOwn == 1;
}

bool CheckAnchor(const PoolRules& rules, const CTransaction& coinbase, const ShareData& d)
{
    if (rules.IsZero())
    {
        // Pool zero's rule, frozen: exactly one "p2p" push, whatever else.
        uint256 hashCommit;
        return !d.fX && FindCommitment(coinbase, hashCommit) && hashCommit == d.GetHash();
    }
    // A share of another pool names that pool, and never pool zero's form.
    if (!d.fX || d.poolId != rules.poolId || rules.poolId == 0)
        return false;
    return CheckAnchorX(rules, coinbase, d);
}

bool ComputePoolPayouts(const PoolRules& rules, const vector<WindowShare>& window, int64 nTotal,
                        vector<Payout>& out, string& errOut)
{
    if (rules.nFeeBps == 0)
        return ComputePayouts(window, nTotal, out, errOut);
    if (nTotal < 0 || !MoneyRange(nTotal) || rules.nFeeBps > 10000 || !IsPayoutScript(rules.feeScript))
        return Fail(errOut, "a creator fee that cannot be paid");
    // floor(nTotal * bps / 10000), split so the product cannot overflow.
    int64 nFee = nTotal / 10000 * (int64)rules.nFeeBps + (nTotal % 10000) * (int64)rules.nFeeBps / 10000;
    if (!ComputePayouts(window, nTotal - nFee, out, errOut))
        return false;
    if (nFee == 0)
        return true;
    for (size_t i = 0; i < out.size(); i++)
    {
        if (out[i].script == rules.feeScript)
        {
            out[i].value += nFee;
            return true;
        }
    }
    Payout fee;
    fee.script = rules.feeScript;
    fee.value = nFee;
    size_t nAt = 0;
    while (nAt < out.size() && out[nAt].script < rules.feeScript)
        nAt++;
    out.insert(out.begin() + nAt, fee);
    return true;
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

#ifdef BITFLASH_FUZZ
bool fFuzzShareWorkStandIn = false;
#endif

// The RandomX hash against the share target, behind the gate. Called only
// once every cheap check of the share has passed.
static bool CheckShareHash(const Share& share, bool& fBlockOut, string& errOut, WorkGate* pGate)
{
    CBigNum bnShare, bnBlock;
    bnShare.SetCompact(share.data.nShareBits);
    bnBlock.SetCompact(share.nBits);
    if (pGate && !pGate->Allow())
        return Fail(errOut, WORK_GATE_CLOSED);
#ifdef BITFLASH_FUZZ
    if (fFuzzShareWorkStandIn)
    {
        if (share.nNonce & 1)
            return Fail(errOut, "RandomX work does not meet the share target");
        fBlockOut = bnBlock > 0 && (share.nNonce & 2) != 0;
        return true;
    }
#endif
    uint256 hashPoW = share.Header().GetPoWHash();
    if (CBigNum(hashPoW) > bnShare)
        return Fail(errOut, "RandomX work does not meet the share target");
    // A block only if it is one by its own nBits; whether the main chain
    // takes it is for the main chain to say.
    fBlockOut = bnBlock > 0 && CBigNum(hashPoW) <= bnBlock;
    return true;
}

// Everything CheckShareWork looks at but the hash.
static bool CheckShareCheap(const Share& share, const PoolRules& rules, string& errOut)
{
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
    // What any window pays: one address per output, and no more outputs than
    // a window of shares with two uncles each. Checked here, on the share
    // alone, so it also bounds a share taken on its work alone, whose
    // payouts are never checked against a window.
    if (share.coinbase.vout.size() > rules.MaxOutputs())
        return Fail(errOut, "a coinbase paying more addresses than a window holds");
    foreach(const CTxOut& o, share.coinbase.vout)
        if (!IsPayoutScript(vector<unsigned char>(o.scriptPubKey.begin(), o.scriptPubKey.end())))
            return Fail(errOut, "a coinbase paying something other than an address");

    // The coinbase commits to this share's chain data, and only to it.
    if (!CheckAnchor(rules, share.coinbase, d))
        return Fail(errOut, "the coinbase does not commit to this share");

    // The coinbase is the first transaction of the block it claims.
    if (CBlock::CheckMerkleBranch(share.coinbase.GetHash(), share.vMerkleBranch, 0) != share.hashMerkleRoot)
        return Fail(errOut, "the coinbase is not in the merkle root");

    // The share's target no easier than the floor. Nothing is checked against
    // nBits, which the share states for itself: a share whose validity rested
    // on it either let anybody pick an easy one, or rested on whether a node
    // had that main block -- and two honest nodes, one with it and one
    // without, parted ways for good.
    CBigNum bnShare;
    bnShare.SetCompact(d.nShareBits);
    if (bnShare <= 0 || bnShare > rules.bnFloor)
        return Fail(errOut, "share target easier than the floor");
    return true;
}

bool CheckShareWork(const Share& share, const CBigNum& bnFloor, bool& fBlockOut, string& errOut,
                    bool fCheckPoW, WorkGate* pGate)
{
    return CheckShareWork(share, PoolRules::Zero(bnFloor), fBlockOut, errOut, fCheckPoW, pGate);
}

bool CheckShare(const Share& share, const vector<WindowShare>& window, int nBlockHeight,
                const CBigNum& bnFloor, bool& fBlockOut, string& errOut, bool fCheckPoW, WorkGate* pGate)
{
    return CheckShare(share, window, nBlockHeight, PoolRules::Zero(bnFloor), fBlockOut, errOut, fCheckPoW, pGate);
}

bool CheckShareWork(const Share& share, const PoolRules& rules, bool& fBlockOut, string& errOut,
                    bool fCheckPoW, WorkGate* pGate)
{
    fBlockOut = false;
    errOut.clear();
    if (!CheckShareCheap(share, rules, errOut))
        return false;
    return !fCheckPoW || CheckShareHash(share, fBlockOut, errOut, pGate);
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
                const PoolRules& rules, bool& fBlockOut, string& errOut, bool fCheckPoW, WorkGate* pGate)
{
    // The hash last: a share that does not pay its window is refused before
    // anything is spent on its work.
    fBlockOut = false;
    errOut.clear();
    if (!CheckShareCheap(share, rules, errOut))
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
    if (!ComputePoolPayouts(rules, window, nTotal, want, errOut))
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
    return !fCheckPoW || CheckShareHash(share, fBlockOut, errOut, pGate);
}

} // namespace p2pool
