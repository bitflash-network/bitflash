// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "p2pool_chain.h"

#include <algorithm>

namespace p2pool
{

static bool Fail(string& errOut, const char* why)
{
    errOut = why;
    return false;
}

uint64_t WorkOf(unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return 0;
    CBigNum bnWork = (CBigNum(1) << 256) / (bnTarget + 1);
    CBigNum bnMax((uint64)0xFFFFFFFFFFFFFFFFULL);
    if (bnWork > bnMax)
        return 0xFFFFFFFFFFFFFFFFULL;
    uint256 w = bnWork.getuint256();
    uint64_t n = 0;
    for (int i = 7; i >= 0; i--)
        n = (n << 8) | w.begin()[i];
    return n;
}

unsigned int ShareBitsFromMain(unsigned int nMainBits, const CBigNum& bnFloor)
{
    CBigNum bn;
    bn.SetCompact(nMainBits);
    bn *= SHARES_PER_BLOCK;
    if (bn > bnFloor)
        bn = bnFloor;
    return bn.GetCompact();
}

// The block height a coinbase states in its first push (rules v2, BIP34).
bool CoinbaseHeight(const CTransaction& coinbase, int& nHeightOut)
{
    if (!coinbase.IsCoinBase())
        return false;
    const CScript& s = coinbase.vin[0].scriptSig;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    vector<unsigned char> push;
    if (!s.GetOp(pc, op, push))
        return false;
    if (op >= OP_1 && op <= OP_16)
    {
        nHeightOut = (int)op - (int)(OP_1 - 1);
        return true;
    }
    if (push.empty() || push.size() > 4)
        return false;
    nHeightOut = CBigNum(push).getint();
    return true;
}

const ShareChain::Entry* ShareChain::Get(const uint256& id) const
{
    map<uint256, Entry>::const_iterator it = mapShares.find(id);
    return it == mapShares.end() ? NULL : &it->second;
}

int ShareChain::Height(const uint256& id) const
{
    const Entry* e = Get(id);
    return e ? e->nHeight : -1;
}

// Is 'id' on the line ending at 'from', within nDepth steps back (0: from itself)?
bool ShareChain::OnLine(const uint256& id, const uint256& from, int nDepth) const
{
    uint256 cur = from;
    for (int i = 0; i <= nDepth && cur != 0; i++)
    {
        if (cur == id)
            return true;
        const Entry* e = Get(cur);
        if (!e)
            return false;
        cur = e->share.data.hashPrevShare;
    }
    return false;
}

// Has a share on the line ending at 'from', within nDepth, already named it?
bool ShareChain::UncleTaken(const uint256& uncle, const uint256& from, int nDepth) const
{
    uint256 cur = from;
    for (int i = 0; i <= nDepth && cur != 0; i++)
    {
        const Entry* e = Get(cur);
        if (!e)
            return false;
        const vector<uint256>& v = e->share.data.vUncles;
        if (std::find(v.begin(), v.end(), uncle) != v.end())
            return true;
        cur = e->share.data.hashPrevShare;
    }
    return false;
}

bool ShareChain::CheckUncles(const ShareData& d, const uint256& parent, int nHeight, string& errOut) const
{
    for (size_t i = 0; i < d.vUncles.size(); i++)
    {
        const uint256& u = d.vUncles[i];
        if (std::count(d.vUncles.begin(), d.vUncles.end(), u) != 1)
            return Fail(errOut, "an uncle named twice");
        const Entry* e = Get(u);
        if (!e)
            return Fail(errOut, "an unknown uncle");
        if (e->nHeight >= nHeight || e->nHeight < nHeight - MAX_UNCLE_DEPTH)
            return Fail(errOut, "an uncle too old or not older");
        // A sibling of the line, not a share on it: its parent is on the
        // line, it is not.
        if (OnLine(u, parent, MAX_UNCLE_DEPTH))
            return Fail(errOut, "an uncle that is an ancestor");
        if (!OnLine(e->share.data.hashPrevShare, parent, MAX_UNCLE_DEPTH))
            return Fail(errOut, "an uncle off this line");
        if (UncleTaken(u, parent, MAX_UNCLE_DEPTH))
            return Fail(errOut, "an uncle already paid as one");
    }
    return true;
}

unsigned int ShareChain::NextShareBits(const uint256& parent, unsigned int nMainBits) const
{
    const Entry* p = Get(parent);
    if (!p || p->nHeight + 1 < (int)RETARGET_SHARES)
        return ShareBitsFromMain(nMainBits, bnFloor);

    // The mean target of the last RETARGET_SHARES shares, scaled by how much
    // faster or slower than SHARE_SPACING they came, by at most 4 either way.
    CBigNum bnSum = 0;
    const Entry* e = p;
    const Entry* first = p;
    for (unsigned int i = 0; i < RETARGET_SHARES && e; i++)
    {
        CBigNum bn;
        bn.SetCompact(e->share.data.nShareBits);
        bnSum += bn;
        first = e;
        e = Get(e->share.data.hashPrevShare);
    }
    int64 nExpected = (int64)(RETARGET_SHARES - 1) * SHARE_SPACING;
    int64 nActual = (int64)p->share.nTime - (int64)first->share.nTime;
    if (nActual < nExpected / 4) nActual = nExpected / 4;
    if (nActual > nExpected * 4) nActual = nExpected * 4;

    CBigNum bnNew = bnSum / (int64)RETARGET_SHARES;
    bnNew *= nActual;
    bnNew /= nExpected;

    // Never easier than the floor, never harder than a block.
    CBigNum bnMain;
    bnMain.SetCompact(nMainBits);
    if (bnNew > bnFloor) bnNew = bnFloor;
    if (bnNew < bnMain) bnNew = bnMain;
    return bnNew.GetCompact();
}

bool ShareChain::WindowFor(const ShareData& d, uint64_t nOwnWork, vector<WindowShare>& out, string& errOut) const
{
    out.clear();
    // One share and its uncles: 80% of each uncle's work to the uncle, the
    // rest to the share that named it. Integer split, nothing lost.
    // False when an uncle it names is not here: skipping it would pay a
    // different list from every node that has it, and refuse their shares.
    struct Credit
    {
        static bool Share(vector<WindowShare>& v, const vector<unsigned char>& script, uint64_t work,
                          const vector<uint256>& uncles, const ShareChain& c)
        {
            uint64_t bonus = 0;
            for (size_t i = 0; i < uncles.size(); i++)
            {
                const Entry* u = c.Get(uncles[i]);
                if (!u)
                    return false;
                uint64_t paid = u->work / 5 * 4 + (u->work % 5) * 4 / 5;
                WindowShare w;
                w.payoutScript = u->share.data.payoutScript;
                w.work = paid;
                if (w.work) v.push_back(w);
                bonus += u->work - paid;
            }
            WindowShare w;
            w.payoutScript = script;
            w.work = work + bonus;
            v.push_back(w);
            return true;
        }
    };

    if (!Credit::Share(out, d.payoutScript, nOwnWork, d.vUncles, *this))
        return Fail(errOut, "the payout window reaches shares this node does not have");
    uint256 cur = d.hashPrevShare;
    for (unsigned int n = 1; n < WINDOW_SHARES && cur != 0; n++)
    {
        // A hole in the window means this node has not synced enough share
        // history to know what the share must pay; guessing would make it
        // disagree with nodes that have.
        const Entry* e = Get(cur);
        if (!e)
            return Fail(errOut, "the payout window reaches shares this node does not have");
        if (!Credit::Share(out, e->share.data.payoutScript, e->work, e->share.data.vUncles, *this))
            return Fail(errOut, "the payout window reaches shares this node does not have");
        cur = e->share.data.hashPrevShare;
    }
    if (out.empty())
        return Fail(errOut, "empty window");
    return true;
}

vector<uint256> ShareChain::UncleCandidates(const uint256& parent) const
{
    vector<uint256> v;
    const Entry* p = Get(parent);
    if (!p)
        return v;
    int nHeight = p->nHeight + 1;
    for (map<uint256, Entry>::const_iterator it = mapShares.begin(); it != mapShares.end() && v.size() < MAX_UNCLES; ++it)
    {
        const Entry& e = it->second;
        if (e.nHeight >= nHeight || e.nHeight < nHeight - MAX_UNCLE_DEPTH)
            continue;
        if (OnLine(it->first, parent, MAX_UNCLE_DEPTH) ||
            !OnLine(e.share.data.hashPrevShare, parent, MAX_UNCLE_DEPTH) ||
            UncleTaken(it->first, parent, MAX_UNCLE_DEPTH))
            continue;
        v.push_back(it->first);
    }
    return v;
}

bool ShareChain::GetShare(const uint256& id, Share& out) const
{
    const Entry* e = Get(id);
    if (!e)
        return false;
    out = e->share;
    return true;
}

bool ShareChain::Add(const Share& s, const MainView& main, string& errOut, vector<uint256>* pvMissing, bool* pfBlock)
{
    if (pvMissing) pvMissing->clear();
    if (pfBlock) *pfBlock = false;
    const ShareData& d = s.data;
    uint256 id = s.GetId();
    if (Has(id))
        return Fail(errOut, "already have this share");

    // Everything it names must be here first: its parent and its uncles.
    // A peer that named an uncle we never received did nothing wrong; it was
    // scored for it once, and two honest nodes ended up banning each other
    // onto separate share chains.
    if (d.vUncles.size() <= MAX_UNCLES)
    {
        vector<uint256> vMissing;
        if (d.hashPrevShare != 0 && !Has(d.hashPrevShare))
            vMissing.push_back(d.hashPrevShare);
        for (size_t i = 0; i < d.vUncles.size(); i++)
            if (!Has(d.vUncles[i]) &&
                std::find(vMissing.begin(), vMissing.end(), d.vUncles[i]) == vMissing.end())
                vMissing.push_back(d.vUncles[i]);
        if (!vMissing.empty())
        {
            if (pvMissing) *pvMissing = vMissing;
            return Fail(errOut, d.hashPrevShare != 0 && !Has(d.hashPrevShare) ? "unknown parent share"
                                                                              : "an unknown uncle");
        }
    }

    // Its place in the share chain.
    const Entry* parent = d.hashPrevShare != 0 ? Get(d.hashPrevShare) : NULL;
    int nHeight = parent ? parent->nHeight + 1 : 0;
    if ((int)d.nShareHeight != nHeight)
        return Fail(errOut, "wrong share height");

    // Its place in the main chain. On a block this node has, the bits must be
    // that block's; on one it does not have -- orphaned since, or never seen
    // here -- the height its coinbase states (rules v2) is enough. How far
    // behind the tip that block is does not decide anything: it would make a
    // share's validity depend on when it arrived, and two honest nodes would
    // disagree about the same share. That split two testnet nodes, when an
    // uncle fetched minutes after it was mined was refused as stale and every
    // share naming it waited forever. Work on an old block is still work the
    // window pays; mining on the tip is the miner's own interest, and this
    // node's templates are always on its tip.
    int nPrevHeight;
    unsigned int nNextBits;
    if (main.BlockInfo(s.hashPrevBlock, nPrevHeight, nNextBits))
    {
        if (s.nBits != nNextBits)
            return Fail(errOut, "wrong main-chain bits");
    }
    else
    {
        int nHeight;
        if (!CoinbaseHeight(s.coinbase, nHeight) || nHeight < 1)
            return Fail(errOut, "a share whose coinbase states no height");
        nPrevHeight = nHeight - 1;
    }

    // Time: after the median of the last 11 shares, not far in the future.
    if ((int64)s.nTime > main.Now() + MAX_SHARE_FUTURE)
        return Fail(errOut, "share time too far in the future");
    if (parent)
    {
        vector<unsigned int> times;
        const Entry* e = parent;
        for (int i = 0; i < 11 && e; i++)
        {
            times.push_back(e->share.nTime);
            e = Get(e->share.data.hashPrevShare);
        }
        std::sort(times.begin(), times.end());
        if (s.nTime <= times[times.size() / 2])
            return Fail(errOut, "share time not after the median of the last 11");
    }

    if (d.nShareBits != NextShareBits(d.hashPrevShare, s.nBits))
        return Fail(errOut, "wrong share target");
    if (!CheckUncles(d, d.hashPrevShare, nHeight, errOut))
        return false;

    uint64_t nWork = WorkOf(d.nShareBits);
    vector<WindowShare> window;
    if (!WindowFor(d, nWork, window, errOut))
        return false;
    bool fBlock = false;
    if (!CheckShare(s, window, nPrevHeight + 1, bnFloor, fBlock, errOut, fCheckPoW))
        return false;

    Entry e;
    e.share = s;
    e.nHeight = nHeight;
    e.work = nWork;
    e.bnChainWork = parent ? parent->bnChainWork : CBigNum(0);
    e.bnChainWork += CBigNum((uint64)nWork);
    for (size_t i = 0; i < d.vUncles.size(); i++)
        e.bnChainWork += CBigNum((uint64)Get(d.vUncles[i])->work);
    mapShares[id] = e;

    // Most work wins; on a tie the line seen first stays.
    const Entry* tip = Get(hashTip);
    if (!tip || e.bnChainWork > tip->bnChainWork)
        hashTip = id;
    if (pfBlock) *pfBlock = fBlock;
    Prune();
    return true;
}

bool ShareChain::AddTrusted(const Share& s, string& errOut)
{
    const ShareData& d = s.data;
    uint256 id = s.GetId();
    if (Has(id))
        return Fail(errOut, "already have this share");
    bool fBlock;
    if (!CheckShareWork(s, bnFloor, fBlock, errOut, fCheckPoW))
        return false;
    // Linked to what is here when its parent is; the deepest one of a
    // history has no parent here, and starts the line.
    const Entry* parent = d.hashPrevShare == 0 ? NULL : Get(d.hashPrevShare);
    if (parent && (int)d.nShareHeight != parent->nHeight + 1)
        return Fail(errOut, "wrong share height");

    Entry e;
    e.share = s;
    e.nHeight = (int)d.nShareHeight;
    e.work = WorkOf(d.nShareBits);
    e.bnChainWork = parent ? parent->bnChainWork : CBigNum(0);
    e.bnChainWork += CBigNum((uint64)e.work);
    for (size_t i = 0; i < d.vUncles.size(); i++)
        if (const Entry* u = Get(d.vUncles[i]))
            e.bnChainWork += CBigNum((uint64)u->work);
    mapShares[id] = e;
    const Entry* tip = Get(hashTip);
    if (!tip || e.bnChainWork > tip->bnChainWork)
        hashTip = id;
    return true;
}

bool ShareChain::AddHistory(const vector<Share>& part, int nTipHeight, const MainView& main, string& errOut)
{
    for (size_t i = 0; i < part.size(); i++)
    {
        const Share& s = part[i];
        string err;
        bool fOk = (int)s.data.nShareHeight < nTipHeight - (int)RETARGET_SHARES
                 ? AddTrusted(s, err)
                 : Add(s, main, err);
        if (!fOk && err != "already have this share")
        {
            errOut = strprintf("share at height %u: %s", s.data.nShareHeight, err.c_str());
            return false;
        }
    }
    return true;
}

void ShareChain::History(vector<Share>& out) const
{
    out.clear();
    set<uint256> seen;
    vector<const Entry*> v;
    uint256 cur = hashTip;
    for (unsigned int n = 0; n < HISTORY_SHARES && cur != 0; n++)
    {
        const Entry* e = Get(cur);
        if (!e)
            break;
        if (seen.insert(cur).second)
            v.push_back(e);
        for (size_t i = 0; i < e->share.data.vUncles.size(); i++)
        {
            const Entry* u = Get(e->share.data.vUncles[i]);
            if (u && seen.insert(e->share.data.vUncles[i]).second)
                v.push_back(u);
        }
        cur = e->share.data.hashPrevShare;
    }
    // Oldest first, a parent always before its children.
    std::stable_sort(v.begin(), v.end(), [](const Entry* a, const Entry* b) { return a->nHeight < b->nHeight; });
    for (size_t i = 0; i < v.size(); i++)
        out.push_back(v[i]->share);
}

// Keep what a window, a retarget and the uncle rules can still reach.
void ShareChain::Prune()
{
    const Entry* tip = Get(hashTip);
    if (!tip)
        return;
    // HISTORY_SHARES covers the window and the retarget, and is what a
    // starting peer is sent.
    int nKeep = (int)HISTORY_SHARES + 10;
    int nCut = tip->nHeight - nKeep;
    if (nCut <= 0)
        return;
    for (map<uint256, Entry>::iterator it = mapShares.begin(); it != mapShares.end();)
    {
        if (it->second.nHeight < nCut)
            mapShares.erase(it++);
        else
            ++it;
    }
}

} // namespace p2pool
