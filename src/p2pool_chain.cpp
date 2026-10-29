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

// The sender may simply be ahead of us, or a moment behind, or see a main
// chain this node does not. A clock and a main chain are this node's own, so
// what they refuse is no fault of a peer that saw it differently.
bool InnocentRefusal(const string& err)
{
    return err == "already have this share" || err == "unknown parent share" ||
           err == "an unknown uncle" ||
           err == "the payout window reaches shares this node does not have" ||
           err.compare(0, 5, "here:") == 0;
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

const char* ShareChain::UncleProblem(const uint256& u, const uint256& parent, int nHeight) const
{
    const Entry* e = Get(u);
    if (!e)
        return "an unknown uncle";
    if (e->nHeight >= nHeight || e->nHeight < nHeight - MAX_UNCLE_DEPTH)
        return "an uncle too old or not older";
    // A sibling of the line, not a share on it: its parent is on the line,
    // it is not.
    if (OnLine(u, parent, MAX_UNCLE_DEPTH))
        return "an uncle that is an ancestor";
    if (!OnLine(e->share.data.hashPrevShare, parent, MAX_UNCLE_DEPTH))
        return "an uncle off this line";
    if (UncleTaken(u, parent, MAX_UNCLE_DEPTH))
        return "an uncle already paid as one";
    return NULL;
}

bool ShareChain::CheckUncles(const ShareData& d, const uint256& parent, int nHeight, string& errOut) const
{
    for (size_t i = 0; i < d.vUncles.size(); i++)
    {
        const uint256& u = d.vUncles[i];
        if (std::count(d.vUncles.begin(), d.vUncles.end(), u) != 1)
            return Fail(errOut, "an uncle named twice");
        if (const char* why = UncleProblem(u, parent, nHeight))
            return Fail(errOut, why);
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
    bool fLocalView = false;
    if (AddInContext(s, main, errOut, pvMissing, pfBlock, fLocalView))
        return true;
    // Judged without the main block it was mined on: what it was refused for
    // may be right on a node that has that block.
    if (fLocalView && errOut.compare(0, 5, "here:") != 0)
        errOut = "here: " + errOut;
    return false;
}

bool ShareChain::AddInContext(const Share& s, const MainView& main, string& errOut,
                              vector<uint256>* pvMissing, bool* pfBlock, bool& fLocalView)
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
        // A node with that block off its main chain never gets here, and
        // takes the share; this one refuses. Neither is the sender's fault.
        if (s.nBits != nNextBits)
            return Fail(errOut, "here: wrong main-chain bits");
    }
    else
    {
        int nHeight;
        if (!CoinbaseHeight(s.coinbase, nHeight) || nHeight < 1)
            return Fail(errOut, "a share whose coinbase states no height");
        nPrevHeight = nHeight - 1;
        fLocalView = true;
    }

    // Time: after the median of the last 11 shares, not far in the future
    // -- by this node's clock, which is nobody else's.
    if ((int64)s.nTime > main.Now() + MAX_SHARE_FUTURE)
        return Fail(errOut, "here: share time too far in the future");
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
    // From here on the share is judged on itself -- its work, its coinbase
    // against a window every node with these shares computes the same -- and
    // a refusal is the sender's to answer for, main block known or not.
    fLocalView = false;
    if (!CheckShare(s, window, nPrevHeight + 1, bnFloor, fBlock, errOut, fCheckPoW))
        return false;

    Entry e;
    e.share = s;
    e.nHeight = nHeight;
    e.work = nWork;
    e.bnOwnWork = CBigNum((uint64)nWork);
    for (size_t i = 0; i < d.vUncles.size(); i++)
        e.bnOwnWork += CBigNum((uint64)Get(d.vUncles[i])->work);
    e.bnChainWork = (parent ? parent->bnChainWork : CBigNum(0)) + e.bnOwnWork;
    e.fTrusted = false;
    mapShares[id] = e;

    if (Heavier(id))
        hashTip = id;
    if (pfBlock) *pfBlock = fBlock;
    Prune();
    Evict();
    return true;
}

bool ShareChain::AddTrusted(const Share& s, string& errOut)
{
    const ShareData& d = s.data;
    uint256 id = s.GetId();
    if (Has(id))
        return Fail(errOut, "already have this share");
    // Unlike a share checked in full, nothing here ties these to the tip's
    // line, so they are capped as they come; a history that does not fit is
    // this node's limit, not the sender's fault.
    if (mapShares.size() >= MAX_CHAIN_SHARES)
        return Fail(errOut, "here: no room for more history");
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
    e.bnOwnWork = CBigNum((uint64)e.work);
    // An uncle adds its work only where the uncle rules can be seen to hold:
    // with its parent here, and each uncle a real sibling not paid before.
    // A history once named one big uncle from share after share and summed
    // it every time.
    if (parent)
        for (size_t i = 0; i < d.vUncles.size(); i++)
            if (!UncleProblem(d.vUncles[i], d.hashPrevShare, e.nHeight))
                e.bnOwnWork += CBigNum((uint64)Get(d.vUncles[i])->work);
    e.bnChainWork = (parent ? parent->bnChainWork : CBigNum(0)) + e.bnOwnWork;
    e.fTrusted = true;
    mapShares[id] = e;
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
        if (fOk || err == "already have this share")
            continue;
        // Nothing wrong with the sender; what follows builds on this one.
        if (InnocentRefusal(err))
            return true;
        errOut = strprintf("share at height %u: %s", s.data.nShareHeight, err.c_str());
        return false;
    }
    return true;
}

// Do the lines ending at a and b share a share held here?
bool ShareChain::LinesMeet(const uint256& a, const uint256& b) const
{
    const Entry* ea = Get(a);
    const Entry* eb = Get(b);
    while (ea && eb)
    {
        if (ea == eb)
            return true;
        if (ea->nHeight >= eb->nHeight)
            ea = Get(ea->share.data.hashPrevShare);
        else
            eb = Get(eb->share.data.hashPrevShare);
    }
    return false;
}

// The work of the last WINDOW_SHARES of the line ending at e, or of as many
// of them as are held.
CBigNum ShareChain::LineWork(const Entry* e) const
{
    const Entry* last = e;
    for (unsigned int n = 1; n < WINDOW_SHARES; n++)
    {
        const Entry* p = Get(last->share.data.hashPrevShare);
        if (!p)
            break;
        last = p;
    }
    return e->bnChainWork - last->bnChainWork + last->bnOwnWork;
}

// Most work wins; on a tie the line seen first stays. Summed work compares
// two lines that meet in the shares held here. Two that do not -- this node
// mined alone before it heard the network, or was cut off for long -- began
// their sums at different shares, and a long run alone would outweigh the
// whole network for good; those are compared on their last WINDOW_SHARES.
bool ShareChain::Heavier(const uint256& id) const
{
    const Entry* c = Get(id);
    if (!c || c->fTrusted)
        return false;
    const Entry* t = Get(hashTip);
    if (!t)
        return true;
    if (LinesMeet(id, hashTip))
        return c->bnChainWork > t->bnChainWork;
    return LineWork(c) > LineWork(t);
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

// The deepest share held on the line through 'id'. 'roots' remembers the
// answers, so a pass over every share costs one walk per line.
uint256 ShareChain::RootOf(const uint256& id, map<uint256, uint256>& roots) const
{
    vector<uint256> path;
    uint256 cur = id, root;
    for (;;)
    {
        map<uint256, uint256>::const_iterator m = roots.find(cur);
        if (m != roots.end())
        {
            root = m->second;
            break;
        }
        path.push_back(cur);
        const uint256& parent = Get(cur)->share.data.hashPrevShare;
        if (!Has(parent))
        {
            root = cur;
            break;
        }
        cur = parent;
    }
    for (size_t i = 0; i < path.size(); i++)
        roots[path[i]] = root;
    return root;
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
    // Every ten heights, not every share: a pass looks at every share held,
    // and keeping a few more than needed for a while costs nothing.
    if (nCut <= 0 || (nCut >= nLastPruneCut && nCut < nLastPruneCut + 10))
        return;
    nLastPruneCut = nCut;
    // Heights compare within the shares that hang together. A line held here
    // that does not meet the tip's began at a share of its own: cut by the
    // tip's height, the network's line arriving at a node that had mined
    // alone higher was dropped share by share, and could never win. Such a
    // line goes once all of it is below the cut; till then Evict bounds it.
    map<uint256, uint256> roots;
    map<uint256, int> nTop;
    for (map<uint256, Entry>::const_iterator it = mapShares.begin(); it != mapShares.end(); ++it)
    {
        int& n = nTop.insert(make_pair(RootOf(it->first, roots), -1)).first->second;
        n = std::max(n, it->second.nHeight);
    }
    uint256 tipRoot = roots[hashTip];
    vector<uint256> vCut;
    for (map<uint256, Entry>::const_iterator it = mapShares.begin(); it != mapShares.end(); ++it)
    {
        if (it->second.nHeight >= nCut)
            continue;
        const uint256& root = roots[it->first];
        if (root == tipRoot || nTop[root] < nCut)
            vCut.push_back(it->first);
    }
    for (size_t i = 0; i < vCut.size(); i++)
        mapShares.erase(vCut[i]);
}

// The memory backstop: past MAX_CHAIN_SHARES, drop side lines, the lightest
// first and a line's newest share before its parent, until a quarter of the
// room is free again. Never the tip's line nor an uncle it names, which a
// template's window needs. A dropped share that later turns out to matter
// is asked for again like any missing one.
void ShareChain::Evict()
{
    if (mapShares.size() <= MAX_CHAIN_SHARES)
        return;
    set<uint256> keep;
    uint256 cur = hashTip;
    for (unsigned int n = 0; n < HISTORY_SHARES + 10 && cur != 0; n++)
    {
        const Entry* e = Get(cur);
        if (!e)
            break;
        keep.insert(cur);
        keep.insert(e->share.data.vUncles.begin(), e->share.data.vUncles.end());
        cur = e->share.data.hashPrevShare;
    }
    map<uint256, int> children;
    for (map<uint256, Entry>::const_iterator it = mapShares.begin(); it != mapShares.end(); ++it)
        if (Has(it->second.share.data.hashPrevShare))
            children[it->second.share.data.hashPrevShare]++;
    multimap<CBigNum, uint256> leaves;
    for (map<uint256, Entry>::const_iterator it = mapShares.begin(); it != mapShares.end(); ++it)
        if (!keep.count(it->first) && !children.count(it->first))
            leaves.insert(make_pair(it->second.bnChainWork, it->first));
    size_t nTarget = MAX_CHAIN_SHARES * 3 / 4;
    while (mapShares.size() > nTarget && !leaves.empty())
    {
        uint256 id = leaves.begin()->second;
        leaves.erase(leaves.begin());
        uint256 parent = Get(id)->share.data.hashPrevShare;
        mapShares.erase(id);
        map<uint256, int>::iterator ci = children.find(parent);
        if (ci != children.end() && --ci->second == 0 && !keep.count(parent))
            leaves.insert(make_pair(Get(parent)->bnChainWork, parent));
    }
}

} // namespace p2pool
