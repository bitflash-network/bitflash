// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See poolindex.h.

#include "headers.h"
#include "poolindex.h"

static const unsigned char TAG_P2P[3] = { 'p', '2', 'p' };
static const unsigned char TAG_P2X[3] = { 'p', '2', 'x' };
static const unsigned char TAG_P2L[3] = { 'p', '2', 'l' };

// The file: a version, the registry, and the hash of both. Version 2 added
// dropped anchors and the locator.
static const int POOL_INDEX_FILE_VERSION = 2;
// The file grows by burns of 1 BTF and by a bounded number of recent anchors;
// far past anything real, and a bound on what a damaged file can ask this
// node to read.
static const size_t POOL_INDEX_FILE_MAX = 256 * 1024 * 1024;

int ClassifyPoolAnchor(const CTransaction& coinbase, uint256& idOut, uint256& hashOut)
{
    if (!coinbase.IsCoinBase())
        return POOL_ANCHOR_NONE;
    const CScript& s = coinbase.vin[0].scriptSig;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    std::vector<unsigned char> push;
    int nP2P = 0, nP2X = 0, nP2L = 0;
    uint256 hashP2P = 0, idP2X = 0, hashP2X = 0;
    while (pc < s.end())
    {
        if (!s.GetOp(pc, op, push))
            return POOL_ANCHOR_NONE;
        if (push.size() == 35 && memcmp(&push[0], TAG_P2P, 3) == 0)
        {
            memcpy(hashP2P.begin(), &push[3], 32);
            nP2P++;
        }
        else if (push.size() == 35 && memcmp(&push[0], TAG_P2L, 3) == 0)
        {
            nP2L++;
        }
        else if (push.size() == 67 && memcmp(&push[0], TAG_P2X, 3) == 0)
        {
            memcpy(idP2X.begin(), &push[3], 32);
            memcpy(hashP2X.begin(), &push[35], 32);
            nP2X++;
        }
    }
    if (nP2P == 1 && nP2X == 0)
    {
        hashOut = hashP2P;
        return POOL_ANCHOR_ZERO;
    }
    if (nP2X == 1 && nP2P == 0 && nP2L == 0)
    {
        idOut = idP2X;
        hashOut = hashP2X;
        return POOL_ANCHOR_REGISTERED;
    }
    return POOL_ANCHOR_NONE;
}

static uint256 IdOf(const std::vector<unsigned char>& record, const unsigned char magic[4])
{
    uint256 id = 0;
    poolreg::PoolId(record, magic, id.begin());
    return id;
}

static std::string Fingerprint(const uint256& id)
{
    uint256 h = id;
    return poolreg::IdHex(h.begin()).substr(0, 8);
}

// The latest sweep at or below a height.
static int LastSweep(int nHeight)
{
    return nHeight < 0 ? -1 : nHeight - nHeight % POOL_ANCHOR_SWEEP_INTERVAL;
}

// Anchors that still count are the suffix of a set; dropped ones the prefix.
static size_t FirstCounted(const std::vector<CPoolAnchor>& v)
{
    size_t i = 0;
    while (i < v.size() && v[i].nDroppedAt >= 0)
        i++;
    return i;
}

CPoolRegistry::CPoolRegistry() : fInit(false), nHeight(-1), hashTip(0), nPurgedTop(-1)
{
    memset(magic, 0, sizeof(magic));
}

void CPoolRegistry::Reset(const unsigned char magicIn[4])
{
    fInit = true;
    memcpy(magic, magicIn, sizeof(magic));
    nHeight = -1;
    hashTip = 0;
    mapPools.clear();
    mapAnchors.clear();
    nPurgedTop = -1;
    vLocator.clear();
}

bool CPoolRegistry::HasMagic(const unsigned char magicIn[4]) const
{
    return fInit && memcmp(magic, magicIn, sizeof(magic)) == 0;
}

uint256 CPoolRegistry::ZeroId() const
{
    return IdOf(poolreg::PoolZero().Encode(), magic);
}

bool CPoolRegistry::IsRegistered(const uint256& id) const
{
    return id == ZeroId() || mapPools.count(id) != 0;
}

// Drop the oldest anchors of a registered pool's set that are past everything
// a reorg within the margin could bring back into view: beyond the newest
// 64 + margin, and older than the window + margin below the tip. Only while
// the set has no dropped prefix (a set of an id that was not registered is
// bounded by the sweeps instead).
void CPoolRegistry::TrimAnchors(const uint256& id, CPoolAnchorSet& set, int nTip)
{
    if (set.v.empty() || set.v[0].nDroppedAt >= 0 || !IsRegistered(id))
        return;
    const size_t nKeep = POOL_RECENT_ANCHORS + POOL_INDEX_REORG_MARGIN;
    const int nOld = nTip - (POOL_ANCHOR_WINDOW + POOL_INDEX_REORG_MARGIN);
    size_t nDrop = 0;
    while (set.v.size() - nDrop > nKeep && set.v[nDrop].nHeight <= nOld)
        nDrop++;
    if (nDrop == 0)
        return;
    set.nTrimmedTop = std::max(set.nTrimmedTop, set.v[nDrop - 1].nHeight);
    set.v.erase(set.v.begin(), set.v.begin() + nDrop);
}

// At a height that is a multiple of 144: ids neither pool zero nor
// registered lose their anchors more than 2160 blocks old (part of the fold);
// anchors dropped at least a margin ago are then removed for good.
void CPoolRegistry::Sweep(int nSweep)
{
    const int nOld = nSweep - POOL_UNREGISTERED_ANCHOR_BLOCKS;
    for (std::map<uint256, CPoolAnchorSet>::iterator it = mapAnchors.begin(); it != mapAnchors.end(); )
    {
        CPoolAnchorSet& set = it->second;
        if (!IsRegistered(it->first))
            for (size_t i = FirstCounted(set.v); i < set.v.size() && set.v[i].nHeight <= nOld; i++)
                set.v[i].nDroppedAt = nSweep;
        size_t nPurge = 0;
        while (nPurge < set.v.size() && set.v[nPurge].nDroppedAt >= 0 &&
               set.v[nPurge].nDroppedAt <= nSweep - POOL_INDEX_REORG_MARGIN)
        {
            nPurgedTop = std::max(nPurgedTop, set.v[nPurge].nDroppedAt);
            nPurge++;
        }
        if (nPurge)
            set.v.erase(set.v.begin(), set.v.begin() + nPurge);
        if (set.v.empty() && set.nTrimmedTop < 0)
            mapAnchors.erase(it++);
        else
            ++it;
    }
}

bool CPoolRegistry::ConnectBlock(const CBlock& block, int nHeightIn, const uint256& hashBlock)
{
    if (!fInit || nHeightIn != nHeight + 1)
        return false;
    const uint256 zero = ZeroId();
    for (unsigned int t = 0; t < block.vtx.size(); t++)
    {
        const CTransaction& tx = block.vtx[t];
        uint256 txid = 0;
        bool fTxid = false;
        for (unsigned int o = 0; o < tx.vout.size(); o++)
        {
            const CTxOut& out = tx.vout[o];
            // The cheap tests first: most outputs are neither burns nor
            // OP_RETURN.
            if (out.nValue < poolreg::MIN_BURN)
                continue;
            const CScript& script = out.scriptPubKey;
            if (script.size() < 2 || script[0] != OP_RETURN)
                continue;
            std::vector<unsigned char> s(script.begin(), script.end());
            poolreg::PoolRecord rec;
            std::string err;
            if (!poolreg::ParseScript(s, rec, err))
                continue;
            if (!fTxid)
            {
                txid = tx.GetHash();
                fTxid = true;
            }
            std::vector<unsigned char> record(s.begin() + 2, s.end());
            uint256 id = IdOf(record, magic);
            CPoolAppearance a;
            a.nHeight = nHeightIn;
            a.hashBlock = hashBlock;
            a.nTx = t;
            a.txid = txid;
            a.nOut = o;
            a.nBurn = out.nValue;
            CPoolEntry& e = mapPools[id];
            if (e.vAppear.empty())
            {
                e.record = record;
                if (id == zero)
                    printf("pool index: pool zero's own record burned in block %d\n", nHeightIn);
                else
                    printf("pool index: pool %s \"%s\" appears in block %d\n",
                           Fingerprint(id).c_str(), rec.name.c_str(), nHeightIn);
            }
            e.vAppear.push_back(a);
        }
    }

    if (!block.vtx.empty())
    {
        uint256 id = 0, hashShare = 0;
        int nKind = ClassifyPoolAnchor(block.vtx[0], id, hashShare);
        // Pool zero's id is never written in its shares ("p2p" names it), so
        // a "p2x" push naming it is a label for no share chain: no pool's.
        if (nKind == POOL_ANCHOR_REGISTERED && id == zero)
            nKind = POOL_ANCHOR_NONE;
        if (nKind == POOL_ANCHOR_ZERO)
            id = zero;
        if (nKind != POOL_ANCHOR_NONE)
        {
            CPoolAnchor anchor;
            anchor.nHeight = nHeightIn;
            anchor.hashBlock = hashBlock;
            anchor.hashShareData = hashShare;
            CPoolAnchorSet& set = mapAnchors[id];
            set.v.push_back(anchor);
            TrimAnchors(id, set, nHeightIn);
        }
    }

    nHeight = nHeightIn;
    hashTip = hashBlock;
    if (nHeightIn % POOL_ANCHOR_SWEEP_INTERVAL == 0)
        Sweep(nHeightIn);

    // The locator: the last 64 blocks, and every 144th for the margin.
    vLocator.push_back(CPoolLocatorEntry(nHeightIn, hashBlock));
    std::vector<CPoolLocatorEntry> v;
    v.reserve(vLocator.size());
    for (size_t i = 0; i < vLocator.size(); i++)
    {
        const CPoolLocatorEntry& l = vLocator[i];
        if (l.nHeight > nHeightIn - POOL_LOCATOR_RECENT ||
            (l.nHeight % POOL_ANCHOR_SWEEP_INTERVAL == 0 && l.nHeight >= nHeightIn - POOL_INDEX_REORG_MARGIN))
            v.push_back(l);
    }
    vLocator.swap(v);
    return true;
}

bool CPoolRegistry::DisconnectAbove(int nHeightIn, const uint256& hashAt)
{
    if (nHeightIn >= nHeight)
        return true;
    // Anchors removed for good at a sweep above the fork would count again.
    bool fExact = nPurgedTop <= nHeightIn;
    const uint256 zero = ZeroId();
    for (std::map<uint256, CPoolEntry>::iterator it = mapPools.begin(); it != mapPools.end(); )
    {
        std::vector<CPoolAppearance>& v = it->second.vAppear;
        while (!v.empty() && v.back().nHeight > nHeightIn)
            v.pop_back();
        if (v.empty())
        {
            if (it->first == zero)
            {
                printf("pool index: the burn of pool zero's own record left the active chain "
                       "(reorg below block %d); pool zero stays entry zero\n", nHeightIn + 1);
            }
            else
            {
                poolreg::PoolRecord rec;
                std::string err;
                poolreg::Parse(it->second.record, rec, err);
                printf("pool index: pool %s \"%s\" left the active chain (reorg below block %d)\n",
                       Fingerprint(it->first).c_str(), rec.name.c_str(), nHeightIn + 1);
            }
            mapPools.erase(it++);
        }
        else
            ++it;
    }
    const int nSweepBelow = LastSweep(nHeightIn);
    for (std::map<uint256, CPoolAnchorSet>::iterator it = mapAnchors.begin(); it != mapAnchors.end(); )
    {
        CPoolAnchorSet& set = it->second;
        while (!set.v.empty() && set.v.back().nHeight > nHeightIn)
            set.v.pop_back();
        // A sweep above the fork never happened on the branch that stays.
        for (size_t i = 0; i < set.v.size(); i++)
            if (set.v[i].nDroppedAt > nHeightIn)
                set.v[i].nDroppedAt = -1;
        if (set.nTrimmedTop >= 0)
        {
            // What was removed still counts if the newest 64 are now fewer
            // than 64, if the window now reaches down to it, or, for an id
            // that is no longer registered, if no sweep on this branch would
            // have dropped it.
            size_t nCounted = set.v.size() - FirstCounted(set.v);
            if (nCounted < POOL_RECENT_ANCHORS || set.nTrimmedTop > nHeightIn - POOL_ANCHOR_WINDOW)
                fExact = false;
            if (!IsRegistered(it->first) && set.nTrimmedTop > nSweepBelow - POOL_UNREGISTERED_ANCHOR_BLOCKS)
                fExact = false;
        }
        if (set.v.empty() && set.nTrimmedTop < 0)
            mapAnchors.erase(it++);
        else
            ++it;
    }
    while (!vLocator.empty() && vLocator.back().nHeight > nHeightIn)
        vLocator.pop_back();
    nHeight = nHeightIn;
    hashTip = hashAt;
    return fExact;
}

int CPoolRegistry::Status(const uint256& id) const
{
    if (id == ZeroId())
        return POOL_ACTIVE;
    std::map<uint256, CPoolEntry>::const_iterator it = mapPools.find(id);
    if (it == mapPools.end() || it->second.vAppear.empty())
        return POOL_UNKNOWN;
    int nConf = nHeight - it->second.vAppear[0].nHeight + 1;
    return nConf >= POOL_ACTIVE_CONFIRMATIONS ? POOL_ACTIVE : POOL_PENDING;
}

void CPoolRegistry::Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const
{
    vRecent.clear();
    nInWindow = 0;
    std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.find(id);
    if (it == mapAnchors.end())
        return;
    const std::vector<CPoolAnchor>& v = it->second.v;
    for (size_t i = v.size(); i-- > 0; )
    {
        if (v[i].nDroppedAt >= 0)
            break;
        if (vRecent.size() < POOL_RECENT_ANCHORS)
            vRecent.push_back(v[i]);
        if (v[i].nHeight > nHeight - POOL_ANCHOR_WINDOW)
            nInWindow++;
        else if (vRecent.size() >= POOL_RECENT_ANCHORS)
            break;
    }
}

size_t CPoolRegistry::AnchorsStored() const
{
    size_t n = 0;
    for (std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.begin(); it != mapAnchors.end(); ++it)
        n += it->second.v.size();
    return n;
}

size_t CPoolRegistry::AnchorsCounted() const
{
    size_t n = 0;
    for (std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.begin(); it != mapAnchors.end(); ++it)
        n += it->second.v.size() - FirstCounted(it->second.v);
    return n;
}

void CPoolRegistry::Fill(const uint256& id, const CPoolEntry* pEntry, CPoolInfo& out) const
{
    out = CPoolInfo();
    out.id = id;
    out.fZero = (id == ZeroId());
    if (out.fZero)
        out.record = poolreg::PoolZero().Encode();
    else if (pEntry)
        out.record = pEntry->record;
    std::string err;
    poolreg::Parse(out.record, out.rec, err);
    if (pEntry && !pEntry->vAppear.empty())
    {
        out.nAppearances = (int)pEntry->vAppear.size();
        out.first = pEntry->vAppear[0];
        out.nConfirmations = nHeight - out.first.nHeight + 1;
    }
    out.nStatus = Status(id);
    Anchors(id, out.vRecentAnchors, out.nAnchorsInWindow);
}

bool CPoolRegistry::Lookup(const uint256& id, CPoolInfo& out) const
{
    std::map<uint256, CPoolEntry>::const_iterator it = mapPools.find(id);
    const CPoolEntry* p = (it == mapPools.end()) ? NULL : &it->second;
    if (!p && id != ZeroId())
    {
        out = CPoolInfo();
        out.id = id;
        return false;
    }
    Fill(id, p, out);
    return true;
}

namespace {
struct FirstAppearanceOrder
{
    bool operator()(const CPoolInfo& a, const CPoolInfo& b) const
    {
        if (a.first.nHeight != b.first.nHeight)
            return a.first.nHeight < b.first.nHeight;
        if (a.first.nTx != b.first.nTx)
            return a.first.nTx < b.first.nTx;
        return a.first.nOut < b.first.nOut;
    }
};
}

void CPoolRegistry::List(std::vector<CPoolInfo>& out) const
{
    out.clear();
    uint256 zero = ZeroId();
    CPoolInfo z;
    std::map<uint256, CPoolEntry>::const_iterator iz = mapPools.find(zero);
    Fill(zero, iz == mapPools.end() ? NULL : &iz->second, z);
    out.push_back(z);
    std::vector<CPoolInfo> v;
    for (std::map<uint256, CPoolEntry>::const_iterator it = mapPools.begin(); it != mapPools.end(); ++it)
    {
        if (it->first == zero)
            continue;
        CPoolInfo info;
        Fill(it->first, &it->second, info);
        v.push_back(info);
    }
    // Two pools never share a first appearance: one output is one record.
    std::sort(v.begin(), v.end(), FirstAppearanceOrder());
    out.insert(out.end(), v.begin(), v.end());
}

bool CPoolRegistry::Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const
{
    out.clear();
    std::map<uint256, CPoolEntry>::const_iterator it = mapPools.find(id);
    if (it == mapPools.end())
        return false;
    out = it->second.vAppear;
    return true;
}

uint256 CPoolRegistry::Digest() const
{
    CDataStream ss(SER_GETHASH);
    ss << FLATDATA(magic) << nHeight << hashTip;
    ss << (unsigned int)mapPools.size();
    for (std::map<uint256, CPoolEntry>::const_iterator it = mapPools.begin(); it != mapPools.end(); ++it)
        ss << it->first << it->second.record << it->second.vAppear;
    // Of the anchors, only what is answered: the newest 64 that count and the
    // count in the window, for every id that has any that count.
    unsigned int nIds = 0;
    for (std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.begin(); it != mapAnchors.end(); ++it)
        if (FirstCounted(it->second.v) < it->second.v.size())
            nIds++;
    ss << nIds;
    for (std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.begin(); it != mapAnchors.end(); ++it)
    {
        if (FirstCounted(it->second.v) == it->second.v.size())
            continue;
        std::vector<CPoolAnchor> vRecent;
        int nInWindow = 0;
        Anchors(it->first, vRecent, nInWindow);
        ss << it->first << vRecent << nInWindow;
    }
    return Hash(ss.begin(), ss.end());
}

bool CPoolRegistry::CheckConsistent(std::string& whyOut) const
{
    if (!fInit)
        return (whyOut = "no network"), false;
    if (nHeight < -1 || (nHeight == -1) != (hashTip == 0))
        return (whyOut = "tip"), false;
    if (nPurgedTop < -1 || nPurgedTop > nHeight)
        return (whyOut = "purge height"), false;
    for (std::map<uint256, CPoolEntry>::const_iterator it = mapPools.begin(); it != mapPools.end(); ++it)
    {
        const CPoolEntry& e = it->second;
        std::string err;
        poolreg::PoolRecord rec;
        if (!poolreg::Parse(e.record, rec, err) || rec.fLocal)
            return (whyOut = "a record that does not parse"), false;
        if (IdOf(e.record, magic) != it->first)
            return (whyOut = "a pool under another id"), false;
        if (e.vAppear.empty())
            return (whyOut = "a pool with no appearance"), false;
        for (size_t i = 0; i < e.vAppear.size(); i++)
        {
            const CPoolAppearance& a = e.vAppear[i];
            if (a.nHeight < 0 || a.nHeight > nHeight || a.nBurn < poolreg::MIN_BURN || !MoneyRange(a.nBurn))
                return (whyOut = "an appearance out of range"), false;
            if (i > 0)
            {
                const CPoolAppearance& p = e.vAppear[i - 1];
                bool fAfter = p.nHeight < a.nHeight ||
                              (p.nHeight == a.nHeight && (p.nTx < a.nTx || (p.nTx == a.nTx && p.nOut < a.nOut)));
                if (!fAfter)
                    return (whyOut = "appearances out of order"), false;
            }
        }
    }
    for (std::map<uint256, CPoolAnchorSet>::const_iterator it = mapAnchors.begin(); it != mapAnchors.end(); ++it)
    {
        const CPoolAnchorSet& set = it->second;
        if (set.nTrimmedTop < -1 || set.nTrimmedTop > nHeight || (set.v.empty() && set.nTrimmedTop < 0))
            return (whyOut = "an anchor set out of range"), false;
        size_t nFirst = FirstCounted(set.v);
        for (size_t i = 0; i < set.v.size(); i++)
        {
            const CPoolAnchor& a = set.v[i];
            if (a.nHeight < 0 || a.nHeight > nHeight || a.nHeight <= set.nTrimmedTop)
                return (whyOut = "an anchor out of range"), false;
            if (i > 0 && set.v[i - 1].nHeight >= a.nHeight)
                return (whyOut = "anchors out of order"), false;
            if (i < nFirst)
            {
                if (a.nDroppedAt > nHeight || a.nDroppedAt % POOL_ANCHOR_SWEEP_INTERVAL != 0 ||
                    a.nHeight > a.nDroppedAt - POOL_UNREGISTERED_ANCHOR_BLOCKS)
                    return (whyOut = "a dropped anchor out of range"), false;
            }
            else if (a.nDroppedAt != -1)
                return (whyOut = "a dropped anchor after one that counts"), false;
        }
    }
    for (size_t i = 0; i < vLocator.size(); i++)
    {
        const CPoolLocatorEntry& l = vLocator[i];
        if (l.nHeight < 0 || l.nHeight > nHeight || l.hash == 0 || (i > 0 && vLocator[i - 1].nHeight >= l.nHeight))
            return (whyOut = "the locator"), false;
    }
    return true;
}


//
// The index: the registry in step with the active chain, and in a file.
//

static bool ReadBlockFromDisk(const CBlockIndex* pindex, CBlock& block)
{
    if (!block.ReadFromDisk(pindex, true))
        return false;
    // The file position is the index's; a block that is not the one it
    // names is a damaged file, not a block to read records from.
    return block.GetHash() == pindex->GetBlockHash();
}

CPoolIndex::CPoolIndex(PoolIndexReadFn fnReadIn)
    : fShadow(false), fnRead(fnReadIn ? fnReadIn : ReadBlockFromDisk), nRebuilds(0), fReadFailLogged(false),
      fStop(false)
{
}

bool CPoolIndex::Stopping() const
{
    return fShutdown || fStop;
}

void CPoolIndex::SetPath(const std::string& strPathIn)
{
    CRITICAL_BLOCK(cs)
        strPath = strPathIn;
}

void CPoolIndex::EnsureInitLocked() const
{
    // The registry is born with the network's message start: before it is,
    // there is no pool zero id to answer with.
    if (!reg.Initialized())
        const_cast<CPoolRegistry&>(reg).Reset((const unsigned char*)pchMessageStart);
}

// Read the chain again from genesis. While that goes on, the registry this
// node had keeps answering (it is a reading of the chain a few blocks or a
// reorg ago, not nothing); the new one takes its place at the tip.
void CPoolIndex::StartOverLocked(const unsigned char magicNet[4])
{
    nRebuilds++;
    if (fShadow || reg.Height() >= 0)
    {
        fShadow = true;
        shadow.Reset(magicNet);
    }
    else
        reg.Reset(magicNet);
}

bool CPoolIndex::Load()
{
    std::string path;
    CRITICAL_BLOCK(cs)
        path = strPath;
    if (path.empty())
        return false;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
        return false;
    std::vector<char> buf;
    char tmp[65536];
    size_t n;
    bool fTooBig = false;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
    {
        if (buf.size() + n > POOL_INDEX_FILE_MAX)
        {
            fTooBig = true;
            break;
        }
        buf.insert(buf.end(), tmp, tmp + n);
    }
    fclose(f);

    std::string why;
    CPoolRegistry r;
    if (fTooBig)
        why = "too large";
    else if (buf.size() < 4 + 32)
        why = "too short";
    else
    {
        uint256 hashFile = 0;
        memcpy(hashFile.begin(), &buf[buf.size() - 32], 32);
        if (Hash(buf.begin(), buf.end() - 32) != hashFile)
            why = "checksum";
        else
        {
            try
            {
                CDataStream ss(&buf[0], &buf[0] + buf.size() - 32, SER_DISK);
                int nVersion = 0;
                ss >> nVersion;
                if (nVersion != POOL_INDEX_FILE_VERSION)
                    why = "another version";
                else
                {
                    ss >> r;
                    if (!ss.empty())
                        why = "trailing bytes";
                    else if (!r.HasMagic((const unsigned char*)pchMessageStart))
                        why = "another network";
                    else if (!r.CheckConsistent(why))
                        why = "inconsistent: " + why;
                }
            }
            catch (std::exception& e)
            {
                why = "unreadable";
            }
        }
    }
    if (!why.empty())
    {
        printf("pool index: pool-registry.dat not used (%s); reading the chain again\n", why.c_str());
        return false;
    }
    CRITICAL_BLOCK(cs)
    {
        reg = r;
        fShadow = false;
        shadow = CPoolRegistry();
    }
    printf("pool index: read pool-registry.dat, %u pool(s) up to block %d\n",
           (unsigned int)r.PoolCount(), r.Height());
    return true;
}

bool CPoolIndex::Save()
{
    std::string path;
    CDataStream ss(SER_DISK);
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        path = strPath;
        ss << POOL_INDEX_FILE_VERSION << reg;
    }
    if (path.empty())
        return false;
    uint256 h = Hash(ss.begin(), ss.end());
    std::string data(ss.begin(), ss.end());
    data.append((const char*)h.begin(), 32);
    std::string err;
    if (!WriteFileAtomicPrivate(path, data, err))
    {
        printf("pool index: %s\n", err.c_str());
        return false;
    }
    return true;
}

// A block index entry for this hash at this height, if this node has one.
static CBlockIndex* KnownBlock(const uint256& hash, int nHeight)
{
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi == mapBlockIndex.end() || mi->second->nHeight != nHeight)
        return NULL;
    return mi->second;
}

int CPoolIndex::Step(unsigned int nMaxBlocks, bool& fSyncedOut)
{
    fSyncedOut = false;
    CRITICAL_BLOCK(csStep)
    {
        const unsigned char* magicNet = (const unsigned char*)pchMessageStart;
        // What is being read: the registry, or the one read again beside it.
        bool fShadowNow = false;
        uint256 hashLast = 0;
        int nLast = -1;
        std::vector<CPoolLocatorEntry> vLoc;
        CRITICAL_BLOCK(cs)
        {
            EnsureInitLocked();
            if (!reg.HasMagic(magicNet))
            {
                // Another network: nothing of the old registry is an answer.
                printf("pool index: the network changed; reading the chain again\n");
                reg.Reset(magicNet);
                fShadow = false;
                shadow = CPoolRegistry();
                nRebuilds++;
                return 1;
            }
            fShadowNow = fShadow;
            const CPoolRegistry& t = fShadow ? shadow : reg;
            hashLast = t.TipHash();
            nLast = t.Height();
            vLoc = t.Locator();
        }

        // Where the index meets the active chain, and what follows it.
        std::vector<CBlockIndex*> vTodo;
        bool fAtTip = false, fReset = false;
        int nFork = -1;
        uint256 hashFork = 0;
        CRITICAL_BLOCK(cs_main)
        {
            if (!pindexBest || !pindexGenesisBlock)
                return 0;
            if (nLast >= 0 && hashLast == pindexBest->GetBlockHash())
                fAtTip = true;
            else
            {
                CBlockIndex* pFork = NULL;
                if (nLast >= 0)
                {
                    pFork = KnownBlock(hashLast, nLast);
                    // A tip this node no longer knows (its block index lost
                    // the last blocks in an unclean stop): the newest block
                    // before it that it does know.
                    for (size_t i = vLoc.size(); !pFork && i-- > 0; )
                        pFork = KnownBlock(vLoc[i].hash, vLoc[i].nHeight);
                    while (pFork && !pFork->IsInMainChain())
                        pFork = pFork->pprev;
                    // None at all (another chain, a block index read again
                    // from nothing): the fold starts over.
                    if (!pFork)
                        fReset = true;
                }
                if (pFork)
                {
                    nFork = pFork->nHeight;
                    hashFork = pFork->GetBlockHash();
                }
                if (!fReset)
                    for (CBlockIndex* p = pFork ? pFork->pnext : pindexGenesisBlock; p && vTodo.size() < nMaxBlocks; p = p->pnext)
                        vTodo.push_back(p);
            }
        }

        int nChanged = 0;
        CRITICAL_BLOCK(cs)
        {
            CPoolRegistry& t = fShadow ? shadow : reg;
            if (fShadow != fShadowNow || t.TipHash() != hashLast || t.Height() != nLast)
                return 0;
            if (fAtTip)
            {
                if (fShadow)
                {
                    printf("pool index: read the chain again up to block %d\n", shadow.Height());
                    reg = shadow;
                    shadow = CPoolRegistry();
                    fShadow = false;
                    return 1;
                }
                fSyncedOut = true;
                return 0;
            }
            if (fReset)
            {
                printf("pool index: block %d is not in this node's chain; reading the chain again\n", nLast);
                StartOverLocked(magicNet);
                return 1;
            }
            if (nFork < nLast)
            {
                nChanged++;
                if (!t.DisconnectAbove(nFork, hashFork))
                {
                    // Deeper than the margin: what is left is not exact.
                    printf("pool index: reorg below block %d, deeper than the index keeps; reading the chain again\n",
                           nFork + 1);
                    StartOverLocked(magicNet);
                    return nChanged;
                }
            }
        }

        bool fMoved = false;
        for (size_t i = 0; i < vTodo.size() && !Stopping(); i++)
        {
            CBlock block;
            bool fRead = false;
            std::string strWhy;
            try
            {
                fRead = fnRead(vTodo[i], block);
            }
            catch (std::exception& e)
            {
                strWhy = e.what();
            }
            catch (...)
            {
                strWhy = "unknown exception";
            }
            if (!fRead)
            {
                if (!fReadFailLogged)
                    printf("pool index: cannot read block %d%s%s; trying again later\n", vTodo[i]->nHeight,
                           strWhy.empty() ? "" : ": ", strWhy.c_str());
                fReadFailLogged = true;
                return nChanged > 0 ? nChanged : -1;
            }
            fReadFailLogged = false;
            // The chain may have moved while the block was read: a block no
            // longer on it ends the pass, and the next one finds the fork.
            bool fMain = false;
            CRITICAL_BLOCK(cs_main)
                fMain = vTodo[i]->IsInMainChain();
            if (!fMain)
            {
                fMoved = true;
                break;
            }
            bool fOk = false;
            CRITICAL_BLOCK(cs)
            {
                CPoolRegistry& t = fShadow ? shadow : reg;
                fOk = t.ConnectBlock(block, vTodo[i]->nHeight, vTodo[i]->GetBlockHash());
            }
            if (!fOk)
                break;
            nChanged++;
        }
        if (fMoved && nChanged == 0)
            return 1;
        return nChanged;
    }
    return 0;
}

CPoolRegistry CPoolIndex::Snapshot() const
{
    CPoolRegistry r;
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        r = reg;
    }
    return r;
}

int CPoolIndex::Height() const
{
    int n = -1;
    CRITICAL_BLOCK(cs)
        n = reg.Height();
    return n;
}

uint256 CPoolIndex::TipHash() const
{
    uint256 h = 0;
    CRITICAL_BLOCK(cs)
        h = reg.TipHash();
    return h;
}

void CPoolIndex::Tip(int& nHeightOut, uint256& hashOut) const
{
    CRITICAL_BLOCK(cs)
    {
        nHeightOut = reg.Height();
        hashOut = reg.TipHash();
    }
}

bool CPoolIndex::Lookup(const uint256& id, CPoolInfo& out) const
{
    bool f = false;
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        f = reg.Lookup(id, out);
    }
    return f;
}

void CPoolIndex::List(std::vector<CPoolInfo>& out) const
{
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        reg.List(out);
    }
}

int CPoolIndex::Status(const uint256& id) const
{
    int n = POOL_UNKNOWN;
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        n = reg.Status(id);
    }
    return n;
}

bool CPoolIndex::Appearances(const uint256& id, std::vector<CPoolAppearance>& out) const
{
    bool f = false;
    CRITICAL_BLOCK(cs)
        f = reg.Appearances(id, out);
    return f;
}

void CPoolIndex::Anchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow) const
{
    CRITICAL_BLOCK(cs)
        reg.Anchors(id, vRecent, nInWindow);
}

uint256 CPoolIndex::Digest() const
{
    uint256 h = 0;
    CRITICAL_BLOCK(cs)
    {
        EnsureInitLocked();
        h = reg.Digest();
    }
    return h;
}

int CPoolIndex::Rebuilds() const
{
    int n = 0;
    CRITICAL_BLOCK(cs)
        n = nRebuilds;
    return n;
}

bool CPoolIndex::Rebuilding() const
{
    bool f = false;
    CRITICAL_BLOCK(cs)
        f = fShadow;
    return f;
}


//
// The node's index and its thread.
//

CPoolIndex& PoolIndex()
{
    static CPoolIndex index;
    return index;
}

bool fPoolIndexAutoStart = true;
static std::atomic<bool> g_fPoolIndexRunning(false);

static void ThreadPoolIndex(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadPoolIndex(parg));
    CPoolIndex& idx = PoolIndex();
    int64 nLastSave = GetTime();
    int nUnsaved = 0;
    int nFailures = 0;
    try
    {
        idx.Load();
    }
    catch (std::exception& e) { printf("pool index: reading the file: %s\n", e.what()); }
    catch (...)               { printf("pool index: reading the file: unknown exception\n"); }
    while (!idx.Stopping())
    {
        // One pass at a time in its own try: whatever one block or one
        // file does, the thread goes on and the next pass tries again.
        int n = 0;
        bool fSynced = false;
        try
        {
            n = idx.Step(1000, fSynced);
        }
        catch (std::exception& e)
        {
            printf("pool index: %s; trying again later\n", e.what());
            n = -1;
        }
        catch (...)
        {
            printf("pool index: unknown exception; trying again later\n");
            n = -1;
        }
        if (n > 0)
            nUnsaved += n;
        nFailures = (n < 0) ? nFailures + 1 : 0;
        int64 nNow = GetTime();
        // At the tip, soon after a change; while reading the chain, now and
        // then, so a restart does not start over. A save that fails is tried
        // again at the next interval.
        bool fSave = nUnsaved > 0 &&
                     ((n <= 0 && nNow - nLastSave >= 10) || nUnsaved >= 20000 || nNow - nLastSave >= 120);
        if (fSave)
        {
            bool fSaved = false;
            try
            {
                fSaved = idx.Save();
            }
            catch (std::exception& e) { printf("pool index: saving: %s\n", e.what()); }
            if (fSaved)
                nUnsaved = 0;
            nLastSave = nNow;
        }
        if (n > 0)
        {
            // More to read: a breath between passes for the rest of the
            // node, which wants cs_main too.
            Sleep(20);
            continue;
        }
        // At the tip, a look every second; after failures, 5 s doubling up
        // to 5 minutes.
        int nTenths = 10;
        if (n < 0)
            nTenths = 10 * std::min(300, 5 << std::min(nFailures - 1, 6));
        for (int i = 0; i < nTenths && !idx.Stopping(); i++)
            Sleep(100);
    }
    if (nUnsaved > 0)
    {
        try
        {
            idx.Save();
        }
        catch (std::exception& e) { printf("pool index: saving: %s\n", e.what()); }
    }
    g_fPoolIndexRunning = false;
}

void PoolIndexStart()
{
#ifdef BITFLASH_FUZZ
    // The fuzzers drive the node's handlers, not its background readers.
    return;
#else
    static bool fStarted = false;
    if (fStarted || !fPoolIndexAutoStart)
        return;
    fStarted = true;
    PoolIndex().SetPath(GetAppDir() + "/pool-registry.dat");
    PoolIndex().ClearStop();
    g_fPoolIndexRunning = true;
    if (_beginthread(ThreadPoolIndex, 0, NULL) == (uintptr_t)-1)
    {
        g_fPoolIndexRunning = false;
        printf("Error: _beginthread(ThreadPoolIndex) failed\n");
    }
#endif
}

void PoolIndexStop()
{
    PoolIndex().RequestStop();
    for (int i = 0; i < 300 && g_fPoolIndexRunning; i++)
        Sleep(100);
}

bool PoolIndexLookup(const uint256& id, CPoolInfo& out)
{
    return PoolIndex().Lookup(id, out);
}

void PoolIndexList(std::vector<CPoolInfo>& out)
{
    PoolIndex().List(out);
}

int PoolIndexStatus(const uint256& id)
{
    return PoolIndex().Status(id);
}

bool PoolIndexAppearances(const uint256& id, std::vector<CPoolAppearance>& out)
{
    return PoolIndex().Appearances(id, out);
}

void PoolIndexAnchors(const uint256& id, std::vector<CPoolAnchor>& vRecent, int& nInWindow)
{
    PoolIndex().Anchors(id, vRecent, nInWindow);
}

int PoolIndexHeight()
{
    return PoolIndex().Height();
}

bool PoolIndexSynced()
{
    // The index's tip under its lock, then the chain's under cs_main: never
    // both locks at once.
    int nHeight = -1;
    uint256 hash = 0;
    PoolIndex().Tip(nHeight, hash);
    if (nHeight < 0)
        return false;
    bool fSynced = false;
    CRITICAL_BLOCK(cs_main)
        fSynced = pindexBest && pindexBest->GetBlockHash() == hash;
    return fSynced;
}
