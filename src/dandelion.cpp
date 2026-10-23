// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#ifdef BITFLASH_DANDELION_PURE
#include "dandelion.h"
#else
#include "headers.h"
#include "dandelion.h"
#endif

#include <algorithm>

namespace dandelion
{

void Router::NewEpoch(int64_t nNow, const std::vector<uint64_t>& vCandidates, const std::vector<uint64_t>& vRandom)
{
    nEpochStart = nNow ? nNow : 1;
    mapRoute.clear();
    vRelays.clear();
    std::vector<uint64_t> pool = vCandidates;
    for (size_t i = 0; i < RELAYS_PER_EPOCH && !pool.empty(); i++)
    {
        size_t k = (size_t)((i < vRandom.size() ? vRandom[i] : 0) % pool.size());
        vRelays.push_back(pool[k]);
        pool.erase(pool.begin() + k);
    }
}

uint64_t Router::RelayFor(uint64_t from, uint64_t r)
{
    std::map<uint64_t, uint64_t>::iterator it = mapRoute.find(from);
    if (it == mapRoute.end())
    {
        // Never back to whoever handed it to us.
        std::vector<uint64_t> choices;
        for (size_t i = 0; i < vRelays.size(); i++)
            if (vRelays[i] != from)
                choices.push_back(vRelays[i]);
        uint64_t relay = choices.empty() ? 0 : choices[r % choices.size()];
        it = mapRoute.insert(std::make_pair(from, relay)).first;
    }
    return it->second;
}

} // namespace dandelion

#ifndef BITFLASH_DANDELION_PURE

using namespace dandelion;

static CCriticalSection cs_dandelion;
static Router g_router;

// Transactions this node put in a stem, with the time it fluffs them itself
// unless someone else has by then.
struct StemTx
{
    CTransaction tx;
    int64 nEmbargo;
};
static map<uint256, StemTx> mapStem;
static const size_t MAX_STEM = 1000;

static uint64_t PeerId(CNode* p)
{
    return (uint64_t)(uintptr_t)p;
}

// A relay of this epoch, if it is still connected. Under cs_vNodes.
static CNode* RelayNode(uint64_t id)
{
    foreach(CNode* pnode, vNodes)
        if (PeerId(pnode) == id && pnode->fDandelion && !pnode->fDisconnect)
            return pnode;
    return NULL;
}

// A new epoch when the old one is over or a relay of it has gone.
static void RenewEpochIfDue()
{
    bool fDue = g_router.EpochOver(GetTime());
    vector<uint64_t> vCandidates;
    CRITICAL_BLOCK(cs_vNodes)
    {
        for (size_t i = 0; i < g_router.Relays().size() && !fDue; i++)
            if (!RelayNode(g_router.Relays()[i]))
                fDue = true;
        if (!fDue)
            return;
        // Outbound only: an inbound peer chose us, and could have been placed
        // to catch what we send.
        foreach(CNode* pnode, vNodes)
            if (pnode->fDandelion && !pnode->fInbound && !pnode->fDisconnect)
                vCandidates.push_back(PeerId(pnode));
    }
    vector<uint64_t> vRandom;
    for (unsigned int i = 0; i < RELAYS_PER_EPOCH; i++)
        vRandom.push_back(GetRand(~(uint64)0));
    g_router.NewEpoch(GetTime(), vCandidates, vRandom);
    LogPrint("dandelion", "dandelion: new epoch, %u relay(s) from %u candidate(s)\n",
             (unsigned)g_router.Relays().size(), (unsigned)vCandidates.size());
}

static void Fluff(const CTransaction& tx)
{
    RelayMessage(CInv(MSG_TX, tx.GetHash()), tx);
}

// Into the stem, toward the epoch's relay for 'from' (0: our own), or
// fluffed when there is none. Under cs_dandelion.
static void Stem(const CTransaction& tx, uint64_t from)
{
    uint256 hash = tx.GetHash();
    if (mapStem.count(hash))
        return;
    uint64_t relay = mapStem.size() < MAX_STEM ? g_router.RelayFor(from, GetRand(~(uint64)0)) : 0;
    CNode* pRelay = NULL;
    if (relay)
        CRITICAL_BLOCK(cs_vNodes)
            if ((pRelay = RelayNode(relay)) != NULL)
                pRelay->PushMessage("stemtx", tx);
    if (!pRelay)
    {
        Fluff(tx);
        return;
    }
    StemTx st;
    st.tx = tx;
    st.nEmbargo = GetTime() + EMBARGO_MIN_SECONDS + (int64)GetRand(EMBARGO_SPREAD_SECONDS + 1);
    mapStem[hash] = st;
    LogPrint("dandelion", "dandelion: %s into the stem%s\n", hash.ToString().substr(0, 10).c_str(),
             from ? "" : " (ours)");
}

void DandelionRelayOwn(const CTransaction& tx)
{
    CRITICAL_BLOCK(cs_dandelion)
    {
        RenewEpochIfDue();
        // Our own always goes into the stem first: fluffing it here would
        // make this node the first to announce it.
        Stem(tx, 0);
    }
}

void DandelionOnVersion(CNode* pfrom)
{
    pfrom->PushMessage("stemok");
}

void DandelionSeenFluffed(const uint256& hash)
{
    CRITICAL_BLOCK(cs_dandelion)
        mapStem.erase(hash);
}

void DandelionTick()
{
    static int64 nLast = 0;
    if (GetTime() == nLast)
        return;
    nLast = GetTime();
    vector<CTransaction> vDue;
    CRITICAL_BLOCK(cs_dandelion)
    {
        RenewEpochIfDue();
        for (map<uint256, StemTx>::iterator it = mapStem.begin(); it != mapStem.end();)
        {
            if (it->second.nEmbargo <= GetTime())
            {
                vDue.push_back(it->second.tx);
                mapStem.erase(it++);
            }
            else
                ++it;
        }
    }
    // A stem that died on the way: fluff it ourselves, so it is never lost.
    foreach(const CTransaction& tx, vDue)
    {
        LogPrint("dandelion", "dandelion: %s embargo over, fluffing\n", tx.GetHash().ToString().substr(0, 10).c_str());
        Fluff(tx);
    }
}

bool DandelionProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "stemok")
    {
        pfrom->fDandelion = true;
        return true;
    }
    if (strCommand != "stemtx")
        return false;

    CTransaction tx;
    vRecv >> tx;
    if (tx.IsCoinBase())
    {
        pfrom->Misbehaving(100);
        return true;
    }
    uint256 hash = tx.GetHash();
    CTxDB txdb("r");
    if (mapTransactions.count(hash) || txdb.ContainsTx(hash))
        return true;   // already have it: a loop in the stem, or it fluffed
    bool fMissingInputs = false;
    if (!tx.AcceptTransaction(txdb, true, &fMissingInputs))
    {
        // An orphan cannot be judged; anything else was invalid.
        if (!fMissingInputs)
            pfrom->Misbehaving(10);
        return true;
    }
    CRITICAL_BLOCK(cs_dandelion)
    {
        RenewEpochIfDue();
        if (Router::Fluff((unsigned int)GetRand(100)))
            Fluff(tx);
        else
            Stem(tx, PeerId(pfrom));
    }
    return true;
}

#endif
