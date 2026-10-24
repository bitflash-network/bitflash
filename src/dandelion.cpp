// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#ifdef BITFLASH_DANDELION_PURE
#include "dandelion.h"
#else
#include "headers.h"
#include "dandelion.h"
#include "proxy.h"
#include "sockcount.h"
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

static void StemOwn(const CTransaction& tx)
{
    CRITICAL_BLOCK(cs_dandelion)
    {
        RenewEpochIfDue();
        // Our own always goes into the stem first: fluffing it here would
        // make this node the first to announce it.
        Stem(tx, 0);
    }
}

// ---------------------------------------------------------------------------
// One connection per transaction.
//
// A stem hides which node wrote a transaction, but every stem hop of ours
// leaves over a long-lived connection, and our relay sees all of them: two
// payments from this wallet reach it over the same connection, from the same
// .btf identity, and can be tied together. So, with Tor, our own transaction
// does not leave over any connection we keep. A few seconds after the wallet
// makes it, a connection is opened for it alone, on a Tor circuit of its own
// (fresh SOCKS credentials, so Tor shares the circuit with nothing), to a peer
// picked at random. It carries a version message, which every connection
// starts with, and the transaction -- no descriptor, no peer list, nothing
// that names this node -- and closes. The peer sees a stranger hand it a stem
// transaction, which is what every stem hop looks like.

static CCriticalSection cs_oneshot;
static set<uint256> setOneShotPending;

static void SetRecvTimeoutMs(SOCKET s, int nMs)
{
#ifdef _WIN32
    DWORD tv = (DWORD)nMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = nMs / 1000;
    tv.tv_usec = (nMs % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

static bool SendAll(SOCKET s, CNode& node)
{
    CDataStream vOut(SER_NETWORK);
    CRITICAL_BLOCK(node.cs_vSend)
    {
        vOut = node.vSend;
        node.vSend.clear();
    }
    const char* p = vOut.empty() ? NULL : &vOut[0];
    size_t nLeft = vOut.size();
    while (nLeft > 0)
    {
        int r = send(s, p, (int)nLeft, BTF_SEND_FLAGS);
        if (r <= 0)
            return false;
        p += r;
        nLeft -= r;
    }
    return true;
}

bool DandelionSendOneShot(const vector<CTransaction>& vtx, const string& strHost, unsigned short nPort,
                          const CAddress& addrYou, const string& strIsolation, string& strHow)
{
    strHow = "connect failed";
    SOCKET s = BtfConnectSocketIsolated(strHost, nPort, SOCK_ONION_PEER, ONESHOT_CONNECT_SECONDS,
                                        strIsolation);
    if (s == INVALID_SOCKET)
        return false;

    // Not in vNodes: nothing the node sends to its peers -- inventory, peer
    // lists, chat, shares -- can reach this connection. The CNode only frames
    // messages; the socket stays ours.
    CNode node(INVALID_SOCKET, addrYou, false);
    bool fOk = SendAll(s, node);
    SetRecvTimeoutMs(s, 1000);

    vector<char> vBuf;
    int nRecvVersion = PROTO_NO_CHECKSUM_VERSION;
    int64 nStart = GetTime(), nVersionAt = 0;
    bool fStemOk = false, fSent = false;
    size_t nRead = 0;
    while (fOk && !fShutdown && !fSent && GetTime() - nStart < ONESHOT_HANDSHAKE_SECONDS)
    {
        char buf[4096];
        int r = recv(s, buf, sizeof(buf), 0);
        if (r == 0)
        {
            strHow = "peer closed";
            fOk = false;
            break;
        }
        if (r < 0)
        {
            // The one-second receive timeout is how this loop ticks; any
            // other error is the end of the connection.
            int nErr = WSAGetLastError();
#ifdef _WIN32
            bool fTick = nErr == WSAETIMEDOUT || nErr == WSAEWOULDBLOCK;
#else
            bool fTick = nErr == EAGAIN || nErr == EWOULDBLOCK || nErr == EINTR;
#endif
            if (!fTick)
            {
                strHow = strprintf("receive error %d", nErr);
                fOk = false;
                break;
            }
        }
        if (r > 0)
        {
            vBuf.insert(vBuf.end(), buf, buf + r);
            nRead += r;
            if (nRead > ONESHOT_MAX_READ)
            {
                strHow = "peer sent too much";
                fOk = false;
                break;
            }
        }
        // Whole messages off the front of the buffer. Only two matter: the
        // peer's version (it fixes the framing from here on) and "stemok".
        for (;;)
        {
            unsigned int nHeader = CMessageHeader::SizeOnWire(nRecvVersion);
            if (vBuf.size() < nHeader)
                break;
            CMessageHeader hdr;
            CDataStream ssHdr(&vBuf[0], &vBuf[0] + nHeader, SER_NETWORK, nRecvVersion);
            ssHdr >> hdr;
            if (!hdr.IsValid())
            {
                strHow = "bad message from peer";
                fOk = false;
                break;
            }
            if (vBuf.size() < nHeader + hdr.nMessageSize)
                break;
            string strCommand = hdr.GetCommand();
            if (strCommand == "version" && nVersionAt == 0 && hdr.nMessageSize >= 4)
            {
                int nPeerVersion = 0;
                memcpy(&nPeerVersion, &vBuf[nHeader], 4);
                if (nPeerVersion <= 0)
                {
                    strHow = "bad version from peer";
                    fOk = false;
                    break;
                }
                nRecvVersion = min(nPeerVersion, VERSION);
                CRITICAL_BLOCK(node.cs_vSend)
                    node.vSend.SetVersion(nRecvVersion);
                nVersionAt = GetTime();
            }
            else if (strCommand == "stemok")
                fStemOk = true;
            vBuf.erase(vBuf.begin(), vBuf.begin() + nHeader + hdr.nMessageSize);
        }
        // A node from before Dandelion never says stemok: after a short wait
        // it gets the transaction the old way, and announces it itself.
        if (fOk && nVersionAt && (fStemOk || GetTime() - nVersionAt >= ONESHOT_STEMOK_WAIT_SECONDS))
        {
            // In order: a parent the peer has not seen must come before the
            // child that spends it, or the child is an orphan there.
            foreach(const CTransaction& tx, vtx)
                node.PushMessage(fStemOk ? "stemtx" : "tx", tx);
            fOk = SendAll(s, node);
            fSent = fOk;
            strHow = fStemOk ? "stem" : "tx (peer predates Dandelion)";
        }
    }
    if (fOk && !fSent)
        strHow = nVersionAt ? "timed out" : "no version from peer";
    if (fSent)
    {
        // Give Tor a moment to carry the last bytes before the stream ends.
        for (int i = 0; i < 4 && !fShutdown; i++)
        {
            char buf[4096];
            if (recv(s, buf, sizeof(buf), 0) == 0)
                break;
        }
    }
    BtfCloseSocket(s);
    return fSent;
}

static void ThreadOneShot(void* parg)
{
    vector<CTransaction> vtx = *(vector<CTransaction>*)parg;
    delete (vector<CTransaction>*)parg;
    uint256 hash = vtx.back().GetHash();

    // Not the instant the wallet made it: a transaction that appears the
    // moment someone clicks Send says when they clicked.
    int64 nWake = GetTime() + ONESHOT_DELAY_MIN_SECONDS + (int64)GetRand(ONESHOT_DELAY_SPREAD_SECONDS + 1);
    while (!fShutdown && GetTime() < nWake)
        Sleep(250);

    bool fSent = false;
    set<string> setTried;
    for (int i = 0; i < ONESHOT_TRIES && !fShutdown && !fSent; i++)
    {
        string strBtfAddr, strOnion, strHost, strHow;
        CAddress addrYou;
        if (!BtfPickBroadcastPeer(setTried, strBtfAddr, strOnion, addrYou))
            break;
        setTried.insert(strBtfAddr);
        size_t colon = strOnion.rfind(':');
        if (colon == string::npos)
            continue;
        strHost = strOnion.substr(0, colon);
        unsigned short nPort = (unsigned short)atoi(strOnion.substr(colon + 1).c_str());
        unsigned char rnd[16];
        RAND_bytes(rnd, sizeof(rnd));
        string strIsolation = HexStr(rnd, rnd + sizeof(rnd), false);
        fSent = DandelionSendOneShot(vtx, strHost, nPort, addrYou, strIsolation, strHow);
        LogPrint("dandelion", "dandelion: %s%s over its own circuit to %.12s...: %s\n",
                 hash.ToString().substr(0, 10).c_str(),
                 vtx.size() > 1 ? strprintf(" (+%u parent)", (unsigned)vtx.size() - 1).c_str() : "",
                 strBtfAddr.c_str(), strHow.c_str());
    }

    foreach(const CTransaction& tx, vtx)
    {
        if (fSent)
        {
            // The stem it went into may die like any other; then it is ours
            // to fluff once the embargo runs out.
            CRITICAL_BLOCK(cs_dandelion)
            {
                uint256 h = tx.GetHash();
                if (!mapStem.count(h) && mapStem.size() < MAX_STEM)
                {
                    StemTx st;
                    st.tx = tx;
                    st.nEmbargo = GetTime() + EMBARGO_MIN_SECONDS + (int64)GetRand(EMBARGO_SPREAD_SECONDS + 1);
                    mapStem[h] = st;
                }
            }
        }
        else if (!fShutdown)
            StemOwn(tx);   // no circuit of its own today: the stem we keep
    }

    CRITICAL_BLOCK(cs_oneshot)
        setOneShotPending.erase(hash);
}

void DandelionRelayOwn(const CTransaction& tx, const vector<CTransaction>& vParents)
{
    vector<CTransaction> vtx = vParents;
    vtx.push_back(tx);
    if (!BtfTorProxyEnabled())
    {
        foreach(const CTransaction& t, vtx)
            StemOwn(t);
        return;
    }
    uint256 hash = tx.GetHash();
    CRITICAL_BLOCK(cs_oneshot)
    {
        // The wallet offers its unconfirmed transactions again every ten
        // minutes; one connection at a time for each.
        if (setOneShotPending.count(hash))
            return;
        CRITICAL_BLOCK(cs_dandelion)
            if (mapStem.count(hash))
                return;
        setOneShotPending.insert(hash);
    }
    vector<CTransaction>* pvtx = new vector<CTransaction>(vtx);
    if (_beginthread(ThreadOneShot, 0, pvtx) == (uintptr_t)-1)
    {
        delete pvtx;
        CRITICAL_BLOCK(cs_oneshot)
            setOneShotPending.erase(hash);
        foreach(const CTransaction& t, vtx)
            StemOwn(t);
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
