// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the registered pools' messages (docs/pool-registry.md,
// sections 8 and 17), fed as a peer feeds them: poolinv, p2xshare, p2xgetsh,
// p2xsync, p2xshares, p2xnone, poolwho and poolat, through
// P2PoolProcessMessage(), on an inbound connection or one this node dialled,
// from a peer that says NODE_POOLREG or one that does not.
//
// Two registered pools join at start: pool A, which this node mines and
// whose line is complete (P2PoolMinedChain() is its share chain), and pool
// B, carried with -poolcarry and with nothing of it here, so a poolinv that
// names it and the message thread's pass start a fetch whose parts reach
// AddHistory and the partial-file logic (kept in memory: no files). The
// chains, the registered class's budgets, orphans, serves and per-connection
// state live for the whole run, as in a node. In this binary only
// (-DBITFLASH_FUZZ), fFuzzShareWorkStandIn replaces the RandomX comparison
// with a rule on nNonce (bit 0 clear: the work holds; bit 1 set: it is also
// a block), after the registered work budget is asked.
//
// Input layout:
//   byte 0   flags:
//              bit 0  the peer is inbound (else one this node dialled)
//              bit 1  records 1 to 6 go out with a pool id in front (pool A,
//                     or pool B when bit 3 of the record's kind byte is set);
//                     else the payload is sent as it is, its own first 32
//                     bytes the id
//              bit 2  the peer's version arrives first (P2PoolOnVersion)
//              bit 3  fix up each share's link: height, target and time from
//                     its parent in pool A's chain, a payout script that is
//                     an address
//              bit 4  fix up each share's coinbase to pay its window
//              bit 5  fix up each share's id, anchor and merkle root
//              bit 6  every shared budget full first
//              bit 7  the peer does not say NODE_POOLREG (a 1.2.34 node)
//   then up to 32 records [kind][length, 2 bytes little-endian][payload]:
//     kind % 8: 0 poolinv (the payload as it is), 1 p2xshare, 2 p2xgetsh,
//               3 p2xsync, 4 p2xshares, 5 p2xnone, 6 poolwho (poolat when
//               the payload's first byte is odd, which is then dropped),
//               7 the message thread's pass, made now (fetches, poolinv,
//               paced serves), then, if the payload's first byte is odd, a
//               new connection with the same flags
//
// After every input: pool A's share chain holds ShareChain::CheckInvariants;
// the registered orphan queue its cap; nothing reached pool zero (its share
// chain, orphan queue and held entries stay empty, section 8); a peer
// without NODE_POOLREG was sent no p2x* or pool* message; a peer that never
// announced a pool nor asked for a share by id was pushed no share; and
// nothing is held for a connection once it is gone.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus (a line of
// shares pushed after a poolinv, syncs from resume points, getsh, a fetch of
// pool B answered in parts, strangers) into <dir> and exits.

#include "headers_core.h"
#include "p2pool_net.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <memory>
#include <string>
#include <vector>

static void FuzzP2PRegInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzP2PRegInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using namespace p2pool;

static const unsigned char F_INBOUND = 1;
static const unsigned char F_ID = 2;
static const unsigned char F_VERSION = 4;
static const unsigned char F_FIX_LINK = 8;
static const unsigned char F_FIX_PAY = 16;
static const unsigned char F_FIX_ANCHOR = 32;
static const unsigned char F_REFILL = 64;
static const unsigned char F_OLD = 128;

enum
{
    K_INV = 0, K_SHARE, K_GETSH, K_SYNC, K_SHARES, K_NONE, K_WHO, K_PASS
};
static const char* const kCommands[] = { "poolinv", "p2xshare", "p2xgetsh", "p2xsync", "p2xshares", "p2xnone", "poolwho" };

static uint256 g_idA = 0, g_idB = 0;

// One connection and what the harness knows of it.
struct Conn
{
    std::unique_ptr<CNode> node;
    bool fReg;              // it says NODE_POOLREG
    bool fAnnounced;        // it sent a poolinv
    bool fAsked;            // it sent a p2xgetsh
};

static vector<unsigned char> PayTo(unsigned char tag)
{
    vector<unsigned char> s;
    s.push_back(OP_DUP); s.push_back(OP_HASH160); s.push_back(20);
    for (int i = 0; i < 20; i++) s.push_back((unsigned char)(tag + i));
    s.push_back(OP_EQUALVERIFY); s.push_back(OP_CHECKSIG);
    return s;
}

// The fix-ups (flags 3 to 5), against pool A's chain. Under cs_p2pool.
static void FixShare(Share& s, unsigned char nFlags)
{
    ShareChain& chain = P2PoolMinedChain();
    const PoolRules& rules = chain.Rules();
    ShareData& d = s.data;
    d.fX = true;
    d.fSalt = false;
    if (nFlags & F_FIX_ANCHOR)
        d.poolId = rules.poolId;
    if (nFlags & F_FIX_LINK)
    {
        int nParent = chain.Height(d.hashPrevShare);
        if (d.hashPrevShare == 0)
            d.nShareHeight = 0;
        else if (nParent >= 0)
            d.nShareHeight = nParent + 1;
        d.nShareBits = chain.NextShareBits(d.hashPrevShare);
        unsigned int nMin = chain.NextShareMinTime(d.hashPrevShare);
        if (s.nTime < nMin)
            s.nTime = nMin;
        if ((int64)s.nTime > GetAdjustedTime() + 100)
            s.nTime = (unsigned int)(GetAdjustedTime() + 100);
        if (!IsPayoutScript(d.payoutScript))
            d.payoutScript = PayTo(d.payoutScript.empty() ? 0 : d.payoutScript[0]);
        if (d.vUncles.size() > MAX_UNCLES)
            d.vUncles.resize(MAX_UNCLES);
    }
    int nHeight = 0;
    if (!CoinbaseHeight(s.coinbase, nHeight) || nHeight < 1 || nHeight > MAX_BLOCK_HEIGHT)
        nHeight = 1;
    if (nFlags & F_FIX_PAY)
    {
        vector<WindowShare> window;
        vector<Payout> pay;
        string err;
        int64 nTotal = 0;
        foreach(const CTxOut& o, s.coinbase.vout)
            if (MoneyRange(o.nValue) && MoneyRange(nTotal + o.nValue))
                nTotal += o.nValue;
        nTotal = std::max(nTotal, CBlock().GetBlockValue(nHeight, 0));
        if (chain.WindowFor(d, WorkOf(d.nShareBits), window, err) && ComputePoolPayouts(rules, window, nTotal, pay, err))
        {
            s.coinbase.vout.clear();
            for (size_t i = 0; i < pay.size(); i++)
                s.coinbase.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));
        }
    }
    if (nFlags & F_FIX_ANCHOR)
    {
        s.coinbase.vin.resize(1);
        s.coinbase.vin[0].prevout.SetNull();
        s.coinbase.vin[0].scriptSig = CScript() << nHeight << AnchorPush(rules, d);
        if (s.vMerkleBranch.size() > 32)
            s.vMerkleBranch.resize(32);
        s.hashMerkleRoot = CBlock::CheckMerkleBranch(s.coinbase.GetHash(), s.vMerkleBranch, 0);
    }
}

// p2xshare and p2xshares carry shares after the pool id; the fix-ups apply
// to them. vBody is what follows the id.
static void FixBody(int nKind, CDataStream& vBody, unsigned char nFlags)
{
    if (!(nFlags & (F_FIX_LINK | F_FIX_PAY | F_FIX_ANCHOR)) || (nKind != K_SHARE && nKind != K_SHARES))
        return;
    try
    {
        CDataStream vCopy(vBody);
        CDataStream vFixed(SER_NETWORK, VERSION);
        if (nKind == K_SHARE)
        {
            ShareX s;
            vCopy >> s;
            CRITICAL_BLOCK(cs_p2pool)
                FixShare(s, nFlags);
            vFixed << s;
        }
        else
        {
            int nTip;
            unsigned char nFlag;
            vector<ShareX> v;
            vCopy >> nTip >> nFlag >> v;
            CRITICAL_BLOCK(cs_p2pool)
                for (size_t i = 0; i < v.size(); i++)
                    FixShare(v[i], nFlags);
            vFixed << nTip << nFlag << v;
        }
        if (!vCopy.empty())
            vFixed.write(&vCopy[0], vCopy.size());   // trailing bytes stay
        vBody = vFixed;
    }
    catch (std::exception&)
    {
        // Not what it claims: the bytes go in as they are.
    }
}

static Conn NewConn(unsigned char nFlags)
{
    Conn c;
    c.fReg = !(nFlags & F_OLD);
    c.fAnnounced = false;
    c.fAsked = false;
    c.node.reset(new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), (nFlags & F_INBOUND) != 0));
    CNode* p = c.node.get();
    p->nVersion = VERSION;
    p->nServices = c.fReg ? (NODE_P2POOL | NODE_POOLREG) : NODE_P2POOL;
    p->strBtfAddr = "BF1fuzzpeer";
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    return c;
}

static void EndConn(Conn& c)
{
    // What the budgets held back for it is served or dropped first: the node
    // never frees a peer that is still held. The message thread's pass then
    // sees nothing of it.
    P2PoolServeDeferred();
    P2PoolForgetDeferred(c.node.get());
    c.node.reset();
}

struct Sent
{
    string strCommand;
    vector<unsigned char> payload;
};

// What the node queued for the peer since the last read, message by message;
// the bytes then count as sent, as the socket thread would count them.
static vector<Sent> Drain(CNode* p)
{
    vector<Sent> out;
    CRITICAL_BLOCK(p->cs_vSend)
    {
        CDataStream v(p->vSend);
        try
        {
            while (!v.empty())
            {
                CMessageHeader hdr;
                v >> hdr;
                if (hdr.nMessageSize > v.size())
                    break;
                Sent m;
                m.strCommand = hdr.GetCommand();
                m.payload.assign(v.begin(), v.begin() + hdr.nMessageSize);
                v.ignore(hdr.nMessageSize);
                out.push_back(m);
            }
        }
        catch (std::exception&) {}
        p->nSendDrained += p->vSend.size();
        p->vSend.clear();
    }
    return out;
}

// A peer without NODE_POOLREG is sent nothing of the registry; a peer that
// announced nothing and asked for no share by id is pushed no share.
static void CheckRouting(const Conn& c, const vector<Sent>& v)
{
    foreach(const Sent& m, v)
    {
        bool fReg = m.strCommand.compare(0, 3, "p2x") == 0 || m.strCommand.compare(0, 4, "pool") == 0;
        if (fReg && !c.fReg)
        {
            fprintf(stderr, "fuzz-p2preg: %s sent to a peer without NODE_POOLREG\n", m.strCommand.c_str());
            abort();
        }
        if (m.strCommand == "p2xshare" && !c.fAnnounced && !c.fAsked)
        {
            fprintf(stderr, "fuzz-p2preg: a share pushed to a peer that announced no pool\n");
            abort();
        }
    }
}

static void Deliver(Conn& c, const char* pszCommand, CDataStream& vMsg)
{
    try
    {
        P2PoolProcessMessage(c.node.get(), pszCommand, vMsg);
    }
    catch (std::exception&)
    {
        // A payload that does not deserialise ends the message, as in
        // ProcessMessages().
    }
    CheckRouting(c, Drain(c.node.get()));
}

static void HandleRecord(Conn& c, int nKindByte, unsigned char nFlags, const uint8_t* data, size_t size)
{
    int nKind = nKindByte % 8;
    if (nKind == K_PASS)
    {
        P2PoolRegTickForTest();
        P2PoolServeDeferred();
        CheckRouting(c, Drain(c.node.get()));
        if (size > 0 && (data[0] & 1))
        {
            EndConn(c);
            c = NewConn(nFlags);
        }
        return;
    }
    const char* pszCommand = kCommands[nKind];
    if (nKind == K_WHO && size > 0 && (data[0] & 1))
    {
        pszCommand = "poolat";
        data++;
        size--;
    }
    if (nKind == K_INV)
        c.fAnnounced = true;
    if (nKind == K_GETSH)
        c.fAsked = true;
    CDataStream vMsg(SER_NETWORK, VERSION);
    if (nKind != K_INV && (nFlags & F_ID))
    {
        vMsg << ((nKindByte & 8) ? g_idB : g_idA);
        CDataStream vBody((const char*)data, (const char*)data + size, SER_NETWORK, VERSION);
        FixBody(nKind, vBody, nFlags);
        if (!vBody.empty())
            vMsg.write(&vBody[0], vBody.size());
    }
    else if (nKind != K_INV && size >= 32)
    {
        vMsg.write((const char*)data, 32);
        CDataStream vBody((const char*)data + 32, (const char*)data + size, SER_NETWORK, VERSION);
        FixBody(nKind, vBody, nFlags);
        if (!vBody.empty())
            vMsg.write(&vBody[0], vBody.size());
    }
    else if (size)
        vMsg.write((const char*)data, size);
    Deliver(c, pszCommand, vMsg);
}

static void CheckState()
{
    string err;
    bool fOk;
    size_t nShares, nZero;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = P2PoolMinedChain().CheckInvariants(err);
        nShares = P2PoolMinedChain().Size();
        nZero = P2PoolChain().Size();
    }
    if (!fOk)
    {
        fprintf(stderr, "fuzz-p2preg: pool A's share chain broke an invariant: %s (%u shares)\n",
                err.c_str(), (unsigned)nShares);
        abort();
    }
    if (P2PoolRegisteredOrphanCount() > 256)
    {
        fprintf(stderr, "fuzz-p2preg: %u orphan shares queued, more than the cap\n",
                (unsigned)P2PoolRegisteredOrphanCount());
        abort();
    }
    if (nZero != 0 || P2PoolOrphanCount() != 0)
    {
        fprintf(stderr, "fuzz-p2preg: a registered pool's traffic reached pool zero (%u shares, %u orphans)\n",
                (unsigned)nZero, (unsigned)P2PoolOrphanCount());
        abort();
    }
    if (P2PoolDeferredCount() != 0)
    {
        fprintf(stderr, "fuzz-p2preg: %u connections still held after theirs closed\n", (unsigned)P2PoolDeferredCount());
        abort();
    }
}

// ---- seeds

static void AppendRecord(string& str, int nKind, const CDataStream& ss)
{
    str += (char)nKind;
    str += (char)(ss.size() & 0xff);
    str += (char)((ss.size() >> 8) & 0xff);
    if (ss.size())
        str.append(&ss[0], ss.size());
}

template <typename T>
static void AppendItem(string& str, int nKind, const T& item)
{
    CDataStream ss(SER_NETWORK, VERSION);
    ss << item;
    AppendRecord(str, nKind, ss);
}

static void WriteRaw(const string& strDir, const char* pszName, const string& str)
{
    string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    fwrite(str.data(), 1, str.size(), f);
    fclose(f);
}

// A share of pool A on 'parent' that pays exactly what the chain says it
// must, with stand-in work and the pool's anchor, added to a scratch copy of
// the chain so the next can build on it. Under cs_p2pool.
static ShareX SeedShare(ShareChain& chain, const uint256& parent, unsigned char tag, unsigned int nTime)
{
    const PoolRules& rules = chain.Rules();
    ShareX s;
    s.data.poolId = rules.poolId;
    s.data.hashPrevShare = parent;
    s.data.payoutScript = PayTo(tag);
    s.data.nShareHeight = parent == 0 ? 0 : chain.Height(parent) + 1;
    s.data.nShareBits = chain.NextShareBits(parent);
    s.coinbase.vin.resize(1);
    s.coinbase.vin[0].prevout.SetNull();
    vector<WindowShare> window;
    vector<Payout> pay;
    string err;
    chain.WindowFor(s.data, WorkOf(s.data.nShareBits), window, err);
    ComputePoolPayouts(rules, window, CBlock().GetBlockValue(61001, 0), pay, err);
    for (size_t i = 0; i < pay.size(); i++)
        s.coinbase.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));
    s.coinbase.vin[0].scriptSig = CScript() << 61001 << AnchorPush(rules, s.data);
    s.nVersion = 1;
    s.hashPrevBlock = 0;
    s.hashMerkleRoot = s.coinbase.GetHash();
    s.nTime = nTime;
    s.nBits = 0x1d00ffff;
    s.nNonce = 0;
    NodeMainView main;
    if (!chain.Add(s, main, err))
    {
        fprintf(stderr, "fuzz-p2preg: seed share refused: %s\n", err.c_str());
        exit(1);
    }
    return s;
}

static void WriteSeeds(const string& strDir)
{
    vector<ShareX> line;
    PoolRules rulesA, rulesB;
    CRITICAL_BLOCK(cs_p2pool)
        rulesA = P2PoolMinedChain().Rules();
    {
        // A scratch chain with pool A's rules: the seeds are what a peer
        // would send, built on nothing this node holds yet.
        ShareChain scratch(rulesA, true);
        unsigned int t = (unsigned int)GetAdjustedTime() - 3000;
        uint256 prev = 0;
        for (int i = 0; i < 20; i++)
        {
            line.push_back(SeedShare(scratch, prev, (unsigned char)(1 + i % 5), t + 30 * i));
            prev = line.back().GetId();
        }
    }
    const unsigned char fIn = F_INBOUND | F_ID, fOut = F_ID;
    CDataStream pass(SER_NETWORK, VERSION);
    pass << (unsigned char)0;
    {
        string str(1, (char)(fIn | F_VERSION));
        AppendItem(str, K_INV, vector<uint256>(1, g_idA));
        for (size_t i = 0; i < line.size(); i++)
            AppendItem(str, K_SHARE, line[i]);
        AppendRecord(str, K_PASS, pass);
        WriteRaw(strDir, "announced-line", str);
    }
    {
        string str(1, (char)fOut);
        for (size_t i = line.size(); i-- > 0;)
            AppendItem(str, K_SHARE, line[i]);
        AppendItem(str, K_SYNC, uint256(0));
        AppendItem(str, K_SYNC, line[5].GetId());
        vector<uint256> ids;
        for (size_t i = 0; i < line.size(); i += 3)
            ids.push_back(line[i].GetId());
        AppendItem(str, K_GETSH, ids);
        AppendRecord(str, K_PASS, pass);
        AppendRecord(str, K_PASS, pass);
        WriteRaw(strDir, "children-first-sync-getsh", str);
    }
    {
        // Pool B announced, the pass asks for it, and parts answer: pool A's
        // shares under B's id (refused), then an end flag, then p2xnone.
        string str(1, (char)fOut);
        AppendItem(str, K_INV, vector<uint256>(1, g_idB));
        AppendRecord(str, K_PASS, pass);
        vector<ShareX> a(line.begin(), line.begin() + 10), b(line.begin() + 10, line.end());
        CDataStream s1(SER_NETWORK, VERSION), s2(SER_NETWORK, VERSION);
        s1 << (int)line.size() - 1 << (unsigned char)0 << a;
        s2 << (int)line.size() - 1 << (unsigned char)1 << b;
        AppendRecord(str, K_SHARES | 8, s1);
        AppendRecord(str, K_SHARES | 8, s2);
        AppendRecord(str, K_PASS, pass);
        AppendRecord(str, K_NONE | 8, CDataStream(SER_NETWORK, VERSION));
        AppendRecord(str, K_PASS, pass);
        WriteRaw(strDir, "fetch-b", str);
    }
    {
        // Strangers: an unknown pool, pool zero's id, a short message, a
        // poolwho and an unasked poolat, from a peer without NODE_POOLREG
        // and then from one with it.
        for (int nOld = 0; nOld < 2; nOld++)
        {
            string str(1, (char)(F_INBOUND | (nOld ? F_OLD : 0)));
            CDataStream unknown(SER_NETWORK, VERSION);
            unknown << uint256(777) << line[0];
            AppendRecord(str, K_SHARE, unknown);
            CDataStream sync(SER_NETWORK, VERSION);
            sync << uint256(778) << uint256(0);
            AppendRecord(str, K_SYNC, sync);
            CDataStream shortMsg(SER_NETWORK, VERSION);
            shortMsg << (unsigned char)1;
            AppendRecord(str, K_GETSH, shortMsg);
            CDataStream who(SER_NETWORK, VERSION);
            who << g_idA;
            AppendRecord(str, K_WHO, who);
            CDataStream at(SER_NETWORK, VERSION);
            at << (unsigned char)1 << g_idA << vector<string>(1, "BF1somebody");
            AppendRecord(str, K_WHO, at);
            AppendItem(str, K_INV, vector<uint256>(40, uint256(5)));
            WriteRaw(strDir, nOld ? "strangers-old" : "strangers", str);
        }
    }
    {
        // Mutable shapes with every fix-up on: bad work (odd nonce), a block
        // (bit 1), a share with no parent here, another pool's id.
        string str(1, (char)(fIn | F_FIX_LINK | F_FIX_PAY | F_FIX_ANCHOR));
        ShareX bad = line[0];
        bad.nNonce = 1;
        AppendItem(str, K_SHARE, bad);
        ShareX block = line[0];
        block.nNonce = 2;
        AppendItem(str, K_SHARE, block);
        ShareX lost = line[5];
        lost.data.hashPrevShare = uint256(12345);
        AppendItem(str, K_SHARE, lost);
        CDataStream other(SER_NETWORK, VERSION);
        other << line[1];
        AppendRecord(str, K_SHARE | 8, other);
        WriteRaw(strDir, "fixups", str);
    }
}

// The node's global maps (the share chains, the connection state) live for
// the run and are never freed, as in a node: no leak check at exit
// (fuzz_datadir.h); libFuzzer checks for leaks after each input.

static void FuzzP2PRegInit()
{
    SelectChainParams(false);
    fFuzzShareWorkStandIn = true;
    poolreg::PoolRecord recA = poolreg::PoolZero();
    recA.nSpacing = 30;
    recA.nWindow = 360;
    recA.nRetarget = 120;
    recA.nUncleDepth = 2;
    recA.nUnclePct = 90;
    recA.nFloor = poolreg::NETWORK_FLOOR;
    recA.name = "fuzz-a";
    poolreg::PoolRecord recB = recA;
    recB.name = "fuzz-b";
    string err;
    if (!P2PoolRegAddForTest(recA, true, false, false, err) || !P2PoolRegAddForTest(recB, false, true, false, err))
    {
        fprintf(stderr, "fuzz-p2preg: no registered pool: %s\n", err.c_str());
        exit(1);
    }
    poolreg::PoolId(recA.Encode(), (const unsigned char*)pchMessageStart, g_idA.begin());
    poolreg::PoolId(recB.Encode(), (const unsigned char*)pchMessageStart, g_idB.begin());
    // Pool A's line starts here: nobody announces it, and its grace runs out.
    P2PoolRegTickForTest();
    P2PoolRegAgeForTest(600);
    P2PoolRegTickForTest();
    if (P2PoolRegFetchForTest(g_idA) != P2PoolRegStatusInfo::FETCH_COMPLETE)
    {
        fprintf(stderr, "fuzz-p2preg: pool A did not start its line\n");
        exit(1);
    }
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 300000)
        return 0;
    unsigned char nFlags = data[0];
    data++;
    size--;
    if (nFlags & F_REFILL)
        P2PoolRefillBudgetsForTest();
    Conn c = NewConn(nFlags);
    if (nFlags & F_VERSION)
    {
        try { P2PoolOnVersion(c.node.get()); }
        catch (std::exception&) {}
        CheckRouting(c, Drain(c.node.get()));
    }
    for (int n = 0; n < 32 && size >= 3; n++)
    {
        int nKindByte = data[0];
        size_t nLen = data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (nLen > size)
            nLen = size;
        HandleRecord(c, nKindByte, nFlags, data, nLen);
        data += nLen;
        size -= nLen;
    }
    EndConn(c);
    CheckState();
    return 0;
}
