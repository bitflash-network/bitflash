// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for a local pool's messages (docs/pool-registry.md, section
// 18), fed as a peer feeds them: the hello (p2lhello, p2lack), and the four
// messages behind a session's handle (p2lshare, p2lgetsh, p2lsync,
// p2lshares), through P2PoolProcessMessage(), on an inbound connection or
// one this node dialled to a peer its local pool lists. One record kind runs
// a valid handshake, from whichever side the connection has, so the records
// after it reach the parsers and the share chain behind the handle; without
// it every message must find its way past the hello and the handle alone.
//
// One local pool joins at start (record and K fixed, so no Argon2id run),
// and this node mines it: P2PoolMinedChain() is its share chain. The chain,
// the registered class's budgets, orphans and paced serves live for the
// whole run, as in a node. In this binary only (-DBITFLASH_FUZZ),
// fFuzzShareWorkStandIn replaces the RandomX comparison with a rule on nNonce
// (bit 0 clear: the work holds; bit 1 set: it is also a block), after the
// registered work budget is asked.
//
// Input layout:
//   byte 0   flags:
//              bit 0  the peer is inbound (else one this node dialled, at an
//                     onion its local pool lists)
//              bit 1  records 2 to 5 go out with the session's handle in
//                     front when there is one (else the payload is sent as
//                     it is, and its first 8 bytes are the handle)
//              bit 2  the peer's version arrives first (P2PoolOnVersion)
//              bit 3  fix up each share's link: height, target and time from
//                     its parent here, a payout script that is an address
//              bit 4  fix up each share's coinbase to pay its window
//              bit 5  fix up each share's anchor and merkle root
//              bit 6  every shared budget full first
//   then up to 32 records [kind][length, 2 bytes little-endian][payload]:
//     kind % 8: 0 p2lhello, 1 p2lack, 2 p2lshare, 3 p2lgetsh, 4 p2lsync,
//               5 p2lshares, 6 a valid handshake on this connection (the
//               payload seeds the nonce), 7 the message thread's pass (paced
//               serves, hellos due, expiries), then, if the payload's first
//               byte is odd, a new connection with the same flags
//
// After every input: the local pool's share chain holds
// ShareChain::CheckInvariants; the registered orphan queue its cap; nothing
// reached pool zero (its share chain and orphan queue stay empty, section
// 8); a connection that never completed a handshake was sent nothing of the
// pool but a hello; and nothing is held for a connection once it is gone.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus (handshakes from
// both sides, then a line of shares, a history, getsh and sync; stray
// hellos and handles) into <dir> and exits.

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

static void FuzzP2PLocalInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzP2PLocalInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using namespace p2pool;

static const unsigned char F_INBOUND = 1;
static const unsigned char F_HANDLE = 2;
static const unsigned char F_VERSION = 4;
static const unsigned char F_FIX_LINK = 8;
static const unsigned char F_FIX_PAY = 16;
static const unsigned char F_FIX_ANCHOR = 32;
static const unsigned char F_REFILL = 64;

enum
{
    K_HELLO = 0, K_ACK, K_SHARE, K_GETSH, K_SYNC, K_SHARES, K_HANDSHAKE, K_PASS
};
static const char* const kCommands[] = { "p2lhello", "p2lack", "p2lshare", "p2lgetsh", "p2lsync", "p2lshares" };

static const char* const POOL_NAME = "fuzz";
// The onion this node answers hellos for, and the one it dials its listed
// peer at.
static const string O_OWN = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
static const string O_PEER = "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy";
static const string PEER_ADDR = "BF1fuzzlistedpeer";

static poollocal::Keys g_keys;

// One connection and what the harness knows of it.
struct Conn
{
    std::unique_ptr<CNode> node;
    bool fInbound;
    bool fSession;          // the harness completed a handshake on it
    uint64 h;               // its handle, when fSession
};

static vector<unsigned char> PayTo(unsigned char tag)
{
    vector<unsigned char> s;
    s.push_back(OP_DUP); s.push_back(OP_HASH160); s.push_back(20);
    for (int i = 0; i < 20; i++) s.push_back((unsigned char)(tag + i));
    s.push_back(OP_EQUALVERIFY); s.push_back(OP_CHECKSIG);
    return s;
}

// The fix-ups (flags 3 to 5), against the local pool's chain. Under cs_p2pool.
static void FixShare(Share& s, unsigned char nFlags)
{
    ShareChain& chain = P2PoolMinedChain();
    const PoolRules& rules = chain.Rules();
    ShareData& d = s.data;
    d.fX = true;
    if (nFlags & (F_FIX_LINK | F_FIX_PAY | F_FIX_ANCHOR))
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

// p2lshare and p2lshares carry shares after the handle; the fix-ups apply to
// them. vBody is what follows the handle.
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
    c.fInbound = (nFlags & F_INBOUND) != 0;
    c.fSession = false;
    c.h = 0;
    c.node.reset(new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), c.fInbound));
    CNode* p = c.node.get();
    p->nVersion = VERSION;
    p->nServices = NODE_P2POOL;
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    if (!c.fInbound)
    {
        p->strBtfAddr = PEER_ADDR;
        p->strBtfMeeting = "onion " + O_PEER + ".onion:18433";
    }
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

// A connection without a session is sent nothing of the pool but a hello.
static void CheckSilence(const Conn& c, const vector<Sent>& v)
{
    if (c.fSession)
        return;
    foreach(const Sent& m, v)
        if (m.strCommand == "p2lshare" || m.strCommand == "p2lgetsh" || m.strCommand == "p2lsync" ||
            m.strCommand == "p2lshares")
        {
            fprintf(stderr, "fuzz-p2plocal: %s sent on a connection with no session\n", m.strCommand.c_str());
            abort();
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
    CheckSilence(c, Drain(c.node.get()));
}

// The whole handshake from the peer's side. Inbound: the peer says hello to
// this node's onion; dialled: this node says hello to the listed peer's.
static void Handshake(Conn& c, const uint8_t* data, size_t size)
{
    static uint64 nCounter = 0;
    unsigned char nPeer[32];
    memset(nPeer, 0, sizeof(nPeer));
    memcpy(nPeer, data, std::min(size, sizeof(nPeer)));
    if (size < sizeof(nPeer))
    {
        // Short seeds would repeat a nonce the pool remembers.
        nCounter++;
        memcpy(nPeer + 24, &nCounter, sizeof(nCounter));
    }
    CNode* p = c.node.get();
    unsigned char nA[32], nB[32];
    const string& O = c.fInbound ? O_OWN : O_PEER;
    if (c.fInbound)
    {
        memcpy(nA, nPeer, 32);
        unsigned char tA[poollocal::TAG_BYTES];
        poollocal::HelloTag(g_keys.A, O, nA, tA);
        CDataStream ss(SER_NETWORK, VERSION);
        ss.write((const char*)nA, 32);
        ss.write((const char*)tA, sizeof(tA));
        P2PoolProcessMessage(p, "p2lhello", ss);
        vector<Sent> v = Drain(p);
        CheckSilence(c, v);
        bool fReply = false;
        foreach(const Sent& m, v)
            if (m.strCommand == "p2lhello" && m.payload.size() == 48)
            {
                memcpy(nB, &m.payload[0], 32);
                fReply = true;
            }
        if (!fReply)
            return;     // rate limit, session cap, a nonce seen before: silence
        unsigned char ack[poollocal::ACK_BYTES];
        poollocal::AckTag(g_keys.A, O, nA, nB, ack);
        CDataStream sa(SER_NETWORK, VERSION);
        sa.write((const char*)ack, sizeof(ack));
        P2PoolProcessMessage(p, "p2lack", sa);
    }
    else
    {
        P2PoolOnVersion(p);
        vector<Sent> v = Drain(p);
        CheckSilence(c, v);
        bool fHello = false;
        foreach(const Sent& m, v)
            if (m.strCommand == "p2lhello" && m.payload.size() == 48)
            {
                memcpy(nA, &m.payload[0], 32);
                fHello = true;
            }
        if (!fHello)
            return;     // a hello already went on this connection lately
        memcpy(nB, nPeer, 32);
        unsigned char tB[poollocal::TAG_BYTES];
        poollocal::ReplyTag(g_keys.A, O, nA, nB, tB);
        CDataStream ss(SER_NETWORK, VERSION);
        ss.write((const char*)nB, 32);
        ss.write((const char*)tB, sizeof(tB));
        P2PoolProcessMessage(p, "p2lhello", ss);
    }
    unsigned char h[poollocal::HANDLE_BYTES];
    poollocal::SessionHandle(g_keys.A, O, nA, nB, h);
    c.fSession = true;
    memcpy(&c.h, h, sizeof(c.h));
    // What the session opened with: an ask for the line, under the handle.
    Drain(p);
}

static void HandleRecord(Conn& c, int nKind, unsigned char nFlags, const uint8_t* data, size_t size)
{
    if (nKind == K_HANDSHAKE)
    {
        Handshake(c, data, size);
        return;
    }
    if (nKind == K_PASS)
    {
        P2PoolServeDeferred();
        CheckSilence(c, Drain(c.node.get()));
        if (size > 0 && (data[0] & 1))
        {
            EndConn(c);
            c = NewConn(nFlags);
        }
        return;
    }
    CDataStream vMsg(SER_NETWORK, VERSION);
    if (nKind >= K_SHARE && (nFlags & F_HANDLE) && c.fSession)
    {
        vMsg << c.h;
        CDataStream vBody((const char*)data, (const char*)data + size, SER_NETWORK, VERSION);
        FixBody(nKind, vBody, nFlags);
        if (!vBody.empty())
            vMsg.write(&vBody[0], vBody.size());
    }
    else if (nKind >= K_SHARE && size >= 8)
    {
        vMsg.write((const char*)data, 8);
        CDataStream vBody((const char*)data + 8, (const char*)data + size, SER_NETWORK, VERSION);
        FixBody(nKind, vBody, nFlags);
        if (!vBody.empty())
            vMsg.write(&vBody[0], vBody.size());
    }
    else if (size)
        vMsg.write((const char*)data, size);
    Deliver(c, kCommands[nKind], vMsg);
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
        fprintf(stderr, "fuzz-p2plocal: the local pool's share chain broke an invariant: %s (%u shares)\n",
                err.c_str(), (unsigned)nShares);
        abort();
    }
    if (P2PoolRegisteredOrphanCount() > 256)
    {
        fprintf(stderr, "fuzz-p2plocal: %u orphan shares queued, more than the cap\n",
                (unsigned)P2PoolRegisteredOrphanCount());
        abort();
    }
    if (nZero != 0 || P2PoolOrphanCount() != 0)
    {
        fprintf(stderr, "fuzz-p2plocal: a local pool's traffic reached pool zero (%u shares, %u orphans)\n",
                (unsigned)nZero, (unsigned)P2PoolOrphanCount());
        abort();
    }
    if (P2PoolDeferredCount() != 0)
    {
        fprintf(stderr, "fuzz-p2plocal: %u connections still held after theirs closed\n", (unsigned)P2PoolDeferredCount());
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

static void AppendHandshake(string& str, unsigned char seed)
{
    CDataStream ss(SER_NETWORK, VERSION);
    for (int i = 0; i < 32; i++)
        ss << (unsigned char)(seed + i);
    AppendRecord(str, K_HANDSHAKE, ss);
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

// A share on 'parent' that pays exactly what the chain says it must, with
// stand-in work and the pool's anchor, added to the chain so the next can
// build on it. Under cs_p2pool.
static ShareX SeedShare(const uint256& parent, unsigned char tag, unsigned int nTime)
{
    ShareChain& chain = P2PoolMinedChain();
    ShareX s;
    s.data.hashPrevShare = parent;
    s.data.payoutScript = PayTo(tag);
    s.coinbase.vin.resize(1);
    s.coinbase.vin[0].prevout.SetNull();
    s.coinbase.vin[0].scriptSig = CScript() << 61001;
    s.nVersion = 1;
    s.hashPrevBlock = 0;
    s.nTime = nTime;
    s.nBits = 0x1d00ffff;
    s.nNonce = 0;
    FixShare(s, F_FIX_LINK | F_FIX_PAY | F_FIX_ANCHOR);
    string err;
    NodeMainView main;
    if (!chain.Add(s, main, err))
    {
        fprintf(stderr, "fuzz-p2plocal: seed share refused: %s\n", err.c_str());
        exit(1);
    }
    return s;
}

static void WriteSeeds(const string& strDir)
{
    vector<ShareX> line;
    CRITICAL_BLOCK(cs_p2pool)
    {
        // The pool's spacing is 30 s: the line is spaced so.
        unsigned int t = (unsigned int)GetAdjustedTime() - 3000;
        uint256 prev = 0;
        for (int i = 0; i < 20; i++)
        {
            line.push_back(SeedShare(prev, (unsigned char)(1 + i % 5), t + 30 * i));
            prev = line.back().GetId();
        }
    }
    const unsigned char fIn = F_INBOUND | F_HANDLE, fOut = F_HANDLE;
    {
        string str(1, (char)fIn);
        AppendHandshake(str, 1);
        for (size_t i = 0; i < line.size(); i++)
            AppendItem(str, K_SHARE, line[i]);
        WriteRaw(strDir, "inbound-session-line", str);
    }
    {
        string str(1, (char)fOut);
        AppendHandshake(str, 2);
        for (size_t i = line.size(); i-- > 0;)
            AppendItem(str, K_SHARE, line[i]);
        WriteRaw(strDir, "dialled-session-children-first", str);
    }
    {
        // A history answering the ask the session opened with, in two parts.
        string str(1, (char)fOut);
        AppendHandshake(str, 3);
        vector<ShareX> a(line.begin(), line.begin() + 10), b(line.begin() + 10, line.end());
        CDataStream s1(SER_NETWORK, VERSION), s2(SER_NETWORK, VERSION);
        s1 << (int)line.size() - 1 << (unsigned char)0 << a;
        s2 << (int)line.size() - 1 << (unsigned char)1 << b;
        AppendRecord(str, K_SHARES, s1);
        AppendRecord(str, K_SHARES, s2);
        WriteRaw(strDir, "history", str);
    }
    {
        string str(1, (char)fIn);
        AppendHandshake(str, 4);
        vector<uint256> ids;
        for (size_t i = 0; i < line.size(); i += 3)
            ids.push_back(line[i].GetId());
        AppendItem(str, K_GETSH, ids);
        AppendItem(str, K_SYNC, uint256(0));
        AppendItem(str, K_SYNC, line[5].GetId());
        CDataStream pass(SER_NETWORK, VERSION);
        pass << (unsigned char)0;
        AppendRecord(str, K_PASS, pass);
        AppendRecord(str, K_PASS, pass);
        WriteRaw(strDir, "getsh-sync-serve", str);
    }
    {
        // No handshake: a hello with a bad tag, an ack out of nowhere, a
        // handle nobody holds, a reconnect, and a hello too short.
        string str(1, (char)F_INBOUND);
        CDataStream hello(SER_NETWORK, VERSION);
        for (int i = 0; i < 48; i++)
            hello << (unsigned char)i;
        AppendRecord(str, K_HELLO, hello);
        CDataStream ack(SER_NETWORK, VERSION);
        for (int i = 0; i < 32; i++)
            ack << (unsigned char)(i * 7);
        AppendRecord(str, K_ACK, ack);
        CDataStream share(SER_NETWORK, VERSION);
        share << (uint64)0x1122334455667788ULL << line[0];
        AppendRecord(str, K_SHARE, share);
        CDataStream pass(SER_NETWORK, VERSION);
        pass << (unsigned char)1;
        AppendRecord(str, K_PASS, pass);
        CDataStream shortHello(SER_NETWORK, VERSION);
        shortHello << (unsigned char)1;
        AppendRecord(str, K_HELLO, shortHello);
        WriteRaw(strDir, "strangers", str);
    }
    {
        // Mutable shapes with every fix-up on: bad work (odd nonce), a block
        // (bit 1), a share with no parent here, another pool's id.
        string str(1, (char)(fIn | F_FIX_LINK | F_FIX_PAY | F_FIX_ANCHOR));
        AppendHandshake(str, 5);
        ShareX bad = line[0];
        bad.nNonce = 1;
        AppendItem(str, K_SHARE, bad);
        ShareX block = line[0];
        block.nNonce = 2;
        AppendItem(str, K_SHARE, block);
        ShareX lost = line[5];
        lost.data.hashPrevShare = uint256(12345);
        AppendItem(str, K_SHARE, lost);
        WriteRaw(strDir, "fixups", str);
    }
}

// The node's global maps (the share chains, the sessions) live for the run
// and are never freed, as in a node: no leak check at exit (fuzz_datadir.h);
// libFuzzer checks for leaks after each input.

static void FuzzP2PLocalInit()
{
    SelectChainParams(false);
    fFuzzShareWorkStandIn = true;
    poolreg::PoolRecord rec = poolreg::PoolZero();
    rec.fLocal = true;
    rec.nSpacing = 30;
    rec.nWindow = 360;
    rec.nRetarget = 120;
    rec.nUncleDepth = 2;
    rec.nUnclePct = 90;
    rec.nFloor = poolreg::NETWORK_FLOOR;
    rec.name = POOL_NAME;
    unsigned char K[32];
    for (int i = 0; i < 32; i++)
        K[i] = (unsigned char)(0xa0 + i);
    string err;
    vector<string> vOwn(1, O_OWN), vPeers(1, PEER_ADDR + "@" + O_PEER + ".onion:18433");
    if (!poollocal::DeriveFromK(rec.Encode(), (const unsigned char*)pchMessageStart, K, g_keys, err) ||
        !P2PoolLocalAdd(rec, g_keys, "", true, err) || !P2PoolLocalSetPeers(POOL_NAME, vPeers, err) ||
        !P2PoolLocalMine(POOL_NAME, err))
    {
        fprintf(stderr, "fuzz-p2plocal: no local pool: %s\n", err.c_str());
        exit(1);
    }
    P2PoolSetOwnOnionsForTest(vOwn);
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
        CheckSilence(c, Drain(c.node.get()));
    }
    for (int n = 0; n < 32 && size >= 3; n++)
    {
        int nKind = data[0] % 8;
        size_t nLen = data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (nLen > size)
            nLen = size;
        HandleRecord(c, nKind, nFlags, data, nLen);
        data += nLen;
        size -= nLen;
    }
    EndConn(c);
    CheckState();
    return 0;
}
