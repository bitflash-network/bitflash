// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for guardian tickets on the wire (docs/pool-registry.md,
// section 10): pooltkt and poolgettkt fed through P2PoolProcessMessage() as
// a peer sends them, on an inbound connection or one this node dialled, from
// a peer that says NODE_POOLREG or one that does not; the ticket thread's
// pass that checks what they queued (Precheck again, the signature and the
// work, the held set); and pool-tickets.dat as a start reads it back
// (LoadTicketFile, then the file's tickets queued and checked like an
// answer).
//
// The node's ticket state lives for the whole run, as in a node: a chain of
// 3701 made-up block hashes (epoch 5, epoch 6's seed buried), registered
// pools open in this process, and a stand-in for the RandomX work hash: the
// header's SHA256d with its top byte cleared when bit 0 of the nonce is
// clear (the work holds) and set when it is set (the work fails), so inputs
// can reach the held set without grinding. Signatures are real BIP340.
//
// Input layout:
//   byte 0   flags:
//              bit 0  the peer is inbound (else one this node dialled)
//              bit 1  the peer is asked for the sets first (its version, the
//                     ask interval run out, the message thread's pass), so
//                     its pooltkt are answers
//              bit 2  the peer does not say NODE_POOLREG (a 1.2.34 node)
//              bit 3  the ticket budget full first
//              bit 4  records of kind 0 get a valid head: the epoch (4, 5 or
//                     6 by the payload's first byte, which is then dropped)
//                     and that epoch's seed
//   then up to 32 records [kind][length, 2 bytes little-endian][payload]:
//     kind % 6: 0 pooltkt, 1 poolgettkt, 2 the ticket thread's pass
//               (payload byte 0: tickets to check, % 64; byte 1 bit 0: make
//               this node's own ticket too), 3 the payload written as
//               pool-tickets.dat and read back as at a start, 4 the message
//               thread's pass (relays and scores go out, the sets asked
//               for), 5 the ticket state's clocks made older (payload byte 0
//               times 8 s)
//
// After every input: no epoch holds more than 4096 tickets; the connection's
// queues stayed within 512 relays and 4096 answers an epoch; nothing reached
// pool zero (its share chain and orphan queue stay empty); a peer without
// NODE_POOLREG was sent no p2x* or pool* message and never scored; nothing
// is held for the connection once it is gone.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus (an answer and a
// relay of signed tickets, bad signatures and bad framing, a relay past the
// deadline, a poolgettkt, a pool-tickets.dat of this node's making) into
// <dir> and exits.

#include "headers_core.h"
#include "p2pool_net.h"
#include "poolindex.h"
#include "poolticket.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <memory>
#include <string>
#include <vector>

static void FuzzPoolTktInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzPoolTktInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

static const unsigned char F_INBOUND = 1;
static const unsigned char F_ASKED = 2;
static const unsigned char F_OLD = 4;
static const unsigned char F_REFILL = 8;
static const unsigned char F_HEAD = 16;

enum { K_TKT = 0, K_GETTKT, K_STEP, K_FILE, K_PASS, K_AGE };

static std::vector<uint256> g_vChain;
static CTicketParams g_params;
static const int TIP = 3700;

static uint256 StandInWork(const unsigned char* pHeader80)
{
    uint256 h = Hash(pHeader80, pHeader80 + 80);
    *(h.begin() + 31) = (pHeader80[76] & 1) ? 0xff : 0x00;
    return h;
}

static uint256 SeedOf(unsigned int nEpoch)
{
    return g_vChain[(nEpoch - 1) * 720];
}

class FuzzView : public CTicketChainView
{
public:
    int TipHeight() const { return (int)g_vChain.size() - 1; }
    bool HashAt(int nHeight, uint256& hashOut) const
    {
        if (nHeight < 0 || nHeight >= (int)g_vChain.size())
            return false;
        hashOut = g_vChain[nHeight];
        return true;
    }
};

struct Conn
{
    std::unique_ptr<CNode> node;
    bool fReg;
};

static Conn NewConn(unsigned char nFlags)
{
    Conn c;
    c.fReg = !(nFlags & F_OLD);
    c.node.reset(new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), (nFlags & F_INBOUND) != 0));
    CNode* p = c.node.get();
    p->nVersion = VERSION;
    p->nServices = c.fReg ? (NODE_P2POOL | NODE_POOLREG) : NODE_P2POOL;
    p->strBtfAddr = "BF1fuzzticketpeer";
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    return c;
}

static void EndConn(Conn& c)
{
    P2PoolServeDeferred();
    P2PoolForgetDeferred(c.node.get());
    c.node.reset();
}

// What the node queued for the peer since the last read: whether any of it
// was a registry message. The bytes then count as sent.
static bool DrainSawReg(CNode* p)
{
    bool fReg = false;
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
                string strCommand = hdr.GetCommand();
                if (strCommand.compare(0, 3, "p2x") == 0 || strCommand.compare(0, 4, "pool") == 0)
                    fReg = true;
                v.ignore(hdr.nMessageSize);
            }
        }
        catch (std::exception&) {}
        p->nSendDrained += p->vSend.size();
        p->vSend.clear();
    }
    return fReg;
}

static void CheckConn(const Conn& c)
{
    if (DrainSawReg(c.node.get()) && !c.fReg)
    {
        fprintf(stderr, "fuzz-pooltkt: a registry message sent to a peer without NODE_POOLREG\n");
        abort();
    }
    if (!c.fReg && c.node->nMisbehavior != 0)
    {
        fprintf(stderr, "fuzz-pooltkt: a peer without NODE_POOLREG was scored for a ticket message\n");
        abort();
    }
    for (unsigned int e = 4; e <= 7; e++)
    {
        size_t nRelay = 0, nAnswer = 0;
        P2PoolTicketQueuedForTest(c.node.get(), e, nRelay, nAnswer);
        if (nRelay > 512 || nAnswer > GUARD_MAX_TICKETS)
        {
            fprintf(stderr, "fuzz-pooltkt: %u relays and %u answers of epoch %u queued for one connection\n",
                    (unsigned)nRelay, (unsigned)nAnswer, e);
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
    CheckConn(c);
}

static void WriteFile(const string& strPath, const uint8_t* data, size_t size)
{
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
        return;
    if (size)
        fwrite(data, 1, size, f);
    fclose(f);
}

static void HandleRecord(Conn& c, int nKindByte, unsigned char nFlags, const uint8_t* data, size_t size)
{
    int nKind = nKindByte % 6;
    if (nKind == K_STEP)
    {
        int n = size > 0 ? data[0] % 64 : 16;
        bool fMake = size > 1 && (data[1] & 1);
        P2PoolTicketStepForTest(n, fMake);
        return;
    }
    if (nKind == K_FILE)
    {
        string strPath = GetAppDir() + "/pool-tickets.dat";
        WriteFile(strPath, data, size);
        std::vector<CTicketFileEpoch> v;
        string why;
        if (pooltkt::LoadTicketFile(strPath, g_params, v, why))
        {
            if (v.size() > 3)
            {
                fprintf(stderr, "fuzz-pooltkt: a ticket file of %u epochs read\n", (unsigned)v.size());
                abort();
            }
        }
        P2PoolTicketLoadForTest();
        return;
    }
    if (nKind == K_PASS)
    {
        P2PoolRegTickForTest();
        CheckConn(c);
        return;
    }
    if (nKind == K_AGE)
    {
        P2PoolTicketAgeForTest(size > 0 ? (int64)data[0] * 8 : 60);
        return;
    }
    CDataStream vMsg(SER_NETWORK, VERSION);
    if (nKind == K_TKT && (nFlags & F_HEAD) && size > 0)
    {
        unsigned int nEpoch = 4 + data[0] % 3;
        vMsg << nEpoch << SeedOf(nEpoch);
        data++;
        size--;
    }
    if (size)
        vMsg.write((const char*)data, size);
    Deliver(c, nKind == K_TKT ? "pooltkt" : "poolgettkt", vMsg);
}

static void CheckState()
{
    for (unsigned int e = 1; e <= 8; e++)
        if (P2PoolTicketHeldForTest(e) > GUARD_MAX_TICKETS)
        {
            fprintf(stderr, "fuzz-pooltkt: %u tickets held for epoch %u\n", (unsigned)P2PoolTicketHeldForTest(e), e);
            abort();
        }
    size_t nZero;
    CRITICAL_BLOCK(cs_p2pool)
        nZero = P2PoolChain().Size();
    if (nZero != 0 || P2PoolOrphanCount() != 0)
    {
        fprintf(stderr, "fuzz-pooltkt: ticket traffic reached pool zero\n");
        abort();
    }
    if (P2PoolDeferredCount() != 0)
    {
        fprintf(stderr, "fuzz-pooltkt: %u connections still held after theirs closed\n", (unsigned)P2PoolDeferredCount());
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

static void AppendRaw(string& str, int nKind, const string& s)
{
    CDataStream ss(SER_NETWORK, VERSION);
    if (!s.empty())
        ss.write(s.data(), s.size());
    AppendRecord(str, nKind, ss);
}

static void WriteSeed(const string& strDir, const char* pszName, const string& str)
{
    string strPath = strDir + "/" + pszName;
    WriteFile(strPath, (const uint8_t*)str.data(), str.size());
}

static std::vector<CGuardTicket> SeedTickets(unsigned int nEpoch, unsigned int iFirst, unsigned int n)
{
    std::vector<CGuardTicket> v;
    for (unsigned int i = 0; i < n; i++)
    {
        string s = strprintf("fuzz-pooltkt-key/%u", iFirst + i);
        uint256 k = Hash(s.begin(), s.end());
        CGuardTicket t;
        uint256 w;
        uint64 nTries = 0;
        if (pooltkt::MakeTicket(g_params, SeedOf(nEpoch), nEpoch, k.begin(), 64, 0, 1000, t, w, nTries))
            v.push_back(t);
    }
    return v;
}

static string StepRecord()
{
    string str;
    CDataStream ss(SER_NETWORK, VERSION);
    ss << (unsigned char)63 << (unsigned char)0;
    AppendRecord(str, K_STEP, ss);
    return str;
}

static void WriteSeeds(const string& strDir)
{
    std::vector<CGuardTicket> v6 = SeedTickets(6, 1, 8), v5 = SeedTickets(5, 20, 4), v4 = SeedTickets(4, 40, 4);
    {
        string str(1, (char)(F_ASKED | F_REFILL));
        CDataStream ss(SER_NETWORK, VERSION);
        ss << (unsigned int)6 << SeedOf(6) << v6;
        AppendRecord(str, K_TKT, ss);
        CDataStream s5(SER_NETWORK, VERSION);
        s5 << (unsigned int)5 << SeedOf(5) << v5;
        AppendRecord(str, K_TKT, s5);
        str += StepRecord();
        CDataStream sp(SER_NETWORK, VERSION);
        AppendRecord(str, K_PASS, sp);
        WriteSeed(strDir, "answer", str);
    }
    {
        string str(1, (char)F_REFILL);
        CDataStream ss(SER_NETWORK, VERSION);
        ss << (unsigned int)6 << SeedOf(6) << std::vector<CGuardTicket>(v6.begin(), v6.begin() + 4);
        AppendRecord(str, K_TKT, ss);
        str += StepRecord();
        CDataStream sg(SER_NETWORK, VERSION);
        sg << (unsigned int)6;
        AppendRecord(str, K_GETTKT, sg);
        CDataStream s5(SER_NETWORK, VERSION);
        s5 << (unsigned int)5 << SeedOf(5) << v5;   // a relay past epoch 5's deadline
        AppendRecord(str, K_TKT, s5);
        WriteSeed(strDir, "relay-gettkt-deadline", str);
    }
    {
        // Bad: a signature, another network's magic, a body of another
        // epoch, a count over 512, a short ticket, another seed; with the
        // valid head and without.
        string str(1, (char)(F_ASKED | F_HEAD));
        std::vector<CGuardTicket> vBad = v4;
        vBad[0].sig[5] ^= 0x40;
        vBad[1].body[0] ^= 1;
        CDataStream sb(SER_NETWORK, VERSION);
        sb << (unsigned char)0 << vBad;           // epoch 4 by the head
        AppendRecord(str, K_TKT, sb);
        CDataStream se(SER_NETWORK, VERSION);
        se << (unsigned char)1 << v4;             // epoch 5's head, epoch 4's bodies
        AppendRecord(str, K_TKT, se);
        CDataStream sc(SER_NETWORK, VERSION);
        sc << (unsigned char)2;
        WriteCompactSize(sc, 513);
        AppendRecord(str, K_TKT, sc);
        CDataStream ss(SER_NETWORK, VERSION);
        ss << (unsigned char)2;
        WriteCompactSize(ss, 1);
        ss.write(string(117, 'x').data(), 117);
        AppendRecord(str, K_TKT, ss);
        str += StepRecord();
        WriteSeed(strDir, "bad", str);
        string strOld(1, (char)(F_OLD | F_INBOUND));
        CDataStream so(SER_NETWORK, VERSION);
        so << (unsigned int)6 << uint256(77) << v6;
        AppendRecord(strOld, K_TKT, so);
        CDataStream sg(SER_NETWORK, VERSION);
        sg << (unsigned int)6;
        AppendRecord(strOld, K_GETTKT, sg);
        WriteSeed(strDir, "old-peer-other-seed", strOld);
    }
    {
        // A file of this node's own making, read back at a start.
        FuzzView view;
        CTicketBook book(g_params);
        for (size_t i = 0; i < v6.size(); i++)
            book.Accept(view, v6[i], SeedOf(6), true);
        for (size_t i = 0; i < v4.size(); i++)
            book.Accept(view, v4[i], SeedOf(4), true);
        string data = pooltkt::TicketFileData(book);
        string str(1, (char)F_REFILL);
        AppendRaw(str, K_FILE, data);
        str += StepRecord();
        CDataStream sa(SER_NETWORK, VERSION);
        sa << (unsigned char)100;
        AppendRecord(str, K_AGE, sa);
        CDataStream sp(SER_NETWORK, VERSION);
        AppendRecord(str, K_PASS, sp);
        WriteSeed(strDir, "file", str);
    }
}

static void FuzzPoolTktInit()
{
    SelectChainParams(false);
    // Mainnet's parameters, with registered pools opened in this process
    // (closed, every ticket message is dropped unread: nothing to fuzz).
    PoolBurnsOpenForTest(true);
    P2PoolResetForTest(bnProofOfWorkLimit, false);
    g_params = CTicketParams::Network();
    g_params.fnWork = StandInWork;
    P2PoolTicketParamsForTest(g_params);
    for (int h = 0; h <= TIP; h++)
    {
        string s = strprintf("fuzz-pooltkt-block/%d", h);
        g_vChain.push_back(Hash(s.begin(), s.end()));
    }
    P2PoolTicketViewForTest(g_vChain);
    uint256 k = Hash(BEGIN(TIP), END(TIP));
    P2PoolTicketKeyForTest(k.begin());
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
        P2PoolTicketBudgetForTest(256);
    Conn c = NewConn(nFlags);
    if (nFlags & F_ASKED)
    {
        try
        {
            P2PoolOnVersion(c.node.get());
        }
        catch (std::exception&) {}
        P2PoolTicketAgeForTest(700);
        P2PoolRegTickForTest();
        CheckConn(c);
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
