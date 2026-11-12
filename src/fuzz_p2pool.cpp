// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the share chain, fed as an untrusted peer feeds it: every
// P2Pool message (p2pshare, p2ppeers, p2pgetsh, p2psync, p2pshares) through
// P2PoolProcessMessage(), and raw share records straight into the share
// chain's acceptance (the path the node's own miner takes, P2PoolSubmitShare).
// The share chain, its orphans and its budgets live for the whole run, as in
// a node, so share validation, chain selection, uncles, orphan resolution,
// history, Prune and Evict are reached across inputs.
//
// In this binary only (-DBITFLASH_FUZZ), fFuzzShareWorkStandIn replaces the
// RandomX comparison with a rule on nNonce (bit 0 clear: the work holds; bit
// 1 set: it is also a block). Everything around it runs as released,
// including the shared budget asked right before that hash.
//
// Input layout:
//   byte 0   flags:
//              bit 0  the peer is inbound (else one this node dialled)
//              bit 1  the peer has already sent a share this node took
//              bit 2  the peer's version arrives first (P2PoolOnVersion)
//              bit 3  fix up each share's link: height, target and time from
//                     its parent here, a payout script that is an address
//              bit 4  fix up each share's coinbase to pay its window
//              bit 5  fix up each share's commitment and merkle root
//              bit 6  every shared budget full first, so an unproven peer's
//                     shares are hashed (else the budgets carry over from the
//                     inputs before, and are mostly spent)
//   then up to 32 records [kind][length, 2 bytes little-endian][payload]:
//     kind % 8: 0 p2pshare, 1 p2ppeers, 2 p2pgetsh, 3 p2psync, 4 p2pshares,
//               5 the share in the payload offered as this node's own,
//               6 this node asks the peer for its history now (no payload),
//               7 the peer reconnects: a new connection, same flags
//
// After every input the share chain must hold ShareChain::CheckInvariants
// and the orphan queue its cap; anything else aborts.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus (a line of shares,
// the same line children first, a history, uncles, a heavier fork, getsh,
// sync, peers, an inbound flood) into <dir> and exits.

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

static void FuzzP2PoolInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzP2PoolInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using namespace p2pool;

static const unsigned char F_INBOUND = 1;
static const unsigned char F_PROVEN = 2;
static const unsigned char F_VERSION = 4;
static const unsigned char F_FIX_LINK = 8;
static const unsigned char F_FIX_PAY = 16;
static const unsigned char F_FIX_COMMIT = 32;
static const unsigned char F_REFILL = 64;

enum
{
    K_SHARE = 0, K_PEERS, K_GETSH, K_SYNC, K_SHARES, K_OWN, K_ASK, K_RECONNECT
};
static const char* const kCommands[] = { "p2pshare", "p2ppeers", "p2pgetsh", "p2psync", "p2pshares" };

static vector<unsigned char> PayTo(unsigned char tag)
{
    vector<unsigned char> s;
    s.push_back(OP_DUP); s.push_back(OP_HASH160); s.push_back(20);
    for (int i = 0; i < 20; i++) s.push_back((unsigned char)(tag + i));
    s.push_back(OP_EQUALVERIFY); s.push_back(OP_CHECKSIG);
    return s;
}

// The fix-ups (flags 3 to 5), so mutated shares stay valid enough to reach
// what is behind each check. Under cs_p2pool.
static void FixShare(Share& s, unsigned char nFlags)
{
    ShareChain& chain = P2PoolChain();
    ShareData& d = s.data;
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
        if (chain.WindowFor(d, WorkOf(d.nShareBits), window, err) && ComputePayouts(window, nTotal, pay, err))
        {
            s.coinbase.vout.clear();
            for (size_t i = 0; i < pay.size(); i++)
                s.coinbase.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));
        }
    }
    if (nFlags & F_FIX_COMMIT)
    {
        s.coinbase.vin.resize(1);
        s.coinbase.vin[0].prevout.SetNull();
        s.coinbase.vin[0].scriptSig = CScript() << nHeight << CommitmentPush(d.GetHash());
        if (s.vMerkleBranch.size() > 32)
            s.vMerkleBranch.resize(32);
        s.hashMerkleRoot = CBlock::CheckMerkleBranch(s.coinbase.GetHash(), s.vMerkleBranch, 0);
    }
}

static void FixPayload(int nKind, CDataStream& vMsg, unsigned char nFlags)
{
    if (!(nFlags & (F_FIX_LINK | F_FIX_PAY | F_FIX_COMMIT)))
        return;
    try
    {
        CDataStream vCopy(vMsg);
        CDataStream vFixed(SER_NETWORK, VERSION);
        if (nKind == K_SHARE || nKind == K_OWN)
        {
            Share s;
            vCopy >> s;
            CRITICAL_BLOCK(cs_p2pool)
                FixShare(s, nFlags);
            vFixed << s;
        }
        else if (nKind == K_SHARES)
        {
            int nTip;
            vector<Share> v;
            vCopy >> nTip >> v;
            // Each in turn, against the chain as it stands: a history's later
            // shares hang on earlier ones the fix-up cannot see yet, so only
            // the payout and commitment fixes help past the first.
            CRITICAL_BLOCK(cs_p2pool)
                for (size_t i = 0; i < v.size(); i++)
                    FixShare(v[i], nFlags);
            vFixed << nTip << v;
        }
        else
            return;
        if (!vCopy.empty())
            vFixed.write(&vCopy[0], vCopy.size());   // trailing bytes stay
        vMsg = vFixed;
    }
    catch (std::exception&)
    {
        // Not what it claims: the bytes go in as they are.
    }
}

static std::unique_ptr<CNode> NewPeer(unsigned char nFlags)
{
    std::unique_ptr<CNode> p(new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), (nFlags & F_INBOUND) != 0));
    p->nVersion = VERSION;
    p->nServices = NODE_P2POOL;
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    if (nFlags & F_PROVEN)
        p->nP2PoolLastGood = GetTime();
    return p;
}

static void HandleRecord(std::unique_ptr<CNode>& node, int nKind, unsigned char nFlags, const uint8_t* data, size_t size)
{
    if (nKind == K_RECONNECT)
    {
        // What the budgets held back for the old connection is served or
        // dropped first: the node never frees a peer that is still held.
        P2PoolServeDeferred();
        P2PoolForgetDeferred(node.get());
        node = NewPeer(nFlags);
        return;
    }
    if (nKind == K_ASK)
    {
        node->nP2PoolSyncAskedAt = GetTime();
        node->nP2PoolHistoryRecv = 0;
        return;
    }
    CDataStream vMsg((const char*)data, (const char*)data + size, SER_NETWORK, VERSION);
    FixPayload(nKind, vMsg, nFlags);
    try
    {
        if (nKind == K_OWN)
        {
            Share s;
            vMsg >> s;
            string err;
            P2PoolSubmitShare(s, err);
        }
        else
            P2PoolProcessMessage(node.get(), kCommands[nKind], vMsg);
    }
    catch (std::exception&)
    {
        // A payload that does not deserialise ends the message, as in
        // ProcessMessages().
    }
    // What the node queued for the peer is not read by anybody here; a peer
    // that never reads is bounded by the node itself, which is what the
    // send-queue checks are for, so keep it across records.
}

static void CheckState()
{
    string err;
    bool fOk;
    size_t nShares;
    CRITICAL_BLOCK(cs_p2pool)
    {
        fOk = P2PoolChain().CheckInvariants(err);
        nShares = P2PoolChain().Size();
    }
    if (!fOk)
    {
        fprintf(stderr, "fuzz-p2pool: share chain invariant broken: %s (%u shares)\n", err.c_str(), (unsigned)nShares);
        abort();
    }
    if (P2PoolOrphanCount() > 256)
    {
        fprintf(stderr, "fuzz-p2pool: %u orphan shares queued, more than the cap\n", (unsigned)P2PoolOrphanCount());
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

// A share on 'parent' that pays exactly what the chain says it must, with
// stand-in work, added to the chain so the next can build on it.
static Share SeedShare(const uint256& parent, unsigned char tag, unsigned int nTime,
                       const vector<uint256>& uncles = vector<uint256>(), bool fAdd = true)
{
    ShareChain& chain = P2PoolChain();
    Share s;
    s.data.hashPrevShare = parent;
    s.data.vUncles = uncles;
    s.data.payoutScript = PayTo(tag);
    s.coinbase.vin.resize(1);
    s.coinbase.vin[0].prevout.SetNull();
    s.coinbase.vin[0].scriptSig = CScript() << 61001;
    s.nVersion = 1;
    s.hashPrevBlock = 0;
    s.nTime = nTime;
    s.nBits = 0x1d00ffff;
    s.nNonce = 0;
    FixShare(s, F_FIX_LINK | F_FIX_PAY | F_FIX_COMMIT);
    if (fAdd)
    {
        string err;
        NodeMainView main;
        if (!chain.Add(s, main, err))
        {
            fprintf(stderr, "fuzz-p2pool: seed share refused: %s\n", err.c_str());
            exit(1);
        }
    }
    return s;
}

static void WriteSeeds(const string& strDir)
{
    CRITICAL_BLOCK(cs_p2pool)
    {
        unsigned int t = (unsigned int)GetAdjustedTime() - 2000;
        vector<Share> line;
        uint256 prev = 0;
        for (int i = 0; i < 30; i++)
        {
            line.push_back(SeedShare(prev, (unsigned char)(1 + i % 5), t + 10 * i));
            prev = line.back().GetId();
        }
        // An uncle: a sibling of line[27], named by a share on line[29].
        Share sib = SeedShare(line[26].GetId(), 40, t + 10 * 27 + 3);
        vector<uint256> uncles = P2PoolChain().UncleCandidates(line[29].GetId());
        Share withUncle = SeedShare(line[29].GetId(), 41, t + 10 * 30, uncles);
        // A fork from line[20] that grows past the tip.
        vector<Share> fork;
        uint256 fp = line[20].GetId();
        for (int i = 0; i < 14; i++)
        {
            fork.push_back(SeedShare(fp, 50, t + 10 * 21 + 5 + 10 * i));
            fp = fork.back().GetId();
        }

        {
            string str(1, (char)0);
            for (size_t i = 0; i < line.size(); i++)
                AppendItem(str, K_SHARE, line[i]);
            WriteRaw(strDir, "line", str);
        }
        {
            string str(1, (char)0);
            for (size_t i = line.size(); i-- > 0;)
                AppendItem(str, K_SHARE, line[i]);
            WriteRaw(strDir, "line-children-first", str);
        }
        {
            string str(1, (char)0);
            for (size_t i = 0; i < line.size(); i++)
                AppendItem(str, K_SHARE, line[i]);
            AppendItem(str, K_SHARE, sib);
            AppendItem(str, K_SHARE, withUncle);
            for (size_t i = 0; i < fork.size(); i++)
                AppendItem(str, K_SHARE, fork[i]);
            WriteRaw(strDir, "line-uncle-fork", str);
        }
        {
            string str(1, (char)0);
            CDataStream ss(SER_NETWORK, VERSION);
            AppendRecord(str, K_ASK, ss);
            ss << (int)line.size() - 1 << line;
            AppendRecord(str, K_SHARES, ss);
            WriteRaw(strDir, "history", str);
        }
        {
            string str(1, (char)0);
            for (size_t i = 0; i < line.size(); i++)
                AppendItem(str, K_OWN, line[i]);
            vector<uint256> ids;
            for (size_t i = 0; i < line.size(); i += 3)
                ids.push_back(line[i].GetId());
            AppendItem(str, K_GETSH, ids);
            AppendRecord(str, K_SYNC, CDataStream(SER_NETWORK, VERSION));
            AppendRecord(str, K_RECONNECT, CDataStream(SER_NETWORK, VERSION));
            AppendRecord(str, K_SYNC, CDataStream(SER_NETWORK, VERSION));
            WriteRaw(strDir, "own-getsh-sync", str);
        }
        {
            string str(1, (char)(F_INBOUND | F_VERSION));
            vector<string> names;
            names.push_back("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.btf");
            names.push_back("x");
            AppendItem(str, K_PEERS, names);
            AppendItem(str, K_PEERS, names);
            WriteRaw(strDir, "inbound-version-peers", str);
        }
        {
            // An unproven inbound peer: the line's children first, so each
            // is an orphan hashed on the shared budget.
            string str(1, (char)F_INBOUND);
            for (size_t i = line.size(); i-- > 1;)
                AppendItem(str, K_SHARE, line[i]);
            AppendRecord(str, K_RECONNECT, CDataStream(SER_NETWORK, VERSION));
            AppendItem(str, K_SHARE, line[29]);
            AppendItem(str, K_SHARE, line[0]);
            WriteRaw(strDir, "inbound-orphans", str);
        }
        {
            // Mutable shapes with every fix-up on: bad work (odd nonce), a
            // block (bit 1), and a share with no parent here.
            string str(1, (char)(F_FIX_LINK | F_FIX_PAY | F_FIX_COMMIT));
            Share bad = line[0];
            bad.nNonce = 1;
            AppendItem(str, K_SHARE, bad);
            Share block = line[0];
            block.nNonce = 2;
            AppendItem(str, K_SHARE, block);
            for (size_t i = 0; i < 5; i++)
                AppendItem(str, K_SHARE, line[i]);
            Share lost = line[5];
            lost.data.hashPrevShare = uint256(12345);
            AppendItem(str, K_SHARE, lost);
            WriteRaw(strDir, "fixups", str);
        }
    }
}

// The node's global maps (the share chain, peer cache) live for the run and
// are never freed, as in a node: no leak check at exit (fuzz_datadir.h);
// libFuzzer checks for leaks after each input.

static void FuzzP2PoolInit()
{
    SelectChainParams(false);
    fFuzzShareWorkStandIn = true;
    // A byte cap a run reaches within a few inputs (the real one is 128 MB):
    // a line of seed shares is a few kB, so Evict, the near-tip lines it keeps
    // and the cap that rises above what is kept all run; CheckInvariants
    // holds them to the same rules. (256 kB was never reached: the campaign's
    // coverage showed Kept and ByteCap at 0%.)
    CRITICAL_BLOCK(cs_p2pool)
        P2PoolChain().SetMaxBytesForTest(4 * 1000);
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // A history part is up to 400 shares; this allows a few dozen real ones
    // and keeps each input quick.
    if (size < 1 || size > 300000)
        return 0;
    unsigned char nFlags = data[0];
    data++;
    size--;
    if (nFlags & F_REFILL)
        P2PoolRefillBudgetsForTest();
    std::unique_ptr<CNode> node = NewPeer(nFlags);
    if (nFlags & F_VERSION)
    {
        try { P2PoolOnVersion(node.get()); }
        catch (std::exception&) {}
    }
    for (int n = 0; n < 32 && size >= 3; n++)
    {
        int nKind = data[0] % 8;
        size_t nLen = data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (nLen > size)
            nLen = size;
        HandleRecord(node, nKind, nFlags, data, nLen);
        data += nLen;
        size -= nLen;
    }
    // What the budgets held back, served as they allow (the message thread
    // does this after every pass), then the connection goes.
    P2PoolServeDeferred();
    P2PoolForgetDeferred(node.get());
    CheckState();
    if (P2PoolDeferredCount() != 0)
    {
        fprintf(stderr, "fuzz-p2pool: %u connections still held after theirs closed\n", (unsigned)P2PoolDeferredCount());
        abort();
    }
    return 0;
}
