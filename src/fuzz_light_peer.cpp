// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the embedded light clients (btclight.cpp), fed what a
// foreign chain's peer sends: the version handshake, addr, headers (with
// AuxPoW on Dogecoin), cfheaders and cfilter (Bitcoin's BIP157), blocks for
// the scan, and the unsolicited ping, reject and notfound in between. The
// bytes go through the client's own receive path (Peer::Receive: magic,
// command, size budget, checksum) into the worker's real code: Round,
// PullHeaders, Headers::Add with each chain's proof of work and retarget,
// ScanBlocks, VerifyBlock, the filter checks, then Find and Call on what was
// kept. fuzz-light-pow covers DigiByte's and Ravencoin's PoW arithmetic
// alone; this one covers the clients around it, per chain.
//
// Input layout:
//   byte 0   which chain and network (an index into kNets)
//   byte 1   flags:
//              bit 0  a second peer (its records have bit 7 of their kind set)
//              bit 1  the version handshake first, on the primary
//              bit 2  getaddr before the rounds
//              bit 3  Find and Call afterwards
//              bit 4  merkle mode: the rest is one block (see below)
//              bit 5  filter mode: the rest is a block hash and scripts
//              bit 6  (merkle mode) write the block's real merkle root into
//                     its header first, so the accepting path is reached
//              bit 7  skip the header hash's comparison with its target (in
//                     this binary only, btclight's fFuzzLightSkipPoW), so main
//                     and test networks' retarget and time rules are reached
//   byte 2   rounds, 1 + byte % 3
//   then records [kind][length, 2 bytes little-endian][payload]; kind & 0x7f
//   indexes kCommands, framed by the harness with the chain's magic and a
//   correct checksum (no fuzzer forges a double SHA-256); the last entry
//   appends the payload to the stream unframed, so the framing checks are
//   fuzzed too.
//
// Merkle mode, the differential: the block is checked by VerifyBlock against
// a header carrying its first bytes. When it passes, the merkle root must
// equal the one Bitflash's own CBlock code computes from the same
// transactions, and every transaction's branch (CBlock::GetMerkleBranch)
// must climb to it (CBlock::CheckMerkleBranch). The block re-encoded must
// pass too, and a copy with its last transaction (or last two) repeated --
// which leaves the merkle root unchanged, CVE-2012-2459 -- must fail.
//
// Filter mode, the round trip: EncodeFilter over the scripts, then
// MatchFilter must call the filter well formed and find every script in it.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes, for every regtest chain, a header
// chain with blocks that fund and then spend the watched contract (and on
// Bitcoin the filter headers and filters for them), plus merkle and filter
// seeds, into <dir> and exits.

#include "headers_core.h"
#include "btclight.h"
#include "swap.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <algorithm>
#include <set>
#include <string>
#include <vector>

static void FuzzLightInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzLightInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using btclight::Bytes;

static const char* const kNets[][2] = {
    {"btc", "regtest"}, {"ltc", "regtest"}, {"doge", "regtest"}, {"dgb", "regtest"}, {"rvn", "regtest"},
    {"bch", "regtest"}, {"xec", "regtest"},
    {"btc", "main"}, {"btc", "testnet4"}, {"ltc", "main"}, {"ltc", "test"}, {"doge", "main"}, {"doge", "test"},
    {"dgb", "main"}, {"dgb", "test"}, {"rvn", "main"}, {"bch", "main"}, {"bch", "test4"}, {"xec", "main"},
    {"xec", "test"},
};
static const size_t kNumNets = sizeof(kNets) / sizeof(kNets[0]);

static const char* const kCommands[] = {
    "headers", "block", "cfheaders", "cfilter", "addr", "version", "verack", "ping", "reject", "notfound",
    "inv", "tx", "sendheaders", "pong",
    NULL, // raw bytes, unframed
};
static const size_t kNumCommands = sizeof(kCommands) / sizeof(kCommands[0]);

static const unsigned char F_SECOND = 1, F_HANDSHAKE = 2, F_DISCOVER = 4, F_QUERY = 8, F_MERKLE = 16,
                           F_FILTER = 32, F_FIX_MERKLE = 64, F_SKIP_POW = 128;

static const btclight::Net* NetAt(size_t i)
{
    return btclight::FindNet(kNets[i][0], kNets[i][1]);
}

static void PutLE(Bytes& b, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; ++i) b.push_back((unsigned char)(v >> (8 * i)));
}

static void PutCompact(Bytes& b, uint64_t v)
{
    if (v < 253) b.push_back((unsigned char)v);
    else if (v <= 0xffff) { b.push_back(253); PutLE(b, v, 2); }
    else if (v <= 0xffffffffULL) { b.push_back(254); PutLE(b, v, 4); }
    else { b.push_back(255); PutLE(b, v, 8); }
}

static void PutHash(Bytes& b, uint256 h)
{
    b.insert(b.end(), h.begin(), h.end());
}

static uint256 Digest(const Bytes& b)
{
    return Hash(b.begin(), b.end());
}

// One message as the peer's node would frame it.
static void Frame(Bytes& out, unsigned int magic, const std::string& command, const Bytes& payload)
{
    PutLE(out, magic, 4);
    Bytes cmd(command.begin(), command.end());
    cmd.resize(12, 0);
    out.insert(out.end(), cmd.begin(), cmd.end());
    PutLE(out, payload.size(), 4);
    uint256 h = Digest(payload);
    out.insert(out.end(), h.begin(), h.begin() + 4);
    out.insert(out.end(), payload.begin(), payload.end());
}

static Bytes Serialize(const CTransaction& tx)
{
    CDataStream ss(SER_NETWORK, VERSION);
    ss << tx;
    return Bytes(ss.begin(), ss.end());
}

// The contract every session watches: fixed keys, a fixed secret, a time lock.
static const unsigned char kSecretByte = 0x33;
static swap::Contract TheContract()
{
    swap::Contract c;
    c.recipientPkh.assign(20, 0x11);
    c.refundPkh.assign(20, 0x22);
    Bytes secret(32, kSecretByte);
    c.secretHash.resize(32);
    SHA256(&secret[0], secret.size(), &c.secretHash[0]);
    c.nLockTime = 1700000000;
    return c;
}

// ---- merkle and filter modes

static Bytes Reencode(const Bytes& header, const std::vector<CTransaction>& txs, size_t nRepeat)
{
    Bytes out(header);
    PutCompact(out, txs.size() + nRepeat);
    for (size_t i = 0; i < txs.size(); i++)
    {
        Bytes t = Serialize(txs[i]);
        out.insert(out.end(), t.begin(), t.end());
    }
    for (size_t i = txs.size() - nRepeat; i < txs.size(); i++)
    {
        Bytes t = Serialize(txs[i]);
        out.insert(out.end(), t.begin(), t.end());
    }
    return out;
}

static void MerkleMode(const btclight::Net& net, unsigned char nFlags, const uint8_t* data, size_t size)
{
    if (size < net.headerSize + 1)
        return;
    Bytes raw(data, data + size);
    std::vector<CTransaction> txs;
    if ((nFlags & F_FIX_MERKLE) && btcswap::ParseBlockTxs(raw, txs, net.auxPow, net.headerSize) && !txs.empty())
    {
        CBlock b;
        b.vtx = txs;
        uint256 root = b.BuildMerkleTree();
        memcpy(&raw[36], root.begin(), 32);
    }
    btclight::Header h;
    h.raw.assign(raw.begin(), raw.begin() + net.headerSize);
    h.merkle = uint256(Bytes(raw.begin() + 36, raw.begin() + 68));
    txs.clear();
    if (!btclight::VerifyBlock(raw, h, txs, net.maxBlock, net.auxPow))
        return;

    // Bitflash's own merkle code, from the same transactions, agrees.
    CBlock b;
    b.vtx = txs;
    uint256 root = b.BuildMerkleTree();
    if (root != h.merkle)
    {
        fprintf(stderr, "fuzz-light-peer: VerifyBlock accepted a root CBlock does not compute\n");
        abort();
    }
    for (size_t i = 0; i < txs.size() && i < 16; i++)
        if (CBlock::CheckMerkleBranch(txs[i].GetHash(), b.GetMerkleBranch((int)i), (int)i) != h.merkle)
        {
            fprintf(stderr, "fuzz-light-peer: the branch of transaction %u does not climb to the root\n", (unsigned)i);
            abort();
        }
    // A merged-mined header is followed by its AuxPoW; the re-encoding below
    // writes the transactions straight after the header.
    if (net.auxPow && (raw[1] & 0x01))
        return;
    std::vector<CTransaction> again;
    if (!btclight::VerifyBlock(Reencode(h.raw, txs, 0), h, again, ~(size_t)0, net.auxPow) || again.size() != txs.size())
    {
        fprintf(stderr, "fuzz-light-peer: the block re-encoded no longer verifies\n");
        abort();
    }
    // The same root with a repeated tail: refused.
    // Only below the top of the tree: one transaction repeated, or two out of
    // two, adds a level and changes the root.
    size_t nRepeat = txs.size() % 2 == 1 && txs.size() > 1 ? 1 : (txs.size() % 4 == 2 && txs.size() > 2 ? 2 : 0);
    if (nRepeat)
    {
        CBlock m;
        m.vtx = txs;
        for (size_t i = txs.size() - nRepeat; i < txs.size(); i++)
            m.vtx.push_back(txs[i]);
        if (m.BuildMerkleTree() != h.merkle)
        {
            fprintf(stderr, "fuzz-light-peer: a repeated tail changed the merkle root\n");
            abort();
        }
        if (btclight::VerifyBlock(Reencode(h.raw, txs, nRepeat), h, again, ~(size_t)0, net.auxPow))
        {
            fprintf(stderr, "fuzz-light-peer: VerifyBlock accepted a block with a repeated tail (CVE-2012-2459)\n");
            abort();
        }
    }
}

static void FilterMode(const uint8_t* data, size_t size)
{
    if (size < 32)
        return;
    const Bytes all(data, data + size);
    uint256 block(Bytes(data, data + 32));
    data += 32;
    size -= 32;
    std::vector<Bytes> scripts;
    while (size && scripts.size() < 64)
    {
        size_t n = std::min<size_t>(data[0], size - 1);
        scripts.push_back(Bytes(data + 1, data + 1 + n));
        data += 1 + n;
        size -= 1 + n;
    }
    Bytes filter = btclight::EncodeFilter(block, scripts);
    for (size_t i = 0; i < scripts.size(); i++)
    {
        if (scripts[i].empty() || scripts[i][0] == OP_RETURN)
            continue;
        bool match = false;
        if (!btclight::MatchFilter(block, filter, std::vector<Bytes>(1, scripts[i]), match) || !match)
        {
            fprintf(stderr, "fuzz-light-peer: a script encoded into a filter is not found in it\n");
            abort();
        }
    }
    bool match;
    if (!btclight::MatchFilter(block, filter, std::vector<Bytes>(), match) || match)
    {
        fprintf(stderr, "fuzz-light-peer: an encoded filter is not well formed\n");
        abort();
    }
    // And the input itself read as a filter: whatever it says, no crash.
    btclight::MatchFilter(block, all, scripts, match);
}

// ---- seeds

static void WriteRaw(const string& strDir, const string& strName, const Bytes& b)
{
    string strPath = strDir + "/" + strName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    if (!b.empty())
        fwrite(&b[0], 1, b.size(), f);
    fclose(f);
}

static void AppendRecord(Bytes& in, unsigned char kind, const Bytes& payload)
{
    in.push_back(kind);
    in.push_back((unsigned char)(payload.size() & 0xff));
    in.push_back((unsigned char)((payload.size() >> 8) & 0xff));
    in.insert(in.end(), payload.begin(), payload.end());
}

static unsigned char CommandIndex(const char* psz)
{
    for (size_t i = 0; i + 1 < kNumCommands; i++)
        if (strcmp(kCommands[i], psz) == 0)
            return (unsigned char)i;
    abort();
}

struct SeedChain
{
    std::vector<Bytes> headers;   // after the starting point
    std::vector<Bytes> blocks;    // the same heights
    std::vector<uint256> hashes;  // as the client names them
};

// A header chain on the net's start, each header ground until the client's
// own Headers::Add takes it, with blocks that pay and then spend the contract.
static bool BuildChain(const btclight::Net& net, SeedChain& out)
{
    btclight::Headers headers(net);
    swap::Contract c = TheContract();
    CScript contract = swap::BuildContract(c);
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);
    uint256 fundingTx = 0;
    const btclight::Header& start = headers.Tip();
    unsigned int version = (unsigned int)(start.raw[0] | (start.raw[1] << 8) | (start.raw[2] << 16) | ((unsigned int)start.raw[3] << 24));
    if (net.auxPow) version &= ~0x100U;
    for (int height = 1; height <= 6; height++)
    {
        std::vector<CTransaction> txs;
        CTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vin[0].scriptSig = CScript() << height << OP_0;
        cb.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
        txs.push_back(cb);
        if (height == 2)
        {
            CTransaction fund;
            fund.vin.resize(1);
            fund.vin[0].prevout = COutPoint(Hash(BEGIN(height), END(height)), 0);
            fund.vout.push_back(CTxOut(COIN, p2sh));
            fund.vout.push_back(CTxOut(2 * COIN, CScript() << OP_TRUE));
            txs.push_back(fund);
            fundingTx = fund.GetHash();
        }
        if (height == 4)
        {
            CTransaction spend;
            spend.vin.resize(1);
            spend.vin[0].prevout = COutPoint(fundingTx, 0);
            spend.vin[0].scriptSig = swap::RedeemScriptSig(Bytes(72, 0x30), Bytes(33, 0x02), Bytes(32, kSecretByte), contract);
            spend.vout.push_back(CTxOut(COIN / 2, CScript() << OP_TRUE));
            txs.push_back(spend);
        }
        CBlock b;
        b.vtx = txs;
        uint256 root = b.BuildMerkleTree();
        const btclight::Header& parent = headers.Tip();
        Bytes raw;
        PutLE(raw, version, 4);
        PutHash(raw, parent.hash);
        PutHash(raw, root);
        PutLE(raw, parent.time + 600, 4);
        PutLE(raw, parent.bits, 4);
        PutLE(raw, 0, 4);
        raw.resize(net.headerSize, 0);
        std::string err;
        bool fOk = false;
        for (uint32_t nonce = 0; nonce < 20000 && !fOk; nonce++)
        {
            for (int i = 0; i < 4; i++) raw[76 + i] = (unsigned char)(nonce >> (8 * i));
            fOk = headers.Add(raw, err);
        }
        if (!fOk)
        {
            fprintf(stderr, "fuzz-light-peer: %s %s: no header found (%s)\n", net.coin.c_str(), net.name.c_str(), err.c_str());
            return false;
        }
        Bytes block(raw);
        PutCompact(block, txs.size());
        for (size_t i = 0; i < txs.size(); i++)
        {
            Bytes t = Serialize(txs[i]);
            block.insert(block.end(), t.begin(), t.end());
        }
        out.headers.push_back(raw);
        out.blocks.push_back(block);
        out.hashes.push_back(headers.Tip().hash);
    }
    return true;
}

static Bytes HeadersPayload(const std::vector<Bytes>& v)
{
    Bytes p;
    PutCompact(p, v.size());
    for (size_t i = 0; i < v.size(); i++)
    {
        p.insert(p.end(), v[i].begin(), v[i].end());
        p.push_back(0);
    }
    return p;
}

// Headers on a main or test network's starting point, each with the bits
// the client expects and a time past the median, taken with the PoW
// comparison skipped (the input carries F_SKIP_POW).
static bool BuildSkippedChain(const btclight::Net& net, std::vector<Bytes>& out)
{
    btclight::FuzzSkipPoW(true);
    btclight::Headers headers(net);
    for (int i = 0; i < 4; i++)
    {
        const btclight::Header& parent = headers.Tip();
        unsigned int version = net.strictChainId ? (unsigned int)(net.auxChainId << 16) | 4 : 0x20000000;
        unsigned int time = (unsigned int)std::max<int64>(headers.Median(parent) + 1, (int64)parent.time + net.spacing);
        Bytes raw;
        PutLE(raw, version, 4);
        PutHash(raw, parent.hash);
        PutHash(raw, Hash(BEGIN(i), END(i)));
        PutLE(raw, time, 4);
        PutLE(raw, headers.NextBits(parent, time), 4);
        PutLE(raw, 0, 4);
        raw.resize(net.headerSize, 0);
        std::string err;
        if (!headers.Add(raw, err))
        {
            fprintf(stderr, "fuzz-light-peer: %s %s: skipped-PoW header refused (%s)\n", net.coin.c_str(), net.name.c_str(), err.c_str());
            btclight::FuzzSkipPoW(false);
            return false;
        }
        out.push_back(raw);
    }
    btclight::FuzzSkipPoW(false);
    return true;
}

// A merged-mined header on Dogecoin's regtest start: version bit 0x100, an
// AuxPoW whose parent coinbase carries the header's hash after the merged-
// mining marker, and whose parent header pays scrypt's easy regtest target.
// Returns the headers message payload.
static Bytes MergedHeaderPayload(const btclight::Net& net)
{
    btclight::Headers headers(net);
    const btclight::Header& parent = headers.Tip();
    Bytes raw;
    PutLE(raw, 0x100 | 4 | (unsigned int)(net.auxChainId << 16), 4);
    PutHash(raw, parent.hash);
    PutHash(raw, Hash(BEGIN(net.magic), END(net.magic)));
    PutLE(raw, parent.time + 60, 4);
    PutLE(raw, parent.bits, 4);
    PutLE(raw, 0, 4);
    uint256 id = Digest(raw);
    Bytes root(id.begin(), id.end());
    std::reverse(root.begin(), root.end());
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    Bytes code;
    code.push_back(0xfa); code.push_back(0xbe); code.push_back(0x6d); code.push_back(0x6d);
    code.insert(code.end(), root.begin(), root.end());
    PutLE(code, 1, 4);   // merkle size 2^0
    PutLE(code, 0, 4);   // nonce
    cb.vin[0].scriptSig = CScript(code.begin(), code.end());
    cb.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    Bytes parentHeader;
    PutLE(parentHeader, 1, 4);
    PutHash(parentHeader, uint256(0));
    PutHash(parentHeader, cb.GetHash());
    PutLE(parentHeader, parent.time + 60, 4);
    PutLE(parentHeader, parent.bits, 4);
    PutLE(parentHeader, 0, 4);
    Bytes aux = Serialize(cb);
    PutHash(aux, uint256(0));        // hashBlock (unused)
    PutCompact(aux, 0);              // coinbase branch
    PutLE(aux, 0, 4);                // its index
    PutCompact(aux, 0);              // chain branch
    PutLE(aux, 0, 4);                // its index
    size_t at = aux.size();
    aux.insert(aux.end(), parentHeader.begin(), parentHeader.end());
    Bytes payload;
    for (uint32_t nonce = 0; nonce < 20000; nonce++)
    {
        for (int i = 0; i < 4; i++) aux[at + 76 + i] = (unsigned char)(nonce >> (8 * i));
        payload.clear();
        PutCompact(payload, 1);
        payload.insert(payload.end(), raw.begin(), raw.end());
        payload.insert(payload.end(), aux.begin(), aux.end());
        payload.push_back(0);
        // Accepted by the client's own parser and Headers::Add?
        size_t pos = 1 + raw.size();
        btcswap::AuxPow parsed;
        std::string err;
        if (btcswap::ParseAuxPow(payload, pos, parsed) && headers.Add(raw, err, &parsed))
            return payload;
    }
    fprintf(stderr, "fuzz-light-peer: no merged-mined Dogecoin regtest header found\n");
    return Bytes();
}

static void WriteSeeds(const string& strDir)
{
    for (size_t n = 0; n < kNumNets; n++)
    {
        const btclight::Net* net = NetAt(n);
        if (!net || !net->regtest)
            continue;
        SeedChain chain;
        if (!BuildChain(*net, chain))
            exit(1);
        string tag = net->coin + "-" + net->name;
        Bytes p2shScript;
        {
            CScript contract = swap::BuildContract(TheContract());
            CScript p2sh;
            p2sh.SetPayToScriptHash(contract);
            p2shScript.assign(p2sh.begin(), p2sh.end());
        }

        // The session: headers, then what the scan asks for, then a quiet
        // second round. With a second peer, a handshake, getaddr and the
        // queries afterwards.
        for (int variant = 0; variant < 2; variant++)
        {
            unsigned char flags = variant ? (F_SECOND | F_HANDSHAKE | F_DISCOVER | F_QUERY) : F_QUERY;
            Bytes in, tailAgain;
            in.push_back((unsigned char)n);
            in.push_back(flags);
            in.push_back(1);   // two rounds
            if (flags & F_HANDSHAKE)
            {
                Bytes version;
                PutLE(version, net->protocol, 4);
                PutLE(version, net->services, 8);
                PutLE(version, 1700000000, 8);
                version.resize(72, 0);
                PutLE(version, 0x0123456789abcdefULL, 8);
                PutCompact(version, 4);
                version.insert(version.end(), 4, 'x');
                PutLE(version, 0, 4);
                version.push_back(0);
                AppendRecord(in, CommandIndex("version"), version);
                AppendRecord(in, CommandIndex("verack"), Bytes());
            }
            if (flags & F_DISCOVER)
            {
                Bytes addr;
                PutCompact(addr, 2);
                for (int i = 0; i < 2; i++)
                {
                    PutLE(addr, 1700000000, 4);
                    PutLE(addr, net->services, 8);
                    addr.insert(addr.end(), 10, 0);
                    addr.push_back(255); addr.push_back(255);
                    addr.push_back(93); addr.push_back((unsigned char)(184 + i)); addr.push_back(1); addr.push_back(2);
                    addr.push_back(0x20); addr.push_back(0x8d);
                }
                AppendRecord(in, CommandIndex("addr"), addr);
            }
            Bytes ping(8, 7);
            AppendRecord(in, CommandIndex("ping"), ping);
            AppendRecord(in, CommandIndex("headers"), HeadersPayload(chain.headers));
            if (flags & F_SECOND)
                AppendRecord(in, 0x80 | CommandIndex("headers"), HeadersPayload(chain.headers));
            if (!net->filters)
            {
                for (size_t i = 0; i < chain.blocks.size(); i++)
                    AppendRecord(in, CommandIndex("block"), chain.blocks[i]);
            }
            else
            {
                // Filter headers for heights 0..6, the filters, then the
                // blocks they match.
                btclight::Headers h(*net);
                std::vector<uint256> ids(1, h.Tip().hash);
                ids.insert(ids.end(), chain.hashes.begin(), chain.hashes.end());
                std::vector<Bytes> filters;
                for (size_t i = 0; i < ids.size(); i++)
                {
                    std::vector<Bytes> scripts;
                    if (i == 2 || i == 4)
                        scripts.push_back(p2shScript);
                    scripts.push_back(Bytes(1, OP_TRUE));
                    filters.push_back(btclight::EncodeFilter(ids[i], scripts));
                }
                Bytes cfh;
                cfh.push_back(0);
                PutHash(cfh, ids.back());
                PutHash(cfh, uint256(0));
                PutCompact(cfh, ids.size());
                for (size_t i = 0; i < filters.size(); i++)
                    PutHash(cfh, Digest(filters[i]));
                AppendRecord(in, CommandIndex("cfheaders"), cfh);
                if (flags & F_SECOND)
                {
                    AppendRecord(in, 0x80 | CommandIndex("cfheaders"), cfh);
                    // The second peer's check of the stored tail.
                    Bytes tail;
                    tail.push_back(0);
                    PutHash(tail, ids.back());
                    uint256 prev = 0;
                    for (size_t i = 0; i + 1 < filters.size(); i++)
                    {
                        Bytes j;
                        PutHash(j, Digest(filters[i]));
                        PutHash(j, prev);
                        prev = Digest(j);
                    }
                    PutHash(tail, prev);
                    PutCompact(tail, 1);
                    PutHash(tail, Digest(filters.back()));
                    AppendRecord(in, 0x80 | CommandIndex("cfheaders"), tail);
                    tailAgain = tail;
                }
                for (size_t i = 0; i < filters.size(); i++)
                {
                    Bytes cf;
                    cf.push_back(0);
                    PutHash(cf, ids[i]);
                    PutCompact(cf, filters[i].size());
                    cf.insert(cf.end(), filters[i].begin(), filters[i].end());
                    AppendRecord(in, CommandIndex("cfilter"), cf);
                }
                AppendRecord(in, CommandIndex("block"), chain.blocks[1]);
                AppendRecord(in, CommandIndex("block"), chain.blocks[3]);
            }
            AppendRecord(in, CommandIndex("headers"), HeadersPayload(std::vector<Bytes>()));
            if ((flags & F_SECOND) && !net->filters)
                AppendRecord(in, 0x80 | CommandIndex("headers"), HeadersPayload(std::vector<Bytes>()));
            // The second round asks the second peer for the stored tail again.
            if (!tailAgain.empty())
                AppendRecord(in, 0x80 | CommandIndex("cfheaders"), tailAgain);
            WriteRaw(strDir, "session-" + tag + (variant ? "-two-peers" : ""), in);
        }

        // Merkle mode: each block, and one with its root left wrong.
        for (size_t i = 0; i < chain.blocks.size(); i++)
        {
            Bytes in;
            in.push_back((unsigned char)n);
            in.push_back(F_MERKLE | (i == 0 ? F_FIX_MERKLE : 0));
            in.push_back(0);
            in.insert(in.end(), chain.blocks[i].begin(), chain.blocks[i].end());
            WriteRaw(strDir, "merkle-" + tag + "-" + std::to_string(i + 1), in);
        }
    }
    // Main and test networks, the PoW comparison skipped: headers on the
    // starting point through the retarget and time rules.
    for (size_t n = 0; n < kNumNets; n++)
    {
        const btclight::Net* net = NetAt(n);
        if (!net || net->regtest || net->nodeOnly || net->multiAlgo || net->kawpow)
            continue;
        std::vector<Bytes> chain;
        if (!BuildSkippedChain(*net, chain))
            exit(1);
        Bytes in;
        in.push_back((unsigned char)n);
        in.push_back(F_SKIP_POW);
        in.push_back(0);
        AppendRecord(in, CommandIndex("headers"), HeadersPayload(chain));
        WriteRaw(strDir, "skip-pow-" + net->coin + "-" + net->name, in);
    }
    // A merged-mined Dogecoin header (AuxPoW).
    for (size_t n = 0; n < kNumNets; n++)
    {
        const btclight::Net* net = NetAt(n);
        if (!net || !net->regtest || !net->auxPow)
            continue;
        Bytes payload = MergedHeaderPayload(*net);
        if (payload.empty())
            exit(1);
        Bytes in;
        in.push_back((unsigned char)n);
        in.push_back(0);
        in.push_back(0);
        AppendRecord(in, CommandIndex("headers"), payload);
        WriteRaw(strDir, "auxpow-" + net->coin + "-" + net->name, in);
    }
    // Filter mode.
    {
        Bytes in;
        in.push_back(0);
        in.push_back(F_FILTER);
        in.push_back(0);
        in.insert(in.end(), 32, 0x5a);
        for (int i = 0; i < 5; i++)
        {
            in.push_back(23);
            for (int k = 0; k < 23; k++) in.push_back((unsigned char)(i * 31 + k));
        }
        in.push_back(1);
        in.push_back(OP_RETURN);
        WriteRaw(strDir, "filter-roundtrip", in);
    }
}

static void FuzzLightInit()
{
    SelectChainParams(false);
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3 || size > 400000)
        return 0;
    const btclight::Net* net = NetAt(data[0] % kNumNets);
    unsigned char nFlags = data[1];
    int nRounds = 1 + data[2] % 3;
    data += 3;
    size -= 3;
    if (!net || net->nodeOnly)
        return 0;
    if (nFlags & F_MERKLE)
    {
        MerkleMode(*net, nFlags, data, size);
        return 0;
    }
    if (nFlags & F_FILTER)
    {
        FilterMode(data, size);
        return 0;
    }
    Bytes primary, second;
    for (int n = 0; n < 64 && size >= 3; n++)
    {
        unsigned char kind = data[0];
        size_t nLen = data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (nLen > size)
            nLen = size;
        Bytes payload(data, data + nLen);
        data += nLen;
        size -= nLen;
        Bytes& stream = (kind & 0x80) ? second : primary;
        size_t nCommand = (kind & 0x7f) % kNumCommands;
        if (kCommands[nCommand])
            Frame(stream, net->magic, kCommands[nCommand], payload);
        else
            stream.insert(stream.end(), payload.begin(), payload.end());
    }
    unsigned int flags = 0;
    if (nFlags & F_SECOND) flags |= btclight::FUZZ_SECOND;
    if (nFlags & F_HANDSHAKE) flags |= btclight::FUZZ_HANDSHAKE;
    if (nFlags & F_DISCOVER) flags |= btclight::FUZZ_DISCOVER;
    if (nFlags & F_QUERY) flags |= btclight::FUZZ_QUERY;
    if (nFlags & F_SKIP_POW) flags |= btclight::FUZZ_SKIP_POW;
    btclight::FuzzSession(*net, flags, nRounds, primary, second, swap::BuildContract(TheContract()));
    return 0;
}
