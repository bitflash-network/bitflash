// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for what peers send after the handshake. fuzz-net-message
// feeds the raw receive buffer, but every message there carries a double
// SHA-256 checksum of its payload that no fuzzer can forge, so almost every
// input stops at the envelope and the handlers for block, tx and inv are never
// reached. This harness starts past that point: the peer has already sent its
// version, and the input is one command and its payload, handed to
// ProcessMessage() the way ProcessMessages() hands them over.
//
// Input layout:
//   byte 0   command, an index into kCommands (the last entry reads the
//            command name from the next 12 bytes instead)
//   byte 1   flags: bit 0 = for "block", recompute the merkle root before the
//            block is handled, so inputs get past that check too;
//            bit 1 = the rest is a sequence of messages from the same peer,
//            each [command][flags][length, 2 bytes little-endian][payload],
//            up to 16 of them (a branch, then the block that makes it the
//            best chain, is how reorganisation is reached)
//   rest     the payload
//
// The node keeps its state between inputs, in a private temporary data
// directory with the genesis block loaded: orphans, blocks that were accepted
// and the chain they make. In this binary only, the RandomX proof-of-work
// comparison in CheckBlock is skipped (fFuzzSkipPoW, compiled only with
// -DBITFLASH_FUZZ), so the contextual checks and block connection behind it
// are fuzzed as well. Every other check runs as in a release build.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a structured starting corpus (a
// block on top of genesis, a transaction, inv, getdata, getblocks, ...) into
// <dir> and exits.

#include "headers_core.h"
#include "p2pool_net.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <string>
#include <vector>

static void FuzzP2PInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzP2PInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

extern bool fFuzzSkipPoW;

static const char* const kCommands[] = {
    "block", "tx", "inv", "getdata", "getblocks", "reply", "ping", "btfpeers",
    "review", "version", "checkorder", "submitorder",
    "chatrec", "chatput", "chatget", "getchatinv", "getchatdir",
    "p2pshare", "p2ppeers", "p2pgetsh", "p2psync", "p2pshares",
    NULL, // command name taken from the input
};
static const size_t kNumCommands = sizeof(kCommands) / sizeof(kCommands[0]);
static const unsigned char FLAG_FIX_MERKLE = 1;
static const unsigned char FLAG_SEQUENCE = 2;

static size_t CommandIndex(const char* psz)
{
    for (size_t i = 0; i + 1 < kNumCommands; i++)
        if (strcmp(kCommands[i], psz) == 0)
            return i;
    abort();
}

static void WriteSeed(const string& strDir, const char* pszName, const char* pszCommand,
                      unsigned char nFlags, const CDataStream& ss)
{
    string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    unsigned char hdr[2] = { (unsigned char)CommandIndex(pszCommand), nFlags };
    fwrite(hdr, 1, 2, f);
    if (ss.size())
        fwrite(&ss[0], 1, ss.size(), f);
    fclose(f);
}

// One record of a sequence input (see the layout at the top).
static void AppendRecord(string& str, const char* pszCommand, unsigned char nFlags, const CDataStream& ss)
{
    str += (char)CommandIndex(pszCommand);
    str += (char)nFlags;
    str += (char)(ss.size() & 0xff);
    str += (char)((ss.size() >> 8) & 0xff);
    if (ss.size())
        str.append(&ss[0], ss.size());
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

static void WriteSeeds(const string& strDir)
{
    CBlock genesis;
    if (!pindexGenesisBlock || !genesis.ReadFromDisk(pindexGenesisBlock, true))
    {
        fprintf(stderr, "fuzz-p2p-payload: cannot read the genesis block\n");
        exit(1);
    }

    // A block on top of genesis that passes every check but the merkle root,
    // which the harness fixes when flag bit 0 is set.
    CBlock block;
    block.nVersion = genesis.nVersion;
    block.hashPrevBlock = pindexGenesisBlock->GetBlockHash();
    block.nTime = max((unsigned int)GetAdjustedTime(), pindexGenesisBlock->nTime + 1);
    block.nBits = GetNextWorkRequired(pindexGenesisBlock);
    block.nNonce = 0;
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << block.nBits << CBigNum(1);
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = block.GetBlockValue(1, 0);
    coinbase.vout[0].scriptPubKey = genesis.vtx[0].vout[0].scriptPubKey;
    block.vtx.push_back(coinbase);
    block.hashMerkleRoot = block.BuildMerkleTree();
    {
        CDataStream ss(SER_NETWORK);
        ss << block;
        WriteSeed(strDir, "block-on-genesis", "block", FLAG_FIX_MERKLE, ss);
    }
    {
        CDataStream ss(SER_NETWORK);
        ss << genesis;
        WriteSeed(strDir, "block-genesis", "block", 0, ss);
    }

    // A reorganisation in one input: block A at height 1, a competing B at
    // height 1, then C on B. B and C carry more work than A, so the node
    // disconnects A and connects B and C.
    {
        CBlock blockB = block;
        blockB.vtx[0].vin[0].scriptSig = CScript() << 1 << block.nBits << CBigNum(2);
        blockB.hashMerkleRoot = blockB.BuildMerkleTree();
        CBlock blockC = block;
        blockC.hashPrevBlock = blockB.GetHash();
        blockC.nTime = blockB.nTime + 1;
        blockC.vtx[0].vin[0].scriptSig = CScript() << 2 << block.nBits << CBigNum(1);
        blockC.vtx[0].vout[0].nValue = blockC.GetBlockValue(2, 0);
        blockC.hashMerkleRoot = blockC.BuildMerkleTree();
        string str;
        str += (char)CommandIndex("block");
        str += (char)FLAG_SEQUENCE;
        CDataStream ssA(SER_NETWORK), ssB(SER_NETWORK), ssC(SER_NETWORK);
        ssA << block;
        ssB << blockB;
        ssC << blockC;
        AppendRecord(str, "block", 0, ssA);
        AppendRecord(str, "block", 0, ssB);
        AppendRecord(str, "block", 0, ssC);
        WriteRaw(strDir, "sequence-reorg", str);
    }

    // A transaction spending the coinbase above: missing input, so it goes
    // through the orphan path, and once the block is in, through the
    // maturity and script checks.
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(coinbase.GetHash(), 0);
    tx.vin[0].scriptSig = CScript() << vector<unsigned char>(72, 0x30);
    tx.vout.resize(1);
    tx.vout[0].nValue = COIN;
    tx.vout[0].scriptPubKey = genesis.vtx[0].vout[0].scriptPubKey;
    {
        CDataStream ss(SER_NETWORK);
        ss << tx;
        WriteSeed(strDir, "tx-spend", "tx", 0, ss);
    }

    vector<CInv> vInv;
    vInv.push_back(CInv(MSG_BLOCK, pindexGenesisBlock->GetBlockHash()));
    vInv.push_back(CInv(MSG_BLOCK, block.GetHash()));
    vInv.push_back(CInv(MSG_TX, tx.GetHash()));
    {
        CDataStream ss(SER_NETWORK);
        ss << vInv;
        WriteSeed(strDir, "inv", "inv", 0, ss);
        WriteSeed(strDir, "getdata", "getdata", 0, ss);
    }
    {
        CDataStream ss(SER_NETWORK);
        ss << CBlockLocator(pindexBest) << uint256(0);
        WriteSeed(strDir, "getblocks", "getblocks", 0, ss);
    }
    {
        CDataStream ss(SER_NETWORK);
        ss << uint256(1);
        WriteSeed(strDir, "reply", "reply", 0, ss);
    }
    {
        CDataStream ss(SER_NETWORK);
        ss << vector<string>(1, string("x"));
        WriteSeed(strDir, "btfpeers", "btfpeers", 0, ss);
    }
    {
        CDataStream ss(SER_NETWORK);
        WriteSeed(strDir, "ping", "ping", 0, ss);
        WriteSeed(strDir, "p2psync", "p2psync", 0, ss);
        WriteSeed(strDir, "getchatinv", "getchatinv", 0, ss);
    }
}

// The Berkeley DB environment stays open for the whole run, as in a node. Its
// internal allocations are referenced from memory the library maps for
// itself, which LeakSanitizer does not scan, so they read as leaks at exit.
// Closing the environment from an exit handler is no way out: by then some of
// the globals it logs through are already destroyed. Only allocations made
// inside libdb are suppressed; a Berkeley DB handle the node itself leaks is
// allocated from node code and is still reported (that is how the CDB open
// leak was found).
extern "C" const char* __lsan_default_suppressions()
{
    return "leak:__os_malloc\n";
}

// The chain this harness builds lives for the whole run (block index entries,
// orphan blocks and transactions), held in global maps. At exit those maps
// are destroyed before the final leak check and their pointers are lost, as
// in the node, which never frees them either. So no leak check at exit;
// libFuzzer still checks after every input that changed the heap, which is
// where a leak an input causes shows up.
extern "C" const char* __asan_default_options()
{
    return "leak_check_at_exit=0";
}

static void FuzzP2PInit()
{
    SelectChainParams(false);
    if (!LoadBlockIndex())
    {
        fprintf(stderr, "fuzz-p2p-payload: LoadBlockIndex failed\n");
        abort();
    }
    fFuzzSkipPoW = true;

    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

// One message from the peer: its command (index into kCommands), flags and
// payload, handled as ProcessMessages() hands messages over.
static void HandleOne(CNode& node, size_t nIndex, unsigned char nFlags, const uint8_t* data, size_t size)
{
    string strCommand;
    if (kCommands[nIndex])
        strCommand = kCommands[nIndex];
    else
    {
        if (size < 12)
            return;
        strCommand.assign((const char*)data, strnlen((const char*)data, 12));
        data += 12;
        size -= 12;
    }

    CDataStream vMsg((const char*)data, (const char*)data + size, SER_NETWORK, VERSION);

    if (strCommand == "block" && (nFlags & FLAG_FIX_MERKLE))
    {
        try
        {
            CDataStream vCopy(vMsg);
            CBlock block;
            vCopy >> block;
            block.hashMerkleRoot = block.BuildMerkleTree();
            CDataStream vFixed(SER_NETWORK, VERSION);
            vFixed << block;
            if (!vCopy.empty())
                vFixed.write(&vCopy[0], vCopy.size()); // trailing bytes stay
            vMsg = vFixed;
        }
        catch (std::exception&)
        {
            // Not a block: hand the bytes over as they are.
        }
    }

    // As in ProcessMessages(): share-chain messages outside cs_main, the rest
    // under it, and a deserialisation failure is an exception that ends the
    // message, not the node.
    try
    {
        bool fDone = false;
        if (strCommand.compare(0, 3, "p2p") == 0)
        {
            CDataStream vCopy(vMsg);
            fDone = P2PoolProcessMessage(&node, strCommand, vCopy);
        }
        if (!fDone)
            CRITICAL_BLOCK(cs_main)
                ProcessMessage(&node, strCommand, vMsg);
    }
    catch (...)
    {
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Large enough for blocks with many transactions, small enough that the
    // size checks, not the allocator, are what a huge input meets.
    if (size < 2 || size > 200000)
        return 0;

    CNode node(INVALID_SOCKET, CAddress("127.0.0.1"));
    node.nVersion = VERSION;
    node.vSend.SetVersion(VERSION);
    node.vRecv.SetVersion(VERSION);

    size_t nIndex = data[0] % kNumCommands;
    unsigned char nFlags = data[1];
    if (!(nFlags & FLAG_SEQUENCE))
    {
        HandleOne(node, nIndex, nFlags, data + 2, size - 2);
        return 0;
    }
    data += 2;
    size -= 2;
    for (int n = 0; n < 16 && size >= 4; n++)
    {
        size_t nRec = data[0] % kNumCommands;
        unsigned char nRecFlags = data[1] & ~FLAG_SEQUENCE;
        size_t nLen = data[2] | ((size_t)data[3] << 8);
        data += 4;
        size -= 4;
        if (nLen > size)
            nLen = size;
        HandleOne(node, nRec, nRecFlags, data, nLen);
        data += nLen;
        size -= nLen;
    }
    return 0;
}
