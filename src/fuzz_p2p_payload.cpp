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
//            block is handled, so inputs get past that check too
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Large enough for blocks with many transactions, small enough that the
    // size checks, not the allocator, are what a huge input meets.
    if (size < 2 || size > 200000)
        return 0;

    size_t nIndex = data[0] % kNumCommands;
    unsigned char nFlags = data[1];
    data += 2;
    size -= 2;

    string strCommand;
    if (kCommands[nIndex])
        strCommand = kCommands[nIndex];
    else
    {
        if (size < 12)
            return 0;
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

    CNode node(INVALID_SOCKET, CAddress("127.0.0.1"));
    node.nVersion = VERSION;
    node.vSend.SetVersion(VERSION);
    node.vRecv.SetVersion(VERSION);

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
    return 0;
}
