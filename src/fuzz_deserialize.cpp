// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the raw deserializers: every record the node reads from a
// peer or from its own files goes through serialize.h, and this feeds each of
// those types arbitrary bytes the way CDataStream >> does in ProcessMessage,
// the block files and the databases.
//
// Input layout:
//   byte 0   which type, an index into kTypes (modulo its size)
//   rest     the bytes handed to the deserializer
//
// For every input a type accepts, the harness checks:
//   - GetSerializeSize() of the object is the length Serialize() writes;
//   - writing the object and reading it back gives the same bytes again
//     (decode(encode(x)) is stable), whatever the input was;
//   - on the types whose encoding is canonical, the bytes written are exactly
//     the bytes that were read. That holds for everything a peer sends: since
//     ReadCompactSize refuses lengths that are not in their shortest form, one
//     transaction or block has one encoding. The exceptions are documented at
//     their entries below (maps and sets, whose order and duplicates the
//     reader does not police, only appear in wallet and marketplace records).
// Any violation aborts.
//
// Two differentials ride along: a block's identity hash against the hash of
// its first 80 bytes as read, and btcswap::ParseTx (the light client's reader
// for other chains' transactions, which strips the witness and then hands the
// bytes to the same CTransaction deserializer) against CDataStream >> on a
// transaction without a witness.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a canonical encoding of every type,
// plus a few deliberately non-canonical ones, into <dir> and exits.

#include "headers_core.h"
#include "chatdir.h"
#include "chatrelay.h"
#include "p2pool_share.h"
#include "btcswap.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <string>
#include <vector>

static void FuzzDeserializeInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzDeserializeInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

static void Fail(const char* pszType, const char* pszWhat)
{
    fprintf(stderr, "fuzz-deserialize: %s: %s\n", pszType, pszWhat);
    abort();
}

// How the round trip may be compared with the input.
enum
{
    // The bytes written must equal the bytes read.
    RT_CANONICAL = 1,
    // The record starts with a 4-byte version that is read into the stream's
    // version and not kept in the object (CTxIndex, CDiskBlockIndex,
    // CBlockLocator, CAddress on disk, CUser): written back with the stream
    // version set to the one that was read, the bytes must match.
    RT_VERSION_PREFIX = 2,
};

// Per-type extra checks on a decoded object and the bytes it was read from.
template<typename T> static void Extra(const char*, const T&, const unsigned char*, size_t) {}

template<>
void Extra<CTransaction>(const char* pszType, const CTransaction& tx, const unsigned char* p, size_t n)
{
    // The txid is the hash of the transaction's own encoding; with canonical
    // lengths that is the hash of the bytes the peer sent.
    if (tx.GetHash() != Hash(p, p + n))
        Fail(pszType, "txid is not the hash of the bytes read");
    tx.CheckTransaction();
    tx.IsStandard();
    tx.GetSigOpCount();
}

template<>
void Extra<CBlock>(const char* pszType, const CBlock& block, const unsigned char* p, size_t n)
{
    if (n < 80)
        Fail(pszType, "a block decoded from fewer than 80 bytes");
    if (block.GetHash() != Hash(p, p + 80))
        Fail(pszType, "block hash is not the hash of the 80 header bytes read");
    CDataStream hdr(SER_NETWORK | SER_BLOCKHEADERONLY);
    hdr << block;
    if (hdr.size() != 80 || memcmp(&hdr[0], p, 80) != 0)
        Fail(pszType, "header-only serialization differs from the first 80 bytes");
    if (block.vtx.size() <= 2000)
        block.BuildMerkleTree();
}

template<typename T>
static void RoundTrip(const char* pszType, const unsigned char* p, size_t n, int nType, int nVersion, unsigned int fFlags)
{
    T obj;
    size_t nConsumed = 0;
    try
    {
        CDataStream ss((const char*)p, (const char*)p + n, nType, nVersion);
        ss >> obj;
        nConsumed = n - ss.size();
    }
    catch (const std::exception&)
    {
        return;     // refused: what the node does with a bad record
    }

    int nWriteVersion = nVersion;
    if (fFlags & RT_VERSION_PREFIX)
    {
        if (nConsumed < 4)
            Fail(pszType, "a versioned record decoded from fewer than 4 bytes");
        memcpy(&nWriteVersion, p, 4);
    }

    CDataStream out(nType, nWriteVersion);
    out << obj;
    if (::GetSerializeSize(obj, nType, nWriteVersion) != out.size())
        Fail(pszType, "GetSerializeSize differs from the serialized length");

    if (fFlags & RT_CANONICAL)
    {
        if (out.size() != nConsumed)
            Fail(pszType, "canonical type: re-encoding has a different length than what was read");
        if (nConsumed && memcmp(&out[0], p, nConsumed) != 0)
            Fail(pszType, "canonical type: re-encoding differs from what was read");
    }

    // Whatever was read, what we write must read back to itself.
    vector<unsigned char> vOut(out.begin(), out.end());
    T obj2;
    try
    {
        CDataStream ss2(vOut, nType, nWriteVersion);
        ss2 >> obj2;
        if (!ss2.empty())
            Fail(pszType, "re-reading our own encoding left bytes over");
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "fuzz-deserialize: %s: %s\n", pszType, e.what());
        Fail(pszType, "our own encoding does not read back");
    }
    CDataStream out2(nType, nWriteVersion);
    out2 << obj2;
    if (out2.size() != vOut.size() || (vOut.size() && memcmp(&out2[0], &vOut[0], vOut.size()) != 0))
        Fail(pszType, "encode(decode(encode(x))) differs from encode(x)");

    Extra<T>(pszType, obj, p, nConsumed);
}

// The length prefix on its own.
static void CompactSize(const unsigned char* p, size_t n)
{
    uint64 nSize = 0;
    size_t nConsumed = 0;
    try
    {
        CDataStream ss((const char*)p, (const char*)p + n, SER_NETWORK);
        nSize = ReadCompactSize(ss);
        nConsumed = n - ss.size();
    }
    catch (const std::exception&)
    {
        return;
    }
    if (nSize > MAX_SIZE)
        Fail("CompactSize", "a length above MAX_SIZE was returned");
    CDataStream out(SER_NETWORK);
    WriteCompactSize(out, nSize);
    if (out.size() != GetSizeOfCompactSize(nSize))
        Fail("CompactSize", "GetSizeOfCompactSize differs from the length written");
    if (out.size() != nConsumed || memcmp(&out[0], p, nConsumed) != 0)
        Fail("CompactSize", "a length was accepted in other than its shortest form");
}

// btcswap::ParseTx against the node's own reader, on transactions without a
// witness (for those the two must agree byte for byte).
static void ParseTxDifferential(const unsigned char* p, size_t n)
{
    vector<unsigned char> raw(p, p + n);
    CTransaction txLight;
    bool fLight = btcswap::ParseTx(raw, txLight);

    CTransaction txNode;
    bool fNode = false;
    try
    {
        CDataStream ss(raw, SER_NETWORK);
        ss >> txNode;
        fNode = ss.empty();
    }
    catch (const std::exception&)
    {
        fNode = false;
    }

    bool fWitnessMarker = n >= 6 && p[4] == 0x00 && p[5] == 0x01;
    if (fLight && !fWitnessMarker)
    {
        if (!fNode)
            Fail("ParseTx", "light client read a transaction the node's reader refuses");
        if (txLight.GetHash() != txNode.GetHash())
            Fail("ParseTx", "light client and node read different transactions");
    }
    // The light client wants at least one input; the node's reader does not.
    if (fNode && !fWitnessMarker && !txNode.vin.empty() && !fLight)
        Fail("ParseTx", "the node's reader took a transaction the light client refuses");
    if (fLight)
    {
        // With a witness, the txid covers the stripped bytes only; the
        // transaction read must still re-encode to something the node reads.
        CDataStream out(SER_NETWORK);
        out << txLight;
        CTransaction tx2;
        CDataStream in(out);
        in >> tx2;
        if (tx2.GetHash() != txLight.GetHash())
            Fail("ParseTx", "re-encoded transaction does not read back");
    }
}

static void ParseBlockTxs(const unsigned char* p, size_t n, bool fAuxPow, size_t nHeader)
{
    vector<unsigned char> raw(p, p + n);
    vector<CTransaction> vtx;
    btcswap::ParseBlockTxs(raw, vtx, fAuxPow, nHeader);
}

typedef void (*FuzzFn)(const unsigned char*, size_t);

#define RT(T, nType, flags) [](const unsigned char* p, size_t n) { RoundTrip<T>(#T, p, n, (nType), VERSION, (flags)); }

typedef map<string, string> StringMap;
typedef vector<pair<string, string> > StringPairs;
typedef vector<unsigned char> Bytes;

struct TypeEntry
{
    const char* pszName;
    FuzzFn fn;
};

// Wire types first: what ProcessMessage reads from a peer.
static const TypeEntry kTypes[] = {
    { "CTransaction",          RT(CTransaction, SER_NETWORK, RT_CANONICAL) },
    { "CBlock",                RT(CBlock, SER_NETWORK, RT_CANONICAL) },
    { "CBlock/disk",           RT(CBlock, SER_DISK, RT_CANONICAL) },
    { "CBlock/header",         RT(CBlock, SER_NETWORK | SER_BLOCKHEADERONLY, RT_CANONICAL) },
    { "CBlockLocator",         RT(CBlockLocator, SER_NETWORK, RT_CANONICAL | RT_VERSION_PREFIX) },
    { "CInv",                  RT(CInv, SER_NETWORK, RT_CANONICAL) },
    { "vector<CInv>",          RT(vector<CInv>, SER_NETWORK, RT_CANONICAL) },
    { "CAddress",              RT(CAddress, SER_NETWORK, RT_CANONICAL) },
    { "vector<CAddress>",      RT(vector<CAddress>, SER_NETWORK, RT_CANONICAL) },
    { "CMessageHeader/102",    [](const unsigned char* p, size_t n) { RoundTrip<CMessageHeader>("CMessageHeader/102", p, n, SER_NETWORK, PROTO_CHECKSUM_VERSION, RT_CANONICAL); } },
    { "CMessageHeader/101",    [](const unsigned char* p, size_t n) { RoundTrip<CMessageHeader>("CMessageHeader/101", p, n, SER_NETWORK, PROTO_NO_CHECKSUM_VERSION, RT_CANONICAL); } },
    { "COutPoint",             RT(COutPoint, SER_NETWORK, RT_CANONICAL) },
    { "CTxIn",                 RT(CTxIn, SER_NETWORK, RT_CANONICAL) },
    { "CTxOut",                RT(CTxOut, SER_NETWORK, RT_CANONICAL) },
    { "CScript",               RT(CScript, SER_NETWORK, RT_CANONICAL) },
    { "string",                RT(string, SER_NETWORK, RT_CANONICAL) },
    { "vector<uchar>",         RT(Bytes, SER_NETWORK, RT_CANONICAL) },
    { "uint256",               RT(uint256, SER_NETWORK, RT_CANONICAL) },
    { "p2pool::ShareData",     RT(p2pool::ShareData, SER_NETWORK, RT_CANONICAL) },
    { "p2pool::Share",         RT(p2pool::Share, SER_NETWORK, RT_CANONICAL) },
    { "CChatListing",          RT(CChatListing, SER_NETWORK, RT_CANONICAL) },
    { "CChatQuery",            RT(CChatQuery, SER_NETWORK, RT_CANONICAL) },
    // Marketplace records carry maps: the reader takes keys in any order and
    // keeps the first of a duplicate, so they are not canonical.
    { "CReview",               RT(CReview, SER_NETWORK, 0) },
    { "CProduct",              RT(CProduct, SER_NETWORK, 0) },

    // Disk: block files, blkindex.dat, wallet.dat, addr.dat, the market files.
    { "CDiskBlockIndex",       RT(CDiskBlockIndex, SER_DISK, RT_CANONICAL | RT_VERSION_PREFIX) },
    { "CTxIndex",              RT(CTxIndex, SER_DISK, RT_CANONICAL | RT_VERSION_PREFIX) },
    { "CDiskTxPos",            RT(CDiskTxPos, SER_DISK, RT_CANONICAL) },
    { "CAddress/disk",         RT(CAddress, SER_DISK, RT_CANONICAL | RT_VERSION_PREFIX) },
    { "CMerkleTx",             RT(CMerkleTx, SER_DISK, RT_CANONICAL) },
    { "CWalletTx",             RT(CWalletTx, SER_DISK, 0) },           // mapValue
    { "CWalletMasterKey",      RT(CWalletMasterKey, SER_DISK, RT_CANONICAL) },
    { "CUser",                 RT(CUser, SER_DISK, RT_CANONICAL | RT_VERSION_PREFIX) },
    { "CProduct/disk",         RT(CProduct, SER_DISK, 0) },
    { "map<string,string>",    RT(StringMap, SER_DISK, 0) },
    { "vector<pair<str,str>>", RT(StringPairs, SER_DISK, RT_CANONICAL) },

    // The pieces and the other readers.
    { "CompactSize",           CompactSize },
    { "btcswap::ParseTx",      ParseTxDifferential },
    { "btcswap::ParseBlockTxs", [](const unsigned char* p, size_t n) { ParseBlockTxs(p, n, false, 80); } },
    { "btcswap::ParseBlockTxs/auxpow", [](const unsigned char* p, size_t n) { ParseBlockTxs(p, n, true, 80); } },
    { "btcswap::ParseBlockTxs/kawpow", [](const unsigned char* p, size_t n) { ParseBlockTxs(p, n, false, 120); } },
};
static const size_t kNumTypes = sizeof(kTypes) / sizeof(kTypes[0]);

static size_t TypeIndex(const char* psz)
{
    for (size_t i = 0; i < kNumTypes; i++)
        if (strcmp(kTypes[i].pszName, psz) == 0)
            return i;
    fprintf(stderr, "fuzz-deserialize: no type %s\n", psz);
    abort();
}

// ---- seeds -------------------------------------------------------------------

static void WriteSeedBytes(const string& strDir, const string& strName, const char* pszType,
                           const char* pch, size_t n)
{
    string strPath = strDir + "/" + strName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    unsigned char sel = (unsigned char)TypeIndex(pszType);
    fwrite(&sel, 1, 1, f);
    if (n)
        fwrite(pch, 1, n, f);
    fclose(f);
}

template<typename T>
static void WriteSeed(const string& strDir, const char* pszType, const T& obj, int nType, int nVersion = VERSION)
{
    CDataStream ss(nType, nVersion);
    ss << obj;
    string strName = pszType;
    for (size_t i = 0; i < strName.size(); i++)
        if (!isalnum((unsigned char)strName[i]))
            strName[i] = '_';
    WriteSeedBytes(strDir, strName, pszType, ss.size() ? &ss[0] : "", ss.size());
}

static CTransaction SampleTx(int nInputs)
{
    CTransaction tx;
    for (int i = 0; i < nInputs; i++)
    {
        uint256 hashPrev = Hash(BEGIN(i), END(i));
        CScript sig;
        sig << vector<unsigned char>(71, 0x30) << vector<unsigned char>(33, 0x02);
        tx.vin.push_back(CTxIn(hashPrev, i, sig, i == 0 ? UINT_MAX : 7));
    }
    CScript pk;
    pk << OP_DUP << OP_HASH160 << uint160(7) << OP_EQUALVERIFY << OP_CHECKSIG;
    tx.vout.push_back(CTxOut(50 * COIN, pk));
    tx.vout.push_back(CTxOut(1234, CScript() << OP_HASH160 << uint160(9) << OP_EQUAL));
    return tx;
}

static void WriteSeeds(const string& strDir)
{
    CTransaction tx = SampleTx(2);
    WriteSeed(strDir, "CTransaction", tx, SER_NETWORK);
    WriteSeed(strDir, "btcswap::ParseTx", tx, SER_NETWORK);
    WriteSeed(strDir, "COutPoint", tx.vin[0].prevout, SER_NETWORK);
    WriteSeed(strDir, "CTxIn", tx.vin[1], SER_NETWORK);
    WriteSeed(strDir, "CTxOut", tx.vout[0], SER_NETWORK);
    WriteSeed(strDir, "CScript", tx.vout[0].scriptPubKey, SER_NETWORK);

    CBlock block;
    block.nVersion = 2;
    block.hashPrevBlock = Hash(BEGIN(block.nVersion), END(block.nVersion));
    block.nTime = 1790000000;
    block.nBits = 0x1e0fffff;
    block.nNonce = 42;
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << block.nBits << CBigNum(1);
    coinbase.vout.push_back(CTxOut(50 * COIN, tx.vout[0].scriptPubKey));
    block.vtx.push_back(coinbase);
    block.vtx.push_back(tx);
    block.hashMerkleRoot = block.BuildMerkleTree();
    WriteSeed(strDir, "CBlock", block, SER_NETWORK);
    WriteSeed(strDir, "CBlock/disk", block, SER_DISK);
    WriteSeed(strDir, "CBlock/header", block, SER_NETWORK | SER_BLOCKHEADERONLY);
    WriteSeed(strDir, "btcswap::ParseBlockTxs", block, SER_NETWORK);

    vector<uint256> vHave;
    for (int i = 0; i < 12; i++)
        vHave.push_back(Hash(BEGIN(i), END(i)));
    CDataStream ssLoc(SER_NETWORK);
    ssLoc << VERSION << vHave;
    WriteSeedBytes(strDir, "CBlockLocator", "CBlockLocator", &ssLoc[0], ssLoc.size());

    CInv inv(MSG_TX, tx.GetHash());
    WriteSeed(strDir, "CInv", inv, SER_NETWORK);
    vector<CInv> vInv;
    vInv.push_back(inv);
    vInv.push_back(CInv(MSG_BLOCK, block.GetHash()));
    WriteSeed(strDir, "vector<CInv>", vInv, SER_NETWORK);

    CAddress addr("10.0.0.1:8333", NODE_NETWORK);
    WriteSeed(strDir, "CAddress", addr, SER_NETWORK);
    WriteSeed(strDir, "CAddress/disk", addr, SER_DISK);
    vector<CAddress> vAddr(3, addr);
    WriteSeed(strDir, "vector<CAddress>", vAddr, SER_NETWORK);

    CMessageHeader hdr("block", 285);
    hdr.nChecksum = 0x01020304;
    WriteSeed(strDir, "CMessageHeader/102", hdr, SER_NETWORK, PROTO_CHECKSUM_VERSION);
    WriteSeed(strDir, "CMessageHeader/101", hdr, SER_NETWORK, PROTO_NO_CHECKSUM_VERSION);

    WriteSeed(strDir, "string", string("bitflash"), SER_NETWORK);
    WriteSeed(strDir, "vector<uchar>", vector<unsigned char>(300, 0xab), SER_NETWORK);
    WriteSeed(strDir, "uint256", block.GetHash(), SER_NETWORK);

    p2pool::ShareData sd;
    sd.hashPrevShare = block.GetHash();
    sd.vUncles.push_back(tx.GetHash());
    sd.nShareHeight = 10;
    sd.nShareBits = 0x1f00ffff;
    sd.payoutScript.assign(tx.vout[0].scriptPubKey.begin(), tx.vout[0].scriptPubKey.end());
    WriteSeed(strDir, "p2pool::ShareData", sd, SER_NETWORK);
    p2pool::Share share;
    share.nVersion = block.nVersion;
    share.hashPrevBlock = block.hashPrevBlock;
    share.hashMerkleRoot = block.hashMerkleRoot;
    share.nTime = block.nTime;
    share.nBits = block.nBits;
    share.coinbase = coinbase;
    share.vMerkleBranch.push_back(tx.GetHash());
    share.data = sd;
    WriteSeed(strDir, "p2pool::Share", share, SER_NETWORK);

    CChatListing listing;
    listing.key.assign(32, 0x11);
    listing.name = "alice";
    listing.nHeight = 1000;
    listing.nTime = 1790000000;
    listing.nBurn = COIN;
    listing.txid = tx.GetHash();
    WriteSeed(strDir, "CChatListing", listing, SER_NETWORK);
    CChatQuery query;
    query.kind = 1;
    query.key.assign(32, 0x22);
    query.nSince = 5;
    query.nMax = 50;
    WriteSeed(strDir, "CChatQuery", query, SER_NETWORK);

    CReview review;
    review.hashTo = tx.GetHash();
    review.mapValue["message"] = "fine";
    review.mapValue["stars"] = "5";
    review.vchPubKeyFrom.assign(65, 0x04);
    review.vchSig.assign(71, 0x30);
    WriteSeed(strDir, "CReview", review, SER_NETWORK);
    CProduct product;
    product.addr = addr;
    product.mapValue["title"] = "x";
    product.mapDetails["d"] = "y";
    product.vOrderForm.push_back(make_pair(string("a"), string("b")));
    product.vchPubKeyFrom.assign(65, 0x04);
    WriteSeed(strDir, "CProduct", product, SER_NETWORK);
    WriteSeed(strDir, "CProduct/disk", product, SER_DISK);

    CBlockIndex index;
    index.nFile = 1;
    index.nBlockPos = 1234;
    index.nHeight = 77;
    index.nVersion = block.nVersion;
    index.hashMerkleRoot = block.hashMerkleRoot;
    index.nTime = block.nTime;
    index.nBits = block.nBits;
    index.nNonce = block.nNonce;
    CDiskBlockIndex diskindex(&index);
    diskindex.hashPrev = block.hashPrevBlock;
    WriteSeed(strDir, "CDiskBlockIndex", diskindex, SER_DISK);

    CTxIndex txindex(CDiskTxPos(1, 1234, 1400), 2);
    txindex.vSpent[1] = CDiskTxPos(1, 9000, 9100);
    WriteSeed(strDir, "CTxIndex", txindex, SER_DISK);
    WriteSeed(strDir, "CDiskTxPos", txindex.pos, SER_DISK);

    CMerkleTx mtx(tx);
    mtx.hashBlock = block.GetHash();
    mtx.vMerkleBranch.push_back(coinbase.GetHash());
    mtx.nIndex = 1;
    WriteSeed(strDir, "CMerkleTx", mtx, SER_DISK);
    CWalletTx wtx(mtx);
    wtx.vtxPrev.push_back(CMerkleTx(coinbase));
    wtx.mapValue["to"] = "B";
    wtx.mapValue["comment"] = "c";
    wtx.vOrderForm.push_back(make_pair(string("k"), string("v")));
    wtx.nTimeReceived = 1790000000;
    wtx.fFromMe = 1;
    WriteSeed(strDir, "CWalletTx", wtx, SER_DISK);
    WriteSeed(strDir, "map<string,string>", wtx.mapValue, SER_DISK);
    WriteSeed(strDir, "vector<pair<str,str>>", wtx.vOrderForm, SER_DISK);

    CWalletMasterKey mkey;
    mkey.vchCryptedKey.assign(48, 0x5a);
    mkey.nDerivationMethod = 1;
    WriteSeed(strDir, "CWalletMasterKey", mkey, SER_DISK);

    CUser user;
    user.vAtomsIn.push_back(3);
    user.vLinksOut.push_back(tx.GetHash());
    WriteSeed(strDir, "CUser", user, SER_DISK);

    // Lengths in every width, and the non-canonical spellings the reader
    // refuses: 5 written in three bytes, in five, and in nine with the high
    // half set (which a 32-bit truncation would read as 5).
    const char kCompact[][10] = {
        { 1, 5 }, { 3, (char)0xfd, (char)0xfd, 0 }, { 5, (char)0xfe, 0, 0, 1, 0 },
        { 3, (char)0xfd, 5, 0 }, { 5, (char)0xfe, 5, 0, 0, 0 },
        { 9, (char)0xff, 5, 0, 0, 0, 1, 0, 0, 0 },
    };
    for (size_t i = 0; i < sizeof(kCompact) / sizeof(kCompact[0]); i++)
        WriteSeedBytes(strDir, strprintf("CompactSize-%d", (int)i), "CompactSize", &kCompact[i][1], (size_t)kCompact[i][0]);

    // The sample transaction with its input count written as 0xfd 02 00.
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    string strTx(ssTx.begin(), ssTx.end());
    string strNonCanon = strTx.substr(0, 4) + string("\xfd\x02\x00", 3) + strTx.substr(5);
    WriteSeedBytes(strDir, "CTransaction-noncanonical-count", "CTransaction", strNonCanon.data(), strNonCanon.size());

    // A witness transaction for the light client's reader: marker, flag, and
    // one witness item per input.
    string strWit = strTx.substr(0, 4) + string("\x00\x01", 2) + strTx.substr(4, strTx.size() - 8);
    for (size_t i = 0; i < tx.vin.size(); i++)
        strWit += string("\x01\x02\xaa\xbb", 4);
    strWit += strTx.substr(strTx.size() - 4);
    WriteSeedBytes(strDir, "btcswap-ParseTx-witness", "btcswap::ParseTx", strWit.data(), strWit.size());
}

static void FuzzDeserializeInit()
{
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        fprintf(stderr, "fuzz-deserialize: seeds written to %s\n", pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > (1 << 20))
        return 0;
    const TypeEntry& e = kTypes[data[0] % kNumTypes];
    e.fn(data + 1, size - 1);
    return 0;
}
