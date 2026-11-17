// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the pool registry index (poolindex.h, docs/pool-registry.md
// sections 3, 4 and 7): what a block's coinbase says about pools, what the
// node reads back from pool-registry.dat, and the fold itself under reorgs.
//
// Input layout: byte 0 picks a mode (bits 0 and 1) and its flags; the rest is
// the mode's own.
//
//   mode 0  ClassifyPoolAnchor: the rest is a coinbase's scriptSig, as any
//           miner may write it. Checked: a transaction that is not a
//           coinbase names no pool; a pool zero or registered anchor's
//           hashes (and id) are bytes of the script, in one piece; adding a
//           second push of the same kind takes the anchor away, a "p2l" push
//           takes a registered anchor away and leaves pool zero's, and a push
//           that is no tag (a 34-byte "p2p...") changes nothing.
//
//   mode 1  CPoolIndex::Load: the rest is the file. Flag bit 2 puts the
//           file's version (2) in front, bit 3 appends the checksum the file
//           ends with, so the bytes behind both reach the reader and the
//           consistency check. A file that loads must hold together
//           (CheckConsistent), answer every query, write itself back
//           (Save) to a file that loads to the same registry (Digest), and
//           take one more block and lose it again: when DisconnectAbove says
//           the answer is exact, it is the one from before the block.
//
//   mode 2, 3  the fold: the rest is a list of operations on a registry and
//           the branch of blocks it read: a block made of fuzzed pushes,
//           records (valid ones from a table, flipped ones, raw bytes) and
//           burns; a run of up to 2048 blocks with one anchor each (to reach
//           the 144-block sweeps, the 720-block window and the 1440 margin);
//           a disconnect to any height on the branch (and, where
//           DisconnectAbove says the answer is no longer exact, a read from
//           genesis, as the node does); and a check. After every operation
//           the registry holds together; at each check and at the end it
//           is, by Digest, the registry read straight from genesis along
//           the branch that remains, and it serializes and reads back to
//           itself.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus (anchors of every
// kind, a registry file made by the fold, and folds with a reorg on either
// side of 30 confirmations and across the sweeps) into <dir> and exits.

#include "headers_core.h"
#include "poolindex.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <memory>
#include <string>
#include <vector>

static void FuzzPoolIndexInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzPoolIndexInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

static const unsigned char F_LOAD_VERSION = 4;
static const unsigned char F_LOAD_CHECKSUM = 8;

enum
{
    OP_FOLD_BLOCK = 0, OP_FOLD_RUN, OP_FOLD_DISCONNECT, OP_FOLD_CHECK
};
// A branch longer than this takes no more blocks (each check reads it all
// again from genesis).
static const int FOLD_MAX_HEIGHT = 6000;
static const int FOLD_MAX_OPS = 64;
static const int FOLD_MAX_CHECKS = 4;
// Reads from genesis after a disconnect that is not exact: after this many,
// the input ends there (each is up to 6000 blocks).
static const int FOLD_MAX_REREADS = 6;

// Records: [0] pool zero's own, [1..4] valid ones of other pools. Ids: pool
// zero, the four, and one nobody can burn.
static const int N_RECORDS = 5;
static const int N_IDS = 6;
static vector<unsigned char> g_record[N_RECORDS];
static uint256 g_id[N_IDS];
static uint64 g_nNextHash = 0;

static void Fail(const char* pszWhat)
{
    fprintf(stderr, "fuzz-poolindex: %s\n", pszWhat);
    abort();
}

struct Reader
{
    const uint8_t* p;
    size_t n;

    Reader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    bool Empty() const { return n == 0; }
    unsigned char Byte()
    {
        if (!n)
            return 0;
        n--;
        return *p++;
    }
    unsigned int U16()
    {
        unsigned int a = Byte();
        return a | ((unsigned int)Byte() << 8);
    }
    uint64 U64()
    {
        uint64 v = 0;
        for (int i = 0; i < 8; i++)
            v |= (uint64)Byte() << (8 * i);
        return v;
    }
    vector<unsigned char> Bytes(size_t nLen)
    {
        if (nLen > n)
            nLen = n;
        vector<unsigned char> v(p, p + nLen);
        p += nLen;
        n -= nLen;
        return v;
    }
};

static vector<unsigned char> MakeRecord(const char* pszName, unsigned int nSpacing, unsigned int nWindow,
                                        unsigned int nFeeBps)
{
    poolreg::PoolRecord r;
    r.nSpacing = nSpacing;
    r.nWindow = nWindow;
    r.nRetarget = 360;
    r.nFloor = poolreg::NETWORK_FLOOR;
    r.nUncleDepth = 2;
    r.nUnclePct = 80;
    r.nFeeBps = nFeeBps;
    if (nFeeBps)
    {
        r.nFeeType = poolreg::FEE_P2PKH;
        for (int i = 0; i < 20; i++)
            r.feeHash[i] = (unsigned char)(0x40 + i);
    }
    r.name = pszName;
    string err;
    if (!r.Check(err))
    {
        fprintf(stderr, "fuzz-poolindex: table record refused: %s\n", err.c_str());
        exit(1);
    }
    return r.Encode();
}

static uint256 IdOfRecord(const vector<unsigned char>& record)
{
    uint256 id = 0;
    poolreg::PoolId(record, (const unsigned char*)pchMessageStart, id.begin());
    return id;
}

static vector<unsigned char> TagPush(const char* tag, const uint256* pId, unsigned char h)
{
    vector<unsigned char> v(tag, tag + 3);
    if (pId)
    {
        uint256 id = *pId;
        v.insert(v.end(), id.begin(), id.end());
    }
    v.insert(v.end(), 32, h);
    return v;
}

static bool Contains(const CScript& s, const unsigned char* p, size_t n)
{
    if (s.size() < n)
        return false;
    for (size_t i = 0; i + n <= s.size(); i++)
        if (memcmp(&s[i], p, n) == 0)
            return true;
    return false;
}

static CTransaction Coinbase(const CScript& scriptSig)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
    return tx;
}

static int Classify(const CScript& scriptSig, uint256& id, uint256& hash)
{
    id = 0;
    hash = 0;
    return ClassifyPoolAnchor(Coinbase(scriptSig), id, hash);
}

//
// Mode 0: ClassifyPoolAnchor.
//

static void RunClassify(const uint8_t* data, size_t size)
{
    CScript s(data, data + size);
    uint256 id, hash;
    int nKind = Classify(s, id, hash);
    if (nKind != POOL_ANCHOR_NONE && nKind != POOL_ANCHOR_ZERO && nKind != POOL_ANCHOR_REGISTERED)
        Fail("an anchor kind that does not exist");

    // Not a coinbase: no pool.
    CTransaction tx = Coinbase(s);
    tx.vin[0].prevout.hash = uint256(1);
    tx.vin[0].prevout.n = 0;
    uint256 id2 = 0, hash2 = 0;
    if (ClassifyPoolAnchor(tx, id2, hash2) != POOL_ANCHOR_NONE)
        Fail("a transaction that is not a coinbase names a pool");

    if (nKind == POOL_ANCHOR_NONE)
        return;
    // The anchor's bytes are in the script, in one piece.
    vector<unsigned char> want;
    if (nKind == POOL_ANCHOR_ZERO)
        want.assign(hash.begin(), hash.end());
    else
    {
        want.assign(id.begin(), id.end());
        want.insert(want.end(), hash.begin(), hash.end());
    }
    if (!Contains(s, &want[0], want.size()))
        Fail("an anchor whose hashes are not in the script");

    // The whole script parsed, so pushes can be added after it.
    const uint256 other = uint256(0x1234);
    struct Case { vector<unsigned char> push; int nWant; };
    Case cases[4];
    cases[0].push = TagPush("p2p", NULL, 0x5a);
    cases[0].nWant = POOL_ANCHOR_NONE;
    cases[1].push = TagPush("p2x", &other, 0x5b);
    cases[1].nWant = POOL_ANCHOR_NONE;
    cases[2].push = TagPush("p2l", NULL, 0x5c);
    cases[2].nWant = nKind == POOL_ANCHOR_ZERO ? POOL_ANCHOR_ZERO : POOL_ANCHOR_NONE;
    cases[3].push = TagPush("p2p", NULL, 0x5d);
    cases[3].push.pop_back();              // 34 bytes: no tag
    cases[3].nWant = nKind;
    for (int i = 0; i < 4; i++)
    {
        CScript t = s;
        t << cases[i].push;
        uint256 idT, hashT;
        int nT = Classify(t, idT, hashT);
        if (nT != cases[i].nWant)
        {
            fprintf(stderr, "fuzz-poolindex: case %d: kind %d, wanted %d (was %d)\n", i, nT, cases[i].nWant, nKind);
            Fail("adding a push changed the anchor the wrong way");
        }
        if (nT == nKind && (hashT != hash || (nKind == POOL_ANCHOR_REGISTERED && idT != id)))
            Fail("adding a push that is no tag changed the anchor");
    }
}

//
// The fold: blocks from the input, and the branch the registry read.
//

struct Branch
{
    vector<std::shared_ptr<const CBlock> > vBlock;   // [height]
    vector<uint256> vHash;
};

static void AppendTxOut(Reader& r, CTransaction& tx)
{
    unsigned char nValue = r.Byte() % 4;
    int64 nOut = 0;
    if (nValue == 0)
        nOut = poolreg::MIN_BURN - 1;
    else if (nValue == 1)
        nOut = poolreg::MIN_BURN;
    else if (nValue == 2)
        nOut = 50 * COIN;
    else
        nOut = (int64)(r.U64() % (uint64)(MAX_MONEY + 1));   // a valid block's outputs are in range
    unsigned char nScript = r.Byte() % 4;
    CScript script;
    if (nScript == 0 || nScript == 1)
    {
        vector<unsigned char> record = g_record[r.Byte() % N_RECORDS];
        if (nScript == 1)
        {
            unsigned char nPos = r.Byte();
            record[nPos % record.size()] ^= (unsigned char)(r.Byte() | 1);
        }
        script << OP_RETURN << record;
    }
    else if (nScript == 2)
    {
        vector<unsigned char> raw = r.Bytes(r.Byte());
        script = CScript(raw.begin(), raw.end());
    }
    else
        script << OP_TRUE;
    tx.vout.push_back(CTxOut(nOut, script));
}

static std::shared_ptr<const CBlock> ReadBlock(Reader& r, int nHeight)
{
    CTransaction cb;
    cb.vin.resize(1);
    CScript& ss = cb.vin[0].scriptSig;
    int nPush = r.Byte() % 5;
    for (int i = 0; i < nPush; i++)
    {
        unsigned char nKind = r.Byte() % 5;
        if (nKind == 0)
            ss << TagPush("p2p", NULL, r.Byte());
        else if (nKind == 1)
        {
            uint256 id = g_id[r.Byte() % N_IDS];
            ss << TagPush("p2x", &id, r.Byte());
        }
        else if (nKind == 2)
            ss << TagPush("p2l", NULL, r.Byte());
        else if (nKind == 3)
        {
            // Raw bytes, as they are: may leave the script unparsable.
            vector<unsigned char> raw = r.Bytes(r.Byte() % 96);
            ss.insert(ss.end(), raw.begin(), raw.end());
        }
        else
            ss << nHeight;
    }
    AppendTxOut(r, cb);
    CBlock* pblock = new CBlock();
    pblock->vtx.push_back(cb);
    int nTx = r.Byte() % 3;
    for (int t = 0; t < nTx; t++)
    {
        CTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.hash = uint256(++g_nNextHash);
        tx.vin[0].prevout.n = 0;
        int nOut = 1 + r.Byte() % 3;
        for (int o = 0; o < nOut; o++)
            AppendTxOut(r, tx);
        pblock->vtx.push_back(tx);
    }
    return std::shared_ptr<const CBlock>(pblock);
}

static std::shared_ptr<const CBlock> RunBlock(unsigned char nAnchor, unsigned char nIdSel, unsigned char h)
{
    CScript ss;
    ss << 1;
    nAnchor %= 4;
    if (nAnchor == 1)
        ss << TagPush("p2p", NULL, h);
    else if (nAnchor == 2)
    {
        uint256 id = g_id[nIdSel % N_IDS];
        ss << TagPush("p2x", &id, h);
    }
    else if (nAnchor == 3)
        ss << TagPush("p2l", NULL, h);
    CBlock* pblock = new CBlock();
    pblock->vtx.push_back(Coinbase(ss));
    return std::shared_ptr<const CBlock>(pblock);
}

static void Connect(CPoolRegistry& reg, Branch& br, const std::shared_ptr<const CBlock>& pblock)
{
    int nHeight = reg.Height() + 1;
    uint256 hash = uint256(++g_nNextHash);
    if (!reg.ConnectBlock(*pblock, nHeight, hash))
        Fail("the next block was refused");
    br.vBlock.push_back(pblock);
    br.vHash.push_back(hash);
}

// What a node with no file reads: the branch from genesis.
static void ReadFromGenesis(CPoolRegistry& reg, const Branch& br)
{
    reg.Reset((const unsigned char*)pchMessageStart);
    for (size_t i = 0; i < br.vBlock.size(); i++)
        if (!reg.ConnectBlock(*br.vBlock[i], (int)i, br.vHash[i]))
            Fail("the branch read from genesis was refused");
}

static void CheckHolds(const CPoolRegistry& reg, const char* pszWhere)
{
    string why;
    if (!reg.CheckConsistent(why))
    {
        fprintf(stderr, "fuzz-poolindex: %s: %s\n", pszWhere, why.c_str());
        Fail("the registry does not hold together");
    }
}

// Every query answers, and the answers agree with each other.
static void CheckQueries(const CPoolRegistry& reg)
{
    vector<CPoolInfo> v;
    vector<CPoolAppearance> vZero;
    reg.List(v);
    if (v.empty() || !v[0].fZero || v[0].nStatus != POOL_ACTIVE)
        Fail("the list does not start with pool zero");
    // Pool zero is listed once, burned or not.
    if (v.size() != reg.PoolCount() + 1 - (reg.Appearances(reg.ZeroId(), vZero) ? 1 : 0))
        Fail("the list does not hold every pool once");
    for (size_t i = 1; i < v.size(); i++)
    {
        const CPoolInfo& p = v[i];
        if (p.fZero)
            Fail("pool zero listed twice");
        if (p.nAppearances < 1 || p.first.nHeight < 0)
            Fail("a listed pool with no appearance");
        int nWantStatus = p.nConfirmations >= POOL_ACTIVE_CONFIRMATIONS ? POOL_ACTIVE : POOL_PENDING;
        if (p.nStatus != nWantStatus || reg.Status(p.id) != p.nStatus)
            Fail("a status that does not follow the confirmations");
        if (p.nConfirmations != reg.Height() - p.first.nHeight + 1)
            Fail("confirmations that do not follow the tip");
        CPoolInfo q;
        if (!reg.Lookup(p.id, q) || q.nAppearances != p.nAppearances || q.record != p.record)
            Fail("a listed pool that its lookup does not find the same");
        vector<CPoolAppearance> va;
        if (!reg.Appearances(p.id, va) || (int)va.size() != p.nAppearances || !(va[0] == p.first))
            Fail("appearances that do not match the list");
        if (i > 1 && v[i - 1].first.nHeight > p.first.nHeight)
            Fail("the list out of first-appearance order");
        if (p.vRecentAnchors.size() > POOL_RECENT_ANCHORS || p.nAnchorsInWindow < 0 ||
            p.nAnchorsInWindow > POOL_ANCHOR_WINDOW)
            Fail("anchors past their bounds");
    }
    for (int i = 0; i < N_IDS; i++)
    {
        vector<CPoolAnchor> vRecent;
        int nInWindow = 0;
        reg.Anchors(g_id[i], vRecent, nInWindow);
        if (vRecent.size() > POOL_RECENT_ANCHORS || nInWindow < 0 || nInWindow > POOL_ANCHOR_WINDOW)
            Fail("anchors past their bounds");
        for (size_t k = 1; k < vRecent.size(); k++)
            if (vRecent[k - 1].nHeight <= vRecent[k].nHeight)
                Fail("recent anchors not newest first");
        int nStatus = reg.Status(g_id[i]);
        if (nStatus != POOL_UNKNOWN && nStatus != POOL_PENDING && nStatus != POOL_ACTIVE)
            Fail("a status that does not exist");
    }
    if (reg.AnchorsCounted() > reg.AnchorsStored())
        Fail("more anchors count than are kept");
}

static void CheckRoundTrip(const CPoolRegistry& reg)
{
    CDataStream ss(SER_DISK);
    ss << reg;
    CPoolRegistry back;
    try
    {
        ss >> back;
    }
    catch (std::exception&)
    {
        Fail("a registry that does not read back");
    }
    if (!ss.empty())
        Fail("a registry that leaves bytes when read back");
    CheckHolds(back, "read back");
    if (back.Digest() != reg.Digest())
        Fail("a registry that reads back to another");
}

static void RunFold(Reader& r)
{
    CPoolRegistry reg;
    reg.Reset((const unsigned char*)pchMessageStart);
    Branch br;
    int nChecks = 0, nRereads = 0;
    for (int nOp = 0; nOp < FOLD_MAX_OPS && !r.Empty(); nOp++)
    {
        unsigned char op = r.Byte() % 4;
        if (op == OP_FOLD_BLOCK)
        {
            std::shared_ptr<const CBlock> pblock = ReadBlock(r, reg.Height() + 1);
            if (reg.Height() < FOLD_MAX_HEIGHT)
                Connect(reg, br, pblock);
        }
        else if (op == OP_FOLD_RUN)
        {
            int nCount = 1 + r.Byte();
            nCount += 256 * (r.Byte() % 8);
            unsigned char nAnchor = r.Byte(), nIdSel = r.Byte(), h = r.Byte();
            std::shared_ptr<const CBlock> pblock = RunBlock(nAnchor, nIdSel, h);
            for (int i = 0; i < nCount && reg.Height() < FOLD_MAX_HEIGHT; i++)
                Connect(reg, br, pblock);
        }
        else if (op == OP_FOLD_DISCONNECT)
        {
            int nDepth = (int)(r.U16() % (unsigned int)(reg.Height() + 2));
            int nTo = reg.Height() - nDepth;
            uint256 hashAt = nTo >= 0 ? br.vHash[nTo] : uint256(0);
            bool fExact = reg.DisconnectAbove(nTo, hashAt);
            br.vBlock.resize(nTo + 1);
            br.vHash.resize(nTo + 1);
            if (reg.Height() != nTo || reg.TipHash() != hashAt)
                Fail("a disconnect that left another tip");
            if (!fExact)
            {
                ReadFromGenesis(reg, br);
                if (++nRereads >= FOLD_MAX_REREADS)
                    break;
            }
        }
        else
        {
            if (nChecks++ >= FOLD_MAX_CHECKS)
                continue;
            CPoolRegistry ref;
            ReadFromGenesis(ref, br);
            if (ref.Digest() != reg.Digest())
                Fail("the registry is not the one read from genesis");
            CheckQueries(reg);
        }
        CheckHolds(reg, "after an operation");
    }
    CPoolRegistry ref;
    ReadFromGenesis(ref, br);
    if (ref.Digest() != reg.Digest())
        Fail("the registry is not the one read from genesis");
    CheckQueries(reg);
    CheckRoundTrip(reg);
}

//
// Mode 1: CPoolIndex::Load.
//

static string DataPath(const char* pszName)
{
    return strSetDataDir + "/" + pszName;
}

static bool WriteFile(const string& path, const string& data)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
        return false;
    bool fOk = fwrite(data.data(), 1, data.size(), f) == data.size();
    return fclose(f) == 0 && fOk;
}

static void RunLoad(unsigned char nFlags, const uint8_t* data, size_t size)
{
    string file;
    if (nFlags & F_LOAD_VERSION)
    {
        int nVersion = 2;
        file.append((const char*)&nVersion, 4);
    }
    file.append((const char*)data, size);
    if (nFlags & F_LOAD_CHECKSUM)
    {
        uint256 h = Hash(file.begin(), file.end());
        file.append((const char*)h.begin(), 32);
    }
    const string path = DataPath("pool-registry.dat");
    if (!WriteFile(path, file))
        Fail("cannot write the file");
    CPoolIndex idx;
    idx.SetPath(path);
    if (!idx.Load())
        return;

    CPoolRegistry reg = idx.Snapshot();
    CheckHolds(reg, "loaded");
    const uint256 digest = reg.Digest();
    if (idx.Digest() != digest)
        Fail("the index answers with another registry than its snapshot");
    CheckQueries(reg);
    CheckRoundTrip(reg);

    // Written back, it loads to the same registry.
    const string path2 = DataPath("pool-registry-2.dat");
    idx.SetPath(path2);
    if (!idx.Save())
        Fail("a loaded registry that does not save");
    CPoolIndex idx2;
    idx2.SetPath(path2);
    if (!idx2.Load() || idx2.Digest() != digest)
        Fail("a saved registry that does not load to itself");

    // One more block, then lost again.
    const int nHeight = reg.Height();
    if (nHeight >= 100000000)
        return;
    const uint256 hashTip = reg.TipHash();
    vector<CPoolInfo> v;
    reg.List(v);
    unsigned char nIdSel = size ? data[size - 1] : 0;
    CScript ss;
    ss << nHeight + 1;
    uint256 id = v[nIdSel % v.size()].id;
    if (nIdSel & 0x80)
        ss << TagPush("p2x", &id, 0x77);
    else
        ss << TagPush("p2p", NULL, 0x77);
    CBlock block;
    block.vtx.push_back(Coinbase(ss));
    if (!reg.ConnectBlock(block, nHeight + 1, uint256(++g_nNextHash)))
        Fail("a loaded registry refused its next block");
    CheckHolds(reg, "loaded, one block on");
    if (reg.DisconnectAbove(nHeight, hashTip) && reg.Digest() != digest)
        Fail("a block taken back left another registry, said to be exact");
    CheckHolds(reg, "loaded, the block taken back");
}

//
// Seeds.
//

struct Writer
{
    string s;
    void Byte(unsigned int b) { s.push_back((char)(unsigned char)b); }
    void U16(unsigned int v) { Byte(v & 0xff); Byte((v >> 8) & 0xff); }
    void Raw(const vector<unsigned char>& v) { s.append(v.begin(), v.end()); }
    // A run of n blocks (1 to 2048) with one anchor each.
    void Run(int n, int nAnchor, int nIdSel, int h)
    {
        n -= 1;
        Byte(OP_FOLD_RUN);
        Byte(n % 256);
        Byte(n / 256);
        Byte(nAnchor);
        Byte(nIdSel);
        Byte(h);
    }
    // A block with a height push, an anchor, and one transaction that burns
    // record nRecord with 1 BTF (and a second output that does not count).
    void BurnBlock(int nRecord, int nAnchor, int nIdSel)
    {
        Byte(OP_FOLD_BLOCK);
        Byte(2);                     // two pushes
        Byte(4);                     // the height
        if (nAnchor == 2)
        {
            Byte(1);
            Byte(nIdSel);
            Byte(0x33);
        }
        else
        {
            Byte(0);
            Byte(0x33);
        }
        Byte(2); Byte(3);            // coinbase output: 50 BTF to OP_TRUE
        Byte(1);                     // one transaction
        Byte(1);                     // two outputs
        Byte(1); Byte(0); Byte(nRecord);         // 1 BTF burning the record
        Byte(0); Byte(0); Byte(nRecord);         // under 1 BTF: no appearance
    }
    void Disconnect(int nDepth)
    {
        Byte(OP_FOLD_DISCONNECT);
        U16(nDepth);
    }
    void Check() { Byte(OP_FOLD_CHECK); }
};

static void WriteRaw(const string& strDir, const char* pszName, const string& str)
{
    if (!WriteFile(strDir + "/" + pszName, str))
    {
        perror((strDir + "/" + pszName).c_str());
        exit(1);
    }
}

static string ScriptSeed(const CScript& s)
{
    string str(1, (char)0);
    str.append(s.begin(), s.end());
    return str;
}

static void WriteSeeds(const string& strDir)
{
    // Mode 0: anchors.
    uint256 id1 = g_id[1];
    WriteRaw(strDir, "anchor-zero", ScriptSeed(CScript() << 23069 << TagPush("p2p", NULL, 0x11)));
    WriteRaw(strDir, "anchor-registered", ScriptSeed(CScript() << 23069 << TagPush("p2x", &id1, 0x22)));
    WriteRaw(strDir, "anchor-zero-and-local",
             ScriptSeed(CScript() << 23069 << TagPush("p2l", NULL, 0x33) << TagPush("p2p", NULL, 0x11)));
    WriteRaw(strDir, "anchor-registered-and-local",
             ScriptSeed(CScript() << 23069 << TagPush("p2x", &id1, 0x22) << TagPush("p2l", NULL, 0x33)));
    WriteRaw(strDir, "anchor-both", ScriptSeed(CScript() << TagPush("p2x", &id1, 0x22) << TagPush("p2p", NULL, 0x11)));
    {
        // A push by OP_PUSHDATA2, then one cut short.
        vector<unsigned char> push = TagPush("p2p", NULL, 0x44);
        string str(1, (char)0);
        str.push_back((char)OP_PUSHDATA2);
        str.push_back((char)push.size());
        str.push_back(0);
        str.append(push.begin(), push.end());
        WriteRaw(strDir, "anchor-pushdata2", str);
        str.push_back((char)OP_PUSHDATA1);
        str.push_back((char)40);
        str.append(5, 'x');
        WriteRaw(strDir, "anchor-truncated", str);
    }

    // Mode 2: folds.
    {
        // A pool burned, then reorged out before 30 confirmations and burned
        // again; another active at 30 and reorged out after.
        Writer w;
        w.Byte(2);
        w.Run(10, 1, 0, 1);
        w.BurnBlock(1, 1, 0);
        w.Run(20, 2, 1, 2);
        w.Check();
        w.Disconnect(15);
        w.Run(25, 1, 0, 3);
        w.BurnBlock(1, 2, 1);
        w.Run(40, 2, 1, 4);
        w.BurnBlock(2, 2, 2);
        w.Run(35, 2, 2, 5);
        w.Check();
        w.Disconnect(40);
        w.Check();
        WriteRaw(strDir, "fold-reorg-around-30", w.s);
    }
    {
        // Anchors for an id nobody burned across sweeps and the margin, then
        // its record burned; a reorg across a sweep; pool zero's own record.
        Writer w;
        w.Byte(3);
        w.Run(1500, 2, 4, 6);
        w.Run(1500, 2, 5, 7);
        w.Run(300, 1, 0, 8);
        w.BurnBlock(4, 2, 4);
        w.Check();
        w.Run(200, 2, 4, 9);
        w.Disconnect(250);
        w.BurnBlock(0, 1, 0);
        w.Run(100, 2, 4, 10);
        w.Check();
        w.Disconnect(2000);
        w.Check();
        WriteRaw(strDir, "fold-sweeps", w.s);
    }
    {
        // A registered pool's anchors past 64 + the margin, trimmed, then a
        // reorg into the trimmed part.
        Writer w;
        w.Byte(2);
        w.BurnBlock(3, 2, 3);
        w.Run(2048, 2, 3, 11);
        w.Run(1500, 2, 3, 12);
        w.Check();
        w.Disconnect(3000);
        w.Check();
        WriteRaw(strDir, "fold-trim", w.s);
    }

    // Mode 1: files the index wrote.
    {
        CPoolRegistry reg;
        reg.Reset((const unsigned char*)pchMessageStart);
        Branch br;
        for (int i = 0; i < 400; i++)
            Connect(reg, br, RunBlock(2, (unsigned char)(4 + i % 2), (unsigned char)i));
        for (int k = 1; k < N_RECORDS; k++)
        {
            CTransaction tx;
            tx.vin.resize(1);
            tx.vin[0].prevout.hash = uint256(1000 + k);
            tx.vout.push_back(CTxOut(poolreg::MIN_BURN, CScript() << OP_RETURN << g_record[k]));
            CBlock* pblock = new CBlock(*RunBlock(2, (unsigned char)k, (unsigned char)k));
            pblock->vtx.push_back(tx);
            Connect(reg, br, std::shared_ptr<const CBlock>(pblock));
            for (int i = 0; i < 20; i++)
                Connect(reg, br, RunBlock(2, (unsigned char)k, (unsigned char)(i + k)));
        }
        CheckHolds(reg, "seed");
        CDataStream ss(SER_DISK);
        ss << 2 << reg;
        string body(ss.begin(), ss.end());
        uint256 h = Hash(body.begin(), body.end());
        string full = body + string((const char*)h.begin(), 32);
        WriteRaw(strDir, "file-as-written", string(1, (char)1) + full);
        WriteRaw(strDir, "file-checksum-fixed", string(1, (char)(1 | F_LOAD_CHECKSUM)) + body);
        WriteRaw(strDir, "file-version-and-checksum-fixed",
                 string(1, (char)(1 | F_LOAD_VERSION | F_LOAD_CHECKSUM)) + body.substr(4));
        CPoolRegistry empty;
        empty.Reset((const unsigned char*)pchMessageStart);
        CDataStream se(SER_DISK);
        se << empty;
        string e(se.begin(), se.end());
        WriteRaw(strDir, "file-empty-registry", string(1, (char)(1 | F_LOAD_VERSION | F_LOAD_CHECKSUM)) + e);
    }
}

static void FuzzPoolIndexInit()
{
    SelectChainParams(false);
    g_record[0] = poolreg::PoolZero().Encode();
    g_record[1] = MakeRecord("fuzz-a", 30, 720, 0);
    g_record[2] = MakeRecord("fuzz-b", 40, 360, 100);
    g_record[3] = MakeRecord("fuzz-c", 60, 2160, 300);
    g_record[4] = MakeRecord("fuzz-d", 120, 1440, 0);
    for (int i = 0; i < N_RECORDS; i++)
        g_id[i] = IdOfRecord(g_record[i]);
    g_id[5] = uint256(0x7777);
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 1000000)
        return 0;
    unsigned char nFlags = data[0];
    data++;
    size--;
    switch (nFlags & 3)
    {
    case 0:
        RunClassify(data, size);
        break;
    case 1:
        RunLoad(nFlags, data, size);
        break;
    default:
    {
        Reader r(data, size);
        RunFold(r);
        break;
    }
    }
    return 0;
}
