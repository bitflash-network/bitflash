// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Integration self-tests that need the real wallet/database code linked into
// the node. These are intentionally run behind an explicit command-line flag
// and against a temporary data directory.

#include "headers_core.h"
#include <atomic>
#include <limits>
#include "btfaddr.h"
#include "bip32.h"
#include "proxy.h"
#include "selftest.h"
#include "p2pool_net.h"
#include "sigcheck.h"
#ifndef _WIN32
#include <sys/wait.h>   // WIFEXITED/WEXITSTATUS for the child-process helper
#endif
#include "sockcount.h"
#include "btfchatnode.h"
#include "btfchatsock.h"
#include "btfchatnet.h"
#include "chatrelay.h"
#include "chatstore.h"
#include "swap.h"
#include "btcswap.h"
#include "btclight.h"
#include "btfchatswap.h"
#include "jsonsafe.h"
#include "invoice.h"
#include "bip21.h"
#include "btfchatwallet.h"
#include "chatdir.h"
#include "community.h"
#include "explorer.h"
#include "jsonrpc.h"
#include "rpcclient.h"
// The chat test signs frames, so it needs a secp256k1 context of its own. Not
// the node identity from nostr.h: asking for that would generate and persist a
// node key, and a self-test has no business creating one.
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "tor.h"
#include "treasury.h"
#include "walletcmd.h"
#include "wallet_sqlite.h"

extern int RunPoolStratumSelfTest();

// Test results go to the terminal, not to debug.log.
//
// printf in this tree is OutputDebugStringF, which writes into the data
// directory's debug.log and binds that path, once, on its first call. For a
// self-test that produced two bad outcomes at the same time. On Windows the
// binary is linked -mwindows and has no console, so `make tests` printed the
// bip32 results, echoed the self-test command, and then showed nothing at all --
// a failure was still caught, because a non-zero return stops make, but it
// arrived with no way to tell which check failed. And because the first line
// printed before strSetDataDir was pointed at the temporary directory, every
// line landed in the developer's real debug.log: the same file users are asked
// to paste into issues.
//
// Undefining the macro here gives this file the real printf, so results reach
// stdout. Nothing else in the tree is affected.
#undef printf

#include <mutex>
#include <cerrno>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif
#include <randomx.h>
#include <openssl/sha.h>

static std::string HexStrLocal(const std::vector<unsigned char>& v)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (unsigned char c : v)
    {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

static vector<unsigned char> DataStreamBytes(const CDataStream& ss)
{
    return vector<unsigned char>(ss.begin(), ss.end());
}

static bool MakeTempDir(std::string& out)
{
#ifdef _WIN32
    char base[MAX_PATH + 1] = {0};
    if (!GetTempPathA(MAX_PATH, base))
        return false;
    for (int i = 0; i < 100; i++)
    {
        std::string path = strprintf("%sbitflash-selftest-%lu-%lld-%d",
            base, (unsigned long)GetCurrentProcessId(), (long long)GetTime(), i);
        if (CreateDirectoryA(path.c_str(), NULL))
        {
            out = path;
            return true;
        }
    }
    return false;
#else
    char tmpl[256];
    snprintf(tmpl, sizeof(tmpl), "/tmp/bitflash-selftest-%ld-XXXXXX", (long)getpid());
    char* p = mkdtemp(tmpl);
    if (!p)
        return false;
    out = p;
    return true;
#endif
}

static bool GetCurrentDir(std::string& out)
{
#ifdef _WIN32
    char buf[MAX_PATH + 1] = {0};
    DWORD n = GetCurrentDirectoryA(MAX_PATH, buf);
    if (n == 0 || n > MAX_PATH)
        return false;
    out = buf;
    return true;
#else
    char buf[4096];
    if (!getcwd(buf, sizeof(buf)))
        return false;
    out = buf;
    return true;
#endif
}

static bool SetCurrentDir(const std::string& path)
{
#ifdef _WIN32
    return SetCurrentDirectoryA(path.c_str()) != 0;
#else
    return chdir(path.c_str()) == 0;
#endif
}

static void RemoveTree(const std::string& path)
{
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        DeleteFileA(path.c_str());
        return;
    }

    WIN32_FIND_DATAA findData;
    std::string pattern = path + "\\*";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            std::string name = findData.cFileName;
            if (name == "." || name == "..")
                continue;
            RemoveTree(path + "\\" + name);
        }
        while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    RemoveDirectoryA(path.c_str());
#else
    struct stat st;
    if (lstat(path.c_str(), &st) != 0)
        return;
    if (!S_ISDIR(st.st_mode))
    {
        unlink(path.c_str());
        return;
    }

    DIR* dir = opendir(path.c_str());
    if (dir)
    {
        struct dirent* ent;
        while ((ent = readdir(dir)) != NULL)
        {
            std::string name = ent->d_name;
            if (name == "." || name == "..")
                continue;
            RemoveTree(path + "/" + name);
        }
        closedir(dir);
    }
    rmdir(path.c_str());
#endif
}

static bool WalletHasPrivateKey(const std::vector<unsigned char>& vchPubKey)
{
    CPrivKey priv;
    return CWalletDB("r").ReadKey(vchPubKey, priv) && !priv.empty();
}

static bool Check(bool condition, const char* message)
{
    if (condition)
    {
        printf("  ok   %s\n", message);
        return true;
    }
    printf("  FAIL %s\n", message);
    return false;
}

// A fresh chain, which is the genesis block alone, and a transaction waiting.
// With EXPLORER_DATADIR it reads that node's files instead and prints what it
// finds for each of EXPLORER_QUERIES, for comparing with a real chain.
static int RunExplorerSelfTest()
{
    printf("explorer self-test\n");
    int nFail = 0;
    const char* pszDataDir = getenv("EXPLORER_DATADIR");
    std::string tmp;
    if (pszDataDir)
        strSetDataDir = pszDataDir;
    else
    {
        if (!MakeTempDir(tmp))
        {
            printf("  FAIL could not create a temporary data directory\n");
            return 1;
        }
        strSetDataDir = tmp;
    }
    try
    {
        if (!LoadBlockIndex())
            throw std::runtime_error("LoadBlockIndex failed");
        const char* pszQueries = getenv("EXPLORER_QUERIES");
        if (pszDataDir)
        {
            std::stringstream queries(pszQueries ? pszQueries : "");
            std::string query;
            while (queries >> query)
            {
                uint256 hash;
                explorer::Result result = explorer::Find(query, hash);
                if (result == explorer::IS_BLOCK)
                {
                    explorer::BlockView view;
                    nFail += explorer::ReadBlock(hash, view) == explorer::FOUND ? 0 : 1;
                    printf("block %d %s txs=%d size=%u main=%d\n", view.height, view.hash.GetHex().c_str(),
                           (int)view.txs.size(), view.nSize, (int)view.fMainChain);
                }
                else if (result == explorer::IS_TX)
                {
                    explorer::TxView view;
                    nFail += explorer::ReadTx(hash, view) == explorer::FOUND ? 0 : 1;
                    printf("tx %s height=%d size=%u fee=%s\n", view.txid.GetHex().c_str(), view.height, view.nSize,
                           view.fFeeKnown ? explorer::Money(view.fee).c_str() : "?");
                    for (size_t i = 0; i < view.in.size(); i++)
                        printf("  in %s:%u %s %s\n", view.in[i].prev.GetHex().c_str(), view.in[i].n,
                               explorer::Money(view.in[i].value).c_str(), view.in[i].from.c_str());
                    for (size_t i = 0; i < view.out.size(); i++)
                        printf("  out %s %s spentby=%s\n", explorer::Money(view.out[i].value).c_str(),
                               view.out[i].to.c_str(), view.out[i].spentBy.GetHex().c_str());
                }
                else
                {
                    printf("  FAIL nothing found for %s\n", query.c_str());
                    nFail++;
                }
            }
            return nFail ? 1 : 0;
        }

        uint256 genesis = hashGenesisBlock;
        uint256 hash;
        nFail += Check(explorer::Find(" 0 ", hash) == explorer::IS_BLOCK && hash == genesis, "a height names its block") ? 0 : 1;
        nFail += Check(explorer::Find(genesis.GetHex(), hash) == explorer::IS_BLOCK, "a block hash names its block") ? 0 : 1;
        nFail += Check(explorer::Find("1", hash) == explorer::NOT_FOUND, "a height past the tip is not found") ? 0 : 1;
        nFail += Check(explorer::Find("xyz", hash) == explorer::BAD_QUERY, "a word is not a query") ? 0 : 1;
        nFail += Check(explorer::Find("", hash) == explorer::BAD_QUERY, "nor is nothing") ? 0 : 1;
        nFail += Check(explorer::Find(std::string(64, 'a'), hash) == explorer::NOT_FOUND, "an unknown hash is not found") ? 0 : 1;

        explorer::BlockView block;
        nFail += Check(explorer::ReadBlock(genesis, block) == explorer::FOUND, "the genesis block reads") ? 0 : 1;
        nFail += Check(block.height == 0 && block.fMainChain && block.next == uint256(0) && block.txs.size() == 1 &&
                       block.txs[0].fCoinBase && block.txs[0].value == 50 * COIN, "and says what it is") ? 0 : 1;
        explorer::BlockView none;
        nFail += Check(explorer::ReadBlock(uint256(7), none) == explorer::NOT_FOUND, "an unknown block does not") ? 0 : 1;

        std::vector<explorer::BlockRow> rows;
        int nTip = -1;
        nFail += Check(explorer::Recent(-1, 25, rows, nTip) == explorer::FOUND && rows.size() == 1 && nTip == 0 &&
                       rows[0].hash == genesis && rows[0].reward == 50 * COIN && !rows[0].to.empty(),
                       "the list starts at the tip") ? 0 : 1;

        nFail += Check(explorer::Find(block.txs[0].txid.GetHex(), hash) == explorer::IS_TX, "a txid names its transaction") ? 0 : 1;
        explorer::TxView coinbase;
        nFail += Check(explorer::ReadTx(block.txs[0].txid, coinbase) == explorer::FOUND && coinbase.fInChain &&
                       coinbase.fCoinBase && coinbase.in.empty() && !coinbase.fFeeKnown && coinbase.height == 0 &&
                       coinbase.nConfirmations == 1 && coinbase.block == genesis && coinbase.out.size() == 1 &&
                       coinbase.out[0].spentBy == uint256(0), "a coinbase reads, unspent") ? 0 : 1;

        // Waiting: spends what no node has, so its value and its fee stay unknown.
        CTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(uint256(9), 0);
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN;
        CScript p2sh;
        p2sh << OP_HASH160 << uint160(3) << OP_EQUAL;
        tx.vout[0].scriptPubKey = p2sh;
        uint256 txid = tx.GetHash();
        CRITICAL_BLOCK(cs_mapTransactions)
            mapTransactions[txid] = tx;
        explorer::TxView waiting;
        nFail += Check(explorer::Find(txid.GetHex(), hash) == explorer::IS_TX, "a waiting transaction is found") ? 0 : 1;
        nFail += Check(explorer::ReadTx(txid, waiting) == explorer::FOUND && !waiting.fInChain && !waiting.fFeeKnown &&
                       waiting.in.size() == 1 && !waiting.in[0].fKnown, "and reads, its fee unknown") ? 0 : 1;
        uint160 three(3);
        nFail += Check(waiting.out[0].to == Hash160ToScriptAddress(three), "a script address is an address") ? 0 : 1;
        CRITICAL_BLOCK(cs_mapTransactions)
            mapTransactions.erase(txid);

        nFail += Check(explorer::Money(23966227) == "0.23966227" && explorer::Money(3 * COIN) == "3.00" &&
                       explorer::Money(-COIN / 2) == "-0.50" && explorer::Money(1) == "0.00000001", "amounts keep every digit") ? 0 : 1;

        CScript data;
        data << OP_RETURN << 1;
        nFail += Check(explorer::DescribeScript(data) == "data", "an OP_RETURN is data") ? 0 : 1;
        CScript unknown;
        unknown << OP_1;
        nFail += Check(explorer::DescribeScript(unknown) == "script", "the rest is a script") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL %s\n", e.what());
        nFail++;
    }
    if (!tmp.empty())
    {
        DBFlush(true);
        RemoveTree(tmp);
    }
    printf("explorer: %d failure(s)\n", nFail);
    return nFail ? 1 : 0;
}

// A transaction holds a lock on every page it touches until it commits, and
// connecting a block is one transaction. Past the limit the node stops on that
// block, while others with their pages elsewhere accept it.
static int RunDbLocksSelfTest()
{
    printf("db-locks self-test\n");
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    int nFail = 0;
    {
        CTxDB txdb("cr+");
        // Filled in small transactions, as blocks fill it: years of a chain.
        CTxIndex txindex(CDiskTxPos(1, 1, 1), 1);
        const int nFill = 600000, nStep = 2000;
        for (int i = 0; i < nFill && nFail == 0; i += nStep)
        {
            nFail += txdb.TxnBegin() ? 0 : 1;
            for (int j = i; j < i + nStep; j++)
            {
                uint256 hash = Hash(BEGIN(j), END(j));
                nFail += txdb.UpdateTxIndex(hash, txindex) ? 0 : 1;
            }
            nFail += txdb.TxnCommit() ? 0 : 1;
        }
        nFail += Check(nFail == 0, "the index fills") ? 0 : 1;

        // A full block of the smallest transactions, 16000 of them: each writes
        // its own entry and the one it spends, and random keys land on their
        // own pages.
        const int nWrites = 32000;
        int nDone = 0;
        nFail += txdb.TxnBegin() ? 0 : 1;
        for (int i = 0; i < nWrites; i++)
        {
            int nKey = i * 18;
            uint256 hash = Hash(BEGIN(nKey), END(nKey));
            if (!txdb.UpdateTxIndex(hash, txindex))
                break;
            nDone++;
        }
        printf("  %d of %d writes in one transaction\n", nDone, nWrites);
        DB_LOCK_STAT* pstat = NULL;
        if (GetDbEnv().lock_stat(&pstat, 0) == 0 && pstat)
        {
            printf("  at most %u locks held, limit %u\n", pstat->st_maxnlocks, pstat->st_maxlocks);
            // Locks grow with the index, and with the page size, which Berkeley
            // DB takes from the filesystem: this same block takes 7921 on one
            // machine and 13976 on another, over the old limit of 10000.
            nFail += Check(pstat->st_maxlocks >= 20 * pstat->st_maxnlocks, "the limit leaves the index room to grow") ? 0 : 1;
            free(pstat);
        }
        nFail += Check(nDone == nWrites, "they all fit under the lock limit") ? 0 : 1;
        nFail += Check(nDone == nWrites ? txdb.TxnCommit() : txdb.TxnAbort(), "and it ends cleanly") ? 0 : 1;
    }
    DBFlush(true);
    RemoveTree(tmp);
    printf("db-locks: %d failure(s)\n", nFail);
    return nFail ? 1 : 0;
}

static int RunWalletKeyPoolSelfTest()
{
    fflush(stdout);
    printf("wallet-keypool self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    // Before anything can open the database or resolve the log path: what the
    // node itself prints during the test belongs in the temporary directory,
    // and dies with it. The test's own results are on stdout, above.
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        TopUpKeyPool();
        int nInitialPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nInitialPoolSize = (int)mapKeyPool.size();
        nFail += Check(nInitialPoolSize == KEYPOOL_SIZE, "TopUpKeyPool fills the pool") ? 0 : 1;

        bool fPooledKeysStored = true;
        CRITICAL_BLOCK(cs_keyPool)
        {
            for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
                 mi != mapKeyPool.end(); ++mi)
                if (!WalletHasPrivateKey(mi->second))
                    fPooledKeysStored = false;
        }
        nFail += Check(fPooledKeysStored, "every pooled public key has a stored private key") ? 0 : 1;

        std::vector<std::vector<unsigned char> > drawn;
        std::mutex drawnMutex;
        const int nThreads = 8;
        const int nDrawsPerThread = 32;
        std::vector<std::thread> threads;

        for (int t = 0; t < nThreads; t++)
        {
            threads.emplace_back([&drawn, &drawnMutex, nDrawsPerThread]() {
                for (int i = 0; i < nDrawsPerThread; i++)
                {
                    std::vector<unsigned char> key = GetKeyFromPool();
                    std::lock_guard<std::mutex> lock(drawnMutex);
                    drawn.push_back(key);
                }
            });
        }
        for (std::thread& t : threads)
            t.join();

        nFail += Check((int)drawn.size() == nThreads * nDrawsPerThread,
                       "all concurrent draws returned a key") ? 0 : 1;

        std::set<std::string> seen;
        bool fUnique = true;
        bool fAllStored = true;
        for (const std::vector<unsigned char>& key : drawn)
        {
            if (!seen.insert(HexStrLocal(key)).second)
                fUnique = false;
            if (!WalletHasPrivateKey(key))
                fAllStored = false;
        }

        nFail += Check(fUnique, "concurrent draws never return the same key") ? 0 : 1;
        nFail += Check(fAllStored, "each drawn key was already stored in wallet.dat") ? 0 : 1;
        int nPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPoolSize = (int)mapKeyPool.size();
        nFail += Check(nPoolSize == KEYPOOL_SIZE, "drawing leaves the key pool topped up") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// AttachTerminal() moved to util.h: the wallet phrase commands need it too,
// and two copies of a console-attach that must get its one condition right is
// one copy too many.

static int RunWalletHDSelfTest()
{
    fflush(stdout);
    printf("wallet-hd self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    // Test-vector phrases, so nothing here depends on randomness.
    const std::string strPhraseA =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    const std::string strPhraseB =
        "legal winner thank year wave sausage worth useful "
        "legal winner thank yellow";

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        std::string strError;
        TopUpKeyPool();
        int nRandomPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nRandomPoolSize = (int)mapKeyPool.size();
        nFail += Check(nRandomPoolSize == KEYPOOL_SIZE,
                       "a wallet can start with a random key pool") ? 0 : 1;

        // The address the wallet was showing before any of this. It has to
        // survive under a name that says it is not covered by the phrase.
        std::vector<unsigned char> vchPreSeedKey = keyUser.GetPubKey();
        std::string strPreSeedAddr = PubKeyToAddress(keyUser.GetPubKey());

        nFail += Check(SetHDSeedFromMnemonic(strPhraseA, "", strError),
                       "a valid phrase installs a seed") ? 0 : 1;
        nFail += Check(HaveHDSeed(), "the wallet reports having a seed") ? 0 : 1;
        nFail += Check(nHDKeySchema == HD_SCHEMA_BIP44,
                       "a new recovery phrase records the BIP44 HD schema") ? 0 : 1;
        nFail += Check(nHDCoinType == HD_BIP44_COIN_TYPE_BITFLASH,
                       "a new recovery phrase records the SLIP-0044 BIP44 coin type") ? 0 : 1;
        nFail += Check(nHDReceiveNext == 1 && nHDChangeNext == 0,
                       "BIP44 receive/change counters reserve the default receive key") ? 0 : 1;
        std::vector<unsigned int> vBIP44Path = HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH,
                                                           HD_BIP44_ACCOUNT,
                                                           HD_BIP44_CHAIN_RECEIVE,
                                                           0);
        nFail += Check(vBIP44Path.size() == 5 &&
                       vBIP44Path[0] == (HD_BIP44_PURPOSE | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[1] == (HD_BIP44_COIN_TYPE_BITFLASH | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[2] == (HD_BIP44_ACCOUNT | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[3] == HD_BIP44_CHAIN_RECEIVE &&
                       vBIP44Path[4] == 0,
                       "the BIP44 helper builds m/44'/coin_type'/account'/change/index") ? 0 : 1;

        int nPoolAfterSeed = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPoolAfterSeed = (int)mapKeyPool.size();
        nFail += Check(nPoolAfterSeed == 0,
                       "installing a phrase clears the old random key pool") ? 0 : 1;
        nFail += Check(nHDNext == 0,
                       "installing a BIP44 phrase leaves the legacy counter unused") ? 0 : 1;

        CKey keyFirstDerived;
        if (!DeriveHDKey(0, keyFirstDerived, strError))
            throw std::runtime_error("default derivation failed: " + strError);
        bitflash::BIP32PrivateNode hdParent;
        hdParent.privateKey = vchHDMaster;
        hdParent.chainCode = vchHDChainCode;
        bitflash::BIP32PrivateNode hdBIP44ReceiveChild;
        if (!bitflash::BIP32DerivePath(hdParent,
                                       HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH,
                                                   HD_BIP44_ACCOUNT,
                                                   HD_BIP44_CHAIN_RECEIVE,
                                                   0),
                                       hdBIP44ReceiveChild,
                                       strError))
            throw std::runtime_error("BIP44 receive path derivation failed: " + strError);
        CKey keyBIP44ReceivePath;
        if (!keyBIP44ReceivePath.SetSecret(hdBIP44ReceiveChild.privateKey))
            throw std::runtime_error("BIP44 receive path produced an unusable key");
        nFail += Check(keyBIP44ReceivePath.GetPubKey() == keyFirstDerived.GetPubKey(),
                       "the default HD key path is m/44'/coin_type'/0'/0/0") ? 0 : 1;

        bitflash::BIP32PrivateNode hdLegacyChild;
        int nSchemaForLegacyCheck = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        CKey keyLegacyDerived;
        if (!DeriveHDKey(0, keyLegacyDerived, strError))
            throw std::runtime_error("legacy derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyCheck;
        if (!bitflash::BIP32DerivePath(hdParent, HDLegacyPath(0), hdLegacyChild, strError))
            throw std::runtime_error("legacy path derivation failed: " + strError);
        CKey keyLegacyPath;
        if (!keyLegacyPath.SetSecret(hdLegacyChild.privateKey))
            throw std::runtime_error("legacy path produced an unusable key");
        nFail += Check(keyLegacyPath.GetPubKey() == keyLegacyDerived.GetPubKey(),
                       "the legacy HD key path remains m/index'") ? 0 : 1;

        std::vector<unsigned char> vchDefaultKey;
        bool fDefaultRead = CWalletDB("r").ReadDefaultKey(vchDefaultKey);
        nFail += Check(fDefaultRead && vchDefaultKey == keyFirstDerived.GetPubKey(),
                       "the default receiving key is derived from the phrase") ? 0 : 1;
        nFail += Check(WalletHasPrivateKey(vchDefaultKey),
                       "the derived default key is stored in wallet.dat") ? 0 : 1;

        std::string strNewAddr = PubKeyToAddress(vchDefaultKey);
        nFail += Check(strPreSeedAddr != strNewAddr,
                       "the visible address stops being the pre-seed one") ? 0 : 1;
        nFail += Check(mapAddressBook.count(strPreSeedAddr) > 0 &&
                       mapAddressBook[strPreSeedAddr] !=
                           mapAddressBook[strNewAddr],
                       "the pre-seed address is kept, named apart from the new one") ? 0 : 1;

        std::vector<unsigned char> vchBefore = vchHDMaster;
        int nSchemaBefore = nHDKeySchema;
        unsigned int nCoinTypeBefore = nHDCoinType;
        nFail += Check(!SetHDSeedFromMnemonic("not a mnemonic at all", "", strError),
                       "an invalid phrase is refused") ? 0 : 1;
        nFail += Check(vchHDMaster == vchBefore,
                       "a refused phrase leaves the existing seed alone") ? 0 : 1;
        nFail += Check(nHDKeySchema == nSchemaBefore,
                       "a refused phrase leaves the derivation schema alone") ? 0 : 1;
        nFail += Check(nHDCoinType == nCoinTypeBefore,
                       "a refused phrase leaves the BIP44 coin type alone") ? 0 : 1;

        // The property the whole feature exists for: the same words give back
        // the same keys, in the same order.
        std::vector<std::string> first;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            first.push_back(HexStrLocal(key.GetPubKey()));
        }

        SetHDSeedFromMnemonic(strPhraseA, "", strError);
        std::vector<std::string> again;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            again.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(first == again,
                       "the same phrase derives the same keys in the same order") ? 0 : 1;

        SetHDSeedFromMnemonic(strPhraseB, "", strError);
        std::vector<std::string> other;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            other.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(first != other, "a different phrase derives different keys") ? 0 : 1;

        // The BIP39 passphrase has to reach the seed, not merely be accepted.
        // If the plumbing dropped it the wallet would look identical and the
        // user would believe coins were protected by something that was never
        // applied -- so this compares derived keys, not return codes.
        SetHDSeedFromMnemonic(strPhraseA, "correcthorsebatterystaple", strError);
        std::vector<std::string> withPass;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            withPass.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(first != withPass,
                       "the same phrase with a passphrase derives different keys") ? 0 : 1;

        SetHDSeedFromMnemonic(strPhraseA, "correcthorsebatterystaple", strError);
        std::vector<std::string> withPassAgain;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            withPassAgain.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(withPass == withPassAgain,
                       "the same phrase and passphrase derive the same keys") ? 0 : 1;

        // One character off is a different wallet, silently. This is the shape
        // of the mistake that loses coins, so it is worth a test of its own.
        SetHDSeedFromMnemonic(strPhraseA, "correcthorsebatterystapl", strError);
        std::vector<std::string> nearMiss;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            nearMiss.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(withPass != nearMiss,
                       "a passphrase off by one character is a different wallet") ? 0 : 1;

        SetHDSeedFromMnemonic(strPhraseA, "", strError);

        std::set<std::string> distinct(first.begin(), first.end());
        nFail += Check(distinct.size() == first.size(),
                       "consecutive indices give distinct keys") ? 0 : 1;

        // With a seed installed the pool must be derived from it, and the
        // counter must move exactly once per key.
        SetHDSeedFromMnemonic(strPhraseA, "", strError);
        unsigned int nReceiveNextBefore = nHDReceiveNext;
        TopUpKeyPool();

        int nPool = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPool = (int)mapKeyPool.size();
        nFail += Check(nPool == KEYPOOL_SIZE, "the derived pool fills") ? 0 : 1;
        nFail += Check(nHDReceiveNext == nReceiveNextBefore + (unsigned int)KEYPOOL_SIZE,
                       "the BIP44 receive counter advances once per pooled key") ? 0 : 1;
        nFail += Check(nHDChangeNext == 0,
                       "filling the receive pool leaves the BIP44 change counter alone") ? 0 : 1;
        nFail += Check(!RestoreScanReachedDepth(HD_SCHEMA_BIP44, 600, 400, 600, 600),
                       "BIP44 restore depth is not satisfied by receive plus legacy alone") ? 0 : 1;
        nFail += Check(RestoreScanReachedDepth(HD_SCHEMA_BIP44, 600, 600, 600, 600),
                       "BIP44 restore depth is satisfied on each branch") ? 0 : 1;
        nFail += Check(RestoreScanReachedDepth(HD_SCHEMA_LEGACY, 0, 0, 600, 600),
                       "legacy restore depth still follows the legacy counter") ? 0 : 1;

        std::set<std::string> derived;
        for (unsigned int i = nReceiveNextBefore; i < nHDReceiveNext; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            derived.insert(HexStrLocal(key.GetPubKey()));
        }

        bool fStored = true;
        bool fFromSeed = true;
        CRITICAL_BLOCK(cs_keyPool)
        {
            for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
                 mi != mapKeyPool.end(); ++mi)
            {
                if (!WalletHasPrivateKey(mi->second))
                    fStored = false;
                if (!derived.count(HexStrLocal(mi->second)))
                    fFromSeed = false;
            }
        }
        nFail += Check(fStored, "every derived pooled key is stored in wallet.dat") ? 0 : 1;
        nFail += Check(fFromSeed, "every pooled key came from the seed, not from chance") ? 0 : 1;

        // A recovery phrase is only useful if the wallet can tell the user
        // what today's spendable balance would actually come back from it.
        CKey keyAuditDerived;
        if (!DeriveHDKey(0, keyAuditDerived, strError))
            throw std::runtime_error("audit derivation failed: " + strError);
        CKey keyAuditChange;
        if (!DeriveHDChangeKey(0, keyAuditChange, strError))
            throw std::runtime_error("audit change derivation failed: " + strError);
        nFail += Check(keyAuditChange.GetPubKey() != keyAuditDerived.GetPubKey(),
                       "BIP44 receive and change chains derive different keys") ? 0 : 1;
        if (!AddKey(keyAuditChange))
            throw std::runtime_error("could not store the audit change key");
        nHDChangeNext = 1;
        int nSchemaForLegacyAudit = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        CKey keyAuditLegacyHD;
        if (!DeriveHDKey(0, keyAuditLegacyHD, strError))
            throw std::runtime_error("audit legacy compatibility derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyAudit;
        if (!AddKey(keyAuditLegacyHD))
            throw std::runtime_error("could not store the audit legacy compatibility key");
        nHDNext = 1;

        CWalletTx wtxLegacy;
        wtxLegacy.vout.push_back(CTxOut(5 * COIN, CScript() << vchPreSeedKey << OP_CHECKSIG));
        CWalletTx wtxDerived;
        wtxDerived.vout.push_back(CTxOut(7 * COIN, CScript() << keyAuditDerived.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxChange;
        wtxChange.vout.push_back(CTxOut(13 * COIN, CScript() << keyAuditChange.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxLegacyHD;
        wtxLegacyHD.vout.push_back(CTxOut(17 * COIN, CScript() << keyAuditLegacyHD.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxImmatureLegacy;
        wtxImmatureLegacy.vin.push_back(CTxIn());
        wtxImmatureLegacy.vout.push_back(CTxOut(11 * COIN, CScript() << vchPreSeedKey << OP_CHECKSIG));

        CRITICAL_BLOCK(cs_mapWallet)
        {
            mapWallet.clear();
            mapWallet[wtxLegacy.GetHash()] = wtxLegacy;
            mapWallet[wtxDerived.GetHash()] = wtxDerived;
            mapWallet[wtxChange.GetHash()] = wtxChange;
            mapWallet[wtxLegacyHD.GetHash()] = wtxLegacyHD;
            mapWallet[wtxImmatureLegacy.GetHash()] = wtxImmatureLegacy;
        }

        WalletRecoveryAudit audit = GetWalletRecoveryAudit();
        nFail += Check(audit.fHaveSeed, "the recovery audit reports the phrase") ? 0 : 1;
        nFail += Check(audit.nSchema == HD_SCHEMA_BIP44,
                       "the recovery audit reports the derivation schema") ? 0 : 1;
        nFail += Check(audit.nCoinType == HD_BIP44_COIN_TYPE_BITFLASH,
                       "the recovery audit reports the BIP44 coin type") ? 0 : 1;
        nFail += Check(audit.nReceiveNext == nHDReceiveNext && audit.nChangeNext == 1,
                       "the recovery audit reports receive/change counters") ? 0 : 1;
        nFail += Check(audit.nLegacyCredit == 5 * COIN,
                       "the recovery audit finds wallet.dat-only balance") ? 0 : 1;
        nFail += Check(audit.nRecoverableCredit == 37 * COIN,
                       "the recovery audit finds BIP44 and legacy-HD phrase balance") ? 0 : 1;
        nFail += Check(audit.nLegacyTx == 1 && audit.nRecoverableTx == 3,
                       "the recovery audit counts wallet.dat-only and phrase-backed transactions") ? 0 : 1;
        nFail += Check(audit.nLegacyImmatureCredit == 11 * COIN,
                       "the recovery audit finds wallet.dat-only immature mining rewards") ? 0 : 1;
        nFail += Check(audit.nLegacyImmatureTx == 1,
                       "the recovery audit counts wallet.dat-only immature mining rewards") ? 0 : 1;

        // A coinbase whose block lost a race. Maturity is measured in depth, and
        // an orphan sits at depth 0 forever, so the audit reported it exactly
        // like a reward two blocks from spendable. A miner watched 50 BTF sit
        // there for days and reported the maturity rule as broken; the rule was
        // fine, the reward was dead, and nothing said so.
        {
            CWalletTx wtxOrphanCoinbase;
            wtxOrphanCoinbase.vin.push_back(CTxIn());
            wtxOrphanCoinbase.vout.push_back(
                CTxOut(50 * COIN, CScript() << keyAuditDerived.GetPubKey() << OP_CHECKSIG));
            // Anchored to a block this node knows and has NOT built on: pnext is
            // null and it is not pindexBest, so IsInMainChain() is false.
            uint256 hashOrphanBlock = wtxOrphanCoinbase.GetHash();
            wtxOrphanCoinbase.hashBlock = hashOrphanBlock;
            wtxOrphanCoinbase.nIndex = 0;
            CBlockIndex* pindexOrphan = new CBlockIndex();
            mapBlockIndex[hashOrphanBlock] = pindexOrphan;

            uint256 hashOrphanTx = wtxOrphanCoinbase.GetHash();
            CRITICAL_BLOCK(cs_mapWallet)
                mapWallet[hashOrphanTx] = wtxOrphanCoinbase;

            WalletRecoveryAudit orphanAudit = GetWalletRecoveryAudit();
            nFail += Check(orphanAudit.nOrphanedImmatureCredit == 50 * COIN &&
                           orphanAudit.nOrphanedImmatureTx == 1,
                           "the audit separates a coinbase whose block is not in the main chain") ? 0 : 1;
            nFail += Check(orphanAudit.nRecoverableImmatureCredit == 50 * COIN,
                           "an orphaned coinbase still counts in the immature total it belongs to") ? 0 : 1;
            nFail += Check(orphanAudit.nUnanchoredImmatureCredit == 11 * COIN &&
                           orphanAudit.nUnanchoredImmatureTx == 1,
                           "a coinbase in no known block is reported apart from an orphaned one") ? 0 : 1;
            nFail += Check(orphanAudit.nSoonestMaturityBlocks == -1,
                           "nothing is reported as on its way to maturity when nothing is") ? 0 : 1;

            CRITICAL_BLOCK(cs_mapWallet)
                mapWallet.erase(hashOrphanTx);
            mapBlockIndex.erase(hashOrphanBlock);
            delete pindexOrphan;
        }

        CKey keyLegacyHD11;
        nSchemaForLegacyAudit = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        if (!DeriveHDKey(11, keyLegacyHD11, strError))
            throw std::runtime_error("legacy compatibility index 11 derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyAudit;
        if (!AddKey(keyLegacyHD11))
            throw std::runtime_error("could not store the legacy compatibility index 11 key");

        std::map<unsigned int, std::vector<unsigned char> > mapLegacyProbe;
        mapLegacyProbe[0] = keyAuditLegacyHD.GetPubKey();
        mapLegacyProbe[11] = keyLegacyHD11.GetPubKey();

        CWalletTx wtxLegacyHD11;
        wtxLegacyHD11.vout.push_back(CTxOut(19 * COIN, CScript() << keyLegacyHD11.GetPubKey() << OP_CHECKSIG));
        CRITICAL_BLOCK(cs_mapWallet)
        {
            mapWallet.clear();
            mapWallet[wtxLegacyHD11.GetHash()] = wtxLegacyHD11;
        }
        nFail += Check(WalletLastUsedPubKeyIndexNext(mapLegacyProbe) == 12,
                       "restore collapses legacy hdnext to the last used compatibility index plus one") ? 0 : 1;

        CRITICAL_BLOCK(cs_mapWallet)
            mapWallet.clear();
        nFail += Check(WalletLastUsedPubKeyIndexNext(mapLegacyProbe) == 0,
                       "restore does not persist legacy hdnext at the scan depth when no compatibility key was used") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunWalletFormatSelfTest()
{
    fflush(stdout);
    printf("wallet-format self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        class CWalletDBRaw : public CWalletDB
        {
        public:
            CWalletDBRaw(const char* pszMode="r+") : CWalletDB(pszMode) { }
            bool WriteStringRecord(const string& strType, int nValue)
            {
                return Write(strType, nValue);
            }
            bool EraseStringRecord(const string& strType)
            {
                return Erase(strType);
            }
        };

        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        {
            CWalletDB walletdb;
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_SUPPORTED),
                           "the current wallet format marker can be written") ? 0 : 1;
        }

        std::vector<unsigned char> vchDefaultKey;
        nFail += Check(CWalletDB("r").LoadWallet(vchDefaultKey),
                       "the current wallet format marker loads") ? 0 : 1;

        {
            CWalletDBRaw walletdb;
            nFail += Check(walletdb.WriteStringRecord("mkey", 1),
                           "a malformed encrypted master-key record can be written") ? 0 : 1;
        }

        vchDefaultKey.clear();
        nFail += Check(!CWalletDB("r").LoadWallet(vchDefaultKey),
                       "a malformed encrypted master-key record is refused") ? 0 : 1;

        {
            CWalletDBRaw walletdb;
            nFail += Check(walletdb.EraseStringRecord("mkey"),
                           "the malformed encrypted master-key record can be removed") ? 0 : 1;
        }

        {
            CWalletDB walletdb;
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_SUPPORTED + 1),
                           "a future wallet format marker can be written") ? 0 : 1;
        }

        vchDefaultKey.clear();
        nFail += Check(!CWalletDB("r").LoadWallet(vchDefaultKey),
                       "a future wallet format marker is refused") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static bool FileContainsText(const string& strPath, const string& strNeedle);
static bool MakeDirLocal(const string& strPath);
static int RunBitflashChild(const string& strExe,
                            const vector<string>& vArgs,
                            const string* pStdinFile,
                            const string* pOutputFile);

class CWalletStorageSanityRawDB : public CWalletDB
{
public:
    CWalletStorageSanityRawDB(const char* pszMode="r+")
        : CWalletDB(pszMode) { }

    bool WriteUnknownRecord()
    {
        return Write(string("storage-sanity-unknown"), 1);
    }

    bool WriteMalformedKeyRecord()
    {
        if (!pdb)
            return false;
        unsigned char chKey = 0xff;
        unsigned char chValue = 0x01;
        Dbt datKey(&chKey, 1);
        Dbt datValue(&chValue, 1);
        return pdb->put(GetTxn(), &datKey, &datValue, 0) == 0;
    }

    bool MakePlainHDSeedIncomplete()
    {
        return Erase(string("hdchaincode"));
    }

    bool AddEncryptedMarkerToPlainWallet()
    {
        CWalletMasterKey kMasterKey;
        kMasterKey.vchCryptedKey.resize(48);
        for (size_t i = 0; i < kMasterKey.vchCryptedKey.size(); i++)
            kMasterKey.vchCryptedKey[i] = (unsigned char)(0x80 + (i & 0x3f));
        for (size_t i = 0; i < kMasterKey.vchSalt.size(); i++)
            kMasterKey.vchSalt[i] = (unsigned char)(0x40 + i);
        return WriteWalletMinVersion(WALLET_FORMAT_ENCRYPTED) &&
               WriteMasterKey(1, kMasterKey);
    }
};

static const char* SELFTEST_MUTATE_WALLET_MARKER =
    ".bitflash-selftest-wallet-mutate-ok";
static const char* SELFTEST_MUTATE_WALLET_MARKER_TEXT =
    "bitflash destructive wallet storage self-test\n";

static string SelfTestMutationMarkerPath()
{
    return GetAppDir() + "/" + SELFTEST_MUTATE_WALLET_MARKER;
}

static bool WriteSelfTestMutationMarker(const string& strDir)
{
    string strPath = strDir + "/" + SELFTEST_MUTATE_WALLET_MARKER;
    FILE* pf = fopen(strPath.c_str(), "wb");
    if (!pf)
        return false;
    bool fOk = fwrite(SELFTEST_MUTATE_WALLET_MARKER_TEXT, 1,
                      strlen(SELFTEST_MUTATE_WALLET_MARKER_TEXT), pf) ==
               strlen(SELFTEST_MUTATE_WALLET_MARKER_TEXT);
    if (fclose(pf) != 0)
        fOk = false;
    return fOk;
}

int RunSelfTestMutateWallet(const std::string& name)
{
    if (!FileContainsText(SelfTestMutationMarkerPath(),
                          SELFTEST_MUTATE_WALLET_MARKER_TEXT))
    {
        fprintf(stderr, "Refusing destructive wallet storage mutation outside "
                        "a marked self-test datadir.\n");
        return 1;
    }

    bool fOk = false;
    try
    {
        CWalletStorageSanityRawDB walletdb;
        if (name == "unknown-record")
            fOk = walletdb.WriteUnknownRecord();
        else if (name == "malformed-key")
            fOk = walletdb.WriteMalformedKeyRecord();
        else if (name == "incomplete-plain-hd")
            fOk = walletdb.MakePlainHDSeedIncomplete();
        else if (name == "encrypted-marker-with-plain-keys")
            fOk = walletdb.AddEncryptedMarkerToPlainWallet();
        else
        {
            fprintf(stderr, "Unknown wallet storage mutation '%s'\n", name.c_str());
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Cannot mutate wallet storage: %s\n", e.what());
        return 1;
    }
    catch (...)
    {
        fprintf(stderr, "Cannot mutate wallet storage: unknown exception\n");
        return 1;
    }

    DBFlush(true);
    return fOk ? 0 : 1;
}

static int RunWalletStorageSanitySelfTest()
{
    fflush(stdout);
    printf("wallet-storage-sanity self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif

        struct StorageScenario
        {
            const char* pszName;
            const char* pszExpectedFailure;
        };

        StorageScenario scenarios[] = {
            { "unknown-record", "wallet.dat contains unknown records" },
            { "malformed-key", "wallet.dat contains malformed records" },
            { "incomplete-plain-hd", "plain HD seed is incomplete" },
            { "encrypted-marker-with-plain-keys",
              "encrypted wallet still contains plain private key records" },
        };

        for (size_t i = 0; i < sizeof(scenarios)/sizeof(scenarios[0]); i++)
        {
            string strScenarioDir = tmp + "/" + scenarios[i].pszName;
            nFail += Check(MakeDirLocal(strScenarioDir),
                           "scenario datadir can be created") ? 0 : 1;

            string strCreateOut = tmp + "/" + scenarios[i].pszName + "-create.txt";
            vector<string> vCreateArgs;
            vCreateArgs.push_back("-datadir=" + strScenarioDir);
            vCreateArgs.push_back("-nomanagedtor");
            vCreateArgs.push_back("-nogui");
            vCreateArgs.push_back("-walletbackend=bdb");   // this suite is about wallet.dat
            vCreateArgs.push_back("-newphrase");
            int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
            nFail += Check(nCreateRet == 0 &&
                           FileContainsText(strCreateOut, "Write these twelve words down"),
                           "scenario phrase wallet can be created") ? 0 : 1;

            if (i == 0)
            {
                string strBlockedOut = tmp + "/" + scenarios[i].pszName + "-blocked-mutate.txt";
                vector<string> vBlockedArgs;
                vBlockedArgs.push_back("-datadir=" + strScenarioDir);
                vBlockedArgs.push_back("-nomanagedtor");
                vBlockedArgs.push_back("-nogui");
                vBlockedArgs.push_back("-selftestmutatewallet=" + string(scenarios[i].pszName));
                int nBlockedRet = RunBitflashChild(strExe, vBlockedArgs, NULL, &strBlockedOut);
                nFail += Check(nBlockedRet != 0 &&
                               FileContainsText(strBlockedOut, "Refusing destructive wallet storage mutation"),
                               "wallet mutation helper is blocked without marker") ? 0 : 1;
            }

            nFail += Check(WriteSelfTestMutationMarker(strScenarioDir),
                           "scenario mutation marker can be written") ? 0 : 1;

            string strMutateOut = tmp + "/" + scenarios[i].pszName + "-mutate.txt";
            vector<string> vMutateArgs;
            vMutateArgs.push_back("-datadir=" + strScenarioDir);
            vMutateArgs.push_back("-nomanagedtor");
            vMutateArgs.push_back("-nogui");
            vMutateArgs.push_back("-selftestmutatewallet=" + string(scenarios[i].pszName));
            int nMutateRet = RunBitflashChild(strExe, vMutateArgs, NULL, &strMutateOut);
            nFail += Check(nMutateRet == 0, scenarios[i].pszName) ? 0 : 1;

            string strCheckOut = tmp + "/" + scenarios[i].pszName + "-check.txt";
            vector<string> vCheckArgs;
            vCheckArgs.push_back("-datadir=" + strScenarioDir);
            vCheckArgs.push_back("-nomanagedtor");
            vCheckArgs.push_back("-nogui");
            vCheckArgs.push_back("-walletstoragecheck");
            int nCheckRet = RunBitflashChild(strExe, vCheckArgs, NULL, &strCheckOut);
            nFail += Check(nCheckRet == 2 &&
                           FileContainsText(strCheckOut, "storage sanity:            failed") &&
                           FileContainsText(strCheckOut, scenarios[i].pszExpectedFailure),
                           scenarios[i].pszExpectedFailure) ? 0 : 1;
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// A Berkeley DB file that cannot be opened. The C++ API throws DbException
// for it; CDB used to look only at the return value, so the Db handle leaked
// and the file's use count stayed up for good (DBFlush then never closed that
// file again). fuzz-net-message found it: every "inv" opens blkindex.dat.
static int RunDbOpenFailureSelfTest()
{
    fflush(stdout);
    printf("db-open-failure self-test\n");
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    int nFail = 0;
    std::string strOldDataDir = strSetDataDir;
    strSetDataDir = tmp;
    try
    {
        int nThrown = 0, nOther = 0;
        for (int i = 0; i < 200; i++)
        {
            try { CTxDB txdb("r"); }
            catch (const std::runtime_error&) { nThrown++; }
            catch (...) { nOther++; }
        }
        nFail += Check(nThrown == 200 && nOther == 0,
                       "a missing database file fails as runtime_error, every time") ? 0 : 1;
        nFail += Check(DbFileUseCount("blkindex.dat") == 0,
                       "a failed open leaves no use count behind") ? 0 : 1;
        nFail += Check(FileExists((tmp + "/db.log").c_str()),
                       "the Berkeley DB error log is in the data directory") ? 0 : 1;
#ifndef _WIN32
        struct stat stLog;
        nFail += Check(stat((tmp + "/db.log").c_str(), &stLog) == 0 && (stLog.st_mode & 0777) == 0600,
                       "and only its owner can read it") ? 0 : 1;
#endif
        {
            CTxDB txdb("cr+");
            nFail += Check(DbFileUseCount("blkindex.dat") == 1, "an open file counts once") ? 0 : 1;
        }
        nFail += Check(DbFileUseCount("blkindex.dat") == 0, "and not after it closes") ? 0 : 1;
        bool fOpened = false;
        try { CTxDB txdb("r"); fOpened = true; } catch (...) { }
        nFail += Check(fOpened, "once created, the same file opens read-only") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    DBFlush(true);
    strSetDataDir = strOldDataDir;
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// OpenPrivateFile: the RPC cookie and the key dump are owner-only from the
// moment they exist, never fopen-then-chmod.
static int RunPrivateFileSelfTest()
{
    fflush(stdout);
    printf("private-file self-test\n");
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary directory\n");
        return 1;
    }
    int nFail = 0;
    std::string path = tmp + "/secret";
    FILE* f = OpenPrivateFile(path.c_str(), true);
    nFail += Check(f != NULL, "a new file opens") ? 0 : 1;
    if (f)
    {
        fputs("first\n", f);
        fclose(f);
    }
#ifndef _WIN32
    struct stat st;
    nFail += Check(stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600,
                   "it is created owner-only (0600)") ? 0 : 1;
#endif
    errno = 0;
    f = OpenPrivateFile(path.c_str(), true);
    nFail += Check(f == NULL && errno == EEXIST, "exclusive refuses an existing file") ? 0 : 1;
    if (f)
        fclose(f);
#ifndef _WIN32
    // Someone who opened the old file (left readable on purpose) keeps that
    // handle; it must never see what is written next. Holding it open also
    // keeps the old inode number from being reused for the new file.
    chmod(path.c_str(), 0644);
    ino_t inoOld = st.st_ino;
    FILE* fReader = fopen(path.c_str(), "r");
#endif
    f = OpenPrivateFile(path.c_str(), false);
    nFail += Check(f != NULL, "non-exclusive replaces an existing file") ? 0 : 1;
    if (f)
    {
        fputs("second\n", f);
        fclose(f);
    }
#ifndef _WIN32
    nFail += Check(stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600 && st.st_ino != inoOld,
                   "with a new owner-only file, not the old one reopened") ? 0 : 1;
    char bufOld[16] = {0};
    if (fReader)
    {
        if (!fgets(bufOld, sizeof(bufOld), fReader))
            bufOld[0] = 0;
        fclose(fReader);
    }
    nFail += Check(fReader != NULL && std::string(bufOld) == "first\n",
                   "a handle on the old file never sees the new contents") ? 0 : 1;
    std::string target = tmp + "/target";
    std::string link = tmp + "/link";
    FILE* t = OpenPrivateFile(target.c_str(), true);
    if (t)
    {
        fputs("keep\n", t);
        fclose(t);
    }
    nFail += Check(symlink(target.c_str(), link.c_str()) == 0, "a symlink for the next checks") ? 0 : 1;
    errno = 0;
    f = OpenPrivateFile(link.c_str(), true);
    nFail += Check(f == NULL, "exclusive refuses a symlink") ? 0 : 1;
    if (f)
        fclose(f);
    f = OpenPrivateFile(link.c_str(), false);
    if (f)
        fclose(f);
    char buf[16] = {0};
    t = fopen(target.c_str(), "r");
    if (t)
    {
        if (!fgets(buf, sizeof(buf), t))
            buf[0] = 0;
        fclose(t);
    }
    nFail += Check(std::string(buf) == "keep\n", "replacing a symlink never writes through it") ? 0 : 1;
#endif
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunDbEnvReopenSelfTest()
{
    fflush(stdout);
    printf("db-env-reopen self-test\n");

    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }

    int nFail = 0;
    std::string strOldDataDir = strSetDataDir;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        for (int i = 0; i < 5; i++)
        {
            int64 nValue = 1000 + i;
            {
                CWalletDB walletdb("cr+");
                nFail += Check(walletdb.WriteSetting("db-env-reopen-cycle", nValue),
                               "wallet setting can be written before shutdown") ? 0 : 1;
            }

            DBFlush(true);

            int64 nRead = 0;
            {
                CWalletDB walletdb("r");
                nFail += Check(walletdb.ReadSetting("db-env-reopen-cycle", nRead),
                               "wallet setting can be read after env reopen") ? 0 : 1;
            }
            nFail += Check(nRead == nValue,
                           "reopened environment reads the last committed value") ? 0 : 1;

            DBFlush(true);
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    strSetDataDir = strOldDataDir;
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunWalletSQLiteSelfTest()
{
    fflush(stdout);
    printf("wallet-sqlite self-test\n");

    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }

    int nFail = 0;
    string strPath = tmp + "/wallet.sqlite";
    string strError;
    string strOldRuntimeDataDir;
    bool fRestoreRuntimeDataDir = false;

    try
    {
        CDataStream ssKeySetting(SER_DISK);
        ssKeySetting << make_pair(string("setting"), string("sqlite-roundtrip"));
        CDataStream ssValueSetting(SER_DISK);
        ssValueSetting << (int64)424242;

        vector<unsigned char> vchPubKey;
        vchPubKey.push_back(0x04);
        for (int i = 0; i < 64; i++)
            vchPubKey.push_back((unsigned char)i);
        CDataStream ssKeyDefault(SER_DISK);
        ssKeyDefault << string("defaultkey");
        CDataStream ssValueDefault(SER_DISK);
        ssValueDefault << vchPubKey;

        {
            CWalletDBSQLite db;
            nFail += Check(db.Open(strPath, strError),
                           "SQLite wallet opens and creates schema") ? 0 : 1;
            nFail += Check(db.BeginTransaction(strError),
                           "SQLite wallet begins a write transaction") ? 0 : 1;
            nFail += Check(db.WriteRecord(DataStreamBytes(ssKeySetting),
                                          DataStreamBytes(ssValueSetting),
                                          strError),
                           "SQLite wallet writes a serialized setting record") ? 0 : 1;
            nFail += Check(db.WriteRecord(DataStreamBytes(ssKeyDefault),
                                          DataStreamBytes(ssValueDefault),
                                          strError),
                           "SQLite wallet writes a serialized defaultkey record") ? 0 : 1;
            nFail += Check(db.CommitTransaction(strError),
                           "SQLite wallet commits a write transaction") ? 0 : 1;
            int nCount = 0;
            nFail += Check(db.CountRecords(nCount, strError) && nCount == 2,
                           "SQLite wallet counts raw records") ? 0 : 1;
        }

        {
            CWalletDBSQLite db;
            nFail += Check(db.Open(strPath, strError),
                           "SQLite wallet reopens") ? 0 : 1;
            vector<unsigned char> vchRead;
            nFail += Check(db.ReadRecord(DataStreamBytes(ssKeySetting),
                                         vchRead,
                                         strError),
                           "SQLite wallet reads a serialized setting record") ? 0 : 1;
            int64 nReadValue = 0;
            CDataStream ssRead(vchRead, SER_DISK);
            ssRead >> nReadValue;
            nFail += Check(!ssRead.fail() && nReadValue == 424242,
                           "SQLite wallet preserves serialized values byte-for-byte") ? 0 : 1;

            vchRead.clear();
            nFail += Check(db.ReadRecord(DataStreamBytes(ssKeyDefault),
                                         vchRead,
                                         strError),
                           "SQLite wallet reads a serialized defaultkey record") ? 0 : 1;
            vector<unsigned char> vchReadPubKey;
            CDataStream ssReadDefault(vchRead, SER_DISK);
            ssReadDefault >> vchReadPubKey;
            nFail += Check(!ssReadDefault.fail() && vchReadPubKey == vchPubKey,
                           "SQLite wallet preserves public key blobs") ? 0 : 1;
        }

        {
            CWalletDBSQLite db;
            nFail += Check(db.Open(strPath, strError),
                           "SQLite wallet reopens for typed records") ? 0 : 1;

            nFail += Check(db.WriteTypedRecord(make_pair(string("setting"),
                                                         string("sqlite-typed")),
                                               (int64)777, strError),
                           "SQLite wallet writes a typed setting record") ? 0 : 1;

            int64 nTypedRead = 0;
            nFail += Check(db.ReadTypedRecord(make_pair(string("setting"),
                                                        string("sqlite-typed")),
                                              nTypedRead, strError) &&
                           nTypedRead == 777,
                           "SQLite wallet reads a typed setting record") ? 0 : 1;

            nFail += Check(!db.WriteTypedRecord(make_pair(string("setting"),
                                                          string("sqlite-typed")),
                                                (int64)888, strError, false),
                           "SQLite wallet refuses typed overwrite when asked") ? 0 : 1;

            nTypedRead = 0;
            nFail += Check(db.ReadTypedRecord(make_pair(string("setting"),
                                                        string("sqlite-typed")),
                                              nTypedRead, strError) &&
                           nTypedRead == 777,
                           "SQLite wallet preserves the old typed value after overwrite refusal") ? 0 : 1;

            nFail += Check(db.EraseTypedRecord(make_pair(string("setting"),
                                                         string("sqlite-typed")),
                                               strError),
                           "SQLite wallet erases a typed record") ? 0 : 1;

            nTypedRead = 0;
            nFail += Check(!db.ReadTypedRecord(make_pair(string("setting"),
                                                         string("sqlite-typed")),
                                               nTypedRead, strError),
                           "SQLite wallet typed erase removes the record") ? 0 : 1;

            nFail += Check(db.WriteTypedRecord(string("defaultkey"), vchPubKey,
                                               strError),
                           "SQLite wallet writes a typed defaultkey record") ? 0 : 1;

            vector<unsigned char> vchTypedPubKey;
            nFail += Check(db.ReadTypedRecord(string("defaultkey"), vchTypedPubKey,
                                              strError) &&
                           vchTypedPubKey == vchPubKey,
                           "SQLite wallet reads a typed defaultkey record") ? 0 : 1;
        }

        {
            string strRuntimePath = tmp + "/runtime-wallet.sqlite";
            string strRuntimeDir = tmp + "/runtime-datadir";
            nFail += Check(MakeDirLocal(strRuntimeDir),
                           "SQLite runtime datadir can be created") ? 0 : 1;

            {
                CWalletDBSQLite db;
                nFail += Check(db.Open(strRuntimePath, strError),
                               "SQLite runtime wallet file can be created") ? 0 : 1;
            }

            string strOldDataDir = strSetDataDir;
            strSetDataDir = strRuntimeDir;
            strOldRuntimeDataDir = strOldDataDir;
            fRestoreRuntimeDataDir = true;
            bool fRuntimeOpened = WalletSQLiteRuntimeOpen(strRuntimePath, strError);
            nFail += Check(fRuntimeOpened,
                           "SQLite runtime wallet can be activated") ? 0 : 1;

            if (fRuntimeOpened)
            {
                CKey key;
                key.MakeNewKey();
                vector<unsigned char> vchRuntimePubKey = key.GetPubKey();
                CPrivKey vchRuntimePrivKey = key.GetPrivKey();
                string strRuntimeAddress = PubKeyToAddress(vchRuntimePubKey);

                nFail += Check(CWalletDB().WriteSetting("runtime-sqlite-setting",
                                                        (int64)909090) &&
                               CWalletDB().WriteDefaultKey(vchRuntimePubKey) &&
                               CWalletDB().WriteKey(vchRuntimePubKey,
                                                    vchRuntimePrivKey) &&
                               CWalletDB().WriteName(strRuntimeAddress,
                                                     "SQLite Runtime Address"),
                               "CWalletDB writes route to active SQLite runtime") ? 0 : 1;

                int64 nRuntimeSetting = 0;
                vector<unsigned char> vchRuntimeDefaultKey;
                CPrivKey vchRuntimeReadPrivKey;
                string strRuntimeName;
                nFail += Check(CWalletDB("r").ReadSetting("runtime-sqlite-setting",
                                                          nRuntimeSetting) &&
                               nRuntimeSetting == 909090 &&
                               CWalletDB("r").ReadDefaultKey(vchRuntimeDefaultKey) &&
                               vchRuntimeDefaultKey == vchRuntimePubKey &&
                               CWalletDB("r").ReadKey(vchRuntimePubKey,
                                                      vchRuntimeReadPrivKey) &&
                               vchRuntimeReadPrivKey == vchRuntimePrivKey &&
                               CWalletDB("r").ReadName(strRuntimeAddress,
                                                       strRuntimeName) &&
                               strRuntimeName == "SQLite Runtime Address",
                               "CWalletDB reads route to active SQLite runtime") ? 0 : 1;

                nFail += Check(CWalletDB().EraseName(strRuntimeAddress) &&
                               !CWalletDB("r").ReadName(strRuntimeAddress,
                                                        strRuntimeName),
                               "CWalletDB erases route to active SQLite runtime") ? 0 : 1;

                nFail += Check(!FileExists((strRuntimeDir + "/wallet.dat").c_str()),
                               "active SQLite runtime does not create wallet.dat") ? 0 : 1;

                // Transaction bracket: a rolled-back group leaves nothing, a
                // committed group persists. This is the all-or-nothing that
                // WriteHDMaster relies on so a half-written seed cannot survive
                // a failure between its two records.
                bool fTxnBegan = WalletSQLiteRuntimeBeginTxn();
                bool fTxnWrote = fTxnBegan &&
                    CWalletDB().WriteSetting("runtime-txn-rollback", (int64)111);
                if (fTxnBegan)
                    WalletSQLiteRuntimeRollbackTxn();
                nFail += Check(fTxnBegan && fTxnWrote,
                               "a SQLite runtime transaction opens and rolls back") ? 0 : 1;
                int64 nRolledBack = 0;
                nFail += Check(!CWalletDB("r").ReadSetting("runtime-txn-rollback",
                                                           nRolledBack),
                               "a rolled-back SQLite runtime write leaves no record") ? 0 : 1;

                bool fCommitOk = WalletSQLiteRuntimeBeginTxn() &&
                    CWalletDB().WriteSetting("runtime-txn-commit", (int64)222) &&
                    WalletSQLiteRuntimeCommitTxn();
                int64 nCommitted = 0;
                nFail += Check(fCommitOk &&
                               CWalletDB("r").ReadSetting("runtime-txn-commit",
                                                          nCommitted) &&
                               nCommitted == 222,
                               "a committed SQLite runtime write persists") ? 0 : 1;

                // WriteHDMaster brackets its two records in that transaction;
                // both halves of the seed must land.
                vector<unsigned char> vchTxnMaster(32, 0x5a);
                vector<unsigned char> vchTxnChainCode(32, 0xa5);
                vector<unsigned char> vchReadMaster, vchReadChainCode;
                nFail += Check(CWalletDB().WriteHDMaster(vchTxnMaster, vchTxnChainCode) &&
                               CWalletDB("r").ReadHDMaster(vchReadMaster, vchReadChainCode) &&
                               vchReadMaster == vchTxnMaster &&
                               vchReadChainCode == vchTxnChainCode,
                               "WriteHDMaster commits both halves of the seed under SQLite") ? 0 : 1;

                // Durability: close the backend (checkpoints the WAL), reopen
                // the same file, and confirm what CWalletDB wrote is still
                // there. This is the write-survives-a-restart property the real
                // -walletbackend=sqlite node depends on.
                WalletSQLiteRuntimeClose();
                bool fReopened =
                    WalletSQLiteRuntimeOpen(strRuntimePath, strError);
                nFail += Check(fReopened,
                               "SQLite runtime wallet reopens after close") ? 0 : 1;
                if (fReopened)
                {
                    int64 nPersisted = 0;
                    CPrivKey vchPersistedPrivKey;
                    vector<unsigned char> vchPersistedDefaultKey;
                    nFail += Check(CWalletDB("r").ReadSetting("runtime-sqlite-setting",
                                                              nPersisted) &&
                                   nPersisted == 909090 &&
                                   CWalletDB("r").ReadDefaultKey(vchPersistedDefaultKey) &&
                                   vchPersistedDefaultKey == vchRuntimePubKey &&
                                   CWalletDB("r").ReadKey(vchRuntimePubKey,
                                                          vchPersistedPrivKey) &&
                                   vchPersistedPrivKey == vchRuntimePrivKey,
                                   "SQLite runtime writes persist across a close and reopen") ? 0 : 1;
                }
            }

            WalletSQLiteRuntimeClose();
            strSetDataDir = strOldDataDir;
            fRestoreRuntimeDataDir = false;
        }
    }
    catch (const std::exception& e)
    {
        WalletSQLiteRuntimeClose();
        if (fRestoreRuntimeDataDir)
            strSetDataDir = strOldRuntimeDataDir;
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        WalletSQLiteRuntimeClose();
        if (fRestoreRuntimeDataDir)
            strSetDataDir = strOldRuntimeDataDir;
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

namespace {

class CWalletRecordMapVisitor : public CWalletRecordVisitor
{
public:
    std::map<vector<unsigned char>, vector<unsigned char> >& mapRecords;

    explicit CWalletRecordMapVisitor(
        std::map<vector<unsigned char>, vector<unsigned char> >& mapRecordsIn)
        : mapRecords(mapRecordsIn) { }

    bool VisitWalletRecord(const CDataStream& ssKey,
                           const CDataStream& ssValue,
                           string& strErrorRet)
    {
        vector<unsigned char> vchKey = DataStreamBytes(ssKey);
        if (mapRecords.count(vchKey))
        {
            strErrorRet = "duplicate serialized wallet key";
            return false;
        }
        mapRecords[vchKey] = DataStreamBytes(ssValue);
        return true;
    }
};

} // namespace

static bool CreateSQLiteWalletWithEmptyKey(const string& strPath)
{
    sqlite3* pdb = NULL;
    int ret = sqlite3_open_v2(strPath.c_str(), &pdb,
                              SQLITE_OPEN_READWRITE |
                              SQLITE_OPEN_CREATE |
                              SQLITE_OPEN_FULLMUTEX,
                              NULL);
    if (ret != SQLITE_OK || !pdb)
    {
        if (pdb)
            sqlite3_close(pdb);
        return false;
    }

    char* pszErr = NULL;
    bool fOk =
        sqlite3_exec(pdb,
                     "CREATE TABLE wallet_records ("
                     "key BLOB PRIMARY KEY NOT NULL,"
                     "value BLOB NOT NULL"
                     ");",
                     NULL, NULL, &pszErr) == SQLITE_OK &&
        sqlite3_exec(pdb,
                     "INSERT INTO wallet_records(key, value) "
                     "VALUES(x'', x'01');",
                     NULL, NULL, &pszErr) == SQLITE_OK;
    if (pszErr)
        sqlite3_free(pszErr);
    sqlite3_close(pdb);
    return fOk;
}

static bool CreateSQLiteWalletWithFutureMinVersion(const string& strPath)
{
    string strError;
    CWalletDBSQLite db;
    CDataStream ssKey(SER_DISK);
    ssKey << string("walletminversion");
    CDataStream ssValue(SER_DISK);
    ssValue << (WALLET_FORMAT_SUPPORTED + 1);

    if (!db.Open(strPath, strError))
        return false;
    if (!db.BeginTransaction(strError))
        return false;
    if (!db.WriteRecord(DataStreamBytes(ssKey), DataStreamBytes(ssValue), strError))
        return false;
    if (!db.CommitTransaction(strError))
        return false;
    if (!db.Checkpoint(strError))
        return false;
    return true;
}

static bool CreateTypedSQLiteWallet(const string& strPath)
{
    string strError;
    CWalletDBSQLite db;
    CKey key;
    key.MakeNewKey();

    vector<unsigned char> vchPubKey = key.GetPubKey();
    CPrivKey vchPrivKey = key.GetPrivKey();
    string strAddress = PubKeyToAddress(vchPubKey);

    if (!db.Open(strPath, strError))
        return false;
    if (!db.BeginTransaction(strError))
        return false;
    if (!db.WriteTypedRecord(make_pair(string("key"), vchPubKey),
                             vchPrivKey, strError, false))
        return false;
    if (!db.WriteTypedRecord(string("defaultkey"), vchPubKey, strError))
        return false;
    if (!db.WriteTypedRecord(make_pair(string("name"), strAddress),
                             string("Typed SQLite Address"), strError))
        return false;
    if (!db.CommitTransaction(strError))
        return false;
    if (!db.Checkpoint(strError))
        return false;
    return true;
}

static int RunWalletSQLiteMigrationSelfTest()
{
    fflush(stdout);
    printf("wallet-sqlite-migration self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strWalletDir = tmp + "/wallet";
        nFail += Check(MakeDirLocal(strWalletDir),
                       "temporary wallet directory can be created") ? 0 : 1;

        string strCreateOut = tmp + "/create.txt";
        vector<string> vCreateArgs;
        vCreateArgs.push_back("-datadir=" + strWalletDir);
        vCreateArgs.push_back("-nomanagedtor");
        vCreateArgs.push_back("-nogui");
        vCreateArgs.push_back("-walletbackend=bdb");   // migrate FROM a Berkeley DB wallet.dat
        vCreateArgs.push_back("-newphrase");
        int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
        nFail += Check(nCreateRet == 0 &&
                       FileContainsText(strCreateOut, "Write these twelve words down"),
                       "a phrase wallet can be created for SQLite export") ? 0 : 1;

        string strSQLite = tmp + "/wallet.sqlite";
        string strExportOut = tmp + "/sqlite-export.txt";
        vector<string> vExportArgs;
        vExportArgs.push_back("-datadir=" + strWalletDir);
        vExportArgs.push_back("-nomanagedtor");
        vExportArgs.push_back("-nogui");
        vExportArgs.push_back("-walletsqliteexport=" + strSQLite);
        int nExportRet = RunBitflashChild(strExe, vExportArgs, NULL, &strExportOut);
        nFail += Check(nExportRet == 0 &&
                       FileExists(strSQLite.c_str()) &&
                       FileContainsText(strExportOut, "SQLite wallet export written"),
                       "wallet.dat can be exported to SQLite") ? 0 : 1;

        string strVerifyOut = tmp + "/sqlite-verify.txt";
        vector<string> vVerifyArgs;
        vVerifyArgs.push_back("-datadir=" + strWalletDir);
        vVerifyArgs.push_back("-nomanagedtor");
        vVerifyArgs.push_back("-nogui");
        vVerifyArgs.push_back("-walletsqliteverify=" + strSQLite);
        int nVerifyRet = RunBitflashChild(strExe, vVerifyArgs, NULL, &strVerifyOut);
        nFail += Check(nVerifyRet == 0 &&
                       FileContainsText(strVerifyOut, "verification:              ok"),
                       "SQLite wallet export verifies against wallet.dat") ? 0 : 1;

        string strLoadCheckOut = tmp + "/sqlite-loadcheck.txt";
        vector<string> vLoadCheckArgs;
        vLoadCheckArgs.push_back("-datadir=" + strWalletDir);
        vLoadCheckArgs.push_back("-nomanagedtor");
        vLoadCheckArgs.push_back("-nogui");
        vLoadCheckArgs.push_back("-walletsqliteloadcheck=" + strSQLite);
        int nLoadCheckRet =
            RunBitflashChild(strExe, vLoadCheckArgs, NULL, &strLoadCheckOut);
        nFail += Check(nLoadCheckRet == 0 &&
                       FileContainsText(strLoadCheckOut,
                                        "load check:                ok"),
                       "SQLite wallet export passes the loader compatibility check") ? 0 : 1;

        string strRuntimeOut = tmp + "/sqlite-runtime.txt";
        vector<string> vRuntimeArgs;
        vRuntimeArgs.push_back("-datadir=" + strWalletDir);
        vRuntimeArgs.push_back("-nomanagedtor");
        vRuntimeArgs.push_back("-nogui");
        vRuntimeArgs.push_back("-walletsqlite=" + strSQLite);
        int nRuntimeRet =
            RunBitflashChild(strExe, vRuntimeArgs, NULL, &strRuntimeOut);
        nFail += Check(nRuntimeRet == 0 &&
                       FileContainsText(strRuntimeOut,
                                        "SQLite wallet loaded: read-only staging backend"),
                       "SQLite wallet export loads through the runtime startup path") ? 0 : 1;

        string strTypedSQLite = tmp + "/typed-wallet.sqlite";
        nFail += Check(CreateTypedSQLiteWallet(strTypedSQLite),
                       "typed SQLite wallet can be created without Berkeley DB") ? 0 : 1;

        string strTypedLoadCheckOut = tmp + "/sqlite-typed-loadcheck.txt";
        vector<string> vTypedLoadCheckArgs;
        vTypedLoadCheckArgs.push_back("-datadir=" + strWalletDir);
        vTypedLoadCheckArgs.push_back("-nomanagedtor");
        vTypedLoadCheckArgs.push_back("-nogui");
        vTypedLoadCheckArgs.push_back("-walletsqliteloadcheck=" + strTypedSQLite);
        int nTypedLoadCheckRet =
            RunBitflashChild(strExe, vTypedLoadCheckArgs, NULL,
                             &strTypedLoadCheckOut);
        nFail += Check(nTypedLoadCheckRet == 0 &&
                       FileContainsText(strTypedLoadCheckOut,
                                        "load check:                ok"),
                       "typed SQLite wallet passes the loader compatibility check") ? 0 : 1;

        string strTypedRuntimeDir = tmp + "/typed-runtime-wallet";
        nFail += Check(MakeDirLocal(strTypedRuntimeDir),
                       "typed SQLite runtime directory can be created") ? 0 : 1;
        string strTypedRuntimeOut = tmp + "/sqlite-typed-runtime.txt";
        vector<string> vTypedRuntimeArgs;
        vTypedRuntimeArgs.push_back("-datadir=" + strTypedRuntimeDir);
        vTypedRuntimeArgs.push_back("-nomanagedtor");
        vTypedRuntimeArgs.push_back("-nogui");
        vTypedRuntimeArgs.push_back("-walletsqlite=" + strTypedSQLite);
        int nTypedRuntimeRet =
            RunBitflashChild(strExe, vTypedRuntimeArgs, NULL,
                             &strTypedRuntimeOut);
        nFail += Check(nTypedRuntimeRet == 0 &&
                       FileContainsText(strTypedRuntimeOut,
                                        "SQLite wallet loaded: read-only staging backend") &&
                       !FileExists((strTypedRuntimeDir + "/wallet.dat").c_str()),
                       "typed SQLite wallet loads through runtime without creating wallet.dat") ? 0 : 1;

        string strRestoredDir = tmp + "/restored-wallet";
        nFail += Check(MakeDirLocal(strRestoredDir),
                       "restored wallet directory can be created") ? 0 : 1;
        string strRestoreOut = tmp + "/sqlite-restore.txt";
        vector<string> vRestoreArgs;
        vRestoreArgs.push_back("-datadir=" + strRestoredDir);
        vRestoreArgs.push_back("-nomanagedtor");
        vRestoreArgs.push_back("-nogui");
        vRestoreArgs.push_back("-walletsqliterestore=" + strSQLite);
        int nRestoreRet = RunBitflashChild(strExe, vRestoreArgs, NULL, &strRestoreOut);
        nFail += Check(nRestoreRet == 0 &&
                       FileContainsText(strRestoreOut, "records restored:"),
                       "SQLite wallet export restores into a fresh wallet.dat") ? 0 : 1;

        string strVerifyRestoredOut = tmp + "/sqlite-verify-restored.txt";
        vector<string> vVerifyRestoredArgs;
        vVerifyRestoredArgs.push_back("-datadir=" + strRestoredDir);
        vVerifyRestoredArgs.push_back("-nomanagedtor");
        vVerifyRestoredArgs.push_back("-nogui");
        vVerifyRestoredArgs.push_back("-walletsqliteverify=" + strSQLite);
        int nVerifyRestoredRet =
            RunBitflashChild(strExe, vVerifyRestoredArgs, NULL, &strVerifyRestoredOut);
        nFail += Check(nVerifyRestoredRet == 0 &&
                       FileContainsText(strVerifyRestoredOut,
                                        "verification:              ok"),
                       "restored wallet.dat verifies against the SQLite export") ? 0 : 1;

        string strRestoreOverwriteOut = tmp + "/sqlite-restore-overwrite.txt";
        int nRestoreOverwriteRet =
            RunBitflashChild(strExe, vRestoreArgs, NULL, &strRestoreOverwriteOut);
        nFail += Check(nRestoreOverwriteRet == 1 &&
                       FileContainsText(strRestoreOverwriteOut,
                                        "Refusing to overwrite existing wallet.dat"),
                       "SQLite wallet restore refuses to overwrite wallet.dat") ? 0 : 1;

        string strBadSQLite = tmp + "/bad-empty-key.sqlite";
        nFail += Check(CreateSQLiteWalletWithEmptyKey(strBadSQLite),
                       "bad SQLite export with an empty key can be created") ? 0 : 1;
        string strBadRestoreDir = tmp + "/bad-restore-wallet";
        nFail += Check(MakeDirLocal(strBadRestoreDir),
                       "bad restore wallet directory can be created") ? 0 : 1;
        string strBadRestoreOut = tmp + "/sqlite-restore-bad.txt";
        vector<string> vBadRestoreArgs;
        vBadRestoreArgs.push_back("-datadir=" + strBadRestoreDir);
        vBadRestoreArgs.push_back("-nomanagedtor");
        vBadRestoreArgs.push_back("-nogui");
        vBadRestoreArgs.push_back("-walletsqliterestore=" + strBadSQLite);
        int nBadRestoreRet =
            RunBitflashChild(strExe, vBadRestoreArgs, NULL, &strBadRestoreOut);
        nFail += Check(nBadRestoreRet == 1 &&
                       FileContainsText(strBadRestoreOut,
                                        "Cannot restore SQLite wallet export") &&
                       !FileExists((strBadRestoreDir + "/wallet.dat").c_str()),
                       "failed SQLite wallet restore removes incomplete wallet.dat") ? 0 : 1;

        string strFutureSQLite = tmp + "/future-wallet.sqlite";
        nFail += Check(CreateSQLiteWalletWithFutureMinVersion(strFutureSQLite),
                       "SQLite export with a future wallet format can be created") ? 0 : 1;
        string strFutureLoadCheckOut = tmp + "/sqlite-loadcheck-future.txt";
        vector<string> vFutureLoadCheckArgs;
        vFutureLoadCheckArgs.push_back("-datadir=" + strWalletDir);
        vFutureLoadCheckArgs.push_back("-nomanagedtor");
        vFutureLoadCheckArgs.push_back("-nogui");
        vFutureLoadCheckArgs.push_back("-walletsqliteloadcheck=" + strFutureSQLite);
        int nFutureLoadCheckRet =
            RunBitflashChild(strExe, vFutureLoadCheckArgs, NULL,
                             &strFutureLoadCheckOut);
        nFail += Check(nFutureLoadCheckRet == 2 &&
                       FileContainsText(strFutureLoadCheckOut,
                                        "unsupported future wallet format") &&
                       FileContainsText(strFutureLoadCheckOut,
                                        "load check:                failed"),
                       "SQLite wallet load check rejects future wallet formats") ? 0 : 1;

        string strFutureRuntimeOut = tmp + "/sqlite-runtime-future.txt";
        vector<string> vFutureRuntimeArgs;
        vFutureRuntimeArgs.push_back("-datadir=" + strWalletDir);
        vFutureRuntimeArgs.push_back("-nomanagedtor");
        vFutureRuntimeArgs.push_back("-nogui");
        vFutureRuntimeArgs.push_back("-walletsqlite=" + strFutureSQLite);
        int nFutureRuntimeRet =
            RunBitflashChild(strExe, vFutureRuntimeArgs, NULL,
                             &strFutureRuntimeOut);
        nFail += Check(nFutureRuntimeRet == 1 &&
                       FileContainsText(strFutureRuntimeOut,
                                        "Cannot open SQLite wallet export") &&
                       FileContainsText(strFutureRuntimeOut,
                                        "newer version of Bitflash"),
                       "SQLite runtime startup rejects future wallet formats") ? 0 : 1;

        string strOverwriteOut = tmp + "/sqlite-export-overwrite.txt";
        int nOverwriteRet =
            RunBitflashChild(strExe, vExportArgs, NULL, &strOverwriteOut);
        nFail += Check(nOverwriteRet != 0 &&
                       FileContainsText(strOverwriteOut,
                                        "Refusing to overwrite existing SQLite wallet export"),
                       "SQLite wallet export refuses to overwrite") ? 0 : 1;
        remove((strSQLite + "-wal").c_str());
        remove((strSQLite + "-shm").c_str());

        std::map<vector<unsigned char>, vector<unsigned char> > mapBDB;
        string strOldDataDir = strSetDataDir;
        string strScanError;
        strSetDataDir = strWalletDir;
        CWalletRecordMapVisitor visitor(mapBDB);
        bool fScanOk = ScanWalletRecords(visitor, strScanError);
        DBFlush(true);
        strSetDataDir = strOldDataDir;
        nFail += Check(fScanOk && !mapBDB.empty(),
                       "wallet.dat records can be scanned for comparison") ? 0 : 1;

        CWalletDBSQLite db;
        string strError;
        nFail += Check(db.Open(strSQLite, strError),
                       "exported SQLite wallet opens") ? 0 : 1;
        int nSQLiteRecords = 0;
        nFail += Check(db.CountRecords(nSQLiteRecords, strError) &&
                       nSQLiteRecords == (int)mapBDB.size(),
                       "SQLite export has the same record count as wallet.dat") ? 0 : 1;

        bool fAllMatch = true;
        for (std::map<vector<unsigned char>, vector<unsigned char> >::const_iterator it =
                 mapBDB.begin(); it != mapBDB.end(); ++it)
        {
            vector<unsigned char> vchSQLiteValue;
            if (!db.ReadRecord(it->first, vchSQLiteValue, strError) ||
                vchSQLiteValue != it->second)
            {
                fAllMatch = false;
                break;
            }
        }
        nFail += Check(fAllMatch,
                       "SQLite export preserves every wallet.dat key/value byte-for-byte") ? 0 : 1;

        std::map<vector<unsigned char>, vector<unsigned char> > mapSQLite;
        CWalletRecordMapVisitor sqliteVisitor(mapSQLite);
        nFail += Check(db.ScanRecords(sqliteVisitor, strError) &&
                       mapSQLite == mapBDB,
                       "SQLite wallet scanner streams every exported record byte-for-byte") ? 0 : 1;

        db.Close();
        CWalletDBSQLite dbCorrupt;
        vector<unsigned char> vchBadValue;
        vchBadValue.push_back(0xba);
        vchBadValue.push_back(0xad);
        nFail += Check(!mapBDB.empty() &&
                       dbCorrupt.Open(strSQLite, strError) &&
                       dbCorrupt.BeginTransaction(strError) &&
                       dbCorrupt.WriteRecord(mapBDB.begin()->first,
                                             vchBadValue,
                                             strError) &&
                       dbCorrupt.CommitTransaction(strError) &&
                       dbCorrupt.Checkpoint(strError),
                       "SQLite export can be deliberately corrupted for verifier test") ? 0 : 1;
        dbCorrupt.Close();

        string strVerifyBadOut = tmp + "/sqlite-verify-bad.txt";
        int nVerifyBadRet =
            RunBitflashChild(strExe, vVerifyArgs, NULL, &strVerifyBadOut);
        nFail += Check(nVerifyBadRet == 2 &&
                       FileContainsText(strVerifyBadOut,
                                        "record value mismatches:   1") &&
                       FileContainsText(strVerifyBadOut,
                                        "verification:              failed"),
                       "SQLite wallet verifier detects a mismatched record value") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static void ClearWalletRuntimeForTest()
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys.clear();
        mapCryptedKeys.clear();
        mapPubKeys.clear();
        mapMasterKeys.clear();
        vWalletMasterKey.clear();
        vchCryptedHDMaster.clear();
        vchCryptedHDChainCode.clear();
        fWalletEncrypted = false;
        fWalletLocked = true;
    }
    CRITICAL_BLOCK(cs_keyPool)
        mapKeyPool.clear();
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nHDNext = 0;
}

static int RunWalletCryptoSelfTest()
{
    fflush(stdout);
    printf("wallet-crypto self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        const string strPassphrase = "btf-test-passphrase";
        const string strWrongPassphrase = "btf-test-passphraser";

        CKey key;
        key.MakeNewKey();
        vector<unsigned char> vchPubKey = key.GetPubKey();
        CPrivKey vchPrivKey = key.GetPrivKey();

        CKeyingMaterial vchMasterKey;
        for (int i = 0; i < 32; i++)
            vchMasterKey.push_back((unsigned char)(i + 1));

        CWalletMasterKey kMasterKey;
        kMasterKey.vchSalt.clear();
        for (int i = 0; i < 8; i++)
            kMasterKey.vchSalt.push_back((unsigned char)(0xa0 + i));
        kMasterKey.nDeriveIterations = 2500;

        CKeyingMaterial vchPassKey;
        vector<unsigned char> vchPassIV;
        nFail += Check(DeriveWalletPassphraseKey(strPassphrase, kMasterKey.vchSalt,
                                                 kMasterKey.nDeriveIterations,
                                                 vchPassKey, vchPassIV),
                       "a passphrase key can be derived") ? 0 : 1;
        nFail += Check(EncryptSecret(vchPassKey,
                                     vector<unsigned char>(vchMasterKey.begin(), vchMasterKey.end()),
                                     vchPassIV, kMasterKey.vchCryptedKey),
                       "the wallet master key can be encrypted") ? 0 : 1;

        vector<unsigned char> vchCryptedKey;
        nFail += Check(EncryptSecret(vchMasterKey,
                                     vector<unsigned char>(vchPrivKey.begin(), vchPrivKey.end()),
                                     WalletKeyIV(vchPubKey), vchCryptedKey),
                       "a private key can be encrypted under the wallet master key") ? 0 : 1;

        {
            CWalletDB walletdb("cr");
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_ENCRYPTED),
                           "an encrypted wallet format marker can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteMasterKey(0, kMasterKey),
                           "the encrypted master key can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteCryptedKey(vchPubKey, vchCryptedKey),
                           "the encrypted private key can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteDefaultKey(vchPubKey),
                           "the encrypted wallet default key can be written") ? 0 : 1;
        }

        ClearWalletRuntimeForTest();

        vector<unsigned char> vchDefaultKey;
        nFail += Check(CWalletDB("r").LoadWallet(vchDefaultKey),
                       "an encrypted wallet can be loaded") ? 0 : 1;
        nFail += Check(vchDefaultKey == vchPubKey,
                       "the encrypted wallet default public key loads") ? 0 : 1;
        nFail += Check(IsWalletEncrypted() && IsWalletLocked(),
                       "an encrypted wallet loads locked") ? 0 : 1;
        nFail += Check(WalletCanSpendKey(vchPubKey),
                       "an encrypted key is recognized as wallet-owned while locked") ? 0 : 1;

        CPrivKey vchDecrypted;
        string strError;
        nFail += Check(!GetWalletPrivKey(vchPubKey, vchDecrypted, strError),
                       "a locked encrypted key cannot be read") ? 0 : 1;
        nFail += Check(!UnlockWallet(strWrongPassphrase, strError),
                       "the wrong-passphrase does not unlock") ? 0 : 1;
        nFail += Check(UnlockWallet(strPassphrase, strError),
                       "the right passphrase unlocks") ? 0 : 1;
        nFail += Check(!IsWalletLocked(),
                       "the wallet reports unlocked") ? 0 : 1;
        nFail += Check(GetWalletPrivKey(vchPubKey, vchDecrypted, strError) &&
                       vchDecrypted == vchPrivKey,
                       "an unlocked encrypted key decrypts to the original private key") ? 0 : 1;
        LockWallet();
        nFail += Check(IsWalletLocked(),
                       "locking clears the unlocked state") ? 0 : 1;

        // keyUser was never set above (LoadWallet here does not go through
        // the startup code that fills it), so that lock forgot the secret of
        // a key with no material at all. Under OpenSSL 3.0 that read through
        // a NULL public point and killed the process (AddressSanitizer).
        {
            CKey keyEmpty;
            bool fThrew = false;
            try { keyEmpty.GetPubKey(); }
            catch (const key_error&) { fThrew = true; }
            nFail += Check(fThrew, "a key with no public point throws when asked for it") ? 0 : 1;
            nFail += Check(keyEmpty.ForgetPrivKey() && !keyEmpty.HasPrivKey(),
                           "and forgetting the secret of a key that has none is a no-op") ? 0 : 1;
            CKey keyFull;
            keyFull.MakeNewKey();
            vector<unsigned char> vchFullPub = keyFull.GetPubKey();
            nFail += Check(keyFull.ForgetPrivKey() && !keyFull.HasPrivKey() &&
                           keyFull.GetPubKey() == vchFullPub,
                           "a full key forgets its secret and keeps its public key") ? 0 : 1;
            // Assignment would not empty keyUser (EC_KEY_copy leaves the
            // destination's halves when the source has none): it is rebuilt.
            CKey keySaved = keyUser;
            keyUser.~CKey();
            new (&keyUser) CKey();
            nFail += Check(UnlockWallet(strPassphrase, strError), "unlocked again") ? 0 : 1;
            LockWallet();
            nFail += Check(IsWalletLocked() && !keyUser.HasPrivKey(),
                           "a wallet whose default key holds nothing locks") ? 0 : 1;
            keyUser.~CKey();
            new (&keyUser) CKey(keySaved);
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static bool FileContainsBytes(const string& strPath, const vector<unsigned char>& vchNeedle)
{
    if (vchNeedle.empty())
        return false;
    FILE* pf = fopen(strPath.c_str(), "rb");
    if (!pf)
        return false;

    vector<unsigned char> vchHaystack;
    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), pf)) > 0)
        vchHaystack.insert(vchHaystack.end(), buf, buf + n);
    fclose(pf);

    if (vchHaystack.size() < vchNeedle.size())
        return false;
    return search(vchHaystack.begin(), vchHaystack.end(),
                  vchNeedle.begin(), vchNeedle.end()) != vchHaystack.end();
}

static bool FileContainsText(const string& strPath, const string& strNeedle)
{
    FILE* pf = fopen(strPath.c_str(), "rb");
    if (!pf)
        return false;

    string strHaystack;
    char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), pf)) > 0)
        strHaystack.append(buf, buf + n);
    fclose(pf);

    return strHaystack.find(strNeedle) != string::npos;
}

static bool WriteTextFile(const string& strPath, const string& strText)
{
    FILE* pf = fopen(strPath.c_str(), "wb");
    if (!pf)
        return false;
    bool fOk = fwrite(strText.data(), 1, strText.size(), pf) == strText.size();
    if (fclose(pf) != 0)
        fOk = false;
    return fOk;
}

static bool MakeDirLocal(const string& strPath)
{
#ifdef _WIN32
    return CreateDirectoryA(strPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(strPath.c_str(), 0700) == 0 || errno == EEXIST;
#endif
}

static bool CopyFileLocal(const string& strSrc, const string& strDst)
{
    FILE* in = fopen(strSrc.c_str(), "rb");
    if (!in)
        return false;
    FILE* out = fopen(strDst.c_str(), "wb");
    if (!out)
    {
        fclose(in);
        return false;
    }

    bool fOk = true;
    char buf[65536];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (fwrite(buf, 1, n, out) != n)
        {
            fOk = false;
            break;
        }
    }
    if (ferror(in))
        fOk = false;
    if (fclose(out) != 0)
        fOk = false;
    fclose(in);
    return fOk;
}

static bool DirectoryHasFileWithPrefix(const string& strDir, const string& strPrefix)
{
#ifdef _WIN32
    WIN32_FIND_DATAA findData;
    string pattern = strDir + "\\*";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
        return false;
    bool fFound = false;
    do
    {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            string name = findData.cFileName;
            if (name.compare(0, strPrefix.size(), strPrefix) == 0)
            {
                fFound = true;
                break;
            }
        }
    }
    while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    return fFound;
#else
    DIR* dir = opendir(strDir.c_str());
    if (!dir)
        return false;
    bool fFound = false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL)
    {
        string name = ent->d_name;
        if (name.compare(0, strPrefix.size(), strPrefix) == 0)
        {
            fFound = true;
            break;
        }
    }
    closedir(dir);
    return fFound;
#endif
}

static string QuoteCommandArg(const string& str)
{
    string out = "\"";
    for (size_t i = 0; i < str.size(); i++)
    {
        if (str[i] == '"')
            out += "\\\"";
        else
            out += str[i];
    }
    out += "\"";
    return out;
}

static int RunBitflashChild(const string& strExe,
                            const vector<string>& vArgs,
                            const string* pStdinFile = NULL,
                            const string* pOutputFile = NULL)
{
#ifdef _WIN32
    vector<char*> argv;
    argv.push_back((char*)strExe.c_str());
    for (size_t i = 0; i < vArgs.size(); i++)
        argv.push_back((char*)vArgs[i].c_str());
    argv.push_back(NULL);

    int nOldOut = _dup(1);
    int nOldErr = _dup(2);
    int nOldIn = _dup(0);
    int nNull = _open("NUL", _O_WRONLY);
    int nOut = -1;
    int nIn = -1;
    if (pOutputFile)
        nOut = _open(pOutputFile->c_str(), _O_WRONLY|_O_CREAT|_O_TRUNC|_O_BINARY, _S_IREAD|_S_IWRITE);
    if (nOut >= 0)
    {
        _dup2(nOut, 1);
        _dup2(nOut, 2);
    }
    else if (nNull >= 0)
    {
        _dup2(nNull, 1);
        _dup2(nNull, 2);
    }
    if (pStdinFile)
    {
        nIn = _open(pStdinFile->c_str(), _O_RDONLY);
        if (nIn >= 0)
            _dup2(nIn, 0);
    }
    int nRet = _spawnv(_P_WAIT, strExe.c_str(), &argv[0]);
    if (nIn >= 0)
        _close(nIn);
    if (nOut >= 0)
        _close(nOut);
    if (nNull >= 0)
        _close(nNull);
    if (nOldIn >= 0)
    {
        _dup2(nOldIn, 0);
        _close(nOldIn);
    }
    if (nOldOut >= 0)
    {
        _dup2(nOldOut, 1);
        _close(nOldOut);
    }
    if (nOldErr >= 0)
    {
        _dup2(nOldErr, 2);
        _close(nOldErr);
    }
    return nRet;
#else
    string strCmd = QuoteCommandArg(strExe);
    for (size_t i = 0; i < vArgs.size(); i++)
        strCmd += " " + QuoteCommandArg(vArgs[i]);
    if (pStdinFile)
        strCmd += " < " + QuoteCommandArg(*pStdinFile);
    if (pOutputFile)
        strCmd += " > " + QuoteCommandArg(*pOutputFile) + " 2>&1";
    else
        strCmd += " > /dev/null 2>&1";
    // system() returns a wait status, not the exit code; unwrap it so callers
    // see the same value the Windows _spawnv path returns (e.g. exit code 2 is
    // 2, not 512). Without this every "== 2" assertion fails only on Linux.
    int nSysRet = system(strCmd.c_str());
    if (nSysRet != -1 && WIFEXITED(nSysRet))
        return WEXITSTATUS(nSysRet);
    return nSysRet;
#endif
}

static int RunWalletEncryptSelfTest()
{
    fflush(stdout);
    printf("wallet-encrypt self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    bool fWalletEnvClosed = false;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        string strError;
        const string strMnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        nFail += Check(SetHDSeedFromMnemonic(strMnemonic, "", strError),
                       "a phrase can be installed before encryption") ? 0 : 1;
        TopUpKeyPool();

        vector<unsigned char> vchDefaultPubKey = keyUser.GetPubKey();
        CKey publicLabelKey;
        publicLabelKey.MakeNewKey();
        string strPublicLabelAddress = PubKeyToAddress(publicLabelKey.GetPubKey());
        nFail += Check(CWalletDB().WriteName(strPublicLabelAddress, "rewrite-public-name") &&
                       CWalletDB().WriteSetting("rewrite-public-setting", (int64)424242),
                       "public wallet records can be written before encryption") ? 0 : 1;

        CPrivKey vchDefaultPrivKey;
        nFail += Check(GetWalletPrivKey(vchDefaultPubKey, vchDefaultPrivKey, strError),
                       "the default private key is readable before encryption") ? 0 : 1;
        vector<unsigned char> vchDefaultPrivBytes(vchDefaultPrivKey.begin(), vchDefaultPrivKey.end());
        vector<unsigned char> vchPlainHDMaster = vchHDMaster;
        vector<unsigned char> vchPlainHDChainCode = vchHDChainCode;

        // New master keys take as many rounds as cost this machine about a
        // tenth of a second, never fewer than the old fixed 25000.
        {
            vector<unsigned char> vchSalt(8, 0x5a);
            unsigned int nRounds = CalibrateWalletDeriveIterations("btf-test-passphrase", vchSalt);
            CKeyingMaterial k1, k2;
            vector<unsigned char> iv1, iv2;
            nFail += Check(nRounds >= 25000 &&
                           DeriveWalletPassphraseKey("btf-test-passphrase", vchSalt, nRounds, k1, iv1) &&
                           DeriveWalletPassphraseKey("btf-test-passphrase", vchSalt, nRounds, k2, iv2) &&
                           k1 == k2 && iv1 == iv2,
                           strprintf("key derivation is calibrated (%u rounds) and stays deterministic", nRounds).c_str()) ? 0 : 1;
        }

        string strBackup;
        nFail += Check(EncryptWallet("btf-test-passphrase", strBackup, strError),
                       "wallet.dat can be rewritten encrypted") ? 0 : 1;
        fWalletEnvClosed = true;
        nFail += Check(FileExists(strBackup.c_str()),
                       "the original wallet is preserved as an explicit backup") ? 0 : 1;

        string strWalletPath = GetAppDir() + "/wallet.dat";
        nFail += Check(!FileContainsBytes(strWalletPath, vchDefaultPrivBytes),
                       "the active wallet no longer contains the default private key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strWalletPath, vchPlainHDMaster),
                       "the active wallet no longer contains the HD master key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strWalletPath, vchPlainHDChainCode),
                       "the active wallet no longer contains the HD chain-code bytes") ? 0 : 1;

#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strStorageAudit = tmp + "/encrypted-storage-audit.txt";
        string strWrongDump = tmp + "/wrong-pass-dump.txt";
        string strRightDump = tmp + "/right-pass-dump.txt";
        string strLiteralDump = tmp + "/literal-pass-dump.txt";
        string strStdinDump = tmp + "/stdin-pass-dump.txt";
        string strLockedAudit = tmp + "/locked-recovery-audit.txt";
        string strUnlockedAudit = tmp + "/unlocked-recovery-audit.txt";
        string strWrongPassFile = tmp + "/wrong-pass.txt";
        string strRightPassFile = tmp + "/right-pass.txt";
        nFail += Check(WriteTextFile(strWrongPassFile, "wrong-passphrase\n") &&
                       WriteTextFile(strRightPassFile, "btf-test-passphrase\n"),
                       "passphrase files can be written for restarted commands") ? 0 : 1;

        vector<string> vStorageAuditArgs;
        vStorageAuditArgs.push_back("-datadir=" + tmp);
        vStorageAuditArgs.push_back("-walletstorageaudit");
        vStorageAuditArgs.push_back("-nogui");
        int nStorageAuditRet = RunBitflashChild(strExe, vStorageAuditArgs, NULL, &strStorageAudit);
        nFail += Check(nStorageAuditRet == 0 &&
                       FileContainsText(strStorageAudit, "address book labels:       3"),
                       "the encrypted rewrite keeps address-book records") ? 0 : 1;
        nFail += Check(nStorageAuditRet == 0 &&
                       FileContainsText(strStorageAudit, "settings:                  1"),
                       "the encrypted rewrite keeps wallet setting records") ? 0 : 1;

        vector<string> vWrongArgs;
        vWrongArgs.push_back("-datadir=" + tmp);
        vWrongArgs.push_back("-walletpassphrase=@" + strWrongPassFile);
        vWrongArgs.push_back("-dumpwallet=" + strWrongDump);
        vWrongArgs.push_back("-nogui");
        int nWrongRet = RunBitflashChild(strExe, vWrongArgs);
        nFail += Check(nWrongRet != 0 && !FileExists(strWrongDump.c_str()),
                       "a restarted wallet rejects the wrong-passphrase") ? 0 : 1;

        vector<string> vLockedAuditArgs;
        vLockedAuditArgs.push_back("-datadir=" + tmp);
        vLockedAuditArgs.push_back("-recoveryaudit");
        vLockedAuditArgs.push_back("-nogui");
        int nLockedAuditRet = RunBitflashChild(strExe, vLockedAuditArgs, NULL, &strLockedAudit);
        nFail += Check(nLockedAuditRet == 2 &&
                       FileContainsText(strLockedAudit, "recovery phrase: encrypted, unlock wallet to audit") &&
                       FileContainsText(strLockedAudit, "recovery coverage:            unavailable while wallet is locked") &&
                       FileContainsText(strLockedAudit, "Unlock the wallet with /walletpassphrase"),
                       "a locked encrypted wallet reports that phrase coverage needs unlock") ? 0 : 1;

        vector<string> vLiteralArgs;
        vLiteralArgs.push_back("-datadir=" + tmp);
        vLiteralArgs.push_back("-walletpassphrase=btf-test-passphrase");
        vLiteralArgs.push_back("-dumpwallet=" + strLiteralDump);
        vLiteralArgs.push_back("-nogui");
        int nLiteralRet = RunBitflashChild(strExe, vLiteralArgs);
        nFail += Check(nLiteralRet != 0 && !FileExists(strLiteralDump.c_str()),
                       "literal passphrases on the command line are refused") ? 0 : 1;

        vector<string> vRightArgs;
        vRightArgs.push_back("-datadir=" + tmp);
        vRightArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vRightArgs.push_back("-dumpwallet=" + strRightDump);
        vRightArgs.push_back("-nogui");
        int nRightRet = RunBitflashChild(strExe, vRightArgs);
        nFail += Check(nRightRet == 0 && FileExists(strRightDump.c_str()),
                       "a restarted wallet unlocks with the right passphrase") ? 0 : 1;
        nFail += Check(FileContainsText(strRightDump, HexStrLocal(vchDefaultPrivBytes)),
                       "the restarted wallet can decrypt and dump the original key") ? 0 : 1;

        vector<string> vUnlockedAuditArgs;
        vUnlockedAuditArgs.push_back("-datadir=" + tmp);
        vUnlockedAuditArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vUnlockedAuditArgs.push_back("-recoveryaudit");
        vUnlockedAuditArgs.push_back("-nogui");
        int nUnlockedAuditRet = RunBitflashChild(strExe, vUnlockedAuditArgs, NULL, &strUnlockedAudit);
        nFail += Check(nUnlockedAuditRet == 0 &&
                       FileContainsText(strUnlockedAudit, "recovery phrase: present") &&
                       !FileContainsText(strUnlockedAudit, "recovery phrase: not installed"),
                       "an unlocked encrypted wallet audits the installed recovery phrase") ? 0 : 1;

        vector<string> vStdinArgs;
        vStdinArgs.push_back("-datadir=" + tmp);
        vStdinArgs.push_back("-walletpassphrase");
        vStdinArgs.push_back("-dumpwallet=" + strStdinDump);
        vStdinArgs.push_back("-nogui");
        int nStdinRet = RunBitflashChild(strExe, vStdinArgs, &strRightPassFile);
        nFail += Check(nStdinRet == 0 && FileExists(strStdinDump.c_str()),
                       "a restarted wallet can read the passphrase from stdin") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    if (!fWalletEnvClosed)
        DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Encrypting a wallet while it runs on the SQLite backend. Unlike the Berkeley
// DB encrypt test above, this drives the real command-line path end to end in
// child processes: build a Berkeley DB wallet, export it to SQLite, then run
// -walletbackend=sqlite -encryptwallet and prove the SQLite wallet came out
// encrypted, unlockable, and with wallet.dat left untouched.
static int RunWalletSQLiteEncryptSelfTest()
{
    fflush(stdout);
    printf("wallet-sqlite-encrypt self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        // Build a normal Berkeley DB wallet with a recovery phrase, a key pool,
        // and a couple of public records, then release it. Everything after this
        // runs the real command-line paths in child processes.
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        string strError;
        const string strMnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        nFail += Check(SetHDSeedFromMnemonic(strMnemonic, "", strError),
                       "a phrase can be installed before encryption") ? 0 : 1;
        TopUpKeyPool();

        vector<unsigned char> vchDefaultPubKey = keyUser.GetPubKey();
        CKey publicLabelKey;
        publicLabelKey.MakeNewKey();
        string strPublicLabelAddress = PubKeyToAddress(publicLabelKey.GetPubKey());
        nFail += Check(CWalletDB().WriteName(strPublicLabelAddress, "rewrite-public-name") &&
                       CWalletDB().WriteSetting("rewrite-public-setting", (int64)424242),
                       "public wallet records can be written before encryption") ? 0 : 1;

        CPrivKey vchDefaultPrivKey;
        nFail += Check(GetWalletPrivKey(vchDefaultPubKey, vchDefaultPrivKey, strError),
                       "the default private key is readable before encryption") ? 0 : 1;
        vector<unsigned char> vchDefaultPrivBytes(vchDefaultPrivKey.begin(), vchDefaultPrivKey.end());
        vector<unsigned char> vchPlainHDMaster = vchHDMaster;
        vector<unsigned char> vchPlainHDChainCode = vchHDChainCode;

        // Release wallet.dat so a child process can read it for the export.
        DBFlush(true);

#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strSQLitePath = tmp + "/wallet.sqlite";
        string strWalletDatPath = tmp + "/wallet.dat";
        string strRightPassFile = tmp + "/right-pass.txt";
        string strWrongPassFile = tmp + "/wrong-pass.txt";
        nFail += Check(WriteTextFile(strRightPassFile, "btf-test-passphrase\n") &&
                       WriteTextFile(strWrongPassFile, "wrong-passphrase\n"),
                       "passphrase files can be written for restarted commands") ? 0 : 1;

        // Step 1: export the Berkeley DB wallet to SQLite.
        vector<string> vExportArgs;
        vExportArgs.push_back("-datadir=" + tmp);
        vExportArgs.push_back("-walletsqliteexport=" + strSQLitePath);
        vExportArgs.push_back("-nogui");
        int nExportRet = RunBitflashChild(strExe, vExportArgs);
        nFail += Check(nExportRet == 0 && FileExists(strSQLitePath.c_str()),
                       "the wallet exports to a SQLite file") ? 0 : 1;
        nFail += Check(FileContainsBytes(strSQLitePath, vchDefaultPrivBytes),
                       "the exported SQLite wallet holds the plaintext key before encryption") ? 0 : 1;

        // Step 2: encrypt through the real SQLite backend command path.
        string strEncryptOut = tmp + "/sqlite-encrypt-out.txt";
        vector<string> vEncryptArgs;
        vEncryptArgs.push_back("-datadir=" + tmp);
        vEncryptArgs.push_back("-walletbackend=sqlite");
        vEncryptArgs.push_back("-encryptwallet=@" + strRightPassFile);
        vEncryptArgs.push_back("-nogui");
        int nEncryptRet = RunBitflashChild(strExe, vEncryptArgs, NULL, &strEncryptOut);
        nFail += Check(nEncryptRet == 0,
                       "the SQLite wallet can be encrypted through -walletbackend=sqlite") ? 0 : 1;
        nFail += Check(FileContainsText(strEncryptOut, "Wallet backend: SQLite"),
                       "encryption took the SQLite persistence path") ? 0 : 1;
        nFail += Check(FileContainsText(strEncryptOut, "wallet.sqlite.before-encrypt"),
                       "the plaintext SQLite wallet is preserved as an explicit backup") ? 0 : 1;

        // The encrypted SQLite wallet must no longer hold the plaintext secrets.
        nFail += Check(!FileContainsBytes(strSQLitePath, vchDefaultPrivBytes),
                       "the encrypted SQLite wallet no longer contains the default private key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strSQLitePath, vchPlainHDMaster),
                       "the encrypted SQLite wallet no longer contains the HD master key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strSQLitePath, vchPlainHDChainCode),
                       "the encrypted SQLite wallet no longer contains the HD chain-code bytes") ? 0 : 1;

        // The Berkeley DB wallet.dat is a separate file: the SQLite encrypt path
        // must never touch it, so its plaintext key is still exactly there.
        nFail += Check(FileContainsBytes(strWalletDatPath, vchDefaultPrivBytes),
                       "the original Berkeley DB wallet.dat is left untouched by the SQLite encrypt") ? 0 : 1;

        // Step 3: a locked encrypted SQLite wallet reports that phrase coverage
        // needs an unlock, exactly as the Berkeley DB path does (exit code 2).
        string strLockedAudit = tmp + "/locked-recovery-audit.txt";
        vector<string> vLockedArgs;
        vLockedArgs.push_back("-datadir=" + tmp);
        vLockedArgs.push_back("-walletbackend=sqlite");
        vLockedArgs.push_back("-recoveryaudit");
        vLockedArgs.push_back("-nogui");
        int nLockedRet = RunBitflashChild(strExe, vLockedArgs, NULL, &strLockedAudit);
        nFail += Check(nLockedRet == 2 &&
                       FileContainsText(strLockedAudit, "recovery phrase: encrypted, unlock wallet to audit"),
                       "a locked encrypted SQLite wallet reports that phrase coverage needs unlock") ? 0 : 1;

        // The wrong passphrase is rejected and reveals nothing.
        string strWrongDump = tmp + "/wrong-dump.txt";
        vector<string> vWrongArgs;
        vWrongArgs.push_back("-datadir=" + tmp);
        vWrongArgs.push_back("-walletbackend=sqlite");
        vWrongArgs.push_back("-walletpassphrase=@" + strWrongPassFile);
        vWrongArgs.push_back("-dumpwallet=" + strWrongDump);
        vWrongArgs.push_back("-nogui");
        int nWrongRet = RunBitflashChild(strExe, vWrongArgs);
        nFail += Check(nWrongRet != 0 && !FileExists(strWrongDump.c_str()),
                       "a restarted SQLite wallet rejects the wrong passphrase") ? 0 : 1;

        // The right passphrase unlocks and can dump the original key.
        string strRightDump = tmp + "/right-dump.txt";
        vector<string> vRightArgs;
        vRightArgs.push_back("-datadir=" + tmp);
        vRightArgs.push_back("-walletbackend=sqlite");
        vRightArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vRightArgs.push_back("-dumpwallet=" + strRightDump);
        vRightArgs.push_back("-nogui");
        int nRightRet = RunBitflashChild(strExe, vRightArgs);
        nFail += Check(nRightRet == 0 && FileExists(strRightDump.c_str()),
                       "a restarted SQLite wallet unlocks with the right passphrase") ? 0 : 1;
        nFail += Check(FileContainsText(strRightDump, HexStrLocal(vchDefaultPrivBytes)),
                       "the unlocked SQLite wallet decrypts and dumps the original key") ? 0 : 1;

        // The recovery phrase survives the encryption.
        string strAudit = tmp + "/recovery-audit.txt";
        vector<string> vAuditArgs;
        vAuditArgs.push_back("-datadir=" + tmp);
        vAuditArgs.push_back("-walletbackend=sqlite");
        vAuditArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vAuditArgs.push_back("-recoveryaudit");
        vAuditArgs.push_back("-nogui");
        int nAuditRet = RunBitflashChild(strExe, vAuditArgs, NULL, &strAudit);
        nFail += Check(nAuditRet == 0 &&
                       FileContainsText(strAudit, "recovery phrase: present"),
                       "the encrypted SQLite wallet still has its recovery phrase") ? 0 : 1;

        // One-shot storage commands honour -walletbackend. The SQLite wallet is
        // encrypted; the wallet.dat beside it is still plaintext. Same datadir,
        // opposite answers -> the flag routes the diagnostic to the right file.
        string strSqliteAuditJson = tmp + "/sqlite-audit.json";
        vector<string> vSqliteAuditArgs;
        vSqliteAuditArgs.push_back("-datadir=" + tmp);
        vSqliteAuditArgs.push_back("-walletbackend=sqlite");
        vSqliteAuditArgs.push_back("-walletstorageauditjson=" + strSqliteAuditJson);
        vSqliteAuditArgs.push_back("-nogui");
        int nSqliteAuditRet = RunBitflashChild(strExe, vSqliteAuditArgs);
        nFail += Check(nSqliteAuditRet == 0 &&
                       FileContainsText(strSqliteAuditJson, "\"encrypted_hd_seed\": \"complete\"") &&
                       FileContainsText(strSqliteAuditJson, "\"plain_hd_seed\": \"none\""),
                       "-walletstorageaudit under SQLite reads the encrypted wallet.sqlite") ? 0 : 1;

        string strBdbAuditJson = tmp + "/bdb-audit.json";
        vector<string> vBdbAuditArgs;
        vBdbAuditArgs.push_back("-datadir=" + tmp);
        vBdbAuditArgs.push_back("-walletstorageauditjson=" + strBdbAuditJson);
        vBdbAuditArgs.push_back("-nogui");
        int nBdbAuditRet = RunBitflashChild(strExe, vBdbAuditArgs);
        nFail += Check(nBdbAuditRet == 0 &&
                       FileContainsText(strBdbAuditJson, "\"plain_hd_seed\": \"complete\"") &&
                       FileContainsText(strBdbAuditJson, "\"encrypted_hd_seed\": \"none\""),
                       "-walletstorageaudit without the flag still reads the plaintext wallet.dat") ? 0 : 1;

        string strSqliteCheckOut = tmp + "/sqlite-check.txt";
        vector<string> vSqliteCheckArgs;
        vSqliteCheckArgs.push_back("-datadir=" + tmp);
        vSqliteCheckArgs.push_back("-walletbackend=sqlite");
        vSqliteCheckArgs.push_back("-walletstoragecheck");
        vSqliteCheckArgs.push_back("-nogui");
        int nSqliteCheckRet = RunBitflashChild(strExe, vSqliteCheckArgs, NULL, &strSqliteCheckOut);
        nFail += Check(nSqliteCheckRet == 0,
                       "-walletstoragecheck under SQLite passes on the encrypted wallet.sqlite") ? 0 : 1;

        // Backup under SQLite copies wallet.sqlite, not the plaintext wallet.dat.
        // The copy is a standalone SQLite wallet (loadcheck accepts it) and holds
        // none of the plaintext key that wallet.dat still contains.
        string strBackupDest = tmp + "/backup.sqlite";
        vector<string> vBackupArgs;
        vBackupArgs.push_back("-datadir=" + tmp);
        vBackupArgs.push_back("-walletbackend=sqlite");
        vBackupArgs.push_back("-backupwallet=" + strBackupDest);
        vBackupArgs.push_back("-nogui");
        int nBackupRet = RunBitflashChild(strExe, vBackupArgs);
        nFail += Check(nBackupRet == 0 && FileExists(strBackupDest.c_str()),
                       "-backupwallet under SQLite writes a backup file") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strBackupDest, vchDefaultPrivBytes),
                       "the SQLite backup holds no plaintext key (it copied wallet.sqlite, not wallet.dat)") ? 0 : 1;

        string strBackupLoadCheck = tmp + "/backup-loadcheck.txt";
        vector<string> vLoadCheckArgs;
        vLoadCheckArgs.push_back("-datadir=" + tmp);
        vLoadCheckArgs.push_back("-walletsqliteloadcheck=" + strBackupDest);
        vLoadCheckArgs.push_back("-nogui");
        int nBackupLoadRet = RunBitflashChild(strExe, vLoadCheckArgs, NULL, &strBackupLoadCheck);
        nFail += Check(nBackupLoadRet == 0,
                       "the SQLite backup is a valid standalone SQLite wallet") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Backend resolution when no -walletbackend flag is given: a fresh install
// starts on SQLite (the new default), an existing wallet.dat stays on Berkeley
// DB, the persistent marker overrides the default, and an explicit flag
// overrides everything. Each scenario runs a real child process.
static int RunWalletBackendDefaultSelfTest()
{
    fflush(stdout);
    printf("wallet-backend-default self-test\n");

    std::string tmp, cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

#ifdef _WIN32
    string strExe = cwd + "\\bitflash.exe";
#else
    string strExe = cwd + "/bitflash-node";
#endif

    try
    {
        // 1. Fresh datadir, no flag -> new wallet.sqlite, marker "sqlite", no wallet.dat.
        string d1 = tmp + "/fresh";
        nFail += Check(MakeDirLocal(d1), "fresh scenario dir can be created") ? 0 : 1;
        vector<string> a1;
        a1.push_back("-datadir=" + d1);
        a1.push_back("-nomanagedtor");
        a1.push_back("-nogui");
        a1.push_back("-newaddress");
        int r1 = RunBitflashChild(strExe, a1);
        nFail += Check(r1 == 0 &&
                       FileExists((d1 + "/wallet.sqlite").c_str()) &&
                       !FileExists((d1 + "/wallet.dat").c_str()) &&
                       FileContainsText(d1 + "/wallet-backend", "sqlite"),
                       "a fresh install starts on SQLite (new default) and records the marker") ? 0 : 1;

        // 1b. Second run reuses it, still SQLite, still no wallet.dat.
        int r1b = RunBitflashChild(strExe, a1);
        nFail += Check(r1b == 0 &&
                       FileExists((d1 + "/wallet.sqlite").c_str()) &&
                       !FileExists((d1 + "/wallet.dat").c_str()),
                       "the recorded SQLite choice survives a restart") ? 0 : 1;

        // 2. Existing wallet.dat, no flag -> stays on Berkeley DB.
        string d2 = tmp + "/existing-bdb";
        nFail += Check(MakeDirLocal(d2), "existing-bdb scenario dir can be created") ? 0 : 1;
        vector<string> a2c;
        a2c.push_back("-datadir=" + d2);
        a2c.push_back("-nomanagedtor");
        a2c.push_back("-nogui");
        a2c.push_back("-walletbackend=bdb");
        a2c.push_back("-newphrase");
        RunBitflashChild(strExe, a2c);
        vector<string> a2;
        a2.push_back("-datadir=" + d2);
        a2.push_back("-nomanagedtor");
        a2.push_back("-nogui");
        a2.push_back("-newaddress");
        int r2 = RunBitflashChild(strExe, a2);
        nFail += Check(r2 == 0 &&
                       FileExists((d2 + "/wallet.dat").c_str()) &&
                       !FileExists((d2 + "/wallet.sqlite").c_str()),
                       "an existing wallet.dat keeps a flagless start on Berkeley DB") ? 0 : 1;

        // 3. Marker "bdb" forces Berkeley DB even on a fresh datadir.
        string d3 = tmp + "/marker-bdb";
        nFail += Check(MakeDirLocal(d3), "marker-bdb scenario dir can be created") ? 0 : 1;
        nFail += Check(WriteTextFile(d3 + "/wallet-backend", "bdb\n"),
                       "a bdb marker can be written") ? 0 : 1;
        vector<string> a3;
        a3.push_back("-datadir=" + d3);
        a3.push_back("-nomanagedtor");
        a3.push_back("-nogui");
        a3.push_back("-newaddress");
        int r3 = RunBitflashChild(strExe, a3);
        nFail += Check(r3 == 0 &&
                       FileExists((d3 + "/wallet.dat").c_str()) &&
                       !FileExists((d3 + "/wallet.sqlite").c_str()),
                       "a bdb marker forces Berkeley DB on a fresh datadir") ? 0 : 1;

        // 4. Explicit -walletbackend=bdb on a fresh datadir -> wallet.dat.
        string d4 = tmp + "/explicit-bdb";
        nFail += Check(MakeDirLocal(d4), "explicit-bdb scenario dir can be created") ? 0 : 1;
        vector<string> a4;
        a4.push_back("-datadir=" + d4);
        a4.push_back("-nomanagedtor");
        a4.push_back("-nogui");
        a4.push_back("-walletbackend=bdb");
        a4.push_back("-newaddress");
        int r4 = RunBitflashChild(strExe, a4);
        nFail += Check(r4 == 0 &&
                       FileExists((d4 + "/wallet.dat").c_str()) &&
                       !FileExists((d4 + "/wallet.sqlite").c_str()),
                       "an explicit -walletbackend=bdb creates wallet.dat on a fresh datadir") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// The wizard's conversion action, headless: build a Berkeley DB wallet, run
// DoConvertWalletToSQLite() (what the GUI button calls), and prove it produced a
// usable wallet.sqlite + backend marker while leaving wallet.dat untouched, then
// that a flagless restart opens the converted SQLite wallet.
static int RunWalletConvertSelfTest()
{
    fflush(stdout);
    printf("wallet-convert self-test\n");

    std::string tmp, cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

#ifdef _WIN32
    string strExe = cwd + "\\bitflash.exe";
#else
    string strExe = cwd + "/bitflash-node";
#endif

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        string strError;
        nFail += Check(SetHDSeedFromMnemonic(
                           "abandon abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon about", "", strError),
                       "a phrase can be installed before conversion") ? 0 : 1;
        TopUpKeyPool();

        vector<unsigned char> vchDefaultPubKey = keyUser.GetPubKey();
        CPrivKey vchDefaultPrivKey;
        nFail += Check(GetWalletPrivKey(vchDefaultPubKey, vchDefaultPrivKey, strError),
                       "the default private key is readable before conversion") ? 0 : 1;
        vector<unsigned char> vchDefaultPrivBytes(vchDefaultPrivKey.begin(),
                                                  vchDefaultPrivKey.end());

        // The conversion action the GUI button invokes.
        int nCopied = 0;
        string strConvertError;
        bool fConverted = DoConvertWalletToSQLite(nCopied, strConvertError);
        nFail += Check(fConverted && nCopied > 0,
                       "DoConvertWalletToSQLite exports the wallet") ? 0 : 1;
        nFail += Check(FileExists((tmp + "/wallet.sqlite").c_str()) &&
                       FileContainsText(tmp + "/wallet-backend", "sqlite"),
                       "conversion writes wallet.sqlite and records the sqlite marker") ? 0 : 1;
        nFail += Check(FileContainsBytes(tmp + "/wallet.dat", vchDefaultPrivBytes),
                       "wallet.dat is left untouched by the conversion") ? 0 : 1;

        // Idempotence guard: a second conversion refuses rather than overwrite.
        int nCopied2 = 0;
        string strSecondError;
        nFail += Check(!DoConvertWalletToSQLite(nCopied2, strSecondError),
                       "a second conversion refuses to overwrite wallet.sqlite") ? 0 : 1;

        DBFlush(true);

        // A flagless restart now opens the converted SQLite wallet (the marker
        // routes it) and finds the same recovery phrase.
        string strAudit = tmp + "/converted-recovery-audit.txt";
        vector<string> vAuditArgs;
        vAuditArgs.push_back("-datadir=" + tmp);
        vAuditArgs.push_back("-nomanagedtor");
        vAuditArgs.push_back("-nogui");
        vAuditArgs.push_back("-recoveryaudit");
        int nAuditRet = RunBitflashChild(strExe, vAuditArgs, NULL, &strAudit);
        nFail += Check(nAuditRet == 0 &&
                       FileContainsText(strAudit, "recovery phrase: present"),
                       "a flagless restart opens the converted SQLite wallet") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunWalletPortabilitySelfTest()
{
    fflush(stdout);
    printf("wallet-portability self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strOriginal = tmp + "/original";
        string strRawCopy = tmp + "/raw-copy";
        string strBackupCopy = tmp + "/backup-copy";
        nFail += Check(MakeDirLocal(strOriginal) &&
                       MakeDirLocal(strRawCopy) &&
                       MakeDirLocal(strBackupCopy),
                       "temporary wallet directories can be created") ? 0 : 1;

        string strCreateOut = tmp + "/create.txt";
        vector<string> vCreateArgs;
        vCreateArgs.push_back("-datadir=" + strOriginal);
        vCreateArgs.push_back("-nomanagedtor");
        vCreateArgs.push_back("-nogui");
        vCreateArgs.push_back("-walletbackend=bdb");   // this suite is about wallet.dat portability
        vCreateArgs.push_back("-newphrase");
        int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
        nFail += Check(nCreateRet == 0 &&
                       FileContainsText(strCreateOut, "Write these twelve words down"),
                       "a phrase wallet can be created in a fresh datadir") ? 0 : 1;

        string strOriginalAudit = tmp + "/original-audit.txt";
        vector<string> vOriginalAuditArgs;
        vOriginalAuditArgs.push_back("-datadir=" + strOriginal);
        vOriginalAuditArgs.push_back("-nomanagedtor");
        vOriginalAuditArgs.push_back("-nogui");
        vOriginalAuditArgs.push_back("-recoveryaudit");
        int nOriginalAuditRet = RunBitflashChild(strExe, vOriginalAuditArgs, NULL, &strOriginalAudit);
        nFail += Check(nOriginalAuditRet == 0 &&
                       FileContainsText(strOriginalAudit, "recovery phrase: present") &&
                       FileContainsText(strOriginalAudit, "SLIP-0044 BITFLASH"),
                       "the original wallet reports its recovery phrase") ? 0 : 1;

        string strOriginalStorageAudit = tmp + "/original-storage-audit.txt";
        vector<string> vOriginalStorageAuditArgs;
        vOriginalStorageAuditArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageAuditArgs.push_back("-nomanagedtor");
        vOriginalStorageAuditArgs.push_back("-nogui");
        vOriginalStorageAuditArgs.push_back("-walletstorageaudit");
        int nOriginalStorageAuditRet =
            RunBitflashChild(strExe, vOriginalStorageAuditArgs, NULL, &strOriginalStorageAudit);
        nFail += Check(nOriginalStorageAuditRet == 0 &&
                       FileContainsText(strOriginalStorageAudit, "Wallet storage audit") &&
                       FileContainsText(strOriginalStorageAudit, "plain HD seed:             complete") &&
                       FileContainsText(strOriginalStorageAudit, "encrypted HD seed:         none") &&
                       FileContainsText(strOriginalStorageAudit, "malformed records:         0"),
                       "the storage audit recognizes a plaintext phrase wallet") ? 0 : 1;

        string strOriginalStorageCheck = tmp + "/original-storage-check.txt";
        vector<string> vOriginalStorageCheckArgs;
        vOriginalStorageCheckArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageCheckArgs.push_back("-nomanagedtor");
        vOriginalStorageCheckArgs.push_back("-nogui");
        vOriginalStorageCheckArgs.push_back("-walletstoragecheck");
        int nOriginalStorageCheckRet =
            RunBitflashChild(strExe, vOriginalStorageCheckArgs, NULL, &strOriginalStorageCheck);
        nFail += Check(nOriginalStorageCheckRet == 0 &&
                       FileContainsText(strOriginalStorageCheck, "storage sanity:            ok") &&
                       FileContainsText(strOriginalStorageCheck, "plain HD seed:             complete"),
                       "the storage sanity check accepts a plaintext phrase wallet") ? 0 : 1;

        string strOriginalStorageAuditJson = tmp + "/original-storage-audit.json";
        vector<string> vOriginalStorageAuditJsonArgs;
        vOriginalStorageAuditJsonArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageAuditJsonArgs.push_back("-nomanagedtor");
        vOriginalStorageAuditJsonArgs.push_back("-nogui");
        vOriginalStorageAuditJsonArgs.push_back("-walletstorageauditjson=" +
                                                strOriginalStorageAuditJson);
        int nOriginalStorageAuditJsonRet =
            RunBitflashChild(strExe, vOriginalStorageAuditJsonArgs);
        nFail += Check(nOriginalStorageAuditJsonRet == 0 &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"format\": \"bitflash-wallet-storage-audit-v1\"") &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"plain_hd_seed\": \"complete\"") &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"encrypted_hd_seed\": \"none\""),
                       "the storage audit can write plaintext-wallet JSON") ? 0 : 1;

        string strPortableWallet = tmp + "/portable-wallet.dat";
        string strBackupOut = tmp + "/backupwallet.txt";
        vector<string> vBackupArgs;
        vBackupArgs.push_back("-datadir=" + strOriginal);
        vBackupArgs.push_back("-nomanagedtor");
        vBackupArgs.push_back("-nogui");
        vBackupArgs.push_back("-backupwallet=" + strPortableWallet);
        int nBackupRet = RunBitflashChild(strExe, vBackupArgs, NULL, &strBackupOut);
        nFail += Check(nBackupRet == 0 && FileExists(strPortableWallet.c_str()),
                       "/backupwallet writes a portable wallet.dat") ? 0 : 1;

        string strBackupOut2 = tmp + "/backupwallet-overwrite.txt";
        int nBackupRet2 = RunBitflashChild(strExe, vBackupArgs, NULL, &strBackupOut2);
        nFail += Check(nBackupRet2 == 0 && FileExists(strPortableWallet.c_str()) &&
                       !DirectoryHasFileWithPrefix(tmp, "portable-wallet.dat.tmp.") &&
                       !DirectoryHasFileWithPrefix(tmp, "portable-wallet.dat.old."),
                       "/backupwallet replaces an existing backup without leaving temp files") ? 0 : 1;

        nFail += Check(CopyFileLocal(strOriginal + "/wallet.dat",
                                     strRawCopy + "/wallet.dat"),
                       "a raw wallet.dat can be copied without database logs") ? 0 : 1;
        string strRawAudit = tmp + "/raw-copy-audit.txt";
        vector<string> vRawAuditArgs;
        vRawAuditArgs.push_back("-datadir=" + strRawCopy);
        vRawAuditArgs.push_back("-nomanagedtor");
        vRawAuditArgs.push_back("-nogui");
        vRawAuditArgs.push_back("-recoveryaudit");
        int nRawAuditRet = RunBitflashChild(strExe, vRawAuditArgs, NULL, &strRawAudit);
        nFail += Check(nRawAuditRet == 0 &&
                       FileContainsText(strRawAudit, "recovery phrase: present") &&
                       !FileContainsText(strRawAudit, "Cannot open wallet.dat"),
                       "a raw wallet.dat copy opens in a new datadir") ? 0 : 1;

        nFail += Check(CopyFileLocal(strPortableWallet,
                                     strBackupCopy + "/wallet.dat"),
                       "the portable backup can be installed as wallet.dat") ? 0 : 1;
        string strBackupAudit = tmp + "/backup-copy-audit.txt";
        vector<string> vBackupAuditArgs;
        vBackupAuditArgs.push_back("-datadir=" + strBackupCopy);
        vBackupAuditArgs.push_back("-nomanagedtor");
        vBackupAuditArgs.push_back("-nogui");
        vBackupAuditArgs.push_back("-recoveryaudit");
        int nBackupAuditRet = RunBitflashChild(strExe, vBackupAuditArgs, NULL, &strBackupAudit);
        nFail += Check(nBackupAuditRet == 0 &&
                       FileContainsText(strBackupAudit, "recovery phrase: present") &&
                       FileContainsText(strBackupAudit, "SLIP-0044 BITFLASH"),
                       "a /backupwallet copy opens in a new datadir") ? 0 : 1;

        string strPassFile = tmp + "/encrypt-pass.txt";
        string strEncryptOut = tmp + "/encryptwallet.txt";
        nFail += Check(WriteTextFile(strPassFile, "portable-test-passphrase\n"),
                       "an encryption passphrase file can be written") ? 0 : 1;
        vector<string> vEncryptArgs;
        vEncryptArgs.push_back("-datadir=" + strOriginal);
        vEncryptArgs.push_back("-nomanagedtor");
        vEncryptArgs.push_back("-nogui");
        vEncryptArgs.push_back("-encryptwallet=@" + strPassFile);
        int nEncryptRet = RunBitflashChild(strExe, vEncryptArgs, NULL, &strEncryptOut);
        nFail += Check(nEncryptRet == 0 &&
                       !DirectoryHasFileWithPrefix(strOriginal + "/database", "log."),
                       "the encryptwallet command purges Berkeley DB environment logs") ? 0 : 1;

        string strEncryptedStorageAudit = tmp + "/encrypted-storage-audit.txt";
        vector<string> vEncryptedStorageAuditArgs;
        vEncryptedStorageAuditArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageAuditArgs.push_back("-nomanagedtor");
        vEncryptedStorageAuditArgs.push_back("-nogui");
        vEncryptedStorageAuditArgs.push_back("-walletstorageaudit");
        int nEncryptedStorageAuditRet =
            RunBitflashChild(strExe, vEncryptedStorageAuditArgs, NULL, &strEncryptedStorageAudit);
        nFail += Check(nEncryptedStorageAuditRet == 0 &&
                       FileContainsText(strEncryptedStorageAudit, "plain private keys:        0") &&
                       FileContainsText(strEncryptedStorageAudit, "encrypted private keys:") &&
                       FileContainsText(strEncryptedStorageAudit, "plain HD seed:             none") &&
                       FileContainsText(strEncryptedStorageAudit, "encrypted HD seed:         complete") &&
                       FileContainsText(strEncryptedStorageAudit, "wallet minimum version:    present") &&
                       FileContainsText(strEncryptedStorageAudit, "malformed records:         0"),
                       "the storage audit recognizes an encrypted wallet") ? 0 : 1;

        string strEncryptedStorageCheck = tmp + "/encrypted-storage-check.txt";
        vector<string> vEncryptedStorageCheckArgs;
        vEncryptedStorageCheckArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageCheckArgs.push_back("-nomanagedtor");
        vEncryptedStorageCheckArgs.push_back("-nogui");
        vEncryptedStorageCheckArgs.push_back("-walletstoragecheck");
        int nEncryptedStorageCheckRet =
            RunBitflashChild(strExe, vEncryptedStorageCheckArgs, NULL, &strEncryptedStorageCheck);
        nFail += Check(nEncryptedStorageCheckRet == 0 &&
                       FileContainsText(strEncryptedStorageCheck, "storage sanity:            ok") &&
                       FileContainsText(strEncryptedStorageCheck, "plain private keys:        0") &&
                       FileContainsText(strEncryptedStorageCheck, "encrypted HD seed:         complete"),
                       "the storage sanity check accepts an encrypted wallet") ? 0 : 1;

        string strEncryptedStorageAuditJson = tmp + "/encrypted-storage-audit.json";
        vector<string> vEncryptedStorageAuditJsonArgs;
        vEncryptedStorageAuditJsonArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageAuditJsonArgs.push_back("-nomanagedtor");
        vEncryptedStorageAuditJsonArgs.push_back("-nogui");
        vEncryptedStorageAuditJsonArgs.push_back("-walletstorageauditjson=" +
                                                 strEncryptedStorageAuditJson);
        int nEncryptedStorageAuditJsonRet =
            RunBitflashChild(strExe, vEncryptedStorageAuditJsonArgs);
        nFail += Check(nEncryptedStorageAuditJsonRet == 0 &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"plain_private_keys\": 0") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"plain_hd_seed\": \"none\"") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"encrypted_hd_seed\": \"complete\"") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"wallet_minimum_version\": \"present\""),
                       "the storage audit can write encrypted-wallet JSON") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunNetMessageSelfTest()
{
    fflush(stdout);
    printf("net-message self-test\n");

    int nFail = 0;
    try
    {
        CNode complete(INVALID_SOCKET, CAddress("127.0.0.1"));
        complete.nVersion = VERSION;
        complete.vRecv << CMessageHeader("ping", 0);
        nFail += Check(ProcessMessages(&complete), "a complete empty message processes") ? 0 : 1;
        nFail += Check(complete.vRecv.empty(), "a complete message is consumed") ? 0 : 1;
        nFail += Check(!complete.fDisconnect, "a valid ping does not disconnect the peer") ? 0 : 1;

        CNode partial(INVALID_SOCKET, CAddress("127.0.0.1"));
        partial.nVersion = VERSION;
        partial.vRecv << CMessageHeader("block", 100);
        unsigned int nPartialBefore = partial.vRecv.size();
        nFail += Check(ProcessMessages(&partial), "an incomplete message returns cleanly") ? 0 : 1;
        nFail += Check(partial.vRecv.size() == nPartialBefore,
                       "an incomplete message keeps one header in the buffer") ? 0 : 1;
        nFail += Check(partial.nIncompleteMessageStart != 0,
                       "an incomplete message starts a timeout clock") ? 0 : 1;
        nFail += Check(!partial.fDisconnect,
                       "a fresh incomplete message does not disconnect immediately") ? 0 : 1;

        CNode stale(INVALID_SOCKET, CAddress("127.0.0.1"));
        stale.nVersion = VERSION;
        stale.vRecv << CMessageHeader("block", 100);
        stale.nIncompleteMessageStart = GetTime() - BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS - 1;
        stale.nIncompleteMessageSize = 100;
        stale.strIncompleteMessageCommand = "block";
        ProcessMessages(&stale);
        nFail += Check(stale.fDisconnect,
                       "a stale incomplete message disconnects the peer") ? 0 : 1;

        CNode oversized(INVALID_SOCKET, CAddress("127.0.0.1"));
        oversized.nVersion = VERSION;
        oversized.vRecv << CMessageHeader("block", MAX_PROTOCOL_MESSAGE_SIZE + 1);
        ProcessMessages(&oversized);
        nFail += Check(oversized.fDisconnect,
                       "an oversized message header disconnects the peer") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunNetworkParamsSelfTest()
{
    fflush(stdout);
    printf("network-params self-test\n");

    int nFail = 0;
    std::string strOldDataDir = strSetDataDir;
    try
    {
        SelectChainParams(false);
        nFail += Check(!IsTestNet(), "starts on mainnet after explicit selection") ? 0 : 1;
        nFail += Check(ntohs(GetDefaultPort()) == MAINNET_PORT,
                       "mainnet default P2P port is 8433") ? 0 : 1;
        CAddress mainAddr("127.0.0.1");
        nFail += Check(mainAddr.port == htons(MAINNET_PORT),
                       "mainnet address parsing uses the mainnet default port") ? 0 : 1;
        CMessageHeader mainHeader("ping", 0);
        char mainMagic[4];
        memcpy(mainMagic, mainHeader.pchMessageStart, sizeof(mainMagic));
        uint256 mainGenesis = hashGenesisBlock;
        uint256 mainMerkle = hashGenesisMerkleRoot;
        unsigned int mainNonce = GENESIS_NONCE;

        {
            // The cold-start list: more than the one machine, each a distinct
            // v3 onion. One host down must not leave a new node with nowhere to go.
            std::vector<std::string> seeds;
            BtfSeedOnions(seeds);
            std::set<std::string> distinct(seeds.begin(), seeds.end());
            bool fShape = true;
            for (size_t i = 0; i < seeds.size(); i++)
            {
                size_t dot = seeds[i].find(".onion:");
                fShape = fShape && dot == 56;
            }
            nFail += Check(seeds.size() >= 8 && distinct.size() == seeds.size() && fShape,
                           strprintf("mainnet cold start knows %u distinct v3 onion seeds", (unsigned)seeds.size()).c_str()) ? 0 : 1;
        }

        SelectChainParams(true);
        nFail += Check(IsTestNet(), "testnet selection is sticky") ? 0 : 1;
        nFail += Check(ntohs(GetDefaultPort()) == TESTNET_PORT,
                       "testnet default P2P port is 18433") ? 0 : 1;
        CAddress testAddr("127.0.0.1");
        nFail += Check(testAddr.port == htons(TESTNET_PORT),
                       "testnet address parsing uses the testnet default port") ? 0 : 1;
        CMessageHeader testHeader("ping", 0);
        nFail += Check(memcmp(mainMagic, testHeader.pchMessageStart, sizeof(mainMagic)) != 0,
                       "testnet message magic differs from mainnet") ? 0 : 1;
        nFail += Check(hashGenesisBlock != mainGenesis &&
                       hashGenesisMerkleRoot != mainMerkle &&
                       GENESIS_NONCE != mainNonce,
                       "testnet genesis constants differ from mainnet") ? 0 : 1;
        nFail += Check(hashGenesisBlock == uint256("0xa9d11c6d697bcb7aea0653bc088b12dcf9f44e732df205162cf085fd9d9963eb") &&
                       hashGenesisMerkleRoot == uint256("0x510b293105e3ff85b8d4c3920e357f85d1a86bf199eb4e7d11f04f380030ec5c") &&
                       GENESIS_NONCE == 3199,
                       "testnet genesis constants are pinned") ? 0 : 1;

        std::string tmp;
        if (!MakeTempDir(tmp))
        {
            nFail += Check(false, "creates a temporary data directory") ? 0 : 1;
        }
        else
        {
            strSetDataDir = tmp;
            SelectChainParams(false);
            std::string mainDir = GetAppDir();
            SelectChainParams(true);
            std::string testDir = GetAppDir();
            nFail += Check(mainDir == tmp,
                           "mainnet uses the selected data directory") ? 0 : 1;
            nFail += Check(testDir == tmp + "/testnet",
                           "testnet stores data below a testnet subdirectory") ? 0 : 1;
            RemoveTree(tmp);
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    strSetDataDir = strOldDataDir;
    SelectChainParams(false);

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static CBlock MakeSizedConsensusBlock(size_t nScriptBytes)
{
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(), CScript() << 1 << 1));
    tx.vout.push_back(CTxOut(0, CScript()));
    tx.vout[0].scriptPubKey.insert(tx.vout[0].scriptPubKey.end(), nScriptBytes, 0);

    CBlock block;
    block.vtx.push_back(tx);
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = GetAdjustedTime();
    block.nBits = bnProofOfWorkLimit.GetCompact();
    block.nNonce = 0;
    return block;
}

// Turn a low-S DER signature (with hash-type byte) into its high-S twin:
// S' = n - S. Verifies against the same key and hash; only the encoding
// rules tell them apart.
static std::vector<unsigned char> HighSTwin(const std::vector<unsigned char>& sig)
{
    static const unsigned char order[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
    unsigned int lenR = sig[3];
    unsigned int lenS = sig[5 + lenR];
    BIGNUM* n = BN_bin2bn(order, 32, NULL);
    BIGNUM* s = BN_bin2bn(&sig[6 + lenR], lenS, NULL);
    BIGNUM* t = BN_new();
    BN_sub(t, n, s);
    std::vector<unsigned char> S(BN_num_bytes(t));
    BN_bn2bin(t, &S[0]);
    if (S[0] & 0x80) S.insert(S.begin(), 0x00);          // DER positive
    BN_free(n); BN_free(s); BN_free(t);
    std::vector<unsigned char> out;
    out.push_back(0x30); out.push_back((unsigned char)(lenR + S.size() + 4));
    out.push_back(0x02); out.push_back((unsigned char)lenR);
    out.insert(out.end(), sig.begin() + 4, sig.begin() + 4 + lenR);
    out.push_back(0x02); out.push_back((unsigned char)S.size());
    out.insert(out.end(), S.begin(), S.end());
    out.push_back(sig.back());                            // hash type
    return out;
}

// Rules v2, each rule with a case it accepts and a case it refuses.
static int RunRulesV2SelfTest()
{
    printf("rules-v2 self-test\n");
    int nFail = 0;
    unsigned int T = RulesV2Time();
    nFail += Check(RULES_V2_TIME_TESTNET < RULES_V2_TIME_MAINNET, "testnet switches before mainnet") ? 0 : 1;
    nFail += Check(RULES_V2_TIME_MAINNET == POW_V2_TIME_MAINNET, "on mainnet rules v2 and PoW v2 switch together") ? 0 : 1;
    nFail += Check(!RulesV2Active(T - 1) && RulesV2Active(T), "the switch is at the activation time, inclusive") ? 0 : 1;

    // ---- signatures: strict DER, low S, and the wallet producing them
    CKey key; key.MakeNewKey();
    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].nValue = 1 * COIN;
    txFrom.vout[0].scriptPubKey << OP_DUP << OP_HASH160 << Hash160(key.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;
    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetHash(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].nValue = 1 * COIN;
    uint256 hash = SignatureHash(txFrom.vout[0].scriptPubKey, txTo, 0, SIGHASH_ALL);

    int nLow = 0, nDer = 0, nSigs = 200;
    std::vector<unsigned char> vchSig;
    for (int i = 0; i < nSigs; i++)
    {
        std::vector<unsigned char> s;
        if (!key.Sign(hash, s)) break;
        s.push_back((unsigned char)SIGHASH_ALL);
        if (IsStrictDERSignature(s)) nDer++;
        if (IsLowSSignature(s)) nLow++;
        vchSig = s;
    }
    nFail += Check(nDer == nSigs, "every signature the wallet makes is strict DER") ? 0 : 1;
    nFail += Check(nLow == nSigs, "every signature the wallet makes is low S (200 of 200)") ? 0 : 1;

    std::vector<unsigned char> vchHigh = HighSTwin(vchSig);
    nFail += Check(IsStrictDERSignature(vchHigh) && !IsLowSSignature(vchHigh),
                   "the high-S twin is well-formed DER but not low S") ? 0 : 1;
    {
        std::vector<unsigned char> a(vchSig.begin(), vchSig.end() - 1), b(vchHigh.begin(), vchHigh.end() - 1);
        nFail += Check(key.Verify(hash, a) && key.Verify(hash, b),
                       "ECDSA itself accepts both twins -- which is the problem") ? 0 : 1;
    }
    txTo.vin[0].scriptSig = CScript() << vchSig << key.GetPubKey();
    nFail += Check(VerifySignature(txFrom, txTo, 0, SIGHASH_ALL, true), "the low-S spend verifies under rules v2") ? 0 : 1;
    txTo.vin[0].scriptSig = CScript() << vchHigh << key.GetPubKey();
    nFail += Check(VerifySignature(txFrom, txTo, 0, SIGHASH_ALL, false), "the high-S twin verifies under the old rules") ? 0 : 1;
    nFail += Check(!VerifySignature(txFrom, txTo, 0, SIGHASH_ALL, true), "the high-S twin is refused under rules v2") ? 0 : 1;
    {
        // a DER shape OpenSSL tolerates and BIP66 does not: a padded R
        std::vector<unsigned char> pad = vchSig;
        pad.insert(pad.begin() + 4, 0x00); pad[3]++; pad[1]++;
        nFail += Check(!IsStrictDERSignature(pad), "a signature with a padded R is not strict DER") ? 0 : 1;
        std::vector<unsigned char> neg = vchSig;
        neg[4] |= 0x80;
        nFail += Check(!IsStrictDERSignature(neg), "a signature with a negative R is not strict DER") ? 0 : 1;
    }

    // ---- BIP34: the coinbase this tree's miners write starts with the height
    {
        int nHeight = 35061;
        CScript cb; cb << nHeight << 0x1d00ffff << CBigNum(7);
        CScript expect = CScript() << nHeight;
        nFail += Check(cb.size() >= expect.size() && std::equal(expect.begin(), expect.end(), cb.begin()),
                       "a coinbase written as <height nBits extranonce> starts with the height") ? 0 : 1;
        CScript old; old << 0x1d00ffff << CBigNum(7);
        nFail += Check(!(old.size() >= expect.size() && std::equal(expect.begin(), expect.end(), old.begin())),
                       "a coinbase without the height does not") ? 0 : 1;
        CScript wrong = CScript() << (nHeight + 1);
        nFail += Check(!std::equal(wrong.begin(), wrong.end(), cb.begin()),
                       "a coinbase with the wrong height does not") ? 0 : 1;
    }

    // ---- retarget: the window covers nInterval intervals from rules v2 on
    {
        // 31 blocks, 120 s apart, except the boundary interval, which is
        // 3600 s wide. Old window (29 intervals) never sees it; the v2
        // window (30) does, so the two disagree -- and only v2 is right
        // about how long the 30 blocks actually took.
        std::vector<CBlockIndex*> v;
        unsigned int nBits = 0x1e0fffff;            // well inside the limit, so easing is visible
        for (int i = 0; i < 31; i++)
        {
            CBlockIndex* p = new CBlockIndex();
            p->nHeight = 29 + i;                    // last is height 59 -> next is 60, a retarget
            p->nBits = nBits;
            p->pprev = i ? v.back() : NULL;
            v.push_back(p);
        }
        // times: block 0 at t0, block 1 at t0+3600 (the wide interval), then +120 each
        unsigned int t0 = T + 100000;
        v[0]->nTime = t0;
        for (int i = 1; i < 31; i++) v[i]->nTime = v[i-1]->nTime + (i == 1 ? 3600 : 120);
        unsigned int nV2 = GetNextWorkRequired(v.back());
        // the same chain, dated before the switch: old window
        for (int i = 0; i < 31; i++) v[i]->nTime -= 200000;
        unsigned int nV1 = GetNextWorkRequired(v.back());
        nFail += Check(nV1 != nV2, "the retarget window changes at the switch") ? 0 : 1;
        // v2: actual = 29*120 + 3600 = 7080 > target 3600 -> easier (bigger target)
        nFail += Check(CBigNum().SetCompact(nV2) > CBigNum().SetCompact(nBits),
                       "rules v2 sees the slow boundary interval and eases difficulty") ? 0 : 1;
        // v1: actual = 29*120 = 3480 < 3600 -> slightly harder
        nFail += Check(CBigNum().SetCompact(nV1) < CBigNum().SetCompact(nBits),
                       "the old window misses it and tightens instead") ? 0 : 1;
        for (size_t i = 0; i < v.size(); i++) delete v[i];
    }

    // ---- relay policy
    {
        CTransaction tx = txTo;
        tx.vin[0].scriptSig = CScript() << vchSig << key.GetPubKey();
        tx.vout[0].scriptPubKey = txFrom.vout[0].scriptPubKey;
        nFail += Check(tx.IsStandard(), "a wallet-shaped transaction is standard") ? 0 : 1;
        CTransaction t2 = tx; t2.vout[0].scriptPubKey = CScript() << OP_TRUE;
        nFail += Check(!t2.IsStandard(), "an output of an unknown shape is not relayed") ? 0 : 1;
        CTransaction t3 = tx; t3.vout[0].scriptPubKey = CScript() << OP_1 << OP_CHECKSIG << OP_CHECKSIG;
        nFail += Check(!t3.IsStandard(), "an output built from bare operators is not relayed") ? 0 : 1;
        CTransaction t4 = tx; t4.vin[0].scriptSig = CScript() << OP_1 << OP_DROP << vchSig << key.GetPubKey();
        nFail += Check(!t4.IsStandard(), "a scriptSig with an operator is not relayed") ? 0 : 1;
        CTransaction t5 = tx;
        for (int i = 0; i < 3000; i++) t5.vout.push_back(txFrom.vout[0]);
        nFail += Check(!t5.IsStandard(), "a transaction over 100 kB is not relayed") ? 0 : 1;
        nFail += Check(MAX_MEMPOOL_TRANSACTIONS >= 1000, "the mempool ceiling leaves room for real traffic") ? 0 : 1;
    }

    // ---- the clock: peers may nudge it, not set it (last: it moves this process's clock)
    {
        int64 before = GetAdjustedTime() - GetTime();
        for (unsigned int ip = 0x0a000001; ip < 0x0a000006; ip++)
            AddTimeData(ip, GetTime() + 5 * 3600);       // five peers, all 5 h ahead
        int64 after = GetAdjustedTime() - GetTime();
        nFail += Check(before == 0 && after == 0, "five peers five hours ahead move the clock by nothing") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// The script interpreter against the ways a scriptSig can try to skip the
// scriptPubKey it is supposed to satisfy. scriptSig and scriptPubKey run as
// one concatenated script (0.1.0), so anything in the scriptSig that changes
// control flow reaches the output's own checks.
// The legacy signature hash as it was written before it stopped copying the
// transaction, kept verbatim as the reference the rewrite must match.
static uint256 SignatureHashReference(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
        return 1;
    CTransaction txTmp(txTo);
    scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));
    for (int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        txTmp.vout.clear();
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
            return 1;
        txTmp.vout.resize(nOut+1);
        for (int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }
    CDataStream ss(SER_GETHASH);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return Hash(ss.begin(), ss.end());
}

// -selftest=sighash-reference -- SignatureHash() against the reference, on
// random transactions, every hash type byte, every input index and one past
// the end, and the three wider compact-size encodings.
static int RunSigHashReferenceSelfTest()
{
    printf("sighash-reference self-test\n");
    int nFail = 0;
    uint64 nSeed = 0x9e3779b97f4a7c15ULL;
    auto rnd = [&nSeed]() -> uint32_t {
        nSeed ^= nSeed << 13; nSeed ^= nSeed >> 7; nSeed ^= nSeed << 17;
        return (uint32_t)(nSeed >> 16);
    };
    auto script = [&rnd](unsigned int nMax) {
        CScript s;
        unsigned int n = rnd() % (nMax + 1);
        for (unsigned int i = 0; i < n; i++)
            s.push_back((rnd() % 7 == 0) ? (unsigned char)OP_CODESEPARATOR : (unsigned char)rnd());
        return s;
    };
    auto randomTx = [&](unsigned int nIns, unsigned int nOuts, unsigned int nScript) {
        CTransaction tx;
        tx.nVersion = (int)rnd();
        tx.vin.resize(nIns);
        for (unsigned int i = 0; i < nIns; i++)
        {
            for (int k = 0; k < 8; k++)
                ((uint32_t*)tx.vin[i].prevout.hash.begin())[k] = rnd();
            tx.vin[i].prevout.n = rnd() % 4 == 0 ? (unsigned int)-1 : rnd();
            tx.vin[i].scriptSig = script(nScript);
            tx.vin[i].nSequence = rnd() % 3 == 0 ? UINT_MAX : rnd();
        }
        tx.vout.resize(nOuts);
        for (unsigned int i = 0; i < nOuts; i++)
        {
            tx.vout[i].nValue = ((int64)rnd() << 32) | rnd();
            tx.vout[i].scriptPubKey = script(nScript);
        }
        tx.nLockTime = (int)rnd();
        return tx;
    };

    unsigned int nCompared = 0, nMismatch = 0;
    auto compare = [&](const CTransaction& tx, const CScript& code, unsigned int nIn, int nHashType) {
        nCompared++;
        if (SignatureHash(code, tx, nIn, nHashType) != SignatureHashReference(code, tx, nIn, nHashType))
        {
            if (nMismatch++ < 5)
                printf("  mismatch: %u in, %u out, nIn %u, hash type 0x%x\n",
                       (unsigned int)tx.vin.size(), (unsigned int)tx.vout.size(), nIn, nHashType);
        }
    };

    for (int t = 0; t < 300; t++)
    {
        CTransaction tx = randomTx(1 + rnd() % 6, rnd() % 7, 60);
        CScript code = script(80);
        for (unsigned int nIn = 0; nIn <= tx.vin.size(); nIn++)
        {
            for (int h = 0; h < 256; h++)
                compare(tx, code, nIn, h);
            for (int r = 0; r < 4; r++)
                compare(tx, code, nIn, (int)rnd());
        }
    }
    nFail += Check(nMismatch == 0, strprintf("%u random cases match the reference", nCompared).c_str()) ? 0 : 1;

    // 0xfd, 0xfe: 300 inputs and outputs, and a 70000-byte script.
    {
        unsigned int nBefore = nMismatch;
        CTransaction tx = randomTx(300, 300, 4);
        tx.vout[5].scriptPubKey.insert(tx.vout[5].scriptPubKey.end(), 70000, (unsigned char)OP_NOP);
        CScript code = script(80);
        code.insert(code.end(), 70000, (unsigned char)OP_NOP);
        int types[] = { SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
                        SIGHASH_ALL | SIGHASH_ANYONECANPAY, SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY };
        for (unsigned int k = 0; k < 6; k++)
            for (unsigned int nIn = 0; nIn < 300; nIn += 37)
                compare(tx, code, nIn, types[k]);
        compare(tx, code, 5, SIGHASH_SINGLE);
        nFail += Check(nMismatch == nBefore, "wide compact sizes match the reference") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunScriptEvalSelfTest()
{
    printf("script-eval self-test\n");
    int nFail = 0;

    // An output paid to a fresh key, and a spend of it with no signature.
    CKey key;
    key.MakeNewKey();
    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].nValue = 1 * COIN;
    txFrom.vout[0].scriptPubKey << OP_DUP << OP_HASH160 << Hash160(key.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetHash(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].nValue = 1 * COIN;

    struct Case { const char* name; CScript scriptSig; };
    std::vector<Case> cases;
    { CScript s; s << OP_1 << OP_0 << OP_IF;            cases.push_back({"scriptSig ending in an open OP_IF (false branch) cannot spend", s}); }
    { CScript s; s << OP_1 << OP_1 << OP_NOTIF;         cases.push_back({"scriptSig ending in an open OP_NOTIF cannot spend", s}); }
    { CScript s; s << OP_1 << OP_0 << OP_IF << OP_ELSE; cases.push_back({"scriptSig ending in an open OP_ELSE cannot spend", s}); }
    { CScript s; s << OP_1 << OP_RETURN;                cases.push_back({"scriptSig ending in OP_RETURN cannot spend", s}); }
    { CScript s; s << OP_1;                             cases.push_back({"scriptSig of a bare OP_1 cannot spend", s}); }
    { CScript s; s << OP_1 << OP_ENDIF;                 cases.push_back({"scriptSig with a stray OP_ENDIF cannot spend", s}); }
    for (size_t i = 0; i < cases.size(); i++)
    {
        txTo.vin[0].scriptSig = cases[i].scriptSig;
        bool fSpent = VerifySignature(txFrom, txTo, 0, SIGHASH_ALL);
        nFail += Check(!fSpent, cases[i].name) ? 0 : 1;
    }

    // And the honest spend still works: sign it.
    txTo.vin[0].scriptSig = CScript();
    uint256 hash = SignatureHash(txFrom.vout[0].scriptPubKey, txTo, 0, SIGHASH_ALL);
    std::vector<unsigned char> vchSig;
    bool fSigned = key.Sign(hash, vchSig);
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    txTo.vin[0].scriptSig << vchSig << key.GetPubKey();
    nFail += Check(fSigned && VerifySignature(txFrom, txTo, 0, SIGHASH_ALL),
                   "a properly signed spend verifies") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunConsensusLimitsSelfTest()
{
    fflush(stdout);
    printf("consensus-limits self-test\n");

    int nFail = 0;
    try
    {
        nFail += Check(MAX_BLOCK_SIZE == 1000000,
                       "the consensus block-size cap is 1 MB") ? 0 : 1;
        nFail += Check(MAX_BLOCK_SIZE < MAX_SIZE,
                       "the block cap is tighter than the serializer cap") ? 0 : 1;

        CBlock small = MakeSizedConsensusBlock(100);
        nFail += Check(small.CheckSizeLimits(),
                       "a small block is within the consensus size limit") ? 0 : 1;

        CBlock oversized = MakeSizedConsensusBlock(MAX_BLOCK_SIZE);
        unsigned int nSerialized = ::GetSerializeSize(oversized, SER_DISK);
        nFail += Check(nSerialized > MAX_BLOCK_SIZE && nSerialized <= MAX_SIZE,
                       "the test block sits between 1 MB and the old 32 MB cap") ? 0 : 1;
        nFail += Check(!oversized.CheckSizeLimits(),
                       "a block above 1 MB is outside the consensus size limit") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Lengths are read in their shortest form only, and never above MAX_SIZE
// (fuzz-deserialize: a transaction read with a non-canonical input count
// re-encoded to different bytes; a nine-byte length with its high half set
// read as its low half). And a "tx" payload is held and relayed as the
// transaction, not as whatever bytes followed it in the message.
extern map<uint256, CDataStream*> mapOrphanTransactions;

static bool CompactSizeReads(const std::string& bytes, uint64& nOut)
{
    try
    {
        CDataStream ss(bytes.data(), bytes.data() + bytes.size(), SER_NETWORK);
        nOut = ReadCompactSize(ss);
        return ss.empty();
    }
    catch (const std::exception&)
    {
        return false;
    }
}

static int RunSerializeCanonicalSelfTest()
{
    printf("serialize-canonical self-test\n");
    int nFail = 0;
    uint64 n = 0;

    // The shortest form of every width reads; each boundary on both sides.
    nFail += Check(CompactSizeReads(std::string("\xfc", 1), n) && n == 252, "252 in one byte") ? 0 : 1;
    nFail += Check(CompactSizeReads(std::string("\xfd\xfd\x00", 3), n) && n == 253, "253 in three bytes") ? 0 : 1;
    nFail += Check(CompactSizeReads(std::string("\xfd\xff\xff", 3), n) && n == 65535, "65535 in three bytes") ? 0 : 1;
    nFail += Check(CompactSizeReads(std::string("\xfe\x00\x00\x01\x00", 5), n) && n == 65536, "65536 in five bytes") ? 0 : 1;
    std::string strMax("\xfe\x00\x00\x00\x02", 5);    // MAX_SIZE, 0x02000000
    nFail += Check(CompactSizeReads(strMax, n) && n == MAX_SIZE, "MAX_SIZE reads") ? 0 : 1;

    // Longer spellings are refused.
    nFail += Check(!CompactSizeReads(std::string("\xfd\x05\x00", 3), n), "5 in three bytes is refused") ? 0 : 1;
    nFail += Check(!CompactSizeReads(std::string("\xfd\xfc\x00", 3), n), "252 in three bytes is refused") ? 0 : 1;
    nFail += Check(!CompactSizeReads(std::string("\xfe\xff\xff\x00\x00", 5), n), "65535 in five bytes is refused") ? 0 : 1;
    nFail += Check(!CompactSizeReads(std::string("\xff\x05\x00\x00\x00\x00\x00\x00\x00", 9), n),
                   "5 in nine bytes is refused") ? 0 : 1;
    // ... and so is anything above MAX_SIZE, which is where a nine-byte
    // length with its high half set used to be cut down to its low half.
    nFail += Check(!CompactSizeReads(std::string("\xfe\x01\x00\x00\x02", 5), n), "MAX_SIZE + 1 is refused") ? 0 : 1;
    nFail += Check(!CompactSizeReads(std::string("\xff\x05\x00\x00\x00\x01\x00\x00\x00", 9), n),
                   "2^32 + 5 is refused, not read as 5") ? 0 : 1;

    // A transaction: the canonical bytes read and re-encode to themselves; the
    // same transaction with its input count spelled fd 01 00 does not read.
    CTransaction tx;
    tx.vin.push_back(CTxIn(uint256(1234), 0, CScript() << std::vector<unsigned char>(72, 0x30)));
    tx.vout.push_back(CTxOut(COIN, CScript() << OP_DUP << OP_HASH160 << uint160(5) << OP_EQUALVERIFY << OP_CHECKSIG));
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    std::string strTx(ssTx.begin(), ssTx.end());
    {
        CTransaction tx2;
        CDataStream ss(strTx.data(), strTx.data() + strTx.size(), SER_NETWORK);
        ss >> tx2;
        nFail += Check(ss.empty() && tx2.GetHash() == tx.GetHash() && tx2.GetHash() == Hash(strTx.begin(), strTx.end()),
                       "a transaction in its own encoding reads back, and its id is the hash of those bytes") ? 0 : 1;
    }
    std::string strLong = strTx.substr(0, 4) + std::string("\xfd\x01\x00", 3) + strTx.substr(5);
    bool fRead = true;
    try
    {
        CTransaction tx3;
        CDataStream ss(strLong.data(), strLong.data() + strLong.size(), SER_NETWORK);
        ss >> tx3;
    }
    catch (const std::exception&)
    {
        fRead = false;
    }
    nFail += Check(!fRead, "the same transaction with a three-byte input count is refused") ? 0 : 1;

    // An orphan: held as the transaction's own bytes, not the payload's.
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    try
    {
        if (!LoadBlockIndex())
            throw std::runtime_error("LoadBlockIndex failed");
        CNode peer(INVALID_SOCKET, CAddress("127.0.0.1"));
        peer.nVersion = VERSION;
        CDataStream payload(SER_NETWORK);
        payload << tx;
        std::vector<char> vJunk(100000, 'x');
        payload.write(&vJunk[0], vJunk.size());
        CRITICAL_BLOCK(cs_main)
            ProcessMessage(&peer, "tx", payload);
        uint256 hash = tx.GetHash();
        std::map<uint256, CDataStream*>::iterator mi = mapOrphanTransactions.find(hash);
        nFail += Check(mi != mapOrphanTransactions.end(), "a transaction with unknown inputs is held as an orphan") ? 0 : 1;
        nFail += Check(mi != mapOrphanTransactions.end() && mi->second->size() == strTx.size() &&
                       std::string(mi->second->begin(), mi->second->end()) == strTx,
                       "the orphan is held as the transaction's bytes, not the 100 kB that followed it") ? 0 : 1;
        if (mi != mapOrphanTransactions.end())
            EraseOrphanTx(hash);
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// What fuzz-decoders found in the text decoders: a .btf name with its
// padding bits set, hex fields in a descriptor read through sscanf, an onion
// port with a leading zero, and uint256::SetHex indexing its table with a
// signed char.
static int RunDecoderCanonicalSelfTest()
{
    printf("decoder-canonical self-test\n");
    int nFail = 0;

    // .btf: 34 bytes take 55 base32 characters, whose last 3 bits are padding.
    unsigned char pk[32];
    for (int i = 0; i < 32; i++)
        pk[i] = (unsigned char)(3 * i + 1);
    std::string name = btf::Address(pk);
    unsigned char pkOut[32];
    int nVersion = 0;
    nFail += Check(btf::ParseAddressVersion(name, pkOut, nVersion) && nVersion == 1 && memcmp(pk, pkOut, 32) == 0,
                   "a .btf name as encoded parses") ? 0 : 1;
    static const char* B32 = "abcdefghijklmnopqrstuvwxyz234567";
    std::string label = name.substr(0, name.size() - 4);
    int nLast = (int)(strchr(B32, label[label.size() - 1]) - B32);
    int nPaddingTaken = 0;
    for (int pad = 1; pad < 8; pad++)
    {
        std::string other = label.substr(0, label.size() - 1) + B32[nLast | pad] + ".btf";
        if (btf::ParseAddressVersion(other, pkOut, nVersion))
            nPaddingTaken++;
    }
    nFail += Check(nPaddingTaken == 0, "the same key with any padding bit set is not the address") ? 0 : 1;
    std::string upper = name;
    for (size_t i = 0; i < upper.size(); i++)
        upper[i] = (char)toupper((unsigned char)upper[i]);
    nFail += Check(btf::ParseAddress(" " + upper + ".\n", pkOut) && memcmp(pk, pkOut, 32) == 0,
                   "case, white space and a trailing dot are still ignored") ? 0 : 1;

    // Onion endpoints: one normal form per endpoint.
    std::string host = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
    std::string norm, norm2;
    nFail += Check(btf::NormalizeOnionEndpoint(host + ":080", norm) && norm == host + ":80" &&
                   btf::NormalizeOnionEndpoint(host + ":80", norm2) && norm2 == norm,
                   "an onion port with a leading zero normalizes to the number") ? 0 : 1;

    // Descriptor hex: plain hex only. Sign one, then spell a byte below 0x10
    // of its signature as " d" and as "+d", which sscanf("%2x") read as 0d.
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char seckey[32];
    for (int i = 0; i < 32; i++)
        seckey[i] = (unsigned char)(i + 7);
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpub;
    unsigned char xonly[32];
    bool fKey = secp256k1_keypair_create(ctx, &kp, seckey) && secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp) &&
                secp256k1_xonly_pubkey_serialize(ctx, xonly, &xpub);
    std::string desc = fKey ? btf::SignDescriptor(ctx, seckey, std::string(64, 'e'), "meet.btf", 1790000000) : "";
    btf::Descriptor d;
    nFail += Check(!desc.empty() && btf::VerifyDescriptor(ctx, desc, xonly, d), "a signed descriptor verifies") ? 0 : 1;
    size_t nSig = desc.find("\"sig\":\"");
    std::string strUpper = desc;
    if (nSig != std::string::npos)
        for (size_t i = nSig + 7; i < nSig + 7 + 128 && i < strUpper.size(); i++)
            strUpper[i] = (char)toupper((unsigned char)strUpper[i]);
    nFail += Check(nSig != std::string::npos && btf::VerifyDescriptor(ctx, strUpper, xonly, d),
                   "upper-case hex is still hex") ? 0 : 1;
    size_t nByte = std::string::npos;
    for (size_t i = nSig + 7; nSig != std::string::npos && i + 1 < nSig + 7 + 128; i += 2)
        if (desc[i] == '0')
        {
            nByte = i;
            break;
        }
    if (nByte != std::string::npos)
    {
        std::string spaced = desc, plus = desc;
        spaced[nByte] = ' ';
        plus[nByte] = '+';
        nFail += Check(!btf::VerifyDescriptor(ctx, spaced, xonly, d) && !btf::VerifyDescriptor(ctx, plus, xonly, d),
                       "a signature byte spelled \" d\" or \"+d\" is refused") ? 0 : 1;
    }
    else
        printf("  (no signature byte below 0x10 to respell; skipped)\n");
    secp256k1_context_destroy(ctx);

    // uint256::SetHex: a byte from 0x80 up ends the digits, wherever the
    // table sits in memory (it was read at a negative index).
    uint256 h;
    h.SetHex(std::string("12\xc8", 3));
    nFail += Check(h == uint256(0x12), "SetHex stops at a byte above 0x7f") ? 0 : 1;
    h.SetHex(std::string("\xa0" "34", 3));
    nFail += Check(h == 0, "SetHex reads nothing from a string that starts with one") ? 0 : 1;
    h.SetHex(" 0xAbC ");
    nFail += Check(h == uint256(0xabc), "SetHex still takes white space, 0x and either case") ? 0 : 1;

    // EncodeBase58 of nothing is nothing (it indexed an empty vector).
    nFail += Check(EncodeBase58(std::vector<unsigned char>()) == "", "base58 of no bytes is the empty string") ? 0 : 1;

    // An address followed by a NUL and more is not that address (the string
    // overloads read up to the NUL and ignored the rest).
    std::string strAddr = Hash160ToAddress(uint160(4242));
    std::string strTail = strAddr + std::string("\0junk", 5);
    uint160 hAddr;
    bool fScriptAddr = false;
    std::vector<unsigned char> vAddr;
    nFail += Check(AddressToHash160(strAddr, hAddr) && hAddr == uint160(4242), "an address reads") ? 0 : 1;
    nFail += Check(!AddressToHash160(strTail, hAddr) && !DecodeAnyAddress(strTail, hAddr, fScriptAddr) &&
                   !IsValidBitcoinAddress(strTail) && !DecodeBase58Check(strTail, vAddr) && !DecodeBase58(strTail, vAddr),
                   "the same address with a NUL and more after it is refused") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunParseMoneySelfTest()
{
    printf("parse-money self-test\n");
    int nFail = 0;
    struct Case { const char* in; bool ok; int64 val; };
    Case cases[] = {
        {"0.5", true, 50000000LL},
        {"1", true, 100000000LL},
        {"1.23456789", true, 123456789LL},
        {"0.00000001", true, 1LL},
        {"10.00000000", true, 1000000000LL},
        {"1,000", true, 100000000000LL},
        {"1.5 ", true, 150000000LL},
        {"0.123456789", false, 0LL},
        {"1.2.3", false, 0LL},
        {"abc", false, 0LL},
        {"-1", false, 0LL},
        {"1e5", false, 0LL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int64 v = -1;
        bool r = ParseMoney(cases[i].in, v);
        bool pass = (r == cases[i].ok) && (!r || v == cases[i].val);
        char desc[160];
        snprintf(desc, sizeof(desc), "ParseMoney(\"%s\") %s and value matches",
                 cases[i].in, cases[i].ok ? "accepts" : "rejects");
        nFail += Check(pass, desc) ? 0 : 1;
    }
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static std::vector<std::string> g_debugLinesSeen;
static void SelfTestDebugLineSink(const char* pszLine) { g_debugLinesSeen.push_back(pszLine); }

// The accumulator in front of OutputDebugStringA. Driven here against a small
// buffer with a canary behind it, through the exact sequence that overflowed
// the real one: a pending tail, a message that does not fit, then more
// messages. The old code left an unreachable NUL in the buffer at step two,
// never drained again, and at the first message after the buffer filled
// wrote past the array (util.h has the full story).
static int RunDebugLogBufferSelfTest()
{
    printf("debug-log-buffer self-test\n");
    int nFail = 0;

    const size_t CAP = 64;
    const size_t GUARD = 32;
    std::vector<char> storage(CAP + GUARD, (char)0xEE);
    CDebugLineBuffer buf = { &storage[0], CAP, 0 };
    std::vector<std::string>& seen = g_debugLinesSeen;

    #define CANARY_OK() ([&]{ for (size_t k = CAP; k < CAP + GUARD; k++) if (storage[k] != (char)0xEE) return false; return true; }())
    #define FEED(str) DebugLineAppend(buf, str, strlen(str), SelfTestDebugLineSink)

    // 1. pieces of a line are held until the '\n', then delivered as one
    seen.clear();
    FEED("received: inv (37 bytes)  ");
    FEED("01 ");
    FEED("02 ");
    nFail += Check(seen.empty(), "pieces without a newline are held back") ? 0 : 1;
    FEED("\n");
    nFail += Check(seen.size() == 1 && seen[0] == "received: inv (37 bytes)  01 02 \n",
                   "the newline delivers the assembled line") ? 0 : 1;
    nFail += Check(buf.nUsed == 0, "nothing pending after a complete line") ? 0 : 1;

    // 2. two lines in one message, plus a tail
    seen.clear();
    FEED("a\nb\nc");
    nFail += Check(seen.size() == 2 && seen[0] == "a\n" && seen[1] == "b\n",
                   "every complete line in a message is delivered") ? 0 : 1;
    nFail += Check(buf.nUsed == 1 && storage[0] == 'c', "the tail waits at the front") ? 0 : 1;

    // 3. the wedge sequence: 40 pending bytes, then a message that does not fit
    seen.clear();
    buf.nUsed = 0;
    std::string tail(40, 't');
    FEED(tail.c_str());
    std::string big(50, 'B');
    FEED(big.c_str());
    nFail += Check(seen.size() == 1 && seen[0] == tail,
                   "a message that does not fit flushes the pending tail as it is") ? 0 : 1;
    nFail += Check(buf.nUsed == 50, "the new message is pending in full") ? 0 : 1;
    nFail += Check(CANARY_OK(), "canary intact after the overflowing message") ? 0 : 1;
    // the old code never recovered from here; this must keep draining
    seen.clear();
    FEED("\n");
    nFail += Check(seen.size() == 1 && seen[0] == big + "\n" && buf.nUsed == 0,
                   "the buffer keeps draining afterwards") ? 0 : 1;

    // 4. exactly the room left, off by one each way
    seen.clear();
    buf.nUsed = 0;
    std::string fill(CAP - 2, 'f');          // fits: leaves the NUL byte
    FEED(fill.c_str());
    nFail += Check(seen.empty() && buf.nUsed == CAP - 2, "a message of exactly the room fits") ? 0 : 1;
    FEED("x");                               // one more does not
    nFail += Check(seen.size() == 1 && seen[0] == fill && buf.nUsed == 1,
                   "one byte over the room flushes and starts over") ? 0 : 1;
    nFail += Check(CANARY_OK(), "canary intact at the boundary") ? 0 : 1;

    // 5. a message larger than the whole buffer goes straight through
    seen.clear();
    buf.nUsed = 0;
    std::string huge(CAP * 3, 'H');
    FEED(huge.c_str());
    nFail += Check(seen.size() == 1 && seen[0] == huge && buf.nUsed == 0,
                   "a message larger than the buffer is delivered directly") ? 0 : 1;
    nFail += Check(CANARY_OK(), "canary intact after the oversize message") ? 0 : 1;

    // 6. the long run: a full buffer's worth of traffic, many times over
    seen.clear();
    for (int i = 0; i < 20000; i++)
    {
        char line[96];
        snprintf(line, sizeof(line), "line %d of %s\n", i, i % 7 == 0 ? "something longer than usual here" : "x");
        FEED(line);
    }
    nFail += Check(seen.size() == 20000, "20000 lines in, 20000 lines out") ? 0 : 1;
    nFail += Check(buf.nUsed == 0 && CANARY_OK(), "nothing pending and canary intact after the long run") ? 0 : 1;

    #undef FEED
    #undef CANARY_OK

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// PoW v2: the input a RandomX miner hashes, the key it is told, and the
// switch by block time. The last check is the one that matters: a RandomX
// VM created here from nothing but the 32-byte seed_hash -- which is all
// XMRig ever gets -- must reproduce the hash consensus computes.
static int RunPoWV2SelfTest()
{
    printf("pow-v2 self-test\n");
    int nFail = 0;
    unsigned int T = PoWV2Time();

    nFail += Check(PoWVersionAt(T - 1) == 1 && PoWVersionAt(T) == 2 && PoWVersionAt(T + 1) == 2,
                   "the switch is at the activation time, inclusive") ? 0 : 1;
    nFail += Check(POW_V2_TIME_MAINNET > POW_V2_TIME_TESTNET,
                   "testnet switches before mainnet") ? 0 : 1;

    unsigned char hdr[80];
    for (int i = 0; i < 80; i++) hdr[i] = (unsigned char)(0xA0 + i);
    unsigned char in[POW_INPUT_MAX];
    size_t n = PoWInputV2(hdr, in);
    nFail += Check(n == 83, "the v2 input is 83 bytes") ? 0 : 1;
    nFail += Check(memcmp(in, hdr, 36) == 0, "version and previous hash stay at 0..35") ? 0 : 1;
    nFail += Check(in[36] == 0 && in[37] == 0 && in[38] == 0, "three zero bytes at 36..38") ? 0 : 1;
    nFail += Check(memcmp(in + 39, hdr + 76, 4) == 0, "the nonce lands at 39..42, where XMRig writes") ? 0 : 1;
    nFail += Check(memcmp(in + 43, hdr + 36, 32) == 0, "the merkle root follows at 43..74") ? 0 : 1;
    nFail += Check(memcmp(in + 75, hdr + 68, 8) == 0, "time and bits close it at 75..82") ? 0 : 1;

    // version selection reads the header's own nTime
    unsigned char h1[80], h2[80];
    memcpy(h1, hdr, 80); memcpy(h2, hdr, 80);
    unsigned int t1 = T - 1, t2 = T;
    memcpy(h1 + 68, &t1, 4); memcpy(h2 + 68, &t2, 4);
    int v = 0;
    unsigned char out[POW_INPUT_MAX];
    size_t n1 = PoWInputFromHeader(h1, out, &v);
    nFail += Check(n1 == 80 && v == 1 && memcmp(out, h1, 80) == 0, "a pre-switch header hashes as itself (v1)") ? 0 : 1;
    size_t n2 = PoWInputFromHeader(h2, out, &v);
    nFail += Check(n2 == 83 && v == 2, "a post-switch header hashes as the v2 input") ? 0 : 1;

    // the seed is SHA-256 of the v1 key string, 32 bytes
    unsigned char want[32];
    const char* k1 = "Bitflash/RandomX/v1/one-cpu-one-vote";
    SHA256((const unsigned char*)k1, strlen(k1), want);
    nFail += Check(memcmp(PoWSeedV2(), want, 32) == 0 && PoWSeedV2Hex().size() == 64,
                   "the v2 seed is SHA-256 of the v1 key, 64 hex chars") ? 0 : 1;

    // consensus hash of each side of the switch equals the raw call
    uint256 c1 = PoWHashHeader(h1);
    uint256 c2 = PoWHashHeader(h2);
    nFail += Check(c1 == RandomXPoWHash(1, h1, 80), "v1 consensus hash is RandomX(v1 key, header)") ? 0 : 1;
    unsigned char in2[POW_INPUT_MAX];
    PoWInputV2(h2, in2);
    nFail += Check(c2 == RandomXPoWHash(2, in2, 83), "v2 consensus hash is RandomX(v2 key, v2 input)") ? 0 : 1;
    nFail += Check(c1 != c2 && c1 != 0 && c2 != 0, "the two sides of the switch hash differently") ? 0 : 1;

    // a miner VM keyed for v2 agrees with the verifier
    void* vm = RandomXCreateMinerVM(2);
    nFail += Check(vm != NULL && PoWHashHeaderWithVM(vm, h2) == c2, "a v2 miner VM agrees with the verifier") ? 0 : 1;
    RandomXDestroyMinerVM(vm);

    // Independent: RandomX from scratch with only the seed, over the blob.
    // This is exactly what XMRig does with the job it is sent.
    randomx_flags flags = randomx_get_flags();
    randomx_cache* cache = randomx_alloc_cache(flags);
    bool fIndependent = false;
    if (cache) {
        randomx_init_cache(cache, PoWSeedV2(), 32);
        randomx_vm* xvm = randomx_create_vm(flags, cache, NULL);
        if (xvm) {
            unsigned char hash[32];
            randomx_calculate_hash(xvm, in2, 83, hash);
            fIndependent = memcmp(hash, &c2, 32) == 0;
            // and the nonce at 39 is what moves the hash
            unsigned char in3[POW_INPUT_MAX];
            memcpy(in3, in2, 83);
            in3[39] ^= 0x01;
            unsigned char hash3[32];
            randomx_calculate_hash(xvm, in3, 83, hash3);
            fIndependent = fIndependent && memcmp(hash3, hash, 32) != 0;
            randomx_destroy_vm(xvm);
        }
        randomx_release_cache(cache);
    }
    nFail += Check(fIndependent, "a fresh RandomX keyed by seed_hash alone reproduces the consensus hash") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static bool SelfTestReadN(SOCKET s, void* buf, int n)
{
    char* p = (char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = recv(s, p + off, n - off, 0);
        if (r <= 0)
            return false;
        off += r;
    }
    return true;
}

static bool SelfTestWriteN(SOCKET s, const void* buf, int n)
{
    const char* p = (const char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = send(s, p + off, n - off, BTF_SEND_FLAGS);
        if (r <= 0)
            return false;
        off += r;
    }
    return true;
}

static void SelfTestSetSocketTimeout(SOCKET s, int nTimeoutSecs)
{
#ifdef _WIN32
    DWORD tv = (DWORD)nTimeoutSecs * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = nTimeoutSecs;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

#ifdef _WIN32
struct SelfTestWinsock
{
    bool fStarted;
    SelfTestWinsock() : fStarted(false)
    {
        WSADATA wsadata;
        fStarted = (WSAStartup(MAKEWORD(2,2), &wsadata) == 0);
    }
    ~SelfTestWinsock()
    {
        if (fStarted)
            WSACleanup();
    }
};
#endif

static bool RunSocks5HandshakeProbe(std::string& errOut)
{
    errOut.clear();
#ifdef _WIN32
    SelfTestWinsock winsock;
    if (!winsock.fStarted)
    {
        errOut = "could not start Winsock";
        return false;
    }
#endif

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
    {
        errOut = "could not create listener";
        return false;
    }
    SelfTestSetSocketTimeout(listener, 5);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0)
    {
        closesocket(listener);
        errOut = "could not bind/listen on loopback";
        return false;
    }

#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    if (getsockname(listener, (struct sockaddr*)&addr, &addrLen) != 0)
    {
        closesocket(listener);
        errOut = "could not read listener port";
        return false;
    }
    unsigned short proxyPort = ntohs(addr.sin_port);

    bool fServerOk = false;
    std::string serverErr;
    std::string requestedHost;
    unsigned short requestedPort = 0;
    std::thread server([&]() {
        SOCKET s = accept(listener, NULL, NULL);
        if (s == INVALID_SOCKET)
        {
            serverErr = "accept failed";
            return;
        }
        SelfTestSetSocketTimeout(s, 5);

        unsigned char hello[3] = {0,0,0};
        if (!SelfTestReadN(s, hello, sizeof(hello)) ||
            hello[0] != 0x05 || hello[1] != 0x01 || hello[2] != 0x00)
        {
            serverErr = "bad SOCKS5 greeting";
            closesocket(s);
            return;
        }
        unsigned char choice[2] = {0x05, 0x00};
        if (!SelfTestWriteN(s, choice, sizeof(choice)))
        {
            serverErr = "could not write method choice";
            closesocket(s);
            return;
        }

        unsigned char hdr[5] = {0,0,0,0,0};
        if (!SelfTestReadN(s, hdr, sizeof(hdr)) ||
            hdr[0] != 0x05 || hdr[1] != 0x01 || hdr[2] != 0x00 || hdr[3] != 0x03)
        {
            serverErr = "CONNECT did not use domain-name address type";
            closesocket(s);
            return;
        }

        unsigned char len = hdr[4];
        std::vector<unsigned char> rest((size_t)len + 2);
        if (!SelfTestReadN(s, &rest[0], (int)rest.size()))
        {
            serverErr = "could not read CONNECT target";
            closesocket(s);
            return;
        }
        requestedHost.assign((const char*)&rest[0], (size_t)len);
        requestedPort = ((unsigned short)rest[len] << 8) | rest[len + 1];

        unsigned char reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
        if (!SelfTestWriteN(s, reply, sizeof(reply)))
        {
            serverErr = "could not write CONNECT reply";
            closesocket(s);
            return;
        }
        fServerOk = true;
        closesocket(s);
    });

    std::string err;
    BtfClearSocks5Proxy();
    bool fClientOk = BtfSetSocks5Proxy(strprintf("127.0.0.1:%u", (unsigned)proxyPort), err);
    SOCKET client = INVALID_SOCKET;
    if (fClientOk)
        client = BtfConnectSocket("relay.example", 443, SOCK_NOSTR, 5);
    if (client != INVALID_SOCKET)
        BtfCloseSocket(client);
    BtfClearSocks5Proxy();
    closesocket(listener);
    server.join();

    if (!fClientOk)
        errOut = strprintf("could not enable proxy: %s", err.c_str());
    else if (client == INVALID_SOCKET)
        errOut = "client SOCKS5 connect failed";
    else if (!fServerOk)
        errOut = serverErr.empty() ? "mock server failed" : serverErr;
    else if (requestedHost != "relay.example" || requestedPort != 443)
        errOut = strprintf("unexpected CONNECT target %s:%u", requestedHost.c_str(), (unsigned)requestedPort);
    else
        return true;
    return false;
}

// A write to a peer that has closed must come back as an error, not end the
// process. This test runs inside the same main() the node runs in, so it
// exercises both halves of the fix: BTF_SEND_FLAGS on the send, and the
// SIGPIPE disposition main() sets for writes that do not go through send().
// On the code before the fix, the plain send below kills the process, and
// the harness sees a missing "ALL TESTS PASSED" instead of a FAIL line.
static int RunSigpipeSelfTest()
{
    printf("sigpipe self-test\n");
    int nFail = 0;
#ifdef _WIN32
    SelfTestWinsock winsock;
    nFail += Check(winsock.fStarted, "Winsock started") ? 0 : 1;
#endif
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool fUp = listener != INVALID_SOCKET
        && ::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 0
        && listen(listener, 1) == 0;
#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    fUp = fUp && getsockname(listener, (struct sockaddr*)&addr, &addrLen) == 0;
    nFail += Check(fUp, "loopback listener up") ? 0 : 1;

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bool fConn = fUp && client != INVALID_SOCKET
        && connect(client, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    SOCKET server = fConn ? accept(listener, NULL, NULL) : INVALID_SOCKET;
    nFail += Check(fConn && server != INVALID_SOCKET, "client connected, server accepted") ? 0 : 1;

    // The peer goes away.
    if (server != INVALID_SOCKET)
        closesocket(server);
    Sleep(100);

    // Writes into the void: the first may be accepted into the buffer (the
    // RST arrives after it), the ones after it must fail -- and the process
    // must still be here to see that.
    int nErr = 0;
    int nLastErrno = 0;
    for (int i = 0; i < 8 && nErr == 0; i++)
    {
        char c = 'x';
        int r = send(client, &c, 1, BTF_SEND_FLAGS);
        if (r < 0) { nErr++; nLastErrno = WSAGetLastError(); }
        Sleep(50);
    }
    nFail += Check(nErr > 0, "send to a closed peer returns an error with BTF_SEND_FLAGS") ? 0 : 1;
#ifndef _WIN32
    nFail += Check(nLastErrno == EPIPE || nLastErrno == ECONNRESET,
                   "the error is EPIPE or ECONNRESET, not a dead process") ? 0 : 1;
    // And the same without the flag: only main()'s SIG_IGN stands between
    // this write and the end of the process.
    nErr = 0;
    for (int i = 0; i < 8 && nErr == 0; i++)
    {
        char c = 'y';
        if (send(client, &c, 1, 0) < 0) nErr++;
        Sleep(50);
    }
    nFail += Check(nErr > 0, "a plain send to a closed peer returns an error too (SIGPIPE ignored)") ? 0 : 1;
#endif
    if (client != INVALID_SOCKET) closesocket(client);
    if (listener != INVALID_SOCKET) closesocket(listener);

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunSocks5ProxySelfTest()
{
    printf("socks5-proxy self-test\n");
    int nFail = 0;
    std::string host, err;
    unsigned short port = 0;

    nFail += Check(BtfParseSocks5Proxy("127.0.0.1:9050", host, port, err) &&
                   host == "127.0.0.1" && port == 9050,
                   "parses local Tor proxy endpoint") ? 0 : 1;
    nFail += Check(BtfParseSocks5Proxy("localhost:9050", host, port, err) &&
                   host == "localhost" && port == 9050,
                   "parses hostname proxy endpoint") ? 0 : 1;
    nFail += Check(BtfParseSocks5Proxy("[::1]:9050", host, port, err) &&
                   host == "::1" && port == 9050,
                   "parses bracketed IPv6 proxy endpoint") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("::1:9050", host, port, err),
                   "rejects unbracketed IPv6 proxy endpoint") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost", host, port, err),
                   "rejects missing port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:0", host, port, err),
                   "rejects zero port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:70000", host, port, err),
                   "rejects out-of-range port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:999999999999999999999999999999", host, port, err),
                   "rejects overflowing port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("user:pass@localhost:9050", host, port, err),
                   "rejects unsupported authenticated proxy syntax") ? 0 : 1;
    nFail += Check(BtfIsTorOnionHost("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion") &&
                   BtfIsTorOnionHost("Relay.Example.ONION.") &&
                   !BtfIsTorOnionHost("relay.example") &&
                   !BtfIsTorOnionHost(".onion"),
                   "detects .onion hosts without accepting lookalikes") ? 0 : 1;
    std::string onion;
    nFail += Check(btf::NormalizeOnionEndpoint("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD.onion.:8433", onion) &&
                   onion == "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:8433",
                   "normalizes v3 onion peer endpoint") ? 0 : 1;
    nFail += Check(!btf::NormalizeOnionEndpoint("short.onion:8433", onion) &&
                   !btf::NormalizeOnionEndpoint("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:0", onion) &&
                   !btf::NormalizeOnionEndpoint("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc1.onion:8433", onion),
                   "rejects malformed onion peer endpoints") ? 0 : 1;

    BtfClearSocks5Proxy();
    nFail += Check(!BtfSocks5ProxyEnabled(), "starts disabled after clear") ? 0 : 1;
    nFail += Check(BtfSetSocks5Proxy("127.0.0.1:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfSocks5ProxyName() == "127.0.0.1:9050",
                   "enables parsed SOCKS5 proxy") ? 0 : 1;
    BtfClearSocks5Proxy();
    nFail += Check(!BtfSocks5ProxyEnabled(), "clear disables proxy") ? 0 : 1;

    nFail += Check(BtfSetSocks5Proxy("[::1]:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfSocks5ProxyName() == "[::1]:9050",
                   "enables bracketed IPv6 proxy endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfEnableTorProxy("", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfTorProxyEnabled() &&
                   BtfSocks5ProxyName() == "127.0.0.1:9050",
                   "enables Tor mode on the default local SOCKS5 endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfEnableTorProxy("[::1]:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfTorProxyEnabled() &&
                   BtfSocks5ProxyName() == "[::1]:9050",
                   "enables Tor mode on a custom IPv6 endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfSetSocks5Proxy("127.0.0.1:9051", err) &&
                   BtfSocks5ProxyEnabled() &&
                   !BtfTorProxyEnabled(),
                   "plain SOCKS5 mode is distinct from Tor mode") ? 0 : 1;
    BtfClearSocks5Proxy();

    std::string handshakeErr;
    bool fHandshakeOk = RunSocks5HandshakeProbe(handshakeErr);
    nFail += Check(fHandshakeOk, handshakeErr.empty() ?
                   "completes SOCKS5 domain-name CONNECT handshake" :
                   strprintf("completes SOCKS5 domain-name CONNECT handshake (%s)",
                             handshakeErr.c_str()).c_str()) ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// --- reply-parsers: what the fuzz-tor-control, fuzz-socks5, fuzz-rpc-* and
// fuzz-http-client harnesses feed, and what they found -----------------------

bool BtfTorReadReply(SOCKET s, BtfTorReply& out);                       // tor.cpp
bool BtfNostrReadRelayStream(SOCKET s, size_t nMax, vector<string>& vMsgOut);   // nostr.cpp
bool JsonRpcRecvRequest(SOCKET s, std::string& out, int nTimeoutSecs);   // jsonrpc.cpp

// A connected pair of loopback TCP sockets (no socketpair on Windows):
// write the other side's bytes into b, shut it, hand a to the code under test.
static bool SelfTestLoopbackPair(SOCKET& a, SOCKET& b)
{
    a = b = INVALID_SOCKET;
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET)
        return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    if (::bind(l, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(l, 1) != 0 ||
        getsockname(l, (struct sockaddr*)&addr, &len) != 0)
    {
        closesocket(l);
        return false;
    }
    a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (a == INVALID_SOCKET || connect(a, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        if (a != INVALID_SOCKET)
            closesocket(a);
        closesocket(l);
        a = INVALID_SOCKET;
        return false;
    }
    b = accept(l, NULL, NULL);
    closesocket(l);
    if (b == INVALID_SOCKET)
    {
        closesocket(a);
        a = INVALID_SOCKET;
        return false;
    }
    SelfTestSetSocketTimeout(a, 5);
    SelfTestSetSocketTimeout(b, 5);
    return true;
}

// The peer's bytes, sent and the sending side shut, on a fresh pair.
struct SelfTestPeer
{
    SOCKET node, peer;
    bool fOk;
    explicit SelfTestPeer(const std::string& bytes) : node(INVALID_SOCKET), peer(INVALID_SOCKET), fOk(false)
    {
        if (!SelfTestLoopbackPair(node, peer))
            return;
        fOk = bytes.empty() || SelfTestWriteN(peer, bytes.data(), (int)bytes.size());
#ifdef _WIN32
        shutdown(peer, SD_SEND);
#else
        shutdown(peer, SHUT_WR);
#endif
    }
    ~SelfTestPeer()
    {
        if (node != INVALID_SOCKET) closesocket(node);
        if (peer != INVALID_SOCKET) closesocket(peer);
    }
    // What the node wrote, without waiting for more than is already there.
    std::string Received()
    {
        std::string s;
        char buf[4096];
        SelfTestSetSocketTimeout(peer, 1);
        for (;;)
        {
            int n = recv(peer, buf, sizeof(buf), 0);
            if (n <= 0)
                break;
            s.append(buf, n);
        }
        return s;
    }
};

static std::string SelfTestB64(const std::string& in)
{
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    unsigned int val = 0;
    int bits = -6;
    for (size_t i = 0; i < in.size(); i++)
    {
        val = (val << 8) + (unsigned char)in[i];
        bits += 8;
        while (bits >= 0)
        {
            out.push_back(t[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(t[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

static std::string SelfTestWsFrame(unsigned char b0, const std::string& payload)
{
    std::string f;
    f += (char)b0;
    if (payload.size() < 126)
        f += (char)payload.size();
    else
    {
        f += (char)126;
        f += (char)(payload.size() >> 8);
        f += (char)(payload.size() & 0xff);
    }
    return f + payload;
}

static int RunReplyParsersSelfTest()
{
    printf("reply-parsers self-test\n");
    int nFail = 0;
#ifdef _WIN32
    SelfTestWinsock winsock;
#endif

    // ---- Tor control port
    {
        BtfTorReply r;
        size_t pos = 0;
        std::string two = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=x SUMMARY=\"Asking \\\"x\\\"\"\r\n250 OK\r\n515 no\r\n";
        nFail += Check(BtfTorReadReplyBuffer(two, pos, r) && r.nCode == 250 && r.vLines.size() == 2 &&
                       r.vLines[1] == "OK", "Tor: a multi-line reply is read whole") ? 0 : 1;
        int pct = -1;
        std::string summary;
        nFail += Check(BtfTorParseBootstrap(r, pct, summary) && pct == 25 && summary == "Asking \"x\"",
                       "Tor: bootstrap percentage and quoted summary") ? 0 : 1;
        BtfTorReply r2;
        nFail += Check(BtfTorReadReplyBuffer(two, pos, r2) && r2.nCode == 515 && pos == two.size(),
                       "Tor: the next reply starts where the last one ended") ? 0 : 1;
        {
            SelfTestPeer p(two);
            BtfTorReply viaSocket;
            nFail += Check(p.fOk && BtfTorReadReply(p.node, viaSocket) && viaSocket.nCode == r.nCode &&
                           viaSocket.vLines == r.vLines, "Tor: the socket reader reads the same reply") ? 0 : 1;
        }

        pos = 0;
        std::string mixed = "250-a\r\n551 b\r\n";
        nFail += Check(!BtfTorReadReplyBuffer(mixed, pos, r), "Tor: lines with different codes are malformed") ? 0 : 1;
        pos = 0;
        std::string data = "250+config-text=\r\nSocksPort 9050\r\n..x\r\n.\r\n250 OK\r\n";
        nFail += Check(BtfTorReadReplyBuffer(data, pos, r) && r.vLines.size() == 2 &&
                       r.vLines[0] == "config-text=\nSocksPort 9050\n.x", "Tor: a data block, dots unescaped") ? 0 : 1;

        const char* bad[] = {
            "551-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n551 no\r\n",   // not a 250
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=-5 TAG=x\r\n250 OK\r\n",
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=101 TAG=x\r\n250 OK\r\n",
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=99999999999 TAG=x\r\n250 OK\r\n",
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=1x TAG=x\r\n250 OK\r\n",
            "250-something-else PROGRESS=100\r\n250 OK\r\n",
        };
        bool fAllRefused = true;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            pos = 0;
            pct = -1;
            if (BtfTorReadReplyBuffer(bad[i], pos, r) && BtfTorParseBootstrap(r, pct, summary))
                fAllRefused = false;
        }
        nFail += Check(fAllRefused, "Tor: no bootstrap percentage from an error, a non-number or the wrong line") ? 0 : 1;
        pos = 0;
        std::string ctl = std::string("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=5 SUMMARY=\"a\x1b[2Jb\"\r\n250 OK\r\n");
        nFail += Check(BtfTorReadReplyBuffer(ctl, pos, r) && BtfTorParseBootstrap(r, pct, summary) &&
                       summary == "a?[2Jb", "Tor: the summary reaches the screen without control characters") ? 0 : 1;

        std::string ep;
        std::string onion = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        nFail += Check(BtfTorHostnameEndpoint(onion + "\r\n", 8434, ep) && ep == onion + ":8434",
                       "Tor: hostname file to endpoint") ? 0 : 1;
        nFail += Check(!BtfTorHostnameEndpoint("evil.example\n", 8434, ep) &&
                       !BtfTorHostnameEndpoint(std::string("abc\0", 4) + onion, 8434, ep) &&
                       !BtfTorHostnameEndpoint(onion, 0, ep),
                       "Tor: a hostname file without a v3 onion name is refused") ? 0 : 1;
        std::vector<std::string> br = BtfParseBridgeLines("Bridge # retired obfs4 1.2.3.4:1\nBridge snowflake 192.0.2.3:80 x\n");
        nFail += Check(br.size() == 1 && br[0] == "snowflake 192.0.2.3:80 x",
                       "Tor: 'Bridge # ...' is a comment, not a bridge") ? 0 : 1;
    }

    // ---- SOCKS5
    {
        std::string host = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        std::string v6 = std::string("\x05\x00\x05\x00\x00\x04", 6) + std::string(16, '\x01') + std::string("\x20\xf1", 2) + "after";
        {
            SelfTestPeer p(v6);
            bool fOk = p.fOk && BtfSocks5Handshake(p.node, host, 8433);
            char rest[5] = {0};
            nFail += Check(fOk && SelfTestReadN(p.node, rest, 5) && memcmp(rest, "after", 5) == 0,
                           "SOCKS5: an IPv6 reply is read in full and nothing past it") ? 0 : 1;
            std::string sent = p.Received();
            nFail += Check(sent.size() == 3 + 7 + host.size() && sent[6] == 0x03 && sent.compare(8, host.size(), host) == 0,
                           "SOCKS5: CONNECT by name, never a local lookup") ? 0 : 1;
        }
        {
            SelfTestPeer p(std::string("\x05\x00\x05\x00\x00\x03\x03" "abc" "\x00\x50", 12));
            nFail += Check(p.fOk && BtfSocks5Handshake(p.node, host, 8433), "SOCKS5: a domain-name reply") ? 0 : 1;
        }
        {
            SelfTestPeer p(std::string("\x05\x00\x05\x00\x00\x01\x7f", 7));
            nFail += Check(p.fOk && !BtfSocks5Handshake(p.node, host, 8433), "SOCKS5: a truncated reply fails") ? 0 : 1;
        }
        {
            SelfTestPeer p(std::string("\x05\x02", 2));
            nFail += Check(p.fOk && !BtfSocks5Handshake(p.node, host, 8433), "SOCKS5: a proxy that wants a password fails") ? 0 : 1;
        }
        {
            SelfTestPeer p(std::string("\x05\x00\x05\x00\x00\x09", 6));
            nFail += Check(p.fOk && !BtfSocks5Handshake(p.node, host, 8433), "SOCKS5: an unknown address type fails") ? 0 : 1;
        }
    }

    // ---- JSON-RPC server
    {
        size_t n = 0;
        nFail += Check(JsonRpcRequestLength("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n{}", n) == -1,
                       "RPC: a negative Content-Length is refused (it ended the read early)") ? 0 : 1;
        nFail += Check(JsonRpcRequestLength("POST / HTTP/1.1\r\nContent-Length: 2\r\ncontent-length: 3\r\n\r\n{}x", n) == -1 &&
                       JsonRpcRequestLength("POST / HTTP/1.1\r\nContent-Length: 2x\r\n\r\n{}", n) == -1 &&
                       JsonRpcRequestLength("POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", n) == -1,
                       "RPC: conflicting, non-numeric or oversized lengths are refused") ? 0 : 1;
        nFail += Check(JsonRpcRequestLength("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n{}", n) == 0 &&
                       JsonRpcRequestLength("POST / HTTP/1.1\r\ncontent-length:2\r\n\r\n{}", n) == 1 && n == 39,
                       "RPC: waits for the body, then has the request") ? 0 : 1;
        nFail += Check(JsonRpcRequestLength("POST /x HTTP/1.1\r\nX-Content-Length: 5\r\n\r\n", n) == 1 &&
                       n == std::string("POST /x HTTP/1.1\r\nX-Content-Length: 5\r\n\r\n").size(),
                       "RPC: only the Content-Length header is a length") ? 0 : 1;

        nFail += Check(JsonNestingWithin("[[[\"]]]]]]]]\"]]]", 3) && !JsonNestingWithin("[[[[1]]]]", 3) &&
                       JsonNestingWithin("{\"a\\\"[[[[\":1}", 1),
                       "JSON: nesting counted outside strings") ? 0 : 1;

        const std::string user = "selftest", pass = "selftest-password-0123456789";
        JsonRpcConfigure(user, pass, "");
        std::string good = "Authorization: Basic " + SelfTestB64(user + ":" + pass) + "\r\n";
        std::string body = "{\"id\":7,\"method\":\"help\",\"params\":[]}";
        std::string len = strprintf("Content-Length: %u\r\n\r\n", (unsigned)body.size());
        std::string reply;
        nFail += Check(JsonRpcHandleRequest("POST / HTTP/1.1\r\n" + len + body, reply) == 401 && reply.empty(),
                       "RPC: no credentials, 401") ? 0 : 1;
        nFail += Check(JsonRpcHandleRequest("POST / HTTP/1.1\r\nAuthorization: Basic " + SelfTestB64(user + ":x") + "\r\n" + len + body, reply) == 401,
                       "RPC: wrong password, 401") ? 0 : 1;
        nFail += Check(JsonRpcHandleRequest("POST /?Authorization: Basic " + SelfTestB64(user + ":" + pass) + " HTTP/1.1\r\n" + len + body, reply) == 401 &&
                       JsonRpcHandleRequest("POST / HTTP/1.1\r\nX-Note: Authorization: Basic " + SelfTestB64(user + ":" + pass) + "\r\n" + len + body, reply) == 401,
                       "RPC: credentials outside an Authorization header line are not credentials") ? 0 : 1;
        nFail += Check(JsonRpcHandleRequest("GET / HTTP/1.1\r\n" + good + "\r\n", reply) == 404,
                       "RPC: right credentials, not a POST, 404") ? 0 : 1;
        nFail += Check(JsonRpcHandleRequest("POST / HTTP/1.1\r\n" + good + len + body, reply) == 200 &&
                       reply.find("\"id\":7") != std::string::npos && reply.find("getinfo") != std::string::npos,
                       "RPC: right credentials, the call is answered") ? 0 : 1;
        nFail += Check(JsonRpcHandleRequest("POST / HTTP/1.1\r\nauthorization:  BASIC " + SelfTestB64(user + ":" + pass) + "\r\n" + len + body, reply) == 200,
                       "RPC: header name and scheme in any case") ? 0 : 1;
        // Deep enough to run any thread's stack out when the reply copied
        // and printed the id back, as it did.
        std::string deep = "{\"id\":" + std::string(200000, '[') + std::string(200000, ']') + ",\"method\":\"help\"}";
        nFail += Check(JsonRpcHandleRequest("POST / HTTP/1.1\r\n" + good + strprintf("Content-Length: %u\r\n\r\n", (unsigned)deep.size()) + deep, reply) == 200 &&
                       reply.find("nests deeper") != std::string::npos,
                       "RPC: a request nested 200000 deep is answered with an error, not a crash") ? 0 : 1;
        // fuzz-rpc-postauth: a prevtx "vout" given as a float (1e70) went
        // through get<int>(), a double-to-int conversion out of range.
        {
            CTransaction txSign;
            txSign.vin.push_back(CTxIn(COutPoint(uint256(1), 0), CScript()));
            txSign.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
            CDataStream ssSign(SER_NETWORK);
            ssSign << txSign;
            std::string hexTx = HexStr(ssSign.begin(), ssSign.end(), false);
            const char* arszVout[] = { "1e70", "-1", "4294967296", "1.5", "\"1\"" };
            bool fAllRefused = true;
            for (size_t i = 0; i < sizeof(arszVout) / sizeof(arszVout[0]); i++)
            {
                std::string sb = "{\"id\":1,\"method\":\"signrawtransaction\",\"params\":[\"" + hexTx +
                                 "\",[{\"txid\":\"" + uint256(1).GetHex() + "\",\"vout\":" + arszVout[i] +
                                 ",\"scriptPubKey\":\"51\"}],[]]}";
                JsonRpcHandleRequest("POST / HTTP/1.1\r\n" + good + strprintf("Content-Length: %u\r\n\r\n", (unsigned)sb.size()) + sb, reply);
                if (reply.find("vout must be a non-negative integer") == std::string::npos)
                    fAllRefused = false;
            }
            nFail += Check(fAllRefused, "RPC: a prevtx vout that is not a non-negative integer is refused") ? 0 : 1;
        }
        // The receive timeout: a caller that connects and says nothing, or
        // stops after part of a request, is let go; a slow but live one is not.
        {
            SOCKET node, peer;
            if (SelfTestLoopbackPair(node, peer))
            {
                std::string req;
                int64 t0 = GetTime();
                bool fGot = JsonRpcRecvRequest(node, req, 2);
                int64 nTook = GetTime() - t0;
                nFail += Check(!fGot && nTook <= 4, "RPC: a silent caller is let go after the timeout") ? 0 : 1;
                closesocket(node);
                closesocket(peer);
            }
            else
                nFail += Check(false, "RPC: loopback pair for the timeout test") ? 0 : 1;
            if (SelfTestLoopbackPair(node, peer))
            {
                std::string full = "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
                std::string req;
                std::thread th([&]() {
                    send(peer, full.data(), 20, 0);
                    Sleep(500);
                    send(peer, full.data() + 20, (int)full.size() - 20, 0);
                });
                bool fGot = JsonRpcRecvRequest(node, req, 2);
                th.join();
                nFail += Check(fGot && req == full, "RPC: a request written in two pieces 500 ms apart is taken") ? 0 : 1;
                closesocket(node);
                closesocket(peer);
            }
            else
                nFail += Check(false, "RPC: loopback pair for the two-piece test") ? 0 : 1;
        }
        JsonRpcConfigure("", "", "");
    }

    // ---- answers to the node's own requests
    {
        LoopbackRpc to;
        nlohmann::json result;
        std::string err;
        int nCode = 0;
        nFail += Check(ParseLoopbackRpcResponse(to, "HTTP/1.1 200 OK\r\n\r\n{\"result\":5,\"error\":null}", result, err, &nCode) &&
                       result == 5, "client: a result") ? 0 : 1;
        nFail += Check(!ParseLoopbackRpcResponse(to, "HTTP/1.1 500 x\r\n\r\n{\"error\":{\"code\":-8,\"message\":\"m\"}}", result, err, &nCode) &&
                       nCode == -8 && err == "m", "client: an error and its code") ? 0 : 1;
        nCode = 0;
        nFail += Check(!ParseLoopbackRpcResponse(to, "HTTP/1.1 500 x\r\n\r\n{\"error\":{\"code\":4294967271,\"message\":\"m\"}}", result, err, &nCode) &&
                       nCode == 0, "client: a code that does not fit an int is not passed on truncated") ? 0 : 1;
        std::string deep = "HTTP/1.1 500 x\r\n\r\n{\"error\":" + std::string(200000, '[') + std::string(200000, ']') + "}";
        nFail += Check(!ParseLoopbackRpcResponse(to, deep, result, err, &nCode),
                       "client: an answer nested 200000 deep is refused, not a crash") ? 0 : 1;
        nFail += Check(!ParseLoopbackRpcResponse(to, "HTTP/1.1 404 Not Found\r\n\r\n<html>[[[[ no such page</html>", result, err, &nCode) &&
                       err.find("no such wallet") != std::string::npos,
                       "client: an HTML 404 page keeps the unknown-wallet hint") ? 0 : 1;
        err.clear();
        nFail += Check(!ParseLoopbackRpcResponse(to, "HTTP/1.1 500 x\r\n\r\n{\"error\":{\"code\":-1,\"message\":\"\"}}", result, err, &nCode) &&
                       !err.empty(),
                       "client: an error with an empty message still gives a reason") ? 0 : 1;

        nFail += Check(invoice::WebhookAnswerOk("HTTP/1.1 204 No Content\r\n", err) &&
                       !invoice::WebhookAnswerOk("HTTP/1.1 2", err) &&
                       !invoice::WebhookAnswerOk("\x1b[2JHTTP/1.1 204", err) && err == "answered ?[2JHTTP/1.1",
                       "webhook: 2xx only, the refusal quoted printable") ? 0 : 1;

        unsigned int ip = 0;
        bool fThrew = false;
        bool fParsed = true;
        try { fParsed = ParseExternalIPResponse("\n\n\r", ip); }
        catch (...) { fThrew = true; }
        nFail += Check(!fThrew && !fParsed, "external IP: a bare \"\\n\\n\\r\" answer, no exception (it killed the node)") ? 0 : 1;
        nFail += Check(!ParseExternalIPResponse("HTTP/1.1 200 OK\r\n\r\n999.1.1.1", ip) &&
                       !ParseExternalIPResponse("HTTP/1.1 200 OK\r\n\r\n1.2.3.4 junk", ip) &&
                       !ParseExternalIPResponse("HTTP/1.1 200 OK\r\n\r\n127.0.0.1", ip),
                       "external IP: not a public dotted quad, refused (999.1.1.1 became 255.255.255.255)") ? 0 : 1;
        unsigned char b[4] = {0, 0, 0, 0};
        bool fIp = ParseExternalIPResponse("HTTP/1.0 200 OK\n\n203.0.113.7\r\n", ip);
        memcpy(b, &ip, 4);
        nFail += Check(fIp && b[0] == 203 && b[1] == 0 && b[2] == 113 && b[3] == 7,
                       "external IP: a plain answer, network byte order") ? 0 : 1;

        std::string up = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        {
            SelfTestPeer p("HTTP/1.1 403 Forbidden\r\nX-Note: 101 \r\n\r\n");
            vector<string> v;
            nFail += Check(p.fOk && !BtfNostrReadRelayStream(p.node, 4, v),
                           "relay: a 403 with \" 101 \" in a header is not an upgrade") ? 0 : 1;
        }
        {
            SelfTestPeer p(up + SelfTestWsFrame(0x89, "hi") + SelfTestWsFrame(0x01, "[\"a\",") + SelfTestWsFrame(0x80, "1]"));
            vector<string> v;
            nFail += Check(p.fOk && BtfNostrReadRelayStream(p.node, 4, v) && v.size() == 1 && v[0] == "[\"a\",1]",
                           "relay: a fragmented message around a ping") ? 0 : 1;
        }
        {
            SelfTestPeer p(up + SelfTestWsFrame(0x89, std::string(126, 'p')) + SelfTestWsFrame(0x81, "x"));
            vector<string> v;
            nFail += Check(p.fOk && BtfNostrReadRelayStream(p.node, 4, v) && v.empty(),
                           "relay: a ping over 125 bytes ends the connection (its pong was corrupt)") ? 0 : 1;
        }
        {
            std::string pings;
            for (int i = 0; i < 4100; i++)
                pings += SelfTestWsFrame(0x8a, "");
            SelfTestPeer p(up + pings + SelfTestWsFrame(0x81, "x"));
            vector<string> v;
            nFail += Check(p.fOk && BtfNostrReadRelayStream(p.node, 4, v) && v.empty(),
                           "relay: endless pongs and nothing else end the connection") ? 0 : 1;
        }
        {
            SelfTestPeer p(up + SelfTestWsFrame(0x83, "x") + SelfTestWsFrame(0xc1, "y") + SelfTestWsFrame(0x80, "z"));
            vector<string> v;
            nFail += Check(p.fOk && BtfNostrReadRelayStream(p.node, 4, v) && v.empty(),
                           "relay: reserved opcodes and RSV bits are refused") ? 0 : 1;
        }
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Checksum framing, misbehavior and bans, DoS scores on blocks, the initial
// block download gate, and confirmation depth in coin selection: the network
// hardening Bitcoin picked up between 0.2 and 0.3.x, done here in one release.
static unsigned int FirstFourOfHash(CDataStream::iterator begin, CDataStream::iterator end)
{
    uint256 hash = Hash(begin, end);
    unsigned int n = 0;
    memcpy(&n, &hash, sizeof(n));
    return n;
}

extern map<uint256, CBlock*> mapOrphanBlocks;   // main.cpp

static int RunNetHardeningSelfTest()
{
    printf("net-hardening self-test\n");
    int nFail = 0;

    // ---- framing: 20 bytes before the peer's version message, 24 after
    {
        nFail += Check(CMessageHeader::SizeOnWire(PROTO_NO_CHECKSUM_VERSION) == 20 &&
                       CMessageHeader::SizeOnWire(PROTO_CHECKSUM_VERSION) == 24,
                       "header is 20 bytes at protocol 101 and 24 at 102") ? 0 : 1;
        CDataStream ssOld(SER_NETWORK, PROTO_NO_CHECKSUM_VERSION);
        CDataStream ssNew(SER_NETWORK, PROTO_CHECKSUM_VERSION);
        ssOld << CMessageHeader("inv", 0);
        ssNew << CMessageHeader("inv", 0);
        nFail += Check(ssOld.size() == 20 && ssNew.size() == 24,
                       "serialization follows the stream version") ? 0 : 1;
        nFail += Check(VERSION == PROTO_CHECKSUM_VERSION,
                       "this build announces the checksum protocol") ? 0 : 1;
    }

    // ---- send side: a fresh node speaks 101 until told otherwise
    CNode nodeOut(INVALID_SOCKET, CAddress());
    {
        CDataStream vHeader(nodeOut.vSend.begin(), nodeOut.vSend.begin() + 20,
                            SER_NETWORK, PROTO_NO_CHECKSUM_VERSION);
        CMessageHeader hdr;
        vHeader >> hdr;
        nFail += Check(hdr.GetCommand() == "version" && hdr.nMessageSize == nodeOut.vSend.size() - 20,
                       "the version message leaves in 101 framing before anything is known") ? 0 : 1;
    }
    // ... and adds the checksum once the streams are at 102
    std::vector<char> vGood;
    {
        nodeOut.vSend.clear();
        nodeOut.vSend.SetVersion(PROTO_CHECKSUM_VERSION);
        std::vector<CInv> vInv(1, CInv(MSG_TX, uint256(12345)));
        nodeOut.PushMessage("inv", vInv);
        bool fOk = nodeOut.vSend.size() > 24;
        CMessageHeader hdr;
        if (fOk)
        {
            CDataStream vHeader(nodeOut.vSend.begin(), nodeOut.vSend.begin() + 24,
                                SER_NETWORK, PROTO_CHECKSUM_VERSION);
            vHeader >> hdr;
            fOk = hdr.GetCommand() == "inv" && hdr.nMessageSize == nodeOut.vSend.size() - 24;
        }
        nFail += Check(fOk, "a message at 102 carries the 24-byte header with the right size") ? 0 : 1;
        nFail += Check(fOk && hdr.nChecksum == FirstFourOfHash(nodeOut.vSend.begin() + 24, nodeOut.vSend.end()),
                       "its checksum is the first four bytes of Hash(payload)") ? 0 : 1;
        nFail += Check(fOk && hdr.nChecksum != 0, "and it is not the zero the old header had there") ? 0 : 1;
        vGood.assign(nodeOut.vSend.begin(), nodeOut.vSend.end());
    }

    // ---- receive side, through ProcessMessages() itself
    {
        CNode nodeIn(INVALID_SOCKET, CAddress());
        nodeIn.vRecv.SetVersion(PROTO_CHECKSUM_VERSION);
        nodeIn.vRecv.insert(nodeIn.vRecv.end(), &vGood[0], &vGood[0] + vGood.size());
        ProcessMessages(&nodeIn);
        nFail += Check(nodeIn.vRecv.empty() && nodeIn.nMisbehavior == 0,
                       "a message with a good checksum is consumed and costs nothing") ? 0 : 1;

        std::vector<char> vBad = vGood;
        vBad[vBad.size() - 1] ^= 0x01;              // one payload bit
        nodeIn.vRecv.insert(nodeIn.vRecv.end(), &vBad[0], &vBad[0] + vBad.size());
        ProcessMessages(&nodeIn);
        nFail += Check(nodeIn.vRecv.empty() && nodeIn.nMisbehavior == 20,
                       "one flipped payload bit is caught, dropped, and costs 20 points") ? 0 : 1;

        // a peer that never announced 102 still gets the 20-byte framing
        CNode nodeOld(INVALID_SOCKET, CAddress());
        nodeOld.vSend.clear();
        std::vector<CInv> vInv(1, CInv(MSG_TX, uint256(777)));
        nodeOld.PushMessage("inv", vInv);
        CNode nodeOldIn(INVALID_SOCKET, CAddress());
        nodeOldIn.vRecv.insert(nodeOldIn.vRecv.end(), nodeOld.vSend.begin(), nodeOld.vSend.end());
        ProcessMessages(&nodeOldIn);
        nFail += Check(nodeOld.vSend.size() == 20 + 1 + 36 && nodeOldIn.vRecv.empty() && nodeOldIn.nMisbehavior == 0,
                       "101 framing still round-trips, so peers on 1.2.27 and earlier keep talking") ? 0 : 1;
    }

    // ---- misbehavior and bans
    {
        int nBannedBefore = BtfBannedCount();
        CNode node(INVALID_SOCKET, CAddress());
        node.strBtfAddr = "selftest-peer-to-ban";
        bool fFirst = node.Misbehaving(50);
        nFail += Check(!fFirst && !node.fDisconnect && node.nMisbehavior == 50,
                       "50 points: noted, still connected") ? 0 : 1;
        bool fSecond = node.Misbehaving(50);
        nFail += Check(fSecond && node.fDisconnect,
                       "100 points: disconnected") ? 0 : 1;
        nFail += Check(BtfIsBanned("selftest-peer-to-ban") && BtfBannedCount() == nBannedBefore + 1,
                       "and its .btf address will not be dialled for a day") ? 0 : 1;
        nFail += Check(!BtfIsBanned("selftest-peer-innocent"),
                       "other addresses are unaffected") ? 0 : 1;

        CNode inbound(INVALID_SOCKET, CAddress(), true);
        bool fDrop = inbound.Misbehaving(100);
        nFail += Check(fDrop && inbound.fDisconnect && BtfBannedCount() == nBannedBefore + 1,
                       "an inbound onion peer is dropped, and there is nothing to ban") ? 0 : 1;
        nFail += Check(!node.Misbehaving(0) && node.nMisbehavior == 100,
                       "zero points change nothing") ? 0 : 1;
    }

    // ---- DoS scores: what a block failure says about the peer that sent it
    {
        CBlock block;
        CTransaction txCoinbase;
        txCoinbase.vin.resize(1);
        txCoinbase.vin[0].prevout.SetNull();
        txCoinbase.vin[0].scriptSig = CScript() << 1 << 2;
        txCoinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
        block.vtx.push_back(txCoinbase);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nTime = GetAdjustedTime();
        block.hashMerkleRoot = block.BuildMerkleTree();

        int nDoS = -1;
        CBlock bFuture = block;
        bFuture.nTime = GetAdjustedTime() + 3 * 60 * 60;
        nFail += Check(!bFuture.CheckBlock(&nDoS) && nDoS == 0,
                       "a block from the future is refused and costs nothing: clocks differ") ? 0 : 1;

        nDoS = -1;
        CBlock bTwo = block;
        bTwo.vtx.push_back(txCoinbase);
        bTwo.hashMerkleRoot = bTwo.BuildMerkleTree();
        nFail += Check(!bTwo.CheckBlock(&nDoS) && nDoS == 100,
                       "two coinbases: 100, no honest node sends that") ? 0 : 1;

        nDoS = -1;
        CBlock bNoCoinbase = block;
        bNoCoinbase.vtx[0].vin[0].prevout.hash = 1;
        bNoCoinbase.hashMerkleRoot = bNoCoinbase.BuildMerkleTree();
        nFail += Check(!bNoCoinbase.CheckBlock(&nDoS) && nDoS == 100,
                       "first transaction not a coinbase: 100") ? 0 : 1;

        nDoS = -1;
        bool fPoW = block.CheckBlock(&nDoS);      // a random header does not meet even the floor
        nFail += Check(!fPoW && nDoS == 50,
                       "proof of work that does not match nBits: 50, two of those and it is out") ? 0 : 1;

        // "already have" through ProcessBlock: useless, not malicious
        nDoS = 0;
        uint256 hash = block.GetHash();
        CBlockIndex* pindexFake = new CBlockIndex();
        mapBlockIndex[hash] = pindexFake;
        // ProcessBlock takes the block and frees it on this path too.
        bool fDup = ProcessBlock(NULL, new CBlock(block), &nDoS);
        mapBlockIndex.erase(hash);
        delete pindexFake;
        // Same for a block already held as an orphan (under the sanitizers a
        // leak or a double free here fails the run).
        CBlock* pheld = new CBlock(block);
        mapOrphanBlocks.insert(make_pair(hash, pheld));
        int nDoSOrphan = -1;
        bool fDupOrphan = ProcessBlock(NULL, new CBlock(block), &nDoSOrphan);
        mapOrphanBlocks.erase(hash);
        delete pheld;
        nFail += Check(!fDupOrphan && nDoSOrphan == 0, "a block we hold as an orphan: refused, no points, freed") ? 0 : 1;

        // A peer's version time at either end of int64 (the difference used
        // to overflow): the adjusted clock stays within the cap.
        const int64 vExtreme[] = { std::numeric_limits<int64>::min(), std::numeric_limits<int64>::max(),
                                   std::numeric_limits<int64>::min() + 1, std::numeric_limits<int64>::max() - 1,
                                   std::numeric_limits<int64>::min() };
        for (int i = 0; i < 5; i++)
            AddTimeData(0x0a0b0c00 + i, vExtreme[i]);
        int64 nSkew = GetAdjustedTime() - GetTime();
        nFail += Check(nSkew <= MAX_TIME_ADJUSTMENT && nSkew >= -MAX_TIME_ADJUSTMENT,
                       "peer times at the ends of int64: no overflow, the clock moves no more than the cap") ? 0 : 1;
        nFail += Check(!fDup && nDoS == 0, "a block we already have: refused, no points") ? 0 : 1;
    }

    // ---- initial block download: peers' heights decide, three blocks of slack
    CBlockIndex* pindexBestSaved = pindexBest;
    int nBestHeightSaved = nBestHeight;
    {
        CBlockIndex tip;
        tip.nHeight = 100;
        pindexBest = &tip;
        nBestHeight = 100;
        nFail += Check(!IsInitialBlockDownload(), "alone: not syncing, a lone node must still mine") ? 0 : 1;

        CNode* peer = new CNode(INVALID_SOCKET, CAddress());
        peer->nStartingHeight = 110;
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(peer);
        nFail += Check(IsInitialBlockDownload(), "a peer ten blocks ahead: syncing") ? 0 : 1;
        peer->nStartingHeight = 102;
        nFail += Check(!IsInitialBlockDownload(), "two blocks ahead is relay lag, not syncing") ? 0 : 1;
        peer->nStartingHeight = 104;
        nFail += Check(IsInitialBlockDownload(), "four blocks ahead is syncing") ? 0 : 1;
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.erase(std::find(vNodes.begin(), vNodes.end(), peer));
        delete peer;
        pindexBest = NULL;
        nFail += Check(IsInitialBlockDownload(), "no chain at all: syncing") ? 0 : 1;
    }

    // ---- coin selection: unconfirmed coins from others are not inputs
    {
        CKey key;
        key.MakeNewKey();
        CRITICAL_BLOCK(cs_mapKeys)
        {
            mapKeys[key.GetPubKey()] = key.GetPrivKey();
            mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
        }
        CScript scriptMine = CScript() << key.GetPubKey() << OP_CHECKSIG;

        // a chain of three index entries: 90 -> 99 -> 100 (tip)
        CBlockIndex idx90, idx99, idx100;
        idx90.nHeight = 90;  idx99.nHeight = 99;  idx100.nHeight = 100;
        idx90.pnext = &idx99; idx99.pnext = &idx100; idx99.pprev = &idx90; idx100.pprev = &idx99;
        pindexBest = &idx100;
        nBestHeight = 100;
        uint256 h90(90), h99(99);
        mapBlockIndex[h90] = &idx90;
        mapBlockIndex[h99] = &idx99;

        // T1: 5 from somebody else, 11 confirmations, already spent by T3
        CWalletTx t1;
        t1.vin.resize(1);
        t1.vin[0].prevout.hash = 1000;
        t1.vout.push_back(CTxOut(5 * COIN, scriptMine));
        t1.hashBlock = h90; t1.nIndex = 0;
        idx90.hashMerkleRoot = t1.GetHash();     // one-transaction block: root == txid
        t1.fSpent = true;
        // T2: 7 from somebody else, unconfirmed
        CWalletTx t2;
        t2.vin.resize(1);
        t2.vin[0].prevout.hash = 2000;
        t2.vout.push_back(CTxOut(7 * COIN, scriptMine));
        // T3: our own change, 3, unconfirmed, spends T1
        CWalletTx t3;
        t3.vin.resize(1);
        t3.vin[0].prevout = COutPoint(t1.GetHash(), 0);
        t3.vout.push_back(CTxOut(3 * COIN, scriptMine));

        CRITICAL_BLOCK(cs_mapWallet)
        {
            mapWallet.clear();
            mapWallet[t1.GetHash()] = t1;
            mapWallet[t2.GetHash()] = t2;
            mapWallet[t3.GetHash()] = t3;
        }
        CWalletTx* pt2 = &mapWallet[t2.GetHash()];
        CWalletTx* pt3 = &mapWallet[t3.GetHash()];
        nFail += Check(pt3->GetDebit() > 0 && pt2->GetDebit() == 0 && pt2->GetDepthInMainChain() == 0,
                       "the fixture reads as intended: T3 is ours, T2 is theirs and unconfirmed") ? 0 : 1;

        std::set<CWalletTx*> setCoins;
        bool fOk = SelectCoins(3 * COIN, setCoins);
        nFail += Check(fOk && setCoins.size() == 1 && setCoins.count(pt3),
                       "3 coins: our own unconfirmed change is used") ? 0 : 1;
        fOk = SelectCoins(6 * COIN, setCoins);
        nFail += Check(!fOk, "6 coins: refused rather than spend the unconfirmed 7 from somebody else") ? 0 : 1;

        // T2 confirms twice
        pt2->hashBlock = h99; pt2->nIndex = 0;
        idx99.hashMerkleRoot = pt2->GetHash();
        nFail += Check(pt2->GetDepthInMainChain() == 2, "T2 now has two confirmations") ? 0 : 1;
        fOk = SelectCoins(6 * COIN, setCoins);
        nFail += Check(fOk && setCoins.count(pt2), "6 coins: the confirmed 7 is now an input") ? 0 : 1;

        mapBlockIndex.erase(h90);
        mapBlockIndex.erase(h99);
        CRITICAL_BLOCK(cs_mapWallet)
            mapWallet.clear();
        CRITICAL_BLOCK(cs_mapKeys)
        {
            mapKeys.erase(key.GetPubKey());
            mapPubKeys.erase(Hash160(key.GetPubKey()));
        }
    }
    pindexBest = pindexBestSaved;
    nBestHeight = nBestHeightSaved;

    printf("\n%s\n", nFail == 0 ? "ALL TESTS PASSED (0 failures)"
                                 : strprintf("%d FAILURE(S)", nFail).c_str());
    return nFail == 0 ? 0 : 1;
}

// Script shapes, the script address, bare multisig signed by one wallet and
// by two halves combined, pay-to-script-hash signing against the redeem
// script, and the relay policy around all of it -- everything 1.2.28 ships
// ahead of the rules v3 switch that gives P2SH its meaning.
static int RunMultisigSelfTest()
{
    printf("multisig self-test\n");
    int nFail = 0;

    // three keys, two in this wallet, one held elsewhere
    CKey keyA, keyB, keyC;
    keyA.MakeNewKey(); keyB.MakeNewKey(); keyC.MakeNewKey();
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[keyA.GetPubKey()] = keyA.GetPrivKey(); mapPubKeys[Hash160(keyA.GetPubKey())] = keyA.GetPubKey();
        mapKeys[keyB.GetPubKey()] = keyB.GetPrivKey(); mapPubKeys[Hash160(keyB.GetPubKey())] = keyB.GetPubKey();
    }
    std::vector<std::vector<unsigned char> > keys;
    keys.push_back(keyA.GetPubKey()); keys.push_back(keyB.GetPubKey()); keys.push_back(keyC.GetPubKey());

    // ---- shapes
    {
        txnouttype t; std::vector<std::vector<unsigned char> > sol;
        CScript p2pkh; p2pkh << OP_DUP << OP_HASH160 << Hash160(keyA.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;
        CScript p2pk; p2pk << keyA.GetPubKey() << OP_CHECKSIG;
        CScript ms; ms.SetMultisig(2, keys);
        CScript p2sh; p2sh.SetPayToScriptHash(ms);
        nFail += Check(SolverTyped(p2pkh, t, sol) && t == TX_PUBKEYHASH && sol.size() == 1 && uint160(sol[0]) == Hash160(keyA.GetPubKey()),
                       "pay-to-pubkey-hash is recognized with its hash") ? 0 : 1;
        nFail += Check(SolverTyped(p2pk, t, sol) && t == TX_PUBKEY && sol[0] == keyA.GetPubKey(),
                       "pay-to-pubkey is recognized with its key") ? 0 : 1;
        nFail += Check(SolverTyped(ms, t, sol) && t == TX_MULTISIG && sol.size() == 5 && sol[0][0] == 2 && sol[4][0] == 3 && sol[2] == keyB.GetPubKey(),
                       "2-of-3 multisig is recognized: m, the keys in order, n") ? 0 : 1;
        nFail += Check(SolverTyped(p2sh, t, sol) && t == TX_SCRIPTHASH && uint160(sol[0]) == Hash160(ms) && p2sh.IsPayToScriptHash(),
                       "pay-to-script-hash is recognized with the script hash") ? 0 : 1;
        CScript bad; bad << OP_3 << keyA.GetPubKey() << keyB.GetPubKey() << OP_2 << OP_CHECKMULTISIG;
        nFail += Check(!SolverTyped(bad, t, sol), "3-of-2 is not a multisig") ? 0 : 1;
        CScript bad2; bad2 << OP_1 << std::vector<unsigned char>(20, 7) << OP_1 << OP_CHECKMULTISIG;
        nFail += Check(!SolverTyped(bad2, t, sol), "a 20-byte push is not a key") ? 0 : 1;
        CScript trailing = ms; trailing << OP_NOP;
        nFail += Check(!SolverTyped(trailing, t, sol), "anything after OP_CHECKMULTISIG breaks the shape") ? 0 : 1;
        nFail += Check(std::string(GetTxnOutputType(TX_MULTISIG)) == "multisig", "the type has a name") ? 0 : 1;

        // ---- the script address
        std::string strAddr = Hash160ToScriptAddress(Hash160(ms));
        uint160 h; bool fScript = false;
        nFail += Check(strAddr[0] == 'C' && DecodeAnyAddress(strAddr, h, fScript) && fScript && h == Hash160(ms),
                       "a script address starts with C and decodes back to the script hash") ? 0 : 1;
        nFail += Check(!AddressToHash160(strAddr, h), "the key-hash decoder refuses it") ? 0 : 1;
        std::string strKeyAddr = PubKeyToAddress(keyA.GetPubKey());
        nFail += Check(DecodeAnyAddress(strKeyAddr, h, fScript) && !fScript && h == Hash160(keyA.GetPubKey()),
                       "a B address decodes as a key hash") ? 0 : 1;
        nFail += Check(RulesV3Time() == RULES_V3_TIME_MAINNET && RulesV3Time() == 1795262400 &&
                       RulesV3Active(GetAdjustedTime()) == ((unsigned int)GetAdjustedTime() >= RulesV3Time()),
                       "rules v3 on mainnet switch on at 2026-11-21 12:00 UTC, not before") ? 0 : 1;
        bool fV3Now = RulesV3Active(GetAdjustedTime());

        // ---- IsMine and relay policy
        nFail += Check(!IsMine(ms), "2-of-3 with one key elsewhere is not 'mine': the wallet cannot spend it alone... " ) ? 0 : 1;
        std::vector<std::vector<unsigned char> > keysAB(keys.begin(), keys.begin() + 2);
        CScript msAB; msAB.SetMultisig(2, keysAB);
        nFail += Check(IsMine(msAB), "...but 2-of-2 with both keys here is") ? 0 : 1;
        nFail += Check(!IsMine(p2sh), "the script hash of an unknown redeem script is not mine") ? 0 : 1;
        CRITICAL_BLOCK(cs_mapKeys)
            mapScripts[Hash160(msAB)] = msAB;
        CScript p2shAB; p2shAB.SetPayToScriptHash(msAB);
        nFail += Check(IsMine(p2shAB), "with the redeem script held and its keys ours, the script hash is mine") ? 0 : 1;

        CTransaction txStd;
        txStd.vin.resize(1);
        txStd.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 1);
        txStd.vout.push_back(CTxOut(1 * COIN, ms));
        nFail += Check(txStd.IsStandard(), "a bare 2-of-3 output is standard (relayed)") ? 0 : 1;
        std::vector<std::vector<unsigned char> > keys4 = keys; keys4.push_back(keyC.GetPubKey());
        CScript ms4; ms4.SetMultisig(2, keys4);
        txStd.vout[0].scriptPubKey = ms4;
        nFail += Check(!txStd.IsStandard(), "four keys is not (relay policy, not validity)") ? 0 : 1;
        txStd.vout[0].scriptPubKey = p2sh;
        nFail += Check(txStd.IsStandard() == fV3Now, "a pay-to-script-hash output is relayed only once rules v3 are live") ? 0 : 1;
        txStd.vout[0].scriptPubKey = p2pkh;
        txStd.vin[0].scriptSig = CScript() << OP_0 << std::vector<unsigned char>(72, 1) << std::vector<unsigned char>(72, 2) << std::vector<unsigned char>(72, 3);
        nFail += Check(txStd.IsStandard(), "a scriptSig with three signatures fits the relay limit") ? 0 : 1;

        // ---- the burn: OP_RETURN
        CScript burn; burn << OP_RETURN << std::vector<unsigned char>(32, 0xAB);
        nFail += Check(SolverTyped(burn, t, sol) && t == TX_NULL_DATA && sol[0].size() == 32 && burn.IsNullData(),
                       "OP_RETURN <32 bytes> is recognized as nulldata with its data") ? 0 : 1;
        CScript burnBare; burnBare << OP_RETURN;
        nFail += Check(burnBare.IsNullData() && SolverTyped(burnBare, t, sol) && t == TX_NULL_DATA && sol[0].empty(),
                       "a bare OP_RETURN is nulldata too") ? 0 : 1;
        CTransaction txSpend;
        txSpend.vin.push_back(CTxIn(COutPoint(uint256(1), 0)));
        txSpend.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 1);
        txSpend.vout.push_back(CTxOut(1, burn));
        nFail += Check(!EvalScript(txSpend.vin[0].scriptSig + CScript(OP_CODESEPARATOR) + burn, txSpend, 0),
                       "and no scriptSig can spend it: the coins are gone") ? 0 : 1;
        txStd.vout.push_back(CTxOut(1 * COIN / 1000, burn));
        nFail += Check(txStd.IsStandard(), "a transaction with one burn output is relayed") ? 0 : 1;
        txStd.vout.push_back(CTxOut(0, burnBare));
        nFail += Check(!txStd.IsStandard(), "two OP_RETURN outputs are not") ? 0 : 1;
        txStd.vout.pop_back();
        CScript burnBig; burnBig << OP_RETURN << std::vector<unsigned char>(81, 1);
        txStd.vout.back().scriptPubKey = burnBig;
        nFail += Check(!txStd.IsStandard(), "81 bytes of data is over the relay limit") ? 0 : 1;
        CScript burn80; burn80 << OP_RETURN << std::vector<unsigned char>(80, 1);
        txStd.vout.back().scriptPubKey = burn80;
        nFail += Check(txStd.IsStandard(), "80 bytes is exactly the limit") ? 0 : 1;
        CScript burnTwoPush; burnTwoPush << OP_RETURN << std::vector<unsigned char>(4, 1) << std::vector<unsigned char>(4, 2);
        nFail += Check(!burnTwoPush.IsNullData(), "OP_RETURN with two pushes is not the shape") ? 0 : 1;
        txStd.vout.pop_back();
    }

    // ---- spending a bare 2-of-3
    CScript ms; ms.SetMultisig(2, keys);
    CTransaction txFrom;
    txFrom.vout.push_back(CTxOut(10 * COIN, ms));
    CTransaction txTo;
    txTo.vin.push_back(CTxIn(COutPoint(txFrom.GetHash(), 0)));
    txTo.vout.push_back(CTxOut(9 * COIN, CScript() << keyA.GetPubKey() << OP_CHECKSIG));
    {
        CTransaction t1 = txTo;
        nFail += Check(SignSignature(txFrom, t1, 0), "the wallet with two of the keys signs a 2-of-3 in one go") ? 0 : 1;
        nFail += Check(VerifySignature(txFrom, t1, 0, 0, true), "and the spend verifies under the strict rules") ? 0 : 1;
        std::vector<std::vector<unsigned char> > pushes;
        CScript::const_iterator pc = t1.vin[0].scriptSig.begin(); opcodetype op; std::vector<unsigned char> vch;
        while (pc < t1.vin[0].scriptSig.end() && t1.vin[0].scriptSig.GetOp(pc, op, vch)) pushes.push_back(vch);
        nFail += Check(pushes.size() == 3 && pushes[0].empty(), "scriptSig is OP_0 then exactly two signatures") ? 0 : 1;
        nFail += Check(t1.IsStandard(), "the spend is standard") ? 0 : 1;

        // two halves: A alone, then C (elsewhere) alone, combined
        CTransaction tA = txTo, tC = txTo;
        CRITICAL_BLOCK(cs_mapKeys)
        {
            mapKeys.erase(keyB.GetPubKey()); mapPubKeys.erase(Hash160(keyB.GetPubKey()));
        }
        uint256 hash = SignatureHash(ms, txTo, 0, SIGHASH_ALL);
        CScript sigA;
        bool fA = Solver(ms, hash, SIGHASH_ALL, sigA);
        nFail += Check(!fA, "one key of two required: the solver reports incomplete") ? 0 : 1;
        tA.vin[0].scriptSig = sigA;
        nFail += Check(!VerifyScriptP2SH(tA.vin[0].scriptSig, ms, tA, 0), "and the half-signed input does not verify") ? 0 : 1;
        // now only C
        CRITICAL_BLOCK(cs_mapKeys)
        {
            mapKeys.erase(keyA.GetPubKey()); mapPubKeys.erase(Hash160(keyA.GetPubKey()));
            mapKeys[keyC.GetPubKey()] = keyC.GetPrivKey(); mapPubKeys[Hash160(keyC.GetPubKey())] = keyC.GetPubKey();
        }
        CScript sigC;
        Solver(ms, hash, SIGHASH_ALL, sigC);
        CScript combined = CombineMultisig(ms, txTo, 0, sigA, sigC);
        tC.vin[0].scriptSig = combined;
        nFail += Check(VerifyScriptP2SH(tC.vin[0].scriptSig, ms, tC, 0) && VerifySignature(txFrom, tC, 0, 0, true),
                       "A's half and C's half combined verify: co-signing across two wallets works") ? 0 : 1;
        CScript again = CombineMultisig(ms, txTo, 0, combined, sigA);
        nFail += Check(again == combined, "combining again with a half already in is a no-op") ? 0 : 1;
        // signatures in wrong key order are put right
        CScript reversed; reversed << OP_0;
        {
            std::vector<std::vector<unsigned char> > pv;
            CScript::const_iterator pc2 = combined.begin();
            while (pc2 < combined.end() && combined.GetOp(pc2, op, vch)) if (!vch.empty()) pv.push_back(vch);
            for (size_t i = pv.size(); i-- > 0;) reversed << pv[i];
        }
        CTransaction tR = txTo; tR.vin[0].scriptSig = reversed;
        nFail += Check(!VerifyScriptP2SH(tR.vin[0].scriptSig, ms, tR, 0), "signatures out of key order do not verify (CHECKMULTISIG is ordered)") ? 0 : 1;
        tR.vin[0].scriptSig = CombineMultisig(ms, txTo, 0, reversed, CScript());
        nFail += Check(VerifyScriptP2SH(tR.vin[0].scriptSig, ms, tR, 0), "CombineMultisig puts them in key order") ? 0 : 1;
        // restore A and B for the P2SH part
        CRITICAL_BLOCK(cs_mapKeys)
        {
            mapKeys.erase(keyC.GetPubKey()); mapPubKeys.erase(Hash160(keyC.GetPubKey()));
            mapKeys[keyA.GetPubKey()] = keyA.GetPrivKey(); mapPubKeys[Hash160(keyA.GetPubKey())] = keyA.GetPubKey();
            mapKeys[keyB.GetPubKey()] = keyB.GetPrivKey(); mapPubKeys[Hash160(keyB.GetPubKey())] = keyB.GetPubKey();
        }
    }

    // ---- pay-to-script-hash: signing against the redeem script
    {
        CScript p2sh; p2sh.SetPayToScriptHash(ms);
        CTransaction txFromS;
        txFromS.vout.push_back(CTxOut(10 * COIN, p2sh));
        CTransaction t = txTo;
        t.vin[0].prevout = COutPoint(txFromS.GetHash(), 0);
        nFail += Check(!SignSignature(txFromS, t, 0), "without the redeem script the wallet cannot sign for the hash") ? 0 : 1;
        CRITICAL_BLOCK(cs_mapKeys)
            mapScripts[Hash160(ms)] = ms;
        nFail += Check(SignSignature(txFromS, t, 0), "with it, it signs") ? 0 : 1;
        std::vector<std::vector<unsigned char> > pushes;
        CScript::const_iterator pc = t.vin[0].scriptSig.begin(); opcodetype op; std::vector<unsigned char> vch;
        while (pc < t.vin[0].scriptSig.end() && t.vin[0].scriptSig.GetOp(pc, op, vch)) pushes.push_back(vch);
        nFail += Check(pushes.size() == 4 && pushes[0].empty() && CScript(pushes[3].begin(), pushes[3].end()) == ms,
                       "scriptSig is OP_0, two signatures, then the redeem script as one push") ? 0 : 1;
        nFail += Check(VerifyScriptP2SH(t.vin[0].scriptSig, p2sh, t, 0),
                       "the rules v3 check runs the redeem script and accepts the spend") ? 0 : 1;
        CTransaction tBad = t;
        tBad.vin[0].scriptSig = CScript() << static_cast<std::vector<unsigned char> >(ms);
        nFail += Check(VerifySignature(txFromS, tBad, 0, 0, true) && !VerifyScriptP2SH(tBad.vin[0].scriptSig, p2sh, tBad, 0),
                       "today's rule accepts the script alone (anyone-can-spend); the rules v3 check refuses it") ? 0 : 1;
        CScript other; other.SetMultisig(1, keys);
        tBad.vin[0].scriptSig = CScript() << OP_0 << pushes[1] << static_cast<std::vector<unsigned char> >(other);
        nFail += Check(!VerifyScriptP2SH(tBad.vin[0].scriptSig, p2sh, tBad, 0), "a different script than the hash names is refused") ? 0 : 1;
        CRITICAL_BLOCK(cs_mapKeys)
            mapScripts.clear();
    }

    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys.erase(keyA.GetPubKey()); mapPubKeys.erase(Hash160(keyA.GetPubKey()));
        mapKeys.erase(keyB.GetPubKey()); mapPubKeys.erase(Hash160(keyB.GetPubKey()));
    }

    printf("\n%s\n", nFail == 0 ? "ALL TESTS PASSED (0 failures)"
                                 : strprintf("%d FAILURE(S)", nFail).c_str());
    return nFail == 0 ? 0 : 1;
}

// The chat's link to a wallet (btfchatwallet.h) against the real RPC server:
// a wallet started the -chatwallet way, a cookie on disk, and the chat's client
// asking it for its balance and an address -- over 127.0.0.1, as in use.
// A loopback port nobody holds right now: the OS picks it. A port drawn from
// the clock could land on a service of the CI machine, which accepted the
// chat's request and never answered ("the wallet sent no answer").
static int FreeLoopbackPort()
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    int nPort = 0;
    if (::bind(s, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
        getsockname(s, (struct sockaddr*)&addr, &addrLen) == 0)
        nPort = ntohs(addr.sin_port);
    closesocket(s);
    return nPort;
}

static int RunChatWalletSelfTest()
{
    printf("chat-wallet self-test\n");
    int nFail = 0;
#ifdef _WIN32
    SelfTestWinsock wsa;
#endif
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    strSetDataDir = tmp;
    if (!LoadWallet())
    {
        printf("LoadWallet failed\n");
        return 1;
    }

    int nPort = FreeLoopbackPort();
    nFail += Check(JsonRpcConfigureCookie(strprintf("%d", nPort)), "-chatwallet configures the RPC with a cookie") ? 0 : 1;
    std::string cookiePath = GetAppDir() + "/.cookie";
    std::string cookie;
    {
        FILE* f = fopen(cookiePath.c_str(), "rb");
        char buf[200] = {0};
        if (f) { size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0; fclose(f); }
        cookie = buf;
    }
    nFail += Check(cookie.compare(0, 11, "__cookie__:") == 0 && cookie.size() >= 11 + 64,
                   "the cookie is a user and a 64-character random password") ? 0 : 1;

    if (_beginthread(ThreadJsonRpcServer, 0, NULL) == -1)
    {
        printf("could not start the RPC server\n");
        return 1;
    }
    Sleep(500);

    btfchat::WalletLinkConfigure(tmp, nPort);
    std::string st, err;
    bool fLinked = btfchat::WalletLinked(st);
    nFail += Check(fLinked && st.find("wallet linked") != std::string::npos,
                   "the chat reaches the wallet with the cookie") ? 0 : 1;
    if (!fLinked) printf("       %s\n", st.c_str());

    std::string addr;
    bool fGot = btfchat::WalletNewAddress(addr, err);
    bool fOurs = false;
    {
        uint160 h;
        bool fScript = false;
        if (fGot && DecodeAnyAddress(addr, h, fScript) && !fScript)
            CRITICAL_BLOCK(cs_mapKeys)
                fOurs = mapPubKeys.count(h) != 0;
    }
    nFail += Check(fGot && fOurs, "and gets a fresh address that is the wallet's own") ? 0 : 1;

    std::string txid;
    nFail += Check(!btfchat::WalletPay(addr, COIN, txid, err) && !err.empty(),
                   "paying from an empty wallet fails, and says why") ? 0 : 1;
    int64_t nRecv = 0;
    int nConf = 0;
    nFail += Check(!btfchat::WalletLookup(std::string(64, '1'), nRecv, nConf, err),
                   "a transaction the wallet never saw is not reported as received") ? 0 : 1;

    // A stale or wrong cookie -- the wallet restarted, or somebody guessed.
    {
        FILE* f = fopen(cookiePath.c_str(), "wb");
        if (f) { fputs("__cookie__:0000000000000000000000000000000000000000000000000000000000000000\n", f); fclose(f); }
    }
    fLinked = btfchat::WalletLinked(st);
    nFail += Check(!fLinked && st.find("refused the cookie") != std::string::npos,
                   "a wrong cookie is refused, and the chat says so") ? 0 : 1;

    btfchat::WalletLinkConfigure(tmp, FreeLoopbackPort());
    fLinked = btfchat::WalletLinked(st);
    nFail += Check(!fLinked && st.find("not answering") != std::string::npos,
                   "no wallet on the port: the chat says it is not answering") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// One signature by `key` over input nIn of tx, against scriptCode, SIGHASH_ALL.
static std::vector<unsigned char> SelfTestSign(CKey& key, const CScript& scriptCode,
                                               const CTransaction& tx, unsigned int nIn)
{
    uint256 hash = SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back((unsigned char)SIGHASH_ALL);
    return sig;
}

// ---- p2pool-share: a share stands or falls on its own --------------------

// A share mined on an easy target: three earlier shares in the window and
// this one, a coinbase committing to the share data and paying the window,
// one more transaction so the merkle branch is not empty.
static p2pool::Share MakeTestShare(const vector<p2pool::WindowShare>& window, unsigned int nShareBits,
                                   unsigned int nBits, int nHeight)
{
    p2pool::Share s;
    s.data.hashPrevShare = Hash(BEGIN(nHeight), END(nHeight));
    s.data.nShareHeight = 4;
    s.data.nShareBits = nShareBits;
    s.data.payoutScript = window.back().payoutScript;

    vector<p2pool::Payout> pay;
    string err;
    p2pool::ComputePayouts(window, CBlock().GetBlockValue(nHeight, 0), pay, err);
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig << nHeight << p2pool::CommitmentPush(s.data.GetHash());
    for (size_t i = 0; i < pay.size(); i++)
        cb.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));

    CTransaction other;
    other.vin.resize(1);
    other.vin[0].prevout = COutPoint(Hash(BEGIN(nBits), END(nBits)), 0);
    other.vout.push_back(CTxOut(COIN, cb.vout[0].scriptPubKey));

    CBlock b;
    b.vtx.push_back(cb);
    b.vtx.push_back(other);
    s.nVersion = 1;
    s.hashPrevBlock = Hash(BEGIN(nShareBits), END(nShareBits));
    s.hashMerkleRoot = b.BuildMerkleTree();
    s.vMerkleBranch = b.GetMerkleBranch(0);
    s.nTime = (unsigned int)GetTime();
    s.nBits = nBits;
    s.coinbase = cb;

    CBigNum bnShare;
    bnShare.SetCompact(nShareBits);
    for (s.nNonce = 0; CBigNum(s.Header().GetPoWHash()) > bnShare; s.nNonce++)
        ;
    return s;
}

static int RunP2PoolShareSelfTest()
{
    printf("p2pool-share self-test\n");
    int nFail = 0;
    RandomXInit();

    CKey a, b, c;
    a.MakeNewKey(); b.MakeNewKey(); c.MakeNewKey();
    auto pay = [](const CKey& k) {
        CScript s;
        s << OP_DUP << OP_HASH160 << Hash160(k.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;
        return vector<unsigned char>(s.begin(), s.end());
    };
    vector<p2pool::WindowShare> window;
    p2pool::WindowShare w;
    w.payoutScript = pay(a); w.work = 300; window.push_back(w);
    w.payoutScript = pay(b); w.work = 300; window.push_back(w);
    w.payoutScript = pay(a); w.work = 300; window.push_back(w);
    w.payoutScript = pay(c); w.work = 300; window.push_back(w);   // this share

    const unsigned int EASY = 0x207fffff, HARD = 0x1d00ffff;
    const int HEIGHT = 61000;
    CBigNum bnFloor;
    bnFloor.SetCompact(EASY);

    p2pool::Share s = MakeTestShare(window, EASY, HARD, HEIGHT);
    bool fBlock = true;
    string err;
    nFail += Check(p2pool::CheckShare(s, window, HEIGHT, bnFloor, fBlock, err) && !fBlock,
                   "a share that pays its window and meets its target is valid, and is not a block") ? 0 : 1;
    if (!err.empty()) printf("       %s\n", err.c_str());

    CDataStream ss(SER_NETWORK);
    ss << s;
    p2pool::Share back;
    ss >> back;
    nFail += Check(back.GetId() == s.GetId() && back.data.GetHash() == s.data.GetHash() &&
                   p2pool::CheckShare(back, window, HEIGHT, bnFloor, fBlock, err),
                   "it survives the wire unchanged") ? 0 : 1;

    p2pool::Share t = s;
    t.coinbase.vout[0].nValue -= 1;
    t.coinbase.vout[1].nValue += 1;
    nFail += Check(!p2pool::CheckShare(t, window, HEIGHT, bnFloor, fBlock, err),
                   "moving one satoshi between miners is refused") ? 0 : 1;

    t = s;
    t.data.payoutScript = pay(b);
    nFail += Check(!p2pool::CheckShare(t, window, HEIGHT, bnFloor, fBlock, err),
                   "share data the coinbase did not commit to is refused") ? 0 : 1;

    t = s;
    t.vMerkleBranch[0] = Hash(BEGIN(HEIGHT), END(HEIGHT));
    nFail += Check(!p2pool::CheckShare(t, window, HEIGHT, bnFloor, fBlock, err),
                   "a coinbase that is not in the merkle root is refused") ? 0 : 1;

    CBigNum bnHarderFloor;
    bnHarderFloor.SetCompact(0x1e00ffff);
    nFail += Check(!p2pool::CheckShare(s, window, HEIGHT, bnHarderFloor, fBlock, err),
                   "a share target easier than the floor is refused") ? 0 : 1;

    t = s;
    t.nNonce++;
    while (CBigNum(t.Header().GetPoWHash()) <= CBigNum().SetCompact(EASY))
        t.nNonce++;
    nFail += Check(!p2pool::CheckShare(t, window, HEIGHT, bnFloor, fBlock, err),
                   "work that misses the share target is refused") ? 0 : 1;

    t = s;
    t.data.vUncles.assign(3, s.GetId());
    nFail += Check(!p2pool::CheckShare(t, window, HEIGHT, bnFloor, fBlock, err),
                   "more than two uncles is refused") ? 0 : 1;

    // Checked on the share alone, so it holds for a share taken on its work
    // in a history too, where a doubled uncle used to count twice.
    t = s;
    t.data.vUncles.assign(2, Hash(BEGIN(HEIGHT), END(HEIGHT)));
    nFail += Check(!p2pool::CheckShareWork(t, bnFloor, fBlock, err) && err == "an uncle named twice",
                   "the same uncle named twice is refused on the share alone") ? 0 : 1;

    // Every payout script of the window becomes an output of every
    // template's coinbase: 64 OP_CHECKMULTISIG count 1280 signature
    // operations there, and a few such shares put every P2Pool block over
    // the block limit. Only an address is a payout script.
    t = s;
    t.data.payoutScript.assign(64, OP_CHECKMULTISIG);
    nFail += Check(!p2pool::CheckShareWork(t, bnFloor, fBlock, err) && err == "bad payout script",
                   "a payout script of signature operations, not an address, is refused") ? 0 : 1;
    {
        CScript p2sh;
        p2sh << OP_HASH160 << uint160(0) << OP_EQUAL;
        vector<unsigned char> v2sh(p2sh.begin(), p2sh.end());
        vector<unsigned char> v2pkh = pay(a);
        vector<unsigned char> vLong = v2pkh;
        vLong.push_back(OP_CHECKSIG);
        nFail += Check(p2pool::IsPayoutScript(v2pkh) && p2pool::IsPayoutScript(v2sh) &&
                       !p2pool::IsPayoutScript(vLong),
                       "a P2PKH or P2SH address is a payout script; anything more is not") ? 0 : 1;
    }

    // A coinbase pays addresses and nothing else, on the share alone: it
    // bounds what a share taken on its work alone can carry, whose payouts
    // are never checked against a window.
    t = s;
    t.coinbase.vout[0].scriptPubKey = CScript() << OP_RETURN << vector<unsigned char>(40, 0x55);
    nFail += Check(!p2pool::CheckShareWork(t, bnFloor, fBlock, err) && err == "a coinbase paying something other than an address",
                   "a coinbase output that is not an address is refused on the share alone") ? 0 : 1;

    t = s;
    t.data.nShareHeight = p2pool::MAX_SHARE_HEIGHT + 1;
    nFail += Check(!p2pool::CheckShareWork(t, bnFloor, fBlock, err) && err == "share height out of range",
                   "a share height past anything real is refused") ? 0 : 1;

    t = s;
    t.coinbase.vin[0].scriptSig << vector<unsigned char>(80, 0x42);
    nFail += Check(!p2pool::CheckShareWork(t, bnFloor, fBlock, err) && err == "a coinbase no block could carry",
                   "a coinbase padded past the 100 bytes any block allows is refused") ? 0 : 1;

    t = s;
    t.coinbase.vin[0].scriptSig << p2pool::CommitmentPush(s.data.GetHash());
    uint256 h;
    nFail += Check(!p2pool::FindCommitment(t.coinbase, h),
                   "a coinbase with two commitments carries none") ? 0 : 1;

    p2pool::Share u = s;
    u.coinbase.vout.clear();
    nFail += Check(!p2pool::CheckShare(u, window, HEIGHT, bnFloor, fBlock, err),
                   "a coinbase paying less than the subsidy is refused") ? 0 : 1;

    p2pool::Share blk = MakeTestShare(window, EASY, EASY, HEIGHT);
    nFail += Check(p2pool::CheckShare(blk, window, HEIGHT, bnFloor, fBlock, err) && fBlock,
                   "a share whose work also meets the block target is a block") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- p2pool-chain: which line, which target, who is paid -----------------

// A main chain of fixed blocks, enough for the share chain to place shares.
class TestMainView : public p2pool::MainView
{
public:
    map<uint256, int> heights;
    unsigned int nBits;
    int nTip;
    int64 nNow;
    bool BlockInfo(const uint256& hash, int& nHeightOut, unsigned int& nNextBitsOut) const
    {
        map<uint256, int>::const_iterator it = heights.find(hash);
        if (it == heights.end())
            return false;
        nHeightOut = it->second;
        nNextBitsOut = nBits;
        return true;
    }
    int TipHeight() const { return nTip; }
    int64 Now() const { return nNow; }
    uint256 BlockAt(int h) const
    {
        for (map<uint256, int>::const_iterator it = heights.begin(); it != heights.end(); ++it)
            if (it->second == h)
                return it->first;
        return 0;
    }
};

// A share on 'parent' that pays exactly what the chain says it must. The
// RandomX work is not done: this chain is built with fCheckPoW off.
static p2pool::Share ChainShare(const p2pool::ShareChain& chain, const TestMainView& main, const uint256& parent,
                                const vector<unsigned char>& payout, unsigned int nTime,
                                const vector<uint256>& uncles = vector<uint256>())
{
    p2pool::Share s;
    s.data.hashPrevShare = parent;
    s.data.nShareHeight = parent == 0 ? 0 : chain.Height(parent) + 1;
    s.data.vUncles = uncles;
    s.data.payoutScript = payout;
    s.data.nShareBits = chain.NextShareBits(parent);

    vector<p2pool::WindowShare> window;
    vector<p2pool::Payout> pay;
    string err;
    chain.WindowFor(s.data, p2pool::WorkOf(s.data.nShareBits), window, err);
    p2pool::ComputePayouts(window, CBlock().GetBlockValue(main.nTip + 1, 0), pay, err);

    s.coinbase.vin.resize(1);
    s.coinbase.vin[0].prevout.SetNull();
    s.coinbase.vin[0].scriptSig << (main.nTip + 1) << (int64)nTime << p2pool::CommitmentPush(s.data.GetHash());
    for (size_t i = 0; i < pay.size(); i++)
        s.coinbase.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));
    s.nVersion = 1;
    s.hashPrevBlock = main.BlockAt(main.nTip);
    s.hashMerkleRoot = s.coinbase.GetHash();
    s.nTime = nTime;
    s.nBits = main.nBits;
    s.nNonce = 0;
    return s;
}

static int RunP2PoolChainSelfTest()
{
    printf("p2pool-chain self-test\n");
    int nFail = 0;
    string err;

    TestMainView main;
    main.nBits = 0x1d00ffff;
    main.nTip = 61000;
    main.nNow = GetTime();
    for (int h = 60990; h <= 61000; h++)
        main.heights[Hash(BEGIN(h), END(h))] = h;
    CBigNum bnFloor;
    bnFloor.SetCompact(0x207fffff);

    auto script = [](unsigned char tag) {
        vector<unsigned char> s;
        s.push_back(0x76); s.push_back(0xa9); s.push_back(20);
        for (int i = 0; i < 20; i++) s.push_back(tag);
        s.push_back(0x88); s.push_back(0xac);
        return s;
    };
    const vector<unsigned char> A = script(1), B = script(2), C = script(3);

    // ---- an empty chain: tip 0, and a first share's window is the share alone.
    // On the heap, over memory filled with garbage first: uint256 does not
    // zero itself, and the miner found a nonzero tip in an empty chain once.
    {
        void* p = ::operator new(sizeof(p2pool::ShareChain));
        memset(p, 0xA5, sizeof(p2pool::ShareChain));
        p2pool::ShareChain* empty = new (p) p2pool::ShareChain(bnFloor, false);
        p2pool::ShareData d;
        d.payoutScript = A;
        vector<p2pool::WindowShare> w;
        nFail += Check(empty->Tip() == 0 && d.hashPrevShare == 0 && empty->WindowFor(d, 5, w, err) && w.size() == 1,
                       "an empty chain has tip 0, and a first share pays itself alone") ? 0 : 1;
        empty->~ShareChain();
        ::operator delete(p);
    }

    // ---- a line, a fork, the heavier side wins
    {
        p2pool::ShareChain chain(bnFloor, false);
        unsigned int t = (unsigned int)main.nNow - 5000;
        p2pool::Share s0 = ChainShare(chain, main, 0, A, t);
        nFail += Check(chain.Add(s0, main, err) && chain.Tip() == s0.GetId() && chain.Height(s0.GetId()) == 0,
                       "the first share starts the chain") ? 0 : 1;
        uint256 prev = s0.GetId();
        vector<uint256> line(1, prev);
        for (int i = 1; i <= 4; i++)
        {
            p2pool::Share s = ChainShare(chain, main, prev, i % 2 ? B : A, t + 10 * i);
            if (!chain.Add(s, main, err)) { printf("       %s\n", err.c_str()); nFail++; }
            prev = s.GetId();
            line.push_back(prev);
        }
        nFail += Check(chain.Tip() == line[4] && chain.Height(line[4]) == 4, "four more on it: the tip is the fifth") ? 0 : 1;

        p2pool::ShareData d;
        d.hashPrevShare = line[4];
        d.payoutScript = C;
        vector<p2pool::WindowShare> w;
        vector<p2pool::Payout> pay;
        bool fWin = chain.WindowFor(d, 100, w, err) && p2pool::ComputePayouts(w, 50 * COIN, pay, err);
        int64 nSum = 0;
        for (size_t i = 0; i < pay.size(); i++) nSum += pay[i].value;
        nFail += Check(fWin && w.size() == 6 && pay.size() == 3 && nSum == 50 * COIN,
                       "a share on that tip pays the five before it and itself, the whole block") ? 0 : 1;

        // A rival branch from the third share, two shares longer: it wins.
        uint256 fork = line[2];
        for (int i = 0; i < 3; i++)
        {
            p2pool::Share s = ChainShare(chain, main, fork, C, t + 25 + 10 * i);
            if (!chain.Add(s, main, err)) { printf("       %s\n", err.c_str()); nFail++; }
            fork = s.GetId();
        }
        nFail += Check(chain.Tip() == fork, "a branch with more work takes the tip") ? 0 : 1;

        p2pool::Share dup = ChainShare(chain, main, line[4], A, t + 60);
        chain.Add(dup, main, err);
        nFail += Check(!chain.Add(dup, main, err) && err == "already have this share", "the same share twice is refused") ? 0 : 1;

        p2pool::Share bad = ChainShare(chain, main, line[4], A, t + 61);
        bad.data.nShareHeight = 9;
        bad.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << p2pool::CommitmentPush(bad.data.GetHash());
        bad.hashMerkleRoot = bad.coinbase.GetHash();
        nFail += Check(!chain.Add(bad, main, err) && err == "wrong share height", "a wrong share height is refused") ? 0 : 1;

        vector<uint256> vMissing;
        p2pool::Share orphan = ChainShare(chain, main, line[4], A, t + 62);
        orphan.data.hashPrevShare = Hash(BEGIN(t), END(t));
        orphan.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << p2pool::CommitmentPush(orphan.data.GetHash());
        orphan.hashMerkleRoot = orphan.coinbase.GetHash();
        nFail += Check(!chain.Add(orphan, main, err, &vMissing) && vMissing.size() == 1 &&
                       vMissing[0] == orphan.data.hashPrevShare,
                       "a share whose parent is unknown is refused, naming the parent to ask for") ? 0 : 1;

        p2pool::Share bits = ChainShare(chain, main, line[4], A, t + 63);
        bits.data.nShareBits = 0x1f00ffff;
        bits.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << p2pool::CommitmentPush(bits.data.GetHash());
        bits.hashMerkleRoot = bits.coinbase.GetHash();
        nFail += Check(!chain.Add(bits, main, err) && err == "wrong share target", "a share target the chain did not set is refused") ? 0 : 1;

        p2pool::Share pay2 = ChainShare(chain, main, line[4], A, t + 64);
        pay2.coinbase.vout[0].nValue -= 1;
        pay2.coinbase.vout[1].nValue += 1;
        pay2.hashMerkleRoot = pay2.coinbase.GetHash();
        nFail += Check(!chain.Add(pay2, main, err) && err == "the coinbase does not pay the window", "a share paying the window wrongly is refused") ? 0 : 1;

        // Work on an old main block is still work: when a share arrives must
        // not decide whether it is valid, or two honest nodes disagree.
        p2pool::Share stale = ChainShare(chain, main, line[4], A, t + 65);
        stale.hashPrevBlock = main.BlockAt(60990);
        p2pool::ShareChain staleProbe = chain;
        nFail += Check(staleProbe.Add(stale, main, err), "a share mined on an old main block is accepted") ? 0 : 1;

        p2pool::Share future = ChainShare(chain, main, line[4], A, (unsigned int)main.nNow + 600);
        nFail += Check(!chain.Add(future, main, err) && err == "here: share time too far in the future", "a share from ten minutes ahead is refused, as this node's own call") ? 0 : 1;

        p2pool::Share old = ChainShare(chain, main, line[4], A, t);
        nFail += Check(!chain.Add(old, main, err) && err == "share time not after the median of the last 11", "a share timed before the median of its line is refused") ? 0 : 1;
    }

    // ---- uncles
    {
        p2pool::ShareChain chain(bnFloor, false);
        unsigned int t = (unsigned int)main.nNow - 5000;
        p2pool::Share s0 = ChainShare(chain, main, 0, A, t);       chain.Add(s0, main, err);
        p2pool::Share s1 = ChainShare(chain, main, s0.GetId(), A, t + 10); chain.Add(s1, main, err);
        p2pool::Share s2a = ChainShare(chain, main, s1.GetId(), A, t + 20); chain.Add(s2a, main, err);
        p2pool::Share s2b = ChainShare(chain, main, s1.GetId(), B, t + 21); chain.Add(s2b, main, err);
        vector<uint256> cand = chain.UncleCandidates(s2a.GetId());
        nFail += Check(cand.size() == 1 && cand[0] == s2b.GetId(),
                       "the share found beside the parent is offered as an uncle") ? 0 : 1;

        p2pool::Share s3 = ChainShare(chain, main, s2a.GetId(), C, t + 30, cand);
        nFail += Check(chain.Add(s3, main, err), "a share naming it as uncle is accepted") ? 0 : 1;
        if (!err.empty()) printf("       %s\n", err.c_str());

        // A node that never received that uncle: the share waits for it,
        // asking for it by id, and is taken once it arrives. Refusing it as
        // bad split two testnet nodes onto separate share chains.
        p2pool::ShareChain lagging(bnFloor, false);
        lagging.Add(s0, main, err); lagging.Add(s1, main, err); lagging.Add(s2a, main, err);
        vector<uint256> vMissingUncle;
        bool fWaits = !lagging.Add(s3, main, err, &vMissingUncle) && err == "an unknown uncle" &&
                      vMissingUncle.size() == 1 && vMissingUncle[0] == s2b.GetId();
        bool fThen = lagging.Add(s2b, main, err) && lagging.Add(s3, main, err) && lagging.Tip() == s3.GetId();
        nFail += Check(fWaits && fThen,
                       "a node missing the uncle asks for it by id, then takes the share") ? 0 : 1;

        p2pool::ShareData d;
        d.hashPrevShare = s3.GetId();
        d.payoutScript = C;
        vector<p2pool::WindowShare> w;
        chain.WindowFor(d, 0 + 1, w, err);
        uint64_t nB = 0, nWork = p2pool::WorkOf(s2b.data.nShareBits);
        for (size_t i = 0; i < w.size(); i++)
            if (w[i].payoutScript == B) nB += w[i].work;
        nFail += Check(nB == nWork / 5 * 4 + (nWork % 5) * 4 / 5, "the uncle is paid 80% of its work") ? 0 : 1;

        p2pool::Share again = ChainShare(chain, main, s3.GetId(), A, t + 40, vector<uint256>(1, s2b.GetId()));
        nFail += Check(!chain.Add(again, main, err) && err == "an uncle already paid as one", "an uncle already paid cannot be named again") ? 0 : 1;
        p2pool::Share anc = ChainShare(chain, main, s3.GetId(), A, t + 41, vector<uint256>(1, s2a.GetId()));
        nFail += Check(!chain.Add(anc, main, err) && err == "an uncle that is an ancestor", "an ancestor cannot be an uncle") ? 0 : 1;

        uint256 prev = s3.GetId();
        for (int i = 0; i < 3; i++)
        {
            p2pool::Share s = ChainShare(chain, main, prev, A, t + 50 + 10 * i);
            chain.Add(s, main, err);
            prev = s.GetId();
        }
        p2pool::Share s2c = ChainShare(chain, main, s1.GetId(), B, t + 22);
        chain.Add(s2c, main, err);
        p2pool::Share late = ChainShare(chain, main, prev, A, t + 90, vector<uint256>(1, s2c.GetId()));
        nFail += Check(!chain.Add(late, main, err) && err == "an uncle too old or not older", "an uncle more than three shares old is refused") ? 0 : 1;
    }

    // ---- the share target follows the pace
    {
        // A chain starts at the floor; the retarget takes it from there.
        CBigNum bnInit = bnFloor;
        for (int pace = 0; pace < 2; pace++)
        {
            p2pool::ShareChain chain(bnFloor, false);
            unsigned int nSpacing = pace == 0 ? 5 : 50;
            unsigned int t = (unsigned int)main.nNow - 50 * p2pool::RETARGET_SHARES - 100;
            uint256 prev = 0;
            bool fOk = true;
            for (unsigned int i = 0; i < p2pool::RETARGET_SHARES && fOk; i++)
            {
                p2pool::Share s = ChainShare(chain, main, prev, (i % 3) ? A : B, t + nSpacing * i);
                fOk = chain.Add(s, main, err);
                prev = s.GetId();
            }
            if (!fOk) printf("       %s\n", err.c_str());
            CBigNum bnNext;
            bnNext.SetCompact(chain.NextShareBits(prev));
            if (pace == 0)
                nFail += Check(fOk && bnNext * 2 <= bnInit + bnInit / 1000 && bnNext * 2 >= bnInit - bnInit / 1000,
                               "720 shares at 5 s instead of 10: the target halves") ? 0 : 1;
            else
                nFail += Check(fOk && bnNext == CBigNum().SetCompact(bnFloor.GetCompact()),
                               "720 shares at 50 s: the target stays at the floor, never easier") ? 0 : 1;
        }
    }

    // ---- past MAX_CHAIN_SHARES side lines are dropped, never a share refused:
    // refusing made a share's validity depend on what else a node held, and
    // two nodes holding different side lines parted ways.
    {
        p2pool::ShareChain chain(bnFloor, false);
        unsigned int t = (unsigned int)main.nNow - 100000;
        uint256 prev = 0;
        vector<uint256> line;
        for (int i = 0; i < 20; i++)
        {
            p2pool::Share s = ChainShare(chain, main, prev, A, t + 10 * i);
            chain.Add(s, main, err);
            prev = s.GetId();
            line.push_back(prev);
        }
        // Siblings of the eleventh share, one second apart.
        bool fAll = true;
        for (unsigned int n = 0; n < p2pool::MAX_CHAIN_SHARES + 50 && fAll; n++)
        {
            p2pool::Share s = ChainShare(chain, main, line[9], script((unsigned char)(10 + n % 200)), t + 200 + n);
            fAll = chain.Add(s, main, err);
        }
        if (!fAll) printf("       %s\n", err.c_str());
        bool fLine = true;
        for (size_t i = 0; i < line.size(); i++)
            fLine = fLine && chain.Has(line[i]);
        nFail += Check(fAll && chain.Size() <= p2pool::MAX_CHAIN_SHARES && chain.Tip() == line[19] && fLine,
                       "side shares past the cap are all taken, the lightest dropped, the tip's line kept") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- p2pool-sync: a starting node takes a peer's history -----------------
static int RunP2PoolSyncSelfTest()
{
    printf("p2pool-sync self-test\n");
    int nFail = 0;
    string err;

    TestMainView main;
    main.nBits = 0x1d00ffff;
    main.nTip = 61000;
    main.nNow = GetTime();
    for (int h = 60990; h <= 61000; h++)
        main.heights[Hash(BEGIN(h), END(h))] = h;
    CBigNum bnFloor;
    bnFloor.SetCompact(0x207fffff);
    auto script = [](unsigned char tag) {
        vector<unsigned char> s;
        s.push_back(0x76); s.push_back(0xa9); s.push_back(20);
        for (int i = 0; i < 20; i++) s.push_back(tag);
        s.push_back(0x88); s.push_back(0xac);
        return s;
    };

    // A running chain, longer than a history, with an uncle every 50 shares.
    p2pool::ShareChain a(bnFloor, false);
    unsigned int nShares = p2pool::HISTORY_SHARES + 200;
    unsigned int t = (unsigned int)main.nNow - 10 * nShares - 100;
    uint256 prev = 0;
    bool fBuilt = true;
    for (unsigned int i = 0; i < nShares && fBuilt; i++)
    {
        vector<uint256> uncles;
        if (i % 50 == 2)
            uncles = a.UncleCandidates(prev);
        p2pool::Share s = ChainShare(a, main, prev, script((unsigned char)(1 + i % 7)), t + 10 * i, uncles);
        fBuilt = a.Add(s, main, err);
        if (fBuilt && i % 50 == 0 && prev != 0)
        {
            // A sibling of this share, to be named as an uncle two shares on.
            p2pool::Share sib = ChainShare(a, main, prev, script(9), t + 10 * i + 1);
            fBuilt = a.Add(sib, main, err);
        }
        prev = s.GetId();
    }
    if (!fBuilt) printf("       %s\n", err.c_str());
    vector<p2pool::Share> hist;
    a.History(hist);
    nFail += Check(fBuilt && hist.size() >= p2pool::HISTORY_SHARES,
                   strprintf("a running chain of %u shares hands over %u, uncles included", nShares,
                             (unsigned)hist.size()).c_str()) ? 0 : 1;

    // A starting node takes it in messages of 400 -- one that has never seen
    // the main block all that history was mined on (orphaned since, say):
    // the shares keep their worth, and their coinbases state the height.
    TestMainView mainB = main;
    mainB.heights.erase(main.BlockAt(main.nTip));
    p2pool::ShareChain b(bnFloor, false);
    int nTipHeight = a.Height(a.Tip());
    bool fSynced = true;
    for (size_t i = 0; i < hist.size() && fSynced; i += 400)
    {
        vector<p2pool::Share> part(hist.begin() + i, hist.begin() + std::min(hist.size(), i + 400));
        fSynced = b.AddHistory(part, nTipHeight, mainB, err);
    }
    if (!fSynced) printf("       %s\n", err.c_str());
    nFail += Check(fSynced && b.Tip() == a.Tip(), "it ends on the same tip, though it never saw their main block") ? 0 : 1;

    // A share a history calls deep, but whose parent was checked in full, is
    // checked in full too. Taken on trust on this node's tip, one carried a
    // child onto the tip that every peer then refused, and blamed this node.
    {
        p2pool::ShareChain probe = b;
        p2pool::Share j = ChainShare(b, main, b.Tip(), script(5), t);   // timed before its line's median
        vector<p2pool::Share> one(1, j);
        bool fRefused = !probe.AddHistory(one, nTipHeight + 100000, main, err) && !probe.Has(j.GetId());
        nFail += Check(fRefused && err.find("median") != string::npos,
                       "a 'deep' share hung on a share checked in full is checked in full, and refused") ? 0 : 1;
    }

    // The deep end of a history is taken on its work alone, and holds no tip:
    // the line a node mines on ends in a share checked in full. A history of
    // such shares alone used to become the tip.
    {
        p2pool::ShareChain d(bnFloor, false);
        vector<p2pool::Share> deep(hist.begin(), hist.begin() + 400);
        bool fDeep = d.AddHistory(deep, nTipHeight, main, err);
        nFail += Check(fDeep && d.Size() == 400 && d.Tip() == 0,
                       "four hundred shares taken on their work alone hold no tip") ? 0 : 1;
        // Nor are they handed to a peer that asks by id (it checks in full,
        // and blames the sender), nor named as uncles.
        p2pool::Share got;
        bool fServed = d.GetShare(deep[200].GetId(), got);
        bool fUncle = !d.UncleCandidates(deep[201].GetId()).empty();
        nFail += Check(!fServed && !fUncle,
                       "and they are not served by id, nor offered as uncles") ? 0 : 1;
    }

    // A part out of height order is refused: a child first, taken on trust
    // while its parent was missing, then sat on the parent once that was
    // checked in full.
    {
        p2pool::ShareChain e(bnFloor, false);
        vector<p2pool::Share> backwards;
        backwards.push_back(hist[hist.size() - 1]);
        backwards.push_back(hist[hist.size() - 2]);
        nFail += Check(!e.AddHistory(backwards, nTipHeight, main, err) && err == "a history out of height order",
                       "a history part out of height order is refused") ? 0 : 1;
    }

    // A node that mined alone, for longer than a history and on easier
    // shares, before it heard the network: its own line has the bigger sum,
    // counted from its own first share, but the network's has more work in a
    // window. Lines that never meet are weighed on their windows; on sums it
    // kept its own line for good.
    {
        // The network: at the floor for its first thousand shares, then
        // coming every 9.5 s instead of 10, so its target hardens a little
        // through the window. A floor hard enough that 5% shows in the work:
        // at the easiest target every share is worth 2.
        CBigNum bnHardFloor;
        bnHardFloor.SetCompact(0x1f00ffff);
        p2pool::ShareChain net(bnHardFloor, false);
        unsigned int nNet = p2pool::HISTORY_SHARES + 200;
        unsigned int nSpan = 0;
        for (unsigned int i = 0; i < nNet; i++)
            nSpan += (i < 1000 || i % 2) ? 10 : 9;
        unsigned int tn = (unsigned int)main.nNow - nSpan - 100;
        uint256 np = 0;
        bool fNet = true;
        for (unsigned int i = 0; i < nNet && fNet; i++)
        {
            tn += (i < 1000 || i % 2) ? 10 : 9;
            p2pool::Share s = ChainShare(net, main, np, script((unsigned char)(1 + i % 7)), tn);
            fNet = net.Add(s, main, err);
            np = s.GetId();
        }
        if (!fNet) printf("       %s\n", err.c_str());
        vector<p2pool::Share> netHist;
        net.History(netHist);

        // The lone node: at the floor throughout, every 10 s, for longer.
        p2pool::ShareChain solo(bnHardFloor, false);
        unsigned int nSolo = 4000;
        unsigned int ts = (unsigned int)main.nNow - 10 * nSolo - 100;
        uint256 sp = 0;
        bool fSolo = true;
        for (unsigned int i = 0; i < nSolo && fSolo; i++)
        {
            p2pool::Share s = ChainShare(solo, main, sp, script(8), ts + 10 * i);
            fSolo = solo.Add(s, main, err);
            sp = s.GetId();
        }
        if (!fSolo) printf("       %s\n", err.c_str());
        p2pool::ShareChain soloBefore = solo;
        bool fTook = true;
        for (size_t i = 0; i < netHist.size() && fTook; i += 400)
        {
            vector<p2pool::Share> part(netHist.begin() + i, netHist.begin() + std::min(netHist.size(), i + 400));
            fTook = solo.AddHistory(part, net.Height(net.Tip()), main, err);
        }
        if (!fTook) printf("       %s\n", err.c_str());
        nFail += Check(fNet && fSolo && fTook && solo.Tip() == net.Tip(),
                       "a node that mined alone longer, on easier shares, moves to the network's line") ? 0 : 1;

        // The same network line played back from two hours ago: just as
        // heavy in its window, but not live. A share's time has no lower
        // bound, so only the tip choice can tell; the lone node stays put.
        p2pool::ShareChain old(bnHardFloor, false);
        unsigned int to = (unsigned int)main.nNow - nSpan - 100 - 7200;
        uint256 op = 0;
        bool fOld = true;
        for (unsigned int i = 0; i < nNet && fOld; i++)
        {
            to += (i < 1000 || i % 2) ? 10 : 9;
            p2pool::Share s = ChainShare(old, main, op, script((unsigned char)(1 + i % 7)), to);
            fOld = old.Add(s, main, err);
            op = s.GetId();
        }
        vector<p2pool::Share> oldHist;
        old.History(oldHist);
        bool fOldTook = true;
        for (size_t i = 0; i < oldHist.size() && fOldTook; i += 400)
        {
            vector<p2pool::Share> part(oldHist.begin() + i, oldHist.begin() + std::min(oldHist.size(), i + 400));
            fOldTook = soloBefore.AddHistory(part, old.Height(old.Tip()), main, err);
        }
        nFail += Check(fOld && fOldTook && soloBefore.Tip() == sp && soloBefore.Has(old.Tip()),
                       "a heavier line from two hours ago, played back, does not take a live tip") ? 0 : 1;
    }

    // The same for a fresh share: a main block this node lacks does not make
    // it wait -- the coinbase states the height -- but a coinbase that states
    // none is refused.
    p2pool::Share fresh = ChainShare(a, main, a.Tip(), script(4), t + 10 * nShares + 2);
    p2pool::ShareChain probe = b;
    nFail += Check(probe.Add(fresh, mainB, err),
                   "a fresh share on a main block this node lacks is taken on its coinbase height") ? 0 : 1;
    p2pool::Share noheight = fresh;
    noheight.coinbase.vin[0].scriptSig = CScript() << p2pool::CommitmentPush(noheight.data.GetHash());
    noheight.hashMerkleRoot = noheight.coinbase.GetHash();
    p2pool::ShareChain probe2 = b;
    nFail += Check(!probe2.Add(noheight, mainB, err) && err == "a share whose coinbase states no height",
                   "and one whose coinbase states no height is refused") ? 0 : 1;

    // And from there checks the next share in full, exactly as the running node does.
    p2pool::Share next = ChainShare(a, main, a.Tip(), script(3), t + 10 * nShares + 5);
    bool fA = a.Add(next, main, err);
    bool fB = b.Add(next, main, err);
    if (!fB) printf("       %s\n", err.c_str());
    nFail += Check(fA && fB && a.Tip() == b.Tip(), "the next share is accepted by both, paying the same window") ? 0 : 1;

    // A history whose recent part pays the wrong miners is refused.
    p2pool::ShareChain c(bnFloor, false);
    vector<p2pool::Share> forged = hist;
    p2pool::Share& f = forged[forged.size() - 10];
    std::swap(f.coinbase.vout[0].scriptPubKey, f.coinbase.vout[1].scriptPubKey);
    f.hashMerkleRoot = f.coinbase.GetHash();
    bool fForged = true;
    for (size_t i = 0; i < forged.size() && fForged; i += 400)
    {
        vector<p2pool::Share> part(forged.begin() + i, forged.begin() + std::min(forged.size(), i + 400));
        fForged = c.AddHistory(part, nTipHeight, main, err);
    }
    nFail += Check(!fForged && err.find("does not pay the window") != string::npos,
                   "a history with a recent share paying the wrong miners is refused") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- p2pool-peers: which cached peers hold the share chain ---------------
// What a dialled peer's version said sticks; another node's word only marks
// peers we know nothing about; and only peers we reached and that said so
// are named to other P2Pool nodes.
static int RunP2PoolPeersSelfTest()
{
    printf("p2pool-peers self-test\n");
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    int nFail = 0;

    // Four cached peers: three reached, one only heard about.
    {
        std::string body = "[";
        const char* names[4] = { "peera.btf", "peerb.btf", "peerc.btf", "peerd.btf" };
        for (int i = 0; i < 4; i++)
        {
            if (i) body += ",";
            body += strprintf("{\"btf\":\"%s\",\"meeting\":\"\",\"enc\":\"%064d\",\"seen\":%lld%s}",
                              names[i], 0, (long long)GetTime(), i < 3 ? ",\"ok\":true" : "");
        }
        body += "]";
        FILE* f = fopen((GetAppDir() + "/btfpeers.json").c_str(), "w");
        if (f)
        {
            fwrite(body.data(), 1, body.size(), f);
            fclose(f);
        }
    }

    BtfNoteP2PoolPeer("peera.btf", true);
    BtfNoteP2PoolPeer("peerb.btf", false);
    vector<string> vKnown;
    BtfKnownP2PoolPeers(vKnown, 32);
    nFail += Check(vKnown.size() == 1 && vKnown[0] == "peera.btf",
                   "a peer whose version said NODE_P2POOL is named to others; one that said nothing of it is not") ? 0 : 1;

    // Hints: peerb said no itself, and a hint does not overrule it; peerc and
    // peerd are unknown and become hints; a name not in the cache is ignored.
    vector<string> vHints;
    vHints.push_back("peerb.btf");
    vHints.push_back("peerc.btf");
    vHints.push_back("peerd.btf");
    vHints.push_back("nobody.btf");
    BtfNoteP2PoolHints(vHints);
    BtfKnownP2PoolPeers(vKnown, 32);
    nFail += Check(vKnown.size() == 1 && vKnown[0] == "peera.btf",
                   "another node's hints are never passed on as known") ? 0 : 1;

    // And a hinted peer that answers takes its own version's word.
    BtfNoteP2PoolPeer("peerc.btf", true);
    BtfKnownP2PoolPeers(vKnown, 32);
    nFail += Check(vKnown.size() == 2, "a hinted peer that says NODE_P2POOL when dialled is known from then on") ? 0 : 1;
    BtfNoteP2PoolPeer("peerd.btf", true);
    BtfKnownP2PoolPeers(vKnown, 32);
    nFail += Check(vKnown.size() == 2, "but one never reached is still not named to anybody") ? 0 : 1;

    nFail += Check((nLocalServices & NODE_P2POOL) != 0, "this node says it holds the share chain") ? 0 : 1;

    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- p2pool-dos: what peers can make the share chain spend ----------------
// H4 (share side), M6 and L6 of the DoS review: one budget for the RandomX
// hashes unproven peers cause, asked only after every cheap check; history
// served and asked for within shared budgets; orphan shares that expire on
// their own; a byte cap on the shares held.

namespace {
class CountingGate : public p2pool::WorkGate
{
public:
    explicit CountingGate(bool fOpenIn) : fOpen(fOpenIn), nAsked(0) {}
    bool Allow() { nAsked++; return fOpen; }
    bool fOpen;
    int nAsked;
};
}

// A peer past its version, as the message thread sees it.
static CNode* NewP2PoolTestNode(bool fInbound)
{
    CNode* p = new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), fInbound);
    p->nVersion = VERSION;
    p->nServices = NODE_P2POOL;
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    return p;
}

static void SendP2PoolTest(CNode* pnode, const char* pszCommand, const CDataStream& ss)
{
    CDataStream v(ss);
    try { P2PoolProcessMessage(pnode, pszCommand, v); }
    catch (std::exception& e) { printf("       %s: %s\n", pszCommand, e.what()); }
}

template <typename T>
static void SendP2PoolTestItem(CNode* pnode, const char* pszCommand, const T& item)
{
    CDataStream ss(SER_NETWORK, VERSION);
    ss << item;
    SendP2PoolTest(pnode, pszCommand, ss);
}

// Real RandomX work on a share target as easy as targets go.
static void GrindShare(p2pool::Share& s)
{
    CBigNum bnShare;
    bnShare.SetCompact(s.data.nShareBits);
    for (s.nNonce = 0; CBigNum(s.Header().GetPoWHash()) > bnShare; s.nNonce++)
        ;
}

// A share whose parent nobody has: a valid coinbase paying one address,
// committing to its data, with real work.
static p2pool::Share OrphanTestShare(const uint256& parent, unsigned int nClaimedHeight, unsigned int nShareBits,
                                     const vector<unsigned char>& payout, unsigned int nTime)
{
    p2pool::Share s;
    s.data.hashPrevShare = parent;
    s.data.nShareHeight = nClaimedHeight;
    s.data.nShareBits = nShareBits;
    s.data.payoutScript = payout;
    s.coinbase.vin.resize(1);
    s.coinbase.vin[0].prevout.SetNull();
    s.coinbase.vin[0].scriptSig << 61001 << (int64)nTime << p2pool::CommitmentPush(s.data.GetHash());
    s.coinbase.vout.push_back(CTxOut(CBlock().GetBlockValue(61001, 0), CScript(payout.begin(), payout.end())));
    s.nVersion = 1;
    s.hashPrevBlock = 0;
    s.hashMerkleRoot = s.coinbase.GetHash();
    s.nTime = nTime;
    s.nBits = 0x1d00ffff;
    GrindShare(s);
    return s;
}

static int RunP2PoolDosSelfTest()
{
    printf("p2pool-dos self-test\n");
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    int nFail = 0;
    string err;
    RandomXInit();

    // The bucket: three tokens, one more every ten seconds, never past three.
    {
        P2PoolBudget b(3, 10);
        bool fThree = b.Take(1000) && b.Take(1000) && b.Take(1000);
        bool fFourth = b.Take(1000);
        bool fEarly = b.Take(1009);
        bool fRefill = b.Take(1010);
        nFail += Check(fThree && !fFourth && !fEarly && fRefill && b.Tokens(1000000) == 3,
                       "a budget of three: three taken, the fourth waits ten seconds, and it fills to three at most") ? 0 : 1;
    }

    auto script = [](unsigned char tag) {
        vector<unsigned char> s;
        s.push_back(0x76); s.push_back(0xa9); s.push_back(20);
        for (int i = 0; i < 20; i++) s.push_back(tag);
        s.push_back(0x88); s.push_back(0xac);
        return s;
    };
    const unsigned int EASY = 0x207fffff, HARD = 0x1d00ffff;
    CBigNum bnEasy;
    bnEasy.SetCompact(EASY);

    // The gate is asked right before the hash, after every cheap check: not
    // for a share whose branch is wrong, nor for one that pays the wrong
    // window; once for one that would be hashed. A closed gate refuses it
    // with a refusal that blames nobody.
    {
        vector<p2pool::WindowShare> window;
        p2pool::WindowShare w;
        w.payoutScript = script(1); w.work = 300; window.push_back(w);
        w.payoutScript = script(2); w.work = 300; window.push_back(w);
        const int HEIGHT = 61000;
        p2pool::Share s = MakeTestShare(window, EASY, HARD, HEIGHT);
        bool fBlock;
        CountingGate closed(false), open(true);
        p2pool::Share t = s;
        t.vMerkleBranch.push_back(uint256(1));
        bool fBranch = !p2pool::CheckShareWork(t, bnEasy, fBlock, err, true, &closed) &&
                       err == "the coinbase is not in the merkle root" && closed.nAsked == 0;
        vector<p2pool::WindowShare> other = window;
        other[0].work = 600;
        bool fWindow = !p2pool::CheckShare(s, other, HEIGHT, bnEasy, fBlock, err, true, &closed) &&
                       err == "the coinbase does not pay the window" && closed.nAsked == 0;
        nFail += Check(fBranch && fWindow,
                       "the gate is not asked for a share a cheap check refuses (branch, window)") ? 0 : 1;
        bool fClosed = !p2pool::CheckShareWork(s, bnEasy, fBlock, err, true, &closed) &&
                       err == p2pool::WORK_GATE_CLOSED && p2pool::InnocentRefusal(err) && closed.nAsked == 1;
        bool fClosed2 = !p2pool::CheckShare(s, window, HEIGHT, bnEasy, fBlock, err, true, &closed) &&
                        err == p2pool::WORK_GATE_CLOSED && closed.nAsked == 2;
        nFail += Check(fClosed && fClosed2,
                       "a share past every cheap check asks the gate once; closed, it is refused and nobody is blamed") ? 0 : 1;
        bool fOpen = p2pool::CheckShare(s, window, HEIGHT, bnEasy, fBlock, err, true, &open) && open.nAsked == 1;
        nFail += Check(fOpen, "an open gate lets the hash run, and the share is valid") ? 0 : 1;
    }

    // The node's share chain, at the easiest floor, with real RandomX work.
    P2PoolResetForTest(bnEasy, true);
    TestMainView main;
    main.nBits = HARD;
    main.nTip = 61000;
    main.nNow = GetTime();
    for (int h = 60990; h <= 61000; h++)
        main.heights[Hash(BEGIN(h), END(h))] = h;
    unsigned int t0 = (unsigned int)GetTime() - 100;
    p2pool::Share s0;
    CRITICAL_BLOCK(cs_p2pool)
        s0 = ChainShare(P2PoolChain(), main, 0, script(1), t0);
    GrindShare(s0);
    unsigned int nBits0;
    CRITICAL_BLOCK(cs_p2pool)
        nBits0 = P2PoolChain().NextShareBits(s0.GetId());

    // Every orphan this test sends, ground before anything is timed.
    vector<p2pool::Share> vOrphans;
    for (int i = 0; i < 120; i++)
    {
        uint256 parent = Hash(BEGIN(i), END(i)) ^ uint256(77);
        vOrphans.push_back(OrphanTestShare(parent, 3, nBits0, script((unsigned char)(10 + i % 40)), t0 + 1 + i));
    }
    size_t iNext = 0;

    CNode* pOut = NewP2PoolTestNode(false);
    SendP2PoolTestItem(pOut, "p2pshare", s0);
    bool fRoot;
    CRITICAL_BLOCK(cs_p2pool)
        fRoot = P2PoolChain().Tip() == s0.GetId();
    nFail += Check(fRoot, "a share from a peer this node dialled starts the chain") ? 0 : 1;

    // A peer this node dialled is proven: forty orphans from it are all
    // hashed and queued, past the shared budget's thirty-two.
    int nTokens0 = P2PoolShareWorkTokens();
    for (int i = 0; i < 40; i++)
        SendP2PoolTestItem(pOut, "p2pshare", vOrphans[iNext++]);
    nFail += Check(P2PoolOrphanCount() == 40 && P2PoolShareWorkTokens() >= nTokens0,
                   "forty orphans from a dialled peer are all queued, and draw nothing from the shared budget") ? 0 : 1;

    // A backlog that big makes this node ask for a history -- but not
    // because a share it has already hashed comes again over a new
    // connection: that re-armed the ask on every reconnect.
    CNode* pAgain = NewP2PoolTestNode(true);
    SendP2PoolTestItem(pAgain, "p2pshare", vOrphans[5]);
    nFail += Check(pAgain->nP2PoolSyncAskedAt == 0 && P2PoolOrphanCount() == 40,
                   "an orphan already hashed, sent again by a new inbound peer, opens no history ask") ? 0 : 1;

    // New orphans from three new inbound peers: each is hashed (budget), but
    // only two of them are asked for their history (the shared ask budget).
    int nAsked = 0;
    vector<CNode*> vIn;
    for (int i = 0; i < 3; i++)
    {
        vIn.push_back(NewP2PoolTestNode(true));
        SendP2PoolTestItem(vIn.back(), "p2pshare", vOrphans[iNext++]);
        nAsked += vIn.back()->nP2PoolSyncAskedAt != 0;
    }
    nFail += Check(P2PoolOrphanCount() == 43 && nAsked == 2,
                   strprintf("three new inbound peers with new orphans: all queued, %d of them asked for a history (2)", nAsked).c_str()) ? 0 : 1;

    // One unproven inbound peer with sixty new orphans: only what is left of
    // the shared budget is hashed; the rest are not, and it is not blamed.
    CNode* pFlood = NewP2PoolTestNode(true);
    int nLeft = P2PoolShareWorkTokens();
    int64 nStart = GetTime();
    size_t nBefore = P2PoolOrphanCount();
    for (int i = 0; i < 60; i++)
        SendP2PoolTestItem(pFlood, "p2pshare", vOrphans[iNext++]);
    int64 nSlack = (GetTime() - nStart) / 2 + 1;
    size_t nQueued = P2PoolOrphanCount() - nBefore;
    nFail += Check(nQueued >= (size_t)nLeft && nQueued <= (size_t)(nLeft + nSlack) && nQueued < 60 &&
                   pFlood->nMisbehavior == 0 && P2PoolDeferredCount() == 1,
                   strprintf("sixty orphans from one unproven inbound peer: %u hashed (budget %d), the rest refused "
                             "unblamed, its newest held for later", (unsigned)nQueued, nLeft).c_str()) ? 0 : 1;
    P2PoolForgetDeferred(pFlood);

    // The budget is spent, and a dialled peer is still heard in full.
    nBefore = P2PoolOrphanCount();
    for (int i = 0; i < 5; i++)
        SendP2PoolTestItem(pOut, "p2pshare", vOrphans[iNext++]);
    nFail += Check(P2PoolOrphanCount() == nBefore + 5, "with the budget spent, five orphans from a dialled peer are still taken") ? 0 : 1;

    // A dialled peer that has since misbehaved goes through the budget like an
    // unproven one: proven status is not taken back within a connection.
    {
        P2PoolDrainBudgetsForTest();
        CNode* pBad = NewP2PoolTestNode(false);
        pBad->nMisbehavior = 20;
        size_t n0 = P2PoolOrphanCount();
        SendP2PoolTestItem(pBad, "p2pshare", vOrphans[iNext++]);
        bool fGated = P2PoolOrphanCount() == n0 && P2PoolDeferredCount() == 1;
        P2PoolForgetDeferred(pBad);
        delete pBad;
        nFail += Check(fGated, "a dialled peer that has misbehaved draws on the shared budget; spent, its share waits") ? 0 : 1;
    }

    // A share the spent budget refuses an unproven peer is held, not lost, and
    // taken once the budget refills: a miner that dials out and listens for
    // nobody is unproven at every node it reaches, and its shares are its pay.
    {
        p2pool::Share sChild;
        CRITICAL_BLOCK(cs_p2pool)
            sChild = ChainShare(P2PoolChain(), main, s0.GetId(), script(3), t0 + 10);
        GrindShare(sChild);
        CNode* pMiner = NewP2PoolTestNode(true);
        P2PoolDrainBudgetsForTest();
        SendP2PoolTestItem(pMiner, "p2pshare", sChild);
        bool fNotYet;
        CRITICAL_BLOCK(cs_p2pool)
            fNotYet = !P2PoolChain().Has(sChild.GetId());
        bool fHeld = fNotYet && P2PoolDeferredCount() == 1 && pMiner->nMisbehavior == 0 && !P2PoolPeerProven(pMiner);
        P2PoolServeDeferred();   // still no token: it stays
        bool fStill = P2PoolDeferredCount() == 1;
        P2PoolRefillBudgetsForTest();
        // With tokens back, a share that comes in live on a newer connection
        // waits behind the held one instead of taking the token first.
        CNode* pLate = NewP2PoolTestNode(true);
        pLate->nTimeConnected = pMiner->nTimeConnected + 1;
        size_t nOrphans0 = P2PoolOrphanCount();
        SendP2PoolTestItem(pLate, "p2pshare", vOrphans[iNext++]);
        bool fBehind = P2PoolOrphanCount() == nOrphans0 && P2PoolDeferredCount() == 2;
        P2PoolServeDeferred();
        bool fTaken;
        CRITICAL_BLOCK(cs_p2pool)
            fTaken = P2PoolChain().Has(sChild.GetId());
        nFail += Check(fHeld && fStill && fTaken && P2PoolDeferredCount() == 0 && P2PoolPeerProven(pMiner),
                       "an unproven peer's share the spent budget refused is held, then taken when the budget refills") ? 0 : 1;
        nFail += Check(fBehind && P2PoolOrphanCount() == nOrphans0 + 1,
                       "a live share on a newer connection waits behind the held one, and is hashed after it") ? 0 : 1;
        delete pMiner;
        delete pLate;

        // A connection that closes meanwhile loses what was held for it.
        CNode* pGone = NewP2PoolTestNode(true);
        P2PoolDrainBudgetsForTest();
        SendP2PoolTestItem(pGone, "p2pshare", vOrphans[iNext++]);
        bool fHeld2 = P2PoolDeferredCount() == 1;
        pGone->fDisconnect = true;
        P2PoolRefillBudgetsForTest();
        size_t n0 = P2PoolOrphanCount();
        P2PoolServeDeferred();
        nFail += Check(fHeld2 && P2PoolDeferredCount() == 0 && P2PoolOrphanCount() == n0,
                       "what was held for a connection that closed is dropped, not hashed") ? 0 : 1;
        delete pGone;
    }

    // Orphans expire on their own clock, not only when another is queued:
    // a full backlog stayed full for good, and kept history asks armed.
    P2PoolAgeOrphansForTest(20 * 60 + 1);
    SendP2PoolTestItem(pOut, "p2pshare", s0);   // already held: queues nothing
    nFail += Check(P2PoolOrphanCount() == 0, "orphans past their expiry are gone at the next share, though none was queued") ? 0 : 1;

    // History served: four times to new unproven peers, then they wait for
    // the shared budget; a dialled peer is served regardless.
    int nServed = 0;
    vector<CNode*> vAsk;
    for (int i = 0; i < 6; i++)
    {
        vAsk.push_back(NewP2PoolTestNode(true));
        SendP2PoolTest(vAsk.back(), "p2psync", CDataStream(SER_NETWORK, VERSION));
        nServed += vAsk.back()->vSend.size() != 0;
    }
    CNode* pOut2 = NewP2PoolTestNode(false);
    SendP2PoolTest(pOut2, "p2psync", CDataStream(SER_NETWORK, VERSION));
    nFail += Check(nServed == 4 && pOut2->vSend.size() != 0 && P2PoolDeferredCount() == 2,
                   strprintf("six new inbound peers asking for the history: %d served (4), the other two held; "
                             "a dialled peer is served", nServed).c_str()) ? 0 : 1;
    for (size_t i = 0; i < vAsk.size(); i++)
        P2PoolForgetDeferred(vAsk[i]);
    // One history in the life of an unproven connection: asking again, even
    // past the interval, neither gets one nor keeps a place in the queue.
    {
        CNode* pServed = vAsk[0];
        P2PoolRefillBudgetsForTest();
        pServed->nP2PoolSyncServed = GetTime() - 3600;
        size_t nSent = pServed->vSend.size();
        SendP2PoolTest(pServed, "p2psync", CDataStream(SER_NETWORK, VERSION));
        nFail += Check(pServed->vSend.size() == nSent && P2PoolDeferredCount() == 0,
                       "an unproven peer that already had its history gets no second one, and holds no place") ? 0 : 1;
    }

    // Nor is a history started for an inbound peer past what inbound peers
    // together hold queued (a proven one counts: one share relayed first
    // proves a peer); it waits, and is sent once there is room. A peer this
    // node dialled is served whatever others hold.
    {
        P2PoolRefillBudgetsForTest();
        CNode* pFull = NewP2PoolTestNode(true);
        pFull->nP2PoolLastGood = GetTime();
        pFull->vSend.resize(65 * 1000 * 1000);
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pFull);
        CNode* pIn = NewP2PoolTestNode(true);
        SendP2PoolTest(pIn, "p2psync", CDataStream(SER_NETWORK, VERSION));
        bool fHeld = pIn->vSend.size() == 0 && P2PoolDeferredCount() == 1 && !pFull->fDisconnect;
        CNode* pOut3 = NewP2PoolTestNode(false);
        SendP2PoolTest(pOut3, "p2psync", CDataStream(SER_NETWORK, VERSION));
        bool fDialled = pOut3->vSend.size() != 0;
        P2PoolServeDeferred();
        bool fStill = pIn->vSend.size() == 0 && P2PoolDeferredCount() == 1;
        pFull->vSend.clear();
        P2PoolServeDeferred();
        bool fLater = pIn->vSend.size() != 0 && P2PoolDeferredCount() == 0;
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), pFull), vNodes.end());
        P2PoolForgetDeferred(pIn);
        delete pFull;
        delete pIn;
        delete pOut3;
        nFail += Check(fHeld && fDialled && fStill && fLater,
                       "with 65 MB queued to inbound peers, an inbound peer's history waits and is sent once "
                       "there is room; a dialled peer is served at once") ? 0 : 1;
    }

    // An inbound peer that still has a history's worth queued long after it
    // was sent one reads too slowly: while inbound queues are over the cap it
    // is cut off, and the waiting ask is answered.
    {
        P2PoolRefillBudgetsForTest();
        CNode* pSlow = NewP2PoolTestNode(true);
        pSlow->nP2PoolLastGood = GetTime();
        pSlow->nP2PoolSyncServed = GetTime() - 3600;
        pSlow->vSend.resize(65 * 1000 * 1000);
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pSlow);
        CNode* pNew = NewP2PoolTestNode(true);
        SendP2PoolTest(pNew, "p2psync", CDataStream(SER_NETWORK, VERSION));
        bool fDropped = pSlow->fDisconnect && pNew->vSend.size() == 0 && P2PoolDeferredCount() == 1;
        P2PoolServeDeferred();
        bool fServed = pNew->vSend.size() != 0 && P2PoolDeferredCount() == 0;
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), pSlow), vNodes.end());
        P2PoolForgetDeferred(pNew);
        delete pSlow;
        delete pNew;
        nFail += Check(fDropped && fServed,
                       "an inbound peer still holding a history's worth 15 minutes after it was sent one is cut off "
                       "when inbound queues are full, and the waiting ask is answered") ? 0 : 1;
    }

    // The bytes of the shares held are capped (L6): side lines go, the tip's
    // line stays, and every count stays true.
    {
        p2pool::ShareChain c(bnEasy, false);
        unsigned int t = (unsigned int)main.nNow - 1000;
        vector<uint256> line;
        uint256 prev = 0;
        bool fBuilt = true;
        for (int i = 0; i < 20 && fBuilt; i++)
        {
            p2pool::Share s = ChainShare(c, main, prev, script((unsigned char)(1 + i % 3)), t + 10 * i);
            fBuilt = c.Add(s, main, err);
            prev = s.GetId();
            line.push_back(prev);
        }
        // A side line far behind the tip in work (forked from the second
        // share): a line near the tip is kept whatever the caps say.
        vector<uint256> side;
        uint256 sp = line[1];
        for (int i = 0; i < 2 && fBuilt; i++)
        {
            p2pool::Share s = ChainShare(c, main, sp, script(9), t + 10 * 1 + 5 + 10 * i);
            fBuilt = c.Add(s, main, err);
            sp = s.GetId();
            side.push_back(sp);
        }
        bool fInv = c.CheckInvariants(err);
        if (!fInv) printf("       %s\n", err.c_str());
        size_t nAll = c.Bytes();
        // Below what the tip's line holds: the cap is then that line's bytes.
        c.SetMaxBytesForTest(1);
        p2pool::Share next = ChainShare(c, main, line.back(), script(4), t + 300);
        fBuilt = fBuilt && c.Add(next, main, err);
        bool fSideGone = true, fLineKept = c.Has(next.GetId());
        for (size_t i = 0; i < side.size(); i++)
            fSideGone &= !c.Has(side[i]);
        for (size_t i = 0; i < line.size(); i++)
            fLineKept &= c.Has(line[i]);
        bool fInv2 = c.CheckInvariants(err);
        if (!fInv2) printf("       %s\n", err.c_str());
        nFail += Check(fBuilt && fInv && fInv2 && fSideGone && fLineKept &&
                       c.Bytes() < nAll + ::GetSerializeSize(next, SER_NETWORK),
                       "past the byte cap the side line goes, the tip's line stays, the counts stay true") ? 0 : 1;

        c.SetMaxBytesForTest(p2pool::MAX_CHAIN_BYTES);
        // A share held on trust is dropped when its parent comes checked in
        // full, found through the index by parent.
        p2pool::Share parent = ChainShare(c, main, next.GetId(), script(5), t + 310);
        p2pool::Share child = OrphanTestShare(parent.GetId(), parent.data.nShareHeight + 1, c.NextShareBits(0),
                                              script(6), t + 320);
        bool fTrusted = c.AddTrusted(child, err) && c.TrustedBytes() > 0;
        bool fParent = c.Add(parent, main, err);
        bool fInv3 = c.CheckInvariants(err);
        if (!fInv3) printf("       %s\n", err.c_str());
        nFail += Check(fTrusted && fParent && !c.Has(child.GetId()) && c.TrustedBytes() == 0 && fInv3,
                       "a share held on trust under a parent then checked in full is dropped, and its bytes with it") ? 0 : 1;
    }

    // What the tip's line holds may pass the byte cap by itself (a window
    // paying thousands of addresses). A line still in play is kept even then:
    // a share at the tip's height, which a nephew then names as an uncle, and
    // a line forked near the tip that overtakes it. Evicted the moment they
    // came, this node stalled while every node with room moved on. A side
    // share far behind the tip in work still goes.
    {
        p2pool::ShareChain c(bnEasy, false);
        unsigned int t = (unsigned int)main.nNow - 1000;
        vector<uint256> line;
        uint256 prev = 0;
        bool fBuilt = true;
        for (int i = 0; i < 30 && fBuilt; i++)
        {
            p2pool::Share s = ChainShare(c, main, prev, script((unsigned char)(1 + i % 3)), t + 10 * i);
            fBuilt = c.Add(s, main, err);
            prev = s.GetId();
            line.push_back(prev);
        }
        c.SetMaxBytesForTest(1);
        p2pool::Share sib = ChainShare(c, main, line[28], script(7), t + 10 * 29 + 3);
        bool fSib = fBuilt && c.Add(sib, main, err) && c.Has(sib.GetId());
        p2pool::Share nephew = ChainShare(c, main, line[29], script(8), t + 10 * 30, vector<uint256>(1, sib.GetId()));
        bool fNephew = c.Add(nephew, main, err) && c.Tip() == nephew.GetId() && c.Has(sib.GetId());
        if (!fNephew) printf("       nephew: %s\n", err.c_str());
        // A line forked four shares back, grown past the tip.
        uint256 fp = line[26];
        bool fFork = true;
        vector<uint256> fork;
        for (int i = 0; i < 8 && fFork; i++)
        {
            p2pool::Share s = ChainShare(c, main, fp, script(9), t + 10 * 31 + 10 * i + 5);
            fFork = c.Add(s, main, err) && c.Has(s.GetId());
            fp = s.GetId();
            fork.push_back(fp);
        }
        bool fOvertook = fFork && c.Tip() == fork.back();
        if (!fOvertook) printf("       fork: %s\n", err.c_str());
        // Far behind in work: forked from the third share, it goes at once.
        p2pool::Share deep = ChainShare(c, main, line[2], script(10), t + 25);
        bool fDeepAdded = c.Add(deep, main, err);
        bool fDeepGone = fDeepAdded && !c.Has(deep.GetId());
        bool fInv = c.CheckInvariants(err);
        if (!fInv) printf("       %s\n", err.c_str());
        nFail += Check(fSib && fNephew && fOvertook && fDeepGone && fInv,
                       "past the byte cap a share at the tip's height stays and its nephew is taken, a line forked "
                       "near the tip overtakes, a side share far behind in work goes") ? 0 : 1;
    }

    string errInv;
    bool fChainInv;
    CRITICAL_BLOCK(cs_p2pool)
        fChainInv = P2PoolChain().CheckInvariants(errInv);
    if (!fChainInv) printf("       %s\n", errInv.c_str());
    nFail += Check(fChainInv, "the node's share chain holds its invariants after all that") ? 0 : 1;

    delete pOut;
    delete pOut2;
    delete pAgain;
    delete pFlood;
    for (size_t i = 0; i < vIn.size(); i++) delete vIn[i];
    for (size_t i = 0; i < vAsk.size(); i++) delete vAsk[i];
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// Rules v3: OP_CHECKLOCKTIMEVERIFY, lock-time finality in blocks, BIP16
// enforced, and the hash-time-locked script an atomic swap is made of. The
// rules are driven here through their flags, not the activation time, so the
// suite checks the rule itself whatever date consensus.h holds.
// ---- sigcheck: libsecp256k1 must answer exactly as OpenSSL did -----------

// r and s of a DER signature, big-endian, leading zeros stripped.
static bool SigDerSplit(const vector<unsigned char>& der, vector<unsigned char>& r, vector<unsigned char>& s)
{
    if (der.size() < 8 || der[0] != 0x30 || der[1] != der.size() - 2 || der[2] != 0x02)
        return false;
    size_t rl = der[3];
    if (4 + rl + 2 > der.size() || der[4 + rl] != 0x02)
        return false;
    size_t sl = der[5 + rl];
    if (6 + rl + sl != der.size())
        return false;
    r.assign(der.begin() + 4, der.begin() + 4 + rl);
    s.assign(der.begin() + 6 + rl, der.end());
    while (r.size() > 1 && r[0] == 0) r.erase(r.begin());
    while (s.size() > 1 && s[0] == 0) s.erase(s.begin());
    return true;
}

static vector<unsigned char> SigDerJoin(const vector<unsigned char>& r, const vector<unsigned char>& s)
{
    vector<unsigned char> rr = r, ss = s;
    if (rr[0] & 0x80) rr.insert(rr.begin(), 0);
    if (ss[0] & 0x80) ss.insert(ss.begin(), 0);
    vector<unsigned char> der;
    der.push_back(0x30);
    der.push_back((unsigned char)(4 + rr.size() + ss.size()));
    der.push_back(0x02); der.push_back((unsigned char)rr.size()); der.insert(der.end(), rr.begin(), rr.end());
    der.push_back(0x02); der.push_back((unsigned char)ss.size()); der.insert(der.end(), ss.begin(), ss.end());
    return der;
}

// The twin of a signature: S' = n - S, which OpenSSL also verifies.
static vector<unsigned char> SigHighS(const vector<unsigned char>& der)
{
    static const unsigned char n[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
    vector<unsigned char> r, s;
    if (!SigDerSplit(der, r, s) || s.size() > 32)
        return der;
    unsigned char s32[32] = {0}, out[32];
    memcpy(s32 + 32 - s.size(), &s[0], s.size());
    int borrow = 0;
    for (int i = 31; i >= 0; i--)
    {
        int d = (int)n[i] - (int)s32[i] - borrow;
        borrow = d < 0;
        out[i] = (unsigned char)(d + (borrow ? 256 : 0));
    }
    vector<unsigned char> s2(out, out + 32);
    while (s2.size() > 1 && s2[0] == 0) s2.erase(s2.begin());
    return SigDerJoin(r, s2);
}

// 04|X|Y as 02/03|X, and as the hybrid 06/07|X|Y.
static vector<unsigned char> PubCompressed(const vector<unsigned char>& full)
{
    vector<unsigned char> c(full.begin(), full.begin() + 33);
    c[0] = (full[64] & 1) ? 0x03 : 0x02;
    return c;
}

static vector<unsigned char> PubHybrid(const vector<unsigned char>& full)
{
    vector<unsigned char> h = full;
    h[0] = (full[64] & 1) ? 0x07 : 0x06;
    return h;
}

static bool SigOpenSsl(const uint256& hash, const vector<unsigned char>& sig, const vector<unsigned char>& pub)
{
    return CKey::Verify(pub, hash, sig);
}

static int RunSigCheckSelfTest()
{
    printf("sigcheck self-test\n");
    int nFail = 0;
    SigCheckSelfTest();

    int nCases = 0, nDisagree = 0, nTrueBoth = 0;
    std::string firstDisagreement;
    auto both = [&](const uint256& h, const vector<unsigned char>& sig, const vector<unsigned char>& pub,
                    const char* what) {
        bool a = SigOpenSsl(h, sig, pub);
        bool b = SigCheckEcdsa((const unsigned char*)&h, sig, pub);
        nCases++;
        if (a && b) nTrueBoth++;
        if (a != b)
        {
            nDisagree++;
            if (firstDisagreement.empty())
                firstDisagreement = strprintf("%s: OpenSSL %d, libsecp256k1 %d", what, a, b);
        }
        return b;
    };

    bool fLow = true, fHigh = true, fComp = true, fHyb = true, fWrong = true;
    for (int k = 0; k < 48; k++)
    {
        CKey key;
        key.MakeNewKey();
        vector<unsigned char> pub = key.GetPubKey();
        uint256 hash;
        RAND_bytes((unsigned char*)&hash, sizeof(hash));
        vector<unsigned char> sig;
        if (!key.Sign(hash, sig))
        {
            nFail++;
            continue;
        }
        fLow  &= both(hash, sig, pub, "low S");
        fHigh &= both(hash, SigHighS(sig), pub, "high S");
        fComp &= both(hash, sig, PubCompressed(pub), "compressed key");
        fHyb  &= both(hash, sig, PubHybrid(pub), "hybrid key");
        uint256 other = hash;
        ((unsigned char*)&other)[k % 32] ^= 0x01;
        fWrong &= !both(other, sig, pub, "another hash");

        vector<unsigned char> longer = sig; longer.push_back(0x00);
        both(hash, longer, pub, "a trailing byte");
        vector<unsigned char> shorter(sig.begin(), sig.end() - 1);
        both(hash, shorter, pub, "one byte short");
        vector<unsigned char> wrongHyb = PubHybrid(pub); wrongHyb[0] ^= 0x01;
        both(hash, sig, wrongHyb, "hybrid key with the wrong parity");

        // Every byte of the signature and of the key, flipped one at a time.
        for (size_t i = 0; i < sig.size(); i++)
        {
            vector<unsigned char> m = sig;
            m[i] ^= (unsigned char)(1 << (i % 8));
            both(hash, m, pub, "a flipped signature byte");
        }
        for (size_t i = 0; i < pub.size(); i += 3)
        {
            vector<unsigned char> m = pub;
            m[i] ^= (unsigned char)(1 << (i % 8));
            both(hash, sig, m, "a flipped key byte");
        }
    }

    nFail += Check(fLow, "a low-S signature verifies") ? 0 : 1;
    nFail += Check(fHigh, "its high-S twin verifies too, as with OpenSSL (blocks before rules v2 carry them)") ? 0 : 1;
    nFail += Check(fComp && fHyb, "compressed and hybrid keys verify") ? 0 : 1;
    nFail += Check(fWrong, "a signature for another hash does not") ? 0 : 1;
    nFail += Check(nDisagree == 0, strprintf("OpenSSL and libsecp256k1 agree on all %d cases (%d valid)",
                                              nCases, nTrueBoth).c_str()) ? 0 : 1;
    if (nDisagree)
        printf("       %d disagreements; first: %s\n", nDisagree, firstDisagreement.c_str());
    uint256 zero = 0;
    nFail += Check(!SigCheckEcdsa((const unsigned char*)&zero, vector<unsigned char>(), vector<unsigned char>(1, 2)),
                   "an empty signature fails") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

static int RunRulesV3SelfTest()
{
    printf("rules-v3 self-test\n");
    int nFail = 0;

    // ---- the launch day of swaps: a date, not a rule
    nFail += Check(SwapsOpenTimeFor(false) == 1798200000,
                   "mainnet swaps open at 2026-12-25 12:00 UTC") ? 0 : 1;
    nFail += Check(RULES_V3_TIME_MAINNET == 1795262400,
                   "while rules v3 still switch on at 2026-11-21 12:00 UTC, as 1.2.29 shipped") ? 0 : 1;
    nFail += Check(SwapsOpenTimeFor(true) == RULES_V3_TIME_TESTNET,
                   "testnet swaps open with the rules") ? 0 : 1;
    if (!IsTestNet())
        nFail += Check(!SwapsOpen(1798200000 - 1) && SwapsOpen(1798200000),
                       "and not a second before") ? 0 : 1;

    CKey keyA, keyB;
    keyA.MakeNewKey();
    keyB.MakeNewKey();

    // ---- the opcode
    nFail += Check(std::string(GetOpName(OP_CHECKLOCKTIMEVERIFY)) == "OP_CHECKLOCKTIMEVERIFY" &&
                   OP_CHECKLOCKTIMEVERIFY == 0xb1,
                   "OP_CHECKLOCKTIMEVERIFY is 0xb1, the byte Bitcoin uses") ? 0 : 1;

    // A bare lock script: <lock> CLTV DROP <A> CHECKSIG
    const int64 LOCK = 1000;
    CScript lockScript;
    lockScript << LOCK << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyA.GetPubKey() << OP_CHECKSIG;
    CScript p2shLock;
    p2shLock.SetPayToScriptHash(lockScript);

    CTransaction txFrom;
    txFrom.vout.push_back(CTxOut(5 * COIN, p2shLock));
    CTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout = COutPoint(txFrom.GetHash(), 0);
    t.vin[0].nSequence = 0;
    t.vout.push_back(CTxOut(5 * COIN - CENT, CScript() << keyA.GetPubKey() << OP_CHECKSIG));

    struct Spend
    {
        static bool Ok(CKey& key, const CScript& redeem, const CTransaction& from, CTransaction tx,
                       bool fV3)
        {
            tx.vin[0].scriptSig = CScript();
            std::vector<unsigned char> sig = SelfTestSign(key, redeem, tx, 0);
            tx.vin[0].scriptSig << sig << static_cast<std::vector<unsigned char> >(redeem);
            return VerifySignature(from, tx, 0, 0, true, fV3);
        }
    };

    t.nLockTime = LOCK;
    nFail += Check(Spend::Ok(keyA, lockScript, txFrom, t, true),
                   "a spend whose nLockTime reaches the lock verifies under rules v3") ? 0 : 1;
    {
        // Run as a bare script, where the opcode actually executes either way.
        CTransaction tb = t;
        std::vector<unsigned char> sig = SelfTestSign(keyA, lockScript, tb, 0);
        CScript run = CScript() << sig << OP_CODESEPARATOR;
        run += lockScript;
        nFail += Check(EvalScript(run, tb, 0, 0, NULL, true, true) &&
                       !EvalScript(run, tb, 0, 0, NULL, true, false),
                       "the same lock script fails before rules v3: the opcode is unknown there") ? 0 : 1;
    }
    t.nLockTime = LOCK - 1;
    nFail += Check(!Spend::Ok(keyA, lockScript, txFrom, t, true),
                   "one block short of the lock is refused") ? 0 : 1;
    t.nLockTime = LOCKTIME_THRESHOLD + 5;
    nFail += Check(!Spend::Ok(keyA, lockScript, txFrom, t, true),
                   "a time in nLockTime does not satisfy a height lock") ? 0 : 1;
    t.nLockTime = LOCK;
    t.vin[0].nSequence = UINT_MAX;
    nFail += Check(!Spend::Ok(keyA, lockScript, txFrom, t, true),
                   "a final input (which switches nLockTime off) is refused") ? 0 : 1;
    t.vin[0].nSequence = 0;
    nFail += Check(!Spend::Ok(keyB, lockScript, txFrom, t, true),
                   "the right time with the wrong key is refused") ? 0 : 1;

    // A time lock, and the wrong unit the other way round
    {
        const int64 TLOCK = (int64)LOCKTIME_THRESHOLD + 100000;
        CScript ts;
        ts << TLOCK << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyA.GetPubKey() << OP_CHECKSIG;
        CScript p; p.SetPayToScriptHash(ts);
        CTransaction from; from.vout.push_back(CTxOut(COIN, p));
        CTransaction s = t;
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        s.nLockTime = (unsigned int)TLOCK;
        nFail += Check(Spend::Ok(keyA, ts, from, s, true), "a time lock is met by an nLockTime past it") ? 0 : 1;
        s.nLockTime = 1000;
        nFail += Check(!Spend::Ok(keyA, ts, from, s, true), "and not by a height") ? 0 : 1;
    }

    // Malformed locks
    {
        CScript neg;
        neg << (int64)-1 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyA.GetPubKey() << OP_CHECKSIG;
        CScript p; p.SetPayToScriptHash(neg);
        CTransaction from; from.vout.push_back(CTxOut(COIN, p));
        CTransaction s = t;
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        nFail += Check(!Spend::Ok(keyA, neg, from, s, true), "a negative lock is refused") ? 0 : 1;

        CScript big;
        big << std::vector<unsigned char>(6, 0x01) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyA.GetPubKey() << OP_CHECKSIG;
        CScript p2; p2.SetPayToScriptHash(big);
        CTransaction from2; from2.vout.push_back(CTxOut(COIN, p2));
        s.vin[0].prevout = COutPoint(from2.GetHash(), 0);
        s.nLockTime = UINT_MAX - 1;
        nFail += Check(!Spend::Ok(keyA, big, from2, s, true), "a lock longer than five bytes is refused") ? 0 : 1;

        CScript empty;
        empty << OP_CHECKLOCKTIMEVERIFY;
        CTransaction s2 = t;
        nFail += Check(!EvalScript(empty, s2, 0, 0, NULL, true, true), "CLTV on an empty stack fails") ? 0 : 1;

        // OP_2DROP used to pop an empty stack: heap corruption, a crash in
        // every node that evaluated the script.
        CScript drop0, drop1, drop2;
        drop0 << OP_2DROP << OP_1;
        drop1 << OP_1 << OP_2DROP << OP_1;
        drop2 << OP_1 << OP_1 << OP_2DROP << OP_1;
        nFail += Check(!EvalScript(drop0, s2, 0, 0, NULL, true, true), "OP_2DROP on an empty stack fails") ? 0 : 1;
        nFail += Check(!EvalScript(drop1, s2, 0, 0, NULL, true, true), "OP_2DROP on one item fails") ? 0 : 1;
        nFail += Check(EvalScript(drop2, s2, 0, 0, NULL, true, true), "OP_2DROP on two items still works") ? 0 : 1;

        // OP_VER and friends answer differently on every release: invalid
        // under rules v3, even in a branch that is not taken.
        CScript ver, verif, skipped;
        ver << OP_VER << OP_DROP << OP_1;
        verif << OP_1 << OP_VERIF << OP_1 << OP_ELSE << OP_1 << OP_ENDIF;
        skipped << OP_0 << OP_IF << OP_VERNOTIF << OP_ENDIF << OP_ENDIF << OP_1;
        nFail += Check(EvalScript(ver, s2, 0, 0, NULL, true, false), "OP_VER still runs before rules v3") ? 0 : 1;
        nFail += Check(!EvalScript(ver, s2, 0, 0, NULL, true, true), "OP_VER fails under rules v3") ? 0 : 1;
        nFail += Check(!EvalScript(verif, s2, 0, 0, NULL, true, true), "OP_VERIF fails under rules v3") ? 0 : 1;
        nFail += Check(!EvalScript(skipped, s2, 0, 0, NULL, true, true), "OP_VERNOTIF fails even in a branch not taken") ? 0 : 1;

        // A key count near INT_MAX used to overflow the index arithmetic.
        CScript manyKeys;
        manyKeys << OP_1 << std::vector<unsigned char>{0xff, 0xff, 0xff, 0x7f} << OP_CHECKMULTISIG;
        nFail += Check(!EvalScript(manyKeys, s2, 0, 0, NULL, true, true), "OP_CHECKMULTISIG with INT_MAX keys fails") ? 0 : 1;

        // Hashing nothing hashes a blank byte's address, not &v[0] of an empty
        // vector; the digest must not change.
        std::vector<unsigned char> none;
        nFail += Check(Hash(none.begin(), none.end()).GetHex() ==
                       "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
                       "the hash of nothing is unchanged") ? 0 : 1;
        nFail += Check(Hash160(none).GetHex() == "cb9f3b7c6fb1cf2c13a40637c189bdd066a272b4",
                       "and so is the Hash160 of nothing") ? 0 : 1;
    }

    // ---- lock-time finality in blocks
    {
        CTransaction f = t;
        f.nLockTime = 100;
        f.vin[0].nSequence = 0;
        nFail += Check(!f.IsFinalAt(100, 0), "nLockTime 100 cannot be in block 100") ? 0 : 1;
        nFail += Check(f.IsFinalAt(101, 0), "and can be in block 101") ? 0 : 1;
        f.nLockTime = LOCKTIME_THRESHOLD + 50;
        nFail += Check(!f.IsFinalAt(1000000, LOCKTIME_THRESHOLD + 50), "a time lock waits for the median time to pass it") ? 0 : 1;
        nFail += Check(f.IsFinalAt(1, LOCKTIME_THRESHOLD + 51), "and is final once it has") ? 0 : 1;
        f.vin[0].nSequence = UINT_MAX;
        nFail += Check(f.IsFinalAt(1, 0), "every input final makes the lock time irrelevant") ? 0 : 1;
        f.nLockTime = 0;
        f.vin[0].nSequence = 0;
        nFail += Check(f.IsFinalAt(0, 0), "nLockTime 0 is always final") ? 0 : 1;
    }

    // ---- BIP16 enforced
    {
        CScript redeem; redeem << keyA.GetPubKey() << OP_CHECKSIG;
        CScript p; p.SetPayToScriptHash(redeem);
        CTransaction from; from.vout.push_back(CTxOut(COIN, p));
        CTransaction s = t;
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        s.nLockTime = 0;
        s.vin[0].scriptSig = CScript() << static_cast<std::vector<unsigned char> >(redeem);
        nFail += Check(VerifySignature(from, s, 0, 0, true, false),
                       "before rules v3 the redeem script alone spends a script hash (anyone-can-spend)") ? 0 : 1;
        nFail += Check(!VerifySignature(from, s, 0, 0, true, true),
                       "under rules v3 it does not: the redeem script runs, and wants a signature") ? 0 : 1;
        nFail += Check(Spend::Ok(keyA, redeem, from, s, true), "with the signature it spends") ? 0 : 1;
        nFail += Check(GetP2SHSigOpCount(CScript() << std::vector<unsigned char>(1, 0) <<
                                         static_cast<std::vector<unsigned char> >(redeem)) == 1,
                       "the redeem script's CHECKSIG is counted against the block") ? 0 : 1;
    }

    // ---- the atomic swap: a hash-time-locked contract
    //
    // B gets the coins by showing the secret whose SHA-256 is in the script;
    // A gets them back after the lock if B never did. The same script, byte for
    // byte, is what the Bitcoin side of the swap uses.
    {
        std::vector<unsigned char> secret(32);
        RAND_bytes(&secret[0], 32);
        std::vector<unsigned char> hash(32);
        SHA256(&secret[0], secret.size(), &hash[0]);
        const int64 REFUND_AT = 2000;

        CScript htlc;
        htlc << OP_IF
                 << OP_SHA256 << hash << OP_EQUALVERIFY << keyB.GetPubKey() << OP_CHECKSIG
             << OP_ELSE
                 << REFUND_AT << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyA.GetPubKey() << OP_CHECKSIG
             << OP_ENDIF;
        CScript p; p.SetPayToScriptHash(htlc);
        CTransaction from; from.vout.push_back(CTxOut(10 * COIN, p));
        CTransaction s;
        s.vin.resize(1);
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        s.vout.push_back(CTxOut(10 * COIN - CENT, CScript() << keyB.GetPubKey() << OP_CHECKSIG));

        // claim: <sigB> <secret> TRUE <htlc>
        s.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sigB = SelfTestSign(keyB, htlc, s, 0);
        s.vin[0].scriptSig << sigB << secret << OP_TRUE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(VerifySignature(from, s, 0, 0, true, true), "B claims with the secret") ? 0 : 1;
        nFail += Check(s.vin[0].scriptSig.IsPushOnly(), "and the claim is push-only, as relay requires") ? 0 : 1;

        std::vector<unsigned char> wrong = secret;
        wrong[0] ^= 1;
        s.vin[0].scriptSig = CScript() << sigB << wrong << OP_TRUE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(!VerifySignature(from, s, 0, 0, true, true), "a wrong secret is refused") ? 0 : 1;

        std::vector<unsigned char> sigAc = SelfTestSign(keyA, htlc, s, 0);
        s.vin[0].scriptSig = CScript() << sigAc << secret << OP_TRUE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(!VerifySignature(from, s, 0, 0, true, true), "the secret is no use to anybody but B") ? 0 : 1;

        // refund: <sigA> FALSE <htlc>, needs nLockTime >= REFUND_AT and a non-final input
        CTransaction r = s;
        r.vout[0] = CTxOut(10 * COIN - CENT, CScript() << keyA.GetPubKey() << OP_CHECKSIG);
        r.vin[0].nSequence = 0;
        r.nLockTime = REFUND_AT;
        r.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sigA = SelfTestSign(keyA, htlc, r, 0);
        r.vin[0].scriptSig << sigA << OP_FALSE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(VerifySignature(from, r, 0, 0, true, true), "A takes the refund once the lock has passed") ? 0 : 1;
        nFail += Check(!r.IsFinalAt(REFUND_AT, 0) && r.IsFinalAt(REFUND_AT + 1, 0),
                       "and no block before the lock height can contain that refund") ? 0 : 1;

        CTransaction early = r;
        early.nLockTime = REFUND_AT - 1;
        early.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sigE = SelfTestSign(keyA, htlc, early, 0);
        early.vin[0].scriptSig << sigE << OP_FALSE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(!VerifySignature(from, early, 0, 0, true, true), "a refund dated before the lock is refused") ? 0 : 1;

        CTransaction stolen = r;
        stolen.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sigX = SelfTestSign(keyB, htlc, stolen, 0);
        stolen.vin[0].scriptSig << sigX << OP_FALSE << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(!VerifySignature(from, stolen, 0, 0, true, true), "B cannot take the refund path") ? 0 : 1;

        // Before rules v3 the script hash is not enforced at all -- anybody
        // holding the script spends it, no secret, no signature. That is the
        // whole reason the wallet refuses to pay to one until the switch.
        CTransaction anyone = s;
        anyone.vin[0].scriptSig = CScript() << static_cast<std::vector<unsigned char> >(htlc);
        nFail += Check(VerifySignature(from, anyone, 0, 0, true, false) &&
                       !VerifySignature(from, anyone, 0, 0, true, true),
                       "before rules v3 a swap output is anyone-can-spend; under them it is not") ? 0 : 1;
    }

    // ---- the swap contract the RPCs build (swap.h): Decred's, byte for byte
    {
        std::vector<unsigned char> secret(32);
        RAND_bytes(&secret[0], 32);
        swap::Contract c;
        c.secretHash.resize(32);
        SHA256(&secret[0], 32, &c.secretHash[0]);
        uint160 hB = Hash160(keyB.GetPubKey()), hA = Hash160(keyA.GetPubKey());
        c.recipientPkh.assign(hB.begin(), hB.end());
        c.refundPkh.assign(hA.begin(), hA.end());
        c.nLockTime = 51234;
        CScript k = swap::BuildContract(c);
        std::string hex = HexStr(k.begin(), k.end(), false);
        std::string sh = HexStr(c.secretHash.begin(), c.secretHash.end(), false);
        std::string pb = HexStr(c.recipientPkh.begin(), c.recipientPkh.end(), false);
        std::string pa = HexStr(c.refundPkh.begin(), c.refundPkh.end(), false);
        // 51234 = 0x00c822 -> pushed as 3 bytes 22 c8 00 (the 00 keeps it positive)
        std::string expect = "6382012088a820" + sh + "8876a914" + pb + "67" + "0322c800" +
                             "b17576a914" + pa + "6888ac";
        nFail += Check(hex == expect, "the contract is the atomicswap template, byte for byte") ? 0 : 1;

        swap::Contract back;
        nFail += Check(swap::ParseContract(k, back) && back.nLockTime == 51234 &&
                       back.secretHash == c.secretHash && back.recipientPkh == c.recipientPkh &&
                       back.refundPkh == c.refundPkh, "and parses back into the same terms") ? 0 : 1;
        CScript longer = k;
        longer << OP_NOP;
        nFail += Check(!swap::ParseContract(longer, back), "a contract with anything appended is not one") ? 0 : 1;

        CScript p2; p2.SetPayToScriptHash(k);
        CTransaction from; from.vout.push_back(CTxOut(3 * COIN, p2));
        CTransaction s;
        s.vin.resize(1);
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        s.vout.push_back(CTxOut(3 * COIN - CENT, CScript() << OP_TRUE));
        std::vector<unsigned char> sig = SelfTestSign(keyB, k, s, 0);
        s.vin[0].scriptSig = swap::RedeemScriptSig(sig, keyB.GetPubKey(), secret, k);
        nFail += Check(VerifySignature(from, s, 0, 0, true, true), "the redeem the RPC builds verifies") ? 0 : 1;
        std::vector<unsigned char> got;
        nFail += Check(swap::ExtractSecret(s.vin[0].scriptSig, c.secretHash, got) && got == secret,
                       "and the secret can be read back out of it") ? 0 : 1;

        CTransaction r = s;
        r.nLockTime = 51234;
        r.vin[0].nSequence = 0;
        r.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sigA = SelfTestSign(keyA, k, r, 0);
        r.vin[0].scriptSig = swap::RefundScriptSig(sigA, keyA.GetPubKey(), k);
        nFail += Check(VerifySignature(from, r, 0, 0, true, true), "the refund the RPC builds verifies") ? 0 : 1;

        std::vector<unsigned char> shortSecret(16, 7);
        unsigned char hs[32];
        SHA256(&shortSecret[0], 16, hs);
        swap::Contract cs = c;
        cs.secretHash.assign(hs, hs + 32);
        CScript ks = swap::BuildContract(cs);
        CScript p3; p3.SetPayToScriptHash(ks);
        CTransaction from3; from3.vout.push_back(CTxOut(COIN, p3));
        CTransaction s3 = s;
        s3.vin[0].prevout = COutPoint(from3.GetHash(), 0);
        s3.vin[0].scriptSig = CScript();
        std::vector<unsigned char> sig3 = SelfTestSign(keyB, ks, s3, 0);
        s3.vin[0].scriptSig = swap::RedeemScriptSig(sig3, keyB.GetPubKey(), shortSecret, ks);
        nFail += Check(!VerifySignature(from3, s3, 0, 0, true, true),
                       "a secret that is not 32 bytes is refused even when its hash matches") ? 0 : 1;
    }

    // ---- relay before activation
    {
        CTransaction pay;
        pay.vin.resize(1);
        pay.vout.push_back(CTxOut(COIN, p2shLock));
        nFail += Check(RulesV3Active((unsigned int)GetAdjustedTime()) || !pay.IsStandard(),
                       "while rules v3 are not active, paying to a script hash is not relayed") ? 0 : 1;
    }

    // ---- lock-in follows the chain's median time, not the clock or the tip's
    // own time: just after the switch a block may still be dated before it
    {
        CBlockIndex* pindexBestSaved = pindexBest;
        const unsigned int t = RulesV3Time();
        std::vector<CBlockIndex> chain(11);
        // Eleven blocks two minutes apart, the newest five after the switch: the
        // median (the sixth newest) is still before it.
        for (int i = 0; i < 11; i++)
        {
            chain[i].nHeight = 1000 + i;
            chain[i].nTime = t - 700 + 120 * i;
            chain[i].pprev = i ? &chain[i - 1] : NULL;
        }
        pindexBest = &chain[10];
        bool fTipPast = chain[10].nTime > t;
        bool fLockedEarly = RulesV3LockedIn();
        CTransaction pay;
        pay.vin.resize(1);
        pay.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 1);
        pay.vout.push_back(CTxOut(COIN, p2shLock));
        bool fRelayedEarly = pay.IsStandard();
        nFail += Check(fTipPast && !fLockedEarly && !fRelayedEarly,
                       "tip past the switch, median not yet: not locked in (the wallet refuses C addresses), not relayed") ? 0 : 1;

        // Six more blocks after it: now the median is past the switch too.
        chain.resize(17);
        for (int i = 0; i < 17; i++)
        {
            chain[i].nHeight = 1000 + i;
            chain[i].nTime = t - 700 + 120 * i;
            chain[i].pprev = i ? &chain[i - 1] : NULL;
        }
        pindexBest = &chain[16];
        bool fLocked = RulesV3LockedIn();
        bool fRelayed = pay.IsStandard();
        nFail += Check(chain[16].GetMedianTimePast() >= (int64)t && fLocked && fRelayed,
                       "median past the switch: locked in (the wallet pays C addresses), relayed") ? 0 : 1;

        pindexBest = NULL;
        nFail += Check(!RulesV3LockedIn(), "no chain: not locked in") ? 0 : 1;
        pindexBest = pindexBestSaved;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Little-endian bytes, appended: the template hash is spelled out again here
// by hand, so the test does not share a serializer with the code it checks.
static void V4PutLE(std::vector<unsigned char>& v, uint64 n, int nBytes)
{
    for (int i = 0; i < nBytes; i++)
        v.push_back((unsigned char)(n >> (8 * i)));
}

static uint256 V4Sha256(const std::vector<unsigned char>& v)
{
    uint256 h;
    SHA256(v.empty() ? (const unsigned char*)"" : &v[0], v.size(), (unsigned char*)&h);
    return h;
}

static uint256 V4TemplateHashByHand(const CTransaction& tx, unsigned int nIn)
{
    std::vector<unsigned char> seq, outs, all;
    for (size_t i = 0; i < tx.vin.size(); i++)
        V4PutLE(seq, tx.vin[i].nSequence, 4);
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        V4PutLE(outs, (uint64)tx.vout[i].nValue, 8);
        const CScript& s = tx.vout[i].scriptPubKey;
        if (s.size() < 253)
            outs.push_back((unsigned char)s.size());
        else
        {
            outs.push_back(253);
            V4PutLE(outs, s.size(), 2);
        }
        outs.insert(outs.end(), s.begin(), s.end());
    }
    V4PutLE(all, (uint32_t)tx.nVersion, 4);
    V4PutLE(all, tx.nLockTime, 4);
    V4PutLE(all, tx.vin.size(), 4);
    uint256 hs = V4Sha256(seq);
    all.insert(all.end(), hs.begin(), hs.end());
    V4PutLE(all, tx.vout.size(), 4);
    uint256 ho = V4Sha256(outs);
    all.insert(all.end(), ho.begin(), ho.end());
    V4PutLE(all, nIn, 4);
    return V4Sha256(all);
}

static std::vector<unsigned char> V4Hex(const char* psz)
{
    return ParseHex(psz);
}

// Rules v4 (docs/rules-v4.md): OP_CHECKSEQUENCEVERIFY and BIP68,
// OP_CHECKTEMPLATEVERIFY with the template hash without scriptSigs, and
// OP_CHECKSIGFROMSTACK with BIP340 signatures.
static int RunRulesV4SelfTest()
{
    printf("rules-v4 self-test\n");
    int nFail = 0;

    // ---- the switch
    bool fWasTestNet = IsTestNet();
    SelectNetworkParams(false);
    nFail += Check(RulesV4Time() == 1798200000 && !RulesV4Active(1798200000 - 1) &&
                   RulesV4Active(1798200000),
                   "mainnet: rules v4 from 2026-12-25 12:00 UTC, not a second before") ? 0 : 1;
    nFail += Check(RulesV4Time() >= RulesV3Time() && RulesV4Time() >= SwapsOpenTimeFor(false),
                   "after rules v3, and not ahead of the swaps") ? 0 : 1;
    SelectNetworkParams(true);
    nFail += Check(RulesV4Time() == 1795176000 && !RulesV4Active(1795176000 - 1) &&
                   RulesV4Active(1795176000),
                   "testnet: rules v4 from 2026-11-20 12:00 UTC, not a second before") ? 0 : 1;
    nFail += Check(RulesV4Time() >= RulesV3Time(), "and never ahead of rules v3") ? 0 : 1;
    nBenchRulesV4Time = 1792500000;
    nFail += Check(RulesV4Time() == 1792500000 && RulesV4Active(1792500000),
                   "an isolated testnet bench can move the switch (-benchrulesv4)") ? 0 : 1;
    SelectNetworkParams(false);
    nFail += Check(RulesV4Time() == 1798200000 && !RulesV4Active(1792500000),
                   "and that never reaches mainnet") ? 0 : 1;
    nBenchRulesV4Time = 0;
    SelectNetworkParams(fWasTestNet);

    nFail += Check(OP_CHECKSEQUENCEVERIFY == 0xb2 && OP_CHECKTEMPLATEVERIFY == 0xb3 &&
                   OP_CHECKSIGFROMSTACK == 0xcc &&
                   std::string(GetOpName(OP_CHECKSEQUENCEVERIFY)) == "OP_CHECKSEQUENCEVERIFY" &&
                   std::string(GetOpName(OP_CHECKTEMPLATEVERIFY)) == "OP_CHECKTEMPLATEVERIFY" &&
                   std::string(GetOpName(OP_CHECKSIGFROMSTACK)) == "OP_CHECKSIGFROMSTACK",
                   "the opcodes are Bitcoin's bytes and names") ? 0 : 1;

    // ---- OP_CHECKSEQUENCEVERIFY (BIP112)
    CTransaction t;
    t.nVersion = 2;
    t.vin.resize(1);
    t.vin[0].prevout = COutPoint(Hash(BEGIN(nFail), END(nFail)), 0);
    t.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    struct Csv
    {
        static bool Run(const CTransaction& tx, int64 nArg, bool fV4)
        {
            CScript s;
            s << nArg << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;
            return EvalScript(s, tx, 0, 0, NULL, true, true, fV4);
        }
    };
    const int64 TYPE = SEQUENCE_LOCKTIME_TYPE_FLAG;
    t.vin[0].nSequence = 10;
    nFail += Check(Csv::Run(t, 10, true), "CSV 10 blocks against nSequence 10 passes") ? 0 : 1;
    nFail += Check(Csv::Run(t, 0, true), "CSV 0 passes") ? 0 : 1;
    nFail += Check(!Csv::Run(t, 10, false), "the same script fails before rules v4: the byte is unknown") ? 0 : 1;
    nFail += Check(!Csv::Run(t, 11, true), "CSV 11 against nSequence 10 fails") ? 0 : 1;
    nFail += Check(!Csv::Run(t, TYPE | 10, true), "a time lock is not met by a height nSequence") ? 0 : 1;
    nFail += Check(!Csv::Run(t, -1, true), "a negative argument fails") ? 0 : 1;
    {
        // Negative zero is zero (Bitcoin's CScriptNum), not 128 or the
        // disable flag read off the raw bytes.
        CScript s1, s2;
        s1 << std::vector<unsigned char>(1, 0x80) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;
        unsigned char nz[4] = {0, 0, 0, 0x80};
        s2 << std::vector<unsigned char>(nz, nz + 4) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;
        CTransaction v1 = t;
        v1.nVersion = 1;
        nFail += Check(EvalScript(s1, t, 0, 0, NULL, true, true, true) &&
                       !EvalScript(s2, v1, 0, 0, NULL, true, true, true),
                       "a negative zero argument is 0: met by nSequence 10, and not a reserved pass in a version 1 tx") ? 0 : 1;
        CTransaction neg = t;
        neg.nVersion = -1;
        nFail += Check(Csv::Run(neg, 10, true), "a negative version counts as a large one, as in Bitcoin") ? 0 : 1;
    }
    t.vin[0].nSequence = (unsigned int)(TYPE | 5);
    nFail += Check(Csv::Run(t, TYPE | 5, true) && !Csv::Run(t, 5, true),
                   "time against time passes, height against time fails") ? 0 : 1;
    t.vin[0].nSequence = 10 | 0x00010000;   // bits outside the mask mean nothing
    nFail += Check(Csv::Run(t, 10, true) && Csv::Run(t, 10 | 0x00bf0000, true),
                   "bits outside the type flag and the mask are ignored on both sides") ? 0 : 1;
    t.vin[0].nSequence = SEQUENCE_LOCKTIME_DISABLE_FLAG | 10;
    nFail += Check(!Csv::Run(t, 10, true), "an input with relative locks disabled fails CSV") ? 0 : 1;
    nFail += Check(Csv::Run(t, (int64)SEQUENCE_LOCKTIME_DISABLE_FLAG, true),
                   "an argument with the disable flag is reserved and passes") ? 0 : 1;
    t.vin[0].nSequence = 10;
    t.nVersion = 1;
    nFail += Check(!Csv::Run(t, 10, true), "a version 1 transaction fails CSV") ? 0 : 1;
    t.nVersion = 2;
    {
        CScript s;
        s << OP_CHECKSEQUENCEVERIFY;
        nFail += Check(!EvalScript(s, t, 0, 0, NULL, true, true, true), "CSV on an empty stack fails") ? 0 : 1;
        CScript big;
        big << std::vector<unsigned char>(6, 1) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;
        nFail += Check(!EvalScript(big, t, 0, 0, NULL, true, true, true), "a 6-byte argument fails") ? 0 : 1;
    }

    // ---- BIP68: the relative lock in a block
    {
        // A chain of 40 blocks ten minutes apart, at disk positions of their
        // own, and a coin mined in block 20.
        std::vector<CBlockIndex*> chain;
        std::vector<uint256> vHashes;
        for (int h = 0; h < 40; h++)
        {
            CBlockIndex* p = new CBlockIndex();
            p->nHeight = h;
            p->nTime = 1800000000 + 600 * h;
            p->nFile = 77;
            p->nBlockPos = 1000 + h;
            p->pprev = h ? chain.back() : NULL;
            chain.push_back(p);
            uint256 hash = Hash(BEGIN(h), END(h));
            vHashes.push_back(hash);
            mapBlockIndex[hash] = p;
        }
        CTxIndex coin(CDiskTxPos(77, 1000 + 20, 0), 1);
        CTxIn in;
        in.nSequence = 5;
        nFail += Check(!SequenceLockPasses(in, coin, false, chain[23]) &&
                       SequenceLockPasses(in, coin, false, chain[24]),
                       "a 5-block lock on a coin of block 20: not in block 24, in block 25") ? 0 : 1;
        in.nSequence = 0;
        nFail += Check(SequenceLockPasses(in, coin, false, chain[19]),
                       "a zero lock is no lock, even a block early") ? 0 : 1;
        {
            // A block that fails to connect leaves the index again; the
            // lookup must still find a block added after it, at the same
            // count of entries as before (the review case: a cache judged
            // by size never looked).
            CBlockIndex* pBad = new CBlockIndex();
            pBad->nHeight = 40; pBad->nFile = 77; pBad->nBlockPos = 5000; pBad->pprev = chain.back();
            uint256 hBad = Hash(BEGIN(pBad->nBlockPos), END(pBad->nBlockPos));
            mapBlockIndex[hBad] = pBad;
            CTxIndex atBad(CDiskTxPos(77, 5000, 0), 1);
            bool fFoundBad = SequenceLockPasses(in, atBad, false, pBad);
            mapBlockIndex.erase(hBad);
            delete pBad;
            CBlockIndex* pGood = new CBlockIndex();
            pGood->nHeight = 40; pGood->nFile = 77; pGood->nBlockPos = 6000; pGood->pprev = chain.back();
            uint256 hGood = Hash(BEGIN(pGood->nBlockPos), END(pGood->nBlockPos));
            mapBlockIndex[hGood] = pGood;
            CTxIndex atGood(CDiskTxPos(77, 6000, 0), 1);
            CTxIndex atGone(CDiskTxPos(77, 5000, 0), 1);
            nFail += Check(fFoundBad && SequenceLockPasses(in, atGood, false, pGood) &&
                           !SequenceLockPasses(in, atGone, false, pGood),
                           "a block deleted from the index and one added after it: the new one is found, the old one is not") ? 0 : 1;
            mapBlockIndex.erase(hGood);
            delete pGood;
        }
        // Time: from the median time past of block 19; 3 units = 1536 s.
        in.nSequence = SEQUENCE_LOCKTIME_TYPE_FLAG | 3;
        int64 nBase = chain[19]->GetMedianTimePast();
        int k = 20;
        while (chain[k]->GetMedianTimePast() < nBase + 1536)
            k++;
        nFail += Check(!SequenceLockPasses(in, coin, false, chain[k - 1]) &&
                       SequenceLockPasses(in, coin, false, chain[k]),
                       "a 3 x 512 s lock is measured in median time past from the block before the coin's") ? 0 : 1;
        in.nSequence = SEQUENCE_LOCKTIME_DISABLE_FLAG | 30;
        nFail += Check(SequenceLockPasses(in, coin, false, chain[20]),
                       "with the disable flag there is no relative lock") ? 0 : 1;
        in.nSequence = 1;
        nFail += Check(!SequenceLockPasses(in, coin, true, chain[39]) &&
                       SequenceLockPasses(CTxIn(), coin, true, chain[39]),
                       "a coin still in the pool counts as mined in the next block") ? 0 : 1;
        CTxIndex nowhere(CDiskTxPos(78, 5, 0), 1);
        in.nSequence = 0;
        nFail += Check(!SequenceLockPasses(in, nowhere, false, chain[39]),
                       "a coin at a position no block has is refused") ? 0 : 1;
        for (size_t i = 0; i < vHashes.size(); i++)
            mapBlockIndex.erase(vHashes[i]);
        for (size_t i = 0; i < chain.size(); i++)
            delete chain[i];
    }

    // ---- OP_CHECKTEMPLATEVERIFY
    {
        CTransaction c;
        c.nVersion = 2;
        c.nLockTime = 123;
        c.vin.resize(2);
        c.vin[0].prevout = COutPoint(Hash(BEGIN(c.nLockTime), END(c.nLockTime)), 0);
        c.vin[0].nSequence = 7;
        c.vin[1].prevout = COutPoint(Hash(BEGIN(c.nVersion), END(c.nVersion)), 1);
        c.vin[1].nSequence = 0xfffffffe;
        c.vout.push_back(CTxOut(3 * COIN, CScript() << OP_TRUE));
        c.vout.push_back(CTxOut(CENT, CScript() << std::vector<unsigned char>(300, 7) << OP_DROP << OP_TRUE));
        uint256 h0 = CheckTemplateHash(c, 0);
        nFail += Check(h0 == V4TemplateHashByHand(c, 0) && CheckTemplateHash(c, 1) == V4TemplateHashByHand(c, 1),
                       "the template hash is BIP119's fields in BIP119's order, minus the scriptSigs") ? 0 : 1;
        nFail += Check(h0 != CheckTemplateHash(c, 1), "it commits to the input index") ? 0 : 1;
        CTransaction m = c;
        m.vin[0].scriptSig << OP_TRUE << std::vector<unsigned char>(40, 1);
        m.vin[1].prevout.n = 9;
        nFail += Check(CheckTemplateHash(m, 0) == h0,
                       "and not to scriptSigs or the coins spent, so P2SH can carry it") ? 0 : 1;
        struct Ctv
        {
            static bool Run(const CTransaction& tx, unsigned int nIn, const std::vector<unsigned char>& arg, bool fV4)
            {
                CScript s;
                s << arg << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;
                return EvalScript(s, tx, nIn, 0, NULL, true, true, fV4);
            }
        };
        std::vector<unsigned char> arg(h0.begin(), h0.end());
        nFail += Check(Ctv::Run(c, 0, arg, true), "CTV with the right template passes") ? 0 : 1;
        nFail += Check(!Ctv::Run(c, 0, arg, false), "and fails before rules v4") ? 0 : 1;
        nFail += Check(!Ctv::Run(c, 1, arg, true), "the template of input 0 does not pass input 1") ? 0 : 1;
        CTransaction d = c;
        d.vout[0].nValue -= 1;
        nFail += Check(!Ctv::Run(d, 0, arg, true), "one satoshi off in an output fails") ? 0 : 1;
        d = c; d.nLockTime++;
        nFail += Check(!Ctv::Run(d, 0, arg, true), "another nLockTime fails") ? 0 : 1;
        d = c; d.vin[1].nSequence--;
        nFail += Check(!Ctv::Run(d, 0, arg, true), "another nSequence, any input's, fails") ? 0 : 1;
        d = c; d.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
        nFail += Check(!Ctv::Run(d, 0, arg, true), "an extra output fails") ? 0 : 1;
        d = c; d.nVersion = 3;
        nFail += Check(!Ctv::Run(d, 0, arg, true), "another version fails") ? 0 : 1;
        nFail += Check(Ctv::Run(c, 0, std::vector<unsigned char>(31, 0), true) &&
                       Ctv::Run(c, 0, std::vector<unsigned char>(33, 0), true),
                       "an argument that is not 32 bytes is reserved and passes") ? 0 : 1;
        CScript bare;
        bare << OP_CHECKTEMPLATEVERIFY;
        nFail += Check(!EvalScript(bare, c, 0, 0, NULL, true, true, true), "CTV on an empty stack fails") ? 0 : 1;

        // In P2SH, with VerifySignature, as the wallet will use it.
        CScript redeem;
        redeem << arg << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;
        CScript p2sh;
        p2sh.SetPayToScriptHash(redeem);
        CTransaction from;
        from.vout.push_back(CTxOut(4 * COIN, p2sh));
        CTransaction s = c;
        s.vin[0].prevout = COutPoint(from.GetHash(), 0);
        s.vin[0].scriptSig = CScript() << static_cast<std::vector<unsigned char> >(redeem);
        uint256 hs = CheckTemplateHash(s, 0);
        nFail += Check(hs == h0, "spending a P2SH CTV output leaves the template hash as it was") ? 0 : 1;
        nFail += Check(VerifySignature(from, s, 0, 0, true, true, true) &&
                       !VerifySignature(from, s, 0, 0, true, true, false),
                       "a P2SH CTV spend verifies under rules v4 and not before") ? 0 : 1;
        s.vout[0].scriptPubKey = CScript() << OP_FALSE << OP_DROP << OP_TRUE;
        nFail += Check(!VerifySignature(from, s, 0, 0, true, true, true),
                       "and with its output redirected it does not") ? 0 : 1;
    }

    // ---- OP_CHECKSIGFROMSTACK
    {
        // BIP340's test vector 0: secret key 3, message 32 zero bytes.
        std::vector<unsigned char> pub0 = V4Hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        std::vector<unsigned char> msg0(32, 0);
        std::vector<unsigned char> sig0 = V4Hex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                                "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
        nFail += Check(SigCheckSchnorr(sig0, msg0, pub0), "BIP340 test vector 0 verifies") ? 0 : 1;
        std::vector<unsigned char> sigBad = sig0;
        sigBad[10] ^= 1;
        nFail += Check(!SigCheckSchnorr(sigBad, msg0, pub0), "and with one bit flipped it does not") ? 0 : 1;

        // A key of our own and a message of any length.
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        unsigned char seckey[32];
        do { RAND_bytes(seckey, 32); } while (!secp256k1_ec_seckey_verify(ctx, seckey));
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xpub;
        unsigned char pub32[32], sig64[64];
        std::string strMsg = "the price at 2027-05-01 12:00 UTC was 42";
        bool fKey = secp256k1_keypair_create(ctx, &kp, seckey) &&
                    secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp) &&
                    secp256k1_xonly_pubkey_serialize(ctx, pub32, &xpub) &&
                    secp256k1_schnorrsig_sign_custom(ctx, sig64, (const unsigned char*)strMsg.data(),
                                                     strMsg.size(), &kp, NULL);
        secp256k1_context_destroy(ctx);
        nFail += Check(fKey, "a BIP340 key and a signature over a 41-byte message") ? 0 : 1;
        std::vector<unsigned char> pub(pub32, pub32 + 32), sig(sig64, sig64 + 64);
        std::vector<unsigned char> msg(strMsg.begin(), strMsg.end());

        CTransaction any;
        any.vin.resize(1);
        any.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
        struct Csfs
        {
            // <sig> <msg> <pub> CSFS, then optionally NOT
            static bool Run(const CTransaction& tx, const std::vector<unsigned char>& s,
                            const std::vector<unsigned char>& m, const std::vector<unsigned char>& p,
                            bool fNot, bool fV4)
            {
                CScript sc;
                sc << s << m << p << OP_CHECKSIGFROMSTACK;
                if (fNot)
                    sc << OP_NOT;
                return EvalScript(sc, tx, 0, 0, NULL, true, true, fV4);
            }
        };
        nFail += Check(Csfs::Run(any, sig, msg, pub, false, true), "CSFS: the key signed the message") ? 0 : 1;
        nFail += Check(!Csfs::Run(any, sig, msg, pub, false, false), "and the byte is unknown before rules v4") ? 0 : 1;
        std::vector<unsigned char> msg2 = msg;
        msg2.back() = '3';
        nFail += Check(!Csfs::Run(any, sig, msg2, pub, false, true) && !Csfs::Run(any, sig, msg2, pub, true, true),
                       "a signature over another message fails the script, NOT or no NOT") ? 0 : 1;
        nFail += Check(!Csfs::Run(any, std::vector<unsigned char>(), msg, pub, false, true) &&
                       Csfs::Run(any, std::vector<unsigned char>(), msg, pub, true, true),
                       "an empty signature is false, and only that can be") ? 0 : 1;
        nFail += Check(!Csfs::Run(any, std::vector<unsigned char>(sig.begin(), sig.begin() + 63), msg, pub, true, true),
                       "a 63-byte signature fails the script") ? 0 : 1;
        nFail += Check(!Csfs::Run(any, sig, msg, std::vector<unsigned char>(), true, true),
                       "an empty key fails the script") ? 0 : 1;
        nFail += Check(Csfs::Run(any, sig, msg, std::vector<unsigned char>(33, 2), false, true),
                       "a key of another size is a later rule's, and passes") ? 0 : 1;
        nFail += Check(Csfs::Run(any, sig0, msg0, pub0, false, true),
                       "BIP340 vector 0 through the opcode") ? 0 : 1;
        CScript two;
        two << sig << msg << OP_CHECKSIGFROMSTACK;
        nFail += Check(!EvalScript(two, any, 0, 0, NULL, true, true, true), "fewer than three items fail") ? 0 : 1;

        CScript counted;
        counted << pub << OP_CHECKSIGFROMSTACK << OP_VERIFY << pub << OP_CHECKSIG;
        nFail += Check(counted.GetSigOpCount(false) == 1 && counted.GetSigOpCount(true) == 2,
                       "CSFS counts as a signature operation from rules v4 on") ? 0 : 1;
        CScript scriptSig;
        scriptSig << static_cast<std::vector<unsigned char> >(counted);
        nFail += Check(GetP2SHSigOpCount(scriptSig, true) == 2 && GetP2SHSigOpCount(scriptSig, false) == 1,
                       "inside a P2SH redeem script too") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// The treasury: the script the keys in treasury.cpp make, what pays it, and
// the coinbase split. Runs against both networks' tables; mainnet may be
// unconfigured, and then everything that would pay it must say so.
static int RunTreasurySelfTest()
{
    printf("treasury self-test\n");
    int nFail = 0;
    bool fWasTestNet = IsTestNet();

    for (int net = 0; net < 2; net++)
    {
        bool fTest = net == 1;
        SelectNetworkParams(fTest);
        printf("  -- %s\n", fTest ? "testnet" : "mainnet");
        CScript s;
        bool fHave = treasury::Script(s);
        nFail += Check(fHave == treasury::Configured(), "Script() and Configured() agree") ? 0 : 1;
        nFail += Check(treasury::Keys().size() == (fHave ? 3u : 0u), "three keys when configured, none otherwise") ? 0 : 1;
        nFail += Check((treasury::ScriptHex().empty()) == !fHave, "ScriptHex() is empty exactly when not configured") ? 0 : 1;
        if (!fHave)
        {
            nFail += Check(treasury::ShareOf(50 * COIN, 10) == 0, "no share is taken for an unconfigured treasury") ? 0 : 1;
            nFail += Check(!treasury::IsTreasury(CScript()), "nothing is the treasury when there is none") ? 0 : 1;
            continue;
        }
        txnouttype t; std::vector<std::vector<unsigned char> > sol;
        nFail += Check(SolverTyped(s, t, sol) && t == TX_MULTISIG && sol.size() == 5 && sol[0][0] == treasury::REQUIRED && sol[4][0] == 3,
                       "the script is a bare 2-of-3 multisig") ? 0 : 1;
        std::vector<std::string> keys = treasury::Keys();
        bool fKeysMatch = sol.size() == 5;
        for (size_t i = 0; fKeysMatch && i < 3; i++)
            fKeysMatch = HexStr(sol[i + 1].begin(), sol[i + 1].end(), false) == keys[i];
        nFail += Check(fKeysMatch, "the keys in the script are the keys listed, in order") ? 0 : 1;
        nFail += Check(treasury::IsTreasury(s), "the script is recognized as the treasury") ? 0 : 1;
        CScript other; other.SetMultisig(2, std::vector<std::vector<unsigned char> >(3, ParseHex(keys[0])));
        nFail += Check(!treasury::IsTreasury(other), "another 2-of-3 is not") ? 0 : 1;
        CTransaction txPay; txPay.vin.resize(1); txPay.vout.push_back(CTxOut(COIN, s));
        nFail += Check(txPay.IsStandard(), "a transaction paying it passes the relay policy") ? 0 : 1;
        nFail += Check(treasury::ScriptHex() == HexStr(s.begin(), s.end(), false), "ScriptHex() is the script") ? 0 : 1;

        // the coinbase split
        nFail += Check(treasury::ShareOf(50 * COIN, 10) == 5 * COIN, "10% of 50 BTF is 5 BTF") ? 0 : 1;
        nFail += Check(treasury::ShareOf(50 * COIN, 0) == 0, "0% is nothing") ? 0 : 1;
        nFail += Check(treasury::ShareOf(50 * COIN, treasury::SHARE_MAX_PERCENT + 1) == 0, "above the cap is nothing, not everything") ? 0 : 1;
        nFail += Check(treasury::ShareOf(50 * COIN, -5) == 0, "a negative share is nothing") ? 0 : 1;
        nFail += Check(treasury::ShareOf(1, 1) == 0 && treasury::ShareOf(0, 50) == 0, "a share below one satoshi is nothing") ? 0 : 1;
        int64 v = 50 * COIN + 12345;
        for (int pct = 1; pct <= treasury::SHARE_MAX_PERCENT; pct++)
        {
            int64 share = treasury::ShareOf(v, pct);
            if (share <= 0 || share > v || v - share <= 0)
            {
                nFail += Check(false, "every share leaves the miner something and the sum intact") ? 0 : 1;
                break;
            }
            if (pct == treasury::SHARE_MAX_PERCENT)
                nFail += Check(true, "every share leaves the miner something and the sum intact") ? 0 : 1;
        }
    }
    SelectNetworkParams(fWasTestNet);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// The chat over real sockets.
//
// btfchatlink is tested on its own over an in-memory pipe, so the protocol is
// already covered. What this covers is the socket glue: that SocketStream moves
// the bytes a Link needs, over a loopback pair, with the endpoint accepting the
// way the Tor-forwarded listener will. Loopback, not Tor, because the point is
// the glue -- Tor in the path would make the test measure Tor.
static int RunChatLinkSelfTest()
{
    printf("chat-link self-test\n");
    int nFail = 0;
#ifdef _WIN32
    SelfTestWinsock winsock;
    nFail += Check(winsock.fStarted, "Winsock started") ? 0 : 1;
#endif

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    nFail += Check(ctx != NULL, "secp256k1 context created") ? 0 : 1;
    if (!ctx)
        return nFail;
    {
        unsigned char rnd[32];
        RAND_bytes(rnd, sizeof(rnd));
        secp256k1_context_randomize(ctx, rnd);
    }

    // Two identities from fixed seeds. The chat key comes from the recovery
    // phrase and the session password, and neither is anywhere near this test.
    std::string err;
    btfchat::Identity alice, bob;
    {
        std::vector<unsigned char> seed(64, 0xA1);
        nFail += Check(btfchat::DeriveIdentityFromSeed(seed, "senha-bem-comprida", alice, err),
                       "a chat identity derives") ? 0 : 1;
        seed.assign(64, 0xB2);
        nFail += Check(btfchat::DeriveIdentityFromSeed(seed, "senha-bem-comprida", bob, err),
                       "and a second one") ? 0 : 1;
    }
    nFail += Check(alice.address != bob.address, "two different .btf addresses") ? 0 : 1;

    // A loopback pair standing in for Tor forwarding its hidden service to the
    // chat listener.
    SOCKET listener = INVALID_SOCKET;
    nFail += Check(btfchat::ChatListen(0, listener, err) == false,
                   "a chat listener refuses port 0") ? 0 : 1;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool fUp = listener != INVALID_SOCKET
        && ::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 0
        && listen(listener, 1) == 0;
#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    fUp = fUp && getsockname(listener, (struct sockaddr*)&addr, &addrLen) == 0;
    nFail += Check(fUp, "loopback chat listener up") ? 0 : 1;

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bool fConn = fUp && client != INVALID_SOCKET
        && connect(client, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    SOCKET server = fConn ? accept(listener, NULL, NULL) : INVALID_SOCKET;
    nFail += Check(fConn && server != INVALID_SOCKET, "dialled and accepted") ? 0 : 1;

    if (fConn && server != INVALID_SOCKET)
    {
        // The handshake needs both sides at once, so the endpoint runs in a
        // thread, exactly as the listener thread will.
        btfchat::SocketStream sClient(client, 20);
        btfchat::SocketStream sServer(server, 20);
        btfchat::Link linkClient, linkServer;

        struct Arg
        {
            btfchat::Link*         link;
            btfchat::SocketStream* stream;
            const unsigned char*   sk;
            std::atomic<bool>      fOk;   // the main thread polls it (ThreadSanitizer)
            std::string            err;
        };
        Arg arg;
        arg.link = &linkServer; arg.stream = &sServer; arg.sk = bob.chan_sk; arg.fOk = false;

        struct Runner
        {
            static void Accept(void* p)
            {
                Arg* a = (Arg*)p;
                a->fOk = a->link->AcceptAsEndpoint(*a->stream, a->sk, a->err);
            }
        };
        bool fThread = _beginthread(Runner::Accept, 0, &arg) != -1;
        nFail += Check(fThread, "endpoint thread started") ? 0 : 1;

        bool fCl = linkClient.ConnectAsClient(sClient, bob.chan_pk, err);
        nFail += Check(fCl, "the client handshake completed over a socket") ? 0 : 1;
        if (!fCl)
            printf("       (%s)\n", err.c_str());

        // Wait for the endpoint side rather than guessing.
        for (int i = 0; i < 200 && !arg.fOk; i++)
            Sleep(50);
        nFail += Check(arg.fOk, "and so did the endpoint") ? 0 : 1;
        if (!arg.fOk && !arg.err.empty())
            printf("       (%s)\n", arg.err.c_str());

        if (fCl && arg.fOk)
        {
            // A real frame, signed, over the socket, through the whole inbound
            // path on the receiving side.
            btfchat::Roster roster;
            btfchat::ReplayGuard replay;
            btfchat::History history;
            btfchat::Inbox inbox;
            inbox.secpctx = ctx;
            inbox.myAddress = bob.address;
            inbox.roster = &roster;
            inbox.replay = &replay;
            inbox.history = &history;

            int64 nNow = GetTime();

            btfchat::Frame inv;
            inv.kind = btfchat::MSG_INVITE;
            inv.sent = nNow;
            inv.text = "primeiro contato";
            std::string jsInv;
            nFail += Check(btfchat::SignFrame(ctx, alice, inv, jsInv, err),
                           "alice signs an invite") ? 0 : 1;
            nFail += Check(linkClient.SendFrame(sClient, jsInv, err),
                           "it goes out over the socket") ? 0 : 1;

            std::string got;
            nFail += Check(linkServer.RecvFrame(sServer, got, err) && got == jsInv,
                           "and arrives byte for byte") ? 0 : 1;

            btfchat::Frame opened;
            nFail += Check(inbox.Deliver(got, alice.address, nNow, opened, err),
                           "the inbound path accepts it") ? 0 : 1;
            nFail += Check(roster.State(alice.address) == btfchat::PEER_INVITE_IN,
                           "and it lands as a pending invite") ? 0 : 1;

            // Before bob accepts, a message is refused -- over a real socket the
            // same as over the pipe.
            btfchat::Frame msg;
            msg.kind = btfchat::MSG_TEXT;
            msg.sent = nNow;
            msg.text = "posso falar antes de aceitar?";
            std::string jsMsg;
            btfchat::SignFrame(ctx, alice, msg, jsMsg, err);
            nFail += Check(linkClient.SendFrame(sClient, jsMsg, err), "a message is sent") ? 0 : 1;
            nFail += Check(linkServer.RecvFrame(sServer, got, err), "and received") ? 0 : 1;
            nFail += Check(!inbox.Deliver(got, alice.address, nNow, opened, err),
                           "and refused: nothing before the accept") ? 0 : 1;
            nFail += Check(history.MessageCount() == 0, "nothing was filed") ? 0 : 1;

            nFail += Check(roster.AcceptInvite(alice.address, err), "bob accepts") ? 0 : 1;
            btfchat::Frame msg2;
            msg2.kind = btfchat::MSG_TEXT;
            msg2.sent = nNow;
            msg2.text = "agora sim";
            std::string jsMsg2;
            btfchat::SignFrame(ctx, alice, msg2, jsMsg2, err);
            nFail += Check(linkClient.SendFrame(sClient, jsMsg2, err), "she writes again") ? 0 : 1;
            nFail += Check(linkServer.RecvFrame(sServer, got, err), "it arrives") ? 0 : 1;
            nFail += Check(inbox.Deliver(got, alice.address, nNow, opened, err) &&
                           history.MessageCount() == 1,
                           "and this one is filed") ? 0 : 1;

            // The reply direction, so both ratchets are exercised over sockets.
            btfchat::Frame rep;
            rep.kind = btfchat::MSG_TEXT;
            rep.sent = nNow;
            rep.text = "recebido";
            std::string jsRep;
            btfchat::SignFrame(ctx, bob, rep, jsRep, err);
            nFail += Check(linkServer.SendFrame(sServer, jsRep, err), "bob answers") ? 0 : 1;
            nFail += Check(linkClient.RecvFrame(sClient, got, err) && got == jsRep,
                           "and alice reads it") ? 0 : 1;
        }

        linkClient.Close();
        linkServer.Close();
    }

    if (client != INVALID_SOCKET) closesocket(client);
    if (server != INVALID_SOCKET) closesocket(server);
    if (listener != INVALID_SOCKET) closesocket(listener);

    // Outbound is onion-only, with no clearnet fallback. Checked here because it
    // is a policy, not an implementation detail: a fallback that works when Tor
    // is down leaks the user's address at the worst possible moment.
    SOCKET s = INVALID_SOCKET;
    nFail += Check(!btfchat::ChatDialOnion("127.0.0.1:8533", 5, s, err) &&
                   err.find("onion") != std::string::npos,
                   "dialling a clearnet address is refused") ? 0 : 1;
    nFail += Check(!btfchat::ChatDialOnion("example.com:8533", 5, s, err),
                   "and so is a hostname") ? 0 : 1;
    nFail += Check(!btfchat::ChatDialOnion("noport.onion", 5, s, err),
                   "an endpoint with no port is refused") ? 0 : 1;
    nFail += Check(!btfchat::ChatDialOnion("abc.onion:notanumber", 5, s, err),
                   "and one with a junk port") ? 0 : 1;
    nFail += Check(!btfchat::ChatDialOnion("abc.onion:99999", 5, s, err),
                   "and one out of range") ? 0 : 1;
    // With a well-formed onion and no Tor configured, it must refuse rather than
    // find another way out.
    nFail += Check(!BtfTorProxyEnabled(), "no Tor proxy in a self-test") ? 0 : 1;
    nFail += Check(!btfchat::ChatDialOnion(
                       "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:8533",
                       5, s, err) && err.find("Tor") != std::string::npos,
                   "and with no Tor it refuses instead of falling back") ? 0 : 1;

    secp256k1_context_destroy(ctx);

    printf("%s (%d failures)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail);
    return nFail == 0 ? 0 : 1;
}

// Where the chat identity comes from.
//
// The point being protected here is that the twelve words never reach the chat.
// The wallet keeps the BIP32 master key and chain code, not the BIP39 seed, and
// those two are a deterministic function of the seed -- so the same phrase gives
// the same chat identity on any machine while the phrase itself stays out of this
// process. A phrase that is not in memory cannot be screenshotted or logged.
// A Stream whose far end is a node's own message handler: what the client
// writes goes into the node's receive buffer and through ProcessMessages, what
// the node pushed is what the client reads. The real node code against the real
// chat client, with no socket and no Tor in between.
class HandlerStream : public btfchat::Stream
{
public:
    explicit HandlerStream(CNode* p) : pnode(p) {}
    bool Write(const unsigned char* p, size_t n)
    {
        pnode->vRecv.insert(pnode->vRecv.end(), (const char*)p, (const char*)p + n);
        ProcessMessages(pnode);
        return !pnode->fDisconnect;
    }
    bool Read(unsigned char* p, size_t n)
    {
        if (pnode->vSend.size() < n)
            return false;
        memcpy(p, &pnode->vSend.begin()[0], n);
        pnode->vSend.ignore((int)n);
        return true;
    }
private:
    CNode* pnode;
};

// Pull every complete message out of a node's send buffer.
static void DrainMessages(CNode& node, std::vector<std::pair<std::string, std::vector<char> > >& out)
{
    out.clear();
    unsigned int nHdr = CMessageHeader::SizeOnWire(node.vSend.GetVersion());
    while (node.vSend.size() >= nHdr)
    {
        CDataStream h(node.vSend.begin(), node.vSend.begin() + nHdr, SER_NETWORK, node.vSend.GetVersion());
        CMessageHeader hdr;
        h >> hdr;
        if (node.vSend.size() < nHdr + hdr.nMessageSize)
            break;
        std::vector<char> pay(node.vSend.begin() + nHdr, node.vSend.begin() + nHdr + hdr.nMessageSize);
        out.push_back(std::make_pair(hdr.GetCommand(), pay));
        node.vSend.ignore((int)(nHdr + hdr.nMessageSize));
    }
}

static btfchat::ChatRecord SelfTestEnvelope(const std::vector<unsigned char>& tag, size_t nPayload)
{
    btfchat::ChatRecord r;
    r.kind = btfchat::CHATREC_ENVELOPE;
    r.key = tag;
    r.nTime = GetTime();
    r.payload.resize(nPayload);
    RAND_bytes(&r.payload[0], (int)nPayload);
    btfchat::ChatRecordMine(r);
    return r;
}

static int RunChatRelaySelfTest()
{
    printf("chat-relay self-test\n");
    int nFail = 0;
    std::string err, why;
    // A datadir of its own: the community directory reads and writes a file in
    // it, and a self-test has no business touching the real one.
    {
        std::string tmp;
        if (MakeTempDir(tmp))
            strSetDataDir = tmp;
    }

    {
        CTxDB txdb("cr+");   // an inv is looked up in the transaction index; there is none yet
    }

    // A peer that holds chat records, to watch what the node relays to it, and
    // one that does not, to make sure it is never offered any.
    CNode* peerChat = new CNode(INVALID_SOCKET, CAddress());
    peerChat->nVersion = VERSION;
    peerChat->nServices = NODE_NETWORK | NODE_CHAT;
    peerChat->vSend.SetVersion(VERSION);
    peerChat->vRecv.SetVersion(VERSION);
    CNode* peerOld = new CNode(INVALID_SOCKET, CAddress());
    peerOld->nVersion = VERSION;
    peerOld->nServices = NODE_NETWORK;
    CRITICAL_BLOCK(cs_vNodes)
    {
        vNodes.push_back(peerChat);
        vNodes.push_back(peerOld);
    }

    // ---- the chat app, connected to this node
    CNode* app = new CNode(INVALID_SOCKET, CAddress(), true);
    HandlerStream st(app);
    btfchat::NodeLink link(st);
    nFail += Check(link.Handshake(err), "the chat client completes a handshake with the real node handler") ? 0 : 1;
    if (!err.empty()) printf("       %s\n", err.c_str());
    nFail += Check((link.Services() & NODE_CHAT) != 0, "and the node says it holds chat records") ? 0 : 1;
    nFail += Check(app->nVersion == VERSION && app->fClient,
                   "the node sees a client, not a node: no chain asked of it") ? 0 : 1;

    std::vector<unsigned char> tag(16);
    RAND_bytes(&tag[0], 16);
    btfchat::ChatRecord env = SelfTestEnvelope(tag, 700);
    int nResult = -1;
    nFail += Check(link.Put(env, nResult, why, err) && nResult == btfchat::ChatStore::ACCEPTED,
                   "an envelope left by the app is kept, and the app is told so") ? 0 : 1;
    nResult = -1;
    nFail += Check(link.Put(env, nResult, why, err) && nResult == btfchat::ChatStore::DUPLICATE,
                   "the same envelope again is a duplicate, not an error") ? 0 : 1;

    btfchat::ChatRecord lazy = env;
    lazy.payload[0] ^= 1;
    while (btfchat::ChatRecordHasWork(lazy))
        lazy.nNonce++;
    nResult = -1;
    nFail += Check(link.Put(lazy, nResult, why, err) && nResult == btfchat::ChatStore::REJECTED &&
                   why.find("proof of work") != std::string::npos,
                   "one without the work is refused, and the app is told why") ? 0 : 1;

    // ---- asking
    {
        std::vector<unsigned char> other(16);
        RAND_bytes(&other[0], 16);
        std::vector<CChatQuery> q(2);
        q[0].kind = btfchat::CHATREC_ENVELOPE; q[0].key = tag;   q[0].nSince = 0; q[0].nMax = 64;
        q[1].kind = btfchat::CHATREC_ENVELOPE; q[1].key = other; q[1].nSince = 0; q[1].nMax = 64;
        std::vector<std::vector<btfchat::ChatRecord> > ans;
        nFail += Check(link.Get(q, ans, err) && ans.size() == 2,
                       "two questions in one request get two answers") ? 0 : 1;
        nFail += Check(ans.size() == 2 && ans[0].size() == 1 && ans[0][0].IdHex() == env.IdHex(),
                       "the first is the envelope left under that tag") ? 0 : 1;
        nFail += Check(ans.size() == 2 && ans[1].empty(), "the second, under a tag nobody used, is empty") ? 0 : 1;

        q.resize(1);
        q[0].nSince = GetTime() + 60;
        nFail += Check(link.Get(q, ans, err) && ans.size() == 1 && ans[0].empty(),
                       "'since' after it leaves it out") ? 0 : 1;
    }

    // ---- relayed to the node that holds chat records, never to the old one
    CInv invEnv;
    {
        unsigned char id[32];
        env.Id(id);
        uint256 h;
        memcpy(h.begin(), id, 32);
        invEnv = CInv(MSG_CHATREC, h);
    }
    bool fOffered = false, fOfferedOld = false, fOfferedApp = false;
    CNode* who[3] = { peerChat, peerOld, app };
    bool* flag[3] = { &fOffered, &fOfferedOld, &fOfferedApp };
    for (int w = 0; w < 3; w++)
        CRITICAL_BLOCK(who[w]->cs_inventory)
            for (size_t i = 0; i < who[w]->vInventoryToSend.size(); i++)
                if (who[w]->vInventoryToSend[i].type == invEnv.type &&
                    who[w]->vInventoryToSend[i].hash == invEnv.hash)
                    *flag[w] = true;
    nFail += Check(fOffered, "a kept record is offered to the peer that holds chat records") ? 0 : 1;
    nFail += Check(!fOfferedOld, "and never to a node from before the chat") ? 0 : 1;
    nFail += Check(!fOfferedApp, "nor back to where it came from") ? 0 : 1;
    nFail += Check(ChatRelayAlreadyHave(invEnv), "and the node answers 'have' for it") ? 0 : 1;

    // ---- the peer asks for it, the node sends it
    std::vector<std::pair<std::string, std::vector<char> > > msgs;
    {
        CNode wire(INVALID_SOCKET, CAddress());
        wire.vSend.clear();
        wire.vSend.SetVersion(VERSION);
        wire.PushMessage("getdata", std::vector<CInv>(1, invEnv));
        peerChat->vSend.clear();
        peerChat->vRecv.insert(peerChat->vRecv.end(), wire.vSend.begin(), wire.vSend.end());
        ProcessMessages(peerChat);
        DrainMessages(*peerChat, msgs);
        bool fGot = false;
        for (size_t i = 0; i < msgs.size(); i++)
            if (msgs[i].first == "chatrec")
            {
                CDataStream ss(msgs[i].second, SER_NETWORK, VERSION);
                std::vector<unsigned char> blob;
                ss >> blob;
                btfchat::ChatRecord back;
                fGot = !blob.empty() && back.Parse(&blob[0], blob.size()) && back.IdHex() == env.IdHex();
            }
        nFail += Check(fGot, "getdata from a peer is answered with the record itself") ? 0 : 1;
    }

    // ---- a record relayed by another node is taken, and the app can find it
    std::vector<unsigned char> tag2(16);
    RAND_bytes(&tag2[0], 16);
    btfchat::ChatRecord relayed = SelfTestEnvelope(tag2, 300);
    {
        // A record is taken from the peer that announced it (and so was asked).
        unsigned char idRelayed[32];
        relayed.Id(idRelayed);
        uint256 hRelayed;
        memcpy(hRelayed.begin(), idRelayed, 32);
        CNode announce(INVALID_SOCKET, CAddress());
        announce.vSend.clear();
        announce.vSend.SetVersion(VERSION);
        announce.PushMessage("inv", std::vector<CInv>(1, CInv(MSG_CHATREC, hRelayed)));
        peerChat->vRecv.insert(peerChat->vRecv.end(), announce.vSend.begin(), announce.vSend.end());
        ProcessMessages(peerChat);
        CNode wire(INVALID_SOCKET, CAddress());
        wire.vSend.clear();
        wire.vSend.SetVersion(VERSION);
        wire.PushMessage("chatrec", relayed.Serialize());
        peerChat->vRecv.insert(peerChat->vRecv.end(), wire.vSend.begin(), wire.vSend.end());
        ProcessMessages(peerChat);
        std::vector<CChatQuery> q(1);
        q[0].kind = btfchat::CHATREC_ENVELOPE; q[0].key = tag2; q[0].nSince = 0; q[0].nMax = 64;
        std::vector<std::vector<btfchat::ChatRecord> > ans;
        nFail += Check(link.Get(q, ans, err) && ans.size() == 1 && ans[0].size() == 1 &&
                       ans[0][0].IdHex() == relayed.IdHex(),
                       "a record another node relays is kept and served to the app") ? 0 : 1;
    }

    // ---- a peer that just connected can ask for everything we hold, once in a while
    {
        CNode wire(INVALID_SOCKET, CAddress());
        wire.vSend.clear();
        wire.vSend.SetVersion(VERSION);
        wire.PushMessage("getchatinv");
        std::vector<char> once(wire.vSend.begin(), wire.vSend.end());
        peerChat->vSend.clear();
        peerChat->vRecv.insert(peerChat->vRecv.end(), &once[0], &once[0] + once.size());
        ProcessMessages(peerChat);
        DrainMessages(*peerChat, msgs);
        size_t nOffered = 0;
        for (size_t i = 0; i < msgs.size(); i++)
            if (msgs[i].first == "inv")
            {
                CDataStream ss(msgs[i].second, SER_NETWORK, VERSION);
                std::vector<CInv> v;
                ss >> v;
                for (size_t k = 0; k < v.size(); k++)
                    if (v[k].type == MSG_CHATREC)
                        nOffered++;
            }
        nFail += Check(nOffered == 2, "getchatinv is answered with the ids of every record held") ? 0 : 1;

        peerChat->vRecv.insert(peerChat->vRecv.end(), &once[0], &once[0] + once.size());
        ProcessMessages(peerChat);
        DrainMessages(*peerChat, msgs);
        nFail += Check(msgs.empty(), "and asking again straight away gets nothing") ? 0 : 1;
    }

    // ---- descriptors: published by one identity, resolved and verified by the client rules
    {
        btfchat::Identity alice;
        std::vector<unsigned char> seed(64, 0x77);
        btfchat::DeriveIdentityFromSeed(seed, "senha-bem-comprida", alice, err);
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        std::string encHex = HexStr(alice.chan_pk, alice.chan_pk + 32, false);   // no spaces: the default has them
        int64 nCreated = GetTime();
        std::string onion = "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8533";
        std::string desc = btf::SignDescriptor(ctx, alice.sign_sk, encHex, "", (uint64_t)nCreated, onion);
        btfchat::ChatRecord d;
        d.kind = btfchat::CHATREC_DESC;
        unsigned char pk[32];
        btf::ParseAddress(alice.address, pk);
        d.key.assign(pk, pk + 32);
        d.nTime = nCreated;
        d.payload.assign(desc.begin(), desc.end());
        btfchat::ChatRecordMine(d);
        nResult = -1;
        nFail += Check(link.Put(d, nResult, why, err) && nResult == btfchat::ChatStore::ACCEPTED,
                       "a signed chat descriptor is kept") ? 0 : 1;

        std::vector<CChatQuery> q(1);
        q[0].kind = btfchat::CHATREC_DESC; q[0].key = d.key; q[0].nSince = 0; q[0].nMax = 1;
        std::vector<std::vector<btfchat::ChatRecord> > ans;
        bool fOk = link.Get(q, ans, err) && ans.size() == 1 && ans[0].size() == 1;
        nFail += Check(fOk && btfchat::ChatRecordVerifySigned(ctx, ans[0][0], GetTime(), why),
                       "and what the node answers verifies against the address asked for") ? 0 : 1;
        secp256k1_context_destroy(ctx);
        btfchat::IdentityClear(alice);
    }

    // ---- the ration: a chat app may not fill the node by itself
    {
        CNode* greedy = new CNode(INVALID_SOCKET, CAddress(), true);
        HandlerStream gs(greedy);
        btfchat::NodeLink gl(gs);
        gl.Handshake(err);
        btfchat::ChatRecord junk;
        junk.kind = btfchat::CHATREC_ENVELOPE;
        junk.key.assign(16, 0);
        junk.nTime = GetTime();
        junk.payload.assign(10, 1);
        for (int i = 0; i < 60; i++)
            gl.Put(junk, nResult, why, err);
        btfchat::ChatRecord fine = SelfTestEnvelope(tag, 100);
        nResult = -1;
        nFail += Check(gl.Put(fine, nResult, why, err) && nResult == btfchat::ChatStore::REJECTED &&
                       why.find("slow down") != std::string::npos,
                       "past sixty records a minute, even a good one is turned away") ? 0 : 1;
        delete greedy;
    }

    // ---- the public community directory: a listing in a block, read by the
    // node, asked for by the app
    {
        unsigned char ckey[32];
        RAND_bytes(ckey, 32);
        std::vector<unsigned char> data = community::ListingData(ckey, "selftest-room");
        CBlock block;
        CTransaction tx;
        tx.vin.resize(1);
        tx.vout.push_back(CTxOut(community::MIN_BURN, CScript() << OP_RETURN << data));
        CTransaction cheap = tx;
        cheap.vout[0].nValue = community::MIN_BURN - 1;
        cheap.vout[0].scriptPubKey = CScript() << OP_RETURN << community::ListingData(ckey, "cheap-room");
        block.vtx.push_back(tx);
        block.vtx.push_back(cheap);
        nFail += Check(ChatDirectoryScanBlock(block, 4242) == 1,
                       "the node reads a listing out of a block, and not one that burned too little") ? 0 : 1;
        std::vector<CChatListing> dir;
        int nHeight = -1;
        nFail += Check(link.GetDirectory(dir, nHeight, err), "the app asks the node for the directory") ? 0 : 1;
        bool fFound = false;
        for (size_t i = 0; i < dir.size(); i++)
            if (dir[i].name == "selftest-room" && dir[i].nHeight == 4242 &&
                dir[i].key == std::vector<unsigned char>(ckey, ckey + 32))
                fFound = true;
        nFail += Check(fFound, "and gets the listing back, key, name and block") ? 0 : 1;
        nFail += Check(ChatDirectoryScanBlock(block, 4243) == 0, "a listing seen once is not listed twice") ? 0 : 1;
    }

    // ---- the client will not use a node that does not hold chat records
    {
        uint64 nSaved = nLocalServices;
        nLocalServices = NODE_NETWORK;            // what a 1.2.28 node says
        CNode* old = new CNode(INVALID_SOCKET, CAddress(), true);
        nLocalServices = nSaved;
        HandlerStream os(old);
        btfchat::NodeLink ol(os);
        bool fShook = ol.Handshake(err);
        nFail += Check(!fShook && err.find("older release") != std::string::npos,
                       "a node from before the chat is recognised and not used") ? 0 : 1;
        delete old;
    }

    CRITICAL_BLOCK(cs_vNodes)
    {
        vNodes.erase(std::find(vNodes.begin(), vNodes.end(), peerChat));
        vNodes.erase(std::find(vNodes.begin(), vNodes.end(), peerOld));
    }
    delete peerChat;
    delete peerOld;
    delete app;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// One command and one argument, as a peer sends it, handled by the node.
template <typename T>
static void FeedChatPeer(CNode* peer, const char* cmd, const T& arg)
{
    CNode wire(INVALID_SOCKET, CAddress());
    wire.vSend.clear();
    wire.vSend.SetVersion(VERSION);
    wire.PushMessage(cmd, arg);
    peer->vRecv.insert(peer->vRecv.end(), wire.vSend.begin(), wire.vSend.end());
    ProcessMessages(peer);
}

// -selftest=chat-dos -- the resource limits of the chat (review M7, M10):
// a store that fills asks for more work with every record and says how much
// (the chat app mines again); a chat record is taken only from the peer that
// announced it; the rations that were per connection are also per node; a
// connection cannot be served without a slot, and a burst of frames saves the
// store once; and whole numbers are read out of JSON as whole numbers.
static int RunChatDosSelfTest()
{
    printf("chat-dos self-test\n");
    int nFail = 0;
    std::string err, why;
    {
        std::string tmp;
        if (MakeTempDir(tmp))
            strSetDataDir = tmp;
    }

    {
        CTxDB txdb("cr+");   // an inv is looked up in the transaction index; there is none yet
    }

    // ---- M7: the work asked grows as the store fills
    const size_t B = btfchat::CHATREC_ENVELOPE_BUDGET;
    nFail += Check(btfchat::ChatRecordFullnessBits(0, B) == 0 && btfchat::ChatRecordFullnessBits(B / 2 - 1, B) == 0 &&
                   btfchat::ChatRecordFullnessBits(B / 2, B) == 2 && btfchat::ChatRecordFullnessBits(B / 4 * 3, B) == 4 &&
                   btfchat::ChatRecordFullnessBits(B / 10 * 9, B) == 6 && btfchat::ChatRecordFullnessBits(B, B) == 6 &&
                   btfchat::ChatRecordFullnessBits(5, 0) == 0,
                   "nothing extra below half the budget, then 2, 4 and 6 more bits") ? 0 : 1;
    nFail += Check(btfchat::ChatRecordAskedBits("not enough proof of work: this node asks 24 bits now") == 24 &&
                   btfchat::ChatRecordAskedBits("not enough proof of work") == 0 &&
                   btfchat::ChatRecordAskedBits("this node asks 999999 bits now") == 0 &&
                   btfchat::ChatRecordAskedBits("this node asks 99 bits") == 99 &&
                   btfchat::ChatRecordAskedBits("this node asks 300 bits now") == 0 &&
                   btfchat::ChatRecordAskedBits("asks -5 bits now") == 0 &&
                   btfchat::ChatRecordAskedBits("") == 0,
                   "the figure is read off a refusal, and nothing else is taken for one") ? 0 : 1;
    {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        btfchat::ChatStore st(1);
        int64_t nNow = GetTime();
        int nKept = 0;
        for (int i = 0; i < 400 && st.Bytes(btfchat::CHATREC_ENVELOPE) < B / 2; i++)
        {
            btfchat::ChatRecord r;
            r.kind = btfchat::CHATREC_ENVELOPE;
            r.key.assign(16, 0);
            r.key[0] = (unsigned char)i;
            r.key[1] = (unsigned char)(i >> 8);
            r.nTime = nNow;
            r.payload.assign(60000, (unsigned char)i);
            btfchat::ChatRecordMine(r, 0, 1);
            unsigned char id[32];
            if (st.Accept(ctx, r, nNow, why, id) == btfchat::ChatStore::ACCEPTED)
                nKept++;
        }
        nFail += Check(st.Bytes(btfchat::CHATREC_ENVELOPE) >= B / 2, "a store is filled to half its envelope budget") ? 0 : 1;
        nFail += Check(st.RequiredBits(btfchat::CHATREC_ENVELOPE, 100) == 3 &&
                       st.RequiredBits(btfchat::CHATREC_DESC, 100) == 1,
                       "an envelope now needs 2 more bits than a descriptor, whose budget is empty") ? 0 : 1;
        btfchat::ChatRecord r;
        r.kind = btfchat::CHATREC_ENVELOPE;
        r.key.assign(16, 0xee);
        r.nTime = nNow;
        r.payload.assign(100, 7);
        btfchat::ChatRecordMine(r, 0, 1);
        // the base work (1 bit) but less than the 3 bits asked: a nonce that
        // gives 0 bits would make the relayed case below fail by chance
        while (btfchat::ChatRecordWork(r) >= 3 || btfchat::ChatRecordWork(r) < 1)
            r.nNonce++;
        unsigned char id[32];
        btfchat::ChatStore::Result res = st.Accept(ctx, r, nNow, why, id);
        nFail += Check(res == btfchat::ChatStore::REJECTED && btfchat::ChatRecordAskedBits(why) == 3,
                       "a record with the old work is refused, and the refusal says 3 bits") ? 0 : 1;
        nFail += Check(st.RequiredBits(btfchat::CHATREC_ENVELOPE, 100, true) == 1 &&
                       st.Accept(ctx, r, nNow, why, id, true) == btfchat::ChatStore::ACCEPTED,
                       "the same record relayed by another node needs one step (2 bits) less of this store's fullness") ? 0 : 1;
        nFail += Check(btfchat::ChatRecordFullnessBits(B / 4 * 3, B) == 4 &&
                       btfchat::ChatRecordFullnessBits(B / 10 * 9, B) == 6,
                       "(at three quarters full a relayed record pays 2 bits over base, at nine tenths 4: the budget cannot be filled at the base price)") ? 0 : 1;
        btfchat::ChatRecord r2 = r;
        r2.payload[0] ^= 1;
        btfchat::ChatRecordMine(r2, 0, 1);
        while (btfchat::ChatRecordWork(r2) >= 3 || btfchat::ChatRecordWork(r2) < 1)
            r2.nNonce++;
        nFail += Check(st.Accept(ctx, r2, nNow, why, id) == btfchat::ChatStore::REJECTED,
                       "while one put by a chat app with that work is still refused") ? 0 : 1;
        r = r2;
        btfchat::ChatRecordMine(r, 0, 3);
        nFail += Check(st.Accept(ctx, r, nNow, why, id) == btfchat::ChatStore::ACCEPTED,
                       "the same record mined to what was asked is kept") ? 0 : 1;
        secp256k1_context_destroy(ctx);
    }

    // ---- M7: only what a peer announced is taken from it
    CNode* peer = new CNode(INVALID_SOCKET, CAddress());
    peer->nVersion = VERSION;
    peer->nServices = NODE_NETWORK | NODE_CHAT;
    peer->vSend.SetVersion(VERSION);
    peer->vRecv.SetVersion(VERSION);
    CRITICAL_BLOCK(cs_vNodes)
        vNodes.push_back(peer);
    {
        std::vector<unsigned char> tagA(16), tagB(16);
        RAND_bytes(&tagA[0], 16);
        RAND_bytes(&tagB[0], 16);
        btfchat::ChatRecord a = SelfTestEnvelope(tagA, 300);
        btfchat::ChatRecord b = SelfTestEnvelope(tagB, 300);
        unsigned char idA[32], idB[32];
        a.Id(idA);
        b.Id(idB);
        uint256 hA, hB;
        memcpy(hA.begin(), idA, 32);
        memcpy(hB.begin(), idB, 32);
        CInv invA(MSG_CHATREC, hA), invB(MSG_CHATREC, hB);

        FeedChatPeer(peer, "chatrec", a.Serialize());
        nFail += Check(!ChatRelayAlreadyHave(invA), "a record nobody announced is not taken") ? 0 : 1;
        FeedChatPeer(peer, "inv", std::vector<CInv>(1, invA));
        FeedChatPeer(peer, "chatrec", b.Serialize());
        nFail += Check(!ChatRelayAlreadyHave(invB) && !ChatRelayAlreadyHave(invA),
                       "after an announcement of one record, another is still not taken") ? 0 : 1;
        FeedChatPeer(peer, "chatrec", a.Serialize());
        nFail += Check(ChatRelayAlreadyHave(invA), "the announced one is") ? 0 : 1;
    }

    // ---- M7: the answer to chatget is bounded per connection
    {
        CNode* app = new CNode(INVALID_SOCKET, CAddress(), true);
        HandlerStream st(app);
        btfchat::NodeLink link(st);
        link.Handshake(err);
        std::vector<unsigned char> tag(16);
        RAND_bytes(&tag[0], 16);
        btfchat::ChatRecord env = SelfTestEnvelope(tag, 700);
        int nResult = -1;
        nFail += Check(link.Put(env, nResult, why, err) && nResult == btfchat::ChatStore::ACCEPTED,
                       "an envelope is left with the node") ? 0 : 1;
        std::vector<CChatQuery> q(1);
        q[0].kind = btfchat::CHATREC_ENVELOPE; q[0].key = tag; q[0].nSince = 0; q[0].nMax = 64;
        std::vector<std::vector<btfchat::ChatRecord> > ans;
        nFail += Check(link.Get(q, ans, err) && ans.size() == 1 && ans[0].size() == 1,
                       "and served back") ? 0 : 1;
        app->nChatWindowStart = GetTime();
        app->nChatAnswerBytesInWindow = (size_t)1 << 40;
        nFail += Check(link.Get(q, ans, err) && ans.size() == 1 && ans[0].empty(),
                       "a connection that has been served its minute's bytes gets an empty answer") ? 0 : 1;
        delete app;
    }

    // ---- M7: the rations per connection are also per node, and are charged
    // only for records that show their work
    {
        int nPuts0 = 0, nRel0 = 0, nPuts1 = 0, nRel1 = 0;
        ChatRelayRations(nPuts0, nRel0);
        std::vector<CNode*> apps;
        btfchat::ChatRecord junk;
        junk.kind = btfchat::CHATREC_ENVELOPE;
        junk.key.assign(16, 0);
        junk.nTime = GetTime();
        junk.payload.assign(10, 1);
        int nResult = -1;
        int nWorkRefusals = 0;
        for (int c = 0; c < 11; c++)
        {
            CNode* g = new CNode(INVALID_SOCKET, CAddress(), true);
            apps.push_back(g);
            HandlerStream gs(g);
            btfchat::NodeLink gl(gs);
            gl.Handshake(err);
            for (int i = 0; i < 59; i++)
                if (gl.Put(junk, nResult, why, err) && why.find("proof of work") != std::string::npos)
                    nWorkRefusals++;
        }
        ChatRelayRations(nPuts1, nRel1);
        nFail += Check(nWorkRefusals == 11 * 59 && nPuts1 == nPuts0 && nRel1 == nRel0,
                       "649 records with no work are refused for it and cost the node-wide ration nothing") ? 0 : 1;

        CNode* fresh = new CNode(INVALID_SOCKET, CAddress(), true);
        HandlerStream fs(fresh);
        btfchat::NodeLink fl(fs);
        fl.Handshake(err);
        std::vector<unsigned char> tag(16);
        RAND_bytes(&tag[0], 16);
        btfchat::ChatRecord fine = SelfTestEnvelope(tag, 100);
        nResult = -1;
        nFail += Check(fl.Put(fine, nResult, why, err) && nResult == btfchat::ChatStore::ACCEPTED,
                       "so a record with its work still goes in after all that") ? 0 : 1;
        ChatRelayRations(nPuts1, nRel1);
        nFail += Check(nPuts1 == nPuts0 + 1, "and it is the one thing the ration counted") ? 0 : 1;
        nResult = -1;
        nFail += Check(fl.Put(fine, nResult, why, err) && nResult == btfchat::ChatStore::DUPLICATE, "the same record again is a duplicate") ? 0 : 1;
        ChatRelayRations(nPuts1, nRel1);
        nFail += Check(nPuts1 == nPuts0 + 1, "and replaying a record the node holds costs the node's minute nothing") ? 0 : 1;
        btfchat::ChatRecord gone = SelfTestEnvelope(tag, 100);
        gone.nTime = GetTime() - 3 * 24 * 3600;           // long expired, with real work for its own time
        btfchat::ChatRecordMine(gone);
        nResult = -1;
        nFail += Check(fl.Put(gone, nResult, why, err) && nResult == btfchat::ChatStore::REJECTED, "an expired one is refused") ? 0 : 1;
        ChatRelayRations(nPuts1, nRel1);
        nFail += Check(nPuts1 == nPuts0 + 1, "and costs the ration nothing either") ? 0 : 1;

        ChatRelayExhaustRations();
        RAND_bytes(&tag[0], 16);
        btfchat::ChatRecord fine2 = SelfTestEnvelope(tag, 100);
        nResult = -1;
        nFail += Check(fl.Put(fine2, nResult, why, err) && nResult == btfchat::ChatStore::REJECTED &&
                       why.find("too many records right now") != std::string::npos,
                       "once the node's minute is spent, a record with its work is told to slow down") ? 0 : 1;
        nFail += Check(fl.Put(junk, nResult, why, err) && why.find("proof of work") != std::string::npos,
                       "and one without is still told about its work") ? 0 : 1;
        delete fresh;
        for (size_t i = 0; i < apps.size(); i++)
            delete apps[i];
    }

    CRITICAL_BLOCK(cs_vNodes)
        vNodes.erase(std::find(vNodes.begin(), vNodes.end(), peer));
    delete peer;

    // ---- M10: serving slots, and the save after a frame
    {
        std::vector<uint64_t> tickets;
        int nTaken = 0;
        for (int i = 0; i < 100; i++)
        {
            uint64_t t = 0;
            if (btfchat::ChatServeSlotTake(INVALID_SOCKET, t, 1000 + i))
            {
                nTaken++;
                tickets.push_back(t);
            }
        }
        nFail += Check(nTaken == 100 && btfchat::ChatServeThreadCount() == 32,
                       "connections that never finish their handshake take turns in 32 slots, the oldest put out") ? 0 : 1;
        for (size_t i = 0; i < tickets.size(); i++)
            btfchat::ChatServeSlotHandshaken(tickets[i]);
        uint64_t t = 0;
        nFail += Check(!btfchat::ChatServeSlotTake(INVALID_SOCKET, t, 2000) && btfchat::ChatServeThreadCount() == 32,
                       "once 32 have finished theirs, the 33rd is turned away") ? 0 : 1;
        btfchat::ChatServeSlotRelease(tickets.back());
        bool fTook = btfchat::ChatServeThreadCount() == 31 && btfchat::ChatServeSlotTake(INVALID_SOCKET, t, 2001);
        btfchat::ChatServeSlotHandshaken(t);
        nFail += Check(fTook && !btfchat::ChatServeSlotTake(INVALID_SOCKET, t, 2002),
                       "one that ends frees one for the next") ? 0 : 1;
        btfchat::ChatServeSlotRelease(t);
        for (size_t i = 0; i < tickets.size(); i++)
            btfchat::ChatServeSlotRelease(tickets[i]);
        nFail += Check(btfchat::ChatServeThreadCount() == 0, "and they all come back (a ticket given twice does nothing)") ? 0 : 1;
        {
            std::vector<uint64_t> fresh;
            for (int i = 0; i < 32; i++)
            {
                uint64_t tk = 0;
                btfchat::ChatServeSlotTake(INVALID_SOCKET, tk, 5000);
                fresh.push_back(tk);
            }
            uint64_t extra = 0;
            bool fEarly = btfchat::ChatServeSlotTake(INVALID_SOCKET, extra, 5002);
            bool fLate = btfchat::ChatServeSlotTake(INVALID_SOCKET, extra, 5006);
            nFail += Check(!fEarly && fLate,
                           "a handshake is put out for a new connection only once it has had five seconds") ? 0 : 1;
            btfchat::ChatServeSlotForget(fresh[5]);        // no handle left to shut down; the slot stays
            for (size_t i = 0; i < fresh.size(); i++)
                btfchat::ChatServeSlotRelease(fresh[i]);
            btfchat::ChatServeSlotRelease(extra);
            nFail += Check(btfchat::ChatServeThreadCount() == 0, "and they come back") ? 0 : 1;
        }

        bool fDirty = false;
        bool a = btfchat::ChatServeSaveDue(50000, fDirty);
        bool fDirtyA = fDirty;
        bool b = btfchat::ChatServeSaveDue(50000, fDirty);
        bool fDirtyB = fDirty;
        bool c = btfchat::ChatServeSaveDue(50001, fDirty);
        bool fDirtyC = fDirty;
        bool d = btfchat::ChatServeSaveDue(49000, fDirty);
        nFail += Check(a && !fDirtyA && !b && fDirtyB && c && !fDirtyC && d,
                       "frames in the same second save once, a later one saves, and a clock set back does not stall it") ? 0 : 1;
    }

    // ---- whole numbers out of JSON
    {
        using nlohmann::json;
        json j = json::parse("{\"a\":5,\"b\":1.9,\"c\":1e300,\"d\":\"7\",\"e\":-3,\"f\":4294967296,\"g\":18446744073709551615,\"h\":null}");
        nFail += Check(JsonIntValue<int>(j, "a", 0) == 5 && JsonIntValue<int>(j, "missing", 9) == 9 &&
                       JsonIntValue<int>(j, "e", 0) == -3 && JsonIntValue<int64_t>(j, "f", 0) == 4294967296LL,
                       "an integer that fits is read, a missing key gives the default") ? 0 : 1;
        const char* bad[] = { "b", "c", "d", "f", "g", "h" };
        bool fAllThrow = true;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            bool fThrew = false;
            try { JsonIntValue<int>(j, bad[i], 0); }
            catch (...) { fThrew = true; }
            if (!fThrew)
                fAllThrow = false;
        }
        nFail += Check(fAllThrow, "a float, a string, null or a number out of range is refused, not cast") ? 0 : 1;
        bool fThrew = false;
        try { JsonIntValue<int>(json::parse("[1]"), "a", 0); }
        catch (...) { fThrew = true; }
        nFail += Check(fThrew, "and a value that is not an object is not read as one") ? 0 : 1;

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        const char* frames[] = {
            "{\"v\":1e300,\"k\":1,\"from\":\"x\",\"t\":1,\"id\":\"i\",\"sig\":\"\"}",
            "{\"v\":1,\"k\":1e300,\"from\":\"x\",\"t\":1,\"id\":\"i\",\"sig\":\"\"}",
            "{\"v\":1,\"k\":2.5,\"from\":\"x\",\"t\":1,\"id\":\"i\",\"sig\":\"\"}",
            "{\"v\":1,\"k\":1,\"from\":\"x\",\"t\":1e300,\"id\":\"i\",\"sig\":\"\"}",
            "{\"v\":1,\"k\":1,\"from\":\"x\",\"t\":1,\"amt\":-1e300,\"id\":\"i\",\"sig\":\"\"}",
        };
        bool fNoThrowNoOpen = true;
        for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++)
        {
            btfchat::Frame f;
            bool fOpened = true, fThrow = false;
            try { fOpened = btfchat::OpenFrame(ctx, frames[i], f, err); }
            catch (...) { fThrow = true; }
            if (fThrow || fOpened)
                fNoThrowNoOpen = false;
        }
        nFail += Check(fNoThrowNoOpen, "a frame whose numbers are floats out of range is refused, without throwing") ? 0 : 1;
        secp256k1_context_destroy(ctx);
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// An event as a relay would send it, signed by the key sk.
static nlohmann::json NostrTestEvent(secp256k1_context* ctx, const unsigned char sk[32], int64 nCreated,
                                     int nKind, const nlohmann::json& tags, const std::string& content)
{
    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, sk);
    secp256k1_xonly_pubkey xp;
    secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp);
    unsigned char pk[32];
    secp256k1_xonly_pubkey_serialize(ctx, pk, &xp);
    std::string pkHex = HexStr(pk, pk + 32, false);
    std::string ser = nlohmann::json::array({ 0, pkHex, nCreated, nKind, tags, content }).dump();
    unsigned char id[32], sig[64];
    SHA256((const unsigned char*)ser.data(), ser.size(), id);
    secp256k1_schnorrsig_sign32(ctx, sig, id, &kp, NULL);
    nlohmann::json ev = nlohmann::json::object();
    ev["id"] = HexStr(id, id + 32, false);
    ev["pubkey"] = pkHex;
    ev["created_at"] = nCreated;
    ev["kind"] = nKind;
    ev["tags"] = tags;
    ev["content"] = content;
    ev["sig"] = HexStr(sig, sig + 64, false);
    return ev;
}

static std::string NostrTestMessage(const char* sub, const nlohmann::json& ev)
{
    return nlohmann::json::array({ "EVENT", sub, ev }).dump();
}

static void NostrTestKey(int n, unsigned char sk[32])
{
    std::string s = strprintf("nostr-relay self-test key %d", n);
    SHA256((const unsigned char*)s.data(), s.size(), sk);
}

static std::string NostrTestAddress(secp256k1_context* ctx, const unsigned char sk[32])
{
    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, sk);
    secp256k1_xonly_pubkey xp;
    secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp);
    unsigned char pk[32];
    secp256k1_xonly_pubkey_serialize(ctx, pk, &xp);
    return btf::Address(pk);
}

// -selftest=nostr-relay -- what public relays hand the node (review M8): an
// event is believed only if its id is its hash and its signature verifies; a
// date ahead of the clock or long past is not taken; the table of discovered
// peers and the list of pools have a size, and one relay adds only so many
// addresses a round; a descriptor is believed because its own signature
// verifies, whatever the event around it says.
static int RunNostrRelaySelfTest()
{
    printf("nostr-relay self-test\n");
    int nFail = 0;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const int64 nNow = GetTime();
    const std::string sub = "btf-disc-1";
    const nlohmann::json dTags = nlohmann::json::array({ nlohmann::json::array({ "d", NostrDescriptorTag() }) });
    unsigned char sk0[32];
    NostrTestKey(0, sk0);

    // ---- an event signed by something else: BIP-340 as the BIP's own reference
    // code writes it (pure Python, no libsecp256k1), over a NIP-01 event
    {
        const char* vec = "{\"id\":\"3cbb6d6babe5f774c30894f7f395d811791014f5888cf46f17cb6ab30694391f\","
                          "\"pubkey\":\"8cc23dde23a163ad3152b8fcf826d61faf4f73f8ca1a5d212623b96c7b234b4c\","
                          "\"created_at\":1790000000,\"kind\":1,\"tags\":[[\"d\",\"btf-descriptor-2\"]],"
                          "\"content\":\"hello nostr\","
                          "\"sig\":\"80b86170d2654c1bd02df168d9df4627d6582ebccad522599a99da40db2a891d"
                          "8e6852ada342ac7b75311c8e67be0f39bc98bf6b1a5249252a5a65fb7736effd\"}";
        NostrEvent out;
        std::string err;
        nFail += Check(NostrVerifyEvent(ctx, vec, out, err) && out.content == "hello nostr",
                       "an event signed by an independent implementation verifies") ? 0 : 1;
        std::string bad = vec;
        bad[bad.find("hello")] = 'j';
        nFail += Check(!NostrVerifyEvent(ctx, bad, out, err), "and with one letter of its content changed it does not") ? 0 : 1;
    }

    // ---- an event is checked, not believed
    {
        nlohmann::json ev = NostrTestEvent(ctx, sk0, nNow, NostrDescriptorKind(), dTags, "hello");
        NostrEvent out;
        std::string err;
        nFail += Check(NostrVerifyEvent(ctx, ev.dump(), out, err) && out.content == "hello" && out.kind == NostrDescriptorKind(),
                       "a signed event is taken") ? 0 : 1;
        nlohmann::json bad = ev;
        bad["content"] = "hellp";
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err), "one whose content was changed is not (its id is no longer its hash)") ? 0 : 1;
        bad = ev;
        std::string sg = bad["sig"].get<std::string>();
        sg[5] = sg[5] == '0' ? '1' : '0';
        bad["sig"] = sg;
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err), "nor one whose signature was changed") ? 0 : 1;
        bad = ev;
        std::string up = bad["id"].get<std::string>();
        for (size_t i = 0; i < up.size(); i++)
            up[i] = (char)toupper((unsigned char)up[i]);
        bad["id"] = up;
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err),
                       "nor one with an id in capitals: one key, one spelling") ? 0 : 1;
        bad = ev;
        bad["pubkey"] = std::string(64, '0');
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err), "nor one claiming a key that is not a point") ? 0 : 1;
        bad = ev;
        bad["created_at"] = 1e300;
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err), "nor one dated with a float out of range") ? 0 : 1;
        bad = ev;
        bad["tags"] = "none";
        nFail += Check(!NostrVerifyEvent(ctx, bad.dump(), out, err), "nor one whose tags are not a list") ? 0 : 1;
        nFail += Check(!NostrVerifyEvent(ctx, "[1,2,3]", out, err) && !NostrVerifyEvent(ctx, "", out, err),
                       "nor something that is not an event") ? 0 : 1;
    }

    // ---- discovery: a signed descriptor event adds a peer; the rest do not
    {
        int nNew = 0;
        int nBefore = GetDiscoveredPeerCount();
        nlohmann::json ev = NostrTestEvent(ctx, sk0, nNow, NostrDescriptorKind(), dTags, "x");
        std::string msg = NostrTestMessage(sub.c_str(), ev);
        nFail += Check(NostrIngestDiscovery(ctx, msg, sub, NULL, nNow, nNew) == NOSTR_MSG_TAKEN &&
                       GetDiscoveredPeerCount() == nBefore + 1 && nNew == 1,
                       "a signed discovery event adds one peer") ? 0 : 1;

        nlohmann::json forged = ev;
        unsigned char sk1[32];
        NostrTestKey(1, sk1);
        nlohmann::json other = NostrTestEvent(ctx, sk1, nNow, NostrDescriptorKind(), dTags, "x");
        forged["pubkey"] = other["pubkey"];     // somebody else's key on this event
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), forged), sub, NULL, nNow, nNew) == NOSTR_MSG_REFUSED &&
                       GetDiscoveredPeerCount() == nBefore + 1,
                       "the same event with another key's name on it adds nothing") ? 0 : 1;

        unsigned char sk2[32];
        NostrTestKey(2, sk2);
        nlohmann::json future = NostrTestEvent(ctx, sk2, nNow + 3600, NostrDescriptorKind(), dTags, "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), future), sub, NULL, nNow, nNew) == NOSTR_MSG_REFUSED &&
                       GetDiscoveredPeerCount() == nBefore + 1,
                       "an event dated an hour ahead adds nothing: it would sort first for good") ? 0 : 1;
        nlohmann::json soon = NostrTestEvent(ctx, sk2, nNow + 300, NostrDescriptorKind(), dTags, "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), soon), sub, NULL, nNow, nNew) == NOSTR_MSG_TAKEN,
                       "one a few minutes ahead (clocks differ) does") ? 0 : 1;
        unsigned char sk3[32];
        NostrTestKey(3, sk3);
        nlohmann::json stale = NostrTestEvent(ctx, sk3, nNow - 5 * 3600, NostrDescriptorKind(), dTags, "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), stale), sub, NULL, nNow, nNew) == NOSTR_MSG_REFUSED,
                       "and a stale one adds nothing: there is nobody to dial") ? 0 : 1;
        nlohmann::json wrongKind = NostrTestEvent(ctx, sk3, nNow, 1, dTags, "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), wrongKind), sub, NULL, nNow, nNew) == NOSTR_MSG_REFUSED,
                       "nor one of another kind") ? 0 : 1;
        nlohmann::json noTag = NostrTestEvent(ctx, sk3, nNow, NostrDescriptorKind(), nlohmann::json::array(), "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), noTag), sub, NULL, nNow, nNew) == NOSTR_MSG_REFUSED,
                       "nor one without the tag the subscription asks for") ? 0 : 1;
        unsigned char selfPk[32];
        {
            secp256k1_keypair kp;
            secp256k1_keypair_create(ctx, &kp, sk3);
            secp256k1_xonly_pubkey xp;
            secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp);
            secp256k1_xonly_pubkey_serialize(ctx, selfPk, &xp);
        }
        nlohmann::json mine = NostrTestEvent(ctx, sk3, nNow, NostrDescriptorKind(), dTags, "x");
        nFail += Check(NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), mine), sub, selfPk, nNow, nNew) == NOSTR_MSG_REFUSED,
                       "this node's own event is not added as a peer") ? 0 : 1;
        nFail += Check(NostrIngestDiscovery(ctx, nlohmann::json::array({ "EOSE", sub }).dump(), sub, NULL, nNow, nNew) == NOSTR_MSG_EOSE &&
                       NostrIngestDiscovery(ctx, NostrTestMessage("other-sub", ev), sub, NULL, nNow, nNew) == NOSTR_MSG_OTHER &&
                       NostrIngestDiscovery(ctx, "garbage", sub, NULL, nNow, nNew) == NOSTR_MSG_OTHER,
                       "end of stored events, another subscription's event and garbage are told apart") ? 0 : 1;
    }

    // ---- one relay adds at most so many new addresses a round; the table has a ceiling
    {
        int nNew = 0;
        int nBefore = GetDiscoveredPeerCount();
        for (int i = 0; i < 80; i++)
        {
            unsigned char k[32];
            NostrTestKey(1000 + i, k);
            NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), NostrTestEvent(ctx, k, nNow, NostrDescriptorKind(), dTags, "x")),
                                 sub, NULL, nNow, nNew);
        }
        nFail += Check(nNew == (int)NOSTR_MAX_NEW_PEERS_PER_ROUND && GetDiscoveredPeerCount() == nBefore + (int)NOSTR_MAX_NEW_PEERS_PER_ROUND,
                       "a relay that sends eighty new addresses in one round adds fifty") ? 0 : 1;
        for (int round = 0; round < 45; round++)
        {
            nNew = 0;
            for (int i = 0; i < (int)NOSTR_MAX_NEW_PEERS_PER_ROUND; i++)
            {
                unsigned char k[32];
                NostrTestKey(2000 + round * 100 + i, k);
                NostrIngestDiscovery(ctx, NostrTestMessage(sub.c_str(), NostrTestEvent(ctx, k, nNow - 1000 + round, NostrDescriptorKind(), dTags, "x")),
                                     sub, NULL, nNow, nNew);
            }
        }
        nFail += Check(GetDiscoveredPeerCount() == (int)NOSTR_MAX_BTF_PEERS,
                       "round after round, the table stops at its ceiling") ? 0 : 1;
    }

    // ---- pools
    {
        const std::string psub = "btf-pools-1";
        unsigned char pk[32];
        NostrTestKey(5000, pk);
        std::string addr = NostrTestAddress(ctx, pk);
        nlohmann::json content = { { "btf", addr }, { "name", "Selftest pool" }, { "fee_pct", 1.5 }, { "miners", 3 }, { "hashrate", 1234.5 } };
        nlohmann::json tags = nlohmann::json::array({ nlohmann::json::array({ "d", "btf-pool" }) });
        nlohmann::json ev = NostrTestEvent(ctx, pk, nNow, NostrPoolKind(), tags, content.dump());
        nFail += Check(NostrIngestPool(NostrTestMessage(psub.c_str(), ev), psub, nNow) == NOSTR_MSG_TAKEN &&
                       NostrDiscoveredPoolCount() == 1,
                       "a pool announcement signed by the key whose address it names is listed") ? 0 : 1;
        nlohmann::json forged = ev;
        std::string sg = forged["sig"].get<std::string>();
        sg[9] = sg[9] == '0' ? '1' : '0';
        forged["sig"] = sg;
        nFail += Check(NostrIngestPool(NostrTestMessage(psub.c_str(), forged), psub, nNow) == NOSTR_MSG_REFUSED,
                       "the same with a bad signature is not") ? 0 : 1;
        unsigned char pk2[32];
        NostrTestKey(5001, pk2);
        nlohmann::json other = content;
        other["btf"] = addr;       // another key announcing this pool's address
        nFail += Check(NostrIngestPool(NostrTestMessage(psub.c_str(), NostrTestEvent(ctx, pk2, nNow, NostrPoolKind(), tags, other.dump())), psub, nNow) == NOSTR_MSG_REFUSED,
                       "an announcement of another key's address is not: a pool speaks for itself") ? 0 : 1;
        nFail += Check(NostrIngestPool(NostrTestMessage(psub.c_str(), NostrTestEvent(ctx, pk, nNow + 7200, NostrPoolKind(), tags, content.dump())), psub, nNow) == NOSTR_MSG_REFUSED,
                       "nor one dated two hours ahead") ? 0 : 1;
        nlohmann::json odd = content;
        odd["miners"] = 1e300;
        odd["fee_pct"] = -50;
        NostrIngestPool(NostrTestMessage(psub.c_str(), NostrTestEvent(ctx, pk, nNow + 1, NostrPoolKind(), tags, odd.dump())), psub, nNow);
        std::vector<BtfPoolAnnouncement> pools;
        BtfGetPoolAnnouncements(pools);
        nFail += Check(pools.size() == 1 && pools[0].connectedMiners == 0 && pools[0].feePercent == 0,
                       "figures that are not figures read as zero") ? 0 : 1;

        for (int i = 0; i < 260; i++)
        {
            unsigned char k[32];
            NostrTestKey(6000 + i, k);
            nlohmann::json c = { { "btf", NostrTestAddress(ctx, k) }, { "name", "p" } };
            NostrIngestPool(NostrTestMessage(psub.c_str(), NostrTestEvent(ctx, k, nNow, NostrPoolKind(), tags, c.dump())), psub, nNow);
        }
        nFail += Check(NostrDiscoveredPoolCount() == NOSTR_MAX_POOLS, "the list of pools stops at its ceiling") ? 0 : 1;
        {
            std::vector<BtfPoolAnnouncement> all;
            BtfGetPoolAnnouncements(all);
            unsigned char klast[32];
            NostrTestKey(6000 + 259, klast);
            std::string lastAddr = NostrTestAddress(ctx, klast);
            bool fHave = false;
            for (size_t i = 0; i < all.size(); i++)
                if (all[i].btfAddress == lastAddr)
                    fHave = true;
            nFail += Check(fHave, "and the newest announcement is in it: a full list drops the oldest, it does not turn the new away") ? 0 : 1;
        }
        {
            std::string e50;
            for (int i = 0; i < 50; i++)
                e50 += "\xc3\xa9";                 // 100 bytes of e-acute
            std::string c = NostrClampUtf8(e50, 63);
            nFail += Check(c.size() == 62 && NostrClampUtf8("short", 64) == "short" &&
                           NostrClampUtf8(std::string(100, 'a'), 64).size() == 64 &&
                           (unsigned char)c[0] == 0xc3,
                           "a pool name is cut to the size the network accepts, never inside a character") ? 0 : 1;
        }
        unsigned char kl[32];
        NostrTestKey(7000, kl);
        nlohmann::json cl = { { "btf", NostrTestAddress(ctx, kl) }, { "name", "late" } };
        NostrIngestPool(NostrTestMessage(psub.c_str(), NostrTestEvent(ctx, kl, nNow + 100000, NostrPoolKind(), tags, cl.dump())), psub, nNow + 100000);
        nFail += Check(NostrDiscoveredPoolCount() == 1, "and an old announcement is dropped when a new one is added, not only when somebody looks") ? 0 : 1;
    }

    // ---- a descriptor is believed for its own signature
    {
        const std::string dsub = "btf-resolve-1";
        unsigned char dk[32];
        NostrTestKey(8000, dk);
        std::string addr = NostrTestAddress(ctx, dk);
        nlohmann::json anyEvent = NostrTestEvent(ctx, dk, nNow, NostrDescriptorKind(), dTags, "x");
        std::string hexpk = anyEvent["pubkey"].get<std::string>();
        std::string encHex(64, 'a');
        std::string desc = btf::SignDescriptor(ctx, dk, encHex, "", (uint64_t)nNow,
                                               "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8533");
        std::map<std::string, std::string> want;
        want[hexpk] = addr;
        std::string a, c;
        nlohmann::json ev = anyEvent;
        ev["content"] = desc;             // the id and signature no longer match: the descriptor is what counts
        nFail += Check(NostrIngestDescriptor(ctx, NostrTestMessage(dsub.c_str(), ev), dsub, want, a, c) == NOSTR_MSG_TAKEN &&
                       a == addr && c == desc,
                       "a descriptor signed by the address asked for is taken") ? 0 : 1;
        nlohmann::json tampered = ev;
        std::string d2 = desc;
        d2[d2.size() / 2] = d2[d2.size() / 2] == 'a' ? 'b' : 'a';
        tampered["content"] = d2;
        nFail += Check(NostrIngestDescriptor(ctx, NostrTestMessage(dsub.c_str(), tampered), dsub, want, a, c) == NOSTR_MSG_REFUSED,
                       "one changed on the way is not") ? 0 : 1;
        std::map<std::string, std::string> none;
        nFail += Check(NostrIngestDescriptor(ctx, NostrTestMessage(dsub.c_str(), ev), dsub, none, a, c) == NOSTR_MSG_REFUSED,
                       "nor one from a key nobody asked about") ? 0 : 1;
        nlohmann::json num = ev;
        num["pubkey"] = 5;
        num["content"] = 7;
        nFail += Check(NostrIngestDescriptor(ctx, NostrTestMessage(dsub.c_str(), num), dsub, want, a, c) == NOSTR_MSG_REFUSED,
                       "nor an event whose fields are not text") ? 0 : 1;
    }

    secp256k1_context_destroy(ctx);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// Not part of `make tests`: it needs Tor and the live network. It is the bench
// proof that the offline mailbox works against real nodes over real Tor, which
// chat-relay cannot be -- that one runs the node handler in-process.
//
// Starts its own Tor in a temp datadir (the bundled one beside the exe, or the
// tor.exe named by BITFLASH_TOR), then: asks the network for a tag nobody uses,
// leaves an envelope under a fresh tag, and collects it back. Prints what it
// reached and why it failed, so a failure says which half broke.
static int RunChatLiveSelfTest()
{
    printf("chat-live self-test (%s, needs Tor and the network)\n", IsTestNet() ? "testnet" : "mainnet");
    int nFail = 0;
    // Self-tests run before StartNode(), which is where the node starts
    // Winsock. Without this every socket fails at once and the dial reads
    // "could not reach ... over Tor" in zero seconds -- which is what the first
    // live runs showed, against a seed curl reached fine through the same Tor.
#ifdef _WIN32
    SelfTestWinsock wsa;
#endif

    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    strSetDataDir = tmp;

    std::string torPath, err;
    const char* pszTor = getenv("BITFLASH_TOR");
    if (pszTor && *pszTor)
        torPath = pszTor;
    else if (!BtfBundledTorPath(torPath))
    {
        printf("no Tor: put tor/ beside the exe or set BITFLASH_TOR to tor.exe\n");
        return 1;
    }
    // No transport ladder here. This build counts peers to decide whether Tor
    // works, a self-test has none, and the watchdog would move Tor onto
    // bridges mid-run -- which is what made the first run from the 202 take
    // eight minutes. The test is of the chat, not of the censorship fallback.
    BtfSetTorFallbackEnabled(false);
    if (!BtfStartManagedTor(torPath, err))
    {
        printf("Tor did not start: %s\n", err.c_str());
        return 1;
    }
    int64 nStart = GetTime();
    while (BtfManagedTorBootstrapPercent() < 100 && GetTime() - nStart < 240)
        Sleep(1000);
    printf("  Tor bootstrap %d%% after %d s\n", BtfManagedTorBootstrapPercent(), (int)(GetTime() - nStart));

    unsigned char tag[16];
    RAND_bytes(tag, sizeof(tag));
    std::string tagHex = HexStr(tag, tag + 16, false);   // no spaces: the default has them

    std::vector<std::pair<std::string, int64_t> > ask(1, std::make_pair(tagHex, (int64_t)0));
    std::map<std::string, std::vector<std::vector<unsigned char> > > got;
    // "Bootstrapped 100%" is not yet "can find an onion": right after it Tor
    // may still lack the directory servers that hold onion descriptors, and a
    // dial then fails at once. The chat app simply asks again next round; this
    // does the same, a few times, past the client's own back-off.
    bool fAsked = false;
    for (int nTry = 1; nTry <= 4 && !fAsked; nTry++)
    {
        int64 t0 = GetTime();
        fAsked = btfchat::NetFetchEnvelopes(ask, got, err);
        printf("  first question, try %d: %s in %d s%s%s\n", nTry, fAsked ? "answered" : "NOT answered",
               (int)(GetTime() - t0), err.empty() ? "" : " -- ", err.c_str());
        if (!fAsked && nTry < 4)
            Sleep(70 * 1000);
    }
    int64 t0 = GetTime();
    nFail += Check(fAsked && got[tagHex].empty(),
                   "a node of this network answers, and has nothing under a tag nobody used") ? 0 : 1;

    std::vector<unsigned char> env(600);
    RAND_bytes(&env[0], (int)env.size());
    t0 = GetTime();
    bool fLeft = btfchat::NetPostEnvelope(tagHex, env, err);
    printf("  leaving an envelope: %s in %d s%s%s\n", fLeft ? "kept" : "NOT kept",
           (int)(GetTime() - t0), err.empty() ? "" : " -- ", err.c_str());
    nFail += Check(fLeft, "an envelope is kept by at least one node") ? 0 : 1;

    got.clear();
    t0 = GetTime();
    bool fBack = btfchat::NetFetchEnvelopes(ask, got, err) && got[tagHex].size() == 1 &&
                 got[tagHex][0] == env;
    printf("  collecting it: %s in %d s%s%s\n", fBack ? "found" : "NOT found",
           (int)(GetTime() - t0), err.empty() ? "" : " -- ", err.c_str());
    nFail += Check(fBack, "and comes back, byte for byte, from the network") ? 0 : 1;

    size_t nKnown = 0, nGood = 0;
    btfchat::NetNodeCounts(nKnown, nGood);
    printf("  nodes known %u, answering %u\n", (unsigned)nKnown, (unsigned)nGood);

    BtfStopManagedTor();
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunChatIdentitySelfTest()
{
    printf("chat-identity self-test\n");
    int nFail = 0;

    // SetHDSeedFromMnemonic writes to wallet.dat, so this runs in a datadir of
    // its own and takes nothing real with it.
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());
    if (!LoadWallet())
    {
        printf("LoadWallet failed\n");
        return 1;
    }

    std::string err;
    std::vector<unsigned char> seed;

    // A wallet with no phrase installed hands out nothing, and says so rather
    // than handing back something derived from whatever happened to be in the
    // globals.
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nFail += Check(!btfchat::ChatSeedFromWallet(seed, err) && seed.empty(),
                   "a wallet with no recovery phrase yields no chat seed") ? 0 : 1;
    btfchat::Identity none;
    nFail += Check(!btfchat::UnlockIdentity("senha-bem-comprida", none, err),
                   "and no identity can be unlocked from it") ? 0 : 1;

    // Install a phrase the way -restorephrase does, then check the chat seed is
    // exactly master || chain code.
    const char* PHRASE =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    nFail += Check(SetHDSeedFromMnemonic(PHRASE, "", err), "a phrase installs") ? 0 : 1;
    nFail += Check(HaveHDSeed(), "and the wallet has an HD seed") ? 0 : 1;

    nFail += Check(btfchat::ChatSeedFromWallet(seed, err) && seed.size() == 64,
                   "the chat seed is 64 bytes") ? 0 : 1;
    if (seed.size() == 64 && vchHDMaster.size() == 32 && vchHDChainCode.size() == 32)
    {
        nFail += Check(memcmp(&seed[0], &vchHDMaster[0], 32) == 0 &&
                       memcmp(&seed[32], &vchHDChainCode[0], 32) == 0,
                       "and it is the master key followed by the chain code") ? 0 : 1;
    }
    else
        nFail++;

    // The identity, and the properties the whole design rests on.
    btfchat::Identity id1, id2, idOther;
    nFail += Check(btfchat::UnlockIdentity("senha-bem-comprida", id1, err),
                   "an identity unlocks with a session password") ? 0 : 1;
    nFail += Check(btfchat::UnlockIdentity("senha-bem-comprida", id2, err) &&
                   id1.address == id2.address,
                   "the same password gives the same .btf address") ? 0 : 1;
    nFail += Check(btfchat::UnlockIdentity("outra-senha-comprida", idOther, err) &&
                   idOther.address != id1.address,
                   "another password gives a DIFFERENT identity, not an error") ? 0 : 1;
    nFail += Check(!btfchat::UnlockIdentity("curta", none, err),
                   "a password under 12 characters is refused") ? 0 : 1;

    // The chat key is not the wallet key. If this ever fails, being reachable
    // for a conversation would be publishing spending material.
    CKey walletKey;
    if (DeriveHDKey(0, walletKey, err))
    {
        // GetPrivKey returns a secure_allocator vector, so it is copied byte by
        // byte rather than assigned to a plain one.
        CPrivKey vchWalletPriv = walletKey.GetPrivKey();
        std::string strWallet((const char*)&vchWalletPriv[0], vchWalletPriv.size());
        std::string strChatSign((const char*)id1.sign_sk, 32);
        std::string strChatChan((const char*)id1.chan_sk, 32);
        nFail += Check(strWallet.find(strChatSign) == std::string::npos,
                       "the chat signing key is not the wallet's first key") ? 0 : 1;
        nFail += Check(strWallet.find(strChatChan) == std::string::npos,
                       "nor is the chat channel key") ? 0 : 1;
    }
    else
        nFail++;
    nFail += Check(memcmp(id1.sign_sk, &vchHDMaster[0], 32) != 0,
                   "and neither is the wallet master key itself") ? 0 : 1;

    // Reinstalling the same phrase rebuilds the same chat identity: this is what
    // makes the chat survive moving to another machine with the words alone.
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nFail += Check(SetHDSeedFromMnemonic(PHRASE, "", err), "the phrase installs again") ? 0 : 1;
    btfchat::Identity idAgain;
    nFail += Check(btfchat::UnlockIdentity("senha-bem-comprida", idAgain, err) &&
                   idAgain.address == id1.address,
                   "and the chat identity comes back identical") ? 0 : 1;

    // A BIP39 passphrase makes a different wallet, so a different chat identity.
    // Stated in a test because it is the kind of thing a user discovers the hard
    // way otherwise.
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nFail += Check(SetHDSeedFromMnemonic(PHRASE, "vigesima-quinta-palavra", err),
                   "the same phrase with a 25th word installs") ? 0 : 1;
    btfchat::Identity idPass;
    nFail += Check(btfchat::UnlockIdentity("senha-bem-comprida", idPass, err) &&
                   idPass.address != id1.address,
                   "and gives a different chat identity, as it must") ? 0 : 1;

    // ---- closing the app and opening it again (what a tester ran into)
    // A message left while the app was closed is sealed to the mailbox key
    // published before closing; and a mistyped password must not open an
    // empty chat as somebody else and then save over the real one.
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nFail += Check(SetHDSeedFromMnemonic(PHRASE, "", err), "back to the plain phrase") ? 0 : 1;
    nFail += Check(btfchat::ChatUnlock("senha-bem-comprida", err), "the chat opens") ? 0 : 1;
    std::string strPub = btfchat::ChatMailboxPublicHex();
    std::string strAddr = btfchat::ChatAddress();
    nFail += Check(strPub.size() == 64, "with this epoch's mailbox key, the one others seal to") ? 0 : 1;
    btfchat::ChatLock();
    std::string strFile = btfchat::ChatStorePath(), strBefore, strAfter;
    {
        FILE* f = fopen(strFile.c_str(), "rb");
        char buf[4096];
        size_t n;
        while (f && (n = fread(buf, 1, sizeof(buf), f)) > 0)
            strBefore.append(buf, n);
        if (f) fclose(f);
    }
    nFail += Check(!strBefore.empty(), "closing it leaves the sealed store on disk") ? 0 : 1;
    nFail += Check(!btfchat::ChatUnlock("senha-digitada-errada", err) && !btfchat::ChatUnlocked() &&
                   err.find("different identity") != std::string::npos,
                   "a mistyped password is refused, saying why -- not an empty chat as somebody else") ? 0 : 1;
    {
        FILE* f = fopen(strFile.c_str(), "rb");
        char buf[4096];
        size_t n;
        while (f && (n = fread(buf, 1, sizeof(buf), f)) > 0)
            strAfter.append(buf, n);
        if (f) fclose(f);
    }
    nFail += Check(strAfter == strBefore, "and the saved chat is left byte for byte as it was") ? 0 : 1;
    nFail += Check(btfchat::ChatUnlock("senha-bem-comprida", err) && btfchat::ChatAddress() == strAddr,
                   "the right password opens it again, as the same identity") ? 0 : 1;
    nFail += Check(btfchat::ChatMailboxPublicHex() == strPub,
                   "with the SAME mailbox key: a message left while it was closed opens") ? 0 : 1;
    btfchat::ChatLock();

    printf("%s (%d failures)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail);
    return nFail == 0 ? 0 : 1;
}

static int RunManagedTorSelfTest()
{
    printf("managed-tor self-test\n");
    int nFail = 0;

    std::string torrc = BtfBuildManagedTorrcForTest("C:/Bitflash Managed Tor/data",
                                                   "C:/Bitflash Managed Tor/onion-service",
                                                   19050, 19051, 8433);
    nFail += Check(torrc.find("DataDirectory \"C:/Bitflash Managed Tor/data\"") != std::string::npos,
                   "quotes the Tor data directory") ? 0 : 1;
    nFail += Check(torrc.find("SocksPort 127.0.0.1:19050") != std::string::npos,
                   "binds SOCKS5 to localhost only") ? 0 : 1;
    nFail += Check(torrc.find("ControlPort 127.0.0.1:19051") != std::string::npos &&
                   torrc.find("CookieAuthentication 1") != std::string::npos,
                   "binds an authenticated Tor control port to localhost only") ? 0 : 1;
    nFail += Check(torrc.find("IsolateSOCKSAuth") != std::string::npos &&
                   torrc.find("IsolateClientAddr") != std::string::npos &&
                   torrc.find("IsolateDestAddr") != std::string::npos &&
                   torrc.find("IsolateDestPort") != std::string::npos,
                   "enables strict Tor stream isolation") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServiceDir \"C:/Bitflash Managed Tor/onion-service\"") != std::string::npos,
                   "writes a hidden service directory") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServiceVersion 3") != std::string::npos,
                   "requests a v3 onion service") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServicePort 8433 127.0.0.1:8433") != std::string::npos,
                   "maps the onion service to the Bitflash P2P listener") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServicePort 8434 127.0.0.1:8434") != std::string::npos,
                   "maps a second port (p2p+1) for the mining pool over onion") ? 0 : 1;
    nFail += Check(torrc.find("UseBridges") == std::string::npos,
                   "no bridge config when none is requested") ? 0 : 1;

    // btfchat's hidden service. Not requested unless a port is set, and when it
    // is, it gets its OWN HiddenServiceDir -- a second virtual port on the node's
    // onion would make the chat address and the P2P address the same string, and
    // being reachable for a conversation would publish which node you mine on.
    nFail += Check(torrc.find("chat-onion") == std::string::npos,
                   "no chat onion service unless one is asked for") ? 0 : 1;
    nFail += Check(BtfManagedTorChatPort() == 0,
                   "the chat service is off by default") ? 0 : 1;
    nFail += Check(BtfManagedTorChatOnion().empty(),
                   "and has no onion until Tor makes one") ? 0 : 1;

    std::string torrcC = BtfBuildManagedTorrcForTest("C:/mt/data", "C:/mt/onion-service",
                                                    19050, 19051, 8433,
                                                    std::vector<std::string>(),
                                                    std::map<std::string, std::string>(),
                                                    "C:/mt/chat-onion-service", 8533);
    nFail += Check(torrcC.find("HiddenServiceDir \"C:/mt/chat-onion-service\"") != std::string::npos,
                   "the chat service gets its own hidden service directory") ? 0 : 1;
    nFail += Check(torrcC.find("HiddenServicePort 8533 127.0.0.1:8533") != std::string::npos,
                   "mapped to the chat listener") ? 0 : 1;
    // Order is not cosmetic here: in a torrc a HiddenServicePort belongs to the
    // HiddenServiceDir above it, so the chat's Dir line has to come after the
    // node's ports or the chat port would be added to the node's onion instead.
    nFail += Check(torrcC.find("C:/mt/chat-onion-service") >
                   torrcC.find("HiddenServicePort 8434 127.0.0.1:8434"),
                   "and declared after the node ports, so the two do not merge") ? 0 : 1;
    nFail += Check(torrcC.find("HiddenServiceDir \"C:/mt/onion-service\"") != std::string::npos,
                   "while the node keeps its own service") ? 0 : 1;
    // Two Dir lines, two services, two .onion names.
    {
        size_t nDirs = 0, at = 0;
        while ((at = torrcC.find("HiddenServiceDir ", at)) != std::string::npos)
        { nDirs++; at += 1; }
        nFail += Check(nDirs == 2, "exactly two hidden services, so two onion names") ? 0 : 1;
    }
    // A port with no directory, or a directory with no port, asks for nothing:
    // half a service in a torrc is a Tor that refuses to start.
    std::string torrcD = BtfBuildManagedTorrcForTest("C:/mt/data", "C:/mt/onion-service",
                                                    19050, 19051, 8433,
                                                    std::vector<std::string>(),
                                                    std::map<std::string, std::string>(),
                                                    std::string(), 8533);
    nFail += Check(torrcD.find("8533") == std::string::npos,
                   "a chat port with no directory is ignored") ? 0 : 1;
    std::string torrcE = BtfBuildManagedTorrcForTest("C:/mt/data", "C:/mt/onion-service",
                                                    19050, 19051, 8433,
                                                    std::vector<std::string>(),
                                                    std::map<std::string, std::string>(),
                                                    "C:/mt/chat-onion-service", 0);
    nFail += Check(torrcE.find("chat-onion") == std::string::npos,
                   "and a directory with no port is ignored too") ? 0 : 1;

    // btfchat runs no peer-to-peer node, so it asks for no node service: a P2P
    // port of 0 means "nothing listens here". An onion that exists and refuses
    // every connection still announces a Bitflash node at that address, which is
    // precisely what a chat identity must not do.
    std::string torrcF = BtfBuildManagedTorrcForTest("C:/mt/data", "C:/mt/onion-service",
                                                    19050, 19051, 0,
                                                    std::vector<std::string>(),
                                                    std::map<std::string, std::string>(),
                                                    "C:/mt/chat-onion-service", 8533);
    nFail += Check(torrcF.find("C:/mt/onion-service") == std::string::npos,
                   "a P2P port of 0 asks for no node onion service") ? 0 : 1;
    nFail += Check(torrcF.find("HiddenServicePort 8433") == std::string::npos &&
                   torrcF.find("HiddenServicePort 8434") == std::string::npos,
                   "and maps neither the P2P port nor the pool port") ? 0 : 1;
    nFail += Check(torrcF.find("HiddenServiceDir \"C:/mt/chat-onion-service\"") != std::string::npos &&
                   torrcF.find("HiddenServicePort 8533 127.0.0.1:8533") != std::string::npos,
                   "while the chat still gets its own service") ? 0 : 1;
    {
        size_t nDirs = 0, at = 0;
        while ((at = torrcF.find("HiddenServiceDir ", at)) != std::string::npos)
        { nDirs++; at += 1; }
        nFail += Check(nDirs == 1, "exactly one hidden service: the chat's") ? 0 : 1;
    }
    // And SOCKS is still there, because that is how the chat dials out at all.
    nFail += Check(torrcF.find("SocksPort 127.0.0.1:19050") != std::string::npos,
                   "with SOCKS still bound, which is how it dials out") ? 0 : 1;

    // With PT binaries and bridges, the torrc must wire both transports: one
    // ClientTransportPlugin per binary, then every Bridge line.
    std::vector<std::string> testBridges;
    testBridges.push_back("obfs4 10.0.0.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0");
    testBridges.push_back("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://x/ fronts=a ice=stun:s:1 utls-imitate=x");
    std::map<std::string, std::string> testPt;
    testPt["obfs4"] = "/x/pt/obfs4proxy";
    testPt["snowflake"] = "/x/pt/snowflake-client";
    std::string torrcB = BtfBuildManagedTorrcForTest("C:/x/data", "C:/x/hs",
                                                    19050, 19051, 8433,
                                                    testBridges, testPt);
    nFail += Check(torrcB.find("UseBridges 1") != std::string::npos,
                   "enables bridges when a PT and bridge are configured") ? 0 : 1;
    nFail += Check(torrcB.find("ClientTransportPlugin obfs4 exec /x/pt/obfs4proxy") != std::string::npos,
                   "declares the obfs4 client transport plugin, unquoted path") ? 0 : 1;
    nFail += Check(torrcB.find("ClientTransportPlugin snowflake exec /x/pt/snowflake-client") != std::string::npos,
                   "declares the snowflake client transport plugin") ? 0 : 1;
    nFail += Check(torrcB.find("Bridge obfs4 10.0.0.1:443") != std::string::npos &&
                   torrcB.find("Bridge snowflake 192.0.2.3:80") != std::string::npos,
                   "writes both bridge lines") ? 0 : 1;
    nFail += Check(BtfBridgeTransport("snowflake 1.2.3.4:1 ABCD") == "snowflake",
                   "parses the transport name from a bridge line") ? 0 : 1;
    nFail += Check(!BtfDefaultBridges().empty() &&
                   BtfBridgeTransport(BtfDefaultBridges()[0]) == "snowflake",
                   "default bridge set ships a Snowflake bridge") ? 0 : 1;

    nFail += Check(BtfManagedTorStatus() == "disabled",
                   "managed Tor starts disabled") ? 0 : 1;

    // Bridge fallback policy: on by default, four minutes, and the transports
    // are looked up beside the Tor we were pointed at as well as beside us.
    nFail += Check(nTorBridgeFallbackSecs == 4 * 60,
                   "bridge fallback defaults to four minutes") ? 0 : 1;
    nFail += Check(!BtfTorBridgesConfigured(),
                   "no bridges configured until asked") ? 0 : 1;
    {
        std::string tmp;
        if (MakeTempDir(tmp))
        {
            std::string torDir = tmp + "/tordir";
            std::string ptDir = torDir + "/pluggable_transports";
            MakeDirLocal(torDir);
            MakeDirLocal(ptDir);
#ifdef _WIN32
            std::string ptFile = ptDir + "/lyrebird.exe";
#else
            std::string ptFile = ptDir + "/lyrebird";
#endif
            WriteTextFile(ptFile, "#!/bin/sh\n");
#ifndef _WIN32
            chmod(ptFile.c_str(), 0755);
#endif
            std::string found;
            BtfSetManagedTorPath(torDir + "/tor");
            nFail += Check(BtfResolveSnowflakePath(found) && found == ptFile,
                           "finds the transport next to the managed Tor binary") ? 0 : 1;
            nFail += Check(BtfResolveObfs4Path(found) && found == ptFile,
                           "lyrebird serves obfs4 too") ? 0 : 1;
            nFail += Check(BtfResolveTransportPath("webtunnel", found) && found == ptFile &&
                           BtfResolveTransportPath("meek_lite", found) && found == ptFile,
                           "webtunnel and meek_lite resolve to lyrebird") ? 0 : 1;
            nFail += Check(!BtfResolveTransportPath("conjure", found),
                           "conjure needs its own client, absent here") ? 0 : 1;

            // The ladder without pt_config.json: the built-in Snowflake set.
            std::vector<BtfBridgeRung> rungs = BtfBundledBridgeRungs();
            nFail += Check(rungs.size() == 1 && rungs[0].name == "snowflake" && rungs[0].lines.size() == 2,
                           "without pt_config.json the ladder is the built-in Snowflake rung") ? 0 : 1;

            // With Tor Browser's pt_config.json beside the transports: rungs
            // in survival order, conjure left out, meek's transport meek_lite.
            WriteTextFile(ptDir + "/pt_config.json",
                "{\"bridges\":{\"meek\":[\"meek_lite 192.0.2.20:80 url=https://x front=y\"],"
                "\"obfs4\":[\"obfs4 10.0.0.1:443 AAAA cert=BBBB iat-mode=0\",\"obfs4 10.0.0.2:443 CCCC cert=DDDD iat-mode=0\"],"
                "\"snowflake\":[\"snowflake 192.0.2.3:80 EEEE url=https://b/\"],"
                "\"conjure\":[\"conjure 192.0.2.5:80 FFFF\"],"
                "\"webtunnel\":[\"webtunnel [2001:db8::1]:443 GGGG url=https://w/ ver=0.0.1\"]}}");
            rungs = BtfBundledBridgeRungs();
            nFail += Check(rungs.size() == 4 && rungs[0].name == "snowflake" && rungs[1].name == "obfs4" &&
                           rungs[2].name == "webtunnel" && rungs[3].name == "meek",
                           "pt_config.json rungs come in survival order, conjure left out") ? 0 : 1;
            nFail += Check(rungs.size() == 4 && rungs[1].lines.size() == 2 &&
                           rungs[0].lines[0] == "snowflake 192.0.2.3:80 EEEE url=https://b/",
                           "rung lines are the file's lines") ? 0 : 1;
            nFail += Check(BtfDefaultBridges().size() == 2,
                           "-torbridges keeps the built-in Snowflake set") ? 0 : 1;
            remove((ptDir + "/pt_config.json").c_str());

            // Bridge lines as people paste them.
            std::vector<std::string> lines = BtfParseBridgeLines(
                "# from the bot\r\n  Bridge obfs4 1.2.3.4:1 AAAA cert=x iat-mode=0  \n\nsnowflake 192.0.2.3:80 BBBB\nbridge webtunnel [::1]:443 CC\n");
            nFail += Check(lines.size() == 3 && lines[0] == "obfs4 1.2.3.4:1 AAAA cert=x iat-mode=0" &&
                           lines[1] == "snowflake 192.0.2.3:80 BBBB" && lines[2] == "webtunnel [::1]:443 CC",
                           "parses pasted bridge lines: comments, blanks, CRLF, Bridge prefix") ? 0 : 1;

            // Configuring: a transport without a binary is refused whole.
            std::string cfgErr;
            nFail += Check(!BtfConfigureBridges(std::vector<std::string>(1, "conjure 192.0.2.5:80 FFFF"), "user", cfgErr) &&
                           cfgErr.find("conjure") != std::string::npos,
                           "refuses a bridge whose transport binary is missing") ? 0 : 1;
            nFail += Check(!BtfTorBridgesConfigured() && BtfTorTransportMode() == "direct",
                           "a refused configuration leaves the mode direct") ? 0 : 1;
            nFail += Check(BtfConfigureBridges(lines, "user", cfgErr) && BtfTorBridgesConfigured() &&
                           BtfTorTransportMode() == "user",
                           "configures the pasted lines under mode user") ? 0 : 1;
            BtfSetTorBridges(std::vector<std::string>(), std::map<std::string, std::string>());
            nFail += Check(BtfTorTransportMode() == "direct",
                           "no bridges means direct") ? 0 : 1;

            BtfSetManagedTorPath("");
            remove(ptFile.c_str());
            rmdir(ptDir.c_str());
            rmdir(torDir.c_str());
            rmdir(tmp.c_str());
        }
        else
            nFail += Check(false, "temp dir for the transport lookup") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// The Bitcoin half of a swap, without a Bitcoin Core: addresses, reading
// Bitcoin's witness serialization, and the redeem and refund this wallet
// signs. What Core itself does with them is the regtest run's job.
static int RunBtcSwapSelfTest()
{
    printf("btc-swap self-test\n");
    int nFail = 0;
    std::string err;

    btcswap::Chain mainChain, testChain;
    mainChain.name = "main";
    mainChain.fMain = true;
    mainChain.pkhVersion = 0x00;
    mainChain.shVersion = 0x05;
    testChain.name = "regtest";
    testChain.pkhVersion = 0x6f;
    testChain.shVersion = 0xc4;

    // ---- addresses
    std::vector<unsigned char> zero(20, 0), pkh;
    nFail += Check(btcswap::PkhToAddress(mainChain, zero) == "1111111111111111111114oLvT2",
                   "a zero key hash is 1111111111111111111114oLvT2 on main, as in Bitcoin") ? 0 : 1;
    nFail += Check(btcswap::PkhToAddress(testChain, zero) == "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8",
                   "and mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8 on the test chains") ? 0 : 1;
    nFail += Check(btcswap::AddressToPkh(mainChain, "1111111111111111111114oLvT2", pkh, err) && pkh == zero,
                   "a main address reads back to its key hash") ? 0 : 1;
    nFail += Check(!btcswap::AddressToPkh(testChain, "1111111111111111111114oLvT2", pkh, err) &&
                   err.find("another Bitcoin network") != std::string::npos,
                   "a main address is refused on a test chain") ? 0 : 1;
    nFail += Check(!btcswap::AddressToPkh(mainChain, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", pkh, err),
                   "a bc1 address is refused: the contract holds a key hash") ? 0 : 1;
    CScript scriptAny;
    scriptAny << OP_TRUE;
    nFail += Check(btcswap::ScriptAddress(mainChain, scriptAny)[0] == '3' && btcswap::ScriptAddress(testChain, scriptAny)[0] == '2',
                   "a contract's address is 3... on main and 2... on the test chains") ? 0 : 1;
    nFail += Check(!btcswap::AddressToPkh(mainChain, btcswap::ScriptAddress(mainChain, scriptAny), pkh, err) &&
                   err.find("script address") != std::string::npos,
                   "a script address is refused as a party to the contract") ? 0 : 1;

    // ---- a contract whose keys are this wallet's
    CKey keyR, keyF;
    keyR.MakeNewKey();
    keyF.MakeNewKey();
    std::vector<unsigned char> pubR = keyR.GetPubKey(), pubF = keyF.GetPubKey();
    uint160 hR = Hash160(pubR), hF = Hash160(pubF);
    swap::Contract c;
    c.recipientPkh.assign(hR.begin(), hR.end());
    c.refundPkh.assign(hF.begin(), hF.end());
    std::vector<unsigned char> secret(32);
    RAND_bytes(&secret[0], 32);
    c.secretHash.resize(32);
    SHA256(&secret[0], 32, &c.secretHash[0]);
    c.nLockTime = 1800000000;
    CScript contract = swap::BuildContract(c);
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);

    // ---- Bitcoin's serialization, with and without a witness
    CTransaction fund;
    fund.vin.resize(1);
    fund.vin[0].prevout = COutPoint(uint256(7), 1);
    fund.vout.push_back(CTxOut(10000000, p2sh));
    fund.vout.push_back(CTxOut(5000, CScript() << OP_0 << std::vector<unsigned char>(20, 1)));
    CDataStream ss(SER_NETWORK);
    ss << fund;
    std::vector<unsigned char> plain(ss.begin(), ss.end());
    std::vector<unsigned char> wit(plain.begin(), plain.begin() + 4);
    wit.push_back(0x00);
    wit.push_back(0x01);
    wit.insert(wit.end(), plain.begin() + 4, plain.end() - 4);
    wit.push_back(2);                                   // two witness items
    wit.push_back(72);
    wit.insert(wit.end(), 72, 0x30);
    wit.push_back(33);
    wit.insert(wit.end(), 33, 0x02);
    wit.insert(wit.end(), plain.end() - 4, plain.end());

    CTransaction parsed;
    nFail += Check(btcswap::ParseTx(wit, parsed) && parsed.GetHash() == fund.GetHash() &&
                   parsed.vout.size() == 2 && parsed.vout[0].scriptPubKey == p2sh,
                   "a witness transaction reads, with the txid of its form without the witness") ? 0 : 1;
    nFail += Check(btcswap::ParseTx(plain, parsed) && parsed.GetHash() == fund.GetHash(),
                   "and so does the same transaction without one") ? 0 : 1;
    std::vector<unsigned char> cut(wit.begin(), wit.end() - 5), extra = wit;
    extra.push_back(0);
    nFail += Check(!btcswap::ParseTx(cut, parsed) && !btcswap::ParseTx(extra, parsed),
                   "a truncated transaction, or one with bytes after it, does not") ? 0 : 1;
    std::vector<unsigned char> blk(80, 0);
    blk.push_back(2);
    blk.insert(blk.end(), wit.begin(), wit.end());
    blk.insert(blk.end(), plain.begin(), plain.end());
    std::vector<CTransaction> txs;
    nFail += Check(btcswap::ParseBlockTxs(blk, txs) && txs.size() == 2 && txs[0].GetHash() == fund.GetHash() &&
                   txs[1].GetHash() == fund.GetHash(),
                   "a raw block reads into its transactions, witness or not") ? 0 : 1;

    // ---- the redeem this wallet signs
    COutPoint outpoint(fund.GetHash(), 0);
    CScript scriptTo;
    scriptTo << OP_0 << std::vector<unsigned char>(20, 2);    // Core's bc1 address
    CTransaction redeem, refund;
    int64 nFee = 0;
    nFail += Check(btcswap::BuildSpend(contract, outpoint, 10000000, scriptTo, keyR, pubR, &secret, 10000, redeem, nFee, err),
                   "the recipient key and the secret redeem the contract") ? 0 : 1;
    int64 nSize = (int64)::GetSerializeSize(redeem, SER_NETWORK);
    int64 nNeed = (nSize * 10000 + 999) / 1000;
    // At least the rate for its size; a signature is 71 to 73 bytes, so at
    // most a couple of bytes' worth over.
    nFail += Check(nFee >= nNeed && nFee <= nNeed + 30 && redeem.vout.size() == 1 &&
                   redeem.vout[0].nValue == 10000000 - nFee && redeem.vout[0].scriptPubKey == scriptTo,
                   "one output, to Core's address, the fee at the rate asked for its size") ? 0 : 1;
    std::vector<unsigned char> got;
    nFail += Check(swap::ExtractSecret(redeem.vin[0].scriptSig, c.secretHash, got) && got == secret,
                   "the redeem shows the secret, as the other side needs") ? 0 : 1;
    CDataStream ssR(SER_NETWORK);
    ssR << redeem;
    CTransaction back;
    nFail += Check(btcswap::ParseTx(std::vector<unsigned char>(ssR.begin(), ssR.end()), back) && back.GetHash() == redeem.GetHash(),
                   "and serializes as a plain Bitcoin transaction") ? 0 : 1;
    std::vector<unsigned char> wrong(32, 9);
    nFail += Check(!btcswap::BuildSpend(contract, outpoint, 10000000, scriptTo, keyR, pubR, &wrong, 10000, redeem, nFee, err),
                   "a wrong secret does not") ? 0 : 1;
    nFail += Check(!btcswap::BuildSpend(contract, outpoint, 10000000, scriptTo, keyF, pubF, &secret, 10000, redeem, nFee, err),
                   "nor does the refund key with the secret") ? 0 : 1;

    // ---- the refund
    nFail += Check(btcswap::BuildSpend(contract, outpoint, 10000000, scriptTo, keyF, pubF, NULL, 10000, refund, nFee, err) &&
                   refund.nLockTime == (unsigned int)c.nLockTime && refund.vin[0].nSequence == 0,
                   "the refund key refunds, with the lock in nLockTime and an input that keeps it on") ? 0 : 1;
    nFail += Check(!btcswap::BuildSpend(contract, outpoint, 10000000, scriptTo, keyR, pubR, NULL, 10000, refund, nFee, err),
                   "the recipient cannot take the refund path") ? 0 : 1;
    nFail += Check(!btcswap::BuildSpend(contract, outpoint, 1500, scriptTo, keyR, pubR, &secret, 10000, redeem, nFee, err) &&
                   err.find("less than the fee") != std::string::npos,
                   "a contract worth less than its fee is not spent into dust") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- fee-policy: fees as a market, and replacing a transaction (BIP125) --------
//
// In a temporary data directory, through the real memory pool: a parent sits
// in the pool, its children spend it with different fees, and AcceptTransaction
// decides on every replacement exactly as it does for one off the network.

extern map<COutPoint, CInPoint> mapNextTx;   // main.cpp

// Into the pool with no checks, as AddToMemoryPool does (it is protected):
// for a parent whose own inputs the test does not have.
static void FeeTestAddToPool(const CTransaction& tx)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 h = tx.GetHash();
        mapTransactions[h] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTransactions[h], i);
    }
}

static CTransaction FeeTestChild(const CTransaction& parent, unsigned int n, int64 nFee, unsigned int nSequence,
                                 const CScript& scriptTo)
{
    CTransaction tx;
    tx.vin.push_back(CTxIn(parent.GetHash(), n, CScript(), nSequence));
    tx.vout.push_back(CTxOut(parent.vout[n].nValue - nFee, scriptTo));
    return tx;
}

static int RunFeePolicySelfTest()
{
    printf("fee-policy self-test\n");
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    int nFail = 0;
    try
    {
        // ---- the rules on their own
        CTransaction t;
        t.vin.resize(1);
        nFail += Check(!t.SignalsReplacement(), "an input with the final sequence does not allow replacement") ? 0 : 1;
        t.vin[0].nSequence = SEQUENCE_FINAL - 1;
        nFail += Check(!t.SignalsReplacement(), "nor does final minus one (that is for nLockTime alone)") ? 0 : 1;
        t.vin[0].nSequence = SEQUENCE_REPLACEABLE;
        nFail += Check(t.SignalsReplacement(), "below that, it does") ? 0 : 1;
        nFail += Check(FeeForSize(1000, 250) == 250 && FeeForSize(1000, 1) == 1 && FeeForSize(1001, 1000) == 1001,
                       "a rate per 1000 bytes rounds up to whole satoshis") ? 0 : 1;
        std::string why;
        std::vector<std::pair<int64, unsigned int> > vOld(1, std::make_pair((int64)100000, 200u));
        nFail += Check(ReplacementPaysEnough(100000 + FeeForSize(MIN_RELAY_FEE_PER_KB, 200), 200, vOld, why),
                       "a replacement paying the old fee plus the relay fee for its size is enough") ? 0 : 1;
        nFail += Check(!ReplacementPaysEnough(100000 + FeeForSize(MIN_RELAY_FEE_PER_KB, 200) - 1, 200, vOld, why),
                       "one satoshi less is not") ? 0 : 1;
        nFail += Check(!ReplacementPaysEnough(1000000, 2000, vOld, why) && why.find("per byte") != std::string::npos,
                       "more in total but less per byte is not") ? 0 : 1;
        vOld.push_back(std::make_pair((int64)100000, 200u));
        nFail += Check(!ReplacementPaysEnough(150000, 200, vOld, why),
                       "replacing two, it has to pay for both") ? 0 : 1;

        // ---- the pool
        CTxDB txdb("cr+");
        CKey key;
        key.MakeNewKey();
        CScript scriptTo;
        scriptTo << OP_DUP << OP_HASH160 << Hash160(key.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTransaction parent;
        parent.vin.push_back(CTxIn(COutPoint(uint256(77), 0)));
        for (int i = 0; i < 6; i++)
            parent.vout.push_back(CTxOut(10 * COIN, CScript() << OP_TRUE));
        FeeTestAddToPool(parent);

        CTransaction a = FeeTestChild(parent, 0, 1000, SEQUENCE_REPLACEABLE, scriptTo);
        CTransaction b = FeeTestChild(parent, 1, 9000, SEQUENCE_REPLACEABLE, scriptTo);
        CTransaction c = FeeTestChild(parent, 2, 5000, SEQUENCE_REPLACEABLE, scriptTo);
        nFail += Check(a.AcceptTransaction(txdb, true) && b.AcceptTransaction(txdb, true) && c.AcceptTransaction(txdb, true),
                       "three children paying 1000, 9000 and 5000 enter the pool") ? 0 : 1;
        std::vector<CTransaction*> vOrder;
        CRITICAL_BLOCK(cs_mapTransactions)
            MempoolByFeeRate(txdb, vOrder);
        bool fOrder = vOrder.size() == 4 && vOrder[0]->GetHash() == b.GetHash() && vOrder[1]->GetHash() == c.GetHash() &&
                      vOrder[2]->GetHash() == a.GetHash();
        nFail += Check(fOrder, "a block takes them best fee per byte first: 9000, 5000, 1000 (the parent, unpriced, last)") ? 0 : 1;

        CTransaction a2 = FeeTestChild(parent, 0, 1000 + FeeForSize(MIN_RELAY_FEE_PER_KB, 200) + 500,
                                       SEQUENCE_REPLACEABLE, scriptTo);
        nFail += Check(a2.AcceptTransaction(txdb, true), "a replacement for the 1000 that pays enough more is taken") ? 0 : 1;
        bool fGone = false, fIn = false;
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            fGone = !mapTransactions.count(a.GetHash());
            fIn = mapTransactions.count(a2.GetHash()) > 0;
        }
        nFail += Check(fGone && fIn, "and the one it replaces leaves the pool") ? 0 : 1;
        CTransaction a3 = FeeTestChild(parent, 0, 1001, SEQUENCE_REPLACEABLE, scriptTo);
        nFail += Check(!a3.AcceptTransaction(txdb, true), "one paying less than what is there now is refused") ? 0 : 1;

        CTransaction d = FeeTestChild(parent, 3, 1000, SEQUENCE_FINAL, scriptTo);
        CTransaction d2 = FeeTestChild(parent, 3, 50000, SEQUENCE_REPLACEABLE, scriptTo);
        nFail += Check(d.AcceptTransaction(txdb, true) && !d2.AcceptTransaction(txdb, true),
                       "a transaction that did not allow replacement is not replaced, whatever the fee") ? 0 : 1;
        // The 0.1.0 rule took a "newer version" -- a higher sequence -- for
        // the same fee, again and again. Sequence 5 then 6, same fee:
        CTransaction f = FeeTestChild(parent, 5, 1000, 5, scriptTo);
        CTransaction f2 = FeeTestChild(parent, 5, 1000, 6, scriptTo);
        nFail += Check(f.AcceptTransaction(txdb, true) && !f2.AcceptTransaction(txdb, true),
                       "the old free replacement by a higher sequence is gone: a replacement pays") ? 0 : 1;

        CTransaction e = FeeTestChild(parent, 4, 1000, SEQUENCE_REPLACEABLE, scriptTo);
        bool fE = e.AcceptTransaction(txdb, true);
        // A child of e, so replacing e would drop it too.
        CTransaction eChild;
        eChild.vin.push_back(CTxIn(e.GetHash(), 0, CScript(), SEQUENCE_REPLACEABLE));
        eChild.vout.push_back(CTxOut(e.vout[0].nValue - 1000, scriptTo));
        FeeTestAddToPool(eChild);
        CTransaction e2 = FeeTestChild(parent, 4, 90000, SEQUENCE_REPLACEABLE, scriptTo);
        nFail += Check(fE && !e2.AcceptTransaction(txdb, true),
                       "a transaction others build on in the pool is not replaced") ? 0 : 1;

        // A fifth of a block's signature operations per transaction, at
        // most: 200 bare 1-of-1 multisig outputs are 4,000 and enter, 201
        // are 4,020 and do not -- such a transaction could never be mined.
        {
            struct Sigops
            {
                static CTransaction Make(const CTransaction& parent, unsigned int n, int nOutputs, CKey& key)
                {
                    CTransaction tx;
                    tx.vin.push_back(CTxIn(parent.GetHash(), n, CScript(), SEQUENCE_REPLACEABLE));
                    CScript ms;
                    ms << OP_1 << key.GetPubKey() << OP_1 << OP_CHECKMULTISIG;
                    for (int i = 0; i < nOutputs; i++)
                        tx.vout.push_back(CTxOut(CENT, ms));
                    return tx;
                }
            };
            CTransaction over = Sigops::Make(parent, 5, 201, key);
            CTransaction at = Sigops::Make(parent, 5, 200, key);
            nFail += Check(over.GetSigOpCount() == 4020 && at.GetSigOpCount() == 4000 &&
                           MAX_STANDARD_TX_SIGOPS == 4000,
                           "the count: 20 per OP_CHECKMULTISIG, the cap a fifth of 20,000") ? 0 : 1;
            nFail += Check(!over.AcceptTransaction(txdb, true) && at.AcceptTransaction(txdb, true),
                           "a transaction over the signature-operation cap is refused, one at it is taken") ? 0 : 1;
        }

        CRITICAL_BLOCK(cs_mapTransactions)
        {
            mapTransactions.clear();
            mapNextTx.clear();
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- script-sigops: what a spend checks against what it is charged -------------
//
// An OP_CHECKMULTISIG is charged 20 signature operations, but it checks one
// signature per key it is handed, and consensus bounds the keys only by the
// stack. fuzz-script, which holds the checks a spend makes to what the block
// and the pool charge for it, found spends whose key count the script
// computes. The pool now takes a multisig only with its key count a literal
// OP_0..OP_16 (MultisigKeyCountsAreLiteral); consensus is unchanged.

static int RunScriptSigOpsSelfTest()
{
    printf("script-sigops self-test\n");
    int nFail = 0;

    std::vector<std::vector<unsigned char> > vKeys;
    for (int i = 0; i < 25; i++)
    {
        CKey k;
        k.MakeNewKey();
        vKeys.push_back(k.GetPubKey());
    }
    CScript literal;
    literal << OP_2 << vKeys[0] << vKeys[1] << vKeys[2] << OP_3 << OP_CHECKMULTISIG;
    CScript computed;
    computed << vKeys[0] << vKeys[1] << OP_1 << OP_1 << OP_ADD << OP_CHECKMULTISIG;
    CScript wide;   // 25 keys, the count made by OP_ADD
    for (int i = 0; i < 25; i++)
        wide << vKeys[i];
    wide << OP_16 << OP_9 << OP_ADD << OP_CHECKMULTISIG;

    nFail += Check(MultisigKeyCountsAreLiteral(literal) && MultisigKeyCountsAreLiteral(CScript() << OP_0 << OP_CHECKMULTISIGVERIFY) &&
                   MultisigKeyCountsAreLiteral(CScript() << OP_16 << OP_CHECKMULTISIG) &&
                   MultisigKeyCountsAreLiteral(CScript() << OP_DUP << OP_HASH160 << uint160(5) << OP_EQUALVERIFY << OP_CHECKSIG),
                   "policy: a literal key count (OP_0..OP_16), or no multisig at all, is taken") ? 0 : 1;
    nFail += Check(!MultisigKeyCountsAreLiteral(computed) && !MultisigKeyCountsAreLiteral(wide) &&
                   !MultisigKeyCountsAreLiteral(CScript() << OP_CHECKMULTISIG) &&
                   !MultisigKeyCountsAreLiteral(CScript() << OP_1 << OP_IF << OP_2 << OP_ENDIF << OP_CHECKMULTISIG) &&
                   !MultisigKeyCountsAreLiteral(CScript() << OP_1NEGATE << OP_CHECKMULTISIG) &&
                   !MultisigKeyCountsAreLiteral(CScript() << std::vector<unsigned char>(1, 2) << OP_CHECKMULTISIG) &&
                   !MultisigKeyCountsAreLiteral(CScript() << OP_2 << OP_CHECKMULTISIGVERIFY << OP_DROP << OP_CHECKMULTISIG),
                   "policy: a computed count, none, one across a branch, a data push, OP_1NEGATE are not") ? 0 : 1;
    {
        CScript bad;
        bad << OP_2;
        bad.push_back(0x4c);   // OP_PUSHDATA1 with no length
        nFail += Check(!MultisigKeyCountsAreLiteral(bad), "policy: a script that does not parse is not") ? 0 : 1;
    }

    // The premise: consensus runs a 25-key multisig and charges it 20.
    CTransaction any;
    any.vin.resize(1);
    any.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    nFail += Check(EvalScript((CScript() << OP_0 << OP_0) + wide, any, 0, 0, NULL, true, true, true) &&
                   wide.GetSigOpCount(true) == 20,
                   "consensus takes 25 keys in one OP_CHECKMULTISIG and counts it as 20 (why the policy exists)") ? 0 : 1;
    {
        CScript twenty;   // 20 keys, the count made by OP_ADD
        for (int i = 0; i < 20; i++)
            twenty << vKeys[i];
        twenty << OP_16 << OP_4 << OP_ADD << OP_CHECKMULTISIG;
        CScript sixteen = CScript() << OP_0 << OP_0;
        for (int i = 0; i < 16; i++)
            sixteen << vKeys[i];
        sixteen << OP_16 << OP_CHECKMULTISIG;
        nFail += Check(!EvalScript((CScript() << OP_0 << OP_0) + wide, any, 0, 0, NULL, true, true, true, 0, true) &&
                       EvalScript((CScript() << OP_0 << OP_0) + twenty, any, 0, 0, NULL, true, true, true, 0, true) &&
                       EvalScript(sixteen, any, 0, 0, NULL, true, true, true, 0, true) &&
                       EvalScript((CScript() << OP_0 << OP_0) + wide, any, 0, 0, NULL, true, true, true, 0, false),
                       "rules v5: 25 keys fail the script, 20 (even computed) and 16 do not") ? 0 : 1;
    }

    CScript literal0;   // 0-of-2: spent with the dummy alone
    literal0 << OP_0 << vKeys[0] << vKeys[1] << OP_2 << OP_CHECKMULTISIG;
    CScript p2shComputed, p2shLiteral;
    p2shComputed.SetPayToScriptHash(computed);
    p2shLiteral.SetPayToScriptHash(literal0);
    CScript sigComputed = CScript() << OP_0 << OP_0 << std::vector<unsigned char>(computed.begin(), computed.end());
    nFail += Check(!InputMultisigKeyCountsAreLiteral(sigComputed, p2shComputed, true) &&
                   InputMultisigKeyCountsAreLiteral(sigComputed, p2shComputed, false) &&
                   InputMultisigKeyCountsAreLiteral(CScript() << OP_0, p2shComputed, true) &&   // no redeem script: nothing runs
                   InputMultisigKeyCountsAreLiteral(CScript() << std::vector<unsigned char>(literal0.begin(), literal0.end()), p2shLiteral, true),
                   "policy on a spend: the redeem script counts once rules v3 run it") ? 0 : 1;

    // ---- through the pool, on testnet where rules v3 are in force
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    bool fWasTestNet = IsTestNet();
    SelectNetworkParams(true);
    try
    {
        nFail += Check(RulesV3Active((unsigned int)GetAdjustedTime()), "testnet: rules v3 are in force") ? 0 : 1;
        CTxDB txdb("cr+");
        CKey key;
        key.MakeNewKey();
        CScript scriptTo;
        scriptTo << OP_DUP << OP_HASH160 << Hash160(key.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;
        CScript bareComputed = (CScript() << OP_0 << OP_0) + computed;   // pushes first: the spend needs no scriptSig
        CScript bareLiteral = CScript() << OP_0 << OP_0 << OP_0 << OP_CHECKMULTISIG;
        CTransaction parent;
        parent.vin.push_back(CTxIn(COutPoint(uint256(78), 0)));
        parent.vout.push_back(CTxOut(10 * COIN, bareComputed));
        parent.vout.push_back(CTxOut(10 * COIN, bareLiteral));
        parent.vout.push_back(CTxOut(10 * COIN, p2shComputed));
        parent.vout.push_back(CTxOut(10 * COIN, p2shLiteral));
        FeeTestAddToPool(parent);

        CTransaction a = FeeTestChild(parent, 0, CENT, SEQUENCE_FINAL, scriptTo);
        CTransaction b = FeeTestChild(parent, 1, CENT, SEQUENCE_FINAL, scriptTo);
        CTransaction c = FeeTestChild(parent, 2, CENT, SEQUENCE_FINAL, scriptTo);
        c.vin[0].scriptSig = sigComputed;
        CTransaction d = FeeTestChild(parent, 3, CENT, SEQUENCE_FINAL, scriptTo);
        d.vin[0].scriptSig = CScript() << OP_0 << std::vector<unsigned char>(literal0.begin(), literal0.end());

        nFail += Check(VerifySignature(parent, a, 0, 0, true, true, true) && VerifySignature(parent, c, 0, 0, true, true, true),
                       "both computed-count spends are valid by consensus") ? 0 : 1;
        bool fMissing = true;
        nFail += Check(!a.AcceptTransaction(txdb, true, &fMissing) && !fMissing,
                       "the pool refuses a bare multisig with a computed key count, and it is not 'missing inputs'") ? 0 : 1;
        fMissing = true;
        nFail += Check(!c.AcceptTransaction(txdb, true, &fMissing) && !fMissing,
                       "and a P2SH redeem script with one (a computed-count spend is dropped, not kept as an orphan)") ? 0 : 1;
        nFail += Check(b.AcceptTransaction(txdb, true) && d.AcceptTransaction(txdb, true),
                       "a literal count enters, bare or as a redeem script") ? 0 : 1;

        // OP_CHECKMULTISIGVERIFY in a redeem script, count computed.
        {
            CScript verifyComputed;
            verifyComputed << vKeys[0] << vKeys[1] << OP_1 << OP_1 << OP_ADD << OP_CHECKMULTISIGVERIFY << OP_TRUE;
            CScript p2shVerify;
            p2shVerify.SetPayToScriptHash(verifyComputed);
            CTransaction parent2;
            parent2.vin.push_back(CTxIn(COutPoint(uint256(79), 0)));
            parent2.vout.push_back(CTxOut(10 * COIN, p2shVerify));
            FeeTestAddToPool(parent2);
            CTransaction e = FeeTestChild(parent2, 0, CENT, SEQUENCE_FINAL, scriptTo);
            e.vin[0].scriptSig = CScript() << OP_0 << OP_0 << std::vector<unsigned char>(verifyComputed.begin(), verifyComputed.end());
            nFail += Check(VerifySignature(parent2, e, 0, 0, true, true, true),
                           "the OP_CHECKMULTISIGVERIFY spend is valid by consensus") ? 0 : 1;
            fMissing = true;
            nFail += Check(!e.AcceptTransaction(txdb, true, &fMissing) && !fMissing,
                           "the pool refuses OP_CHECKMULTISIGVERIFY on a computed count, missing inputs false") ? 0 : 1;
        }

        // What the wallet makes is never refused: a real signed 2-of-3 P2SH.
        {
            CKey k1, k2, k3;
            k1.MakeNewKey(); k2.MakeNewKey(); k3.MakeNewKey();
            std::vector<std::vector<unsigned char> > msKeys;
            msKeys.push_back(k1.GetPubKey()); msKeys.push_back(k2.GetPubKey()); msKeys.push_back(k3.GetPubKey());
            CScript redeem;
            redeem.SetMultisig(2, msKeys);
            CScript p2shReal;
            p2shReal.SetPayToScriptHash(redeem);
            CTransaction parent3;
            parent3.vin.push_back(CTxIn(COutPoint(uint256(80), 0)));
            parent3.vout.push_back(CTxOut(10 * COIN, p2shReal));
            FeeTestAddToPool(parent3);
            CTransaction f = FeeTestChild(parent3, 0, CENT, SEQUENCE_FINAL, scriptTo);
            uint256 hashSig = SignatureHash(redeem, f, 0, SIGHASH_ALL);
            std::vector<unsigned char> sig1, sig3;
            bool fSigned = k1.Sign(hashSig, sig1) && k3.Sign(hashSig, sig3);
            sig1.push_back((unsigned char)SIGHASH_ALL);
            sig3.push_back((unsigned char)SIGHASH_ALL);
            f.vin[0].scriptSig = CScript() << OP_0 << sig1 << sig3 << std::vector<unsigned char>(redeem.begin(), redeem.end());
            nFail += Check(fSigned && VerifySignature(parent3, f, 0, 0, true, true, true),
                           "a real 2-of-3 P2SH spend with two signatures verifies") ? 0 : 1;
            fMissing = true;
            nFail += Check(f.AcceptTransaction(txdb, true, &fMissing) && !fMissing,
                           "the pool takes it: the policy cannot refuse what the wallet makes") ? 0 : 1;
        }

        // A parent the node does not know is still 'missing inputs'.
        {
            CTransaction orphan = FeeTestChild(parent, 1, CENT, SEQUENCE_FINAL, scriptTo);
            orphan.vin[0].prevout.hash = uint256(999);
            fMissing = false;
            nFail += Check(!orphan.AcceptTransaction(txdb, true, &fMissing) && fMissing,
                           "a spend of an unknown prevout still reports missing inputs") ? 0 : 1;
        }

        // The miner is held to it too, silently; a block is not (the check
        // is off for fBlock, so consensus is unchanged).
        {
            std::map<uint256, CTxIndex> mapTestPool;
            mapTestPool[parent.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), parent.vout.size());
            int64 nFees = 0;
            nFail += Check(!a.ConnectInputs(txdb, mapTestPool, CDiskTxPos(1,1,1), 0, nFees, false, true, 0,
                                            (unsigned int)GetAdjustedTime()),
                           "the miner's path refuses a computed count too (relay policy)") ? 0 : 1;
            std::map<uint256, CTxIndex> mapTestPool2;
            mapTestPool2[parent.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), parent.vout.size());
            nFees = 0;
            nFail += Check(b.ConnectInputs(txdb, mapTestPool2, CDiskTxPos(1,1,1), 0, nFees, false, true, 0,
                                           (unsigned int)GetAdjustedTime()),
                           "and connects a literal one") ? 0 : 1;
        }
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            mapTransactions.clear();
            mapNextTx.clear();
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    SelectNetworkParams(fWasTestNet);
    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- invoice: the shop's own payment gateway (invoice.h) ------------------------

static int RunInvoiceSelfTest()
{
    printf("invoice self-test\n");
    int nFail = 0;
    using invoice::StatusFor;
    // ---- the status rule
    nFail += Check(StatusFor(100, 0, 0, false, 2000, 1000) == "waiting", "nothing yet: waiting") ? 0 : 1;
    nFail += Check(StatusFor(100, 40, 0, false, 2000, 1000) == "partial", "some of it: partial") ? 0 : 1;
    nFail += Check(StatusFor(100, 100, 0, false, 2000, 1000) == "seen", "all of it, unconfirmed: seen -- not money yet") ? 0 : 1;
    nFail += Check(StatusFor(100, 100, 100, false, 2000, 1000) == "paid", "all of it, confirmed: paid") ? 0 : 1;
    nFail += Check(StatusFor(100, 150, 150, false, 2000, 1000) == "paid", "more than asked is still paid (and reported as overpaid)") ? 0 : 1;
    nFail += Check(StatusFor(100, 40, 0, false, 2000, 3000) == "expired", "the time ran out first: expired") ? 0 : 1;
    nFail += Check(StatusFor(100, 100, 100, false, 2000, 3000) == "paid", "paid after the time ran out is still paid: the money is there") ? 0 : 1;
    nFail += Check(StatusFor(100, 100, 100, true, 2000, 1000) == "cancelled", "cancelled is cancelled") ? 0 : 1;

    // ---- the signature a shop checks (RFC 4231-style known vector)
    nFail += Check(invoice::SignBody("key", "The quick brown fox jumps over the lazy dog") ==
                   "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
                   "the webhook signature is HMAC-SHA256, as any shop's code computes it") ? 0 : 1;

    // ---- URLs
    std::string host, path;
    unsigned short port = 0;
    nFail += Check(invoice::ParseHttpUrl("http://127.0.0.1:8080/btf/hook", host, port, path) &&
                   host == "127.0.0.1" && port == 8080 && path == "/btf/hook", "http://host:port/path reads") ? 0 : 1;
    nFail += Check(invoice::ParseHttpUrl("http://shop.example", host, port, path) && port == 80 && path == "/",
                   "port and path default") ? 0 : 1;
    nFail += Check(!invoice::ParseHttpUrl("https://shop.example/hook", host, port, path),
                   "https is refused rather than sent in the clear") ? 0 : 1;
    nFail += Check(!invoice::ParseHttpUrl("http://shop.example/a b", host, port, path),
                   "a URL that would break the request line is refused") ? 0 : 1;

    // ---- the QR a checkout page shows
    std::string svg = invoice::QrSvg("bitflash:BE39QRszEZSeqHnGEHqsZZV2hu5d8GCQAw?amount=1");
    nFail += Check(svg.compare(0, 4, "<svg") == 0 && svg.find("fill=\"#ffffff\"") != std::string::npos &&
                   svg.find("M4,4h1v1h-1z") != std::string::npos,
                   "the QR is an SVG, white behind, the first finder module at the quiet zone's edge") ? 0 : 1;

    // ---- an invoice's life, in a wallet of its own
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    std::string strOld = strSetDataDir;
    strSetDataDir = tmp;
    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");
        nlohmann::json a = invoice::Create(150000000, "Two coffees", 600, "order-41");
        std::string id = a["id"].get<std::string>();
        nFail += Check(id.size() == 32 && a["status"] == "waiting" && a["amount"].get<double>() == 1.5,
                       "an invoice is made: an id, waiting, 1.5 BTF") ? 0 : 1;
        uint160 hAddr;
        bool fMine = AddressToHash160(a["address"].get<std::string>(), hAddr);
        CRITICAL_BLOCK(cs_mapKeys)
            fMine = fMine && mapPubKeys.count(hAddr) && mapKeys.count(mapPubKeys[hAddr]);
        nFail += Check(fMine,
                       "its address is a fresh one of this wallet: the money comes straight here") ? 0 : 1;
        PaymentLink link;
        std::string err;
        nFail += Check(ParsePaymentLink(a["copyPaste"].get<std::string>(), link, err) &&
                       link.address == a["address"] && link.amount == 150000000 && link.message == "Two coffees",
                       "the copy-and-paste is the payment link, with the amount and what it is for") ? 0 : 1;
        nFail += Check(a["qrSvg"].get<std::string>().compare(0, 4, "<svg") == 0, "and the QR comes with it") ? 0 : 1;
        nlohmann::json b = invoice::Create(100000000, "", 600, "");
        nFail += Check(b["address"] != a["address"], "every invoice has its own address") ? 0 : 1;
        nFail += Check(invoice::Get(id)["orderId"] == "order-41", "getinvoice finds it by id") ? 0 : 1;
        nFail += Check(invoice::List("waiting").size() == 2, "listinvoices waiting lists both") ? 0 : 1;
        invoice::Cancel(b["id"].get<std::string>());
        nFail += Check(invoice::Get(b["id"].get<std::string>())["status"] == "cancelled" &&
                       invoice::List("waiting").size() == 1, "a cancelled one leaves the waiting list") ? 0 : 1;
        bool fThrew = false;
        try { invoice::Create(0, "", 600, ""); } catch (std::exception&) { fThrew = true; }
        nFail += Check(fThrew, "an invoice for nothing is refused") ? 0 : 1;
        fThrew = false;
        try { invoice::Get("00000000000000000000000000000000"); } catch (std::exception&) { fThrew = true; }
        nFail += Check(fThrew, "an unknown id is an error, not an empty invoice") ? 0 : 1;
        FILE* f = fopen((tmp + "/invoices.json").c_str(), "rb");
        bool fFile = f != NULL;
        if (f) fclose(f);
        nFail += Check(fFile, "invoices are kept on disk in the data directory") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    DBFlush(true);
    strSetDataDir = strOld;
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- chat-swap: the swap engine, end to end, with coins ------------------------
//
// Two engines (btfchatswap.h) wired to each other in place of the chat, each
// to a real Bitflash wallet on testnet and through it to a real Bitcoin Core
// on regtest. Every round both engines are written out and read back, as if
// the app had restarted. Not in `make tests`: it needs the wallets and Core.
//
//   CHATSWAP_A=port:passfile   Alice's Bitflash wallet (RPC user "swap")
//   CHATSWAP_B=port:passfile   Bob's
//   CHATSWAP_BTC=port          the regtest Core both wallets use (user/pass swap/swap,
//                              wallet "w" mines)
//   CHATSWAP_COIN=LTC          swap against Litecoin Core instead (or DOGE, BCH,
//                              XEC: Dogecoin Core, Bitcoin Cash Node, Bitcoin ABC)

namespace
{
struct SwapTestHost : public btfchat::SwapHost
{
    std::string addr;
    SwapTestHost* other = NULL;
    std::vector<btfchat::LogEntry> convo;
    std::map<std::string, btfchat::SwapOffer> offers;
    LoopbackRpc wallet;

    std::string MyAddress() { return addr; }
    bool PeerAccepted(const std::string&) { return true; }
    bool Invite(const std::string&, const std::string&, std::string&) { return true; }
    bool SendStep(const std::string&, const std::string& text, std::string&)
    {
        btfchat::LogEntry e;
        e.from = addr;
        e.sent = GetTime();
        unsigned char b[16];
        if (RAND_bytes(b, sizeof(b)) != 1)
            throw std::runtime_error("the random number generator failed");
        e.id = HexStr(b, b + sizeof(b), false);
        e.text = text;
        e.kind = btfchat::MSG_SWAP;
        e.outgoing = true;
        convo.push_back(e);
        e.outgoing = false;
        other->convo.push_back(e);
        return true;
    }
    void Contacts(std::vector<std::string>& out) { out.assign(1, other->addr); }
    void Conversation(const std::string&, std::vector<btfchat::LogEntry>& out) { out = convo; }
    bool FindMyOffer(const std::string& id, btfchat::SwapOffer& out)
    {
        if (!offers.count(id))
            return false;
        out = offers[id];
        return true;
    }
    bool Wallet(const std::string& method, const nlohmann::json& params, nlohmann::json& r, std::string& err)
    {
        return LoopbackRpcCall(wallet, method, params, r, err);
    }
    bool Changed() { return true; }
};

static nlohmann::json SwapTestBtc(int nPort, const std::string& method, const nlohmann::json& params,
                                  const std::string& path = "/")
{
    LoopbackRpc to;
    to.nPort = nPort;
    // Dogecoin Core 1.14 has one wallet and no /wallet/ path.
    to.strPath = getenv("CHATSWAP_COIN") && (std::string(getenv("CHATSWAP_COIN")) == "DOGE" || std::string(getenv("CHATSWAP_COIN")) == "RVN") ? "/" : path;
    to.strAuth = "swap:swap";
    to.strWho = "Bitcoin Core";
    nlohmann::json r;
    std::string err;
    if (!LoopbackRpcCall(to, method, params, r, err))
        throw std::runtime_error("Bitcoin Core " + method + ": " + err);
    return r;
}

static bool SwapTestWallet(const char* env, LoopbackRpc& to)
{
    const char* v = getenv(env);
    if (!v)
        return false;
    std::string s = v;
    size_t c = s.find(':');
    if (c == std::string::npos)
        return false;
    to.nPort = atoi(s.substr(0, c).c_str());
    FILE* f = fopen(s.substr(c + 1).c_str(), "rb");
    if (!f)
        return false;
    char buf[256] = "";
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    std::string pass(buf, n);
    while (!pass.empty() && (pass[pass.size() - 1] == '\n' || pass[pass.size() - 1] == '\r'))
        pass.erase(pass.size() - 1);
    to.strAuth = "swap:" + pass;
    to.strWho = env;
    to.nTimeoutSecs = 900;
    return true;
}

static const btfchat::SwapView* SwapTestFind(const std::vector<btfchat::SwapView>& v)
{
    return v.empty() ? NULL : &v.back();
}

// CHATSWAP_LIGHT=1: both Bitflash wallets run the built-in Bitcoin light
// client, with Core only as the Bitcoin nodes they reach and as the outside
// wallet that pays a contract. The person's part, done here: a Bitcoin
// address to receive (and be refunded) to, and paying the contract's address
// when the chat asks for it.
static void SwapTestLightPerson(btfchat::SwapEngine& e, const btfchat::SwapView* v, int nBtcPort,
                                std::set<std::string>& paid)
{
    if (!v || !getenv("CHATSWAP_LIGHT"))
        return;
    if (v->btcDestination.empty() && v->myTxid.empty() && v->paymentAddress.empty())
    {
        nlohmann::json addr = SwapTestBtc(nBtcPort, "getnewaddress", nlohmann::json::array(), "/wallet/w");
        e.SetBitcoinDestination(v->id, addr.get<std::string>());
    }
    if (v->stage == btfchat::SW_WAIT_PAYMENT && !v->paymentAddress.empty() && !paid.count(v->paymentAddress))
    {
        std::string amount = CoinAmountText(v->give, v->giveAmount);
        nlohmann::json txid = SwapTestBtc(nBtcPort, "sendtoaddress", nlohmann::json::array({ v->paymentAddress, amount }), "/wallet/w");
        printf("    paid %s BTC to the contract %s from an outside wallet (%s)\n", amount.c_str(),
               v->paymentAddress.c_str(), txid.is_string() ? txid.get<std::string>().c_str() : "?");
        paid.insert(v->paymentAddress);
    }
}

// Run both engines until both swaps end, pressing the buttons a person would.
// stopMaker: stop running the maker once the taker has locked (the maker
// vanishes); btcSkew: move the regtest clock this far each round once the
// taker has locked (to reach a Bitcoin refund without waiting for it).
static bool SwapTestRun(btfchat::SwapEngine& maker, btfchat::SwapEngine& taker, int nBtcPort,
                        int64_t nDeadline, bool fStopMakerAfterTakerLocks, int64_t nBtcSkew,
                        btfchat::SwapView& makerEnd, btfchat::SwapView& takerEnd)
{
    std::string lastM, lastT;
    int64_t nStart = GetTime(), nMock = 0;
    bool fMakerGone = false;
    std::set<std::string> paid;
    while (GetTime() - nStart < nDeadline)
    {
        if (!fMakerGone)
            maker.Round();
        taker.Round();
        // As if the app had been closed and opened again.
        maker.FromJson(maker.ToJson());
        taker.FromJson(taker.ToJson());

        std::vector<btfchat::SwapView> vm, vt;
        maker.List(vm);
        taker.List(vt);
        const btfchat::SwapView* m = SwapTestFind(vm);
        const btfchat::SwapView* t = SwapTestFind(vt);
        std::string err;
        if (!fMakerGone)
            SwapTestLightPerson(maker, m, nBtcPort, paid);
        SwapTestLightPerson(taker, t, nBtcPort, paid);
        if (m && m->fNeedsMe && !fMakerGone)
            maker.Approve(m->id, err);
        if (t && t->fNeedsMe)
            taker.Approve(t->id, err);
        std::string sm = m ? strprintf("%d %s", m->stage, m->status.c_str()) : "-";
        std::string st = t ? strprintf("%d %s", t->stage, t->status.c_str()) : "-";
        if (sm != lastM) { printf("    [%4ds] maker: %s\n", (int)(GetTime() - nStart), sm.c_str()); lastM = sm; }
        if (st != lastT) { printf("    [%4ds] taker: %s\n", (int)(GetTime() - nStart), st.c_str()); lastT = st; }
        fflush(stdout);

        bool fTakerLocked = t && !t->myTxid.empty();
        // Gone the moment the taker's side is locked -- before the maker's
        // next round could read lock2 and redeem.
        if (fStopMakerAfterTakerLocks && fTakerLocked && !fMakerGone)
        {
            printf("    the maker goes away\n");
            fMakerGone = true;
        }
        auto fin = [](const btfchat::SwapView* v) {
            return v && (v->stage == btfchat::SW_DONE || v->stage == btfchat::SW_REFUNDED ||
                         v->stage == btfchat::SW_CANCELLED || v->stage == btfchat::SW_FAILED);
        };
        if (fMakerGone && fin(t))
        {
            // The taker is done; the maker comes back, to find its own refund.
            printf("    the maker comes back\n");
            fMakerGone = false;
            fStopMakerAfterTakerLocks = false;
        }
        if (fin(m) && fin(t))
        {
            makerEnd = *m;
            takerEnd = *t;
            return true;
        }
        // Bitcoin blocks, so contracts there confirm; Bitflash makes its own.
        nlohmann::json addr = SwapTestBtc(nBtcPort, "getnewaddress", nlohmann::json::array(), "/wallet/w");
        if (nBtcSkew > 0 && fTakerLocked)
        {
            nMock = std::max<int64_t>(nMock, GetTime()) + nBtcSkew;
            // A light client refuses headers more than two hours ahead of
            // its own clock, as Bitcoin nodes do.
            if (getenv("CHATSWAP_LIGHT"))
                nMock = std::min<int64_t>(nMock, GetTime() + 5400);
            SwapTestBtc(nBtcPort, "setmocktime", nlohmann::json::array({ nMock }));
        }
        SwapTestBtc(nBtcPort, "generatetoaddress", nlohmann::json::array({ 1, addr }));
        Sleep(10000);
    }
    std::vector<btfchat::SwapView> vm, vt;
    maker.List(vm);
    taker.List(vt);
    if (!vm.empty()) makerEnd = vm.back();
    if (!vt.empty()) takerEnd = vt.back();
    return false;
}
} // namespace

static int RunChatSwapSelfTest()
{
    printf("chat-swap self-test (testnet Bitflash wallets + Bitcoin Core regtest)\n");
#ifdef _WIN32
    // A self-test starts before the node would have started Winsock.
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif
    SwapTestHost a, b;
    const char* pszBtc = getenv("CHATSWAP_BTC");
    if (!IsTestNet() || !SwapTestWallet("CHATSWAP_A", a.wallet) || !SwapTestWallet("CHATSWAP_B", b.wallet) || !pszBtc)
    {
        printf("  needs -testnet and CHATSWAP_A, CHATSWAP_B, CHATSWAP_BTC; see selftest.cpp\n");
        return 1;
    }
    int nBtc = atoi(pszBtc);
    int nFail = 0;
    // CHATSWAP_COIN=LTC: the same swaps on Litecoin, with Litecoin Core on
    // regtest in Bitcoin Core's place (CHATSWAP_BTC names its port), and so
    // on with BCH and XEC.
    const std::string coin = getenv("CHATSWAP_COIN") ? getenv("CHATSWAP_COIN") : "BTC";
    // A DigiByte or Ravencoin contract holds at least 0.1.
    const int64_t nScale = coin == "DGB" || coin == "RVN" ? 10 : 1;
    a.addr = "alice.btf";
    b.addr = "bob.btf";
    a.other = &b;
    b.other = &a;

    // Each scenario on its own: one that throws does not hide the others.
    {
        // ---- 1: Alice gives BTF, Bob gives BTC; both finish
        try {
            printf("  1. Alice offers 1 BTF for 0.05 BTC; Bob takes it\n");
            btfchat::SwapEngine ea(&a), eb(&b);
            btfchat::SwapOffer o;
            o.give = "BTF"; o.giveAmount = COIN;
            o.want = coin; o.wantAmount = 5000000 * nScale;
            a.offers["11111111111111111111111111111111"] = o;
            std::string id, err;
            nFail += Check(eb.Take(a.addr, "11111111111111111111111111111111", o, id, err), "Bob takes the offer") ? 0 : 1;
            btfchat::SwapView m, t;
            bool fEnd = SwapTestRun(ea, eb, nBtc, 7200, false, 0, m, t);
            nFail += Check(fEnd && m.stage == btfchat::SW_DONE && t.stage == btfchat::SW_DONE,
                           "both sides finish: DONE and DONE") ? 0 : 1;
            nlohmann::json tx = SwapTestBtc(nBtc, "gettransaction", nlohmann::json::array({ m.redeemTxid }), "/wallet/w");
            double got = tx.value("amount", 0.0) * CoinUnit(coin) / COIN;   // in BTC-sized units on every chain
            // Dogecoin's fee is a thousand times Bitcoin's, as a share of this amount.
            nFail += Check(got > (coin == "DOGE" ? 0.04 : coin == "RVN" ? 0.049 : 0.0499) * nScale && got <= 0.05 * nScale, strprintf("Alice's node wallet got %.8f of 0.05 in base units", got).c_str()) ? 0 : 1;
            nlohmann::json bt;
            std::string e2;
            bool fGot = LoopbackRpcCall(b.wallet, "gettransaction", nlohmann::json::array({ t.redeemTxid }), bt, e2) &&
                        bt.is_object();
            double amt = fGot ? bt.value("amount", 0.0) : 0.0;
            nFail += Check(fGot && amt > 0.98,
                           strprintf("Bob's Bitflash wallet got %.8f BTF (redeem %s%s%s)", amt, t.redeemTxid.c_str(),
                                     fGot ? "" : ": ", e2.c_str()).c_str()) ? 0 : 1;
        } catch (std::exception& e) { nFail += Check(false, e.what()) ? 0 : 1; }

        // ---- 2: Bob gives BTC, Alice gives BTF; the other direction
        try {
            printf("  2. Bob offers 0.04 BTC for 0.8 BTF; Alice takes it\n");
            btfchat::SwapEngine ea(&a), eb(&b);
            a.convo.clear();
            b.convo.clear();
            btfchat::SwapOffer o;
            o.give = coin; o.giveAmount = 4000000 * nScale;
            o.want = "BTF"; o.wantAmount = 80000000;
            b.offers["22222222222222222222222222222222"] = o;
            std::string id, err;
            nFail += Check(ea.Take(b.addr, "22222222222222222222222222222222", o, id, err), "Alice takes it") ? 0 : 1;
            btfchat::SwapView m, t;
            bool fEnd = SwapTestRun(eb, ea, nBtc, 7200, false, 0, m, t);
            nFail += Check(fEnd && m.stage == btfchat::SW_DONE && t.stage == btfchat::SW_DONE,
                           "both sides finish the other way round too") ? 0 : 1;
        } catch (std::exception& e) { nFail += Check(false, e.what()) ? 0 : 1; }

        // ---- 3: Alice locks, Bob locks, Alice vanishes: both refund
        try {
            printf("  3. Alice offers 0.5 BTF for 0.03 BTC; Bob locks; Alice vanishes\n");
            btfchat::SwapConfig cfg;
            // Short locks (test chains only): 24 minutes of Bitflash median
            // time for Alice, 15 minutes of Bitcoin median time for Bob, and
            // the margins to match.
            cfg.nBtfInitiatorSecs = 1440;
            cfg.nBtcParticipantSecs = 900;
            cfg.nTakerMinLeft = 240;
            cfg.nMakerMinLeft = 60;
            btfchat::SwapEngine ea(&a, cfg), eb(&b, cfg);
            a.convo.clear();
            b.convo.clear();
            btfchat::SwapOffer o;
            o.give = "BTF"; o.giveAmount = 50000000;
            o.want = coin; o.wantAmount = 3000000 * nScale;
            a.offers["33333333333333333333333333333333"] = o;
            std::string id, err;
            nFail += Check(eb.Take(a.addr, "33333333333333333333333333333333", o, id, err), "Bob takes it") ? 0 : 1;
            btfchat::SwapView m, t;
            bool fEnd = SwapTestRun(ea, eb, nBtc, 14400, true, 300, m, t);
            nFail += Check(fEnd && t.stage == btfchat::SW_REFUNDED && !t.refundTxid.empty(),
                           "Bob's BTC comes back by itself after its lock") ? 0 : 1;
            nFail += Check(fEnd && m.stage == btfchat::SW_REFUNDED && !m.refundTxid.empty(),
                           "and Alice's BTF after hers -- she never showed the secret") ? 0 : 1;
        } catch (std::exception& e) { nFail += Check(false, e.what()) ? 0 : 1; }
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// A canonical swap contract, hex, locked at nLockTime under hash (hex).
static std::string SwapTestContract(int64_t nLockTime, const std::string& hash,
                                    const std::vector<unsigned char>& recipient = std::vector<unsigned char>(20, 0x11))
{
    swap::Contract c;
    c.recipientPkh = recipient;
    c.refundPkh.assign(20, 0x22);
    c.secretHash = ParseHex(hash);
    c.nLockTime = nLockTime;
    CScript k = swap::BuildContract(c);
    return HexStr(k.begin(), k.end(), false);
}

// -selftest=swap-wait-payment -- a swap whose Bitcoin contract waits to be paid
// from another wallet (the light backend). Nothing is locked yet, but the
// contract exists, so it can neither hang forever nor be dropped while a
// payment may be on its way. The wallet is a stand-in that answers the audit
// the way the light backend does.
namespace
{
struct WaitPayHost : public btfchat::SwapHost
{
    nlohmann::json audit;                           // our own BTC contract ("00")
    std::map<std::string, nlohmann::json> audits;   // any other contract, by its hex
    std::map<std::string, nlohmann::json> finds;    // btcfindsecret/swapfindsecret, by contract
    nlohmann::json refundParams, redeemParams;
    int nRefunds = 0, nSteps = 0, nRedeems = 0, nCoinCalls = 0;
    std::string lastStep;

    std::string MyAddress() { return "me"; }
    bool PeerAccepted(const std::string&) { return true; }
    bool Invite(const std::string&, const std::string&, std::string&) { return true; }
    bool SendStep(const std::string&, const std::string& text, std::string&) { nSteps++; lastStep = text; return true; }
    void Contacts(std::vector<std::string>& out) { out.clear(); }
    void Conversation(const std::string&, std::vector<btfchat::LogEntry>& out) { out.clear(); }
    bool FindMyOffer(const std::string&, btfchat::SwapOffer&) { return false; }
    bool Wallet(const std::string& methodIn, const nlohmann::json& paramsIn, nlohmann::json& r, std::string& err)
    {
        // A chain other than Bitcoin goes through coin<step>, the chain first.
        std::string method = methodIn;
        nlohmann::json params = paramsIn;
        if (method.compare(0, 4, "coin") == 0)
        {
            if (!params.is_array() || params.empty() || params[0] != "ltc") { err = "coin call without its chain"; return false; }
            nCoinCalls++;
            method = "btc" + method.substr(4);
            params.erase(params.begin());
        }
        std::string contract = params.is_array() && !params.empty() && params[0].is_string() ? params[0].get<std::string>() : "";
        if (method == "btcauditcontract" || method == "swapauditcontract")
        {
            r = audits.count(contract) ? audits[contract] : audit;
            return true;
        }
        if (method == "btcfindsecret" || method == "swapfindsecret")
        {
            r = finds.count(contract) ? finds[contract] : nlohmann::json{ { "spent", false } };
            return true;
        }
        if (method == "btcrefund" || method == "swaprefund") { nRefunds++; refundParams = params; r = { { "txid", std::string(64, 'f') } }; return true; }
        if (method == "btcredeem")
        {
            // As the light client answers: sent, not seen in any memory pool.
            nRedeems++; redeemParams = params;
            r = { { "txid", strprintf("%064d", nRedeems) }, { "feeRatePerKvB", 0.0001 }, { "awaitingConfirmation", true } };
            return true;
        }
        if (method == "swapredeem") { nRedeems++; redeemParams = params; r = { { "txid", std::string(64, 'd') } }; return true; }
        if (method == "btcswapinfo") { r = { { "backend", "light" } }; return true; }
        err = "not in this test: " + method;
        return false;
    }
    bool Changed() { return true; }

    void Unpaid(int64_t nSecondsLeft, int64_t nLockTime)
    {
        audit = { { "contractTxid", std::string(64, '0') }, { "vout", 0 }, { "unspent", false },
                  { "confirmations", 0 }, { "amount", nullptr }, { "secondsUntilRefund", nSecondsLeft },
                  { "lockTime", nLockTime } };
    }
    void Paid(double amount, int64_t nSecondsLeft, int64_t nLockTime)
    {
        audit = { { "contractTxid", std::string(64, 'a') }, { "vout", 1 }, { "unspent", true },
                  { "confirmations", 6 }, { "amount", amount }, { "secondsUntilRefund", nSecondsLeft },
                  { "lockTime", nLockTime } };
    }
};

static std::string WaitPaySwapJson(const std::string& id, const std::string& coin = "BTC")
{
    nlohmann::json s = { { "id", id }, { "peer", "them" }, { "maker", true },
                         { "give", coin }, { "ga", 1000000 }, { "want", "BTF" }, { "wa", 100000000 },
                         { "btcDestination", "bcrt1qdestination" }, { "paymentAddress", "2NcontractAddress" },
                         { "myC", "00" }, { "myTx", "" }, { "myN", -1 }, { "stage", (int)btfchat::SW_WAIT_PAYMENT },
                         { "ok", true }, { "inv", true }, { "created", GetTime() }, { "updated", GetTime() } };
    nlohmann::json j = { { "swaps", nlohmann::json::array({ s }) }, { "seen", nlohmann::json::array() } };
    return j.dump();
}

static btfchat::SwapView WaitPayView(btfchat::SwapEngine& e)
{
    std::vector<btfchat::SwapView> v;
    e.List(v);
    return v.empty() ? btfchat::SwapView() : v[0];
}
} // namespace

static int RunSwapWaitPaymentSelfTest()
{
    int nFail = 0;
    const std::string id(32, '1');
    int64_t nNow = GetTime();

    {
        // The same path on Litecoin: every chain call is coin<step> ltc.
        WaitPayHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(WaitPaySwapJson(id, "LTC"));
        h.Unpaid(0, nNow - 2 * 86400);
        e.Round();
        std::string err;
        e.Cancel(id, err);
        h.Paid(0.01, 0, nNow - 60);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(h.nRefunds == 1 && v.stage == btfchat::SW_REFUNDING,
                       "a payment on Litecoin is refunded at its lock, and watched until a block has the refund") ? 0 : 1;
        h.finds["00"] = { { "spent", true }, { "refunded", true }, { "confirmed", true } };
        e.Round();
        v = WaitPayView(e);
        nFail += Check(h.nCoinCalls >= 1, "a Litecoin swap asks the wallet through coin* with its chain") ? 0 : 1;
        nFail += Check(v.give == "LTC" && h.nRefunds == 1 && v.stage == btfchat::SW_REFUNDED,
                       "and once a block has it, it came back") ? 0 : 1;
        nFail += Check(h.refundParams.size() == 3 && h.refundParams[1] == std::string(64, 'a') + ":1",
                       "from the output that was paid, named as on Bitcoin") ? 0 : 1;
    }

    {
        WaitPayHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(WaitPaySwapJson(id));
        h.Unpaid(3600, nNow + 3600);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_WAIT_PAYMENT, "unpaid, lock ahead: still waiting for the payment") ? 0 : 1;
        nFail += Check(v.fCanCancel, "and it can be cancelled") ? 0 : 1;
        std::string err;
        nFail += Check(e.Cancel(id, err), "cancel is accepted") ? 0 : 1;
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING, "cancelled: the contract is still watched, not forgotten") ? 0 : 1;
        nFail += Check(h.lastStep.find("cancel") != std::string::npos, "the other side is told") ? 0 : 1;
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nRefunds == 0, "nothing paid: nothing to refund yet") ? 0 : 1;

        // The payment was already on its way when it was cancelled.
        h.Paid(0.01, 1800, nNow + 1800);
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && v.myTxid == std::string(64, 'a'),
                       "a late payment is adopted for the refund") ? 0 : 1;
        nFail += Check(h.nRefunds == 0, "and not refunded before its lock") ? 0 : 1;
        h.Paid(0.01, 0, nNow - 60);
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nRefunds == 1, "at the lock it is refunded") ? 0 : 1;
        h.finds["00"] = { { "spent", true }, { "refunded", true }, { "confirmed", false } };
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nRefunds == 1,
                       "a refund only in a memory pool is not the end yet") ? 0 : 1;
        h.finds["00"]["confirmed"] = true;
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDED && h.nRefunds == 1, "in a block, it came back") ? 0 : 1;
        nFail += Check(h.refundParams.size() == 3 && h.refundParams[1] == std::string(64, 'a') + ":1" &&
                       h.refundParams[2] == "bcrt1qdestination",
                       "to the person's own Bitcoin address, from the output that was paid") ? 0 : 1;
    }

    {
        WaitPayHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(WaitPaySwapJson(id));
        h.Unpaid(0, nNow - 3600);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nSteps == 1,
                       "never paid by its lock: the swap is called off and the other side told") ? 0 : 1;
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING, "still watched for a day past the lock") ? 0 : 1;
        h.Unpaid(0, nNow - 2 * 86400);
        e.Round();
        v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_CANCELLED && h.nRefunds == 0, "then it ends, with nothing to refund") ? 0 : 1;
    }

    {
        WaitPayHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(WaitPaySwapJson(id));
        h.Paid(0.02, 7200, nNow + 7200);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING && v.myTxid == std::string(64, 'a'),
                       "a wrong amount paid in: the swap stops and that payment is refunded") ? 0 : 1;
        std::string err;
        nFail += Check(!e.Cancel(id, err), "and once something is locked, cancel is refused") ? 0 : 1;
    }

    {
        WaitPayHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(WaitPaySwapJson(id));
        h.Paid(0.01, 7200, nNow + 7200);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(v.stage == btfchat::SW_LOCKED && v.myTxid == std::string(64, 'a') && !v.fCanCancel,
                       "the exact amount, confirmed: the swap goes on and can no longer be cancelled") ? 0 : 1;
    }

    // A maker who wants BTC redeems it through the light client, which only
    // sends: the swap is done when the redeem is in a block, and a redeem that
    // sits goes out again with twice the fee -- the secret is already public.
    {
        const std::string secret(64, 'a'), hash(64, 'c');
        const std::string theirs = SwapTestContract(nNow + 8 * 3600, hash);
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", true },
                              { "give", "BTF" }, { "ga", 100000000 }, { "want", "BTC" }, { "wa", 1000000 },
                              { "btcDestination", "bcrt1qdestination" }, { "myRecv", "mvMine" },
                              { "secret", secret }, { "hash", hash },
                              { "myC", "22" }, { "myTx", std::string(64, '2') },
                              { "thC", theirs }, { "thTx", std::string(64, '1') }, { "thN", 0 },
                              { "stage", (int)btfchat::SW_REDEEMING }, { "ok", true }, { "inv", true },
                              { "created", nNow }, { "updated", nNow }, { "since", nNow } };
        std::string state = nlohmann::json{ { "swaps", nlohmann::json::array({ sw }) }, { "seen", nlohmann::json::array() } }.dump();
        WaitPayHost h;
        h.audits[theirs] = { { "recipientIsMine", true }, { "recipient", "mvMine" }, { "secretHash", hash },
                             { "unspent", true }, { "confirmations", 6 }, { "amount", 0.01 }, { "secondsUntilRefund", 8 * 3600 } };
        btfchat::SwapEngine e(&h);
        e.FromJson(state);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(h.nRedeems == 1 && v.stage == btfchat::SW_REDEEMING && v.status.find("waiting for Bitcoin") != std::string::npos,
                       "light redeem sent: not done until it confirms") ? 0 : 1;
        nFail += Check(h.redeemParams.size() == 4 && h.redeemParams[3] == "bcrt1qdestination", "to the person's own address") ? 0 : 1;
        nFail += Check(h.lastStep.find("redeemed") != std::string::npos, "and the other side is told") ? 0 : 1;
        h.audits[theirs]["secondsUntilRefund"] = 60;
        e.Round();
        v = WaitPayView(e);
        nFail += Check(h.nRedeems == 1 && v.stage == btfchat::SW_REDEEMING,
                       "before the bump time: no second redeem, and their lock running low cancels nothing") ? 0 : 1;

        btfchat::SwapConfig quick;
        quick.nRedeemBumpAfter = 0;
        btfchat::SwapEngine e2(&h, quick);
        e2.FromJson(e.ToJson());
        e2.Round();
        v = WaitPayView(e2);
        nFail += Check(h.nRedeems == 2 && h.redeemParams.size() == 5 && h.redeemParams[4] == "0.00020000" &&
                       v.redeemTxid == strprintf("%064d", 2),
                       "still unconfirmed: sent again at twice the fee rate") ? 0 : 1;
        h.finds[theirs] = { { "spent", true }, { "secret", secret } };
        e2.Round();
        v = WaitPayView(e2);
        nFail += Check(v.stage == btfchat::SW_DONE && h.nRedeems == 2, "in a block: done") ? 0 : 1;
    }

    // A taker's refund is not the end while the maker can still redeem ours
    // with the secret instead: before a block has the refund, or by a
    // reorganisation that replaces the block. Watched until the refund has
    // the chain's confirmations and the maker's contract is spent or open.
    for (int nCase = 0; nCase < 3; nCase++)
    {
        const std::string secret(64, 'b');
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", false },
                              { "give", "BTC" }, { "ga", 1000000 }, { "want", "BTF" }, { "wa", 100000000 },
                              { "btcDestination", "bcrt1qdestination" }, { "hash", std::string(64, 'c') },
                              { "myC", "33" }, { "myTx", std::string(64, '3') }, { "myN", 1 },
                              { "thC", "44" }, { "thTx", std::string(64, '4') },
                              { "stage", (int)btfchat::SW_REFUNDING }, { "ok", true }, { "inv", true },
                              { "created", nNow }, { "updated", nNow } };
        WaitPayHost h;
        h.audits["33"] = { { "unspent", true }, { "secondsUntilRefund", 0 } };
        h.audits["44"] = { { "unspent", true }, { "secondsUntilRefund", 3600 } };
        btfchat::SwapEngine e(&h);
        e.FromJson(nlohmann::json{ { "swaps", nlohmann::json::array({ sw }) }, { "seen", nlohmann::json::array() } }.dump());
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(h.nRefunds == 1 && v.stage == btfchat::SW_REFUNDING && !v.refundTxid.empty(),
                       "taker refunded ours: still watching while theirs is locked") ? 0 : 1;
        e.Round();
        nFail += Check(h.nRefunds == 1, "the refund is not sent twice") ? 0 : 1;
        if (nCase == 0)
        {
            // The maker outbid our refund with a redeem: the secret is out.
            h.finds["33"] = { { "spent", true }, { "secret", secret } };
            e.Round();
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_DONE && h.nRedeems == 1 && h.redeemParams.size() >= 3 && h.redeemParams[2] == secret,
                           "ours was taken instead: theirs is taken with the secret") ? 0 : 1;
        }
        else if (nCase == 1)
        {
            // Our refund is in one block; a reorganisation replaces it with
            // their redeem, which shows the secret on the chain.
            h.finds["33"] = { { "spent", true }, { "refunded", true }, { "confirmed", true }, { "spendConfirmations", 1 } };
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nRedeems == 0,
                           "our refund one block deep: not over, still watching") ? 0 : 1;
            h.finds["33"] = { { "spent", true }, { "secret", secret }, { "confirmed", true }, { "spendConfirmations", 1 } };
            e.Round();
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_DONE && h.nRedeems == 1 && h.redeemParams.size() >= 3 && h.redeemParams[2] == secret,
                           "reorganised into their redeem: theirs is taken with the secret") ? 0 : 1;
        }
        else
        {
            // Their lock opening is not enough while our refund is in no
            // block; nor is a refund deep enough while their lock still runs.
            h.audits["44"] = { { "unspent", true }, { "secondsUntilRefund", 0 } };
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_REFUNDING && h.nRedeems == 0,
                           "their lock opened, our refund is in no block yet: still watching") ? 0 : 1;
            h.audits["44"] = { { "unspent", true }, { "secondsUntilRefund", 3600 } };
            h.finds["33"] = { { "spent", true }, { "refunded", true }, { "confirmed", true }, { "spendConfirmations", 6 } };
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_REFUNDING, "our refund deep, their lock still running: still watching") ? 0 : 1;
            h.audits["44"] = { { "unspent", true }, { "secondsUntilRefund", 0 } };
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_REFUNDED && h.nRedeems == 0,
                           "our refund deep and their lock open: it is over") ? 0 : 1;
        }
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- swap hardening (review of 2026-11-10) -------------------------------------

// -selftest=swap-timelock -- Bitflash contracts locked by time, and the margins
// that keep the swap's ordering (swap.h, THE TIMING).
static int RunSwapTimelockSelfTest()
{
    printf("swap-timelock self-test\n");
    int nFail = 0;

    // What the wallet reports as seconds left is exactly when the next block
    // takes the refund (IsFinalAt at the tip's median time).
    {
        const int64_t L = 1800000000;
        CTransaction t;
        t.vin.resize(1);
        t.vin[0].nSequence = 0;
        t.nLockTime = (unsigned int)L;
        bool fAgree = true;
        for (int64_t d = -3; d <= 3; d++)
        {
            int64_t nMedian = L + d;
            bool fFinal = t.IsFinalAt(1000, nMedian);
            if (fFinal != (swap::SecondsUntilRefund(L, nMedian) == 0))
                fAgree = false;
        }
        nFail += Check(fAgree, "seconds left reach 0 exactly when the next block may hold the refund") ? 0 : 1;
        nFail += Check(swap::SecondsUntilRefund(L, L - 3600) == 3601 && swap::SecondsUntilRefund(L, L + 1) == 0,
                       "and count down by the median time, not the clock") ? 0 : 1;
    }

    // The locks are times; the margins hold the worst case the comment argues.
    btfchat::SwapConfig cfg;
    const int64_t nBlock = 120, nWorstBlock = 64 * nBlock;      // three largest retarget steps
    const int64_t nDogeEarly = 2 * 3600;                        // no BIP113 on Dogecoin
    nFail += Check(swap::BTF_INITIATOR_LOCK_SECS == 48 * 3600 && swap::BTF_PARTICIPANT_LOCK_SECS == 18 * 3600,
                   "Bitflash locks are 48 and 18 hours of median time") ? 0 : 1;
    nFail += Check(cfg.nTakerMinLeft - swap::BTF_PARTICIPANT_LOCK_SECS >= 7 * nWorstBlock + nDogeEarly,
                   "a taker giving BTF has room for its refund's seven blocks at 64 times the target, Dogecoin included") ? 0 : 1;
    nFail += Check(cfg.nTakerMinLeft - btcswap::PARTICIPANT_LOCK_SECS >= 6 * 3600 + 2 * 3600,
                   "a taker giving another coin keeps six hours past a Bitflash median running two hours ahead") ? 0 : 1;
    nFail += Check(swap::BTF_PARTICIPANT_LOCK_SECS >= cfg.nMakerMinLeft + 4 * 30 * nBlock,
                   "a maker can see 30 confirmations of a BTF lock at a quarter of the speed and still have 6 hours") ? 0 : 1;
    nFail += Check(swap::BTF_INITIATOR_LOCK_SECS > cfg.nTakerMinLeft && btcswap::INITIATOR_LOCK_SECS > cfg.nTakerMinLeft,
                   "every initiator lock leaves the taker time to check and lock") ? 0 : 1;
    nFail += Check(cfg.nBtfMaxMedianLag > 0 && cfg.nBtfMaxMedianLag <= 3600,
                   "a taker giving BTF waits while the chain's median time is over an hour behind") ? 0 : 1;

    // A new Bitflash lock is counted from the median time and refused while
    // the node is catching up (swap::BtfLockTime). On the public eCash
    // testnet swap of 2026-11-14 a wallet four days behind made an 18 hour
    // participant lock that had opened three days before it was paid.
    {
        const int64_t nNow = 1800000000, P = swap::BTF_PARTICIPANT_LOCK_SECS;
        int64_t L = -1;
        std::string err;
        nFail += Check(swap::BtfLockTime(nNow, nNow - 12 * 60, P, L, err) && L == nNow + P,
                       "a synced node: the lock is the clock plus the lock seconds") ? 0 : 1;
        nFail += Check(swap::BtfLockTime(nNow, nNow - 59 * 60, P, L, err) && L == nNow - 59 * 60 + 20 * 60 + P,
                       "a median 59 minutes behind: counted from the median plus 20 minutes") ? 0 : 1;
        nFail += Check(swap::BtfLockTime(nNow, nNow + 600, P, L, err) && L == nNow + P,
                       "a median ahead of the clock: never later than the clock") ? 0 : 1;
        err.clear();
        nFail += Check(!swap::BtfLockTime(nNow, nNow - 61 * 60, P, L, err) && L == 0 && err.find("behind") != std::string::npos,
                       "a median 61 minutes behind: refused, and says why") ? 0 : 1;
        err.clear();
        const int64_t nMedianFound = nNow - 4 * 86400;
        const int64_t nOldLock = std::min<int64_t>(nNow, nMedianFound + 20 * 60) + P;   // the 1.2.33 formula
        nFail += Check(nOldLock < nNow && !swap::BtfLockTime(nNow, nMedianFound, P, L, err) && !err.empty(),
                       "four days behind, which 1.2.33 made into a lock already open: refused") ? 0 : 1;
        err.clear();
        nFail += Check(!swap::BtfLockTime(nNow, 0, P, L, err) && !err.empty(),
                       "no chain: refused") ? 0 : 1;
        nFail += Check(swap::BTF_LOCK_MAX_MEDIAN_LAG == cfg.nBtfMaxMedianLag,
                       "the same hour a chat taker giving BTF waits on") ? 0 : 1;
    }

    // Both sides agree on the contract form: an offer or a take from a
    // version that locks BTF by height is refused before anything moves.
    {
        std::string err;
        btfchat::SwapOffer o;
        o.give = "BTF"; o.giveAmount = COIN; o.want = "LTC"; o.wantAmount = 200000000;
        std::string text = btfchat::FormatSwapOffer(o);
        nFail += Check(text.find("\"v\":2") != std::string::npos, "an offer says it locks BTF by time") ? 0 : 1;
        btfchat::SwapOffer back;
        nFail += Check(!btfchat::ParseSwapOffer("{\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000000}", back, err) &&
                       err.find("older") != std::string::npos,
                       "an offer from an older version is refused, saying why") ? 0 : 1;
        btfchat::SwapStep st;
        std::string take = "{\"s\":\"" + std::string(32, 'a') + "\",\"step\":\"take\",\"offer\":\"" + std::string(32, 'b') +
                           "\",\"terms\":{\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000000},"
                           "\"to\":\"BE39QRszEZSeqHnGEHqsZZV2hu5d8GCQAw\"}";
        nFail += Check(!btfchat::ParseSwapStep(take, st, err), "and so is a take from one") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static std::string SwapTestReadFile(const std::string& path)
{
    std::string out;
    FILE* f = fopen(path.c_str(), "rb");
    char buf[4096];
    size_t n;
    while (f && (n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    if (f)
        fclose(f);
    return out;
}

// -selftest=swap-journal -- the secret on the disk before anything is sent
// (H2), the file private and replaced in one step, the secret's randomness
// checked.
static int RunSwapJournalSelfTest()
{
    printf("swap-journal self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary directory\n");
        return 1;
    }
    std::string err;

    // The atomic private write.
    std::string path = tmp + "/store";
    nFail += Check(WriteFileAtomicPrivate(path, "one", err) && SwapTestReadFile(path) == "one", "a file is written") ? 0 : 1;
    nFail += Check(WriteFileAtomicPrivate(path, "two", err) && SwapTestReadFile(path) == "two" &&
                   !FileExists((path + ".new").c_str()),
                   "and replaced whole, nothing left beside it") ? 0 : 1;
#ifndef _WIN32
    struct stat st;
    nFail += Check(stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "only its owner can read it (0600)") ? 0 : 1;
#endif
    nFail += Check(!WriteFileAtomicPrivate(tmp + "/no-such-dir/store", "x", err) && !err.empty(),
                   "a write that cannot happen fails and says why") ? 0 : 1;
    {
        // A store whose new copy cannot be made keeps the old one, byte for byte.
        std::string blocked = tmp + "/blocked";
        WriteFileAtomicPrivate(blocked, "old", err);
#ifdef _WIN32
        CreateDirectoryA((blocked + ".new").c_str(), NULL);
#else
        mkdir((blocked + ".new").c_str(), 0700);
#endif
        bool fRefused = !WriteFileAtomicPrivate(blocked, "new", err);
        nFail += Check(fRefused && SwapTestReadFile(blocked) == "old", "a failed save leaves the old file as it was") ? 0 : 1;
    }

    // The secret.
    std::vector<unsigned char> secret, hash;
    nFail += Check(swap::NewSecret(secret, hash) && secret.size() == 32 && hash.size() == 32 &&
                   secret != std::vector<unsigned char>(32, 0), "a new secret is 32 random bytes") ? 0 : 1;
    unsigned char h[32];
    SHA256(&secret[0], secret.size(), h);
    nFail += Check(std::vector<unsigned char>(h, h + 32) == hash, "and its hash is SHA-256 of it") ? 0 : 1;

    // The journal.
    std::string journal = tmp + "/swaps.log";
    swap::JournalSetPathForTest(journal);
    nlohmann::json merged;
    nFail += Check(swap::JournalLookup("abc", merged, err) && merged.is_null(), "an empty journal knows no tag") ? 0 : 1;
    nlohmann::json intent = { { "tag", "abc" }, { "state", "intent" }, { "chain", "btf" }, { "secret", "5e" },
                              { "contract", "63" }, { "contractAddress", "3x" } };
    nFail += Check(swap::JournalAppend(intent, err), "an intent is written") ? 0 : 1;
    std::string raw = SwapTestReadFile(journal);
    nFail += Check(raw.find("\"secret\":\"5e\"") != std::string::npos, "with the secret in it, on the disk") ? 0 : 1;
#ifndef _WIN32
    nFail += Check(stat(journal.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "swaps.log is 0600") ? 0 : 1;
#endif
    // A line cut short by an older version's crash does not hide the others.
    {
        FILE* f = fopen(journal.c_str(), "ab");
        if (f) { fputs("{\"tag\":\"abc\",\"state\":\"fun", f); fclose(f); }
    }
    nFail += Check(swap::JournalAppend(nlohmann::json{ { "tag", "abc" }, { "state", "funded" }, { "contractTxid", "77" } }, err),
                   "a line is added after a torn one") ? 0 : 1;
    nFail += Check(swap::JournalAppend(nlohmann::json{ { "tag", "other" }, { "state", "failed" } }, err), "another tag") ? 0 : 1;
    nFail += Check(swap::JournalLookup("abc", merged, err) && merged.is_object() && merged.value("state", "") == "funded" &&
                   merged.value("secret", "") == "5e" && merged.value("contractTxid", "") == "77",
                   "a tag's lines merge: the secret from its intent, the transaction from its funding") ? 0 : 1;
    std::vector<nlohmann::json> lines;
    nFail += Check(swap::JournalRead(lines, err) && lines.size() == 3, "the torn line is skipped, the rest read") ? 0 : 1;
    nFail += Check(swap::JournalTagOk(std::string(32, 'a')) && !swap::JournalTagOk("") && !swap::JournalTagOk("a b") &&
                   !swap::JournalTagOk(std::string(65, 'a')), "a tag is 1 to 64 plain characters") ? 0 : 1;
    swap::JournalSetPathForTest("");

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=swap-parse -- an offer or a step of any shape is refused, never
// thrown out of the parser (M4), and offers have floors (L3).
static int RunSwapParseSelfTest()
{
    printf("swap-parse self-test\n");
    int nFail = 0;
    std::string err;
    btfchat::SwapOffer o;
    btfchat::SwapStep st;
    const std::string sid = std::string(32, 'a');
    const char* badOffers[] = {
        "{\"v\":2,\"give\":5,\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000000}",
        "{\"v\":2,\"give\":\"BTF\",\"ga\":100000000,\"want\":[\"LTC\"],\"wa\":200000000}",
        "{\"v\":2,\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000000,\"note\":{}}",
        "{\"v\":\"2\",\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000000}",
        "[1,2,3]", "null", "\"text\"",
    };
    bool fAllRefused = true;
    for (size_t i = 0; i < sizeof(badOffers) / sizeof(badOffers[0]); i++)
    {
        try { if (btfchat::ParseSwapOffer(badOffers[i], o, err)) fAllRefused = false; }
        catch (...) { fAllRefused = false; }
    }
    nFail += Check(fAllRefused, "offers with fields of the wrong type are refused, not thrown") ? 0 : 1;
    std::vector<std::string> badSteps = {
        "{\"s\":123,\"step\":\"cancel\"}",
        "{\"s\":\"" + sid + "\",\"step\":false}",
        "{\"s\":\"" + sid + "\",\"step\":\"take\",\"offer\":7}",
        "{\"s\":\"" + sid + "\",\"step\":\"take\",\"offer\":\"" + std::string(32, 'b') + "\",\"terms\":{\"v\":2,\"give\":{}}}",
        "{\"s\":\"" + sid + "\",\"step\":\"lock1\",\"chain\":[\"BTC\"],\"c\":\"dd\",\"tx\":\"" + std::string(64, 'e') + "\"}",
        "{\"s\":\"" + sid + "\",\"step\":\"lock2\",\"chain\":\"BTC\",\"c\":1,\"tx\":\"" + std::string(64, 'e') + "\",\"n\":0}",
        "{\"s\":\"" + sid + "\",\"step\":\"lock2\",\"chain\":\"BTC\",\"c\":\"dd\",\"tx\":\"" + std::string(64, 'e') + "\",\"n\":4294967297}",
        "{\"s\":\"" + sid + "\",\"step\":\"redeemed\",\"tx\":null}",
    };
    fAllRefused = true;
    for (size_t i = 0; i < badSteps.size(); i++)
    {
        try { if (btfchat::ParseSwapStep(badSteps[i], st, err)) fAllRefused = false; }
        catch (...) { fAllRefused = false; }
    }
    nFail += Check(fAllRefused, "steps with fields of the wrong type are refused, an output past 2^31 too") ? 0 : 1;
    nFail += Check(btfchat::ParseSwapStep("{\"s\":\"" + sid + "\",\"step\":\"cancel\",\"why\":5}", st, err) && st.why.empty(),
                   "a cancel with a reason of the wrong type still cancels") ? 0 : 1;

    // A community post of that kind, before any signature is checked: the
    // frame is refused, and the thread reading it goes on.
    {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        nlohmann::json fr = { { "v", btfchat::FRAME_VERSION }, { "k", (int)btfchat::MSG_SWAP_OFFER }, { "from", "x" },
                              { "t", 1 }, { "id", std::string(32, 'c') }, { "g", "community" },
                              { "text", badOffers[0] }, { "sig", "" } };
        btfchat::Frame f;
        bool fThrew = false, fOpened = true;
        try { fOpened = btfchat::OpenFrame(ctx, fr.dump(), f, err); }
        catch (...) { fThrew = true; }
        nFail += Check(!fThrew && !fOpened, "a frame carrying such an offer is refused without throwing") ? 0 : 1;
        fr["k"] = (int)btfchat::MSG_SWAP;
        fr["g"] = "";
        fr["text"] = badSteps[0];
        fThrew = false; fOpened = true;
        try { fOpened = btfchat::OpenFrame(ctx, fr.dump(), f, err); }
        catch (...) { fThrew = true; }
        nFail += Check(!fThrew && !fOpened, "and so is a direct step of that shape") ? 0 : 1;
        secp256k1_context_destroy(ctx);
    }

    // Floors: no contract that costs more to spend than it holds.
    o = btfchat::SwapOffer();
    o.give = "BTF"; o.giveAmount = 5; o.want = "BTC"; o.wantAmount = 100000;
    nFail += Check(!btfchat::ParseSwapOffer(btfchat::FormatSwapOffer(o), o, err), "5 satoshis of BTF is not an offer") ? 0 : 1;
    o.give = "BTF"; o.giveAmount = COIN; o.want = "BTC"; o.wantAmount = 100;
    nFail += Check(!btfchat::ParseSwapOffer(btfchat::FormatSwapOffer(o), o, err), "nor is 100 satoshis of Bitcoin") ? 0 : 1;
    o.give = "BTF"; o.giveAmount = COIN; o.want = "BTC"; o.wantAmount = 100000;
    nFail += Check(btfchat::ParseSwapOffer(btfchat::FormatSwapOffer(o), o, err), "1 BTF for 0.001 BTC is") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=swap-engine -- the engine's side of the fixes, against a wallet
// stand-in: a lock that gave no answer is found, never made twice (H2); a
// refund is over only in a block, and bumped (M2); a maker whose redeem lost
// the race refunds its own (M3); their contract's lock is read before any
// chain is asked (M1, H1); a coinbase or a height lock is refused (L2, H1); a
// taker giving BTF waits out a crawling chain (H1); a destination is checked
// (L5); and nothing is locked while the store cannot be saved (M5).
namespace
{
struct EngineHost : public btfchat::SwapHost
{
    std::map<std::string, nlohmann::json> answers;   // method -> its answer; absent: an error
    std::map<std::string, std::string> errors;       // method -> the error it gives
    std::vector<std::pair<std::string, nlohmann::json> > calls;
    std::vector<std::string> steps;
    std::vector<btfchat::LogEntry> convo;            // what "them" sent
    bool fSaveOk = true;
    btfchat::SwapEngine* pEngine = NULL;             // to read back what a save wrote
    std::string lastSaved, savedAtLock;

    std::string MyAddress() { return "me"; }
    bool PeerAccepted(const std::string&) { return true; }
    bool Invite(const std::string&, const std::string&, std::string&) { return true; }
    bool SendStep(const std::string&, const std::string& text, std::string&) { steps.push_back(text); return true; }
    void Contacts(std::vector<std::string>& out) { out.assign(1, "them"); }
    void Conversation(const std::string&, std::vector<btfchat::LogEntry>& out) { out = convo; }
    bool fUnlockedChat = true;                       // false: the chat is locked and every conversation reads back empty
    bool Unlocked() { return fUnlockedChat; }
    bool fHaveOffer = false;                         // an offer of ours any take names
    btfchat::SwapOffer myOffer;
    bool FindMyOffer(const std::string&, btfchat::SwapOffer& out) { if (!fHaveOffer) return false; out = myOffer; return true; }
    bool Wallet(const std::string& method, const nlohmann::json& params, nlohmann::json& r, std::string& err)
    {
        calls.push_back(std::make_pair(method, params));
        if (method == "swapinitiate" || method == "swapparticipate" || method == "coininitiate" || method == "coinparticipate")
            savedAtLock = lastSaved;
        if (errors.count(method)) { err = errors[method]; return false; }
        if (!answers.count(method)) { err = "not in this test: " + method; return false; }
        r = answers[method];
        return true;
    }
    bool Changed()
    {
        if (fSaveOk && pEngine)
            lastSaved = pEngine->ToJson();
        return fSaveOk;
    }
    int Count(const std::string& method) const
    {
        int n = 0;
        for (size_t i = 0; i < calls.size(); i++)
            if (calls[i].first == method)
                n++;
        return n;
    }
    nlohmann::json Last(const std::string& method) const
    {
        for (size_t i = calls.size(); i-- > 0; )
            if (calls[i].first == method)
                return calls[i].second;
        return nlohmann::json();
    }
};

static std::string EngineState(const nlohmann::json& sw)
{
    return nlohmann::json{ { "swaps", nlohmann::json::array({ sw }) }, { "seen", nlohmann::json::array() } }.dump();
}

static btfchat::SwapView EngineView(btfchat::SwapEngine& e)
{
    std::vector<btfchat::SwapView> v;
    e.List(v);
    return v.empty() ? btfchat::SwapView() : v[0];
}
} // namespace

static int RunSwapEngineSelfTest()
{
    printf("swap-engine self-test\n");
    int nFail = 0;
    const std::string id(32, '1'), hash(64, 'c'), secret(64, 'a');
    int64_t nNow = GetTime();

    // ---- H1 / M1: their lock is read from the contract before any audit
    {
        // The maker gives BTF; its contract is locked by height (an older version).
        swap::Contract c;
        c.recipientPkh.assign(20, 0x11); c.refundPkh.assign(20, 0x22); c.secretHash = ParseHex(hash);
        c.nLockTime = 100000;
        CScript k = swap::BuildContract(c);
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", false }, { "give", "BTC" }, { "ga", 1000000 },
                              { "want", "BTF" }, { "wa", 100000000 }, { "myRecv", "Bmine" },
                              { "thC", HexStr(k.begin(), k.end(), false) }, { "thTx", std::string(64, '4') },
                              { "stage", (int)btfchat::SW_CHECKING_THEIRS }, { "created", nNow }, { "since", nNow } };
        EngineHost h;
        h.answers["swapauditcontract"] = { { "recipientIsMine", true }, { "recipient", "Bmine" }, { "secretHash", hash },
                                           { "unspent", true }, { "confirmations", 40 }, { "amount", 1.0 },
                                           { "lockIsHeight", true }, { "blocksUntilRefund", 1400 } };
        btfchat::SwapEngine e(&h);
        e.FromJson(EngineState(sw));
        e.Round();
        btfchat::SwapView v = EngineView(e);
        nFail += Check(v.stage == btfchat::SW_CANCELLED && h.Count("swapauditcontract") == 0,
                       "a Bitflash contract locked by height is refused, before its chain is even asked") ? 0 : 1;

        // A time lock far in the past: a light client would rescan from its anchor.
        c.nLockTime = (int64_t)LOCKTIME_THRESHOLD + 1;
        k = swap::BuildContract(c);
        sw["thC"] = HexStr(k.begin(), k.end(), false);
        sw["give"] = "BTF"; sw["want"] = "LTC"; sw["wa"] = 200000000; sw["myRecv"] = "Lmine";
        EngineHost h2;
        btfchat::SwapEngine e2(&h2);
        e2.FromJson(EngineState(sw));
        e2.Round();
        v = EngineView(e2);
        nFail += Check(v.stage == btfchat::SW_CANCELLED && h2.Count("coinauditcontract") == 0,
                       "a lock time long past is refused without an audit that would rescan the other chain") ? 0 : 1;

        // A good time lock, paid by a coinbase.
        c.nLockTime = nNow + 47 * 3600;
        k = swap::BuildContract(c);
        sw["thC"] = HexStr(k.begin(), k.end(), false);
        EngineHost h3;
        h3.answers["coinauditcontract"] = { { "recipientIsMine", true }, { "recipient", "Lmine" }, { "secretHash", hash },
                                            { "unspent", true }, { "confirmations", 40 }, { "amount", 2.0 },
                                            { "secondsUntilRefund", 47 * 3600 }, { "coinbase", true } };
        btfchat::SwapEngine e3(&h3);
        e3.FromJson(EngineState(sw));
        e3.Round();
        v = EngineView(e3);
        nFail += Check(v.stage == btfchat::SW_CANCELLED && v.status.find("coinbase") != std::string::npos,
                       "a contract paid by a coinbase is refused") ? 0 : 1;
        h3.answers["coinauditcontract"]["coinbase"] = false;
        btfchat::SwapEngine e4(&h3);
        e4.FromJson(EngineState(sw));
        e4.Round();
        v = EngineView(e4);
        nFail += Check(v.stage == btfchat::SW_READY_TO_LOCK, "the same contract paid normally checks out") ? 0 : 1;

        // ---- H1: the taker gives BTF; the Bitflash chain crawls.
        h3.answers["coinswapinfo"] = { { "backend", "core" } };
        h3.answers["getinfo"] = { { "mediantime", nNow - 2 * 3600 } };
        h3.answers["swapparticipate"] = { { "contract", "aa" }, { "contractTxid", std::string(64, '9') },
                                          { "secretHash", hash } };
        std::string err;
        e4.Approve(id, err);
        e4.Round();
        v = EngineView(e4);
        nFail += Check(h3.Count("swapparticipate") == 0 && v.stage == btfchat::SW_READY_TO_LOCK &&
                       v.status.find("slow") != std::string::npos,
                       "a taker giving BTF does not lock while the chain's median time is two hours behind") ? 0 : 1;
        h3.answers["getinfo"] = { { "mediantime", nNow - 600 } };
        h3.fSaveOk = false;
        e4.Round();
        nFail += Check(h3.Count("swapparticipate") == 0, "nor while the chat store cannot be saved") ? 0 : 1;
        h3.fSaveOk = true;
        e4.Round();
        v = EngineView(e4);
        nlohmann::json p = h3.Last("swapparticipate");
        nFail += Check(h3.Count("swapparticipate") == 1 && v.stage == btfchat::SW_LOCKED,
                       "with the chain at its pace and the store saved, it locks") ? 0 : 1;
        nFail += Check(p.is_array() && p.size() == 5 && p[3].is_null() && p[4] == id,
                       "the standard lock, named in the wallet's journal by the swap's id") ? 0 : 1;
    }

    // ---- H2: a lock call that gives no answer
    {
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", true }, { "give", "BTF" }, { "ga", 100000000 },
                              { "want", "LTC" }, { "wa", 200000000 }, { "theirRecv", "Btheirs" }, { "myRecv", "Lmine" },
                              { "stage", (int)btfchat::SW_TAKE_RECEIVED }, { "ok", true }, { "created", nNow } };
        EngineHost h;
        h.answers["coinswapinfo"] = { { "backend", "core" } };
        h.errors["swapinitiate"] = "the wallet is not answering on 127.0.0.1:18432";
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        e.FromJson(EngineState(sw));
        e.Round();
        btfchat::SwapView v = EngineView(e);
        nFail += Check(h.savedAtLock.find("\"lockTried\":true") != std::string::npos,
                       "the store said a lock was under way before the wallet was asked for it") ? 0 : 1;
        // Their cancel arrives while nobody knows whether ours was paid.
        {
            btfchat::LogEntry le;
            le.from = "them"; le.kind = btfchat::MSG_SWAP; le.id = std::string(32, '7'); le.outgoing = false;
            le.text = "{\"s\":\"" + id + "\",\"step\":\"cancel\",\"why\":\"no lock1\"}";
            h.convo.push_back(le);
            h.answers["swaplookup"] = { { "state", "intent" } };
            e.Round();
            h.convo.clear();
            v = EngineView(e);
            nFail += Check(v.stage == btfchat::SW_TAKE_RECEIVED,
                           "a cancel from them does not end a swap whose lock is still unresolved") ? 0 : 1;
            h.answers.erase("swaplookup");
        }
        std::string err;
        nFail += Check(h.Count("swapinitiate") == 1 && !v.fCanCancel && !e.Cancel(id, err),
                       "no answer to the lock: the swap cannot be called off while that is unknown") ? 0 : 1;
        nlohmann::json p = h.Last("swapinitiate");
        nFail += Check(p.is_array() && p.size() == 4 && p[3] == id, "the lock was asked for under the swap's id") ? 0 : 1;
        h.errors.clear();
        h.answers["swaplookup"] = { { "state", "funded" }, { "contract", "bb" }, { "contractTxid", std::string(64, '8') },
                                    { "secret", secret }, { "secretHash", hash } };
        e.Round();
        e.FromJson(e.ToJson());
        v = EngineView(e);
        nFail += Check(v.stage == btfchat::SW_LOCKED && v.myTxid == std::string(64, '8') && h.Count("swapinitiate") == 1,
                       "the journal says it was paid: that lock is the swap's, and no second one is made") ? 0 : 1;
        nFail += Check(e.ToJson().find(secret) != std::string::npos, "with its secret kept") ? 0 : 1;

        EngineHost h2;
        h2.answers["coinswapinfo"] = { { "backend", "core" } };
        h2.errors["swapinitiate"] = "send failed: insufficient balance once the fee is counted";
        btfchat::SwapEngine e2(&h2);
        e2.FromJson(EngineState(sw));
        e2.Round();
        h2.answers["swaplookup"] = { { "state", "failed" } };
        e2.Round();
        v = EngineView(e2);
        nFail += Check(v.fCanCancel && e2.Cancel(id, err), "the journal says nothing went out: it can be called off") ? 0 : 1;

        EngineHost h3;
        h3.answers["coinswapinfo"] = { { "backend", "core" } };
        h3.fSaveOk = false;
        btfchat::SwapEngine e3(&h3);
        e3.FromJson(EngineState(sw));
        e3.Round();
        v = EngineView(e3);
        nFail += Check(h3.Count("swapinitiate") == 0 && v.status.find("cannot be saved") != std::string::npos,
                       "no lock while the chat store cannot be saved") ? 0 : 1;
    }

    // ---- M2: a light refund is over in a block, and sent again with a higher fee
    {
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", false }, { "give", "BTC" }, { "ga", 1000000 },
                              { "want", "BTF" }, { "wa", 100000000 }, { "btcDestination", "bcrt1qdestination" },
                              { "hash", hash }, { "myC", "33" }, { "myTx", std::string(64, '3') }, { "myN", 1 },
                              { "thC", "44" }, { "thTx", std::string(64, '4') },
                              { "stage", (int)btfchat::SW_LOCKED }, { "ok", true }, { "sent", true }, { "created", nNow } };
        EngineHost h;
        h.answers["btcfindsecret"] = { { "spent", false } };
        h.answers["btcauditcontract"] = { { "unspent", true }, { "secondsUntilRefund", 0 } };
        h.answers["btcrefund"] = { { "txid", std::string(64, 'f') }, { "feeRatePerKvB", 0.0001 }, { "awaitingConfirmation", true } };
        btfchat::SwapEngine e(&h);
        e.FromJson(EngineState(sw));
        e.Round();
        e.Round();
        btfchat::SwapView v = EngineView(e);
        nFail += Check(h.Count("btcrefund") == 1 && v.stage == btfchat::SW_REFUNDING,
                       "a light refund sent is not the end, and not sent twice within the hour") ? 0 : 1;
        btfchat::SwapConfig quick;
        quick.nRedeemBumpAfter = 0;
        btfchat::SwapEngine e2(&h, quick);
        e2.FromJson(e.ToJson());
        e2.Round();
        nlohmann::json p = h.Last("btcrefund");
        nFail += Check(h.Count("btcrefund") == 2 && p.size() == 4 && p[3] == "0.00020000",
                       "still in no block: sent again at twice the fee rate") ? 0 : 1;
        h.answers["btcfindsecret"] = { { "spent", true }, { "secret", secret } };
        e2.Round();
        v = EngineView(e2);
        nFail += Check(v.stage == btfchat::SW_REDEEMING, "outbid by their redeem: the secret is ours, theirs is taken") ? 0 : 1;

        btfchat::SwapEngine e3(&h);
        e3.FromJson(e.ToJson());
        h.answers["btcfindsecret"] = { { "spent", true }, { "refunded", true }, { "confirmed", true }, { "spendConfirmations", 1 } };
        h.answers["swapauditcontract"] = { { "unspent", true }, { "secondsUntilRefund", 3600 } };
        e3.Round();
        v = EngineView(e3);
        nFail += Check(v.stage == btfchat::SW_REFUNDING, "our refund one block deep: still watching for the secret") ? 0 : 1;
        h.answers["btcfindsecret"]["spendConfirmations"] = 2;
        e3.Round();
        v = EngineView(e3);
        nFail += Check(v.stage == btfchat::SW_REFUNDING, "deep enough, but their lock still runs: still watching") ? 0 : 1;
        h.answers["swapauditcontract"] = { { "unspent", true }, { "secondsUntilRefund", 0 } };
        e3.Round();
        v = EngineView(e3);
        nFail += Check(v.stage == btfchat::SW_REFUNDED, "deep enough and their lock open: refunded") ? 0 : 1;
    }

    // ---- M3: a maker whose redeem lost the race refunds its own
    {
        swap::Contract c;
        c.recipientPkh.assign(20, 0x11); c.refundPkh.assign(20, 0x22); c.secretHash = ParseHex(hash);
        c.nLockTime = nNow + 6 * 3600;
        CScript k = swap::BuildContract(c);
        std::string theirs = HexStr(k.begin(), k.end(), false);
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", true }, { "give", "BTF" }, { "ga", 100000000 },
                              { "want", "BTC" }, { "wa", 1000000 }, { "btcDestination", "bcrt1qdestination" },
                              { "secret", secret }, { "hash", hash }, { "myC", "22" }, { "myTx", std::string(64, '2') },
                              { "thC", theirs }, { "thTx", std::string(64, '1') }, { "thN", 0 },
                              { "stage", (int)btfchat::SW_REDEEMING }, { "rsince", nNow - 60 }, { "created", nNow } };
        EngineHost h;
        h.answers["btcfindsecret"] = { { "spent", true }, { "refunded", true }, { "confirmed", true } };
        h.answers["swapauditcontract"] = { { "unspent", true }, { "secondsUntilRefund", 3600 } };
        btfchat::SwapEngine e(&h);
        e.FromJson(EngineState(sw));
        e.Round();
        btfchat::SwapView v = EngineView(e);
        nFail += Check(v.stage == btfchat::SW_REFUNDING,
                       "their contract refunded under the maker's redeem: the maker goes on to refund its own, not FAILED") ? 0 : 1;
    }

    // ---- L5: the destination is checked by the wallet
    {
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", false }, { "give", "BTC" }, { "ga", 1000000 },
                              { "want", "BTF" }, { "wa", 100000000 }, { "stage", (int)btfchat::SW_TAKE_SENT }, { "created", nNow } };
        EngineHost h;
        btfchat::SwapEngine e(&h);
        e.FromJson(EngineState(sw));
        nFail += Check(!e.SetBitcoinDestination(id, "bc1q not an address"), "an address with spaces in it is not kept") ? 0 : 1;
        nFail += Check(e.SetBitcoinDestination(id, "bcrt1qdestination") && EngineView(e).btcDestination == "bcrt1qdestination",
                       "a plausible one is") ? 0 : 1;
        nFail += Check(h.Count("btcvalidatedestination") == 0, "without a wallet call that could freeze the screen") ? 0 : 1;
        // The round checks it with the wallet before anything is locked.
        nlohmann::json sw2 = sw;
        sw2["maker"] = true; sw2["stage"] = (int)btfchat::SW_TAKE_RECEIVED; sw2["ok"] = true;
        sw2["btcDestination"] = "bcrt1qwrongnetwork"; sw2["give"] = "BTF"; sw2["want"] = "BTC";
        sw2["ga"] = 100000000; sw2["wa"] = 1000000; sw2["myRecv"] = "mvMine";
        EngineHost h2;
        h2.answers["btcswapinfo"] = { { "backend", "light" } };
        h2.errors["btcvalidatedestination"] = "not an address of this network";
        btfchat::SwapEngine e2(&h2);
        e2.FromJson(EngineState(sw2));
        e2.Round();
        btfchat::SwapView v2 = EngineView(e2);
        nFail += Check(h2.Count("swapinitiate") == 0 && v2.fNeedsMe && v2.status.find("receiving address") != std::string::npos,
                       "an address the wallet refuses stops the lock, and the person is asked again") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=swap-prune -- what the chat swap engine keeps (review L4): one take
// of an offer at a time from a peer, and a few takes per peer in all; a swap
// that is over is dropped after a while, but never one that is not over and
// never a failed one that may hold a lock of ours; the step ids kept are the
// ones a conversation still holds.
static int RunSwapPruneSelfTest()
{
    printf("swap-prune self-test\n");
    int nFail = 0;
    int64_t nNow = GetTime();

    btfchat::SwapOffer o;
    o.give = "BTC"; o.giveAmount = 100000; o.want = "BTF"; o.wantAmount = COIN;
    const std::string offerA(32, 'a'), offerB(32, 'b');

    auto TakeStep = [&](int n, const std::string& offer) {
        btfchat::SwapStep st;
        st.swap = strprintf("%032x", n);
        st.step = "take";
        st.offer = offer;
        st.terms = o;
        st.to = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        btfchat::LogEntry le;
        le.from = "them"; le.kind = btfchat::MSG_SWAP; le.outgoing = false;
        le.id = strprintf("%032x", 0x1000 + n);
        le.sent = GetTime();
        le.text = btfchat::FormatSwapStep(st);
        return le;
    };
    {
        btfchat::SwapStep chk;
        std::string err;
        nFail += Check(btfchat::ParseSwapStep(TakeStep(1, offerA).text, chk, err), "the take used here is a good one") ? 0 : 1;
    }

    auto Count = [](btfchat::SwapEngine& e, int stage) {
        std::vector<btfchat::SwapView> v;
        e.List(v);
        int n = 0;
        for (size_t i = 0; i < v.size(); i++)
            if (stage < 0 || v[i].stage == stage)
                n++;
        return n;
    };

    // ---- one take of an offer at a time, a few per peer
    {
        EngineHost h;
        h.fHaveOffer = true;
        h.myOffer = o;
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        for (int i = 1; i <= 20; i++)
            h.convo.push_back(TakeStep(i, offerA));
        e.Round();
        nFail += Check(Count(e, -1) == 1 && Count(e, btfchat::SW_TAKE_RECEIVED) == 1,
                       "twenty takes of one offer with twenty swap ids make one swap") ? 0 : 1;
        h.convo.clear();
        for (int i = 21; i <= 60; i++)
            h.convo.push_back(TakeStep(i, strprintf("%032x", 0x2000 + i)));
        e.Round();
        nFail += Check(Count(e, -1) == 8, "and takes of forty other offers make seven more, eight in all") ? 0 : 1;
        // The same ids again, from the conversation, are not read twice.
        int nBefore = Count(e, -1);
        e.Round();
        nFail += Check(Count(e, -1) == nBefore, "a step read once is not read again") ? 0 : 1;
    }

    // ---- finished swaps are dropped after their time, the open and the failed-with-a-lock are not
    {
        EngineHost h;
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        const int64_t nOld = nNow - 40 * 24 * 3600;
        nlohmann::json arr = nlohmann::json::array();
        auto Sw = [&](int n, int stage, int64_t nUpdated, const char* contract) {
            nlohmann::json sw = { { "id", strprintf("%032x", n) }, { "peer", "them" }, { "maker", true }, { "give", "BTF" },
                                  { "ga", 100000000 }, { "want", "LTC" }, { "wa", 200000000 }, { "stage", stage },
                                  { "created", nUpdated }, { "updated", nUpdated } };
            if (contract[0])
                sw["myC"] = contract;
            return sw;
        };
        arr.push_back(Sw(1, btfchat::SW_DONE, nOld, ""));
        arr.push_back(Sw(2, btfchat::SW_CANCELLED, nOld, ""));
        arr.push_back(Sw(3, btfchat::SW_REFUNDED, nOld, ""));
        arr.push_back(Sw(4, btfchat::SW_FAILED, nOld, ""));
        arr.push_back(Sw(5, btfchat::SW_FAILED, nNow - 5 * 24 * 3600, "aabb"));
        arr.push_back(Sw(6, btfchat::SW_DONE, nNow - 3600, ""));
        arr.push_back(Sw(7, btfchat::SW_LOCKED, nOld, "aabb"));
        arr.push_back(Sw(8, btfchat::SW_TAKE_RECEIVED, nOld, ""));
        arr.push_back(Sw(9, btfchat::SW_DONE, nOld, "aabb"));
        e.FromJson(nlohmann::json{ { "swaps", arr }, { "seen", nlohmann::json::array({ "gone", "also-gone" }) } }.dump());
        {
            btfchat::LogEntry le;           // a conversation that can be read: something in it
            le.from = "them"; le.kind = btfchat::MSG_SWAP; le.outgoing = false; le.sent = nNow;
            le.id = std::string(32, '9');
            le.text = "{\"s\":\"" + std::string(32, '5') + "\",\"step\":\"cancel\"}";
            h.convo.push_back(le);
        }
        nFail += Check(Count(e, -1) == 9, "nine swaps loaded") ? 0 : 1;
        e.Round();
        std::vector<btfchat::SwapView> v;
        e.List(v);
        std::set<std::string> kept;
        for (size_t i = 0; i < v.size(); i++)
            kept.insert(v[i].id);
        nFail += Check(!kept.count(strprintf("%032x", 1)) && !kept.count(strprintf("%032x", 2)) &&
                       !kept.count(strprintf("%032x", 3)) && !kept.count(strprintf("%032x", 4)) &&
                       !kept.count(strprintf("%032x", 9)),
                       "swaps that finished long ago are dropped, those with a lock of ours only after the 30 days too") ? 0 : 1;
        nFail += Check(kept.count(strprintf("%032x", 5)) && kept.count(strprintf("%032x", 6)) &&
                       kept.count(strprintf("%032x", 7)) && kept.count(strprintf("%032x", 8)),
                       "a recent one, one that failed with a lock of ours a few days ago, and the ones not over are kept") ? 0 : 1;
        nFail += Check(e.ToJson().find("gone") == std::string::npos,
                       "step ids no conversation holds are forgotten") ? 0 : 1;
    }

    // ---- no more finished swaps kept than the limit
    {
        EngineHost h;
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        nlohmann::json arr = nlohmann::json::array();
        for (int n = 1; n <= 130; n++)
            arr.push_back({ { "id", strprintf("%032x", n) }, { "peer", "them" }, { "maker", true }, { "give", "BTF" },
                            { "ga", 100000000 }, { "want", "LTC" }, { "wa", 200000000 },
                            { "stage", (int)btfchat::SW_DONE }, { "created", nNow - 1000 - n }, { "updated", nNow - 1000 - n } });
        e.FromJson(nlohmann::json{ { "swaps", arr }, { "seen", nlohmann::json::array() } }.dump());
        e.Round();
        std::vector<btfchat::SwapView> v;
        e.List(v);
        bool fNewest = false, fOldest = false;
        for (size_t i = 0; i < v.size(); i++)
        {
            if (v[i].id == strprintf("%032x", 1)) fNewest = true;
            if (v[i].id == strprintf("%032x", 130)) fOldest = true;
        }
        nFail += Check(v.size() == 100 && fNewest && !fOldest,
                       "a hundred and thirty finished swaps become the newest hundred") ? 0 : 1;
    }

    // ---- a swap with a lock of ours is not counted out
    {
        EngineHost h;
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        nlohmann::json arr = nlohmann::json::array();
        for (int n = 1; n <= 260; n++)
        {
            nlohmann::json sw = { { "id", strprintf("%032x", n) }, { "peer", "them" }, { "maker", true }, { "give", "BTF" },
                                  { "ga", 100000000 }, { "want", "LTC" }, { "wa", 200000000 },
                                  { "stage", (int)btfchat::SW_DONE }, { "created", nNow - 1000 - n }, { "updated", nNow - 1000 - n } };
            if (n % 2 == 0)
                sw["myC"] = "aabb";             // had a contract: done, and a redeem that may be unconfirmed
            arr.push_back(sw);
        }
        e.FromJson(nlohmann::json{ { "swaps", arr }, { "seen", nlohmann::json::array() } }.dump());
        e.Round();
        std::vector<btfchat::SwapView> v;
        e.List(v);
        int nWithLock = 0, nWithout = 0;
        for (size_t i = 0; i < v.size(); i++)
        {
            int n = (int)strtol(v[i].id.c_str(), NULL, 16);
            (n % 2 == 0 ? nWithLock : nWithout)++;
        }
        nFail += Check(nWithLock == 130 && nWithout == 100,
                       "the count limit takes the oldest of those that never locked; all 130 that had a contract stay") ? 0 : 1;
    }

    // ---- the step ids are kept while a conversation cannot be read, and an old take is not news
    {
        EngineHost h;
        h.fHaveOffer = true;
        h.myOffer = o;
        btfchat::SwapEngine e(&h);
        h.pEngine = &e;
        h.convo.push_back(TakeStep(1, offerA));
        e.Round();
        nFail += Check(Count(e, -1) == 1 && e.ToJson().find(TakeStep(1, offerA).id) != std::string::npos,
                       "a take is read and its step id kept") ? 0 : 1;
        h.convo.clear();                       // the chat is locked: the conversation comes back empty
        h.fUnlockedChat = false;
        e.Round();
        h.fUnlockedChat = true;
        nFail += Check(e.ToJson().find(TakeStep(1, offerA).id) != std::string::npos,
                       "a locked chat does not make the engine forget what it has read") ? 0 : 1;
        h.convo.push_back(TakeStep(2, offerB));
        e.Round();
        h.convo[0].sent = nNow - 3 * 24 * 3600;
        h.convo[0].id = strprintf("%032x", 0x5000);
        h.convo[0].text = btfchat::FormatSwapStep([&] { btfchat::SwapStep st; st.swap = strprintf("%032x", 77); st.step = "take";
                                                       st.offer = std::string(32, 'c'); st.terms = o; st.to = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"; return st; }());
        int nBefore = Count(e, -1);
        e.Round();
        nFail += Check(Count(e, -1) == nBefore, "a take three days old, long past answering, makes no swap") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=chat-store-save -- the chat store is replaced in one step, private,
// a failed save is reported and leaves the old store, and a store left only as
// btfchat.dat.new by an older version's interrupted save is read (M5).
static int RunChatStoreSaveSelfTest()
{
    printf("chat-store-save self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    strSetDataDir = tmp;
    if (!LoadWallet())
    {
        printf("LoadWallet failed\n");
        return 1;
    }
    std::string err;
    nFail += Check(SetHDSeedFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", err),
                   "a phrase installs") ? 0 : 1;
    nFail += Check(btfchat::ChatUnlock("senha-bem-comprida", err), "the chat opens") ? 0 : 1;
    std::string strAddr = btfchat::ChatAddress();
    std::string strFile = btfchat::ChatStorePath();
    nFail += Check(btfchat::ChatSaveStore(&err) && !SwapTestReadFile(strFile).empty() && !FileExists((strFile + ".new").c_str()),
                   "a save puts the store in place, nothing left beside it") ? 0 : 1;
#ifndef _WIN32
    struct stat st;
    nFail += Check(stat(strFile.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "and only its owner can read it") ? 0 : 1;
#endif
    std::string strBefore = SwapTestReadFile(strFile);
    std::string blocker = strFile + ".new";
#ifdef _WIN32
    CreateDirectoryA(blocker.c_str(), NULL);
#else
    mkdir(blocker.c_str(), 0700);
#endif
    err.clear();
    nFail += Check(!btfchat::ChatSaveStore(&err) && !err.empty(), "a save that cannot be written says so") ? 0 : 1;
    nFail += Check(SwapTestReadFile(strFile) == strBefore, "and the store on the disk is left as it was") ? 0 : 1;
#ifdef _WIN32
    RemoveDirectoryA(blocker.c_str());
#else
    rmdir(blocker.c_str());
#endif
    nFail += Check(btfchat::ChatSaveStore(&err), "once it can be written, it saves again") ? 0 : 1;
    btfchat::ChatLock();

    // What an interrupted save of an older version left: only the new copy.
    std::string strStore = SwapTestReadFile(strFile);
    remove(strFile.c_str());
    WriteFileAtomicPrivate(strFile + ".new", strStore, err);
    nFail += Check(btfchat::ChatUnlock("senha-bem-comprida", err) && btfchat::ChatAddress() == strAddr,
                   "a store left only as btfchat.dat.new opens") ? 0 : 1;
    btfchat::ChatLock();
    nFail += Check(!btfchat::ChatSaveStore(&err) && err.find("locked") != std::string::npos,
                   "a locked chat saves nothing, and says why") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=wallet-final -- a transaction with a unix-time nLockTime (a
// time-locked refund, an atomic swap's) is counted and spent by the wallet
// once a block holds it. The 0.1.0 rule (nLockTime < nBestHeight) never
// called it final, and such a refund vanished from balance and coin choice.
static int RunWalletFinalSelfTest()
{
    printf("wallet-final self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    strSetDataDir = tmp;
    if (!LoadWallet())
    {
        printf("LoadWallet failed\n");
        return 1;
    }
    std::vector<unsigned char> vchKey = GetKeyFromPool();
    nFail += Check(!vchKey.empty(), "a key of this wallet") ? 0 : 1;
    CScript script;
    script << vchKey << OP_CHECKSIG;

    // A refund: input non-final (nSequence 0), nLockTime a unix time.
    CWalletTx wtx;
    wtx.vin.resize(1);
    wtx.vin[0].prevout = COutPoint(uint256(4242), 0);
    wtx.vin[0].nSequence = 0;
    wtx.vout.push_back(CTxOut(5 * COIN, script));
    wtx.nLockTime = 1800000000;

    // A block of the main chain that holds it (a one-transaction block:
    // the merkle root is the transaction's hash).
    CBlockIndex* pSavedBest = pindexBest;
    int nSavedHeight = nBestHeight;
    CBlockIndex* p = new CBlockIndex();
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(std::make_pair(uint256(777777), p)).first;
    p->phashBlock = &mi->first;
    p->nHeight = 10;
    p->nTime = 1700000000;      // its median time is before the lock
    p->hashMerkleRoot = wtx.GetHash();
    pindexBest = p;
    nBestHeight = 10;
    wtx.hashBlock = mi->first;
    wtx.nIndex = 0;

    nFail += Check(!wtx.IsFinal(), "the 0.1.0 rule calls a confirmed time-locked refund not final") ? 0 : 1;
    nFail += Check(wtx.GetDepthInMainChain() == 1 && wtx.IsFinalForWallet(), "in a block of the main chain it is final for the wallet") ? 0 : 1;
    uint256 hash = wtx.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
        mapWallet[hash] = wtx;
    nFail += Check(GetBalance() == 5 * COIN, "it counts in the balance") ? 0 : 1;
    std::set<CWalletTx*> coins;
    nFail += Check(SelectCoins(COIN, coins) && coins.size() == 1 && (*coins.begin())->GetHash() == hash,
                   "and coin selection spends it") ? 0 : 1;

    // Not in a block, and the next block's median time before the lock: not yet.
    CWalletTx loose = wtx;
    loose.hashBlock = 0;
    loose.nIndex = -1;
    nFail += Check(!loose.IsFinalForWallet(), "the same refund outside a block, before its lock, is not final yet") ? 0 : 1;
    CWalletTx plain = loose;
    plain.nLockTime = 0;
    nFail += Check(plain.IsFinalForWallet(), "an ordinary transaction is final as before") ? 0 : 1;

    CRITICAL_BLOCK(cs_mapWallet)
        mapWallet.erase(hash);
    mapBlockIndex.erase(mi);
    delete p;
    pindexBest = pSavedBest;
    nBestHeight = nSavedHeight;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// -selftest=swap-rpc -- the lock RPCs through the node's own JSON-RPC server,
// on a test network wallet with nothing in it: the lock is a time 48 or 18
// hours out, its intent (and the secret) is in swaps.log before the send that
// fails, a tag answers for its lock, and a journal that cannot be written
// stops the lock before anything is sent.
static int RunSwapRpcSelfTest()
{
    printf("swap-rpc self-test\n");
    int nFail = 0;
#ifdef _WIN32
    SelfTestWinsock wsa;
#endif
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("could not make a temp datadir\n");
        return 1;
    }
    SelectChainParams(true);       // swaps are open on the test network
    strSetDataDir = tmp;
    if (!LoadWallet())
    {
        printf("LoadWallet failed\n");
        return 1;
    }
    {
        // An empty transaction index, so a send gets as far as the wallet's
        // own refusal (no coins) instead of failing to open the database.
        CTxDB txdb("cr");
    }
    int nPort = FreeLoopbackPort();
    if (!JsonRpcConfigureCookie(strprintf("%d", nPort)) || _beginthread(ThreadJsonRpcServer, 0, NULL) == -1)
    {
        printf("could not start the RPC server\n");
        return 1;
    }
    Sleep(500);
    LoopbackRpc to;
    to.nPort = nPort;
    std::string err;
    if (!ReadRpcCookie(GetAppDir() + "/.cookie", to.strAuth, err))
    {
        printf("no cookie: %s\n", err.c_str());
        return 1;
    }
    auto call = [&](const std::string& method, const nlohmann::json& params, nlohmann::json& r, std::string& e) {
        return LoopbackRpcCall(to, method, params, r, e);
    };
    auto lines = [&]() {
        std::vector<nlohmann::json> v;
        std::string e;
        swap::JournalRead(v, e);
        return v;
    };
    nlohmann::json r;
    nlohmann::json addr;
    call("getnewaddress", nlohmann::json::array(), addr, err);
    nFail += Check(addr.is_string(), "a Bitflash address of the wallet") ? 0 : 1;

    // No chain yet, so rules v3 are not locked in: refused before anything
    // is made or written.
    bool fGuard = call("swapinitiate", nlohmann::json::array({ addr, "1", nullptr, "rpc-guard" }), r, err);
    std::vector<nlohmann::json> v0;
    std::string e0;
    swap::JournalRead(v0, e0);
    nFail += Check(!fGuard && err.find("rules v3 locked in") != std::string::npos && v0.empty(),
                   "before rules v3 are locked in by median time, no lock and no journal line") ? 0 : 1;
    // A tip whose median time is now: past the test network's switch.
    CBlockIndex* pTip = new CBlockIndex();
    std::map<uint256, CBlockIndex*>::iterator miTip = mapBlockIndex.insert(std::make_pair(uint256(888888), pTip)).first;
    pTip->phashBlock = &miTip->first;
    pTip->nHeight = 1;
    pTip->nTime = (unsigned int)GetTime();
    pindexBest = pTip;
    nBestHeight = 1;

    int64_t nNow = GetTime();
    bool fOk = call("swapinitiate", nlohmann::json::array({ addr, "1", nullptr, "rpc-t1" }), r, err);
    nFail += Check(!fOk && err.find("send failed") != std::string::npos, "an empty wallet cannot pay the lock") ? 0 : 1;
    if (fOk || err.find("send failed") == std::string::npos)
        printf("       (%s)\n", fOk ? "it was paid" : err.c_str());
    std::vector<nlohmann::json> v = lines();
    nlohmann::json intent, failed;
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].value("tag", "") == "rpc-t1")
            (v[i].value("state", "") == "intent" ? intent : failed) = v[i];
    nFail += Check(intent.is_object() && intent.value("secret", "").size() == 64 && intent.value("chain", "") == "btf",
                   "the intent, with the secret, was written before the send") ? 0 : 1;
    int64_t nLock = intent.value("lockTime", (int64_t)0);
    nFail += Check(nLock >= (int64_t)LOCKTIME_THRESHOLD && nLock >= nNow + swap::BTF_INITIATOR_LOCK_SECS - 3600 &&
                   nLock <= GetTime() + swap::BTF_INITIATOR_LOCK_SECS,
                   "the initiator's lock is a time, 48 hours out") ? 0 : 1;
    nFail += Check(failed.is_object() && failed.value("state", "") == "failed", "and the failed send is recorded after it") ? 0 : 1;
    nFail += Check(call("swaplookup", nlohmann::json::array({ "rpc-t1" }), r, err) && r.value("state", "") == "failed",
                   "swaplookup says nothing was paid") ? 0 : 1;
    nFail += Check(call("swaplookup", nlohmann::json::array({ "rpc-none" }), r, err) && r.value("state", "") == "none",
                   "and knows no lock under a tag never used") ? 0 : 1;
    fOk = call("swapinitiate", nlohmann::json::array({ addr, "2", nullptr, "rpc-t1" }), r, err);
    nFail += Check(!fOk && err.find("different swap lock") != std::string::npos,
                   "a tag already used names that lock only: other terms are refused") ? 0 : 1;

    std::string hash(64, 'c');
    fOk = call("swapparticipate", nlohmann::json::array({ addr, "1", hash, nullptr, "rpc-t2" }), r, err);
    v = lines();
    int64_t nLock2 = 0;
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].value("tag", "") == "rpc-t2" && v[i].value("state", "") == "intent")
            nLock2 = v[i].value("lockTime", (int64_t)0);
    nFail += Check(!fOk && nLock2 >= nNow + swap::BTF_PARTICIPANT_LOCK_SECS - 3600 && nLock2 <= GetTime() + swap::BTF_PARTICIPANT_LOCK_SECS,
                   "the participant's lock is a time, 18 hours out") ? 0 : 1;
    fOk = call("swapinitiate", nlohmann::json::array({ addr, "1", 600, "rpc-t4" }), r, err);
    v = lines();
    int64_t nLock4 = 0;
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].value("tag", "") == "rpc-t4" && v[i].value("state", "") == "intent")
            nLock4 = v[i].value("lockTime", (int64_t)0);
    nFail += Check(nLock4 >= nNow + 600 - 60 && nLock4 <= GetTime() + 600, "on the test network a shorter lock, in seconds") ? 0 : 1;

    // swaps.log cannot be replaced: refused before any send.
    std::string blocker = swap::JournalPath() + ".new";
#ifdef _WIN32
    CreateDirectoryA(blocker.c_str(), NULL);
#else
    mkdir(blocker.c_str(), 0700);
#endif
    fOk = call("swapinitiate", nlohmann::json::array({ addr, "1", nullptr, "rpc-t3" }), r, err);
    nFail += Check(!fOk && err.find("nothing was sent") != std::string::npos,
                   "a journal that cannot be written stops the lock before anything is sent") ? 0 : 1;
#ifdef _WIN32
    RemoveDirectoryA(blocker.c_str());
#else
    rmdir(blocker.c_str());
#endif
    v = lines();
    bool fT3 = false;
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].value("tag", "") == "rpc-t3")
            fT3 = true;
    nFail += Check(!fT3, "and nothing about that lock is in the journal") ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

#include "test_light_pow.h"

// One block of a made-up index, registered in mapBlockIndex under a hash that
// is just its number, with the work and checkpoint mark filled in the way
// AddToBlockIndex and the index load do it.
static CBlockIndex* ChainWorkTestBlock(CBlockIndex* pprev, unsigned int nBits, unsigned int nNumber,
                                       std::vector<CBlockIndex*>& vMade)
{
    CBlockIndex* pindex = new CBlockIndex();
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(uint256(nNumber), pindex)).first;
    pindex->phashBlock = &((*mi).first);
    pindex->pprev = pprev;
    pindex->nHeight = pprev ? pprev->nHeight + 1 : 0;
    pindex->nBits = nBits;
    SetChainWork(pindex);
    vMade.push_back(pindex);
    return pindex;
}

static int RunChainWorkSelfTest()
{
    fflush(stdout);
    printf("chain-work self-test\n");

    int nFail = 0;
    const unsigned int nFloor = 0x1f0fffff;   // the proof-of-work limit
    const unsigned int nHard  = 0x1f03ffff;   // four times as hard: one retarget up
    std::vector<CBlockIndex*> vMade;
    MapCheckpoints mapSaved;
    try
    {
        // The real tables first, before the test puts its own in their place.
        SelectChainParams(true);
        nFail += Check(mapCheckpoints.empty(), "testnet has no checkpoints") ? 0 : 1;
        SelectChainParams(false);
        nFail += Check(mapCheckpoints.size() == 1 && mapCheckpoints.count(68000) &&
                       mapCheckpoints[68000] == uint256("0xda46bdcfe661ddb61b8d27a1adc5c0fc30f6ad6a8f18f03fc9dc07a7e003bfc6"),
                       "mainnet checkpoint at height 68000 is pinned") ? 0 : 1;
        nFail += Check(mapCheckpoints.begin()->first > 0 && mapCheckpoints.count(0) == 0,
                       "no checkpoint sits on the genesis block") ? 0 : 1;
        mapSaved = mapCheckpoints;
        mapCheckpoints.clear();

        // Work of one block.
        nFail += Check(GetBlockWork(nFloor) == uint256(4096), "a block at the floor is worth 4096 hashes") ? 0 : 1;
        nFail += Check(GetBlockWork(nHard) == uint256(16384), "a block four times as hard is worth 16384") ? 0 : 1;
        nFail += Check(GetBlockWork(0x1d00ffff) == uint256((uint64)0x100010001ULL),
                       "Bitcoin's difficulty 1 is worth 0x100010001, as in Bitcoin") ? 0 : 1;
        nFail += Check(GetBlockWork(0) == uint256(0) && GetBlockWork(0x1f8fffff) == uint256(0),
                       "a zero or negative target is worth nothing") ? 0 : 1;
        nFail += Check(GetBlockWork(0x01010000) > GetBlockWork(0x02010000) && GetBlockWork(0x01010000) > uint256(0),
                       "the smallest target does not overflow") ? 0 : 1;
        nFail += Check(ChainWorkToString(uint256(4096)) == "1000" && ChainWorkToString(uint256(0)) == "0",
                       "work prints as hex without leading zeros") ? 0 : 1;

        // Two branches off one block. A is longer. B is shorter and went
        // through a retarget, so it holds more work.
        CBlockIndex* proot = ChainWorkTestBlock(NULL, nFloor, 1000, vMade);
        CBlockIndex* pa = proot;
        for (int i = 1; i <= 40; i++)
            pa = ChainWorkTestBlock(pa, nFloor, 1000 + i, vMade);
        CBlockIndex* pb = proot;
        for (int i = 1; i <= 30; i++)
            pb = ChainWorkTestBlock(pb, nFloor, 2000 + i, vMade);
        for (int i = 31; i <= 35; i++)
            pb = ChainWorkTestBlock(pb, nHard, 2000 + i, vMade);
        // A second branch with exactly A's work, seen after it.
        CBlockIndex* pc = proot;
        for (int i = 1; i <= 40; i++)
            pc = ChainWorkTestBlock(pc, nFloor, 3000 + i, vMade);

        nFail += Check(proot->nChainWork == uint256(4096) && pa->nChainWork == uint256(41 * 4096) &&
                       pb->nChainWork == uint256(31 * 4096 + 5 * 16384),
                       "work adds up along a branch") ? 0 : 1;
        nFail += Check(pa->nHeight == 40 && pb->nHeight == 35 && pb->nChainWork > pa->nChainWork,
                       "the test has a shorter branch with more work") ? 0 : 1;
        nFail += Check(IsBetterChain(pb, pa), "the shorter branch with more work is the better chain") ? 0 : 1;
        nFail += Check(!IsBetterChain(pa, pb), "the longer branch with less work is not") ? 0 : 1;
        nFail += Check(!IsBetterChain(pc, pa) && !IsBetterChain(pa, pc),
                       "equal work does not replace the chain seen first") ? 0 : 1;
        nFail += Check(IsBetterChain(proot, NULL) && !IsBetterChain(NULL, proot) && !IsBetterChain(pa, pa),
                       "anything beats no chain, and a chain does not beat itself") ? 0 : 1;
        CBlockIndex* pa41 = ChainWorkTestBlock(pa, nFloor, 1041, vMade);
        nFail += Check(IsBetterChain(pa41, pa) && !IsBetterChain(pa41, pb),
                       "one more block wins over its parent, not over a heavier branch") ? 0 : 1;

        // Checkpoints. The main branch M is blocks 101..110 at heights 1..10
        // on top of a new root; the checkpoint is its block at height 5.
        mapCheckpoints[5] = uint256(105);
        CBlockIndex* pm = ChainWorkTestBlock(NULL, nFloor, 100, vMade);
        CBlockIndex* pm2 = NULL;
        CBlockIndex* pm4 = NULL;
        for (int i = 1; i <= 4; i++)
        {
            pm = ChainWorkTestBlock(pm, nFloor, 100 + i, vMade);
            if (i == 2) pm2 = pm;
            if (i == 4) pm4 = pm;
        }
        const char* pszWhy = NULL;
        int nScore = -1;
        nFail += Check(LastCheckpointInIndex() == NULL, "the checkpoint block is not here yet") ? 0 : 1;
        nFail += Check(CheckpointsAllow(pm4, uint256(105), &pszWhy, &nScore) && pszWhy == NULL && nScore == 0,
                       "the checkpoint block is allowed at its height") ? 0 : 1;
        nFail += Check(!CheckpointsAllow(pm4, uint256(905), &pszWhy, &nScore) && pszWhy != NULL && nScore == 100,
                       "another block at the checkpoint height is refused, and its sender dropped") ? 0 : 1;
        nFail += Check(CheckpointsAllow(pm2, uint256(903)),
                       "a fork below a checkpoint this node does not have yet is still allowed") ? 0 : 1;

        CBlockIndex* pm5 = NULL;
        for (int i = 5; i <= 10; i++)
        {
            pm = ChainWorkTestBlock(pm, nFloor, 100 + i, vMade);
            if (i == 5) pm5 = pm;
        }
        nFail += Check(!pm->fOffCheckpoint && !pm5->fOffCheckpoint, "the branch through the checkpoint is not marked") ? 0 : 1;
        nFail += Check(LastCheckpointInIndex() == pm5, "the checkpoint block is found once it is here") ? 0 : 1;
        nFail += Check(CheckpointsAllow(pm, uint256(111)), "the next block of the best chain is allowed") ? 0 : 1;
        nFail += Check(CheckpointsAllow(pm5, uint256(906)), "a fork right above the checkpoint is allowed") ? 0 : 1;
        nFail += Check(!CheckpointsAllow(pm2, uint256(903), &pszWhy, &nScore) && pszWhy != NULL,
                       "a fork from below the checkpoint is refused now") ? 0 : 1;
        nFail += Check(nScore == CHECKPOINT_SCORE_OLD_FORK && nScore * 4 < 100 && nScore * 5 >= 100,
                       "its sender is kept for four such blocks and dropped at the fifth") ? 0 : 1;
        nFail += Check(!CheckpointsAllow(pm4, uint256(905)), "another block at the checkpoint height is still refused") ? 0 : 1;

        // An index that already holds a branch around the checkpoint, as one
        // written by an older build could: X leaves M at height 4 and is
        // heavier than M.
        CBlockIndex* px = pm4;
        for (int i = 5; i <= 8; i++)
            px = ChainWorkTestBlock(px, nHard, 200 + i, vMade);
        nFail += Check(px->fOffCheckpoint && px->pprev->fOffCheckpoint && !pm4->fOffCheckpoint,
                       "a branch with another block at the checkpoint height is marked from there on") ? 0 : 1;
        nFail += Check(px->nChainWork > pm->nChainWork && !IsBetterChain(px, pm),
                       "more work does not make that branch the better chain") ? 0 : 1;
        nFail += Check(IsBetterChain(pm, px), "a node on that branch takes the chain through the checkpoint") ? 0 : 1;
        nFail += Check(!CheckpointsAllow(px, uint256(209), &pszWhy, &nScore) && pszWhy != NULL && nScore == 100,
                       "nothing may be built on that branch") ? 0 : 1;
        nFail += Check(BackToCheckpoints(px) == pm4 && BackToCheckpoints(pm) == pm && BackToCheckpoints(NULL) == NULL,
                       "walking back from that branch stops at the block before it left") ? 0 : 1;
        nFail += Check(LastCheckpointInIndex() == pm5, "the marked branch does not hide the checkpoint block") ? 0 : 1;

        // No checkpoints, no opinion.
        mapCheckpoints.clear();
        nFail += Check(CheckpointsAllow(pm2, uint256(903)) && LastCheckpointInIndex() == NULL,
                       "with no checkpoints every fork is allowed") ? 0 : 1;

        // -benchcheckpoint=HEIGHT:HASH
        std::string strHash(64, 'a');
        nFail += Check(AddBenchCheckpoint("12:" + strHash) && mapCheckpoints.size() == 1 &&
                       mapCheckpoints[12] == uint256(strHash),
                       "a bench checkpoint is read as HEIGHT:HASH") ? 0 : 1;
        nFail += Check(!AddBenchCheckpoint("") && !AddBenchCheckpoint("12") && !AddBenchCheckpoint(":" + strHash) &&
                       !AddBenchCheckpoint("-1:" + strHash) && !AddBenchCheckpoint("x:" + strHash) &&
                       !AddBenchCheckpoint("12:abcd") && !AddBenchCheckpoint("12:" + std::string(64, 'g')) &&
                       mapCheckpoints.size() == 1,
                       "anything else is refused and adds nothing") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    for (size_t i = 0; i < vMade.size(); i++)
    {
        mapBlockIndex.erase(vMade[i]->GetBlockHash());
        delete vMade[i];
    }
    mapCheckpoints = mapSaved;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- rules v5 (docs/rules-v5.md)

// A block on pindexPrev for the rules-v5 bench chain: an anyone-can-spend
// coinbase that starts with the height (BIP34), then vtx, at the nBits the
// chain asks for. No proof of work: AcceptBlock, which holds every rule that
// depends on the chain, does not look at it (CheckBlock does, without
// context), so the whole contextual path runs with no mining at all.
static CBlock V5Block(const CBlockIndex* pindexPrev, unsigned int nTime, const std::vector<CTransaction>& vtx,
                      const std::vector<CTxOut>* pvCoinbaseOut = NULL)
{
    CBlock b;
    b.hashPrevBlock = pindexPrev->GetBlockHash();
    b.nTime = nTime;
    b.nBits = GetNextWorkRequired(pindexPrev);
    b.nNonce = 0;
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << (pindexPrev->nHeight + 1) << OP_0;
    if (pvCoinbaseOut)
        cb.vout = *pvCoinbaseOut;
    else
        cb.vout.push_back(CTxOut(b.GetBlockValue(pindexPrev->nHeight + 1, 0), CScript() << OP_TRUE));
    b.vtx.push_back(cb);
    b.vtx.insert(b.vtx.end(), vtx.begin(), vtx.end());
    b.hashMerkleRoot = b.BuildMerkleTree();
    return b;
}

// One transaction spending these outpoints (anyone-can-spend, so empty
// scriptSigs) into outputs of nEach to scriptOut, nOut of them.
static CTransaction V5Spend(const std::vector<COutPoint>& vIn, int64 nEach, int nOut, const CScript& scriptOut)
{
    CTransaction tx;
    for (size_t i = 0; i < vIn.size(); i++)
    {
        CTxIn in;
        in.prevout = vIn[i];
        tx.vin.push_back(in);
    }
    for (int i = 0; i < nOut; i++)
        tx.vout.push_back(CTxOut(nEach, scriptOut));
    return tx;
}

static CBlockIndex* V5IndexOf(const CBlock& b)
{
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(b.GetHash());
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// A block that breaks a rule when connected stays in the index, marked failed
// (MarkBlockFailed), and a copy sent again is "already have". This bench
// switches the rules off within one process to offer the same block again,
// which no node does; it forgets the refused entry first. Safe: the block was
// refused on the direct-connect path, so nothing was built on it.
static void V5ForgetRefused(const CBlock& b)
{
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(b.GetHash());
    if (mi == mapBlockIndex.end() || !mi->second->fFailed)
        return;
    CBlockIndex* pindex = mi->second;
    mapBlockIndex.erase(mi);
    delete pindex;
}

// Free the whole block index and forget the chain, as a test that built one
// on a real data directory leaves. A node keeps its index for the life of
// the process, so nothing frees it; but at exit mapBlockIndex is destroyed
// first and LeakSanitizer then sees every entry no global still points to --
// the side branches, which pindexBest's parent links do not reach -- as
// leaked.
static void SelfTestFreeBlockIndex()
{
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        delete (*mi).second;
    mapBlockIndex.clear();
    pindexGenesisBlock = NULL;
    pindexBest = NULL;
    pindexBadChainFork = NULL;
    pindexBadChainFirst = NULL;
    hashBestChain = 0;
    nBestHeight = -1;
}

// -selftest=rules-v5: every rule of rules v5, each one with the rules off
// (what this chain does today, unchanged) and on (through -benchrulesv5's
// switch on testnet), and the switch itself.
static int RunRulesV5SelfTest()
{
    fflush(stdout);
    printf("rules-v5 self-test\n");
    int nFail = 0;
    bool fWasTestNet = IsTestNet();
    std::vector<CBlockIndex*> vMade;
    std::string tmp;
    std::string strOldDataDir = strSetDataDir;
    try
    {
        // ---- the switch: not scheduled anywhere
        SelectNetworkParams(false);
        nFail += Check(RULES_V5_TIME_MAINNET == 0 && RULES_V5_TIME_TESTNET == 0,
                       "rules v5 are not scheduled on either network") ? 0 : 1;
        nFail += Check(RulesV5Time() == 0 && !RulesV5ActiveAtMedianTime(1798200000) &&
                       !RulesV5ActiveAtMedianTime(0xffffffffLL) && !RulesV5Active(NULL),
                       "mainnet: never, at any time") ? 0 : 1;
        nBenchRulesV5Time = 1796000000;
        nFail += Check(RulesV5Time() == 0 && !RulesV5ActiveAtMedianTime(1799000000),
                       "a bench time never reaches mainnet") ? 0 : 1;
        SelectNetworkParams(true);
        nBenchRulesV5Time = 0;
        nFail += Check(RulesV5Time() == 0 && !RulesV5ActiveAtMedianTime(0xffffffffLL),
                       "testnet: never, without the bench switch") ? 0 : 1;
        nBenchRulesV5Time = 1796000000;
        nFail += Check(RulesV5Time() == 1796000000 && !RulesV5ActiveAtMedianTime(1796000000 - 1) &&
                       RulesV5ActiveAtMedianTime(1796000000),
                       "an isolated testnet bench moves it (-benchrulesv5), by median time past") ? 0 : 1;
        nBenchRulesV5Time = 1793000000;   // before testnet's rules v4 (1795176000)
        nFail += Check(!RulesV5ActiveAtMedianTime(1793000000) && !RulesV5ActiveAtMedianTime(1795176000 - 1) &&
                       RulesV5ActiveAtMedianTime(1795176000),
                       "never ahead of rules v4") ? 0 : 1;
        nBenchRulesV4Time = 1792900000;
        nFail += Check(RulesV5ActiveAtMedianTime(1793000000),
                       "and with rules v4 moved too, from its own time") ? 0 : 1;
        nBenchRulesV4Time = 0;

        // The parent decides, once: a made-up chain two minutes a block,
        // with the switch at block 10's time.
        const unsigned int nBase = 1796000000;
        nBenchRulesV5Time = nBase + 10 * 120;
        CBlockIndex* p = NULL;
        std::vector<CBlockIndex*> vChain;
        for (int i = 0; i <= 30; i++)
        {
            p = ChainWorkTestBlock(p, 0x1f0fffff, 50000 + i, vMade);
            p->nTime = nBase + 120 * i;
            vChain.push_back(p);
        }
        // The block after vChain[i] is timed past the switch from i = 10 on,
        // but runs v5 only once the median of its last eleven has passed it.
        bool fMonotonic = true;
        int nFirstOn = -1;
        for (int i = 0; i <= 30; i++)
        {
            bool fOn = RulesV5Active(vChain[i]);
            if (fOn && nFirstOn < 0)
                nFirstOn = i;
            if (!fOn && nFirstOn >= 0)
                fMonotonic = false;
        }
        nFail += Check(nFirstOn == 15 && fMonotonic && !RulesV5Active(vChain[11]),
                       "a block timed past the switch is not under v5 until its parent's median time is; from there on every block is") ? 0 : 1;

        // ---- finding 12: no subsidy after 64 halvings (no switch needed)
        {
            CBlock b;
            bool fSame = true;
            for (int nBench = 0; nBench < 2; nBench++)
            {
                nBenchRulesV5Time = nBench ? 1 : 0;
                for (int h = 0; h < 64 * 210000 && fSame; h++)
                    if (b.GetBlockValue(h, 7) != ((int64)(50 * COIN) >> (h / 210000)) + 7)
                        fSame = false;
            }
            nFail += Check(fSame, "every height below 13,440,000 pays exactly what it always did, v5 or not") ? 0 : 1;
            nFail += Check(b.GetBlockValue(64 * 210000 - 1, 0) == 0 && b.GetBlockValue(64 * 210000, 123) == 123 &&
                           b.GetBlockValue(65 * 210000, 0) == 0 && b.GetBlockValue(0x7fffffff, 5) == 5,
                           "from 64 halvings the subsidy is 0, fees only (no shift by 64 back to 50)") ? 0 : 1;
        }

        // ---- finding 8: nLockTime read unsigned
        {
            CTransaction lt;
            lt.vin.resize(1);
            lt.vin[0].prevout = COutPoint(uint256(1), 0);
            lt.vin[0].nSequence = 0;
            lt.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
            lt.nLockTime = (int)0x80000000u;
            nFail += Check(lt.IsFinalAt(100, nBase, false),
                           "v5 off: a lock time of 2^31 counts as final at once, as it always has") ? 0 : 1;
            nFail += Check(!lt.IsFinalAt(100, nBase, true),
                           "v5 on: it is a time in 2038, not final yet") ? 0 : 1;
            nFail += Check(!lt.IsFinalAt(100, 0x80000000LL, true) && lt.IsFinalAt(100, 0x80000001LL, true),
                           "and final once the median time is past it") ? 0 : 1;
            lt.nLockTime = -1;
            nFail += Check(lt.IsFinalAt(100, nBase, false) && !lt.IsFinalAt(100, 0xffffffffLL, true),
                           "0xffffffff: final at once before, never by time under v5") ? 0 : 1;
            lt.vin[0].nSequence = UINT_MAX;
            nFail += Check(lt.IsFinalAt(100, nBase, true), "a final nSequence still makes it final") ? 0 : 1;
            lt.vin[0].nSequence = 0;
            // Below 2^31 nothing changes.
            const unsigned int vLock[] = { 1, 100, 101, 499999999, 500000000, nBase, nBase + 1, 0x7fffffff };
            const int vHeight[] = { 1, 100, 101, 1000000 };
            const int64 vCut[] = { 0, 499999999, nBase, nBase + 1, 0x7fffffffLL, 0x80000000LL, 0xffffffffLL };
            bool fSame = true;
            for (size_t a = 0; a < sizeof(vLock) / sizeof(vLock[0]); a++)
                for (size_t b = 0; b < sizeof(vHeight) / sizeof(vHeight[0]); b++)
                    for (size_t c = 0; c < sizeof(vCut) / sizeof(vCut[0]); c++)
                    {
                        lt.nLockTime = (int)vLock[a];
                        if (lt.IsFinalAt(vHeight[b], vCut[c], false) != lt.IsFinalAt(vHeight[b], vCut[c], true))
                            fSame = false;
                    }
            nFail += Check(fSame, "every lock time below 2^31 gives the same answer either way") ? 0 : 1;
            lt.nLockTime = (int)0x80000000u;
            nBenchRulesV5Time = 0;
            bool fOff = IsFinalAfter(lt, vChain[30]);
            nBenchRulesV5Time = nBase;
            bool fOn = IsFinalAfter(lt, vChain[30]);
            nFail += Check(fOff && !fOn, "the block rule (IsFinalAfter) follows the switch") ? 0 : 1;
        }

        // ---- finding 2: the retarget window, on a made-up index
        {
            // Heights 0..59 at nHard; block 29, the first block of the window
            // block 59 closes, is timed 100000 s ahead.
            const unsigned int nHard = 0x1e0fffff;
            const unsigned int nAhead = nBase + 29 * 120 + 100000;
            CBlockIndex* q = NULL;
            std::vector<CBlockIndex*> w;
            for (int i = 0; i <= 59; i++)
            {
                q = ChainWorkTestBlock(q, nHard, 60000 + i, vMade);
                q->nTime = (i == 29) ? nAhead : nBase + 120 * i;
                w.push_back(q);
            }
            const unsigned int nNormal59 = nBase + 120 * 59;
            nBenchRulesV5Time = 0;
            nFail += Check(RetargetTimeAllowed(w[58], nNormal59) && BlockTimeFloor(w[58]) == w[58]->GetMedianTimePast() + 1,
                           "v5 off: block 59 may be timed before block 29, and builders start at the median time") ? 0 : 1;
            // What the retarget does with it is what it always did: the
            // timespan wraps and is clamped to four windows, 4x easier.
            CBigNum bnOld;
            bnOld.SetCompact(nHard);
            CBigNum bnEasier = bnOld * 4;
            if (bnEasier > bnProofOfWorkLimit)
                bnEasier = bnProofOfWorkLimit;
            CBigNum bnHarder = bnOld * 900;
            bnHarder /= 3600;
            nFail += Check(GetNextWorkRequired(w[59]) == bnEasier.GetCompact(),
                           "v5 off: the wrapped timespan still makes the next target 4x easier, bit for bit") ? 0 : 1;
            nBenchRulesV5Time = nBase;
            nFail += Check(!RetargetTimeAllowed(w[58], nNormal59) && !RetargetTimeAllowed(w[58], nAhead - 1),
                           "v5 on: block 59 timed before block 29 is refused") ? 0 : 1;
            nFail += Check(RetargetTimeAllowed(w[58], nAhead) && RetargetTimeAllowed(w[58], nAhead + 1),
                           "timed at or after it, it is allowed") ? 0 : 1;
            nFail += Check(RetargetTimeAllowed(w[57], w[57]->GetMedianTimePast() + 1) &&
                           RetargetTimeAllowed(w[29], w[29]->GetMedianTimePast() + 1),
                           "a block that closes no window is not held to it") ? 0 : 1;
            nFail += Check(BlockTimeFloor(w[58]) == nAhead && BlockTimeFloor(w[57]) == w[57]->GetMedianTimePast() + 1,
                           "builders start the closing block at the window's first block, the others at the median time") ? 0 : 1;
            // The first block is block 29 exactly: moving the outlier to 28
            // or 30 moves the bound with it.
            w[29]->nTime = nBase + 120 * 29;
            w[28]->nTime = nAhead;
            bool f28 = RetargetTimeAllowed(w[58], nNormal59);
            w[28]->nTime = nBase + 120 * 28;
            w[30]->nTime = nAhead;
            bool f30 = RetargetTimeAllowed(w[58], nNormal59);
            w[30]->nTime = nBase + 120 * 30;
            w[29]->nTime = nAhead;
            nFail += Check(f28 && f30, "the bound is block 29, the one the retarget subtracts: an outlier at 28 or 30 binds nothing") ? 0 : 1;
            w[59]->nTime = nAhead;
            nFail += Check(GetNextWorkRequired(w[59]) == bnHarder.GetCompact(),
                           "at the earliest time v5 allows, the timespan is 0 and the target 4x harder, as in Bitcoin") ? 0 : 1;
        }
        nBenchRulesV5Time = 0;
        for (size_t i = 0; i < vMade.size(); i++)
        {
            mapBlockIndex.erase(vMade[i]->GetBlockHash());
            delete vMade[i];
        }
        vMade.clear();

        // ---- a real chain: findings 4, 8, 2 and review-v4 4 through AcceptBlock
        if (!MakeTempDir(tmp))
            throw std::runtime_error("could not create a temporary data directory");
        strSetDataDir = tmp;
        SelectChainParams(true);
        if (!LoadBlockIndex())
            throw std::runtime_error("LoadBlockIndex failed");

        // Blocks 1-29 two minutes apart from the genesis, before rules v2 (the
        // first retarget's window then stays on the chain); from block 30 on,
        // under rules v3, two minutes apart from T0. Rules v4 from block 129's
        // time (bench), rules v5 from the same time when switched on: the
        // block after height 134 is the first whose parent's median time has
        // reached it.
        const unsigned int T0 = 1792600000;
        const unsigned int TV4 = T0 + 120 * 100;
        nBenchRulesV4Time = TV4;
        struct TimeOf
        {
            static unsigned int At(int h, unsigned int t0)
            {
                return h <= 29 ? 1787184000 + 120 * h : t0 + 120 * (h - 29);
            }
        };
        std::vector<CTransaction> vNone;
        std::vector<uint256> vCb(1, uint256(0));   // coinbase txid by height
        bool fBuilt = true;
        // Extend the best chain to height h with plain blocks.
        struct Grow
        {
            static bool To(int h, std::vector<uint256>& vCb, unsigned int t0, const std::vector<CTransaction>& vNone)
            {
                while (nBestHeight < h)
                {
                    CBlock b = V5Block(pindexBest, TimeOf::At(nBestHeight + 1, t0), vNone);
                    if (!b.AcceptBlock())
                        return false;
                    vCb.push_back(b.vtx[0].GetHash());
                }
                return true;
            }
        };
        const int64 nCb = 50 * COIN;
        CScript scriptCsfs;
        scriptCsfs << OP_0 << OP_IF;
        for (int i = 0; i < 195; i++)
            scriptCsfs << OP_CHECKSIGFROMSTACK;
        scriptCsfs << OP_ENDIF << OP_1;
        nFail += Check(scriptCsfs.GetSigOpCount(false) == 0 && scriptCsfs.GetSigOpCount(true) == 195,
                       "the test output carries 195 CSFS, counted only under rules v4") ? 0 : 1;

        fBuilt = Grow::To(109, vCb, T0, vNone);
        // Block 110, before rules v4: 103 bare CSFS outputs, counted as nothing.
        CTransaction txPre = V5Spend(std::vector<COutPoint>(1, COutPoint(vCb[1], 0)), nCb / 103, 103, scriptCsfs);
        {
            CBlock b = V5Block(pindexBest, TimeOf::At(110, T0), std::vector<CTransaction>(1, txPre));
            fBuilt = fBuilt && !RulesV4Active(b.nTime) && b.AcceptBlock();
            vCb.push_back(b.vtx[0].GetHash());
        }
        fBuilt = fBuilt && Grow::To(129, vCb, T0, vNone);
        // Blocks 130 and 131, under rules v4: 52 and 51 more, counted when made.
        CTransaction txPost1 = V5Spend(std::vector<COutPoint>(1, COutPoint(vCb[2], 0)), nCb / 52, 52, scriptCsfs);
        CTransaction txPost2 = V5Spend(std::vector<COutPoint>(1, COutPoint(vCb[3], 0)), nCb / 51, 51, scriptCsfs);
        {
            CBlock b = V5Block(pindexBest, TimeOf::At(130, T0), std::vector<CTransaction>(1, txPost1));
            fBuilt = fBuilt && RulesV4Active(b.nTime) && b.AcceptBlock();
            vCb.push_back(b.vtx[0].GetHash());
            CBlock c = V5Block(pindexBest, TimeOf::At(131, T0), std::vector<CTransaction>(1, txPost2));
            fBuilt = fBuilt && c.AcceptBlock();
            vCb.push_back(c.vtx[0].GetHash());
        }
        fBuilt = fBuilt && Grow::To(139, vCb, T0, vNone);
        nFail += Check(fBuilt && nBestHeight == 139, "the bench chain is built to height 139") ? 0 : 1;
        nBenchRulesV5Time = TV4;
        {
            const CBlockIndex* p134 = pindexBest;
            while (p134 && p134->nHeight > 134)
                p134 = p134->pprev;
            nFail += Check(p134 && p134->nHeight == 134 && RulesV5Active(p134) && !RulesV5Active(p134->pprev),
                           "on it, switched on, rules v5 hold from block 135: the first whose parent's median time has reached the switch") ? 0 : 1;
        }

        // Finding 4: block 140 spends its own coinbase.
        {
            int nDoS = 0;
            CBlock b = V5Block(pindexBest, TimeOf::At(140, T0), vNone);
            CTransaction self = V5Spend(std::vector<COutPoint>(1, COutPoint(b.vtx[0].GetHash(), 0)), nCb, 1,
                                        CScript() << OP_TRUE);
            b.vtx.push_back(self);
            b.hashMerkleRoot = b.BuildMerkleTree();
            nBenchRulesV5Time = TV4;
            nFail += Check(!b.AcceptBlock(&nDoS) && nBestHeight == 139 && (V5IndexOf(b) == NULL || V5IndexOf(b)->fFailed),
                           "v5 on: a block spending its own coinbase is refused") ? 0 : 1;
            V5ForgetRefused(b);
            nBenchRulesV5Time = 0;
            nFail += Check(b.AcceptBlock() && nBestHeight == 140 && pindexBest == V5IndexOf(b),
                           "v5 off: the same block is accepted, as it always was") ? 0 : 1;
            vCb.push_back(b.vtx[0].GetHash());
        }

        // Review-v4 finding 4: block 141 spends the 103 outputs made before
        // rules v4, 20085 CSFS that no block ever counted.
        {
            std::vector<COutPoint> vIn;
            for (unsigned int i = 0; i < 103; i++)
                vIn.push_back(COutPoint(txPre.GetHash(), i));
            CTransaction spend = V5Spend(vIn, (nCb / 103) * 103, 1, CScript() << OP_TRUE);
            CBlock b = V5Block(pindexBest, TimeOf::At(141, T0), std::vector<CTransaction>(1, spend));
            nBenchRulesV5Time = TV4;
            nFail += Check(!b.AcceptBlock() && nBestHeight == 140,
                           "v5 on: spending pre-v4 CSFS outputs counts them, and 20085 is over the block's 20000") ? 0 : 1;
            V5ForgetRefused(b);
            nBenchRulesV5Time = 0;
            nFail += Check(b.AcceptBlock() && nBestHeight == 141,
                           "v5 off: the same block is accepted, as it always was") ? 0 : 1;
            vCb.push_back(b.vtx[0].GetHash());
        }
        // Block 142 spends the 103 made under rules v4: counted when made,
        // not again.
        {
            std::vector<COutPoint> vIn;
            for (unsigned int i = 0; i < 52; i++)
                vIn.push_back(COutPoint(txPost1.GetHash(), i));
            for (unsigned int i = 0; i < 51; i++)
                vIn.push_back(COutPoint(txPost2.GetHash(), i));
            CTransaction spend = V5Spend(vIn, (nCb / 52) * 52 + (nCb / 51) * 51, 1, CScript() << OP_TRUE);
            CBlock b = V5Block(pindexBest, TimeOf::At(142, T0), std::vector<CTransaction>(1, spend));
            nBenchRulesV5Time = TV4;
            nFail += Check(b.AcceptBlock() && nBestHeight == 142,
                           "v5 on: the same 20085 CSFS made under rules v4 are not counted twice") ? 0 : 1;
            vCb.push_back(b.vtx[0].GetHash());
        }

        // Finding 8: block 143 holds a transaction locked until 2^31 (2038).
        {
            CTransaction locked = V5Spend(std::vector<COutPoint>(1, COutPoint(vCb[4], 0)), nCb, 1, CScript() << OP_TRUE);
            locked.vin[0].nSequence = 0;
            locked.nLockTime = (int)0x80000000u;
            nBenchRulesV5Time = TV4;
            bool fNextOn = IsFinalForNextBlock(locked);
            nBenchRulesV5Time = 0;
            bool fNextOff = IsFinalForNextBlock(locked);
            nFail += Check(fNextOff && !fNextOn, "block builders leave it out under v5 only") ? 0 : 1;
            CBlock b = V5Block(pindexBest, TimeOf::At(143, T0), std::vector<CTransaction>(1, locked));
            int nDoS = 0;
            nBenchRulesV5Time = TV4;
            nFail += Check(!b.AcceptBlock(&nDoS) && nDoS == 10 && nBestHeight == 142,
                           "v5 on: a block with it is refused (not final until 2038)") ? 0 : 1;
            nBenchRulesV5Time = 0;
            nFail += Check(b.AcceptBlock() && nBestHeight == 143,
                           "v5 off: the same block is accepted, as it always was") ? 0 : 1;
            vCb.push_back(b.vtx[0].GetHash());
        }

        // fuzz-script: block 144 makes a bare output whose OP_CHECKMULTISIG
        // takes 25 keys (the count computed, so 20 sigops are charged); block
        // 145 spends it. Rules v5 cap the keys at 20.
        {
            std::vector<std::vector<unsigned char> > vKeys;
            for (int i = 0; i < 25; i++)
            {
                CKey k;
                k.MakeNewKey();
                vKeys.push_back(k.GetPubKey());
            }
            CScript wide;
            for (int i = 0; i < 25; i++)
                wide << vKeys[i];
            wide << OP_16 << OP_9 << OP_ADD << OP_CHECKMULTISIG;
            nBenchRulesV5Time = 0;
            CTransaction make = V5Spend(std::vector<COutPoint>(1, COutPoint(vCb[5], 0)), nCb, 1, wide);
            CBlock b = V5Block(pindexBest, TimeOf::At(144, T0), std::vector<CTransaction>(1, make));
            bool fMade = b.AcceptBlock() && nBestHeight == 144;
            vCb.push_back(b.vtx[0].GetHash());
            CTransaction spend = V5Spend(std::vector<COutPoint>(1, COutPoint(make.GetHash(), 0)), nCb, 1, CScript() << OP_TRUE);
            spend.vin[0].scriptSig = CScript() << OP_0 << OP_0;
            CBlock c = V5Block(pindexBest, TimeOf::At(145, T0), std::vector<CTransaction>(1, spend));
            nBenchRulesV5Time = TV4;
            nFail += Check(fMade && wide.GetSigOpCount(true) == 20 && !c.AcceptBlock() && nBestHeight == 144,
                           "v5 on: spending a 25-key OP_CHECKMULTISIG (charged 20) is refused") ? 0 : 1;
            V5ForgetRefused(c);
            nBenchRulesV5Time = 0;
            nFail += Check(c.AcceptBlock() && nBestHeight == 145,
                           "v5 off: the same block is accepted, as it always was") ? 0 : 1;
            vCb.push_back(c.vtx[0].GetHash());
        }

        // Finding 2: block 149 is timed 30000 s ahead; block 179 closes the
        // window it opens.
        nBenchRulesV5Time = TV4;
        fBuilt = Grow::To(148, vCb, T0, vNone);
        const unsigned int nAhead = TimeOf::At(149, T0) + 30000;
        {
            CBlock b = V5Block(pindexBest, nAhead, vNone);
            fBuilt = fBuilt && b.AcceptBlock();
            vCb.push_back(b.vtx[0].GetHash());
        }
        fBuilt = fBuilt && Grow::To(178, vCb, T0, vNone);
        nFail += Check(fBuilt && nBestHeight == 178, "the chain is built to height 178") ? 0 : 1;
        {
            CBlockIndex* p178 = pindexBest;
            unsigned int nEarly = (unsigned int)p178->GetMedianTimePast() + 1;
            nFail += Check(nEarly < nAhead && BlockTimeFloor(p178) == nAhead,
                           "builders time block 179 no earlier than block 149") ? 0 : 1;
            CBlock bad = V5Block(p178, nEarly, vNone);
            CBlock good = V5Block(p178, nAhead, vNone);
            int nDoS = 0;
            nBenchRulesV5Time = TV4;
            nFail += Check(!bad.AcceptBlock(&nDoS) && nDoS == 10 && V5IndexOf(bad) == NULL,
                           "v5 on: block 179 timed before block 149 is refused") ? 0 : 1;
            nFail += Check(good.AcceptBlock() && nBestHeight == 179, "and timed at block 149's time it is accepted") ? 0 : 1;
            nBenchRulesV5Time = 0;
            nFail += Check(BlockTimeFloor(p178) == p178->GetMedianTimePast() + 1,
                           "v5 off: builders start at the median time, as they did") ? 0 : 1;
            nFail += Check(bad.AcceptBlock() && V5IndexOf(bad) != NULL,
                           "v5 off: the early block is accepted, as it always was (here as a side branch)") ? 0 : 1;
            CBlockIndex* pBad = V5IndexOf(bad);
            CBlockIndex* pGood = V5IndexOf(good);
            if (pBad && pGood)
            {
                CBigNum bnOld;
                bnOld.SetCompact(p178->nBits);
                CBigNum bnEasier = bnOld * 4;
                if (bnEasier > bnProofOfWorkLimit)
                    bnEasier = bnProofOfWorkLimit;
                CBigNum bnHarder = bnOld * 900;
                bnHarder /= 3600;
                nFail += Check(GetNextWorkRequired(pBad) == bnEasier.GetCompact() &&
                               GetNextWorkRequired(pGood) == bnHarder.GetCompact(),
                               "after the early block the target eases (the old arithmetic, unchanged); after the allowed one it hardens") ? 0 : 1;
            }
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }
    nBenchRulesV4Time = 0;
    nBenchRulesV5Time = 0;
    for (size_t i = 0; i < vMade.size(); i++)
    {
        mapBlockIndex.erase(vMade[i]->GetBlockHash());
        delete vMade[i];
    }
    if (!tmp.empty())
    {
        // The chain built on the data directory, its side branches included.
        SelfTestFreeBlockIndex();
        DBFlush(true);
        RemoveTree(tmp);
    }
    strSetDataDir = strOldDataDir;
    SelectChainParams(fWasTestNet);

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- wallet fixes: encrypted seed, pool on encryption, restore, relock,
// ---- secret arguments, file modes, fee limit, chat replay quota

static const char* WF_PHRASE_A =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static const char* WF_PHRASE_B =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
static const char* WF_PHRASE_C =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
static const char* WF_PASS = "btf-test-passphrase";

static bool WfMaster(const char* pszPhrase, bitflash::BIP32PrivateNode& node)
{
    std::vector<unsigned char> seed;
    std::string err;
    return bitflash::BIP39MnemonicToSeed(pszPhrase, "", seed, err) &&
           bitflash::BIP32MasterFromSeed(seed, node, err);
}

static bool WfDeriveKey(const bitflash::BIP32PrivateNode& m, unsigned int nChain, unsigned int nIndex, CKey& key)
{
    bitflash::BIP32PrivateNode child;
    std::string err;
    return bitflash::BIP32DerivePath(m, HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH, HD_BIP44_ACCOUNT, nChain, nIndex),
                                     child, err) &&
           key.SetSecret(child.privateKey);
}

static std::vector<unsigned char> WfDerivePub(const bitflash::BIP32PrivateNode& m, unsigned int nChain, unsigned int nIndex)
{
    CKey key;
    if (!WfDeriveKey(m, nChain, nIndex, key))
        return std::vector<unsigned char>();
    return key.GetPubKey();
}

class CWfRecordCounter : public CWalletRecordVisitor
{
public:
    std::map<std::string, int> m;
    bool VisitWalletRecord(const CDataStream& ssKey, const CDataStream&, std::string&)
    {
        CDataStream s = ssKey;
        std::string strType;
        s >> strType;
        m[strType]++;
        return true;
    }
};

static std::map<std::string, int> WfCountRecords()
{
    CWfRecordCounter c;
    std::string err;
    ScanWalletRecords(c, err);
    return c.m;
}

// The backend the Wf* scenarios run on: Berkeley DB (wallet.dat), or the
// SQLite runtime (wallet.sqlite, the default for new installs).
static bool gWfSQLite = false;

static std::string WfSQLitePath()
{
    return GetAppDir() + "/wallet.sqlite";
}

static bool WfLoadWallet()
{
    if (!gWfSQLite)
        return LoadWallet();
    if (!FileExists(WfSQLitePath().c_str()))
        return CreateNewSQLiteWallet(WfSQLitePath());
    return LoadWalletFromSQLiteRuntime(WfSQLitePath());
}

// Close everything and read the wallet back from disk in this process, as a
// restart would.
static bool WfReloadWallet()
{
    DBFlush(true);
    WalletSQLiteRuntimeClose();
    ClearWalletRuntimeForTest();
    vchPlainSeedPendingMaster.clear();
    vchPlainSeedPendingChainCode.clear();
    strWalletSeedNotice.clear();
    SetWalletRelockTimeout(0);
    return WfLoadWallet();
}

// A wallet with phrase A and a full pool, encrypted by EncryptWallet, then
// loaded again (locked).
static bool WfMakeEncryptedHDWallet(std::string& err)
{
    if (!WfLoadWallet())
    {
        err = "LoadWallet failed";
        return false;
    }
    if (!SetHDSeedFromMnemonic(WF_PHRASE_A, "", err))
        return false;
    TopUpKeyPool();
    std::string strBackup;
    if (!EncryptWallet(WF_PASS, strBackup, err))
        return false;
    if (!WfReloadWallet())
    {
        err = "the encrypted wallet did not load again";
        return false;
    }
    return true;
}

static int WfRunInTempDir(const char* pszName, int (*fn)(const std::string&, const std::string&))
{
    fflush(stdout);
    printf("%s self-test\n", pszName);
    std::string tmp, cwd;
    if (!MakeTempDir(tmp) || !GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());
    int nFail = 0;
    try
    {
        nFail += fn(tmp, cwd);
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }
    SetWalletRelockTimeout(0);
    nWalletSQLiteWritesBeforeFailForTest = -1;
    if (gWfSQLite && WalletSQLiteRuntimeActive())
        printf("  (ran on the SQLite backend)\n");
    WalletSQLiteRuntimeClose();
    gWfSQLite = false;
    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// H1, its repair, and I1.
static int WfEncryptedSeed(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    bitflash::BIP32PrivateNode mA, mB, mC;
    nFail += Check(WfMaster(WF_PHRASE_A, mA) && WfMaster(WF_PHRASE_B, mB) && WfMaster(WF_PHRASE_C, mC),
                   "three test phrases give three seeds") ? 0 : 1;
    if (!WfMakeEncryptedHDWallet(err))
    {
        printf("  FAIL setup: %s\n", err.c_str());
        return nFail + 1;
    }
    if (gWfSQLite)
        nFail += Check(WalletSQLiteRuntimeActive(), "the wallet runs on the SQLite backend") ? 0 : 1;
    nFail += Check(IsWalletEncrypted() && IsWalletLocked(), "the encrypted wallet loads locked") ? 0 : 1;
    nFail += Check(!HaveHDSeed() && WalletHasHDSeed(),
                   "a locked wallet has a seed, though not one in memory") ? 0 : 1;

    // A phrase install on the locked wallet: refused before anything is written.
    std::map<std::string, int> before = WfCountRecords();
    unsigned int nRecv = nHDReceiveNext, nChange = nHDChangeNext;
    size_t nPool = mapKeyPool.size();
    bool fInstalled = SetHDSeedFromMnemonic(WF_PHRASE_B, "", err);
    std::map<std::string, int> after = WfCountRecords();
    nFail += Check(!fInstalled && err.find("locked") != std::string::npos,
                   "a phrase install on a locked encrypted wallet is refused, saying why") ? 0 : 1;
    nFail += Check(after == before && after["hdmaster"] == 0 && nHDReceiveNext == nRecv &&
                   nHDChangeNext == nChange && mapKeyPool.size() == nPool,
                   "and nothing was written: no plaintext seed, pool and counters as they were") ? 0 : 1;
    nFail += Check(!HaveHDSeed(), "the refused seed is not in memory either") ? 0 : 1;

    // Unlocked: the new seed is stored encrypted, never in plaintext.
    nFail += Check(UnlockWallet(WF_PASS, err) && vchHDMaster == mA.privateKey,
                   "unlocked, the wallet's seed decrypts") ? 0 : 1;
    nFail += Check(SetHDSeedFromMnemonic(WF_PHRASE_B, "", err), "unlocked, a new phrase installs") ? 0 : 1;
    after = WfCountRecords();
    std::vector<unsigned char> vchDec;
    bool fDec = DecryptSecret(vWalletMasterKey, vchCryptedHDMaster, WalletSecretIV("hdmaster"), vchDec) &&
                vchDec == mB.privateKey;
    nFail += Check(after["hdmaster"] == 0 && after["hdchaincode"] == 0 &&
                   after["cryptedhdmaster"] == 1 && fDec,
                   "it is stored encrypted only: no plaintext seed record") ? 0 : 1;
    nFail += Check(keyUser.GetPubKey() == WfDerivePub(mB, 0, 0) && vchHDMaster == mB.privateKey,
                   "and the wallet derives from it, its first receive key the default") ? 0 : 1;
    nFail += Check(!keyUser.HasPrivKey(),
                   "the default key's secret is not kept in memory (it lives encrypted only)") ? 0 : 1;
    TopUpKeyPool();
    unsigned int nRecvB = nHDReceiveNext;

    nFail += Check(WfReloadWallet() && IsWalletLocked() && !HaveHDSeed() && strWalletSeedNotice.empty(),
                   "reloaded: locked, no seed in memory, nothing to repair") ? 0 : 1;
    nFail += Check(UnlockWallet(WF_PASS, err) && vchHDMaster == mB.privateKey,
                   "and the unlock gives the new seed back") ? 0 : 1;

    // What an older build left after a phrase install on a locked wallet: the
    // new seed in plaintext, the counters reset to 1/0, the default key not
    // changed.
    nFail += Check(CWalletDB().WriteHDMaster(mC.privateKey, mC.chainCode) &&
                   CWalletDB().WriteHDReceiveNext(1) && CWalletDB().WriteHDChangeNext(0),
                   "the records an older build left can be written back") ? 0 : 1;
    nFail += Check(WfReloadWallet(), "that wallet loads") ? 0 : 1;
    nFail += Check(IsWalletLocked() && !HaveHDSeed() && !vchPlainSeedPendingMaster.empty() &&
                   !strWalletSeedNotice.empty(),
                   "locked, its plaintext seed is set aside, not used, and the user is told") ? 0 : 1;
    std::vector<unsigned char> vchChat;
    std::string strChatErr;
    nFail += Check(!btfchat::ChatSeedFromWallet(vchChat, strChatErr),
                   "the chat identity cannot be computed from it while locked") ? 0 : 1;
    nFail += Check(UnlockWallet(WF_PASS, err), "the wallet unlocks") ? 0 : 1;
    after = WfCountRecords();
    nFail += Check(after["hdmaster"] == 0 && after["hdchaincode"] == 0 && vchPlainSeedPendingMaster.empty(),
                   "and the plaintext seed records are gone") ? 0 : 1;
    nFail += Check(vchHDMaster == mB.privateKey,
                   "the encrypted seed stays: that install never set its default key") ? 0 : 1;
    nFail += Check(nHDReceiveNext >= nRecvB,
                   strprintf("the receive counter is back past every key handed out (%u; it had been reset to 1)",
                             nHDReceiveNext).c_str()) ? 0 : 1;
    nFail += Check(strWalletSeedNotice.find("did not finish") != std::string::npos,
                   "and the notice says what was done") ? 0 : 1;

    // What an older build left after a phrase install that finished on an
    // unlocked wallet: the seed in plaintext and its first key the default.
    CKey keyC0;
    nFail += Check(WfDeriveKey(mC, 0, 0, keyC0) && AddKey(keyC0) &&
                   CWalletDB().WriteDefaultKey(keyC0.GetPubKey()) &&
                   CWalletDB().WriteHDMaster(mC.privateKey, mC.chainCode),
                   "a finished install of an older build can be written back") ? 0 : 1;
    nFail += Check(WfReloadWallet() && !HaveHDSeed() && UnlockWallet(WF_PASS, err),
                   "that wallet loads locked and unlocks") ? 0 : 1;
    after = WfCountRecords();
    vchDec.clear();
    fDec = DecryptSecret(vWalletMasterKey, vchCryptedHDMaster, WalletSecretIV("hdmaster"), vchDec) &&
           vchDec == mC.privateKey;
    nFail += Check(after["hdmaster"] == 0 && vchHDMaster == mC.privateKey && fDec &&
                   keyUser.GetPubKey() == keyC0.GetPubKey(),
                   "the seed the install finished with becomes the wallet's seed, encrypted, plaintext gone") ? 0 : 1;

    // A plaintext copy of the very seed that is encrypted: just removed.
    // The write is its own statement: a temporary CWalletDB lives to the end
    // of the full expression, and the reload closes the database environment
    // under its open handle (LeakSanitizer saw Berkeley DB's handle leak).
    bool fCopyWritten = CWalletDB().WriteHDMaster(mC.privateKey, mC.chainCode);
    nFail += Check(fCopyWritten && WfReloadWallet() &&
                   UnlockWallet(WF_PASS, err),
                   "a plaintext copy of the encrypted seed loads and unlocks") ? 0 : 1;
    after = WfCountRecords();
    nFail += Check(after["hdmaster"] == 0 && vchHDMaster == mC.privateKey,
                   "and the copy is removed, the seed unchanged") ? 0 : 1;

    // I1: nothing to check a candidate master key against is not a pass.
    std::map<unsigned int, CWalletMasterKey> mapMk = mapMasterKeys;
    ClearWalletRuntimeForTest();
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapMasterKeys = mapMk;
        fWalletEncrypted = true;
        fWalletLocked = true;
    }
    bool fUnlocked = UnlockWallet(WF_PASS, err);
    nFail += Check(!fUnlocked && err.find("no encrypted key") != std::string::npos,
                   "an encrypted wallet with no encrypted key to check the passphrase against does not unlock") ? 0 : 1;
    ClearWalletRuntimeForTest();
    return nFail;
}

// M1.
static int WfEncryptPool(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    bitflash::BIP32PrivateNode mA;
    if (!WfMaster(WF_PHRASE_A, mA) || !WfLoadWallet() || !SetHDSeedFromMnemonic(WF_PHRASE_A, "", err))
    {
        printf("  FAIL setup: %s\n", err.c_str());
        return 1;
    }
    TopUpKeyPool();
    std::set<std::vector<unsigned char> > setIssued;
    setIssued.insert(keyUser.GetPubKey());
    for (int i = 0; i < 5; i++)
        setIssued.insert(GetKeyFromPool());
    unsigned int nRecvBefore = nHDReceiveNext;
    std::set<std::vector<unsigned char> > setPoolBefore;
    CRITICAL_BLOCK(cs_keyPool)
        for (map<int64, vector<unsigned char> >::iterator it = mapKeyPool.begin(); it != mapKeyPool.end(); ++it)
            setPoolBefore.insert(it->second);
    nFail += Check(setIssued.size() == 6 && setPoolBefore.size() == (size_t)KEYPOOL_SIZE,
                   "a phrase wallet has handed out its default and five addresses, with a full pool") ? 0 : 1;

    std::string strBackup;
    nFail += Check(EncryptWallet(WF_PASS, strBackup, err), "it encrypts") ? 0 : 1;
    nFail += Check(WfReloadWallet() && UnlockWallet(WF_PASS, err), "and loads and unlocks again") ? 0 : 1;

    std::set<std::vector<unsigned char> > setPoolAfter;
    int nReissued = 0;
    CRITICAL_BLOCK(cs_keyPool)
        for (map<int64, vector<unsigned char> >::iterator it = mapKeyPool.begin(); it != mapKeyPool.end(); ++it)
        {
            setPoolAfter.insert(it->second);
            if (setIssued.count(it->second))
                nReissued++;
        }
    nFail += Check(nReissued == 0,
                   strprintf("the encrypted wallet's pool holds none of the addresses already handed out (%d did)",
                             nReissued).c_str()) ? 0 : 1;
    nFail += Check(setPoolAfter == setPoolBefore, "it keeps the pool it had") ? 0 : 1;
    nFail += Check(nHDReceiveNext == nRecvBefore, "and its receive counter") ? 0 : 1;

    std::set<std::vector<unsigned char> > setDrawn;
    int nBad = 0;
    for (int i = 0; i < KEYPOOL_SIZE + 20; i++)
    {
        std::vector<unsigned char> v = GetKeyFromPool();
        if (v.empty() || setIssued.count(v) || !setDrawn.insert(v).second)
            nBad++;
    }
    nFail += Check(nBad == 0, "120 new addresses after encryption: none handed out before, none twice") ? 0 : 1;

    // M-2: a wallet an older release encrypted holds receive/0..99 in its pool
    // (and hdnext 100). The unlock repairs it.
    std::set<std::vector<unsigned char> > setHanded = setIssued;
    setHanded.insert(setDrawn.begin(), setDrawn.end());
    unsigned int nRecvBeforeDamage = nHDReceiveNext;
    bool fDamaged = ResetKeyPoolRecords(err) && CWalletDB().WriteHDNext(100);
    for (int i = 0; i < KEYPOOL_SIZE && fDamaged; i++)
        fDamaged = CWalletDB().WritePool(i + 1, WfDerivePub(mA, 0, i));
    nFail += Check(fDamaged, "the pool an older release left (receive/0..99) can be written back") ? 0 : 1;
    nFail += Check(WfReloadWallet() && UnlockWallet(WF_PASS, err), "that wallet loads and unlocks") ? 0 : 1;
    int nStillIssued = 0;
    CRITICAL_BLOCK(cs_keyPool)
        for (map<int64, vector<unsigned char> >::iterator it = mapKeyPool.begin(); it != mapKeyPool.end(); ++it)
            if (setHanded.count(it->second))
                nStillIssued++;
    nFail += Check(nStillIssued == 0 && !strWalletSeedNotice.empty() && nHDReceiveNext >= nRecvBeforeDamage,
                   strprintf("the unlock rebuilt the pool: no address handed out before is in it (%d), the user is told",
                             nStillIssued).c_str()) ? 0 : 1;
    int nAgain = 0;
    for (int i = 0; i < 20; i++)
    {
        std::vector<unsigned char> v = GetKeyFromPool();
        if (v.empty() || setHanded.count(v))
            nAgain++;
        setHanded.insert(v);
    }
    nFail += Check(nAgain == 0, "and the next 20 addresses are all new") ? 0 : 1;
    nFail += Check(WfReloadWallet() && UnlockWallet(WF_PASS, err) && strWalletSeedNotice.empty(),
                   "a healthy pool is left alone at the next unlock") ? 0 : 1;

    // L6: when the phrase cannot derive the next key, the wallet hands out
    // what its pool holds and then nothing -- never a random key the phrase
    // cannot bring back. (A hardened index is refused by the derivation.)
    unsigned int nSavedReceive = nHDReceiveNext;
    CRITICAL_BLOCK(cs_keyPool)
        nHDReceiveNext = bitflash::BIP32_HARDENED;
    std::set<std::vector<unsigned char> > setPhrase;
    for (unsigned int i = 0; i < nSavedReceive + 5; i++)
        setPhrase.insert(WfDerivePub(mA, 0, i));
    int nRandom = 0, nEmpty = 0;
    for (int i = 0; i < KEYPOOL_SIZE + 5; i++)
    {
        std::vector<unsigned char> v = GetKeyFromPool();
        if (v.empty())
            nEmpty++;
        else if (!setPhrase.count(v))
            nRandom++;
    }
    CRITICAL_BLOCK(cs_keyPool)
        nHDReceiveNext = nSavedReceive;
    nFail += Check(nRandom == 0 && nEmpty > 0,
                   strprintf("with derivation failing, the pool runs dry instead of filling with random keys "
                             "(%d random, %d empty draws)", nRandom, nEmpty).c_str()) ? 0 : 1;
    return nFail;
}

// M3 and I2.
static int WfRelock(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    if (!WfMakeEncryptedHDWallet(err))
    {
        printf("  FAIL setup: %s\n", err.c_str());
        return 1;
    }
    nFail += Check(UnlockWalletFor(WF_PASS, 1, err) && !IsWalletLocked() && GetWalletRelockTime() > 0,
                   "unlocked with a one-second timeout") ? 0 : 1;
    bool fRelocked = false;
    for (int i = 0; i < 100 && !fRelocked; i++)
    {
        Sleep(100);
        fRelocked = IsWalletLocked();
    }
    bool fCleared = false;
    CRITICAL_BLOCK(cs_mapKeys)
        fCleared = vWalletMasterKey.empty();
    nFail += Check(fRelocked && fCleared && !HaveHDSeed() && GetWalletRelockTime() == 0,
                   "it locks itself when the time runs out: master key and seed out of memory") ? 0 : 1;
    nFail += Check(GetKeyFromPool().empty(), "locked again, it hands out no key") ? 0 : 1;
    nFail += Check(UnlockWallet(WF_PASS, err) && !IsWalletLocked() && GetWalletRelockTime() == 0,
                   "an unlock without a timeout stays unlocked") ? 0 : 1;
    LockWallet();
    nFail += Check(IsWalletLocked() && !HaveHDSeed(), "LockWallet locks it at once") ? 0 : 1;

    // Keys added on one thread while another locks and unlocks: each one
    // that was accepted was encrypted with the whole master key.
    nFail += Check(UnlockWallet(WF_PASS, err), "unlocked for the concurrency check") ? 0 : 1;
    std::vector<std::vector<unsigned char> > vAdded;
    std::mutex mutexAdded;
    std::atomic<bool> fAdderDone(false);
    std::thread adder([&]() {
        for (int i = 0; i < 400; i++)
        {
            CKey k;
            k.MakeNewKey();
            if (AddKey(k))
            {
                std::lock_guard<std::mutex> lock(mutexAdded);
                vAdded.push_back(k.GetPubKey());
            }
        }
        fAdderDone = true;
    });
    for (int i = 0; i < 30 && !fAdderDone; i++)
    {
        LockWallet();
        UnlockWallet(WF_PASS, err);
    }
    adder.join();
    UnlockWallet(WF_PASS, err);
    int nBad = 0;
    for (size_t i = 0; i < vAdded.size(); i++)
    {
        CPrivKey vchPriv;
        std::string e;
        CKey k;
        if (!GetWalletPrivKey(vAdded[i], vchPriv, e) || !k.SetPrivKey(vchPriv) || k.GetPubKey() != vAdded[i])
            nBad++;
    }
    nFail += Check(!vAdded.empty() && nBad == 0,
                   strprintf("%u key(s) added while the wallet locked and unlocked: every one decrypts",
                             (unsigned int)vAdded.size()).c_str()) ? 0 : 1;

    int fWasGenerate = fGenerateBitcoins;
    fGenerateBitcoins = 1;
    std::string strWhy;
    bool fRefused = WalletLockRefusedWhy(strWhy);
    fGenerateBitcoins = fWasGenerate;
    std::string strWhy2;
    nFail += Check(fRefused && !strWhy.empty() && !WalletLockRefusedWhy(strWhy2),
                   "a mining node does not lock its wallet (its blocks need keys); a plain node does") ? 0 : 1;

    // M-1: mining switched on AFTER a timed unlock. The timer asks again when
    // it fires, and leaves the wallet unlocked.
    nFail += Check(UnlockWalletFor(WF_PASS, 1, err) && GetWalletRelockTime() > 0,
                   "unlocked with a one-second timeout, mining off") ? 0 : 1;
    fGenerateBitcoins = 1;
    for (int i = 0; i < 30 && GetWalletRelockTime() != 0; i++)
        Sleep(100);
    Sleep(500);
    bool fStillUnlocked = !IsWalletLocked() && HaveHDSeed() && GetWalletRelockTime() == 0;
    std::vector<unsigned char> vchMinerKey = GetKeyFromPool();
    fGenerateBitcoins = fWasGenerate;
    nFail += Check(fStillUnlocked && !vchMinerKey.empty(),
                   "mining turned on after the unlock: the timeout does not lock the wallet, and the miner still gets keys") ? 0 : 1;

    // L-4: an inheritance this wallet renews by itself keeps the wallet unlocked.
    std::string strContracts = GetAppDir() + "/v4contracts.json";
    nFail += Check(WriteTextFile(strContracts,
                                 "{\"Cinheritance\": {\"type\": \"inheritance\", \"role\": \"owner\", \"autoRenew\": true}}"),
                   "an owner inheritance with autoRenew is on record") ? 0 : 1;
    std::string strWhyInherit;
    bool fInheritRefuses = WalletLockRefusedWhy(strWhyInherit) &&
                           strWhyInherit.find("inheritance") != std::string::npos;
    WriteTextFile(strContracts,
                  "{\"Cinheritance\": {\"type\": \"inheritance\", \"role\": \"owner\", \"autoRenew\": true, \"closedTxid\": \"00\"}}");
    std::string strWhyClosed;
    bool fClosedAllows = !WalletLockRefusedWhy(strWhyClosed);
    remove(strContracts.c_str());
    nFail += Check(fInheritRefuses && fClosedAllows,
                   "the wallet does not lock while it renews an inheritance by itself; once that is closed, it may") ? 0 : 1;

    // L-3: locking forgets the default key's secret.
    CKey keyFull;
    keyFull.MakeNewKey();
    keyUser = keyFull;
    bool fHadSecret = keyUser.HasPrivKey();
    LockWallet();
    nFail += Check(fHadSecret && !keyUser.HasPrivKey() && keyUser.GetPubKey() == keyFull.GetPubKey(),
                   "LockWallet keeps the default key's public half and forgets its secret") ? 0 : 1;
    return nFail;
}

// M2.
static int WfRestoreRace(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    bitflash::BIP32PrivateNode mA;
    if (!WfMaster(WF_PHRASE_A, mA) || !LoadWallet())
    {
        printf("  FAIL setup\n");
        return 1;
    }
    // A stand-in chain: RestoreFromPhrase insists on one, and the scan finds
    // no block on disk to read, which is all this test needs.
    CBlockIndex fakeIndex;
    CBlockIndex* pSavedGenesis = pindexGenesisBlock;
    CBlockIndex* pSavedBest = pindexBest;
    uint256 hashSaved = hashBestChain;
    int nSavedHeight = nBestHeight;
    pindexGenesisBlock = &fakeIndex;
    pindexBest = &fakeIndex;
    hashBestChain = uint256(1);
    nBestHeight = 1;

    nFail += Check(SetHDSeedFromMnemonic(WF_PHRASE_A, "", err) && nHDKeySchema == HD_SCHEMA_BIP44,
                   "a BIP44 phrase wallet") ? 0 : 1;
    {
        CKey keyLegacy;
        bitflash::BIP32PrivateNode child;
        CKey keyExpect;
        bool fOk = DeriveHDKeyForSchema(HD_SCHEMA_LEGACY, 3, keyLegacy, err) &&
                   bitflash::BIP32DerivePath(mA, HDLegacyPath(3), child, err) &&
                   keyExpect.SetSecret(child.privateKey);
        nFail += Check(fOk && keyLegacy.GetPubKey() == keyExpect.GetPubKey() && nHDKeySchema == HD_SCHEMA_BIP44,
                       "the legacy path is derived by name, the wallet's own schema untouched") ? 0 : 1;
    }

    std::atomic<bool> fDone(false);
    std::atomic<bool> fSawOtherSchema(false);
    bool fRestored = false;
    int nRecovered = 0, nDerived = 0;
    std::string strRestoreErr;
    std::thread restorer([&]() {
        fRestored = RestoreFromPhrase(WF_PHRASE_A, "", 0, NULL, NULL, strRestoreErr, nRecovered, nDerived);
        fDone = true;
    });
    std::vector<std::vector<unsigned char> > vDrawn;
    while (!fDone)
    {
        // Read as the wallet reads it, under cs_keyPool: the phrase install
        // writes it under that lock (ThreadSanitizer saw this read without it).
        CRITICAL_BLOCK(cs_keyPool)
            if (nHDKeySchema != HD_SCHEMA_BIP44)
                fSawOtherSchema = true;
        std::vector<unsigned char> v = GetKeyFromPool();
        if (!v.empty())
            vDrawn.push_back(v);
        Sleep(2);
    }
    restorer.join();

    nFail += Check(fRestored, "the restore runs to the end while another thread draws keys") ? 0 : 1;
    nFail += Check(!fSawOtherSchema, "the wallet's derivation schema never changed under the other thread") ? 0 : 1;
    std::set<std::vector<unsigned char> > setReceive;
    for (unsigned int i = 0; i < nHDReceiveNext + 10; i++)
        setReceive.insert(WfDerivePub(mA, 0, i));
    std::set<std::vector<unsigned char> > setSeen;
    int nForeign = 0, nTwice = 0;
    for (size_t i = 0; i < vDrawn.size(); i++)
    {
        if (!setReceive.count(vDrawn[i]))
            nForeign++;
        if (!setSeen.insert(vDrawn[i]).second)
            nTwice++;
    }
    nFail += Check(!vDrawn.empty() && nForeign == 0 && nTwice == 0,
                   strprintf("%u key(s) drawn during the restore: all on the phrase's receive path (%d not), none twice (%d)",
                             (unsigned int)vDrawn.size(), nForeign, nTwice).c_str()) ? 0 : 1;
    size_t nPoolMem = 0;
    CRITICAL_BLOCK(cs_keyPool)
        nPoolMem = mapKeyPool.size();
    std::map<std::string, int> recs = WfCountRecords();
    nFail += Check((size_t)recs["pool"] == nPoolMem,
                   strprintf("the pool on disk is the pool in memory (%d records, %u entries): no stale entry comes back",
                             recs["pool"], (unsigned int)nPoolMem).c_str()) ? 0 : 1;

    pindexGenesisBlock = pSavedGenesis;
    pindexBest = pSavedBest;
    hashBestChain = hashSaved;
    nBestHeight = nSavedHeight;
    return nFail;
}

// M4 (and the echo-off reader behind every secret option).
static int WfSecretArgs(const std::string& tmp, const std::string& cwd)
{
    int nFail = 0;
    std::string s, err;
    nFail += Check(!ReadSecretArgument(WF_PHRASE_A, "recovery phrase", s, err) &&
                   err.find("literal") != std::string::npos && s.empty(),
                   "a recovery phrase given as a literal is refused") ? 0 : 1;
    std::string strFile = tmp + "/phrase.txt";
    nFail += Check(WriteTextFile(strFile, std::string(WF_PHRASE_A) + "\r\n") &&
                   ReadSecretArgument("@" + strFile, "recovery phrase", s, err) && s == WF_PHRASE_A,
                   "@FILE reads it, line end stripped") ? 0 : 1;
    std::string strEmpty = tmp + "/empty.txt";
    nFail += Check(WriteTextFile(strEmpty, "\n") && !ReadSecretArgument("@" + strEmpty, "recovery phrase", s, err) &&
                   !ReadSecretArgument("@" + tmp + "/missing.txt", "recovery phrase", s, err),
                   "an empty or missing file is refused") ? 0 : 1;

#ifdef _WIN32
    std::string strExe = cwd + "\\bitflash.exe";
#else
    std::string strExe = cwd + "/bitflash-node";
#endif
    std::string strChildDir = tmp + "/child";
    MakeDirLocal(strChildDir);
    std::string strOutLiteral = tmp + "/literal.txt", strOutFile = tmp + "/file.txt";
    std::vector<std::string> vLiteral;
    vLiteral.push_back("-datadir=" + strChildDir);
    vLiteral.push_back(std::string("-restorephrase=") + WF_PHRASE_A);
    vLiteral.push_back("-nogui");
    int nRetLiteral = RunBitflashChild(strExe, vLiteral, NULL, &strOutLiteral);
    nFail += Check(nRetLiteral != 0 && FileContainsText(strOutLiteral, "literal") &&
                   !FileContainsText(strOutLiteral, "Checking the phrase"),
                   "the node refuses -restorephrase=WORDS before reading anything") ? 0 : 1;
    std::vector<std::string> vFile;
    vFile.push_back("-datadir=" + strChildDir);
    vFile.push_back("-restorephrase=@" + strFile);
    vFile.push_back("-nogui");
    RunBitflashChild(strExe, vFile, NULL, &strOutFile);
    nFail += Check(FileContainsText(strOutFile, "Checking the phrase") && !FileContainsText(strOutFile, "literal"),
                   "and takes -restorephrase=@FILE") ? 0 : 1;
    return nFail;
}

// M5 and M6.
static int WfFileModes(const std::string& tmp, const std::string&)
{
    int nFail = 0;
    unsigned char a[32], b[32], zero[32];
    memset(zero, 0, sizeof(zero));
    GetStrongRandBytes(a, sizeof(a));
    GetStrongRandBytes(b, sizeof(b));
    nFail += Check(memcmp(a, b, 32) != 0 && memcmp(a, zero, 32) != 0,
                   "GetStrongRandBytes fills buffers with fresh bytes") ? 0 : 1;
#ifndef _WIN32
    struct stat st;
    std::string strSub = tmp + "/made-by-mkdir";
    nFail += Check(_mkdir(strSub.c_str()) == 0 && stat(strSub.c_str(), &st) == 0 && (st.st_mode & 077) == 0,
                   "directories the node makes are owner-only") ? 0 : 1;
    {
        CWalletDBSQLite db;
        std::string strDb = tmp + "/fresh.sqlite";
        std::string err;
        std::vector<unsigned char> k(4, 0x11), v(4, 0x22);
        bool fOpen = db.Open(strDb, err) && db.WriteRecord(k, v, err, true);
        bool fMode = stat(strDb.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600;
        bool fWal = stat((strDb + "-wal").c_str(), &st) != 0 || (st.st_mode & 077) == 0;
        db.Close();
        nFail += Check(fOpen && fMode && fWal, "a new SQLite wallet and its write-ahead log are owner-only") ? 0 : 1;
    }
    {
        // Files an older build left readable: tightened at start.
        const char* apsz[] = { "wallet.dat", "wallet.sqlite", "nostr.key", "wallet.dat.before-encrypt.1.bak",
                               "wallet.sqlite.encrypting.1700000000", "wallet.encrypting.1700000000.dat" };
        const size_t nFiles = sizeof(apsz) / sizeof(apsz[0]);
        bool fMade = true;
        for (size_t i = 0; i < nFiles; i++)
        {
            std::string p = tmp + "/" + apsz[i];
            fMade = fMade && WriteTextFile(p, "x") && chmod(p.c_str(), 0644) == 0;
        }
        std::string strLogDir = tmp + "/database";
        fMade = fMade && mkdir(strLogDir.c_str(), 0755) == 0 && chmod(strLogDir.c_str(), 0755) == 0;
        RestrictWalletFileModes();
        bool fAll = true;
        for (size_t i = 0; i < nFiles; i++)
            fAll = fAll && stat((tmp + "/" + apsz[i]).c_str(), &st) == 0 && (st.st_mode & 0777) == 0600;
        fAll = fAll && stat(strLogDir.c_str(), &st) == 0 && (st.st_mode & 077) == 0;
        nFail += Check(fMade && fAll,
                       "wallet.dat, wallet.sqlite, nostr.key, encryption backups and leftover encryption temp files (both backends), and database/ are made owner-only at start") ? 0 : 1;
    }
    {
        std::string p = tmp + "/private.out";
        FILE* f = OpenPrivateFile(p.c_str(), false);
        if (f)
            fclose(f);
        nFail += Check(f && stat(p.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600,
                       "OpenPrivateFile (backups, nostr.key, dumps) creates owner-only files") ? 0 : 1;
    }
#else
    printf("  skip   POSIX file modes (Windows: the data directory's ACL keeps other accounts out)\n");
#endif
    return nFail;
}

// Index of the output that is not the payment, or -1.
static int WfChangeIndex(const CTransaction& tx, const CScript& scriptPay)
{
    for (size_t i = 0; i < tx.vout.size(); i++)
        if (tx.vout[i].scriptPubKey != scriptPay)
            return (int)i;
    return -1;
}

// M7, L7 and I3 (the coin flips are exercised by every build below).
static int WfFeeLimit(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    if (!LoadWallet())
    {
        printf("  FAIL setup\n");
        return 1;
    }
    {
        CTxDB txdb("cr+");   // the transaction index CreateTransaction opens
    }
    // Coins: somebody paid us 10, and we sent 9 of it back to ourselves, so
    // the 9 is our own change, spendable unconfirmed.
    std::vector<unsigned char> vchMe = keyUser.GetPubKey();
    CScript scriptMe;
    scriptMe << vchMe << OP_CHECKSIG;
    CTransaction tx0;
    tx0.vin.push_back(CTxIn(COutPoint(uint256(4242), 0)));
    tx0.vout.push_back(CTxOut(10 * COIN, scriptMe));
    CTransaction tx1;
    tx1.vin.push_back(CTxIn(COutPoint(tx0.GetHash(), 0)));
    tx1.vout.push_back(CTxOut(9 * COIN, scriptMe));
    AddToWallet(CWalletTx(tx0));
    AddToWallet(CWalletTx(tx1));
    CRITICAL_BLOCK(cs_mapWallet)
        mapWallet[tx0.GetHash()].fSpent = true;
    CKey keyPayee;
    keyPayee.MakeNewKey();
    CScript scriptPay;
    scriptPay << OP_DUP << OP_HASH160 << Hash160(keyPayee.GetPubKey()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // A flat fee of 0.01, so every build below pays something to compare.
    nTransactionFee = CENT;
    CWalletTx wtx;
    int64 nFee = 0;
    nFail += Check(CreateTransaction(scriptPay, COIN, wtx, nFee) && nFee == CENT,
                   "a send of 1 builds, paying the 0.01 flat fee") ? 0 : 1;
    int nChange = WfChangeIndex(wtx, scriptPay);
    std::vector<unsigned char> vchChange;
    bool fFresh = nChange >= 0 && ExtractPubKey(wtx.vout[nChange].scriptPubKey, true, vchChange) &&
                  vchChange != vchMe;
    nFail += Check(fFresh, "a wallet without a seed sends its change to a fresh key, not back to the input's") ? 0 : 1;

    int nFirst = 0, nSecond = 0;
    for (int i = 0; i < 40; i++)
    {
        CWalletTx w;
        int64 f = 0;
        if (CreateTransaction(scriptPay, COIN, w, f, -1, true))
        {
            int n = WfChangeIndex(w, scriptPay);
            if (n == 0)
                nFirst++;
            else if (n == 1)
                nSecond++;
        }
    }
    nFail += Check(nFirst > 0 && nSecond > 0,
                   strprintf("the change is not always the second output (%d first, %d second in 40)",
                             nFirst, nSecond).c_str()) ? 0 : 1;

    // The flat fee: a unit slip (5 BTF) is refused by the 1 BTF limit.
    nTransactionFee = 5 * COIN;
    bool fBuilt = CreateTransaction(scriptPay, COIN, wtx, nFee);
    nFail += Check(!fBuilt && LastCreateTransactionError().find("above the limit") != std::string::npos,
                   "a 5 BTF flat fee is refused by the 1 BTF /maxtxfee limit, saying why") ? 0 : 1;
    nMaxTxFee = 10 * COIN;
    nFail += Check(CreateTransaction(scriptPay, COIN, wtx, nFee) && nFee == 5 * COIN,
                   "with /maxtxfee raised, the same send builds") ? 0 : 1;
    nMaxTxFee = COIN;
    nTransactionFee = 2 * COIN;
    ClampLoadedFeeSettings();
    nFail += Check(nTransactionFee == 0, "a stored flat fee above 1 BTF is not used") ? 0 : 1;
    nFail += Check(IsAcceptableTxFeeSetting(0) && IsAcceptableTxFeeSetting(COIN) &&
                   !IsAcceptableTxFeeSetting(COIN + 1) && !IsAcceptableTxFeeSetting(-1),
                   "the fee setting takes 0 to 1 BTF") ? 0 : 1;
    nTransactionFee = CENT;

    // The GUI's review: the fee shown first, no change key taken; the send
    // after it never pays noticeably more.
    nFail += Check(SetHDSeedFromMnemonic(WF_PHRASE_A, "", err), "now with a recovery phrase") ? 0 : 1;
    unsigned int nChangeNext = nHDChangeNext;
    size_t nWalletSize = 0;
    CRITICAL_BLOCK(cs_mapWallet)
        nWalletSize = mapWallet.size();
    int64 nPreview = 0;
    std::string strWhy;
    bool fPreview = PreviewSendFee(scriptPay, COIN, nPreview, strWhy);
    size_t nWalletSize2 = 0;
    CRITICAL_BLOCK(cs_mapWallet)
        nWalletSize2 = mapWallet.size();
    nFail += Check(fPreview && nPreview > 0 && nHDChangeNext == nChangeNext && nWalletSize2 == nWalletSize,
                   "the review shows the fee without taking a change key or writing anything") ? 0 : 1;
    nFail += Check(SendFeeLimitAfterReview(CENT) == CENT + CENT / 10 + 1 &&
                   SendFeeLimitAfterReview(5 * COIN) == nMaxTxFee,
                   "the send after a review may pay a tenth more, never above /maxtxfee") ? 0 : 1;
    nFail += Check(CreateTransaction(scriptPay, COIN, wtx, nFee, SendFeeLimitAfterReview(nPreview)) &&
                   nFee <= SendFeeLimitAfterReview(nPreview) && nHDChangeNext == nChangeNext + 1,
                   "the real build stays within it, and takes its change key") ? 0 : 1;
    CWalletTx wtxSend;
    bool fSent = SendMoney(scriptPay, COIN, wtxSend, nPreview - 1);
    size_t nWalletSize3 = 0;
    CRITICAL_BLOCK(cs_mapWallet)
        nWalletSize3 = mapWallet.size();
    nFail += Check(!fSent && nWalletSize3 == nWalletSize,
                   "SendMoney refuses a fee above the one confirmed, and records nothing") ? 0 : 1;
    nTransactionFee = 0;
    return nFail;
}

// M8: strangers' invites have their own share of the replay table.
static int RunChatReplayQuotaSelfTest()
{
    printf("chat-replay-quota self-test\n");
    int nFail = 0;
    int64 nNow = GetTime();
    int nCounter = 0;
    struct F
    {
        static btfchat::Frame Make(int64 nSent, int& n)
        {
            btfchat::Frame f;
            f.sent = nSent;
            f.id = strprintf("%032x", ++n);
            return f;
        }
    };
    btfchat::ReplayGuard rg;
    std::string err;
    bool fAll = true;
    for (size_t i = 0; i < btfchat::MAX_SEEN_STRANGER_FRAMES; i++)
        fAll = fAll && rg.Accept(F::Make(nNow, nCounter), nNow, err, true);
    nFail += Check(fAll && rg.StrangerSize() == btfchat::MAX_SEEN_STRANGER_FRAMES,
                   "strangers' invites fill their own share of the replay table") ? 0 : 1;
    nFail += Check(!rg.Accept(F::Make(nNow, nCounter), nNow, err, true) &&
                   err.find("strangers") != std::string::npos,
                   "one more is refused, saying why") ? 0 : 1;
    btfchat::Frame fContact = F::Make(nNow, nCounter);
    nFail += Check(rg.Accept(fContact, nNow, err, false), "a frame from an accepted contact still gets through") ? 0 : 1;
    nFail += Check(!rg.Accept(fContact, nNow, err, false) && !rg.Accept(fContact, nNow, err, true),
                   "and is not taken twice, either way") ? 0 : 1;

    // The inbound path: when the pending-invite list is full, a stranger's
    // invite is refused before it takes a replay slot.
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    struct Id
    {
        static bool Make(secp256k1_context* c, btfchat::Identity& id)
        {
            memset(id.sign_sk, 0, sizeof(id.sign_sk));
            memset(id.sign_pk, 0, sizeof(id.sign_pk));
            memset(id.chan_sk, 0, sizeof(id.chan_sk));
            memset(id.chan_pk, 0, sizeof(id.chan_pk));
            memset(id.store_key, 0, sizeof(id.store_key));
            secp256k1_keypair kp;
            secp256k1_xonly_pubkey xpub;
            for (int tries = 0; tries < 10; tries++)
            {
                GetStrongRandBytes(id.sign_sk, 32);
                if (secp256k1_keypair_create(c, &kp, id.sign_sk))
                    break;
            }
            if (!secp256k1_keypair_xonly_pub(c, &xpub, NULL, &kp) ||
                !secp256k1_xonly_pubkey_serialize(c, id.sign_pk, &xpub))
                return false;
            id.address = btf::Address(id.sign_pk);
            return true;
        }
    };
    btfchat::Identity me, stranger;
    bool fIds = ctx && Id::Make(ctx, me) && Id::Make(ctx, stranger);
    nFail += Check(fIds, "two chat identities") ? 0 : 1;
    if (fIds)
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox inbox;
        inbox.secpctx = ctx;
        inbox.myAddress = me.address;
        inbox.roster = &roster;
        inbox.replay = &replay;
        inbox.history = &history;
        for (size_t i = 0; i < btfchat::MAX_PENDING_INVITES; i++)
            roster.NoteIncomingInvite(strprintf("filler%u.btf", (unsigned int)i), "", nNow, err);
        btfchat::Frame inv;
        inv.kind = btfchat::MSG_INVITE;
        inv.sent = nNow;
        inv.text = "oi";
        std::string js;
        btfchat::Frame opened;
        bool fSigned = btfchat::SignFrame(ctx, stranger, inv, js, err);
        bool fDelivered = fSigned && inbox.Deliver(js, std::string(), nNow, opened, err);
        nFail += Check(fSigned && roster.PendingInvitesFull() && !fDelivered && replay.Size() == 0,
                       "with the invite list full, a stranger's invite is refused without taking a replay slot") ? 0 : 1;
    }
    if (ctx)
        secp256k1_context_destroy(ctx);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int WfRpcAndV4(const std::string&, const std::string&)
{
    return WalletRpcV4SelfTest();
}

// The same scenarios on the SQLite backend, the default for new installs.
static int WfEncryptedSeedSQLite(const std::string& tmp, const std::string& cwd)
{
    gWfSQLite = true;
    return WfEncryptedSeed(tmp, cwd);
}

static int WfEncryptPoolSQLite(const std::string& tmp, const std::string& cwd)
{
    gWfSQLite = true;
    return WfEncryptPool(tmp, cwd);
}

// SQLite brackets: nesting, a rollback dooming the whole transaction, and a
// seed install that fails part way leaving the disk as it was.
static int WfSQLiteRollback(const std::string&, const std::string&)
{
    int nFail = 0;
    std::string err;
    gWfSQLite = true;
    bitflash::BIP32PrivateNode mA;
    if (!WfMaster(WF_PHRASE_A, mA) || !WfLoadWallet() || !WalletSQLiteRuntimeActive() ||
        !SetHDSeedFromMnemonic(WF_PHRASE_A, "", err))
    {
        printf("  FAIL setup: %s\n", err.c_str());
        return 1;
    }
    TopUpKeyPool();

    {
        int64 n = 0;
        bool fBegun = WalletSQLiteRuntimeBeginTxn() && CWalletDB().WriteSetting("wf-outer", (int64)1) &&
                      WalletSQLiteRuntimeBeginTxn() && CWalletDB().WriteSetting("wf-inner", (int64)2);
        WalletSQLiteRuntimeRollbackTxn();
        bool fCommitted = WalletSQLiteRuntimeCommitTxn();
        nFail += Check(fBegun && !fCommitted && !CWalletDB().ReadSetting("wf-outer", n) &&
                       !CWalletDB().ReadSetting("wf-inner", n),
                       "an inner rollback dooms the outer transaction: its commit fails and neither write stays") ? 0 : 1;
        bool fNested = WalletSQLiteRuntimeBeginTxn() && CWalletDB().WriteSetting("wf-outer", (int64)3) &&
                       WalletSQLiteRuntimeBeginTxn() && CWalletDB().WriteSetting("wf-inner", (int64)4) &&
                       WalletSQLiteRuntimeCommitTxn() && WalletSQLiteRuntimeCommitTxn();
        int64 a = 0, b = 0;
        nFail += Check(fNested && CWalletDB().ReadSetting("wf-outer", a) && a == 3 &&
                       CWalletDB().ReadSetting("wf-inner", b) && b == 4,
                       "nested brackets that both commit keep both writes") ? 0 : 1;
    }

    std::map<std::string, int> before = WfCountRecords();
    unsigned int nRecv = nHDReceiveNext, nChange = nHDChangeNext;
    // Three writes succeed (the default key, then the two seed halves), the
    // fourth -- the schema -- fails, inside the install's transaction.
    nWalletSQLiteWritesBeforeFailForTest = 3;
    bool fInstalled = SetHDSeedFromMnemonic(WF_PHRASE_B, "", err);
    nWalletSQLiteWritesBeforeFailForTest = -1;
    nFail += Check(!fInstalled, strprintf("a seed install whose fourth write fails is refused (%s)", err.c_str()).c_str()) ? 0 : 1;
    nFail += Check(WfReloadWallet() && WalletSQLiteRuntimeActive(), "the wallet loads again from SQLite") ? 0 : 1;
    std::map<std::string, int> after = WfCountRecords();
    after["key"] -= 1;   // the new default key, stored before the transaction on purpose
    nFail += Check(vchHDMaster == mA.privateKey && nHDReceiveNext == nRecv && nHDChangeNext == nChange &&
                   after == before && after["pool"] == KEYPOOL_SIZE,
                   "on disk the old seed, counters and full pool are all still there: the transaction rolled back") ? 0 : 1;
    return nFail;
}

extern map<uint256, CBlock*> mapOrphanBlocks;
extern multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

// GetNextWorkRequired as it was before the walk stopped at genesis, with the
// assert turned into fPastGenesis: the reference every real chain must still
// match.
static unsigned int OldGetNextWorkRequired(const CBlockIndex* pindexLast, bool& fPastGenesis)
{
    const unsigned int nTargetSpacing  = 2 * 60;
    const unsigned int nInterval       = 30;
    const unsigned int nTargetTimespan = nInterval * nTargetSpacing;
    fPastGenesis = false;
    if (pindexLast == NULL)
        return bnProofOfWorkLimit.GetCompact();
    if ((pindexLast->nHeight+1) % nInterval != 0)
        return pindexLast->nBits;
    int nWindow = RulesV2Active(pindexLast->nTime) ? nInterval : nInterval-1;
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nWindow; i++)
        pindexFirst = pindexFirst->pprev;
    if (!pindexFirst)
    {
        fPastGenesis = true;
        return 0;
    }
    unsigned int nActualTimespan = pindexLast->nTime - pindexFirst->nTime;
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;
    return bnNew.GetCompact();
}

// A chain of nLength made-up index entries (not in mapBlockIndex), times and
// nBits as given.
static void FakeChain(std::vector<CBlockIndex>& v, int nLength)
{
    v.clear();
    v.resize(nLength);
    for (int h = 0; h < nLength; h++)
    {
        v[h].nHeight = h;
        v[h].pprev = h ? &v[h - 1] : NULL;
    }
}

static unsigned int CompactOf(const CBigNum& bn)
{
    return bn.GetCompact();
}

// Consensus-adjacent safety fixes that need no data directory: the retarget
// walk at genesis, the block template's rules, nBits in CheckBlock, the
// replacement fee overflow, the failed-block mark, which side blocks and
// orphans are kept, and the orphan pool's byte ceiling.
static int RunConsensusSafetySelfTest()
{
    fflush(stdout);
    printf("consensus-safety self-test\n");
    int nFail = 0;
    // The node's own log lines (CheckBlock's errors, MarkBlockFailed) go to a
    // throwaway data directory, not the developer's.
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    std::vector<CBlockIndex*> vMade;
    MapCheckpoints mapSaved = mapCheckpoints;
    CBlockIndex* pindexBestSaved = pindexBest;
    int nBestHeightSaved = nBestHeight;
    const unsigned int nFloor  = bnProofOfWorkLimit.GetCompact();
    const unsigned int nHard4  = CompactOf(bnProofOfWorkLimit / 4);
    const unsigned int nHard16 = CompactOf(bnProofOfWorkLimit / 16);
    const unsigned int nHard64 = CompactOf(bnProofOfWorkLimit / 64);
    try
    {
        // ---- 1. GetNextWorkRequired at the first retarget
        {
            std::vector<CBlockIndex> v;
            FakeChain(v, 30);
            for (int h = 0; h < 30; h++)
            {
                v[h].nTime = RulesV2Time() + 1000 + 120 * h;
                v[h].nBits = nFloor;
            }
            bool fPast = false;
            OldGetNextWorkRequired(&v[29], fPast);
            nFail += Check(fPast, "a v2-timestamped branch from genesis: block 29's window reaches past genesis (the old assert)") ? 0 : 1;
            unsigned int nBits = GetNextWorkRequired(&v[29]);
            CBigNum bn;
            bn.SetCompact(nBits);
            nFail += Check(nBits != 0 && bn > 0 && bn <= bnProofOfWorkLimit,
                           "the new walk stops at genesis and gives a real target, no abort") ? 0 : 1;
            CBigNum bnExpect;
            bnExpect.SetCompact(nFloor);
            bnExpect *= 29 * 120;
            bnExpect /= 3600;
            nFail += Check(nBits == bnExpect.GetCompact(), "measured over the 29 blocks there are") ? 0 : 1;

            for (int h = 0; h < 30; h++)
                v[h].nTime = RulesV2Time() - 100000 + 120 * h;
            unsigned int nOld = OldGetNextWorkRequired(&v[29], fPast);
            nFail += Check(!fPast && GetNextWorkRequired(&v[29]) == nOld,
                           "a pre-v2 block 29 lands on genesis, as it always did, with the same answer") ? 0 : 1;
        }
        {
            // Every height of many made-up chains whose window does not pass
            // genesis: the same answer as before, timestamps going backwards,
            // across the v2 switch, at several difficulties.
            unsigned int nSeed = 12345;
            int nCompared = 0, nDiffer = 0, nRetargets = 0;
            const unsigned int vBits[4] = { nFloor, nHard4, nHard16, CompactOf(bnProofOfWorkLimit / 3) };
            for (int nChain = 0; nChain < 40; nChain++)
            {
                std::vector<CBlockIndex> v;
                FakeChain(v, 300);
                unsigned int nTime = RulesV2Time() - 120 * 30 * (nChain % 8);
                for (int h = 0; h < 300; h++)
                {
                    nSeed = nSeed * 1103515245 + 12345;
                    int nStep = (int)((nSeed >> 8) % 1800) - 300;
                    nTime = (unsigned int)((int64)nTime + nStep);
                    v[h].nTime = nTime;
                    v[h].nBits = vBits[(nSeed >> 20) % 4];
                }
                for (int h = 0; h < 300; h++)
                {
                    bool fPast = false;
                    unsigned int nOld = OldGetNextWorkRequired(&v[h], fPast);
                    if (fPast)
                        continue;
                    nCompared++;
                    if ((h + 1) % 30 == 0)
                        nRetargets++;
                    if (GetNextWorkRequired(&v[h]) != nOld)
                        nDiffer++;
                }
            }
            printf("  info compared %d heights (%d retargets) on 40 chains\n", nCompared, nRetargets);
            nFail += Check(nCompared > 11000 && nRetargets > 350 && nDiffer == 0,
                           "every height whose window stays on the chain: the same nBits as before") ? 0 : 1;
        }

        // ---- 7. The block template's rules follow its own time
        {
            nFail += Check(!(RuleSetAt(RulesV3Time() - 1) & 2) && (RuleSetAt(RulesV3Time()) & 2) &&
                           RuleSetAt(RulesV3Time() - 1) != RuleSetAt(RulesV3Time()),
                           "a template moved across the v3 switch sees another rule set, and is rebuilt") ? 0 : 1;
            nFail += Check(!(RuleSetAt(RulesV2Time() - 1) & 1) && (RuleSetAt(RulesV2Time()) & 1),
                           "and across the v2 switch") ? 0 : 1;
            nFail += Check(RuleSetAt(RulesV4Time() - 1) != RuleSetAt(RulesV4Time()),
                           "and across the v4 switch, as before") ? 0 : 1;

            std::vector<CBlockIndex> v;
            FakeChain(v, 20);
            for (int h = 0; h < 20; h++)
                v[h].nTime = RulesV3Time() - 5000 + 120 * h;
            CTransaction tx;
            tx.vin.resize(1);
            tx.vin[0].prevout = COutPoint(uint256(77), 0);
            tx.vin[0].nSequence = 0;
            tx.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
            tx.nLockTime = 19;   // the height of the template's parent
            nBestHeight = 19;
            nFail += Check(!IsFinalForBlock(tx, &v[19], RulesV3Time() - 1),
                           "a template timed before v3: the old rule (lock time below the best height), not final") ? 0 : 1;
            nFail += Check(IsFinalForBlock(tx, &v[19], RulesV3Time()),
                           "the same template timed at v3: IsFinalAt(next height), final -- the template's time decides") ? 0 : 1;
            nBestHeight = nBestHeightSaved;
        }

        // ---- 14. Zero and negative nBits
        {
            CBlock block;
            CTransaction cb;
            cb.vin.resize(1);
            cb.vin[0].prevout.SetNull();
            cb.vin[0].scriptSig = CScript() << 1 << 2;
            cb.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
            block.vtx.push_back(cb);
            block.nVersion = 1;
            block.nTime = (unsigned int)GetAdjustedTime();
            block.hashMerkleRoot = block.BuildMerkleTree();
            int nDoS = 0;
            block.nBits = 0;
            bool fZero = block.CheckBlock(&nDoS);
            nFail += Check(!fZero && nDoS == 100, "a block with nBits 0 is refused outright") ? 0 : 1;
            nDoS = 0;
            block.nBits = nFloor | 0x00800000;   // the floor with the sign bit set
            bool fNeg = block.CheckBlock(&nDoS);
            nFail += Check(!fNeg && nDoS == 100, "a block with a negative target is refused outright, not hashed against its magnitude") ? 0 : 1;
            nDoS = 0;
            block.nBits = 0x00123456;            // zero size: the value is 0
            bool fEmpty = block.CheckBlock(&nDoS);
            nFail += Check(!fEmpty && nDoS == 100, "and so is a compact form whose value is zero") ? 0 : 1;
        }

        // ---- 15. ReplacementPaysEnough at the money limit
        {
            std::string strWhy;
            vector<pair<int64, unsigned int> > vOld;
            vOld.push_back(make_pair((int64)(MAX_MONEY / 2), (unsigned int)90000));
            nFail += Check(ReplacementPaysEnough(MAX_MONEY, 90000, vOld, strWhy),
                           "a replacement paying more per byte at fees near MAX_MONEY passes (the products pass 2^63)") ? 0 : 1;
            vOld.clear();
            vOld.push_back(make_pair((int64)MAX_MONEY, (unsigned int)90000));
            nFail += Check(!ReplacementPaysEnough(MAX_MONEY / 2, 90000, vOld, strWhy),
                           "and one paying less per byte there fails") ? 0 : 1;
            vOld.clear();
            vOld.push_back(make_pair((int64)1000, (unsigned int)200));
            nFail += Check(!ReplacementPaysEnough(1000, 200, vOld, strWhy) &&
                           ReplacementPaysEnough(1000 + FeeForSize(MIN_RELAY_FEE_PER_KB, 200), 200, vOld, strWhy),
                           "ordinary amounts behave as before") ? 0 : 1;
        }

        // ---- 3. The failed mark
        mapCheckpoints.clear();
        {
            CBlockIndex* pr  = ChainWorkTestBlock(NULL, nFloor, 50000, vMade);
            CBlockIndex* pa1 = ChainWorkTestBlock(pr,  nFloor, 50001, vMade);
            CBlockIndex* pa2 = ChainWorkTestBlock(pa1, nFloor, 50002, vMade);
            CBlockIndex* pb3 = ChainWorkTestBlock(pa2, nFloor, 50003, vMade);
            CBlockIndex* pc3 = ChainWorkTestBlock(pa2, nFloor, 50013, vMade);
            CBlockIndex* pc4 = ChainWorkTestBlock(pc3, nHard64, 50014, vMade);
            CBlockIndex* pd2 = ChainWorkTestBlock(pa1, nFloor, 50022, vMade);
            std::vector<CBlockIndex*> vMarked = MarkBlockFailed(pa2);
            nFail += Check(vMarked.size() == 4 && pa2->fFailed && pb3->fFailed && pc3->fFailed && pc4->fFailed,
                           "a failed block and every descendant, on both of its branches, are marked") ? 0 : 1;
            nFail += Check(!pr->fFailed && !pa1->fFailed && !pd2->fFailed,
                           "its ancestors and its sibling are not") ? 0 : 1;
            nFail += Check(MarkBlockFailed(pa2).empty(), "marking it again marks nothing new") ? 0 : 1;
            CBlockIndex* pc5 = ChainWorkTestBlock(pc4, nFloor, 50015, vMade);
            nFail += Check(pc5->fFailed, "a block added later on top of a marked one is marked as it is indexed") ? 0 : 1;
            nFail += Check(pc5->nChainWork > pd2->nChainWork && !IsBetterChain(pc5, pd2) && IsBetterChain(pd2, pc5),
                           "more work does not make a failed branch the better chain") ? 0 : 1;
        }

        // ---- 11. Which orphans are held, against a best chain M of ten
        // blocks at 64 times the floor's difficulty on a floor root. (Side
        // blocks with a parent here are stored whatever their work: see
        // reorg-safety.)
        {
            CBlockIndex* pm = ChainWorkTestBlock(NULL, nFloor, 60000, vMade);
            pm->nTime = 1800000000;
            std::vector<CBlockIndex*> vm(1, pm);
            for (int i = 1; i <= 10; i++)
            {
                CBlockIndex* p = ChainWorkTestBlock(pm, nHard64, 60000 + i, vMade);
                p->nTime = 1800000000 + 120 * i;
                pm->pnext = p;
                pm = p;
                vm.push_back(p);
            }
            pindexBest = pm;
            nBestHeight = pm->nHeight;
            unsigned int nTip = pm->nTime;
            CBlock orphan;
            orphan.nBits = nFloor;
            orphan.nTime = nTip;
            nFail += Check(!OrphanBlockWorthKeeping(orphan), "synced, no checkpoints: an orphan 64 times easier than the tip is not held") ? 0 : 1;
            orphan.nBits = nHard16;
            nFail += Check(OrphanBlockWorthKeeping(orphan), "one within the slack is") ? 0 : 1;
            orphan.nBits = nFloor;
            orphan.nTime = nTip + 2 * 3600 - 1;
            nFail += Check(!OrphanBlockWorthKeeping(orphan), "a floor one dated just under two hours after the tip is not") ? 0 : 1;
            orphan.nTime = nTip + 4 * 3600;
            nFail += Check(OrphanBlockWorthKeeping(orphan), "four hours after a stale tip it is (four times per two hours)") ? 0 : 1;
            orphan.nBits = 0;
            nFail += Check(!OrphanBlockWorthKeeping(orphan), "a zero target is not") ? 0 : 1;
            orphan.nBits = nFloor;
            orphan.nTime = nTip;
            mapCheckpoints[50] = uint256(424242);
            nFail += Check(OrphanBlockWorthKeeping(orphan),
                           "while the best chain lacks the newest checkpoint (still syncing), nothing is refused") ? 0 : 1;
            mapCheckpoints.clear();
            mapCheckpoints[5] = vm[5]->GetBlockHash();
            nFail += Check(!OrphanBlockWorthKeeping(orphan), "once it holds the checkpoint, the filter applies") ? 0 : 1;
            mapCheckpoints.clear();
            pindexBest = pindexBestSaved;
            nBestHeight = nBestHeightSaved;
        }

        // ---- The check at load does not use the clock
        {
            CBlock block;
            CTransaction cb;
            cb.vin.resize(1);
            cb.vin[0].prevout.SetNull();
            cb.vin[0].scriptSig = CScript() << 1 << 3;
            cb.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
            block.vtx.push_back(cb);
            block.nVersion = 1;
            block.nTime = (unsigned int)GetAdjustedTime() + 3 * 3600;
            block.nBits = 0;   // refused further on, with score 100
            block.hashMerkleRoot = block.BuildMerkleTree();
            int nDoS = -1;
            bool fTimed = block.CheckBlock(&nDoS, true);
            nFail += Check(!fTimed && nDoS == 0, "a block three hours ahead of the clock fails the time test (score 0)") ? 0 : 1;
            nDoS = -1;
            bool fUntimed = block.CheckBlock(&nDoS, false);
            nFail += Check(!fUntimed && nDoS == 100, "without the time test (the load check) it gets past it, to the next rule") ? 0 : 1;
        }

        // ---- 11. The orphan pool by bytes
        {
            nFail += Check(mapOrphanBlocks.empty() && nOrphanBlockBytes == 0, "the orphan pool starts empty") ? 0 : 1;
            unsigned int nMaxSeen = 0;
            for (int i = 0; i < 40; i++)
            {
                CBlock* pblock = new CBlock();
                CTransaction cb;
                cb.vin.resize(1);
                cb.vin[0].prevout.SetNull();
                cb.vin[0].scriptSig = CScript() << 1 << i;
                cb.vout.push_back(CTxOut(0, CScript() << std::vector<unsigned char>(900000, (unsigned char)i)));
                pblock->vtx.push_back(cb);
                pblock->hashPrevBlock = uint256(900 + i);
                pblock->nNonce = i;
                pblock->hashMerkleRoot = pblock->BuildMerkleTree();
                AddOrphanBlock(pblock);
                LimitOrphanBlocks(MAX_ORPHAN_BLOCKS);
                nMaxSeen = max(nMaxSeen, nOrphanBlockBytes);
            }
            unsigned int nSum = 0;
            for (map<uint256, CBlock*>::iterator mi = mapOrphanBlocks.begin(); mi != mapOrphanBlocks.end(); ++mi)
                nSum += ::GetSerializeSize(*(*mi).second, SER_NETWORK);
            printf("  info %d orphans of ~900 kB held, %u bytes\n", (int)mapOrphanBlocks.size(), nOrphanBlockBytes);
            nFail += Check(nMaxSeen <= MAX_ORPHAN_BLOCK_BYTES && mapOrphanBlocks.size() < 40 && mapOrphanBlocks.size() >= 30,
                           "40 orphans of 900 kB: the pool stays under its byte ceiling, below the count ceiling") ? 0 : 1;
            nFail += Check(nSum == nOrphanBlockBytes && mapOrphanBlocksByPrev.size() == mapOrphanBlocks.size(),
                           "the byte count matches what is held, and both maps agree") ? 0 : 1;
            LimitOrphanBlocks(0);
            nFail += Check(mapOrphanBlocks.empty() && mapOrphanBlocksByPrev.empty() && nOrphanBlockBytes == 0,
                           "emptied, nothing is counted") ? 0 : 1;
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    pindexBest = pindexBestSaved;
    nBestHeight = nBestHeightSaved;
    for (size_t i = 0; i < vMade.size(); i++)
    {
        mapBlockIndex.erase(vMade[i]->GetBlockHash());
        delete vMade[i];
    }
    mapCheckpoints = mapSaved;
    RemoveTree(tmp);

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- reorg-safety: a real data directory, real blocks (no proof of work:
// AcceptBlock does not check it, CheckBlock does), real reorganizations.

static unsigned int nReorgTestSalt = 1;
static unsigned int nReorgTestStart = 0;

static CBlock ReorgTestBlock(const CBlockIndex* pindexPrev, const std::vector<CTransaction>& vtxExtra,
                             int64 nCoinbase = 50 * COIN, unsigned int nSpacing = 120)
{
    CBlock block;
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << (pindexPrev->nHeight + 1) << (int64)(nReorgTestSalt++);
    cb.vout.push_back(CTxOut(nCoinbase, CScript() << OP_TRUE));
    block.vtx.push_back(cb);
    block.vtx.insert(block.vtx.end(), vtxExtra.begin(), vtxExtra.end());
    block.nVersion = 1;
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    block.nTime = max(pindexPrev->nTime, nReorgTestStart) + nSpacing;
    block.nBits = GetNextWorkRequired(pindexPrev);
    block.nNonce = nReorgTestSalt;
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

// Accept a block as AcceptBlock does for a peer's; its index entry, or NULL.
static CBlockIndex* ReorgTestAccept(const CBlock& blockIn, bool* pfAccepted = NULL)
{
    CBlock block = blockIn;
    bool fOk = false;
    CRITICAL_BLOCK(cs_main)
        fOk = block.AcceptBlock();
    if (pfAccepted)
        *pfAccepted = fOk;
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    return mi == mapBlockIndex.end() ? NULL : (*mi).second;
}

static CBlockIndex* ReorgTestExtend(CBlockIndex* pindexPrev, const std::vector<CTransaction>& vtx = std::vector<CTransaction>(),
                                    int64 nCoinbase = 50 * COIN)
{
    bool fOk = false;
    CBlockIndex* p = ReorgTestAccept(ReorgTestBlock(pindexPrev, vtx, nCoinbase), &fOk);
    return fOk ? p : NULL;
}

static CTransaction ReorgTestSpend(const uint256& hashPrev, unsigned int n, int64 nValue, bool fStandardOut,
                                   unsigned int nLockTime = 0, unsigned int nSequence = SEQUENCE_FINAL)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(hashPrev, n);
    tx.vin[0].nSequence = nSequence;
    tx.nLockTime = nLockTime;
    CScript out;
    if (fStandardOut)
        out << OP_DUP << OP_HASH160 << uint160(nReorgTestSalt++) << OP_EQUALVERIFY << OP_CHECKSIG;
    else
        out << OP_TRUE;
    tx.vout.push_back(CTxOut(nValue, out));
    return tx;
}

// Every pprev in the index is NULL or an entry of the index. Compares pointer
// values only: nothing is read through them.
static bool IndexHasNoDanglingParent()
{
    set<const CBlockIndex*> setEntries;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        setEntries.insert((*mi).second);
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        if ((*mi).second->pprev && !setEntries.count((*mi).second->pprev))
            return false;
    return true;
}

// Forget the in-memory chain and read the index again, as a restart does.
static bool ReorgTestReload()
{
    SelfTestFreeBlockIndex();
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        mapTransactions.clear();
        mapNextTx.clear();
    }
    DBFlush(false);
    return LoadBlockIndex();
}

// Where the check at load will roll a best chain ending at ptip back to when
// it looks at nCheck blocks: the parent of the oldest one that fails
// CheckBlock (without the clock test), as CTxDB::LoadBlockIndex does.
static int ReorgTestExpectedRollback(const CBlockIndex* ptip, int nCheck, uint256* phFirstBad)
{
    int nFork = ptip->nHeight;
    int nChecked = 0;
    for (const CBlockIndex* p = ptip; p && p->pprev && nChecked < nCheck; p = p->pprev, nChecked++)
    {
        CBlock block;
        if (block.ReadFromDisk(p, true) && !block.CheckBlock(NULL, false))
        {
            nFork = p->nHeight - 1;
            if (phFirstBad)
                *phFirstBad = p->GetBlockHash();
        }
    }
    return nFork;
}

static int RunReorgSafetySelfTest()
{
    printf("reorg-safety self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    try
    {
        if (!LoadBlockIndex() || pindexBest == NULL || pindexBest->nHeight != 0)
            throw std::runtime_error("LoadBlockIndex failed");
        // Recent v2 timestamps, so the chain from genesis meets rules v2
        // (BIP34) -- and its block 29 is exactly the one that used to abort.
        nReorgTestStart = (unsigned int)GetAdjustedTime() - 400 * 120;
        nFail += Check(RulesV2Active(nReorgTestStart), "the test chain runs under rules v2") ? 0 : 1;

        std::vector<CBlockIndex*> vMain(1, pindexBest);
        for (int h = 1; h <= 110; h++)
        {
            CBlockIndex* p = ReorgTestExtend(vMain.back());
            if (!p)
                throw std::runtime_error(strprintf("block %d not accepted", h));
            vMain.push_back(p);
        }
        nFail += Check(pindexBest == vMain[110] && nBestHeight == 110,
                       "110 blocks from genesis with v2 timestamps, through the first retarget, no abort") ? 0 : 1;

        CBlock blockM1, blockM2, blockM3;
        blockM1.ReadFromDisk(vMain[1], true);
        blockM2.ReadFromDisk(vMain[2], true);
        blockM3.ReadFromDisk(vMain[3], true);
        uint256 hCb1 = blockM1.vtx[0].GetHash(), hCb2 = blockM2.vtx[0].GetHash(), hCb3 = blockM3.vtx[0].GetHash();

        // ---- 9. Only final transactions enter the pool
        {
            CTransaction txLocked = ReorgTestSpend(hCb1, 0, 49 * COIN, true, 1000000, 0);
            nFail += Check(!txLocked.AcceptTransaction(true),
                           "a transaction locked to a height far ahead is not accepted into the pool") ? 0 : 1;
            CRITICAL_BLOCK(cs_mapTransactions)
                nFail += Check(mapTransactions.empty(), "and is not there") ? 0 : 1;
        }

        // ---- Pool hygiene: a block that spends what a pool transaction spends
        CTransaction txC = ReorgTestSpend(hCb1, 0, 49 * COIN, true);
        CTransaction txE = ReorgTestSpend(hCb2, 0, 49 * COIN, true);
        nFail += Check(txC.AcceptTransaction(true) && txE.AcceptTransaction(true),
                       "two final transactions spending mature coinbases are accepted") ? 0 : 1;
        CTransaction txD = ReorgTestSpend(txC.GetHash(), 0, 48 * COIN, true);
        // Its child, unsigned, so straight into the pool as AddToMemoryPool would.
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            mapTransactions[txD.GetHash()] = txD;
            mapNextTx[txD.vin[0].prevout] = CInPoint(&mapTransactions[txD.GetHash()], 0);
        }
        {
            CTransaction txT = ReorgTestSpend(hCb1, 0, 49 * COIN + COIN / 2, false);
            CBlockIndex* p111 = ReorgTestExtend(vMain[110], std::vector<CTransaction>(1, txT));
            nFail += Check(p111 && pindexBest == p111, "a block spending the same coin as the pool's transaction connects") ? 0 : 1;
            CRITICAL_BLOCK(cs_mapTransactions)
            {
                nFail += Check(!mapTransactions.count(txC.GetHash()) && !mapTransactions.count(txD.GetHash()),
                               "the conflicting pool transaction and its child are gone") ? 0 : 1;
                nFail += Check(mapTransactions.count(txE.GetHash()) && mapTransactions.size() == 1,
                               "an unrelated one stays") ? 0 : 1;
                nFail += Check(!mapNextTx.count(COutPoint(hCb1, 0)) && !mapNextTx.count(COutPoint(txC.GetHash(), 0)) &&
                               mapNextTx.count(COutPoint(hCb2, 0)) && mapNextTx.size() == 1,
                               "and the spends index matches the pool") ? 0 : 1;
            }
        }

        // The same through a reorganization: S111, S112 off block 110, S111
        // spending what pool transaction C2 spends.
        CBlockIndex* pS112 = NULL;
        CBlockIndex* pS111 = NULL;
        {
            CTransaction txC2 = ReorgTestSpend(hCb3, 0, 49 * COIN, true);
            nFail += Check(txC2.AcceptTransaction(true), "another pool transaction is accepted") ? 0 : 1;
            CTransaction txT2 = ReorgTestSpend(hCb3, 0, 49 * COIN + COIN / 2, false);
            pS111 = ReorgTestExtend(vMain[110], std::vector<CTransaction>(1, txT2));
            nFail += Check(pS111 && pindexBest != pS111, "a rival block 111 spending the same coin is kept on the side") ? 0 : 1;
            pS112 = pS111 ? ReorgTestExtend(pS111) : NULL;
            nFail += Check(pS112 && pindexBest == pS112, "its child makes that branch the best: reorganized") ? 0 : 1;
            CRITICAL_BLOCK(cs_mapTransactions)
                nFail += Check(!mapTransactions.count(txC2.GetHash()) && !mapNextTx.count(COutPoint(hCb3, 0)) &&
                               mapTransactions.count(txE.GetHash()),
                               "the pool transaction it conflicts with is gone after the reorganization") ? 0 : 1;
        }
        if (!pS112)
            throw std::runtime_error("the reorganization did not happen");

        // ---- 3. A block that fails to connect, with two children
        CBlockIndex* pTip = pS112;
        for (int i = 0; i < 3; i++)
            pTip = ReorgTestExtend(pTip);
        nFail += Check(pTip && pindexBest == pTip && nBestHeight == 115, "the best chain is at 115") ? 0 : 1;
        if (!pTip)
            throw std::runtime_error("could not extend the best chain");
        CBlockIndex* pX112 = ReorgTestExtend(pS111);
        CBlockIndex* pX113 = pX112 ? ReorgTestExtend(pX112, std::vector<CTransaction>(), 51 * COIN) : NULL;   // pays itself too much
        CBlockIndex* pY114 = pX113 ? ReorgTestExtend(pX113) : NULL;
        CBlockIndex* pZ114 = pX113 ? ReorgTestExtend(pX113) : NULL;
        CBlockIndex* pY115 = pY114 ? ReorgTestExtend(pY114) : NULL;
        nFail += Check(pX112 && pX113 && pY114 && pZ114 && pY115 && pindexBest == pTip,
                       "a side branch whose block 113 overpays, with two children, is stored, not yet the best") ? 0 : 1;
        if (!pY115 || !pZ114)
            throw std::runtime_error("could not build the failing branch");
        uint256 hX113 = pX113->GetBlockHash(), hY114 = pY114->GetBlockHash(), hZ114 = pZ114->GetBlockHash();
        CBlock blockY116 = ReorgTestBlock(pY115, std::vector<CTransaction>());
        bool fY116 = true;
        CBlockIndex* pY116 = ReorgTestAccept(blockY116, &fY116);
        nFail += Check(!fY116 && pindexBest == pTip && nBestHeight == 115,
                       "the block that would make it the best fails in Reorganize, and the best chain stays") ? 0 : 1;
        nFail += Check(IndexHasNoDanglingParent(), "no index entry points at a deleted parent") ? 0 : 1;
        nFail += Check(mapBlockIndex.count(hX113) && mapBlockIndex.count(hY114) && mapBlockIndex.count(hZ114) &&
                       pY116 != NULL && pZ114->pprev == pX113,
                       "the failed block and its children stay in the index") ? 0 : 1;
        nFail += Check(pX113->fFailed && pY114->fFailed && pZ114->fFailed && pY115->fFailed && pY116 && pY116->fFailed &&
                       !pX112->fFailed && !pTip->fFailed,
                       "marked failed: it and every descendant, on the branch that was tried and the other") ? 0 : 1;
        nFail += Check(pY116 && pY116->nChainWork > pTip->nChainWork && !IsBetterChain(pY116, pTip),
                       "more work, never the better chain") ? 0 : 1;
        {
            bool fOk = true;
            ReorgTestAccept(ReorgTestBlock(pZ114, std::vector<CTransaction>()), &fOk);
            nFail += Check(!fOk, "a block on the other child is refused (the old code walked freed memory here)") ? 0 : 1;
            CBlock blockAgain;
            blockAgain.ReadFromDisk(pX113, true);
            ReorgTestAccept(blockAgain, &fOk);
            nFail += Check(!fOk && pindexBest == pTip, "the failed block sent again changes nothing") ? 0 : 1;
        }
        fCheckpointWalkBack = true;
        nFail += Check(ActivateBestKnownChain() && pindexBest == pTip,
                       "ActivateBestKnownChain does not pick the failed branch") ? 0 : 1;
        CBlockIndex* p116 = ReorgTestExtend(pTip);
        nFail += Check(p116 && pindexBest == p116 && nBestHeight == 116, "the best chain goes on") ? 0 : 1;
        if (!p116)
            throw std::runtime_error("could not extend the best chain after the failure");
        uint256 hTip = p116->GetBlockHash();
        uint256 hS111 = pS111->GetBlockHash(), hS112 = pS112->GetBlockHash(), hX112 = pX112->GetBlockHash();

        // ---- A failure that is this node's, not the block's, marks nothing.
        // The index places this coin in a block file that does not exist, so
        // reading it fails here -- a stand-in for a file another program
        // holds open, or a database that cannot answer.
        {
            CTransaction txGhost;
            txGhost.vin.resize(1);
            txGhost.vin[0].prevout = COutPoint(uint256(31337), 0);
            txGhost.vout.push_back(CTxOut(10 * COIN, CScript() << OP_TRUE));
            {
                CTxDB txdb;
                txdb.AddTxIndex(txGhost, CDiskTxPos(99, 0, 0), 1);
                txdb.Close();
            }
            std::vector<CTransaction> vUse(1, ReorgTestSpend(txGhost.GetHash(), 0, 9 * COIN, false));
            CBlock blockL = ReorgTestBlock(p116, vUse);
            bool fOk = true;
            CBlockIndex* pL = ReorgTestAccept(blockL, &fOk);
            nFail += Check(!fOk && pL == NULL && pindexBest == p116,
                           "a block that fails on a local read error is not marked: it is forgotten (extending the tip)") ? 0 : 1;
            pL = ReorgTestAccept(blockL, &fOk);
            nFail += Check(!fOk && pL == NULL, "and the same block sent again is tried again, not \"already have\"") ? 0 : 1;

            CBlockIndex* pQ116 = ReorgTestExtend(pTip);
            CBlock blockQ117 = ReorgTestBlock(pQ116 ? pQ116 : pTip, vUse);
            CBlockIndex* pQ117 = pQ116 ? ReorgTestAccept(blockQ117, &fOk) : NULL;
            nFail += Check(pQ116 && pQ117 && !fOk && pindexBest == p116 && !pQ117->fFailed && !pQ116->fFailed &&
                           IsBetterChain(pQ117, p116),
                           "in a reorganization: not marked, and still the better candidate, to be tried again") ? 0 : 1;
            CBlockIndex* pQ118 = pQ117 ? ReorgTestAccept(ReorgTestBlock(pQ117, std::vector<CTransaction>()), &fOk) : NULL;
            nFail += Check(pQ118 && !fOk && !pQ118->fFailed && pindexBest == p116,
                           "the next block on that branch tries again (and fails again, unmarked)") ? 0 : 1;
        }

        // ---- 10. The check at load fails these blocks (they carry no proof of
        // work; one may pass the floor by chance, so the expected answer is
        // worked out first, the way the load check does it). Only the last
        // five are checked, so the repair rolls back to about 111 and marks
        // from the first bad block up -- not everything.
        int nCheckSaved = nCheckBlocksOnLoad;
        nCheckBlocksOnLoad = 5;
        uint256 hFirstBad = 0;
        int nExpect = ReorgTestExpectedRollback(p116, 5, &hFirstBad);
        printf("  info the load check should roll back to %d\n", nExpect);
        if (!ReorgTestReload())
            throw std::runtime_error("reload failed");
        nFail += Check(!mapBlockIndex.count(hX113) && !mapBlockIndex.count(hZ114),
                       "blocks marked in Reorganize are off the disk index after a restart") ? 0 : 1;
        nFail += Check(nExpect < 116 && nExpect >= 111 && nBestHeight == nExpect,
                       "the load check of the last five blocks rolled back to just below the first bad one") ? 0 : 1;
        if (mapBlockIndex.count(hTip) && mapBlockIndex.count(hFirstBad) && mapBlockIndex.count(hX112) && pindexBest)
        {
            CBlockIndex* pOldTip = mapBlockIndex[hTip];
            nFail += Check(pOldTip->fFailed && mapBlockIndex[hFirstBad]->fFailed && !pindexBest->fFailed &&
                           !pindexBest->pprev->fFailed && !IsBetterChain(pOldTip, pindexBest),
                           "the first bad block and everything above it are marked; below it, nothing") ? 0 : 1;
            nFail += Check(!mapBlockIndex[hX112]->fFailed,
                           "a side block off 111, not built on the first bad block, is not marked") ? 0 : 1;
            bool fOk = true;
            ReorgTestAccept(ReorgTestBlock(pOldTip, std::vector<CTransaction>()), &fOk);
            nFail += Check(!fOk && nBestHeight == nExpect,
                           "a new block on the old tip is refused: the repair is not undone") ? 0 : 1;
            nFail += Check(IndexHasNoDanglingParent(), "and the index has no dangling parent") ? 0 : 1;
        }
        else
        {
            printf("  FAIL the old tip, the first bad block or the side block off 111 is missing after the restart\n");
            nFail++;
        }
        uint256 hFirstBad2 = 0;
        int nExpect2 = pindexBest ? ReorgTestExpectedRollback(pindexBest, 5, &hFirstBad2) : -1;
        if (!ReorgTestReload())
            throw std::runtime_error("second reload failed");
        nFail += Check(!mapBlockIndex.count(hTip) && !mapBlockIndex.count(hFirstBad),
                       "a second restart does not read the marked blocks back") ? 0 : 1;
        nFail += Check(nBestHeight == nExpect2 && mapBlockIndex.count(hS111),
                       "and checks its own last five again, with the same rule") ? 0 : 1;
        nCheckBlocksOnLoad = nCheckSaved;
        CBlockIndex* pNext = ReorgTestExtend(pindexBest);
        nFail += Check(pNext && pindexBest == pNext, "the chain grows again from where the repair left it") ? 0 : 1;
        if (!pNext)
            throw std::runtime_error("could not extend after the second restart");

        // ---- 5. A side block far weaker than the tip is stored: no admission
        // rule by work (it could strand a node on the lighter chain). Seconds
        // between blocks make each retarget four times harder; three of them
        // put the tip at 64 times the floor's difficulty.
        CBlockIndex* pHard = pNext;
        for (int i = 0; i < 103 && pHard; i++)
            pHard = ReorgTestAccept(ReorgTestBlock(pHard, std::vector<CTransaction>(), 50 * COIN, 1));
        if (!pHard || pindexBest != pHard)
            throw std::runtime_error("could not build the hard chain");
        CBigNum bnTip, bnFloor;
        bnTip.SetCompact(pHard->nBits);
        bnFloor.SetCompact(GetNextWorkRequired(pNext));
        nFail += Check(bnTip * 32 <= bnFloor, "the tip's target is more than 16 times harder than the fork's") ? 0 : 1;
        bool fWeak = false;
        CBlockIndex* pWeak = ReorgTestAccept(ReorgTestBlock(pNext, std::vector<CTransaction>()), &fWeak);
        nFail += Check(fWeak && pWeak && pindexBest == pHard && !pWeak->fFailed,
                       "a side block 64 times easier than the tip is stored, not the best") ? 0 : 1;
        CBlockIndex* pWeak2 = pWeak ? ReorgTestExtend(pWeak) : NULL;
        nFail += Check(pWeak2 != NULL && pindexBest == pHard, "and so is the next block on it") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    fCheckpointWalkBack = false;
    // The chain and its side branches (the weak blocks above, the marked
    // branch the loader read back).
    SelfTestFreeBlockIndex();
    DBFlush(true);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// p2p-dos: the bounds on what one peer can make this node hold or do.
// ---------------------------------------------------------------------------

// A peer whose version message has been read, with an empty send buffer that
// frames at the current protocol.
static CNode* P2PDoSPeer(bool fInbound = false)
{
    CNode* p = new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), fInbound);
    p->nVersion = VERSION;
    p->vSend.clear();
    p->vSend.SetVersion(VERSION);
    p->vRecv.SetVersion(VERSION);
    return p;
}

// Append one framed message to a peer's receive buffer.
static void P2PDoSQueue(CNode& node, const char* pszCommand, const CDataStream& payload)
{
    CMessageHeader hdr(pszCommand, payload.size());
    if (node.vRecv.GetVersion() >= PROTO_CHECKSUM_VERSION)
    {
        uint256 hash = Hash(payload.begin(), payload.end());
        memcpy(&hdr.nChecksum, &hash, sizeof(hdr.nChecksum));
    }
    CDataStream ss(SER_NETWORK, node.vRecv.GetVersion());
    ss << hdr;
    node.vRecv.insert(node.vRecv.end(), ss.begin(), ss.end());
    node.vRecv.insert(node.vRecv.end(), payload.begin(), payload.end());
}

// The commands queued in a peer's send buffer, in order, with their sizes.
static std::vector<std::string> P2PDoSSent(CNode& node, std::vector<unsigned int>* pvSizes = NULL)
{
    std::vector<std::string> v;
    unsigned int nHdr = CMessageHeader::SizeOnWire(node.vSend.GetVersion());
    size_t pos = 0;
    while (pos + nHdr <= node.vSend.size())
    {
        CDataStream h(node.vSend.begin() + pos, node.vSend.begin() + pos + nHdr,
                      SER_NETWORK, node.vSend.GetVersion());
        CMessageHeader hdr;
        h >> hdr;
        v.push_back(hdr.GetCommand());
        if (pvSizes)
            pvSizes->push_back(hdr.nMessageSize);
        pos += nHdr + hdr.nMessageSize;
    }
    return v;
}

static bool P2PDoSProcess(CNode* p, const char* pszCommand, CDataStream& ss)
{
    bool fRet = false;
    CRITICAL_BLOCK(cs_main)
        fRet = ProcessMessage(p, pszCommand, ss);
    return fRet;
}

// A block that passes every check CheckBlock makes before the proof-of-work
// hash: one coinbase, floor nBits, merkle root set. Its work is random, so it
// almost always fails the hash itself.
static CBlock P2PDoSBlock(unsigned int nNonce, int64 nTimeOffset)
{
    CBlock block;
    CTransaction txCoinbase;
    txCoinbase.vin.resize(1);
    txCoinbase.vin[0].prevout.SetNull();
    txCoinbase.vin[0].scriptSig = CScript() << (int64)nNonce << 2;
    txCoinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    block.vtx.push_back(txCoinbase);
    block.nBits = bnProofOfWorkLimit.GetCompact();
    block.nTime = GetAdjustedTime() + nTimeOffset;
    block.nNonce = nNonce;
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

static int RunP2PDoSSelfTest()
{
    fflush(stdout);
    printf("p2p-dos self-test\n");
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    std::string strOldDataDir = strSetDataDir;
    strSetDataDir = tmp;
    int nFail = 0;
    std::vector<CBlockIndex*> vMade;
    CBlockIndex* pindexBestSaved = NULL;
    const unsigned int nSendSaved = nSendBufferSize, nRecvSaved = nReceiveFloodSize;
    try
    {
        if (!LoadBlockIndex())
            throw std::runtime_error("LoadBlockIndex failed");
        pindexBestSaved = pindexBest;

        // ---- C1: getdata is queued and served only while the send buffer has room
        {
            CInv invBig(MSG_TX, uint256(0xd05));
            CDataStream ssItem(SER_NETWORK);
            ssItem << std::vector<unsigned char>(20000, 0x5a);
            CRITICAL_BLOCK(cs_mapRelay)
                mapRelay[invBig] = ssItem;

            CNode* p = P2PDoSPeer();
            CDataStream ss(SER_NETWORK);
            ss << std::vector<CInv>(MAX_INV_SZ, invBig);    // one item, asked for 50000 times
            P2PDoSProcess(p, "getdata", ss);
            unsigned int nSent = p->vSend.size();
            size_t nQueued = p->vRecvGetData.size();
            nFail += Check(nSent >= SendBufferSize() && nSent < SendBufferSize() + 2 * ssItem.size(),
                           "one getdata of 50000 copies queues about SendBufferSize(), not 1 GB") ? 0 : 1;
            nFail += Check(nQueued > 0 && nQueued + P2PDoSSent(*p).size() == MAX_INV_SZ,
                           "and the rest waits in the getdata queue") ? 0 : 1;

            p->vSend.clear();                          // the peer read it
            ProcessMessages(p);
            nFail += Check(p->vRecvGetData.size() < nQueued && p->vSend.size() < SendBufferSize() + 2 * ssItem.size(),
                           "as the buffer drains, the queue is served from where it stopped") ? 0 : 1;

            CDataStream ssMore(SER_NETWORK);
            ssMore << std::vector<CInv>(MAX_INV_SZ, invBig);
            P2PDoSProcess(p, "getdata", ssMore);
            nFail += Check(p->vRecvGetData.size() <= MAX_INV_SZ,
                           "asking again without reading never queues more than MAX_INV_SZ") ? 0 : 1;
            delete p;

            CNode* q = P2PDoSPeer();
            CDataStream ssOver(SER_NETWORK);
            ssOver << std::vector<CInv>(MAX_INV_SZ + 1, invBig);
            P2PDoSProcess(q, "getdata", ssOver);
            nFail += Check(q->nMisbehavior == 20 && q->vRecvGetData.empty() && q->vSend.empty(),
                           "a getdata over MAX_INV_SZ is refused and costs 20 points") ? 0 : 1;
            delete q;
            CRITICAL_BLOCK(cs_mapRelay)
                mapRelay.erase(invBig);

            // A batch of blocks that does not end at our tip ends with an inv
            // of the tip; one that does, does not. The only block on disk
            // here is genesis, so the tip is pretended for the first case.
            {
                uint256 hashBestSaved = hashBestChain;
                hashBestChain = uint256(0xbe57);
                CNode* r = P2PDoSPeer();
                CDataStream ssBlock(SER_NETWORK);
                ssBlock << std::vector<CInv>(1, CInv(MSG_BLOCK, hashGenesisBlock));
                P2PDoSProcess(r, "getdata", ssBlock);
                std::vector<std::string> vCmd = P2PDoSSent(*r);
                bool fInvOfTip = false;
                if (vCmd.size() == 2 && vCmd[1] == "inv")
                {
                    unsigned int nHdr = CMessageHeader::SizeOnWire(r->vSend.GetVersion());
                    std::vector<unsigned int> vSizes;
                    P2PDoSSent(*r, &vSizes);
                    size_t nInvAt = nHdr + vSizes[0] + nHdr;
                    CDataStream ssInv(r->vSend.begin() + nInvAt, r->vSend.end(), SER_NETWORK, r->vSend.GetVersion());
                    std::vector<CInv> vInv;
                    ssInv >> vInv;
                    fInvOfTip = vInv.size() == 1 && vInv[0].hash == uint256(0xbe57);
                }
                nFail += Check(vCmd.size() == 2 && vCmd[0] == "block" && fInvOfTip,
                               "a batch of blocks that does not end at our tip is followed by an inv of the tip") ? 0 : 1;
                delete r;
                hashBestChain = hashBestSaved;

                CNode* t = P2PDoSPeer();
                CDataStream ssTip(SER_NETWORK);
                ssTip << std::vector<CInv>(1, CInv(MSG_BLOCK, hashGenesisBlock));
                P2PDoSProcess(t, "getdata", ssTip);
                vCmd = P2PDoSSent(*t);
                nFail += Check(vCmd.size() == 1 && vCmd[0] == "block",
                               "a peer that asks for our tip gets the block and no inv") ? 0 : 1;
                delete t;

                // The block is served, the send buffer fills, and the batch
                // ends in a later call that serves only a transaction.
                hashBestChain = uint256(0xbe57);
                CInv invTx(MSG_TX, uint256(0xd07));
                CDataStream ssTx(SER_NETWORK);
                ssTx << std::vector<unsigned char>(50, 2);
                CRITICAL_BLOCK(cs_mapRelay)
                    mapRelay[invTx] = ssTx;
                CNode* u = P2PDoSPeer();
                u->vSend.resize(SendBufferSize() - 10);
                std::vector<CInv> vMixed;
                vMixed.push_back(CInv(MSG_BLOCK, hashGenesisBlock));
                vMixed.push_back(invTx);
                CDataStream ssMixed(SER_NETWORK);
                ssMixed << vMixed;
                P2PDoSProcess(u, "getdata", ssMixed);
                bool fWaits = u->vRecvGetData.size() == 1;
                u->vSend.clear();
                ProcessMessages(u);
                vCmd = P2PDoSSent(*u);
                nFail += Check(fWaits && vCmd.size() == 2 && vCmd[0] == "tx" && vCmd[1] == "inv" &&
                               u->hashBatchLastBlock == 0,
                               "a batch that ends in a later call serving only a transaction still ends with the tip inv") ? 0 : 1;
                delete u;
                CRITICAL_BLOCK(cs_mapRelay)
                    mapRelay.erase(invTx);
                hashBestChain = hashBestSaved;
            }

            // At version time: a peer behind us is told our tip, and a peer
            // ahead of us is asked for blocks even when we have other peers.
            {
                std::vector<CNode*> vSavedNodes;
                CRITICAL_BLOCK(cs_vNodes)
                    vSavedNodes.swap(vNodes);
                CNode* other1 = P2PDoSPeer();
                CNode* other2 = P2PDoSPeer();
                CRITICAL_BLOCK(cs_vNodes)
                {
                    vNodes.push_back(other1);
                    vNodes.push_back(other2);
                }
                int nBestHeightSaved = nBestHeight;
                nBestHeight = 100;
                VersionGetBlocksResetForTest();
                // behind, level, ahead, ahead again (rate-limited), barely ahead
                int nHeights[5] = { 40, 100, 200, 300, 102 };
                bool fTipInv[5], fGetBlocks[5];
                for (int i = 0; i < 5; i++)
                {
                    CNode* v = new CNode(INVALID_SOCKET, CAddress("127.0.0.1"), true);
                    v->vSend.clear();
                    CDataStream ssVer(SER_NETWORK);
                    ssVer << (int)VERSION << (uint64)NODE_NETWORK << (int64)GetAdjustedTime()
                          << CAddress("127.0.0.1") << nHeights[i] << std::string("1.2.32");
                    P2PDoSProcess(v, "version", ssVer);
                    v->vSend.SetVersion(VERSION);
                    std::vector<std::string> vCmd = P2PDoSSent(*v);
                    fTipInv[i] = std::find(vCmd.begin(), vCmd.end(), "inv") != vCmd.end();
                    fGetBlocks[i] = std::find(vCmd.begin(), vCmd.end(), "getblocks") != vCmd.end();
                    delete v;
                }
                nBestHeight = nBestHeightSaved;
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.swap(vSavedNodes);
                delete other1;
                delete other2;
                nFail += Check(fTipInv[0] && !fTipInv[1] && !fTipInv[2],
                               "at version time a peer behind us, and only that peer, is sent an inv of our tip") ? 0 : 1;
                nFail += Check(fGetBlocks[2] && !fGetBlocks[1],
                               "a peer ahead of us is asked for blocks though we have other peers") ? 0 : 1;
                nFail += Check(!fGetBlocks[3] && !fGetBlocks[4] && !fGetBlocks[0],
                               "but only one such request per five minutes, and not for a peer a few blocks ahead") ? 0 : 1;
                VersionGetBlocksResetForTest();
            }
        }

        // ---- H2: getblocks answers at most 500 and says where to continue
        {
            CBlockIndex* pprev = NULL;
            CBlockIndex* pRoot = NULL;
            CBlockIndex* p500 = NULL;
            for (int i = 0; i < 1200; i++)
            {
                CBlockIndex* pindex = new CBlockIndex();
                map<uint256, CBlockIndex*>::iterator mi =
                    mapBlockIndex.insert(make_pair(uint256(7700000 + i), pindex)).first;
                pindex->phashBlock = &((*mi).first);
                pindex->pprev = pprev;
                pindex->nHeight = i;
                if (pprev)
                    pprev->pnext = pindex;
                vMade.push_back(pindex);
                pprev = pindex;
                if (i == 0) pRoot = pindex;
                if (i == 500) p500 = pindex;
            }
            std::vector<uint256> vHave(1, pRoot->GetBlockHash());

            CNode* p = P2PDoSPeer();
            CDataStream ss(SER_NETWORK);
            ss << CBlockLocator(vHave) << uint256(0);
            P2PDoSProcess(p, "getblocks", ss);
            nFail += Check(p->vInventoryToSend.size() == (size_t)MAX_GETBLOCKS_RESULTS,
                           "a getblocks from far behind gets 500 hashes, not the whole chain") ? 0 : 1;
            nFail += Check(p->vInventoryToSend.back().hash == p500->GetBlockHash(),
                           "and they are the 500 after the locator, in order") ? 0 : 1;

            CDataStream ssStop(SER_NETWORK);
            ssStop << CBlockLocator(vHave) << vMade[11]->GetBlockHash();
            CNode* s = P2PDoSPeer();
            P2PDoSProcess(s, "getblocks", ssStop);
            nFail += Check(s->vInventoryToSend.size() == 10,
                           "hashStop still ends the answer early") ? 0 : 1;
            delete s;

            CNode* q = P2PDoSPeer();
            std::vector<uint256> vLong(MAX_LOCATOR_SZ + 1, pRoot->GetBlockHash());
            CDataStream ssLong(SER_NETWORK);
            ssLong << CBlockLocator(vLong) << uint256(0);
            P2PDoSProcess(q, "getblocks", ssLong);
            nFail += Check(q->nMisbehavior == 20 && q->vInventoryToSend.empty(),
                           "a locator over 101 hashes is refused and costs 20 points") ? 0 : 1;
            delete q;

            // With the send buffer full the answer waits, then goes out.
            CNode* w = P2PDoSPeer();
            w->vSend.resize(SendBufferSize());
            CDataStream ssWait(SER_NETWORK);
            ssWait << CBlockLocator(vHave) << uint256(0);
            P2PDoSProcess(w, "getblocks", ssWait);
            nFail += Check(w->fGetBlocksPending && w->vInventoryToSend.empty(),
                           "a getblocks to a peer that is not reading waits") ? 0 : 1;
            CDataStream ssWait2(SER_NETWORK);
            ssWait2 << CBlockLocator(vHave) << uint256(0);
            P2PDoSProcess(w, "getblocks", ssWait2);
            nFail += Check(w->fGetBlocksPending && w->vInventoryToSend.empty() && w->vSend.size() == SendBufferSize(),
                           "and so does the next, replacing it: nothing piles up") ? 0 : 1;
            w->vSend.clear();
            CRITICAL_BLOCK(w->cs_vSend)
                SendMessages(w);
            std::vector<unsigned int> vSizes;
            std::vector<std::string> vCmd = P2PDoSSent(*w, &vSizes);
            nFail += Check(!w->fGetBlocksPending && vCmd.size() == 1 && vCmd[0] == "inv" &&
                           vSizes[0] == 3 + 36 * (unsigned int)MAX_GETBLOCKS_RESULTS,
                           "once it has room, SendMessages answers it: one inv of 500") ? 0 : 1;
            delete w;
            delete p;
        }

        // ---- H3: inv, mapAskFor, mapAlreadyAskedFor, setInventoryKnown
        {
            mruset<int> m(100);
            for (int i = 0; i < 300; i++)
                m.insert(i);
            nFail += Check(m.size() == 100 && m.count(299) && !m.count(199),
                           "mruset keeps the most recent 100") ? 0 : 1;
            for (int i = 0; i < 10000; i++)
            {
                m.erase(299);
                m.insert(299);
            }
            nFail += Check(m.size() == 100 && m.order_size() <= 2 * 100 + 16,
                           "erase and insert in a loop do not grow it") ? 0 : 1;

            mapAlreadyAskedFor.clear();
            std::vector<CNode*> vPeers;
            for (int n = 0; n < 3; n++)
            {
                CNode* p = P2PDoSPeer();
                vPeers.push_back(p);
                std::vector<CInv> vInv;
                for (unsigned int i = 0; i < MAX_INV_SZ + 10000; i++)
                    vInv.push_back(CInv(MSG_BLOCK, uint256(((uint64)(n + 1) << 32) + i)));
                CDataStream ss(SER_NETWORK);
                ss << vInv;
                P2PDoSProcess(p, "inv", ss);
            }
            nFail += Check(vPeers[0]->nMisbehavior == 0,
                           "an inv over MAX_INV_SZ costs nothing: 1.2.x nodes send whole-chain invs") ? 0 : 1;
            nFail += Check(vPeers[0]->mapAskFor.size() <= MAX_ASKFOR_PER_PEER,
                           "one peer queues at most MAX_ASKFOR_PER_PEER requests") ? 0 : 1;
            nFail += Check(vPeers[0]->setInventoryKnown.size() <= MAX_INVENTORY_KNOWN,
                           "what a peer is known to have is held to MAX_INVENTORY_KNOWN") ? 0 : 1;
            nFail += Check(mapAlreadyAskedFor.size() <= MAX_ALREADY_ASKED_FOR,
                           "three invs of random hashes leave at most MAX_ALREADY_ASKED_FOR behind") ? 0 : 1;
            for (size_t i = 0; i < vPeers.size(); i++)
                delete vPeers[i];

            // Entries more than two minutes in the past go for free.
            mapAlreadyAskedFor.clear();
            int64 nNow = GetTime() * 1000000LL;
            for (int i = 0; i < 1000; i++)
                mapAlreadyAskedFor[CInv(MSG_TX, uint256(9100000 + i))] = nNow - (i < 600 ? 10 * 60 : 30) * 1000000LL;
            PruneAlreadyAskedFor(nNow, MAX_ALREADY_ASKED_FOR);
            nFail += Check(mapAlreadyAskedFor.size() == 400,
                           "requests older than the two-minute stagger are forgotten") ? 0 : 1;
            PruneAlreadyAskedFor(nNow, 100);
            nFail += Check(mapAlreadyAskedFor.size() == 100,
                           "and past the target the oldest go") ? 0 : 1;
            mapAlreadyAskedFor.clear();
        }

        // ---- H1: receive backpressure and a per-pass share for each peer
        {
            nReceiveFloodSize = 1000;
            CNode* p = P2PDoSPeer();
            for (int i = 0; i < 60; i++)
                P2PDoSQueue(*p, "ping", CDataStream(SER_NETWORK));
            nFail += Check(p->RecvFloodPaused(),
                           "over ReceiveFloodSize() with a complete message waiting: not read") ? 0 : 1;
            delete p;

            CNode* q = P2PDoSPeer();
            CDataStream ssBig(SER_NETWORK);
            ssBig << std::vector<unsigned char>(5000, 1);
            P2PDoSQueue(*q, "tx", ssBig);
            q->vRecv.resize(q->vRecv.size() - 2000);       // 3000 of its 5000 bytes so far
            nFail += Check(!q->RecvFloodPaused(),
                           "a message larger than the bound is still read to its end") ? 0 : 1;
            delete q;
            nReceiveFloodSize = nRecvSaved;

            CNode* r = P2PDoSPeer();
            for (int i = 0; i < 250; i++)
                P2PDoSQueue(*r, "ping", CDataStream(SER_NETWORK));
            unsigned int nPing = 24;
            ProcessMessages(r);
            bool fFirst = r->vRecv.size() == 150 * nPing && r->fRecvMorePending;
            ProcessMessages(r);
            ProcessMessages(r);
            nFail += Check(fFirst && r->vRecv.empty() && !r->fRecvMorePending,
                           "a backlog of 250 is taken 100 per pass, and the thread told to come back") ? 0 : 1;
            delete r;
        }

        // ---- H4: a dropped peer is not listened to, and goes without drain grace
        {
            CInv invItem(MSG_TX, uint256(0xd06));
            CDataStream ssItem(SER_NETWORK);
            ssItem << std::vector<unsigned char>(100, 1);
            CRITICAL_BLOCK(cs_mapRelay)
                mapRelay[invItem] = ssItem;
            CDataStream ssGet(SER_NETWORK);
            ssGet << std::vector<CInv>(1, invItem);

            // A peer dropped for misbehavior is not listened to any more; one
            // that is merely on its way out still has what it sent taken.
            CNode* p = P2PDoSPeer();
            p->fDisconnect = true;
            p->fDropWithoutDrain = true;
            P2PDoSQueue(*p, "getdata", ssGet);
            ProcessMessages(p);
            nFail += Check(p->vRecv.empty() && p->vSend.empty(),
                           "a peer dropped for misbehavior: its messages are dropped unread") ? 0 : 1;
            delete p;

            CNode* closing = P2PDoSPeer();
            closing->fDisconnect = true;
            P2PDoSQueue(*closing, "getdata", ssGet);
            ProcessMessages(closing);
            std::vector<std::string> vClosing = P2PDoSSent(*closing);
            nFail += Check(closing->vRecv.empty() && vClosing.size() == 1 && vClosing[0] == "tx",
                           "a peer that only closed: what it already sent is still processed") ? 0 : 1;
            delete closing;

            CNode* q = P2PDoSPeer();
            CDataStream ssEmpty(SER_NETWORK);
            for (int i = 0; i < 5; i++)
            {
                P2PDoSQueue(*q, "ping", ssEmpty);
                // Corrupt the checksum of the ping just queued: with no
                // payload, it is the last four bytes in the buffer.
                q->vRecv[q->vRecv.size() - 4] ^= 0x55;
            }
            P2PDoSQueue(*q, "getdata", ssGet);
            ProcessMessages(q);
            nFail += Check(q->fDisconnect && q->fDropWithoutDrain && q->vSend.empty() && q->vRecv.empty(),
                           "dropped mid-pass for bad checksums: what follows is not processed") ? 0 : 1;
            nFail += Check(NodeReadyToDrop(q, GetTime()),
                           "and it leaves at once, without the drain grace") ? 0 : 1;
            delete q;
            CRITICAL_BLOCK(cs_mapRelay)
                mapRelay.erase(invItem);

            CNode* d = P2PDoSPeer();
            d->fDisconnect = true;
            d->vSend.resize(100);
            d->nDisconnectSince = GetTime();
            bool fWaits = !NodeReadyToDrop(d, GetTime());
            nFail += Check(fWaits && NodeReadyToDrop(d, GetTime() + DISCONNECT_DRAIN_SECS + 1),
                           "an ordinary disconnect still gets its drain grace, bounded") ? 0 : 1;
            delete d;

            // The inbound block budget: a token is spent only by a block that
            // passed every cheap check and is about to be hashed.
            InboundBlockBudgetResetForTest(3, true);
            {
                CNode* in = P2PDoSPeer(true);
                CBlock bFuture = P2PDoSBlock(500, 24 * 60 * 60);
                CDataStream ssB(SER_NETWORK);
                ssB << bFuture;
                P2PDoSProcess(in, "block", ssB);
                CNode* in2 = P2PDoSPeer(true);
                CBlock bEmpty;
                bEmpty.nNonce = 501;
                CDataStream ssE(SER_NETWORK);
                ssE << bEmpty;
                P2PDoSProcess(in2, "block", ssE);
                nFail += Check(InboundBlockBudgetTokensForTest() == 3 && in->nMisbehavior == 0,
                               "a block from the future, or with no coinbase, spends no token") ? 0 : 1;
                delete in;
                delete in2;
            }
            int64 nRefusedBefore = nInboundBlocksRefused;
            int64 nBefore = nBlocksReceived;
            CNode* r = NULL;
            uint256 hashRefused = 0;
            for (int i = 0; i < 5; i++)
            {
                CNode* in = P2PDoSPeer(true);
                CBlock block = P2PDoSBlock(1000 + i, 0);
                CDataStream ssB(SER_NETWORK);
                ssB << block;
                P2PDoSProcess(in, "block", ssB);
                if (i == 4)
                {
                    r = in;
                    hashRefused = block.GetHash();
                }
                else
                    delete in;
            }
            nFail += Check(nBlocksReceived - nBefore == 5 && InboundBlockBudgetTokensForTest() == 0 &&
                           nInboundBlocksRefused - nRefusedBefore == 2,
                           "five well-formed blocks from new inbound peers, budget of three: two not hashed") ? 0 : 1;
            nFail += Check(r && r->nMisbehavior == 0 && r->vBlocksRefused.size() == 1 &&
                           r->vBlocksRefused[0] == hashRefused &&
                           !mapAlreadyAskedFor.count(CInv(MSG_BLOCK, hashRefused)),
                           "a refused block costs nothing and is remembered, not forgotten") ? 0 : 1;
            if (r)
            {
                CRITICAL_BLOCK(r->cs_vSend)
                    SendMessages(r);
                bool fNotYet = P2PDoSSent(*r).empty() && r->vBlocksRefused.size() == 1;
                InboundBlockBudgetResetForTest(1);
                CRITICAL_BLOCK(r->cs_vSend)
                    SendMessages(r);
                std::vector<std::string> vCmd = P2PDoSSent(*r);
                nFail += Check(fNotYet && r->vBlocksRefused.empty() && vCmd.size() == 1 && vCmd[0] == "getdata",
                               "and it is asked for again once there is budget") ? 0 : 1;
                delete r;
            }

            InboundBlockBudgetResetForTest(0, true);
            nRefusedBefore = nInboundBlocksRefused;
            nBefore = nBlocksReceived;
            CNode* old = P2PDoSPeer(true);
            old->nTimeConnected = GetTime() - INBOUND_BLOCK_BUDGET_EXEMPT_SECS - 1;
            CNode* out = P2PDoSPeer(false);
            CNode* proven = P2PDoSPeer(true);
            proven->nGoodBlocks = 1;
            CNode* vPeers3[3] = { old, out, proven };
            for (int i = 0; i < 3; i++)
            {
                CBlock block = P2PDoSBlock(2000 + i, 0);
                CDataStream ssB(SER_NETWORK);
                ssB << block;
                P2PDoSProcess(vPeers3[i], "block", ssB);
            }
            nFail += Check(nBlocksReceived - nBefore == 3 && nInboundBlocksRefused == nRefusedBefore,
                           "inbound peers connected ten minutes, outbound peers, and peers that gave a block are not limited") ? 0 : 1;
            delete old;
            delete out;
            delete proven;
            InboundBlockBudgetResetForTest(32);

            // A peer that announces and does not read gets no getdata from us.
            {
                CNode* h = P2PDoSPeer();
                h->vSend.resize(SendBufferSize());
                std::vector<CInv> vInv;
                for (int i = 0; i < 100; i++)
                    vInv.push_back(CInv(MSG_BLOCK, uint256(0xa000000 + i)));
                for (int i = 0; i < 100; i++)
                    vInv.push_back(CInv(MSG_TX, uint256(0xb000000 + i)));
                CDataStream ss(SER_NETWORK);
                ss << vInv;
                P2PDoSProcess(h, "inv", ss);
                size_t nAsked = h->mapAskFor.size();
                CRITICAL_BLOCK(h->cs_vSend)
                    SendMessages(h);
                nFail += Check(nAsked == 100 && h->vSend.size() == SendBufferSize() && h->mapAskFor.size() == 100,
                               "with its send buffer full: transactions are not looked up, nothing is sent, requests wait") ? 0 : 1;
                h->vSend.clear();
                CRITICAL_BLOCK(h->cs_vSend)
                    SendMessages(h);
                std::vector<std::string> vCmd = P2PDoSSent(*h);
                nFail += Check(vCmd.size() == 1 && vCmd[0] == "getdata" && h->mapAskFor.empty(),
                               "and they go out once it reads") ? 0 : 1;
                delete h;

                CNode* f = P2PDoSPeer();
                f->vSend.resize(MAX_SEND_BUFFER_HARD);
                bool fUnder = !SendFloodCheck(f) && !f->fDisconnect;
                f->vSend.resize(MAX_SEND_BUFFER_HARD + 1);
                bool fOver = SendFloodCheck(f) && f->fDisconnect && f->fDropWithoutDrain;
                f->vSend.release();
                nFail += Check(fUnder && fOver, "past MAX_SEND_BUFFER_HARD queued, the peer is dropped") ? 0 : 1;
                delete f;
            }

            // Database reads for announced transactions are rationed per peer.
            {
                CNode* t = P2PDoSPeer();
                std::vector<CInv> vInv;
                for (int i = 0; i < 2 * TX_INV_LOOKUPS_MAX; i++)
                    vInv.push_back(CInv(MSG_TX, uint256(0xc0000000ULL + i)));
                CDataStream ss(SER_NETWORK);
                ss << vInv;
                P2PDoSProcess(t, "inv", ss);
                nFail += Check(t->mapAskFor.size() == (size_t)TX_INV_LOOKUPS_MAX && t->nTxInvTokens == 0,
                               "an inv of 10000 transactions: 5000 looked up, the rest not asked for") ? 0 : 1;
                delete t;
            }

            // Disconnect() gives the buffers back, and touches what the
            // message thread uses under cs_vSend only when it holds cs_vSend.
            {
                CNode* x = P2PDoSPeer();
                P2PDoSQueue(*x, "ping", CDataStream(SER_NETWORK));
                x->vRecvGetData.push_back(CInv(MSG_TX, uint256(1)));
                x->fGetBlocksPending = true;
                x->vGetBlocksHave.assign(5, uint256(2));
                x->vBlocksRefused.push_back(uint256(3));
                x->AskFor(CInv(MSG_TX, uint256(0xd1)));
                x->vSend.resize(1000);
                std::atomic<int> nHold(0);
                std::thread holder([&]() {
                    CRITICAL_BLOCK(x->cs_vSend)
                    {
                        nHold = 1;
                        while (nHold == 1)
                            Sleep(5);
                    }
                });
                while (nHold == 0)
                    Sleep(5);
                x->Disconnect();
                bool fHeld = x->vRecv.empty() && x->vRecvGetData.empty() &&
                             x->fGetBlocksPending && x->vGetBlocksHave.size() == 5 &&
                             x->vBlocksRefused.size() == 1 && x->mapAskFor.size() == 1 &&
                             x->vSend.size() == 1000;
                nHold = 2;
                holder.join();
                nFail += Check(fHeld, "with cs_vSend held elsewhere, Disconnect leaves the pending getblocks alone") ? 0 : 1;
                x->Disconnect();
                nFail += Check(!x->fGetBlocksPending && x->vGetBlocksHave.empty() && x->vBlocksRefused.empty() &&
                               x->mapAskFor.empty() && x->setAskFor.empty() && x->vSend.empty(),
                               "and frees it all when it can take both locks") ? 0 : 1;
                delete x;
            }
        }

        // ---- M2: eviction picks a fresh, idle peer and never a useful one
        {
            int64 nNow = GetTime();
            std::vector<NodeEvictionCandidate> v;
            for (int i = 0; i < 40; i++)
            {
                NodeEvictionCandidate c;
                c.nTimeConnected = nNow - 10000 + i * 100;    // larger i: younger
                c.nLastBlockTime = c.nLastTxTime = c.nLastShareTime = 0;
                c.fHandshakeDone = true;
                v.push_back(c);
            }
            // The four youngest relayed blocks, the next four transactions.
            for (int i = 36; i < 40; i++) v[i].nLastBlockTime = nNow - (40 - i);
            for (int i = 32; i < 36; i++) v[i].nLastTxTime = nNow - (40 - i);
            int n = SelectNodeToEvict(v);
            nFail += Check(n == 31, "the youngest peer that has given us nothing is evicted") ? 0 : 1;
            v[20].fHandshakeDone = false;
            n = SelectNodeToEvict(v);
            nFail += Check(n == 20, "one that never finished its handshake goes first") ? 0 : 1;
            v[0].fHandshakeDone = false;
            n = SelectNodeToEvict(v);
            nFail += Check(n == 20, "but not from among the longest connected") ? 0 : 1;
            std::vector<NodeEvictionCandidate> vUseful(v.begin() + 32, v.end());
            nFail += Check(SelectNodeToEvict(vUseful) == -1,
                           "with every peer useful, nobody is evicted") ? 0 : 1;
        }

        // ---- M2 (review): a whole-chain inv cut at MAX_INV_SZ continues
        {
            CNode* c = P2PDoSPeer();
            std::vector<CInv> vInv;
            for (unsigned int i = 0; i < MAX_INV_SZ + 5; i++)
                vInv.push_back(CInv(MSG_BLOCK, uint256(((uint64)7 << 40) + i)));
            CDataStream ss(SER_NETWORK);
            ss << vInv;
            P2PDoSProcess(c, "inv", ss);
            bool fKept = c->hashInvContinue == vInv[MAX_INV_SZ - 1].hash;
            c->mapAskFor.clear();
            c->setAskFor.clear();
            // When that block arrives (here one refused for its timestamp,
            // which costs nothing), the same peer is asked for the rest.
            CBlock block = P2PDoSBlock(3000, 24 * 60 * 60);
            c->hashInvContinue = block.GetHash();
            CDataStream ssB(SER_NETWORK);
            ssB << block;
            P2PDoSProcess(c, "block", ssB);
            std::vector<std::string> vCmd = P2PDoSSent(*c);
            nFail += Check(fKept && c->hashInvContinue == 0 && vCmd.size() == 1 && vCmd[0] == "getblocks",
                           "an inv cut at MAX_INV_SZ: when its last block arrives, getblocks goes to the same peer") ? 0 : 1;
            delete c;
        }

        // ---- M2: eviction with real nodes in vNodes
        {
            std::vector<CNode*> vSavedNodes;
            CRITICAL_BLOCK(cs_vNodes)
                vSavedNodes.swap(vNodes);
            int64 nNow = GetTime();
            std::vector<CNode*> vMine;
            for (int i = 0; i < 6; i++)
            {
                CNode* n = P2PDoSPeer(true);
                n->nTimeConnected = nNow - 1000 + i * 10;   // larger i: younger
                vMine.push_back(n);
            }
            vMine[5]->fDisconnect = true;                    // the youngest, already going
            CNode* outbound = P2PDoSPeer(false);
            outbound->nTimeConnected = nNow;
            vMine.push_back(outbound);
            CRITICAL_BLOCK(cs_vNodes)
                vNodes = vMine;
            bool fEvicted = AttemptToEvictConnection();
            nFail += Check(fEvicted && vMine[4]->fDisconnect && vMine[4]->fDropWithoutDrain &&
                           !vMine[5]->fDropWithoutDrain && !outbound->fDisconnect &&
                           !vMine[0]->fDisconnect && !vMine[3]->fDisconnect,
                           "eviction among real nodes: the youngest live inbound peer, never outbound") ? 0 : 1;
            CRITICAL_BLOCK(cs_vNodes)
                vNodes.swap(vSavedNodes);
            for (size_t i = 0; i < vMine.size(); i++)
                delete vMine[i];
        }

        // ---- M4: hearsay never pushes a peer that answered out of the cache
        {
            for (int i = 0; i < 10; i++)
                BtfRememberPeerForTest(strprintf("selftest-verified-%d", i), "", true);
            for (int i = 0; i < 200; i++)
                BtfRememberPeerForTest(strprintf("selftest-hearsay-%d", i), "", false);
            int nVerified = 0, nHearsay = 0;
            std::vector<std::string> vOrder;
            BtfPeerCacheStatsForTest(nVerified, nHearsay, vOrder);
            bool fFirst = vOrder.size() >= 10;
            for (int i = 0; fFirst && i < 10; i++)
                fFirst = vOrder[i].compare(0, 18, "selftest-verified-") == 0;
            nFail += Check(nVerified == 10 && nHearsay == 50,
                           "200 peers heard of: the 10 that answered stay, hearsay is held to 50") ? 0 : 1;
            nFail += Check(fFirst, "and the ones that answered are dialled first") ? 0 : 1;
            for (int i = 10; i < 70; i++)
                BtfRememberPeerForTest(strprintf("selftest-verified-%d", i), "", true);
            BtfPeerCacheStatsForTest(nVerified, nHearsay, vOrder);
            nFail += Check(nVerified == 50 && nHearsay == 50,
                           "peers that answered have their own 50") ? 0 : 1;

            CNode* p = P2PDoSPeer(true);
            CDataStream ss1(SER_NETWORK), ss2(SER_NETWORK);
            ss1 << std::vector<std::string>();
            ss2 << std::vector<std::string>(1, "x");
            P2PDoSProcess(p, "btfpeers", ss1);
            int64 nFirst = p->nLastPexRecv;
            P2PDoSProcess(p, "btfpeers", ss2);
            nFail += Check(nFirst != 0 && ss2.empty() && p->nLastPexRecv == nFirst,
                           "one btfpeers per connection is read, the next is not") ? 0 : 1;
            delete p;
        }

        // ---- L1: the legacy review message does nothing
        {
            CNode* p = P2PDoSPeer();
            CDataStream ss(SER_NETWORK);
            ss << std::vector<unsigned char>(64, 0xee);
            bool fOk = P2PDoSProcess(p, "review", ss);
            nFail += Check(fOk && ss.empty() && p->nMisbehavior == 0 && p->vSend.empty() &&
                           !FileExists((tmp + "/reviews.dat").c_str()),
                           "a review is dropped unread: no signature check, no file") ? 0 : 1;
            delete p;
        }

        // ---- H5: what a peer can write to debug.log is bounded
        {
            std::string strLog = tmp + "/rotate-test.log";
            FILE* f = fopen(strLog.c_str(), "w");
            if (f)
            {
                std::string s(2000, 'x');
                fwrite(s.data(), 1, s.size(), f);
                fclose(f);
            }
            bool fNo = !DebugLogRotateIfOver(strLog, 500, 1000);
            bool fYes = DebugLogRotateIfOver(strLog, 2000, 1000);
            nFail += Check(fNo && fYes && FileExists((strLog + ".1").c_str()) && !FileExists(strLog.c_str()),
                           "a log over the cap is moved to .1") ? 0 : 1;
            f = fopen(strLog.c_str(), "w");
            if (f) { fputs("second", f); fclose(f); }
            bool fAgain = DebugLogRotateIfOver(strLog, -1, 1000);
            long nOld = -1;
            f = fopen((strLog + ".1").c_str(), "r");
            if (f) { fseek(f, 0, SEEK_END); nOld = ftell(f); fclose(f); }
            nFail += Check(fAgain && nOld == 6, "and a later rotation replaces the old .1") ? 0 : 1;

            int64 nSuppressedBefore = nLogLinesSuppressed;
            for (int i = 0; i < 50; i++)
                error("p2p-dos self-test repeated error %d", i);
            nFail += Check(nLogLinesSuppressed - nSuppressedBefore == 49,
                           "50 identical errors in a burst write one line") ? 0 : 1;
            nSuppressedBefore = nLogLinesSuppressed;
            error("%s", "p2p-dos alpha");
            error("%s", "p2p-dos beta");
            nFail += Check(nLogLinesSuppressed == nSuppressedBefore,
                           "different errors through one bare \"%s\" format are not merged") ? 0 : 1;

            const std::string& strPath = DebugLogPath();
            if (strPath.compare(0, tmp.size(), tmp) == 0)
            {
                long nSavedMax = nDebugLogMaxBytes;
                nDebugLogMaxBytes = 4000;
                for (int i = 0; i < 100; i++)
                    OutputDebugStringF("p2p-dos rotation check, line %d of a hundred\n", i);
                nDebugLogMaxBytes = nSavedMax;
                long nNow = -1;
                FILE* fl = fopen(strPath.c_str(), "r");
                if (fl) { fseek(fl, 0, SEEK_END); nNow = ftell(fl); fclose(fl); }
                nFail += Check(FileExists((strPath + ".1").c_str()) && nNow >= 0 && nNow <= 4000 + 200,
                               "through the real logging path, debug.log rotates at the cap") ? 0 : 1;

                // A burst's count reaches the log once its window closes,
                // without waiting for the same line to come again.
                for (int i = 0; i < 5; i++)
                    error("p2p-dos flush check %d", i);
                Sleep(3200);
                LogDedupFlush();
                std::string body;
                fl = fopen(strPath.c_str(), "r");
                if (fl)
                {
                    char buf[4096];
                    size_t r;
                    while ((r = fread(buf, 1, sizeof(buf), fl)) > 0)
                        body.append(buf, r);
                    fclose(fl);
                }
                nFail += Check(body.find("(4 similar in 3s, last: p2p-dos flush check 4)") != std::string::npos,
                               "and a burst's count is written once its window closes") ? 0 : 1;
            }
            else
                printf("  skip debug.log path checks: this process logs to %s\n", strPath.c_str());

            // A message that does not parse is one line and the next is read.
            CNode* p = P2PDoSPeer();
            CDataStream ssShort(SER_NETWORK);
            ssShort << (unsigned char)5;             // claims five entries, has none
            P2PDoSQueue(*p, "inv", ssShort);
            P2PDoSQueue(*p, "ping", CDataStream(SER_NETWORK));
            ProcessMessages(p);
            nFail += Check(p->vRecv.empty() && !p->fDisconnect,
                           "a short inv is dropped and the next message read") ? 0 : 1;
            delete p;
        }

        // ---- M5: block checks do not wait behind another verifier
        {
            unsigned char data[80];
            memset(data, 0x42, sizeof(data));
            uint256 hRef = RandomXPoWHash(2, data, sizeof(data));
            std::atomic<int> nHolder(0);
            std::thread holder([&]() {
                RandomXHoldPrimaryVerifyForTest(2, true);
                nHolder = 1;
                while (nHolder == 1)
                    Sleep(10);
                RandomXHoldPrimaryVerifyForTest(2, false);
            });
            while (nHolder == 0)
                Sleep(10);
            std::atomic<bool> fDone(false);
            uint256 hGot = 0;
            std::thread hasher([&]() {
                hGot = RandomXPoWHash(2, data, sizeof(data));
                fDone = true;
            });
            for (int i = 0; i < 3000 && !fDone; i++)
                Sleep(10);
            bool fFinished = fDone;
            nHolder = 2;
            holder.join();
            hasher.join();
            nFail += Check(fFinished && hGot == hRef && hRef != 0,
                           "with the first VM held, a hash completes on another, and agrees") ? 0 : 1;
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    nSendBufferSize = nSendSaved;
    nReceiveFloodSize = nRecvSaved;
    for (size_t i = 0; i < vMade.size(); i++)
    {
        mapBlockIndex.erase(vMade[i]->GetBlockHash());
        delete vMade[i];
    }
    if (pindexBestSaved)
        pindexBest = pindexBestSaved;
    DBFlush(true);
    strSetDataDir = strOldDataDir;
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- sync-stall: a fresh node syncing on 1.2.33 stalled for good ----
// 1.2.33 peers announce their tip on connect and after every batch they
// serve. A fresh 1.2.33 node turned each such inv, and every inv naming an
// orphan, into a getblocks to that peer: every peer at the tip ran its own
// download of the same blocks, most arrived as orphans, and each getblocks
// answer named the next block again, pushing its retry slot two minutes on
// each time. On testnet it was scheduled 38 hours ahead three minutes into
// the sync. Each check marked so passes on 1.2.33 too; the rest fail there.
static int CountCommand(CNode& node, const char* pszCommand)
{
    std::vector<std::string> v = P2PDoSSent(node);
    return (int)std::count(v.begin(), v.end(), std::string(pszCommand));
}

static void SyncStallInv(CNode* p, const std::vector<uint256>& vHashes)
{
    std::vector<CInv> vInv;
    for (size_t i = 0; i < vHashes.size(); i++)
        vInv.push_back(CInv(MSG_BLOCK, vHashes[i]));
    CDataStream ss(SER_NETWORK);
    ss << vInv;
    P2PDoSProcess(p, "inv", ss);
}

static int RunSyncStallSelfTest()
{
    fflush(stdout);
    printf("sync-stall self-test\n");
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    std::string strOldDataDir = strSetDataDir;
    strSetDataDir = tmp;
    int nFail = 0;
    std::vector<CNode*> vSavedNodes;
    std::vector<CNode*> vPeers;
    bool fSwapped = false;
    try
    {
        if (!LoadBlockIndex())
            throw std::runtime_error("LoadBlockIndex failed");

        // Twenty orphans, each missing a different parent: the orphan pool in
        // pieces, as random eviction left it.
        std::vector<uint256> vOrphans;
        for (int i = 0; i < 20; i++)
        {
            CBlock* pblock = new CBlock(P2PDoSBlock(5100 + i, 0));
            pblock->hashPrevBlock = uint256(0x5170000 + i);
            vOrphans.push_back(pblock->GetHash());
            AddOrphanBlock(pblock);
        }

        // ---- a peer naming the same block over and over
        {
            mapAlreadyAskedFor.clear();
            CNode* x = P2PDoSPeer();
            std::vector<uint256> vNext(1, uint256(0x5171111));
            for (int i = 0; i < 50; i++)
                SyncStallInv(x, vNext);
            int64 nSlot = mapAlreadyAskedFor[CInv(MSG_BLOCK, vNext[0])];
            int64 nNow = GetTime() * 1000000LL;
            nFail += Check(x->mapAskFor.size() == 1,
                           "a block named in 50 invs by one peer is asked of it once") ? 0 : 1;
            nFail += Check(nSlot <= nNow + 2 * 60 * 1000000LL,
                           "and its retry slot stays within two minutes, not 100 minutes ahead") ? 0 : 1;
            CRITICAL_BLOCK(x->cs_vSend)
                SendMessages(x);
            SyncStallInv(x, vNext);
            nFail += Check(CountCommand(*x, "getdata") == 1 && x->mapAskFor.size() == 1,
                           "once the getdata went out, the next inv may queue a retry") ? 0 : 1;
            delete x;
            mapAlreadyAskedFor.clear();
        }

        // Catching up: three peers 5000 blocks ahead of a node at genesis.
        CRITICAL_BLOCK(cs_vNodes)
            vSavedNodes.swap(vNodes);
        fSwapped = true;
        for (int i = 0; i < 3; i++)
        {
            CNode* p = P2PDoSPeer();
            p->nStartingHeight = nBestHeight + 5000;
            vPeers.push_back(p);
        }
        CRITICAL_BLOCK(cs_vNodes)
            vNodes = vPeers;
        CNode* a = vPeers[0];
        CNode* b = vPeers[1];
        CNode* c = vPeers[2];
        nFail += Check(IsInitialBlockDownload(), "three peers 5000 blocks ahead: catching up (passes on 1.2.33 too)") ? 0 : 1;

        // ---- one getblocks per inv, not one per orphan
        {
            SyncStallInv(a, std::vector<uint256>(1, vOrphans[0]));
            bool fFirst = CountCommand(*a, "getblocks") == 1 && a->fSyncPeer;
            a->vSend.clear();
            SyncStallInv(a, std::vector<uint256>(vOrphans.begin() + 1, vOrphans.end()));
            int nGetBlocks = CountCommand(*a, "getblocks");
            a->vSend.clear();
            nFail += Check(fFirst, "the first peer to name an orphan becomes the sync peer and is asked") ? 0 : 1;
            nFail += Check(nGetBlocks == 1,
                           "an inv naming 19 orphans with 19 roots sends one getblocks, not 19") ? 0 : 1;
        }

        // ---- the tip inv of another peer starts no second download
        {
            SyncStallInv(b, std::vector<uint256>(1, vOrphans[5]));
            nFail += Check(CountCommand(*b, "getblocks") == 0 && !b->fSyncPeer && a->fSyncPeer,
                           "while the sync peer makes progress, another peer naming an orphan is not asked") ? 0 : 1;
            ProcessMessages(b);
            nFail += Check(CountCommand(*b, "getblocks") == 0,
                           "nor on its next pass") ? 0 : 1;
            b->vSend.clear();
        }

        // ---- a stalled sync peer is replaced, once per stall
        {
            SyncPeerResetForTest(121);
            ProcessMessages(c);
            bool fTook = CountCommand(*c, "getblocks") == 1 && c->fSyncPeer && !a->fSyncPeer;
            ProcessMessages(b);
            ProcessMessages(a);
            bool fOnce = CountCommand(*b, "getblocks") == 0 && CountCommand(*a, "getblocks") == 0 && !b->fSyncPeer;
            nFail += Check(fTook, "no block for two minutes: a peer ahead of us is asked on its next pass, and takes over") ? 0 : 1;
            nFail += Check(fOnce, "and only that one (passes on 1.2.33 too)") ? 0 : 1;
            c->vSend.clear();

            SyncPeerResetForTest(121);
            SyncStallInv(b, std::vector<uint256>(1, vOrphans[6]));
            nFail += Check(CountCommand(*b, "getblocks") == 1 && b->fSyncPeer && !c->fSyncPeer,
                           "a stall is also ended by the next peer that names an orphan") ? 0 : 1;
            b->vSend.clear();

            // a last heard getblocks(best, root of orphan 1): taking over with
            // the same question, it is asked all the same.
            SyncPeerResetForTest(121);
            SyncStallInv(a, std::vector<uint256>(1, vOrphans[1]));
            nFail += Check(CountCommand(*a, "getblocks") == 1 && a->fSyncPeer,
                           "a peer that takes over is asked even what it was last asked") ? 0 : 1;
            a->vSend.clear();

            a->fDisconnect = true;
            SyncStallInv(c, std::vector<uint256>(1, vOrphans[7]));
            nFail += Check(CountCommand(*c, "getblocks") == 1 && c->fSyncPeer && !a->fSyncPeer,
                           "and a sync peer on its way out is replaced at once") ? 0 : 1;
            c->vSend.clear();
            a->fDisconnect = false;

            // c is the only peer that can serve (b is a client, a on its way
            // out): after a stall it is asked again itself, but only after twice
            // as long, so another peer gets the first chance.
            b->fClient = true;
            a->fDisconnect = true;
            SyncPeerResetForTest(121);
            ProcessMessages(c);
            bool fNotYet = CountCommand(*c, "getblocks") == 0;
            SyncPeerResetForTest(241);
            ProcessMessages(c);
            nFail += Check(fNotYet && CountCommand(*c, "getblocks") == 1 && c->fSyncPeer,
                           "a stalled sync peer that is the only one ahead is asked again after four minutes") ? 0 : 1;
            c->vSend.clear();
            b->fClient = false;
            a->fDisconnect = false;
        }

        // ---- caught up: every peer is asked, as before (passes on 1.2.33 too)
        {
            for (size_t i = 0; i < vPeers.size(); i++)
                vPeers[i]->nStartingHeight = nBestHeight;
            SyncStallInv(a, std::vector<uint256>(1, vOrphans[8]));
            SyncStallInv(b, std::vector<uint256>(1, vOrphans[9]));
            nFail += Check(!IsInitialBlockDownload() && CountCommand(*a, "getblocks") == 1 &&
                           CountCommand(*b, "getblocks") == 1,
                           "once caught up, any peer naming an orphan is asked for its parents") ? 0 : 1;
        }
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    LimitOrphanBlocks(0);
    mapAlreadyAskedFor.clear();
    if (fSwapped)
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.swap(vSavedNodes);
    for (size_t i = 0; i < vPeers.size(); i++)
        delete vPeers[i];
    SyncPeerResetForTest(0);
    DBFlush(true);
    strSetDataDir = strOldDataDir;
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- bignum-int: script numbers read as int the same on every platform ----
// CBigNum::getint() kept OpenSSL's 64-bit word in an unsigned long, 32 bits on
// Windows, so 2^32 read as 0 there and as INT_MAX on Linux. Script numbers are
// not limited to 4 bytes here, so OP_PICK, OP_ROLL and OP_CHECKMULTISIG could
// be handed such a value, and Windows and Linux nodes judged the script
// differently. The cases between 2^32 and 2^64 and the interpreter cases fail
// on a Windows build of the old code; the others pin the clamping around them.
// (Neither chain has ever used such a value: no OP_PICK or OP_ROLL, and every
// multisig count a literal, in all 225,066 mainnet and 28,446 testnet scripts
// scanned in November 2026.)

static CBigNum BigNumFromLE(const std::vector<unsigned char>& v)
{
    return CBigNum(v);   // script numbers: little endian, sign in the top bit
}

static int RunBigNumIntSelfTest()
{
    printf("bignum-int self-test\n");
    int nFail = 0;
    typedef std::vector<unsigned char> V;
    struct Case { V v; int nExpect; const char* name; };
    const Case cases[] = {
        { V{0x05}, 5, "5" },
        { V{0x85}, -5, "-5" },
        { V{0xff, 0xff, 0xff, 0x7f}, INT_MAX, "2^31-1, the largest int" },
        { V{0x00, 0x00, 0x00, 0x80, 0x00}, INT_MAX, "2^31 clamps to INT_MAX" },
        { V{0xff, 0xff, 0xff, 0xff, 0x00}, INT_MAX, "2^32-1 clamps to INT_MAX" },
        { V{0x00, 0x00, 0x00, 0x00, 0x01}, INT_MAX, "2^32 clamps to INT_MAX (read as 0 on Windows before)" },
        { V{0x05, 0x00, 0x00, 0x00, 0x01}, INT_MAX, "2^32+5 clamps to INT_MAX (read as 5 on Windows before)" },
        { V{0x00, 0x00, 0x00, 0x00, 0x81}, INT_MIN, "-2^32 clamps to INT_MIN (read as 0 on Windows before)" },
        { V{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, INT_MAX, "2^64+1, past 64 bits, clamps to INT_MAX" },
        { V{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81}, INT_MIN, "-(2^64+1) clamps to INT_MIN" },
        { V{0x00, 0x00, 0x00, 0x80, 0x80}, INT_MIN, "-2^31 clamps to INT_MIN" },
        { V{0xff, 0xff, 0xff, 0xff}, -INT_MAX, "-(2^31-1) is itself" },
        { V{0x80}, 0, "negative zero is 0" },
        { V{}, 0, "the empty number is 0" },
        { V{0x05, 0x00, 0x00, 0x00, 0x00}, 5, "a non-minimal 5 is 5" },
        { V(520, 0x7f), INT_MAX, "a 520-byte number clamps to INT_MAX" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int n = BigNumFromLE(cases[i].v).getint();
        nFail += Check(n == cases[i].nExpect, strprintf("getint: %s (got %d)", cases[i].name, n).c_str()) ? 0 : 1;
    }

    // The same through the interpreter. An index or a count past INT_MAX is
    // out of range on every platform; on Windows the old code read 2^32 as 0
    // (OP_PICK became OP_DUP) and 2^32+1 keys as one key.
    CTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    const V big = V{0x00, 0x00, 0x00, 0x00, 0x01};
    {
        CScript s; s << OP_1 << OP_0 << OP_PICK;
        nFail += Check(EvalScript(s, tx, 0), "control: OP_1 0 OP_PICK runs") ? 0 : 1;
    }
    {
        CScript s; s << OP_1 << big << OP_PICK;
        nFail += Check(!EvalScript(s, tx, 0), "OP_PICK with index 2^32 fails on every platform") ? 0 : 1;
    }
    {
        CScript s; s << OP_1 << OP_2 << big << OP_ROLL;
        nFail += Check(!EvalScript(s, tx, 0), "OP_ROLL with index 2^32 fails on every platform") ? 0 : 1;
    }
    {
        // 0 signatures, then 2^32+1 keys with one key on the stack: on Windows
        // the old code saw one key and the spend ran to the end.
        CKey key;
        key.MakeNewKey();
        CScript s;
        s << OP_0 << OP_0 << key.GetPubKey() << V{0x01, 0x00, 0x00, 0x00, 0x01} << OP_CHECKMULTISIG;
        nFail += Check(!EvalScript(s, tx, 0), "OP_CHECKMULTISIG with a key count of 2^32+1 fails on every platform") ? 0 : 1;
        // A signature count of 2^32 with one key: the old Windows build read
        // it as no signatures and the check passed.
        CScript g;
        g << OP_0 << big << key.GetPubKey() << OP_1 << OP_CHECKMULTISIG;
        nFail += Check(!EvalScript(g, tx, 0), "OP_CHECKMULTISIG with a signature count of 2^32 fails on every platform") ? 0 : 1;
        CScript c;
        c << OP_0 << OP_0 << key.GetPubKey() << OP_1 << OP_CHECKMULTISIG;
        nFail += Check(EvalScript(c, tx, 0), "control: the same with a key count of 1 runs") ? 0 : 1;
    }
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- orphan-tx: the orphan transaction pool --------------------------------
// AddOrphanTx, EraseOrphanTx and LimitOrphanTx keep two maps in step: the
// orphans by hash, and each input's parent hash to the orphan naming it. A
// stale entry in the second would point at a freed stream. No self-test
// reached these before (coverage, November 2026).

extern map<uint256, CDataStream*> mapOrphanTransactions;
extern multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;

static CDataStream OrphanTestTx(const vector<pair<uint256, unsigned int> >& vPrev, int nTag)
{
    CTransaction tx;
    for (size_t i = 0; i < vPrev.size(); i++)
    {
        CTxIn in;
        in.prevout = COutPoint(vPrev[i].first, vPrev[i].second);
        tx.vin.push_back(in);
    }
    tx.vout.push_back(CTxOut(COIN + nTag, CScript() << OP_TRUE));
    CDataStream ss(SER_NETWORK);
    ss << tx;
    return ss;
}

static uint256 OrphanTestHash(const CDataStream& ss)
{
    CTransaction tx;
    CDataStream(ss) >> tx;
    return tx.GetHash();
}

// Every parent entry points at a live orphan that names that parent.
static bool OrphanMapsInStep()
{
    for (multimap<uint256, CDataStream*>::const_iterator mi = mapOrphanTransactionsByPrev.begin();
         mi != mapOrphanTransactionsByPrev.end(); ++mi)
    {
        bool fLive = false;
        for (map<uint256, CDataStream*>::const_iterator it = mapOrphanTransactions.begin();
             it != mapOrphanTransactions.end(); ++it)
            if (it->second == mi->second)
            {
                CTransaction tx;
                CDataStream(*it->second) >> tx;
                for (size_t i = 0; i < tx.vin.size(); i++)
                    fLive |= tx.vin[i].prevout.hash == mi->first;
            }
        if (!fLive)
            return false;
    }
    return true;
}

static int RunOrphanTxSelfTest()
{
    printf("orphan-tx self-test\n");
    int nFail = 0;
    CRITICAL_BLOCK(cs_main)
    {
        while (!mapOrphanTransactions.empty())
            EraseOrphanTx(mapOrphanTransactions.begin()->first);
        nFail += Check(mapOrphanTransactionsByPrev.empty(), "the orphan pool starts empty") ? 0 : 1;

        uint256 P = Hash(BEGIN("P"), END("P")), Q = Hash(BEGIN("Q"), END("Q")), R = Hash(BEGIN("R"), END("R"));
        vector<pair<uint256, unsigned int> > v;

        v.assign(1, make_pair(P, 0u));
        CDataStream a = OrphanTestTx(v, 1);
        AddOrphanTx(a);
        AddOrphanTx(a);
        nFail += Check(mapOrphanTransactions.size() == 1 && mapOrphanTransactionsByPrev.size() == 1,
                       "an orphan is held once, under its one parent, however often it comes") ? 0 : 1;

        v.clear();
        v.push_back(make_pair(P, 1u));
        v.push_back(make_pair(Q, 0u));
        CDataStream b = OrphanTestTx(v, 2);
        AddOrphanTx(b);
        v.clear();
        v.push_back(make_pair(R, 0u));
        v.push_back(make_pair(R, 1u));
        CDataStream c = OrphanTestTx(v, 3);
        AddOrphanTx(c);
        nFail += Check(mapOrphanTransactions.size() == 3 && mapOrphanTransactionsByPrev.size() == 5 &&
                       mapOrphanTransactionsByPrev.count(P) == 2 && mapOrphanTransactionsByPrev.count(R) == 2 &&
                       OrphanMapsInStep(),
                       "two parents, and one parent named twice: an entry per input, each pointing at its orphan") ? 0 : 1;

        EraseOrphanTx(OrphanTestHash(b));
        bool fB = mapOrphanTransactions.size() == 2 && mapOrphanTransactionsByPrev.size() == 3 &&
                  mapOrphanTransactionsByPrev.count(P) == 1 && mapOrphanTransactionsByPrev.count(Q) == 0;
        EraseOrphanTx(OrphanTestHash(c));
        bool fC = mapOrphanTransactions.size() == 1 && mapOrphanTransactionsByPrev.size() == 1 &&
                  mapOrphanTransactionsByPrev.count(R) == 0;
        EraseOrphanTx(OrphanTestHash(c));   // gone already: nothing happens
        nFail += Check(fB && fC && OrphanMapsInStep() && mapOrphanTransactions.size() == 1,
                       "erasing an orphan removes every parent entry it had and no other; erasing it twice is harmless") ? 0 : 1;

        v.clear();
        for (unsigned int i = 0; i < 10001; i++)
            v.push_back(make_pair(Q, i));
        AddOrphanTx(OrphanTestTx(v, 4));
        nFail += Check(mapOrphanTransactions.size() == 1 && mapOrphanTransactionsByPrev.size() == 1,
                       "an orphan with more than 10,000 inputs is not held") ? 0 : 1;

        for (int i = 0; i < (int)MAX_ORPHAN_TRANSACTIONS + 50; i++)
        {
            uint256 parent = Hash(BEGIN(i), END(i));
            v.assign(1, make_pair(parent, 0u));
            AddOrphanTx(OrphanTestTx(v, 100 + i));
        }
        nFail += Check(mapOrphanTransactions.size() == MAX_ORPHAN_TRANSACTIONS &&
                       mapOrphanTransactionsByPrev.size() == MAX_ORPHAN_TRANSACTIONS && OrphanMapsInStep(),
                       strprintf("past %u orphans, others are dropped at random and the maps stay in step",
                                 MAX_ORPHAN_TRANSACTIONS).c_str()) ? 0 : 1;

        LimitOrphanTx(10);
        bool fTen = mapOrphanTransactions.size() == 10 && mapOrphanTransactionsByPrev.size() == 10 && OrphanMapsInStep();
        while (!mapOrphanTransactions.empty())
            EraseOrphanTx(mapOrphanTransactions.begin()->first);
        nFail += Check(fTen && mapOrphanTransactionsByPrev.empty(),
                       "a lower limit drops down to it; erasing all leaves both maps empty") ? 0 : 1;
    }
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- script-opcodes: every opcode the interpreter has, one row each ----------
// A table of scripts run through EvalScript under four rule sets: before rules
// v3 (the flags all off), v3 (CLTV, no OP_VER), v4 (CSV, CTV, CSFS) and v5 (the
// multisig key cap). Each row says which sets it runs under, whether the
// script is true, and for the scripts that run to their end, the stack they
// leave. The expectations are Bitcoin's where this node follows Bitcoin; where
// it does not (numbers of any length, the unassigned NOP bytes failing,
// OP_VERIF before v3, the v4 opcodes before v4) a comment on the row says so
// and the row pins what the code does. Signature-dependent cases are the other
// suites' (rules-v2 to rules-v5, script-eval, multisig).

typedef std::vector<unsigned char> OpVal;

static OpVal OV(std::initializer_list<int> l)
{
    OpVal v;
    for (std::initializer_list<int>::const_iterator it = l.begin(); it != l.end(); ++it)
        v.push_back((unsigned char)*it);
    return v;
}

static CScript OpRaw(std::initializer_list<int> l)
{
    OpVal v = OV(l);
    CScript s;
    s.insert(s.end(), v.begin(), v.end());
    return s;
}

static CScript OpRepeat(opcodetype op, int n)
{
    CScript s;
    for (int i = 0; i < n; i++)
        s << op;
    return s;
}

// n copies of one opcode, appended with <<.
struct OpRun
{
    opcodetype op;
    int n;
    OpRun(opcodetype o, int c) : op(o), n(c) { }
};
static CScript& operator<<(CScript& s, const OpRun& r)
{
    for (int i = 0; i < r.n; i++)
        s << r.op;
    return s;
}
static CScript operator<<(CScript&& s, const OpRun& r)
{
    for (int i = 0; i < r.n; i++)
        s << r.op;
    return s;
}

static OpVal OpBytes(int n, int fill)
{
    return OpVal(n, (unsigned char)fill);
}

static CScript OpCat(const CScript& a, const OpVal& b)
{
    CScript s = a;
    s.insert(s.end(), b.begin(), b.end());
    return s;
}

// Bitcoin's number encoding (little endian, sign in the top bit of the last
// byte, nothing for zero), written out here so the table does not lean on the
// CBigNum the interpreter itself uses.
static OpVal OpNum(int64 n)
{
    OpVal v;
    if (n == 0)
        return v;
    bool fNeg = n < 0;
    uint64 a = fNeg ? (uint64)(-n) : (uint64)n;
    while (a)
    {
        v.push_back((unsigned char)(a & 0xff));
        a >>= 8;
    }
    if (v.back() & 0x80)
        v.push_back(fNeg ? 0x80 : 0x00);
    else if (fNeg)
        v.back() |= 0x80;
    return v;
}

struct OpRow
{
    std::string section, name;
    CScript script;
    unsigned sets;          // bit 0: before v3, 1: v3, 2: v4, 3: v5
    bool ok;
    bool fStack;
    std::vector<OpVal> stack;
    int tx;
    unsigned policy;
};

struct OpTable
{
    std::string cur;
    std::vector<OpRow> rows;
    void Add(const std::string& name, const CScript& s, unsigned sets, bool ok, int tx = 0, unsigned policy = 0)
    {
        OpRow r;
        r.section = cur; r.name = name; r.script = s; r.sets = sets; r.ok = ok; r.fStack = false; r.tx = tx; r.policy = policy;
        rows.push_back(r);
    }
    void AddS(const std::string& name, const CScript& s, unsigned sets, bool ok, const std::vector<OpVal>& st,
              int tx = 0, unsigned policy = 0)
    {
        Add(name, s, sets, ok, tx, policy);
        rows.back().fStack = true;
        rows.back().stack = st;
    }
};

static CTransaction OpTx(int nVersion, unsigned int nLockTime, unsigned int nSequence, int nOuts = 1)
{
    CTransaction tx;
    tx.nVersion = nVersion;
    tx.nLockTime = nLockTime;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256(4242), 0);
    tx.vin[0].nSequence = nSequence;
    for (int i = 0; i < nOuts; i++)
        tx.vout.push_back(CTxOut(COIN + i, CScript() << OP_TRUE));
    return tx;
}

static int RunScriptOpcodesSelfTest()
{
    printf("script-opcodes self-test\n");
    int nFail = 0;

    const unsigned PRE = 1, V3 = 2, V4 = 4, V5 = 8, ALL = 15, V3UP = V3 | V4 | V5, V4UP = V4 | V5;
    const OpVal T = OV({1}), F = OV({});
    typedef std::vector<OpVal> Stk;

    // The transactions the lock opcodes look at.
    enum { TX_PLAIN, TX_LOCK100, TX_LOCKTIME, TX_LOCK100_FINAL, TX_SEQ10, TX_SEQTIME10, TX_V1_SEQ10, TX_SEQ_DISABLED,
           TX_TWO_OUTS, TX_NEGVERSION, TX_V2_FINAL, TX_COUNT };
    std::vector<CTransaction> txs(TX_COUNT);
    txs[TX_PLAIN]          = OpTx(1, 0, SEQUENCE_FINAL);
    txs[TX_LOCK100]        = OpTx(1, 100, 0);
    txs[TX_LOCKTIME]       = OpTx(1, 600000000, 0);
    txs[TX_LOCK100_FINAL]  = OpTx(1, 100, SEQUENCE_FINAL);
    txs[TX_SEQ10]          = OpTx(2, 0, 10);
    txs[TX_SEQTIME10]      = OpTx(2, 0, SEQUENCE_LOCKTIME_TYPE_FLAG | 10);
    txs[TX_V1_SEQ10]       = OpTx(1, 0, 10);
    txs[TX_SEQ_DISABLED]   = OpTx(2, 0, SEQUENCE_LOCKTIME_DISABLE_FLAG | 10);
    txs[TX_TWO_OUTS]       = OpTx(1, 0, SEQUENCE_FINAL, 2);
    txs[TX_NEGVERSION]     = OpTx(-1, 0, 10);
    txs[TX_V2_FINAL]       = OpTx(2, 0, SEQUENCE_FINAL);

    OpTable t;

    // ---- constants and pushes
    t.cur = "constants and pushes";
    t.AddS("empty script: nothing on the stack, false", CScript(), ALL, false, Stk());
    t.AddS("OP_0 pushes an empty element, which is false", CScript() << OP_0, ALL, false, Stk{F});
    for (int n = 1; n <= 16; n++)
        t.AddS(strprintf("OP_%d pushes %d", n, n), OpRaw({0x50 + n}), ALL, true, Stk{OV({n})});
    t.AddS("OP_1NEGATE pushes -1 (0x81)", OpRaw({0x4f}), ALL, true, Stk{OV({0x81})});
    t.AddS("a direct push of one byte", OpRaw({0x01, 0x05}), ALL, true, Stk{OV({5})});
    t.AddS("a direct push of three bytes", OpRaw({0x03, 1, 2, 3}), ALL, true, Stk{OV({1, 2, 3})});
    t.AddS("PUSHDATA1 of three bytes", OpRaw({0x4c, 0x03, 0xaa, 0xbb, 0xcc}), ALL, true, Stk{OV({0xaa, 0xbb, 0xcc})});
    t.AddS("PUSHDATA2 of two bytes", OpRaw({0x4d, 0x02, 0x00, 0xaa, 0xbb}), ALL, true, Stk{OV({0xaa, 0xbb})});
    t.AddS("PUSHDATA4 of one byte", OpRaw({0x4e, 0x01, 0x00, 0x00, 0x00, 0xaa}), ALL, true, Stk{OV({0xaa})});
    // Minimal encoding is not enforced (Bitcoin enforces it only as policy).
    t.AddS("PUSHDATA1 of zero bytes is an empty element, then OP_1", OpRaw({0x4c, 0x00, 0x51}), ALL, true, Stk{F, T});
    t.AddS("PUSHDATA2 of zero bytes", OpRaw({0x4d, 0x00, 0x00, 0x51}), ALL, true, Stk{F, T});
    t.AddS("PUSHDATA4 of zero bytes", OpRaw({0x4e, 0x00, 0x00, 0x00, 0x00, 0x51}), ALL, true, Stk{F, T});
    t.AddS("PUSHDATA1 of one byte (a non-minimal push of 5)", OpRaw({0x4c, 0x01, 0x05}), ALL, true, Stk{OV({5})});
    t.AddS("a direct push of the byte 1 (a non-minimal OP_1)", OpRaw({0x01, 0x01}), ALL, true, Stk{T});
    t.Add("a bare PUSHDATA1 with no length byte", OpRaw({0x4c}), ALL, false);
    t.Add("PUSHDATA1 longer than what is left", OpRaw({0x4c, 0x05, 0x01, 0x02}), ALL, false);
    t.Add("a bare PUSHDATA2", OpRaw({0x4d}), ALL, false);
    t.Add("PUSHDATA2 with one length byte", OpRaw({0x4d, 0x01}), ALL, false);
    t.Add("PUSHDATA2 longer than what is left", OpRaw({0x4d, 0x05, 0x00, 0x01}), ALL, false);
    t.Add("PUSHDATA4 with three length bytes", OpRaw({0x4e, 0x01, 0x00, 0x00}), ALL, false);
    t.Add("PUSHDATA4 of 65536 bytes with none behind it", OpRaw({0x4e, 0x00, 0x00, 0x01, 0x00}), ALL, false);
    t.Add("a direct push of one byte with none behind it", OpRaw({0x01}), ALL, false);
    t.Add("a direct push of two bytes with one behind it", OpRaw({0x02, 0xaa}), ALL, false);
    t.AddS("control: a complete push inside a branch not taken is skipped", OpCat(CScript() << OP_0 << OP_IF, OV({0x4c, 0x01, 0x01})) << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.Add("a push cut short inside a branch not taken fails: the script cannot be read (the control above, closed, passes)", OpRaw({0x00, 0x63, 0x4c, 0x05, 0x01}), ALL, false);
    t.AddS("a 520-byte push is allowed", CScript() << OpBytes(520, 7), ALL, true, Stk{OpBytes(520, 7)});
    t.Add("a 521-byte push is refused", CScript() << OpBytes(521, 7), ALL, false);
    t.Add("a 521-byte push in a branch not taken is refused too", CScript() << OP_0 << OP_IF << OpBytes(521, 7) << OP_ENDIF << OP_1, ALL, false);
    t.AddS("a 520-byte PUSHDATA4", OpCat(OpRaw({0x4e, 0x08, 0x02, 0x00, 0x00}), OpBytes(520, 9)), ALL, true, Stk{OpBytes(520, 9)});
    t.Add("a 521-byte PUSHDATA4", OpCat(OpRaw({0x4e, 0x09, 0x02, 0x00, 0x00}), OpBytes(521, 9)), ALL, false);
    t.Add("OP_RESERVED run fails", OpRaw({0x50}), ALL, false);
    t.AddS("OP_RESERVED in a branch not taken is skipped", CScript() << OP_0 << OP_IF << OP_RESERVED << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.Add("OP_RESERVED1 run fails", CScript() << OP_RESERVED1, ALL, false);
    t.Add("OP_RESERVED2 run fails", CScript() << OP_RESERVED2, ALL, false);
    t.AddS("OP_RESERVED1 in a branch not taken is skipped", CScript() << OP_0 << OP_IF << OP_RESERVED1 << OP_ENDIF << OP_1, ALL, true, Stk{T});

    // ---- flow control
    t.cur = "flow control";
    t.AddS("OP_NOP does nothing", CScript() << OP_1 << OP_NOP, ALL, true, Stk{T});
    t.AddS("IF takes the true branch", CScript() << OP_1 << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({2})});
    t.AddS("IF takes the false branch", CScript() << OP_0 << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({3})});
    t.AddS("NOTIF takes the true branch on false", CScript() << OP_0 << OP_NOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({2})});
    t.AddS("NOTIF takes the else on true", CScript() << OP_1 << OP_NOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({3})});
    t.AddS("IF without ELSE, false: nothing runs and the condition is gone", CScript() << OP_1 << OP_0 << OP_IF << OP_2 << OP_ENDIF, ALL, true, Stk{T});
    t.AddS("IF consumes its condition", CScript() << OP_1 << OP_1 << OP_IF << OP_ENDIF, ALL, true, Stk{T});
    t.AddS("nested IF, both taken", CScript() << OP_1 << OP_IF << OP_1 << OP_IF << OP_5 << OP_ELSE << OP_6 << OP_ENDIF << OP_ENDIF, ALL, true, Stk{OV({5})});
    t.AddS("nested IF, inner else", CScript() << OP_1 << OP_IF << OP_0 << OP_IF << OP_5 << OP_ELSE << OP_6 << OP_ENDIF << OP_ENDIF, ALL, true, Stk{OV({6})});
    t.AddS("nested IF under a false outer: the inner ELSE does not wake it",
           CScript() << OP_0 << OP_IF << OP_1 << OP_IF << OP_5 << OP_ELSE << OP_6 << OP_ENDIF << OP_ELSE << OP_7 << OP_ENDIF, ALL, true, Stk{OV({7})});
    t.AddS("an IF inside a branch not taken needs no condition", CScript() << OP_0 << OP_IF << OP_IF << OP_ENDIF << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("a second ELSE flips back (as in Bitcoin)", CScript() << OP_1 << OP_IF << OP_ELSE << OP_ELSE << OP_2 << OP_ENDIF, ALL, true, Stk{OV({2})});
    t.AddS("negative zero is false for IF", CScript() << OpVal(OV({0x80})) << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({3})});
    t.AddS("0x0000 is false for IF", CScript() << OV({0, 0}) << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({3})});
    t.AddS("0x0080 (a negative zero) is false for IF", CScript() << OV({0, 0x80}) << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({3})});
    t.AddS("0x8000 (128) is true for IF", CScript() << OV({0x80, 0}) << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({2})});
    t.AddS("0x000001 is true for IF", CScript() << OV({0, 0, 1}) << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, ALL, true, Stk{OV({2})});
    t.Add("a lone ELSE", CScript() << OP_ELSE, ALL, false);
    t.Add("a lone ENDIF", CScript() << OP_ENDIF, ALL, false);
    t.Add("an IF left open", CScript() << OP_1 << OP_IF, ALL, false);
    t.Add("an IF left open on the false branch", CScript() << OP_1 << OP_0 << OP_IF << OP_2, ALL, false);
    t.Add("one ENDIF too many", CScript() << OP_1 << OP_IF << OP_1 << OP_ENDIF << OP_ENDIF, ALL, false);
    t.Add("a NOTIF left open", CScript() << OP_1 << OP_NOTIF << OP_1, ALL, false);
    t.Add("IF on an empty stack", CScript() << OP_IF << OP_ENDIF, ALL, false);
    t.Add("NOTIF on an empty stack", CScript() << OP_NOTIF << OP_ENDIF, ALL, false);
    t.AddS("VERIFY of a true value pops it", CScript() << OP_1 << OP_1 << OP_VERIFY, ALL, true, Stk{T});
    t.Add("VERIFY of a false value fails the script", CScript() << OP_1 << OP_0 << OP_VERIFY, ALL, false);
    t.Add("VERIFY ends the script: what follows a failed one does not rescue it", CScript() << OP_1 << OP_0 << OP_VERIFY << OP_1, ALL, false);
    t.Add("VERIFY of a negative zero fails", CScript() << OP_1 << OV({0x80}) << OP_VERIFY, ALL, false);
    t.Add("VERIFY on an empty stack", CScript() << OP_VERIFY, ALL, false);
    t.Add("VERIFY failing inside an IF leaves the IF open: false", CScript() << OP_1 << OP_IF << OP_0 << OP_VERIFY << OP_ENDIF, ALL, false);
    t.Add("RETURN fails the script", CScript() << OP_1 << OP_RETURN, ALL, false);
    t.Add("RETURN fails even with a true stack and more script behind it", CScript() << OP_1 << OP_RETURN << OP_1, ALL, false);
    t.AddS("RETURN in a branch not taken is skipped", CScript() << OP_0 << OP_IF << OP_RETURN << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("VERIFY in a branch not taken is skipped", CScript() << OP_0 << OP_IF << OP_VERIFY << OP_ENDIF << OP_1, ALL, true, Stk{T});
    // OP_VER, OP_VERIF, OP_VERNOTIF: this node's version decides, until rules
    // v3, which makes all three invalid wherever they sit (Bitcoin did it for
    // every block; here it waits for the fork height).
    t.Add("OP_VER before v3 pushes this node's version (true)", CScript() << OP_VER, PRE, true);
    t.Add("OP_VER from v3 fails", CScript() << OP_VER, V3UP, false);
    t.AddS("OP_VER in a branch not taken is skipped before v3", CScript() << OP_0 << OP_IF << OP_VER << OP_ENDIF << OP_1, PRE, true, Stk{T});
    t.Add("OP_VER in a branch not taken from v3", CScript() << OP_0 << OP_IF << OP_VER << OP_ENDIF << OP_1, V3UP, false);
    t.AddS("OP_VERIF before v3: this version is at least 0, so the branch runs",
           CScript() << OP_0 << OP_VERIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, PRE, true, Stk{OV({2})});
    t.AddS("OP_VERIF before v3 against a number far above any version: the else branch",
           CScript() << OV({0xff, 0xff, 0xff, 0xff, 0x7f}) << OP_VERIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, PRE, true, Stk{OV({3})});
    t.AddS("OP_VERNOTIF before v3 is the opposite",
           CScript() << OP_0 << OP_VERNOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, PRE, true, Stk{OV({3})});
    t.Add("OP_VERIF from v3 fails", CScript() << OP_0 << OP_VERIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, V3UP, false);
    t.Add("OP_VERNOTIF from v3 fails", CScript() << OP_0 << OP_VERNOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF, V3UP, false);
    t.Add("OP_VERIF in a branch not taken from v3 fails", CScript() << OP_0 << OP_IF << OP_VERIF << OP_ENDIF << OP_ENDIF << OP_1, V3UP, false);
    t.Add("OP_VERNOTIF in a branch not taken from v3 fails", CScript() << OP_0 << OP_IF << OP_VERNOTIF << OP_ENDIF << OP_ENDIF << OP_1, V3UP, false);
    t.Add("OP_VERIF with no condition on an empty stack", CScript() << OP_VERIF << OP_ENDIF, PRE, false);
    // Before v3, in a branch not taken, OP_VERIF and OP_VERNOTIF still open a branch of their own, as OP_IF
    // does: it takes its own OP_ENDIF (Bitcoin made them invalid everywhere, so the question never arises).
    t.AddS("OP_VERIF in a branch not taken opens a branch: two ENDIFs close it", CScript() << OP_0 << OP_IF << OP_VERIF << OP_ENDIF << OP_ENDIF << OP_1, PRE, true, Stk{T});
    t.Add("and with one ENDIF the outer IF is left open: false", CScript() << OP_0 << OP_IF << OP_VERIF << OP_ENDIF << OP_1, PRE, false);
    t.AddS("OP_VERNOTIF in a branch not taken opens a branch: two ENDIFs close it", CScript() << OP_0 << OP_IF << OP_VERNOTIF << OP_ENDIF << OP_ENDIF << OP_1, PRE, true, Stk{T});
    t.Add("and with one ENDIF the outer IF is left open: false (OP_VERNOTIF)", CScript() << OP_0 << OP_IF << OP_VERNOTIF << OP_ENDIF << OP_1, PRE, false);
    // The limits.
    t.AddS("201 non-push opcodes are allowed", CScript() << OP_1 << OpRun(OP_NOP, 201), ALL, true, Stk{T});
    t.Add("202 are not", CScript() << OP_1 << OpRun(OP_NOP, 202), ALL, false);
    t.Add("pushes are not counted: 300 of OP_1 .. then 201 NOPs is fine (stack 300)", CScript() << OpRun(OP_1, 300) << OpRun(OP_NOP, 201), ALL, true);
    t.AddS("opcodes in a branch not taken count too: 201 in all is allowed",
           CScript() << OP_0 << OP_IF << OpRun(OP_NOP, 199) << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.Add("and 202 in all is not", CScript() << OP_0 << OP_IF << OpRun(OP_NOP, 200) << OP_ENDIF << OP_1, ALL, false);
    t.AddS("a stack of 1000 elements is allowed", OpRepeat(OP_1, 1000), ALL, true, Stk(1000, T));
    t.Add("a stack of 1001 is not", OpRepeat(OP_1, 1001), ALL, false);
    t.Add("999 and a DUP reaches exactly 1000", CScript() << OpRun(OP_1, 999) << OP_DUP, ALL, true);
    t.Add("1000 and a DUP is one too many", CScript() << OpRun(OP_1, 1000) << OP_DUP, ALL, false);
    t.Add("the altstack counts against the same 1000 (999 + 1 moved + 2 pushed)", CScript() << OpRun(OP_1, 999) << OP_TOALTSTACK << OP_1 << OP_1, ALL, false);
    t.Add("998 on the stack + 1 on the altstack + 1 = 1000: allowed", CScript() << OpRun(OP_1, 999) << OP_TOALTSTACK << OP_1, ALL, true);

    // ---- stack operations
    t.cur = "stack operations";
    t.AddS("TOALTSTACK takes the top", CScript() << OP_1 << OP_2 << OP_TOALTSTACK, ALL, true, Stk{T});
    t.AddS("FROMALTSTACK brings it back", CScript() << OP_1 << OP_2 << OP_TOALTSTACK << OP_FROMALTSTACK, ALL, true, Stk{T, OV({2})});
    t.AddS("the altstack is last in, first out", CScript() << OP_1 << OP_TOALTSTACK << OP_2 << OP_TOALTSTACK << OP_FROMALTSTACK << OP_FROMALTSTACK, ALL, true, Stk{OV({2}), T});
    t.AddS("what is left on the altstack does not matter", CScript() << OP_1 << OP_1 << OP_TOALTSTACK, ALL, true, Stk{T});
    t.Add("FROMALTSTACK with an empty altstack", CScript() << OP_1 << OP_FROMALTSTACK, ALL, false);
    t.AddS("2DROP", CScript() << OP_1 << OP_2 << OP_3 << OP_2DROP, ALL, true, Stk{T});
    t.AddS("2DUP", CScript() << OP_1 << OP_2 << OP_2DUP, ALL, true, Stk{T, OV({2}), T, OV({2})});
    t.AddS("3DUP", CScript() << OP_1 << OP_2 << OP_3 << OP_3DUP, ALL, true, Stk{T, OV({2}), OV({3}), T, OV({2}), OV({3})});
    t.AddS("2OVER", CScript() << OP_1 << OP_2 << OP_3 << OP_4 << OP_2OVER, ALL, true, Stk{T, OV({2}), OV({3}), OV({4}), T, OV({2})});
    t.AddS("2ROT", CScript() << OP_1 << OP_2 << OP_3 << OP_4 << OP_5 << OP_6 << OP_2ROT, ALL, true, Stk{OV({3}), OV({4}), OV({5}), OV({6}), T, OV({2})});
    t.AddS("2SWAP", CScript() << OP_1 << OP_2 << OP_3 << OP_4 << OP_2SWAP, ALL, true, Stk{OV({3}), OV({4}), T, OV({2})});
    t.AddS("IFDUP of a true value duplicates it", CScript() << OP_1 << OP_IFDUP, ALL, true, Stk{T, T});
    t.AddS("IFDUP of a false value does not", CScript() << OP_0 << OP_IFDUP, ALL, false, Stk{F});
    t.AddS("IFDUP of a negative zero does not", CScript() << OV({0x80}) << OP_IFDUP, ALL, false, Stk{OV({0x80})});
    t.AddS("DEPTH of an empty stack is 0", CScript() << OP_DEPTH, ALL, false, Stk{F});
    t.AddS("DEPTH counts the stack", CScript() << OP_5 << OP_6 << OP_DEPTH, ALL, true, Stk{OV({5}), OV({6}), OV({2})});
    t.AddS("DROP", CScript() << OP_1 << OP_2 << OP_DROP, ALL, true, Stk{T});
    t.AddS("DUP", CScript() << OP_1 << OP_DUP, ALL, true, Stk{T, T});
    t.AddS("NIP", CScript() << OP_1 << OP_2 << OP_NIP, ALL, true, Stk{OV({2})});
    t.AddS("OVER", CScript() << OP_1 << OP_2 << OP_OVER, ALL, true, Stk{T, OV({2}), T});
    t.AddS("PICK copies the element n deep", CScript() << OP_1 << OP_2 << OP_3 << OP_2 << OP_PICK, ALL, true, Stk{T, OV({2}), OV({3}), T});
    t.AddS("PICK 0 is DUP", CScript() << OP_1 << OP_0 << OP_PICK, ALL, true, Stk{T, T});
    t.AddS("ROLL moves the element n deep", CScript() << OP_1 << OP_2 << OP_3 << OP_2 << OP_ROLL, ALL, true, Stk{OV({2}), OV({3}), T});
    t.AddS("ROLL 0 does nothing", CScript() << OP_1 << OP_0 << OP_ROLL, ALL, true, Stk{T});
    t.AddS("PICK reads its index as a number: 0x0100 is 1", CScript() << OP_1 << OP_2 << OV({1, 0}) << OP_PICK, ALL, true, Stk{T, OV({2}), T});
    t.AddS("PICK of a negative zero index is index 0", CScript() << OP_1 << OV({0x80}) << OP_PICK, ALL, true, Stk{T, T});
    t.Add("PICK past the bottom", CScript() << OP_1 << OP_1 << OP_PICK, ALL, false);
    t.Add("ROLL past the bottom", CScript() << OP_1 << OP_1 << OP_ROLL, ALL, false);
    t.Add("PICK with a negative index", CScript() << OP_1 << OP_1NEGATE << OP_PICK, ALL, false);
    t.Add("ROLL with a negative index", CScript() << OP_1 << OP_1NEGATE << OP_ROLL, ALL, false);
    t.Add("PICK with an index that does not fit an int", CScript() << OP_1 << OV({0xff, 0xff, 0xff, 0xff, 0x00}) << OP_PICK, ALL, false);
    // 2^32: its low 32 bits are zero, which reads as index 0 where an int is 32 bits (the fix of CBigNum::getint).
    t.Add("PICK with an index of 2^32 fails (not index 0)", CScript() << OP_1 << OV({0, 0, 0, 0, 1}) << OP_PICK, ALL, false);
    t.Add("ROLL with an index of 2^32 fails (not index 0)", CScript() << OP_1 << OV({0, 0, 0, 0, 1}) << OP_ROLL, ALL, false);
    t.AddS("ROT", CScript() << OP_1 << OP_2 << OP_3 << OP_ROT, ALL, true, Stk{OV({2}), OV({3}), T});
    t.AddS("SWAP", CScript() << OP_1 << OP_2 << OP_SWAP, ALL, true, Stk{OV({2}), T});
    t.AddS("TUCK", CScript() << OP_1 << OP_2 << OP_TUCK, ALL, true, Stk{OV({2}), T, OV({2})});
    t.AddS("SIZE of three bytes", CScript() << OV({1, 2, 3}) << OP_SIZE, ALL, true, Stk{OV({1, 2, 3}), OV({3})});
    t.AddS("SIZE of an empty element is 0", CScript() << OP_0 << OP_SIZE, ALL, false, Stk{F, F});
    t.AddS("SIZE of a 520-byte element", CScript() << OpBytes(520, 1) << OP_SIZE, ALL, true, Stk{OpBytes(520, 1), OV({0x08, 0x02})});
    {
        // Every stack operation one element short of what it needs.
        struct { opcodetype op; int need; } aNeed[] = {
            { OP_TOALTSTACK, 1 }, { OP_2DROP, 2 }, { OP_2DUP, 2 }, { OP_3DUP, 3 }, { OP_2OVER, 4 }, { OP_2ROT, 6 },
            { OP_2SWAP, 4 }, { OP_IFDUP, 1 }, { OP_DROP, 1 }, { OP_DUP, 1 }, { OP_NIP, 2 }, { OP_OVER, 2 },
            { OP_PICK, 2 }, { OP_ROLL, 2 }, { OP_ROT, 3 }, { OP_SWAP, 2 }, { OP_TUCK, 2 }, { OP_SIZE, 1 },
            { OP_EQUAL, 2 }, { OP_EQUALVERIFY, 2 }, { OP_1ADD, 1 }, { OP_1SUB, 1 }, { OP_NEGATE, 1 }, { OP_ABS, 1 },
            { OP_NOT, 1 }, { OP_0NOTEQUAL, 1 }, { OP_ADD, 2 }, { OP_SUB, 2 }, { OP_BOOLAND, 2 }, { OP_BOOLOR, 2 },
            { OP_NUMEQUAL, 2 }, { OP_NUMEQUALVERIFY, 2 }, { OP_NUMNOTEQUAL, 2 }, { OP_LESSTHAN, 2 },
            { OP_GREATERTHAN, 2 }, { OP_LESSTHANOREQUAL, 2 }, { OP_GREATERTHANOREQUAL, 2 }, { OP_MIN, 2 },
            { OP_MAX, 2 }, { OP_WITHIN, 3 }, { OP_RIPEMD160, 1 }, { OP_SHA1, 1 }, { OP_SHA256, 1 },
            { OP_HASH160, 1 }, { OP_HASH256, 1 }, { OP_CHECKSIG, 2 }, { OP_CHECKSIGVERIFY, 2 },
        };
        for (size_t i = 0; i < sizeof(aNeed) / sizeof(aNeed[0]); i++)
            t.Add(strprintf("%s with %d element%s fails", GetOpName(aNeed[i].op), aNeed[i].need - 1, aNeed[i].need == 2 ? "" : "s"),
                  OpRepeat(OP_1, aNeed[i].need - 1) << aNeed[i].op, ALL, false);
    }

    // ---- the disabled splice, bitwise and arithmetic opcodes
    // Bitcoin removed these in 0.3.x because OP_CAT and the shifts can be used
    // to exhaust memory; this node does the same, from genesis, under every
    // rule set, and -- as Bitcoin does -- even in a branch that is not taken.
    t.cur = "disabled opcodes";
    {
        const opcodetype aDisabled[] = { OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR,
                                         OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT };
        for (size_t i = 0; i < sizeof(aDisabled) / sizeof(aDisabled[0]); i++)
        {
            t.Add(strprintf("%s with operands ready fails", GetOpName(aDisabled[i])),
                  OpRepeat(OP_1, 3) << aDisabled[i], ALL, false);
            t.Add(strprintf("%s fails in a branch not taken", GetOpName(aDisabled[i])),
                  CScript() << OP_0 << OP_IF << aDisabled[i] << OP_ENDIF << OP_1, ALL, false);
            t.Add(strprintf("%s fails on an empty stack too", GetOpName(aDisabled[i])),
                  CScript() << aDisabled[i], ALL, false);
        }
    }

    // ---- equality
    t.cur = "equality";
    t.AddS("EQUAL of equal numbers", CScript() << OP_1 << OP_1 << OP_EQUAL, ALL, true, Stk{T});
    t.AddS("EQUAL of different numbers", CScript() << OP_1 << OP_2 << OP_EQUAL, ALL, false, Stk{F});
    t.AddS("EQUAL of two empty elements", CScript() << OP_0 << OP_0 << OP_EQUAL, ALL, true, Stk{T});
    t.AddS("EQUAL of OP_0 and an empty PUSHDATA1", OpCat(CScript() << OP_0, OV({0x4c, 0x00})) << OP_EQUAL, ALL, true, Stk{T});
    t.AddS("EQUAL compares bytes: 0x01 and 0x0100 differ", CScript() << OV({1}) << OV({1, 0}) << OP_EQUAL, ALL, false, Stk{F});
    t.AddS("EQUAL compares bytes: negative zero and empty differ", CScript() << OV({0x80}) << OP_0 << OP_EQUAL, ALL, false, Stk{F});
    t.AddS("EQUAL of equal 520-byte elements", CScript() << OpBytes(520, 3) << OpBytes(520, 3) << OP_EQUAL, ALL, true, Stk{T});
    t.AddS("EQUALVERIFY of equal values pops both and goes on", CScript() << OP_1 << OP_1 << OP_EQUALVERIFY << OP_1, ALL, true, Stk{T});
    t.Add("EQUALVERIFY of different values fails", CScript() << OP_1 << OP_2 << OP_EQUALVERIFY << OP_1, ALL, false);

    // ---- arithmetic
    t.cur = "arithmetic";
    {
        struct { opcodetype op; int64 a, r; } aUn[] = {
            { OP_1ADD, 0, 1 }, { OP_1ADD, 1, 2 }, { OP_1ADD, -1, 0 }, { OP_1ADD, 127, 128 }, { OP_1ADD, 255, 256 },
            { OP_1ADD, 2147483647LL, 2147483648LL }, { OP_1ADD, -2147483648LL, -2147483647LL },
            { OP_1SUB, 0, -1 }, { OP_1SUB, 1, 0 }, { OP_1SUB, -127, -128 }, { OP_1SUB, 128, 127 },
            { OP_NEGATE, 5, -5 }, { OP_NEGATE, 0, 0 }, { OP_NEGATE, -5, 5 }, { OP_NEGATE, 127, -127 }, { OP_NEGATE, 128, -128 },
            { OP_ABS, -5, 5 }, { OP_ABS, 5, 5 }, { OP_ABS, 0, 0 }, { OP_ABS, -128, 128 },
            { OP_NOT, 0, 1 }, { OP_NOT, 1, 0 }, { OP_NOT, 5, 0 }, { OP_NOT, -1, 0 },
            { OP_0NOTEQUAL, 0, 0 }, { OP_0NOTEQUAL, 5, 1 }, { OP_0NOTEQUAL, -5, 1 },
        };
        for (size_t i = 0; i < sizeof(aUn) / sizeof(aUn[0]); i++)
            t.AddS(strprintf("%s of %lld is %lld", GetOpName(aUn[i].op), (long long)aUn[i].a, (long long)aUn[i].r),
                   CScript() << aUn[i].a << aUn[i].op, ALL, aUn[i].r != 0, Stk{OpNum(aUn[i].r)});

        struct { opcodetype op; int64 a, b, r; } aBin[] = {
            { OP_ADD, 2, 3, 5 }, { OP_ADD, -2, 3, 1 }, { OP_ADD, 0, 0, 0 }, { OP_ADD, -5, -6, -11 },
            { OP_ADD, 2147483647LL, 1, 2147483648LL }, { OP_ADD, 2147483647LL, 2147483647LL, 4294967294LL },
            { OP_ADD, -2147483647LL, -2147483647LL, -4294967294LL },
            { OP_SUB, 2, 3, -1 }, { OP_SUB, 3, 2, 1 }, { OP_SUB, 0, 5, -5 }, { OP_SUB, -3, -4, 1 }, { OP_SUB, 5, 5, 0 },
            { OP_BOOLAND, 1, 0, 0 }, { OP_BOOLAND, 1, 2, 1 }, { OP_BOOLAND, 0, 0, 0 }, { OP_BOOLAND, -1, -1, 1 },
            { OP_BOOLOR, 0, 0, 0 }, { OP_BOOLOR, 0, 1, 1 }, { OP_BOOLOR, -3, 0, 1 },
            { OP_NUMEQUAL, 2, 2, 1 }, { OP_NUMEQUAL, 2, 3, 0 }, { OP_NUMEQUAL, -1, -1, 1 }, { OP_NUMEQUAL, 0, 0, 1 },
            { OP_NUMNOTEQUAL, 2, 3, 1 }, { OP_NUMNOTEQUAL, 2, 2, 0 },
            { OP_LESSTHAN, 2, 3, 1 }, { OP_LESSTHAN, 3, 2, 0 }, { OP_LESSTHAN, 2, 2, 0 }, { OP_LESSTHAN, -3, -2, 1 }, { OP_LESSTHAN, -1, 0, 1 },
            { OP_GREATERTHAN, 3, 2, 1 }, { OP_GREATERTHAN, 2, 3, 0 }, { OP_GREATERTHAN, 2, 2, 0 }, { OP_GREATERTHAN, 0, -1, 1 },
            { OP_LESSTHANOREQUAL, 2, 2, 1 }, { OP_LESSTHANOREQUAL, 2, 3, 1 }, { OP_LESSTHANOREQUAL, 3, 2, 0 },
            { OP_GREATERTHANOREQUAL, 2, 2, 1 }, { OP_GREATERTHANOREQUAL, 3, 2, 1 }, { OP_GREATERTHANOREQUAL, 2, 3, 0 },
            { OP_MIN, 2, 3, 2 }, { OP_MIN, 3, 2, 2 }, { OP_MIN, -1, 1, -1 }, { OP_MIN, 5, 5, 5 },
            { OP_MAX, 2, 3, 3 }, { OP_MAX, 3, 2, 3 }, { OP_MAX, -1, 1, 1 }, { OP_MAX, -5, -7, -5 },
        };
        for (size_t i = 0; i < sizeof(aBin) / sizeof(aBin[0]); i++)
            t.AddS(strprintf("%lld %lld %s is %lld", (long long)aBin[i].a, (long long)aBin[i].b, GetOpName(aBin[i].op), (long long)aBin[i].r),
                   CScript() << aBin[i].a << aBin[i].b << aBin[i].op, ALL, aBin[i].r != 0, Stk{OpNum(aBin[i].r)});

        struct { int64 x, lo, hi, r; } aWithin[] = {
            { 2, 1, 3, 1 }, { 1, 1, 3, 1 }, { 3, 1, 3, 0 }, { 0, 1, 3, 0 }, { -1, -2, 0, 1 }, { 5, 5, 5, 0 }, { 5, 6, 4, 0 },
        };
        for (size_t i = 0; i < sizeof(aWithin) / sizeof(aWithin[0]); i++)
            t.AddS(strprintf("%lld in [%lld, %lld) is %lld", (long long)aWithin[i].x, (long long)aWithin[i].lo, (long long)aWithin[i].hi, (long long)aWithin[i].r),
                   CScript() << aWithin[i].x << aWithin[i].lo << aWithin[i].hi << OP_WITHIN, ALL, aWithin[i].r != 0, Stk{OpNum(aWithin[i].r)});
    }
    t.AddS("NUMEQUALVERIFY of equal numbers goes on", CScript() << OP_2 << OP_2 << OP_NUMEQUALVERIFY << OP_1, ALL, true, Stk{T});
    t.Add("NUMEQUALVERIFY of different numbers fails", CScript() << OP_2 << OP_3 << OP_NUMEQUALVERIFY << OP_1, ALL, false);
    // Numbers are read as Bitcoin 0.1.0 read them: any length, negative zero
    // is zero, a number need not be minimal, and the result is always minimal.
    t.AddS("negative zero is zero for NOT", CScript() << OV({0x80}) << OP_NOT, ALL, true, Stk{T});
    t.AddS("negative zero is zero for 0NOTEQUAL", CScript() << OV({0x80}) << OP_0NOTEQUAL, ALL, false, Stk{F});
    t.AddS("negative zero plus one", CScript() << OV({0x80}) << OP_1ADD, ALL, true, Stk{T});
    t.AddS("negating a negative zero is the empty zero", CScript() << OV({0x80}) << OP_NEGATE, ALL, false, Stk{F});
    t.AddS("the absolute value of a negative zero", CScript() << OV({0x80}) << OP_ABS, ALL, false, Stk{F});
    t.AddS("0x0000 is zero for NOT", CScript() << OV({0, 0}) << OP_NOT, ALL, true, Stk{T});
    t.AddS("0x0000000000 plus one", CScript() << OV({0, 0, 0, 0, 0}) << OP_1ADD, ALL, true, Stk{T});
    t.AddS("a non-minimal 1 plus one", CScript() << OV({1, 0}) << OP_1ADD, ALL, true, Stk{OV({2})});
    t.AddS("a non-minimal -2 (0x0280) plus one is -1", CScript() << OV({2, 0x80}) << OP_1ADD, ALL, true, Stk{OV({0x81})});
    t.AddS("NUMEQUAL ignores padding", CScript() << OV({1, 0, 0, 0}) << OP_1 << OP_NUMEQUAL, ALL, true, Stk{T});
    t.AddS("NUMEQUAL: negative zero equals zero", CScript() << OV({0x80}) << OP_0 << OP_NUMEQUAL, ALL, true, Stk{T});
    // Not Bitcoin's 4-byte limit: this node reads operands of any length (up
    // to the 520 an element can hold), as 0.1.0 did, and a changed rule here
    // would be a fork. The results are exact, with no wrap at 2^31 or 2^32.
    t.AddS("a 4-byte maximum plus one does not wrap: a 5-byte result", CScript() << OV({0xff, 0xff, 0xff, 0x7f}) << OP_1ADD, ALL, true, Stk{OV({0, 0, 0, 0x80, 0})});
    t.AddS("a 5-byte operand is accepted (Bitcoin refuses an operand over four bytes)", CScript() << OV({0, 0, 0, 0x80, 0}) << OP_1ADD, ALL, true, Stk{OV({1, 0, 0, 0x80, 0})});
    t.AddS("an 8-byte operand is accepted", CScript() << OV({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}) << OP_1ADD, ALL, true, Stk{OV({0, 0, 0, 0, 0, 0, 0, 0x80, 0})});
    t.AddS("two 8-byte operands add exactly", CScript() << OV({1, 0, 0, 0, 0, 0, 0, 0}) << OV({1, 0, 0, 0, 0, 0, 0, 0}) << OP_ADD, ALL, true, Stk{OV({2})});
    t.AddS("an operand of 0x0100000000 (2^32) is 2^32", CScript() << OV({0, 0, 0, 0, 1}) << OP_1SUB, ALL, true, Stk{OV({0xff, 0xff, 0xff, 0xff, 0})});
    t.AddS("a 520-byte zero is zero", CScript() << OpBytes(520, 0) << OP_NOT, ALL, true, Stk{T});
    t.AddS("-(2^31-1) negated", CScript() << OV({0xff, 0xff, 0xff, 0xff}) << OP_NEGATE, ALL, true, Stk{OV({0xff, 0xff, 0xff, 0x7f})});

    // ---- crypto
    t.cur = "hash opcodes";
    {
        const OpVal abc = OV({'a', 'b', 'c'});
        struct { opcodetype op; bool fAbc; const char* hex; } aHash[] = {
            { OP_RIPEMD160, false, "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
            { OP_SHA1,      false, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
            { OP_SHA256,    false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { OP_HASH160,   false, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" },
            { OP_HASH256,   false, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" },
            { OP_RIPEMD160, true,  "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
            { OP_SHA1,      true,  "a9993e364706816aba3e25717850c26c9cd0d89d" },
            { OP_SHA256,    true,  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            { OP_HASH160,   true,  "bb1be98c142444d7a56aa3981c3942a978e4dc33" },
            { OP_HASH256,   true,  "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358" },
        };
        for (size_t i = 0; i < sizeof(aHash) / sizeof(aHash[0]); i++)
        {
            CScript s;
            if (aHash[i].fAbc)
                s << abc;
            else
                s << OP_0;
            s << aHash[i].op;
            t.AddS(strprintf("%s of %s", GetOpName(aHash[i].op), aHash[i].fAbc ? "\"abc\"" : "the empty string"),
                   s, ALL, true, Stk{ParseHex(aHash[i].hex)});
        }
    }
    t.AddS("SHA256 twice is HASH256", CScript() << OP_0 << OP_SHA256 << OP_SHA256, ALL, true,
           Stk{ParseHex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")});
    t.AddS("HASH160 is RIPEMD160 of SHA256", CScript() << OP_0 << OP_SHA256 << OP_RIPEMD160, ALL, true,
           Stk{ParseHex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")});
    t.Add("a 520-byte element hashes", CScript() << OpBytes(520, 0xab) << OP_SHA256 << OP_SIZE << OP_NIP, ALL, true);
    t.AddS("the hash of a hash has the right size (20 for HASH160)", CScript() << OP_1 << OP_HASH160 << OP_SIZE << OP_NIP, ALL, true, Stk{OV({20})});
    t.AddS("and 32 for HASH256", CScript() << OP_1 << OP_HASH256 << OP_SIZE << OP_NIP, ALL, true, Stk{OV({32})});

    // ---- code separator and the signature opcodes that need no signature
    t.cur = "code separator and signature opcodes";
    t.AddS("CODESEPARATOR does nothing to the stack", CScript() << OP_1 << OP_CODESEPARATOR, ALL, true, Stk{T});
    t.AddS("CODESEPARATOR in a branch not taken", CScript() << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("CHECKSIG of an empty signature and key is false, not a failure", CScript() << OP_0 << OP_0 << OP_CHECKSIG, ALL, false, Stk{F});
    t.AddS("CHECKSIG of garbage is false", CScript() << OV({1, 2, 3}) << OV({4, 5, 6}) << OP_CHECKSIG, ALL, false, Stk{F});
    t.Add("CHECKSIGVERIFY of garbage fails", CScript() << OV({1, 2, 3}) << OV({4, 5, 6}) << OP_CHECKSIGVERIFY << OP_1, ALL, false);
    t.AddS("CHECKMULTISIG, no signatures and no keys, takes the dummy: true",
           CScript() << OP_0 << OP_0 << OP_0 << OP_CHECKMULTISIG, ALL, true, Stk{T});
    t.Add("CHECKMULTISIG without the dummy element fails", CScript() << OP_0 << OP_0 << OP_CHECKMULTISIG, ALL, false);
    t.AddS("CHECKMULTISIGVERIFY, no signatures and no keys", CScript() << OP_0 << OP_0 << OP_0 << OP_CHECKMULTISIGVERIFY << OP_1, ALL, true, Stk{T});
    t.Add("CHECKMULTISIG with more keys than the stack holds", CScript() << OP_0 << OP_0 << OP_5 << OP_CHECKMULTISIG, ALL, false);
    t.Add("CHECKMULTISIG with a negative key count", CScript() << OP_0 << OP_0 << OP_1NEGATE << OP_CHECKMULTISIG, ALL, false);
    t.Add("CHECKMULTISIG with more signatures than keys", CScript() << OP_0 << OP_2 << OP_0 << OP_1 << OP_CHECKMULTISIG, ALL, false);
    t.Add("CHECKMULTISIG with a negative signature count", CScript() << OP_0 << OP_1NEGATE << OP_0 << OP_1 << OP_CHECKMULTISIG, ALL, false);
    t.AddS("CHECKMULTISIG of an empty signature against an empty key is false",
           CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_CHECKMULTISIG, ALL, false, Stk{F});
    t.Add("CHECKMULTISIGVERIFY of that fails", CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_CHECKMULTISIGVERIFY << OP_1, ALL, false);
    t.AddS("20 keys and no signatures: allowed everywhere",
           CScript() << OP_0 << OP_0 << OpRun(OP_0, 20) << 20 << OP_CHECKMULTISIG, ALL, true, Stk{T});
    // Rules v5: at most MAX_PUBKEYS_PER_MULTISIG (20) keys, the 20 signature
    // operations the block is charged for it.
    t.AddS("21 keys and no signatures before v5", CScript() << OP_0 << OP_0 << OpRun(OP_0, 21) << 21 << OP_CHECKMULTISIG, ALL & ~V5, true, Stk{T});
    t.Add("21 keys under rules v5 fail", CScript() << OP_0 << OP_0 << OpRun(OP_0, 21) << 21 << OP_CHECKMULTISIG, V5, false);
    t.Add("a key count of 2^32 + 1 fails (not 1)", CScript() << OP_0 << OP_0 << OV({1, 0, 0, 0, 1}) << OP_CHECKMULTISIG, ALL, false);
    t.Add("a signature count of 2^32 with one key fails (not 0 signatures, which would pass)", CScript() << OP_0 << OV({0, 0, 0, 0, 1}) << OP_0 << OP_1 << OP_CHECKMULTISIG, ALL, false);
    // Bitcoin adds the key count of an OP_CHECKMULTISIG to the 201-opcode count; this node counts the opcode
    // alone (the 20 signature operations are charged to the block by GetSigOpCount instead). So 20 keys and
    // 190 NOPs, 211 by Bitcoin's count, are 191 here and pass; 201 NOPs after it are 202 and fail.
    t.AddS("20 keys and 190 NOPs pass here (211 by Bitcoin's count)", CScript() << OP_0 << OP_0 << OpRun(OP_0, 20) << 20 << OP_CHECKMULTISIG << OpRun(OP_NOP, 190), ALL, true, Stk{T});
    t.Add("the multisig opcode itself still counts: 201 NOPs after it are one too many", CScript() << OP_0 << OP_0 << OpRun(OP_0, 20) << 20 << OP_CHECKMULTISIG << OpRun(OP_NOP, 201), ALL, false);

    // ---- the NOP bytes and the bytes no rule gives a meaning
    // Bitcoin runs 0xb0 and 0xb3..0xb9 as NOPs and leaves them to soft forks.
    // This node has no upgradable NOPs: the byte is unknown and fails the
    // script that runs it, like 0xba and every byte above the assigned ones.
    // Only OP_NOP (0x61) is a NOP. A byte not run (a branch not taken) is
    // skipped, as is an opcode of any value.
    t.cur = "unassigned bytes";
    t.AddS("OP_NOP (0x61)", OpRaw({0x61, 0x51}), ALL, true, Stk{T});
    {
        const int aUnknown[] = { 0xb0, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xc0, 0xcb, 0xcd, 0xd0, 0xef };
        for (size_t i = 0; i < sizeof(aUnknown) / sizeof(aUnknown[0]); i++)
        {
            t.Add(strprintf("byte 0x%02x run fails (Bitcoin: NOP or reserved, here unknown)", aUnknown[i]),
                  OpRaw({0x51, aUnknown[i]}), ALL, false);
            t.AddS(strprintf("byte 0x%02x in a branch not taken is skipped", aUnknown[i]),
                   OpCat(CScript() << OP_0 << OP_IF, OV({aUnknown[i]})) << OP_ENDIF << OP_1, ALL, true, Stk{T});
        }
    }
    t.Add("a two-byte opcode (0xf000) run fails", OpRaw({0xf0, 0x00}), ALL, false);
    t.AddS("a two-byte opcode in a branch not taken is skipped", OpCat(CScript() << OP_0 << OP_IF, OV({0xf0, 0x00})) << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.Add("a lone 0xf0 as the last byte inside a branch not taken fails: its second byte is missing, so the script cannot be read (the two-byte form above, closed, passes)", OpCat(CScript() << OP_0 << OP_IF, OV({0xf0})), ALL, false);

    // ---- OP_CHECKLOCKTIMEVERIFY (rules v3)
    t.cur = "OP_CHECKLOCKTIMEVERIFY";
    t.Add("before v3 the byte is unknown and fails", CScript() << 100 << OP_CHECKLOCKTIMEVERIFY, PRE, false, TX_LOCK100);
    t.AddS("before v3 it is skipped in a branch not taken", CScript() << OP_0 << OP_IF << OP_CHECKLOCKTIMEVERIFY << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("lock 100, tx lock time 100: satisfied, and the lock stays on the stack", CScript() << 100 << OP_CHECKLOCKTIMEVERIFY, V3UP, true, Stk{OV({100})}, TX_LOCK100);
    t.AddS("lock 99 is passed", CScript() << 99 << OP_CHECKLOCKTIMEVERIFY, V3UP, true, Stk{OV({99})}, TX_LOCK100);
    t.Add("lock 101 is not yet", CScript() << 101 << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100);
    t.AddS("lock 0", CScript() << OP_0 << OP_CHECKLOCKTIMEVERIFY << OP_1, V3UP, true, Stk{F, T}, TX_LOCK100);
    t.Add("a negative lock fails", CScript() << OP_1NEGATE << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100);
    t.Add("an empty stack fails", CScript() << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100);
    t.AddS("a 5-byte lock is read (a time after 2038 needs five)", CScript() << OV({100, 0, 0, 0, 0}) << OP_CHECKLOCKTIMEVERIFY, V3UP, true, Stk{OV({100, 0, 0, 0, 0})}, TX_LOCK100);
    t.Add("a 6-byte lock fails", CScript() << OV({100, 0, 0, 0, 0, 0}) << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100);
    t.AddS("a time lock against a time", CScript() << 500000000 << OP_CHECKLOCKTIMEVERIFY, V3UP, true, Stk{OV({0x00, 0x65, 0xcd, 0x1d})}, TX_LOCKTIME);
    t.Add("a time lock not yet reached", CScript() << 600000001 << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCKTIME);
    t.Add("a height lock does not satisfy a time (units differ)", CScript() << 100 << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCKTIME);
    t.Add("a time lock does not satisfy a height", CScript() << 500000000 << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100);
    t.Add("a final input switches the lock off: fails", CScript() << 100 << OP_CHECKLOCKTIMEVERIFY, V3UP, false, TX_LOCK100_FINAL);
    t.Add("lock time 0 and a final input", CScript() << OP_0 << OP_CHECKLOCKTIMEVERIFY << OP_1, V3UP, false, TX_PLAIN);

    // ---- OP_CHECKSEQUENCEVERIFY (rules v4)
    t.cur = "OP_CHECKSEQUENCEVERIFY";
    const unsigned CSVPRE = PRE | V3;
    t.Add("before v4 the byte is unknown and fails", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, CSVPRE, false, TX_SEQ10);
    t.AddS("before v4 it is skipped in a branch not taken", CScript() << OP_0 << OP_IF << OP_CHECKSEQUENCEVERIFY << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("sequence 10, lock 10", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10})}, TX_SEQ10);
    t.AddS("lock 5", CScript() << 5 << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({5})}, TX_SEQ10);
    t.Add("lock 11 is not yet", CScript() << 11 << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ10);
    t.AddS("lock 0", CScript() << OP_0 << OP_CHECKSEQUENCEVERIFY << OP_1, V4UP, true, Stk{F, T}, TX_SEQ10);
    t.AddS("a negative zero lock is 0, not 128", CScript() << OV({0x80}) << OP_CHECKSEQUENCEVERIFY << OP_1, V4UP, true, Stk{OV({0x80}), T}, TX_SEQ10);
    t.Add("a negative lock fails", CScript() << OP_1NEGATE << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ10);
    t.Add("an empty stack fails", CScript() << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ10);
    t.Add("a 6-byte lock fails", CScript() << OV({10, 0, 0, 0, 0, 0}) << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ10);
    t.Add("transaction version 1 has no relative locks", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_V1_SEQ10);
    t.AddS("a negative transaction version reads as a large one (unsigned, as in Bitcoin)", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10})}, TX_NEGVERSION);
    t.Add("an input with the disable flag set fails", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ_DISABLED);
    t.Add("a final input has the disable flag (version 2, so it is the sequence that refuses it)", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_V2_FINAL);
    t.Add("blocks against a time-based input", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQTIME10);
    t.AddS("time against time", CScript() << OV({10, 0, 0x40}) << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10, 0, 0x40})}, TX_SEQTIME10);
    t.Add("time against blocks", CScript() << OV({10, 0, 0x40}) << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQ10);
    t.Add("a time lock longer than the input's", CScript() << OV({11, 0, 0x40}) << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_SEQTIME10);
    t.AddS("bits outside the mask mean nothing (bit 21)", CScript() << OV({10, 0, 0x20}) << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10, 0, 0x20})}, TX_SEQ10);
    t.AddS("nothing above bit 31 means anything (2^32 + 10)", CScript() << OV({10, 0, 0, 0, 1}) << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10, 0, 0, 0, 1})}, TX_SEQ10);
    // Bit 31 in the script's number is an upgrade hook: consensus lets it pass
    // whatever the transaction, relay policy refuses it.
    t.AddS("bit 31 in the lock passes by consensus (a hook for a later rule), on any transaction",
           CScript() << OV({0, 0, 0, 0x80, 0}) << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({0, 0, 0, 0x80, 0})}, TX_PLAIN);
    t.Add("and relay policy refuses it", CScript() << OV({0, 0, 0, 0x80, 0}) << OP_CHECKSEQUENCEVERIFY, V4UP, false, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
    t.AddS("policy leaves an ordinary lock alone", CScript() << 10 << OP_CHECKSEQUENCEVERIFY, V4UP, true, Stk{OV({10})}, TX_SEQ10, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);

    // ---- OP_CHECKTEMPLATEVERIFY (rules v4)
    t.cur = "OP_CHECKTEMPLATEVERIFY";
    {
        uint256 hashPlain = CheckTemplateHash(txs[TX_PLAIN], 0);
        OpVal vchHash(hashPlain.begin(), hashPlain.end());
        t.Add("before v4 the byte is unknown and fails", CScript() << vchHash << OP_CHECKTEMPLATEVERIFY, CSVPRE, false, TX_PLAIN);
        t.AddS("before v4 it is skipped in a branch not taken", CScript() << OP_0 << OP_IF << OP_CHECKTEMPLATEVERIFY << OP_ENDIF << OP_1, ALL, true, Stk{T});
        t.AddS("the template hash of this transaction", CScript() << vchHash << OP_CHECKTEMPLATEVERIFY, V4UP, true, Stk{vchHash}, TX_PLAIN);
        t.Add("the same hash on a transaction with another output", CScript() << vchHash << OP_CHECKTEMPLATEVERIFY, V4UP, false, TX_TWO_OUTS);
        t.Add("the same hash on a transaction with another version and sequence", CScript() << vchHash << OP_CHECKTEMPLATEVERIFY, V4UP, false, TX_SEQ10);
        OpVal vchWrong = vchHash;
        vchWrong[31] ^= 1;
        t.Add("a hash one bit off", CScript() << vchWrong << OP_CHECKTEMPLATEVERIFY, V4UP, false, TX_PLAIN);
        t.Add("an empty stack fails", CScript() << OP_CHECKTEMPLATEVERIFY, V4UP, false, TX_PLAIN);
        // Any other size is an upgrade hook: consensus lets it pass.
        t.AddS("a 31-byte argument passes (reserved for a later rule)", CScript() << OpBytes(31, 5) << OP_CHECKTEMPLATEVERIFY << OP_1, V4UP, true, Stk{OpBytes(31, 5), T}, TX_PLAIN);
        t.AddS("a 33-byte argument passes", CScript() << OpBytes(33, 5) << OP_CHECKTEMPLATEVERIFY << OP_1, V4UP, true, Stk{OpBytes(33, 5), T}, TX_PLAIN);
        t.AddS("an empty argument passes", CScript() << OP_0 << OP_CHECKTEMPLATEVERIFY << OP_1, V4UP, true, Stk{F, T}, TX_PLAIN);
        t.Add("relay policy refuses a 31-byte argument", CScript() << OpBytes(31, 5) << OP_CHECKTEMPLATEVERIFY << OP_1, V4UP, false, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
        t.Add("relay policy refuses an empty argument", CScript() << OP_0 << OP_CHECKTEMPLATEVERIFY << OP_1, V4UP, false, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
        t.AddS("relay policy lets the real hash through", CScript() << vchHash << OP_CHECKTEMPLATEVERIFY, V4UP, true, Stk{vchHash}, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
    }

    // ---- OP_CHECKSIGFROMSTACK (rules v4), the cases that need no valid signature
    t.cur = "OP_CHECKSIGFROMSTACK";
    t.Add("before v4 the byte is unknown and fails", CScript() << OP_0 << OP_0 << OpBytes(32, 2) << OP_CHECKSIGFROMSTACK, CSVPRE, false);
    t.AddS("before v4 it is skipped in a branch not taken", CScript() << OP_0 << OP_IF << OP_CHECKSIGFROMSTACK << OP_ENDIF << OP_1, ALL, true, Stk{T});
    t.AddS("an empty signature is the one way to say false (32-byte key)", CScript() << OP_0 << OV({'h', 'i'}) << OpBytes(32, 2) << OP_CHECKSIGFROMSTACK, V4UP, false, Stk{F});
    t.AddS("and OP_NOT of it is true", CScript() << OP_0 << OV({'h', 'i'}) << OpBytes(32, 2) << OP_CHECKSIGFROMSTACK << OP_NOT, V4UP, true, Stk{T});
    t.Add("an empty key fails", CScript() << OP_0 << OP_0 << OP_0 << OP_CHECKSIGFROMSTACK, V4UP, false);
    t.Add("a signature that does not verify against a 32-byte key fails the script", CScript() << OpBytes(64, 1) << OV({'h', 'i'}) << OpBytes(32, 1) << OP_CHECKSIGFROMSTACK, V4UP, false);
    t.Add("a bad signature fails whatever follows", CScript() << OpBytes(64, 1) << OV({'h', 'i'}) << OpBytes(32, 1) << OP_CHECKSIGFROMSTACK << OP_NOT, V4UP, false);
    t.Add("two elements are not enough", CScript() << OP_1 << OP_1 << OP_CHECKSIGFROMSTACK, V4UP, false);
    // A key that is not 32 bytes is an upgrade hook: consensus takes any
    // non-empty signature as valid for it. Relay policy refuses it.
    t.AddS("a 33-byte key with any signature passes by consensus (a hook for a later key type)",
           CScript() << OpBytes(64, 1) << OV({'h', 'i'}) << OpBytes(33, 2) << OP_CHECKSIGFROMSTACK, V4UP, true, Stk{T});
    t.AddS("a 1-byte key too", CScript() << OP_1 << OV({'h', 'i'}) << OV({7}) << OP_CHECKSIGFROMSTACK, V4UP, true, Stk{T});
    t.AddS("a 33-byte key with an empty signature is false", CScript() << OP_0 << OV({'h', 'i'}) << OpBytes(33, 2) << OP_CHECKSIGFROMSTACK, V4UP, false, Stk{F});
    t.Add("relay policy refuses the 33-byte key", CScript() << OpBytes(64, 1) << OV({'h', 'i'}) << OpBytes(33, 2) << OP_CHECKSIGFROMSTACK, V4UP, false, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
    t.Add("relay policy refuses it even with an empty signature", CScript() << OP_0 << OV({'h', 'i'}) << OpBytes(33, 2) << OP_CHECKSIGFROMSTACK, V4UP, false, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);
    t.AddS("relay policy leaves a 32-byte key and an empty signature alone", CScript() << OP_0 << OV({'h', 'i'}) << OpBytes(32, 2) << OP_CHECKSIGFROMSTACK << OP_NOT, V4UP, true, Stk{T}, TX_PLAIN, SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4);

    // ---- run the table
    const char* const aSetName[4] = { "before v3", "v3", "v4", "v5" };
    const bool aR3[4] = { false, true, true, true };
    const bool aR4[4] = { false, false, true, true };
    const bool aR5[4] = { false, false, false, true };
    std::vector<std::string> vSections;
    std::map<std::string, std::pair<int, int> > mapSection;   // runs, failures
    for (size_t i = 0; i < t.rows.size(); i++)
    {
        const OpRow& r = t.rows[i];
        if (!mapSection.count(r.section))
        {
            vSections.push_back(r.section);
            mapSection[r.section] = std::make_pair(0, 0);
        }
        for (int s = 0; s < 4; s++)
        {
            if (!(r.sets & (1u << s)))
                continue;
            std::vector<OpVal> stack;
            bool fResult = false;
            try
            {
                fResult = EvalScript(r.script, txs[r.tx], 0, 0, &stack, false, aR3[s], aR4[s], r.policy, aR5[s]);
            }
            catch (const std::exception& e)
            {
                printf("  FAIL [%s] %s (%s): exception %s\n", r.section.c_str(), r.name.c_str(), aSetName[s], e.what());
                mapSection[r.section].first++;
                mapSection[r.section].second++;
                continue;
            }
            bool fGood = fResult == r.ok && (!r.fStack || stack == r.stack);
            mapSection[r.section].first++;
            if (!fGood)
            {
                mapSection[r.section].second++;
                printf("  FAIL [%s] %s (%s): result %d, expected %d", r.section.c_str(), r.name.c_str(), aSetName[s], (int)fResult, (int)r.ok);
                if (r.fStack && fResult == r.ok)
                    printf("; stack differs (%d elements, expected %d)", (int)stack.size(), (int)r.stack.size());
                printf("\n");
            }
        }
    }
    int nRuns = 0;
    for (size_t i = 0; i < vSections.size(); i++)
    {
        const std::pair<int, int>& p = mapSection[vSections[i]];
        nRuns += p.first;
        nFail += Check(p.second == 0, strprintf("%s: %d runs", vSections[i].c_str(), p.first).c_str()) ? 0 : 1;
    }
    printf("  info %d rows, %d runs under the four rule sets\n", (int)t.rows.size(), nRuns);

    // ---- pay-to-script-hash: what VerifySignature runs before and from v3
    {
        CScript redeem = CScript() << OP_ADD << OP_5 << OP_EQUAL;
        OpVal vchRedeem(redeem.begin(), redeem.end());
        CTransaction txFrom;
        txFrom.vout.push_back(CTxOut(COIN, CScript() << OP_HASH160 << Hash160(vchRedeem) << OP_EQUAL));
        CTransaction txTo = OpTx(1, 0, SEQUENCE_FINAL);
        txTo.vin[0].prevout = COutPoint(txFrom.GetHash(), 0);
        nFail += Check(txFrom.vout[0].scriptPubKey.IsPayToScriptHash(), "the output is pay-to-script-hash") ? 0 : 1;

        txTo.vin[0].scriptSig = CScript() << OP_2 << OP_3 << vchRedeem;
        nFail += Check(VerifySignature(txFrom, txTo, 0, 0, false, false) && VerifySignature(txFrom, txTo, 0, 0, false, true),
                       "2 3 <redeem>: the redeem script is satisfied, before and from v3") ? 0 : 1;
        txTo.vin[0].scriptSig = CScript() << OP_2 << OP_4 << vchRedeem;
        nFail += Check(VerifySignature(txFrom, txTo, 0, 0, false, false),
                       "2 4 <redeem>: before v3 the hash alone spends it (the script is not run)") ? 0 : 1;
        nFail += Check(!VerifySignature(txFrom, txTo, 0, 0, false, true),
                       "and from v3 the redeem script runs, finds 2 + 4 != 5, and refuses") ? 0 : 1;
        txTo.vin[0].scriptSig = CScript() << OP_2 << OP_3 << OV({1, 2, 3});
        nFail += Check(!VerifySignature(txFrom, txTo, 0, 0, false, false) && !VerifySignature(txFrom, txTo, 0, 0, false, true),
                       "a last push that does not hash to the script hash spends nothing") ? 0 : 1;
        txTo.vin[0].scriptSig = CScript() << OP_2 << OP_3 << OP_NOP << vchRedeem;
        nFail += Check(!VerifySignature(txFrom, txTo, 0, 0, false, false) && !VerifySignature(txFrom, txTo, 0, 0, false, true),
                       "a scriptSig with an operator is refused") ? 0 : 1;
        txTo.vin[0].scriptSig = CScript();
        nFail += Check(!VerifySignature(txFrom, txTo, 0, 0, false, false) && !VerifySignature(txFrom, txTo, 0, 0, false, true),
                       "an empty scriptSig spends nothing") ? 0 : 1;
        txTo.vin[0].scriptSig = CScript() << OP_2 << OP_3 << vchRedeem;
        nFail += Check(VerifyScriptP2SH(txTo.vin[0].scriptSig, txFrom.vout[0].scriptPubKey, txTo, 0, false, true) &&
                       !VerifyScriptP2SH(CScript() << OP_2 << OP_4 << vchRedeem, txFrom.vout[0].scriptPubKey, txTo, 0, false, true),
                       "VerifyScriptP2SH itself always runs the redeem script") ? 0 : 1;
        // A redeem script with an IF/ELSE, and a scriptSig that picks the branch with OP_TRUE or OP_0 in front of
        // it: those pushes carry no data (OP_1 .. OP_16), and the split of the scriptSig must keep them as they were.
        CScript redeemIf = CScript() << OP_IF << OP_1 << OP_ELSE << OP_0 << OP_ENDIF;
        OpVal vchIf(redeemIf.begin(), redeemIf.end());
        CTransaction txFrom2;
        txFrom2.vout.push_back(CTxOut(COIN, CScript() << OP_HASH160 << Hash160(vchIf) << OP_EQUAL));
        CTransaction txTo2 = OpTx(1, 0, SEQUENCE_FINAL);
        txTo2.vin[0].prevout = COutPoint(txFrom2.GetHash(), 0);
        txTo2.vin[0].scriptSig = CScript() << OP_TRUE << vchIf;
        bool fTrue = VerifySignature(txFrom2, txTo2, 0, 0, false, true);
        txTo2.vin[0].scriptSig = CScript() << OP_FALSE << vchIf;
        bool fFalse = VerifySignature(txFrom2, txTo2, 0, 0, false, true);
        nFail += Check(fTrue && !fFalse, "OP_TRUE before the redeem script selects the true branch, OP_0 the false one") ? 0 : 1;
        // VerifyScriptP2SH takes the rule flag too: a redeem script using OP_VER passes without it and fails with it.
        CScript redeemVer = CScript() << OP_VER << OP_DROP << OP_1;
        OpVal vchVer(redeemVer.begin(), redeemVer.end());
        CScript pubVer = CScript() << OP_HASH160 << Hash160(vchVer) << OP_EQUAL;
        CScript sigVer = CScript() << vchVer;
        nFail += Check(VerifyScriptP2SH(sigVer, pubVer, txTo, 0, false, false) && !VerifyScriptP2SH(sigVer, pubVer, txTo, 0, false, true),
                       "VerifyScriptP2SH without the v3 flag runs the redeem script by the old rules (OP_VER passes), with it by v3's (it fails)") ? 0 : 1;
        nFail += Check(!VerifyScriptP2SH(CScript() << OP_2 << OP_4 << vchRedeem, txFrom.vout[0].scriptPubKey, txTo, 0, false, false),
                       "and a redeem script that is false is refused without the flag too") ? 0 : 1;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- orphan-blocks: ProcessBlock with a parent it does not have -------------
// A block whose parent is unknown is held, and what is waiting for a block is
// connected, in order, when it arrives. CheckBlock runs before the block is
// held, so these are real blocks with RandomX proof of work at the floor
// (about 4096 hashes each at this chain's minimum difficulty). Mining them on
// every run would take minutes, so each carries the nonce found when the test
// was written: the search starts from it, and on a miss (a change to the
// header, the coinbase or the hash function) it carries on from there, slowly
// but correctly, and says so. The headers are fixed: they hang off the
// genesis block and use its time plus a constant.

uint256 GetOrphanRoot(const CBlock* pblock);   // main.cpp, not in a header

static unsigned int OrphanBlocksSumBytes()
{
    unsigned int n = 0;
    for (map<uint256, CBlock*>::iterator mi = mapOrphanBlocks.begin(); mi != mapOrphanBlocks.end(); ++mi)
        n += ::GetSerializeSize(*(*mi).second, SER_NETWORK);
    return n;
}

static CBlock OrphanTestBlock(const uint256& hashPrev, int nHeight, int nTag, unsigned int nTime, unsigned int nHint, const char* pszName)
{
    CBlock block;
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << nHeight << nTag;
    cb.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
    block.vtx.push_back(cb);
    block.nVersion = 1;
    block.hashPrevBlock = hashPrev;
    block.nTime = nTime;
    block.nBits = bnProofOfWorkLimit.GetCompact();
    block.hashMerkleRoot = block.BuildMerkleTree();
    uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
    block.nNonce = nHint;
    unsigned int nTries = 0;
    int64 nStart = GetTime();
    // A stale hint is a failure, not a quarter of an hour of hashing on every
    // run: BITFLASH_SELFTEST_MINE=1 lets the search run, and prints the nonce
    // to put in the table.
    const unsigned int nMaxTries = getenv("BITFLASH_SELFTEST_MINE") ? 0xffffffffU : 64;
    while (block.GetPoWHash() > hashTarget)
    {
        block.nNonce++;
        nTries++;
        if (nTries > nMaxTries)
            throw std::runtime_error(strprintf("the nonce hint %u for block %s no longer meets the target (the header or the proof of work changed); "
                                               "run with BITFLASH_SELFTEST_MINE=1 to find new ones", nHint, pszName));
    }
    if (nTries)
        printf("  info %s: the nonce hint %u missed; found %u after %u hashes (%lld s)\n",
               pszName, nHint, block.nNonce, nTries, (long long)(GetTime() - nStart));
    return block;
}

// The blocks every test here builds on: A1 A2 A3 off the genesis block, and
// their nonces.
static void OrphanTestChainA(CBlock& A1, CBlock& A2, CBlock& A3)
{
    const unsigned int nGenesisTime = pindexGenesisBlock->nTime;
    A1 = OrphanTestBlock(pindexGenesisBlock->GetBlockHash(), 1, 1, nGenesisTime + 120, 7607, "A1");
    A2 = OrphanTestBlock(A1.GetHash(), 2, 2, nGenesisTime + 240, 4677, "A2");
    A3 = OrphanTestBlock(A2.GetHash(), 3, 3, nGenesisTime + 360, 805, "A3");
}

static bool OrphanTestProcess(const CBlock& block, CNode* pfrom, int* pnDoS)
{
    bool fOk = false;
    CRITICAL_BLOCK(cs_main)
        fOk = ProcessBlock(pfrom, new CBlock(block), pnDoS);
    return fOk;
}

// A block that has not been mined and never will be: it fills the pool.
static CBlock* OrphanTestFiller(int i, size_t nPadding)
{
    CBlock* pblock = new CBlock();
    CTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << 1 << (60000 + i);
    // One well-formed push: OP_PUSHDATA4, a four-byte length, the bytes (CScript << vector writes a
    // two-byte length, which a padding of 900 kB does not fit).
    CScript pad;
    if (nPadding < 256)
        pad << std::vector<unsigned char>(nPadding, (unsigned char)i);
    else
    {
        pad.push_back(OP_PUSHDATA4);
        for (int k = 0; k < 4; k++)
            pad.push_back((unsigned char)((nPadding >> (8 * k)) & 0xff));
        pad.insert(pad.end(), nPadding, (unsigned char)i);
    }
    cb.vout.push_back(CTxOut(0, pad));
    pblock->vtx.push_back(cb);
    pblock->hashPrevBlock = uint256(70000 + i);
    pblock->nNonce = i;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    return pblock;
}

static int RunOrphanBlocksSelfTest()
{
    printf("orphan-blocks self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    CNode* pPeer = NULL;
    try
    {
        if (!LoadBlockIndex() || pindexBest == NULL || pindexBest->nHeight != 0)
            throw std::runtime_error("LoadBlockIndex failed");
        LimitOrphanBlocks(0);
        const unsigned int nGenesisTime = pindexGenesisBlock->nTime;
        const uint256 hashGenesis = pindexGenesisBlock->GetBlockHash();
        const uint256 hashUnknown1 = uint256(0x0a0b0c01), hashUnknown2 = uint256(0x0a0b0c02), hashUnknown3 = uint256(0x0a0b0c03);

        // The chain A1 A2 A3 off genesis; X1 X2 with a parent nobody has;
        // C, a child of A1 that AcceptBlock will refuse (dated before genesis).
        int64 nMineStart = GetTime();
        CBlock A1, A2, A3;
        OrphanTestChainA(A1, A2, A3);
        CBlock X1 = OrphanTestBlock(hashUnknown1, 1, 4, nGenesisTime + 120, 3460, "X1");
        CBlock X2 = OrphanTestBlock(X1.GetHash(), 2, 5, nGenesisTime + 240, 4130, "X2");
        CBlock C  = OrphanTestBlock(A1.GetHash(), 2, 6, nGenesisTime - 1000, 6078, "C");
        CBlock Y1 = OrphanTestBlock(hashUnknown2, 1, 7, nGenesisTime + 120, 4287, "Y1");
        CBlock Y2 = OrphanTestBlock(hashUnknown3, 1, 8, nGenesisTime + 120, 4270, "Y2");
        printf("  info the blocks took %lld s\n", (long long)(GetTime() - nMineStart));
        nFail += Check(A1.CheckBlock(NULL) && A3.CheckBlock(NULL) && X2.CheckBlock(NULL) && C.CheckBlock(NULL),
                       "the test blocks meet CheckBlock, proof of work included") ? 0 : 1;

        pPeer = P2PDoSPeer();
        int64 nWithoutParent = nBlocksWithoutParent;
        int nDoS = -1;

        // ---- one orphan
        nFail += Check(OrphanTestProcess(A3, pPeer, &nDoS) && nDoS == 0, "a block whose parent is unknown is accepted into the orphan pool") ? 0 : 1;
        nFail += Check(mapOrphanBlocks.size() == 1 && mapOrphanBlocks.count(A3.GetHash()) &&
                       mapOrphanBlocksByPrev.size() == 1 && mapOrphanBlocksByPrev.count(A2.GetHash()) &&
                       !mapBlockIndex.count(A3.GetHash()) && pindexBest == pindexGenesisBlock,
                       "it is held under its parent's hash, is not in the block index, and the chain has not moved") ? 0 : 1;
        nFail += Check(nOrphanBlockBytes == ::GetSerializeSize(A3, SER_NETWORK) && nOrphanBlockBytes == OrphanBlocksSumBytes(),
                       "the pool counts its bytes") ? 0 : 1;
        nFail += Check(GetOrphanRoot(&A3) == A3.GetHash() && GetOrphanRoot(mapOrphanBlocks[A3.GetHash()]) == A3.GetHash(),
                       "GetOrphanRoot of a lone orphan is itself") ? 0 : 1;
        nFail += Check(pPeer->hashLastGetBlocksEnd == A3.GetHash() && pPeer->pindexLastGetBlocksBegin == pindexBest &&
                       nBlocksWithoutParent == nWithoutParent + 1,
                       "the peer is asked for the blocks in between, up to the orphan's root, and the orphan is counted") ? 0 : 1;

        // ---- the same block again
        unsigned int nBytes = nOrphanBlockBytes;
        nDoS = -1;
        nFail += Check(!OrphanTestProcess(A3, NULL, &nDoS) && nDoS == 0, "the same orphan again is refused, with no points") ? 0 : 1;
        nFail += Check(mapOrphanBlocks.size() == 1 && mapOrphanBlocksByPrev.size() == 1 && nOrphanBlockBytes == nBytes,
                       "and nothing is held twice") ? 0 : 1;

        // ---- a chain of orphans: the root is the one with no parent held
        nFail += Check(OrphanTestProcess(A2, pPeer, &nDoS), "its parent, also unknown parent, is held too") ? 0 : 1;
        nFail += Check(mapOrphanBlocks.size() == 2 && mapOrphanBlocksByPrev.size() == 2 && nOrphanBlockBytes == OrphanBlocksSumBytes(),
                       "two held, in step") ? 0 : 1;
        nFail += Check(GetOrphanRoot(&A3) == A2.GetHash() && GetOrphanRoot(&A2) == A2.GetHash(),
                       "GetOrphanRoot of the child is the parent, which has none held above it") ? 0 : 1;
        nFail += Check(pPeer->hashLastGetBlocksEnd == A2.GetHash(), "the peer is now asked up to A2") ? 0 : 1;

        // ---- an unrelated orphan chain, and a child that will turn out invalid
        nFail += Check(OrphanTestProcess(X1, pPeer, NULL) && OrphanTestProcess(X2, pPeer, NULL),
                       "another chain with a parent nobody has") ? 0 : 1;
        nFail += Check(GetOrphanRoot(&X2) == X1.GetHash() && GetOrphanRoot(&A3) == A2.GetHash(),
                       "each chain has its own root") ? 0 : 1;
        nFail += Check(OrphanTestProcess(C, NULL, NULL), "a block dated before its parent's time is held like any other: that is AcceptBlock's check") ? 0 : 1;
        nFail += Check(mapOrphanBlocks.size() == 5 && mapOrphanBlocksByPrev.size() == 5 &&
                       mapOrphanBlocksByPrev.count(A1.GetHash()) == 2 && mapOrphanBlocksByPrev.count(A2.GetHash()) == 1 &&
                       nOrphanBlockBytes == OrphanBlocksSumBytes(), "five held: A2 and C waiting for A1, A3 for A2, X1 and X2") ? 0 : 1;
        nFail += Check(pindexBest == pindexGenesisBlock && nBestHeight == 0, "and still nothing connected") ? 0 : 1;

        // ---- the parent arrives
        nFail += Check(OrphanTestProcess(A1, NULL, &nDoS) && nDoS == 0, "the missing parent arrives and is accepted") ? 0 : 1;
        nFail += Check(pindexBest != NULL && pindexBest->GetBlockHash() == A3.GetHash() && nBestHeight == 3,
                       "the whole chain behind it connects: the tip is A3 at height 3") ? 0 : 1;
        {
            map<uint256, CBlockIndex*>::iterator m1 = mapBlockIndex.find(A1.GetHash());
            map<uint256, CBlockIndex*>::iterator m2 = mapBlockIndex.find(A2.GetHash());
            map<uint256, CBlockIndex*>::iterator m3 = mapBlockIndex.find(A3.GetHash());
            nFail += Check(m1 != mapBlockIndex.end() && m2 != mapBlockIndex.end() && m3 != mapBlockIndex.end() &&
                           m1->second->pprev == pindexGenesisBlock && m2->second->pprev == m1->second && m3->second->pprev == m2->second &&
                           m1->second->nHeight == 1 && m2->second->nHeight == 2 && m3->second->nHeight == 3,
                           "linked in order: genesis, A1, A2, A3") ? 0 : 1;
        }
        nFail += Check(!mapBlockIndex.count(C.GetHash()), "the child AcceptBlock refuses did not connect") ? 0 : 1;
        nFail += Check(mapOrphanBlocks.size() == 2 && mapOrphanBlocks.count(X1.GetHash()) && mapOrphanBlocks.count(X2.GetHash()) &&
                       mapOrphanBlocksByPrev.size() == 2 && mapOrphanBlocksByPrev.count(hashUnknown1) == 1 &&
                       !mapOrphanBlocks.count(C.GetHash()) && !mapOrphanBlocks.count(A2.GetHash()) && !mapOrphanBlocks.count(A3.GetHash()),
                       "what connected, and the refused child, left the pool; the other chain is still waiting") ? 0 : 1;
        nFail += Check(nOrphanBlockBytes == ::GetSerializeSize(X1, SER_NETWORK) + ::GetSerializeSize(X2, SER_NETWORK) &&
                       nOrphanBlockBytes == OrphanBlocksSumBytes(),
                       "and the byte count followed") ? 0 : 1;

        // ---- blocks already in the index
        nFail += Check(!OrphanTestProcess(A2, NULL, &nDoS) && nDoS == 0 && !OrphanTestProcess(A1, NULL, &nDoS) && nDoS == 0 &&
                       pindexBest->GetBlockHash() == A3.GetHash() && mapOrphanBlocks.size() == 2,
                       "a block that already connected is refused, with no points, and nothing changes") ? 0 : 1;
        nFail += Check(!OrphanTestProcess(X2, NULL, &nDoS) && nDoS == 0 && mapOrphanBlocks.size() == 2,
                       "a held orphan sent again too") ? 0 : 1;

        // ---- a block that fails CheckBlock is not held
        {
            CBlock* pFiller = OrphanTestFiller(500, 100);
            CBlock bad = *pFiller;
            delete pFiller;
            bad.nBits = bnProofOfWorkLimit.GetCompact();
            bad.nTime = nGenesisTime + 120;
            unsigned int nBytesBefore = nOrphanBlockBytes;
            size_t nHeldBefore = mapOrphanBlocks.size();
            int nDoSBad = 0;
            bool fBad = OrphanTestProcess(bad, NULL, &nDoSBad);
            nFail += Check(!fBad && nDoSBad > 0, "an unmined block (an unknown parent, no proof of work) is refused, with DoS points") ? 0 : 1;
            nFail += Check(mapOrphanBlocks.size() == nHeldBefore && nOrphanBlockBytes == nBytesBefore && !mapOrphanBlocks.count(bad.GetHash()) &&
                           mapOrphanBlocksByPrev.size() == nHeldBefore,
                           "and the orphan pool is as it was") ? 0 : 1;
            printf("  info CheckBlock failure scored %d\n", nDoSBad);
        }

        // ---- the bounds on the pool, with fillers that were never mined
        LimitOrphanBlocks(0);
        nFail += Check(mapOrphanBlocks.empty() && mapOrphanBlocksByPrev.empty() && nOrphanBlockBytes == 0, "the pool emptied") ? 0 : 1;
        {
            // 36 blocks of about 900 kB are over the byte ceiling together; one
            // more real orphan comes through ProcessBlock and the pool is cut.
            for (int i = 0; i < 36; i++)
                AddOrphanBlock(OrphanTestFiller(i, 900000));
            unsigned int nBefore = nOrphanBlockBytes;
            nFail += Check(nBefore > MAX_ORPHAN_BLOCK_BYTES && mapOrphanBlocks.size() == 36,
                           "36 blocks of 900 kB are over the 32 MB ceiling (nothing has trimmed them yet)") ? 0 : 1;
            nFail += Check(OrphanTestProcess(Y1, NULL, NULL), "one more orphan is accepted") ? 0 : 1;
            nFail += Check(nOrphanBlockBytes <= MAX_ORPHAN_BLOCK_BYTES && nOrphanBlockBytes == OrphanBlocksSumBytes() &&
                           mapOrphanBlocksByPrev.size() == mapOrphanBlocks.size() &&
                           mapOrphanBlocks.size() >= 35 && mapOrphanBlocks.size() <= 36,
                           "and the pool is cut back under the byte ceiling, the maps and the count in step") ? 0 : 1;
            printf("  info %d orphans held, %u of %u bytes\n", (int)mapOrphanBlocks.size(), nOrphanBlockBytes, MAX_ORPHAN_BLOCK_BYTES);
            LimitOrphanBlocks(0);
        }
        {
            for (unsigned int i = 0; i < MAX_ORPHAN_BLOCKS; i++)
                AddOrphanBlock(OrphanTestFiller(100 + i, 10));
            nFail += Check(mapOrphanBlocks.size() == MAX_ORPHAN_BLOCKS, "200 small orphans fill the count ceiling") ? 0 : 1;
            nFail += Check(OrphanTestProcess(Y2, NULL, NULL), "the 201st comes through ProcessBlock") ? 0 : 1;
            nFail += Check(mapOrphanBlocks.size() == MAX_ORPHAN_BLOCKS && mapOrphanBlocksByPrev.size() == MAX_ORPHAN_BLOCKS &&
                           nOrphanBlockBytes == OrphanBlocksSumBytes(),
                           "one is dropped at random: 200 held, the maps in step, the bytes right") ? 0 : 1;
            LimitOrphanBlocks(0);
            nFail += Check(mapOrphanBlocks.empty() && mapOrphanBlocksByPrev.empty() && nOrphanBlockBytes == 0, "emptied, nothing counted") ? 0 : 1;
        }
        nFail += Check(pindexBest->GetBlockHash() == A3.GetHash(), "through all of it the chain stayed at A3") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    delete pPeer;
    LimitOrphanBlocks(0);
    DBFlush(true);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---- block-index-load: the restart path ------------------------------------
// A chain written by one run is read back by the next: LoadBlockIndex rebuilds
// the links, the heights and the accumulated work, picks the best chain the
// disk names, verifies the tail of it, and when the tail fails takes the
// failed blocks off the chain and marks them. The valid blocks are the mined
// ones of orphan-blocks; the failing ones carry no proof of work (what
// AcceptBlock stores, and CheckBlock at load refuses).

static int RunBlockIndexLoadSelfTest()
{
    printf("block-index-load self-test\n");
    int nFail = 0;
    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    strSetDataDir = tmp;
    const int nCheckSaved = nCheckBlocksOnLoad;
    const MapCheckpoints mapCheckpointsSaved = mapCheckpoints;
    try
    {
        if (!LoadBlockIndex() || pindexBest == NULL || pindexBest->nHeight != 0)
            throw std::runtime_error("LoadBlockIndex failed");
        const uint256 hashGenesis = pindexGenesisBlock->GetBlockHash();
        nReorgTestStart = pindexGenesisBlock->nTime;
        CBlock A1, A2, A3;
        OrphanTestChainA(A1, A2, A3);
        const uint256 hA1 = A1.GetHash(), hA2 = A2.GetHash(), hA3 = A3.GetHash();
        nFail += Check(OrphanTestProcess(A1, NULL, NULL) && OrphanTestProcess(A2, NULL, NULL) && OrphanTestProcess(A3, NULL, NULL) &&
                       nBestHeight == 3 && pindexBest->GetBlockHash() == hA3,
                       "three blocks with proof of work connect from genesis") ? 0 : 1;
        const uint256 workA1 = mapBlockIndex[hA1]->nChainWork, workA2 = mapBlockIndex[hA2]->nChainWork,
                      workA3 = mapBlockIndex[hA3]->nChainWork;
        nFail += Check(workA1 > 0 && workA2 > workA1 && workA3 > workA2, "accumulated work grows with each block") ? 0 : 1;

        // ---- a restart with nothing to repair
        nCheckBlocksOnLoad = 288;
        if (!ReorgTestReload())
            throw std::runtime_error("reload failed");
        {
            CBlockIndex* p1 = mapBlockIndex.count(hA1) ? mapBlockIndex[hA1] : NULL;
            CBlockIndex* p2 = mapBlockIndex.count(hA2) ? mapBlockIndex[hA2] : NULL;
            CBlockIndex* p3 = mapBlockIndex.count(hA3) ? mapBlockIndex[hA3] : NULL;
            nFail += Check(p1 && p2 && p3 && mapBlockIndex.size() == 4, "the genesis block and the three blocks are read back") ? 0 : 1;
            if (!p1 || !p2 || !p3)
                throw std::runtime_error("blocks missing after the restart");
            nFail += Check(pindexGenesisBlock && pindexGenesisBlock->GetBlockHash() == hashGenesis && pindexGenesisBlock->pprev == NULL,
                           "the genesis block is found") ? 0 : 1;
            nFail += Check(pindexBest == p3 && hashBestChain == hA3 && nBestHeight == 3,
                           "the best chain is the one the disk names: A3, height 3") ? 0 : 1;
            nFail += Check(p1->pprev == pindexGenesisBlock && p2->pprev == p1 && p3->pprev == p2 &&
                           pindexGenesisBlock->pnext == p1 && p1->pnext == p2 && p2->pnext == p3 && p3->pnext == NULL &&
                           p1->nHeight == 1 && p2->nHeight == 2 && p3->nHeight == 3,
                           "heights, parents and next links are rebuilt") ? 0 : 1;
            nFail += Check(p1->nChainWork == workA1 && p2->nChainWork == workA2 && p3->nChainWork == workA3,
                           "the accumulated work, which is not on the disk, comes out the same as before") ? 0 : 1;
            nFail += Check(p2->IsInMainChain() && p3->IsInMainChain() && !p1->fFailed && !p2->fFailed && !p3->fFailed &&
                           pindexBadChainFork == NULL && pindexBadChainFirst == NULL,
                           "all of it in the main chain, nothing failed, no repair pending") ? 0 : 1;
            CTxDB txdb("r");
            CTransaction tx;
            nFail += Check(txdb.ReadDiskTx(A2.vtx[0].GetHash(), tx) && tx.GetHash() == A2.vtx[0].GetHash() &&
                           txdb.ContainsTx(A3.vtx[0].GetHash()),
                           "the transaction index still finds the blocks' coinbases") ? 0 : 1;
        }

        // ---- the best chain is the heaviest, not the last one written; a restart whose
        // tail fails verification goes back to the fork and marks the failed branch
        CBlockIndex* pA1 = mapBlockIndex[hA1];
        CBlockIndex* pF2 = ReorgTestExtend(pA1);
        CBlockIndex* pF3 = pF2 ? ReorgTestExtend(pF2) : NULL;
        nFail += Check(pF2 && pF3 && pF3->nHeight == 3 && pF3->nChainWork == workA3 && pindexBest->GetBlockHash() == hA3,
                       "a branch from A1 to the same height and work is stored, and the first one stays the best") ? 0 : 1;
        CBlockIndex* pF4 = pF3 ? ReorgTestExtend(pF3) : NULL;
        nFail += Check(pF4 && pindexBest == pF4 && nBestHeight == 4, "one more block on it has more work: it becomes the best chain") ? 0 : 1;
        if (!pF4)
            throw std::runtime_error("could not build the branch");
        const uint256 hF2 = pF2->GetBlockHash(), hF3 = pF3->GetBlockHash(), hF4 = pF4->GetBlockHash();
        uint256 hFirstBad = 0;
        int nExpect = ReorgTestExpectedRollback(pF4, 288, &hFirstBad);
        printf("  info the load check should roll back to height %d\n", nExpect);
        if (!ReorgTestReload())
            throw std::runtime_error("second reload failed");
        nFail += Check(nExpect == 1 && nBestHeight == nExpect && pindexBest && pindexBest->GetBlockHash() == hA1,
                       "the branch's blocks fail the check at load: the chain goes back to A1, where it forked") ? 0 : 1;
        nFail += Check(mapBlockIndex.count(hFirstBad) && mapBlockIndex[hFirstBad]->fFailed &&
                       mapBlockIndex.count(hF4) && mapBlockIndex[hF4]->fFailed && mapBlockIndex.count(hF3) && mapBlockIndex[hF3]->fFailed,
                       "the first bad block and everything on top of it are marked failed") ? 0 : 1;
        nFail += Check(mapBlockIndex.count(hA3) && !mapBlockIndex[hA3]->fFailed && !mapBlockIndex[hA2]->fFailed &&
                       !IsBetterChain(mapBlockIndex[hF4], mapBlockIndex[hA3]) && IsBetterChain(mapBlockIndex[hA3], pindexBest),
                       "the valid branch is untouched, and a failed branch is never the better chain") ? 0 : 1;
        fCheckpointWalkBack = true;
        nFail += Check(ActivateBestKnownChain() && pindexBest->GetBlockHash() == hA3 && nBestHeight == 3,
                       "the best of what is left, by work, is A3: it is picked, not the heavier failed branch") ? 0 : 1;
        nFail += Check(pindexBadChainFork == NULL && pindexBadChainFirst == NULL, "no repair left pending") ? 0 : 1;

        // The failed blocks came off the disk index.
        if (!ReorgTestReload())
            throw std::runtime_error("third reload failed");
        nFail += Check(!mapBlockIndex.count(hF2) && !mapBlockIndex.count(hF3) && !mapBlockIndex.count(hF4) && mapBlockIndex.size() == 4 &&
                       pindexBest && pindexBest->GetBlockHash() == hA3 && nBestHeight == 3,
                       "the next restart does not read them back: the chain is A3, four entries") ? 0 : 1;
        nFail += Check(mapBlockIndex[hA3]->nChainWork == workA3 && mapBlockIndex[hA3]->IsInMainChain(),
                       "and the work of A3 is what it was") ? 0 : 1;

        // ---- only the tail is checked: with a window of one block, the tip
        // goes and the block under it, never looked at, stays
        CBlockIndex* pA4 = ReorgTestExtend(pindexBest);
        CBlockIndex* pA5 = pA4 ? ReorgTestExtend(pA4) : NULL;
        if (!pA5)
            throw std::runtime_error("could not extend the chain");
        const uint256 hA4 = pA4->GetBlockHash(), hA5 = pA5->GetBlockHash();
        nCheckBlocksOnLoad = 1;
        uint256 hBad1 = 0;
        int nExpect1 = ReorgTestExpectedRollback(pA5, 1, &hBad1);
        if (!ReorgTestReload())
            throw std::runtime_error("fourth reload failed");
        nFail += Check(nExpect1 == 4 && nBestHeight == 4 && pindexBest->GetBlockHash() == hA4 && mapBlockIndex.count(hA5) && mapBlockIndex[hA5]->fFailed &&
                       !mapBlockIndex[hA4]->fFailed,
                       "a window of one: only the tip is checked and removed; the unchecked block under it is the new tip") ? 0 : 1;
        uint256 hBad2 = 0;
        int nExpect2 = ReorgTestExpectedRollback(pindexBest, 1, &hBad2);
        if (!ReorgTestReload())
            throw std::runtime_error("fifth reload failed");
        nFail += Check(!mapBlockIndex.count(hA5) && nExpect2 == 3 && nBestHeight == 3 && pindexBest->GetBlockHash() == hA3 &&
                       mapBlockIndex.count(hA4) && mapBlockIndex[hA4]->fFailed,
                       "the next restart checks that one, finds it bad, and is back on A3 with A4 marked") ? 0 : 1;
        nFail += Check(IndexHasNoDanglingParent(), "no entry points at a block that is gone") ? 0 : 1;
        nCheckBlocksOnLoad = 0;
        if (!ReorgTestReload())
            throw std::runtime_error("sixth reload failed");
        nFail += Check(nBestHeight == 3 && pindexBest->GetBlockHash() == hA3 && !mapBlockIndex.count(hA4),
                       "a window of 0 checks the whole chain: all three blocks pass, nothing to repair") ? 0 : 1;

        // ---- a best chain that contradicts a checkpoint goes back to the last block that does not
        nCheckBlocksOnLoad = 288;
        mapCheckpoints.clear();
        mapCheckpoints[2] = uint256(0xdeadbeef);   // not A2
        fCheckpointWalkBack = false;
        if (!ReorgTestReload())
            throw std::runtime_error("seventh reload failed");
        {
            CBlockIndex* p2 = mapBlockIndex.count(hA2) ? mapBlockIndex[hA2] : NULL;
            CBlockIndex* p3 = mapBlockIndex.count(hA3) ? mapBlockIndex[hA3] : NULL;
            nFail += Check(p2 && p3 && p2->fOffCheckpoint && p3->fOffCheckpoint && !mapBlockIndex[hA1]->fOffCheckpoint,
                           "a checkpoint at height 2 that is not A2: A2 and A3 are off it, A1 is not") ? 0 : 1;
            nFail += Check(nBestHeight == 1 && pindexBest && pindexBest->GetBlockHash() == hA1 && fCheckpointWalkBack,
                           "the load goes back to A1 and asks for a walk back to the best chain by work") ? 0 : 1;
            nFail += Check(p3 && !p2->fFailed && !p3->fFailed && !IsBetterChain(p3, pindexBest),
                           "A2 and A3 are not marked failed, and a chain off a checkpoint is not the better one") ? 0 : 1;
        }
        // The checkpoint now names A2: nothing is off it, and the walk back finds A3 again.
        mapCheckpoints[2] = hA2;
        if (!ReorgTestReload())
            throw std::runtime_error("eighth reload failed");
        nFail += Check(nBestHeight == 1 && pindexBest->GetBlockHash() == hA1 && !mapBlockIndex[hA3]->fOffCheckpoint &&
                       IsBetterChain(mapBlockIndex[hA3], pindexBest),
                       "with a checkpoint A2 meets, A3 is the better chain again") ? 0 : 1;
        fCheckpointWalkBack = true;
        nFail += Check(ActivateBestKnownChain() && pindexBest->GetBlockHash() == hA3 && nBestHeight == 3,
                       "and the walk back returns to it") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    nCheckBlocksOnLoad = nCheckSaved;
    mapCheckpoints = mapCheckpointsSaved;
    fCheckpointWalkBack = false;
    DBFlush(true);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

int RunSelfTest(const std::string& name)
{
    AttachTerminal();

    if (name == "wallet-keypool")
        return RunWalletKeyPoolSelfTest();
    if (name == "wallet-hd")
        return RunWalletHDSelfTest();
    if (name == "wallet-format")
        return RunWalletFormatSelfTest();
    if (name == "wallet-storage-sanity")
        return RunWalletStorageSanitySelfTest();
    if (name == "db-locks")
        return RunDbLocksSelfTest();
    if (name == "db-env-reopen")
        return RunDbEnvReopenSelfTest();
    if (name == "db-open-failure")
        return RunDbOpenFailureSelfTest();
    if (name == "private-file")
        return RunPrivateFileSelfTest();
    if (name == "wallet-sqlite")
        return RunWalletSQLiteSelfTest();
    if (name == "wallet-sqlite-migration")
        return RunWalletSQLiteMigrationSelfTest();
    if (name == "wallet-crypto")
        return RunWalletCryptoSelfTest();
    if (name == "wallet-encrypt")
        return RunWalletEncryptSelfTest();
    if (name == "wallet-sqlite-encrypt")
        return RunWalletSQLiteEncryptSelfTest();
    if (name == "wallet-backend-default")
        return RunWalletBackendDefaultSelfTest();
    if (name == "wallet-convert")
        return RunWalletConvertSelfTest();
    if (name == "wallet-portability")
        return RunWalletPortabilitySelfTest();
    if (name == "net-message")
        return RunNetMessageSelfTest();
    if (name == "network-params")
        return RunNetworkParamsSelfTest();
    if (name == "consensus-limits")
        return RunConsensusLimitsSelfTest();
    if (name == "chain-work")
        return RunChainWorkSelfTest();
    if (name == "consensus-safety")
        return RunConsensusSafetySelfTest();
    if (name == "reorg-safety")
        return RunReorgSafetySelfTest();
    if (name == "pool-stratum")
        return RunPoolStratumSelfTest();
    if (name == "parse-money")
        return RunParseMoneySelfTest();
    if (name == "serialize-canonical")
        return RunSerializeCanonicalSelfTest();
    if (name == "decoder-canonical")
        return RunDecoderCanonicalSelfTest();
    if (name == "debug-log-buffer")
        return RunDebugLogBufferSelfTest();
    if (name == "dgb-pow")
        return RunDgbPoWSelfTest();
    if (name == "rvn-kawpow")
        return RunRvnKawPoWSelfTest();
    if (name == "pow-v2")
        return RunPoWV2SelfTest();
    if (name == "sigpipe")
        return RunSigpipeSelfTest();
    if (name == "bignum-int")
        return RunBigNumIntSelfTest();
    if (name == "script-eval")
        return RunScriptEvalSelfTest();
    if (name == "sighash-reference")
        return RunSigHashReferenceSelfTest();
    if (name == "rules-v2")
        return RunRulesV2SelfTest();
    if (name == "orphan-tx")
        return RunOrphanTxSelfTest();
    if (name == "script-opcodes")
        return RunScriptOpcodesSelfTest();
    if (name == "orphan-blocks")
        return RunOrphanBlocksSelfTest();
    if (name == "block-index-load")
        return RunBlockIndexLoadSelfTest();
    if (name == "net-hardening")
        return RunNetHardeningSelfTest();
    if (name == "sync-stall")
        return RunSyncStallSelfTest();
    if (name == "p2p-dos")
        return RunP2PDoSSelfTest();
    if (name == "multisig")
        return RunMultisigSelfTest();
    if (name == "socks5-proxy")
        return RunSocks5ProxySelfTest();
    if (name == "reply-parsers")
        return RunReplyParsersSelfTest();
    if (name == "managed-tor")
        return RunManagedTorSelfTest();
    if (name == "treasury")
        return RunTreasurySelfTest();
    if (name == "chat-link")
        return RunChatLinkSelfTest();
    if (name == "chat-identity")
        return RunChatIdentitySelfTest();
    if (name == "chat-relay")
        return RunChatRelaySelfTest();
    if (name == "chat-wallet")
        return RunChatWalletSelfTest();
    if (name == "p2pool-sync")
        return RunP2PoolSyncSelfTest();
    if (name == "p2pool-peers")
        return RunP2PoolPeersSelfTest();
    if (name == "p2pool-dos")
        return RunP2PoolDosSelfTest();
    if (name == "p2pool-chain")
        return RunP2PoolChainSelfTest();
    if (name == "p2pool-share")
        return RunP2PoolShareSelfTest();
    if (name == "rules-v3")
        return RunRulesV3SelfTest();
    if (name == "rules-v4")
        return RunRulesV4SelfTest();
    if (name == "rules-v5")
        return RunRulesV5SelfTest();
    if (name == "inheritance")
        return InheritanceSelfTest();
    if (name == "sigcheck")
        return RunSigCheckSelfTest();
    if (name == "btc-light")
        return btclight::SelfTest();
    if (name == "ltc-light")
        return btclight::SelfTestLitecoin();
    if (name == "cash-light")
        return btclight::SelfTestCash();
    if (name == "doge-light")
        return btclight::SelfTestDogecoin();
    if (name == "dgb-light")
        return btclight::SelfTestDigiByte();
    if (name == "rvn-chain")
        return btclight::SelfTestRavencoin();
    if (name == "explorer")
        return RunExplorerSelfTest();
    if (name == "btc-swap")
        return RunBtcSwapSelfTest();
    if (name == "chat-swap")
        return RunChatSwapSelfTest();
    if (name == "swap-wait-payment")
        return RunSwapWaitPaymentSelfTest();
    if (name == "swap-timelock")
        return RunSwapTimelockSelfTest();
    if (name == "swap-journal")
        return RunSwapJournalSelfTest();
    if (name == "swap-parse")
        return RunSwapParseSelfTest();
    if (name == "swap-engine")
        return RunSwapEngineSelfTest();
    if (name == "swap-prune")
        return RunSwapPruneSelfTest();
    if (name == "chat-dos")
        return RunChatDosSelfTest();
    if (name == "nostr-relay")
        return RunNostrRelaySelfTest();
    if (name == "chat-store-save")
        return RunChatStoreSaveSelfTest();
    if (name == "wallet-final")
        return RunWalletFinalSelfTest();
    if (name == "swap-rpc")
        return RunSwapRpcSelfTest();
    if (name == "fee-policy")
        return RunFeePolicySelfTest();
    if (name == "script-sigops")
        return RunScriptSigOpsSelfTest();
    if (name == "invoice")
        return RunInvoiceSelfTest();
    if (name == "chat-live")
        return RunChatLiveSelfTest();
    if (name == "wallet-encrypted-seed")
        return WfRunInTempDir("wallet-encrypted-seed", WfEncryptedSeed);
    if (name == "wallet-encrypt-pool")
        return WfRunInTempDir("wallet-encrypt-pool", WfEncryptPool);
    if (name == "wallet-relock")
        return WfRunInTempDir("wallet-relock", WfRelock);
    if (name == "wallet-restore-race")
        return WfRunInTempDir("wallet-restore-race", WfRestoreRace);
    if (name == "wallet-secret-args")
        return WfRunInTempDir("wallet-secret-args", WfSecretArgs);
    if (name == "wallet-file-modes")
        return WfRunInTempDir("wallet-file-modes", WfFileModes);
    if (name == "wallet-fee-limit")
        return WfRunInTempDir("wallet-fee-limit", WfFeeLimit);
    if (name == "chat-replay-quota")
        return RunChatReplayQuotaSelfTest();
    if (name == "wallet-encrypted-seed-sqlite")
        return WfRunInTempDir("wallet-encrypted-seed-sqlite", WfEncryptedSeedSQLite);
    if (name == "wallet-encrypt-pool-sqlite")
        return WfRunInTempDir("wallet-encrypt-pool-sqlite", WfEncryptPoolSQLite);
    if (name == "wallet-sqlite-rollback")
        return WfRunInTempDir("wallet-sqlite-rollback", WfSQLiteRollback);
    if (name == "wallet-rpc-v4")
        return WfRunInTempDir("wallet-rpc-v4", WfRpcAndV4);

    printf("Unknown self-test '%s'\n", name.c_str());
    printf("Known self-tests: wallet-keypool, wallet-hd, wallet-format, wallet-storage-sanity, db-env-reopen, db-open-failure, private-file, wallet-sqlite, wallet-sqlite-migration, wallet-crypto, wallet-encrypt, wallet-sqlite-encrypt, wallet-backend-default, wallet-convert, wallet-portability, wallet-encrypted-seed, wallet-encrypt-pool, wallet-relock, wallet-restore-race, wallet-secret-args, wallet-file-modes, wallet-fee-limit, wallet-rpc-v4, chat-replay-quota, wallet-encrypted-seed-sqlite, wallet-encrypt-pool-sqlite, wallet-sqlite-rollback, net-message, network-params, consensus-limits, chain-work, consensus-safety, reorg-safety, pool-stratum, parse-money, serialize-canonical, decoder-canonical, debug-log-buffer, pow-v2, dgb-pow, rvn-kawpow, sigpipe, script-eval, bignum-int, script-sigops, script-opcodes, rules-v2, rules-v3, rules-v4, rules-v5, net-hardening, p2p-dos, orphan-tx, orphan-blocks, block-index-load, multisig, socks5-proxy, reply-parsers, managed-tor, treasury, chat-link, chat-identity, chat-relay, chat-live, swap-wait-payment, swap-timelock, swap-journal, swap-parse, swap-engine, swap-prune, chat-dos, nostr-relay, chat-store-save, wallet-final, swap-rpc, p2pool-dos\n");
    return 1;
}
