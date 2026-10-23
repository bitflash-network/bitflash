// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Integration self-tests that need the real wallet/database code linked into
// the node. These are intentionally run behind an explicit command-line flag
// and against a temporary data directory.

#include "headers_core.h"
#include "btfaddr.h"
#include "bip32.h"
#include "proxy.h"
#include "selftest.h"
#include "p2pool_chain.h"
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
#include "invoice.h"
#include "bip21.h"
#include "btfchatwallet.h"
#include "chatdir.h"
#include "community.h"
#include "jsonrpc.h"
// The chat test signs frames, so it needs a secp256k1 context of its own. Not
// the node identity from nostr.h: asking for that would generate and persist a
// node key, and a self-test has no business creating one.
#include <secp256k1.h>
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
        CBlock* pblock = new CBlock(block);
        bool fDup = ProcessBlock(NULL, pblock, &nDoS);
        mapBlockIndex.erase(hash);
        delete pindexFake;
        delete pblock;
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
    s.data.nShareBits = chain.NextShareBits(parent, main.nBits);

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

        bool fMissing = false;
        p2pool::Share orphan = ChainShare(chain, main, line[4], A, t + 62);
        orphan.data.hashPrevShare = Hash(BEGIN(t), END(t));
        orphan.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << p2pool::CommitmentPush(orphan.data.GetHash());
        orphan.hashMerkleRoot = orphan.coinbase.GetHash();
        nFail += Check(!chain.Add(orphan, main, err, &fMissing) && fMissing,
                       "a share whose parent is unknown is refused, asking for the parent") ? 0 : 1;

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

        p2pool::Share stale = ChainShare(chain, main, line[4], A, t + 65);
        stale.hashPrevBlock = main.BlockAt(60990);
        nFail += Check(!chain.Add(stale, main, err) && err == "mined on a stale main block", "a share mined on a stale main block is refused") ? 0 : 1;

        p2pool::Share future = ChainShare(chain, main, line[4], A, (unsigned int)main.nNow + 600);
        nFail += Check(!chain.Add(future, main, err) && err == "share time too far in the future", "a share from ten minutes ahead is refused") ? 0 : 1;

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
        unsigned int nInit = p2pool::ShareBitsFromMain(main.nBits, bnFloor);
        CBigNum bnInit;
        bnInit.SetCompact(nInit);
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
            bnNext.SetCompact(chain.NextShareBits(prev, main.nBits));
            if (pace == 0)
                nFail += Check(fOk && bnNext * 2 <= bnInit + bnInit / 1000 && bnNext * 2 >= bnInit - bnInit / 1000,
                               "720 shares at 5 s instead of 10: the target halves") ? 0 : 1;
            else
                nFail += Check(fOk && bnNext * 4 <= bnInit * 16 + bnInit / 100 && bnNext >= bnInit * 4 - bnInit / 100,
                               "720 shares at 50 s: the target eases, by four at most") ? 0 : 1;
        }
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

    // A starting node takes it in messages of 400.
    p2pool::ShareChain b(bnFloor, false);
    int nTipHeight = a.Height(a.Tip());
    bool fSynced = true;
    for (size_t i = 0; i < hist.size() && fSynced; i += 400)
    {
        vector<p2pool::Share> part(hist.begin() + i, hist.begin() + std::min(hist.size(), i + 400));
        fSynced = b.AddHistory(part, nTipHeight, main, err);
    }
    if (!fSynced) printf("       %s\n", err.c_str());
    nFail += Check(fSynced && b.Tip() == a.Tip(), "it ends on the same tip") ? 0 : 1;

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

// Rules v3: OP_CHECKLOCKTIMEVERIFY, lock-time finality in blocks, BIP16
// enforced, and the hash-time-locked script an atomic swap is made of. The
// rules are driven here through their flags, not the activation time, so the
// suite checks the rule itself whatever date consensus.h holds.
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
            bool                   fOk;
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
        RAND_bytes(b, sizeof(b));
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
    void Changed() {}
};

static nlohmann::json SwapTestBtc(int nPort, const std::string& method, const nlohmann::json& params,
                                  const std::string& path = "/")
{
    LoopbackRpc to;
    to.nPort = nPort;
    to.strPath = path;
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
        std::string amount = strprintf("%lld.%08lld", (long long)(v->giveAmount / COIN), (long long)(v->giveAmount % COIN));
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
    SwapTestHost a, b;
    const char* pszBtc = getenv("CHATSWAP_BTC");
    if (!IsTestNet() || !SwapTestWallet("CHATSWAP_A", a.wallet) || !SwapTestWallet("CHATSWAP_B", b.wallet) || !pszBtc)
    {
        printf("  needs -testnet and CHATSWAP_A, CHATSWAP_B, CHATSWAP_BTC; see selftest.cpp\n");
        return 1;
    }
    int nBtc = atoi(pszBtc);
    int nFail = 0;
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
            o.want = "BTC"; o.wantAmount = 5000000;
            a.offers["11111111111111111111111111111111"] = o;
            std::string id, err;
            nFail += Check(eb.Take(a.addr, "11111111111111111111111111111111", o, id, err), "Bob takes the offer") ? 0 : 1;
            btfchat::SwapView m, t;
            bool fEnd = SwapTestRun(ea, eb, nBtc, 7200, false, 0, m, t);
            nFail += Check(fEnd && m.stage == btfchat::SW_DONE && t.stage == btfchat::SW_DONE,
                           "both sides finish: DONE and DONE") ? 0 : 1;
            nlohmann::json tx = SwapTestBtc(nBtc, "gettransaction", nlohmann::json::array({ m.redeemTxid }), "/wallet/w");
            double got = tx.value("amount", 0.0);
            nFail += Check(got > 0.0499 && got <= 0.05, strprintf("Alice's Bitcoin Core wallet got %.8f BTC", got).c_str()) ? 0 : 1;
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
            o.give = "BTC"; o.giveAmount = 4000000;
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
            // Short locks (test chains only): 6 Bitflash blocks for Alice, 15
            // minutes of Bitcoin median time for Bob, and the margins to match.
            cfg.nBtfInitiatorBlocks = 6;
            cfg.nBtcParticipantSecs = 900;
            cfg.nTakerMinLeft = 240;
            cfg.nMakerMinLeft = 60;
            btfchat::SwapEngine ea(&a, cfg), eb(&b, cfg);
            a.convo.clear();
            b.convo.clear();
            btfchat::SwapOffer o;
            o.give = "BTF"; o.giveAmount = 50000000;
            o.want = "BTC"; o.wantAmount = 3000000;
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
    int nRefunds = 0, nSteps = 0, nRedeems = 0;
    std::string lastStep;

    std::string MyAddress() { return "me"; }
    bool PeerAccepted(const std::string&) { return true; }
    bool Invite(const std::string&, const std::string&, std::string&) { return true; }
    bool SendStep(const std::string&, const std::string& text, std::string&) { nSteps++; lastStep = text; return true; }
    void Contacts(std::vector<std::string>& out) { out.clear(); }
    void Conversation(const std::string&, std::vector<btfchat::LogEntry>& out) { out.clear(); }
    bool FindMyOffer(const std::string&, btfchat::SwapOffer&) { return false; }
    bool Wallet(const std::string& method, const nlohmann::json& params, nlohmann::json& r, std::string& err)
    {
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
    void Changed() {}

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

static std::string WaitPaySwapJson(const std::string& id)
{
    nlohmann::json s = { { "id", id }, { "peer", "them" }, { "maker", true },
                         { "give", "BTC" }, { "ga", 1000000 }, { "want", "BTF" }, { "wa", 100000000 },
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
        nFail += Check(v.stage == btfchat::SW_REFUNDED && h.nRefunds == 1, "at the lock it comes back") ? 0 : 1;
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
        nlohmann::json sw = { { "id", id }, { "peer", "them" }, { "maker", true },
                              { "give", "BTF" }, { "ga", 100000000 }, { "want", "BTC" }, { "wa", 1000000 },
                              { "btcDestination", "bcrt1qdestination" }, { "myRecv", "mvMine" },
                              { "secret", secret }, { "hash", hash },
                              { "myC", "22" }, { "myTx", std::string(64, '2') },
                              { "thC", "11" }, { "thTx", std::string(64, '1') }, { "thN", 0 },
                              { "stage", (int)btfchat::SW_REDEEMING }, { "ok", true }, { "inv", true },
                              { "created", nNow }, { "updated", nNow }, { "since", nNow } };
        std::string state = nlohmann::json{ { "swaps", nlohmann::json::array({ sw }) }, { "seen", nlohmann::json::array() } }.dump();
        WaitPayHost h;
        h.audits["11"] = { { "recipientIsMine", true }, { "recipient", "mvMine" }, { "secretHash", hash },
                           { "unspent", true }, { "confirmations", 6 }, { "amount", 0.01 }, { "secondsUntilRefund", 8 * 3600 } };
        btfchat::SwapEngine e(&h);
        e.FromJson(state);
        e.Round();
        btfchat::SwapView v = WaitPayView(e);
        nFail += Check(h.nRedeems == 1 && v.stage == btfchat::SW_REDEEMING && v.status.find("waiting for Bitcoin") != std::string::npos,
                       "light redeem sent: not done until it confirms") ? 0 : 1;
        nFail += Check(h.redeemParams.size() == 4 && h.redeemParams[3] == "bcrt1qdestination", "to the person's own address") ? 0 : 1;
        nFail += Check(h.lastStep.find("redeemed") != std::string::npos, "and the other side is told") ? 0 : 1;
        h.audits["11"]["secondsUntilRefund"] = 60;
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
        h.finds["11"] = { { "spent", true }, { "secret", secret } };
        e2.Round();
        v = WaitPayView(e2);
        nFail += Check(v.stage == btfchat::SW_DONE && h.nRedeems == 2, "in a block: done") ? 0 : 1;
    }

    // A taker's refund is not the end while the maker can still redeem ours
    // with the secret instead: until their lock opens, that is watched for.
    for (int nCase = 0; nCase < 2; nCase++)
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
        h.audits["44"] = { { "unspent", true }, { "blocksUntilRefund", 100 } };
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
        else
        {
            h.audits["44"] = { { "unspent", true }, { "blocksUntilRefund", 0 } };
            e.Round();
            v = WaitPayView(e);
            nFail += Check(v.stage == btfchat::SW_REFUNDED && h.nRedeems == 0, "their lock opened: the refund stands, it is over") ? 0 : 1;
        }
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", nFail, nFail == 1 ? "" : "s");
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
    if (name == "db-env-reopen")
        return RunDbEnvReopenSelfTest();
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
    if (name == "pool-stratum")
        return RunPoolStratumSelfTest();
    if (name == "parse-money")
        return RunParseMoneySelfTest();
    if (name == "debug-log-buffer")
        return RunDebugLogBufferSelfTest();
    if (name == "pow-v2")
        return RunPoWV2SelfTest();
    if (name == "sigpipe")
        return RunSigpipeSelfTest();
    if (name == "script-eval")
        return RunScriptEvalSelfTest();
    if (name == "rules-v2")
        return RunRulesV2SelfTest();
    if (name == "net-hardening")
        return RunNetHardeningSelfTest();
    if (name == "multisig")
        return RunMultisigSelfTest();
    if (name == "socks5-proxy")
        return RunSocks5ProxySelfTest();
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
    if (name == "p2pool-chain")
        return RunP2PoolChainSelfTest();
    if (name == "p2pool-share")
        return RunP2PoolShareSelfTest();
    if (name == "rules-v3")
        return RunRulesV3SelfTest();
    if (name == "btc-light")
        return btclight::SelfTest();
    if (name == "btc-swap")
        return RunBtcSwapSelfTest();
    if (name == "chat-swap")
        return RunChatSwapSelfTest();
    if (name == "swap-wait-payment")
        return RunSwapWaitPaymentSelfTest();
    if (name == "fee-policy")
        return RunFeePolicySelfTest();
    if (name == "invoice")
        return RunInvoiceSelfTest();
    if (name == "chat-live")
        return RunChatLiveSelfTest();

    printf("Unknown self-test '%s'\n", name.c_str());
    printf("Known self-tests: wallet-keypool, wallet-hd, wallet-format, wallet-storage-sanity, db-env-reopen, wallet-sqlite, wallet-sqlite-migration, wallet-crypto, wallet-encrypt, wallet-sqlite-encrypt, wallet-backend-default, wallet-convert, wallet-portability, net-message, network-params, consensus-limits, pool-stratum, parse-money, debug-log-buffer, pow-v2, sigpipe, script-eval, rules-v2, net-hardening, multisig, socks5-proxy, managed-tor, treasury, chat-link, chat-identity, chat-relay, chat-live\n");
    return 1;
}
