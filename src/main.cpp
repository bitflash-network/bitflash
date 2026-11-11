// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#include <chrono>
#pragma pop_macro("snprintf")
#ifdef snprintf
#undef snprintf
#endif
#include "headers.h"
#include "treasury.h"
#include "chatrelay.h"  // the chat's records: held, relayed and served here
#include "p2pool_net.h"  // the P2Pool share chain: held, checked and relayed here
#include "sha.h"
#include "proxy.h"      // BtfConnectSocket: dial the pool over its Tor onion
#include "sockcount.h"  // SOCK_ONION_PEER
#include <atomic>
#include <random>       // coin selection's coin flips
#ifndef WIN32
#include <dirent.h>     // RestrictWalletFileModes: the encryption backups
#endif
#include <mutex>
#include <thread>
#include "bip32.h"
#include "btfaddr.h"
#include "btfsock.h"
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif





//
// Global state
//

CCriticalSection cs_main;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;
// Bitflash mainnet genesis -- mined under RandomX PoW for the 2026 stable
// relaunch. Testnet gets its own resettable genesis below so block indexes,
// headers, and wallet scans cannot be accidentally mixed across networks.
static const unsigned int MAINNET_GENESIS_TIME  = 1753315200; // 2026-07-24 00:00:00 UTC
static const unsigned int MAINNET_GENESIS_NONCE = 3141;
static const char* MAINNET_GENESIS_TIMESTAMP =
    "Bitflash 24/Jul/2026 Fair launch: one CPU one vote, no premine";
static const char* MAINNET_GENESIS_HASH =
    "0x5bd7cb255d814e48cebcdfb72da4dc87b34bd774227f8ceb546c5640f4bdc169";
static const char* MAINNET_GENESIS_MERKLE =
    "0x1a45b4482532abb29b10e234d3f13132230525a339ecea91658ffa675a5b1325";

static const unsigned int TESTNET_GENESIS_TIME  = 1787184000; // 2026-08-20 00:00:00 UTC
static const unsigned int TESTNET_GENESIS_NONCE = 3199;
static const char* TESTNET_GENESIS_TIMESTAMP =
    "Bitflash testnet 20/Aug/2026: resettable public test chain";
static const char* TESTNET_GENESIS_HASH =
    "0xa9d11c6d697bcb7aea0653bc088b12dcf9f44e732df205162cf085fd9d9963eb";
static const char* TESTNET_GENESIS_MERKLE =
    "0x510b293105e3ff85b8d4c3920e357f85d1a86bf199eb4e7d11f04f380030ec5c";

unsigned int GENESIS_NONCE = MAINNET_GENESIS_NONCE;
uint256 hashGenesisBlock(MAINNET_GENESIS_HASH);
uint256 hashGenesisMerkleRoot(MAINNET_GENESIS_MERKLE);
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashBestChain = 0;
// Blocks at the tip to re-verify on startup. 0 means the whole chain. 288 is
// about ten hours at a two-minute target -- far enough back to catch a bad tip,
// short enough that startup does not pay a RandomX hash per block for the whole
// history. /checkblocks=N overrides it.
int nCheckBlocksOnLoad = 288;
// Set by CTxDB::LoadBlockIndex when the tail of the chain fails verification.
// The repair runs in LoadBlockIndex() below, once that read-only handle and its
// cursor are closed.
CBlockIndex* pindexBadChainFork = NULL;
CBlockIndex* pindexBadChainFirst = NULL;
CBlockIndex* pindexBest = NULL;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
// What the blocks in mapOrphanBlocks take, as serialized.
unsigned int nOrphanBlockBytes = 0;

map<uint256, CDataStream*> mapOrphanTransactions;
multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool> > vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<vector<unsigned char>, vector<unsigned char> > mapCryptedKeys;
map<uint160, vector<unsigned char> > mapPubKeys;
map<unsigned int, CWalletMasterKey> mapMasterKeys;
unsigned int nWalletMasterKeyMaxID = 0;
CKeyingMaterial vWalletMasterKey;
vector<unsigned char> vchCryptedHDMaster;
vector<unsigned char> vchCryptedHDChainCode;
bool fWalletEncrypted = false;
std::atomic<bool> fWalletLocked(true);   // read without a lock by IsWalletLocked
CCriticalSection cs_mapKeys;
CKey keyUser;
// A plaintext seed found in an encrypted wallet at load (see
// QuarantinePlainSeedInEncryptedWallet). Held aside, never used for
// derivation while the wallet is locked, and resolved at the next unlock.
vector<unsigned char> vchPlainSeedPendingMaster;
vector<unsigned char> vchPlainSeedPendingChainCode;
string strWalletSeedNotice;
// Largest fee CreateTransaction will pay without being told otherwise
// (/maxtxfee). A sanity limit, like Bitcoin's -maxtxfee: it catches a unit
// mistake in the fee setting before it is paid on every send.
int64 nMaxTxFee = COIN;

string strSetDataDir;
int nDropMessagesTest = 0;
bool fSoloMineTest = false; // /solomine: mine without requiring a peer (local test)

// Settings
int fGenerateBitcoins;
// How many threads to hash with. 0 means "decide from the hardware" -- see
// MinerThreadCount(). This was effectively 1 forever, because Bitcoin 0.1.0
// started exactly one miner thread and nothing here ever changed that. It made
// sense for SHA-256d in 2009; RandomX is built to be fed by every core at once,
// so a 32-core machine was mining at a thirty-second of its capacity and the
// only visible symptom was a suspiciously idle CPU.
int nMinerThreads = 0;
int64 nTransactionFee = 0;
int64 nPayTxFeePerKB = 0;
CAddress addrIncoming;
int    nMineMode        = MINE_RELAY;
bool   fMineModeFromCommandLine = false;
string strParticipantPool;           // participant mode: pool .btf address
string strPoolName       = "Bitflash Pool";
string strPoolDashboardUrl;
string strPoolStatusFile;
string strPoolRoundsFile;
double dPoolFeePercent   = 0.0;
bool   fStratumBridge    = false;
bool   fP2PoolMode       = false;
unsigned short nP2PoolPort = 3333;
string strP2PoolPayTo;
int    nStratumBridgePort = 3333;
string strStratumBridgeBind = "127.0.0.1";

static std::atomic<uint64> gParticipantSharesSent{0};
static std::atomic<uint64> gParticipantSharesAccepted{0};
static std::atomic<uint64> gParticipantHashes{0};
static std::atomic<uint64> gParticipantHashRateX1000{0};
static std::mutex gParticipantStatusMutex;
static std::string gParticipantStatus;

MapCheckpoints mapCheckpoints;

// Mainnet checkpoints. Each was more than a week under the tip on the day it
// went in, and was read from the block files of three nodes that agreed.
// Testnet has none: it is reset and re-mined on purpose.
static void SelectCheckpoints(bool fTestNetIn)
{
    mapCheckpoints.clear();
    if (fTestNetIn)
        return;
    mapCheckpoints[68000] = uint256("0xda46bdcfe661ddb61b8d27a1adc5c0fc30f6ad6a8f18f03fc9dc07a7e003bfc6");
}

void SelectGenesisParams(bool fTestNetIn)
{
    static bool fGenesisParamsSelected = false;
    static bool fGenesisParamsTestNet = false;
    if (fGenesisParamsSelected && fGenesisParamsTestNet == fTestNetIn)
        return;

    fGenesisParamsSelected = true;
    fGenesisParamsTestNet = fTestNetIn;

    if (fTestNetIn)
    {
        GENESIS_NONCE = TESTNET_GENESIS_NONCE;
        hashGenesisBlock = uint256(TESTNET_GENESIS_HASH);
        hashGenesisMerkleRoot = uint256(TESTNET_GENESIS_MERKLE);
    }
    else
    {
        GENESIS_NONCE = MAINNET_GENESIS_NONCE;
        hashGenesisBlock = uint256(MAINNET_GENESIS_HASH);
        hashGenesisMerkleRoot = uint256(MAINNET_GENESIS_MERKLE);
    }
    SelectCheckpoints(fTestNetIn);
}

void SelectChainParams(bool fTestNetIn)
{
    SelectNetworkParams(fTestNetIn);
    SelectGenesisParams(fTestNetIn);
}

// The work one block stands for: how many hashes it takes, on average, to find
// one at or under its target, which is 2^256 / (target + 1). A block at the
// floor (0x1f0fffff) counts 4096; one at four times the difficulty, 16384.
uint256 GetBlockWork(unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return 0;
    // A named value: the operators return const CBigNum, and getuint256() is
    // not const (GCC let -fpermissive pass that; clang does not).
    CBigNum bnWork = (CBigNum(1) << 256) / (bnTarget + 1);
    return bnWork.getuint256();
}

// Fill in what is not stored for a block whose pprev, nHeight and nBits are
// set and whose parent has been through here already.
void SetChainWork(CBlockIndex* pindex)
{
    pindex->nChainWork = GetBlockWork(pindex->nBits);
    pindex->fOffCheckpoint = false;
    pindex->fFailed = false;
    if (pindex->pprev)
    {
        pindex->nChainWork += pindex->pprev->nChainWork;
        pindex->fOffCheckpoint = pindex->pprev->fOffCheckpoint;
        pindex->fFailed = pindex->pprev->fFailed;
    }
    MapCheckpoints::const_iterator mi = mapCheckpoints.find(pindex->nHeight);
    if (mi != mapCheckpoints.end() && pindex->phashBlock && (*mi).second != pindex->GetBlockHash())
        pindex->fOffCheckpoint = true;
}

std::string ChainWorkToString(const uint256& nWork)
{
    std::string str = nWork.GetHex();
    size_t nFirst = str.find_first_not_of('0');
    return nFirst == std::string::npos ? "0" : str.substr(nFirst);
}

// Whether pindexNew should replace pindexOld as the best chain.
bool IsBetterChain(const CBlockIndex* pindexNew, const CBlockIndex* pindexOld)
{
    if (pindexNew == NULL || pindexNew->fOffCheckpoint || pindexNew->fFailed)
        return false;
    if (pindexOld == NULL || pindexOld->fOffCheckpoint || pindexOld->fFailed)
        return true;
    return pindexNew->nChainWork > pindexOld->nChainWork;
}

std::vector<CBlockIndex*> MarkBlockFailed(CBlockIndex* pindexBad)
{
    std::vector<CBlockIndex*> vMarked;
    if (pindexBad == NULL)
        return vMarked;
    if (!pindexBad->fFailed)
    {
        pindexBad->fFailed = true;
        vMarked.push_back(pindexBad);
    }
    // Every descendant, whichever branch it is on: parents before children,
    // so one pass in height order carries the mark all the way down.
    vector<pair<int, CBlockIndex*> > vByHeight;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        if ((*mi).second->nHeight > pindexBad->nHeight)
            vByHeight.push_back(make_pair((*mi).second->nHeight, (*mi).second));
    sort(vByHeight.begin(), vByHeight.end());
    for (unsigned int i = 0; i < vByHeight.size(); i++)
    {
        CBlockIndex* pindex = vByHeight[i].second;
        if (!pindex->fFailed && pindex->pprev && pindex->pprev->fFailed)
        {
            pindex->fFailed = true;
            vMarked.push_back(pindex);
        }
    }
    printf("MarkBlockFailed() : block %s at height %d failed, %d block(s) marked\n",
           pindexBad->GetBlockHash().ToString().substr(0,14).c_str(), pindexBad->nHeight, (int)vMarked.size());
    return vMarked;
}

// Take the records of marked blocks off the disk index, with no transaction
// open on txdb. A record that stays (a failed erase) only means the block is
// read back at the next start, unmarked, and has to fail again. No record left
// on disk names one of them as its parent or its next block: every descendant
// is marked too, and none of them is on the best chain (a block that was is
// disconnected first, which clears its parent's next).
static void EraseFailedFromDiskIndex(CTxDB& txdb, const std::vector<CBlockIndex*>& vMarked)
{
    for (unsigned int i = 0; i < vMarked.size(); i++)
        txdb.EraseBlockIndex(vMarked[i]->GetBlockHash());
}

// The highest checkpoint whose block this node has.
const CBlockIndex* LastCheckpointInIndex()
{
    for (MapCheckpoints::const_reverse_iterator it = mapCheckpoints.rbegin(); it != mapCheckpoints.rend(); ++it)
    {
        map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find((*it).second);
        if (mi != mapBlockIndex.end() && (*mi).second->nHeight == (*it).first && !(*mi).second->fOffCheckpoint)
            return (*mi).second;
    }
    return NULL;
}

// Whether a block with this hash may go on top of pindexPrev.
bool CheckpointsAllow(const CBlockIndex* pindexPrev, const uint256& hash, const char** ppszWhy, int* pnScore)
{
    const char* pszWhy = NULL;
    int nScore = 0;
    if (pindexPrev && !mapCheckpoints.empty())
    {
        int nHeight = pindexPrev->nHeight + 1;
        MapCheckpoints::const_iterator mi = mapCheckpoints.find(nHeight);
        const CBlockIndex* pcheckpoint = LastCheckpointInIndex();
        if (pindexPrev->fOffCheckpoint)
        {
            pszWhy = "builds on a chain that contradicts a checkpoint";
            nScore = CHECKPOINT_SCORE_CONTRADICTS;
        }
        else if (mi != mapCheckpoints.end() && (*mi).second != hash)
        {
            pszWhy = "is not the checkpoint block of its height";
            nScore = CHECKPOINT_SCORE_CONTRADICTS;
        }
        else if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        {
            pszWhy = "forks off below the last checkpoint";
            nScore = CHECKPOINT_SCORE_OLD_FORK;
        }
    }
    if (ppszWhy)
        *ppszWhy = pszWhy;
    if (pnScore)
        *pnScore = nScore;
    return pszWhy == NULL;
}

CBlockIndex* BackToCheckpoints(CBlockIndex* pindex)
{
    while (pindex && pindex->fOffCheckpoint)
        pindex = pindex->pprev;
    return pindex;
}

bool fCheckpointWalkBack = false;
bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew);

// Only after a checkpoint walk back: a walk back for a tail that failed
// verification marks those blocks failed, and they are never candidates.
// Every block in the index is on disk (AcceptBlock writes it first), and
// Reorganize connects each one, so a candidate that does not connect is
// marked failed by Reorganize and the next one is tried.
bool ActivateBestKnownChain()
{
    if (!fCheckpointWalkBack)
        return true;
    fCheckpointWalkBack = false;
    bool fRet = true;
    CRITICAL_BLOCK(cs_main)
    {
        for (int nTry = 0; nTry < 8; nTry++)
        {
            CBlockIndex* pindexBestKnown = pindexBest;
            for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
                if (IsBetterChain((*mi).second, pindexBestKnown))
                    pindexBestKnown = (*mi).second;
            if (pindexBestKnown == pindexBest)
                break;
            printf("ActivateBestKnownChain() : the index already has a better chain, height %d work %s\n",
                   pindexBestKnown->nHeight, ChainWorkToString(pindexBestKnown->nChainWork).c_str());
            CTxDB txdb;
            txdb.TxnBegin();
            if (!Reorganize(txdb, pindexBestKnown))
            {
                txdb.TxnAbort();
                fRet = error("ActivateBestKnownChain() : Reorganize failed");
                if (!pindexBestKnown->fFailed)
                    break;   // nothing was marked, so the same candidate would come back
                continue;
            }
            hashBestChain = pindexBestKnown->GetBlockHash();
            pindexBest = pindexBestKnown;
            nBestHeight = pindexBest->nHeight;
            nTransactionsUpdated++;
            printf("ActivateBestKnownChain() : new best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0,14).c_str(),
                   nBestHeight, ChainWorkToString(pindexBest->nChainWork).c_str());
            fRet = true;
            break;
        }
    }
    return fRet;
}

// "HEIGHT:HASH", for -benchcheckpoint.
bool AddBenchCheckpoint(const std::string& strArg)
{
    size_t nColon = strArg.find(':');
    if (nColon == std::string::npos)
        return false;
    std::string strHeight = strArg.substr(0, nColon);
    std::string strHash = strArg.substr(nColon + 1);
    if (strHeight.empty() || strHeight.size() > 9 || strHeight.find_first_not_of("0123456789") != std::string::npos)
        return false;
    if (strHash.size() != 64 || strHash.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        return false;
    mapCheckpoints[atoi(strHeight.c_str())] = uint256(strHash);
    return true;
}

static CBlock BuildGenesisBlock()
{
    const char* pszTimestamp = IsTestNet() ?
        TESTNET_GENESIS_TIMESTAMP : MAINNET_GENESIS_TIMESTAMP;

    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) <<
        vector<unsigned char>((unsigned char*)pszTimestamp,
                              (unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey = CScript() <<
        CBigNum("0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704") <<
        OP_CHECKSIG;

    CBlock block;
    block.vtx.push_back(txNew);
    block.hashPrevBlock = 0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = IsTestNet() ? TESTNET_GENESIS_TIME : MAINNET_GENESIS_TIME;
    block.nBits = 0x1f0fffff; // = bnProofOfWorkLimit (Bitflash RandomX floor)
    block.nNonce = GENESIS_NONCE;
    return block;
}

void SetParticipantMiningStatus(const std::string& status)
{
    // Updates the GUI status string only. Logging is done at each call site
    // with full context; duplicating it here just adds noise to the log.
    std::lock_guard<std::mutex> lk(gParticipantStatusMutex);
    gParticipantStatus = status;
}

std::string GetParticipantMiningStatus()
{
    std::lock_guard<std::mutex> lk(gParticipantStatusMutex);
    return gParticipantStatus;
}

void GetParticipantMiningStats(uint64& sharesSent, uint64& sharesAccepted, double& hashRate)
{
    sharesSent = gParticipantSharesSent.load();
    sharesAccepted = gParticipantSharesAccepted.load();
    hashRate = (double)gParticipantHashRateX1000.load() / 1000.0;
}







//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//

// Threads to hash with, resolving the automatic case.
//
// Automatic leaves one core to the rest of the node -- accepting blocks,
// talking to peers, serving the GUI -- because a machine that mines perfectly
// while falling behind the chain has won nothing. Anyone who disagrees can say
// so with /genproclimit and get exactly what they ask for.
//
// Memory is not the reason to hold back: the ~2 GB RandomX dataset is shared by
// every thread, and each one adds only its own 2 MB scratchpad. Sixteen threads
// cost about 32 MB more than one.
int MinerThreadCount()
{
    if (nMinerThreads > 0)
        return nMinerThreads;
    unsigned int nCores = std::thread::hardware_concurrency();
    if (nCores <= 1)
        return 1;
    return (int)(nCores - 1);
}

static void SecureClearBytes(vector<unsigned char>& vch);
static void SecureClearKeyingMaterial(CKeyingMaterial& vch);

bool AddKey(const CKey& key)
{
    if (IsWalletEncrypted())
    {
        string strError;
        CPrivKey vchPrivKey = key.GetPrivKey();
        vector<unsigned char> vchCryptedSecret;
        // The master key is read under cs_mapKeys, the lock LockWallet clears
        // it under: a relock (timeout or walletlock) can come from another
        // thread at any moment now.
        CRITICAL_BLOCK(cs_mapKeys)
        {
            if (IsWalletLocked())
                return error("AddKey() : wallet is locked\n");
            vector<unsigned char> vchPlainSecret(vchPrivKey.begin(), vchPrivKey.end());
            bool fEncrypted = EncryptSecret(vWalletMasterKey, vchPlainSecret,
                                            WalletKeyIV(key.GetPubKey()), vchCryptedSecret);
            SecureClearBytes(vchPlainSecret);
            if (!fEncrypted)
                return error("AddKey() : encrypting key failed\n");
            if (!AddCryptedKey(key.GetPubKey(), vchCryptedSecret))
                return false;
        }
        return CWalletDB().WriteCryptedKey(key.GetPubKey(), vchCryptedSecret);
    }

    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[key.GetPubKey()] = key.GetPrivKey();
        mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
    }
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

bool IsWalletEncrypted()
{
    return fWalletEncrypted;
}

bool IsWalletLocked()
{
    return fWalletEncrypted && fWalletLocked;
}

static void SecureClearBytes(vector<unsigned char>& vch)
{
    if (!vch.empty())
        OPENSSL_cleanse(&vch[0], vch.size());
    vch.clear();
}

static void SecureClearKeyingMaterial(CKeyingMaterial& vch)
{
    if (!vch.empty())
        OPENSSL_cleanse(&vch[0], vch.size());
    vch.clear();
}

// When the wallet locks itself again (0: it does not). Set by an unlock with a
// timeout, cleared by any lock.
static std::atomic<int64> nWalletRelockTime(0);
static std::atomic<bool> fWalletRelockThreadStarted(false);

void LockWallet()
{
    if (!fWalletEncrypted)
        return;
    nWalletRelockTime.store(0);
    // Every lock in the wallet's order (cs_main, cs_mapWallet, cs_keyPool,
    // cs_mapKeys): a send, a key derivation or a key-pool draw that is under
    // way finishes with the keys it started with, and the next one sees the
    // wallet locked. The seed copy is read under cs_keyPool, the master key
    // under cs_mapKeys, so both are cleared with those held.
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    CRITICAL_BLOCK(cs_keyPool)
    CRITICAL_BLOCK(cs_mapKeys)
    {
        SecureClearKeyingMaterial(vWalletMasterKey);
        if (!vchCryptedHDMaster.empty())
            SecureClearBytes(vchHDMaster);
        if (!vchCryptedHDChainCode.empty())
            SecureClearBytes(vchHDChainCode);
        // The default key's secret too: a phrase install in this session
        // left a full key in keyUser.
        keyUser.ForgetPrivKey();
        fWalletLocked = true;
    }
}

int64 GetWalletRelockTime()
{
    return nWalletRelockTime.load();
}

// A node that mines or runs a pool draws a wallet key for every coinbase, and
// a locked wallet has none to give: the miner stops, and the pool's template
// builder would pay its blocks to an empty key. So such a node does not lock.
bool (*pfnWalletLockRefusedExtra)(string& strWhyRet) = NULL;

bool WalletLockRefusedWhy(string& strWhyRet)
{
    strWhyRet.clear();
    if (fGenerateBitcoins || nMineMode == MINE_OPERATOR || fP2PoolMode)
    {
        strWhyRet = "this node mines or runs a pool, and every block it makes needs a wallet key; "
                    "stop mining first";
        return true;
    }
    if (pfnWalletLockRefusedExtra && pfnWalletLockRefusedExtra(strWhyRet))
        return true;
    strWhyRet.clear();
    return false;
}

static void ThreadWalletRelock()
{
    while (!fShutdown)
    {
        Sleep(250);
        int64 nWhen = nWalletRelockTime.load();
        if (nWhen != 0 && GetTime() >= nWhen && !IsWalletLocked())
        {
            // Asked again now, not only when the timeout was set: mining or a
            // pool can have been switched on since, and a locked wallet would
            // leave them no key for the next block.
            string strWhy;
            if (WalletLockRefusedWhy(strWhy))
            {
                nWalletRelockTime.store(0);
                printf("wallet: the unlock timeout ran out, but the wallet stays unlocked: %s\n",
                       strWhy.c_str());
                continue;
            }
            LockWallet();
            printf("wallet: the unlock timeout ran out; the wallet is locked again\n");
        }
    }
}

// 0 keeps the wallet unlocked until LockWallet; a positive number locks it
// that many seconds from now, whatever unlock came before.
void SetWalletRelockTimeout(int64 nSeconds)
{
    if (nSeconds <= 0)
    {
        nWalletRelockTime.store(0);
        return;
    }
    nWalletRelockTime.store(GetTime() + nSeconds);
    bool fExpected = false;
    if (fWalletRelockThreadStarted.compare_exchange_strong(fExpected, true))
        std::thread(ThreadWalletRelock).detach();
}

bool DeriveWalletPassphraseKey(const string& strPassphrase,
                               const vector<unsigned char>& vchSalt,
                               unsigned int nDeriveIterations,
                               CKeyingMaterial& vchKeyRet,
                               vector<unsigned char>& vchIVRet)
{
    vchKeyRet.clear();
    vchIVRet.clear();
    if (vchSalt.size() != 8 || nDeriveIterations < 1)
        return false;

    unsigned char chKey[32];
    unsigned char chIV[16];
    int n = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &vchSalt[0],
                           (const unsigned char*)strPassphrase.data(),
                           (int)strPassphrase.size(),
                           (int)nDeriveIterations,
                           chKey, chIV);
    if (n != 32)
    {
        OPENSSL_cleanse(chKey, sizeof(chKey));
        OPENSSL_cleanse(chIV, sizeof(chIV));
        return false;
    }
    vchKeyRet.assign(chKey, chKey + sizeof(chKey));
    vchIVRet.assign(chIV, chIV + sizeof(chIV));
    OPENSSL_cleanse(chKey, sizeof(chKey));
    OPENSSL_cleanse(chIV, sizeof(chIV));
    return true;
}

// Rounds for a new master key. The fixed 25000 is cheap for a GPU guessing
// passphrases against a stolen wallet file. As Bitcoin Core does, measure
// this machine and take what costs about a tenth of a second per unlock,
// never fewer than 25000. The count is stored with the master key, so a
// wallet encrypted before this keeps opening with its own.
unsigned int CalibrateWalletDeriveIterations(const string& strPassphrase,
                                             const vector<unsigned char>& vchSalt)
{
    static const unsigned int nFloor = 25000;
    static const double dCeiling = 50000000.0;
    static const double dTargetMs = 100.0;
    unsigned int nRounds = nFloor;
    // Twice: the first run at the floor only estimates the speed, the second
    // runs near the target and corrects for what the estimate got wrong.
    for (int pass = 0; pass < 2; pass++)
    {
        CKeyingMaterial vchKey;
        vector<unsigned char> vchIV;
        std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
        if (!DeriveWalletPassphraseKey(strPassphrase, vchSalt, nRounds, vchKey, vchIV))
            return nFloor;
        double dMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        double dNext = nRounds * dTargetMs / std::max(dMs, 1.0);
        nRounds = (unsigned int)std::min(dNext, dCeiling);
    }
    return std::max(nRounds, nFloor);
}

bool EncryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchPlaintext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchCiphertextRet)
{
    vchCiphertextRet.clear();
    if (vchKey.size() != 32 || vchIV.size() != 16)
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool fOk = false;
    int nLen = 0;
    int nFinal = 0;
    vector<unsigned char> vchOut(vchPlaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &vchKey[0], &vchIV[0]) &&
        EVP_EncryptUpdate(ctx, &vchOut[0], &nLen,
                          vchPlaintext.empty() ? NULL : &vchPlaintext[0],
                          (int)vchPlaintext.size()) &&
        EVP_EncryptFinal_ex(ctx, &vchOut[0] + nLen, &nFinal))
    {
        vchOut.resize(nLen + nFinal);
        vchCiphertextRet.swap(vchOut);
        fOk = true;
    }
    EVP_CIPHER_CTX_free(ctx);
    return fOk;
}

bool DecryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchCiphertext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchPlaintextRet)
{
    vchPlaintextRet.clear();
    if (vchKey.size() != 32 || vchIV.size() != 16 || vchCiphertext.empty())
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool fOk = false;
    int nLen = 0;
    int nFinal = 0;
    vector<unsigned char> vchOut(vchCiphertext.size());
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &vchKey[0], &vchIV[0]) &&
        EVP_DecryptUpdate(ctx, &vchOut[0], &nLen, &vchCiphertext[0],
                          (int)vchCiphertext.size()) &&
        EVP_DecryptFinal_ex(ctx, &vchOut[0] + nLen, &nFinal))
    {
        vchOut.resize(nLen + nFinal);
        vchPlaintextRet.swap(vchOut);
        fOk = true;
    }
    if (!fOk)
        SecureClearBytes(vchOut);
    EVP_CIPHER_CTX_free(ctx);
    return fOk;
}

vector<unsigned char> WalletKeyIV(const vector<unsigned char>& vchPubKey)
{
    uint256 hash = Hash(vchPubKey.begin(), vchPubKey.end());
    vector<unsigned char> vchIV(16);
    memcpy(&vchIV[0], hash.begin(), vchIV.size());
    return vchIV;
}

vector<unsigned char> WalletSecretIV(const string& strLabel)
{
    uint256 hash = Hash(strLabel.begin(), strLabel.end());
    vector<unsigned char> vchIV(16);
    memcpy(&vchIV[0], hash.begin(), vchIV.size());
    return vchIV;
}

bool AddCryptedKey(const vector<unsigned char>& vchPubKey,
                   const vector<unsigned char>& vchCryptedSecret)
{
    if (vchPubKey.empty() || vchCryptedSecret.empty())
        return false;
    CRITICAL_BLOCK(cs_mapKeys)
    {
        fWalletEncrypted = true;
        mapCryptedKeys[vchPubKey] = vchCryptedSecret;
        mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
    }
    return true;
}

map<uint160, CScript> mapScripts;

bool AddCScript(const CScript& redeemScript)
{
    uint160 hash = Hash160(redeemScript);
    CRITICAL_BLOCK(cs_mapKeys)
        mapScripts[hash] = redeemScript;
    return CWalletDB().WriteCScript(hash, redeemScript);
}

bool HaveCScript(const uint160& hash)
{
    CRITICAL_BLOCK(cs_mapKeys)
        return mapScripts.count(hash) > 0;
    return false;
}

bool GetWalletCScript(const uint160& hash, CScript& scriptRet)
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<uint160, CScript>::iterator mi = mapScripts.find(hash);
        if (mi == mapScripts.end())
            return false;
        scriptRet = mi->second;
    }
    return true;
}

bool WalletCanSpendKey(const vector<unsigned char>& vchPubKey)
{
    CRITICAL_BLOCK(cs_mapKeys)
        return mapKeys.count(vchPubKey) > 0 || mapCryptedKeys.count(vchPubKey) > 0;
    return false;
}

bool GetWalletPrivKey(const vector<unsigned char>& vchPubKey,
                      CPrivKey& vchPrivKeyRet,
                      string& strErrorRet)
{
    vchPrivKeyRet.clear();
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<vector<unsigned char>, CPrivKey>::iterator mi = mapKeys.find(vchPubKey);
        if (mi != mapKeys.end())
        {
            vchPrivKeyRet = (*mi).second;
            return true;
        }

        map<vector<unsigned char>, vector<unsigned char> >::iterator mci = mapCryptedKeys.find(vchPubKey);
        if (mci == mapCryptedKeys.end())
        {
            strErrorRet = "private key not found";
            return false;
        }
        if (IsWalletLocked())
        {
            strErrorRet = "wallet is locked";
            return false;
        }

        vector<unsigned char> vchPlaintext;
        if (!DecryptSecret(vWalletMasterKey, (*mci).second, WalletKeyIV(vchPubKey), vchPlaintext))
        {
            strErrorRet = "could not decrypt private key";
            return false;
        }

        CPrivKey vchPrivKey(vchPlaintext.begin(), vchPlaintext.end());
        SecureClearBytes(vchPlaintext);
        CKey key;
        if (!key.SetPrivKey(vchPrivKey) || key.GetPubKey() != vchPubKey)
        {
            strErrorRet = "decrypted private key does not match its public key";
            return false;
        }
        vchPrivKeyRet = vchPrivKey;
        return true;
    }
    return false;
}

bool UnlockWallet(const string& strPassphrase, string& strErrorRet)
{
    strErrorRet.clear();
    if (!IsWalletEncrypted())
        return true;

    bool fUnlocked = false;
    CRITICAL_BLOCK(cs_mapKeys)
    {
        for (map<unsigned int, CWalletMasterKey>::iterator mi = mapMasterKeys.begin();
             mi != mapMasterKeys.end(); ++mi)
        {
            const CWalletMasterKey& kMasterKey = (*mi).second;
            CKeyingMaterial vchPassKey;
            vector<unsigned char> vchPassIV;
            if (!DeriveWalletPassphraseKey(strPassphrase, kMasterKey.vchSalt,
                                           kMasterKey.nDeriveIterations,
                                           vchPassKey, vchPassIV))
                continue;

            vector<unsigned char> vchMasterPlain;
            if (!DecryptSecret(vchPassKey, kMasterKey.vchCryptedKey,
                               vchPassIV, vchMasterPlain))
            {
                SecureClearBytes(vchPassIV);
                continue;
            }
            if (vchMasterPlain.size() != 32)
            {
                SecureClearBytes(vchMasterPlain);
                SecureClearBytes(vchPassIV);
                continue;
            }

            CKeyingMaterial vchCandidate(vchMasterPlain.begin(), vchMasterPlain.end());
            SecureClearBytes(vchMasterPlain);
            SecureClearBytes(vchPassIV);
            // A candidate master key is accepted only when it decrypts a key
            // whose public half it must match. An encrypted wallet with no
            // encrypted key gives nothing to check it against -- EncryptWallet
            // never writes one, so only a damaged or crafted file looks like
            // that -- and is refused rather than trusted.
            bool fValid = false;
            for (map<vector<unsigned char>, vector<unsigned char> >::iterator mci = mapCryptedKeys.begin();
                 mci != mapCryptedKeys.end(); ++mci)
            {
                vector<unsigned char> vchPlaintext;
                if (!DecryptSecret(vchCandidate, (*mci).second, WalletKeyIV((*mci).first), vchPlaintext))
                    break;
                CPrivKey vchPrivKey(vchPlaintext.begin(), vchPlaintext.end());
                SecureClearBytes(vchPlaintext);
                CKey key;
                if (key.SetPrivKey(vchPrivKey) && key.GetPubKey() == (*mci).first)
                    fValid = true;
                break;
            }
            if (fValid)
            {
                vWalletMasterKey = vchCandidate;
                if (!vchCryptedHDMaster.empty())
                {
                    vector<unsigned char> vchPlainHDMaster;
                    if (!DecryptSecret(vWalletMasterKey, vchCryptedHDMaster,
                                       WalletSecretIV("hdmaster"), vchPlainHDMaster) ||
                        vchPlainHDMaster.size() != 32)
                    {
                        SecureClearBytes(vchPlainHDMaster);
                        strErrorRet = "could not decrypt HD master key";
                        return false;
                    }
                    vchHDMaster = vchPlainHDMaster;
                    SecureClearBytes(vchPlainHDMaster);
                }
                if (!vchCryptedHDChainCode.empty())
                {
                    vector<unsigned char> vchPlainHDChainCode;
                    if (!DecryptSecret(vWalletMasterKey, vchCryptedHDChainCode,
                                       WalletSecretIV("hdchaincode"), vchPlainHDChainCode) ||
                        vchPlainHDChainCode.size() != 32)
                    {
                        SecureClearBytes(vchPlainHDChainCode);
                        strErrorRet = "could not decrypt HD chain code";
                        return false;
                    }
                    vchHDChainCode = vchPlainHDChainCode;
                    SecureClearBytes(vchPlainHDChainCode);
                }
                fWalletLocked = false;
                fUnlocked = true;
                break;
            }
        }
    }
    if (fUnlocked)
    {
        // Outside cs_mapKeys: the repair takes cs_keyPool first, as every
        // other path does.
        RepairPlainSeedAfterUnlock();
        RepairReissuedPool();
        return true;
    }
    if (mapCryptedKeys.empty() && !mapMasterKeys.empty())
    {
        strErrorRet = "this encrypted wallet holds no encrypted key to check the passphrase against";
        return false;
    }

    strErrorRet = "passphrase did not unlock the wallet";
    return false;
}

bool UnlockWalletFor(const string& strPassphrase, int64 nSeconds, string& strErrorRet)
{
    if (!UnlockWallet(strPassphrase, strErrorRet))
        return false;
    SetWalletRelockTimeout(nSeconds);
    return true;
}

static bool WalletAlreadyHasKey(const vector<unsigned char>& vchPubKey)
{
    CRITICAL_BLOCK(cs_mapKeys)
        return mapKeys.count(vchPubKey) > 0 || mapCryptedKeys.count(vchPubKey) > 0;
    return false;
}

static bool AddKeyIfMissing(const CKey& key)
{
    if (WalletAlreadyHasKey(key.GetPubKey()))
        return true;
    return AddKey(key);
}

static bool DeriveNextHDReceiveKey(vector<unsigned char>& vchPubKeyRet, string& strErrorRet)
{
    vchPubKeyRet.clear();
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (!HaveHDSeed())
        {
            strErrorRet = "no seed";
            return false;
        }

        CKey key;
        unsigned int nIndex = 0;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
            nIndex = nHDReceiveNext;
        else
            nIndex = nHDNext;
        if (!DeriveHDKey(nIndex, key, strErrorRet))
            return false;
        if (!AddKeyIfMissing(key))
        {
            strErrorRet = "could not write the derived key to wallet.dat";
            return false;
        }

        unsigned int nNext = nIndex + 1;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
        {
            if (!CWalletDB().WriteHDReceiveNext(nNext))
            {
                strErrorRet = "could not advance the receive derivation counter";
                return false;
            }
            nHDReceiveNext = nNext;
        }
        else
        {
            if (!CWalletDB().WriteHDNext(nNext))
            {
                strErrorRet = "could not advance the derivation counter";
                return false;
            }
            nHDNext = nNext;
        }

        vchPubKeyRet = key.GetPubKey();
    }
    return true;
}

static bool DeriveNextHDChangeKey(vector<unsigned char>& vchPubKeyRet, string& strErrorRet)
{
    vchPubKeyRet.clear();
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (!HaveHDSeed())
        {
            strErrorRet = "no seed";
            return false;
        }

        CKey key;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
        {
            if (!DeriveHDChangeKey(nHDChangeNext, key, strErrorRet))
                return false;
            if (!AddKeyIfMissing(key))
            {
                strErrorRet = "could not write the derived change key to wallet.dat";
                return false;
            }
            unsigned int nNext = nHDChangeNext + 1;
            if (!CWalletDB().WriteHDChangeNext(nNext))
            {
                strErrorRet = "could not advance the change derivation counter";
                return false;
            }
            nHDChangeNext = nNext;
        }
        else
        {
            if (!DeriveHDKey(nHDNext, key, strErrorRet))
                return false;
            if (!AddKeyIfMissing(key))
            {
                strErrorRet = "could not write the derived change key to wallet.dat";
                return false;
            }
            unsigned int nNext = nHDNext + 1;
            if (!CWalletDB().WriteHDNext(nNext))
            {
                strErrorRet = "could not advance the derivation counter";
                return false;
            }
            nHDNext = nNext;
        }
        vchPubKeyRet = key.GetPubKey();
    }
    return true;
}

vector<unsigned char> GenerateNewKey()
{
    CKey key;
    key.MakeNewKey();
    if (!AddKey(key))
        throw runtime_error("GenerateNewKey() : AddKey failed\n");
    return key.GetPubKey();
}

CCriticalSection cs_keyPool;
map<int64, vector<unsigned char> > mapKeyPool;

vector<unsigned char> vchHDMaster;
vector<unsigned char> vchHDChainCode;
unsigned int nHDNext = 0;
int nHDKeySchema = HD_SCHEMA_NONE;
unsigned int nHDReceiveNext = 0;
unsigned int nHDChangeNext = 0;
unsigned int nHDCoinType = HD_BIP44_COIN_TYPE_BITFLASH;

string HDKeySchemaName(int nSchema)
{
    if (nSchema == HD_SCHEMA_LEGACY)
        return "legacy-hd";
    if (nSchema == HD_SCHEMA_BIP44)
        return "bip44";
    return "none";
}

std::vector<unsigned int> HDLegacyPath(unsigned int nIndex)
{
    std::vector<unsigned int> path;
    path.push_back(nIndex | bitflash::BIP32_HARDENED);
    return path;
}

std::vector<unsigned int> HDBIP44Path(unsigned int nCoinType,
                                      unsigned int nAccount,
                                      unsigned int nChain,
                                      unsigned int nIndex)
{
    std::vector<unsigned int> path;
    path.push_back(HD_BIP44_PURPOSE | bitflash::BIP32_HARDENED);
    path.push_back(nCoinType | bitflash::BIP32_HARDENED);
    path.push_back(nAccount | bitflash::BIP32_HARDENED);
    path.push_back(nChain);
    path.push_back(nIndex);
    return path;
}

static bool ClearKeyPoolRecords(string& strErrorRet)
{
    CWalletDB walletdb;
    for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
         mi != mapKeyPool.end(); ++mi)
    {
        if (!walletdb.ErasePool(mi->first))
        {
            strErrorRet = strprintf("could not clear old key-pool entry %lld",
                                    (long long)mi->first);
            return false;
        }
    }
    mapKeyPool.clear();
    return true;
}

bool ResetKeyPoolRecords(string& strErrorRet)
{
    CRITICAL_BLOCK(cs_keyPool)
        return ClearKeyPoolRecords(strErrorRet);
    return false;
}

// One key from an explicit seed and path. Everything else derives through
// here, so the seed copies and the intermediate nodes are wiped in one place
// (BIP32PrivateNode wipes itself when it goes out of scope).
static bool DeriveKeyFromSeed(const vector<unsigned char>& vchMaster,
                              const vector<unsigned char>& vchChainCode,
                              const std::vector<unsigned int>& path,
                              CKey& keyRet, string& strErrorRet)
{
    if (vchMaster.size() != 32 || vchChainCode.size() != 32)
    {
        strErrorRet = "no seed";
        return false;
    }
    bitflash::BIP32PrivateNode parent;
    parent.privateKey = vchMaster;
    parent.chainCode  = vchChainCode;

    bitflash::BIP32PrivateNode child;
    if (!bitflash::BIP32DerivePath(parent, path, child, strErrorRet))
        return false;

    if (!keyRet.SetSecret(child.privateKey))
    {
        strErrorRet = "derived scalar is not a usable key";
        return false;
    }
    return true;
}

static std::vector<unsigned int> HDReceivePathFor(int nSchema, unsigned int nCoinType, unsigned int nIndex)
{
    return nSchema == HD_SCHEMA_BIP44
        ? HDBIP44Path(nCoinType, HD_BIP44_ACCOUNT, HD_BIP44_CHAIN_RECEIVE, nIndex)
        : HDLegacyPath(nIndex);
}

bool DeriveHDKeyForSchema(int nSchema, unsigned int nIndex, CKey& keyRet, string& strErrorRet)
{
    if (!HaveHDSeed())
    {
        strErrorRet = "no seed";
        return false;
    }
    if (nIndex >= bitflash::BIP32_HARDENED)
    {
        strErrorRet = "child index must be non-hardened; hardening is applied here";
        return false;
    }
    return DeriveKeyFromSeed(vchHDMaster, vchHDChainCode,
                             HDReceivePathFor(nSchema, nHDCoinType, nIndex),
                             keyRet, strErrorRet);
}

bool DeriveHDKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet)
{
    return DeriveHDKeyForSchema(nHDKeySchema, nIndex, keyRet, strErrorRet);
}

bool DeriveHDChangeKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet)
{
    if (!HaveHDSeed())
    {
        strErrorRet = "no seed";
        return false;
    }
    if (nIndex >= bitflash::BIP32_HARDENED)
    {
        strErrorRet = "child index must be non-hardened; hardening is applied here";
        return false;
    }

    if (nHDKeySchema != HD_SCHEMA_BIP44)
        return DeriveHDKey(nIndex, keyRet, strErrorRet);

    return DeriveKeyFromSeed(vchHDMaster, vchHDChainCode,
                             HDBIP44Path(nHDCoinType, HD_BIP44_ACCOUNT,
                                         HD_BIP44_CHAIN_CHANGE, nIndex),
                             keyRet, strErrorRet);
}

bool WalletAddKeyIfMissing(const CKey& key)
{
    return AddKeyIfMissing(key);
}

// Move the derivation counters past keys the wallet already holds. A counter
// that went backwards (an interrupted phrase install reset it to 1/0) would
// hand out addresses that were handed out before. Keys are derived and stored
// in order, so what the wallet holds is a run from the start of each chain.
// Hold cs_keyPool.
static void AdvanceHDCountersPastHeldKeys()
{
    if (!HaveHDSeed())
        return;
    static const unsigned int nMaxScan = 1000000;
    string strError;
    if (nHDKeySchema == HD_SCHEMA_BIP44)
    {
        unsigned int n = nHDReceiveNext;
        for (unsigned int i = 0; i < nMaxScan; i++, n++)
        {
            CKey key;
            if (!DeriveHDKey(n, key, strError) || !WalletAlreadyHasKey(key.GetPubKey()))
                break;
        }
        if (n != nHDReceiveNext && CWalletDB().WriteHDReceiveNext(n))
        {
            printf("wallet: receive counter moved from %u to %u, past keys already handed out\n",
                   nHDReceiveNext, n);
            nHDReceiveNext = n;
        }
        n = nHDChangeNext;
        for (unsigned int i = 0; i < nMaxScan; i++, n++)
        {
            CKey key;
            if (!DeriveHDChangeKey(n, key, strError) || !WalletAlreadyHasKey(key.GetPubKey()))
                break;
        }
        if (n != nHDChangeNext && CWalletDB().WriteHDChangeNext(n))
        {
            printf("wallet: change counter moved from %u to %u, past keys already used\n",
                   nHDChangeNext, n);
            nHDChangeNext = n;
        }
    }
    else
    {
        unsigned int n = nHDNext;
        for (unsigned int i = 0; i < nMaxScan; i++, n++)
        {
            CKey key;
            if (!DeriveHDKey(n, key, strError) || !WalletAlreadyHasKey(key.GetPubKey()))
                break;
        }
        if (n != nHDNext && CWalletDB().WriteHDNext(n))
            nHDNext = n;
    }
}

// Called by both loaders once every record is read. An encrypted wallet must
// never hold its seed in the clear; one that does was written by the phrase
// install of an older build (it wrote "hdmaster" whatever the wallet's
// encryption). The plaintext copy is taken out of use at once -- nothing
// derives from it, and the chat identity cannot be computed from it, while the
// wallet is locked -- and settled at the next unlock, when the master key is
// there to encrypt it with (RepairPlainSeedAfterUnlock).
void QuarantinePlainSeedInEncryptedWallet()
{
    if (!fWalletEncrypted || (vchHDMaster.empty() && vchHDChainCode.empty()))
        return;
    vchPlainSeedPendingMaster = vchHDMaster;
    vchPlainSeedPendingChainCode = vchHDChainCode;
    SecureClearBytes(vchHDMaster);
    SecureClearBytes(vchHDChainCode);
    strWalletSeedNotice =
        "This encrypted wallet also holds a copy of a recovery seed in plaintext, "
        "left by a phrase install or restore of an older version. That copy is not "
        "used. The next time the wallet is unlocked it is encrypted (if it is the "
        "wallet's seed) or removed (if the encrypted seed is the one in use), and the "
        "address counters are moved past every key already in the wallet. Earlier "
        "copies of this wallet file, and Berkeley DB log files, may still hold the "
        "plaintext seed: if any of those left this machine, move the coins to a new "
        "wallet.";
    printf("LoadWallet: %s\n", strWalletSeedNotice.c_str());
}

// The other half of QuarantinePlainSeedInEncryptedWallet, with the master key
// in hand. Which seed stays:
//   - no encrypted seed: the plaintext one is the wallet's only seed -- it is
//     encrypted and the plaintext records removed;
//   - both, equal: the plaintext copy is redundant -- it is removed;
//   - both, different: an install that wrote the plaintext seed and then
//     finished set the default key to its first receive key. If it did, the
//     plaintext seed is the one the user holds the words for and it replaces
//     the encrypted one; if not, the install failed half way (the wallet was
//     locked) and the encrypted seed stays. Every key either seed derived is a
//     stored key of its own, so no coin depends on the seed that goes.
// Either way the counters are moved past the keys the wallet already holds,
// because the interrupted install had reset them.
void RepairPlainSeedAfterUnlock()
{
    if (vchPlainSeedPendingMaster.empty() && vchPlainSeedPendingChainCode.empty())
        return;
    // cs_main and cs_mapWallet first, as everywhere: under SQLite the bracket
    // below is one transaction on the shared connection, and holding the
    // wallet writers out keeps their writes from joining (and rolling back
    // with) it.
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (vchPlainSeedPendingMaster.size() != 32 || vchPlainSeedPendingChainCode.size() != 32)
        {
            strWalletSeedNotice = "the plaintext seed copy in this encrypted wallet is incomplete; "
                                  "it was left in place untouched -- run /walletstoragecheck";
            printf("wallet: %s\n", strWalletSeedNotice.c_str());
            return;
        }
        bool fHaveCrypted = !vchCryptedHDMaster.empty();
        bool fUsePlain = false;
        if (!fHaveCrypted)
            fUsePlain = true;
        else if (vchPlainSeedPendingMaster == vchHDMaster &&
                 vchPlainSeedPendingChainCode == vchHDChainCode)
            fUsePlain = false;
        else
        {
            CKey key0;
            string strError;
            if (DeriveKeyFromSeed(vchPlainSeedPendingMaster, vchPlainSeedPendingChainCode,
                                  HDReceivePathFor(nHDKeySchema, nHDCoinType, 0), key0, strError) &&
                key0.GetPubKey() == keyUser.GetPubKey())
                fUsePlain = true;
        }

        vector<unsigned char> vchCryptMaster, vchCryptChain;
        if (fUsePlain)
        {
            bool fOk = false;
            CRITICAL_BLOCK(cs_mapKeys)
                fOk = !IsWalletLocked() &&
                      EncryptSecret(vWalletMasterKey, vchPlainSeedPendingMaster,
                                    WalletSecretIV("hdmaster"), vchCryptMaster) &&
                      EncryptSecret(vWalletMasterKey, vchPlainSeedPendingChainCode,
                                    WalletSecretIV("hdchaincode"), vchCryptChain);
            if (!fOk)
            {
                strWalletSeedNotice = "could not encrypt the plaintext seed copy; it was left in place";
                printf("wallet: %s\n", strWalletSeedNotice.c_str());
                return;
            }
        }

        bool fWritten = WalletSQLiteRuntimeBeginTxn();
        if (fWritten && fUsePlain)
            fWritten = CWalletDB().WriteCryptedHDMaster(vchCryptMaster, vchCryptChain);
        if (fWritten)
            fWritten = CWalletDB().EraseHDMaster();
        if (fWritten)
            fWritten = WalletSQLiteRuntimeCommitTxn();
        else
            WalletSQLiteRuntimeRollbackTxn();
        if (!fWritten)
        {
            strWalletSeedNotice = "could not rewrite the seed records; the plaintext copy is still in "
                                  "the wallet file -- check free disk space and unlock again";
            printf("wallet: %s\n", strWalletSeedNotice.c_str());
            return;
        }

        if (fUsePlain)
        {
            CRITICAL_BLOCK(cs_mapKeys)
            {
                vchCryptedHDMaster = vchCryptMaster;
                vchCryptedHDChainCode = vchCryptChain;
            }
            vchHDMaster = vchPlainSeedPendingMaster;
            vchHDChainCode = vchPlainSeedPendingChainCode;
            if (nHDKeySchema == HD_SCHEMA_NONE)
                nHDKeySchema = HD_SCHEMA_LEGACY;
        }
        SecureClearBytes(vchPlainSeedPendingMaster);
        SecureClearBytes(vchPlainSeedPendingChainCode);
        AdvanceHDCountersPastHeldKeys();

        strWalletSeedNotice = !fHaveCrypted
            ? "The plaintext recovery seed in this encrypted wallet was encrypted, and the plaintext records removed."
            : fUsePlain
                ? "This wallet held two recovery seeds: the encrypted one and, in plaintext, the one its last "
                  "phrase install finished with. The latter is now the wallet's seed, encrypted; the plaintext "
                  "records were removed. Keys from the older seed stay in the wallet."
                : "This wallet held a plaintext copy of a recovery seed from a phrase install that did not "
                  "finish. The encrypted seed stays in use, the plaintext copy was removed, and the address "
                  "counters were moved past every key already handed out. Words written down during that "
                  "failed install do not cover this wallet.";
        strWalletSeedNotice += " Earlier copies of this wallet file, and Berkeley DB log files, may still hold "
                               "the plaintext seed: if any of those left this machine, move the coins to a new wallet.";
        printf("wallet: %s\n", strWalletSeedNotice.c_str());
    }
}

// Releases up to 1.2.32 rebuilt the key pool of an encrypted BIP44 wallet
// from the legacy counter -- 0 in such a wallet -- so its pool came to hold
// receive/0..99: the default address and addresses already handed out, to be
// handed out again (a merchant would credit one payer's coins to another).
// Such a pool is recognised by holding a key certainly issued already: the
// default key, receive/0, a key with an address-book label, a key some wallet
// transaction pays, or the same key twice. Which of the other pool keys were
// also handed out cannot be known, so the whole pool goes; the counters move
// past every key the wallet holds and the pool is refilled from there. The
// gap this leaves (at most a pool's worth) is within what a restore scans
// past. Runs at unlock, when the seed is there to derive with.
bool RepairReissuedPool()
{
    bool fRepaired = false;
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (!HaveHDSeed() || nHDKeySchema != HD_SCHEMA_BIP44 || mapKeyPool.empty())
            return false;
        set<vector<unsigned char> > setIssued;
        try { setIssued.insert(keyUser.GetPubKey()); } catch (...) { }
        CKey key0;
        string strError;
        if (DeriveHDKey(0, key0, strError))
            setIssued.insert(key0.GetPubKey());
        CRITICAL_BLOCK(cs_mapKeys)
        {
            for (map<string, string>::const_iterator it = mapAddressBook.begin(); it != mapAddressBook.end(); ++it)
            {
                uint160 hash;
                if (!AddressToHash160(it->first, hash))
                    continue;
                map<uint160, vector<unsigned char> >::const_iterator mi = mapPubKeys.find(hash);
                if (mi != mapPubKeys.end())
                    setIssued.insert(mi->second);
            }
        }
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
            for (size_t i = 0; i < it->second.vout.size(); i++)
            {
                vector<unsigned char> vchPubKey;
                if (ExtractPubKey(it->second.vout[i].scriptPubKey, true, vchPubKey))
                    setIssued.insert(vchPubKey);
            }
        set<vector<unsigned char> > setSeen;
        int nIssuedInPool = 0, nTwice = 0;
        for (map<int64, vector<unsigned char> >::const_iterator it = mapKeyPool.begin(); it != mapKeyPool.end(); ++it)
        {
            if (setIssued.count(it->second))
                nIssuedInPool++;
            if (!setSeen.insert(it->second).second)
                nTwice++;
        }
        if (nIssuedInPool == 0 && nTwice == 0)
            return false;

        if (!ClearKeyPoolRecords(strError))
        {
            printf("RepairReissuedPool() : %s\n", strError.c_str());
            return false;
        }
        AdvanceHDCountersPastHeldKeys();
        TopUpKeyPool();
        fRepaired = true;
        string strNotice = strprintf(
            "The key pool of this wallet held %d address(es) already handed out (left by the encryption of "
            "an older version). The pool was rebuilt from receive index %u; addresses handed out before "
            "will not be handed out again.", nIssuedInPool + nTwice, nHDReceiveNext);
        printf("wallet: %s\n", strNotice.c_str());
        strWalletSeedNotice = strWalletSeedNotice.empty() ? strNotice : strWalletSeedNotice + " " + strNotice;
    }
    return fRepaired;
}

bool WalletHasHDSeed()
{
    return HaveHDSeed() || !vchCryptedHDMaster.empty() || !vchPlainSeedPendingMaster.empty();
}

void RestrictWalletFileModes()
{
#ifndef WIN32
    // New directories are made 0700 (compat.h) and new secret files 0600.
    // Files an older build made keep whatever mode they were given -- SQLite
    // and Berkeley DB create theirs readable by the group or everyone -- so
    // the ones that hold keys are tightened here, on every start.
    string strDir = GetAppDir();
    const char* apszFiles[] = { "wallet.dat", "wallet.sqlite", "wallet.sqlite-wal",
                                "wallet.sqlite-shm", "wallet.sqlite-journal", "nostr.key",
                                // swap secrets and the chat store (with every running
                                // swap's secret), as an older build left them
                                "swaps.log", "btfchat.dat" };
    for (size_t i = 0; i < sizeof(apszFiles) / sizeof(apszFiles[0]); i++)
        if (!RestrictFileToOwner(strDir + "/" + apszFiles[i]))
            printf("RestrictWalletFileModes() : could not make %s owner-only\n", apszFiles[i]);
    // The plaintext originals EncryptWallet leaves as backups.
    DIR* pdir = opendir(strDir.c_str());
    if (pdir)
    {
        struct dirent* pent;
        while ((pent = readdir(pdir)) != NULL)
        {
            string strName = pent->d_name;
            if (strName.find(".before-encrypt.") != string::npos ||
                strName.compare(0, 24, "wallet.sqlite.encrypting") == 0 ||
                strName.compare(0, 18, "wallet.encrypting.") == 0)
                RestrictFileToOwner(strDir + "/" + strName);
        }
        closedir(pdir);
    }
    // Berkeley DB's logs carry every record ever written, plaintext keys of an
    // unencrypted wallet included.
    struct stat st;
    string strLogDir = strDir + "/database";
    if (lstat(strLogDir.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 077))
        chmod(strLogDir.c_str(), S_IRWXU);
    // The data directory itself is the user's to set (another program may be
    // meant to read it), so it is only reported.
    if (stat(strDir.c_str(), &st) == 0 && (st.st_mode & 077))
        printf("RestrictWalletFileModes() : the data directory %s is open to other accounts "
               "(mode %03o); the wallet files in it are owner-only, but consider chmod 700\n",
               strDir.c_str(), (unsigned int)(st.st_mode & 0777));
#endif
}

// strPassphrase is BIP39's optional extra word. It is NOT a lock on the file:
// it goes into the key derivation, so the same twelve words with two different
// passphrases are two different wallets, both valid, neither an error. That is
// the whole point -- the words alone are not enough to spend -- and also the
// whole danger: a wrong passphrase opens an empty wallet instead of refusing.
// Callers pass "" when the user did not ask for one, and every call site says
// so explicitly rather than relying on a default nobody reads.
bool SetHDSeedFromMnemonic(const string& strMnemonic, const string& strPassphrase,
                           string& strErrorRet)
{
    string strNormalized;
    if (!bitflash::BIP39ValidateMnemonic(strMnemonic, strNormalized, strErrorRet))
        return false;

    // An encrypted wallet takes a new seed only while it is unlocked, because
    // the seed is stored encrypted under the wallet's master key. Refused here,
    // before anything is written: an older build went on, cleared the pool,
    // reset the counters and wrote the seed in plaintext, and then reported
    // that nothing had changed.
    if (IsWalletLocked())
    {
        strErrorRet = "the wallet is encrypted and locked; unlock it first (nothing was changed)";
        return false;
    }

    vector<unsigned char> vchSeed;
    bool fSeedOk = bitflash::BIP39MnemonicToSeed(strNormalized, strPassphrase, vchSeed, strErrorRet);
    if (!strNormalized.empty())
        OPENSSL_cleanse(&strNormalized[0], strNormalized.size());
    if (!fSeedOk)
        return false;

    bitflash::BIP32PrivateNode master;
    bool fMasterOk = bitflash::BIP32MasterFromSeed(vchSeed, master, strErrorRet);
    SecureClearBytes(vchSeed);
    if (!fMasterOk)
        return false;

    // The default key: receive/0 on the BIP44 path, derived from the new seed
    // directly, before the wallet's own seed changes.
    CKey key;
    if (!DeriveKeyFromSeed(master.privateKey, master.chainCode,
                           HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH, HD_BIP44_ACCOUNT,
                                       HD_BIP44_CHAIN_RECEIVE, 0),
                           key, strErrorRet))
        return false;

    // cs_main and cs_mapWallet before cs_keyPool (the wallet's order): the
    // install is one SQLite transaction on the shared connection, and the
    // wallet writers (AddToWallet from the message thread, settings) are kept
    // out of it while it is open.
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    CRITICAL_BLOCK(cs_keyPool)
    {
        const bool fEncrypted = IsWalletEncrypted();
        vector<unsigned char> vchCryptMaster, vchCryptChain;
        if (fEncrypted)
        {
            bool fOk = false;
            CRITICAL_BLOCK(cs_mapKeys)
                fOk = !IsWalletLocked() &&
                      EncryptSecret(vWalletMasterKey, master.privateKey,
                                    WalletSecretIV("hdmaster"), vchCryptMaster) &&
                      EncryptSecret(vWalletMasterKey, master.chainCode,
                                    WalletSecretIV("hdchaincode"), vchCryptChain);
            if (!fOk)
            {
                strErrorRet = IsWalletLocked()
                    ? "the wallet is encrypted and locked; unlock it first (nothing was changed)"
                    : "could not encrypt the new seed (nothing was changed)";
                return false;
            }
        }

        // Every check that can fail on its own comes before the first write
        // that changes what the wallet is: the default key is stored first (an
        // extra key in the wallet is harmless if anything below fails).
        if (!AddKeyIfMissing(key))
        {
            strErrorRet = "could not write the default derived key to the wallet (nothing else was changed)";
            return false;
        }

        // Remember which address stops being the default, so it can be named
        // for what it is. Two entries reading "Your Address" -- one covered by
        // the phrase and one not -- is the wrong thing to find at the moment a
        // person has just written twelve words down.
        vector<unsigned char> vchOldDefault = keyUser.GetPubKey();
        vector<unsigned char> vchPubKey = key.GetPubKey();

        // The pool is cleared with the seed, never apart from it: a seed
        // installed beside the old random pool would go on handing out
        // addresses the words cannot reproduce. Under SQLite all of this is
        // one transaction; Berkeley DB writes record by record, in this order
        // (a failure part way leaves an empty pool, which TopUpKeyPool refills).
        //
        // The seed is written encrypted in an encrypted wallet, and any
        // plaintext seed records an older build left there are erased with it.
        if (!WalletSQLiteRuntimeBeginTxn())
        {
            strErrorRet = "could not start a wallet transaction (nothing was changed)";
            return false;
        }
        bool fWritten =
            ClearKeyPoolRecords(strErrorRet) &&
            (fEncrypted
                ? (CWalletDB().WriteCryptedHDMaster(vchCryptMaster, vchCryptChain) &&
                   CWalletDB().EraseHDMaster())
                : CWalletDB().WriteHDMaster(master.privateKey, master.chainCode)) &&
            CWalletDB().WriteHDSchema(HD_SCHEMA_BIP44) &&
            CWalletDB().WriteHDCoinType(HD_BIP44_COIN_TYPE_BITFLASH) &&
            CWalletDB().WriteHDNext(0) &&
            CWalletDB().WriteHDReceiveNext(1) &&
            CWalletDB().WriteHDChangeNext(0) &&
            CWalletDB().WriteDefaultKey(vchPubKey) &&
            SetAddressBookName(PubKeyToAddress(vchPubKey), "Your Address");
        if (!fWritten)
        {
            WalletSQLiteRuntimeRollbackTxn();
            if (strErrorRet.empty())
                strErrorRet = "could not write the seed records to the wallet";
            return false;
        }
        if (!WalletSQLiteRuntimeCommitTxn())
        {
            strErrorRet = "could not commit the seed records to the wallet";
            return false;
        }

        // In memory only once the records are written.
        if (fEncrypted)
        {
            CRITICAL_BLOCK(cs_mapKeys)
            {
                vchCryptedHDMaster    = vchCryptMaster;
                vchCryptedHDChainCode = vchCryptChain;
            }
        }
        SecureClearBytes(vchPlainSeedPendingMaster);
        SecureClearBytes(vchPlainSeedPendingChainCode);
        vchHDMaster    = master.privateKey;
        vchHDChainCode = master.chainCode;
        nHDKeySchema   = HD_SCHEMA_BIP44;
        // Index 0 is the default key, so the pool starts at 1.
        nHDReceiveNext = 1;
        nHDChangeNext  = 0;
        nHDCoinType    = HD_BIP44_COIN_TYPE_BITFLASH;
        nHDNext = 0;

        if (!vchOldDefault.empty() && vchOldDefault != vchPubKey)
            SetAddressBookName(PubKeyToAddress(vchOldDefault),
                               "Your Address (created before the recovery phrase)");
        keyUser = key;
        // In an encrypted wallet the private half lives encrypted only; the
        // loader never keeps it in keyUser either.
        if (fEncrypted)
            keyUser.ForgetPrivKey();

        // The same phrase installed again (a restore of the wallet's own
        // words) finds its keys already here: start past them, so addresses
        // handed out before are not handed out again.
        AdvanceHDCountersPastHeldKeys();
    }
    return true;
}

void TopUpKeyPool()
{
    if (IsWalletLocked())
    {
        printf("TopUpKeyPool() : wallet is encrypted and locked\n");
        return;
    }

    CRITICAL_BLOCK(cs_keyPool)
    {
        while ((int)mapKeyPool.size() < KEYPOOL_SIZE)
        {
            // Indices only ever go up. Reusing one would mean two pool records
            // racing for the same slot after an erase.
            int64 nIndex = 1;
            if (!mapKeyPool.empty())
                nIndex = (--mapKeyPool.end())->first + 1;

            CKey key;
            if (HaveHDSeed())
            {
                // Derived, so a recovery phrase can reproduce this exact key.
                //
                // A derivation that fails stops the top-up. It used to fall
                // back to a random key, which the phrase cannot bring back --
                // and the user learnt that only from debug.log, after being
                // told the phrase was the backup. The failure is nearly always
                // a write that did not happen (disk full), which a random key
                // would not survive either. The pool keeps what it has; a key
                // handed out from it is still covered.
                string strError;
                vector<unsigned char> vchPubKey;
                if (!DeriveNextHDReceiveKey(vchPubKey, strError))
                {
                    printf("TopUpKeyPool() : receive derivation failed (%s); the key pool "
                           "was not topped up\n", strError.c_str());
                    return;
                }
                if (!CWalletDB().WritePool(nIndex, vchPubKey))
                    return;
                mapKeyPool[nIndex] = vchPubKey;
                continue;
            }
            else
            {
                key.MakeNewKey();
            }
            // AddKey writes the private key. Order matters: the key is in
            // wallet.dat before anything can point at it, so a crash between
            // the two writes costs an unused key, never a usable one.
            if (!AddKeyIfMissing(key))
                return;
            vector<unsigned char> vchPubKey = key.GetPubKey();
            if (!CWalletDB().WritePool(nIndex, vchPubKey))
                return;
            mapKeyPool[nIndex] = vchPubKey;
        }
    }
}

vector<unsigned char> GetKeyFromPool()
{
    if (IsWalletLocked())
    {
        printf("GetKeyFromPool() : wallet is encrypted and locked\n");
        return vector<unsigned char>();
    }

    CRITICAL_BLOCK(cs_keyPool)
    {
        TopUpKeyPool();
        if (!mapKeyPool.empty())
        {
            map<int64, vector<unsigned char> >::iterator mi = mapKeyPool.begin();
            int64 nIndex = mi->first;
            vector<unsigned char> vchPubKey = mi->second;
            // The record goes first. A key handed out while its pool record
            // stays on disk is handed out again after a restart.
            if (!CWalletDB().ErasePool(nIndex))
            {
                printf("GetKeyFromPool() : could not erase key-pool record %lld (disk full?); "
                       "no key handed out\n", (long long)nIndex);
                return vector<unsigned char>();
            }
            mapKeyPool.erase(mi);
            // Leave the wallet with a full backup window after each draw too,
            // not only immediately before a draw. If topping up fails, the key
            // already chosen is still safe to use -- its private half was
            // written before it entered the pool.
            TopUpKeyPool();
            return vchPubKey;
        }
    }
    // Nothing in the pool and nothing could be added -- disk full, wallet
    // locked open elsewhere. A wallet with a recovery phrase does not fall
    // back to a random key: the phrase could never bring it back, and the
    // user would not know. Without a phrase, generating on demand is what
    // this code did for its whole life, so it still does.
    if (HaveHDSeed())
    {
        printf("GetKeyFromPool() : pool empty and no key could be derived; no key handed out\n");
        return vector<unsigned char>();
    }
    printf("GetKeyFromPool() : pool empty, generating a key on demand\n");
    try
    {
        return GenerateNewKey();
    }
    catch (const std::exception& e)
    {
        printf("GetKeyFromPool() : failed to generate a key: %s\n", e.what());
        return vector<unsigned char>();
    }
}




//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        //// debug print
        if (LogAcceptsCategory("net")) printf("AddToWallet %s  %s\n", wtxIn.GetHash().ToString().substr(0,6).c_str(), fInsertedNew ? "new" : "update");

        if (!fInsertedNew)
        {
            // Merge
            bool fUpdated = false;
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent)
            {
                wtx.fSpent = wtxIn.fSpent;
                fUpdated = true;
            }
            if (!fUpdated)
                return true;
        }

        // Write to disk
        if (!wtx.WriteToDisk())
            return false;

        // Whatever this transaction spends of ours is spent now. 0.1.0 set
        // the flag only in CommitTransaction, i.e. for sends it built itself;
        // a spend that arrived from outside -- a raw transaction, a copy of
        // this wallet elsewhere -- left the coin listed as available until
        // RescanSpentFlags at the next start, and the next send built on it
        // was refused for missing inputs (Bitcoin 0.3: WalletUpdateSpent).
        foreach(const CTxIn& txin, wtx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi == mapWallet.end() || mi->second.fSpent)
                continue;
            CWalletTx& prev = mi->second;
            if (txin.prevout.n < prev.vout.size() && prev.vout[txin.prevout.n].IsMine())
            {
                prev.fSpent = true;
                prev.WriteToDisk();
                vWalletUpdated.push_back(make_pair(prev.GetHash(), false));
            }
        }

        // Notify UI
        vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
    }

    // Refresh UI
    MainFrameRepaint();
    return true;
}

bool AddToWalletIfMine(const CTransaction& tx, const CBlock* pblock)
{
    // Ours if it pays us, or if it spends something of ours: the second kind
    // is a send, and the wallet has to know its coin went.
    bool fSpendsMine = false;
    if (!tx.IsCoinBase())
        foreach(const CTxIn& txin, tx.vin)
            if (txin.IsMine())
            {
                fSpendsMine = true;
                break;
            }
    if (tx.IsMine() || fSpendsMine || mapWallet.count(tx.GetHash()))
    {
        CWalletTx wtx(tx);
        if (fSpendsMine)
            wtx.fFromMe = true;
        // Get merkle branch if transaction was found in a block
        if (pblock)
            wtx.SetMerkleBranch(pblock);
        return AddToWallet(wtx);
    }
    return true;
}

bool CanScanWalletTransactions(string& strErrorRet)
{
    strErrorRet.clear();

    if (pindexGenesisBlock == NULL || pindexBest == NULL || hashBestChain == 0 || nBestHeight < 0)
    {
        strErrorRet = "The block index is not loaded, so the wallet scan cannot "
                      "prove whether imported or restored keys own coins.";
        return false;
    }

    if (nBestHeight == 0)
    {
        strErrorRet = "The local chain is only at height 0. A wallet scan would "
                      "inspect only the genesis block and could incorrectly "
                      "report zero transactions. Start the node and let it sync "
                      "before scanning. If this happened after copying a data "
                      "directory, keep wallet.dat safe and rebuild or re-download "
                      "the block data instead of trusting the copied database/ "
                      "environment.";
        return false;
    }

    return true;
}

int ScanForWalletTransactions(CBlockIndex* pindexStart)
{
    // Walk the chain looking for transactions that belong to keys this wallet
    // holds now, whatever it held when those blocks arrived.
    //
    // Nothing in this tree could do that. A key added after the fact -- from
    // /importwallet, or from a backup restored onto a node that had since
    // moved on -- was simply invisible: the coins were on the chain, the
    // private key was in wallet.dat, and the balance did not show them,
    // because a transaction only ever entered the wallet at the moment its
    // block arrived over the network.
    //
    // Bitcoin grew the same function for the same reason. It is also what any
    // recovery-phrase feature has to stand on: deriving the keys is the easy
    // half, and without this the other half does not exist.
    int nFound = 0;
    int nScanned = 0;
    CBlockIndex* pindex = pindexStart;
    CRITICAL_BLOCK(cs_main)
    {
        while (pindex)
        {
            CBlock block;
            if (block.ReadFromDisk(pindex, true))
            {
                foreach(CTransaction& tx, block.vtx)
                {
                    // Ask before handing it over: AddToWalletIfMine returns
                    // true for a transaction that is none of our business, so
                    // its return value cannot be counted.
                    if (tx.IsMine())
                    {
                        if (AddToWalletIfMine(tx, &block))
                            nFound++;
                    }
                }
            }
            nScanned++;
            if ((nScanned % 500) == 0)
                printf("ScanForWalletTransactions() : %d blocks scanned, %d transaction(s) found\n",
                       nScanned, nFound);
            pindex = pindex->pnext;
        }
    }
    printf("ScanForWalletTransactions() : %d block(s) scanned, %d transaction(s) added or updated\n",
           nScanned, nFound);
    return nFound;
}

bool EraseFromWallet(uint256 hash)
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        if (mapWallet.erase(hash))
            CWalletDB().EraseTx(hash);
    }
    return true;
}









//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return;

    // Do not allow an orphan to have an unbounded number of inputs.
    // 10,000 inputs is enough for massive legitimate sweeps, but bounds the total
    // memory in mapOrphanTransactionsByPrev to ~10,000 * MAX_ORPHAN_TRANSACTIONS.
    if (tx.vin.size() > 10000)
    {
        if (LogAcceptsCategory("net")) printf("AddOrphanTx() : orphan with %d inputs rejected\n", (int)tx.vin.size());
        return;
    }

    CDataStream* pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
    foreach(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
    LimitOrphanTx(MAX_ORPHAN_TRANSACTIONS);
}

// Orphans cost nothing to create -- a transaction naming a parent that does
// not exist is never validated, just held -- so without a ceiling any peer can
// grow this map until the node runs out of memory. Evict at random rather than
// in map order, so an attacker cannot keep its own orphans resident by
// choosing hashes that sort low.
// Drop orphan blocks at random until we are back under the ceiling.
//
// Random rather than oldest-first, matching LimitOrphanTx below: there is no
// arrival order recorded, and an attacker who knew the eviction rule could aim
// at it. Dropping one costs nothing that matters -- if its parent ever shows
// up, the block is requested again like any other.
//
// Both maps have to be kept in step, and the CBlock itself has to be deleted:
// mapOrphanBlocks owns it.
void AddOrphanBlock(CBlock* pblock)
{
    if (!mapOrphanBlocks.insert(make_pair(pblock->GetHash(), pblock)).second)
        return;
    mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));
    nOrphanBlockBytes += ::GetSerializeSize(*pblock, SER_NETWORK);
}

// By bytes as well as by count: 200 blocks of up to 1 MB each was 200 MB held
// for any peer that cared to send them.
void LimitOrphanBlocks(unsigned int nMaxOrphans)
{
    while (mapOrphanBlocks.size() > nMaxOrphans ||
           (nOrphanBlockBytes > MAX_ORPHAN_BLOCK_BYTES && !mapOrphanBlocks.empty()))
    {
        uint256 randomhash;
        for (int i = 0; i < 4; i++)
            ((uint64*)&randomhash)[i] = GetRand(_UI64_MAX);
        map<uint256, CBlock*>::iterator it = mapOrphanBlocks.lower_bound(randomhash);
        if (it == mapOrphanBlocks.end())
            it = mapOrphanBlocks.begin();

        CBlock* pblock = it->second;
        uint256 hashPrev = pblock->hashPrevBlock;

        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);)
        {
            if (mi->second == pblock)
                mapOrphanBlocksByPrev.erase(mi++);
            else
                ++mi;
        }

        mapOrphanBlocks.erase(it);
        nOrphanBlockBytes -= min(nOrphanBlockBytes, (unsigned int)::GetSerializeSize(*pblock, SER_NETWORK));
        delete pblock;
    }
    if (mapOrphanBlocks.empty())
        nOrphanBlockBytes = 0;
}

void LimitOrphanTx(unsigned int nMaxOrphans)
{
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        uint256 randomhash;
        for (int i = 0; i < 4; i++)
            ((uint64*)&randomhash)[i] = GetRand(_UI64_MAX);
        map<uint256, CDataStream*>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
    }
}

void EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    foreach(const CTxIn& txin, tx.vin)
    {
        for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
             mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);)
        {
            if ((*mi).second == pvMsg)
                mapOrphanTransactionsByPrev.erase(mi++);
            else
                mi++;
        }
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}








//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return true;
        }
    }
    return false;
}

int64 CTxIn::GetDebit() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return prev.vout[prevout.n].nValue;
        }
    }
    return 0;
}

int64 CWalletTx::GetTxTime() const
{
    if (!fTimeReceivedIsTxTime && hashBlock != 0)
    {
        // If we did not receive the transaction directly, we rely on the block's
        // time to figure out when it happened.  We use the median over a range
        // of blocks to try to filter out inaccurate block times.
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (pindex)
                return pindex->GetMedianTime();
        }
    }
    return nTimeReceived;
}






int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, true))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            if (LogAcceptsCategory("net")) printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}



void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        foreach(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        CRITICAL_BLOCK(cs_mapWallet)
        {
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                if (mapWallet.count(hash))
                {
                    tx = mapWallet[hash];
                    foreach(const CMerkleTx& txWalletPrev, mapWallet[hash].vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    if (LogAcceptsCategory("net")) printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                    foreach(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}











bool CTransaction::AcceptTransaction(CTxDB& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return error("AcceptTransaction() : coinbase as individual tx");

    if (!CheckTransaction())
        return error("AcceptTransaction() : CheckTransaction failed");

    // Relay policy, not consensus: what this node is willing to hold and
    // pass on. A block may still carry anything consensus allows.
    if (!IsStandard())
        return error("AcceptTransaction() : non-standard transaction %s", GetHash().ToString().substr(0,6).c_str());

    // Relay policy: only what could go in the next block. A transaction locked
    // for later took a pool slot until then, and no miner would take it (they
    // ask the same question). Not on the way back from a reorganization
    // (fCheckInputs false): those were in a block already.
    if (fCheckInputs && !IsFinalForNextBlock(*this))
        return error("AcceptTransaction() : %s is not final", GetHash().ToString().substr(0,6).c_str());

    // Do we already have it?
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash))
            return false;
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Conflicts with what is already waiting: a replacement (BIP125), or not
    // at all. 0.1.0 let a "newer version" by nSequence replace for free,
    // which anybody holding the keys could repeat forever at no cost to
    // themselves and some to every node; a replacement now has to have been
    // allowed by the original and has to pay for itself.
    set<uint256> setConflicts;
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        for (int i = 0; i < vin.size(); i++)
        {
            map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(vin[i].prevout);
            if (mi != mapNextTx.end() && mi->second.ptx)
                setConflicts.insert(mi->second.ptx->GetHash());
        }
        if (!setConflicts.empty())
        {
            if (!fCheckInputs)
                return false;
            if (setConflicts.size() > MAX_REPLACED_TXS)
                return error("AcceptTransaction() : %s would replace too many transactions", hash.ToString().substr(0,6).c_str());
            foreach(const uint256& h, setConflicts)
            {
                const CTransaction& txOld = mapTransactions[h];
                if (!txOld.SignalsReplacement())
                    return error("AcceptTransaction() : %s conflicts with %s, which did not allow replacement",
                                 hash.ToString().substr(0,6).c_str(), h.ToString().substr(0,6).c_str());
                // Replacing a transaction that others already build on would
                // drop them too; not taken, so a replacement never takes more
                // out of the pool than it names.
                for (unsigned int n = 0; n < txOld.vout.size(); n++)
                    if (mapNextTx.count(COutPoint(h, n)))
                        return error("AcceptTransaction() : %s would replace %s, which has unconfirmed children",
                                     hash.ToString().substr(0,6).c_str(), h.ToString().substr(0,6).c_str());
            }
        }
    }

    // Check against previous transactions
    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    unsigned int nSigOps = GetSigOpCount(RulesV4Active((unsigned int)GetAdjustedTime()));
    if (fCheckInputs && !ConnectInputs(txdb, mapUnused, CDiskTxPos(1,1,1), 0, nFees, false, false, 0, 0, &nSigOps))
    {
        if (pfMissingInputs)
            *pfMissingInputs = true;
        return error("AcceptTransaction() : ConnectInputs failed %s", hash.ToString().substr(0,6).c_str());
    }
    // Relay policy: no one transaction may take more than a fifth of a
    // block's signature operations (Bitcoin's MAX_STANDARD_TX_SIGOPS),
    // redeem scripts included once rules v3 run them. Without it a
    // transaction that can never fit in a block -- six P2SH inputs, each a
    // redeem script of 199 untaken OP_CHECKMULTISIGs, is about 1.5 kB and
    // over the block's 20,000 -- sat in every pool for good, and every block
    // built from that pool was one the network rejects.
    if (nSigOps > MAX_STANDARD_TX_SIGOPS)
        return error("AcceptTransaction() : %s has %u signature operations, over %u",
                     hash.ToString().substr(0,6).c_str(), nSigOps, MAX_STANDARD_TX_SIGOPS);

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        // The pool is bounded. Past the ceiling only a transaction that
        // pays the full base fee gets in, so a flood of free ones cannot
        // grow memory without limit or crowd out the ones that pay.
        if (fCheckInputs && setConflicts.empty() && mapTransactions.size() >= MAX_MEMPOOL_TRANSACTIONS
            && nFees < GetMinFee(false))
            return error("AcceptTransaction() : mempool full (%d), %s pays too little to enter",
                         (int)mapTransactions.size(), hash.ToString().substr(0,6).c_str());
        if (!setConflicts.empty())
        {
            // The money rules, now that this one's fee is known.
            vector<pair<int64, unsigned int> > vOld;
            foreach(const uint256& h, setConflicts)
            {
                map<uint256, CTransaction>::iterator mi = mapTransactions.find(h);
                int64 nOldFee = 0;
                if (mi == mapTransactions.end() || !GetMempoolTxFee(mi->second, txdb, nOldFee))
                    return error("AcceptTransaction() : %s: cannot price what it replaces", hash.ToString().substr(0,6).c_str());
                vOld.push_back(make_pair(nOldFee, (unsigned int)::GetSerializeSize(mi->second, SER_NETWORK)));
            }
            string strWhy;
            if (!ReplacementPaysEnough(nFees, ::GetSerializeSize(*this, SER_NETWORK), vOld, strWhy))
                return error("AcceptTransaction() : %s: %s", hash.ToString().substr(0,6).c_str(), strWhy.c_str());
            foreach(const uint256& h, setConflicts)
            {
                if (LogAcceptsCategory("net")) printf("AcceptTransaction(): %s replaced by %s\n", h.ToString().substr(0,6).c_str(), hash.ToString().substr(0,6).c_str());
                // A copy: RemoveFromMemoryPool erases the entry it is called on.
                CTransaction txOld = mapTransactions[h];
                txOld.RemoveFromMemoryPool();
            }
        }
        AddToMemoryPool();
    }

    // What was replaced is gone for good: out of the wallet too, if it was ours.
    foreach(const uint256& h, setConflicts)
        EraseFromWallet(h);

    if (LogAcceptsCategory("net")) printf("AcceptTransaction(): accepted %s\n", hash.ToString().substr(0,6).c_str());
    return true;
}


// ---- fees ------------------------------------------------------------------

bool GetMempoolTxFee(const CTransaction& tx, CTxDB& txdb, int64& nFeeOut)
{
    nFeeOut = 0;
    if (tx.IsCoinBase())
        return false;
    int64 nValueIn = 0;
    foreach(const CTxIn& txin, tx.vin)
    {
        CTransaction txPrev;
        map<uint256, CTransaction>::iterator mi = mapTransactions.find(txin.prevout.hash);
        if (mi != mapTransactions.end())
            txPrev = mi->second;
        else if (!txdb.ReadDiskTx(txin.prevout.hash, txPrev))
            return false;
        if (txin.prevout.n >= txPrev.vout.size())
            return false;
        nValueIn += txPrev.vout[txin.prevout.n].nValue;
    }
    nFeeOut = nValueIn - tx.GetValueOut();
    return nFeeOut >= 0;
}

void MempoolByFeeRate(CTxDB& txdb, vector<CTransaction*>& vOut)
{
    // (fee per 1000 bytes, hash) -- the hash only to keep equal rates in a
    // fixed order, so a rebuilt block template does not reshuffle.
    vector<pair<pair<int64, uint256>, CTransaction*> > v;
    v.reserve(mapTransactions.size());
    for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi)
    {
        int64 nFee = 0;
        unsigned int nSize = ::GetSerializeSize(mi->second, SER_NETWORK);
        int64 nRate = GetMempoolTxFee(mi->second, txdb, nFee) && nSize ? nFee * 1000 / nSize : 0;
        v.push_back(make_pair(make_pair(-nRate, mi->first), &mi->second));
    }
    sort(v.begin(), v.end());
    vOut.clear();
    for (size_t i = 0; i < v.size(); i++)
        vOut.push_back(v[i].second);
}

bool ReplacementPaysEnough(int64 nNewFee, unsigned int nNewSize,
                           const vector<pair<int64, unsigned int> >& vOld, string& whyOut)
{
    int64 nOldFees = 0;
    for (size_t i = 0; i < vOld.size(); i++)
    {
        nOldFees += vOld[i].first;
        // Per byte, compared without division: new/newsize > old/oldsize.
        // In big numbers: a fee near MAX_MONEY times a size past about
        // 4,400 bytes is beyond int64.
        if (CBigNum(nNewFee) * CBigNum(vOld[i].second) <= CBigNum(vOld[i].first) * CBigNum(nNewSize))
        {
            whyOut = "the replacement pays no more per byte than what it replaces";
            return false;
        }
    }
    int64 nNeed = nOldFees + FeeForSize(MIN_RELAY_FEE_PER_KB, nNewSize);
    if (nNewFee < nNeed)
    {
        whyOut = strprintf("the replacement pays %s, it needs at least %s (what it replaces plus the relay fee)",
                           FormatMoney(nNewFee).c_str(), FormatMoney(nNeed).c_str());
        return false;
    }
    return true;
}

int64 EstimateNextBlockFeePerKB()
{
    // What the next block takes: the first 100 transactions under 10 KB free
    // (GetMinFee's discount), and up to the block size limit in all, in the
    // order the miners now use. If everything waiting fits, the minimum does;
    // if not, a little over the rate where the block would cut off.
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        CTxDB txdb("r");
        vector<CTransaction*> v;
        MempoolByFeeRate(txdb, v);
        unsigned int nSize = 0;
        for (size_t i = 0; i < v.size(); i++)
        {
            unsigned int n = ::GetSerializeSize(*v[i], SER_NETWORK);
            if (nSize + n >= MAX_BLOCK_SIZE - MINER_COINBASE_ROOM || i >= 100)
            {
                int64 nFee = 0;
                int64 nRate = GetMempoolTxFee(*v[i], txdb, nFee) && n ? nFee * 1000 / n : 0;
                return max(nRate + nRate / 10 + 1, (int64)CENT);
            }
            nSize += n;
        }
    }
    return 0;
}

bool CTransaction::AddToMemoryPool()
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptTransaction to properly check the transaction first.
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = GetHash();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTransaction::RemoveFromMemoryPool()
{
    // Remove transaction from memory pool
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        // Only the spends that are this transaction's. Called for every
        // transaction of a block, most of them never in this pool, it erased
        // whatever spend of the same outpoint the pool held: the conflicting
        // transaction stayed in mapTransactions with nothing in mapNextTx to
        // say what it spent.
        map<uint256, CTransaction>::iterator mt = mapTransactions.find(GetHash());
        if (mt != mapTransactions.end())
        {
            foreach(const CTxIn& txin, vin)
            {
                map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(txin.prevout);
                if (mi != mapNextTx.end() && mi->second.ptx == &mt->second)
                    mapNextTx.erase(mi);
            }
            mapTransactions.erase(mt);
        }
        nTransactionsUpdated++;
    }
    return true;
}

void RemoveConflictsFromMemoryPool(const CTransaction& tx)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = tx.GetHash();
        vector<uint256> vQueue;
        foreach(const CTxIn& txin, tx.vin)
        {
            map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(txin.prevout);
            if (mi != mapNextTx.end() && mi->second.ptx && mi->second.ptx->GetHash() != hash)
                vQueue.push_back(mi->second.ptx->GetHash());
        }
        // What spends a conflict's outputs goes with it: those outputs will
        // never exist. Breadth first, each child found before its parent goes.
        set<uint256> setSeen;
        for (unsigned int i = 0; i < vQueue.size(); i++)
        {
            if (!setSeen.insert(vQueue[i]).second)
                continue;
            map<uint256, CTransaction>::iterator mt = mapTransactions.find(vQueue[i]);
            if (mt == mapTransactions.end())
                continue;
            for (unsigned int n = 0; n < mt->second.vout.size(); n++)
            {
                map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(COutPoint(vQueue[i], n));
                if (mi != mapNextTx.end() && mi->second.ptx)
                    vQueue.push_back(mi->second.ptx->GetHash());
            }
            if (LogAcceptsCategory("net"))
                printf("RemoveConflictsFromMemoryPool(): %s conflicts with %s in a block, removed\n",
                       vQueue[i].ToString().substr(0,6).c_str(), hash.ToString().substr(0,6).c_str());
            // A copy: RemoveFromMemoryPool erases the entry it is called on.
            CTransaction txOld = mt->second;
            txOld.RemoveFromMemoryPool();
        }
    }
}






int CMerkleTx::GetDepthInMainChain() const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    return pindexBest->nHeight - pindex->nHeight + 1;
}


bool CWalletTx::IsFinalForWallet() const
{
    if (GetDepthInMainChain() > 0)
        return true;
    return IsFinalForNextBlock(*this);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY+20) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptTransaction(txdb, false);
    }
    else
    {
        return CTransaction::AcceptTransaction(txdb, fCheckInputs);
    }
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        foreach(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptTransaction(txdb, fCheckInputs);
            }
        }
        if (!IsCoinBase())
            return AcceptTransaction(txdb, fCheckInputs);
    }
    return true;
}

int RescanSpentFlags()
{
    // Believe the chain, not the wallet, about what has already been spent.
    //
    // fSpent lives in wallet.dat and is written when this node spends
    // something. A wallet.dat that was restored from backup, or copied and
    // used on another machine, carries whatever that flag was at the moment
    // the copy was taken -- so it can say "unspent" about coins the chain
    // shows as gone. The balance then reads high, and the error only surfaces
    // when a send is attempted against coins that no longer exist.
    //
    // Issue #47 is about this shape of problem and #40 reports living through
    // it. Bitcoin fixed the same thing in 53d508072.
    //
    // One direction only. Marking spent when the chain says spent is safe;
    // clearing the flag because the chain has not caught up yet would offer
    // up coins that are already on their way out.
    CTxDB txdb("r");
    int nCorrected = 0;
    int nExamined = 0;
    int nAlreadySpent = 0, nNotIndexed = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            nExamined++;
            if (wtx.fSpent)
                { nAlreadySpent++; continue; }

            CTxIndex txindex;
            if (!txdb.ReadTxIndex(wtx.GetHash(), txindex))
                { nNotIndexed++; continue; }

            // fSpent is one flag for the whole transaction, not one per
            // output -- CommitTransactionSpent already marks the entire
            // previous transaction when it spends any part of it, so matching
            // that here keeps the two consistent.
            bool fSeenSpent = false;
            for (int i = 0; i < (int)txindex.vSpent.size() && i < (int)wtx.vout.size(); i++)
                if (!txindex.vSpent[i].IsNull() && wtx.vout[i].IsMine())
                    fSeenSpent = true;

            if (fSeenSpent)
            {
                wtx.fSpent = true;
                wtx.WriteToDisk();
                nCorrected++;
                printf("RescanSpentFlags() : %s was spent on chain but the wallet did not know\n",
                       wtx.GetHash().ToString().substr(0,10).c_str());
            }
        }
    }
    // Always say it ran. A check that reports only when it finds something is
    // indistinguishable from a check that never executed, and this codebase has
    // paid for that confusion more than once.
    printf("RescanSpentFlags() : examined %d, already-spent %d, not-indexed %d, corrected %d\n",
           nExamined, nAlreadySpent, nNotIndexed, nCorrected);
    if (nCorrected)
        printf("RescanSpentFlags() : this wallet was behind the chain about what it had already spent, "
               "which is what a restored backup looks like\n");
    return nCorrected;
}


void ReacceptWalletTransactions()
{
    // Reaccept any txes of ours that aren't already in a block
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (!wtx.IsCoinBase() && !txdb.ContainsTx(wtx.GetHash()))
                wtx.AcceptWalletTransaction(txdb, false);
        }
    }
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    foreach(const CMerkleTx& tx, vtxPrev)
    {
        if (!tx.IsCoinBase())
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
        }
    }
    if (!IsCoinBase())
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            if (LogAcceptsCategory("net")) printf("Relaying wtx %s\n", hash.ToString().substr(0,6).c_str());
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
        }
    }
}

void RelayWalletTransactions()
{
    static int64 nLastTime;
    if (GetTime() - nLastTime < 10 * 60)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    if (LogAcceptsCategory("net")) printf("RelayWalletTransactions()\n");
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        foreach(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction(txdb);
        }
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex* pblockindex, bool fReadTransactions)
{
    return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos, fReadTransactions);
}

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

int64 CBlock::GetBlockValue(int nHeight, int64 nFees) const
{
    int64 nSubsidy = 50 * COIN;

    // Halve on the height of this block, never on nBestHeight. The subsidy a
    // block is allowed to pay is a property of that block; deriving it from
    // the validating node's own tip makes the answer depend on how far that
    // node happens to have synced, so two nodes at different heights would
    // disagree about the same block across a halving boundary.
    //
    // No subsidy after 64 halvings (BIP42). Shifting a 64-bit value by 64 or
    // more is undefined behaviour; on x86 the count wraps, and at height
    // 13,440,000 the subsidy would have jumped back to 50. Below that height
    // nHeight / 210000 is at most 63 and this returns exactly what it always
    // did, so the check needs no switch: it only decides heights no chain has
    // reached (the rules-v5 self-test runs every height below it).
    int nHalvings = nHeight / 210000;
    if (nHalvings >= 64)
        return nFees;
    nSubsidy >>= nHalvings;

    return nSubsidy + nFees;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast)
{
    // Bitflash: 2-minute target block time with a fast retarget (every 30
    // blocks, ~1h) so difficulty tracks the small, volatile CPU hashrate and
    // brief disconnections no longer spawn divergent forks.
    const unsigned int nTargetSpacing  = 2 * 60;                    // 2 minutes
    const unsigned int nInterval       = 30;                        // retarget window
    const unsigned int nTargetTimespan = nInterval * nTargetSpacing; // 3600s

    // Genesis block
    if (pindexLast == NULL)
        return bnProofOfWorkLimit.GetCompact();

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
        return pindexLast->nBits;

    // Go back by what we want to be 14 days worth of blocks
    // Go back the whole window from rules v2 on. 0.1.0 walked nInterval-1
    // blocks, so the timespan it measured was one interval short of the
    // one it divided by, and the block on the boundary was counted by
    // neither window -- the gap the time-warp attack drives through.
    // Bitcoin never fixed this on mainnet; here the window is 30 blocks,
    // which makes it a proportionally larger lever, so it is fixed.
    //
    // The walk stops at the first block, which has no parent. At the first
    // retarget (height 29) a v2 window is one block longer than the chain, and
    // this asserted: a branch from genesis with v2 timestamps, which anyone can
    // send to a node without the newest checkpoint, aborted the process at its
    // 30th block. No live chain has a v2-timestamped block 29, so stopping at
    // genesis changes no block's validity; everywhere else the walk ends where
    // it always did.
    int nWindow = RulesV2Active(pindexLast->nTime) ? nInterval : nInterval-1;
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst->pprev && i < nWindow; i++)
        pindexFirst = pindexFirst->pprev;
    // Cannot happen any more; if it ever does, no block meets this (AcceptBlock
    // refuses a required nBits of 0) rather than the process stopping.
    if (pindexFirst == NULL)
        return 0;

    // Limit adjustment step
    unsigned int nActualTimespan = pindexLast->nTime - pindexFirst->nTime;
    if (LogAcceptsCategory("net")) printf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    /// debug print
    if (LogAcceptsCategory("net")) { printf("\n\n\nGetNextWorkRequired RETARGET *****\n"); printf("nTargetTimespan = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan); printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str()); printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str()); }

    return bnNew.GetCompact();
}

// Rules v5. GetNextWorkRequired measures a window as the closing block's time
// minus the first block's, in unsigned arithmetic. Only the median of the
// last eleven blocks bounds a block's time from below, and the first block
// is thirty back, so the closing block may legally be timed before it: the
// difference then wraps to about 4.29e9, is clamped to four windows, and the
// target becomes four times easier where Bitcoin's signed arithmetic makes it
// four times harder. Changing the arithmetic would change which nBits is
// valid in both directions (a hard fork). Refusing the closing block that is
// timed before the first block (as BIP94 bounds its timestamps) only removes
// blocks, so it is a soft fork, and the subtraction can then never wrap.
//
// The window is GetNextWorkRequired's, mirrored: thirty blocks, the closing
// one at a height of 29 mod 30, and from rules v2 (by the closing block's own
// time) the whole window, nInterval-1 blocks before. The walk stops at the
// genesis block instead of running off it.
static const int RETARGET_INTERVAL = 30;

static const CBlockIndex* RetargetWindowFirst(const CBlockIndex* pindexPrev, unsigned int nTime)
{
    if (!pindexPrev || (pindexPrev->nHeight + 2) % RETARGET_INTERVAL != 0)
        return NULL;    // the block after pindexPrev closes no window
    int nWindow = RulesV2Active(nTime) ? RETARGET_INTERVAL : RETARGET_INTERVAL - 1;
    const CBlockIndex* pindexFirst = pindexPrev;
    for (int i = 0; pindexFirst->pprev && i < nWindow - 1; i++)
        pindexFirst = pindexFirst->pprev;
    return pindexFirst;
}

bool RetargetTimeAllowed(const CBlockIndex* pindexPrev, unsigned int nTime)
{
    if (!RulesV5Active(pindexPrev))
        return true;
    const CBlockIndex* pindexFirst = RetargetWindowFirst(pindexPrev, nTime);
    return !pindexFirst || nTime >= pindexFirst->nTime;
}

int64 BlockTimeFloor(const CBlockIndex* pindexPrev)
{
    if (!pindexPrev)
        return 0;
    int64 nFloor = pindexPrev->GetMedianTimePast() + 1;
    if (RulesV5Active(pindexPrev))
    {
        // The window's first block for a block timed at the floor. The window
        // size depends on rules v2 by the closing block's time, and v5 is
        // never on before v2, so it is the full window at any time from here.
        const CBlockIndex* pindexFirst = RetargetWindowFirst(pindexPrev, (unsigned int)nFloor);
        if (pindexFirst && (int64)pindexFirst->nTime > nFloor)
            nFloor = pindexFirst->nTime;
    }
    return nFloor;
}









bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        foreach(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            txdb.UpdateTxIndex(prevout.hash, txindex);
        }
    }

    // Remove transaction from index
    if (!txdb.EraseTxIndex(*this))
        return error("DisconnectInputs() : EraseTxPos failed");

    return true;
}


// The block a transaction index entry points into. The index keeps where a
// transaction sits on disk, not its height, and BIP68 needs the height.
//
// A cache over mapBlockIndex, rebuilt from scratch on any miss: a block
// index entry is also deleted (a block that fails to connect), so neither
// the count of entries nor any pointer kept from before can say the cache is
// current. A hit is believed only if that entry is still in mapBlockIndex,
// at that position. Misses come from blocks added since the last rebuild,
// about one rebuild per new block. Under cs_main.
static CBlockIndex* BlockIndexAtDiskPos(unsigned int nFile, unsigned int nBlockPos)
{
    static map<pair<unsigned int, unsigned int>, uint256> mapByPos;
    pair<unsigned int, unsigned int> key(nFile, nBlockPos);
    for (int nPass = 0; nPass < 2; nPass++)
    {
        map<pair<unsigned int, unsigned int>, uint256>::iterator it = mapByPos.find(key);
        if (it != mapByPos.end())
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(it->second);
            if (mi != mapBlockIndex.end() && mi->second->nFile == nFile && mi->second->nBlockPos == nBlockPos)
                return mi->second;
        }
        if (nPass == 1)
            break;
        mapByPos.clear();
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
            mapByPos[make_pair(mi->second->nFile, mi->second->nBlockPos)] = mi->first;
    }
    return NULL;
}

// BIP68 for one input: is the relative lock its nSequence states over by the
// block after pindexPrev? txindex is where the coin it spends sits. fUnmined:
// the coin is not in a block yet, and counts as mined in that next block.
bool SequenceLockPasses(const CTxIn& txin, const CTxIndex& txindex, bool fUnmined,
                               const CBlockIndex* pindexPrev)
{
    if (txin.nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return true;
    if (!pindexPrev)
        return false;
    int nNextHeight = pindexPrev->nHeight + 1;
    int nCoinHeight = nNextHeight;
    int64 nCoinTime = pindexPrev->GetMedianTimePast();
    if (!fUnmined)
    {
        CBlockIndex* pindexCoin = BlockIndexAtDiskPos(txindex.pos.nFile, txindex.pos.nBlockPos);
        if (!pindexCoin)
            return error("SequenceLockPasses() : no block at %u:%u", txindex.pos.nFile, txindex.pos.nBlockPos);
        nCoinHeight = pindexCoin->nHeight;
        // Time is measured from the median time past of the block before the
        // coin's, as in Bitcoin: the coin's own block time is its miner's say.
        const CBlockIndex* pindexBase = pindexCoin->pprev ? pindexCoin->pprev : pindexCoin;
        nCoinTime = pindexBase->GetMedianTimePast();
    }
    int64 nValue = txin.nSequence & SEQUENCE_LOCKTIME_MASK;
    if (txin.nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG)
        return pindexPrev->GetMedianTimePast() >= nCoinTime + (nValue << SEQUENCE_LOCKTIME_GRANULARITY);
    return nNextHeight >= nCoinHeight + nValue;
}

// Rules v5: were the outputs of the transaction at txindex counted under
// rules v4 when their block was checked (OP_CHECKSIGFROMSTACK included)?
// fUnmined: not in a block yet, so it will be in the next one or later, which
// is under v4 whenever v5 asks. A coin whose block cannot be found is taken
// as not counted: counting it is the side that never lets more through.
static bool CoinCountedUnderRulesV4(const CTxIndex& txindex, bool fUnmined)
{
    if (fUnmined)
        return true;
    const CBlockIndex* pindexCoin = BlockIndexAtDiskPos(txindex.pos.nFile, txindex.pos.nBlockPos);
    return pindexCoin && RulesV4Active(pindexCoin->nTime);
}

bool CTransaction::ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee, unsigned int nBlockTime,
                                 unsigned int* pnP2SHSigOps, const CBlockIndex* pindexPrev, bool* pfLocalError)
{
    // A failure that is this node's (a read or write that did not work), not
    // the transaction's: the block it is in must not be marked failed.
    struct LocalFailure
    {
        static bool Set(bool* pf, bool fRet) { if (pf) *pf = true; return fRet; }
    };
    unsigned int nRulesTime = nBlockTime ? nBlockTime : (unsigned int)GetAdjustedTime();
    bool fStrictSigs = RulesV2Active(nRulesTime);
    bool fRulesV3 = RulesV3Active(nRulesTime);
    bool fRulesV4 = RulesV4Active(nRulesTime);
    // The block this one would follow: the block's parent when connecting a
    // block, the tip for the mempool and the miner.
    if (!pindexPrev)
        pindexPrev = pindexBest;
    // Rules v5 follow the parent, not the block's own time (consensus.h).
    bool fRulesV5 = RulesV5Active(pindexPrev);
    // Take over previous transactions' spent pointers
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            // Read txindex
            CTxIndex txindex;
            bool fFound = true;
            if (fMiner && mapTestPool.count(prevout.hash))
            {
                // Get txindex from current proposed changes
                txindex = mapTestPool[prevout.hash];
            }
            else
            {
                // Read txindex from txdb
                fFound = txdb.ReadTxIndex(prevout.hash, txindex);
            }
            if (!fFound && fBlock && !txdb.LastReadNotFound())
                return LocalFailure::Set(pfLocalError, error("ConnectInputs() : %s could not read the index entry of prev tx %s",
                                                             GetHash().ToString().substr(0,6).c_str(), prevout.hash.ToString().substr(0,6).c_str()));
            if (!fFound && (fBlock || fMiner))
                return fMiner ? false : error("ConnectInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());

            // Read txPrev
            CTransaction txPrev;
            if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
            {
                // Get prev tx from single transactions in memory
                CRITICAL_BLOCK(cs_mapTransactions)
                {
                    if (!mapTransactions.count(prevout.hash))
                        return error("ConnectInputs() : %s mapTransactions prev not found %s", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());
                    txPrev = mapTransactions[prevout.hash];
                }
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else
            {
                // Get prev tx from disk
                if (!txPrev.ReadFromDisk(txindex.pos))
                    return LocalFailure::Set(pfLocalError, error("ConnectInputs() : %s ReadFromDisk prev tx %s failed",
                                                                 GetHash().ToString().substr(0,6).c_str(), prevout.hash.ToString().substr(0,6).c_str()));
            }

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return error("ConnectInputs() : %s prevout.n out of range %d %d %d", GetHash().ToString().substr(0,6).c_str(), prevout.n, (int)txPrev.vout.size(), (int)txindex.vSpent.size());

            // If prev is coinbase, check that it's matured -- on the chain
            // this transaction is being connected to. It walked back from
            // pindexBest, which during a reorganization is still the old tip:
            // a block on the new branch spending a coinbase of that branch too
            // early was found on neither, and passed on a node that reached
            // it by reorganizing while every other node refused it. Outside a
            // reorganization pindexPrev is pindexBest, as before.
            if (txPrev.IsCoinBase())
            {
                // Rules v5: nor in the block that creates it. The walk below
                // starts at the parent, so depth 0 was never looked at: the
                // coinbase is indexed first in ConnectBlock, a later
                // transaction of the same block found it, and its coins left
                // the block as ordinary outputs, spendable at once. Only a
                // block being connected can hold its own coinbase; the pool
                // never holds one.
                if (fRulesV5 && fBlock && txindex.pos.nFile == posThisTx.nFile &&
                    txindex.pos.nBlockPos == posThisTx.nBlockPos)
                    return error("ConnectInputs() : %s spends the coinbase of its own block",
                                 GetHash().ToString().substr(0,6).c_str());
                int nPrevHeight = pindexPrev ? pindexPrev->nHeight : nBestHeight;
                for (const CBlockIndex* pindex = pindexPrev; pindex && nPrevHeight - pindex->nHeight < COINBASE_MATURITY-1; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend coinbase at depth %d", nPrevHeight - pindex->nHeight);
            }

            // Rules v4 (BIP68): in a version 2 transaction, an input's
            // nSequence can say "not until this long after the coin was mined".
            if (fRulesV4 && (unsigned int)nVersion >= 2 && !SequenceLockPasses(vin[i], txindex,
                                                                       !fFound || txindex.pos == CDiskTxPos(1,1,1), pindexPrev))
                return fMiner ? false : error("ConnectInputs() : %s input %d is under a relative lock",
                                              GetHash().ToString().substr(0,6).c_str(), i);

            // Verify signature. On the memory-pool path only (neither a block
            // nor the miner), relay policy also refuses the upgrade hooks of
            // rules v4 (SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4). Blocks are
            // checked with no policy at all: what is valid does not change.
            const unsigned int nPolicyFlags = (!fBlock && !fMiner) ? SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4 : 0;
            if (!VerifySignature(txPrev, *this, i, 0, fStrictSigs, fRulesV3, fRulesV4, nPolicyFlags))
                return error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,6).c_str());

            // Rules v3 runs the redeem script, so its signature operations cost
            // what any other does and count against the block's cap. Before,
            // a P2SH scriptSig's last push was data and cost nothing to check.
            if (fRulesV3 && pnP2SHSigOps && txPrev.vout[prevout.n].scriptPubKey.IsPayToScriptHash())
                *pnP2SHSigOps += GetP2SHSigOpCount(vin[i].scriptSig, fRulesV4);

            // Rules v5: an output's script is counted once, by the block that
            // makes it, under that block's rules. Before rules v4
            // OP_CHECKSIGFROMSTACK counted nothing, so a bare output made then
            // could carry a verification per byte that no block ever paid
            // for. Its CSFS operations count now, when it is spent. Outputs
            // made under rules v4 were counted when made and are not counted
            // twice; a P2SH output's script carries no operations of its own.
            if (fRulesV5 && pnP2SHSigOps)
            {
                const CScript& scriptPrev = txPrev.vout[prevout.n].scriptPubKey;
                unsigned int nCsfs = scriptPrev.GetSigOpCount(true) - scriptPrev.GetSigOpCount(false);
                if (nCsfs && !CoinCountedUnderRulesV4(txindex, !fFound || txindex.pos == CDiskTxPos(1,1,1)))
                    *pnP2SHSigOps += nCsfs;
            }

            // Check for conflicts
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,6).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock)
                txdb.UpdateTxIndex(prevout.hash, txindex);
            else if (fMiner)
                mapTestPool[prevout.hash] = txindex;

            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return error("ConnectInputs() : txin values out of range");
        }

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,6).c_str());
        if (nTxFee < nMinFee)
            return false;
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return error("ConnectInputs() : nFees out of range");
    }

    if (fBlock)
    {
        // Add transaction to disk index
        if (!txdb.AddTxIndex(*this, posThisTx, nHeight))
            return LocalFailure::Set(pfLocalError, error("ConnectInputs() : AddTxPos failed"));
    }
    else if (fMiner)
    {
        // Add transaction to test pool
        mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1,1,1), vout.size());
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mapTransactions.count(prevout.hash))
                return false;
            CTransaction& txPrev = mapTransactions[prevout.hash];

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}




bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        txdb.WriteBlockIndex(blockindexPrev);
    }

    return true;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool* pfLocalError)
{
    if (pfLocalError)
        *pfLocalError = false;
    //// issue here: it doesn't know the version
    unsigned int nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    // CheckBlock already capped the sigops it can see in the scripts; under
    // rules v3 the redeem scripts run too, and only here are they known.
    unsigned int nSigOps = 0;
    foreach(CTransaction& tx, vtx)
        nSigOps += tx.GetSigOpCount(RulesV4Active(nTime));
    foreach(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        // Rules v2 (BIP30): a transaction whose txid is already in the index
        // with outputs still unspent cannot be connected -- AddTxPos would
        // replace the earlier entry and its unspent outputs would be gone.
        // With the height in every coinbase (above) this cannot happen going
        // forward; the check is what stops it if something ever does.
        if (RulesV2Active(nTime))
        {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(tx.GetHash(), txindexOld))
                foreach(const CDiskTxPos& pos, txindexOld.vSpent)
                    if (pos.IsNull())
                        return error("ConnectBlock() : tx %s already exists unspent (BIP30)",
                                     tx.GetHash().ToString().substr(0,10).c_str());
        }

        if (!tx.ConnectInputs(txdb, mapUnused, posThisTx, pindex->nHeight, nFees, true, false, 0, nTime, &nSigOps,
                              pindex->pprev, pfLocalError))
            return false;
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return error("ConnectBlock() : too many signature operations once redeem scripts are counted");
    }

    if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
        return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        txdb.WriteBlockIndex(blockindexPrev);
    }

    // Watch for transactions paying to me
    foreach(CTransaction& tx, vtx)
        AddToWalletIfMine(tx, this);

    return true;
}



bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    LogPrint("net", "*** REORGANIZE ***\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    foreach(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock failed");

        // Queue memory transactions to resurrect
        foreach(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for connect failed");
        bool fLocalError = false;
        if (!block.ConnectBlock(txdb, pindex, &fLocalError))
        {
            txdb.TxnAbort();
            // This node could not read or write something: nothing is known
            // about the block. Nothing is marked, and the next block on this
            // branch tries again.
            if (fLocalError)
                return error("Reorganize() : ConnectBlock failed on a local error, will retry");
            // The block breaks a rule: mark it and everything built on it, on
            // this branch or any other. 0.1.0 deleted the index entries from
            // here to pindexNew, and any other child of a deleted block -- a
            // side branch that forked at or after it -- kept a pprev into
            // freed memory, which the next block on it, or the next
            // reorganization, walked.
            EraseFailedFromDiskIndex(txdb, MarkBlockFailed(pindex));
            return error("Reorganize() : ConnectBlock failed");
        }

        // Queue memory transactions to delete
        foreach(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Commit now because resurrecting could take some time
    txdb.TxnCommit();

    // Disconnect shorter branch
    foreach(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    foreach(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    foreach(CTransaction& tx, vResurrect)
        tx.AcceptTransaction(txdb, false);

    // Delete redundant memory transactions that are in the connected branch,
    // and whatever spends the same coins as they do, resurrected or not.
    foreach(CTransaction& tx, vDelete)
    {
        tx.RemoveFromMemoryPool();
        RemoveConflictsFromMemoryPool(tx);
    }

    return true;
}


bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,14).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    SetChainWork(pindexNew);

    CTxDB txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));

    // New best: more accumulated work than the chain this node is on, not
    // more blocks (see GetBlockWork in main.h).
    if (IsBetterChain(pindexNew, pindexBest))
    {
        if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
        {
            pindexGenesisBlock = pindexNew;
            txdb.WriteHashBestChain(hash);
        }
        else if (hashPrevBlock == hashBestChain)
        {
            // Adding to current best branch
            bool fLocalError = false;
            bool fConnected = ConnectBlock(txdb, pindexNew, &fLocalError);
            if (fConnected && !txdb.WriteHashBestChain(hash))
            {
                fConnected = false;
                fLocalError = true;   // a write that failed says nothing about the block
            }
            if (!fConnected)
            {
                txdb.TxnAbort();
                if (fLocalError)
                {
                    // As 0.1.0 did: forget the block, so the next copy a peer
                    // sends is connected again. It was indexed a moment ago
                    // and nothing can be built on it yet, so deleting the
                    // entry leaves no pointer to it.
                    pindexNew->EraseBlockFromDisk();
                    mapBlockIndex.erase(hash);
                    delete pindexNew;
                    return error("AddToBlockIndex() : ConnectBlock failed on a local error, the block can come again");
                }
                // The block breaks a rule. Kept in the index, marked, like a
                // block that fails in Reorganize: nothing is accepted on top
                // of it, and a copy sent again is "already have" instead of
                // connected again. Its record was in the transaction just
                // aborted, so a restart forgets it.
                MarkBlockFailed(pindexNew);
                return error("AddToBlockIndex() : ConnectBlock failed");
            }
            txdb.TxnCommit();
            pindexNew->pprev->pnext = pindexNew;

            // Delete redundant memory transactions, and what conflicts with them
            foreach(CTransaction& tx, vtx)
            {
                tx.RemoveFromMemoryPool();
                RemoveConflictsFromMemoryPool(tx);
            }
        }
        else
        {
            // New best branch
            if (!Reorganize(txdb, pindexNew))
            {
                txdb.TxnAbort();
                // Not marked (a local error, or a block before it that could
                // not be read): it stays a candidate and the next block on
                // this branch tries again. Its own record went with the
                // aborted transaction; write it again, or a later successful
                // reorganization would leave the disk index naming a block it
                // has no record of.
                if (!pindexNew->fFailed)
                    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
                return error("AddToBlockIndex() : Reorganize failed");
            }
        }

        // New best link
        hashBestChain = hash;
        pindexBest = pindexNew;
        nBestHeight = pindexBest->nHeight;
        nTransactionsUpdated++;
        printf("AddToBlockIndex: new best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0,14).c_str(), nBestHeight,
               ChainWorkToString(pindexBest->nChainWork).c_str());
    }

    txdb.TxnCommit();
    txdb.Close();

    // Relay wallet transactions that haven't gotten in yet
    if (pindexNew == pindexBest)
        RelayWalletTransactions();

    MainFrameRepaint();
    return true;
}




// Failure with a misbehavior score attached, for the peer that sent it.
static bool DoS(int* pnDoS, int nScore, bool fRet)
{
    if (pnDoS)
        *pnDoS = nScore;
    return fRet;
}

#ifdef BITFLASH_FUZZ
// Fuzz builds only (obj-fuzz, -DBITFLASH_FUZZ; never a node or a release).
// fuzz-p2p-payload sets it so blocks get past the RandomX comparison, which no
// fuzzer can satisfy, to the checks behind it. Every other harness leaves it
// false.
bool fFuzzSkipPoW = false;
#endif
// Relay policy, never validity. The block message handler sets the gate around
// one ProcessBlock call for a block from an inbound peer that has to draw on
// the shared inbound budget (PeerNeedsBlockBudget). CheckBlock takes the token
// right before the proof-of-work hash, after every cheap check, and clears the
// gate. With no token the block is not looked at: false with no score and
// nothing recorded about it, so it can be fetched again. Only the thread that
// set it sees it, and nothing else ever sets it.
static thread_local bool tl_fPoWBudgetGate = false;
static thread_local bool tl_fPoWBudgetRefused = false;

bool CBlock::CheckBlock(int* pnDoS, bool fCheckTime) const
{
    if (pnDoS)
        *pnDoS = 0;
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (!CheckSizeLimits())
        return DoS(pnDoS, 100, error("CheckBlock() : size limits failed"));

    // Check timestamp
    if (fCheckTime && nTime > GetAdjustedTime() + 2 * 60 * 60)
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(pnDoS, 100, error("CheckBlock() : first tx is not coinbase"));
    for (int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(pnDoS, 100, error("CheckBlock() : more than one coinbase"));

    // Check transactions
    foreach(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return DoS(pnDoS, 100, error("CheckBlock() : CheckTransaction failed"));

    // Cap the work a block can demand. MAX_SIZE bounds the bytes, not the cost:
    // every signature operation is an elliptic-curve verification, and at this
    // chain's difficulty a block packed with them is affordable to mine and
    // expensive for everyone else to reject.
    unsigned int nSigOps = 0;
    foreach(const CTransaction& tx, vtx)
        nSigOps += tx.GetSigOpCount(RulesV4Active(nTime));
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(pnDoS, 100, error("CheckBlock() : out-of-bounds signature operation count"));

    // Reject blocks carrying the same transaction twice (CVE-2012-2459).
    //
    // BuildMerkleTree duplicates the last hash when a level has an odd width,
    // so appending a copy of the trailing transaction(s) yields a block with
    // an identical merkle root -- and therefore an identical block hash -- to
    // a legitimate one. The forgery fails validation, the hash gets recorded
    // as bad, and the real block is then refused because it hashes the same.
    set<uint256> setTxHashes;
    foreach(const CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();
        if (setTxHashes.count(hashTx))
            return DoS(pnDoS, 100, error("CheckBlock() : duplicate transaction in block"));
        setTxHashes.insert(hashTx);
    }

    // Check proof of work matches claimed amount (memory-hard RandomX PoW).
    // A zero or negative target (the sign bit of the compact form) is no
    // target: getuint256() drops the sign, so the hash was compared with its
    // magnitude. AcceptBlock's exact nBits match already refused such a block,
    // since GetCompact never makes one; here it is refused before anything
    // else looks at it, orphans included.
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return DoS(pnDoS, 100, error("CheckBlock() : nBits is not a positive target"));
    if (bnTarget > bnProofOfWorkLimit)
        return DoS(pnDoS, 100, error("CheckBlock() : nBits below minimum work"));
    if (tl_fPoWBudgetGate)
    {
        tl_fPoWBudgetGate = false;
        if (!InboundBlockBudgetTake())
        {
            tl_fPoWBudgetRefused = true;
            return false;
        }
    }
#ifdef BITFLASH_FUZZ
    if (!fFuzzSkipPoW)
#endif
    if (GetPoWHash() > CBigNum().SetCompact(nBits).getuint256())
        return DoS(pnDoS, 50, error("CheckBlock() : RandomX proof-of-work does not match nBits"));

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return DoS(pnDoS, 100, error("CheckBlock() : hashMerkleRoot mismatch"));

    return true;
}

bool RulesV3LockedIn()
{
    // A block's rules follow its own timestamp, which only has to be above
    // its parent's median time past. So for the first few blocks after the
    // switch time a block may still be dated before it, and run the old
    // rules. Once the tip's median time past has reached the switch, every
    // valid next block is dated after it.
    unsigned int t = RulesV3Time();
    return t != 0 && pindexBest && (unsigned int)pindexBest->GetMedianTimePast() >= t;
}

bool IsFinalForNextBlock(const CTransaction& tx)
{
    if (!pindexBest || !RulesV3Active((unsigned int)GetAdjustedTime()))
        return tx.IsFinal();
    return IsFinalAfter(tx, pindexBest);
}

bool IsFinalAfter(const CTransaction& tx, const CBlockIndex* pindexPrev)
{
    return tx.IsFinalAt(pindexPrev->nHeight + 1, pindexPrev->GetMedianTimePast(), RulesV5Active(pindexPrev));
}

bool IsFinalForBlock(const CTransaction& tx, const CBlockIndex* pindexPrev, unsigned int nBlockTime)
{
    // v3 by the template's own time, as AcceptBlock; v5's unsigned nLockTime
    // follows pindexPrev's median time past (IsFinalAfter), which no template
    // time moves.
    if (!pindexPrev || !RulesV3Active(nBlockTime))
        return tx.IsFinal();
    return IsFinalAfter(tx, pindexPrev);
}

int RuleSetAt(unsigned int nTime)
{
    return (RulesV2Active(nTime) ? 1 : 0) | (RulesV3Active(nTime) ? 2 : 0) | (RulesV4Active(nTime) ? 4 : 0);
}

// Orphan blocks (their parent is not here) only have to meet their own nBits
// to be held, so one at the floor cost next to nothing to make. Once this node
// is synced, an orphan whose target is more than ORPHAN_WORK_SLACK times
// easier than the tip's is not held, with more room the later it is dated than
// the tip (a stale tip while the network's difficulty fell). The allowance is
// generous on purpose -- four times per two hours, faster than the clamped
// retarget eases an honest chain -- and it is not a bound anyone relies on: a
// refused orphan only costs a re-request, because the request that continues
// the sync is sent either way (ProcessBlock), and its parent's blocks then
// arrive in order and are judged as any other. Not used while syncing, nor
// while the best chain lacks the newest checkpoint: the tip is then whatever
// the node was handed, and must not be the yardstick.
static const int64 ORPHAN_EASE_SECONDS = 2 * 3600;

bool OrphanTargetWithinReach(unsigned int nBits, unsigned int nTime, unsigned int nRefBits, unsigned int nRefTime)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnEasiest;
    bnEasiest.SetCompact(nRefBits);
    if (bnTarget <= 0 || bnEasiest <= 0)
        return false;
    bnEasiest *= ORPHAN_WORK_SLACK;
    for (int64 n = ((int64)nTime - (int64)nRefTime) / ORPHAN_EASE_SECONDS; n > 0 && bnEasiest < bnProofOfWorkLimit; n--)
        bnEasiest *= 4;
    if (bnEasiest > bnProofOfWorkLimit)
        bnEasiest = bnProofOfWorkLimit;
    return bnTarget <= bnEasiest;
}

bool OrphanBlockWorthKeeping(const CBlock& block)
{
    if (pindexBest == NULL || pindexBest->fOffCheckpoint || IsInitialBlockDownload())
        return true;
    if (!mapCheckpoints.empty())
    {
        map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(mapCheckpoints.rbegin()->second);
        if (mi == mapBlockIndex.end() || !(*mi).second->IsInMainChain())
            return true;
    }
    return OrphanTargetWithinReach(block.nBits, block.nTime, pindexBest->nBits, pindexBest->nTime);
}

bool CBlock::AcceptBlock(int* pnDoS)
{
    if (pnDoS)
        *pnDoS = 0;
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return error("AcceptBlock() : prev block not found");
    CBlockIndex* pindexPrev = (*mi).second;

    // Nothing on top of a block that failed to connect (MarkBlockFailed).
    if (pindexPrev->fFailed)
        return error("AcceptBlock() : block %s builds on a block that failed to connect",
                     hash.ToString().substr(0,14).c_str());

    // Checkpoints (see main.h): not on a chain that contradicts one, and not
    // a fork from below the newest one this node has.
    const char* pszCheckpoint = NULL;
    int nCheckpointScore = 0;
    if (!CheckpointsAllow(pindexPrev, hash, &pszCheckpoint, &nCheckpointScore))
        return DoS(pnDoS, nCheckpointScore, error("AcceptBlock() : block %s at height %d %s",
                                     hash.ToString().substr(0,14).c_str(), pindexPrev->nHeight + 1, pszCheckpoint));

    // Check timestamp against prev
    if (nTime <= pindexPrev->GetMedianTimePast())
        return error("AcceptBlock() : block's timestamp is too early");

    // Rules v5: a block that closes a retarget window is not timed before the
    // window's first block (see RetargetTimeAllowed). Scored like the
    // finality rule below: a miner on an older release can produce one.
    if (!RetargetTimeAllowed(pindexPrev, nTime))
        return DoS(pnDoS, 10, error("AcceptBlock() : block at height %d closes a retarget window and is timed before its first block",
                                    pindexPrev->nHeight + 1));

    // Check proof of work
    unsigned int nBitsRequired = GetNextWorkRequired(pindexPrev);
    if (nBitsRequired == 0 || nBits != nBitsRequired)
        return DoS(pnDoS, 100, error("AcceptBlock() : incorrect proof of work"));

    // Rules v2: the coinbase scriptSig starts with the block height (BIP34).
    // Two coinbases paying the same key with the same value were otherwise
    // byte-identical, so the second had the txid of the first and its index
    // entry overwrote it. Both miners in this tree have written the height
    // first since before the switch; from here on it is required.
    if (RulesV2Active(nTime))
    {
        CScript expect = CScript() << (pindexPrev->nHeight + 1);
        const CScript& cb = vtx[0].vin[0].scriptSig;
        if (cb.size() < expect.size() || !std::equal(expect.begin(), expect.end(), cb.begin()))
            return DoS(pnDoS, 100, error("AcceptBlock() : coinbase does not start with height %d", pindexPrev->nHeight + 1));
    }

    // Rules v3: every transaction in the block is final at its height and at
    // the median time past of the block before it (BIP113 -- not this block's
    // own time, which its miner picks). See CTransaction::IsFinalAt.
    // From rules v5, nLockTime is read unsigned (IsFinalAfter).
    if (RulesV3Active(nTime))
    {
        int nHeight = pindexPrev->nHeight + 1;
        foreach(const CTransaction& tx, vtx)
            if (!IsFinalAfter(tx, pindexPrev))
                return DoS(pnDoS, 10, error("AcceptBlock() : transaction %s is not final at height %d",
                                            tx.GetHash().ToString().substr(0,10).c_str(), nHeight));
    }

    // Side branches (consensus review 5, DoS review M9) are stored whatever
    // their work, deliberately. A block that does not become the best chain is
    // written to disk after only the checks above; its transactions are
    // checked when its branch takes over. A rule refusing such blocks by work
    // was tried and taken out: without headers it judges a block by the work
    // before it, never by what follows, so it could refuse a block of a branch
    // that later carries more work and leave this node on the lighter chain
    // for good -- a reorganization limit by another name, and there is none.
    // The real fix is headers-first sync: take a branch's headers, and
    // download a body only once its header chain has more work than ours.
    // Until then the disk a weak branch can take is bounded by elapsed time:
    // no branch runs its difficulty down faster than its timestamps allow,
    // and rules v5 removes the unsigned-timespan wrap that lets a window ease
    // when a boundary block's time goes backwards (consensus review 2).
    if (LogAcceptsCategory("net") && pindexPrev != pindexBest)
        printf("AcceptBlock() : block %s at height %d does not build on the tip, nBits %08x (tip %08x), stored\n",
               hash.ToString().substr(0,14).c_str(), pindexPrev->nHeight + 1, nBits, pindexBest ? pindexBest->nBits : 0);

    // Write block to history file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!WriteToDisk(!fClient, nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    if (hashBestChain == hash && !IsInitialBlockDownload())
        RelayInventory(CInv(MSG_BLOCK, hash));

    // // Add atoms to user reviews for coins created
    // vector<unsigned char> vchPubKey;
    // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
    // {
    //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
    //     vector<unsigned short> vAtoms(1, nAtom);
    //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
    // }

    return true;
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock, int* pnDoS)
{
    if (pnDoS)
        *pnDoS = 0;
    // Counted before any check, so the ratio below is against everything that
    // arrived rather than everything that was any good.
    if (pfrom)
        nBlocksReceived++;

    // ProcessBlock owns pblock on every path: it is kept as an orphan or
    // deleted here. The two duplicate returns used to leave it to the caller,
    // which the network path never freed (every repeated block leaked) while
    // the pool freed it on any refusal, so a block refused by CheckBlock or
    // AcceptBlock was freed twice. fuzz-p2p-payload found the leak.
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
    {
        int nHeight = mapBlockIndex[hash]->nHeight;
        delete pblock;
        return error("ProcessBlock() : already have block %d %s", nHeight, hash.ToString().substr(0,14).c_str());
    }
    if (mapOrphanBlocks.count(hash))
    {
        delete pblock;
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,14).c_str());
    }

    // An orphan only has to meet its own nBits, so one at the floor costs next
    // to nothing; once synced, held only when its target is within reach of
    // the tip's (OrphanBlockWorthKeeping). Before CheckBlock: that is a
    // RandomX hash, this is not. Not held is not ignored: the request that
    // continues the sync (below, for a held orphan) goes out all the same, so
    // a real chain this filter misjudges still arrives, in order.
    if (!mapBlockIndex.count(pblock->hashPrevBlock) && !OrphanBlockWorthKeeping(*pblock))
    {
        uint256 hashOrphanRoot = GetOrphanRoot(pblock);
        delete pblock;
        if (pfrom)
            pfrom->PushGetBlocks(pindexBest, hashOrphanRoot);
        return error("ProcessBlock() : orphan block %s has a target far easier than the tip's, not held",
                     hash.ToString().substr(0,14).c_str());
    }

    // Preliminary checks
    if (!pblock->CheckBlock(pnDoS))
    {
        delete pblock;
        return error("ProcessBlock() : CheckBlock FAILED");
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,14).c_str());
        if (pfrom)
            nBlocksWithoutParent++;
        AddOrphanBlock(pblock);

        // Read what we need out of pblock before trimming: eviction picks at
        // random and is perfectly entitled to pick the block just inserted,
        // which would leave the GetOrphanRoot call below reading freed memory.
        uint256 hashOrphanRoot = GetOrphanRoot(pblock);

        LimitOrphanBlocks(MAX_ORPHAN_BLOCKS);

        // Ask this guy to fill in what we're missing
        if (pfrom)
            pfrom->PushGetBlocks(pindexBest, hashOrphanRoot);
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock(pnDoS))
    {
        delete pblock;
        return error("ProcessBlock() : AcceptBlock FAILED");
    }
    delete pblock;

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            if (mapOrphanBlocks.erase(pblockOrphan->GetHash()))
                nOrphanBlockBytes -= min(nOrphanBlockBytes, (unsigned int)::GetSerializeSize(*pblockOrphan, SER_NETWORK));
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");
    return true;
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL)
        return true;
    // Peers' heights are what they announced at handshake, a floor on where
    // they are now; so this only ever under-reports how far behind we are.
    // Three blocks of slack for ordinary relay lag. No peer heights, no
    // opinion: a node alone is not "downloading", and refusing to mine on a
    // chain nobody claims to be ahead of would only wedge a stalled network.
    int nNet = GetPeerMedianHeight();
    if (nNet < 0)
        return false;
    return nBestHeight < nNet - 3;
}








template<typename Stream>
bool ScanMessageStart(Stream& s)
{
    // Scan ahead to the next pchMessageStart, which should normally be immediately
    // at the file pointer.  Leaves file pointer at end of pchMessageStart.
    s.clear(0);
    short prevmask = s.exceptions(0);
    const char* p = BEGIN(pchMessageStart);
    try
    {
        loop
        {
            char c;
            s.read(&c, 1);
            if (s.fail())
            {
                s.clear(0);
                s.exceptions(prevmask);
                return false;
            }
            if (*p != c)
                p = BEGIN(pchMessageStart);
            if (*p == c)
            {
                if (++p == END(pchMessageStart))
                {
                    s.clear(0);
                    s.exceptions(prevmask);
                    return true;
                }
            }
        }
    }
    catch (...)
    {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
    }
}

// The data directory's name, and the one thing that keeps btfchat's wallet,
// chain and keys away from the miner's by default.
//
// A compile-time choice rather than a variable somebody sets at startup: with a
// variable, any code that touched GetAppDir() before it was set would silently
// open the wrong directory -- and "the wrong directory" here means the chat app
// reading the wallet that holds the coins. There is no initialization order to
// get wrong this way.
//
// Both binaries still honour /datadir=PATH, which overrides this entirely.
#ifdef BITFLASH_CHAT_APP
static const char* APPDIR_WIN   = "Bitflash-chat";
static const char* APPDIR_POSIX = ".bitflash-chat";
#else
static const char* APPDIR_WIN   = "Bitflash";
static const char* APPDIR_POSIX = ".bitflash";
#endif

string GetAppDir()
{
    string strDir;
    if (!strSetDataDir.empty())
    {
        strDir = strSetDataDir;
    }
#ifdef _WIN32
    else if (getenv("APPDATA"))
    {
        strDir = strprintf("%s\\%s", getenv("APPDATA"), APPDIR_WIN);
    }
    else if (getenv("USERPROFILE"))
    {
        string strAppData = strprintf("%s\\Application Data", getenv("USERPROFILE"));
        static bool fMkdirDone;
        if (!fMkdirDone)
        {
            fMkdirDone = true;
            _mkdir(strAppData.c_str());
        }
        strDir = strprintf("%s\\%s", strAppData.c_str(), APPDIR_WIN);
    }
#else
    else if (getenv("HOME"))
    {
        strDir = strprintf("%s/%s", getenv("HOME"), APPDIR_POSIX);
    }
#endif
    else
    {
        return ".";
    }
    static string strCreatedBaseDir;
    if (strCreatedBaseDir != strDir)
    {
        _mkdir(strDir.c_str());
        strCreatedBaseDir = strDir;
    }
    if (IsTestNet())
    {
        strDir += "/testnet";
        static string strCreatedTestnetDir;
        if (strCreatedTestnetDir != strDir)
        {
            _mkdir(strDir.c_str());
            strCreatedTestnetDir = strDir;
        }
    }
    return strDir;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("%s/blk%04d.dat", GetAppDir().c_str(), nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    // Initialize the RandomX PoW before touching any block (both the genesis
    // and verification depend on it).
    if (!RandomXInit())
        return error("LoadBlockIndex() : RandomXInit failed");

    //
    // Load block index
    //
    CTxDB txdb("cr");
    if (!txdb.LoadBlockIndex())
        return false;
    txdb.Close();

    // Repair a bad tip found during verification.
    //
    // This has to happen after the handle above is closed. CTxDB::LoadBlockIndex
    // walks the index with a cursor it never closes, so it is still holding read
    // locks -- a write transaction opened alongside it waits on them forever.
    // Measured, not guessed: the node came up, printed the diagnosis, and hung
    // there with nothing in any log.
    if (pindexBadChainFork)
    {
        CBlockIndex* pindexFork = pindexBadChainFork;
        CBlockIndex* pindexFirstBad = pindexBadChainFirst;
        pindexBadChainFork = NULL;
        pindexBadChainFirst = NULL;

        printf("LoadBlockIndex() : *** moving best chain back to height %d, discarding %d block(s)\n",
               pindexFork->nHeight, nBestHeight - pindexFork->nHeight);

        vector<CBlockIndex*> vDisconnect;
        for (CBlockIndex* pindex = pindexBest; pindex && pindex != pindexFork; pindex = pindex->pprev)
            vDisconnect.push_back(pindex);

        bool fRolledBack = false;
        try
        {
            CTxDB txdbWrite;
            txdbWrite.TxnBegin();
            foreach(CBlockIndex* pindex, vDisconnect)
            {
                CBlock block;
                if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
                    throw runtime_error("ReadFromDisk for disconnect failed");
                if (!block.DisconnectBlock(txdbWrite, pindex))
                    throw runtime_error("DisconnectBlock failed");
            }
            if (!txdbWrite.WriteHashBestChain(pindexFork->GetBlockHash()))
                throw runtime_error("WriteHashBestChain failed");
            txdbWrite.TxnCommit();
            txdbWrite.Close();
            fRolledBack = true;
        }
        catch (const std::exception& e)
        {
            printf("LoadBlockIndex() : rollback failed: %s\n", e.what());
        }
        catch (...)
        {
            printf("LoadBlockIndex() : rollback failed\n");
        }

        if (fRolledBack)
        {
            foreach(CBlockIndex* pindex, vDisconnect)
                if (pindex->pprev)
                    pindex->pprev->pnext = NULL;

            pindexBest    = pindexFork;
            hashBestChain = pindexBest->GetBlockHash();
            nBestHeight   = pindexBest->nHeight;
            printf("LoadBlockIndex() : now at height %d, will re-download from peers\n", nBestHeight);

            // The blocks that failed the check, and all on top of them, are
            // still in the index with all their work: mark them, or the next
            // block a peer sends on top makes that branch the best again and
            // Reorganize connects them without the check they just failed.
            // Their records come off the disk index, so the next start does
            // not read them back unmarked.
            if (pindexFirstBad)
            {
                try
                {
                    CTxDB txdbErase;
                    EraseFailedFromDiskIndex(txdbErase, MarkBlockFailed(pindexFirstBad));
                    txdbErase.Close();
                }
                catch (const std::exception& e)
                {
                    printf("LoadBlockIndex() : could not take the failed blocks off the disk index: %s\n", e.what());
                }
            }
        }
        else
        {
            // Start anyway. The operator needs a running node to read this from.
            printf("LoadBlockIndex() : *** still on the bad chain at height %d -- back up the data directory and report this\n",
                   nBestHeight);
        }
    }

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;


        // Genesis Block:
        // GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        // hashMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        // txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
        // txNew.vout[0].nValue       = 5000000000
        // txNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG
        // block.nVersion = 1
        // block.nTime    = 1231006505
        // block.nBits    = 0x1d00ffff
        // block.nNonce   = 2083236893
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e

        // Bitflash genesis block -- own header (fair launch, 2026 stable relaunch)
        CBlock block = BuildGenesisBlock();

        // If the nonce has not been found yet, mine the genesis once (RandomX)
        // and print the values to be hardcoded in the constants above.
        if (block.GetHash() != hashGenesisBlock)
        {
            printf("Mining Bitflash genesis block (RandomX)...\n");
            uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
            while (block.GetPoWHash() > hashTarget)
            {
                if ((block.nNonce & 0x3ff) == 0)
                    printf("nonce %u\r", block.nNonce);
                block.nNonce++;
                if (block.nNonce == 0)
                {
                    printf("nonce overflow, incrementing nTime\n");
                    block.nTime++;
                }
            }
            printf("\n=== BITFLASH GENESIS (RandomX) FOUND ===\n");
            printf("nTime   = %u\n", block.nTime);
            printf("nNonce  = %u  (0x%08x)\n", block.nNonce, block.nNonce);
            printf("powhash = %s\n", block.GetPoWHash().ToString().c_str());
            printf("hash    = %s\n", block.GetHash().ToString().c_str());
            printf("merkle  = %s\n", block.hashMerkleRoot.ToString().c_str());
            printf("========================================\n");
        }

        // Asserts only apply once the genesis values are hardcoded
        if (hashGenesisBlock != uint256(0))
        {
            assert(block.hashMerkleRoot == hashGenesisMerkleRoot);
            assert(block.GetHash() == hashGenesisBlock);
        }

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(!fClient, nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");
    }

    return true;
}



void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex, true);
        printf("%d (%u,%u) %s  %s  tx %d",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().substr(0,14).c_str(),
            DateTimeStr(block.nTime).c_str(),
            (int)block.vtx.size());

        CRITICAL_BLOCK(cs_mapWallet)
        {
            if (mapWallet.count(block.vtx[0].GetHash()))
            {
                CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
                printf("    mine:  %d  %d  %lld", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
            }
        }
        printf("\n");


        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:        return mapTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:     return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
    case MSG_REVIEW:    return true;
    case MSG_PRODUCT:   return mapProducts.count(inv.hash);
    case MSG_CHATREC:   return ChatRelayAlreadyHave(inv);
    }
    // Don't know what it is, just say we already got one
    return true;
}







// Serve queued getdata entries from the front until the send buffer is full.
// One getdata of a single block hash repeated hundreds of thousands of times
// used to be answered in full, all at once and under cs_main, into a send
// buffer nothing bounded: one message was enough to run the node out of
// memory. Now what does not fit waits in vRecvGetData and goes out as the peer
// reads (Bitcoin's ProcessGetData). Message thread, under cs_vRecv.
static void ProcessGetData(CNode* pfrom)
{
    CRITICAL_BLOCK(cs_main)
    {
        while (!pfrom->vRecvGetData.empty() && !fShutdown)
        {
            unsigned int nQueued;
            CRITICAL_BLOCK(pfrom->cs_vSend)
                nQueued = pfrom->vSend.size();
            if (nQueued >= SendBufferSize())
                break;

            const CInv inv = pfrom->vRecvGetData.front();
            pfrom->vRecvGetData.pop_front();
            if (LogAcceptsCategory("net")) printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    //// could optimize this to send header straight from blockindex for client
                    CBlock block;
                    block.ReadFromDisk((*mi).second, !pfrom->fClient);
                    pfrom->PushMessage("block", block);
                    pfrom->hashBatchLastBlock = inv.hash;
                }
            }
            else if (inv.type == MSG_CHATREC)
            {
                // From the chat store, not the relay memory: records live for a
                // day, the relay memory for fifteen minutes.
                ChatRelayServeGetData(pfrom, inv);
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }
        }

        // A batch of blocks that did not end at our tip ends with an inv of
        // the tip. A 1.2.x node does not have it, or holds it as an orphan,
        // and either way sends getblocks from where it now is: that is how a
        // getblocks answer cut at MAX_GETBLOCKS_RESULTS continues. This used
        // to be sent only after one block (the 500th of the last answer), and
        // a sync whose connection was replaced mid-round could lose it for
        // good: the old node asks nothing on its own. Every batch end comes
        // after the peer has the batch, so the getblocks it answers with is a
        // new question (a repeat is dropped by the peer itself). A peer in
        // step asks for our tip, which is the last block, and gets no inv.
        // The batch is over when the queue is empty, which may be in a later
        // call than the one that served its last block.
        if (pfrom->vRecvGetData.empty() && pfrom->hashBatchLastBlock != 0)
        {
            if (pfrom->hashBatchLastBlock != hashBestChain)
            {
                vector<CInv> vTip(1, CInv(MSG_BLOCK, hashBestChain));
                pfrom->PushMessage("inv", vTip);
            }
            pfrom->hashBatchLastBlock = 0;
        }
    }
}

// Answer a getblocks: up to MAX_GETBLOCKS_RESULTS block hashes after the first
// locator entry on our main chain, stopping at hashStop. It used to walk to the
// tip whatever the distance -- the whole chain, as one inv, for every request.
// Under cs_main.
static void ServeGetBlocks(CNode* pfrom, CBlockLocator& locator, const uint256& hashStop)
{
    // Find the first block the caller has in the main chain
    CBlockIndex* pindex = locator.GetBlockIndex();

    // Send the rest of the chain
    if (pindex)
        pindex = pindex->pnext;
    int nLimit = MAX_GETBLOCKS_RESULTS;
    if (LogAcceptsCategory("net")) printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,14).c_str(), nLimit);
    for (; pindex; pindex = pindex->pnext)
    {
        if (pindex->GetBlockHash() == hashStop)
        {
            if (LogAcceptsCategory("net")) printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,14).c_str());
            break;
        }

        // Bypass setInventoryKnown in case an inventory message got lost
        CRITICAL_BLOCK(pfrom->cs_inventory)
        {
            CInv inv(MSG_BLOCK, pindex->GetBlockHash());
            // returns true if wasn't already contained in the set
            if (pfrom->setInventoryKnown2.insert(inv).second)
            {
                pfrom->setInventoryKnown.erase(inv);
                pfrom->vInventoryToSend.push_back(inv);
            }
        }
        if (--nLimit <= 0)
        {
            // The peer comes back for the rest after the tip inv that ends
            // the batch it fetches (ProcessGetData).
            if (LogAcceptsCategory("net")) printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,14).c_str());
            break;
        }
    }
}

// Peer exchange. Nothing here is taken on trust: BtfPexAccept checks every
// descriptor's signature against the key its .btf address decodes to, and drops
// the rest. One message per connection: a node sends its list once, right after
// the version, and nothing more is needed from it.
static bool ProcessBtfPeers(CNode* pfrom, CDataStream& vRecv)
{
    if (pfrom->nLastPexRecv != 0)
    {
        LogPrint("net", "btfpeers: ignoring, %s already sent its list\n",
                 pfrom->addr.ToString().c_str());
        vRecv.clear();
        return true;
    }
    pfrom->nLastPexRecv = GetTime();

    vector<string> vDesc;
    vRecv >> vDesc;
    int nKept = BtfPexAccept(vDesc);
    LogPrint("net", "btfpeers: kept %d of %zu descriptor(s) from %s\n",
             nKept, vDesc.size(), pfrom->addr.ToString().c_str());
    return true;
}

// A getblocks that waited for room in the send buffer. Under cs_main.
static void ServePendingGetBlocks(CNode* pfrom)
{
    if (!pfrom->fGetBlocksPending || pfrom->fDisconnect)
        return;
    unsigned int nQueued;
    CRITICAL_BLOCK(pfrom->cs_vSend)
        nQueued = pfrom->vSend.size();
    if (nQueued >= SendBufferSize())
        return;
    CBlockLocator locator(pfrom->vGetBlocksHave);
    uint256 hashStop = pfrom->hashGetBlocksStop;
    pfrom->fGetBlocksPending = false;
    vector<uint256>().swap(pfrom->vGetBlocksHave);
    ServeGetBlocks(pfrom, locator, hashStop);
}

bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    pfrom->fRecvMorePending = false;

    // A peer dropped for misbehavior (or evicted) is not listened to any more.
    // Its messages used to be processed in full for as long as it was kept
    // for its send buffer to drain -- a minute, for a peer that kept sending.
    // A peer that is only on its way out (it closed, it timed out) is no
    // longer read from, but what it already sent is still taken: those are
    // often the blocks we asked it for.
    if (pfrom->fDropWithoutDrain)
    {
        vRecv.clear();
        pfrom->vRecvGetData.clear();
        return true;
    }

    // What an earlier getdata asked for and did not fit yet.
    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    if (vRecv.empty())
        return true;
    LogPrint("net", "ProcessMessages(%d bytes)\n", (int)vRecv.size());
    int nMessages = 0;
    const int64 nPassStart = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (x) data
    //

    loop
    {
        // Dropped by something it sent this pass: stop listening now.
        if (pfrom->fDropWithoutDrain)
        {
            vRecv.clear();
            pfrom->vRecvGetData.clear();
            return true;
        }
        // This peer's share of the pass is used up; the rest waits for the
        // next one, after every other peer has had its turn.
        if (nMessages >= MAX_MESSAGES_PER_PASS ||
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count() - nPassStart > MAX_PEER_PASS_MILLIS)
        {
            pfrom->fRecvMorePending = !vRecv.empty();
            break;
        }

        // Scan for message start
        // 20 bytes until the peer's version message, 24 (with checksum) from
        // 102 on -- see CMessageHeader.
        unsigned int nHeaderSize = CMessageHeader::SizeOnWire(vRecv.GetVersion());
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vRecv.end() - pstart < nHeaderSize)
        {
            if (vRecv.size() > nHeaderSize)
            {
                if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", (int)(pstart - vRecv.begin()));
        vRecv.erase(vRecv.begin(), pstart);

        // Read the header from a copy first. The old path consumed the header,
        // noticed the payload was incomplete, inserted the header back at the
        // front of the receive buffer, then slept inside the shared message
        // thread. A peer could announce a large payload and drip bytes forever,
        // making every pass pay for an O(n) insert and a 100 ms stall.
        CMessageHeader hdr;
        CDataStream vHeader(vRecv.begin(), vRecv.begin() + nHeaderSize,
                            vRecv.nType, vRecv.nVersion);
        vHeader >> hdr;
        if (!hdr.IsValid())
        {
            if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            if (hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_SIZE)
                pfrom->fDisconnect = true;
            pfrom->Misbehaving(10);
            pfrom->nIncompleteMessageStart = 0;
            vRecv.ignore(nHeaderSize);
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        unsigned int nPayloadAvailable = vRecv.size() - nHeaderSize;
        if (nMessageSize > nPayloadAvailable)
        {
            if (pfrom->nIncompleteMessageStart == 0 ||
                pfrom->nIncompleteMessageSize != nMessageSize ||
                pfrom->strIncompleteMessageCommand != strCommand)
            {
                pfrom->nIncompleteMessageStart = GetTime();
                pfrom->nIncompleteMessageSize = nMessageSize;
                pfrom->strIncompleteMessageCommand = strCommand;
            }
            else if (GetTime() - pfrom->nIncompleteMessageStart >
                     BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS)
            {
                LogPrint("net",
                         "disconnecting %s: incomplete %s message, %u of %u bytes after %d seconds\n",
                         pfrom->addr.ToString().c_str(), strCommand.c_str(),
                         nPayloadAvailable, nMessageSize,
                         BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS);
                pfrom->fDisconnect = true;
            }
            break;
        }
        pfrom->nIncompleteMessageStart = 0;
        pfrom->nIncompleteMessageSize = 0;
        pfrom->strIncompleteMessageCommand.clear();
        vRecv.ignore(nHeaderSize);

        // Checksum, on streams that carry one. A mismatch is a mangled or
        // forged payload either way; drop the message rather than parse it.
        if (vRecv.GetVersion() >= PROTO_CHECKSUM_VERSION)
        {
            uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            if (nChecksum != hdr.nChecksum)
            {
                LogPrintAlways("net", "ProcessMessages(%s, %u bytes) from %s: CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
                               strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(),
                               nChecksum, hdr.nChecksum);
                vRecv.ignore(nMessageSize);
                pfrom->Misbehaving(20);
                continue;
            }
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);
        nMessages++;

        // Process message
        bool fRet = false;
        try
        {
            CheckForShutdown(2);
            // The share chain's messages read no chain state, and a history
            // costs a RandomX hash a share: under cs_main, a few thousand of
            // them held up blocks, RPC and mining for minutes. They take
            // cs_p2pool alone. Before the version, ProcessMessage refuses them.
            bool fDone = false;
            if (strCommand.compare(0, 3, "p2p") == 0 && pfrom->nVersion != 0)
            {
                CDataStream vCopy(vMsg);
                fDone = fRet = P2PoolProcessMessage(pfrom, strCommand, vCopy);
            }
            // Peer exchange reads no chain state either: signature checks and
            // a file, which have no business holding up everything else.
            if (!fDone && strCommand == "btfpeers" && pfrom->nVersion != 0)
                fDone = fRet = ProcessBtfPeers(pfrom, vMsg);
            if (!fDone)
                CRITICAL_BLOCK(cs_main)
                    fRet = ProcessMessage(pfrom, strCommand, vMsg);
            CheckForShutdown(2);
        }
        // A message that does not parse: one line, burst-collapsed. This was
        // a multi-line EXCEPTION block in debug.log for every short message,
        // written whatever the log settings, at no cost to the sender.
        CATCH_FORCED_UNWIND
        catch (std::exception& e)
        {
            LogPrintAlways("net", "ProcessMessage(%s, %u bytes) from %s: %s\n",
                           strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
        }
        catch (...)
        {
            LogPrintAlways("net", "ProcessMessage(%s, %u bytes) from %s: unknown exception\n",
                           strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str());
        }
        if (!fRet)
            if (LogAcceptsCategory("net")) printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n", strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), addrLocalHost.ToString().c_str());
    }

    vRecv.Compact();
    return true;
}




// Version-time getblocks: whether we have asked anybody yet, and when we last
// asked a peer only because it said it was ahead of us.
static bool fAskedForBlocks = false;
static int64 nLastAheadGetBlocks = 0;
static const int AHEAD_GETBLOCKS_MIN_GAP = 3;          // blocks: relay lag is not "ahead"
static const int64 AHEAD_GETBLOCKS_INTERVAL = 5 * 60;  // seconds

void VersionGetBlocksResetForTest()
{
    fAskedForBlocks = true;
    nLastAheadGetBlocks = 0;
}

bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    if (LogAcceptsCategory("net")) { printf("received: %-12s (%d bytes)  ", strCommand.c_str(), (int)vRecv.size()); for (int i = 0; i < min(vRecv.size(), (unsigned int)25); i++) printf("%02x ", vRecv[i] & 0xff); printf("\n"); }
    if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
    {
        if (LogAcceptsCategory("net")) printf("dropmessages DROPPING RECV MESSAGE\n");
        return true;
    }



    if (strCommand == "version")
    {
        // Can only do this once
        if (pfrom->nVersion != 0)
            return false;

        int64 nTime;
        CAddress addrMe;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 0)
            return false;

        // Optional: peers older than this field simply end the message here,
        // and nStartingHeight stays -1 for them. Never make this a requirement
        // -- every node released so far sends the short form.
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        // Same rule for the release string (1.2.24+). Bounded: it is a peer's
        // claim, and it only ever reaches a log line and the diagnostics.
        if (!vRecv.empty())
        {
            try { vRecv >> pfrom->strRelease; } catch (...) { pfrom->strRelease = ""; }
            if (pfrom->strRelease.size() > 32)
                pfrom->strRelease.resize(32);
            for (size_t i = 0; i < pfrom->strRelease.size(); i++)
                if (!isprint((unsigned char)pfrom->strRelease[i]))
                    pfrom->strRelease[i] = '?';
        }

        // From here on both sides frame with the lower of the two versions.
        // Our own version message left in 101 framing before this could be
        // known; the peer's did too, and it is the message being read now, so
        // the switch is clean on both streams. The send side is locked
        // because another thread may be mid-PushMessage, and it fixed its
        // header layout at BeginMessage() for exactly this reason.
        CRITICAL_BLOCK(pfrom->cs_vSend)
            pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        CRITICAL_BLOCK(pfrom->cs_vRecv)
            pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);
        if (pfrom->fClient)
        {
            pfrom->vSend.nType |= SER_BLOCKHEADERONLY;
            pfrom->vRecv.nType |= SER_BLOCKHEADERONLY;
        }

        AddTimeData(pfrom->addr.ip, nTime);

        // Ask the first connected node for block updates, and ask again when
        // a node is the only one there is: the first may be long gone, and
        // nothing else would ask before the next block is announced.
        bool fOnlyPeer = false;
        CRITICAL_BLOCK(cs_vNodes)
            fOnlyPeer = (vNodes.size() <= 1);
        // Also ask a peer that says it is clearly ahead of us, whoever else
        // we have: a node behind its peers used to wait for the next block to
        // be announced before it asked anybody. At most one such extra
        // request per AHEAD_GETBLOCKS_INTERVAL: a 1.2.x peer answers with an
        // inv of its whole chain, and a fresh node meeting many of them must
        // not download that once per peer.
        bool fAhead = pfrom->nStartingHeight > nBestHeight + AHEAD_GETBLOCKS_MIN_GAP &&
                      GetTime() - nLastAheadGetBlocks >= AHEAD_GETBLOCKS_INTERVAL;
        if ((!fAskedForBlocks || fOnlyPeer || fAhead) && !pfrom->fClient)
        {
            if (fAskedForBlocks && !fOnlyPeer)
                nLastAheadGetBlocks = GetTime();
            fAskedForBlocks = true;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }

        // A peer behind us gets our tip. A 1.2.x node turns it into a
        // getblocks on this connection (orphan path, or ask, receive, then
        // orphan path), which restarts a sync whose continuation went down
        // with an earlier connection: its own version-time getblocks is
        // skipped while the old connection is still draining.
        if (!pfrom->fClient && pfrom->nStartingHeight >= 0 && pfrom->nStartingHeight < nBestHeight)
        {
            vector<CInv> vTip(1, CInv(MSG_BLOCK, hashBestChain));
            pfrom->PushMessage("inv", vTip);
        }

        // Introduce ourselves and hand over the .btf peers that answered us.
        // Everything in here is self-certifying, so this is safe to send to a
        // node we know nothing about, and safe for it to act on.
        vector<string> vPexOut;
        BtfPexCollect(vPexOut);
        if (!vPexOut.empty())
            pfrom->PushMessage("btfpeers", vPexOut);

        ChatRelayOnVersion(pfrom);
        // A peer we dialled says whether it holds the share chain; a P2Pool
        // miner looks for the ones that do (net.cpp, DialP2PoolPeers).
        if (!pfrom->strBtfAddr.empty())
            BtfNoteP2PoolPeer(pfrom->strBtfAddr, (pfrom->nServices & NODE_P2POOL) != 0);
        P2PoolOnVersion(pfrom);

        if (LogAcceptsCategory("net")) printf("version addrMe = %s, peer height = %d\n", addrMe.ToString().c_str(), pfrom->nStartingHeight);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        return false;
    }


    else if (strCommand == "btfpeers")
    {
        // ProcessMessages hands this over before taking cs_main; this branch
        // is for callers that come straight here.
        return ProcessBtfPeers(pfrom, vRecv);
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        // No score for a long one: a 1.2.x node answers getblocks with every
        // block from the fork point to its tip in a single inv, which is past
        // MAX_INV_SZ on the chain as it is. Its start is what a syncing node
        // needs first. The last block kept is remembered, and when it arrives
        // the same peer is sent getblocks again for the rest (block handler):
        // without that, a node syncing from 1.2.x peers stopped there until
        // somebody announced a new block.
        if (vInv.size() > MAX_INV_SZ)
        {
            LogPrint("net", "inv from %s: %u entries, taking the first %u\n",
                     pfrom->addr.ToString().c_str(), (unsigned int)vInv.size(), MAX_INV_SZ);
            vInv.resize(MAX_INV_SZ);
            if (vInv.back().type == MSG_BLOCK)
                pfrom->hashInvContinue = vInv.back().hash;
        }

        CTxDB txdb("r");
        // Nothing is asked of a peer whose send buffer is full -- the getdata
        // would only add to it -- so its transactions are not worth a read.
        bool fAskForFull = false;
        unsigned int nQueued;
        CRITICAL_BLOCK(pfrom->cs_vSend)
            nQueued = pfrom->vSend.size();
        if (nQueued >= SendBufferSize())
            fAskForFull = true;
        // Database reads for transaction hashes are rationed per peer.
        {
            int64 nNow = GetTime();
            int64 nAdd = (nNow - pfrom->nTxInvRefilled) * TX_INV_LOOKUPS_PER_SEC;
            if (nAdd > 0)
            {
                pfrom->nTxInvTokens = (int)min((int64)TX_INV_LOOKUPS_MAX, pfrom->nTxInvTokens + nAdd);
                pfrom->nTxInvRefilled = nNow;
            }
        }
        foreach(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            // Once this peer has MAX_ASKFOR_PER_PEER requests queued nothing
            // more is asked of it, so a transaction it names is not worth the
            // database read. Blocks are looked up in memory and may still need
            // the orphan follow-up below.
            if (fAskForFull && inv.type != MSG_BLOCK)
                continue;
            if (inv.type == MSG_TX)
            {
                if (pfrom->nTxInvTokens <= 0)
                    continue;
                pfrom->nTxInvTokens--;
            }

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (LogAcceptsCategory("net")) printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
            {
                if (!pfrom->AskFor(inv))
                    fAskForFull = true;
            }
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        // Nothing this node sends makes an honest peer ask for this much at
        // once: getblocks answers carry MAX_GETBLOCKS_RESULTS.
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            LogPrint("net", "getdata from %s: %u entries, refused\n",
                     pfrom->addr.ToString().c_str(), (unsigned int)vInv.size());
            return true;
        }

        // Queued, and served as the send buffer drains. The queue as a whole
        // is held to MAX_INV_SZ: a peer that keeps asking without reading gets
        // the start of what it asked for and nothing more.
        size_t nRoom = pfrom->vRecvGetData.size() < MAX_INV_SZ ? MAX_INV_SZ - pfrom->vRecvGetData.size() : 0;
        if (vInv.size() > nRoom)
        {
            LogPrint("net", "getdata from %s: %u entries queued already, dropping %u\n",
                     pfrom->addr.ToString().c_str(), (unsigned int)pfrom->vRecvGetData.size(),
                     (unsigned int)(vInv.size() - nRoom));
            vInv.resize(nRoom);
        }
        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // CBlockLocator::Set makes about 10 + log2(height) entries; each one
        // costs a lookup here, under cs_main.
        if (locator.Have().size() > MAX_LOCATOR_SZ)
        {
            pfrom->Misbehaving(20);
            LogPrint("net", "getblocks from %s: locator of %u entries, refused\n",
                     pfrom->addr.ToString().c_str(), (unsigned int)locator.Have().size());
            return true;
        }

        // With the send buffer full the answer waits: the latest request
        // replaces an older one, and SendMessages answers it once there is
        // room. A stream of getblocks to a peer that does not read used to
        // grow its send buffer by a whole-chain inv each.
        unsigned int nQueued;
        CRITICAL_BLOCK(pfrom->cs_vSend)
            nQueued = pfrom->vSend.size();
        if (nQueued >= SendBufferSize())
        {
            pfrom->fGetBlocksPending = true;
            pfrom->vGetBlocksHave = locator.Have();
            pfrom->hashGetBlocksStop = hashStop;
        }
        else
        {
            pfrom->fGetBlocksPending = false;
            vector<uint256>().swap(pfrom->vGetBlocksHave);
            ServeGetBlocks(pfrom, locator, hashStop);
        }
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        CTransaction tx;
        vRecv >> tx;
        // What is relayed, and held if the transaction is an orphan, is the
        // transaction itself, re-encoded -- not the payload as it arrived.
        // The payload may carry any number of bytes after the transaction,
        // which the reader leaves unread; kept, they were stored with every
        // orphan and served to every peer that asked, bounded by the message
        // size rather than by the transaction's, which IsStandard limits.
        CDataStream vMsg(SER_NETWORK, vRecv.nVersion);
        vMsg << tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        // A coinbase on its own, or a transaction that fails the shape checks,
        // is not something an honest node relays: it validates first.
        if (tx.IsCoinBase())
        {
            pfrom->Misbehaving(100);
            return error("ProcessMessage(tx) : coinbase as individual tx");
        }
        if (!tx.CheckTransaction())
        {
            pfrom->Misbehaving(10);
            return error("ProcessMessage(tx) : CheckTransaction failed");
        }

        bool fMissingInputs = false;
        if (tx.AcceptTransaction(true, &fMissingInputs))
        {
            AddToWalletIfMine(tx, NULL);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            pfrom->nLastTxTime = GetTime();

            // Recursively process any orphan transactions that depended on this one
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                     mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                     ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());

                    if (tx.AcceptTransaction(true))
                    {
                        if (LogAcceptsCategory("net")) printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
                        AddToWalletIfMine(tx, NULL);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                    }
                }
            }

            foreach(uint256 hash, vWorkQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            if (LogAcceptsCategory("net")) printf("storing orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
            AddOrphanTx(vMsg);
        }
    }


    else if (strCommand == "review")
    {
        // The 0.1.0 marketplace's reviews: an ECDSA check against a key the
        // sender chose, under cs_main, then reviews.dat read and rewritten in
        // full with no dedup or cap (nTime is not signed, so one review could
        // be replayed for ever). Nothing in Bitflash sends or reads them, and
        // AlreadyHave never asks for one. A quiet no-op, like checkorder.
        vRecv.clear();
    }


    else if (strCommand == "block")
    {
        auto_ptr<CBlock> pblock(new CBlock);
        vRecv >> *pblock;

        //// debug print
        if (LogAcceptsCategory("net")) { printf("received block:\n"); pblock->print(); }

        CInv inv(MSG_BLOCK, pblock->GetHash());
        pfrom->AddInventoryKnown(inv);

        // The last block of a cut whole-chain inv: once it is here, ask the
        // same peer for the rest (see hashInvContinue).
        bool fContinue = pfrom->hashInvContinue != 0 && inv.hash == pfrom->hashInvContinue;

        // A new inbound peer draws on a budget shared by all such peers before
        // its block costs a proof-of-work check. Dropped for bad work, an
        // inbound onion peer is back at once with a clean score (it has no
        // address to ban), so its own score bounds nothing over time; this
        // does. The token is taken inside CheckBlock right before the hash,
        // so a block that fails a cheap check costs none.
        struct PoWBudgetGate
        {
            explicit PoWBudgetGate(bool f) { tl_fPoWBudgetGate = f; tl_fPoWBudgetRefused = false; }
            ~PoWBudgetGate() { tl_fPoWBudgetGate = false; tl_fPoWBudgetRefused = false; }
        };
        int nDoS = 0;
        bool fOk = false, fRefused = false;
        {
            PoWBudgetGate gate(PeerNeedsBlockBudget(pfrom));
            fOk = ProcessBlock(pfrom, pblock.release(), &nDoS);
            fRefused = tl_fPoWBudgetRefused;
        }
        if (fRefused)
        {
            // Not looked at, and not forgotten: the next peer that announces
            // it is asked at once, and this one again once there is budget.
            nInboundBlocksRefused++;
            LogPrintAlways("net", "block %s from new inbound peer %s not checked yet: inbound budget spent\n",
                           inv.hash.ToString().substr(0,14).c_str(), pfrom->addr.ToString().c_str());
            mapAlreadyAskedFor.erase(inv);
            if (pfrom->vBlocksRefused.size() < MAX_BLOCKS_REFUSED_PER_PEER &&
                find(pfrom->vBlocksRefused.begin(), pfrom->vBlocksRefused.end(), inv.hash) == pfrom->vBlocksRefused.end())
                pfrom->vBlocksRefused.push_back(inv.hash);
            return true;
        }
        if (fOk)
        {
            mapAlreadyAskedFor.erase(inv);
            // Good only once it connected: an orphan at the floor proves little.
            if (mapBlockIndex.count(inv.hash))
            {
                pfrom->nGoodBlocks++;
                pfrom->nLastBlockTime = GetTime();
            }
        }
        else if (nDoS > 0)
            pfrom->Misbehaving(nDoS);

        if (fContinue)
        {
            pfrom->hashInvContinue = 0;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }
    }


    else if (strCommand == "checkorder" || strCommand == "submitorder")
    {
        // Legacy Bitcoin 0.1 marketplace messages are not part of Bitflash's
        // supported protocol. They used to let a remote peer make this wallet
        // reserve a key or import/broadcast a wallet transaction. Keep the
        // command names explicit so old peers get a quiet no-op instead of a
        // wallet side effect.
        if (LogAcceptsCategory("net"))
            printf("ProcessMessage(%s) : disabled legacy order message\n", strCommand.c_str());
        vRecv.clear();
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping")
    {
        // Nothing to do and nothing to answer. Arriving at all is the entire
        // content of the message: the receive path has already stamped
        // nLastRecv, which is what the sender wanted us to notice.
        //
        // Deliberately no reply. A node old enough not to know "ping" ignores
        // it as an unknown command and would never answer one, so a scheme
        // that required an answer would read every such peer as dead.
    }


    else if (ChatRelayProcessMessage(pfrom, strCommand, vRecv))
    {
        // chatrec, chatput, chatget, getchatinv -- see chatrelay.h.
    }


    else if (P2PoolProcessMessage(pfrom, strCommand, vRecv))
    {
        // p2pshare, p2pgetsh, p2psync, p2pshares -- see p2pool_net.h.
    }


    else
    {
        // Ignore unknown commands for extensibility
        if (LogAcceptsCategory("net")) printf("ProcessMessage(%s) : Ignored unknown message\n", strCommand.c_str());
    }


    if (!vRecv.empty())
        if (LogAcceptsCategory("net")) printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(), (int)vRecv.size());

    return true;
}









bool SendMessages(CNode* pto)
{
    CheckForShutdown(2);
    // Try, not take. The message thread arrives here holding this peer's
    // cs_vSend; a thread that holds cs_main and pushes a message to this
    // peer -- an RPC call relaying the transaction it just made, a block
    // being relayed -- takes cs_main first and cs_vSend second. Blocking on
    // cs_main here with cs_vSend held is a deadlock with that thread, and
    // it was reached: an RPC chatsend and the message thread stopped each
    // other on the 202 (2026-09-19). Bitcoin 0.3.x made the same change.
    // When cs_main is busy, this round is skipped; the next comes in 100 ms.
    TRY_CRITICAL_BLOCK(cs_main)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;


        //
        // Message: keep-alive ping
        //
        // Only when we have nothing else queued -- any real message serves the
        // same purpose. A peer with nothing to relay is otherwise silent, and
        // silence is exactly what the inactivity check disconnects on.
        //
        if (pto->nLastSend && GetTime() - pto->nLastSend > BTF_PING_INTERVAL_SECS && pto->vSend.empty())
            pto->PushMessage("ping");

        // A getblocks that arrived with the send buffer full, now that it has
        // room. Its answer goes out with the inventory below.
        ServePendingGetBlocks(pto);

        // Forget requests that stagger nothing any more, once a minute. AskFor
        // also trims the map when it passes MAX_ALREADY_ASKED_FOR.
        {
            static int64 nLastPrune = 0;
            if (GetTime() - nLastPrune > 60)
            {
                nLastPrune = GetTime();
                PruneAlreadyAskedFor(GetTime() * 1000000, MAX_ALREADY_ASKED_FOR);
            }
        }


        //
        // Message: inventory
        //
        vector<CInv> vInventoryToSend;
        CRITICAL_BLOCK(pto->cs_inventory)
        {
            vInventoryToSend.reserve(pto->vInventoryToSend.size());
            foreach(const CInv& inv, pto->vInventoryToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                    vInventoryToSend.push_back(inv);
            }
            pto->vInventoryToSend.clear();
            pto->setInventoryKnown2.clear();
        }
        if (!vInventoryToSend.empty())
            pto->PushMessage("inv", vInventoryToSend);


        //
        // Blocks the inbound budget refused from this peer: asked for again
        // once there is budget, or once the peer no longer needs any.
        //
        if (!pto->vBlocksRefused.empty() && (!PeerNeedsBlockBudget(pto) || InboundBlockBudgetAvailable()))
        {
            vector<uint256> vRefused;
            vRefused.swap(pto->vBlocksRefused);
            foreach(const uint256& hash, vRefused)
                if (!mapBlockIndex.count(hash) && !mapOrphanBlocks.count(hash))
                    pto->AskFor(CInv(MSG_BLOCK, hash));
        }

        //
        // Message: getdata
        //
        // Not while the send buffer is full: a peer that announces and does
        // not read would otherwise grow it by a getdata for every inv. The
        // requests wait in mapAskFor, which is capped.
        //
        unsigned int nQueuedNow;
        CRITICAL_BLOCK(pto->cs_vSend)
            nQueuedNow = pto->vSend.size();
        if (nQueuedNow < SendBufferSize())
        {
            vector<CInv> vAskFor;
            int64 nNow = GetTime() * 1000000;
            CTxDB txdb("r");
            while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
            {
                const CInv& inv = (*pto->mapAskFor.begin()).second;
                if (LogAcceptsCategory("net")) printf("sending getdata: %s\n", inv.ToString().c_str());
                if (!AlreadyHave(txdb, inv))
                    vAskFor.push_back(inv);
                pto->mapAskFor.erase(pto->mapAskFor.begin());
            }
            if (!vAskFor.empty())
                pto->PushMessage("getdata", vAskFor);
        }

    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout)
{
    unsigned int* pinput = (unsigned int*)pin;
    unsigned int* pstate = (unsigned int*)pout;

    CryptoPP::SHA256::InitState(pstate);

    if (*(char*)&detectlittleendian != 0)
    {
        for (int n = 0; n < nBlocks; n++)
        {
            unsigned int pbuf[16];
            for (int i = 0; i < 16; i++)
                pbuf[i] = ByteReverse(pinput[n * 16 + i]);
            CryptoPP::SHA256::Transform(pstate, pbuf);
        }
        for (int i = 0; i < 8; i++)
            pstate[i] = ByteReverse(pstate[i]);
    }
    else
    {
        for (int n = 0; n < nBlocks; n++)
            CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
    }
}


// ---------------------------------------------------------------------------
// Participant pool miner -- connects to an external Stratum server, receives
// RandomX jobs, hashes with the local CPU, and submits shares.
// Called from BitcoinMiner() when nMineMode == MINE_PARTICIPANT.
// ---------------------------------------------------------------------------

using json = nlohmann::json;


// ---------------------------------------------------------------------------
// Participant miner -- connects to a pool over a .btf tunnel, runs Stratum,
// hashes with RandomX, submits shares. Called from BitcoinMiner().
// ---------------------------------------------------------------------------

using json = nlohmann::json;

static std::string ToHexStr(const void* p, size_t n)
{
    const unsigned char* b = (const unsigned char*)p;
    std::string s; s.reserve(n*2);
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { s += H[b[i]>>4]; s += H[b[i]&0xf]; }
    return s;
}

static std::vector<unsigned char> FromHexStr(const std::string& s)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i+1 < s.size(); i += 2) {
        auto h = [](char c)->int{
            if(c>='0'&&c<='9') return c-'0';
            if(c>='a'&&c<='f') return c-'a'+10;
            if(c>='A'&&c<='F') return c-'A'+10;
            return 0;
        };
        v.push_back((unsigned char)((h(s[i])<<4)|h(s[i+1])));
    }
    return v;
}

static void UpdateParticipantHashRate(uint64 hashesSinceSample, int64 sampleStart)
{
    int64 elapsed = GetTime() - sampleStart;
    if (elapsed <= 0) elapsed = 1;
    gParticipantHashRateX1000.store(
        (uint64)((double)hashesSinceSample / (double)elapsed * 1000.0));
}

// Blocking send of a JSON line to the pool.
static bool StratumSendLine(SOCKET s, const json& j)
{
    std::string line = j.dump() + "\n";
    int sent = 0, total = (int)line.size();
    while (sent < total) {
        int r = send(s, line.c_str()+sent, total-sent, BTF_SEND_FLAGS);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Non-blocking recv into carry buffer. Returns true + fills line when a
// complete newline-terminated message is ready. Returns false in two cases:
//   disconnected=true  -- socket closed by peer; caller must stop
//   disconnected=false -- no complete line yet; caller should select() and retry
static bool StratumRecvLine(SOCKET s, std::string& buf,
                            std::string& line, bool& disconnected)
{
    disconnected = false;
    char tmp[4096];
#ifdef _WIN32
    u_long avail = 0;
    ioctlsocket(s, FIONREAD, &avail);
    if (avail > 0) {
        int r = recv(s, tmp, (int)std::min((u_long)(sizeof(tmp)-1), avail), 0);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
    }
#else
    {
        int r = recv(s, tmp, sizeof(tmp)-1, MSG_DONTWAIT);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
        // r < 0: EAGAIN -- no data right now
    }
#endif
    size_t pos = buf.find('\n');
    if (pos == std::string::npos) return false;
    line = buf.substr(0, pos);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    buf = buf.substr(pos + 1);
    return true;
}

// How long to wait for a mining.notify after authorize before giving up
static const int64 STUCK_NO_JOB_TIMEOUT_SECS = 120;

static bool PoolParticipantMiner()
{
    // ------------------------------------------------------------------
    // Step 1: resolve .btf address -> meeting node
    // ------------------------------------------------------------------
    if (strParticipantPool.empty()) {
        LogPrint("worker", "[worker] no pool selected\n");
        SetParticipantMiningStatus("no pool selected");
        return false;
    }

    LogPrint("worker", "[worker] connecting to pool %s\n", strParticipantPool.c_str());
    SetParticipantMiningStatus("resolving pool address");

    unsigned char target_pubkey[32];
    if (!btf::ParseAddress(strParticipantPool, target_pubkey)) {
        LogPrint("worker", "[worker] invalid .btf address: %s\n", strParticipantPool.c_str());
        SetParticipantMiningStatus("invalid pool address");
        return false;
    }

    (void)target_pubkey; // onion authenticates by address; no echan key needed

    // Prefer a peer we have already reached (its onion is cached): a direct
    // lookup, no Nostr. Nostr over Tor often has no exit, so the cache is the
    // reliable path when the pool is a peer we have seen. Fall back to a Nostr
    // resolve of the pool's signed descriptor otherwise.
    std::string onionHostPort;
    if (!BtfCachedPeerOnion(strParticipantPool, onionHostPort)) {
        std::string meetingHostPort;   // unused: the pool is reached over its onion
        unsigned char service_enc_pub[32];
        if (!BtfResolve(strParticipantPool, meetingHostPort, service_enc_pub, &onionHostPort)
            || onionHostPort.empty()) {
            LogPrint("worker", "[worker] failed to resolve pool %s over onion"
                     " (pool offline, or its descriptor has no hidden service)\n",
                     strParticipantPool.c_str());
            SetParticipantMiningStatus("failed to resolve pool");
            return false;
        }
    }

    // The pool listens at p2p+1 on the same hidden service as its P2P port, so
    // derive the pool endpoint from the resolved P2P onion -- no separate
    // announcement, and nothing routed through a rendezvous relay.
    size_t colon = onionHostPort.rfind(':');
    if (colon == std::string::npos) {
        LogPrint("worker", "[worker] bad pool onion format '%s'\n", onionHostPort.c_str());
        SetParticipantMiningStatus("bad pool endpoint");
        return false;
    }
    std::string host = onionHostPort.substr(0, colon);
    int p2p = atoi(onionHostPort.substr(colon + 1).c_str());
    if (p2p <= 0 || p2p >= 65535) {
        LogPrint("worker", "[worker] bad pool onion port %d in '%s'\n", p2p, onionHostPort.c_str());
        SetParticipantMiningStatus("bad pool port");
        return false;
    }
    int port = p2p + 1;

    // ------------------------------------------------------------------
    // Step 2: connect to the pool over its Tor hidden service
    // ------------------------------------------------------------------
    SetParticipantMiningStatus("connecting over onion");
    btf_socket_t s = BtfConnectSocket(host, (unsigned short)port, SOCK_ONION_PEER, 30);
    if (s == INVALID_SOCKET) {
        LogPrint("worker", "[worker] onion connect FAILED to %s:%d"
                 " (pool not listening, or Tor has no route)\n", host.c_str(), port);
        SetParticipantMiningStatus("pool connect failed");
        return false;
    }
    LogPrint("worker", "[worker] connected to pool over onion %s:%d\n", host.c_str(), port);
    SetParticipantMiningStatus("connected over onion");

    // ------------------------------------------------------------------
    // Step 3: determine our payout address (mining username)
    // ------------------------------------------------------------------
    std::string username;
    {
        std::vector<unsigned char> vchPubKey;
        if (CWalletDB("r").ReadDefaultKey(vchPubKey))
            username = PubKeyToAddress(vchPubKey);
    }
    if (username.empty()) username = BtfLocalAddress();
    if (username.empty()) {
        LogPrint("worker", "[worker] WARNING: could not determine wallet address"
                 " -- shares will not pay out\n");
        username = "unknown";
    }
    LogPrint("worker", "[worker] payout address: %s\n", username.c_str());

    // ------------------------------------------------------------------
    // Step 4: build the fast (~2 GB dataset) RandomX mode if not already
    // built, then start our VM. Without this, RandomXCreateMinerVM() falls
    // back to "light" mode (cache only) forever, which is dramatically
    // slower per hash than fast mode -- it recomputes dataset items on the
    // fly for every single hash instead of a direct memory lookup. That
    // alone can turn a "few seconds per share" pool into "many minutes per
    // share" regardless of how easy the share target is.
    //
    // This MUST happen before we send mining.subscribe/authorize, not
    // after: it's a synchronous, single-threaded-per-call build that can
    // take anywhere from several seconds to a couple of minutes depending
    // on core count. If it runs after the handshake messages are sent,
    // the pool's replies (subscribe ack, authorize ack, set_difficulty,
    // and the first job) all land in the OS socket buffer while we're
    // not reading -- nothing is lost, but we sit there looking (and
    // logging) like we're "stuck waiting for pool response" for the
    // entire build duration, when really we're just not listening yet.
    // Building the dataset first means that by the time we say
    // "subscribing", we're genuinely ready to read the reply the instant
    // it arrives.
    // ------------------------------------------------------------------
    // Keyed for the PoW version in force now; a job from the other side of
    // the switch re-keys in the hashing loop below.
    int nPoWVersion = PoWVersionAt(GetAdjustedTime());
    if (!RandomXFastReady(nPoWVersion)) {
        SetParticipantMiningStatus("building RandomX dataset (~2GB, one-time)");
        unsigned int nThreads = std::thread::hardware_concurrency();
        RandomXInitDataset(nPoWVersion, nThreads > 0 ? (int)nThreads : 1);
    }
    void* rxvm = RandomXCreateMinerVM(nPoWVersion);
    if (!rxvm) {
        LogPrint("worker", "[worker] failed to create RandomX VM\n");
        SetParticipantMiningStatus("RandomX init failed");
        closesocket(s); return false;
    }
    LogPrint("worker", "[worker] RandomX v%d VM ready (%s)\n", nPoWVersion,
             RandomXFastReady(nPoWVersion) ? "fast 2GB" : "light 256MB");

    // ------------------------------------------------------------------
    // Step 5: Stratum subscribe + authorize. The socket is read from
    // immediately after this, in the main loop below, so nothing sits
    // unread behind a blocking dataset build anymore.
    // ------------------------------------------------------------------
    std::string buf;
    int msgId = 1;
    std::set<int> pendingSubmitIds;

    SetParticipantMiningStatus("subscribing");
    // Say which chain we are mining. A pool on the other network refuses here
    // instead of handing out work we would hash for a payout that cannot land.
    LogPrint("worker", "[worker->pool] sending mining.subscribe (network=%s)\n", BtfNetworkName());
    if (!StratumSendLine(s, json{{"id",msgId++},{"method","mining.subscribe"},
                                 {"params",json::array({BtfNetworkName()})}})) {
        LogPrint("worker", "[worker] subscribe send FAILED -- pool dropped connection\n");
        SetParticipantMiningStatus("subscribe send failed");
        RandomXDestroyMinerVM(rxvm);
        closesocket(s); return false;
    }

    SetParticipantMiningStatus("authorizing");
    LogPrint("worker", "[worker->pool] sending mining.authorize as %s\n", username.c_str());
    if (!StratumSendLine(s, json{{"id",msgId++},{"method","mining.authorize"},
                                 {"params",json::array({username,"x"})}})) {
        LogPrint("worker", "[worker] authorize send FAILED -- pool dropped connection\n");
        SetParticipantMiningStatus("authorize send failed");
        RandomXDestroyMinerVM(rxvm);
        closesocket(s); return false;
    }

    // ------------------------------------------------------------------
    // Step 6: main loop -- receive messages, hash, submit shares
    // ------------------------------------------------------------------
    std::string jobId;
    unsigned char header[80] = {};
    uint256 target;
    double currentDifficulty = 1.0; // updated by mining.set_difficulty from pool
    bool haveJob         = false;
    bool gotSubscribeAck = false;
    bool gotAuthorizeAck = false;
    int64 authWaitStart  = 0;
    int64 lastStuckLog   = 0;
    unsigned int nNonce  = 1;
    uint64 hashesSinceSample  = 0;
    uint64 sessionSharesSent  = 0; // this connection only
    uint64 sessionSharesAccepted = 0;
    int64  sampleStart       = GetTime();

    SetParticipantMiningStatus("waiting for pool response");

    while (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown)
    {
        // -- Receive: check buffer first, then select --
        {
            bool haveBuffered = buf.find('\n') != std::string::npos;
            bool readable     = false;
            if (!haveBuffered) {
                fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
                struct timeval tv = {0, 50000}; // 50ms
                readable = select((int)s+1, &fds, NULL, NULL, &tv) > 0;
            }

            if (haveBuffered || readable) {
                std::string line;
                bool disc = false;
                while (StratumRecvLine(s, buf, line, disc)) {
                    json msg;
                    try { msg = json::parse(line); } catch (...) {
                        LogPrint("worker", "[pool->worker] JSON parse error: %.80s\n",
                                 line.c_str());
                        continue;
                    }

                    // -- Response to our subscribe (id=1) --
                    if (msg.contains("id") && msg["id"].is_number_integer()
                        && msg["id"].get<int>() == 1
                        && msg.contains("result") && !msg["result"].is_null()) {
                        gotSubscribeAck = true;
                        LogPrint("worker", "[pool->worker] subscribe ack received\n");
                        SetParticipantMiningStatus("subscribed; waiting for authorize ack");
                    }

                    // -- Response to our authorize (id=2) --
                    else if (msg.contains("id") && msg["id"].is_number_integer()
                             && msg["id"].get<int>() == 2
                             && msg.contains("result")) {
                        bool ok = msg["result"].is_boolean() && msg["result"].get<bool>();
                        authWaitStart = GetTime();
                        if (ok) {
                            gotAuthorizeAck = true;
                            LogPrint("worker", "[pool->worker] authorize OK -- waiting for job\n");
                            SetParticipantMiningStatus("authorized; waiting for job");
                        } else {
                            std::string reason = msg.value("error", json("unspecified")).is_string()
                                ? msg["error"].get<std::string>() : "unspecified";
                            LogPrint("worker", "[pool->worker] authorize REJECTED: %s\n",
                                     reason.c_str());
                            SetParticipantMiningStatus("authorization rejected");
                            // Don't break -- pool might still send a job (some pools
                            // reject bad addresses but still send work)
                        }
                    }

                    // -- Share submission response --
                    else if (msg.contains("id") && msg["id"].is_number_integer()) {
                        int rid = msg["id"].get<int>();
                        if (pendingSubmitIds.erase(rid) > 0) {
                            bool accepted = msg.contains("result")
                                         && msg["result"].is_boolean()
                                         && msg["result"].get<bool>();
                            if (accepted) {
                                gParticipantSharesAccepted.fetch_add(1);
                                sessionSharesAccepted++;
                                LogPrint("worker", "[pool->worker] share id=%d ACCEPTED\n", rid);
                                SetParticipantMiningStatus("share accepted");
                            } else {
                                std::string reason = (msg.contains("error")
                                    && msg["error"].is_string())
                                    ? msg["error"].get<std::string>() : "unspecified";
                                LogPrint("worker", "[pool->worker] share id=%d REJECTED: %s\n",
                                         rid, reason.c_str());
                                SetParticipantMiningStatus("share rejected: " + reason);
                            }
                        }
                    }

                    // -- Server notification --
                    else {
                        std::string method = msg.value("method", "");

                        if (method == "mining.notify") {
                            auto& p = msg["params"];
                            if (!p.is_array() || p.size() < 4) {
                                LogPrint("worker", "[pool->worker] malformed mining.notify"
                                         " (params size=%zu)\n", p.is_array() ? p.size() : 0);
                            } else {
                                std::string newJobId = p[0].get<std::string>();
                                auto hdrBytes = FromHexStr(p[1].get<std::string>());
                                auto tgtBytes = FromHexStr(p[3].get<std::string>());

                                if (hdrBytes.size() < 80) {
                                    LogPrint("worker", "[pool->worker] mining.notify:"
                                             " header too short (%zu bytes)\n",
                                             hdrBytes.size());
                                } else if (tgtBytes.size() < 32) {
                                    LogPrint("worker", "[pool->worker] mining.notify:"
                                             " target too short (%zu bytes)\n",
                                             tgtBytes.size());
                                } else {
                                    jobId = newJobId;
                                    memcpy(header, hdrBytes.data(), 80);
                                    memcpy(&target, tgtBytes.data(), 32);
                                    haveJob = true;
                                    nNonce  = 1;
                                    LogPrint("worker", "[pool->worker] new job %s received\n",
                                             jobId.c_str());
                                    SetParticipantMiningStatus("hashing job " + jobId);
                                }
                            }
                        } else if (method == "mining.set_difficulty") {
                            // Pool adjusts our share difficulty via vardiff.
                            // Apply it immediately so we start hashing at the new target.
                            if (msg.contains("params") && msg["params"].is_array()
                                && msg["params"].size() > 0
                                && msg["params"][0].is_number()) {
                                double newDiff = msg["params"][0].get<double>();
                                if (newDiff > 0.0) {
                                    bool changed = (newDiff != currentDifficulty);
                                    currentDifficulty = newDiff;
                                    LogPrint("worker", "[pool->worker] set_difficulty %.6f%s\n",
                                             newDiff, changed ? " (updated)" : " (initial)");
                                }
                            } else {
                                LogPrint("worker", "[pool->worker] set_difficulty"
                                         " received (no valid params)\n");
                            }
                        } else if (!method.empty()) {
                            LogPrint("worker", "[pool->worker] unknown server method: %s\n",
                                     method.c_str());
                        }
                    }
                }

                if (disc) {
                    LogPrint("worker", "[worker] pool closed the connection"
                             " (gotSubscribeAck=%d gotAuthorizeAck=%d haveJob=%d)\n",
                             gotSubscribeAck, gotAuthorizeAck, haveJob);
                    break;
                }
            }
        }

        // -- Stuck watchdog: authorized but no job arriving --
        if (gotAuthorizeAck && !haveJob && authWaitStart > 0) {
            int64 waited = GetTime() - authWaitStart;
            if (waited > 10 && GetTime() - lastStuckLog >= 15) {
                LogPrint("worker", "[worker] authorized but no job after %llds"
                         " -- pool tunnel is live, waiting on mining.notify\n",
                         (long long)waited);
                lastStuckLog = GetTime();
            }
            if (waited > STUCK_NO_JOB_TIMEOUT_SECS) {
                LogPrint("worker", "[worker] no job received after %llds -- disconnecting"
                         " and reconnecting\n", (long long)STUCK_NO_JOB_TIMEOUT_SECS);
                SetParticipantMiningStatus("timeout waiting for job; reconnecting");
                break;
            }
        }

        if (!haveJob) { Sleep(100); continue; }

        // -- Hash one nonce --
        memcpy(header+76, &nNonce, 4);
        {
            // The job header carries its own nTime, so it decides the PoW
            // version. When the pool crosses the switch, re-key once.
            unsigned int nJobTime; memcpy(&nJobTime, header+68, 4);
            int v = PoWVersionAt(nJobTime);
            if (v != nPoWVersion) {
                LogPrint("worker", "[worker] job is PoW v%d, re-keying RandomX\n", v);
                RandomXDestroyMinerVM(rxvm);
                unsigned int nThreads = std::thread::hardware_concurrency();
                RandomXInitDataset(v, nThreads > 0 ? (int)nThreads : 1);
                rxvm = RandomXCreateMinerVM(v);
                if (!rxvm) { SetParticipantMiningStatus("RandomX re-key failed"); break; }
                nPoWVersion = v;
            }
        }
        uint256 hash = PoWHashHeaderWithVM(rxvm, header);
        hashesSinceSample++;
        gParticipantHashes.fetch_add(1);
        if ((hashesSinceSample & 0x3ff) == 0)
            UpdateParticipantHashRate(hashesSinceSample, sampleStart);

        if (hash <= target) {
            LogPrint("worker", "[worker] share found! nonce=%u job=%s difficulty=%.4f\n",
                     nNonce, jobId.c_str(), currentDifficulty);
            SetParticipantMiningStatus("share found; submitting");
            int submitId = msgId++;
            pendingSubmitIds.insert(submitId);
            gParticipantSharesSent.fetch_add(1);
            sessionSharesSent++;
            json submit = {{"id",submitId},{"method","mining.submit"},
                           {"params",json::array({username, jobId, ToHexStr(&nNonce,4)})}};
            if (!StratumSendLine(s, submit)) {
                LogPrint("worker", "[worker] share submit send FAILED"
                         " -- pool connection lost\n");
                break;
            }
        }

        nNonce++;
        if (nNonce == 0) {
            LogPrint("worker", "[worker] nonce space exhausted for job %s"
                     " -- waiting for new job\n", jobId.c_str());
            haveJob = false;
        }
    }

    // ------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------
    RandomXDestroyMinerVM(rxvm);
    closesocket(s);
    UpdateParticipantHashRate(hashesSinceSample, sampleStart);
    SetParticipantMiningStatus("disconnected");
    LogPrint("worker", "[worker] disconnected from pool"
             " (hashes this session: %llu, shares sent: %llu, accepted: %llu)\n",
             (unsigned long long)hashesSinceSample,
             (unsigned long long)sessionSharesSent,
             (unsigned long long)sessionSharesAccepted);
    return true;
}

// ---------------------------------------------------------------------------
// Local Stratum bridge -- lets external miners speak plain Stratum to
// 127.0.0.1 while Bitflash opens the .btf tunnel to the selected pool.
// ---------------------------------------------------------------------------

struct StratumBridgeClientCtx
{
    SOCKET miner;
    std::string pool;
};

static bool BridgeSendAll(SOCKET s, const char* p, int n)
{
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

static void BridgePump(SOCKET a, SOCKET b)
{
    char buf[8192];
    while (!fShutdown)
    {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(a, &rd);
        FD_SET(b, &rd);
        SOCKET maxfd = a > b ? a : b;
        struct timeval tv = {1, 0};
        int r = select((int)maxfd + 1, &rd, NULL, NULL, &tv);
        if (r <= 0)
            continue;

        if (FD_ISSET(a, &rd))
        {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0 || !BridgeSendAll(b, buf, n))
                break;
        }
        if (FD_ISSET(b, &rd))
        {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0 || !BridgeSendAll(a, buf, n))
                break;
        }
    }
}

static void ThreadStratumBridgeClient(void* arg)
{
    StratumBridgeClientCtx* ctx = (StratumBridgeClientCtx*)arg;
    SOCKET miner = ctx->miner;
    std::string pool = ctx->pool;
    delete ctx;

    unsigned char target_pubkey[32];
    if (!btf::ParseAddress(pool, target_pubkey))
    {
        LogPrint("worker", "[bridge] invalid pool .btf address: %s\n", pool.c_str());
        BtfCloseSocket(miner);
        return;
    }

    (void)target_pubkey; // onion authenticates by address; no echan key needed

    // Cache first (a peer we have reached), then a Nostr descriptor resolve.
    std::string onionHostPort;
    if (!BtfCachedPeerOnion(pool, onionHostPort))
    {
        std::string meetingHostPort;   // unused: the pool is reached over its onion
        unsigned char service_enc_pub[32];
        if (!BtfResolve(pool, meetingHostPort, service_enc_pub, &onionHostPort) || onionHostPort.empty())
        {
            LogPrint("worker", "[bridge] failed to resolve pool %s over onion\n", pool.c_str());
            BtfCloseSocket(miner);
            return;
        }
    }

    // The pool listens at p2p+1 on the same hidden service as its P2P port.
    size_t colon = onionHostPort.rfind(':');
    if (colon == std::string::npos)
    {
        LogPrint("worker", "[bridge] bad pool onion '%s'\n", onionHostPort.c_str());
        BtfCloseSocket(miner);
        return;
    }
    std::string host = onionHostPort.substr(0, colon);
    int p2p = atoi(onionHostPort.substr(colon + 1).c_str());
    if (p2p <= 0 || p2p >= 65535)
    {
        LogPrint("worker", "[bridge] bad pool onion port in '%s'\n", onionHostPort.c_str());
        BtfCloseSocket(miner);
        return;
    }
    int port = p2p + 1;

    SOCKET poolSock = BtfConnectSocket(host, (unsigned short)port, SOCK_ONION_PEER, 30);
    if (poolSock == INVALID_SOCKET)
    {
        LogPrint("worker", "[bridge] onion connect failed for pool %s at %s:%d\n",
                 pool.c_str(), host.c_str(), port);
        BtfCloseSocket(miner);
        return;
    }

    LogPrint("worker", "[bridge] miner connected to pool %s over onion %s:%d\n",
             pool.c_str(), host.c_str(), port);
    BridgePump(miner, poolSock);
    BtfCloseSocket(poolSock);
    BtfCloseSocket(miner);
    LogPrint("worker", "[bridge] miner disconnected from pool %s\n", pool.c_str());
}

void ThreadStratumBridge(void*)
{
    if (strParticipantPool.empty())
    {
        printf("Stratum bridge: no pool selected. Use /stratumbridge=POOL_BTF_ADDRESS\n");
        return;
    }

    SOCKET listener = BtfSocketTag(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP),
                                   SOCK_STRATUM_BRIDGE);
    if (listener == INVALID_SOCKET)
    {
        printf("Stratum bridge: could not create listen socket\n");
        return;
    }

    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // Loopback unless told otherwise. The bridge is the one piece of this node
    // meant to face the clear network -- a public stratum door so ordinary
    // miners can reach a pool that itself lives behind Tor -- but it still has
    // to be asked for. A bridge that opened up on its own would hand every
    // user a listening port they did not know they had.
    unsigned long nBind = inet_addr(strStratumBridgeBind.c_str());
    if (nBind == INADDR_NONE)
    {
        printf("Stratum bridge: -stratumbridgebind=%s is not a usable IPv4 address\n",
               strStratumBridgeBind.c_str());
        BtfCloseSocket(listener);
        return;
    }
    addr.sin_addr.s_addr = nBind;
    addr.sin_port = htons((unsigned short)nStratumBridgePort);

    if (::bind(listener, (sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listener, 16) != 0)
    {
        printf("Stratum bridge: could not listen on %s:%d\n",
               strStratumBridgeBind.c_str(), nStratumBridgePort);
        BtfCloseSocket(listener);
        return;
    }

    printf("Stratum bridge: listening on %s:%d for pool %s\n",
           strStratumBridgeBind.c_str(),
           nStratumBridgePort, strParticipantPool.c_str());

    while (!fShutdown)
    {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(listener, &rd);
        struct timeval tv = {1, 0};
        if (select((int)listener + 1, &rd, NULL, NULL, &tv) <= 0)
            continue;

        sockaddr_in cli;
#ifdef _WIN32
        int len = sizeof(cli);
#else
        socklen_t len = sizeof(cli);
#endif
        SOCKET miner = BtfSocketTag(accept(listener, (sockaddr*)&cli, &len),
                                    SOCK_STRATUM_BRIDGE);
        if (miner == INVALID_SOCKET)
            continue;

        StratumBridgeClientCtx* ctx = new StratumBridgeClientCtx();
        ctx->miner = miner;
        ctx->pool = strParticipantPool;
        if (_beginthread(ThreadStratumBridgeClient, 0, ctx) == (uintptr_t)-1)
        {
            delete ctx;
            BtfCloseSocket(miner);
            LogPrint("worker", "[bridge] failed to spawn client thread\n");
        }
    }

    BtfCloseSocket(listener);
    printf("Stratum bridge: stopped\n");
}

bool BitcoinMiner(int nThreadId)
{
    // Relay mode: never mines, just relays/syncs. (Shouldn't normally get here
    // since the GUI hides Start Mining for Relay, but guard it regardless.)
    if (nMineMode == MINE_RELAY)
        return true;

    // Participant mode: connect to external pool instead of mining solo/operator
    if (nMineMode == MINE_PARTICIPANT)
    {
        while (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown) {
            PoolParticipantMiner();
            if (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown) {
                LogPrint("worker", "PoolParticipantMiner: reconnecting in 10s\n");
                for (int i = 0; i < 10 && !fShutdown; i++) Sleep(1000);
            }
        }
        return true;
    }

    // Operator mode only serves the pool; it does not mine solo.
    if (nMineMode == MINE_OPERATOR)
        return true;

    LogPrint("net", "BitcoinMiner started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    // Build the fast (~2 GB dataset) RandomX mode once, up front, so we're
    // not stuck mining in the much slower light/cache-only mode forever.
    if (!RandomXFastReady(PoWVersionAt(GetAdjustedTime()))) {
        unsigned int nThreads = std::thread::hardware_concurrency();
        RandomXInitDataset(PoWVersionAt(GetAdjustedTime()), nThreads > 0 ? (int)nThreads : 1);
    }

    // Drawn from the pool, so it is already in wallet.dat before a single hash
    // is computed. The old code generated a key here and only saved it if this
    // thread happened to win a block, which meant a backup taken while mining
    // could not spend what the very next block paid.
    vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
    {
        printf("BitcoinMiner: no wallet key available for coinbase; mining stopped\n");
        return false;
    }
    CBigNum bnExtraNonce = 0;
    while (fGenerateBitcoins)
    {
        Sleep(50);
        // Return instead of _endthread()ing. With more than one miner thread the
        // bookkeeping in ThreadBitcoinMiner has to run on the way out, and
        // _endthread() does not unwind on Windows, so a normal return is the
        // only exit that works the same on both platforms.
        if (fShutdown)
            return true;
        while ((vNodes.empty() || IsInitialBlockDownload()) && !fSoloMineTest)
        {
            Sleep(1000);
            if (fShutdown)
                return true;
        }

        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;
        unsigned int nBits = GetNextWorkRequired(pindexPrev);


        //
        // Create coinbase tx
        //
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        // The height comes first and is what makes this transaction unique.
        //
        // Without it nothing in the coinbase belongs to the block: it is a
        // function of the difficulty, a counter, and the payout key. nBits
        // holds still for long stretches and bnExtraNonce is a local that
        // restarts at zero whenever the miner does, so the same combination
        // comes round again and produces a byte-identical transaction with the
        // same txid. Two blocks then name the same transaction and the index
        // keeps whichever arrived last, which silently destroys the outputs of
        // the first. It has already happened twice on this chain, at heights
        // 859 and 860 (#58).
        //
        // Two coinbases at different heights can now never be identical, no
        // matter what the counter or the key do.
        //
        // Nothing validates coinbase content, so this changes only what we
        // produce -- nodes that do not upgrade accept these blocks unchanged.
        // Requiring the height is a separate, coordinated step.
        txNew.vin[0].scriptSig << (pindexPrev ? pindexPrev->nHeight + 1 : 0) << nBits << ++bnExtraNonce;
        txNew.vout.resize(1);
        // Always pay coinbase to own wallet key. In operator mode, the pool
        // server distributes shares to miners via SendMoney() after each block.
        txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;


        //
        // Create new block
        //
        auto_ptr<CBlock> pblock(new CBlock());
        if (!pblock.get())
            return false;

        // Add our coinbase tx as first transaction
        pblock->vtx.push_back(txNew);

        // Collect the latest transactions into the block
        int64 nFees = 0;
        int nSelectedRules = 0;     // the rules the transactions were chosen under (RuleSetAt)
        CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            CTxDB txdb("r");
            map<uint256, CTxIndex> mapTestPool;
            // Best fee per byte first, so paying more gets a transaction in
            // sooner; repeated passes still pick up a child whose parent came
            // later in that order.
            vector<CTransaction*> vOrder;
            MempoolByFeeRate(txdb, vOrder);
            vector<char> vfAlreadyAdded(vOrder.size());
            bool fFoundSomething = true;
            // Under MAX_BLOCK_SIZE, which CheckBlock holds every block to.
            // This loop capped at MAX_SIZE/2 (16 MB, the message limit, as
            // in 0.1.0 before there was a block limit), so whenever the
            // memory pool held more than a megabyte the miner built a block
            // its own CheckBlock refused ("size limits failed"), and went on
            // building the same block: no block at all until the pool
            // drained. Counted from the block as it stands (header,
            // coinbase), with room for what the coinbase gains later.
            unsigned int nBlockSize = ::GetSerializeSize(*pblock, SER_NETWORK) + MINER_COINBASE_ROOM;
            // The block's time before its contents: the rules its
            // transactions are checked under follow from it, and it was still
            // 0 here, so they were the clock's. Never under BlockTimeFloor:
            // the median time past, and under rules v5 a window-closing block
            // is not timed before its window's first block.
            pblock->nTime = max(BlockTimeFloor(pindexPrev), GetAdjustedTime());
            // Under MAX_BLOCK_SIGOPS, counted as ConnectBlock counts: the
            // scripts, plus the redeem scripts rules v3 run. This miner did not
            // count at all, and one transaction over the cap in the pool made
            // every block it built one the network rejects.
            bool fSigOpsV4 = RulesV4Active(pblock->nTime);
            nSelectedRules = RuleSetAt(pblock->nTime);
            unsigned int nBlockSigOps = pblock->vtx[0].GetSigOpCount(fSigOpsV4);
            while (fFoundSomething && nBlockSize < MAX_BLOCK_SIZE)
            {
                fFoundSomething = false;
                for (unsigned int n = 0; n < vOrder.size(); n++)
                {
                    if (vfAlreadyAdded[n])
                        continue;
                    CTransaction& tx = *vOrder[n];
                    // Final as the block will be judged: by its own time, not
                    // the clock's (they differ right at the v3 switch).
                    if (tx.IsCoinBase() || !IsFinalForBlock(tx, pindexPrev, pblock->nTime))
                        continue;
                    unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
                    if (nBlockSize + nTxSize > MAX_BLOCK_SIZE)
                        continue;

                    // Transaction fee requirements, mainly only needed for flood control
                    // Under 10K (about 80 inputs) is free for first 100 transactions
                    // Base rate is 0.01 per KB
                    int64 nMinFee = tx.GetMinFee(pblock->vtx.size() < 100);

                    map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
                    int64 nFeesTmp = nFees;
                    unsigned int nTxSigOps = tx.GetSigOpCount(fSigOpsV4);
                    if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1,1,1), 0, nFeesTmp, false, true, nMinFee, pblock->nTime,
                                          &nTxSigOps))
                        continue;
                    if (nBlockSigOps + nTxSigOps > MAX_BLOCK_SIGOPS)
                        continue;
                    nBlockSigOps += nTxSigOps;
                    nFees = nFeesTmp;
                    swap(mapTestPool, mapTestPoolTmp);

                    pblock->vtx.push_back(tx);
                    nBlockSize += nTxSize;
                    vfAlreadyAdded[n] = true;
                    fFoundSomething = true;
                }
            }
        }
        pblock->nBits = nBits;
        pblock->vtx[0].vout[0].nValue = pblock->GetBlockValue(nBestHeight + 1, nFees);
        // Solo miner's share to the treasury: a second coinbase output, the
        // sum unchanged, so the block is worth exactly what it was. Not in
        // operator mode, where the pool fee is the way (-poolfeeto).
        if (nMineMode != MINE_OPERATOR)
        {
            int64 nShare = treasury::ShareOf(pblock->vtx[0].vout[0].nValue, nTreasurySharePercent);
            CScript scriptTreasury;
            if (nShare > 0 && treasury::Script(scriptTreasury))
            {
                pblock->vtx[0].vout[0].nValue -= nShare;
                pblock->vtx[0].vout.push_back(CTxOut(nShare, scriptTreasury));
            }
        }
        if (LogAcceptsCategory("net")) printf("\n\nRunning BitcoinMiner with %d transactions in block\n", (int)pblock->vtx.size());


        //
        // Prepare the block header
        //
        pblock->hashPrevBlock  = (pindexPrev ? pindexPrev->GetBlockHash() : 0);
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        // A later time, unless it would put the block under other rules than
        // its transactions were chosen under: it keeps the time it was built
        // at then, which is still after the median time past. All the rule
        // sets, not only v4: P2SH spends and finality change at v3.
        {
            unsigned int nNow = max(BlockTimeFloor(pindexPrev), GetAdjustedTime());
            if (RuleSetAt(nNow) == nSelectedRules)
                pblock->nTime = nNow;
        }
        pblock->nBits          = nBits;
        pblock->nNonce         = 1;


        //
        // Search (memory-hard RandomX PoW) -- each thread uses its own VM
        //
        // Keyed for the version this block's nTime selects. The first block
        // after the switch pays for the other dataset once.
        int nPoWVersion = PoWVersionAt(pblock->nTime);
        if (!RandomXFastReady(nPoWVersion))
        {
            unsigned int nThreads = std::thread::hardware_concurrency();
            RandomXInitDataset(nPoWVersion, nThreads > 0 ? (int)nThreads : 1);
        }
        void* rxvm = RandomXCreateMinerVM(nPoWVersion);
        if (!rxvm)
        {
            LogPrint("net", "BitcoinMiner: failed to create RandomX VM\n");
            Sleep(1000);
            continue;
        }
        // The thread number is in the line on purpose: every miner would
        // otherwise print the same text, and the dedup filter would fold them
        // into one, leaving no way to tell four threads from one.
        LogPrint("net", "BitcoinMiner: thread %d hashing with RandomX v%d (%s)\n",
               nThreadId, nPoWVersion, RandomXFastReady(nPoWVersion) ? "fast 2GB" : "light 256MB");

        unsigned int nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        loop
        {
            uint256 hash = PoWHashHeaderWithVM(rxvm, (const unsigned char*)BEGIN(pblock->nVersion));

            if (hash <= hashTarget)
            {
                    //// debug print
                    if (LogAcceptsCategory("net")) printf("BitcoinMiner:\n");
                    if (LogAcceptsCategory("net")) printf("RandomX proof-of-work found  \n  powhash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    if (LogAcceptsCategory("net")) pblock->print();

                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
                CRITICAL_BLOCK(cs_main)
                {
                    // Is the parent we solved for still the tip?
                    //
                    // The loop only tests this every 256 hashes, and never
                    // again once a solution turns up. So a thread that found
                    // one just after somebody else extended the chain would
                    // submit a block built on a parent that is no longer the
                    // tip -- a block born orphaned, at a height already taken.
                    //
                    // Every miner thread on this machine works from the same
                    // pindexPrev, so the moment one of them wins, all the
                    // others are hashing a doomed template until their next
                    // checkpoint. On a 32-core box that is thirty threads with
                    // a standing chance of producing a guaranteed orphan, and
                    // it is why a healthy miner's wallet filled up with them.
                    if (pindexPrev != pindexBest)
                    {
                        LogPrint("net", "BitcoinMiner: thread %d solved for a parent that is no longer the tip, discarding\n",
                                 nThreadId);
                    }
                    else
                    {
                        // The key that just got paid was written to wallet.dat
                        // when it left the pool, so there is nothing to save
                        // here -- only a fresh one to take for the next block.
                        // Two threads never draw the same key: the pool hands
                        // them out one at a time under cs_keyPool, which is
                        // what keeps concurrent coinbases distinct (#58).
                        vchPubKey = GetKeyFromPool();
                        if (vchPubKey.empty())
                        {
                            printf("BitcoinMiner: no replacement wallet key available; mining stopped\n");
                            fGenerateBitcoins = false;
                        }

                        // Process this block the same as if we had received it from another node
                        if (!ProcessBlock(NULL, pblock.release()))
                            LogPrint("net", "ERROR in BitcoinMiner, ProcessBlock, block not accepted\n");
                    }
                }
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

                Sleep(500);
                break;
            }

            // Check stop conditions periodically (RandomX is slow, so every
            // ~256 hashes is already plenty of time)
            if ((++pblock->nNonce & 0xff) == 0)
            {
                if (fShutdown)
                    break;          // falls through to RandomXDestroyMinerVM below
                if (pblock->nNonce == 0)
                    break;
                if (pindexPrev != pindexBest)
                    break;
                if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (!fGenerateBitcoins)
                    break;
                pblock->nTime = max(BlockTimeFloor(pindexPrev), GetAdjustedTime());
                if (PoWVersionAt(pblock->nTime) != nPoWVersion)
                    break;          // the switch happened under us: rebuild, keyed for v2
                if (RuleSetAt(pblock->nTime) != nSelectedRules)
                    break;          // a rule set (v2, v3, v4) switched on under us: rebuild under it
            }
        }
        RandomXDestroyMinerVM(rxvm);
        if (fShutdown)
            break;
    }

    return true;
}


















//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


// Why an immature coinbase is immature.
//
// GetBlocksToMaturity() answers with a number of blocks and nothing else, so a
// reward that is two blocks away and a reward that lost a race five months ago
// give the same answer: "not yet". The difference is whether the block it was
// paid in is in the main chain, which is knowable right here.
//
// 0 = maturing normally, 1 = its block is not in the main chain (never coming),
// 2 = not anchored to any block this node can connect it to.
static int ClassifyImmatureCoinbase(const CWalletTx& wtx, int& nDepthOut)
{
    nDepthOut = wtx.GetDepthInMainChain();
    if (nDepthOut > 0)
        return 0;
    if (wtx.hashBlock == 0 || wtx.nIndex == -1)
        return 2;
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi == mapBlockIndex.end() || !(*mi).second)
        return 2;  // a block this node does not have: still syncing, most likely
    if (!(*mi).second->IsInMainChain())
        return 1;  // the block exists and lost: this reward is dead
    return 2;      // in the main chain but the merkle branch does not connect
}

WalletRecoveryAudit GetWalletRecoveryAudit()
{
    WalletRecoveryAudit audit;
    set<vector<unsigned char> > setDerivedPubKeys;

    CRITICAL_BLOCK(cs_keyPool)
    {
        audit.fHaveSeed = HaveHDSeed();
        audit.fSeedEncryptedLocked = !audit.fHaveSeed &&
                                     (!vchCryptedHDMaster.empty() ||
                                      !vchCryptedHDChainCode.empty() ||
                                      !vchPlainSeedPendingMaster.empty());
        audit.nSchema = nHDKeySchema;
        audit.nDerivedKnown = nHDNext;
        audit.nReceiveNext = nHDReceiveNext;
        audit.nChangeNext = nHDChangeNext;
        audit.nCoinType = nHDCoinType;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
            audit.nDerivedKnown = nHDReceiveNext + nHDChangeNext + nHDNext;
        if (audit.fHaveSeed)
        {
            string strError;
            unsigned int nReceiveDepth = nHDKeySchema == HD_SCHEMA_BIP44
                ? nHDReceiveNext
                : nHDNext;
            for (unsigned int i = 0; i < nReceiveDepth; i++)
            {
                CKey key;
                if (!DeriveHDKey(i, key, strError))
                {
                    audit.fDeriveComplete = false;
                    audit.strDeriveError = strprintf("derivation failed at index %u: %s",
                                                      i, strError.c_str());
                    break;
                }
                setDerivedPubKeys.insert(key.GetPubKey());
            }
            if (nHDKeySchema == HD_SCHEMA_BIP44)
            {
                int nSavedSchema = nHDKeySchema;
                for (unsigned int i = 0; i < nHDChangeNext; i++)
                {
                    CKey key;
                    if (!DeriveHDChangeKey(i, key, strError))
                    {
                        audit.fDeriveComplete = false;
                        audit.strDeriveError = strprintf("change derivation failed at index %u: %s",
                                                          i, strError.c_str());
                        break;
                    }
                    setDerivedPubKeys.insert(key.GetPubKey());
                }
                nHDKeySchema = HD_SCHEMA_LEGACY;
                for (unsigned int i = 0; i < nHDNext; i++)
                {
                    CKey key;
                    if (!DeriveHDKey(i, key, strError))
                    {
                        audit.fDeriveComplete = false;
                        audit.strDeriveError = strprintf("legacy compatibility derivation failed at index %u: %s",
                                                          i, strError.c_str());
                        break;
                    }
                    setDerivedPubKeys.insert(key.GetPubKey());
                }
                nHDKeySchema = nSavedSchema;
            }
        }
    }

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx& wtx = (*it).second;
            if (!wtx.IsFinalForWallet() || wtx.fSpent)
                continue;
            bool fImmature = wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0;

            // Counted only over the outputs that are ours, exactly like the
            // totals below: an immature coinbase that pays somebody else too
            // must not inflate this.
            int64 nMineImmature = 0;

            bool fTxRecoverable = false;
            bool fTxLegacy = false;
            for (int i = 0; i < (int)wtx.vout.size(); i++)
            {
                const CTxOut& txout = wtx.vout[i];
                if (!txout.IsMine())
                    continue;

                vector<unsigned char> vchPubKey;
                bool fRecoverable = false;
                if (audit.fHaveSeed && ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                    fRecoverable = setDerivedPubKeys.count(vchPubKey) > 0;

                if (fImmature)
                    nMineImmature += txout.nValue;

                if (fRecoverable)
                {
                    if (fImmature)
                        audit.nRecoverableImmatureCredit += txout.nValue;
                    else
                        audit.nRecoverableCredit += txout.nValue;
                    fTxRecoverable = true;
                }
                else
                {
                    if (fImmature)
                        audit.nLegacyImmatureCredit += txout.nValue;
                    else
                        audit.nLegacyCredit += txout.nValue;
                    fTxLegacy = true;
                }
            }

            if (fImmature && nMineImmature > 0)
            {
                int nDepth = 0;
                switch (ClassifyImmatureCoinbase(wtx, nDepth))
                {
                case 1:
                    audit.nOrphanedImmatureCredit += nMineImmature;
                    audit.nOrphanedImmatureTx++;
                    break;
                case 2:
                    audit.nUnanchoredImmatureCredit += nMineImmature;
                    audit.nUnanchoredImmatureTx++;
                    break;
                default:
                    {
                        int nToGo = wtx.GetBlocksToMaturity();
                        if (audit.nSoonestMaturityBlocks < 0 ||
                            nToGo < audit.nSoonestMaturityBlocks)
                        {
                            audit.nSoonestMaturityBlocks = nToGo;
                            audit.nSoonestMaturityDepth = nDepth;
                        }
                    }
                    break;
                }
            }

            if (fTxRecoverable)
            {
                if (fImmature)
                    audit.nRecoverableImmatureTx++;
                else
                    audit.nRecoverableTx++;
            }
            if (fTxLegacy)
            {
                if (fImmature)
                    audit.nLegacyImmatureTx++;
                else
                    audit.nLegacyTx++;
            }
        }
    }

    return audit;
}

int64 GetBalance()
{
    int64 nStart, nEnd;
    QueryPerformanceCounter((LARGE_INTEGER*)&nStart);

    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinalForWallet() || pcoin->fSpent)
                continue;
            nTotal += pcoin->GetCredit();
        }
    }

    QueryPerformanceCounter((LARGE_INTEGER*)&nEnd);
    ///printf(" GetBalance() time = %16lld\n", nEnd - nStart);
    return nTotal;
}



// Bitcoin 0.3.x's rule. 0.1.0 spent any credit the moment it was in the
// wallet: a payment somebody had just announced, unconfirmed, was fair input
// for the next send, and if that payment never made it into a block the send
// built on it died with it. Coins received from others need nConfTheirs
// confirmations, our own change needs nConfMine; SelectCoins() below tries
// the strict pairs first and relaxes only as far as the target requires.
static bool SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs,
                               set<CWalletTx*>& setCoinsRet)
{
    setCoinsRet.clear();

    // List of values less than target
    int64 nLowestLarger = _I64_MAX;
    CWalletTx* pcoinLowestLarger = NULL;
    vector<pair<int64, CWalletTx*> > vValue;
    int64 nTotalLower = 0;

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinalForWallet() || pcoin->fSpent)
                continue;
            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->GetDebit() > 0 ? nConfMine : nConfTheirs))
                continue;
            int64 n = pcoin->GetCredit();
            if (n <= 0)
                continue;
            if (n < nTargetValue)
            {
                vValue.push_back(make_pair(n, pcoin));
                nTotalLower += n;
            }
            else if (n == nTargetValue)
            {
                setCoinsRet.insert(pcoin);
                return true;
            }
            else if (n < nLowestLarger)
            {
                nLowestLarger = n;
                pcoinLowestLarger = pcoin;
            }
        }
    }

    if (nTotalLower < nTargetValue)
    {
        if (pcoinLowestLarger == NULL)
            return false;
        setCoinsRet.insert(pcoinLowestLarger);
        return true;
    }

    // Solve subset sum by stochastic approximation. The coin flips come from
    // a generator seeded from the system's RNG on each call: std::rand() was
    // never seeded, so every process start made the same choices.
    std::mt19937 rng((std::mt19937::result_type)GetRand(0xffffffffULL));
    sort(vValue.rbegin(), vValue.rend());
    vector<char> vfIncluded;
    vector<char> vfBest(vValue.size(), true);
    int64 nBest = nTotalLower;

    for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? (rng() & 1) : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // If the next larger is still closer, return it
    if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
        setCoinsRet.insert(pcoinLowestLarger);
    else
    {
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                setCoinsRet.insert(vValue[i].second);

        //// debug print
        if (LogAcceptsCategory("net")) printf("SelectCoinsMinConf() best subset: ");
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                if (LogAcceptsCategory("net")) printf("%s ", FormatMoney(vValue[i].first).c_str());
        if (LogAcceptsCategory("net")) printf("total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
}

bool SelectCoins(int64 nTargetValue, set<CWalletTx*>& setCoinsRet)
{
    return (SelectCoinsMinConf(nTargetValue, 1, 6, setCoinsRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, setCoinsRet) ||
            SelectCoinsMinConf(nTargetValue, 0, 1, setCoinsRet));
}




static thread_local string tlsCreateTransactionError;

string LastCreateTransactionError()
{
    return tlsCreateTransactionError;
}

void ClampLoadedFeeSettings()
{
    if (!IsAcceptableTxFeeSetting(nTransactionFee))
    {
        printf("LoadWallet: the stored flat fee %s is outside 0..%s; using the minimum fee instead\n",
               FormatMoney(nTransactionFee).c_str(), FormatMoney(MAX_TX_FEE_SETTING).c_str());
        // Where an operator who set it on purpose will see it, not only debug.log.
        fprintf(stderr, "Wallet: the stored fee per transaction (%s) is above %s and is not used; "
                        "the minimum fee applies. Set it again (at most %s) if needed.\n",
                FormatMoney(nTransactionFee).c_str(), FormatMoney(MAX_TX_FEE_SETTING).c_str(),
                FormatMoney(MAX_TX_FEE_SETTING).c_str());
        nTransactionFee = 0;
    }
    if (nPayTxFeePerKB < 0 || nPayTxFeePerKB > COIN)
    {
        printf("LoadWallet: the stored fee rate %s per kB is outside 0..1 per kB; using the minimum instead\n",
               FormatMoney(nPayTxFeePerKB).c_str());
        nPayTxFeePerKB = 0;
    }
}

bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, int64& nFeeRequiredRet,
                       int64 nFeeLimit, bool fDryRun)
{
    nFeeRequiredRet = 0;
    tlsCreateTransactionError.clear();
    if (nFeeLimit < 0)
        nFeeLimit = nMaxTxFee;
    CRITICAL_BLOCK(cs_main)
    {
        // txdb must be opened before the mapWallet lock
        CTxDB txdb("r");
        CRITICAL_BLOCK(cs_mapWallet)
        {
            int64 nFee = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                if (nValue < 0)
                    return false;

                // nValue is the amount the payee asked for and must stay that.
                //
                // This used to read "nValueOut = nValue; nValue += nFee;", and
                // both lines are inside the retry loop. The first pass was
                // fine. But when the fee turned out to be too low the loop
                // starts over, and on the second pass nValueOut is read from
                // an nValue that already had the fee added -- so the payee is
                // sent the amount plus the fee, and it compounds on every
                // further retry, with the sender covering it.
                //
                // The retry fires whenever GetMinFee exceeds the fee we
                // guessed, which for this fee schedule means any transaction
                // over 10 KB: a wallet paying from many small inputs. Bitcoin
                // fixed this in 107d9e288.
                int64 nTotalValue = nValue + nFee;

                // Choose coins to use
                set<CWalletTx*> setCoins;
                if (!SelectCoins(nTotalValue, setCoins))
                {
                    tlsCreateTransactionError = strprintf("insufficient funds for %s plus a fee of %s",
                                                          FormatMoney(nValue).c_str(), FormatMoney(nFee).c_str());
                    return false;
                }
                int64 nValueIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    nValueIn += pcoin->GetCredit();

                // Fill vout[0] to the payee
                wtxNew.vout.push_back(CTxOut(nValue, scriptPubKey));

                // Fill vout[1] back to self with any change
                if (nValueIn > nTotalValue)
                {
                    vector<unsigned char> vchPubKey;
                    if (fDryRun)
                    {
                        // Same size as a real change key, and nothing drawn.
                        vchPubKey = keyUser.GetPubKey();
                    }
                    else if (HaveHDSeed())
                    {
                        string strError;
                        if (!DeriveNextHDChangeKey(vchPubKey, strError))
                        {
                            printf("CreateTransaction() : could not derive a phrase-backed change key: %s\n",
                                   strError.c_str());
                            tlsCreateTransactionError = "could not derive a change key: " + strError;
                            return false;
                        }
                    }
                    else
                    {
                        // A wallet without a seed takes change to a fresh key
                        // from its pool. 0.1.0 sent it back to a key of the
                        // first input, which told every observer which output
                        // was the change and tied the payer's addresses
                        // together. The pool key is in the wallet before it is
                        // used, so a backup taken since the last top-up covers
                        // it. If the pool cannot give one, the old way stays.
                        vchPubKey = GetKeyFromPool();
                        if (vchPubKey.empty())
                        {
                            CTransaction& txFirst = *(*setCoins.begin());
                            foreach(const CTxOut& txout, txFirst.vout)
                                if (txout.IsMine())
                                    if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                                        break;
                        }
                    }
                    if (vchPubKey.empty())
                    {
                        tlsCreateTransactionError = "no key for the change";
                        return false;
                    }

                    // The change goes in at a random position, not always
                    // second: a fixed place marks it as the change for anyone
                    // reading the chain. (BumpFee finds change by IsMine.)
                    CScript scriptPubKey;
                    scriptPubKey << vchPubKey << OP_CHECKSIG;
                    CTxOut change(nValueIn - nTotalValue, scriptPubKey);
                    if (GetRand(2) == 0)
                        wtxNew.vout.insert(wtxNew.vout.begin(), change);
                    else
                        wtxNew.vout.push_back(change);
                }

                // Fill vin. Replaceable (BIP125), so it can be sped up later
                // with bumpfee; with nLockTime 0 the sequence changes nothing
                // about when it is final, on any node.
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            wtxNew.vin.push_back(CTxIn(pcoin->GetHash(), nOut, CScript(), SEQUENCE_REPLACEABLE));

                // Sign
                int nIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            SignSignature(*pcoin, wtxNew, nIn++);

                // Check that enough fee is included: the minimum, or the
                // wallet's rate for this size if that is more.
                int64 nNeed = max(wtxNew.GetMinFee(true),
                                  FeeForSize(nPayTxFeePerKB, ::GetSerializeSize(wtxNew, SER_NETWORK)));
                if (nFee < nNeed)
                {
                    nFee = nFeeRequiredRet = nNeed;
                    continue;
                }
                nFeeRequiredRet = nFee;

                // A sanity limit, not a policy: a fee this large is a mistake
                // in the settings far more often than a choice.
                if (nFee > nFeeLimit)
                {
                    tlsCreateTransactionError = strprintf(
                        "the fee would be %s, above the limit of %s (/maxtxfee, or the fee you confirmed); "
                        "nothing was sent", FormatMoney(nFee).c_str(), FormatMoney(nFeeLimit).c_str());
                    printf("CreateTransaction() : %s\n", tlsCreateTransactionError.c_str());
                    return false;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

// Undo what CommitTransactionSpent did: unmark the inputs it marked spent
// and erase the half-committed wallet entry. Used when a transaction is
// accepted into the wallet but then rejected by the mempool/chain, so we
// don't end up with a wallet that thinks money is spent that never left.
void RollbackTransactionSpent(const CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        set<CWalletTx*> setCoins;
        foreach(const CTxIn& txin, wtxNew.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
                setCoins.insert(&mi->second);
        }
        foreach(CWalletTx* pcoin, setCoins)
        {
            pcoin->fSpent = false;
            pcoin->WriteToDisk();
            vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
        }

        EraseFromWallet(wtxNew.GetHash());
    }
    MainFrameRepaint();
}

// Call after CreateTransaction unless you want to abort
bool CommitTransactionSpent(const CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        //// todo: make this transactional, never want to add a transaction
        ////  without marking spent transactions

        // Add tx to wallet, because if it has change it's also ours,
        // otherwise just for transaction history.
        //
        // Every write is checked, and a failed one stops the send before it
        // is broadcast: a payment on the network that the wallet file does
        // not record is change the wallet cannot see after a restart, and
        // pool payouts are de-duplicated by exactly this record.
        bool fOk = AddToWallet(wtxNew);

        // Mark old coins as spent
        set<CWalletTx*> setCoins;
        foreach(const CTxIn& txin, wtxNew.vin)
            setCoins.insert(&mapWallet[txin.prevout.hash]);
        foreach(CWalletTx* pcoin, setCoins)
        {
            pcoin->fSpent = true;
            if (!pcoin->WriteToDisk())
                fOk = false;
            vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
        }
        if (!fOk)
        {
            printf("CommitTransactionSpent() : could not write the transaction to the wallet "
                   "(disk full?); it was not sent\n");
            RollbackTransactionSpent(wtxNew);
            return false;
        }
    }
    MainFrameRepaint();
    return true;
}




bool PreviewSendFee(const CScript& scriptPubKey, int64 nValue, int64& nFeeRet, string& strWhyRet)
{
    nFeeRet = 0;
    strWhyRet.clear();
    if (IsWalletLocked())
    {
        strWhyRet = "The wallet is locked.";
        return false;
    }
    CWalletTx wtx;
    int64 nFee = 0;
    if (!CreateTransaction(scriptPubKey, nValue, wtx, nFee, -1, true))
    {
        strWhyRet = LastCreateTransactionError();
        if (strWhyRet.empty())
            strWhyRet = "Transaction failed.";
        return false;
    }
    nFeeRet = nFee;
    return true;
}

bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, int64 nFeeLimit)
{
    CRITICAL_BLOCK(cs_main)
    {
        int64 nFeeRequired;
        if (!CreateTransaction(scriptPubKey, nValue, wtxNew, nFeeRequired, nFeeLimit))
        {
            string strError;
            if (!LastCreateTransactionError().empty())
                strError = "Error: " + LastCreateTransactionError();
            else if (nValue + nFeeRequired > GetBalance())
                strError = strprintf("Error: This is an oversized transaction that requires a transaction fee of %s ", FormatMoney(nFeeRequired).c_str());
            else
                strError = "Error: Transaction creation failed ";
            return error("SendMoney() : %s\n", strError.c_str());
        }
        if (!CommitTransactionSpent(wtxNew))
        {
            return error("SendMoney() : Error finalizing transaction");
        }

        if (LogAcceptsCategory("net")) printf("SendMoney: %s\n", wtxNew.GetHash().ToString().substr(0,6).c_str());

        // Broadcast
        if (!wtxNew.AcceptTransaction())
        {
            // The transaction was already signed and committed to the wallet
            // above, but the chain/mempool just rejected it (e.g. a raced
            // input already spent by another transaction). Unwind the
            // wallet state we just wrote instead of crashing the app.
            RollbackTransactionSpent(wtxNew);
            return error("SendMoney() : wtxNew.AcceptTransaction() failed");
        }
        wtxNew.RelayWalletTransaction();
    }
    MainFrameRepaint();
    return true;
}

bool BumpFee(const uint256& txid, int64 nNewRatePerKB, uint256& newTxidOut,
             int64& nOldFeeOut, int64& nNewFeeOut, string& errOut)
{
    newTxidOut = 0;
    nOldFeeOut = nNewFeeOut = 0;
    CRITICAL_BLOCK(cs_main)
    {
        CTxDB txdb("r");
        CWalletTx wtxOld;
        CRITICAL_BLOCK(cs_mapWallet)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txid);
            if (mi == mapWallet.end())
            {
                errOut = "that transaction is not in this wallet";
                return false;
            }
            wtxOld = mi->second;
        }
        unsigned int nOldSize = ::GetSerializeSize((CTransaction&)wtxOld, SER_NETWORK);
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            if (!mapTransactions.count(txid))
            {
                errOut = "it is not waiting: already in a block, or not in the memory pool";
                return false;
            }
            if (!GetMempoolTxFee(wtxOld, txdb, nOldFeeOut))
            {
                errOut = "cannot tell what it pays now";
                return false;
            }
        }
        if (!wtxOld.SignalsReplacement())
        {
            errOut = "it was sent as final, before this wallet sent replaceable transactions; it cannot be sped up";
            return false;
        }

        // Every input ours (we have to sign them all again), and some change
        // to take the extra fee from: CreateTransaction puts it last.
        map<uint256, CWalletTx> mapPrev;
        CRITICAL_BLOCK(cs_mapWallet)
            foreach(const CTxIn& txin, wtxOld.vin)
            {
                map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
                if (mi == mapWallet.end() || txin.prevout.n >= mi->second.vout.size() ||
                    !mi->second.vout[txin.prevout.n].IsMine())
                {
                    errOut = "not every input of it is ours";
                    return false;
                }
                mapPrev[txin.prevout.hash] = mi->second;
            }
        int nChange = -1;
        for (int i = (int)wtxOld.vout.size() - 1; i >= 0; i--)
            if (wtxOld.vout[i].IsMine())
            {
                nChange = i;
                break;
            }
        if (nChange < 0 || wtxOld.vout.size() < 2)
        {
            errOut = "it has no change to take a bigger fee from";
            return false;
        }

        CTransaction txNew = wtxOld;
        int64 nFee = nOldFeeOut;
        for (int nPass = 0; nPass < 16; nPass++)
        {
            txNew.vout[nChange].nValue = wtxOld.vout[nChange].nValue - (nFee - nOldFeeOut);
            if (txNew.vout[nChange].nValue < CENT / 100)
            {
                errOut = strprintf("the change (%s) does not cover a fee of %s",
                                   FormatMoney(wtxOld.vout[nChange].nValue).c_str(), FormatMoney(nFee).c_str());
                return false;
            }
            for (unsigned int i = 0; i < txNew.vin.size(); i++)
                txNew.vin[i].scriptSig = CScript();
            for (unsigned int i = 0; i < txNew.vin.size(); i++)
                if (!SignSignature(mapPrev[txNew.vin[i].prevout.hash], txNew, i))
                {
                    errOut = "signing failed";
                    return false;
                }
            unsigned int nSize = ::GetSerializeSize(txNew, SER_NETWORK);
            // The rate asked for, and BIP125's floor: what it pays now plus the
            // relay fee for its size, and more per byte than before.
            int64 nNeed = max(FeeForSize(nNewRatePerKB, nSize),
                              nOldFeeOut + FeeForSize(MIN_RELAY_FEE_PER_KB, nSize));
            nNeed = max(nNeed, nOldFeeOut * (int64)nSize / max(1u, nOldSize) + 1);
            if (nFee >= nNeed && nFee > nOldFeeOut)
                break;
            nFee = max(nNeed, nOldFeeOut + 1);
            if (nPass == 15)
            {
                errOut = "could not settle the new fee";
                return false;
            }
        }

        CWalletTx wtxNew(txNew);
        wtxNew.mapValue = wtxOld.mapValue;
        wtxNew.fFromMe = true;
        wtxNew.AddSupportingTransactions(txdb);
        wtxNew.fTimeReceivedIsTxTime = true;
        // The pool decides: it takes the replacement out of the old one only
        // if every rule holds, and nothing in the wallet changes before that.
        if (!wtxNew.AcceptTransaction())
        {
            errOut = "the replacement was refused (see debug.log)";
            return false;
        }
        CRITICAL_BLOCK(cs_mapWallet)
            AddToWallet(wtxNew);
        wtxNew.RelayWalletTransaction();
        newTxidOut = wtxNew.GetHash();
        nNewFeeOut = nFee;
    }
    MainFrameRepaint();
    return true;
}
