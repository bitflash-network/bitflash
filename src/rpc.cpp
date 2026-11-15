// Copyright (c) 2009 Satoshi Nakamoto / Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash pool server -- .btf Stratum pool, operator side.
//
// Architecture:
//   PoolEventLoop  -- single thread, owns all miner fds, all job/share/payout
//                     state. No locks needed on any of that data.
//   AcceptOneFn    -- one thread per relay. Blocks on RvServiceRegister +
//                     BtfServiceWrap, pushes finished socket to gReadyQueue.
//   AcceptLoopFn   -- spawns AcceptOneFn threads, re-polls relay list every
//                     60s so dynamically discovered relays get picked up.
//
// GUI-visible state is snapshotted under gStatsMutex every 2s.
// Accept queue handoff uses gReadyMutex (held for microseconds).

#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")

#include "headers.h"
#include "treasury.h"
#include "p2pool_net.h"
#ifdef snprintf
#undef snprintf
#endif
#include "btfsock.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <atomic>
#include <mutex>
#include <map>
#include <set>
#include <deque>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>

using json = nlohmann::json;

#define sock_close(s)  BtfCloseSocket(s)
#define SEND_FLAGS     BTF_SEND_FLAGS

volatile bool gPoolRunning = false;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
static std::string ToHex(const void* p, size_t n)
{
    const unsigned char* b = (const unsigned char*)p;
    std::string s; s.reserve(n * 2);
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { s += H[b[i] >> 4]; s += H[b[i] & 0xf]; }
    return s;
}

static std::vector<unsigned char> FromHex(const std::string& s)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        auto h = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        v.push_back((unsigned char)((h(s[i]) << 4) | h(s[i + 1])));
    }
    return v;
}

// ---------------------------------------------------------------------------
// Job -- written and read exclusively by the event loop thread
// ---------------------------------------------------------------------------
struct StratumJob {
    std::string jobId;
    CBlock      block;
    uint256     target;  // full block target; share targets are per-miner via vardiff
    int         height;
    // P2Pool: what the coinbase commits to, the target a miner is given (the
    // easier of the share chain's and the block's, so a block is never
    // filtered out by the miner), the share chain's own target, and the
    // coinbase's merkle branch -- the same for every miner, since index 0's
    // branch holds no coinbase hash.
    p2pool::ShareData shareData;
    uint256     shareTarget;
    uint256     shareChainTarget;
    std::vector<uint256> vBranch;
};

// The script this node's shares pay: -p2poolpayto, or a fresh key of its own
// wallet, changed every 24 hours so the coinbases do not tie its days
// together. Event loop thread only.
static std::vector<unsigned char> P2PoolPayoutScript()
{
    static std::vector<unsigned char> vchScript;
    static int64 nChosenAt = 0;
    if (!strP2PoolPayTo.empty())
    {
        if (vchScript.empty())
        {
            uint160 h;
            if (!AddressToHash160(strP2PoolPayTo, h))
                return vchScript;
            CScript s;
            s << OP_DUP << OP_HASH160 << h << OP_EQUALVERIFY << OP_CHECKSIG;
            vchScript.assign(s.begin(), s.end());
        }
        return vchScript;
    }
    if (vchScript.empty() || GetTime() - nChosenAt > 24 * 60 * 60)
    {
        // A locked wallet has no key to hand out and returns an empty one;
        // hashing that would pay every block to a key nobody holds. Keep the
        // last good key, or none: no script, no templates, and the miner is
        // told why (P2PoolCoinbase).
        vector<unsigned char> vchPubKey = GetKeyFromPool();
        if (vchPubKey.empty())
            return vchScript;
        CScript s;
        s << OP_DUP << OP_HASH160 << Hash160(vchPubKey) << OP_EQUALVERIFY << OP_CHECKSIG;
        vchScript.assign(s.begin(), s.end());
        nChosenAt = GetTime();
    }
    return vchScript;
}

// Room a P2Pool template keeps for its coinbase, which is written after the
// transactions are chosen: an output and a signature operation per address,
// for a window of 2160 shares each naming up to two uncles.
static const unsigned int P2POOL_COINBASE_SIGOPS = 3 * p2pool::WINDOW_SHARES;
static const unsigned int P2POOL_COINBASE_BYTES = 3 * p2pool::WINDOW_SHARES * 34 + 1000;

// The coinbase of a P2Pool template: height, bits, extranonce and the share
// commitment in, the share window paid out. False when this node cannot know
// what the window must pay (its share chain is still syncing). nMinTimeOut:
// the earliest time the share may carry.
static bool P2PoolCoinbase(CBlock& block, int nHeight, unsigned int nBits, uint32_t extraNonce, int64 nFees,
                           p2pool::ShareData& dataOut, uint256& shareTargetOut, unsigned int& nMinTimeOut)
{
    p2pool::ShareData d;
    vector<p2pool::Payout> pay;
    string err;
    CRITICAL_BLOCK(cs_p2pool)
    {
        if (P2PoolAwaitingHistory())
        {
            LogPrint("pool", "[p2pool] no template yet: waiting for the share chain from peers\n");
            return false;
        }
        p2pool::ShareChain& c = P2PoolChain();
        d.hashPrevShare = c.Tip();
        d.nShareHeight = d.hashPrevShare == 0 ? 0 : c.Height(d.hashPrevShare) + 1;
        d.nShareBits = c.NextShareBits(d.hashPrevShare);
        nMinTimeOut = c.NextShareMinTime(d.hashPrevShare);
        d.vUncles = c.UncleCandidates(d.hashPrevShare);
        d.payoutScript = P2PoolPayoutScript();
        vector<p2pool::WindowShare> window;
        if (d.payoutScript.empty() ||
            !c.WindowFor(d, p2pool::WorkOf(d.nShareBits), window, err) ||
            !p2pool::ComputePayouts(window, block.GetBlockValue(nHeight, nFees), pay, err))
        {
            LogPrint("pool", "[p2pool] no template: %s\n",
                     d.payoutScript.empty()
                         ? (strP2PoolPayTo.empty() ? "the wallet is locked and has no key to pay; unlock it or give -p2poolpayto"
                                                   : "-p2poolpayto is not a Bitflash address")
                         : err.c_str());
            return false;
        }
    }
    CTransaction& cb = block.vtx[0];
    cb.vin[0].scriptSig = CScript() << nHeight << nBits << (CBigNum)extraNonce
                                    << p2pool::CommitmentPush(d.GetHash());
    cb.vout.clear();
    for (size_t i = 0; i < pay.size(); i++)
        cb.vout.push_back(CTxOut(pay[i].value, CScript(pay[i].script.begin(), pay[i].script.end())));
    dataOut = d;
    shareTargetOut = CBigNum().SetCompact(d.nShareBits).getuint256();
    return true;
}
static StratumJob gCurrentJob;
// The last jobs sent, newest first: a miner may answer any of them while its
// block still builds on the tip.
static std::deque<StratumJob> gRecentJobs;
static const size_t MAX_RECENT_JOBS = 8;
static bool       gHaveJob = false;

// Compute a share target from a Stratum difficulty value.
// Stratum difficulty 1 must correspond to THIS chain's easiest allowed target
// (bnProofOfWorkLimit = ~uint256(0) >> 12, compact 0x1f0fffff), not Bitcoin's
// SHA256 diff-1 target (0x1d00ffff). Those differ by about 2^20 (~1e6x):
// Bitcoin's diff-1 needs ~2^32 hashes/share on average, while this chain's PoW
// floor needs only ~2^12. Using the Bitcoin constant made every miner's
// "difficulty 1" about a million times harder than the chain's own floor, so a
// worker could hash for minutes without ever finding a share -- and vardiff
// never gets the samples it needs to correct course, because no share ever
// comes in for it to measure. Base off the actual chain limit instead so
// difficulty 1 is genuinely easy and vardiff has real data to retarget from.
// Higher difficulty = smaller (harder) target.
static uint256 ShareTargetFromDifficulty(double difficulty)
{
    if (difficulty <= 0.0) difficulty = 1.0;
    static const uint256 diff1 = CBigNum(bnProofOfWorkLimit).getuint256();
    // shareTarget = diff1 / difficulty
    CBigNum bn; bn.setuint256(diff1);
    // Multiply by 2^16 to keep precision, divide, shift back
    bn <<= 16;
    bn /= (uint64)(difficulty * 65536.0);
    uint256 t = bn.getuint256();
    // Cap at all-ones (maximum, easiest possible)
    if (t < diff1 && difficulty < 1.0) t = ~uint256(0);
    return t;
}

// Expected number of hashes to find one share at a given Stratum difficulty,
// on this chain's scale (difficulty 1 == bnProofOfWorkLimit, which needs on
// average 2^12 = 4096 hashes). Used to turn "shares per second" into H/s.
static const double SHARE_HASHES_AT_DIFF_1 = 4096.0;
static double ExpectedHashesForDifficulty(double difficulty)
{
    if (difficulty <= 0.0) difficulty = 1.0;
    return difficulty * SHARE_HASHES_AT_DIFF_1;
}

// Rebuild the current job from the best chain tip.
// Must be called from the event loop thread (or startup, before the loop).
// Returns true on success. Logs the specific failure reason on false.
static bool RebuildJob()
{
    CRITICAL_BLOCK(cs_main)
    {
        if (!pindexBest) {
            LogPrint("pool", "RebuildJob: no chain tip (pindexBest is null)\n");
            return false;
        }

        CBlockIndex* pindexPrev = pindexBest;
        unsigned int nBits = GetNextWorkRequired(pindexPrev);

        // From the pool, so the template's payout key is in wallet.dat before
        // any miner is handed work against it. Not under P2Pool, whose
        // coinbase pays the window: a key a rebuild, one every share, filled
        // wallet.dat with thousands a day that nothing ever paid.
        vector<unsigned char> vchPubKey;
        if (!fP2PoolMode)
        {
            vchPubKey = GetKeyFromPool();
            // A locked wallet (or a full disk) gives no key. A template built
            // on it would pay its block to "<empty> OP_CHECKSIG", which nobody
            // can ever spend; no template at all is the safe answer, as
            // P2PoolCoinbase already does.
            if (vchPubKey.empty())
            {
                printf("RebuildJob: no wallet key for the coinbase (wallet locked?); no template built\n");
                return false;
            }
        }
        static std::atomic<uint32_t> sExtra{0};
        uint32_t extraNonce = ++sExtra;

        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        // Height first, for the reason given at the matching line in
        // BitcoinMiner: it is what keeps two coinbases at different heights
        // from ever being byte-identical. This builder was missed when that
        // went in, and it produces real blocks -- a pool operator's template
        // is mined and submitted like any other. #58.
        txNew.vin[0].scriptSig << (pindexPrev ? pindexPrev->nHeight + 1 : 0) << nBits << (CBigNum)extraNonce;
        txNew.vout.resize(1);
        if (fP2PoolMode)
            txNew.vout[0].scriptPubKey << OP_TRUE;   // replaced by P2PoolCoinbase
        else
            txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;

        CBlock block;
        block.vtx.push_back(txNew);

        // Fill the block the same way BitcoinMiner() does, because this is the
        // same job: a block that gets mined and submitted for real.
        //
        // It used to differ in two ways, and both were bugs.
        //
        // One pass over mapTransactions is not enough. That map is keyed by
        // hash, so it has no dependency order, and a transaction spending the
        // still-unconfirmed output of another (change from a recent send, most
        // commonly) fails ConnectInputs whenever its parent happens to sit
        // later in map order. A single pass then drops it -- and because map
        // order does not change between rebuilds, every later rebuild drops it
        // again at the same point. Deterministic exclusion, not bad luck: if
        // pool operators mine most of the blocks, a transaction of that shape
        // can stay unconfirmed for as long as its parent does.
        //
        // Diagnosis and fix both come from Vic-Nas, who found it in his fork
        // of this code and described it exactly. The fork has since been
        // deleted, so this carries it back rather than losing it.
        bool fSelectedV4 = false;   // the rules the transactions were chosen under
        int nSelectedRules = 0;     // all of them (RuleSetAt): v3 changes P2SH and finality
        int64 nFees = 0;
        {
            CTxDB txdb("r");
            CRITICAL_BLOCK(cs_mapTransactions)
            {
                map<uint256, CTxIndex> pool;
                // The same order the solo miner uses: best fee per byte first.
                vector<CTransaction*> vOrder;
                MempoolByFeeRate(txdb, vOrder);
                vector<char> vfAlreadyAdded(vOrder.size());
                bool fFoundSomething = true;
                unsigned int sz = 0;
                // The block's time before its contents, as in BitcoinMiner:
                // it was 0 here, so the rules were the clock's.
                block.nTime = max((unsigned int)BlockTimeFloor(pindexPrev),
                                  (unsigned int)GetAdjustedTime());
                // Under MAX_BLOCK_SIGOPS, P2SH included, as ConnectBlock
                // counts. This builder did not count at all, and its blocks
                // are mined and submitted for real.
                bool fSigOpsV4 = RulesV4Active(block.nTime);
                fSelectedV4 = fSigOpsV4;
                nSelectedRules = RuleSetAt(block.nTime);
                unsigned int nBlockSigOps = block.vtx[0].GetSigOpCount(fSigOpsV4);
                // Under MAX_BLOCK_SIZE, which CheckBlock holds every block
                // to; this was MAX_SIZE / 2 (16 MB), and a memory pool past
                // a megabyte made every operator block fail its own check.
                // sz counts transactions only: the header and the coinbase,
                // with what it gains later, have the room taken off.
                unsigned int nSizeLimit = MAX_BLOCK_SIZE - MINER_COINBASE_ROOM;
                if (fP2PoolMode)
                {
                    // Room for the coinbase P2PoolCoinbase writes later: an
                    // output, and a signature operation, per address of the
                    // window, its uncles included.
                    nBlockSigOps = P2POOL_COINBASE_SIGOPS;
                    nSizeLimit = MAX_BLOCK_SIZE - P2POOL_COINBASE_BYTES;
                }
                while (fFoundSomething && sz < nSizeLimit)
                {
                    fFoundSomething = false;
                    for (unsigned int n = 0; n < vOrder.size(); n++)
                    {
                        if (vfAlreadyAdded[n])
                            continue;
                        CTransaction& tx = *vOrder[n];
                        if (tx.IsCoinBase() || !IsFinalForBlock(tx, pindexPrev, block.nTime)) continue;
                        map<uint256, CTxIndex> tmp(pool);
                        int64 nFeesTmp = nFees;
                        unsigned int nTxSigOps = tx.GetSigOpCount(fSigOpsV4);
                        if (!tx.ConnectInputs(txdb, tmp, CDiskTxPos(1,1,1), 0, nFeesTmp,
                                              false, true, tx.GetMinFee(block.vtx.size() < 100), block.nTime,
                                              &nTxSigOps))
                            continue;
                        if (nBlockSigOps + nTxSigOps > MAX_BLOCK_SIGOPS)
                            continue;
                        if (sz + ::GetSerializeSize(tx, SER_NETWORK) >= nSizeLimit)
                            continue;
                        nBlockSigOps += nTxSigOps;
                        nFees = nFeesTmp;
                        swap(pool, tmp);
                        block.vtx.push_back(tx);
                        sz += ::GetSerializeSize(tx, SER_NETWORK);
                        vfAlreadyAdded[n] = true;
                        fFoundSomething = true;
                    }
                }
            }
        }

        // And the fees actually go to the coinbase now. nFees was declared
        // inside the scan loop, so every transaction reset it and the total was
        // thrown away, while this line passed a hardcoded 0. A pool operator
        // collected fees into a block and paid none of them to itself. Solo
        // mining has always passed nFees here; only this builder did not.
        block.vtx[0].vout[0].nValue = block.GetBlockValue(pindexPrev->nHeight + 1, nFees);

        // P2Pool: the coinbase pays the share window instead of this node,
        // and commits to the share chain.
        p2pool::ShareData shareData;
        uint256 shareTarget;
        unsigned int nShareMinTime = 0;
        if (fP2PoolMode &&
            !P2PoolCoinbase(block, pindexPrev->nHeight + 1, nBits, extraNonce, nFees, shareData, shareTarget,
                            nShareMinTime))
            return false;
        if (fP2PoolMode)
        {
            // The coinbase came after the transactions were chosen: check
            // the block it makes as CheckBlock will, rather than trust the
            // room set aside for it.
            unsigned int nSigOps = 0;
            foreach(const CTransaction& tx, block.vtx)
                nSigOps += tx.GetSigOpCount(fSelectedV4);
            if (nSigOps > MAX_BLOCK_SIGOPS || ::GetSerializeSize(block, SER_DISK) > MAX_BLOCK_SIZE)
            {
                LogPrint("pool", "[p2pool] no template: the block would carry %u signature operations, %u bytes\n",
                         nSigOps, (unsigned)::GetSerializeSize(block, SER_DISK));
                return false;
            }
        }

        block.hashPrevBlock  = pindexPrev->GetBlockHash();
        block.hashMerkleRoot = block.BuildMerkleTree();
        // Later, unless that would put the block under other rules than its
        // transactions were chosen under (BitcoinMiner does the same).
        {
            unsigned int nNow = max((unsigned int)BlockTimeFloor(pindexPrev),
                                    (unsigned int)GetAdjustedTime());
            if (RuleSetAt(nNow) == nSelectedRules)
                block.nTime = nNow;
        }
        // And after the share chain's median: a share timed before it is
        // refused, after the miner had been told it was accepted.
        if (fP2PoolMode && block.nTime < nShareMinTime)
        {
            if (RuleSetAt(nShareMinTime) != nSelectedRules)
                return false;
            block.nTime = nShareMinTime;
        }
        block.nBits  = nBits;
        block.nNonce = 1;
        // No AddKey here: the pool wrote this key to wallet.dat before it was
        // handed out.

        StratumJob job;
        job.jobId       = ToHex(&extraNonce, 4);
        job.block       = block;
        job.target      = CBigNum().SetCompact(nBits).getuint256();
        job.height      = nBestHeight + 1;
        if (fP2PoolMode)
        {
            job.shareData        = shareData;
            job.shareChainTarget = shareTarget;
            // The share target is no longer held to the block's: when blocks
            // are the easier, the miner is given theirs, or it would never
            // hand back a block that is not also a share.
            job.shareTarget      = shareTarget < job.target ? job.target : shareTarget;
            job.vBranch          = block.GetMerkleBranch(0);
        }

        gCurrentJob = job;
        gHaveJob    = true;
        gRecentJobs.push_front(job);
        if (gRecentJobs.size() > MAX_RECENT_JOBS)
            gRecentJobs.pop_back();
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Payouts -- event loop thread only
// ---------------------------------------------------------------------------
struct PendingPayout {
    std::string                  id;
    int                          blockHeight;
    int                          matureAtHeight;
    std::map<std::string, int64> amounts; // address -> satoshis
    std::map<std::string, std::string> paidTxids; // address -> txid
    int64                        nextAttempt;

    PendingPayout() : blockHeight(0), matureAtHeight(0), nextAttempt(0) {}
};
static std::vector<PendingPayout> gPendingPayouts;
// The name under which the treasury appears among a round's recipients.
static const char* const TREASURY_RECIPIENT = "treasury";
static std::mutex                 gPayoutLedgerMutex;

struct PoolRoundProof {
    std::string                  id;
    int                          blockHeight;
    int                          matureAtHeight;
    int64                        createdAt;
    std::string                  blockHash;
    std::string                  coinbaseTxid;
    std::string                  foundBy;
    double                       feePercent;
    uint64                       totalShares;
    int64                        coinbaseValue;
    int64                        subsidy;
    int64                        minerReward;
    int64                        operatorReward;
    int                          skippedDust;
    int64                        forfeitedBadAddress;
    std::map<std::string, uint64> shares;
    std::map<std::string, int64>  payouts;
    std::map<std::string, std::string> paidTxids;

    PoolRoundProof()
        : blockHeight(0), matureAtHeight(0), createdAt(0), feePercent(0.0),
          totalShares(0), coinbaseValue(0), subsidy(0), minerReward(0), operatorReward(0),
          skippedDust(0), forfeitedBadAddress(0) {}
};
static std::vector<PoolRoundProof> gPoolRounds;
static std::mutex                  gPoolRoundsMutex;
static const size_t                MAX_POOL_ROUNDS = 200;

static std::string PayoutFilePath()
{
    return GetAppDir() + "/pending_payouts.json";
}

static std::string PoolRoundsFilePath()
{
    if (!strPoolRoundsFile.empty())
        return strPoolRoundsFile;
    return GetAppDir() + "/pool_rounds.json";
}

static std::string PayoutIdForBlock(int blockHeight)
{
    return strprintf("block-%d", blockHeight);
}

static bool PayoutFullyPaid(const PendingPayout& pp)
{
    for (const auto& kv : pp.amounts)
        if (pp.paidTxids.count(kv.first) == 0)
            return false;
    return true;
}

static void SavePendingPayoutsLocked()
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& pp : gPendingPayouts) {
        nlohmann::json obj;
        obj["id"] = pp.id;
        obj["blockHeight"] = pp.blockHeight;
        obj["matureAtHeight"] = pp.matureAtHeight;
        obj["nextAttempt"] = pp.nextAttempt;
        nlohmann::json amounts = nlohmann::json::object();
        for (const auto& kv : pp.amounts)
            amounts[kv.first] = kv.second;
        obj["amounts"] = amounts;
        nlohmann::json paid = nlohmann::json::object();
        for (const auto& kv : pp.paidTxids)
            paid[kv.first] = kv.second;
        obj["paidTxids"] = paid;
        arr.push_back(obj);
    }
    std::string path = PayoutFilePath();
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "w");
    if (f) {
        std::string s = arr.dump(2);
        fwrite(s.c_str(), 1, s.size(), f);
        if (fclose(f) != 0) {
            LogPrint("payout", "[payout] WARNING: could not close %s\n", tmp.c_str());
            return;
        }
#ifdef _WIN32
        remove(path.c_str());
#endif
        if (rename(tmp.c_str(), path.c_str()) != 0)
            LogPrint("payout", "[payout] WARNING: could not replace %s\n", path.c_str());
    } else {
        LogPrint("payout", "[payout] WARNING: could not write %s\n", tmp.c_str());
    }
}

static void LoadPendingPayouts()
{
    std::string path = PayoutFilePath();
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return; // no file yet -- first run, nothing to load
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string s(sz, '\0');
    fread(&s[0], 1, sz, f);
    fclose(f);
    try {
        nlohmann::json arr = nlohmann::json::parse(s);
        std::lock_guard<std::mutex> lk(gPayoutLedgerMutex);
        for (const auto& obj : arr) {
            PendingPayout pp;
            if (obj.contains("blockHeight"))
                pp.blockHeight = obj["blockHeight"].get<int>();
            pp.matureAtHeight = obj["matureAtHeight"].get<int>();
            if (obj.contains("id") && obj["id"].is_string())
                pp.id = obj["id"].get<std::string>();
            if (pp.blockHeight == 0)
                pp.blockHeight = pp.matureAtHeight - COINBASE_MATURITY;
            if (pp.id.empty())
                pp.id = PayoutIdForBlock(pp.blockHeight);
            if (obj.contains("nextAttempt"))
                pp.nextAttempt = obj["nextAttempt"].get<int64>();
            for (auto it = obj["amounts"].begin(); it != obj["amounts"].end(); ++it)
                pp.amounts[it.key()] = it.value().get<int64>();
            if (obj.contains("paidTxids") && obj["paidTxids"].is_object())
                for (auto it = obj["paidTxids"].begin(); it != obj["paidTxids"].end(); ++it)
                    pp.paidTxids[it.key()] = it.value().get<std::string>();
            gPendingPayouts.push_back(pp);
        }
        LogPrint("payout", "[payout] loaded %zu pending payout(s) from disk\n",
                 gPendingPayouts.size());
    } catch (const std::exception& e) {
        LogPrint("payout", "[payout] WARNING: failed to parse %s: %s\n",
                 path.c_str(), e.what());
    }
}

static nlohmann::json PoolRoundToJson(const PoolRoundProof& r)
{
    nlohmann::json j;
    j["id"] = r.id;
    j["blockHeight"] = r.blockHeight;
    j["matureAtHeight"] = r.matureAtHeight;
    j["createdAt"] = r.createdAt;
    j["blockHash"] = r.blockHash;
    j["coinbaseTxid"] = r.coinbaseTxid;
    j["foundBy"] = r.foundBy;
    j["feePercent"] = r.feePercent;
    j["totalShares"] = r.totalShares;
    j["coinbaseValueSatoshis"] = r.coinbaseValue;
    j["coinbaseValueBtf"] = FormatMoney(r.coinbaseValue);
    j["subsidySatoshis"] = r.subsidy;
    j["subsidyBtf"] = FormatMoney(r.subsidy);
    j["minerRewardSatoshis"] = r.minerReward;
    j["minerRewardBtf"] = FormatMoney(r.minerReward);
    j["operatorRewardSatoshis"] = r.operatorReward;
    j["operatorRewardBtf"] = FormatMoney(r.operatorReward);
    j["skippedDust"] = r.skippedDust;
    j["forfeitedBadAddressSatoshis"] = r.forfeitedBadAddress;
    j["forfeitedBadAddressBtf"] = FormatMoney(r.forfeitedBadAddress);

    j["shares"] = nlohmann::json::object();
    for (const auto& kv : r.shares)
        j["shares"][kv.first] = kv.second;

    j["payouts"] = nlohmann::json::object();
    for (const auto& kv : r.payouts) {
        nlohmann::json p;
        p["amountSatoshis"] = kv.second;
        p["amountBtf"] = FormatMoney(kv.second);
        std::map<std::string, std::string>::const_iterator tx = r.paidTxids.find(kv.first);
        if (tx != r.paidTxids.end())
            p["txid"] = tx->second;
        else
            p["txid"] = nullptr;
        j["payouts"][kv.first] = p;
    }
    return j;
}

static void SavePoolRoundsLocked()
{
    nlohmann::json root;
    root["schema"] = "bitflash-pool-rounds-1";
    root["updatedAt"] = GetTime();
    root["rounds"] = nlohmann::json::array();
    for (const PoolRoundProof& r : gPoolRounds)
        root["rounds"].push_back(PoolRoundToJson(r));

    std::string path = PoolRoundsFilePath();
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "w");
    if (!f) {
        LogPrint("payout", "[payout] WARNING: could not write %s\n", tmp.c_str());
        return;
    }
    std::string s = root.dump(2);
    fwrite(s.c_str(), 1, s.size(), f);
    if (fclose(f) != 0) {
        LogPrint("payout", "[payout] WARNING: could not close %s\n", tmp.c_str());
        return;
    }
#ifdef _WIN32
    remove(path.c_str());
#endif
    if (rename(tmp.c_str(), path.c_str()) != 0)
        LogPrint("payout", "[payout] WARNING: could not replace %s\n", path.c_str());
}

static void LoadPoolRounds()
{
    std::string path = PoolRoundsFilePath();
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string s(sz, '\0');
    fread(&s[0], 1, sz, f);
    fclose(f);

    try {
        nlohmann::json root = nlohmann::json::parse(s);
        nlohmann::json arr = root.is_array() ? root : root["rounds"];
        std::lock_guard<std::mutex> lk(gPoolRoundsMutex);
        for (const auto& obj : arr) {
            PoolRoundProof r;
            if (obj.contains("id") && obj["id"].is_string()) r.id = obj["id"].get<std::string>();
            if (obj.contains("blockHeight")) r.blockHeight = obj["blockHeight"].get<int>();
            if (obj.contains("matureAtHeight")) r.matureAtHeight = obj["matureAtHeight"].get<int>();
            if (obj.contains("createdAt")) r.createdAt = obj["createdAt"].get<int64>();
            if (obj.contains("blockHash") && obj["blockHash"].is_string()) r.blockHash = obj["blockHash"].get<std::string>();
            if (obj.contains("coinbaseTxid") && obj["coinbaseTxid"].is_string()) r.coinbaseTxid = obj["coinbaseTxid"].get<std::string>();
            if (obj.contains("foundBy") && obj["foundBy"].is_string()) r.foundBy = obj["foundBy"].get<std::string>();
            if (obj.contains("feePercent")) r.feePercent = obj["feePercent"].get<double>();
            if (obj.contains("totalShares")) r.totalShares = obj["totalShares"].get<uint64>();
            if (obj.contains("coinbaseValueSatoshis")) r.coinbaseValue = obj["coinbaseValueSatoshis"].get<int64>();
            if (obj.contains("subsidySatoshis")) r.subsidy = obj["subsidySatoshis"].get<int64>();
            if (obj.contains("minerRewardSatoshis")) r.minerReward = obj["minerRewardSatoshis"].get<int64>();
            if (obj.contains("operatorRewardSatoshis")) r.operatorReward = obj["operatorRewardSatoshis"].get<int64>();
            if (obj.contains("skippedDust")) r.skippedDust = obj["skippedDust"].get<int>();
            if (obj.contains("forfeitedBadAddressSatoshis")) r.forfeitedBadAddress = obj["forfeitedBadAddressSatoshis"].get<int64>();
            if (obj.contains("shares") && obj["shares"].is_object())
                for (auto it = obj["shares"].begin(); it != obj["shares"].end(); ++it)
                    r.shares[it.key()] = it.value().get<uint64>();
            if (obj.contains("payouts") && obj["payouts"].is_object())
                for (auto it = obj["payouts"].begin(); it != obj["payouts"].end(); ++it) {
                    if (it.value().is_object()) {
                        r.payouts[it.key()] = it.value().value("amountSatoshis", (int64)0);
                        if (it.value().contains("txid") && it.value()["txid"].is_string())
                            r.paidTxids[it.key()] = it.value()["txid"].get<std::string>();
                    } else if (it.value().is_number_integer()) {
                        r.payouts[it.key()] = it.value().get<int64>();
                    }
                }
            if (!r.id.empty())
                gPoolRounds.push_back(r);
        }
        while (gPoolRounds.size() > MAX_POOL_ROUNDS)
            gPoolRounds.erase(gPoolRounds.begin());
        LogPrint("payout", "[payout] loaded %zu pool round proof(s) from disk\n",
                 gPoolRounds.size());
    } catch (const std::exception& e) {
        LogPrint("payout", "[payout] WARNING: failed to parse %s: %s\n",
                 path.c_str(), e.what());
    }
}

static void RecordPoolRound(const PoolRoundProof& round)
{
    std::lock_guard<std::mutex> lk(gPoolRoundsMutex);
    for (PoolRoundProof& existing : gPoolRounds) {
        if (existing.id == round.id) {
            existing = round;
            SavePoolRoundsLocked();
            return;
        }
    }
    gPoolRounds.push_back(round);
    while (gPoolRounds.size() > MAX_POOL_ROUNDS)
        gPoolRounds.erase(gPoolRounds.begin());
    SavePoolRoundsLocked();
}

static void MarkPoolRoundPaid(const std::string& id,
                              const std::string& address,
                              const std::string& txid)
{
    std::lock_guard<std::mutex> lk(gPoolRoundsMutex);
    for (PoolRoundProof& r : gPoolRounds) {
        if (r.id != id)
            continue;
        r.paidTxids[address] = txid;
        SavePoolRoundsLocked();
        return;
    }
}

// Payouts ready to execute are moved here under gPayoutExecMutex.
// A dedicated thread drains this list so SendMoney (which takes cs_main)
// never runs on the event loop thread and can't stall miner I/O.
static std::vector<PendingPayout> gPayoutExecQueue;
static std::mutex                 gPayoutExecMutex;
static std::atomic<bool>          gPayoutThreadRunning{false};

static std::set<std::string>      gQueuedPayouts;

static bool FindRecordedPoolPayout(const std::string& id,
                                   const std::string& address,
                                   int64 amount,
                                   std::string& txidRet)
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin();
             it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            map<string, string>::const_iterator idIt = wtx.mapValue.find("pool_payout_id");
            if (idIt == wtx.mapValue.end() || idIt->second != id)
                continue;
            map<string, string>::const_iterator addrIt = wtx.mapValue.find("pool_payout_address");
            if (addrIt == wtx.mapValue.end() || addrIt->second != address)
                continue;
            map<string, string>::const_iterator amtIt = wtx.mapValue.find("pool_payout_amount");
            if (amtIt == wtx.mapValue.end() || amtIt->second != strprintf("%lld", amount))
                continue;
            txidRet = wtx.GetHash().GetHex();
            return true;
        }
    }
    return false;
}

static void QueuePayouts(int blockHeight,
                         const std::string& blockHash,
                         const std::string& coinbaseTxid,
                         int64 coinbaseValue,
                         const std::string& foundBy,
                         const std::map<std::string, uint64>& shareCount,
                         uint64 total)
{
    PoolRoundProof round;
    round.id = PayoutIdForBlock(blockHeight);
    round.blockHeight = blockHeight;
    round.matureAtHeight = blockHeight + COINBASE_MATURITY;
    round.createdAt = GetTime();
    round.blockHash = blockHash;
    round.coinbaseTxid = coinbaseTxid;
    round.coinbaseValue = coinbaseValue;
    round.foundBy = foundBy;
    round.feePercent = dPoolFeePercent;
    round.totalShares = total;
    round.shares = shareCount;

    if (total == 0) {
        RecordPoolRound(round);
        LogPrint("payout", "[payout] block %d: zero shares recorded -- nothing to pay out\n",
                 blockHeight);
        return;
    }

    double feeFrac = dPoolFeePercent / 100.0;
    if (feeFrac < 0.0) feeFrac = 0.0;
    if (feeFrac > 1.0) feeFrac = 1.0;

    // Compute the block subsidy at the height that was just found.
    // We do not include tx fees in miner payout -- those stay in the operator
    // wallet as part of the coinbase, which is the operator's cut on top of feeFrac.
    // The consensus schedule itself, so the 64-halving end (BIP42) holds here too.
    int64 nSubsidy = CBlock().GetBlockValue(blockHeight, 0);
    int64 minerReward = (int64)((double)nSubsidy * (1.0 - feeFrac));
    int64 operatorCut = nSubsidy - minerReward;
    round.subsidy = nSubsidy;
    round.minerReward = minerReward;
    round.operatorReward = operatorCut;

    PendingPayout pp;
    pp.id = round.id;
    pp.blockHeight = blockHeight;
    pp.matureAtHeight = blockHeight + COINBASE_MATURITY;

    int skipped = 0;
    int64 burned = 0; // amount owed to miners with bad/empty addresses
    for (auto& kv : shareCount) {
        int64 amount = (int64)(((double)kv.second / (double)total) * (double)minerReward);
        if (amount < CENT) {
            skipped++;
            continue;
        }
        uint160 addrCheck;
        if (kv.first.empty() || !AddressToHash160(kv.first, addrCheck)) {
            // Address was invalid at authorize time (warned then). Their share
            // of the reward cannot be paid -- log the amount so it's visible.
            burned += amount;
            LogPrint("payout", "[payout] WARNING: %s owed to miner with invalid"
                     " address '%s' -- cannot pay out, amount forfeited\n",
                     FormatMoney(amount).c_str(), kv.first.c_str());
            continue;
        }
        pp.amounts[kv.first] = amount;
        round.payouts[kv.first] = amount;
    }
    round.skippedDust = skipped;
    round.forfeitedBadAddress = burned;

    // The operator's cut goes to the treasury when so configured: one more
    // recipient in the same round, paid, recorded and recovered like any
    // miner, under the name the payout thread turns into the script.
    if (fPoolFeeToTreasury && operatorCut >= CENT && treasury::Configured())
    {
        pp.amounts[TREASURY_RECIPIENT] = operatorCut;
        round.payouts[TREASURY_RECIPIENT] = operatorCut;
    }

    {
        std::lock_guard<std::mutex> lk(gPayoutLedgerMutex);
        gPendingPayouts.push_back(pp);
        SavePendingPayoutsLocked();
    }
    RecordPoolRound(round);

    LogPrint("payout",
             "[payout] block %d: subsidy %s BTF, miners get %s"
             " (fee %.2f%% = %s to operator),"
             " %zu recipients, matures height %d,"
             " %d below dust%s\n",
             blockHeight,
             FormatMoney(nSubsidy).c_str(),
             FormatMoney(minerReward).c_str(),
             dPoolFeePercent,
             FormatMoney(operatorCut).c_str(),
             pp.amounts.size(), pp.matureAtHeight, skipped,
             burned > 0 ? (", " + FormatMoney(burned) + " forfeited (bad address)").c_str()
                        : "");
}

// Called from event loop: copy matured entries to the exec queue (fast).
// The ledger entry stays on disk until every recipient has a txid recorded.
// On restart, FindRecordedPoolPayout() checks wallet metadata before sending,
// so a crash after SendMoney but before the ledger update does not double-pay.
static void FlushMaturePayouts()
{
    std::vector<PendingPayout> ready;
    {
        std::lock_guard<std::mutex> ledger(gPayoutLedgerMutex);
        std::lock_guard<std::mutex> queue(gPayoutExecMutex);
        int64 now = GetTime();
        for (const PendingPayout& pp : gPendingPayouts) {
            if (nBestHeight < pp.matureAtHeight)
                continue;
            if (pp.nextAttempt > now)
                continue;
            if (PayoutFullyPaid(pp))
                continue;
            if (gQueuedPayouts.count(pp.id))
                continue;
            LogPrint("payout", "[payout] block height %d matured -- queuing payout %s (%zu recipients)\n",
                     pp.matureAtHeight, pp.id.c_str(), pp.amounts.size());
            ready.push_back(pp);
            gQueuedPayouts.insert(pp.id);
        }
        for (auto& pp : ready)
            gPayoutExecQueue.push_back(pp);
    }
}

// Payout execution thread: drains gPayoutExecQueue, calls SendMoney.
// Runs independently of the event loop so slow wallet operations
// (SendMoney takes cs_main) never stall miner I/O.
static void PayoutThreadFn(void*)
{
    gPayoutThreadRunning = true;
    LogPrint("payout", "[payout] payout thread started\n");

    while (!fShutdown && gPoolRunning) {
        std::vector<PendingPayout> batch;
        {
            std::lock_guard<std::mutex> lk(gPayoutExecMutex);
            batch.swap(gPayoutExecQueue);
        }

        for (auto& ppQueued : batch) {
            LogPrint("payout", "[payout] executing payments for block matured at %d"
                     " (%zu miners)\n", ppQueued.matureAtHeight, ppQueued.amounts.size());
            bool fAbortBatch = false;
            for (auto& kv : ppQueued.amounts) {
                bool alreadyPaid = false;
                {
                    std::lock_guard<std::mutex> lk(gPayoutLedgerMutex);
                    for (const PendingPayout& pp : gPendingPayouts)
                        if (pp.id == ppQueued.id && pp.paidTxids.count(kv.first))
                            alreadyPaid = true;
                }
                if (alreadyPaid)
                    continue;

                CScript sc;
                uint160 h160;
                if (kv.first == TREASURY_RECIPIENT) {
                    if (!treasury::Script(sc)) {
                        LogPrint("payout", "[payout] SKIPPED treasury: not configured on this network\n");
                        continue;
                    }
                } else if (!AddressToHash160(kv.first, h160)) {
                    // Should not happen -- bad addresses are filtered in QueuePayouts
                    LogPrint("payout", "[payout] SKIPPED bad address '%s'\n",
                             kv.first.c_str());
                    continue;
                } else {
                    sc << OP_DUP << OP_HASH160 << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
                }
                CWalletTx wtx;
                wtx.mapValue["comment"] = strprintf("Pool payout height %d", ppQueued.matureAtHeight);
                wtx.mapValue["pool_payout_id"] = ppQueued.id;
                wtx.mapValue["pool_payout_address"] = kv.first;
                wtx.mapValue["pool_payout_amount"] = strprintf("%lld", kv.second);

                std::string txid;
                if (FindRecordedPoolPayout(ppQueued.id, kv.first, kv.second, txid))
                {
                    LogPrint("payout", "[payout] recovered recorded payout %s to %s"
                             " from wallet tx %s\n",
                             FormatMoney(kv.second).c_str(), kv.first.c_str(), txid.c_str());
                    MarkPoolRoundPaid(ppQueued.id, kv.first, txid);
                }
                else if (SendMoney(sc, kv.second, wtx))
                {
                    txid = wtx.GetHash().GetHex();
                    LogPrint("payout", "[payout] paid %s to %s\n",
                              FormatMoney(kv.second).c_str(), kv.first.c_str());
                    MarkPoolRoundPaid(ppQueued.id, kv.first, txid);
                }
                else
                {
                    LogPrint("payout", "[payout] FAILED to pay %s to %s"
                              " (insufficient funds or wallet locked?)\n",
                              FormatMoney(kv.second).c_str(), kv.first.c_str());
                    std::lock_guard<std::mutex> lk(gPayoutLedgerMutex);
                    for (PendingPayout& pp : gPendingPayouts)
                        if (pp.id == ppQueued.id)
                            pp.nextAttempt = GetTime() + 60;
                    SavePendingPayoutsLocked();
                    fAbortBatch = true;
                    break;
                }

                {
                    std::lock_guard<std::mutex> lk(gPayoutLedgerMutex);
                    for (PendingPayout& pp : gPendingPayouts) {
                        if (pp.id != ppQueued.id)
                            continue;
                        pp.paidTxids[kv.first] = txid;
                        pp.nextAttempt = 0;
                        SavePendingPayoutsLocked();
                        break;
                    }
                }
            }

            {
                std::lock_guard<std::mutex> ledger(gPayoutLedgerMutex);
                for (auto it = gPendingPayouts.begin(); it != gPendingPayouts.end(); ) {
                    if (it->id == ppQueued.id && PayoutFullyPaid(*it)) {
                        LogPrint("payout", "[payout] payout %s complete -- removing from ledger\n",
                                 it->id.c_str());
                        it = gPendingPayouts.erase(it);
                        SavePendingPayoutsLocked();
                    } else {
                        ++it;
                    }
                }
            }
            {
                std::lock_guard<std::mutex> lk(gPayoutExecMutex);
                gQueuedPayouts.erase(ppQueued.id);
            }
            if (fAbortBatch)
                continue;
        }

        Sleep(500); // check for new work every 500ms
    }

    gPayoutThreadRunning = false;
    LogPrint("payout", "[payout] payout thread stopped\n");
}

// ---------------------------------------------------------------------------
// GUI stats snapshot -- event loop writes, GUI threads read
// ---------------------------------------------------------------------------
struct StatsSnapshot {
    int    authorizedMiners = 0;
    int    blocksFound      = 0;
    uint64 roundShares      = 0;
    double totalHashRate    = 0.0;
};
static StatsSnapshot                   gStats;
static std::vector<PoolWorkerStatView> gWorkerStats;
static std::vector<PendingPayoutView>  gPayoutViews;
static std::mutex                      gStatsMutex;
static int64                           gLastPoolStatusWrite = 0;

void GetPoolOperatorStats(int& authorizedMiners, int& blocksFound, uint64& roundShares, double& totalHashRate)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    authorizedMiners = gStats.authorizedMiners;
    blocksFound      = gStats.blocksFound;
    roundShares      = gStats.roundShares;
    totalHashRate    = gStats.totalHashRate;
}

void GetPoolWorkerStats(std::vector<PoolWorkerStatView>& out)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    out = gWorkerStats;
}

void GetPendingPayouts(std::vector<PendingPayoutView>& out)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    out = gPayoutViews;
}

static std::string PoolStatusFilePath()
{
    if (!strPoolStatusFile.empty())
        return strPoolStatusFile;
    return GetAppDir() + "/pool_status.json";
}

static void WritePoolStatusJsonLocked()
{
    nlohmann::json j;
    j["schema"] = "bitflash-pool-status-1";
    // Which chain this pool pays on. It said "bitflash" on both networks, so a
    // dashboard had no way to tell a test pool from a real one.
    j["network"] = IsTestNet() ? "bitflash-testnet" : "bitflash";
    j["updatedAt"] = GetTime();

    j["operator"] = {
        {"name", strPoolName},
        {"btfAddress", BtfLocalAddress()},
        {"feePercent", dPoolFeePercent},
        {"feeTo", fPoolFeeToTreasury && treasury::Configured() ? "treasury" : "operator"},
        {"dashboardUrl", strPoolDashboardUrl},
        {"roundsFile", "pool_rounds.json"}
    };

    j["node"] = {
        {"height", nBestHeight},
        {"poolRunning", (bool)gPoolRunning},
        {"mode", nMineMode.load()}
    };

    j["pool"] = {
        {"authorizedMiners", gStats.authorizedMiners},
        {"blocksFoundSession", gStats.blocksFound},
        {"roundShares", gStats.roundShares},
        {"hashRate", gStats.totalHashRate}
    };

    j["workers"] = nlohmann::json::array();
    for (const PoolWorkerStatView& row : gWorkerStats) {
        j["workers"].push_back({
            {"address", row.address},
            {"worker", row.worker},
            {"totalShares", row.totalShares},
            {"roundShares", row.roundShares},
            {"lastSeen", row.lastSeen},
            {"hashRate", row.hashRate}
        });
    }

    j["pendingPayouts"] = nlohmann::json::array();
    for (const PendingPayoutView& row : gPayoutViews) {
        j["pendingPayouts"].push_back({
            {"matureAtHeight", row.matureAtHeight},
            {"recipients", row.recipients},
            {"totalAmountSatoshis", row.totalAmount},
            {"totalAmountBtf", FormatMoney(row.totalAmount)}
        });
    }

    j["recentRounds"] = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lk(gPoolRoundsMutex);
        size_t start = gPoolRounds.size() > 10 ? gPoolRounds.size() - 10 : 0;
        for (size_t i = start; i < gPoolRounds.size(); i++) {
            const PoolRoundProof& r = gPoolRounds[i];
            int unpaid = 0;
            for (const auto& kv : r.payouts)
                if (r.paidTxids.count(kv.first) == 0)
                    unpaid++;
            j["recentRounds"].push_back({
                {"id", r.id},
                {"blockHeight", r.blockHeight},
                {"blockHash", r.blockHash},
                {"coinbaseTxid", r.coinbaseTxid},
                {"totalShares", r.totalShares},
                {"payouts", (int)r.payouts.size()},
                {"unpaidPayouts", unpaid},
                {"coinbaseValueBtf", FormatMoney(r.coinbaseValue)},
                {"minerRewardBtf", FormatMoney(r.minerReward)}
            });
        }
    }

    std::string path = PoolStatusFilePath();
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "w");
    if (!f) {
        LogPrint("pool", "[pool] WARNING: could not write status file %s\n", tmp.c_str());
        return;
    }
    std::string s = j.dump(2);
    fwrite(s.c_str(), 1, s.size(), f);
    if (fclose(f) != 0) {
        LogPrint("pool", "[pool] WARNING: could not close status file %s\n", tmp.c_str());
        return;
    }
#ifdef _WIN32
    remove(path.c_str());
#endif
    if (rename(tmp.c_str(), path.c_str()) != 0)
        LogPrint("pool", "[pool] WARNING: could not replace status file %s\n", path.c_str());
}

// ---------------------------------------------------------------------------
// Miner state -- event loop thread only
// ---------------------------------------------------------------------------
static std::atomic<uint32_t> gNextExtranonce2{1};

// Vardiff target: aim for one share every VARDIFF_TARGET_SECS seconds per miner.
// After VARDIFF_SHARES_PER_CHECK shares, recalculate and adjust if rate is off
// by more than 50%. Shares are the stable unit; difficulty floats to match.
static const int64  VARDIFF_TARGET_SECS       = 15;  // one share every 15s
static const uint64 VARDIFF_SHARES_PER_CHECK  = 5;   // re-evaluate every 5 shares
static const double VARDIFF_RETARGET_RATIO    = 1.5; // adjust if >50% off target
static const double VARDIFF_MIN               = 0.001;
static const double VARDIFF_MAX               = 1e12;
// If a miner has gone this long since its vardiff window opened with ZERO
// shares, the normal vardiff retarget (which only fires after
// VARDIFF_SHARES_PER_CHECK shares) can never trigger -- it has no samples to
// act on. This is the residual gap the ShareTargetFromDifficulty fix above
// doesn't cover: even with a correctly-easy diff-1 target, a miner stuck in
// RandomX light mode (or otherwise much slower than expected) can go
// indefinitely without a single share, and difficulty would never drop to
// meet it. Force a difficulty cut on a timeout instead of waiting for shares
// that will never come.
static const int64  VARDIFF_STALL_SECS        = 45;  // 3x share target -- reacts faster without false-triggering on normal variance
static const double VARDIFF_STALL_CUT         = 4.0; // divide difficulty by this much

struct Miner {
    btf_socket_t fd;
    std::string  peer;                   // numeric address it connected from
    std::string  peerKey;                // what the per-address quota counts
    bool         fLoopback     = false;  // from this machine (or Tor, for the central pool)
    bool         authorised    = false;
    std::string  address;
    std::string  worker;
    std::string  readBuf;
    int64        connectTime;
    uint64       sessionShares  = 0;
    uint64       roundShares    = 0;
    uint64       totalShares    = 0;
    int64        lastSeen       = 0;
    uint32_t     extranonce2;

    // Which stratum the miner speaks. Bitflash's own worker uses the Bitcoin
    // dialect (mining.subscribe / mining.notify / mining.submit). XMRig and
    // its relatives use the CryptoNote one (login / job / submit), with a
    // JSON-RPC 2.0 envelope and the share target inside the job -- there is
    // no set_difficulty there, a new job carries the new target.
    bool         fCryptoNote    = false;
    std::string  agent;                  // what the CryptoNote miner said it was

    // Vardiff state
    double       difficulty     = 1.0;   // current share difficulty sent to this miner
    uint256      shareTarget;            // derived from difficulty; what we check against
    int64        vardiffWindowStart = 0; // when the current vardiff window opened
    uint64       vardiffShares  = 0;     // shares found in current window

    // Hashrate estimate -- EWMA of (expected hashes per share at current
    // difficulty) / (seconds since the previous share). We had all the data
    // to compute this (difficulty + share timing) but never actually did,
    // so pool/GUI hashrate always showed as zero/missing.
    int64        lastShareTime  = 0;     // GetTime() of the previous accepted share
    double       hashRate       = 0.0;   // smoothed H/s estimate

    explicit Miner(btf_socket_t f)
        : fd(f), connectTime(GetTime()),
          extranonce2(gNextExtranonce2.fetch_add(1)) {}
};

static std::vector<Miner*> gMiners;

struct FoundBlock { int height; int64 ts; std::string addr; };
static std::deque<FoundBlock> gFoundBlocks;

// ---------------------------------------------------------------------------
// Accept queue -- accept threads push; event loop pops at top of each tick
// ---------------------------------------------------------------------------
// peerKey: what the per-address quota counts by, the numeric address. An
// IPv6 machine can pick new addresses at will, so on IPv6 that quota is weak;
// the local network's 48 and the 12 slots kept for 127.0.0.1 still hold.
// Counting by /64 would put a whole home network (one ULA /64, or every
// link-local peer) under one quota of 8.
struct ReadyConn { btf_socket_t fd; std::string peer; std::string peerKey; bool fLoopback; };
static std::vector<ReadyConn> gReadyQueue;
static std::mutex             gReadyMutex;
// Accepted sockets waiting for the event loop. Bounded so that a stalled loop
// cannot turn a connection flood into every descriptor of the process.
static const size_t MAX_READY_QUEUE = 64;

// False when the queue is full; the caller closes the socket.
static bool PushReady(btf_socket_t s, const std::string& strPeer, const std::string& strPeerKey, bool fLoopback)
{
    std::lock_guard<std::mutex> lk(gReadyMutex);
    if (gReadyQueue.size() >= MAX_READY_QUEUE)
        return false;
    gReadyQueue.push_back(ReadyConn{s, strPeer, strPeerKey, fLoopback});
    return true;
}

// ---------------------------------------------------------------------------
// I/O helpers -- event loop thread only
// ---------------------------------------------------------------------------

// The self-test drives HandleLine without a socket and reads what the pool
// would have sent from here instead.
static std::string* gSelfTestCapture = NULL;

// Sockets a send failed on. The event loop drops their miners at the end of
// the tick: a line that went out in part leaves the stream unusable anyway.
static std::set<btf_socket_t> gSendFailed;

// Accepted miner sockets are non-blocking. A miner that never reads fills
// its socket's send buffer; a blocking send would then hold this thread, and
// every other miner with it, for as long as that miner liked. A line that
// does not go out at once marks the socket failed and its miner is dropped.
static bool StratumSetNonBlocking(btf_socket_t fd)
{
#ifdef _WIN32
    u_long nOne = 1;
    return ioctlsocket(fd, FIONBIO, &nOne) == 0;
#else
    int fl = fcntl(fd, F_GETFL, 0);
    return fl != -1 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) != -1;
#endif
}

// Send of a complete JSON line, or false at once. Called only from the
// event loop so no other thread is writing to the same fd concurrently.
static bool SendLine(btf_socket_t fd, const json& j)
{
    std::string s = j.dump() + "\n";
    if (gSelfTestCapture) { *gSelfTestCapture += s; return true; }
    if (gSendFailed.count(fd)) return false;
    int off = 0, total = (int)s.size();
    while (off < total) {
        int r = send(fd, s.c_str() + off, total - off, SEND_FLAGS);
        if (r <= 0) { gSendFailed.insert(fd); return false; }
        off += r;
    }
    return true;
}

// Ceilings on what an unauthenticated peer can make the pool operator hold.
// Stratum lines are a few hundred bytes and a real pool this size will not see
// anything near a thousand miners.
static const size_t MAX_STRATUM_LINE = 64 * 1024;
static const size_t MAX_POOL_MINERS  = 1000;
// P2Pool serves one person's own rigs, now possibly from the local network
// (-p2poolbind). The event loop watches them with one select() set, which
// holds 64 sockets on Windows; past that, miners would sit unheard.
static const size_t MAX_P2POOL_MINERS = 60;
// Of those, what the local network may take, all its machines together and
// one address alone. The rest is kept for 127.0.0.1, so a stranger on the
// network cannot lock out the XMRig on the node's own machine.
static const size_t MAX_P2POOL_LAN_MINERS = 48;
static const size_t MAX_P2POOL_PER_PEER   = 8;
// A P2Pool connection that has not logged in by then is dropped: XMRig logs
// in as soon as it connects. Idle sockets only hold slots.
static const int64  P2POOL_LOGIN_SECS     = 30;

// What a miner calls itself (login, worker, agent), and anything else it
// sends that the log repeats, is shown short and printable: a JSON string can
// carry line breaks, and the log would print them as forged lines of its own.
// In P2Pool mode the login is only a label anyway; a real payment address is
// short and printable, so the central pool's payouts see the same string.
static std::string StratumLabel(const std::string& s, size_t nMax = 64)
{
    std::string out;
    for (size_t i = 0; i < s.size() && out.size() < nMax; i++)
        out += (s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : '?';
    return out;
}

// A login as a payment address: the base58 decoder skips whitespace around
// it, so an address sent with a trailing newline was paid before labels were
// cleaned, and still is.
static std::string StratumAddress(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n\f\v");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n\f\v");
    return StratumLabel(s.substr(a, b - a + 1));
}

// Non-blocking recv: pull whatever bytes are available now into buf, then
// return one complete line if one is ready. Three outcomes:
//   true  -- line is filled; buf may still contain more lines
//   false, errno EAGAIN/EWOULDBLOCK (or FIONREAD==0) -- no data right now
//   false, r==0 -- clean disconnect; caller must treat fd as dead
// Caller distinguishes disconnect from "not yet" by checking whether
// line.empty() after a false return (line is "" on both paths, so we
// use a separate out-param for the disconnect signal).
static bool RecvLine(btf_socket_t fd, std::string& buf,
                     std::string& line, bool& disconnected)
{
    disconnected = false;
    char tmp[4096];

    // Miner sockets are non-blocking (StratumSetNonBlocking), so recv() is
    // asked every time. Windows used to ask only when FIONREAD showed bytes,
    // which never sees a peer that closed without sending: select() kept
    // reporting it readable and the slot stayed taken.
#ifdef _WIN32
    {
        int r = recv(fd, tmp, (int)sizeof(tmp) - 1, 0);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
        else if (WSAGetLastError() != WSAEWOULDBLOCK) { disconnected = true; return false; }
    }
#else
    {
        int r = recv(fd, tmp, sizeof(tmp) - 1, MSG_DONTWAIT);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { disconnected = true; return false; }
    }
#endif

    // A peer that never sends a newline would otherwise grow this buffer for
    // as long as it keeps writing, and it does not have to authorize first --
    // the read happens before any of that. Stratum lines are a few hundred
    // bytes; anything past the cap is not a slow line, it is a flood.
    if (buf.size() > MAX_STRATUM_LINE) {
        disconnected = true;
        buf.clear();
        return false;
    }

    size_t pos = buf.find('\n');
    if (pos == std::string::npos) return false; // no complete line yet

    line = buf.substr(0, pos);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    buf = buf.substr(pos + 1);
    return true;
}

// ---------------------------------------------------------------------------
// Job helpers
// ---------------------------------------------------------------------------
static CBlock BuildMinerBlock(const StratumJob& job, uint32_t extranonce2)
{
    CBlock blk = job.block;
    blk.vtx[0].vin[0].scriptSig << (CBigNum)extranonce2;
    blk.hashMerkleRoot = blk.BuildMerkleTree();
    return blk;
}

// shareTarget is per-miner (set by vardiff) and passed explicitly so the
// value in p[3] of mining.notify always matches what HandleLine checks on submit.
// This is the single source of truth for share difficulty.
static json MakeNotifyParams(const StratumJob& job, const CBlock& b,
                              const uint256& shareTarget, bool clean)
{
    unsigned char hdr[80];
    memcpy(hdr,    &b.nVersion,       4);
    memcpy(hdr+4,  &b.hashPrevBlock,  32);
    memcpy(hdr+36, &b.hashMerkleRoot, 32);
    memcpy(hdr+68, &b.nTime,          4);
    memcpy(hdr+72, &b.nBits,          4);
    memcpy(hdr+76, &b.nNonce,         4);
    unsigned char tgt[32]; memcpy(tgt, &shareTarget, 32);
    return json::array({job.jobId, ToHex(hdr, 80),
                        b.hashPrevBlock.GetHex(), ToHex(tgt, 32), clean});
}

// The same job as a CryptoNote miner (XMRig, SRBMiner) expects it:
//   blob       the PoW v2 input -- the header laid out with the nonce at
//              byte 39, nonce zeroed (a non-zero nonce puts XMRig in its
//              NiceHash mode, where it only iterates the low three bytes)
//   target     the top 64 bits of the share target, little-endian hex; the
//              miner compares bytes 24..31 of the hash against it
//   seed_hash  the 32-byte RandomX key
//   algo       rx/0 -- Bitflash uses RandomX with the reference parameters
// Returns null when the job predates the PoW switch: the miner cannot hash
// that (wrong key, wrong nonce position), and the template is refreshed
// within a minute anyway.
static json MakeCryptoNoteJob(const StratumJob& job, const CBlock& b,
                              const uint256& shareTarget)
{
    unsigned char hdr[80];
    memcpy(hdr,    &b.nVersion,       4);
    memcpy(hdr+4,  &b.hashPrevBlock,  32);
    memcpy(hdr+36, &b.hashMerkleRoot, 32);
    memcpy(hdr+68, &b.nTime,          4);
    memcpy(hdr+72, &b.nBits,          4);
    memset(hdr+76, 0,                 4);
    if (PoWVersionAt(b.nTime) != 2)
        return nullptr;
    unsigned char input[POW_INPUT_MAX];
    size_t n = PoWInputV2(hdr, input);
    const unsigned char* tgt = (const unsigned char*)&shareTarget;
    return json{{"blob", ToHex(input, n)},
                {"job_id", job.jobId},
                {"target", ToHex(tgt + 24, 8)},
                {"algo", "rx/0"},
                {"height", job.height},
                {"seed_hash", PoWSeedV2Hex()}};
}

static void SendJob(Miner* m, bool clean)
{
    if (!gHaveJob) return;
    // P2Pool: every miner works to the share chain's target, the one a share
    // is checked against; there is no per-miner difficulty to tune.
    if (fP2PoolMode)
        m->shareTarget = gCurrentJob.shareTarget;
    CBlock mb = BuildMinerBlock(gCurrentJob, m->extranonce2);
    json n;
    if (m->fCryptoNote) {
        json j = MakeCryptoNoteJob(gCurrentJob, mb, m->shareTarget);
        if (j.is_null()) {
            LogPrint("worker", "[pool->worker] job %s is PoW v1, not sent to %s (RandomX miner)\n",
                     gCurrentJob.jobId.c_str(), m->address.c_str());
            return;
        }
        n = {{"jsonrpc","2.0"},{"method","job"},{"params", j}};
    } else {
        // Use this miner's own shareTarget (set by vardiff) in the notify params.
        // The participant miner reads p[3] as its share target, and HandleLine
        // checks m->shareTarget on submit -- both sides now use the same value.
        n = {{"id",nullptr},{"method","mining.notify"},
             {"params", MakeNotifyParams(gCurrentJob, mb, m->shareTarget, clean)}};
    }
    if (!SendLine(m->fd, n))
        LogPrint("worker", "[pool->worker] job send FAILED for %s -- miner will be dropped\n",
                 m->address.empty() ? "(not yet authorized)" : m->address.c_str());
}

static void BroadcastJob(bool clean)
{
    if (!gHaveJob) return;
    int sent = 0;
    for (Miner* m : gMiners) {
        if (!m->authorised) continue;
        SendJob(m, clean);
        sent++;
    }
    LogPrint("pool", "[pool] job %s broadcast to %d miner(s)\n",
             gCurrentJob.jobId.c_str(), sent);
}

// ---------------------------------------------------------------------------
// Stratum message handler -- called for each complete line from a miner
// Returns false if the miner should be disconnected immediately.
// ---------------------------------------------------------------------------
static bool HandleLine(Miner* m, const std::string& rawLine,
                       std::map<std::string, uint64>& roundShareCount,
                       uint64& roundShareTotal,
                       int& blocksFoundThisSession)
{
    json req;
    try {
        // Fast pre-parse depth check to prevent stack overflow in json::parse.
        // Legitimate Stratum requests have a depth of at most 4.
        int depth = 0;
        bool in_string = false;
        bool escape = false;
        for (char c : rawLine) {
            if (in_string) {
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') in_string = false;
            } else {
                if (c == '"') in_string = true;
                else if (c == '{' || c == '[') {
                    if (++depth > 20) {
                        LogPrint("worker", "[worker] JSON too deeply nested from %s\n",
                                 m->address.empty() ? "(unauth)" : m->address.c_str());
                        return true;
                    }
                } else if (c == '}' || c == ']') {
                    depth--;
                }
            }
        }
        req = json::parse(rawLine);
    }
    catch (...) {
        LogPrint("worker", "[worker] JSON parse error from %s: %.80s\n",
                 m->address.empty() ? "(unauth)" : m->address.c_str(),
                 StratumLabel(rawLine, 80).c_str());
        return true; // don't disconnect on bad JSON, just ignore the line
    }

    // value() throws when the document is not an object, and again when a key
    // is present with the wrong type -- "[1,2,3]" and {"method":1} are both
    // valid JSON that parse cleanly and then blow up on the next two lines.
    if (!req.is_object() || (req.contains("method") && !req["method"].is_string())) {
        LogPrint("worker", "[worker] malformed request from %s: %.80s\n",
                 m->address.empty() ? "(unauth)" : m->address.c_str(),
                 StratumLabel(rawLine, 80).c_str());
        return true;
    }

    json        id     = req.value("id", json(nullptr));
    std::string method = req.value("method", "");

    // Reply helper: always sends result+error pair as Stratum requires
    // A CryptoNote miner announces itself with "login"; from then on every
    // reply to it wears the JSON-RPC 2.0 envelope, with errors as an object.
    // That shape is not cosmetic: XMRig acts only on an error *object* --
    // {"error":"unknown method"} as a string is ignored, and the miner sat at
    // its banner forever. That is how the first public-pool user found out
    // the pool did not speak its language.
    if (method == "login" || method == "submit" || method == "keepalived" || method == "getjob")
        m->fCryptoNote = true;

    auto reply = [&](json result, std::string error = "") {
        json msg;
        if (m->fCryptoNote) {
            if (!error.empty())
                msg = json{{"id",id},{"jsonrpc","2.0"},{"result",nullptr},
                           {"error",json{{"code",-1},{"message",error}}}};
            else
                msg = json{{"id",id},{"jsonrpc","2.0"},{"error",nullptr},
                           {"result", result.is_boolean() ? json{{"status","OK"}} : result}};
        } else {
            json err = error.empty() ? json(nullptr) : json(error);
            msg = json{{"id",id},{"result",result},{"error",err}};
        }
        if (!SendLine(m->fd, msg))
            LogPrint("worker", "[pool->worker] reply send FAILED for %s (method=%s)\n",
                     m->address.empty() ? "(unauth)" : m->address.c_str(),
                     StratumLabel(method).c_str());
    };

    // Shared by both dialects' first message. A pool that is still catching
    // up hands out templates for a height the network has already passed,
    // and every share a worker submits against them is wasted -- not
    // rejected, wasted, because the pool accepts them and they can never
    // become a block anybody keeps. Seen on the first day of the public
    // pool: it came up, took an hour to sync over Tor, and served height-1
    // jobs to the door the whole time. The peers' median height is in every
    // handshake, so the pool knows.
    auto refuseIfBehind = [&]() -> bool {
        int nNet = GetPeerMedianHeight();
        if (nNet >= 0 && nBestHeight < nNet - 3) {
            LogPrint("worker", "[pool] refusing fd=%d: pool is %d blocks behind the network (%d vs %d)\n",
                     (int)m->fd, nNet - nBestHeight, nBestHeight, nNet);
            reply(nullptr, strprintf("pool is syncing (%d blocks behind); try again in a few minutes",
                                     nNet - nBestHeight));
            return true;
        }
        return false;
    };

    // Vardiff state and the first job, once a miner of either dialect is in.
    auto authorise = [&]() {
        m->authorised = true;
        m->lastSeen   = GetTime();
        m->difficulty       = 1.0;
        m->shareTarget      = ShareTargetFromDifficulty(m->difficulty);
        m->vardiffWindowStart = GetTime();
        m->vardiffShares    = 0;
    };

    // ------------------------------------------------------------------
    if (method == "login") {
        // XMRig: {"method":"login","params":{"login":ADDRESS,"pass":"x",
        //         "agent":"XMRig/6.26.0","algo":["rx/0",...]}}
        if (refuseIfBehind())
            return false;
        auto& p = req["params"];
        if (!p.is_object() || !p.contains("login") || !p["login"].is_string()) {
            reply(nullptr, "login must carry a Bitflash payment address");
            return false;
        }
        if (PoWVersionAt(GetAdjustedTime()) < 2) {
            // Before the switch there is no job this miner could hash. Say
            // when, in the error XMRig prints, instead of leaving it waiting.
            LogPrint("worker", "[pool] refusing RandomX miner fd=%d before the PoW v2 switch\n", (int)m->fd);
            reply(nullptr, strprintf("Bitflash PoW v2 (RandomX-miner compatible) activates at block time %u; "
                                     "until then mine with: bitflash -participant=POOL.btf", PoWV2Time()));
            return false;
        }
        if (!gHaveJob) {
            reply(nullptr, "pool has no work yet; try again in a minute");
            return false;
        }
        m->address = p["login"].get<std::string>();
        m->worker  = (p.contains("pass") && p["pass"].is_string()) ? p["pass"].get<std::string>() : "worker";
        m->agent   = (p.contains("agent") && p["agent"].is_string()) ? p["agent"].get<std::string>() : "";
        m->address = StratumAddress(m->address);
        m->worker  = StratumLabel(m->worker);
        m->agent   = StratumLabel(m->agent);
        uint160 h160; bool validAddr = AddressToHash160(m->address, h160);
        // P2Pool pays the node's own address, whatever this miner logs in
        // as: the name is only a label in the log.
        if (fP2PoolMode)
            validAddr = true;
        if (!validAddr) {
            // The Bitcoin-dialect worker is let through with an invalid
            // address because it is our own software and the log says why.
            // A third-party miner shows its user the error string, so here
            // refusing is the message that actually reaches a person.
            LogPrint("worker", "[pool] refusing RandomX miner fd=%d: '%s' is not a Bitflash payment address\n",
                     (int)m->fd, m->address.c_str());
            reply(nullptr, "not a Bitflash payment address (use the kind -newaddress prints, not a .btf)");
            return false;
        }
        authorise();
        if (fP2PoolMode)
            m->shareTarget = gCurrentJob.shareTarget;
        CBlock mb = BuildMinerBlock(gCurrentJob, m->extranonce2);
        json job = MakeCryptoNoteJob(gCurrentJob, mb, m->shareTarget);
        if (job.is_null()) {
            reply(nullptr, "pool template predates the PoW v2 switch; try again in a minute");
            return false;
        }
        std::string sid = ToHex(&m->fd, 4);
        LogPrint("worker", "[worker->pool] login address=%s agent=%s sid=%s -- RandomX miner, PoW v2 job %s\n",
                 m->address.c_str(), m->agent.c_str(), sid.c_str(), gCurrentJob.jobId.c_str());
        reply(json{{"id", sid},{"job", job},{"status","OK"}});
        return true;
    }

    if (method == "keepalived") {
        m->lastSeen = GetTime();
        reply(json{{"status","KEEPALIVED"}});
        return true;
    }

    if (method == "getjob") {
        if (!m->authorised) { reply(nullptr, "Unauthenticated"); return false; }
        if (!gHaveJob)      { reply(nullptr, "no work yet"); return true; }
        CBlock mb = BuildMinerBlock(gCurrentJob, m->extranonce2);
        json job = MakeCryptoNoteJob(gCurrentJob, mb, m->shareTarget);
        if (job.is_null())  { reply(nullptr, "no PoW v2 work yet"); return true; }
        reply(job);
        return true;
    }

    // ------------------------------------------------------------------
    if (method == "mining.subscribe") {
        if (refuseIfBehind())
            return false;

        // Which chain the worker thinks it is mining. Discovery is namespaced
        // per network now, but a worker can also be pointed at a pool by hand,
        // and hashing a testnet template for a mainnet payout address is a
        // silent waste of somebody's electricity. Refuse before sending work.
        // Workers built before this send no params; those are still accepted.
        auto& ps = req["params"];
        if (ps.is_array() && ps.size() > 0 && ps[0].is_string()) {
            std::string strTheirs = StratumLabel(ps[0].get<std::string>());
            if (strTheirs != BtfNetworkName()) {
                LogPrint("worker", "[pool] refusing fd=%d: worker is on '%s', this pool is on '%s'\n",
                         (int)m->fd, strTheirs.c_str(), BtfNetworkName());
                reply(nullptr, strprintf("this pool mines %s, not %s",
                                         BtfNetworkName(), strTheirs.c_str()));
                return false;
            }
        }
        std::string sid = ToHex(&m->fd, 4);
        LogPrint("worker", "[worker->pool] subscribe from fd=%d sid=%s network=%s\n",
                 (int)m->fd, sid.c_str(), BtfNetworkName());
        reply(json::array({json::array({json::array({"mining.notify",sid})}),sid,4}));
        return true;
    }

    // ------------------------------------------------------------------
    if (method == "mining.authorize") {
        // is_array() matters as much as the element checks: indexing a json
        // object with a number throws, and size() on an object returns its key
        // count, so "params":{"a":1} would pass a bare size() test.
        auto& p = req["params"];
        bool fArr = p.is_array();
        m->address = (fArr && p.size() > 0 && p[0].is_string()) ? p[0].get<std::string>() : "";
        m->worker  = (fArr && p.size() > 1 && p[1].is_string()) ? p[1].get<std::string>() : "worker";
        // In P2Pool mode only a label here as well: P2PoolPayoutScript pays
        // this node.
        m->address = StratumAddress(m->address);
        m->worker  = StratumLabel(m->worker);

        // Validate address before authorising
        uint160 h160; bool validAddr = AddressToHash160(m->address, h160);

        LogPrint("worker", "[worker->pool] authorize address=%s worker=%s addr_valid=%s\n",
                 m->address.c_str(), m->worker.c_str(), validAddr ? "yes" : "NO");

        if (!validAddr)
            LogPrint("worker", "[pool] WARNING: address '%s' is invalid -- "
                     "miner will hash but shares cannot be paid out\n",
                     m->address.c_str());

        reply(true);

        // Authorise regardless -- shares just won't pay out. Vardiff starts
        // at 1.0; the Bitcoin dialect is told so explicitly.
        authorise();
        LogPrint("worker", "[pool->worker] initial difficulty=%.4f for %s\n",
                 m->difficulty, m->address.c_str());
        if (!SendLine(m->fd, json{{"id",nullptr},{"method","mining.set_difficulty"},
                                  {"params",json::array({m->difficulty})}}))
            LogPrint("worker", "[pool->worker] set_difficulty send FAILED for %s\n",
                     m->address.c_str());

        if (gHaveJob) {
            LogPrint("worker", "[pool->worker] sending job %s to %s\n",
                     gCurrentJob.jobId.c_str(), m->address.c_str());
            SendJob(m, true);
        } else {
            LogPrint("worker", "[pool->worker] no job available yet for %s"
                     " -- will be sent one as soon as the pool builds it\n",
                     m->address.c_str());
        }
        return true;
    }

    // ------------------------------------------------------------------
    if (method == "mining.extranonce.subscribe") { reply(true); return true; }
    if (method == "mining.get_transactions")     { reply(json::array()); return true; }

    // ------------------------------------------------------------------
    if (method == "mining.submit" || method == "submit") {
        if (!m->authorised) {
            LogPrint("worker", "[worker->pool] submit from unauthorized miner (fd=%d)\n",
                     (int)m->fd);
            reply(false, m->fCryptoNote ? "Unauthenticated" : "not authorised");
            return true;
        }

        auto& p = req["params"];
        std::string submitJobId, nonceHex, resultHex;
        if (m->fCryptoNote) {
            // XMRig: {"params":{"id":SID,"job_id":..,"nonce":"8 hex, the 4 bytes
            // at blob offset 39 in order","result":"the 32-byte hash, hex"}}
            if (!p.is_object() || !p.contains("job_id") || !p["job_id"].is_string()
                || !p.contains("nonce") || !p["nonce"].is_string()) {
                LogPrint("worker", "[worker->pool] submit bad params from %s\n", m->address.c_str());
                reply(false, "bad params");
                return true;
            }
            submitJobId = StratumLabel(p["job_id"].get<std::string>());
            nonceHex    = StratumLabel(p["nonce"].get<std::string>());
            if (p.contains("result") && p["result"].is_string())
                resultHex = StratumLabel(p["result"].get<std::string>(), 128);
        } else {
            // Check the shape as well as the length: a submit carrying
            // "params":[1,2,3] would otherwise reach get<std::string>() and throw
            // a json::type_error that nothing above catches, taking the pool down
            // with it. Authorising costs an attacker nothing but an address.
            if (!p.is_array() || p.size() < 3 || !p[1].is_string() || !p[2].is_string()) {
                LogPrint("worker", "[worker->pool] submit bad params from %s\n",
                         m->address.c_str());
                reply(false, "bad params");
                return true;
            }
            submitJobId = StratumLabel(p[1].get<std::string>());
            nonceHex    = StratumLabel(p[2].get<std::string>());
        }

        if (!gHaveJob) {
            LogPrint("worker", "[worker->pool] submit from %s but pool has no current job\n",
                     m->address.c_str());
            reply(false, "stale job");
            return true;
        }
        // Any of the last few jobs, as long as its block still builds on the
        // tip. Only the newest used to count, and a job is replaced every
        // minute -- and in P2Pool on every new share, about every 10 s -- so
        // work a miner had in flight was thrown away as "stale" when it was
        // still good.
        const StratumJob* pFound = gCurrentJob.jobId == submitJobId ? &gCurrentJob : NULL;
        for (size_t i = 0; !pFound && i < gRecentJobs.size(); i++)
            if (gRecentJobs[i].jobId == submitJobId)
                pFound = &gRecentJobs[i];
        bool fOnTip = false;
        if (pFound)
            CRITICAL_BLOCK(cs_main)
                // No tip at all happens only in the selftest: a job is never built without one.
                fOnTip = !pindexBest || pFound->block.hashPrevBlock == pindexBest->GetBlockHash();
        if (!pFound || !fOnTip) {
            LogPrint("worker", "[worker->pool] submit stale job from %s"
                     " (submitted=%s current=%s)\n",
                     m->address.c_str(), submitJobId.c_str(), gCurrentJob.jobId.c_str());
            reply(false, "stale job");
            return true;
        }
        // A copy: a block found below rebuilds the job list.
        const StratumJob sj = *pFound;

        auto nb = FromHex(nonceHex);
        if (nb.size() < 4) {
            LogPrint("worker", "[worker->pool] submit bad nonce from %s: '%s'\n",
                     m->address.c_str(), nonceHex.c_str());
            reply(false, "bad nonce");
            return true;
        }
        unsigned int nNonce; memcpy(&nNonce, nb.data(), 4);

        // Rebuild this miner's exact block (unique merkle via extranonce2)
        CBlock b = BuildMinerBlock(sj, m->extranonce2);
        b.nNonce = nNonce;
        unsigned char hdr[80];
        memcpy(hdr,    &b.nVersion,       4);
        memcpy(hdr+4,  &b.hashPrevBlock,  32);
        memcpy(hdr+36, &b.hashMerkleRoot, 32);
        memcpy(hdr+68, &b.nTime,          4);
        memcpy(hdr+72, &b.nBits,          4);
        memcpy(hdr+76, &b.nNonce,         4);

        uint256 powHash = PoWHashHeader(hdr);

        // A RandomX miner sends the hash it computed. If it differs from ours
        // the miner is keyed or laid out wrong, and "Low difficulty share"
        // would send its user hunting in the wrong place.
        if (!resultHex.empty()) {
            auto rb = FromHex(resultHex);
            if (rb.size() != 32 || memcmp(rb.data(), &powHash, 32) != 0) {
                LogPrint("worker", "[worker->pool] hash mismatch from %s (agent %s):"
                         " miner %s pool %s\n", m->address.c_str(), m->agent.c_str(),
                         resultHex.c_str(), powHash.GetHex().c_str());
                reply(false, "hash does not match: this pool is Bitflash PoW v2 (rx/0, seed_hash from the job)");
                return true;
            }
        }

        // Check against this miner's personal share target (set by vardiff)
        // P2Pool: the target of the job this work was done on; it moves with
        // every share, so the latest one sent is not the one to hold it to.
        if (powHash > (fP2PoolMode ? sj.shareTarget : m->shareTarget)) {
            LogPrint("worker", "[worker->pool] high-hash from %s"
                     " nonce=%u (difficulty=%.4f)\n",
                     m->address.c_str(), nNonce, m->difficulty);
            reply(false, m->fCryptoNote ? "Low difficulty share" : "high-hash");
            return true;
        }

        // Valid share -- record it
        m->sessionShares++;
        m->roundShares++;
        m->totalShares++;
        m->vardiffShares++;
        int64 shareTime = GetTime();
        m->lastSeen = shareTime;
        roundShareCount[m->address]++;
        roundShareTotal++;

        // Update hashrate estimate: expected hashes for this share divided by
        // the time since the last one, smoothed with an EWMA so a single fast
        // or slow share doesn't make the number jump around.
        if (m->lastShareTime > 0) {
            int64 dt = shareTime - m->lastShareTime;
            if (dt <= 0) dt = 1;
            double inst = ExpectedHashesForDifficulty(m->difficulty) / (double)dt;
            const double alpha = 0.25;
            m->hashRate = (m->hashRate <= 0.0) ? inst
                                                : alpha * inst + (1.0 - alpha) * m->hashRate;
        }
        m->lastShareTime = shareTime;

        LogPrint("worker", "[worker->pool] valid share from %s"
                 " nonce=%u job=%s difficulty=%.4f (session: %llu)\n",
                 m->address.c_str(), nNonce,
                 sj.jobId.c_str(), m->difficulty,
                 (unsigned long long)m->sessionShares);
        reply(true);

        // P2Pool: the work is a share of the share chain. Keep it and send it
        // to every peer; the template then moves onto it. Work that met only
        // the block target is a block, checked below, and not a share.
        if (fP2PoolMode && powHash <= sj.shareChainTarget) {
            p2pool::Share s;
            s.nVersion       = b.nVersion;
            s.hashPrevBlock  = b.hashPrevBlock;
            s.hashMerkleRoot = b.hashMerkleRoot;
            s.nTime          = b.nTime;
            s.nBits          = b.nBits;
            s.nNonce         = b.nNonce;
            s.coinbase       = b.vtx[0];
            s.vMerkleBranch  = sj.vBranch;
            s.data           = sj.shareData;
            string err;
            bool fOk;
            CRITICAL_BLOCK(cs_main)
                fOk = P2PoolSubmitShare(s, err);
            if (fOk)
                LogPrint("pool", "[p2pool] share %s at share height %u from %s\n",
                         s.GetId().ToString().substr(0, 12).c_str(), s.data.nShareHeight, m->address.c_str());
            else
                LogPrint("pool", "[p2pool] our own share refused: %s\n", err.c_str());
            // Not rebuilt here: the block check below must still see this
            // job. The event loop moves the template onto the new share tip.
        }

        // Vardiff: after every VARDIFF_SHARES_PER_CHECK shares, check rate
        if (!fP2PoolMode && m->vardiffShares >= VARDIFF_SHARES_PER_CHECK) {
            int64 elapsed = GetTime() - m->vardiffWindowStart;
            if (elapsed <= 0) elapsed = 1;
            double actualSecsPerShare = (double)elapsed / (double)m->vardiffShares;
            double ratio = actualSecsPerShare / (double)VARDIFF_TARGET_SECS;
            // ratio < 1 means shares arriving faster than target (too easy)
            // ratio > 1 means shares arriving slower than target (too hard)
            if (ratio < (1.0 / VARDIFF_RETARGET_RATIO) ||
                ratio > VARDIFF_RETARGET_RATIO) {
                // New difficulty scales inversely with actual share rate
                double newDiff = m->difficulty / ratio;
                if (newDiff < VARDIFF_MIN) newDiff = VARDIFF_MIN;
                if (newDiff > VARDIFF_MAX) newDiff = VARDIFF_MAX;
                // Only apply if the change is meaningful (>10%)
                if (newDiff / m->difficulty > 1.1 || m->difficulty / newDiff > 1.1) {
                    m->difficulty    = newDiff;
                    m->shareTarget   = ShareTargetFromDifficulty(m->difficulty);
                    LogPrint("worker", "[pool] vardiff: %s new difficulty=%.4f"
                             " (%.1fs/share actual vs %ds target)\n",
                             m->address.c_str(), m->difficulty,
                             actualSecsPerShare, (int)VARDIFF_TARGET_SECS);
                    if (!m->fCryptoNote)   // a RandomX miner reads the target off the job
                        SendLine(m->fd, json{{"id",nullptr},
                                            {"method","mining.set_difficulty"},
                                            {"params",json::array({m->difficulty})}});
                    // set_difficulty alone doesn't change what the worker
                    // actually hashes against -- it only reads its share
                    // target from mining.notify params[3]. Without this, the
                    // new difficulty wouldn't take effect until the next
                    // natural job broadcast (new block, or the 60s trickle
                    // refresh), so push a fresh notify for this miner now.
                    SendJob(m, false);
                }
            }
            // Reset window
            m->vardiffWindowStart = GetTime();
            m->vardiffShares      = 0;
        }

        if (powHash > sj.target) return true; // valid share, not a block

        // Full difficulty met -- submit block to the chain
        LogPrint("pool", "[pool] BLOCK CANDIDATE from %s height=%d nNonce=%u -- submitting\n",
                 m->address.c_str(), sj.height, nNonce);

        CBlock* pblock = new CBlock(b);
        bool accepted = false;
        CRITICAL_BLOCK(cs_main)
        {
            int heightBefore = nBestHeight;
            if (ProcessBlock(NULL, pblock)) {
                // ProcessBlock returns true for orphans too -- verify the chain
                // actually advanced. If nBestHeight didn't increase, the block
                // was shelved as an orphan (pool was behind the chain tip) and
                // no coinbase was added to the wallet. Do not pay out.
                if (nBestHeight > heightBefore) {
                    accepted = true;
                    LogPrint("pool", "[pool] BLOCK ACCEPTED height=%d by %s\n",
                             sj.height, m->address.c_str());
                    gFoundBlocks.push_front({sj.height, GetTime(), m->address});
                    if (gFoundBlocks.size() > 50) gFoundBlocks.pop_back();
                    blocksFoundThisSession++;
                    gHaveJob = false; // invalidate job immediately
                } else {
                    LogPrint("pool", "[pool] BLOCK ORPHANED height=%d by %s"
                             " -- pool was behind chain tip, no payout\n",
                             sj.height, m->address.c_str());
                    gHaveJob = false; // job is stale regardless
                }
            } else {
                // ProcessBlock has already freed it, whatever the refusal.
                LogPrint("pool", "[pool] BLOCK REJECTED height=%d (ProcessBlock returned false)\n",
                         sj.height);
            }
        }

        if (accepted) {
            // Snapshot height before RebuildJob() (which increments it)
            int foundHeight = sj.height;
            // P2Pool: the block already paid every miner of the window.
            if (!fP2PoolMode)
                QueuePayouts(foundHeight, b.GetHash().GetHex(), b.vtx[0].GetHash().GetHex(),
                             b.vtx[0].vout[0].nValue, m->address,
                             roundShareCount, roundShareTotal);
            // Reset round shares
            roundShareCount.clear();
            roundShareTotal = 0;
            for (Miner* mi : gMiners) mi->roundShares = 0;
            // Build and broadcast new job immediately
            if (RebuildJob()) {
                LogPrint("pool", "[pool] new job %s built after block %d\n",
                         gCurrentJob.jobId.c_str(), foundHeight);
                BroadcastJob(true);
            } else {
                LogPrint("pool", "[pool] WARNING: RebuildJob() failed after block %d"
                         " -- miners will wait\n", foundHeight);
            }
        }
        return true;
    }

    // Unknown method -- log it (can reveal miner software quirks)
    LogPrint("worker", "[worker->pool] unknown method '%s' from %s\n",
             StratumLabel(method).c_str(),
             m->address.empty() ? "(unauth)" : m->address.c_str());
    reply(nullptr, "unknown method");
    return true;
}

int RunPoolStratumSelfTest()
{
    int nFail = 0;
    auto check = [&](bool ok, const char* msg) {
        fprintf(stdout, "  %s   %s\n", ok ? "ok" : "FAIL", msg);
        if (!ok) nFail++;
    };

    fprintf(stdout, "pool-stratum self-test\n");

    StratumJob savedJob = gCurrentJob;
    bool savedHaveJob = gHaveJob;

    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig << 1 << (CBigNum)1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 50 * COIN;

    CBlock block;
    block.vtx.push_back(coinbase);
    block.nVersion = 1;
    block.nBits = 0x1f0fffff;
    block.nTime = 1;
    block.nNonce = 1;
    block.hashMerkleRoot = block.BuildMerkleTree();

    gCurrentJob.jobId = "selftest";
    gCurrentJob.block = block;
    gCurrentJob.target = 0; // accepted share, not a block candidate
    gCurrentJob.height = 1;
    gHaveJob = true;

    Miner miner(INVALID_SOCKET);
    miner.authorised = true;
    miner.address = "selftest-address";
    miner.worker = "worker";
    miner.shareTarget = ~uint256(0); // every RandomX hash is a valid share
    miner.difficulty = 0.001;
    miner.vardiffWindowStart = GetTime();

    std::map<std::string, uint64> roundShareCount;
    uint64 roundShareTotal = 0;
    int blocksFound = 0;

    uint256 targetFromNotify;
    CBlock minerBlock = BuildMinerBlock(gCurrentJob, miner.extranonce2);
    json params = MakeNotifyParams(gCurrentJob, minerBlock, miner.shareTarget, true);
    std::vector<unsigned char> targetBytes = FromHex(params[3].get<std::string>());
    if (targetBytes.size() == 32)
        memcpy(&targetFromNotify, &targetBytes[0], 32);
    check(targetFromNotify == miner.shareTarget,
          "mining.notify exposes the same share target the pool validates");

    json submit = {
        {"id", 7},
        {"method", "mining.submit"},
        {"params", json::array({miner.address, "selftest", ToHex(&minerBlock.nNonce, 4)})}
    };
    HandleLine(&miner, submit.dump(), roundShareCount, roundShareTotal, blocksFound);

    check(roundShareTotal == 1, "fake low-difficulty share increments the round total");
    check(roundShareCount[miner.address] == 1, "fake share is credited to the submitting address");
    check(miner.sessionShares == 1 && miner.roundShares == 1 && miner.totalShares == 1,
          "miner share counters advance together");
    check(blocksFound == 0, "share below block target is not counted as a found block");

    json stale = {
        {"id", 8},
        {"method", "mining.submit"},
        {"params", json::array({miner.address, "stale", ToHex(&minerBlock.nNonce, 4)})}
    };
    HandleLine(&miner, stale.dump(), roundShareCount, roundShareTotal, blocksFound);
    check(roundShareTotal == 1, "stale submit does not increment shares");

    // What a miner calls itself reaches the log only short and printable.
    {
        std::string lbl = StratumLabel(std::string("ab\ncd\r\x01\x7f\xc3\xa9") + std::string(100, 'x'));
        bool fPrintable = true;
        for (char c : lbl)
            if (c < 0x20 || c >= 0x7f) fPrintable = false;
        check(fPrintable && lbl.size() == 64 && lbl.compare(0, 6, "ab?cd?") == 0,
              "a miner's label is cut to 64 printable characters");
        check(StratumLabel("BJZ48selftestaddressxxxxxxxxxxxxxx") == "BJZ48selftestaddressxxxxxxxxxxxxxx",
              "a payment address passes through unchanged");
        std::string capturedAuth;
        gSelfTestCapture = &capturedAuth;
        Miner lm(INVALID_SOCKET);
        json auth = {{"id", 3}, {"method", "mining.authorize"},
                     {"params", json::array({"fake\n[pool] BLOCK ACCEPTED", "w\r\nx"})}};
        HandleLine(&lm, auth.dump(), roundShareCount, roundShareTotal, blocksFound);
        gSelfTestCapture = NULL;
        check(lm.address == "fake?[pool] BLOCK ACCEPTED" && lm.worker == "w??x",
              "mining.authorize keeps no line break in the miner's name");
    }

    // ---- The CryptoNote dialect (XMRig, SRBMiner) against a PoW v2 job ----
    // A template whose nTime is past the switch, so it has a v2 input.
    CBlock v2block = block;
    v2block.nTime = PoWV2Time() + 1;
    gCurrentJob.block = v2block;
    gCurrentJob.jobId = "selftest-v2";
    CBlock v2miner = BuildMinerBlock(gCurrentJob, miner.extranonce2);

    json cnjob = MakeCryptoNoteJob(gCurrentJob, v2miner, miner.shareTarget);
    check(cnjob.is_object(), "a v2 template yields a CryptoNote job");
    std::string blobHex = cnjob.value("blob", "");
    std::vector<unsigned char> blob = FromHex(blobHex);
    check(blob.size() == POW_INPUT_V2_SIZE, "job blob is the 83-byte v2 input");
    bool nonceZero = blob.size() == 83 && blob[39] == 0 && blob[40] == 0 && blob[41] == 0 && blob[42] == 0;
    check(nonceZero, "job blob carries a zero nonce at byte 39 (else XMRig goes NiceHash)");
    check(blob.size() == 83 && memcmp(&blob[0], &v2miner.nVersion, 4) == 0
          && memcmp(&blob[4], &v2miner.hashPrevBlock, 32) == 0
          && memcmp(&blob[43], &v2miner.hashMerkleRoot, 32) == 0
          && memcmp(&blob[75], &v2miner.nTime, 4) == 0
          && memcmp(&blob[79], &v2miner.nBits, 4) == 0,
          "job blob is the miner's own header, nonce moved to 39");
    check(cnjob.value("seed_hash", "") == PoWSeedV2Hex() && PoWSeedV2Hex().size() == 64,
          "job carries the 32-byte v2 seed as seed_hash");
    check(cnjob.value("target", "") == ToHex(((const unsigned char*)&miner.shareTarget) + 24, 8),
          "job target is the top 64 bits of the share target, little-endian");
    check(cnjob.value("algo", "") == "rx/0" && cnjob.value("job_id", "") == "selftest-v2",
          "job says rx/0 and names the job");
    CBlock v1block = block;
    v1block.nTime = PoWV2Time() - 1;
    check(MakeCryptoNoteJob(gCurrentJob, v1block, miner.shareTarget).is_null(),
          "a v1 template yields no CryptoNote job");

    // login, with the reply captured
    std::string captured;
    gSelfTestCapture = &captured;
    Miner cn(INVALID_SOCKET);
    json login = {{"id", 1}, {"jsonrpc", "2.0"}, {"method", "login"},
                  {"params", json{{"login", "selftest-cn-address"}, {"pass", "x"},
                                  {"agent", "XMRig/6.26.0"}, {"algo", json::array({"rx/0"})}}}};
    HandleLine(&cn, login.dump(), roundShareCount, roundShareTotal, blocksFound);
    json loginReply;
    try { loginReply = json::parse(captured); } catch (...) {}
    check(loginReply.is_object() && loginReply.value("jsonrpc", "") == "2.0" && loginReply["id"] == 1,
          "login reply wears the JSON-RPC 2.0 envelope");
    check(cn.fCryptoNote, "a login marks the miner as CryptoNote");
    // Before the switch the pool must say so in an error *object*; after it,
    // the address above is not a payment address and must be refused the
    // same way. Either way: an object XMRig will show its user.
    check(loginReply.is_object() && loginReply["error"].is_object()
          && loginReply["error"].value("message", "").size() > 0,
          "login refusal is an error object with a message, not a string");
    if (PoWVersionAt(GetAdjustedTime()) < 2)
        check(loginReply.is_object() && loginReply["error"].value("message", "").find("activates") != std::string::npos,
              "before the switch the refusal names the activation time");
    else
        check(loginReply.is_object() && loginReply["error"].value("message", "").find("payment address") != std::string::npos,
              "after the switch a non-address login is refused as such");
    check(!cn.authorised, "a refused login does not authorise");

    // submit: the nonce and the hash a correctly keyed miner would send
    cn.authorised = true; cn.address = "selftest-cn-address";
    cn.shareTarget = ~uint256(0); cn.difficulty = 0.001; cn.vardiffWindowStart = GetTime();
    CBlock cnBlock = BuildMinerBlock(gCurrentJob, cn.extranonce2);
    cnBlock.nNonce = 0x01020304;
    unsigned char hdr[80];
    memcpy(hdr, &cnBlock.nVersion, 4); memcpy(hdr+4, &cnBlock.hashPrevBlock, 32);
    memcpy(hdr+36, &cnBlock.hashMerkleRoot, 32); memcpy(hdr+68, &cnBlock.nTime, 4);
    memcpy(hdr+72, &cnBlock.nBits, 4); memcpy(hdr+76, &cnBlock.nNonce, 4);
    uint256 want = PoWHashHeader(hdr);
    uint64 before = roundShareTotal;
    captured.clear();
    json cnsubmit = {{"id", 2}, {"jsonrpc", "2.0"}, {"method", "submit"},
                     {"params", json{{"id", "00"}, {"job_id", "selftest-v2"},
                                     {"nonce", ToHex(&cnBlock.nNonce, 4)},
                                     {"result", ToHex((const unsigned char*)&want, 32)}}}};
    HandleLine(&cn, cnsubmit.dump(), roundShareCount, roundShareTotal, blocksFound);
    json submitReply;
    try { submitReply = json::parse(captured); } catch (...) {}
    check(roundShareTotal == before + 1 && roundShareCount["selftest-cn-address"] == 1,
          "CryptoNote submit with the right nonce and hash is credited");
    check(submitReply.is_object() && submitReply["error"].is_null()
          && submitReply["result"].value("status", "") == "OK",
          "accepted submit answers {\"status\":\"OK\"}");

    captured.clear();
    uint256 wrong = want; ((unsigned char*)&wrong)[0] ^= 1;
    cnsubmit["params"]["result"] = ToHex((const unsigned char*)&wrong, 32);
    cnsubmit["id"] = 3;
    HandleLine(&cn, cnsubmit.dump(), roundShareCount, roundShareTotal, blocksFound);
    try { submitReply = json::parse(captured); } catch (...) {}
    check(roundShareTotal == before + 1, "a submit whose hash differs from the pool's is not credited");
    check(submitReply.is_object() && submitReply["error"].is_object()
          && submitReply["error"].value("message", "").find("does not match") != std::string::npos,
          "the mismatch is reported as such, not as low difficulty");

    captured.clear();
    json keep = {{"id", 4}, {"jsonrpc", "2.0"}, {"method", "keepalived"}, {"params", json{{"id", "00"}}}};
    HandleLine(&cn, keep.dump(), roundShareCount, roundShareTotal, blocksFound);
    try { submitReply = json::parse(captured); } catch (...) {}
    check(submitReply.is_object() && submitReply["result"].value("status", "") == "KEEPALIVED",
          "keepalived is answered");
    gSelfTestCapture = NULL;
    gCurrentJob.block = block;
    gCurrentJob.jobId = "selftest";

    std::vector<PoolRoundProof> savedRounds = gPoolRounds;
    std::string savedRoundsFile = strPoolRoundsFile;
    std::string proofPath = "pool_rounds_selftest.json";
    remove(proofPath.c_str());
    remove((proofPath + ".tmp").c_str());
    gPoolRounds.clear();
    strPoolRoundsFile = proofPath;

    PoolRoundProof proof;
    proof.id = "selftest-round";
    proof.blockHeight = 42;
    proof.matureAtHeight = 42 + COINBASE_MATURITY;
    proof.createdAt = GetTime();
    proof.blockHash = block.GetHash().GetHex();
    proof.coinbaseTxid = coinbase.GetHash().GetHex();
    proof.foundBy = miner.address;
    proof.feePercent = 1.25;
    proof.totalShares = 3;
    proof.coinbaseValue = 50 * COIN;
    proof.subsidy = 50 * COIN;
    proof.minerReward = 49 * COIN;
    proof.operatorReward = 1 * COIN;
    proof.shares[miner.address] = 3;
    proof.payouts[miner.address] = 49 * COIN;
    RecordPoolRound(proof);
    MarkPoolRoundPaid(proof.id, miner.address, "selftest-txid");

    bool proofOk = false;
    FILE* pf = fopen(proofPath.c_str(), "r");
    if (pf) {
        fseek(pf, 0, SEEK_END);
        long sz = ftell(pf);
        fseek(pf, 0, SEEK_SET);
        std::string s(sz, '\0');
        fread(&s[0], 1, sz, pf);
        fclose(pf);
        try {
            json root = json::parse(s);
            proofOk =
                root.value("schema", "") == "bitflash-pool-rounds-1" &&
                root["rounds"].is_array() &&
                root["rounds"].size() == 1 &&
                root["rounds"][0].value("id", "") == proof.id &&
                root["rounds"][0]["shares"].value(miner.address, (uint64)0) == 3 &&
                root["rounds"][0]["payouts"][miner.address].value("txid", "") == "selftest-txid";
        } catch (...) {
            proofOk = false;
        }
    }
    check(proofOk, "pool round proof ledger is written and paid txid is recorded");

    remove(proofPath.c_str());
    remove((proofPath + ".tmp").c_str());
    strPoolRoundsFile = savedRoundsFile;
    gPoolRounds = savedRounds;

    // A miner that never reads costs the event loop nothing: its socket is
    // non-blocking, so the send that finds the buffer full fails at once and
    // marks it, and every later send to it returns at once.
    {
#ifdef _WIN32
        WSADATA wsadata;
        WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif
        std::string* savedCapture = gSelfTestCapture;
        auto StMillis = []() -> int64 {
            return (int64)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        };
        gSelfTestCapture = NULL;
        bool fSetUp = false;
        btf_socket_t ls = (btf_socket_t)socket(AF_INET, SOCK_STREAM, 0);
        btf_socket_t cl = (btf_socket_t)socket(AF_INET, SOCK_STREAM, 0);
        btf_socket_t sv = INVALID_SOCKET;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t alen = sizeof(a);
        int nSmall = 4096;
        if (ls != INVALID_SOCKET && cl != INVALID_SOCKET &&
            ::bind(ls, (struct sockaddr*)&a, sizeof(a)) == 0 && listen(ls, 1) == 0 &&
            getsockname(ls, (struct sockaddr*)&a, &alen) == 0)
        {
            setsockopt(cl, SOL_SOCKET, SO_RCVBUF, (const char*)&nSmall, sizeof(nSmall));
            if (connect(cl, (struct sockaddr*)&a, sizeof(a)) == 0)
            {
                sv = (btf_socket_t)accept(ls, NULL, NULL);
                fSetUp = sv != INVALID_SOCKET && StratumSetNonBlocking(sv);
            }
        }
        check(fSetUp, "a loopback miner that never reads is set up");
        if (fSetUp)
        {
            json big = {{"id", nullptr}, {"pad", std::string(16384, 'x')}};
            int64 t0 = StMillis();
            bool fOk = true;
            int n = 0;
            while (n < 100000 && (fOk = SendLine(sv, big)))
                n++;
            int64 dt = StMillis() - t0;
            check(!fOk && gSendFailed.count(sv) && dt < 2000,
                  "a miner that never reads fails a send at once and is marked");
            t0 = StMillis();
            bool fAgain = SendLine(sv, big);
            check(!fAgain && StMillis() - t0 < 100, "every later send to it returns at once");
        }
        gSendFailed.clear();
        if (sv != INVALID_SOCKET) sock_close(sv);
        if (cl != INVALID_SOCKET) sock_close(cl);
        if (ls != INVALID_SOCKET) sock_close(ls);
        gSelfTestCapture = savedCapture;
    }

    gCurrentJob = savedJob;
    gHaveJob = savedHaveJob;

    fprintf(stdout, "%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
            nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Stats refresh -- called every 2s from event loop
// ---------------------------------------------------------------------------
static void RefreshStats(int blocksFoundThisSession, uint64 roundShareTotal)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);

    gStats.authorizedMiners = 0;
    gStats.blocksFound      = blocksFoundThisSession;
    gStats.roundShares      = roundShareTotal;
    gStats.totalHashRate    = 0.0;
    for (Miner* m : gMiners)
        if (m->authorised) gStats.authorizedMiners++;

    gWorkerStats.clear();
    for (Miner* m : gMiners) {
        if (!m->authorised || m->lastSeen <= 0) continue;
        PoolWorkerStatView v;
        v.address     = m->address;
        v.worker      = m->worker;
        v.roundShares = m->roundShares;
        v.totalShares = m->totalShares;
        v.lastSeen    = m->lastSeen;
        v.hashRate    = m->hashRate;
        gWorkerStats.push_back(v);
        gStats.totalHashRate += m->hashRate;
    }
    std::sort(gWorkerStats.begin(), gWorkerStats.end(),
        [](const PoolWorkerStatView& a, const PoolWorkerStatView& b) {
            return a.roundShares != b.roundShares ? a.roundShares > b.roundShares
                                                  : a.lastSeen > b.lastSeen;
        });

    gPayoutViews.clear();
    std::lock_guard<std::mutex> ledger(gPayoutLedgerMutex);
    for (const PendingPayout& pp : gPendingPayouts) {
        PendingPayoutView pv;
        pv.matureAtHeight = pp.matureAtHeight;
        pv.recipients     = 0;
        pv.totalAmount    = 0;
        for (auto& kv : pp.amounts) {
            if (pp.paidTxids.count(kv.first))
                continue;
            pv.recipients++;
            pv.totalAmount += kv.second;
        }
        if (pv.recipients > 0)
            gPayoutViews.push_back(pv);
    }

    int64 now = GetTime();
    if (now - gLastPoolStatusWrite >= 10) {
        WritePoolStatusJsonLocked();
        gLastPoolStatusWrite = now;
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------
static void PoolEventLoop()
{
    int   lastHeight            = -1;
    int64 lastRefresh           = GetTime();
    int64 lastStatsRefresh      = 0;
    int   blocksFoundThisSession = 0;
    int64 noJobSince            = 0;   // 0 = have a job
    bool  warnedNoJob           = false;
    int64 lastNoJobRetry        = 0;   // throttle RebuildJob calls when no tip

    std::map<std::string, uint64> roundShareCount;
    uint64 roundShareTotal = 0;

    static const int64 JOB_REFRESH_SECS  = 60;  // re-stamp nTime periodically
    static const int64 NO_JOB_WARN_SECS  = 15;  // warn after this long with no job
    static const int64 NO_JOB_RETRY_SECS = 5;   // how often to retry RebuildJob

    while (!fShutdown && gPoolRunning) {

        // 1. Drain accept queue
        {
            std::lock_guard<std::mutex> lk(gReadyMutex);
            for (const ReadyConn& rc : gReadyQueue) {
                btf_socket_t fd = rc.fd;
                // Connecting costs nothing and every accepted socket carries a
                // read buffer, so an unbounded miner list is an unbounded
                // allocation for whoever runs the pool.
                if (gMiners.size() >= (fP2PoolMode ? MAX_P2POOL_MINERS : MAX_POOL_MINERS)) {
                    LogPrint("worker", "[pool] refusing miner fd=%d --"
                             " already at %zu connections\n",
                             (int)fd, gMiners.size());
                    sock_close(fd);
                    continue;
                }
                if (fP2PoolMode && !rc.fLoopback) {
                    size_t nLan = 0, nSame = 0;
                    for (Miner* o : gMiners) {
                        if (o->fLoopback) continue;
                        nLan++;
                        if (o->peerKey == rc.peerKey) nSame++;
                    }
                    if (nLan >= MAX_P2POOL_LAN_MINERS || nSame >= MAX_P2POOL_PER_PEER) {
                        LogPrint("worker", "[p2pool] refusing miner from %s -- %s\n", rc.peer.c_str(),
                                 nSame >= MAX_P2POOL_PER_PEER ? "that address already holds its share of connections"
                                                              : "the local network already holds its share of connections");
                        sock_close(fd);
                        continue;
                    }
                }
                Miner* nm = new Miner(fd);
                nm->peer = rc.peer;
                nm->peerKey = rc.peerKey;
                nm->fLoopback = rc.fLoopback;
                gMiners.push_back(nm);
                LogPrint("worker", "[pool] miner fd=%d entered event loop"
                         " -- awaiting subscribe/authorize\n", (int)fd);
            }
            gReadyQueue.clear();
        }

        // 1.5. P2Pool: a new share tip, ours or a peer's, is new work. A
        // template still on the old tip would pay a window the next share no
        // longer has.
        if (fP2PoolMode && gHaveJob) {
            uint256 tip;
            CRITICAL_BLOCK(cs_p2pool)
                tip = P2PoolChain().Tip();
            if (tip != gCurrentJob.shareData.hashPrevShare && RebuildJob()) {
                BroadcastJob(true);
                lastRefresh = GetTime();
            }
        }

        // 2. Detect new block.
        // When our own miner found the block, HandleLine already called
        // RebuildJob() + BroadcastJob(true) and set gHaveJob=true.
        // We still flush mature payouts and update bookkeeping, but skip
        // rebuilding if a fresh job already exists for this height.
        {
            bool newBlock = false;
            bool jobStale = false;
            CRITICAL_BLOCK(cs_main)
            {
                if (pindexBest && nBestHeight != lastHeight) {
                    lastHeight = nBestHeight;
                    newBlock   = true;
                }
                // A job is stale when its block no longer builds on the tip.
                // Only our own block used to clear gHaveJob, so after a
                // block found elsewhere the miners went on hashing the old
                // one until the 60 s refresh: up to half of every 2-minute
                // block wasted, on every block someone else found.
                if (pindexBest && gHaveJob && gCurrentJob.block.hashPrevBlock != pindexBest->GetBlockHash())
                    jobStale = true;
            }
            if (jobStale)
                gHaveJob = false;
            if (newBlock) {
                FlushMaturePayouts();
                if (!gHaveJob) {
                    // External block (not found by our miners), or HandleLine's
                    // RebuildJob failed. Either way this round is over with no
                    // payout from us, so clear round shares before starting the
                    // next one -- otherwise they'd keep accumulating across
                    // rounds that our own miners didn't win.
                    roundShareCount.clear();
                    roundShareTotal = 0;
                    for (Miner* mi : gMiners) mi->roundShares = 0;

                    // Build and broadcast now.
                    if (RebuildJob()) {
                        LogPrint("pool", "[pool] new block height=%d -- job %s ready,"
                                 " %zu miner(s) connected\n",
                                 lastHeight, gCurrentJob.jobId.c_str(), gMiners.size());
                        BroadcastJob(true);
                    } else {
                        LogPrint("pool", "[pool] new block height=%d but RebuildJob() failed"
                                 " -- miners will wait\n", lastHeight);
                    }
                } else {
                    // HandleLine already built and broadcast for this height.
                    LogPrint("pool", "[pool] new block height=%d -- job already"
                             " broadcast by submit handler\n", lastHeight);
                }
                lastRefresh  = GetTime();
                noJobSince   = 0;
                warnedNoJob  = false;
            }
        }

        // 3. No-job watchdog (throttled: only retry every NO_JOB_RETRY_SECS)
        if (!gHaveJob) {
            int64 now = GetTime();
            if (noJobSince == 0) noJobSince = now;

            if (now - lastNoJobRetry >= NO_JOB_RETRY_SECS) {
                lastNoJobRetry = now;
                if (RebuildJob()) {
                    LogPrint("pool", "[pool] job built after %llds without one\n",
                             (long long)(now - noJobSince));
                    BroadcastJob(false);
                    noJobSince  = 0;
                    warnedNoJob = false;
                    lastRefresh = now;
                } else if (!warnedNoJob && now - noJobSince >= NO_JOB_WARN_SECS) {
                    LogPrint("pool", "[pool] STUCK: no job for %llds -- %s."
                             " Miners are waiting. Will keep retrying every %llds.\n",
                             (long long)(now - noJobSince),
                             pindexBest ? "RebuildJob() keeps failing (check above for why)"
                                        : "no chain tip yet (node still syncing)",
                             (long long)NO_JOB_RETRY_SECS);
                    warnedNoJob = true;
                }
            }
        } else if (GetTime() - lastRefresh >= JOB_REFRESH_SECS) {
            // Periodic nTime refresh -- stale timestamps cause valid hashes to be rejected
            if (RebuildJob()) BroadcastJob(false);
            lastRefresh = GetTime();
        }

        // 3.5. Vardiff stall watchdog -- runs independently of share count.
        // The normal vardiff check in HandleLine only fires once
        // VARDIFF_SHARES_PER_CHECK shares have arrived; a miner that never
        // finds a single share never reaches that check, so it can be stuck
        // at its initial (or last) difficulty forever. Catch that here.
        // P2Pool has no per-miner difficulty: the share target is the chain's.
        for (Miner* m : gMiners) {
            if (fP2PoolMode || !m->authorised || m->vardiffShares != 0 || m->vardiffWindowStart <= 0)
                continue;
            int64 stalled = GetTime() - m->vardiffWindowStart;
            if (stalled < VARDIFF_STALL_SECS) continue;

            double newDiff = m->difficulty / VARDIFF_STALL_CUT;
            if (newDiff < VARDIFF_MIN) newDiff = VARDIFF_MIN;

            if (newDiff < m->difficulty) {
                m->difficulty         = newDiff;
                m->shareTarget        = ShareTargetFromDifficulty(m->difficulty);
                m->vardiffWindowStart = GetTime();
                LogPrint("worker", "[pool] vardiff STALL: %s sent zero shares in"
                         " %llds -- forcing difficulty down to %.6f (no share data"
                         " to retarget from normally)\n",
                         m->address.c_str(), (long long)stalled, m->difficulty);
                SendLine(m->fd, json{{"id",nullptr},
                                    {"method","mining.set_difficulty"},
                                    {"params",json::array({m->difficulty})}});
                // Same reasoning as the normal vardiff retarget above: the
                // worker only reads its share target from mining.notify, so
                // push a fresh job now instead of waiting on the next
                // natural broadcast.
                SendJob(m, false);
            } else {
                // Already at the difficulty floor -- this miner's problem isn't
                // difficulty, it's something else (slow hashing, bad connection,
                // stuck RandomX light mode, etc). Log once per stall window so
                // it's visible without spamming.
                LogPrint("worker", "[pool] vardiff STALL: %s still at zero shares"
                         " after %llds at floor difficulty %.6f -- likely a"
                         " hashrate/connectivity problem, not a difficulty problem\n",
                         m->address.c_str(), (long long)stalled, m->difficulty);
                m->vardiffWindowStart = GetTime(); // avoid re-logging every tick
            }
        }

        // 4. Select over miner sockets
        if (!gMiners.empty()) {
            fd_set fds; FD_ZERO(&fds);
            int maxfd = 0;
            for (Miner* m : gMiners) {
                FD_SET(m->fd, &fds);
                if ((int)m->fd > maxfd) maxfd = (int)m->fd;
            }
            struct timeval tv = {0, 50000}; // 50ms
            if (select(maxfd + 1, &fds, NULL, NULL, &tv) > 0) {
                std::vector<Miner*> dead;
                for (Miner* m : gMiners) {
                    if (!FD_ISSET(m->fd, &fds)) continue;
                    std::string line;
                    bool disc = false;
                    // Drain all complete lines buffered for this miner.
                    // HandleLine always returns true; disc signals clean disconnect.
                    // ThreadRPCServer has no handler of its own, so anything
                    // thrown here would reach the top of the thread and
                    // terminate the whole node -- not just the pool. Every
                    // line arrives from an unauthenticated socket.
                    while (!gSendFailed.count(m->fd) && RecvLine(m->fd, m->readBuf, line, disc)) {
                        try {
                            HandleLine(m, line, roundShareCount,
                                       roundShareTotal, blocksFoundThisSession);
                        } catch (const std::exception& e) {
                            LogPrint("worker", "[pool] dropping miner %s --"
                                     " exception handling line: %s\n",
                                     m->address.empty() ? "(unauth)" : m->address.c_str(),
                                     e.what());
                            disc = true;
                            break;
                        } catch (...) {
                            LogPrint("worker", "[pool] dropping miner %s --"
                                     " unknown exception handling line\n",
                                     m->address.empty() ? "(unauth)" : m->address.c_str());
                            disc = true;
                            break;
                        }
                    }
                    if (disc || gSendFailed.count(m->fd)) dead.push_back(m);
                }
                for (Miner* m : dead) {
                    LogPrint("worker", "[pool] miner %s disconnected"
                             " (session shares: %llu, round shares: %llu)\n",
                             m->worker.empty() ? "(never authorized)" : m->worker.c_str(),
                             (unsigned long long)m->sessionShares,
                             (unsigned long long)m->roundShares);
                    sock_close(m->fd);
                    gMiners.erase(std::find(gMiners.begin(), gMiners.end(), m));
                    delete m;
                }
            }
        } else {
            Sleep(50);
        }

        // 4.5. Miners a send failed on, and P2Pool connections that never
        // logged in.
        {
            std::vector<Miner*> dead;
            int64 now = GetTime();
            for (Miner* m : gMiners)
                if (gSendFailed.count(m->fd) ||
                    (fP2PoolMode && !m->authorised && now - m->connectTime > P2POOL_LOGIN_SECS))
                    dead.push_back(m);
            for (Miner* m : dead) {
                LogPrint("worker", "[pool] dropping miner %s from %s -- %s\n",
                         m->worker.empty() ? "(never authorized)" : m->worker.c_str(),
                         m->peer.c_str(),
                         gSendFailed.count(m->fd) ? "a send did not complete" : "no login in time");
                sock_close(m->fd);
                gMiners.erase(std::find(gMiners.begin(), gMiners.end(), m));
                delete m;
            }
            gSendFailed.clear();
        }

        // 5. Refresh GUI stats every 2s
        if (GetTime() - lastStatsRefresh >= 2) {
            RefreshStats(blocksFoundThisSession, roundShareTotal);
            lastStatsRefresh = GetTime();
        }
    }

    for (Miner* m : gMiners) { sock_close(m->fd); delete m; }
    gMiners.clear();
}

// ---------------------------------------------------------------------------
// -p2poolbind: the P2Pool stratum on the local network
// ---------------------------------------------------------------------------
// The stratum has no login: whoever reaches it mines, and every share pays
// this node's address (P2PoolPayoutScript), whatever name the miner gives.
// So it may face a network the owner's own machines share, never the
// internet: the address it binds must be private, and so must every peer.

// 127/8 loopback, 10/8, 172.16/12 and 192.168/16 (RFC 1918), 169.254/16
// link-local.
static bool PrivateV4(const unsigned char* a)
{
    return a[0] == 127
        || a[0] == 10
        || (a[0] == 172 && (a[1] & 0xf0) == 16)
        || (a[0] == 192 && a[1] == 168)
        || (a[0] == 169 && a[1] == 254);
}

static bool MappedV4(const unsigned char* a)
{
    static const unsigned char prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return memcmp(a, prefix, 12) == 0;
}

// ::1 loopback, fc00::/7 unique local, fe80::/10 link-local.
static bool PrivateV6(const unsigned char* a)
{
    static const unsigned char loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(a, loopback, 16) == 0
        || (a[0] & 0xfe) == 0xfc
        || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
}

bool P2PoolPeerAllowed(const struct sockaddr* pAddr, size_t nAddrLen)
{
    if (!pAddr)
        return false;
    if (pAddr->sa_family == AF_INET && nAddrLen >= sizeof(struct sockaddr_in))
        return PrivateV4((const unsigned char*)&((const struct sockaddr_in*)pAddr)->sin_addr);
    if (pAddr->sa_family == AF_INET6 && nAddrLen >= sizeof(struct sockaddr_in6))
    {
        const unsigned char* a = (const unsigned char*)&((const struct sockaddr_in6*)pAddr)->sin6_addr;
        return MappedV4(a) ? PrivateV4(a + 12) : PrivateV6(a);
    }
    return false;
}

// Parses -p2poolbind into a socket address. Numeric only: a name would be
// looked up, and could resolve to anything.
static bool P2PoolParseBind(const std::string& strAddr, struct sockaddr_storage& ss,
                            socklen_t& nLen, std::string& strWhyNot)
{
    memset(&ss, 0, sizeof(ss));
    nLen = 0;
    // Brackets and blanks are refused here, not left to the parser: Windows'
    // getaddrinfo takes "[fd00::10]", glibc's does not, and an option should
    // mean the same on both.
    if (strAddr.empty() || strAddr.size() > 64 ||
        strAddr.find_first_of("[] \t\r\n\f\v") != std::string::npos)
    {
        strWhyNot = "it is not a numeric IPv4 or IPv6 address (no names, no port)";
        return false;
    }
#ifdef _WIN32
    // Command-line parsing runs before the node starts Winsock; the reference
    // count makes this pair harmless later too.
    WSADATA wsadata;
    bool fWsa = WSAStartup(MAKEWORD(2, 2), &wsadata) == 0;
#endif
    bool fParsed = false;
    struct in_addr a4;
    if (inet_pton(AF_INET, strAddr.c_str(), &a4) == 1)
    {
        // inet_pton, not getaddrinfo, for IPv4: it takes only the plain
        // dotted quad, not "10.1" or "0x0a000001".
        struct sockaddr_in* sin = (struct sockaddr_in*)&ss;
        sin->sin_family = AF_INET;
        sin->sin_addr = a4;
        nLen = sizeof(struct sockaddr_in);
        fParsed = true;
    }
    else if (strAddr.find(':') != std::string::npos)
    {
        // getaddrinfo for IPv6, which also reads a link-local zone
        // ("fe80::1%eth0", or "%12" on Windows).
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
        if (getaddrinfo(strAddr.c_str(), NULL, &hints, &res) == 0 && res)
        {
            if (res->ai_family == AF_INET6 && res->ai_addrlen <= sizeof(ss))
            {
                memcpy(&ss, res->ai_addr, res->ai_addrlen);
                nLen = (socklen_t)res->ai_addrlen;
                fParsed = true;
            }
            freeaddrinfo(res);
        }
    }
#ifdef _WIN32
    if (fWsa)
        WSACleanup();
#endif
    if (!fParsed)
    {
        strWhyNot = "it is not a numeric IPv4 or IPv6 address (no names, no port)";
        return false;
    }
    if (ss.ss_family == AF_INET6)
    {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)&ss;
        const unsigned char* a = (const unsigned char*)&sin6->sin6_addr;
        static const unsigned char any[16] = {0};
        if (memcmp(a, any, 16) == 0)
        {
            strWhyNot = ":: listens on every interface, including any that face the internet";
            return false;
        }
        if (MappedV4(a))
        {
            strWhyNot = "give the IPv4 address itself, not its IPv6-mapped form";
            return false;
        }
        if (!PrivateV6(a))
        {
            strWhyNot = "it is not a private address (loopback, link-local fe80::/10 or unique local fc00::/7)";
            return false;
        }
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80 && sin6->sin6_scope_id == 0)
        {
            strWhyNot = "a link-local IPv6 address needs its interface, e.g. fe80::1%eth0";
            return false;
        }
        return true;
    }
    const unsigned char* a = (const unsigned char*)&((const struct sockaddr_in*)&ss)->sin_addr;
    if (a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0)
    {
        strWhyNot = "0.0.0.0 listens on every interface, including any that face the internet";
        return false;
    }
    if (!PrivateV4(a))
    {
        strWhyNot = "it is not a private address (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, "
                    "192.168.0.0/16 or link-local 169.254.0.0/16)";
        return false;
    }
    return true;
}

bool P2PoolBindAllowed(const std::string& strAddr, std::string& strWhyNot)
{
    struct sockaddr_storage ss;
    socklen_t nLen;
    return P2PoolParseBind(strAddr, ss, nLen, strWhyNot);
}

static std::string SockAddrString(const struct sockaddr* pAddr, socklen_t nLen)
{
    char host[NI_MAXHOST];
    if (getnameinfo(pAddr, nLen, host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0)
        return "?";
    return host;
}

static int LastSocketError()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// A listening socket on addr:port, or INVALID_SOCKET with the error in
// *pnErr.
static btf_socket_t StratumListen(const struct sockaddr_storage& ss, socklen_t nLen, unsigned short nPort,
                                  int* pnErr = NULL)
{
    struct sockaddr_storage addr = ss;
    if (addr.ss_family == AF_INET)
        ((struct sockaddr_in*)&addr)->sin_port = htons(nPort);
    else
        ((struct sockaddr_in6*)&addr)->sin6_port = htons(nPort);
    btf_socket_t s = (btf_socket_t)socket(addr.ss_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        if (pnErr) *pnErr = LastSocketError();
        return s;
    }
    int one = 1;
#ifndef _WIN32
    // POSIX: rebind at once over connections still in TIME_WAIT. On Windows
    // that is the default, and SO_REUSEADDR there would instead let another
    // socket bind the same address and port and take the miners.
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
#endif
    if (addr.ss_family == AF_INET6)
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&one, sizeof(one));
    if (::bind(s, (struct sockaddr*)&addr, nLen) != 0 || listen(s, SOMAXCONN) != 0)
    {
        if (pnErr) *pnErr = LastSocketError();
        sock_close(s);
        return INVALID_SOCKET;
    }
#ifndef _WIN32
    // The accept loop puts it in an fd_set.
    if ((int)s >= FD_SETSIZE) {
        if (pnErr) *pnErr = EMFILE;
        sock_close(s);
        return INVALID_SOCKET;
    }
#endif
    return s;
}

// ---------------------------------------------------------------------------
// Accept miners over the Tor hidden service
// ---------------------------------------------------------------------------
// The pool no longer registers at a rendezvous relay. Tor forwards
// <onion>:(p2p+1) to the loopback listener below, so a miner reaches the pool
// the same way it reaches any .btf node -- over its .onion, with no VPS relay
// in the path. The onion address is the pool's key, so the link is
// authenticated end to end and needs no echan handshake on top.
static void AcceptLoopFn(void*)
{
    unsigned short poolPort;
    if (fP2PoolMode) {
        // P2Pool: this node's own miners only, on 127.0.0.1 and, with
        // -p2poolbind, one private address -- no onion, nothing announced.
        // Everyone else runs their own node.
        poolPort = nP2PoolPort;
    } else {
        // The pool shares the node's .btf identity; wait for it (so the log can name
        // the pool) and for the P2P listener (so we know which port to offset from).
        unsigned char pk[32], sk[32];
        while (!BtfGetIdentity(pk, sk)) {
            if (fShutdown || !gPoolRunning) return;
            Sleep(2000);
        }
        int waited = 0;
        while (nListenPort == 0) {
            if (fShutdown || !gPoolRunning) return;
            if (++waited > 120) {
                LogPrint("pool", "[pool] P2P port never came up -- pool listener aborting\n");
                return;
            }
            Sleep(1000);
        }
        unsigned short p2p = ntohs(nListenPort);
        if (p2p >= 65535) {
            LogPrint("pool", "[pool] P2P port %u leaves no room for the pool port (p2p+1) -- pool listener aborting\n",
                     (unsigned)p2p);
            return;
        }
        poolPort = (unsigned short)(p2p + 1);
    }

    struct sockaddr_storage loopAddr;
    memset(&loopAddr, 0, sizeof(loopAddr));
    ((struct sockaddr_in*)&loopAddr)->sin_family = AF_INET;
    ((struct sockaddr_in*)&loopAddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK); // reached via Tor, or this machine's miners
    // Retried every 10 s like the LAN one below: a port still held (another
    // program, or a pool restarted a moment ago) is not a reason to leave the
    // pool deaf for good.
    btf_socket_t lsock = INVALID_SOCKET;
    int64 nLoopTried = 0;
    int nLoopWarned = 0;

    // -p2poolbind, checked at startup. The loopback listener stays: this
    // machine's own XMRig keeps pointing at 127.0.0.1. An address that is not
    // up yet (DHCP late at boot) is tried again every 10 s.
    struct sockaddr_storage lan;
    socklen_t nLanLen = 0;
    bool fLan = false;
    std::string strLan;
    if (fP2PoolMode && !strP2PoolBind.empty()) {
        std::string strWhyNot;
        if (!P2PoolParseBind(strP2PoolBind, lan, nLanLen, strWhyNot))
            LogPrint("pool", "[p2pool] -p2poolbind=%s refused: %s\n", strP2PoolBind.c_str(), strWhyNot.c_str());
        else if (!(lan.ss_family == AF_INET &&
                   ((struct sockaddr_in*)&lan)->sin_addr.s_addr == htonl(INADDR_LOOPBACK))) {
            fLan = true;
            strLan = lan.ss_family == AF_INET6 ? "[" + strP2PoolBind + "]" : strP2PoolBind;
        }
    }
    btf_socket_t lanSock = INVALID_SOCKET;
    int64 nLanTried = 0;
    int nLanWarned = 0;

    int64 nRefusedLogged = 0;
    while (!fShutdown && gPoolRunning) {
        if (lsock == INVALID_SOCKET && GetTime() - nLoopTried >= 10) {
            nLoopTried = GetTime();
            int nErr = 0;
            lsock = StratumListen(loopAddr, sizeof(struct sockaddr_in), poolPort, &nErr);
            if (lsock != INVALID_SOCKET) {
                if (fP2PoolMode)
                    LogPrint("pool", "[p2pool] point XMRig at 127.0.0.1:%u -- shares go to the share chain, "
                             "blocks pay the window\n", (unsigned)poolPort);
                else
                    LogPrint("pool", "[pool] miners connect at %s (pool port %u) over onion\n",
                             BtfLocalAddress().c_str(), (unsigned)poolPort);
            }
            else if (nErr != nLoopWarned) {
                LogPrint("pool", "[pool] could not listen on 127.0.0.1:%u (socket error %d)"
                         " -- trying again every 10 s\n", (unsigned)poolPort, nErr);
                nLoopWarned = nErr ? nErr : -1;
            }
        }
        if (fLan && lanSock == INVALID_SOCKET && GetTime() - nLanTried >= 10) {
            nLanTried = GetTime();
            int nErr = 0;
            lanSock = StratumListen(lan, nLanLen, poolPort, &nErr);
            if (lanSock != INVALID_SOCKET)
                LogPrint("pool", "[p2pool] also serving the local network at %s:%u -- anyone who can "
                         "reach it mines to this node's address\n", strLan.c_str(), (unsigned)poolPort);
            else if (nErr != nLanWarned) {
                // Once per distinct error: an address that is not up yet
                // (EADDRNOTAVAIL) says something different from a port in use.
                LogPrint("pool", "[p2pool] could not listen on %s:%u (socket error %d: is that address on "
                         "this machine, and the port free?) -- trying again every 10 s\n",
                         strLan.c_str(), (unsigned)poolPort, nErr);
                nLanWarned = nErr;
            }
        }

        if (lsock == INVALID_SOCKET && lanSock == INVALID_SOCKET) {
            Sleep(1000);
            continue;
        }
        fd_set rs;
        FD_ZERO(&rs);
        int maxfd = 0;
        if (lsock != INVALID_SOCKET) {
            FD_SET(lsock, &rs);
            maxfd = (int)lsock;
        }
        if (lanSock != INVALID_SOCKET) {
            FD_SET(lanSock, &rs);
            if ((int)lanSock > maxfd) maxfd = (int)lanSock;
        }
        struct timeval tv;
        tv.tv_sec = 1; tv.tv_usec = 0;
        int r = select(maxfd + 1, &rs, NULL, NULL, &tv);
        if (r <= 0) continue;           // timeout or interrupt -> re-check shutdown
        btf_socket_t ls[2] = {lsock, lanSock};
        for (int i = 0; i < 2; i++) {
            if (ls[i] == INVALID_SOCKET || !FD_ISSET(ls[i], &rs))
                continue;
            struct sockaddr_storage peer;
            socklen_t nPeerLen = sizeof(peer);
            memset(&peer, 0, sizeof(peer));
            btf_socket_t c = (btf_socket_t)accept(ls[i], (struct sockaddr*)&peer, &nPeerLen);
            if (c == INVALID_SOCKET) {
                // Out of descriptors (EMFILE) leaves the connection pending,
                // and select() reports it again at once: do not spin on it.
                Sleep(100);
                continue;
            }
#ifndef _WIN32
            // The event loop puts every miner in an fd_set; a descriptor past
            // FD_SETSIZE would be written outside it.
            if ((int)c >= FD_SETSIZE) {
                LogPrint("pool", "[pool] dropping a miner connection: descriptor %d is past FD_SETSIZE\n", (int)c);
                sock_close(c);
                continue;
            }
#endif
            // Defence in depth behind the bind check: a router forwarding a
            // public port to this address would otherwise open the stratum to
            // the internet.
            if (!P2PoolPeerAllowed((struct sockaddr*)&peer, (size_t)nPeerLen)) {
                if (GetTime() - nRefusedLogged >= 60) {
                    LogPrint("pool", "[p2pool] dropped a stratum connection from %s: not a private address\n",
                             SockAddrString((struct sockaddr*)&peer, nPeerLen).c_str());
                    nRefusedLogged = GetTime();
                }
                sock_close(c);
                continue;
            }
            std::string strPeer = SockAddrString((struct sockaddr*)&peer, nPeerLen);
            // Loopback: this machine's own miners, or Tor delivering the
            // central pool's onion connections.
            bool fLoopback = (peer.ss_family == AF_INET &&
                              ((const unsigned char*)&((struct sockaddr_in*)&peer)->sin_addr)[0] == 127) ||
                             (peer.ss_family == AF_INET6 && strPeer == "::1");
            if (!StratumSetNonBlocking(c)) {
                sock_close(c);
                continue;
            }
            if (!PushReady(c, strPeer, strPeer, fLoopback)) {
                LogPrint("worker", "[pool] dropping a miner connection from %s: the event loop is behind\n",
                         strPeer.c_str());
                sock_close(c);
                continue;
            }
            if (fP2PoolMode)
                LogPrint("worker", "[p2pool] miner connected from %s\n", strPeer.c_str());
            else
                LogPrint("worker", "[pool] miner connected over onion -- pushing to event loop\n");
        }
    }
    if (lanSock != INVALID_SOCKET)
        sock_close(lanSock);
    if (lsock != INVALID_SOCKET)
        sock_close(lsock);
    LogPrint("pool", "[pool] pool listener stopped\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
void ThreadRPCServer(void*)
{
    gPoolRunning = true;

    LogPrint("pool", "[pool] ============================================\n");
    LogPrint("pool", "[pool] Pool server starting\n");
    LogPrint("pool", "[pool] .btf address: %s\n", BtfLocalAddress().c_str());
    LogPrint("pool", "[pool] fee: %.2f%%\n", dPoolFeePercent);

    if (RebuildJob()) {
        LogPrint("pool", "[pool] initial job %s seeded at height %d\n",
                 gCurrentJob.jobId.c_str(), nBestHeight + 1);
    } else {
        LogPrint("pool", "[pool] no chain tip yet -- job will build on first block\n");
    }

    // P2Pool holds nobody's coins, so it has no payout ledger, and no pool
    // to announce.
    if (!fP2PoolMode) {
        LoadPendingPayouts();
        LoadPoolRounds();
    }

    _beginthread(AcceptLoopFn, 0, NULL);
    if (!fP2PoolMode) {
        _beginthread(ThreadBtfPoolAnnouncer, 0, NULL);
        _beginthread(PayoutThreadFn, 0, NULL);
    }

    PoolEventLoop(); // blocks until gPoolRunning = false or fShutdown

    LogPrint("pool", "[pool] pool server stopped\n");
    LogPrint("pool", "[pool] ============================================\n");
    gPoolRunning = false;
}
