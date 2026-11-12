// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btfchatswap.h.

#include "headers.h"
#include "btfchatswap.h"
#include "btfchatnode.h"
#include "btfchatwallet.h"
#include "swap.h"

#include <sodium.h>
#include <algorithm>

using json = nlohmann::json;

namespace btfchat
{

static const int64_t BTF_BLOCK_SECS = 120;

// ---- the store ---------------------------------------------------------------

static json SwapToJson(const ChatSwap& s)
{
    json j;
    j["id"] = s.id; j["peer"] = s.peer; j["offer"] = s.offerId; j["maker"] = s.fMaker;
    j["give"] = s.give; j["ga"] = s.giveAmount; j["want"] = s.want; j["wa"] = s.wantAmount;
    j["btcDestination"] = s.btcDestination; j["paymentAddress"] = s.paymentAddress;
    j["myRecv"] = s.myRecv; j["theirRecv"] = s.theirRecv;
    j["secret"] = s.secret; j["hash"] = s.secretHash;
    j["myC"] = s.myContract; j["myTx"] = s.myTxid; j["myN"] = s.myVout;
    j["thC"] = s.theirContract; j["thTx"] = s.theirTxid; j["thN"] = s.theirVout;
    j["redeem"] = s.redeemTxid; j["refund"] = s.refundTxid; j["refundSince"] = s.refundSince;
    j["stage"] = s.stage; j["ok"] = s.fUserOk; j["inv"] = s.fInvited; j["sent"] = s.fSentLock;
    j["status"] = s.status; j["err"] = s.lastError;
    j["created"] = s.created; j["updated"] = s.updated; j["since"] = s.theirSince;
    j["rsince"] = s.redeemSince; j["rfee"] = s.redeemFeeRate;
    j["lockTried"] = s.fLockTried; j["refundFee"] = s.refundFeeRate;
    return j;
}

static bool SwapFromJson(const json& j, ChatSwap& s)
{
    if (!j.is_object())
        return false;
    try
    {
        s.id = j.value("id", std::string()); s.peer = j.value("peer", std::string());
        s.offerId = j.value("offer", std::string()); s.fMaker = j.value("maker", false);
        s.give = j.value("give", std::string()); s.giveAmount = j.value("ga", (int64_t)0);
        s.want = j.value("want", std::string()); s.wantAmount = j.value("wa", (int64_t)0);
        s.btcDestination = j.value("btcDestination", std::string()); s.paymentAddress = j.value("paymentAddress", std::string());
        s.myRecv = j.value("myRecv", std::string()); s.theirRecv = j.value("theirRecv", std::string());
        s.secret = j.value("secret", std::string()); s.secretHash = j.value("hash", std::string());
        s.myContract = j.value("myC", std::string()); s.myTxid = j.value("myTx", std::string());
        s.myVout = j.value("myN", -1);
        s.theirContract = j.value("thC", std::string()); s.theirTxid = j.value("thTx", std::string());
        s.theirVout = j.value("thN", -1);
        s.redeemTxid = j.value("redeem", std::string()); s.refundTxid = j.value("refund", std::string());
        s.refundSince = j.value("refundSince", (int64_t)0);
        s.stage = j.value("stage", (int)SW_FAILED); s.fUserOk = j.value("ok", false);
        s.fInvited = j.value("inv", false); s.fSentLock = j.value("sent", false);
        s.status = j.value("status", std::string()); s.lastError = j.value("err", std::string());
        s.created = j.value("created", (int64_t)0); s.updated = j.value("updated", (int64_t)0);
        s.theirSince = j.value("since", (int64_t)0);
        s.redeemSince = j.value("rsince", (int64_t)0); s.redeemFeeRate = j.value("rfee", (int64_t)0);
        s.fLockTried = j.value("lockTried", false); s.refundFeeRate = j.value("refundFee", (int64_t)0);
    }
    catch (...) { return false; }
    return s.id.size() == 32 && !s.peer.empty() && SwapCoinOk(s.give) && SwapCoinOk(s.want);
}

std::string SwapEngine::ToJson()
{
    json j;
    j["swaps"] = json::array();
    j["seen"] = json::array();
    CRITICAL_BLOCK(cs)
    {
        for (std::map<std::string, ChatSwap>::const_iterator it = swaps.begin(); it != swaps.end(); ++it)
            j["swaps"].push_back(SwapToJson(it->second));
        for (std::set<std::string>::const_iterator it = stepsSeen.begin(); it != stepsSeen.end(); ++it)
            j["seen"].push_back(*it);
    }
    return j.dump();
}

void SwapEngine::FromJson(const std::string& str)
{
    CRITICAL_BLOCK(cs)
    {
        swaps.clear();
        stepsSeen.clear();
        if (str.empty())
            return;
        try
        {
            json j = json::parse(str);
            if (j.contains("swaps") && j["swaps"].is_array())
                for (size_t i = 0; i < j["swaps"].size(); i++)
                {
                    ChatSwap s;
                    if (SwapFromJson(j["swaps"][i], s))
                        swaps[s.id] = s;
                }
            if (j.contains("seen") && j["seen"].is_array())
                for (size_t i = 0; i < j["seen"].size(); i++)
                    if (j["seen"][i].is_string())
                        stepsSeen.insert(j["seen"][i].get<std::string>());
        }
        catch (...) {}
    }
}

void SwapEngine::Clear()
{
    CRITICAL_BLOCK(cs)
    {
        for (std::map<std::string, ChatSwap>::iterator it = swaps.begin(); it != swaps.end(); ++it)
            if (!it->second.secret.empty())
                sodium_memzero(&it->second.secret[0], it->second.secret.size());
        swaps.clear();
        stepsSeen.clear();
    }
}

// ---- helpers ---------------------------------------------------------------

static bool IsFinal(int stage)
{
    return stage == SW_DONE || stage == SW_REFUNDED || stage == SW_CANCELLED || stage == SW_FAILED;
}

// What the wallet's calls take and answer: the coin's own units.
static std::string AmountText(const std::string& coin, int64_t n)
{
    return CoinAmountText(coin, n);
}

static int64_t Sats(const std::string& coin, const json& v)
{
    if (!v.is_number())
        return -1;
    double d = v.get<double>();
    return (int64_t)(d * CoinUnit(coin) + (d >= 0 ? 0.5 : -0.5));
}

static std::string Ref(const std::string& coin, const std::string& txid, int vout)
{
    // An output whose index is not known (the node paid it but could not
    // say where) is named by its transaction: the audit finds the output.
    return coin != "BTF" && vout >= 0 ? txid + ":" + strprintf("%d", vout) : txid;
}

static std::string CoinName(const std::string& coin)
{
    return coin == "LTC" ? "Litecoin" : coin == "DOGE" ? "Dogecoin" : coin == "DGB" ? "DigiByte" : coin == "RVN" ? "Ravencoin" : coin == "BCH" ? "Bitcoin Cash" : coin == "XEC" ? "eCash" : coin == "BTC" ? "Bitcoin" : "Bitflash";
}

// The chain that is not Bitflash, in a swap that has one Bitflash side.
static std::string Other(const ChatSwap& s)
{
    return s.give == "BTF" ? s.want : s.give;
}

static std::string NewId()
{
    unsigned char b[16];
    randombytes_buf(b, sizeof(b));
    return HexStr(b, b + sizeof(b), false);
}

int SwapEngine::MinConfirmations(const std::string& coin) const
{
    if (config.nMinConfirmations > 0)
        return config.nMinConfirmations;
    if (IsTestNet())
        return 1;
    // A private fork is stopped by the time it takes to mine, so Litecoin's
    // blocks, four to Bitcoin's one, and Dogecoin's, ten, are asked for in the
    // same time: 20 min.
    // Bitcoin Cash and eCash run Bitcoin's SHA-256 with a sliver of its hash
    // rate, so anyone can rent their next block: there, more time. DigiByte's
    // five algorithms include SHA-256 and scrypt, as rentable: 40 min, at 15 s.
    // KAWPOW's hash rate can be rented too, and honest nodes and this wallet's
    // light client stay on their tip against a fork 60 blocks deep: 60, an hour.
    // Bitflash runs RandomX, which anyone can rent by the hour, on a chain far
    // smaller than any of these: 30 of its two-minute blocks, an hour too.
    return coin == "LTC" ? 8 : coin == "DOGE" ? 20 : coin == "DGB" ? 160 : coin == "RVN" ? 60 : coin == "BCH" ? 4 : coin == "XEC" ? 6 :
           coin == "BTF" ? 30 : 2;
}

bool SwapEngine::Wallet(const char* method, const json& params, json& r, std::string& err)
{
    return host->Wallet(method, params, r, err);
}

// One step on a chain: Bitflash's own call, btc<step> on Bitcoin, and on any
// other chain coin<step> with the chain first.
bool SwapEngine::OnChain(const std::string& coin, const char* btf, const char* step, const json& params,
                         json& r, std::string& err)
{
    if (coin == "BTF")
        return Wallet(btf, params, r, err);
    if (coin == "BTC")
        return Wallet((std::string("btc") + step).c_str(), params, r, err);
    std::string strLower = coin;
    std::transform(strLower.begin(), strLower.end(), strLower.begin(), ::tolower);
    json all = json::array({ strLower });
    for (const json& p : params)
        all.push_back(p);
    return Wallet((std::string("coin") + step).c_str(), all, r, err);
}

bool SwapEngine::NewAddress(const std::string& coin, std::string& out, std::string& err)
{
    json r;
    if (!OnChain(coin, "getnewaddress", "newaddress", json::array(), r, err))
        return false;
    if (!r.is_string() || !SwapAddressShapeOk(coin, r.get<std::string>()))
    {
        err = "the wallet gave no usable " + coin + " address";
        return false;
    }
    out = r.get<std::string>();
    return true;
}

bool SwapEngine::SendStep(const ChatSwap& s, SwapStep& st, std::string& err)
{
    st.swap = s.id;
    return host->SendStep(s.peer, FormatSwapStep(st), err);
}

void SwapEngine::SendCancel(const ChatSwap& s, const std::string& why)
{
    SwapStep st;
    st.step = "cancel";
    st.why = why.substr(0, MAX_SWAP_NOTE);
    std::string err;
    SendStep(s, st, err);
}

// The lock-length parameter for a test chain's shorter locks, or nothing.
json SwapEngine::LockParams(const ChatSwap& s, bool fInitiator) const
{
    int64_t n = s.give != "BTF" ? (fInitiator ? config.nBtcInitiatorSecs : config.nBtcParticipantSecs)
                                : (fInitiator ? config.nBtfInitiatorSecs : config.nBtfParticipantSecs);
    return n > 0 ? json(n) : json(nullptr);
}

// Seconds until a contract's refund opens, from an audit: by median time on
// every chain. A Bitflash contract from before 1.2.33 is locked by height;
// only our own are still read that way (to refund them), never theirs.
static int64_t SecondsLeft(const std::string& coin, const json& a)
{
    if (coin == "BTF" && a.value("lockIsHeight", false))
        return a.value("blocksUntilRefund", (int64_t)0) * BTF_BLOCK_SECS;
    return a.value("secondsUntilRefund", (int64_t)0);
}

enum Verdict { V_OK, V_WAIT, V_BAD };

// Their contract, as our own nodes see it.
int SwapEngine::CheckTheirs(const ChatSwap& s, int64_t nMinLeft, const std::string& expectHash,
                            std::string& hashOut, std::string& why)
{
    // The lock first, from the contract itself, before any chain is asked:
    // auditing a contract makes a light client look for its payment from
    // its lock less the longest lock, and a lock the other side chose far in
    // the past would send it back over months of blocks. Every lock here is a
    // time; one that is a height, long gone, or further ahead than any lock
    // this version makes is not a contract this swap can be.
    {
        swap::Contract c;
        std::vector<unsigned char> vch = ParseHex(s.theirContract);
        if (!swap::ParseContract(CScript(vch.begin(), vch.end()), c))
        {
            why = "their contract is not an atomic swap contract";
            return V_BAD;
        }
        if (c.nLockTime < (int64_t)LOCKTIME_THRESHOLD)
        {
            why = "their contract is locked by block height, as only versions before 1.2.33 make; it needs a time lock";
            return V_BAD;
        }
        int64_t nNow = GetTime();
        if (c.nLockTime < nNow - 7200 || c.nLockTime > nNow + swap::BTF_INITIATOR_LOCK_SECS + 4 * 3600)
        {
            why = "their contract's lock time is not one a swap made now would have";
            return V_BAD;
        }
    }
    json a;
    std::string err;
    if (!OnChain(s.want, "swapauditcontract", "auditcontract",
                json::array({ s.theirContract, Ref(s.want, s.theirTxid, s.theirVout) }), a, err))
    {
        why = err;
        // A contract the wallet cannot even find may still be on its way.
        return V_WAIT;
    }
    if (!a.is_object())
    {
        why = "the wallet's audit is empty";
        return V_WAIT;
    }
    if (!a.value("recipientIsMine", false) || a.value("recipient", std::string()) != s.myRecv)
    {
        why = "their contract does not pay the address we gave";
        return V_BAD;
    }
    hashOut = a.value("secretHash", std::string());
    if (hashOut.size() != 64 || (!expectHash.empty() && hashOut != expectHash))
    {
        why = "their contract is under another secret";
        return V_BAD;
    }
    int nConf = a.contains("confirmations") && a["confirmations"].is_number_integer() ? a["confirmations"].get<int>() : 0;
    bool fUnspent = a.value("unspent", false);
    if (!fUnspent)
    {
        if (nConf > 0)
        {
            why = "their contract is already spent";
            return V_BAD;
        }
        why = "their contract is not on the chain yet";
        return V_WAIT;
    }
    if (Sats(s.want, a["amount"]) != s.wantAmount)
    {
        why = "their contract holds " + a["amount"].dump() + " " + s.want + ", not " + FormatSwapAmount(s.want, s.wantAmount);
        return V_BAD;
    }
    // A coinbase pays nothing spendable until it matures, and disappears for
    // good if its block is orphaned -- after we had shown the secret.
    if (a.value("coinbase", false))
    {
        why = "their contract is paid by a coinbase";
        return V_BAD;
    }
    if (nConf < MinConfirmations(s.want))
    {
        why = strprintf("their contract has %d of %d confirmations", nConf, MinConfirmations(s.want));
        return V_WAIT;
    }
    if (a.value("lockIsHeight", false))
    {
        why = "their contract is locked by block height; it needs a time lock";
        return V_BAD;
    }
    int64_t nLeft = a.value("secondsUntilRefund", (int64_t)0);
    if (nLeft < nMinLeft)
    {
        why = strprintf("their contract opens for refund in %lld minutes; too soon to go on",
                        (long long)(nLeft / 60));
        return V_BAD;
    }
    return V_OK;
}

// Seconds until our own contract can be refunded (0: it can be now).
bool SwapEngine::MyTimeLeft(const ChatSwap& s, int64_t& nLeft, std::string& err)
{
    json a;
    if (!OnChain(s.give, "swapauditcontract", "auditcontract",
                json::array({ s.myContract, Ref(s.give, s.myTxid, s.myVout) }), a, err) || !a.is_object())
        return false;
    nLeft = SecondsLeft(s.give, a);
    return true;
}

// Seconds until their contract can be refunded by them; 0 once it can, or
// once it is spent and there is nothing left in it to take.
bool SwapEngine::TheirTimeLeft(const ChatSwap& s, int64_t& nLeft, std::string& err)
{
    json a;
    if (!OnChain(s.want, "swapauditcontract", "auditcontract",
                json::array({ s.theirContract, Ref(s.want, s.theirTxid, s.theirVout) }), a, err) || !a.is_object())
        return false;
    nLeft = !a.value("unspent", false) ? 0 : SecondsLeft(s.want, a);
    return true;
}

// Has a contract been spent, and did the spend show the secret?
bool SwapEngine::FindSecret(const std::string& coin, const std::string& contract, const std::string& ref,
                            bool& fSpent, std::string& secretOut, bool& fRefunded, std::string& err,
                            bool* pfConfirmed, int* pnSpendConf, std::string* pSpendTxid)
{
    json r;
    fSpent = false;
    fRefunded = false;
    secretOut.clear();
    if (pfConfirmed)
        *pfConfirmed = false;
    if (pnSpendConf)
        *pnSpendConf = 0;
    if (pSpendTxid)
        pSpendTxid->clear();
    if (!OnChain(coin, "swapfindsecret", "findsecret", json::array({ contract, ref }), r, err) || !r.is_object())
        return false;
    fSpent = r.value("spent", false);
    secretOut = r.value("secret", std::string());
    fRefunded = r.value("refunded", false);
    // In a block, not only in a memory pool, where a spend paying more could
    // still take its place.
    if (pfConfirmed)
        *pfConfirmed = fSpent && r.value("confirmed", false);
    if (pnSpendConf && fSpent && r.contains("spendConfirmations") && r["spendConfirmations"].is_number_integer())
        *pnSpendConf = r["spendConfirmations"].get<int>();
    if (pSpendTxid && fSpent)
        *pSpendTxid = r.value("txid", std::string());
    return true;
}

// Locking one of ours: what the wallet answers, kept in the swap.
static bool TakeLockResult(ChatSwap& s, const json& r, std::string& err)
{
    if (!r.is_object() || !r.contains("contract") || !r["contract"].is_string())
    {
        err = "the wallet's answer has no contract";
        return false;
    }
    bool fAwaiting = r.value("awaitingPayment", false);
    std::string txid = r.contains("contractTxid") && r["contractTxid"].is_string() ? r["contractTxid"].get<std::string>() : "";
    if (!fAwaiting && txid.empty())
    {
        err = "the wallet's answer has no contract transaction";
        return false;
    }
    s.paymentAddress = fAwaiting ? r.value("contractAddress", std::string()) : std::string();
    s.myContract = r["contract"].get<std::string>();
    s.myTxid = txid;
    s.myVout = s.give != "BTF" && r.contains("vout") && r["vout"].is_number_integer() ? r["vout"].get<int>() : -1;
    if (r.contains("secret") && r["secret"].is_string())
        s.secret = r["secret"].get<std::string>();
    if (r.contains("secretHash") && r["secretHash"].is_string())
        s.secretHash = r["secretHash"].get<std::string>();
    return true;
}

// Our lock, as the wallet made it -- answered by initiate/participate, or
// found again by swaplookup after a call that gave no answer.
bool SwapEngine::AdoptLock(ChatSwap& s, const json& r, std::string& err)
{
    if (!TakeLockResult(s, r, err))
        return false;
    s.fLockTried = false;
    s.fSentLock = false;
    if (r.contains("fundingUnverified"))
    {
        // Paid, but the node could not show the output it paid: the other
        // side could not audit it, and neither could we. Called off; the
        // refund stage finds the output by its transaction at the lock.
        s.stage = SW_REFUNDING;
        s.status = "our contract was paid, but the node could not show its output; the swap is off and ours comes back at its lock";
        SendCancel(s, "my contract could not be verified");
        return true;
    }
    s.stage = s.paymentAddress.empty() ? SW_LOCKED : SW_WAIT_PAYMENT;
    s.status = s.fMaker ? "locked ours; waiting for them to lock theirs"
                        : "locked ours; waiting for them to take it, which shows the secret";
    return true;
}

// After a lock call that gave no answer: did the wallet lock anything under
// this swap's id? 1: yes, and it is ours now (adopted). 0: no, nothing was
// sent. -1: not known yet.
int SwapEngine::LookupLock(ChatSwap& s, std::string& err)
{
    json r;
    if (!Wallet("swaplookup", json::array({ s.id }), r, err) || !r.is_object())
        return -1;
    std::string state = r.value("state", std::string());
    if (state == "funded" || state == "made")
        return AdoptLock(s, r, err) ? 1 : -1;
    // "unpaid": the contract was made but nothing of ours paid it; asked
    // again, the wallet makes that same contract, so locking again is safe.
    if (state == "none" || state == "failed" || state == "unpaid")
    {
        s.fLockTried = false;
        return 0;
    }
    err = "the wallet cannot tell yet whether our lock was paid";
    return -1;
}

// Before a new lock: the store has to be on the disk. A lock is a promise
// the engine must keep for two days, and a store it cannot save is one it
// could lose.
bool SwapEngine::StoreSaved(ChatSwap& s)
{
    if (host->Changed())
        return true;
    s.status = "not locking: the chat store cannot be saved (disk full?); the swap waits until it can";
    return false;
}

// Written ahead: the store says a lock call is under way before it is made.
// Stopped during the call or right after it, the swap comes back with
// fLockTried set, and Tick asks the wallet's journal what happened before
// anything can lock again or call the swap off.
bool SwapEngine::SaveLockAttempt(ChatSwap& s)
{
    bool fWas = false;
    CRITICAL_BLOCK(cs)
    {
        std::map<std::string, ChatSwap>::iterator it = swaps.find(s.id);
        if (it != swaps.end())
        {
            fWas = it->second.fLockTried;
            it->second.fLockTried = true;
        }
    }
    s.fLockTried = true;
    if (StoreSaved(s))
        return true;
    CRITICAL_BLOCK(cs)
    {
        std::map<std::string, ChatSwap>::iterator it = swaps.find(s.id);
        if (it != swaps.end())
            it->second.fLockTried = fWas;
    }
    s.fLockTried = fWas;
    return false;
}

// Our contract was spent by a refund. When is that the end?
//
// A maker with its secret not out has nothing to lose to a reorganisation:
// the block that has the refund will do. A taker has: the maker holds the
// secret, and a refund one block deep that a reorganisation replaces with
// the maker's redeem puts the secret on the chain while the maker's own coins
// are still locked for us. So a taker's refund is over only once it has the
// chain's confirmations (MinConfirmations) and the maker's contract is spent
// or past its lock; until then the refund stage keeps reading our contract
// for a spend that shows the secret.
void SwapEngine::RefundSeen(ChatSwap& s, bool fConfirmed, int nConf)
{
    s.stage = SW_REFUNDING;
    if (!fConfirmed)
    {
        // In a memory pool: the node relays it; a block will say.
        s.status = "refund sent; waiting for a block to confirm it";
        return;
    }
    if (!s.fMaker)
    {
        int nNeed = MinConfirmations(s.give);
        if (nConf < nNeed)
        {
            s.status = strprintf("our refund has %d of %d confirmations; still watching for the secret", nConf, nNeed);
            return;
        }
        if (!s.theirContract.empty())
        {
            int64_t nLeft = 1;
            std::string err;
            if (!TheirTimeLeft(s, nLeft, err))
            {
                s.lastError = err;
                s.status = "our refund is confirmed; checking their contract before calling it over";
                return;
            }
            if (nLeft > 0)
            {
                s.status = strprintf("our refund is confirmed; watching for the secret until their lock opens, in about %lld minutes",
                                     (long long)(nLeft / 60 + 1));
                return;
            }
        }
    }
    s.refundSince = 0;
    s.stage = SW_REFUNDED;
    s.status = "refunded: our " + FormatSwapAmount(s.give, s.giveAmount) + " " + s.give + " came back";
}

// Our contract was spent with the secret while we waited to refund it. A
// taker: the maker redeemed ours, so the secret is ours too and theirs is
// taken with it. A maker: its own redeem lost to their refund and they then
// took ours -- a loss, and said so, not a swap "done".
static void OursTakenWithSecret(ChatSwap& s, const std::string& secret)
{
    s.refundSince = 0;
    if (!s.fMaker)
    {
        s.secret = secret;
        s.stage = SW_REDEEMING;
        s.status = "they took ours with the secret; taking theirs with it";
    }
    else
    {
        s.stage = SW_FAILED;
        s.status = "lost: their refund came before our redeem, and they then took ours with the secret";
    }
}

// The refund at the end of our lock, and what to make of it failing.
//
// A refund is over only once a block has it. Until then the other side, if
// it has the secret -- and a taker's maker always has -- can still redeem
// ours instead, paying more. So REFUNDING watches our contract until it is
// spent: by our refund in a block (REFUNDED), or with the secret (a taker
// then takes theirs with it). A refund no block takes within the hour goes
// out again, on a light client at twice the fee rate.
void SwapEngine::TryRefund(ChatSwap& s)
{
    int64_t nLeft = 1;
    int64_t nNow = GetTime();
    std::string err;
    if (s.give != "BTF" && s.myTxid.empty())
    {
        // Our contract waited for a payment from another wallet. Paid after
        // all: refund that like any other lock. Never paid: once a day past
        // the lock has given a late payment time to confirm, it is over.
        json a;
        if (!OnChain(s.give, "swapauditcontract", "auditcontract", json::array({ s.myContract, "" }), a, err) || !a.is_object())
        {
            s.lastError = err;
            return;
        }
        // A funding found, spent or not, names its transaction; none is zeros.
        std::string strFunding = a.value("contractTxid", std::string());
        if (a.value("unspent", false) || (!strFunding.empty() && strFunding.find_first_not_of('0') != std::string::npos))
        {
            s.myTxid = a.value("contractTxid", std::string());
            s.myVout = a.value("vout", -1);
        }
        else if (GetTime() > a.value("lockTime", (int64_t)0) + 86400)
        {
            s.stage = SW_CANCELLED;
            s.status = "ended: nothing was ever paid into our contract";
            return;
        }
        else
        {
            if (s.stage == SW_REFUNDING)
                s.status = "nothing was paid into our contract; do not pay it now (anything already sent comes back at the lock)";
            return;
        }
    }
    bool fResend = false;
    if (!s.refundTxid.empty())
    {
        bool fSpent = false, fRefunded = false, fConfirmed = false;
        int nConf = 0;
        std::string secret;
        if (!FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err, &fConfirmed, &nConf))
        {
            s.lastError = err;
            return;
        }
        if (fSpent && !secret.empty())
        {
            OursTakenWithSecret(s, secret);
            return;
        }
        if (fSpent && fRefunded)
        {
            RefundSeen(s, fConfirmed, nConf);
            return;
        }
        s.stage = SW_REFUNDING;
        if (fSpent)
        {
            // Spent where the node cannot read by what yet.
            s.status = "ours was spent; waiting for a block to show by what";
            return;
        }
        if (!s.refundSince)
            s.refundSince = nNow;
        if (nNow - s.refundSince < config.nRedeemBumpAfter)
        {
            s.status = "refund sent; waiting for " + CoinName(s.give) + " to confirm it";
            return;
        }
        // An hour and no block has it, nor a memory pool the wallet can see:
        // sent again below.
        fResend = true;
    }
    if (!MyTimeLeft(s, nLeft, err))
    {
        s.lastError = err;
        return;
    }
    if (nLeft > 0)
    {
        if (s.stage == SW_REFUNDING)
            s.status = strprintf("ours comes back when its lock runs out, in about %lld minutes", (long long)(nLeft / 60 + 1));
        return;
    }
    json r;
    json refundParams = json::array({s.myContract, Ref(s.give, s.myTxid, s.myVout)});
    int64_t nRate = 0;
    if (s.give != "BTF" && !s.btcDestination.empty())
    {
        refundParams.push_back(s.btcDestination);
        // The light client: the same refund again, at twice the rate, up to
        // the ceiling its spends allow.
        if (fResend)
        {
            int64_t nMaxRate = s.give == "DOGE" || s.give == "DGB" || s.give == "RVN" ? COIN : 1000000;
            nRate = std::min<int64_t>(std::max<int64_t>(s.refundFeeRate, 1000) * 2, nMaxRate);
            refundParams.push_back(AmountText(s.give, nRate));
        }
    }
    if (OnChain(s.give, "swaprefund", "refund", refundParams, r, err) && r.is_object())
    {
        s.refundTxid = r.value("txid", std::string());
        s.refundSince = nNow;
        if (nRate)
            s.refundFeeRate = nRate;
        else if (r.contains("feeRatePerKvB"))
            s.refundFeeRate = Sats(s.give, r["feeRatePerKvB"]);
        s.stage = SW_REFUNDING;
        s.status = fResend ? "our refund was not confirmed yet; sent it again" + std::string(nRate ? " with a higher fee" : "")
                           : "refund sent; waiting for a block to confirm it";
        return;
    }
    // Spent already? With the secret means they redeemed ours -- which they
    // can only do after we showed the secret, i.e. after we took theirs.
    bool fSpent = false, fRefunded = false, fConfirmed = false;
    int nConf = 0;
    std::string secret, err2, spendTxid;
    if (FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err2, &fConfirmed,
                   &nConf, &spendTxid) && fSpent)
    {
        if (!secret.empty())
            OursTakenWithSecret(s, secret);
        else if (fRefunded)
        {
            // Refunded already (an earlier round, or by hand): watched from
            // here as our refund.
            if (s.refundTxid.empty())
                s.refundTxid = spendTxid;
            if (!s.refundSince)
                s.refundSince = nNow;
            RefundSeen(s, fConfirmed, nConf);
        }
        else
        {
            // Spent where the node cannot read it yet: a memory pool its RPC
            // does not search (only Bitcoin Core 25 and later do), or a
            // refund not yet in a block. Never over until a block says which.
            s.status = "ours was spent; waiting for a block to show by what";
        }
        return;
    }
    s.lastError = err;
}

// ---- one round for one swap ----------------------------------------------------

// Their contract was refunded before we could take it. A final stage only
// when nothing of ours is left out: a taker's own contract was spent by the
// maker (that is where its secret came from), but a maker's is still locked
// -- and once its redeem was sent the secret is public -- so the maker goes
// on to refund it at its lock instead of stopping here.
static void TheirsRefunded(ChatSwap& s, const std::string& why)
{
    if (s.fMaker)
    {
        s.stage = SW_REFUNDING;
        s.status = why + "; ours comes back at its lock";
    }
    else
    {
        s.stage = SW_FAILED;
        s.status = why;
    }
}

void SwapEngine::Tick(ChatSwap& s)
{
    int64_t nNow = GetTime();
    std::string err;
    if (s.fLockTried && (s.stage == SW_TAKE_RECEIVED || s.stage == SW_CHECKING_THEIRS || s.stage == SW_READY_TO_LOCK))
    {
        // The last lock call gave no answer, or an error after which the
        // wallet may still have sent. Until its journal says, the swap is
        // neither locked again nor called off: either could orphan coins.
        int n = LookupLock(s, err);
        if (n != 0)
        {
            if (n < 0)
            {
                s.status = "the last lock gave no clear answer; asking the wallet whether anything was locked";
                s.lastError = err;
            }
            return;
        }
    }
    if ((s.stage == SW_TAKE_RECEIVED || s.stage == SW_READY_TO_LOCK) && s.fUserOk)
    {
        json info;
        if (OnChain(Other(s), "", "swapinfo", json::array(), info, err) && info.value("backend", std::string()) == "light")
        {
            json checked;
            if (s.btcDestination.empty() || !OnChain(Other(s), "", "validatedestination", json::array({s.btcDestination}), checked, err))
            {
                s.status = "enter your " + CoinName(Other(s)) + " receiving address before locking";
                s.lastError = err; s.fUserOk = false; return;
            }
        }
    }
    switch (s.stage)
    {
    case SW_INVITING:
    {
        if (host->PeerAccepted(s.peer))
        {
            if (s.myRecv.empty() && !NewAddress(s.want, s.myRecv, err))
            {
                s.lastError = err;
                return;
            }
            SwapStep st;
            st.step = "take";
            st.offer = s.offerId;
            st.terms.give = s.want;  st.terms.giveAmount = s.wantAmount;   // the maker's side
            st.terms.want = s.give;  st.terms.wantAmount = s.giveAmount;
            st.to = s.myRecv;
            if (!SendStep(s, st, err))
            {
                s.lastError = err;
                return;
            }
            s.stage = SW_TAKE_SENT;
            s.theirSince = nNow;
            s.status = "asked them to lock first";
        }
        else if (!s.fInvited)
        {
            SwapOffer o;
            o.give = s.want; o.giveAmount = s.wantAmount; o.want = s.give; o.wantAmount = s.giveAmount;
            std::string note = "I would like to take your swap offer: " + DescribeSwapOffer(o);
            if (host->Invite(s.peer, note.substr(0, MAX_INVITE_NOTE), err) || err.find("already") != std::string::npos)
                s.fInvited = true;
            else
                s.lastError = err;
            s.status = "invited them to talk; the swap starts when they accept";
        }
        else if (nNow - s.created > config.nAnswerWithin)
        {
            s.stage = SW_CANCELLED;
            s.status = "they never accepted the invite";
        }
        return;
    }

    case SW_TAKE_SENT:
        if (nNow - s.theirSince > config.nAnswerWithin)
        {
            SendCancel(s, "no answer");
            s.stage = SW_CANCELLED;
            s.status = "they never locked their side";
        }
        return;

    case SW_TAKE_RECEIVED:
    {
        if (!s.fUserOk)
        {
            if (nNow - s.created > config.nAnswerWithin)
            {
                SendCancel(s, "not accepted in time");
                s.stage = SW_CANCELLED;
                s.status = "not accepted in time";
            }
            return;
        }
        if (s.myRecv.empty() && !NewAddress(s.want, s.myRecv, err))
        {
            s.lastError = err;
            s.fUserOk = false;
            return;
        }
        if (!SaveLockAttempt(s))
            return;
        // The swap's id names the lock in the wallet's journal (swaps.log),
        // where its secret is written before anything is sent: asked again,
        // the wallet answers with that lock instead of making a second.
        json params = json::array({ s.theirRecv, AmountText(s.give, s.giveAmount), LockParams(s, true), s.id });
        json r;
        if (!OnChain(s.give, "swapinitiate", "initiate", params, r, err) || !AdoptLock(s, r, err))
        {
            s.lastError = err;
            s.fUserOk = false;      // the person decides again, knowing why
            s.fLockTried = true;    // once the journal says nothing went out
            s.status = "the wallet did not lock ours";
            return;
        }
        // Saved by the caller before anything else is tried: the secret is in
        // the swap now (and in swaps.log).
        return;
    }

    case SW_CHECKING_THEIRS:
    case SW_READY_TO_LOCK:
    {
        std::string hash, why;
        int v = CheckTheirs(s, config.nTakerMinLeft, std::string(), hash, why);
        if (v == V_BAD)
        {
            SendCancel(s, why);
            s.stage = SW_CANCELLED;
            s.status = "not going on: " + why;
            return;
        }
        if (v == V_WAIT)
        {
            s.status = "checking their side: " + why;
            if (nNow - s.theirSince > config.nGiveUpWaiting)
            {
                SendCancel(s, "your contract never confirmed");
                s.stage = SW_CANCELLED;
                s.status = "their contract never confirmed";
            }
            return;
        }
        s.secretHash = hash;
        if (s.stage == SW_CHECKING_THEIRS)
        {
            s.stage = SW_READY_TO_LOCK;
            s.status = "their " + FormatSwapAmount(s.want, s.wantAmount) + " " + s.want + " is locked for us and checks out";
            return;
        }
        if (!s.fUserOk)
            return;
        if (s.give == "BTF" && config.nBtfMaxMedianLag > 0)
        {
            // Our BTF refund needs a few Bitflash blocks between our lock and
            // theirs (swap.h, THE TIMING). A chain already crawling is where a
            // slowdown would start: not now.
            json info;
            if (!Wallet("getinfo", json::array(), info, err) || !info.is_object() || !info.contains("mediantime") ||
                !info["mediantime"].is_number_integer())
            {
                s.status = "checking the Bitflash chain before locking";
                s.lastError = err.empty() ? "the wallet does not say its chain's median time (update it)" : err;
                return;
            }
            int64_t nLag = nNow - info["mediantime"].get<int64_t>();
            if (nLag > config.nBtfMaxMedianLag)
            {
                s.status = strprintf("not locking yet: Bitflash blocks are slow right now (its median time is %lld minutes behind)",
                                     (long long)(nLag / 60));
                if (nNow - s.theirSince > config.nGiveUpWaiting)
                {
                    SendCancel(s, "the Bitflash chain was too slow to lock against");
                    s.stage = SW_CANCELLED;
                    s.status = "not going on: the Bitflash chain stayed too slow to lock against";
                }
                return;
            }
        }
        if (!SaveLockAttempt(s))
            return;
        json params = json::array({ s.theirRecv, AmountText(s.give, s.giveAmount), s.secretHash, LockParams(s, false), s.id });
        json r;
        if (!OnChain(s.give, "swapparticipate", "participate", params, r, err) || !AdoptLock(s, r, err))
        {
            s.lastError = err;
            s.fUserOk = false;
            s.fLockTried = true;
            s.status = "the wallet did not lock ours";
            return;
        }
        return;
    }

    case SW_WAIT_PAYMENT:
    {
        s.status = "waiting for you to pay the contract: pay exactly " + AmountText(s.give, s.giveAmount) + " " + s.give + " to " + s.paymentAddress;
        json audit;
        if (!OnChain(s.give, "swapauditcontract", "auditcontract", json::array({ s.myContract, "" }), audit, err))
        {
            s.lastError = err;
            return;
        }
        std::string strFunding = audit.value("contractTxid", std::string());
        bool fFunded = audit.value("unspent", false) ||
                       (!strFunding.empty() && strFunding.find_first_not_of('0') != std::string::npos);
        if (!fFunded && audit.value("secondsUntilRefund", (int64_t)1) <= 0)
        {
            // Nothing paid before the lock: there is no swap left to make. The
            // refund stage still watches, in case a payment is on its way.
            SendCancel(s, "the " + CoinName(s.give) + " contract was never paid");
            s.stage = SW_REFUNDING;
            s.status = "nothing was paid into our contract before its lock; do not pay it now";
            return;
        }
        if (fFunded && !audit.value("unspent", false))
        {
            // Paid and already spent: the refund stage finds out by whom.
            s.myTxid = strFunding; s.myVout = audit.value("vout", -1);
            s.stage = SW_REFUNDING;
            return;
        }
        if (!audit.value("unspent", false) || audit.value("confirmations", 0) < MinConfirmations(s.give)) return;
        s.myTxid = audit.at("contractTxid").get<std::string>(); s.myVout = audit.at("vout").get<int>();
        if (Sats(s.give, audit["amount"]) != s.giveAmount || audit.value("secondsUntilRefund", (int64_t)0) <= 0)
        {
            s.stage = SW_REFUNDING;
            s.status = "payment amount differs or contract expired; waiting to refund";
            return;
        }
        s.stage = SW_LOCKED; s.fSentLock = false;
        s.status = CoinName(s.give) + " contract payment confirmed";
        return;
    }

    case SW_LOCKED:
    {
        if (!s.fSentLock)
        {
            SwapStep st;
            st.step = s.fMaker ? "lock1" : "lock2";
            st.chain = s.give;
            st.contract = s.myContract;
            st.txid = s.myTxid;
            st.vout = s.myVout;
            if (s.fMaker)
                st.to = s.myRecv;
            if (SendStep(s, st, err))
                s.fSentLock = true;
            else
                s.lastError = err;
        }
        if (!s.fMaker)
        {
            // Waiting for the maker to take ours: the secret will be in that spend.
            bool fSpent = false, fRefunded = false, fConfirmed = false;
            int nConf = 0;
            std::string secret, spendTxid;
            if (FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err,
                           &fConfirmed, &nConf, &spendTxid))
            {
                if (fSpent && !secret.empty())
                {
                    s.secret = secret;
                    s.stage = SW_REDEEMING;
                    s.status = "they took ours; taking theirs with the secret";
                    return;
                }
                if (fSpent && fRefunded)
                {
                    if (s.refundTxid.empty())
                        s.refundTxid = spendTxid;
                    if (!s.refundSince)
                        s.refundSince = nNow;
                    RefundSeen(s, fConfirmed, nConf);
                    return;
                }
            }
        }
        TryRefund(s);
        return;
    }

    case SW_REDEEMING:
    {
        if (s.redeemSince > 0)
        {
            // The light client sent our Bitcoin redeem but cannot see a memory
            // pool: the swap is done only once the redeem is in a block. The
            // secret is out, so until then the other side's lock is a race --
            // a redeem that sits is sent again with twice the fee.
            bool fSpent = false, fRefunded = false;
            std::string secret, e2;
            if (FindSecret(s.want, s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), fSpent, secret, fRefunded, e2) && fSpent &&
                (fRefunded || !secret.empty()))
            {
                s.redeemSince = 0;
                if (fRefunded)
                    TheirsRefunded(s, "they refunded theirs before our redeem confirmed");
                else
                {
                    s.stage = SW_DONE;
                    s.status = "done: received " + FormatSwapAmount(s.want, s.wantAmount) + " " + s.want;
                }
                return;
            }
            if (!e2.empty())
                s.lastError = e2;
            if (nNow - s.redeemSince < config.nRedeemBumpAfter)
            {
                s.status = "redeemed; waiting for " + CoinName(s.want) + " to confirm it";
                return;
            }
            // Dogecoin's and Ravencoin's floor is COIN/100 a kvB already: their
            // ceiling is the one the wallet's spends allow, a whole coin.
            int64_t nMaxRate = s.want == "DOGE" || s.want == "DGB" || s.want == "RVN" ? COIN : 1000000;
            int64_t nRate = std::min<int64_t>(std::max<int64_t>(s.redeemFeeRate, 1000) * 2, nMaxRate);
            json r;
            json bumpParams = json::array({s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), s.secret,
                                           s.btcDestination, AmountText(s.want, nRate)});
            if (OnChain(s.want, "swapredeem", "redeem", bumpParams, r, err) && r.is_object())
            {
                s.redeemTxid = r.value("txid", std::string());
                s.redeemSince = nNow;
                s.redeemFeeRate = nRate;
                s.status = "our redeem was not confirmed yet; sent it again with a higher fee";
            }
            else
                s.lastError = err;
            return;
        }
        if (s.fMaker)
        {
            std::string hash, why;
            int v = CheckTheirs(s, config.nMakerMinLeft, s.secretHash, hash, why);
            if (v == V_WAIT)
            {
                s.status = "checking their side: " + why;
                // Our own lock keeps running while we wait for theirs; past
                // it, ours comes back instead.
                int64_t nLeft = 1;
                std::string e2;
                if ((MyTimeLeft(s, nLeft, e2) && nLeft == 0) || nNow - s.theirSince > config.nGiveUpWaiting)
                {
                    s.stage = SW_REFUNDING;
                    s.status = "their contract never checked out; ours comes back at its lock";
                }
                return;
            }
            if (v == V_BAD)
            {
                // Never show the secret against a contract that does not check
                // out: wait for our own lock instead.
                SendCancel(s, why);
                s.stage = SW_REFUNDING;
                s.status = "not taking theirs (" + why + "); ours comes back at its lock";
                return;
            }
        }
        json r;
        json redeemParams = json::array({s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), s.secret});
        if (s.want != "BTF" && !s.btcDestination.empty()) redeemParams.push_back(s.btcDestination);
        if (OnChain(s.want, "swapredeem", "redeem",
                   redeemParams, r, err) &&
            r.is_object())
        {
            s.redeemTxid = r.value("txid", std::string());
            if (s.want != "BTF" && r.value("awaitingConfirmation", false))
            {
                s.redeemSince = nNow;
                s.redeemFeeRate = r.contains("feeRatePerKvB") ? Sats(s.want, r["feeRatePerKvB"]) : 0;
                s.status = "redeemed; waiting for " + CoinName(s.want) + " to confirm it";
            }
            else
            {
                s.stage = SW_DONE;
                s.status = "done: received " + FormatSwapAmount(s.want, s.wantAmount) + " " + s.want;
            }
            if (s.fMaker)
            {
                SwapStep st;
                st.step = "redeemed";
                st.txid = s.redeemTxid;
                std::string e2;
                SendStep(s, st, e2);
            }
            return;
        }
        // Already ours from an earlier round, or gone?
        bool fSpent = false, fRefunded = false;
        std::string secret, e2;
        // Spent with the secret is our redeem; spent with neither the secret
        // nor a refund to show is a spend not yet in a block: wait for it.
        if (FindSecret(s.want, s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), fSpent, secret, fRefunded, e2) && fSpent &&
            (fRefunded || !secret.empty()))
        {
            if (fRefunded)
                TheirsRefunded(s, "they refunded theirs before we could take it");
            else
            {
                s.stage = SW_DONE;
                s.status = "done";
            }
            return;
        }
        s.lastError = err;
        return;
    }

    case SW_REFUNDING:
        if (!s.fMaker)
        {
            // Even now: if they take ours, the secret is ours too.
            bool fSpent = false, fRefunded = false;
            std::string secret;
            if (FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err) &&
                fSpent && !secret.empty())
            {
                s.secret = secret;
                s.stage = SW_REDEEMING;
                return;
            }
        }
        TryRefund(s);
        return;
    }
}

// ---- steps from the other side ----------------------------------------------

// Under cs, and calls nothing of the host's: the chat's lock is taken before
// this one (its store reads the swaps), never after. pMyOffer is the offer a
// take names, looked up beforehand -- NULL when it is not ours.
void SwapEngine::OnStep(const std::string& peer, const SwapStep& st, int64_t nNow, const SwapOffer* pMyOffer)
{
    if (st.step == "take")
    {
        if (swaps.count(st.swap) || !pMyOffer)
            return;
        const SwapOffer& o = *pMyOffer;
        // One take of this offer at a time from this peer, and a few takes
        // waiting in all: a fresh swap id costs the sender nothing, and each
        // swap is kept (and written out) until it is pruned.
        int nPending = 0;
        for (std::map<std::string, ChatSwap>::const_iterator q = swaps.begin(); q != swaps.end(); ++q)
            if (q->second.peer == peer && q->second.fMaker && !IsFinal(q->second.stage))
            {
                if (q->second.offerId == st.offer)
                    return;
                nPending++;
            }
        if (nPending >= config.nMaxPendingTakesPerPeer)
            return;
        if (o.give != st.terms.give || o.want != st.terms.want ||
            o.giveAmount != st.terms.giveAmount || o.wantAmount != st.terms.wantAmount)
            return;     // not its terms
        ChatSwap s;
        s.id = st.swap;
        s.peer = peer;
        s.offerId = st.offer;
        s.fMaker = true;
        s.give = o.give; s.giveAmount = o.giveAmount;
        s.want = o.want; s.wantAmount = o.wantAmount;
        s.theirRecv = st.to;
        s.stage = SW_TAKE_RECEIVED;
        s.created = s.updated = nNow;
        s.status = "they want to take your offer: " + DescribeSwapOffer(o);
        swaps[s.id] = s;
        return;
    }
    std::map<std::string, ChatSwap>::iterator it = swaps.find(st.swap);
    if (it == swaps.end() || it->second.peer != peer)
        return;
    ChatSwap& s = it->second;
    s.updated = nNow;
    if (st.step == "lock1" && !s.fMaker && s.stage == SW_TAKE_SENT && st.chain == s.want &&
        SwapAddressShapeOk(s.give, st.to))
    {
        s.theirContract = st.contract; s.theirTxid = st.txid; s.theirVout = st.vout;
        s.theirRecv = st.to;
        s.theirSince = nNow;
        s.stage = SW_CHECKING_THEIRS;
        s.status = "they locked their side; checking it";
    }
    else if (st.step == "lock2" && s.fMaker && s.stage == SW_LOCKED && st.chain == s.want)
    {
        s.theirContract = st.contract; s.theirTxid = st.txid; s.theirVout = st.vout;
        s.theirSince = nNow;
        s.stage = SW_REDEEMING;
        s.status = "they locked theirs; checking it before taking it";
    }
    else if (st.step == "cancel")
    {
        if (!s.fLockTried && s.myContract.empty() && s.myTxid.empty() && !s.fUserOk && !IsFinal(s.stage))
        {
            s.stage = SW_CANCELLED;
            s.status = "they cancelled" + (st.why.empty() ? std::string() : ": " + st.why);
        }
        else if (!IsFinal(s.stage))
            s.status = "they cancelled; ours comes back at its lock unless they take it";
    }
    // "redeemed" needs no handling: the secret is read off the chain.
}

// Under cs. Drops finished swaps past their keeping time, and, of those that
// never locked anything of ours, the oldest past the most kept; and the step
// ids that no conversation holds any more. Never a swap that is not over, and
// no swap with a contract or a transaction of ours (done, with a redeem that
// may not be confirmed yet; cancelled after a lock; failed) before its keeping
// time: its status and contract are what the person has to go on.
bool SwapEngine::Prune(int64_t nNow, const std::set<std::string>& stepIdsPresent, bool fPruneSteps)
{
    bool fChanged = false;
    std::vector<std::pair<int64_t, std::string> > finals;   // never locked: count and age
    std::vector<std::pair<int64_t, std::string> > locked;   // had a lock: age only
    for (std::map<std::string, ChatSwap>::const_iterator it = swaps.begin(); it != swaps.end(); ++it)
    {
        const ChatSwap& s = it->second;
        if (!IsFinal(s.stage))
            continue;
        bool fLocked = !s.myContract.empty() || !s.myTxid.empty() || s.fLockTried;
        (fLocked ? locked : finals).push_back(std::make_pair(std::max(s.updated, s.created), it->first));
    }
    std::sort(finals.begin(), finals.end());
    size_t nDrop = finals.size() > config.nKeepFinalMax ? finals.size() - config.nKeepFinalMax : 0;
    std::vector<std::string> vDrop;
    for (size_t i = 0; i < finals.size(); i++)
        if (i < nDrop || nNow - finals[i].first > config.nKeepFinalSecs)
            vDrop.push_back(finals[i].second);
    for (size_t i = 0; i < locked.size(); i++)
        if (nNow - locked[i].first > config.nKeepFinalSecs)
            vDrop.push_back(locked[i].second);
    for (size_t i = 0; i < vDrop.size(); i++)
    {
        std::map<std::string, ChatSwap>::iterator it = swaps.find(vDrop[i]);
        if (it != swaps.end() && !it->second.secret.empty())
            sodium_memzero(&it->second.secret[0], it->second.secret.size());
        swaps.erase(vDrop[i]);
        fChanged = true;
    }
    if (fPruneSteps)
        for (std::set<std::string>::iterator it = stepsSeen.begin(); it != stepsSeen.end(); )
            if (!stepIdsPresent.count(*it))
            {
                stepsSeen.erase(it++);
                fChanged = true;
            }
            else
                ++it;
    return fChanged;
}

void SwapEngine::ReadSteps()
{
    std::vector<std::string> peers;
    host->Contacts(peers);
    int64_t nNow = GetTime();
    bool fChanged = false;
    std::set<std::string> present;      // the step ids in the conversations now
    // Whether what is gone from the conversations is really gone: not while the
    // chat is locked (every conversation then reads back empty).
    bool fAllRead = !peers.empty() && host->Unlocked();
    for (size_t i = 0; i < peers.size(); i++)
    {
        std::vector<LogEntry> v;
        host->Conversation(peers[i], v);
        for (size_t k = 0; k < v.size(); k++)
        {
            const LogEntry& e = v[k];
            if (e.kind != MSG_SWAP || e.outgoing || e.from != peers[i])
                continue;
            present.insert(e.id);
            bool fNew = false;
            CRITICAL_BLOCK(cs)
                fNew = stepsSeen.insert(e.id).second;
            if (!fNew)
                continue;
            fChanged = true;
            SwapStep st;
            std::string err;
            if (!ParseSwapStep(e.text, st, err))
                continue;
            // A take nobody could have answered in time is not news: it would
            // only wait for the person and then be cancelled.
            if (st.step == "take" && nNow - e.sent > config.nAnswerWithin)
                continue;
            SwapOffer mine;
            bool fMine = st.step == "take" && host->FindMyOffer(st.offer, mine);
            CRITICAL_BLOCK(cs)
                OnStep(peers[i], st, nNow, fMine ? &mine : NULL);
        }
    }
    // Pruned after the reading, so what was just read is not read again: the
    // step ids kept are the ones still in a conversation, which is where a
    // step would be read from.
    CRITICAL_BLOCK(cs)
        if (Prune(nNow, present, fAllRead))
            fChanged = true;
    if (fChanged)
    {
        bool fSaved = host->Changed();
        CRITICAL_BLOCK(cs)
            strStoreError = fSaved ? std::string() : std::string("the chat store could not be saved");
    }
}

void SwapEngine::Round()
{
    ReadSteps();
    std::vector<std::string> ids;
    CRITICAL_BLOCK(cs)
        for (std::map<std::string, ChatSwap>::iterator it = swaps.begin(); it != swaps.end(); ++it)
            if (!IsFinal(it->second.stage))
                ids.push_back(it->first);
    for (size_t i = 0; i < ids.size() && !fShutdown; i++)
    {
        ChatSwap s;
        bool fHave = false;
        CRITICAL_BLOCK(cs)
        {
            std::map<std::string, ChatSwap>::iterator it = swaps.find(ids[i]);
            if (it != swaps.end())
            {
                s = it->second;
                fHave = true;
            }
        }
        if (!fHave)
            continue;
        ChatSwap before = s;
        s.lastError.clear();
        Tick(s);
        bool fChanged = s.stage != before.stage || s.status != before.status || s.lastError != before.lastError ||
                        s.secret != before.secret || s.fSentLock != before.fSentLock ||
                        s.fUserOk != before.fUserOk || s.fInvited != before.fInvited || s.myTxid != before.myTxid ||
                        s.myContract != before.myContract || s.fLockTried != before.fLockTried ||
                        s.refundTxid != before.refundTxid || s.redeemTxid != before.redeemTxid;
        if (fChanged)
            s.updated = GetTime();
        CRITICAL_BLOCK(cs)
        {
            std::map<std::string, ChatSwap>::iterator it = swaps.find(ids[i]);
            if (it != swaps.end())
            {
                // Pressed during this round: an approval still counts if the
                // stage it was for is the stage we are in, and a cancel stands
                // -- Cancel refuses once anything of ours is locked, so it
                // never undoes a lock.
                bool fApprovedMeanwhile = it->second.fUserOk && !before.fUserOk && s.stage == before.stage;
                bool fCancelledMeanwhile = it->second.stage == SW_CANCELLED && before.stage != SW_CANCELLED;
                // Cancelled while waiting for the contract's payment: the round
                // may have just seen that payment, but the swap stays called off
                // and the refund stage gives the payment back.
                bool fWithdrawnMeanwhile = before.stage == SW_WAIT_PAYMENT && it->second.stage == SW_REFUNDING &&
                                           (s.stage == SW_WAIT_PAYMENT || s.stage == SW_LOCKED);
                std::string strWithdrawn = it->second.status;
                // Changed by the person during this round: kept only while
                // nothing of ours is locked yet. The round that locked used
                // (and checked) the one it read; after that it is fixed.
                if (s.myContract.empty() && s.redeemTxid.empty())
                    s.btcDestination = it->second.btcDestination;
                it->second = s;
                if (fApprovedMeanwhile)
                    it->second.fUserOk = true;
                if (fCancelledMeanwhile && s.myTxid.empty())
                    it->second.stage = SW_CANCELLED;
                if (fWithdrawnMeanwhile)
                {
                    it->second.stage = SW_REFUNDING;
                    it->second.status = strWithdrawn;
                }
            }
        }
        if (fChanged)
        {
            bool fSaved = host->Changed();
            CRITICAL_BLOCK(cs)
                strStoreError = fSaved ? std::string() : std::string("the chat store could not be saved");
        }
    }
}

void SwapEngine::List(std::vector<SwapView>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs)
        for (std::map<std::string, ChatSwap>::const_iterator it = swaps.begin(); it != swaps.end(); ++it)
        {
            const ChatSwap& s = it->second;
            SwapView v;
            v.id = s.id; v.peer = s.peer; v.fMaker = s.fMaker;
            v.give = s.give; v.want = s.want; v.giveAmount = s.giveAmount; v.wantAmount = s.wantAmount;
            v.stage = s.stage; v.btcDestination = s.btcDestination; v.paymentAddress = s.paymentAddress;
            v.status = s.status + (s.lastError.empty() ? std::string() : " (" + s.lastError + ")") +
                       (strStoreError.empty() || IsFinal(s.stage) ? std::string() : " [" + strStoreError + "]");
            v.fNeedsMe = !s.fUserOk && (s.stage == SW_TAKE_RECEIVED || s.stage == SW_READY_TO_LOCK);
            v.fCanCancel = !s.fLockTried &&
                           ((s.myContract.empty() && s.myTxid.empty() && !s.fUserOk && !IsFinal(s.stage)) ||
                            (s.stage == SW_WAIT_PAYMENT && s.myTxid.empty()));
            v.myTxid = s.myTxid; v.theirTxid = s.theirTxid;
            v.redeemTxid = s.redeemTxid; v.refundTxid = s.refundTxid;
            v.updated = s.updated;
            out.push_back(v);
        }
}

bool SwapEngine::Take(const std::string& peer, const std::string& offerId, const SwapOffer& o,
                      std::string& idOut, std::string& errOut)
{
    errOut.clear();
    if (peer == host->MyAddress())
    {
        errOut = "that is your own offer";
        return false;
    }
    ChatSwap s;
    s.id = NewId();
    s.peer = peer;
    s.offerId = offerId;
    s.fMaker = false;
    s.give = o.want; s.giveAmount = o.wantAmount;
    s.want = o.give; s.wantAmount = o.giveAmount;
    s.stage = SW_INVITING;
    s.created = s.updated = GetTime();
    s.status = "taking: " + DescribeSwapOffer(o);
    idOut = s.id;
    CRITICAL_BLOCK(cs)
        swaps[s.id] = s;
    host->Changed();
    return true;
}

bool SwapEngine::Approve(const std::string& id, std::string& errOut)
{
    errOut.clear();
    CRITICAL_BLOCK(cs)
    {
        std::map<std::string, ChatSwap>::iterator it = swaps.find(id);
        if (it == swaps.end() || (it->second.stage != SW_TAKE_RECEIVED && it->second.stage != SW_READY_TO_LOCK))
        {
            errOut = "nothing to approve on that swap";
            return false;
        }
        it->second.fUserOk = true;
        it->second.lastError.clear();
        it->second.status = "locking ours...";
    }
    host->Changed();
    return true;
}

bool SwapEngine::SetBitcoinDestination(const std::string& id, const std::string& address)
{
    if (address.empty() || address.size() > 90) return false;
    std::string coin;
    CRITICAL_BLOCK(cs)
    {
        auto it = swaps.find(id);
        if (it == swaps.end() || !it->second.myContract.empty() || !it->second.redeemTxid.empty()) return false;
        coin = Other(it->second);
    }
    // Called from the screen: no wallet call here (one can wait minutes behind
    // a long one). Only its shape; the round asks the wallet whether it is an
    // address of that chain and network before anything is locked, and it
    // cannot be changed once ours is.
    (void)coin;
    for (size_t i = 0; i < address.size(); i++)
        if (!isalnum((unsigned char)address[i]) && address[i] != ':')
            return false;
    CRITICAL_BLOCK(cs)
    {
        auto it = swaps.find(id);
        if (it == swaps.end() || !it->second.myContract.empty() || !it->second.redeemTxid.empty()) return false;
        it->second.btcDestination = address;
    }
    host->Changed();
    return true;
}

bool SwapEngine::Cancel(const std::string& id, std::string& errOut)
{
    errOut.clear();
    ChatSwap s;
    CRITICAL_BLOCK(cs)
    {
        std::map<std::string, ChatSwap>::iterator it = swaps.find(id);
        if (it == swaps.end() || IsFinal(it->second.stage))
        {
            errOut = "no such swap in progress";
            return false;
        }
        if (it->second.fLockTried)
        {
            errOut = "the last lock gave no clear answer; wait until the wallet says whether anything was locked";
            return false;
        }
        if (it->second.stage == SW_WAIT_PAYMENT && it->second.myTxid.empty())
        {
            // Our contract exists but nothing paid it yet. It cannot simply be
            // forgotten -- a payment may already be on its way -- so the refund
            // stage keeps watching it and gives back anything that arrives.
            it->second.stage = SW_REFUNDING;
            it->second.status = "cancelled: do not pay the contract now (anything already sent comes back at the lock)";
        }
        else if (!it->second.myContract.empty() || !it->second.myTxid.empty() || it->second.fUserOk)
        {
            errOut = "ours is locked (or being locked): it comes back at the lock, or the swap finishes";
            return false;
        }
        else
        {
            it->second.stage = SW_CANCELLED;
            it->second.status = "cancelled";
        }
        s = it->second;
    }
    if (s.fInvited || s.fMaker || !s.myRecv.empty())
        SendCancel(s, "cancelled");
    host->Changed();
    return true;
}

// ---- the chat app's engine ------------------------------------------------------

class ChatHost : public SwapHost
{
public:
    std::string MyAddress() { return ChatAddress(); }
    bool PeerAccepted(const std::string& peer) { return ChatPeerState(peer) == PEER_ACCEPTED; }
    bool Invite(const std::string& peer, const std::string& note, std::string& errOut)
    {
        return ChatInvite(peer, note, errOut);
    }
    bool SendStep(const std::string& peer, const std::string& stepText, std::string& errOut)
    {
        bool fLeft = false;
        return ChatSendSwapStep(peer, stepText, fLeft, errOut);
    }
    void Contacts(std::vector<std::string>& out) { ChatContacts(out); }
    void Conversation(const std::string& peer, std::vector<LogEntry>& out) { ChatConversation(peer, out); }
    bool FindMyOffer(const std::string& offerId, SwapOffer& out)
    {
        std::vector<std::pair<std::string, std::string> > cs;
        ChatCommunities(cs);
        for (size_t i = 0; i < cs.size(); i++)
        {
            std::vector<LogEntry> v;
            ChatCommunityLog(cs[i].first, v);
            for (size_t k = 0; k < v.size(); k++)
            {
                std::string err;
                if (v[k].id == offerId && v[k].outgoing && v[k].kind == MSG_SWAP_OFFER &&
                    ParseSwapOffer(v[k].text, out, err))
                    return true;
            }
        }
        return false;
    }
    bool Wallet(const std::string& method, const json& params, json& resultOut, std::string& errOut)
    {
        return WalletRpc(method, params, resultOut, errOut);
    }
    bool Changed() { return ChatSaveStore(); }
    bool Unlocked() { return ChatUnlocked(); }
};

static ChatHost g_chatHost;
static SwapEngine g_engine(&g_chatHost);
static volatile bool g_fWake = false;

std::string SwapsToJson() { return g_engine.ToJson(); }
void SwapsFromJson(const std::string& s) { g_engine.FromJson(s); }
void SwapsClear() { g_engine.Clear(); }
void ChatSwapList(std::vector<SwapView>& out) { g_engine.List(out); }

static bool WalletCanSwap(const std::string& a, const std::string& b, std::string& err)
{
    // The wallet refuses before the launch day too; saying so here keeps an
    // offer nobody can take out of the community.
    if (!SwapsOpen((unsigned int)GetTime()))
    {
        time_t t = (time_t)SwapsOpenTime();
        char buf[32] = "";
        struct tm* g = gmtime(&t);
        if (g)
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", g);
        err = SwapsOpenTime() == 0 ? std::string("atomic swaps are not scheduled on this network")
                                   : strprintf("atomic swaps open at %s UTC", buf);
        return false;
    }
    json r;
    if (!WalletRpc("getinfo", json::array(), r, err))
        return false;
    for (const std::string& coin : { a, b })
    {
        if (coin == "BTF")
            continue;
        std::string strLower = coin;
        std::transform(strLower.begin(), strLower.end(), strLower.begin(), ::tolower);
        bool fReady = coin == "BTC" ? WalletRpc("btcswapinfo", json::array(), r, err)
                                    : WalletRpc("coinswapinfo", json::array({ strLower }), r, err);
        if (!fReady)
        {
            err = "the " + CoinName(coin) + " side is not ready: " + err;
            return false;
        }
        // A node that answers but whose wallet does not, say two loaded and
        // none named, could not spend what the swap gives it.
        if (r.is_object() && r.contains("walletError"))
        {
            err = "the " + CoinName(coin) + " side is not ready: " + r["walletError"].dump();
            return false;
        }
    }
    return true;
}

bool ChatSwapPostOffer(const std::string& communityId, const SwapOffer& offer, std::string& errOut)
{
    errOut.clear();
    SwapOffer check;
    if (!ParseSwapOffer(FormatSwapOffer(offer), check, errOut))
        return false;
    if (!WalletCanSwap(offer.give, offer.want, errOut))
        return false;
    return ChatCommunityPostOffer(communityId, FormatSwapOffer(offer), errOut);
}

bool ChatSwapTake(const std::string& communityId, const std::string& offerFrameId, std::string& errOut)
{
    errOut.clear();
    std::vector<LogEntry> v;
    ChatCommunityLog(communityId, v);
    for (size_t k = 0; k < v.size(); k++)
    {
        const LogEntry& e = v[k];
        if (e.id != offerFrameId || e.kind != MSG_SWAP_OFFER)
            continue;
        if (e.outgoing)
        {
            errOut = "that is your own offer";
            return false;
        }
        SwapOffer o;
        if (!ParseSwapOffer(e.text, o, errOut))
            return false;
        if (!WalletCanSwap(o.give, o.want, errOut))
            return false;
        std::string id;
        if (!g_engine.Take(e.from, e.id, o, id, errOut))
            return false;
        ChatSwapWake();
        return true;
    }
    errOut = "that offer is not in this community";
    return false;
}

bool ChatSwapApprove(const std::string& id, std::string& errOut)
{
    if (!g_engine.Approve(id, errOut))
        return false;
    ChatSwapWake();
    return true;
}

bool ChatSwapCancel(const std::string& id, std::string& errOut)
{
    return g_engine.Cancel(id, errOut);
}

bool ChatSwapBitcoinDestination(const std::string& id, const std::string& address)
{
    return g_engine.SetBitcoinDestination(id, address);
}

void ChatSwapWake()
{
    g_fWake = true;
}

void ThreadChatSwaps(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatSwaps(parg));
    while (!fShutdown)
    {
        if (ChatUnlocked())
        {
            try { g_engine.Round(); }
            catch (std::exception& e) { printf("btfchat: swap round: %s\n", e.what()); }
            catch (...) { printf("btfchat: swap round: unknown exception\n"); }
        }
        for (int i = 0; i < 20 && !fShutdown && !g_fWake; i++)
            Sleep(1000);
        g_fWake = false;
    }
}

} // namespace btfchat
