// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btfchatswap.h.

#include "headers.h"
#include "btfchatswap.h"
#include "btfchatnode.h"
#include "btfchatwallet.h"

#include <sodium.h>

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
    j["redeem"] = s.redeemTxid; j["refund"] = s.refundTxid;
    j["stage"] = s.stage; j["ok"] = s.fUserOk; j["inv"] = s.fInvited; j["sent"] = s.fSentLock;
    j["status"] = s.status; j["err"] = s.lastError;
    j["created"] = s.created; j["updated"] = s.updated; j["since"] = s.theirSince;
    j["rsince"] = s.redeemSince; j["rfee"] = s.redeemFeeRate;
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
        s.stage = j.value("stage", (int)SW_FAILED); s.fUserOk = j.value("ok", false);
        s.fInvited = j.value("inv", false); s.fSentLock = j.value("sent", false);
        s.status = j.value("status", std::string()); s.lastError = j.value("err", std::string());
        s.created = j.value("created", (int64_t)0); s.updated = j.value("updated", (int64_t)0);
        s.theirSince = j.value("since", (int64_t)0);
        s.redeemSince = j.value("rsince", (int64_t)0); s.redeemFeeRate = j.value("rfee", (int64_t)0);
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

static std::string AmountText(int64_t n)
{
    return strprintf("%lld.%08lld", (long long)(n / COIN), (long long)(n % COIN));
}

static int64_t Sats(const json& v)
{
    if (!v.is_number())
        return -1;
    double d = v.get<double>();
    return (int64_t)(d * COIN + (d >= 0 ? 0.5 : -0.5));
}

static std::string Ref(const std::string& coin, const std::string& txid, int vout)
{
    return coin == "BTC" ? txid + ":" + strprintf("%d", vout) : txid;
}

static const char* Method(const std::string& coin, const char* btf, const char* btc)
{
    return coin == "BTC" ? btc : btf;
}

static std::string NewId()
{
    unsigned char b[16];
    randombytes_buf(b, sizeof(b));
    return HexStr(b, b + sizeof(b), false);
}

int SwapEngine::MinConfirmations() const
{
    if (config.nMinConfirmations > 0)
        return config.nMinConfirmations;
    return IsTestNet() ? 1 : 2;
}

bool SwapEngine::Wallet(const char* method, const json& params, json& r, std::string& err)
{
    return host->Wallet(method, params, r, err);
}

bool SwapEngine::NewAddress(const std::string& coin, std::string& out, std::string& err)
{
    json r;
    if (!Wallet(Method(coin, "getnewaddress", "btcnewaddress"), json::array(), r, err))
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
    if (s.give == "BTC")
    {
        int64_t n = fInitiator ? config.nBtcInitiatorSecs : config.nBtcParticipantSecs;
        return n > 0 ? json(n) : json(nullptr);
    }
    int n = fInitiator ? config.nBtfInitiatorBlocks : config.nBtfParticipantBlocks;
    return n > 0 ? json(n) : json(nullptr);
}

enum Verdict { V_OK, V_WAIT, V_BAD };

// Their contract, as our own nodes see it.
int SwapEngine::CheckTheirs(const ChatSwap& s, int64_t nMinLeft, const std::string& expectHash,
                            std::string& hashOut, std::string& why)
{
    json a;
    std::string err;
    if (!Wallet(Method(s.want, "swapauditcontract", "btcauditcontract"),
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
    if (Sats(a["amount"]) != s.wantAmount)
    {
        why = "their contract holds " + a["amount"].dump() + " " + s.want + ", not " + FormatSwapAmount(s.wantAmount);
        return V_BAD;
    }
    if (nConf < MinConfirmations())
    {
        why = strprintf("their contract has %d of %d confirmations", nConf, MinConfirmations());
        return V_WAIT;
    }
    int64_t nLeft = s.want == "BTC" ? a.value("secondsUntilRefund", (int64_t)0)
                                    : a.value("blocksUntilRefund", (int64_t)0) * BTF_BLOCK_SECS;
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
    if (!Wallet(Method(s.give, "swapauditcontract", "btcauditcontract"),
                json::array({ s.myContract, Ref(s.give, s.myTxid, s.myVout) }), a, err) || !a.is_object())
        return false;
    nLeft = s.give == "BTC" ? a.value("secondsUntilRefund", (int64_t)0)
                            : a.value("blocksUntilRefund", (int64_t)0) * BTF_BLOCK_SECS;
    return true;
}

// Seconds until their contract can be refunded by them; 0 once it can, or
// once it is spent and there is nothing left in it to take.
bool SwapEngine::TheirTimeLeft(const ChatSwap& s, int64_t& nLeft, std::string& err)
{
    json a;
    if (!Wallet(Method(s.want, "swapauditcontract", "btcauditcontract"),
                json::array({ s.theirContract, Ref(s.want, s.theirTxid, s.theirVout) }), a, err) || !a.is_object())
        return false;
    nLeft = !a.value("unspent", false) ? 0
          : s.want == "BTC" ? a.value("secondsUntilRefund", (int64_t)0)
                            : a.value("blocksUntilRefund", (int64_t)0) * BTF_BLOCK_SECS;
    return true;
}

// Has a contract been spent, and did the spend show the secret?
bool SwapEngine::FindSecret(const std::string& coin, const std::string& contract, const std::string& ref,
                            bool& fSpent, std::string& secretOut, bool& fRefunded, std::string& err)
{
    json r;
    fSpent = false;
    fRefunded = false;
    secretOut.clear();
    if (!Wallet(Method(coin, "swapfindsecret", "btcfindsecret"), json::array({ contract, ref }), r, err) || !r.is_object())
        return false;
    fSpent = r.value("spent", false);
    secretOut = r.value("secret", std::string());
    fRefunded = r.value("refunded", false);
    return true;
}

// Locking one of ours: what the wallet answers, kept in the swap.
static bool TakeLockResult(ChatSwap& s, const json& r, std::string& err)
{
    if (!r.is_object() || !r.contains("contract") || !r.contains("contractTxid"))
    {
        err = "the wallet's answer has no contract";
        return false;
    }
    s.paymentAddress = r.value("awaitingPayment", false) ? r.value("contractAddress", std::string()) : std::string();
    s.myContract = r["contract"].get<std::string>();
    s.myTxid = r["contractTxid"].get<std::string>();
    s.myVout = s.give == "BTC" && r.contains("vout") ? r["vout"].get<int>() : -1;
    if (r.contains("secret"))
        s.secret = r["secret"].get<std::string>();
    if (r.contains("secretHash"))
        s.secretHash = r["secretHash"].get<std::string>();
    return true;
}

// The refund at the end of our lock, and what to make of it failing.
void SwapEngine::TryRefund(ChatSwap& s)
{
    int64_t nLeft = 1;
    std::string err;
    if (!s.fMaker && !s.refundTxid.empty())
    {
        // Our refund went out, but the maker holds the secret and can still
        // redeem ours instead -- outbidding the refund's fee -- which shows
        // the secret. Until their own lock opens, the refund stage keeps
        // looking for that (above), so theirs would be ours to take.
        if (!TheirTimeLeft(s, nLeft, err))
        {
            s.lastError = err;
            return;
        }
        if (nLeft <= 0)
        {
            s.stage = SW_REFUNDED;
            s.status = "refunded: our " + FormatSwapAmount(s.giveAmount) + " " + s.give + " came back";
        }
        else
            s.status = strprintf("refunded ours; watching theirs for %lld more minutes in case ours is taken instead",
                                 (long long)(nLeft / 60 + 1));
        return;
    }
    if (s.give == "BTC" && s.myTxid.empty())
    {
        // Our contract waited for a payment from another wallet. Paid after
        // all: refund that like any other lock. Never paid: once a day past
        // the lock has given a late payment time to confirm, it is over.
        json a;
        if (!Wallet("btcauditcontract", json::array({ s.myContract, "" }), a, err) || !a.is_object())
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
    if (s.give == "BTC" && !s.btcDestination.empty()) refundParams.push_back(s.btcDestination);
    if (Wallet(Method(s.give, "swaprefund", "btcrefund"),
               refundParams, r, err) && r.is_object())
    {
        s.refundTxid = r.value("txid", std::string());
        if (!s.fMaker && !s.theirContract.empty())
        {
            s.stage = SW_REFUNDING;
            s.status = "refunded ours; watching theirs in case ours is taken instead";
            return;
        }
        s.stage = SW_REFUNDED;
        s.status = "refunded: our " + FormatSwapAmount(s.giveAmount) + " " + s.give + " came back";
        return;
    }
    // Spent already? With the secret means they redeemed ours -- which they
    // can only do after we showed the secret, i.e. after we took theirs.
    bool fSpent = false, fRefunded = false;
    std::string secret, err2;
    if (FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err2) && fSpent)
    {
        s.stage = fRefunded ? SW_REFUNDED : SW_DONE;
        s.status = fRefunded ? "refunded" : "they took ours with the secret";
        return;
    }
    s.lastError = err;
}

// ---- one round for one swap ----------------------------------------------------

void SwapEngine::Tick(ChatSwap& s)
{
    int64_t nNow = GetTime();
    std::string err;
    if ((s.stage == SW_TAKE_RECEIVED || s.stage == SW_READY_TO_LOCK) && s.fUserOk)
    {
        json info;
        if (Wallet("btcswapinfo", json::array(), info, err) && info.value("backend", std::string()) == "light")
        {
            json checked;
            if (s.btcDestination.empty() || !Wallet("btcvalidatedestination", json::array({s.btcDestination}), checked, err))
            {
                s.status = "enter your Bitcoin receiving address before locking";
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
        json params = json::array({ s.theirRecv, AmountText(s.giveAmount) });
        json lock = LockParams(s, true);
        if (!lock.is_null())
            params.push_back(lock);
        json r;
        if (!Wallet(Method(s.give, "swapinitiate", "btcinitiate"), params, r, err) || !TakeLockResult(s, r, err))
        {
            s.lastError = err;
            s.fUserOk = false;      // the person decides again, knowing why
            return;
        }
        s.stage = s.paymentAddress.empty() ? SW_LOCKED : SW_WAIT_PAYMENT;
        s.fSentLock = false;
        s.status = "locked ours; waiting for them to lock theirs";
        // Saved by the caller before anything else is tried: the secret is in
        // the swap now, and it is the one thing that cannot be made again.
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
            s.status = "their " + FormatSwapAmount(s.wantAmount) + " " + s.want + " is locked for us and checks out";
            return;
        }
        if (!s.fUserOk)
            return;
        json params = json::array({ s.theirRecv, AmountText(s.giveAmount), s.secretHash });
        json lock = LockParams(s, false);
        if (!lock.is_null())
            params.push_back(lock);
        json r;
        if (!Wallet(Method(s.give, "swapparticipate", "btcparticipate"), params, r, err) || !TakeLockResult(s, r, err))
        {
            s.lastError = err;
            s.fUserOk = false;
            return;
        }
        s.stage = s.paymentAddress.empty() ? SW_LOCKED : SW_WAIT_PAYMENT;
        s.fSentLock = false;
        s.status = "locked ours; waiting for them to take it, which shows the secret";
        return;
    }

    case SW_WAIT_PAYMENT:
    {
        s.status = "waiting for you to pay the contract: pay exactly " + AmountText(s.giveAmount) + " BTC to " + s.paymentAddress;
        json audit;
        if (!Wallet("btcauditcontract", json::array({s.myContract, ""}), audit, err))
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
            SendCancel(s, "the Bitcoin contract was never paid");
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
        if (!audit.value("unspent", false) || audit.value("confirmations", 0) < MinConfirmations()) return;
        s.myTxid = audit.at("contractTxid").get<std::string>(); s.myVout = audit.at("vout").get<int>();
        if (Sats(audit["amount"]) != s.giveAmount || audit.value("secondsUntilRefund", (int64_t)0) <= 0)
        {
            s.stage = SW_REFUNDING;
            s.status = "payment amount differs or contract expired; waiting to refund";
            return;
        }
        s.stage = SW_LOCKED; s.fSentLock = false;
        s.status = "Bitcoin contract payment confirmed";
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
            bool fSpent = false, fRefunded = false;
            std::string secret;
            if (FindSecret(s.give, s.myContract, Ref(s.give, s.myTxid, s.myVout), fSpent, secret, fRefunded, err))
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
                    s.stage = SW_REFUNDED;
                    s.status = "refunded";
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
            if (FindSecret(s.want, s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), fSpent, secret, fRefunded, e2) && fSpent)
            {
                s.redeemSince = 0;
                s.stage = fRefunded ? SW_FAILED : SW_DONE;
                s.status = fRefunded ? "they refunded theirs before our redeem confirmed"
                                     : "done: received " + FormatSwapAmount(s.wantAmount) + " " + s.want;
                return;
            }
            if (!e2.empty())
                s.lastError = e2;
            if (nNow - s.redeemSince < config.nRedeemBumpAfter)
            {
                s.status = "redeemed; waiting for Bitcoin to confirm it";
                return;
            }
            int64_t nRate = std::min<int64_t>(std::max<int64_t>(s.redeemFeeRate, 1000) * 2, 1000000);
            json r;
            json bumpParams = json::array({s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), s.secret,
                                           s.btcDestination, AmountText(nRate)});
            if (Wallet("btcredeem", bumpParams, r, err) && r.is_object())
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
        if (s.want == "BTC" && !s.btcDestination.empty()) redeemParams.push_back(s.btcDestination);
        if (Wallet(Method(s.want, "swapredeem", "btcredeem"),
                   redeemParams, r, err) &&
            r.is_object())
        {
            s.redeemTxid = r.value("txid", std::string());
            if (s.want == "BTC" && r.value("awaitingConfirmation", false))
            {
                s.redeemSince = nNow;
                s.redeemFeeRate = r.contains("feeRatePerKvB") ? Sats(r["feeRatePerKvB"]) : 0;
                s.status = "redeemed; waiting for Bitcoin to confirm it";
            }
            else
            {
                s.stage = SW_DONE;
                s.status = "done: received " + FormatSwapAmount(s.wantAmount) + " " + s.want;
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
        if (FindSecret(s.want, s.theirContract, Ref(s.want, s.theirTxid, s.theirVout), fSpent, secret, fRefunded, e2) && fSpent)
        {
            s.stage = fRefunded ? SW_FAILED : SW_DONE;
            s.status = fRefunded ? "they refunded theirs before we could take it" : "done";
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
        if (s.myTxid.empty() && !s.fUserOk && !IsFinal(s.stage))
        {
            s.stage = SW_CANCELLED;
            s.status = "they cancelled" + (st.why.empty() ? std::string() : ": " + st.why);
        }
        else if (!IsFinal(s.stage))
            s.status = "they cancelled; ours comes back at its lock unless they take it";
    }
    // "redeemed" needs no handling: the secret is read off the chain.
}

void SwapEngine::ReadSteps()
{
    std::vector<std::string> peers;
    host->Contacts(peers);
    int64_t nNow = GetTime();
    bool fChanged = false;
    for (size_t i = 0; i < peers.size(); i++)
    {
        std::vector<LogEntry> v;
        host->Conversation(peers[i], v);
        for (size_t k = 0; k < v.size(); k++)
        {
            const LogEntry& e = v[k];
            if (e.kind != MSG_SWAP || e.outgoing || e.from != peers[i])
                continue;
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
            SwapOffer mine;
            bool fMine = st.step == "take" && host->FindMyOffer(st.offer, mine);
            CRITICAL_BLOCK(cs)
                OnStep(peers[i], st, nNow, fMine ? &mine : NULL);
        }
    }
    if (fChanged)
        host->Changed();
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
                        s.fUserOk != before.fUserOk || s.fInvited != before.fInvited || s.myTxid != before.myTxid;
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
            host->Changed();
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
            v.status = s.status + (s.lastError.empty() ? std::string() : " (" + s.lastError + ")");
            v.fNeedsMe = !s.fUserOk && (s.stage == SW_TAKE_RECEIVED || s.stage == SW_READY_TO_LOCK);
            v.fCanCancel = (s.myContract.empty() && s.myTxid.empty() && !s.fUserOk && !IsFinal(s.stage)) ||
                           (s.stage == SW_WAIT_PAYMENT && s.myTxid.empty());
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
    void Changed() { ChatSaveStore(); }
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
    if ((a == "BTC" || b == "BTC") && !WalletRpc("btcswapinfo", json::array(), r, err))
    {
        err = "the Bitcoin side is not ready: " + err;
        return false;
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
        }
        for (int i = 0; i < 20 && !fShutdown && !g_fWake; i++)
            Sleep(1000);
        g_fWake = false;
    }
}

} // namespace btfchat
