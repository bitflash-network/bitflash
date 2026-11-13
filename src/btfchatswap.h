// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The swap engine: an atomic swap BTF<->BTC carried through from an offer in
// a community to both sides paid, by the chat, with the person's own wallet.
//
// WHO DOES WHAT. The chat holds no coins and signs no transaction. Every lock,
// audit, redeem and refund is a call to the person's Bitflash wallet (linked
// with -chatwallet), which does the Bitflash half itself and the Bitcoin half
// against the person's Bitcoin Core (btcswap.h). The chat carries the steps
// (chatswap.h) and keeps, sealed in its store, what the swap needs later: the
// secret, both contracts, where they were funded.
//
// WHAT NEEDS THE PERSON. Locking a coin: the maker accepts a take, the taker
// confirms after the maker's contract checks out. Nothing else. Redeeming and
// refunding only ever pay this person's own wallet, so the engine does them
// on its own -- including the refund after a lock runs out, which is the one
// thing that must happen even if nobody is looking.
//
// WHAT IS CHECKED BEFORE A COIN MOVES.
//   taker, before locking: the maker's contract is on the chain, unspent,
//     confirmed, not a coinbase, locked by time, pays the taker's own address
//     the agreed amount, and has at least 36 hours left -- the taker's own
//     lock is 24, or 18 on Bitflash (swap.h, THE TIMING); a taker giving BTF
//     also waits while Bitflash blocks are coming slowly.
//   maker, before redeeming (which shows the secret): the taker's contract
//     is on the chain, unspent, confirmed, pays the maker's own address the
//     agreed amount under the maker's secret hash, and has at least 6 hours
//     left, so the redeem is in a block before the taker could refund.
// The secret is read off the chain by the side waiting for it, so a maker who
// redeems and goes quiet still pays out.
//
// Not reached: a taker whose app stays closed for the whole 24 hours after
// the maker redeems. Then the maker could refund too and keep both. It is the
// reason the maker's lock is twice the taker's, and why the app warns to stay
// open while a swap runs.

#ifndef BITFLASH_BTFCHATSWAP_H
#define BITFLASH_BTFCHATSWAP_H

#include "chatswap.h"
#include "btfchatlog.h"
#include "rpcclient.h"

#include <map>
#include <set>
#include <string>
#include <vector>
#include <stdint.h>

namespace btfchat
{

enum SwapStage
{
    SW_INVITING = 0,     // taker: our invite to the maker is not accepted yet
    SW_TAKE_SENT,        // taker: waiting for the maker to lock
    SW_TAKE_RECEIVED,    // maker: somebody takes the offer; the person decides
    SW_CHECKING_THEIRS,  // taker: the maker locked; checking that contract
    SW_READY_TO_LOCK,    // taker: it checks out; the person confirms the lock
    SW_LOCKED,           // ours is locked; waiting for the other side
    SW_REDEEMING,        // taking theirs (maker: after checking it)
    SW_DONE,
    SW_REFUNDING,        // ours is locked and the swap will not finish: refund at the lock
    SW_REFUNDED,
    SW_CANCELLED,        // ended before anything of ours was locked
    SW_FAILED,           // something the engine cannot fix; see status
    SW_WAIT_PAYMENT,     // the external Bitcoin wallet must fund our contract
};

struct SwapView
{
    std::string id, peer;
    bool        fMaker;
    std::string give, want;         // ours / theirs
    int64_t     giveAmount, wantAmount;
    int         stage;
    std::string status;             // a sentence for the screen
    bool        fNeedsMe;           // TAKE_RECEIVED or READY_TO_LOCK
    bool        fCanCancel;         // nothing of ours is locked yet
    std::string myTxid, theirTxid, redeemTxid, refundTxid;
    std::string btcDestination, paymentAddress;
    int64_t     updated;

    SwapView() : fMaker(false), giveAmount(0), wantAmount(0), stage(0), fNeedsMe(false),
                 fCanCancel(false), updated(0) {}
};

// ---- the engine, apart from the chat ------------------------------------------
//
// Everything the engine needs from outside goes through SwapHost: the chat in
// the app, and in the chat-swap self-test two engines wired to each other and
// to real wallets on real chains -- which is how the whole state machine is
// proven with coins, not only its message format.

class SwapHost
{
public:
    virtual ~SwapHost() {}
    virtual std::string MyAddress() = 0;
    virtual bool PeerAccepted(const std::string& peer) = 0;
    virtual bool Invite(const std::string& peer, const std::string& note, std::string& errOut) = 0;
    // True when it left, or is queued to leave.
    virtual bool SendStep(const std::string& peer, const std::string& stepText, std::string& errOut) = 0;
    virtual void Contacts(std::vector<std::string>& out) = 0;
    virtual void Conversation(const std::string& peer, std::vector<LogEntry>& out) = 0;
    // An offer WE posted, by its frame id.
    virtual bool FindMyOffer(const std::string& offerId, SwapOffer& out) = 0;
    virtual bool Wallet(const std::string& method, const nlohmann::json& params, nlohmann::json& resultOut,
                        std::string& errOut) = 0;
    // Something changed that has to survive a restart: save now. False when
    // it could not be saved; no new lock is made until it can.
    virtual bool Changed() = 0;
    // Can the conversations be read? False while the chat is locked, when they
    // all read back empty and nothing may be concluded from what is missing.
    virtual bool Unlocked() { return true; }
};

struct SwapConfig
{
    int64_t nTakerMinLeft = 36 * 3600;   // on the maker's contract, before the taker locks
    int64_t nMakerMinLeft = 6 * 3600;    // on the taker's, before the maker shows the secret
    int64_t nGiveUpWaiting = 12 * 3600;  // a contract that never confirms
    int64_t nAnswerWithin = 24 * 3600;   // a take nobody answers
    int64_t nRedeemBumpAfter = 3600;     // a light-client Bitcoin redeem still unconfirmed: send again, fee doubled
    int     nMinConfirmations = 0;       // 0: 1 on testnet; on mainnet 2, 8 on Litecoin
    // A taker giving BTF waits while the Bitflash tip's median time is this
    // far behind the clock (swap.h, THE TIMING); 0: no such wait.
    int64_t nBtfMaxMedianLag = 3600;
    // Test chains only (the wallet refuses them on mainnet): shorter locks,
    // in seconds on every chain.
    int64_t nBtfInitiatorSecs = 0, nBtfParticipantSecs = 0;
    int64_t nBtcInitiatorSecs = 0, nBtcParticipantSecs = 0;
    // What the engine keeps and accepts from the other side (review L4). A
    // contact can send a take with a fresh swap id as often as it likes, and
    // every swap, and every step id seen, is written out whole on each change.
    // One take of an offer at a time per peer, and a few takes per peer in all;
    // a finished swap is kept this long, and no more than this many are kept.
    int     nMaxPendingTakesPerPeer = 8;
    int64_t nKeepFinalSecs = 30 * 24 * 3600;
    size_t  nKeepFinalMax = 100;
};

struct ChatSwap
{
    std::string id, peer, offerId;
    bool        fMaker = false;
    std::string give, want;
    int64_t     giveAmount = 0, wantAmount = 0;
    std::string myRecv;          // where we want their coin (on `want`)
    std::string theirRecv;       // where they want ours (on `give`)
    std::string secret, secretHash;
    std::string myContract, myTxid;
    std::string btcDestination, paymentAddress;
    int         myVout = -1;
    std::string theirContract, theirTxid;
    int         theirVout = -1;
    std::string redeemTxid, refundTxid;
    int         stage = SW_INVITING;
    bool        fUserOk = false, fInvited = false, fSentLock = false;
    // A lock call (initiate/participate) gave no answer: until the wallet's
    // journal says whether it locked anything (swaplookup), the swap is
    // neither locked again nor called off.
    bool        fLockTried = false;
    std::string status, lastError;
    int64_t     created = 0, updated = 0, theirSince = 0;
    int64_t     refundSince = 0, refundFeeRate = 0;   // a refund sent, no block has it yet
    int64_t     redeemSince = 0, redeemFeeRate = 0;   // a Bitcoin redeem the light client sent, not yet confirmed
};

class SwapEngine
{
public:
    explicit SwapEngine(SwapHost* pHost, const SwapConfig& cfg = SwapConfig()) : host(pHost), config(cfg) {}

    std::string ToJson();
    void        FromJson(const std::string& s);
    void        Clear();
    void        List(std::vector<SwapView>& out);

    // Start taking an offer of `peer`'s (the taker's side).
    bool Take(const std::string& peer, const std::string& offerId, const SwapOffer& offer,
              std::string& idOut, std::string& errOut);
    bool Approve(const std::string& id, std::string& errOut);
    bool Cancel(const std::string& id, std::string& errOut);
    bool SetBitcoinDestination(const std::string& id, const std::string& address);

    // One round: read the other side's steps, move every swap one step.
    void Round();

private:
    SwapHost*   host;
    SwapConfig  config;
    CCriticalSection cs;
    std::map<std::string, ChatSwap> swaps;
    std::set<std::string> stepsSeen;
    std::string strStoreError;     // the last save that failed; "" when the store is on the disk

    int  MinConfirmations(const std::string& coin) const;
    bool Wallet(const char* method, const nlohmann::json& params, nlohmann::json& r, std::string& err);
    bool OnChain(const std::string& coin, const char* btf, const char* step, const nlohmann::json& params,
                 nlohmann::json& r, std::string& err);
    bool NewAddress(const std::string& coin, std::string& out, std::string& err);
    bool TheirTimeLeft(const ChatSwap& s, int64_t& nLeft, std::string& err);
    bool SendStep(const ChatSwap& s, SwapStep& st, std::string& err);
    void SendCancel(const ChatSwap& s, const std::string& why);
    int  CheckTheirs(const ChatSwap& s, int64_t nMinLeft, const std::string& expectHash,
                     std::string& hashOut, std::string& why);
    bool MyTimeLeft(const ChatSwap& s, int64_t& nLeft, std::string& err);
    bool FindSecret(const std::string& coin, const std::string& contract, const std::string& ref,
                    bool& fSpent, std::string& secretOut, bool& fRefunded, std::string& err,
                    bool* pfConfirmed = NULL, int* pnSpendConf = NULL, std::string* pSpendTxid = NULL);
    void RefundSeen(ChatSwap& s, bool fConfirmed, int nConf);
    bool SaveLockAttempt(ChatSwap& s);
    int  LookupLock(ChatSwap& s, std::string& err);
    bool AdoptLock(ChatSwap& s, const nlohmann::json& r, std::string& err);
    bool StoreSaved(ChatSwap& s);
    void TryRefund(ChatSwap& s);
    nlohmann::json LockParams(const ChatSwap& s, bool fInitiator) const;
    void Tick(ChatSwap& s);
    void OnStep(const std::string& peer, const SwapStep& st, int64_t nNow, const SwapOffer* pMyOffer);
    void ReadSteps();
    bool Prune(int64_t nNow, const std::set<std::string>& stepIdsPresent, bool fPruneSteps);
};

// ---- the chat app's engine ------------------------------------------------------

// The store's fifth line. Called by btfchatnode holding its lock.
std::string SwapsToJson();
void        SwapsFromJson(const std::string& s);
void        SwapsClear();

void ChatSwapList(std::vector<SwapView>& out);

// Post an offer to a community we are in.
bool ChatSwapPostOffer(const std::string& communityId, const SwapOffer& offer, std::string& errOut);

// Take somebody's offer: the community it is in and the offer's frame id.
bool ChatSwapTake(const std::string& communityId, const std::string& offerFrameId, std::string& errOut);

// The person's yes: the maker accepts a take, or the taker confirms the lock.
bool ChatSwapApprove(const std::string& id, std::string& errOut);

// Only while nothing of ours is locked.
bool ChatSwapCancel(const std::string& id, std::string& errOut);
bool ChatSwapBitcoinDestination(const std::string& id, const std::string& address);

// Look again now, instead of at the next round.
void ChatSwapWake();

void ThreadChatSwaps(void* parg);

} // namespace btfchat

#endif
