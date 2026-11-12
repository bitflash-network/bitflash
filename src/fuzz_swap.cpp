// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for atomic-swap negotiation: everything the other side of a
// swap can send, through the real parsers and the real engine.
//
//   - offers and steps as text (ParseSwapOffer, ParseSwapStep), with a round
//     trip through their formatters;
//   - contract scripts (swap::ParseContract against swap::BuildContract) and
//     the secret search in a spend (swap::ExtractSecret);
//   - foreign transactions and blocks (btcswap::ParseTx, ParseBlockTxs);
//   - the swap engine (btfchat::SwapEngine) driven through a whole swap as
//     maker or taker: the counterparty's steps come from the input, and so do
//     the facts its contract shows on the chain (what the wallet's audit, the
//     secret search and the lock calls answer). The answers have the types the
//     real wallet gives; their values are the input's.
//
// The invariants on the engine are the ones that keep coins safe:
//   - a taker locks (participate) only right after an audit of the maker's
//     contract that pays an address this wallet gave, under the hash it locks
//     to, the agreed amount, unspent, with the confirmations asked for and at
//     least nTakerMinLeft before the maker can refund -- and nTakerMinLeft is
//     longer than the taker's own lock plus a margin (the time-lock order);
//   - a maker shows its secret (redeem) only right after an audit of the
//     taker's contract with the same properties, under the maker's own hash,
//     with at least nMakerMinLeft left;
//   - the engine's state reads back from its JSON to the same JSON.
//
// Input: byte 0 picks the mode, the rest is the mode's body.
//   0  an offer as text          1  a step as text
//   2  a script as a contract, and as a spend to search for a secret
//   3  a foreign transaction, and a block
//   4..7  the engine: a header (role, coins, amounts, timeouts), then rounds,
//      each an optional step from the counterparty, an optional approval or
//      cancel by the person, and Round(); the wallet's answers are read from
//      the same input as they are asked for.
//
// The host stands in for the chat app: its Changed() saves (and says it did),
// as SwapHost asks.

#include "headers_core.h"
#include "chatswap.h"
#include "btfchatswap.h"
#include "swap.h"
#include "btcswap.h"

#include <openssl/sha.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <string>
#include <vector>

static void FuzzSwapInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzSwapInit
#include "fuzz_datadir.h"

map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using namespace btfchat;
using json = nlohmann::json;

struct Reader
{
    const uint8_t* p;
    size_t n;
    Reader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    uint8_t U8() { if (!n) return 0; n--; return *p++; }
    uint16_t U16() { uint16_t a = U8(); return (uint16_t)(a | (U8() << 8)); }
    uint32_t U32() { uint32_t a = U16(); return a | ((uint32_t)U16() << 16); }
    std::string Str(size_t k) { if (k > n) k = n; std::string s((const char*)p, k); p += k; n -= k; return s; }
};

static std::string HexOf(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}

// ---- parsers ----------------------------------------------------------------

static bool SameOffer(const SwapOffer& a, const SwapOffer& b)
{
    return a.give == b.give && a.want == b.want && a.giveAmount == b.giveAmount &&
           a.wantAmount == b.wantAmount && a.note == b.note;
}

static void ModeOffer(Reader& rd)
{
    std::string text = rd.Str(rd.n), err;
    SwapOffer o;
    if (!ParseSwapOffer(text, o, err))
        return;
    SwapOffer back;
    if (!ParseSwapOffer(FormatSwapOffer(o), back, err) || !SameOffer(o, back))
        abort();   // an offer that parses does not survive its own formatter
    if (o.giveAmount <= 0 || o.wantAmount <= 0 || o.giveAmount > MAX_SWAP_AMOUNT || o.wantAmount > MAX_SWAP_AMOUNT ||
        o.give == o.want || (o.give != "BTF" && o.want != "BTF") || !SwapCoinOk(o.give) || !SwapCoinOk(o.want))
        abort();   // an offer the rules refuse was taken
}

static void ModeStep(Reader& rd)
{
    std::string text = rd.Str(rd.n), err;
    SwapStep s;
    if (!ParseSwapStep(text, s, err))
        return;
    SwapStep b;
    if (!ParseSwapStep(FormatSwapStep(s), b, err))
        abort();
    if (b.swap != s.swap || b.step != s.step || b.offer != s.offer || !SameOffer(b.terms, s.terms) ||
        b.to != s.to || b.chain != s.chain || b.contract != s.contract || b.txid != s.txid ||
        b.vout != s.vout || b.why != s.why)
        abort();   // a step that parses does not survive its own formatter
    if (s.swap.size() != 32)
        abort();
    if ((s.step == "lock1" || s.step == "lock2") && (!SwapCoinOk(s.chain) || s.txid.size() != 64))
        abort();
}

static void ModeScript(Reader& rd)
{
    std::string raw = rd.Str(rd.n);
    CScript script((const unsigned char*)raw.data(), (const unsigned char*)raw.data() + raw.size());
    swap::Contract c;
    if (swap::ParseContract(script, c))
    {
        if (swap::BuildContract(c) != script)
            abort();   // not the one canonical encoding
        if (c.secretHash.size() != 32 || c.recipientPkh.size() != 20 || c.refundPkh.size() != 20 ||
            c.nLockTime <= 0 || c.nLockTime > 0xffffffffLL)
            abort();
    }
    // As a spend: whatever secret it finds hashes to the hash asked for.
    std::vector<unsigned char> hash(32);
    if (raw.size() >= 32)
        memcpy(&hash[0], raw.data(), 32);
    for (int k = 0; k < 2; k++)
    {
        std::vector<unsigned char> secret;
        if (swap::ExtractSecret(script, hash, secret))
        {
            unsigned char h[32];
            SHA256(&secret[0], secret.size(), h);
            if (secret.size() != swap::SECRET_BYTES || memcmp(h, &hash[0], 32) != 0)
                abort();
        }
        // The second time, the hash of the first 32-byte push, so a secret
        // is found.
        CScript::const_iterator pc = script.begin();
        opcodetype op;
        std::vector<unsigned char> v;
        while (pc < script.end() && script.GetOp(pc, op, v))
            if (v.size() == 32)
            {
                SHA256(&v[0], 32, &hash[0]);
                break;
            }
    }
}

static void ModeTx(Reader& rd)
{
    std::string raw = rd.Str(rd.n);
    std::vector<unsigned char> b(raw.begin(), raw.end());
    CTransaction tx;
    if (btcswap::ParseTx(b, tx))
    {
        bool fWitness = b.size() > 5 && b[4] == 0 && b[5] == 1;
        if (!fWitness)
        {
            // Without witness data a foreign transaction is laid out as ours:
            // it reads back to the bytes it came from, or the txid this node
            // computes is not the one the other chain uses.
            CDataStream ss(SER_NETWORK);
            ss << tx;
            if (std::vector<unsigned char>(ss.begin(), ss.end()) != b)
                abort();
        }
    }
    std::vector<CTransaction> txs;
    btcswap::ParseBlockTxs(b, txs, false, 80);
    btcswap::ParseBlockTxs(b, txs, true, 80);
}

// ---- the engine ---------------------------------------------------------------

static const char* const kCoins[] = { "BTC", "LTC", "DOGE", "BCH", "XEC", "DGB", "RVN" };
static const int64_t PARTICIPANT_LOCK_SECS = 24 * 3600;   // the wallet's default lock for a taker
static const int64_t ORDER_MARGIN_SECS = 6 * 3600;        // what the time-lock order must leave at least

static std::string AddressFor(const std::string& coin, unsigned int n)
{
    if (coin == "BCH" || coin == "XEC")
    {
        std::string s = coin == "BCH" ? "bitcoincash:q" : "ecash:q";
        static const char* cs = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for (int i = 0; i < 41; i++)
            s += cs[(n * 7 + i * 13) % 32];
        return s;
    }
    char first = coin == "BTF" ? 'B' : coin == "BTC" ? '1' : coin == "LTC" ? 'L' : coin == "DOGE" ? 'D' :
                 coin == "DGB" ? 'D' : 'R';
    static const char* b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string s(1, first);
    for (int i = 0; i < 33; i++)
        s += b58[(n * 11 + i * 17 + 5) % 58];
    return s;
}

static std::string CoinOf(const std::string& method)
{
    if (method.compare(0, 3, "btc") == 0) return "BTC";
    if (method.compare(0, 4, "coin") == 0) return "";      // the chain is the first parameter
    return "BTF";
}

static std::string Suffix(const std::string& method)
{
    if (method.compare(0, 4, "swap") == 0) return method.substr(4);
    if (method.compare(0, 3, "btc") == 0) return method.substr(3);
    if (method.compare(0, 4, "coin") == 0) return method.substr(4);
    if (method == "getnewaddress") return "newaddress";
    return method;
}

struct Audit
{
    bool fValid = false;
    bool fRecipientIsMine = false;
    std::string recipient, secretHash;
    int confirmations = 0;
    bool fUnspent = false;
    int64_t amountSats = 0;
    int64_t left = 0;          // seconds before the other side may refund
};

class FuzzHost : public SwapHost
{
public:
    Reader* rd = NULL;
    SwapConfig cfg;
    std::string me = "me.btf", peer = "peer.btf";
    std::vector<LogEntry> conv;
    SwapOffer myOffer;
    std::string myOfferId;
    bool fMaker = false;
    std::string give, want;          // ours / theirs in the swap being run
    int64_t giveAmount = 0, wantAmount = 0;
    std::set<std::string> issued;    // addresses this wallet gave out
    std::set<std::string> mySecrets; // secrets this wallet made (hex)
    Audit last;                      // the latest audit answered, of any contract
    std::string lastAuditContract;
    std::set<std::string> redeemCleared;   // contracts a first maker redeem was checked for
    unsigned int nAddr = 0;
    int nNextId = 0;

    std::string MyAddress() { return me; }
    bool PeerAccepted(const std::string& p) { return p == peer; }
    bool Invite(const std::string&, const std::string&, std::string&) { return true; }
    bool SendStep(const std::string&, const std::string& stepText, std::string& err)
    {
        // What the engine says must itself parse.
        SwapStep st;
        if (!ParseSwapStep(stepText, st, err))
            abort();
        return (rd->U8() & 7) != 0;
    }
    void Contacts(std::vector<std::string>& out) { out.assign(1, peer); }
    void Conversation(const std::string& p, std::vector<LogEntry>& out) { if (p == peer) out = conv; else out.clear(); }
    bool FindMyOffer(const std::string& id, SwapOffer& out) { if (id != myOfferId) return false; out = myOffer; return true; }
    bool Changed() { return true; }

    void AddStep(const std::string& text)
    {
        LogEntry e;
        e.from = peer;
        e.kind = MSG_SWAP;
        e.outgoing = false;
        e.id = strprintf("%032x", ++nNextId);
        e.text = text;
        conv.push_back(e);
    }

    // The checks a lock or a redeem relies on, against the audit just given.
    void CheckAuditFor(const std::string& hash, int64_t nMinLeft, int64_t nAmount) const
    {
        if (!last.fValid)
            abort();   // locked or redeemed with no audit before it
        if (!last.fRecipientIsMine || !issued.count(last.recipient))
            abort();   // their contract does not pay us
        if (last.secretHash != hash)
            abort();   // under another secret
        if (!last.fUnspent || last.amountSats != nAmount)
            abort();   // spent, or not the amount agreed
        if (last.confirmations < cfg.nMinConfirmations)
            abort();
        if (last.left < nMinLeft)
            abort();   // too little time left on their contract
    }

    bool Wallet(const std::string& method, const json& params, json& r, std::string& err)
    {
        std::string coin = CoinOf(method);
        json p = params;
        if (coin.empty())
        {
            if (!p.is_array() || p.empty() || !p[0].is_string())
                abort();
            std::string c = p[0].get<std::string>();
            for (size_t i = 0; i < c.size(); i++) c[i] = (char)toupper((unsigned char)c[i]);
            coin = c;
            p.erase(p.begin());
        }
        std::string what = Suffix(method);
        uint8_t ctl = rd->U8();
        if ((ctl & 0x0f) == 0)
        {
            err = "the wallet did not answer";
            return false;
        }
        if (what == "newaddress")
        {
            std::string a = AddressFor(coin, ++nAddr);
            issued.insert(a);
            r = a;
            return true;
        }
        if (what == "info")
        {
            r = json::object();
            r["backend"] = (ctl & 0x10) ? "light" : "core";
            return true;
        }
        if (what == "validatedestination")
        {
            r = json::object();
            r["isvalid"] = true;
            return true;
        }
        if (what == "auditcontract")
        {
            // The facts their contract (or ours) shows, as the wallet reports them.
            Audit a;
            a.fValid = true;
            a.fRecipientIsMine = (ctl & 0x10) != 0;
            uint8_t sel = rd->U8();
            a.recipient = (sel & 1) && !issued.empty() ? *issued.rbegin() : AddressFor(coin, 1000 + sel);
            uint8_t hs = rd->U8();
            if ((hs & 3) == 0 && !mySecrets.empty())
            {
                std::vector<unsigned char> s = ParseHex(*mySecrets.begin());
                unsigned char h[32];
                SHA256(&s[0], s.size(), h);
                a.secretHash = HexOf(h, 32);
            }
            else if ((hs & 3) == 1)
                a.secretHash = std::string(64, 'c');
            else
                a.secretHash = HexOf((const unsigned char*)rd->Str(32).c_str(), std::min<size_t>(32, 32));
            a.confirmations = (int)(rd->U8() % 40) - 2;
            a.fUnspent = (ctl & 0x20) != 0;
            int64_t nExact = p.size() >= 1 && p[0].is_string() && p[0].get<std::string>() == lastAuditContract ? wantAmount : wantAmount;
            uint8_t am = rd->U8();
            a.amountSats = (am & 3) == 0 ? nExact + (int8_t)rd->U8() : (am & 3) == 1 ? giveAmount : nExact;
            int64_t hours = (int64_t)(int8_t)rd->U8();
            a.left = hours * 3600 + (int64_t)(rd->U8() % 60) * 60;
            last = a;
            lastAuditContract = p.size() >= 1 && p[0].is_string() ? p[0].get<std::string>() : std::string();

            r = json::object();
            r["recipientIsMine"] = a.fRecipientIsMine;
            r["recipient"] = a.recipient;
            r["secretHash"] = a.secretHash;
            r["confirmations"] = a.confirmations;
            r["unspent"] = a.fUnspent;
            r["amount"] = (double)a.amountSats / (double)CoinUnit(coin);
            if (coin == "BTF")
            {
                // The engine counts Bitflash blocks at 120 s; the answer is in
                // blocks, rounded down, so the facts are judged as it judges them.
                r["blocksUntilRefund"] = a.left / 120;
                last.left = (a.left / 120) * 120;
            }
            else
                r["secondsUntilRefund"] = a.left;
            r["contractTxid"] = std::string(64, (ctl & 0x40) ? 'a' : '0');
            r["vout"] = (int)(rd->U8() % 3);
            r["lockTime"] = (int64_t)GetTime() + a.left;
            return true;
        }
        if (what == "initiate" || what == "participate")
        {
            if (what == "participate")
            {
                // The taker locks: the maker's contract must check out, and the
                // order of the locks must hold.
                if (fMaker)
                    abort();   // a maker never participates
                if (p.size() < 3 || !p[2].is_string())
                    abort();
                CheckAuditFor(p[2].get<std::string>(), cfg.nTakerMinLeft, wantAmount);
                if (cfg.nTakerMinLeft < PARTICIPANT_LOCK_SECS + ORDER_MARGIN_SECS)
                    abort();   // the configuration itself breaks the order
            }
            else if (!fMaker)
                abort();       // a taker never initiates
            r = json::object();
            r["contract"] = std::string(194, 'f');
            r["contractTxid"] = std::string(64, 'b');
            r["vout"] = 0;
            if (what == "initiate")
            {
                unsigned char sec[32], h[32];
                for (int i = 0; i < 32; i++) sec[i] = (unsigned char)(i + mySecrets.size() * 3 + 1);
                SHA256(sec, 32, h);
                r["secret"] = HexOf(sec, 32);
                r["secretHash"] = HexOf(h, 32);
                mySecrets.insert(HexOf(sec, 32));
            }
            if (ctl & 0x10)
            {
                r["awaitingPayment"] = true;
                r["contractAddress"] = AddressFor(coin, 77);
            }
            last = Audit();   // an audit before a lock is good for that lock only
            return true;
        }
        if (what == "redeem")
        {
            if (p.size() < 3 || !p[0].is_string() || !p[2].is_string())
                abort();
            std::string contract = p[0].get<std::string>();
            if (mySecrets.count(p[2].get<std::string>()))
            {
                // A maker shows its own secret: only right after the taker's
                // contract checked out, or again for one that did.
                if (!fMaker)
                    abort();
                if (!redeemCleared.count(contract))
                {
                    std::vector<unsigned char> s = ParseHex(p[2].get<std::string>());
                    unsigned char h[32];
                    SHA256(&s[0], s.size(), h);
                    CheckAuditFor(HexOf(h, 32), cfg.nMakerMinLeft, wantAmount);
                    redeemCleared.insert(contract);
                }
            }
            last = Audit();
            r = json::object();
            r["txid"] = std::string(64, 'd');
            r["awaitingConfirmation"] = (ctl & 0x10) != 0;
            if (ctl & 0x20)
                r["feeRatePerKvB"] = 0.0001;
            return true;
        }
        if (what == "findsecret")
        {
            r = json::object();
            r["spent"] = (ctl & 0x10) != 0;
            r["refunded"] = (ctl & 0x20) != 0;
            if (ctl & 0x40)
            {
                unsigned char sec[32];
                for (int i = 0; i < 32; i++) sec[i] = rd->U8();
                r["secret"] = HexOf(sec, 32);
            }
            return true;
        }
        if (what == "refund")
        {
            r = json::object();
            r["txid"] = std::string(64, 'e');
            r["awaitingConfirmation"] = (ctl & 0x10) != 0;
            return true;
        }
        err = "unknown method " + method;
        return false;
    }
};

static std::string StepText(Reader& rd, FuzzHost& h, const std::string& swapId)
{
    uint8_t k = rd.U8();
    if ((k & 7) == 0)
        return rd.Str(rd.U16() % 1024);   // anything at all
    json j;
    j["s"] = (k & 0x80) ? HexOf((const unsigned char*)rd.Str(16).c_str(), 0) + std::string(32, 'a') : swapId;
    if (j["s"].get<std::string>().size() != 32)
        j["s"] = swapId;
    switch (k & 7)
    {
    case 1:
    {
        j["step"] = "take";
        j["offer"] = h.myOfferId;
        json t;
        t["give"] = h.myOffer.give;
        t["ga"] = (k & 0x40) ? h.myOffer.giveAmount + 1 : h.myOffer.giveAmount;
        t["want"] = h.myOffer.want;
        t["wa"] = h.myOffer.wantAmount;
        j["terms"] = t;
        j["to"] = AddressFor(h.myOffer.give, 500 + rd.U8());
        break;
    }
    case 2:
    case 3:
    {
        j["step"] = (k & 7) == 2 ? "lock1" : "lock2";
        std::string chain = (k & 0x40) ? h.give : h.want;
        j["chain"] = chain;
        j["c"] = std::string(2 * (1 + rd.U8() % 100), '7');
        j["tx"] = std::string(64, '9');
        if (chain != "BTF")
            j["n"] = (int)(rd.U8() % 4);
        j["to"] = AddressFor(h.give, 600 + rd.U8());
        break;
    }
    case 4:
        j["step"] = "redeemed";
        j["tx"] = std::string(64, '8');
        break;
    default:
        j["step"] = "cancel";
        if (k & 0x20)
            j["why"] = rd.Str(rd.U8());
        break;
    }
    try { return j.dump(); }
    catch (...) { return std::string(); }
}

static void ModeEngine(Reader& rd)
{
    FuzzHost h;
    h.rd = &rd;
    uint8_t hdr = rd.U8();
    h.fMaker = hdr & 1;
    std::string other = kCoins[rd.U8() % (sizeof(kCoins) / sizeof(kCoins[0]))];
    bool fBtfGive = hdr & 2;
    h.give = fBtfGive ? "BTF" : other;
    h.want = fBtfGive ? other : "BTF";
    h.giveAmount = 10000000 + (int64_t)rd.U32();
    h.wantAmount = 10000000 + (int64_t)rd.U32();
    h.cfg.nMinConfirmations = 1 + rd.U8() % 4;
    h.cfg.nAnswerWithin = (hdr & 4) ? 0 : 24 * 3600;
    h.cfg.nGiveUpWaiting = (hdr & 8) ? 0 : 12 * 3600;
    h.cfg.nRedeemBumpAfter = (hdr & 16) ? 0 : 3600;
    h.myOfferId = std::string(32, 'a');
    // As maker, our offer gives what we give.
    h.myOffer.give = h.give; h.myOffer.giveAmount = h.giveAmount;
    h.myOffer.want = h.want; h.myOffer.wantAmount = h.wantAmount;

    SwapEngine engine(&h, h.cfg);
    std::string swapId, err;
    if (!h.fMaker)
    {
        // We take their offer: they give what we want.
        SwapOffer theirs;
        theirs.give = h.want; theirs.giveAmount = h.wantAmount;
        theirs.want = h.give; theirs.wantAmount = h.giveAmount;
        if (!engine.Take(h.peer, std::string(32, 'b'), theirs, swapId, err))
            abort();
    }
    else
        swapId = std::string(32, '5');

    for (int round = 0; round < 24 && rd.n; round++)
    {
        uint8_t a = rd.U8();
        if (a & 1)
        {
            std::string t = StepText(rd, h, swapId);
            if (!t.empty())
                h.AddStep(t);
        }
        if (a & 2)
            engine.Approve(swapId, err);
        if ((a & 0x0c) == 0x0c)
            engine.Cancel(swapId, err);
        if (a & 0x10)
            engine.SetBitcoinDestination(swapId, AddressFor(h.want, 900));
        try
        {
            engine.Round();
        }
        catch (const std::exception&)
        {
            // ThreadChatSwaps catches what a round throws; nothing here may
            // throw on answers of the right types, so note it as a finding.
            abort();
        }
    }

    // The state reads back from its JSON to the same JSON.
    std::string js = engine.ToJson();
    SwapEngine again(&h, h.cfg);
    again.FromJson(js);
    if (again.ToJson() != js)
        abort();
}

static void FuzzSwapInit()
{
    SelectChainParams(false);
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (!pszSeeds || !*pszSeeds)
        return;
    std::string dir = pszSeeds;
    auto put = [&](const std::string& name, const std::string& data) {
        FILE* f = fopen((dir + "/" + name).c_str(), "wb");
        if (!f) { perror(name.c_str()); exit(1); }
        fwrite(data.data(), 1, data.size(), f);
        fclose(f);
    };
    put("offer", std::string(1, '\0') + "{\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000,\"note\":\"hi\"}");
    put("offer-float", std::string(1, '\0') + "{\"give\":\"BTF\",\"ga\":1e300,\"want\":\"LTC\",\"wa\":2.5}");
    put("step-take", std::string("\x01") + "{\"s\":\"00112233445566778899aabbccddeeff\",\"step\":\"take\",\"offer\":\"00112233445566778899aabbccddeeff\",\"terms\":{\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":200000},\"to\":\"B6yBpt1nTq3VuV1mNQXrWpYAuB4VJkH9mV\"}");
    put("step-lock1", std::string("\x01") + "{\"s\":\"00112233445566778899aabbccddeeff\",\"step\":\"lock1\",\"chain\":\"LTC\",\"c\":\"6382\",\"tx\":\"" + std::string(64, 'a') + "\",\"n\":1,\"to\":\"LKxQ6Kb5bUBk8mZbqm1g7pYJfxvbvnYgUm\"}");
    put("step-n-big", std::string("\x01") + "{\"s\":\"00112233445566778899aabbccddeeff\",\"step\":\"lock2\",\"chain\":\"LTC\",\"c\":\"63\",\"tx\":\"" + std::string(64, 'a') + "\",\"n\":4294967297}");
    // A contract as BuildContract makes it.
    {
        swap::Contract c;
        c.secretHash.assign(32, 0x11);
        c.recipientPkh.assign(20, 0x22);
        c.refundPkh.assign(20, 0x33);
        c.nLockTime = 1790000000;
        CScript s = swap::BuildContract(c);
        put("contract", std::string("\x02") + std::string((const char*)&s[0], s.size()));
        std::vector<unsigned char> secret(32, 0x44), sig(71, 0x30), pub(33, 0x02);
        CScript spend = swap::RedeemScriptSig(sig, pub, secret, s);
        put("spend", std::string("\x02") + std::string((const char*)&spend[0], spend.size()));
    }
    // A one-input, one-output transaction, without and with witness.
    {
        CTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(uint256(5), 1);
        tx.vout.resize(1);
        tx.vout[0].nValue = 12345;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        CDataStream ss(SER_NETWORK);
        ss << tx;
        std::string legacy(ss.begin(), ss.end());
        put("tx", std::string("\x03") + legacy);
        std::string wit = legacy.substr(0, 4) + std::string("\x00\x01", 2) + legacy.substr(4, legacy.size() - 8) +
                          std::string("\x01\x02\xab\xcd", 4) + legacy.substr(legacy.size() - 4);
        put("tx-witness", std::string("\x03") + wit);
    }
    // Engine runs: taker and maker, each coin side, with rounds that answer
    // every wallet call.
    for (int role = 0; role < 2; role++)
        for (int side = 0; side < 2; side++)
        {
            std::string s;
            s += (char)4;
            s += (char)(role | (side << 1));
            s += (char)1;                                // LTC
            s += std::string("\x00\x00\x00\x00", 4);     // give amount extra
            s += std::string("\x00\x00\x00\x00", 4);     // want amount extra
            s += (char)1;                                // confirmations
            for (int r = 0; r < 24; r++)
            {
                s += (char)(r % 3 == 0 ? 3 : 2);         // a step on some rounds, approve always
                if (r % 3 == 0)
                    s += (char)(role ? (r == 0 ? 1 : 3) : 2);
                s += std::string(24, (char)(0x31 + r));  // wallet answers
            }
            put("engine-" + std::to_string(role) + std::to_string(side), s);
        }
    exit(0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 100000)
        return 0;
    Reader rd(data + 1, size - 1);
    switch (data[0] % 8)
    {
    case 0: ModeOffer(rd); break;
    case 1: ModeStep(rd); break;
    case 2: ModeScript(rd); break;
    case 3: ModeTx(rd); break;
    default: ModeEngine(rd); break;
    }
    return 0;
}
