// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See chatswap.h. Pure: no node, no wallet, no socket.

#include <nlohmann/json.hpp>

#include "chatswap.h"

#include <cstdio>
#include <cstring>

using json = nlohmann::json;

namespace btfchat
{

bool SwapCoinOk(const std::string& coin)
{
    return coin == "BTF" || coin == "BTC";
}

static bool IsHexString(const std::string& s)
{
    if (s.empty() || s.size() % 2)
        return false;
    for (size_t i = 0; i < s.size(); i++)
        if (!strchr("0123456789abcdef", s[i]))
            return false;
    return true;
}

bool SwapAddressShapeOk(const std::string& coin, const std::string& addr)
{
    static const char* b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (addr.size() < 25 || addr.size() > 35)
        return false;
    for (size_t i = 0; i < addr.size(); i++)
        if (!strchr(b58, addr[i]))
            return false;
    if (coin == "BTF")
        return addr[0] == 'B';
    if (coin == "BTC")
        return addr[0] == '1' || addr[0] == 'm' || addr[0] == 'n';
    return false;
}

std::string FormatSwapAmount(int64_t n)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld.%08lld", (long long)(n / 100000000), (long long)(n % 100000000));
    std::string s = buf;
    while (s.size() > 1 && s[s.size() - 1] == '0')
        s.erase(s.size() - 1);
    if (s[s.size() - 1] == '.')
        s.erase(s.size() - 1);
    return s;
}

static bool AmountOk(const json& j, const char* key, int64_t& out)
{
    if (!j.contains(key) || !j[key].is_number_integer())
        return false;
    out = j[key].get<int64_t>();
    return out > 0 && out <= MAX_SWAP_AMOUNT;
}

static bool OfferFromJson(const json& j, SwapOffer& o, std::string& errOut)
{
    if (!j.is_object())                    { errOut = "an offer is an object"; return false; }
    o.give = j.value("give", std::string());
    o.want = j.value("want", std::string());
    if (!SwapCoinOk(o.give) || !SwapCoinOk(o.want) || o.give == o.want)
    {
        errOut = "an offer trades BTF for BTC or BTC for BTF";
        return false;
    }
    if (!AmountOk(j, "ga", o.giveAmount) || !AmountOk(j, "wa", o.wantAmount))
    {
        errOut = "an offer needs two amounts, more than zero and at most 21 million";
        return false;
    }
    o.note = j.contains("note") && j["note"].is_string() ? j["note"].get<std::string>() : std::string();
    if (o.note.size() > MAX_SWAP_NOTE)     { errOut = "the offer's note is too long"; return false; }
    return true;
}

static json OfferToJson(const SwapOffer& o)
{
    json j;
    j["give"] = o.give;
    j["ga"] = o.giveAmount;
    j["want"] = o.want;
    j["wa"] = o.wantAmount;
    if (!o.note.empty())
        j["note"] = o.note;
    return j;
}

bool ParseSwapOffer(const std::string& text, SwapOffer& out, std::string& errOut)
{
    out = SwapOffer();
    json j;
    try { j = json::parse(text); }
    catch (...) { errOut = "the offer is not JSON"; return false; }
    return OfferFromJson(j, out, errOut);
}

std::string FormatSwapOffer(const SwapOffer& o)
{
    return OfferToJson(o).dump();
}

std::string DescribeSwapOffer(const SwapOffer& o)
{
    return FormatSwapAmount(o.giveAmount) + " " + o.give + " for " + FormatSwapAmount(o.wantAmount) + " " + o.want;
}

bool ParseSwapStep(const std::string& text, SwapStep& s, std::string& errOut)
{
    s = SwapStep();
    json j;
    try { j = json::parse(text); }
    catch (...) { errOut = "the swap step is not JSON"; return false; }
    if (!j.is_object())                    { errOut = "a swap step is an object"; return false; }
    s.swap = j.value("s", std::string());
    s.step = j.value("step", std::string());
    if (s.swap.size() != 32 || !IsHexString(s.swap)) { errOut = "the swap id is 32 hex characters"; return false; }

    if (s.step == "take")
    {
        s.offer = j.value("offer", std::string());
        if (s.offer.size() != 32 || !IsHexString(s.offer)) { errOut = "a take names the offer's frame id"; return false; }
        if (!j.contains("terms") || !OfferFromJson(j["terms"], s.terms, errOut))
            return false;
        s.to = j.value("to", std::string());
        // The taker is paid in the coin the maker gives.
        if (!SwapAddressShapeOk(s.terms.give, s.to)) { errOut = "a take needs an address for the coin it receives"; return false; }
        return true;
    }
    if (s.step == "lock1" || s.step == "lock2")
    {
        s.chain = j.value("chain", std::string());
        s.contract = j.value("c", std::string());
        s.txid = j.value("tx", std::string());
        if (!SwapCoinOk(s.chain))           { errOut = "a lock names its chain"; return false; }
        // Decred's contract is 97 bytes; a little room, no more.
        if (!IsHexString(s.contract) || s.contract.size() > 300) { errOut = "the contract is hex, at most 150 bytes"; return false; }
        if (s.txid.size() != 64 || !IsHexString(s.txid)) { errOut = "the contract's txid is 64 hex characters"; return false; }
        if (s.chain == "BTC")
        {
            if (!j.contains("n") || !j["n"].is_number_integer() || j["n"].get<int>() < 0 || j["n"].get<int>() > 100000)
            {
                errOut = "a Bitcoin contract names its output";
                return false;
            }
            s.vout = j["n"].get<int>();
        }
        if (s.step == "lock1")
        {
            s.to = j.value("to", std::string());
            // The maker wants the other coin.
            std::string other = s.chain == "BTF" ? "BTC" : "BTF";
            if (!SwapAddressShapeOk(other, s.to)) { errOut = "lock1 needs an address for the coin it receives"; return false; }
        }
        return true;
    }
    if (s.step == "redeemed")
    {
        s.txid = j.value("tx", std::string());
        if (s.txid.size() != 64 || !IsHexString(s.txid)) { errOut = "the redeem's txid is 64 hex characters"; return false; }
        return true;
    }
    if (s.step == "cancel")
    {
        s.why = j.contains("why") && j["why"].is_string() ? j["why"].get<std::string>() : std::string();
        if (s.why.size() > MAX_SWAP_NOTE)   { errOut = "the reason is too long"; return false; }
        return true;
    }
    errOut = "unknown swap step";
    return false;
}

std::string FormatSwapStep(const SwapStep& s)
{
    json j;
    j["s"] = s.swap;
    j["step"] = s.step;
    if (s.step == "take")
    {
        j["offer"] = s.offer;
        j["terms"] = OfferToJson(s.terms);
        j["to"] = s.to;
    }
    else if (s.step == "lock1" || s.step == "lock2")
    {
        j["chain"] = s.chain;
        j["c"] = s.contract;
        j["tx"] = s.txid;
        if (s.chain == "BTC")
            j["n"] = s.vout;
        if (s.step == "lock1")
            j["to"] = s.to;
    }
    else if (s.step == "redeemed")
        j["tx"] = s.txid;
    else if (s.step == "cancel" && !s.why.empty())
        j["why"] = s.why;
    return j.dump();
}

} // namespace btfchat
