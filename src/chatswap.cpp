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
    return coin == "BTF" || coin == "BTC" || coin == "LTC" || coin == "DOGE" || coin == "BCH" || coin == "XEC" || coin == "DGB" || coin == "RVN";
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
    if (coin == "BCH" || coin == "XEC")
    {
        // A key address in cashaddr, with its prefix: what a contract holds.
        size_t nColon = addr.find(':');
        if (nColon == std::string::npos || nColon + 34 > addr.size() || addr.size() > 60 || addr[nColon + 1] != 'q')
            return false;
        std::string prefix = addr.substr(0, nColon);
        if (coin == "BCH" ? prefix != "bitcoincash" && prefix != "bchtest" && prefix != "bchreg"
                          : prefix != "ecash" && prefix != "ectest" && prefix != "ecregtest")
            return false;
        for (size_t i = nColon + 1; i < addr.size(); i++)
            if (!strchr("qpzry9x8gf2tvdw0s3jn54khce6mua7l", addr[i]))
                return false;
        return true;
    }
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
    if (coin == "LTC")
        return addr[0] == 'L' || addr[0] == 'm' || addr[0] == 'n';
    if (coin == "DOGE")
        return addr[0] == 'D' || addr[0] == 'm' || addr[0] == 'n';
    if (coin == "DGB")
        return addr[0] == 'D' || addr[0] == 's' || addr[0] == 't';
    if (coin == "RVN")
        return addr[0] == 'R' || addr[0] == 'm' || addr[0] == 'n';
    return false;
}

std::string FormatSwapAmount(const std::string& coin, int64_t n)
{
    std::string s = CoinAmountText(coin, n);
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

// A string field: absent reads as "", anything but a string is refused. A
// stranger writes these, and nlohmann's value() throws on a wrong type.
static bool StrField(const json& j, const char* key, std::string& out)
{
    out.clear();
    if (!j.contains(key))
        return true;
    if (!j[key].is_string())
        return false;
    out = j[key].get<std::string>();
    return true;
}

int64_t SwapMinAmount(const std::string& coin)
{
    // Bitflash's own spend of a contract pays at least 0.01 BTF.
    if (coin == "BTF")  return 10000000;     // 0.1 BTF
    if (coin == "BTC")  return 20000;        // 0.0002 BTC
    if (coin == "LTC")  return 100000;       // 0.001 LTC
    if (coin == "BCH")  return 10000;        // 0.0001 BCH
    if (coin == "XEC")  return 10000;        // 100 XEC (two places)
    if (coin == "DOGE") return 2000000;      // 0.02 DOGE
    if (coin == "DGB")  return 10000000;     // 0.1 DGB
    if (coin == "RVN")  return 10000000;     // 0.1 RVN
    return 0;
}

static bool OfferFromJson(const json& j, SwapOffer& o, std::string& errOut)
{
    if (!j.is_object())                    { errOut = "an offer is an object"; return false; }
    if (!j.contains("v") || !j["v"].is_number_integer() || j["v"].get<int64_t>() != SWAP_PROTOCOL_VERSION)
    {
        errOut = "this offer is from an older Bitflash, which locks BTF by block height; it cannot be taken";
        return false;
    }
    if (!StrField(j, "give", o.give) || !StrField(j, "want", o.want))
    {
        errOut = "an offer names its coins as text";
        return false;
    }
    if (!SwapCoinOk(o.give) || !SwapCoinOk(o.want) || o.give == o.want || (o.give != "BTF" && o.want != "BTF"))
    {
        errOut = "an offer trades BTF for BTC or LTC, or either of them for BTF";
        return false;
    }
    if (!AmountOk(j, "ga", o.giveAmount) || !AmountOk(j, "wa", o.wantAmount))
    {
        errOut = "an offer needs two amounts, more than zero and at most 21 million";
        return false;
    }
    // Under this a contract's redeem would leave dust or nothing (the RPC
    // refuses it too): a taker could lock coins for a contract it could never
    // spend.
    if (o.giveAmount < SwapMinAmount(o.give) || o.wantAmount < SwapMinAmount(o.want))
    {
        const std::string& coin = o.giveAmount < SwapMinAmount(o.give) ? o.give : o.want;
        errOut = "the least " + coin + " a swap contract can hold is " + FormatSwapAmount(coin, SwapMinAmount(coin)) + " " + coin;
        return false;
    }
    if (!StrField(j, "note", o.note))    { errOut = "the offer's note is text"; return false; }
    if (o.note.size() > MAX_SWAP_NOTE)     { errOut = "the offer's note is too long"; return false; }
    return true;
}

static json OfferToJson(const SwapOffer& o)
{
    json j;
    j["v"] = SWAP_PROTOCOL_VERSION;
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
    // Every read above checks its type first; this is the backstop, so that
    // no offer anybody can post makes the thread reading it throw.
    try { return OfferFromJson(j, out, errOut); }
    catch (...) { out = SwapOffer(); errOut = "the offer has a field of the wrong type"; return false; }
}

std::string FormatSwapOffer(const SwapOffer& o)
{
    return OfferToJson(o).dump();
}

std::string DescribeSwapOffer(const SwapOffer& o)
{
    return FormatSwapAmount(o.give, o.giveAmount) + " " + o.give + " for " + FormatSwapAmount(o.want, o.wantAmount) + " " + o.want;
}

static bool StepFromJson(const json& j, SwapStep& s, std::string& errOut)
{
    if (!j.is_object())                    { errOut = "a swap step is an object"; return false; }
    if (!StrField(j, "s", s.swap) || !StrField(j, "step", s.step))
    {
        errOut = "a swap step names its swap and step as text";
        return false;
    }
    if (s.swap.size() != 32 || !IsHexString(s.swap)) { errOut = "the swap id is 32 hex characters"; return false; }

    if (s.step == "take")
    {
        if (!StrField(j, "offer", s.offer) || s.offer.size() != 32 || !IsHexString(s.offer))
        {
            errOut = "a take names the offer's frame id";
            return false;
        }
        if (!j.contains("terms") || !OfferFromJson(j["terms"], s.terms, errOut))
            return false;
        // The taker is paid in the coin the maker gives.
        if (!StrField(j, "to", s.to) || !SwapAddressShapeOk(s.terms.give, s.to))
        {
            errOut = "a take needs an address for the coin it receives";
            return false;
        }
        return true;
    }
    if (s.step == "lock1" || s.step == "lock2")
    {
        if (!StrField(j, "chain", s.chain) || !StrField(j, "c", s.contract) || !StrField(j, "tx", s.txid))
        {
            errOut = "a lock names its chain, contract and transaction as text";
            return false;
        }
        if (!SwapCoinOk(s.chain))           { errOut = "a lock names its chain"; return false; }
        // Decred's contract is 97 bytes; a little room, no more.
        if (!IsHexString(s.contract) || s.contract.size() > 300) { errOut = "the contract is hex, at most 150 bytes"; return false; }
        if (s.txid.size() != 64 || !IsHexString(s.txid)) { errOut = "the contract's txid is 64 hex characters"; return false; }
        if (s.chain != "BTF")
        {
            // Read whole before it is bounded: a number past 2^31 narrowed to
            // an int first could land inside the bound.
            if (!j.contains("n") || !j["n"].is_number_integer() || j["n"].get<int64_t>() < 0 || j["n"].get<int64_t>() > 100000)
            {
                errOut = "a contract off Bitflash names its output";
                return false;
            }
            s.vout = (int)j["n"].get<int64_t>();
        }
        if (s.step == "lock1")
        {
            if (!StrField(j, "to", s.to))   { errOut = "lock1 needs an address for the coin it receives"; return false; }
            // The maker wants the other coin. From a Bitflash lock this cannot
            // tell which, so any of them will do here; the contract built on
            // that chain refuses an address of the wrong network.
            bool fShape = s.chain == "BTF" ? SwapAddressShapeOk("BTC", s.to) || SwapAddressShapeOk("LTC", s.to) ||
                                                 SwapAddressShapeOk("DOGE", s.to) || SwapAddressShapeOk("DGB", s.to) || SwapAddressShapeOk("RVN", s.to) ||
                                                 SwapAddressShapeOk("BCH", s.to) || SwapAddressShapeOk("XEC", s.to)
                                           : SwapAddressShapeOk("BTF", s.to);
            if (!fShape) { errOut = "lock1 needs an address for the coin it receives"; return false; }
        }
        return true;
    }
    if (s.step == "redeemed")
    {
        if (!StrField(j, "tx", s.txid) || s.txid.size() != 64 || !IsHexString(s.txid))
        {
            errOut = "the redeem's txid is 64 hex characters";
            return false;
        }
        return true;
    }
    if (s.step == "cancel")
    {
        // A reason of the wrong type is no reason; the cancel still stands.
        if (!StrField(j, "why", s.why))
            s.why.clear();
        if (s.why.size() > MAX_SWAP_NOTE)   { errOut = "the reason is too long"; return false; }
        return true;
    }
    errOut = "unknown swap step";
    return false;
}

bool ParseSwapStep(const std::string& text, SwapStep& s, std::string& errOut)
{
    s = SwapStep();
    json j;
    try { j = json::parse(text); }
    catch (...) { errOut = "the swap step is not JSON"; return false; }
    try { return StepFromJson(j, s, errOut); }
    catch (...) { s = SwapStep(); errOut = "the swap step has a field of the wrong type"; return false; }
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
        if (s.chain != "BTF")
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
