// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_COINUNIT_H
#define BITFLASH_COINUNIT_H

#include <stdint.h>
#include <stdio.h>
#include <string>

// How a chain counts. Amounts in the swap code are in the chain's base unit,
// the satoshi, on every chain; people and nodes count whole coins. A Bitcoin
// is 100000000 of them, an XEC only 100 (bitcoin-abc v0.34.3,
// src/consensus/amount.cpp). The ticker is "xec" or "XEC".
inline int CoinDecimals(const std::string& coin)
{
    return coin == "xec" || coin == "XEC" ? 2 : 8;
}

inline int64_t CoinUnit(const std::string& coin)
{
    return coin == "xec" || coin == "XEC" ? 100 : 100000000;
}

// Every decimal the chain has: "1.50000000", "1.50".
inline std::string CoinAmountText(const std::string& coin, int64_t n)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld.%0*lld", (long long)(n / CoinUnit(coin)), CoinDecimals(coin), (long long)(n % CoinUnit(coin)));
    return buf;
}

// A decimal amount of the chain's coin, at most the decimals it has.
inline bool ParseCoinAmount(const std::string& coin, const std::string& text, int64_t& out)
{
    static const int64_t MAX_BASE_UNITS = (int64_t)21000000 * 100000000;
    const int64_t unit = CoinUnit(coin);
    size_t dot = text.find('.');
    std::string whole = text.substr(0, dot), frac = dot == std::string::npos ? std::string() : text.substr(dot + 1);
    if (whole.empty() && frac.empty())
        return false;
    if ((int)frac.size() > CoinDecimals(coin))
        return false;
    frac.resize(CoinDecimals(coin), '0');
    int64_t w = 0, f = 0;
    for (size_t i = 0; i < whole.size(); i++)
    {
        if (whole[i] < '0' || whole[i] > '9' || w > MAX_BASE_UNITS / unit)
            return false;
        w = w * 10 + (whole[i] - '0');
    }
    for (size_t i = 0; i < frac.size(); i++)
    {
        if (frac[i] < '0' || frac[i] > '9')
            return false;
        f = f * 10 + (frac[i] - '0');
    }
    if (w > MAX_BASE_UNITS / unit)
        return false;
    out = w * unit + f;
    return out <= MAX_BASE_UNITS;
}

#endif
