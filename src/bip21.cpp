// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See bip21.h. Pure.

#include "bip21.h"

#include <cctype>
#include <cstdio>
#include <cstring>

static const char* SCHEME = "bitflash:";

static int HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool PercentDecode(const std::string& in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); i++)
    {
        if (in[i] == '%')
        {
            if (i + 2 >= in.size())
                return false;
            int h = HexVal(in[i + 1]), l = HexVal(in[i + 2]);
            if (h < 0 || l < 0)
                return false;
            out += (char)(h * 16 + l);
            i += 2;
        }
        else if (in[i] == '+')
            out += ' ';
        else
            out += in[i];
    }
    return true;
}

static std::string PercentEncode(const std::string& in)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < in.size(); i++)
    {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += (char)c;
        else
        {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

// "1.5" -> 150000000. Digits, at most one point, at most eight decimals:
// BIP21 forbids anything else (no exponent, no comma, no sign).
static bool ParseAmount(const std::string& s, int64_t& out)
{
    if (s.empty() || s.size() > 20)
        return false;
    int64_t whole = 0, frac = 0;
    int nFrac = -1;
    for (size_t i = 0; i < s.size(); i++)
    {
        char c = s[i];
        if (c == '.')
        {
            if (nFrac >= 0)
                return false;
            nFrac = 0;
            continue;
        }
        if (c < '0' || c > '9')
            return false;
        if (nFrac < 0)
        {
            whole = whole * 10 + (c - '0');
            if (whole > 21000000)
                return false;
        }
        else
        {
            if (++nFrac > 8)
                return false;
            frac = frac * 10 + (c - '0');
        }
    }
    if (nFrac == 0)
        return false;               // "1." is not an amount
    for (int k = nFrac < 0 ? 0 : nFrac; k < 8; k++)
        frac *= 10;
    out = whole * 100000000 + frac;
    return out <= (int64_t)21000000 * 100000000;
}

bool ParsePaymentLink(const std::string& uriIn, PaymentLink& out, std::string& errOut)
{
    out = PaymentLink();
    std::string uri = uriIn;
    while (!uri.empty() && isspace((unsigned char)uri[uri.size() - 1]))
        uri.erase(uri.size() - 1);
    size_t n = strlen(SCHEME);
    if (uri.size() < n)
    {
        errOut = "not a bitflash: link";
        return false;
    }
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)uri[i]) != SCHEME[i])
        {
            errOut = "not a bitflash: link";
            return false;
        }
    std::string rest = uri.substr(n);
    if (rest.compare(0, 2, "//") == 0)
        rest = rest.substr(2);      // bitflash://addr, which some apps write
    size_t q = rest.find('?');
    out.address = rest.substr(0, q);
    if (out.address.empty())
    {
        errOut = "the link has no address";
        return false;
    }
    if (q == std::string::npos)
        return true;
    std::string query = rest.substr(q + 1);
    size_t pos = 0;
    while (pos <= query.size())
    {
        size_t amp = query.find('&', pos);
        std::string pair = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        pos = amp == std::string::npos ? query.size() + 1 : amp + 1;
        if (pair.empty())
            continue;
        size_t eq = pair.find('=');
        std::string key = pair.substr(0, eq);
        std::string val;
        if (!PercentDecode(eq == std::string::npos ? std::string() : pair.substr(eq + 1), val))
        {
            errOut = "the link is not properly encoded";
            return false;
        }
        if (key == "amount")
        {
            if (!ParseAmount(val, out.amount))
            {
                errOut = "the link's amount is not a plain BTF amount";
                return false;
            }
        }
        else if (key == "label")
            out.label = val;
        else if (key == "message")
            out.message = val;
        else if (key.compare(0, 4, "req-") == 0)
        {
            errOut = "the link requires \"" + key.substr(4) + "\", which this wallet does not know";
            return false;
        }
        // Anything else is optional and ignored.
    }
    return true;
}

std::string MakePaymentLink(const PaymentLink& link)
{
    std::string s = std::string(SCHEME) + link.address;
    std::string sep = "?";
    if (link.amount > 0)
    {
        char buf[48];
        snprintf(buf, sizeof(buf), "%lld.%08lld", (long long)(link.amount / 100000000),
                 (long long)(link.amount % 100000000));
        std::string a = buf;
        while (a[a.size() - 1] == '0')
            a.erase(a.size() - 1);
        if (a[a.size() - 1] == '.')
            a.erase(a.size() - 1);
        s += sep + "amount=" + a;
        sep = "&";
    }
    if (!link.label.empty())
    {
        s += sep + "label=" + PercentEncode(link.label);
        sep = "&";
    }
    if (!link.message.empty())
        s += sep + "message=" + PercentEncode(link.message);
    return s;
}
