// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btfchatwallet.h.

#include "headers.h"
#include "btfchatwallet.h"

// util.h redefines snprintf as a macro, which breaks nlohmann/json.
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

#include <cstdio>

using json = nlohmann::json;

namespace btfchat
{

static CCriticalSection cs_wallet;
static std::string g_strWalletDir;
static int g_nWalletPort = 0;

void WalletLinkConfigure(const std::string& strWalletDir, int nPort)
{
    CRITICAL_BLOCK(cs_wallet)
    {
        g_strWalletDir = strWalletDir;
        g_nWalletPort = nPort;
    }
}

// The wallet's data directory: what was configured, or the default Bitflash
// one -- never btfchat's own, which is a different folder on purpose.
static std::string WalletDir()
{
    std::string dir;
    CRITICAL_BLOCK(cs_wallet)
        dir = g_strWalletDir;
    if (dir.empty())
    {
#ifdef _WIN32
        const char* app = getenv("APPDATA");
        dir = std::string(app ? app : ".") + "\\Bitflash";
#else
        const char* home = getenv("HOME");
        dir = std::string(home ? home : ".") + "/.bitflash";
#endif
    }
    if (IsTestNet())
        dir += "/testnet";
    return dir;
}

static int WalletPort()
{
    int n = 0;
    CRITICAL_BLOCK(cs_wallet)
        n = g_nWalletPort;
    return n ? n : (IsTestNet() ? 18432 : 8432);
}

static bool ReadCookie(std::string& authOut, std::string& errOut)
{
    std::string path = WalletDir() + "/.cookie";
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
    {
        errOut = "no wallet linked (start Bitflash with -chatwallet; looked for " + path + ")";
        return false;
    }
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    authOut = buf;
    while (!authOut.empty() && (authOut[authOut.size() - 1] == '\n' || authOut[authOut.size() - 1] == '\r'))
        authOut.erase(authOut.size() - 1);
    if (authOut.find(':') == std::string::npos)
    {
        errOut = "the wallet's .cookie is malformed";
        return false;
    }
    return true;
}

static std::string Base64(const std::string& in)
{
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (size_t i = 0; i < in.size(); i++)
    {
        val = (val << 8) + (unsigned char)in[i];
        bits += 8;
        while (bits >= 0)
        {
            out.push_back(t[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(t[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

// One JSON-RPC call to the wallet over 127.0.0.1. Loopback only, by
// construction: the address is not a parameter.
static bool Call(const std::string& method, const json& params, json& resultOut, std::string& errOut)
{
    std::string auth;
    if (!ReadCookie(auth, errOut))
        return false;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not open a socket";
        return false;
    }
#ifdef _WIN32
    DWORD tv = 30000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)WalletPort());
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) != 0)
    {
        closesocket(s);
        errOut = strprintf("the wallet is not answering on 127.0.0.1:%d -- is Bitflash running with -chatwallet?",
                           WalletPort());
        return false;
    }

    json req;
    req["jsonrpc"] = "1.0";
    req["id"] = 1;
    req["method"] = method;
    req["params"] = params;
    std::string body = req.dump();
    std::string http = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic " + Base64(auth) +
                       "\r\nContent-Type: application/json\r\nContent-Length: " +
                       strprintf("%u", (unsigned)body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < http.size())
    {
        int n = send(s, http.data() + sent, (int)(http.size() - sent), 0);
        if (n <= 0)
        {
            closesocket(s);
            errOut = "the wallet closed the connection";
            return false;
        }
        sent += n;
    }

    std::string resp;
    char buf[4096];
    for (;;)
    {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        resp.append(buf, n);
        if (resp.size() > 1024 * 1024)
            break;
    }
    closesocket(s);

    size_t p = resp.find("\r\n\r\n");
    if (p == std::string::npos)
    {
        errOut = "the wallet sent no answer";
        return false;
    }
    if (resp.compare(0, 12, "HTTP/1.1 401") == 0 || resp.compare(0, 12, "HTTP/1.0 401") == 0)
    {
        errOut = "the wallet refused the cookie (was it restarted? the cookie changes every start)";
        return false;
    }
    json j;
    try { j = json::parse(resp.substr(p + 4)); }
    catch (...) { errOut = "the wallet's answer is not JSON"; return false; }
    if (j.contains("error") && !j["error"].is_null())
    {
        errOut = j["error"].is_object() && j["error"].contains("message")
                     ? j["error"]["message"].get<std::string>() : j["error"].dump();
        return false;
    }
    resultOut = j.contains("result") ? j["result"] : json(nullptr);
    return true;
}

bool WalletLinked(std::string& strStatusOut)
{
    json r;
    std::string err;
    if (!Call("getinfo", json::array(), r, err))
    {
        strStatusOut = err;
        return false;
    }
    double bal = r.is_object() && r.contains("balance") && r["balance"].is_number() ? r["balance"].get<double>() : 0.0;
    strStatusOut = strprintf("wallet linked, %.8f BTF", bal);
    return true;
}

bool WalletNewAddress(std::string& addrOut, std::string& errOut)
{
    json r;
    if (!Call("getnewaddress", json::array(), r, errOut))
        return false;
    if (!r.is_string())
    {
        errOut = "the wallet gave no address";
        return false;
    }
    addrOut = r.get<std::string>();
    return true;
}

bool WalletPay(const std::string& addr, int64_t amount, std::string& txidOut, std::string& errOut)
{
    // As a string with eight decimals: the wallet parses it with ParseMoney,
    // and a double would round some amounts by a satoshi.
    std::string strAmount = strprintf("%lld.%08lld", (long long)(amount / COIN), (long long)(amount % COIN));
    json r;
    if (!Call("sendtoaddress", json::array({ addr, strAmount }), r, errOut))
        return false;
    if (!r.is_string() || r.get<std::string>().size() != 64)
    {
        errOut = "the wallet did not return a transaction id";
        return false;
    }
    txidOut = r.get<std::string>();
    return true;
}

bool WalletLookup(const std::string& txid, int64_t& receivedOut, int& confirmationsOut,
                  std::string& errOut)
{
    receivedOut = 0;
    confirmationsOut = 0;
    json r;
    if (!Call("gettransaction", json::array({ txid }), r, errOut))
        return false;
    if (!r.is_object())
    {
        errOut = "the wallet does not know that transaction";
        return false;
    }
    double amount = r.contains("amount") && r["amount"].is_number() ? r["amount"].get<double>() : 0.0;
    receivedOut = (int64_t)(amount * COIN + (amount >= 0 ? 0.5 : -0.5));
    confirmationsOut = r.contains("confirmations") && r["confirmations"].is_number_integer()
                           ? r["confirmations"].get<int>() : 0;
    return true;
}

} // namespace btfchat
