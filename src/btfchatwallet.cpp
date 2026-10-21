// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btfchatwallet.h.

#include "headers.h"
#include "btfchatwallet.h"
#include "rpcclient.h"

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

// One JSON-RPC call to the wallet over 127.0.0.1 (rpcclient.h), with the
// password the wallet wrote to its .cookie.
static bool Call(const std::string& method, const json& params, json& resultOut, std::string& errOut,
                 int nTimeoutSecs = 30)
{
    LoopbackRpc to;
    to.nPort = WalletPort();
    to.nTimeoutSecs = nTimeoutSecs;
    to.strWho = "the wallet";
    std::string path = WalletDir() + "/.cookie";
    if (!ReadRpcCookie(path, to.strAuth, errOut))
    {
        errOut = "no wallet linked (start Bitflash with -chatwallet; looked for " + path + ")";
        return false;
    }
    if (!LoopbackRpcCall(to, method, params, resultOut, errOut))
    {
        if (errOut.find("not answering") != std::string::npos)
            errOut += " -- is Bitflash running with -chatwallet?";
        return false;
    }
    return true;
}

bool WalletRpc(const std::string& method, const json& params, json& resultOut, std::string& errOut)
{
    // Looking for a secret can mean reading a few hundred Bitcoin blocks.
    return Call(method, params, resultOut, errOut, 900);
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

bool WalletBurn(int64_t amount, const std::string& dataHex, std::string& txidOut, std::string& errOut)
{
    std::string strAmount = strprintf("%lld.%08lld", (long long)(amount / COIN), (long long)(amount % COIN));
    json r;
    if (!Call("sendburn", json::array({ strAmount, dataHex }), r, errOut))
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
