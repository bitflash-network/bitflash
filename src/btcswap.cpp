// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btcswap.h.

#include "headers.h"
#include "btcswap.h"
#include "swap.h"
#include "btclight.h"

using json = nlohmann::json;

namespace btcswap
{

// Each chain's own-node settings (-btcchain ..., -ltcchain ...). An empty
// entry means the defaults: the chain's main network (its test network on
// Bitflash testnet), its node's default RPC port and data directory, and the
// embedded light client when no node cookie is there.
struct Config
{
    std::string strChain, strDataDir, strWallet, strUser, strPassword, strFeeRate;
    int nPort = 0;
};
static CCriticalSection cs_config;
static std::map<std::string, Config> g_config;
static std::string ConfiguredChain(const std::string& coin);
static bool DirExists(const std::string& path);

bool KnownCoin(const std::string& coin)
{
    return coin == "btc" || coin == "ltc" || coin == "doge" || coin == "bch" || coin == "xec" || coin == "dgb";
}

static Config GetConfig(const std::string& coin)
{
    Config c;
    CRITICAL_BLOCK(cs_config)
    {
        std::map<std::string, Config>::const_iterator it = g_config.find(coin);
        if (it != g_config.end())
            c = it->second;
    }
    return c;
}

void Configure(const std::string& strCoin, const std::string& strChain, const std::string& strDataDir, int nPort,
               const std::string& strWallet, const std::string& strUser, const std::string& strPassword,
               const std::string& strFeeRate)
{
    if (!KnownCoin(strCoin))
        return;
    CRITICAL_BLOCK(cs_config)
    {
        Config& c = g_config[strCoin];
        c.strChain = strChain;
        c.strDataDir = strDataDir;
        c.nPort = nPort;
        c.strWallet = strWallet;
        c.strUser = strUser;
        c.strPassword = strPassword;
        c.strFeeRate = strFeeRate;
    }
    // Loading the queue here resumes broadcasts after a wallet restart, even
    // before the person next opens the swap screen or calls RPC. Bitcoin's
    // client always starts, as it did; another chain's only once it has been
    // used (its state file exists), so a wallet that never swaps with it
    // never dials that chain's peers.
    std::string strState = std::string(GetAppDir()) + "/" + strCoin + "-light-" + ConfiguredChain(strCoin) + ".json";
    if (UsingLight(strCoin) && (strCoin == "btc" || DirExists(strState)))
    {
        Chain chain;
        std::string err;
        if (!btclight::CheckChain(strCoin, ConfiguredChain(strCoin), chain, err))
            printf("%s light: %s\n", btclight::Label(strCoin).c_str(), err.c_str());
    }
}

void Configure(const std::string& strChain, const std::string& strDataDir, int nPort,
               const std::string& strWallet, const std::string& strUser, const std::string& strPassword,
               const std::string& strFeeRate)
{
    Configure("btc", strChain, strDataDir, nPort, strWallet, strUser, strPassword, strFeeRate);
}

static std::string ConfiguredChain(const std::string& coin)
{
    std::string s = GetConfig(coin).strChain;
    if (s.empty())
        s = !IsTestNet() ? "main" : coin == "btc" ? "testnet4" : coin == "bch" ? "test4" : "test";
    if (s == "mainnet")
        s = "main";
    if (s == "testnet" || s == "testnet3")
        s = "test";
    if (coin == "bch" && s == "testnet4")
        s = "test4";
    return s;
}

static int DefaultPort(const std::string& coin, const std::string& chain)
{
    if (coin == "ltc")
    {
        // litecoin v0.21.4, src/chainparamsbase.cpp
        if (chain == "test")    return 19332;
        if (chain == "regtest") return 19443;
        return 9332;
    }
    if (coin == "doge")
    {
        // dogecoin v1.14.9, src/chainparamsbase.cpp
        if (chain == "test")    return 44555;
        if (chain == "regtest") return 18332;
        return 22555;
    }
    if (coin == "dgb")
    {
        // digibyte v9.26.7, src/chainparamsbase.cpp
        if (chain == "test")    return 14026;
        if (chain == "regtest") return 18443;
        return 14022;
    }
    if (coin == "bch")
    {
        // bitcoin-cash-node v29.2.0, src/chainparamsbase.cpp
        if (chain == "test4")   return 28332;
        if (chain == "regtest") return 18443;
        return 8332;
    }
    if (coin == "xec")
    {
        // bitcoin-abc v0.34.3, src/chainparamsbase.cpp
        if (chain == "test")    return 18332;
        if (chain == "regtest") return 18443;
        return 8332;
    }
    if (chain == "test")     return 18332;
    if (chain == "testnet4") return 48332;
    if (chain == "signet")   return 38332;
    if (chain == "regtest")  return 18443;
    return 8332;
}

static std::string ChainSubdir(const std::string& coin, const std::string& chain)
{
    if (coin == "ltc")
    {
        // Litecoin keeps its test network in "testnet4" (chainparamsbase.cpp).
        if (chain == "test")    return "testnet4";
        if (chain == "regtest") return "regtest";
        return "";
    }
    if (coin == "dgb")
    {
        // DigiByte's test network was started over in 2026 (chainparamsbase.cpp).
        if (chain == "test")    return "testnet26";
        if (chain == "regtest") return "regtest";
        return "";
    }
    if (chain == "test4")    return "testnet4";
    if (chain == "test")     return "testnet3";
    if (chain == "testnet4") return "testnet4";
    if (chain == "signet")   return "signet";
    if (chain == "regtest")  return "regtest";
    return "";
}

static bool DirExists(const std::string& path)
{
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

// The node's default data directory. On Windows, Bitcoin Core 28.0 moved new
// installs to %LOCALAPPDATA%; an older install keeps %APPDATA%, where
// Litecoin Core still is.
static std::string CoreDataDir(const std::string& coin)
{
    std::string dir = GetConfig(coin).strDataDir;
    if (!dir.empty())
        return dir;
    // Bitcoin Cash Node and Bitcoin ABC use Bitcoin Core's names.
    std::string name = coin == "ltc" ? "Litecoin" : coin == "doge" ? "Dogecoin" : coin == "dgb" ? "DigiByte" : "Bitcoin";
#ifdef _WIN32
    const char* local = getenv("LOCALAPPDATA");
    const char* roam = getenv("APPDATA");
    std::string a = std::string(local ? local : ".") + "\\" + name;
    std::string b = std::string(roam ? roam : ".") + "\\" + name;
    if (coin == "ltc" || coin == "doge" || coin == "dgb")
        return b;
    return DirExists(b) && !DirExists(a) ? b : a;
#elif defined(__APPLE__)
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + "/Library/Application Support/" + name;
#else
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + (coin == "ltc" ? "/.litecoin" : coin == "doge" ? "/.dogecoin" : coin == "dgb" ? "/.digibyte" : "/.bitcoin");
#endif
}

bool UsingLight(const std::string& coin)
{
    Config c = GetConfig(coin);
    if (!c.strDataDir.empty() || c.nPort || !c.strWallet.empty() || !c.strUser.empty() || !c.strPassword.empty())
        return false;
    // An existing cookie keeps the original automatic node setup working.
    // Bitcoin Cash Node and Bitcoin ABC keep Bitcoin Core's data directory and
    // RPC port, so a cookie there says nothing about which chain it is for.
    // Their own-node mode asks to be named: -bchdatadir, -bchrpcport, ...
    if (coin == "bch" || coin == "xec")
        return true;
    std::string sub = ChainSubdir(coin, ConfiguredChain(coin));
    return !DirExists(CoreDataDir(coin) + (sub.empty() ? "" : "/" + sub) + "/.cookie");
}

bool UsingLight()
{
    return UsingLight("btc");
}

static const char* NodeWord(const std::string& coin)
{
    return coin == "bch" || coin == "xec" ? " node" : " Core";
}

std::string BackendName(const std::string& coin)
{
    return btclight::Label(coin) + (UsingLight(coin) ? " light" : NodeWord(coin));
}

bool Call(const std::string& coin, const std::string& method, const json& params, json& resultOut,
          std::string& errOut, size_t nMaxBytes, int* pnCodeOut)
{
    if (!KnownCoin(coin))
    {
        errOut = "unknown chain " + coin;
        return false;
    }
    std::string chain = ConfiguredChain(coin);
    if (UsingLight(coin))
    {
        Chain info;
        if (!btclight::CheckChain(coin, chain, info, errOut)) return false;
        return btclight::Call(info, method, params, resultOut, errOut);
    }
    Config c = GetConfig(coin);
    LoopbackRpc to;
    to.strWho = btclight::Label(coin) + NodeWord(coin);
    to.nMaxBytes = nMaxBytes;
    to.nTimeoutSecs = 120;
    to.nPort = c.nPort ? c.nPort : DefaultPort(coin, chain);
    // Dogecoin Core 1.14 has one wallet and no such path.
    if (!c.strWallet.empty() && coin != "doge")
        to.strPath = "/wallet/" + c.strWallet;
    if (!c.strUser.empty())
        to.strAuth = c.strUser + ":" + c.strPassword;
    else
    {
        std::string sub = ChainSubdir(coin, chain);
        std::string path = CoreDataDir(coin) + (sub.empty() ? "" : "/" + sub) + "/.cookie";
        if (!ReadRpcCookie(path, to.strAuth, errOut))
        {
            errOut = to.strWho + " not found: " + errOut + " (is it running? or give -" + coin +
                     "datadir, or -" + coin + "rpcuser/-" + coin + "rpcpassword)";
            return false;
        }
    }
    return LoopbackRpcCall(to, method, params, resultOut, errOut, pnCodeOut);
}

bool Call(const std::string& method, const json& params, json& resultOut, std::string& errOut,
          size_t nMaxBytes, int* pnCodeOut)
{
    return Call("btc", method, params, resultOut, errOut, nMaxBytes, pnCodeOut);
}

bool CheckChain(const std::string& coin, Chain& out, std::string& errOut)
{
    if (!KnownCoin(coin))
    {
        errOut = "unknown chain " + coin;
        return false;
    }
    std::string want = ConfiguredChain(coin);
    if (UsingLight(coin)) return btclight::CheckChain(coin, want, out, errOut);
    std::string who = btclight::Label(coin) + NodeWord(coin);
    json r;
    if (!Call(coin, "getblockchaininfo", json::array(), r, errOut))
        return false;
    if (!r.is_object() || !r.contains("chain") || !r["chain"].is_string())
    {
        errOut = who + " did not say which chain it is on";
        return false;
    }
    out.coin = coin;
    out.name = r["chain"].get<std::string>();
    out.fMain = out.name == "main";
    if (coin == "btc")
    {
        out.pkhVersion = out.fMain ? 0x00 : 0x6f;
        out.shVersion = out.fMain ? 0x05 : 0xc4;
    }
    else
    {
        const btclight::Net* net = btclight::FindNet(coin, out.name);
        if (!net)
        {
            errOut = who + " is on " + out.name + ", which this wallet does not know";
            return false;
        }
        out.pkhVersion = net->pkhVersion;
        out.shVersion = net->shVersion;
        out.cashPrefix = net->cashPrefix;
        out.fForkId = net->forkId;
    }
    // Bitcoin Core, Bitcoin Cash Node and Bitcoin ABC all call their chain
    // "main" on the same port with the same cookie, and only one of them knows
    // this prefix. A swap made against the wrong one could not be redeemed.
    if (coin == "btc" || !out.cashPrefix.empty())
    {
        std::string probe = coin != "btc" ? PkhToAddress(out, std::vector<unsigned char>(20, 0))
                            : out.name == "main" ? "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
                            : out.name == "regtest" ? "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
                            : "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        json v;
        if (!Call(coin, "validateaddress", json::array({ probe }), v, errOut))
            return false;
        if (!v.is_object() || !v.contains("isvalid") || !v["isvalid"].is_boolean() || !v["isvalid"].get<bool>())
        {
            errOut = "the node at that port is not on " + btclight::Label(coin);
            return false;
        }
    }
    out.nBlocks = r.contains("blocks") && r["blocks"].is_number_integer() ? r["blocks"].get<int>() : 0;
    out.nMedianTime = r.contains("mediantime") && r["mediantime"].is_number_integer() ? r["mediantime"].get<int64>() : 0;
    if (out.name != want)
    {
        errOut = who + " is on " + out.name + ", -" + coin + "chain says " + want;
        return false;
    }
    if (out.fMain == IsTestNet())
    {
        errOut = IsTestNet() ? "testnet BTF trades only against a " + btclight::Label(coin) + " test chain, and this node is on main"
                             : "mainnet BTF trades only against " + btclight::Label(coin) + "'s main chain, and this node is on " + out.name;
        return false;
    }
    if (r.contains("initialblockdownload") && r["initialblockdownload"].is_boolean() &&
        r["initialblockdownload"].get<bool>() && out.fMain)
    {
        errOut = who + " is still downloading the chain; a swap needs it at the tip";
        return false;
    }
    return true;
}

bool CheckChain(Chain& out, std::string& errOut)
{
    return CheckChain("btc", out, errOut);
}

static std::string Encode(unsigned char nVersion, const std::vector<unsigned char>& h20)
{
    std::vector<unsigned char> v(1, nVersion);
    v.insert(v.end(), h20.begin(), h20.end());
    return EncodeBase58Check(v);
}

// Cashaddr (bitcoin-cash-node v29.2.0, src/cashaddr.cpp): five-bit groups of a
// version byte and the hash, closed by eight groups of a 40-bit checksum that
// covers the prefix.
static uint64_t CashPolyMod(const std::vector<unsigned char>& v)
{
    uint64_t c = 1;
    for (size_t i = 0; i < v.size(); i++)
    {
        unsigned char c0 = (unsigned char)(c >> 35);
        c = ((c & 0x07ffffffffULL) << 5) ^ v[i];
        if (c0 & 0x01) c ^= 0x98f2bc8e61ULL;
        if (c0 & 0x02) c ^= 0x79b76d99e2ULL;
        if (c0 & 0x04) c ^= 0xf33e5fb3c4ULL;
        if (c0 & 0x08) c ^= 0xae2eabe2a8ULL;
        if (c0 & 0x10) c ^= 0x1e4f43e470ULL;
    }
    return c ^ 1;
}

static std::vector<unsigned char> CashPrefixBits(const std::string& prefix)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i < prefix.size(); i++)
        v.push_back((unsigned char)prefix[i] & 0x1f);
    v.push_back(0);
    return v;
}

static const char CASH_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

std::string CashEncode(const std::string& prefix, unsigned char nType, const std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> payload(1, (unsigned char)((nType << 3) | (hash.size() == 32 ? 3 : 0)));
    payload.insert(payload.end(), hash.begin(), hash.end());
    std::vector<unsigned char> groups;
    int nBits = 0, nAcc = 0;
    for (size_t i = 0; i < payload.size(); i++)
    {
        nAcc = (nAcc << 8) | payload[i];
        nBits += 8;
        while (nBits >= 5)
        {
            nBits -= 5;
            groups.push_back((nAcc >> nBits) & 0x1f);
        }
        nAcc &= (1 << nBits) - 1;
    }
    if (nBits)
        groups.push_back((nAcc << (5 - nBits)) & 0x1f);
    std::vector<unsigned char> check = CashPrefixBits(prefix);
    check.insert(check.end(), groups.begin(), groups.end());
    check.insert(check.end(), 8, 0);
    uint64_t nCheck = CashPolyMod(check);
    std::string s = prefix + ":";
    for (size_t i = 0; i < groups.size(); i++)
        s += CASH_CHARSET[groups[i]];
    for (int i = 0; i < 8; i++)
        s += CASH_CHARSET[(nCheck >> (5 * (7 - i))) & 0x1f];
    return s;
}

bool CashDecode(const std::string& prefix, const std::string& addr, unsigned char& nTypeOut, std::vector<unsigned char>& hashOut)
{
    std::string s = addr;
    bool fUpper = false, fLower = false;
    for (size_t i = 0; i < s.size(); i++)
    {
        if (s[i] >= 'A' && s[i] <= 'Z') { fUpper = true; s[i] = (char)(s[i] + 32); }
        else if (s[i] >= 'a' && s[i] <= 'z') fLower = true;
    }
    if (fUpper && fLower)
        return false;
    size_t nColon = s.find(':');
    if (nColon != std::string::npos)
    {
        if (s.substr(0, nColon) != prefix)
            return false;
        s = s.substr(nColon + 1);
    }
    std::vector<unsigned char> groups;
    for (size_t i = 0; i < s.size(); i++)
    {
        const char* p = s[i] ? strchr(CASH_CHARSET, s[i]) : NULL;
        if (!p)
            return false;
        groups.push_back((unsigned char)(p - CASH_CHARSET));
    }
    if (groups.size() < 9)
        return false;
    std::vector<unsigned char> check = CashPrefixBits(prefix);
    check.insert(check.end(), groups.begin(), groups.end());
    if (CashPolyMod(check) != 0)
        return false;
    groups.resize(groups.size() - 8);
    std::vector<unsigned char> payload;
    int nBits = 0, nAcc = 0;
    for (size_t i = 0; i < groups.size(); i++)
    {
        nAcc = (nAcc << 5) | groups[i];
        nBits += 5;
        if (nBits >= 8)
        {
            nBits -= 8;
            payload.push_back((unsigned char)((nAcc >> nBits) & 0xff));
        }
        nAcc &= (1 << nBits) - 1;
    }
    if (nBits >= 5 || nAcc || payload.empty() || (payload[0] & 0x80))
        return false;
    size_t nHash = (payload[0] & 7) == 0 ? 20 : (payload[0] & 7) == 3 ? 32 : 0;
    if (!nHash || payload.size() != nHash + 1)
        return false;
    nTypeOut = (unsigned char)(payload[0] >> 3);
    hashOut.assign(payload.begin() + 1, payload.end());
    return true;
}

std::string PkhToAddress(const Chain& chain, const std::vector<unsigned char>& pkh)
{
    if (!chain.cashPrefix.empty())
        return CashEncode(chain.cashPrefix, 0, pkh);
    return Encode(chain.pkhVersion, pkh);
}

bool AddressToPkh(const Chain& chain, const std::string& addr, std::vector<unsigned char>& pkhOut,
                  std::string& errOut)
{
    std::vector<unsigned char> v;
    if (!chain.cashPrefix.empty())
    {
        unsigned char nType = 0;
        std::vector<unsigned char> hash;
        if (CashDecode(chain.cashPrefix, addr, nType, hash))
        {
            if (nType != 0 || hash.size() != 20)
            {
                errOut = "that is not a plain key address; the contract needs " + chain.cashPrefix + ":q...";
                return false;
            }
            pkhOut = hash;
            return true;
        }
        errOut = "need a " + btclight::Label(chain.coin) + " key address (" + chain.cashPrefix + ":q...)";
        return false;
    }
    if (!DecodeBase58Check(addr, v) || v.size() != 21)
    {
        errOut = chain.coin == "dgb"
                     ? "need a legacy DigiByte key address (D... on main, s... or t... on test chains); "
                       "dgb1/dgbt1 addresses cannot be in this contract"
                 : chain.coin == "ltc"
                     ? "need a legacy Litecoin key address (L... on main, m... or n... on test chains); "
                       "ltc1/tltc1 addresses cannot be in this contract"
                     : "need a legacy Bitcoin address (1... on main, m... or n... on test chains); "
                       "bc1/tb1 addresses cannot be in this contract";
        return false;
    }
    if (v[0] != chain.pkhVersion)
    {
        errOut = v[0] == chain.shVersion ? "that is a script address; the contract needs a key address"
                                         : "that address is for another " + btclight::Label(chain.coin) + " network than " + chain.name;
        return false;
    }
    pkhOut.assign(v.begin() + 1, v.end());
    return true;
}

std::string ScriptAddress(const Chain& chain, const CScript& redeemScript)
{
    uint160 h = Hash160(redeemScript);
    std::vector<unsigned char> hash(h.begin(), h.end());
    if (!chain.cashPrefix.empty())
        return CashEncode(chain.cashPrefix, 1, hash);
    return Encode(chain.shVersion, hash);
}

// ---- reading Bitcoin's serialization

static bool ReadVarInt(const std::vector<unsigned char>& b, size_t& pos, uint64& n)
{
    if (pos >= b.size())
        return false;
    unsigned char c = b[pos++];
    int nBytes = c < 0xfd ? 0 : c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
    if (nBytes == 0)
    {
        n = c;
        return true;
    }
    if (pos + nBytes > b.size())
        return false;
    n = 0;
    for (int i = 0; i < nBytes; i++)
        n |= (uint64)b[pos + i] << (8 * i);
    pos += nBytes;
    return true;
}

static bool Skip(const std::vector<unsigned char>& b, size_t& pos, uint64 n)
{
    if (n > b.size() - pos)
        return false;
    pos += (size_t)n;
    return true;
}

static void WriteVarInt(std::vector<unsigned char>& out, uint64 n)
{
    if (n < 0xfd)
        out.push_back((unsigned char)n);
    else
    {
        int nBytes = n <= 0xffff ? 2 : n <= 0xffffffffULL ? 4 : 8;
        out.push_back(nBytes == 2 ? 0xfd : nBytes == 4 ? 0xfe : 0xff);
        for (int i = 0; i < nBytes; i++)
            out.push_back((unsigned char)(n >> (8 * i)));
    }
}

bool ParseTxAt(const std::vector<unsigned char>& b, size_t& pos, CTransaction& txOut)
{
    // version | [00 01] | vin | vout | [witness per input] | locktime
    size_t start = pos;
    if (!Skip(b, pos, 4))
        return false;
    bool fWitness = pos + 1 < b.size() && b[pos] == 0x00 && b[pos + 1] == 0x01;
    if (fWitness)
        pos += 2;
    size_t bodyStart = pos;
    uint64 nIn = 0, nOut = 0;
    // Counts are bounded by the bytes left, not by a number of their own: a
    // valid transaction over any fixed limit would stop a block scan for good.
    if (!ReadVarInt(b, pos, nIn) || nIn == 0 || nIn > (b.size() - pos) / 41)
        return false;
    for (uint64 i = 0; i < nIn; i++)
    {
        uint64 n = 0;
        if (!Skip(b, pos, 36) || !ReadVarInt(b, pos, n) || !Skip(b, pos, n) || !Skip(b, pos, 4))
            return false;
    }
    if (!ReadVarInt(b, pos, nOut) || nOut > (b.size() - pos) / 9)
        return false;
    for (uint64 i = 0; i < nOut; i++)
    {
        uint64 n = 0;
        if (!Skip(b, pos, 8) || !ReadVarInt(b, pos, n) || !Skip(b, pos, n))
            return false;
    }
    size_t bodyEnd = pos;
    if (fWitness)
        for (uint64 i = 0; i < nIn; i++)
        {
            uint64 nItems = 0;
            if (!ReadVarInt(b, pos, nItems))
                return false;
            for (uint64 k = 0; k < nItems; k++)
            {
                uint64 n = 0;
                if (!ReadVarInt(b, pos, n) || !Skip(b, pos, n))
                    return false;
            }
        }
    if (!Skip(b, pos, 4))
        return false;

    // The same bytes without the marker and the witness: what the txid hashes,
    // and exactly how a Bitflash transaction is laid out.
    std::vector<unsigned char> stripped(b.begin() + start, b.begin() + start + 4);
    stripped.insert(stripped.end(), b.begin() + bodyStart, b.begin() + bodyEnd);
    stripped.insert(stripped.end(), b.begin() + pos - 4, b.begin() + pos);
    try
    {
        CDataStream ss(stripped, SER_NETWORK);
        ss >> txOut;
        if (!ss.empty())
            return false;
    }
    catch (std::exception&)
    {
        return false;
    }
    return true;
}

bool ParseTx(const std::vector<unsigned char>& raw, CTransaction& txOut)
{
    size_t pos = 0;
    return ParseTxAt(raw, pos, txOut) && pos == raw.size();
}

static bool ReadHashList(const std::vector<unsigned char>& b, size_t& pos, std::vector<uint256>& out)
{
    uint64 n = 0;
    if (!ReadVarInt(b, pos, n) || n > (b.size() - pos) / 32)
        return false;
    out.resize((size_t)n);
    for (uint64 i = 0; i < n; i++, pos += 32)
        out[(size_t)i] = uint256(std::vector<unsigned char>(b.begin() + pos, b.begin() + pos + 32));
    return true;
}

bool ParseAuxPow(const std::vector<unsigned char>& b, size_t& pos, AuxPow& out)
{
    if (!ParseTxAt(b, pos, out.tx) || !Skip(b, pos, 32) || !ReadHashList(b, pos, out.branch) || b.size() - pos < 4)
        return false;
    out.nIndex = (int)(b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | ((unsigned int)b[pos + 3] << 24));
    pos += 4;
    if (!ReadHashList(b, pos, out.chainBranch) || b.size() - pos < 84)
        return false;
    out.nChainIndex = (int)(b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | ((unsigned int)b[pos + 3] << 24));
    pos += 4;
    out.parent.assign(b.begin() + pos, b.begin() + pos + 80);
    pos += 80;
    return true;
}

bool ParseBlockTxs(const std::vector<unsigned char>& raw, std::vector<CTransaction>& txsOut, bool fAuxPow)
{
    txsOut.clear();
    size_t pos = 80;
    uint64 n = 0;
    if (raw.size() < 81)
        return false;
    if (fAuxPow && (raw[1] & 1))    // VERSION_AUXPOW, 1 << 8
    {
        AuxPow aux;
        if (!ParseAuxPow(raw, pos, aux))
            return false;
    }
    if (!ReadVarInt(raw, pos, n) || n == 0 || n > 1000000)
        return false;
    txsOut.reserve((size_t)n);
    for (uint64 i = 0; i < n; i++)
    {
        CTransaction tx;
        if (!ParseTxAt(raw, pos, tx))
            return false;
        txsOut.push_back(tx);
    }
    return pos == raw.size();
}

int64 FeeRatePerKvB(const std::string& coin)
{
    int64 nRate = 0;
    json r;
    std::string err;
    bool fCash = coin == "bch" || coin == "xec";
    // Dogecoin counts fees in its own coin: 0.01 DOGE per 1000 bytes is the
    // recommended rate (dogecoin v1.14.9, src/policy/policy.h), and it often
    // has no estimate. Bitcoin Cash Node and Bitcoin ABC have no
    // estimatesmartfee, and their blocks have room: 1 sat/byte is what
    // everyone pays.
    if (!fCash && Call(coin, "estimatesmartfee", json::array({ 6 }), r, err) && r.is_object() &&
        r.contains("feerate") && r["feerate"].is_number())
        nRate = (int64)(r["feerate"].get<double>() * COIN + 0.5);
    if (nRate <= 0)
    {
        std::string s = GetConfig(coin).strFeeRate;
        int64_t nConfigured = 0;
        if (!s.empty() && ParseCoinAmount(coin, s, nConfigured))
            nRate = nConfigured;
        else
            nRate = coin == "doge" ? COIN / 100 : coin == "dgb" ? COIN / 1000 : fCash ? 1000 : 10000; // 1 or 10 sat/vbyte
    }
    if (coin == "doge")
        return std::max<int64>(nRate, COIN / 100);
    // DigiByte's minimum relay fee (digibyte v9.26.7, src/policy/policy.h).
    if (coin == "dgb")
        return std::max<int64>(nRate, COIN / 1000);
    // 1000 per 1000 vbytes is the minimum relay fee of Bitcoin Core and of
    // Litecoin Core (litecoin v0.21.4, src/validation.h).
    return std::max<int64>(nRate, 1000);
}

int64 FeeRatePerKvB()
{
    return FeeRatePerKvB("btc");
}

// The signature hash Bitcoin Cash and eCash require, BIP143's layout, which
// commits to the amount spent. The base type here is always ALL
// (bitcoin-cash-node v29.2.0, src/script/interpreter.cpp).
uint256 ForkIdSignatureHash(const CScript& scriptCode, const CTransaction& tx, unsigned int nIn, int64 nAmount,
                            unsigned int nHashType)
{
    CDataStream prevouts(SER_GETHASH), sequences(SER_GETHASH), outputs(SER_GETHASH);
    for (size_t i = 0; i < tx.vin.size(); i++)
    {
        prevouts << tx.vin[i].prevout;
        sequences << tx.vin[i].nSequence;
    }
    for (size_t i = 0; i < tx.vout.size(); i++)
        outputs << tx.vout[i];
    CDataStream ss(SER_GETHASH);
    ss << tx.nVersion
       << Hash(prevouts.begin(), prevouts.end())
       << Hash(sequences.begin(), sequences.end())
       << tx.vin[nIn].prevout
       << scriptCode
       << nAmount
       << tx.vin[nIn].nSequence
       << Hash(outputs.begin(), outputs.end())
       << tx.nLockTime
       << nHashType;
    return Hash(ss.begin(), ss.end());
}

bool BuildSpend(const CScript& contract, const COutPoint& outpoint, int64 nValue, const CScript& scriptTo,
                CKey& key, const std::vector<unsigned char>& vchPubKey,
                const std::vector<unsigned char>* pSecret, int64 nFeeRatePerKvB,
                CTransaction& tx, int64& nFee, std::string& errOut, bool fForkId)
{
    swap::Contract c;
    if (!swap::ParseContract(contract, c))
    {
        errOut = "that is not an atomic swap contract";
        return false;
    }
    tx = CTransaction();
    tx.vin.resize(1);
    tx.vin[0].prevout = outpoint;
    if (!pSecret)
    {
        tx.nLockTime = (unsigned int)c.nLockTime;
        tx.vin[0].nSequence = 0;
    }
    else
        tx.vin[0].nSequence = SEQUENCE_REPLACEABLE;   // a stuck redeem can be made again with a higher fee
    // A signature is 71 to 73 bytes, so each signing can change the size the
    // fee is for. The fee only grows, so this ends once it covers the size of
    // the transaction as finally signed -- a byte or two over at most.
    nFee = 0;
    bool fCovered = false;
    for (int nPass = 0; nPass < 16 && !fCovered; nPass++)
    {
        if (nValue - nFee < 1000)
        {
            errOut = "the contract holds less than the fee to spend it";
            return false;
        }
        tx.vout.assign(1, CTxOut(nValue - nFee, scriptTo));
        tx.vin[0].scriptSig = CScript();
        uint256 hash = fForkId ? ForkIdSignatureHash(contract, tx, 0, nValue) : SignatureHash(contract, tx, 0, SIGHASH_ALL);
        std::vector<unsigned char> sig;
        if (!key.Sign(hash, sig))
        {
            errOut = "signing failed";
            return false;
        }
        sig.push_back((unsigned char)(fForkId ? FORKID_SIGHASH_ALL : SIGHASH_ALL));
        tx.vin[0].scriptSig = pSecret ? swap::RedeemScriptSig(sig, vchPubKey, *pSecret, contract)
                                      : swap::RefundScriptSig(sig, vchPubKey, contract);
        // No witness, so the size is the virtual size.
        int64 nSize = (int64)::GetSerializeSize(tx, SER_NETWORK);
        int64 nNeed = (nSize * nFeeRatePerKvB + 999) / 1000;
        if (nNeed <= nFee)
            fCovered = true;
        else
            nFee = nNeed;
    }
    if (!fCovered)
    {
        errOut = "could not settle the fee";
        return false;
    }
    if (fForkId)
    {
        // Bitflash's interpreter does not know this signature hash, and its
        // consensus has no reason to, so the contract's conditions are
        // checked here: the right key and the right secret.
        uint160 h = Hash160(vchPubKey);
        std::vector<unsigned char> pkh(h.begin(), h.end());
        bool fOk = pkh == (pSecret ? c.recipientPkh : c.refundPkh);
        if (fOk && pSecret)
        {
            std::vector<unsigned char> digest(32);
            SHA256(pSecret->data(), pSecret->size(), digest.data());
            fOk = pSecret->size() == swap::SECRET_BYTES && digest == c.secretHash;
        }
        if (!fOk)
            errOut = pSecret ? "the redeem does not satisfy the contract -- is that the right secret and key?"
                             : "the refund does not satisfy the contract";
        return fOk;
    }
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);
    if (!VerifyScriptP2SH(tx.vin[0].scriptSig, p2sh, tx, 0, true, true))
    {
        errOut = pSecret ? "the redeem does not satisfy the contract -- is that the right secret and key?"
                         : "the refund does not satisfy the contract";
        return false;
    }
    return true;
}

} // namespace btcswap
