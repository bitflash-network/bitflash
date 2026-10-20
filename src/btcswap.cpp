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

static CCriticalSection cs_config;
static std::string g_strChain, g_strDataDir, g_strWallet, g_strUser, g_strPassword, g_strFeeRate;
static int g_nPort = 0;
static std::string ConfiguredChain();

void Configure(const std::string& strChain, const std::string& strDataDir, int nPort,
               const std::string& strWallet, const std::string& strUser, const std::string& strPassword,
               const std::string& strFeeRate)
{
    CRITICAL_BLOCK(cs_config)
    {
        g_strChain = strChain;
        g_strDataDir = strDataDir;
        g_nPort = nPort;
        g_strWallet = strWallet;
        g_strUser = strUser;
        g_strPassword = strPassword;
        g_strFeeRate = strFeeRate;
    }
    if (UsingLight())
    {
        Chain chain;
        std::string err;
        // Loading the queue here resumes broadcasts after a wallet restart,
        // even before the person next opens the swap screen or calls RPC.
        if (!btclight::CheckChain(ConfiguredChain(), chain, err))
            printf("Bitcoin light: %s\n", err.c_str());
    }
}

static std::string ConfiguredChain()
{
    std::string s;
    CRITICAL_BLOCK(cs_config)
        s = g_strChain;
    if (s.empty())
        s = IsTestNet() ? "testnet4" : "main";
    if (s == "mainnet")
        s = "main";
    if (s == "testnet" || s == "testnet3")
        s = "test";
    return s;
}

static int DefaultPort(const std::string& chain)
{
    if (chain == "test")     return 18332;
    if (chain == "testnet4") return 48332;
    if (chain == "signet")   return 38332;
    if (chain == "regtest")  return 18443;
    return 8332;
}

static std::string ChainSubdir(const std::string& chain)
{
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

// Bitcoin Core's default data directory. On Windows, 28.0 moved new installs
// to %LOCALAPPDATA%; an older install keeps %APPDATA%.
static std::string CoreDataDir()
{
    std::string dir;
    CRITICAL_BLOCK(cs_config)
        dir = g_strDataDir;
    if (!dir.empty())
        return dir;
#ifdef _WIN32
    const char* local = getenv("LOCALAPPDATA");
    const char* roam = getenv("APPDATA");
    std::string a = std::string(local ? local : ".") + "\\Bitcoin";
    std::string b = std::string(roam ? roam : ".") + "\\Bitcoin";
    return DirExists(b) && !DirExists(a) ? b : a;
#elif defined(__APPLE__)
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + "/Library/Application Support/Bitcoin";
#else
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + "/.bitcoin";
#endif
}

bool UsingLight()
{
    CRITICAL_BLOCK(cs_config)
    {
        if (!g_strDataDir.empty() || g_nPort || !g_strWallet.empty() || !g_strUser.empty() || !g_strPassword.empty())
            return false;
    }
    // An existing cookie keeps the original automatic Core setup working.
    std::string sub = ChainSubdir(ConfiguredChain());
    return !DirExists(CoreDataDir() + (sub.empty() ? "" : "/" + sub) + "/.cookie");
}

bool Call(const std::string& method, const json& params, json& resultOut, std::string& errOut,
          size_t nMaxBytes, int* pnCodeOut)
{
    std::string chain = ConfiguredChain();
    if (UsingLight())
    {
        Chain info;
        if (!btclight::CheckChain(chain, info, errOut)) return false;
        return btclight::Call(method, params, resultOut, errOut);
    }
    LoopbackRpc to;
    to.strWho = "Bitcoin Core";
    to.nMaxBytes = nMaxBytes;
    to.nTimeoutSecs = 120;
    std::string user, pass, wallet;
    CRITICAL_BLOCK(cs_config)
    {
        to.nPort = g_nPort;
        user = g_strUser;
        pass = g_strPassword;
        wallet = g_strWallet;
    }
    if (!to.nPort)
        to.nPort = DefaultPort(chain);
    if (!wallet.empty())
        to.strPath = "/wallet/" + wallet;
    if (!user.empty())
        to.strAuth = user + ":" + pass;
    else
    {
        std::string sub = ChainSubdir(chain);
        std::string path = CoreDataDir() + (sub.empty() ? "" : "/" + sub) + "/.cookie";
        if (!ReadRpcCookie(path, to.strAuth, errOut))
        {
            errOut = "Bitcoin Core not found: " + errOut +
                     " (is it running? or give -btcdatadir, or -btcrpcuser/-btcrpcpassword)";
            return false;
        }
    }
    return LoopbackRpcCall(to, method, params, resultOut, errOut, pnCodeOut);
}

bool CheckChain(Chain& out, std::string& errOut)
{
    if (UsingLight()) return btclight::CheckChain(ConfiguredChain(), out, errOut);
    json r;
    if (!Call("getblockchaininfo", json::array(), r, errOut))
        return false;
    if (!r.is_object() || !r.contains("chain") || !r["chain"].is_string())
    {
        errOut = "Bitcoin Core did not say which chain it is on";
        return false;
    }
    out.name = r["chain"].get<std::string>();
    out.fMain = out.name == "main";
    out.pkhVersion = out.fMain ? 0x00 : 0x6f;
    out.shVersion = out.fMain ? 0x05 : 0xc4;
    out.nBlocks = r.contains("blocks") && r["blocks"].is_number_integer() ? r["blocks"].get<int>() : 0;
    out.nMedianTime = r.contains("mediantime") && r["mediantime"].is_number_integer() ? r["mediantime"].get<int64>() : 0;
    std::string want = ConfiguredChain();
    if (out.name != want)
    {
        errOut = "Bitcoin Core is on " + out.name + ", -btcchain says " + want;
        return false;
    }
    if (out.fMain == IsTestNet())
    {
        errOut = IsTestNet() ? "testnet BTF trades only against a Bitcoin test chain, and this Core is on main"
                             : "mainnet BTF trades only against Bitcoin's main chain, and this Core is on " + out.name;
        return false;
    }
    if (r.contains("initialblockdownload") && r["initialblockdownload"].is_boolean() &&
        r["initialblockdownload"].get<bool>() && out.fMain)
    {
        errOut = "Bitcoin Core is still downloading the chain; a swap needs it at the tip";
        return false;
    }
    return true;
}

static std::string Encode(unsigned char nVersion, const std::vector<unsigned char>& h20)
{
    std::vector<unsigned char> v(1, nVersion);
    v.insert(v.end(), h20.begin(), h20.end());
    return EncodeBase58Check(v);
}

std::string PkhToAddress(const Chain& chain, const std::vector<unsigned char>& pkh)
{
    return Encode(chain.pkhVersion, pkh);
}

bool AddressToPkh(const Chain& chain, const std::string& addr, std::vector<unsigned char>& pkhOut,
                  std::string& errOut)
{
    std::vector<unsigned char> v;
    if (!DecodeBase58Check(addr, v) || v.size() != 21)
    {
        errOut = "need a legacy Bitcoin address (1... on main, m... or n... on test chains); "
                 "bc1/tb1 addresses cannot be in this contract";
        return false;
    }
    if (v[0] != chain.pkhVersion)
    {
        errOut = v[0] == chain.shVersion ? "that is a script address; the contract needs a key address"
                                         : "that address is for another Bitcoin network than " + chain.name;
        return false;
    }
    pkhOut.assign(v.begin() + 1, v.end());
    return true;
}

std::string ScriptAddress(const Chain& chain, const CScript& redeemScript)
{
    uint160 h = Hash160(redeemScript);
    return Encode(chain.shVersion, std::vector<unsigned char>(h.begin(), h.end()));
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
    if (!ReadVarInt(b, pos, nIn) || nIn == 0 || nIn > 100000)
        return false;
    for (uint64 i = 0; i < nIn; i++)
    {
        uint64 n = 0;
        if (!Skip(b, pos, 36) || !ReadVarInt(b, pos, n) || !Skip(b, pos, n) || !Skip(b, pos, 4))
            return false;
    }
    if (!ReadVarInt(b, pos, nOut) || nOut > 100000)
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

bool ParseBlockTxs(const std::vector<unsigned char>& raw, std::vector<CTransaction>& txsOut)
{
    txsOut.clear();
    size_t pos = 80;
    uint64 n = 0;
    if (raw.size() < 81 || !ReadVarInt(raw, pos, n) || n == 0 || n > 1000000)
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

int64 FeeRatePerKvB()
{
    int64 nRate = 0;
    json r;
    std::string err;
    if (Call("estimatesmartfee", json::array({ 6 }), r, err) && r.is_object() &&
        r.contains("feerate") && r["feerate"].is_number())
        nRate = (int64)(r["feerate"].get<double>() * COIN + 0.5);
    if (nRate <= 0)
    {
        std::string s;
        CRITICAL_BLOCK(cs_config)
            s = g_strFeeRate;
        if (s.empty() || !ParseMoney(s.c_str(), nRate))
            nRate = 10000;            // 10 sat/vbyte
    }
    return std::max<int64>(nRate, 1000);
}

bool BuildSpend(const CScript& contract, const COutPoint& outpoint, int64 nValue, const CScript& scriptTo,
                CKey& key, const std::vector<unsigned char>& vchPubKey,
                const std::vector<unsigned char>* pSecret, int64 nFeeRatePerKvB,
                CTransaction& tx, int64& nFee, std::string& errOut)
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
        uint256 hash = SignatureHash(contract, tx, 0, SIGHASH_ALL);
        std::vector<unsigned char> sig;
        if (!key.Sign(hash, sig))
        {
            errOut = "signing failed";
            return false;
        }
        sig.push_back((unsigned char)SIGHASH_ALL);
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
