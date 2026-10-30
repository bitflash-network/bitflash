// JSON-RPC over HTTP for exchange integration.
//
// Bitcoin 0.1.0 had no RPC; it arrived in 0.3.x and this tree never inherited
// it. Without one there is no way for anybody else's software to run a wallet:
// no deposit address per user, no way to notice a deposit landed, no way to pay
// a withdrawal. Every exchange integration is built on exactly those calls, so
// they are what this file provides -- and only those. The method set is the
// one exchanges actually use, named and shaped the way bitcoind names and
// shapes them, so an integration written for any Bitcoin-derived coin works
// here unchanged.
//
// Exposure is the design constraint. A node on this network goes to some
// trouble not to be reachable in the clear, and a wallet that spends on command
// must not undo that. So: nothing listens unless -rpcuser and -rpcpassword are
// both given, the socket binds loopback and there is no option to bind wider,
// every request carries HTTP Basic credentials, and the comparison is constant
// time. What the exchange runs beside the daemon can talk to it; nothing else.

#include <nlohmann/json.hpp>
#include "headers.h"
#include "btfsock.h"
#include "jsonrpc.h"
#include "tor.h"
#include "treasury.h"
#include "swap.h"
#include "btcswap.h"
#include "btclight.h"
#include "invoice.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define rpc_close(s) closesocket(s)
#else
#define rpc_close(s) close(s)
#endif

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// configuration

static string g_rpcUser;
static string g_rpcPassword;
static int    g_rpcPort = 0;

bool JsonRpcConfigure(const string& strUser, const string& strPassword, const string& strPort)
{
    g_rpcUser     = strUser;
    g_rpcPassword = strPassword;

    if (g_rpcUser.empty() && g_rpcPassword.empty())
        return false;                                   // not asked for
    if (g_rpcUser.empty() || g_rpcPassword.empty())
    {
        fprintf(stderr, "JSON-RPC needs both -rpcuser and -rpcpassword; refusing to start it with one\n");
        return false;
    }
    if (g_rpcPassword.size() < 16)
    {
        // A wallet behind a short password on a local port is a wallet behind
        // whatever else runs on that machine. Sixteen is a floor, not advice.
        fprintf(stderr, "JSON-RPC: -rpcpassword must be at least 16 characters\n");
        return false;
    }
    g_rpcPort = strPort.empty() ? (IsTestNet() ? 18432 : 8432) : atoi(strPort.c_str());
    if (g_rpcPort <= 0 || g_rpcPort > 65535)
    {
        fprintf(stderr, "JSON-RPC: -rpcport=%s is not a port\n", strPort.c_str());
        return false;
    }
    return true;
}

bool JsonRpcConfigureCookie(const string& strPort)
{
    // A fresh random password every start, in a file only this user can read,
    // for the chat (btfchatwallet.h) or any other local tool. Bitcoin's .cookie,
    // same shape, so a tool written for that reads this.
    unsigned char rnd[32];
    RAND_bytes(rnd, sizeof(rnd));
    string strPass = HexStr(rnd, rnd + sizeof(rnd), false);
    OPENSSL_cleanse(rnd, sizeof(rnd));

    string path = GetAppDir() + "/.cookie";
    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
    {
        fprintf(stderr, "-chatwallet: could not write %s\n", path.c_str());
        return false;
    }
#ifndef _WIN32
    chmod(path.c_str(), 0600);
#endif
    string line = "__cookie__:" + strPass + "\n";
    fwrite(line.data(), 1, line.size(), f);
    fclose(f);
    return JsonRpcConfigure("__cookie__", strPass, strPort);
}

// ---------------------------------------------------------------------------
// small helpers

static double ValueFromAmount(int64 n) { return (double)n / (double)COIN; }

static int64 AmountFromValue(const json& v)
{
    // Exchanges send amounts as JSON numbers or as strings; accept both, and
    // go through ParseMoney so "1.5" and 1.5 land on the same satoshi count.
    string s = v.is_string() ? v.get<string>() : strprintf("%.8f", v.get<double>());
    int64 n = 0;
    if (!ParseMoney(s.c_str(), n) || n <= 0)
        throw runtime_error("invalid amount");
    return n;
}

static bool ConstantTimeEqual(const string& a, const string& b)
{
    // Length leaks, but a guess at the length of a password is not a guess at
    // the password. What must not leak is where the first wrong byte is.
    unsigned char diff = (unsigned char)(a.size() != b.size());
    size_t n = min(a.size(), b.size());
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static string Base64Decode(const string& in)
{
    static const string tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string out;
    int val = 0, bits = -8;
    foreach(unsigned char c, in)
    {
        if (c == '=') break;
        string::size_type p = tbl.find((char)c);
        if (p == string::npos) continue;
        val = (val << 6) + (int)p;
        bits += 6;
        if (bits >= 0)
        {
            out.push_back((char)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

static CScript ScriptForAddress(const string& strAddr)
{
    CScript s;
    // The word "treasury" stands for the treasury's multisig script wherever
    // an address is taken, so any wallet can pay it without pasting a script.
    if (strAddr == "treasury")
    {
        if (!treasury::Script(s))
            throw runtime_error("there is no treasury on this network yet");
        return s;
    }
    uint160 hash160;
    bool fScript = false;
    if (!DecodeAnyAddress(strAddr, hash160, fScript))
        throw runtime_error("invalid Bitflash address");
    if (fScript)
    {
        // Until the rules v3 switch a pay-to-script-hash output is spendable
        // by anyone who presents the script, signatures or not. Paying to one
        // before then is giving the money away.
        if (!RulesV3Active(GetAdjustedTime()))
            throw runtime_error(RulesV3Time() == 0
                ? "pay-to-script-hash addresses (C...) are not active on this network yet: the rules v3 switch is not scheduled"
                : strprintf("pay-to-script-hash addresses (C...) activate at block time %u; not before", RulesV3Time()));
        s << OP_HASH160 << hash160 << OP_EQUAL;
        return s;
    }
    s << OP_DUP << OP_HASH160 << hash160 << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

// A public key for multisig construction: hex, or an address whose key this
// wallet holds.
static vector<unsigned char> PubKeyFromParam(const string& str)
{
    if (IsHex(str))
    {
        vector<unsigned char> vch = ParseHex(str);
        if (vch.size() != 65 && vch.size() != 33)
            throw runtime_error("public key must be 65 (or 33) bytes: " + str);
        return vch;
    }
    uint160 h;
    if (!AddressToHash160(str, h))
        throw runtime_error("not a public key and not a Bitflash address: " + str);
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(h);
        if (mi == mapPubKeys.end())
            throw runtime_error("this wallet does not hold the key for " + str + "; give the public key in hex");
        return mi->second;
    }
    throw runtime_error("unreachable");
}

static CScript MultisigRedeemScript(const json& p)
{
    if (p.size() < 2 || !p[0].is_number_integer() || !p[1].is_array())
        throw runtime_error("<nrequired> [\"key\",...]");
    int nRequired = p[0].get<int>();
    vector<vector<unsigned char> > keys;
    for (size_t i = 0; i < p[1].size(); i++)
    {
        if (!p[1][i].is_string())
            throw runtime_error("keys must be strings");
        keys.push_back(PubKeyFromParam(p[1][i].get<string>()));
    }
    if (keys.empty() || keys.size() > 16)
        throw runtime_error("between 1 and 16 keys");
    if (nRequired < 1 || nRequired > (int)keys.size())
        throw runtime_error(strprintf("nrequired must be between 1 and %d", (int)keys.size()));
    CScript redeem;
    redeem.SetMultisig(nRequired, keys);
    if (redeem.size() > 520)
        throw runtime_error("redeem script over 520 bytes");
    return redeem;
}

static json ScriptToJson(const CScript& script)
{
    json j;
    j["asm"] = script.ToString();
    j["hex"] = HexStr(script.begin(), script.end(), false);
    txnouttype whichType;
    vector<vector<unsigned char> > vSolutions;
    if (SolverTyped(script, whichType, vSolutions))
    {
        j["type"] = GetTxnOutputType(whichType);
        if (whichType == TX_PUBKEYHASH)
            j["address"] = Hash160ToAddress(uint160(vSolutions[0]));
        else if (whichType == TX_PUBKEY)
            j["address"] = PubKeyToAddress(vSolutions[0]);
        else if (whichType == TX_SCRIPTHASH)
            j["address"] = Hash160ToScriptAddress(uint160(vSolutions[0]));
        else if (whichType == TX_NULL_DATA)
        {
            j["data"] = HexStr(vSolutions[0].begin(), vSolutions[0].end(), false);
        }
        else if (whichType == TX_MULTISIG)
        {
            j["reqSigs"] = (int)vSolutions.front()[0];
            json a = json::array();
            for (size_t i = 1; i + 1 < vSolutions.size(); i++)
                a.push_back(PubKeyToAddress(vSolutions[i]));
            j["addresses"] = a;
        }
    }
    else
        j["type"] = "nonstandard";
    return j;
}

static string AddressOfScript(const CScript& scriptPubKey)
{
    uint160 h;
    if (ExtractHash160(scriptPubKey, h))
        return Hash160ToAddress(h);
    // Coinbase outputs pay to a bare public key, the 2009 way, so there is no
    // hash in the script to read off; derive the address from the key instead.
    // Without this every mining reward listed with an empty address.
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(scriptPubKey, false, vchPubKey))
        return PubKeyToAddress(vchPubKey);
    return "";
}

static bool IsMineAddress(const string& strAddr)
{
    uint160 h;
    if (!AddressToHash160(strAddr, h))
        return false;
    CRITICAL_BLOCK(cs_mapKeys)
        return mapPubKeys.count(h) > 0;
    return false;
}

static CBlockIndex* BlockIndexOf(const uint256& hash)
{
    map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? NULL : it->second;
}

// ---------------------------------------------------------------------------
// the shape exchanges read

// One wallet transaction, the way gettransaction / listtransactions describe
// it: net amount from this wallet's point of view, confirmations, and one
// "details" entry per output that concerns us.
static json WalletTxToJson(const CWalletTx& wtx)
{
    json j;
    int64 nCredit = wtx.GetCredit();
    int64 nDebit  = wtx.GetDebit();
    int nDepth    = wtx.GetDepthInMainChain();

    j["txid"]          = wtx.GetHash().GetHex();
    j["amount"]        = ValueFromAmount(nCredit - nDebit);
    j["confirmations"] = nDepth;
    j["time"]          = (int64)wtx.nTimeReceived;
    j["timereceived"]  = (int64)wtx.nTimeReceived;
    // Bitcoin Core's name for it: while unconfirmed, can it be replaced
    // (sped up with bumpfee, or by its sender for a payment to us)?
    j["bip125-replaceable"] = nDepth > 0 ? "no" : (wtx.SignalsReplacement() ? "yes" : "no");
    if (nDepth > 0)
    {
        j["blockhash"] = wtx.hashBlock.GetHex();
        CBlockIndex* pindex = BlockIndexOf(wtx.hashBlock);
        if (pindex)
        {
            j["blockindex"] = pindex->nHeight;
            j["blocktime"]  = (int64)pindex->nTime;
        }
    }
    if (wtx.IsCoinBase())
    {
        // Mining reward. An exchange should not credit these until mature, and
        // the category says so; confirmations alone would not.
        j["generated"] = true;
    }

    json details = json::array();
    for (size_t i = 0; i < wtx.vout.size(); i++)
    {
        const CTxOut& out = wtx.vout[i];
        bool fMine = out.IsMine();
        string addr = AddressOfScript(out.scriptPubKey);
        if (nDebit > 0 && !fMine)
        {
            json d;
            d["category"] = "send";
            d["address"]  = addr;
            d["amount"]   = -ValueFromAmount(out.nValue);
            d["vout"]     = (int)i;
            details.push_back(d);
        }
        // An output of ours in a transaction we funded is change, not a
        // receipt. It must not be listed as one: an exchange that sums the
        // "receive" entries to credit deposits would credit its own change
        // every time it paid a withdrawal. Coinbase has no inputs of ours, so
        // it is never mistaken for change.
        if (fMine && (nDebit == 0 || wtx.IsCoinBase()))
        {
            json d;
            d["category"] = wtx.IsCoinBase()
                                ? (wtx.GetBlocksToMaturity() > 0 ? "immature" : "generate")
                                : "receive";
            d["address"]  = addr;
            d["amount"]   = ValueFromAmount(out.nValue);
            d["vout"]     = (int)i;
            details.push_back(d);
        }
    }
    j["details"] = details;
    return j;
}

static json BlockToJson(CBlockIndex* pindex)
{
    CBlock block;
    if (!block.ReadFromDisk(pindex, true))
        throw runtime_error("block not on disk");
    json j;
    j["hash"]          = pindex->GetBlockHash().GetHex();
    j["confirmations"] = nBestHeight - pindex->nHeight + 1;
    j["height"]        = pindex->nHeight;
    j["version"]       = block.nVersion;
    j["merkleroot"]    = block.hashMerkleRoot.GetHex();
    j["time"]          = (int64)block.nTime;
    j["nonce"]         = (int64)block.nNonce;
    j["bits"]          = strprintf("%08x", block.nBits);
    json tx = json::array();
    foreach(const CTransaction& t, block.vtx)
        tx.push_back(t.GetHash().GetHex());
    j["tx"] = tx;
    if (pindex->pprev)
        j["previousblockhash"] = pindex->pprev->GetBlockHash().GetHex();
    if (pindex->pnext)
        j["nextblockhash"] = pindex->pnext->GetBlockHash().GetHex();
    return j;
}

// ---------------------------------------------------------------------------
// methods

typedef json (*RpcMethod)(const json& params);

static json rpc_getinfo(const json&)
{
    json j;
    j["version"]         = BITFLASH_VERSION_STRING;
    j["protocolversion"] = VERSION;
    j["blocks"]          = nBestHeight;
    int nConnections = 0;
    CRITICAL_BLOCK(cs_vNodes)
        nConnections = (int)vNodes.size();
    j["connections"]     = nConnections;
    j["testnet"]         = IsTestNet();
    j["balance"]         = ValueFromAmount(GetBalance());
    j["walletlocked"]    = IsWalletLocked();
    return j;
}

static json rpc_getblockcount(const json&)
{
    return nBestHeight;
}

static json rpc_getblockhash(const json& p)
{
    if (p.size() < 1 || !p[0].is_number_integer())
        throw runtime_error("getblockhash <height>");
    int n = p[0].get<int>();
    if (n < 0 || n > nBestHeight)
        throw runtime_error("block height out of range");
    CBlockIndex* pindex = pindexBest;
    while (pindex && pindex->nHeight > n)
        pindex = pindex->pprev;
    if (!pindex)
        throw runtime_error("block not found");
    return pindex->GetBlockHash().GetHex();
}

static json rpc_getblock(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("getblock <hash>");
    CBlockIndex* pindex = BlockIndexOf(uint256(p[0].get<string>()));
    if (!pindex)
        throw runtime_error("block not found");
    return BlockToJson(pindex);
}

static json rpc_getnewaddress(const json&)
{
    // One fresh address per call: what an exchange wants is a unique deposit
    // address for each of its users.
    //
    // From the key pool, not GenerateNewKey(). The pool is derived from the HD
    // seed, so an address handed out here is covered by the recovery phrase;
    // GenerateNewKey() makes a random key outside the seed, and an exchange
    // that lost its wallet file would restore from the phrase and find every
    // deposit address it ever gave out missing. That is the difference between
    // an outage and a loss, and it is exactly what -newaddress already gets
    // right on the command line.
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
        throw runtime_error("could not draw a key from the wallet");
    return PubKeyToAddress(vchPubKey);
}

static json rpc_validateaddress(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("validateaddress <address>");
    string addr = p[0].get<string>();
    uint160 h;
    bool fScript = false;
    json j;
    bool fValid = DecodeAnyAddress(addr, h, fScript);
    j["isvalid"] = fValid;
    if (fValid)
    {
        j["address"] = addr;
        j["isscript"] = fScript;
        if (fScript)
        {
            CScript redeem;
            bool fHave = GetWalletCScript(h, redeem);
            j["ismine"] = fHave && IsMine(redeem);
            if (fHave)
            {
                json sub = ScriptToJson(redeem);
                j["script"] = sub["type"];
                j["hex"] = sub["hex"];
                if (sub.contains("addresses")) j["addresses"] = sub["addresses"];
                if (sub.contains("reqSigs")) j["sigsrequired"] = sub["reqSigs"];
            }
            j["active"] = RulesV3Active(GetAdjustedTime());
        }
        else
        {
            j["ismine"] = IsMineAddress(addr);
            // The public key, when it is ours: what the other parties of a
            // multisig need from this wallet, and nothing else hands out.
            CRITICAL_BLOCK(cs_mapKeys)
            {
                map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(h);
                if (mi != mapPubKeys.end())
                    j["pubkey"] = HexStr(mi->second.begin(), mi->second.end(), false);
            }
        }
    }
    return j;
}

// createmultisig <nrequired> ["key",...]: the redeem script and its address,
// nothing stored. addmultisigaddress does the same and keeps the script, so
// the wallet recognizes and can sign for outputs paid to it.
static json rpc_createmultisig(const json& p)
{
    CScript redeem = MultisigRedeemScript(p);
    json j;
    j["address"] = Hash160ToScriptAddress(Hash160(redeem));
    j["redeemScript"] = HexStr(redeem.begin(), redeem.end(), false);
    return j;
}

static json rpc_addmultisigaddress(const json& p)
{
    CScript redeem = MultisigRedeemScript(p);
    if (!AddCScript(redeem))
        throw runtime_error("could not store the redeem script in the wallet");
    string strAddr = Hash160ToScriptAddress(Hash160(redeem));
    if (p.size() >= 3 && p[2].is_string() && !p[2].get<string>().empty())
        SetAddressBookName(strAddr, p[2].get<string>());
    return strAddr;
}

static json rpc_decodescript(const json& p)
{
    if (p.size() < 1 || !p[0].is_string() || !IsHex(p[0].get<string>()))
        throw runtime_error("decodescript <hex>");
    vector<unsigned char> vch = ParseHex(p[0].get<string>());
    CScript script(vch.begin(), vch.end());
    json j = ScriptToJson(script);
    j["p2sh"] = Hash160ToScriptAddress(Hash160(script));
    return j;
}

static json rpc_getbalance(const json& p)
{
    // GetBalance() counts what the wallet would let you spend now, which
    // already excludes immature coinbase. minconf beyond that is filtered here.
    int nMinConf = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 1;
    if (nMinConf <= 1)
        return ValueFromAmount(GetBalance());

    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            if (!wtx.IsFinal() || wtx.GetDepthInMainChain() < nMinConf)
                continue;
            if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0)
                continue;
            nTotal += wtx.GetCredit() - wtx.GetDebit();
        }
    }
    return ValueFromAmount(nTotal);
}

// ---- invoices (invoice.h): the shop's own payment gateway ----

// createinvoice <amount> [description] [expiry seconds=3600] [order id]
static json rpc_createinvoice(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("createinvoice <amount> [description] [expiry seconds, default 3600] [order id]");
    string strDesc = p.size() >= 2 && p[1].is_string() ? p[1].get<string>() : string();
    int64 nExpiry = p.size() >= 3 && p[2].is_number_integer() ? p[2].get<int64>() : 3600;
    string strOrder = p.size() >= 4 && p[3].is_string() ? p[3].get<string>() : string();
    return invoice::Create(AmountFromValue(p[0]), strDesc, nExpiry, strOrder);
}

static json rpc_getinvoice(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("getinvoice <id>");
    return invoice::Get(p[0].get<string>());
}

// listinvoices [status]
static json rpc_listinvoices(const json& p)
{
    return invoice::List(p.size() >= 1 && p[0].is_string() ? p[0].get<string>() : string());
}

static json rpc_cancelinvoice(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("cancelinvoice <id>");
    return invoice::Cancel(p[0].get<string>());
}

// estimatefee -- BTF per 1000 bytes to be in the next block, from what is
// waiting now. 0: everything waiting fits, the minimum is enough.
static json rpc_estimatefee(const json&)
{
    int64 n = EstimateNextBlockFeePerKB();
    json j;
    j["feeRatePerKB"] = ValueFromAmount(n);
    j["minimumEnough"] = n == 0;
    CRITICAL_BLOCK(cs_mapTransactions)
        j["waiting"] = (int)mapTransactions.size();
    return j;
}

// settxfee <BTF per 1000 bytes> -- the rate this wallet pays; 0 is the minimum.
static json rpc_settxfee(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("settxfee <BTF per 1000 bytes>  (0: the minimum)");
    string s = p[0].is_string() ? p[0].get<string>() : strprintf("%.8f", p[0].get<double>());
    int64 n = 0;
    if (!ParseMoney(s.c_str(), n) || n < 0 || n > COIN)
        throw runtime_error("a rate from 0 to 1 BTF per 1000 bytes");
    nPayTxFeePerKB = n;
    CWalletDB().WriteSetting("nPayTxFeePerKB", nPayTxFeePerKB);
    return true;
}

// bumpfee <txid> [BTF per 1000 bytes] -- speed up a payment of ours that is
// still waiting: the same payment again, the extra fee from its change.
static json rpc_bumpfee(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("bumpfee <txid> [BTF per 1000 bytes]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    int64 nRate = 0;
    if (p.size() >= 2)
    {
        string s = p[1].is_string() ? p[1].get<string>() : strprintf("%.8f", p[1].get<double>());
        if (!ParseMoney(s.c_str(), nRate) || nRate <= 0 || nRate > COIN)
            throw runtime_error("a rate above 0 and up to 1 BTF per 1000 bytes");
    }
    else
        nRate = max(EstimateNextBlockFeePerKB(), nPayTxFeePerKB);
    uint256 newTxid;
    int64 nOld = 0, nNew = 0;
    string err;
    if (!BumpFee(uint256(p[0].get<string>()), nRate, newTxid, nOld, nNew, err))
        throw runtime_error(err);
    json j;
    j["txid"] = newTxid.GetHex();
    j["replaces"] = p[0];
    j["oldFee"] = ValueFromAmount(nOld);
    j["newFee"] = ValueFromAmount(nNew);
    return j;
}

static json rpc_sendtoaddress(const json& p)
{
    if (p.size() < 2 || !p[0].is_string())
        throw runtime_error("sendtoaddress <address> <amount>");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CScript scriptPubKey = ScriptForAddress(p[0].get<string>());
    int64 nValue = AmountFromValue(p[1]);
    CWalletTx wtx;
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    return wtx.GetHash().GetHex();
}

// sendburn <amount> <data hex>: burn `amount` into an OP_RETURN carrying the
// data -- provably unspendable, gone from the supply. What a public community
// listing is (community.h); 80 bytes of data at most, the relay limit.
static json rpc_sendburn(const json& p)
{
    if (p.size() < 2 || !p[1].is_string() || !IsHex(p[1].get<string>()))
        throw runtime_error("sendburn <amount> <data hex>");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    vector<unsigned char> data = ParseHex(p[1].get<string>());
    if (data.empty() || data.size() > MAX_OP_RETURN_RELAY)
        throw runtime_error(strprintf("the data is 1 to %u bytes", MAX_OP_RETURN_RELAY));
    CScript scriptPubKey;
    scriptPubKey << OP_RETURN << data;
    int64 nValue = AmountFromValue(p[0]);
    CWalletTx wtx;
    wtx.mapValue["comment"] = "Burned";
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    return wtx.GetHash().GetHex();
}

// donate <amount>: pay the treasury. Exactly sendtoaddress treasury <amount>,
// under the name people will look for.
static json rpc_donate(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("donate <amount>");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CScript scriptPubKey;
    if (!treasury::Script(scriptPubKey))
        throw runtime_error("there is no treasury on this network yet");
    int64 nValue = AmountFromValue(p[0]);
    CWalletTx wtx;
    wtx.mapValue["comment"] = "Donation to the Bitflash treasury";
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    return wtx.GetHash().GetHex();
}

// gettreasuryinfo: the script, its keys, and where to watch it.
static json rpc_gettreasuryinfo(const json&)
{
    json j;
    j["configured"] = treasury::Configured();
    j["network"] = IsTestNet() ? "testnet" : "mainnet";
    j["page"] = treasury::PAGE;
    if (!treasury::Configured())
        return j;
    CScript s;
    treasury::Script(s);
    j["required"] = treasury::REQUIRED;
    j["keys"] = treasury::Keys();
    j["script"] = ScriptToJson(s);
    j["howToPay"] = "sendtoaddress treasury <amount>, donate <amount>, or an output {\"treasury\": amount} in createrawtransaction";
    j["mining"] = "-treasuryshare=PCT (solo), -poolfeeto=treasury (pool operator)";
    j["treasuryShare"] = nTreasurySharePercent;
    j["poolFeeTo"] = fPoolFeeToTreasury ? "treasury" : "operator";
    return j;
}

static json rpc_gettransaction(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("gettransaction <txid>");
    uint256 hash(p[0].get<string>());
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator it = mapWallet.find(hash);
        if (it == mapWallet.end())
            throw runtime_error("transaction not in wallet");
        return WalletTxToJson(it->second);
    }
    throw runtime_error("transaction not in wallet");
}

static json rpc_listtransactions(const json& p)
{
    int nCount = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 10;
    if (nCount < 0) nCount = 0;

    // Newest last, like bitcoind: the caller reads the tail.
    vector<pair<int64, const CWalletTx*> > v;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
            v.push_back(make_pair((int64)it->second.nTimeReceived, &it->second));
        sort(v.begin(), v.end());
        json out = json::array();
        size_t nStart = v.size() > (size_t)nCount ? v.size() - nCount : 0;
        for (size_t i = nStart; i < v.size(); i++)
            out.push_back(WalletTxToJson(*v[i].second));
        return out;
    }
    return json::array();
}

static json rpc_listsinceblock(const json& p)
{
    // The call exchanges actually poll. Everything that touched the wallet in
    // blocks after the given one, plus everything still unconfirmed, and the
    // hash to pass next time. An empty or unknown hash means "everything".
    int nSinceHeight = -1;
    if (p.size() >= 1 && p[0].is_string() && !p[0].get<string>().empty())
    {
        CBlockIndex* pindex = BlockIndexOf(uint256(p[0].get<string>()));
        if (pindex && pindex->IsInMainChain())
            nSinceHeight = pindex->nHeight;
    }

    json txs = json::array();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            int nDepth = wtx.GetDepthInMainChain();
            int nHeight = nDepth > 0 ? nBestHeight - nDepth + 1 : -1;
            if (nDepth > 0 && nHeight <= nSinceHeight)
                continue;
            txs.push_back(WalletTxToJson(wtx));
        }
    }
    json j;
    j["transactions"] = txs;
    j["lastblock"]    = hashBestChain.GetHex();
    return j;
}

// ---------------------------------------------------------------------------
// raw transactions: what a multisig needs, since the two (or three) wallets
// that hold the keys pass one half-signed transaction between them

static json TxToJson(const CTransaction& tx)
{
    json j;
    j["txid"] = tx.GetHash().GetHex();
    j["version"] = tx.nVersion;
    j["locktime"] = tx.nLockTime;
    json vin = json::array();
    for (size_t i = 0; i < tx.vin.size(); i++)
    {
        const CTxIn& txin = tx.vin[i];
        json in;
        if (tx.IsCoinBase())
            in["coinbase"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end(), false);
        else
        {
            in["txid"] = txin.prevout.hash.GetHex();
            in["vout"] = txin.prevout.n;
            json ss;
            ss["asm"] = txin.scriptSig.ToString();
            ss["hex"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end(), false);
            in["scriptSig"] = ss;
        }
        in["sequence"] = txin.nSequence;
        vin.push_back(in);
    }
    j["vin"] = vin;
    json vout = json::array();
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        json out;
        out["value"] = ValueFromAmount(tx.vout[i].nValue);
        out["n"] = (int)i;
        out["scriptPubKey"] = ScriptToJson(tx.vout[i].scriptPubKey);
        vout.push_back(out);
    }
    j["vout"] = vout;
    CDataStream ss(SER_NETWORK);
    ss << tx;
    j["hex"] = HexStr(ss.begin(), ss.end(), false);
    return j;
}

static CTransaction TxFromHexParam(const json& v)
{
    if (!v.is_string() || !IsHex(v.get<string>()))
        throw runtime_error("expected a transaction in hex");
    vector<unsigned char> vch = ParseHex(v.get<string>());
    CDataStream ss(vch, SER_NETWORK);
    CTransaction tx;
    try { ss >> tx; }
    catch (std::exception&) { throw runtime_error("transaction does not decode"); }
    return tx;
}

// The transaction an outpoint refers to: memory pool, then the chain.
static bool LookupTransaction(const uint256& hash, CTransaction& txRet)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        map<uint256, CTransaction>::iterator mi = mapTransactions.find(hash);
        if (mi != mapTransactions.end())
        {
            txRet = mi->second;
            return true;
        }
    }
    CTxDB txdb("r");
    return txdb.ReadDiskTx(hash, txRet);
}

// listunspent [minconf=1] [maxconf=9999999] [["address",...]]
// The wallet marks spending per transaction (0.1.0), so an unspent wallet
// transaction's outputs that are ours are the unspent outputs.
static json rpc_listunspent(const json& p)
{
    int nMinDepth = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 1;
    int nMaxDepth = (p.size() >= 2 && p[1].is_number_integer()) ? p[1].get<int>() : 9999999;
    set<string> setFilter;
    if (p.size() >= 3 && p[2].is_array())
        for (size_t i = 0; i < p[2].size(); i++)
            if (p[2][i].is_string())
                setFilter.insert(p[2][i].get<string>());

    json out = json::array();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            if (wtx.fSpent || !wtx.IsFinal())
                continue;
            if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0)
                continue;
            int nDepth = wtx.GetDepthInMainChain();
            if (nDepth < nMinDepth || nDepth > nMaxDepth)
                continue;
            for (size_t n = 0; n < wtx.vout.size(); n++)
            {
                const CTxOut& txout = wtx.vout[n];
                if (!IsMine(txout.scriptPubKey))
                    continue;
                json sj = ScriptToJson(txout.scriptPubKey);
                string strAddr = sj.contains("address") ? sj["address"].get<string>() : "";
                if (!setFilter.empty() && !setFilter.count(strAddr))
                    continue;
                json o;
                o["txid"] = wtx.GetHash().GetHex();
                o["vout"] = (int)n;
                if (!strAddr.empty())
                    o["address"] = strAddr;
                o["scriptPubKey"] = HexStr(txout.scriptPubKey.begin(), txout.scriptPubKey.end(), false);
                if (txout.scriptPubKey.IsPayToScriptHash())
                {
                    CScript redeem;
                    if (GetWalletCScript(uint160(vector<unsigned char>(txout.scriptPubKey.begin() + 2, txout.scriptPubKey.begin() + 22)), redeem))
                        o["redeemScript"] = HexStr(redeem.begin(), redeem.end(), false);
                }
                o["amount"] = ValueFromAmount(txout.nValue);
                o["confirmations"] = nDepth;
                out.push_back(o);
            }
        }
    }
    return out;
}

// createrawtransaction [{"txid":h,"vout":n},...] {"address":amount,...}
// An output key may also be "script:<hex>" for a script that has no address
// form -- a bare multisig, which is what works before the rules v3 switch.
static json rpc_createrawtransaction(const json& p)
{
    if (p.size() < 2 || !p[0].is_array() || !p[1].is_object())
        throw runtime_error("createrawtransaction [{\"txid\":txid,\"vout\":n},...] {address:amount,...}");
    CTransaction tx;
    for (size_t i = 0; i < p[0].size(); i++)
    {
        const json& in = p[0][i];
        if (!in.is_object() || !in.contains("txid") || !in["txid"].is_string() ||
            !in.contains("vout") || !in["vout"].is_number_integer())
            throw runtime_error("each input needs txid and vout");
        int nOut = in["vout"].get<int>();
        if (nOut < 0)
            throw runtime_error("vout must be positive");
        tx.vin.push_back(CTxIn(COutPoint(uint256(in["txid"].get<string>()), nOut)));
    }
    set<string> setSeen;
    for (json::const_iterator it = p[1].begin(); it != p[1].end(); ++it)
    {
        string strKey = it.key();
        if (setSeen.count(strKey))
            throw runtime_error("duplicated output: " + strKey);
        setSeen.insert(strKey);
        CScript scriptPubKey;
        if (strKey.compare(0, 5, "data:") == 0)
        {
            // A burn: OP_RETURN <data>. The amount is what is destroyed.
            string strHex = strKey.substr(5);
            if (!IsHex(strHex) && !strHex.empty())
                throw runtime_error("data: must be followed by hex");
            vector<unsigned char> vch = ParseHex(strHex);
            if (vch.size() > MAX_OP_RETURN_RELAY)
                throw runtime_error(strprintf("data: at most %u bytes", MAX_OP_RETURN_RELAY));
            scriptPubKey << OP_RETURN;
            if (!vch.empty())
                scriptPubKey << vch;
            int64 nBurn = AmountFromValue(it.value());
            if (nBurn < 0)
                throw runtime_error("amount must not be negative");
            tx.vout.push_back(CTxOut(nBurn, scriptPubKey));
            continue;
        }
        if (strKey.compare(0, 7, "script:") == 0)
        {
            string strHex = strKey.substr(7);
            if (!IsHex(strHex))
                throw runtime_error("script: must be followed by hex");
            vector<unsigned char> vch = ParseHex(strHex);
            scriptPubKey = CScript(vch.begin(), vch.end());
            if (scriptPubKey.IsPayToScriptHash() && !RulesV3Active(GetAdjustedTime()))
                throw runtime_error("pay-to-script-hash outputs are not active on this network yet");
        }
        else
            scriptPubKey = ScriptForAddress(strKey);
        int64 nValue = AmountFromValue(it.value());
        if (nValue <= 0)
            throw runtime_error("amount must be positive");
        tx.vout.push_back(CTxOut(nValue, scriptPubKey));
    }
    if (tx.vin.empty() || tx.vout.empty())
        throw runtime_error("a transaction needs at least one input and one output");
    CDataStream ss(SER_NETWORK);
    ss << tx;
    return HexStr(ss.begin(), ss.end(), false);
}

static json rpc_decoderawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("decoderawtransaction <hex>");
    return TxToJson(TxFromHexParam(p[0]));
}

static json rpc_getrawtransaction(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("getrawtransaction <txid> [verbose=0]");
    CTransaction tx;
    if (!LookupTransaction(uint256(p[0].get<string>()), tx))
        throw runtime_error("transaction not found (not in the memory pool and not in the chain)");
    json j = TxToJson(tx);
    bool fVerbose = p.size() >= 2 && ((p[1].is_boolean() && p[1].get<bool>()) || (p[1].is_number_integer() && p[1].get<int>() != 0));
    return fVerbose ? j : j["hex"];
}

// A key handed to signrawtransaction lives in the wallet's key map only for
// the duration of the call, and is never written anywhere.
struct CTemporaryKeys
{
    vector<vector<unsigned char> > vPubKeys;
    ~CTemporaryKeys()
    {
        CRITICAL_BLOCK(cs_mapKeys)
            for (size_t i = 0; i < vPubKeys.size(); i++)
            {
                mapKeys.erase(vPubKeys[i]);
                mapPubKeys.erase(Hash160(vPubKeys[i]));
            }
    }
};

// signrawtransaction <hex> [[{"txid","vout","scriptPubKey","redeemScript"},...]] [["privkey-hex",...]]
// Signs what this wallet's keys (plus any given) can sign, keeps what is
// already signed, and says whether every input now verifies.
static json rpc_signrawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("signrawtransaction <hex> [prevtxs] [privkeys]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CTransaction tx = TxFromHexParam(p[0]);

    // Previous outputs: given, else looked up
    map<COutPoint, CScript> mapPrevOut;
    map<uint160, CScript> mapRedeem;
    if (p.size() >= 2 && p[1].is_array())
    {
        for (size_t i = 0; i < p[1].size(); i++)
        {
            const json& pv = p[1][i];
            if (!pv.is_object() || !pv.contains("txid") || !pv.contains("vout") || !pv.contains("scriptPubKey"))
                throw runtime_error("each prevtx needs txid, vout and scriptPubKey");
            vector<unsigned char> vch = ParseHex(pv["scriptPubKey"].get<string>());
            mapPrevOut[COutPoint(uint256(pv["txid"].get<string>()), pv["vout"].get<int>())] = CScript(vch.begin(), vch.end());
            if (pv.contains("redeemScript") && pv["redeemScript"].is_string())
            {
                vector<unsigned char> r = ParseHex(pv["redeemScript"].get<string>());
                CScript redeem(r.begin(), r.end());
                mapRedeem[Hash160(redeem)] = redeem;
            }
        }
    }
    CTemporaryKeys tempKeys;
    if (p.size() >= 3 && p[2].is_array())
    {
        for (size_t i = 0; i < p[2].size(); i++)
        {
            if (!p[2][i].is_string() || !IsHex(p[2][i].get<string>()))
                throw runtime_error("private keys are given as 64 hex characters");
            CKey key;
            if (!key.SetSecret(ParseHex(p[2][i].get<string>())))
                throw runtime_error("invalid private key");
            vector<unsigned char> vchPubKey = key.GetPubKey();
            CRITICAL_BLOCK(cs_mapKeys)
            {
                if (!mapKeys.count(vchPubKey))
                {
                    mapKeys[vchPubKey] = key.GetPrivKey();
                    mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
                    tempKeys.vPubKeys.push_back(vchPubKey);
                }
            }
        }
    }
    // Redeem scripts named by the caller are usable for this call
    for (map<uint160, CScript>::iterator it = mapRedeem.begin(); it != mapRedeem.end(); ++it)
        CRITICAL_BLOCK(cs_mapKeys)
            if (!mapScripts.count(it->first))
                mapScripts[it->first] = it->second;

    bool fComplete = true;
    json errors = json::array();
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CTxIn& txin = tx.vin[i];
        CScript scriptPubKey;
        map<COutPoint, CScript>::iterator mi = mapPrevOut.find(txin.prevout);
        if (mi != mapPrevOut.end())
            scriptPubKey = mi->second;
        else
        {
            CTransaction txPrev;
            if (!LookupTransaction(txin.prevout.hash, txPrev) || txin.prevout.n >= txPrev.vout.size())
            {
                json e; e["vout"] = (int)i; e["error"] = "previous output not found; give it in prevtxs";
                errors.push_back(e);
                fComplete = false;
                continue;
            }
            scriptPubKey = txPrev.vout[txin.prevout.n].scriptPubKey;
        }

        // Sign afresh into a scratch transaction, then merge with what the
        // input already carried
        CScript scriptSigOld = txin.scriptSig;
        CTransaction txScratch = tx;
        txScratch.vin[i].scriptSig.clear();
        CTransaction txFrom;
        txFrom.vout.resize(txin.prevout.n + 1);
        txFrom.vout[txin.prevout.n].scriptPubKey = scriptPubKey;
        // SignSignature checks prevout.hash against txFrom's hash only through
        // VerifySignature; here the outpoint is trusted as given
        CScript scriptSigNew;
        {
            CTransaction txForSig = txScratch;
            uint256 hash;
            if (scriptPubKey.IsPayToScriptHash())
            {
                CScript subscript;
                if (GetWalletCScript(uint160(vector<unsigned char>(scriptPubKey.begin() + 2, scriptPubKey.begin() + 22)), subscript))
                {
                    hash = SignatureHash(subscript, txForSig, i, SIGHASH_ALL);
                    CScript inner;
                    Solver(subscript, hash, SIGHASH_ALL, inner);
                    // merge inner parts (multisig) before appending the script
                    CScript innerOld;
                    {
                        vector<vector<unsigned char> > pushes;
                        CScript::const_iterator pc = scriptSigOld.begin();
                        opcodetype opcode; vector<unsigned char> vch;
                        while (pc < scriptSigOld.end() && scriptSigOld.GetOp(pc, opcode, vch))
                            pushes.push_back(vch);
                        for (size_t k = 0; k + 1 < pushes.size(); k++)
                            innerOld << pushes[k];
                    }
                    CScript merged = CombineMultisig(subscript, txForSig, i, innerOld, inner);
                    scriptSigNew = merged;
                    scriptSigNew << static_cast<vector<unsigned char> >(subscript);
                }
                else
                    scriptSigNew = scriptSigOld;
            }
            else
            {
                hash = SignatureHash(scriptPubKey, txForSig, i, SIGHASH_ALL);
                CScript fresh;
                Solver(scriptPubKey, hash, SIGHASH_ALL, fresh);
                txnouttype whichType;
                vector<vector<unsigned char> > vSolutions;
                if (SolverTyped(scriptPubKey, whichType, vSolutions) && whichType == TX_MULTISIG)
                    scriptSigNew = CombineMultisig(scriptPubKey, txForSig, i, scriptSigOld, fresh);
                else
                    scriptSigNew = fresh.empty() ? scriptSigOld : fresh;
            }
        }
        txin.scriptSig = scriptSigNew;
        // Under the rules a block made now would be checked by, so a lock
        // script (CLTV, CSV, CTV) counts as complete once it is.
        unsigned int nNow = (unsigned int)GetAdjustedTime();
        if (!VerifyScriptP2SH(txin.scriptSig, scriptPubKey, tx, i, RulesV2Active(nNow), RulesV3Active(nNow),
                              RulesV4Active(nNow)))
        {
            fComplete = false;
            json e; e["vout"] = (int)i; e["error"] = "input does not verify yet (more signatures needed, or keys not held)";
            errors.push_back(e);
        }
    }

    // Forget the caller's redeem scripts again unless the wallet had them
    for (map<uint160, CScript>::iterator it = mapRedeem.begin(); it != mapRedeem.end(); ++it)
        CRITICAL_BLOCK(cs_mapKeys)
            if (mapScripts.count(it->first) && !HaveCScript(it->first))
                mapScripts.erase(it->first);

    CDataStream ss(SER_NETWORK);
    ss << tx;
    json j;
    j["hex"] = HexStr(ss.begin(), ss.end(), false);
    j["complete"] = fComplete;
    if (!errors.empty())
        j["errors"] = errors;
    return j;
}

static json rpc_sendrawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("sendrawtransaction <hex>");
    CTransaction tx = TxFromHexParam(p[0]);
    uint256 hash = tx.GetHash();
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    CRITICAL_BLOCK(cs_main)
    {
        CTransaction txHave;
        bool fHave = LookupTransaction(hash, txHave);
        if (!fHave)
        {
            bool fMissingInputs = false;
            if (!tx.AcceptTransaction(true, &fMissingInputs))
                throw runtime_error(fMissingInputs ? "transaction rejected: missing inputs"
                                                   : "transaction rejected (invalid, non-standard, or already spent inputs)");
            AddToWalletIfMine(tx, NULL);
        }
        RelayMessage(CInv(MSG_TX, hash), ssTx);
    }
    return hash.GetHex();
}

// Tor as the node sees it: transport in use, Tor's own bootstrap, the
// rungs the ladder still has, what worked last time. For the operator on a
// blocked network who has only a terminal.
static json rpc_gettorinfo(const json&)
{
    json j;
    j["managed"]   = BtfManagedTorEnabled();
    j["status"]    = BtfManagedTorStatus();
    j["transport"] = BtfTorTransportMode();
    int pct = BtfManagedTorBootstrapPercent();
    j["bootstrap"] = pct < 0 ? json(nullptr) : json(pct);
    j["bootstrapline"] = BtfManagedTorBootstrapLine();
    j["autobridges"] = nTorBridgeFallbackSecs > 0;
    j["fallbacksecs"] = nTorBridgeFallbackSecs;
    j["rungsecs"]  = nTorBridgeRungSecs;
    json rungs = json::array();
    std::vector<BtfBridgeRung> v = BtfBundledBridgeRungs();
    for (size_t i = 0; i < v.size(); i++)
    {
        json r;
        r["name"] = v[i].name;
        r["lines"] = (int)v[i].lines.size();
        rungs.push_back(r);
    }
    j["ladder"] = rungs;
    j["userbridges"] = (int)BtfLoadUserBridges().size();
    j["userbridgesfile"] = BtfUserBridgesPath();
    std::string last = BtfLastWorkingTransport();
    j["lastworking"] = last.empty() ? json(nullptr) : json(last);
    int nConnections = 0;
    CRITICAL_BLOCK(cs_vNodes)
        nConnections = (int)vNodes.size();
    j["connections"] = nConnections;
    return j;
}

// settorbridges ["line", ...]   -- save to bridges.txt and switch Tor to
// them now; [] clears the file. settorbridges "now" -- climb to the next
// bundled rung right away instead of waiting for the watchdog.
static json rpc_settorbridges(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("settorbridges [\"bridge line\", ...] | \"now\" | \"forget\"");
    std::string err;
    json j;
    if (p[0].is_string() && p[0].get<std::string>() == "forget")
    {
        BtfForgetLastWorkingTransport();
        j["forgotten"] = true;
        return j;
    }
    if (p[0].is_array())
    {
        std::string text;
        for (size_t i = 0; i < p[0].size(); i++)
        {
            if (!p[0][i].is_string())
                throw runtime_error("bridge lines must be strings");
            text += p[0][i].get<std::string>() + "\n";
        }
        if (!BtfSaveUserBridges(text, err))
            throw runtime_error(err);
        j["saved"] = (int)BtfParseBridgeLines(text).size();
        if (j["saved"].get<int>() == 0)
        {
            j["switched"] = false;
            return j;
        }
    }
    else if (!(p[0].is_string() && p[0].get<std::string>() == "now"))
        throw runtime_error("settorbridges [\"bridge line\", ...] | \"now\" | \"forget\"");
    if (!BtfTryBridgesNow(err))
        throw runtime_error(err);
    j["switched"] = true;
    j["transport"] = BtfTorTransportMode();
    return j;
}

// ---------------------------------------------------------------------------
// Atomic swaps (swap.h). Named after Decred's atomicswap commands, so the steps
// on the Bitflash side read the same as the steps on the Bitcoin side.

static vector<unsigned char> PkhOfAddress(const string& strAddr)
{
    uint160 h;
    bool fScript = false;
    if (!DecodeAnyAddress(strAddr, h, fScript) || fScript)
        throw runtime_error("need an ordinary Bitflash address (B...), not a script address");
    return vector<unsigned char>(h.begin(), h.end());
}

static void RequireSwapsOpen()
{
    // Swaps wait for rules v3: before the switch a script-hash output is
    // anyone-can-spend, and a contract funded then could be taken by anybody
    // who read it off the chain. On mainnet they also wait for their launch
    // day, after the rules (consensus.h, SWAPS_OPEN_TIME_MAINNET). The
    // Bitcoin half waits too, so nobody locks bitcoin into a swap whose
    // Bitflash half cannot be made.
    if (!SwapsOpen(GetAdjustedTime()))
    {
        if (SwapsOpenTime() == 0)
            throw runtime_error("atomic swaps need rules v3, which are not scheduled on this network");
        time_t t = (time_t)SwapsOpenTime();
        char buf[32] = "";
        struct tm* g = gmtime(&t);
        if (g)
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", g);
        throw runtime_error(strprintf("atomic swaps open at %s UTC (time %u); not before",
                                      buf, SwapsOpenTime()));
    }
}

static json ContractJson(const swap::Contract& c, const CScript& contract)
{
    json j;
    j["contract"]        = HexStr(contract.begin(), contract.end(), false);
    j["contractAddress"] = Hash160ToScriptAddress(Hash160(contract));
    j["recipient"]       = Hash160ToAddress(uint160(c.recipientPkh));
    j["refundAddress"]   = Hash160ToAddress(uint160(c.refundPkh));
    j["secretHash"]      = HexStr(c.secretHash.begin(), c.secretHash.end(), false);
    j["lockTime"]        = c.nLockTime;
    if (c.nLockTime < (int64)LOCKTIME_THRESHOLD)
        j["blocksUntilRefund"] = std::max<int64>(0, c.nLockTime - nBestHeight);
    return j;
}

// The lock, in blocks from now: the standard one, or on testnet only a shorter
// one given as the last parameter -- so a refund can be tried in minutes, not a
// day. On mainnet a short lock is how a participant loses their coins (the
// initiator waits it out, refunds, and redeems the other side), so there it
// is not even accepted.
static int LockBlocksParam(const json& p, size_t nIndex, int nDefault)
{
    if (p.size() <= nIndex)
        return nDefault;
    if (!IsTestNet())
        throw runtime_error("the lock length is fixed on mainnet");
    if (!p[nIndex].is_number_integer() || p[nIndex].get<int>() < 1 || p[nIndex].get<int>() > nDefault)
        throw runtime_error(strprintf("lock blocks: 1 to %d", nDefault));
    return p[nIndex].get<int>();
}

// Fund a contract from this wallet and say where it went.
static json FundContract(const swap::Contract& c, int64 nValue, const char* pszComment)
{
    CScript contract = swap::BuildContract(c);
    CScript scriptPubKey;
    scriptPubKey.SetPayToScriptHash(contract);
    CWalletTx wtx;
    wtx.mapValue["comment"] = pszComment;
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    json j = ContractJson(c, contract);
    j["contractTxid"] = wtx.GetHash().GetHex();
    j["amount"] = ValueFromAmount(nValue);
    return j;
}

// A line per swap in the data directory: the secret is the one thing that,
// lost, cannot be recovered -- and an RPC answer scrolls away.
static void LogSwap(const json& j)
{
    string path = GetAppDir() + "/swaps.log";
    FILE* f = fopen(path.c_str(), "a");
    if (!f)
        return;
    json line = j;
    line["time"] = (int64)GetTime();
    fprintf(f, "%s\n", line.dump().c_str());
    fclose(f);
}

// swapinitiate <participant address> <amount>
static json rpc_swapinitiate(const json& p)
{
    if (p.size() < 2 || !p[0].is_string())
        throw runtime_error("swapinitiate <participant address> <amount> [lock blocks, testnet only]");
    RequireSwapsOpen();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");

    swap::Contract c;
    c.recipientPkh = PkhOfAddress(p[0].get<string>());
    vector<unsigned char> vchRefund = GetKeyFromPool();
    if (vchRefund.empty())
        throw runtime_error("could not draw a key from the wallet");
    uint160 hRefund = Hash160(vchRefund);
    c.refundPkh.assign(hRefund.begin(), hRefund.end());

    vector<unsigned char> secret(swap::SECRET_BYTES);
    RAND_bytes(&secret[0], (int)secret.size());
    c.secretHash.resize(32);
    SHA256(&secret[0], secret.size(), &c.secretHash[0]);
    c.nLockTime = nBestHeight + LockBlocksParam(p, 2, swap::INITIATOR_LOCK_BLOCKS);

    json j = FundContract(c, AmountFromValue(p[1]), "Atomic swap: initiated");
    j["secret"] = HexStr(secret.begin(), secret.end(), false);
    j["role"] = "initiator";
    LogSwap(j);
    OPENSSL_cleanse(&secret[0], secret.size());
    return j;
}

// swapparticipate <initiator address> <amount> <secret hash>
static json rpc_swapparticipate(const json& p)
{
    if (p.size() < 3 || !p[0].is_string() || !p[2].is_string())
        throw runtime_error("swapparticipate <initiator address> <amount> <secret hash> [lock blocks, testnet only]");
    RequireSwapsOpen();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");

    swap::Contract c;
    c.recipientPkh = PkhOfAddress(p[0].get<string>());
    string strHash = p[2].get<string>();
    if (strHash.size() != 64 || !IsHex(strHash))
        throw runtime_error("the secret hash is 64 hex characters");
    c.secretHash = ParseHex(strHash);
    vector<unsigned char> vchRefund = GetKeyFromPool();
    if (vchRefund.empty())
        throw runtime_error("could not draw a key from the wallet");
    uint160 hRefund = Hash160(vchRefund);
    c.refundPkh.assign(hRefund.begin(), hRefund.end());
    c.nLockTime = nBestHeight + LockBlocksParam(p, 3, swap::PARTICIPANT_LOCK_BLOCKS);

    json j = FundContract(c, AmountFromValue(p[1]), "Atomic swap: participated");
    j["role"] = "participant";
    LogSwap(j);
    return j;
}

static swap::Contract ContractFromParam(const json& v, CScript& contractOut)
{
    if (!v.is_string() || !IsHex(v.get<string>()))
        throw runtime_error("the contract is given as hex");
    vector<unsigned char> vch = ParseHex(v.get<string>());
    contractOut = CScript(vch.begin(), vch.end());
    swap::Contract c;
    if (!swap::ParseContract(contractOut, c))
        throw runtime_error("that is not an atomic swap contract");
    return c;
}

// The output of txid that pays the contract, or an error saying why not.
static void FindContractOutput(const CScript& contract, const uint256& txid,
                               CTransaction& txOut, unsigned int& nOut)
{
    if (!LookupTransaction(txid, txOut))
        throw runtime_error("contract transaction not found (not in the memory pool and not in the chain)");
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);
    for (nOut = 0; nOut < txOut.vout.size(); nOut++)
        if (txOut.vout[nOut].scriptPubKey == p2sh)
            return;
    throw runtime_error("that transaction does not pay this contract");
}

// Blocks on top of (and including) the one holding txid in the main chain;
// 0 when it is only in the memory pool or nowhere.
static int ChainConfirmations(const uint256& txid)
{
    CTxIndex txindex;
    if (!CTxDB("r").ReadTxIndex(txid, txindex))
        return 0;
    CBlock block;
    if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
        return 0;
    int nDepth = 0;
    CRITICAL_BLOCK(cs_main)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
        if (mi != mapBlockIndex.end() && mi->second->IsInMainChain())
            nDepth = 1 + nBestHeight - mi->second->nHeight;
    }
    return nDepth;
}

// swapauditcontract <contract> <contract txid>
static json rpc_swapauditcontract(const json& p)
{
    if (p.size() < 2 || !p[1].is_string())
        throw runtime_error("swapauditcontract <contract hex> <contract txid>");
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    CTransaction tx;
    unsigned int n = 0;
    FindContractOutput(contract, uint256(p[1].get<string>()), tx, n);
    json j = ContractJson(c, contract);
    j["contractTxid"] = tx.GetHash().GetHex();
    j["vout"] = (int)n;
    j["amount"] = ValueFromAmount(tx.vout[n].nValue);
    // The other side's contract is not a wallet transaction: count its
    // confirmations from the block the transaction index puts it in.
    j["confirmations"] = ChainConfirmations(tx.GetHash());
    CTxIndex txindex;
    j["unspent"] = CTxDB("r").ReadTxIndex(tx.GetHash(), txindex) && n < txindex.vSpent.size() &&
                   txindex.vSpent[n].IsNull();
    // What a participant must check before locking anything of theirs: that
    // the coins are to THEIR address and that the lock leaves them time.
    j["recipientIsMine"] = IsMineAddress(Hash160ToAddress(uint160(c.recipientPkh)));
    return j;
}

// The key a contract pays to on the path we take: the recipient's to redeem,
// the refund key to refund. The same wallet keys sign on either chain.
static void KeyForContract(const swap::Contract& c, bool fRedeem, CKey& key, vector<unsigned char>& vchPubKey)
{
    const vector<unsigned char>& pkh = fRedeem ? c.recipientPkh : c.refundPkh;
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(uint160(pkh));
        if (mi == mapPubKeys.end() || !mapKeys.count(mi->second))
            throw runtime_error(fRedeem ? "this wallet does not hold the recipient key of that contract"
                                        : "this wallet does not hold the refund key of that contract");
        vchPubKey = mi->second;
        key.SetPrivKey(mapKeys[vchPubKey]);
    }
}

extern map<COutPoint, CInPoint> mapNextTx;   // main.cpp: memory-pool spends

// Already spent, in the memory pool or in the chain?
static bool OutputSpent(const COutPoint& outpoint)
{
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapNextTx.count(outpoint))
            return true;
    CTxIndex txindex;
    return CTxDB("r").ReadTxIndex(outpoint.hash, txindex) && outpoint.n < txindex.vSpent.size() &&
           !txindex.vSpent[outpoint.n].IsNull();
}

// Spend a contract output: redeem with the secret, or refund after the lock.
static json SpendContract(const CScript& contract, const swap::Contract& c, const uint256& txid,
                          const vector<unsigned char>* pSecret)
{
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CTransaction txFrom;
    unsigned int nOut = 0;
    FindContractOutput(contract, txid, txFrom, nOut);
    if (OutputSpent(COutPoint(txFrom.GetHash(), nOut)))
        throw runtime_error("that contract is already spent (redeemed or refunded)");

    vector<unsigned char> vchPubKey;
    CKey key;
    KeyForContract(c, pSecret != NULL, key, vchPubKey);

    if (!pSecret)
    {
        if (c.nLockTime < (int64)LOCKTIME_THRESHOLD && nBestHeight + 1 <= c.nLockTime)
            throw runtime_error(strprintf("the refund opens at block %lld; the chain is at %d",
                                          (long long)c.nLockTime + 1, nBestHeight));
        if (c.nLockTime >= (int64)LOCKTIME_THRESHOLD && pindexBest &&
            pindexBest->GetMedianTimePast() <= c.nLockTime)
            throw runtime_error("the refund lock time has not passed yet");
    }

    vector<unsigned char> vchTo = GetKeyFromPool();
    if (vchTo.empty())
        throw runtime_error("could not draw a key from the wallet");
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(txFrom.GetHash(), nOut);
    if (!pSecret)
    {
        // CHECKLOCKTIMEVERIFY wants the lock in nLockTime and an input that
        // does not switch nLockTime off.
        tx.nLockTime = (unsigned int)c.nLockTime;
        tx.vin[0].nSequence = 0;
    }
    CScript scriptTo;
    scriptTo << OP_DUP << OP_HASH160 << Hash160(vchTo) << OP_EQUALVERIFY << OP_CHECKSIG;
    int64 nIn = txFrom.vout[nOut].nValue;
    int64 nFee = CENT;
    for (int nPass = 0; nPass < 2; nPass++)
    {
        if (nIn <= nFee)
            throw runtime_error("the contract holds less than the fee to spend it");
        tx.vout.assign(1, CTxOut(nIn - nFee, scriptTo));
        tx.vin[0].scriptSig = CScript();
        uint256 hash = SignatureHash(contract, tx, 0, SIGHASH_ALL);
        vector<unsigned char> sig;
        if (!key.Sign(hash, sig))
            throw runtime_error("signing failed");
        sig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[0].scriptSig = pSecret ? swap::RedeemScriptSig(sig, vchPubKey, *pSecret, contract)
                                      : swap::RefundScriptSig(sig, vchPubKey, contract);
        int64 nNeed = tx.GetMinFee();
        if (nNeed <= nFee)
            break;
        nFee = nNeed;
    }
    if (!VerifySignature(txFrom, tx, 0, 0, true, true))
        throw runtime_error(pSecret ? "the redeem does not verify -- is that the right secret?"
                                    : "the refund does not verify");

    uint256 hash = tx.GetHash();
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    CRITICAL_BLOCK(cs_main)
    {
        bool fMissingInputs = false;
        if (!tx.AcceptTransaction(true, &fMissingInputs))
            throw runtime_error(fMissingInputs ? "the contract output is not known to this node yet"
                                               : "the network refused it (already spent?)");
        AddToWalletIfMine(tx, NULL);
        RelayMessage(CInv(MSG_TX, hash), ssTx);
    }
    json j;
    j["txid"] = hash.GetHex();
    j["amount"] = ValueFromAmount(nIn - nFee);
    j["fee"] = ValueFromAmount(nFee);
    j["to"] = PubKeyToAddress(vchTo);
    return j;
}

// ---- scripts of rules v4, by hand (docs/rules-v4.md) -----------------------
//
// Two tools for contracts the wallet has no button for yet: the template hash
// OP_CHECKTEMPLATEVERIFY will compare with, and the spend of a P2SH output by
// any redeem script, with the version, sequence and lock time the script
// needs. What the wallet signs is only ever what is asked: "sig:<pubkey>".

// The outputs of an {address: amount} object, in address order (the order
// the JSON object keeps), the same for templatehash and spendscript.
static vector<CTxOut> OutputsFromParam(const json& o)
{
    if (!o.is_object() || o.empty())
        throw runtime_error("outputs: {\"address\": amount, ...}");
    vector<CTxOut> v;
    for (json::const_iterator it = o.begin(); it != o.end(); ++it)
        v.push_back(CTxOut(AmountFromValue(it.value()), ScriptForAddress(it.key())));
    return v;
}

static unsigned int UIntParam(const json& p, size_t i, unsigned int nDefault)
{
    if (p.size() <= i || p[i].is_null())
        return nDefault;
    if (!p[i].is_number_integer() || p[i].get<int64>() < 0 || p[i].get<int64>() > 0xffffffffLL)
        throw runtime_error(strprintf("parameter %u is not a 32-bit unsigned number", (unsigned)i + 1));
    return (unsigned int)p[i].get<int64>();
}

// templatehash {outputs} [version=2] [sequence=0xffffffff] [locktime=0]
// The hash of a one-input transaction with these fields, for input 0.
static json rpc_templatehash(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("templatehash {\"address\": amount, ...} [version=2] [sequence] [locktime]");
    CTransaction tx;
    tx.nVersion = (int)UIntParam(p, 1, 2);
    tx.vin.resize(1);
    tx.vin[0].nSequence = UIntParam(p, 2, 0xffffffff);
    tx.nLockTime = UIntParam(p, 3, 0);
    tx.vout = OutputsFromParam(p[0]);
    uint256 h = CheckTemplateHash(tx, 0);
    json j;
    j["hash"] = HexStr(h.begin(), h.end(), false);
    return j;
}

// spendscript <redeem hex> <txid> [stack items] {outputs} [version] [sequence] [locktime]
// Stack items, bottom first: hex data, true, false, or sig:<pubkey hex> for a
// SIGHASH_ALL signature by a key this wallet holds. The redeem script goes on
// top. What the outputs leave over is the fee.
static json rpc_spendscript(const json& p)
{
    if (p.size() < 4 || !p[0].is_string() || !p[1].is_string() || !p[2].is_array())
        throw runtime_error("spendscript <redeem hex> <txid> [\"sig:<pubkey>\" | true | false | <hex>, ...] "
                            "{\"address\": amount} [version=2] [sequence=0xffffffff] [locktime=0] [maxfee=1]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    if (!IsHex(p[0].get<string>()))
        throw runtime_error("the redeem script is not hex");
    vector<unsigned char> vchRedeem = ParseHex(p[0].get<string>());
    CScript redeem(vchRedeem.begin(), vchRedeem.end());
    uint256 txid;
    txid.SetHex(p[1].get<string>());
    CTransaction txFrom;
    unsigned int nOut = 0;
    FindContractOutput(redeem, txid, txFrom, nOut);
    if (OutputSpent(COutPoint(txFrom.GetHash(), nOut)))
        throw runtime_error("that output is already spent");

    CTransaction tx;
    tx.nVersion = (int)UIntParam(p, 4, 2);
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(txFrom.GetHash(), nOut);
    tx.vin[0].nSequence = UIntParam(p, 5, 0xffffffff);
    tx.nLockTime = UIntParam(p, 6, 0);
    tx.vout = OutputsFromParam(p[3]);
    int64 nIn = txFrom.vout[nOut].nValue, nOutTotal = tx.GetValueOut();
    if (nOutTotal >= nIn)
        throw runtime_error("the outputs leave nothing for the fee");
    // There is no change here: whatever the outputs leave over goes to the
    // miner. A typo in an amount must not give a contract away.
    int64 nMaxFee = (p.size() > 7 && !p[7].is_null()) ? AmountFromValue(p[7]) : COIN;
    if (nIn - nOutTotal > nMaxFee)
        throw runtime_error(strprintf("the outputs leave %s for the fee, over maxfee %s; pay the rest somewhere, or raise maxfee",
                                      FormatMoney(nIn - nOutTotal).c_str(), FormatMoney(nMaxFee).c_str()));

    // Signatures commit to everything but the scriptSigs, so build those last.
    CScript scriptSig;
    uint256 hashSig = SignatureHash(redeem, tx, 0, SIGHASH_ALL);
    foreach(const json& item, p[2])
    {
        if (item.is_boolean())
        {
            scriptSig << (item.get<bool>() ? OP_TRUE : OP_FALSE);
            continue;
        }
        if (!item.is_string())
            throw runtime_error("a stack item is hex, true, false or sig:<pubkey>");
        string s = item.get<string>();
        if (s.compare(0, 4, "sig:") == 0)
        {
            vector<unsigned char> vchPubKey = ParseHex(s.substr(4));
            CKey key;
            CRITICAL_BLOCK(cs_mapKeys)
            {
                if (!mapKeys.count(vchPubKey))
                    throw runtime_error("this wallet does not hold the key " + s.substr(4));
                key.SetPrivKey(mapKeys[vchPubKey]);
            }
            vector<unsigned char> sig;
            if (!key.Sign(hashSig, sig))
                throw runtime_error("signing failed");
            sig.push_back((unsigned char)SIGHASH_ALL);
            scriptSig << sig;
        }
        else if (IsHex(s))
            scriptSig << ParseHex(s);
        else
            throw runtime_error("a stack item is hex, true, false or sig:<pubkey>");
    }
    scriptSig << vchRedeem;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int nNow = (unsigned int)GetAdjustedTime();
    if (!VerifySignature(txFrom, tx, 0, 0, true, RulesV3Active(nNow), RulesV4Active(nNow)))
        throw runtime_error("the spend does not verify under the rules now in force");

    uint256 hash = tx.GetHash();
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    CRITICAL_BLOCK(cs_main)
    {
        bool fMissingInputs = false;
        // AcceptTransaction says "missing inputs" for every input it could not
        // connect, a relative lock not over yet included.
        if (!tx.AcceptTransaction(true, &fMissingInputs))
            throw runtime_error(fMissingInputs ? "the node could not connect the input: not known to it, or under a relative lock not over yet"
                                               : "the node refused it (see debug.log)");
        AddToWalletIfMine(tx, NULL);
        RelayMessage(CInv(MSG_TX, hash), ssTx);
    }
    json j;
    j["txid"] = hash.GetHex();
    j["fee"] = ValueFromAmount(nIn - nOutTotal);
    j["hex"] = HexStr(ssTx.begin(), ssTx.end(), false);
    return j;
}

// ---- rules v4 in the wallet: a vault and a CTV batch (docs/rules-v4.md) ----
//
// Both are made of what templatehash and spendscript already do; these name
// the two uses the rules were written for and remember the scripts, so that
// spending them later takes an address, not five hex strings.
//
// A vault: the coins can leave it one way only, by a transaction fixed when
// it was made, which moves them to an "unvault" output everybody can see.
// From there the hot key can take them only `delay` blocks later; the
// recovery key can take them at once. A stolen hot key shows itself by the
// unvault, and the owner has `delay` blocks to send everything to safety.
//
// A batch: one output now, which unfolds into many payments later, fixed in
// advance, by a transaction anybody can broadcast.
//
// The scripts and keys are kept in v4contracts.json beside the wallet. The
// redeem scripts are also in every result: with them and the keys, the coins
// can be spent with spendscript alone.

static string V4ContractsPath()
{
    return GetAppDir() + "/v4contracts.json";
}

static json LoadV4Contracts()
{
    FILE* f = fopen(V4ContractsPath().c_str(), "r");
    if (!f)
        return json::object();
    string body;
    char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        body.append(buf, r);
    fclose(f);
    try
    {
        json j = json::parse(body);
        return j.is_object() ? j : json::object();
    }
    catch (...)
    {
        throw runtime_error(V4ContractsPath() + " is unreadable; it holds the scripts of your vaults and batches -- restore it from a backup");
    }
}

static void SaveV4Contracts(const json& j)
{
    string tmp = V4ContractsPath() + ".new";
    FILE* f = fopen(tmp.c_str(), "w");
    if (!f)
        throw runtime_error("could not write " + tmp);
    string s = j.dump(2);
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    remove(V4ContractsPath().c_str());
    rename(tmp.c_str(), V4ContractsPath().c_str());
}

// Before rules v4, OP_CHECKSEQUENCEVERIFY and OP_CHECKTEMPLATEVERIFY are
// no-ops: coins locked behind them could be taken by anybody.
static void RequireRulesV4()
{
    if (!RulesV4Active((unsigned int)GetAdjustedTime()))
        throw runtime_error("rules v4 are not in force on this chain yet; coins locked in such a script now could be taken by anybody");
}

static json V4Contract(const string& strAddr, const char* pszType)
{
    json all = LoadV4Contracts();
    if (!all.contains(strAddr) || all[strAddr].value("type", "") != pszType)
        throw runtime_error(strprintf("no %s at %s in %s", pszType, strAddr.c_str(), V4ContractsPath().c_str()));
    return all[strAddr];
}

// The RPC thread and the inheritance renewer both write the file.
static CCriticalSection cs_v4contracts;

static void SetV4Contract(const string& strAddr, const json& rec)
{
    CRITICAL_BLOCK(cs_v4contracts)
    {
        json all = LoadV4Contracts();
        all[strAddr] = rec;
        SaveV4Contracts(all);
    }
}

// The one-input transaction a CTV hash fixes: version 2, sequence final,
// lock time 0 -- what spendscript builds by default.
static uint256 TemplateHashFor(const vector<CTxOut>& vout)
{
    CTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 0xffffffff;
    tx.nLockTime = 0;
    tx.vout = vout;
    return CheckTemplateHash(tx, 0);
}

static CScript CtvScript(uint256 hash)   // by value: uint256's begin() is not const
{
    CScript s;
    s << vector<unsigned char>(hash.begin(), hash.end()) << OP_CHECKTEMPLATEVERIFY;
    return s;
}

static CWalletTx FundScript(const CScript& redeem, int64 nValue)
{
    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << Hash160(redeem) << OP_EQUAL;
    CWalletTx wtx;
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    return wtx;
}

static vector<unsigned char> FreshWalletKey()
{
    vector<unsigned char> v = GetKeyFromPool();
    if (v.empty())
        throw runtime_error("could not draw a key from the wallet");
    return v;
}

// vaultcreate <amount> <delay blocks> [recovery address] [fee=0.01]
static json rpc_vaultcreate(const json& p)
{
    if (p.size() < 2)
        throw runtime_error("vaultcreate <amount> <delay in blocks, 1-65535> [recovery address] [fee=0.01]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    RequireRulesV4();
    int64 nAmount = AmountFromValue(p[0]);
    unsigned int nDelay = UIntParam(p, 1, 0);
    if (nDelay < 1 || nDelay > 0xffff)
        throw runtime_error("the delay is 1 to 65535 blocks");
    int64 nFee = (p.size() > 3 && !p[3].is_null()) ? AmountFromValue(p[3]) : CENT;
    if (nFee <= 0 || nAmount <= nFee)
        throw runtime_error("the amount must be more than the fee the unvault prepays");

    vector<unsigned char> vchHot = FreshWalletKey();
    uint160 hashRecovery;
    vector<unsigned char> vchRecovery;
    bool fRecoveryHere = !(p.size() > 2 && p[2].is_string() && !p[2].get<string>().empty());
    if (fRecoveryHere)
    {
        vchRecovery = FreshWalletKey();
        hashRecovery = Hash160(vchRecovery);
    }
    else if (!AddressToHash160(p[2].get<string>(), hashRecovery))
        throw runtime_error("the recovery address is not a Bitflash address");

    // Stage 2: the hot key after the delay, or the recovery key at once.
    CScript unvault;
    unvault << OP_IF << (int64)nDelay << OP_CHECKSEQUENCEVERIFY << OP_DROP
            << OP_DUP << OP_HASH160 << Hash160(vchHot) << OP_EQUALVERIFY << OP_CHECKSIG
            << OP_ELSE
            << OP_DUP << OP_HASH160 << hashRecovery << OP_EQUALVERIFY << OP_CHECKSIG
            << OP_ENDIF;
    string strUnvault = Hash160ToScriptAddress(Hash160(unvault));
    // Stage 1: out only by the unvault transaction, its fee paid in advance.
    vector<CTxOut> vUnvault(1, CTxOut(nAmount - nFee, ScriptForAddress(strUnvault)));
    CScript vault = CtvScript(TemplateHashFor(vUnvault));
    string strVault = Hash160ToScriptAddress(Hash160(vault));

    CWalletTx wtx = FundScript(vault, nAmount);
    json rec;
    rec["type"] = "vault";
    rec["vaultRedeem"] = HexStr(vault.begin(), vault.end(), false);
    rec["unvaultAddress"] = strUnvault;
    rec["unvaultRedeem"] = HexStr(unvault.begin(), unvault.end(), false);
    rec["hotPubKey"] = HexStr(vchHot.begin(), vchHot.end(), false);
    rec["recoveryAddress"] = Hash160ToAddress(hashRecovery);
    if (fRecoveryHere)
        rec["recoveryPubKey"] = HexStr(vchRecovery.begin(), vchRecovery.end(), false);
    rec["delay"] = nDelay;
    rec["amount"] = ValueFromAmount(nAmount);
    rec["unvaultAmount"] = ValueFromAmount(nAmount - nFee);
    rec["fundTxid"] = wtx.GetHash().GetHex();
    SetV4Contract(strVault, rec);

    json j = rec;
    j["vaultAddress"] = strVault;
    if (fRecoveryHere)
        j["warning"] = "the recovery key is in this same wallet; for a vault worth the name, give the address of a key kept somewhere else";
    return j;
}

// vaultunvault <vault address>: the one way out, fixed in advance; no key.
static json rpc_vaultunvault(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("vaultunvault <vault address>");
    json rec = V4Contract(p[0].get<string>(), "vault");
    // Done before: broadcast again. It pays no address of this wallet, so the
    // wallet does not keep it, and a restart before it was mined lost it.
    if (rec.contains("unvaultHex"))
    {
        json again = json::object();
        again["txid"] = rpc_sendrawtransaction(json::array({ rec["unvaultHex"] }));
        again["rebroadcast"] = true;
        return again;
    }
    json out;
    out[rec["unvaultAddress"].get<string>()] = rec["unvaultAmount"];
    json r = rpc_spendscript(json::array({ rec["vaultRedeem"], rec["fundTxid"], json::array(), out,
                                           2, 0xffffffffLL, 0, rec["amount"] }));
    rec["unvaultTxid"] = r["txid"];
    rec["unvaultHex"] = r["hex"];
    SetV4Contract(p[0].get<string>(), rec);
    r["unvaultAddress"] = rec["unvaultAddress"];
    r["withdrawFrom"] = strprintf("the hot key can take it %u blocks after this confirms; vaultrecover can take it now",
                                  rec["delay"].get<unsigned int>());
    return r;
}

// The unvault output to `to`, by the hot key (fHot: after the delay) or the
// recovery key (at once).
static json SpendUnvault(const string& strVault, const json& p, bool fHot)
{
    json rec = V4Contract(strVault, "vault");
    if (!rec.contains("unvaultTxid"))
        throw runtime_error("not unvaulted yet: vaultunvault first");
    if (p.size() < 2 || !p[1].is_string())
        throw runtime_error(fHot ? "vaultwithdraw <vault address> <to address> [fee=0.01]"
                                 : "vaultrecover <vault address> <to address> [fee=0.01]");
    int64 nFee = (p.size() > 2 && !p[2].is_null()) ? AmountFromValue(p[2]) : CENT;
    int64 nIn = AmountFromValue(rec["unvaultAmount"]);
    if (nIn <= nFee)
        throw runtime_error("the unvault output holds less than the fee");
    string strPub = fHot ? rec["hotPubKey"].get<string>() : rec.value("recoveryPubKey", "");
    if (strPub.empty())
        throw runtime_error("the recovery key is not in this wallet: sign with the wallet that holds " +
                            rec["recoveryAddress"].get<string>() + " (spendscript, redeem " +
                            rec["unvaultRedeem"].get<string>() + ", items [sig, pubkey, false])");
    json out;
    out[p[1].get<string>()] = ValueFromAmount(nIn - nFee);
    json items = json::array({ "sig:" + strPub, strPub, fHot });
    // The hot path carries the delay in nSequence, which OP_CHECKSEQUENCEVERIFY reads.
    unsigned int nSequence = fHot ? rec["delay"].get<unsigned int>() : 0xffffffff;
    json r = rpc_spendscript(json::array({ rec["unvaultRedeem"], rec["unvaultTxid"], items, out,
                                           2, (int64)nSequence, 0, ValueFromAmount(nFee) }));
    rec[fHot ? "withdrawTxid" : "recoverTxid"] = r["txid"];
    SetV4Contract(strVault, rec);
    return r;
}

// vaultwithdraw <vault address> <to address> [fee]
static json rpc_vaultwithdraw(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("vaultwithdraw <vault address> <to address> [fee=0.01]");
    return SpendUnvault(p[0].get<string>(), p, true);
}

// vaultrecover <vault address> <to address> [fee]
static json rpc_vaultrecover(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("vaultrecover <vault address> <to address> [fee=0.01]");
    return SpendUnvault(p[0].get<string>(), p, false);
}

// ctvbatch {"address": amount, ...} [fee=0.01]
static json rpc_ctvbatch(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("ctvbatch {\"address\": amount, ...} [fee=0.01]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    RequireRulesV4();
    vector<CTxOut> vout = OutputsFromParam(p[0]);
    int64 nFee = (p.size() > 1 && !p[1].is_null()) ? AmountFromValue(p[1]) : CENT;
    if (nFee <= 0)
        throw runtime_error("the expansion needs a fee, paid now");
    int64 nTotal = 0;
    foreach(const CTxOut& o, vout)
        nTotal += o.nValue;
    CScript batch = CtvScript(TemplateHashFor(vout));
    string strBatch = Hash160ToScriptAddress(Hash160(batch));
    CWalletTx wtx = FundScript(batch, nTotal + nFee);
    json rec;
    rec["type"] = "batch";
    rec["redeem"] = HexStr(batch.begin(), batch.end(), false);
    rec["outputs"] = p[0];
    rec["fee"] = ValueFromAmount(nFee);
    rec["fundTxid"] = wtx.GetHash().GetHex();
    SetV4Contract(strBatch, rec);
    json j = rec;
    j["batchAddress"] = strBatch;
    return j;
}

// ctvexpand <batch address>: the payments, exactly as fixed; no key.
static json rpc_ctvexpand(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("ctvexpand <batch address>");
    json rec = V4Contract(p[0].get<string>(), "batch");
    // Done before: broadcast again (see vaultunvault).
    if (rec.contains("expandHex"))
    {
        json again = json::object();
        again["txid"] = rpc_sendrawtransaction(json::array({ rec["expandHex"] }));
        again["rebroadcast"] = true;
        return again;
    }
    json r = rpc_spendscript(json::array({ rec["redeem"], rec["fundTxid"], json::array(), rec["outputs"],
                                           2, 0xffffffffLL, 0, rec["fee"] }));
    rec["expandTxid"] = r["txid"];
    rec["expandHex"] = r["hex"];
    SetV4Contract(p[0].get<string>(), rec);
    return r;
}

// listv4contracts: the vaults and batches this wallet made.
static json rpc_listv4contracts(const json& p)
{
    return LoadV4Contracts();
}

// ---- inheritance: coins an heir can take once the owner has gone quiet ----
//
// docs/inheritance.md. One pay-to-script-hash output:
//
//   OP_IF
//     OP_DUP OP_HASH160 <owner> OP_EQUALVERIFY OP_CHECKSIG
//   OP_ELSE
//     <period> OP_CHECKSEQUENCEVERIFY OP_DROP
//     OP_DUP OP_HASH160 <heir> OP_EQUALVERIFY OP_CHECKSIG
//   OP_ENDIF
//
// The owner can spend it at any time. The heir can spend it only once it has
// sat unspent for <period>: a relative lock in time (BIP68 units of 512
// seconds, at most about 388 days), not in blocks, which at two minutes a
// block would stop at 91 days. The owner's wallet renews it -- spends it back
// to the same address -- once half the period has gone by, and that starts
// the clock again. The address never changes, so what the heir keeps (the
// script and the first transaction) stays good for good: the heir's wallet
// follows the renewals through the transaction index.

static const int64 INHERIT_UNIT_SECS = (int64)1 << SEQUENCE_LOCKTIME_GRANULARITY;
static const int INHERIT_MIN_DAYS_MAINNET = 30;

// The RPC thread and the renewer must not both spend the same output.
static CCriticalSection cs_inherit;

static unsigned int InheritSequence(double dDays)
{
    if (!(dDays > 0))
        throw runtime_error("the period is a number of days");
    if (!IsTestNet() && dDays < INHERIT_MIN_DAYS_MAINNET)
        throw runtime_error(strprintf("the period is at least %d days on mainnet: any shorter, and a holiday away from the wallet hands the coins over",
                                      INHERIT_MIN_DAYS_MAINNET));
    double dUnits = ceil(dDays * 86400.0 / INHERIT_UNIT_SECS);
    if (dUnits > SEQUENCE_LOCKTIME_MASK)
        throw runtime_error(strprintf("the period is at most %d days (65535 units of 512 seconds)",
                                      (int)(SEQUENCE_LOCKTIME_MASK * INHERIT_UNIT_SECS / 86400)));
    return SEQUENCE_LOCKTIME_TYPE_FLAG | (unsigned int)dUnits;
}

static int64 InheritPeriodSecs(unsigned int nSequence)
{
    return (int64)(nSequence & SEQUENCE_LOCKTIME_MASK) * INHERIT_UNIT_SECS;
}

static CScript InheritScript(const uint160& hashOwner, const uint160& hashHeir, unsigned int nSequence)
{
    CScript s;
    s << OP_IF
      << OP_DUP << OP_HASH160 << hashOwner << OP_EQUALVERIFY << OP_CHECKSIG
      << OP_ELSE
      << (int64)nSequence << OP_CHECKSEQUENCEVERIFY << OP_DROP
      << OP_DUP << OP_HASH160 << hashHeir << OP_EQUALVERIFY << OP_CHECKSIG
      << OP_ENDIF;
    return s;
}

// The owner, heir and period of an inheritance script; false for anything
// else, byte for byte.
static bool ParseInheritScript(const CScript& s, uint160& hashOwner, uint160& hashHeir, unsigned int& nSequence)
{
    vector<vector<unsigned char> > vPush;
    CScript::const_iterator pc = s.begin();
    while (pc < s.end())
    {
        opcodetype op;
        vector<unsigned char> vch;
        if (!s.GetOp(pc, op, vch))
            return false;
        if (op <= OP_PUSHDATA4)
            vPush.push_back(vch);
    }
    if (vPush.size() != 3 || vPush[0].size() != 20 || vPush[2].size() != 20 || vPush[1].size() > 5)
        return false;
    CBigNum bnSeq(vPush[1]);
    if (bnSeq < 0)
        return false;
    vector<unsigned char> vchSeq = bnSeq.getvch();
    nSequence = 0;
    for (size_t k = 0; k < vchSeq.size() && k < 4; k++)
        nSequence |= (unsigned int)vchSeq[k] << (8 * k);
    hashOwner = uint160(vPush[0]);
    hashHeir = uint160(vPush[2]);
    if (!(nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) || (nSequence & ~(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK)) ||
        !(nSequence & SEQUENCE_LOCKTIME_MASK))
        return false;
    return InheritScript(hashOwner, hashHeir, nSequence) == s;
}

static json InheritRecord(const string& strAddr)
{
    json all = LoadV4Contracts();
    if (!all.contains(strAddr) || all[strAddr].value("type", "") != "inheritance")
        throw runtime_error(strprintf("no inheritance at %s in %s (an heir imports the package first: inheritimport)",
                                      strAddr.c_str(), V4ContractsPath().c_str()));
    return all[strAddr];
}

static CScript InheritRedeem(const json& rec)
{
    vector<unsigned char> v = ParseHex(rec["redeem"].get<string>());
    return CScript(v.begin(), v.end());
}

// Where an inheritance stands: the output holding it now, found by following
// the renewals from the first transaction. False when it was spent somewhere
// else -- by the owner, or by the heir; txOut is then the transaction that
// spent it.
static bool InheritFollow(const CScript& redeem, const uint256& txidFirst, CTransaction& txOut,
                          unsigned int& nOut, int& nRenewals)
{
    FindContractOutput(redeem, txidFirst, txOut, nOut);
    CScript p2sh;
    p2sh.SetPayToScriptHash(redeem);
    nRenewals = 0;
    for (;;)
    {
        COutPoint outpoint(txOut.GetHash(), nOut);
        CTransaction txNext;
        bool fSpent = false;
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(outpoint);
            if (mi != mapNextTx.end())
            {
                txNext = *mi->second.ptx;
                fSpent = true;
            }
        }
        if (!fSpent)
        {
            CTxIndex txindex;
            if (CTxDB("r").ReadTxIndex(outpoint.hash, txindex) && outpoint.n < txindex.vSpent.size() &&
                !txindex.vSpent[outpoint.n].IsNull())
            {
                if (!txNext.ReadFromDisk(txindex.vSpent[outpoint.n]))
                    throw runtime_error("could not read the transaction that spent " + outpoint.hash.GetHex());
                fSpent = true;
            }
        }
        if (!fSpent)
            return true;
        txOut = txNext;
        unsigned int n = 0;
        while (n < txNext.vout.size() && txNext.vout[n].scriptPubKey != p2sh)
            n++;
        if (n == txNext.vout.size())
            return false;
        nOut = n;
        nRenewals++;
    }
}

// The median time past the relative lock of a coin counts from (that of the
// block before the coin's, as BIP68 has it); -1 while the coin is not in the
// main chain.
static int64 InheritCoinTime(const uint256& txid)
{
    CTxIndex txindex;
    if (!CTxDB("r").ReadTxIndex(txid, txindex))
        return -1;
    CBlock block;
    if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
        return -1;
    int64 nTime = -1;
    CRITICAL_BLOCK(cs_main)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
        if (mi != mapBlockIndex.end() && mi->second->IsInMainChain())
        {
            const CBlockIndex* pindexBase = mi->second->pprev ? mi->second->pprev : mi->second;
            nTime = pindexBase->GetMedianTimePast();
        }
    }
    return nTime;
}

static int64 TipMedianTime()
{
    int64 nTime = 0;
    CRITICAL_BLOCK(cs_main)
        if (pindexBest)
            nTime = pindexBest->GetMedianTimePast();
    return nTime;
}

static string InheritDuration(int64 nSecs)
{
    if (nSecs >= 2 * 86400)
        return strprintf("%.1f days", nSecs / 86400.0);
    if (nSecs >= 2 * 3600)
        return strprintf("%.1f hours", nSecs / 3600.0);
    return strprintf("%d minutes", (int)((nSecs + 59) / 60));
}

// What an heir needs, and all of it: hand it over on paper or in a file, with
// the heir's own wallet backup. No key is in it.
static json InheritPackage(const string& strAddr, const json& rec)
{
    json pkg;
    pkg["type"] = "bitflash-inheritance";
    pkg["network"] = IsTestNet() ? "testnet" : "mainnet";
    pkg["address"] = strAddr;
    pkg["redeem"] = rec["redeem"];
    pkg["firstTxid"] = rec["fundTxid"];
    pkg["heirAddress"] = rec["heirAddress"];
    pkg["days"] = rec["days"];
    return pkg;
}

static json InheritStatus(const string& strAddr, const json& rec)
{
    json j = rec;
    j["address"] = strAddr;
    unsigned int nSequence = rec["sequence"].get<unsigned int>();
    int64 nPeriod = InheritPeriodSecs(nSequence);
    CTransaction tx;
    unsigned int n = 0;
    int nRenewals = 0;
    bool fOpen = InheritFollow(InheritRedeem(rec), uint256(rec["fundTxid"].get<string>()), tx, n, nRenewals);
    j["renewals"] = nRenewals;
    if (!fOpen)
    {
        j["state"] = "closed";
        j["closedBy"] = tx.GetHash().GetHex();
        return j;
    }
    j["state"] = "active";
    j["currentTxid"] = tx.GetHash().GetHex();
    j["currentVout"] = (int)n;
    j["currentAmount"] = ValueFromAmount(tx.vout[n].nValue);
    int64 nCoinTime = InheritCoinTime(tx.GetHash());
    j["confirmed"] = nCoinTime >= 0;
    if (nCoinTime >= 0)
    {
        int64 nNow = TipMedianTime();
        j["heirOpensAt"] = nCoinTime + nPeriod;
        j["heirCanClaim"] = nNow >= nCoinTime + nPeriod;
        j["heirOpensIn"] = nNow >= nCoinTime + nPeriod ? string("now") : InheritDuration(nCoinTime + nPeriod - nNow);
        if (rec.value("role", "") == "owner")
            j["renewDueAt"] = nCoinTime + nPeriod / 2;
    }
    j["heirPackage"] = InheritPackage(strAddr, rec);
    return j;
}

// The owner spends the inheritance output: back to its own address (a
// renewal), or anywhere else (closing it).
static json InheritOwnerSpend(const string& strAddr, const string* pstrTo, int64 nFee)
{
    json rec = InheritRecord(strAddr);
    if (rec.value("role", "") != "owner")
        throw runtime_error("this wallet is the heir of that inheritance, not its owner");
    CTransaction tx;
    unsigned int n = 0;
    int nRenewals = 0;
    if (!InheritFollow(InheritRedeem(rec), uint256(rec["fundTxid"].get<string>()), tx, n, nRenewals))
        throw runtime_error("that inheritance is closed: spent by " + tx.GetHash().GetHex());
    if (pstrTo == NULL && InheritCoinTime(tx.GetHash()) < 0)
    {
        // The last renewal is not mined yet: say it again rather than chain
        // another on top of it.
        if (rec.value("lastRenewTxid", "") == tx.GetHash().GetHex() && rec.contains("lastRenewHex"))
        {
            json again = json::object();
            again["txid"] = rpc_sendrawtransaction(json::array({ rec["lastRenewHex"] }));
            again["rebroadcast"] = true;
            return again;
        }
        throw runtime_error("the output is not mined yet; the clock starts when it is");
    }
    int64 nIn = tx.vout[n].nValue;
    if (nIn <= nFee + CENT)
        throw runtime_error("the inheritance holds too little to pay the fee");
    string strPub = rec["ownerPubKey"].get<string>();
    json out;
    out[pstrTo ? *pstrTo : strAddr] = ValueFromAmount(nIn - nFee);
    json r = rpc_spendscript(json::array({ rec["redeem"], tx.GetHash().GetHex(),
                                           json::array({ "sig:" + strPub, strPub, true }), out,
                                           2, 0xffffffffLL, 0, ValueFromAmount(nFee) }));
    if (pstrTo)
    {
        rec["closedTxid"] = r["txid"];
        rec.erase("lastRenewHex");
    }
    else
    {
        // It pays no address of this wallet, so the wallet will not keep it:
        // keep it here, to broadcast again until it is mined.
        rec["lastRenewTxid"] = r["txid"];
        rec["lastRenewHex"] = r["hex"];
        rec["lastRenewTime"] = GetTime();
    }
    SetV4Contract(strAddr, rec);
    r["renewals"] = nRenewals + (pstrTo ? 0 : 1);
    return r;
}

// inheritcreate <amount> <heir address> <days> [fee=0.01]
static json rpc_inheritcreate(const json& p)
{
    if (p.size() < 3 || !p[1].is_string() || !p[2].is_number())
        throw runtime_error("inheritcreate <amount> <heir address> <days the owner may stay silent before the heir can take it> [renewal fee=0.01]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    RequireRulesV4();
    int64 nAmount = AmountFromValue(p[0]);
    uint160 hashHeir;
    string strHeir = p[1].get<string>();
    if (!AddressToHash160(strHeir, hashHeir))
        throw runtime_error("the heir address is not an ordinary Bitflash address (a key the heir holds, not a script)");
    unsigned int nSequence = InheritSequence(p[2].get<double>());
    int64 nFee = (p.size() > 3 && !p[3].is_null()) ? AmountFromValue(p[3]) : CENT;
    if (nFee <= 0 || nAmount <= 10 * nFee)
        throw runtime_error("the amount must be well over the renewal fee, which each renewal takes from it");

    CRITICAL_BLOCK(cs_inherit)
    {
        vector<unsigned char> vchOwner = FreshWalletKey();
        CScript redeem = InheritScript(Hash160(vchOwner), hashHeir, nSequence);
        string strAddr = Hash160ToScriptAddress(Hash160(redeem));
        CWalletTx wtx = FundScript(redeem, nAmount);
        json rec;
        rec["type"] = "inheritance";
        rec["role"] = "owner";
        rec["redeem"] = HexStr(redeem.begin(), redeem.end(), false);
        rec["ownerPubKey"] = HexStr(vchOwner.begin(), vchOwner.end(), false);
        rec["heirAddress"] = strHeir;
        rec["sequence"] = nSequence;
        rec["days"] = InheritPeriodSecs(nSequence) / 86400.0;
        rec["amount"] = ValueFromAmount(nAmount);
        rec["renewFee"] = ValueFromAmount(nFee);
        rec["autoRenew"] = true;
        rec["fundTxid"] = wtx.GetHash().GetHex();
        SetV4Contract(strAddr, rec);

        json j = rec;
        j["address"] = strAddr;
        j["heirPackage"] = InheritPackage(strAddr, rec);
        if (IsMineAddress(strHeir))
            j["warning"] = "the heir key is in this same wallet: fine for a test, useless as an inheritance";
        return j;
    }
    return json();
}

// inheritinfo <address>
static json rpc_inheritinfo(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("inheritinfo <inheritance address>");
    return InheritStatus(p[0].get<string>(), InheritRecord(p[0].get<string>()));
}

// inheritrenew <address> [fee]: what the wallet does by itself, now.
static json rpc_inheritrenew(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("inheritrenew <inheritance address> [fee]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CRITICAL_BLOCK(cs_inherit)
    {
        json rec = InheritRecord(p[0].get<string>());
        int64 nFee = (p.size() > 1 && !p[1].is_null()) ? AmountFromValue(p[1]) : AmountFromValue(rec["renewFee"]);
        return InheritOwnerSpend(p[0].get<string>(), NULL, nFee);
    }
    return json();
}

// inheritcancel <address> <to address> [fee=0.01]: the owner takes it back.
static json rpc_inheritcancel(const json& p)
{
    if (p.size() < 2 || !p[0].is_string() || !p[1].is_string())
        throw runtime_error("inheritcancel <inheritance address> <to address> [fee=0.01]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    string strTo = p[1].get<string>();
    if (strTo == p[0].get<string>())
        throw runtime_error("that is the inheritance address itself: inheritrenew does that");
    int64 nFee = (p.size() > 2 && !p[2].is_null()) ? AmountFromValue(p[2]) : CENT;
    CRITICAL_BLOCK(cs_inherit)
        return InheritOwnerSpend(p[0].get<string>(), &strTo, nFee);
    return json();
}

// inheritpackage <address>: what to hand the heir.
static json rpc_inheritpackage(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("inheritpackage <inheritance address>");
    return InheritPackage(p[0].get<string>(), InheritRecord(p[0].get<string>()));
}

// inheritimport <package>: in the heir's wallet.
static json rpc_inheritimport(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("inheritimport <package, as given by inheritcreate or inheritpackage>");
    json pkg = p[0];
    if (pkg.is_string())
    {
        try { pkg = json::parse(pkg.get<string>()); }
        catch (...) { throw runtime_error("the package is not JSON"); }
    }
    if (!pkg.is_object() || pkg.value("type", "") != "bitflash-inheritance")
        throw runtime_error("that is not an inheritance package");
    if (pkg.value("network", "") != (IsTestNet() ? "testnet" : "mainnet"))
        throw runtime_error("that package is for the other network");
    if (!pkg.contains("redeem") || !pkg["redeem"].is_string() || !IsHex(pkg["redeem"].get<string>()) ||
        !pkg.contains("firstTxid") || !pkg["firstTxid"].is_string())
        throw runtime_error("the package lacks its script or first transaction");
    vector<unsigned char> v = ParseHex(pkg["redeem"].get<string>());
    CScript redeem(v.begin(), v.end());
    uint160 hashOwner, hashHeir;
    unsigned int nSequence = 0;
    if (!ParseInheritScript(redeem, hashOwner, hashHeir, nSequence))
        throw runtime_error("the script in the package is not an inheritance script");
    // Everything is taken from the script itself, not from what the package
    // says about it.
    string strAddr = Hash160ToScriptAddress(Hash160(redeem));
    if (pkg.value("address", strAddr) != strAddr)
        throw runtime_error("the package's address does not match its script");
    string strHeir = Hash160ToAddress(hashHeir);
    if (!IsMineAddress(strHeir))
        throw runtime_error("this wallet does not hold the heir key " + strHeir + "; import the package into the wallet that does");
    json rec;
    rec["type"] = "inheritance";
    rec["role"] = "heir";
    rec["redeem"] = pkg["redeem"];
    rec["heirAddress"] = strHeir;
    rec["ownerAddress"] = Hash160ToAddress(hashOwner);
    rec["sequence"] = nSequence;
    rec["days"] = InheritPeriodSecs(nSequence) / 86400.0;
    rec["fundTxid"] = pkg["firstTxid"];
    CTransaction tx;
    unsigned int n = 0;
    FindContractOutput(redeem, uint256(pkg["firstTxid"].get<string>()), tx, n);
    SetV4Contract(strAddr, rec);
    return InheritStatus(strAddr, rec);
}

// inheritclaim <address> <to address> [fee=0.01]: the heir, after the period.
static json rpc_inheritclaim(const json& p)
{
    if (p.size() < 2 || !p[0].is_string() || !p[1].is_string())
        throw runtime_error("inheritclaim <inheritance address> <to address> [fee=0.01]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    string strAddr = p[0].get<string>();
    int64 nFee = (p.size() > 2 && !p[2].is_null()) ? AmountFromValue(p[2]) : CENT;
    CRITICAL_BLOCK(cs_inherit)
    {
        json rec = InheritRecord(strAddr);
        unsigned int nSequence = rec["sequence"].get<unsigned int>();
        CTransaction tx;
        unsigned int n = 0;
        int nRenewals = 0;
        if (!InheritFollow(InheritRedeem(rec), uint256(rec["fundTxid"].get<string>()), tx, n, nRenewals))
            throw runtime_error("that inheritance is closed: spent by " + tx.GetHash().GetHex());
        int64 nCoinTime = InheritCoinTime(tx.GetHash());
        if (nCoinTime < 0)
            throw runtime_error(nRenewals ? "the owner renewed it moments ago (the renewal is not even mined yet)"
                                          : "it was made moments ago (its first transaction is not mined yet); the period counts from its block");
        int64 nOpens = nCoinTime + InheritPeriodSecs(nSequence), nNow = TipMedianTime();
        if (nNow < nOpens)
            throw runtime_error(strprintf("not yet: it opens to the heir in about %s, if the owner does not renew it first (renewals so far: %d)",
                                          InheritDuration(nOpens - nNow).c_str(), nRenewals));
        int64 nIn = tx.vout[n].nValue;
        if (nIn <= nFee)
            throw runtime_error("the inheritance holds less than the fee");
        uint160 hashHeir;
        AddressToHash160(rec["heirAddress"].get<string>(), hashHeir);
        string strPub;
        CRITICAL_BLOCK(cs_mapKeys)
        {
            map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(hashHeir);
            if (mi != mapPubKeys.end())
                strPub = HexStr(mi->second.begin(), mi->second.end(), false);
        }
        if (strPub.empty())
            throw runtime_error("this wallet does not hold the heir key " + rec["heirAddress"].get<string>());
        json out;
        out[p[1].get<string>()] = ValueFromAmount(nIn - nFee);
        // The heir's path carries the period in nSequence, which
        // OP_CHECKSEQUENCEVERIFY compares and BIP68 enforces.
        json r = rpc_spendscript(json::array({ rec["redeem"], tx.GetHash().GetHex(),
                                               json::array({ "sig:" + strPub, strPub, false }), out,
                                               2, (int64)nSequence, 0, ValueFromAmount(nFee) }));
        rec["closedTxid"] = r["txid"];
        SetV4Contract(strAddr, rec);
        return r;
    }
    return json();
}

// The renewer: a few minutes after start and every five minutes after that,
// every inheritance this wallet owns that is half way to opening is spent back
// to its own address.
static void InheritanceTick()
{
    if (IsInitialBlockDownload())
        return;
    json all;
    CRITICAL_BLOCK(cs_v4contracts)
        all = LoadV4Contracts();
    for (json::iterator it = all.begin(); it != all.end(); ++it)
    {
        const string strAddr = it.key();
        const json& rec = it.value();
        if (rec.value("type", "") != "inheritance" || rec.value("role", "") != "owner" ||
            rec.contains("closedTxid") || !rec.value("autoRenew", true))
            continue;
        try
        {
            CRITICAL_BLOCK(cs_inherit)
            {
                CTransaction tx;
                unsigned int n = 0;
                int nRenewals = 0;
                if (!InheritFollow(InheritRedeem(rec), uint256(rec["fundTxid"].get<string>()), tx, n, nRenewals))
                {
                    json closed = rec;
                    closed["closedTxid"] = tx.GetHash().GetHex();
                    closed.erase("lastRenewHex");
                    SetV4Contract(strAddr, closed);
                    printf("inheritance %s: closed by %s\n", strAddr.c_str(), tx.GetHash().GetHex().c_str());
                    continue;
                }
                int64 nCoinTime = InheritCoinTime(tx.GetHash());
                if (nCoinTime < 0)
                {
                    if (rec.value("lastRenewTxid", "") == tx.GetHash().GetHex() && rec.contains("lastRenewHex"))
                    {
                        try { rpc_sendrawtransaction(json::array({ rec["lastRenewHex"] })); }
                        catch (std::exception& e) { printf("inheritance %s: rebroadcast: %s\n", strAddr.c_str(), e.what()); }
                    }
                    continue;
                }
                int64 nPeriod = InheritPeriodSecs(rec["sequence"].get<unsigned int>());
                int64 nNow = TipMedianTime();
                if (nNow - nCoinTime < nPeriod / 2)
                    continue;
                if (IsWalletLocked())
                {
                    printf("inheritance %s: renewal due, but the wallet is locked; unlock it within %s or the heir can take the coins\n",
                           strAddr.c_str(), InheritDuration(max((int64)0, nCoinTime + nPeriod - nNow)).c_str());
                    continue;
                }
                json r = InheritOwnerSpend(strAddr, NULL, AmountFromValue(rec["renewFee"]));
                printf("inheritance %s: renewed by %s (renewal %d)\n", strAddr.c_str(),
                       r["txid"].get<string>().c_str(), r.value("renewals", 0));
            }
        }
        catch (std::exception& e)
        {
            printf("inheritance %s: %s\n", strAddr.c_str(), e.what());
        }
    }
}

// -selftest=inheritance: the period, the script and its three ways to be spent.
// To the terminal: printf here is the debug log (util.h).
int InheritanceSelfTest()
{
    fprintf(stdout, "inheritance self-test\n");
    int nFail = 0;
    struct T
    {
        static int Check(bool f, const char* psz)
        {
            fprintf(stdout, "  %s %s\n", f ? "ok  " : "FAIL", psz);
            return f ? 0 : 1;
        }
        static bool Throws(double dDays)
        {
            try { InheritSequence(dDays); }
            catch (std::exception&) { return true; }
            return false;
        }
    };

    // ---- the period
    bool fWasTestNet = IsTestNet();
    SelectNetworkParams(false);
    nFail += T::Check(InheritSequence(30) == (SEQUENCE_LOCKTIME_TYPE_FLAG | 5063),
                      "mainnet: 30 days is 5063 units of 512 seconds, a time lock") ;
    nFail += T::Check(T::Throws(29.9) && T::Throws(0) && T::Throws(-1),
                      "mainnet: under 30 days, zero or negative is refused");
    nFail += T::Check(!T::Throws(388) && T::Throws(388.4) && T::Throws(1000),
                      "388 days fits the 16-bit field; more does not");
    SelectNetworkParams(true);
    nFail += T::Check(InheritSequence(0.01) == (SEQUENCE_LOCKTIME_TYPE_FLAG | 2),
                      "testnet: a short period for a bench (0.01 day, rounded up to 2 units)");
    nFail += T::Check(InheritPeriodSecs(InheritSequence(1)) >= 86400 &&
                      InheritPeriodSecs(InheritSequence(1)) < 86400 + 512,
                      "the period is never shorter than asked, and at most one unit longer");
    SelectNetworkParams(fWasTestNet);

    // ---- the script
    CKey keyOwner, keyHeir, keyOther;
    keyOwner.MakeNewKey();
    keyHeir.MakeNewKey();
    keyOther.MakeNewKey();
    vector<unsigned char> vchOwner = keyOwner.GetPubKey(), vchHeir = keyHeir.GetPubKey(), vchOther = keyOther.GetPubKey();
    const unsigned int nSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | 5063;
    CScript redeem = InheritScript(Hash160(vchOwner), Hash160(vchHeir), nSeq);
    uint160 hOwner, hHeir;
    unsigned int nSeqParsed = 0;
    nFail += T::Check(ParseInheritScript(redeem, hOwner, hHeir, nSeqParsed) && hOwner == Hash160(vchOwner) &&
                      hHeir == Hash160(vchHeir) && nSeqParsed == nSeq,
                      "the script reads back: owner, heir, period");
    {
        CScript extra = redeem;
        extra << OP_DROP;
        CScript blocks = InheritScript(Hash160(vchOwner), Hash160(vchHeir), 5063);
        CScript swapped = redeem;
        swapped[1] = OP_NOP;   // OP_DUP of the owner's path
        nFail += T::Check(!ParseInheritScript(extra, hOwner, hHeir, nSeqParsed) &&
                          !ParseInheritScript(blocks, hOwner, hHeir, nSeqParsed) &&
                          !ParseInheritScript(swapped, hOwner, hHeir, nSeqParsed) &&
                          !ParseInheritScript(CScript() << OP_TRUE, hOwner, hHeir, nSeqParsed),
                          "anything else is refused: a trailing opcode, a lock in blocks, one byte changed");
    }

    // ---- the three ways out, signed and verified as a block would
    CTransaction txFrom;
    txFrom.vin.resize(1);
    txFrom.vin[0].prevout = COutPoint(Hash(BEGIN(nSeq), END(nSeq)), 0);
    CScript p2sh;
    p2sh.SetPayToScriptHash(redeem);
    txFrom.vout.push_back(CTxOut(10 * COIN, p2sh));
    struct Spend
    {
        static bool Run(const CTransaction& txFrom, const CScript& redeem, CKey& key, bool fOwnerPath,
                        unsigned int nSequence, int nVersion, bool fRulesV4)
        {
            CTransaction tx;
            tx.nVersion = nVersion;
            tx.vin.resize(1);
            tx.vin[0].prevout = COutPoint(txFrom.GetHash(), 0);
            tx.vin[0].nSequence = nSequence;
            tx.vout.push_back(CTxOut(10 * COIN - CENT, CScript() << OP_TRUE));
            uint256 hash = SignatureHash(redeem, tx, 0, SIGHASH_ALL);
            vector<unsigned char> sig;
            if (!key.Sign(hash, sig))
                return false;
            sig.push_back((unsigned char)SIGHASH_ALL);
            CScript scriptSig;
            scriptSig << sig << key.GetPubKey() << (fOwnerPath ? OP_TRUE : OP_FALSE)
                      << vector<unsigned char>(redeem.begin(), redeem.end());
            tx.vin[0].scriptSig = scriptSig;
            return VerifySignature(txFrom, tx, 0, 0, true, true, fRulesV4);
        }
    };
    nFail += T::Check(Spend::Run(txFrom, redeem, keyOwner, true, 0xffffffff, 2, true),
                      "the owner spends at any time, no lock in nSequence");
    nFail += T::Check(Spend::Run(txFrom, redeem, keyHeir, false, nSeq, 2, true),
                      "the heir's spend carries the period in nSequence and passes the script (BIP68 holds it out of blocks until then)");
    nFail += T::Check(!Spend::Run(txFrom, redeem, keyHeir, false, nSeq - 1, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyHeir, false, 5063, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyHeir, false, 0xffffffff, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyHeir, false, nSeq, 1, true),
                      "the heir is refused with a shorter period, a lock in blocks, no lock, or a version 1 transaction");
    nFail += T::Check(!Spend::Run(txFrom, redeem, keyHeir, true, 0xffffffff, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyOwner, false, nSeq, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyOther, true, 0xffffffff, 2, true) &&
                      !Spend::Run(txFrom, redeem, keyOther, false, nSeq, 2, true),
                      "nobody takes the other's path, and a stranger takes neither");
    nFail += T::Check(!Spend::Run(txFrom, redeem, keyHeir, false, nSeq, 2, false),
                      "before rules v4 the heir's path fails outright (the CSV byte is unknown)");

    fprintf(stdout, "%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

void ThreadInheritance(void*)
{
    int64 nNext = GetTime() + 120;
    while (!fShutdown)
    {
        Sleep(5000);
        if (GetTime() < nNext)
            continue;
        nNext = GetTime() + 300;
        try
        {
            InheritanceTick();
        }
        catch (std::exception& e)
        {
            printf("inheritance: %s\n", e.what());
        }
    }
}

// swapredeem <contract> <contract txid> <secret>
static json rpc_swapredeem(const json& p)
{
    if (p.size() < 3 || !p[1].is_string() || !p[2].is_string())
        throw runtime_error("swapredeem <contract hex> <contract txid> <secret hex>");
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    string strSecret = p[2].get<string>();
    if (strSecret.size() != 64 || !IsHex(strSecret))
        throw runtime_error("the secret is 64 hex characters");
    vector<unsigned char> secret = ParseHex(strSecret);
    unsigned char h[32];
    SHA256(&secret[0], secret.size(), h);
    if (vector<unsigned char>(h, h + 32) != c.secretHash)
        throw runtime_error("that secret does not match the contract's secret hash");
    json j = SpendContract(contract, c, uint256(p[1].get<string>()), &secret);
    LogSwap(json{{"redeemed", j["txid"]}, {"contractAddress", Hash160ToScriptAddress(Hash160(contract))}});
    return j;
}

// swaprefund <contract> <contract txid>
static json rpc_swaprefund(const json& p)
{
    if (p.size() < 2 || !p[1].is_string())
        throw runtime_error("swaprefund <contract hex> <contract txid>");
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    json j = SpendContract(contract, c, uint256(p[1].get<string>()), NULL);
    LogSwap(json{{"refunded", j["txid"]}, {"contractAddress", Hash160ToScriptAddress(Hash160(contract))}});
    return j;
}

extern map<COutPoint, CInPoint> mapNextTx;   // main.cpp: memory-pool spends

// swapfindsecret <contract> <contract txid>
// Has our contract been spent, and with the secret? Read off this node's own
// memory pool and chain: whoever waits for the secret needs nobody to send it.
static json rpc_swapfindsecret(const json& p)
{
    if (p.size() < 2 || !p[1].is_string())
        throw runtime_error("swapfindsecret <contract hex> <contract txid>");
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    CTransaction txFrom;
    unsigned int n = 0;
    FindContractOutput(contract, uint256(p[1].get<string>()), txFrom, n);
    COutPoint outpoint(txFrom.GetHash(), n);

    CTransaction spend;
    bool fFound = false;
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        map<COutPoint, CInPoint>::iterator mi = mapNextTx.find(outpoint);
        if (mi != mapNextTx.end() && mi->second.ptx)
        {
            spend = *mi->second.ptx;
            fFound = true;
        }
    }
    if (!fFound)
    {
        CTxIndex txindex;
        if (CTxDB("r").ReadTxIndex(outpoint.hash, txindex) && n < txindex.vSpent.size() &&
            !txindex.vSpent[n].IsNull() && spend.ReadFromDisk(txindex.vSpent[n]))
            fFound = true;
    }
    json j;
    j["spent"] = fFound;
    if (!fFound)
        return j;
    j["txid"] = spend.GetHash().GetHex();
    for (size_t k = 0; k < spend.vin.size(); k++)
    {
        vector<unsigned char> secret;
        if (spend.vin[k].prevout == outpoint && swap::ExtractSecret(spend.vin[k].scriptSig, c.secretHash, secret))
        {
            j["secret"] = HexStr(secret.begin(), secret.end(), false);
            return j;
        }
    }
    j["refunded"] = true;
    return j;
}

// swapextractsecret <redeem transaction: txid on this chain, or raw hex from either chain> <secret hash>
static json rpc_swapextractsecret(const json& p)
{
    if (p.size() < 2 || !p[0].is_string() || !p[1].is_string())
        throw runtime_error("swapextractsecret <redeem txid or raw hex> <secret hash>");
    string strHash = p[1].get<string>();
    if (strHash.size() != 64 || !IsHex(strHash))
        throw runtime_error("the secret hash is 64 hex characters");
    vector<unsigned char> vchHash = ParseHex(strHash);

    string s = p[0].get<string>();
    CTransaction tx;
    if (s.size() == 64 && IsHex(s))
    {
        if (!LookupTransaction(uint256(s), tx))
            throw runtime_error("transaction not found");
    }
    else
    {
        // A Bitcoin transaction reads as one of ours once its witness, if it
        // has one, is dropped (btcswap.h); the scriptSigs are what matter.
        if (!IsHex(s) || !btcswap::ParseTx(ParseHex(s), tx))
            throw runtime_error("transaction does not decode");
    }
    vector<unsigned char> secret;
    for (size_t i = 0; i < tx.vin.size(); i++)
        if (swap::ExtractSecret(tx.vin[i].scriptSig, vchHash, secret))
        {
            json j;
            j["secret"] = HexStr(secret.begin(), secret.end(), false);
            return j;
        }
    throw runtime_error("no input of that transaction reveals a secret with that hash");
}

// ---------------------------------------------------------------------------
// The Bitcoin half (btcswap.h): this wallet's keys in the contract, Bitcoin
// Core for the coins and the chain.

static btcswap::Chain RequireBitcoin()
{
    btcswap::Chain chain;
    string err;
    if (!btcswap::CheckChain(chain, err))
        throw runtime_error(err);
    return chain;
}

static json BtcCall(const string& method, const json& params, size_t nMaxBytes = 4 * 1024 * 1024)
{
    json r;
    string err;
    if (!btcswap::Call(method, params, r, err, nMaxBytes))
        throw runtime_error(string(btcswap::UsingLight() ? "Bitcoin light: " : "Bitcoin Core: ") + err);
    return r;
}

static string UtcText(int64 t)
{
    time_t tt = (time_t)t;
    char buf[32] = "";
    struct tm* g = gmtime(&tt);
    if (g)
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", g);
    return buf;
}

// The lock in seconds: the standard one, or on a Bitcoin test chain a
// shorter one as the last parameter (a refund tried in minutes, not a day).
static int64 LockSecsParam(const json& p, size_t nIndex, int64 nDefault, const btcswap::Chain& chain)
{
    if (p.size() <= nIndex)
        return nDefault;
    if (chain.fMain)
        throw runtime_error("the lock length is fixed on Bitcoin's main chain");
    if (!p[nIndex].is_number_integer() || p[nIndex].get<int64>() < 60 || p[nIndex].get<int64>() > nDefault)
        throw runtime_error(strprintf("lock seconds: 60 to %lld", (long long)nDefault));
    return p[nIndex].get<int64>();
}

static string BtcAmountText(int64 n)
{
    return strprintf("%lld.%08lld", (long long)(n / COIN), (long long)(n % COIN));
}

static json BtcContractJson(const btcswap::Chain& chain, const swap::Contract& c, const CScript& contract)
{
    json j;
    j["chain"]           = "bitcoin-" + chain.name;
    j["contract"]        = HexStr(contract.begin(), contract.end(), false);
    j["contractAddress"] = btcswap::ScriptAddress(chain, contract);
    j["recipient"]       = btcswap::PkhToAddress(chain, c.recipientPkh);
    j["refundAddress"]   = btcswap::PkhToAddress(chain, c.refundPkh);
    j["secretHash"]      = HexStr(c.secretHash.begin(), c.secretHash.end(), false);
    j["lockTime"]        = c.nLockTime;
    j["refundOpens"]     = UtcText(c.nLockTime);
    return j;
}

// Lock BTC from Bitcoin Core's wallet in a contract whose keys are ours.
static json BtcFundContract(const btcswap::Chain& chain, const swap::Contract& c, int64 nValue)
{
    CScript contract = swap::BuildContract(c);
    string strAddr = btcswap::ScriptAddress(chain, contract);
    if (btcswap::UsingLight())
    {
        btclight::Watch(contract);
        json j = BtcContractJson(chain, c, contract);
        j["contractTxid"] = ""; j["vout"] = -1;
        j["amount"] = ValueFromAmount(nValue);
        j["awaitingPayment"] = true;
        j["paymentInstructions"] = "pay exactly " + BtcAmountText(nValue) + " BTC to " + strAddr;
        return j;
    }
    json txid = BtcCall("sendtoaddress", json::array({ strAddr, BtcAmountText(nValue) }));
    if (!txid.is_string())
        throw runtime_error("Bitcoin Core did not return a transaction id");
    json wtx = BtcCall("gettransaction", json::array({ txid }));
    if (!wtx.is_object() || !wtx.contains("hex") || !wtx["hex"].is_string())
        throw runtime_error("Bitcoin Core did not return the contract transaction");
    CTransaction tx;
    if (!btcswap::ParseTx(ParseHex(wtx["hex"].get<string>()), tx))
        throw runtime_error("the contract transaction does not decode");
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);
    int nOut = -1;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
        if (tx.vout[i].scriptPubKey == p2sh && tx.vout[i].nValue == nValue)
            nOut = (int)i;
    if (nOut < 0)
        throw runtime_error("Bitcoin Core's transaction does not pay the contract");
    json j = BtcContractJson(chain, c, contract);
    j["contractTxid"] = txid;
    j["contractTx"] = wtx["hex"];
    j["vout"] = nOut;
    j["amount"] = ValueFromAmount(nValue);
    return j;
}

static swap::Contract BtcNewContract(const btcswap::Chain& chain, const string& strTheirAddr)
{
    swap::Contract c;
    string err;
    if (!btcswap::AddressToPkh(chain, strTheirAddr, c.recipientPkh, err))
        throw runtime_error(err);
    vector<unsigned char> vchRefund = GetKeyFromPool();
    if (vchRefund.empty())
        throw runtime_error("could not draw a key from the wallet");
    uint160 h = Hash160(vchRefund);
    c.refundPkh.assign(h.begin(), h.end());
    return c;
}

// btcswapinfo -- is Bitcoin Core there, on which chain, and what it holds.
static json rpc_btcswapinfo(const json&)
{
    btcswap::Chain chain = RequireBitcoin();
    json j;
    j["chain"] = chain.name;
    j["blocks"] = chain.nBlocks;
    j["mediantime"] = chain.nMedianTime;
    json bal;
    string err;
    j["backend"] = btcswap::UsingLight() ? "light" : "core";
    if (btcswap::UsingLight())
    {
        json status = BtcCall("getblockchaininfo", json::array());
        j["light"] = status;
        j["balance"] = nullptr;
        j["feeRatePerKvB"] = ValueFromAmount(btcswap::FeeRatePerKvB());
        return j;
    }
    j["balance"] = btcswap::Call("getbalance", json::array(), bal, err) ? bal : json(nullptr);
    if (!err.empty())
        j["walletError"] = err;
    j["feeRatePerKvB"] = ValueFromAmount(btcswap::FeeRatePerKvB());
    return j;
}

static json rpc_btcvalidatedestination(const json& p)
{
    btcswap::Chain chain = RequireBitcoin();
    if (p.size() != 1 || !p[0].is_string()) throw runtime_error("btcvalidatedestination <Bitcoin address>");
    CScript script; string err;
    if (!btclight::Destination(chain, p[0].get<string>(), script, err)) throw runtime_error(err);
    return json{{"valid",true}};
}

// btcnewaddress -- a Bitcoin address whose key is in THIS wallet: what to
// give the other side of a swap to be paid BTC to.
static json rpc_btcnewaddress(const json&)
{
    btcswap::Chain chain = RequireBitcoin();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    vector<unsigned char> vch = GetKeyFromPool();
    if (vch.empty())
        throw runtime_error("could not draw a key from the wallet");
    uint160 h = Hash160(vch);
    return btcswap::PkhToAddress(chain, vector<unsigned char>(h.begin(), h.end()));
}

// btcinitiate <their BTC address> <amount> [lock seconds, test chains only]
static json rpc_btcinitiate(const json& p)
{
    if (p.size() < 2 || !p[0].is_string())
        throw runtime_error("btcinitiate <participant's Bitcoin address> <amount> [lock seconds, test chains only]");
    RequireSwapsOpen();
    btcswap::Chain chain = RequireBitcoin();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    swap::Contract c = BtcNewContract(chain, p[0].get<string>());
    vector<unsigned char> secret(swap::SECRET_BYTES);
    RAND_bytes(&secret[0], (int)secret.size());
    c.secretHash.resize(32);
    SHA256(&secret[0], secret.size(), &c.secretHash[0]);
    c.nLockTime = GetTime() + LockSecsParam(p, 2, btcswap::INITIATOR_LOCK_SECS, chain);
    json j = BtcFundContract(chain, c, AmountFromValue(p[1]));
    j["secret"] = HexStr(secret.begin(), secret.end(), false);
    j["role"] = "initiator";
    LogSwap(j);
    OPENSSL_cleanse(&secret[0], secret.size());
    return j;
}

// btcparticipate <their BTC address> <amount> <secret hash> [lock seconds, test chains only]
static json rpc_btcparticipate(const json& p)
{
    if (p.size() < 3 || !p[0].is_string() || !p[2].is_string())
        throw runtime_error("btcparticipate <initiator's Bitcoin address> <amount> <secret hash> [lock seconds, test chains only]");
    RequireSwapsOpen();
    btcswap::Chain chain = RequireBitcoin();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    string strHash = p[2].get<string>();
    if (strHash.size() != 64 || !IsHex(strHash))
        throw runtime_error("the secret hash is 64 hex characters");
    swap::Contract c = BtcNewContract(chain, p[0].get<string>());
    c.secretHash = ParseHex(strHash);
    c.nLockTime = GetTime() + LockSecsParam(p, 3, btcswap::PARTICIPANT_LOCK_SECS, chain);
    json j = BtcFundContract(chain, c, AmountFromValue(p[1]));
    j["role"] = "participant";
    LogSwap(j);
    return j;
}

// A contract transaction given as raw hex, or as a txid Bitcoin Core can
// find (its memory pool, its wallet, or its txindex).
static CTransaction BtcContractTx(const json& v)
{
    if (!v.is_string() || !IsHex(v.get<string>()))
        throw runtime_error("the contract transaction is given as hex or as a txid");
    string s = v.get<string>();
    if (s.size() == 64)
    {
        json r;
        string err;
        if (btcswap::Call("getrawtransaction", json::array({ s }), r, err) && r.is_string())
            s = r.get<string>();
        else if (btcswap::Call("gettransaction", json::array({ s }), r, err) && r.is_object() &&
                 r.contains("hex") && r["hex"].is_string())
            s = r["hex"].get<string>();
        else
            throw runtime_error("Bitcoin Core does not have that transaction; give its raw hex");
    }
    CTransaction tx;
    if (!btcswap::ParseTx(ParseHex(s), tx))
        throw runtime_error("the contract transaction does not decode");
    return tx;
}

static unsigned int BtcContractOutput(const CTransaction& tx, const CScript& contract)
{
    CScript p2sh;
    p2sh.SetPayToScriptHash(contract);
    for (unsigned int i = 0; i < tx.vout.size(); i++)
        if (tx.vout[i].scriptPubKey == p2sh)
            return i;
    throw runtime_error("that transaction does not pay this contract");
}

// The contract's output as Bitcoin Core sees it. The reference is raw hex, a
// txid Core can find, or "txid:vout" -- what the chat sends, since a funding
// transaction can be bigger than a message and Core's own gettxout says all
// that matters: how much, to which script, how deep. nValue is -1 when Core
// does not see the output unspent (spent, or not on its chain).
struct BtcContractOut
{
    uint256 txid;
    unsigned int n = 0;
    int64 nValue = -1;
    bool fUnspent = false;
    int nConfirmations = 0;
};

static BtcContractOut BtcResolveContract(const json& v, const CScript& contract)
{
    BtcContractOut o;
    if (btcswap::UsingLight())
    {
        json found = btclight::Find(contract, v.is_string() ? v.get<string>() : "", false);
        o.txid = uint256(found["contractTxid"].get<string>());
        o.n = found["vout"].get<int>() < 0 ? 0 : found["vout"].get<unsigned int>();
        o.fUnspent = found["unspent"].get<bool>();
        o.nConfirmations = found["confirmations"].get<int>();
        if (o.fUnspent) o.nValue = AmountFromValue(found["amount"]);
        return o;
    }
    string s = v.is_string() ? v.get<string>() : string();
    size_t colon = s.find(':');
    int64 nFromTx = -1;
    if (colon == 64 && IsHex(s.substr(0, 64)) && colon + 1 < s.size() &&
        s.find_first_not_of("0123456789", colon + 1) == string::npos && s.size() - colon <= 7)
    {
        o.txid = uint256(s.substr(0, 64));
        o.n = (unsigned int)atoi(s.c_str() + colon + 1);
    }
    else
    {
        CTransaction tx = BtcContractTx(v);
        o.txid = tx.GetHash();
        o.n = BtcContractOutput(tx, contract);
        nFromTx = tx.vout[o.n].nValue;
    }
    json out = BtcCall("gettxout", json::array({ o.txid.GetHex(), (int)o.n, true }));
    if (out.is_object())
    {
        CScript p2sh;
        p2sh.SetPayToScriptHash(contract);
        string strScript = out.contains("scriptPubKey") && out["scriptPubKey"].is_object() &&
                           out["scriptPubKey"].contains("hex") ? out["scriptPubKey"]["hex"].get<string>() : string();
        if (strScript != HexStr(p2sh.begin(), p2sh.end(), false))
            throw runtime_error("that output does not pay this contract");
        o.fUnspent = true;
        o.nValue = AmountFromValue(out["value"]);
        o.nConfirmations = out.contains("confirmations") && out["confirmations"].is_number_integer()
                               ? out["confirmations"].get<int>() : 0;
    }
    else if (nFromTx >= 0)
        o.nValue = -1;     // the transaction says how much, but Core does not see it unspent
    return o;
}

// btcauditcontract <contract> <contract tx hex or txid>
// What a participant checks before locking anything: the coins are on OUR
// Bitcoin node's chain, unspent, confirmed, to OUR key, with time left.
static json rpc_btcauditcontract(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("btcauditcontract <contract hex> <contract transaction hex or txid>");
    btcswap::Chain chain = RequireBitcoin();
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    BtcContractOut o = BtcResolveContract(p.size() > 1 ? p[1] : json(""), contract);
    json j = BtcContractJson(chain, c, contract);
    j["contractTxid"] = o.txid.GetHex();
    j["vout"] = (int)o.n;
    // Only what Core sees on its own chain counts: an output it does not see
    // unspent is worth nothing to this side of the swap, whatever a raw
    // transaction claims.
    j["amount"] = o.fUnspent ? json(ValueFromAmount(o.nValue)) : json(nullptr);
    j["unspent"] = o.fUnspent;
    j["confirmations"] = o.nConfirmations;
    j["secondsUntilRefund"] = std::max<int64>(0, c.nLockTime - chain.nMedianTime);
    j["recipientIsMine"] = IsMineAddress(Hash160ToAddress(uint160(c.recipientPkh)));
    return j;
}

static json BtcSpend(const json& p, const vector<unsigned char>* pSecret)
{
    btcswap::Chain chain = RequireBitcoin();
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    BtcContractOut o = BtcResolveContract(p[1], contract);
    if (!o.fUnspent)
        throw runtime_error("the Bitcoin backend does not see that contract output unspent "
                            "(already redeemed or refunded, or not on this chain)");
    if (!pSecret && chain.nMedianTime <= c.nLockTime)
        throw runtime_error(strprintf("the refund opens when Bitcoin's median time passes %s (about %lld minutes)",
                                      UtcText(c.nLockTime).c_str(),
                                      (long long)((c.nLockTime - chain.nMedianTime) / 60 + 1)));
    vector<unsigned char> vchPubKey;
    CKey key;
    KeyForContract(c, pSecret != NULL, key, vchPubKey);

    json addr;
    CScript scriptTo;
    int64 nFeeRate = btcswap::FeeRatePerKvB();
    if (btcswap::UsingLight())
    {
        size_t destination = pSecret ? 3 : 2;
        if (p.size() <= destination || !p[destination].is_string())
            throw runtime_error("Bitcoin light needs your Bitcoin destination address as the last parameter");
        addr = p[destination];
        string err;
        if (!btclight::Destination(chain, addr.get<string>(), scriptTo, err)) throw runtime_error(err);
        // The light client has no fee estimate and no memory pool to say a
        // spend went in. A spend that sits unconfirmed is made again with a
        // higher rate (BTC per 1000 vbytes) after the destination.
        if (p.size() > destination + 1 && !p[destination + 1].is_null())
        {
            nFeeRate = AmountFromValue(p[destination + 1]);
            if (nFeeRate < 1000 || nFeeRate > COIN / 100)
                throw runtime_error("fee rate out of range (0.00001 to 0.01 BTC per 1000 vbytes)");
        }
    }
    else
    {
        addr = BtcCall("getnewaddress", json::array());
        json info = BtcCall("getaddressinfo", json::array({ addr }));
        if (!info.is_object() || !info.contains("scriptPubKey") || !info["scriptPubKey"].is_string())
            throw runtime_error("Bitcoin Core gave no address to be paid to");
        vector<unsigned char> vchTo = ParseHex(info["scriptPubKey"].get<string>());
        scriptTo = CScript(vchTo.begin(), vchTo.end());
    }

    CTransaction tx;
    int64 nFee = 0;
    string err;
    if (!btcswap::BuildSpend(contract, COutPoint(o.txid, o.n), o.nValue, scriptTo,
                             key, vchPubKey, pSecret, nFeeRate, tx, nFee, err))
        throw runtime_error(err);
    CDataStream ss(SER_NETWORK);
    ss << tx;
    string strHex = HexStr(ss.begin(), ss.end(), false);
    json txid = BtcCall("sendrawtransaction", json::array({ strHex }));
    json j;
    j["txid"] = txid;
    j["tx"] = strHex;
    j["amount"] = ValueFromAmount(o.nValue - nFee);
    j["fee"] = ValueFromAmount(nFee);
    j["feeRatePerKvB"] = ValueFromAmount(nFeeRate);
    j["to"] = addr;
    // Core checked it into its memory pool; the light client only sent it.
    j["awaitingConfirmation"] = btcswap::UsingLight();
    return j;
}

// btcredeem <contract> <contract tx hex or txid> <secret>
static json rpc_btcredeem(const json& p)
{
    if (p.size() < 3 || !p[2].is_string())
        throw runtime_error("btcredeem <contract hex> <contract transaction hex or txid> <secret hex> [Bitcoin destination] [fee rate]");
    string strSecret = p[2].get<string>();
    if (strSecret.size() != 64 || !IsHex(strSecret))
        throw runtime_error("the secret is 64 hex characters");
    vector<unsigned char> secret = ParseHex(strSecret);
    json j = BtcSpend(p, &secret);
    LogSwap(json{{"redeemed", j["txid"]}, {"chain", "bitcoin"}});
    return j;
}

// btcrefund <contract> <contract tx hex or txid>
static json rpc_btcrefund(const json& p)
{
    if (p.size() < 2)
        throw runtime_error("btcrefund <contract hex> <contract transaction hex or txid> [Bitcoin destination] [fee rate]");
    json j = BtcSpend(p, NULL);
    LogSwap(json{{"refunded", j["txid"]}, {"chain", "bitcoin"}});
    return j;
}

// btcfindsecret <contract> <contract tx hex or txid> [from height]
// Has the other side redeemed our Bitcoin contract -- and so shown the
// secret? Looks in Core's memory pool, then in the blocks from `from height`
// (default: the last 400, more than a 48-hour lock). Without asking anyone:
// a participant who never hears from the initiator again still gets the
// secret off the chain.
static json rpc_btcfindsecret(const json& p)
{
    if (p.size() < 2)
        throw runtime_error("btcfindsecret <contract hex> <contract transaction hex or txid> [from height]");
    btcswap::Chain chain = RequireBitcoin();
    CScript contract;
    swap::Contract c = ContractFromParam(p[0], contract);
    if (btcswap::UsingLight()) return btclight::Find(contract, p[1].get<string>(), true);
    BtcContractOut o = BtcResolveContract(p[1], contract);
    unsigned int n = o.n;
    string strTxid = o.txid.GetHex();
    COutPoint outpoint(o.txid, n);

    json j;
    if (o.fUnspent)
    {
        j["spent"] = false;
        return j;
    }
    j["spent"] = true;

    vector<CTransaction> vCandidates;
    json r;
    string err;
    if (btcswap::Call("gettxspendingprevout", json::array({ json::array({ json{{"txid", strTxid}, {"vout", (int)n}} }) }), r, err) &&
        r.is_array() && !r.empty() && r[0].is_object() && r[0].contains("spendingtxid"))
    {
        json raw;
        CTransaction tx;
        if (btcswap::Call("getrawtransaction", json::array({ r[0]["spendingtxid"] }), raw, err) && raw.is_string() &&
            btcswap::ParseTx(ParseHex(raw.get<string>()), tx))
            vCandidates.push_back(tx);
    }
    int nFrom = p.size() >= 3 && p[2].is_number_integer() ? p[2].get<int>() : std::max(0, chain.nBlocks - 400);
    for (int h = chain.nBlocks; vCandidates.empty() && h >= nFrom; h--)
    {
        json hash = BtcCall("getblockhash", json::array({ h }));
        json raw = BtcCall("getblock", json::array({ hash, 0 }), 64 * 1024 * 1024);
        vector<CTransaction> txs;
        if (!raw.is_string() || !btcswap::ParseBlockTxs(ParseHex(raw.get<string>()), txs))
            throw runtime_error(strprintf("Bitcoin block %d does not decode", h));
        for (size_t i = 0; i < txs.size(); i++)
            for (size_t k = 0; k < txs[i].vin.size(); k++)
                if (txs[i].vin[k].prevout == outpoint)
                {
                    vCandidates.push_back(txs[i]);
                    j["height"] = h;
                }
    }
    if (vCandidates.empty())
    {
        j["found"] = false;
        return j;
    }
    const CTransaction& spend = vCandidates[0];
    j["found"] = true;
    j["txid"] = spend.GetHash().GetHex();
    for (size_t k = 0; k < spend.vin.size(); k++)
    {
        vector<unsigned char> secret;
        if (spend.vin[k].prevout == outpoint && swap::ExtractSecret(spend.vin[k].scriptSig, c.secretHash, secret))
        {
            j["secret"] = HexStr(secret.begin(), secret.end(), false);
            return j;
        }
    }
    j["refunded"] = true;     // spent without the secret: the refund path
    return j;
}

static json rpc_help(const json&)
{
    return "getinfo getblockcount getblockhash getblock getnewaddress validateaddress "
           "getbalance sendtoaddress estimatefee settxfee bumpfee createinvoice getinvoice listinvoices cancelinvoice "
           "gettransaction listtransactions listsinceblock "
           "createmultisig addmultisigaddress decodescript listunspent createrawtransaction "
           "decoderawtransaction getrawtransaction signrawtransaction sendrawtransaction "
           "swapinitiate swapparticipate swapauditcontract swapredeem swaprefund swapextractsecret swapfindsecret "
           "btcswapinfo btcnewaddress btcvalidatedestination btcinitiate btcparticipate btcauditcontract btcredeem btcrefund btcfindsecret "
           "gettorinfo settorbridges gettreasuryinfo donate sendburn help";
}

struct RpcEntry { const char* name; RpcMethod fn; };
static const RpcEntry kMethods[] = {
    { "getinfo",          rpc_getinfo },
    { "gettorinfo",       rpc_gettorinfo },
    { "settorbridges",    rpc_settorbridges },
    { "getblockcount",    rpc_getblockcount },
    { "getblockhash",     rpc_getblockhash },
    { "getblock",         rpc_getblock },
    { "getnewaddress",    rpc_getnewaddress },
    { "validateaddress",  rpc_validateaddress },
    { "getbalance",       rpc_getbalance },
    { "sendtoaddress",    rpc_sendtoaddress },
    { "estimatefee",      rpc_estimatefee },
    { "createinvoice",    rpc_createinvoice },
    { "getinvoice",       rpc_getinvoice },
    { "listinvoices",     rpc_listinvoices },
    { "cancelinvoice",    rpc_cancelinvoice },
    { "settxfee",         rpc_settxfee },
    { "bumpfee",          rpc_bumpfee },
    { "donate",           rpc_donate },
    { "sendburn",         rpc_sendburn },
    { "gettreasuryinfo",  rpc_gettreasuryinfo },
    { "gettransaction",   rpc_gettransaction },
    { "listtransactions", rpc_listtransactions },
    { "listsinceblock",   rpc_listsinceblock },
    { "createmultisig",   rpc_createmultisig },
    { "addmultisigaddress", rpc_addmultisigaddress },
    { "decodescript",     rpc_decodescript },
    { "listunspent",      rpc_listunspent },
    { "createrawtransaction", rpc_createrawtransaction },
    { "decoderawtransaction", rpc_decoderawtransaction },
    { "getrawtransaction", rpc_getrawtransaction },
    { "signrawtransaction", rpc_signrawtransaction },
    { "sendrawtransaction", rpc_sendrawtransaction },
    { "swapinitiate",     rpc_swapinitiate },
    { "swapparticipate",  rpc_swapparticipate },
    { "swapauditcontract", rpc_swapauditcontract },
    { "templatehash",     rpc_templatehash },
    { "spendscript",      rpc_spendscript },
    { "vaultcreate",      rpc_vaultcreate },
    { "vaultunvault",     rpc_vaultunvault },
    { "vaultwithdraw",    rpc_vaultwithdraw },
    { "vaultrecover",     rpc_vaultrecover },
    { "ctvbatch",         rpc_ctvbatch },
    { "ctvexpand",        rpc_ctvexpand },
    { "listv4contracts",  rpc_listv4contracts },
    { "inheritcreate",    rpc_inheritcreate },
    { "inheritinfo",      rpc_inheritinfo },
    { "inheritrenew",     rpc_inheritrenew },
    { "inheritcancel",    rpc_inheritcancel },
    { "inheritpackage",   rpc_inheritpackage },
    { "inheritimport",    rpc_inheritimport },
    { "inheritclaim",     rpc_inheritclaim },
    { "swapredeem",       rpc_swapredeem },
    { "swaprefund",       rpc_swaprefund },
    { "swapextractsecret", rpc_swapextractsecret },
    { "swapfindsecret",   rpc_swapfindsecret },
    { "btcswapinfo",      rpc_btcswapinfo },
    { "btcvalidatedestination", rpc_btcvalidatedestination },
    { "btcnewaddress",    rpc_btcnewaddress },
    { "btcinitiate",      rpc_btcinitiate },
    { "btcparticipate",   rpc_btcparticipate },
    { "btcauditcontract", rpc_btcauditcontract },
    { "btcredeem",        rpc_btcredeem },
    { "btcrefund",        rpc_btcrefund },
    { "btcfindsecret",    rpc_btcfindsecret },
    { "help",             rpc_help },
};

static json Dispatch(const json& req)
{
    json id = req.contains("id") ? req["id"] : json(nullptr);
    json reply;
    reply["id"] = id;
    try
    {
        if (!req.contains("method") || !req["method"].is_string())
            throw runtime_error("missing method");
        string method = req["method"].get<string>();
        json params = json::array();
        if (req.contains("params"))
        {
            // Positional only. Silently treating an object as "no params"
            // would turn a caller's typo into a call with defaults -- for
            // sendtoaddress, that is the wrong kind of forgiving.
            if (!req["params"].is_array())
                throw runtime_error("params must be an array");
            params = req["params"];
        }

        RpcMethod fn = NULL;
        for (size_t i = 0; i < ARRAYLEN(kMethods); i++)
            if (method == kMethods[i].name) { fn = kMethods[i].fn; break; }
        if (!fn)
            throw runtime_error("method not found");

        // Chain state and wallet state are read together; hold both the whole
        // way through, the same order the rest of the node takes them.
        CRITICAL_BLOCK(cs_main)
        {
            reply["result"] = fn(params);
            reply["error"]  = nullptr;
        }
    }
    catch (const std::exception& e)
    {
        reply["result"] = nullptr;
        reply["error"]  = json{{"code", -1}, {"message", e.what()}};
    }
    return reply;
}

// ---------------------------------------------------------------------------
// http

static bool RecvAll(btf_socket_t s, string& out, int nTimeoutSecs)
{
    // Read headers, then exactly Content-Length bytes of body. No keep-alive:
    // one request, one response, close -- which is how every RPC client that
    // targets bitcoind behaves anyway.
    char buf[4096];
    int64 nStart = GetTime();
    size_t nHeaderEnd = string::npos, nBodyLen = 0;
    while (GetTime() - nStart < nTimeoutSecs)
    {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) return false;
        out.append(buf, r);
        if (out.size() > 1 << 20) return false;                  // nobody needs a 1 MB request
        if (nHeaderEnd == string::npos)
        {
            nHeaderEnd = out.find("\r\n\r\n");
            if (nHeaderEnd == string::npos) continue;
            string hdr = out.substr(0, nHeaderEnd);
            string lower = hdr;
            for (size_t i = 0; i < lower.size(); i++) lower[i] = (char)tolower((unsigned char)lower[i]);
            size_t p = lower.find("content-length:");
            if (p != string::npos)
                nBodyLen = (size_t)atoi(hdr.c_str() + p + 15);
        }
        if (out.size() >= nHeaderEnd + 4 + nBodyLen)
            return true;
    }
    return false;
}

static void SendHttp(btf_socket_t s, int nCode, const string& strBody)
{
    const char* pszText = nCode == 200 ? "OK" : nCode == 401 ? "Unauthorized" :
                          nCode == 400 ? "Bad Request" : nCode == 404 ? "Not Found" : "Error";
    string resp = strprintf("HTTP/1.1 %d %s\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %u\r\n"
                            "Connection: close\r\n"
                            "%s"
                            "\r\n",
                            nCode, pszText, (unsigned)strBody.size(),
                            nCode == 401 ? "WWW-Authenticate: Basic realm=\"bitflash\"\r\n" : "");
    resp += strBody;
    size_t off = 0;
    while (off < resp.size())
    {
        int w = send(s, resp.data() + off, (int)(resp.size() - off), BTF_SEND_FLAGS);
        if (w <= 0) break;
        off += w;
    }
}

static bool Authorised(const string& strHeaders)
{
    string lower = strHeaders;
    for (size_t i = 0; i < lower.size(); i++) lower[i] = (char)tolower((unsigned char)lower[i]);
    size_t p = lower.find("authorization: basic ");
    if (p == string::npos) return false;
    size_t e = strHeaders.find("\r\n", p);
    string b64 = strHeaders.substr(p + 21, e == string::npos ? string::npos : e - (p + 21));
    while (!b64.empty() && isspace((unsigned char)b64[b64.size()-1])) b64.erase(b64.size()-1);
    return ConstantTimeEqual(Base64Decode(b64), g_rpcUser + ":" + g_rpcPassword);
}

static void HandleConnection(btf_socket_t s)
{
    string req;
    if (!RecvAll(s, req, 30))
    {
        rpc_close(s);
        return;
    }
    size_t nHeaderEnd = req.find("\r\n\r\n");
    string headers = req.substr(0, nHeaderEnd);
    string body    = req.substr(nHeaderEnd + 4);

    if (!Authorised(headers))
    {
        // Same answer whether the user is unknown or the password is wrong,
        // and a pause so a brute force at loopback speed is still slow.
        Sleep(250);
        SendHttp(s, 401, "");
        rpc_close(s);
        return;
    }
    if (headers.compare(0, 5, "POST ") != 0)
    {
        SendHttp(s, 404, "");
        rpc_close(s);
        return;
    }

    json reply;
    try
    {
        json parsed = json::parse(body);
        if (parsed.is_array())
        {
            // Batch: one reply per request, in order. Capped, because every
            // entry takes the chain lock in turn and a single request with
            // thousands of them would hold the node's main lock for as long
            // as it liked.
            if (parsed.size() > 100)
                throw runtime_error("batch too large (max 100)");
            reply = json::array();
            foreach(const json& r, parsed)
                reply.push_back(Dispatch(r));
        }
        else
            reply = Dispatch(parsed);
    }
    catch (const json::parse_error&)
    {
        reply = json{{"result", nullptr}, {"error", json{{"code", -32700}, {"message", "parse error"}}}, {"id", nullptr}};
    }
    catch (const std::exception& e)
    {
        reply = json{{"result", nullptr}, {"error", json{{"code", -32600}, {"message", e.what()}}}, {"id", nullptr}};
    }
    SendHttp(s, 200, reply.dump());
    rpc_close(s);
}

void ThreadJsonRpcServer(void* parg)
{
    btf_socket_t lsock = (btf_socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if (lsock == INVALID_SOCKET)
    {
        printf("JSON-RPC: could not create listener socket\n");
        return;
    }
    int one = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      // loopback, and only loopback
    addr.sin_port = htons((unsigned short)g_rpcPort);
    if (::bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        printf("JSON-RPC: could not bind 127.0.0.1:%d\n", g_rpcPort);
        rpc_close(lsock);
        return;
    }
    if (listen(lsock, 16) != 0)
    {
        printf("JSON-RPC: could not listen on %d\n", g_rpcPort);
        rpc_close(lsock);
        return;
    }
    printf("JSON-RPC listening on 127.0.0.1:%d\n", g_rpcPort);

    while (!fShutdown)
    {
        fd_set fds; FD_ZERO(&fds); FD_SET(lsock, &fds);
        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        int r = select((int)lsock + 1, &fds, NULL, NULL, &tv);
        if (r <= 0) continue;
        struct sockaddr_in peer; socklen_t len = sizeof(peer);
        btf_socket_t s = (btf_socket_t)accept(lsock, (struct sockaddr*)&peer, &len);
        if (s == INVALID_SOCKET) continue;
        // Belt and braces on top of the bind: even if something ever changed
        // the bind, a request from off-box is refused here.
        if (peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        {
            rpc_close(s);
            continue;
        }
        HandleConnection(s);
    }
    rpc_close(lsock);
    printf("JSON-RPC stopped\n");
}
