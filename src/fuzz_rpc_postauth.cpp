// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the JSON-RPC server past authentication: what a caller who
// holds the credentials (an exchange's software, the chat's cookie) can make
// the node parse. The input is a request body. It goes into a complete,
// correctly authenticated HTTP request and through JsonRpcHandleRequest(),
// the function HandleConnection() calls: the JSON parser, single calls and
// batches, the dispatcher, and the parameter decoding of the methods that
// take hex, amounts, addresses and objects.
//
// No method that spends, writes the wallet or anything else, or dials out
// runs: in this binary alone (-DBITFLASH_FUZZ) the dispatcher asks
// g_pfnFuzzRpcAllow first, and kAllowed below is the whole list. Everything
// else answers "method not found", as an unknown method does.
//
// Input layout: byte 0 selects
//   0  the rest is the request body
//   1  a swap chain's address: byte 1 picks the chain and network (kNets),
//      the rest is the address, handed to btclight::Destination() as the
//      coinvalidatedestination method does once it knows the chain (the
//      method itself first asks the chain's node, which a harness cannot)
//
// The node's chain (genesis only) and an empty wallet live in a private
// temporary data directory. BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes one
// request per allowed method, with real hashes, hex and addresses, and exits.

#include <nlohmann/json.hpp>
#include "headers.h"
#include "jsonrpc.h"
#include "btclight.h"
#include "btcswap.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

using json = nlohmann::json;

static void FuzzRpcInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzRpcInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

extern bool (*g_pfnFuzzRpcAllow)(const char* pszMethod);   // jsonrpc.cpp, fuzz builds only

// Methods that only read and parse. Not here: anything that sends, funds,
// signs and broadcasts, writes the wallet, the invoice store or the contract
// file, changes a setting, restarts Tor, or calls another chain's node.
static const char* const kAllowed[] = {
    "getinfo", "getblockcount", "getblockhash", "getblock", "validateaddress",
    "createmultisig", "decodescript", "getbalance", "getinvoice", "listinvoices",
    "estimatefee", "gettreasuryinfo", "gettransaction", "listtransactions",
    "listsinceblock", "listunspent", "createrawtransaction", "decoderawtransaction",
    "getrawtransaction", "signrawtransaction", "swapauditcontract", "templatehash",
    "swapextractsecret", "swapfindsecret", "listv4contracts", "inheritinfo",
    "inheritpackage", "gettorinfo", "help",
};

static bool Allowed(const char* pszMethod)
{
    for (size_t i = 0; i < sizeof(kAllowed) / sizeof(kAllowed[0]); i++)
        if (strcmp(kAllowed[i], pszMethod) == 0)
            return true;
    return false;
}

static const char* const kNets[][2] = {
    { "btc", "main" }, { "btc", "test" }, { "btc", "regtest" },
    { "ltc", "main" }, { "ltc", "test" }, { "doge", "main" },
    { "bch", "main" }, { "bch", "test" }, { "xec", "main" },
    { "dgb", "main" }, { "rvn", "main" }, { "rvn", "test" },
};
static const size_t kNumNets = sizeof(kNets) / sizeof(kNets[0]);

static const char* const kUser = "fuzz";
static const char* const kPassword = "fuzz-postauth-password-0123456789";

static void Check(bool f, const char* pszWhat)
{
    if (!f)
    {
        fprintf(stderr, "fuzz-rpc-postauth: %s\n", pszWhat);
        abort();
    }
}

static std::string Base64(const std::string& in)
{
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3)
    {
        unsigned int v = ((unsigned char)in[i] << 16) | ((unsigned char)in[i + 1] << 8) | (unsigned char)in[i + 2];
        out += t[(v >> 18) & 63]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63]; out += t[v & 63];
    }
    if (i + 1 == in.size())
    {
        unsigned int v = (unsigned char)in[i] << 16;
        out += t[(v >> 18) & 63]; out += t[(v >> 12) & 63]; out += "==";
    }
    else if (i + 2 == in.size())
    {
        unsigned int v = ((unsigned char)in[i] << 16) | ((unsigned char)in[i + 1] << 8);
        out += t[(v >> 18) & 63]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63]; out += '=';
    }
    return out;
}

static std::string Request(const std::string& body)
{
    return "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic " +
           Base64(std::string(kUser) + ":" + kPassword) +
           "\r\nContent-Type: application/json\r\nContent-Length: " +
           strprintf("%u", (unsigned)body.size()) + "\r\n\r\n" + body;
}

static void FuzzBody(const std::string& body)
{
    std::string reply;
    int nCode = JsonRpcHandleRequest(Request(body), reply);
    Check(nCode == 200, "an authenticated POST was not answered 200");
    json j;
    try
    {
        j = json::parse(reply);
    }
    catch (...)
    {
        Check(false, "the reply is not JSON");
    }
    Check(j.is_object() || j.is_array(), "the reply is neither a call's answer nor a batch's");
}

static void FuzzDestination(const uint8_t* data, size_t size)
{
    if (size < 1)
        return;
    const char* const* net = kNets[data[0] % kNumNets];
    const btclight::Net* p = btclight::FindNet(net[0], net[1]);
    if (!p)
        return;
    // The chain as btcswap::CheckChain fills it in from the node's answer.
    btcswap::Chain chain;
    chain.coin = net[0];
    chain.name = net[1];
    chain.fMain = chain.name == "main";
    chain.pkhVersion = p->pkhVersion;
    chain.shVersion = p->shVersion;
    chain.cashPrefix = p->cashPrefix;
    chain.fForkId = p->forkId;
    CScript script;
    std::string err;
    std::string address((const char*)data + 1, size - 1);
    if (btclight::Destination(chain, address, script, err))
        Check(!script.empty(), "a valid address gave an empty script");
}

static void WriteSeed(const std::string& strDir, const char* pszName, unsigned char nMode, const std::string& body)
{
    std::string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    fputc(nMode, f);
    fwrite(body.data(), 1, body.size(), f);
    fclose(f);
}

static void WriteCall(const std::string& d, const char* pszName, const json& params)
{
    json req;
    req["jsonrpc"] = "1.0";
    req["id"] = pszName;
    req["method"] = pszName;
    req["params"] = params;
    WriteSeed(d, (std::string("call-") + pszName).c_str(), 0, req.dump());
}

static void WriteSeeds(const std::string& d)
{
    CBlock genesis;
    if (!pindexGenesisBlock || !genesis.ReadFromDisk(pindexGenesisBlock, true))
    {
        fprintf(stderr, "fuzz-rpc-postauth: cannot read the genesis block\n");
        exit(1);
    }
    std::string hashGenesis = pindexGenesisBlock->GetBlockHash().GetHex();
    const CTransaction& cb = genesis.vtx[0];
    std::string txid = cb.GetHash().GetHex();
    CDataStream ss(SER_NETWORK);
    ss << cb;
    std::string txHex = HexStr(ss.begin(), ss.end(), false);
    const CScript& spk = cb.vout[0].scriptPubKey;
    std::string spkHex = HexStr(spk.begin(), spk.end(), false);
    std::string addr = Hash160ToAddress(uint160(1));
    CKey key;
    key.MakeNewKey();
    std::vector<unsigned char> vchPub = key.GetPubKey();
    std::string pubHex = HexStr(vchPub.begin(), vchPub.end(), false);
    std::string addr2 = PubKeyToAddress(vchPub);

    WriteCall(d, "getinfo", json::array());
    WriteCall(d, "getblockcount", json::array());
    WriteCall(d, "getblockhash", json::array({ 0 }));
    WriteCall(d, "getblock", json::array({ hashGenesis }));
    WriteCall(d, "validateaddress", json::array({ addr }));
    WriteCall(d, "createmultisig", json::array({ 1, json::array({ pubHex, addr2 }) }));
    WriteCall(d, "decodescript", json::array({ spkHex }));
    WriteCall(d, "getbalance", json::array({ "*", 1 }));
    WriteCall(d, "getinvoice", json::array({ std::string(32, 'a') }));
    WriteCall(d, "listinvoices", json::array({ "paid" }));
    WriteCall(d, "estimatefee", json::array());
    WriteCall(d, "gettreasuryinfo", json::array());
    WriteCall(d, "gettransaction", json::array({ txid }));
    WriteCall(d, "listtransactions", json::array({ "*", 10, 0 }));
    WriteCall(d, "listsinceblock", json::array({ hashGenesis, 1 }));
    WriteCall(d, "listunspent", json::array({ 0, 9999999, json::array({ addr }) }));
    WriteCall(d, "createrawtransaction",
              json::array({ json::array({ json{{"txid", txid}, {"vout", 0}} }), json{{addr, 1.5}, {addr2, "0.25"}} }));
    WriteCall(d, "decoderawtransaction", json::array({ txHex }));
    WriteCall(d, "getrawtransaction", json::array({ txid, 1 }));
    WriteCall(d, "signrawtransaction",
              json::array({ txHex, json::array({ json{{"txid", txid}, {"vout", 0}, {"scriptPubKey", spkHex}} }),
                            json::array({ std::string(62, '0') + "01" }) }));
    WriteCall(d, "swapauditcontract", json::array({ spkHex, txid }));
    WriteCall(d, "templatehash", json::array({ json{{addr, 1}}, 2, 0xffffffffLL, 0 }));
    WriteCall(d, "swapextractsecret", json::array({ txHex, std::string(64, '0') }));
    WriteCall(d, "swapfindsecret", json::array({ spkHex, txid }));
    WriteCall(d, "listv4contracts", json::array());
    WriteCall(d, "inheritinfo", json::array({ addr }));
    WriteCall(d, "inheritpackage", json::array({ addr }));
    WriteCall(d, "gettorinfo", json::array());
    WriteCall(d, "help", json::array());

    json batch = json::array();
    batch.push_back(json{{"id", 1}, {"method", "getblockcount"}, {"params", json::array()}});
    batch.push_back(json{{"id", json::array({ 1, json{{"a", nullptr}} })}, {"method", "decodescript"}, {"params", json::array({ "51" })}});
    WriteSeed(d, "batch", 0, batch.dump());
    WriteSeed(d, "not-allowed", 0, "{\"method\":\"sendtoaddress\",\"params\":[\"x\",1],\"id\":1}");
    WriteSeed(d, "params-object", 0, "{\"method\":\"help\",\"params\":{},\"id\":null}");
    WriteSeed(d, "garbage", 0, "{\"method\":");

    WriteSeed(d, "dest-btc", 1, std::string(1, (char)0) + "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    WriteSeed(d, "dest-btc-legacy", 1, std::string(1, (char)0) + "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    WriteSeed(d, "dest-ltc", 1, std::string(1, (char)3) + "ltc1qg42tkwuuxefutzxezdkdel39gfstuap288mfea");
    WriteSeed(d, "dest-bch", 1, std::string(1, (char)6) + "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
    WriteSeed(d, "dest-doge", 1, std::string(1, (char)5) + "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L");
}

static void FuzzRpcInit()
{
    SelectChainParams(false);
    if (!LoadBlockIndex())
    {
        fprintf(stderr, "fuzz-rpc-postauth: LoadBlockIndex failed\n");
        abort();
    }
    if (!JsonRpcConfigure(kUser, kPassword, ""))
    {
        fprintf(stderr, "fuzz-rpc-postauth: JsonRpcConfigure failed\n");
        abort();
    }
    g_pfnFuzzRpcAllow = Allowed;

    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // A request may be 1 MB; the parsers meet their limits well before that.
    if (size < 1 || size > 256 * 1024)
        return 0;
    if (data[0] % 2 == 0)
        FuzzBody(std::string((const char*)data + 1, size - 1));
    else
        FuzzDestination(data + 1, size - 1);
    return 0;
}
