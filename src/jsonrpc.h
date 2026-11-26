// JSON-RPC over HTTP, the interface an exchange integrates a coin through.
//
// Off unless both -rpcuser and -rpcpassword are given. Binds 127.0.0.1 and
// nothing else: the daemon runs on the machine that talks to it, and a wallet
// that can be told to spend over the network should not be reachable from one.
#ifndef BITFLASH_JSONRPC_H
#define BITFLASH_JSONRPC_H

#include <string>
#include <vector>

// Hand over the -rpcuser / -rpcpassword / -rpcport values (the flag reader is
// private to main_gui.cpp). Returns true when the server should start.
bool JsonRpcConfigure(const std::string& strUser, const std::string& strPassword,
                      const std::string& strPort);

// Listener thread. Serves one request at a time; exchange integrations poll
// sequentially and the wallet lock would serialise them anyway.
// -chatwallet: the same server, on 127.0.0.1, with a random password written
// to <datadir>/.cookie for local tools -- btfchat paying from this wallet.
bool JsonRpcConfigureCookie(const std::string& strPort);
void ThreadJsonRpcServer(void* parg);

// The HTTP side, apart from the socket so the self-test and the fuzz
// harnesses reach exactly what a caller does.
//
// Whether buf holds a whole request: 1 (nTotalOut = headers + body length),
// 0 (not yet), -1 (never: a Content-Length that is not a plain number, two
// that disagree, or more than a request may be).
int JsonRpcRequestLength(const std::string& buf, size_t& nTotalOut);
// One complete request: the credentials checked first (401 without the
// right ones, before anything else is looked at), then POST (404), then the
// JSON-RPC call or batch. Returns the HTTP status; strReplyOut is the body.
int JsonRpcHandleRequest(const std::string& req, std::string& strReplyOut);
// Self-tests: a request's JSON, parsed, every string value wiped as a call's
// params are once it is answered (a pool call's password among them), and
// written back out.
std::string JsonRpcWipeStringsForTest(const std::string& strJson);

// The Everpool screen of the wallet window creates pools through exactly
// what `poolcreate everpool` runs (CreateEverpool): each field is the text
// the call would take for that parameter, an empty one is left out (its
// default), and the defaults, the checks and the 1 BTF burn are the call's
// own. The fee is typed as a percentage and handed over as "feebps".
struct EverpoolCreateParams
{
    std::string strName, strSpacing, strWindow, strRetarget, strFloor, strUncleDepth, strUnclePct,
                strFeePercent, strFeeAddress;
};
struct EverpoolCreateResult
{
    std::string strName, strId, strFingerprint;
    unsigned int nSpacing, nWindow, nRetarget, nFloor, nUncleDepth, nUnclePct, nFeeBps;
    std::string strFeePercent;         // "1.50%"
    std::string strFeeAddress;         // empty: no fee
    long long nBurn;                   // satoshis
    bool fPoolZero;                    // the record is pool zero's own
    std::vector<std::string> vSameName; // fingerprints of the pools named alike ("pool zero" for it)
    bool fRecorded;                    // already on the chain
    std::string strRecordedStatus;
    int nRecordedHeight;
    bool fIndexSynced;
    bool fBurnsOpen;                   // PoolBurnsOpen(): "send" may burn here
    std::string strSendNote;           // what the preview says about sending
    bool fSent;
    std::string strTxid, strStatus;
    EverpoolCreateResult() : nSpacing(0), nWindow(0), nRetarget(0), nFloor(0), nUncleDepth(0), nUnclePct(0),
                             nFeeBps(0), nBurn(0), fPoolZero(false), fRecorded(false), nRecordedHeight(-1),
                             fIndexSynced(false), fBurnsOpen(false), fSent(false) {}
};
// fSend false: the preview (the call's "dryrun"), nothing sent; true: the
// call's "send". False with the call's own error in errOut.
bool EverpoolCreate(const EverpoolCreateParams& p, bool fSend, EverpoolCreateResult& out, std::string& errOut);
// A fee typed as a percentage ("1", "0.5", "1.25": at most two decimals) in
// basis points; false for anything else.
bool PoolFeePercentToBps(const std::string& s, unsigned int& nBpsOut);
// What poollist compares names by (names alike: equal once case, '-' and
// '_' are set aside).
std::string PoolLookalikeKey(const std::string& s);

// Renews the inheritances this wallet owns before they open to the heir
// (docs/inheritance.md). Runs whether or not the RPC server does.
void ThreadInheritance(void* parg);
int InheritanceSelfTest();   // -selftest=inheritance
// -selftest=wallet-rpc-v4, run inside a temporary data directory: vault
// recovery follows the chain, CTV templates are checked against mining
// policy, the rules-v4 upgrade hooks are policy-refused, signrawtransaction's
// temporary keys and getbalance minconf 1.
int WalletRpcV4SelfTest();

#endif
