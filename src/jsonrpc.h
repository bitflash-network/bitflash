// JSON-RPC over HTTP, the interface an exchange integrates a coin through.
//
// Off unless both -rpcuser and -rpcpassword are given. Binds 127.0.0.1 and
// nothing else: the daemon runs on the machine that talks to it, and a wallet
// that can be told to spend over the network should not be reachable from one.
#ifndef BITFLASH_JSONRPC_H
#define BITFLASH_JSONRPC_H

#include <string>

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
