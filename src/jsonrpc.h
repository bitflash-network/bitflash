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

// Renews the inheritances this wallet owns before they open to the heir
// (docs/inheritance.md). Runs whether or not the RPC server does.
void ThreadInheritance(void* parg);
int InheritanceSelfTest();   // -selftest=inheritance

#endif
