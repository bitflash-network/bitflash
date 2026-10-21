// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// One JSON-RPC call over HTTP to a program on this same machine: the chat
// talking to the Bitflash wallet, and the wallet talking to Bitcoin Core for
// the Bitcoin half of a swap. 127.0.0.1 only, by construction -- the address
// is not a parameter, so nothing built on this can be pointed off the machine.

#ifndef BITFLASH_RPCCLIENT_H
#define BITFLASH_RPCCLIENT_H

#include <string>

// util.h redefines snprintf as a macro, which breaks nlohmann/json; put it
// back afterwards for whoever includes this after util.h.
#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")

struct LoopbackRpc
{
    int nPort = 0;
    std::string strPath = "/";       // "/wallet/<name>" for a Bitcoin Core wallet
    std::string strAuth;             // "user:password", as in a .cookie
    std::string strWho = "the wallet";   // for the error messages
    size_t nMaxBytes = 1024 * 1024;  // a raw Bitcoin block is a few MB
    int nTimeoutSecs = 30;
};

// Read "user:password" from a .cookie file. errOut says which file and why.
bool ReadRpcCookie(const std::string& path, std::string& authOut, std::string& errOut);

// On failure errOut says why in words fit for the screen; for an error the
// server answered with, it is that error's message, and *pnCodeOut (when
// given) its code.
bool LoopbackRpcCall(const LoopbackRpc& to, const std::string& method, const nlohmann::json& params,
                     nlohmann::json& resultOut, std::string& errOut, int* pnCodeOut = NULL);

#endif
