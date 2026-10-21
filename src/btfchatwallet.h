// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The chat's link to the person's own Bitflash wallet, so money can move inside
// a conversation without the chat ever holding a coin or a chain.
//
// HOW IT CONNECTS. The wallet, started with -chatwallet, opens its JSON-RPC on
// 127.0.0.1 only and writes a random password to a file in its own data
// directory (.cookie, the way bitcoind does it). btfchat reads that file and
// talks to the wallet on the loopback interface. Nothing crosses the network,
// so this is the one connection the chat makes that does not go through Tor --
// it never leaves the machine.
//
// WHO CAN USE IT. Anything running as the same user can read the cookie and
// spend from the wallet, exactly as with bitcoind's. That is why it is off
// until the wallet is started with -chatwallet, and why the chat says plainly
// which wallet it is linked to.

#ifndef BITFLASH_BTFCHATWALLET_H
#define BITFLASH_BTFCHATWALLET_H

#include "rpcclient.h"

#include <string>
#include <stdint.h>

namespace btfchat
{

// Where to find the wallet: its data directory (the cookie is read from there,
// or from its testnet/ when this is testnet) and the RPC port. Empty directory
// means the default Bitflash one; port 0 means the network's default.
void WalletLinkConfigure(const std::string& strWalletDir, int nPort);

// Is a wallet answering? `strStatusOut` says which, or why not, for the screen.
bool WalletLinked(std::string& strStatusOut);

// A fresh receiving address from the wallet.
bool WalletNewAddress(std::string& addrOut, std::string& errOut);

// Pay `amount` satoshis to `addr`. The wallet's own fee rule applies.
bool WalletPay(const std::string& addr, int64_t amount, std::string& txidOut, std::string& errOut);

// Burn `amount` satoshis into an OP_RETURN carrying `dataHex` (a public
// community listing).
bool WalletBurn(int64_t amount, const std::string& dataHex, std::string& txidOut, std::string& errOut);

// What the wallet knows of a transaction: how much of it reached us and with
// how many confirmations. False when the wallet has never seen it.
bool WalletLookup(const std::string& txid, int64_t& receivedOut, int& confirmationsOut,
                  std::string& errOut);

// Any call, for the swap engine (btfchatswap.h): the swap* and btc* calls,
// where the wallet does the work on both chains.
bool WalletRpc(const std::string& method, const nlohmann::json& params, nlohmann::json& resultOut,
               std::string& errOut);

} // namespace btfchat

#endif
