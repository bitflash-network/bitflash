// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The Bitcoin half of an atomic swap, done by this wallet against the
// person's own Bitcoin Core.
//
// WHY NOT btcatomicswap. Decred's tool signs with `dumpprivkey`, which only a
// legacy wallet answers, and Bitcoin Core removed legacy wallets in 30.0: on a
// current Core it cannot redeem or refund. So the key that the Bitcoin
// contract pays to is a key of THIS wallet (its Hash160 is all the contract
// holds, and Bitcoin's P2PKH uses the same curve and the same Hash160), and
// this wallet signs. Bitcoin Core is asked only for what any version does:
// send to an address (funding the contract), a fresh address of its own
// (where redeemed or refunded coins go), the fee rate, the chain, and
// relaying the transaction. Any Core from 25 on, descriptor wallet or not.
//
// The contract is still Decred's, byte for byte (swap.h), so the person on
// the other side can be running btcatomicswap and nothing changes for them.
//
// WHAT IS CHECKED ON BITCOIN'S OWN CHAIN. A contract the other side says they
// funded is looked up in OUR Bitcoin Core: unspent, how many confirmations,
// how much. A raw transaction they send proves nothing until our node has it
// in a block.
//
// THE NETWORKS MUST MATCH. BTF on mainnet trades only against Bitcoin's main
// chain, testnet BTF only against a test chain (testnet3/4, signet, regtest):
// otherwise someone pays real BTF with regtest coins they minted for free.
//
// Loopback only: Bitcoin Core is reached on 127.0.0.1 (rpcclient.h).

#ifndef BITFLASH_BTCSWAP_H
#define BITFLASH_BTCSWAP_H

#include "rpcclient.h"

#include <string>
#include <vector>

namespace btcswap
{

// Locks on Bitcoin, in seconds of median time past, as btcatomicswap does.
static const int64 INITIATOR_LOCK_SECS   = 48 * 3600;
static const int64 PARTICIPANT_LOCK_SECS = 24 * 3600;

// Where Bitcoin Core is. Empty / 0 means the default for the chain:
// -btcchain main (testnet4 when this is Bitflash testnet), the chain's
// default RPC port, Core's default data directory (its .cookie), and the
// default wallet. A -btcrpcuser/-btcrpcpassword pair replaces the cookie.
// strFeeRate: BTC per 1000 vbytes when Core has no estimate (regtest).
void Configure(const std::string& strChain, const std::string& strDataDir, int nPort,
               const std::string& strWallet, const std::string& strUser, const std::string& strPassword,
               const std::string& strFeeRate);

struct Chain
{
    std::string name;            // as getblockchaininfo says: main, test, testnet4, signet, regtest
    bool fMain = false;
    unsigned char pkhVersion = 0;
    unsigned char shVersion = 5;
    int nBlocks = 0;
    int64 nMedianTime = 0;
};

bool UsingLight();

// One call to Bitcoin Core. nMaxBytes: a raw block needs more than the default.
bool Call(const std::string& method, const nlohmann::json& params, nlohmann::json& resultOut,
          std::string& errOut, size_t nMaxBytes = 4 * 1024 * 1024, int* pnCodeOut = NULL);

// Ask Core which chain it is on, and refuse a chain that does not go with
// this Bitflash network or with -btcchain.
bool CheckChain(Chain& out, std::string& errOut);

std::string PkhToAddress(const Chain& chain, const std::vector<unsigned char>& pkh);
// Only P2PKH: the contract holds a Hash160 of a key, nothing else.
bool AddressToPkh(const Chain& chain, const std::string& addr, std::vector<unsigned char>& pkhOut,
                  std::string& errOut);
std::string ScriptAddress(const Chain& chain, const CScript& redeemScript);

// A Bitcoin transaction, witness or not, read into the parts Bitflash's
// CTransaction has (the witness is dropped -- the txid does not cover it).
// ParseTx: the whole buffer is one transaction.
bool ParseTx(const std::vector<unsigned char>& raw, CTransaction& txOut);
// One transaction at `pos`, which is moved past it.
bool ParseTxAt(const std::vector<unsigned char>& raw, size_t& pos, CTransaction& txOut);
// Every transaction in a raw block.
bool ParseBlockTxs(const std::vector<unsigned char>& raw, std::vector<CTransaction>& txsOut);

// Fee rate to use, satoshis per 1000 vbytes: Core's estimate for 6 blocks,
// else the configured one; never under 1 sat/vbyte.
int64 FeeRatePerKvB();

// Build and sign the spend of a contract output: redeem when pSecret is
// given, else refund (nLockTime set to the contract's). One output, to
// scriptTo, the fee taken from the contract's coins. Checked against the
// contract before it is returned.
bool BuildSpend(const CScript& contract, const COutPoint& outpoint, int64 nValue, const CScript& scriptTo,
                CKey& key, const std::vector<unsigned char>& vchPubKey,
                const std::vector<unsigned char>* pSecret, int64 nFeeRatePerKvB,
                CTransaction& txOut, int64& nFeeOut, std::string& errOut);

} // namespace btcswap

#endif
