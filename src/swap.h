// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Atomic swaps: trade BTF for BTC (or LTC, or any coin with the same script)
// with nobody in the middle. Needs rules v3 (P2SH and OP_CHECKLOCKTIMEVERIFY).
//
// THE CONTRACT is the one Decred's atomicswap tools use on every chain they
// support, byte for byte:
//
//   OP_IF
//       OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <secret hash> OP_EQUALVERIFY
//       OP_DUP OP_HASH160 <recipient pubkey hash>
//   OP_ELSE
//       <lock time> OP_CHECKLOCKTIMEVERIFY OP_DROP
//       OP_DUP OP_HASH160 <refund pubkey hash>
//   OP_ENDIF
//   OP_EQUALVERIFY OP_CHECKSIG
//
// The recipient takes the coins by showing a 32-byte secret whose SHA-256 is in
// the script; the other side takes them back after the lock if that never
// happens. Using the same script on both chains is what lets the Bitcoin half
// be done with btcatomicswap, which already exists and has been used for years,
// instead of with anything of ours.
//
// HOW A SWAP GOES (A has BTF, B has BTC):
//   1. A: swapinitiate -- makes the secret, locks BTF for B for 48 hours.
//   2. B: audits A's contract, locks BTC for A for 24 hours under the same
//      secret hash (btcatomicswap participate).
//   3. A: redeems the BTC, which shows the secret on the Bitcoin chain.
//   4. B: reads the secret from that transaction (swapextractsecret) and
//      redeems the BTF.
// Whoever stops answering, the other gets their coins back after their lock.
// The initiator's lock is the longer one so that B always has time to redeem
// after A has revealed the secret.

#ifndef BITFLASH_SWAP_H
#define BITFLASH_SWAP_H

#include <string>
#include <vector>

// Boost before 1.84 calls an unqualified swap() in a template that is only
// valid while no namespace named swap exists. Parse it first: the Bitcoin
// light client's big integers pull it in, and Debian 13 ships Boost 1.83.
#include <boost/version.hpp>
#if BOOST_VERSION < 108400
#include <boost/core/swap.hpp>
#endif

namespace swap
{

static const unsigned int SECRET_BYTES = 32;

// Locks, in blocks of two minutes: 48 hours for the initiator, 24 for the
// participant, as Decred's tools do in time.
static const int INITIATOR_LOCK_BLOCKS   = 48 * 30;
static const int PARTICIPANT_LOCK_BLOCKS = 24 * 30;

struct Contract
{
    std::vector<unsigned char> recipientPkh;   // 20 bytes
    std::vector<unsigned char> refundPkh;      // 20 bytes
    std::vector<unsigned char> secretHash;     // 32 bytes
    int64_t nLockTime;
};

CScript BuildContract(const Contract& c);

// True only for a script of exactly the shape above.
bool ParseContract(const CScript& script, Contract& out);

// The scriptSigs that spend it, through P2SH: the contract is the last push.
CScript RedeemScriptSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey,
                        const std::vector<unsigned char>& secret, const CScript& contract);
CScript RefundScriptSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey,
                        const CScript& contract);

// The secret, from a redeem transaction's scriptSig on either chain: the
// 32-byte push whose SHA-256 is secretHash.
bool ExtractSecret(const CScript& scriptSig, const std::vector<unsigned char>& secretHash,
                   std::vector<unsigned char>& secretOut);

} // namespace swap

#endif
