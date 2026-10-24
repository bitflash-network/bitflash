// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// ECDSA verification for consensus, by libsecp256k1 -- the library Bitcoin
// verifies with -- instead of OpenSSL, whose idea of a valid signature has
// changed between its own versions. Same answers as the OpenSSL path it
// replaces (proved by fuzz-sigcheck, which runs both on the same bytes), and
// several times faster.
#ifndef BITFLASH_SIGCHECK_H
#define BITFLASH_SIGCHECK_H

#include <vector>

// hash32: the 32 bytes OpenSSL was handed, in the same order (the raw memory
// of the uint256). vchSig: DER, without the hash-type byte. vchPubKey:
// compressed, uncompressed or hybrid. A high S is accepted, as OpenSSL did:
// rules v2 refuses it before this is reached, and older blocks carry it.
bool SigCheckEcdsa(const unsigned char* hash32, const std::vector<unsigned char>& vchSig,
                   const std::vector<unsigned char>& vchPubKey);

// BIP340 Schnorr, for OP_CHECKSIGFROMSTACK (rules v4): a 64-byte signature
// over a message of any length (BIP340 allows any), by a 32-byte x-only key.
// False for any other sizes; the caller decides what those mean.
bool SigCheckSchnorr(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchMsg,
                     const std::vector<unsigned char>& vchPubKey);

// libsecp256k1's own self test, once, before the first verification.
bool SigCheckSelfTest();

#endif
