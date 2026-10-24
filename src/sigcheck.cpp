// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "sigcheck.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

bool SigCheckEcdsa(const unsigned char* hash32, const std::vector<unsigned char>& vchSig,
                   const std::vector<unsigned char>& vchPubKey)
{
    // Verification needs no precomputed tables, so the static context does.
    const secp256k1_context* ctx = secp256k1_context_static;
    if (vchSig.empty() || vchPubKey.empty())
        return false;

    // 02/03 (33 bytes), 04 and the hybrid 06/07 (65), as OpenSSL's
    // o2i_ECPublicKey takes them; anything else, or a point off the curve,
    // fails here as it failed there.
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, &vchPubKey[0], vchPubKey.size()))
        return false;

    // Strict DER. OpenSSL 3 re-encodes what it parsed and refuses anything
    // that does not come back byte for byte, which is the same set.
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, &vchSig[0], vchSig.size()))
        return false;

    // libsecp256k1 verifies only low S; OpenSSL took both. Half the
    // signatures before rules v2 are high S, so fold them before verifying.
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    return secp256k1_ecdsa_verify(ctx, &sig, hash32, &pubkey) == 1;
}

bool SigCheckSchnorr(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchMsg,
                     const std::vector<unsigned char>& vchPubKey)
{
    const secp256k1_context* ctx = secp256k1_context_static;
    if (vchSig.size() != 64 || vchPubKey.size() != 32)
        return false;
    // An x-only key that is not the x coordinate of a curve point fails to
    // parse, and the check with it.
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, &vchPubKey[0]))
        return false;
    static const unsigned char empty = 0;
    return secp256k1_schnorrsig_verify(ctx, &vchSig[0], vchMsg.empty() ? &empty : &vchMsg[0],
                                       vchMsg.size(), &pubkey) == 1;
}

bool SigCheckSelfTest()
{
    secp256k1_selftest();   // aborts on a broken build instead of returning
    return true;
}
