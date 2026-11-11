// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Shared by fuzz-script and fuzz-v4-templates: a byte reader, four fixed keys,
// and signatures made with them by libsecp256k1. ECDSA nonces are RFC 6979 and
// BIP340 signing gets no auxiliary randomness, so the same input makes the
// same bytes on every run and every engine -- a saved crash replays.

#ifndef BITFLASH_FUZZ_SCRIPT_UTIL_H
#define BITFLASH_FUZZ_SCRIPT_UTIL_H

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Reads the input front to back; past the end every read is zero.
struct FuzzReader
{
    const uint8_t* p;
    size_t n;
    FuzzReader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    uint8_t U8() { if (!n) return 0; n--; return *p++; }
    uint16_t U16() { uint16_t v = U8(); v |= (uint16_t)U8() << 8; return v; }
    uint32_t U32() { uint32_t v = U16(); v |= (uint32_t)U16() << 16; return v; }
    uint64_t U64() { uint64_t v = U32(); v |= (uint64_t)U32() << 32; return v; }
    std::vector<unsigned char> Bytes(size_t k)
    {
        if (k > n) k = n;
        std::vector<unsigned char> v(p, p + k);
        p += k; n -= k;
        return v;
    }
    std::vector<unsigned char> Rest() { return Bytes(n); }
};

struct FuzzKey
{
    unsigned char sec[32];
    std::vector<unsigned char> pubC, pubU, xonly;
    uint160 hashC;            // Hash160 of the compressed key: its address
    secp256k1_keypair kp;
};

static secp256k1_context* FuzzSecp()
{
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

static const std::vector<FuzzKey>& FuzzKeys()
{
    static std::vector<FuzzKey> v;
    if (!v.empty())
        return v;
    secp256k1_context* ctx = FuzzSecp();
    for (int i = 0; i < 4; i++)
    {
        FuzzKey k;
        char sz[32];
        snprintf(sz, sizeof(sz), "bitflash fuzz key %d", i);
        SHA256((const unsigned char*)sz, strlen(sz), k.sec);
        secp256k1_pubkey pub;
        if (!secp256k1_ec_seckey_verify(ctx, k.sec) || !secp256k1_ec_pubkey_create(ctx, &pub, k.sec) ||
            !secp256k1_keypair_create(ctx, &k.kp, k.sec))
            abort();
        unsigned char buf[65];
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &pub, SECP256K1_EC_COMPRESSED);
        k.pubC.assign(buf, buf + len);
        len = 65;
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
        k.pubU.assign(buf, buf + len);
        secp256k1_xonly_pubkey xpub;
        unsigned char x[32];
        if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &k.kp) || !secp256k1_xonly_pubkey_serialize(ctx, x, &xpub))
            abort();
        k.xonly.assign(x, x + 32);
        k.hashC = Hash160(k.pubC);
        v.push_back(k);
    }
    return v;
}

// DER, without the hash-type byte, over the 32 bytes CheckSig hands
// libsecp256k1 (the raw memory of the uint256). fHighS: the S' = n - S twin,
// which verifies too and which rules v2 refuse.
static std::vector<unsigned char> FuzzSignEcdsa(const FuzzKey& key, const uint256& hash, bool fHighS = false)
{
    secp256k1_context* ctx = FuzzSecp();
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, (const unsigned char*)&hash, key.sec, NULL, NULL))
        abort();
    if (fHighS)
    {
        static const unsigned char n[32] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
        unsigned char c[64];
        secp256k1_ecdsa_signature_serialize_compact(ctx, c, &sig);
        int borrow = 0;
        for (int i = 31; i >= 0; i--)
        {
            int d = (int)n[i] - (int)c[32 + i] - borrow;
            borrow = d < 0;
            c[32 + i] = (unsigned char)(d + (borrow ? 256 : 0));
        }
        if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, c))
            abort();
    }
    unsigned char der[80];
    size_t len = sizeof(der);
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &len, &sig))
        abort();
    return std::vector<unsigned char>(der, der + len);
}

// BIP340 over a message of any length.
static std::vector<unsigned char> FuzzSignSchnorr(const FuzzKey& key, const std::vector<unsigned char>& msg)
{
    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign_custom(FuzzSecp(), sig, msg.empty() ? NULL : &msg[0], msg.size(), &key.kp, NULL))
        abort();
    return std::vector<unsigned char>(sig, sig + 64);
}

// A SIGHASH_ALL signature of txTo's input nIn against scriptCode, as the
// wallet and spendscript make it: DER plus the hash-type byte.
static std::vector<unsigned char> FuzzSigFor(const FuzzKey& key, const CScript& scriptCode, const CTransaction& txTo,
                                             unsigned int nIn, int nHashType = SIGHASH_ALL, bool fHighS = false)
{
    std::vector<unsigned char> sig = FuzzSignEcdsa(key, SignatureHash(scriptCode, txTo, nIn, nHashType), fHighS);
    sig.push_back((unsigned char)nHashType);
    return sig;
}

#define FUZZ_CHECK(cond, ...) \
    do { if (!(cond)) { fprintf(stderr, "fuzz invariant failed: %s\n  ", #cond); \
                        fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); abort(); } } while (0)

#endif
