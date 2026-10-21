// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "btfchatbox.h"

#include "btfaddr.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>

#include <cstring>

using json = nlohmann::json;

namespace btfchat
{

static const char* LBL_TAG    = "btfchat-mailbox-v1";
static const char* DS_EPOCH   = ".btfchat-epoch-keys-v1";

// How far from now a published epoch may be. One epoch ahead covers a peer whose
// clock is a few hours fast or who rotated early; one behind covers the envelope
// that crosses midnight. Anything else is a stale or forged announcement.
static const int64_t EPOCH_SLACK = 1;

static std::string HexEncode(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 0x0f]; }
    return s;
}

static bool HexDecode(const std::string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        int hi = -1, lo = -1;
        char a = s[2 * i], b = s[2 * i + 1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

// ---- epochs and tags -------------------------------------------------------

int64_t MailboxEpoch(int64_t nNow)
{
    if (nNow < 0)
        return 0;
    return nNow / MAILBOX_EPOCH_SECONDS;
}

bool MailboxTag(const unsigned char my_chan_sk[btf::CHAN_KEYBYTES],
                const unsigned char their_chan_pub[btf::CHAN_KEYBYTES],
                int64_t nEpoch, std::string& tagHexOut)
{
    tagHexOut.clear();
    if (sodium_init() < 0)
        return false;

    // X25519 on the two STATIC chat keys. Symmetric, so both sides land on the
    // same tag, and computable by nobody else -- a relay watching the tag cannot
    // work backwards to either key.
    unsigned char dh[btf::CHAN_KEYBYTES];
    if (crypto_scalarmult(dh, my_chan_sk, their_chan_pub) != 0)
    {
        // A small-order peer key. There is no shared secret to key a tag with.
        sodium_memzero(dh, sizeof(dh));
        return false;
    }

    unsigned char be[8];
    uint64_t e = (uint64_t)nEpoch;
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((e >> (8 * (7 - i))) & 0xff);

    crypto_generichash_state st;
    // Keyed by the shared secret, not merely mixed in: the tag is a MAC, and a
    // hash of public material with a secret appended is not one.
    crypto_generichash_init(&st, dh, sizeof(dh), MAILBOX_TAG_BYTES);
    crypto_generichash_update(&st, (const unsigned char*)LBL_TAG, strlen(LBL_TAG));
    crypto_generichash_update(&st, be, sizeof(be));
    unsigned char tag[MAILBOX_TAG_BYTES];
    crypto_generichash_final(&st, tag, sizeof(tag));

    sodium_memzero(&st, sizeof(st));
    sodium_memzero(dh, sizeof(dh));

    tagHexOut = HexEncode(tag, sizeof(tag));
    return true;
}

// ---- epoch keys ------------------------------------------------------------

void EpochKeysClear(EpochKeys& k)
{
    sodium_memzero(k.x_pk,   sizeof(k.x_pk));
    sodium_memzero(k.x_sk,   sizeof(k.x_sk));
    sodium_memzero(k.kem_pk, sizeof(k.kem_pk));
    sodium_memzero(k.kem_sk, sizeof(k.kem_sk));
    k.epoch = 0;
}

bool Mailbox::Rotate(int64_t nNow, std::string& errOut)
{
    errOut.clear();
    if (!btf::ChanInit())
    {
        errOut = "libsodium failed to initialize";
        return false;
    }
    int64_t e = MailboxEpoch(nNow);

    if (!mapKeys.count(e))
    {
        EpochKeys k;
        k.epoch = e;
        btf::ChanKeypair(k.x_pk, k.x_sk);
        if (!btf::ChanKemKeypair(k.kem_pk, k.kem_sk))
        {
            EpochKeysClear(k);
            errOut = "the epoch KEM keypair failed";
            return false;
        }
        mapKeys[e] = k;
        EpochKeysClear(k);
    }

    // Keep this epoch and the MAILBOX_KEEP_EPOCHS-1 before it.
    Forget(e - (int64_t)(MAILBOX_KEEP_EPOCHS - 1));
    return true;
}

bool Mailbox::PublicFor(int64_t nEpoch, unsigned char x_pk[btf::CHAN_KEYBYTES],
                        unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES]) const
{
    std::map<int64_t, EpochKeys>::const_iterator it = mapKeys.find(nEpoch);
    if (it == mapKeys.end())
        return false;
    memcpy(x_pk,   it->second.x_pk,   btf::CHAN_KEYBYTES);
    memcpy(kem_pk, it->second.kem_pk, btf::CHAN_KEM_PUBBYTES);
    return true;
}

bool Mailbox::Open(const unsigned char* in, size_t n,
                   std::vector<unsigned char>& out, std::string& errOut) const
{
    out.clear();
    errOut.clear();
    if (!in || n < (size_t)btf::CHAN_SEAL_OVERHEAD)
    {
        errOut = "the envelope is too short";
        return false;
    }
    if (n > MAX_ENVELOPE_BYTES)
    {
        errOut = "the envelope is too big";
        return false;
    }

    // Newest epoch first: most envelopes are for the current one.
    for (std::map<int64_t, EpochKeys>::const_reverse_iterator it = mapKeys.rbegin();
         it != mapKeys.rend(); ++it)
    {
        if (btf::ChanOpenSealed(it->second.x_sk, it->second.kem_pk, it->second.kem_sk,
                                in, n, out))
            return true;
    }

    // Also the ordinary outcome for an envelope we posted ourselves under a
    // shared tag, so the caller treats this as "not mine", not as an error.
    errOut = "no epoch key opens this envelope";
    return false;
}

void Mailbox::Forget(int64_t nEpoch)
{
    for (std::map<int64_t, EpochKeys>::iterator it = mapKeys.begin(); it != mapKeys.end(); )
    {
        if (it->first < nEpoch)
        {
            EpochKeysClear(it->second);
            mapKeys.erase(it++);
        }
        else
            ++it;
    }
}

void Mailbox::Wipe()
{
    for (std::map<int64_t, EpochKeys>::iterator it = mapKeys.begin(); it != mapKeys.end(); ++it)
        EpochKeysClear(it->second);
    mapKeys.clear();
}

static std::string BoxHex(const unsigned char* p, size_t n)
{
    std::string s(n * 2 + 1, '\0');
    sodium_bin2hex(&s[0], s.size(), p, n);
    s.resize(n * 2);
    return s;
}

static bool BoxUnhex(const std::string& s, unsigned char* out, size_t n)
{
    size_t got = 0;
    return s.size() == n * 2 &&
           sodium_hex2bin(out, n, s.c_str(), s.size(), NULL, &got, NULL) == 0 && got == n;
}

std::string Mailbox::ToJson() const
{
    json a = json::array();
    for (std::map<int64_t, EpochKeys>::const_iterator it = mapKeys.begin(); it != mapKeys.end(); ++it)
    {
        const EpochKeys& k = it->second;
        a.push_back(json{{"e", k.epoch},
                         {"xp", BoxHex(k.x_pk, sizeof(k.x_pk))}, {"xs", BoxHex(k.x_sk, sizeof(k.x_sk))},
                         {"kp", BoxHex(k.kem_pk, sizeof(k.kem_pk))}, {"ks", BoxHex(k.kem_sk, sizeof(k.kem_sk))}});
    }
    return a.dump();
}

bool Mailbox::FromJson(const std::string& s, std::string& errOut)
{
    errOut.clear();
    Wipe();
    if (s.empty())
        return true;
    try
    {
        json a = json::parse(s);
        if (!a.is_array())
        {
            errOut = "the epoch keys are not a list";
            return false;
        }
        for (size_t i = 0; i < a.size() && i < 16; i++)
        {
            const json& e = a[i];
            EpochKeys k;
            k.epoch = e.value("e", (int64_t)-1);
            bool fOk = k.epoch >= 0 &&
                       BoxUnhex(e.value("xp", std::string()), k.x_pk, sizeof(k.x_pk)) &&
                       BoxUnhex(e.value("xs", std::string()), k.x_sk, sizeof(k.x_sk)) &&
                       BoxUnhex(e.value("kp", std::string()), k.kem_pk, sizeof(k.kem_pk)) &&
                       BoxUnhex(e.value("ks", std::string()), k.kem_sk, sizeof(k.kem_sk));
            if (fOk)
                mapKeys[k.epoch] = k;
            EpochKeysClear(k);
        }
    }
    catch (...)
    {
        Wipe();
        errOut = "the epoch keys do not parse";
        return false;
    }
    return true;
}

// ---- sealing ---------------------------------------------------------------

bool SealEnvelope(const unsigned char their_x_pk[btf::CHAN_KEYBYTES],
                  const unsigned char their_kem_pk[btf::CHAN_KEM_PUBBYTES],
                  const std::string& frameJson,
                  std::vector<unsigned char>& out, std::string& errOut)
{
    out.clear();
    errOut.clear();
    if (frameJson.empty()) { errOut = "nothing to seal"; return false; }
    if (frameJson.size() + (size_t)btf::CHAN_SEAL_OVERHEAD > MAX_ENVELOPE_BYTES)
    {
        errOut = "the frame is too big for an envelope";
        return false;
    }
    if (!btf::ChanInit()) { errOut = "libsodium failed to initialize"; return false; }

    if (!btf::ChanSealTo(their_x_pk, their_kem_pk,
                         (const unsigned char*)frameJson.data(), frameJson.size(), out))
    {
        errOut = "sealing failed (bad recipient key?)";
        return false;
    }
    return true;
}

// ---- published epoch keys --------------------------------------------------

static void EpochDigest(const std::string& address, int64_t nEpoch,
                        const unsigned char x_pk[btf::CHAN_KEYBYTES],
                        const unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES],
                        unsigned char out[32])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)DS_EPOCH, strlen(DS_EPOCH));
    // Length-prefixed, so the address cannot borrow bytes from what follows.
    unsigned char be[8];
    uint64_t n = (uint64_t)address.size();
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((n >> (8 * (7 - i))) & 0xff);
    SHA256_Update(&ctx, be, 8);
    SHA256_Update(&ctx, (const unsigned char*)address.data(), address.size());
    uint64_t e = (uint64_t)nEpoch;
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((e >> (8 * (7 - i))) & 0xff);
    SHA256_Update(&ctx, be, 8);
    SHA256_Update(&ctx, x_pk, btf::CHAN_KEYBYTES);
    SHA256_Update(&ctx, kem_pk, btf::CHAN_KEM_PUBBYTES);
    SHA256_Final(out, &ctx);
}

bool SignEpochKeys(void* secpctx, const Identity& id, const EpochKeys& keys,
                   std::string& jsonOut, std::string& errOut)
{
    jsonOut.clear();
    errOut.clear();
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }
    if (id.address.empty()) { errOut = "the identity has no address"; return false; }

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, id.sign_sk))
    {
        errOut = "the signing key is not valid";
        return false;
    }
    unsigned char digest[32];
    EpochDigest(id.address, keys.epoch, keys.x_pk, keys.kem_pk, digest);
    unsigned char sig[64];
    bool fSigned = secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL) != 0;
    sodium_memzero(&kp, sizeof(kp));
    if (!fSigned) { errOut = "signing failed"; return false; }

    json v = json::object();
    v["v"]     = 1;
    v["addr"]  = id.address;
    v["epoch"] = keys.epoch;
    v["x"]     = HexEncode(keys.x_pk, btf::CHAN_KEYBYTES);
    v["kem"]   = HexEncode(keys.kem_pk, btf::CHAN_KEM_PUBBYTES);
    v["sig"]   = HexEncode(sig, 64);
    jsonOut = v.dump();
    return true;
}

bool VerifyEpochKeys(void* secpctx, const std::string& expectAddress,
                     const std::string& jsonStr, int64_t nNow,
                     int64_t& epochOut,
                     unsigned char x_pk[btf::CHAN_KEYBYTES],
                     unsigned char kem_pk[btf::CHAN_KEM_PUBBYTES],
                     std::string& errOut)
{
    errOut.clear();
    epochOut = 0;
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }

    // Bounded before parsing: the announcement is a relay's answer, so it is a
    // stranger's bytes.
    const size_t MAXLEN = 8192;
    if (jsonStr.empty() || jsonStr.size() > MAXLEN)
    {
        errOut = "the announcement has an impossible size";
        return false;
    }

    json j;
    try { j = json::parse(jsonStr); }
    catch (...) { errOut = "the announcement is not valid JSON"; return false; }
    if (!j.is_object()) { errOut = "the announcement is not an object"; return false; }

    std::string addr, xHex, kemHex, sigHex;
    int64_t epoch = 0;
    int ver = 0;
    try
    {
        ver    = j.value("v", 0);
        addr   = j.value("addr", std::string());
        epoch  = j.value("epoch", (int64_t)0);
        xHex   = j.value("x", std::string());
        kemHex = j.value("kem", std::string());
        sigHex = j.value("sig", std::string());
    }
    catch (...) { errOut = "the announcement has a field of the wrong type"; return false; }

    if (ver != 1) { errOut = "unknown announcement version"; return false; }
    if (addr.empty() || addr != expectAddress)
    {
        // Verifying against the address we asked for, not the one it claims to
        // be: otherwise a relay answers with a valid announcement from somebody
        // else entirely and we seal the conversation to a stranger.
        errOut = "the announcement is for a different address";
        return false;
    }

    int64_t eNow = MailboxEpoch(nNow);
    if (epoch < eNow - EPOCH_SLACK || epoch > eNow + EPOCH_SLACK)
    {
        // A stale announcement is worse than none: its secrets may already be
        // destroyed, and a message sealed to them is lost without a trace.
        errOut = "the announced epoch is not current";
        return false;
    }

    unsigned char x[btf::CHAN_KEYBYTES];
    unsigned char kem[btf::CHAN_KEM_PUBBYTES];
    unsigned char sig[64];
    if (!HexDecode(xHex, x, sizeof(x)))       { errOut = "the X25519 key is malformed"; return false; }
    if (!HexDecode(kemHex, kem, sizeof(kem))) { errOut = "the ML-KEM key is malformed"; return false; }
    if (!HexDecode(sigHex, sig, sizeof(sig))) { errOut = "the signature is malformed"; return false; }

    unsigned char pubkey[32];
    int nAddrVersion = 0;
    if (!btf::ParseAddressVersion(expectAddress, pubkey, nAddrVersion))
    {
        errOut = "the address does not parse";
        return false;
    }
    if (nAddrVersion != btf::ADDR_VERSION_XONLY)
    {
        errOut = "the address version cannot be verified by this build";
        return false;
    }

    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, pubkey))
    {
        errOut = "the address is not a point on the curve";
        return false;
    }
    unsigned char digest[32];
    EpochDigest(expectAddress, epoch, x, kem, digest);
    if (!secp256k1_schnorrsig_verify(ctx, sig, digest, 32, &xpub))
    {
        errOut = "the announcement is not signed by that address";
        return false;
    }

    epochOut = epoch;
    memcpy(x_pk, x, sizeof(x));
    memcpy(kem_pk, kem, sizeof(kem));
    return true;
}

} // namespace btfchat
