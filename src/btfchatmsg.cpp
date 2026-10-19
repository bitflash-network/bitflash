// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "btfchatmsg.h"

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

static const char* DS_FRAME  = ".btfchat-frame-v1";
static const char* DS_GINVITE = ".btfchat-group-invite-v1";

// ---- hex -------------------------------------------------------------------

static std::string HexEncode(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++)
    {
        s += h[p[i] >> 4];
        s += h[p[i] & 0x0f];
    }
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
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

// ---- digests ---------------------------------------------------------------
//
// Every variable-length field goes in behind its own 8-byte big-endian length.
// Concatenating strings without that is ambiguous -- "ab" + "c" hashes the same
// as "a" + "bc" -- and an ambiguous digest means one signature is valid over
// two different frames. It costs eight bytes per field and removes the whole
// class of problem.
static void UpdateLenPrefixed(SHA256_CTX& ctx, const std::string& s)
{
    unsigned char be[8];
    uint64_t n = (uint64_t)s.size();
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((n >> (8 * (7 - i))) & 0xff);
    SHA256_Update(&ctx, be, 8);
    if (!s.empty())
        SHA256_Update(&ctx, (const unsigned char*)s.data(), s.size());
}

static void UpdateU64(SHA256_CTX& ctx, uint64_t v)
{
    unsigned char be[8];
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((v >> (8 * (7 - i))) & 0xff);
    SHA256_Update(&ctx, be, 8);
}

static void FrameDigest(const Frame& f, unsigned char out[32])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)DS_FRAME, strlen(DS_FRAME));
    UpdateU64(ctx, (uint64_t)f.version);
    UpdateU64(ctx, (uint64_t)f.kind);
    UpdateLenPrefixed(ctx, f.from);
    UpdateU64(ctx, (uint64_t)f.sent);
    UpdateLenPrefixed(ctx, f.id);
    UpdateLenPrefixed(ctx, f.group);
    UpdateLenPrefixed(ctx, f.text);
    // The admin proof is signed over too: without it, a member could strip the
    // proof off an invite and the frame would still look authentic.
    UpdateLenPrefixed(ctx, f.proof);
    SHA256_Final(out, &ctx);
}

static void GroupInviteDigest(const std::string& adminAddr, const std::string& groupId,
                              const std::string& groupName, const std::string& inviteeAddr,
                              unsigned char out[32])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)DS_GINVITE, strlen(DS_GINVITE));
    UpdateLenPrefixed(ctx, adminAddr);
    UpdateLenPrefixed(ctx, groupId);
    UpdateLenPrefixed(ctx, groupName);
    UpdateLenPrefixed(ctx, inviteeAddr);
    SHA256_Final(out, &ctx);
}

// ---- field rules -----------------------------------------------------------
//
// One place decides what a well-formed frame looks like, and both the signer and
// the verifier go through it. Two copies of these rules would drift, and the
// half that drifted looser would be the one facing the network.
static bool CheckFields(const Frame& f, std::string& errOut)
{
    if (f.version != FRAME_VERSION) { errOut = "unknown frame version"; return false; }
    if (f.from.empty())             { errOut = "no sender"; return false; }
    if (f.id.size() != 32)          { errOut = "the frame id must be 32 hex characters"; return false; }
    unsigned char idbytes[16];
    if (!HexDecode(f.id, idbytes, 16)) { errOut = "the frame id is not hex"; return false; }
    if (f.sent < 0)                 { errOut = "negative timestamp"; return false; }

    switch (f.kind)
    {
    case MSG_INVITE:
        if (f.text.size() > MAX_INVITE_NOTE) { errOut = "the invite note is too long"; return false; }
        if (!f.group.empty())  { errOut = "a direct invite carries no group"; return false; }
        if (!f.proof.empty())  { errOut = "a direct invite carries no admin proof"; return false; }
        return true;

    case MSG_INVITE_ACCEPT:
        if (!f.text.empty())   { errOut = "an accept carries no text"; return false; }
        if (!f.group.empty())  { errOut = "an accept carries no group"; return false; }
        if (!f.proof.empty())  { errOut = "an accept carries no admin proof"; return false; }
        return true;

    case MSG_TEXT:
        if (f.text.size() > MAX_TEXT_BYTES) { errOut = "the message is too long"; return false; }
        if (f.text.empty())    { errOut = "an empty message is not a message"; return false; }
        if (!f.group.empty())  { errOut = "a direct message carries no group"; return false; }
        if (!f.proof.empty())  { errOut = "a direct message carries no admin proof"; return false; }
        return true;

    case MSG_GROUP_INVITE:
        if (f.group.empty())   { errOut = "a group invite needs a group"; return false; }
        if (f.group.size() > 64) { errOut = "the group id is too long"; return false; }
        if (f.text.empty())    { errOut = "a group invite needs the group name"; return false; }
        if (f.text.size() > MAX_GROUP_NAME) { errOut = "the group name is too long"; return false; }
        if (f.proof.size() != 128) { errOut = "a group invite needs the admin's proof"; return false; }
        return true;

    case MSG_GROUP_TEXT:
        if (f.group.empty())   { errOut = "a group message needs a group"; return false; }
        if (f.group.size() > 64) { errOut = "the group id is too long"; return false; }
        if (f.text.empty())    { errOut = "an empty message is not a message"; return false; }
        if (f.text.size() > MAX_TEXT_BYTES) { errOut = "the message is too long"; return false; }
        if (!f.proof.empty())  { errOut = "a group message carries no admin proof"; return false; }
        return true;
    }

    errOut = "unknown frame kind";
    return false;
}

// ---- sign / open -----------------------------------------------------------

bool SignFrame(void* secpctx, const Identity& id, Frame& f,
               std::string& outJson, std::string& errOut)
{
    errOut.clear();
    outJson.clear();
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }
    if (id.address.empty()) { errOut = "the identity has no address"; return false; }

    f.version = FRAME_VERSION;
    f.from    = id.address;
    if (f.id.empty())
    {
        unsigned char rnd[16];
        randombytes_buf(rnd, sizeof(rnd));
        f.id = HexEncode(rnd, sizeof(rnd));
    }
    if (!CheckFields(f, errOut))
        return false;

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, id.sign_sk))
    {
        errOut = "the signing key is not valid";
        return false;
    }

    unsigned char digest[32];
    FrameDigest(f, digest);

    unsigned char sig[64];
    // Deterministic (NULL aux_rand), matching how .btf descriptors are signed.
    bool fSigned = secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL) != 0;
    sodium_memzero(&kp, sizeof(kp));
    if (!fSigned)
    {
        errOut = "signing failed";
        return false;
    }

    json v = json::object();
    v["v"]     = f.version;
    v["k"]     = (int)f.kind;
    v["from"]  = f.from;
    v["t"]     = f.sent;
    v["id"]    = f.id;
    if (!f.group.empty()) v["g"]     = f.group;
    if (!f.text.empty())  v["text"]  = f.text;
    if (!f.proof.empty()) v["proof"] = f.proof;
    v["sig"]   = HexEncode(sig, 64);

    outJson = v.dump();
    if (outJson.size() > MAX_FRAME_BYTES)
    {
        // Refuse to emit something the other side is required to refuse.
        outJson.clear();
        errOut = "the frame came out bigger than the wire limit";
        return false;
    }
    return true;
}

bool OpenFrame(void* secpctx, const std::string& jsonStr, Frame& out,
               std::string& errOut)
{
    errOut.clear();
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }

    // Size first: the parser is the one piece of our code a stranger runs.
    if (jsonStr.size() > MAX_FRAME_BYTES) { errOut = "the frame is too big"; return false; }
    if (jsonStr.empty())                  { errOut = "empty frame"; return false; }

    json j;
    try { j = json::parse(jsonStr); }
    catch (...) { errOut = "the frame is not valid JSON"; return false; }
    if (!j.is_object()) { errOut = "the frame is not an object"; return false; }

    Frame f;
    std::string sigHex;
    try
    {
        f.version = j.value("v", 0);
        int nKind = j.value("k", -1);
        if (nKind < MSG_INVITE || nKind > MSG_GROUP_TEXT)
        {
            errOut = "unknown frame kind";
            return false;
        }
        f.kind  = (MsgKind)nKind;
        f.from  = j.value("from", std::string());
        f.sent  = j.value("t", (int64_t)0);
        f.id    = j.value("id", std::string());
        f.group = j.value("g", std::string());
        f.text  = j.value("text", std::string());
        f.proof = j.value("proof", std::string());
        sigHex  = j.value("sig", std::string());
    }
    catch (...)
    {
        errOut = "the frame has a field of the wrong type";
        return false;
    }

    if (!CheckFields(f, errOut))
        return false;

    // The sender's key comes from the address, never from the frame. A frame
    // that carried its own public key would let anyone sign as anyone and point
    // at a key that matches.
    unsigned char pubkey[32];
    int nAddrVersion = 0;
    if (!btf::ParseAddressVersion(f.from, pubkey, nAddrVersion))
    {
        errOut = "the sender address does not parse";
        return false;
    }
    if (nAddrVersion != btf::ADDR_VERSION_XONLY)
    {
        // The whole point of the version byte: an identity scheme we do not know
        // is refused rather than checked under the wrong one.
        errOut = "the sender uses an address version this build cannot verify";
        return false;
    }

    unsigned char sig[64];
    if (!HexDecode(sigHex, sig, 64)) { errOut = "the signature is not 64 bytes of hex"; return false; }

    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, pubkey))
    {
        errOut = "the sender address is not a point on the curve";
        return false;
    }

    unsigned char digest[32];
    FrameDigest(f, digest);
    if (!secp256k1_schnorrsig_verify(ctx, sig, digest, 32, &xpub))
    {
        errOut = "the signature does not verify under the sender address";
        return false;
    }

    out = f;
    return true;
}

// ---- group invite proof ----------------------------------------------------

bool SignGroupInvite(void* secpctx, const Identity& adminId,
                     const std::string& groupId, const std::string& groupName,
                     const std::string& inviteeAddr,
                     std::string& proofHexOut, std::string& errOut)
{
    errOut.clear();
    proofHexOut.clear();
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }
    if (groupId.empty() || groupId.size() > 64) { errOut = "bad group id"; return false; }
    if (groupName.empty() || groupName.size() > MAX_GROUP_NAME) { errOut = "bad group name"; return false; }
    if (inviteeAddr.empty()) { errOut = "no invitee"; return false; }
    if (adminId.address.empty()) { errOut = "the admin identity has no address"; return false; }

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, adminId.sign_sk))
    {
        errOut = "the admin key is not valid";
        return false;
    }
    unsigned char digest[32];
    GroupInviteDigest(adminId.address, groupId, groupName, inviteeAddr, digest);
    unsigned char sig[64];
    bool fSigned = secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL) != 0;
    sodium_memzero(&kp, sizeof(kp));
    if (!fSigned) { errOut = "signing failed"; return false; }

    proofHexOut = HexEncode(sig, 64);
    return true;
}

bool VerifyGroupInvite(void* secpctx, const std::string& adminAddr,
                       const std::string& groupId, const std::string& groupName,
                       const std::string& inviteeAddr,
                       const std::string& proofHex, std::string& errOut)
{
    errOut.clear();
    secp256k1_context* ctx = (secp256k1_context*)secpctx;
    if (!ctx) { errOut = "no secp256k1 context"; return false; }

    unsigned char pubkey[32];
    int nAddrVersion = 0;
    if (!btf::ParseAddressVersion(adminAddr, pubkey, nAddrVersion))
    {
        errOut = "the admin address does not parse";
        return false;
    }
    if (nAddrVersion != btf::ADDR_VERSION_XONLY)
    {
        errOut = "the admin uses an address version this build cannot verify";
        return false;
    }
    unsigned char sig[64];
    if (!HexDecode(proofHex, sig, 64)) { errOut = "the proof is not 64 bytes of hex"; return false; }

    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, pubkey))
    {
        errOut = "the admin address is not a point on the curve";
        return false;
    }
    unsigned char digest[32];
    GroupInviteDigest(adminAddr, groupId, groupName, inviteeAddr, digest);
    if (!secp256k1_schnorrsig_verify(ctx, sig, digest, 32, &xpub))
    {
        errOut = "the admin proof does not verify";
        return false;
    }
    return true;
}

// ---- replay ----------------------------------------------------------------

void ReplayGuard::Prune(int64_t nNow)
{
    for (std::map<std::string, int64_t>::iterator it = mapSeen.begin(); it != mapSeen.end(); )
    {
        if (nNow - it->second > FRAME_MAX_AGE)
            mapSeen.erase(it++);
        else
            ++it;
    }
}

bool ReplayGuard::Accept(const Frame& f, int64_t nNow, std::string& errOut)
{
    errOut.clear();
    if (f.id.size() != 32) { errOut = "the frame id is malformed"; return false; }

    if (f.sent > nNow + FRAME_FUTURE_SKEW)
    {
        errOut = "the frame is timestamped in the future";
        return false;
    }
    if (nNow - f.sent > FRAME_MAX_AGE)
    {
        errOut = "the frame is too old";
        return false;
    }

    Prune(nNow);

    if (mapSeen.count(f.id))
    {
        errOut = "this frame was already delivered";
        return false;
    }
    if (mapSeen.size() >= MAX_SEEN_FRAMES)
    {
        // Fail closed. Making room means forgetting an id, and forgetting an id
        // is exactly the state a replay needs.
        errOut = "the replay table is full";
        return false;
    }

    mapSeen[f.id] = f.sent;
    return true;
}

} // namespace btfchat
