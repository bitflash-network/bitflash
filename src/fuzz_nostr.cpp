// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for what Nostr relays send a node: relay messages
// on each subscription the node opens (discovery, pool announcements,
// descriptor lookups, OK), and NIP-01 event checks (NostrVerifyEvent: the id is
// the hash of the event, the signature is BIP-340 by its pubkey).
//
// The BIP-340 verification is differential: libsecp256k1 (what the node uses)
// against a reference written here on OpenSSL's generic elliptic-curve
// arithmetic, from the BIP's own pseudocode. Any disagreement aborts.
//
// Input: byte 0 picks the mode, the rest is the mode's body.
//   0  several relay messages, one per line, through every subscription
//   1  a relay message on the discovery subscription
//   2  a relay message on the pool subscription
//   3  a relay message answering a descriptor lookup
//   4  a relay message waited on for an OK
//   5  an event as JSON, checked, and its signature against the reference
//   6  (32-byte key, 32-byte message, 64-byte signature): both verifiers
//   7  an event built from fields and signed by one of four keys, wrapped as
//      a relay message, optionally changed, then through every subscription
//
// What is checked, beyond the sanitizers:
//   - both BIP-340 verifiers agree, on every key, message and signature;
//   - an event NostrVerifyEvent takes has the id of its own serialization and
//     a signature the reference also accepts; one refused for its signature
//     is refused by the reference too;
//   - an event the discovery or pool path took verifies, is of its kind and
//     is not dated more than NOSTR_MAX_FUTURE ahead; the peer table and the
//     pool list never pass their caps, nor new peers per round theirs.

#include "headers_core.h"
#include "btfaddr.h"

#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
// util.h redefines snprintf as a macro, which breaks nlohmann/json (see nostr.cpp).
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>

static void FuzzNostrInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzNostrInit
#include "fuzz_datadir.h"

map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using json = nlohmann::json;

static secp256k1_context* g_ctx = NULL;
static const int NUM_KEYS = 4;
static unsigned char g_sk[NUM_KEYS][32];
static unsigned char g_pk[NUM_KEYS][32];
static unsigned char g_self[32];
static const char* SUB_DISC = "btf-disc-7";
static const char* SUB_POOL = "btf-pools-8";
static const char* SUB_DESC = "btf-resolve-9";
static const int64 NOW = 1790000000;

// ---- the BIP-340 reference ----------------------------------------------------

static EC_GROUP* g_group = NULL;
static BIGNUM* g_p = NULL;
static BIGNUM* g_n = NULL;

static void TaggedHash(const char* tag, const unsigned char* msg, size_t n, unsigned char out[32])
{
    unsigned char th[32];
    SHA256((const unsigned char*)tag, strlen(tag), th);
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, th, 32);
    SHA256_Update(&c, th, 32);
    SHA256_Update(&c, msg, n);
    SHA256_Final(out, &c);
}

// Verify(pk, m, sig) exactly as BIP-340 states it.
static bool RefVerify(const unsigned char pk[32], const unsigned char msg[32], const unsigned char sig[64])
{
    BN_CTX* bc = BN_CTX_new();
    BIGNUM* x = BN_bin2bn(pk, 32, NULL);
    BIGNUM* r = BN_bin2bn(sig, 32, NULL);
    BIGNUM* s = BN_bin2bn(sig + 32, 32, NULL);
    BIGNUM* e = BN_new();
    BIGNUM* ne = BN_new();
    BIGNUM* rx = BN_new();
    BIGNUM* ry = BN_new();
    EC_POINT* P = EC_POINT_new(g_group);
    EC_POINT* R = EC_POINT_new(g_group);
    bool fOk = false;
    do
    {
        // P = lift_x(int(pk)): fail if x >= p or x^3 + 7 has no square root;
        // the even y.
        if (BN_cmp(x, g_p) >= 0)
            break;
        ERR_set_mark();
        int nLift = EC_POINT_set_compressed_coordinates(g_group, P, x, 0, bc);
        ERR_pop_to_mark();
        if (nLift != 1)
            break;
        // r < p, s < n.
        if (BN_cmp(r, g_p) >= 0 || BN_cmp(s, g_n) >= 0)
            break;
        // e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        unsigned char buf[96], h[32];
        memcpy(buf, sig, 32);
        memcpy(buf + 32, pk, 32);
        memcpy(buf + 64, msg, 32);
        TaggedHash("BIP0340/challenge", buf, sizeof(buf), h);
        BN_bin2bn(h, 32, e);
        BN_mod(e, e, g_n, bc);
        // R = s*G - e*P.
        BN_mod_sub(ne, g_n, e, g_n, bc);
        if (EC_POINT_mul(g_group, R, s, P, ne, bc) != 1)
            break;
        // Fail if R is infinite, has odd y, or x(R) != r.
        if (EC_POINT_is_at_infinity(g_group, R))
            break;
        if (EC_POINT_get_affine_coordinates(g_group, R, rx, ry, bc) != 1)
            break;
        if (BN_is_odd(ry) || BN_cmp(rx, r) != 0)
            break;
        fOk = true;
    } while (0);
    EC_POINT_free(P);
    EC_POINT_free(R);
    BN_free(x); BN_free(r); BN_free(s); BN_free(e); BN_free(ne); BN_free(rx); BN_free(ry);
    BN_CTX_free(bc);
    return fOk;
}

static bool SecpVerify(const unsigned char pk[32], const unsigned char msg[32], const unsigned char sig[64])
{
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(g_ctx, &xpub, pk))
        return false;
    return secp256k1_schnorrsig_verify(g_ctx, sig, msg, 32, &xpub) == 1;
}

static void Differential(const unsigned char pk[32], const unsigned char msg[32], const unsigned char sig[64])
{
    bool a = SecpVerify(pk, msg, sig);
    bool b = RefVerify(pk, msg, sig);
    if (a != b)
    {
        fprintf(stderr, "BIP-340 disagreement: libsecp256k1 %d, reference %d\n", (int)a, (int)b);
        abort();
    }
}

// ---- helpers ------------------------------------------------------------------

struct Reader
{
    const uint8_t* p;
    size_t n;
    Reader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    uint8_t U8() { if (!n) return 0; n--; return *p++; }
    uint16_t U16() { uint16_t a = U8(); return (uint16_t)(a | (U8() << 8)); }
    int64_t S16() { return (int16_t)U16(); }
    std::string Str(size_t k) { if (k > n) k = n; std::string s((const char*)p, k); p += k; n -= k; return s; }
};

static std::string Hex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}

static bool UnHex(const std::string& s, unsigned char* out, size_t n)
{
    if (s.size() != 2 * n)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        int v = 0;
        for (int k = 0; k < 2; k++)
        {
            char c = s[2 * i + k];
            int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (d < 0)
                return false;
            v = v * 16 + d;
        }
        out[i] = (unsigned char)v;
    }
    return true;
}

// NostrVerifyEvent, checked against the reference on what it decides.
static bool CheckEvent(const std::string& evJson, NostrEvent* pOut = NULL)
{
    NostrEvent e;
    std::string err;
    bool fOk = NostrVerifyEvent(g_ctx, evJson, e, err);
    // Whatever it said, if the fields are there, the two verifiers agree on them.
    try
    {
        json ev = json::parse(evJson);
        if (ev.is_object() && ev.contains("pubkey") && ev["pubkey"].is_string() &&
            ev.contains("id") && ev["id"].is_string() && ev.contains("sig") && ev["sig"].is_string())
        {
            unsigned char pk[32], id[32], sig[64];
            if (UnHex(ev["pubkey"].get<std::string>(), pk, 32) && UnHex(ev["id"].get<std::string>(), id, 32) &&
                UnHex(ev["sig"].get<std::string>(), sig, 64))
            {
                Differential(pk, id, sig);
                bool fRef = RefVerify(pk, id, sig);
                if (fOk && !fRef)
                    abort();   // took an event the reference refuses
                if (!fOk && (err == "the signature does not verify" || err == "the pubkey is not a point") && fRef)
                    abort();   // refused for a signature the reference accepts
            }
        }
    }
    catch (...)
    {
        if (fOk)
            abort();   // took something that is not JSON
    }
    if (fOk)
    {
        // The id is the hash of the canonical serialization.
        json tags = json::array();
        for (size_t i = 0; i < e.tags.size(); i++)
            tags.push_back(e.tags[i]);
        std::string ser = json::array({ 0, e.pubkey, e.created_at, e.kind, tags, e.content }).dump();
        unsigned char h[32];
        SHA256((const unsigned char*)ser.data(), ser.size(), h);
        if (Hex(h, 32) != e.id)
            abort();
        if (pOut)
            *pOut = e;
    }
    return fOk;
}

static void CheckCaps(int nNewThisRound)
{
    if ((size_t)GetDiscoveredPeerCount() > NOSTR_MAX_BTF_PEERS)
        abort();
    if (NostrDiscoveredPoolCount() > NOSTR_MAX_POOLS)
        abort();
    if (nNewThisRound > (int)NOSTR_MAX_NEW_PEERS_PER_ROUND)
        abort();
}

// The event inside ["EVENT", sub, ev], if there is one.
static bool InnerEvent(const std::string& msg, std::string& evOut)
{
    try
    {
        json j = json::parse(msg);
        if (!j.is_array() || j.size() < 3 || !j[2].is_object())
            return false;
        evOut = j[2].dump();
        return true;
    }
    catch (...) { return false; }
}

static void AllSubscriptions(const std::string& msg, int& nNew)
{
    int n = NostrIngestDiscovery(g_ctx, msg, SUB_DISC, g_self, NOW, nNew);
    std::string ev;
    if (n == NOSTR_MSG_TAKEN)
    {
        NostrEvent e;
        if (!InnerEvent(msg, ev) || !CheckEvent(ev, &e) || e.kind != 38501 || e.created_at > NOW + NOSTR_MAX_FUTURE)
            abort();   // discovery took an event that does not hold up
    }
    CheckCaps(nNew);
    n = NostrIngestPool(msg, SUB_POOL, NOW);
    if (n == NOSTR_MSG_TAKEN)
    {
        NostrEvent e;
        if (!InnerEvent(msg, ev) || !CheckEvent(ev, &e) || e.kind != 38503 || e.created_at > NOW + NOSTR_MAX_FUTURE)
            abort();
        // A pool speaks for its own key only.
        json c = json::parse(e.content);
        std::string addr = c.contains("btf") && c["btf"].is_string() ? c["btf"].get<std::string>()
                                                                     : c.value("address", std::string());
        unsigned char pk[32];
        if (!UnHex(e.pubkey, pk, 32) || btf::Address(pk) != addr)
            abort();
    }
    CheckCaps(nNew);
    std::map<std::string, std::string> want;
    for (int i = 0; i < 2; i++)
        want[Hex(g_pk[i], 32)] = btf::Address(g_pk[i]);
    std::string addr, desc;
    n = NostrIngestDescriptor(g_ctx, msg, SUB_DESC, want, addr, desc);
    if (n == NOSTR_MSG_TAKEN)
    {
        unsigned char pk[32];
        btf::Descriptor d;
        if (!btf::ParseAddress(addr, pk) || !btf::VerifyDescriptor(g_ctx, desc, pk, d))
            abort();   // a descriptor not signed by the address it was taken for
        bool fWanted = false;
        for (std::map<std::string, std::string>::const_iterator it = want.begin(); it != want.end(); ++it)
            if (it->second == addr)
                fWanted = true;
        if (!fWanted)
            abort();
    }
    std::string reason;
    NostrRelayOk(msg, std::string(64, 'a'), reason);
}

// ---- modes --------------------------------------------------------------------

// Several relay messages in a row, split at newlines (what one connection
// delivers): every one through every subscription, state kept between them.
// WebSocket framing is not here: CWebSocket::RecvText reads a socket and is
// covered by fuzz-http-client.
static void ModeMessages(Reader& rd)
{
    std::string all = rd.Str(rd.n);
    size_t at = 0;
    for (int i = 0; i < 32 && at <= all.size(); i++)
    {
        size_t nl = all.find('\n', at);
        if (nl == std::string::npos)
            nl = all.size();
        int nNew = 0;
        AllSubscriptions(all.substr(at, nl - at), nNew);
        at = nl + 1;
    }
}

// Bytes as the text JSON can carry: what is not UTF-8 becomes U+FFFD, as a
// parser's output never holds it anyway. (A stranger's event reaches the node
// through json::parse, which refuses such text; only a harness builds it.)
static std::string Clean(const std::string& b)
{
    return json::parse(json(b).dump(-1, ' ', false, json::error_handler_t::replace)).get<std::string>();
}

static std::string SignedEvent(Reader& rd, int& signer)
{
    signer = rd.U8() % NUM_KEYS;
    uint8_t b = rd.U8();
    int kind = (b & 1) ? 38501 : (b & 2) ? 38503 : (int)rd.U16();
    int64 created = NOW + rd.S16() * ((b & 4) ? 600 : 1);
    json tags = json::array();
    if (b & 8)
        tags.push_back(json::array({ "d", kind == 38503 ? "btf-pool-2" : "btf-descriptor-2" }));
    int nExtra = (b >> 4) & 3;
    for (int i = 0; i < nExtra; i++)
        tags.push_back(json::array({ Clean(rd.Str(rd.U8() % 8)), Clean(rd.Str(rd.U8() % 16)) }));
    std::string content;
    uint8_t c = rd.U8();
    if (c % 4 == 0)
    {
        unsigned char enc[32];
        for (int i = 0; i < 32; i++) enc[i] = (unsigned char)(i + c);
        content = btf::SignDescriptor(g_ctx, g_sk[signer], Hex(enc, 32), "", (uint64_t)created,
                                      (c & 4) ? Clean(rd.Str(rd.U8())) : "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8533");
    }
    else if (c % 4 == 1)
    {
        json p = json::object();
        p["btf"] = (c & 4) ? btf::Address(g_pk[(signer + 1) % NUM_KEYS]) : btf::Address(g_pk[signer]);
        p["name"] = Clean(rd.Str(rd.U8() % 80));
        p["fee_pct"] = (double)(int8_t)rd.U8();
        if (c & 8) p["miners"] = 1e300; else p["miners"] = rd.U16();
        p["hashrate"] = (c & 16) ? json(-1.0) : json(12345.5);
        content = p.dump();
    }
    else
        content = Clean(rd.Str(rd.U16() % 4096));

    std::string pkHex = Hex(g_pk[signer], 32);
    std::string ser;
    try { ser = json::array({ 0, pkHex, created, kind, tags, content }).dump(); }
    catch (...) { return std::string(); }   // content that is not UTF-8
    unsigned char id[32], sig[64];
    SHA256((const unsigned char*)ser.data(), ser.size(), id);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_ctx, &kp, g_sk[signer]) ||
        !secp256k1_schnorrsig_sign32(g_ctx, sig, id, &kp, NULL))
        abort();
    if (!RefVerify(g_pk[signer], id, sig))
        abort();       // the reference refuses a signature libsecp256k1 made
    json ev = json::object();
    ev["id"] = Hex(id, 32);
    ev["pubkey"] = pkHex;
    ev["created_at"] = created;
    ev["kind"] = kind;
    ev["tags"] = tags;
    ev["content"] = content;
    ev["sig"] = Hex(sig, 64);
    return ev.dump();
}

static void ModeSigned(Reader& rd)
{
    int nNew = 0;
    for (int round = 0; round < 4 && rd.n; round++)
    {
        int signer = 0;
        std::string ev = SignedEvent(rd, signer);
        if (ev.empty())
            continue;
        uint8_t m = rd.U8();
        if (m & 1)
        {
            // One character changed: still the event, or not at all.
            ev[rd.U16() % ev.size()] ^= (char)(rd.U8() | 1);
        }
        bool fValid = CheckEvent(ev);
        if (!(m & 1) && !fValid)
            abort();   // a correctly signed event refused
        const char* sub = (m & 6) == 0 ? SUB_DISC : (m & 6) == 2 ? SUB_POOL : (m & 6) == 4 ? SUB_DESC : "other";
        AllSubscriptions(std::string("[\"EVENT\",\"") + sub + "\"," + ev + "]", nNew);
    }
    AllSubscriptions(std::string("[\"EOSE\",\"") + SUB_DISC + "\"]", nNew);
}

static void FuzzNostrInit()
{
    SelectChainParams(false);
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    g_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    g_p = BN_new();
    g_n = BN_new();
    if (!g_ctx || !g_group || EC_GROUP_get_curve(g_group, g_p, NULL, NULL, NULL) != 1 ||
        EC_GROUP_get_order(g_group, g_n, NULL) != 1)
        abort();
    for (int i = 0; i < NUM_KEYS; i++)
    {
        for (int k = 0; k < 32; k++)
            g_sk[i][k] = (unsigned char)(0x31 * (i + 1) + 5 * k + 7);
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xp;
        if (!secp256k1_keypair_create(g_ctx, &kp, g_sk[i]) || !secp256k1_keypair_xonly_pub(g_ctx, &xp, NULL, &kp))
            abort();
        secp256k1_xonly_pubkey_serialize(g_ctx, g_pk[i], &xp);
    }
    memset(g_self, 0, sizeof(g_self));
    memcpy(g_self, g_pk[3], 32);   // events by key 3 are "ourselves"

    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        std::string dir = pszSeeds;
        auto put = [&](const std::string& name, const std::string& data) {
            FILE* f = fopen((dir + "/" + name).c_str(), "wb");
            if (!f) { perror(name.c_str()); exit(1); }
            fwrite(data.data(), 1, data.size(), f);
            fclose(f);
        };
        // Signed builders: a descriptor event on discovery, a pool
        // announcement, a descriptor lookup answer, a changed event.
        put("signed-disc", std::string("\x07\x00\x09\x00\x00\x00\x00", 7));
        put("signed-pool", std::string("\x07\x01\x0a\x00\x00\x01\x04pool\x07\x05\x00\x02", 15));
        put("signed-desc", std::string("\x07\x00\x09\x00\x00\x00\x04", 7));
        put("signed-changed", std::string("\x07\x02\x09\x00\x00\x00\x01\x30\x00\x02", 10));
        // A WebSocket text frame, a ping, a fragmented message, a close.
        std::string msg = std::string("[\"EOSE\",\"") + SUB_DISC + "\"]";
        std::string ws;
        ws += (char)0x81; ws += (char)msg.size(); ws += msg;
        ws += (char)0x89; ws += (char)0x04; ws += "ping";
        ws += (char)0x01; ws += (char)0x03; ws += "[\"E";
        ws += (char)0x80; ws += (char)0x03; ws += "OSE";
        ws += (char)0x81; ws += (char)0x7e; ws += (char)0x00; ws += (char)0x02; ws += "[]";
        ws += (char)0x88; ws += (char)0x00;
        put("ws", std::string("\x00", 1) + ws);
        put("relay-ok", std::string("\x04") + "[\"OK\",\"" + std::string(64, 'a') + "\",false,\"blocked\"]");
        put("relay-notice", std::string("\x01") + "[\"NOTICE\",\"slow down\"]");
        put("relay-closed", std::string("\x02") + "[\"CLOSED\",\"" + SUB_POOL + "\",\"error\"]");
        put("event-float", std::string("\x05") + "{\"id\":\"00\",\"kind\":1e300,\"created_at\":1.5}");
        std::string triple(1, '\x06');
        triple += std::string((const char*)g_pk[0], 32);
        triple += std::string(32, 'm');
        triple += std::string(64, 's');
        put("bip340-triple", triple);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 200000)
        return 0;
    NostrFuzzReset();
    Reader rd(data + 1, size - 1);
    int nNew = 0;
    switch (data[0] % 8)
    {
    case 0: ModeMessages(rd); break;
    case 1: NostrIngestDiscovery(g_ctx, rd.Str(rd.n), SUB_DISC, g_self, NOW, nNew); CheckCaps(nNew); break;
    case 2: NostrIngestPool(rd.Str(rd.n), SUB_POOL, NOW); CheckCaps(0); break;
    case 3:
    case 4: AllSubscriptions(rd.Str(rd.n), nNew); break;
    case 5: CheckEvent(rd.Str(rd.n)); break;
    case 6:
    {
        std::string b = rd.Str(128);
        b.resize(128, '\0');
        const unsigned char* p = (const unsigned char*)b.data();
        Differential(p, p + 32, p + 64);
        break;
    }
    case 7: ModeSigned(rd); break;
    }
    return 0;
}
