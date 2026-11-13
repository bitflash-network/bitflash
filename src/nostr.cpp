// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Peer discovery over Nostr relays. See nostr.h.

#include "headers.h"
#include "tor.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef _WIN32
#include <wincrypt.h>
#endif
// We link libsecp256k1 statically (without this the header assumes DLL import).
// Both makefiles also pass -DSECP256K1_STATIC; the guard keeps that from
// warning while leaving this file correct if built without the flag.
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

// util.h redefines snprintf as a macro (2009 MSVC compat); this breaks
// nlohmann/json, which calls std::snprintf. Undo the macro just here.
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>
#include <limits>

#include "btfaddr.h"
#include "btfchan.h"
#include "proxy.h"

using json = nlohmann::json;

// Bitflash rendezvous descriptor: parameterized-replaceable Nostr event so each
// node keeps exactly one current descriptor (keyed by author pubkey).
static const int   BTF_DESC_KIND = 38501;
// "-2" scopes the 2026 stable relaunch: new nodes discover only each other, and
// the abandoned test .btf descriptors lingering on the relays become invisible.
static const char* BTF_DESC_DTAG = "btf-descriptor-2";

// Relay auto-discovery: a relay operator announces their relay as an addressable
// event (kind 38502) so every node learns it automatically -- no manual
// seed-list edit, no maintainer approval. Volunteer relays just work.
static const int    BTF_RELAY_KIND = 38502;
static const char*  BTF_RELAY_DTAG = "btf-relay-2";
static const size_t BTF_MAX_DISCOVERED_RELAYS = 50; // anti-spam cap

// Pool announcements carry the operator's .btf address, fee, and live stats.
static const int   BTF_POOL_KIND = 38503;
static const char* BTF_POOL_DTAG  = "btf-pool-2";
static const int64 BTF_POOL_MAX_AGE = 3 * 60; // seconds

// Discovery is per network, or it is not discovery.
//
// Both networks published and subscribed under the same d-tags, so a testnet
// node learned mainnet peers, dialled them, and spent its outbound slots on
// handshakes the magic bytes were always going to reject -- while testnet pool
// announcements sat in the same list as the real ones. Chain separation held
// throughout: what leaked was everyone's time and the operator's attention.
//
// Mainnet keeps the exact tags it publishes today, so nothing already announced
// has to be re-announced. Testnet takes a suffix and the two stop seeing each
// other.
static string BtfNetTag(const char* pszBase)
{
    string s(pszBase);
    if (IsTestNet())
        s += "-testnet";
    return s;
}

// ---- subscriptions ---------------------------------------------------------
//
// Every query gets a subscription id of its own, and reads only what comes back
// addressed to it.
//
// The relay sockets are pooled and reused, and a query that stops early -- the
// descriptor resolver returns the moment one descriptor verifies -- leaves its
// subscription open with events still on the wire. The next question asked over
// that same socket then reads the previous question's answer.
//
// That is not a theory. It was found by asking two questions in a row about the
// same peer: resolve their descriptor, then ask for something else. The second
// answer was the first question's leftovers, and the caller refused it as
// malformed -- correctly, since it was an answer to a different question.
//
// Fixed at the root: a fresh id per query, a reader that ignores anything
// addressed elsewhere, and a CLOSE when the query is done so the relay stops
// sending.
static string NewSubId(const char* pszPrefix)
{
    static CCriticalSection cs_subid;
    static unsigned int nNextSub = 0;
    unsigned int n = 0;
    CRITICAL_BLOCK(cs_subid)
        n = ++nNextSub;
    return strprintf("%s-%u", pszPrefix, n);
}

// True when this relay message answers the subscription we are reading for.
// NOTICE and OK carry something else in that slot, so they fall out here too.
static bool SubMatches(const json& j, const string& strSub)
{
    return j.size() >= 2 && j[1].is_string() && j[1].get<string>() == strSub;
}
// CloseSub() and the publish helpers live further down, with CWebSocket.

// Anonymous auto-discovery: how many peers to keep connected via .btf rendezvous
// before we stop dialing more, and how many new dials to attempt per cycle.
// Target outbound peer count. With ~100 known .btf peers on the network,
// an Erdos-Renyi random graph stays connected with overwhelming probability
// once average degree exceeds ln(N) (~4.6 here); 24 is ~5x past that
// threshold, so this is plenty *provided* selection isn't fully correlated
// across nodes -- see the diversity slice in ConnectDiscoveredBtfPeers.
static const unsigned int BTF_TARGET_CONN   = 24;
static const int          BTF_DIALS_PER_PASS = 12;  // try more peers per Nostr cycle

// Nostr descriptor freshness cutoff: skip peers whose descriptor hasn't been
// refreshed in this many seconds. Stale descriptors mean the node isn't running.
static const int64 BTF_PEER_MAX_AGE = 3 * 60 * 60; // 3 hours

// Other nodes' .btf addresses learned from their descriptors on the relays.
// Maps address -> descriptor created_at timestamp (Unix seconds).
static map<string, int64> g_btfPeers;
static CCriticalSection   cs_btfPeers;

// Public discovery relays. Tunable.
//
// Picked for: free/public (no NIP-42 auth or payment wall), track record of
// high uptime, and *infrastructure* diversity, not just different hostnames.
// relay.damus.io, relay.snort.social and relay.primal.net are all fronted by
// Cloudflare -- different operators, same upstream, so a Cloudflare-side
// incident (or a Cloudflare IP range getting rate-limited/blocked on some
// network) can take out several of them at once even though they look like
// independent relays. Kept only one Cloudflare-fronted relay (damus.io, the
// most established) and filled the rest with relays on different hosts
// (Hetzner, various independents) so no single upstream provider is a
// single point of failure for peer discovery. 7 relays lands inside the
// commonly recommended 5-10 range for redundancy without keeping an
// excessive number of persistent sockets open per node.
const char* pszNostrRelays[] = {
    "wss://relay.damus.io",
    "wss://nos.lol",
    // Was relay.nostr.band, which went down and stayed down (2026-07-31:
    // resolves, refuses TCP on 443, from several networks). Replaced with a
    // relay on a different upstream again -- 206.245.132.32, neither
    // Cloudflare nor Hetzner, which the rest of this list already leans on.
    "wss://nostr.bitcoiner.social",
    "wss://nostr21.com",
    "wss://offchain.pub",
    "wss://nostr.mom",
    "wss://relay.primal.net",
};
const int nNostrRelays = ARRAYLEN(pszNostrRelays);

// Kept only so old call sites still link; the network is onion-only and no
// longer uses rendezvous meeting relays, so there are no baked relay IPs.
vector<string> vBtfMeetingRelays;
string strBtfActiveRelay;
static CCriticalSection cs_activeRelay;
static string strBtfOnionEndpoint;
static CCriticalSection cs_onionEndpoint;

// Only the rendezvous we actually registered at (BtfSetActiveRelay, called from
// ThreadBtfAccept once registration succeeds). Empty until then, on purpose: it
// used to fall back to vBtfMeetingRelays[0], and since ThreadNostrSeed and
// ThreadBtfAccept start in parallel (net.cpp), that fallback is what got
// published at boot -- a descriptor telling peers to dial a relay we were not
// registered at. When that first seed was down, every peer that read the
// descriptor burned a dial on a dead rendezvous.
string BtfActiveRelay()
{
    CRITICAL_BLOCK(cs_activeRelay)
        return strBtfActiveRelay;
    return "";
}

void BtfSetActiveRelay(const string& relay)
{
    CRITICAL_BLOCK(cs_activeRelay)
        strBtfActiveRelay = relay;
}

bool BtfSetLocalOnionEndpoint(const string& endpoint, string& errOut)
{
    string norm;
    if (!btf::NormalizeOnionEndpoint(endpoint, norm))
    {
        errOut = "expected v3 onion endpoint HOST.onion:PORT";
        return false;
    }
    CRITICAL_BLOCK(cs_onionEndpoint)
        strBtfOnionEndpoint = norm;
    return true;
}

string BtfLocalOnionEndpoint()
{
    CRITICAL_BLOCK(cs_onionEndpoint)
        return strBtfOnionEndpoint;
    return "";
}

// A relay this node advertises on Nostr for others to discover (/announcerelay).
string strBtfAnnounceRelay;
// Relays learned from other operators' Nostr announcements.
static set<string> g_discoveredRelays;
static CCriticalSection cs_discoveredRelays;

// Live pool announcements discovered from the relays.
static map<string, BtfPoolAnnouncement> g_discoveredPools;
static CCriticalSection cs_discoveredPools;

// Basic sanity: "host:port" with a numeric 1..65535 port and a plausible host.
static bool LooksLikeRelay(const string& r)
{
    size_t colon = r.rfind(':');
    if (colon == string::npos || colon == 0 || colon + 1 >= r.size())
        return false;
    if (r.size() > 100)
        return false;
    for (size_t i = colon + 1; i < r.size(); i++)
        if (!isdigit((unsigned char)r[i]))
            return false;
    int port = atoi(r.c_str() + colon + 1);
    if (port <= 0 || port > 65535)
        return false;
    // host: allow letters, digits, dot, dash, colon (IPv6 not supported yet)
    for (size_t i = 0; i < colon; i++)
    {
        char c = r[i];
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-'))
            return false;
    }
    return true;
}

// Every relay to try: curated seeds first (reliable bootstrap), then the ones
// discovered from Nostr announcements (volunteer relays).
vector<string> BtfAllRelays()
{
    vector<string> all = vBtfMeetingRelays;
    CRITICAL_BLOCK(cs_discoveredRelays)
        foreach(const string& r, g_discoveredRelays)
            if (find(all.begin(), all.end(), r) == all.end())
                all.push_back(r);
    return all;
}


//
// Utilities
//
static string HexEncode(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++)
    {
        s += h[p[i] >> 4];
        s += h[p[i] & 0xf];
    }
    return s;
}

// Exactly 2n hex digits, nothing else. This used sscanf("%2x"), which also
// takes a sign, "0x" and leading spaces: "-1" read as ff, so two different
// strings off a relay named the same key.
static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool HexDecode(const string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        int hi = HexNibble(s[2 * i]), lo = HexNibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

static string Base64Encode(const unsigned char* p, size_t n)
{
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string s;
    for (size_t i = 0; i < n; i += 3)
    {
        unsigned int b = p[i] << 16;
        if (i + 1 < n) b |= p[i + 1] << 8;
        if (i + 2 < n) b |= p[i + 2];
        s += tbl[(b >> 18) & 0x3f];
        s += tbl[(b >> 12) & 0x3f];
        s += (i + 1 < n) ? tbl[(b >> 6) & 0x3f] : '=';
        s += (i + 2 < n) ? tbl[b & 0x3f] : '=';
    }
    return s;
}


//
// Node Nostr key -- secp256k1 x-only (BIP340), persisted in <appdir>/nostr.key
//
class CNostrKey
{
public:
    secp256k1_context* ctx;
    secp256k1_keypair  keypair;
    unsigned char      seckey[32];   // node's secp256k1 secret (for descriptor signing)
    unsigned char      xonly[32];    // node's x-only pubkey (also its .btf identity)
    unsigned char      enc_pk[32];   // node's x25519 public key (echan `enc` field)
    unsigned char      enc_sk[32];   // node's x25519 secret key
    bool               fValid;

    CNostrKey() : ctx(NULL), fValid(false) {}

    ~CNostrKey()
    {
        if (ctx) secp256k1_context_destroy(ctx);
    }

    // Load or generate a 32-byte key persisted as hex in <appdir>/<name>.
    static void LoadOrGenSecp(secp256k1_context* ctx, const string& file, unsigned char sk[32])
    {
        FILE* f = fopen(file.c_str(), "rb");
        string strHex;
        if (f) { char buf[65] = {0}; fread(buf, 1, 64, f); fclose(f); strHex = buf; }
        if (!HexDecode(strHex, sk, 32) || !secp256k1_ec_seckey_verify(ctx, sk))
        {
            // GetStrongRandBytes aborts if the generator fails, so this loop
            // can neither spin forever nor keep a stale or zero key.
            do { GetStrongRandBytes(sk, 32); } while (!secp256k1_ec_seckey_verify(ctx, sk));
            // Owner-only from the moment it exists: it is this node's identity.
            FILE* fw = OpenPrivateFile(file.c_str(), false);
            if (fw) { string h = HexEncode(sk, 32); fwrite(h.c_str(), 1, h.size(), fw); fclose(fw); }
        }
    }

    bool Init()
    {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!ctx)
            return false;
        unsigned char seed[32];
        GetStrongRandBytes(seed, sizeof(seed));
        secp256k1_context_randomize(ctx, seed);

        LoadOrGenSecp(ctx, GetAppDir() + "/nostr.key", seckey);

        if (!secp256k1_keypair_create(ctx, &keypair, seckey))
            return false;
        secp256k1_xonly_pubkey xpub;
        if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &keypair))
            return false;
        secp256k1_xonly_pubkey_serialize(ctx, xonly, &xpub);

        // x25519 encryption keypair for the end-to-end channel, persisted separately.
        btf::ChanInit();
        string strEncFile = GetAppDir() + "/btf_enc.key";
        FILE* fe = fopen(strEncFile.c_str(), "rb");
        bool fLoaded = false;
        if (fe)
        {
            char buf[65] = {0};
            if (fread(buf, 1, 64, fe) == 64 && HexDecode(string(buf), enc_sk, 32))
                fLoaded = true;
            fclose(fe);
        }
        if (fLoaded)
        {
            // Derive the public key from the stored secret (stable identity).
            btf::ChanPublicFromSecret(enc_pk, enc_sk);
        }
        else
        {
            btf::ChanKeypair(enc_pk, enc_sk);
            FILE* few = fopen(strEncFile.c_str(), "wb");
            if (few) { string h = HexEncode(enc_sk, 32); fwrite(h.c_str(), 1, h.size(), few); fclose(few); }
        }

        fValid = true;
        return true;
    }

    string PubKeyHex() const { return HexEncode(xonly, 32); }
    string EncPubHex() const { return HexEncode(enc_pk, 32); }
    string BtfAddress() const { return btf::Address(xonly); }

    bool SignId(const unsigned char id[32], string& sigHexOut)
    {
        unsigned char sig[64];
        unsigned char aux[32];
        GetStrongRandBytes(aux, sizeof(aux));
        if (!secp256k1_schnorrsig_sign32(ctx, sig, id, &keypair, aux))
            return false;
        sigHexOut = HexEncode(sig, 64);
        return true;
    }
};

// The node's single Nostr/.btf identity, shared by the seeding thread here and
// the rendezvous transport in net.cpp. Lazily initialized under a lock; the
// secp256k1 context is immutable after Init, so concurrent use is safe.
static CNostrKey g_nostrKey;
static CCriticalSection cs_nostrKey;

static bool EnsureNostrKey()
{
    CRITICAL_BLOCK(cs_nostrKey)
        if (!g_nostrKey.fValid)
            g_nostrKey.Init();
    return g_nostrKey.fValid;
}

bool BtfGetIdentity(unsigned char pubkey[32], unsigned char enc_sk[32])
{
    if (!EnsureNostrKey())
        return false;
    memcpy(pubkey, g_nostrKey.xonly, 32);
    memcpy(enc_sk, g_nostrKey.enc_sk, 32);
    return true;
}

std::string BtfLocalAddress()
{
    if (!EnsureNostrKey())
        return "";
    return g_nostrKey.BtfAddress();
}

// This node's own descriptor, signed and self-certifying -- the same blob
// PublishDescriptor puts on Nostr, but handed straight to a peer instead.
//
// Reads strBtfActiveRelay directly rather than going through BtfActiveRelay():
// only a rendezvous we actually registered at is worth announcing. Handing out
// a meeting node we are not reachable at would make every peer that receives
// it burn a dial, and over peer exchange that mistake travels further than it
// does over Nostr.
std::string BtfLocalDescriptor()
{
    if (!EnsureNostrKey())
        return "";
    // Onion-only: we advertise our Tor hidden service and never a rendezvous
    // meeting node. With no onion yet there is nothing reachable to publish.
    string onion = BtfLocalOnionEndpoint();
    if (onion.empty())
        return "";
    return btf::SignDescriptor(g_nostrKey.ctx, g_nostrKey.seckey,
                               g_nostrKey.EncPubHex(), "", (uint64_t)GetTime(),
                               onion);
}

// The shared secp256k1 context, so net.cpp can verify descriptors that arrive
// from peers. NULL if the identity could not be loaded.
void* BtfSecpContext()
{
    if (!EnsureNostrKey())
        return NULL;
    return (void*)g_nostrKey.ctx;
}

int GetDiscoveredPeerCount()
{
    int n = 0;
    CRITICAL_BLOCK(cs_btfPeers) { n = (int)g_btfPeers.size(); }
    return n;
}

void BtfGetPoolAnnouncements(std::vector<BtfPoolAnnouncement>& out)
{
    out.clear();
    int64 now = GetTime();
    CRITICAL_BLOCK(cs_discoveredPools)
    {
        for (map<string, BtfPoolAnnouncement>::iterator it = g_discoveredPools.begin(); it != g_discoveredPools.end(); )
        {
            if (it->second.createdAt > 0 && now - it->second.createdAt > BTF_POOL_MAX_AGE)
            {
                it = g_discoveredPools.erase(it);
                continue;
            }
            out.push_back(it->second);
            ++it;
        }
    }
    sort(out.begin(), out.end(), [](const BtfPoolAnnouncement& a, const BtfPoolAnnouncement& b) {
        return a.createdAt > b.createdAt;
    });
}

// Build and sign a Nostr event (NIP-01). Returns the event JSON.
static bool BuildSignedEvent(CNostrKey& key, int kind, const json& tags,
                             const string& content, json& eventOut)
{
    int64 created = GetTime();
    // Canonical serialization for the id: [0,pubkey,created_at,kind,tags,content]
    json ser = json::array({ 0, key.PubKeyHex(), created, kind, tags, content });
    string s = ser.dump();

    unsigned char id[32];
    SHA256((const unsigned char*)s.data(), s.size(), id);

    string sigHex;
    if (!key.SignId(id, sigHex))
        return false;

    eventOut = json::object();
    eventOut["id"]         = HexEncode(id, 32);
    eventOut["pubkey"]     = key.PubKeyHex();
    eventOut["created_at"] = created;
    eventOut["kind"]       = kind;
    eventOut["tags"]       = tags;
    eventOut["content"]    = content;
    eventOut["sig"]        = sigHex;
    return true;
}


//
// Minimal WebSocket client over TLS (wss) or TCP (ws), blocking with timeout.
//
// Ceilings on what a relay may make this node allocate. Nostr events are
// small -- relays themselves usually refuse anything over a few hundred KB --
// so these are generous, and they bound an otherwise attacker-chosen size.
static const uint64 MAX_WS_FRAME   = 1 << 20;  // 1 MiB per frame
static const uint64 MAX_WS_MESSAGE = 4 << 20;  // 4 MiB reassembled

static int BtfConnectedNodeCount()
{
    int nNodes = 0;
    CRITICAL_BLOCK(cs_vNodes)
    {
        nNodes = (int)vNodes.size();
    }
    return nNodes;
}

#ifdef _WIN32
static bool BtfLoadWindowsRootCertificates(SSL_CTX* sslctx)
{
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
    if (!hStore)
        return false;

    bool fLoaded = false;
    X509_STORE* x509store = SSL_CTX_get_cert_store(sslctx);
    PCCERT_CONTEXT pCert = NULL;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL)
    {
        const unsigned char* p = pCert->pbCertEncoded;
        X509* x509 = d2i_X509(NULL, &p, pCert->cbCertEncoded);
        if (!x509)
            continue;
        if (X509_STORE_add_cert(x509store, x509) == 1)
            fLoaded = true;
        X509_free(x509);
    }
    CertCloseStore(hStore, 0);
    return fLoaded;
}
#endif

class CWebSocket
{
public:
    SOCKET     hSocket;
    SSL_CTX*   sslctx;
    SSL*       ssl;
    bool       fTls;
    string     recvbuf;

    CWebSocket() : hSocket(INVALID_SOCKET), sslctx(NULL), ssl(NULL), fTls(false) {}
    ~CWebSocket() { Close(); }

    void Close()
    {
        if (ssl)    { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
        if (sslctx) { SSL_CTX_free(sslctx); sslctx = NULL; }
        if (hSocket != INVALID_SOCKET) { BtfCloseSocket(hSocket); hSocket = INVALID_SOCKET; }
    }

    int RawRead(char* buf, int len)
    {
        if (fTls) return SSL_read(ssl, buf, len);
        return recv(hSocket, buf, len, 0);
    }

    bool RawWrite(const char* buf, int len)
    {
        int off = 0;
        while (off < len)
        {
            int n = fTls ? SSL_write(ssl, buf + off, len - off)
                         : send(hSocket, buf + off, len - off, BTF_SEND_FLAGS);
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }

    // Connect and perform the WebSocket handshake. url = wss://host[:port]/path
    bool Connect(const string& url, int timeoutSec)
    {
        // Every relay goes through here: an isolated bench says nothing to
        // the public relays, whatever mode it runs in (a bench node in
        // -operator mode used to announce itself as a pool).
        if (fBtfIsolated)
            return false;
        string u = url;
        int port = 443;
        fTls = true;
        if (u.compare(0, 6, "wss://") == 0) { u = u.substr(6); fTls = true; port = 443; }
        else if (u.compare(0, 5, "ws://") == 0) { u = u.substr(5); fTls = false; port = 80; }
        else return false;

        string host, path = "/";
        size_t slash = u.find('/');
        if (slash != string::npos) { host = u.substr(0, slash); path = u.substr(slash); }
        else host = u;
        size_t colon = host.find(':');
        if (colon != string::npos) { port = atoi(host.substr(colon + 1).c_str()); host = host.substr(0, colon); }

        hSocket = BtfConnectSocket(host, (unsigned short)port, SOCK_NOSTR, timeoutSec);
        if (hSocket == INVALID_SOCKET)
            return error("Nostr: connect %s:%d failed", host.c_str(), port);

        // TLS
        if (fTls)
        {
            sslctx = SSL_CTX_new(TLS_client_method());
            if (!sslctx) return false;
            SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);
            bool fTrustLoaded = (SSL_CTX_set_default_verify_paths(sslctx) == 1);
#ifdef _WIN32
            fTrustLoaded = BtfLoadWindowsRootCertificates(sslctx) || fTrustLoaded;
#endif
            if (!fTrustLoaded)
                return error("Nostr: failed to load TLS trust store");
            ssl = SSL_new(sslctx);
            if (!ssl) return false;
            SSL_set_fd(ssl, (int)hSocket);
            if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1)
                return error("Nostr: failed to set TLS SNI for %s", host.c_str());
            if (SSL_set1_host(ssl, host.c_str()) != 1)
                return error("Nostr: failed to set TLS hostname for %s", host.c_str());
            if (SSL_connect(ssl) != 1)
                return error("Nostr: TLS handshake with %s failed", host.c_str());
            long nVerify = SSL_get_verify_result(ssl);
            if (nVerify != X509_V_OK)
                return error("Nostr: TLS certificate verification failed for %s: %s",
                             host.c_str(), X509_verify_cert_error_string(nVerify));
        }

        // WebSocket handshake (HTTP Upgrade)
        unsigned char keybytes[16];
        GetStrongRandBytes(keybytes, sizeof(keybytes));
        string wskey = Base64Encode(keybytes, sizeof(keybytes));
        string req =
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + wskey + "\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        if (!RawWrite(req.data(), (int)req.size()))
            return false;
        return ReadHandshakeResponse(host);
    }

    // The relay's answer to the upgrade request, up to and including the
    // blank line. True only for a 101 status line, with nothing read past it.
    bool ReadHandshakeResponse(const string& host)
    {
        // Read the handshake response until \r\n\r\n
        string resp;
        char c;
        while (resp.size() < 4 || resp.compare(resp.size() - 4, 4, "\r\n\r\n") != 0)
        {
            int n = RawRead(&c, 1);
            if (n <= 0) return error("Nostr: no handshake response from %s", host.c_str());
            resp += c;
            // Bail out instead of breaking: breaking left the socket parked in
            // the middle of the header block, and since the status line is read
            // first the " 101 " check below still passed -- so the caller got a
            // "connected" socket whose next bytes were leftover HTTP, which the
            // frame parser then read as garbage frames.
            if (resp.size() > 8192)
                return error("Nostr: handshake headers too large from %s", host.c_str());
        }
        // The status line says 101, not some header further down: "HTTP/1.1
        // 403 Forbidden" with an "X-Note: 101 " header used to count as an
        // upgrade, and the error page was then read as frames.
        if (resp.compare(0, 13, "HTTP/1.1 101 ") != 0 && resp.compare(0, 14, "HTTP/1.1 101\r\n") != 0)
            return error("Nostr: handshake refused by %s", host.c_str());
        return true;
    }

    // Send a text message (masked frame, as required by the protocol)
    bool SendText(const string& msg)
    {
        string frame;
        frame += (char)0x81; // FIN + opcode texto
        size_t len = msg.size();
        if (len < 126)
            frame += (char)(0x80 | len);
        else if (len <= 0xffff)
        {
            frame += (char)(0x80 | 126);
            frame += (char)((len >> 8) & 0xff);
            frame += (char)(len & 0xff);
        }
        else
        {
            frame += (char)(0x80 | 127);
            for (int i = 7; i >= 0; i--) frame += (char)((len >> (8 * i)) & 0xff);
        }
        unsigned char mask[4];
        GetStrongRandBytes(mask, 4);
        frame.append((char*)mask, 4);
        string masked = msg;
        for (size_t i = 0; i < masked.size(); i++)
            masked[i] ^= mask[i & 3];
        frame += masked;
        return RawWrite(frame.data(), (int)frame.size());
    }

    // Receive the next complete text message. Returns false on error/timeout.
    bool RecvText(string& out)
    {
        out.clear();
        bool fInMessage = false;
        int nControl = 0;
        for (;;)
        {
            unsigned char hdr[2];
            if (!ReadN((char*)hdr, 2)) return false;
            bool fin = hdr[0] & 0x80;
            int opcode = hdr[0] & 0x0f;
            bool masked = hdr[1] & 0x80;
            // RFC 6455 5.2-5.5: no extension was negotiated, so the RSV bits
            // are 0; opcodes 3-7 and 11-15 are reserved; a control frame
            // (close, ping, pong) is unfragmented and carries at most 125
            // bytes -- SendPong echoes a ping in a one-byte length, so a
            // longer one went back as a corrupt frame; a continuation needs a
            // message to continue and a new message needs the last one ended.
            if (hdr[0] & 0x70) return false;
            if ((opcode >= 0x3 && opcode <= 0x7) || opcode >= 0xB) return false;
            if (opcode >= 0x8 && (!fin || (hdr[1] & 0x7f) > 125)) return false;
            if (opcode == 0x0 && !fInMessage) return false;
            if ((opcode == 0x1 || opcode == 0x2) && fInMessage) return false;
            // Pings and pongs answer no question: a relay sending nothing
            // else would otherwise keep this loop, and its thread, forever.
            if (opcode >= 0x8 && ++nControl > 4096) return false;
            uint64 len = hdr[1] & 0x7f;
            if (len == 126)
            {
                unsigned char e[2];
                if (!ReadN((char*)e, 2)) return false;
                len = (e[0] << 8) | e[1];
            }
            else if (len == 127)
            {
                unsigned char e[8];
                if (!ReadN((char*)e, 8)) return false;
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
            }
            // The length is whatever the relay says it is, and these are public
            // relays the node does not control. Unbounded, a single frame header
            // claiming 2^40 bytes makes the node allocate until it dies -- and
            // reassembly across continuation frames grows without limit even
            // when each frame is small. Cap both, and refuse anything that will
            // not survive the int narrowing ReadN takes.
            if (len > MAX_WS_FRAME) return false;

            unsigned char mask[4] = {0,0,0,0};
            if (masked && !ReadN((char*)mask, 4)) return false;

            string payload;
            payload.resize((size_t)len);
            if (len && !ReadN(&payload[0], (int)len)) return false;
            if (masked)
                for (size_t i = 0; i < payload.size(); i++)
                    payload[i] ^= mask[i & 3];

            if (opcode == 0x8) return false;                 // close
            if (opcode == 0x9) { SendPong(payload); continue; } // ping
            if (opcode == 0xA) continue;                      // pong
            if (out.size() + payload.size() > MAX_WS_MESSAGE) return false;
            out += payload;                                   // text/continuation
            if (fin) return true;
            fInMessage = true;
        }
    }

private:
    bool ReadN(char* buf, int n)
    {
        int off = 0;
        while (off < n)
        {
            int r = RawRead(buf + off, n - off);
            if (r <= 0) return false;
            off += r;
        }
        return true;
    }

    void SendPong(const string& payload)
    {
        string frame;
        frame += (char)0x8A;
        frame += (char)(0x80 | (payload.size() & 0x7f));
        unsigned char mask[4]; GetStrongRandBytes(mask, 4);
        frame.append((char*)mask, 4);
        string m = payload;
        for (size_t i = 0; i < m.size(); i++) m[i] ^= mask[i & 3];
        frame += m;
        RawWrite(frame.data(), (int)frame.size());
    }
};

// A relay's half of a connection, read the way every relay call reads it: the
// answer to the upgrade request, then up to nMax messages. Plain TCP, the
// bytes TLS would carry. For the self-test and fuzz-http-client, which play
// the relay over a local socket (declared there; nostr.h does not know
// SOCKET). The socket stays the caller's. False when the upgrade was refused.
bool BtfNostrReadRelayStream(SOCKET s, size_t nMax, vector<string>& vMsgOut)
{
    CWebSocket ws;
    ws.hSocket = s;
    ws.fTls = false;
    bool fOk = ws.ReadHandshakeResponse("test relay");
    string msg;
    while (fOk && vMsgOut.size() < nMax && ws.RecvText(msg))
        vMsgOut.push_back(msg);
    ws.hSocket = INVALID_SOCKET;
    return fOk;
}


// Persistent relay connections. Public relays (relay.damus.io in particular)
// rate-limit new connections per source IP fairly aggressively. Before this,
// every single operation -- self-test, per-pass seeding, batch descriptor
// resolve, pool announce, pool query -- opened its own fresh CWebSocket,
// meaning a single node could fire a dozen-plus brand-new TCP+TLS+WS
// handshakes at the same 4 relays within any given minute (ThreadNostrSeed's
// own loop plus the separate ThreadBtfPoolAnnouncer thread, each reconnecting
// from scratch every cycle). That's exactly what was showing up as constant
// "handshake refused by relay.damus.io" and "connect ... failed" -- not
// necessarily dead relays, just this node getting rate-limited by its own
// reconnect churn.
//
// Now every relay-touching call reuses one long-lived socket per relay via
// this pool, reconnecting only when a socket actually drops. That cuts fresh
// connections from several per minute down to essentially one per relay for
// the life of the process.
struct RelayConn
{
    CWebSocket ws;
    CCriticalSection cs;   // serializes use of this relay's socket
    bool fConnected;
    RelayConn() : fConnected(false) {}
};
static map<string, RelayConn*> g_relayPool;
static CCriticalSection cs_relayPool;

static RelayConn* GetRelayConn(const string& relay)
{
    CRITICAL_BLOCK(cs_relayPool)
    {
        map<string, RelayConn*>::iterator it = g_relayPool.find(relay);
        if (it != g_relayPool.end())
            return it->second;
        RelayConn* rc = new RelayConn();
        g_relayPool[relay] = rc;
        return rc;
    }
    return NULL; // unreachable
}

// RAII lease on a relay's pooled connection: connects (if not already
// connected) on construction, and on destruction either keeps the socket
// alive for the next caller (if the exchange succeeded) or closes it so the
// next caller reconnects instead of reusing a socket that may be wedged.
// Caller must set fOk = true once its exchange with the relay completed
// cleanly.
// Tell the relay to stop a subscription. Sockets here are pooled and reused, so
// a subscription left open goes on delivering into whatever the next query is
// reading. See NewSubId above.
static void CloseSub(CWebSocket& ws, const string& strSub)
{
    ws.SendText(json::array({ "CLOSE", strSub }).dump());
}

// Did the relay actually take the event? 1 = yes, 0 = it said no, -1 = it never
// answered.
//
// SendText() returning true means the bytes reached the socket, and nothing
// beyond that. A relay that refuses an event -- unknown kind, rate limit, bad
// timestamp, too large, paid relay -- says so in an OK frame, and nobody here
// was listening. So "no relay accepted this" was reporting on whether a write
// succeeded, which it almost always does.
//
// The node publishes its own .btf descriptor this way. If every relay refused
// it, the node would be invisible to the whole network and nothing, anywhere,
// would say a word.
static int WaitForRelayOk(CWebSocket& ws, const string& strEventId, string& strReasonOut)
{
    strReasonOut.clear();
    // Bounded twice over: the socket carries a receive timeout, and a relay that
    // chatters without ever answering must not hold this thread.
    for (int i = 0; i < 20; i++)
    {
        string msg;
        if (!ws.RecvText(msg))
        {
            strReasonOut = "no answer";
            return -1;
        }
        int n = NostrRelayOk(msg, strEventId, strReasonOut);
        if (n >= 0)
            return n;
    }
    strReasonOut = "never said whether it took it";
    return -1;
}

class CRelayLease
{
public:
    RelayConn* rc;
    bool fOk;
    bool fJustConnected; // true if this lease had to (re)connect, false if reusing a live socket

    CRelayLease(const string& relay, int timeoutSec) : rc(NULL), fOk(false), fJustConnected(false)
    {
        rc = GetRelayConn(relay);
        rc->cs.Enter();
        if (!rc->fConnected)
        {
            rc->ws.Close();
            rc->fConnected = rc->ws.Connect(relay, timeoutSec);
            fJustConnected = rc->fConnected;
            // A relay that answered is proof Tor carried a connection end to
            // end. The Tor watchdog needs to hear it: in a build with no peers
            // to count, this is the only honest evidence that Tor works, and
            // without it the watchdog restarts Tor with bridges forever.
            if (rc->fConnected)
                BtfTorNoteNetworkReached();
        }
    }
    ~CRelayLease()
    {
        if (!fOk)
        {
            rc->ws.Close();
            rc->fConnected = false;
        }
        rc->cs.Leave();
    }
    bool Connected() const { return rc->fConnected; }
    CWebSocket& Ws() { return rc->ws; }

private:
    CRelayLease(const CRelayLease&);
    CRelayLease& operator=(const CRelayLease&);
};


// Publish this node's self-certifying `.btf` descriptor: "reach me (this key)
// via <meeting_node>, encrypting to my x25519 key <enc>". Signed by the node
// key so only the address's owner can publish it (no hijacking).
static void PublishDescriptor(CWebSocket& ws, CNostrKey& key)
{
    // Onion-only: we advertise our Tor hidden service, never a rendezvous
    // meeting node. Until the hidden service is up there is nothing to publish.
    string onion = BtfLocalOnionEndpoint();
    if (onion.empty())
    {
        LogPrint("nostr", "Nostr: skipping descriptor publish, no onion endpoint yet\n");
        return;
    }
    string desc = btf::SignDescriptor(key.ctx, key.seckey, key.EncPubHex(),
                                      "", (uint64_t)GetTime(),
                                      onion);
    if (desc.empty())
        return;
    json tags = json::array({ json::array({ "d", BtfNetTag(BTF_DESC_DTAG) }) });
    json ev;
    if (BuildSignedEvent(key, BTF_DESC_KIND, tags, desc, ev))
    {
        json pub = json::array({ "EVENT", ev });
        if (!ws.SendText(pub.dump()))
            return;
        // This is how the node tells the network it exists. A relay that refuses
        // it -- rate limit, policy, anything -- used to be indistinguishable from
        // one that stored it, so a node could sit there invisible, publishing
        // into nothing, with a clean log.
        string strWhy;
        int n = WaitForRelayOk(ws, ev.value("id", string()), strWhy);
        if (n == 1)
            LogPrint("nostr", "Nostr: descriptor stored\n");
        else
            printf("Nostr: the relay did not store our descriptor (%s)\n", strWhy.c_str());
    }
}

// Announce our relay (from /announcerelay=host:port) so every node discovers it
// automatically -- volunteer relays join the network with no maintainer step.
static void PublishRelayAnnouncement(CWebSocket& ws, CNostrKey& key)
{
    if (strBtfAnnounceRelay.empty())
        return;
    json tags = json::array({ json::array({ "d", BtfNetTag(BTF_RELAY_DTAG) }) });
    json ev;
    if (BuildSignedEvent(key, BTF_RELAY_KIND, tags, strBtfAnnounceRelay, ev))
    {
        json pub = json::array({ "EVENT", ev });
        ws.SendText(pub.dump());
    }
}

static bool PublishPoolAnnouncementOnRelay(CWebSocket& ws, CNostrKey& key,
                                           const BtfPoolAnnouncement& ann)
{
    if (ann.btfAddress.empty() || ann.poolName.empty())
        return false;

    json content = json::object();
    content["btf"] = ann.btfAddress;
    content["name"] = ann.poolName;
    if (!ann.dashboardUrl.empty())
        content["dashboard_url"] = ann.dashboardUrl;
    content["fee_pct"] = ann.feePercent;
    content["miners"] = ann.connectedMiners;
    content["blocks"] = ann.blocksFound;
    content["hashrate"] = ann.hashRate;

    json tags = json::array({
        json::array({ "d", BtfNetTag(BTF_POOL_DTAG) }),
        json::array({ "t", BtfNetTag(BTF_POOL_DTAG) })
    });
    json ev;
    if (!BuildSignedEvent(key, BTF_POOL_KIND, tags, content.dump(), ev))
        return false;
    json pub = json::array({ "EVENT", ev });
    return ws.SendText(pub.dump());
}

bool BtfPublishPoolAnnouncement(const BtfPoolAnnouncement& ann)
{
    if (!EnsureNostrKey())
        return false;

    bool fPublished = false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            if (PublishPoolAnnouncementOnRelay(lease.Ws(), g_nostrKey, ann))
                fPublished = lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfPublishPoolAnnouncement")
    }
    return fPublished;
}

// At most nMax bytes, cut where a character begins: what we publish is what
// PoolFromEvent accepts (a longer name or URL would be refused by every node),
// and a cut inside a character would not be text.
string NostrClampUtf8(const string& str, size_t nMax)
{
    if (str.size() <= nMax)
        return str;
    size_t n = nMax;
    while (n > 0 && ((unsigned char)str[n] & 0xC0) == 0x80)
        n--;
    return str.substr(0, n);
}

// Defined below, with the rest of what relays send.
static int NostrSubMessage(const string& msg, const string& strSub, json& evOut);
static bool PoolFromEvent(const json& ev, int64 nNow, BtfPoolAnnouncement& ann, string& err);

bool BtfQueryPoolAnnouncement(const std::string& poolBtfAddr, BtfPoolAnnouncement& out)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(poolBtfAddr, pk))
        return false;

    if (!EnsureNostrKey())
        return false;

    int64 bestCreatedAt = 0;
    bool fFound = false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            CWebSocket& ws = lease.Ws();

            json filter = json::object();
            filter["authors"] = json::array({ HexEncode(pk, 32) });
            filter["kinds"] = json::array({ BTF_POOL_KIND });
            filter["#d"] = json::array({ BtfNetTag(BTF_POOL_DTAG) });
            filter["limit"] = 1;
            string strSub = NewSubId("btf-pool-query");
            json req = json::array({ "REQ", strSub, filter });
            if (!ws.SendText(req.dump()))
                continue;

            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json ev;
                int n = NostrSubMessage(msg, strSub, ev);
                if (n == NOSTR_MSG_EOSE)
                    break;
                if (n != NOSTR_MSG_EVENT)
                    continue;
                BtfPoolAnnouncement ann;
                string err;
                if (!PoolFromEvent(ev, GetTime(), ann, err))
                    continue;
                if (ann.btfAddress == poolBtfAddr && ann.createdAt >= bestCreatedAt)
                {
                    bestCreatedAt = ann.createdAt;
                    out = ann;
                    fFound = true;
                }
            }
            CloseSub(ws, strSub);
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfQueryPoolAnnouncement")
    }

    return fFound;
}

// ---- what relays send, checked without a socket ------------------------------
//
// A relay is a stranger's server. It can send any JSON it likes, invent events
// under any public key, date them in the future, and send as many as it likes.
// Everything a relay hands this node goes through the functions below, which
// never touch a socket, so the self-tests and the fuzzer can feed them bytes.

// An integer field, read whole. nlohmann converts a float to int with a plain
// cast, which is undefined behaviour out of range (1e300), so only real
// integers are taken.
static bool NostrIntField(const json& j, const char* key, int64& out)
{
    if (!j.is_object() || !j.contains(key))
        return false;
    const json& v = j[key];
    if (v.is_number_unsigned())
    {
        uint64_t u = v.get<uint64_t>();
        if (u > (uint64_t)std::numeric_limits<int64>::max())
            return false;
        out = (int64)u;
        return true;
    }
    if (!v.is_number_integer())
        return false;
    out = v.get<int64_t>();
    return true;
}

static bool NostrStrField(const json& j, const char* key, string& out)
{
    if (!j.is_object() || !j.contains(key) || !j[key].is_string())
        return false;
    out = j[key].get<string>();
    return true;
}

static bool IsLowerHex(const string& s, size_t nBytes)
{
    if (s.size() != nBytes * 2)
        return false;
    for (size_t i = 0; i < s.size(); i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

// NIP-01: the id is SHA-256 of [0,pubkey,created_at,kind,tags,content]
// serialized without whitespace, and sig is a BIP-340 signature of the id by
// pubkey. Both are checked here; an event that fails either is someone else's
// words under that key.
static bool NostrCheckEvent(secp256k1_context* ctx, const json& ev, NostrEvent& out, string& errOut)
{
    errOut.clear();
    if (!ctx) { errOut = "no secp256k1 context"; return false; }
    if (!ev.is_object()) { errOut = "an event is an object"; return false; }
    NostrEvent e;
    int64 nKind = 0;
    if (!NostrStrField(ev, "id", e.id) || !IsLowerHex(e.id, 32)) { errOut = "bad id"; return false; }
    if (!NostrStrField(ev, "pubkey", e.pubkey) || !IsLowerHex(e.pubkey, 32)) { errOut = "bad pubkey"; return false; }
    if (!NostrStrField(ev, "sig", e.sig) || !IsLowerHex(e.sig, 64)) { errOut = "bad sig"; return false; }
    if (!NostrIntField(ev, "created_at", e.created_at) || e.created_at < 0) { errOut = "bad created_at"; return false; }
    if (!NostrIntField(ev, "kind", nKind) || nKind < 0 || nKind > 65535) { errOut = "bad kind"; return false; }
    e.kind = (int)nKind;
    if (!NostrStrField(ev, "content", e.content)) { errOut = "bad content"; return false; }
    if (!ev.contains("tags") || !ev["tags"].is_array()) { errOut = "bad tags"; return false; }
    const json& tags = ev["tags"];
    for (size_t i = 0; i < tags.size(); i++)
    {
        if (!tags[i].is_array()) { errOut = "a tag is an array"; return false; }
        std::vector<std::string> t;
        for (size_t k = 0; k < tags[i].size(); k++)
        {
            if (!tags[i][k].is_string()) { errOut = "a tag holds strings"; return false; }
            t.push_back(tags[i][k].get<string>());
        }
        e.tags.push_back(t);
    }

    string ser;
    try { ser = json::array({ 0, e.pubkey, e.created_at, e.kind, tags, e.content }).dump(); }
    catch (...) { errOut = "the event does not serialize"; return false; }
    unsigned char id[32], idClaimed[32], pk[32], sig[64];
    SHA256((const unsigned char*)ser.data(), ser.size(), id);
    if (!HexDecode(e.id, idClaimed, 32) || memcmp(id, idClaimed, 32) != 0) { errOut = "the id is not the event's hash"; return false; }
    if (!HexDecode(e.pubkey, pk, 32) || !HexDecode(e.sig, sig, 64)) { errOut = "bad hex"; return false; }
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, pk)) { errOut = "the pubkey is not a point"; return false; }
    if (!secp256k1_schnorrsig_verify(ctx, sig, id, 32, &xpub)) { errOut = "the signature does not verify"; return false; }
    out = e;
    return true;
}

static secp256k1_context* NostrVerifyContext()
{
    static secp256k1_context* ctx = NULL;
    static CCriticalSection cs_ctx;
    CRITICAL_BLOCK(cs_ctx)
        if (!ctx)
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

bool NostrVerifyEvent(void* secpctx, const std::string& eventJson, NostrEvent& out, std::string& errOut)
{
    json ev;
    try { ev = json::parse(eventJson); }
    catch (...) { errOut = "not JSON"; return false; }
    return NostrCheckEvent(secpctx ? (secp256k1_context*)secpctx : NostrVerifyContext(), ev, out, errOut);
}

int NostrRelayOk(const std::string& msg, const std::string& strEventId, std::string& strReasonOut)
{
    json j;
    try { j = json::parse(msg); } catch (...) { return -1; }
    if (!j.is_array() || j.size() < 3 || !j[0].is_string()) return -1;
    if (j[0].get<string>() != "OK") return -1;
    if (!j[1].is_string() || j[1].get<string>() != strEventId) return -1;
    if (j[2].is_boolean() && j[2].get<bool>())
        return 1;
    strReasonOut = (j.size() >= 4 && j[3].is_string() && !j[3].get<string>().empty())
                       ? j[3].get<string>() : "refused";
    return 0;
}

// A relay message for subscription strSub: NOSTR_MSG_OTHER if it is not an
// EVENT or EOSE for it, NOSTR_MSG_EOSE, or NOSTR_MSG_EVENT with the event in
// evOut (not yet checked).
static int NostrSubMessage(const string& msg, const string& strSub, json& evOut)
{
    json j;
    try { j = json::parse(msg); } catch (...) { return NOSTR_MSG_OTHER; }
    if (!j.is_array() || j.empty() || !j[0].is_string()) return NOSTR_MSG_OTHER;
    if (!SubMatches(j, strSub)) return NOSTR_MSG_OTHER;
    string t = j[0].get<string>();
    if (t == "EOSE")
        return NOSTR_MSG_EOSE;
    if (t == "EVENT" && j.size() >= 3)
    {
        evOut = j[2];
        return NOSTR_MSG_EVENT;
    }
    return NOSTR_MSG_OTHER;
}

static bool EventHasTag(const NostrEvent& e, const string& name, const string& value)
{
    for (size_t i = 0; i < e.tags.size(); i++)
        if (e.tags[i].size() >= 2 && e.tags[i][0] == name && e.tags[i][1] == value)
            return true;
    return false;
}

// Keep g_btfPeers at NOSTR_MAX_BTF_PEERS: the oldest descriptors go first.
static void TrimBtfPeers()
{
    while (g_btfPeers.size() > NOSTR_MAX_BTF_PEERS)
    {
        map<string, int64>::iterator oldest = g_btfPeers.begin();
        for (map<string, int64>::iterator it = g_btfPeers.begin(); it != g_btfPeers.end(); ++it)
            if (it->second < oldest->second)
                oldest = it;
        g_btfPeers.erase(oldest);
    }
}

int NostrIngestDiscovery(void* secpctx, const std::string& msg, const std::string& strSub,
                         const unsigned char selfXonly[32], int64 nNow, int& nNewThisRound)
{
    json ev;
    int n = NostrSubMessage(msg, strSub, ev);
    if (n != NOSTR_MSG_EVENT)
        return n;
    NostrEvent e;
    string err;
    if (!NostrCheckEvent(secpctx ? (secp256k1_context*)secpctx : NostrVerifyContext(), ev, e, err))
    {
        LogPrint("nostr", "Nostr: discovery event refused: %s\n", err.c_str());
        return NOSTR_MSG_REFUSED;
    }
    if (e.kind != BTF_DESC_KIND || !EventHasTag(e, "d", BtfNetTag(BTF_DESC_DTAG)))
        return NOSTR_MSG_REFUSED;
    // A date in the future would sort first forever and never go stale.
    if (e.created_at > nNow + NOSTR_MAX_FUTURE)
        return NOSTR_MSG_REFUSED;
    if (e.created_at < nNow - BTF_PEER_MAX_AGE)
        return NOSTR_MSG_REFUSED;     // stale already: nothing to dial
    unsigned char pkb[32];
    if (!HexDecode(e.pubkey, pkb, 32))
        return NOSTR_MSG_REFUSED;
    if (selfXonly && memcmp(pkb, selfXonly, 32) == 0)
        return NOSTR_MSG_REFUSED;     // ourselves
    string peerAddr = btf::Address(pkb);
    bool fNew = false;
    CRITICAL_BLOCK(cs_btfPeers)
    {
        map<string, int64>::iterator it = g_btfPeers.find(peerAddr);
        if (it != g_btfPeers.end())
        {
            if (e.created_at > it->second)
                it->second = e.created_at;     // refresh
        }
        else if (nNewThisRound < (int)NOSTR_MAX_NEW_PEERS_PER_ROUND)
        {
            g_btfPeers[peerAddr] = e.created_at;
            nNewThisRound++;
            fNew = true;
            TrimBtfPeers();
        }
    }
    if (fNew && fDebug)
        LogPrint("nostr", "Nostr: discovered .btf peer %s\n", peerAddr.c_str());
    return NOSTR_MSG_TAKEN;
}

// The pool's announcement: signed, of the pool kind, by the key whose .btf
// address it announces -- a pool speaks only for itself.
static bool PoolFromEvent(const json& ev, int64 nNow, BtfPoolAnnouncement& ann, string& err)
{
    NostrEvent e;
    if (!NostrCheckEvent(NostrVerifyContext(), ev, e, err))
        return false;
    if (e.kind != BTF_POOL_KIND) { err = "not a pool announcement"; return false; }
    if (e.created_at > nNow + NOSTR_MAX_FUTURE) { err = "dated in the future"; return false; }
    json content;
    try { content = json::parse(e.content); }
    catch (...) { err = "the content is not JSON"; return false; }
    if (!content.is_object()) { err = "the content is not an object"; return false; }
    if (!NostrStrField(content, "btf", ann.btfAddress)) NostrStrField(content, "address", ann.btfAddress);
    if (!NostrStrField(content, "name", ann.poolName)) NostrStrField(content, "pool_name", ann.poolName);
    if (!NostrStrField(content, "dashboard_url", ann.dashboardUrl)) NostrStrField(content, "dashboard", ann.dashboardUrl);
    if (ann.btfAddress.empty() || ann.poolName.empty()) { err = "no address or name"; return false; }
    if (ann.poolName.size() > NOSTR_MAX_POOL_NAME || ann.dashboardUrl.size() > NOSTR_MAX_DASHBOARD_URL) { err = "too long"; return false; }
    unsigned char pk[32];
    if (!HexDecode(e.pubkey, pk, 32) || btf::Address(pk) != ann.btfAddress) { err = "announces another key's address"; return false; }
    // Numbers as numbers, finite and in range; anything else reads as 0.
    double d = 0;
    if ((content.contains("fee_pct") && content["fee_pct"].is_number()) ) d = content["fee_pct"].get<double>();
    else if (content.contains("fee") && content["fee"].is_number()) d = content["fee"].get<double>();
    ann.feePercent = (d >= 0 && d <= 100) ? d : 0;
    int64 n = 0;
    ann.connectedMiners = NostrIntField(content, "miners", n) && n >= 0 && n <= 1000000000 ? (int)n : 0;
    n = 0;
    ann.blocksFound = NostrIntField(content, "blocks", n) && n >= 0 && n <= 1000000000 ? (int)n : 0;
    d = content.contains("hashrate") && content["hashrate"].is_number() ? content["hashrate"].get<double>() : 0;
    ann.hashRate = (d >= 0 && d <= 1e30) ? d : 0;
    ann.createdAt = e.created_at;
    return true;
}

static void PrunePools(int64 nNow)
{
    for (map<string, BtfPoolAnnouncement>::iterator it = g_discoveredPools.begin(); it != g_discoveredPools.end(); )
    {
        if (nNow - it->second.createdAt > BTF_POOL_MAX_AGE)
            it = g_discoveredPools.erase(it);
        else
            ++it;
    }
}

int NostrIngestPool(const std::string& msg, const std::string& strSub, int64 nNow)
{
    json ev;
    int n = NostrSubMessage(msg, strSub, ev);
    if (n != NOSTR_MSG_EVENT)
        return n;
    BtfPoolAnnouncement ann;
    string err;
    if (!PoolFromEvent(ev, nNow, ann, err))
    {
        LogPrint("nostr", "Nostr: pool announcement refused: %s\n", err.c_str());
        return NOSTR_MSG_REFUSED;
    }
    CRITICAL_BLOCK(cs_discoveredPools)
    {
        PrunePools(nNow);
        map<string, BtfPoolAnnouncement>::iterator it = g_discoveredPools.find(ann.btfAddress);
        if (it != g_discoveredPools.end())
        {
            if (ann.createdAt >= it->second.createdAt)
                it->second = ann;
        }
        else
        {
            // Full: the oldest announcement goes, so that a flood of new keys
            // does not keep a live pool from being listed (each of them still
            // needs a signature of its own, and goes stale in minutes).
            if (g_discoveredPools.size() >= NOSTR_MAX_POOLS)
            {
                map<string, BtfPoolAnnouncement>::iterator oldest = g_discoveredPools.begin();
                for (map<string, BtfPoolAnnouncement>::iterator q = g_discoveredPools.begin(); q != g_discoveredPools.end(); ++q)
                    if (q->second.createdAt < oldest->second.createdAt)
                        oldest = q;
                g_discoveredPools.erase(oldest);
            }
            g_discoveredPools[ann.btfAddress] = ann;
        }
    }
    return NOSTR_MSG_TAKEN;
}

int NostrIngestDescriptor(void* secpctx, const std::string& msg, const std::string& strSub,
                          const std::map<std::string, std::string>& hexToAddr,
                          std::string& addrOut, std::string& descriptorOut, btf::Descriptor* pDescOut)
{
    json ev;
    int n = NostrSubMessage(msg, strSub, ev);
    if (n != NOSTR_MSG_EVENT)
        return n;
    // The descriptor in the content is signed by the address's own key
    // (btf::VerifyDescriptor), which is what makes it trustworthy whatever the
    // relay did to the event around it. The event is still read with care.
    string hexpk, content;
    if (!NostrStrField(ev, "pubkey", hexpk) || !NostrStrField(ev, "content", content))
        return NOSTR_MSG_REFUSED;
    std::map<std::string, std::string>::const_iterator ai = hexToAddr.find(hexpk);
    if (ai == hexToAddr.end())
        return NOSTR_MSG_REFUSED;
    unsigned char pk[32];
    if (!HexDecode(hexpk, pk, 32))
        return NOSTR_MSG_REFUSED;
    btf::Descriptor d;
    if (!btf::VerifyDescriptor(secpctx ? secpctx : (void*)NostrVerifyContext(), content, pk, d))
        return NOSTR_MSG_REFUSED;
    addrOut = ai->second;
    descriptorOut = content;
    if (pDescOut)
        *pDescOut = d;
    return NOSTR_MSG_TAKEN;
}

#ifdef BITFLASH_FUZZ
// Fuzzing only: forget what earlier inputs taught the node.
void NostrFuzzReset()
{
    CRITICAL_BLOCK(cs_btfPeers)
        g_btfPeers.clear();
    CRITICAL_BLOCK(cs_discoveredPools)
        g_discoveredPools.clear();
}
#endif

int NostrDescriptorKind() { return BTF_DESC_KIND; }
int NostrPoolKind() { return BTF_POOL_KIND; }
string NostrDescriptorTag() { return BtfNetTag(BTF_DESC_DTAG); }

size_t NostrDiscoveredPoolCount()
{
    size_t n = 0;
    CRITICAL_BLOCK(cs_discoveredPools)
        n = g_discoveredPools.size();
    return n;
}

// Resolve a `.btf` address via a relay: fetch the descriptor published by that
// address's key and verify it self-certifies under the decoded pubkey.
static bool ResolveDescriptor(CWebSocket& ws, void* ctx, const string& btfAddr,
                              btf::Descriptor& out, string* rawOut = NULL)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(btfAddr, pk))
        return false;
    json filter = json::object();
    filter["authors"] = json::array({ HexEncode(pk, 32) });
    filter["kinds"]   = json::array({ BTF_DESC_KIND });
    filter["#d"]      = json::array({ BtfNetTag(BTF_DESC_DTAG) });
    filter["limit"]   = 1;
    string strSub = NewSubId("btf-resolve");
    json req = json::array({ "REQ", strSub, filter });
    if (!ws.SendText(req.dump()))
        return false;
    // Stopping at the first good descriptor is right, but it used to return from
    // here with the subscription still open on a socket that gets reused. The
    // next question asked over it read this answer. Close it on the way out,
    // whichever way out that is.
    bool fFound = false;
    std::map<std::string, std::string> want;
    want[HexEncode(pk, 32)] = btfAddr;
    for (;;)
    {
        string msg;
        if (!ws.RecvText(msg))
            break;
        string addr, content;
        int n = NostrIngestDescriptor(ctx, msg, strSub, want, addr, content, &out);
        if (n == NOSTR_MSG_EOSE)
            break;
        if (n == NOSTR_MSG_TAKEN)
        {
            if (rawOut)
                *rawOut = content;
            fFound = true;
            break;
        }
    }
    CloseSub(ws, strSub);
    return fFound;
}

// Resolve a `.btf` address into its rendezvous coordinates by querying the
// public discovery relays for the owner's self-certified descriptor. Used by
// ConnectNodeBtf in net.cpp.
bool BtfResolve(const std::string& btfAddr, std::string& meetingHostPort,
                unsigned char enc_pub[32], std::string* onionHostPort)
{
    if (onionHostPort)
        onionHostPort->clear();
    if (!EnsureNostrKey())
        return false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            btf::Descriptor d;
            if (!ResolveDescriptor(lease.Ws(), g_nostrKey.ctx, btfAddr, d))
            {
                lease.fOk = true; // exchange completed, just no match
                continue;
            }
            lease.fOk = true;
            if (d.meeting_node.empty() || d.meeting_node == "rendezvous-pending")
            {
                if (!onionHostPort || d.onion.empty())
                    continue; // caller needs rendezvous, or descriptor has no direct path
            }
            if (!HexDecode(d.enc, enc_pub, 32))
                continue;
            meetingHostPort = d.meeting_node;
            if (onionHostPort)
                *onionHostPort = d.onion;
            return true;
        }
        CATCH_PRINT_EXCEPTION("BtfResolve")
    }
    return false;
}

// Resolve MANY .btf addresses in one pass. A single relay connection carries
// a REQ with every still-unresolved address's pubkey in "authors", instead of
// opening one relay connection per address. This matters because callers like
// ConnectDiscoveredBtfPeers dial many candidates in parallel; without
// batching, each of those dial threads independently walks the same handful
// of public relays on its own, so a pass of N candidates can fire up to
// N * nNostrRelays near-simultaneous connections at the same few relays --
// enough to get rate-limited or have handshakes refused, which then looks
// like "dead peers" even though the descriptors are perfectly resolvable.
bool BtfResolveMany(const std::vector<std::string>& btfAddrs,
                     std::map<std::string, BtfResolvedPeer>& out)
{
    if (!EnsureNostrKey() || btfAddrs.empty())
        return false;

    map<string, string> hexToAddr; // pubkey hex -> .btf addr, for matching events back
    set<string> pending;
    for (const string& a : btfAddrs)
    {
        unsigned char pk[32];
        if (!btf::ParseAddress(a, pk))
            continue;
        hexToAddr[HexEncode(pk, 32)] = a;
        pending.insert(a);
    }
    if (pending.empty())
        return false;

    for (int i = 0; i < nNostrRelays && !fShutdown && !pending.empty(); i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            CWebSocket& ws = lease.Ws();

            json authors = json::array();
            for (auto& kv : hexToAddr)
                if (pending.count(kv.second))
                    authors.push_back(kv.first);
            if (authors.empty())
            {
                lease.fOk = true;
                break;
            }

            json filter = json::object();
            filter["authors"] = authors;
            filter["kinds"]   = json::array({ BTF_DESC_KIND });
            filter["#d"]      = json::array({ BtfNetTag(BTF_DESC_DTAG) });
            filter["limit"]   = (int)authors.size();
            string strSub = NewSubId("btf-resolve-many");
            json req = json::array({ "REQ", strSub, filter });
            if (!ws.SendText(req.dump()))
                continue;

            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                std::map<std::string, std::string> want;
                for (auto& kv : hexToAddr)
                    if (pending.count(kv.second))
                        want.insert(kv);
                string addr, content;
                btf::Descriptor d;
                int n = NostrIngestDescriptor(g_nostrKey.ctx, msg, strSub, want, addr, content, &d);
                if (n == NOSTR_MSG_EOSE)
                    break;
                if (n != NOSTR_MSG_TAKEN)
                    continue;
                if ((d.meeting_node.empty() || d.meeting_node == "rendezvous-pending") &&
                    d.onion.empty())
                    continue;
                BtfResolvedPeer rp;
                if (!HexDecode(d.enc, rp.enc_pub, 32))
                    continue;
                rp.meetingHostPort = d.meeting_node;
                rp.onionHostPort = d.onion;
                rp.descriptor = content;
                out[addr] = rp;
                pending.erase(addr);
            }
            CloseSub(ws, strSub);
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfResolveMany")
    }
    return !out.empty();
}


// ---- per-relay backoff -----------------------------------------------------
//
// A relay that is down costs the whole discovery loop the full connect timeout,
// every round, forever. relay.nostr.band went down and produced 1092 identical
// error lines on the seed while adding ten seconds to every pass -- and the
// loop is what discovers peers, so a dead relay was slowing down the live ones.
//
// Back off per relay instead: 30s after the first failure, doubling to a
// fifteen-minute ceiling, cleared the moment it answers again. This changes
// only when an attempt happens, never whether discovery is correct.
struct CRelayBackoff
{
    int64 nNextTry;
    int   nFails;
    CRelayBackoff() : nNextTry(0), nFails(0) {}
};
static map<string, CRelayBackoff> mapRelayBackoff;
static CCriticalSection           cs_relayBackoff;

static const int64 RELAY_BACKOFF_BASE_SECS = 30;
static const int64 RELAY_BACKOFF_MAX_SECS  = 15 * 60;

static bool RelayDueForRetry(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        map<string, CRelayBackoff>::iterator it = mapRelayBackoff.find(relay);
        if (it == mapRelayBackoff.end())
            return true;
        return GetTime() >= it->second.nNextTry;
    }
    return true;
}

static void RelayNoteFailure(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        CRelayBackoff& b = mapRelayBackoff[relay];
        b.nFails++;
        int64 nWait = RELAY_BACKOFF_BASE_SECS;
        for (int i = 1; i < b.nFails && nWait < RELAY_BACKOFF_MAX_SECS; i++)
            nWait *= 2;
        if (nWait > RELAY_BACKOFF_MAX_SECS)
            nWait = RELAY_BACKOFF_MAX_SECS;
        b.nNextTry = GetTime() + nWait;
        // Only on the way in, so a relay that stays down says this once per
        // backoff step rather than once per pass.
        LogPrint("nostr", "Nostr: %s unreachable (%d in a row), not retrying for %ds\n",
                 relay.c_str(), b.nFails, (int)nWait);
    }
}

static void RelayNoteSuccess(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        map<string, CRelayBackoff>::iterator it = mapRelayBackoff.find(relay);
        if (it != mapRelayBackoff.end())
        {
            if (it->second.nFails > 0)
                LogPrint("nostr", "Nostr: %s answering again after %d failure(s)\n",
                         relay.c_str(), it->second.nFails);
            mapRelayBackoff.erase(it);
        }
    }
}

// Connect to a relay: publish our .btf descriptor and collect relay data.
static bool SeedFromRelay(CNostrKey& key, const string& relay)
{
    CRelayLease lease(relay, 10);
    if (!lease.Connected())
        return false;
    CWebSocket& ws = lease.Ws();
    if (lease.fJustConnected)
        LogPrint("nostr", "Nostr: connected to %s\n", relay.c_str());

    // Publish our self-certifying .btf descriptor (onion discovery)
    PublishDescriptor(ws, key);

    // Discover other nodes' .btf descriptors so we can auto-connect anonymously
    // (no manual /connectbtf). Each node publishes one addressable descriptor
    // (kind 38501, d-tag btf-descriptor); we learn every peer's .btf address by
    // deriving it from the event author. Reachability is verified later, when
    // the rendezvous tunnel boxes to that key's static x25519 key.
    ws.SendText(json::array({ "CLOSE", "bf-sub" }).dump());
    {
        json dfilter = json::object();
        dfilter["kinds"] = json::array({ BTF_DESC_KIND });
        dfilter["#d"]    = json::array({ BtfNetTag(BTF_DESC_DTAG) });
        dfilter["limit"] = 200;
        string strSub = NewSubId("btf-disc");
        json dreq = json::array({ "REQ", strSub, dfilter });
        int nPeers = 0;
        int nNewThisRound = 0;     // new addresses this relay may add (NOSTR_MAX_NEW_PEERS_PER_ROUND)
        if (ws.SendText(dreq.dump()))
        {
            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                int n = NostrIngestDiscovery(key.ctx, msg, strSub, key.xonly, GetTime(), nNewThisRound);
                if (n == NOSTR_MSG_EOSE)
                    break;
                if (n == NOSTR_MSG_OTHER)
                    continue;
                if (++nPeers > 500) break;
            }
        }
        // Onion-only: there are no rendezvous relays to discover. Just close the
        // descriptor subscription opened above -- and close it here, before the
        // next question goes out over this same socket, not after.
        CloseSub(ws, strSub);
    }

    // Discover live pool announcements. These are expiring status beacons, not
    // permanent directory entries, so the GUI can show only fresh pools.
    {
        json pfilter = json::object();
        pfilter["kinds"] = json::array({ BTF_POOL_KIND });
        pfilter["#d"]    = json::array({ BtfNetTag(BTF_POOL_DTAG) });
        pfilter["limit"]  = 200;
        string strSub = NewSubId("btf-pools");
        int nPools = 0;
        json preq = json::array({ "REQ", strSub, pfilter });
        if (ws.SendText(preq.dump()))
        {
            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                int nPool = NostrIngestPool(msg, strSub, GetTime());
                if (nPool == NOSTR_MSG_EOSE)
                    break;
                if (nPool != NOSTR_MSG_OTHER && ++nPools > 500)
                    break;
            }
            CloseSub(ws, strSub);
        }
    }
    lease.fOk = true;
    return true;
}

volatile bool gAnnounceNow = false;

void ThreadBtfPoolAnnouncer(void*)
{
    LogPrint("pool", "ThreadBtfPoolAnnouncer started\n");
    while (!fShutdown)
    {
        if (nMineMode == MINE_OPERATOR && gPoolRunning)
        {
            BtfPoolAnnouncement ann;
            ann.btfAddress = BtfLocalAddress();
            ann.poolName = NostrClampUtf8(strPoolName, NOSTR_MAX_POOL_NAME);
            ann.dashboardUrl = NostrClampUtf8(strPoolDashboardUrl, NOSTR_MAX_DASHBOARD_URL);
            ann.feePercent = dPoolFeePercent;
            uint64 roundShares = 0;
            double totalHashRate = 0.0;
            GetPoolOperatorStats(ann.connectedMiners, ann.blocksFound, roundShares, totalHashRate);
            ann.hashRate = totalHashRate;
            ann.createdAt = GetTime();
            if (!ann.btfAddress.empty() && !ann.poolName.empty())
                BtfPublishPoolAnnouncement(ann);
        }

        for (int i = 0; i < 60 && !fShutdown && !gAnnounceNow; i++)
            Sleep(1000);
        gAnnounceNow = false;
    }
}


// Per-peer backoff: don't redial a .btf that just failed until this time. Keeps
// dead/stale descriptors (e.g. abandoned test identities that linger on the
// relays) from consuming the whole per-pass dial budget and starving the live
// peers. Backoff grows on repeated failures, capped.
//
// g_btfPeerFails also doubles as the priority signal for dial ordering: a peer
// we've connected to before (present in g_btfPeerEverConnected) is known-good
// and goes first; a peer we've never tried goes next; a peer with a growing
// fail count is known-bad and goes last, worst offenders furthest back. This
// replaces the old behavior where the whole candidate list was shuffled right
// after being sorted by freshness, which made the freshness sort a no-op and
// gave dead peers equal footing with everyone else.
static map<string, int64> g_btfPeerBackoff;   // addr -> next-try time
static map<string, int>   g_btfPeerFails;      // addr -> consecutive failures
static set<string>        g_btfPeerEverConnected; // addr -> has succeeded at least once
static CCriticalSection   cs_btfPeerState;

// Backoff cap for repeatedly-dead peers. The old 15-minute cap meant a
// descriptor that has failed many times in a row cycles back into the dial
// pool just as often as a peer we've never tried, wasting dial budget on
// known-dead addresses every pass. Once a peer has failed enough times to
// be "chronic", stretch the cap much further so it consumes budget far less
// often while still getting retried eventually in case it comes back online.
static const int64 BTF_BACKOFF_CAP_SECS       = 15 * 60;      // 15 min: initial ramp cap
static const int64 BTF_BACKOFF_CAP_SECS_DEAD  = 6 * 60 * 60;  // 6 hr: cap for chronic failures
static const int   BTF_CHRONIC_FAIL_THRESHOLD = 6;            // fails before "chronic" cap kicks in

// Dial the .btf peers discovered on the relays, up to a target connection count.
// Connections are attempted in parallel so a single slow/dead relay doesn't
// stall the entire pass. Each candidate gets its own thread; all threads start
// at once and we wait for them to finish before returning.
static void ConnectDiscoveredBtfPeers()
{
    vector<pair<int64,string>> peersWithAge;
    int nTotal = 0;
    CRITICAL_BLOCK(cs_btfPeers)
    {
        nTotal = g_btfPeers.size();
        for (auto& kv : g_btfPeers)
            peersWithAge.push_back({kv.second, kv.first});
    }
    int64 cutoff = GetTime() - BTF_PEER_MAX_AGE;
    int nFresh = 0;
    vector<pair<int64,string>> fresh; // (createdAt, addr), newest first
    for (auto& p : peersWithAge)
    {
        if (p.first < cutoff)
            continue;
        fresh.push_back(p);
        nFresh++;
    }
    if (!fresh.empty())
        LogPrint("nostr", "Nostr: %d fresh peers, %d stale (of %d total)\n", nFresh, nTotal-nFresh, nTotal);

    // Drop stale peers so we stop retrying dead descriptors until they refresh.
    {
        CRITICAL_BLOCK(cs_btfPeers)
        {
            for (map<string, int64>::iterator it = g_btfPeers.begin(); it != g_btfPeers.end(); )
            {
                if (it->second < cutoff)
                    it = g_btfPeers.erase(it);
                else
                    ++it;
            }
        }
    }
    // And what we remember about dialling them: an address no longer in the
    // table has nothing to back off from. These maps used to grow with every
    // address any relay ever named.
    {
        set<string> live;
        CRITICAL_BLOCK(cs_btfPeers)
            for (auto& kv : g_btfPeers)
                live.insert(kv.first);
        CRITICAL_BLOCK(cs_btfPeerState)
        {
            for (map<string, int64>::iterator it = g_btfPeerBackoff.begin(); it != g_btfPeerBackoff.end(); )
                if (!live.count(it->first)) it = g_btfPeerBackoff.erase(it); else ++it;
            for (map<string, int>::iterator it = g_btfPeerFails.begin(); it != g_btfPeerFails.end(); )
                if (!live.count(it->first)) it = g_btfPeerFails.erase(it); else ++it;
            for (set<string>::iterator it = g_btfPeerEverConnected.begin(); it != g_btfPeerEverConnected.end(); )
                if (!live.count(*it)) it = g_btfPeerEverConnected.erase(it); else ++it;
        }
    }

    // Sort newest descriptor first -- recently-active nodes are much more
    // likely to be online right now.
    sort(fresh.begin(), fresh.end(),
         [](const pair<int64,string>& a, const pair<int64,string>& b){ return a.first > b.first; });

    // Reorder into tiers: known-good (succeeded before) first, untried next,
    // known-bad (has a fail count) last -- worst offenders furthest back.
    // Freshness order is preserved *within* each tier, so recency still
    // matters, but a peer we know is dead no longer gets equal footing with
    // a peer we've never tried or one that's worked before.
    vector<string> tierGood, tierUntried, tierBad;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        for (auto& p : fresh)
        {
            const string& addr = p.second;
            if (g_btfPeerEverConnected.count(addr))
                tierGood.push_back(addr);
            else if (g_btfPeerFails.find(addr) == g_btfPeerFails.end())
                tierUntried.push_back(addr);
            else
                tierBad.push_back(addr);
        }
        // Within known-bad, put fewer-fails peers ahead of chronic offenders.
        sort(tierBad.begin(), tierBad.end(),
             [](const string& a, const string& b){ return g_btfPeerFails[a] < g_btfPeerFails[b]; });
    }

    vector<string> peers;
    peers.reserve(fresh.size());
    peers.insert(peers.end(), tierGood.begin(), tierGood.end());
    peers.insert(peers.end(), tierUntried.begin(), tierUntried.end());
    peers.insert(peers.end(), tierBad.begin(), tierBad.end());

    // Pick candidates for this pass (skip those in backoff, cap at budget).
    //
    // The tiered order above is deliberately biased toward peers we know
    // are good -- that's the right default, since dialing untested/bad
    // peers wastes attempts. But if every node on the network applies the
    // same bias, everyone converges on the same small set of "known good"
    // peers as neighbors: that correlates peer sets across the network,
    // which is exactly what standard random-graph connectivity results
    // assume you avoid. If that shared hub set has a bad day (e.g. one
    // relay outage), many nodes lose the same edges at once instead of
    // losing independent, uncorrelated edges.
    //
    // So: fill most of the pass from the reliable/tiered order, but reserve
    // a slice for peers picked at random from the *entire* fresh pool
    // (not just the front of the sorted list). Same pattern Bitcoin's own
    // peer manager and Kademlia-style DHTs use -- sticky reliable peers
    // plus a random sample, not one or the other.
    int64 now = GetTime();
    int nBudget = (int)BTF_DIALS_PER_PASS;
    int nNodeCount = BtfConnectedNodeCount();
    {
        int nRoom = (int)BTF_TARGET_CONN - nNodeCount;
        if (nRoom < nBudget) nBudget = nRoom;
    }
    if (nBudget < 0) nBudget = 0;
    int nRandomSlots = (nBudget > 0) ? max(1, nBudget * 3 / 10) : 0;
    int nSortedSlots = nBudget - nRandomSlots;

    vector<string> candidates;
    set<string> setChosen;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        // Reliability slice: walk the tiered (good -> untried -> bad) order.
        for (const string& addr : peers)
        {
            if ((int)candidates.size() >= nSortedSlots) break;
            map<string, int64>::iterator bi = g_btfPeerBackoff.find(addr);
            if (bi != g_btfPeerBackoff.end() && now < bi->second)
                continue;
            candidates.push_back(addr);
            setChosen.insert(addr);
        }

        // Diversity slice: random sample from the full fresh pool, so the
        // dial isn't limited to whatever the tiered sort put up front.
        vector<string> pool;
        for (auto& p : fresh)
        {
            const string& addr = p.second;
            if (setChosen.count(addr))
                continue;
            map<string, int64>::iterator bi = g_btfPeerBackoff.find(addr);
            if (bi != g_btfPeerBackoff.end() && now < bi->second)
                continue;
            pool.push_back(addr);
        }
        int nWant = min(nRandomSlots, (int)pool.size());
        for (int i = 0; i < nWant; i++)
        {
            if (nNodeCount + (int)candidates.size() >= (int)BTF_TARGET_CONN) break;
            if ((int)candidates.size() >= nBudget) break;
            size_t j = i + (size_t)GetRand((uint64)(pool.size() - i));
            std::swap(pool[i], pool[j]);
            candidates.push_back(pool[i]);
            setChosen.insert(pool[i]);
        }
    }

    if (candidates.empty()) return;

    // Resolve every candidate's descriptor in one batched pass (a handful of
    // relay round-trips total, one REQ per relay covering all candidates)
    // instead of each dial thread independently walking the relay list on
    // its own. That per-thread approach meant a 12-candidate pass could fire
    // up to 12 * nNostrRelays near-simultaneous connections at the same
    // handful of public relays -- enough to trip rate limits or get
    // handshakes refused, which then looks exactly like "dead peers" even
    // though the descriptors were perfectly resolvable.
    map<string, BtfResolvedPeer> resolved;
    for (const string& addr : candidates)
        BtfChurnNoteResolveAttempt();
    BtfResolveMany(candidates, resolved);

    // Candidates whose descriptor didn't resolve this pass are recorded as a
    // failure right away (no point spawning a tunnel thread with nothing to
    // dial), same bookkeeping as a failed connect attempt.
    vector<string> toDial;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        for (const string& addr : candidates)
        {
            if (resolved.count(addr))
            {
                BtfChurnNoteResolveResult(true);
                toDial.push_back(addr);
                continue;
            }
            BtfChurnNoteResolveResult(false);
            int n = ++g_btfPeerFails[addr];
            int64 cap = (n >= BTF_CHRONIC_FAIL_THRESHOLD) ? BTF_BACKOFF_CAP_SECS_DEAD
                                                           : BTF_BACKOFF_CAP_SECS;
            int64 secs = 30;
            for (int k = 1; k < n && secs < cap; k++) secs *= 2;
            if (secs > cap) secs = cap;
            g_btfPeerBackoff[addr] = GetTime() + secs;
        }
    }
    if (toDial.empty()) return;

    // Launch one thread per resolved candidate -- all connect attempts run in
    // parallel, but purely against each peer's own rendezvous meeting node,
    // not the shared Nostr relays, so there's no thundering-herd effect here.
    // Each thread writes its result back via shared state guarded by cs_btfPeerState.
    struct DialCtx { string addr; BtfResolvedPeer rp; };
    for (const string& addr : toDial)
    {
        DialCtx* ctx = new DialCtx{addr, resolved[addr]};
        uintptr_t tid = _beginthread([](void* arg) {
            DialCtx* ctx = (DialCtx*)arg;
            string addr = ctx->addr;
            string meeting = ctx->rp.meetingHostPort;
            string onion = ctx->rp.onionHostPort;
            string desc = ctx->rp.descriptor;
            unsigned char enc_pub[32];
            memcpy(enc_pub, ctx->rp.enc_pub, 32);
            delete ctx;

            CNode* pnode = ConnectNodeBtfResolved(addr, meeting, onion, enc_pub, desc);
            CRITICAL_BLOCK(cs_btfPeerState)
            {
                if (pnode)
                {
                    if (!pnode->fNetworkNode)
                        pnode->fNetworkNode = true;
                    else
                        pnode->Release();
                    g_btfPeerBackoff.erase(addr);
                    g_btfPeerFails.erase(addr);
                    g_btfPeerEverConnected.insert(addr);
                }
                else
                {
                    int n = ++g_btfPeerFails[addr];
                    int64 cap = (n >= BTF_CHRONIC_FAIL_THRESHOLD) ? BTF_BACKOFF_CAP_SECS_DEAD
                                                                   : BTF_BACKOFF_CAP_SECS;
                    int64 secs = 30;
                    for (int k = 1; k < n && secs < cap; k++) secs *= 2;
                    if (secs > cap) secs = cap;
                    g_btfPeerBackoff[addr] = GetTime() + secs;
                }
            }
        }, 0, ctx);
        if (tid == (uintptr_t)-1)
        {
            LogPrint("nostr", "Nostr: failed to create .btf dial thread for %s\n", addr.c_str());
            CRITICAL_BLOCK(cs_btfPeerState)
            {
                int n = ++g_btfPeerFails[addr];
                int64 cap = (n >= BTF_CHRONIC_FAIL_THRESHOLD) ? BTF_BACKOFF_CAP_SECS_DEAD
                                                               : BTF_BACKOFF_CAP_SECS;
                int64 secs = 30;
                for (int k = 1; k < n && secs < cap; k++) secs *= 2;
                if (secs > cap) secs = cap;
                g_btfPeerBackoff[addr] = GetTime() + secs;
            }
            delete ctx;
        }
    }

    // Wait long enough for all parallel dials to finish (each has a 10s socket
    // timeout, so 12s gives them all time to resolve).
    for (int i = 0; i < 12 && !fShutdown; i++)
        Sleep(1000);
}


void ThreadNostrSeed(void* parg)
{
    LogPrint("nostr", "ThreadNostrSeed started\n");

    if (!EnsureNostrKey())
    {
        LogPrint("nostr", "Nostr: failed to initialize secp256k1 key\n");
        return;
    }
    CNostrKey& key = g_nostrKey;
    LogPrint("nostr", "Nostr: node pubkey = %s\n", key.PubKeyHex().c_str());
    LogPrint("nostr", "Nostr: node .btf address = %s\n", key.BtfAddress().c_str());

    // The self-test below publishes a real descriptor. Onion-only: a node can
    // publish as soon as its signed Tor hidden-service endpoint exists.
    for (int i = 0; i < 60 && !fShutdown &&
                    BtfLocalOnionEndpoint().empty(); i++)
        Sleep(1000);

    // One-time self-test of the rendezvous: publish our descriptor to a relay,
    // then resolve our OWN .btf address back and verify it self-certifies. Proves
    // the .btf publish/resolve/verify chain works against real public relays.
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected()) continue;
            CWebSocket& ws = lease.Ws();
            PublishDescriptor(ws, key);
            Sleep(700); // let the relay store the replaceable event
            btf::Descriptor d;
            if (ResolveDescriptor(ws, key.ctx, key.BtfAddress(), d))
            {
                LogPrint("nostr", "Nostr: .btf self-resolve OK via %s (meeting_node=%s, enc=%s...)\n",
                       pszNostrRelays[i], d.meeting_node.c_str(), d.enc.substr(0, 16).c_str());
                lease.fOk = true;
                break;
            }
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("btf self-test")
    }

    // OpenSSL is already initialized by the rest of the app; TLS_client_method is enough.
    loop
    {
        for (int i = 0; i < nNostrRelays; i++)
        {
            if (fShutdown) return;
            if (!RelayDueForRetry(pszNostrRelays[i]))
                continue;
            try
            {
                if (SeedFromRelay(key, pszNostrRelays[i]))
                    RelayNoteSuccess(pszNostrRelays[i]);
                else
                    RelayNoteFailure(pszNostrRelays[i]);
            }
            CATCH_PRINT_EXCEPTION("SeedFromRelay")
        }

        // Auto-connect to discovered .btf peers over the rendezvous relay -- the
        // anonymous, CGNAT-friendly replacement for the old IP-based connect. No
        // manual /connectbtf needed: nodes find each other purely via Nostr.
        try
        {
            ConnectDiscoveredBtfPeers();
        }
        CATCH_PRINT_EXCEPTION("ConnectDiscoveredBtfPeers")

        if (nMineMode == MINE_OPERATOR && gPoolRunning)
        {
            BtfPoolAnnouncement ann;
            ann.btfAddress = BtfLocalAddress();
            ann.poolName = NostrClampUtf8(strPoolName, NOSTR_MAX_POOL_NAME);
            ann.dashboardUrl = NostrClampUtf8(strPoolDashboardUrl, NOSTR_MAX_DASHBOARD_URL);
            ann.feePercent = dPoolFeePercent;
            uint64 roundShares = 0;
            double totalHashRate = 0.0;
            GetPoolOperatorStats(ann.connectedMiners, ann.blocksFound, roundShares, totalHashRate);
            ann.hashRate = totalHashRate;
            ann.createdAt = GetTime();
            if (!ann.btfAddress.empty() && !ann.poolName.empty())
                BtfPublishPoolAnnouncement(ann);
        }

        // Re-discover periodically. Sleep less aggressively when
        // we have no connections yet so we find peers faster on startup.
        int nSleepSecs = (BtfConnectedNodeCount() == 0) ? 20 : 60;
        for (int i = 0; i < nSleepSecs && !fShutdown; i++)
            Sleep(1000);
    }
}
