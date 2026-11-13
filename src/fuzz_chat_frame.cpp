// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for what reaches a chat identity from strangers: signed frames
// (OpenFrame and the whole inbound path, Inbox::Deliver, with the consent gate
// and the replay guard), sealed mailbox envelopes (Mailbox::Open, whose key
// agreement is X25519 plus ML-KEM-1024), the encrypted link (the endpoint
// handshake and Link::RecvFrame, and the frame cipher), and signed epoch-key
// announcements (VerifyEpochKeys). Plus a differential of the vendored
// ML-KEM-1024 (mlkem-native) against an independent implementation.
//
// Input: byte 0 picks the mode, the rest is the mode's body.
//   0  frame JSON as received, delivered to a fixed identity (Alice) whose
//      roster accepts Bob, has invited Erin, blocks Dave and runs a group
//   1  a frame built from fields and signed by one of five identities (Bob,
//      Carol who is unknown, Dave who is blocked, Erin who was invited,
//      Alice herself), then delivered
//   2  a valid envelope sealed to Alice's epoch key, with the input's
//      mutations applied (position, xor) and a cut or an extension
//   3  raw bytes as an envelope, and a frame sealed from the input
//   4  ML-KEM-1024: decapsulation of input ciphertexts, key generation from
//      an input seed, encapsulation to an input public key
//   5  the link: the endpoint side of a handshake fed the input, then frames;
//      and frames sealed by a real client session, mutated or not
//   6  an epoch-keys announcement as received, and one signed from fields
//   7  the mailbox key store and the roster from JSON, and back
//
// What is checked, beyond the sanitizers:
//   - a frame delivered once is refused the second time (replay), whatever
//     path took it; a delivered frame's sender was in the state its kind
//     requires; its time is inside the window ReplayGuard allows;
//   - a changed envelope never opens, an unchanged one opens to the frame it
//     carried; what SealEnvelope makes, Open opens;
//   - ML-KEM: what encapsulation gives, decapsulation recovers; a ciphertext
//     that is not the one made decapsulates to SHAKE256(z || c) (implicit
//     rejection, FIPS 203); and with OpenSSL 3.5 or later, key generation,
//     encapsulation (public key check included) and decapsulation agree byte
//     for byte with OpenSSL's ML-KEM-1024;
//   - a frame body changed on the wire never decrypts; one unchanged decrypts
//     to what was sent;
//   - an announcement signed by its own address fails, if at all, only for
//     its epoch;
//   - JSON stores read back to what they wrote.

#include "btfchat.h"
#include "btfchan.h"
#include "btfchatbox.h"
#include "btfchatlink.h"
#include "btfchatlog.h"
#include "btfchatmsg.h"
#include "btfaddr.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#define FUZZ_HAVE_OPENSSL_MLKEM 1
#endif

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem/mlkem_native.h"
#define BTF_MLK_CAT_(a, b) a##b
#define BTF_MLK_CAT(a, b) BTF_MLK_CAT_(a, b)
#define BTF_MLK(sym) BTF_MLK_CAT(BTF_MLK_CAT(MLK_CONFIG_NAMESPACE_PREFIX, _), sym)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include <map>
// util.h redefines snprintf as a macro, which breaks nlohmann/json (see nostr.cpp).
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

// The node objects are linked (the chat modules live among them), so the
// stand-ins the GUI or headless entry objects normally supply are needed, and
// the private temporary data directory of every harness. None of the node
// runs here.
extern std::string strSetDataDir;
std::map<std::string, std::string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}
static void Init();
#define BITFLASH_FUZZ_INIT_EXTRA Init
#include "fuzz_datadir.h"

using namespace btfchat;

static secp256k1_context* g_ctx = NULL;
enum { ALICE, BOB, CAROL, DAVE, ERIN, NUM_IDS };
static Identity g_id[NUM_IDS];
static Roster g_roster;               // Alice's, before any input
static std::string g_groupId;
static Mailbox g_mailbox;             // Alice's epoch keys
static EpochKeys g_epoch;             // the public halves of the current one
static std::string g_frameInEnvelope; // a frame from Bob
static std::vector<unsigned char> g_envelope;

static const unsigned char KEM_SEED[64] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
    33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64 };
static unsigned char g_kemPk[btf::CHAN_KEM_PUBBYTES];
static unsigned char g_kemSk[btf::CHAN_KEM_SECBYTES];

static int64_t Now()
{
    // A fixed clock: an input means the same thing whenever it runs.
    return 1790000000;
}

static void MakeIdentity(int i, Identity& id)
{
    memset(&id, 0, sizeof(id));
    for (int k = 0; k < 32; k++)
        id.sign_sk[k] = (unsigned char)(0x21 * (i + 1) + 3 * k + 1);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_ctx, &kp, id.sign_sk))
        abort();
    secp256k1_xonly_pubkey xpub;
    secp256k1_keypair_xonly_pub(g_ctx, &xpub, NULL, &kp);
    secp256k1_xonly_pubkey_serialize(g_ctx, id.sign_pk, &xpub);
    for (int k = 0; k < 32; k++)
        id.chan_sk[k] = (unsigned char)(0x77 ^ (i * 11 + k));
    btf::ChanPublicFromSecret(id.chan_pk, id.chan_sk);
    id.address = btf::Address(id.sign_pk);
}

struct Reader
{
    const uint8_t* p;
    size_t n;
    Reader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    uint8_t U8() { if (!n) return 0; n--; return *p++; }
    uint16_t U16() { uint16_t a = U8(); return (uint16_t)(a | (U8() << 8)); }
    int64_t S16() { return (int16_t)U16(); }
    std::string Str(size_t k) { if (k > n) k = n; std::string s((const char*)p, k); p += k; n -= k; return s; }
    std::vector<unsigned char> Bytes(size_t k) { std::string s = Str(k); return std::vector<unsigned char>(s.begin(), s.end()); }
};

static std::string Hex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}

// ---- delivery ---------------------------------------------------------------

struct InboxState
{
    Roster roster;
    ReplayGuard replay;
    History history;
};

// Deliver as Alice; check what a delivery promises, and that it never
// happens twice.
static void DeliverChecked(InboxState& st, const std::string& js, const std::string& peer)
{
    Inbox in;
    in.secpctx = g_ctx;
    in.myAddress = g_id[ALICE].address;
    in.roster = &st.roster;
    in.replay = &st.replay;
    in.history = &st.history;

    Frame f;
    std::string err;
    // The state of every possible sender before, to judge the gate after.
    Frame peek;
    std::string e0;
    PeerState stBefore = PEER_UNKNOWN;
    bool fParsed = OpenFrame(g_ctx, js, peek, e0);
    if (fParsed)
        stBefore = st.roster.State(peek.from);
    bool fGroupMember = false;
    if (fParsed && peek.kind == MSG_GROUP_TEXT)
    {
        std::string e1;
        fGroupMember = st.roster.MayDeliverGroup(peek.group, peek.from, e1);
    }

    bool fOk = in.Deliver(js, peer, Now(), f, err);
    if (!fOk)
        return;
    if (!fParsed)
        abort();   // delivered something OpenFrame refuses
    if (f.sent > Now() + FRAME_FUTURE_SKEW || Now() - f.sent > FRAME_MAX_AGE)
        abort();   // outside the replay window
    if (stBefore == PEER_BLOCKED)
        abort();   // nothing from a blocked address, ever
    switch (f.kind)
    {
    case MSG_TEXT: case MSG_PAY_ADDRESS: case MSG_PAYMENT: case MSG_SWAP:
        if (stBefore != PEER_ACCEPTED && stBefore != PEER_INVITE_OUT)
            abort();   // a message from someone with no conversation
        break;
    case MSG_INVITE_ACCEPT:
        if (stBefore != PEER_INVITE_OUT)
            abort();
        break;
    case MSG_GROUP_TEXT:
        if (!fGroupMember)
            abort();
        break;
    case MSG_SWAP_OFFER:
        abort();       // offers never arrive this way
    default:
        break;
    }
    if (!peer.empty() && f.kind != MSG_GROUP_TEXT && f.kind != MSG_GROUP_INVITE && f.from != peer)
        abort();       // forwarded one-to-one frame

    // The same frame again, on this link or another: refused.
    Frame f2;
    std::string err2;
    if (in.Deliver(js, peer, Now(), f2, err2))
        abort();
    if (in.Deliver(js, std::string(), Now() + 60, f2, err2))
        abort();
}

static InboxState FreshInbox()
{
    InboxState st;
    st.roster = g_roster;
    return st;
}

static void ModeFrameJson(Reader& rd)
{
    InboxState st = FreshInbox();
    uint8_t sel = rd.U8();
    std::string peer = (sel & 1) ? g_id[sel % NUM_IDS].address : std::string();
    std::string js = rd.Str(rd.n);
    DeliverChecked(st, js, peer);
    // OpenFrame on its own, and if it takes the frame, the frame re-signed by
    // its author (when we hold the key) opens to the same fields.
    Frame f;
    std::string err;
    if (OpenFrame(g_ctx, js, f, err))
    {
        for (int i = 0; i < NUM_IDS; i++)
            if (f.from == g_id[i].address)
            {
                Frame g = f;
                std::string js2, e2;
                Frame back;
                if (!SignFrame(g_ctx, g_id[i], g, js2, e2))
                {
                    // Re-encoded, a frame can come out longer than the one
                    // received (escapes written differently); that is the only
                    // reason a frame that verified may not be signed again.
                    if (e2.find("wire limit") == std::string::npos)
                        abort();
                    continue;
                }
                if (!OpenFrame(g_ctx, js2, back, e2))
                    abort();   // what SignFrame makes, OpenFrame takes
                if (back.kind != f.kind || back.text != f.text || back.group != f.group ||
                    back.sent != f.sent || back.id != f.id || back.amount != f.amount ||
                    back.payTo != f.payTo || back.txid != f.txid || back.proof != f.proof)
                    abort();
            }
    }
}

// Bytes as the text JSON can carry: what is not UTF-8 becomes U+FFFD. A peer's
// frame arrives through json::parse, which refuses such text, and what a person
// types is text; only this harness builds frames from raw bytes, and
// SignFrame's dump() throws on them.
static std::string Clean(const std::string& b)
{
    return nlohmann::json::parse(nlohmann::json(b).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)).get<std::string>();
}

static bool BuildSigned(Reader& rd, int& signer, std::string& js)
{
    signer = rd.U8() % NUM_IDS;
    Frame f;
    uint8_t b = rd.U8();
    f.kind = (MsgKind)(rd.U8() % (MSG_SWAP + 1));
    f.sent = Now() + rd.S16() * ((b & 1) ? 60 : 1);
    if (b & 2)
        f.id = Clean(rd.Str(rd.U8() % 40));
    else
    {
        std::vector<unsigned char> idb = rd.Bytes(16);
        idb.resize(16, 0xa5);
        f.id = Hex(&idb[0], 16);
    }
    f.text = Clean(rd.Str(rd.U16() % (MAX_TEXT_BYTES + 64)));
    if (b & 4)
        f.group = (b & 8) ? g_groupId : Clean(rd.Str(rd.U8() % 80));
    if (f.kind == MSG_GROUP_INVITE && (b & 16))
    {
        std::string e;
        SignGroupInvite(g_ctx, g_id[signer], f.group.empty() ? g_groupId : f.group,
                        f.text.empty() ? "g" : f.text.substr(0, MAX_GROUP_NAME),
                        g_id[ALICE].address, f.proof, e);
        if (f.group.empty()) f.group = g_groupId;
        if (f.text.empty()) f.text = "g";
    }
    if (f.kind == MSG_PAY_ADDRESS || f.kind == MSG_PAYMENT || (b & 32))
    {
        f.payTo = (b & 64) ? Clean(rd.Str(rd.U8() % 40)) : "B6yBpt1nTq3VuV1mNQXrWpYAuB4VJkH9mV";
        f.amount = (int64_t)rd.U16() * ((b & 128) ? 100000000LL : 1);
        if (f.kind == MSG_PAYMENT)
        {
            std::vector<unsigned char> tb = rd.Bytes(32);
            tb.resize(32, 0x3c);
            f.txid = Hex(&tb[0], 32);
        }
    }
    std::string err;
    return SignFrame(g_ctx, g_id[signer], f, js, err);
}

static void ModeFrameSigned(Reader& rd)
{
    InboxState st = FreshInbox();
    int signer = 0;
    std::string js;
    std::vector<unsigned char> bodyBuf;
    if (!BuildSigned(rd, signer, js))
        return;
    uint8_t sel = rd.U8();
    std::string peer = (sel & 1) ? g_id[signer].address : (sel & 2) ? g_id[sel % NUM_IDS].address : std::string();
    DeliverChecked(st, js, peer);
    // A second, different frame after the first, in the same state.
    if (BuildSigned(rd, signer, js))
        DeliverChecked(st, js, std::string());
}

// ---- envelopes --------------------------------------------------------------

static void ModeEnvelopeMutate(Reader& rd)
{
    std::vector<unsigned char> e = g_envelope;
    int nMut = rd.U8() % 8;
    for (int i = 0; i < nMut; i++)
    {
        size_t pos = rd.U16() % e.size();
        e[pos] ^= rd.U8();
    }
    uint8_t cut = rd.U8();
    if (cut & 0x80)
        e.resize(e.size() - (cut & 0x7f) % e.size());
    else if (cut & 0x40)
        e.insert(e.end(), (size_t)(cut & 0x3f), (unsigned char)cut);
    std::vector<unsigned char> out;
    std::string err;
    bool fOpen = g_mailbox.Open(e.empty() ? NULL : &e[0], e.size(), out, err);
    if (e == g_envelope)
    {
        if (!fOpen || std::string(out.begin(), out.end()) != g_frameInEnvelope)
            abort();
    }
    else if (fOpen)
        abort();       // a changed envelope opened
}

static void ModeEnvelopeRaw(Reader& rd)
{
    std::vector<unsigned char> raw = rd.Bytes(rd.n);
    std::vector<unsigned char> out;
    std::string err;
    g_mailbox.Open(raw.empty() ? NULL : &raw[0], raw.size(), out, err);
    // Sealed to Alice from the same bytes, it opens to them.
    std::string frame(raw.begin(), raw.end());
    std::vector<unsigned char> env;
    if (SealEnvelope(g_epoch.x_pk, g_epoch.kem_pk, frame, env, err))
    {
        if (!g_mailbox.Open(&env[0], env.size(), out, err) || std::string(out.begin(), out.end()) != frame)
            abort();
    }
}

// ---- ML-KEM -----------------------------------------------------------------

static void Shake256(const unsigned char* in, size_t n, unsigned char out[32])
{
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    if (!c || EVP_DigestInit_ex(c, EVP_shake256(), NULL) != 1 ||
        EVP_DigestUpdate(c, in, n) != 1 || EVP_DigestFinalXOF(c, out, 32) != 1)
        abort();
    EVP_MD_CTX_free(c);
}

// K-bar = J(z || c): what decapsulation must answer for a ciphertext that does
// not re-encrypt to itself. z is the last 32 bytes of the decapsulation key.
static void ImplicitReject(const unsigned char sk[btf::CHAN_KEM_SECBYTES],
                           const unsigned char ct[btf::CHAN_KEM_CTBYTES], unsigned char out[32])
{
    std::vector<unsigned char> buf(32 + btf::CHAN_KEM_CTBYTES);
    memcpy(&buf[0], sk + btf::CHAN_KEM_SECBYTES - 32, 32);
    memcpy(&buf[32], ct, btf::CHAN_KEM_CTBYTES);
    Shake256(&buf[0], buf.size(), out);
}

#ifdef FUZZ_HAVE_OPENSSL_MLKEM
static EVP_PKEY* OsslKey(const char* param, const unsigned char* p, size_t n)
{
    EVP_PKEY_CTX* pc = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    EVP_PKEY* key = NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(param, (void*)p, n);
    params[1] = OSSL_PARAM_construct_end();
    if (!pc || EVP_PKEY_fromdata_init(pc) != 1 ||
        EVP_PKEY_fromdata(pc, &key, strcmp(param, OSSL_PKEY_PARAM_PUB_KEY) == 0 ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params) != 1)
        key = NULL;
    EVP_PKEY_CTX_free(pc);
    return key;
}

// Encapsulation with caller-chosen coins ("ikme"), when this OpenSSL honours
// it: probed at start by encapsulating twice with the same coins.
static bool g_fOsslIkme = false;

static bool OsslEncap(EVP_PKEY* key, const unsigned char m[32], unsigned char* ct, unsigned char ss[32])
{
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void*)m, 32);
    params[1] = OSSL_PARAM_construct_end();
    size_t nct = btf::CHAN_KEM_CTBYTES, nss = 32;
    bool fOk = c && EVP_PKEY_encapsulate_init(c, params) == 1 &&
               EVP_PKEY_encapsulate(c, ct, &nct, ss, &nss) == 1 &&
               nct == (size_t)btf::CHAN_KEM_CTBYTES && nss == 32;
    EVP_PKEY_CTX_free(c);
    return fOk;
}

static bool OsslDecap(const unsigned char* ct, unsigned char ss[32])
{
    static EVP_PKEY* key = NULL;
    if (!key && !(key = OsslKey(OSSL_PKEY_PARAM_PRIV_KEY, g_kemSk, sizeof(g_kemSk))))
        abort();   // OpenSSL refuses a key mlkem-native made
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    size_t n = 32;
    bool fOk = c && EVP_PKEY_decapsulate_init(c, NULL) == 1 &&
               EVP_PKEY_decapsulate(c, ss, &n, ct, btf::CHAN_KEM_CTBYTES) == 1 && n == 32;
    EVP_PKEY_CTX_free(c);
    return fOk;
}
#endif

static void ModeMlKem(Reader& rd)
{
    uint8_t what = rd.U8();
    if (what % 3 == 0)
    {
        // A real encapsulation from input coins, then the input's changes.
        std::vector<unsigned char> m = rd.Bytes(32);
        m.resize(32, 0);
        unsigned char ct[btf::CHAN_KEM_CTBYTES], ss[32], ss2[32];
        if (BTF_MLK(enc_derand)(ct, ss, g_kemPk, &m[0]) != 0)
            abort();
        if (BTF_MLK(dec)(ss2, ct, g_kemSk) != 0 || memcmp(ss, ss2, 32) != 0)
            abort();   // decapsulation did not recover the secret
#ifdef FUZZ_HAVE_OPENSSL_MLKEM
        unsigned char ss3[32];
        if (!OsslDecap(ct, ss3) || memcmp(ss, ss3, 32) != 0)
            abort();
#endif
        unsigned char orig[btf::CHAN_KEM_CTBYTES];
        memcpy(orig, ct, sizeof(ct));
        int nMut = rd.U8() % 6;
        for (int i = 0; i < nMut; i++)
            ct[rd.U16() % sizeof(ct)] ^= rd.U8();
        if (BTF_MLK(dec)(ss2, ct, g_kemSk) != 0)
            abort();
        unsigned char rej[32];
        ImplicitReject(g_kemSk, ct, rej);
        if (memcmp(ct, orig, sizeof(ct)) == 0)
        {
            if (memcmp(ss2, ss, 32) != 0)
                abort();
        }
        else if (memcmp(ss2, rej, 32) != 0)
            abort();   // a changed ciphertext did not get the implicit rejection value
#ifdef FUZZ_HAVE_OPENSSL_MLKEM
        if (!OsslDecap(ct, ss3) || memcmp(ss2, ss3, 32) != 0)
            abort();
#endif
    }
    else if (what % 3 == 1)
    {
        // Key generation from an input seed (d || z).
        std::vector<unsigned char> seed = rd.Bytes(64);
        seed.resize(64, 0x33);
        unsigned char pk[btf::CHAN_KEM_PUBBYTES], sk[btf::CHAN_KEM_SECBYTES];
        if (BTF_MLK(keypair_derand)(pk, sk, &seed[0]) != 0)
            abort();
        // The decapsulation key carries the encapsulation key and z = seed[32..64].
        if (memcmp(sk + btf::CHAN_KEM_SECBYTES - 32, &seed[32], 32) != 0)
            abort();
#ifdef FUZZ_HAVE_OPENSSL_MLKEM
        EVP_PKEY* key = OsslKey(OSSL_PKEY_PARAM_ML_KEM_SEED, &seed[0], 64);
        if (!key)
            abort();
        unsigned char opk[btf::CHAN_KEM_PUBBYTES], osk[btf::CHAN_KEM_SECBYTES];
        size_t npk = sizeof(opk), nsk = sizeof(osk);
        if (EVP_PKEY_get_raw_public_key(key, opk, &npk) != 1 || npk != sizeof(opk) ||
            EVP_PKEY_get_raw_private_key(key, osk, &nsk) != 1 || nsk != sizeof(osk))
            abort();
        if (memcmp(opk, pk, sizeof(pk)) != 0 || memcmp(osk, sk, sizeof(sk)) != 0)
            abort();   // the two implementations derive different keys
        EVP_PKEY_free(key);
#endif
    }
    else
    {
        // Encapsulation to an input public key: the public key check, and the
        // ciphertext and secret for the same coins.
        std::vector<unsigned char> pk = rd.Bytes(btf::CHAN_KEM_PUBBYTES);
        if (pk.size() < (size_t)btf::CHAN_KEM_PUBBYTES)
        {
            // Short input: start from the real key and change a few bytes, so
            // valid and invalid keys both come up.
            std::vector<unsigned char> base(g_kemPk, g_kemPk + btf::CHAN_KEM_PUBBYTES);
            for (size_t i = 0; i + 2 < pk.size(); i += 3)
                base[((size_t)pk[i] | ((size_t)pk[i + 1] << 8)) % base.size()] ^= pk[i + 2];
            pk = base;
        }
        unsigned char m[32];
        for (int i = 0; i < 32; i++) m[i] = (unsigned char)(i * 7 + what);
        unsigned char ct[btf::CHAN_KEM_CTBYTES], ss[32];
        int r = BTF_MLK(enc_derand)(ct, ss, &pk[0], m);
#ifdef FUZZ_HAVE_OPENSSL_MLKEM
        EVP_PKEY* key = OsslKey(OSSL_PKEY_PARAM_PUB_KEY, &pk[0], pk.size());
        if ((key != NULL) != (r == 0))
            abort();   // one accepts the public key and the other refuses it
        if (key)
        {
            unsigned char oct[btf::CHAN_KEM_CTBYTES], oss[32];
            if (g_fOsslIkme && OsslEncap(key, m, oct, oss) &&
                (memcmp(oct, ct, sizeof(oct)) != 0 || memcmp(oss, ss, 32) != 0))
                abort();   // same key, same coins, different result
            EVP_PKEY_free(key);
        }
#else
        (void)r;
#endif
    }
}

// ---- the link ---------------------------------------------------------------

class MemStream : public Stream
{
public:
    std::vector<unsigned char> in;
    size_t at;
    std::vector<unsigned char> out;
    MemStream() : at(0) {}
    bool Write(const unsigned char* p, size_t n) { out.insert(out.end(), p, p + n); return true; }
    bool Read(unsigned char* p, size_t n)
    {
        if (in.size() - at < n)
            return false;
        memcpy(p, &in[at], n);
        at += n;
        return true;
    }
};

static void ModeLink(Reader& rd)
{
    uint8_t sel = rd.U8();
    if (sel & 1)
    {
        // The endpoint, fed the input: flight 1, flight 3, then frames.
        MemStream s;
        std::vector<unsigned char> b = rd.Bytes(rd.n);
        s.in = b;
        Link link;
        std::string err;
        if (!link.AcceptAsEndpoint(s, g_id[ALICE].chan_sk, err))
            return;
        for (int i = 0; i < 8 && link.IsOpen(); i++)
        {
            std::string js;
            if (!link.RecvFrame(s, js, err))
                break;
            abort();   // a frame authenticated under a session nobody else holds
        }
        return;
    }
    // A real client and endpoint, in memory, then the input's frames.
    btf::ChanClientCtx cc;
    btf::ChanEndpointCtx ec;
    btf::ChanSession cs, es;
    unsigned char hs1[btf::CHAN_HS1BYTES], hs2[btf::CHAN_HS2BYTES], hs3[btf::CHAN_HS3BYTES];
    if (!btf::ChanClientFlight1(cc, hs1) || !btf::ChanEndpointFlight2(ec, hs1, hs2) ||
        !btf::ChanClientFlight3(cc, g_id[ALICE].chan_pk, hs2, hs3, cs) ||
        !btf::ChanEndpointFinish(ec, g_id[ALICE].chan_sk, hs3, es))
        abort();
    InboxState st = FreshInbox();
    for (int i = 0; i < 8 && rd.n; i++)
    {
        uint8_t f = rd.U8();
        std::string pt;
        int signer = 0;
        if (f & 1)
            BuildSigned(rd, signer, pt);
        else
            pt = rd.Str(rd.U16() % (MAX_FRAME_BYTES + 128));
        std::vector<unsigned char> wire = btf::ChanEncryptFrame(cs, (const unsigned char*)pt.data(), pt.size());
        std::vector<unsigned char> body(wire.begin() + 4, wire.end());
        std::vector<unsigned char> orig = body;
        if (f & 2)
            body[rd.U16() % body.size()] ^= (unsigned char)(rd.U8() | 1);
        std::vector<unsigned char> got;
        bool fOk = btf::ChanDecryptBody(es, &body[0], body.size(), got);
        if (body != orig)
        {
            if (fOk)
                abort();   // a changed body decrypted
            return;        // the session is out of step now, as on a real link
        }
        if (!fOk || std::string(got.begin(), got.end()) != pt)
            abort();
        DeliverChecked(st, pt, g_id[BOB].address);
    }
}

// ---- epoch announcements ----------------------------------------------------

static void ModeEpoch(Reader& rd)
{
    uint8_t sel = rd.U8();
    int64_t e = 0;
    unsigned char x[btf::CHAN_KEYBYTES], kem[btf::CHAN_KEM_PUBBYTES];
    std::string err;
    if (sel & 1)
    {
        std::string js = rd.Str(rd.n);
        VerifyEpochKeys(g_ctx, g_id[sel % NUM_IDS].address, js, Now(), e, x, kem, err);
        return;
    }
    const Identity& id = g_id[(sel >> 1) % NUM_IDS];
    EpochKeys k;
    k.epoch = MailboxEpoch(Now()) + (int8_t)rd.U8();
    std::vector<unsigned char> xb = rd.Bytes(32);
    xb.resize(32, 1);
    memcpy(k.x_pk, &xb[0], 32);
    memcpy(k.kem_pk, g_kemPk, sizeof(k.kem_pk));
    std::string js;
    if (!SignEpochKeys(g_ctx, id, k, js, err))
        abort();
    bool fOk = VerifyEpochKeys(g_ctx, id.address, js, Now(), e, x, kem, err);
    if (!fOk && err != "the announced epoch is not current")
        abort();       // signed by its own address, refused for something else
    if (fOk && (e != k.epoch || memcmp(x, k.x_pk, 32) != 0 || memcmp(kem, k.kem_pk, sizeof(kem)) != 0))
        abort();
    // Announced for one address, never accepted for another.
    if (VerifyEpochKeys(g_ctx, g_id[(id.address == g_id[BOB].address) ? CAROL : BOB].address, js, Now(), e, x, kem, err))
        abort();
}

// ---- stores -----------------------------------------------------------------

static void ModeStores(Reader& rd)
{
    uint8_t sel = rd.U8();
    std::string js = rd.Str(rd.n);
    std::string err;
    if (sel & 1)
    {
        Mailbox m;
        if (m.FromJson(js, err))
        {
            std::string a = m.ToJson();
            Mailbox m2;
            if (!m2.FromJson(a, err) || m2.ToJson() != a)
                abort();
        }
    }
    else
    {
        Roster r;
        if (r.FromJson(js, err))
        {
            std::string a = r.ToJson();
            Roster r2;
            if (!r2.FromJson(a, err) || r2.ToJson() != a)
                abort();
        }
    }
}

// ---- seeds --------------------------------------------------------------------

static void WriteFile(const std::string& path, const std::string& data)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { perror(path.c_str()); exit(1); }
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
}

static void WriteSeeds(const std::string& dir)
{
    // Mode 0: real frames from Bob (accepted) and Carol (unknown).
    const char* texts[] = { "hello", "{\"v\":2,\"give\":\"BTF\",\"ga\":100000000,\"want\":\"LTC\",\"wa\":100000}" };
    for (int i = 0; i < 2; i++)
    {
        Frame f;
        f.kind = i == 0 ? MSG_TEXT : MSG_INVITE;
        f.sent = Now();
        f.id = std::string(31, 'b') + (char)('0' + i);
        f.text = i == 0 ? texts[0] : "hi";
        std::string js, err;
        SignFrame(g_ctx, g_id[i == 0 ? BOB : CAROL], f, js, err);
        WriteFile(dir + "/frame-" + std::to_string(i), std::string(1, '\0') + std::string(1, (char)(i ? 0 : 3)) + js);
    }
    // Mode 1: field-built frames of each kind.
    for (int k = 0; k <= MSG_SWAP; k++)
    {
        std::string s;
        s += (char)1;
        s += (char)(k % NUM_IDS);      // signer
        s += (char)(k == MSG_GROUP_INVITE ? 0x1c : k == MSG_GROUP_TEXT ? 0x0c : 0);
        s += (char)k;
        s += std::string("\x00\x00", 2);
        s += std::string(16, (char)k);
        std::string text = k == MSG_SWAP_OFFER ? texts[1] : k == MSG_SWAP ? "{\"s\":\"00112233445566778899aabbccddeeff\",\"step\":\"cancel\"}" : "text";
        s += (char)(text.size() & 0xff);
        s += (char)(text.size() >> 8);
        s += text;
        s += std::string(40, '\x01');
        WriteFile(dir + "/signed-" + std::to_string(k), s);
    }
    WriteFile(dir + "/envelope-intact", std::string("\x02\x00\x00", 3));
    WriteFile(dir + "/envelope-flip", std::string("\x02\x01\x10\x00\x01\x00", 6));
    WriteFile(dir + "/envelope-raw", std::string("\x03") + "{\"v\":1}");
    WriteFile(dir + "/mlkem-encap", std::string("\x04\x00") + std::string(32, 'm') + std::string("\x01\x05\x00\x80", 4));
    WriteFile(dir + "/mlkem-keygen", std::string("\x04\x01") + std::string(64, 's'));
    WriteFile(dir + "/mlkem-pk", std::string("\x04\x02\x10\x00\x01"));
    WriteFile(dir + "/link-client", std::string("\x05\x00\x00\x05\x00hello\x02\x05\x00world\x03\x00", 20));
    WriteFile(dir + "/link-endpoint", std::string("\x05\x01") + std::string(32 + 1568 + 4 + 40, 'x'));
    WriteFile(dir + "/epoch-signed", std::string("\x06\x02\x00", 3) + std::string(32, 'x'));
    WriteFile(dir + "/epoch-json", std::string("\x06\x03{\"v\":1,\"addr\":\"x\",\"epoch\":1e300}"));
    WriteFile(dir + "/store-mailbox", std::string("\x07\x01") + g_mailbox.ToJson());
    WriteFile(dir + "/store-roster", std::string("\x07\x00") + g_roster.ToJson());
}

static void Init()
{
    if (sodium_init() < 0)
        abort();
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    for (int i = 0; i < NUM_IDS; i++)
        MakeIdentity(i, g_id[i]);

    std::string err;
    int64_t t = Now() - 1000;
    if (!g_roster.NoteIncomingInvite(g_id[BOB].address, "hi", t, err) ||
        !g_roster.AcceptInvite(g_id[BOB].address, err) ||
        !g_roster.NoteOutgoingInvite(g_id[ERIN].address, t, err) ||
        !g_roster.Block(g_id[DAVE].address, err))
        abort();
    g_groupId = std::string(64, 'f');
    if (!g_roster.CreateGroup(g_groupId, "room", g_id[ALICE].address, err) ||
        !g_roster.AddGroupMember(g_groupId, g_id[BOB].address, g_id[ALICE].address, err))
        abort();

    // ML-KEM key from a fixed seed, and Alice's epoch keys around it.
    if (BTF_MLK(keypair_derand)(g_kemPk, g_kemSk, KEM_SEED) != 0)
        abort();
    g_epoch.epoch = MailboxEpoch(Now());
    for (int i = 0; i < 32; i++) g_epoch.x_sk[i] = (unsigned char)(0x90 + i);
    btf::ChanPublicFromSecret(g_epoch.x_pk, g_epoch.x_sk);
    memcpy(g_epoch.kem_pk, g_kemPk, sizeof(g_kemPk));
    memcpy(g_epoch.kem_sk, g_kemSk, sizeof(g_kemSk));
    std::string mj = "[{\"e\":" + std::to_string(g_epoch.epoch) +
                     ",\"xp\":\"" + Hex(g_epoch.x_pk, 32) + "\",\"xs\":\"" + Hex(g_epoch.x_sk, 32) +
                     "\",\"kp\":\"" + Hex(g_epoch.kem_pk, sizeof(g_epoch.kem_pk)) +
                     "\",\"ks\":\"" + Hex(g_epoch.kem_sk, sizeof(g_epoch.kem_sk)) + "\"}]";
    if (!g_mailbox.FromJson(mj, err) || g_mailbox.LiveEpochs() != 1)
        abort();

#ifdef FUZZ_HAVE_OPENSSL_MLKEM
    {
        EVP_PKEY* key = OsslKey(OSSL_PKEY_PARAM_PUB_KEY, g_kemPk, sizeof(g_kemPk));
        unsigned char m[32], c1[btf::CHAN_KEM_CTBYTES], c2[btf::CHAN_KEM_CTBYTES], s1[32], s2[32];
        memset(m, 7, sizeof(m));
        g_fOsslIkme = key && OsslEncap(key, m, c1, s1) && OsslEncap(key, m, c2, s2) &&
                      memcmp(c1, c2, sizeof(c1)) == 0;
        if (key)
            EVP_PKEY_free(key);
        fprintf(stderr, "fuzz-chat-frame: OpenSSL ML-KEM-1024 differential on%s\n",
                g_fOsslIkme ? ", encapsulation with fixed coins too" : " (decapsulation and key generation)");
    }
#endif

    Frame f;
    f.kind = MSG_TEXT;
    f.sent = Now();
    f.id = std::string(32, 'e');
    f.text = "left while you were away";
    if (!SignFrame(g_ctx, g_id[BOB], f, g_frameInEnvelope, err) ||
        !SealEnvelope(g_epoch.x_pk, g_epoch.kem_pk, g_frameInEnvelope, g_envelope, err))
        abort();

    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 70000)
        return 0;
    Reader rd(data + 1, size - 1);
    switch (data[0] % 8)
    {
    case 0: ModeFrameJson(rd); break;
    case 1: ModeFrameSigned(rd); break;
    case 2: ModeEnvelopeMutate(rd); break;
    case 3: ModeEnvelopeRaw(rd); break;
    case 4: ModeMlKem(rd); break;
    case 5: ModeLink(rd); break;
    case 6: ModeEpoch(rd); break;
    case 7: ModeStores(rd); break;
    }
    return 0;
}
