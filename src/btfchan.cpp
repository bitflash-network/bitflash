// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Hybrid X25519 + ML-KEM-1024 channel. See btfchan.h for the shape of the
// handshake and why each piece is there.

#include "btfchan.h"

#include <sodium.h>
#include <cstring>

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem/mlkem_native.h"

// mlkem_native.h undefines its own namespacing macros on the way out, so
// MLK_API_NAMESPACE() is gone by the time this file uses it. The prefix the
// config settled on does survive, and the exported names are that prefix, an
// underscore, and the function -- so build them here and stay in step with
// whatever parameter set the build was configured for.
#define BTF_MLK_CAT_(a, b) a##b
#define BTF_MLK_CAT(a, b) BTF_MLK_CAT_(a, b)
#define BTF_MLK(sym) BTF_MLK_CAT(BTF_MLK_CAT(MLK_CONFIG_NAMESPACE_PREFIX, _), sym)

namespace btf
{

// Our constants against libsodium's and the KEM's. A parameter-set slip is a
// build failure here rather than a buffer overrun in the field.
static_assert(CHAN_NONCEBYTES == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "nonce");
static_assert(CHAN_MACBYTES   == crypto_aead_xchacha20poly1305_ietf_ABYTES,    "mac");
static_assert(CHAN_KEYBYTES   == crypto_aead_xchacha20poly1305_ietf_KEYBYTES,  "key");
static_assert(CHAN_KEYBYTES   == crypto_scalarmult_BYTES,                      "x25519");
static_assert(CHAN_KEM_PUBBYTES == MLKEM_PUBLICKEYBYTES(1024),  "kem pk");
static_assert(CHAN_KEM_SECBYTES == MLKEM_SECRETKEYBYTES(1024),  "kem sk");
static_assert(CHAN_KEM_CTBYTES  == MLKEM_CIPHERTEXTBYTES(1024), "kem ct");
static_assert(CHAN_KEYBYTES     == MLKEM_BYTES,                "kem ss");

// Labels keep the three uses of the same hash apart: two chains derived from
// one root, and two kinds of step within a chain. Without them a chain key
// could be mistaken for a message key, and one leak would cost the other.
static const unsigned char LBL_ROOT[]  = "btfchan-v2-root";
static const unsigned char LBL_C2S[]   = "btfchan-v2-c2s";
static const unsigned char LBL_S2C[]   = "btfchan-v2-s2c";
static const unsigned char LBL_MSG     = 0x01;
static const unsigned char LBL_STEP    = 0x02;

bool ChanInit()
{
    return sodium_init() >= 0;
}

void ChanKeypair(unsigned char pk[CHAN_KEYBYTES], unsigned char sk[CHAN_KEYBYTES])
{
    randombytes_buf(sk, CHAN_KEYBYTES);
    crypto_scalarmult_base(pk, sk);
}

void ChanPublicFromSecret(unsigned char pk[CHAN_KEYBYTES], const unsigned char sk[CHAN_KEYBYTES])
{
    crypto_scalarmult_base(pk, sk);
}

void ChanClientCtxClear(ChanClientCtx& ctx)   { sodium_memzero(&ctx, sizeof(ctx)); }
void ChanEndpointCtxClear(ChanEndpointCtx& ctx) { sodium_memzero(&ctx, sizeof(ctx)); }
void ChanSessionClear(ChanSession& s)         { sodium_memzero(&s, sizeof(s)); }

// ---------------------------------------------------------------- key schedule

// One BLAKE2b over label || parts. Every derivation in this file goes through
// here so there is a single place to read and a single place to get wrong.
static void Kdf(unsigned char out[CHAN_KEYBYTES],
                const unsigned char* label, size_t label_len,
                const unsigned char* a, size_t a_len,
                const unsigned char* b, size_t b_len,
                const unsigned char* c, size_t c_len)
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, CHAN_KEYBYTES);
    crypto_generichash_update(&st, label, label_len);
    if (a && a_len) crypto_generichash_update(&st, a, a_len);
    if (b && b_len) crypto_generichash_update(&st, b, b_len);
    if (c && c_len) crypto_generichash_update(&st, c, c_len);
    crypto_generichash_final(&st, out, CHAN_KEYBYTES);
    sodium_memzero(&st, sizeof(st));
}

// The three secrets and the full transcript go in; the two chain keys come out.
// The transcript is included so that a man in the middle who swaps a public key
// ends up with a different root and simply cannot talk to either side.
static void DeriveSession(ChanSession& sess,
                          bool fClient,
                          const unsigned char dh_ee[CHAN_KEYBYTES],
                          const unsigned char dh_es[CHAN_KEYBYTES],
                          const unsigned char ss_kem[CHAN_KEYBYTES],
                          const unsigned char* transcript, size_t transcript_len)
{
    unsigned char root[CHAN_KEYBYTES];
    unsigned char secrets[3 * CHAN_KEYBYTES];
    memcpy(secrets,                        dh_ee,  CHAN_KEYBYTES);
    memcpy(secrets + CHAN_KEYBYTES,        dh_es,  CHAN_KEYBYTES);
    memcpy(secrets + 2 * CHAN_KEYBYTES,    ss_kem, CHAN_KEYBYTES);

    Kdf(root, LBL_ROOT, sizeof(LBL_ROOT) - 1,
        secrets, sizeof(secrets),
        transcript, transcript_len,
        NULL, 0);

    unsigned char ck_c2s[CHAN_KEYBYTES];
    unsigned char ck_s2c[CHAN_KEYBYTES];
    Kdf(ck_c2s, LBL_C2S, sizeof(LBL_C2S) - 1, root, CHAN_KEYBYTES, NULL, 0, NULL, 0);
    Kdf(ck_s2c, LBL_S2C, sizeof(LBL_S2C) - 1, root, CHAN_KEYBYTES, NULL, 0, NULL, 0);

    memcpy(sess.ck_send, fClient ? ck_c2s : ck_s2c, CHAN_KEYBYTES);
    memcpy(sess.ck_recv, fClient ? ck_s2c : ck_c2s, CHAN_KEYBYTES);
    sess.n_send = 0;
    sess.n_recv = 0;

    sodium_memzero(secrets, sizeof(secrets));
    sodium_memzero(root,    sizeof(root));
    sodium_memzero(ck_c2s,  sizeof(ck_c2s));
    sodium_memzero(ck_s2c,  sizeof(ck_s2c));
}

// Take this frame's key out of the chain and push the chain forward. The old
// chain key is overwritten, so the keys already used cannot be recomputed from
// what the process still holds.
static void RatchetStep(unsigned char ck[CHAN_KEYBYTES],
                        uint64_t counter,
                        unsigned char mk_out[CHAN_KEYBYTES])
{
    unsigned char ctr[CHAN_CTRBYTES];
    for (int i = 0; i < CHAN_CTRBYTES; i++)
        ctr[i] = (unsigned char)((counter >> (8 * (CHAN_CTRBYTES - 1 - i))) & 0xff);

    unsigned char tag_msg = LBL_MSG;
    unsigned char tag_step = LBL_STEP;
    unsigned char next[CHAN_KEYBYTES];

    Kdf(mk_out, &tag_msg,  1, ck, CHAN_KEYBYTES, ctr, sizeof(ctr), NULL, 0);
    Kdf(next,   &tag_step, 1, ck, CHAN_KEYBYTES, NULL, 0,          NULL, 0);

    memcpy(ck, next, CHAN_KEYBYTES);
    sodium_memzero(next, sizeof(next));
    sodium_memzero(ctr,  sizeof(ctr));
}

// ------------------------------------------------------------------ handshake

bool ChanClientFlight1(ChanClientCtx& ctx, unsigned char out[CHAN_HS1BYTES])
{
    randombytes_buf(ctx.eph_sk, CHAN_KEYBYTES);
    crypto_scalarmult_base(ctx.eph_pub, ctx.eph_sk);
    memcpy(out, ctx.eph_pub, CHAN_KEYBYTES);
    return true;
}

bool ChanEndpointFlight2(ChanEndpointCtx& ctx,
                         const unsigned char hs1[CHAN_HS1BYTES],
                         unsigned char out[CHAN_HS2BYTES])
{
    memcpy(ctx.client_eph_pub, hs1, CHAN_KEYBYTES);

    randombytes_buf(ctx.eph_sk, CHAN_KEYBYTES);
    crypto_scalarmult_base(ctx.eph_pub, ctx.eph_sk);

    // The KEM library never reaches for randomness itself: we hand it coins
    // from libsodium, which is the only source this project trusts.
    unsigned char coins[2 * CHAN_KEYBYTES];
    randombytes_buf(coins, sizeof(coins));
    int r = BTF_MLK(keypair_derand)(ctx.kem_pub, ctx.kem_sk, coins);
    sodium_memzero(coins, sizeof(coins));
    if (r != 0)
        return false;

    memcpy(out, ctx.eph_pub, CHAN_KEYBYTES);
    memcpy(out + CHAN_KEYBYTES, ctx.kem_pub, CHAN_KEM_PUBBYTES);
    return true;
}

// transcript = hs1 || hs2 || hs3, the bytes both sides actually saw.
static void BuildTranscript(std::vector<unsigned char>& t,
                            const unsigned char* hs1,
                            const unsigned char* hs2,
                            const unsigned char* hs3)
{
    t.resize(CHAN_HS1BYTES + CHAN_HS2BYTES + CHAN_HS3BYTES);
    memcpy(&t[0], hs1, CHAN_HS1BYTES);
    memcpy(&t[CHAN_HS1BYTES], hs2, CHAN_HS2BYTES);
    memcpy(&t[CHAN_HS1BYTES + CHAN_HS2BYTES], hs3, CHAN_HS3BYTES);
}

bool ChanClientFlight3(ChanClientCtx& ctx,
                       const unsigned char endpoint_static_pub[CHAN_KEYBYTES],
                       const unsigned char hs2[CHAN_HS2BYTES],
                       unsigned char out[CHAN_HS3BYTES],
                       ChanSession& sess)
{
    const unsigned char* ep_eph_pub = hs2;
    const unsigned char* ep_kem_pub = hs2 + CHAN_KEYBYTES;

    unsigned char dh_ee[CHAN_KEYBYTES];
    unsigned char dh_es[CHAN_KEYBYTES];
    unsigned char ss_kem[CHAN_KEYBYTES];
    bool fOk = false;

    // crypto_scalarmult rejects a point that would force the shared secret to a
    // known constant; a peer sending one is trying to fix the key, not talk.
    if (crypto_scalarmult(dh_ee, ctx.eph_sk, ep_eph_pub) != 0)
        goto done;
    if (crypto_scalarmult(dh_es, ctx.eph_sk, endpoint_static_pub) != 0)
        goto done;

    {
        unsigned char coins[CHAN_KEYBYTES];
        randombytes_buf(coins, sizeof(coins));
        int r = BTF_MLK(enc_derand)(out, ss_kem, ep_kem_pub, coins);
        sodium_memzero(coins, sizeof(coins));
        if (r != 0)
            goto done;
    }

    {
        std::vector<unsigned char> transcript;
        BuildTranscript(transcript, ctx.eph_pub, hs2, out);
        DeriveSession(sess, true, dh_ee, dh_es, ss_kem, &transcript[0], transcript.size());
        sodium_memzero(&transcript[0], transcript.size());
    }
    fOk = true;

done:
    sodium_memzero(dh_ee,  sizeof(dh_ee));
    sodium_memzero(dh_es,  sizeof(dh_es));
    sodium_memzero(ss_kem, sizeof(ss_kem));
    return fOk;
}

bool ChanEndpointFinish(ChanEndpointCtx& ctx,
                        const unsigned char my_static_sk[CHAN_KEYBYTES],
                        const unsigned char hs3[CHAN_HS3BYTES],
                        ChanSession& sess)
{
    unsigned char dh_ee[CHAN_KEYBYTES];
    unsigned char dh_es[CHAN_KEYBYTES];
    unsigned char ss_kem[CHAN_KEYBYTES];
    bool fOk = false;

    if (crypto_scalarmult(dh_ee, ctx.eph_sk, ctx.client_eph_pub) != 0)
        goto done;
    if (crypto_scalarmult(dh_es, my_static_sk, ctx.client_eph_pub) != 0)
        goto done;

    // ML-KEM decapsulation never reports failure: on a bad ciphertext it returns
    // a deterministic decoy secret instead. That is deliberate in the standard,
    // and it is why the frame tag is what ultimately rejects a wrong peer.
    if (BTF_MLK(dec)(ss_kem, hs3, ctx.kem_sk) != 0)
        goto done;

    {
        unsigned char hs2[CHAN_HS2BYTES];
        memcpy(hs2, ctx.eph_pub, CHAN_KEYBYTES);
        memcpy(hs2 + CHAN_KEYBYTES, ctx.kem_pub, CHAN_KEM_PUBBYTES);

        std::vector<unsigned char> transcript;
        BuildTranscript(transcript, ctx.client_eph_pub, hs2, hs3);
        DeriveSession(sess, false, dh_ee, dh_es, ss_kem, &transcript[0], transcript.size());
        sodium_memzero(&transcript[0], transcript.size());
    }
    fOk = true;

done:
    sodium_memzero(dh_ee,  sizeof(dh_ee));
    sodium_memzero(dh_es,  sizeof(dh_es));
    sodium_memzero(ss_kem, sizeof(ss_kem));
    return fOk;
}

// --------------------------------------------------------------------- frames

std::vector<unsigned char> ChanEncryptFrame(ChanSession& sess,
                                            const unsigned char* pt, size_t n)
{
    unsigned char ctr[CHAN_CTRBYTES];
    for (int i = 0; i < CHAN_CTRBYTES; i++)
        ctr[i] = (unsigned char)((sess.n_send >> (8 * (CHAN_CTRBYTES - 1 - i))) & 0xff);

    unsigned char mk[CHAN_KEYBYTES];
    RatchetStep(sess.ck_send, sess.n_send, mk);

    // One key per frame, so the nonce never has to be unique by itself. It is
    // still the counter rather than zero, so a capture reads in order.
    unsigned char nonce[CHAN_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, ctr, CHAN_CTRBYTES);

    size_t bodylen = CHAN_CTRBYTES + n + CHAN_MACBYTES;
    std::vector<unsigned char> out(4 + bodylen);
    out[0] = (unsigned char)((bodylen >> 24) & 0xff);
    out[1] = (unsigned char)((bodylen >> 16) & 0xff);
    out[2] = (unsigned char)((bodylen >> 8)  & 0xff);
    out[3] = (unsigned char)( bodylen        & 0xff);
    memcpy(&out[4], ctr, CHAN_CTRBYTES);

    unsigned long long ctlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        &out[4 + CHAN_CTRBYTES], &ctlen,
        pt, (unsigned long long)n,
        ctr, CHAN_CTRBYTES,   // counter is authenticated, not just carried
        NULL, nonce, mk);

    sess.n_send++;
    sodium_memzero(mk, sizeof(mk));
    return out;
}

bool ChanDecryptBody(ChanSession& sess,
                     const unsigned char* body, size_t n,
                     std::vector<unsigned char>& out)
{
    out.clear();
    if (n < (size_t)(CHAN_CTRBYTES + CHAN_MACBYTES))
        return false;

    const unsigned char* ctr = body;
    const unsigned char* ct  = body + CHAN_CTRBYTES;
    size_t ctlen = n - CHAN_CTRBYTES;

    uint64_t counter = 0;
    for (int i = 0; i < CHAN_CTRBYTES; i++)
        counter = (counter << 8) | ctr[i];

    // Out of order means dropped, replayed or reordered. The ratchet only moves
    // forward, so there is no key for any of those: refuse without touching it.
    if (counter != sess.n_recv)
        return false;

    unsigned char mk[CHAN_KEYBYTES];
    unsigned char ck_try[CHAN_KEYBYTES];
    memcpy(ck_try, sess.ck_recv, CHAN_KEYBYTES);
    RatchetStep(ck_try, counter, mk);

    unsigned char nonce[CHAN_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, ctr, CHAN_CTRBYTES);

    out.resize(ctlen - CHAN_MACBYTES);
    unsigned long long ptlen = 0;
    int r = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.empty() ? NULL : &out[0], &ptlen,
        NULL,
        ct, (unsigned long long)ctlen,
        ctr, CHAN_CTRBYTES,
        nonce, mk);

    sodium_memzero(mk, sizeof(mk));

    if (r != 0)
    {
        // A frame that does not authenticate is not a frame. Leaving the ratchet
        // where it was means a forgery cannot cost the next real frame its key.
        sodium_memzero(ck_try, sizeof(ck_try));
        out.clear();
        return false;
    }

    memcpy(sess.ck_recv, ck_try, CHAN_KEYBYTES);
    sodium_memzero(ck_try, sizeof(ck_try));
    sess.n_recv++;
    out.resize((size_t)ptlen);
    return true;
}

// ------------------------------------------------------------ store and forward

static const unsigned char LBL_SEAL[]   = "btfchan-v2-seal";
static const unsigned char LBL_SEALN[]  = "btfchan-v2-seal-nonce";

bool ChanKemKeypair(unsigned char pk[CHAN_KEM_PUBBYTES], unsigned char sk[CHAN_KEM_SECBYTES])
{
    unsigned char coins[2 * 32];
    randombytes_buf(coins, sizeof(coins));
    int r = BTF_MLK(keypair_derand)(pk, sk, coins);
    sodium_memzero(coins, sizeof(coins));
    return r == 0;
}

// The envelope key and its nonce, from the two shared secrets plus everything
// that identifies this envelope and this recipient. Binding both recipient
// public keys in is what stops an envelope from being re-aimed: change who it is
// for and the key changes with it.
static void SealKeys(unsigned char key_out[CHAN_KEYBYTES],
                     unsigned char nonce_out[CHAN_NONCEBYTES],
                     const unsigned char dh[CHAN_KEYBYTES],
                     const unsigned char ss_kem[CHAN_KEYBYTES],
                     const unsigned char eph_pub[CHAN_KEYBYTES],
                     const unsigned char kem_ct[CHAN_KEM_CTBYTES],
                     const unsigned char recip_x_pub[CHAN_KEYBYTES],
                     const unsigned char recip_kem_pub[CHAN_KEM_PUBBYTES])
{
    unsigned char secrets[2 * CHAN_KEYBYTES];
    memcpy(secrets,                 dh,     CHAN_KEYBYTES);
    memcpy(secrets + CHAN_KEYBYTES, ss_kem, CHAN_KEYBYTES);

    // The transcript: the envelope's own public parts, then whom it is for.
    std::vector<unsigned char> tr;
    tr.reserve(CHAN_KEYBYTES + CHAN_KEM_CTBYTES + CHAN_KEYBYTES + CHAN_KEM_PUBBYTES);
    tr.insert(tr.end(), eph_pub,       eph_pub + CHAN_KEYBYTES);
    tr.insert(tr.end(), kem_ct,        kem_ct + CHAN_KEM_CTBYTES);
    tr.insert(tr.end(), recip_x_pub,   recip_x_pub + CHAN_KEYBYTES);
    tr.insert(tr.end(), recip_kem_pub, recip_kem_pub + CHAN_KEM_PUBBYTES);

    Kdf(key_out, LBL_SEAL, sizeof(LBL_SEAL) - 1,
        secrets, sizeof(secrets), &tr[0], tr.size(), NULL, 0);

    // A separate derivation for the nonce rather than a zero one: the key is
    // already unique per envelope, so a zero nonce would be safe -- and would
    // stop being safe the day someone reuses an ephemeral by accident. This
    // costs one hash and removes that day.
    unsigned char nfull[CHAN_KEYBYTES];
    Kdf(nfull, LBL_SEALN, sizeof(LBL_SEALN) - 1,
        secrets, sizeof(secrets), &tr[0], tr.size(), NULL, 0);
    memcpy(nonce_out, nfull, CHAN_NONCEBYTES);

    sodium_memzero(secrets, sizeof(secrets));
    sodium_memzero(nfull,   sizeof(nfull));
}

bool ChanSealTo(const unsigned char recip_x25519_pub[CHAN_KEYBYTES],
                const unsigned char recip_kem_pub[CHAN_KEM_PUBBYTES],
                const unsigned char* pt, size_t n,
                std::vector<unsigned char>& out)
{
    out.clear();
    if (!pt && n)
        return false;

    unsigned char eph_sk[CHAN_KEYBYTES], eph_pub[CHAN_KEYBYTES];
    ChanKeypair(eph_pub, eph_sk);

    unsigned char dh[CHAN_KEYBYTES];
    bool fOk = crypto_scalarmult(dh, eph_sk, recip_x25519_pub) == 0;
    sodium_memzero(eph_sk, sizeof(eph_sk));
    if (!fOk)
    {
        // An all-zero shared secret: the recipient key is a small-order point,
        // so there is nothing to encrypt to.
        sodium_memzero(dh, sizeof(dh));
        return false;
    }

    unsigned char kem_ct[CHAN_KEM_CTBYTES];
    unsigned char ss_kem[CHAN_KEYBYTES];
    unsigned char coins[32];
    randombytes_buf(coins, sizeof(coins));
    int r = BTF_MLK(enc_derand)(kem_ct, ss_kem, recip_kem_pub, coins);
    sodium_memzero(coins, sizeof(coins));
    if (r != 0)
    {
        sodium_memzero(dh, sizeof(dh));
        sodium_memzero(ss_kem, sizeof(ss_kem));
        return false;
    }

    unsigned char key[CHAN_KEYBYTES], nonce[CHAN_NONCEBYTES];
    SealKeys(key, nonce, dh, ss_kem, eph_pub, kem_ct, recip_x25519_pub, recip_kem_pub);
    sodium_memzero(dh, sizeof(dh));
    sodium_memzero(ss_kem, sizeof(ss_kem));

    out.resize(CHAN_KEYBYTES + CHAN_KEM_CTBYTES + n + CHAN_MACBYTES);
    memcpy(&out[0], eph_pub, CHAN_KEYBYTES);
    memcpy(&out[CHAN_KEYBYTES], kem_ct, CHAN_KEM_CTBYTES);

    unsigned long long ctlen = 0;
    r = crypto_aead_xchacha20poly1305_ietf_encrypt(
        &out[CHAN_KEYBYTES + CHAN_KEM_CTBYTES], &ctlen,
        pt, (unsigned long long)n,
        // The envelope's public parts are authenticated as associated data, so
        // the ciphertext cannot be lifted onto a different header.
        &out[0], CHAN_KEYBYTES + CHAN_KEM_CTBYTES,
        NULL, nonce, key);

    sodium_memzero(key,   sizeof(key));
    sodium_memzero(nonce, sizeof(nonce));

    if (r != 0)
    {
        out.clear();
        return false;
    }
    out.resize(CHAN_KEYBYTES + CHAN_KEM_CTBYTES + (size_t)ctlen);
    return true;
}

bool ChanOpenSealed(const unsigned char recip_x25519_sk[CHAN_KEYBYTES],
                    const unsigned char recip_kem_pub[CHAN_KEM_PUBBYTES],
                    const unsigned char recip_kem_sk[CHAN_KEM_SECBYTES],
                    const unsigned char* in, size_t n,
                    std::vector<unsigned char>& out)
{
    out.clear();
    const size_t HDR = CHAN_KEYBYTES + CHAN_KEM_CTBYTES;
    if (!in || n < HDR + CHAN_MACBYTES)
        return false;

    const unsigned char* eph_pub = in;
    const unsigned char* kem_ct  = in + CHAN_KEYBYTES;

    unsigned char dh[CHAN_KEYBYTES];
    if (crypto_scalarmult(dh, recip_x25519_sk, eph_pub) != 0)
    {
        sodium_memzero(dh, sizeof(dh));
        return false;
    }

    unsigned char ss_kem[CHAN_KEYBYTES];
    if (BTF_MLK(dec)(ss_kem, kem_ct, recip_kem_sk) != 0)
    {
        sodium_memzero(dh, sizeof(dh));
        sodium_memzero(ss_kem, sizeof(ss_kem));
        return false;
    }

    // The X25519 half is recomputed from the secret rather than taken on trust;
    // the ML-KEM half is the caller's, for the reason in the header.
    unsigned char recip_x_pub[CHAN_KEYBYTES];
    crypto_scalarmult_base(recip_x_pub, recip_x25519_sk);

    unsigned char key[CHAN_KEYBYTES], nonce[CHAN_NONCEBYTES];
    SealKeys(key, nonce, dh, ss_kem, eph_pub, kem_ct, recip_x_pub, recip_kem_pub);
    sodium_memzero(dh, sizeof(dh));
    sodium_memzero(ss_kem, sizeof(ss_kem));

    out.resize(n - HDR - CHAN_MACBYTES);
    unsigned long long ptlen = 0;
    int r = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.empty() ? NULL : &out[0], &ptlen, NULL,
        in + HDR, (unsigned long long)(n - HDR),
        in, HDR,
        nonce, key);

    sodium_memzero(key,   sizeof(key));
    sodium_memzero(nonce, sizeof(nonce));

    if (r != 0)
    {
        out.clear();
        return false;
    }
    out.resize((size_t)ptlen);
    return true;
}

} // namespace btf
