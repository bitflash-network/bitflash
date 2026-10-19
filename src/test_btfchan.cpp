// Standalone tests for btfchan (hybrid X25519 + ML-KEM-1024 channel).
// Build (UCRT64):
//   g++ -std=gnu++14 -I. test_btfchan.cpp btfchan.cpp mlkem/mlkem_native.c
//       -lsodium -o test_btfchan.exe
//
// What these tests are for: the handshake is the part of this project where a
// mistake is silent. A channel with a broken key schedule still encrypts, still
// decrypts, and still looks fine from the outside -- it just stops protecting
// anything. So the checks below are written against the properties, not against
// the implementation: same key on both sides, no key reuse between frames, and
// a peer who is not the one the .btf names gets nowhere.

#include "btfchan.h"
#include <sodium.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace btf;
static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

// Run the three flights and hand back both sides' sessions.
static bool Handshake(const unsigned char ep_pk[32], const unsigned char ep_sk[32],
                      ChanSession& cs, ChanSession& es,
                      const unsigned char* client_sees_static = NULL)
{
    ChanClientCtx cc;
    ChanEndpointCtx ec;
    unsigned char hs1[CHAN_HS1BYTES];
    unsigned char hs2[CHAN_HS2BYTES];
    unsigned char hs3[CHAN_HS3BYTES];

    if (!ChanClientFlight1(cc, hs1)) return false;
    if (!ChanEndpointFlight2(ec, hs1, hs2)) return false;
    if (!ChanClientFlight3(cc, client_sees_static ? client_sees_static : ep_pk,
                           hs2, hs3, cs)) return false;
    if (!ChanEndpointFinish(ec, ep_sk, hs3, es)) return false;

    ChanClientCtxClear(cc);
    ChanEndpointCtxClear(ec);
    return true;
}

// Send one frame from a to b and report whether it arrived intact.
static bool Pass(ChanSession& a, ChanSession& b, const std::string& msg)
{
    std::vector<unsigned char> f =
        ChanEncryptFrame(a, (const unsigned char*)msg.data(), msg.size());
    std::vector<unsigned char> pt;
    if (!ChanDecryptBody(b, &f[4], f.size() - 4, pt)) return false;
    return pt.size() == msg.size() && memcmp(&pt[0], msg.data(), msg.size()) == 0;
}

int main()
{
    if (!ChanInit()) { printf("sodium init failed\n"); return 2; }

    unsigned char ep_pk[32], ep_sk[32];
    ChanKeypair(ep_pk, ep_sk);

    printf("wire_sizes\n");
    CHECK(CHAN_HS1BYTES == 32,          "flight 1 is one X25519 key");
    CHECK(CHAN_HS2BYTES == 32 + 1568,   "flight 2 is one X25519 key plus an ML-KEM-1024 key");
    CHECK(CHAN_HS3BYTES == 1568,        "flight 3 is one ML-KEM-1024 ciphertext");

    printf("handshake_derives_matching_sessions\n");
    ChanSession cs, es;
    CHECK(Handshake(ep_pk, ep_sk, cs, es), "three flights complete");
    // The client's send chain is the endpoint's receive chain, and the reverse.
    CHECK(memcmp(cs.ck_send, es.ck_recv, 32) == 0, "client send chain == endpoint recv chain");
    CHECK(memcmp(cs.ck_recv, es.ck_send, 32) == 0, "endpoint send chain == client recv chain");
    CHECK(memcmp(cs.ck_send, cs.ck_recv, 32) != 0, "the two directions use different chains");

    printf("frames_roundtrip_both_ways\n");
    CHECK(Pass(cs, es, "bom dia"),            "client -> endpoint");
    CHECK(Pass(es, cs, "bom dia pra voce"),   "endpoint -> client");
    CHECK(Pass(cs, es, "segunda mensagem"),   "client -> endpoint again");

    printf("every_frame_gets_its_own_key\n");
    {
        ChanSession a, b;
        CHECK(Handshake(ep_pk, ep_sk, a, b), "fresh session");
        const std::string same = "mesma coisa duas vezes";
        std::vector<unsigned char> f1 = ChanEncryptFrame(a, (const unsigned char*)same.data(), same.size());
        std::vector<unsigned char> f2 = ChanEncryptFrame(a, (const unsigned char*)same.data(), same.size());
        // Identical plaintext, different ciphertext: the chain moved between them.
        CHECK(f1.size() == f2.size() && memcmp(&f1[4], &f2[4], f1.size() - 4) != 0,
              "same plaintext twice produces different ciphertext");
        std::vector<unsigned char> pt;
        CHECK(ChanDecryptBody(b, &f1[4], f1.size() - 4, pt), "first frame opens");
        CHECK(ChanDecryptBody(b, &f2[4], f2.size() - 4, pt), "second frame opens");
        ChanSessionClear(a); ChanSessionClear(b);
    }

    printf("tampering_is_rejected\n");
    {
        ChanSession a, b;
        CHECK(Handshake(ep_pk, ep_sk, a, b), "fresh session");
        const std::string msg = "valor 116045";
        std::vector<unsigned char> good = ChanEncryptFrame(a, (const unsigned char*)msg.data(), msg.size());
        std::vector<unsigned char> bad = good;
        bad[bad.size() - 1] ^= 0x01;
        std::vector<unsigned char> pt;
        CHECK(!ChanDecryptBody(b, &bad[4], bad.size() - 4, pt), "flipped bit in the tag is refused");
        CHECK(pt.empty(), "nothing is handed back from a bad frame");
        // The forgery must cost the honest frame nothing: the receive ratchet
        // stayed where it was, so the real frame still opens afterwards.
        CHECK(ChanDecryptBody(b, &good[4], good.size() - 4, pt) &&
              pt.size() == msg.size() && memcmp(&pt[0], msg.data(), msg.size()) == 0,
              "the genuine frame still opens after the forgery");
        ChanSessionClear(a); ChanSessionClear(b);
    }

    printf("replay_and_reorder_are_rejected\n");
    {
        ChanSession a, b;
        CHECK(Handshake(ep_pk, ep_sk, a, b), "fresh session");
        const std::string msg = "manda 1 btf";
        std::vector<unsigned char> f = ChanEncryptFrame(a, (const unsigned char*)msg.data(), msg.size());
        std::vector<unsigned char> pt;
        CHECK(ChanDecryptBody(b, &f[4], f.size() - 4, pt), "frame opens once");
        CHECK(!ChanDecryptBody(b, &f[4], f.size() - 4, pt), "the same frame again is refused");

        // Skipping ahead is refused too: frame 2 before frame 1 has no key.
        std::vector<unsigned char> f1 = ChanEncryptFrame(a, (const unsigned char*)msg.data(), msg.size());
        std::vector<unsigned char> f2 = ChanEncryptFrame(a, (const unsigned char*)msg.data(), msg.size());
        CHECK(!ChanDecryptBody(b, &f2[4], f2.size() - 4, pt), "out of order frame is refused");
        CHECK(ChanDecryptBody(b, &f1[4], f1.size() - 4, pt), "the expected frame still opens");
        ChanSessionClear(a); ChanSessionClear(b);
    }

    printf("wrong_endpoint_key_gets_nowhere\n");
    {
        // A relay in the middle answers with its own keys. The client believes
        // the .btf address, so it mixes the REAL static key into the schedule --
        // and ends up with a session the relay cannot open.
        unsigned char other_pk[32], other_sk[32];
        ChanKeypair(other_pk, other_sk);

        ChanSession cs2, es2;
        CHECK(Handshake(ep_pk, ep_sk, cs2, es2, other_pk),
              "handshake completes even against the wrong static key");
        CHECK(memcmp(cs2.ck_send, es2.ck_recv, 32) != 0,
              "the sessions do NOT match when the static key is wrong");
        CHECK(!Pass(cs2, es2, "isso nao pode chegar"),
              "a frame from the impostor's session does not open");
        ChanSessionClear(cs2); ChanSessionClear(es2);
    }

    printf("payload_edges\n");
    {
        ChanSession a, b;
        CHECK(Handshake(ep_pk, ep_sk, a, b), "fresh session");
        std::vector<unsigned char> f0 = ChanEncryptFrame(a, NULL, 0);
        std::vector<unsigned char> o0;
        CHECK(ChanDecryptBody(b, &f0[4], f0.size() - 4, o0) && o0.empty(),
              "empty payload roundtrips");
        std::vector<unsigned char> big(200 * 1024, 0xAB);
        std::vector<unsigned char> fb = ChanEncryptFrame(a, &big[0], big.size());
        std::vector<unsigned char> ob;
        CHECK(ChanDecryptBody(b, &fb[4], fb.size() - 4, ob) && ob == big,
              "200KB payload roundtrips");
        ChanSessionClear(a); ChanSessionClear(b);
    }

    printf("two_handshakes_share_nothing\n");
    {
        ChanSession a1, b1, a2, b2;
        CHECK(Handshake(ep_pk, ep_sk, a1, b1), "first session");
        CHECK(Handshake(ep_pk, ep_sk, a2, b2), "second session");
        // Same endpoint identity, yet no key material in common: this is the
        // property the old half-ephemeral handshake did not have.
        CHECK(memcmp(a1.ck_send, a2.ck_send, 32) != 0, "same endpoint, different session keys");
        CHECK(!Pass(a1, b2, "nao pode atravessar sessoes"), "a frame cannot cross sessions");
        ChanSessionClear(a1); ChanSessionClear(b1);
        ChanSessionClear(a2); ChanSessionClear(b2);
    }

    printf("sealed_envelopes_for_someone_who_is_offline\n");
    {
        // The recipient's epoch keys: one X25519 pair, one ML-KEM pair. Both
        // rotate, and that rotation is where forward secrecy comes from on this
        // path -- there is no second party online to contribute an ephemeral.
        unsigned char rx_pk[32], rx_sk[32];
        ChanKeypair(rx_pk, rx_sk);
        unsigned char rk_pk[CHAN_KEM_PUBBYTES], rk_sk[CHAN_KEM_SECBYTES];
        CHECK(ChanKemKeypair(rk_pk, rk_sk), "an epoch KEM keypair is generated");

        const char* msg = "mensagem deixada para quem nao esta online";
        std::vector<unsigned char> env;
        CHECK(ChanSealTo(rx_pk, rk_pk, (const unsigned char*)msg, strlen(msg), env),
              "the envelope seals");
        CHECK(env.size() == strlen(msg) + (size_t)CHAN_SEAL_OVERHEAD,
              "and costs exactly the documented overhead");

        std::vector<unsigned char> got;
        CHECK(ChanOpenSealed(rx_sk, rk_pk, rk_sk, &env[0], env.size(), got),
              "the recipient opens it");
        CHECK(got.size() == strlen(msg) && memcmp(&got[0], msg, strlen(msg)) == 0,
              "with the message intact");

        // No sender key is in there to find: the only public key on the wire is
        // a one-use ephemeral. Who wrote it is inside, signed, for the recipient.
        std::vector<unsigned char> env2;
        CHECK(ChanSealTo(rx_pk, rk_pk, (const unsigned char*)msg, strlen(msg), env2),
              "sealing the same message again works");
        CHECK(env2 != env, "and produces a completely different envelope");

        std::vector<unsigned char> e0, g0;
        CHECK(ChanSealTo(rx_pk, rk_pk, NULL, 0, e0) &&
              ChanOpenSealed(rx_sk, rk_pk, rk_sk, &e0[0], e0.size(), g0) && g0.empty(),
              "an empty payload roundtrips");
        std::vector<unsigned char> big(64 * 1024, 0x5A), eb, gb;
        CHECK(ChanSealTo(rx_pk, rk_pk, &big[0], big.size(), eb) &&
              ChanOpenSealed(rx_sk, rk_pk, rk_sk, &eb[0], eb.size(), gb) && gb == big,
              "a 64KB payload roundtrips");

        // Every byte is authenticated, header included: the header is the
        // associated data, so a ciphertext cannot be moved onto another one.
        for (size_t at = 0; at < 3; at++)
        {
            size_t idx = (at == 0) ? 0                       // ephemeral key
                       : (at == 1) ? 32                      // KEM ciphertext
                                   : env.size() - 1;         // tag
            std::vector<unsigned char> bad = env;
            bad[idx] ^= 1;
            std::vector<unsigned char> o;
            CHECK(!ChanOpenSealed(rx_sk, rk_pk, rk_sk, &bad[0], bad.size(), o),
                  at == 0 ? "a tampered ephemeral key is refused"
                          : at == 1 ? "a tampered KEM ciphertext is refused"
                                    : "a tampered tag is refused");
        }

        std::vector<unsigned char> o;
        CHECK(!ChanOpenSealed(rx_sk, rk_pk, rk_sk, &env[0], (size_t)CHAN_SEAL_OVERHEAD - 1, o),
              "a truncated envelope is refused");

        // Rotation: last epoch's envelope against this epoch's keys. Both halves
        // have to be the right ones, which is the point of mixing them.
        unsigned char nx_pk[32], nx_sk[32];
        ChanKeypair(nx_pk, nx_sk);
        unsigned char nk_pk[CHAN_KEM_PUBBYTES], nk_sk[CHAN_KEM_SECBYTES];
        CHECK(ChanKemKeypair(nk_pk, nk_sk), "the next epoch's keys are generated");
        CHECK(!ChanOpenSealed(nx_sk, rk_pk, rk_sk, &env[0], env.size(), o),
              "the wrong X25519 secret opens nothing");
        CHECK(!ChanOpenSealed(rx_sk, nk_pk, nk_sk, &env[0], env.size(), o),
              "the wrong KEM secret opens nothing either");
        CHECK(!ChanOpenSealed(nx_sk, nk_pk, nk_sk, &env[0], env.size(), o),
              "so an expired epoch cannot be read back");
        // Naming the wrong recipient key changes the derivation, even with the
        // right secrets: an envelope cannot be re-aimed.
        CHECK(!ChanOpenSealed(rx_sk, nk_pk, rk_sk, &env[0], env.size(), o),
              "a mismatched pair of recipient keys opens nothing");

        sodium_memzero(rx_sk, sizeof(rx_sk));
        sodium_memzero(rk_sk, sizeof(rk_sk));
        sodium_memzero(nx_sk, sizeof(nx_sk));
        sodium_memzero(nk_sk, sizeof(nk_sk));
    }

    ChanSessionClear(cs);
    ChanSessionClear(es);

    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
