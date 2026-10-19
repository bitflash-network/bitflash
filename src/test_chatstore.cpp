// Standalone tests for the chat records the nodes hold (chatstore.h): the wire
// form, the work, and every rule that decides what a node keeps.
//
// Build (UCRT64): see the test_chatstore.exe target in makefile.mingw.

#include "chatstore.h"
#include "btfchatbox.h"
#include "btfchat.h"
#include "btfchan.h"
#include "btfaddr.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

using namespace btfchat;

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

// Low enough that the store tests mine in microseconds. The real rule is
// exercised on its own below.
static const unsigned int TEST_BITS = 6;

static std::vector<unsigned char> Bytes(size_t n, unsigned char fill)
{
    return std::vector<unsigned char>(n, fill);
}

static ChatRecord Envelope(const std::vector<unsigned char>& tag, int64_t nTime,
                           size_t nPayload, unsigned char fill)
{
    ChatRecord r;
    r.kind = CHATREC_ENVELOPE;
    r.key = tag;
    r.nTime = nTime;
    r.payload = Bytes(nPayload, fill);
    ChatRecordMine(r, 0, TEST_BITS);
    return r;
}

static std::string Hex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}

static ChatRecord Desc(void* ctx, const Identity& id, int64_t created,
                       const std::string& onion)
{
    ChatRecord r;
    r.kind = CHATREC_DESC;
    unsigned char pk[32];
    btf::ParseAddress(id.address, pk);
    r.key.assign(pk, pk + 32);
    r.nTime = created;
    std::string d = btf::SignDescriptor(ctx, id.sign_sk, Hex(id.chan_pk, 32), "",
                                        (uint64_t)created, onion);
    r.payload.assign(d.begin(), d.end());
    ChatRecordMine(r, 0, TEST_BITS);
    return r;
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }
    if (!btf::ChanInit())  { printf("ChanInit failed\n"); return 1; }

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    std::string err;
    Identity alice, bob;
    {
        std::vector<unsigned char> s(64, 0x33);
        if (!DeriveIdentityFromSeed(s, "senha-bem-comprida", alice, err))
        { printf("alice: %s\n", err.c_str()); return 1; }
        s.assign(64, 0x44);
        if (!DeriveIdentityFromSeed(s, "senha-bem-comprida", bob, err))
        { printf("bob: %s\n", err.c_str()); return 1; }
    }

    const int64_t NOW = 1790000000;
    const std::string ONION =
        "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8533";
    unsigned char id[32];

    printf("the_wire_form_round_trips_and_refuses_what_does_not_fit\n");
    {
        ChatRecord r = Envelope(Bytes(16, 0xab), NOW, 300, 0x5a);
        std::vector<unsigned char> w = r.Serialize();
        ChatRecord back;
        CHECK(back.Parse(&w[0], w.size()), "a record parses back");
        CHECK(back.kind == r.kind && back.key == r.key && back.nTime == r.nTime &&
              back.payload == r.payload && back.nNonce == r.nNonce,
              "into exactly the same fields");
        CHECK(back.IdHex() == r.IdHex(), "with the same id");

        CHECK(!back.Parse(&w[0], w.size() - 1), "one byte short is refused");
        std::vector<unsigned char> longer = w;
        longer.push_back(0);
        CHECK(!back.Parse(&longer[0], longer.size()), "one byte of trailing junk is refused");
        std::vector<unsigned char> other = w;
        other[0] = 2;
        CHECK(!back.Parse(&other[0], other.size()), "another wire version is refused, not misread");
        std::vector<unsigned char> bigkey = w;
        bigkey[2] = 200;
        CHECK(!back.Parse(&bigkey[0], bigkey.size()), "a key length past what a key can be is refused");
        // Claim a payload far past the cap, in a buffer that does not have it.
        std::vector<unsigned char> liar = w;
        size_t at = 3 + 16 + 16;
        liar[at] = 0xff; liar[at + 1] = 0xff; liar[at + 2] = 0xff; liar[at + 3] = 0x7f;
        CHECK(!back.Parse(&liar[0], liar.size()), "a payload length that lies is refused");
        CHECK(!back.Parse(NULL, 0), "nothing at all is refused");
    }

    printf("the_id_commits_to_every_field\n");
    {
        ChatRecord r = Envelope(Bytes(16, 1), NOW, 100, 7);
        std::string base = r.IdHex();
        ChatRecord t;
        t = r; t.kind = CHATREC_DESC;       CHECK(t.IdHex() != base, "the kind");
        t = r; t.key[0] ^= 1;               CHECK(t.IdHex() != base, "the key");
        t = r; t.nTime++;                   CHECK(t.IdHex() != base, "the time");
        t = r; t.payload[99] ^= 1;          CHECK(t.IdHex() != base, "the last payload byte");
        t = r; t.nNonce++;                  CHECK(t.IdHex() != base, "the nonce");
    }

    printf("the_work_scales_with_size\n");
    {
        CHECK(ChatRecordBitsFor(100) == CHATREC_BASE_BITS, "a small record pays the base");
        CHECK(ChatRecordBitsFor(4096) == CHATREC_BASE_BITS, "up to 4 KB");
        CHECK(ChatRecordBitsFor(4097) == CHATREC_BASE_BITS + 1, "one bit more past it");
        CHECK(ChatRecordBitsFor(CHATREC_MAX_PAYLOAD) == CHATREC_BASE_BITS + 4,
              "and 64 KB costs sixteen times a small one");
    }

    printf("real_work_is_paid_and_checked\n");
    {
        ChatRecord r;
        r.kind = CHATREC_ENVELOPE;
        r.key = Bytes(16, 9);
        r.nTime = NOW;
        r.payload = Bytes(1000, 3);
        clock_t c0 = clock();
        CHECK(ChatRecordMine(r), "a record mines at the real difficulty");
        double secs = double(clock() - c0) / CLOCKS_PER_SEC;
        printf("       (%.2f s of CPU)\n", secs);
        CHECK(ChatRecordHasWork(r), "and passes the real check");
        CHECK(ChatRecordWork(r) >= CHATREC_BASE_BITS, "with the bits it claims");
        r.payload[0] ^= 1;
        CHECK(!ChatRecordHasWork(r), "changing the payload after mining voids the work");

        ChatRecord cheap = Envelope(Bytes(16, 9), NOW, 1000, 3);
        // A 6-bit record is overwhelmingly unlikely to clear 20 by luck; if it
        // did, this would be the one-in-a-quarter-million run that says so.
        CHECK(!ChatRecordHasWork(cheap) || ChatRecordWork(cheap) >= CHATREC_BASE_BITS,
              "a record mined for the test rule does not pass the real one");

        volatile bool fStop = true;
        ChatRecord a = r;
        CHECK(!ChatRecordMine(a, &fStop), "mining stops when asked to");
    }

    printf("envelopes_are_kept_queried_and_capped\n");
    {
        ChatStore st(TEST_BITS);
        std::vector<unsigned char> tag = Bytes(16, 0x10);
        ChatRecord e1 = Envelope(tag, NOW - 100, 200, 1);
        CHECK(st.Accept(ctx, e1, NOW, err, id) == ChatStore::ACCEPTED, "a fresh envelope is kept");
        CHECK(st.Has(id), "and can be found by its id");
        CHECK(st.Accept(ctx, e1, NOW, err, id) == ChatStore::DUPLICATE, "the same one again is a duplicate");

        ChatRecord e2 = Envelope(tag, NOW - 50, 200, 2);
        st.Accept(ctx, e2, NOW, err, id);
        std::vector<ChatRecord> q;
        st.Query(CHATREC_ENVELOPE, tag, 0, 64, q);
        CHECK(q.size() == 2 && q[0].nTime == NOW - 100 && q[1].nTime == NOW - 50,
              "a query returns them oldest first");
        st.Query(CHATREC_ENVELOPE, tag, NOW - 60, 64, q);
        CHECK(q.size() == 1 && q[0].nTime == NOW - 50, "and 'since' leaves out what was already seen");
        st.Query(CHATREC_ENVELOPE, Bytes(16, 0x11), 0, 64, q);
        CHECK(q.empty(), "another tag sees none of it");

        ChatRecord fut = Envelope(tag, NOW + CHATREC_MAX_FUTURE + 10, 50, 3);
        CHECK(st.Accept(ctx, fut, NOW, err, id) == ChatStore::REJECTED, "a record from the future is refused");
        CHECK(err.find("future") != std::string::npos, "  because of its time");
        ChatRecord old = Envelope(tag, NOW - CHATREC_ENVELOPE_LIFETIME - 10, 50, 4);
        CHECK(st.Accept(ctx, old, NOW, err, id) == ChatStore::REJECTED, "an expired one is refused");
        CHECK(err.find("expired") != std::string::npos, "  because it expired");

        ChatRecord lazy = e2;
        lazy.payload[0] ^= 0x80;   // new content, no new work
        // At six bits one nonce in 64 pays by accident; step off any that does,
        // so this tests the refusal and not the dice.
        while (ChatRecordHasWork(lazy, TEST_BITS))
            lazy.nNonce++;
        CHECK(st.Accept(ctx, lazy, NOW, err, id) == ChatStore::REJECTED,
              "one without the work is refused");
        CHECK(err.find("proof of work") != std::string::npos, "  because of the work");

        ChatRecord badKey = e1;
        badKey.key.resize(32);
        ChatRecordMine(badKey, 0, TEST_BITS);
        CHECK(st.Accept(ctx, badKey, NOW, err, id) == ChatStore::REJECTED,
              "an envelope under an identity-sized key is refused");

        ChatRecord unknown = e1;
        unknown.kind = 9;
        ChatRecordMine(unknown, 0, TEST_BITS);
        CHECK(st.Accept(ctx, unknown, NOW, err, id) == ChatStore::REJECTED, "an unknown kind is refused");

        // Fill one tag to its cap.
        ChatStore full(TEST_BITS);
        std::vector<unsigned char> t2 = Bytes(16, 0x22);
        for (size_t i = 0; i < CHATREC_MAX_PER_TAG; i++)
            full.Accept(ctx, Envelope(t2, NOW - 1000 + (int64_t)i, 40, (unsigned char)i), NOW, err, id);
        full.Query(CHATREC_ENVELOPE, t2, 0, 1000, q);
        CHECK(q.size() == CHATREC_MAX_PER_TAG, "a tag holds up to its cap");
        CHECK(full.Accept(ctx, Envelope(t2, NOW - 2000, 40, 0xee), NOW, err, id) == ChatStore::REJECTED,
              "past it, one older than all of them is refused");
        CHECK(full.Accept(ctx, Envelope(t2, NOW, 40, 0xef), NOW, err, id) == ChatStore::ACCEPTED,
              "a newer one is kept");
        full.Query(CHATREC_ENVELOPE, t2, 0, 1000, q);
        CHECK(q.size() == CHATREC_MAX_QUERY && q[0].nTime == NOW - 999,
              "by dropping the oldest, and a query still returns at most its cap");

        CHECK(st.Expire(NOW + CHATREC_ENVELOPE_LIFETIME + 1000) == 2, "expiry drops both after their lifetime");
        CHECK(st.Count() == 0 && st.Bytes(CHATREC_ENVELOPE) == 0, "and accounts the memory back");
    }

    printf("a_full_store_refuses_new_records_and_keeps_what_it_holds\n");
    {
        ChatStore st(TEST_BITS);
        size_t nEach = CHATREC_MAX_PAYLOAD;
        size_t n = CHATREC_ENVELOPE_BUDGET / nEach + 8;
        size_t nKept = 0, nRefusedFull = 0;
        for (size_t i = 0; i < n; i++)
        {
            std::vector<unsigned char> tag = Bytes(16, 0);
            tag[0] = (unsigned char)i; tag[1] = (unsigned char)(i >> 8);
            ChatStore::Result res = st.Accept(ctx, Envelope(tag, NOW - 10000 + (int64_t)i, nEach, (unsigned char)i),
                                              NOW, err, id);
            if (res == ChatStore::ACCEPTED) nKept++;
            else if (err.find("full") != std::string::npos) nRefusedFull++;
        }
        CHECK(st.Bytes(CHATREC_ENVELOPE) <= CHATREC_ENVELOPE_BUDGET, "the store never goes over budget");
        CHECK(nKept > 0 && nRefusedFull > 0 && nKept + nRefusedFull == n,
              "once full, every further record is refused as 'full' -- none is silently dropped");
        std::vector<unsigned char> first = Bytes(16, 0), last = Bytes(16, 0);
        last[0] = (unsigned char)(n - 1); last[1] = (unsigned char)((n - 1) >> 8);
        std::vector<ChatRecord> q;
        st.Query(CHATREC_ENVELOPE, first, 0, 64, q);
        CHECK(q.size() == 1, "the first envelope held is still held: a flood erases nothing");
        st.Query(CHATREC_ENVELOPE, last, 0, 64, q);
        CHECK(q.empty(), "the one that did not fit was the one refused");

        // Expiry is what makes room again.
        st.Expire(NOW + CHATREC_ENVELOPE_LIFETIME - 10000 + 5);
        CHECK(st.Accept(ctx, Envelope(last, NOW + CHATREC_ENVELOPE_LIFETIME - 9000, 100, 1),
                        NOW + CHATREC_ENVELOPE_LIFETIME - 9000, err, id) == ChatStore::ACCEPTED,
              "and once the oldest expire, new records fit again");
    }

    printf("a_full_identity_store_still_lets_an_identity_replace_its_own\n");
    {
        // A flood of new identities must not stop an existing one from
        // publishing its next descriptor: replacing frees the old one's room.
        ChatStore st(TEST_BITS);
        ChatRecord d1 = Desc(ctx, alice, NOW - 3600, ONION);
        CHECK(st.Accept(ctx, d1, NOW, err, id) == ChatStore::ACCEPTED, "alice is held");
        // Throwaway identities straight from random keys: deriving them from a
        // phrase stretches a password each time, and thousands of those would
        // take minutes to test one rule.
        size_t nFill = 0;
        ChatStore::Result res = ChatStore::ACCEPTED;
        for (int i = 0; i < 50000 && res != ChatStore::REJECTED; i++)
        {
            unsigned char sk[32];
            do { randombytes_buf(sk, 32); } while (!secp256k1_ec_seckey_verify(ctx, sk));
            secp256k1_keypair kp;
            secp256k1_xonly_pubkey xp;
            unsigned char pk[32];
            secp256k1_keypair_create(ctx, &kp, sk);
            secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp);
            secp256k1_xonly_pubkey_serialize(ctx, pk, &xp);
            ChatRecord r;
            r.kind = CHATREC_DESC;
            r.key.assign(pk, pk + 32);
            r.nTime = NOW - 100;
            std::string d = btf::SignDescriptor(ctx, sk, std::string(64, 'a'), "", (uint64_t)r.nTime, ONION);
            r.payload.assign(d.begin(), d.end());
            ChatRecordMine(r, 0, TEST_BITS);
            res = st.Accept(ctx, r, NOW, err, id);
            if (res == ChatStore::ACCEPTED)
                nFill++;
        }
        CHECK(res == ChatStore::REJECTED && err.find("full") != std::string::npos,
              "with the budget spent, a new identity is refused");
        ChatRecord d2 = Desc(ctx, alice, NOW - 60, ONION);
        CHECK(st.Accept(ctx, d2, NOW, err, id) == ChatStore::ACCEPTED,
              "but alice can still replace her own descriptor");
        printf("       (%u descriptors to fill %u bytes)\n", (unsigned)nFill, (unsigned)CHATREC_DESC_BUDGET);
    }

    printf("descriptors_must_be_signed_by_their_key_and_newest_wins\n");
    {
        ChatStore st(TEST_BITS);
        ChatRecord d1 = Desc(ctx, alice, NOW - 3600, ONION);
        CHECK(st.Accept(ctx, d1, NOW, err, id) == ChatStore::ACCEPTED, "alice's descriptor is kept");

        ChatRecord forged = Desc(ctx, bob, NOW - 100, ONION);
        forged.key = d1.key;            // bob's signature, filed under alice
        ChatRecordMine(forged, 0, TEST_BITS);
        CHECK(st.Accept(ctx, forged, NOW, err, id) == ChatStore::REJECTED,
              "a descriptor signed by somebody else is refused");
        CHECK(err.find("not signed by the key") != std::string::npos, "  because of the signature");

        ChatRecord rewrapped = d1;
        rewrapped.nTime = NOW - 10;     // old signed content, newer record time
        ChatRecordMine(rewrapped, 0, TEST_BITS);
        CHECK(st.Accept(ctx, rewrapped, NOW, err, id) == ChatStore::REJECTED,
              "an old descriptor cannot be made to look new");
        CHECK(err.find("signed time") != std::string::npos, "  because the time is not the signed one");

        ChatRecord noOnion = Desc(ctx, alice, NOW - 50, "");
        CHECK(st.Accept(ctx, noOnion, NOW, err, id) == ChatStore::REJECTED,
              "a descriptor with nowhere to reach is refused");
        CHECK(err.find("no onion") != std::string::npos, "  because it names no onion");

        ChatRecord d2 = Desc(ctx, alice, NOW - 60, ONION);
        CHECK(st.Accept(ctx, d2, NOW, err, id) == ChatStore::ACCEPTED, "a newer one is kept");
        std::vector<ChatRecord> q;
        st.Query(CHATREC_DESC, d1.key, 0, 64, q);
        CHECK(q.size() == 1 && q[0].nTime == NOW - 60, "and replaces the old one");
        CHECK(st.Count() == 1, "which is gone, not kept alongside");
        CHECK(st.Accept(ctx, d1, NOW, err, id) == ChatStore::DUPLICATE,
              "the older one arriving late changes nothing");
        st.Query(CHATREC_DESC, d1.key, 0, 64, q);
        CHECK(q.size() == 1 && q[0].nTime == NOW - 60, "the newest is still the one held");

        std::string why;
        CHECK(ChatRecordVerifySigned(ctx, q[0], NOW, why), "what a node answers verifies for the client too");
    }

    printf("epoch_keys_must_be_signed_and_dated_by_their_epoch\n");
    {
        ChatStore st(TEST_BITS);
        Mailbox mb;
        mb.Rotate(NOW, err);
        EpochKeys pub;
        pub.epoch = MailboxEpoch(NOW);
        mb.PublicFor(pub.epoch, pub.x_pk, pub.kem_pk);
        std::string ann;
        CHECK(SignEpochKeys(ctx, alice, pub, ann, err), "alice signs her epoch keys");

        ChatRecord r;
        r.kind = CHATREC_EPOCH;
        unsigned char pk[32];
        btf::ParseAddress(alice.address, pk);
        r.key.assign(pk, pk + 32);
        r.nTime = pub.epoch * MAILBOX_EPOCH_SECONDS;
        r.payload.assign(ann.begin(), ann.end());
        ChatRecordMine(r, 0, TEST_BITS);
        CHECK(st.Accept(ctx, r, NOW, err, id) == ChatStore::ACCEPTED, "and a node keeps them");
        CHECK(r.payload.size() > 1000 && ChatRecordBitsFor(r.payload.size()) == CHATREC_BASE_BITS,
              "a post-quantum announcement still fits the base work");

        ChatRecord shifted = r;
        shifted.nTime += 1;
        ChatRecordMine(shifted, 0, TEST_BITS);
        CHECK(st.Accept(ctx, shifted, NOW, err, id) == ChatStore::REJECTED,
              "a record time that is not the epoch's start is refused");
        CHECK(err.find("start of the signed epoch") != std::string::npos, "  because of the time");

        ChatRecord elsewhere = r;
        unsigned char bpk[32];
        btf::ParseAddress(bob.address, bpk);
        elsewhere.key.assign(bpk, bpk + 32);
        ChatRecordMine(elsewhere, 0, TEST_BITS);
        CHECK(st.Accept(ctx, elsewhere, NOW, err, id) == ChatStore::REJECTED,
              "alice's keys filed under bob are refused");
        CHECK(err.find("different address") != std::string::npos, "  because the address does not match");
    }

    printf("ids_are_offered_newest_first\n");
    {
        ChatStore st(TEST_BITS);
        for (int i = 0; i < 5; i++)
            st.Accept(ctx, Envelope(Bytes(16, (unsigned char)(0x40 + i)), NOW - 500 + i * 10, 30, 1), NOW, err, id);
        std::vector<std::vector<unsigned char> > ids;
        st.Ids(3, ids);
        CHECK(ids.size() == 3, "at most what was asked for");
        ChatRecord newest;
        unsigned char raw[32];
        memcpy(raw, &ids[0][0], 32);
        CHECK(st.Get(raw, newest) && newest.nTime == NOW - 460, "the first is the newest");
    }

    secp256k1_context_destroy(ctx);
    IdentityClear(alice);
    IdentityClear(bob);

    if (g_fail)
    {
        printf("%d FAILURE(S)\n", g_fail);
        return 1;
    }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
