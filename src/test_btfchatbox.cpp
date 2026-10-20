// Standalone tests for the btfchat mailbox -- epoch tags, epoch key rotation,
// sealed envelopes and signed epoch announcements.
//
// Build (UCRT64):
//   g++ -std=gnu++14 -DSECP256K1_STATIC -I../deps/include test_btfchatbox.cpp \
//       btfchatbox.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o \
//       bip32.cpp btfaddr.cpp -L../deps/lib -lsecp256k1 -lsodium -lssl -lcrypto \
//       -o test_btfchatbox.exe

#include "btfchatbox.h"
#include "btfchatmsg.h"
#include "btfchat.h"
#include "btfchan.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using json = nlohmann::json;

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static const int64_t DAY = btfchat::MAILBOX_EPOCH_SECONDS;

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }
    if (!btf::ChanInit())  { printf("ChanInit failed\n"); return 1; }

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char rnd[32];
    randombytes_buf(rnd, sizeof(rnd));
    if (!secp256k1_context_randomize(ctx, rnd)) { printf("blinding failed\n"); return 1; }

    std::string err;
    btfchat::Identity alice, bob;
    {
        std::vector<unsigned char> s(64, 0x33);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", alice, err))
        { printf("alice: %s\n", err.c_str()); return 1; }
        s.assign(64, 0x44);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", bob, err))
        { printf("bob: %s\n", err.c_str()); return 1; }
    }

    // A fixed instant well inside an epoch, so the arithmetic below is readable.
    const int64_t NOW = 1790000000;
    const int64_t E   = btfchat::MailboxEpoch(NOW);

    printf("epochs_are_whole_days\n");
    {
        CHECK(btfchat::MailboxEpoch(0) == 0, "time zero is epoch zero");
        CHECK(btfchat::MailboxEpoch(DAY - 1) == 0, "one second before the day ends");
        CHECK(btfchat::MailboxEpoch(DAY) == 1, "and the next second is the next epoch");
        CHECK(btfchat::MailboxEpoch(-5) == 0, "a negative clock does not go negative");
    }

    printf("the_tag_is_shared_by_the_pair_and_nobody_else\n");
    {
        std::string tagA, tagB;
        CHECK(btfchat::MailboxTag(alice.chan_sk, bob.chan_pk, E, tagA),
              "alice computes the tag from her secret and bob's key");
        CHECK(btfchat::MailboxTag(bob.chan_sk, alice.chan_pk, E, tagB),
              "bob computes it from his secret and alice's key");
        CHECK(tagA == tagB, "and they get the same tag without exchanging anything");
        CHECK(tagA.size() == btfchat::MAILBOX_TAG_BYTES * 2, "32 hex characters");

        // The relay sees the tag and nothing else. It must not be able to tell
        // that two tags belong to the same pair.
        std::string tagNext;
        CHECK(btfchat::MailboxTag(alice.chan_sk, bob.chan_pk, E + 1, tagNext),
              "next epoch has its own tag");
        CHECK(tagNext != tagA, "which looks unrelated to this one");

        // And a third party cannot compute it even knowing both addresses.
        btfchat::Identity eve;
        std::vector<unsigned char> s(64, 0x55);
        CHECK(btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", eve, err),
              "eve has her own identity");
        std::string tagEve;
        CHECK(btfchat::MailboxTag(eve.chan_sk, bob.chan_pk, E, tagEve),
              "eve can compute HER tag with bob");
        CHECK(tagEve != tagA, "but it is not the one alice and bob share");

        // A degenerate peer key has no shared secret to key a tag with.
        unsigned char zero[32];
        memset(zero, 0, sizeof(zero));
        std::string tagZero;
        CHECK(!btfchat::MailboxTag(alice.chan_sk, zero, E, tagZero),
              "an all-zero peer key is refused");
    }

    printf("epoch_keys_rotate_and_old_ones_are_destroyed\n");
    {
        btfchat::Mailbox mb;
        CHECK(mb.LiveEpochs() == 0, "a fresh mailbox holds nothing");
        CHECK(mb.Rotate(NOW, err), "rotating creates this epoch's keys");
        CHECK(mb.Has(E) && mb.LiveEpochs() == 1, "one epoch is live");

        unsigned char x1[32], k1[btf::CHAN_KEM_PUBBYTES];
        CHECK(mb.PublicFor(E, x1, k1), "its public halves are available");
        CHECK(!mb.PublicFor(E + 1, x1, k1), "a future epoch has none yet");

        CHECK(mb.Rotate(NOW + 60, err), "rotating again inside the same epoch");
        CHECK(mb.LiveEpochs() == 1, "does not make a second set");
        unsigned char x1b[32], k1b[btf::CHAN_KEM_PUBBYTES];
        CHECK(mb.PublicFor(E, x1b, k1b) && memcmp(x1, x1b, 32) == 0,
              "and does not replace the keys under us");

        CHECK(mb.Rotate(NOW + DAY, err), "the next day rotates");
        CHECK(mb.LiveEpochs() == btfchat::MAILBOX_KEEP_EPOCHS,
              "and we keep exactly the documented number of epochs");
        CHECK(mb.Has(E) && mb.Has(E + 1), "this epoch and the one before it");

        CHECK(mb.Rotate(NOW + 2 * DAY, err), "a day later again");
        CHECK(mb.LiveEpochs() == btfchat::MAILBOX_KEEP_EPOCHS && !mb.Has(E),
              "and the oldest is gone");
    }

    printf("a_message_waits_for_someone_offline\n");
    std::string frameJson;
    {
        // Alice writes to bob, who is not there. The frame is signed as usual --
        // the envelope is what makes it anonymous to whoever holds it.
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT;
        f.sent = NOW;
        f.text = "te procurei, me chama quando puder";
        CHECK(btfchat::SignFrame(ctx, alice, f, frameJson, err), "alice signs the frame");

        btfchat::Mailbox bobBox;
        CHECK(bobBox.Rotate(NOW, err), "bob's mailbox has keys for this epoch");
        unsigned char bx[32], bk[btf::CHAN_KEM_PUBBYTES];
        CHECK(bobBox.PublicFor(E, bx, bk), "and publishes them");

        std::vector<unsigned char> env;
        CHECK(btfchat::SealEnvelope(bx, bk, frameJson, env, err), "alice seals the envelope");
        CHECK(env.size() == frameJson.size() + (size_t)btf::CHAN_SEAL_OVERHEAD,
              "at the documented overhead");

        // Nothing in the envelope says who wrote it.
        std::string blob((const char*)&env[0], env.size());
        CHECK(blob.find(alice.address) == std::string::npos, "alice's address is not in it");
        CHECK(blob.find("te procurei") == std::string::npos, "nor the message");

        std::vector<unsigned char> got;
        CHECK(bobBox.Open(&env[0], env.size(), got, err), "bob opens it");
        std::string back((const char*)&got[0], got.size());
        CHECK(back == frameJson, "and gets the frame back byte for byte");

        btfchat::Frame g;
        CHECK(btfchat::OpenFrame(ctx, back, g, err), "the frame still verifies");
        CHECK(g.from == alice.address && g.text == "te procurei, me chama quando puder",
              "and it says who wrote it, provably");

        // An envelope alice posted under a tag she shares with bob: she cannot
        // open her own, which is exactly how the shared tag stays workable.
        btfchat::Mailbox aliceBox;
        CHECK(aliceBox.Rotate(NOW, err), "alice has a mailbox too");
        CHECK(!aliceBox.Open(&env[0], env.size(), got, err),
              "she cannot open the envelope she posted");
        CHECK(err.find("no epoch key") != std::string::npos, "it simply is not hers");

        // Rotation is what ends it. Two days on, bob's own keys are gone.
        CHECK(bobBox.Rotate(NOW + 2 * DAY, err), "two days pass");
        CHECK(!bobBox.Open(&env[0], env.size(), got, err),
              "and the envelope is unreadable even by bob");
    }

    printf("envelope_limits\n");
    {
        btfchat::Mailbox mb;
        CHECK(mb.Rotate(NOW, err), "a mailbox with keys");
        unsigned char x[32], k[btf::CHAN_KEM_PUBBYTES];
        CHECK(mb.PublicFor(E, x, k), "public halves");

        std::vector<unsigned char> env;
        CHECK(!btfchat::SealEnvelope(x, k, "", env, err), "an empty frame is not sealed");
        std::string huge(btfchat::MAX_ENVELOPE_BYTES, 'x');
        CHECK(!btfchat::SealEnvelope(x, k, huge, env, err), "an oversized frame is not sealed");

        std::vector<unsigned char> got;
        unsigned char tiny[4] = {0, 0, 0, 0};
        CHECK(!mb.Open(tiny, sizeof(tiny), got, err), "a short envelope is refused");
        std::vector<unsigned char> big(btfchat::MAX_ENVELOPE_BYTES + 1, 0);
        CHECK(!mb.Open(&big[0], big.size(), got, err), "an oversized envelope is refused");
        CHECK(err.find("too big") != std::string::npos, "for its size, before any crypto");

        CHECK(btfchat::SealEnvelope(x, k, "{\"a\":1}", env, err), "a small frame seals");
        std::vector<unsigned char> bad = env;
        bad[bad.size() - 1] ^= 1;
        CHECK(!mb.Open(&bad[0], bad.size(), got, err), "a tampered envelope is refused");
    }

    // ---- published epoch keys ----------------------------------------------

    printf("epoch_keys_are_published_signed\n");
    {
        btfchat::Mailbox mb;
        CHECK(mb.Rotate(NOW, err), "bob rotates");
        btfchat::EpochKeys pub;
        pub.epoch = E;
        CHECK(mb.PublicFor(E, pub.x_pk, pub.kem_pk), "and takes his public halves");

        std::string ann;
        CHECK(btfchat::SignEpochKeys(ctx, bob, pub, ann, err), "he signs the announcement");

        int64_t gotEpoch = 0;
        unsigned char gx[32], gk[btf::CHAN_KEM_PUBBYTES];
        CHECK(btfchat::VerifyEpochKeys(ctx, bob.address, ann, NOW, gotEpoch, gx, gk, err),
              "alice verifies it against bob's address");
        CHECK(gotEpoch == E && memcmp(gx, pub.x_pk, 32) == 0 &&
              memcmp(gk, pub.kem_pk, btf::CHAN_KEM_PUBBYTES) == 0,
              "and gets the keys she will seal to");

        // Asking for bob and being handed a valid announcement for someone else
        // is the relay substituting a recipient. It must not pass.
        CHECK(!btfchat::VerifyEpochKeys(ctx, alice.address, ann, NOW, gotEpoch, gx, gk, err),
              "an announcement for bob does not pass as alice's");

        // The relay swapping its own keys in is the full man in the middle on
        // every offline message. The signature is the only thing that stops it.
        json j = json::parse(ann);
        unsigned char ex[32], esk[32];
        btf::ChanKeypair(ex, esk);
        j["x"] = json::parse(ann)["x"];
        std::string hexEx;
        {
            static const char* h = "0123456789abcdef";
            for (int i = 0; i < 32; i++) { hexEx += h[ex[i] >> 4]; hexEx += h[ex[i] & 0x0f]; }
        }
        j["x"] = hexEx;
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, j.dump(), NOW, gotEpoch, gx, gk, err),
              "a relay swapping the X25519 key is caught");

        j = json::parse(ann);
        j["kem"] = std::string(btf::CHAN_KEM_PUBBYTES * 2, '0');
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, j.dump(), NOW, gotEpoch, gx, gk, err),
              "swapping the ML-KEM key is caught too");

        j = json::parse(ann);
        j["sig"] = std::string(128, '0');
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, j.dump(), NOW, gotEpoch, gx, gk, err),
              "a made-up signature is caught");

        j = json::parse(ann);
        j["v"] = 2;
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, j.dump(), NOW, gotEpoch, gx, gk, err),
              "an unknown announcement version is refused");
    }

    printf("a_stale_announcement_is_refused\n");
    {
        btfchat::Mailbox mb;
        CHECK(mb.Rotate(NOW, err), "bob rotates today");
        btfchat::EpochKeys pub;
        pub.epoch = E;
        CHECK(mb.PublicFor(E, pub.x_pk, pub.kem_pk), "his keys");
        std::string ann;
        CHECK(btfchat::SignEpochKeys(ctx, bob, pub, ann, err), "he signs today's announcement");

        int64_t gotEpoch = 0;
        unsigned char gx[32], gk[btf::CHAN_KEM_PUBBYTES];
        CHECK(btfchat::VerifyEpochKeys(ctx, bob.address, ann, NOW + DAY, gotEpoch, gx, gk, err),
              "yesterday's announcement is still usable today");
        // Sealing to keys whose secrets are already destroyed loses the message
        // silently, so an old announcement has to be refused, signature or not.
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, ann, NOW + 3 * DAY, gotEpoch, gx, gk, err),
              "a three-day-old announcement is refused");
        CHECK(err.find("not current") != std::string::npos, "for being stale");
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, ann, NOW - 3 * DAY, gotEpoch, gx, gk, err),
              "and one from the future is refused as well");

        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, "{", NOW, gotEpoch, gx, gk, err),
              "broken JSON is refused");
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, "", NOW, gotEpoch, gx, gk, err),
              "an empty announcement is refused");
        std::string huge(9000, 'x');
        CHECK(!btfchat::VerifyEpochKeys(ctx, bob.address, huge, NOW, gotEpoch, gx, gk, err),
              "an oversized announcement is refused before parsing");
    }

    printf("the_whole_offline_path_end_to_end\n");
    {
        // Alice and bob have accepted each other. Bob goes offline. Alice leaves
        // a message under the tag they share, bob comes back and reads it, and
        // nothing about the relay's copy tells the relay who either of them is.
        btfchat::Roster bobRoster;
        CHECK(bobRoster.NoteIncomingInvite(alice.address, "oi", NOW, err), "alice invited bob");
        CHECK(bobRoster.AcceptInvite(alice.address, err), "bob accepted");

        btfchat::Mailbox bobBox;
        CHECK(bobBox.Rotate(NOW, err), "bob's epoch keys exist");
        btfchat::EpochKeys pub;
        pub.epoch = E;
        CHECK(bobBox.PublicFor(E, pub.x_pk, pub.kem_pk), "and he published them");
        std::string ann;
        CHECK(btfchat::SignEpochKeys(ctx, bob, pub, ann, err), "signed");

        // Alice's side: verify, seal, and work out where to post.
        int64_t gotEpoch = 0;
        unsigned char bx[32], bk[btf::CHAN_KEM_PUBBYTES];
        CHECK(btfchat::VerifyEpochKeys(ctx, bob.address, ann, NOW, gotEpoch, bx, bk, err),
              "alice verifies bob's epoch keys");
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.sent = NOW; f.text = "deixei recado";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "she signs the frame");
        std::vector<unsigned char> env;
        CHECK(btfchat::SealEnvelope(bx, bk, js, env, err), "seals it to his epoch keys");
        std::string tagPost;
        CHECK(btfchat::MailboxTag(alice.chan_sk, bob.chan_pk, gotEpoch, tagPost),
              "and computes the tag to post under");

        // Bob's side: poll the same tag, open, then the gate and the replay table.
        std::string tagPoll;
        CHECK(btfchat::MailboxTag(bob.chan_sk, alice.chan_pk, E, tagPoll), "bob polls his side");
        CHECK(tagPoll == tagPost, "which is the same tag");

        // The trap this test walked past for a long time: bx, the key the
        // envelope is SEALED to, is sitting right there in the same function and
        // is exactly the wrong size and shape to notice. The node passed it to
        // MailboxTag as well, so every offline message was filed under a name
        // the other side never reads -- and the sender reported success, because
        // posting to a tag nobody listens to works perfectly.
        std::string tagWrong;
        CHECK(btfchat::MailboxTag(alice.chan_sk, bx, gotEpoch, tagWrong),
              "a tag computed from bob's EPOCH key succeeds");
        CHECK(tagWrong != tagPoll,
              "but names a different mailbox: sealing keys are not naming keys");

        std::vector<unsigned char> got;
        CHECK(bobBox.Open(&env[0], env.size(), got, err), "he opens the envelope");
        btfchat::Frame g;
        std::string back((const char*)&got[0], got.size());
        CHECK(btfchat::OpenFrame(ctx, back, g, err), "the frame verifies");
        CHECK(bobRoster.MayDeliver(g.from, g.kind, err), "the gate lets it in: she is accepted");
        btfchat::ReplayGuard rg;
        CHECK(rg.Accept(g, NOW, err), "first delivery");
        // The relay kept a copy. Handing it back is not a second message.
        CHECK(!rg.Accept(g, NOW, err), "the relay's copy replayed is dropped");
        CHECK(g.text == "deixei recado", "and the message reads correctly");

        // A stranger who found the tag can post to it, and gets nowhere: the
        // envelope opens, but the gate refuses an unknown sender's message.
        btfchat::Identity eve;
        std::vector<unsigned char> s(64, 0x66);
        CHECK(btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", eve, err), "eve exists");
        btfchat::Frame ef;
        ef.kind = btfchat::MSG_TEXT; ef.sent = NOW; ef.text = "clique aqui";
        std::string ejs;
        CHECK(btfchat::SignFrame(ctx, eve, ef, ejs, err), "eve signs a message");
        std::vector<unsigned char> eenv;
        CHECK(btfchat::SealEnvelope(bx, bk, ejs, eenv, err), "and seals it to bob's keys");
        CHECK(bobBox.Open(&eenv[0], eenv.size(), got, err), "bob can open it");
        back.assign((const char*)&got[0], got.size());
        CHECK(btfchat::OpenFrame(ctx, back, g, err), "it is a valid frame");
        CHECK(!bobRoster.MayDeliver(g.from, g.kind, err),
              "and the gate refuses it: she was never accepted");
    }

    printf("the_mailbox_survives_closing_the_app\n");
    {
        // What a tester found: a message left while the app was closed never
        // arrived, because the epoch keys it was sealed to died with the
        // session. They now go in the sealed store and come back with it.
        const int64_t NOW = 1792500000, DAY = 86400;
        std::string err;
        btfchat::Mailbox before;
        CHECK(before.Rotate(NOW, err), "bob opens the app: this epoch's keys");
        unsigned char x[32], k[btf::CHAN_KEM_PUBBYTES];
        CHECK(before.PublicFor(btfchat::MailboxEpoch(NOW), x, k), "and publishes them");
        std::string saved = before.ToJson();
        before.Wipe();
        CHECK(before.LiveEpochs() == 0, "bob closes the app: nothing left in memory");

        std::vector<unsigned char> env, got;
        CHECK(btfchat::SealEnvelope(x, k, "{\"left\":\"while bob was away\"}", env, err),
              "alice leaves a message, sealed to the keys bob published");

        btfchat::Mailbox after;
        CHECK(after.FromJson(saved, err) && after.LiveEpochs() == 1, "bob opens the app again: the keys come back from the store");
        CHECK(after.Rotate(NOW + 3600, err) && after.LiveEpochs() == 1,
              "and the same day keeps the same keys, not new ones");
        CHECK(after.Open(&env[0], env.size(), got, err) &&
              std::string((const char*)&got[0], got.size()) == "{\"left\":\"while bob was away\"}",
              "so alice's message opens");
        CHECK(after.Rotate(NOW + 2 * DAY, err) && !after.Open(&env[0], env.size(), got, err),
              "and two days on the key is destroyed: forward secrecy per epoch");
        btfchat::Mailbox later;
        CHECK(later.FromJson(after.ToJson(), err) && !later.Open(&env[0], env.size(), got, err),
              "nor does a store written after that carry it");
        CHECK(!btfchat::Mailbox().FromJson("not json", err) && btfchat::Mailbox().FromJson("", err),
              "a damaged list is refused; none at all (an older store) is fine");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    secp256k1_context_destroy(ctx);
    return g_fail == 0 ? 0 : 1;
}
