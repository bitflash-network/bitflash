// Standalone tests for btfchat frames -- signing, verification, the group admin
// proof and the replay guard.
//
// Build (UCRT64):
//   g++ -std=gnu++14 -DSECP256K1_STATIC -I../deps/include test_btfchatmsg.cpp \
//       btfchatmsg.cpp btfchat.cpp bip32.cpp btfaddr.cpp -L../deps/lib \
//       -lsecp256k1 -lsodium -lssl -lcrypto -o test_btfchatmsg.exe

#include "btfchatmsg.h"
#include "btfchat.h"
#include "btfaddr.h"

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

// Two throwaway seeds. The identities only have to be real keys, not real
// people, so the seeds are fixed and the derivation cost is paid twice.
static void FixedSeed(unsigned char b, std::vector<unsigned char>& out)
{
    out.assign(64, b);
}

// Re-sign nothing: just edit one field of an already-signed frame's JSON. Every
// one of these has to be refused, because each is a relay changing a byte.
static std::string EditField(const std::string& js, const char* key, const json& val)
{
    json j = json::parse(js);
    j[key] = val;
    return j.dump();
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char rnd[32];
    randombytes_buf(rnd, sizeof(rnd));
    if (!secp256k1_context_randomize(ctx, rnd)) { printf("blinding failed\n"); return 1; }

    std::string err;
    const char* PW = "senha-bem-comprida";

    btfchat::Identity alice, bob;
    {
        std::vector<unsigned char> s;
        FixedSeed(0x11, s);
        if (!btfchat::DeriveIdentityFromSeed(s, PW, alice, err))
        { printf("alice: %s\n", err.c_str()); return 1; }
        FixedSeed(0x22, s);
        if (!btfchat::DeriveIdentityFromSeed(s, PW, bob, err))
        { printf("bob: %s\n", err.c_str()); return 1; }
    }
    printf("two identities: %s / %s\n", alice.address.c_str(), bob.address.c_str());

    // ---- round trips -------------------------------------------------------

    printf("every_kind_round_trips\n");
    std::string jsText;
    {
        btfchat::Frame f;
        f.kind = btfchat::MSG_INVITE;
        f.sent = 1000;
        f.text = "oi, sou a alice";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "an invite signs");
        CHECK(f.from == alice.address, "the sender is filled in from the identity");
        CHECK(f.id.size() == 32, "and a frame id was generated");
        btfchat::Frame g;
        CHECK(btfchat::OpenFrame(ctx, js, g, err), "and opens");
        CHECK(g.kind == btfchat::MSG_INVITE && g.text == "oi, sou a alice" &&
              g.from == alice.address && g.sent == 1000 && g.id == f.id,
              "with every field intact");

        btfchat::Frame t;
        t.kind = btfchat::MSG_TEXT;
        t.sent = 1001;
        t.text = "mensagem de verdade";
        CHECK(btfchat::SignFrame(ctx, alice, t, jsText, err), "a message signs");
        CHECK(btfchat::OpenFrame(ctx, jsText, g, err) && g.text == "mensagem de verdade",
              "and opens");

        btfchat::Frame a;
        a.kind = btfchat::MSG_INVITE_ACCEPT;
        a.sent = 1002;
        std::string jsA;
        CHECK(btfchat::SignFrame(ctx, alice, a, jsA, err), "an accept signs with no body");
        CHECK(btfchat::OpenFrame(ctx, jsA, g, err) && g.kind == btfchat::MSG_INVITE_ACCEPT,
              "and opens");

        btfchat::Frame gt;
        gt.kind  = btfchat::MSG_GROUP_TEXT;
        gt.sent  = 1003;
        gt.group = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        gt.text  = "oi grupo";
        std::string jsG;
        CHECK(btfchat::SignFrame(ctx, alice, gt, jsG, err), "a group message signs");
        CHECK(btfchat::OpenFrame(ctx, jsG, g, err) && g.group == gt.group,
              "and keeps its group");
    }

    printf("a_frame_cannot_be_edited_in_flight\n");
    {
        btfchat::Frame g;
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "text", "outra mensagem"), g, err),
              "changing the message is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "t", 9999), g, err),
              "changing the timestamp is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "id", std::string(32, 'a')), g, err),
              "changing the frame id is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "from", bob.address), g, err),
              "claiming somebody else sent it is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "sig", std::string(128, '0')), g, err),
              "a rewritten signature is refused");

        // A group id bolted onto a direct message: the field rules refuse it
        // before the signature even gets a say.
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "g", "deadbeef"), g, err),
              "a direct message that grew a group is refused");
    }

    printf("a_frame_signed_by_one_key_does_not_pass_as_another\n");
    {
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT;
        f.sent = 2000;
        f.text = "sou eu, juro";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, bob, f, js, err), "bob signs a message");
        json j = json::parse(js);
        j["from"] = alice.address;   // same frame, alice's name on it
        btfchat::Frame g;
        CHECK(!btfchat::OpenFrame(ctx, j.dump(), g, err),
              "bob cannot send a message as alice");

        // The other direction: alice's valid signature moved onto bob's frame.
        json ja = json::parse(jsText);
        j = json::parse(js);
        j["sig"] = ja["sig"];
        CHECK(!btfchat::OpenFrame(ctx, j.dump(), g, err),
              "a signature lifted from another frame does not fit");
    }

    printf("the_address_version_byte_earns_its_keep\n");
    {
        // The same key, spelled as a version 2 address. An old build must say it
        // cannot check this identity scheme rather than verify under the wrong
        // one. This is the reason the byte was reserved.
        unsigned char pk[32];
        CHECK(btf::ParseAddress(alice.address, pk), "alice's address parses");
        std::string v2 = btf::AddressVersioned(pk, 2);
        CHECK(v2 != alice.address, "the version 2 spelling is a different address");

        btfchat::Frame g;
        std::string js = EditField(jsText, "from", v2);
        CHECK(!btfchat::OpenFrame(ctx, js, g, err), "a frame from a version 2 address is refused");
        CHECK(err.find("version") != std::string::npos,
              "and refused for the version, not for the signature");
    }

    printf("malformed_frames_are_refused\n");
    {
        btfchat::Frame g;
        CHECK(!btfchat::OpenFrame(ctx, "", g, err), "an empty frame is refused");
        CHECK(!btfchat::OpenFrame(ctx, "{", g, err), "broken JSON is refused");
        CHECK(!btfchat::OpenFrame(ctx, "[]", g, err), "a JSON array is refused");
        CHECK(!btfchat::OpenFrame(ctx, "{}", g, err), "an empty object is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "v", 2), g, err),
              "an unknown frame version is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "k", 99), g, err),
              "an unknown frame kind is refused");
        CHECK(!btfchat::OpenFrame(ctx, EditField(jsText, "from", "nao-e-um-endereco"), g, err),
              "a sender that is not a .btf is refused");

        // Bigger than the wire limit, and refused before the parser runs.
        std::string huge = "{\"pad\":\"" + std::string(btfchat::MAX_FRAME_BYTES, 'x') + "\"}";
        CHECK(!btfchat::OpenFrame(ctx, huge, g, err), "an oversized frame is refused");
        CHECK(err.find("too big") != std::string::npos, "for being oversized");
    }

    printf("field_rules_are_the_same_on_both_sides\n");
    {
        btfchat::Frame f;
        std::string js;
        f.kind = btfchat::MSG_TEXT; f.sent = 1; f.text = "";
        CHECK(!btfchat::SignFrame(ctx, alice, f, js, err), "an empty message is not signed");
        f.text = std::string(btfchat::MAX_TEXT_BYTES + 1, 'x');
        CHECK(!btfchat::SignFrame(ctx, alice, f, js, err), "an over-long message is not signed");
        f.text = std::string(btfchat::MAX_TEXT_BYTES, 'x');
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "exactly at the limit is fine");

        btfchat::Frame gi;
        gi.kind = btfchat::MSG_GROUP_INVITE; gi.sent = 1; gi.text = "equipe";
        CHECK(!btfchat::SignFrame(ctx, alice, gi, js, err),
              "a group invite with no group is not signed");
        gi.group = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        CHECK(!btfchat::SignFrame(ctx, alice, gi, js, err),
              "and one with no admin proof is not signed either");

        btfchat::Frame it;
        it.kind = btfchat::MSG_INVITE; it.sent = 1;
        it.text = std::string(btfchat::MAX_INVITE_NOTE + 1, 'x');
        CHECK(!btfchat::SignFrame(ctx, alice, it, js, err), "an over-long invite note is not signed");
    }

    // ---- the group admin proof ---------------------------------------------

    const std::string GID   = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const std::string GNAME = "equipe bitflash";

    printf("only_the_admin_can_prove_a_group_invite\n");
    {
        std::string proof;
        CHECK(btfchat::SignGroupInvite(ctx, alice, GID, GNAME, bob.address, proof, err),
              "the admin signs an invite for bob");
        CHECK(proof.size() == 128, "the proof is 64 bytes of hex");
        CHECK(btfchat::VerifyGroupInvite(ctx, alice.address, GID, GNAME, bob.address, proof, err),
              "and it verifies");

        // Every field is bound, so the proof cannot be moved anywhere.
        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, "ffffffffffffffffffffffffffffffff",
                                          GNAME, bob.address, proof, err),
              "it does not work for another group");
        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, GID, "outro nome", bob.address, proof, err),
              "nor under another group name");
        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, GID, GNAME, alice.address, proof, err),
              "nor for another invitee");
        CHECK(!btfchat::VerifyGroupInvite(ctx, bob.address, GID, GNAME, bob.address, proof, err),
              "and bob cannot claim it as his own");

        std::string bobProof;
        CHECK(btfchat::SignGroupInvite(ctx, bob, GID, GNAME, alice.address, bobProof, err),
              "bob can sign an invite to a group id he does not own");
        // He can sign it -- anybody can sign anything. What he cannot do is make
        // it verify against the admin address the group is known by.
        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, GID, GNAME, alice.address, bobProof, err),
              "but it does not verify as the admin's, which is what matters");

        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, GID, GNAME, bob.address,
                                          std::string(128, '0'), err),
              "a made-up proof is refused");
        CHECK(!btfchat::VerifyGroupInvite(ctx, alice.address, GID, GNAME, bob.address, "abcd", err),
              "a short proof is refused");
    }

    printf("a_group_invite_frame_carries_the_proof_intact\n");
    {
        std::string proof;
        CHECK(btfchat::SignGroupInvite(ctx, alice, GID, GNAME, bob.address, proof, err),
              "the admin signs the invite");
        btfchat::Frame f;
        f.kind  = btfchat::MSG_GROUP_INVITE;
        f.sent  = 3000;
        f.group = GID;
        f.text  = GNAME;
        f.proof = proof;
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "the frame signs");

        btfchat::Frame g;
        CHECK(btfchat::OpenFrame(ctx, js, g, err), "and opens");
        CHECK(g.proof == proof, "with the proof intact");
        CHECK(btfchat::VerifyGroupInvite(ctx, g.from, g.group, g.text, bob.address, g.proof, err),
              "and the proof verifies against the sender");

        // Stripping the proof off is a change to the frame, so the signature
        // catches it -- which is why the digest covers the proof field.
        CHECK(!btfchat::OpenFrame(ctx, EditField(js, "proof", std::string(128, '0')), g, err),
              "swapping the proof breaks the frame signature");
    }

    printf("the_roster_and_the_proof_together_close_the_group_door\n");
    {
        // Eve is blocked. She writes a group invite, signs it properly as the
        // admin of her own group, and sends it. Both layers have to refuse.
        btfchat::Roster r;
        CHECK(r.Block(bob.address, err), "bob is blocked");

        std::string proof;
        CHECK(btfchat::SignGroupInvite(ctx, bob, GID, GNAME, alice.address, proof, err),
              "he signs a genuine invite to his own group");
        btfchat::Frame f;
        f.kind = btfchat::MSG_GROUP_INVITE; f.sent = 4000;
        f.group = GID; f.text = GNAME; f.proof = proof;
        std::string js;
        CHECK(btfchat::SignFrame(ctx, bob, f, js, err), "the frame is validly signed");

        btfchat::Frame g;
        CHECK(btfchat::OpenFrame(ctx, js, g, err), "the crypto is fine -- it opens");
        CHECK(btfchat::VerifyGroupInvite(ctx, g.from, g.group, g.text, alice.address, g.proof, err),
              "and the admin proof is genuine");
        // Everything about it is authentic. It still must not arrive.
        CHECK(!r.MayDeliver(g.from, g.kind, err), "and the gate refuses it anyway, for being blocked");
        CHECK(!r.NoteGroupInvite(g.group, g.text, g.from, g.from, 4000, err),
              "and the roster will not record it");
    }

    // ---- replay ------------------------------------------------------------

    printf("a_frame_is_delivered_once\n");
    {
        btfchat::ReplayGuard rg;
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.text = "oi"; f.sent = 10000;
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "a message signs");

        CHECK(rg.Accept(f, 10000, err), "the first delivery is accepted");
        CHECK(!rg.Accept(f, 10000, err), "the same frame again is refused");
        CHECK(err.find("already") != std::string::npos, "as a replay");
        // A whole day later, on a brand new channel, the recording is still a
        // recording -- until it falls out of the window, at which point the age
        // check is what refuses it.
        CHECK(!rg.Accept(f, 10000 + btfchat::FRAME_MAX_AGE + 1, err),
              "and a day later it is refused for being too old");
        CHECK(rg.Size() == 1, "one id is remembered");

        btfchat::Frame future = f;
        future.id = std::string(32, 'b');
        future.sent = 10000 + btfchat::FRAME_FUTURE_SKEW + 1;
        CHECK(!rg.Accept(future, 10000, err), "a frame from the future is refused");
        future.sent = 10000 + btfchat::FRAME_FUTURE_SKEW;
        CHECK(rg.Accept(future, 10000, err), "a little clock skew is tolerated");

        btfchat::Frame bad = f;
        bad.id = "nope";
        CHECK(!rg.Accept(bad, 10000, err), "a malformed id is refused");
    }

    printf("the_replay_table_forgets_only_what_expired\n");
    {
        btfchat::ReplayGuard rg;
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.text = "oi"; f.sent = 1000;
        f.id = std::string(32, 'c');
        CHECK(rg.Accept(f, 1000, err), "accepted at t=1000");
        rg.Prune(1000 + btfchat::FRAME_MAX_AGE);
        CHECK(rg.Size() == 1, "still remembered at the edge of the window");
        rg.Prune(1000 + btfchat::FRAME_MAX_AGE + 1);
        CHECK(rg.Size() == 0, "and forgotten one second past it");
    }

    printf("the_replay_table_fails_closed_when_full\n");
    {
        btfchat::ReplayGuard rg;
        char buf[64];
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.text = "x"; f.sent = 1000;
        for (size_t i = 0; i < btfchat::MAX_SEEN_FRAMES; i++)
        {
            snprintf(buf, sizeof(buf), "%032u", (unsigned)i);
            f.id = buf;
            if (!rg.Accept(f, 1000, err)) { g_fail++; break; }
        }
        CHECK(rg.Size() == btfchat::MAX_SEEN_FRAMES, "the table fills to its ceiling");
        f.id = std::string(32, 'f');
        CHECK(!rg.Accept(f, 1000, err), "and then refuses rather than forgetting");
        CHECK(err.find("full") != std::string::npos, "saying so");
        // Once the window passes, the room comes back on its own.
        f.sent = 1000 + btfchat::FRAME_MAX_AGE + 1;
        CHECK(rg.Accept(f, 1000 + btfchat::FRAME_MAX_AGE + 1, err),
              "a day later there is room again");
    }

    printf("the_intended_order_end_to_end\n");
    {
        // Gate, then signature, then replay. Alice invites, bob accepts, alice
        // writes -- and nothing before the accept gets through.
        btfchat::Roster r;          // bob's roster
        btfchat::ReplayGuard rg;    // bob's replay table
        const int64_t NOW = 50000;

        btfchat::Frame msg;
        msg.kind = btfchat::MSG_TEXT; msg.sent = NOW; msg.text = "oi antes do convite";
        std::string jsMsg;
        CHECK(btfchat::SignFrame(ctx, alice, msg, jsMsg, err), "alice signs a message first");
        btfchat::Frame g;
        CHECK(btfchat::OpenFrame(ctx, jsMsg, g, err), "it is a perfectly valid frame");
        CHECK(!r.MayDeliver(g.from, g.kind, err), "and the gate refuses it: not accepted");

        btfchat::Frame inv;
        inv.kind = btfchat::MSG_INVITE; inv.sent = NOW; inv.text = "posso falar?";
        std::string jsInv;
        CHECK(btfchat::SignFrame(ctx, alice, inv, jsInv, err), "alice invites");
        CHECK(btfchat::OpenFrame(ctx, jsInv, g, err), "the invite opens");
        CHECK(r.MayDeliver(g.from, g.kind, err), "the gate lets one invite through");
        CHECK(rg.Accept(g, NOW, err), "the replay table records it");
        CHECK(r.NoteIncomingInvite(g.from, g.text, g.sent, err), "and it lands as pending");
        CHECK(!rg.Accept(g, NOW, err), "a resend of the same invite is dropped");

        CHECK(r.AcceptInvite(alice.address, err), "bob accepts");
        CHECK(btfchat::OpenFrame(ctx, jsMsg, g, err), "alice's first message still opens");
        CHECK(r.MayDeliver(g.from, g.kind, err), "and now the gate lets it in");
        CHECK(rg.Accept(g, NOW, err), "first delivery");
        CHECK(!rg.Accept(g, NOW, err), "second is a replay");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    secp256k1_context_destroy(ctx);
    return g_fail == 0 ? 0 : 1;
}
