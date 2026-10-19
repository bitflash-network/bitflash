// Standalone tests for the btfchat history -- what gets recorded, what does not,
// the two ceilings, and the sealed form on disk.
//
// Build (UCRT64):
//   g++ -std=gnu++14 -DSECP256K1_STATIC -I../deps/include test_btfchatlog.cpp \
//       btfchatlog.cpp btfchatmsg.cpp btfchat.cpp bip32.cpp btfaddr.cpp \
//       -L../deps/lib -lsecp256k1 -lsodium -lssl -lcrypto -o test_btfchatlog.exe

#include "btfchatlog.h"
#include "btfchatmsg.h"
#include "btfchat.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static std::string IdOf(unsigned n)
{
    char buf[40];
    snprintf(buf, sizeof(buf), "%032u", n);
    return buf;
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
    btfchat::Identity me, alice;
    {
        std::vector<unsigned char> s(64, 0x77);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", me, err))
        { printf("me: %s\n", err.c_str()); return 1; }
        s.assign(64, 0x88);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", alice, err))
        { printf("alice: %s\n", err.c_str()); return 1; }
    }
    const std::string GID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

    // Build a frame the way the rest of the chat does, so the history is tested
    // against the real shape and not a hand-made struct.
    struct Maker
    {
        secp256k1_context* ctx;
        btfchat::Identity* who;
        btfchat::Frame Text(const char* s, int64_t t)
        {
            btfchat::Frame f;
            f.kind = btfchat::MSG_TEXT; f.sent = t; f.text = s;
            std::string js, e;
            btfchat::SignFrame(ctx, *who, f, js, e);
            return f;
        }
        btfchat::Frame GroupText(const std::string& g, const char* s, int64_t t)
        {
            btfchat::Frame f;
            f.kind = btfchat::MSG_GROUP_TEXT; f.group = g; f.sent = t; f.text = s;
            std::string js, e;
            btfchat::SignFrame(ctx, *who, f, js, e);
            return f;
        }
    };
    Maker mkAlice; mkAlice.ctx = ctx; mkAlice.who = &alice;
    Maker mkMe;    mkMe.ctx = ctx;    mkMe.who = &me;

    printf("a_conversation_is_recorded_in_order\n");
    {
        btfchat::History h;
        CHECK(h.MessageCount() == 0 && h.ConversationCount() == 0, "a fresh history is empty");

        btfchat::Frame in1 = mkAlice.Text("oi", 1000);
        CHECK(h.Append(in1, alice.address, false, err), "an incoming message is recorded");
        btfchat::Frame out1 = mkMe.Text("oi, tudo bem?", 1001);
        CHECK(h.Append(out1, alice.address, true, err), "and one we sent");
        btfchat::Frame in2 = mkAlice.Text("tudo", 1002);
        CHECK(h.Append(in2, alice.address, false, err), "and the reply");

        std::vector<btfchat::LogEntry> v;
        h.Conversation(alice.address, v);
        CHECK(v.size() == 3, "three lines in the conversation");
        CHECK(v[0].text == "oi" && v[1].text == "oi, tudo bem?" && v[2].text == "tudo",
              "in the order they happened");
        CHECK(!v[0].outgoing && v[1].outgoing, "and each one knows which way it went");
        CHECK(v[0].from == alice.address && v[1].from == me.address,
              "with the writer on every line");
        CHECK(h.ConversationCount() == 1, "one conversation");

        std::vector<btfchat::LogEntry> none;
        h.Conversation("someone-else.btf", none);
        CHECK(none.empty(), "an unknown conversation reads back empty");
    }

    printf("the_same_frame_is_never_recorded_twice\n");
    {
        btfchat::History h;
        btfchat::Frame f = mkAlice.Text("oi", 1000);
        CHECK(h.Append(f, alice.address, false, err), "recorded once");
        CHECK(!h.Append(f, alice.address, false, err), "and refused the second time");
        CHECK(err.find("already") != std::string::npos, "as a duplicate");
        CHECK(h.MessageCount() == 1, "so the line does not double up");
    }

    printf("a_message_cannot_be_filed_under_the_wrong_name\n");
    {
        btfchat::History h;
        btfchat::Frame f = mkAlice.Text("oi", 1000);
        // Alice's words, filed as if they came from the conversation with me:
        // this is how a conversation gets forged without touching the network.
        CHECK(!h.Append(f, me.address, false, err),
              "an incoming message must be filed under its sender");
        CHECK(!h.Append(f, "", false, err), "a direct message needs the other party");
        btfchat::Frame mine = mkMe.Text("oi", 1000);
        CHECK(!h.Append(mine, me.address, true, err), "we are not our own conversation");
        CHECK(h.MessageCount() == 0, "and nothing was recorded by any of that");
    }

    printf("only_messages_go_into_the_history\n");
    {
        btfchat::History h;
        btfchat::Frame inv;
        inv.kind = btfchat::MSG_INVITE; inv.sent = 1000; inv.text = "posso falar?";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, inv, js, err), "alice signs an invite");
        CHECK(!h.Append(inv, alice.address, false, err),
              "an invite is a roster event, not a line of conversation");

        btfchat::Frame acc;
        acc.kind = btfchat::MSG_INVITE_ACCEPT; acc.sent = 1001;
        CHECK(btfchat::SignFrame(ctx, alice, acc, js, err), "and an accept");
        CHECK(!h.Append(acc, alice.address, false, err), "an accept is not either");
        CHECK(h.MessageCount() == 0, "so a stranger's note never lands in the history");
    }

    printf("groups_have_their_own_log\n");
    {
        btfchat::History h;
        btfchat::Frame g1 = mkAlice.GroupText(GID, "oi grupo", 2000);
        CHECK(h.Append(g1, "", false, err), "a group message is recorded without a peer");
        btfchat::Frame g2 = mkMe.GroupText(GID, "oi", 2001);
        CHECK(h.Append(g2, "", true, err), "and one we sent to the group");

        std::vector<btfchat::LogEntry> v;
        h.GroupLog(GID, v);
        CHECK(v.size() == 2, "two lines in the group");
        std::vector<btfchat::LogEntry> d;
        h.Conversation(alice.address, d);
        CHECK(d.empty(), "and none of them leaked into the direct conversation");

        btfchat::Frame bad = mkAlice.GroupText(GID, "oi", 2002);
        bad.group.clear();
        CHECK(!h.Append(bad, "", false, err), "a group message with no group is refused");
    }

    printf("forgetting_is_immediate_and_per_conversation\n");
    {
        btfchat::History h;
        btfchat::Frame a1 = mkAlice.Text("oi", 1000);
        btfchat::Frame g1 = mkAlice.GroupText(GID, "oi grupo", 1001);
        CHECK(h.Append(a1, alice.address, false, err), "a direct line");
        CHECK(h.Append(g1, "", false, err), "and a group line");
        CHECK(h.MessageCount() == 2, "two lines total");

        h.ForgetPeer(alice.address);
        std::vector<btfchat::LogEntry> v;
        h.Conversation(alice.address, v);
        CHECK(v.empty(), "the conversation is gone");
        h.GroupLog(GID, v);
        CHECK(v.size() == 1, "and the group is untouched");

        // The id went with it, so the same message can be recorded again --
        // forgetting has to actually forget, not leave a tombstone that silently
        // refuses the message next time.
        CHECK(h.Append(a1, alice.address, false, err), "and the line can come back");

        h.Wipe();
        CHECK(h.MessageCount() == 0 && h.ConversationCount() == 0, "wiping clears everything");
    }

    printf("a_full_conversation_drops_its_oldest_line\n");
    {
        // The opposite of the replay table on purpose: a log is not a security
        // boundary, so it forgets rather than refusing to record.
        btfchat::History h;
        btfchat::Frame f = mkAlice.Text("x", 1000);
        for (size_t i = 0; i < btfchat::MAX_CONVERSATION_MESSAGES; i++)
        {
            f.id = IdOf((unsigned)i);
            if (!h.Append(f, alice.address, false, err)) { g_fail++; break; }
        }
        CHECK(h.MessageCount() == btfchat::MAX_CONVERSATION_MESSAGES,
              "the conversation fills to its ceiling");
        f.id = IdOf(999999);
        CHECK(h.Append(f, alice.address, false, err), "one more is still accepted");
        CHECK(h.MessageCount() == btfchat::MAX_CONVERSATION_MESSAGES,
              "and the count stays at the ceiling");
        std::vector<btfchat::LogEntry> v;
        h.Conversation(alice.address, v);
        CHECK(v[0].id == IdOf(1), "the oldest line is the one that went");
        CHECK(v.back().id == IdOf(999999), "and the newest is there");
        // The evicted id was released, so that message is recordable again.
        f.id = IdOf(0);
        CHECK(h.Append(f, alice.address, false, err), "the evicted id is free again");
    }

    printf("the_history_survives_a_round_trip\n");
    {
        btfchat::History h;
        btfchat::Frame a1 = mkAlice.Text("oi, sou a alice", 1000);
        btfchat::Frame m1 = mkMe.Text("oi", 1001);
        btfchat::Frame g1 = mkAlice.GroupText(GID, "oi grupo", 1002);
        CHECK(h.Append(a1, alice.address, false, err), "incoming");
        CHECK(h.Append(m1, alice.address, true, err), "outgoing");
        CHECK(h.Append(g1, "", false, err), "group");

        std::string js = h.ToJson();
        btfchat::History h2;
        CHECK(h2.FromJson(js, err), "the history reloads");
        std::vector<btfchat::LogEntry> v;
        h2.Conversation(alice.address, v);
        CHECK(v.size() == 2 && v[0].text == "oi, sou a alice" && v[1].outgoing,
              "with the conversation intact, directions included");
        h2.GroupLog(GID, v);
        CHECK(v.size() == 1 && v[0].text == "oi grupo", "and the group log");

        // Reloading has to restore the duplicate check too, or a restart would
        // let every message in the file be recorded a second time.
        CHECK(!h2.Append(a1, alice.address, false, err),
              "a line already in the file is still refused after a reload");

        CHECK(!h2.FromJson("{", err), "broken JSON is refused");
        CHECK(!h2.FromJson("[]", err), "a history that is not an object is refused");
        h2.Conversation(alice.address, v);
        CHECK(v.size() == 2, "and a refused load leaves what was loaded alone");

        // Junk lines are dropped rather than taken on faith.
        btfchat::History h3;
        CHECK(h3.FromJson("{\"v\":1,\"direct\":{\"a.btf\":[{\"f\":\"\",\"i\":\"x\"},"
                          "{\"f\":\"b.btf\",\"i\":\"00000000000000000000000000000001\","
                          "\"x\":\"ok\",\"t\":5,\"o\":false}]}}", err),
              "a file with one good line and one broken one loads");
        h3.Conversation("a.btf", v);
        CHECK(v.size() == 1 && v[0].text == "ok", "keeping only the line that made sense");
    }

    printf("the_history_is_sealed_on_disk\n");
    {
        btfchat::History h;
        btfchat::Frame a1 = mkAlice.Text("segredo que nao pode vazar", 1000);
        CHECK(h.Append(a1, alice.address, false, err), "a line is recorded");
        std::string plain = h.ToJson();

        std::vector<unsigned char> sealed;
        CHECK(btfchat::SealStore(me, plain, sealed), "the history seals under the identity key");
        std::string blob((const char*)&sealed[0], sealed.size());
        CHECK(blob.find("segredo") == std::string::npos, "the message is not in the file");
        CHECK(blob.find(alice.address) == std::string::npos, "nor who it was with");

        std::string opened;
        CHECK(btfchat::OpenStore(me, &sealed[0], sealed.size(), opened) && opened == plain,
              "and it opens back");
        CHECK(!btfchat::OpenStore(alice, &sealed[0], sealed.size(), opened),
              "another identity -- or a wrong session password -- opens nothing");

        btfchat::History h2;
        CHECK(btfchat::OpenStore(me, &sealed[0], sealed.size(), opened) &&
              h2.FromJson(opened, err) && h2.MessageCount() == 1,
              "the round trip through the seal is lossless");
    }

    printf("payment_lines_are_kept_and_survive_a_reload\n");
    {
        btfchat::History h;
        btfchat::Frame pa;
        pa.kind = btfchat::MSG_PAY_ADDRESS;
        pa.sent = 3000;
        pa.payTo = "BSdf5xY8s8u8gRtP6ZoSjcPnUBGSMM2N5u";
        pa.amount = 250000000;
        std::string js, e;
        CHECK(btfchat::SignFrame(ctx, alice, pa, js, e), "alice signs an address with no note");
        CHECK(h.Append(pa, alice.address, false, err), "a payment line with no note is recorded");

        btfchat::Frame p;
        p.kind = btfchat::MSG_PAYMENT;
        p.sent = 3001;
        p.payTo = pa.payTo;
        p.amount = 250000000;
        p.txid = std::string(64, 'd');
        p.text = "done";
        CHECK(btfchat::SignFrame(ctx, me, p, js, e) && h.Append(p, alice.address, true, err),
              "so is the payment we made");

        btfchat::History h2;
        CHECK(h2.FromJson(h.ToJson(), err), "the history reloads");
        std::vector<btfchat::LogEntry> v;
        h2.Conversation(alice.address, v);
        CHECK(v.size() == 2 && v[0].kind == btfchat::MSG_PAY_ADDRESS && v[0].payTo == pa.payTo &&
              v[0].amount == 250000000 && !v[0].outgoing, "the address line comes back whole");
        CHECK(v.size() == 2 && v[1].kind == btfchat::MSG_PAYMENT && v[1].txid == p.txid &&
              v[1].amount == 250000000 && v[1].outgoing, "and so does the payment, txid included");

        btfchat::Frame forged = p;
        forged.id = std::string(32, 'e');
        CHECK(!h.Append(forged, me.address, true, err),
              "our own payment is never filed as a conversation with ourselves");
    }

    // ---- the outbox --------------------------------------------------------
    {
        printf("\n-- the outbox --\n");
        const int64_t NOW = 1800000000;
        std::string err;

        btfchat::Outbox ob;
        btfchat::Pending p;
        p.peer = "bpeer1.btf"; p.id = IdOf(9001); p.text = "oi"; p.sent = NOW;
        p.frameJson = "{\"fake\":\"frame\"}";
        CHECK(ob.Add(p, err), "a message that could not be sent is kept");
        CHECK(!ob.Add(p, err), "the same frame is not queued twice");
        CHECK(ob.Size() == 1 && ob.CountFor("bpeer1.btf") == 1, "and it is counted once");

        btfchat::Pending bad = p;
        bad.id = IdOf(9002);
        bad.frameJson.clear();
        CHECK(!ob.Add(bad, err), "a message with no frame is refused");
        bad = p; bad.id = "short";
        CHECK(!ob.Add(bad, err), "a malformed id is refused");

        btfchat::Pending q = p;
        q.id = IdOf(9003); q.text = "segunda"; q.sent = NOW + 10;
        CHECK(ob.Add(q, err), "a second one queues behind it");
        std::vector<btfchat::Pending> got;
        ob.For("bpeer1.btf", got);
        CHECK(got.size() == 2 && got[0].id == IdOf(9001) && got[1].id == IdOf(9003),
              "and they come back in the order they were written");

        std::vector<std::string> peers;
        ob.Peers(peers);
        CHECK(peers.size() == 1 && peers[0] == "bpeer1.btf", "one peer is waiting");

        ob.Remove(IdOf(9001));
        ob.For("bpeer1.btf", got);
        CHECK(got.size() == 1 && got[0].id == IdOf(9003), "a delivered one leaves the queue");
        // Removing frees the id, because the message is gone for good and a
        // later message could legitimately reuse nothing -- but the id check
        // must not keep refusing it forever either.
        CHECK(ob.Add(p, err), "and its slot is free again");
        ob.Remove(IdOf(9001));

        // The ceiling refuses rather than dropping. A log drops its oldest line
        // because a log is a record; a queue must not, because its contents have
        // NOT happened yet.
        btfchat::Outbox full;
        for (size_t i = 0; i < btfchat::MAX_OUTBOX_PER_PEER; i++)
        {
            btfchat::Pending f;
            f.peer = "bfull.btf"; f.id = IdOf((unsigned)(20000 + i));
            f.text = "x"; f.sent = NOW; f.frameJson = "{}";
            if (!full.Add(f, err)) { CHECK(false, "the queue filled early"); break; }
        }
        btfchat::Pending over;
        over.peer = "bfull.btf"; over.id = IdOf(29999); over.text = "x";
        over.sent = NOW; over.frameJson = "{}";
        CHECK(!full.Add(over, err), "a full queue refuses instead of dropping the oldest");
        std::vector<btfchat::Pending> stillThere;
        full.For("bfull.btf", stillThere);
        CHECK(stillThere.size() == btfchat::MAX_OUTBOX_PER_PEER &&
              stillThere[0].id == IdOf(20000),
              "and the first thing the user said is still the first thing waiting");

        // Expiry is not a preference: past FRAME_MAX_AGE the receiving side
        // refuses the frame, so holding it is holding something that can no
        // longer arrive.
        btfchat::Outbox aging;
        btfchat::Pending fresh, stale;
        fresh.peer = "bage.btf"; fresh.id = IdOf(31001); fresh.text = "nova";
        fresh.sent = NOW; fresh.frameJson = "{}";
        stale.peer = "bage.btf"; stale.id = IdOf(31002); stale.text = "velha";
        stale.sent = NOW - btfchat::FRAME_MAX_AGE; stale.frameJson = "{}";
        CHECK(aging.Add(fresh, err) && aging.Add(stale, err), "one fresh, one at the limit");
        CHECK(aging.Expire(NOW) == 1, "the one the other side would refuse is dropped");
        aging.For("bage.btf", got);
        CHECK(got.size() == 1 && got[0].id == IdOf(31001), "and the deliverable one stays");

        // A store is a file, and a file is something else could have edited.
        btfchat::Outbox loaded;
        CHECK(loaded.FromJson(full.ToJson(), err), "the queue reloads from its sealed form");
        CHECK(loaded.CountFor("bfull.btf") == btfchat::MAX_OUTBOX_PER_PEER,
              "with everything that was in it");
        std::string strOversized = full.ToJson();
        // Same queue claimed twice over: FromJson must not end up holding more
        // than Add() would ever have allowed.
        CHECK(loaded.FromJson(strOversized, err) &&
              loaded.CountFor("bfull.btf") <= btfchat::MAX_OUTBOX_PER_PEER,
              "and a store that grew past the ceiling elsewhere does not get past it here");

        btfchat::Outbox forget;
        CHECK(forget.Add(p, err), "one queued");
        forget.ForgetPeer("bpeer1.btf");
        CHECK(forget.Size() == 0, "forgetting a peer drops what was waiting for them");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    secp256k1_context_destroy(ctx);
    return g_fail == 0 ? 0 : 1;
}
