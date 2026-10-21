// Standalone tests for the btfchat link -- the handshake and framing over a
// stream, and Inbox::Deliver, which is the one place the inbound order lives.
//
// The stream here is a blocking in-memory pipe and the endpoint runs in a
// thread, so the two sides interleave exactly as they would over a socket. That
// is the point of the Stream abstraction: the protocol under test is byte for
// byte the one that will run over Tor, and none of it needs a network to prove.
//
// Build (UCRT64):
//   g++ -std=gnu++14 -pthread -DSECP256K1_STATIC -I../deps/include \
//       test_btfchatlink.cpp btfchatlink.cpp btfchatlog.cpp btfchatmsg.cpp \
//       btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp \
//       -L../deps/lib -lsecp256k1 -lsodium -lssl -lcrypto -o test_btfchatlink.exe

#include "btfchatlink.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

// ---- a blocking in-memory socket pair --------------------------------------

class Pipe
{
public:
    Pipe() : fClosed(false) {}

    void Push(bool fToB, const unsigned char* p, size_t n)
    {
        std::unique_lock<std::mutex> lk(mtx);
        std::deque<unsigned char>& q = fToB ? a2b : b2a;
        for (size_t i = 0; i < n; i++) q.push_back(p[i]);
        cv.notify_all();
    }

    // Waits for n bytes, or gives up when the pipe is closed.
    bool Pull(bool fFromB, unsigned char* p, size_t n)
    {
        std::unique_lock<std::mutex> lk(mtx);
        std::deque<unsigned char>& q = fFromB ? b2a : a2b;
        cv.wait(lk, [&] { return q.size() >= n || fClosed; });
        if (q.size() < n)
            return false;
        for (size_t i = 0; i < n; i++) { p[i] = q.front(); q.pop_front(); }
        return true;
    }

    void Close()
    {
        std::unique_lock<std::mutex> lk(mtx);
        fClosed = true;
        cv.notify_all();
    }

    bool Closed() const { return fClosed; }

private:
    std::mutex              mtx;
    std::condition_variable cv;
    std::deque<unsigned char> a2b, b2a;
    bool                      fClosed;
};

// One end. Side A writes into a2b and reads from b2a.
class PipeEnd : public btfchat::Stream
{
public:
    PipeEnd(Pipe& p, bool fSideA) : pipe(p), fA(fSideA), nFlipAt(-1), nWritten(0) {}

    // Flip one bit at this offset into everything this end writes from now on.
    // Stands in for whatever is on the path between the two of them.
    void FlipBitAt(long at) { nFlipAt = at; }

    bool Write(const unsigned char* p, size_t n)
    {
        if (pipe.Closed()) return false;
        std::vector<unsigned char> buf(p, p + n);
        if (nFlipAt >= 0)
        {
            long rel = nFlipAt - (long)nWritten;
            if (rel >= 0 && (size_t)rel < n)
            {
                buf[(size_t)rel] ^= 1;
                nFlipAt = -1;
            }
        }
        nWritten += n;
        pipe.Push(fA, buf.empty() ? (const unsigned char*)"" : &buf[0], n);
        return true;
    }

    bool Read(unsigned char* p, size_t n) { return pipe.Pull(fA, p, n); }

    // Put raw bytes on the wire without going through a Link, to feed the peer
    // something no honest Link would ever produce.
    void WriteRaw(const unsigned char* p, size_t n) { pipe.Push(fA, p, n); }

private:
    Pipe&  pipe;
    bool   fA;
    long   nFlipAt;
    size_t nWritten;
};

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
    btfchat::Identity alice, bob, eve;
    {
        std::vector<unsigned char> s(64, 0x91);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", alice, err))
        { printf("alice: %s\n", err.c_str()); return 1; }
        s.assign(64, 0x92);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", bob, err))
        { printf("bob: %s\n", err.c_str()); return 1; }
        s.assign(64, 0x93);
        if (!btfchat::DeriveIdentityFromSeed(s, "senha-bem-comprida", eve, err))
        { printf("eve: %s\n", err.c_str()); return 1; }
    }
    const int64_t NOW = 1790000000;

    printf("the_handshake_completes_over_a_stream\n");
    {
        Pipe p;
        PipeEnd ca(p, true), eb(p, false);

        btfchat::Link endpoint;
        std::string epErr;
        bool fEp = false;
        std::thread th([&] { fEp = endpoint.AcceptAsEndpoint(eb, bob.chan_sk, epErr); });

        btfchat::Link client;
        bool fCl = client.ConnectAsClient(ca, bob.chan_pk, err);
        th.join();

        CHECK(fCl, "the client completes the handshake");
        CHECK(fEp, "and so does the endpoint");
        if (!fEp) printf("       (%s)\n", epErr.c_str());
        CHECK(client.IsOpen() && endpoint.IsOpen(), "both links are open");

        // Frames, both directions, sealed under the session they just derived.
        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.sent = NOW; f.text = "primeira mensagem pelo canal";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "alice signs a frame");
        CHECK(client.SendFrame(ca, js, err), "the client sends it");
        std::string got;
        CHECK(endpoint.RecvFrame(eb, got, err) && got == js,
              "and the endpoint reads it back unchanged");

        btfchat::Frame r;
        r.kind = btfchat::MSG_TEXT; r.sent = NOW + 1; r.text = "resposta";
        std::string jsr;
        CHECK(btfchat::SignFrame(ctx, bob, r, jsr, err), "bob signs a reply");
        CHECK(endpoint.SendFrame(eb, jsr, err), "the endpoint answers");
        CHECK(client.RecvFrame(ca, got, err) && got == jsr, "and the client reads it");

        // Several in a row, to walk the ratchet.
        for (int i = 0; i < 5; i++)
        {
            btfchat::Frame n;
            n.kind = btfchat::MSG_TEXT; n.sent = NOW + 10 + i; n.text = "rajada";
            std::string jn;
            btfchat::SignFrame(ctx, alice, n, jn, err);
            if (!client.SendFrame(ca, jn, err) || !endpoint.RecvFrame(eb, got, err) || got != jn)
            { g_fail++; break; }
        }
        CHECK(true, "five frames in a row walk the ratchet");

        p.Close();
        client.Close();
        endpoint.Close();
        CHECK(!client.IsOpen(), "closing zeroes the session");
    }

    printf("the_wrong_endpoint_key_gets_no_session\n");
    {
        Pipe p;
        PipeEnd ca(p, true), eb(p, false);

        btfchat::Link endpoint;
        std::string epErr;
        bool fEp = false;
        std::thread th([&] { fEp = endpoint.AcceptAsEndpoint(eb, bob.chan_sk, epErr); });

        // Dialling bob's onion but checking against eve's key: this is what a
        // man in the middle looks like from the client's side, and the whole
        // reason the static key is in the derivation.
        btfchat::Link client;
        bool fCl = client.ConnectAsClient(ca, eve.chan_pk, err);
        th.join();

        if (fCl)
        {
            // The handshake cannot fail locally -- both sides just derive
            // different roots -- so the proof is that nothing crosses.
            btfchat::Frame f;
            f.kind = btfchat::MSG_TEXT; f.sent = NOW; f.text = "consegue ler isso?";
            std::string js, got;
            btfchat::SignFrame(ctx, alice, f, js, err);
            CHECK(client.SendFrame(ca, js, err), "the client can still send");
            CHECK(!endpoint.RecvFrame(eb, got, err),
                  "but the endpoint cannot open a single frame");
            CHECK(!endpoint.IsOpen(), "and drops the link");
        }
        else
        {
            CHECK(true, "the handshake itself refused the wrong key");
        }
        p.Close();
        client.Close();
        endpoint.Close();
    }

    printf("a_byte_changed_on_the_path_ends_the_link\n");
    {
        Pipe p;
        PipeEnd ca(p, true), eb(p, false);
        btfchat::Link endpoint;
        std::string epErr;
        bool fEp = false;
        std::thread th([&] { fEp = endpoint.AcceptAsEndpoint(eb, bob.chan_sk, epErr); });
        btfchat::Link client;
        bool fCl = client.ConnectAsClient(ca, bob.chan_pk, err);
        th.join();
        CHECK(fCl && fEp, "a good handshake first");

        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.sent = NOW; f.text = "mensagem que vai ser mexida";
        std::string js;
        btfchat::SignFrame(ctx, alice, f, js, err);

        // Flip a bit inside the ciphertext of the next frame. The client has
        // written CHAN_HS1BYTES + CHAN_HS3BYTES bytes of handshake so far, so
        // aim past the length word of the frame that follows.
        ca.FlipBitAt((long)(btf::CHAN_HS1BYTES + btf::CHAN_HS3BYTES) + 20);
        CHECK(client.SendFrame(ca, js, err), "the client sends it");
        std::string got;
        CHECK(!endpoint.RecvFrame(eb, got, err), "the endpoint refuses the frame");
        CHECK(err.find("authenticate") != std::string::npos ||
              err.find("impossible") != std::string::npos ||
              err.find("closed") != std::string::npos, "and says why");
        CHECK(!endpoint.IsOpen(),
              "the link is closed -- framing that slipped cannot be resynchronized");

        p.Close();
        client.Close();
    }

    printf("an_impossible_length_is_refused_before_any_allocation\n");
    {
        Pipe p;
        PipeEnd ca(p, true), eb(p, false);
        btfchat::Link endpoint;
        std::string epErr;
        bool fEp = false;
        std::thread th([&] { fEp = endpoint.AcceptAsEndpoint(eb, bob.chan_sk, epErr); });
        btfchat::Link client;
        bool fCl = client.ConnectAsClient(ca, bob.chan_pk, err);
        th.join();
        CHECK(fCl && fEp, "a good handshake first");

        // Four bytes claiming a 4 GB frame. Nothing honest produces this, and it
        // must not become an allocation.
        unsigned char huge[4] = {0xff, 0xff, 0xff, 0xff};
        ca.WriteRaw(huge, sizeof(huge));
        std::string got;
        CHECK(!endpoint.RecvFrame(eb, got, err), "the endpoint refuses it");
        CHECK(err.find("impossible") != std::string::npos, "for the length");
        CHECK(!endpoint.IsOpen(), "and closes the link");

        p.Close();
        client.Close();
    }

    printf("a_closed_link_does_nothing\n");
    {
        Pipe p;
        PipeEnd ca(p, true);
        btfchat::Link l;
        std::string js;
        CHECK(!l.SendFrame(ca, "{}", err), "a closed link sends nothing");
        CHECK(err.find("not open") != std::string::npos, "saying it is not open");
        CHECK(!l.RecvFrame(ca, js, err), "and receives nothing");
        p.Close();
    }

    printf("a_frame_over_the_wire_limit_is_not_sent\n");
    {
        Pipe p;
        PipeEnd ca(p, true), eb(p, false);
        btfchat::Link endpoint;
        std::string epErr;
        std::thread th([&] { endpoint.AcceptAsEndpoint(eb, bob.chan_sk, epErr); });
        btfchat::Link client;
        CHECK(client.ConnectAsClient(ca, bob.chan_pk, err), "handshake");
        th.join();

        std::string huge(btfchat::MAX_FRAME_BYTES + 1, 'x');
        CHECK(!client.SendFrame(ca, huge, err),
              "an oversized frame is refused by the sender too");
        CHECK(client.IsOpen(), "and refusing it did not cost the link");
        CHECK(!client.SendFrame(ca, "", err), "an empty frame is not sent");

        p.Close();
        client.Close();
        endpoint.Close();
    }

    // ---- Inbox::Deliver: the order, end to end -----------------------------

    printf("deliver_needs_every_piece_wired\n");
    {
        btfchat::Inbox in;
        btfchat::Frame g;
        CHECK(!in.Deliver("{}", "", NOW, g, err), "an unwired inbox refuses everything");
        CHECK(err.find("wired") != std::string::npos, "and says so");
    }

    printf("deliver_walks_the_whole_path_in_order\n");
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox in;
        in.secpctx = ctx; in.myAddress = bob.address;
        in.roster = &roster; in.replay = &replay; in.history = &history;

        // A message before any invite: a valid frame, refused at consent -- and
        // the part that matters, it must not have taken a replay slot.
        btfchat::Frame msg;
        msg.kind = btfchat::MSG_TEXT; msg.sent = NOW; msg.text = "oi antes do convite";
        std::string jsMsg;
        CHECK(btfchat::SignFrame(ctx, alice, msg, jsMsg, err), "alice signs a message");
        btfchat::Frame g;
        CHECK(!in.Deliver(jsMsg, alice.address, NOW, g, err), "it is refused");
        CHECK(err.find("not accepted") != std::string::npos, "at the consent gate");
        CHECK(replay.Size() == 0,
              "and a refused stranger did not take a slot in the replay table");
        CHECK(history.MessageCount() == 0, "nor a line in the history");

        btfchat::Frame inv;
        inv.kind = btfchat::MSG_INVITE; inv.sent = NOW; inv.text = "posso falar?";
        std::string jsInv;
        CHECK(btfchat::SignFrame(ctx, alice, inv, jsInv, err), "alice invites");
        CHECK(in.Deliver(jsInv, alice.address, NOW, g, err), "the invite is delivered");
        CHECK(roster.State(alice.address) == btfchat::PEER_INVITE_IN, "and is pending");
        CHECK(replay.Size() == 1, "now the table has one id");
        CHECK(!in.Deliver(jsInv, alice.address, NOW, g, err), "a resend is dropped");
        // Stopped at CONSENT, not at replay: the invite is already pending, and
        // the gate runs first because it is the cheaper check. Either refusal is
        // correct; which one fires is what the order in the header decides.
        CHECK(err.find("already pending") != std::string::npos,
              "by the gate, before the replay table is even consulted");
        CHECK(roster.PendingCount() == 1, "and the pending list did not grow");

        CHECK(roster.AcceptInvite(alice.address, err), "bob accepts");
        CHECK(in.Deliver(jsMsg, alice.address, NOW, g, err), "alice's message now lands");
        std::vector<btfchat::LogEntry> v;
        history.Conversation(alice.address, v);
        CHECK(v.size() == 1 && v[0].text == "oi antes do convite" && !v[0].outgoing,
              "filed under alice, incoming");
        CHECK(!in.Deliver(jsMsg, alice.address, NOW, g, err), "and it cannot arrive twice");
        CHECK(history.MessageCount() == 1, "so the conversation has one line");
    }

    // The run that found it: both invited, bob's invite reached alice (who
    // became accepted with no button pressed), alice's never reached bob. Bob
    // sat at "invite sent" and dropped alice's "oi" as not accepted.
    printf("a_half_crossed_invite_still_becomes_a_conversation\n");
    {
        btfchat::Roster ra, rb;
        btfchat::ReplayGuard pa, pb;
        btfchat::History ha, hb;
        btfchat::Inbox ina, inb;
        ina.secpctx = ctx; ina.myAddress = alice.address; ina.roster = &ra; ina.replay = &pa; ina.history = &ha;
        inb.secpctx = ctx; inb.myAddress = bob.address;   inb.roster = &rb; inb.replay = &pb; inb.history = &hb;

        CHECK(rb.NoteOutgoingInvite(alice.address, NOW, err), "bob invites alice");
        CHECK(ra.NoteOutgoingInvite(bob.address, NOW, err), "alice invites bob, and hers is lost");
        btfchat::Frame inv;
        inv.kind = btfchat::MSG_INVITE; inv.sent = NOW; inv.text = "oi";
        std::string jsInv;
        CHECK(btfchat::SignFrame(ctx, bob, inv, jsInv, err), "bob signs his invite");
        btfchat::Frame g;
        CHECK(ina.Deliver(jsInv, bob.address, NOW, g, err), "bob's reaches alice");
        CHECK(ra.State(bob.address) == btfchat::PEER_ACCEPTED, "crossing: alice is talking to bob");
        CHECK(ina.strAcceptReply == bob.address, "and is told to send bob her yes");

        // Her yes is lost too; her first message is what reaches bob.
        btfchat::Frame msg;
        msg.kind = btfchat::MSG_TEXT; msg.sent = NOW + 1; msg.text = "oi";
        std::string jsMsg;
        CHECK(btfchat::SignFrame(ctx, alice, msg, jsMsg, err), "alice writes");
        CHECK(inb.Deliver(jsMsg, alice.address, NOW + 1, g, err), "bob takes it: he invited her");
        CHECK(rb.State(alice.address) == btfchat::PEER_ACCEPTED, "and now talks to her");
        std::vector<btfchat::LogEntry> v;
        hb.Conversation(alice.address, v);
        CHECK(v.size() == 1 && v[0].text == "oi", "her message is in his conversation");
        CHECK(inb.strAcceptReply.empty(), "a message asks for no reply of its own");

        // Bob, not knowing, sends his invite again: alice answers with her yes.
        btfchat::Frame again;
        again.kind = btfchat::MSG_INVITE; again.sent = NOW + 2; again.text = "oi?";
        std::string jsAgain;
        CHECK(btfchat::SignFrame(ctx, bob, again, jsAgain, err), "bob invites again");
        CHECK(ina.Deliver(jsAgain, bob.address, NOW + 2, g, err), "alice takes the invite");
        CHECK(ina.strAcceptReply == bob.address && ra.PendingCount() == 0,
              "and answers it with her yes, not a second pending invite");

        // A stranger's message is still refused.
        btfchat::Frame strange;
        strange.kind = btfchat::MSG_TEXT; strange.sent = NOW; strange.text = "oi";
        std::string jsStrange;
        CHECK(btfchat::SignFrame(ctx, eve, strange, jsStrange, err), "eve writes to bob");
        CHECK(!inb.Deliver(jsStrange, eve.address, NOW, g, err), "nobody invited eve: refused");
    }

    printf("deliver_refuses_a_frame_the_peer_did_not_write\n");
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox in;
        in.secpctx = ctx; in.myAddress = bob.address;
        in.roster = &roster; in.replay = &replay; in.history = &history;

        CHECK(roster.NoteIncomingInvite(alice.address, "oi", NOW, err) &&
              roster.AcceptInvite(alice.address, err), "alice is accepted");
        CHECK(roster.NoteIncomingInvite(eve.address, "oi", NOW, err) &&
              roster.AcceptInvite(eve.address, err), "and so is eve");

        btfchat::Frame f;
        f.kind = btfchat::MSG_TEXT; f.sent = NOW; f.text = "sou a alice, confia";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "alice signs a message");

        // Eve is on the link, handing over a genuine frame of alice's. Both are
        // accepted, the signature is real -- and one to one this still must not
        // pass, or eve chooses when alice appears to speak.
        btfchat::Frame g;
        CHECK(!in.Deliver(js, eve.address, NOW, g, err),
              "eve cannot deliver alice's frame on eve's link");
        CHECK(err.find("other than the peer") != std::string::npos, "for the mismatch");
        CHECK(history.MessageCount() == 0, "and nothing was filed");
        CHECK(in.Deliver(js, alice.address, NOW, g, err), "on alice's own link it lands");
    }

    printf("deliver_checks_the_group_admin_proof\n");
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox in;
        in.secpctx = ctx; in.myAddress = bob.address;
        in.roster = &roster; in.replay = &replay; in.history = &history;

        const std::string GID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        const std::string GNAME = "equipe";

        btfchat::Frame bad;
        bad.kind = btfchat::MSG_GROUP_INVITE; bad.sent = NOW;
        bad.group = GID; bad.text = GNAME; bad.proof = std::string(128, '0');
        std::string jsBad;
        CHECK(btfchat::SignFrame(ctx, eve, bad, jsBad, err), "eve signs a group invite");
        btfchat::Frame g;
        CHECK(!in.Deliver(jsBad, eve.address, NOW, g, err), "it is refused");
        CHECK(err.find("proof") != std::string::npos, "for the admin proof");
        CHECK(replay.Size() == 0, "and it took no replay slot");

        std::string proof;
        CHECK(btfchat::SignGroupInvite(ctx, eve, GID, GNAME, bob.address, proof, err),
              "eve signs a real proof for her own group");
        btfchat::Frame ok;
        ok.kind = btfchat::MSG_GROUP_INVITE; ok.sent = NOW;
        ok.group = GID; ok.text = GNAME; ok.proof = proof;
        std::string jsOk;
        CHECK(btfchat::SignFrame(ctx, eve, ok, jsOk, err), "and the frame");
        CHECK(in.Deliver(jsOk, eve.address, NOW, g, err), "that one is delivered");
        btfchat::Group grp;
        CHECK(!roster.GetGroup(GID, grp), "as a pending invite, not a membership");

        // A proof made out to somebody else cannot be pointed at bob.
        btfchat::Roster r2;
        btfchat::ReplayGuard rp2;
        btfchat::History h2;
        btfchat::Inbox in2;
        in2.secpctx = ctx; in2.myAddress = bob.address;
        in2.roster = &r2; in2.replay = &rp2; in2.history = &h2;
        std::string proofForAlice;
        CHECK(btfchat::SignGroupInvite(ctx, eve, GID, GNAME, alice.address, proofForAlice, err),
              "eve signs a proof for alice");
        btfchat::Frame lifted;
        lifted.kind = btfchat::MSG_GROUP_INVITE; lifted.sent = NOW;
        lifted.group = GID; lifted.text = GNAME; lifted.proof = proofForAlice;
        std::string jsLifted;
        CHECK(btfchat::SignFrame(ctx, eve, lifted, jsLifted, err), "and a frame carrying it");
        CHECK(!in2.Deliver(jsLifted, eve.address, NOW, g, err),
              "bob refuses an invite that was issued to alice");
    }

    printf("deliver_group_messages_need_membership\n");
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox in;
        in.secpctx = ctx; in.myAddress = bob.address;
        in.roster = &roster; in.replay = &replay; in.history = &history;

        const std::string GID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        CHECK(roster.CreateGroup(GID, "equipe", bob.address, err), "bob runs a group");

        btfchat::Frame f;
        f.kind = btfchat::MSG_GROUP_TEXT; f.sent = NOW; f.group = GID; f.text = "oi grupo";
        std::string js;
        CHECK(btfchat::SignFrame(ctx, alice, f, js, err), "alice writes to the group");
        btfchat::Frame g;
        CHECK(!in.Deliver(js, alice.address, NOW, g, err), "refused: she is not a member");
        CHECK(replay.Size() == 0, "no replay slot spent");

        CHECK(roster.AddGroupMember(GID, alice.address, bob.address, err), "bob adds her");
        CHECK(in.Deliver(js, alice.address, NOW, g, err), "now her message lands");
        std::vector<btfchat::LogEntry> v;
        history.GroupLog(GID, v);
        CHECK(v.size() == 1 && v[0].text == "oi grupo", "in the group log");

        // Inside a group a frame relayed by another member is normal, so peer and
        // writer are allowed to differ: membership is the rule there.
        btfchat::Frame f2;
        f2.kind = btfchat::MSG_GROUP_TEXT; f2.sent = NOW + 1; f2.group = GID; f2.text = "de novo";
        std::string js2;
        CHECK(btfchat::SignFrame(ctx, alice, f2, js2, err), "alice writes again");
        CHECK(in.Deliver(js2, eve.address, NOW + 1, g, err),
              "and it may arrive over somebody else's link");

        CHECK(roster.Block(alice.address, err), "bob blocks alice");
        btfchat::Frame f3;
        f3.kind = btfchat::MSG_GROUP_TEXT; f3.sent = NOW + 2; f3.group = GID; f3.text = "e agora";
        std::string js3;
        CHECK(btfchat::SignFrame(ctx, alice, f3, js3, err), "she writes once more");
        CHECK(!in.Deliver(js3, alice.address, NOW + 2, g, err),
              "and a block reaches into the group she was in");
    }

    printf("deliver_refuses_garbage_before_anything_else\n");
    {
        btfchat::Roster roster;
        btfchat::ReplayGuard replay;
        btfchat::History history;
        btfchat::Inbox in;
        in.secpctx = ctx; in.myAddress = bob.address;
        in.roster = &roster; in.replay = &replay; in.history = &history;

        btfchat::Frame g;
        CHECK(!in.Deliver("", "", NOW, g, err), "an empty frame is refused");
        CHECK(!in.Deliver("{\"v\":1}", "", NOW, g, err), "a frame with no signature is refused");
        std::string huge = "{\"pad\":\"" + std::string(btfchat::MAX_FRAME_BYTES, 'x') + "\"}";
        CHECK(!in.Deliver(huge, "", NOW, g, err), "an oversized frame is refused");
        CHECK(replay.Size() == 0 && history.MessageCount() == 0 &&
              roster.PendingCount() == 0, "and none of it left a trace");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    secp256k1_context_destroy(ctx);
    return g_fail == 0 ? 0 : 1;
}
