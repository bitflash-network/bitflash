// Standalone tests for btfchat -- identity derivation, the consent gate, the
// sealed store and the inactivity lock.
//
// Build (UCRT64):
//   g++ -std=gnu++14 -DSECP256K1_STATIC -I../deps/include test_btfchat.cpp \
//       btfchat.cpp bip32.cpp btfaddr.cpp -L../deps/lib -lsecp256k1 \
//       -lsodium -lssl -lcrypto -o test_btfchat.exe
//
// Identity derivation runs Argon2id at 256 MiB on purpose, so each DeriveIdentity
// here costs about a second. The tests reuse the identities they derive instead
// of asking for a cheap mode: a cheap mode would exist in production too.

#include "btfchat.h"
#include "bip32.h"
#include "btfaddr.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

// Two published BIP39 vectors -- valid phrases that are worthless on purpose.
static const char* PHRASE_A =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static const char* PHRASE_B =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

static const char* PW_GOOD  = "cavalo-bateria-grampo";   // 21 characters
static const char* PW_OTHER = "outra-senha-comprida";    // 20 characters
static const char* PW_SHORT = "curta";                   // 5 -- must be refused

static bool AllZero(const unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; i++) if (p[i]) return false;
    return true;
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }

    std::string err;

    // ---- identity ----------------------------------------------------------

    printf("identity_refuses_bad_input\n");
    {
        btfchat::Identity id;
        CHECK(!btfchat::DeriveIdentity(PHRASE_A, PW_SHORT, id, err),
              "a password under 12 characters is refused");
        CHECK(err.find("12") != std::string::npos, "and the error says why");
        CHECK(!btfchat::DeriveIdentity("not a real recovery phrase at all", PW_GOOD, id, err),
              "a phrase that does not validate is refused");
        CHECK(!btfchat::DeriveIdentity(PHRASE_A, "", id, err),
              "an empty password is refused");
    }

    printf("identity_is_deterministic_and_password_bound\n");
    btfchat::Identity idA1, idA2, idAother, idB;
    {
        CHECK(btfchat::DeriveIdentity(PHRASE_A, PW_GOOD, idA1, err), "phrase A + password derives");
        if (!err.empty()) printf("       (%s)\n", err.c_str());
        CHECK(btfchat::DeriveIdentity(PHRASE_A, PW_GOOD, idA2, err), "the same inputs derive again");
        CHECK(idA1.address == idA2.address, "the same phrase and password give the same address");
        CHECK(memcmp(idA1.sign_sk, idA2.sign_sk, 32) == 0, "and the same signing key");

        CHECK(btfchat::DeriveIdentity(PHRASE_A, PW_OTHER, idAother, err),
              "the same phrase with another password derives");
        // This is the whole point of the session password: the phrase alone
        // does not get you in, because the phrase alone lands somewhere else.
        CHECK(idAother.address != idA1.address,
              "another password on the same phrase is a DIFFERENT identity");
        CHECK(memcmp(idAother.chan_sk, idA1.chan_sk, 32) != 0, "with a different channel key");
        CHECK(memcmp(idAother.store_key, idA1.store_key, 32) != 0, "and a different store key");

        CHECK(btfchat::DeriveIdentity(PHRASE_B, PW_GOOD, idB, err), "phrase B derives");
        CHECK(idB.address != idA1.address, "a different phrase is a different identity");
    }

    printf("identity_shape\n");
    {
        CHECK(idA1.address.size() > 4 &&
              idA1.address.compare(idA1.address.size() - 4, 4, ".btf") == 0,
              "the address is a .btf");
        unsigned char parsed[32];
        CHECK(btf::ParseAddress(idA1.address, parsed) &&
              memcmp(parsed, idA1.sign_pk, 32) == 0,
              "the address decodes back to the signing public key");

        unsigned char pk[32];
        crypto_scalarmult_base(pk, idA1.chan_sk);
        CHECK(memcmp(pk, idA1.chan_pk, 32) == 0, "the channel public key matches its secret");

        CHECK(!AllZero(idA1.sign_sk, 32) && !AllZero(idA1.chan_sk, 32) &&
              !AllZero(idA1.store_key, 32), "no key came out zero");
        CHECK(memcmp(idA1.sign_sk, idA1.chan_sk, 32) != 0 &&
              memcmp(idA1.sign_sk, idA1.store_key, 32) != 0 &&
              memcmp(idA1.chan_sk, idA1.store_key, 32) != 0,
              "signing, channel and store keys are three different keys");
    }

    printf("chat_key_is_not_the_wallet_key\n");
    {
        // The wallet's tree from the same twelve words, with no BIP39 passphrase
        // -- exactly what -restorephrase installs. Nothing in the chat tree may
        // equal anything in it, or being reachable would leak spending material.
        std::string strNorm, e;
        CHECK(bitflash::BIP39ValidateMnemonic(PHRASE_A, strNorm, e), "phrase A validates");
        std::vector<unsigned char> seed;
        CHECK(bitflash::BIP39MnemonicToSeed(strNorm, std::string(), seed, e), "seed derives");

        bitflash::BIP32PrivateNode walletRoot;
        CHECK(bitflash::BIP32MasterFromSeed(seed, walletRoot, e), "wallet master derives");
        CHECK(walletRoot.privateKey.size() == 32 &&
              memcmp(&walletRoot.privateKey[0], idA1.sign_sk, 32) != 0,
              "the chat key is not the wallet master key");

        bitflash::BIP32PrivateNode acct;
        std::vector<unsigned int> path;
        path.push_back(0 | bitflash::BIP32_HARDENED);
        path.push_back(0 | bitflash::BIP32_HARDENED);
        CHECK(bitflash::BIP32DerivePath(walletRoot, path, acct, e), "wallet m/0'/0' derives");
        CHECK(memcmp(&acct.privateKey[0], idA1.sign_sk, 32) != 0 &&
              memcmp(&acct.privateKey[0], idA1.chan_sk, 32) != 0,
              "and it is not the first wallet account key either");

        // Same seed, so if the domain separation were missing this would collide.
        btfchat::Identity fromSeed;
        CHECK(btfchat::DeriveIdentityFromSeed(seed, PW_GOOD, fromSeed, e),
              "deriving from the seed directly works");
        CHECK(fromSeed.address == idA1.address,
              "and lands on the same identity as deriving from the phrase");
    }

    // ---- consent -----------------------------------------------------------

    const std::string ME    = idA1.address;
    const std::string ALICE = idB.address;
    const std::string BOB   = idAother.address;
    const std::string EVE   = "eve2222222222222222222222222222222222222222222222222222z.btf";

    printf("an_unknown_address_may_send_exactly_one_invite\n");
    {
        btfchat::Roster r;
        CHECK(r.State(ALICE) == btfchat::PEER_UNKNOWN, "a stranger starts unknown");
        CHECK(r.MayDeliver(ALICE, btfchat::MSG_INVITE, err), "a stranger may invite");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_TEXT, err), "a stranger may NOT send a message");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_INVITE_ACCEPT, err),
              "a stranger may not accept an invite nobody sent");
        CHECK(!r.MayDeliver("", btfchat::MSG_INVITE, err), "an empty sender is refused");
        CHECK(!r.MayDeliver(ALICE, (btfchat::MsgKind)99, err), "an unknown frame kind is refused");

        CHECK(r.NoteIncomingInvite(ALICE, "oi, sou a alice", 1000, err), "the invite is recorded");
        CHECK(r.State(ALICE) == btfchat::PEER_INVITE_IN, "the state is invite-in");
        CHECK(r.PendingCount() == 1, "one invite waits");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_TEXT, err),
              "a pending invite still cannot send a message");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_INVITE, err),
              "and cannot invite a second time");
        CHECK(!r.NoteIncomingInvite(ALICE, "oi de novo", 1001, err),
              "a second invite is not a second notification");
        CHECK(r.PendingCount() == 1, "the list did not grow");
    }

    printf("a_conversation_needs_an_explicit_accept\n");
    {
        btfchat::Roster r;
        CHECK(!r.AcceptInvite(ALICE, err), "accepting someone who never asked is impossible");
        CHECK(r.NoteIncomingInvite(ALICE, "oi", 1000, err), "invite arrives");
        CHECK(r.AcceptInvite(ALICE, err), "accept works");
        CHECK(r.State(ALICE) == btfchat::PEER_ACCEPTED, "the state is accepted");
        CHECK(r.PendingCount() == 0, "the invite left the pending list");
        CHECK(r.MayDeliver(ALICE, btfchat::MSG_TEXT, err), "now a message may arrive");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_INVITE, err),
              "an invite from someone we already talk to is refused");
    }

    printf("the_roster_can_list_who_is_in_it\n");
    {
        btfchat::Roster r;
        std::vector<std::string> v;
        r.Accepted(v);
        CHECK(v.empty(), "a fresh roster has no contacts");

        CHECK(r.NoteIncomingInvite(BOB, "oi", 1000, err), "bob invites");
        r.Accepted(v);
        CHECK(v.empty(), "a pending invite is not a contact");

        CHECK(r.AcceptInvite(BOB, err) && r.NoteIncomingInvite(ALICE, "oi", 1001, err) &&
              r.AcceptInvite(ALICE, err), "both are accepted");
        r.Accepted(v);
        CHECK(v.size() == 2, "two contacts");
        CHECK(v[0] < v[1], "listed in a stable order, so two runs look the same");

        std::vector<std::string> b;
        r.Blocked(b);
        CHECK(b.empty(), "nobody is blocked yet");
        CHECK(r.Block(ALICE, err), "alice is blocked");
        r.Accepted(v);
        r.Blocked(b);
        CHECK(v.size() == 1 && v[0] == BOB, "she is no longer a contact");
        CHECK(b.size() == 1 && b[0] == ALICE, "and she is on the blocked list");
    }

    printf("declining_is_not_blocking\n");
    {
        btfchat::Roster r;
        CHECK(r.NoteIncomingInvite(ALICE, "oi", 1000, err), "invite arrives");
        CHECK(r.DeclineInvite(ALICE, err), "declining works");
        CHECK(r.State(ALICE) == btfchat::PEER_UNKNOWN, "the address is a stranger again");
        CHECK(r.MayDeliver(ALICE, btfchat::MSG_INVITE, err), "so it may ask again some day");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_TEXT, err), "but still cannot send a message");
    }

    printf("blocking_is_permanent_and_they_cannot_undo_it\n");
    {
        btfchat::Roster r;
        CHECK(r.NoteIncomingInvite(EVE, "clique aqui", 1000, err), "an invite arrives");
        CHECK(r.Block(EVE, err), "blocking works");
        CHECK(r.State(EVE) == btfchat::PEER_BLOCKED, "the state is blocked");
        CHECK(r.PendingCount() == 0, "the block cleared the invite off the screen");

        // Everything below is the same attacker trying every door.
        CHECK(!r.MayDeliver(EVE, btfchat::MSG_INVITE, err), "a blocked address cannot invite");
        CHECK(!r.MayDeliver(EVE, btfchat::MSG_TEXT, err), "cannot send a message");
        CHECK(!r.MayDeliver(EVE, btfchat::MSG_GROUP_INVITE, err),
              "cannot invite us to a group -- the door other chats leave open");
        CHECK(!r.NoteIncomingInvite(EVE, "sou outra pessoa", 2000, err),
              "re-inviting does not clear the block");
        CHECK(!r.AcceptInvite(EVE, err), "and there is nothing to accept");
        CHECK(!r.NoteOutgoingInvite(EVE, 2000, err),
              "we cannot even invite them ourselves without unblocking first");
        CHECK(r.State(EVE) == btfchat::PEER_BLOCKED, "still blocked after all of that");
    }

    printf("blocking_before_they_ever_write\n");
    {
        btfchat::Roster r;
        CHECK(r.Block(EVE, err), "an address can be blocked cold");
        CHECK(!r.MayDeliver(EVE, btfchat::MSG_INVITE, err), "and never gets a first invite");
    }

    printf("crossing_invites_are_an_agreement\n");
    {
        btfchat::Roster r;
        CHECK(r.NoteOutgoingInvite(ALICE, 1000, err), "we invite alice");
        CHECK(r.State(ALICE) == btfchat::PEER_INVITE_OUT, "state is invite-out");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_TEXT, err),
              "she cannot write before accepting");
        CHECK(r.MayDeliver(ALICE, btfchat::MSG_INVITE, err),
              "her invite crossing ours is allowed");
        CHECK(r.NoteIncomingInvite(ALICE, "oi", 1001, err), "and is recorded");
        CHECK(r.State(ALICE) == btfchat::PEER_ACCEPTED, "both invited, so both agreed");
        CHECK(r.PendingCount() == 0, "nothing is left waiting on a human");

        btfchat::Roster r2;
        CHECK(r2.NoteIncomingInvite(ALICE, "oi", 1000, err), "the other order: she invites first");
        CHECK(r2.NoteOutgoingInvite(ALICE, 1001, err), "we invite back");
        CHECK(r2.State(ALICE) == btfchat::PEER_ACCEPTED, "which also counts as accepting");
    }

    printf("the_invite_note_is_one_line\n");
    {
        btfchat::Roster r;
        std::string wall(btfchat::MAX_INVITE_NOTE + 1, 'x');
        CHECK(!r.NoteIncomingInvite(ALICE, wall, 1000, err), "an over-long note is refused");
        CHECK(r.State(ALICE) == btfchat::PEER_UNKNOWN, "and nothing was recorded");
        std::string edge(btfchat::MAX_INVITE_NOTE, 'x');
        CHECK(r.NoteIncomingInvite(ALICE, edge, 1000, err), "exactly at the limit is fine");
    }

    printf("the_pending_list_has_a_ceiling\n");
    {
        btfchat::Roster r;
        char buf[128];
        for (size_t i = 0; i < btfchat::MAX_PENDING_INVITES; i++)
        {
            snprintf(buf, sizeof(buf), "spam%04u222222222222222222222222222222222222222222222222z.btf",
                     (unsigned)i);
            if (!r.NoteIncomingInvite(buf, "x", 1000 + (int64_t)i, err)) { g_fail++; break; }
        }
        CHECK(r.PendingCount() == btfchat::MAX_PENDING_INVITES, "the list fills to the ceiling");
        CHECK(!r.NoteIncomingInvite(ALICE, "oi", 9999, err), "and then refuses more");
        // Documented tradeoff: the flood cannot evict what is already there.
        snprintf(buf, sizeof(buf), "spam%04u222222222222222222222222222222222222222222222222z.btf", 0u);
        CHECK(r.State(buf) == btfchat::PEER_INVITE_IN,
              "a flood cannot evict an invite that arrived earlier");
    }

    // ---- groups ------------------------------------------------------------

    const std::string GID  = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const std::string GID2 = "ffffffffffffffffffffffffffffffff";

    printf("the_creator_is_the_admin\n");
    {
        btfchat::Roster r;
        CHECK(r.CreateGroup(GID, "equipe bitflash", ME, err), "creating a group works");
        btfchat::Group g;
        CHECK(r.GetGroup(GID, g), "the group is there");
        CHECK(g.admin == ME, "the creator is the admin");
        CHECK(g.IsMember(ME), "and is a member from the start");
        CHECK(!r.CreateGroup(GID, "outra", ME, err), "the same id cannot be reused");
        CHECK(!r.CreateGroup(GID2, std::string(btfchat::MAX_GROUP_NAME + 1, 'x'), ME, err),
              "an over-long group name is refused");
        CHECK(!r.CreateGroup(GID2, "", ME, err), "an unnamed group is refused");
    }

    printf("a_group_invite_needs_the_admin_and_an_accept\n");
    {
        btfchat::Roster r;
        // ALICE runs the group; BOB is just a member trying to drag us in.
        CHECK(!r.NoteGroupInvite(GID, "grupo", ALICE, BOB, 1000, err),
              "a member who is not the admin cannot invite");
        CHECK(r.NoteGroupInvite(GID, "grupo", ALICE, ALICE, 1000, err),
              "the admin can invite");
        btfchat::Group g;
        CHECK(!r.GetGroup(GID, g), "we are not in it yet -- an invite is not a membership");
        CHECK(!r.MayDeliverGroup(GID, ALICE, err), "so its frames are refused");
        CHECK(!r.NoteGroupInvite(GID, "grupo", ALICE, ALICE, 1001, err),
              "a second invite to the same group is not a second notification");

        CHECK(r.AcceptGroupInvite(GID, ME, err), "accepting works");
        CHECK(r.GetGroup(GID, g) && g.IsMember(ME), "now we are a member");
        CHECK(r.MayDeliverGroup(GID, ALICE, err), "and the admin's frames arrive");
        // Being in a room with someone is not agreeing to hear them privately.
        CHECK(r.State(ALICE) == btfchat::PEER_UNKNOWN,
              "joining a group did not accept the admin as a contact");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_TEXT, err),
              "so she still cannot message us directly");
    }

    printf("group_frames_need_membership_on_both_ends\n");
    {
        btfchat::Roster r;
        CHECK(r.CreateGroup(GID, "equipe", ME, err), "we create a group");
        CHECK(r.AddGroupMember(GID, ALICE, ME, err), "the admin adds alice");
        CHECK(r.MayDeliverGroup(GID, ALICE, err), "alice's group frames arrive");
        CHECK(!r.MayDeliverGroup(GID, BOB, err), "a non-member's do not");
        CHECK(!r.MayDeliverGroup(GID2, ALICE, err), "nor frames for a group we are not in");
        CHECK(!r.MayDeliver(ALICE, btfchat::MSG_GROUP_TEXT, err),
              "a group frame cannot be judged by its sender alone");

        CHECK(!r.AddGroupMember(GID, BOB, ALICE, err), "a member cannot add members");
        CHECK(!r.RemoveGroupMember(GID, ALICE, BOB, err), "a stranger cannot remove members");
        CHECK(!r.RemoveGroupMember(GID, ME, ME, err), "the admin cannot be removed");
        CHECK(r.RemoveGroupMember(GID, ALICE, ME, err), "the admin can remove alice");
        CHECK(!r.MayDeliverGroup(GID, ALICE, err), "and her frames stop arriving");
    }

    printf("blocking_reaches_into_groups\n");
    {
        btfchat::Roster r;
        CHECK(r.CreateGroup(GID, "equipe", ME, err), "we create a group");
        CHECK(r.AddGroupMember(GID, EVE, ME, err), "eve is a member");
        CHECK(r.MayDeliverGroup(GID, EVE, err), "her frames arrive while she is welcome");
        CHECK(r.Block(EVE, err), "we block her");
        CHECK(!r.MayDeliverGroup(GID, EVE, err), "her group frames stop too");
        btfchat::Group g;
        CHECK(r.GetGroup(GID, g) && !g.IsMember(EVE),
              "and she is out of the group we admin");
        CHECK(!r.AddGroupMember(GID, EVE, ME, err), "she cannot be added back while blocked");

        // A group someone else runs: we cannot remove her, but she does not
        // reach our screen either.
        btfchat::Roster r2;
        CHECK(r2.NoteGroupInvite(GID2, "grupo do alice", ALICE, ALICE, 1000, err), "invited");
        CHECK(r2.AcceptGroupInvite(GID2, ME, err), "accepted");
        CHECK(r2.Block(EVE, err), "we block eve");
        CHECK(!r2.MayDeliverGroup(GID2, EVE, err),
              "a blocked member of someone else's group still cannot reach us");
    }

    printf("leaving_a_group_forgets_it\n");
    {
        btfchat::Roster r;
        CHECK(r.NoteGroupInvite(GID, "grupo", ALICE, ALICE, 1000, err), "invited");
        CHECK(r.AcceptGroupInvite(GID, ME, err), "accepted");
        CHECK(r.LeaveGroup(GID, ME, err), "leaving works");
        btfchat::Group g;
        CHECK(!r.GetGroup(GID, g), "the group is gone");
        CHECK(!r.MayDeliverGroup(GID, ALICE, err), "and its frames are refused");
        CHECK(!r.LeaveGroup(GID, ME, err), "leaving twice fails");
    }

    // ---- persistence -------------------------------------------------------

    printf("the_store_survives_a_round_trip\n");
    {
        btfchat::Roster r;
        r.NoteIncomingInvite(ALICE, "oi, sou a alice", 1000, err);
        r.AcceptInvite(ALICE, err);
        r.NoteIncomingInvite(BOB, "posso falar?", 1100, err);
        r.Block(EVE, err);
        r.CreateGroup(GID, "equipe bitflash", ME, err);
        r.AddGroupMember(GID, ALICE, ME, err);

        std::string js = r.ToJson();
        btfchat::Roster r2;
        CHECK(r2.FromJson(js, err), "the store reloads");
        CHECK(r2.State(ALICE) == btfchat::PEER_ACCEPTED, "an accepted contact stays accepted");
        CHECK(r2.State(BOB) == btfchat::PEER_INVITE_IN, "a pending invite stays pending");
        CHECK(r2.PendingCount() == 1, "with its note in the list");
        CHECK(r2.State(EVE) == btfchat::PEER_BLOCKED, "a block survives a restart");
        btfchat::Group g;
        CHECK(r2.GetGroup(GID, g) && g.admin == ME && g.IsMember(ALICE),
              "the group and its membership survive");
        CHECK(!r2.FromJson("{", err), "a truncated store is refused");
        CHECK(!r2.FromJson("[]", err), "a store that is not an object is refused");
        CHECK(r2.State(ALICE) == btfchat::PEER_ACCEPTED,
              "and a refused load does not wipe what was loaded");
    }

    printf("a_corrupt_store_fails_closed\n");
    {
        // A state number this build does not know must not become "accepted".
        btfchat::Roster r;
        std::string js = "{\"v\":1,\"peers\":{\"" + ALICE + "\":42}}";
        CHECK(r.FromJson(js, err), "the store loads");
        CHECK(r.State(ALICE) == btfchat::PEER_BLOCKED,
              "an unknown peer state becomes blocked, not accepted");

        // A group invite written down before the block does not come back.
        btfchat::Roster r2;
        std::string js2 = "{\"v\":1,\"peers\":{\"" + EVE + "\":4},"
                          "\"group_invites\":[{\"id\":\"" + GID + "\",\"name\":\"g\","
                          "\"admin\":\"" + EVE + "\",\"from\":\"" + EVE + "\",\"t\":1}]}";
        CHECK(r2.FromJson(js2, err), "the store loads");
        btfchat::Group g;
        CHECK(!r2.GetGroup(GID, g), "we are not in the group");
        CHECK(!r2.MayDeliver(EVE, btfchat::MSG_GROUP_INVITE, err),
              "and the blocked inviter is still blocked");
    }

    printf("the_store_is_sealed_on_disk\n");
    {
        btfchat::Roster r;
        r.NoteIncomingInvite(ALICE, "oi, sou a alice", 1000, err);
        r.AcceptInvite(ALICE, err);
        std::string plain = r.ToJson();

        std::vector<unsigned char> sealed;
        CHECK(btfchat::SealStore(idA1, plain, sealed), "the store seals");
        CHECK(sealed.size() > plain.size(), "the sealed form carries a nonce and a tag");

        // Who you talk to is the metadata that matters, so it must not be
        // readable in the file.
        std::string blob((const char*)&sealed[0], sealed.size());
        CHECK(blob.find(ALICE) == std::string::npos,
              "a contact's address does not appear in the clear");
        CHECK(blob.find("alice") == std::string::npos, "nor the note");

        std::string opened;
        CHECK(btfchat::OpenStore(idA1, &sealed[0], sealed.size(), opened), "it opens again");
        CHECK(opened == plain, "with the same contents");

        std::vector<unsigned char> sealed2;
        CHECK(btfchat::SealStore(idA1, plain, sealed2) && sealed2 != sealed,
              "sealing twice gives two different files");

        std::vector<unsigned char> bad = sealed;
        bad[bad.size() - 1] ^= 1;
        CHECK(!btfchat::OpenStore(idA1, &bad[0], bad.size(), opened), "a tampered tag is refused");
        bad = sealed;
        bad[0] ^= 1;
        CHECK(!btfchat::OpenStore(idA1, &bad[0], bad.size(), opened), "a tampered nonce is refused");

        // A wrong session password is exactly this case, from here.
        CHECK(!btfchat::OpenStore(idAother, &sealed[0], sealed.size(), opened),
              "another identity cannot open it");
        CHECK(!btfchat::OpenStore(idA1, &sealed[0], 8, opened), "a truncated file is refused");
    }

    // ---- inactivity lock ---------------------------------------------------

    printf("the_session_locks_itself_after_fifteen_minutes\n");
    {
        btfchat::AutoLock lock;
        CHECK(lock.IsLocked(1000), "a session starts locked");
        lock.Unlock(1000);
        CHECK(!lock.IsLocked(1000), "unlocking works");
        CHECK(lock.SecondsLeft(1000) == btfchat::LOCK_AFTER_SECONDS, "the clock starts full");
        CHECK(!lock.IsLocked(1000 + btfchat::LOCK_AFTER_SECONDS - 1),
              "one second before the limit it is still open");
        CHECK(lock.IsLocked(1000 + btfchat::LOCK_AFTER_SECONDS),
              "at fifteen minutes of silence it locks");
        CHECK(lock.SecondsLeft(1000 + btfchat::LOCK_AFTER_SECONDS) == 0, "and reports no time left");

        lock.Unlock(2000);
        lock.Touch(2500);
        CHECK(!lock.IsLocked(2500 + btfchat::LOCK_AFTER_SECONDS - 1),
              "activity pushes the deadline forward");
        CHECK(lock.IsLocked(2500 + btfchat::LOCK_AFTER_SECONDS), "but only that far");

        // The point of the timeout is the case where someone else is at the
        // keyboard: their clicks must not keep the session open.
        lock.Lock();
        lock.Touch(3000);
        CHECK(lock.IsLocked(3000), "activity does not unlock a locked session");

        lock.Unlock(4000);
        CHECK(lock.IsLocked(3000), "a clock that went backwards counts as silence");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
