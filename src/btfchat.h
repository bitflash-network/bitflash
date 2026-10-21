// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat -- identity, consent and local storage for the Bitflash chat.
//
// This is the layer ABOVE btfchan (which encrypts a live connection) and BELOW
// the interface. It answers three questions, and nothing else:
//
//   who am I          -- derived from the recovery phrase and a session password
//   may this arrive   -- a default-deny gate: nothing is delivered from someone
//                        who was not explicitly accepted
//   what is kept here -- the contact list, sealed, because who you talk to is
//                        the part that betrays you even when the words do not
//
// IDENTITY. The chat key is NOT the mining key and never can be: it comes from
// the wallet seed through its own hardened path, under its own domain string,
// and only the public half ever leaves the machine. Two consequences the design
// depends on: the twelve words restore the chat along with the coins, and a
// chat address never links back to a coinbase, so being reachable does not
// publish what you mined.
//
// The session password is mixed into the derivation, not merely checked against
// something stored. That is what makes it required on a new machine: the phrase
// alone lands on a different, empty identity. It also means the password cannot
// be "recovered" -- there is nothing to reset. A wrong one is not an error, it
// is a different account, so the address is shown on unlock and the user is the
// one who recognizes it. Argon2id stands between the password and the key, so
// guessing it offline costs 256 MiB and real time per attempt.
//
// CONSENT. Every frame is checked against the roster before anything else looks
// at it, and the only thing an unknown address may send is one invite. Not a
// message, not a file, not a group add. Accepting is a deliberate act; blocking
// is permanent and cannot be undone by the other side re-inviting, because an
// unblock that the blocked party can trigger is not a block. A blocked address
// also cannot reach you through a group -- that door is the one every chat app
// leaves open, and it is shut here on purpose.
//
// STORAGE. The contact list, the pending invites and the group membership are
// sealed with a key from the same root. An attacker with the file learns how
// many bytes it is. The plaintext never touches disk.

#ifndef BITFLASH_BTFCHAT_H
#define BITFLASH_BTFCHAT_H

#include <map>
#include <string>
#include <vector>
#include <stdint.h>

namespace btfchat
{

// Minimum session password. Twelve is the founder's number and it is the right
// order of magnitude: Argon2id at 256 MiB makes a twelve-character password
// that is not a dictionary phrase expensive enough to guess, and makes a short
// one no safer, which is why short ones are refused rather than warned about.
static const size_t MIN_PASSWORD_CHARS = 12;

// Longest note that may ride along with an invite. An invite is the one thing a
// stranger can put on your screen, so it is a line of text and not a canvas:
// no images, no links rendered, no length to hide a wall of abuse in.
static const size_t MAX_INVITE_NOTE = 140;

// Longest group name, same reasoning -- a group invite shows its name.
static const size_t MAX_GROUP_NAME = 64;

// How many invites may wait at once.
//
// This bounds memory, and that is all it bounds. Identities are free, so an
// attacker can fill the list and then legitimate invites are refused until the
// user clears it. The alternative -- dropping the oldest to make room -- is
// worse: it lets the same attacker evict a real invite with noise. So the list
// fills, says so, and waits for a human. Whoever wants to be reachable through
// a flood has to be reachable some other way; nobody has solved this without
// charging for identities, and charging for identities was rejected.
static const size_t MAX_PENDING_INVITES = 128;

// The session locks itself after this long without activity. It re-locks the
// identity in memory; it does not delete anything.
static const int64_t LOCK_AFTER_SECONDS = 15 * 60;

// ---- Identity --------------------------------------------------------------

// An unlocked identity. Holds secret key material: clear it with
// IdentityClear() when the session locks or ends.
struct Identity
{
    unsigned char sign_sk[32];  // secp256k1 scalar -- signs invites and group acts
    unsigned char sign_pk[32];  // x-only public key; this IS the address
    unsigned char chan_sk[32];  // x25519 static secret, handed to btfchan
    unsigned char chan_pk[32];  // x25519 static public, published in the descriptor
    unsigned char store_key[32];// seals the local store
    std::string   address;      // "<base32>.btf", what the user reads out loud
};

void IdentityClear(Identity& id);

// Derive the chat identity from a BIP39 recovery phrase and the session
// password. Rejects a phrase that does not validate and a password shorter than
// MIN_PASSWORD_CHARS. Costs one Argon2id pass (256 MiB, roughly a second) by
// design -- there is no cheap mode, because a cheap mode is the one an attacker
// would use.
bool DeriveIdentity(const std::string& mnemonic, const std::string& password,
                    Identity& out, std::string& errOut);

// Same, when the caller already has the 64-byte BIP39 seed. Note that this is
// the seed WITHOUT a BIP39 passphrase applied; the session password enters
// here, separately, so the chat identity and the wallet's 25th-word passphrase
// stay independent knobs.
bool DeriveIdentityFromSeed(const std::vector<unsigned char>& seed,
                            const std::string& password,
                            Identity& out, std::string& errOut);

// ---- Consent ---------------------------------------------------------------

enum PeerState
{
    PEER_UNKNOWN = 0, // never heard of; may send exactly one invite
    PEER_INVITE_IN,   // asked to talk to us; still cannot send anything
    PEER_INVITE_OUT,  // we asked them; we may not send anything else yet
    PEER_ACCEPTED,    // a conversation exists
    PEER_BLOCKED,     // terminal, and only we can have put it here
};

// What a frame claims to be. The gate decides per kind, so a new kind cannot
// quietly inherit the permissions of an old one.
enum MsgKind
{
    MSG_INVITE = 0,      // "let's talk" + a short note
    MSG_INVITE_ACCEPT,   // answer to an invite we sent
    MSG_TEXT,            // a message
    MSG_GROUP_INVITE,    // "join <group>", signed by the group admin
    MSG_GROUP_TEXT,      // a message inside a group
    // Money in the conversation. The chat holds no coins: the person's own
    // Bitflash wallet pays and receives (btfchatwallet.h). What the chat adds
    // is that the address you pay was signed by the person you are talking to,
    // so a payment cannot be redirected by anything between you.
    MSG_PAY_ADDRESS,     // "pay me here": a B address of the sender's wallet
    MSG_PAYMENT,         // "I paid you": txid, amount, the address it went to
    // Atomic swaps BTF<->BTC arranged in the chat (chatswap.h). An offer is a
    // post in a public community; the steps go in the conversation.
    MSG_SWAP_OFFER,      // a community post: "I give X, I want Y"
    MSG_SWAP,            // one step of a swap between the two of us
};

struct Invite
{
    std::string address;  // the other side's .btf
    std::string note;     // at most MAX_INVITE_NOTE characters
    int64_t     received; // unix seconds, for ordering the list
    Invite() : received(0) {}
};

struct Group
{
    std::string              id;      // 32 random bytes, hex
    std::string              name;
    std::string              admin;   // .btf of whoever created it
    std::vector<std::string> members; // accepted members, admin included
    Group() {}
    bool IsMember(const std::string& addr) const;
};

// The consent state for one identity: who may speak to us, who asked, who is
// blocked, and which groups we are in. Pure logic -- no network, no disk, no
// clock except what the caller passes in, so every rule here is testable.
class Roster
{
public:
    Roster() {}

    // ---- queries
    PeerState State(const std::string& addr) const;
    bool      IsAccepted(const std::string& addr) const;
    bool      IsBlocked(const std::string& addr) const;
    size_t    PendingCount() const { return mapPending.size(); }
    void      Pending(std::vector<Invite>& out) const;
    // Everyone we have an accepted conversation with, and everyone we blocked.
    // Sorted, so the interface does not have to and two runs look the same.
    void      Accepted(std::vector<std::string>& out) const;
    // Everyone we invited who has not answered yet.
    void      Invited(std::vector<std::string>& out) const;
    void      Blocked(std::vector<std::string>& out) const;
    bool      GetGroup(const std::string& id, Group& out) const;
    void      Groups(std::vector<Group>& out) const;

    // THE GATE. Called on every inbound frame before it is parsed, shown,
    // stored or counted. Default deny: a kind this build does not know about,
    // or an address in any state other than the one that kind requires, is
    // refused. `errOut` says why, for the log -- never for the sender.
    bool MayDeliver(const std::string& addr, MsgKind kind, std::string& errOut) const;

    // ---- transitions
    // Record an invite that arrived. Refused if the address is blocked, if a
    // conversation or invite already exists (a second invite is not a second
    // notification -- that is how invites become a spam channel), if the note
    // is too long, or if the pending list is full.
    bool NoteIncomingInvite(const std::string& addr, const std::string& note,
                            int64_t nNow, std::string& errOut);

    // Record an invite we are sending. Refused to a blocked address: the point
    // of blocking is that nothing crosses, in either direction.
    bool NoteOutgoingInvite(const std::string& addr, int64_t nNow, std::string& errOut);

    // Accept an invite that arrived. Only valid from PEER_INVITE_IN -- there is
    // no way to accept someone who never asked, so no way for the interface to
    // create a conversation the user did not consent to.
    bool AcceptInvite(const std::string& addr, std::string& errOut);

    // They accepted the invite we sent. Only valid from PEER_INVITE_OUT.
    bool NoteInviteAccepted(const std::string& addr, std::string& errOut);

    // Refuse an invite without blocking: it disappears, and that address may
    // ask again some day.
    bool DeclineInvite(const std::string& addr, std::string& errOut);

    // Block, permanently. Valid from any state, including PEER_UNKNOWN (block
    // before they ever write). Removes any pending invite, ends any
    // conversation, and drops them out of every group we admin.
    bool Block(const std::string& addr, std::string& errOut);

    // ---- groups
    // Create a group. We are the admin, and the admin is a member from the
    // start. Members are invited afterwards and each one has to accept.
    bool CreateGroup(const std::string& id, const std::string& name,
                     const std::string& myAddress, std::string& errOut);

    // A group invite arrived. Refused if the inviter is blocked (this is the
    // hole that lets a blocked stranger back onto your screen in every other
    // chat app), if the inviter is not the admin of the group they are inviting
    // to, if we are already in it, or if the pending list is full.
    bool NoteGroupInvite(const std::string& groupId, const std::string& name,
                         const std::string& adminAddr, const std::string& fromAddr,
                         int64_t nNow, std::string& errOut);

    // Accept a pending group invite. Only then do we become a member.
    bool AcceptGroupInvite(const std::string& groupId, const std::string& myAddress,
                           std::string& errOut);

    // Admin only: add an accepted member to a group we created.
    bool AddGroupMember(const std::string& groupId, const std::string& memberAddr,
                        const std::string& myAddress, std::string& errOut);

    // Admin only: remove a member.
    bool RemoveGroupMember(const std::string& groupId, const std::string& memberAddr,
                           const std::string& myAddress, std::string& errOut);

    // Leave a group we are in.
    bool LeaveGroup(const std::string& groupId, const std::string& myAddress,
                    std::string& errOut);

    // May this group frame be delivered? The sender has to be a member of that
    // group and not blocked -- membership is not enough, because a member we
    // blocked personally is still someone we said we do not want to hear.
    bool MayDeliverGroup(const std::string& groupId, const std::string& fromAddr,
                         std::string& errOut) const;

    // ---- persistence (see SealStore/OpenStore for the sealed form)
    std::string ToJson() const;
    bool        FromJson(const std::string& jsonStr, std::string& errOut);

private:
    struct GroupInvite
    {
        Group       group;
        std::string fromAddr;
        int64_t     received;
        GroupInvite() : received(0) {}
    };

    std::map<std::string, PeerState>   mapPeers;   // address -> state
    std::map<std::string, Invite>      mapPending; // address -> invite
    std::map<std::string, Group>       mapGroups;  // id -> group we are in
    std::map<std::string, GroupInvite> mapGroupInvites;

    size_t TotalPending() const { return mapPending.size() + mapGroupInvites.size(); }
};

// ---- Local store -----------------------------------------------------------

// Seal the roster for disk with the identity's store key. XChaCha20-Poly1305
// with a random 24-byte nonce prepended, so the same roster sealed twice is two
// different files and the size is all an attacker gets.
bool SealStore(const Identity& id, const std::string& plain,
               std::vector<unsigned char>& out);

// Open a sealed store. Fails on a truncated file, a tampered one, or the wrong
// identity -- which is also what a wrong session password looks like from here.
bool OpenStore(const Identity& id, const unsigned char* in, size_t n,
               std::string& out);

// ---- Inactivity lock -------------------------------------------------------

// Locks itself after LOCK_AFTER_SECONDS without a Touch(). The caller supplies
// the clock: nothing here reads the system time, so the rule is testable and
// cannot be bent by a timezone or a suspended laptop.
class AutoLock
{
public:
    AutoLock() : nLastActivity(0), fLocked(true) {}

    // The user did something. A locked session does not unlock by activity --
    // only Unlock() does that, and Unlock() is what the password guards.
    void Touch(int64_t nNow);

    // Unlock at `nNow` (the caller has just re-derived the identity).
    void Unlock(int64_t nNow);

    // Lock now, e.g. because the user asked or the window closed.
    void Lock();

    bool IsLocked(int64_t nNow) const;

    // Seconds until the lock trips, 0 if it already has.
    int64_t SecondsLeft(int64_t nNow) const;

private:
    int64_t nLastActivity;
    bool    fLocked;
};

} // namespace btfchat

#endif
