// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "btfchat.h"

#include "bip32.h"
#include "btfaddr.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>

using json = nlohmann::json;

namespace btfchat
{

// ---- domain separation -----------------------------------------------------
//
// Every key below is a BLAKE2b keyed by one of these strings. They are the
// reason a chat key cannot collide with a wallet key even though both grow from
// the same twelve words: the hash is keyed differently, so the two trees have
// no shared node. Changing a string changes every identity derived from it, so
// they are frozen the day the first address is published.
static const char* LBL_SALT = "btfchat-v1-salt";
static const char* LBL_ROOT = "btfchat-v1-identity";

// Hardened path under the chat root. The chat lives on its own purpose, not on
// a branch of the wallet's, so a future wallet path can never walk into it.
static const unsigned int CHAT_PURPOSE = 1337;
static const unsigned int CHAT_SIGN    = 0; // .btf identity key
static const unsigned int CHAT_CHAN    = 1; // x25519 static, for btfchan
static const unsigned int CHAT_STORE   = 2; // seals the local roster

static bool EnsureSodium()
{
    static bool fInit = false;
    if (!fInit)
    {
        if (sodium_init() < 0)
            return false;
        fInit = true;
    }
    return true;
}

void IdentityClear(Identity& id)
{
    sodium_memzero(id.sign_sk, sizeof(id.sign_sk));
    sodium_memzero(id.sign_pk, sizeof(id.sign_pk));
    sodium_memzero(id.chan_sk, sizeof(id.chan_sk));
    sodium_memzero(id.chan_pk, sizeof(id.chan_pk));
    sodium_memzero(id.store_key, sizeof(id.store_key));
    id.address.clear();
}

// Derive one hardened leaf m/CHAT_PURPOSE'/index' and hand back its 32-byte key.
static bool DeriveLeaf(const bitflash::BIP32PrivateNode& root, unsigned int nIndex,
                       unsigned char out[32], std::string& errOut)
{
    std::vector<unsigned int> path;
    path.push_back(CHAT_PURPOSE | bitflash::BIP32_HARDENED);
    path.push_back(nIndex | bitflash::BIP32_HARDENED);

    bitflash::BIP32PrivateNode leaf;
    if (!bitflash::BIP32DerivePath(root, path, leaf, errOut))
        return false;
    if (leaf.privateKey.size() != 32)
    {
        errOut = "derived key has the wrong length";
        return false;
    }
    memcpy(out, &leaf.privateKey[0], 32);
    sodium_memzero(&leaf.privateKey[0], leaf.privateKey.size());
    if (!leaf.chainCode.empty())
        sodium_memzero(&leaf.chainCode[0], leaf.chainCode.size());
    return true;
}

bool DeriveIdentityFromSeed(const std::vector<unsigned char>& seed,
                            const std::string& password,
                            Identity& out, std::string& errOut)
{
    errOut.clear();
    if (!EnsureSodium())
    {
        errOut = "libsodium failed to initialize";
        return false;
    }
    if (seed.size() < 32 || seed.size() > 64)
    {
        errOut = "the seed has to be between 32 and 64 bytes";
        return false;
    }
    // Counted in characters, not bytes: an accented password is not shorter for
    // being UTF-8, and a rule the user cannot count is a rule they will fight.
    // Continuation bytes (10xxxxxx) are the ones that do not start a character.
    size_t nChars = 0;
    for (size_t i = 0; i < password.size(); i++)
        if ((static_cast<unsigned char>(password[i]) & 0xC0) != 0x80)
            nChars++;
    if (nChars < MIN_PASSWORD_CHARS)
    {
        errOut = "the session password needs at least 12 characters";
        return false;
    }

    // Salt from the seed, so the same password on two different phrases lands on
    // two unrelated keys -- and so the salt needs no storage of its own.
    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (crypto_generichash(salt, sizeof(salt),
                           reinterpret_cast<const unsigned char*>(LBL_SALT), strlen(LBL_SALT),
                           &seed[0], seed.size()) != 0)
    {
        errOut = "salt derivation failed";
        return false;
    }

    // Argon2id, moderate: 256 MiB and about a second per guess. This is the only
    // thing standing between a stolen phrase-and-nothing-else and the identity,
    // so there is no faster setting available to callers, tests included.
    unsigned char pw[32];
    if (crypto_pwhash(pw, sizeof(pw), password.c_str(), password.size(), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        errOut = "the password hash failed (out of memory?)";
        return false;
    }

    // Chat root = BLAKE2b(seed || argon2(password)), keyed by the domain string.
    std::vector<unsigned char> vchMix;
    vchMix.insert(vchMix.end(), seed.begin(), seed.end());
    vchMix.insert(vchMix.end(), pw, pw + sizeof(pw));
    sodium_memzero(pw, sizeof(pw));

    unsigned char chat_seed[64];
    if (crypto_generichash_blake2b_salt_personal(
            chat_seed, sizeof(chat_seed), &vchMix[0], vchMix.size(),
            reinterpret_cast<const unsigned char*>(LBL_ROOT), strlen(LBL_ROOT),
            NULL, NULL) != 0)
    {
        sodium_memzero(&vchMix[0], vchMix.size());
        errOut = "root derivation failed";
        return false;
    }
    sodium_memzero(&vchMix[0], vchMix.size());

    std::vector<unsigned char> vchChatSeed(chat_seed, chat_seed + sizeof(chat_seed));
    sodium_memzero(chat_seed, sizeof(chat_seed));

    bitflash::BIP32PrivateNode root;
    if (!bitflash::BIP32MasterFromSeed(vchChatSeed, root, errOut))
    {
        sodium_memzero(&vchChatSeed[0], vchChatSeed.size());
        return false;
    }
    sodium_memzero(&vchChatSeed[0], vchChatSeed.size());

    Identity id;
    memset(id.sign_sk,   0, sizeof(id.sign_sk));
    memset(id.sign_pk,   0, sizeof(id.sign_pk));
    memset(id.chan_sk,   0, sizeof(id.chan_sk));
    memset(id.chan_pk,   0, sizeof(id.chan_pk));
    memset(id.store_key, 0, sizeof(id.store_key));
    bool fOk = DeriveLeaf(root, CHAT_SIGN,  id.sign_sk,   errOut)
            && DeriveLeaf(root, CHAT_CHAN,  id.chan_sk,   errOut)
            && DeriveLeaf(root, CHAT_STORE, id.store_key, errOut);
    if (!root.privateKey.empty()) sodium_memzero(&root.privateKey[0], root.privateKey.size());
    if (!root.chainCode.empty())  sodium_memzero(&root.chainCode[0], root.chainCode.size());
    if (!fOk)
    {
        IdentityClear(id);
        return false;
    }

    // x-only public key: this is the address, so it is computed here and never
    // taken from anywhere else.
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        IdentityClear(id);
        errOut = "secp256k1 context failed";
        return false;
    }
    unsigned char rnd[32];
    randombytes_buf(rnd, sizeof(rnd));
    bool fRandomized = secp256k1_context_randomize(ctx, rnd) != 0;
    sodium_memzero(rnd, sizeof(rnd));
    if (!fRandomized)
    {
        secp256k1_context_destroy(ctx);
        IdentityClear(id);
        errOut = "secp256k1 blinding failed";
        return false;
    }

    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_keypair_create(ctx, &kp, id.sign_sk) ||
        !secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp) ||
        !secp256k1_xonly_pubkey_serialize(ctx, id.sign_pk, &xpub))
    {
        sodium_memzero(&kp, sizeof(kp));
        secp256k1_context_destroy(ctx);
        IdentityClear(id);
        errOut = "the derived key is not a valid secp256k1 key";
        return false;
    }
    sodium_memzero(&kp, sizeof(kp));
    secp256k1_context_destroy(ctx);

    // x25519 public half. This is exactly what btfchan's ChanPublicFromSecret
    // does; it is called directly so this module does not have to link the
    // ML-KEM object just to publish a key.
    crypto_scalarmult_base(id.chan_pk, id.chan_sk);

    id.address = btf::Address(id.sign_pk);
    if (id.address.empty())
    {
        IdentityClear(id);
        errOut = "address encoding failed";
        return false;
    }

    out = id;
    return true;
}

bool DeriveIdentity(const std::string& mnemonic, const std::string& password,
                    Identity& out, std::string& errOut)
{
    errOut.clear();
    std::string strNormalized;
    if (!bitflash::BIP39ValidateMnemonic(mnemonic, strNormalized, errOut))
        return false;

    // No BIP39 passphrase here on purpose. The wallet's 25th word and the chat
    // session password are separate secrets protecting separate things; folding
    // one into the other would mean changing a chat password silently moved the
    // coins, and nobody would expect that.
    std::vector<unsigned char> vchSeed;
    if (!bitflash::BIP39MnemonicToSeed(strNormalized, std::string(), vchSeed, errOut))
        return false;

    bool fOk = DeriveIdentityFromSeed(vchSeed, password, out, errOut);
    if (!vchSeed.empty())
        sodium_memzero(&vchSeed[0], vchSeed.size());
    return fOk;
}

// ---- Group -----------------------------------------------------------------

bool Group::IsMember(const std::string& addr) const
{
    return std::find(members.begin(), members.end(), addr) != members.end();
}

// ---- Roster ----------------------------------------------------------------

PeerState Roster::State(const std::string& addr) const
{
    std::map<std::string, PeerState>::const_iterator it = mapPeers.find(addr);
    return it == mapPeers.end() ? PEER_UNKNOWN : it->second;
}

bool Roster::IsAccepted(const std::string& addr) const { return State(addr) == PEER_ACCEPTED; }
bool Roster::IsBlocked(const std::string& addr) const  { return State(addr) == PEER_BLOCKED; }

void Roster::Pending(std::vector<Invite>& out) const
{
    out.clear();
    for (std::map<std::string, Invite>::const_iterator it = mapPending.begin();
         it != mapPending.end(); ++it)
        out.push_back(it->second);
}

static void CollectByState(const std::map<std::string, PeerState>& m, PeerState want,
                           std::vector<std::string>& out)
{
    out.clear();
    for (std::map<std::string, PeerState>::const_iterator it = m.begin(); it != m.end(); ++it)
        if (it->second == want)
            out.push_back(it->first);
    // The map is already ordered by address, so this is sorted; sorting again
    // costs nothing and stops that from being an accident of the container.
    std::sort(out.begin(), out.end());
}

void Roster::Accepted(std::vector<std::string>& out) const
{
    CollectByState(mapPeers, PEER_ACCEPTED, out);
}

void Roster::Invited(std::vector<std::string>& out) const
{
    CollectByState(mapPeers, PEER_INVITE_OUT, out);
}

void Roster::Blocked(std::vector<std::string>& out) const
{
    CollectByState(mapPeers, PEER_BLOCKED, out);
}

bool Roster::GetGroup(const std::string& id, Group& out) const
{
    std::map<std::string, Group>::const_iterator it = mapGroups.find(id);
    if (it == mapGroups.end())
        return false;
    out = it->second;
    return true;
}

void Roster::Groups(std::vector<Group>& out) const
{
    out.clear();
    for (std::map<std::string, Group>::const_iterator it = mapGroups.begin();
         it != mapGroups.end(); ++it)
        out.push_back(it->second);
}

bool Roster::MayDeliver(const std::string& addr, MsgKind kind, std::string& errOut) const
{
    errOut.clear();
    if (addr.empty())
    {
        errOut = "no sender";
        return false;
    }
    PeerState st = State(addr);
    if (st == PEER_BLOCKED)
    {
        errOut = "blocked";
        return false;
    }

    switch (kind)
    {
    case MSG_INVITE:
        // A stranger's one allowance. Also allowed from PEER_INVITE_OUT: two
        // people who invite each other at the same time are agreeing, not
        // colliding, and refusing there would deadlock the pair. And from
        // PEER_ACCEPTED: they invite again because our yes never reached
        // them, and the answer is to say it again (Inbox::Deliver), not to
        // ignore them.
        if (st == PEER_UNKNOWN || st == PEER_INVITE_OUT || st == PEER_ACCEPTED)
            return true;
        errOut = "invite already pending";
        return false;

    case MSG_INVITE_ACCEPT:
        if (st == PEER_INVITE_OUT)
            return true;
        errOut = "we never invited them";
        return false;

    // Somebody we invited can only write to us after taking our invite, so
    // their first message IS their yes -- also when the accept itself never
    // arrived (Inbox::Deliver records it). We consented by inviting them.
    case MSG_TEXT:
        if (st == PEER_ACCEPTED || st == PEER_INVITE_OUT)
            return true;
        errOut = "not accepted";
        return false;

    case MSG_PAY_ADDRESS:
    case MSG_PAYMENT:
        // Only from somebody we agreed to talk to. A stranger's "pay me here"
        // is the oldest scam there is, and it does not get to sit in the list
        // of people this wallet might pay.
        if (st == PEER_ACCEPTED || st == PEER_INVITE_OUT)
            return true;
        errOut = "not accepted";
        return false;

    case MSG_SWAP:
        // A swap is arranged with somebody we agreed to talk to, never a
        // stranger: a step names addresses the app will lock coins towards.
        if (st == PEER_ACCEPTED || st == PEER_INVITE_OUT)
            return true;
        errOut = "not accepted";
        return false;

    case MSG_SWAP_OFFER:
        // Offers are community posts, read off the community, never handed
        // over a direct link.
        errOut = "offers come through their community";
        return false;

    case MSG_GROUP_INVITE:
        // May come from someone we do not know -- that is what an invite is for.
        // Blocked was already refused above, which is the property that matters.
        return true;

    case MSG_GROUP_TEXT:
        // Deliberately refused here. A group frame cannot be judged by its
        // sender alone; the caller has to name the group, so it has to call
        // MayDeliverGroup. Returning true for it would make forgetting that
        // call the easy path, and the easy path has to be the safe one.
        errOut = "group frames go through MayDeliverGroup";
        return false;
    }

    // An unknown kind. A build that does not understand a frame refuses it
    // rather than guessing which of the rules above it resembles.
    errOut = "unknown frame kind";
    return false;
}

bool Roster::NoteIncomingInvite(const std::string& addr, const std::string& note,
                               int64_t nNow, std::string& errOut)
{
    errOut.clear();
    if (addr.empty())          { errOut = "no sender"; return false; }
    if (note.size() > MAX_INVITE_NOTE) { errOut = "the invite note is too long"; return false; }

    PeerState st = State(addr);
    if (st == PEER_BLOCKED)    { errOut = "blocked"; return false; }
    if (st == PEER_ACCEPTED)   { errOut = "already talking"; return false; }
    if (st == PEER_INVITE_IN)  { errOut = "invite already pending"; return false; }

    // Crossing invites: we asked them, they asked us. Both sides said yes, so
    // there is nothing left to consent to.
    if (st == PEER_INVITE_OUT)
    {
        mapPeers[addr] = PEER_ACCEPTED;
        return true;
    }

    if (TotalPending() >= MAX_PENDING_INVITES)
    {
        errOut = "the pending invite list is full";
        return false;
    }

    Invite inv;
    inv.address  = addr;
    inv.note     = note;
    inv.received = nNow;
    mapPending[addr] = inv;
    mapPeers[addr]   = PEER_INVITE_IN;
    return true;
}

bool Roster::NoteOutgoingInvite(const std::string& addr, int64_t nNow, std::string& errOut)
{
    errOut.clear();
    (void)nNow;
    if (addr.empty())        { errOut = "no address"; return false; }
    PeerState st = State(addr);
    if (st == PEER_BLOCKED)  { errOut = "blocked"; return false; }
    if (st == PEER_ACCEPTED) { errOut = "already talking"; return false; }
    if (st == PEER_INVITE_OUT) { errOut = "invite already sent"; return false; }

    // They invited us first and we are answering by inviting back: that is an
    // accept, and it goes through the same door as one.
    if (st == PEER_INVITE_IN)
    {
        mapPending.erase(addr);
        mapPeers[addr] = PEER_ACCEPTED;
        return true;
    }

    mapPeers[addr] = PEER_INVITE_OUT;
    return true;
}

bool Roster::AcceptInvite(const std::string& addr, std::string& errOut)
{
    errOut.clear();
    if (State(addr) != PEER_INVITE_IN)
    {
        // There is no path from "never asked" to "accepted". The interface
        // cannot open a conversation the user did not consent to, even by bug.
        errOut = "there is no invite from that address";
        return false;
    }
    mapPending.erase(addr);
    mapPeers[addr] = PEER_ACCEPTED;
    return true;
}

bool Roster::NoteInviteAccepted(const std::string& addr, std::string& errOut)
{
    errOut.clear();
    if (State(addr) != PEER_INVITE_OUT)
    {
        errOut = "we never invited them";
        return false;
    }
    mapPeers[addr] = PEER_ACCEPTED;
    return true;
}

bool Roster::DeclineInvite(const std::string& addr, std::string& errOut)
{
    errOut.clear();
    if (State(addr) != PEER_INVITE_IN)
    {
        errOut = "there is no invite from that address";
        return false;
    }
    mapPending.erase(addr);
    mapPeers.erase(addr);
    return true;
}

bool Roster::Block(const std::string& addr, std::string& errOut)
{
    errOut.clear();
    if (addr.empty()) { errOut = "no address"; return false; }

    mapPending.erase(addr);
    mapPeers[addr] = PEER_BLOCKED;

    // Drop any group invite that came from them, so blocking also clears what
    // they already put on the screen.
    for (std::map<std::string, GroupInvite>::iterator it = mapGroupInvites.begin();
         it != mapGroupInvites.end(); )
    {
        if (it->second.fromAddr == addr)
            mapGroupInvites.erase(it++);
        else
            ++it;
    }

    // And take them out of every group we admin. In a group someone else runs
    // we cannot remove them -- MayDeliverGroup is what keeps their words off
    // our screen there.
    for (std::map<std::string, Group>::iterator it = mapGroups.begin();
         it != mapGroups.end(); ++it)
    {
        std::vector<std::string>& v = it->second.members;
        v.erase(std::remove(v.begin(), v.end(), addr), v.end());
    }
    return true;
}

bool Roster::CreateGroup(const std::string& id, const std::string& name,
                         const std::string& myAddress, std::string& errOut)
{
    errOut.clear();
    if (id.empty())                 { errOut = "the group needs an id"; return false; }
    if (myAddress.empty())          { errOut = "no local address"; return false; }
    if (name.empty())               { errOut = "the group needs a name"; return false; }
    if (name.size() > MAX_GROUP_NAME) { errOut = "the group name is too long"; return false; }
    if (mapGroups.count(id) || mapGroupInvites.count(id))
    {
        errOut = "that group id is already in use";
        return false;
    }

    Group g;
    g.id    = id;
    g.name  = name;
    g.admin = myAddress;          // whoever creates it runs it
    g.members.push_back(myAddress);
    mapGroups[id] = g;
    return true;
}

bool Roster::NoteGroupInvite(const std::string& groupId, const std::string& name,
                             const std::string& adminAddr, const std::string& fromAddr,
                             int64_t nNow, std::string& errOut)
{
    errOut.clear();
    if (groupId.empty() || name.empty() || adminAddr.empty() || fromAddr.empty())
    {
        errOut = "incomplete group invite";
        return false;
    }
    if (name.size() > MAX_GROUP_NAME) { errOut = "the group name is too long"; return false; }

    // The door every other chat app leaves open: blocked, so nothing crosses,
    // including an invitation to a room.
    if (IsBlocked(fromAddr)) { errOut = "blocked"; return false; }

    // Only the group's admin can invite into it. Without this, any member could
    // drag anyone into a room, and a block would be one hop from useless.
    if (fromAddr != adminAddr) { errOut = "only the group admin may invite"; return false; }

    if (mapGroups.count(groupId))       { errOut = "already in that group"; return false; }
    if (mapGroupInvites.count(groupId)) { errOut = "group invite already pending"; return false; }
    if (TotalPending() >= MAX_PENDING_INVITES)
    {
        errOut = "the pending invite list is full";
        return false;
    }

    GroupInvite gi;
    gi.group.id    = groupId;
    gi.group.name  = name;
    gi.group.admin = adminAddr;
    gi.group.members.push_back(adminAddr);
    gi.fromAddr    = fromAddr;
    gi.received    = nNow;
    mapGroupInvites[groupId] = gi;
    return true;
}

bool Roster::AcceptGroupInvite(const std::string& groupId, const std::string& myAddress,
                               std::string& errOut)
{
    errOut.clear();
    std::map<std::string, GroupInvite>::iterator it = mapGroupInvites.find(groupId);
    if (it == mapGroupInvites.end())
    {
        errOut = "there is no invite to that group";
        return false;
    }
    if (myAddress.empty()) { errOut = "no local address"; return false; }

    Group g = it->second.group;
    if (!g.IsMember(myAddress))
        g.members.push_back(myAddress);
    mapGroups[groupId] = g;
    mapGroupInvites.erase(it);

    // Joining a group does NOT accept its admin as a contact. Two separate
    // consents, because being willing to be in a room with someone is not the
    // same as being willing to hear from them privately.
    return true;
}

bool Roster::AddGroupMember(const std::string& groupId, const std::string& memberAddr,
                            const std::string& myAddress, std::string& errOut)
{
    errOut.clear();
    std::map<std::string, Group>::iterator it = mapGroups.find(groupId);
    if (it == mapGroups.end())          { errOut = "no such group"; return false; }
    if (it->second.admin != myAddress)  { errOut = "only the group admin may add members"; return false; }
    if (!it->second.IsMember(myAddress)) { errOut = "the admin has left this group"; return false; }
    if (memberAddr.empty())             { errOut = "no member address"; return false; }
    if (IsBlocked(memberAddr))          { errOut = "blocked"; return false; }
    if (it->second.IsMember(memberAddr)) { errOut = "already a member"; return false; }

    it->second.members.push_back(memberAddr);
    return true;
}

bool Roster::RemoveGroupMember(const std::string& groupId, const std::string& memberAddr,
                               const std::string& myAddress, std::string& errOut)
{
    errOut.clear();
    std::map<std::string, Group>::iterator it = mapGroups.find(groupId);
    if (it == mapGroups.end())         { errOut = "no such group"; return false; }
    if (it->second.admin != myAddress) { errOut = "only the group admin may remove members"; return false; }
    if (memberAddr == it->second.admin) { errOut = "the admin cannot be removed"; return false; }
    if (!it->second.IsMember(memberAddr)) { errOut = "not a member"; return false; }

    std::vector<std::string>& v = it->second.members;
    v.erase(std::remove(v.begin(), v.end(), memberAddr), v.end());
    return true;
}

bool Roster::LeaveGroup(const std::string& groupId, const std::string& myAddress,
                        std::string& errOut)
{
    errOut.clear();
    std::map<std::string, Group>::iterator it = mapGroups.find(groupId);
    if (it == mapGroups.end()) { errOut = "no such group"; return false; }
    if (!it->second.IsMember(myAddress)) { errOut = "not a member"; return false; }

    // The group is forgotten entirely, not just left: keeping a room we walked
    // out of would keep delivering its frames.
    mapGroups.erase(it);
    return true;
}

bool Roster::MayDeliverGroup(const std::string& groupId, const std::string& fromAddr,
                             std::string& errOut) const
{
    errOut.clear();
    if (IsBlocked(fromAddr))
    {
        // Blocked wins over membership. Someone we blocked personally is
        // someone we said we do not want to hear, room or no room.
        errOut = "blocked";
        return false;
    }
    std::map<std::string, Group>::const_iterator it = mapGroups.find(groupId);
    if (it == mapGroups.end())
    {
        errOut = "not in that group";
        return false;
    }
    if (!it->second.IsMember(fromAddr))
    {
        errOut = "the sender is not in that group";
        return false;
    }
    return true;
}

// ---- persistence -----------------------------------------------------------

std::string Roster::ToJson() const
{
    json j;
    j["v"] = 1;

    json jp = json::object();
    for (std::map<std::string, PeerState>::const_iterator it = mapPeers.begin();
         it != mapPeers.end(); ++it)
        jp[it->first] = (int)it->second;
    j["peers"] = jp;

    json ji = json::array();
    for (std::map<std::string, Invite>::const_iterator it = mapPending.begin();
         it != mapPending.end(); ++it)
    {
        json e;
        e["a"] = it->second.address;
        e["n"] = it->second.note;
        e["t"] = it->second.received;
        ji.push_back(e);
    }
    j["pending"] = ji;

    json jg = json::array();
    for (std::map<std::string, Group>::const_iterator it = mapGroups.begin();
         it != mapGroups.end(); ++it)
    {
        json e;
        e["id"]      = it->second.id;
        e["name"]    = it->second.name;
        e["admin"]   = it->second.admin;
        e["members"] = it->second.members;
        jg.push_back(e);
    }
    j["groups"] = jg;

    json jgi = json::array();
    for (std::map<std::string, GroupInvite>::const_iterator it = mapGroupInvites.begin();
         it != mapGroupInvites.end(); ++it)
    {
        json e;
        e["id"]    = it->second.group.id;
        e["name"]  = it->second.group.name;
        e["admin"] = it->second.group.admin;
        e["from"]  = it->second.fromAddr;
        e["t"]     = it->second.received;
        jgi.push_back(e);
    }
    j["group_invites"] = jgi;

    return j.dump();
}

bool Roster::FromJson(const std::string& jsonStr, std::string& errOut)
{
    errOut.clear();
    json j;
    try { j = json::parse(jsonStr); }
    catch (...) { errOut = "the store is not valid JSON"; return false; }
    if (!j.is_object()) { errOut = "the store is not an object"; return false; }

    Roster r;
    try
    {
        if (j.count("peers") && j["peers"].is_object())
        {
            for (json::const_iterator it = j["peers"].begin(); it != j["peers"].end(); ++it)
            {
                int n = it.value().get<int>();
                // A state this build does not know becomes BLOCKED, not
                // ACCEPTED. A corrupt or downgraded store must fail closed:
                // the cost is a contact the user has to re-add, and the
                // alternative cost is a stranger in the conversation.
                if (n < PEER_UNKNOWN || n > PEER_BLOCKED)
                    n = PEER_BLOCKED;
                r.mapPeers[it.key()] = (PeerState)n;
            }
        }
        if (j.count("pending") && j["pending"].is_array())
        {
            for (size_t i = 0; i < j["pending"].size(); i++)
            {
                const json& e = j["pending"][i];
                Invite inv;
                inv.address  = e.value("a", std::string());
                inv.note     = e.value("n", std::string());
                inv.received = e.value("t", (int64_t)0);
                if (inv.address.empty()) continue;
                if (inv.note.size() > MAX_INVITE_NOTE)
                    inv.note.resize(MAX_INVITE_NOTE);
                // Only keep an invite whose peer state agrees it is pending.
                if (r.State(inv.address) != PEER_INVITE_IN) continue;
                r.mapPending[inv.address] = inv;
            }
        }
        if (j.count("groups") && j["groups"].is_array())
        {
            for (size_t i = 0; i < j["groups"].size(); i++)
            {
                const json& e = j["groups"][i];
                Group g;
                g.id    = e.value("id", std::string());
                g.name  = e.value("name", std::string());
                g.admin = e.value("admin", std::string());
                if (e.count("members") && e["members"].is_array())
                    g.members = e["members"].get<std::vector<std::string> >();
                if (g.id.empty() || g.admin.empty()) continue;
                if (g.name.size() > MAX_GROUP_NAME) g.name.resize(MAX_GROUP_NAME);
                r.mapGroups[g.id] = g;
            }
        }
        if (j.count("group_invites") && j["group_invites"].is_array())
        {
            for (size_t i = 0; i < j["group_invites"].size(); i++)
            {
                const json& e = j["group_invites"][i];
                GroupInvite gi;
                gi.group.id    = e.value("id", std::string());
                gi.group.name  = e.value("name", std::string());
                gi.group.admin = e.value("admin", std::string());
                gi.fromAddr    = e.value("from", std::string());
                gi.received    = e.value("t", (int64_t)0);
                if (gi.group.id.empty() || gi.group.admin.empty() || gi.fromAddr.empty())
                    continue;
                // A blocked inviter's pending invite does not come back to life
                // because it was written down before the block.
                if (r.IsBlocked(gi.fromAddr)) continue;
                if (r.mapGroups.count(gi.group.id)) continue;
                if (gi.group.name.size() > MAX_GROUP_NAME) gi.group.name.resize(MAX_GROUP_NAME);
                gi.group.members.push_back(gi.group.admin);
                r.mapGroupInvites[gi.group.id] = gi;
            }
        }
    }
    catch (...)
    {
        errOut = "the store has a field of the wrong type";
        return false;
    }

    *this = r;
    return true;
}

// ---- sealed store ----------------------------------------------------------

bool SealStore(const Identity& id, const std::string& plain,
               std::vector<unsigned char>& out)
{
    out.clear();
    if (!EnsureSodium())
        return false;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ct(plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long nCt = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            &ct[0], &nCt,
            reinterpret_cast<const unsigned char*>(plain.data()), plain.size(),
            NULL, 0, NULL, nonce, id.store_key) != 0)
        return false;

    out.insert(out.end(), nonce, nonce + sizeof(nonce));
    out.insert(out.end(), ct.begin(), ct.begin() + (size_t)nCt);
    return true;
}

bool OpenStore(const Identity& id, const unsigned char* in, size_t n,
               std::string& out)
{
    out.clear();
    if (!EnsureSodium())
        return false;
    const size_t NONCE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (n < NONCE + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return false;

    std::vector<unsigned char> pt(n - NONCE);
    unsigned long long nPt = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            &pt[0], &nPt, NULL,
            in + NONCE, n - NONCE, NULL, 0, in, id.store_key) != 0)
        return false;

    out.assign(reinterpret_cast<const char*>(pt.data()), (size_t)nPt);
    return true;
}

// ---- inactivity lock -------------------------------------------------------

void AutoLock::Touch(int64_t nNow)
{
    // A locked session is not woken by activity. Only the password does that,
    // otherwise the timeout would reset itself on the very clicks it is meant
    // to be protecting against.
    if (fLocked)
        return;
    if (nNow > nLastActivity)
        nLastActivity = nNow;
}

void AutoLock::Unlock(int64_t nNow)
{
    fLocked = false;
    nLastActivity = nNow;
}

void AutoLock::Lock()
{
    fLocked = true;
    nLastActivity = 0;
}

bool AutoLock::IsLocked(int64_t nNow) const
{
    if (fLocked)
        return true;
    // A clock that went backwards (a resync, a laptop resuming) counts as
    // inactivity rather than as fresh activity: locking early is a nuisance,
    // staying unlocked is the failure that matters.
    if (nNow < nLastActivity)
        return true;
    return (nNow - nLastActivity) >= LOCK_AFTER_SECONDS;
}

int64_t AutoLock::SecondsLeft(int64_t nNow) const
{
    if (IsLocked(nNow))
        return 0;
    return LOCK_AFTER_SECONDS - (nNow - nLastActivity);
}

} // namespace btfchat
