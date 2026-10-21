// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat frames -- what actually travels, and why it cannot be forged.
//
// btfchan encrypts the pipe and btfchat decides who may speak. This is the
// third piece: the shape of one message, signed by the sender's chat key, so
// that the thing carrying it -- a rendezvous relay, a Nostr relay, a hop we do
// not control -- cannot change a byte of it or invent a sender.
//
// WHY SIGN INSIDE AN ENCRYPTED CHANNEL. The channel proves you are talking to
// the key the .btf address names, and nothing more. Two places that is not
// enough:
//
//   groups     -- a frame reaches you through whoever relayed it, not only from
//                 the person who wrote it. Without a signature, any member of a
//                 group could put words in another member's mouth.
//   store      -- a frame kept on disk and read back later has no live channel
//                 behind it. The signature is what still vouches for it.
//
// THE GROUP ADMIN PROOF. "Only the admin may invite" is a rule the roster
// enforces locally, and a local rule is worth nothing against a peer who simply
// claims to be the admin. So a group invite carries a separate signature from
// the admin's key over the group, its name and the person being invited. The
// invitee verifies it against the admin address the invite names, and that
// address is the one the group is identified by from then on. Without this the
// block-cannot-be-bypassed-by-a-group guarantee is decorative.
//
// REPLAY. Inside one channel, btfchan's authenticated counter already refuses a
// repeated frame. Across channels it cannot: a frame captured today and handed
// back on a fresh connection tomorrow is, to the cipher, a perfectly good
// frame. So every frame carries a random id and a timestamp, and ReplayGuard
// refuses one it has already seen, one from the future, and one too old to
// matter.

#ifndef BITFLASH_BTFCHATMSG_H
#define BITFLASH_BTFCHATMSG_H

#include "btfchat.h"

#include <map>
#include <string>
#include <stdint.h>

namespace btfchat
{

// Frame format version. A frame of any other version is refused, not guessed
// at: a build that does not understand a frame has no business acting on it.
static const int FRAME_VERSION = 1;

// One message. 4 KiB is a long paragraph; anything bigger is a file, and files
// are a different problem with different rules.
static const size_t MAX_TEXT_BYTES = 4096;

// Longest frame accepted off the wire, checked BEFORE parsing. A parser is the
// one piece of code a stranger gets to run, so it is handed a bounded buffer.
static const size_t MAX_FRAME_BYTES = 16384;

// A frame timestamped further ahead than this is refused: it would otherwise
// sit at the top of the conversation forever.
static const int64_t FRAME_FUTURE_SKEW = 300;

// And one older than this is refused, which is also what bounds how long
// ReplayGuard has to remember anything.
static const int64_t FRAME_MAX_AGE = 24 * 60 * 60;

// How many frame ids ReplayGuard keeps. See the note on Accept() for what
// happens when it fills, and why it fails closed.
static const size_t MAX_SEEN_FRAMES = 4096;

struct Frame
{
    int         version;
    MsgKind     kind;
    std::string from;   // sender's .btf -- the signature is verified under it
    int64_t     sent;   // unix seconds, the sender's clock
    std::string id;     // 32 hex characters (16 random bytes)
    std::string group;  // group id, group frames only
    std::string text;   // invite note, message body, or group name
    std::string proof;  // group invites: the admin's signature, 128 hex
    std::string payTo;  // payment frames: the B address
    int64_t     amount; // MSG_PAYMENT: satoshis paid
    std::string txid;   // MSG_PAYMENT: 64 hex characters

    Frame() : version(FRAME_VERSION), kind(MSG_TEXT), sent(0), amount(0) {}
};

// A payment note is a short paragraph, not a letter.
static const size_t MAX_PAY_NOTE = 280;

// Sign and serialize. Fills in `from`, `version`, and `id` when it is empty.
// `secpctx` is a secp256k1_context* (void* to keep this header free of secp).
// Refuses a frame whose fields break their own rules -- an over-long body, a
// group frame with no group, a direct frame carrying one -- because a signature
// over a malformed frame just makes the malformed frame authentic.
bool SignFrame(void* secpctx, const Identity& id, Frame& f,
               std::string& outJson, std::string& errOut);

// Parse and verify. Returns true only if the frame is well formed AND its
// signature verifies under the key its `from` address decodes to.
//
// An address whose version this build does not understand is refused here. That
// is the reason the version byte exists: when the identity key stops being a
// secp256k1 x-only key, an old build must say "I cannot check this" instead of
// verifying it under the wrong scheme.
bool OpenFrame(void* secpctx, const std::string& jsonStr, Frame& out,
               std::string& errOut);

// The admin's proof that this invite to this group, for this person, is real.
// Signed over the group id, its name, the invitee and the admin's own address,
// so it cannot be lifted onto another group, another name or another invitee.
bool SignGroupInvite(void* secpctx, const Identity& adminId,
                     const std::string& groupId, const std::string& groupName,
                     const std::string& inviteeAddr,
                     std::string& proofHexOut, std::string& errOut);

bool VerifyGroupInvite(void* secpctx, const std::string& adminAddr,
                       const std::string& groupId, const std::string& groupName,
                       const std::string& inviteeAddr,
                       const std::string& proofHex, std::string& errOut);

// Remembers which frames have already been delivered.
//
// Call it AFTER the consent gate, never before: the gate is what keeps a
// stranger from filling this table, and the order is the only thing that makes
// the ceiling below safe.
class ReplayGuard
{
public:
    ReplayGuard() {}

    // True if this frame may be delivered for the first time. Refuses an id
    // already seen, a timestamp from the future, one older than FRAME_MAX_AGE,
    // and -- once MAX_SEEN_FRAMES ids are live even after pruning -- everything,
    // because the alternative is evicting an id and accepting the replay it was
    // protecting against. A chat that stops is a bug; a chat that replays a
    // message as if it were new is a lie.
    bool Accept(const Frame& f, int64_t nNow, std::string& errOut);

    size_t Size() const { return mapSeen.size(); }
    void   Prune(int64_t nNow);

private:
    std::map<std::string, int64_t> mapSeen; // frame id -> sent
};

} // namespace btfchat

#endif
