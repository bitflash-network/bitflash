// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat history -- what is kept after the connection closes.
//
// A chat that forgets everything on exit is a different product, and not the one
// that was asked for. So messages are kept, and kept sealed with the same key
// that seals the contact list: the plaintext of a conversation never touches
// disk. Losing the machine loses the history, which is the correct outcome --
// history that survives without the session password would be history an
// attacker with the phrase alone could read.
//
// WHAT IS NOT HERE. No read receipts, no typing state, no "last seen". Each of
// those is a signal sent to the other side about what you are doing while you
// are not talking, and every one of them has been used to place people in time.
// If they ever arrive they should arrive as something the user turns ON.
//
// TWO CEILINGS, TWO OPPOSITE ANSWERS. When the replay table fills it refuses,
// because making room there means accepting a replay. When a conversation fills
// it drops its oldest message, because a log is not a security boundary and
// refusing to record would be worse than forgetting the oldest line. The two
// look like the same decision and are not, so both are written down.

#ifndef BITFLASH_BTFCHATLOG_H
#define BITFLASH_BTFCHATLOG_H

#include "btfchat.h"
#include "btfchatmsg.h"

#include <map>
#include <string>
#include <vector>
#include <stdint.h>

namespace btfchat
{

// Messages kept per conversation. Past this the oldest is dropped.
static const size_t MAX_CONVERSATION_MESSAGES = 5000;

// Conversations kept at all. A roster is capped, so this only bites for someone
// who accepted thousands of people and then walked away from them.
static const size_t MAX_CONVERSATIONS = 1024;

struct LogEntry
{
    std::string from;     // who wrote it -- always a .btf, ours included
    int64_t     sent;     // the sender's clock, as the frame carried it
    std::string id;       // frame id, which is also what makes a line unique
    std::string text;
    bool        outgoing; // we wrote it
    // Payment lines (MSG_PAY_ADDRESS, MSG_PAYMENT); a plain message is MSG_TEXT.
    int         kind;
    std::string payTo;
    int64_t     amount;
    std::string txid;

    LogEntry() : sent(0), outgoing(false), kind(MSG_TEXT), amount(0) {}
};

// One identity's history. Direct conversations are keyed by the other party's
// address; groups by group id. Pure logic: no clock, no disk, no network.
class History
{
public:
    History() {}

    // Record a delivered frame.
    //
    // `peer` is the other party for a direct message and is ignored for a group
    // one, where the group in the frame decides. For an incoming direct message
    // `peer` has to be the sender -- filing someone's words under a third
    // party's name is how a conversation gets forged locally, and there is no
    // legitimate caller that needs it.
    //
    // Refuses a frame id already recorded, so a frame that got past the replay
    // guard twice still cannot appear twice.
    bool Append(const Frame& f, const std::string& peer, bool fOutgoing,
                std::string& errOut);

    // Read back, oldest first.
    void Conversation(const std::string& peer, std::vector<LogEntry>& out) const;
    void GroupLog(const std::string& groupId, std::vector<LogEntry>& out) const;

    size_t ConversationCount() const { return mapDirect.size() + mapGroup.size(); }
    size_t MessageCount() const;

    // Forgetting is a user action and it is immediate. Blocking someone does NOT
    // erase what they said: the user may want to keep it, and deciding that for
    // them would be deciding what evidence they get to hold.
    void ForgetPeer(const std::string& peer);
    void ForgetGroup(const std::string& groupId);
    void Wipe();

    // The sealed form is SealStore(identity, ToJson()) -- the same seal the
    // roster uses, under the same key.
    std::string ToJson() const;
    bool        FromJson(const std::string& jsonStr, std::string& errOut);

private:
    std::map<std::string, std::vector<LogEntry> > mapDirect; // peer  -> messages
    std::map<std::string, std::vector<LogEntry> > mapGroup;  // group -> messages
    std::map<std::string, bool>                   mapSeenIds;

    bool PushInto(std::map<std::string, std::vector<LogEntry> >& m,
                  const std::string& key, const LogEntry& e, std::string& errOut);
};

// ---- the outbox ------------------------------------------------------------
//
// What to do with a message for somebody who is not there.
//
// Nothing leaves this machine. The signed frame is kept here, under the same
// seal as the history, and sent when that person is reachable again. No relay
// stores it, no node is asked to hold it, nobody has to be trusted with it --
// which is the entire point, and the reason this exists instead of a mailbox
// somewhere.
//
// The honest cost, said out loud: WE have to be running when they come back.
// A message to somebody in another timezone may simply never go. The user is
// told this, because a queue that quietly never delivers is worse than an error.
//
// HOW LONG IT LIVES IS NOT A PREFERENCE. ReplayGuard refuses any frame older
// than FRAME_MAX_AGE -- one day -- so a message delivered after that is refused
// on arrival and vanishes without a trace. The queue therefore stops at the same
// line and says the message expired. Widening the window instead would widen the
// replay window, which is trading a security property for a convenience, and
// this is not a trade worth making.
static const size_t MAX_OUTBOX_PER_PEER = 200;
static const size_t MAX_OUTBOX_TOTAL    = 1000;

struct Pending
{
    std::string peer;      // who it is for
    std::string frameJson; // signed at the moment it was written, not at delivery
    std::string id;        // the frame id, which is what identifies it everywhere
    std::string text;      // for showing the user what is still waiting
    int64_t     sent;      // the clock it was signed under

    Pending() : sent(0) {}
};

class Outbox
{
public:
    Outbox() {}

    // Refuses a duplicate id, a full queue, and a message for nobody.
    bool Add(const Pending& p, std::string& errOut);

    // Everything still waiting for this peer, oldest first.
    void For(const std::string& peer, std::vector<Pending>& out) const;
    // Every peer with something waiting.
    void Peers(std::vector<std::string>& out) const;

    // Gone because it was delivered.
    void Remove(const std::string& id);
    // Gone because it can no longer be delivered to anybody: past FRAME_MAX_AGE
    // the receiving side refuses it. Returns how many were dropped, so the
    // caller can say so rather than letting them disappear quietly.
    int  Expire(int64_t nNow);

    size_t Size() const;
    size_t CountFor(const std::string& peer) const;
    void   ForgetPeer(const std::string& peer);
    void   Wipe();

    std::string ToJson() const;
    bool        FromJson(const std::string& jsonStr, std::string& errOut);

private:
    std::map<std::string, std::vector<Pending> > mapQueued; // peer -> in order
    std::map<std::string, bool>                  mapIds;
};

} // namespace btfchat

#endif
