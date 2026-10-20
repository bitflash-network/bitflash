// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "btfchatlog.h"

#include <nlohmann/json.hpp>

#include <algorithm>

using json = nlohmann::json;

namespace btfchat
{

size_t History::MessageCount() const
{
    size_t n = 0;
    for (std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapDirect.begin();
         it != mapDirect.end(); ++it)
        n += it->second.size();
    for (std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapGroup.begin();
         it != mapGroup.end(); ++it)
        n += it->second.size();
    return n;
}

bool History::PushInto(std::map<std::string, std::vector<LogEntry> >& m,
                       const std::string& key, const LogEntry& e, std::string& errOut)
{
    if (!m.count(key) && (mapDirect.size() + mapGroup.size()) >= MAX_CONVERSATIONS)
    {
        errOut = "too many conversations";
        return false;
    }
    std::vector<LogEntry>& v = m[key];
    v.push_back(e);
    // A log is not a security boundary: when it is full the oldest line goes,
    // rather than the new one being refused. The replay table does the opposite
    // and the header says why.
    if (v.size() > MAX_CONVERSATION_MESSAGES)
    {
        mapSeenIds.erase(v.front().id);
        v.erase(v.begin());
    }
    return true;
}

bool History::Append(const Frame& f, const std::string& peer, bool fOutgoing,
                     std::string& errOut)
{
    errOut.clear();
    if (f.id.size() != 32)  { errOut = "the frame has no usable id"; return false; }
    if (f.from.empty())     { errOut = "the frame has no sender"; return false; }
    bool fPay = f.kind == MSG_PAY_ADDRESS || f.kind == MSG_PAYMENT;
    // A payment line may come without a note; what it records is the address.
    if (fPay ? f.payTo.empty() : f.text.empty()) { errOut = "there is nothing to record"; return false; }
    if (mapSeenIds.count(f.id))
    {
        // Belt and braces with the replay guard: even if a frame reaches here
        // twice, the conversation does not gain a duplicate line.
        errOut = "that frame is already in the history";
        return false;
    }

    LogEntry e;
    e.from     = f.from;
    e.sent     = f.sent;
    e.id       = f.id;
    e.text     = f.text;
    e.outgoing = fOutgoing;
    e.kind     = (int)f.kind;
    e.payTo    = f.payTo;
    e.amount   = f.amount;
    e.txid     = f.txid;

    bool fOk = false;
    if (f.kind == MSG_GROUP_TEXT || f.kind == MSG_SWAP_OFFER)
    {
        if (f.group.empty()) { errOut = "a group message with no group"; return false; }
        fOk = PushInto(mapGroup, f.group, e, errOut);
    }
    else if (f.kind == MSG_TEXT || f.kind == MSG_PAY_ADDRESS || f.kind == MSG_PAYMENT || f.kind == MSG_SWAP)
    {
        // A payment line belongs to the conversation it happened in, under the
        // same rules as a message: filed under its sender, never under us.
        if (peer.empty()) { errOut = "a direct message needs the other party"; return false; }
        if (!fOutgoing && peer != f.from)
        {
            // Filing an incoming message under somebody else's conversation.
            errOut = "an incoming message must be filed under its sender";
            return false;
        }
        if (fOutgoing && peer == f.from)
        {
            // Our own address as the peer would make a conversation with
            // ourselves out of every message we send.
            errOut = "we are not our own conversation";
            return false;
        }
        fOk = PushInto(mapDirect, peer, e, errOut);
    }
    else
    {
        // Invites, accepts and group invites are roster events, not messages.
        // The roster already records them, and a log line for each would put a
        // stranger's note into the history of a conversation that may never
        // exist.
        errOut = "only messages go into the history";
        return false;
    }

    if (fOk)
        mapSeenIds[f.id] = true;
    return fOk;
}

void History::Conversation(const std::string& peer, std::vector<LogEntry>& out) const
{
    out.clear();
    std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapDirect.find(peer);
    if (it != mapDirect.end())
        out = it->second;
}

void History::GroupLog(const std::string& groupId, std::vector<LogEntry>& out) const
{
    out.clear();
    std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapGroup.find(groupId);
    if (it != mapGroup.end())
        out = it->second;
}

static void DropIds(const std::vector<LogEntry>& v, std::map<std::string, bool>& ids)
{
    for (size_t i = 0; i < v.size(); i++)
        ids.erase(v[i].id);
}

void History::ForgetPeer(const std::string& peer)
{
    std::map<std::string, std::vector<LogEntry> >::iterator it = mapDirect.find(peer);
    if (it == mapDirect.end())
        return;
    DropIds(it->second, mapSeenIds);
    mapDirect.erase(it);
}

void History::ForgetGroup(const std::string& groupId)
{
    std::map<std::string, std::vector<LogEntry> >::iterator it = mapGroup.find(groupId);
    if (it == mapGroup.end())
        return;
    DropIds(it->second, mapSeenIds);
    mapGroup.erase(it);
}

void History::Wipe()
{
    mapDirect.clear();
    mapGroup.clear();
    mapSeenIds.clear();
}

// ---- persistence -----------------------------------------------------------

static json EntriesToJson(const std::vector<LogEntry>& v)
{
    json a = json::array();
    for (size_t i = 0; i < v.size(); i++)
    {
        json e;
        e["f"] = v[i].from;
        e["t"] = v[i].sent;
        e["i"] = v[i].id;
        e["x"] = v[i].text;
        e["o"] = v[i].outgoing;
        if (v[i].kind != MSG_TEXT)
        {
            e["k"] = v[i].kind;
            e["p"] = v[i].payTo;
            e["a"] = v[i].amount;
            if (!v[i].txid.empty()) e["h"] = v[i].txid;
        }
        a.push_back(e);
    }
    return a;
}

std::string History::ToJson() const
{
    json j;
    j["v"] = 1;
    json d = json::object();
    for (std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapDirect.begin();
         it != mapDirect.end(); ++it)
        d[it->first] = EntriesToJson(it->second);
    j["direct"] = d;

    json g = json::object();
    for (std::map<std::string, std::vector<LogEntry> >::const_iterator it = mapGroup.begin();
         it != mapGroup.end(); ++it)
        g[it->first] = EntriesToJson(it->second);
    j["groups"] = g;
    return j.dump();
}

static bool EntriesFromJson(const json& a, std::vector<LogEntry>& out,
                            std::map<std::string, bool>& ids)
{
    out.clear();
    if (!a.is_array())
        return false;
    for (size_t i = 0; i < a.size() && out.size() < MAX_CONVERSATION_MESSAGES; i++)
    {
        const json& e = a[i];
        if (!e.is_object())
            continue;
        LogEntry le;
        le.from     = e.value("f", std::string());
        le.sent     = e.value("t", (int64_t)0);
        le.id       = e.value("i", std::string());
        le.text     = e.value("x", std::string());
        le.outgoing = e.value("o", false);
        le.kind     = e.value("k", (int)MSG_TEXT);
        le.payTo    = e.value("p", std::string());
        le.amount   = e.value("a", (int64_t)0);
        le.txid     = e.value("h", std::string());
        bool fPay = le.kind == MSG_PAY_ADDRESS || le.kind == MSG_PAYMENT;
        // Group lines carry their kind too -- dropping every kind that was not
        // a plain or payment message emptied every group on reload, which the
        // round-trip test caught.
        if (le.kind != MSG_TEXT && le.kind != MSG_GROUP_TEXT && le.kind != MSG_SWAP_OFFER && le.kind != MSG_SWAP && !fPay)
            continue;
        // A line with no sender or no id is not a line we can reason about, and
        // one whose id repeats would defeat the duplicate check on reload. A
        // payment line may have no note; it must have its address.
        if (le.from.empty() || le.id.size() != 32 || (fPay ? le.payTo.empty() : le.text.empty()))
            continue;
        if (ids.count(le.id))
            continue;
        ids[le.id] = true;
        out.push_back(le);
    }
    return true;
}

bool History::FromJson(const std::string& jsonStr, std::string& errOut)
{
    errOut.clear();
    json j;
    try { j = json::parse(jsonStr); }
    catch (...) { errOut = "the history is not valid JSON"; return false; }
    if (!j.is_object()) { errOut = "the history is not an object"; return false; }

    History h;
    try
    {
        if (j.count("direct") && j["direct"].is_object())
        {
            for (json::const_iterator it = j["direct"].begin(); it != j["direct"].end(); ++it)
            {
                if (h.mapDirect.size() + h.mapGroup.size() >= MAX_CONVERSATIONS)
                    break;
                std::vector<LogEntry> v;
                if (EntriesFromJson(it.value(), v, h.mapSeenIds) && !v.empty())
                    h.mapDirect[it.key()] = v;
            }
        }
        if (j.count("groups") && j["groups"].is_object())
        {
            for (json::const_iterator it = j["groups"].begin(); it != j["groups"].end(); ++it)
            {
                if (h.mapDirect.size() + h.mapGroup.size() >= MAX_CONVERSATIONS)
                    break;
                std::vector<LogEntry> v;
                if (EntriesFromJson(it.value(), v, h.mapSeenIds) && !v.empty())
                    h.mapGroup[it.key()] = v;
            }
        }
    }
    catch (...)
    {
        errOut = "the history has a field of the wrong type";
        return false;
    }

    *this = h;
    return true;
}

// ---- the outbox ------------------------------------------------------------

bool Outbox::Add(const Pending& p, std::string& errOut)
{
    errOut.clear();
    if (p.peer.empty() || p.frameJson.empty() || p.id.size() != 32)
    {
        errOut = "that message cannot be queued";
        return false;
    }
    if (mapIds.count(p.id))
    {
        // Queuing the same frame twice would deliver it twice if the receiving
        // side's replay table had rotated in between.
        errOut = "that message is already waiting";
        return false;
    }
    if (Size() >= MAX_OUTBOX_TOTAL)
    {
        errOut = "there are too many messages waiting to be sent";
        return false;
    }
    if (CountFor(p.peer) >= MAX_OUTBOX_PER_PEER)
    {
        // Refusing is the honest answer. Dropping the oldest would mean the user
        // keeps typing while the thing they said first silently disappears --
        // and unlike a log, this is a queue of things that have NOT happened.
        errOut = "too many messages are already waiting for that address";
        return false;
    }

    mapQueued[p.peer].push_back(p);
    mapIds[p.id] = true;
    return true;
}

void Outbox::For(const std::string& peer, std::vector<Pending>& out) const
{
    out.clear();
    std::map<std::string, std::vector<Pending> >::const_iterator it = mapQueued.find(peer);
    if (it != mapQueued.end())
        out = it->second;
}

void Outbox::Peers(std::vector<std::string>& out) const
{
    out.clear();
    for (std::map<std::string, std::vector<Pending> >::const_iterator it = mapQueued.begin();
         it != mapQueued.end(); ++it)
        if (!it->second.empty())
            out.push_back(it->first);
}

void Outbox::Remove(const std::string& id)
{
    for (std::map<std::string, std::vector<Pending> >::iterator it = mapQueued.begin();
         it != mapQueued.end(); )
    {
        for (size_t i = 0; i < it->second.size(); i++)
            if (it->second[i].id == id)
            {
                it->second.erase(it->second.begin() + i);
                break;
            }
        if (it->second.empty())
            mapQueued.erase(it++);
        else
            ++it;
    }
    mapIds.erase(id);
}

int Outbox::Expire(int64_t nNow)
{
    int nDropped = 0;
    for (std::map<std::string, std::vector<Pending> >::iterator it = mapQueued.begin();
         it != mapQueued.end(); )
    {
        std::vector<Pending> keep;
        for (size_t i = 0; i < it->second.size(); i++)
        {
            // The receiving side refuses anything older than this, so holding it
            // any longer is holding something that can no longer arrive.
            if (nNow - it->second[i].sent >= FRAME_MAX_AGE)
            {
                mapIds.erase(it->second[i].id);
                nDropped++;
            }
            else
                keep.push_back(it->second[i]);
        }
        it->second = keep;
        if (it->second.empty())
            mapQueued.erase(it++);
        else
            ++it;
    }
    return nDropped;
}

size_t Outbox::Size() const
{
    size_t n = 0;
    for (std::map<std::string, std::vector<Pending> >::const_iterator it = mapQueued.begin();
         it != mapQueued.end(); ++it)
        n += it->second.size();
    return n;
}

size_t Outbox::CountFor(const std::string& peer) const
{
    std::map<std::string, std::vector<Pending> >::const_iterator it = mapQueued.find(peer);
    return it == mapQueued.end() ? 0 : it->second.size();
}

void Outbox::ForgetPeer(const std::string& peer)
{
    std::map<std::string, std::vector<Pending> >::iterator it = mapQueued.find(peer);
    if (it == mapQueued.end())
        return;
    for (size_t i = 0; i < it->second.size(); i++)
        mapIds.erase(it->second[i].id);
    mapQueued.erase(it);
}

void Outbox::Wipe()
{
    mapQueued.clear();
    mapIds.clear();
}

std::string Outbox::ToJson() const
{
    json j;
    j["v"] = 1;
    json q = json::object();
    for (std::map<std::string, std::vector<Pending> >::const_iterator it = mapQueued.begin();
         it != mapQueued.end(); ++it)
    {
        json a = json::array();
        for (size_t i = 0; i < it->second.size(); i++)
        {
            json e = json::object();
            e["t"] = it->second[i].sent;
            e["i"] = it->second[i].id;
            e["x"] = it->second[i].text;
            e["m"] = it->second[i].frameJson;
            a.push_back(e);
        }
        q[it->first] = a;
    }
    j["queued"] = q;
    return j.dump();
}

bool Outbox::FromJson(const std::string& jsonStr, std::string& errOut)
{
    errOut.clear();
    json j;
    try { j = json::parse(jsonStr); }
    catch (...) { errOut = "the outbox is not valid JSON"; return false; }
    if (!j.is_object()) { errOut = "the outbox is not an object"; return false; }

    Outbox o;
    try
    {
        if (j.count("queued") && j["queued"].is_object())
        {
            for (json::const_iterator it = j["queued"].begin(); it != j["queued"].end(); ++it)
            {
                const json& a = it.value();
                if (!a.is_array())
                    continue;
                for (size_t i = 0; i < a.size(); i++)
                {
                    if (!a[i].is_object())
                        continue;
                    Pending p;
                    p.peer      = it.key();
                    p.sent      = a[i].value("t", (int64_t)0);
                    p.id        = a[i].value("i", std::string());
                    p.text      = a[i].value("x", std::string());
                    p.frameJson = a[i].value("m", std::string());
                    std::string e;
                    // Add() carries every bound and every refusal, so a store
                    // that grew past them elsewhere cannot get past them here.
                    o.Add(p, e);
                }
            }
        }
    }
    catch (...)
    {
        errOut = "the outbox has a field of the wrong type";
        return false;
    }

    *this = o;
    return true;
}

} // namespace btfchat
