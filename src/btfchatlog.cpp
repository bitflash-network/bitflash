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
    if (f.text.empty())     { errOut = "there is nothing to record"; return false; }
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

    bool fOk = false;
    if (f.kind == MSG_GROUP_TEXT)
    {
        if (f.group.empty()) { errOut = "a group message with no group"; return false; }
        fOk = PushInto(mapGroup, f.group, e, errOut);
    }
    else if (f.kind == MSG_TEXT)
    {
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
        // A line with no sender or no id is not a line we can reason about, and
        // one whose id repeats would defeat the duplicate check on reload.
        if (le.from.empty() || le.id.size() != 32 || le.text.empty())
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

} // namespace btfchat
