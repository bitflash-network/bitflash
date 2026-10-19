// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The chat app's way to the Bitflash nodes -- where it publishes who it is and
// leaves messages for people who are offline. Replaces the public Nostr relays
// the chat used before: no server of anybody's, ours included.
//
// HOW IT FINDS NODES. Exactly like a node does. It starts from the onion seeds
// pinned in the binary, and every node it talks to hands it signed descriptors
// of other nodes ("btfpeers"), which it checks and remembers. A seed is trusted
// for nothing: everything it could hand over is either signed by its owner or
// sealed to its recipient.
//
// HOW IT TALKS. Over Tor, to the node's ordinary onion, in the node's ordinary
// protocol: a version message saying "not a node", then requests. One
// connection per round, not one per question -- each connection is a Tor
// circuit, which costs seconds and is traffic somebody can count.
//
// WHAT A NODE LEARNS. That somebody, over Tor, published a descriptor, or asked
// for one, or left or collected envelopes under a tag. Not who: the app never
// connects from anywhere but Tor, and a tag names a pair nobody can identify
// (btfchatbox.h). The same as a relay learned before -- minus the relay being
// one of a handful of companies.

#ifndef BITFLASH_BTFCHATNET_H
#define BITFLASH_BTFCHATNET_H

#include "chatstore.h"
#include "btfchatlink.h"

#include <map>
#include <string>
#include <vector>

class CChatQuery;

namespace btfchat
{

// One connection to one node, in the node's protocol. Works over any Stream,
// so the framing is tested without Tor.
class NodeLink
{
public:
    explicit NodeLink(Stream& s);

    // Send our version, read theirs. Fails if the far end is not a Bitflash
    // node of this network, or is one that does not hold chat records.
    bool Handshake(std::string& errOut);

    // Leave one record. `nResultOut` is a ChatStore::Result.
    bool Put(const ChatRecord& r, int& nResultOut, std::string& whyOut, std::string& errOut);

    // Ask several questions at once. `out` has one entry per question.
    bool Get(const std::vector<CChatQuery>& vQuery,
             std::vector<std::vector<ChatRecord> >& out, std::string& errOut);

    // Descriptors of other nodes this one handed us on the way.
    const std::vector<std::string>& PeerDescriptors() const { return vPex; }

    uint64_t Services() const { return nServices; }

private:
    Stream& s;
    int nFraming;
    int nPeerVersion;
    uint64_t nServices;
    unsigned int nNextReq;
    std::vector<std::string> vPex;

    bool Send(const char* pszCommand, const std::vector<unsigned char>& payload);
    bool Recv(std::string& strCommand, std::vector<unsigned char>& payload, std::string& errOut);
    // Read until `pszReply` carrying `nReq` arrives; keep what else is useful.
    bool Await(const char* pszReply, unsigned int nReq,
               std::vector<unsigned char>& payload, std::string& errOut);
};

// ---- what the chat uses ------------------------------------------------------

// Publish a record on the network: mined here if it carries no work yet, then
// left with up to two nodes, which pass it on. True when at least one kept it.
bool NetPublish(ChatRecord& r, std::string& errOut);

// Ask the network. One answer list per question, merged across the nodes
// asked and deduplicated. True when at least one node answered.
bool NetQuery(const std::vector<CChatQuery>& vQuery,
              std::vector<std::vector<ChatRecord> >& out, std::string& errOut);

// A chat address's onion and channel key, from its signed descriptor. Checked
// here against the address asked for: a node cannot answer with somebody else.
bool NetResolve(const std::string& chatAddr, std::string& onionOut,
                unsigned char encPubOut[32], std::string& errOut);

// A chat address's signed epoch-keys announcement, as published. The caller
// verifies it (VerifyEpochKeys) -- the same check the nodes ran.
bool NetQueryEpochKeys(const std::string& chatAddr, std::string& annOut,
                       std::string& errOut);

// Leave a sealed envelope under a pair tag (32 hex characters).
bool NetPostEnvelope(const std::string& tagHex, const std::vector<unsigned char>& env,
                     std::string& errOut);

// Collect envelopes under several tags in one round. `since` per tag; `out`
// keyed by tag. True when at least one node answered.
bool NetFetchEnvelopes(const std::vector<std::pair<std::string, int64_t> >& vTagSince,
                       std::map<std::string, std::vector<std::vector<unsigned char> > >& out,
                       std::string& errOut);

// Publish our own descriptor and epoch keys. `sign_sk` is the chat identity's
// signing key; it is used for this call and not kept.
bool NetPublishDescriptor(const unsigned char sign_sk[32], const std::string& encPubHex,
                          const std::string& onion, std::string& errOut);
bool NetPublishEpochKeys(const std::string& chatAddr, const std::string& annJson,
                         int64_t nEpoch, std::string& errOut);

// For the status line: nodes known, and how many answered lately.
void NetNodeCounts(size_t& nKnown, size_t& nGood);

} // namespace btfchat

#endif
