// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The node's side of the chat: hold the records (chatstore.h), hand them to
// peers the way transactions are handed around, and answer the chat app's
// questions.
//
// Two kinds of caller, one port. Other NODES speak inventory: "inv" offers a
// record by id, "getdata" asks for it, "chatrec" carries it -- the transaction
// pattern, so a record left at one node reaches every node that holds chat
// records without anyone choosing where. The chat APP speaks request and answer:
// "chatput" leaves a record and gets a "chatack" saying whether it was kept,
// "chatget" asks for what is filed under some keys and gets "chatrecs". The app
// connects like any peer, over the node's onion, and says in its version that
// it is not a node.
//
// Nothing a peer sends is trusted. chatstore.cpp checks the work, the time, the
// signature; this file rations how much any one peer may ask for.

#ifndef BITFLASH_CHATRELAY_H
#define BITFLASH_CHATRELAY_H

#include <string>
#include <vector>

class CNode;
class CInv;
class CDataStream;

// One question in a "chatget": what is filed under `key` of `kind`, from
// `nSince` on, at most `nMax` records.
class CChatQuery
{
public:
    unsigned char kind;
    std::vector<unsigned char> key;
    int64 nSince;
    int nMax;

    CChatQuery() : kind(0), nSince(0), nMax(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(kind);
        READWRITE(key);
        READWRITE(nSince);
        READWRITE(nMax);
    )
};

// Questions a single "chatget" may carry, and the bytes its answer may take.
static const unsigned int CHAT_MAX_QUERIES_PER_MSG = 32;
static const unsigned int CHAT_MAX_ANSWER_BYTES = 4 * 1024 * 1024;

// "chatack" result codes: the ChatStore::Result values, sent as an int.

// True if `strCommand` is one of the chat's and was dealt with here.
bool ChatRelayProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);

// For "inv": do we already hold this record.
bool ChatRelayAlreadyHave(const CInv& inv);

// For "getdata": send the record if we hold it. True if it was ours to answer.
bool ChatRelayServeGetData(CNode* pfrom, const CInv& inv);

// After a peer's version: if it holds chat records too, ask what it has. A node
// that just started holds nothing, and a message waiting for somebody should
// not depend on which node they happen to ask.
void ChatRelayOnVersion(CNode* pfrom);

// Counts, for the status line and the selftest.
void ChatRelayStats(size_t& nRecords, size_t& nEnvelopeBytes);

#endif
