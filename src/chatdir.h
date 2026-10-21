// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The node's reading of the public community directory off the chain
// (community.h), and its answer to the chat app's "getchatdir".
//
// Public data, kept in chat-directory.dat in the clear: everything in it is in
// a block anyway. Not consensus: a listing is an output like any other, and a
// node that never heard of communities carries it unchanged.

#ifndef BITFLASH_CHATDIR_H
#define BITFLASH_CHATDIR_H

#include <string>
#include <vector>

class CChatListing
{
public:
    std::vector<unsigned char> key;   // 32 bytes
    std::string name;
    int nHeight;
    int64 nTime;
    int64 nBurn;
    uint256 txid;

    CChatListing() : nHeight(-1), nTime(0), nBurn(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(key);
        READWRITE(name);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nBurn);
        READWRITE(txid);
    )
};

// Listings the directory answers with, at most.
static const unsigned int CHAT_DIRECTORY_MAX = 2000;

// The background reader, started with the node.
void ThreadChatDirectory(void* parg);

// What has been read so far, oldest first.
void ChatDirectoryListings(std::vector<CChatListing>& out);
int ChatDirectoryHeight();

// For tests: read one block's listings into the directory.
int ChatDirectoryScanBlock(const CBlock& block, int nHeight);

#endif
