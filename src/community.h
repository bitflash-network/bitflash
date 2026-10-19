// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Public communities: open rooms whose directory is the chain.
//
// A community is a 32-byte key and a name. A PUBLIC one puts both in a block:
// creating it burns at least 0.01 BTF into an OP_RETURN that reads
//
//     "BTFC" | 0 | 4 | key (32) | name (1..32 letters, digits, - or _)
//
// (the format the btfchat branch tested on testnet in September, unchanged, so
// what was listed then is listed now). Every node reads the chain for those and
// answers the chat with the list; nobody can take one down, not the creator and
// not the network. The burn is the only moderation, and it is what keeps the
// directory from being free to fill.
//
// Posts are signed frames from the poster's identity, sealed with the
// community key, and left with the nodes like any offline message -- under a
// tag that changes daily, which everybody who has the key can compute. A node
// holding them sees envelopes under a tag, not what they say or who wrote
// them. For a public community that is a courtesy, not a secret: the key is in
// a block for anybody to read.

#ifndef BITFLASH_COMMUNITY_H
#define BITFLASH_COMMUNITY_H

#include <string>
#include <vector>
#include <stdint.h>

namespace community
{

static const size_t KEY_BYTES = 32;
static const size_t NAME_MAX  = 32;

// What a listing must burn to be shown: 0.01 BTF.
static const int64_t MIN_BURN = 1000000;

// The data inside the OP_RETURN, and reading it back. ParseListing takes the
// whole scriptPubKey.
std::vector<unsigned char> ListingData(const unsigned char key[KEY_BYTES], const std::string& name);
bool ParseListing(const std::vector<unsigned char>& scriptPubKey, unsigned char keyOut[KEY_BYTES],
                  std::string& nameOut);

bool NameOk(const std::string& name);

// The community's public id (what tells two #bitflash apart), and the tag its
// posts are filed under on a given day. Both derived from the key, so whoever
// can read the community can find it.
std::string IdHex(const unsigned char key[KEY_BYTES]);
std::string TagHex(const unsigned char key[KEY_BYTES], int64_t nEpoch);

// Seal a post (a signed frame) with the key, and open one.
bool Seal(const unsigned char key[KEY_BYTES], const std::string& frameJson,
          std::vector<unsigned char>& out);
bool Open(const unsigned char key[KEY_BYTES], const std::vector<unsigned char>& in,
          std::string& frameJsonOut);

} // namespace community

#endif
