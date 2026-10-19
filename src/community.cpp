// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See community.h. Pure: no node, no socket, no chain.

#include "community.h"

#include <sodium.h>

#include <cctype>
#include <cstring>

namespace community
{

static const unsigned char MAGIC[4] = { 'B', 'T', 'F', 'C' };
static const unsigned char VERSION = 0;
static const unsigned char PURPOSE_PUBLIC_COMMUNITY = 4;

static std::string Hex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}

bool NameOk(const std::string& name)
{
    if (name.empty() || name.size() > NAME_MAX)
        return false;
    for (size_t i = 0; i < name.size(); i++)
    {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '-' || c == '_'))
            return false;
    }
    return true;
}

std::vector<unsigned char> ListingData(const unsigned char key[KEY_BYTES], const std::string& name)
{
    std::vector<unsigned char> d(MAGIC, MAGIC + 4);
    d.push_back(VERSION);
    d.push_back(PURPOSE_PUBLIC_COMMUNITY);
    d.insert(d.end(), key, key + KEY_BYTES);
    d.insert(d.end(), name.begin(), name.end());
    return d;
}

bool ParseListing(const std::vector<unsigned char>& s, unsigned char keyOut[KEY_BYTES],
                  std::string& nameOut)
{
    nameOut.clear();
    // OP_RETURN (0x6a), then one direct push of the data (1..75 bytes: a
    // listing is at most 70).
    if (s.size() < 3 || s[0] != 0x6a)
        return false;
    size_t n = s[1];
    if (n < 1 || n > 75 || s.size() != 2 + n)
        return false;
    const unsigned char* d = &s[2];
    if (n < 38 + 1 || n > 38 + NAME_MAX)
        return false;
    if (memcmp(d, MAGIC, 4) != 0 || d[4] != VERSION || d[5] != PURPOSE_PUBLIC_COMMUNITY)
        return false;
    std::string name((const char*)d + 38, n - 38);
    if (!NameOk(name))
        return false;
    memcpy(keyOut, d + 6, KEY_BYTES);
    nameOut = name;
    return true;
}

std::string IdHex(const unsigned char key[KEY_BYTES])
{
    static const char DS[] = "btfchat-community-id-1";
    unsigned char buf[sizeof(DS) - 1 + KEY_BYTES];
    memcpy(buf, DS, sizeof(DS) - 1);
    memcpy(buf + sizeof(DS) - 1, key, KEY_BYTES);
    unsigned char h[32];
    crypto_hash_sha256(h, buf, sizeof(buf));
    return Hex(h, 32);
}

std::string TagHex(const unsigned char key[KEY_BYTES], int64_t nEpoch)
{
    static const char DS[] = "btfchat-community-tag-1";
    unsigned char buf[sizeof(DS) - 1 + KEY_BYTES + 8];
    memcpy(buf, DS, sizeof(DS) - 1);
    memcpy(buf + sizeof(DS) - 1, key, KEY_BYTES);
    for (int i = 0; i < 8; i++)
        buf[sizeof(DS) - 1 + KEY_BYTES + i] = (unsigned char)((uint64_t)nEpoch >> (8 * i));
    unsigned char h[32];
    crypto_hash_sha256(h, buf, sizeof(buf));
    return Hex(h, 16);   // the 16-byte tag a mailbox record is filed under
}

bool Seal(const unsigned char key[KEY_BYTES], const std::string& frameJson,
          std::vector<unsigned char>& out)
{
    out.assign(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + frameJson.size(), 0);
    randombytes_buf(&out[0], crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(&out[crypto_secretbox_NONCEBYTES],
                                 (const unsigned char*)frameJson.data(), frameJson.size(),
                                 &out[0], key) == 0;
}

bool Open(const unsigned char key[KEY_BYTES], const std::vector<unsigned char>& in,
          std::string& frameJsonOut)
{
    frameJsonOut.clear();
    if (in.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 1)
        return false;
    std::vector<unsigned char> plain(in.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(&plain[0], &in[crypto_secretbox_NONCEBYTES],
                                   in.size() - crypto_secretbox_NONCEBYTES, &in[0], key) != 0)
        return false;
    frameJsonOut.assign((const char*)&plain[0], plain.size());
    return true;
}

} // namespace community
