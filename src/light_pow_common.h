// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_LIGHT_POW_COMMON_H
#define BITFLASH_LIGHT_POW_COMMON_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace lightpow
{
// Hashes and work use Bitcoin's internal little-endian byte order. Display
// hashes by reversing these bytes; no legacy, non-const uint256 access is used.
using Hash = std::array<unsigned char, 32>;

struct PastBlock
{
    int height;
    uint32_t time;
    uint32_t bits;
};

inline uint32_t Read32(const unsigned char* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline uint64_t Read64(const unsigned char* p)
{
    return uint64_t(Read32(p)) | (uint64_t(Read32(p + 4)) << 32);
}

inline std::string DisplayHash(const Hash& hash)
{
    const char alphabet[] = "0123456789abcdef";
    std::string text;
    text.reserve(64);
    for (auto it = hash.rbegin(); it != hash.rend(); ++it)
    {
        text.push_back(alphabet[*it >> 4]);
        text.push_back(alphabet[*it & 15]);
    }
    return text;
}

}
#endif
