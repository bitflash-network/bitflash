// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_LIGHT_POW_INTERNAL_H
#define BITFLASH_LIGHT_POW_INTERNAL_H

#include "light_pow_common.h"
#pragma push_macro("snprintf")
#undef snprintf
#include <boost/multiprecision/cpp_int.hpp>
#pragma pop_macro("snprintf")
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>

namespace lightpow
{
namespace detail
{
using UInt = boost::multiprecision::uint256_t;

inline UInt Number(const Hash& hash)
{
    UInt n = 0;
    for (int i = 31; i >= 0; --i)
    {
        n <<= 8;
        n |= hash[static_cast<size_t>(i)];
    }
    return n;
}

inline Hash Bytes(UInt value)
{
    Hash out{};
    for (auto& byte : out)
    {
        byte = static_cast<unsigned char>((value & 255).convert_to<unsigned int>());
        value >>= 8;
    }
    return out;
}

// Bitcoin arith_uint256::SetCompact, as shipped by both pinned upstreams.
inline bool Target(uint32_t bits, const UInt& limit, UInt& out)
{
    const unsigned int size = bits >> 24;
    uint32_t word = bits & 0x007fffff;
    if (size <= 3)
        word >>= 8 * (3 - size);
    const bool negative = word != 0 && (bits & 0x00800000) != 0;
    const bool overflow = word != 0 && (size > 34 ||
        (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if (negative || overflow || word == 0)
        return false;
    out = word;
    if (size > 3)
        out <<= 8 * (size - 3);
    return out != 0 && out <= limit;
}

inline uint32_t Compact(const UInt& target)
{
    if (target == 0)
        return 0;
    unsigned int size = (boost::multiprecision::msb(target) + 8) / 8;
    UInt mantissa = target;
    if (size <= 3)
        mantissa <<= 8 * (3 - size);
    else
        mantissa >>= 8 * (size - 3);
    uint32_t word = mantissa.convert_to<uint32_t>();
    if (word & 0x00800000)
    {
        word >>= 8;
        ++size;
    }
    return word | (size << 24);
}

inline UInt Work(const UInt& target)
{
    // Fixed-width complement/division matches Core, including its rounding.
    return (~target / (target + 1)) + 1;
}

inline Hash DoubleSHA(const unsigned char* data, size_t size)
{
    unsigned char first[32];
    Hash out{};
    SHA256(data, size, first);
    SHA256(first, sizeof(first), out.data());
    return out;
}

inline bool Fail(std::string& err, const char* message)
{
    err = message;
    return false;
}
}
}
#endif
