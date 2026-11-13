// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Reading an integer out of JSON somebody else wrote.
//
// nlohmann's j.value("k", 0) and get<int>() convert whatever number is there
// with a plain cast. From a float that is out of the target's range (1e300
// read as an int) that cast is undefined behaviour, and from a float in range
// it silently truncates (1.9 reads as 1). A frame, an epoch announcement or a
// relay message is written by a stranger, so the fields that are integers are
// read here instead: an integer that fits, the default when the key is
// absent, and an exception for anything else (a float, a string, a number out
// of range), which the callers already treat as "a field of the wrong type".

#ifndef BITFLASH_JSONSAFE_H
#define BITFLASH_JSONSAFE_H

#include <nlohmann/json.hpp>

#include <limits>
#include <stdexcept>
#include <stdint.h>

template <typename T>
T JsonIntValue(const nlohmann::json& j, const char* key, T def)
{
    if (!j.is_object())
        throw std::invalid_argument("not an object");
    nlohmann::json::const_iterator it = j.find(key);
    if (it == j.end())
        return def;
    if (it->is_number_unsigned())
    {
        uint64_t u = it->get<uint64_t>();
        if (u > (uint64_t)std::numeric_limits<T>::max())
            throw std::out_of_range(key);
        return (T)u;
    }
    if (it->is_number_integer())
    {
        int64_t v = it->get<int64_t>();
        if (v < (int64_t)std::numeric_limits<T>::min() || v > (int64_t)std::numeric_limits<T>::max())
            throw std::out_of_range(key);
        return (T)v;
    }
    throw std::invalid_argument(key);
}

#endif
