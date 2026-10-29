// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static bool Check(bool condition, const char* message)
{
    if (!condition)
        std::printf("FAIL: %s\n", message);
    return condition;
}

static std::vector<unsigned char> ParseHex(const char* text)
{
    const std::string input(text);
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < input.size(); i += 2)
        bytes.push_back(static_cast<unsigned char>(std::stoul(input.substr(i, 2), nullptr, 16)));
    return bytes;
}

#include "test_light_pow.h"

// This driver keeps the real self-test bodies usable without wallet libraries,
// so native and sanitizer runs exercise exactly the assertions in RunSelfTest.
int main(int argc, char** argv)
{
    if (argc == 1)
    {
        const int dgb = RunDgbPoWSelfTest();
        const int rvn = RunRvnKawPoWSelfTest();
        return dgb || rvn;
    }
    const std::string name(argv[1]);
    if (name == "dgb-pow") return RunDgbPoWSelfTest();
    if (name == "rvn-kawpow") return RunRvnKawPoWSelfTest();
    std::fprintf(stderr, "Usage: test_light_pow [dgb-pow|rvn-kawpow]\n");
    return 2;
}
