// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_TEST_LIGHT_POW_H
#define BITFLASH_TEST_LIGHT_POW_H

#include "dgb_pow.h"
#include "rvn_kawpow.h"
#include "test_light_pow_vectors.h"
#include <chrono>

// Called from selftest.cpp after Check/ParseHex; also usable by a standalone
// sanitizer driver, so the foreign-chain modules need no wallet dependencies.
static double LightPoWMicros(std::chrono::steady_clock::time_point start)
{
    return std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
}

static int RunDgbPoWSelfTest()
{
    bool ok = true;
    std::string err;
    std::vector<dgbpow::PastBlock> parents;
    unsigned int algorithms = 0;
    uint32_t firstKey = 0, lastKey = 0;
    double micros[8] = {};
    unsigned int counts[8] = {};
    dgbpow::Header first;
    for (const auto& vector : lightpowtest::dgb)
    {
        auto raw = ParseHex(vector.raw);
        dgbpow::Header header;
        if (!Check(dgbpow::ParseHeader(raw.data(), raw.size(), header, err), "DGB parse mainnet header"))
            return 1;
        ok &= Check(lightpow::DisplayHash(dgbpow::BlockHash(header)) == vector.hash, "DGB mainnet block ID");
        if (!parents.empty() && vector.height == parents.back().height + 1)
        {
            const auto& previous = lightpowtest::dgb[parents.size() - 1];
            auto hash = ParseHex(previous.hash);
            ok &= Check(std::equal(hash.rbegin(), hash.rend(), header.raw.begin() + 4), "DGB consecutive previous hash");
        }
        if (vector.height >= dgbpow::CHECKPOINT_HEIGHT)
        {
            const auto algo = dgbpow::Algorithm(header);
            algorithms |= 1U << algo;
            if (algo == dgbpow::ODOCRYPT)
            {
                lastKey = dgbpow::OdoKey(header.Time());
                if (!firstKey) firstKey = lastKey;
            }
            const auto start = std::chrono::steady_clock::now();
            const bool valid = dgbpow::CheckProofOfWork(header, vector.height, err);
            micros[algo] += LightPoWMicros(start);
            ++counts[algo];
            ok &= Check(valid, "DGB real mainnet PoW");
            lightpow::Hash hash{};
            ok &= Check(dgbpow::PoWHash(header, hash, err) && lightpow::DisplayHash(hash) == vector.proof, "DGB expected algorithm digest");
            auto mutated = header;
            mutated.raw[76] ^= 1;
            ok &= Check(!dgbpow::CheckProofOfWork(mutated, vector.height, err), "DGB nonce mutation rejected");
            if (*vector.work)
            {
                ok &= Check(dgbpow::NextWorkRequired(parents, algo, err) == header.Bits(), "DGB consecutive MultiShield difficulty");
                ok &= Check(dgbpow::BlockProof(parents, header, vector.height, hash, err) &&
                            lightpow::DisplayHash(hash) == vector.work, "DGB Core geometric chain work");
                lightpow::Hash validated{};
                ok &= Check(dgbpow::ValidateHeader(parents, header, vector.height, validated, err) &&
                            validated == hash, "DGB ValidateHeader takes the real header, same work");
                ok &= Check(!dgbpow::ValidateHeader(parents, mutated, vector.height, validated, err),
                            "DGB ValidateHeader refuses a broken proof that BlockProof alone would price");
                if (vector.height == dgbpow::CHECKPOINT_HEIGHT) first = header;
            }
        }
        dgbpow::PastBlock parent;
        parent.height = vector.height;
        parent.time = header.Time();
        parent.bits = header.Bits();
        parent.algo = dgbpow::Algorithm(header);
        parents.push_back(parent);
    }
    ok &= Check(algorithms == ((1U << 0) | (1U << 1) | (1U << 3) | (1U << 4) | (1U << 7)), "DGB all five current algorithms");
    ok &= Check(firstKey == 1785888000U && lastKey == 1786752000U && firstKey != lastKey, "DGB two real Odocrypt key epochs");
    ok &= Check(dgbpow::OdoKey(1786751999U) == 1785888000U && dgbpow::OdoKey(1786752000U) == 1786752000U, "DGB exact Odocrypt epoch boundary");
    dgbpow::Header parsed;
    ok &= Check(!dgbpow::ParseHeader(nullptr, 80, parsed, err) && !dgbpow::ParseHeader(first.raw.data(), 79, parsed, err), "DGB malformed header size rejected");
    auto unknown = first;
    unknown.raw[1] = (unknown.raw[1] & 0xf0) | 4;
    ok &= Check(!dgbpow::ParseHeader(unknown.raw.data(), 80, parsed, err) &&
                !dgbpow::CheckProofOfWork(unknown, dgbpow::CHECKPOINT_HEIGHT, err), "DGB retired algorithm rejected");
    ok &= Check(!dgbpow::CheckProofOfWork(first, dgbpow::CHECKPOINT_HEIGHT - 1, err), "DGB checkpoint range enforced");
    for (uint32_t bits : {0U, 0x1d80ffffU, 0x23000001U, 0x1e100000U})
    {
        auto invalid = first;
        for (int i = 0; i < 4; ++i) invalid.raw[72 + i] = static_cast<unsigned char>(bits >> (8 * i));
        ok &= Check(!dgbpow::CheckProofOfWork(invalid, dgbpow::CHECKPOINT_HEIGHT, err), "DGB zero/negative/overflow/above-limit target rejected");
    }
    std::vector<dgbpow::PastBlock> missing(parents.begin(), parents.begin() + 60);
    ok &= Check(dgbpow::NextWorkRequired(missing, dgbpow::SHA256D, err) == 0 && !err.empty(), "DGB missing history fails closed");
    missing.assign(parents.begin(), parents.begin() + 100);
    missing[50].height++;
    ok &= Check(dgbpow::NextWorkRequired(missing, dgbpow::SHA256D, err) == 0, "DGB mixed or gapped branch history rejected");
    missing.assign(parents.begin(), parents.begin() + 100);
    lightpow::Hash work{};
    auto wrong = first;
    wrong.raw[72] ^= 1;
    ok &= Check(!dgbpow::BlockProof(missing, wrong, dgbpow::CHECKPOINT_HEIGHT, work, err), "DGB work rejects unexpected difficulty");
    ok &= Check(!dgbpow::BlockProof(missing, first, dgbpow::CHECKPOINT_HEIGHT + 1, work, err), "DGB work rejects wrong candidate height");
    ok &= Check(!dgbpow::ValidateHeader(missing, wrong, dgbpow::CHECKPOINT_HEIGHT, work, err) &&
                !dgbpow::ValidateHeader(missing, first, dgbpow::CHECKPOINT_HEIGHT + 1, work, err),
                "DGB ValidateHeader refuses a wrong difficulty or height before any proof");
    for (int algo : {0, 1, 3, 4, 7})
        printf("dgb-pow: algo=%d %.3f us/header (%u real headers)\n", algo, micros[algo] / counts[algo], counts[algo]);
    printf("dgb-pow self-test: %s (101 proofs, 100 consecutive retargets/work)\n", ok ? "PASS" : "FAIL");
    fflush(stdout);
    return ok ? 0 : 1;
}

static int RunRvnKawPoWSelfTest()
{
    bool ok = true;
    std::string err;
    std::vector<lightpow::PastBlock> parents;
    rvnpow::ClearCache();
    double cold = 0, warm = 0;
    unsigned int coldCount = 0, warmCount = 0;
    rvnpow::Header first, last;
    std::vector<lightpow::PastBlock> lastParents;
    for (const auto& vector : lightpowtest::rvn)
    {
        auto raw = ParseHex(vector.raw);
        rvnpow::Header header;
        if (!Check(rvnpow::ParseHeader(raw.data(), raw.size(), header, err), "RVN parse mainnet KAWPOW header"))
            return 1;
        ok &= Check(header.Height() == static_cast<uint32_t>(vector.height), "RVN embedded mainnet height");
        ok &= Check(lightpow::DisplayHash(rvnpow::BlockHash(header)) == vector.hash, "RVN expected KAWPOW block ID");
        if (!parents.empty())
        {
            auto hash = ParseHex(lightpowtest::rvn[parents.size() - 1].hash);
            ok &= Check(std::equal(hash.rbegin(), hash.rend(), header.raw.begin() + 4), "RVN consecutive previous hash");
        }
        lightpow::Hash work{};
        ok &= Check(rvnpow::BlockProof(header.Bits(), work, err) && lightpow::DisplayHash(work) == vector.work, "RVN Core chain work");
        if (vector.height >= rvnpow::CHECKPOINT_HEIGHT)
        {
            const auto count = rvnpow::CachedEpochs();
            const auto start = std::chrono::steady_clock::now();
            const bool valid = rvnpow::CheckProofOfWork(header, err);
            const double micros = LightPoWMicros(start);
            if (rvnpow::CachedEpochs() > count) { cold += micros; ++coldCount; }
            else { warm += micros; ++warmCount; }
            ok &= Check(valid, "RVN real mainnet mix and final target");
            ok &= Check(rvnpow::NextWorkRequired(parents, err) == header.Bits(), "RVN consecutive DGW difficulty");
            auto mutated = header;
            mutated.raw[80] ^= 1;
            ok &= Check(!rvnpow::CheckProofOfWork(mutated, err), "RVN nonce mutation rejected");
            mutated = header;
            mutated.raw[88] ^= 1;
            ok &= Check(!rvnpow::CheckProofOfWork(mutated, err), "RVN mix mutation rejected");
            lightpow::Hash validated{};
            ok &= Check(rvnpow::ValidateHeader(parents, header, validated, err) && validated == work,
                        "RVN ValidateHeader takes the real header, same work");
            if (vector.height == rvnpow::CHECKPOINT_HEIGHT) first = header;
            last = header;
            lastParents = parents;
        }
        parents.push_back({vector.height, header.Time(), header.Bits()});
    }
    ok &= Check(coldCount == 2 && warmCount == 30 && rvnpow::CachedEpochs() == 2 &&
                rvnpow::CachedBytes() <= 256U * 1024 * 1024, "RVN two bounded light caches across real epochs 600/601");
    rvnpow::Header parsed;
    ok &= Check(!rvnpow::ParseHeader(nullptr, 120, parsed, err) && !rvnpow::ParseHeader(first.raw.data(), 119, parsed, err), "RVN malformed header size rejected");
    auto early = first;
    for (int i = 0; i < 4; ++i) early.raw[68 + i] = 0;
    ok &= Check(!rvnpow::ParseHeader(early.raw.data(), 120, parsed, err) && !rvnpow::CheckProofOfWork(early, err), "RVN pre-KAWPOW header rejected");
    early = first;
    early.raw[79] = 0xff;
    ok &= Check(!rvnpow::ParseHeader(early.raw.data(), 120, parsed, err) && !rvnpow::CheckProofOfWork(early, err), "RVN excessive embedded height rejected");
    for (uint32_t bits : {0U, 0x1d80ffffU, 0x23000001U, 0x1e100000U})
    {
        auto invalid = first;
        for (int i = 0; i < 4; ++i) invalid.raw[72 + i] = static_cast<unsigned char>(bits >> (8 * i));
        lightpow::Hash work{};
        ok &= Check(!rvnpow::CheckProofOfWork(invalid, err) && !rvnpow::BlockProof(bits, work, err), "RVN malformed/above-limit target rejected");
    }
    std::vector<lightpow::PastBlock> missing(parents.begin(), parents.begin() + 179);
    ok &= Check(rvnpow::NextWorkRequired(missing, err) == 0 && !err.empty(), "RVN missing history fails closed");
    missing.assign(parents.begin(), parents.begin() + 180);
    missing[50].height++;
    ok &= Check(rvnpow::NextWorkRequired(missing, err) == 0, "RVN mixed or gapped branch history rejected");
    printf("rvn-kawpow: cold %.3f ms/header (%u epochs), warm %.3f ms/header (%u proofs), cache %llu bytes\n",
           cold / coldCount / 1000, coldCount, warm / warmCount / 1000, warmCount,
           static_cast<unsigned long long>(rvnpow::CachedBytes()));
    // Prime LRU with epoch 600, then force verification (not the cheap target
    // rejection) with invalid mixes in epoch 600 and a third epoch, 602.
    ok &= Check(rvnpow::CheckProofOfWork(first, err), "RVN reuse first epoch cache");
    for (const char* text : lightpowtest::forgedRvn)
    {
        const auto raw = ParseHex(text);
        rvnpow::Header forged;
        ok &= Check(rvnpow::ParseHeader(raw.data(), raw.size(), forged, err), "RVN forged candidate parses");
        const auto finalHash = lightpow::DisplayHash(rvnpow::BlockHash(forged));
        ok &= Check(finalHash <= "00000fffff000000000000000000000000000000000000000000000000000000",
                    "RVN forged candidate passes final target precheck");
        ok &= Check(!rvnpow::CheckProofOfWork(forged, err) && err.find("mix does not match") != std::string::npos,
                    "RVN reject invalid mix even when final hash meets target");
        ok &= Check(rvnpow::CachedEpochs() == 2 && rvnpow::CachedBytes() <= 256U * 1024 * 1024,
                    "RVN evicts before allocating third light cache");
    }
    ok &= Check(rvnpow::CheckProofOfWork(first, err), "RVN LRU retained epoch remains valid");
    rvnpow::ClearCache();
    ok &= Check(rvnpow::CachedEpochs() == 0 && rvnpow::CachedBytes() == 0, "RVN cache release");
    // A forged header names its own nBits and embedded height, so its epoch:
    // ValidateHeader must refuse it on those, before building any cache.
    {
        lightpow::Hash work{};
        auto easy = last;
        for (int i = 0; i < 4; ++i) easy.raw[72 + i] = static_cast<unsigned char>(0x1e0fffffU >> (8 * i));
        ok &= Check(!rvnpow::ValidateHeader(lastParents, easy, work, err) && rvnpow::CachedEpochs() == 0,
                    "RVN ValidateHeader refuses a self-chosen easy nBits before any cache");
        const auto raw = ParseHex(lightpowtest::forgedRvn[1]);
        rvnpow::Header forged;
        rvnpow::ParseHeader(raw.data(), raw.size(), forged, err);
        ok &= Check(!rvnpow::ValidateHeader(lastParents, forged, work, err) && rvnpow::CachedEpochs() == 0,
                    "RVN ValidateHeader refuses an embedded height off the branch before any cache");
        // The first epoch past MAX_CACHE_BYTES, at the easiest target, with a
        // nonce found so the cheap final-hash check passes: only the budget
        // can stop it, and it must, before allocating.
        auto distant = last;
        const uint32_t beyond = 7500U * 1920U;
        for (int i = 0; i < 4; ++i) distant.raw[76 + i] = static_cast<unsigned char>(beyond >> (8 * i));
        for (int i = 0; i < 4; ++i) distant.raw[72 + i] = static_cast<unsigned char>(0x1e0fffffU >> (8 * i));
        bool found = false;
        for (uint64_t nonce = 0; nonce < (uint64_t(1) << 26) && !found; ++nonce)
        {
            for (int i = 0; i < 8; ++i) distant.raw[80 + i] = static_cast<unsigned char>(nonce >> (8 * i));
            found = lightpow::DisplayHash(rvnpow::BlockHash(distant)) <=
                    "00000fffff000000000000000000000000000000000000000000000000000000";
        }
        ok &= Check(found && !rvnpow::CheckProofOfWork(distant, err) &&
                    err.find("resource budget") != std::string::npos && rvnpow::CachedEpochs() == 0,
                    "RVN an epoch past this node's cache budget is refused without allocating");
    }
    printf("rvn-kawpow self-test: %s (32 proofs, 32 consecutive retargets)\n", ok ? "PASS" : "FAIL");
    fflush(stdout);
    return ok ? 0 : 1;
}
#endif
