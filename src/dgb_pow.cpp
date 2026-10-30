// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "dgb_pow.h"
#include "light_pow_internal.h"
#include "pow_vendor/dgb/sph_skein.h"
#include "pow_vendor/dgb/sph_luffa.h"
#include "pow_vendor/dgb/sph_cubehash.h"
#include "pow_vendor/dgb/sph_shavite.h"
#include "pow_vendor/dgb/sph_simd.h"
#include "pow_vendor/dgb/sph_echo.h"
#include "pow_vendor/dgb/odocrypt.h"
#include "pow_vendor/dgb/KeccakP-800-SnP.h"
#include <openssl/evp.h>
#include <limits>

namespace dgbpow
{
using lightpow::detail::UInt;
using lightpow::detail::Fail;

static UInt PowLimit()
{
    // DigiByte Core v8.22.2, src/chainparams.cpp CMainParams: ~uint256(0) >> 20.
    return (UInt(1) << 236) - 1;
}

static bool Active(Algo algo)
{
    // v8.22.2 src/validation.cpp IsAlgoActive: the five post-Odo algorithms.
    return algo == SHA256D || algo == SCRYPT || algo == SKEIN ||
           algo == QUBIT || algo == ODOCRYPT;
}

Algo Algorithm(const Header& header)
{
    // v8.22.2 src/primitives/block.{h,cpp}: mask is four bits, not three.
    switch (header.Version() & (15U << 8))
    {
        case 0U << 8: return SCRYPT;
        case 2U << 8: return SHA256D;
        case 6U << 8: return SKEIN;
        case 8U << 8: return QUBIT;
        case 14U << 8: return ODOCRYPT;
        default: return UNKNOWN;
    }
}

uint32_t OdoKey(uint32_t time)
{
    // v8.22.2 src/primitives/block.cpp OdoKey and CMainParams: ten UTC days,
    // anchored at Unix zero, rather than an epoch counted from activation.
    return time - time % (10U * 24 * 60 * 60);
}

bool ParseHeader(const unsigned char* raw, size_t size, Header& out, std::string& err)
{
    err.clear();
    if (raw == nullptr || size != HEADER_SIZE)
        return Fail(err, "DigiByte header must contain exactly 80 bytes");
    Header parsed;
    std::copy(raw, raw + size, parsed.raw.begin());
    if (!Active(Algorithm(parsed)))
        return Fail(err, "unknown or retired DigiByte algorithm version bits");
    out = parsed;
    return true;
}

lightpow::Hash BlockHash(const Header& header)
{
    // Block ID remains SHA256d even when a different algorithm supplies PoW.
    return lightpow::detail::DoubleSHA(header.raw.data(), header.raw.size());
}

bool PoWHash(const Header& header, lightpow::Hash& hash, std::string& err)
{
    err.clear();
    hash.fill(0);
    switch (Algorithm(header))
    {
        case SHA256D:
            hash = BlockHash(header);
            return true;
        case SCRYPT:
            // v8.22.2 src/crypto/scrypt.cpp: password and salt are the same
            // 80-byte header; N=1024, r=p=1, output=256 bits.
            if (EVP_PBE_scrypt(reinterpret_cast<const char*>(header.raw.data()), HEADER_SIZE,
                               header.raw.data(), HEADER_SIZE, 1024, 1, 1,
                               1024 * 1024, hash.data(), hash.size()) != 1)
                return Fail(err, "DigiByte scrypt computation failed");
            return true;
        case SKEIN:
        {
            // v8.22.2 src/crypto/hashskein.h: Skein-512 followed by SHA256,
            // not a truncated Skein digest and not SHA256d.
            alignas(16) unsigned char result[64];
            sph_skein512_context context;
            sph_skein512_init(&context);
            sph_skein512(&context, header.raw.data(), HEADER_SIZE);
            sph_skein512_close(&context, result);
            SHA256(result, sizeof(result), hash.data());
            return true;
        }
        case QUBIT:
        {
            // v8.22.2 src/crypto/hashqubit.h, all five stages are 512-bit.
            alignas(16) unsigned char a[64], b[64];
            sph_luffa512_context luffa;
            sph_cubehash512_context cube;
            sph_shavite512_context shavite;
            sph_simd512_context simd;
            sph_echo512_context echo;
            sph_luffa512_init(&luffa);
            sph_luffa512(&luffa, header.raw.data(), HEADER_SIZE);
            sph_luffa512_close(&luffa, a);
            sph_cubehash512_init(&cube);
            sph_cubehash512(&cube, a, sizeof(a));
            sph_cubehash512_close(&cube, b);
            sph_shavite512_init(&shavite);
            sph_shavite512(&shavite, b, sizeof(b));
            sph_shavite512_close(&shavite, a);
            sph_simd512_init(&simd);
            sph_simd512(&simd, a, sizeof(a));
            sph_simd512_close(&simd, b);
            sph_echo512_init(&echo);
            sph_echo512(&echo, b, sizeof(b));
            sph_echo512_close(&echo, a);
            std::copy(a, a + hash.size(), hash.begin());
            return true;
        }
        case ODOCRYPT:
        {
            // v8.22.2 src/crypto/hashodo.h: the delimiter byte is outside the
            // 80-byte encryption, but inside the 100-byte Keccak-p[800] state.
            alignas(16) char state[100] = {};
            std::memcpy(state, header.raw.data(), HEADER_SIZE);
            state[HEADER_SIZE] = 1;
            OdoCrypt(OdoKey(header.Time())).Encrypt(state, state);
            KeccakP800_Permute_12rounds(state);
            std::memcpy(hash.data(), state, hash.size());
            return true;
        }
        default:
            return Fail(err, "unknown or retired DigiByte proof algorithm");
    }
}

bool CheckProofOfWork(const Header& header, int height, std::string& err)
{
    err.clear();
    if (height < CHECKPOINT_HEIGHT)
        return Fail(err, "DigiByte header precedes the supported checkpoint");
    UInt target;
    if (!lightpow::detail::Target(header.Bits(), PowLimit(), target))
        return Fail(err, "invalid DigiByte compact target");
    lightpow::Hash hash{};
    if (!PoWHash(header, hash, err))
        return false;
    if (lightpow::detail::Number(hash) > target)
        return Fail(err, "DigiByte proof hash exceeds the target");
    return true;
}

static int64_t Median(const std::vector<PastBlock>& history, size_t pos)
{
    std::array<uint32_t, 11> times{};
    for (size_t i = 0; i < times.size(); ++i)
        times[i] = history[pos - i].time;
    std::sort(times.begin(), times.end());
    return times[5];
}

static bool History(const std::vector<PastBlock>& history, std::string& err)
{
    if (history.size() < 61 || history.back().height < CHECKPOINT_HEIGHT - 1)
        return Fail(err, "DigiByte retarget requires 61 checkpoint-context parents");
    for (size_t i = 0; i < history.size(); ++i)
    {
        UInt target;
        if (history[i].height < 0 || !Active(history[i].algo) ||
            !lightpow::detail::Target(history[i].bits, PowLimit(), target))
            return Fail(err, "invalid DigiByte difficulty history");
        if (i && (history[i - 1].height == (std::numeric_limits<int>::max)() ||
                  history[i].height != history[i - 1].height + 1))
            return Fail(err, "DigiByte difficulty history must be consecutive");
    }
    return true;
}

static uint32_t Next(const std::vector<PastBlock>& history, Algo algo, std::string& err)
{
    if (!Active(algo))
    {
        err = "unknown or retired DigiByte retarget algorithm";
        return 0;
    }
    size_t previous = history.size();
    for (size_t i = history.size(); i > 0; --i)
        if (history[i - 1].algo == algo)
        {
            previous = i - 1;
            break;
        }
    if (previous == history.size())
    {
        err = "missing most-recent DigiByte parent for this algorithm";
        return 0;
    }
    // v8.22.2 src/pow.cpp GetNextWorkRequiredV4, and src/chainparams.cpp:
    // 5 algorithms * 10 blocks * 15 seconds; median interval over 50 parents.
    const size_t last = history.size() - 1;
    int64_t elapsed = Median(history, last) - Median(history, last - 50);
    elapsed = 750 + (elapsed - 750) / 4;
    elapsed = std::max<int64_t>(690, std::min<int64_t>(870, elapsed));
    UInt target;
    lightpow::detail::Target(history[previous].bits, PowLimit(), target);
    target *= elapsed;
    target /= 750;
    const int64_t adjustments = int64_t(history[previous].height) + 4 - history[last].height;
    if (adjustments > 0)
        for (int64_t i = 0; i < adjustments; ++i)
        {
            target *= 100;
            target /= 104;
        }
    else
        for (int64_t i = 0; i < -adjustments; ++i)
        {
            const UInt before = target;
            target *= 104;
            target /= 100;
            if (target > PowLimit())
            {
                target = PowLimit();
                break;
            }
            // Core's repeated integer operation has a fixed point at tiny
            // targets. Skipping the remaining identical steps avoids a long
            // loop on deliberately sparse, caller-supplied histories.
            if (target == before)
                break;
        }
    if (target > PowLimit())
        target = PowLimit();
    return lightpow::detail::Compact(target);
}

uint32_t NextWorkRequired(const std::vector<PastBlock>& history, Algo algo, std::string& err)
{
    err.clear();
    if (!History(history, err))
        return 0;
    return Next(history, algo, err);
}

static UInt ApproxFifthRoot(const UInt& value)
{
    // v8.22.2 src/arith_uint256.cpp ApproxNthRoot(5). An exact integer root
    // would change chain work: Core deliberately roots a truncated high word.
    const int length = static_cast<int>(boost::multiprecision::msb(value)) + 1;
    const int shifts = std::max(0, (length - 1) / 5 + 1 - 64 / 5);
    const uint64_t head = (value >> (5 * shifts)).convert_to<uint64_t>();
    uint64_t root = 0;
    for (int i = 64 / 5 - 1; i >= 0; --i)
    {
        const uint64_t next = root | (uint64_t(1) << i);
        uint64_t power = next;
        for (int j = 1; j < 5; ++j)
            power *= next;
        if (power <= head)
            root = next;
    }
    return UInt(root) << shifts;
}

bool BlockProof(const std::vector<PastBlock>& history, const Header& header,
                int height, lightpow::Hash& work, std::string& err)
{
    err.clear();
    work.fill(0);
    if (!History(history, err))
        return false;
    if (height < CHECKPOINT_HEIGHT || history.back().height == (std::numeric_limits<int>::max)() ||
        height != history.back().height + 1)
        return Fail(err, "DigiByte work requires the candidate's actual height");
    const uint32_t expected = Next(history, Algorithm(header), err);
    if (expected == 0)
        return err.empty() ? Fail(err, "DigiByte retarget gave no target") : false;
    if (header.Bits() != expected)
        return Fail(err, "DigiByte header difficulty does not match its history");
    // v8.22.2 src/chain.cpp GetBlockProof: post-DigiSpeed work is the inverse
    // product of approximate fifth roots of ALL active next targets, times 128.
    // The historical fixed Scrypt/Skein/Qubit factors do not apply here.
    const Algo algorithms[] = {SHA256D, SCRYPT, SKEIN, QUBIT, ODOCRYPT};
    UInt average = 1;
    for (Algo algo : algorithms)
    {
        const uint32_t bits = Next(history, algo, err);
        if (bits == 0)
            return false;
        UInt target;
        if (!lightpow::detail::Target(bits, PowLimit(), target))
            return Fail(err, "invalid DigiByte next target in work computation");
        average *= ApproxFifthRoot(target);
    }
    work = lightpow::detail::Bytes(lightpow::detail::Work(average) << 7);
    return true;
}

bool ValidateHeader(const std::vector<PastBlock>& parents, const Header& header,
                    int height, lightpow::Hash& work, std::string& err)
{
    err.clear();
    work.fill(0);
    if (!History(parents, err))
        return false;
    if (height < CHECKPOINT_HEIGHT || parents.back().height == (std::numeric_limits<int>::max)() ||
        height != parents.back().height + 1)
        return Fail(err, "DigiByte header height is not its parent's plus one");
    const uint32_t expected = Next(parents, Algorithm(header), err);
    if (expected == 0)
        return err.empty() ? Fail(err, "DigiByte retarget gave no target") : false;
    if (header.Bits() != expected)
        return Fail(err, "DigiByte header difficulty does not match its history");
    if (!CheckProofOfWork(header, height, err))
        return false;
    return BlockProof(parents, header, height, work, err);
}
}
