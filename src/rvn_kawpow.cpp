// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "rvn_kawpow.h"
#include "light_pow_internal.h"
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <limits>
#include <mutex>

namespace rvnpow
{
using lightpow::detail::UInt;
using lightpow::detail::Fail;

static UInt PowLimit()
{
    // Ravencoin v4.6.1 src/chainparams.cpp CMainParams, consensus.powLimit.
    // The temporary kawpowLimit only applies to the first 180 KAWPOW blocks.
    return (UInt(1) << 236) - 1;
}

bool ParseHeader(const unsigned char* raw, size_t size, Header& out, std::string& err)
{
    err.clear();
    if (raw == nullptr || size != HEADER_SIZE)
        return Fail(err, "Ravencoin KAWPOW header must contain exactly 120 bytes");
    Header parsed;
    std::copy(raw, raw + size, parsed.raw.begin());
    // v4.6.1 src/chainparams.cpp CMainParams nKAAAWWWPOWActivationTime.
    if (parsed.Time() < 1588788000U)
        return Fail(err, "pre-KAWPOW Ravencoin header is unsupported");
    if (parsed.Height() > static_cast<uint32_t>((std::numeric_limits<int>::max)()))
        return Fail(err, "Ravencoin height exceeds upstream's signed block-number range");
    out = parsed;
    return true;
}

static ethash::hash256 Input(const Header& header)
{
    // v4.6.1 src/primitives/block.h CKAWPOWInput and src/hash.cpp KAWPOWHash:
    // SHA256d of the first 80 bytes, then GetHex/to_hash256 reverses the bytes.
    const auto hash = lightpow::detail::DoubleSHA(header.raw.data(), 80);
    ethash::hash256 input{};
    std::reverse_copy(hash.begin(), hash.end(), input.bytes);
    return input;
}

static ethash::hash256 Mix(const Header& header)
{
    ethash::hash256 mix{};
    std::reverse_copy(header.raw.begin() + 88, header.raw.end(), mix.bytes);
    return mix;
}

lightpow::Hash BlockHash(const Header& header)
{
    const int height = static_cast<int>(header.Height());
    const auto hash = progpow::hash_no_verify(height, Input(header), Mix(header), header.Nonce());
    lightpow::Hash out{};
    std::reverse_copy(hash.bytes, hash.bytes + sizeof(hash.bytes), out.begin());
    return out;
}

struct CacheEntry
{
    ethash::epoch_context_ptr context{nullptr, ethash_destroy_epoch_context};
    size_t bytes = 0;
    uint64_t used = 0;
};

struct EpochMemo
{
    std::array<CacheEntry, 2> entries;
    uint64_t clock = 0;
};

// Intentionally not managed.cpp's global cache: this memo has a hard two-entry
// bound and no full DAG. It is locked across the lookup AND the verification
// that uses the returned context: a second thread's eviction would otherwise
// free a context still being read. The lock costs nothing next to ~14 ms a
// proof.
static EpochMemo memo;
static std::mutex memoMutex;

size_t CachedEpochs()
{
    std::lock_guard<std::mutex> lock(memoMutex);
    size_t count = 0;
    for (const auto& entry : memo.entries)
        if (entry.context)
            ++count;
    return count;
}

size_t CachedBytes()
{
    std::lock_guard<std::mutex> lock(memoMutex);
    size_t bytes = 0;
    for (const auto& entry : memo.entries)
        bytes += entry.bytes;
    return bytes;
}

void ClearCache()
{
    std::lock_guard<std::mutex> lock(memoMutex);
    for (auto& entry : memo.entries)
    {
        entry.context.reset();
        entry.bytes = 0;
        entry.used = 0;
    }
    memo.clock = 0;
}

static const ethash::epoch_context* Context(int height, std::string& err)
{
    // v4.6.1 src/crypto/ethash/include/ethash/ethash.h: epochs are 7500 blocks.
    const int epoch = ethash::get_epoch_number(height);
    for (auto& entry : memo.entries)
        if (entry.context && entry.context->epoch_number == epoch)
        {
            entry.used = ++memo.clock;
            return entry.context.get();
        }
    // Resource policy, not a consensus constant. Bound memory before asking
    // upstream to size/allocate a cache for an untrusted embedded height.
    const uint64_t estimate = (uint64_t(1) << 24) + uint64_t(epoch) * (uint64_t(1) << 17) +
                              progpow::l1_cache_size + 64;
    if (estimate > MAX_CACHE_BYTES)
    {
        err = "Ravencoin epoch exceeds this node's per-cache resource budget";
        return nullptr;
    }
    CacheEntry* victim = &memo.entries[0];
    if (memo.entries[1].used < victim->used)
        victim = &memo.entries[1];
    // Evict before allocation, so replacing a cache never creates a third one.
    victim->context.reset();
    victim->bytes = 0;
    victim->used = 0;
    auto context = ethash::create_epoch_context(epoch);
    if (!context)
    {
        err = "Ravencoin light cache allocation failed";
        return nullptr;
    }
    victim->bytes = ethash::get_light_cache_size(context->light_cache_num_items) +
                    progpow::l1_cache_size + 64;
    victim->context = std::move(context);
    victim->used = ++memo.clock;
    return victim->context.get();
}

bool CheckProofOfWork(const Header& header, std::string& err)
{
    err.clear();
    if (header.Height() < static_cast<uint32_t>(CHECKPOINT_HEIGHT) ||
        header.Height() > static_cast<uint32_t>((std::numeric_limits<int>::max)()) ||
        header.Time() < 1588788000U)
        return Fail(err, "Ravencoin header is outside the supported KAWPOW range");
    UInt target;
    if (!lightpow::detail::Target(header.Bits(), PowLimit(), target))
        return Fail(err, "invalid Ravencoin compact target");
    // This cheap precheck does not establish PoW. It prevents allocating a
    // large epoch cache for almost all arbitrary, invalid network headers.
    if (lightpow::detail::Number(BlockHash(header)) > target)
        return Fail(err, "Ravencoin final hash exceeds the target");
    const int height = static_cast<int>(header.Height());
    std::lock_guard<std::mutex> lock(memoMutex);
    const auto* context = Context(height, err);
    if (!context)
        return false;
    ethash::hash256 boundary{};
    const auto little = lightpow::detail::Bytes(target);
    std::reverse_copy(little.begin(), little.end(), boundary.bytes);
    // v4.6.1 progpow.cpp verify: check the final hash AND recompute hash_mix
    // through light dataset items. Comparing only hash_no_verify is unsafe.
    if (!progpow::verify(*context, height, Input(header), Mix(header), header.Nonce(), boundary))
        return Fail(err, "Ravencoin KAWPOW mix does not match the light computation");
    return true;
}

bool ValidateHeader(const std::vector<lightpow::PastBlock>& parents, const Header& header,
                    lightpow::Hash& work, std::string& err)
{
    err.clear();
    work.fill(0);
    // Stricter than Ravencoin Core, on purpose: v4.6.1 never ties the embedded
    // nHeight to the real height (validation.cpp CheckBlockHeader). Here it
    // must be the parent's plus one, because it picks the KAWPOW epoch, and an
    // unchecked one let a header choose which multi-MiB cache to build.
    if (parents.empty() || parents.back().height == (std::numeric_limits<int>::max)() ||
        header.Height() != static_cast<uint32_t>(parents.back().height + 1))
        return Fail(err, "Ravencoin embedded height is not its parent's plus one");
    const uint32_t expected = NextWorkRequired(parents, err);
    if (expected == 0)
        return false;
    if (header.Bits() != expected)
        return Fail(err, "Ravencoin header difficulty does not match DGW");
    if (!CheckProofOfWork(header, err))
        return false;
    return BlockProof(header.Bits(), work, err);
}

uint32_t NextWorkRequired(const std::vector<lightpow::PastBlock>& history, std::string& err)
{
    err.clear();
    // v4.6.1 src/pow.cpp DarkGravityWave: 180 headers, not Dash's 24.
    if (history.size() < 180 || history.back().height < CHECKPOINT_HEIGHT - 1)
    {
        err = "Ravencoin DGW requires 180 checkpoint-context parents";
        return 0;
    }
    const size_t first = history.size() - 180;
    for (size_t i = first; i < history.size(); ++i)
    {
        UInt target;
        if (history[i].height < 0 || history[i].time < 1588788000U ||
            !lightpow::detail::Target(history[i].bits, PowLimit(), target))
        {
            err = "invalid Ravencoin DGW history";
            return 0;
        }
        if (i > first && (history[i - 1].height == (std::numeric_limits<int>::max)() ||
                          history[i].height != history[i - 1].height + 1))
        {
            err = "Ravencoin DGW history must be consecutive";
            return 0;
        }
    }
    UInt average = 0;
    for (size_t count = 1; count <= 180; ++count)
    {
        UInt target;
        lightpow::detail::Target(history[history.size() - count].bits, PowLimit(), target);
        if (count == 1)
            average = target;
        else
            average = (average * count + target) / (count + 1);
    }
    // The span covers 179 gaps, but upstream divides by 180 * 60 seconds.
    int64_t elapsed = int64_t(history.back().time) - history[first].time;
    elapsed = std::max<int64_t>(3600, std::min<int64_t>(32400, elapsed));
    average *= elapsed;
    average /= 10800;
    if (average > PowLimit())
        average = PowLimit();
    return lightpow::detail::Compact(average);
}

bool BlockProof(uint32_t bits, lightpow::Hash& work, std::string& err)
{
    err.clear();
    work.fill(0);
    UInt target;
    if (!lightpow::detail::Target(bits, PowLimit(), target))
        return Fail(err, "invalid Ravencoin compact target in work computation");
    // v4.6.1 src/chain.cpp GetBlockProof, no per-algorithm multiplier.
    work = lightpow::detail::Bytes(lightpow::detail::Work(target));
    return true;
}
}
