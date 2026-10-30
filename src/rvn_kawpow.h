// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_RVN_KAWPOW_H
#define BITFLASH_RVN_KAWPOW_H

#include "light_pow_common.h"
#include <vector>

namespace rvnpow
{
static constexpr int CHECKPOINT_HEIGHT = 4507490;
static constexpr size_t HEADER_SIZE = 120;

struct Header
{
    std::array<unsigned char, HEADER_SIZE> raw{};
    uint32_t Version() const { return lightpow::Read32(raw.data()); }
    uint32_t Time() const { return lightpow::Read32(raw.data() + 68); }
    uint32_t Bits() const { return lightpow::Read32(raw.data() + 72); }
    uint32_t Height() const { return lightpow::Read32(raw.data() + 76); }
    uint64_t Nonce() const { return lightpow::Read64(raw.data() + 80); }
};

bool ParseHeader(const unsigned char* raw, size_t size, Header& out, std::string& err);
// Cheap ID from the supplied mix. NOT a proof check: only trust this ID after
// CheckProofOfWork has recomputed and compared the mix using the light cache.
lightpow::Hash BlockHash(const Header& header);
bool CheckProofOfWork(const Header& header, std::string& err);
uint32_t NextWorkRequired(const std::vector<lightpow::PastBlock>& parents, std::string& err);
bool BlockProof(uint32_t bits, lightpow::Hash& work, std::string& err);

// THE entry point for a header from the network. In this order, cheapest
// first: the embedded height is the parent's plus one, nBits is what DGW
// gives on `parents` (oldest first, one validated branch), and only then the
// KAWPOW proof, whose epoch cache costs seconds and up to MAX_CACHE_BYTES. On
// success `work` is the header's chain work. The pieces above stay public
// for tests; a header taken with CheckProofOfWork alone could name any nBits
// and any epoch, and make this node build caches for headers costing ~1 s.
bool ValidateHeader(const std::vector<lightpow::PastBlock>& parents, const Header& header,
                    lightpow::Hash& work, std::string& err);

// Each cached epoch is held to this. A light cache grows by 128 KiB an epoch
// (7500 blocks, about five days); this budget lasts to epoch 1919, height
// about 14.4 million, around 2045. A header past it is refused as this node's
// resource limit, not as invalid; raise it, after review, well before then.
static constexpr uint64_t MAX_CACHE_BYTES = uint64_t(256) * 1024 * 1024;

// The sole mutable process-wide state is this two-entry epoch memo. It is
// locked: verification and these helpers may be called from any thread.
size_t CachedEpochs();
size_t CachedBytes();
void ClearCache();
}
#endif
