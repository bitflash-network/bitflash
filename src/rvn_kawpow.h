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

// The sole mutable process-wide state is this two-entry epoch memo. Callers
// must serialize proof verification and these cache helpers on one worker.
// There are no internal locks. Each cache is limited to 128 MiB, including L1.
size_t CachedEpochs();
size_t CachedBytes();
void ClearCache();
}
#endif
