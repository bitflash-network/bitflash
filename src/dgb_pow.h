// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_DGB_POW_H
#define BITFLASH_DGB_POW_H

#include "light_pow_common.h"
#include <vector>

namespace dgbpow
{
// Core's identifiers are sparse: Odocrypt is 7, not the fifth dense index.
// DigiByte Core v8.22.2, src/primitives/block.h.
enum Algo { UNKNOWN = -1, SHA256D = 0, SCRYPT = 1, SKEIN = 3, QUBIT = 4, ODOCRYPT = 7 };
static constexpr int CHECKPOINT_HEIGHT = 24000000;
static constexpr size_t HEADER_SIZE = 80;

// What differs between DigiByte's networks here: the first height supported,
// how often Odocrypt changes shape, and the longest timespan a retarget takes
// (CMainParams and CTestNetParams, nOdoShapechangeInterval and
// nMaxActualTimespanV4, which CTestNetParams works out from nMaxAdjustUpV4).
struct Params
{
    int checkpoint = CHECKPOINT_HEIGHT;
    uint32_t odoInterval = 10U * 24 * 60 * 60;
    int64_t maxTimespan = 870;
};

struct Header
{
    std::array<unsigned char, HEADER_SIZE> raw{};
    uint32_t Version() const { return lightpow::Read32(raw.data()); }
    uint32_t Time() const { return lightpow::Read32(raw.data() + 68); }
    uint32_t Bits() const { return lightpow::Read32(raw.data() + 72); }
    uint32_t Nonce() const { return lightpow::Read32(raw.data() + 76); }
};

struct PastBlock : lightpow::PastBlock
{
    Algo algo;
};

Algo Algorithm(const Header& header);
uint32_t OdoKey(uint32_t time, const Params& params = Params());
bool ParseHeader(const unsigned char* raw, size_t size, Header& out, std::string& err);
lightpow::Hash BlockHash(const Header& header);
bool PoWHash(const Header& header, lightpow::Hash& hash, std::string& err, const Params& params = Params());
bool CheckProofOfWork(const Header& header, int height, std::string& err, const Params& params = Params());

// Oldest first, on one already-validated branch. Include at least 61 parents
// and the most recent block of every active algorithm, even if older than 61.
// Missing history fails closed; it must never select the initial difficulty.
uint32_t NextWorkRequired(const std::vector<PastBlock>& parents, Algo algo, std::string& err, const Params& params = Params());
bool BlockProof(const std::vector<PastBlock>& parents, const Header& header,
                int height, lightpow::Hash& work, std::string& err, const Params& params = Params());

// THE entry point for a header from the network: `height` is the parent's
// plus one, nBits is what MultiShield V4 gives on `parents` for the header's
// algorithm, and only then the proof of work (scrypt costs ~300 us). On
// success `work` is the header's chain work. BlockProof alone returns work
// without checking the proof; the pieces stay public for tests.
bool ValidateHeader(const std::vector<PastBlock>& parents, const Header& header,
                    int height, lightpow::Hash& work, std::string& err, const Params& params = Params());
}
#endif
