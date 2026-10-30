// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "dgb_pow.h"
#include "rvn_kawpow.h"
#include <algorithm>
#include <cstdlib>
#include <vector>

// Bounded synthetic histories exercise retarget arithmetic without needing a
// chain database. Real proof seeds are supplied by the offline vector corpus.
extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size)
{
    if (size < 2) return 0;
    std::string err;
    lightpow::Hash hash{};
    const unsigned char flags = data[size - 1];
    if ((data[0] & 1) == 0)
    {
        dgbpow::Header header;
        if (!dgbpow::ParseHeader(data + 1, std::min(size - 1, dgbpow::HEADER_SIZE), header, err)) return 0;
        dgbpow::BlockHash(header);
        dgbpow::PoWHash(header, hash, err);
        dgbpow::CheckProofOfWork(header, dgbpow::CHECKPOINT_HEIGHT, err);
        const dgbpow::Algo algos[] = {dgbpow::SHA256D, dgbpow::SCRYPT, dgbpow::SKEIN, dgbpow::QUBIT, dgbpow::ODOCRYPT};
        std::vector<dgbpow::PastBlock> parents;
        for (int i = 0; i < 61; ++i)
        {
            dgbpow::PastBlock parent;
            parent.height = dgbpow::CHECKPOINT_HEIGHT - 61 + i;
            parent.time = header.Time() - static_cast<uint32_t>((60 - i) * (flags & 1 ? 1 : 1000));
            parent.bits = header.Bits();
            parent.algo = algos[i % 5];
            parents.push_back(parent);
        }
        if (flags & 2) parents[flags % parents.size()].height = -1;
        if (flags & 4) parents[flags % parents.size()].algo = dgbpow::UNKNOWN;
        const uint32_t expected = dgbpow::NextWorkRequired(parents, dgbpow::Algorithm(header), err);
        if (expected)
        {
            for (int i = 0; i < 4; ++i) header.raw[72 + i] = static_cast<unsigned char>(expected >> (8 * i));
            dgbpow::BlockProof(parents, header, dgbpow::CHECKPOINT_HEIGHT, hash, err);
        }
    }
    else
    {
        rvnpow::Header header;
        if (!rvnpow::ParseHeader(data + 1, std::min(size - 1, rvnpow::HEADER_SIZE), header, err)) return 0;
        rvnpow::BlockHash(header);
        rvnpow::CheckProofOfWork(header, err);
        rvnpow::BlockProof(header.Bits(), hash, err);
        std::vector<lightpow::PastBlock> parents;
        for (int i = 0; i < 180; ++i)
            parents.push_back({rvnpow::CHECKPOINT_HEIGHT - 180 + i,
                header.Time() - static_cast<uint32_t>((179 - i) * (flags & 1 ? 1 : 1000)), header.Bits()});
        if (flags & 2) parents[flags % parents.size()].height = -1;
        if (flags & 4) parents[flags % parents.size()].bits ^= 0x800000U;
        rvnpow::NextWorkRequired(parents, err);
        if (rvnpow::CachedEpochs() > 2 || rvnpow::CachedBytes() > 256U * 1024 * 1024) std::abort();
    }
    return 0;
}
