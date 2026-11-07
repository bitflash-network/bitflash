// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_X16RV2_H
#define BITFLASH_X16RV2_H

namespace x16rv2
{
// The block ID of an 80-byte Ravencoin header (v4.8.0, src/hash.h HashX16RV2):
// sixteen hashes in the order the previous block's hash picks. KAWPOW replaced
// it on the real networks in 2020. Only regtest still uses it, where KAWPOW never
// activates, so the light client can be tested there with coins.
void Hash(const unsigned char* header, unsigned char* out32);
}
#endif
