// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#include "x16rv2.h"
#include "pow_vendor/dgb/sph_cubehash.h"
#include "pow_vendor/dgb/sph_echo.h"
#include "pow_vendor/dgb/sph_luffa.h"
#include "pow_vendor/dgb/sph_shavite.h"
#include "pow_vendor/dgb/sph_simd.h"
#include "pow_vendor/dgb/sph_skein.h"
#include "pow_vendor/x16/sph_blake.h"
#include "pow_vendor/x16/sph_bmw.h"
#include "pow_vendor/x16/sph_fugue.h"
#include "pow_vendor/x16/sph_groestl.h"
#include "pow_vendor/x16/sph_hamsi.h"
#include "pow_vendor/x16/sph_jh.h"
#include "pow_vendor/x16/sph_keccak.h"
#include "pow_vendor/x16/sph_sha2.h"
#include "pow_vendor/x16/sph_shabal.h"
#include "pow_vendor/x16/sph_tiger.h"
#include "pow_vendor/x16/sph_whirlpool.h"
#include <cstring>

namespace x16rv2
{
// uint256::GetNibble, for the last sixteen nibbles of the hash as it is shown.
static int Selection(const unsigned char* prev, int round)
{
    const int index = 63 - (48 + round);
    return index % 2 == 1 ? prev[index / 2] >> 4 : prev[index / 2] & 0x0F;
}

template <void (*Init)(void*), void (*Update)(void*, const void*, size_t), void (*Close)(void*, void*), class Context>
static void One(Context& cc, const void* in, size_t size, void* out)
{
    Init(&cc);
    Update(&cc, in, size);
    Close(&cc, out);
}

// Version 2 runs Tiger first where X16R ran Keccak, Luffa or SHA-512.
static void Tiger(const void* in, size_t size, void* out)
{
    sph_tiger_context cc;
    One<sph_tiger_init, sph_tiger, sph_tiger_close>(cc, in, size, out);
}

void Hash(const unsigned char* header, unsigned char* out32)
{
    unsigned char hash[16][64];
    std::memset(hash, 0, sizeof(hash));
    const unsigned char* prev = header + 4;
    for (int i = 0; i < 16; ++i)
    {
        const void* in = i == 0 ? static_cast<const void*>(header) : hash[i - 1];
        const size_t size = i == 0 ? 80 : 64;
        void* out = hash[i];
        switch (Selection(prev, i))
        {
            case 0: { sph_blake512_context c; One<sph_blake512_init, sph_blake512, sph_blake512_close>(c, in, size, out); break; }
            case 1: { sph_bmw512_context c; One<sph_bmw512_init, sph_bmw512, sph_bmw512_close>(c, in, size, out); break; }
            case 2: { sph_groestl512_context c; One<sph_groestl512_init, sph_groestl512, sph_groestl512_close>(c, in, size, out); break; }
            case 3: { sph_jh512_context c; One<sph_jh512_init, sph_jh512, sph_jh512_close>(c, in, size, out); break; }
            case 4:
            {
                Tiger(in, size, out);
                sph_keccak512_context c;
                One<sph_keccak512_init, sph_keccak512, sph_keccak512_close>(c, out, 64, out);
                break;
            }
            case 5: { sph_skein512_context c; One<sph_skein512_init, sph_skein512, sph_skein512_close>(c, in, size, out); break; }
            case 6:
            {
                Tiger(in, size, out);
                sph_luffa512_context c;
                One<sph_luffa512_init, sph_luffa512, sph_luffa512_close>(c, out, 64, out);
                break;
            }
            case 7: { sph_cubehash512_context c; One<sph_cubehash512_init, sph_cubehash512, sph_cubehash512_close>(c, in, size, out); break; }
            case 8: { sph_shavite512_context c; One<sph_shavite512_init, sph_shavite512, sph_shavite512_close>(c, in, size, out); break; }
            case 9: { sph_simd512_context c; One<sph_simd512_init, sph_simd512, sph_simd512_close>(c, in, size, out); break; }
            case 10: { sph_echo512_context c; One<sph_echo512_init, sph_echo512, sph_echo512_close>(c, in, size, out); break; }
            case 11: { sph_hamsi512_context c; One<sph_hamsi512_init, sph_hamsi512, sph_hamsi512_close>(c, in, size, out); break; }
            case 12: { sph_fugue512_context c; One<sph_fugue512_init, sph_fugue512, sph_fugue512_close>(c, in, size, out); break; }
            case 13: { sph_shabal512_context c; One<sph_shabal512_init, sph_shabal512, sph_shabal512_close>(c, in, size, out); break; }
            case 14: { sph_whirlpool_context c; One<sph_whirlpool_init, sph_whirlpool, sph_whirlpool_close>(c, in, size, out); break; }
            case 15:
            {
                Tiger(in, size, out);
                sph_sha512_context c;
                One<sph_sha512_init, sph_sha512, sph_sha512_close>(c, out, 64, out);
                break;
            }
        }
    }
    std::memcpy(out32, hash[15], 32);
}
}
