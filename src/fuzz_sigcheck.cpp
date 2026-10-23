// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// libFuzzer harness: OpenSSL and libsecp256k1 must give the same answer for
// every (hash, signature, key). Random bytes almost never make a valid
// signature, so the input mutates real ones: a few signed triples are made
// once, and the fuzzer's bytes pick one, a form of the key and of S, and what
// to change. Any disagreement aborts -- it would be a consensus split.

#include "headers_core.h"
#include "sigcheck.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

struct Triple
{
    uint256 hash;
    vector<unsigned char> sig, pub;
};

static vector<Triple> MakeTriples()
{
    vector<Triple> v;
    for (int i = 0; i < 8; i++)
    {
        CKey key;
        key.MakeNewKey();
        Triple t;
        RAND_bytes((unsigned char*)&t.hash, sizeof(t.hash));
        if (!key.Sign(t.hash, t.sig))
            abort();
        t.pub = key.GetPubKey();
        v.push_back(t);
    }
    return v;
}

// S' = n - S, the twin OpenSSL also accepts.
static vector<unsigned char> HighS(const vector<unsigned char>& der)
{
    static const unsigned char n[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
    if (der.size() < 8 || der[2] != 0x02)
        return der;
    size_t rl = der[3];
    if (6 + rl > der.size())
        return der;
    vector<unsigned char> r(der.begin() + 4, der.begin() + 4 + rl);
    vector<unsigned char> s(der.begin() + 6 + rl, der.end());
    while (s.size() > 1 && s[0] == 0) s.erase(s.begin());
    if (s.size() > 32)
        return der;
    unsigned char s32[32] = {0}, out[32];
    memcpy(s32 + 32 - s.size(), &s[0], s.size());
    int borrow = 0;
    for (int i = 31; i >= 0; i--)
    {
        int d = (int)n[i] - (int)s32[i] - borrow;
        borrow = d < 0;
        out[i] = (unsigned char)(d + (borrow ? 256 : 0));
    }
    vector<unsigned char> s2(out, out + 32);
    while (s2.size() > 1 && s2[0] == 0) s2.erase(s2.begin());
    if (s2[0] & 0x80) s2.insert(s2.begin(), 0);
    vector<unsigned char> o;
    o.push_back(0x30);
    o.push_back((unsigned char)(4 + r.size() + s2.size()));
    o.push_back(0x02); o.push_back((unsigned char)r.size()); o.insert(o.end(), r.begin(), r.end());
    o.push_back(0x02); o.push_back((unsigned char)s2.size()); o.insert(o.end(), s2.begin(), s2.end());
    return o;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const vector<Triple> triples = MakeTriples();
    if (size < 2 || size > 512)
        return 0;

    const Triple& t = triples[data[0] % triples.size()];
    uint256 hash = t.hash;
    vector<unsigned char> sig = (data[0] & 0x08) ? HighS(t.sig) : t.sig;
    vector<unsigned char> pub = t.pub;
    if (data[0] & 0x10)          // compressed
    {
        pub.resize(33);
        pub[0] = (t.pub[64] & 1) ? 0x03 : 0x02;
    }
    else if (data[0] & 0x20)     // hybrid
        pub[0] = (t.pub[64] & 1) ? 0x07 : 0x06;

    const uint8_t* p = data + 2;
    size_t n = size - 2;
    switch (data[1] % 6)
    {
    case 0:  // flip bytes of the signature: (position, xor) pairs
        for (size_t i = 0; i + 1 < n; i += 2)
            if (!sig.empty()) sig[p[i] % sig.size()] ^= p[i + 1];
        break;
    case 1:  // flip bytes of the key
        for (size_t i = 0; i + 1 < n; i += 2)
            if (!pub.empty()) pub[p[i] % pub.size()] ^= p[i + 1];
        break;
    case 2:  // flip bytes of the hash
        for (size_t i = 0; i + 1 < n; i += 2)
            ((unsigned char*)&hash)[p[i] % 32] ^= p[i + 1];
        break;
    case 3:  // the signature is the input
        sig.assign(p, p + n);
        break;
    case 4:  // the key is the input
        pub.assign(p, p + n);
        break;
    default: // cut or grow the signature
        if (n > 0 && (p[0] & 1) && !sig.empty())
            sig.resize(p[0] % sig.size());
        else
            sig.insert(sig.end(), p, p + n);
        break;
    }

    bool fOpenSsl = CKey::Verify(pub, hash, sig);
    bool fSecp = SigCheckEcdsa((const unsigned char*)&hash, sig, pub);
    if (fOpenSsl != fSecp)
    {
        fprintf(stderr, "DISAGREE: OpenSSL %d, libsecp256k1 %d\n", fOpenSsl, fSecp);
        abort();
    }
    return 0;
}
