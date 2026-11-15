// Standalone tests for the pool registry record (poolrecord.h,
// docs/pool-registry.md sections 1, 2 and 4): the canonical encoding, every
// rule that refuses a record, the pool id, and pool zero's fixed vectors.

#include "poolrecord.h"

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static std::string Hex(const std::vector<unsigned char>& v)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < v.size(); i++) { s += hx[v[i] >> 4]; s += hx[v[i] & 15]; }
    return s;
}

static std::string RawHex(const unsigned char* p, size_t n)
{
    return Hex(std::vector<unsigned char>(p, p + n));
}

static std::vector<unsigned char> Script(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> s;
    s.push_back(0x6a);
    s.push_back((unsigned char)data.size());
    s.insert(s.end(), data.begin(), data.end());
    return s;
}

// Pool zero's rules at 30 s: valid, and not pool zero's own record, so every
// rule applies to it in full.
static poolreg::PoolRecord Base()
{
    poolreg::PoolRecord r = poolreg::PoolZero();
    r.nSpacing = 30;
    return r;
}

static bool Refused(const poolreg::PoolRecord& r)
{
    std::string err;
    poolreg::PoolRecord back;
    return !r.Check(err) && !poolreg::Parse(r.Encode(), back, err);
}

// What CBigNum::SetCompact then GetCompact give back, without OpenSSL: the
// size byte, that many mantissa bytes as a big-endian MPI magnitude whose top
// bit is the sign, zeros past the third; written back as the minimal MPI.
static unsigned int RoundTrip(unsigned int c, bool& fNegative, bool& fZero)
{
    unsigned int nSize = c >> 24;
    unsigned char d[3] = { (unsigned char)(c >> 16), (unsigned char)(c >> 8), (unsigned char)c };
    std::vector<unsigned char> mag;
    for (unsigned int i = 0; i < nSize; i++)
        mag.push_back(i < 3 ? d[i] : 0);
    fNegative = !mag.empty() && (mag[0] & 0x80);
    if (!mag.empty())
        mag[0] &= 0x7f;
    size_t k = 0;
    while (k < mag.size() && mag[k] == 0)
        k++;
    mag.erase(mag.begin(), mag.begin() + k);
    fZero = mag.empty();
    if (fZero)
        return 0;
    if (mag[0] & 0x80)
        mag.insert(mag.begin(), 0);
    if (fNegative)
        mag[0] |= 0x80;
    unsigned int out = (unsigned int)mag.size() << 24;
    if (mag.size() >= 1) out |= mag[0] << 16;
    if (mag.size() >= 2) out |= mag[1] << 8;
    if (mag.size() >= 3) out |= mag[2];
    return out;
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }
    std::string err;

    printf("pool_zero_vectors\n");
    {
        poolreg::PoolRecord z = poolreg::PoolZero();
        std::vector<unsigned char> rec = z.Encode();
        CHECK(z.Check(err), "pool zero is a valid record");
        CHECK(rec.size() == 49, "pool zero's record is 49 bytes");
        CHECK(Hex(rec) == "4254465001010a007008d002ffff0f1f03500000000000000000000000000000000000000000000000626974666c617368",
              "pool zero's record bytes (docs/pool-registry.md section 4)");
        const unsigned char mainMagic[4] = { 0xbf, 0x20, 0x5c, 0xfd };
        const unsigned char testMagic[4] = { 0xce, 0xe2, 0xc0, 0xff };
        unsigned char id[32];
        poolreg::PoolId(rec, mainMagic, id);
        CHECK(RawHex(id, 32) == "8a7c198b08da304183bc37545f2c29cb0f04463e08dc34d09280d9206ff325d9", "mainnet id, internal order");
        CHECK(poolreg::IdHex(id) == "d925f36f20d98092d034dc083e46040fcb292c5f5437bc834130da088b197c8a", "mainnet id, shown");
        poolreg::PoolId(rec, testMagic, id);
        CHECK(RawHex(id, 32) == "3627dbfd95b0b07ca8806aa5bbde9aa77c2998f0455b5a5428f865b09c437da9", "testnet id, internal order");
        CHECK(poolreg::IdHex(id) == "a97d439cb065f828545a5b45f098297ca79adebba56a80a87cb0b095fddb2736", "testnet id, shown");
        poolreg::PoolRecord back;
        CHECK(poolreg::ParseScript(Script(rec), back, err) && back.Encode() == rec, "pool zero reads back from its OP_RETURN");
    }

    printf("a_record_round_trips\n");
    {
        poolreg::PoolRecord r = poolreg::PoolZero();
        r.nSpacing = 30; r.nWindow = 1440; r.nRetarget = 360; r.nFloor = 0x1e7fffff;
        r.nUncleDepth = 2; r.nUnclePct = 90; r.nFeeBps = 100; r.nFeeType = poolreg::FEE_P2SH;
        memset(r.feeHash, 0xab, 20); r.name = "A_pool-2";
        poolreg::PoolRecord back;
        CHECK(r.Check(err), "a fee pool is a valid record");
        CHECK(poolreg::Parse(r.Encode(), back, err) && back.Encode() == r.Encode(), "and reads back to the same bytes");
        std::vector<unsigned char> fs = back.FeeScript();
        CHECK(fs.size() == 23 && fs[0] == 0xa9 && fs[1] == 20 && fs[22] == 0x87, "its fee script is the P2SH it names");
        r.nFeeType = poolreg::FEE_P2PKH;
        fs = r.FeeScript();
        CHECK(fs.size() == 25 && fs[0] == 0x76 && fs[24] == 0xac, "a P2PKH fee script");
        r.name = std::string(32, 'x');
        CHECK(r.Check(err) && r.Encode().size() == 73, "the longest name makes a 73-byte record");
        r.name = "x";
        CHECK(r.Check(err) && r.Encode().size() == 42, "the shortest makes a 42-byte record");
    }

    printf("one_byte_is_another_pool\n");
    {
        const unsigned char magic[4] = { 0xbf, 0x20, 0x5c, 0xfd };
        poolreg::PoolRecord a = poolreg::PoolZero(), b = poolreg::PoolZero();
        b.nWindow = 1080;
        unsigned char ia[32], ib[32], ia2[32];
        poolreg::PoolId(a.Encode(), magic, ia);
        poolreg::PoolId(b.Encode(), magic, ib);
        poolreg::PoolId(poolreg::PoolZero().Encode(), magic, ia2);
        CHECK(memcmp(ia, ib, 32) != 0, "an \"edit\" has another id");
        CHECK(memcmp(ia, ia2, 32) == 0, "the same rules have the same id");
    }

    printf("every_rule_refuses\n");
    {
        poolreg::PoolRecord r;
        r = Base(); r.nFormat = 2;            CHECK(Refused(r), "a later record format");
        r = Base(); r.nRules = 2;             CHECK(Refused(r), "a later rules version");
        r = Base(); r.nSpacing = 19;          CHECK(Refused(r), "spacing under 20 s");
        r = Base(); r.nSpacing = 121;         CHECK(Refused(r), "spacing over 120 s");
        r = Base(); r.nWindow = 359;          CHECK(Refused(r), "window under 360");
        r = Base(); r.nWindow = 2161;         CHECK(Refused(r), "window over 2160");
        r = Base(); r.nRetarget = 119;        CHECK(Refused(r), "retarget under 120");
        r = Base(); r.nRetarget = 721;        CHECK(Refused(r), "retarget over 720");
        r = Base(); r.nWindow = 400; r.nRetarget = 401; CHECK(Refused(r), "retarget over the window");
        r = Base(); r.nFloor = 0x1f100000;    CHECK(Refused(r), "a floor easier than the network's");
        r = Base(); r.nFloor = 0x2000ffff;    CHECK(Refused(r), "a floor much easier than the network's");
        r = Base(); r.nFloor = 0x1e007fff;    CHECK(Refused(r), "a floor spelled with a needless leading zero");
        r = Base(); r.nFloor = 0x1e00ffff;    CHECK(r.Check(err), "the leading zero MPI needs is canonical");
        r = Base(); r.nFloor = 0x1e800000;    CHECK(Refused(r), "a negative floor");
        r = Base(); r.nFloor = 0x01003456;    CHECK(Refused(r), "a floor with bytes SetCompact never reads");
        r = Base(); r.nFloor = 0;             CHECK(Refused(r), "a zero floor");
        r = Base(); r.nUncleDepth = 4;        CHECK(Refused(r), "uncle depth over 3");
        r = Base(); r.nUnclePct = 79;         CHECK(Refused(r), "uncle share under 80");
        r = Base(); r.nUnclePct = 101;        CHECK(Refused(r), "uncle share over 100");
        r = Base(); r.nUnclePct = 100;        CHECK(r.Check(err), "uncle share of 100");
        r = Base(); r.nUncleDepth = 0;        CHECK(Refused(r), "no uncles");
        r = Base(); r.nUncleDepth = 0; r.nUnclePct = 0; CHECK(Refused(r), "no uncles and no uncle share");
        r = Base(); r.nSpacing = 120; r.nUncleDepth = 0; r.nUnclePct = 0; CHECK(Refused(r), "no uncles even at 120 s");
        r = Base(); r.nSpacing = 20; r.nUncleDepth = 3; CHECK(r.Check(err), "20 s with depth 3");
        r = Base(); r.nSpacing = 20; r.nUncleDepth = 2; CHECK(Refused(r), "20 s with depth 2");
        r = Base(); r.nSpacing = 29; r.nUncleDepth = 2; CHECK(Refused(r), "29 s with depth 2");
        r = Base(); r.nSpacing = 30; r.nUncleDepth = 2; CHECK(r.Check(err), "30 s with depth 2");
        r = Base(); r.nSpacing = 39; r.nUncleDepth = 1; CHECK(Refused(r), "39 s with depth 1");
        r = Base(); r.nSpacing = 59; r.nUncleDepth = 1; CHECK(Refused(r), "59 s with depth 1");
        r = Base(); r.nSpacing = 60; r.nUncleDepth = 1; CHECK(r.Check(err), "60 s with depth 1");
        r = Base(); r.nSpacing = 120; r.nUncleDepth = 1; CHECK(r.Check(err), "120 s with depth 1");
        r = poolreg::PoolZero();              CHECK(r.Check(err), "pool zero's own record, at 10 s");
        r = poolreg::PoolZero(); r.name = "bitflash2"; CHECK(Refused(r), "a copy of pool zero at 10 s with another name");
        r = poolreg::PoolZero(); r.nWindow = 2159; CHECK(Refused(r), "a copy of pool zero at 10 s with another window");
        r = poolreg::PoolZero(); r.nSpacing = 20; r.name = "copy"; CHECK(r.Check(err), "pool zero's rules at 20 s are a valid record");
        r = Base(); r.nFeeBps = 301; r.nFeeType = poolreg::FEE_P2PKH; r.feeHash[0] = 1;
        CHECK(Refused(r), "a fee over 3%");
        r = Base(); r.nFeeBps = 300; r.nFeeType = poolreg::FEE_P2PKH; r.feeHash[0] = 1;
        CHECK(r.Check(err), "a fee of exactly 3%");
        r = Base(); r.nFeeBps = 50;           CHECK(Refused(r), "a fee with no destination");
        r = Base(); r.nFeeType = poolreg::FEE_P2PKH; CHECK(Refused(r), "a destination type with no fee");
        r = Base(); r.feeHash[7] = 1;         CHECK(Refused(r), "a destination hash with no fee");
        r = Base(); r.nFeeBps = 50; r.nFeeType = 3; r.feeHash[0] = 1; CHECK(Refused(r), "an unknown fee type");
        r = Base(); r.name = "";              CHECK(Refused(r), "no name");
        r = Base(); r.name = "has space";     CHECK(Refused(r), "a space in the name");
        r = Base(); r.name = "caf\xc3\xa9";   CHECK(Refused(r), "a non-ASCII name");
        r = Base(); r.name = "dot.name";      CHECK(Refused(r), "a dot in the name");
    }

    printf("the_script_shape\n");
    {
        std::vector<unsigned char> rec = poolreg::PoolZero().Encode();
        poolreg::PoolRecord back;
        std::vector<unsigned char> s = Script(rec);
        s.push_back(0x51);
        CHECK(!poolreg::ParseScript(s, back, err), "anything after the push");
        s = Script(rec);
        s.insert(s.begin() + 1, 0x4c);   // OP_PUSHDATA1 <len> <data>
        CHECK(!poolreg::ParseScript(s, back, err), "an OP_PUSHDATA1 push");
        s = Script(rec);
        s[0] = 0x00;
        CHECK(!poolreg::ParseScript(s, back, err), "not an OP_RETURN");
        s = Script(rec);
        s[1] = (unsigned char)(rec.size() - 1);
        CHECK(!poolreg::ParseScript(s, back, err), "a push length that does not match");
        std::vector<unsigned char> bad = rec;
        bad[0] = 'X';
        CHECK(!poolreg::ParseScript(Script(bad), back, err), "another magic (a community listing, say)");
        CHECK(!poolreg::Parse(std::vector<unsigned char>(rec.begin(), rec.begin() + 41), back, err), "a record with no name");
    }

    printf("compact_canonical_matches_bignum\n");
    {
        // Every size, a spread of mantissas, against the MPI round trip.
        static const unsigned int mant[] = { 0x000000, 0x000001, 0x00007f, 0x000080, 0x0000ff, 0x000100,
            0x007fff, 0x008000, 0x00ffff, 0x010000, 0x0fffff, 0x123456, 0x7fffff, 0x800000, 0x80ffff,
            0xffffff, 0x00ff00, 0x7f0000, 0x000081 };
        int nBad = 0, nCanon = 0;
        for (unsigned int nSize = 0; nSize <= 40; nSize++)
        {
            for (size_t i = 0; i < sizeof(mant) / sizeof(mant[0]); i++)
            {
                unsigned int c = (nSize << 24) | mant[i];
                bool fNeg, fZero;
                bool fRef = RoundTrip(c, fNeg, fZero) == c && !fNeg && !fZero;
                if (fRef != poolreg::CompactCanonical(c)) nBad++;
                if (fRef) nCanon++;
            }
            for (int k = 0; k < 2000; k++)
            {
                unsigned int c = (nSize << 24) | ((unsigned int)rand() & 0xffffff);
                bool fNeg, fZero;
                bool fRef = RoundTrip(c, fNeg, fZero) == c && !fNeg && !fZero;
                if (fRef != poolreg::CompactCanonical(c)) nBad++;
            }
        }
        CHECK(nBad == 0 && nCanon > 100, "CompactCanonical agrees with SetCompact/GetCompact everywhere tried");
        CHECK(poolreg::CompactCanonical(poolreg::NETWORK_FLOOR), "the network floor is canonical");
    }

    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "all passed", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
