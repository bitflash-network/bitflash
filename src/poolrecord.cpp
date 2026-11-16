// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See poolrecord.h. Pure: no node, no socket, no chain.

#include "poolrecord.h"

#include <sodium.h>

#include <cstring>

namespace poolreg
{

static const unsigned char MAGIC[4] = { 'B', 'T', 'F', 'P' };
static const unsigned char MAGIC_LOCAL[4] = { 'B', 'T', 'F', 'L' };
static const char ID_TAG[] = "Bitflash/pool/1";

static bool Fail(std::string& errOut, const char* why)
{
    errOut = why;
    return false;
}

PoolRecord::PoolRecord()
    : fLocal(false), nFormat(RECORD_FORMAT), nRules(SHARE_RULES_V1), nSpacing(0), nWindow(0), nRetarget(0),
      nFloor(0), nUncleDepth(0), nUnclePct(0), nFeeBps(0), nFeeType(FEE_NONE)
{
    memset(feeHash, 0, sizeof(feeHash));
}

static void Put16(std::vector<unsigned char>& v, unsigned int n)
{
    v.push_back((unsigned char)(n & 0xff));
    v.push_back((unsigned char)((n >> 8) & 0xff));
}

static void Put32(std::vector<unsigned char>& v, unsigned int n)
{
    for (int i = 0; i < 4; i++)
        v.push_back((unsigned char)((n >> (8 * i)) & 0xff));
}

static unsigned int Get16(const unsigned char* p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int Get32(const unsigned char* p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

std::vector<unsigned char> PoolRecord::Encode() const
{
    const unsigned char* pMagic = fLocal ? MAGIC_LOCAL : MAGIC;
    std::vector<unsigned char> v(pMagic, pMagic + 4);
    v.push_back(nFormat);
    v.push_back(nRules);
    Put16(v, nSpacing);
    Put16(v, nWindow);
    Put16(v, nRetarget);
    Put32(v, nFloor);
    v.push_back((unsigned char)nUncleDepth);
    v.push_back((unsigned char)nUnclePct);
    Put16(v, nFeeBps);
    v.push_back(nFeeType);
    v.insert(v.end(), feeHash, feeHash + 20);
    v.insert(v.end(), name.begin(), name.end());
    return v;
}

bool NameOk(const std::string& name)
{
    if (name.empty() || name.size() > MAX_NAME_LEN)
        return false;
    for (size_t i = 0; i < name.size(); i++)
    {
        unsigned char c = (unsigned char)name[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

// CBigNum::SetCompact reads the size byte, then that many of the three
// mantissa bytes as a big-endian MPI magnitude whose top bit is the sign, and
// zeros past the third. GetCompact writes the minimal MPI back: a leading
// zero byte only when the next byte's top bit is set, unused bytes zero. So a
// positive compact is canonical when the bytes SetCompact ignores are zero
// and the magnitude starts either with a byte from 0x01 to 0x7f, or with a
// zero followed by a byte of 0x80 or more.
bool CompactCanonical(unsigned int c)
{
    unsigned int nSize = c >> 24;
    unsigned char d[3] = { (unsigned char)((c >> 16) & 0xff), (unsigned char)((c >> 8) & 0xff),
                           (unsigned char)(c & 0xff) };
    if (nSize == 0)
        return false;                       // zero
    for (unsigned int i = nSize; i < 3; i++)
        if (d[i] != 0)
            return false;                   // bytes SetCompact never reads
    if (d[0] >= 0x80)
        return false;                       // negative
    if (d[0] != 0)
        return true;
    return nSize >= 2 && d[1] >= 0x80;      // the one leading zero MPI allows
}

// Positive canonical compacts order by (size, mantissa): each size covers its
// own range of values, above every smaller size's.
static bool NoEasierThanNetwork(unsigned int c)
{
    unsigned int nSize = c >> 24, nMant = c & 0xffffff;
    unsigned int nNetSize = NETWORK_FLOOR >> 24, nNetMant = NETWORK_FLOOR & 0xffffff;
    return nSize < nNetSize || (nSize == nNetSize && nMant <= nNetMant);
}

static bool AllZero(const unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return false;
    return true;
}

bool PoolRecord::Check(std::string& errOut) const
{
    if (nFormat != RECORD_FORMAT)
        return Fail(errOut, "unknown record format");
    if (nRules != SHARE_RULES_V1)
        return Fail(errOut, "unknown share rules version");
    // Pool zero's exact record is the only one allowed its 10 s; a copy of it
    // with any other byte changed is an ordinary record and needs 20 s.
    bool fPoolZero = nSpacing == POOL_ZERO_SPACING && Encode() == PoolZero().Encode();
    if (!fPoolZero && (nSpacing < MIN_SPACING || nSpacing > MAX_SPACING))
        return Fail(errOut, "share spacing out of range (20 to 120 s)");
    if (nWindow < MIN_WINDOW || nWindow > MAX_WINDOW)
        return Fail(errOut, "PPLNS window out of range (360 to 2160 shares)");
    if (nRetarget < MIN_RETARGET || nRetarget > MAX_RETARGET || nRetarget > nWindow)
        return Fail(errOut, "retarget window out of range (120 to 720 shares, no more than the window)");
    if (!CompactCanonical(nFloor))
        return Fail(errOut, "share floor is not a canonical positive compact target");
    if (!NoEasierThanNetwork(nFloor))
        return Fail(errOut, "share floor easier than the network floor");
    if (nUncleDepth < MIN_UNCLE_DEPTH || nUncleDepth > MAX_UNCLE_DEPTH)
        return Fail(errOut, "uncle depth out of range (1 to 3)");
    if (!fPoolZero && nSpacing * nUncleDepth < MIN_UNCLE_SECONDS)
        return Fail(errOut, "spacing x uncle depth under 60 s (depth 3 below 30 s, 2 below 60 s)");
    if (nUnclePct < MIN_UNCLE_PCT || nUnclePct > MAX_UNCLE_PCT)
        return Fail(errOut, "uncle share out of range (80 to 100)");
    if (nFeeBps > MAX_FEE_BPS)
        return Fail(errOut, "creator fee above 3%");
    if (nFeeType > FEE_P2SH)
        return Fail(errOut, "unknown fee script type");
    bool fZeroHash = AllZero(feeHash, sizeof(feeHash));
    if (nFeeBps == 0 && (nFeeType != FEE_NONE || !fZeroHash))
        return Fail(errOut, "a fee destination with no fee");
    if (nFeeBps != 0 && nFeeType == FEE_NONE)
        return Fail(errOut, "a fee with no destination");
    if (!NameOk(name))
        return Fail(errOut, "bad name (1 to 32 of A-Z a-z 0-9 - _)");
    return true;
}

bool Parse(const std::vector<unsigned char>& data, PoolRecord& out, std::string& errOut)
{
    out = PoolRecord();
    if (data.size() < MIN_RECORD_BYTES || data.size() > MAX_RECORD_BYTES)
        return Fail(errOut, "not 42 to 73 bytes");
    const unsigned char* d = &data[0];
    bool fLocal = memcmp(d, MAGIC_LOCAL, 4) == 0;
    if (!fLocal && memcmp(d, MAGIC, 4) != 0)
        return Fail(errOut, "not a pool record");
    PoolRecord r;
    r.fLocal = fLocal;
    r.nFormat = d[4];
    r.nRules = d[5];
    r.nSpacing = Get16(d + 6);
    r.nWindow = Get16(d + 8);
    r.nRetarget = Get16(d + 10);
    r.nFloor = Get32(d + 12);
    r.nUncleDepth = d[16];
    r.nUnclePct = d[17];
    r.nFeeBps = Get16(d + 18);
    r.nFeeType = d[20];
    memcpy(r.feeHash, d + 21, 20);
    r.name.assign((const char*)d + FIXED_BYTES, data.size() - FIXED_BYTES);
    if (!r.Check(errOut))
        return false;
    // Every field is fixed width or bounded by the push, so a record that
    // passed Check writes back to the same bytes; say so rather than assume.
    if (r.Encode() != data)
        return Fail(errOut, "not in canonical form");
    out = r;
    return true;
}

bool ParseScript(const std::vector<unsigned char>& s, PoolRecord& out, std::string& errOut)
{
    // OP_RETURN (0x6a), one direct push (opcode = length, 42 to 73), nothing more.
    if (s.size() < 2 || s[0] != 0x6a)
        return Fail(errOut, "not an OP_RETURN");
    size_t n = s[1];
    if (n < MIN_RECORD_BYTES || n > MAX_RECORD_BYTES || s.size() != 2 + n)
        return Fail(errOut, "not one direct push of a record");
    if (!Parse(std::vector<unsigned char>(s.begin() + 2, s.end()), out, errOut))
        return false;
    if (out.fLocal)
    {
        out = PoolRecord();
        return Fail(errOut, "a local pool record, never read from the chain");
    }
    return true;
}

std::vector<unsigned char> PoolRecord::FeeScript() const
{
    std::vector<unsigned char> s;
    if (nFeeType == FEE_P2PKH)
    {
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        s.push_back(0x76);
        s.push_back(0xa9);
        s.push_back(20);
        s.insert(s.end(), feeHash, feeHash + 20);
        s.push_back(0x88);
        s.push_back(0xac);
    }
    else if (nFeeType == FEE_P2SH)
    {
        // OP_HASH160 <20> OP_EQUAL
        s.push_back(0xa9);
        s.push_back(20);
        s.insert(s.end(), feeHash, feeHash + 20);
        s.push_back(0x87);
    }
    return s;
}

void PoolId(const std::vector<unsigned char>& record, const unsigned char magic[4], unsigned char idOut[32])
{
    std::vector<unsigned char> buf(ID_TAG, ID_TAG + sizeof(ID_TAG) - 1);
    buf.insert(buf.end(), magic, magic + 4);
    buf.insert(buf.end(), record.begin(), record.end());
    unsigned char h[32];
    crypto_hash_sha256(h, &buf[0], buf.size());
    crypto_hash_sha256(idOut, h, sizeof(h));
}

std::string IdHex(const unsigned char id[32])
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (int i = 31; i >= 0; i--)
    {
        s += hx[id[i] >> 4];
        s += hx[id[i] & 15];
    }
    return s;
}

PoolRecord PoolZero()
{
    PoolRecord r;
    r.nSpacing = 10;
    r.nWindow = 2160;
    r.nRetarget = 720;
    r.nFloor = NETWORK_FLOOR;
    r.nUncleDepth = 3;
    r.nUnclePct = 80;
    r.nFeeBps = 0;
    r.nFeeType = FEE_NONE;
    r.name = "bitflash";
    return r;
}

} // namespace poolreg
