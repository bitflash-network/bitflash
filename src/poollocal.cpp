// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See poollocal.h. Pure: no node, no socket, no chain.

#include "poollocal.h"

#include <sodium.h>

#include <cstring>

namespace poollocal
{

static const char CODE_PREFIX[] = "btfl1:";
static const char SALT_TAG[] = "Bitflash/localpool/1/salt";
static const char ID_TAG[] = "Bitflash/localpool/1/id";
static const char AUTH_TAG[] = "Bitflash/localpool/1/auth";
static const char ANCHOR_TAG[] = "Bitflash/localpool/1/anchor";
static const unsigned char ANCHOR_MARK[3] = { 'p', '2', 'l' };

static bool Fail(std::string& errOut, const char* why)
{
    errOut = why;
    return false;
}

static void Sha256d(const std::vector<unsigned char>& in, unsigned char out[32])
{
    unsigned char h[32];
    crypto_hash_sha256(h, in.empty() ? NULL : &in[0], in.size());
    crypto_hash_sha256(out, h, sizeof(h));
}

static void Append(std::vector<unsigned char>& v, const char* tag)
{
    v.insert(v.end(), tag, tag + strlen(tag));
}

static void Append(std::vector<unsigned char>& v, const unsigned char* p, size_t n)
{
    v.insert(v.end(), p, p + n);
}

static void Hmac(const unsigned char key[32], const std::vector<unsigned char>& msg, unsigned char out[32])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, 32);
    crypto_auth_hmacsha256_update(&st, msg.empty() ? NULL : &msg[0], msg.size());
    crypto_auth_hmacsha256_final(&st, out);
}

// ---- The pool code ---------------------------------------------------------

std::string Code(const poolreg::PoolRecord& rec)
{
    static const char* hx = "0123456789abcdef";
    std::vector<unsigned char> v = rec.Encode();
    unsigned char sum[32];
    Sha256d(v, sum);
    v.insert(v.end(), sum, sum + 4);
    std::string s(CODE_PREFIX);
    for (size_t i = 0; i < v.size(); i++)
    {
        s += hx[v[i] >> 4];
        s += hx[v[i] & 15];
    }
    return s;
}

static int HexVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

bool ParseCode(const std::string& code, poolreg::PoolRecord& out, std::string& errOut)
{
    out = poolreg::PoolRecord();
    size_t nPrefix = sizeof(CODE_PREFIX) - 1;
    if (code.size() < nPrefix || code.compare(0, nPrefix, CODE_PREFIX) != 0)
        return Fail(errOut, "not a local pool code (it starts with btfl1:)");
    size_t nHex = code.size() - nPrefix;
    if (nHex % 2 != 0 || nHex / 2 < poolreg::MIN_RECORD_BYTES + 4 || nHex / 2 > poolreg::MAX_RECORD_BYTES + 4)
        return Fail(errOut, "a local pool code of the wrong length");
    std::vector<unsigned char> v(nHex / 2);
    for (size_t i = 0; i < v.size(); i++)
    {
        int hi = HexVal(code[nPrefix + 2 * i]), lo = HexVal(code[nPrefix + 2 * i + 1]);
        if (hi < 0 || lo < 0)
            return Fail(errOut, "a local pool code is lowercase hex after btfl1:");
        v[i] = (unsigned char)(hi * 16 + lo);
    }
    std::vector<unsigned char> rec(v.begin(), v.end() - 4);
    unsigned char sum[32];
    Sha256d(rec, sum);
    if (memcmp(sum, &v[v.size() - 4], 4) != 0)
        return Fail(errOut, "the pool code's checksum does not match (mistyped or cut short)");
    poolreg::PoolRecord r;
    if (!poolreg::Parse(rec, r, errOut))
        return false;
    if (!r.fLocal)
        return Fail(errOut, "not a local pool's record");
    out = r;
    return true;
}

// ---- Identity --------------------------------------------------------------

static bool LocalRecordOk(const std::vector<unsigned char>& record, std::string& errOut)
{
    poolreg::PoolRecord r;
    if (!poolreg::Parse(record, r, errOut))
        return false;
    if (!r.fLocal)
        return Fail(errOut, "not a local pool's record");
    return true;
}

bool DeriveFromK(const std::vector<unsigned char>& record, const unsigned char magic[4],
                 const unsigned char K[32], Keys& out, std::string& errOut)
{
    if (!LocalRecordOk(record, errOut))
        return false;
    memcpy(out.K, K, 32);

    std::vector<unsigned char> buf;
    Append(buf, ID_TAG);
    Append(buf, magic, 4);
    Append(buf, &record[0], record.size());
    Append(buf, K, 32);
    Sha256d(buf, out.id);

    std::vector<unsigned char> a;
    Append(a, AUTH_TAG);
    Append(a, out.id, 32);
    Hmac(K, a, out.A);

    std::vector<unsigned char> c;
    Append(c, ANCHOR_TAG);
    Append(c, out.id, 32);
    Hmac(K, c, out.C);

    sodium_memzero(&buf[0], buf.size());
    return true;
}

bool Derive(const std::vector<unsigned char>& record, const unsigned char magic[4],
            const std::string& password, Keys& out, std::string& errOut)
{
    if (!LocalRecordOk(record, errOut))
        return false;
    if (password.size() > MAX_PASSWORD_LEN)
        return Fail(errOut, "password too long (1024 bytes at most)");

    std::vector<unsigned char> buf;
    Append(buf, SALT_TAG);
    Append(buf, magic, 4);
    Append(buf, &record[0], record.size());
    unsigned char salt[32];
    Sha256d(buf, salt);

    // crypto_pwhash reads crypto_pwhash_SALTBYTES (16) of the salt.
    unsigned char K[32];
    if (crypto_pwhash(K, sizeof(K), password.data(), password.size(), salt,
                      KDF_PASSES, KDF_MEMORY, crypto_pwhash_ALG_ARGON2ID13) != 0)
        return Fail(errOut, "could not stretch the password (64 MiB of memory are needed)");
    bool fOk = DeriveFromK(record, magic, K, out, errOut);
    sodium_memzero(K, sizeof(K));
    return fOk;
}

// ---- The coinbase anchor ---------------------------------------------------

void AnchorTag(const unsigned char C[32], const unsigned char hashShareData[32], unsigned char out[32])
{
    std::vector<unsigned char> m(hashShareData, hashShareData + 32);
    Hmac(C, m, out);
}

std::vector<unsigned char> AnchorData(const unsigned char C[32], const unsigned char hashShareData[32])
{
    std::vector<unsigned char> v(ANCHOR_MARK, ANCHOR_MARK + 3);
    unsigned char tag[32];
    AnchorTag(C, hashShareData, tag);
    v.insert(v.end(), tag, tag + 32);
    return v;
}

bool AnchorMatches(const std::vector<unsigned char>& pushed, const unsigned char C[32],
                   const unsigned char hashShareData[32])
{
    if (pushed.size() != ANCHOR_BYTES || memcmp(&pushed[0], ANCHOR_MARK, 3) != 0)
        return false;
    unsigned char tag[32];
    AnchorTag(C, hashShareData, tag);
    return sodium_memcmp(tag, &pushed[3], 32) == 0;
}

// ---- The hello -------------------------------------------------------------

bool OnionName(const std::string& addr, std::string& oOut)
{
    std::string s = addr;
    size_t at = s.rfind('@');
    if (at != std::string::npos)
        s = s.substr(at + 1);
    static const char SUFFIX[] = ".onion";
    size_t nSuffix = sizeof(SUFFIX) - 1;
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = (char)(s[i] - 'A' + 'a');
    if (s.size() > nSuffix && s.compare(s.size() - nSuffix, nSuffix, SUFFIX) == 0)
        s.resize(s.size() - nSuffix);
    if (s.size() != 56)
        return false;
    for (size_t i = 0; i < s.size(); i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '2' && s[i] <= '7')))
            return false;
    oOut = s;
    return true;
}

static void Tag(const unsigned char A[32], const char* what, const std::string& O,
                const unsigned char* nA, const unsigned char* nB, unsigned char out[32])
{
    std::vector<unsigned char> m;
    Append(m, what);
    m.insert(m.end(), O.begin(), O.end());
    Append(m, nA, NONCE_BYTES);
    if (nB)
        Append(m, nB, NONCE_BYTES);
    Hmac(A, m, out);
}

void HelloTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32], unsigned char out[TAG_BYTES])
{
    unsigned char full[32];
    Tag(A, "hello", O, nA, NULL, full);
    memcpy(out, full, TAG_BYTES);
}

void ReplyTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
              const unsigned char nB[32], unsigned char out[TAG_BYTES])
{
    unsigned char full[32];
    Tag(A, "reply", O, nA, nB, full);
    memcpy(out, full, TAG_BYTES);
}

void AckTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
            const unsigned char nB[32], unsigned char out[ACK_BYTES])
{
    Tag(A, "ack", O, nA, nB, out);
}

void SessionHandle(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
                   const unsigned char nB[32], unsigned char out[HANDLE_BYTES])
{
    unsigned char full[32];
    Tag(A, "session", O, nA, nB, full);
    memcpy(out, full, HANDLE_BYTES);
}

uint64_t HandleValue(const unsigned char h[HANDLE_BYTES])
{
    uint64_t n = 0;
    for (size_t i = 0; i < HANDLE_BYTES; i++)
        n |= (uint64_t)h[i] << (8 * i);
    return n;
}

bool HelloLimiter::Allow(int64_t nNow)
{
    if (nTotal >= HELLO_LIFETIME)
        return false;
    if (nTotal > 0 && nNow < nLast + HELLO_INTERVAL)
        return false;
    nLast = nNow;
    nTotal++;
    return true;
}

Sessions::Sessions(const Keys& keysIn)
{
    memcpy(A, keysIn.A, sizeof(A));
}

Sessions::~Sessions()
{
    sodium_memzero(A, sizeof(A));
}

bool Sessions::Seen(const unsigned char nA[32]) const
{
    for (size_t i = 0; i < vSeen.size(); i++)
        if (memcmp(&vSeen[i][0], nA, NONCE_BYTES) == 0)
            return true;
    return false;
}

bool Sessions::StartHello(uint64_t conn, const std::string& O, const unsigned char nA[32], Hello& out)
{
    std::string o;
    if (!OnionName(O, o))
        return false;
    if (mapSession.count(conn) || mapOut.count(conn))
        return false;
    if (mapSession.size() >= MAX_SESSIONS || mapOut.size() >= MAX_LISTED_PEERS)
        return false;
    Half half;
    half.O = o;
    memcpy(half.nA, nA, NONCE_BYTES);
    memset(half.nB, 0, NONCE_BYTES);
    half.nTime = 0;
    mapOut[conn] = half;
    memcpy(out.nonce, nA, NONCE_BYTES);
    HelloTag(A, o, nA, out.tag);
    return true;
}

bool Sessions::OnReply(uint64_t conn, const Hello& reply, unsigned char ackOut[ACK_BYTES],
                       unsigned char hOut[HANDLE_BYTES])
{
    std::map<uint64_t, Half>::iterator it = mapOut.find(conn);
    if (it == mapOut.end())
        return false;
    const Half& half = it->second;
    unsigned char want[TAG_BYTES];
    ReplyTag(A, half.O, half.nA, reply.nonce, want);
    if (sodium_memcmp(want, reply.tag, TAG_BYTES) != 0)
        return false;
    if (mapSession.size() >= MAX_SESSIONS)
    {
        mapOut.erase(it);
        return false;
    }
    AckTag(A, half.O, half.nA, reply.nonce, ackOut);
    Handle handle;
    SessionHandle(A, half.O, half.nA, reply.nonce, handle.h);
    memcpy(hOut, handle.h, HANDLE_BYTES);
    mapSession[conn] = handle;
    mapOut.erase(it);
    return true;
}

bool Sessions::OnHello(uint64_t conn, const std::vector<std::string>& vOwnOnions, const Hello& hello,
                       const unsigned char nB[32], int64_t nNow, Hello& replyOut)
{
    Expire(nNow);
    for (size_t i = 0; i < vOwnOnions.size(); i++)
    {
        std::string o;
        if (!OnionName(vOwnOnions[i], o))
            continue;
        unsigned char want[TAG_BYTES];
        HelloTag(A, o, hello.nonce, want);
        if (sodium_memcmp(want, hello.tag, TAG_BYTES) != 0)
            continue;
        // A member's hello for this node. Everything below answers with the
        // same silence a non-member gets.
        if (Seen(hello.nonce))
            return false;
        if (mapPending.count(conn))
            return false;
        // A fresh hello of a member on a connection that already holds a
        // session: the other side no longer has it (its operator took this
        // node off the pool's list and put it back). Its ack replaces the
        // session, in the same place: refusing it left that side unable to
        // open a session on the connection for as long as it lasted.
        if (mapSession.size() - mapSession.count(conn) + mapPending.size() >= MAX_SESSIONS)
            return false;
        vSeen.push_back(std::vector<unsigned char>(hello.nonce, hello.nonce + NONCE_BYTES));
        while (vSeen.size() > SEEN_NONCES)
            vSeen.pop_front();
        Half half;
        half.O = o;
        memcpy(half.nA, hello.nonce, NONCE_BYTES);
        memcpy(half.nB, nB, NONCE_BYTES);
        half.nTime = nNow;
        mapPending[conn] = half;
        memcpy(replyOut.nonce, nB, NONCE_BYTES);
        ReplyTag(A, o, hello.nonce, nB, replyOut.tag);
        return true;
    }
    return false;
}

bool Sessions::OnAck(uint64_t conn, const unsigned char ack[ACK_BYTES], int64_t nNow,
                     unsigned char hOut[HANDLE_BYTES])
{
    Expire(nNow);
    std::map<uint64_t, Half>::iterator it = mapPending.find(conn);
    if (it == mapPending.end())
        return false;
    const Half& half = it->second;
    unsigned char want[ACK_BYTES];
    AckTag(A, half.O, half.nA, half.nB, want);
    if (sodium_memcmp(want, ack, ACK_BYTES) != 0)
        return false;
    // A session already on this connection is replaced (OnHello).
    if (mapSession.size() - mapSession.count(conn) >= MAX_SESSIONS)
    {
        mapPending.erase(it);
        return false;
    }
    Handle handle;
    SessionHandle(A, half.O, half.nA, half.nB, handle.h);
    memcpy(hOut, handle.h, HANDLE_BYTES);
    mapSession[conn] = handle;
    mapPending.erase(it);
    mapOut.erase(conn);
    return true;
}

bool Sessions::HasSession(uint64_t conn, const unsigned char h[HANDLE_BYTES]) const
{
    std::map<uint64_t, Handle>::const_iterator it = mapSession.find(conn);
    return it != mapSession.end() && sodium_memcmp(it->second.h, h, HANDLE_BYTES) == 0;
}

bool Sessions::SessionOf(uint64_t conn, unsigned char hOut[HANDLE_BYTES]) const
{
    std::map<uint64_t, Handle>::const_iterator it = mapSession.find(conn);
    if (it == mapSession.end())
        return false;
    memcpy(hOut, it->second.h, HANDLE_BYTES);
    return true;
}

void Sessions::Close(uint64_t conn)
{
    mapOut.erase(conn);
    mapPending.erase(conn);
    mapSession.erase(conn);
}

void Sessions::Expire(int64_t nNow)
{
    for (std::map<uint64_t, Half>::iterator it = mapPending.begin(); it != mapPending.end();)
    {
        if (nNow >= it->second.nTime + REPLY_TIMEOUT)
            mapPending.erase(it++);
        else
            ++it;
    }
}

} // namespace poollocal
