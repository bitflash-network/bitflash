// Standalone tests for P2Pool local (poollocal.h, docs/pool-registry.md
// section 18): the "BTFL" record, the pool code and its checksum, fixed
// vectors for K, the id, A and C, the keyed coinbase anchor, and the hello:
// a match, silence for everyone else, replay and relay failing, and its
// limits.

#include "poollocal.h"

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static std::string Hex(const unsigned char* p, size_t n)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += hx[p[i] >> 4]; s += hx[p[i] & 15]; }
    return s;
}

static std::string Hex(const std::vector<unsigned char>& v)
{
    return v.empty() ? std::string() : Hex(&v[0], v.size());
}

static const unsigned char mainMagic[4] = { 0xbf, 0x20, 0x5c, 0xfd };
static const unsigned char testMagic[4] = { 0xce, 0xe2, 0xc0, 0xff };

// The record the fixed vectors use: section 9's defaults for depth 3.
static poolreg::PoolRecord Home()
{
    poolreg::PoolRecord r = poolreg::PoolZero();
    r.fLocal = true;
    r.nSpacing = 30;
    r.name = "home";
    return r;
}

static void Fill(unsigned char* p, size_t n, unsigned char c)
{
    memset(p, c, n);
}

static const std::string ONION_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const std::string ONION_C = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

// One full handshake from a (dialling O) to b; true if both hold a session
// with the same handle.
static bool Shake(poollocal::Sessions& a, uint64_t connA, poollocal::Sessions& b, uint64_t connB,
                  const std::string& O, const std::vector<std::string>& bOnions, unsigned char seed, int64_t now)
{
    unsigned char nA[32], nB[32], ack[32], hA[8], hB[8];
    Fill(nA, 32, seed); Fill(nB, 32, (unsigned char)(seed + 1));
    poollocal::Hello hello, reply;
    if (!a.StartHello(connA, O, nA, hello)) return false;
    if (!b.OnHello(connB, bOnions, hello, nB, now, reply)) return false;
    if (!a.OnReply(connA, reply, ack, hA)) return false;
    if (!b.OnAck(connB, ack, now, hB)) return false;
    return memcmp(hA, hB, 8) == 0 && a.HasSession(connA, hA) && b.HasSession(connB, hB);
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }
    std::string err;

    printf("local_record\n");
    {
        poolreg::PoolRecord r = Home(), back;
        std::vector<unsigned char> rec = r.Encode();
        CHECK(r.Check(err), "a local record is a valid record");
        CHECK(Hex(rec) == "4254464c01011e007008d002ffff0f1f03500000000000000000000000000000000000000000000000686f6d65",
              "its bytes start with BTFL");
        CHECK(poolreg::Parse(rec, back, err) && back.fLocal && back.Encode() == rec, "and reads back, marked local");
        poolreg::PoolRecord reg = r; reg.fLocal = false;
        CHECK(poolreg::Parse(reg.Encode(), back, err) && !back.fLocal, "the same fields under BTFP read back as a registry record");
        std::vector<unsigned char> script;
        script.push_back(0x6a); script.push_back((unsigned char)rec.size());
        script.insert(script.end(), rec.begin(), rec.end());
        CHECK(!poolreg::ParseScript(script, back, err), "a BTFL record in an OP_RETURN is not read");
        std::vector<unsigned char> regRec = reg.Encode();
        script.assign(1, 0x6a); script.push_back((unsigned char)regRec.size());
        script.insert(script.end(), regRec.begin(), regRec.end());
        CHECK(poolreg::ParseScript(script, back, err), "while the BTFP one is");
        std::vector<unsigned char> other = rec; other[3] = 'M';
        CHECK(!poolreg::Parse(other, back, err), "any other magic is no record");

        // Every rule of section 1 holds under BTFL exactly as under BTFP.
        poolreg::PoolRecord z = poolreg::PoolZero(); z.fLocal = true;
        CHECK(!z.Check(err), "pool zero's 10 s is not allowed to a local copy of it");
        int nDiff = 0, nRefused = 0, nTried = 0;
        struct Mut { unsigned int spacing, window, retarget, floor, depth, pct, fee; unsigned char type; const char* name; };
        static const Mut muts[] = {
            { 19, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "x" }, { 20, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "x" },
            { 20, 2160, 720, 0x1f0fffff, 2, 80, 0, 0, "x" }, { 29, 2160, 720, 0x1f0fffff, 2, 80, 0, 0, "x" },
            { 30, 2160, 720, 0x1f0fffff, 2, 80, 0, 0, "x" }, { 59, 2160, 720, 0x1f0fffff, 1, 80, 0, 0, "x" },
            { 60, 2160, 720, 0x1f0fffff, 1, 80, 0, 0, "x" }, { 121, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "x" },
            { 30, 359, 120, 0x1f0fffff, 3, 80, 0, 0, "x" }, { 30, 2161, 720, 0x1f0fffff, 3, 80, 0, 0, "x" },
            { 30, 360, 361, 0x1f0fffff, 3, 80, 0, 0, "x" }, { 30, 2160, 119, 0x1f0fffff, 3, 80, 0, 0, "x" },
            { 30, 2160, 721, 0x1f0fffff, 3, 80, 0, 0, "x" }, { 30, 2160, 720, 0x1f100000, 3, 80, 0, 0, "x" },
            { 30, 2160, 720, 0x1f8fffff, 3, 80, 0, 0, "x" }, { 30, 2160, 720, 0x1e7fffff, 3, 80, 0, 0, "x" },
            { 30, 2160, 720, 0x1f0fffff, 0, 80, 0, 0, "x" }, { 30, 2160, 720, 0x1f0fffff, 4, 80, 0, 0, "x" },
            { 30, 2160, 720, 0x1f0fffff, 3, 79, 0, 0, "x" }, { 30, 2160, 720, 0x1f0fffff, 3, 101, 0, 0, "x" },
            { 30, 2160, 720, 0x1f0fffff, 3, 100, 0, 0, "x" }, { 30, 2160, 720, 0x1f0fffff, 3, 80, 301, 1, "x" },
            { 30, 2160, 720, 0x1f0fffff, 3, 80, 300, 1, "x" }, { 30, 2160, 720, 0x1f0fffff, 3, 80, 100, 0, "x" },
            { 30, 2160, 720, 0x1f0fffff, 3, 80, 0, 1, "x" }, { 30, 2160, 720, 0x1f0fffff, 3, 80, 100, 3, "x" },
            { 30, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "" }, { 30, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "a b" },
            { 30, 2160, 720, 0x1f0fffff, 3, 80, 0, 0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        };
        for (size_t i = 0; i < sizeof(muts) / sizeof(muts[0]); i++)
        {
            poolreg::PoolRecord m;
            m.nSpacing = muts[i].spacing; m.nWindow = muts[i].window; m.nRetarget = muts[i].retarget;
            m.nFloor = muts[i].floor; m.nUncleDepth = muts[i].depth; m.nUnclePct = muts[i].pct;
            m.nFeeBps = muts[i].fee; m.nFeeType = muts[i].type; m.name = muts[i].name;
            if (muts[i].fee) memset(m.feeHash, 0x11, 20);
            poolreg::PoolRecord b1, b2;
            m.fLocal = false;
            bool fReg = m.Check(err) && poolreg::Parse(m.Encode(), b1, err);
            m.fLocal = true;
            bool fLoc = m.Check(err) && poolreg::Parse(m.Encode(), b2, err);
            nTried++;
            if (fReg != fLoc) nDiff++;
            if (!fLoc) nRefused++;
        }
        CHECK(nDiff == 0 && nRefused == 23 && nTried == 29, "every section 1 rule refuses and accepts the same under BTFL");
    }

    printf("pool_code\n");
    {
        poolreg::PoolRecord r = Home(), back;
        std::string code = poollocal::Code(r);
        CHECK(code == "btfl1:4254464c01011e007008d002ffff0f1f03500000000000000000000000000000000000000000000000686f6d65" + code.substr(code.size() - 8),
              "the code is btfl1: and the record in hex");
        CHECK(code.substr(code.size() - 8) == "aed186a7", "and the first 4 bytes of its SHA256d");
        CHECK(poollocal::ParseCode(code, back, err) && back.Encode() == r.Encode(), "the code reads back to the record");
        std::string bad = code; bad[20] = bad[20] == '0' ? '1' : '0';
        CHECK(!poollocal::ParseCode(bad, back, err), "one character changed fails the checksum");
        CHECK(!poollocal::ParseCode(code.substr(0, code.size() - 2), back, err), "a code cut short is refused");
        CHECK(!poollocal::ParseCode(code + "00", back, err), "and one with bytes added");
        std::string upper = code; for (size_t i = 6; i < upper.size(); i++) if (upper[i] >= 'a') upper[i] = (char)(upper[i] - 32);
        CHECK(!poollocal::ParseCode(upper, back, err), "uppercase hex is not the code");
        CHECK(!poollocal::ParseCode("btfp1:" + code.substr(6), back, err), "another prefix is refused");
        CHECK(!poollocal::ParseCode("", back, err) && !poollocal::ParseCode("btfl1:", back, err), "an empty code is refused");
        poolreg::PoolRecord reg = r; reg.fLocal = false;
        CHECK(!poollocal::ParseCode(poollocal::Code(reg), back, err), "a registry record inside a code is refused");
        poolreg::PoolRecord inv = r; inv.nSpacing = 19;
        CHECK(!poollocal::ParseCode(poollocal::Code(inv), back, err), "a record breaking section 1 inside a good checksum is refused");
    }

    printf("derivation_vectors\n");
    {
        std::vector<unsigned char> rec = Home().Encode();
        poollocal::Keys k0, k1, k2, kt;
        CHECK(poollocal::Derive(rec, mainMagic, "", k0, err), "derives with no password");
        CHECK(Hex(k0.K, 32) == "d5df9f563daf019e1c009b676fd66c2cfe99927cc5bf093d6c20a4bc7797ec0e", "K, no password, mainnet");
        CHECK(Hex(k0.id, 32) == "2489c62570504bd372b1364625eac1209d1733d93339cbc7bcfa78b5e1ad94d3", "id, no password");
        CHECK(Hex(k0.A, 32) == "1a199f152896c95e7c7b8c50baff6d127495b1187d517cbe2b0c1a9e288c817f", "A, no password");
        CHECK(Hex(k0.C, 32) == "aa10aadd53ccea6d8d5f4d341f71f8d092717c11c640ca5057c8e6a2765fa4e9", "C, no password");
        CHECK(poollocal::Derive(rec, mainMagic, "correct horse battery staple", k1, err), "derives with a password");
        CHECK(Hex(k1.K, 32) == "0f285cdff9fd35f5596baa2dbd731da19397cad00529e135dc359d7b43714e2a", "K, with a password");
        CHECK(Hex(k1.id, 32) == "e8645b92963405f86c8a6ce6299874ac1c167797ff975c78b63d401b877ae70f", "id, with a password");
        CHECK(Hex(k1.A, 32) == "9ea81151bae11a5637711e7ee9a5279fb3cf08d6d9b763de5c34cca8792d4cc6", "A, with a password");
        CHECK(Hex(k1.C, 32) == "19e4fa9d29f89eadb0a30e54370aba84aa49b5a46b68af64347c24c88857ce2d", "C, with a password");
        CHECK(poollocal::Derive(rec, testMagic, "", kt, err), "derives on testnet");
        CHECK(Hex(kt.K, 32) == "0cb0d8ef23ed379b4a933edd1da0bc006ce552e1a718fc11767f1944e7094ae2", "K, no password, testnet");
        CHECK(Hex(kt.id, 32) == "5c843d0eb3c946d9a021b504277a34b62e907635ba581a9e663c4fff6617d0a6", "id, no password, testnet");
        CHECK(memcmp(k0.id, k1.id, 32) != 0 && memcmp(k0.id, kt.id, 32) != 0, "the password and the network each change the id");
        poolreg::PoolRecord named = Home(); named.name = "office";
        CHECK(poollocal::Derive(named.Encode(), mainMagic, "", k2, err) && memcmp(k0.id, k2.id, 32) != 0,
              "the same parameters under another name are another pool");
        poollocal::Keys kk;
        CHECK(poollocal::DeriveFromK(rec, mainMagic, k1.K, kk, err) && memcmp(&kk, &k1, sizeof(kk)) == 0,
              "the stored K gives the same id and keys without the password");
        poolreg::PoolRecord reg = Home(); reg.fLocal = false;
        CHECK(!poollocal::Derive(reg.Encode(), mainMagic, "", kk, err), "a registry record derives nothing");
        CHECK(!poollocal::Derive(rec, mainMagic, std::string(1025, 'x'), kk, err), "a password over 1024 bytes is refused");
    }

    printf("anchor\n");
    {
        std::vector<unsigned char> rec = Home().Encode();
        poollocal::Keys k0, k1;
        poollocal::Derive(rec, mainMagic, "", k0, err);
        poollocal::Derive(rec, mainMagic, "correct horse battery staple", k1, err);
        unsigned char hash[32], other[32];
        for (int i = 0; i < 32; i++) { hash[i] = (unsigned char)i; other[i] = (unsigned char)(i + 1); }
        std::vector<unsigned char> a = poollocal::AnchorData(k1.C, hash);
        CHECK(a.size() == 35 && a[0] == 'p' && a[1] == '2' && a[2] == 'l', "the anchor is p2l and 32 bytes");
        CHECK(Hex(a) == "70326cc9edfdb41b0157183b2979b1bd07eae47b1ed7bd6471fb8533293ef6a4521905", "its fixed vector");
        CHECK(poollocal::AnchorMatches(a, k1.C, hash), "a member checks it with C");
        CHECK(!poollocal::AnchorMatches(a, k1.C, other), "other share data does not match");
        CHECK(!poollocal::AnchorMatches(a, k0.C, hash), "nor the key of the pool without the password");
        std::vector<unsigned char> unkeyed(a.begin(), a.begin() + 3);
        unkeyed.insert(unkeyed.end(), hash, hash + 32);
        CHECK(!poollocal::AnchorMatches(unkeyed, k1.C, hash), "an unkeyed hash after p2l is refused");
        std::vector<unsigned char> p2x = a; p2x[2] = 'x';
        CHECK(!poollocal::AnchorMatches(p2x, k1.C, hash), "the tag under another mark is refused");
        std::vector<unsigned char> shorter(a.begin(), a.end() - 1);
        CHECK(!poollocal::AnchorMatches(shorter, k1.C, hash), "34 bytes are no anchor");
        CHECK(Hex(a).find(Hex(k1.id, 32)) == std::string::npos, "the pool id is not in it");
    }

    printf("sessions_wipe\n");
    {
        // A Sessions keeps A alone of the keys, and wipes it when it goes.
        std::vector<unsigned char> rec = Home().Encode();
        poollocal::Keys k;
        poollocal::Derive(rec, mainMagic, "correct horse battery staple", k, err);
        alignas(poollocal::Sessions) unsigned char buf[sizeof(poollocal::Sessions)];
        poollocal::Sessions* p = new (buf) poollocal::Sessions(k);
        bool fHeldA = std::search(buf, buf + sizeof(buf), k.A, k.A + 32) != buf + sizeof(buf);
        bool fNoK = std::search(buf, buf + sizeof(buf), k.K, k.K + 32) == buf + sizeof(buf) &&
                    std::search(buf, buf + sizeof(buf), k.C, k.C + 32) == buf + sizeof(buf) &&
                    std::search(buf, buf + sizeof(buf), k.id, k.id + 32) == buf + sizeof(buf);
        p->~Sessions();
        bool fGone = std::search(buf, buf + sizeof(buf), k.A, k.A + 32) == buf + sizeof(buf);
        CHECK(fHeldA && fNoK, "a pool's sessions hold A, and not K, C or the id");
        CHECK(fGone, "and A is wiped when they go");
        sodium_memzero(&k, sizeof(k));
    }

    printf("handle_value\n");
    {
        unsigned char h[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88 };
        CHECK(poollocal::HandleValue(h) == 0x8807060504030201ULL, "the handle is its 8 bytes read little-endian");
    }

    printf("onion_name\n");
    {
        std::string o;
        CHECK(poollocal::OnionName("BJZ48@" + ONION_B + ".onion", o) && o == ONION_B, "ADDR@HOST.onion gives the 56 characters");
        CHECK(poollocal::OnionName(ONION_B + ".onion", o) && o == ONION_B, "so does HOST.onion");
        CHECK(poollocal::OnionName(ONION_B, o) && o == ONION_B, "and the bare name");
        std::string up = ONION_B; up[0] = 'B';
        CHECK(poollocal::OnionName(up + ".ONION", o) && o == ONION_B, "uppercase is folded");
        CHECK(!poollocal::OnionName(ONION_B.substr(1) + ".onion", o), "55 characters are refused");
        std::string badc = ONION_B; badc[5] = '1';
        CHECK(!poollocal::OnionName(badc, o), "a character outside base32 is refused");
        CHECK(!poollocal::OnionName("example.com", o), "a clearnet name is refused");
    }

    printf("hello\n");
    {
        std::vector<unsigned char> rec = Home().Encode();
        poollocal::Keys kPw, kWrong, kOther;
        poollocal::Derive(rec, mainMagic, "correct horse battery staple", kPw, err);
        poollocal::Derive(rec, mainMagic, "correct horse battery stapler", kWrong, err);
        poolreg::PoolRecord office = Home(); office.name = "office";
        poollocal::Derive(office.Encode(), mainMagic, "correct horse battery staple", kOther, err);
        std::vector<std::string> onB(1, ONION_B + ".onion"), onC(1, ONION_C + ".onion");
        unsigned char nA[32], nB[32], ack[32], hA[8], hB[8];
        Fill(nA, 32, 1); Fill(nB, 32, 2);
        poollocal::Hello hello, reply;

        {
            poollocal::Sessions a(kPw), b(kPw);
            CHECK(a.StartHello(7, "X@" + ONION_B + ".onion", nA, hello), "a member starts a hello for the onion it dialled");
            unsigned char tag[16];
            poollocal::HelloTag(kPw.A, ONION_B, nA, tag);
            CHECK(Hex(tag, 16) == "cf5d6f3aea177d1b6400788bb6a83679" && memcmp(tag, hello.tag, 16) == 0, "tA, fixed vector");
            CHECK(b.OnHello(9, onB, hello, nB, 1000, reply), "the member it dialled answers");
            CHECK(Hex(reply.tag, 16) == "c737d3f370262c70005b7717a40af28a", "tB, fixed vector");
            CHECK(a.OnReply(7, reply, ack, hA), "the initiator accepts the reply");
            CHECK(Hex(ack, 32) == "4f7e796f327c5a4068fcc1660de548990b6324b2fc054977dd83c26c7231bd0f", "the ack, fixed vector");
            CHECK(Hex(hA, 8) == "62d8e1e5cf5fb82d", "the session handle, fixed vector");
            CHECK(b.Count() == 0, "the responder holds no session before the ack");
            CHECK(b.OnAck(9, ack, 1001, hB) && memcmp(hA, hB, 8) == 0, "the ack opens the same session on both sides");
            CHECK(a.HasSession(7, hA) && b.HasSession(9, hB) && a.Count() == 1 && b.Count() == 1, "one session each");
            CHECK(Hex(hA, 8) != Hex(kPw.id, 8) && Hex(kPw.id, 32).find(Hex(hA, 8)) == std::string::npos, "the handle is not the pool id");
            unsigned char hBad[8]; memcpy(hBad, hA, 8); hBad[0] ^= 1;
            CHECK(!b.HasSession(9, hBad) && !b.HasSession(10, hB), "an unknown handle, or the handle on another connection, names nothing");
            b.Close(9);
            CHECK(b.Count() == 0 && !b.HasSession(9, hB), "closing the connection ends the session");
        }
        {
            poollocal::Sessions a(kPw), w(kWrong), o(kOther);
            a.StartHello(7, ONION_B, nA, hello);
            CHECK(!w.OnHello(9, onB, hello, nB, 1000, reply) && w.Pending() == 0, "a node with the wrong password answers nothing");
            CHECK(!o.OnHello(9, onB, hello, nB, 1000, reply), "nor a member of another pool");
            // The wrong-password node sends its own hello: a member is silent.
            poollocal::Sessions m(kPw);
            poollocal::Hello hw;
            w.StartHello(3, ONION_B, nA, hw);
            CHECK(!m.OnHello(4, onB, hw, nB, 1000, reply) && m.Pending() == 0 && m.Count() == 0, "a member is silent to a hello made with the wrong password");
        }
        {
            // Replay: C, listed by mistake, got a's hello (made for C's onion)
            // and sends it to member b.
            poollocal::Sessions a(kPw), b(kPw);
            a.StartHello(7, ONION_C, nA, hello);
            CHECK(!b.OnHello(9, onB, hello, nB, 1000, reply), "a hello replayed to another node matches nothing there");
            // Relay: C sits between a (who dialled C) and b, passing messages.
            // b never answers, so there is nothing to pass back.
            CHECK(b.Pending() == 0 && b.Count() == 0, "so a handshake relayed between two members never starts");
            // Even a reply made by a member for another onion fails at a.
            poollocal::Sessions a2(kPw), b2(kPw);
            poollocal::Hello h2, r2;
            a2.StartHello(1, ONION_B, nA, h2);
            b2.OnHello(2, onB, h2, nB, 1000, r2);
            CHECK(!a.OnReply(7, r2, ack, hA) && a.Count() == 0, "a reply bound to another onion is refused by the initiator");
        }
        {
            poollocal::Sessions a(kPw), b(kPw);
            a.StartHello(7, ONION_B, nA, hello);
            CHECK(b.OnHello(9, onB, hello, nB, 1000, reply), "a first hello is answered");
            CHECK(!b.OnHello(10, onB, hello, nB, 1001, reply), "the same nA again is dropped");
            b.Close(9);
            CHECK(!b.OnHello(11, onB, hello, nB, 5000, reply), "and still dropped later");
        }
        {
            poollocal::Sessions a(kPw), b(kPw);
            a.StartHello(7, ONION_B, nA, hello);
            b.OnHello(9, onB, hello, nB, 1000, reply);
            a.OnReply(7, reply, ack, hA);
            CHECK(b.Pending() == 1, "a reply waits for its ack");
            unsigned char badAck[32]; memcpy(badAck, ack, 32); badAck[31] ^= 1;
            CHECK(!b.OnAck(9, badAck, 1001, hB) && b.Count() == 0, "a wrong ack opens nothing");
            CHECK(!b.OnAck(8, ack, 1001, hB), "the right ack on another connection opens nothing");
            CHECK(!b.OnAck(9, ack, 1030, hB) && b.Pending() == 0 && b.Count() == 0, "an ack 30 s late finds the reply forgotten");
        }
        {
            // The session cap: 16, both directions; the 17th gets silence.
            poollocal::Sessions b(kPw);
            std::vector<poollocal::Sessions> peers(17, poollocal::Sessions(kPw));
            int nOk = 0;
            for (int i = 0; i < 16; i++)
                if (Shake(peers[i], 1, b, 100 + i, ONION_B, onB, (unsigned char)(10 + 2 * i), 2000))
                    nOk++;
            CHECK(nOk == 16 && b.Count() == 16, "sixteen sessions open");
            unsigned char n17[32]; Fill(n17, 32, 200);
            peers[16].StartHello(1, ONION_B, n17, hello);
            CHECK(!b.OnHello(116, onB, hello, nB, 2000, reply) && b.Count() == 16, "the seventeenth hello gets silence");
            unsigned char n18[32]; Fill(n18, 32, 201);
            CHECK(!b.StartHello(300, ONION_C, n18, hello), "and the node at its cap sends no hello of its own");
            b.Close(100);
            unsigned char n19[32]; Fill(n19, 32, 202);
            poollocal::Sessions late(kPw);
            late.StartHello(1, ONION_B, n19, hello);
            CHECK(b.OnHello(117, onB, hello, nB, 2001, reply), "a session closed makes room for one more");
        }
        {
            poollocal::HelloLimiter lim;
            CHECK(lim.Allow(1000), "a connection's first hello is read");
            CHECK(!lim.Allow(1059), "a second within the minute is dropped");
            CHECK(lim.Allow(1060), "one a minute later is read");
            int n = 2;
            for (int64_t t = 1120; n < 8; t += 60) if (lim.Allow(t)) n++;
            CHECK(n == 8 && !lim.Allow(100000), "the ninth in a connection's life is dropped, however late");
        }
    }

    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "all passed", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
