// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "btclight.h"
#include "proxy.h"
#include "swap.h"
#include <fstream>
#include <thread>
#include <mutex>
#include <set>
#include <stdexcept>
#include <chrono>
#include <sodium.h>
#ifdef _WIN32
#include <io.h>
#endif
#ifdef __APPLE__
#include <crt_externs.h>
#endif

using json = nlohmann::json;
namespace btclight
{
static uint64_t LE(const Bytes& b, size_t p, size_t n)
{
    if (p > b.size() || n > b.size() - p || n > 8) throw std::runtime_error("short Bitcoin message");
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= uint64_t(b[p+i]) << (8*i);
    return v;
}
static void Put(Bytes& b, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; ++i) b.push_back((unsigned char)(v >> (8*i)));
}
static void Compact(Bytes& b, uint64_t v)
{
    if (v < 253) b.push_back((unsigned char)v);
    else { b.push_back(v <= 65535 ? 253 : v <= 0xffffffff ? 254 : 255); Put(b, v, v <= 65535 ? 2 : v <= 0xffffffff ? 4 : 8); }
}
static uint64_t Count(const Bytes& b, size_t& p, uint64_t maximum)
{
    unsigned int c = (unsigned int)LE(b, p++, 1);
    unsigned int n = c == 253 ? 2 : c == 254 ? 4 : c == 255 ? 8 : 0;
    uint64_t v = n ? LE(b, p, n) : c;
    p += n;
    if ((n && (v < 253 || (n > 2 && v <= 65535) || (n > 4 && v <= 0xffffffff))) || v > maximum)
        throw std::runtime_error("noncanonical or oversized Bitcoin count");
    return v;
}
static uint256 Digest(const Bytes& b)
{
    unsigned char first[32];
    uint256 out;
    SHA256(b.empty() ? (const unsigned char*)"" : &b[0], b.size(), first);
    SHA256(first, 32, out.begin());
    return out;
}
static uint256 ReadHash(const Bytes& b, size_t p)
{
    if (p > b.size() || b.size()-p < 32) throw std::runtime_error("short Bitcoin hash");
    return uint256(Bytes(b.begin()+p, b.begin()+p+32));
}
static void HashBytes(Bytes& b, uint256 h) { b.insert(b.end(), h.begin(), h.end()); }
static uint256 Joined(const uint256& a, const uint256& b)
{
    Bytes raw; HashBytes(raw, a); HashBytes(raw, b); return Digest(raw);
}
static Integer Number(uint256 h)   // by value: this uint256 has no const begin()
{
    Integer n = 0;
    for (int i = 31; i >= 0; --i) { n <<= 8; n += h.begin()[i]; }
    return n;
}
static Integer Target(unsigned int bits)
{
    unsigned int size = bits >> 24, word = bits & 0x007fffff;
    if (!word || (bits & 0x00800000) || size > 34 || (word > 255 && size > 33) || (word > 65535 && size > 32))
        return 0;
    Integer n = word;
    if (size <= 3) n >>= 8*(3-size); else n <<= 8*(size-3);
    return n;
}
static unsigned int Bits(Integer n)
{
    if (n <= 0) return 0;
    unsigned int size = (boost::multiprecision::msb(n)+8)/8;
    Integer mantissa = n;
    if (size <= 3) mantissa <<= 8*(3-size); else mantissa >>= 8*(size-3);
    unsigned int word = mantissa.convert_to<unsigned int>();
    if (word & 0x00800000) { word >>= 8; ++size; }
    return word | (size << 24);
}
unsigned int Retarget(unsigned int bits, int64 elapsed, unsigned int limit)
{
    elapsed = std::max<int64>(1209600/4, std::min<int64>(1209600*4, elapsed));
    Integer n = Target(bits)*elapsed/1209600, cap = Target(limit);
    return Bits(n > cap ? cap : n);
}
// Litecoin's CalculateNextWorkRequired (v0.21.4, src/pow.cpp): 3.5 days, and
// a target within a bit of the limit is halved before the multiply and
// doubled after, dropping its lowest bit as the 256-bit original does.
unsigned int LitecoinRetarget(unsigned int bits, int64 elapsed, unsigned int limit)
{
    const int64 timespan = 302400;
    elapsed = std::max<int64>(timespan/4, std::min<int64>(timespan*4, elapsed));
    Integer n = Target(bits), cap = Target(limit);
    bool shift = boost::multiprecision::msb(n)+1 > boost::multiprecision::msb(cap);
    if (shift) n >>= 1;
    n = n*elapsed/timespan;
    if (shift) n <<= 1;
    return Bits(n > cap ? cap : n);
}
// Litecoin's proof of work: scrypt with N=1024, r=1, p=1 of the 80-byte
// header, salted with itself (v0.21.4, src/crypto/scrypt.cpp).
static uint256 Scrypt(const Bytes& raw)
{
    uint256 out;
    if (crypto_pwhash_scryptsalsa208sha256_ll(&raw[0], raw.size(), &raw[0], raw.size(), 1024, 1, 1, out.begin(), 32) != 0)
        throw std::runtime_error("scrypt failed");
    return out;
}

// ---- the chains, each from its own source at a named tag
//
// Bitcoin: Bitcoin Core v31.1, src/kernel/chainparams.cpp. Litecoin:
// litecoin-project/litecoin v0.21.4, src/chainparams.cpp and src/pow.cpp.
//
// Litecoin starts from a run of real headers instead of its genesis: from
// genesis that is over three million scrypt headers over Tor. Each run ends
// at a retarget boundary and carries the twelve headers the next retarget and
// the first median times need. The mainnet run (heights 3203413 to 3203424)
// was read from litecoinspace.org and its hashes checked against Trezor's
// Blockbook (litecoinblockexplorer.net), and every header in it carries its
// scrypt proof of work (SelfTestLitecoin). Its first retarget was checked
// against the header the chain made: 0x192ea885 over 290369 s -> 0x192ccd4e.
// The test network run is from litecoinspace.org alone; test coins are worth
// nothing, and a wrong run only fails to connect.
static const char* LTC_MAIN_ANCHOR[] = {
    "140000205cbbcb71c02ef990ba2baad3d0d6ab1ccd6018e2683719c5b4a77090ca5a2801d75cbe847adc747952e2d9ecd3fb37e0282c370d25cbeec20a0435dc2398c2b3e474e26a85a82e19940ca448", // 3203413
    "00000020cd213b6062b0e5f5db45d34b5f59682605fdb8008c07d94326022e11ba30db1134279dd9928621ed5fa631e4433b632a473381caab70490397097bcf002b523ca775e26a85a82e19dd1216dd", // 3203414
    "000000209ca69383cb88a7e021a79c5c068b74e7dcf5d6d7e1a3d37993dfcf1914ded9e3b1cdae5b9a250068c0fb83f176c639bcedcb39c213576ded09e380952eea9296bc75e26a85a82e196ab8c37b", // 3203415
    "00000020f11a62885ae848a1518354213cbf129169ae2c939b8838c5a6f9704acec53ed9336a5322ea767606f0ed47ddddb0e68881678c75ed2877cb0b72b59c6a6261388276e26a85a82e196a3b8c55", // 3203416
    "1400002009483541436ed493f404347626c3c5bcc1f1b60243ce29573ed63be6f55eb36302de703c60d3f0015f4a16e169272b257e7f62d8c9c2bd7f600184391f974ea98a76e26a85a82e199f2856b3", // 3203417
    "000000206c1110d17c9901fb88ac5910fdde78c6563ec0e5a25b90ae62bf7584f525011120dcfee42700c8f3cfdbc3dde7de755ffbb3c5e7a90afcb8031c9ce8322214160d77e26a85a82e1957b22f1b", // 3203418
    "14000020da20e5b0afd2fb966a54ffc7810c2b2a271a9a8bb4a12af8e927527a931cfb7d7e9945c54d4016df272cbced32b8b458c3ab59f50508ece041d3028dc49765592a77e26a85a82e192270c986", // 3203419
    "000000202aeebeee8b4db0e0e24e18abcf8df5b76b90afc8f255347e53565a8acfe8a7c04dca6209f833731d78a3bceb9bfc17a77486d8b4f634800c6f4afa5523ff4186c777e26a85a82e198550039d", // 3203420
    "00000020e5b748978d989dc943f4baab522bfc910707e77408d4070b921fbd46cfe4b6c0f645167bc2ba4aa4e8f101c71d35239db90db0e48fa2e8ca0cb795ebd6c770d25578e26a85a82e1979a856f6", // 3203421
    "0000002039b2403845894f554a211f135782966c79c796cb88baec43221e91e1b558484fa5f82b692588661a215b8990896c74cb36ea9f89c4f8cbc87d0324874afe24cd0079e26a85a82e190b4301e2", // 3203422
    "000000205a73135b77e9eba4359f4bd09b9923950d779ac6cc19948029f037b161520b9977f4d5aeea81539e15765a34ca6114dbcf9fea38356991e09989df4e1bf3db881f7be26a85a82e1943ae8e6a", // 3203423
    "00000020946d142d132dc0fdfac21ebeeac58485cc83882781d8ea6cb28a18e28951c489e06270c1e7943582248ea01a6525c23b4f06eb711561f7d05c7a4fe7285a8bef7a7be26a4ecd2c19c78e625c", // 3203424
};
static const char* LTC_TEST_ANCHOR[] = {
    "000000201b9a3a27fef1d85b37b94e269ac847ae2dbae749587ab5a660d20f0d897225c91823e8e48261dacd0e61649fc357974fddc39ea13cca77273cf8101c3ac824424408e96afcff031dc9c17c9c", // 5013781
    "00000020f670837ae40ea01c56b73ebca9d8345480d4e2cc124edd909970f393e6a42fae6753df0cf83b4b3ccf10d401a79ca26a84a6f92f6a9732e9c141ccbd959617984408e96afcff031d0ca03644", // 5013782
    "000000201480122103e2cf4d7b96a3a597aa0cf6f51248eea6ddc7fc239072866b067049cd0288137fa745c7368c5e9f6477546ddc1ef1b592d1d4c9e23fac2c5f04031b4508e96afcff031d957d7b2e", // 5013783
    "000000205ee59b39fe7c465a451a8e8bc6bd94f0ad0ef8c73fc91b93418215a8128d6563046759cdc8936515571729e734d198a217b04f7369fb3c907bf68a53e66bca154808e96afcff031dbda885f8", // 5013784
    "00000020a21269d4f98151bb8b95cc052f1037efaabdca9a93790d125558616e3b5585c453ff615dc526a9a67ee08789f370475f6479f7a9b8e23e5da20dd3c1a34081df4908e96afcff031d0deaea58", // 5013785
    "00000020d364453aef841570cf22873fb8302f9f819ca2c4c3e4e80b30e6ec5997db5edbada84d078023ca906a3f81b16ccc2ec0f752f052f3c5ae547577611bf743acc54b08e96afcff031d5c3e87b4", // 5013786
    "000000201cfecf934ee964571b0a9721d59a92c0aa89f49a680a0c4ad1c3610dd6bea7b7afecbdab52721f9e4e830c2ad3529338b501c5380a449464e345c97e52106d354c08e96afcff031d19a068ab", // 5013787
    "0000002069c170bf7d051ce965411eea7124faf4a9aaf751beec724563fd804f88b4f0d869f4b4321399df57c86fbfddf65f151d426b20379ed4f03d04dd452d1be716444d08e96afcff031dd5b3dc07", // 5013788
    "00000020f37915829492ffc716c076fb8440f1a92c362b73ad44f3c594a324d1d9bb82d6652f98a32e7fb774a48adb1674e30c691c6cb32a1ba425e0161d39c255c349a05208e96afcff031d081e820a", // 5013789
    "00000020e3d02f012e806d18c026c685f7c76a547bd19bf74047f574fc3d4a285251cc0a26b8d2b545c17a42b7d0e1ae1991cc40a58a2c01847f89fd19f9d714c75c06905508e96afcff031dab86c609", // 5013790
    "0000002040a8bc2019b62a0b2a6e04babf759fd246317c5520f735e67a2cf1a0aacd3e7bf6942267077deee68be5b7978ad6e9a5de5fa366a842b9f6d7255d8c60daac155608e96afcff031de3c89edd", // 5013791
    "00000020c78a61f81591df6ba42729bf1c51fca73794cb5cbcdce06c764a58e50a1a1b2d5fee8d2811c8bc302335386cf549fc00c29b2440adfd34abb052d2183dd7a4ad5808e96affff001d3d4b238f", // 5013792
};
static Bytes GenesisHeader(unsigned int version, const char* merkle, unsigned int time, unsigned int bits, unsigned int nonce)
{
    Bytes b; Put(b, version, 4); b.resize(36, 0);
    uint256 m(merkle); b.insert(b.end(), m.begin(), m.end());
    Put(b, time, 4); Put(b, bits, 4); Put(b, nonce, 4);
    return b;
}
static std::vector<Net> MakeNets()
{
    std::vector<Net> v;
    const char* btcMerkle = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    Net n;
    n.coin = "btc"; n.label = "Bitcoin"; n.timespan = 1209600; n.spacing = 600; n.filters = true;
    n.services = 64; n.blockInv = 0x40000002; n.agent = "/Bitflash:btc-light/";
    n.name = "main"; n.magic = 0xd9b4bef9; n.port = 8333;
    n.seeds = {"x49.seed.bitcoin.sprovoost.nl", "x49.dnsseed.emzy.de", "x49.seed.mainnet.achownodes.xyz"};
    n.pkhVersion = 0; n.shVersion = 5; n.shVersion2 = 5; n.hrp = "bc"; n.limitBits = 0x1d00ffff;
    // assumevalid block 938343
    n.minimumWork = "0000000000000000000000000000000000000001128750f82f4c366153a3a030";
    n.genesis = GenesisHeader(1, btcMerkle, 1231006505, 0x1d00ffff, 2083236893);
    v.push_back(n);
    n.name = "testnet4"; n.magic = 0x283f161c; n.port = 48333;
    n.seeds = {"x49.seed.testnet4.bitcoin.sprovoost.nl", "x49.seed.testnet4.wiz.biz"};
    n.pkhVersion = 111; n.shVersion = 196; n.shVersion2 = 196; n.hrp = "tb";
    n.minDifficulty = true; n.bip94 = true;
    // assumevalid block 123613
    n.minimumWork = "0000000000000000000000000000000000000000000009a0fe15d0177d086304";
    n.genesis = GenesisHeader(1, "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e", 1714777860, 0x1d00ffff, 393743547);
    v.push_back(n);
    n.name = "regtest"; n.magic = 0xdab5bffa; n.port = 18444; n.seeds.clear(); n.hrp = "bcrt";
    n.minDifficulty = false; n.bip94 = false; n.regtest = true; n.limitBits = 0x207fffff; n.minimumWork = "";
    n.genesis = GenesisHeader(1, btcMerkle, 1296688602, 0x207fffff, 2);
    v.push_back(n);

    const char* ltcMerkle = "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9";
    Net l;
    l.coin = "ltc"; l.label = "Litecoin"; l.timespan = 302400; l.spacing = 150; l.scrypt = true; l.fullPeriod = true;
    // Few Litecoin peers serve BIP157 filters; any full node serves blocks,
    // and asked for MSG_BLOCK it sends them without MWEB data (net_processing.cpp).
    l.filters = false; l.services = 1; l.blockInv = 2; l.agent = "/Bitflash:ltc-light/";
    l.name = "main"; l.magic = 0xdbb6c0fb; l.port = 9333;
    l.seeds = {"seed-a.litecoin.loshan.co.uk", "dnsseed.thrasher.io", "dnsseed.litecointools.com",
               "dnsseed.litecoinpool.org", "dnsseed.koin-project.com"};
    l.pkhVersion = 48; l.shVersion = 50; l.shVersion2 = 5; l.hrp = "ltc"; l.limitBits = 0x1e0fffff;
    l.genesis = GenesisHeader(1, ltcMerkle, 1317972665, 0x1e0ffff0, 2084524493);
    l.anchorHeight = 3203424; l.anchor.assign(LTC_MAIN_ANCHOR, LTC_MAIN_ANCHOR + sizeof(LTC_MAIN_ANCHOR)/sizeof(LTC_MAIN_ANCHOR[0]));
    v.push_back(l);
    l.name = "test"; l.magic = 0xf1c8d2fd; l.port = 19335;
    l.seeds = {"testnet-seed.litecointools.com", "seed-b.litecoin.loshan.co.uk", "dnsseed-testnet.thrasher.io"};
    l.pkhVersion = 111; l.shVersion = 58; l.shVersion2 = 196; l.hrp = "tltc"; l.minDifficulty = true;
    l.genesis = GenesisHeader(1, ltcMerkle, 1486949366, 0x1e0ffff0, 293345);
    l.anchorHeight = 5013792; l.anchor.assign(LTC_TEST_ANCHOR, LTC_TEST_ANCHOR + sizeof(LTC_TEST_ANCHOR)/sizeof(LTC_TEST_ANCHOR[0]));
    v.push_back(l);
    l.name = "regtest"; l.magic = 0xdab5bffa; l.port = 19444; l.seeds.clear(); l.hrp = "rltc";
    l.minDifficulty = false; l.regtest = true; l.limitBits = 0x207fffff;
    l.genesis = GenesisHeader(1, ltcMerkle, 1296688602, 0x207fffff, 0);
    l.anchorHeight = 0; l.anchor.clear();
    v.push_back(l);
    return v;
}
static const std::vector<Net>& Nets()
{
    static const std::vector<Net> nets = MakeNets();
    return nets;
}
const Net* FindNet(const std::string& coin, const std::string& network)
{
    for (const Net& n : Nets())
        if (n.coin == coin && n.name == network)
            return &n;
    return NULL;
}
std::string Label(const std::string& coin)
{
    return coin == "ltc" ? "Litecoin" : "Bitcoin";
}
static Header Decode(const Bytes& raw)
{
    if (raw.size() != 80) throw std::runtime_error("Bitcoin header must be 80 bytes");
    Header h; h.raw = raw; h.hash = Digest(raw); h.prev = ReadHash(raw, 4); h.merkle = ReadHash(raw, 36);
    h.time = (unsigned int)LE(raw, 68, 4); h.bits = (unsigned int)LE(raw, 72, 4); return h;
}
Headers::Headers(const std::string& net) : network(net), net(FindNet("btc", net))
{
    // Height zero, each header after it checked for work and retarget: slow
    // the first time, and safe. These genesis fields are Bitcoin Core's (v31.1,
    // src/kernel/chainparams.cpp), and SelfTest checks the hashes they make.
    if (!this->net) throw std::runtime_error("Bitcoin light supports main, testnet4 and regtest");
    Start(*this->net);
}
Headers::Headers(const Net& n) : network(n.name), net(&n) { Start(n); }
void Headers::Start(const Net& n)
{
    if (n.anchor.empty())
    {
        Header h = Decode(n.genesis);
        h.work = (Integer(1)<<256)/(Target(h.bits)+1);
        nodes[h.hash] = h; active.push_back(h.hash); base = 0;
        return;
    }
    // A run of real headers, trusted as a checkpoint is: linked to each
    // other, and counting work only from here.
    base = n.anchorHeight-(int)n.anchor.size()+1;
    for (size_t i = 0; i < n.anchor.size(); ++i)
    {
        Header h = Decode(ParseHex(n.anchor[i]));
        if (i && h.prev != active.back()) throw std::runtime_error(n.label+" anchor headers do not link");
        h.height = base+(int)i;
        h.work = i ? nodes.at(active.back()).work+(Integer(1)<<256)/(Target(h.bits)+1) : Integer(0);
        nodes[h.hash] = h; active.push_back(h.hash);
    }
}
const Header& Headers::Tip() const { return nodes.at(active.back()); }
const Header& Headers::At(int height) const
{
    if (height < base) throw std::runtime_error("header before the light client's starting point");
    return nodes.at(active.at(height-base));
}
bool Headers::Contains(const uint256& hash) const { return nodes.count(hash) != 0; }
int Headers::ActiveHeight(const uint256& hash) const
{
    auto it = nodes.find(hash);
    if (it == nodes.end() || it->second.height < base || it->second.height > Tip().height || At(it->second.height).hash != hash) return -1;
    return it->second.height;
}
int64 Headers::Median(const Header& header) const
{
    std::vector<unsigned int> times;
    const Header* h = &header;
    for (int i = 0; i < 11; ++i)
    {
        times.push_back(h->time);
        if (h->height <= base) break;
        h = &nodes.at(h->prev);
    }
    std::sort(times.begin(), times.end()); return times[times.size()/2];
}
unsigned int Headers::NextBits(const Header& parent, unsigned int time) const
{
    if (net->regtest) return parent.bits;
    int next = parent.height+1, interval = net->Interval();
    if (next % interval)
    {
        if (!net->minDifficulty) return parent.bits;
        // Testnet: a block more than two spacings after its parent may be
        // at the limit; otherwise the last bits not at the limit.
        if ((int64)time > (int64)parent.time+2*net->spacing) return net->limitBits;
        const Header* h = &parent;
        while (h->height % interval && h->height > base && h->bits == net->limitBits) h = &nodes.at(h->prev);
        return h->bits;
    }
    // Bitcoin measures the period from its first block (interval-1 back);
    // Litecoin from the block before it, except on the first retarget.
    int back = net->fullPeriod && next != interval ? interval : interval-1;
    const Header* first = &parent;
    for (int i = 0; i < back; ++i) first = &nodes.at(first->prev);
    if (net->fullPeriod) return LitecoinRetarget(parent.bits, (int64)parent.time-first->time, net->limitBits);
    // BIP94 preserves the first block's difficulty across testnet4 periods.
    return Retarget(net->bip94 ? first->bits : parent.bits, (int64)parent.time-first->time, net->limitBits);
}
bool Headers::Add(const Bytes& raw, std::string& err)
{
    try
    {
        Header h = Decode(raw);
        if (nodes.count(h.hash)) return true;
        std::map<uint256, Header>::const_iterator it = nodes.find(h.prev);
        if (it == nodes.end()) throw std::runtime_error("unknown "+net->label+" header parent");
        const Header& p = it->second;
        Integer target = Target(h.bits), limit = Target(net->limitBits);
        if (target <= 0 || target > limit || Number(net->scrypt ? (storedHeaders ? uint256(0) : Scrypt(raw)) : h.hash) > target)
            throw std::runtime_error("invalid "+net->label+" proof of work");
        if (h.bits != NextBits(p, h.time)) throw std::runtime_error("invalid "+net->label+" difficulty");
        if (h.time <= Median(p) || (int64)h.time > GetTime()+7200) throw std::runtime_error("invalid "+net->label+" header time");
        if (net->bip94 && (p.height+1)%net->Interval() == 0 && (int64)h.time < (int64)p.time-600)
            throw std::runtime_error("testnet4 timewarp");
        h.height = p.height+1; h.work = p.work+(Integer(1)<<256)/(target+1);
        nodes[h.hash] = h;
        if (h.work > Tip().work)
        {
            active.resize(h.height+1-base,uint256(0));
            const Header* walk = &nodes.at(h.hash);
            while (active[walk->height-base] != walk->hash)
            {
                active[walk->height-base] = walk->hash;
                if (walk->height == base) break;
                walk = &nodes.at(walk->prev);
            }
        }
        return true;
    }
    catch (const std::exception& e) { err = e.what(); return false; }
}
int Headers::ForkHeight(const uint256& hash) const
{
    auto it = nodes.find(hash);
    while (it != nodes.end() && ActiveHeight(it->first) < 0)
    {
        if (it->second.height <= base) return -1;
        it = nodes.find(it->second.prev);
    }
    return it == nodes.end() ? -1 : it->second.height;
}
std::vector<uint256> Headers::Locator() const
{
    std::vector<uint256> out;
    int step = 1, h = Tip().height;
    for (;;) { out.push_back(At(h).hash); if (h == base) break; h = std::max(base, h-step); if (out.size() > 10) step *= 2; }
    return out;
}

static uint64_t Sip(uint256 hash, const Bytes& script)
{
    unsigned char out[8];
    crypto_shorthash_siphash24(out, script.empty() ? (const unsigned char*)"" : &script[0], script.size(), hash.begin());
    Bytes b(out, out+8); return LE(b, 0, 8);
}
static uint64_t Mapped(const uint256& block, const Bytes& script, uint64_t range)
{
    return ((boost::multiprecision::uint128_t(Sip(block, script))*range)>>64).convert_to<uint64_t>();
}
static void Bit(Bytes& b, size_t& pos, bool v)
{
    if (pos/8 == b.size()) b.push_back(0);
    if (v) b[pos/8] |= 1 << (7-pos%8);
    ++pos;
}
Bytes EncodeFilter(const uint256& block, const std::vector<Bytes>& scripts)
{
    std::set<Bytes> unique;
    for (size_t i = 0; i < scripts.size(); ++i) if (!scripts[i].empty() && scripts[i][0] != OP_RETURN) unique.insert(scripts[i]);
    Bytes out; Compact(out, unique.size()); size_t bit = out.size()*8;
    std::vector<uint64_t> values;
    for (std::set<Bytes>::const_iterator it = unique.begin(); it != unique.end(); ++it) values.push_back(Mapped(block, *it, unique.size()*784931ULL));
    std::sort(values.begin(), values.end()); uint64_t last = 0;
    for (size_t i = 0; i < values.size(); ++i)
    {
        uint64_t delta = values[i]-last; last = values[i];
        for (uint64_t q = delta>>19; q; --q) Bit(out, bit, true);
        Bit(out, bit, false);
        for (int k = 18; k >= 0; --k) Bit(out, bit, (delta>>k)&1);
    }
    return out;
}
bool MatchFilter(const uint256& block, const Bytes& filter, const std::vector<Bytes>& scripts, bool& match)
{
    match = false;
    try
    {
        size_t p = 0; uint64_t n = Count(filter, p, 1000000), range = n*784931ULL, value = 0;
        size_t bit = p*8;
        std::set<uint64_t> queries;
        for (size_t i = 0; i < scripts.size(); ++i) queries.insert(Mapped(block, scripts[i], range));
        auto read = [&]() -> unsigned int {
            if (bit >= filter.size()*8) throw std::runtime_error("truncated Bitcoin filter");
            unsigned int v = (filter[bit/8]>>(7-bit%8))&1; ++bit; return v;
        };
        for (uint64_t i = 0; i < n; ++i)
        {
            uint64_t q = 0;
            while (read()) if (++q > range>>19) throw std::runtime_error("invalid Bitcoin filter quotient");
            uint64_t delta = q<<19;
            for (int k = 18; k >= 0; --k) delta |= uint64_t(read())<<k;
            if (delta >= range || value >= range-delta) throw std::runtime_error("invalid Bitcoin filter range");
            value += delta;
            if (queries.count(value)) match = true;
        }
        if ((bit+7)/8 != filter.size()) return false;
        while (bit < filter.size()*8) if (read()) return false;
        return true;
    }
    catch (...) { match = false; return false; }
}
bool VerifyBlock(const Bytes& raw, const Header& h, std::vector<CTransaction>& txs)
{
    if (raw.size() < 81 || raw.size() > 4000000 || !std::equal(h.raw.begin(), h.raw.end(), raw.begin()) || !btcswap::ParseBlockTxs(raw, txs)) return false;
    std::vector<uint256> tree;
    for (size_t i = 0; i < txs.size(); ++i) tree.push_back(txs[i].GetHash());
    while (tree.size() > 1)
    {
        std::vector<uint256> next;
        for (size_t i = 0; i < tree.size(); i += 2)
        {
            if (i+1 < tree.size() && tree[i] == tree[i+1]) return false;
            next.push_back(Joined(tree[i], tree[std::min(i+1, tree.size()-1)]));
        }
        tree.swap(next);
    }
    return !tree.empty() && tree[0] == h.merkle;
}

bool Destination(const btcswap::Chain& chain, const std::string& addr, CScript& script, std::string& err)
{
    // Bitcoin's own-node mode also knows test and signet, which the light
    // client does not: their prefixes are testnet4's.
    const Net* net = FindNet(chain.coin, chain.name);
    if (!net && chain.coin == "btc" && !chain.fMain) net = FindNet("btc", "testnet4");
    script.clear(); Bytes base;
    if (DecodeBase58Check(addr, base) && base.size() == 21)
    {
        Bytes hash(base.begin()+1, base.end());
        if (base[0] == chain.pkhVersion) { script << OP_DUP << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG; return true; }
        if (base[0] == chain.shVersion || (net && base[0] == net->shVersion2)) { script << OP_HASH160 << hash << OP_EQUAL; return true; }
    }
    std::string lower = addr; bool upper = false, small = false;
    for (size_t i = 0; i < lower.size(); ++i) { if (lower[i] >= 'A' && lower[i] <= 'Z') upper = true; if (lower[i] >= 'a' && lower[i] <= 'z') small = true; lower[i] = (char)tolower((unsigned char)lower[i]); }
    size_t sep = lower.rfind('1');
    std::string hrp = net ? net->hrp : chain.fMain ? "bc" : "tb";
    if (addr.size() <= 90 && !(upper && small) && sep != std::string::npos && lower.substr(0, sep) == hrp && sep+7 < lower.size())
    {
        uint32_t check = 1;
        auto feed = [&](unsigned int v) {
            uint32_t top = check>>25; check = ((check & 0x1ffffff)<<5)^v;
            const uint32_t gen[5] = {0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
            for (int i = 0; i < 5; ++i) if ((top>>i)&1) check ^= gen[i];
        };
        for (size_t i = 0; i < hrp.size(); ++i) feed(hrp[i]>>5);
        feed(0); for (size_t i = 0; i < hrp.size(); ++i) feed(hrp[i]&31);
        Bytes data; const std::string alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for (size_t i = sep+1; i < lower.size(); ++i)
        {
            size_t x = alphabet.find(lower[i]); if (x == std::string::npos) { err = "invalid Bitcoin address character"; return false; }
            feed((unsigned int)x); data.push_back((unsigned char)x);
        }
        unsigned int version = data[0], acc = 0, bits = 0; Bytes program;
        for (size_t i = 1; i+6 < data.size(); ++i)
        {
            acc = ((acc<<5)|data[i])&0xfff; bits += 5;
            if (bits >= 8) { bits -= 8; program.push_back((unsigned char)(acc>>bits)); }
        }
        if (version <= 16 && check == (version ? 0x2bc830a3U : 1U) && bits < 5 && ((acc<<(8-bits))&255) == 0 &&
            program.size() >= 2 && program.size() <= 40 && (version != 0 || program.size() == 20 || program.size() == 32))
        {
            script.push_back(version ? OP_1+version-1 : OP_0); script.push_back((unsigned char)program.size());
            script.insert(script.end(), program.begin(), program.end()); return true;
        }
    }
    err = "invalid "+Label(chain.coin)+" destination or wrong network"; return false;
}

struct Peer
{
    SOCKET socket = INVALID_SOCKET;
    std::string identity;
    unsigned int magic;
    const Net& net;
    explicit Peer(const Net& n) : magic(n.magic), net(n) {}
    ~Peer() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    void Transfer(unsigned char* data, size_t size, bool writing)
    {
        while (size && !fShutdown)
        {
            int n = writing ? send(socket, (const char*)data, (int)size, 0) : recv(socket, (char*)data, (int)size, 0);
            if (n <= 0) throw std::runtime_error(net.label+" peer disconnected or timed out");
            data += n; size -= n;
        }
        if (size) throw std::runtime_error(net.label+" light shutting down");
    }
    void Send(const std::string& command, const Bytes& payload)
    {
        Bytes packet; Put(packet, magic, 4);
        packet.insert(packet.end(), command.begin(), command.end()); packet.resize(16, 0);
        Put(packet, payload.size(), 4); uint256 hash = Digest(payload);
        packet.insert(packet.end(), hash.begin(), hash.begin()+4); packet.insert(packet.end(), payload.begin(), payload.end());
        Transfer(&packet[0], packet.size(), true);
    }
    Bytes Receive(const std::string& wanted)
    {
        // Bound unsolicited traffic as well as individual messages.
        size_t budget = 16*1024*1024;
        for (int messages = 0; messages < 256; ++messages)
        {
            Bytes header(24); Transfer(&header[0], 24, false);
            if (LE(header, 0, 4) != magic) throw std::runtime_error("wrong "+net.label+" message magic");
            size_t length = (size_t)LE(header, 16, 4);
            if (length > 4000000 || length > budget) throw std::runtime_error("oversized "+net.label+" message");
            budget -= length;
            std::string command;
            bool ended = false;
            for (int i = 4; i < 16; ++i)
            {
                if (!header[i]) ended = true;
                else if (ended || header[i] < 32 || header[i] > 126) throw std::runtime_error("invalid "+net.label+" command");
                else command += (char)header[i];
            }
            Bytes payload(length); if (length) Transfer(&payload[0], length, false);
            uint256 hash = Digest(payload);
            if (!std::equal(hash.begin(), hash.begin()+4, header.begin()+20)) throw std::runtime_error(net.label+" checksum mismatch");
            if (command == wanted) return payload;
            if (command == "ping") { if (length != 8) throw std::runtime_error("invalid ping"); Send("pong", payload); }
            if (command == "reject" || command == "notfound") throw std::runtime_error(net.label+" peer rejected request");
        }
        throw std::runtime_error(net.label+" peer did not answer request");
    }
    Bytes Request(const std::string& command, const Bytes& payload, const std::string& response)
    {
        Send(command, payload); return Receive(response);
    }
    void Connect(const std::string& spec, unsigned short defaultPort)
    {
        std::string host = spec; unsigned short port = defaultPort;
        size_t colon = spec.rfind(':');
        if (colon != std::string::npos && (spec.find(':') == colon || spec[0] == '['))
        {
            std::string text = spec.substr(colon+1);
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos || text.size() > 5 || atoi(text.c_str()) < 1 || atoi(text.c_str()) > 65535)
                throw std::runtime_error("invalid -"+net.coin+"peer port");
            port = (unsigned short)atoi(text.c_str()); host = spec.substr(0, colon);
        }
        if (host.size() > 2 && host[0] == '[' && host.back() == ']') host = host.substr(1, host.size()-2);
        // Separate nodes on one host can listen on different P2P ports.
        identity = host + ":" + strprintf("%u", (unsigned int)port);
        // Regtest has no Tor to wait for, and with the wallet's Tor up a peer
        // on this machine could not be reached through it. Nothing leaves.
        socket = net.regtest && (host == "127.0.0.1" || host == "localhost") ? BtfConnectLoopback(port, 15) : BtfConnectSocket(host, port, 0, 15);
        if (socket == INVALID_SOCKET) throw std::runtime_error("cannot connect to "+net.label+" peer " + spec);
#ifdef _WIN32
        DWORD timeout = 15000;
#else
        struct timeval timeout = {15, 0};
#endif
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        Bytes version; Put(version, 70016, 4); Put(version, 0, 8); Put(version, GetTime(), 8);
        version.resize(72, 0); uint64_t nonce; randombytes_buf(&nonce, sizeof(nonce)); Put(version, nonce, 8);
        std::string agent = net.agent; Compact(version, agent.size()); version.insert(version.end(), agent.begin(), agent.end());
        Put(version, 0, 4); version.push_back(0);
        Send("version", version); Bytes theirs = Receive("version");
        if (theirs.size() < 80 || LE(theirs, 0, 4) < 70015 || (LE(theirs, 4, 8)&net.services) != net.services)
            throw std::runtime_error(net.filters ? "Bitcoin peer lacks NODE_COMPACT_FILTERS" : net.label+" peer is not a full node");
        if (LE(theirs, 72, 8) == nonce) throw std::runtime_error(net.label+" self connection");
        Send("verack", Bytes()); Receive("verack");
    }
};

struct FilterRecord { uint256 block, hash, header; };
struct State
{
    std::recursive_mutex mutex;
    Headers headers;
    std::string path, error;
    std::vector<FilterRecord> filters;
    std::set<Bytes> watched;
    std::map<uint256, Bytes> blocks, pending;
    std::vector<std::string> peers;
    int scan = 0;
    int64 birthday = 0;
    int peersCompared = 0;
    size_t savedFilters = 0;
    uint256 savedFilterTail = uint256(0);
    // Where a chain without filters (Litecoin) scans blocks: scan is the next
    // height, and scanHash the block before it, to step back after a reorg.
    uint256 scanHash = uint256(0);
    bool synced = false;
    const Net& net;
    explicit State(const std::string& network) : State(*FindNet("btc", network)) {}
    explicit State(const Net& n) : headers(n), path(std::string(GetAppDir())+"/"+n.coin+"-light-"+n.name), net(n)
    {
        if (!n.filters) scan = headers.Tip().height+1;
    }
};
static std::map<std::string, State*> states;
static std::mutex startMutex;
static State& StateOf(const btcswap::Chain& chain)
{
    std::lock_guard<std::mutex> start(startMutex);
    auto it = states.find(chain.coin+"/"+chain.name);
    if (it == states.end()) throw std::runtime_error(Label(chain.coin)+" light not initialized");
    return *it->second;
}
static std::string Hex(const Bytes& b) { return HexStr(b.begin(), b.end(), false); }
static void AtomicFile(const std::string& path, const std::string& data)
{
    std::string temp = path+".tmp";
    FILE* file = fopen(temp.c_str(), "wb");
    if (!file) throw std::runtime_error("cannot write Bitcoin light state");
    bool ok = fwrite(data.data(), 1, data.size(), file) == data.size();
    if (fflush(file)) ok = false;
#ifdef _WIN32
    if (_commit(_fileno(file))) ok = false;
#else
    if (fsync(fileno(file))) ok = false;
#endif
    if (fclose(file)) ok = false;
    if (!ok) throw std::runtime_error("cannot flush Bitcoin light state");
#ifdef _WIN32
    if (!MoveFileExA(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
#else
    if (rename(temp.c_str(), path.c_str()))
#endif
        throw std::runtime_error("cannot replace Bitcoin light state");
}
static void Save(State& s)
{
    json j; j["version"] = 1; j["network"] = s.headers.network; j["scan"] = s.scan; j["birthday"] = s.birthday;
    if (s.net.coin != "btc") { j["coin"] = s.net.coin; j["scanHash"] = s.scanHash.GetHex(); }
    j["watched"] = json::array(); j["blocks"] = json::array(); j["pending"] = json::array();
    for (std::set<Bytes>::const_iterator it = s.watched.begin(); it != s.watched.end(); ++it) j["watched"].push_back(Hex(*it));
    for (auto it = s.blocks.begin(); it != s.blocks.end(); ++it) j["blocks"].push_back(Hex(it->second));
    for (auto it = s.pending.begin(); it != s.pending.end(); ++it) j["pending"].push_back(Hex(it->second));
    j["peers"] = s.peers;
    AtomicFile(s.path+".json", j.dump());
}
static void AppendHeader(State& s, const Bytes& raw)
{
    std::ofstream f((s.path+".headers").c_str(), std::ios::binary|std::ios::app);
    f.write((const char*)raw.data(), raw.size()); f.flush();
    if (!f) throw std::runtime_error("cannot save Bitcoin header");
}
static void SaveFilters(State& s)
{
    bool append = s.savedFilters <= s.filters.size() &&
        (!s.savedFilters || s.filters[s.savedFilters-1].block == s.savedFilterTail);
    std::string data;
    size_t first = append ? s.savedFilters : 0;
    data.reserve((s.filters.size()-first)*96);
    for (size_t i = first; i < s.filters.size(); ++i)
    {
        data.append((const char*)s.filters[i].block.begin(),32);
        data.append((const char*)s.filters[i].hash.begin(),32);
        data.append((const char*)s.filters[i].header.begin(),32);
    }
    if (append && !data.empty())
    {
        // Appending avoids rewriting a hundred megabytes for every 2000
        // hashes during initial synchronization. Reorgs replace the file.
        FILE* file = fopen((s.path+".filters").c_str(),"ab");
        if (!file) throw std::runtime_error("cannot append Bitcoin filter headers");
        bool ok = fwrite(data.data(),1,data.size(),file) == data.size();
        if (fflush(file)) ok = false;
#ifdef _WIN32
        if (_commit(_fileno(file))) ok = false;
#else
        if (fsync(fileno(file))) ok = false;
#endif
        if (fclose(file)) ok = false;
        if (!ok) throw std::runtime_error("cannot flush Bitcoin filter headers");
    }
    else if (!append) AtomicFile(s.path+".filters",data);
    s.savedFilters = s.filters.size();
    s.savedFilterTail = s.filters.empty() ? uint256(0) : s.filters.back().block;
}

static void Reconcile(State& s)
{
    if (!s.net.filters)
    {
        // Blocks scanned on a branch that left the active chain are scanned
        // again on the one that replaced it.
        int floor = s.headers.Base()+1;
        s.scan = std::max(floor, std::min(s.scan, s.headers.Tip().height+1));
        if (s.scan > floor && s.scanHash != uint256(0) && s.headers.ActiveHeight(s.scanHash) != s.scan-1)
        {
            // Back to the fork point, or from the start if the block is unknown.
            int fork = s.headers.ForkHeight(s.scanHash);
            s.scan = std::max(floor, std::min(s.scan, fork < 0 ? floor : fork+1));
        }
        s.scanHash = s.scan > s.headers.Base() ? s.headers.At(s.scan-1).hash : uint256(0);
        return;
    }
    while (!s.filters.empty() && ((int)s.filters.size()-1 > s.headers.Tip().height || s.filters.back().block != s.headers.At((int)s.filters.size()-1).hash))
        s.filters.pop_back();
    s.scan = std::min(s.scan, (int)s.filters.size());
    // Cached blocks from a disconnected branch cannot prove a payment or spend.
    // Keep them for a possible return to that branch; queries only use At(height).
}
static void Load(State& s)
{
    std::ifstream f((s.path+".headers").c_str(), std::ios::binary);
    if (f)
    {
        Bytes raw(80); std::string err;
        s.headers.storedHeaders = true;
        while (f.read((char*)raw.data(), 80))
        {
            // A later release can start from a later anchor: what is stored
            // from before it no longer connects, and is not needed.
            if (!s.net.anchor.empty() && !s.headers.Contains(ReadHash(raw,4))) continue;
            if (!s.headers.Add(raw, err)) throw std::runtime_error(s.net.label+" header store: "+err);
        }
        s.headers.storedHeaders = false;
        if (f.gcount()) throw std::runtime_error("truncated Bitcoin header store; restore its backup");
    }
    std::ifstream filters((s.path+".filters").c_str(), std::ios::binary);
    if (filters)
    {
        Bytes raw(96); uint256 previous(0);
        while (filters.read((char*)raw.data(), 96))
        {
            FilterRecord r; r.block = ReadHash(raw,0); r.hash = ReadHash(raw,32); r.header = ReadHash(raw,64);
            if (r.header != Joined(r.hash, previous)) throw std::runtime_error("corrupt Bitcoin filter store");
            s.filters.push_back(r); previous = r.header;
        }
        if (filters.gcount()) throw std::runtime_error("truncated Bitcoin filter store");
    }
    std::ifstream stored((s.path+".json").c_str(), std::ios::binary);
    if (stored)
    {
        json j; stored >> j;
        if (j.value("version",0) != 1 || j.value("network",std::string()) != s.headers.network || j.value("coin",std::string("btc")) != s.net.coin)
            throw std::runtime_error("wrong "+s.net.label+" state network/version");
        if (j.contains("scanHash")) s.scanHash = uint256(j.at("scanHash").get<std::string>());
        for (const auto& text : j.at("watched")) { Bytes b = ParseHex(text.get<std::string>()); if (b.size() != 23) throw std::runtime_error("invalid saved contract script"); s.watched.insert(b); }
        for (const auto& text : j.at("blocks"))
        {
            Bytes b = ParseHex(text.get<std::string>()); Header h = Decode(Bytes(b.begin(), b.begin()+std::min<size_t>(80,b.size())));
            std::vector<CTransaction> txs; if (!VerifyBlock(b,h,txs)) throw std::runtime_error("invalid saved Bitcoin block"); s.blocks[h.hash] = b;
        }
        for (const auto& text : j.at("pending"))
        {
            Bytes b = ParseHex(text.get<std::string>()); CTransaction tx;
            if (!btcswap::ParseTx(b,tx)) throw std::runtime_error("invalid saved Bitcoin transaction"); s.pending[tx.GetHash()] = b;
        }
        s.birthday = j.value("birthday", (int64)0);
        s.scan = j.at("scan").get<int>(); if (s.scan < 0) throw std::runtime_error("invalid saved filter cursor");
        s.peers = j.value("peers", std::vector<std::string>());
        if (s.peers.size() > 256) s.peers.resize(256);
    }
    s.savedFilters = s.filters.size();
    s.savedFilterTail = s.filters.empty() ? uint256(0) : s.filters.back().block;
    Reconcile(s);
}
static Bytes Fetch(Peer& p, const std::string& command, const Bytes& payload, const std::string& response, std::unique_lock<std::recursive_mutex>& lock)
{
    lock.unlock();
    try { Bytes b = p.Request(command,payload,response); lock.lock(); return b; }
    catch (...) { lock.lock(); throw; }
}
static void Discover(State& s, Peer& p, std::unique_lock<std::recursive_mutex>& lock)
{
    Bytes b = Fetch(p,"getaddr",Bytes(),"addr",lock); size_t pos = 0; uint64_t n = Count(b,pos,1000);
    if (b.size()-pos != n*30) throw std::runtime_error("invalid Bitcoin addr size");
    for (uint64_t i = 0; i < n && s.peers.size() < 256; ++i, pos += 30)
    {
        if ((LE(b,pos+4,8)&s.net.services) != s.net.services) continue;
        bool ipv4 = true;
        for (int k = 0; k < 10; ++k) if (b[pos+12+k]) ipv4 = false;
        if (!ipv4 || b[pos+22] != 255 || b[pos+23] != 255) continue;
        unsigned int a = b[pos+24], c = b[pos+25];
        if (!a || a == 10 || a == 127 || a >= 224 || (a == 169 && c == 254) || (a == 172 && c >= 16 && c <= 31) || (a == 192 && c == 168)) continue;
        unsigned int port = b[pos+28]*256+b[pos+29]; if (!port) continue;
        std::string peer = strprintf("%u.%u.%u.%u:%u",a,c,b[pos+26],b[pos+27],port);
        if (std::find(s.peers.begin(),s.peers.end(),peer) == s.peers.end()) s.peers.push_back(peer);
    }
}
static std::vector<Bytes> ActiveScripts(State& s);
struct Located { CTransaction tx; int height; };
static std::map<uint256, Located> Transactions(State& s);
// A chain whose peers serve no filters: every block from the contract's
// window to the tip (Watch), each checked against its header's merkle root,
// and those that pay a watched contract or spend such a payment kept.
static void ScanBlocks(State& s, Peer& primary, std::unique_lock<std::recursive_mutex>& lock)
{
    int tip = s.headers.Tip().height;
    if (!s.synced) return;
    // With nothing watched the cursor follows the tip, so a first contract
    // looks back as far as it needs (Watch) and not to the starting point.
    if (s.watched.empty()) { s.scan = tip+1; s.scanHash = s.headers.At(tip).hash; return; }
    if (s.birthday)
        while (s.scan <= tip && s.headers.Median(s.headers.At(s.scan)) < s.birthday-7200) ++s.scan;
    if (s.scan > tip) return;
    std::vector<Bytes> scripts = ActiveScripts(s);
    if (scripts.empty()) { s.scan = tip+1; s.scanHash = s.headers.At(tip).hash; return; }
    std::set<Bytes> wanted(scripts.begin(), scripts.end()), requested = s.watched;
    std::set<COutPoint> paid;
    for (const auto& entry : Transactions(s))
        for (size_t n = 0; n < entry.second.tx.vout.size(); ++n)
        {
            const CScript& out = entry.second.tx.vout[n].scriptPubKey;
            if (s.watched.count(Bytes(out.begin(),out.end()))) paid.insert(COutPoint(entry.first,(unsigned int)n));
        }
    // Twenty at a time: over Tor a peer that drops the connection costs at
    // most twenty blocks, and the cursor is saved after each batch.
    int from = s.scan, stop = std::min(from+19, tip);
    Bytes inv; Compact(inv,stop-from+1);
    for (int height = from; height <= stop; ++height) { Put(inv,s.net.blockInv,4); HashBytes(inv,s.headers.At(height).hash); }
    lock.unlock();
    try { primary.Send("getdata",inv); lock.lock(); } catch (...) { lock.lock(); throw; }
    for (int height = from; height <= stop; ++height)
    {
        lock.unlock(); Bytes block;
        try { block = primary.Receive("block"); lock.lock(); } catch (...) { lock.lock(); throw; }
        std::vector<CTransaction> txs;
        if (!VerifyBlock(block,s.headers.At(height),txs)) throw std::runtime_error(s.net.label+" block does not match its header");
        bool keep = false;
        for (const CTransaction& tx : txs)
        {
            for (const CTxIn& in : tx.vin) if (paid.count(in.prevout)) keep = true;
            for (size_t n = 0; n < tx.vout.size(); ++n)
            {
                const CScript& out = tx.vout[n].scriptPubKey;
                if (wanted.count(Bytes(out.begin(),out.end()))) { keep = true; paid.insert(COutPoint(tx.GetHash(),(unsigned int)n)); }
            }
        }
        if (keep) s.blocks[s.headers.At(height).hash] = block;
    }
    if (s.scan == from && s.watched == requested) { s.scan = stop+1; s.scanHash = s.headers.At(stop).hash; }
}
// One getheaders with a peer; how many headers it sent. Each goes through the
// same checks whoever sent it, and the most work wins.
static uint64_t PullHeaders(State& s, Peer& peer, std::unique_lock<std::recursive_mutex>& lock)
{
    Bytes request; Put(request,70016,4); std::vector<uint256> locator = s.headers.Locator(); Compact(request,locator.size());
    for (size_t i = 0; i < locator.size(); ++i) HashBytes(request,locator[i]); HashBytes(request,uint256(0));
    Bytes response = Fetch(peer,"getheaders",request,"headers",lock);
    size_t pos = 0; uint64_t n = Count(response,pos,2000);
    uint256 last(0);
    for (uint64_t i = 0; i < n; ++i)
    {
        if (response.size()-pos < 81) throw std::runtime_error("truncated Bitcoin headers");
        Bytes raw(response.begin()+pos,response.begin()+pos+80); pos += 80;
        if (Count(response,pos,0) != 0) throw std::runtime_error("header has transactions");
        Header h = Decode(raw);
        if (i && h.prev != last) throw std::runtime_error("discontinuous Bitcoin headers");
        bool known = s.headers.Contains(h.hash);
        std::string err; if (!s.headers.Add(raw,err)) throw std::runtime_error(err);
        if (!s.headers.Contains(h.hash)) throw std::runtime_error("header index insertion failed");
        if (!known) AppendHeader(s,raw); last = h.hash;
    }
    if (pos != response.size()) throw std::runtime_error("extra Bitcoin header bytes");
    return n;
}
static void Round(State& s, Peer& primary, Peer* second)
{
    std::unique_lock<std::recursive_mutex> lock(s.mutex);
    uint64_t n = PullHeaders(s,primary,lock);
    // Without filter headers to compare, a chain of real work that only the
    // primary peer shows would go uncontradicted: the second peer's headers
    // count too. A second peer that fails only takes itself out.
    if (second && !s.net.filters)
    {
        try { n = std::max(n,PullHeaders(s,*second,lock)); }
        catch (const std::exception& e) { printf("%s light: second peer: %s\n",s.net.label.c_str(),e.what()); }
    }
    Reconcile(s);
    if (s.filters.size() < s.savedFilters) SaveFilters(s);
    // A fresh timestamp alone is cheap to forge near genesis. Do not expose
    // payments until the chain has independently accumulated modern work.
    // These are Bitcoin Core's own nMinimumChainWork, from
    // src/kernel/chainparams.cpp at the signed release tag v31.1 (main:
    // assumevalid block 938343; testnet4: 123613). The values first written
    // here matched no Core release and nobody could say where they came from.
    // A chain started from an anchor counts work only from there; the anchor
    // itself is the checkpoint, and every header after it pays its own work.
    Integer minimum = *s.net.minimumWork && s.net.anchor.empty() ? Number(uint256(s.net.minimumWork)) : Integer(0);
    s.synced = n < 2000 && s.headers.Tip().work >= minimum &&
        (s.net.regtest || (int64)s.headers.Tip().time > GetTime()-7200);
    // Confirmed transactions remain saved so a reorg can resume rebroadcast.
    std::set<uint256> confirmed;
    for (auto it = s.blocks.begin(); it != s.blocks.end(); ++it)
        if (s.headers.ActiveHeight(it->first) >= 0)
        {
            std::vector<CTransaction> txs; btcswap::ParseBlockTxs(it->second,txs);
            for (const auto& tx : txs) confirmed.insert(tx.GetHash());
        }
    std::vector<Bytes> broadcasts;
    for (auto it = s.pending.begin(); it != s.pending.end(); ++it) if (!confirmed.count(it->first)) broadcasts.push_back(it->second);
    lock.unlock();
    try { for (const auto& raw : broadcasts) { primary.Send("tx",raw); if (second) second->Send("tx",raw); } lock.lock(); }
    catch (...) { lock.lock(); throw; }
    s.peersCompared = 1;
    if (!s.net.filters) { ScanBlocks(s,primary,lock); Save(s); return; }
    int start = (int)s.filters.size();
    if (start <= s.headers.Tip().height)
    {
        int stop = std::min(start+1999,s.headers.Tip().height);
        Bytes req(1,0); Put(req,start,4); HashBytes(req,s.headers.At(stop).hash);
        Bytes a = Fetch(primary,"getcfheaders",req,"cfheaders",lock);
        s.peersCompared = 1;
        if (second)
        {
            Bytes b = Fetch(*second,"getcfheaders",req,"cfheaders",lock);
            if (a != b) throw std::runtime_error("Bitcoin filter headers disagree between peers; scan stopped");
            s.peersCompared = 2;
        }
        if (a.size() < 66 || a[0] != 0 || ReadHash(a,1) != s.headers.At(stop).hash || ReadHash(a,33) != (start ? s.filters.back().header : uint256(0)))
            throw std::runtime_error("Bitcoin filter header anchor mismatch");
        size_t at = 65; uint64_t count = Count(a,at,2000);
        if (count != (uint64_t)(stop-start+1) || a.size()-at != count*32) throw std::runtime_error("invalid cfheaders count");
        uint256 previous = start ? s.filters.back().header : uint256(0);
        for (int height = start; height <= stop; ++height, at += 32)
        {
            FilterRecord r; r.block = s.headers.At(height).hash; r.hash = ReadHash(a,at); r.header = Joined(r.hash,previous);
            s.filters.push_back(r); previous = r.header;
        }
        SaveFilters(s);
    }
    // A second connection checks a previously stored anchor too, including after
    // restart. A single-peer history must not silently become two-peer history.
    if (second && !s.filters.empty())
    {
        int stop = (int)s.filters.size()-1;
        Bytes req(1,0); Put(req,stop,4); HashBytes(req,s.headers.At(stop).hash);
        Bytes a = Fetch(*second,"getcfheaders",req,"cfheaders",lock);
        size_t at = 65;
        if (a.size() < 65 || a[0] != 0 || ReadHash(a,1) != s.filters.back().block ||
            ReadHash(a,33) != (stop ? s.filters[stop-1].header : uint256(0)) || Count(a,at,1) != 1 || a.size()-at != 32 || ReadHash(a,at) != s.filters.back().hash)
            throw std::runtime_error("Bitcoin second peer disagrees with saved filter history");
        s.peersCompared = 2;
    }
    // Skip pre-watch history by median time, with a week of overlap for an
    // incoming contract. A saved cursor is never advanced merely by wall time.
    if (s.birthday && s.synced)
        while (s.scan < (int)s.filters.size() && s.headers.Median(s.headers.At(s.scan)) < s.birthday-7200) ++s.scan;
    if (!s.watched.empty() && s.synced && s.scan < (int)s.filters.size())
    {
        int from = s.scan, stop = std::min(from+99,(int)s.filters.size()-1);
        std::set<Bytes> requested = s.watched;
        std::vector<Bytes> scripts = ActiveScripts(s);
        if (scripts.empty()) { s.scan = (int)s.filters.size(); Save(s); return; }
        Bytes req(1,0); Put(req,from,4); HashBytes(req,s.headers.At(stop).hash);
        lock.unlock();
        try { primary.Send("getcfilters",req); lock.lock(); } catch (...) { lock.lock(); throw; }
        std::vector<int> matched;
        for (int height = from; height <= stop; ++height)
        {
            lock.unlock(); Bytes a;
            try { a = primary.Receive("cfilter"); lock.lock(); } catch (...) { lock.lock(); throw; }
            size_t at = 33;
            if (a.size() < 34 || a[0] != 0 || ReadHash(a,1) != s.filters[height].block) throw std::runtime_error("Bitcoin cfilter block mismatch");
            uint64_t size = Count(a,at,4000000);
            if (size != a.size()-at) throw std::runtime_error("Bitcoin cfilter size mismatch");
            Bytes filter(a.begin()+at,a.end());
            if (Digest(filter) != s.filters[height].hash) throw std::runtime_error("Bitcoin filter hash mismatch");
            bool match = false;
            if (!MatchFilter(s.headers.At(height).hash,filter,scripts,match)) throw std::runtime_error("invalid Bitcoin basic filter");
            if (match) matched.push_back(height);
        }
        // Drain the filter batch before requesting any blocks. Otherwise the
        // block receiver would discard filters still queued on this connection.
        // A batch also avoids one Tor round trip for every individual filter.
        for (size_t i = 0; i < matched.size(); ++i)
        {
            int height = matched[i];
            Bytes inv; Compact(inv,1); Put(inv,0x40000002,4); HashBytes(inv,s.headers.At(height).hash);
            Bytes block = Fetch(primary,"getdata",inv,"block",lock); std::vector<CTransaction> txs;
            if (!VerifyBlock(block,s.headers.At(height),txs)) throw std::runtime_error("Bitcoin block merkle root mismatch");
            s.blocks[s.headers.At(height).hash] = block;
            // Pending transactions are kept until their confirmation is on
            // the active branch; reorgs put them back in the broadcast set.
        }
        if (s.scan == from && s.watched == requested) s.scan = stop+1;
    }
    Save(s);
}
static std::vector<std::string> ConfiguredPeers(const std::string& coin)
{
    const std::string option = "-"+coin+"peer=";
    std::vector<std::string> args, peers;
#ifdef _WIN32
    // Read repeated options without changing the legacy wallet's parser,
    // which keeps only the last occurrence of an option.
    const char* command = GetCommandLineA();
    std::string arg; bool quoted = false;
    for (const char* c = command;; ++c)
    {
        if (*c == '\"') quoted = !quoted;
        else if (!*c || (!quoted && (*c == ' ' || *c == '\t')))
        {
            if (!arg.empty()) { args.push_back(arg); arg.clear(); }
            if (!*c) break;
        }
        else arg += *c;
    }
#elif defined(__APPLE__)
    // No /proc on macOS; the C runtime keeps the original argv.
    char** argv = *_NSGetArgv();
    for (int i = 0, n = *_NSGetArgc(); i < n; ++i) if (argv[i]) args.push_back(argv[i]);
#else
    std::ifstream input("/proc/self/cmdline", std::ios::binary);
    std::string arg;
    while (std::getline(input,arg,'\0')) args.push_back(arg);
#endif
    for (const auto& arg : args)
        if (arg.compare(0,option.size(),option) == 0)
        {
            std::string peer = arg.substr(option.size());
            if (peer.empty() || peer.size() > 300) throw std::runtime_error("invalid "+option.substr(0,option.size()-1));
            if (std::find(peers.begin(),peers.end(),peer) == peers.end()) peers.push_back(peer);
        }
    return peers;
}

static void Worker(State* s)
{
    const Net& net = s->net;
    unsigned short port = net.port;
    size_t rotation = 0;
    while (!fShutdown)
    {
        try
        {
            // Configure can run before managed Tor finishes starting. Wait
            // here instead of ever leaking a seed or peer connection directly.
            if (!net.regtest && !BtfTorProxyEnabled())
                throw std::runtime_error(net.label+" light is waiting for the wallet's Tor proxy");
            std::vector<std::string> choices;
            // Explicit peers suppress seeds, which makes regtest deterministic.
            std::vector<std::string> configured = ConfiguredPeers(net.coin);
            // An isolated bench dials only what it is told to: no seeds and
            // no saved peers, here as on the Bitflash side.
            if (configured.empty() && fBtfIsolated)
                throw std::runtime_error("isolated node: "+net.label+" light connects only to -"+net.coin+"peer=host:port");
            if (!configured.empty()) choices = configured;
            else
            {
                std::lock_guard<std::recursive_mutex> lock(s->mutex); choices = s->peers;
                choices.insert(choices.end(), net.seeds.begin(), net.seeds.end());
            }
            if (choices.empty()) throw std::runtime_error("regtest needs -"+net.coin+"peer=host:port");
            Peer primary(net); primary.Connect(choices[rotation++%choices.size()],port);
            std::unique_ptr<Peer> second;
            for (size_t i = 0; i < std::min<size_t>(choices.size(),4); ++i)
            {
                std::unique_ptr<Peer> candidate(new Peer(net));
                try { candidate->Connect(choices[(rotation+i)%choices.size()],port); }
                catch (...) { continue; }
                if (candidate->identity != primary.identity) { second = std::move(candidate); break; }
            }
            if (configured.empty())
            {
                std::unique_lock<std::recursive_mutex> lock(s->mutex);
                try { Discover(*s,primary,lock); } catch (...) {}
            }
            for (int rounds = 0; rounds < 100 && !fShutdown; ++rounds)
            {
                Round(*s,primary,second.get());
                bool synced;
                { std::lock_guard<std::recursive_mutex> lock(s->mutex); s->error.clear(); synced = s->synced && (s->watched.empty() || s->scan >= (s->net.filters ? (int)s->filters.size() : s->headers.Tip().height+1)); }
                for (int i = 0; i < (synced ? 200 : 1) && !fShutdown; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        catch (const std::exception& e)
        {
            std::lock_guard<std::recursive_mutex> lock(s->mutex); s->error = e.what(); s->synced = false;
        }
        for (int i = 0; i < 50 && !fShutdown; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
bool CheckChain(const std::string& coin, const std::string& network, btcswap::Chain& out, std::string& err)
{
    try
    {
        const Net* net = FindNet(coin, network);
        if (!net) throw std::runtime_error(Label(coin)+" light does not support the network "+network);
        if ((network == "main") == IsTestNet()) throw std::runtime_error(net->label+" and Bitflash networks must match");
        State* state = NULL;
        {
            std::lock_guard<std::mutex> start(startMutex);
            for (auto it = states.begin(); it != states.end(); ++it)
                if (it->second->net.coin == coin && it->second->net.name != network)
                    throw std::runtime_error("restart wallet to change "+net->label+" light network");
            auto it = states.find(coin+"/"+network);
            if (it == states.end())
            {
                std::unique_ptr<State> initial(new State(*net)); Load(*initial);
                state = initial.release(); states[coin+"/"+network] = state; std::thread(Worker,state).detach();
            }
            else state = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(state->mutex);
        out.coin = coin; out.name = network; out.fMain = network == "main"; out.pkhVersion = net->pkhVersion; out.shVersion = net->shVersion;
        out.nBlocks = state->headers.Tip().height; out.nMedianTime = state->headers.Median(state->headers.Tip());
        return true;
    }
    catch (const std::exception& e) { err = e.what(); return false; }
}
void Watch(const btcswap::Chain& chain, const CScript& contract)
{
    State& s = StateOf(chain);
    CScript script; script.SetPayToScriptHash(contract); Bytes b(script.begin(),script.end());
    std::lock_guard<std::recursive_mutex> lock(s.mutex);
    if (s.watched.insert(b).second)
    {
        if (s.net.filters)
        {
            if (!s.birthday) s.birthday = GetTime()-7*86400;
            // New contracts can already have a funding transaction in a recent
            // block. Existing watches retain their cursor across restarts.
            s.scan = std::min(s.scan,std::max(0,s.headers.Tip().height-400));
        }
        else
        {
            // Scanned block by block, the contract says how far back to look:
            // it cannot have been funded before its lock less the longest lock.
            // That holds however late the audit or the refund comes, and costs
            // only the blocks since the contract was made.
            swap::Contract c;
            int64 start = swap::ParseContract(contract,c) ? c.nLockTime-btcswap::INITIATOR_LOCK_SECS-7200 : GetTime()-3*86400;
            int height = s.headers.Tip().height;
            while (height > s.headers.Base()+1 && (int64)s.headers.At(height-1).time >= start) --height;
            s.scan = std::min(s.scan,height);
            s.scanHash = s.headers.At(s.scan-1).hash;
            if (!s.birthday || start < s.birthday) s.birthday = start;
        }
        Save(s);
    }
}
static std::map<uint256, Located> Transactions(State& s)
{
    std::map<uint256, Located> out;
    for (auto it = s.blocks.begin(); it != s.blocks.end(); ++it)
    {
        Header h = Decode(Bytes(it->second.begin(),it->second.begin()+80));
        // The height is in the coinbase only on modern networks; use the
        // header index instead of trusting an unvalidated coinbase field.
        std::vector<CTransaction> txs; if (!btcswap::ParseBlockTxs(it->second,txs)) continue;
        int height = s.headers.ActiveHeight(h.hash);
        if (height >= 0)
            for (size_t i = 0; i < txs.size(); ++i) out[txs[i].GetHash()] = Located{txs[i],height};
    }
    return out;
}
static std::vector<Bytes> ActiveScripts(State& s)
{
    auto transactions = Transactions(s);
    std::map<COutPoint,int> spends;
    for (const auto& entry : transactions)
        for (const auto& input : entry.second.tx.vin) spends[input.prevout] = entry.second.height;
    std::vector<Bytes> active;
    for (const auto& script : s.watched)
    {
        bool funded = false, complete = true;
        for (const auto& entry : transactions)
            for (size_t n = 0; n < entry.second.tx.vout.size(); ++n)
            {
                const CScript& output = entry.second.tx.vout[n].scriptPubKey;
                if (Bytes(output.begin(),output.end()) != script) continue;
                funded = true;
                auto spend = spends.find(COutPoint(entry.first,(unsigned int)n));
                if (spend == spends.end() || s.headers.Tip().height-spend->second+1 < 6) complete = false;
            }
        // Retain the watch record for reorg recovery, but do not query filters
        // for contracts whose spends have six confirmations on the active chain.
        if (!funded || !complete) active.push_back(script);
    }
    return active;
}

json Find(const btcswap::Chain& chain, const CScript& contract, const std::string& ref, bool secret)
{
    Watch(chain, contract); State& s = StateOf(chain); std::lock_guard<std::recursive_mutex> lock(s.mutex);
    if (!s.error.empty()) throw std::runtime_error(s.error);
    if (!s.synced || s.scan < s.headers.Tip().height+1)
        throw std::runtime_error(s.net.label+(s.net.filters ? " light is synchronizing headers and contract filters" : " light is synchronizing headers and scanning blocks"));
    CScript script; script.SetPayToScriptHash(contract);
    auto txs = Transactions(s); uint256 txid(0); int output = -1;
    size_t colon = ref.find(':');
    if (ref.empty() || ref == ":-1")
    {
        for (auto it = txs.begin(); it != txs.end(); ++it)
            for (size_t n = 0; n < it->second.tx.vout.size(); ++n)
                if (it->second.tx.vout[n].scriptPubKey == script)
                { if (output >= 0) throw std::runtime_error("multiple payments; specify txid:vout"); txid = it->first; output = (int)n; }
    }
    else if (colon == 64 && ref.size() > 65 && ref.size() <= 72 && ref.find_first_not_of("0123456789",65) == std::string::npos && IsHex(ref.substr(0,64)))
    { txid = uint256(ref.substr(0,64)); output = atoi(ref.c_str()+65); }
    else if (ref.size() == 64 && IsHex(ref)) txid = uint256(ref);
    else
    {
        CTransaction tx; if (!IsHex(ref) || !btcswap::ParseTx(ParseHex(ref),tx)) throw std::runtime_error("invalid "+s.net.label+" contract reference"); txid = tx.GetHash();
    }
    auto funding = txs.find(txid);
    if (funding != txs.end() && output < 0)
        for (size_t n = 0; n < funding->second.tx.vout.size(); ++n) if (funding->second.tx.vout[n].scriptPubKey == script) { output = (int)n; break; }
    json j = {{"contractTxid",txid.GetHex()},{"vout",output},{"unspent",false},{"confirmations",0},{"amount",nullptr},{"spent",false},{"found",false}};
    if (funding == txs.end() || output < 0) return j;
    if ((size_t)output >= funding->second.tx.vout.size() || funding->second.tx.vout[output].scriptPubKey != script) throw std::runtime_error(s.net.label+" output does not pay this contract");
    j["confirmations"] = s.headers.Tip().height-funding->second.height+1; j["unspent"] = true;
    j["amount"] = (double)funding->second.tx.vout[output].nValue/COIN;
    COutPoint prev(txid,(unsigned int)output); swap::Contract c; swap::ParseContract(contract,c);
    for (auto it = txs.begin(); it != txs.end(); ++it)
        for (size_t k = 0; k < it->second.tx.vin.size(); ++k) if (it->second.tx.vin[k].prevout == prev)
        {
            j["spent"] = true; j["unspent"] = false; j["amount"] = nullptr; j["found"] = true;
            j["txid"] = it->first.GetHex(); j["height"] = it->second.height;
            if (secret)
            {
                Bytes value;
                if (swap::ExtractSecret(it->second.tx.vin[k].scriptSig,c.secretHash,value)) j["secret"] = Hex(value);
                else j["refunded"] = true;
            }
            return j;
        }
    return j;
}
bool Call(const btcswap::Chain& chain, const std::string& method, const json& params, json& result, std::string& err)
{
    try
    {
        State& s = StateOf(chain); std::lock_guard<std::recursive_mutex> lock(s.mutex);
        if (method == "getblockchaininfo")
        {
            result = {{"chain",s.headers.network},{"blocks",s.headers.Tip().height},{"mediantime",s.headers.Median(s.headers.Tip())},
                      {"initialblockdownload",!s.synced},{"backend","light"},{"filters",s.filters.size()},{"scanned",s.scan},{"filterPeers",s.peersCompared},{"networkError",s.error}};
            if (!s.net.filters) { result.erase("filters"); result.erase("filterPeers"); result["startHeight"] = s.headers.Base(); result["watched"] = s.watched.size(); }
            return true;
        }
        if (method == "sendrawtransaction")
        {
            Bytes raw = ParseHex(params.at(0).get<std::string>()); CTransaction tx;
            if (!btcswap::ParseTx(raw,tx)) throw std::runtime_error("invalid "+s.net.label+" transaction");
            s.pending[tx.GetHash()] = raw; Save(s); result = tx.GetHash().GetHex(); return true;
        }
        if (method == "getrawtransaction" || method == "gettransaction")
        {
            auto txs = Transactions(s); auto it = txs.find(uint256(params.at(0).get<std::string>()));
            if (it == txs.end()) throw std::runtime_error(s.net.label+" transaction not found by contract filters");
            CDataStream stream(SER_NETWORK); stream << it->second.tx;
            result = HexStr(stream.begin(),stream.end(),false); if (method == "gettransaction") result = json{{"hex",result}};
            return true;
        }
        throw std::runtime_error(s.net.label+" light has no wallet RPC: "+method);
    }
    catch (const std::exception& e) { err = e.what(); return false; }
}

#undef printf
int SelfTest()
{
    setbuf(stdout, NULL);
    printf("btc-light self-test\n");
    int failures = 0;
    auto check = [&](bool ok, const char* what) { printf("  %s %s\n",ok ? "PASS" : "FAIL",what); if (!ok) ++failures; };
    Headers main("main"), test("testnet4"), reg("regtest");
    check(main.Tip().hash.GetHex() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f","main checkpoint hash");
    check(test.Tip().hash.GetHex() == "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043","testnet4 checkpoint hash");
    check(reg.Tip().hash.GetHex() == "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","regtest genesis hash");
    check(Retarget(0x1d00ffff,1262152739LL-1261130161LL,0x1d00ffff) == 0x1d00d86a,"historical mainnet retarget at height 32256");
    check(Retarget(0x1c0ffff0,1209600,0x1d00ffff) == 0x1c0ffff0,"unchanged retarget");
    check(Retarget(0x1c0ffff0,1,0x1d00ffff) == Retarget(0x1c0ffff0,302400,0x1d00ffff),"retarget lower clamp");
    check(Retarget(0x1c0ffff0,9000000,0x1d00ffff) == Retarget(0x1c0ffff0,4838400,0x1d00ffff),"retarget upper clamp");
    check(Retarget(0x1d00ffff,4838400,0x1d00ffff) == 0x1d00ffff,"retarget proof of work limit");
    std::string err;
    auto mine = [&](const Header& parent, unsigned int time, unsigned int tag) {
        Bytes b; Put(b,1,4); HashBytes(b,parent.hash); HashBytes(b,uint256(tag)); Put(b,time,4); Put(b,0x207fffff,4); Put(b,0,4);
        for (unsigned int nonce = 0;; ++nonce) { for (int i = 0; i < 4; ++i) b[76+i] = (unsigned char)(nonce>>(8*i)); if (Number(Digest(b)) <= Target(0x207fffff)) return b; }
    };
    Header genesis = reg.Tip(); Bytes a = mine(genesis,genesis.time+1,1);
    check(reg.Add(a,err) && reg.Tip().height == 1,"valid header and proof of work"); Header first = reg.Tip();
    Bytes bad = mine(first,genesis.time,2); check(!reg.Add(bad,err),"reject timestamp at/below median");
    bad = mine(first,first.time+1,3); bad[72] = 0; check(!reg.Add(bad,err),"reject wrong difficulty/proof of work");
    Bytes fork = mine(genesis,genesis.time+2,4); check(reg.Add(fork,err) && reg.Tip().hash == first.hash,"equal-work fork does not replace active chain");
    Header forkHeader = Decode(fork); Bytes fork2 = mine(forkHeader,genesis.time+3,5);
    check(reg.Add(fork2,err) && reg.Tip().height == 2 && reg.At(1).hash == forkHeader.hash,"greater-work reorg replaces disconnected branch");
    std::vector<Bytes> scripts = {Bytes{0x51},Bytes{0xa9,0x14,1,2,3,0x87},Bytes{0x51}};
    Bytes pubkeyScript = ParseHex("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac");
    uint256 vectorBlock("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");
    check(Hex(EncodeFilter(vectorBlock,std::vector<Bytes>{pubkeyScript})) == "019dfca8", "BIP158 published testnet genesis encoding vector");
    check(Joined(Digest(ParseHex("019dfca8")),uint256(0)).GetHex() == "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750", "BIP157 published filter header vector");
    Bytes filter = EncodeFilter(main.Tip().hash,scripts); bool match = false;
    check(MatchFilter(main.Tip().hash,filter,scripts,match) && match,"basic filter encoding, deduplication and match");
    check(MatchFilter(main.Tip().hash,filter,std::vector<Bytes>{Bytes{99,98,97}},match) && !match,"basic filter nonmatch");
    check(EncodeFilter(main.Tip().hash,std::vector<Bytes>{Bytes(),Bytes{OP_RETURN,1}}) == Bytes{0},"basic filter excludes empty and OP_RETURN outputs");
    check(EncodeFilter(main.Tip().hash,std::vector<Bytes>()) == Bytes{0} && MatchFilter(main.Tip().hash,Bytes{0},scripts,match) && !match,"empty filter");
    filter.pop_back(); check(!MatchFilter(main.Tip().hash,filter,scripts,match),"reject truncated filter");
    check(!MatchFilter(main.Tip().hash,Bytes{253,0,0},scripts,match),"reject noncanonical filter count");
    btcswap::Chain chain; chain.name = "main"; chain.fMain = true; CScript dest;
    check(Destination(chain,"1111111111111111111114oLvT2",dest,err) && dest.size() == 25,"legacy destination");
    check(Destination(chain,"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",dest,err) && dest.size() == 23,"P2SH destination");
    check(Destination(chain,"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",dest,err) && Hex(Bytes(dest.begin(),dest.end())) == "0014751e76e8199196d454941c45d1b3a323f1433bd6","BIP350 witness v0 destination vector");
    check(Destination(chain,"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",dest,err) && Hex(Bytes(dest.begin(),dest.end())) == "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","BIP350 taproot destination vector");
    check(!Destination(chain,"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",dest,err),"reject Bech32 checksum for taproot");
    check(!Destination(chain,"bc1invalid",dest,err),"reject malformed witness destination");
    CTransaction funding;
    funding.vin.resize(1); funding.vout.push_back(CTxOut(100000,CScript()<<OP_TRUE));
    CDataStream stream(SER_NETWORK); stream << funding;
    Bytes rawBlock = mine(reg.Tip(),reg.Tip().time+1,6);
    uint256 merkle = funding.GetHash(); std::copy(merkle.begin(),merkle.end(),rawBlock.begin()+36);
    Header blockHeader = Decode(rawBlock);
    Compact(rawBlock,1); rawBlock.insert(rawBlock.end(),stream.begin(),stream.end());
    std::vector<CTransaction> blockTxs;
    check(VerifyBlock(rawBlock,blockHeader,blockTxs) && blockTxs.size() == 1,"verify matched block merkle root");
    rawBlock.back() ^= 1;
    check(!VerifyBlock(rawBlock,blockHeader,blockTxs),"reject matched block with tampered transaction");
    check(reg.ActiveHeight(first.hash) == -1 && reg.ActiveHeight(forkHeader.hash) == 1,"disconnected branch cannot prove payments");
    Header cursor = reg.Tip();
    for (int i = 0; i < 12; ++i)
    {
        Bytes h = mine(cursor,cursor.time+1,20+i); reg.Add(h,err); cursor = reg.Tip();
    }
    check(reg.Median(reg.Tip()) == reg.Tip().time-5,"median time uses the preceding eleven headers");
    try
    {
        // Exercise the same disk format and validation used at startup. The
        // build runner sets TEMP inside the project, as for the wallet tests.
        const char* temporary = getenv("TEMP");
        unsigned char nonce[8]; randombytes_buf(nonce,sizeof(nonce));
        std::string prefix = std::string(temporary ? temporary : ".")+"/btc-light-selftest-"+Hex(Bytes(nonce,nonce+8));
        State saved("regtest"); saved.path = prefix;
        for (const auto& raw : std::vector<Bytes>{a,fork,fork2})
        {
            if (!saved.headers.Add(raw,err)) throw std::runtime_error(err);
            AppendHeader(saved,raw);
        }
        rawBlock.back() ^= 1;
        Bytes header(rawBlock.begin(),rawBlock.begin()+80);
        for (uint32_t nonce = 0;; ++nonce)
        {
            for (int i = 0; i < 4; ++i) header[76+i] = (unsigned char)(nonce>>(8*i));
            if (Number(Digest(header)) <= Target(0x207fffff)) break;
        }
        std::copy(header.begin(),header.end(),rawBlock.begin());
        if (!saved.headers.Add(header,err)) throw std::runtime_error(err);
        AppendHeader(saved,header);
        saved.blocks[Digest(header)] = rawBlock;
        saved.pending[funding.GetHash()] = Bytes(stream.begin(),stream.end());
        CScript watched; watched.SetPayToScriptHash(CScript()<<OP_TRUE);
        saved.watched.insert(Bytes(watched.begin(),watched.end()));
        uint256 previous(0);
        for (int h = 0; h <= saved.headers.Tip().height; ++h)
        {
            FilterRecord r; r.block = saved.headers.At(h).hash;
            r.hash = Digest(EncodeFilter(r.block,std::vector<Bytes>(saved.watched.begin(),saved.watched.end())));
            r.header = Joined(r.hash,previous); previous = r.header; saved.filters.push_back(r);
        }
        saved.scan = (int)saved.filters.size(); SaveFilters(saved); Save(saved);
        State restored("regtest"); restored.path = prefix; Load(restored);
        check(restored.headers.Tip().hash == saved.headers.Tip().hash && restored.scan == saved.scan && restored.watched == saved.watched && restored.pending.size() == 1 && Transactions(restored).count(funding.GetHash()),"restart revalidates headers, filters, matched block, watch and pending transaction");
        Header side = Decode(a);
        for (int i = 0; i < 3; ++i)
        {
            Bytes raw = mine(side,side.time+1,70+i);
            if (!restored.headers.Add(raw,err)) throw std::runtime_error(err);
            AppendHeader(restored,raw); side = Decode(raw);
        }
        Reconcile(restored); SaveFilters(restored); Save(restored);
        check(restored.filters.size() == 1 && restored.scan == 1 && !Transactions(restored).count(funding.GetHash()) && restored.pending.size() == 1,"reorg rolls back scan/filter headers and makes disconnected funding unusable");
        State again("regtest"); again.path = prefix; Load(again);
        check(again.headers.Tip().hash == restored.headers.Tip().hash && again.filters.size() == 1 && again.pending.size() == 1,"restart after reorg preserves rollback and rebroadcast data");
        std::ofstream broken((prefix+".headers").c_str(),std::ios::binary|std::ios::app); broken.put(1); broken.close();
        bool refused = false;
        try { State corrupt("regtest"); corrupt.path = prefix; Load(corrupt); } catch (...) { refused = true; }
        check(refused,"truncated header store fails closed");
    }
    catch (const std::exception& e)
    {
        printf("  persistence fixture: %s\n",e.what()); check(false,"Bitcoin light persistence fixture");
    }
    printf("btc-light: %d failure(s)\n",failures); return failures ? 1 : 0;
}

int SelfTestLitecoin()
{
    setbuf(stdout, NULL);
    printf("ltc-light self-test\n");
    int failures = 0;
    auto check = [&](bool ok, const char* what) { printf("  %s %s\n",ok ? "PASS" : "FAIL",what); if (!ok) ++failures; };
    std::string err;
    const Net* mainNet = FindNet("ltc","main"); const Net* testNet = FindNet("ltc","test"); const Net* regNet = FindNet("ltc","regtest");
    check(mainNet && testNet && regNet && !FindNet("ltc","testnet4"),"Litecoin networks: main, test, regtest");
    if (!mainNet || !testNet || !regNet) { printf("ltc-light: %d failure(s)\n",failures+1); return 1; }
    // Genesis fields of litecoin v0.21.4 (chainparams.cpp asserts these hashes).
    check(Decode(mainNet->genesis).hash.GetHex() == "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2","main genesis hash");
    check(Decode(testNet->genesis).hash.GetHex() == "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0","test genesis hash");
    check(Decode(regNet->genesis).hash.GetHex() == "530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9","regtest genesis hash");
    check(Number(Scrypt(mainNet->genesis)) <= Target(0x1e0ffff0),"scrypt proof of work of the main genesis");
    // The anchors: linked, at the heights named, each with real scrypt work.
    Headers main(*mainNet), test(*testNet);
    check(main.Tip().height == 3203424 && main.Tip().hash.GetHex() == "fe01c0e62d46266732835006c15bda7ba9a7b5ad97c3f7d6991913d18c00b1fd","main anchor ends at 3203424");
    check(main.Base() == 3203413 && main.At(3203413).hash.GetHex() == "11db30ba112e022643d9078c00b8fd052668595f4bd345dbf5e5b062603b21cd","main anchor starts at 3203413");
    check(test.Tip().height == 5013792 && test.Tip().hash.GetHex() == "670e8f9e180cc5b59f5498e19b1c9895dce4967dd20f4d45b4eb3d171b56772e" &&
          test.At(5013781).hash.GetHex() == "ae2fa4e693f3709990dd4e12cce2d4805434d8a9bc3eb7561ca00ee47a8370f6","test anchor runs 5013781 to 5013792");
    bool work = true;
    for (const Net* n : {mainNet, testNet})
        for (const char* text : n->anchor)
        {
            Bytes raw = ParseHex(text); Header h = Decode(raw);
            if (Number(Scrypt(raw)) > Target(h.bits)) work = false;
        }
    check(work,"every anchor header carries its scrypt proof of work");
    Bytes flipped = ParseHex(mainNet->anchor.back()); flipped[76] ^= 1;
    check(Number(Scrypt(flipped)) > Target(Decode(flipped).bits),"one nonce bit flipped loses the proof of work");
    // Retargets the chains made (heights 3203424 and 5013792).
    check(LitecoinRetarget(0x192ea885,1793227551LL-1792937182LL,0x1e0fffff) == 0x192ccd4e,"main retarget at 3203424 (full period)");
    check(LitecoinRetarget(0x1d03fffc,1793656918LL-1793653639LL,0x1e0fffff) == 0x1d00ffff,"test retarget at 5013792 (clamped)");
    check(LitecoinRetarget(0x1e0fffff,302400*4,0x1e0fffff) == 0x1e0fffff,"retarget capped at the proof-of-work limit");
    check(main.NextBits(main.Tip(),main.Tip().time+150) == main.Tip().bits,"main keeps its bits inside a period");
    check(test.NextBits(test.Tip(),test.Tip().time+301) == 0x1e0fffff,"test: more than two spacings late allows the limit");
    check(test.NextBits(test.Tip(),test.Tip().time+100) == test.Tip().bits,"test: on time keeps the last real bits");
    // A header on the anchor with the right bits and no work is refused.
    Bytes fake; Put(fake,0x20000000,4); HashBytes(fake,main.Tip().hash); HashBytes(fake,uint256(7));
    Put(fake,main.Tip().time+150,4); Put(fake,main.Tip().bits,4); Put(fake,0,4);
    check(!main.Add(fake,err) && err.find("proof of work") != std::string::npos,"header without scrypt work refused");
    Headers reg(*regNet);
    auto mine = [&](const Header& parent, unsigned int time, unsigned int tag) {
        Bytes b; Put(b,0x20000000,4); HashBytes(b,parent.hash); HashBytes(b,uint256(tag)); Put(b,time,4); Put(b,0x207fffff,4); Put(b,0,4);
        for (unsigned int nonce = 0;; ++nonce) { for (int i = 0; i < 4; ++i) b[76+i] = (unsigned char)(nonce>>(8*i)); if (Number(Scrypt(b)) <= Target(0x207fffff)) return b; }
    };
    Bytes a = mine(reg.Tip(),reg.Tip().time+1,1);
    check(reg.Add(a,err) && reg.Tip().height == 1,"regtest header with scrypt work");
    // A nonce whose header hash meets the target and whose scrypt does not.
    Bytes b; Put(b,0x20000000,4); HashBytes(b,reg.Tip().hash); HashBytes(b,uint256(2)); Put(b,reg.Tip().time+1,4); Put(b,0x207fffff,4); Put(b,0,4);
    for (unsigned int nonce = 0;; ++nonce)
    {
        for (int i = 0; i < 4; ++i) b[76+i] = (unsigned char)(nonce>>(8*i));
        if (Number(Digest(b)) <= Target(0x207fffff) && Number(Scrypt(b)) > Target(0x207fffff)) break;
    }
    check(!reg.Add(b,err),"work judged by scrypt, not by the header hash");
    // A reorg: the scan cursor goes back to the fork point, however deep.
    {
        State s(*regNet);
        Header top = s.headers.Tip(); std::vector<Bytes> line;
        for (int i = 0; i < 4; ++i) { Bytes h = mine(top,top.time+1,10+i); s.headers.Add(h,err); top = s.headers.Tip(); line.push_back(h); }
        s.scan = 5; s.scanHash = s.headers.At(4).hash; Reconcile(s);
        check(s.scan == 5,"scan stays where it is on the same branch");
        Header side = s.headers.At(1);
        for (int i = 0; i < 5; ++i) { Bytes h = mine(side,side.time+1,40+i); s.headers.Add(h,err); side = Decode(h); side.height = 2+i; }
        check(s.headers.Tip().height == 6 && s.headers.ForkHeight(Decode(line[3]).hash) == 1,"fork height of a block on a dead branch");
        Reconcile(s);
        check(s.scan == 2 && s.scanHash == s.headers.At(1).hash,"reorg sends the scan back to the fork point");
    }
    // The store: a later anchor drops what no longer connects, and the stored
    // chain is read without scrypt, every other rule still applied.
    {
        const char* temporary = getenv("TEMP");
        unsigned char nonce[8]; randombytes_buf(nonce,sizeof(nonce));
        std::string prefix = std::string(temporary ? temporary : ".")+"/ltc-light-selftest-"+Hex(Bytes(nonce,nonce+8));
        State s(*regNet); s.path = prefix;
        Header top = s.headers.Tip();
        for (int i = 0; i < 3; ++i) { Bytes h = mine(top,top.time+1,60+i); s.headers.Add(h,err); AppendHeader(s,h); top = s.headers.Tip(); }
        State again(*regNet); again.path = prefix; Load(again);
        check(again.headers.Tip().hash == top.hash,"stored headers read back");
        Net later = *mainNet; later.anchor.assign(mainNet->anchor.end()-1,mainNet->anchor.end());
        State moved(later); moved.path = prefix; Load(moved);
        check(moved.headers.Tip().height == 3203424 && moved.headers.Base() == 3203424,"headers from before a later anchor are skipped, not fatal");
    }
    btcswap::Chain chain; chain.coin = "ltc"; chain.name = "main"; chain.fMain = true; chain.pkhVersion = 48; chain.shVersion = 50; CScript dest;
    check(Destination(chain,"LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",dest,err) && dest.size() == 25,"Litecoin key address (L...)");
    check(Destination(chain,"MJaRnao1s62a2zAKSkmG582KbLKianqb7v",dest,err) && dest.size() == 23,"Litecoin script address (M...)");
    check(Destination(chain,"3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw",dest,err) && dest.size() == 23,"Litecoin legacy script address (3...)");
    check(Destination(chain,"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",dest,err) && Hex(Bytes(dest.begin(),dest.end())) == "0014751e76e8199196d454941c45d1b3a323f1433bd6","Litecoin witness v0 address (ltc1)");
    check(!Destination(chain,"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",dest,err),"a Bitcoin address is not a Litecoin destination");
    check(!Destination(chain,"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",dest,err),"a test network address is not a main one");
    check(btcswap::PkhToAddress(chain,ParseHex("751e76e8199196d454941c45d1b3a323f1433bd6")) == "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ","contract key address for Litecoin");
    printf("ltc-light: %d failure(s)\n",failures); return failures ? 1 : 0;
}
} // namespace btclight
