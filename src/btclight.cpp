// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "btclight.h"
#include "dgb_anchors.h"
#include "dgb_pow.h"
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
// aserti3-2d lowers the difficulty for a chain that claims time has passed,
// and DigiShield eases by half a step on each block that claims a long gap,
// so past the anchor a private fork need pay little more than one real block
// and then almost nothing. It has to show a sixteenth of the work the real chain did since:
// a quarter of the blocks at a quarter of the anchor's difficulty, room for
// the chain's own slumps and a price no peer pays for one swap.
Integer AnchorWorkFloor(const Net& net, const Header& anchor, int64 now)
{
    int64 blocks = std::max<int64>(0, now-(int64)anchor.time)/net.spacing;
    return anchor.work+(Integer(1)<<256)/(Target(anchor.bits)+1)*blocks/16;
}
// DigiByte's MultiShield eases too, up to 16% a block for a chain that claims
// time has passed. Each block's work is on its own scale: the anchor's last.
Integer DgbWorkFloor(const Net& net, const Headers& headers, int64 now)
{
    const Header& anchor = headers.At(net.anchorHeight);
    int64 blocks = std::max<int64>(0, now-(int64)anchor.time)/net.spacing;
    return anchor.work+(anchor.work-headers.At(net.anchorHeight-1).work)*blocks/16;
}
// Peers that still send "reject" (Dogecoin Core 1.14) send it for a broadcast
// too, a replaced spend or one under their fee. That answers no request of
// ours: the transaction goes on waiting and the blocks still have to be read.
bool RefusesTx(const Bytes& reject)
{
    return reject.size() >= 3 && reject[0] == 2 && reject[1] == 't' && reject[2] == 'x';
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
// Dogecoin's DigiShield (v1.14.9, src/dogecoin.cpp): a retarget every block,
// on the last block's time, an eighth of the way and within a band.
unsigned int DigiShield(unsigned int bits, int64 elapsed, unsigned int limit)
{
    const int64 timespan = 60;
    int64 modulated = timespan+(elapsed-timespan)/8;
    modulated = std::max<int64>(timespan-timespan/4, std::min<int64>(timespan+timespan/2, modulated));
    Integer n = Target(bits)*modulated/timespan, cap = Target(limit);
    return Bits(n > cap ? cap : n);
}
static uint256 ClimbBranch(uint256 hash, const std::vector<uint256>& branch, int index)
{
    if (index == -1) return uint256(0);
    for (size_t i = 0; i < branch.size(); ++i, index >>= 1)
        hash = (index&1) ? Joined(branch[i],hash) : Joined(hash,branch[i]);
    return hash;
}
// CAuxPow::check (dogecoin v1.14.9, src/auxpow.cpp): the block's hash is in a
// chain merkle tree whose root sits in the coinbase of a parent block, so the
// parent's proof of work is paid for this block too.
bool CheckAuxPow(const btcswap::AuxPow& aux, const uint256& block, int chainId, bool strict, std::string& err)
{
    err = "AuxPoW is not valid";
    if (aux.nIndex != 0 || aux.chainBranch.size() > 30 || aux.parent.size() != 80 || aux.tx.vin.empty()) return false;
    if (strict && (int)((uint32_t)LE(aux.parent,0,4) >> 16) == chainId) return false;
    uint256 rootHash = ClimbBranch(block,aux.chainBranch,aux.nChainIndex);
    Bytes root(rootHash.begin(),rootHash.end()); std::reverse(root.begin(),root.end());
    if (ClimbBranch(aux.tx.GetHash(),aux.branch,aux.nIndex) != ReadHash(aux.parent,36)) return false;
    const CScript& script = aux.tx.vin[0].scriptSig;
    const Bytes code(script.begin(),script.end());
    static const unsigned char head[4] = {0xfa,0xbe,0x6d,0x6d};
    Bytes::const_iterator headAt = std::search(code.begin(),code.end(),head,head+4);
    Bytes::const_iterator rootAt = std::search(code.begin(),code.end(),root.begin(),root.end());
    if (rootAt == code.end()) return false;
    if (headAt != code.end())
    {
        if (std::search(headAt+1,code.end(),head,head+4) != code.end() || headAt+4 != rootAt) return false;
    }
    else if (rootAt-code.begin() > 20) return false;
    size_t after = (rootAt-code.begin())+root.size();
    if (code.size()-after < 8) return false;
    uint32_t size = (uint32_t)LE(code,after,4), nonce = (uint32_t)LE(code,after+4,4);
    unsigned int height = (unsigned int)aux.chainBranch.size();
    if (size != (1u<<height)) return false;
    uint32_t slot = nonce*1103515245u+12345u; slot += (uint32_t)chainId; slot = slot*1103515245u+12345u;
    if (aux.nChainIndex != (int)(slot%(1u<<height))) return false;
    err.clear(); return true;
}
// aserti3-2d (bitcoin-cash-node v29.2.0, src/pow.cpp, CalculateASERT): the
// anchor's target, doubled for each half-life the chain is behind its ideal
// schedule. The exponent's division truncates and its shift floors, as there.
unsigned int Asert(unsigned int anchorBits, int64 timeDiff, int64 heightDiff, int64 spacing, int64 halfLife, unsigned int limit)
{
    const int64 exponent = ((timeDiff-spacing*(heightDiff+1))*65536)/halfLife;
    int64 shifts = exponent >> 16;
    const uint64_t frac = (uint16_t)exponent;
    const uint64_t factor = 65536+((195766423245049ULL*frac+971821376ULL*frac*frac+5127ULL*frac*frac*frac+(1ULL<<47)) >> 48);
    Integer n = Target(anchorBits)*factor, cap = Target(limit);
    shifts -= 16;
    if (shifts <= 0) n >>= (unsigned int)-shifts; else n <<= (unsigned int)shifts;
    if (n == 0) n = 1;
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
// Bitcoin Cash Node v29.2.0 and Bitcoin ABC v0.34.3 start the same way: a run
// of real headers, read from the chains' own peers on 2026-11-04. Every
// header from the chain's ASERT anchor to these was checked by a second
// implementation of aserti3-2d (0 mismatches on the four networks), and the
// mainnet hashes against two explorers.
static const int BCH_MAIN_ANCHOR_HEIGHT = 970331;
static const char* BCH_MAIN_ANCHOR[] = {
    "00407521fc3e4a9eb87792eee29024d53fddabd1e0e59473fb0ddc6cb90900000000000000b5029f793f1db3677481bb12b65db6f2bf4f76177f4f28da21652bad14b2271e36eb6a6d92161a95044521",
    "00e016207e525a8b181b91189ceb2d41bea36e4519faccf84542cfb8040300000000000070a52e336120b98edde4782d23815d8d8037266055d23abb99a4b1e5a66256d46e36eb6a3f89161acc853048",
    "002060254f94c4321ca2ebb68fe6e86221ffbbc6fc93518e332475714213000000000000173915f45596999ff1e33ca5bd20b0a10a05894bcae2acd69ccd1d020b5c69eb2039eb6a427d161a81800e7d",
    "00a0aa206debb9230e06cfe53116ec5125e66f0dd7543d85bbf8b89cf50f000000000000250d1c385c21d9f2f97ab5635df4ef468c308ab357babd1d1b3914db797244a36b39eb6a627f161ae6840bfc",
    "00201d25c2f6146756f7203a9cf64eb69c0a2180b7e283e562bd9d246b100000000000002994d492ba20a793a15321fc6f63ab7d3ae372a82a13b491c600bbaf5728d134053beb6a3e73161a0c00f4d4",
    "0000c621a209845f69a22b835b63e8bb0d87ffac9d6793688a324c97c71200000000000090005dc365c14afde64cbb9ac795f6af2687579b48ff47e1c9afc84274b3b2bf283beb6aeb6e161a660474a5",
    "004033232a9f2990ba9b9656b717256cb933b862ab2c255f29b2df40ba0e000000000000f0c43df49ebbf8e7536c2ffa3276ed0e8a46c97dcc717c66eb8b88493efa0e2c823beb6af261161a69823808",
    "00a01d25b96c157d198b0ca1953f17c0f96e970ee735462bfd017e87dc10000000000000f0de870b522a5aec5aeca3c46348d21db9c63222847f39a6d6ef3f9d9364b5b4e33eeb6a3056161af3837f99",
    "0020a22233943939f1d45ae273d551e983bc2dc083b1012bbf68f90649110000000000006efb1ef4101ab3c19a7454ab3236d69213c196bbb1b79fe58d00f0abcb52dc8a134beb6a555c161aab05818e",
    "00205a235f3b8cde3e535f0c95879f78b9b0d512f03c94a178d64e7dae0a0000000000005ff10fae229716341dab3a18cde44dc53cf690e3a68598ebe433c8ce5ade983f164deb6a5f96161ad681f562",
    "00e0742194fd383eeca6a439f6ab7065b8db5d9b9c74a82c6d3d4ee2a3100000000000006b2977767e501da261a3babd0e77a22788b01d392ae9302c7df4c63c2248905cab4eeb6a6694161a888076d1",
    "0040c421ab6a0d22edd82d3b20083702701f4876fe4cb6c43688c1f6d70f0000000000006c670d599d1efc05335cb167b5b32a9f7f866fefec9cd1f757e4dee9774147ac9b4feb6ad88f161a98824c82",
};
static const int BCH_TEST_ANCHOR_HEIGHT = 330867;
static const char* BCH_TEST_ANCHOR[] = {
    "004029217b8ed791e1d771622ac59f2127ae887e1152a725eb2dd9987f60000000000000a188eb88435bcd009f6cc394d50c9ce0d8ca2cc86422ef88744000559d7b61e03e3feb6affff001d420054aa",
    "004024255d0966fafe1f54eb40b81525baaa7ead21791b07463858cae8542600000000000761b9da447ce7c292bfe8f76361448c35f42e375db928222b022378d1b49e8deb42eb6a5403011b7c021750",
    "0060bf3196baa3a61d9964cdff1d0273d1fe5afe327c218c9a1e79251bac000000000000e14a6c4757f018555452c4d1954af35ea358ba736331d1a22166b0b9b053508dee44eb6af214011b64007fb2",
    "0060e32577d45cf73f94c1c281db71f43861aef9a26a15870dd22866eda600000000000004fe9b9892b35ddb2de99976b49de1d62b8e43d23eacea23fbd4f4f4e7072dc8f444eb6a7310011bde013a5e",
    "0000c7242cc0ef6df6901322f7898767b794c58a637cfa2d06b225f9c3b4000000000000d87be52217e79c8fed61fe1611d272ba7b845e807c6f1a706f34dd7acefe1af9e845eb6a01f3001b9e002da4",
    "0060b120d73b7cdf504526fed007640ecc128e16f8c170bdb8137c664bd80000000000006ae9a08cd2f5eab742068fed812ae1cd3bc8236b76f08fc1e27cc86e1d53fc980448eb6ae8e2001b0000f96e",
    "00802b219ff68b1f6ecf8aa7b5d1ba33238a36389581516e419833235766000000000000cfef65f0253ae9feeb4846301dc0f67e6656daafe1686941fa9d1510e10b54006c49eb6a4de0001b60001c7e",
    "006072229e94ee8af4ab835c66deafa5a1960293ce36389a87012d0a9218000000000000f54f393be037476483cb2b09e2668b203905c78a926549ebeea834d419031489324ceb6a2ad6001bc002705f",
    "00a02a2aa562e996b50313e4d3656e249f7f62da67499b6e9f19cceb4dbf000000000000565bada2f70f8c1ee786c9b00c79caee0a0a62cd6a95f55525deb62589c62b7bec4feb6ac0da001b6401191b",
    "00c023212db03e1152dff5bc55e85b3de7a3ae0d1e65617c977123f8283a0000000000009cf4e8d0c12dcfdb6cf1088e8fb88d282bcd5fa7d8a33940f7aef63ba75a62eab851eb6a30ea001b060171bd",
    "00a00a2ad02e941c18b5aa3575ee10729f6d92508b2b1127a9edcdf14a4f000000000000d493a49f912ddea92d266b65067a170513f6bf0be887c92778d701961e421b227856eb6affff001dde00400f",
    "00a031237cf82772b80750c740d6be79dd59a25b8d3ec55cc8e52114a02000000000000046dce700dc27276991487f68a0fa92aba4359ed0daab57fb414ad0eabb23a0d8c357eb6aa300011bb600a906",
};
static const int XEC_MAIN_ANCHOR_HEIGHT = 974096;
static const char* XEC_MAIN_ANCHOR[] = {
    "0000b42db33ec8e4e6fc906f2383d3474496c703450fa27e61cdf09a00000000000000009f443c713a4d49dd9e3b40e8af1fa00db638b9f1edb1626a551e214163951381ab4ceb6a81af0019b8c6d75f",
    "00c0f124d71b42637f45a953dab8687571c6c485667d616d1b0ede75000000000000000089fa46931e7f28c1632ab9bf9f4cef318d60225559aa2c87e9b1b4e85af527a65c4feb6a6daf00191ef94125",
    "000004204c034cf4e24d64a3274fa156d8d975ed401f03048f7e2319000000000000000010018a68887ccd3567331066db6c3ee68554035ad83bba28578b6c70bcdae4090250eb6a7caf00199e066244",
    "00a00020e73e4ffbf9d948b6a6409d5533affaee136c79f60928937e0000000000000000973a5570ead554e41550ec23f2f9591538ef3b6c70290f3326af32d7149fe846af53eb6a2eaf00196666d7b3",
    "00206b256f9dd408f0cf5065d3890e339e6ae71e030a9eb32dd7d36e0000000000000000384a28d5a746612f3535576347ccc427a4b487333984700e87c754bcb09f934d2c54eb6a6baf00194ac08f11",
    "00005a27904f1183c53509e475de4d0bed226c3b48f2758e6b0f1c1d000000000000000080b942225fbad37d63a7eb7df54cdaf4d520ca5b4181c8456d45bc6563ede4759a55eb6a16af00194128ea31",
    "00202c24f504d3496682b2bad6fe33e5bbba292e576c6e028db05bad00000000000000005c7474e649d82ec89baf59b80ae9b8edd70999cf9955b9e5682940d72101882d5956eb6aedae0019baad845f",
    "0020072040f1cba55d10402a8136d649d71c79bfdf4f14c623d03f100000000000000000916cff87211fe11bcfff8cba78f32a28701b0a116cd92bafc51b683b4f55a3cda557eb6aa3ae0019b90d01af",
    "00c05c202a1bfbbc6da63dde41ffd1960795daeda7f9ac1535b83b7f0000000000000000579555cb77f8b13eec7f00d7faad4621384f93da2e455b3200ce1ad64f8ccdf0de57eb6a73ae001915a5c55e",
    "0020f923b2928908683b6095ce6171d91cda61606978d4c18a1415a30000000000000000c27cb03a914ea98e2993777b7d221cd6bafe226a0ba8d3eec10d500c3edbf75c665beb6a12ae00197456af91",
    "00200320c27c2a38436ddbc9fc5734bc6fc273cc3652e573ac6c5d250000000000000000fbc5dbce40ecb0bdfbf282ffde42fe686badc23bee994dca74bb146ee41286578b5eeb6a48ae00195563ea40",
    "00c08436833aec5d532df796db3e8da81115cd1f744a14c2ab1dc9ac0000000000000000157d1448ba3b3856914d151a44f8c5a9c104ad8d8c25ca2c58cc935f2a54d5f42b60eb6a6dae00191839039e",
};
static const int XEC_TEST_ANCHOR_HEIGHT = 1738711;
static const char* XEC_TEST_ANCHOR[] = {
    "00000020f000c47a6a7fa73098d5d9bd2fdd750eaea60cb23c2be258150908000000000073aad7dbaa944b7aa25d19625efdb5fd15b58e54c8b2483e97366a8af8140593333aeb6a5896171b09b1a6cf",
    "000000209dd93b344c270548d86ab4070fef0a89a72f6a8a8dd471c4f1db07000000000092d8b3ada4dbfb4a4e1a72919c369d08ad90f81d61c3b90ef8df4671789649dc3e3eeb6ab89a171b0d006fb2",
    "00000020edcee752fe71379f50c2f3d7b8bbc9e4ac1ba83ee71dc7d936d61100000000007e3b52ab199c9ccde2d5124512d874fcbb1c4a42dbcee56bccddbbda8a33d87df442eb6affff001dab955fa2",
    "000000201631c21138d715ff376bec651bd4cc77667bdf396342c0dd230c170b0000000028052175895dd427f9ed05a51b4de4229ce3442b9c7525f93f0536c9d5308152bd45eb6af8b3171b2a0b1120",
    "0000002030ff5ccf5d7a52b6e82c457f7aa34be76d47a937796a3d7da12e0700000000003ef50d79f21f7f31d6bc5a16f9121c657ac9c9dbecc63778b6879a3af1db5019234aeb6ab8b6171b980f3f4e",
    "00000020538661e0da99bc2078787f24c82f9f1113d405d37b18628bfbdf1400000000009dc4e8a4c2837c0bc7ac542c7d48d31456696aa240227a03a2ab199bde7dceb0e34eeb6affff001db3d41945",
    "000000208b164f1efe2c00180406ab5c10173e92c4f9f7edc6b8e1b1ceb92d0300000000991353b3432885f2295262018a1deb11ff18e1091fd786446afa4ce05ad3163e884feb6aa8d2171b3c9c456b",
    "00000020bbd913dcd8d3b0bc7b6d370c00e41879ef711011cc29ca2deaec07000000000056a0de138f96e5b93b415d0d5d592fe07b73ab2c04321539bc7333ae918a26f86752eb6af8c7171baa50aaa5",
    "00000020d7f9b7341df48d3693e492ad4c3da82e473e129189b0025dad5c1300000000002d79d28aef6dbb735647c02a519568c5f9fa63eca9648c216be65d08f7afe35fee56eb6a58cb171b8cb2b90b",
    "000000203b059d38cbb1539e5b3839da14b889e27c14b983c1cc9c3a39d90b0000000000ca53873d21956ebf482f835fc7c7780e005fd51b52e817e167687a6c53ecedc2ee57eb6a08d9171b884f48d3",
    "0000002036071c0a0e8820ad08445162a4083f4dc55622fb7a340afedbb50b0000000000ccb9f07d4f3019d2f25d475a67a547f24623a62f3fb5b0eea08518813ba9a4a66559eb6a98d0171b46ce6178",
    "00000020dba2db08ec0a23a6b4c8d573868bc44dc190bc56ba18fde18fae0700000000009fe987574fa40e0179c3f0a03ab6e5b9b45f46329df0feb9491926f60f4440aeb059eb6a18cb171b0b37b60e",
};
static const unsigned int XEC_TEST_ASERT_BITS = 0x1d00ffff;
static const int64 XEC_TEST_ASERT_TIME = 1605445400;
// Dogecoin starts the same way, from dogecoin v1.14.9's rules: twelve real
// headers from the chain's peers, each DigiShield step and AuxPoW since the
// last checkpoint checked by a second implementation, and the main hash
// against two explorers. A merged-mined header's proof is not kept: the
// anchor is a checkpoint, as Litecoin's.
static const int DOGE_MAIN_ANCHOR_HEIGHT = 6445060;
static const char* DOGE_MAIN_ANCHOR[] = {
    "040162003f485b8fdd2a9a67907de787b76c5ff0af99798e6ef564a7783e889812a0d57e48e7ef929220fc0f6d4c4a9d62cc63d308385dc45b3d6771c2270351c1513f95f385ec6a5990461900000000",
    "040162005bf700f27fa036bfe66dda564978be945b1f1fa770ddb95505e55f57e112e1e160a5e9fbd430387fc8182311348dd496f3d80ac81024ee5823ada399f658b61e3886ec6a59904619beba0df0",
    "040162000320cae3249c43b8c4e5039143708c98df01c64157f568b555bb75658c62928f0af35e20238cee2e7aaa2a83d9e914b3ac550771773c861276b4541b204d77fef986ec6a6bbd471900000000",
    "04016200a829921d306bb8019508397a57a2f27fe9913b34ff5d9bcec22594a3120655fb418ee2f61c1a7f2076cdc298a0f3cd79db1e964a7036b576dbf5e93146bded701887ec6adcde5a1900000000",
    "040162005a582324f3ad7dbe8ca7c5a73dac9ea4c60a31f7d6e0b17d0b331e1b1973b626856f8a805f0791f43f2a6c00ecdd120c53005f1ebb4392dec806d6b0488ebbf93387ec6ab753561900000000",
    "04016200932ca87c510ef505294c5d8594a570f9487229658ce232974aabbf80649b876a9c548c224de32b7c7a851a6bfe51e02601006554dc9dd63dede67e25e571dcd54587ec6a6692501900000000",
    "04016200e248d92b49ec86027c4aa5476857bc27cfac321c80540c03a5c3c245d717d11bd28c71c6fb9ea1dc9f4e24a10e9bf1534baae9b299f4f95d90ac970102ca87904f87ec6a88db491900000000",
    "0401620006e64c2b71153f0214c45907e32532a940f7e98d768e0e5dcdd8aee81d4023d20e3338403f17feaf1dd3adddda72c0b87be6d2ca8673547f62b52a59cfaff52c5687ec6ac778421900000000",
    "040162004f8e9711ae94c4db9008d9f938bad85aa5667814546ba2614a8f8ad51bdc1bdd0819512fbd83f5433df27ea4ccd1d267f6f16b5f4aa1927dd196e5ac589d3d096d87ec6a19d33b1900000000",
    "04016200fae1a39019b2855155bfb1c0fd987142ca5bb05a2b75b364d86b17fe1db5c6b274919041df40ccdb01e52c0f65bc94206d37381977b0c85ed39c65e0eeda6f49ce87ec6a17d6371900000000",
    "0401620061d2ff115906ba3862f7ed4a9a42ed04a47337821b35020e5d1a9808d1babb7b1405d1f2c091613c845b2f65968c7b1ce1a64a4654bacb76f81e33a70930fc34ea87ec6a078f3b1900000000",
    "040162000b12bd55ff99fcf2fe3ec492c735a111f4f629c4910d01cfa6b9c2034339aee322718ee2d024df81061723af943f839d93659679775e5c959da5c4761ebff97b1988ec6a8f96371900000000",
};
static const int DOGE_TEST_ANCHOR_HEIGHT = 68043613;
static const char* DOGE_TEST_ANCHOR[] = {
    "04006200db7ad3d79394a31fff098f06e6d751c78453df18f3b6562570a9c4298cd24e95f09d3691116f8c10250142b2a343bcce06b64731e57279d7d01312f0653e981f23bdec6a28230a1e00082124",
    "040062008a071c72b24a4bac3b4108ea57b3bbea784b3c296fa18e4f88b45813405ce6547b70a5187b7fb1e87017d2ec0813051cbbe36e3f500b7d44b617c2fb77146acf58bdec6aeaa40a1ed0d50000",
    "0400620027be1adf3d92e04ba20328d301f38bb7ff8642e97394d39e684114701e854dc27ab9fb4a2bb6af2c6f2cad4a14442091c57f31e2b573117f58ce5909cc28ad4764bdec6aeaa40a1e0003a88f",
    "0400620028657d8c9ce8b29a3519a0f24d9f8a51e21171d0bc8af9635c90be2e57b3dbacc761e8bfd55b0e09c3f5c19c65f2361b122ccdda7d5338e13e6d11650dbc2841f1bdec6affff0f1e80018ca3",
    "04006200175b7f2e88088002c4cae17658b4d847a9d3fa3182e64abe576f818939fdd6bb77a409006db88bd25e0d7d612c1df3997a9f865ecad36870633cab06f49215f7f9bdec6affff0f1e0007e9e4",
    "0400620071648cabeb2d779c74b9461ad2eb8cba79e5fce26c920e310f887761220153b1a0a62567c3c6c6095643f57e084ac6e79f8f77fa7bba9b7afcc217c966e1dd561dbeec6a65660e1e8002e276",
    "04006200335065410dcc0013789ce2cebfccc545c98309861011dff5a43c21c95c5bdb0cbea63067cdfd3c65badd6d7a7f7d4e603da53f23186e81a8af5939a3e7e482b72bbeec6a13ae0d1e000a1954",
    "0400620087d32da16b40c4d9dbd671d41f154a54036605e0b3139a74e0937f48be1cdc1b00d74e20357eef9ad306b7a1d162d9f0458303c552916453ba593b67addbd5045bbeec6a3c8a0c1e80028fc4",
    "0400620015957ed38fff53e6fce950e16a523d6feb0b6cf3a0d8d98e17b4af0b3c640ecd84090c1a208481194c110f6c7b3fd4f9d04daef03841a39d725cac33664dbb5668beec6abb540c1e800416fd",
    "0400620012644ca45f99ab01224f65df168dd19e8154302f19d7c61a90058551231d90387c86b91d375041c57d894adff474207a59a511bb93d8f4b3bbe904d0fdca49a07dbeec6aab4d0b1e80033b05",
    "04006200a0e3cc34d6072dcd7f6f4f0cacf4401ef29b2174714d05fb1b408e8f2227f616b27af2fb2b2c94ee46b98bed7f90ea6f3a59de48afb25906c4f7272aa27a031d8dbeec6ac18c0a1e80048764",
    "0400620023b2f3abce84f31464f8ba171faea6a85b584934625d09c86a977d98f164ca21bc67a16b1e7986b8238d7873b2a6ebd78aa6d129c02fb4fcf8b6a64b0ba93b9aa3beec6ab0ab091e80080bb9",
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
    // The x49 seeds stopped answering in 2026, and few test peers serve
    // filters: these five did on 2026-11-04. Peers they name are kept.
    n.seeds = {"x49.seed.testnet4.bitcoin.sprovoost.nl", "x49.seed.testnet4.wiz.biz", "135.180.99.74:48333", "148.51.196.40:48333",
               "198.206.204.71:48333", "208.68.4.50:48333", "208.68.4.71:48333", "seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"};
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
    // Over Tor these names often do not resolve: five peers that answered on 2026-11-04.
    l.seeds = {"testnet-seed.litecointools.com", "seed-b.litecoin.loshan.co.uk", "dnsseed-testnet.thrasher.io", "81.17.120.243:19335",
               "167.172.77.184:19335", "2.29.40.191:19335", "5.253.84.166:19335", "139.162.112.41:19335"};
    l.pkhVersion = 111; l.shVersion = 58; l.shVersion2 = 196; l.hrp = "tltc"; l.minDifficulty = true;
    l.genesis = GenesisHeader(1, ltcMerkle, 1486949366, 0x1e0ffff0, 293345);
    l.anchorHeight = 5013792; l.anchor.assign(LTC_TEST_ANCHOR, LTC_TEST_ANCHOR + sizeof(LTC_TEST_ANCHOR)/sizeof(LTC_TEST_ANCHOR[0]));
    v.push_back(l);
    l.name = "regtest"; l.magic = 0xdab5bffa; l.port = 19444; l.seeds.clear(); l.hrp = "rltc";
    l.minDifficulty = false; l.regtest = true; l.limitBits = 0x207fffff;
    l.genesis = GenesisHeader(1, ltcMerkle, 1296688602, 0x207fffff, 0);
    l.anchorHeight = 0; l.anchor.clear();
    v.push_back(l);
    Net d;
    const char* dogeMerkle = "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69";
    d.coin = "doge"; d.label = "Dogecoin"; d.timespan = 60; d.spacing = 60; d.scrypt = true; d.digishield = true; d.auxPow = true;
    d.auxChainId = 98; d.limitBits = 0x1e0fffff;
    // No BIP157; a block is up to 1 MB, but a headers message of AuxPoWs is more.
    d.filters = false; d.services = 1; d.blockInv = 2; d.agent = "/Bitflash:doge-light/"; d.maxBlock = 32000000;
    d.name = "main"; d.magic = 0xc0c0c0c0; d.port = 22556; d.strictChainId = true;
    d.seeds = {"seed.multidoge.org", "seed2.multidoge.org"};
    d.pkhVersion = 30; d.shVersion = 22; d.shVersion2 = 22;
    d.genesis = GenesisHeader(1, dogeMerkle, 1386325540, 0x1e0ffff0, 99943);
    d.anchorHeight = DOGE_MAIN_ANCHOR_HEIGHT; d.anchor.assign(DOGE_MAIN_ANCHOR, DOGE_MAIN_ANCHOR + sizeof(DOGE_MAIN_ANCHOR)/sizeof(DOGE_MAIN_ANCHOR[0]));
    v.push_back(d);
    d.name = "test"; d.magic = 0xdcb7c1fc; d.port = 44556; d.strictChainId = false; d.minDifficulty = true;
    // Six peers that answered over Tor on 2026-11-05.
    d.seeds = {"testseed.jrn.me.uk", "107.6.112.101:44556", "135.181.168.83:44556", "185.232.70.226:44556",
               "209.126.12.41:44556", "23.92.177.93:44556", "89.58.9.219:44556"};
    d.pkhVersion = 113; d.shVersion = 196; d.shVersion2 = 196;
    d.genesis = GenesisHeader(1, dogeMerkle, 1391503289, 0x1e0ffff0, 997879);
    d.anchorHeight = DOGE_TEST_ANCHOR_HEIGHT; d.anchor.assign(DOGE_TEST_ANCHOR, DOGE_TEST_ANCHOR + sizeof(DOGE_TEST_ANCHOR)/sizeof(DOGE_TEST_ANCHOR[0]));
    v.push_back(d);
    d.name = "regtest"; d.magic = 0xdab5bffa; d.port = 18444; d.seeds.clear(); d.minDifficulty = false; d.regtest = true; d.strictChainId = true;
    d.pkhVersion = 111; d.limitBits = 0x207fffff;
    d.genesis = GenesisHeader(1, dogeMerkle, 1296688602, 0x207fffff, 2);
    d.anchorHeight = 0; d.anchor.clear();
    v.push_back(d);
    // digibyte v9.26.7, src/kernel/chainparams.cpp. Its peers refuse anything under 70017.
    Net g;
    g.coin = "dgb"; g.label = "DigiByte"; g.multiAlgo = true; g.protocol = 70019; g.timespan = 15; g.spacing = 15;
    g.limitBits = 0x1e0fffff;
    // No BIP157 in a default node: the window's blocks are read.
    g.filters = false; g.services = 1; g.blockInv = 2; g.agent = "/Bitflash:dgb-light/";
    g.name = "main"; g.magic = 0xdab6c3fa; g.port = 12024; g.pkhVersion = 30; g.shVersion = 63; g.shVersion2 = 5; g.hrp = "dgb";
    // Over Tor these names often do not resolve: nine peers that answered on 2026-11-06.
    g.seeds = {"seed.digibyte.io", "seed.diginode.tools", "seed.digibyte.link", "seed.aroundtheblock.app", "seed.tuyul.cc",
               "23.252.125.42:12024", "24.116.234.41:12024", "32.220.187.168:12024", "35.132.227.95:12024", "35.87.253.194:12024",
               "45.229.196.41:12024", "47.243.23.126:12024", "51.159.211.131:12024", "64.182.71.16:12024"};
    g.anchorHeight = DGB_MAIN_ANCHOR_HEIGHT; g.anchor.assign(DGB_MAIN_ANCHOR, DGB_MAIN_ANCHOR + sizeof(DGB_MAIN_ANCHOR)/sizeof(DGB_MAIN_ANCHOR[0]));
    v.push_back(g);
    g.name = "test"; g.magic = 0xe7b9c6fe; g.port = 12033; g.pkhVersion = 126; g.shVersion = 140; g.shVersion2 = 140; g.hrp = "dgbt";
    // The one peer the seeds gave on 2026-11-06.
    g.seeds = {"testnetseed.digibyte.io", "testnetseed.digibyte.link", "64.182.71.16:12033"};
    g.anchorHeight = DGB_TEST_ANCHOR_HEIGHT; g.anchor.assign(DGB_TEST_ANCHOR, DGB_TEST_ANCHOR + sizeof(DGB_TEST_ANCHOR)/sizeof(DGB_TEST_ANCHOR[0]));
    v.push_back(g);
    g.name = "regtest"; g.magic = 0xdab5bffa; g.port = 18444; g.hrp = "dgbrt"; g.regtest = true; g.seeds.clear(); g.limitBits = 0x207fffff;
    g.genesis = GenesisHeader(1, "72ddd9496b004221ed0557358846d9248ecd4c440ebd28ed901efc18757d0fad", 1519460922, 0x207fffff, 4);
    g.anchorHeight = 0; g.anchor.clear();
    v.push_back(g);
    Net c;
    c.coin = "bch"; c.label = "Bitcoin Cash"; c.timespan = 1209600; c.spacing = 600; c.limitBits = 0x1d00ffff;
    c.cashPrefix = "bitcoincash"; c.forkId = true;
    // No BIP157 on Bitcoin Cash Node: payments are found in the window's
    // blocks, whose limit is 32 MB and adapts upward (ABLA).
    c.filters = false; c.services = 1; c.blockInv = 2; c.agent = "/Bitflash:bch-light/"; c.maxBlock = 256000000;
    c.name = "main"; c.magic = 0xe8f3e1e3; c.port = 8333;
    c.seeds = {"seed.flowee.cash", "seed-bch.bitcoinforks.org", "btccash-seeder.bitcoinunlimited.info", "seed.bchd.cash",
               "seed.bch.loping.net", "bchseed.c3-soft.com", "bch.bitjson.com"};
    c.pkhVersion = 0; c.shVersion = 5; c.shVersion2 = 5;
    c.asertHeight = 661647; c.asertBits = 0x1804dafe; c.asertParentTime = 1605447844; c.asertHalfLife = 172800;
    c.genesis = GenesisHeader(1, btcMerkle, 1231006505, 0x1d00ffff, 2083236893);
    c.anchorHeight = BCH_MAIN_ANCHOR_HEIGHT; c.anchor.assign(BCH_MAIN_ANCHOR, BCH_MAIN_ANCHOR + sizeof(BCH_MAIN_ANCHOR)/sizeof(BCH_MAIN_ANCHOR[0]));
    v.push_back(c);
    c.name = "test4"; c.magic = 0xafdab7e2; c.port = 28333; c.cashPrefix = "bchtest"; c.minDifficulty = true;
    c.seeds = {"testnet4-seed-bch.toom.im", "seed.tbch4.loping.net", "testnet4-seed.flowee.cash", "testnet4.bitjson.com",
               "172.105.82.175:28333", "51.222.248.18:28333", "54.38.193.222:28333", "62.210.216.223:28333", "66.175.208.143:28333"};
    c.pkhVersion = 111; c.shVersion = 196; c.shVersion2 = 196;
    c.asertHeight = 16844; c.asertBits = 0x1d00ffff; c.asertParentTime = 1605451779; c.asertHalfLife = 3600;
    c.genesis = GenesisHeader(1, btcMerkle, 1597811185, 0x1d00ffff, 114152193);
    c.anchorHeight = BCH_TEST_ANCHOR_HEIGHT; c.anchor.assign(BCH_TEST_ANCHOR, BCH_TEST_ANCHOR + sizeof(BCH_TEST_ANCHOR)/sizeof(BCH_TEST_ANCHOR[0]));
    v.push_back(c);
    c.name = "regtest"; c.magic = 0xfabfb5da; c.port = 18444; c.seeds.clear(); c.cashPrefix = "bchreg"; c.minDifficulty = false;
    c.regtest = true; c.limitBits = 0x207fffff; c.asertHeight = 0;
    c.genesis = GenesisHeader(1, btcMerkle, 1296688602, 0x207fffff, 2);
    c.anchorHeight = 0; c.anchor.clear();
    v.push_back(c);
    Net x;
    x.coin = "xec"; x.label = "eCash"; x.timespan = 1209600; x.spacing = 600; x.limitBits = 0x1d00ffff;
    x.cashPrefix = "ecash"; x.forkId = true;
    x.filters = false; x.services = 1; x.blockInv = 2; x.agent = "/Bitflash:xec-light/"; x.maxBlock = 256000000;
    x.name = "main"; x.magic = 0xe8f3e1e3; x.port = 8333;
    x.seeds = {"seed.bitcoinabc.org", "seeder.fabien.cash", "seeder.status.cash"};
    x.pkhVersion = 0; x.shVersion = 5; x.shVersion2 = 5;
    // Bitcoin ABC reads the anchor from the chain at axionHeight, the last
    // block before eCash and Bitcoin Cash split, and its half-life is two
    // days on every network.
    x.asertHeight = 661647; x.asertBits = 0x1804dafe; x.asertParentTime = 1605447844; x.asertHalfLife = 172800;
    x.genesis = GenesisHeader(1, btcMerkle, 1231006505, 0x1d00ffff, 2083236893);
    x.anchorHeight = XEC_MAIN_ANCHOR_HEIGHT; x.anchor.assign(XEC_MAIN_ANCHOR, XEC_MAIN_ANCHOR + sizeof(XEC_MAIN_ANCHOR)/sizeof(XEC_MAIN_ANCHOR[0]));
    v.push_back(x);
    x.name = "test"; x.magic = 0xf4f3e5f4; x.port = 18333; x.cashPrefix = "ectest"; x.minDifficulty = true;
    x.seeds = {"testnet-seed.bitcoinabc.org", "testnet-seeder.fabien.cash", "testnet-seeder.status.cash",
               "5.189.141.79:18333", "51.79.81.158:18333"};
    x.pkhVersion = 111; x.shVersion = 196; x.shVersion2 = 196;
    x.asertHeight = 1421481; x.asertBits = XEC_TEST_ASERT_BITS; x.asertParentTime = XEC_TEST_ASERT_TIME;
    x.genesis = GenesisHeader(1, btcMerkle, 1296688602, 0x1d00ffff, 414098458);
    x.anchorHeight = XEC_TEST_ANCHOR_HEIGHT; x.anchor.assign(XEC_TEST_ANCHOR, XEC_TEST_ANCHOR + sizeof(XEC_TEST_ANCHOR)/sizeof(XEC_TEST_ANCHOR[0]));
    v.push_back(x);
    x.name = "regtest"; x.magic = 0xfabfb5da; x.port = 18444; x.seeds.clear(); x.cashPrefix = "ecregtest"; x.minDifficulty = false;
    x.regtest = true; x.limitBits = 0x207fffff; x.asertHeight = 0;
    x.genesis = GenesisHeader(1, btcMerkle, 1296688602, 0x207fffff, 2);
    x.anchorHeight = 0; x.anchor.clear();
    v.push_back(x);
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
    return coin == "ltc" ? "Litecoin" : coin == "doge" ? "Dogecoin" : coin == "dgb" ? "DigiByte" : coin == "bch" ? "Bitcoin Cash" : coin == "xec" ? "eCash" : "Bitcoin";
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
// What dgbpow needs of a network (CMainParams, CTestNetParams, CRegTestParams).
static dgbpow::Params DgbParams(const Net& net)
{
    dgbpow::Params p;
    if (net.name != "main") { p.checkpoint = 0; p.odoInterval = 24*60*60; p.maxTimespan = 810; }
    return p;
}
// The parents one header's retarget and work read, oldest first: 61, and on
// back to the latest block of each of the five algorithms.
static std::vector<dgbpow::PastBlock> DgbParents(const std::map<uint256, Header>& nodes, const Header& parent, int base)
{
    std::vector<dgbpow::PastBlock> out;
    std::set<int> seen;
    const Header* h = &parent;
    for (size_t i = 0; i < 2000; ++i)
    {
        dgbpow::Header parsed; std::copy(h->raw.begin(), h->raw.end(), parsed.raw.begin());
        dgbpow::PastBlock past; past.height = h->height; past.time = h->time; past.bits = h->bits; past.algo = dgbpow::Algorithm(parsed);
        out.push_back(past); seen.insert((int)past.algo);
        if ((out.size() >= 61 && seen.size() >= 5) || h->height <= base) break;
        h = &nodes.at(h->prev);
    }
    std::reverse(out.begin(), out.end());
    return out;
}
static Integer DgbWork(const lightpow::Hash& work)
{
    Integer n = 0;
    for (size_t i = work.size(); i > 0; --i) n = (n<<8)|work[i-1];
    return n;
}
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
        // The anchor's end carries DigiByte's own measure: the work floor reads it.
        if (n.multiAlgo && i+1 == n.anchor.size())
        {
            dgbpow::Header parsed; std::string proofErr; lightpow::Hash proof;
            std::copy(h.raw.begin(), h.raw.end(), parsed.raw.begin());
            const Header& parent = nodes.at(h.prev);
            if (!dgbpow::BlockProof(DgbParents(nodes,parent,base),parsed,h.height,proof,proofErr,DgbParams(n)))
                throw std::runtime_error(n.label+" anchor: "+proofErr);
            h.work = parent.work+DgbWork(proof);
        }
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
    if (net->digishield)
    {
        if (net->minDifficulty && (int64)time > (int64)parent.time+2*net->spacing) return net->limitBits;
        return DigiShield(parent.bits, (int64)parent.time-(int64)nodes.at(parent.prev).time, net->limitBits);
    }
    if (net->asertHeight)
    {
        if (net->minDifficulty && (int64)time > (int64)parent.time+2*net->spacing) return net->limitBits;
        return Asert(net->asertBits, (int64)parent.time-net->asertParentTime, parent.height-net->asertHeight, net->spacing, net->asertHalfLife, net->limitBits);
    }
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
bool Headers::Add(const Bytes& raw, std::string& err, const btcswap::AuxPow* aux)
{
    try
    {
        Header h = Decode(raw);
        if (nodes.count(h.hash)) return true;
        std::map<uint256, Header>::const_iterator it = nodes.find(h.prev);
        if (it == nodes.end()) throw std::runtime_error("unknown "+net->label+" header parent");
        const Header& p = it->second;
        Integer target = Target(h.bits), limit = Target(net->limitBits);
        Integer step = (Integer(1)<<256)/(target+1);
        // DigiByte: which algorithm, whose retarget and whose work. A header
        // from the store is not hashed again, like scrypt below.
        if (net->multiAlgo)
        {
            dgbpow::Header parsed; std::string powErr; lightpow::Hash work{}, hash{};
            const dgbpow::Params params = DgbParams(*net);
            if (!dgbpow::ParseHeader(raw.data(),raw.size(),parsed,powErr)) throw std::runtime_error("invalid "+net->label+" header: "+powErr);
            if (net->regtest)
            {
                if (!storedHeaders && (!dgbpow::PoWHash(parsed,hash,powErr,params) || DgbWork(hash) > target || target > limit))
                    throw std::runtime_error("invalid "+net->label+" proof of work");
            }
            else
            {
                std::vector<dgbpow::PastBlock> parents = DgbParents(nodes,p,base);
                if (!(storedHeaders ? dgbpow::BlockProof(parents,parsed,p.height+1,work,powErr,params)
                                    : dgbpow::ValidateHeader(parents,parsed,p.height+1,work,powErr,params)))
                    throw std::runtime_error("invalid "+net->label+" header: "+powErr);
                step = DgbWork(work);
            }
        }
        // A merged-mined header's work is its parent's, by a proof that does
        // not stay in the header store: read once, from the peer.
        const int version = (int)(uint32_t)LE(raw,0,4);
        const bool merged = net->auxPow && (version&0x100);
        if (net->auxPow && !storedHeaders)
        {
            std::string auxErr;
            if (merged != (aux != NULL)) throw std::runtime_error("invalid "+net->label+" AuxPoW");
            if (net->strictChainId && !net->regtest && (version>>16) != net->auxChainId) throw std::runtime_error("invalid "+net->label+" chain id");
            if (merged && !CheckAuxPow(*aux,h.hash,version>>16,net->strictChainId,auxErr)) throw std::runtime_error("invalid "+net->label+" AuxPoW");
        }
        if (!net->multiAlgo && (target <= 0 || target > limit || Number(net->scrypt ? (storedHeaders ? uint256(0) : Scrypt(merged ? aux->parent : raw)) : h.hash) > target))
            throw std::runtime_error("invalid "+net->label+" proof of work");
        if (!net->multiAlgo && h.bits != NextBits(p, h.time)) throw std::runtime_error("invalid "+net->label+" difficulty");
        if (h.time <= Median(p) || (int64)h.time > GetTime()+7200) throw std::runtime_error("invalid "+net->label+" header time");
        if (net->bip94 && (p.height+1)%net->Interval() == 0 && (int64)h.time < (int64)p.time-600)
            throw std::runtime_error("testnet4 timewarp");
        h.height = p.height+1; h.work = p.work+step;
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
bool VerifyBlock(const Bytes& raw, const Header& h, std::vector<CTransaction>& txs, size_t maxBlock, bool auxPow)
{
    if (raw.size() < 81 || raw.size() > maxBlock || !std::equal(h.raw.begin(), h.raw.end(), raw.begin()) || !btcswap::ParseBlockTxs(raw, txs, auxPow)) return false;
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
    if (!chain.cashPrefix.empty())
    {
        // Cashaddr: a key, a script, and on Bitcoin Cash the token-aware forms
        // of the two, and a script's 32 bytes. Not base58: it reads the same
        // on Bitcoin, so a Bitcoin address pasted here would pay nobody.
        unsigned char type = 0; Bytes hash;
        if (btcswap::CashDecode(chain.cashPrefix, addr, type, hash))
        {
            if (type > (chain.coin == "bch" ? 3 : 1)) { err = "that is not a "+Label(chain.coin)+" address this wallet can pay"; return false; }
            if (type%2 == 0 && hash.size() == 20) { script << OP_DUP << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG; return true; }
            if (type%2 == 1 && hash.size() == 20) { script << OP_HASH160 << hash << OP_EQUAL; return true; }
            if (type%2 == 1 && hash.size() == 32 && chain.coin == "bch") { script << OP_HASH256 << hash << OP_EQUAL; return true; }
            err = "that is not a "+Label(chain.coin)+" address this wallet can pay"; return false;
        }
        err = "invalid "+Label(chain.coin)+" destination or wrong network"; return false;
    }
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
    if (!hrp.empty() && addr.size() <= 90 && !(upper && small) && sep != std::string::npos && lower.substr(0, sep) == hrp && sep+7 < lower.size())
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
        size_t budget = std::max<size_t>(16*1024*1024, 2*net.maxBlock);
        for (int messages = 0; messages < 256; ++messages)
        {
            Bytes header(24); Transfer(&header[0], 24, false);
            if (LE(header, 0, 4) != magic) throw std::runtime_error("wrong "+net.label+" message magic");
            size_t length = (size_t)LE(header, 16, 4);
            if (length > net.maxBlock || length > budget) throw std::runtime_error("oversized "+net.label+" message");
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
            if ((command == "reject" && !RefusesTx(payload)) || command == "notfound") throw std::runtime_error(net.label+" peer rejected request");
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
        Bytes version; Put(version, net.protocol, 4); Put(version, 0, 8); Put(version, GetTime(), 8);
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
            std::vector<CTransaction> txs; if (!VerifyBlock(b,h,txs,s.net.maxBlock,s.net.auxPow)) throw std::runtime_error("invalid saved Bitcoin block"); s.blocks[h.hash] = b;
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
        if (!VerifyBlock(block,s.headers.At(height),txs,s.net.maxBlock,s.net.auxPow)) throw std::runtime_error(s.net.label+" block does not match its header");
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
    Bytes request; Put(request,s.net.protocol,4); std::vector<uint256> locator = s.headers.Locator(); Compact(request,locator.size());
    for (size_t i = 0; i < locator.size(); ++i) HashBytes(request,locator[i]); HashBytes(request,uint256(0));
    Bytes response = Fetch(peer,"getheaders",request,"headers",lock);
    size_t pos = 0; uint64_t n = Count(response,pos,2000);
    uint256 last(0);
    for (uint64_t i = 0; i < n; ++i)
    {
        if (response.size()-pos < 81) throw std::runtime_error("truncated Bitcoin headers");
        Bytes raw(response.begin()+pos,response.begin()+pos+80); pos += 80;
        btcswap::AuxPow aux; const bool merged = s.net.auxPow && (LE(raw,0,4)&0x100);
        if (merged && !btcswap::ParseAuxPow(response,pos,aux)) throw std::runtime_error("truncated "+s.net.label+" AuxPoW");
        if (Count(response,pos,0) != 0) throw std::runtime_error("header has transactions");
        Header h = Decode(raw);
        if (i && h.prev != last) throw std::runtime_error("discontinuous Bitcoin headers");
        bool known = s.headers.Contains(h.hash);
        std::string err; if (!s.headers.Add(raw,err,merged ? &aux : NULL)) throw std::runtime_error(err);
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
    if ((s.net.asertHeight || s.net.digishield) && !s.net.minDifficulty && !s.net.anchor.empty())
        minimum = AnchorWorkFloor(s.net, s.headers.At(s.net.anchorHeight), GetTime());
    if (s.net.multiAlgo && s.net.name == "main") minimum = DgbWorkFloor(s.net, s.headers, GetTime());
    s.synced = n < 2000 && s.headers.Tip().work >= minimum &&
        (s.net.regtest || (int64)s.headers.Tip().time > GetTime()-7200);
    // Confirmed transactions remain saved so a reorg can resume rebroadcast.
    std::set<uint256> confirmed;
    for (auto it = s.blocks.begin(); it != s.blocks.end(); ++it)
        if (s.headers.ActiveHeight(it->first) >= 0)
        {
            std::vector<CTransaction> txs; btcswap::ParseBlockTxs(it->second,txs,s.net.auxPow);
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
            if (!VerifyBlock(block,s.headers.At(height),txs,s.net.maxBlock,s.net.auxPow)) throw std::runtime_error("Bitcoin block merkle root mismatch");
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
        out.coin = coin; out.name = network; out.fMain = network == "main"; out.pkhVersion = net->pkhVersion; out.shVersion = net->shVersion; out.cashPrefix = net->cashPrefix; out.fForkId = net->forkId;
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
        std::vector<CTransaction> txs; if (!btcswap::ParseBlockTxs(it->second,txs,s.net.auxPow)) continue;
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
    j["amount"] = (double)funding->second.tx.vout[output].nValue/CoinUnit(s.net.coin);
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
    check(VerifyBlock(rawBlock,blockHeader,blockTxs,4000000) && blockTxs.size() == 1,"verify matched block merkle root");
    rawBlock.back() ^= 1;
    check(!VerifyBlock(rawBlock,blockHeader,blockTxs,4000000),"reject matched block with tampered transaction");
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

int SelfTestCash()
{
    int failures = 0;
    auto check = [&](bool ok, const char* name) { printf("  %-70s %s\n",name,ok?"ok":"FAILED"); if (!ok) ++failures; };
    printf("cash-light self-test\n");
    const Net* bch = FindNet("bch","main"); const Net* bchTest = FindNet("bch","test4"); const Net* bchReg = FindNet("bch","regtest");
    const Net* xec = FindNet("xec","main"); const Net* xecTest = FindNet("xec","test"); const Net* xecReg = FindNet("xec","regtest");
    check(bch && bchTest && bchReg && xec && xecTest && xecReg,"Bitcoin Cash and eCash networks");
    if (!bch || !bchTest || !bchReg || !xec || !xecTest || !xecReg) { printf("cash-light: %d failure(s)\n",failures+1); return 1; }
    // Genesis fields of the two nodes (chainparams.cpp asserts these hashes).
    check(Decode(bch->genesis).hash.GetHex() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f","main genesis");
    check(Decode(bchTest->genesis).hash.GetHex() == "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b","Bitcoin Cash test4 genesis");
    check(Decode(xecTest->genesis).hash.GetHex() == "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943","eCash test genesis");
    check(Decode(bchReg->genesis).hash.GetHex() == "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","regtest genesis");

    // aserti3-2d against the real chain.
    struct { int parentHeight; int64 parentTime; unsigned int bits; } rows[] = { {661647,1605449609,0x1804e0d0U},{661648,1605449817,0x1804dedcU},{699999,1628513500,0x180606aeU},{799999,1688286172,0x18026bd4U},{899999,1748287553,0x18026f44U} };
    for (auto& r : rows)
    {
        unsigned int got = Asert(bch->asertBits,r.parentTime-bch->asertParentTime,r.parentHeight-bch->asertHeight,600,bch->asertHalfLife,bch->limitBits);
        check(got == r.bits,"aserti3-2d gives the real chain's bits");
        check(Asert(bch->asertBits,r.parentTime+1000-bch->asertParentTime,r.parentHeight-bch->asertHeight,600,bch->asertHalfLife,bch->limitBits) != r.bits ||
              r.parentHeight == bch->asertHeight,"another time gives other bits");
    }
    check(Asert(0x1d00ffff,86400*365,1,600,3600,0x1d00ffff) == 0x1d00ffff,"aserti3-2d stops at the proof-of-work limit");
    check(Asert(0x1804dafe,-(int64)86400*36500,0,600,172800,0x1d00ffff) != 0,"aserti3-2d keeps a target of at least one");

    struct { const Net* net; int height; const char* hash; const char* next[3]; } chains[] = {
        {bch,970331,"0000000000000a8169cd101774e715c087e26f069d3d81d5a758db30410c9513",{"00c0d42213950c4130db58a7d5813d9d066fe287c015e7741710cd69810a0000000000008595f457a2534e4b41a10eaedd4c8e4e31b5bab0472e1a8b63578662ff270bb08051eb6a9387161aad831263","00c017234da7cd84c004a0dff3e7d88bb97596bd37fb8b1ad42f91967b080000000000004c04e56f27e01cfecde459878a8cf8c67d695f40398f7b5ed8cddc138546c71d1954eb6aec84161a4780bc99","00807923575cbcfdaac76f77d9b6d292f000d215bec03d39767a37d99115000000000000ecb23b568aa993bce9ea2a78c735df01812838f8d492681538021efa5f7704a0c458eb6a7086161a9804d4ca"}},{bchTest,330867,"000000000000df73e882aa0303d88593920f9c18c0c727d2010dd0606459f432",{"0060d32732f4596460d00d01d227c7c0189c0f929385d80303aa82e873df000000000000cce6f4058d409131a35f8825ffd220735ee58e1b13989740549620dfb8b103297f5ceb6affff001ddc010e70","00a0af2dbf40b64fa9a697bc8a6dae02310b6fa520ef0ed0dfd1567f92443c00000000008b2b999f2af8bd594853a8608979548c48f3b80286adc6037c3ca165b7c76fc0415feb6a3012011b92009757","0080a522503ca3bef162e48c98a48b1f52ca23ce3295511e21f6c0b9a284000000000000e4111122a348fb455e1f2e7ec789a3c37d23a8bf78d1705677d8c58aa21790b3ae61eb6ad717011b4e00af23"}},{xec,974096,"000000000000000061d9b8630f8386d3adc91896ee3d79b764e84e51ceb83df3",{"00001020f33db8ce514ee864b7793dee9618c9add386830f63b8d96100000000000000002c8e5e3512715e8548ced5436b66ad7e9b4185188f778517836bccce5c2e32170c62eb6a4cae001913f0256f","0020cd23c8afa5ae08a8d80fbd9963296e60554a9623ba666c4ad405000000000000000066c6810d845aa51deeb73ec5e6cf61f1ed53f1342a817f0d8eb972e9ad04d8763864eb6a37ae00197c0365ae","00805925dd1935ceeaa3723149f337fc0abb48e1ae498f8c085ee0530000000000000000c831447f770906dd7533826f795f7d5633c40d30cc1d714ecf22b1e243a2b6c20466eb6a2fae001938c52691"}},{xecTest,1738711,"000000000000a67398cd330e2d8871c49cb9d8fe97e32730544a72f5b0715293",{"00000020935271b0f5724a543027e397fed8b99cc471882d0e33cd9873a60000000000000c902b8617489cf52f1dd7a07f4cf264764afd55f795b2e3b7dd2a17ecb0f906355ceb6a48be171b83e80c33","000000209d40065d4f69ae958bd72bff7f54f9d5e61818dff5d905f8b5560a00000000007d7c85165a011ad7487c52f8c023f6b88167dc7257fe950beb2ce22b7dc45af0d25feb6a58bf171b8d5ba461","0000002013e1097ee945edbdbdd975de66a0129839cf96616244953ae4d60d0000000000f28a20efd645f65a62f5f9282a472eb9436b8b25b5cda9b423b2965d668ad6cc1e62eb6a48c7171b20a392c6"}} };
    for (auto& c : chains)
    {
        Headers h(*c.net);
        check(h.Tip().height == c.height && h.Tip().hash == uint256(std::string(c.hash)),"anchor headers chain up to their tip, proof of work included");
        std::string err;
        for (const char* raw : c.next) check(h.Add(ParseHex(raw),err),"the next real headers pay aserti3-2d");
        Bytes flipped = ParseHex(c.next[0]); flipped[72] ^= 1;
        Headers again(*c.net);
        check(!again.Add(flipped,err),"a header with other bits is refused");
        check(c.net->anchor.size() == 12,"twelve anchor headers");
    }
    {
        Headers h(*bch); std::string err; Bytes wrong = ParseHex(chains[2].next[0]);
        check(!h.Add(wrong,err),"eCash's headers do not continue Bitcoin Cash's");
    }

    // Cashaddr: bitcoin-cash-node's test vectors and Bitcoin ABC's own output.
    Bytes hash = ParseHex("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
    check(btcswap::CashEncode("bitcoincash",0,hash) == "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2","cashaddr key address vector");
    check(btcswap::CashEncode("bchtest",1,hash) == "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t","cashaddr script address vector");
    check(btcswap::CashEncode("bchtest",3,hash) == "bchtest:rr6m7j9njldwwzlg9v7v53unlr4jkmx6eytyt3jytc","cashaddr token address vector");
    check(btcswap::CashEncode("ecash",0,ParseHex("1abed8be89284f058bcb9f1b7f5c37d272b6032b")) == "ecash:qqdtak973y5y7pvtew03kl6uxlf89dsr9vzx7jeyke","eCash address from Bitcoin ABC");
    check(btcswap::CashEncode("ecash",0,ParseHex("ab6ac78ca455a654900b6e4b47786160c2977ce9")) == "ecash:qz4k43uv5326v4yspdhyk3mcv9sv99muaycdj3n5ws","eCash address from Bitcoin ABC, again");
    unsigned char type = 9; Bytes out;
    check(btcswap::CashDecode("bitcoincash","bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",type,out) && type == 0 && out == hash,"cashaddr decodes");
    check(btcswap::CashDecode("bitcoincash","qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",type,out) && out == hash,"cashaddr without its prefix");
    check(btcswap::CashDecode("bitcoincash","BITCOINCASH:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2",type,out),"cashaddr in capitals");
    check(!btcswap::CashDecode("bitcoincash","bitcoincash:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2",type,out),"cashaddr in mixed case is refused");
    check(!btcswap::CashDecode("ecash","bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",type,out),"a Bitcoin Cash address is not an eCash one");
    check(!btcswap::CashDecode("ecash","qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",type,out),"the prefix is in the checksum");
    check(!btcswap::CashDecode("bitcoincash","bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3",type,out),"a mistyped cashaddr is refused");

    btcswap::Chain chain; chain.coin = "bch"; chain.name = "main"; chain.fMain = true; chain.pkhVersion = 0; chain.shVersion = 5;
    chain.cashPrefix = "bitcoincash"; chain.fForkId = true;
    CScript dest; std::string err; Bytes pkhBase58; std::string addrBase58;
    check(Destination(chain,"bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",dest,err) && dest.size() == 25,"Bitcoin Cash key destination");
    check(Destination(chain,btcswap::CashEncode("bitcoincash",1,hash),dest,err) && dest.size() == 23,"Bitcoin Cash script destination");
    check(Destination(chain,btcswap::CashEncode("bitcoincash",1,Bytes(32,7)),dest,err) && dest.size() == 35,"Bitcoin Cash 32-byte script destination");
    check(Destination(chain,btcswap::CashEncode("bitcoincash",2,hash),dest,err) && dest.size() == 25,"Bitcoin Cash token-aware destination");
    check(!Destination(chain,"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",dest,err),"base58 reads the same on Bitcoin: refused");
    check(!Destination(chain,"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",dest,err),"a base58 script address too");
    check(!btcswap::AddressToPkh(chain,"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",pkhBase58,addrBase58),"and as a contract key");
    check(!Destination(chain,"ecash:qqdtak973y5y7pvtew03kl6uxlf89dsr9vzx7jeyke",dest,err),"an eCash address is not a Bitcoin Cash destination");
    check(!Destination(chain,"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",dest,err),"a Bitcoin address is not a Bitcoin Cash destination");
    Bytes pkh; std::string addrErr;
    check(btcswap::AddressToPkh(chain,"bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",pkh,addrErr) && pkh == hash,"contract key from a cashaddr");
    check(!btcswap::AddressToPkh(chain,btcswap::CashEncode("bitcoincash",1,hash),pkh,addrErr),"a contract key is not a script");
    check(btcswap::PkhToAddress(chain,hash) == "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2","contract key to cashaddr");
    btcswap::Chain ec = chain; ec.coin = "xec"; ec.cashPrefix = "ecash";
    check(!Destination(ec,btcswap::CashEncode("ecash",2,hash),dest,err),"no token-aware addresses on eCash");
    check(!Destination(ec,btcswap::CashEncode("ecash",1,Bytes(32,7)),dest,err),"no 32-byte script addresses on eCash");

    // A valid transaction with more outputs than any fixed limit: a block
    // holding one must not stop a scan for good.
    Bytes wide; Bytes header32 = ParseHex("01000000"); wide = header32; wide.push_back(1); wide.insert(wide.end(),36,0); wide.push_back(0); wide.insert(wide.end(),4,0);
    const uint32_t outputs = 110000; wide.push_back(0xfe); for (int i = 0; i < 4; ++i) wide.push_back((unsigned char)(outputs>>(8*i)));
    wide.insert(wide.end(),outputs*9,0); wide.insert(wide.end(),4,0);
    CTransaction wideTx;
    check(btcswap::ParseTx(wide,wideTx) && wideTx.vout.size() == outputs,"a transaction with 110000 outputs reads");
    Bytes cut(wide.begin(),wide.end()-100);
    check(!btcswap::ParseTx(cut,wideTx),"and a cut one does not");

    // aserti3-2d past the anchor: the floor a private fork would have to show.
    {
        Headers h(*bch); const Header& a = h.At(bch->anchorHeight); Integer perBlock = (Integer(1)<<256)/(Target(a.bits)+1);
        check(AnchorWorkFloor(*bch,a,(int64)a.time-5000) == a.work && AnchorWorkFloor(*bch,a,(int64)a.time+500) == a.work,"no floor at the anchor");
        int64 month = (int64)a.time+30*86400;
        check(AnchorWorkFloor(*bch,a,month) == a.work+perBlock*4320/16,"a month on, 270 blocks of the anchor's work");
        // One real block, stamped a month later, then six almost free ones.
        unsigned int cheap = Asert(bch->asertBits,month-bch->asertParentTime,bch->anchorHeight+1-bch->asertHeight,600,bch->asertHalfLife,bch->limitBits);
        Integer fork = a.work+perBlock+(Integer(1)<<256)/(Target(cheap)+1)*6;
        check(Target(cheap) > Target(a.bits)*1000 && fork < AnchorWorkFloor(*bch,a,month),"a cheap fork from the anchor stays under it");
    }

    // The chain's own signature hash vectors (bitcoin-cash-node, test/data/sighash.json).
    struct { const char* tx; const char* script; int input; unsigned int type; const char* hash; } sigs[] = { {"13938a7d011e4545c281cbd8c6c85c796194285adb908ab052755cf65b60c5f7fc7e0e125c020000000953530000ac6a526a00d36774ce04d94bb802000000000600516353ac63f9f9fe000000000000b0123a05000000000251ace0b7c10400000000055351abab6300000000","5300655100",0,0x1be50b41U,"6bfb3e169f83f480b12c45223182650ae9dfa1e6be45e42a70b4bfdbf75cf923"},
        {"753ca84702758209899178670a37c457207494591a31ece76b9654e35d9e38e3e0879462e2030000000952ab515253acab63656d0120aae21ec8043302ace9d58d296672649452875895946eaf44942c410b16df1cef2f020000000400635200ffffffff0348b17202000000000665526a525365d8ada10300000000056563510051d47f54030000000009536aab65abac0052652963ff8d","",0,0x8e0b8841U,"d550d784646703f7db64c8755a5cd58b8ea736e6e344542bd206c21cc569a82e"},
        {"ddadc1eb045d16b79907449cc9f00f7f74e4b8dc891417c1ffed225d5f6665980ca500d3df0000000005acab53ac5277506c8885fe8846264f4e1d2721b4a4d0795bd55d2cf5a43164713a42b813995408024d0200000007abab00635353abffffffff6992b2678018777756025009c13fec6e53b7d1b59ae5f36cb771c61a43a8161d010000000353ababffffffff0c59a711c690c00a13a9d3a9125d3b45db372c26841d9b902932310246695b1c01000000046a51ac006176e522016ef66d0300000000010000000000","ab6a6a63516aac65",0,0x9f20f041U,"d6fe4e12b301525576c14ca489d6edb914c5326f02c63ed5097b78ad6c51d827"} };
    for (auto& v : sigs)
    {
        CTransaction tx; Bytes raw = ParseHex(v.tx), code = ParseHex(v.script);
        check(btcswap::ParseTx(raw,tx),"sighash vector transaction");
        check(btcswap::ForkIdSignatureHash(CScript(code.begin(),code.end()),tx,v.input,0,v.type).GetHex() == v.hash,"ALL|FORKID signature hash vector");
        check(btcswap::ForkIdSignatureHash(CScript(code.begin(),code.end()),tx,v.input,1,v.type).GetHex() != v.hash,"the amount is in the signature hash");
    }

    // eCash counts to two places.
    int64_t n = 0;
    check(CoinUnit("xec") == 100 && CoinUnit("bch") == 100000000,"an XEC is 100 base units");
    check(ParseCoinAmount("xec","1234.56",n) && n == 123456 && CoinAmountText("xec",n) == "1234.56","XEC amount and back");
    check(!ParseCoinAmount("xec","0.001",n),"XEC has no third decimal");
    check(ParseCoinAmount("bch","0.00000001",n) && n == 1,"Bitcoin Cash has eight");
    check(ParseCoinAmount("xec","200000000000",n) && n == 20000000000000LL,"more XEC than fit at eight decimals");
    check(!ParseCoinAmount("xec","99999999999999999999",n),"too many XEC");
    check(!ParseCoinAmount("bch","1.2.3",n) && !ParseCoinAmount("bch","",n) && !ParseCoinAmount("bch","-1",n),"malformed amounts");
    printf("cash-light: %d failure(s)\n",failures); return failures ? 1 : 0;
}
int SelfTestDigiByte()
{
    int failures = 0;
    auto check = [&](bool ok, const char* name) { printf("  %-70s %s\n",name,ok?"ok":"FAILED"); if (!ok) ++failures; };
    printf("dgb-light self-test\n");
    const Net* mainNet = FindNet("dgb","main"); const Net* testNet = FindNet("dgb","test"); const Net* regNet = FindNet("dgb","regtest");
    check(mainNet && testNet && regNet,"DigiByte networks: main, test, regtest");
    if (!mainNet || !testNet || !regNet) { printf("dgb-light: %d failure(s)\n",failures+1); return 1; }
    // digibyte v9.26.7's chainparams.cpp asserts this hash.
    check(Decode(regNet->genesis).hash.GetHex().compare(0,16,"4598a0f2b823aaf9") == 0,"regtest genesis hash");
    check(mainNet->protocol >= 70017 && testNet->protocol >= 70017,"at least the peers' minimum protocol");
    for (const Net* net : {mainNet,testNet})
    {
        Headers h(*net);
        check(h.Tip().height == net->anchorHeight,"the anchor loads, links and proves its end");
        check(DgbParents(*std::unique_ptr<std::map<uint256,Header>>(new std::map<uint256,Header>()),h.Tip(),h.Tip().height).size() == 1,"history stops at the base");
        std::vector<int> algos;
        for (int i = net->anchorHeight; i > net->anchorHeight-200; --i)
        {
            dgbpow::Header parsed; std::string err; const Header& one = h.At(i);
            check(dgbpow::ParseHeader(one.raw.data(),one.raw.size(),parsed,err),"an anchor header parses");
            if (std::find(algos.begin(),algos.end(),(int)dgbpow::Algorithm(parsed)) == algos.end()) algos.push_back((int)dgbpow::Algorithm(parsed));
        }
        check(algos.size() == 5,"the anchor holds all five algorithms");
        // A header on the anchor: no proof of work, then the wrong difficulty.
        Bytes forged(net == mainNet ? 80 : 80,0);
        const Header& tip = h.Tip();
        std::copy(tip.raw.begin(),tip.raw.end(),forged.begin());
        for (int i = 0; i < 32; ++i) forged[4+i] = tip.hash.begin()[i];
        uint32_t later = tip.time+15;
        for (int i = 0; i < 4; ++i) forged[68+i] = (later>>(8*i))&255;
        std::string err;
        check(!h.Add(forged,err) && err.find("difficulty") != std::string::npos,"a header with its parent's bits is refused");
        dgbpow::Header parsed; std::copy(forged.begin(),forged.end(),parsed.raw.begin());
        // The next bits of its own algorithm: only the proof can fail now.
        std::vector<dgbpow::PastBlock> parents;
        for (int i = net->anchorHeight-199; i <= net->anchorHeight; ++i)
        {
            dgbpow::Header one; std::copy(h.At(i).raw.begin(),h.At(i).raw.end(),one.raw.begin());
            dgbpow::PastBlock past; past.height = i; past.time = one.Time(); past.bits = one.Bits(); past.algo = dgbpow::Algorithm(one);
            parents.push_back(past);
        }
        uint32_t bits = dgbpow::NextWorkRequired(parents,dgbpow::Algorithm(parsed),err,DgbParams(*net));
        for (int i = 0; i < 4; ++i) forged[72+i] = (bits>>(8*i))&255;
        err.clear();
        check(bits != 0 && !h.Add(forged,err) && err.find("proof hash") != std::string::npos,"a header without proof of work is refused");
    }
    {
        // The floor: a month on, a chain has to show 1/16 of a month of work.
        Headers h(*mainNet);
        const Header& a = h.At(mainNet->anchorHeight); const Header& b = h.At(mainNet->anchorHeight-1);
        int64 month = (int64)a.time+30*86400;
        check(DgbWorkFloor(*mainNet,h,(int64)a.time+10) == a.work,"no floor at the anchor");
        check(DgbWorkFloor(*mainNet,h,month) == a.work+(a.work-b.work)*(30*86400/15)/16,"a month on");
    }
    // A real address of each network, as DigiByte Core gave them.
    btcswap::Chain chain; chain.coin = "dgb"; chain.name = "regtest"; chain.pkhVersion = regNet->pkhVersion; chain.shVersion = regNet->shVersion;
    std::vector<unsigned char> pkh; std::string err;
    check(btcswap::AddressToPkh(chain,"skzSdPmkCiRX64ocF1LJKmF7CXh6st1PTb",pkh,err) && HexStr(pkh.begin(),pkh.end(),false) == "255748c1a58483cb7df2984d06247f95add99b45","a regtest address and its key hash");
    printf("dgb-light: %d failure(s)\n",failures); return failures ? 1 : 0;
}
int SelfTestDogecoin()
{
    int failures = 0;
    auto check = [&](bool ok, const char* name) { printf("  %-70s %s\n",name,ok?"ok":"FAILED"); if (!ok) ++failures; };
    printf("doge-light self-test\n");
    const Net* mainNet = FindNet("doge","main"); const Net* testNet = FindNet("doge","test"); const Net* regNet = FindNet("doge","regtest");
    check(mainNet && testNet && regNet,"Dogecoin networks: main, test, regtest");
    if (!mainNet || !testNet || !regNet) { printf("doge-light: %d failure(s)\n",failures+1); return 1; }
    // dogecoin v1.14.9's chainparams.cpp asserts these hashes.
    check(Decode(mainNet->genesis).hash.GetHex() == "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691","main genesis hash");
    check(Decode(testNet->genesis).hash.GetHex() == "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e","test genesis hash");
    check(Decode(regNet->genesis).hash.GetHex() == "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5","regtest genesis hash");
    check(Number(Scrypt(mainNet->genesis)) <= Target(0x1e0ffff0),"scrypt proof of work of the main genesis");

    // DigiShield against the real chain.
    struct { unsigned int bits; int64 elapsed; unsigned int next; } steps[] = { {0x194d1e75U,5,0x19456836U},{0x1947bd6bU,193,0x195adedcU},{0x1949db88U,10,0x194278c7U},{0x19441587U,826,0x1966204aU},{0x196c2fd0U,55,0x196c2fd0U} };
    for (auto& r : steps) check(DigiShield(r.bits,r.elapsed,0x1e0fffff) == r.next,"DigiShield gives the real chain's bits");
    check(DigiShield(0x1e0fffff,3600,0x1e0fffff) == 0x1e0fffff,"DigiShield stops at the proof-of-work limit");
    Integer slow = Target(0x1b0404cb), fast = slow;
    check(Target(DigiShield(0x1b0404cb,100000,0x1e0fffff)) > slow*14/10 && Target(DigiShield(0x1b0404cb,100000,0x1e0fffff)) <= slow*15/10,"a long gap moves the target at most 3/2");
    check(Target(DigiShield(0x1b0404cb,-100000,0x1e0fffff)) >= fast*7/10 && Target(DigiShield(0x1b0404cb,-100000,0x1e0fffff)) < fast*8/10,"a block from the future moves it at most 3/4");

    struct { const Net* net; int height; const char* hash; const char* next[3]; } chains[] = { {mainNet,6445060,"54fff389d18fc451605d06a7173e5774df4d2d20fa51681b82b1fd2fbe786b80",{"04016200806b78be2ffdb1821b6851fa202d4ddf74573e17a7065d6051c48fd189f3ff54f00948b1e110aa6951a3afe2460988cbacba06ee95e83194fb8c20ab0afa6ebbdc88ec6a61a936190000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff64039ff2302cfabe6d6d91ff6513b9644bf941c66d44c231c6af294df615e00d3abe167fbb8d2e24ce1020000000f09f909f092f4632506f6f6c2f6400000000000000000000000000000000000000000000000000000000000000000000000500f90f0000000000000250015725000000001976a914dfd88711bf5d20f2ac7049ba28d053a89186ce9288ac0000000000000000266a24aa21a9ede95bfb806dede2f1803efb5ce5a921152fe58e6732799c6f4ce6828901301bff46235845548d4733e81ceffa84ba3dfb0bc9da05a95d46ff4c97eb082a0000000000000009734362c54b3f6f285234e3c5a87dadf570e3206827d1ce78b723c3d2dfe93a55779695c32c391b8b4984b515696937bba61642f8c2b81edb406f351a76fcf46f3b31b484fdd8d79391a7c0af48c72e895700228ea7e7ef098041c8b68931d187203cdfc0530b4246f49a803978c8ecfe1ba5a7beee95bd9da44ac5af79a69fcbeb32ee3723653bc758047c63622f77808425d8f7122b05730aefce54303655986b4cb160b87f2ba87331c313badc777fa3dd9fd0c3b5f65226644c7c270f1be8a0fb676b1533c1ba5700f468f495ba73110d11e5e4ab9d9454ee921c66b3cdac9c1e3541cfa7ca48e115b3c7aaa543d17508bd5afc2e0db20bbf8dfeac7dbd63abb45fc9c79e78542891ffd8278ee0d25008c6faacec3ce4db35a2e1fd4b3d7200000000050900000000000000000000000000000000000000000000000000000000000000af09df5d2d23e3873c9c04cbe183ddd004503311b734a5fb3d364bd242084acab58d63cd5e34858cecf95f8f4ef6118124125fde91b129bc0bcbd47d0c32eab1e4b2e25910150cba609207bc0258757dea692f7ae114927b0762cdcbfc2404c8ad11d36c1e67ce3741bedda751dc1cd0212763dedfa10f659ec6d9ad298959f308000000140000205e3498b4c50fec0d0c92e89210303c4b0826361833b2446b61345e17daf1eb13d3189529497d7bd39d030e17473ac3f9afac205cf3c77e11c44d7d30fe5266c3e788ec6ae0eb2b19339c92d7","040162007e033840b342762c3e2ede82bf918cfc07237cbf0e97f2527dd700462e0d9d721253659ceba3eb48e8479166fdda6904702641f0d0ace93c5c0196ae654ea2600e89ec6af23c45190000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6403a0f2302cfabe6d6d4c4e476801a47d2c39312825007d840f4f7c21d9fab121940717341c1e0af8f220000000f09f909f092f4632506f6f6c2f65000000000000000000000000000000000000000000000000000000000000000000000005009ab6ca4c1400ca4c02d8454825000000001976a914dfd88711bf5d20f2ac7049ba28d053a89186ce9288ac0000000000000000266a24aa21a9ed70ac251e29b30e699c3c4c25adffdcd5f13da812bac539ddbf4336b6e57ecc6d2a88bb3e8b88122348ac1f45462ee08934ad606b2f7be655d955ec9e4100000000000000074b4f2cd20fc3ae62600878d087e00648389c29e6ec1031a44a93d159cb305ec04f35bbca54b8f9255b3464e3d696c7fa7639ef484aca1d70100a46d7bbaaacb4dbda8f4e7964b9b2e0dec0327cf9a2f656706222d1744cce4d356be0008ce912eb7e6783df5d16b9a0d9c35f4ccd54a1a6b96cc6a1c654b37ffd32b39f2eb416676fc41e6bf156d16e5b3ea772dacb74e5d10c2ad55228fbb697b52176290c18a7bf3e863d8e6e8c29f04a13a89ef66ac53fffad645ec563b1486207c4d5116990414dbfd65b8a53d600ef0296ce447750aa39b7aa1e66bf40a6d95b0ec4c0c40000000005090000000000000000000000000000000000000000000000000000000000000084a5579c8d0d89e29a20e0fca19c455e6c13f43a0d5544dab12c72553e7a54bf47837d6eb6907e7221093532899717a218345125ca85ee6883131e61938339a70740480bf5824a3b443716d119c8fd9e09e9bf59b4812d630e67cb7cfe0cf7eb98c9a6aa9bba89af0c50a7402ef8d51bc763a659b65ca70706adc65d4e2561740800000014000020d4f8270c4ada3fd122481137115f5d31b445c23ac37592ef4ae8f3da5040a92200cd420fe6c63c0565d0c6b1483deaef6d9ae6acc85104166bc2ae27b369b8580e89ec6ae0eb2b19ff0698e4","040162003f60909b9a8472aedf98e8ef9d8d66ec81cd9f3dc0baa4473b322207e94c33311768905d77d1a2f8e129c4a7676c65d1b9e3a7827822b83c063659ca13f5cb43488cec6a871544190000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6203a0f2301b2f5669614254432f4d696e656420627920616c656b736c3030372f2cfabe6d6d36655be62ce7f47e61f817653cbf0dcb24634cf518d14d1d261b49ef3f2018a6200000000000000010335a2d01b3bcf1768d153d067d723b007d723b00ffffffff02c6ff8f25000000001976a91493e278b485679cfd2d21441a94bb29dd7c99d72088ac0000000000000000266a24aa21a9ed37144b19c0ffca72143052b533571b3e83e1ebce841889f5034ebac562e6d892000000007766caa122d24a37806450b4640c2100e671129f4f1506520d462d14efe930660b7df322bcf3f3c670e33454adf96aa3bb1e5bda015fe78ae964135b9199724b9a177e795fd7f142f0c912a09bcf5a1c924e663f8bc4a67855d01d5d2322587c99b5c4450b187a9be4f332c570738b7315e2693187036a7f372f8b98368aa8aa40403279769f8ef48ebbb012e0cef40225e593683a30203ea9d464cdfa0cf48300b399e8cadb31863dd53e9245d84678718710e5a6ee505ccecf91eb1ca7de2f85711d9c3cd33ddbfd39d1f179889c5997b7ca51a882c2022ae9fa663c90ec27aee1d7cd37e422f455f60f93d920c1b93e232484ba8d3bb150d347d739848dd1b5a556f5a49048367d663bd8038097f868def94a9fee6078eb4a27b19b580f618ebed4f42a0418fb0017d130c29b68e12bc2e75440b4bb2361fce785ee83f3eb0a3ba8f9c4fa171bbb0f6afd8aa6bd82b5b6c8188bd7cb97d30b0553b78079c71e10beaec0f259ad413d61116c4fbb31a07b4ec749615833b638f0fe1441095c4b00000000050000000000000000000000000000000000000000000000000000000000000000e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf97d24db2bfa41474bfb2f877d688fac5faa5e10a2808cf9de307370b93352e548f31c8add9a607b0be34d795c949dd8798ff6904f9ff2ddf55b872833f54d1c1dfd409908f49b8f3317b604408dac9d1a45c69a068f74dc0503364737cb07d75f1800000000000020d4f8270c4ada3fd122481137115f5d31b445c23ac37592ef4ae8f3da5040a92223c096db17ec34a0f5a6c2ecdd42904c849ebab47dd073000a84653159d37575868bec6ae0eb2b1923f07ca1"}},{testNet,68043613,"f2afbcfce7ab352bf5e907f402eddcac80cd575243f253ff1c2b2fc92256054d",{"040062004d055622c92f2b1cff53f2435257cd80acdced02f407e9f52b35abe7fcbcaff26ea30c1ed9968ea1d2f5ef0b1162f9a70083d339f3da2345b1fb91ea4ca3e89e06bfec6aa406091e800039dd","04006200d610696413d1c60d78247cad66b1694c0e0a01369f7fd082057eb1501f0954d03c4be8551a0efba1d632090937d2bb6c4445d1178421f4516051d296ee41a3aa15bfec6aaea0091ec0002250","04006200334819a9f7732df16306de860980ac6bbd0032b49356e7ffa934dec1c329a5eda3db5a0f646a152002d5404779ff3b83a7f1f1231af545ffdcafc8a328a62b5816bfec6a4ad3081e80001031"}} };
    for (auto& c : chains)
    {
        Headers h(*c.net); std::string err;
        check(h.Tip().height == c.height && h.Tip().hash == uint256(std::string(c.hash)),"anchor headers link up to their tip");
        for (const char* text : c.next)
        {
            Bytes full = ParseHex(text), raw(full.begin(),full.begin()+80); size_t pos = 80; btcswap::AuxPow aux;
            if (full.size() == 80) { check(h.Add(raw,err),"the next real headers pay DigiShield and their own scrypt"); continue; }
            check(btcswap::ParseAuxPow(full,pos,aux) && pos == full.size(),"a real AuxPoW reads to its end");
            Headers without(*c.net), sameBlock(*c.net);
            btcswap::AuxPow bent = aux; bent.parent[79] ^= 1;
            if (&text == &c.next[0] || text == c.next[0])
            {
                check(!without.Add(raw,err),"a merged-mined header without its proof is refused");
                check(!sameBlock.Add(raw,err,&bent),"a proof whose parent was changed is refused");
                bent = aux; bent.nChainIndex ^= 1;
                check(!sameBlock.Add(raw,err,&bent),"a proof in the wrong slot is refused");
                bent = aux; if (!bent.branch.empty()) bent.branch[0] = Joined(bent.branch[0],bent.branch[0]); else bent.tx.vin[0].scriptSig << OP_0;
                check(!sameBlock.Add(raw,err,&bent),"a proof with another coinbase is refused");
                bent = aux; bent.tx.vin[0].scriptSig = CScript();
                check(!sameBlock.Add(raw,err,&bent),"a coinbase without the block in it is refused");
                std::string auxErr;
                check(CheckAuxPow(aux,Decode(raw).hash,(int)((uint32_t)LE(raw,0,4)>>16),c.net->strictChainId,auxErr),"the real proof passes");
                check(!CheckAuxPow(aux,Joined(Decode(raw).hash,Decode(raw).hash),(int)((uint32_t)LE(raw,0,4)>>16),c.net->strictChainId,auxErr),"and proves no other block");
                // CAuxPow::check refuses a second marker, not a second root.
                uint256 rootHash = ClimbBranch(Decode(raw).hash,aux.chainBranch,aux.nChainIndex);
                Bytes again(rootHash.begin(),rootHash.end()); std::reverse(again.begin(),again.end());
                btcswap::AuxPow twice = aux; twice.branch.clear(); twice.nIndex = 0;
                twice.tx.vin[0].scriptSig.insert(twice.tx.vin[0].scriptSig.end(),again.begin(),again.end());
                uint256 merkle = twice.tx.GetHash(); std::copy(merkle.begin(),merkle.end(),twice.parent.begin()+36);
                check(CheckAuxPow(twice,Decode(raw).hash,(int)((uint32_t)LE(raw,0,4)>>16),c.net->strictChainId,auxErr),"a coinbase that repeats the root is valid, as in CAuxPow::check");
                static const unsigned char marker[4] = {0xfa,0xbe,0x6d,0x6d};
                twice.tx.vin[0].scriptSig.insert(twice.tx.vin[0].scriptSig.end(),marker,marker+4);
                merkle = twice.tx.GetHash(); std::copy(merkle.begin(),merkle.end(),twice.parent.begin()+36);
                check(!CheckAuxPow(twice,Decode(raw).hash,(int)((uint32_t)LE(raw,0,4)>>16),c.net->strictChainId,auxErr),"a coinbase with a second marker is not");
            }
            check(h.Add(raw,err,&aux),"the next real headers pay DigiShield and their parent's scrypt");
        }
        // A block with an AuxPoW between its header and its transactions.
        if (strlen(c.next[0]) == 160) continue;
        Bytes block = ParseHex(c.next[0]);
        Bytes coinbase = ParseHex("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100e1f505000000000000000000");
        block.push_back(1); block.insert(block.end(),coinbase.begin(),coinbase.end());
        std::vector<CTransaction> txs;
        check(btcswap::ParseBlockTxs(block,txs,true) && txs.size() == 1,"a block with an AuxPoW reads");
        check(!btcswap::ParseBlockTxs(block,txs),"and not without being told of it");
    }

    {
        // A fork that stamps long gaps gets the easing for free.
        Header a = Headers(*mainNet).Tip(); int64 month = (int64)a.time+2592000;
        Integer perBlock = (Integer(1)<<256)/(Target(a.bits)+1), floor = AnchorWorkFloor(*mainNet,a,month), work = a.work;
        check(AnchorWorkFloor(*mainNet,a,(int64)a.time+30) == a.work,"no floor at the anchor");
        check(floor == a.work+perBlock*43200/16,"a month on, 2700 blocks of the anchor's work");
        unsigned int bits = a.bits;
        for (int i = 0; i < 2000; ++i) { bits = DigiShield(bits,300,mainNet->limitBits); work += (Integer(1)<<256)/(Target(bits)+1); }
        check(bits == mainNet->limitBits && work < floor,"a long fork at the eased difficulty stays under it");
    }
    check(RefusesTx(ParseHex("02747842")) && !RefusesTx(ParseHex("0767657464617461")),"a refused broadcast stops nothing, a refused request does");

    btcswap::Chain chain; chain.coin = "doge"; chain.name = "main"; chain.fMain = true; chain.pkhVersion = 30; chain.shVersion = 22; CScript dest; std::string err;
    Bytes hash = ParseHex("751e76e8199196d454941c45d1b3a323f1433bd6"); std::string address = btcswap::PkhToAddress(chain,hash);
    check(address[0] == 'D' && Destination(chain,address,dest,err) && dest.size() == 25,"Dogecoin key address (D...)");
    check(!Destination(chain,"1111111111111111111114oLvT2",dest,err),"a Bitcoin address is not a Dogecoin destination");
    check(!Destination(chain,"LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",dest,err),"nor a Litecoin one");
    check(!Destination(chain,"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",dest,err),"nor a bech32 one");
    printf("doge-light: %d failure(s)\n",failures); return failures ? 1 : 0;
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
