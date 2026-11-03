// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
#ifndef BITFLASH_BTCLIGHT_H
#define BITFLASH_BTCLIGHT_H

#include "btcswap.h"
#pragma push_macro("snprintf")
#undef snprintf
#include <boost/multiprecision/cpp_int.hpp>
#pragma pop_macro("snprintf")
#include <map>

// The embedded light client: another chain's P2P protocol, over Tor, to that
// chain's own peers. One instance per chain and network (Bitcoin, Litecoin),
// each with its own header store, peers and worker thread.
namespace btclight
{
typedef std::vector<unsigned char> Bytes;
typedef boost::multiprecision::cpp_int Integer;

// Everything the client knows about one chain's network, each value from that
// chain's own source at a named release tag (see the table in btclight.cpp).
struct Net
{
    std::string coin;             // "btc", "ltc": the -<coin>peer option, the state file
    std::string name;             // as the chain's own node says: main, testnet4, test, regtest
    std::string label;            // "Bitcoin", "Litecoin"
    unsigned int magic = 0;
    unsigned short port = 0;
    std::vector<std::string> seeds;
    unsigned char pkhVersion = 0, shVersion = 5, shVersion2 = 5;   // shVersion2: an older script prefix still valid
    std::string hrp;              // bech32 prefix
    unsigned int limitBits = 0;   // proof-of-work limit, compact
    int64 timespan = 0, spacing = 0;
    bool scrypt = false;          // proof of work is scrypt(1024,1,1) of the header, not its hash
    bool fullPeriod = false;      // Litecoin's retarget: the timespan covers the whole period
    bool minDifficulty = false;   // testnet: a block after 2 spacings may be at the limit
    bool bip94 = false;           // testnet4: the period's first bits, and no time warp
    bool regtest = false;         // no retarget, no minimum work, no time check
    bool filters = false;         // payments found by BIP157 filters; else by blocks in the window
    uint64_t services = 0;        // what a peer must offer
    unsigned int blockInv = 2;    // the inventory type asked for a block
    const char* agent = "";
    const char* minimumWork = ""; // the chain's nMinimumChainWork, hex; checked only from genesis
    // Where the header chain starts: genesis, or a run of real headers ending
    // at a retarget boundary (anchorHeight), enough for the next retarget and
    // the median time of the first headers after it.
    Bytes genesis;
    int anchorHeight = 0;
    std::vector<const char*> anchor;
    int Interval() const { return (int)(timespan / spacing); }
};
const Net* FindNet(const std::string& coin, const std::string& network);
std::string Label(const std::string& coin);

struct Header
{
    Bytes raw;
    uint256 hash, prev, merkle;
    unsigned int time = 0, bits = 0;
    int height = 0;
    Integer work = 0;
};

class Headers
{
public:
    explicit Headers(const std::string& network);   // Bitcoin's
    explicit Headers(const Net& net);
    bool Add(const Bytes& raw, std::string& err);
    const Header& Tip() const;
    const Header& At(int height) const;
    int ActiveHeight(const uint256& hash) const;
    bool Contains(const uint256& hash) const;
    int64 Median(const Header& h) const;
    unsigned int NextBits(const Header& parent, unsigned int time) const;
    std::vector<uint256> Locator() const;
    int Base() const { return base; }
    std::string network;
    const Net* net;
private:
    void Start(const Net& n);
    std::map<uint256, Header> nodes;
    std::vector<uint256> active;
    int base = 0;
};

unsigned int Retarget(unsigned int bits, int64 elapsed, unsigned int limit);
unsigned int LitecoinRetarget(unsigned int bits, int64 elapsed, unsigned int limit);
Bytes EncodeFilter(const uint256& block, const std::vector<Bytes>& scripts);
// A malformed filter is an error, never evidence that a payment is absent.
bool MatchFilter(const uint256& block, const Bytes& filter, const std::vector<Bytes>& scripts, bool& match);
bool VerifyBlock(const Bytes& raw, const Header& header, std::vector<CTransaction>& txs);
bool Destination(const btcswap::Chain& chain, const std::string& address, CScript& script, std::string& err);

bool CheckChain(const std::string& coin, const std::string& network, btcswap::Chain& chain, std::string& err);
void Watch(const btcswap::Chain& chain, const CScript& contract);
bool Call(const btcswap::Chain& chain, const std::string& method, const nlohmann::json& params, nlohmann::json& result, std::string& err);
nlohmann::json Find(const btcswap::Chain& chain, const CScript& contract, const std::string& ref, bool secret);
int SelfTest();
int SelfTestLitecoin();
}
#endif
