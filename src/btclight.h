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

namespace btclight
{
typedef std::vector<unsigned char> Bytes;
typedef boost::multiprecision::cpp_int Integer;

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
    explicit Headers(const std::string& network);
    bool Add(const Bytes& raw, std::string& err);
    const Header& Tip() const;
    const Header& At(int height) const;
    int ActiveHeight(const uint256& hash) const;
    bool Contains(const uint256& hash) const;
    int64 Median(const Header& h) const;
    unsigned int NextBits(const Header& parent, unsigned int time) const;
    std::vector<uint256> Locator() const;
    std::string network;
private:
    std::map<uint256, Header> nodes;
    std::vector<uint256> active;
};

unsigned int Retarget(unsigned int bits, int64 elapsed, unsigned int limit);
Bytes EncodeFilter(const uint256& block, const std::vector<Bytes>& scripts);
// A malformed filter is an error, never evidence that a payment is absent.
bool MatchFilter(const uint256& block, const Bytes& filter, const std::vector<Bytes>& scripts, bool& match);
bool VerifyBlock(const Bytes& raw, const Header& header, std::vector<CTransaction>& txs);
bool Destination(const btcswap::Chain& chain, const std::string& address, CScript& script, std::string& err);

bool CheckChain(const std::string& network, btcswap::Chain& chain, std::string& err);
void Watch(const CScript& contract);
bool Call(const std::string& method, const nlohmann::json& params, nlohmann::json& result, std::string& err);
nlohmann::json Find(const CScript& contract, const std::string& ref, bool secret);
int SelfTest();
}
#endif
