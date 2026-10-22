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
static Header Decode(const Bytes& raw)
{
    if (raw.size() != 80) throw std::runtime_error("Bitcoin header must be 80 bytes");
    Header h; h.raw = raw; h.hash = Digest(raw); h.prev = ReadHash(raw, 4); h.merkle = ReadHash(raw, 36);
    h.time = (unsigned int)LE(raw, 68, 4); h.bits = (unsigned int)LE(raw, 72, 4); return h;
}
static Bytes Genesis(const std::string& network)
{
    Bytes b; Put(b, 1, 4); b.resize(36, 0);
    // TODO: independently verify the main/testnet4 checkpoint and replace height
    // zero with a recent retarget-boundary checkpoint plus its preceding MTP
    // context and filter-header anchor before shipping a fast initial sync.
    uint256 merkle(network == "testnet4" ? "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
                                           : "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    HashBytes(b, merkle);
    Put(b, network == "main" ? 1231006505 : network == "testnet4" ? 1714777860 : 1296688602, 4);
    Put(b, network == "regtest" ? 0x207fffff : 0x1d00ffff, 4);
    Put(b, network == "main" ? 2083236893 : network == "testnet4" ? 393743547 : 2, 4);
    return b;
}
Headers::Headers(const std::string& net) : network(net)
{
    if (net != "main" && net != "testnet4" && net != "regtest") throw std::runtime_error("Bitcoin light supports main, testnet4 and regtest");
    Header h = Decode(Genesis(net));
    h.work = (Integer(1)<<256)/(Target(h.bits)+1);
    nodes[h.hash] = h; active.push_back(h.hash);
}
const Header& Headers::Tip() const { return nodes.at(active.back()); }
const Header& Headers::At(int height) const { return nodes.at(active.at(height)); }
bool Headers::Contains(const uint256& hash) const { return nodes.count(hash) != 0; }
int Headers::ActiveHeight(const uint256& hash) const
{
    auto it = nodes.find(hash);
    if (it == nodes.end() || it->second.height > Tip().height || At(it->second.height).hash != hash) return -1;
    return it->second.height;
}
int64 Headers::Median(const Header& header) const
{
    std::vector<unsigned int> times;
    const Header* h = &header;
    for (int i = 0; i < 11; ++i)
    {
        times.push_back(h->time);
        if (!h->height) break;
        h = &nodes.at(h->prev);
    }
    std::sort(times.begin(), times.end()); return times[times.size()/2];
}
unsigned int Headers::NextBits(const Header& parent, unsigned int time) const
{
    if (network == "regtest") return parent.bits;
    int next = parent.height+1;
    if (next % 2016)
    {
        if (network == "main") return parent.bits;
        if ((int64)time > (int64)parent.time+1200) return 0x1d00ffff;
        const Header* h = &parent;
        while (h->height % 2016 && h->bits == 0x1d00ffff) h = &nodes.at(h->prev);
        return h->bits;
    }
    const Header* first = &parent;
    for (int i = 0; i < 2015; ++i) first = &nodes.at(first->prev);
    // BIP94 preserves the first block's difficulty across testnet4 periods.
    return Retarget(network == "testnet4" ? first->bits : parent.bits, (int64)parent.time-first->time, 0x1d00ffff);
}
bool Headers::Add(const Bytes& raw, std::string& err)
{
    try
    {
        Header h = Decode(raw);
        if (nodes.count(h.hash)) return true;
        std::map<uint256, Header>::const_iterator it = nodes.find(h.prev);
        if (it == nodes.end()) throw std::runtime_error("unknown Bitcoin header parent");
        const Header& p = it->second;
        Integer target = Target(h.bits), limit = Target(network == "regtest" ? 0x207fffff : 0x1d00ffff);
        if (target <= 0 || target > limit || Number(h.hash) > target) throw std::runtime_error("invalid Bitcoin proof of work");
        if (h.bits != NextBits(p, h.time)) throw std::runtime_error("invalid Bitcoin difficulty");
        if (h.time <= Median(p) || (int64)h.time > GetTime()+7200) throw std::runtime_error("invalid Bitcoin header time");
        if (network == "testnet4" && (p.height+1)%2016 == 0 && (int64)h.time < (int64)p.time-600)
            throw std::runtime_error("testnet4 timewarp");
        h.height = p.height+1; h.work = p.work+(Integer(1)<<256)/(target+1);
        nodes[h.hash] = h;
        if (h.work > Tip().work)
        {
            active.resize(h.height+1,uint256(0));
            const Header* walk = &nodes.at(h.hash);
            while (active[walk->height] != walk->hash)
            {
                active[walk->height] = walk->hash;
                if (!walk->height) break;
                walk = &nodes.at(walk->prev);
            }
        }
        return true;
    }
    catch (const std::exception& e) { err = e.what(); return false; }
}
std::vector<uint256> Headers::Locator() const
{
    std::vector<uint256> out;
    int step = 1, h = Tip().height;
    for (;;) { out.push_back(At(h).hash); if (!h) break; h = std::max(0, h-step); if (out.size() > 10) step *= 2; }
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
    script.clear(); Bytes base;
    if (DecodeBase58Check(addr, base) && base.size() == 21)
    {
        Bytes hash(base.begin()+1, base.end());
        if (base[0] == chain.pkhVersion) { script << OP_DUP << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG; return true; }
        if (base[0] == chain.shVersion) { script << OP_HASH160 << hash << OP_EQUAL; return true; }
    }
    std::string lower = addr; bool upper = false, small = false;
    for (size_t i = 0; i < lower.size(); ++i) { if (lower[i] >= 'A' && lower[i] <= 'Z') upper = true; if (lower[i] >= 'a' && lower[i] <= 'z') small = true; lower[i] = (char)tolower((unsigned char)lower[i]); }
    size_t sep = lower.rfind('1');
    std::string hrp = chain.fMain ? "bc" : chain.name == "regtest" ? "bcrt" : "tb";
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
    err = "invalid Bitcoin destination or wrong network"; return false;
}

struct Peer
{
    SOCKET socket = INVALID_SOCKET;
    std::string identity;
    unsigned int magic;
    explicit Peer(unsigned int m) : magic(m) {}
    ~Peer() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    void Transfer(unsigned char* data, size_t size, bool writing)
    {
        while (size && !fShutdown)
        {
            int n = writing ? send(socket, (const char*)data, (int)size, 0) : recv(socket, (char*)data, (int)size, 0);
            if (n <= 0) throw std::runtime_error("Bitcoin peer disconnected or timed out");
            data += n; size -= n;
        }
        if (size) throw std::runtime_error("Bitcoin light shutting down");
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
            if (LE(header, 0, 4) != magic) throw std::runtime_error("wrong Bitcoin message magic");
            size_t length = (size_t)LE(header, 16, 4);
            if (length > 4000000 || length > budget) throw std::runtime_error("oversized Bitcoin message");
            budget -= length;
            std::string command;
            bool ended = false;
            for (int i = 4; i < 16; ++i)
            {
                if (!header[i]) ended = true;
                else if (ended || header[i] < 32 || header[i] > 126) throw std::runtime_error("invalid Bitcoin command");
                else command += (char)header[i];
            }
            Bytes payload(length); if (length) Transfer(&payload[0], length, false);
            uint256 hash = Digest(payload);
            if (!std::equal(hash.begin(), hash.begin()+4, header.begin()+20)) throw std::runtime_error("Bitcoin checksum mismatch");
            if (command == wanted) return payload;
            if (command == "ping") { if (length != 8) throw std::runtime_error("invalid ping"); Send("pong", payload); }
            if (command == "reject" || command == "notfound") throw std::runtime_error("Bitcoin peer rejected request");
        }
        throw std::runtime_error("Bitcoin peer did not answer request");
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
                throw std::runtime_error("invalid -btcpeer port");
            port = (unsigned short)atoi(text.c_str()); host = spec.substr(0, colon);
        }
        if (host.size() > 2 && host[0] == '[' && host.back() == ']') host = host.substr(1, host.size()-2);
        // Separate nodes on one host can listen on different P2P ports.
        identity = host + ":" + strprintf("%u", (unsigned int)port);
        socket = BtfConnectSocket(host, port, 0, 15);
        if (socket == INVALID_SOCKET) throw std::runtime_error("cannot connect to Bitcoin peer " + spec);
#ifdef _WIN32
        DWORD timeout = 15000;
#else
        struct timeval timeout = {15, 0};
#endif
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        Bytes version; Put(version, 70016, 4); Put(version, 0, 8); Put(version, GetTime(), 8);
        version.resize(72, 0); uint64_t nonce; randombytes_buf(&nonce, sizeof(nonce)); Put(version, nonce, 8);
        std::string agent = "/Bitflash:btc-light/"; Compact(version, agent.size()); version.insert(version.end(), agent.begin(), agent.end());
        Put(version, 0, 4); version.push_back(0);
        Send("version", version); Bytes theirs = Receive("version");
        if (theirs.size() < 80 || LE(theirs, 0, 4) < 70015 || !(LE(theirs, 4, 8)&64))
            throw std::runtime_error("Bitcoin peer lacks NODE_COMPACT_FILTERS");
        if (LE(theirs, 72, 8) == nonce) throw std::runtime_error("Bitcoin self connection");
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
    bool synced = false;
    explicit State(const std::string& net) : headers(net), path(std::string(GetAppDir())+"/btc-light-"+net) {}
};
static State* state = NULL;
static std::mutex startMutex;
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
        while (f.read((char*)raw.data(), 80)) if (!s.headers.Add(raw, err)) throw std::runtime_error("Bitcoin header store: "+err);
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
        if (j.value("version",0) != 1 || j.value("network",std::string()) != s.headers.network) throw std::runtime_error("wrong Bitcoin state network/version");
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
        if (!(LE(b,pos+4,8)&64)) continue;
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
static void Round(State& s, Peer& primary, Peer* second)
{
    std::unique_lock<std::recursive_mutex> lock(s.mutex);
    Bytes request; Put(request,70016,4); std::vector<uint256> locator = s.headers.Locator(); Compact(request,locator.size());
    for (size_t i = 0; i < locator.size(); ++i) HashBytes(request,locator[i]); HashBytes(request,uint256(0));
    Bytes response = Fetch(primary,"getheaders",request,"headers",lock);
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
    Reconcile(s);
    if (s.filters.size() < s.savedFilters) SaveFilters(s);
    // A fresh timestamp alone is cheap to forge near genesis. Do not expose
    // payments until the chain has independently accumulated modern work.
    // TODO: independently verify these minimum-work anchors with checkpoints.
    Integer minimum = s.headers.network == "main"
        ? Number(uint256("000000000000000000000000000000000000000145ec036acc5ba740052af1a0"))
        : s.headers.network == "testnet4"
        ? Number(uint256("000000000000000000000000000000000000000000000e346a558455ade8eca9")) : Integer(0);
    s.synced = n < 2000 && s.headers.Tip().work >= minimum &&
        (s.headers.network == "regtest" || (int64)s.headers.Tip().time > GetTime()-7200);
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
static std::vector<std::string> ConfiguredPeers()
{
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
        if (arg.compare(0,9,"-btcpeer=") == 0)
        {
            std::string peer = arg.substr(9);
            if (peer.empty() || peer.size() > 300) throw std::runtime_error("invalid -btcpeer");
            if (std::find(peers.begin(),peers.end(),peer) == peers.end()) peers.push_back(peer);
        }
    return peers;
}

static void Worker(State* s)
{
    unsigned short port = s->headers.network == "main" ? 8333 : s->headers.network == "testnet4" ? 48333 : 18444;
    unsigned int magic = s->headers.network == "main" ? 0xd9b4bef9 : s->headers.network == "testnet4" ? 0x283f161c : 0xdab5bffa;
    size_t rotation = 0;
    while (!fShutdown)
    {
        try
        {
            // Configure can run before managed Tor finishes starting. Wait
            // here instead of ever leaking a seed or peer connection directly.
            if (s->headers.network != "regtest" && !BtfTorProxyEnabled())
                throw std::runtime_error("Bitcoin light is waiting for the wallet's Tor proxy");
            std::vector<std::string> choices;
            // Explicit peers suppress seeds, which makes regtest deterministic.
            std::vector<std::string> configured = ConfiguredPeers();
            if (!configured.empty()) choices = configured;
            else
            {
                std::lock_guard<std::recursive_mutex> lock(s->mutex); choices = s->peers;
                if (s->headers.network == "main")
                {
                    choices.push_back("x49.seed.bitcoin.sprovoost.nl"); choices.push_back("x49.dnsseed.emzy.de"); choices.push_back("x49.seed.mainnet.achownodes.xyz");
                }
                else if (s->headers.network == "testnet4")
                {
                    choices.push_back("x49.seed.testnet4.bitcoin.sprovoost.nl"); choices.push_back("x49.seed.testnet4.wiz.biz");
                }
            }
            if (choices.empty()) throw std::runtime_error("regtest needs -btcpeer=host:port");
            Peer primary(magic); primary.Connect(choices[rotation++%choices.size()],port);
            std::unique_ptr<Peer> second;
            for (size_t i = 0; i < std::min<size_t>(choices.size(),4); ++i)
            {
                std::unique_ptr<Peer> candidate(new Peer(magic));
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
                { std::lock_guard<std::recursive_mutex> lock(s->mutex); s->error.clear(); synced = s->synced && (s->watched.empty() || s->scan >= (int)s->filters.size()); }
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
bool CheckChain(const std::string& network, btcswap::Chain& out, std::string& err)
{
    try
    {
        if ((network == "main") == IsTestNet()) throw std::runtime_error("Bitcoin and Bitflash networks must match");
        std::lock_guard<std::mutex> start(startMutex);
        if (!state)
        {
            std::unique_ptr<State> initial(new State(network)); Load(*initial);
            state = initial.release(); std::thread(Worker,state).detach();
        }
        if (network != state->headers.network) throw std::runtime_error("restart wallet to change Bitcoin light network");
        std::lock_guard<std::recursive_mutex> lock(state->mutex);
        out.name = network; out.fMain = network == "main"; out.pkhVersion = out.fMain ? 0 : 111; out.shVersion = out.fMain ? 5 : 196;
        out.nBlocks = state->headers.Tip().height; out.nMedianTime = state->headers.Median(state->headers.Tip());
        return true;
    }
    catch (const std::exception& e) { err = e.what(); return false; }
}
void Watch(const CScript& contract)
{
    if (!state) throw std::runtime_error("Bitcoin light not initialized");
    CScript script; script.SetPayToScriptHash(contract); Bytes b(script.begin(),script.end());
    std::lock_guard<std::recursive_mutex> lock(state->mutex);
    if (state->watched.insert(b).second)
    {
        if (!state->birthday) state->birthday = GetTime()-7*86400;
        // New contracts can already have a funding transaction in a recent
        // block. Existing watches retain their cursor across restarts.
        state->scan = std::min(state->scan,std::max(0,state->headers.Tip().height-400)); Save(*state);
    }
}
struct Located { CTransaction tx; int height; };
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

json Find(const CScript& contract, const std::string& ref, bool secret)
{
    Watch(contract); std::lock_guard<std::recursive_mutex> lock(state->mutex); State& s = *state;
    if (!s.error.empty()) throw std::runtime_error(s.error);
    if (!s.synced || s.scan < s.headers.Tip().height+1) throw std::runtime_error("Bitcoin light is synchronizing headers and contract filters");
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
        CTransaction tx; if (!IsHex(ref) || !btcswap::ParseTx(ParseHex(ref),tx)) throw std::runtime_error("invalid Bitcoin contract reference"); txid = tx.GetHash();
    }
    auto funding = txs.find(txid);
    if (funding != txs.end() && output < 0)
        for (size_t n = 0; n < funding->second.tx.vout.size(); ++n) if (funding->second.tx.vout[n].scriptPubKey == script) { output = (int)n; break; }
    json j = {{"contractTxid",txid.GetHex()},{"vout",output},{"unspent",false},{"confirmations",0},{"amount",nullptr},{"spent",false},{"found",false}};
    if (funding == txs.end() || output < 0) return j;
    if ((size_t)output >= funding->second.tx.vout.size() || funding->second.tx.vout[output].scriptPubKey != script) throw std::runtime_error("Bitcoin output does not pay this contract");
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
bool Call(const std::string& method, const json& params, json& result, std::string& err)
{
    try
    {
        if (!state) throw std::runtime_error("Bitcoin light not initialized");
        State& s = *state; std::lock_guard<std::recursive_mutex> lock(s.mutex);
        if (method == "getblockchaininfo")
        {
            result = {{"chain",s.headers.network},{"blocks",s.headers.Tip().height},{"mediantime",s.headers.Median(s.headers.Tip())},
                      {"initialblockdownload",!s.synced},{"backend","light"},{"filters",s.filters.size()},{"scanned",s.scan},{"filterPeers",s.peersCompared},{"networkError",s.error}};
            return true;
        }
        if (method == "sendrawtransaction")
        {
            Bytes raw = ParseHex(params.at(0).get<std::string>()); CTransaction tx;
            if (!btcswap::ParseTx(raw,tx)) throw std::runtime_error("invalid Bitcoin transaction");
            s.pending[tx.GetHash()] = raw; Save(s); result = tx.GetHash().GetHex(); return true;
        }
        if (method == "getrawtransaction" || method == "gettransaction")
        {
            auto txs = Transactions(s); auto it = txs.find(uint256(params.at(0).get<std::string>()));
            if (it == txs.end()) throw std::runtime_error("Bitcoin transaction not found by contract filters");
            CDataStream stream(SER_NETWORK); stream << it->second.tx;
            result = HexStr(stream.begin(),stream.end(),false); if (method == "gettransaction") result = json{{"hex",result}};
            return true;
        }
        throw std::runtime_error("Bitcoin light has no wallet RPC: "+method);
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
} // namespace btclight
