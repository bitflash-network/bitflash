// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See btfchatnet.h.

#include "headers.h"
#include "btfchatnet.h"
#include "btfchatsock.h"
#include "btfchatbox.h"
#include "chatrelay.h"
#include "btfaddr.h"
#include "tor.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

// util.h redefines snprintf as a macro, which breaks nlohmann/json.
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <thread>

namespace btfchat
{

// The most a node's single message may make us allocate: the largest answer it
// is allowed to give, and some room around it.
static const unsigned int CLIENT_MAX_MESSAGE = CHAT_MAX_ANSWER_BYTES + 64 * 1024;
// Messages read while waiting for one answer before giving up on the node. A
// node pushes inventory and peers at a client too; a few hundred is plenty.
static const int MAX_MESSAGES_PER_AWAIT = 500;
// How long one Tor connection to a node may take, and any one read on it.
static const int NODE_DIAL_TIMEOUT = 45;
static const int NODE_IO_TIMEOUT = 45;
// Nodes that must keep a record before a publish counts as done, and nodes
// asked before a query is answered. Two, so that one node restarting -- which
// forgets everything -- is not the same as the message being gone.
static const int PUBLISH_COPIES = 2;
static const int QUERY_ANSWERS = 2;
// Nodes tried per round before giving up.
static const size_t NODES_PER_ROUND = 5;
// Nodes remembered. Every descriptor a node hands us is checked, but there is
// still no reason to let anybody grow this without end.
static const size_t MAX_KNOWN_NODES = 128;
// How long a resolved descriptor is reused before asking again.
static const int64 RESOLVE_CACHE_SECS = 10 * 60;

// ---- framing -----------------------------------------------------------------

NodeLink::NodeLink(Stream& sIn)
    : s(sIn), nFraming(PROTO_NO_CHECKSUM_VERSION), nPeerVersion(0), nServices(0), nNextReq(0)
{
    randombytes_buf(&nNextReq, sizeof(nNextReq));
}

static std::vector<unsigned char> Bytes(const CDataStream& ss)
{
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool NodeLink::Send(const char* pszCommand, const std::vector<unsigned char>& payload)
{
    CMessageHeader hdr(pszCommand, (unsigned int)payload.size());
    if (nFraming >= PROTO_CHECKSUM_VERSION)
    {
        static const unsigned char zero = 0;
        const unsigned char* p = payload.empty() ? &zero : &payload[0];
        uint256 h = Hash(p, p + payload.size());
        memcpy(&hdr.nChecksum, &h, sizeof(hdr.nChecksum));
    }
    CDataStream hs(SER_NETWORK, nFraming);
    hs << hdr;
    std::vector<unsigned char> out(hs.begin(), hs.end());
    out.insert(out.end(), payload.begin(), payload.end());
    return s.Write(&out[0], out.size());
}

bool NodeLink::Recv(std::string& strCommand, std::vector<unsigned char>& payload,
                    std::string& errOut)
{
    unsigned int nHdr = CMessageHeader::SizeOnWire(nFraming);
    unsigned char hb[24];
    if (!s.Read(hb, nHdr))
    {
        errOut = "the node closed the connection";
        return false;
    }
    CDataStream hs(SER_NETWORK, nFraming);
    hs.write((const char*)hb, nHdr);
    CMessageHeader hdr;
    hs >> hdr;
    if (!hdr.IsValid())
    {
        // Wrong magic is a node of the other network, or not a node at all.
        errOut = "that is not a Bitflash node of this network";
        return false;
    }
    if (hdr.nMessageSize > CLIENT_MAX_MESSAGE)
    {
        errOut = "the node sent a message larger than any answer can be";
        return false;
    }
    payload.assign(hdr.nMessageSize, 0);
    if (hdr.nMessageSize > 0 && !s.Read(&payload[0], payload.size()))
    {
        errOut = "the node closed the connection mid-message";
        return false;
    }
    if (nFraming >= PROTO_CHECKSUM_VERSION)
    {
        static const unsigned char zero = 0;
        const unsigned char* p = payload.empty() ? &zero : &payload[0];
        uint256 h = Hash(p, p + payload.size());
        unsigned int nCheck = 0;
        memcpy(&nCheck, &h, sizeof(nCheck));
        if (nCheck != hdr.nChecksum)
        {
            errOut = "a message from the node arrived damaged";
            return false;
        }
    }
    strCommand = hdr.GetCommand();
    return true;
}

bool NodeLink::Handshake(std::string& errOut)
{
    // In the framing every node understands, saying we hold no chain and no
    // chat records: we are asking, not serving.
    CDataStream p(SER_NETWORK, PROTO_NO_CHECKSUM_VERSION);
    p << VERSION << (uint64)0 << (int64)GetTime() << CAddress() << (int)0
      << std::string(BITFLASH_VERSION_STRING);
    if (!Send("version", Bytes(p)))
    {
        errOut = "could not send to the node";
        return false;
    }

    std::string cmd;
    std::vector<unsigned char> pay;
    if (!Recv(cmd, pay, errOut))
        return false;
    if (cmd != "version")
    {
        errOut = "the node did not introduce itself";
        return false;
    }
    try
    {
        CDataStream v(pay, SER_NETWORK, PROTO_NO_CHECKSUM_VERSION);
        int64 nTime = 0;
        CAddress addrMe;
        uint64 services = 0;
        v >> nPeerVersion >> services >> nTime >> addrMe;
        nServices = services;
    }
    catch (std::exception&)
    {
        errOut = "the node's version message did not parse";
        return false;
    }
    if (nPeerVersion <= 0)
    {
        errOut = "the node's version message is empty";
        return false;
    }
    // The node moves to the lower of the two versions as soon as it reads
    // ours, so everything after this point is framed that way in both
    // directions.
    nFraming = std::min(nPeerVersion, VERSION);

    if (!(nServices & NODE_CHAT))
    {
        errOut = "that node does not hold chat records (it runs an older release)";
        return false;
    }
    return true;
}

bool NodeLink::Await(const char* pszReply, unsigned int nReq,
                     std::vector<unsigned char>& payload, std::string& errOut)
{
    for (int i = 0; i < MAX_MESSAGES_PER_AWAIT; i++)
    {
        std::string cmd;
        if (!Recv(cmd, payload, errOut))
            return false;
        if (cmd == "btfpeers")
        {
            try
            {
                CDataStream ss(payload, SER_NETWORK, nFraming);
                std::vector<std::string> v;
                ss >> v;
                for (size_t k = 0; k < v.size() && vPex.size() < 64; k++)
                    vPex.push_back(v[k]);
            }
            catch (std::exception&) {}
            continue;
        }
        if (cmd != pszReply || payload.size() < 4)
            continue;
        unsigned int n = (unsigned int)payload[0] | ((unsigned int)payload[1] << 8) |
                         ((unsigned int)payload[2] << 16) | ((unsigned int)payload[3] << 24);
        if (n != nReq)
            continue;
        return true;
    }
    errOut = "the node never answered the question";
    return false;
}

void NodeLink::CollectPeers(int nMaxMessages)
{
    if (nPeerVersion <= 0)
        return;
    // The handshake stopped before switching framing; the node did not.
    nFraming = std::min(nPeerVersion, VERSION);
    size_t nBefore = vPex.size();
    for (int i = 0; i < nMaxMessages && vPex.size() == nBefore; i++)
    {
        std::string cmd, err;
        std::vector<unsigned char> payload;
        if (!Recv(cmd, payload, err))
            return;
        if (cmd != "btfpeers")
            continue;
        try
        {
            CDataStream ss(payload, SER_NETWORK, nFraming);
            std::vector<std::string> v;
            ss >> v;
            for (size_t k = 0; k < v.size() && vPex.size() < 64; k++)
                vPex.push_back(v[k]);
        }
        catch (std::exception&) {}
        return;
    }
}

bool NodeLink::Put(const ChatRecord& r, int& nResultOut, std::string& whyOut,
                   std::string& errOut)
{
    nResultOut = ChatStore::REJECTED;
    whyOut.clear();
    unsigned int nReq = nNextReq++;
    CDataStream p(SER_NETWORK, nFraming);
    p << nReq << r.Serialize();
    if (!Send("chatput", Bytes(p)))
    {
        errOut = "could not send to the node";
        return false;
    }
    std::vector<unsigned char> pay;
    if (!Await("chatack", nReq, pay, errOut))
        return false;
    try
    {
        CDataStream a(pay, SER_NETWORK, nFraming);
        unsigned int nEcho = 0;
        std::vector<unsigned char> vId;
        a >> nEcho >> vId >> nResultOut >> whyOut;
        if (whyOut.size() > 200)
            whyOut.resize(200);
    }
    catch (std::exception&)
    {
        errOut = "the node's answer did not parse";
        return false;
    }
    return true;
}

bool NodeLink::Get(const std::vector<CChatQuery>& vQuery,
                   std::vector<std::vector<ChatRecord> >& out, std::string& errOut)
{
    out.clear();
    for (size_t at = 0; at < vQuery.size(); at += CHAT_MAX_QUERIES_PER_MSG)
    {
        size_t nEnd = std::min(vQuery.size(), at + (size_t)CHAT_MAX_QUERIES_PER_MSG);
        std::vector<CChatQuery> part(vQuery.begin() + at, vQuery.begin() + nEnd);
        unsigned int nReq = nNextReq++;
        CDataStream p(SER_NETWORK, nFraming);
        p << nReq << part;
        if (!Send("chatget", Bytes(p)))
        {
            errOut = "could not send to the node";
            return false;
        }
        std::vector<unsigned char> pay;
        if (!Await("chatrecs", nReq, pay, errOut))
            return false;
        std::vector<std::vector<std::vector<unsigned char> > > vAnswer;
        try
        {
            CDataStream a(pay, SER_NETWORK, nFraming);
            unsigned int nEcho = 0;
            a >> nEcho >> vAnswer;
        }
        catch (std::exception&)
        {
            errOut = "the node's answer did not parse";
            return false;
        }
        for (size_t i = 0; i < part.size(); i++)
        {
            std::vector<ChatRecord> recs;
            if (i < vAnswer.size())
            {
                for (size_t k = 0; k < vAnswer[i].size() && recs.size() < CHATREC_MAX_QUERY; k++)
                {
                    ChatRecord r;
                    const std::vector<unsigned char>& w = vAnswer[i][k];
                    // A node answers what it likes; only what parses, is of the
                    // kind asked and is filed under the key asked is kept.
                    if (w.empty() || !r.Parse(&w[0], w.size()))
                        continue;
                    if (r.kind != part[i].kind || r.key != part[i].key)
                        continue;
                    recs.push_back(r);
                }
            }
            out.push_back(recs);
        }
    }
    return true;
}

// ---- the nodes we know -------------------------------------------------------

struct KnownNode
{
    int64 nLastOk;
    int64 nLastFail;
    int nFails;
    int64 nNoChatUntil;
    bool fSeed;
    KnownNode() : nLastOk(0), nLastFail(0), nFails(0), nNoChatUntil(0), fSeed(false) {}
};

static CCriticalSection cs_nodes;
static std::map<std::string, KnownNode> g_nodes;

static secp256k1_context* Ctx()
{
    static secp256k1_context* ctx = NULL;
    static CCriticalSection cs_ctx;
    CRITICAL_BLOCK(cs_ctx)
        if (!ctx)
        {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            unsigned char rnd[32];
            randombytes_buf(rnd, sizeof(rnd));
            if (ctx && !secp256k1_context_randomize(ctx, rnd))
            {
                secp256k1_context_destroy(ctx);
                ctx = NULL;
            }
        }
    return ctx;
}

static void EnsureSeeds()
{
    std::vector<std::string> v;
    BtfSeedOnions(v);
    CRITICAL_BLOCK(cs_nodes)
        for (size_t i = 0; i < v.size(); i++)
            g_nodes[v[i]].fSeed = true;
}

// Descriptors a node handed us. Each is checked against the key it names; the
// ones that verify and name an onion of this network are remembered.
static void LearnNodes(const std::vector<std::string>& vDesc)
{
    secp256k1_context* ctx = Ctx();
    if (!ctx)
        return;
    for (size_t i = 0; i < vDesc.size(); i++)
    {
        if (vDesc[i].empty() || vDesc[i].size() > 4096)
            continue;
        unsigned char pubkey[32];
        try
        {
            nlohmann::json v = nlohmann::json::parse(vDesc[i]);
            if (!v.is_object() || !v.contains("pubkey") || !v["pubkey"].is_string())
                continue;
            std::string hex = v["pubkey"].get<std::string>();
            if (hex.size() != 64 || sodium_hex2bin(pubkey, 32, hex.c_str(), hex.size(),
                                                   NULL, NULL, NULL) != 0)
                continue;
        }
        catch (...) { continue; }
        btf::Descriptor d;
        if (!btf::VerifyDescriptor(ctx, vDesc[i], pubkey, d))
            continue;
        std::string onion;
        if (d.onion.empty() || !btf::NormalizeOnionEndpoint(d.onion, onion))
            continue;
        if (!BtfOnionFitsThisNetwork(onion))
            continue;
        CRITICAL_BLOCK(cs_nodes)
            if (g_nodes.count(onion) || g_nodes.size() < MAX_KNOWN_NODES)
                g_nodes[onion];
    }
}

static void NoteOk(const std::string& onion)
{
    CRITICAL_BLOCK(cs_nodes)
    {
        KnownNode& k = g_nodes[onion];
        k.nLastOk = GetTime();
        k.nFails = 0;
    }
    // A node answered over Tor: proof Tor carries connections end to end. The
    // chat build has no peers to count, so its Tor watchdog relies on hearing
    // this -- it used to come from the Nostr relays, which the chat no longer
    // talks to, and without it the watchdog would move Tor onto bridges for no
    // reason.
    BtfTorNoteNetworkReached();
}

static void NoteFail(const std::string& onion, bool fNoChat)
{
    CRITICAL_BLOCK(cs_nodes)
    {
        KnownNode& k = g_nodes[onion];
        k.nLastFail = GetTime();
        k.nFails++;
        // A node from before the chat will not grow chat records by itself;
        // ask again in a few hours, in case it was upgraded.
        if (fNoChat)
            k.nNoChatUntil = GetTime() + 6 * 60 * 60;
    }
    // A node that is merely too old still answered over Tor: Tor works. Not
    // saying so let the watchdog decide Tor was blocked and restart it onto
    // bridges while every node it could reach was simply 1.2.28 -- seen on the
    // first live run against mainnet.
    if (fNoChat)
        BtfTorNoteNetworkReached();
}

// Up to `n` nodes worth trying now: the ones that answered lately first, the
// rest in random order, and none that is backing off.
static void PickNodes(size_t n, std::vector<std::string>& out)
{
    EnsureSeeds();
    out.clear();
    int64 nNow = GetTime();
    std::vector<std::string> good, other;
    CRITICAL_BLOCK(cs_nodes)
        for (std::map<std::string, KnownNode>::const_iterator it = g_nodes.begin();
             it != g_nodes.end(); ++it)
        {
            const KnownNode& k = it->second;
            if (k.nNoChatUntil > nNow)
                continue;
            int nShift = std::min(k.nFails, 6);
            if (k.nFails > 0 && k.nLastFail + (int64)(30 << nShift) > nNow)
                continue;
            if (k.nLastOk > nNow - 60 * 60)
                good.push_back(it->first);
            else
                other.push_back(it->first);
        }
    // Shuffle both, so the load and what any one node sees are spread.
    for (size_t i = good.size(); i > 1; i--)
        std::swap(good[i - 1], good[randombytes_uniform((uint32_t)i)]);
    for (size_t i = other.size(); i > 1; i--)
        std::swap(other[i - 1], other[randombytes_uniform((uint32_t)i)]);
    for (size_t i = 0; i < good.size() && out.size() < n; i++)
        out.push_back(good[i]);
    for (size_t i = 0; i < other.size() && out.size() < n; i++)
        out.push_back(other[i]);
}

// Nodes tried in one round, at most. A round that keeps learning new nodes from
// old ones would otherwise walk the whole network over Tor before giving up.
static const size_t MAX_NODES_PER_ROUND = 10;

// Top up a round's candidates with nodes learned during it -- typically from
// the peer list of a node too old to hold chat records itself. False when
// there is nothing new to try, or the round has tried enough.
static bool MoreNodes(std::vector<std::string>& cand, std::set<std::string>& tried)
{
    if (cand.size() >= MAX_NODES_PER_ROUND)
        return false;
    std::vector<std::string> more;
    PickNodes(MAX_NODES_PER_ROUND, more);
    bool fAdded = false;
    for (size_t i = 0; i < more.size() && cand.size() < MAX_NODES_PER_ROUND; i++)
        if (tried.insert(more[i]).second)
        {
            cand.push_back(more[i]);
            fAdded = true;
        }
    return fAdded;
}

void NetNodeCounts(size_t& nKnown, size_t& nGood)
{
    EnsureSeeds();
    nKnown = nGood = 0;
    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_nodes)
        for (std::map<std::string, KnownNode>::const_iterator it = g_nodes.begin();
             it != g_nodes.end(); ++it)
        {
            nKnown++;
            if (it->second.nLastOk > nNow - 60 * 60)
                nGood++;
        }
}

// Nodes dialled at the same time. One at a time was what made the first live
// run on testnet take eight minutes for one answer: the peer lists it learned
// were full of onions that no longer exist, and each one cost a full Tor
// timeout before the next was tried. Four in flight bounds a round by the
// slowest of four, not the sum of ten.
static const size_t DIAL_PARALLEL = 4;

// One node, dialled and introduced, or the reason it was not.
struct Dialed
{
    btf_socket_t sock;
    SocketStream* st;
    NodeLink* link;
    bool fShook;
    bool fNoChat;
    std::string err;
    Dialed() : sock(INVALID_SOCKET), st(NULL), link(NULL), fShook(false), fNoChat(false) {}
    ~Dialed()
    {
        delete link;
        delete st;
        if (sock != INVALID_SOCKET)
            closesocket(sock);
    }
};

static void DialOne(const std::string& onion, Dialed& d)
{
    if (!ChatDialOnion(onion, NODE_DIAL_TIMEOUT, d.sock, d.err))
        return;
    d.st = new SocketStream(d.sock, NODE_IO_TIMEOUT);
    d.link = new NodeLink(*d.st);
    if (d.link->Handshake(d.err))
    {
        d.fShook = true;
        return;
    }
    d.fNoChat = d.link->Services() != 0 && !(d.link->Services() & NODE_CHAT);
    if (d.fNoChat)
        d.link->CollectPeers(20);
}

// Run `use` on nodes until `nWanted` of them count. `use` returns 1 when the
// node did what was asked, 0 when it answered but that answer does not count
// (a refusal), -1 when the exchange failed. Dials in parallel batches, and
// tops the list up with nodes learned on the way. Returns how many counted.
template <typename F>
static int WithNodes(int nWanted, F use, std::string& strLastErr)
{
    std::vector<std::string> cand;
    PickNodes(NODES_PER_ROUND, cand);
    std::set<std::string> tried(cand.begin(), cand.end());
    int nDone = 0;
    size_t at = 0;
    while (nDone < nWanted && !fShutdown)
    {
        if (at >= cand.size() && !MoreNodes(cand, tried))
            break;
        size_t nEnd = std::min(cand.size(), at + DIAL_PARALLEL);
        std::vector<std::string> batch(cand.begin() + at, cand.begin() + nEnd);
        at = nEnd;

        std::vector<Dialed> d(batch.size());
        std::vector<std::thread> th;
        for (size_t i = 0; i < batch.size(); i++)
            th.push_back(std::thread(DialOne, std::cref(batch[i]), std::ref(d[i])));
        for (size_t i = 0; i < th.size(); i++)
            th[i].join();

        for (size_t i = 0; i < batch.size(); i++)
        {
            if (!d[i].fShook)
            {
                NoteFail(batch[i], d[i].fNoChat);
                strLastErr = d[i].err;
            }
            else if (nDone < nWanted)
            {
                std::string err;
                int n = use(*d[i].link, batch[i], err);
                if (n < 0)
                {
                    NoteFail(batch[i], false);
                    strLastErr = err;
                }
                else
                {
                    NoteOk(batch[i]);
                    nDone += n;
                }
            }
            if (d[i].link)
                LearnNodes(d[i].link->PeerDescriptors());
        }
    }
    return nDone;
}

// ---- publish and query ---------------------------------------------------------

bool NetPublish(ChatRecord& r, std::string& errOut)
{
    errOut.clear();
    if (!ChatRecordWellFormed(r, errOut))
        return false;
    if (!ChatRecordHasWork(r))
    {
        // Seconds of one core, once. Aborted only by shutdown.
        if (!ChatRecordMine(r, (volatile bool*)&fShutdown))
        {
            errOut = "shutting down";
            return false;
        }
    }

    std::string strLastWhy, strLastErr;
    int nKept = WithNodes(PUBLISH_COPIES,
        [&](NodeLink& link, const std::string& onion, std::string& err) -> int
        {
            int nResult = ChatStore::REJECTED;
            std::string why;
            if (!link.Put(r, nResult, why, err))
                return -1;
            if (nResult == ChatStore::ACCEPTED || nResult == ChatStore::DUPLICATE)
                return 1;
            strLastWhy = why;
            LogPrint("btfchat", "btfchat: node %s refused a record: %s\n",
                     onion.c_str(), why.c_str());
            return 0;
        }, strLastErr);

    if (nKept > 0)
        return true;
    if (!strLastWhy.empty())
        errOut = "the nodes refused it: " + strLastWhy;
    else if (!strLastErr.empty())
        errOut = "no Bitflash node could be reached: " + strLastErr;
    else
        errOut = "no Bitflash node could be reached";
    return false;
}

bool NetQuery(const std::vector<CChatQuery>& vQuery,
              std::vector<std::vector<ChatRecord> >& out, std::string& errOut)
{
    errOut.clear();
    out.assign(vQuery.size(), std::vector<ChatRecord>());
    if (vQuery.empty())
        return true;

    std::vector<std::set<std::string> > seen(vQuery.size());
    std::string strLastErr;
    int nAnswered = WithNodes(QUERY_ANSWERS,
        [&](NodeLink& link, const std::string&, std::string& err) -> int
        {
            std::vector<std::vector<ChatRecord> > ans;
            if (!link.Get(vQuery, ans, err))
                return -1;
            for (size_t q = 0; q < ans.size() && q < out.size(); q++)
                for (size_t k = 0; k < ans[q].size(); k++)
                    if (seen[q].insert(ans[q][k].IdHex()).second)
                        out[q].push_back(ans[q][k]);
            return 1;
        }, strLastErr);

    if (nAnswered > 0)
        return true;
    errOut = strLastErr.empty() ? "no Bitflash node could be reached"
                                : "no Bitflash node could be reached: " + strLastErr;
    return false;
}

// ---- what the chat asks for ----------------------------------------------------

static CChatQuery Question(uint8_t kind, const unsigned char* key, size_t nKey,
                           int64 nSince, int nMax)
{
    CChatQuery q;
    q.kind = kind;
    q.key.assign(key, key + nKey);
    q.nSince = nSince;
    q.nMax = nMax;
    return q;
}

struct ResolvedDesc
{
    std::string onion;
    unsigned char enc[32];
    int64 nWhen;
};
static CCriticalSection cs_resolved;
static std::map<std::string, ResolvedDesc> g_resolved;

bool NetResolve(const std::string& chatAddr, std::string& onionOut,
                unsigned char encPubOut[32], std::string& errOut)
{
    errOut.clear();
    onionOut.clear();
    unsigned char pk[32];
    if (!btf::ParseAddress(chatAddr, pk))
    {
        errOut = "that is not a .btf address";
        return false;
    }

    int64 nNow = GetTime();
    CRITICAL_BLOCK(cs_resolved)
    {
        std::map<std::string, ResolvedDesc>::const_iterator it = g_resolved.find(chatAddr);
        if (it != g_resolved.end() && it->second.nWhen > nNow - RESOLVE_CACHE_SECS)
        {
            onionOut = it->second.onion;
            memcpy(encPubOut, it->second.enc, 32);
            return true;
        }
    }

    std::vector<CChatQuery> q(1, Question(CHATREC_DESC, pk, 32, 0, 1));
    std::vector<std::vector<ChatRecord> > ans;
    if (!NetQuery(q, ans, errOut))
        return false;

    // The newest that verifies against the address asked for. What a node
    // answers is a claim; the signature is what makes it true.
    secp256k1_context* ctx = Ctx();
    const ChatRecord* best = NULL;
    for (size_t k = 0; k < ans[0].size(); k++)
    {
        std::string why;
        if (memcmp(&ans[0][k].key[0], pk, 32) != 0)
            continue;
        if (!ChatRecordVerifySigned(ctx, ans[0][k], nNow, why))
            continue;
        if (!best || ans[0][k].nTime > best->nTime)
            best = &ans[0][k];
    }
    if (!best)
    {
        errOut = "that address has not published where to reach it";
        return false;
    }

    btf::Descriptor d;
    std::string js(best->payload.begin(), best->payload.end());
    std::string onion;
    if (!btf::VerifyDescriptor(ctx, js, pk, d) || !btf::NormalizeOnionEndpoint(d.onion, onion) ||
        d.enc.size() != 64 ||
        sodium_hex2bin(encPubOut, 32, d.enc.c_str(), d.enc.size(), NULL, NULL, NULL) != 0)
    {
        errOut = "that address's descriptor is malformed";
        return false;
    }
    onionOut = onion;

    CRITICAL_BLOCK(cs_resolved)
    {
        ResolvedDesc& r = g_resolved[chatAddr];
        r.onion = onionOut;
        memcpy(r.enc, encPubOut, 32);
        r.nWhen = nNow;
    }
    return true;
}

bool NetQueryEpochKeys(const std::string& chatAddr, std::string& annOut, std::string& errOut)
{
    errOut.clear();
    annOut.clear();
    unsigned char pk[32];
    if (!btf::ParseAddress(chatAddr, pk))
    {
        errOut = "that is not a .btf address";
        return false;
    }
    std::vector<CChatQuery> q(1, Question(CHATREC_EPOCH, pk, 32, 0, 1));
    std::vector<std::vector<ChatRecord> > ans;
    if (!NetQuery(q, ans, errOut))
        return false;

    secp256k1_context* ctx = Ctx();
    int64 nNow = GetTime();
    const ChatRecord* best = NULL;
    for (size_t k = 0; k < ans[0].size(); k++)
    {
        std::string why;
        if (!ChatRecordVerifySigned(ctx, ans[0][k], nNow, why))
            continue;
        if (!best || ans[0][k].nTime > best->nTime)
            best = &ans[0][k];
    }
    if (!best)
    {
        errOut = "no epoch keys published for that address";
        return false;
    }
    annOut.assign(best->payload.begin(), best->payload.end());
    return true;
}

static bool TagFromHex(const std::string& tagHex, unsigned char tag[CHATREC_TAG_KEY_BYTES])
{
    return tagHex.size() == CHATREC_TAG_KEY_BYTES * 2 &&
           sodium_hex2bin(tag, CHATREC_TAG_KEY_BYTES, tagHex.c_str(), tagHex.size(),
                          NULL, NULL, NULL) == 0;
}

bool NetPostEnvelope(const std::string& tagHex, const std::vector<unsigned char>& env,
                     std::string& errOut)
{
    errOut.clear();
    unsigned char tag[CHATREC_TAG_KEY_BYTES];
    if (!TagFromHex(tagHex, tag))
    {
        errOut = "malformed mailbox tag";
        return false;
    }
    if (env.empty() || env.size() > MAX_ENVELOPE_BYTES)
    {
        errOut = "that envelope is too big for a mailbox";
        return false;
    }
    ChatRecord r;
    r.kind = CHATREC_ENVELOPE;
    r.key.assign(tag, tag + CHATREC_TAG_KEY_BYTES);
    r.nTime = GetTime();
    r.payload = env;
    return NetPublish(r, errOut);
}

bool NetFetchEnvelopes(const std::vector<std::pair<std::string, int64_t> >& vTagSince,
                       std::map<std::string, std::vector<std::vector<unsigned char> > >& out,
                       std::string& errOut)
{
    errOut.clear();
    out.clear();
    std::vector<CChatQuery> q;
    std::vector<std::string> vTag;
    for (size_t i = 0; i < vTagSince.size(); i++)
    {
        unsigned char tag[CHATREC_TAG_KEY_BYTES];
        if (!TagFromHex(vTagSince[i].first, tag))
        {
            // Not skipped. Skipping made a call with only bad tags return
            // "answered" without asking any node -- which reads exactly like an
            // empty mailbox, and is how chat-live first caught it.
            errOut = "malformed mailbox tag";
            return false;
        }
        q.push_back(Question(CHATREC_ENVELOPE, tag, CHATREC_TAG_KEY_BYTES,
                             vTagSince[i].second, (int)CHATREC_MAX_QUERY));
        vTag.push_back(vTagSince[i].first);
    }
    if (q.empty())
        return true;
    std::vector<std::vector<ChatRecord> > ans;
    if (!NetQuery(q, ans, errOut))
        return false;
    for (size_t i = 0; i < ans.size() && i < vTag.size(); i++)
    {
        std::vector<std::vector<unsigned char> >& v = out[vTag[i]];
        for (size_t k = 0; k < ans[i].size(); k++)
            if (!ans[i][k].payload.empty() && ans[i][k].payload.size() <= MAX_ENVELOPE_BYTES)
                v.push_back(ans[i][k].payload);
    }
    return true;
}

bool NetPublishDescriptor(const unsigned char sign_sk[32], const std::string& encPubHex,
                          const std::string& onion, std::string& errOut)
{
    errOut.clear();
    if (onion.empty())
    {
        errOut = "the chat has no onion endpoint yet";
        return false;
    }
    if (encPubHex.size() != 64)
    {
        errOut = "the chat channel public key is malformed";
        return false;
    }
    secp256k1_context* ctx = Ctx();
    if (!ctx)
    {
        errOut = "secp256k1 context failed";
        return false;
    }
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpub;
    unsigned char pk[32];
    if (!secp256k1_keypair_create(ctx, &kp, sign_sk) ||
        !secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp) ||
        !secp256k1_xonly_pubkey_serialize(ctx, pk, &xpub))
    {
        sodium_memzero(&kp, sizeof(kp));
        errOut = "the chat signing key is not usable";
        return false;
    }
    sodium_memzero(&kp, sizeof(kp));

    // No meeting node: the chat is onion-only, like the rest of the network.
    int64 nCreated = GetTime();
    std::string desc = btf::SignDescriptor(ctx, sign_sk, encPubHex, "", (uint64_t)nCreated, onion);
    if (desc.empty())
    {
        errOut = "signing the chat descriptor failed";
        return false;
    }
    ChatRecord r;
    r.kind = CHATREC_DESC;
    r.key.assign(pk, pk + 32);
    r.nTime = nCreated;
    r.payload.assign(desc.begin(), desc.end());
    return NetPublish(r, errOut);
}

bool NetPublishEpochKeys(const std::string& chatAddr, const std::string& annJson,
                         int64_t nEpoch, std::string& errOut)
{
    errOut.clear();
    unsigned char pk[32];
    if (!btf::ParseAddress(chatAddr, pk))
    {
        errOut = "that is not a .btf address";
        return false;
    }
    if (annJson.empty())
    {
        errOut = "nothing to publish";
        return false;
    }
    ChatRecord r;
    r.kind = CHATREC_EPOCH;
    r.key.assign(pk, pk + 32);
    r.nTime = nEpoch * MAILBOX_EPOCH_SECONDS;
    r.payload.assign(annJson.begin(), annJson.end());
    return NetPublish(r, errOut);
}

} // namespace btfchat
