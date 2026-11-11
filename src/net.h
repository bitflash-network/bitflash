// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class CMessageHeader;
class CAddress;
class CInv;
class CRequestTracker;
class CNode;
// Defined in main.h, which is included after this file. Only ever used here as
// a pointer, so the forward declaration is enough.
class CBlockIndex;



static const unsigned short MAINNET_PORT = 8433;
static const unsigned short TESTNET_PORT = 18433;
static const unsigned int PUBLISH_HOPS = 5;
enum
{
    NODE_NETWORK = (1 << 0),
    // Holds and relays chat records (chatstore.h). Inventory of that kind is
    // only ever offered to a peer that says this, so a node from before the
    // chat never sees a type it would choke on.
    NODE_CHAT    = (1 << 1),
    // Holds and relays the P2Pool share chain (p2pool_net.h). Shares, and
    // asks for them, only go to a peer that says this: a node from before
    // P2Pool drops them unread, so a miner whose peers are all such nodes
    // hears no share at all. A P2Pool miner looks for peers with this bit.
    NODE_P2POOL  = (1 << 2),
};






bool GetMyExternalIP(unsigned int& ipRet);
bool IsTestNet();
unsigned short GetDefaultPort();
void SelectNetworkParams(bool fTestNetIn);
CNode* ConnectNodeBtf(const string& strBtfAddr);
CNode* ConnectNodeBtfResolved(const string& strBtfAddr, const string& strMeeting,
                              const string& strOnion, const unsigned char enc_pub[32],
                              const string& strDesc=string());
void ThreadBtfConnect(void* parg);
// Cached direct-onion endpoint (host.onion:port) for a .btf address, from peers
// we have reached before. True on a hit -- lets callers skip a Nostr resolve.
bool BtfCachedPeerOnion(const string& strBtfAddr, string& strOnionOut);
// P2Pool peers in the peer cache (net.cpp): what a dialled peer's version
// said about NODE_P2POOL; addresses another P2Pool node named, kept as hints
// for peers we know nothing about yet; and the ones we reached that hold the
// share chain, to name to other P2Pool nodes.
void BtfNoteP2PoolPeer(const string& strBtfAddr, bool fP2Pool);
void BtfNoteP2PoolHints(const vector<string>& vBtfAddr);
void BtfKnownP2PoolPeers(vector<string>& vOut, size_t nMax);
// The pinned onion seeds of the active network. The chat app starts from these
// the same way a node does: no server to ask first.
void BtfSeedOnions(vector<string>& vOut);
// False for an onion whose port says it belongs to the other network.
bool BtfOnionFitsThisNetwork(const string& strOnion);
extern string strBtfConnect;
extern bool fBtfIsolated;
// Bootstrap seeds added at runtime with /btfseed=ADDRESS:ENCHEX (repeatable).
// The compiled-in list lives in net.cpp; these are appended to it.
extern std::vector<std::pair<std::string, std::string> > vBtfExtraSeeds;
// Explicit IPv4 address for the P2P listener (-bindaddr). Empty means: loopback
// only when managed Tor is running, every interface otherwise. Needed when Tor
// runs on a different machine and has to reach this one over the network.
void BtfSetListenBindAddress(const string& strAddr);
string BtfListenBindAddress();
// The name this chain answers to outside the magic bytes: pool handshakes and
// dashboards. One spelling, so the two networks cannot be confused by a typo.
inline const char* BtfNetworkName() { return IsTestNet() ? "bitflash-testnet" : "bitflash"; }

// --- .btf peer exchange ---------------------------------------------------
// Peers gossip signed descriptors so discovery survives a relay outage. Both
// caps apply to a single "btfpeers" message; the generic header limit is 256 MB,
// which is no protection at all for something a stranger can send unprompted.
static const unsigned int MAX_PEX_DESCRIPTORS      = 20;
static const unsigned int MAX_PEX_DESCRIPTOR_BYTES = 1024;
// One announcement per side per connection is the intended traffic, and all a
// connection gets (ProcessBtfPeers in main.cpp): this used to allow one a
// minute, which a peer that stayed connected could use to keep churning the
// cache.

// How long to sit registered at a rendezvous relay before giving up on this
// attempt and registering again. Bounded because a registration socket that
// goes quiet is indistinguishable, from inside recv(), from one whose path has
// died -- and the second kind never wakes up. Five minutes is short enough
// that a node is unreachable only briefly and long enough that the reconnect
// traffic is nothing: one per relay per five minutes.
static const int          BTF_RENDEZVOUS_WAIT_SECS = 300;

// Registrations this node parks at a rendezvous at once.
//
// Back to one, and it stays at one until every relay in vBtfMeetingRelays runs
// the queue from #113. More than one is what keeps a node reachable while one
// registration is being paired -- but only against a relay that accepts more
// than one. An older relay closes the previous registration whenever the same
// node registers again, so several accept threads pointed at one of those
// evict each other in a loop: thread 2 registers and kills thread 1, thread 3
// kills thread 2, thread 1 sees its socket die and kills thread 3.
//
// #113 called that harmless. It is not. Measured on a node running three
// threads against the un-upgraded New Jersey relay: 189 registrations in about
// fifteen minutes -- roughly twelve a minute -- and not one pairing. The node
// was not merely failing to benefit, it was unreachable through that relay and
// hammering it. A node with one thread does none of this.
//
// The bench that approved #113 could not see it: its harness re-registers by
// design, which is exactly what hides an eviction loop.
//
// Raise this to 3 only when the other two relays are upgraded.
static const int          BTF_ACCEPT_THREADS       = 1;

// Liveness of an established peer connection. BTF_RENDEZVOUS_WAIT_SECS bounds
// the wait for a dial to arrive; these bound the connection that comes out of
// it, which has the same failure mode once it goes quiet.
//
// A healthy peer relays a block inventory roughly every nTargetSpacing (two
// minutes), so silence measured in block intervals is the honest signal.
// Bitcoin used ninety minutes against ten-minute blocks -- nine intervals --
// and the same nine intervals here is eighteen minutes; thirty leaves margin
// for a slow stretch without letting a dead path last an hour.
static const int          BTF_RECV_TIMEOUT_SECS    = 30 * 60;
static const int          BTF_SEND_STALL_SECS      = 10 * 60;
static const int          BTF_HANDSHAKE_GRACE_SECS = 60;

// A serialized object cannot be larger than MAX_SIZE, so no valid network
// message needs the old 256 MB header allowance. Keep the wire cap aligned with
// what the deserializer can accept and bound how long one peer may sit on a
// partial payload after a complete header has arrived.
static const unsigned int MAX_PROTOCOL_MESSAGE_SIZE = MAX_SIZE;
static const int          BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS = 2 * 60;

// --- Per-peer resource bounds ----------------------------------------------
//
// What one peer can make this node hold or do. Bitcoin carried most of these
// by 0.3.x; Bitflash forked from 0.1.0 and had none of them, so a peer could
// ask for gigabytes of output with one getdata, for the whole chain with one
// getblocks, and leave entries in a global map with every inv.
//
// Entries in one inv or getdata. Bitcoin's MAX_INV_SZ. A getdata over it is
// refused and scored: no node of ours ever announces that much at once. An inv
// over it is cut to its first MAX_INV_SZ entries without a score, because a
// 1.2.x node answers getblocks with the whole chain in one inv, and a node
// syncing from one must still take the start of it.
#ifndef BTF_MAX_INV_SZ
#define BTF_MAX_INV_SZ 50000   // a bench build may lower it to exercise the cut
#endif
static const unsigned int MAX_INV_SZ = BTF_MAX_INV_SZ;
// Block hashes one getblocks answer offers. The rest of the chain follows when
// the peer asks for the last of them: see hashContinue.
static const int          MAX_GETBLOCKS_RESULTS = 500;
// Hashes in a block locator. One built by CBlockLocator::Set has about 10 +
// log2(height) of them, so 101 is far past any real chain.
static const unsigned int MAX_LOCATOR_SZ = 101;
// Requests one peer can have queued with us (mapAskFor), and the global memory
// of what was asked and when (mapAlreadyAskedFor). The global one used to be
// erased only when the item arrived, so every random hash ever announced stayed.
static const unsigned int MAX_ASKFOR_PER_PEER  = MAX_INV_SZ;
static const unsigned int MAX_ALREADY_ASKED_FOR = 2 * MAX_INV_SZ;
// Inventory remembered as known to a peer, most recent kept.
static const unsigned int MAX_INVENTORY_KNOWN = 10000;
// Messages taken from one peer per pass of the message thread, and the time
// spent on it, so one peer's backlog cannot hold up everybody else's.
static const int          MAX_MESSAGES_PER_PASS = 100;
static const int64        MAX_PEER_PASS_MILLIS  = 250;

// Bytes queued to a peer before this node stops producing more for it (served
// getdata waits in vRecvGetData, a getblocks answer waits as pending), and
// bytes received from a peer and not yet processed before its socket is no
// longer read. A message larger than the receive bound is still read to its
// end, so the bound never refuses a message the protocol allows. Variables so
// the self-test can shrink them.
extern unsigned int nSendBufferSize;
extern unsigned int nReceiveFloodSize;
inline unsigned int SendBufferSize()    { return nSendBufferSize; }
inline unsigned int ReceiveFloodSize()  { return nReceiveFloodSize; }
// Past this many bytes queued to a peer, it is dropped (Bitcoin 0.3.x's send
// flood control). Above everything this node queues on purpose -- a P2Pool
// history stops at 32 MB -- so only a peer that asks and does not read gets
// here, whatever path it asked through.
static const unsigned int MAX_SEND_BUFFER_HARD = 64 * 1000 * 1000;
// Transaction hashes from one peer's inv looked up in the database, per second
// and at most at once. The rest of a bigger inv is not asked for.
static const int TX_INV_LOOKUPS_PER_SEC = 100;
static const int TX_INV_LOOKUPS_MAX     = 5000;
// An inbound peer connected this long no longer draws on the inbound block
// budget (InboundBlockBudgetTake): it has had its chance to misbehave, and a
// dropped peer starts over.
static const int64 INBOUND_BLOCK_BUDGET_EXEMPT_SECS = 10 * 60;
// Blocks the budget refused, kept per peer to ask for again later.
static const unsigned int MAX_BLOCKS_REFUSED_PER_PEER = 8;

// Inbound connections. Outbound dials are this node's own choice and are not
// counted against it; the room above it is theirs. When inbound is full a new
// inbound peer evicts the least useful one instead of being refused.
static const unsigned int MAX_INBOUND_CONNECTIONS = 117;

// Ceiling on simultaneous connections.
//
// ThreadSocketHandler watches every peer in one socket loop. This used to be a
// select() loop, which made FD_SETSIZE the real limit and silently starved
// sockets past that bitmap. It is now poll()/WSAPoll(), so the ceiling below is
// a deliberate resource bound rather than a descriptor-set accident.
//
// Measured on two nodes before this ceiling existed: 277 and 90 CNode objects
// against 93 and 90 live sockets, and a status bar reporting hundreds of
// peers for a node that was really talking to thirty.
//
// 125 is Bitcoin's number and remains a conservative public-node default.
static const unsigned int MAX_CONNECTIONS = 125;

// Cap inbound connections from any single address. Without it one source can
// hold every slot up to MAX_CONNECTIONS -- exactly what happened to the
// rendezvous relays, where a single IP parked hundreds of connections and
// starved real peers. A legitimate peer, even a relay talking to a relay,
// needs only a handful; 32 leaves generous room while denying any one address
// more than a quarter of the table. The firewall connlimit on the relays does
// the same thing a layer lower; this makes every build carry the defense.
//
// Loopback (127.0.0.0/8) is exempt in the accept path. A managed-Tor node
// receives every inbound onion peer over its local hidden-service listener, so
// they all appear as 127.0.0.1 -- capping loopback would cap onion peers as a
// group, which is exactly wrong for a network moving toward onion-only. The
// global MAX_CONNECTIONS still bounds the total; a per-onion-identity limit,
// applied once identity is known after accept(), is the right future tool for
// onion floods.
static const unsigned int MAX_CONNECTIONS_PER_IP = 32;

// A node marked for disconnect is normally held until its buffers drain, so
// a last message still goes out. But vSend cannot drain through a socket
// whose far end is gone, and that made such a node immortal: it stayed in
// vNodes, kept its socket open, and kept being counted. Force it out after
// this long regardless of what is still buffered.
static const int64        DISCONNECT_DRAIN_SECS    = 60;

// Send a ping after this long with nothing to say, so a peer running the
// inactivity check above does not mistake a quiet node for a dead one. Must
// stay well under BTF_RECV_TIMEOUT_SECS.
static const int          BTF_PING_INTERVAL_SECS   = 10 * 60;

// How long a node must stay behind the network before it says so, and how
// often it repeats itself. Five minutes is two and a half block intervals --
// long enough that ordinary relay lag never trips it.
static const int          BTF_BEHIND_GRACE_SECS         = 5 * 60;
static const int          BTF_BEHIND_WARN_INTERVAL_SECS = 5 * 60;

// --- Self-diagnosis -------------------------------------------------------
//
// A node that has stopped working looks exactly like a node with nothing to
// do. That has cost this project real time more than once: a node deaf to
// most of its peers, a miner allocating one RandomX dataset per thread, a
// third of arriving blocks missing their parent -- each was found from
// outside, by reading the process's sockets or its memory from another
// machine, because the node itself had no way to say so.
//
// These counters exist so it can. Cheap to keep, and they name the failures
// that actually happened rather than the ones that sound impressive.
extern int   nPeersWatched;        // peers in the last poll() set
extern int64 nBlocksReceived;      // blocks handed to ProcessBlock
extern int64 nBlocksWithoutParent; // ...of those, how many arrived orphaned

// One report, rendered the same way for the GUI panel and the log, so what a
// user pastes into an issue is what a developer already knows how to read.
string GetDiagnosticsText();

#include "sockcount.h"

// Defined in main.cpp. Declared here because CNode announces it in the version
// message, and net.h is included before main.h.
extern int nBestHeight;

// Median height announced by the peers we are connected to, or -1 while nobody
// has told us anything. Median rather than maximum so one peer claiming an
// absurd height cannot move it.
int GetPeerMedianHeight();

// Lightweight .btf churn accounting. These counters are diagnostics only: they
// let an operator tell stale descriptors, relay pairing failures, and paired
// tunnels that never speak apart before changing behaviour.
void BtfChurnNoteResolveAttempt();
void BtfChurnNoteResolveResult(bool fOk);
void BtfChurnNoteDialAttempt(const string& strBtfAddr, const string& strMeeting);
void BtfChurnNoteDialResult(const string& strBtfAddr, const string& strMeeting, bool fOk);
void BtfChurnNoteRegisterResult(const string& strMeeting, bool fOk);
void BtfChurnNotePairResult(const string& strMeeting, bool fOk);
void BtfChurnNoteHandshakeTimeout(const string& strBtfAddr, const string& strMeeting,
                                  bool fRecv, bool fSend);

// Descriptors to hand a peer: ours first, then peers that answered us.
void BtfPexCollect(std::vector<std::string>& vDescOut);
// Verify descriptors a peer sent and remember the good ones. Returns how many.
int  BtfPexAccept(const std::vector<std::string>& vDesc);
// Self-test access to the peer cache (btfpeers.json in the data directory).
void BtfRememberPeerForTest(const std::string& strBtfAddr, const std::string& strOnion, bool fVerified);
void BtfPeerCacheStatsForTest(int& nVerified, int& nHearsay, std::vector<std::string>& vDialOrder);
void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1);
bool AnySubscribed(unsigned int nChannel);
void ThreadBitcoinMiner(void* parg);
// Starts MinerThreadCount() miners; returns how many came up.
int  StartMinerThreads();
bool StartNode(string& strError=REF(string()));
bool StopNode();
void CheckForShutdown(int n);









//
// Message header
//  (4) message start
//  (12) command
//  (4) size

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
// Magic bytes unique to the selected Bitflash network. Mainnet uses 0xbf =
// "BF"; testnet swaps the whole sequence so a test node cannot handshake with
// mainnet before consensus-level testnet activation exists.
extern char pchMessageStart[4];

class CMessageHeader
{
public:
    enum { COMMAND_SIZE=12 };
    enum { MESSAGE_START_SIZE=4 };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    // First 4 bytes of Hash(payload). On the wire only when the stream's
    // version is PROTO_CHECKSUM_VERSION or later; 0.1.0 had no way to tell a
    // payload from the bytes a peer, or the path to it, had mangled.
    unsigned int nChecksum;

    CMessageHeader()
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        memset(pchCommand, 0, sizeof(pchCommand));
        pchCommand[1] = 1;
        nMessageSize = -1;
        nChecksum = 0;
    }

    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn)
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        strncpy(pchCommand, pszCommand, COMMAND_SIZE);
        nMessageSize = nMessageSizeIn;
        nChecksum = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        if (nVersion >= PROTO_CHECKSUM_VERSION)
            READWRITE(nChecksum);
    )

    // Bytes this header takes on a stream of the given version.
    static unsigned int SizeOnWire(int nStreamVersion)
    {
        return nStreamVersion >= PROTO_CHECKSUM_VERSION ? 24 : 20;
    }

    string GetCommand()
    {
        if (pchCommand[COMMAND_SIZE-1] == 0)
            return string(pchCommand, pchCommand + strlen(pchCommand));
        else
            return string(pchCommand, pchCommand + COMMAND_SIZE);
    }

    bool IsValid()
    {
        // Check start string
        if (memcmp(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart)) != 0)
            return false;

        // Check the command string for errors
        for (char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
        {
            if (*p1 == 0)
            {
                // Must be all zeros after the first zero
                for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                    if (*p1 != 0)
                        return false;
            }
            else if (*p1 < ' ' || *p1 > 0x7E)
                return false;
        }

        // Message size
        if (nMessageSize > MAX_PROTOCOL_MESSAGE_SIZE)
        {
            if (LogAcceptsCategory("net")) printf("CMessageHeader::IsValid() : nMessageSize too large %u\n", nMessageSize);
            return false;
        }

        return true;
    }
};






static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

class CAddress
{
public:
    uint64 nServices;
    unsigned char pchReserved[12];
    unsigned int ip;
    unsigned short port;

    // disk only
    unsigned int nTime;

    // memory only
    unsigned int nLastFailed;

    CAddress()
    {
        nServices = 0;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = GetDefaultPort();
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    CAddress(unsigned int ipIn, unsigned short portIn, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = ipIn;
        port = portIn;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const struct sockaddr_in& sockaddr, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = sockaddr.sin_addr.s_addr;
        port = sockaddr.sin_port;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const char* pszIn, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = GetDefaultPort();
        nTime = GetAdjustedTime();
        nLastFailed = 0;

        char psz[100];
        if (strlen(pszIn) > ARRAYLEN(psz)-1)
            return;
        strcpy(psz, pszIn);
        unsigned int a, b, c, d, e;
        if (sscanf(psz, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e) < 4)
            return;
        char* pszPort = strchr(psz, ':');
        if (pszPort)
        {
            *pszPort++ = '\0';
            port = htons(atoi(pszPort));
        }
        ip = inet_addr(psz);
    }

    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
        {
            READWRITE(nVersion);
            READWRITE(nTime);
        }
        READWRITE(nServices);
        READWRITE(FLATDATA(pchReserved));
        READWRITE(ip);
        READWRITE(port);
    )

    friend inline bool operator==(const CAddress& a, const CAddress& b)
    {
        return (memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved)) == 0 &&
                a.ip   == b.ip &&
                a.port == b.port);
    }

    friend inline bool operator<(const CAddress& a, const CAddress& b)
    {
        int ret = memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved));
        if (ret < 0)
            return true;
        else if (ret == 0)
        {
            if (ntohl(a.ip) < ntohl(b.ip))
                return true;
            else if (a.ip == b.ip)
                return ntohs(a.port) < ntohs(b.port);
        }
        return false;
    }

    vector<unsigned char> GetKey() const
    {
        CDataStream ss;
        ss.reserve(18);
        ss << FLATDATA(pchReserved) << ip << port;

        #if defined(_MSC_VER) && _MSC_VER < 1300
        return vector<unsigned char>((unsigned char*)&ss.begin()[0], (unsigned char*)&ss.end()[0]);
        #else
        return vector<unsigned char>(ss.begin(), ss.end());
        #endif
    }

    struct sockaddr_in GetSockAddr() const
    {
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = ip;
        sockaddr.sin_port = port;
        return sockaddr;
    }

    bool IsIPv4() const
    {
        return (memcmp(pchReserved, pchIPv4, sizeof(pchIPv4)) == 0);
    }

    bool IsRoutable() const
    {
        return !(GetByte(3) == 10 || (GetByte(3) == 192 && GetByte(2) == 168));
    }

    unsigned char GetByte(int n) const
    {
        return ((unsigned char*)&ip)[3-n];
    }

    string ToStringIPPort() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
    }

    string ToStringIP() const
    {
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    string ToString() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
        //return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    void print() const
    {
        if (LogAcceptsCategory("net")) printf("CAddress(%s)\n", ToString().c_str());
    }
};







enum
{
    MSG_TX = 1,
    MSG_BLOCK,
    MSG_REVIEW,
    MSG_PRODUCT,
    MSG_TABLE,
    MSG_CHATREC,
};

static const char* ppszTypeName[] =
{
    "ERROR",
    "tx",
    "block",
    "review",
    "product",
    "table",
    "chatrec",
};

class CInv
{
public:
    int type;
    uint256 hash;

    CInv()
    {
        type = 0;
        hash = 0;
    }

    CInv(int typeIn, const uint256& hashIn)
    {
        type = typeIn;
        hash = hashIn;
    }

    CInv(const string& strType, const uint256& hashIn)
    {
        int i;
        for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
        {
            if (strType == ppszTypeName[i])
            {
                type = i;
                break;
            }
        }
        if (i == ARRAYLEN(ppszTypeName))
            throw std::out_of_range(strprintf("CInv::CInv(string, uint256) : unknown type '%s'", strType.c_str()));
        hash = hashIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(type);
        READWRITE(hash);
    )

    friend inline bool operator<(const CInv& a, const CInv& b)
    {
        return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
    }

    bool IsKnownType() const
    {
        return (type >= 1 && type < ARRAYLEN(ppszTypeName));
    }

    const char* GetCommand() const
    {
        if (!IsKnownType())
            // Was "type=% unknown type": the % swallowed the space as a flag and
            // the u as the conversion, so this read "type= 3nknown type".
            throw std::out_of_range(strprintf("CInv::GetCommand() : type=%d unknown type", type));
        return ppszTypeName[type];
    }

    string ToString() const
    {
        return strprintf("%s %s", GetCommand(), hash.ToString().substr(0,14).c_str());
    }

    void print() const
    {
        if (LogAcceptsCategory("net")) printf("CInv(%s)\n", ToString().c_str());
    }
};





class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&);
    void* param1;

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&)=NULL, void* param1In=NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull()
    {
        return fn == NULL;
    }
};





extern bool fClient;
extern uint64 nLocalServices;
extern CAddress addrLocalHost;
extern unsigned short nListenPort;
extern CNode* pnodeLocalHost;
extern bool fShutdown;
extern array<bool, 10> vfThreadRunning;
extern vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern map<CInv, CDataStream> mapRelay;
extern deque<pair<int64, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;
extern map<CInv, int64> mapAlreadyAskedFor;
// Forget requests that no longer stagger anything, then the oldest, until at
// most nTarget remain. Under cs_main, like every use of the map.
void PruneAlreadyAskedFor(int64 nNowMicros, size_t nTarget);


// A set that keeps only its most recently inserted nMax elements (Bitcoin's
// mruset). Used for what a peer is known to have, which was a plain set that
// one inv could grow by a million entries.
template <typename T>
class mruset
{
public:
    typedef typename std::set<T>::iterator iterator;

    explicit mruset(size_t nMaxIn) : nMax(nMaxIn) {}

    std::pair<iterator, bool> insert(const T& x)
    {
        std::pair<iterator, bool> ret = set.insert(x);
        if (ret.second)
        {
            order.push_back(x);
            while (set.size() > nMax && !order.empty())
            {
                set.erase(order.front());
                order.pop_front();
            }
            // erase() leaves stale names in the order queue; rebuild it before
            // they outnumber the live ones.
            if (order.size() > 2 * nMax + 16)
                Compact();
            ret.first = set.find(x);
        }
        return ret;
    }
    size_t erase(const T& x) { return set.erase(x); }
    size_t count(const T& x) const { return set.count(x); }
    size_t size() const { return set.size(); }
    bool empty() const { return set.empty(); }
    void clear() { set.clear(); order.clear(); }
    size_t max_size() const { return nMax; }
    size_t order_size() const { return order.size(); }

private:
    void Compact()
    {
        std::deque<T> keep;
        std::set<T> seen;
        // Newest first, so a name inserted twice keeps its latest position.
        for (typename std::deque<T>::reverse_iterator it = order.rbegin(); it != order.rend(); ++it)
            if (set.count(*it) && seen.insert(*it).second)
                keep.push_front(*it);
        order.swap(keep);
    }

    std::set<T> set;
    std::deque<T> order;
    size_t nMax;
};





class CNode
{
public:
    // socket
    uint64 nServices;
    SOCKET hSocket;
    CDataStream vSend;
    CDataStream vRecv;
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    unsigned int nPushPos;
    // Header size and checksum choice of the message being built, fixed at
    // BeginMessage(): the stream version may change under it (the peer's
    // version message arrives on another thread) and EndMessage() has to
    // finish the header it started, not the one the new version would write.
    unsigned int nPushHeaderSize;
    bool fPushChecksum;
    // Misbehavior score, Bitcoin 0.3.x style: garbage costs points, 100 points
    // disconnects and, for a peer we dialled by .btf address, bans that
    // address for a day. An inbound onion peer has no address to ban -- Tor
    // is the whole point -- so for it a ban is a disconnect and nothing more.
    int nMisbehavior;
    CAddress addr;
    int nVersion;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fDisconnect;
    // P2Pool history (p2pool_net.cpp): when we last sent this peer ours, when
    // we asked it for its own (0: not asked, or the answer is over), and how
    // many shares of that history it has sent.
    int64 nP2PoolSyncServed;
    int64 nP2PoolSyncAskedAt;
    unsigned int nP2PoolHistoryRecv;
    // When it last sent a share this node took (0: never), and whether it
    // has named its P2Pool peers to us yet (once per connection).
    int64 nP2PoolLastGood;
    bool fP2PoolPeersRecv;
protected:
    int nRefCount;
public:
    int64 nReleaseTime;
    int64 nDisconnectSince;
    map<uint256, CRequestTracker> mapRequests;
    CCriticalSection cs_mapRequests;

    // inventory based relay
    mruset<CInv> setInventoryKnown;
    set<CInv> setInventoryKnown2;
    vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    multimap<int64, CInv> mapAskFor;

    // getdata entries not served yet because the send buffer was full; served
    // from the front as it drains (ProcessGetData in main.cpp). Message thread
    // only, under cs_vRecv.
    deque<CInv> vRecvGetData;
    // The last block of a getblocks answer cut at MAX_GETBLOCKS_RESULTS. When
    // the peer asks for it, it is told of our tip as well, which makes it ask
    // for the next part. Bitcoin's continuation, understood by every 1.2.x node.
    uint256 hashContinue;
    // A getblocks that arrived while the send buffer was full, answered once it
    // has room. Only the latest is kept: a newer locator supersedes the older.
    bool fGetBlocksPending;
    vector<uint256> vGetBlocksHave;
    uint256 hashGetBlocksStop;
    // ProcessMessages stopped on its per-pass budget with complete messages
    // still waiting, so the message thread should come back soon.
    bool fRecvMorePending;

    // The last block hash kept of an inv cut at MAX_INV_SZ (a 1.2.x node's
    // whole-chain getblocks answer). When that block arrives, getblocks is
    // sent again to the same peer for the rest. Message thread only.
    uint256 hashInvContinue;
    // Blocks the inbound budget refused from this peer, asked for again once
    // there is budget (SendMessages). Under cs_vRecv and cs_vSend, as
    // mapAskFor: the message thread touches it holding one or the other.
    vector<uint256> vBlocksRefused;
    // Database lookups left for transaction hashes this peer announces, and
    // when they were last topped up (TX_INV_LOOKUPS_PER_SEC).
    int nTxInvTokens;
    int64 nTxInvRefilled;

    // Dropped for misbehavior or evicted: no drain grace, nothing more read.
    bool fDropWithoutDrain;
    // When this peer last gave us something we kept, and how many of its
    // blocks we took. What eviction protects, and what lets an inbound peer's
    // blocks skip the shared budget for unproven peers.
    int64 nLastBlockTime;
    int64 nLastTxTime;
    int nGoodBlocks;

    // publish and subscription
    vector<char> vfSubscribe;

    // When we took this node's "btfpeers" (0: not yet). One per connection.
    int64 nLastPexRecv;

    // Chat records this peer has handed us in the current minute, the minute
    // it started, and the last time it asked for our whole inventory. See
    // chatrelay.cpp: the store is open to anybody, so each peer gets a ration.
    int64 nChatWindowStart;
    int nChatPutsInWindow;
    int nChatQueriesInWindow;
    int64 nLastChatInvAsked;

    // Last getblocks we sent this peer, so we do not ask the same question
    // over and over. See CNode::PushGetBlocks.
    CBlockIndex* pindexLastGetBlocksBegin;
    uint256      hashLastGetBlocksEnd;

    // Liveness. A peer whose network path dies silently -- NAT drops an idle
    // mapping, a relay restarts, a route changes -- never sends FIN, so the
    // socket stays readable-never and the node simply stops hearing from it
    // with no error anywhere. These stamps are the only way to tell that
    // apart from a peer that merely has nothing to say.
    int64 nTimeConnected;
    int64 nLastSend;
    int64 nLastRecv;
    int64 nLastSendEmpty;
    int64 nIncompleteMessageStart;
    unsigned int nIncompleteMessageSize;
    string strIncompleteMessageCommand;
    string strBtfAddr;
    string strBtfMeeting;

    // Height this peer announced in its version message, or -1 if it sent a
    // version message that predates the field. Knowing how far along everyone
    // else is, is the only way a node can tell "in sync" from "not hearing".
    int nStartingHeight;

    // Release this peer said it runs ("1.2.24"), sent after the height from
    // 1.2.24 on. Empty for peers older than that. The protocol number above
    // has been 101 across every release, so until this field existed no node
    // could tell which of its peers would follow a consensus change.
    std::string strRelease;


    CNode(SOCKET hSocketIn, CAddress addrIn, bool fInboundIn=false)
        : setInventoryKnown(MAX_INVENTORY_KNOWN)
    {
        hashContinue = 0;
        fGetBlocksPending = false;
        hashGetBlocksStop = 0;
        fRecvMorePending = false;
        hashInvContinue = 0;
        nTxInvTokens = TX_INV_LOOKUPS_MAX;
        nTxInvRefilled = GetTime();
        fDropWithoutDrain = false;
        nLastBlockTime = 0;
        nLastTxTime = 0;
        nGoodBlocks = 0;
        nServices = 0;
        hSocket = hSocketIn;
        vSend.SetType(SER_NETWORK);
        vRecv.SetType(SER_NETWORK);
        nPushPos = -1;
        addr = addrIn;
        nVersion = 0;
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fDisconnect = false;
        nP2PoolSyncServed = 0;
        nP2PoolSyncAskedAt = 0;
        nP2PoolHistoryRecv = 0;
        nP2PoolLastGood = 0;
        fP2PoolPeersRecv = false;
        nRefCount = 0;
        nReleaseTime = 0;
        nDisconnectSince = 0;
        nLastPexRecv = 0;
        nChatWindowStart = 0;
        nChatPutsInWindow = 0;
        nChatQueriesInWindow = 0;
        nLastChatInvAsked = 0;
        pindexLastGetBlocksBegin = NULL;
        hashLastGetBlocksEnd = 0;
        nTimeConnected = GetTime();
        nLastSend = 0;
        nLastRecv = 0;
        nLastSendEmpty = GetTime();
        nIncompleteMessageStart = 0;
        nIncompleteMessageSize = 0;
        strIncompleteMessageCommand.clear();
        strBtfAddr.clear();
        strBtfMeeting.clear();
        nStartingHeight = -1;
        strRelease = "";
        nPushHeaderSize = 0;
        fPushChecksum = false;
        nMisbehavior = 0;
        vfSubscribe.assign(256, false);
        // Nothing is known about the peer yet, so the version message goes
        // out in the 101 framing every node understands. Both streams move to
        // the negotiated version when the peer's version message arrives.
        vSend.SetVersion(PROTO_NO_CHECKSUM_VERSION);
        vRecv.SetVersion(PROTO_NO_CHECKSUM_VERSION);

        // Push a version message
        /// when NTP implemented, change to just nTime = GetAdjustedTime()
        int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());
        // nBestHeight goes last so a node that predates it stops reading after
        // addr and treats the rest as trailing bytes, which cost it a log line
        // and nothing else.
        PushMessage("version", VERSION, nLocalServices, nTime, addr, nBestHeight,
                    std::string(BITFLASH_VERSION_STRING));
    }

    // Disconnect() closes the socket and sets this to INVALID_SOCKET, so by the
    // time a node is deleted there is normally nothing left to do here. It used
    // not to: Disconnect() closed the handle and left the number in place, and
    // this destructor closed that same number a second time -- with a raw
    // closesocket() that the socket accounting never saw, so neither the double
    // close nor the stale claim showed up in any report.
    //
    // A double close is not a harmless no-op. Between the two, the operating
    // system is free to hand that number to a new socket -- this node opens
    // hundreds a minute -- and the second close then takes down a connection
    // that belongs to somebody else, which the log can only report as a peer
    // vanishing for no reason. `dropping node: its socket is no longer valid`
    // is what that looks like from the outside.
    ~CNode()
    {
        if (hSocket != INVALID_SOCKET)
        {
            BtfCloseSocket(hSocket);
            hSocket = INVALID_SOCKET;
        }
    }

private:
    CNode(const CNode&);
    void operator=(const CNode&);
public:


    bool ReadyToDisconnect()
    {
        return fDisconnect || GetRefCount() <= 0;
    }

    int GetRefCount()
    {
        return max(nRefCount, 0) + (GetTime() < nReleaseTime ? 1 : 0);
    }

    void AddRef(int64 nTimeout=0)
    {
        if (nTimeout != 0)
            nReleaseTime = max(nReleaseTime, GetTime() + nTimeout);
        else
            nRefCount++;
    }

    void Release()
    {
        nRefCount--;
    }



    void AddInventoryKnown(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            setInventoryKnown.insert(inv);
    }

    void PushInventory(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            if (!setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
    }

    // False when this peer already has MAX_ASKFOR_PER_PEER requests queued:
    // the item is then not asked of it at all.
    bool AskFor(const CInv& inv)
    {
        if (mapAskFor.size() >= MAX_ASKFOR_PER_PEER)
            return false;

        // Make sure not to reuse time indexes to keep things in the same order
        int64 nNow = (GetTime() - 1) * 1000000;
        static int64 nLastTime;
        nLastTime = nNow = max(nNow, ++nLastTime);

        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        int64 nRequestTime;
        {
            int64& nSlot = mapAlreadyAskedFor[inv];
            if (LogAcceptsCategory("net")) printf("askfor %s  %lld\n", inv.ToString().c_str(), nSlot);
            // Each retry is 2 minutes after the last
            nSlot = max(nSlot + 2 * 60 * 1000000, nNow);
            nRequestTime = nSlot;
        }
        mapAskFor.insert(make_pair(nRequestTime, inv));
        if (mapAlreadyAskedFor.size() > MAX_ALREADY_ASKED_FOR)
            PruneAlreadyAskedFor(nNow, MAX_ALREADY_ASKED_FOR * 3 / 4);
        return true;
    }

    // Whether a receive would only add to a backlog this node has not got to:
    // more than ReceiveFloodSize() unprocessed, and the message at its front
    // already complete. Under cs_vRecv.
    bool RecvFloodPaused();



    void BeginMessage(const char* pszCommand)
    {
        EnterCriticalSection(&cs_vSend);
        if (nPushPos != -1)
            AbortMessage();
        nPushPos = vSend.size();
        fPushChecksum = vSend.GetVersion() >= PROTO_CHECKSUM_VERSION;
        vSend << CMessageHeader(pszCommand, 0);
        nPushHeaderSize = vSend.size() - nPushPos;
        if (LogAcceptsCategory("net")) printf("sending: %-12s ", pszCommand);
    }

    void AbortMessage()
    {
        if (nPushPos == -1)
            return;
        vSend.resize(nPushPos);
        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
        if (LogAcceptsCategory("net")) printf("(aborted)\n");
    }

    void EndMessage()
    {
        extern int nDropMessagesTest;
        if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
        {
            if (LogAcceptsCategory("net")) printf("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nPushPos == -1)
            return;

        // Patch in the size, and the checksum when the peer can read one
        unsigned int nSize = vSend.size() - nPushPos - nPushHeaderSize;
        memcpy((char*)&vSend[nPushPos] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));
        if (fPushChecksum)
        {
            uint256 hash = Hash(vSend.begin() + nPushPos + nPushHeaderSize, vSend.end());
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            memcpy((char*)&vSend[nPushPos] + offsetof(CMessageHeader, nChecksum), &nChecksum, sizeof(nChecksum));
        }

        if (LogAcceptsCategory("net")) printf("(%d bytes)  ", nSize);
        //for (int i = nPushPos+sizeof(CMessageHeader); i < min(vSend.size(), nPushPos+sizeof(CMessageHeader)+20U); i++)
        //    printf("%02x ", vSend[i] & 0xff);
        if (LogAcceptsCategory("net")) printf("\n");

        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
    }

    void EndMessageAbortIfEmpty()
    {
        if (nPushPos == -1)
            return;
        int nSize = vSend.size() - nPushPos - nPushHeaderSize;
        if (nSize > 0)
            EndMessage();
        else
            AbortMessage();
    }

    const char* GetMessageCommand() const
    {
        if (nPushPos == -1)
            return "";
        return &vSend[nPushPos] + offsetof(CMessageHeader, pchCommand);
    }




    // Ask this peer to fill in blocks we are missing, but only once per
    // question.
    //
    // Every orphan block fires one of these, and an inv for a block we already
    // hold as an orphan fires another. A node that is missing part of the
    // chain therefore asks the same peer the same thing repeatedly: measured
    // on a production node, 1287 orphan blocks out of 4117 processed, and 97
    // "already have block" from the answers coming back more than once. The
    // duplicate answers create more orphans, which fire more requests.
    //
    // Remembering the last question asked breaks that loop. Same fix Bitcoin
    // made in e2c2648c1.
    // Body lives in net.cpp: it builds a CBlockLocator, which main.h defines,
    // and main.h is included after this file.
    void PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd);

    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }


    void PushRequest(const char* pszCommand,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char* pszCommand, const T1& a1,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char* pszCommand, const T1& a1, const T2& a2,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1, a2);
    }



    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops=0);
    void CancelSubscribe(unsigned int nChannel);
    void Disconnect();
    // Add to the misbehavior score; true when this pushed it over the line
    // and the peer is now being dropped (and its .btf address banned).
    bool Misbehaving(int nHowMuch);
};

// Whether the socket thread should take a node out of vNodes now: it is marked
// and either drained, dropped without drain, or stuck past the drain grace.
bool NodeReadyToDrop(CNode* pnode, int64 nNow);

// What eviction looks at for one inbound peer, and the choice itself: the
// index of the peer to evict, or -1 when every candidate is protected.
struct NodeEvictionCandidate
{
    int64 nTimeConnected;
    int64 nLastBlockTime;
    int64 nLastTxTime;
    int64 nLastShareTime;
    bool  fHandshakeDone;
};
int SelectNodeToEvict(const std::vector<NodeEvictionCandidate>& vCandidates);

// Blocks from an inbound peer that has not yet given us a block draw on one
// shared budget before this node spends a proof-of-work check on them. An
// inbound onion peer has no address: dropped, it comes back at once with a
// clean score, so a per-peer score alone does not bound what it costs.
//
// The token is taken in CheckBlock right before the RandomX hash, after every
// cheap check, so a block that fails those costs no token. A peer connected
// for INBOUND_BLOCK_BUDGET_EXEMPT_SECS, or that has given us a block that
// connected, does not draw on it at all.
bool InboundBlockBudgetTake();
bool InboundBlockBudgetAvailable();
bool PeerNeedsBlockBudget(const CNode* pnode);
extern int64 nInboundBlocksRefused;
void InboundBlockBudgetResetForTest(int nTokens);
int  InboundBlockBudgetTokensForTest();

// Drop a peer whose send buffer is past MAX_SEND_BUFFER_HARD. Caller holds
// cs_vSend. True when it did.
bool SendFloodCheck(CNode* pnode);

// Mark one inbound peer for eviction (SelectNodeToEvict) to make room for a
// new one. False when every inbound peer is protected.
bool AttemptToEvictConnection();

static const int BAN_MISBEHAVIOR_THRESHOLD = 100;
static const int64 BAN_SECONDS = 24 * 60 * 60;
// .btf addresses we will not dial until the time given. Nothing about an
// inbound onion peer can be banned, so this only ever holds addresses we
// chose to connect to.
bool BtfIsBanned(const std::string& strBtfAddr);
int BtfBannedCount();










inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            pnode->PushInventory(inv);
}

template<typename T>
void RelayMessage(const CInv& inv, const T& a)
{
    CDataStream ss(SER_NETWORK);
    ss.reserve(10000);
    ss << a;
    RelayMessage(inv, ss);
}

template<>
inline void RelayMessage<>(const CInv& inv, const CDataStream& ss)
{
    CRITICAL_BLOCK(cs_mapRelay)
    {
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay[inv] = ss;
        vRelayExpiration.push_back(make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}








//
// Templates for the publish and subscription system.
// The object being published as T& obj needs to have:
//   a set<unsigned int> setSources member
//   specializations of AdvertInsert and AdvertErase
// Currently implemented for CTable and CProduct.
//

template<typename T>
void AdvertStartPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Add to sources
    obj.setSources.insert(pfrom->addr.ip);

    if (!AdvertInsert(obj))
        return;

    // Relay
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("publish", nChannel, nHops, obj);
}

template<typename T>
void AdvertStopPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    uint256 hash = obj.GetHash();

    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("pub-cancel", nChannel, nHops, hash);

    AdvertErase(obj);
}

template<typename T>
void AdvertRemoveSource(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Remove a source
    obj.setSources.erase(pfrom->addr.ip);

    // If no longer supported by any sources, cancel it
    if (obj.setSources.empty())
        AdvertStopPublish(pfrom, nChannel, nHops, obj);
}
