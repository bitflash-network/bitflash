// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The share chain on the wire (docs/p2pool.md, step 4). Every node keeps and
// relays the share chain, mining or not: checking one share every ten seconds
// costs next to nothing, and shares then reach every miner however few of
// them happen to be connected to each other.
//
// Messages, over the same Tor-only connections as blocks:
//   p2pshare   one share, fresh off a miner or relayed
//   p2pgetsh   vector<uint256>: send me these shares
//   p2psync    (empty): send me your line, I am starting
//   p2pshares  int tip height, vector<Share>: part of a line, oldest first
//   p2ppeers   vector<string>: .btf addresses of peers we reached that hold
//              the share chain (hints for a miner looking for such peers)
// All of them go only to peers that say NODE_P2POOL; nodes from before P2Pool
// would ignore them, as they ignore every command they do not know.
#ifndef BITFLASH_P2POOL_NET_H
#define BITFLASH_P2POOL_NET_H

// Include headers.h first: it has no include guard.
#include "p2pool_chain.h"

// Handles a P2Pool message; false when strCommand is not one. Called from
// ProcessMessages without cs_main (it takes cs_p2pool, and never cs_main
// inside it: the template code takes cs_main first).
bool P2PoolProcessMessage(CNode* pfrom, const string& strCommand, CDataStream& vRecv);

// Whether a command is a P2Pool message, which ProcessMessages hands to
// P2PoolProcessMessage without cs_main: pool zero's ("p2p..."), a local
// pool's ("p2l..."), a registered pool's ("p2x...") and the registry's
// ("pool...", docs/pool-registry.md section 8).
bool P2PoolCommand(const string& strCommand);

// After the version handshake: ask the peer for its line if ours is empty.
void P2PoolOnVersion(CNode* pfrom);

// A share this node's own miner found: keep it and send it to every peer.
bool P2PoolSubmitShare(const p2pool::Share& share, string& errOut, bool* pfBlock = NULL);

// -sharetimelog: a registered pool's share events (found here, received,
// sent, asked for, probed) written with the wall clock in milliseconds to
// sharetime.log in the data directory, one line each:
//   <unix ms> <event> <pool id, 16 hex> <share id> <share height or -1> <peer or ->
// For measuring a share's delay between nodes (docs/pool-registry.md,
// sections 15 and 17). Off by default.
extern bool fShareTimeLog;
std::string ShareTimeLine(int64 nMillis, const char* pszEvent, const uint256& idPool, const uint256& idShare,
                          int nHeight, const std::string& strPeer);
// poolprobe: ask every connected peer that announced the pool for this
// node's tip share (p2xgetsh); the share and the peers asked come back.
// False when the pool is not carried here or nothing of it is held. Its
// answer is a share already held: taken for nothing, nobody scored.
bool P2PoolProbe(const uint256& idPool, vector<string>& vAskedOut, uint256& idShareOut);

// The share chain, under cs_p2pool. Created on first use.
extern CCriticalSection cs_p2pool;
p2pool::ShareChain& P2PoolChain();

// At startup, once the block index is loaded: read the share chain this node
// saved in p2pool.dat (every two minutes while it runs).
void P2PoolInit();

// What the share chain takes from the node: the later of its own clock and
// the peer-adjusted one (see Now() in p2pool_net.cpp).
class NodeMainView : public p2pool::MainView
{
public:
    int64 Now() const;
};

// Whether this node should hold back templates: it has no share chain yet
// and has just asked a peer for one. Mining meanwhile would start a chain of
// its own at height 0. Under cs_p2pool.
bool P2PoolAwaitingHistory();

// A token bucket: up to nCapacity tokens, one more every nSecsPerToken
// seconds. What this code spends on behalf of peers that have not shown
// they are honest -- a RandomX hash, a history sent or asked for -- is drawn
// from one of these, shared by every such peer: a budget per connection is
// reset by reconnecting, which an inbound onion peer does for free.
class P2PoolBudget
{
public:
    P2PoolBudget(int nCapacityIn, int64 nSecsPerTokenIn)
        : nCapacity(nCapacityIn), nSecsPerToken(nSecsPerTokenIn), nTokens(nCapacityIn), nLast(0) {}
    bool Take(int64 nNow);
    int Tokens(int64 nNow);
    void Reset() { nTokens = nCapacity; nLast = 0; }
    // Self-tests: nLeft tokens (none by default), the next one
    // nSecsPerToken from nNow.
    void Drain(int64 nNow, int nLeft = 0) { nTokens = nLeft; nLast = nNow; }
private:
    void Refill(int64 nNow);
    int nCapacity;
    int64 nSecsPerToken;
    int nTokens;
    int64 nLast;
};

// Whether a peer's word has been worth something on this connection: one we
// dialled, or one that sent a share this node took. Such peers do not draw
// on the shared budgets above.
bool P2PoolPeerProven(const CNode* pnode);

// Self-tests only: forget every share, orphan, budget and ask, and start an
// empty share chain with this floor (fCheckPoW false skips the RandomX hash,
// as ShareChain's own tests do).
void P2PoolResetForTest(const CBigNum& bnFloor, bool fCheckPoW);
// Self-tests and fuzz-p2pool: shares waiting for parents, the budgets'
// tokens left.
size_t P2PoolOrphanCount();
int P2PoolShareWorkTokens();
int P2PoolHistoryServeTokens();
int P2PoolHistoryAskTokens();
// Self-tests only: make every queued orphan this many seconds older.
void P2PoolAgeOrphansForTest(int64 nSecs);

// Shares and history asks of unproven peers that the shared budgets refused
// are held, one of each per connection, and served here as the budgets
// refill, the oldest connection first. Called on every pass of the message
// thread, after every peer's messages.
void P2PoolServeDeferred();
// Connections held for that (each referenced until served or cut off).
size_t P2PoolDeferredCount();
// Self-tests and fuzz-p2pool, whose peers are not in vNodes and are freed by
// the test: drop what is held for this one (and its reference).
void P2PoolForgetDeferred(CNode* pnode);
// Self-tests and fuzz-p2pool: every shared budget full again.
void P2PoolRefillBudgetsForTest();
// Self-tests: every shared budget empty, the next token a full period away.
void P2PoolDrainBudgetsForTest();

// ---- Pools other than pool zero (docs/pool-registry.md, sections 8 and 18)
//
// Pool zero keeps the budgets, the orphan queue and the held entries above
// to itself. Every other pool this node is in spends from one second set of
// the same shape, the registered class, so nothing done with those pools
// changes how pool zero's traffic is treated.
//
// A local pool's messages, between members only, after a hello that proves
// membership to the onion that was dialled:
//   p2lhello   32-byte nonce, 16-byte tag: the hello, and the answer to it
//   p2lack     32 bytes: the initiator's proof; the session is open
//   p2lshare   handle, ShareL (format 1 with the salt)
//   p2lgetsh   handle, vector<uint256>
//   p2lsync    handle, uint256 (a share to resume from, or 0)
//   p2lshares  handle, int tip height, end flag, vector<ShareL>
// The handle is the session's 8 bytes; the pool id is never on the wire. A
// hello that matches no pool of this node, and a handle it does not hold on
// that connection, get silence, and nobody is scored for them.

// The share chain this node's miners work on: pool zero's, the local pool's
// that P2PoolLocalMine named, or the registered pool's of -p2pool=<pool id>
// once it has joined (P2PoolMinedReady says whether it may be mined on).
// Under cs_p2pool.
p2pool::ShareChain& P2PoolMinedChain();
// A number that changes whenever a share joins that chain: the stratum
// checks then whether the uncles its job names are still the ones the next
// share could name (docs/pool-registry.md, section 9).
uint64 P2PoolMinedChainSeq();

// A local pool joins this node (at most poollocal::MAX_LOCAL_POOLS, one per
// name). strFile is where its share chain is kept between runs; empty keeps
// it in memory only. fCheckPoW false is for self-tests. Nothing is written:
// P2PoolLocalJoin is what poolcreate and pooljoin use.
bool P2PoolLocalAdd(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, const string& strFile,
                    bool fCheckPoW, string& errOut);
// A local pool joins this node for good: its file pools/local/<id>.conf is
// written owner-only (the record, K and the listed peers, never the
// password), it comes back from there on every start (P2PoolInit), and a
// share chain left in pools/local/<id>.dat is read. The keys come from
// poollocal::Derive, whose Argon2id run the caller makes before, outside
// every lock. Takes cs_p2pool only (never cs_main), and reads a share
// chain left in the file outside every lock. Errors name no file.
bool P2PoolLocalJoin(const poolreg::PoolRecord& rec, const poollocal::Keys& keys, string& errOut);
// Read its saved share chain, once the block index is loaded.
bool P2PoolLocalLoad(const string& strName);
// The members' nodes this one dials and says hello to, each
// ADDRESS@HOST.onion[:PORT]; at most poollocal::MAX_LISTED_PEERS. Saved in
// the pool's file.
bool P2PoolLocalSetPeers(const string& strName, const vector<string>& vPeers, string& errOut);
// Forget a local pool: its sessions close and its files go on the next
// pass of the message thread. Refused while this node mines it.
bool P2PoolLocalLeave(const string& strName, string& errOut);
// Mine this local pool instead of pool zero (-p2pool=local:<name>); at
// startup, before any template is built.
bool P2PoolLocalMine(const string& strName, string& errOut);
// What -p2pool=<value> asks to mine (docs/pool-registry.md, section 9):
// pool zero (true, strLocalOut empty and idRegOut 0: no value, any value
// that is not a pool id, or pool zero's own id), a local pool (true, its
// name, from "local:<name>"), an Everpool pool (true, its id in idRegOut,
// from 64 hex digits), or nothing a node may start with (false, and why: 40
// to 80 hex digits that are not 64, a mistyped id). The value is never
// echoed back.
bool P2PoolParseChoice(const string& strValue, string& strLocalOut, uint256& idRegOut, string& errOut);
// -poolcarry=<pool id>[,<pool id>...]: added to vOut (no repeats); false on
// anything that is not a pool id, pool zero's id, or more than 8 in all.
bool P2PoolParseCarry(const string& strValue, vector<uint256>& vOut, string& errOut);
struct P2PoolLocalStatusInfo
{
    enum
    {
        PEER_NOT_CONNECTED = 0, // no connection this node dialled to it
        PEER_CONNECTED,         // dialled, no hello sent on it yet
        PEER_NO_PROOF,          // a hello went, and no session came of it
        PEER_OUR_CAP,           // this node is at its session cap for the pool
        PEER_SESSION,           // in session
    };
    poolreg::PoolRecord rec;
    size_t nSessions;       // members in session with this node
    size_t nInboundSessions;
    size_t nPending;        // hellos answered and not acked yet
    size_t nShares;
    int nTipHeight;
    vector<string> vPeers;
    vector<int> vPeerState; // one of the above per listed peer
    bool fMined;
    bool fAtCap;
};
bool P2PoolLocalStatus(const string& strName, P2PoolLocalStatusInfo& out);
// The names of this node's local pools.
void P2PoolLocalNames(vector<string>& out);
// Every peer some local pool of this node lists, once each.
void P2PoolLocalDialList(vector<string>& out);
// Whether some local pool of this node (not one being left) still lists
// that peer. Takes cs_p2pool: callers may hold cs_vNodes, not the other way.
bool P2PoolLocalStillListed(const string& strPeer);

// ---- Registered pools (docs/pool-registry.md, sections 8, 9, 11 and 17)
//
// A pool recorded on the chain, mined with -p2pool=<pool id> or carried
// with -poolcarry=<pool id>. Its messages, only between peers that say
// NODE_POOLREG:
//   poolinv    vector<uint256>, at most 32: the pools this node announces
//              (carried, complete, and holding shares or mined); after the
//              version, and again when the set changes, at most once a minute
//   p2xshare   pool id, ShareX: pushed only to peers that announced the pool
//   p2xgetsh   pool id, vector<uint256>
//   p2xsync    pool id, uint256 resume point (a share id, or 0)
//   p2xshares  pool id, int snapshot tip height, end flag, vector<ShareX>
//              (at most 100 shares and 256 x 1024 bytes but for one share)
//   p2xnone    pool id: this node holds nothing of that pool
//   poolwho    pool id: who carries it? (hints, as p2ppeers)
//   poolat     pool id, vector<string>: .btf addresses, the answer
// Whether the pool is active on this node's chain decides only whether it
// is carried, mined and announced; never whether a share of it is valid.

static const size_t MAX_POOL_CARRY = 8;
// Registered pools are open on testnet, and on mainnet once the release that
// carries and mines them there sets POOL_REGISTRY_MAINNET_OPEN (poolindex.h,
// docs/pool-registry.md section 9). Until then, on mainnet, no registered
// pool is mined, carried, announced, relayed or served, every registry
// message is dropped unread, and -p2pool=<pool id> and -poolcarry are
// refused with this.
static const char* const P2POOL_REG_CLOSED =
    "Everpool pools are not open on mainnet in this release: -p2pool=<pool id> and -poolcarry work on testnet only";
// The pool mined (fMine) or one more carried. Before P2PoolInit, which reads
// back their files (pools/<id>.dat, or pools/<id>.part for a fetch in
// progress); a pool with no file here joins once the registry index names
// it. False for pool zero's id, a ninth -poolcarry pool, or any pool where
// registered pools are not open (P2POOL_REG_CLOSED).
bool P2PoolRegWant(const uint256& id, bool fMine, string& errOut);
// The pools wanted: the mined one first, then those carried.
void P2PoolRegWanted(vector<uint256>& out);
// Whether this node's miners can be given a template now; why not
// otherwise (a registered pool mined: unknown, pending, its line still on
// its way). Always true for pool zero and a local pool.
bool P2PoolMinedReady(string& whyOut);
struct P2PoolRegStatusInfo
{
    enum { FETCH_IDLE = 0, FETCH_RUNNING, FETCH_CATCHUP, FETCH_COMPLETE };
    bool fMined;
    bool fCarry;
    bool fGuard;            // guarded here (section 10), or its line pulled for the draw
    bool fCarried;          // its shares taken, relayed and served
    bool fAnnounced;
    int nStatus;            // PoolStatus, as this node last read it
    int nFetch;
    size_t nShares;
    size_t nBytes;          // of every share held, as the guard budget counts them
    int nTipHeight;
    uint256 work;           // the tip line's work over the last window
    size_t nAnnouncers;     // peers whose latest poolinv names it
    size_t nServes;         // paced serves of it in flight
};
// A wanted pool's state on this node; false for a pool not wanted here.
bool P2PoolRegStatus(const uint256& id, P2PoolRegStatusInfo& out);

// Self-tests and fuzz: a registered pool from its record, active, mined or
// carried (fFiles false: no files); its status set; its fetch state (-1: no
// such pool); the message thread's once-a-second pass made now; every time
// the registered pools keep made nSecs older; and a pool dropped from
// memory and read back from its files, as at a restart.
bool P2PoolRegAddForTest(const poolreg::PoolRecord& rec, bool fMine, bool fCarry, bool fFiles, string& errOut);
void P2PoolRegSetStatusForTest(const uint256& id, int nStatus);
int P2PoolRegFetchForTest(const uint256& id);
void P2PoolRegTickForTest();
void P2PoolRegAgeForTest(int64 nSecs);
// Self-tests: the paced serves in flight made nSecs older, their last part
// left as recent as it was (slow, not stalled).
void P2PoolRegAgeServeStartsForTest(int64 nSecs);
// fForceActive false: the pool comes back as at a real start, its status not
// known until the index says (P2PoolRegIndexForTest).
bool P2PoolRegReloadForTest(const uint256& id, bool fForceActive = true);
// Self-tests: statuses read from a made-up registry index from now on,
// ready (loaded, at its tip, not rebuilding) or not, naming these pools with
// these statuses; or from the node's own index; and the cap on a registered
// pool's partial file made smaller (0: the pool's byte cap).
void P2PoolRegIndexForTest(bool fReady, const vector<std::pair<uint256, int> >& vStatus);
void P2PoolRegUseNodeIndexForTest();
void P2PoolRegSetPartCapForTest(const uint256& id, uint64 n);

// ---- Guardians (docs/pool-registry.md, sections 10 to 12)
//
// Between NODE_POOLREG peers, where registered pools are open and the node
// guards (-poolguard, on by default):
//   pooltkt     uint32 epoch, uint256 ticket seed, vector of 118-byte
//               guardian tickets (at most 512): relayed when held, or in
//               answer to poolgettkt
//   poolgettkt  uint32 epoch: send me the tickets you hold for it (at most
//               4096, in parts of 512)
// Tickets are checked on a thread of their own with its own RandomX VM and
// budget; the draw over them decides which registered pools this node
// guards (carries like a -poolcarry pool, within -poolguardmb) and which
// nodes a seeker of a pool dials. Nothing of it decides a share's validity.

// -poolguard (false: no tickets made, relayed, served or asked for; never
// drawn), -poolguardmb (the guard budget in MB; 0 keeps 128) and
// -poolguardkbps (each registered history serve's pace in KB/s; 0 keeps 64).
// At startup, before P2PoolTicketsStart.
void P2PoolGuardSetOptions(bool fGuard, int64 nMB, int64 nKBps);
// Whether this node takes part: registered pools open here, -poolguard on.
bool P2PoolGuarding();
// The ticket thread: started after StartNode (pool-tickets.dat is read and
// queued to be checked again, never hashed at start), stopped at exit with a
// last save of pool-tickets.dat and pool-guards.dat.
void P2PoolTicketsStart();
void P2PoolTicketsStop();
// The .btf addresses of the guardians (this epoch's and the previous one's
// 16) of the pools this node looks for: the one it mines while its line is
// not here, and drawn pools nobody announces. At most 16; the dialler adds
// up to 3 connections for them.
void P2PoolGuardDialList(vector<string>& out);
struct P2PoolGuardianInfo
{
    string strBtf;
    int nRank;              // 0 to 7 guardian, 8 to 15 reserve
    bool fSelf;
    unsigned short nCapacityMB;
};
struct P2PoolGuardDrawInfo
{
    int nEpoch;
    bool fSettled;
    int64 nUntil;           // the height its guardians let go at
    size_t nTickets;        // held for the epoch
    vector<P2PoolGuardianInfo> vGuardians;  // the pool's 16 in this node's view, lowest score first
    int nOwnRank;           // this node's place in this draw, -1 when not drawn
    P2PoolGuardDrawInfo() : nEpoch(-1), fSettled(false), nUntil(0), nTickets(0), nOwnRank(-1) {}
};
struct P2PoolGuardInfo
{
    bool fGuarding;         // false: tickets are off here (mainnet closed, or -poolguard=0)
    int nEpoch;
    bool fSettled;
    size_t nTickets;        // held for the epoch
    vector<P2PoolGuardianInfo> vGuardians;  // the pool's 16 in this node's view, lowest score first
    int nOwnRank;           // this node's place for it, -1 when not drawn
    int64 nOwnUntil;        // until which height that place holds
    string strOwn;          // what this node does with it
    vector<P2PoolGuardDrawInfo> vDraws; // the draws in force, oldest epoch first: the previous
                                        // epoch's while its guardians linger, this epoch's, and
                                        // the next one's once settled
    P2PoolGuardInfo() : fGuarding(false), nEpoch(-1), fSettled(false), nTickets(0), nOwnRank(-1), nOwnUntil(0) {}
};
// A pool's guardians this epoch, as poolinfo shows them.
bool P2PoolGuardians(const uint256& id, P2PoolGuardInfo& out);

// Self-tests: the ticket book's parameters (a cheap work hash), the chain
// the tickets see (the hash of every height up to the tip), the key this
// node's own ticket is signed with, the active pools the draw reads, one
// pass of the ticket thread (returns the tickets it hashed), the ticket
// state's clocks made older, the ticket budget set, what is held, own and
// queued (pnode NULL: this node's file), pool-tickets.dat written and read
// back as at a start, the guard budget, what the guard decided, and
// pool-guards.dat written and read back.
class CTicketParams;
class CGuardTicket;
class CPoolInfo;
void P2PoolTicketParamsForTest(const CTicketParams& params);
void P2PoolTicketViewForTest(const vector<uint256>& vHashes);
void P2PoolTicketKeyForTest(const unsigned char seckey[32]);
void P2PoolTicketPoolsForTest(const vector<CPoolInfo>& v);
int P2PoolTicketStepForTest(int nMaxVerify, bool fMake);
void P2PoolTicketAgeForTest(int64 nSecs);
void P2PoolTicketBudgetForTest(int nTokens);
size_t P2PoolTicketHeldForTest(unsigned int nEpoch);
bool P2PoolTicketIsHeldForTest(unsigned int nEpoch, const CGuardTicket& t);
bool P2PoolTicketOwnForTest(unsigned int nEpoch, CGuardTicket& out);
void P2PoolTicketQueuedForTest(CNode* pnode, unsigned int nEpoch, size_t& nRelayOut, size_t& nAnswerOut);
bool P2PoolTicketSaveForTest();
size_t P2PoolTicketLoadForTest();
void P2PoolGuardLimitsForTest(int64 nBudget, int64 nMaxPoolBytes, unsigned int nMaxPools);
// A guard pull (section 10) holds one of 4 slots. A peer that announces a
// pool and then serves nothing, or drips it, must not hold a slot for good:
// that would keep this node from pulling any pool it is drawn for. A pull
// that averages under GUARD_PULL_MIN_RATE bytes a second once it is
// GUARD_PULL_STALL old, or that is not complete GUARD_PULL_LONGEST after it
// began, gives its slot back, and the pool is not pulled again for
// GUARD_PULL_BACKOFF (a peer announcing it again does not shorten that).
// A pull past what this node would keep of one pool (the per-pool guard cap,
// or the budget if smaller) stops there: the pool cannot be guarded here, so
// the rest of its line is not fetched (section 11).
static const int64 GUARD_PULL_STALL = 20 * 60;
static const int64 GUARD_PULL_MIN_RATE = 1000;
static const int64 GUARD_PULL_LONGEST = 4 * 60 * 60;
static const int64 GUARD_PULL_BACKOFF = 2 * 60 * 60;
// Self-tests: the guard clocks (pulls and their backoff) moved back; whether
// registered pools keep files (pools/<id>.dat and .part).
void P2PoolGuardAgeForTest(int64 nSecs);
void P2PoolRegFilesForTest(bool fFiles);
struct P2PoolGuardEntryInfo
{
    uint256 id;
    int nRank;
    int64 nUntil;
    int nChoice;            // GuardChoice
    bool fEmpty;
    bool fGuard;            // its RegPool is flagged guarded now
};
void P2PoolGuardEntriesForTest(vector<P2PoolGuardEntryInfo>& out);
void P2PoolGuardSaveForTest();
size_t P2PoolGuardLoadForTest();
// Self-tests: guard-only pools out of memory and nothing drawn, as at a
// start (P2PoolGuardLoadForTest then reads pool-guards.dat); one entry's
// place and linger end set and kept, as a redraw this run cannot see would
// have left them; the node taken as behind (initial block download, or a
// tip a day old) or caught up.
void P2PoolGuardRestartForTest();
void P2PoolGuardSetEntryForTest(const uint256& id, int nRank, int64 nUntil);
void P2PoolTicketBehindForTest(bool fBehind);

// Self-tests: the onions this node answers hellos for, the registered
// class's counters, and its budgets emptied.
void P2PoolSetOwnOnionsForTest(const vector<string>& v);
size_t P2PoolRegisteredOrphanCount();
int P2PoolRegisteredShareWorkTokens();
size_t P2PoolRegisteredServesForTest();
void P2PoolDrainRegisteredBudgetsForTest();
// Self-tests: n bytes queued on a connection as a message of a pool other
// than zero; the bytes of such messages still queued (and the stretches
// kept to count them).
void P2PoolQueueRegBytesForTest(CNode* pnode, size_t n);
size_t P2PoolRegQueuedForTest(CNode* pnode, size_t* pnSpans = NULL);
// Self-tests: the bytes the paced serves in flight hold for their snapshots,
// and the next share of each made to be one the chain no longer holds.
size_t P2PoolRegServeHeldBytesForTest();
void P2PoolRegServeLoseNextForTest();
// Self-tests: the budgets for proven peers' shares in local pools (each
// pool's and each session's) emptied or refilled, and the connections the
// registered class holds a share or an ask for.
void P2PoolDrainProvenWorkForTest(bool fPools, bool fSessions);
void P2PoolRefillProvenWorkForTest();
size_t P2PoolRegisteredDeferredCount();
// Self-tests: a local pool's budget for its proven peers set to n tokens; a
// session's count of wasted tokens set, and read (-1 with no session); a
// session's own tokens (-1 with no session); the connections a local pool
// keeps state for; whether this node asked a local pool's members for a
// share lately.
bool P2PoolLocalSetPoolTokensForTest(const string& strName, int n);
bool P2PoolLocalSetWorkDebtForTest(const string& strName, CNode* pnode, int nDebt);
int P2PoolLocalWorkDebtForTest(const string& strName, CNode* pnode);
int P2PoolLocalSessionTokensForTest(const string& strName, CNode* pnode);
size_t P2PoolLocalPeerEntriesForTest(const string& strName);
bool P2PoolLocalAskedForTest(const string& strName, const uint256& id);
bool P2PoolLocalNoteAskedForTest(const string& strName, const uint256& id);
// Self-tests: the hellos sent and read on a connection made nSecs older.
void P2PoolLocalAgeHelloForTest(CNode* pnode, int64 nSecs);
// Self-tests: the message thread's check of one connection for a listed
// peer reached at another onion than the one listed (true: dropped), and
// the drops made so far made nSecs older.
bool P2PoolLocalDropWrongOnionForTest(CNode* pnode);
void P2PoolLocalAgeWrongOnionDropsForTest(int64 nSecs);

#endif
