// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Guardian tickets and the draw (docs/pool-registry.md, section 10: "Epochs
// and seeds", "Who can be drawn: candidates and tickets", "The draw",
// "Handoff"; sections 11 and 12 for the bounds).
//
// A guardian of a registered pool keeps its share chain for one epoch of 720
// blocks. Who guards what is drawn from tickets: 118 bytes signed by a node's
// .btf key, carrying a RandomX proof of work against a block hash known an
// epoch ahead. This file is the part with no network in it:
//
//   - the epochs and their seeds, as functions of a height and of a view of
//     the active chain;
//   - the ticket: its bytes, its work header, its signature, how one is made
//     and how one is checked;
//   - the tickets a node holds for an epoch: one per key, the 4096 lowest
//     work hashes, and the bodies it already checked;
//   - the draw: every pool's own order of the tickets, 8 guardians and 8 in
//     reserve, and which of the pools a node is drawn for fit in its budget;
//   - pool-tickets.dat.
//
// Nothing here decides whether a share or a block is valid. Guardians are
// availability: two nodes holding slightly different ticket sets disagree
// about who keeps a copy, never about a share.
//
// Not locked: whoever owns a CTicketBook locks it.

#ifndef BITFLASH_POOLTICKET_H
#define BITFLASH_POOLTICKET_H

#include <map>
#include <set>
#include <string>
#include <vector>

// ---- epochs ---------------------------------------------------------------

// An epoch is 720 blocks: epoch e is heights 720e to 720e + 719.
static const int GUARD_EPOCH_BLOCKS = 720;
// The ticket deadline of epoch e is block 720e - 120.
static const int GUARD_DEADLINE_BEFORE = 120;
// The draw seed of epoch e is the hash of block 720e - 60.
static const int GUARD_DRAW_SEED_BEFORE = 60;
// A seed counts once its block has this many confirmations: the block and 29
// on top (the same count the registry index uses).
static const int GUARD_SEED_CONFIRMATIONS = 30;
// Old guardians keep a pool until 720e + 180.
static const int GUARD_LINGER_BLOCKS = 180;
// Guardians and reserve of one pool.
static const unsigned int GUARD_PLACES = 8;
static const unsigned int GUARD_RESERVE = 8;
// Tickets held per epoch, and bodies remembered as checked.
static const unsigned int GUARD_MAX_TICKETS = 4096;
static const unsigned int GUARD_MAX_CHECKED = 16384;
// Bodies that left a full checked set, remembered by a salted 64-bit tag so
// that a replay of one costs no hash. A std::set node is about 48 bytes:
// under 4 MB an epoch.
static const unsigned int GUARD_MAX_GONE = 65536;
// Draw seeds an epoch was drawn with before a redraw, kept through the linger.
static const unsigned int GUARD_MAX_OLD_DRAW_SEEDS = 4;
// The guard budget (section 11).
static const unsigned int GUARD_MAX_POOLS = 8;
static const int64 GUARD_DEFAULT_BYTES = 128 * 1024 * 1024;
static const int64 GUARD_MAX_POOL_BYTES = 64 * 1024 * 1024;

static const size_t GUARD_TICKET_BODY = 54;
static const size_t GUARD_TICKET_SIZE = 118;
// The work header's nVersion: the bytes "BTFG" as the node serializes an int.
static const int GUARD_TICKET_HEADER_VERSION = 0x47465442;

// The ticket target, frozen with the format (a change is a new ticket version
// in a new command). 2^-13 of all hashes: 8192 tries on average, one hash to
// check. Measured on the verification (light) RandomX VM at idle priority on
// a busy four-core server: 33 to 55 hashes a second, so two and a half to
// four minutes of one core for a ticket. The same on both networks.
static const unsigned int GUARD_TICKET_BITS_MAINNET = 0x1f07ffff;
static const unsigned int GUARD_TICKET_BITS_TESTNET = 0x1f07ffff;

namespace pooltkt
{

// The height's epoch. Heights below zero have none (-1).
int EpochOf(int nHeight);
// These are heights; they are below zero for epochs with no such block.
// Epoch 0 has no ticket seed (it would be block -720), so the first epoch
// with tickets and a draw is epoch 1, seeded by the genesis block.
int64 EpochStart(int64 nEpoch);
int64 TicketSeedHeight(int64 nEpoch);       // 720(e - 1)
int64 TicketDeadlineHeight(int64 nEpoch);   // 720e - 120
int64 DrawSeedHeight(int64 nEpoch);         // 720e - 60
int64 DrawSettleHeight(int64 nEpoch);       // 720e - 31
int64 LingerEndHeight(int64 nEpoch);        // 720e + 180: guardians of e - 1 let go

} // namespace pooltkt

// The active chain as the tickets see it: its tip's height and the hash of
// the block at a height. The node answers from pindexBest; the self-test from
// a table.
class CTicketChainView
{
public:
    virtual ~CTicketChainView() {}
    // -1 with no chain.
    virtual int TipHeight() const = 0;
    // False when the active chain has no block at that height.
    virtual bool HashAt(int nHeight, uint256& hashOut) const = 0;
};

namespace pooltkt
{

// The ticket seed of epoch e: the hash of block 720(e - 1). False when the
// active chain has no such block. fBuriedOut says whether it has 30
// confirmations, which is when tickets against it are made and taken.
bool TicketSeed(const CTicketChainView& view, int64 nEpoch, uint256& hashOut, bool& fBuriedOut);
// Whether the node has the deadline block of epoch e on its active chain.
bool PastDeadline(const CTicketChainView& view, int64 nEpoch);
// The draw seed of epoch e: the hash of block 720e - 60. False when the
// active chain has no such block. fSettledOut: the tip is at 720e - 31 or
// above, so the block has 30 confirmations.
bool DrawSeed(const CTicketChainView& view, int64 nEpoch, uint256& hashOut, bool& fSettledOut);
// Whether a ticket's epoch is the previous, the current or the next one by
// the view's tip (and has a seed at all: epoch 1 or later). The previous
// epoch counts only through handoff: while the tip is below the current
// epoch's LingerEndHeight (720e + 180).
bool EpochInRange(const CTicketChainView& view, int64 nEpoch);

} // namespace pooltkt

// ---- the ticket -----------------------------------------------------------

// How a ticket's work header is hashed. NULL in the parameters means the main
// chain's proof of work (PoWHashHeader); the self-test names a cheap one to
// fill sets of thousands.
typedef uint256 (*TicketWorkFn)(const unsigned char* pHeader80);

// What a ticket is checked against: one set per network, frozen.
class CTicketParams
{
public:
    unsigned char magic[4];   // pchMessageStart
    unsigned int nBits;       // the ticket target
    unsigned int nTime;       // the work header's nTime: PoWV2Time()
    TicketWorkFn fnWork;      // NULL: PoWHashHeader

    CTicketParams();
    // This node's network (pchMessageStart, PoWV2Time(), the network's target).
    static CTicketParams Network();
    uint256 Target() const;
};

class CGuardTicket
{
public:
    // 0: magic(4)  4: "BTFG"  8: epoch(4, LE)  12: x-only key(32)
    // 44: capacity in MB(2, LE)  46: nonce(8, LE)
    unsigned char body[GUARD_TICKET_BODY];
    unsigned char sig[64];

    CGuardTicket();

    // The 118 bytes, and back. FromBytes takes exactly 118.
    std::vector<unsigned char> Bytes() const;
    bool FromBytes(const unsigned char* p, size_t n);

    void SetBody(const unsigned char magic[4], unsigned int nEpoch, const unsigned char pubkey[32],
                 unsigned short nCapacityMB, uint64 nNonce);
    void SetNonce(uint64 nNonce);

    bool HasMagic(const unsigned char magic[4]) const;
    bool HasTag() const;
    unsigned int Epoch() const;
    const unsigned char* PubKey() const { return body + 12; }
    std::vector<unsigned char> Key() const { return std::vector<unsigned char>(body + 12, body + 44); }
    unsigned short CapacityMB() const;
    uint64 Nonce() const;

    // SHA256d of the 54 bytes: the body's name in the checked set, and the
    // work header's merkle root.
    uint256 BodyHash() const;
    // What the signature signs: SHA256("Bitflash/guard-ticket/1" || body).
    void SigHash(unsigned char out32[32]) const;
    // The 80 bytes whose proof of work is the ticket's work.
    void WorkHeader(const CTicketParams& params, const uint256& hashSeed, unsigned char out80[80]) const;
    uint256 WorkHash(const CTicketParams& params, const uint256& hashSeed) const;

    // BIP340, as descriptors are signed and checked. Sign fills the body's
    // key from the secret key's and is deterministic (no auxiliary
    // randomness), so the same key and body give the same 118 bytes.
    bool Sign(const unsigned char seckey[32]);
    bool VerifySig() const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(body));
        READWRITE(FLATDATA(sig));
    )

    bool operator==(const CGuardTicket& b) const
    {
        return memcmp(body, b.body, sizeof(body)) == 0 && memcmp(sig, b.sig, sizeof(sig)) == 0;
    }
};

namespace pooltkt
{

// The x-only public key of a secret key, as a .btf address encodes it.
bool XOnlyPubKey(const unsigned char seckey[32], unsigned char pubkeyOut[32]);

// Make a ticket: try nonces from nNonceStart, at most nMaxTries of them,
// until the work is at or under the target, then sign. False when none was
// found (nTriesOut says how many were hashed; the caller goes on from
// nNonceStart + nTriesOut) or when pfStop became true. A work hash of zero is
// a hash that could not be computed, never a ticket: MakeTicket stops there
// and returns false with fewer than nMaxTries counted, and the caller waits
// before it tries that nonce again. The node runs this in a thread of its own
// at idle priority; nothing here sleeps or yields.
bool MakeTicket(const CTicketParams& params, const uint256& hashSeed, unsigned int nEpoch,
                const unsigned char seckey[32], unsigned short nCapacityMB,
                uint64 nNonceStart, uint64 nMaxTries,
                CGuardTicket& ticketOut, uint256& hashWorkOut, uint64& nTriesOut,
                const volatile bool* pfStop = NULL);

} // namespace pooltkt

// ---- the tickets a node holds ---------------------------------------------

enum TicketVerdict
{
    // Passed (signature and work) and held: relayed on.
    TICKET_HELD = 0,
    // Passed, and its body is remembered, but not held: its key already has a
    // ticket with a lower work hash, or the set is full of lower ones.
    TICKET_OUTRANKED = 1,
    TICKET_PAST_CAP = 2,
    // Not final. Precheck: steps 1 and 2 passed, the ticket goes on to step
    // 3. VerifyTicket: the signature and the work passed, the ticket goes on
    // to Add.
    TICKET_PRECHECK_OK = 5,
    TICKET_VERIFIED = 6,
    // Step 2, before any hash, nobody scored.
    TICKET_DROP_EPOCH = 10,       // not the previous, current or next epoch
    TICKET_DROP_NO_SEED = 11,     // its seed block is not on this chain with 30 confirmations
    TICKET_DROP_OTHER_SEED = 12,  // the message names another seed than this chain's
    TICKET_DROP_DEADLINE = 13,    // an unasked relay after the deadline
    TICKET_DROP_SEEN = 14,        // a body already checked
    TICKET_DROP_NO_HASH = 15,     // this node could not compute the work hash (it came out zero)
    // The sender's fault, scored.
    TICKET_BAD_FRAMING = 20,      // not 118 bytes, or no "BTFG"
    TICKET_BAD_MAGIC = 21,        // another network's
    TICKET_BAD_EPOCH = 22,        // the body's epoch is not the message's
    TICKET_BAD_SIG = 23,
    TICKET_BAD_WORK = 24,
};

inline bool TicketPassed(int v) { return v == TICKET_HELD || v == TICKET_OUTRANKED || v == TICKET_PAST_CAP; }
inline bool TicketDropped(int v) { return v >= TICKET_DROP_EPOCH && v <= TICKET_DROP_NO_HASH; }
inline bool TicketScored(int v) { return v >= TICKET_BAD_FRAMING; }
const char* TicketVerdictName(int v);

namespace pooltkt
{

// Step 3 without the set: the signature, then the work against the seed.
// Touches no CTicketBook, so it runs with no lock held, on any thread.
// TICKET_VERIFIED with the work hash, TICKET_BAD_SIG, TICKET_BAD_WORK, or
// TICKET_DROP_NO_HASH when the hash came out zero (this node's failure, not
// the sender's: nobody scored, nothing remembered).
int VerifyTicket(const CTicketParams& params, const CGuardTicket& ticket, const uint256& hashSeed,
                 uint256& hashWorkOut);

} // namespace pooltkt

// A held ticket with its work hash.
class CHeldTicket
{
public:
    CGuardTicket ticket;
    uint256 hashWork;
    uint256 hashBody;
};

// One epoch's tickets, checked against one seed.
class CTicketEpoch
{
public:
    unsigned int nEpoch;
    uint256 hashSeed;
    // The held set, by key: one ticket per key.
    std::map<std::vector<unsigned char>, CHeldTicket> mapHeld;
    // The same, by (work hash, body hash), naming the key: the last one is
    // the first to go.
    std::map<std::pair<uint256, uint256>, std::vector<unsigned char> > mapHeldOrder;
    // Every body whose signature and work passed, with its work hash; and
    // those of them not held, by (work hash, body hash).
    std::map<uint256, uint256> mapChecked;
    std::set<std::pair<uint256, uint256> > setLoose;
    // Tags of the loose bodies that left a full checked set. A loose body is
    // never held again under the same seed (a key's ticket and the cap's
    // cutoff only go down), so a replay of one is a body already seen.
    std::set<uint64> setGone;
    // This node's own ticket for the epoch, if it made one.
    bool fOwn;
    CGuardTicket own;
    uint256 hashOwnWork;

    CTicketEpoch() : nEpoch(0), hashSeed(0), fOwn(false), hashOwnWork(0) {}
};

// What Sync found changed.
class CTicketSync
{
public:
    // Epochs whose seed left the active chain: their held and checked sets
    // and this node's own ticket are gone. The caller makes a ticket again
    // and asks its peers for the set.
    std::vector<unsigned int> vSeedGone;
    // Epochs too old to keep (before the previous one), forgotten.
    std::vector<unsigned int> vExpired;
    // Epochs whose draw seed is not the one last drawn with: a redraw. With
    // each, the seed it was drawn with before, and the height until which the
    // nodes drawn by that seed keep their pools: the later of the epoch's
    // LingerEndHeight and 180 blocks past the tip the redraw was seen at.
    std::vector<unsigned int> vRedraw;
    std::vector<uint256> vRedrawOldSeed;
    std::vector<int64> vRedrawUntil;
};

// One place in a pool's draw.
class CDrawPlace
{
public:
    uint256 hashScore;
    uint256 hashWork;
    std::vector<unsigned char> key;   // the ticket's .btf key
    unsigned short nCapacityMB;

    CDrawPlace() : hashScore(0), hashWork(0), nCapacityMB(0) {}
};

// The tickets of the previous, current and next epochs.
class CTicketBook
{
public:
    explicit CTicketBook(const CTicketParams& paramsIn);

    const CTicketParams& Params() const { return params; }

    // Steps 1 and 2 of the check: everything that costs no hash. Returns
    // TICKET_PRECHECK_OK when the ticket is to be checked in full (step 3),
    // and the reason otherwise. fAnswer: it came in answer to this node's own
    // poolgettkt (or from its own file), so the deadline does not apply.
    // Tickets that waited in a queue come through here again when they leave.
    int Precheck(const CTicketChainView& view, const unsigned char* p, size_t n,
                 unsigned int nMsgEpoch, const uint256& hashMsgSeed, bool fAnswer,
                 CGuardTicket& ticketOut) const;
    // Step 3, with no lock: pooltkt::VerifyTicket with this book's
    // parameters, which never change after construction. The caller charges
    // the ticket RandomX budget before calling, and holds no lock across it.
    int Verify(const CGuardTicket& ticket, const uint256& hashSeed, uint256& hashWorkOut) const;
    // The set: one per key and the cap, for a ticket Verify passed against
    // hashSeed with that work hash. The chain may have moved since Precheck,
    // so the seed is looked at again: TICKET_DROP_EPOCH, TICKET_DROP_NO_SEED
    // or TICKET_DROP_OTHER_SEED when hashSeed is no longer the buried seed of
    // the ticket's epoch on this view, and TICKET_DROP_OTHER_SEED too when
    // the book still holds that epoch under another seed (Sync was not run
    // since the reorg). Add never forgets an epoch: that is Sync's.
    int Add(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashSeed,
            const uint256& hashWork);
    // All three, for a caller with no budget and no lock to mind.
    int Accept(const CTicketChainView& view, const unsigned char* p, size_t n,
               unsigned int nMsgEpoch, const uint256& hashMsgSeed, bool fAnswer);
    int Accept(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashMsgSeed, bool fAnswer);

    // This node's own ticket for an epoch: checked like any other (as an
    // answer: a node may make its ticket after its own deadline), held if it
    // ranks, and remembered as its own either way.
    int AddOwn(const CTicketChainView& view, const CGuardTicket& ticket, const uint256& hashSeed);
    bool Own(unsigned int nEpoch, CGuardTicket& ticketOut, uint256& hashWorkOut) const;

    // Follow the chain: forget epochs before the previous one (and the
    // previous one once its linger is over), drop the sets of an epoch whose
    // seed block is no longer the active chain's, and say which settled draws
    // changed seed. Run on every change of tip, before any Add.
    void Sync(const CTicketChainView& view, CTicketSync& out);

    // What is held for an epoch, lowest work hash first (the order they are
    // served in), and the seed they were checked against.
    bool Has(unsigned int nEpoch) const;
    size_t Held(unsigned int nEpoch) const;
    size_t Checked(unsigned int nEpoch) const;
    // Loose bodies remembered only by their tag, and whether one is.
    size_t Gone(unsigned int nEpoch) const;
    bool IsGone(unsigned int nEpoch, const uint256& hashBody) const;
    // The self-test: a smaller limit than GUARD_MAX_GONE.
    void SetGoneLimit(size_t n) { nMaxGone = n; }
    bool Seed(unsigned int nEpoch, uint256& hashOut) const;
    void Tickets(unsigned int nEpoch, std::vector<CHeldTicket>& out) const;
    bool HeldByKey(unsigned int nEpoch, const unsigned char pubkey[32], CHeldTicket& out) const;
    bool IsChecked(unsigned int nEpoch, const uint256& hashBody) const;
    std::vector<unsigned int> Epochs() const;

    // The draw of one pool in an epoch, over the tickets held: up to 16
    // places, lowest score first; the first 8 are its guardians, the rest its
    // reserve. False when the active chain has no draw seed for the epoch
    // yet. fSettledOut: the seed has its 30 confirmations. Remembers the seed
    // drawn with, for Sync's vRedraw.
    bool Draw(const CTicketChainView& view, unsigned int nEpoch, const uint256& poolId,
              std::vector<CDrawPlace>& out, bool& fSettledOut);
    // Where this node's own ticket stands in each of these pools: 0 to 7 a
    // guardian, 8 to 15 in reserve, -1 neither (or no own ticket held).
    // Costs pools times tickets SHA256d.
    bool OwnRanks(const CTicketChainView& view, unsigned int nEpoch, const std::vector<uint256>& vPools,
                  std::vector<int>& vRankOut, bool& fSettledOut);
    // The same under a draw seed the caller names (one of OldDrawSeeds): the
    // pools this node was drawn for before a redraw, while it still holds the
    // tickets of that epoch.
    void OwnRanksBySeed(const CTicketChainView& view, unsigned int nEpoch, const uint256& hashDrawSeed,
                        const std::vector<uint256>& vPools, std::vector<int>& vRankOut) const;
    // The seeds an epoch was drawn with before a redraw and whose linger is
    // not over: nodes drawn by any of them, or by the present seed, hold the
    // pool. Not saved in the file.
    void OldDrawSeeds(unsigned int nEpoch, std::vector<uint256>& out) const;

    // Forget everything (the self-test, and a change of network).
    void Clear();

    const std::map<unsigned int, CTicketEpoch>& All() const { return mapEpochs; }

private:
    CTicketParams params;
    std::map<unsigned int, CTicketEpoch> mapEpochs;
    std::map<unsigned int, uint256> mapDrawnSeed;
    // Per epoch: (seed drawn with before a redraw, height its linger ends).
    std::map<unsigned int, std::vector<std::pair<uint256, int64> > > mapOldDrawSeed;
    // The salt of the replay tags, this node's own, so nobody can aim a body
    // at another body's tag.
    unsigned char salt[32];
    size_t nMaxGone;

    uint64 GoneTag(const uint256& hashBody) const;
    void RememberChecked(CTicketEpoch& ep, const uint256& hashBody, const uint256& hashWork, bool fHeld);
    void Unhold(CTicketEpoch& ep, const std::vector<unsigned char>& key);
};

// ---- the draw -------------------------------------------------------------

namespace pooltkt
{

// score(t, P) = SHA256d("Bitflash/guard/1" || draw seed || pool id || work
// hash), each hash as the node serializes a uint256; compared as a number,
// lowest first.
uint256 Score(const uint256& hashDrawSeed, const uint256& poolId, const uint256& hashWork);

// A pool's places over a set of tickets: at most nPlaces, lowest score first
// (equal scores, which take a SHA256d collision, by work hash).
void Draw(const uint256& hashDrawSeed, const uint256& poolId, const std::vector<CHeldTicket>& vTickets,
          unsigned int nPlaces, std::vector<CDrawPlace>& out);

// How many of the tickets score below this work hash for the pool, counted up
// to nPlaces: the rank of the ticket with that work hash, or nPlaces if it
// has no place.
unsigned int RankOf(const uint256& hashDrawSeed, const uint256& poolId, const std::vector<CHeldTicket>& vTickets,
                    const uint256& hashWork, unsigned int nPlaces);

} // namespace pooltkt

// ---- the guard budget -----------------------------------------------------

// What a node knows of a pool's line: held, or offered at handoff.
class CGuardLine
{
public:
    bool fKnown;        // false: not pulled yet
    unsigned int nShares;
    int64 nBytes;       // the whole line, uncles included
    CBigNum bnWork;     // over the pool's last window

    CGuardLine() : fKnown(false), nShares(0), nBytes(0), bnWork(0) {}
};

// Answers for one pool. May leave the line unknown.
typedef void (*GuardLineFn)(void* pCtx, const uint256& poolId, CGuardLine& lineOut);

enum GuardChoice
{
    GUARD_NOT_DRAWN = 0,   // no place among the pool's 16
    GUARD_KEEP = 1,        // guarded: a slot and its bytes
    GUARD_EMPTY = 2,       // drawn, the pool has no shares: no slot, nothing to keep yet
    GUARD_PULL = 3,        // drawn, line not known yet: to be pulled, ranked once known
    GUARD_NO_ROOM = 4,     // drawn, does not fit: left to the next in its ranking
};

class CGuardDecision
{
public:
    uint256 poolId;
    int nRank;          // 0..7 guardian, 8..15 reserve, -1 not drawn
    int nChoice;        // GuardChoice
    CGuardLine line;

    CGuardDecision() : poolId(0), nRank(-1), nChoice(GUARD_NOT_DRAWN) {}
};

namespace pooltkt
{

// Which of the pools a node is drawn for it keeps. Pools where it is one of
// the 8 come before pools where it is in reserve (the reserve takes what room
// is left); within each, heaviest line first, a line not known yet last, and
// equal work by pool id. A pool is kept while fewer than nMaxPools are, its
// line is at most nMaxPoolBytes and fits in what is left of nBudgetBytes;
// one that does not fit is skipped whole and the next is tried. Pools with
// no shares take no slot. vOut is in that order, the pools not drawn last.
void ChooseGuarded(const std::vector<uint256>& vPools, const std::vector<int>& vRanks,
                   GuardLineFn fnLine, void* pCtx,
                   int64 nBudgetBytes, int64 nMaxPoolBytes, unsigned int nMaxPools,
                   std::vector<CGuardDecision>& vOut);

} // namespace pooltkt

// ---- pool-tickets.dat -----------------------------------------------------

// One epoch as the file keeps it: the seed the tickets were checked against,
// this node's own ticket, and the held set.
class CTicketFileEpoch
{
public:
    unsigned int nEpoch;
    uint256 hashSeed;
    std::vector<CGuardTicket> vOwn;      // none or one
    std::vector<CGuardTicket> vTickets;

    CTicketFileEpoch() : nEpoch(0), hashSeed(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nEpoch);
        READWRITE(hashSeed);
        READWRITE(vOwn);
        READWRITE(vTickets);
    )
};

namespace pooltkt
{

// The file: a version, the network's magic, up to three epochs, and the hash
// of all of it; written to a temporary name and renamed into place.
bool SaveTicketFile(const std::string& strPath, const CTicketBook& book);
// Reads it. False, with the reason, when there is none or it is not this
// version's, this network's, whole and consistent: the node then starts with
// no tickets and asks its peers. What is read is not trusted: the caller
// feeds every ticket back through the checks as an answer, each with its
// epoch's seed (CTicketBook::Accept, or the ticket budget queue in the node).
bool LoadTicketFile(const std::string& strPath, const CTicketParams& params,
                    std::vector<CTicketFileEpoch>& vOut, std::string& strWhyOut);
// Feeds what a file held back through the checks, own tickets included.
// Returns how many are held after. For the self-test and for callers with no
// budget to mind: it hashes every ticket where it stands (up to 3 x 4096
// RandomX hashes), so the node does not call it at start; there the file's
// tickets go through the ticket budget queue like an answer.
size_t RestoreTickets(CTicketBook& book, const CTicketChainView& view, const std::vector<CTicketFileEpoch>& vFile);

} // namespace pooltkt

#endif
