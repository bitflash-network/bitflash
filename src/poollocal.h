// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// P2Pool local (docs/pool-registry.md, section 18): a private pool whose
// record is never put on the chain. Its members hand each other a pool code
// and, if they chose one, a password; from those two every member derives
// the same pool id and the same two keys, and nobody else can.
//
// Here: the pool code, the derivation, the coinbase anchor, and the hello by
// which two member nodes recognise each other while a non-member gets
// silence. Pure: no node, no chain, no socket, and the clock is an argument.

#ifndef BITFLASH_POOLLOCAL_H
#define BITFLASH_POOLLOCAL_H

#include "poolrecord.h"

#include <stdint.h>
#include <deque>
#include <map>
#include <string>
#include <vector>

namespace poollocal
{

// ---- The pool code ---------------------------------------------------------

// "btfl1:" then the record in hex, then the first 4 bytes of its SHA256d in
// hex. Lowercase only, so a pool has one code. It never holds the password.
std::string Code(const poolreg::PoolRecord& rec);
// False unless the text is a code in exactly that form, its checksum holds,
// and the record inside is a valid local ("BTFL") record.
bool ParseCode(const std::string& code, poolreg::PoolRecord& out, std::string& errOut);

// ---- Identity --------------------------------------------------------------

// Argon2id (libsodium crypto_pwhash, ARGON2ID13): 3 passes, 64 MiB.
static const unsigned long long KDF_PASSES = 3;
static const size_t KDF_MEMORY = 64 * 1024 * 1024;
static const size_t MAX_PASSWORD_LEN = 1024;

struct Keys
{
    unsigned char K[32];    // the stretched password
    unsigned char id[32];   // the local pool id, internal byte order
    unsigned char A[32];    // authenticates members to each other
    unsigned char C[32];    // keys the coinbase anchor
};

// K  = Argon2id(password, salt), salt = the first 16 bytes of
//      SHA256d("Bitflash/localpool/1/salt" || magic || record);
// id = SHA256d("Bitflash/localpool/1/id" || magic || record || K);
// A  = HMAC-SHA256(K, "Bitflash/localpool/1/auth" || id);
// C  = HMAC-SHA256(K, "Bitflash/localpool/1/anchor" || id).
// With no password the same runs on the empty string. 'magic' is the
// network's message start. False if the record is not a valid local record,
// the password is too long, or the 64 MiB cannot be had.
bool Derive(const std::vector<unsigned char>& record, const unsigned char magic[4],
            const std::string& password, Keys& out, std::string& errOut);

// The same from K, as a node does on start from the file it saved (it never
// stores the password): no Argon2id run.
bool DeriveFromK(const std::vector<unsigned char>& record, const unsigned char magic[4],
                 const unsigned char K[32], Keys& out, std::string& errOut);

// ---- The coinbase anchor ---------------------------------------------------

static const size_t ANCHOR_BYTES = 35;      // "p2l" and 32 bytes

// HMAC-SHA256(C, hashShareData): what follows "p2l" in the push.
void AnchorTag(const unsigned char C[32], const unsigned char hashShareData[32], unsigned char out[32]);
// The 35 bytes pushed: "p2l" and the tag.
std::vector<unsigned char> AnchorData(const unsigned char C[32], const unsigned char hashShareData[32]);
// Whether 35 pushed bytes are this pool's anchor for this share data
// (constant time on the tag).
bool AnchorMatches(const std::vector<unsigned char>& pushed, const unsigned char C[32],
                   const unsigned char hashShareData[32]);

// ---- The hello -------------------------------------------------------------

// O: the onion the initiator dialled, one way only: the 56 lowercase
// characters of the v3 name, without ".onion" and without "ADDR@". False if
// the text does not hold a v3 onion name.
bool OnionName(const std::string& addr, std::string& oOut);

static const size_t NONCE_BYTES = 32;
static const size_t TAG_BYTES = 16;         // hello and reply tags
static const size_t ACK_BYTES = 32;
static const size_t HANDLE_BYTES = 8;       // the session's name on a connection

// p2lhello, both ways: a nonce and a 16-byte tag (48 bytes).
struct Hello
{
    unsigned char nonce[NONCE_BYTES];
    unsigned char tag[TAG_BYTES];
};

// tA = HMAC(A, "hello" || O || nA), first 16 bytes.
void HelloTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32], unsigned char out[TAG_BYTES]);
// tB = HMAC(A, "reply" || O || nA || nB), first 16 bytes.
void ReplyTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
              const unsigned char nB[32], unsigned char out[TAG_BYTES]);
// HMAC(A, "ack" || O || nA || nB), all 32 bytes.
void AckTag(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
            const unsigned char nB[32], unsigned char out[ACK_BYTES]);
// h = HMAC(A, "session" || O || nA || nB), first 8 bytes.
void SessionHandle(const unsigned char A[32], const std::string& O, const unsigned char nA[32],
                   const unsigned char nB[32], unsigned char out[HANDLE_BYTES]);
// The handle as the uint64 the messages carry: its 8 bytes read as a
// little-endian number, as the node's serialization writes integers, so the
// bytes on the wire are h on every host.
uint64_t HandleValue(const unsigned char h[HANDLE_BYTES]);

static const size_t MAX_LOCAL_POOLS = 4;        // per node
static const size_t MAX_LISTED_PEERS = 16;      // per local pool
static const size_t MAX_SESSIONS = 16;          // per local pool, both directions
static const size_t SEEN_NONCES = 256;          // per local pool
static const int64_t REPLY_TIMEOUT = 30;        // seconds an unacked reply lives
static const int64_t HELLO_INTERVAL = 60;       // one hello read per connection per minute
static const int HELLO_LIFETIME = 8;            // and this many in a connection's life

// What a connection may ask of this node in hellos, whatever pool they are
// for: checked before anything is read or hashed.
struct HelloLimiter
{
    int64_t nLast;
    int nTotal;
    HelloLimiter() : nLast(0), nTotal(0) {}
    bool Allow(int64_t nNow);
};

// One local pool's sessions on this node. A connection is named by a number
// the caller picks (unique among live connections). Not thread safe: the
// caller holds its own lock.
class Sessions
{
public:
    // Keeps A alone of the keys, and wipes it when it goes (each copy its
    // own).
    explicit Sessions(const Keys& keysIn);
    ~Sessions();

    // Initiator, step 1: the hello for a listed peer dialled at onion O.
    // False (send nothing) when the pool is at its session cap, the onion is
    // not a v3 name, or a hello is already out on this connection.
    bool StartHello(uint64_t conn, const std::string& O, const unsigned char nA[32], Hello& out);
    // Initiator, step 3: the peer's reply. True opens the session: ackOut is
    // to be sent and hOut names the session. False: not this pool's reply
    // (the caller tries its other pools, then says nothing).
    bool OnReply(uint64_t conn, const Hello& reply, unsigned char ackOut[ACK_BYTES],
                 unsigned char hOut[HANDLE_BYTES]);

    // Responder, step 2: a hello from 'conn', tried against each of this
    // node's own onions. True: replyOut is to be sent (nB is the caller's
    // fresh nonce). False: silence, whatever the reason (no match, a
    // repeated nonce, the session cap, a reply already pending). A hello on a
    // connection that already holds a session is answered: the other side
    // has lost it.
    bool OnHello(uint64_t conn, const std::vector<std::string>& vOwnOnions, const Hello& hello,
                 const unsigned char nB[32], int64_t nNow, Hello& replyOut);
    // Responder, after step 3: the ack. True opens the session, in place of
    // one the connection held.
    bool OnAck(uint64_t conn, const unsigned char ack[ACK_BYTES], int64_t nNow,
               unsigned char hOut[HANDLE_BYTES]);

    // The session a handle names on a connection, if any.
    bool HasSession(uint64_t conn, const unsigned char h[HANDLE_BYTES]) const;
    bool SessionOf(uint64_t conn, unsigned char hOut[HANDLE_BYTES]) const;
    // The connection closed: its session, pending reply and hello go.
    void Close(uint64_t conn);
    // Forget replies not acked within REPLY_TIMEOUT.
    void Expire(int64_t nNow);

    size_t Count() const { return mapSession.size(); }
    size_t Pending() const { return mapPending.size(); }

private:
    struct Half
    {
        std::string O;
        unsigned char nA[32];
        unsigned char nB[32];
        int64_t nTime;
    };
    struct Handle
    {
        unsigned char h[HANDLE_BYTES];
    };
    unsigned char A[32];
    std::map<uint64_t, Half> mapOut;        // hellos sent, waiting for a reply
    std::map<uint64_t, Half> mapPending;    // replies sent, waiting for an ack
    std::map<uint64_t, Handle> mapSession;
    std::deque<std::vector<unsigned char> > vSeen;  // the last SEEN_NONCES nA

    bool Seen(const unsigned char nA[32]) const;
};

} // namespace poollocal

#endif
