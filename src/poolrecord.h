// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The pool registry record (docs/pool-registry.md, sections 1, 2 and 4).
//
// A pool is created by burning at least 1 BTF into an OP_RETURN that carries
// its rules. The pool's id is the hash of those bytes and the network, so the
// same rules always mean the same pool, one byte more or less is another pool,
// and nobody, its creator included, can change a pool once it exists.
//
// A record is read only if writing back what was read gives the same bytes:
// every pool has exactly one record and every record exactly one pool. Pure:
// no node, no chain, no socket.

#ifndef BITFLASH_POOLRECORD_H
#define BITFLASH_POOLRECORD_H

#include <stdint.h>
#include <string>
#include <vector>

namespace poolreg
{

static const unsigned char RECORD_FORMAT = 1;
static const unsigned char SHARE_RULES_V1 = 1;

static const size_t FIXED_BYTES = 41;     // everything before the name
static const size_t MAX_NAME_LEN = 32;
static const size_t MIN_RECORD_BYTES = FIXED_BYTES + 1;
static const size_t MAX_RECORD_BYTES = FIXED_BYTES + MAX_NAME_LEN;

// What a record must burn to count: 1 BTF.
static const int64_t MIN_BURN = 100000000;

static const unsigned int MIN_SPACING = 10, MAX_SPACING = 120;
static const unsigned int MIN_WINDOW = 360, MAX_WINDOW = 2160;
static const unsigned int MIN_RETARGET = 120, MAX_RETARGET = 720;
static const unsigned int MAX_UNCLE_DEPTH = 3;
static const unsigned int MIN_UNCLE_PCT = 50, MAX_UNCLE_PCT = 100;
static const unsigned int MAX_FEE_BPS = 300;
// The network floor, bnProofOfWorkLimit (~uint256(0) >> 12), in compact form.
// No compact value lies strictly between SetCompact(NETWORK_FLOOR) and
// bnProofOfWorkLimit, so "no easier than this" is the same rule for both.
static const unsigned int NETWORK_FLOOR = 0x1f0fffff;

enum FeeType
{
    FEE_NONE = 0,
    FEE_P2PKH = 1,
    FEE_P2SH = 2,
};

struct PoolRecord
{
    unsigned char nFormat;        // RECORD_FORMAT
    unsigned char nRules;         // SHARE_RULES_V1
    unsigned int nSpacing;        // seconds per share
    unsigned int nWindow;         // PPLNS window, shares
    unsigned int nRetarget;       // retarget window, shares
    unsigned int nFloor;          // compact share floor
    unsigned int nUncleDepth;     // 0 turns uncles off
    unsigned int nUnclePct;       // what an uncle is paid of its work, percent
    unsigned int nFeeBps;         // creator fee, basis points
    unsigned char nFeeType;       // FeeType
    unsigned char feeHash[20];    // HASH160 of the fee address; zero for FEE_NONE
    std::string name;

    PoolRecord();

    // The record's bytes. Encode does not check; Check says whether the
    // fields form a record that Parse would read back.
    std::vector<unsigned char> Encode() const;
    bool Check(std::string& errOut) const;

    // The fee destination as a scriptPubKey (P2PKH or P2SH); empty for none.
    std::vector<unsigned char> FeeScript() const;
};

// Read a record from its bytes (the OP_RETURN's data). False, with a reason,
// unless the bytes are a record in exactly its canonical form.
bool Parse(const std::vector<unsigned char>& data, PoolRecord& out, std::string& errOut);

// Read a record from an output's script: OP_RETURN and one direct push of the
// record (opcode equal to its length), nothing after it. The burn is the
// caller's to check (MIN_BURN).
bool ParseScript(const std::vector<unsigned char>& scriptPubKey, PoolRecord& out, std::string& errOut);

// SHA256d("Bitflash/pool/1" || network magic || record), the 32 bytes in
// internal order (as they go into the coinbase anchor).
void PoolId(const std::vector<unsigned char>& record, const unsigned char magic[4], unsigned char idOut[32]);
// Shown like a block hash: the bytes reversed, in hex.
std::string IdHex(const unsigned char id[32]);

// Pool zero: today's share chain written as a record (section 4).
PoolRecord PoolZero();

// The pool name rule: 1 to 32 of A-Z, a-z, 0-9, '-' and '_', tested as byte
// ranges (isalnum depends on the C locale).
bool NameOk(const std::string& name);

// Whether a compact target is in the one form GetCompact(SetCompact(c))
// gives back, and positive.
bool CompactCanonical(unsigned int nCompact);

} // namespace poolreg

#endif
