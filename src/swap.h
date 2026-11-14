// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Atomic swaps: trade BTF for BTC (or LTC, or any coin with the same script)
// with nobody in the middle. Needs rules v3 (P2SH and OP_CHECKLOCKTIMEVERIFY).
//
// THE CONTRACT is the one Decred's atomicswap tools use on every chain they
// support, byte for byte:
//
//   OP_IF
//       OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <secret hash> OP_EQUALVERIFY
//       OP_DUP OP_HASH160 <recipient pubkey hash>
//   OP_ELSE
//       <lock time> OP_CHECKLOCKTIMEVERIFY OP_DROP
//       OP_DUP OP_HASH160 <refund pubkey hash>
//   OP_ENDIF
//   OP_EQUALVERIFY OP_CHECKSIG
//
// The recipient takes the coins by showing a 32-byte secret whose SHA-256 is in
// the script; the other side takes them back after the lock if that never
// happens. Using the same script on both chains is what lets the Bitcoin half
// be done with btcatomicswap, which already exists and has been used for years,
// instead of with anything of ours.
//
// HOW A SWAP GOES (A has BTF, B has BTC):
//   1. A: swapinitiate -- makes the secret, locks BTF for B for 48 hours.
//   2. B: audits A's contract, locks BTC for A for 24 hours under the same
//      secret hash (btcatomicswap participate). A participant who gives BTF
//      locks it for 18 hours (see the timing below).
//   3. A: redeems the BTC, which shows the secret on the Bitcoin chain.
//   4. B: reads the secret from that transaction (swapextractsecret) and
//      redeems the BTF.
// Whoever stops answering, the other gets their coins back after their lock.
// The initiator's lock is the longer one so that B always has time to redeem
// after A has revealed the secret.

#ifndef BITFLASH_SWAP_H
#define BITFLASH_SWAP_H

#include <string>
#include <vector>
#include <stdint.h>
// util.h redefines snprintf as a macro, which breaks nlohmann/json (as in
// rpcclient.h): undone around it, put back for whoever includes this after.
#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")

// Boost before 1.84 calls an unqualified swap() in a template that is only
// valid while no namespace named swap exists. Parse it first: the Bitcoin
// light client's big integers pull it in, and Debian 13 ships Boost 1.83.
#include <boost/version.hpp>
#if BOOST_VERSION < 108400
#include <boost/core/swap.hpp>
#endif

namespace swap
{

static const unsigned int SECRET_BYTES = 32;

// THE TIMING. A Bitflash contract is locked by time, like the contract on the
// other chain: its lock is a unix time, and OP_CHECKLOCKTIMEVERIFY with rules
// v3 lets the refund into a block only once the median time of the eleven
// blocks before it has passed that time (BIP113, CTransaction::IsFinalAt).
//
// It used to be locked by height, 48 * 30 or 24 * 30 blocks of two minutes.
// A height lock is a promise about how fast the chain will be, and Bitflash
// retargets every 30 blocks by at most four times: difficulty pushed up for a
// few windows and then left to the honest miners makes the next blocks come
// hours apart. A taker who gave BTF against a coin locked by time could then
// still be waiting for its 720th block when the maker's lock had run out; the
// maker took its own coins back and the taker's too. By time, a slowed chain
// no longer stretches the lock itself, only the last few blocks around it.
//
// The ordering the swap needs, with both locks in time:
//   (1) the side that shows the secret (the maker, redeeming the taker's
//       contract) gets its redeem in before the taker's refund opens;
//   (2) the taker, who reads the secret off the chain, gets its redeem in
//       before the maker's refund opens;
//   (3) the taker's refund is in a block before the maker's refund opens, or
//       the maker could take its own coins back and then the taker's.
// (1) and (2): a redeem is valid at once and sent hours before the lock,
// while a refund needs the median time to pass the lock, i.e. six blocks
// stamped after it plus one to carry it. Slowing the chain delays the refund
// at least as much as the redeem; speeding it is bounded by the two hours a
// block's time may run ahead and by the retarget, far inside the margins
// (the maker redeems only with 6 hours left, the taker has at least 12).
// (3) is the one a slowed Bitflash chain can attack, and only when the taker
// gives BTF: its refund then needs those seven Bitflash blocks between its
// own lock and the maker's. The taker locks only while the maker's contract
// has at least 36 hours left, so with an 18 hour lock there are at least 18
// hours for seven blocks: on average about 150 minutes a block, more than 64
// times the two-minute target, three of the largest retarget steps in a row.
// That is a mean; block times vary, so the slowdown the margin covers with
// high probability is somewhat smaller. Driving the difficulty that high
// takes far more work than reversing the 30 Bitflash confirmations both
// sides already wait for before acting, so this margin is not the weakest
// point of the swap. Before locking, a taker who gives BTF also refuses
// while the chain is already slow (the tip's median time more than an hour
// behind the clock, SwapConfig::nBtfMaxMedianLag). That only sees a slowdown
// under way: difficulty can be pushed up while blocks still come on time,
// and the slow part starts when that hash rate leaves. Dogecoin judges a
// lock by the next block's own time, not the median (BIP113 never activated
// there), which costs up to about two of those 18 hours; the margin covers
// it.
static const int64_t BTF_INITIATOR_LOCK_SECS   = 48 * 3600;
static const int64_t BTF_PARTICIPANT_LOCK_SECS = 18 * 3600;

// Seconds until a refund of a contract time-locked at nLockTime can be in the
// next block, given the tip's median time past (0: it can now). The next
// block takes it once nLockTime < that median (IsFinalAt).
int64_t SecondsUntilRefund(int64_t nLockTime, int64_t nMedianTimePast);

// The lock time of a new Bitflash contract (swapinitiate, swapparticipate):
// nLockSecs on from the tip's median time plus its usual lag, never later
// than the clock. The lock is judged by the median time, so it is counted
// from it; but a node still catching up has a median days behind the clock,
// and a lock counted from there is already open when it is paid: the other
// side could refund at once (found on the public eCash testnet swap,
// 2026-11-14). False, with the reason in err, when the median time is more
// than BTF_LOCK_MAX_MEDIAN_LAG behind the clock -- the same hour a chat taker
// giving BTF waits on (SwapConfig::nBtfMaxMedianLag).
static const int64_t BTF_LOCK_MAX_MEDIAN_LAG = 3600;
bool BtfLockTime(int64_t nNow, int64_t nMedianTimePast, int64_t nLockSecs, int64_t& nLockTimeOut, std::string& err);

// The secret of a new swap and its hash. False, and nothing usable in either,
// when the system's random generator fails: an all-zero secret is one
// anybody could guess, and its hash is public in the contract.
bool NewSecret(std::vector<unsigned char>& secretOut, std::vector<unsigned char>& hashOut);

// ---- the journal ------------------------------------------------------------
//
// swaps.log in the data directory: one JSON object per line, for whoever has
// to recover a swap by hand, and the record that lets a lock never be made
// twice. A lock's secret, contract and lock time are written as a line with
// "state":"intent" BEFORE anything is sent, then "funded" (or "made", for a
// contract an outside wallet pays, or "failed" when nothing was sent) under
// the same "tag". The file is rewritten whole beside itself, flushed and
// renamed into place (WriteFileAtomicPrivate): a line is on the disk before
// the send that depends on it, and only this user can read it.
std::string JournalPath();
void JournalSetPathForTest(const std::string& path);   // "" for the default
bool JournalAppend(const nlohmann::json& line, std::string& errOut);
bool JournalRead(std::vector<nlohmann::json>& out, std::string& errOut);
// The lines of one tag merged in order (later fields win), or null when the
// journal has none. "state" is then the latest line's.
bool JournalLookup(const std::string& tag, nlohmann::json& mergedOut, std::string& errOut);
// 1 to 64 of [0-9A-Za-z_:-]: what a caller may name a lock with.
bool JournalTagOk(const std::string& tag);

struct Contract
{
    std::vector<unsigned char> recipientPkh;   // 20 bytes
    std::vector<unsigned char> refundPkh;      // 20 bytes
    std::vector<unsigned char> secretHash;     // 32 bytes
    int64_t nLockTime;
};

CScript BuildContract(const Contract& c);

// True only for a script of exactly the shape above.
bool ParseContract(const CScript& script, Contract& out);

// The scriptSigs that spend it, through P2SH: the contract is the last push.
CScript RedeemScriptSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey,
                        const std::vector<unsigned char>& secret, const CScript& contract);
CScript RefundScriptSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey,
                        const CScript& contract);

// The secret, from a redeem transaction's scriptSig on either chain: the
// 32-byte push whose SHA-256 is secretHash.
bool ExtractSecret(const CScript& scriptSig, const std::vector<unsigned char>& secretHash,
                   std::vector<unsigned char>& secretOut);

} // namespace swap

#endif
