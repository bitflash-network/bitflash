// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Rules v2: the consensus rules Bitcoin adopted after 0.1.0, applied here
// from one moment, by block time -- the same shape as the PoW v2 switch in
// randomx_pow.h, and on mainnet the same moment, so a node updates once.
//
//   - the coinbase scriptSig starts with the block height (BIP34), and a
//     transaction whose txid already exists unspent is refused (BIP30): two
//     coinbases could otherwise be byte-identical, and the second one
//     overwrote the first's index entry
//   - signatures must be strictly DER-encoded with a low S value (BIP66,
//     BIP62): validation no longer depends on how permissive the linked
//     OpenSSL happens to be -- which is what split Bitcoin in 2015 -- and a
//     third party can no longer change a txid by re-encoding a signature
//   - the difficulty retarget measures the time of nInterval intervals, not
//     nInterval-1 (the off-by-one behind the time-warp attack)
//
// Testnet switches first so the rules run on a live chain before mainnet.

#ifndef BITFLASH_CONSENSUS_H
#define BITFLASH_CONSENSUS_H

// Mainnet: 2026-09-21 12:00:00 UTC, with PoW v2. Testnet: 2026-09-16 15:00:00 UTC.
static const unsigned int RULES_V2_TIME_MAINNET = 1789992000;
static const unsigned int RULES_V2_TIME_TESTNET = 1789570800;

// The most a peer can move this node's clock, in either direction. Beyond
// it the offset is dropped rather than applied: a node whose peers disagree
// with its own clock by more than this has a clock problem, not a peer
// problem, and letting peers set the time is how a node is walked off the
// chain (Bitcoin 0.3.x: 70 minutes).
static const int64 MAX_TIME_ADJUSTMENT = 70 * 60;

unsigned int RulesV2Time();
bool RulesV2Active(unsigned int nBlockTime);

// Rules v3 -- pay-to-script-hash (BIP16), OP_CHECKLOCKTIMEVERIFY (BIP65),
// lock-time finality against median-time-past (BIP113), and sigops counted
// inside redeem scripts. No CHECKSEQUENCEVERIFY: a swap needs only an
// absolute lock. A time of 0 would mean "never". The wallet refuses to pay to
// a script hash before the switch, because until the rule is live such an
// output belongs to whoever spends it first.
//
// Mainnet: 2026-11-21 12:00 UTC, a month after testnet. The rules only
// tighten what a block may hold, so a 1.2.28 node keeps following the chain;
// what has to upgrade before the date is the hashrate.
static const unsigned int RULES_V3_TIME_MAINNET = 1795262400;
// Testnet first, as with PoW v2: 2026-10-20 01:00 UTC, so a real swap can be
// made on a real chain before anything is scheduled where coins are worth
// something.
static const unsigned int RULES_V3_TIME_TESTNET = 1792458000;

unsigned int RulesV3Time();
bool RulesV3Active(unsigned int nBlockTime);

// Rules v4 (docs/rules-v4.md): relative lock time (BIP68) and
// OP_CHECKSEQUENCEVERIFY (BIP112), OP_CHECKTEMPLATEVERIFY (BIP119, without
// the scriptSigs field), OP_CHECKSIGFROMSTACK (BIP348). Only after rules v3:
// they need P2SH and median-time-past finality.
//
// Mainnet: 0, never, until the founder fixes the date (planned May 2027).
static const unsigned int RULES_V4_TIME_MAINNET = 0;
// Testnet: 2026-12-25 12:00 UTC at the latest.
static const unsigned int RULES_V4_TIME_TESTNET = 1798200000;

unsigned int RulesV4Time();
bool RulesV4Active(unsigned int nBlockTime);
// -benchrulesv4=TIME: rules v4 from TIME on an isolated testnet bench
// (-isolate), so they can be proven with coins before the real date. Refused
// on mainnet; 0 when not given.
extern unsigned int nBenchRulesV4Time;

// The day atomic swaps open in the wallet and in btfchat on mainnet:
// 2026-12-25 12:00 UTC. Not a consensus rule. Rules v3 still switch on at
// 2026-11-21, as 1.2.29 shipped them; moving that date in a later release
// would leave two rule sets live at once, and a swap funded on 1.2.29 open to
// anyone on the other. Only the launch moves. On testnet swaps open with the
// rules, as they did.
static const unsigned int SWAPS_OPEN_TIME_MAINNET = 1798200000;

unsigned int SwapsOpenTimeFor(bool fTestNetwork);
unsigned int SwapsOpenTime();
bool SwapsOpen(unsigned int nTime);

#endif
