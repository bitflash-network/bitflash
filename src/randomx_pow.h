// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Memory-hard Proof of Work (CPU + RAM) via RandomX -- replaces SHA-256d as
// the PoW algorithm. The block IDENTITY hash stays SHA-256d (GetHash),
// preserving all indexing; what changes is the PROOF-OF-WORK hash
// (GetPoWHash), computed with RandomX.
//
// Modes:
//   - Verification (all nodes): 256 MB cache, "light" VM. Cheap.
//   - Mining (optional, fast): ~2 GB dataset, "full" VMs. Fast.
// GPUs and ASICs are neutralized by RandomX's memory cost/latency.
//
// Two versions of the proof of work exist, selected by the block's nTime:
//
//   v1  RandomX over the 80-byte header as serialized, keyed by the string
//       "Bitflash/RandomX/v1/one-cpu-one-vote". Every block before
//       POW_V2_TIME.
//
//   v2  RandomX over an 83-byte input built from the same header with the
//       nonce moved to bytes 39..42, keyed by SHA-256 of the v1 key string.
//       Every block from POW_V2_TIME on.
//
// v2 exists for one reason: ordinary RandomX miners. XMRig and its relatives
// put their nonce at byte 39 of whatever blob the pool hands them, hash the
// whole blob, and take the RandomX key from a 32-byte "seed_hash" in the job.
// v1 put the nonce at byte 76 and used a 36-byte key, so no such miner could
// produce a share the chain would accept -- the public pool announced in
// September 2026 could not actually be mined by the software it named. The
// v2 input is the header the chain already has, laid out where those miners
// expect it, with a key they can be told.

#ifndef BITFLASH_RANDOMX_POW_H
#define BITFLASH_RANDOMX_POW_H

#include <string>

// uint256 comes from uint256.h, already included by headers.h before this file.

// Activation, by block time (nTime), so the hash function of a header is a
// function of the header alone. Mainnet: 2026-09-21 12:00:00 UTC. Testnet:
// 2026-09-14 21:00:00 UTC.
static const unsigned int POW_V2_TIME_MAINNET = 1789992000;
static const unsigned int POW_V2_TIME_TESTNET = 1789419600;
unsigned int PoWV2Time();

// 1 or 2 for a block carrying this nTime.
int PoWVersionAt(unsigned int nTime);

// The v2 input of an 80-byte header, as serialized (nonce at 76). Returns
// its length, POW_INPUT_V2_SIZE. pOut needs POW_INPUT_MAX bytes.
static const size_t POW_INPUT_V2_SIZE = 83;
static const size_t POW_INPUT_MAX     = 83;
static const size_t POW_V2_NONCE_OFFSET = 39;
size_t PoWInputV2(const unsigned char* pHeader80, unsigned char* pOut);

// The PoW input of a header for whichever version its nTime selects.
size_t PoWInputFromHeader(const unsigned char* pHeader80, unsigned char* pOut, int* pnVersion = NULL);

// The 32-byte v2 key, and its hex -- the seed_hash a RandomX miner is given.
const unsigned char* PoWSeedV2();
std::string PoWSeedV2Hex();

// A hash that could not be computed. Every hash function below returns it
// when RandomX could not be set up on this machine: all ones, above every
// target, so code that only compares a hash with a target treats such work
// as not done. It used to be zero, which is below every target: a node whose
// 256 MB cache could not be allocated took any block's proof of work as met.
// Code that has to tell "not met" from "not known" uses the Checked forms.
#define POW_HASH_UNAVAILABLE (~uint256(0))

// PoW hash of an 80-byte header, version chosen by its nTime, on the shared
// verification VM (thread-safe). This is what consensus checks.
// POW_HASH_UNAVAILABLE when RandomX is not available.
uint256 PoWHashHeader(const unsigned char* pHeader80);

// Same, but false when the hash could not be computed here: the work is
// unknown, which is neither valid nor invalid. A caller must not accept what
// it could not check, and must not blame the sender for this node's failure.
bool PoWHashHeaderChecked(const unsigned char* pHeader80, uint256& hashOut);

// Same, on an owned mining VM created for the header's version.
uint256 PoWHashHeaderWithVM(void* vm, const unsigned char* pHeader80);

// Initialize flags and the v1/v2 cache + verification VM on demand. Call once
// at startup; the caches themselves are allocated the first time each
// version is asked for, so a node that never sees a v1 block after the
// switch never pays for the v1 cache.
bool RandomXInit();

// Allocate and initialize the ~2 GB dataset of one version for fast mining,
// using nThreads to speed it up. Idempotent per version. Returns false on
// failure (the miner then falls back to light mode automatically).
bool RandomXInitDataset(int nVersion, int nThreads);

// Raw hash on the verification VM of one version. Consensus code should use
// PoWHashHeader; this is for tests and for the pool, which builds its own
// inputs.
uint256 RandomXPoWHash(int nVersion, const void* pData, size_t nSize);
bool RandomXPoWHashChecked(int nVersion, const void* pData, size_t nSize, uint256& hashOut);
// Self-test only: hold (or let go of) the first verification VM from the
// calling thread.
void RandomXHoldPrimaryVerifyForTest(int nVersion, bool fHold);

// Set up the cache and verification VM of one version now. False when that
// cannot be done (not enough memory for the 256 MB cache, or the VM could not
// be created). Startup asks for v2 always, and for v1 too while the best
// chain still ends before the switch, and refuses to run without them: a node
// that cannot check proof of work must not follow any chain. Once set up, a
// version's verifier is never released.
bool RandomXVerifierReady(int nVersion);

// True when the last attempt to set up a verifier failed (for the message a
// failed startup gives). An attempt is only made when the retry delay allows
// one, so a call turned away by the delay does not change it.
bool RandomXSetupFailed();

// True when that version's verifier is not set up and its last set-up
// attempt failed. Makes no attempt and takes no lock: for callers that can
// decide without the hash and want to avoid starting a set-up for nothing.
// With RandomX working this is always false.
bool RandomXVerifierKnownUnavailable(int nVersion);

// Self-test only: while set, every verifier behaves as if RandomX could not
// be set up, whatever was set up before, and no new miner VM can be made.
// The per-version form does that for one version only.
void RandomXForceUnavailableForTest(bool fUnavailable);
void RandomXForceVersionUnavailableForTest(int nVersion, bool fUnavailable);

// Create a VM for a mining thread (own VM, not shared) keyed for one version.
// Uses that version's dataset (fast) if ready, otherwise its cache (light).
// Release with RandomXDestroyMinerVM. Returns NULL on failure.
void* RandomXCreateMinerVM(int nVersion);
void  RandomXDestroyMinerVM(void* vm);

// Compute a hash on an owned mining VM (not guarded). POW_HASH_UNAVAILABLE
// for a NULL VM, so a miner without one can never "find" a block.
uint256 RandomXHashWithVM(void* vm, const void* pData, size_t nSize);

// True when the 2 GB dataset of that version is ready (fast mode active).
bool RandomXFastReady(int nVersion);

// Ask for large (2 MB) pages for the cache, dataset and scratchpads. Set false
// by -nolargepages. Must be set before the first RandomXInit().
extern bool fRandomXLargePages;

// Which allocations actually got large pages, for the status display.
const char* RandomXLargePagesStatus();

#endif
