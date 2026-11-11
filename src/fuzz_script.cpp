// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// libFuzzer harness for the script engine, under every rule set a block or the
// memory pool evaluates with: rules v2 (strict DER, low S), v3 (P2SH, CLTV,
// OP_VER* invalid) and v4 (CSV, CTV, CSFS), all eight combinations, through
// EvalScript, VerifyScriptP2SH and VerifySignature -- and with rules v5 (the
// OP_CHECKMULTISIG key cap) on top of all three -- the call ConnectInputs
// makes for the block, the miner and the pool alike -- and with the pool's
// relay policy (SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4) on the v4 sets.
//
// Every input is used twice.
//
// 1. Raw: bytes 1.. are one script, byte 0 its hash type, as this harness
//    always did (the existing corpus keeps its meaning): the parser, the
//    standard-form extractors, the sigop count, and EvalScript under each
//    rule set against a one-input transaction.
//
// 2. Structured, so that CLTV, CSV and CTV see a transaction worth checking
//    and signatures can be valid:
//      byte  0     (shared with the raw part)
//      byte  1     control: bit 0 the scriptPubKey is P2SH of the script;
//                  bit 1 the script is pushed last in the scriptSig (its
//                  redeem script); bit 4 the spent output is the funding
//                  transaction's second
//      4 bytes     nVersion, then 4 bytes nLockTime (little-endian)
//      1 byte      inputs (1 + b % 3) and which one is checked ((b >> 2) % n)
//      4 bytes     nSequence, per input
//      1 byte      outputs (b % 4); per output 2 bytes value (x 0.0001) and
//                  1 byte picking the script (empty, OP_TRUE, P2PKH of a fixed
//                  key, P2SH)
//      2 bytes     length of the scriptSig part; then the scriptSig part; the
//                  rest is the script (the scriptPubKey, or the redeem script)
//    In either part, a 2-byte push 0xFB <arg> is a placeholder for what no
//    fuzzer could type: kind = arg >> 4, key k = arg & 3, variant v =
//    (arg >> 2) & 3.
//      0 ECDSA signature by k, hash type {ALL, NONE, SINGLE, ALL|ANYONECANPAY}[v]
//      1 k's compressed key   2 k's uncompressed key   3 Hash160 of 1
//      4 k's x-only key       5 BIP340 signature by k over message v
//      6 message v            7 the CTV hash of the transaction, this input
//      8 this input's nSequence as a script number   9 nLockTime likewise
//      10 ECDSA signature by k with high S           11 signature over another hash
//      12 the CTV hash for another input
//    Signatures are made last, over the script as it ends up, so they verify.
//
// Invariants, each an abort when broken:
//  - rules v5 only take away, and only from OP_CHECKMULTISIG; the relay policy
//    only takes away, and only from the v4 opcodes.
//  - rules v4 only adds: a spend that passes with v4 off passes with v4 on,
//    leaving the same stack; with no v4 opcode in it the answer is the same.
//  - with no CLTV or OP_VER* the v3 switch does not change EvalScript, and
//    without P2SH it does not change VerifySignature either.
//  - with no signature opcode the strict-signature switch changes nothing.
//  - VerifySignature is VerifyScriptP2SH for a P2SH output under v3, and the
//    push-only check plus EvalScript otherwise.
//  - the signature checks a spend starts are at most what the block and the
//    pool charge for it: the scriptSig's and scriptPubKey's sigop counts plus
//    the redeem script's under v3, the output's CSFS at the spend under rules
//    v5 when it was made before v4. Before v5 this holds when the relay
//    policy on OP_CHECKMULTISIG key counts (MultisigKeyCountsAreLiteral)
//    holds; under v5, whose key cap closes the gap in consensus, always.
//    Rules v5 also act in this count and in IsFinalAt, checked off and on.
//  - CLTV and the block's finality rule agree: a lock CLTV accepts keeps the
//    transaction out of every block before it (IsFinalAt, v5 off and on), and
//    under v5 a block past nLockTime takes it.
//  - the counts with v4 differ from those without by the OP_CHECKSIGFROMSTACKs;
//    a transaction's count is the sum of its scripts', with no wrap.
//  - the CTV hash commits to version, lock time, the input count, every
//    sequence, every output and the input index, and to nothing else (not
//    scriptSigs, not prevouts); its per-run cache gives the hash a fresh
//    computation gives.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes structured seeds (P2PKH, P2PK,
// multisig bare and P2SH, CLTV, CSV, CTV, CSFS, the vault and inheritance
// scripts, a computed multisig key count) into <dir> and exits.

#include "headers_core.h"
#include "sigcheck.h"

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

static void FuzzScriptInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzScriptInit
#include "fuzz_datadir.h"
#include "fuzz_script_util.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

typedef vector<unsigned char> valtype;

// Index bits: 1 strict signatures (v2), 2 rules v3, 4 rules v4, 8 rules v5,
// 16 the memory pool's relay policy (SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4,
// what ConnectInputs passes when neither a block nor the miner asks). Rules v5
// never hold without v2, v3 and v4, and the policy only matters with v4, so
// the sets evaluated are 0-7, 15 (every rule), 23 (v2-v4 and the policy, the
// pool today) and 31 (every rule and the policy).
static const int kFlagSets = 32;
static const int kAllRules = 15;
static const int kPolicy = 16;
static bool FStrict(int f) { return (f & 1) != 0; }
static bool FV3(int f) { return (f & 2) != 0; }
static bool FV4(int f) { return (f & 4) != 0; }
static bool FV5(int f) { return (f & 8) != 0; }
static unsigned int FPolicyFlags(int f) { return (f & kPolicy) ? SCRIPT_POLICY_DISCOURAGE_UPGRADABLE_V4 : 0; }
static bool FValid(int f) { return f < 8 || f == kAllRules || f == (7 | kPolicy) || f == (kAllRules | kPolicy); }
static const opcodetype kMultisigOps[] = { OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY };

static const unsigned char PLACEHOLDER = 0xFB;

// BITFLASH_FUZZ_SCRIPT_NO_POLICY=1 holds every spend to the sigop bound, as if
// the relay policy on multisig key counts did not exist: how the gap it
// closes was shown (a computed key count above 20 aborts within minutes).
static bool fNoPolicy = false;
// BITFLASH_FUZZ_SCRIPT_DEBUG=1: print each spend and what every rule set made
// of it, for triage when replaying one input.
static bool fScriptDebug = false;
static bool Literal(bool f) { return fNoPolicy || f; }

// The opcodes of a script, up to where it stops parsing.
static set<opcodetype> OpsOf(const CScript& s)
{
    set<opcodetype> ops;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    valtype vch;
    while (pc < s.end() && s.GetOp(pc, op, vch))
        ops.insert(op);
    return ops;
}

static bool AnyOf(const set<opcodetype>& ops, const opcodetype* list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (ops.count(list[i]))
            return true;
    return false;
}

static const opcodetype kV4Ops[] = { OP_CHECKSEQUENCEVERIFY, OP_CHECKTEMPLATEVERIFY, OP_CHECKSIGFROMSTACK };
static const opcodetype kV3Ops[] = { OP_CHECKLOCKTIMEVERIFY, OP_VER, OP_VERIF, OP_VERNOTIF };
static const opcodetype kSigOps[] = { OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY };

static bool fV4OpsAny(const set<opcodetype>& ops) { return AnyOf(ops, kV4Ops, 3); }

static unsigned int CountOp(const CScript& s, opcodetype target)
{
    unsigned int n = 0;
    CScript::const_iterator pc = s.begin();
    opcodetype op;
    valtype vch;
    while (pc < s.end() && s.GetOp(pc, op, vch))
        if (op == target)
            n++;
    return n;
}

static void CheckSigOpCounts(const CScript& s)
{
    unsigned int n0 = s.GetSigOpCount(false), n1 = s.GetSigOpCount(true);
    unsigned int nCsfs = CountOp(s, OP_CHECKSIGFROMSTACK);
    FUZZ_CHECK(n1 >= n0 && n1 - n0 == nCsfs, "sigops without v4 %u, with %u, CSFS %u", n0, n1, nCsfs);
    // Twenty per byte at most: far from wrapping for any script that fits a block.
    FUZZ_CHECK((uint64)n1 <= 20 * (uint64)s.size(), "sigops %u for %u bytes", n1, (unsigned)s.size());
}

static valtype Message(int v)
{
    switch (v & 3)
    {
    case 0: return valtype();
    case 1: { const char* p = "bitflash"; return valtype(p, p + 8); }
    case 2: return valtype(32, 0);
    default: return valtype(80, 0xA5);
    }
}

static const int kHashTypes[4] = { SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY };

// Replace the placeholders in raw script bytes. pScriptCode: what signatures
// commit to; NULL leaves signature placeholders as they are.
static CScript Substitute(const valtype& raw, const CTransaction& tx, unsigned int nIn, const CScript* pScriptCode)
{
    CScript in(raw.begin(), raw.end()), out;
    const vector<FuzzKey>& keys = FuzzKeys();
    CScript::const_iterator pc = in.begin();
    while (pc < in.end())
    {
        CScript::const_iterator pcStart = pc;
        opcodetype op;
        valtype vch;
        if (!in.GetOp(pc, op, vch))
        {
            CScript::const_iterator pcEnd = in.end();
            out.insert(out.end(), pcStart, pcEnd);
            break;
        }
        if (op == 2 && vch.size() == 2 && vch[0] == PLACEHOLDER)
        {
            int arg = vch[1], kind = arg >> 4, v = (arg >> 2) & 3;
            const FuzzKey& k = keys[arg & 3];
            bool fDone = true;
            switch (kind)
            {
            case 0: case 10: case 11:
                if (!pScriptCode) { fDone = false; break; }
                {
                    int nHashType = kind == 0 ? kHashTypes[v] : SIGHASH_ALL;
                    valtype sig;
                    if (kind == 11)
                    {
                        sig = FuzzSignEcdsa(k, uint256(arg + 1));
                        sig.push_back((unsigned char)nHashType);
                    }
                    else
                        sig = FuzzSigFor(k, *pScriptCode, tx, nIn, nHashType, kind == 10);
                    out << sig;
                }
                break;
            case 1: out << k.pubC; break;
            case 2: out << k.pubU; break;
            case 3: out << k.hashC; break;
            case 4: out << k.xonly; break;
            case 5: out << FuzzSignSchnorr(k, Message(v)); break;
            case 6: out << Message(v); break;
            case 7: case 12:
                {
                    uint256 h = CheckTemplateHash(tx, kind == 7 ? nIn : nIn + 1);
                    out << valtype(h.begin(), h.end());
                }
                break;
            case 8: out << (int64)tx.vin[nIn].nSequence; break;
            case 9: out << (int64)tx.nLockTime; break;
            default: fDone = false; break;
            }
            if (fDone)
                continue;
        }
        out.insert(out.end(), pcStart, pc);
    }
    return out;
}

// ---- part 1: one raw script

static void RawScript(int nHashType, const CScript& script)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype vchPush;
    while (pc < script.end())
        if (!script.GetOp(pc, opcode, vchPush))
            break;
    script.ToString();
    vector<unsigned char> vchPubKey;
    ExtractPubKey(script, false, vchPubKey);
    uint160 hash160;
    ExtractHash160(script, hash160);
    txnouttype type;
    vector<valtype> vSolutions;
    SolverTyped(script, type, vSolutions);
    MultisigKeyCountsAreLiteral(script);
    CheckSigOpCounts(script);

    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(), CScript()));
    tx.vout.push_back(CTxOut(0, CScript()));

    // As this harness always ran it: every rule set off.
    vector<valtype> stack;
    EvalScript(script, tx, 0, nHashType, &stack);

    bool r[kFlagSets];
    unsigned int nChecks[kFlagSets];
    vector<valtype> st[kFlagSets];
    for (int f = 0; f < kFlagSets; f++)
    {
        if (!FValid(f))
            continue;
        nFuzzSigChecks = 0;
        r[f] = EvalScript(script, tx, 0, nHashType, &st[f], FStrict(f), FV3(f), FV4(f), FPolicyFlags(f), FV5(f));
        nChecks[f] = nFuzzSigChecks;
    }

    set<opcodetype> ops = OpsOf(script);
    bool fV4Ops = AnyOf(ops, kV4Ops, 3), fV3Ops = AnyOf(ops, kV3Ops, 4), fSigOps = AnyOf(ops, kSigOps, 4);
    bool fLiteral = Literal(MultisigKeyCountsAreLiteral(script));
    bool fMultisigOps = AnyOf(ops, kMultisigOps, 2);
    // Rules v5 only take away, and only from OP_CHECKMULTISIG; under them the
    // checks are bounded by the count whatever the relay policy says.
    FUZZ_CHECK(!r[kAllRules] || (r[7] && st[kAllRules] == st[7]), "raw: passes with v5, not without");
    FUZZ_CHECK(fMultisigOps || r[kAllRules] == r[7], "raw: no multisig, yet v5 changes the answer");
    FUZZ_CHECK(nChecks[kAllRules] <= script.GetSigOpCount(true), "raw: under v5, %u signature checks, %u counted",
               nChecks[kAllRules], script.GetSigOpCount(true));
    // The relay policy only takes away, and only from the v4 opcodes.
    for (int f = 7; f <= kAllRules; f += 8)
    {
        FUZZ_CHECK(!r[f | kPolicy] || (r[f] && st[f | kPolicy] == st[f]), "raw: passes with the policy, not without (flags %d)", f);
        FUZZ_CHECK(fV4OpsAny(ops) || r[f | kPolicy] == r[f], "raw: no v4 opcode, yet the policy changes the answer (flags %d)", f);
    }
    for (int f = 0; f < 8; f++)
    {
        if (!FV4(f))
        {
            FUZZ_CHECK(!r[f] || (r[f | 4] && st[f] == st[f | 4]), "raw: passes with v4 off, not with v4 on (flags %d)", f);
            FUZZ_CHECK(fV4Ops || r[f] == r[f | 4], "raw: no v4 opcode, yet v4 changes the answer (flags %d)", f);
        }
        if (!FV3(f))
            FUZZ_CHECK(fV3Ops || r[f] == r[f | 2], "raw: no CLTV or OP_VER*, yet v3 changes the answer (flags %d)", f);
        if (!FStrict(f))
            FUZZ_CHECK(fSigOps || r[f] == r[f | 1], "raw: no signature opcode, yet strict signatures change the answer (flags %d)", f);
        if (fLiteral)
            FUZZ_CHECK(nChecks[f] <= script.GetSigOpCount(FV4(f)), "raw: %u signature checks, %u counted (flags %d)",
                       nChecks[f], script.GetSigOpCount(FV4(f)), f);
    }
}

// ---- part 2: a spend

static void CheckTemplateCommitments(const CTransaction& tx, unsigned int nIn)
{
    CtvHashCache cache;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        FUZZ_CHECK(CheckTemplateHash(tx, i, &cache) == CheckTemplateHash(tx, i), "CTV cache gives another hash for input %u", i);

    uint256 h = CheckTemplateHash(tx, nIn);
    CTransaction t;
    t = tx; t.vin[nIn].scriptSig << OP_0;
    FUZZ_CHECK(CheckTemplateHash(t, nIn) == h, "CTV hash covers the scriptSig");
    t = tx; t.vin[nIn].prevout.n ^= 1; t.vin[nIn].prevout.hash = uint256(7);
    FUZZ_CHECK(CheckTemplateHash(t, nIn) == h, "CTV hash covers the prevout");
    t = tx; t.nVersion ^= 1;
    FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the version");
    t = tx; t.nLockTime ^= 1;
    FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the lock time");
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        t = tx; t.vin[i].nSequence ^= 1;
        FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the sequence of input %u", i);
        if (i != nIn)
            FUZZ_CHECK(CheckTemplateHash(tx, i) != h, "CTV hash misses the input index (%u and %u)", i, nIn);
    }
    t = tx; t.vin.push_back(CTxIn());
    FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the input count");
    t = tx; t.vout.push_back(CTxOut());
    FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the output count");
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        t = tx; t.vout[i].nValue ^= 1;
        FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the value of output %u", i);
        t = tx; t.vout[i].scriptPubKey << OP_0;
        FUZZ_CHECK(CheckTemplateHash(t, nIn) != h, "CTV hash misses the script of output %u", i);
    }
}

// OP_CHECKLOCKTIMEVERIFY checks nLockTime; the block rule IsFinalAt keeps
// the transaction out until the lock has passed. Both halves must agree: if
// CLTV <lock> passes, no block where the lock has not passed may take the
// transaction, under rules v5 (nLockTime read unsigned) or before them; and
// under v5 a block past nLockTime does take it.
// A script number of at most five bytes (little-endian, sign in the top bit).
static int64 ScriptNum5(const valtype& vch)
{
    if (vch.empty())
        return 0;
    int64 n = 0;
    for (size_t i = 0; i < vch.size(); i++)
        n |= (int64)vch[i] << (8 * i);
    if (vch.back() & 0x80)
        return -(int64)(n & ~((int64)0x80 << (8 * (vch.size() - 1))));
    return n;
}

static void CheckLockTimeHalves(const CTransaction& tx, unsigned int nIn, int64 nLock)
{
    CScript s;
    s << nLock << OP_CHECKLOCKTIMEVERIFY;
    if (!EvalScript(s, tx, nIn, 0, NULL, true, true, true))
        return;
    FUZZ_CHECK(nLock >= 0 && nLock <= (int64)(unsigned int)tx.nLockTime && !tx.vin[nIn].IsFinal(),
               "CLTV %lld passed for nLockTime %u", (long long)nLock, (unsigned int)tx.nLockTime);
    bool fTime = nLock >= (int64)LOCKTIME_THRESHOLD;
    int nHeight = fTime ? INT_MAX : (int)nLock;
    int64 nTime = fTime ? nLock : (int64)0x7fffffffffffLL;
    for (int v5 = 0; v5 < 2; v5++)
        FUZZ_CHECK(!tx.IsFinalAt(nHeight, nTime, v5), "CLTV %lld passed, and IsFinalAt (v5 %d) takes the "
                   "transaction at height %d, time %lld, before the lock", (long long)nLock, v5, nHeight, (long long)nTime);
    unsigned int nTx = (unsigned int)tx.nLockTime;
    if (nTx < LOCKTIME_THRESHOLD)
        FUZZ_CHECK(tx.IsFinalAt((int)nTx + 1, 0, true), "rules v5: not final the block after its lock height %u", nTx);
    else
        FUZZ_CHECK(tx.IsFinalAt(0, (int64)nTx + 1, true), "rules v5: not final after its lock time %u", nTx);
}

static void Spend(int nHashTypeUnused, FuzzReader& r)
{
    (void)nHashTypeUnused;
    const vector<FuzzKey>& keys = FuzzKeys();
    uint8_t ctl = r.U8();
    CTransaction tx;
    tx.nVersion = (int)r.U32();
    tx.nLockTime = r.U32();
    uint8_t b = r.U8();
    unsigned int nIns = 1 + b % 3, nIn = (b >> 2) % nIns;
    tx.vin.resize(nIns);
    for (unsigned int i = 0; i < nIns; i++)
    {
        tx.vin[i].prevout = COutPoint(uint256(100 + i), i);
        tx.vin[i].nSequence = r.U32();
    }
    unsigned int nOuts = r.U8() % 4;
    for (unsigned int i = 0; i < nOuts; i++)
    {
        int64 nValue = (int64)r.U16() * (CENT / 100);
        uint8_t sel = r.U8();
        CScript s;
        switch (sel & 3)
        {
        case 0: break;
        case 1: s << OP_TRUE; break;
        case 2: s << OP_DUP << OP_HASH160 << keys[(sel >> 2) & 3].hashC << OP_EQUALVERIFY << OP_CHECKSIG; break;
        default: s.SetPayToScriptHash(CScript() << (int64)(sel >> 2)); break;
        }
        tx.vout.push_back(CTxOut(nValue, s));
    }
    uint16_t nSigLen = r.U16();
    valtype vSig = r.Bytes(nSigLen);
    valtype vScript = r.Rest();

    // The script first: signatures commit to it.
    CScript script = Substitute(vScript, tx, nIn, NULL);
    CScript scriptPubKey;
    if (ctl & 1)
        scriptPubKey.SetPayToScriptHash(script);
    else
        scriptPubKey = script;

    CTransaction txFrom;
    txFrom.vin.push_back(CTxIn(COutPoint(uint256(1), 0), CScript()));
    unsigned int nOut = (ctl & 0x10) ? 1 : 0;
    if (nOut)
        txFrom.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    txFrom.vout.push_back(CTxOut(COIN, scriptPubKey));
    tx.vin[nIn].prevout = COutPoint(txFrom.GetHash(), nOut);

    // What a signature in the scriptSig commits to: the redeem script for a
    // P2SH spend, the scriptPubKey otherwise -- from its last code separator.
    CScript scriptCode = script;
    {
        CScript::const_iterator pc = script.begin(), pcCode = script.begin();
        opcodetype op;
        valtype vch;
        while (pc < script.end() && script.GetOp(pc, op, vch))
            if (op == OP_CODESEPARATOR)
                pcCode = pc;
        scriptCode = CScript(pcCode, script.end());
    }
    CScript scriptSig = Substitute(vSig, tx, nIn, &scriptCode);
    if (ctl & 2)
        scriptSig << valtype(script.begin(), script.end());
    tx.vin[nIn].scriptSig = scriptSig;

    CheckSigOpCounts(scriptSig);
    CheckSigOpCounts(scriptPubKey);
    CheckSigOpCounts(script);
    for (int v4 = 0; v4 < 2; v4++)
    {
        uint64 nSum = 0;
        foreach(const CTxIn& txin, tx.vin)
            nSum += txin.scriptSig.GetSigOpCount(v4);
        foreach(const CTxOut& txout, tx.vout)
            nSum += txout.scriptPubKey.GetSigOpCount(v4);
        FUZZ_CHECK(nSum == tx.GetSigOpCount(v4), "transaction sigops %u, its scripts %llu", tx.GetSigOpCount(v4),
                   (unsigned long long)nSum);
    }
    CheckTemplateCommitments(tx, nIn);
    {
        // The locks CLTV could see: nLockTime and the one before it, and the
        // small pushes of the script.
        vector<int64> vLocks;
        vLocks.push_back((int64)(unsigned int)tx.nLockTime);
        vLocks.push_back((int64)(unsigned int)tx.nLockTime - 1);
        CScript::const_iterator pc = script.begin();
        opcodetype op;
        valtype vch;
        while (pc < script.end() && script.GetOp(pc, op, vch) && vLocks.size() < 10)
            if (op <= OP_PUSHDATA4 && vch.size() <= 5)
                vLocks.push_back(ScriptNum5(vch));
        foreach(int64 nLock, vLocks)
            CheckLockTimeHalves(tx, nIn, nLock);
    }

    bool fPushOnly = scriptSig.IsPushOnly();
    bool fP2SH = scriptPubKey.IsPayToScriptHash();
    CScript whole = scriptSig + CScript(OP_CODESEPARATOR) + scriptPubKey;
    set<opcodetype> ops = OpsOf(whole);
    if (fP2SH)
    {
        // The redeem script as VerifyScriptP2SH and GetP2SHSigOpCount find it.
        CScript::const_iterator pc = scriptSig.begin();
        opcodetype op;
        valtype vch, last;
        while (pc < scriptSig.end() && scriptSig.GetOp(pc, op, vch))
            last = vch;
        set<opcodetype> inner = OpsOf(CScript(last.begin(), last.end()));
        ops.insert(inner.begin(), inner.end());
    }
    bool fV4Ops = AnyOf(ops, kV4Ops, 3), fV3Ops = AnyOf(ops, kV3Ops, 4), fSigOps = AnyOf(ops, kSigOps, 4);

    bool rEval[kFlagSets], rVer[kFlagSets], rP2SH[kFlagSets];
    unsigned int cEval[kFlagSets], cVer[kFlagSets];
    vector<valtype> st[kFlagSets];
    for (int f = 0; f < kFlagSets; f++)
    {
        if (!FValid(f))
            continue;
        nFuzzSigChecks = 0;
        rEval[f] = EvalScript(whole, tx, nIn, 0, &st[f], FStrict(f), FV3(f), FV4(f), FPolicyFlags(f), FV5(f));
        cEval[f] = nFuzzSigChecks;
        nFuzzSigChecks = 0;
        rVer[f] = VerifySignature(txFrom, tx, nIn, 0, FStrict(f), FV3(f), FV4(f), FPolicyFlags(f), FV5(f));
        cVer[f] = nFuzzSigChecks;
        rP2SH[f] = VerifyScriptP2SH(scriptSig, scriptPubKey, tx, nIn, FStrict(f), FV3(f), FV4(f), FPolicyFlags(f), FV5(f));
    }

    bool fLiteralWhole = Literal(MultisigKeyCountsAreLiteral(whole));
    if (fScriptDebug)
    {
        fprintf(stderr, "spend: version %d locktime %u, input %u of %u, sequence %08x, %u outputs\n",
                tx.nVersion, (unsigned int)tx.nLockTime, nIn, (unsigned)tx.vin.size(), tx.vin[nIn].nSequence,
                (unsigned)tx.vout.size());
        fprintf(stderr, "  scriptSig    %s\n  scriptPubKey %s\n  script       %s\n", scriptSig.ToString().c_str(),
                scriptPubKey.ToString().c_str(), script.ToString().c_str());
        for (int f = 0; f < kFlagSets; f++)
            if (FValid(f))
                fprintf(stderr, "  flags %d: EvalScript %d (%u checks), VerifySignature %d (%u checks), VerifyScriptP2SH %d\n",
                        f, rEval[f], cEval[f], rVer[f], cVer[f], rP2SH[f]);
    }
    bool fMultisigOps = AnyOf(ops, kMultisigOps, 2);
    FUZZ_CHECK(!rEval[kAllRules] || (rEval[7] && st[kAllRules] == st[7]), "EvalScript passes with v5, not without");
    FUZZ_CHECK(!rVer[kAllRules] || rVer[7], "VerifySignature passes with v5, not without");
    FUZZ_CHECK(fMultisigOps || (rEval[kAllRules] == rEval[7] && rVer[kAllRules] == rVer[7]),
               "no multisig, yet v5 changes the answer");
    for (int f = 7; f <= kAllRules; f += 8)
    {
        FUZZ_CHECK(!rEval[f | kPolicy] || (rEval[f] && st[f | kPolicy] == st[f]),
                   "EvalScript passes with the policy, not without (flags %d)", f);
        FUZZ_CHECK(!rVer[f | kPolicy] || rVer[f], "VerifySignature passes with the policy, not without (flags %d)", f);
        FUZZ_CHECK(fV4Ops || (rEval[f | kPolicy] == rEval[f] && rVer[f | kPolicy] == rVer[f]),
                   "no v4 opcode, yet the policy changes the answer (flags %d)", f);
    }
    for (int f = 0; f < kFlagSets; f++)
    {
        if (!FValid(f))
            continue;
        bool v3 = FV3(f), v4 = FV4(f), v5 = FV5(f);
        bool fBase = f < 8;   // the pairwise switches below compare sets 0-7
        if (fBase && !v4)
        {
            FUZZ_CHECK(!rEval[f] || (rEval[f | 4] && st[f] == st[f | 4]), "EvalScript passes with v4 off, not on (flags %d)", f);
            FUZZ_CHECK(!rVer[f] || rVer[f | 4], "VerifySignature passes with v4 off, not on (flags %d)", f);
            FUZZ_CHECK(fV4Ops || (rEval[f] == rEval[f | 4] && rVer[f] == rVer[f | 4]),
                       "no v4 opcode, yet v4 changes the answer (flags %d)", f);
        }
        if (fBase && !v3)
        {
            FUZZ_CHECK(fV3Ops || rEval[f] == rEval[f | 2], "no CLTV or OP_VER*, yet v3 changes EvalScript (flags %d)", f);
            FUZZ_CHECK(fV3Ops || fP2SH || rVer[f] == rVer[f | 2], "no CLTV, OP_VER* or P2SH, yet v3 changes VerifySignature (flags %d)", f);
        }
        if (fBase && !FStrict(f))
            FUZZ_CHECK(fSigOps || (rEval[f] == rEval[f | 1] && rVer[f] == rVer[f | 1]),
                       "no signature opcode, yet strict signatures change the answer (flags %d)", f);

        if (fP2SH && v3)
            FUZZ_CHECK(rVer[f] == rP2SH[f], "VerifySignature %d, VerifyScriptP2SH %d on a P2SH output (flags %d)",
                       rVer[f], rP2SH[f], f);
        else
            FUZZ_CHECK(rVer[f] == (fPushOnly && rEval[f]), "VerifySignature %d, push-only %d and EvalScript %d (flags %d)",
                       rVer[f], fPushOnly, rEval[f], f);
        if (!fP2SH)
            FUZZ_CHECK(rP2SH[f] == (fPushOnly && rEval[f]), "VerifyScriptP2SH %d on a bare output, push-only %d, EvalScript %d",
                       rP2SH[f], fPushOnly, rEval[f]);
        if (rP2SH[f])
            FUZZ_CHECK(fPushOnly && rEval[f], "VerifyScriptP2SH passed, the outer script did not (flags %d)", f);

        // What ConnectBlock (and CheckBlock before it), the miners and the pool
        // charge for this input: the spending scriptSig; the spent
        // scriptPubKey, counted when its transaction was mined, under the
        // rules of that block (v4 or not); under v3 the redeem script; and
        // under v5 (main.cpp ConnectInputs, CoinCountedUnderRulesV4) the
        // OP_CHECKSIGFROMSTACKs of an output made before v4, counted at the
        // spend. Before v5, an output made before v4 and spent under v4 is
        // the gap v5 closes, and an OP_CHECKMULTISIG with more than 20 keys
        // the one the relay policy keeps out of the pool (and v5's key cap
        // out of blocks); under v5 consensus alone bounds the checks.
        if (v5 || Literal(InputMultisigKeyCountsAreLiteral(scriptSig, scriptPubKey, v3)))
        {
            for (int nMadeV4 = 0; nMadeV4 < 2; nMadeV4++)
            {
                bool fMadeV4 = nMadeV4 != 0;
                if (fMadeV4 && !v4)
                    continue;   // v4 never switches off again
                if (!v5 && fMadeV4 != v4)
                    continue;
                uint64 nCharged = (uint64)scriptSig.GetSigOpCount(v4) + scriptPubKey.GetSigOpCount(fMadeV4) +
                                  ((v3 && fP2SH) ? GetP2SHSigOpCount(scriptSig, v4) : 0);
                if (v5 && !fMadeV4)
                    nCharged += scriptPubKey.GetSigOpCount(true) - scriptPubKey.GetSigOpCount(false);
                FUZZ_CHECK(cVer[f] <= nCharged, "the spend made %u signature checks, %llu charged "
                           "(flags %d, output made under v4 %d)", cVer[f], (unsigned long long)nCharged, f, fMadeV4);
            }
        }
        if (v5 || fLiteralWhole)
            FUZZ_CHECK(cEval[f] <= whole.GetSigOpCount(v4), "EvalScript made %u signature checks, %u counted (flags %d)",
                       cEval[f], whole.GetSigOpCount(v4), f);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // 4 kB: every script op copies and scans the script code (FindAndDelete)
    // and each spend is evaluated 27 times. Under honggfuzz, whose memcmp hook
    // is far slower than memcmp, inputs up to 8 kB ran past its 20 s limit
    // (97 timeouts in a 20-minute run; under libFuzzer the slowest was 0.2 s).
    if (size < 1 || size > 4096)
        return 0;
    try
    {
        int nHashType = data[0];
        RawScript(nHashType, CScript(data + 1, data + size));
        FuzzReader r(data + 1, size - 1);
        Spend(nHashType, r);
    }
    catch (std::exception&)
    {
    }
    return 0;
}

// ---- seeds

static valtype PH(int kind, int k = 0, int v = 0)
{
    valtype p(2);
    p[0] = PLACEHOLDER;
    p[1] = (unsigned char)((kind << 4) | ((v & 3) << 2) | (k & 3));
    return p;
}

struct SeedTx
{
    uint8_t ctl;
    uint32_t nVersion, nLockTime;
    vector<uint32_t> vSeq;
    unsigned int nIn;
    vector<pair<uint16_t, uint8_t> > vOut;
    SeedTx() : ctl(0), nVersion(1), nLockTime(0), vSeq(1, 0xffffffff), nIn(0) {}
};

static void Put32(string& s, uint32_t v) { for (int i = 0; i < 4; i++) s += (char)((v >> (8 * i)) & 0xff); }

static void WriteSeed(const string& strDir, const char* pszName, const SeedTx& t, const CScript& sig, const CScript& script)
{
    string s;
    s += (char)0;
    s += (char)t.ctl;
    Put32(s, t.nVersion);
    Put32(s, t.nLockTime);
    s += (char)((t.vSeq.size() - 1) | (t.nIn << 2));
    for (size_t i = 0; i < t.vSeq.size(); i++)
        Put32(s, t.vSeq[i]);
    s += (char)t.vOut.size();
    for (size_t i = 0; i < t.vOut.size(); i++)
    {
        s += (char)(t.vOut[i].first & 0xff);
        s += (char)(t.vOut[i].first >> 8);
        s += (char)t.vOut[i].second;
    }
    s += (char)(sig.size() & 0xff);
    s += (char)(sig.size() >> 8);
    s.append(sig.begin(), sig.end());
    s.append(script.begin(), script.end());
    string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f || fwrite(s.data(), 1, s.size(), f) != s.size())
    {
        perror(strPath.c_str());
        exit(1);
    }
    fclose(f);
}

static void WriteSeeds(const string& strDir)
{
    SeedTx t;
    t.vOut.push_back(make_pair((uint16_t)5000, (uint8_t)2));
    CScript p2pkh = CScript() << OP_DUP << OP_HASH160 << PH(3, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript sigP2pkh = CScript() << PH(0, 0) << PH(1, 0);
    WriteSeed(strDir, "p2pkh", t, sigP2pkh, p2pkh);
    WriteSeed(strDir, "p2pk-uncompressed", t, CScript() << PH(0, 1, 1), CScript() << PH(2, 1) << OP_CHECKSIG);
    WriteSeed(strDir, "p2pkh-high-s", t, CScript() << PH(10, 0) << PH(1, 0), p2pkh);
    CScript ms = CScript() << OP_2 << PH(1, 0) << PH(1, 1) << PH(1, 2) << OP_3 << OP_CHECKMULTISIG;
    CScript sigMs = CScript() << OP_0 << PH(0, 0) << PH(0, 1);
    WriteSeed(strDir, "multisig", t, sigMs, ms);
    t.ctl = 3;
    WriteSeed(strDir, "multisig-p2sh", t, sigMs, ms);
    WriteSeed(strDir, "p2pkh-p2sh", t, sigP2pkh, p2pkh);

    SeedTx c = t;
    c.nLockTime = 1000;
    c.vSeq[0] = 0xfffffffe;
    WriteSeed(strDir, "cltv", c, sigP2pkh, CScript() << PH(9) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                                                     << OP_DUP << OP_HASH160 << PH(3, 0) << OP_EQUALVERIFY << OP_CHECKSIG);
    c.nLockTime = 1800000000;
    WriteSeed(strDir, "cltv-time", c, sigP2pkh, CScript() << PH(9) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << PH(1, 0) << OP_CHECKSIG);

    SeedTx v = t;
    v.nVersion = 2;
    v.vSeq[0] = 144;
    WriteSeed(strDir, "csv", v, sigP2pkh, CScript() << PH(8) << OP_CHECKSEQUENCEVERIFY << OP_DROP
                                                    << OP_DUP << OP_HASH160 << PH(3, 0) << OP_EQUALVERIFY << OP_CHECKSIG);
    v.vSeq[0] = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    WriteSeed(strDir, "csv-time", v, sigP2pkh, CScript() << PH(8) << OP_CHECKSEQUENCEVERIFY << OP_DROP << PH(1, 0) << OP_CHECKSIG);

    SeedTx ctv = t;
    ctv.nVersion = 2;
    ctv.vOut.push_back(make_pair((uint16_t)7000, (uint8_t)1));
    WriteSeed(strDir, "ctv", ctv, CScript(), CScript() << PH(7) << OP_CHECKTEMPLATEVERIFY);
    ctv.vSeq.push_back(0xffffffff);
    ctv.nIn = 1;
    WriteSeed(strDir, "ctv-two-inputs", ctv, CScript(), CScript() << PH(12) << OP_CHECKTEMPLATEVERIFY);

    WriteSeed(strDir, "csfs", t, CScript() << PH(5, 0, 1), CScript() << PH(6, 0, 1) << PH(4, 0) << OP_CHECKSIGFROMSTACK);
    WriteSeed(strDir, "csfs-empty-message", t, CScript() << PH(5, 2, 0) << PH(6, 0, 0),
              CScript() << PH(4, 2) << OP_CHECKSIGFROMSTACK);

    // The vault's unvault script (hot path) and the inheritance script (heir).
    CScript vault = CScript() << OP_IF << (int64)144 << OP_CHECKSEQUENCEVERIFY << OP_DROP
                              << OP_DUP << OP_HASH160 << PH(3, 0) << OP_EQUALVERIFY << OP_CHECKSIG
                              << OP_ELSE << OP_DUP << OP_HASH160 << PH(3, 1) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
    v.vSeq[0] = 144;
    WriteSeed(strDir, "vault-hot", v, CScript() << PH(0, 0) << PH(1, 0) << OP_1, vault);
    WriteSeed(strDir, "vault-recover", v, CScript() << PH(0, 1) << PH(1, 1) << OP_0, vault);
    CScript inherit = CScript() << OP_IF << OP_DUP << OP_HASH160 << PH(3, 0) << OP_EQUALVERIFY << OP_CHECKSIG
                                << OP_ELSE << (int64)(SEQUENCE_LOCKTIME_TYPE_FLAG | 10) << OP_CHECKSEQUENCEVERIFY << OP_DROP
                                << OP_DUP << OP_HASH160 << PH(3, 1) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
    v.vSeq[0] = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    WriteSeed(strDir, "inherit-heir", v, CScript() << PH(0, 1) << PH(1, 1) << OP_0, inherit);

    // A key count the script computes, which the relay policy refuses.
    t.ctl = 0;
    WriteSeed(strDir, "multisig-computed-keys", t, CScript() << OP_0 << OP_0,
              CScript() << PH(1, 0) << PH(1, 1) << OP_1 << OP_1 << OP_ADD << OP_CHECKMULTISIG);
    // 25 keys, the count made by OP_ADD, one signature by the deepest key: 25
    // checks for 20 charged. Refused by the relay policy and by rules v5;
    // without v5 held to the bound only under BITFLASH_FUZZ_SCRIPT_NO_POLICY=1,
    // where it aborts.
    CScript wide;
    wide << PH(1, 3);   // deepest: the keys are tried from the top of the stack down
    for (int i = 0; i < 24; i++)
        wide << PH(1, i % 3);
    wide << OP_16 << OP_9 << OP_ADD << OP_CHECKMULTISIG;
    WriteSeed(strDir, "multisig-25-keys-computed", t, CScript() << OP_0 << PH(0, 3) << OP_1, wide);
}

static void FuzzScriptInit()
{
    FuzzKeys();
    const char* pszNoPolicy = getenv("BITFLASH_FUZZ_SCRIPT_NO_POLICY");
    fNoPolicy = pszNoPolicy && *pszNoPolicy == '1';
    const char* pszDebug = getenv("BITFLASH_FUZZ_SCRIPT_DEBUG");
    fScriptDebug = pszDebug && *pszDebug == '1';
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        fprintf(stderr, "fuzz-script: seeds written to %s\n", pszSeeds);
        exit(0);
    }
}
