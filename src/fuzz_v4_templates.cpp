// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// libFuzzer harness for the rules v4 wallet contracts (docs/rules-v4.md,
// docs/inheritance.md): the vault, the CTV batch and the inheritance. Each is
// built from fuzzed parameters by the functions the RPCs use (v4templates.h),
// funded by a made-up transaction, and spent the way the RPCs spend it, then
// checked with the real interpreter (VerifySignature, as ConnectInputs calls
// it) against what the documents promise:
//
//  vault    the vault output leaves only by the transaction its template
//           fixes -- any spend that verifies has version 2, lock time 0, one
//           input with the final sequence and exactly the unvault output --
//           and that transaction, rebuilt the way vaultunvault rebuilds it
//           from the contracts file, verifies; nothing before rules v4 does.
//           The unvault output: the recovery key at once; the hot key only
//           with a version >= 2 transaction whose nSequence is a block-type
//           lock of at least the delay (BIP112); no other key, and no
//           scriptSig without the right key's signature, either way.
//  batch    the same for the expansion, with the outputs read back from the
//           JSON the contracts file keeps.
//  inherit  the period is a time-type lock no shorter than asked; the script
//           reads back (owner, heir, period), and anything ParseInheritScript
//           accepts is exactly the script InheritScript makes; the owner
//           spends at any time, the heir only with a v2 transaction carrying
//           a time-type lock of at least the period; nobody else.
//  all      a scriptSig changed by a third party (pushes added in front) still
//           verifies -- the txid of a CTV or signed spend is not fixed, as
//           docs/rules-v4.md says -- but what the transaction does stays
//           fixed: the CTV template, or the signature, still decides it.
//
// Input: byte 0 picks the contract; the rest are its parameters and the
// attack (see each function). BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a seed
// per contract and exits.

// nlohmann before the node headers: util.h redefines snprintf (as jsonrpc.cpp does it).
#include <nlohmann/json.hpp>
#include "headers_core.h"
#include "v4templates.h"

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

static void FuzzTemplatesInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzTemplatesInit
#include "fuzz_datadir.h"
#include "fuzz_script_util.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using json = nlohmann::json;
typedef vector<unsigned char> valtype;

// ---- helpers

// A transaction paying `value` to P2SH(redeem), as FundScript makes it.
static CTransaction Fund(const CScript& redeem, int64 nValue, unsigned int nOut)
{
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(uint256(42), 0), CScript() << OP_TRUE));
    for (unsigned int i = 0; i < nOut; i++)
        tx.vout.push_back(CTxOut(CENT, CScript() << OP_TRUE));
    CScript p2sh;
    p2sh.SetPayToScriptHash(redeem);
    tx.vout.push_back(CTxOut(nValue, p2sh));
    return tx;
}

// The spending transaction spendscript builds: one input, these fields.
static CTransaction SpendOf(const CTransaction& txFrom, unsigned int nOut, const vector<CTxOut>& vout,
                            int nVersion, unsigned int nSequence, unsigned int nLockTime)
{
    CTransaction tx;
    tx.nVersion = nVersion;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(txFrom.GetHash(), nOut);
    tx.vin[0].nSequence = nSequence;
    tx.nLockTime = nLockTime;
    tx.vout = vout;
    return tx;
}

static bool Verify(const CTransaction& txFrom, const CTransaction& tx, bool fV4 = true)
{
    return VerifySignature(txFrom, tx, 0, 0, true, true, fV4);
}

// Pushes a third party could put in front of a scriptSig: from the input.
static CScript Junk(FuzzReader& r)
{
    CScript s;
    unsigned int n = r.GetU8() % 4;
    for (unsigned int i = 0; i < n; i++)
    {
        uint8_t b = r.GetU8();
        if (b < 0x20)
            s << OP_0;
        else if (b < 0x40)
            s << (opcodetype)(OP_1 + (b & 15));
        else
            s << r.Bytes(b & 0x3f);
    }
    return s;
}

// A random but well-formed change to a template spend that the template must
// refuse. False when the change turned out to be no change.
static bool Mutate(CTransaction& tx, FuzzReader& r)
{
    uint8_t m = r.GetU8();
    uint32_t x = r.GetU32() | 1;
    switch (m % 8)
    {
    case 0: tx.nVersion ^= (int)x; return true;
    case 1: tx.nLockTime ^= x; return true;
    case 2: tx.vin[0].nSequence ^= x; return true;
    case 3: tx.vin.push_back(CTxIn(COutPoint(uint256(x), 0), CScript())); return true;
    case 4:
        if (tx.vout.empty()) return false;
        tx.vout[x % tx.vout.size()].nValue += (x >> 1) + 1;
        return true;
    case 5:
        if (tx.vout.empty()) return false;
        tx.vout[x % tx.vout.size()].nValue -= 1;
        return true;
    case 6: tx.vout.push_back(CTxOut(x, CScript() << OP_TRUE)); return true;
    default:
        if (tx.vout.empty()) return false;
        tx.vout.erase(tx.vout.begin() + x % tx.vout.size());
        return true;
    }
}

static int kHashTypeFor(uint8_t b)
{
    static const int k[4] = { SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY };
    return k[b & 3];
}

static bool SameTemplate(const CTransaction& tx, const vector<CTxOut>& vout)
{
    return tx.nVersion == 2 && tx.nLockTime == 0 && tx.vin.size() == 1 && tx.vin[0].nSequence == 0xffffffff &&
           tx.vout == vout;
}

// A CTV-guarded redeem (vault stage 1, batch): the honest spend verifies only
// under v4; changes are refused; added pushes keep it valid and the template
// intact; and any spend the fuzzer makes that verifies is the template.
static void CheckCtvContract(const char* pszWhat, const CScript& redeem, const vector<CTxOut>& vTemplate,
                             const vector<CTxOut>& vRebuilt, int64 nFunded, FuzzReader& r)
{
    FUZZ_CHECK(TemplateHashFor(vRebuilt) == TemplateHashFor(vTemplate),
               "%s: the outputs read back from the contracts file make another template; it could never be spent", pszWhat);
    CTransaction txFund = Fund(redeem, nFunded, r.GetU8() % 2);
    unsigned int nOut = txFund.vout.size() - 1;
    CTransaction tx = SpendOf(txFund, nOut, vRebuilt, 2, 0xffffffff, 0);
    tx.vin[0].scriptSig << valtype(redeem.begin(), redeem.end());
    FUZZ_CHECK(Verify(txFund, tx), "%s: the template spend does not verify under rules v4", pszWhat);
    FUZZ_CHECK(!Verify(txFund, tx, false), "%s: the template spend verifies before rules v4", pszWhat);

    // A third party's pushes in front: still valid, still the template.
    CTransaction txMal = tx;
    txMal.vin[0].scriptSig = Junk(r) + tx.vin[0].scriptSig;
    FUZZ_CHECK(Verify(txFund, txMal) && SameTemplate(txMal, vTemplate),
               "%s: a scriptSig with pushes added in front no longer verifies", pszWhat);

    CTransaction txBad = tx;
    if (Mutate(txBad, r))
        FUZZ_CHECK(!Verify(txFund, txBad), "%s: a changed spend still verifies", pszWhat);

    // Whatever the fuzzer builds: if it verifies, it is the template.
    int nAnyVersion = (int)r.GetU32();
    unsigned int nAnySeq = r.GetU32(), nAnyLock = r.GetU32();
    CTransaction txAny = SpendOf(txFund, nOut, vRebuilt, nAnyVersion, nAnySeq, nAnyLock);
    if (r.GetU8() & 1)
        Mutate(txAny, r);
    txAny.vin[0].scriptSig = Junk(r);
    txAny.vin[0].scriptSig << valtype(redeem.begin(), redeem.end());
    if (Verify(txFund, txAny))
        FUZZ_CHECK(SameTemplate(txAny, vTemplate), "%s: a spend other than the template verifies", pszWhat);
}

// One path of a two-key script, signed by key `k`, with [sig pub flag] as
// spendscript lays them out and the redeem script on top.
static bool SignedPath(const CTransaction& txFrom, CTransaction tx, const CScript& redeem, const FuzzKey& k,
                       bool fIfBranch, const CScript& junk, bool fHighS = false)
{
    valtype sig = FuzzSigFor(k, redeem, tx, 0, SIGHASH_ALL, fHighS);
    tx.vin[0].scriptSig = junk;
    tx.vin[0].scriptSig << sig << k.pubC << (fIfBranch ? OP_TRUE : OP_FALSE) << valtype(redeem.begin(), redeem.end());
    return Verify(txFrom, tx);
}

// A scriptSig made by the fuzzer from pushes, signatures and keys of the keys
// in `mask` only, and the redeem script. Must fail when mask holds neither
// of the keys the script names.
static bool ForgedPath(const CTransaction& txFrom, CTransaction tx, const CScript& redeem, unsigned int mask, FuzzReader& r)
{
    const vector<FuzzKey>& keys = FuzzKeys();
    CScript s;
    unsigned int n = 1 + r.GetU8() % 5;
    for (unsigned int i = 0; i < n; i++)
    {
        uint8_t b = r.GetU8();
        unsigned int k = (b >> 4) & 3;
        if (!(mask & (1u << k)))
            k = 0xff;
        switch (b & 7)
        {
        case 0: s << OP_0; break;
        case 1: s << OP_1; break;
        case 2: if (k != 0xff) s << FuzzSigFor(keys[k], redeem, tx, 0); break;
        case 3: if (k != 0xff) s << keys[k].pubC; break;
        case 4: if (k != 0xff) s << keys[k].pubU; break;
        case 5: if (k != 0xff) s << FuzzSigFor(keys[k], redeem, tx, 0, kHashTypeFor(r.GetU8())); break;
        default: s << r.Bytes(r.GetU8() % 80); break;
        }
    }
    s << valtype(redeem.begin(), redeem.end());
    tx.vin[0].scriptSig = s;
    return Verify(txFrom, tx);
}

// ---- vault
//   u16 delay, u8 hot/recovery key, u32 amount, u32 fee, then the attacks.

static void Vault(FuzzReader& r)
{
    const vector<FuzzKey>& keys = FuzzKeys();
    unsigned int nDelay = 1 + r.GetU16() % 0xffff;
    uint8_t kb = r.GetU8();
    unsigned int iHot = kb & 3, iRec = (kb >> 2) & 3;
    int64 nAmount = (int64)(r.GetU64() % (21000000 * COIN)) + 1;
    int64 nFee = (int64)(r.GetU32() % 100000000) + 1;
    if (nAmount <= nFee)   // vaultcreate's rule
        return;

    CScript unvault = VaultUnvaultScript(nDelay, keys[iHot].hashC, keys[iRec].hashC);
    vector<CTxOut> vUnvault = VaultUnvaultOutputs(unvault, nAmount - nFee);
    CScript vault = CtvScript(TemplateHashFor(vUnvault));
    CheckCtvSpendPolicy(vault, vUnvault, nFee, "unvault transaction");   // throws: vaultcreate funds nothing

    // vaultcreate keeps the unvault amount as a JSON number in the contracts
    // file; vaultunvault reads it back and spends to {unvaultAddress: it}.
    json rec;
    rec["unvaultAddress"] = Hash160ToScriptAddress(Hash160(unvault));
    rec["unvaultAmount"] = ValueFromAmount(nAmount - nFee);
    json back = json::parse(rec.dump());
    json out;
    out[back["unvaultAddress"].get<string>()] = back["unvaultAmount"];
    vector<CTxOut> vRebuilt = OutputsFromParam(out);
    CheckCtvContract("vault", vault, vUnvault, vRebuilt, nAmount, r);

    // Stage 2: the unvault output, as SpendUnvault spends it.
    CTransaction txUnvault = Fund(unvault, nAmount - nFee, 0);
    int nVersion = (int)r.GetU32();
    unsigned int nSeq = r.GetU32();
    if (r.GetU8() & 1)
        nSeq = nDelay + (r.GetU8() % 3) - 1;   // near the boundary
    if (r.GetU8() & 1)
        nVersion = 2;
    vector<CTxOut> vTo(1, CTxOut(nAmount - nFee - CENT, CScript() << OP_DUP << OP_HASH160 << keys[3].hashC
                                                                  << OP_EQUALVERIFY << OP_CHECKSIG));
    CTransaction tx2 = SpendOf(txUnvault, 0, vTo, nVersion, nSeq, r.GetU32());
    CScript junk = Junk(r);

    FUZZ_CHECK(SignedPath(txUnvault, tx2, unvault, keys[iRec], false, junk),
               "vault: the recovery key cannot take the unvault output at once (version %d, sequence %08x)", nVersion, nSeq);
    bool fLockOk = (unsigned int)nVersion >= 2 && !(nSeq & SEQUENCE_LOCKTIME_DISABLE_FLAG) &&
                   !(nSeq & SEQUENCE_LOCKTIME_TYPE_FLAG) && (nSeq & SEQUENCE_LOCKTIME_MASK) >= nDelay;
    FUZZ_CHECK(SignedPath(txUnvault, tx2, unvault, keys[iHot], true, junk) == fLockOk,
               "vault: hot path with version %d, sequence %08x, delay %u: expected %d", nVersion, nSeq, nDelay, fLockOk);
    FUZZ_CHECK(!SignedPath(txUnvault, tx2, unvault, keys[iHot], true, junk, true),
               "vault: a high-S signature passes under rules v2");
    for (unsigned int k = 0; k < 4; k++)
    {
        if (keys[k].hashC != keys[iHot].hashC)
            FUZZ_CHECK(!SignedPath(txUnvault, tx2, unvault, keys[k], true, junk), "vault: key %u takes the hot path", k);
        if (keys[k].hashC != keys[iRec].hashC)
            FUZZ_CHECK(!SignedPath(txUnvault, tx2, unvault, keys[k], false, junk), "vault: key %u takes the recovery path", k);
    }
    unsigned int mask = 0xf & ~(1u << iHot) & ~(1u << iRec);
    FUZZ_CHECK(!ForgedPath(txUnvault, tx2, unvault, mask, r), "vault: a scriptSig without the hot or recovery key verifies");
}

// ---- batch
//   u8 outputs, then per output: u8 kind (address type, amount form), key or
//   script bytes, amount; u32 fee; then the attacks.

static void Batch(FuzzReader& r)
{
    const vector<FuzzKey>& keys = FuzzKeys();
    json outputs = json::object();
    unsigned int n = 1 + r.GetU8() % 8;
    for (unsigned int i = 0; i < n; i++)
    {
        uint8_t kind = r.GetU8();
        string strAddr;
        if (kind & 1)
            strAddr = Hash160ToAddress(keys[(kind >> 1) & 3].hashC);
        else
        {
            CScript s = CScript() << r.Bytes(1 + r.GetU8() % 8);
            strAddr = Hash160ToScriptAddress(Hash160(s));
        }
        uint64 v = r.GetU64();
        switch ((kind >> 3) & 3)
        {
        case 0: outputs[strAddr] = ValueFromAmount((int64)(v % (21000000 * COIN)) + 1); break;
        case 1: outputs[strAddr] = FormatMoney((int64)(v % (21000000 * COIN)) + 1); break;
        case 2: outputs[strAddr] = (double)(v % 100000) / 1000.0; break;
        default:
            {
                valtype b = r.Bytes(r.GetU8() % 16);
                outputs[strAddr] = string(b.begin(), b.end());
            }
            break;
        }
    }
    vector<CTxOut> vout;
    try
    {
        vout = OutputsFromParam(outputs);   // what ctvbatch takes
    }
    catch (std::exception&)
    {
        return;   // refused at creation: nothing is funded
    }
    int64 nTotal = 0;
    foreach(const CTxOut& o, vout)
        nTotal += o.nValue;
    int64 nFee = (int64)(r.GetU32() % 100000000) + 1;
    CScript batch = CtvScript(TemplateHashFor(vout));
    try
    {
        CheckCtvSpendPolicy(batch, vout, nFee, "expansion transaction");
    }
    catch (std::exception&)
    {
        return;   // ctvbatch refuses it before funding
    }

    // ctvbatch stores the outputs object; ctvexpand reads it back from the file.
    json rec;
    rec["outputs"] = outputs;
    json back = json::parse(rec.dump());
    vector<CTxOut> vRebuilt;
    try
    {
        vRebuilt = OutputsFromParam(back["outputs"]);
    }
    catch (std::exception& e)
    {
        FUZZ_CHECK(false, "batch: the stored outputs no longer parse (%s); the batch could never be expanded", e.what());
    }
    CheckCtvContract("batch", batch, vout, vRebuilt, nTotal + nFee, r);
}

// ---- inheritance
//   u8 network/form, u32 days (x 1/1000) or raw double, u8 owner/heir, the
//   attacks; then bytes handed to ParseInheritScript.

static void Inherit(FuzzReader& r)
{
    const vector<FuzzKey>& keys = FuzzKeys();
    uint8_t form = r.GetU8();
    bool fTestNet = (form & 1) != 0;
    double dDays;
    if (form & 2)
    {
        uint64 bits = r.GetU64();
        memcpy(&dDays, &bits, sizeof(dDays));
    }
    else
        dDays = (double)r.GetU32() / 1000.0;
    SelectNetworkParams(fTestNet);
    unsigned int nSeq = 0;
    bool fOk = true;
    try
    {
        nSeq = InheritSequence(dDays);
    }
    catch (std::exception&)
    {
        fOk = false;
    }
    SelectNetworkParams(true);
    if (fOk)
    {
        FUZZ_CHECK((nSeq & SEQUENCE_LOCKTIME_TYPE_FLAG) && (nSeq & SEQUENCE_LOCKTIME_MASK) &&
                   !(nSeq & ~(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK)),
                   "inherit: %g days gave sequence %08x", dDays, nSeq);
        FUZZ_CHECK(dDays > 0 && (fTestNet || dDays >= 30), "inherit: %g days accepted on %s", dDays, fTestNet ? "testnet" : "mainnet");
        double dSecs = dDays * 86400.0;
        FUZZ_CHECK((double)InheritPeriodSecs(nSeq) >= dSecs - 1e-6 && (double)InheritPeriodSecs(nSeq) <= dSecs + 512,
                   "inherit: %g days became %lld seconds", dDays, (long long)InheritPeriodSecs(nSeq));
    }
    else
        nSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | (1 + r.GetU16() % 0xffff);

    uint8_t kb = r.GetU8();
    unsigned int iOwner = kb & 3, iHeir = (kb >> 2) & 3;
    CScript redeem = InheritScript(keys[iOwner].hashC, keys[iHeir].hashC, nSeq);
    uint160 hOwner, hHeir;
    unsigned int nSeqBack = 0;
    FUZZ_CHECK(ParseInheritScript(redeem, hOwner, hHeir, nSeqBack) && hOwner == keys[iOwner].hashC &&
               hHeir == keys[iHeir].hashC && nSeqBack == nSeq, "inherit: the script does not read back");

    CTransaction txFrom = Fund(redeem, 10 * COIN, r.GetU8() % 2);
    unsigned int nOut = txFrom.vout.size() - 1;
    int nVersion = (r.GetU8() & 1) ? 2 : (int)r.GetU32();
    unsigned int nTxSeq = r.GetU32();
    uint8_t nNear = r.GetU8();
    if (nNear & 1)
        nTxSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | ((nSeq & SEQUENCE_LOCKTIME_MASK) + (nNear >> 1) % 3 - 1);
    vector<CTxOut> vTo(1, CTxOut(10 * COIN - CENT, CScript() << OP_TRUE));
    CTransaction tx = SpendOf(txFrom, nOut, vTo, nVersion, nTxSeq, r.GetU32());
    CScript junk = Junk(r);

    FUZZ_CHECK(SignedPath(txFrom, tx, redeem, keys[iOwner], true, junk),
               "inherit: the owner cannot spend (version %d, sequence %08x)", nVersion, nTxSeq);
    bool fLockOk = (unsigned int)nVersion >= 2 && !(nTxSeq & SEQUENCE_LOCKTIME_DISABLE_FLAG) &&
                   (nTxSeq & SEQUENCE_LOCKTIME_TYPE_FLAG) &&
                   (nTxSeq & SEQUENCE_LOCKTIME_MASK) >= (nSeq & SEQUENCE_LOCKTIME_MASK);
    FUZZ_CHECK(SignedPath(txFrom, tx, redeem, keys[iHeir], false, junk) == fLockOk,
               "inherit: heir with version %d, sequence %08x, period %08x: expected %d", nVersion, nTxSeq, nSeq, fLockOk);
    for (unsigned int k = 0; k < 4; k++)
    {
        if (keys[k].hashC != keys[iOwner].hashC)
            FUZZ_CHECK(!SignedPath(txFrom, tx, redeem, keys[k], true, junk), "inherit: key %u takes the owner's path", k);
        if (keys[k].hashC != keys[iHeir].hashC)
            FUZZ_CHECK(!SignedPath(txFrom, tx, redeem, keys[k], false, junk), "inherit: key %u takes the heir's path", k);
    }
    unsigned int mask = 0xf & ~(1u << iOwner) & ~(1u << iHeir);
    FUZZ_CHECK(!ForgedPath(txFrom, tx, redeem, mask, r), "inherit: a scriptSig without the owner's or heir's key verifies");

    // Anything ParseInheritScript takes (inheritimport reads a package from
    // somebody else) is exactly an inheritance script, with a time lock.
    valtype vb = r.Rest();
    CScript s(vb.begin(), vb.end());
    if (r.n == 0 && (form & 4))
        s = redeem;
    if (ParseInheritScript(s, hOwner, hHeir, nSeqBack))
        FUZZ_CHECK(InheritScript(hOwner, hHeir, nSeqBack) == s && (nSeqBack & SEQUENCE_LOCKTIME_TYPE_FLAG) &&
                   (nSeqBack & SEQUENCE_LOCKTIME_MASK) &&
                   !(nSeqBack & ~(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK)),
                   "inherit: ParseInheritScript accepted something else");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 4096)
        return 0;
    FuzzReader r(data + 1, size - 1);
    try
    {
        switch (data[0] % 3)
        {
        case 0: Vault(r); break;
        case 1: Batch(r); break;
        default: Inherit(r); break;
        }
    }
    catch (std::exception&)
    {
    }
    SelectNetworkParams(true);
    return 0;
}

static void WriteSeed(const string& strDir, const char* pszName, const string& s)
{
    string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f || fwrite(s.data(), 1, s.size(), f) != s.size())
    {
        perror(strPath.c_str());
        exit(1);
    }
    fclose(f);
}

static void FuzzTemplatesInit()
{
    // Testnet: rules v3 are in force there, so script addresses are taken
    // (ScriptForAddress refuses them before the switch), as on a node the
    // contracts are made on. Inherit switches to mainnet for its period
    // rule and back.
    SelectNetworkParams(true);
    FuzzKeys();
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        // vault: delay 144 (0x0090), hot 0 recovery 1, amount, fee, attacks
        WriteSeed(pszSeeds, "vault", string("\x00\x90\x00\x04\x00\xe1\xf5\x05\x00\x00\x00\x00\x40\x42\x0f\x00"
                                            "\x01\x02\x03\x01\x91\x00\x00\x00\x01\x02\x01", 27));
        WriteSeed(pszSeeds, "vault-same-keys", string("\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x07", 17));
        // batch: three outputs of different forms
        WriteSeed(pszSeeds, "batch", string("\x01\x02\x01\x00\xe1\xf5\x05\x00\x00\x00\x00\x08\x03\x01\x02\x03\x00\x10\x00\x00\x00\x00\x00\x00"
                                            "\x0b\x40\x42\x0f\x00\x00\x00\x00\x00\x10\x27\x00\x00", 37));
        WriteSeed(pszSeeds, "batch-string-amount", string("\x01\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x04" "1.5x", 16));
        // inheritance: testnet, 1 day; mainnet, 30 days; a raw double
        WriteSeed(pszSeeds, "inherit-testnet", string("\x02\x05\x40\x42\x0f\x00\x04\x00\x01\x02\x00\x00\x00\x01", 14));
        WriteSeed(pszSeeds, "inherit-mainnet", string("\x02\x04\x30\x93\x01\x00\x01\x00\x01\x02\x00\x00\x00\x03", 14));
        WriteSeed(pszSeeds, "inherit-double", string("\x02\x03\x00\x00\x00\x00\x00\x00\xf0\x3f\x09", 11));
        fprintf(stderr, "fuzz-v4-templates: seeds written to %s\n", pszSeeds);
        exit(0);
    }
}
