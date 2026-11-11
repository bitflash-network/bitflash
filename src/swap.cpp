// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See swap.h.

#include "headers.h"
#include "swap.h"

namespace swap
{

typedef std::vector<unsigned char> valtype;

CScript BuildContract(const Contract& c)
{
    CScript s;
    s << OP_IF
          << OP_SIZE << (int64)SECRET_BYTES << OP_EQUALVERIFY << OP_SHA256 << c.secretHash << OP_EQUALVERIFY
          << OP_DUP << OP_HASH160 << c.recipientPkh
      << OP_ELSE
          << (int64)c.nLockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP
          << OP_DUP << OP_HASH160 << c.refundPkh
      << OP_ENDIF
      << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

bool ParseContract(const CScript& script, Contract& out)
{
    // Walk the ops and compare against the template. Every push is checked
    // for length, and the script must end where the template does: a contract
    // with anything appended is not this contract.
    std::vector<std::pair<opcodetype, valtype> > ops;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end())
    {
        opcodetype op;
        valtype v;
        if (!script.GetOp(pc, op, v))
            return false;
        ops.push_back(std::make_pair(op, v));
    }
    if (ops.size() != 20)
        return false;
    // The size check: 32 is pushed as data (0x01 0x20), not an OP_N.
    if (ops[0].first != OP_IF || ops[1].first != OP_SIZE ||
        ops[2].second != valtype(1, (unsigned char)SECRET_BYTES) ||
        ops[3].first != OP_EQUALVERIFY || ops[4].first != OP_SHA256 ||
        ops[5].second.size() != 32 || ops[6].first != OP_EQUALVERIFY ||
        ops[7].first != OP_DUP || ops[8].first != OP_HASH160 || ops[9].second.size() != 20 ||
        ops[10].first != OP_ELSE ||
        ops[12].first != OP_CHECKLOCKTIMEVERIFY || ops[13].first != OP_DROP ||
        ops[14].first != OP_DUP || ops[15].first != OP_HASH160 || ops[16].second.size() != 20 ||
        ops[17].first != OP_ENDIF || ops[18].first != OP_EQUALVERIFY || ops[19].first != OP_CHECKSIG)
        return false;
    // The lock: a minimal positive number of at most five bytes.
    const valtype& lock = ops[11].second;
    if (lock.empty() || lock.size() > 5 || (lock.back() & 0x80))
        return false;
    // Little-endian, sign bit already known clear. nLockTime is 32 bits, so a
    // lock past that is one no transaction could ever meet.
    uint64_t n = 0;
    for (size_t i = lock.size(); i-- > 0; )
        n = (n << 8) | lock[i];
    if (n == 0 || n > 0xffffffffULL)
        return false;
    out.secretHash   = ops[5].second;
    out.recipientPkh = ops[9].second;
    out.refundPkh    = ops[16].second;
    out.nLockTime    = (int64_t)n;
    // The same ops can be pushed the long way (OP_PUSHDATA1 for 32 bytes).
    // Bitcoin Cash and eCash refuse such a push in a spend, the others will
    // not relay it: a redeem of that contract never confirms, and its maker
    // refunds. Only the bytes this wallet would have written are a contract.
    if (BuildContract(out) != script)
        return false;
    return true;
}

CScript RedeemScriptSig(const valtype& sig, const valtype& pubkey, const valtype& secret,
                        const CScript& contract)
{
    CScript s;
    s << sig << pubkey << secret << OP_TRUE << static_cast<valtype>(contract);
    return s;
}

CScript RefundScriptSig(const valtype& sig, const valtype& pubkey, const CScript& contract)
{
    CScript s;
    s << sig << pubkey << OP_FALSE << static_cast<valtype>(contract);
    return s;
}

int64_t SecondsUntilRefund(int64_t nLockTime, int64_t nMedianTimePast)
{
    return nMedianTimePast > nLockTime ? 0 : nLockTime - nMedianTimePast + 1;
}

bool NewSecret(valtype& secretOut, valtype& hashOut)
{
    secretOut.assign(SECRET_BYTES, 0);
    hashOut.clear();
    if (RAND_bytes(&secretOut[0], (int)secretOut.size()) != 1)
    {
        OPENSSL_cleanse(&secretOut[0], secretOut.size());
        secretOut.clear();
        return false;
    }
    hashOut.resize(32);
    SHA256(&secretOut[0], secretOut.size(), &hashOut[0]);
    return true;
}

// ---- the journal ------------------------------------------------------------

static CCriticalSection cs_journal;
static std::string g_strJournalPath;

std::string JournalPath()
{
    CRITICAL_BLOCK(cs_journal)
        if (!g_strJournalPath.empty())
            return g_strJournalPath;
    return GetAppDir() + "/swaps.log";
}

void JournalSetPathForTest(const std::string& path)
{
    CRITICAL_BLOCK(cs_journal)
        g_strJournalPath = path;
}

bool JournalTagOk(const std::string& tag)
{
    if (tag.empty() || tag.size() > 64)
        return false;
    for (size_t i = 0; i < tag.size(); i++)
        if (!isalnum((unsigned char)tag[i]) && tag[i] != '_' && tag[i] != ':' && tag[i] != '-')
            return false;
    return true;
}

// The whole file, or "" when there is none yet. False when it is there but
// cannot be read: writing over it then would lose every secret it holds.
static bool ReadJournalFile(const std::string& path, std::string& out, std::string& errOut)
{
    out.clear();
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
    {
        if (errno == ENOENT)
            return true;
        errOut = strprintf("cannot read %s (%s)", path.c_str(), strerror(errno));
        return false;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    bool fErr = ferror(f) != 0;
    fclose(f);
    if (fErr)
    {
        errOut = "cannot read " + path;
        return false;
    }
    return true;
}

bool JournalAppend(const nlohmann::json& line, std::string& errOut)
{
    errOut.clear();
    nlohmann::json j = line;
    if (!j.is_object())
    {
        errOut = "a journal line is an object";
        return false;
    }
    if (!j.contains("time"))
        j["time"] = (int64_t)GetTime();
    std::string path = JournalPath();
    CRITICAL_BLOCK(cs_journal)
    {
        std::string all;
        if (!ReadJournalFile(path, all, errOut))
            return false;
        // A line cut short by a crash of an older version ends without a
        // newline: the next one starts on its own.
        if (!all.empty() && all[all.size() - 1] != '\n')
            all += "\n";
        all += j.dump() + "\n";
        bool fOk = WriteFileAtomicPrivate(path, all, errOut);
        if (!all.empty())
            OPENSSL_cleanse(&all[0], all.size());
        return fOk;
    }
    return false;
}

bool JournalRead(std::vector<nlohmann::json>& out, std::string& errOut)
{
    out.clear();
    errOut.clear();
    std::string all;
    CRITICAL_BLOCK(cs_journal)
        if (!ReadJournalFile(JournalPath(), all, errOut))
            return false;
    size_t nStart = 0;
    while (nStart < all.size())
    {
        size_t nEnd = all.find('\n', nStart);
        if (nEnd == std::string::npos)
            nEnd = all.size();
        if (nEnd > nStart)
        {
            try
            {
                nlohmann::json j = nlohmann::json::parse(all.substr(nStart, nEnd - nStart));
                if (j.is_object())
                    out.push_back(j);
            }
            catch (...) {}    // a torn line from before the journal was atomic
        }
        nStart = nEnd + 1;
    }
    if (!all.empty())
        OPENSSL_cleanse(&all[0], all.size());
    return true;
}

bool JournalLookup(const std::string& tag, nlohmann::json& mergedOut, std::string& errOut)
{
    mergedOut = nlohmann::json();
    std::vector<nlohmann::json> lines;
    if (!JournalRead(lines, errOut))
        return false;
    for (size_t i = 0; i < lines.size(); i++)
    {
        if (!lines[i].contains("tag") || !lines[i]["tag"].is_string() || lines[i]["tag"].get<std::string>() != tag)
            continue;
        if (mergedOut.is_null())
            mergedOut = nlohmann::json::object();
        for (nlohmann::json::const_iterator it = lines[i].begin(); it != lines[i].end(); ++it)
            mergedOut[it.key()] = it.value();
    }
    return true;
}

bool ExtractSecret(const CScript& scriptSig, const valtype& secretHash, valtype& secretOut)
{
    CScript::const_iterator pc = scriptSig.begin();
    while (pc < scriptSig.end())
    {
        opcodetype op;
        valtype v;
        if (!scriptSig.GetOp(pc, op, v))
            return false;
        if (v.size() != SECRET_BYTES)
            continue;
        unsigned char h[32];
        SHA256(&v[0], v.size(), h);
        if (valtype(h, h + 32) == secretHash)
        {
            secretOut = v;
            return true;
        }
    }
    return false;
}

} // namespace swap
