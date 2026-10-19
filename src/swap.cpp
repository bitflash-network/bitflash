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
