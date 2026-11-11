// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The scripts behind the rules v4 wallet contracts (docs/rules-v4.md,
// docs/inheritance.md): the vault, the CTV batch and the inheritance. The RPCs
// in jsonrpc.cpp build them with these functions, and so does the
// fuzz-v4-templates harness, so what it checks is what the wallet funds.
// Include <nlohmann/json.hpp> before headers_core.h (util.h redefines
// snprintf), and this after it.
#ifndef BITFLASH_V4TEMPLATES_H
#define BITFLASH_V4TEMPLATES_H

#include <nlohmann/json.hpp>

// The hash of the one-input transaction a CTV template fixes: version 2,
// sequence final, lock time 0, these outputs (what spendscript builds by
// default), for input 0.
uint256 TemplateHashFor(const vector<CTxOut>& vout);
// <hash> OP_CHECKTEMPLATEVERIFY: the redeem script of a vault's first stage and
// of a CTV batch.
CScript CtvScript(uint256 hash);
// Throws when the template's spend could never be relayed or mined (too large,
// or a fee below what miners ask of it): vaultcreate and ctvbatch call it
// before any coin goes in.
void CheckCtvSpendPolicy(const CScript& redeem, const vector<CTxOut>& vout, int64 nFee, const char* pszWhat);

// Vault. Stage 2 (the unvault output): the hot key after nDelay blocks, or the
// recovery key at once. Stage 1 (the vault) is CtvScript(TemplateHashFor(
// VaultUnvaultOutputs(unvault, amount - fee))).
CScript VaultUnvaultScript(unsigned int nDelay, const uint160& hashHot, const uint160& hashRecovery);
vector<CTxOut> VaultUnvaultOutputs(const CScript& unvault, int64 nUnvaultAmount);

// CTV batch: {"address": amount, ...} as ctvbatch takes it and ctvexpand reads
// it back from the contracts file, in the order the JSON object keeps.
vector<CTxOut> OutputsFromParam(const nlohmann::json& o);
// Amounts as the RPCs write them into JSON (and into the contracts file) and
// read them back: a vault's unvault amount makes this round trip between
// vaultcreate and vaultunvault, and its template holds only if it is exact.
double ValueFromAmount(int64 n);
int64 AmountFromValue(const nlohmann::json& v);

// Inheritance: the period as a BIP68 time-type nSequence (throws on a period
// out of range), its length in seconds, the script, and the script read back.
unsigned int InheritSequence(double dDays);
int64 InheritPeriodSecs(unsigned int nSequence);
CScript InheritScript(const uint160& hashOwner, const uint160& hashHeir, unsigned int nSequence);
bool ParseInheritScript(const CScript& s, uint160& hashOwner, uint160& hashHeir, unsigned int& nSequence);

#endif
