// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// What the wallet's explorer shows, read from this node's own files. Nothing
// here touches the network: a lookup on a website tells that website which
// transaction is interesting, and this one tells nobody.
//
// Kept apart from the window so it can be tested without one. Every call waits
// for cs_main, which the node hardly ever leaves free for long: a caller with a
// frame to draw calls from a thread of its own.

#ifndef BITFLASH_EXPLORER_H
#define BITFLASH_EXPLORER_H

#include <string>
#include <vector>

namespace explorer {

enum Result { FOUND, IS_BLOCK, IS_TX, NOT_FOUND, BAD_QUERY };

struct BlockRow
{
    int height;
    uint256 hash;
    int64 time;
    int nTx;
    unsigned int nSize;
    int64 reward;       // what the coinbase pays, fees included
    std::string to;     // its first output
};

struct TxRow
{
    uint256 txid;
    bool fCoinBase;
    int nIn, nOut;
    int64 value;
};

struct BlockView
{
    int height;
    uint256 hash, prev, next;   // next is zero at the tip and off the main chain
    uint256 merkleRoot;
    int nVersion;
    int64 time;
    unsigned int nBits, nNonce, nSize;
    bool fMainChain;
    std::vector<TxRow> txs;
};

struct Input
{
    uint256 prev;
    unsigned int n;
    bool fKnown;        // the transaction it spends was found
    int64 value;
    std::string from;
};

struct Output
{
    int64 value;
    std::string to;     // an address, or what kind of script it is
    uint256 spentBy;    // zero while unspent, and for one still unconfirmed
};

struct TxView
{
    uint256 txid;
    bool fCoinBase, fInChain;
    int height, nConfirmations; // meaningful when fInChain
    uint256 block;
    int64 time;
    unsigned int nSize;
    bool fFeeKnown;     // every input's value was found
    int64 fee;
    std::vector<Input> in;
    std::vector<Output> out;
};

// What a query names: a height or a block hash (IS_BLOCK) or a txid (IS_TX).
Result Find(const std::string& strQuery, uint256& hashRet);
// nCount blocks of the main chain, newest first, from height nTop down: from
// the tip when nTop is negative. nTipRet is the tip's height.
Result Recent(int nTop, int nCount, std::vector<BlockRow>& rowsRet, int& nTipRet);
Result ReadBlock(const uint256& hash, BlockView& viewRet);
Result ReadTx(const uint256& txid, TxView& viewRet);
// Every digit, with at least two decimals: FormatMoney stops at cents.
std::string Money(int64 n);
// An address, or failing that a word for the kind of script.
std::string DescribeScript(const CScript& scriptPubKey);

}

#endif
