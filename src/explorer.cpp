// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "explorer.h"

namespace explorer {

// A transaction can have thousands of inputs and each is a read under cs_main.
// Past this many the fee goes unknown instead of the window going grey.
static const size_t MAX_INPUTS_READ = 1000;

string Money(int64 n)
{
    string str = strprintf("%s%lld.%08lld", n < 0 ? "-" : "", (long long)((n < 0 ? -n : n) / COIN), (long long)((n < 0 ? -n : n) % COIN));
    size_t nDot = str.find('.');
    while (str.size() > nDot + 3 && str[str.size()-1] == '0')
        str.erase(str.size()-1);
    return str;
}

string DescribeScript(const CScript& scriptPubKey)
{
    if (scriptPubKey.IsPayToScriptHash())
        return Hash160ToScriptAddress(uint160(vector<unsigned char>(scriptPubKey.begin()+2, scriptPubKey.begin()+22)));
    uint160 hash160;
    if (ExtractHash160(scriptPubKey, hash160))
        return Hash160ToAddress(hash160);
    // Coinbase outputs pay to a bare public key, so the address is the key's.
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(scriptPubKey, false, vchPubKey))
        return PubKeyToAddress(vchPubKey);
    if (!scriptPubKey.empty() && scriptPubKey[0] == OP_RETURN)
        return "data";
    if (!scriptPubKey.empty() && scriptPubKey[scriptPubKey.size()-1] == OP_CHECKMULTISIG)
        return "multisig";
    return "script";
}

// The caller holds cs_main.
static CBlockIndex* MainChainAt(int nHeight)
{
    if (nHeight < 0 || nHeight > nBestHeight)
        return NULL;
    CBlockIndex* pindex = pindexBest;
    while (pindex && pindex->nHeight > nHeight)
        pindex = pindex->pprev;
    return pindex;
}

static bool InMempool(const uint256& hash, CTransaction* ptx=NULL)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        map<uint256, CTransaction>::iterator mi = mapTransactions.find(hash);
        if (mi == mapTransactions.end())
            return false;
        if (ptx)
            *ptx = mi->second;
        return true;
    }
    return false;
}

// The genesis block was never connected, so its coinbase is in no index. The
// caller holds cs_main.
static bool IsGenesisCoinbase(const uint256& txid, CTransaction& txRet)
{
    CBlock block;
    if (!pindexGenesisBlock || !block.ReadFromDisk(pindexGenesisBlock, true) || block.vtx.empty() ||
        block.vtx[0].GetHash() != txid)
        return false;
    txRet = block.vtx[0];
    return true;
}

// A window may be reading when the node stops, with the databases closing: each
// read looks at fShutdown once it has the lock.
Result Find(const string& strQuery, uint256& hashRet)
{
    size_t nBegin = strQuery.find_first_not_of(" \t\r\n");
    if (nBegin == string::npos)
        return BAD_QUERY;
    string str = strQuery.substr(nBegin, strQuery.find_last_not_of(" \t\r\n") - nBegin + 1);
    bool fHeight = str.size() <= 9 && str.find_first_not_of("0123456789") == string::npos;
    if (!fHeight && !(str.size() == 64 && IsHex(str)))
        return BAD_QUERY;
    CRITICAL_BLOCK(cs_main)
    {
        if (fShutdown)
            return NOT_FOUND;
        if (fHeight)
        {
            CBlockIndex* pindex = MainChainAt(atoi(str.c_str()));
            if (!pindex)
                return NOT_FOUND;
            hashRet = pindex->GetBlockHash();
            return IS_BLOCK;
        }
        hashRet.SetHex(str);
        if (mapBlockIndex.count(hashRet))
            return IS_BLOCK;
        CTxIndex txindex;
        CTransaction tx;
        if (InMempool(hashRet) || CTxDB("r").ReadTxIndex(hashRet, txindex) || IsGenesisCoinbase(hashRet, tx))
            return IS_TX;
        return NOT_FOUND;
    }
    return NOT_FOUND;
}

Result Recent(int nTop, int nCount, vector<BlockRow>& rowsRet, int& nTipRet)
{
    CRITICAL_BLOCK(cs_main)
    {
        if (fShutdown)
            return NOT_FOUND;
        rowsRet.clear();
        nTipRet = nBestHeight;
        CBlockIndex* pindex = nTop < 0 ? pindexBest : MainChainAt(nTop);
        for (; pindex && (int)rowsRet.size() < nCount; pindex = pindex->pprev)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex, true))
                return NOT_FOUND;
            BlockRow row;
            row.height = pindex->nHeight;
            row.hash = pindex->GetBlockHash();
            row.time = block.nTime;
            row.nTx = block.vtx.size();
            row.nSize = ::GetSerializeSize(block, SER_NETWORK);
            row.reward = block.vtx.empty() ? 0 : block.vtx[0].GetValueOut();
            if (!block.vtx.empty() && !block.vtx[0].vout.empty())
                row.to = DescribeScript(block.vtx[0].vout[0].scriptPubKey);
            rowsRet.push_back(row);
        }
        return FOUND;
    }
    return NOT_FOUND;
}

Result ReadBlock(const uint256& hash, BlockView& viewRet)
{
    CRITICAL_BLOCK(cs_main)
    {
        if (fShutdown)
            return NOT_FOUND;
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi == mapBlockIndex.end())
            return NOT_FOUND;
        CBlockIndex* pindex = mi->second;
        CBlock block;
        if (!block.ReadFromDisk(pindex, true))
            return NOT_FOUND;
        viewRet.height = pindex->nHeight;
        viewRet.hash = hash;
        viewRet.prev = block.hashPrevBlock;
        viewRet.next = pindex->pnext ? pindex->pnext->GetBlockHash() : uint256(0);
        viewRet.merkleRoot = block.hashMerkleRoot;
        viewRet.nVersion = block.nVersion;
        viewRet.time = block.nTime;
        viewRet.nBits = block.nBits;
        viewRet.nNonce = block.nNonce;
        viewRet.nSize = ::GetSerializeSize(block, SER_NETWORK);
        viewRet.fMainChain = pindex->IsInMainChain();
        viewRet.txs.clear();
        foreach(const CTransaction& tx, block.vtx)
        {
            TxRow row;
            row.txid = tx.GetHash();
            row.fCoinBase = tx.IsCoinBase();
            row.nIn = tx.vin.size();
            row.nOut = tx.vout.size();
            row.value = tx.GetValueOut();
            viewRet.txs.push_back(row);
        }
        return FOUND;
    }
    return NOT_FOUND;
}

Result ReadTx(const uint256& txid, TxView& viewRet)
{
    CRITICAL_BLOCK(cs_main)
    {
        if (fShutdown)
            return NOT_FOUND;
        CTxDB txdb("r");
        CTransaction tx;
        CTxIndex txindex;
        bool fIndexed = txdb.ReadTxIndex(txid, txindex) && tx.ReadFromDisk(txindex.pos);
        bool fGenesis = !fIndexed && IsGenesisCoinbase(txid, tx);
        if (!fIndexed && !fGenesis && !InMempool(txid, &tx))
            return NOT_FOUND;
        viewRet.fInChain = fIndexed || fGenesis;

        viewRet.txid = txid;
        viewRet.fCoinBase = tx.IsCoinBase();
        viewRet.nSize = ::GetSerializeSize(tx, SER_NETWORK);
        viewRet.height = -1;
        viewRet.nConfirmations = 0;
        viewRet.block = 0;
        viewRet.time = 0;
        if (viewRet.fInChain)
        {
            CBlock block;
            if (!(fGenesis ? block.ReadFromDisk(pindexGenesisBlock, false)
                           : block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false)))
                return NOT_FOUND;
            viewRet.block = block.GetHash();
            viewRet.time = block.nTime;
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(viewRet.block);
            if (mi != mapBlockIndex.end())
            {
                viewRet.height = mi->second->nHeight;
                viewRet.nConfirmations = nBestHeight - mi->second->nHeight + 1;
            }
        }

        viewRet.in.clear();
        int64 nValueIn = 0;
        viewRet.fFeeKnown = !viewRet.fCoinBase && tx.vin.size() <= MAX_INPUTS_READ;
        if (!viewRet.fCoinBase)
            foreach(const CTxIn& txin, tx.vin)
            {
                Input in;
                in.prev = txin.prevout.hash;
                in.n = txin.prevout.n;
                in.fKnown = false;
                in.value = 0;
                CTransaction txPrev;
                if (tx.vin.size() <= MAX_INPUTS_READ &&
                    (txdb.ReadDiskTx(txin.prevout.hash, txPrev) || InMempool(txin.prevout.hash, &txPrev)) &&
                    txin.prevout.n < txPrev.vout.size())
                {
                    in.fKnown = true;
                    in.value = txPrev.vout[txin.prevout.n].nValue;
                    in.from = DescribeScript(txPrev.vout[txin.prevout.n].scriptPubKey);
                    nValueIn += in.value;
                }
                else
                    viewRet.fFeeKnown = false;
                viewRet.in.push_back(in);
            }
        viewRet.fee = viewRet.fFeeKnown ? nValueIn - tx.GetValueOut() : 0;

        viewRet.out.clear();
        for (unsigned int i = 0; i < tx.vout.size(); i++)
        {
            Output out;
            out.value = tx.vout[i].nValue;
            out.to = DescribeScript(tx.vout[i].scriptPubKey);
            out.spentBy = 0;
            // The index keeps where each output was spent, which is what lets a
            // reader walk from a swap's contract to the transaction that took it.
            CTransaction txSpend;
            if (viewRet.fInChain && i < txindex.vSpent.size() && !txindex.vSpent[i].IsNull() &&
                txSpend.ReadFromDisk(txindex.vSpent[i]))
                out.spentBy = txSpend.GetHash();
            viewRet.out.push_back(out);
        }
        return FOUND;
    }
    return NOT_FOUND;
}

}
