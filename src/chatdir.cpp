// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See chatdir.h.

#include "headers.h"
#include "chatdir.h"
#include "community.h"

static CCriticalSection cs_chatdir;
static std::vector<CChatListing> g_listings;
static int g_nScanned = -1;          // last block height read
static bool g_fLoaded = false;

class CChatDirectoryFile
{
public:
    int nHeight;
    std::vector<CChatListing> v;
    CChatDirectoryFile() : nHeight(-1) {}
    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(v);
    )
};

static std::string DirPath()
{
    return GetAppDir() + "/chat-directory.dat";
}

static void Load()
{
    if (g_fLoaded)
        return;
    g_fLoaded = true;
    FILE* f = fopen(DirPath().c_str(), "rb");
    if (!f)
        return;
    std::vector<char> buf;
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0 && buf.size() < 8 * 1024 * 1024)
        buf.insert(buf.end(), tmp, tmp + n);
    fclose(f);
    try
    {
        CDataStream ss(buf, SER_DISK);
        CChatDirectoryFile d;
        ss >> d;
        g_nScanned = d.nHeight;
        g_listings = d.v;
    }
    catch (std::exception&)
    {
        // A damaged file is read again from the chain, which is the truth.
        g_nScanned = -1;
        g_listings.clear();
    }
}

static void Save()
{
    CChatDirectoryFile d;
    d.nHeight = g_nScanned;
    d.v = g_listings;
    CDataStream ss(SER_DISK);
    ss << d;
    std::string tmpPath = DirPath() + ".new";
    FILE* f = fopen(tmpPath.c_str(), "wb");
    if (!f)
        return;
    fwrite(&ss.begin()[0], 1, ss.size(), f);
    fclose(f);
    remove(DirPath().c_str());
    rename(tmpPath.c_str(), DirPath().c_str());
}

// Add a listing unless its key is already there. True when new.
static bool Add(const CChatListing& c)
{
    for (size_t i = 0; i < g_listings.size(); i++)
        if (g_listings[i].key == c.key)
            return false;
    if (g_listings.size() >= 100000)
        return false;
    g_listings.push_back(c);
    return true;
}

int ChatDirectoryScanBlock(const CBlock& block, int nHeight)
{
    int nNew = 0;
    for (size_t t = 0; t < block.vtx.size(); t++)
        for (size_t o = 0; o < block.vtx[t].vout.size(); o++)
        {
            const CTxOut& out = block.vtx[t].vout[o];
            if (out.nValue < community::MIN_BURN)
                continue;
            std::vector<unsigned char> s(out.scriptPubKey.begin(), out.scriptPubKey.end());
            unsigned char key[community::KEY_BYTES];
            std::string name;
            if (!community::ParseListing(s, key, name))
                continue;
            CChatListing c;
            c.key.assign(key, key + community::KEY_BYTES);
            c.name = name;
            c.nHeight = nHeight;
            c.nTime = block.nTime;
            c.nBurn = out.nValue;
            c.txid = block.vtx[t].GetHash();
            CRITICAL_BLOCK(cs_chatdir)
                if (Add(c))
                {
                    nNew++;
                    printf("chat directory: #%s listed in block %d\n", name.c_str(), nHeight);
                }
        }
    return nNew;
}

// One pass: up to 2000 blocks from where the last one stopped.
static void CatchUp()
{
    std::vector<CBlockIndex*> todo;
    CRITICAL_BLOCK(cs_chatdir)
        Load();
    int nFrom = 0;
    CRITICAL_BLOCK(cs_chatdir)
        nFrom = g_nScanned + 1;
    CRITICAL_BLOCK(cs_main)
    {
        if (!pindexBest || nFrom > nBestHeight)
            return;
        int nTo = std::min(nBestHeight, nFrom + 2000 - 1);
        CBlockIndex* p = pindexBest;
        while (p && p->nHeight > nTo)
            p = p->pprev;
        while (p && p->nHeight >= nFrom)
        {
            todo.push_back(p);
            p = p->pprev;
        }
    }
    bool fChanged = false;
    for (size_t i = todo.size(); i-- > 0 && !fShutdown; )
    {
        CBlock block;
        if (!block.ReadFromDisk(todo[i], true))
            break;
        if (ChatDirectoryScanBlock(block, todo[i]->nHeight) > 0)
            fChanged = true;
        CRITICAL_BLOCK(cs_chatdir)
            g_nScanned = todo[i]->nHeight;
        fChanged = fChanged || (i == 0);
    }
    if (fChanged)
        CRITICAL_BLOCK(cs_chatdir)
            Save();
}

void ThreadChatDirectory(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatDirectory(parg));
    try
    {
        // Wait out the start: the block index has to be loaded before there is
        // a chain to read.
        for (int i = 0; i < 30 && !fShutdown; i++)
            Sleep(1000);
        while (!fShutdown)
        {
            CatchUp();
            for (int i = 0; i < 30 && !fShutdown; i++)
                Sleep(1000);
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatDirectory()"); }
    catch (...)               { PrintException(NULL, "ThreadChatDirectory()"); }
}

void ChatDirectoryListings(std::vector<CChatListing>& out)
{
    CRITICAL_BLOCK(cs_chatdir)
    {
        Load();
        out = g_listings;
    }
}

int ChatDirectoryHeight()
{
    CRITICAL_BLOCK(cs_chatdir)
    {
        Load();
        return g_nScanned;
    }
    return -1;
}
