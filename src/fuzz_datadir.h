// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Included once by each fuzz harness that links the node. Without it the node
// code resolves its data directory the usual way, $HOME/.bitflash, and a
// harness run on a machine that also runs a node opens that node's Berkeley DB
// environment and writes to its logs. Every engine (libFuzzer, AFL++,
// honggfuzz) calls LLVMFuzzerInitialize once before the first input, so the
// node sees a fresh, empty directory of its own instead. It is left behind in
// the temporary directory for inspection; it holds only what the inputs made.

#ifndef BITFLASH_FUZZ_DATADIR_H
#define BITFLASH_FUZZ_DATADIR_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    const char* pszTmp = getenv("TMPDIR");
    std::string strTemplate = std::string(pszTmp && *pszTmp ? pszTmp : "/tmp") + "/bitflash-fuzz-XXXXXX";
    std::vector<char> buf(strTemplate.begin(), strTemplate.end());
    buf.push_back('\0');
    if (mkdtemp(&buf[0]) == NULL)
    {
        perror("fuzz: mkdtemp");
        abort();   // never fall back to the real data directory
    }
    strSetDataDir = &buf[0];
#ifdef BITFLASH_FUZZ_INIT_EXTRA
    // A harness that needs node state (a block index, say) sets this up once
    // the data directory is in place.
    BITFLASH_FUZZ_INIT_EXTRA();
#endif
    return 0;
}

#endif
