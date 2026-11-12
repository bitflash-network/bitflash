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

// LeakSanitizer, for every harness that links the node.
//
// The Berkeley DB environment is opened once and stays open for the whole
// run, as in a node. The allocations libdb makes for it when it opens
// (DbEnv::open -> __env_open -> __memp_open / __lock_open -> __env_alloc ->
// __os_malloc) are reached from the environment's regions through offsets,
// not pointers, so a heap scan never finds them and reads them as leaked.
// libFuzzer scans the heap after any input that left more blocks allocated
// than it found, so they turn up at some input that has nothing to do with
// them: in November 2026 a 5.5-hour single-process run of fuzz-net-message
// (22.7 M inputs, the environment opened once) stopped on exactly these two
// blocks, 136 bytes. The 711 leak reports of the fork-mode campaign before
// it, whose stacks fork mode does not keep, behaved the same way: none of
// their inputs reproduces a leak on its own. Only allocations made inside
// libdb are suppressed; a Berkeley DB handle the node itself leaks is
// allocated from node code and is still reported (that is how the CDB open
// leak was found).
extern "C" const char* __lsan_default_suppressions()
{
    return "leak:__os_malloc\n";
}

// What a node builds for its whole run (block index entries, orphan blocks
// and transactions, address and inventory maps) sits in global maps that are
// destroyed before the final leak check, as in the node, which never frees
// them either. So no leak check at exit; libFuzzer still checks after every
// input that changed the heap, which is where a leak an input causes shows up.
extern "C" const char* __asan_default_options()
{
    return "leak_check_at_exit=0";
}

#endif
