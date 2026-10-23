// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The Dandelion++ router: relays per epoch, fixed routes, never back to the
// sender, one hop in ten fluffing.

#include "dandelion.h"

#include <stdio.h>
#include <set>

using namespace dandelion;

static int nFail = 0;

static void Check(bool f, const char* what)
{
    printf("  %s %s\n", f ? "ok  " : "FAIL", what);
    if (!f)
        nFail++;
}

int main()
{
    printf("dandelion router tests\n");

    Router r;
    Check(r.EpochOver(1000), "a router that never started has its epoch over");

    std::vector<uint64_t> cand;
    cand.push_back(11); cand.push_back(22); cand.push_back(33);
    std::vector<uint64_t> rnd;
    rnd.push_back(4); rnd.push_back(9);
    r.NewEpoch(1000, cand, rnd);
    std::set<uint64_t> relays(r.Relays().begin(), r.Relays().end());
    Check(r.Relays().size() == RELAYS_PER_EPOCH && relays.size() == RELAYS_PER_EPOCH,
          "an epoch picks two distinct relays out of three candidates");
    Check(!r.EpochOver(1000 + EPOCH_SECONDS - 1) && r.EpochOver(1000 + EPOCH_SECONDS),
          "an epoch lasts ten minutes");

    // Same route for the whole epoch, whatever randomness comes later.
    uint64_t first = r.RelayFor(77, 0);
    bool fFixed = relays.count(first) == 1;
    for (uint64_t i = 1; i < 50; i++)
        fFixed = fFixed && r.RelayFor(77, i) == first;
    Check(fFixed, "everything from one neighbour leaves through the same relay all epoch");

    // Our own transactions (from 0) have a fixed route too.
    uint64_t own = r.RelayFor(0, 1);
    Check(relays.count(own) == 1 && r.RelayFor(0, 0) == own, "our own transactions take one fixed relay");

    // Never back to the sender.
    Router two;
    std::vector<uint64_t> c2;
    c2.push_back(5); c2.push_back(7);
    two.NewEpoch(1, c2, std::vector<uint64_t>(2, 0));
    bool fNeverBack = true;
    for (uint64_t i = 0; i < 20; i++)
    {
        Router t = two;
        fNeverBack = fNeverBack && t.RelayFor(5, i) == 7 && t.RelayFor(7, i) == 5;
    }
    Check(fNeverBack, "a stem never goes back to the peer that sent it");

    Router one;
    one.NewEpoch(1, std::vector<uint64_t>(1, 5), std::vector<uint64_t>(1, 0));
    Check(one.RelayFor(5, 3) == 0, "with the sender as the only relay there is none: it fluffs");

    Router none;
    none.NewEpoch(1, std::vector<uint64_t>(), std::vector<uint64_t>());
    Check(none.Relays().empty() && none.RelayFor(0, 1) == 0,
          "with no peer that takes stems, our own transaction fluffs at once");

    // A new epoch forgets the routes.
    Router re = two;
    re.RelayFor(99, 0);
    std::vector<uint64_t> c3(1, 42);
    re.NewEpoch(5000, c3, std::vector<uint64_t>(1, 0));
    Check(re.RelayFor(99, 1) == 42, "a new epoch draws new routes");

    int nFluff = 0;
    for (unsigned int i = 0; i < 100; i++)
        nFluff += Router::Fluff(i) ? 1 : 0;
    Check(nFluff == FLUFF_PERCENT, "one hop in ten fluffs");

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    return nFail ? 1 : 0;
}
