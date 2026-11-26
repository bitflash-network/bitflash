// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The scale case of the attack harness: see selftest_attack.inc.

// ---- attack-scale: share size, lines, the guard budget at its limits -------
//
// SPEC sections 11 and 12 and PROOFS claim 4. Part A: every payout script in
// a pool's window is an output of every share's coinbase, so a share grows
// with the number of distinct miners in the window; what a share, a line and
// the relay cost for 10 to 2000 distinct miners, and where the line stops
// fitting in the 64 MB a guardian gives one pool. Part B: 200 pools with 2000
// miners spread unevenly (a Zipf law), announced by peers, against the
// draw and the guard budget of one node: more pools than places.

static const unsigned int GUARD_MAX_PULLS_FOR_TEST = 4;   // GUARD_MAX_PULLS in p2pool_net.cpp

static int RunAttackScaleSelfTest()
{
    printf("attack-scale\n");
    AtkDir dir;
    if (!dir.fOk)
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    int nFail = 0;
    auto ok = [&nFail](bool f, const char* psz) { if (!Check(f, psz)) nFail++; };
    string err;
    TestMainView main = AtkMain();
    CBigNum bnFloor;
    bnFloor.SetCompact(0x207fffff);
    const unsigned char* magic = (const unsigned char*)pchMessageStart;

    // ---- Part A
    {
        printf("  A. one pool, spacing 20 s, N distinct miners in the window; the node mines it and relays to 8 peers\n");
        printf("     %6s %7s %7s %11s %11s %10s %12s %12s %10s\n", "miners", "window", "shares", "bytes/share", "line (MB)",
               "fits 64MB", "node us/shr", "relay B/hour", "RSS (MB)");
        const unsigned int vN[] = { 10, 50, 100, 200, 340, 720, 1000, 2000 };
        for (size_t iN = 0; iN < sizeof(vN) / sizeof(vN[0]); iN++)
        {
            const unsigned int nMiners = vN[iN];
            const unsigned int nWindow = nMiners <= 720 ? 720 : 2160;
            P2PoolResetForTest(bnFloor, false);
            PoolBurnsOpenForTest(true);
            AtkPool A;
            A.rec = AtkRecord(strprintf("atk-scale-%u", nMiners), nWindow, 720);
            A.rec.nSpacing = 20;
            A.rec.nUncleDepth = 3;
            p2pool::RulesForRegistered(A.rec, magic, A.rules, err);
            A.id = A.rules.poolId;
            std::vector<CNode*> vFree;
            P2PoolRegAddForTest(A.rec, true, false, false, err);
            std::vector<CNode*> vPeer;
            for (int i = 0; i < 8; i++)
            {
                CNode* p = NewRegTestNode(false, strprintf("BF1atk-scale-peer%d", i).c_str());
                vFree.push_back(p);
                vPeer.push_back(p);
                P2PoolOnVersion(p);
            }
            P2PoolRegTickForTest();
            P2PoolRegAgeForTest(121);
            P2PoolRegTickForTest();
            for (int i = 0; i < 8; i++)
                SendPoolInv(vPeer[i], std::vector<uint256>(1, A.id));
            P2PoolRegTickForTest();

            p2pool::ShareChain mirror(A.rules, false);
            const unsigned int nShares = A.rules.HistoryShares();
            uint256 prev = 0;
            const unsigned int t0 = (unsigned int)main.nNow - 20 * (nShares + 1);
            double dCpu = 0;
            uint64 nRelayBytes = 0, nShareBytes = 0;
            for (unsigned int i = 0; i < nShares; i++)
            {
                // Uneven: a Zipf draw over the miners, so the window holds as
                // many distinct ones as it holds.
                const unsigned int iM = i < nMiners ? i : (unsigned int)(nMiners * pow((double)((i * 2654435761u) % 1000003) / 1000003.0, 2.0));
                p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo(iM % nMiners), t0 + 20 * i);
                mirror.Add(s, main, err);
                nShareBytes += ::GetSerializeSize(p2pool::ShareX(s), SER_NETWORK);
                AtkMeter m;
                bool f = P2PoolSubmitShare(s, err);
                dCpu += m.Cpu();
                if (!f)
                {
                    printf("     share %u refused: %s\n", i, err.c_str());
                    break;
                }
                prev = s.GetId();
                for (int k = 0; k < 8; k++)
                {
                    nRelayBytes += vPeer[k]->vSend.size();
                    vPeer[k]->vSend.clear();
                }
            }
            P2PoolRegStatusInfo st;
            P2PoolRegStatus(A.id, st);
            const double dAvg = (double)nShareBytes / nShares;
            const double dLineMB = st.nBytes / 1e6;
            // A share every 20 s on average, to the 8 peers that announced.
            const double dRelayHour = (nRelayBytes / (double)nShares) * (3600.0 / 20.0);
            printf("     %6u %7u %7u %11.0f %11.2f %10s %12.0f %12.0f %10ld\n", nMiners, nWindow, (unsigned)st.nShares, dAvg,
                   dLineMB, st.nBytes <= (size_t)GUARD_MAX_POOL_BYTES ? "yes" : "NO", 1e6 * dCpu / nShares, dRelayHour,
                   AtkProcKB("VmRSS:") / 1024);
            if (nMiners <= 100)
                ok(st.nBytes <= (size_t)GUARD_MAX_POOL_BYTES, "a pool with up to 100 miners in its window fits in what a guardian gives one pool");
            AtkFree(vFree);
        }
    }

    // ---- Part B
    {
        const unsigned int nPools = AtkEnv("ATTACK_POOLS_SCALE", 200);
        const unsigned int nMinersTotal = AtkEnv("ATTACK_MINERS_SCALE", 2000);
        const unsigned int nAnnouncers = (nPools + 27) / 28;
        printf("  B. %u pools, %u miners spread by a Zipf law, window 360, announced by %u peers, against one node's draw and guard budget\n",
               nPools, nMinersTotal, nAnnouncers);
        P2PoolResetForTest(bnFloor, false);
        PoolBurnsOpenForTest(true);
        CTicketParams params = CTicketParams::Network();
        params.fnWork = TicketTestWork;
        TicketTestView w;
        w.Grow(3700, 0);
        const uint256 seed5 = w.v[2880], seed6 = w.v[3600];
        unsigned char skOwn[32];
        TicketTestKey(400, skOwn);
        P2PoolTicketParamsForTest(params);
        P2PoolTicketViewForTest(w.v);
        P2PoolTicketKeyForTest(skOwn);
        std::vector<CNode*> vFree;
        CNode* pH = NewRegTestNode(false, "BF1atk-scale-honest");
        vFree.push_back(pH);
        P2PoolOnVersion(pH);
        std::vector<CNode*> vAnn;
        for (unsigned int i = 0; i < nAnnouncers; i++)
        {
            CNode* p = NewRegTestNode(false, strprintf("BF1atk-scale-ann%u", i).c_str());
            vFree.push_back(p);
            vAnn.push_back(p);
            P2PoolOnVersion(p);
        }
        P2PoolRegTickForTest();
        const unsigned int nHonest = 24;
        std::vector<CHeldTicket> t5 = GuardMake(params, seed5, 5, 1, nHonest);
        std::vector<CHeldTicket> t6 = GuardMake(params, seed6, 6, 1, nHonest);
        P2PoolTicketBudgetForTest(100000);
        GuardSendTickets(pH, 5, seed5, GuardBodies(t5, 0, t5.size()));
        GuardSendTickets(pH, 6, seed6, GuardBodies(t6, 0, t6.size()));
        for (int i = 0; i < 10; i++)
            P2PoolTicketStepForTest(512, false);
        CGuardTicket o5, o6;
        for (int i = 0; i < 20000 && !(P2PoolTicketOwnForTest(5, o5) && P2PoolTicketOwnForTest(6, o6)); i++)
            P2PoolTicketStepForTest(0, true);

        // The pools and their lines.
        double dWeights = 0;
        for (unsigned int i = 0; i < nPools; i++)
            dWeights += 1.0 / (i + 1);
        std::vector<CPoolInfo> vPools;
        std::map<uint256, std::vector<p2pool::Share> > mapLine;
        std::map<uint256, unsigned int> mapMiners;
        unsigned int nMinerSum = 0;
        uint64 nLineBytes = 0;
        AtkMeter mb;
        for (unsigned int i = 0; i < nPools; i++)
        {
            unsigned int nM = (unsigned int)(nMinersTotal / (dWeights * (i + 1)) + 0.5);
            if (nM < 1) nM = 1;
            if (nM > 360) nM = 360;
            nMinerSum += nM;
            poolreg::PoolRecord rec = AtkRecord(strprintf("atk-scale-b-%u", i), 360, 120);
            rec.nSpacing = 20;
            rec.nUncleDepth = 3;
            CPoolInfo info = GuardInfo(rec);
            p2pool::PoolRules rules;
            p2pool::RulesForRegistered(rec, magic, rules, err);
            p2pool::ShareChain mirror(rules, false);
            const unsigned int n = rules.HistoryShares();
            const unsigned int t0 = (unsigned int)main.nNow - 20 * (n + 1);
            std::vector<p2pool::Share> line;
            uint256 prev = 0;
            for (unsigned int k = 0; k < n; k++)
            {
                p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo((i * 977 + k % nM) % 100000), t0 + 20 * k);
                mirror.Add(s, main, err);
                prev = s.GetId();
                nLineBytes += ::GetSerializeSize(p2pool::ShareX(s), SER_NETWORK);
                line.push_back(s);
            }
            mapLine[info.id] = line;
            mapMiners[info.id] = nM;
            vPools.push_back(info);
        }
        printf("     built %u pools with %u miners in all (largest pool %u miners, smallest %u), %.1f MB of lines in all; %.1f s CPU, RSS %ld MB\n",
               nPools, nMinerSum, mapMiners[vPools[0].id], mapMiners[vPools[nPools - 1].id], nLineBytes / 1e6, mb.Cpu(),
               AtkProcKB("VmRSS:") / 1024);

        P2PoolTicketPoolsForTest(vPools);
        for (unsigned int i = 0; i < nPools; i++)
        {
            // each announcer names up to 28 pools
        }
        for (unsigned int a = 0; a < nAnnouncers; a++)
        {
            std::vector<uint256> v;
            for (unsigned int i = a; i < nPools; i += nAnnouncers)
                v.push_back(vPools[i].id);
            SendPoolInv(vAnn[a], v);
        }
        AtkMeter mDraw;
        GuardDrawAndApply();
        const double dDraw = mDraw.Cpu();
        std::set<std::pair<CNode*, uint256> > setAnswered;
        unsigned int nRounds = 0;
        AtkMeter mPull;
        for (; nRounds < 400; nRounds++)
        {
            bool fAny = false;
            for (unsigned int a = 0; a < nAnnouncers; a++)
                foreach(const SentMessage& m, SentTo(vAnn[a]))
                {
                    if (m.strCommand != "p2xsync" || m.payload.size() != 64)
                        continue;
                    uint256 id;
                    memcpy(id.begin(), &m.payload[0], 32);
                    if (setAnswered.count(std::make_pair(vAnn[a], id)) || !mapLine.count(id))
                        continue;
                    setAnswered.insert(std::make_pair(vAnn[a], id));
                    const std::vector<p2pool::Share>& line = mapLine[id];
                    for (size_t i = 0; i < line.size(); i += 100)
                    {
                        std::vector<p2pool::Share> part(line.begin() + i, line.begin() + std::min(line.size(), i + 100));
                        SendRegPart(vAnn[a], id, (int)line.size() - 1, i + 100 >= line.size() ? 1 : 0, part);
                    }
                    fAny = true;
                }
            P2PoolRegAgeForTest(301);
            P2PoolRegTickForTest();
            P2PoolRegAgeForTest(61);
            P2PoolRegTickForTest();
            if (!fAny && nRounds > 6)
                break;
        }
        std::vector<P2PoolGuardEntryInfo> vE = GuardEntries();
        unsigned int nKeep = 0, nNoRoom = 0, nPull = 0, nEmpty = 0, nNot = 0, nDrawn = 0;
        uint64 nGuardBytes = 0, nKeptBytes = 0;
        for (size_t i = 0; i < vE.size(); i++)
        {
            nDrawn++;
            if (vE[i].nChoice == GUARD_KEEP) nKeep++;
            else if (vE[i].nChoice == GUARD_NO_ROOM) nNoRoom++;
            else if (vE[i].nChoice == GUARD_PULL) nPull++;
            else if (vE[i].nChoice == GUARD_EMPTY) nEmpty++;
            else nNot++;
        }
        unsigned int nHeld = 0, nAnnounced = 0;
        for (unsigned int i = 0; i < nPools; i++)
        {
            P2PoolRegStatusInfo st;
            if (P2PoolRegStatus(vPools[i].id, st) && st.fGuard && st.nShares > 0)
            {
                nHeld++;
                nGuardBytes += st.nBytes;
                if (st.fAnnounced)
                {
                    nAnnounced++;
                    nKeptBytes += st.nBytes;
                }
            }
        }
        printf("     draw of %u pools over %u tickets: %.2f s CPU; %u rounds of pulling (%.1f s CPU): %u pools drawn for this node: "
               "%u kept, %u no room, %u still to pull, %u empty; guarded and announced (kept): %u (of %u with a line in memory, the rest being pulls to learn their work, at most %u at once), %.1f MB in all, %.1f MB of it kept (budget "
               "%u pools, %.0f MB, %.0f MB a pool); RSS %ld MB, peak %ld MB\n",
               nPools, (unsigned)(nHonest + 1), dDraw, nRounds, mPull.Cpu(), nDrawn, nKeep, nNoRoom, nPull, nEmpty, nAnnounced,
               nHeld, (unsigned)GUARD_MAX_PULLS_FOR_TEST, nGuardBytes / 1e6, nKeptBytes / 1e6, GUARD_MAX_POOLS, GUARD_DEFAULT_BYTES / 1e6, GUARD_MAX_POOL_BYTES / 1e6,
               AtkProcKB("VmRSS:") / 1024, AtkProcKB("VmHWM:") / 1024);
        ok(nAnnounced <= GUARD_MAX_POOLS && nKeptBytes <= (uint64)GUARD_DEFAULT_BYTES && nHeld <= GUARD_MAX_POOLS + GUARD_MAX_PULLS_FOR_TEST,
           "never more than 8 pools with shares guarded, and never past the byte budget, whatever the number of pools drawn");
        ok(nKeep <= GUARD_MAX_POOLS, "kept pools within the pool budget");

        // The same draw over a full set of 4096 tickets.
        {
            std::vector<CHeldTicket> vBig = GuardMake(params, seed6, 6, 1000, GUARD_MAX_TICKETS);
            P2PoolTicketBudgetForTest(1000000);
            for (size_t i = 0; i < vBig.size(); i += 512)
            {
                GuardSendTickets(pH, 6, seed6, GuardBodies(vBig, i, std::min(vBig.size(), i + 512)));
                AtkDrainTickets();
            }
            w.Grow(4300, 0);
            P2PoolTicketViewForTest(w.v);
            AtkMeter m;
            GuardDrawAndApply();
            printf("     a draw of %u pools over a full set (%u held for epoch 6): %.2f s CPU (made at most every 30 s, and 10 minutes when nothing changed)\n",
                   nPools, (unsigned)P2PoolTicketHeldForTest(6), m.Cpu());
            ok(P2PoolTicketHeldForTest(6) >= GUARD_MAX_TICKETS - 1, "the set is at its cap of 4096");
        }
        AtkFree(vFree);
    }

    // ---- Part C: the byte budget at its limits. Ten pools whose lines are
    // about 22 MB each (720 distinct miners in a window of 720), more than
    // the 134 MB budget holds, and one of about 79 MB, past the 64 MB a
    // guardian gives one pool. The node is drawn for all of them (a small
    // network: 25 tickets for 16 places).
    {
        const unsigned int nFat = AtkEnv("ATTACK_FAT_POOLS", 10);
        printf("  C. byte budget: %u pools of about 22 MB and one of about 79 MB, one node drawn for all\n", nFat);
        P2PoolResetForTest(bnFloor, false);
        PoolBurnsOpenForTest(true);
        CTicketParams params = CTicketParams::Network();
        params.fnWork = TicketTestWork;
        TicketTestView w;
        w.Grow(3700, 0);
        const uint256 seed5 = w.v[2880], seed6 = w.v[3600];
        unsigned char skOwn[32];
        TicketTestKey(400, skOwn);
        P2PoolTicketParamsForTest(params);
        P2PoolTicketViewForTest(w.v);
        P2PoolTicketKeyForTest(skOwn);
        std::vector<CNode*> vFree;
        CNode* pH = NewRegTestNode(false, "BF1atk-fat-honest");
        CNode* pA = NewRegTestNode(false, "BF1atk-fat-announcer");
        vFree.push_back(pH);
        vFree.push_back(pA);
        P2PoolOnVersion(pH);
        P2PoolOnVersion(pA);
        P2PoolRegTickForTest();
        std::vector<CHeldTicket> t5 = GuardMake(params, seed5, 5, 1, 12);
        std::vector<CHeldTicket> t6 = GuardMake(params, seed6, 6, 1, 12);
        GuardSendTickets(pH, 5, seed5, GuardBodies(t5, 0, t5.size()));
        AtkDrainTickets();
        GuardSendTickets(pH, 6, seed6, GuardBodies(t6, 0, t6.size()));
        AtkDrainTickets();
        CGuardTicket o5, o6;
        for (int i = 0; i < 20000 && !(P2PoolTicketOwnForTest(5, o5) && P2PoolTicketOwnForTest(6, o6)); i++)
            P2PoolTicketStepForTest(0, true);
        std::vector<CPoolInfo> vPools;
        std::map<uint256, std::vector<p2pool::Share> > mapLine;
        std::vector<uint256> vIds;
        uint64 nLineBytes = 0;
        for (unsigned int i = 0; i <= nFat; i++)
        {
            const bool fHuge = i == nFat;
            const unsigned int nM = fHuge ? 1000 : 720, nWin = fHuge ? 2160 : 720;
            poolreg::PoolRecord rec = AtkRecord(strprintf("atk-fat-%u", i), nWin, 720);
            rec.nSpacing = 20;
            rec.nUncleDepth = 3;
            CPoolInfo info = GuardInfo(rec);
            p2pool::PoolRules rules;
            p2pool::RulesForRegistered(rec, magic, rules, err);
            p2pool::ShareChain mirror(rules, false);
            const unsigned int n = rules.HistoryShares();
            const unsigned int t0 = (unsigned int)main.nNow - 20 * (n + 1);
            uint256 prev = 0;
            uint64 nB = 0;
            std::vector<p2pool::Share> line;
            for (unsigned int k = 0; k < n; k++)
            {
                p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo((i * 977 + k) % nM), t0 + 20 * k);
                mirror.Add(s, main, err);
                prev = s.GetId();
                nB += ::GetSerializeSize(p2pool::ShareX(s), SER_NETWORK);
                line.push_back(s);
            }
            nLineBytes += nB;
            mapLine[info.id] = line;
            vIds.push_back(info.id);
            vPools.push_back(info);
        }
        const long nRss0 = AtkProcKB("VmRSS:") / 1024;
        P2PoolTicketPoolsForTest(vPools);
        SendPoolInv(pA, vIds);
        GuardDrawAndApply();
        std::set<uint256> setAnswered;
        AtkMeter mPull;
        for (unsigned int nRounds = 0; nRounds < 400; nRounds++)
        {
            bool fAny = false;
            foreach(const SentMessage& m, SentTo(pA))
            {
                if (m.strCommand != "p2xsync" || m.payload.size() != 64)
                    continue;
                uint256 id;
                memcpy(id.begin(), &m.payload[0], 32);
                if (setAnswered.count(id) || !mapLine.count(id))
                    continue;
                setAnswered.insert(id);
                const std::vector<p2pool::Share>& line = mapLine[id];
                // Parts of at most 200 KB (the node refuses and scores a part past 256 KB).
                size_t iFrom = 0;
                while (iFrom < line.size())
                {
                    std::vector<p2pool::Share> part;
                    size_t nB = 0;
                    while (iFrom + part.size() < line.size() && part.size() < 100)
                    {
                        const size_t n = ::GetSerializeSize(p2pool::ShareX(line[iFrom + part.size()]), SER_NETWORK);
                        if (!part.empty() && nB + n > 200 * 1024)
                            break;
                        nB += n;
                        part.push_back(line[iFrom + part.size()]);
                    }
                    iFrom += part.size();
                    SendRegPart(pA, id, (int)line.size() - 1, iFrom >= line.size() ? 1 : 0, part);
                }
                fAny = true;
            }
            P2PoolRegAgeForTest(301);
            P2PoolRegTickForTest();
            P2PoolRegAgeForTest(61);
            P2PoolRegTickForTest();
            if (!fAny && nRounds > 8)
                break;
        }
        unsigned int nKept = 0, nHugeKept = 0, nHeld = 0;
        uint64 nKeptBytes = 0, nHeldBytes = 0;
        for (size_t i = 0; i < vPools.size(); i++)
        {
            P2PoolRegStatusInfo st;
            if (P2PoolRegStatus(vPools[i].id, st) && st.fGuard && st.nShares > 0)
            {
                nHeld++;
                nHeldBytes += st.nBytes;
                if (st.fAnnounced)
                {
                    nKept++;
                    nKeptBytes += st.nBytes;
                    if (i == nFat)
                        nHugeKept++;
                }
            }
        }
        printf("     lines %.0f MB in all in the test's own memory; %u pools drawn; kept (guarded and announced) %u pools, %.1f MB "
               "(budget %.0f MB, %u pools); %u with a line in memory, %.1f MB; the 79 MB pool kept: %s; node RSS %ld MB "
               "(%ld MB before the pulls, test fixtures included), peak %ld MB; %.1f s CPU\n",
               nLineBytes / 1e6, (unsigned)GuardEntries().size(), nKept, nKeptBytes / 1e6, GUARD_DEFAULT_BYTES / 1e6,
               GUARD_MAX_POOLS, nHeld, nHeldBytes / 1e6, nHugeKept ? "YES" : "no", AtkProcKB("VmRSS:") / 1024, nRss0,
               AtkProcKB("VmHWM:") / 1024, mPull.Cpu());
        ok(nKeptBytes <= (uint64)GUARD_DEFAULT_BYTES, "the kept lines never pass the guard budget in bytes");
        ok(nKept <= GUARD_MAX_POOLS, "never more than 8 pools kept");
        ok(nHugeKept == 0, "a line past the 64 MB a guardian gives one pool is guarded by nobody");
        ok(nKept >= 4, "the budget still holds what fits (at least four 22 MB lines)");
        AtkFree(vFree);
    }

    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-scale: all passed" : "attack-scale: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}
