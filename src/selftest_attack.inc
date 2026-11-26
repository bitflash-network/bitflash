// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The attack and scale harness of Everpool (docs/pool-registry.md, sections
// 8, 10, 11 and 12). Included by selftest.cpp, so it can use the helpers the
// guardian and registered-pool self-tests use: fake peers that read the
// registry, messages fed to the same handlers a socket feeds, the ticket
// book with a cheap work function, and mirror share chains.
//
// None of these cases is in the default run or in `make tests`: each is run
// by name (-selftest=attack-sybil, attack-ticket-flood, attack-shares,
// attack-flood, attack-withhold, attack-stale, attack-scale), prints what it
// measured, and fails only when a bound of the SPEC is broken. Sizes are set
// from the environment where it matters (ATTACK_POOLS, ATTACK_HONEST, ...).
//
// What is real here: the message handlers, the ticket book and its caps, the
// draw, the guard budget, the share chain and its rules, RandomX where a case
// says so. What is not: sockets and Tor (messages are handed to the handlers
// as the message thread would), and the work of a ticket or of a share where
// a case says its work is cheap (the draw reads only the work hash, never how
// it was found; a share's own RandomX hash is on or off per case, and its
// cost is measured apart).

#include <chrono>

namespace {

double AtkCpu() { return (double)clock() / (double)CLOCKS_PER_SEC; }

double AtkWall()
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// A /proc/self/status figure in KB ("VmRSS:", "VmHWM:"); -1 where there is
// no /proc.
long AtkProcKB(const char* pszKey)
{
    FILE* f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    long n = -1;
    const size_t k = strlen(pszKey);
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, pszKey, k) == 0)
        {
            n = atol(line + k);
            break;
        }
    fclose(f);
    return n;
}

unsigned int AtkEnv(const char* pszName, unsigned int nDefault)
{
    const char* p = getenv(pszName);
    if (!p || !*p)
        return nDefault;
    return (unsigned int)strtoul(p, NULL, 10);
}

// A node's data directory for one case, and back.
struct AtkDir
{
    std::string tmp, cwd;
    bool fOk;
    AtkDir() : fOk(false)
    {
        fOk = MakeTempDir(tmp) && GetCurrentDir(cwd) && SetCurrentDir(tmp);
        if (fOk)
            strSetDataDir = tmp;
    }
    ~AtkDir()
    {
        if (fOk)
        {
            SetCurrentDir(cwd);
            RemoveTree(tmp);
        }
    }
};

std::string AtkKey(const std::vector<unsigned char>& k) { return std::string((const char*)&k[0], k.size()); }

// The Poisson-ish bound used to compare a count with its expectation.
bool AtkNear(double dObs, double dExp, double dSigmas = 4.0)
{
    return fabs(dObs - dExp) <= dSigmas * sqrt(dExp) + 3.0;
}

// CPU seconds and wall seconds of a stretch of work, and the resident set
// before and after.
struct AtkMeter
{
    double c0, w0;
    long rss0;
    AtkMeter() { Reset(); }
    void Reset() { c0 = AtkCpu(); w0 = AtkWall(); rss0 = AtkProcKB("VmRSS:"); }
    double Cpu() const { return AtkCpu() - c0; }
    double Wall() const { return AtkWall() - w0; }
    long RssDelta() const { return rss0 < 0 ? -1 : AtkProcKB("VmRSS:") - rss0; }
};

// The ticket thread, run until the queues are empty: the budget (a burst of
// 256 tokens) is refilled by hand, a hash at a time of the real VM would
// take 64 s a burst at the node's own rate. Returns the checks made.
int AtkDrainTickets(int nMaxRounds = 400)
{
    int nTotal = 0;
    for (int i = 0; i < nMaxRounds; i++)
    {
        P2PoolTicketBudgetForTest(256);
        int n = P2PoolTicketStepForTest(256, false);
        nTotal += n;
        if (n == 0)
            break;
    }
    return nTotal;
}

} // namespace

// ---- attack-sybil: tickets and the places they win ------------------------
//
// SPEC section 12: "Sybil: many tickets to capture a pool's guardians" and
// the arithmetic after the table. An attacker with as many tickets as all the
// honest nodes together (and twice and three times as many) meets the same
// book the node keeps: one ticket per key, the 4096 lowest work hashes, the
// lowest hash winning whatever the order of arrival. The draw is then taken
// over that held set for many pools and the places counted.

static int RunAttackSybilSelfTest()
{
    printf("attack-sybil\n");
    int nFail = 0;
    auto ok = [&nFail](bool f, const char* psz) { if (!Check(f, psz)) nFail++; };
    const unsigned int nH = AtkEnv("ATTACK_HONEST", 4096);
    const unsigned int nPools = AtkEnv("ATTACK_POOLS", 20000);
    const unsigned int vRatio[3] = { 1, 2, 3 };
    const unsigned int nAMax = 3 * nH;
    const unsigned int nBase = 1000000;   // attacker keys start here

    CTicketParams params = CTicketParams::Network();
    params.fnWork = TicketTestWork;
    TicketTestView w;
    w.Grow(3700, 0);
    const uint256 seed = w.v[3600];       // epoch 6's ticket seed, buried
    const uint256 hashDraw = TicketVectorHash("attack-sybil-draw-seed");

    std::vector<CGuardTicket> vHon, vAtk;
    std::set<std::string> setAtk;
    AtkMeter mk;
    for (unsigned int i = 0; i < nH + nAMax; i++)
    {
        CGuardTicket t;
        uint256 hw;
        const bool fAtk = i >= nH;
        if (!TicketTestMake(params, seed, 6, fAtk ? nBase + (i - nH) : i, 0, t, hw))
        {
            printf("  FAIL no ticket found for key %u\n", i);
            return 1;
        }
        if (fAtk)
        {
            vAtk.push_back(t);
            setAtk.insert(AtkKey(t.Key()));
        }
        else
            vHon.push_back(t);
    }
    printf("  made %u honest and %u attacker tickets (cheap work function: %.1f s CPU, %llu work hashes; a real "
           "ticket is 8192 RandomX hashes on average)\n",
           nH, nAMax, mk.Cpu(), (unsigned long long)g_nTicketTestHashes);

    for (size_t iR = 0; iR < 3; iR++)
    {
        const unsigned int r = vRatio[iR];
        const unsigned int nA = r * nH;
        CTicketBook book(params);
        AtkMeter mAdd;
        unsigned int nHeldVerdict = 0, nOut = 0, nOther = 0;
        // The attacker's tickets first, then the honest ones: arrival order
        // must not matter, only the work hash.
        std::vector<CGuardTicket> vIn(vAtk.begin(), vAtk.begin() + nA);
        vIn.insert(vIn.end(), vHon.begin(), vHon.end());
        for (size_t i = 0; i < vIn.size(); i++)
        {
            int v = book.Accept(w, vIn[i], seed, true);
            if (v == TICKET_HELD) nHeldVerdict++;
            else if (v == TICKET_OUTRANKED || v == TICKET_PAST_CAP) nOut++;
            else nOther++;
        }
        std::vector<CHeldTicket> held;
        book.Tickets(6, held);
        unsigned int nAtkHeld = 0;
        for (size_t i = 0; i < held.size(); i++)
            if (setAtk.count(AtkKey(held[i].ticket.Key())))
                nAtkHeld++;
        const double dQ = held.empty() ? 0 : (double)nAtkHeld / held.size();
        printf("  A = %uH: %u tickets offered, %u held (cap %u): the attacker holds %u, a share of %.4f "
               "(A/(H+A) = %.4f); %.2f s CPU for all the checks\n",
               r, (unsigned)vIn.size(), (unsigned)held.size(), GUARD_MAX_TICKETS, nAtkHeld, dQ,
               (double)r / (1 + r), mAdd.Cpu());
        ok(nOther == 0 && held.size() == std::min((size_t)GUARD_MAX_TICKETS, vIn.size()),
           "the set is full to the cap and nothing was refused");
        ok(fabs(dQ - (double)r / (1 + r)) < 0.02, "the attacker's share of the held set is its share of all tickets");

        // The draw over the held set.
        std::vector<unsigned int> vHist(17, 0);
        unsigned int nAll8 = 0, nAll16 = 0, nNoHonestGuardian = 0;
        uint64 nAtkPlaces = 0;
        AtkMeter mDraw;
        for (unsigned int j = 0; j < nPools; j++)
        {
            std::string s = strprintf("attack-sybil-pool/%u", j);
            std::vector<CDrawPlace> v;
            pooltkt::Draw(hashDraw, Hash(s.begin(), s.end()), held, 16, v);
            unsigned int k = 0, k8 = 0;
            for (size_t i = 0; i < v.size(); i++)
                if (setAtk.count(AtkKey(v[i].key)))
                {
                    k++;
                    if (i < 8)
                        k8++;
                }
            vHist[k]++;
            nAtkPlaces += k;
            if (k8 == 8)
                nAll8++;
            if (k == 16)
                nAll16++;
            if (k8 == 8 && k < 16)
                nNoHonestGuardian++;
        }
        double dExact8 = 1.0, dExact16 = 1.0;
        for (unsigned int i = 0; i < 16; i++)
        {
            const double dTerm = (double)(nAtkHeld - i) / (double)(held.size() - i);
            dExact16 *= dTerm;
            if (i < 8)
                dExact8 *= dTerm;
        }
        const double dEst8 = pow((double)r / (1 + r), 8.0), dEst16 = pow((double)r / (1 + r), 16.0);
        printf("    %u pools drawn (%.1f s CPU): the attacker holds %.4f of the places;\n"
               "    all 8 guardian places of %u pools (%.5f; (A/(H+A))^8 = %.5f; exact %.5f, expected %.1f pools);\n"
               "    all 16 places of %u pools (%.6f; (A/(H+A))^16 = %.6f; exact %.6f, expected %.1f pools)\n",
               nPools, mDraw.Cpu(), (double)nAtkPlaces / (16.0 * nPools), nAll8, (double)nAll8 / nPools, dEst8,
               dExact8, dExact8 * nPools, nAll16, (double)nAll16 / nPools, dEst16, dExact16, dExact16 * nPools);
        printf("    places per pool held by the attacker (0..16):");
        for (unsigned int k = 0; k <= 16; k++)
            printf(" %u", vHist[k]);
        printf("\n");
        ok(fabs((double)nAtkPlaces / (16.0 * nPools) - dQ) < 0.01, "each place goes to the attacker with its share of the set");
        ok(AtkNear(nAll8, dExact8 * nPools) && AtkNear(nAll16, dExact16 * nPools),
           "capturing all 8 or all 16 places of a pool happens as often as the share to that power says");
        ok(dExact16 <= dEst16 * 1.0001, "section 12's estimate is the upper side of the exact value");
        (void)nHeldVerdict;
    }

    // Aiming: the attacker waits for the draw seed and the pool it wants,
    // and grinds tickets until its lowest scores beat every honest one.
    {
        const unsigned int nTrials = AtkEnv("ATTACK_AIM_TRIALS", 200);
        std::vector<double> v8, v16;
        for (unsigned int trial = 0; trial < nTrials; trial++)
        {
            const uint256 hd = TicketVectorHash(strprintf("attack-aim-seed/%u", trial).c_str());
            const uint256 pool = TicketVectorHash(strprintf("attack-aim-pool/%u", trial).c_str());
            uint256 hMin = ~uint256(0);
            for (unsigned int i = 0; i < nH; i++)
            {
                CHeldTicket t = TicketTestFake(strprintf("attack-aim-honest/%u", trial), i);
                uint256 sc = pooltkt::Score(hd, pool, t.hashWork);
                if (sc < hMin)
                    hMin = sc;
            }
            unsigned int nBeat = 0;
            uint64 nTried = 0, nAt8 = 0, nAt16 = 0;
            while (nBeat < 16 && nTried < 2000ULL * nH)
            {
                CHeldTicket t = TicketTestFake(strprintf("attack-aim-own/%u", trial), (unsigned int)nTried);
                nTried++;
                if (pooltkt::Score(hd, pool, t.hashWork) < hMin)
                {
                    nBeat++;
                    if (nBeat == 8) nAt8 = nTried;
                    if (nBeat == 16) nAt16 = nTried;
                }
            }
            v8.push_back((double)nAt8);
            v16.push_back((double)nAt16);
        }
        double s8 = 0, s16 = 0;
        for (size_t i = 0; i < v8.size(); i++) { s8 += v8[i]; s16 += v16[i]; }
        s8 /= v8.size(); s16 /= v16.size();
        std::sort(v8.begin(), v8.end());
        std::sort(v16.begin(), v16.end());
        const double m8 = v8[v8.size() / 2], m16 = v16[v16.size() / 2], p90_16 = v16[v16.size() * 9 / 10], p10_16 = v16[v16.size() / 10];
        printf("  (the cost is heavy-tailed: it is 16 divided by the best honest score for that pool; for all 16 places the tickets ground: "
               "median %.1f H, 10th percentile %.1f H, 90th percentile %.1f H; for the 8 guardian places the median is %.1f H)\n",
               m16 / nH, p10_16 / nH, p90_16 / nH, m8 / nH);
        printf("  aiming at one pool after its seed is known, against H = %u honest tickets, %u trials: "
               "tickets ground to hold all 8 guardian places %.0f on average (%.1f H); all 16 places %.0f (%.1f H); "
               "at 8192 RandomX hashes a ticket that is %.2e and %.2e hashes\n",
               nH, nTrials, s8, s8 / nH, s16, s16 / nH, s8 * 8192.0, s16 * 8192.0);
        ok(m16 > 12.0 * nH && m16 < 40.0 * nH, "capturing one chosen pool takes tickets of the order of 16 H to 25 H at the median (section 12 says about 16 H; the tail is heavier)");
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-sybil: all passed" : "attack-sybil: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- attack-ticket-flood: the 4096 places filled by an attacker -----------
//
// SPEC section 12, "Sybil: flooding the ticket set": an attacker that sends
// more valid tickets than a set holds. Checks that honest guardians keep the
// pools they hold, that poolwho still names the peers that announce a pool,
// and measures what the ticket path costs per message for valid tickets and
// for each kind of bad one.

static int RunAttackTicketFloodSelfTest()
{
    printf("attack-ticket-flood\n");
    AtkDir dir;
    if (!dir.fOk)
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    int nFail = 0;
    auto ok = [&nFail](bool f, const char* psz) { if (!Check(f, psz)) nFail++; };
    string err;
    CBigNum bnFloor;
    bnFloor.SetCompact(0x207fffff);
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
    CNode* pH = NewRegTestNode(false, "BF1atk-honest");
    CNode* pAnn = NewRegTestNode(false, "BF1atk-announcer");
    vFree.push_back(pH);
    vFree.push_back(pAnn);
    const unsigned int NX = 8;
    std::vector<CNode*> vX;
    for (unsigned int i = 0; i < NX; i++)
    {
        vX.push_back(NewRegTestNode(true, strprintf("BF1atk-x%u", i).c_str()));
        vFree.push_back(vX.back());
    }
    P2PoolOnVersion(pH);
    P2PoolOnVersion(pAnn);
    for (unsigned int i = 0; i < NX; i++)
        P2PoolOnVersion(vX[i]);
    P2PoolRegTickForTest();     // asks the peers for the sets

    // Honest: 40 tickets for epoch 5 and 300 for epoch 6, from an honest peer.
    const unsigned int nHon6 = 300;
    std::vector<CHeldTicket> t5 = GuardMake(params, seed5, 5, 1, 40);
    std::vector<CHeldTicket> t6 = GuardMake(params, seed6, 6, 1, nHon6);
    P2PoolTicketBudgetForTest(100000);
    GuardSendTickets(pH, 5, seed5, GuardBodies(t5, 0, t5.size()));
    AtkDrainTickets();
    for (size_t i = 0; i < t6.size(); i += 100)
    {
        GuardSendTickets(pH, 6, seed6, GuardBodies(t6, i, i + 100));
        AtkDrainTickets();
    }
    CGuardTicket own5, own6;
    for (int i = 0; i < 20000 && !(P2PoolTicketOwnForTest(5, own5) && P2PoolTicketOwnForTest(6, own6)); i++)
        P2PoolTicketStepForTest(0, true);
    size_t nHon6Held = 0;
    for (size_t i = 0; i < t6.size(); i++)
        if (P2PoolTicketIsHeldForTest(6, t6[i].ticket))
            nHon6Held++;
    printf("  honest tickets held before the flood: epoch 5 %u, epoch 6 %u of %u sent (and the node's own)\n", (unsigned)P2PoolTicketHeldForTest(5), (unsigned)nHon6Held, nHon6);
    ok(P2PoolTicketHeldForTest(5) >= 40 && nHon6Held >= 100, "honest tickets held for epochs 5 and 6");

    // Three pools with a line, announced by one peer, guarded by this node.
    std::vector<CPoolInfo> vPools;
    for (int i = 0; i < 6; i++)
        vPools.push_back(GuardInfo(GuardRecord(i)));
    TestMainView main;
    main.nBits = 0x1d00ffff;
    main.nTip = 61000;
    main.nNow = GetTime();
    for (int h = 60990; h <= 61000; h++)
        main.heights[Hash(BEGIN(h), END(h))] = h;
    P2PoolTicketPoolsForTest(vPools);
    GuardDrawAndApply();
    std::vector<uint256> vAnn;
    std::vector<vector<p2pool::Share> > vLines;
    for (int i = 0; i < 3; i++)
    {
        p2pool::PoolRules rules;
        p2pool::RulesForRegistered(vPools[i].rec, (const unsigned char*)pchMessageStart, rules, err);
        p2pool::ShareChain mirror(rules, false);
        vLines.push_back(RegLine(mirror, main, 30 + 10 * i, (unsigned char)(i + 1)));
        vAnn.push_back(vPools[i].id);
    }
    SendPoolInv(pAnn, vAnn);
    P2PoolRegTickForTest();
    P2PoolRegTickForTest();
    for (int round = 0; round < 6; round++)
    {
        for (int i = 0; i < 3; i++)
        {
            uint256 id, resume;
            if (LastRegSync(pAnn, id, resume) && id == vAnn[i] && RegShares(vAnn[i]) == 0)
                SendRegPart(pAnn, vAnn[i], (int)vLines[i].size() - 1, 1, vLines[i]);
        }
        P2PoolRegAgeForTest(301);
        P2PoolRegTickForTest();
        P2PoolRegAgeForTest(61);
        P2PoolRegTickForTest();
    }
    size_t nGuarded = 0;
    for (int i = 0; i < 3; i++)
    {
        P2PoolRegStatusInfo st;
        if (P2PoolRegStatus(vAnn[i], st) && st.fGuard && st.fAnnounced && st.nShares > 0)
            nGuarded++;
    }
    ok(nGuarded >= 1, "before the flood this node guards and announces pools it pulled");
    printf("  before the flood: %u of 3 pools with a line guarded and announced here; epoch 6 holds %u tickets\n",
           (unsigned)nGuarded, (unsigned)P2PoolTicketHeldForTest(6));

    // The flood: 3x the cap of valid tickets of epoch 6, from 8 connections,
    // 512 a message, the node's own queue limits in force (512 a connection),
    // the budget unlimited here (the cost of a check is measured, the rate
    // is the constant TKT_BUDGET_PER_SEC).
    const unsigned int nAtk = 3 * GUARD_MAX_TICKETS;
    std::vector<CHeldTicket> vA;
    {
        AtkMeter mk;
        for (unsigned int i = 0; i < nAtk; i++)
        {
            CHeldTicket h;
            if (TicketTestMake(params, seed6, 6, 5000000 + i, 0, h.ticket, h.hashWork))
                vA.push_back(h);
        }
        printf("  attacker made %u valid tickets (cheap work: %.1f s CPU)\n", (unsigned)vA.size(), mk.Cpu());
    }
    {
        AtkMeter m;
        unsigned int nSent = 0;
        size_t iNext = 0;
        // The peers this node asked for epoch 6's set may answer with up to
        // 4096 each; the others can only relay, and a relay waits in a queue
        // of 512 a connection and 4096 in all.
        std::vector<unsigned int> vAns(NX, 0);
        unsigned int nAnsSent = 0, nRelaySent = 0, nRounds = 0;
        while (iNext < vA.size() && nRounds < 400)
        {
            nRounds++;
            P2PoolTicketBudgetForTest(100000);
            for (unsigned int c = 0; c < NX && iNext < vA.size(); c++)
            {
                const bool fAsked = GuardAsked(vX[c]).count(6) > 0;
                if (fAsked && vAns[c] >= GUARD_MAX_TICKETS)
                    continue;
                size_t n = std::min((size_t)512, vA.size() - iNext);
                GuardSendTickets(vX[c], 6, seed6, GuardBodies(vA, iNext, iNext + n));
                iNext += n;
                nSent += (unsigned)n;
                if (fAsked) { vAns[c] += (unsigned)n; nAnsSent += (unsigned)n; }
                else nRelaySent += (unsigned)n;
            }
            AtkDrainTickets();
        }
        printf("  flood delivered as: %u in answers to the node's own asks (up to 4096 a peer), %u as relays (queue 512 a connection, 4096 in all), %u rounds\n",
               nAnsSent, nRelaySent, nRounds);
        size_t nHeld = P2PoolTicketHeldForTest(6);
        size_t nHonKept = 0;
        for (size_t i = 0; i < t6.size(); i++)
            if (P2PoolTicketIsHeldForTest(6, t6[i].ticket))
                nHonKept++;
        const bool fOwnKept = P2PoolTicketIsHeldForTest(6, own6);
        // The honest ones survive in proportion to the lowest 4096 of all.
        const double dExpKept = (double)t6.size() * GUARD_MAX_TICKETS / (double)(t6.size() + nSent);
        size_t nScored = 0;
        for (unsigned int c = 0; c < NX; c++)
            nScored += vX[c]->nMisbehavior;
        printf("  flood: %u valid attacker tickets in %.1f s CPU (%.2f ms per ticket, %.1f s wall): the set of epoch 6 "
               "holds %u (cap %u); %u of %u honest tickets still held (expected about %.0f by lowest work hash); "
               "this node's own %s; the flood scored %u points\n",
               nSent, m.Cpu(), 1000.0 * m.Cpu() / nSent, m.Wall(), (unsigned)nHeld, GUARD_MAX_TICKETS,
               (unsigned)nHonKept, (unsigned)t6.size(), dExpKept, fOwnKept ? "held" : "pushed out", (unsigned)nScored);
        ok(nHeld <= GUARD_MAX_TICKETS && nHeld >= t6.size(), "the set never goes past its cap and keeps what honest peers sent");
        ok(nHeld < GUARD_MAX_TICKETS ? nHonKept == t6.size() : AtkNear((double)nHonKept, dExpKept), "honest tickets stay while the set has room, and go by work hash alone once it is full");
        ok(nScored == 0, "valid tickets are never scored, however many");
        printf("  at the node's budget (%d tokens a second, a burst of %d) the flood above takes at least %.0f minutes "
               "to be checked; every check on the real VM is one RandomX hash (see attack-flood for its cost)\n",
               4, 256, (nSent - 256) / 4.0 / 60.0);
    }

    // After the flood: the epoch moves on, the draw is taken over the
    // attacker's set. What this node held stays until its linger ends.
    {
        w.Grow(4300, 0);        // epoch 5's draw is old; epoch 6's seed (block 4260) is settled at 4289
        P2PoolTicketViewForTest(w.v);
        GuardDrawAndApply();
        std::vector<P2PoolGuardEntryInfo> v = GuardEntries();
        size_t nStill = 0;
        for (int i = 0; i < 3; i++)
        {
            P2PoolRegStatusInfo st;
            if (P2PoolRegStatus(vAnn[i], st) && st.fGuard && st.fAnnounced && st.nShares > 0)
                nStill++;
        }
        ok(nStill == nGuarded, "after epoch 6's draw over the attacker's set, the pools this node held are still guarded and announced (linger)");

        // poolwho from a fresh peer: the announcer is named.
        CNode* pQ = NewRegTestNode(false, "BF1atk-asker");
        vFree.push_back(pQ);
        P2PoolOnVersion(pQ);
        CDataStream ss(SER_NETWORK, VERSION);
        ss << vAnn[0];
        SendP2PoolTest(pQ, "poolwho", ss);
        bool fNamed = false;
        foreach(const SentMessage& m, SentTo(pQ))
            if (m.strCommand == "poolat" && m.payload.size() > 33)
            {
                std::string s((const char*)&m.payload[0], m.payload.size());
                if (s.find("BF1atk-announcer") != std::string::npos)
                    fNamed = true;
            }
        ok(fNamed, "poolwho still names the peer that announces the pool");

        w.Grow(4600, 0);
        P2PoolTicketViewForTest(w.v);
        GuardDrawAndApply();
        size_t nAfterLinger = 0;
        for (int i = 0; i < 3; i++)
        {
            P2PoolRegStatusInfo st;
            if (P2PoolRegStatus(vAnn[i], st) && st.fGuard && st.nShares > 0)
                nAfterLinger++;
        }
        printf("  past the linger (tip 4600, epoch 6's guardians are the attacker's set): %u of 3 pools still guarded here "
               "(by design they are let go when no longer drawn; the miners and -poolcarry nodes hold the line)\n",
               (unsigned)nAfterLinger);
    }

    // The cost of each kind of bad ticket, per message of 512 (a connection
    // that scores 100 is dropped, so every few messages a new one).
    {
        w.Cut(3700);            // back to the view of the flood (epoch 6 is the next epoch again)
        P2PoolTicketViewForTest(w.v);
        std::vector<CGuardTicket> vGood = GuardBodies(vA, 0, 512);
        struct Kind { const char* name; };
        const unsigned int nMsgs = AtkEnv("ATTACK_BAD_MSGS", 400);
        for (int kind = 0; kind < 6; kind++)
        {
            AtkMeter m;
            unsigned int nPeers = 0;
            int nMis = 0;
            CNode* p = NULL;
            for (unsigned int i = 0; i < nMsgs; i++)
            {
                if (!p || p->nMisbehavior >= 60)
                {
                    nMis += p ? p->nMisbehavior : 0;
                    p = NewRegTestNode(true, strprintf("BF1atk-bad%d-%u", kind, nPeers).c_str());
                    vFree.push_back(p);
                    P2PoolOnVersion(p);
                    nPeers++;
                }
                std::vector<CGuardTicket> v = vGood;
                CDataStream ss(SER_NETWORK, VERSION);
                if (kind == 0)          // a bad signature in every ticket
                {
                    for (size_t k = 0; k < v.size(); k++)
                        v[k].sig[k % 64] ^= 1;
                    ss << (unsigned int)6 << seed6 << v;
                }
                else if (kind == 1)     // not whole tickets
                {
                    ss << (unsigned int)6 << seed6;
                    WriteCompactSize(ss, 1);
                    ss.write(std::string(117, 'x').data(), 117);
                }
                else if (kind == 2)     // another seed: dropped unread
                    ss << (unsigned int)6 << uint256(77) << v;
                else if (kind == 3)     // an epoch not taken: dropped unread
                    ss << (unsigned int)99 << seed6 << v;
                else if (kind == 4)     // tickets already checked (valid ones sent again)
                    ss << (unsigned int)6 << seed6 << v;
                else                    // a poolgettkt: a set asked for
                    ss << (unsigned int)6;
                SendP2PoolTest(p, kind == 5 ? "poolgettkt" : "pooltkt", ss);
                if (kind == 0 || kind == 4)
                {
                    P2PoolTicketBudgetForTest(100000);
                    P2PoolTicketStepForTest(512, false);
                }
            }
            nMis += p ? p->nMisbehavior : 0;
            static const char* const vName[6] = { "512 bad signatures a message", "a message of one malformed ticket",
                "another seed's tickets", "an epoch not taken", "tickets already checked", "poolgettkt asks" };
            printf("    %-34s %u messages from %u connections: %.1f us CPU a message, %d points scored, RSS %+ld KB\n",
                   vName[kind], nMsgs, nPeers, 1e6 * m.Cpu() / nMsgs, nMis, m.RssDelta());
        }
        ok(P2PoolTicketHeldForTest(6) <= GUARD_MAX_TICKETS, "bad tickets leave the set within its cap");
    }

    for (size_t i = 0; i < vFree.size(); i++)
    {
        P2PoolForgetDeferred(vFree[i]);
        delete vFree[i];
    }
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-ticket-flood: all passed" : "attack-ticket-flood: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}
