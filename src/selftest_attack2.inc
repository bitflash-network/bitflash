// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The registered-pool cases of the attack harness: see selftest_attack.inc.

// ---- shared by the registered-pool cases ----------------------------------

namespace {

std::vector<unsigned char> AtkPayTo(unsigned int n)
{
    CScript s;
    s << OP_DUP << OP_HASH160 << uint160((uint64)n + 1) << OP_EQUALVERIFY << OP_CHECKSIG;
    return std::vector<unsigned char>(s.begin(), s.end());
}

poolreg::PoolRecord AtkRecord(const std::string& strName, unsigned int nWindow = 360, unsigned int nRetarget = 120)
{
    poolreg::PoolRecord rec = poolreg::PoolZero();
    rec.nSpacing = 30; rec.nWindow = nWindow; rec.nRetarget = nRetarget; rec.nUncleDepth = 2;
    rec.nUnclePct = 90; rec.nFloor = 0x1f0fffff;
    rec.name = strName;
    return rec;
}

// The same share with its data changed and its coinbase made to match: the
// anchor over the new data hash, the merkle root over the new coinbase. What
// a forger does to get past the cheap checks.
p2pool::Share AtkReseal(p2pool::Share s, const p2pool::PoolRules& rules, const TestMainView& main)
{
    s.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << (int64)s.nTime << p2pool::AnchorPush(rules, s.data);
    s.hashMerkleRoot = s.coinbase.GetHash();
    return s;
}

TestMainView AtkMain()
{
    TestMainView main;
    main.nBits = 0x1d00ffff;
    main.nTip = 61000;
    main.nNow = GetTime();
    for (int h = 60990; h <= 61000; h++)
        main.heights[Hash(BEGIN(h), END(h))] = h;
    return main;
}

size_t AtkSentBytes(CNode* p)
{
    size_t n = 0;
    foreach(const SentMessage& m, SentTo(p))
        n += m.payload.size() + 24;
    return n;
}

struct AtkPool
{
    poolreg::PoolRecord rec;
    p2pool::PoolRules rules;
    uint256 id;
};

size_t AtkZeroSize()
{
    size_t n;
    CRITICAL_BLOCK(cs_p2pool)
        n = P2PoolChain().Size();
    return n;
}

void AtkFree(std::vector<CNode*>& v)
{
    for (size_t i = 0; i < v.size(); i++)
    {
        P2PoolForgetDeferred(v[i]);
        delete v[i];
    }
    v.clear();
}

} // namespace

// ---- attack-shares: invalid, forged and replayed shares -------------------
//
// SPEC section 8 (what is scored and what is dropped unread) and section 12
// ("flooding shares of a carried pool", "a forged deep history", "a share
// replayed across networks"), against a registered pool that is mined here,
// with pool zero beside it.

static int RunAttackSharesSelfTest()
{
    printf("attack-shares\n");
    AtkDir dir;
    if (!dir.fOk)
    {
        printf("  FAIL could not set up a temporary data directory\n");
        return 1;
    }
    int nFail = 0;
    auto ok = [&nFail](bool f, const char* psz) { if (!Check(f, psz)) nFail++; };
    string err;
    RandomXInit();
    TestMainView main = AtkMain();
    CBigNum bnFloor;
    bnFloor.SetCompact(0x207fffff);
    const unsigned char* magic = (const unsigned char*)pchMessageStart;
    const unsigned char otherMagic[4] = { 0x0b, 0x11, 0x09, 0x07 };
    std::vector<CNode*> vFree;
    auto newPeer = [&vFree](bool fIn, const char* psz) {
        CNode* p = NewRegTestNode(fIn, psz);
        vFree.push_back(p);
        P2PoolOnVersion(p);
        return p;
    };

    // ---- structural attacks, no RandomX (the work is judged in the second half)
    {
        P2PoolResetForTest(bnFloor, false);
        PoolBurnsOpenForTest(true);
        AtkPool A;
        A.rec = AtkRecord("atk-shares-a");
        p2pool::RulesForRegistered(A.rec, magic, A.rules, err);
        A.id = A.rules.poolId;
        ok(P2PoolRegAddForTest(A.rec, true, false, true, err), "a registered pool to mine joins");
        CNode* pOld = NewP2PoolTestNode(true);
        vFree.push_back(pOld);
        P2PoolOnVersion(pOld);
        CNode* pAnn = newPeer(false, "BF1atk-announcer");
        P2PoolRegTickForTest();
        P2PoolRegAgeForTest(121);
        P2PoolRegTickForTest();

        p2pool::ShareChain mirror(A.rules, false);
        uint256 prev = 0;
        unsigned int t = (unsigned int)main.nNow - 30 * 60;
        for (int i = 0; i < 40; i++)
        {
            p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo(i % 3), t + 30 * i);
            mirror.Add(s, main, err);
            P2PoolSubmitShare(s, err);
            prev = s.GetId();
        }
        SendPoolInv(pAnn, std::vector<uint256>(1, A.id));
        P2PoolRegTickForTest();
        ok(RegShares(A.id) == 40, "the honest line, 40 shares, is held here");

        const size_t nZero = AtkZeroSize();
        const int nZeroWork = P2PoolShareWorkTokens(), nZeroServe = P2PoolHistoryServeTokens();
        const int nRegWork = P2PoolRegisteredShareWorkTokens();

        // A valid next share to alter.
        p2pool::Share good = RulesShare(mirror, main, prev, AtkPayTo(1), t + 30 * 40);
        struct Attack
        {
            const char* name;
            p2pool::Share share;
            uint256 head;
            int nExpectScore;   // 0: not scored; -1: scored by whatever the rule says
        };
        std::vector<Attack> v;
        {
            Attack a = { "head names the pool, the share's data names another", good, A.id, 20 };
            a.share.data.poolId = uint256(777);
            a.share = AtkReseal(a.share, A.rules, main);
            v.push_back(a);
        }
        {
            Attack a = { "payout list that is not the window's", good, A.id, -1 };
            a.share.coinbase.vout[0].nValue -= 1;
            a.share.hashMerkleRoot = a.share.coinbase.GetHash();
            v.push_back(a);
        }
        {
            Attack a = { "share height not the parent's plus one", good, A.id, -1 };
            a.share.data.nShareHeight += 5;
            a.share = AtkReseal(a.share, A.rules, main);
            v.push_back(a);
        }
        {
            Attack a = { "share target easier than the chain's", good, A.id, -2 };
            a.share.data.nShareBits = 0x207fffff;
            a.share = AtkReseal(a.share, A.rules, main);
            v.push_back(a);
        }
        {
            Attack a = { "coinbase anchored with another network's pool id", good, A.id, -1 };
            p2pool::PoolRules other = A.rules;
            poolreg::PoolId(A.rec.Encode(), otherMagic, other.poolId.begin());
            a.share.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << (int64)a.share.nTime
                                                          << p2pool::AnchorPush(other, a.share.data);
            a.share.hashMerkleRoot = a.share.coinbase.GetHash();
            v.push_back(a);
        }
        {
            Attack a = { "no anchor in the coinbase", good, A.id, -1 };
            a.share.coinbase.vin[0].scriptSig = CScript() << (main.nTip + 1) << (int64)a.share.nTime;
            a.share.hashMerkleRoot = a.share.coinbase.GetHash();
            v.push_back(a);
        }
        {
            Attack a = { "two uncles that are not on the chain", good, A.id, 0 };
            a.share.data.vUncles.push_back(uint256(11));
            a.share.data.vUncles.push_back(uint256(12));
            a.share = AtkReseal(a.share, A.rules, main);
            v.push_back(a);
        }
        {
            Attack a = { "payout script that is not P2PKH or P2SH", good, A.id, -1 };
            a.share.data.payoutScript.assign(40, 0x51);
            a.share = AtkReseal(a.share, A.rules, main);
            v.push_back(a);
        }
        for (size_t i = 0; i < v.size(); i++)
        {
            CNode* p = newPeer(true, strprintf("BF1atk-evil%u", (unsigned)i).c_str());
            const size_t nBefore = RegShares(A.id);
            AtkMeter m;
            SendRegItem(p, "p2xshare", v[i].head, p2pool::ShareX(v[i].share));
            const bool fRefused = RegShares(A.id) == nBefore;
            printf("    %-56s refused %s, sender scored %d, %.0f us\n", v[i].name, fRefused ? "yes" : "NO", p->nMisbehavior,
                   1e6 * m.Cpu());
            ok(fRefused, v[i].name);
            if (v[i].nExpectScore > 0)
                ok(p->nMisbehavior == v[i].nExpectScore, "and scored as section 8 says");
            else if (v[i].nExpectScore == -2)
                ok(p->nMisbehavior == 0, "and not scored: valid on its own line, as pool zero treats an old honest share");
            else if (v[i].nExpectScore < 0)
                ok(p->nMisbehavior > 0, "and its sender scored (it is invalid in itself)");
        }
        // Another network's pool: its id is not carried here: unread, unscored.
        {
            AtkPool X;
            X.rec = A.rec;
            X.rules = A.rules;
            poolreg::PoolId(A.rec.Encode(), otherMagic, X.rules.poolId.begin());
            X.id = X.rules.poolId;
            p2pool::ShareChain mx(X.rules, false);
            p2pool::Share s = RulesShare(mx, main, 0, AtkPayTo(1), t);
            CNode* p = newPeer(true, "BF1atk-replay");
            SendRegItem(p, "p2xshare", X.id, p2pool::ShareX(s));
            ok(p->nMisbehavior == 0 && RegShares(A.id) == 40,
               "a pool of another network (its id has that network's magic in it): dropped unread, nobody scored");
        }
        // Pool zero is untouched by all of it.
        {
            ok(AtkZeroSize() == nZero && P2PoolShareWorkTokens() == nZeroWork && P2PoolHistoryServeTokens() == nZeroServe &&
               P2PoolOrphanCount() == 0 && pOld->nMisbehavior == 0 && !SentRegMessage(pOld),
               "pool zero's chain, budgets and orphans untouched; a 1.2.34 peer sent nothing of the registry");
            printf("    registered share-work tokens %d -> %d; pool zero's unchanged at %d\n", nRegWork,
                   P2PoolRegisteredShareWorkTokens(), nZeroWork);
        }
    }
    AtkFree(vFree);

    // ---- with RandomX: forged work, and a forged deep history
    {
        P2PoolResetForTest(bnFloor, true);
        PoolBurnsOpenForTest(true);
        double dHash;
        {
            AtkPool Z;
            Z.rec = AtkRecord("atk-shares-z");
            p2pool::RulesForRegistered(Z.rec, magic, Z.rules, err);
            p2pool::ShareChain mz(Z.rules, false);
            p2pool::Share s = RulesShare(mz, main, 0, AtkPayTo(1), (unsigned int)main.nNow - 600);
            AtkMeter m;
            const int n = 200;
            for (int i = 0; i < n; i++)
            {
                s.nNonce = i;
                (void)s.Header().GetPoWHash();
            }
            dHash = m.Cpu() / n;
            printf("  one RandomX check of a share on this machine: %.2f ms\n", dHash * 1000);
        }
        AtkPool B;
        B.rec = AtkRecord("atk-shares-b");
        p2pool::RulesForRegistered(B.rec, magic, B.rules, err);
        B.id = B.rules.poolId;
        ok(P2PoolRegAddForTest(B.rec, true, false, true, err), "a registered pool to mine joins (RandomX on)");
        newPeer(false, "BF1atk-announcer-b");
        P2PoolRegTickForTest();
        P2PoolRegAgeForTest(121);
        P2PoolRegTickForTest();
        p2pool::ShareChain mirror(B.rules, false);
        const unsigned int t = (unsigned int)main.nNow - 30 * 60;
        p2pool::Share g = RulesShare(mirror, main, 0, AtkPayTo(1), t);   // work is not ground: it fails the target

        // Forged work, from fresh unproven connections: each is hashed
        // while the registered budget lasts, then refused unscored.
        {
            const unsigned int nForged = AtkEnv("ATTACK_FORGED", 400);
            unsigned int nScored = 0, nUnscored = 0;
            AtkMeter m;
            const int nTokens0 = P2PoolRegisteredShareWorkTokens();
            for (unsigned int i = 0; i < nForged; i++)
            {
                CNode* p = NewRegTestNode(true, strprintf("BF1atk-forge%u", i).c_str());
                vFree.push_back(p);
                P2PoolOnVersion(p);
                p2pool::Share s = g;
                s.nNonce = 1000 + i;
                SendRegItem(p, "p2xshare", B.id, p2pool::ShareX(s));
                if (p->nMisbehavior)
                    nScored++;
                else
                    nUnscored++;
            }
            printf("  forged work: %u shares from %u new inbound connections: %.2f s CPU (%.1f ms each), %u senders "
                   "scored, %u refused unscored (budget); registered share-work tokens %d -> %d; none held: %s\n",
                   nForged, nForged, m.Cpu(), 1000.0 * m.Cpu() / nForged, nScored, nUnscored, nTokens0,
                   P2PoolRegisteredShareWorkTokens(), RegShares(B.id) == 0 ? "yes" : "NO");
            ok(RegShares(B.id) == 0, "no share with forged work is taken");
            ok((double)nScored <= (double)nTokens0 + 8, "the RandomX hashes spent are bounded by the registered budget, not by the number of shares");
            ok(m.Cpu() <= (nTokens0 + 8) * dHash * 1.5 + 2.0, "CPU spent on the whole flood stays near the budget's worth of hashes");
        }

        // A forged deep history, from an announcer this node dialled.
        {
            AtkPool C;
            C.rec = AtkRecord("atk-shares-c");
            p2pool::RulesForRegistered(C.rec, magic, C.rules, err);
            C.id = C.rules.poolId;
            ok(P2PoolRegAddForTest(C.rec, true, false, true, err), "a second registered pool to mine joins");
            CNode* pF = newPeer(false, "BF1atk-forger");
            SendPoolInv(pF, std::vector<uint256>(1, C.id));
            P2PoolRegTickForTest();
            uint256 id, resume;
            const bool fAsked = LastRegSync(pF, id, resume) && id == C.id;
            p2pool::ShareChain mc(C.rules, false);
            const unsigned int nFake = AtkEnv("ATTACK_FORGED_HISTORY", 360);
            std::vector<p2pool::Share> fake;
            uint256 prev = 0;
            for (unsigned int i = 0; i < nFake; i++)
            {
                p2pool::Share s = RulesShare(mc, main, prev, AtkPayTo(i % 5), t + 5 * i);
                mc.Add(s, main, err);
                prev = s.GetId();
                fake.push_back(s);
            }
            AtkMeter m;
            for (size_t i = 0; i < fake.size(); i += 100)
            {
                std::vector<p2pool::Share> part(fake.begin() + i, fake.begin() + std::min(fake.size(), i + 100));
                SendRegPart(pF, C.id, (int)fake.size() - 1, i + 100 >= fake.size() ? 1 : 0, part);
            }
            P2PoolRegAgeForTest(301);
            P2PoolRegTickForTest();
            printf("  forged deep history: %u shares with no work, sent to a dialled announcer's ask: asked %s; %.2f s CPU "
                   "(%.1f ms a share), taken %u shares, announcer scored %d\n",
                   nFake, fAsked ? "yes" : "NO", m.Cpu(), 1000.0 * m.Cpu() / nFake, (unsigned)RegShares(C.id),
                   pF->nMisbehavior);
            ok(fAsked && RegShares(C.id) == 0, "a history with no work behind it is not taken");
            ok(pF->nMisbehavior > 0, "and the peer that sent it is scored");
        }
    }

    AtkFree(vFree);
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-shares: all passed" : "attack-shares: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- attack-flood: messages for pools not carried, oversized shares, asks --
//
// SPEC section 12, "flooding p2x* for pools not carried" and the budgets of
// sections 8 and 11. The flood is fed to the handlers the message thread
// feeds; CPU is process CPU, memory the resident set. (A real socket adds the
// cost of reading the bytes in: the kernel's, not the handler's.)

static int RunAttackFloodSelfTest()
{
    printf("attack-flood\n");
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
    P2PoolResetForTest(bnFloor, false);
    PoolBurnsOpenForTest(true);
    const unsigned char* magic = (const unsigned char*)pchMessageStart;
    std::vector<CNode*> vFree;
    auto newPeer = [&vFree](bool fIn, const char* psz) {
        CNode* p = NewRegTestNode(fIn, psz);
        vFree.push_back(p);
        P2PoolOnVersion(p);
        return p;
    };
    AtkPool A;
    A.rec = AtkRecord("atk-flood-a");
    p2pool::RulesForRegistered(A.rec, magic, A.rules, err);
    A.id = A.rules.poolId;
    ok(P2PoolRegAddForTest(A.rec, true, false, true, err), "a registered pool to mine joins");
    CNode* pAnn = newPeer(false, "BF1atk-announcer");
    P2PoolRegTickForTest();
    P2PoolRegAgeForTest(121);
    P2PoolRegTickForTest();
    p2pool::ShareChain mirror(A.rules, false);
    uint256 prev = 0;
    const unsigned int t = (unsigned int)main.nNow - 3600;
    const unsigned int nLine = AtkEnv("ATTACK_LINE", 600);
    for (unsigned int i = 0; i < nLine; i++)
    {
        p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo(i % 40), t + 5 * i);
        mirror.Add(s, main, err);
        P2PoolSubmitShare(s, err);
        prev = s.GetId();
    }
    SendPoolInv(pAnn, std::vector<uint256>(1, A.id));
    P2PoolRegTickForTest();
    P2PoolRegStatusInfo st0;
    P2PoolRegStatus(A.id, st0);
    ok(st0.nShares >= 400, "a line of the pool is held here (a window of shares: the rest were pruned by the window)");
    printf("  node: pool line %u shares, %.2f MB; RSS %ld KB, peak %ld KB\n", (unsigned)st0.nShares, st0.nBytes / 1e6,
           AtkProcKB("VmRSS:"), AtkProcKB("VmHWM:"));
    const size_t nZero0 = AtkZeroSize();
    const size_t nShares0 = st0.nShares;

    const unsigned int N = AtkEnv("ATTACK_FLOOD_N", 300000);
    // F1: p2xshare for pools not carried.
    {
        CNode* p = newPeer(true, "BF1atk-f1");
        const size_t nQ0 = p->vSend.size();
        AtkMeter m;
        for (unsigned int i = 0; i < N; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << Hash(BEGIN(i), END(i)) << std::vector<char>(200, 'x');
            SendP2PoolTest(p, "p2xshare", ss);
        }
        printf("  F1 p2xshare for %u pools not carried: %.2f us CPU a message (message built and handled), RSS %+ld KB, "
               "scored %d, bytes sent back %u\n",
               N, 1e6 * m.Cpu() / N, m.RssDelta(), p->nMisbehavior, (unsigned)(p->vSend.size() - nQ0));
        ok(p->nMisbehavior == 0 && p->vSend.size() == nQ0, "dropped at the pool id: nobody scored, nothing answered");
    }
    // F1b: the same with 250 KB messages (the handler never reads past the id).
    {
        CNode* p = newPeer(true, "BF1atk-f1b");
        const unsigned int n = 2000;
        AtkMeter m;
        for (unsigned int i = 0; i < n; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << Hash(BEGIN(i), END(i)) << std::vector<char>(250 * 1024, 'x');
            SendP2PoolTest(p, "p2xshare", ss);
        }
        printf("  F1b p2xshare of 250 KB for pools not carried: %u messages, %.1f us CPU a message including building them\n",
               n, 1e6 * m.Cpu() / n);
        ok(p->nMisbehavior == 0, "big ones too: unread, unscored");
    }
    // F2: p2xsync and p2xgetsh for pools not carried.
    {
        CNode* p = newPeer(true, "BF1atk-f2");
        AtkMeter m;
        for (unsigned int i = 0; i < N; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << Hash(BEGIN(i), END(i));
            if (i & 1)
                ss << uint256(0);
            else
                ss << std::vector<uint256>(1, uint256(i));
            SendP2PoolTest(p, (i & 1) ? "p2xsync" : "p2xgetsh", ss);
        }
        const size_t nNone = CountSent(p, "p2xnone");
        printf("  F2 p2xsync/p2xgetsh for pools not carried: %u messages, %.2f us CPU a message, p2xnone answers %u "
               "(limit 8 an interval), scored %d, send queue %u bytes\n",
               N, 1e6 * m.Cpu() / N, (unsigned)nNone, p->nMisbehavior, (unsigned)p->vSend.size());
        ok(nNone <= 8 && p->nMisbehavior == 0, "at most 8 p2xnone an interval a connection, the rest dropped, nobody scored");
    }
    // F3: history asks for a carried pool, past the budgets.
    {
        CNode* p = newPeer(true, "BF1atk-f3");
        const unsigned int nAsks = 2000;
        AtkMeter m;
        for (unsigned int i = 0; i < nAsks; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << A.id << uint256(0);
            SendP2PoolTest(p, "p2xsync", ss);
            P2PoolServeDeferred();
        }
        for (int k = 0; k < 3000; k++)
            P2PoolServeDeferred();
        const size_t nParts = CountSent(p, "p2xshares");
        const size_t nBytes = AtkSentBytes(p);
        printf("  F3 %u p2xsync asks for a carried pool from one unproven inbound connection: %.2f s CPU, %u parts "
               "sent (%.2f MB), against a line of %.2f MB (one history's worth is the limit)\n",
               nAsks, m.Cpu(), (unsigned)nParts, nBytes / 1e6, st0.nBytes / 1e6);
        ok(nBytes <= (size_t)(st0.nBytes * 1.2) + 100000, "no more than one history's worth is sent to an unproven connection, however many asks");
    }
    // F4: oversized shares for the carried pool.
    {
        const unsigned int n = 300;
        unsigned int nScored = 0;
        AtkMeter m;
        for (unsigned int i = 0; i < n; i++)
        {
            CNode* p = newPeer(true, strprintf("BF1atk-f4-%u", i).c_str());
            p2pool::Share s = RulesShare(mirror, main, prev, AtkPayTo(1), t + 5 * nLine + i);
            for (int k = 0; k < 6; k++)
                s.coinbase.vout.push_back(CTxOut(0, CScript(std::vector<unsigned char>(50 * 1024, 0x6a))));
            s.hashMerkleRoot = s.coinbase.GetHash();
            SendRegItem(p, "p2xshare", A.id, p2pool::ShareX(s));
            if (p->nMisbehavior)
                nScored++;
        }
        P2PoolRegStatusInfo st;
        P2PoolRegStatus(A.id, st);
        printf("  F4 %u shares of about 300 KB for the carried pool (cap 256 KB), building each included: %.2f ms CPU "
               "each, %u senders scored; pool still %u shares\n",
               n, 1000.0 * m.Cpu() / n, nScored, (unsigned)st.nShares);
        ok(st.nShares == nShares0, "oversized shares are not taken");
    }
    // F5: poolwho, poolinv, poolat floods.
    {
        CNode* p = newPeer(true, "BF1atk-f5");
        AtkMeter m;
        for (unsigned int i = 0; i < N; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << A.id;
            SendP2PoolTest(p, "poolwho", ss);
        }
        printf("  F5a poolwho: %u messages, %.2f us CPU a message, %u poolat answers (limit 8 an interval)\n", N,
               1e6 * m.Cpu() / N, (unsigned)CountSent(p, "poolat"));
        m.Reset();
        for (unsigned int i = 0; i < N / 3; i++)
        {
            std::vector<uint256> v;
            for (unsigned int k = 0; k < 32; k++)
                v.push_back(Hash(BEGIN(i), END(i)) ^ uint256(k));
            SendPoolInv(p, v);
        }
        printf("  F5b poolinv of 32 ids: %u messages, %.2f us CPU a message, RSS %+ld KB, scored %d\n", N / 3,
               1e6 * m.Cpu() / (N / 3), m.RssDelta(), p->nMisbehavior);
        m.Reset();
        for (unsigned int i = 0; i < N / 3; i++)
        {
            CDataStream ss(SER_NETWORK, VERSION);
            ss << Hash(BEGIN(i), END(i)) << std::vector<std::string>(32, std::string(60, 'a'));
            SendP2PoolTest(p, "poolat", ss);
        }
        printf("  F5c unasked poolat of 32 addresses: %u messages, %.2f us CPU a message, scored %d\n", N / 3,
               1e6 * m.Cpu() / (N / 3), p->nMisbehavior);
        ok(CountSent(p, "poolat") <= 8, "poolwho answered at most 8 an interval a connection");
    }

    P2PoolRegStatusInfo stEnd;
    P2PoolRegStatus(A.id, stEnd);
    ok(AtkZeroSize() == nZero0 && stEnd.nShares == nShares0, "pool zero and the carried pool unchanged after every flood");
    printf("  end: RSS %ld KB, peak %ld KB\n", AtkProcKB("VmRSS:"), AtkProcKB("VmHWM:"));

    AtkFree(vFree);
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-flood: all passed" : "attack-flood: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

// ---- attack-withhold and attack-stale: the line from the wrong peers ------

static int RunAttackWithholdSelfTest()
{
    printf("attack-withhold\n");
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
    const unsigned int nW = AtkEnv("ATTACK_WITHHOLDERS", 16);

    AtkPool A;
    A.rec = AtkRecord("atk-withhold");
    p2pool::RulesForRegistered(A.rec, magic, A.rules, err);
    A.id = A.rules.poolId;
    p2pool::ShareChain mirror(A.rules, false);
    std::vector<p2pool::Share> line = RegLine(mirror, main, 60, 3);

    for (int mode = 0; mode < 3; mode++)
    {
        // mode 0: withholders stay silent; 1: they answer p2xnone; 2: nobody announces, only poolwho
        P2PoolResetForTest(bnFloor, false);
        PoolBurnsOpenForTest(true);
        std::vector<CNode*> vFree;
        ok(P2PoolRegAddForTest(A.rec, true, false, true, err), "a registered pool to mine joins, no copy of its line here");
        std::vector<CNode*> vWh;
        for (unsigned int i = 0; i < nW; i++)
        {
            CNode* p = NewRegTestNode(false, strprintf("BF1atk-guardian%u", i).c_str());
            vFree.push_back(p);
            vWh.push_back(p);
            P2PoolOnVersion(p);
        }
        CNode* pM = NewRegTestNode(false, "BF1atk-miner");
        vFree.push_back(pM);
        P2PoolOnVersion(pM);
        P2PoolRegTickForTest();
        if (mode != 2)
        {
            for (unsigned int i = 0; i < nW; i++)
                SendPoolInv(vWh[i], std::vector<uint256>(1, A.id));
            SendPoolInv(pM, std::vector<uint256>(1, A.id));
        }
        std::set<CNode*> setAsked;
        unsigned int nAskedWh = 0;
        int64 nSimSecs = 0;
        bool fMAsked = false, fTaken = false;
        for (int round = 0; round < 80 && !fTaken; round++)
        {
            P2PoolRegTickForTest();
            for (unsigned int i = 0; i < nW; i++)
            {
                uint256 id, resume;
                if (!setAsked.count(vWh[i]) && LastRegSync(vWh[i], id, resume) && id == A.id)
                {
                    setAsked.insert(vWh[i]);
                    nAskedWh++;
                    if (mode == 1)
                        SendRegItem(vWh[i], "p2xnone", A.id, std::string());
                }
            }
            uint256 id, resume;
            if (!fMAsked && LastRegSync(pM, id, resume) && id == A.id)
            {
                fMAsked = true;
                SendRegPart(pM, A.id, (int)line.size() - 1, 1, line);
            }
            const int64 nStep = mode == 1 ? 61 : 181;
            P2PoolRegAgeForTest(nStep);
            nSimSecs += nStep;
            P2PoolRegTickForTest();
            fTaken = RegShares(A.id) == line.size();
            string why;
            if (!fTaken && P2PoolMinedReady(why))
                break;      // the node's own line has started: nothing came in time
        }
        bool fWho = false;
        for (unsigned int i = 0; i < nW; i++)
        {
            std::vector<unsigned char> who;
            if (LastSent(vWh[i], "poolwho", who))
                fWho = true;
        }
        static const char* const vMode[3] = { "silent guardians", "guardians answering p2xnone", "no guardian announces" };
        printf("  %s: %u of %u asked before the miner's turn (the miner is the last in the node's order, the worst place); "
               "line %s after %lld simulated seconds (%.1f minutes); the miner asked: %s; poolwho sent: %s\n",
               vMode[mode], nAskedWh, nW, fTaken ? "taken whole" : "NOT taken", (long long)nSimSecs, nSimSecs / 60.0,
               fMAsked ? "yes" : "no", fWho ? "yes" : "no");

        // The node's own line has started if the line did not come in time (a
        // mined pool starts after 10 minutes whatever was asked). It mines two
        // shares on it alone; then the live miner's next shares arrive.
        P2PoolRegStatusInfo st;
        P2PoolRegStatus(A.id, st);
        const bool fOwnLine = !fTaken && st.nShares == 0;
        if (fOwnLine)
        {
            p2pool::ShareChain mineN(A.rules, false);
            uint256 pv = 0;
            for (int i = 0; i < 2; i++)
            {
                p2pool::Share s = RulesShare(mineN, main, pv, AtkPayTo(77), (unsigned int)main.nNow - 100 + 20 * i);
                mineN.Add(s, main, err);
                P2PoolSubmitShare(s, err);
                pv = s.GetId();
            }
        }
        // M's next three shares, pushed to the node.
        {
            uint256 pv = line.back().GetId();
            std::vector<p2pool::Share> ext;
            for (int i = 0; i < 3; i++)
            {
                p2pool::Share s = RulesShare(mirror, main, pv, AtkPayTo(3), (unsigned int)main.nNow - 30 + 10 * i);
                mirror.Add(s, main, err);
                pv = s.GetId();
                ext.push_back(s);
            }
            std::vector<p2pool::Share> all = line;
            all.insert(all.end(), ext.begin(), ext.end());
            for (size_t i = 0; i < ext.size(); i++)
                SendRegItem(pM, "p2xshare", A.id, p2pool::ShareX(ext[i]));
            for (int k = 0; k < 6; k++)
            {
                uint256 id2, resume2;
                if (LastRegSync(pM, id2, resume2) && id2 == A.id)
                    SendRegPart(pM, A.id, (int)all.size() - 1, 1, all);
                P2PoolRegAgeForTest(61);
                P2PoolRegTickForTest();
            }
            P2PoolRegStatus(A.id, st);
            printf("     then the miner's next 3 shares reached the node%s: tip height %d (the miner's line ends at %d), %u shares held\n",
                   fOwnLine ? ", which had started its own line and mined 2 shares on it" : "", st.nTipHeight,
                   (int)all.size() - 1, (unsigned)st.nShares);
            ok(st.nTipHeight == (int)all.size() - 1, "the node ends on the miner's line, the heavier: its own lone shares are orphaned, the miner's window untouched");
        }
        if (mode == 2)
            ok(fWho, "with nobody announcing, peers are asked who carries the pool (poolwho)");
        AtkFree(vFree);
    }
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-withhold: all passed" : "attack-withhold: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}

static int RunAttackStaleSelfTest()
{
    printf("attack-stale\n");
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
    const unsigned char* magic = (const unsigned char*)pchMessageStart;
    P2PoolResetForTest(bnFloor, false);
    PoolBurnsOpenForTest(true);
    std::vector<CNode*> vFree;
    TestMainView mainNow = AtkMain();
    TestMainView mainOld = AtkMain();
    mainOld.nNow -= 3 * 3600;      // a line whose newest share is hours old: dormant

    AtkPool A;
    A.rec = AtkRecord("atk-stale");
    p2pool::RulesForRegistered(A.rec, magic, A.rules, err);
    A.id = A.rules.poolId;
    p2pool::ShareChain mOld(A.rules, false), mNew(A.rules, false);
    std::vector<p2pool::Share> stale = RegLine(mOld, mainOld, 30, 1);      // 30 shares, hours old
    std::vector<p2pool::Share> live = RegLine(mNew, mainNow, 60, 2);       // 60 shares, live, another miner's

    ok(P2PoolRegAddForTest(A.rec, true, false, true, err), "a registered pool to mine joins, nothing of its line here");
    CNode* pS = NewRegTestNode(false, "BF1atk-stale-guardian");
    CNode* pM = NewRegTestNode(false, "BF1atk-live-miner");
    vFree.push_back(pS);
    vFree.push_back(pM);
    P2PoolOnVersion(pS);
    P2PoolOnVersion(pM);
    P2PoolRegTickForTest();
    SendPoolInv(pS, std::vector<uint256>(1, A.id));
    P2PoolRegTickForTest();
    uint256 id, resume;
    ok(LastRegSync(pS, id, resume) && id == A.id, "the node asks the guardian that announces the pool");
    SendRegPart(pS, A.id, (int)stale.size() - 1, 1, stale);
    P2PoolRegAgeForTest(301);
    P2PoolRegTickForTest();
    P2PoolRegAgeForTest(61);
    P2PoolRegTickForTest();
    P2PoolRegStatusInfo st;
    P2PoolRegStatus(A.id, st);
    printf("  after the stale guardian's line (30 shares, newest 3 hours old): %u shares held, tip height %d\n",
           (unsigned)st.nShares, st.nTipHeight);
    ok(st.nShares == stale.size(), "the stale line is taken when nothing else is offered (an empty tip takes anything checked)");

    // The live miner shows up and pushes its newest shares; the node asks it for the rest.
    SendPoolInv(pM, std::vector<uint256>(1, A.id));
    P2PoolRegTickForTest();
    for (size_t i = 0; i < live.size(); i++)
        SendRegItem(pM, "p2xshare", A.id, p2pool::ShareX(live[i]));
    for (int k = 0; k < 4; k++)
    {
        uint256 id2, resume2;
        if (LastRegSync(pM, id2, resume2) && id2 == A.id)
            SendRegPart(pM, A.id, (int)live.size() - 1, 1, live);
        P2PoolRegAgeForTest(61);
        P2PoolRegTickForTest();
    }
    P2PoolRegStatus(A.id, st);
    printf("  after the live miner's line (60 shares, newest 30 s old): %u shares held, tip height %d (the live line's tip is 59, the stale one's 29)\n",
           (unsigned)st.nShares, st.nTipHeight);
    ok(st.nTipHeight == 59, "the live line replaces the dormant one (live beats dormant, section 10)");
    std::string strLog = ReadWholeFile(DebugLogPath(), 0);
    const bool fWarned = strLog.find("anchor") != std::string::npos || strLog.find("stale or private") != std::string::npos;
    printf("  the anchor warning of section 10 (a line given that does not hold the newest anchored share) in the debug log: %s\n",
           fWarned ? "yes" : "NO: the node has no such check");

    AtkFree(vFree);
    P2PoolResetForTest(bnProofOfWorkLimit, true);
    PoolBurnsOpenForTest(false);
    printf("%s (%d failure%s)\n", nFail == 0 ? "attack-stale: all passed" : "attack-stale: FAILED", nFail,
           nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail ? 1 : 0;
}
