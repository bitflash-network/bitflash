// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The Everpool window (docs/pool-registry.md). What it shows comes from the
// registry index (poolindex.h) and the share chains this node holds
// (p2pool_net.h); a thread reads them and hands over a copy every few
// seconds while the window is open, so a frame never waits on the index's or
// the share chain's lock. Creating a pool goes through EverpoolCreate
// (jsonrpc.h), which is `poolcreate everpool` itself: the same defaults, the
// same checks, the same burn. Which pool P2Pool mines is fixed when the node
// starts, so choosing one writes p2pool-choice and takes effect on restart.

#include "imgui/imgui.h"
#include "headers_core.h"
#include <algorithm>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "p2pool_net.h"
#include "poolindex.h"
#include "jsonrpc.h"
#include "gui_explorer.h"
#include "gui_everpool.h"

bool g_showEverpool = false;

string DateTimeStr(int64 nTime);

static const int REFRESH_SECONDS = 5;
// Lookalike names listed per pool, as poollist bounds them.
static const size_t SAME_NAME_SHOWN = 32;
// Anchors shown in the detail panel.
static const size_t ANCHORS_SHOWN = 10;

static const ImVec4 COL_GREEN(0.35f, 1.0f, 0.45f, 1.0f);
static const ImVec4 COL_AMBER(1.0f, 0.75f, 0.25f, 1.0f);
static const ImVec4 COL_RED(1.0f, 0.40f, 0.40f, 1.0f);
static const ImVec4 COL_NOTE(1.0f, 0.85f, 0.40f, 1.0f);

// ---- What a refresh hands over ---------------------------------------------

struct EvAnchor
{
    int nHeight;
    uint256 hashBlock;
    int64 nTime;   // 0: not in this node's block index
};

struct EvRow
{
    uint256 id;
    std::string strId, strFp, strName;
    bool fZero;
    poolreg::PoolRecord rec;
    int nStatus;              // PoolStatus; POOL_UNKNOWN for a burn not in a block yet
    int nConfirmations;
    int nFirstHeight;         // -1: pool zero, never burned
    int64 nFirstTime;
    uint256 txidFirst;
    int nAppearances;
    int nClaims;              // anchors in the last 720 blocks
    std::vector<EvAnchor> vAnchors;
    bool fHeld;               // a share chain of it is on this node
    P2PoolRegStatusInfo st;   // pool zero: fMined, nShares, nTipHeight, work only
    std::vector<std::string> vSameName;
    double dHashRate;         // estimated from the line's work; < 0 unknown
    bool fJustSent;           // sent from this window, not in a block yet
    std::string strSentTxid;
    EvRow() : id(0), fZero(false), nStatus(POOL_UNKNOWN), nConfirmations(0), nFirstHeight(-1), nFirstTime(0),
              txidFirst(0), nAppearances(0), nClaims(0), fHeld(false), dHashRate(-1.0), fJustSent(false)
    {
        memset(&st, 0, sizeof(st));
        st.work = 0;
    }
};

struct EvSnapshot
{
    int nIndexHeight;
    bool fSynced, fRebuilding;
    std::vector<EvRow> rows;
    // This wallet's part of the window of the pool mined, when there is one.
    bool fHavePart;
    uint256 idMined;
    uint64 nMineWork, nTotalWork;
    unsigned int nMinedFeeBps;
    int64 nBlockValue;
    bool fMinedReady;
    std::string strMinedWhy;
    int nMiners;
    uint64 nMinerShares;
    double dMinerHashRate;
    int64 nTime;
    bool fP2PoolBusy;         // the share chain's lock was held: what this node holds is not known
    EvSnapshot() : nIndexHeight(-1), fSynced(false), fRebuilding(false), fHavePart(false), idMined(0),
                   nMineWork(0), nTotalWork(0), nMinedFeeBps(0), nBlockValue(0), fMinedReady(true), nMiners(0),
                   nMinerShares(0), dMinerHashRate(0.0), nTime(0), fP2PoolBusy(false) {}
};

// A pool this window sent the burn of, shown as such until the index has it.
struct EvSent
{
    uint256 id;
    std::string strName, strTxid;
    poolreg::PoolRecord rec;
};

// The thread's side; what it touches is never destroyed (a read may still
// run when the program exits).
static std::mutex& g_lock = *new std::mutex;
static bool g_working = false;
static bool g_done = false;
static EvSnapshot& g_result = *new EvSnapshot;
static std::vector<EvSent>& g_sent = *new std::vector<EvSent>;

static EvSnapshot g_shown;
static bool g_haveShown = false;
static int64 g_askedAt = 0;
static uint256 g_selected = 0;
static bool g_haveSelected = false;

// ---- Helpers ----------------------------------------------------------------

static const char* Unit() { return IsTestNet() ? "tBTF" : "BTF"; }

static double WorkToDouble(uint256 w)
{
    double d = 0.0;
    for (int i = 31; i >= 0; i--)
        d = d * 256.0 + (double)w.begin()[i];
    return d;
}

static std::string FmtHashRate(double d)
{
    if (d < 0.0)
        return "unknown";
    if (d >= 1e9) return strprintf("%.2f GH/s", d / 1e9);
    if (d >= 1e6) return strprintf("%.2f MH/s", d / 1e6);
    if (d >= 1e3) return strprintf("%.2f kH/s", d / 1e3);
    return strprintf("%.0f H/s", d);
}

static std::string FmtDuration(int64 n)
{
    if (n < 0) n = 0;
    if (n < 3600)      return strprintf("%lld min", (long long)(n / 60));
    if (n < 2 * 86400) return strprintf("%lld h", (long long)(n / 3600));
    return strprintf("%lld days", (long long)(n / 86400));
}

static std::string FeePercent(unsigned int nBps)
{
    return strprintf("%u.%02u%%", nBps / 100, nBps % 100);
}

static ImVec4 FeeColor(unsigned int nBps)
{
    if (nBps == 0)   return COL_GREEN;
    if (nBps <= 200) return COL_AMBER;
    return COL_RED;
}

static std::string FeeAddress(const poolreg::PoolRecord& rec)
{
    if (rec.nFeeType == poolreg::FEE_NONE)
        return std::string();
    uint160 h;
    memcpy(h.begin(), rec.feeHash, sizeof(rec.feeHash));
    return rec.nFeeType == poolreg::FEE_P2SH ? Hash160ToScriptAddress(h) : Hash160ToAddress(h);
}

static uint256 IdOf(const poolreg::PoolRecord& rec)
{
    uint256 id = 0;
    poolreg::PoolId(rec.Encode(), (const unsigned char*)pchMessageStart, id.begin());
    return id;
}

static int64 BlockTime(const uint256& hash)
{
    int64 n = 0;
    CRITICAL_BLOCK(cs_main)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end() && mi->second)
            n = mi->second->nTime;
    }
    return n;
}

static void FillAnchors(const std::vector<CPoolAnchor>& v, EvRow& row)
{
    for (size_t i = 0; i < v.size() && row.vAnchors.size() < ANCHORS_SHOWN; i++)
    {
        EvAnchor a;
        a.nHeight = v[i].nHeight;
        a.hashBlock = v[i].hashBlock;
        a.nTime = BlockTime(v[i].hashBlock);
        row.vAnchors.push_back(a);
    }
}

// The line's work over its last window, spread over the time that many
// shares take at the pool's spacing: what the pool's own retarget aims at.
static double EstimateHashRate(const uint256& work, int nTipHeight, const poolreg::PoolRecord& rec)
{
    if (nTipHeight < 1 || work == 0 || rec.nSpacing == 0)
        return -1.0;
    double n = std::min((double)(nTipHeight + 1), (double)rec.nWindow);
    return WorkToDouble(work) / (n * (double)rec.nSpacing);
}

static bool IsOurScript(const std::vector<unsigned char>& v)
{
    return IsMine(CScript(v.begin(), v.end()));
}

// ---- The refresh (on its own thread) ---------------------------------------

static void Load(EvSnapshot& snap, std::vector<EvSent> vSent)
{
    PoolIndexState(snap.nIndexHeight, snap.fSynced, snap.fRebuilding);
    std::vector<CPoolInfo> vReg;
    PoolIndexList(vReg);
    const P2PoolChoiceInfo running = P2PoolChoiceRunning();

    // Pool zero, always first: the pool every P2Pool miner mines by default.
    {
        EvRow z;
        z.fZero = true;
        z.rec = poolreg::PoolZero();
        z.id = IdOf(z.rec);
        z.strName = z.rec.name;
        z.nStatus = POOL_ACTIVE;
        if (!vReg.empty() && vReg[0].fZero)
        {
            z.nClaims = vReg[0].nAnchorsInWindow;
            z.nAppearances = vReg[0].nAppearances;
            z.nFirstHeight = vReg[0].first.nHeight;
            FillAnchors(vReg[0].vRecentAnchors, z);
        }
        z.fHeld = true;
        z.st.fCarried = true;
        z.st.nFetch = P2PoolRegStatusInfo::FETCH_COMPLETE;
        snap.rows.push_back(z);
    }
    for (size_t i = 0; i < vReg.size(); i++)
    {
        const CPoolInfo& info = vReg[i];
        if (info.fZero)
            continue;
        EvRow r;
        r.id = info.id;
        r.rec = info.rec;
        r.strName = info.rec.name;
        r.nStatus = info.nStatus;
        r.nConfirmations = info.nConfirmations;
        r.nFirstHeight = info.first.nHeight;
        r.txidFirst = info.first.txid;
        r.nFirstTime = info.first.nHeight >= 0 ? BlockTime(info.first.hashBlock) : 0;
        r.nAppearances = info.nAppearances;
        r.nClaims = info.nAnchorsInWindow;
        FillAnchors(info.vRecentAnchors, r);
        snap.rows.push_back(r);
    }

    // What this node holds of each pool, under the share chain's lock and
    // never waiting for it: while the node checks a long history of shares
    // it holds that lock for minutes, and the list is shown meanwhile with
    // this part marked busy. (cs_main is never taken inside it: block times
    // were read above.)
    const bool fMinedHere = fP2PoolMode && running.nKind != P2POOL_CHOICE_LOCAL;
    std::vector<p2pool::WindowShare> window;
    bool fWindow = false;
    snap.fP2PoolBusy = true;
    TRY_CRITICAL_BLOCK(cs_p2pool)
    {
        snap.fP2PoolBusy = false;
        EvRow& z = snap.rows[0];
        p2pool::ShareChain& c = P2PoolChain();
        z.st.fMined = fP2PoolMode && &P2PoolMinedChain() == &c;
        z.st.nShares = c.Size();
        z.st.nTipHeight = c.Height(c.Tip());
        z.st.work = c.TipLineWork();
        for (size_t i = 1; i < snap.rows.size(); i++)
            snap.rows[i].fHeld = P2PoolRegStatus(snap.rows[i].id, snap.rows[i].st);
        if (fMinedHere)
        {
            snap.fMinedReady = P2PoolMinedReady(snap.strMinedWhy);
            fWindow = P2PoolMinedWindow(window, snap.idMined, snap.nMinedFeeBps);
        }
    }
    for (size_t i = 0; i < snap.rows.size(); i++)
        if (snap.rows[i].fHeld && snap.rows[i].st.fCarried)
            snap.rows[i].dHashRate = EstimateHashRate(snap.rows[i].st.work, snap.rows[i].st.nTipHeight,
                                                      snap.rows[i].rec);
    // Burns this window sent that no block holds yet, and those this wallet
    // holds unconfirmed (sent before a restart, or with poolcreate): the
    // wallet sends them again until they are mined.
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            if (it->second.GetDepthInMainChain() > 0)
                continue;
            for (size_t k = 0; k < it->second.vout.size(); k++)
            {
                std::vector<unsigned char> record;
                poolreg::PoolRecord rec;
                if (!PoolBurnedRecord(it->second.vout[k], record, rec))
                    continue;
                EvSent s;
                poolreg::PoolId(record, (const unsigned char*)pchMessageStart, s.id.begin());
                s.strName = rec.name;
                s.strTxid = it->first.GetHex();
                s.rec = rec;
                bool fHave = false;
                for (size_t m = 0; m < vSent.size() && !fHave; m++)
                    fHave = vSent[m].id == s.id;
                if (!fHave)
                    vSent.push_back(s);
            }
        }
    }
    for (size_t i = 0; i < vSent.size(); i++)
    {
        bool fKnown = false;
        for (size_t k = 0; k < snap.rows.size() && !fKnown; k++)
            fKnown = snap.rows[k].id == vSent[i].id;
        if (fKnown)
            continue;
        EvRow r;
        r.id = vSent[i].id;
        r.rec = vSent[i].rec;
        r.strName = vSent[i].strName;
        r.fJustSent = true;
        r.strSentTxid = vSent[i].strTxid;
        snap.rows.push_back(r);
    }
    for (size_t i = 0; i < snap.rows.size(); i++)
    {
        snap.rows[i].strId = snap.rows[i].id.GetHex();
        snap.rows[i].strFp = snap.rows[i].strId.substr(0, 8);
    }

    // Pool zero first; then the pools whose line this node holds, by its
    // work; then by claims; ties in the order of first appearance (poollist's).
    std::stable_sort(snap.rows.begin() + 1, snap.rows.end(), [](const EvRow& x, const EvRow& y) {
        bool fX = x.fHeld && x.st.fCarried, fY = y.fHeld && y.st.fCarried;
        if (fX != fY)
            return fX;
        if (fX && x.st.work != y.st.work)
            return y.st.work < x.st.work;
        if (x.fJustSent != y.fJustSent)
            return y.fJustSent;
        return x.nClaims > y.nClaims;
    });

    // Names alike (poollist's comparison), pool zero's included.
    map<std::string, std::vector<size_t> > mapNames;
    for (size_t i = 0; i < snap.rows.size(); i++)
        mapNames[PoolLookalikeKey(snap.rows[i].strName)].push_back(i);
    for (size_t i = 0; i < snap.rows.size(); i++)
    {
        const std::vector<size_t>& v = mapNames[PoolLookalikeKey(snap.rows[i].strName)];
        for (size_t k = 0; k < v.size() && snap.rows[i].vSameName.size() < SAME_NAME_SHOWN; k++)
            if (v[k] != i)
                snap.rows[i].vSameName.push_back(snap.rows[v[k]].fZero ? std::string("pool zero")
                                                                       : snap.rows[v[k]].strFp);
    }

    // The pool mined: is it ready, and this wallet's part of its window.
    if (fMinedHere)
    {
        if (fWindow)
        {
            P2PoolWindowPart(window, IsOurScript, snap.nMineWork, snap.nTotalWork);
            snap.fHavePart = snap.nTotalWork > 0;
            CBlock blk;
            snap.nBlockValue = blk.GetBlockValue(nBestHeight + 1, 0);
        }
        std::vector<PoolWorkerStatView> workers;
        GetPoolWorkerStats(workers);
        for (size_t i = 0; i < workers.size(); i++)
        {
            snap.nMiners++;
            snap.nMinerShares += workers[i].totalShares;
            snap.dMinerHashRate += workers[i].hashRate;
        }
    }
    snap.nTime = GetTime();
}

static void LoadThread(std::vector<EvSent> vSent)
{
    EvSnapshot snap;
    try
    {
        Load(snap, vSent);
    }
    catch (const std::exception& e)
    {
        printf("everpool window: refresh failed: %s\n", e.what());
    }
    std::lock_guard<std::mutex> lk(g_lock);
    g_result = snap;
    g_working = false;
    g_done = true;
}

static void AskRefresh()
{
    std::lock_guard<std::mutex> lk(g_lock);
    if (g_working)
        return;
    g_working = true;
    g_askedAt = GetTime();
    std::thread(LoadThread, g_sent).detach();
}

// The choice saved for the next start, read again with each refresh and
// after every save (not on every frame).
static bool g_savedFile = false;
static int g_savedKind = P2POOL_CHOICE_OFF;
static uint256 g_savedId = 0;

static void ReadSaved()
{
    g_savedFile = P2PoolChoiceRead(g_savedKind, g_savedId);
}

static void TakeRefresh()
{
    std::lock_guard<std::mutex> lk(g_lock);
    if (!g_done)
        return;
    g_shown = g_result;
    g_haveShown = true;
    g_done = false;
    ReadSaved();
}

// ---- "Mine this pool" -------------------------------------------------------

static std::string g_mineMsg;
static bool g_mineNeedsRestart = false;

static std::string ChoiceLabel(int nKind, const uint256& id, const std::string& strLocal)
{
    switch (nKind)
    {
    case P2POOL_CHOICE_OFF:   return "P2Pool off";
    case P2POOL_CHOICE_ZERO:  return "pool zero (the default pool)";
    case P2POOL_CHOICE_LOCAL: return "the local pool \"" + strLocal + "\"";
    default:
        for (size_t i = 0; i < g_shown.rows.size(); i++)
            if (g_shown.rows[i].id == id)
                return "\"" + g_shown.rows[i].strName + "\" #" + g_shown.rows[i].strFp;
        return "the pool #" + id.GetHex().substr(0, 8);
    }
}

static bool SameChoice(int nKindA, const uint256& idA, int nKindB, const uint256& idB)
{
    return nKindA == nKindB && (nKindA != P2POOL_CHOICE_REGISTERED || idA == idB);
}

static void SaveChoice(int nKind, const uint256& id)
{
    std::string err;
    bool fWritten = P2PoolChoiceWrite(nKind, id, err);
    ReadSaved();
    if (!fWritten)
    {
        g_mineMsg = "Not saved: " + err;
        g_mineNeedsRestart = false;
        return;
    }
    const P2PoolChoiceInfo running = P2PoolChoiceRunning();
    int nRunning = fP2PoolMode ? running.nKind : P2POOL_CHOICE_OFF;
    if (SameChoice(nKind, id, nRunning, running.id))
    {
        g_mineMsg = "Saved. This is what Bitflash already does now.";
        g_mineNeedsRestart = false;
        return;
    }
    g_mineMsg = "Saved: " + ChoiceLabel(nKind, id, "") +
                ". Which pool P2Pool mines is set when Bitflash starts, so this takes effect after a restart.";
    g_mineNeedsRestart = true;
}

static void DrawStratumLine()
{
    std::string strAddr = strprintf("127.0.0.1:%u", (unsigned)nP2PoolPort);
    ImGui::TextUnformatted("Point the Bitflash Miner or XMRig at");
    ImGui::SameLine();
    ImGui::TextColored(COL_GREEN, "%s", strAddr.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy##stratum"))
        ImGui::SetClipboardText(strAddr.c_str());
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("XMRig by hand: xmrig -a rx/0 -o %s -u p2pool -p x\n"
                          "The stratum has no login and listens on this machine only.", strAddr.c_str());
    if (!strP2PoolBind.empty())
        ImGui::TextDisabled("Also on your local network: %s:%u", strP2PoolBind.c_str(), (unsigned)nP2PoolPort);
}

static void DrawMiningBox()
{
    const P2PoolChoiceInfo running = P2PoolChoiceRunning();
    const int nSaved = g_savedKind;
    const uint256 idSaved = g_savedId;
    const bool fSavedFile = g_savedFile;

    ImGui::SeparatorText("Your P2Pool mining");
    if (fP2PoolMode)
    {
        ImGui::Text("Mining now:");
        ImGui::SameLine();
        ImGui::TextColored(COL_GREEN, "%s", ChoiceLabel(running.nKind, running.id, running.strLocal).c_str());
        if (running.fFromCommandLine)
        {
            ImGui::SameLine();
            ImGui::TextDisabled("(set on the command line)");
        }
        if (!g_shown.fMinedReady && !g_shown.strMinedWhy.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
            ImGui::TextWrapped("No work for miners yet: %s.", g_shown.strMinedWhy.c_str());
            ImGui::PopStyleColor();
        }
        DrawStratumLine();
        if (g_shown.nMiners > 0)
            ImGui::TextDisabled("Miners connected: %d, about %s, shares sent here: %llu", g_shown.nMiners,
                                FmtHashRate(g_shown.dMinerHashRate).c_str(), (unsigned long long)g_shown.nMinerShares);
        else
            ImGui::TextDisabled("No miner connected to this node's stratum yet.");
        if (g_shown.fHavePart)
        {
            double dPart = (double)g_shown.nMineWork / (double)g_shown.nTotalWork;
            int64 nFee = g_shown.nBlockValue / 10000 * (int64)g_shown.nMinedFeeBps +
                         (g_shown.nBlockValue % 10000) * (int64)g_shown.nMinedFeeBps / 10000;
            double dExpect = (double)(g_shown.nBlockValue - nFee) * dPart / (double)COIN;
            ImGui::Text("This wallet's part of the current window: %.2f%%", dPart * 100.0);
            ImGui::SameLine();
            ImGui::TextDisabled("(about %.4f %s of the next block the pool finds)", dExpect, Unit());
        }
    }
    else
    {
        ImGui::TextDisabled("P2Pool is off: this node does not serve work to miners.");
        if (!running.strProblem.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
            ImGui::TextWrapped("The pool chosen here could not be mined at startup: %s.", running.strProblem.c_str());
            ImGui::PopStyleColor();
        }
    }
    int nRunning = fP2PoolMode ? running.nKind : P2POOL_CHOICE_OFF;
    if (fSavedFile && !SameChoice(nSaved, idSaved, nRunning, running.id))
        ImGui::TextColored(COL_NOTE, "Saved for the next start: %s", ChoiceLabel(nSaved, idSaved, "").c_str());
    if (running.fFromCommandLine)
        ImGui::TextDisabled("Bitflash was started with -p2pool on its command line, which decides; a choice made "
                            "here is used when it starts without it.");

    if (fP2PoolMode || (fSavedFile && nSaved != P2POOL_CHOICE_OFF))
    {
        ImGui::BeginDisabled(fSavedFile && nSaved == P2POOL_CHOICE_OFF);
        if (ImGui::Button("Turn P2Pool mining off"))
            SaveChoice(P2POOL_CHOICE_OFF, 0);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("The next start runs without P2Pool. Solo mining and the other\n"
                              "modes in Options are not touched.");
    }
    if (!g_mineMsg.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_NOTE);
        ImGui::TextWrapped("%s", g_mineMsg.c_str());
        ImGui::PopStyleColor();
        if (g_mineNeedsRestart && !running.fFromCommandLine)
        {
            if (ImGui::Button("Restart Now"))
            {
                if (!GuiRestartApplication())
                    g_mineMsg = "Could not relaunch automatically: please close Bitflash and start it again.";
            }
            ImGui::SameLine();
            if (ImGui::Button("Later"))
                g_mineNeedsRestart = false;
        }
    }
}

// ---- Create a pool ----------------------------------------------------------

enum CreateStep { STEP_EDIT, STEP_REVIEW, STEP_DONE };
static bool g_showCreate = false;
static CreateStep g_step = STEP_EDIT;
static char g_cName[40], g_cFee[16], g_cFeeAddr[100], g_cSpacing[16], g_cWindow[16], g_cRetarget[16],
            g_cFloor[16], g_cUncleDepth[8], g_cUnclePct[8];
static EverpoolCreateParams g_previewParams;
static bool g_havePreview = false;
static EverpoolCreateResult g_preview;
static std::string g_previewErr;
static bool g_understood = false;
static std::string g_createMsg;
static EverpoolCreateResult g_sentResult;

static EverpoolCreateParams ParamsFromFields()
{
    EverpoolCreateParams p;
    p.strName = g_cName;
    p.strFeePercent = g_cFee;
    p.strFeeAddress = g_cFeeAddr;
    p.strSpacing = g_cSpacing;
    p.strWindow = g_cWindow;
    p.strRetarget = g_cRetarget;
    p.strFloor = g_cFloor;
    p.strUncleDepth = g_cUncleDepth;
    p.strUnclePct = g_cUnclePct;
    // Spaces around what was typed are not part of it.
    std::string* v[] = { &p.strName, &p.strFeePercent, &p.strFeeAddress, &p.strSpacing, &p.strWindow,
                         &p.strRetarget, &p.strFloor, &p.strUncleDepth, &p.strUnclePct };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
    {
        while (!v[i]->empty() && isspace((unsigned char)(*v[i])[v[i]->size() - 1]))
            v[i]->erase(v[i]->size() - 1);
        while (!v[i]->empty() && isspace((unsigned char)(*v[i])[0]))
            v[i]->erase(0, 1);
    }
    // No fee typed and no address: no fee. A fee of 0 with an address is the
    // call's to judge, as it would be on the command line.
    return p;
}

static bool SameParams(const EverpoolCreateParams& a, const EverpoolCreateParams& b)
{
    return a.strName == b.strName && a.strFeePercent == b.strFeePercent && a.strFeeAddress == b.strFeeAddress &&
           a.strSpacing == b.strSpacing && a.strWindow == b.strWindow && a.strRetarget == b.strRetarget &&
           a.strFloor == b.strFloor && a.strUncleDepth == b.strUncleDepth && a.strUnclePct == b.strUnclePct;
}

static void OpenCreate()
{
    g_showCreate = true;
    g_step = STEP_EDIT;
    g_havePreview = false;
    g_understood = false;
    g_createMsg.clear();
}

static std::string WalletAddress()
{
    std::vector<unsigned char> vchPubKey;
    if (CWalletDB("r").ReadDefaultKey(vchPubKey))
        return PubKeyToAddress(vchPubKey);
    return std::string();
}

static void RulesLines(const EverpoolCreateResult& r)
{
    ImGui::BulletText("A share every %u s; payouts over the last %u shares (PPLNS)", r.nSpacing, r.nWindow);
    ImGui::BulletText("Share difficulty retargets over %u shares; floor 0x%08x", r.nRetarget, r.nFloor);
    ImGui::BulletText("Uncles up to %u shares deep, paid %u%% of their work", r.nUncleDepth, r.nUnclePct);
}

static void DrawCreateEdit()
{
    ImGui::TextWrapped("A pool is a record on the chain: its name and its share rules. Anyone can create one for "
                       "a burn of 1 %s; the project does not vet pools. Leave a field empty for its default.", Unit());
    ImGui::Spacing();
    ImGui::Text("Name");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##cname", "1 to 32 of A-Z, a-z, 0-9, - and _", g_cName, sizeof(g_cName));

    ImGui::Text("Creator fee (%%)");
    ImGui::SameLine();
    ImGui::TextDisabled("taken from every block the pool finds, paid to the fee address");
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputTextWithHint("##cfee", "0", g_cFee, sizeof(g_cFee));
    ImGui::Text("Fee address");
    ImGui::SameLine();
    if (ImGui::SmallButton("use this wallet's address"))
        snprintf(g_cFeeAddr, sizeof(g_cFeeAddr), "%s", WalletAddress().c_str());
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##cfeeaddr", "needed only with a fee", g_cFeeAddr, sizeof(g_cFeeAddr));

    if (ImGui::CollapsingHeader("Share rules (the defaults suit most pools)"))
    {
        struct F { const char* label; const char* id; char* buf; size_t n; const char* hint; };
        F fields[] = {
            { "Seconds between shares", "##csp", g_cSpacing, sizeof(g_cSpacing), "default: 30, or more for few uncles" },
            { "Payout window (shares)", "##cwin", g_cWindow, sizeof(g_cWindow), "default: 2160" },
            { "Retarget window (shares)", "##cret", g_cRetarget, sizeof(g_cRetarget), "default: 720" },
            { "Uncle depth (1 to 3)", "##cud", g_cUncleDepth, sizeof(g_cUncleDepth), "default: 3" },
            { "Uncle share (%)", "##cup", g_cUnclePct, sizeof(g_cUnclePct), "default: 80" },
            { "Share floor (compact)", "##cfl", g_cFloor, sizeof(g_cFloor), "default: 0x1f0fffff" },
        };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        {
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted(fields[i].label);
            ImGui::SameLine(200.0f);
            ImGui::SetNextItemWidth(260.0f);
            ImGui::InputTextWithHint(fields[i].id, fields[i].hint, fields[i].buf, fields[i].n);
        }
    }

    // The preview is the call itself (nothing sent), run again whenever a
    // field changes: every rule the command line applies, applied here.
    EverpoolCreateParams p = ParamsFromFields();
    if (!g_havePreview || !SameParams(p, g_previewParams))
    {
        g_previewParams = p;
        g_havePreview = true;
        g_previewErr.clear();
        if (p.strName.empty())
            g_previewErr = "a pool needs a name";
        else
            EverpoolCreate(p, false, g_preview, g_previewErr);
    }
    ImGui::Spacing();
    ImGui::Separator();
    if (!g_previewErr.empty())
        ImGui::TextColored(COL_RED, "%s", g_previewErr.c_str());
    else
    {
        ImGui::Text("Pool id: #%s", g_preview.strFingerprint.c_str());
        ImGui::SameLine();
        ImGui::TextColored(FeeColor(g_preview.nFeeBps), "fee %s", g_preview.strFeePercent.c_str());
        RulesLines(g_preview);
    }
    ImGui::Spacing();
    ImGui::BeginDisabled(!g_previewErr.empty());
    if (ImGui::Button("Review", ImVec2(110.0f, 0.0f)))
    {
        g_step = STEP_REVIEW;
        g_understood = false;
        g_createMsg.clear();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f)))
        g_showCreate = false;
}

static void DrawCreateReview()
{
    const EverpoolCreateResult& r = g_preview;
    ImGui::TextWrapped("Check everything below. Nothing has been sent yet.");
    ImGui::Spacing();
    ImGui::Text("Name: %s", r.strName.c_str());
    ImGui::Text("Pool id:");
    ImGui::SameLine();
    ImGui::TextColored(COL_GREEN, "#%s", r.strFingerprint.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy full id"))
        ImGui::SetClipboardText(r.strId.c_str());
    ImGui::TextDisabled("%s", r.strId.c_str());
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, FeeColor(r.nFeeBps));
    ImGui::SetWindowFontScale(1.25f);
    ImGui::Text("Creator fee: %s", r.strFeePercent.c_str());
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();
    if (r.strFeeAddress.empty())
        ImGui::TextDisabled("No fee address: miners keep the whole block.");
    else
        ImGui::Text("Fee address: %s", r.strFeeAddress.c_str());
    RulesLines(r);
    ImGui::Spacing();
    ImGui::SeparatorText("What sending does");
    ImGui::BulletText("Burns 1 %s (plus the network fee): it is gone, for nobody.", Unit());
    ImGui::BulletText("The pool is pending until the burn has %d confirmations (about %d minutes), then active.",
                      POOL_ACTIVE_CONFIRMATIONS, POOL_ACTIVE_CONFIRMATIONS * 2);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
    ImGui::BulletText("A pool can never be edited or deleted. Changing anything makes a new pool with a new id.");
    ImGui::PopStyleColor();
    if (!r.vSameName.empty())
    {
        std::string s;
        for (size_t i = 0; i < r.vSameName.size(); i++)
            s += (i ? ", " : "") + (r.vSameName[i] == "pool zero" ? r.vSameName[i] : "#" + r.vSameName[i]);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
        ImGui::TextWrapped("Other pools already have a name like this one (%s). Names are not unique: miners tell "
                           "pools apart by id, age and fee.", s.c_str());
        ImGui::PopStyleColor();
    }
    bool fCan = true;
    if (r.fPoolZero)
    {
        ImGui::TextColored(COL_RED, "These are pool zero's own rules: it is already in every node, so this window "
                                    "does not burn anything for it.");
        fCan = false;
    }
    else if (r.fRecorded)
    {
        ImGui::TextColored(COL_RED, "This pool is already recorded (first at block %d): burning it again changes "
                                    "nothing.", r.nRecordedHeight);
        fCan = false;
    }
    if (!r.fBurnsOpen)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
        ImGui::TextWrapped("Everpool is not open on mainnet in this build: this is a preview of what would be "
                           "recorded, and nothing can be sent from it.");
        ImGui::PopStyleColor();
        fCan = false;
    }
    if (fCan && IsWalletLocked())
    {
        ImGui::TextColored(COL_RED, "The wallet is encrypted and locked: sending needs it unlocked "
                                    "(start with /walletpassphrase).");
        fCan = false;
    }
    ImGui::Spacing();
    if (fCan)
        ImGui::Checkbox(strprintf("I understand: 1 %s is burned, and this pool can never be changed or removed.", Unit()).c_str(),
                        &g_understood);
    if (!g_createMsg.empty())
        ImGui::TextColored(COL_RED, "%s", g_createMsg.c_str());
    ImGui::Spacing();
    if (ImGui::Button("Back", ImVec2(110.0f, 0.0f)))
        g_step = STEP_EDIT;
    if (fCan)
    {
        ImGui::SameLine();
        ImGui::BeginDisabled(!g_understood);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.45f, 0.20f, 0.10f, 1.0f));
        if (ImGui::Button(strprintf("Burn 1 %s and create the pool##burn", Unit()).c_str(), ImVec2(260.0f, 0.0f)))
        {
            EverpoolCreateResult sent;
            std::string err;
            // Exactly what was reviewed: the same fields, the same call.
            if (!SameParams(ParamsFromFields(), g_previewParams))
                g_createMsg = "The fields changed after the review: review again.";
            else if (!EverpoolCreate(g_previewParams, true, sent, err))
                g_createMsg = "Not sent: " + err;
            else
            {
                g_sentResult = sent;
                g_step = STEP_DONE;
                EvSent s;
                s.id.SetHex(sent.strId);
                s.strName = sent.strName;
                s.strTxid = sent.strTxid;
                s.rec = poolreg::PoolZero();
                s.rec.name = sent.strName;
                s.rec.nSpacing = sent.nSpacing;
                s.rec.nWindow = sent.nWindow;
                s.rec.nRetarget = sent.nRetarget;
                s.rec.nFloor = sent.nFloor;
                s.rec.nUncleDepth = sent.nUncleDepth;
                s.rec.nUnclePct = sent.nUnclePct;
                s.rec.nFeeBps = sent.nFeeBps;
                {
                    std::lock_guard<std::mutex> lk(g_lock);
                    g_sent.push_back(s);
                }
                g_selected = s.id;
                g_haveSelected = true;
                MainFrameRepaint();
                AskRefresh();
            }
        }
        ImGui::PopStyleColor();
        ImGui::EndDisabled();
    }
}

static void DrawCreateDone()
{
    const EverpoolCreateResult& r = g_sentResult;
    ImGui::TextColored(COL_GREEN, "Sent. The pool \"%s\" #%s is recorded once the burn is in a block.",
                       r.strName.c_str(), r.strFingerprint.c_str());
    ImGui::TextWrapped("Status: %s.", r.strStatus.c_str());
    ImGui::Text("Transaction:");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", r.strTxid.c_str());
    if (ImGui::SmallButton("Copy##senttx"))
        ImGui::SetClipboardText(r.strTxid.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("View in the explorer"))
    {
        uint256 h;
        h.SetHex(r.strTxid);
        ExplorerOpenTx(h);
    }
    ImGui::Spacing();
    ImGui::TextWrapped("It shows in the list as pending, then as active after %d confirmations. Remember: this pool "
                       "can never be edited or deleted.", POOL_ACTIVE_CONFIRMATIONS);
    if (ImGui::Button("Close", ImVec2(110.0f, 0.0f)))
        g_showCreate = false;
}

static void DrawCreateDialog()
{
    if (!g_showCreate)
        return;
    // As tall as its content, never taller than the window: the rest scrolls.
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowSizeConstraints(ImVec2(600.0f, 0.0f), ImVec2(600.0f, vp->Size.y - 40.0f));
    ImGui::SetNextWindowSize(ImVec2(600.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Create an Everpool pool", &g_showCreate, ImGuiWindowFlags_NoCollapse))
    {
        if (!PoolBurnsOpen())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
            ImGui::TextWrapped("Everpool is not open on mainnet in this build. You can fill in a pool and preview "
                               "it; nothing can be sent.");
            ImGui::PopStyleColor();
            ImGui::Separator();
        }
        if (g_step == STEP_EDIT)
            DrawCreateEdit();
        else if (g_step == STEP_REVIEW)
            DrawCreateReview();
        else
            DrawCreateDone();
    }
    ImGui::End();
}

// ---- The list and the detail panel ------------------------------------------

static const EvRow* SelectedRow()
{
    if (!g_haveSelected)
        return NULL;
    for (size_t i = 0; i < g_shown.rows.size(); i++)
        if (g_shown.rows[i].id == g_selected)
            return &g_shown.rows[i];
    return NULL;
}

static void StatusText(const EvRow& r)
{
    if (r.fJustSent)
        ImGui::TextColored(COL_AMBER, "sent, waiting for a block");
    else if (r.fZero || r.nStatus == POOL_ACTIVE)
        ImGui::TextColored(COL_GREEN, "active");
    else if (r.nStatus == POOL_PENDING)
        ImGui::TextColored(COL_AMBER, "pending: %d of %d", r.nConfirmations, POOL_ACTIVE_CONFIRMATIONS);
    else
        ImGui::TextDisabled("unknown");
}

static std::string NodeRole(const EvRow& r)
{
    std::string s;
    if (r.st.fMined)
        s = "mines";
    if (r.fZero || (r.fHeld && (r.st.fCarry || r.st.fCarried)))
        s += std::string(s.empty() ? "" : ", ") + "carries";
    if (r.fHeld && r.st.fGuard)
        s += std::string(s.empty() ? "" : ", ") + "guards";
    return s.empty() ? std::string("-") : s;
}

static std::string LineState(const EvRow& r)
{
    if (g_shown.fP2PoolBusy)
        return "not known right now: this node is busy checking shares";
    if (r.fZero)
        return r.st.nShares ? strprintf("complete: %u shares, tip at share %d", (unsigned)r.st.nShares, r.st.nTipHeight)
                            : std::string("no shares yet");
    if (!r.fHeld)
        return "not held here (this node neither mines, carries nor guards it)";
    if (r.st.fOverCap)
        return "let go: its line passed what this node holds of a pool";
    static const char* const v[] = { "nothing yet", "fetching its line", "catching up", "complete" };
    return strprintf("%s: %u shares, tip at share %d", v[std::max(0, std::min(3, r.st.nFetch))],
                     (unsigned)r.st.nShares, r.st.nTipHeight);
}

static void PoolNameCell(const EvRow& r)
{
    if (r.fZero)
    {
        ImGui::TextUnformatted("pool zero");
        ImGui::SameLine();
        ImGui::TextDisabled("\"%s\" #%s", r.strName.c_str(), r.strFp.c_str());
        ImGui::SameLine();
        ImGui::TextColored(COL_GREEN, "default");
    }
    else
    {
        ImGui::TextUnformatted(r.strName.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("#%s", r.strFp.c_str());
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Pool id: %s\nRight-click to copy it.", r.strId.c_str());
    if (ImGui::BeginPopupContextItem(("ctx" + r.strId).c_str()))
    {
        if (ImGui::MenuItem("Copy pool id"))
            ImGui::SetClipboardText(r.strId.c_str());
        ImGui::EndPopup();
    }
    if (!r.vSameName.empty())
    {
        ImGui::SameLine();
        ImGui::TextColored(COL_AMBER, "(name shared)");
        if (ImGui::IsItemHovered())
        {
            std::string s;
            for (size_t i = 0; i < r.vSameName.size(); i++)
                s += "\n  " + (r.vSameName[i] == "pool zero" ? r.vSameName[i] : "#" + r.vSameName[i]);
            ImGui::SetTooltip("Names are not unique. Other pools named like this one:%s", s.c_str());
        }
    }
}

static void DrawList(float h)
{
    if (!ImGui::BeginTable("everpools", 6,
                           ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                           ImGuiTableFlags_SizingStretchProp,
                           ImVec2(0.0f, h)))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Pool", ImGuiTableColumnFlags_WidthStretch, 3.0f);
    ImGui::TableSetupColumn("Fee", ImGuiTableColumnFlags_WidthFixed, 62.0f);
    ImGui::TableSetupColumn("Age", ImGuiTableColumnFlags_WidthFixed, 80.0f);
    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Recent work", ImGuiTableColumnFlags_WidthStretch, 1.4f);
    ImGui::TableSetupColumn("This node", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < g_shown.rows.size(); i++)
    {
        const EvRow& r = g_shown.rows[i];
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        bool fSel = g_haveSelected && g_selected == r.id;
        if (ImGui::Selectable(("##row" + r.strId).c_str(), fSel,
                              ImGuiSelectableFlags_SpanAllColumns))
        {
            g_selected = r.id;
            g_haveSelected = true;
        }
        ImGui::SameLine(0.0f, 0.0f);
        PoolNameCell(r);
        ImGui::TableSetColumnIndex(1);
        ImGui::TextColored(FeeColor(r.rec.nFeeBps), "%s", FeePercent(r.rec.nFeeBps).c_str());
        ImGui::TableSetColumnIndex(2);
        if (r.fZero)
            ImGui::TextDisabled("genesis");
        else if (r.nFirstTime > 0)
            ImGui::TextUnformatted(FmtDuration(GetTime() - r.nFirstTime).c_str());
        else
            ImGui::TextDisabled("-");
        ImGui::TableSetColumnIndex(3);
        StatusText(r);
        ImGui::TableSetColumnIndex(4);
        if (r.dHashRate >= 0.0)
            ImGui::Text("~%s, %d blocks", FmtHashRate(r.dHashRate).c_str(), r.nClaims);
        else
            ImGui::Text("%d blocks", r.nClaims);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Blocks in the last %d whose coinbase names this pool (claims: anybody can name a pool).\n"
                              "The hashrate is estimated from the share line this node holds, when it holds one.",
                              POOL_ANCHOR_WINDOW);
        ImGui::TableSetColumnIndex(5);
        ImGui::TextUnformatted(NodeRole(r).c_str());
    }
    ImGui::EndTable();
}

static void DrawDetail(const EvRow& r)
{
    const P2PoolChoiceInfo running = P2PoolChoiceRunning();
    if (r.fZero)
        ImGui::Text("Pool zero: the default pool every P2Pool miner already mines");
    else
        ImGui::Text("%s", r.strName.c_str());
    ImGui::TextDisabled("Pool id %s", r.strId.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy##detailid"))
        ImGui::SetClipboardText(r.strId.c_str());

    ImGui::PushStyleColor(ImGuiCol_Text, FeeColor(r.rec.nFeeBps));
    ImGui::Text("Creator fee: %s", FeePercent(r.rec.nFeeBps).c_str());
    ImGui::PopStyleColor();
    std::string strFeeAddr = FeeAddress(r.rec);
    if (!strFeeAddr.empty())
    {
        ImGui::SameLine();
        ImGui::TextDisabled("to %s", strFeeAddr.c_str());
    }
    ImGui::BulletText("A share every %u s; payouts over the last %u shares (PPLNS)", r.rec.nSpacing, r.rec.nWindow);
    ImGui::BulletText("Retarget over %u shares; floor 0x%08x", r.rec.nRetarget, r.rec.nFloor);
    ImGui::BulletText("Uncles up to %u deep, paid %u%% of their work", r.rec.nUncleDepth, r.rec.nUnclePct);

    if (r.fJustSent)
        ImGui::TextWrapped("Sent from this window in transaction %s; recorded once it is in a block.",
                           r.strSentTxid.c_str());
    else if (!r.fZero && r.nFirstHeight >= 0)
    {
        ImGui::Text("Recorded at block %d%s", r.nFirstHeight,
                    r.nFirstTime > 0 ? (", " + DateTimeStr(r.nFirstTime)).c_str() : "");
        ImGui::SameLine();
        if (ImGui::SmallButton("burn##view"))
            ExplorerOpenTx(r.txidFirst);
        if (r.nAppearances > 1)
            ImGui::TextDisabled("Burned %d times; the first one counts.", r.nAppearances);
    }
    ImGui::Text("This node's line:");
    ImGui::SameLine();
    ImGui::TextUnformatted(LineState(r).c_str());
    if (r.fHeld && !r.fZero && r.st.nAnnouncers)
        ImGui::TextDisabled("%u peer(s) announce it", (unsigned)r.st.nAnnouncers);

    if (!r.vAnchors.empty())
    {
        ImGui::Text("Blocks naming it lately (%d in the last %d):", r.nClaims, POOL_ANCHOR_WINDOW);
        std::string s;
        for (size_t i = 0; i < r.vAnchors.size(); i++)
        {
            s += strprintf("%s%d", i ? ", " : "", r.vAnchors[i].nHeight);
            if (r.vAnchors[i].nTime > 0 && i == 0)
                s += " (" + FmtDuration(GetTime() - r.vAnchors[i].nTime) + " ago)";
        }
        ImGui::TextDisabled("%s", s.c_str());
    }
    else
        ImGui::TextDisabled("No block names this pool in the last %d.", POOL_ANCHOR_WINDOW);

    // Mine it.
    ImGui::Spacing();
    int nKind = r.fZero ? P2POOL_CHOICE_ZERO : P2POOL_CHOICE_REGISTERED;
    uint256 id = r.fZero ? uint256(0) : r.id;
    const int nSaved = g_savedKind;
    const uint256 idSaved = g_savedId;
    const bool fSaved = g_savedFile;
    bool fRunning = fP2PoolMode && SameChoice(nKind, id, running.nKind, running.id);
    bool fIsSaved = fSaved ? SameChoice(nKind, id, nSaved, idSaved) : fRunning;
    std::string strWhyNot;
    if (nMineMode == MINE_OPERATOR)
        strWhyNot = "This node runs a pool as operator (Options): P2Pool and operator mode do not go together.";
    else if (!r.fZero && !PoolBurnsOpen())
        strWhyNot = "Everpool pools are not open on mainnet in this build: only pool zero can be mined.";
    else if (r.fJustSent)
        strWhyNot = "Wait until the burn is in a block.";
    else if (!r.fZero && r.nStatus != POOL_ACTIVE && r.nStatus != POOL_PENDING)
        strWhyNot = "This pool is not recorded on the chain this node follows.";
    ImGui::BeginDisabled(!strWhyNot.empty() || fIsSaved);
    const char* pszLabel = fIsSaved ? (fRunning ? "Mining this pool" : "Chosen for the next start")
                                    : (r.fZero ? "Mine pool zero" : "Mine this pool");
    if (ImGui::Button(pszLabel, ImVec2(200.0f, 0.0f)))
        SaveChoice(nKind, id);
    ImGui::EndDisabled();
    if (!strWhyNot.empty())
    {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", strWhyNot.c_str());
    }
    else if (!r.fZero && r.nStatus == POOL_PENDING && !fIsSaved)
    {
        ImGui::SameLine();
        ImGui::TextDisabled("Pending: miners get work once it is active.");
    }
    else if (!fIsSaved)
    {
        ImGui::SameLine();
        ImGui::TextDisabled("Uses an external miner (Bitflash Miner or XMRig) on this node's stratum.");
    }
}

// ---- The window -------------------------------------------------------------

void DrawEverpoolWindow()
{
    if (!g_showEverpool)
    {
        DrawCreateDialog();
        return;
    }
    TakeRefresh();
    if (!g_haveShown || GetTime() - g_askedAt >= REFRESH_SECONDS)
        AskRefresh();

    ImGui::SetNextWindowSize(ImVec2(920.0f, 640.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Everpool", &g_showEverpool, ImGuiWindowFlags_NoCollapse))
    {
        ImGui::TextWrapped("Everpool pools are P2Pool pools recorded on the chain. Pool zero is the default pool "
                           "every P2Pool miner already mines; the others each have their own name, fee and rules.");
        ImGui::PushStyleColor(ImGuiCol_Text, COL_AMBER);
        ImGui::TextWrapped("Anyone can create a pool and the project does not vet them. Names are not unique: a pool "
                           "is its id (the fingerprint is its first 8 digits), its age, its fee and its work.");
        ImGui::PopStyleColor();
        if (!PoolBurnsOpen())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
            ImGui::TextWrapped("Everpool pools are not open on mainnet in this build: you can look and preview, "
                               "but only pool zero can be mined and no pool can be created.");
            ImGui::PopStyleColor();
        }

        if (!g_haveShown)
            ImGui::TextDisabled("Reading the pool registry...");
        else
        {
            DrawMiningBox();

            ImGui::SeparatorText("Pools");
            if (ImGui::Button("Create a pool..."))
                OpenCreate();
            ImGui::SameLine();
            if (ImGui::Button("Refresh"))
                AskRefresh();
            ImGui::SameLine();
            if (g_shown.fRebuilding)
                ImGui::TextColored(COL_AMBER, "The registry is being read again from the start of the chain.");
            else if (!g_shown.fSynced)
                ImGui::TextColored(COL_AMBER, "The registry has read up to block %d; still catching up.",
                                   g_shown.nIndexHeight);
            else
                ImGui::TextDisabled("Registry read up to block %d. %d pool(s) besides pool zero.",
                                    g_shown.nIndexHeight, (int)g_shown.rows.size() - 1);

            if (g_shown.fP2PoolBusy)
                ImGui::TextDisabled("This node is busy checking shares it received; what it holds of each pool "
                                    "shows when it is done.");
            float h = ImGui::GetContentRegionAvail().y * 0.45f;
            if (h < 140.0f) h = 140.0f;
            DrawList(h);

            ImGui::BeginChild("##evdetail", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders);
            const EvRow* r = SelectedRow();
            if (r)
                DrawDetail(*r);
            else
                ImGui::TextDisabled("Pick a pool above to see its rules and mine it.");
            ImGui::EndChild();
        }
    }
    ImGui::End();
    DrawCreateDialog();
}
