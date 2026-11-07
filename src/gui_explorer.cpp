// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The explorer window. All it knows comes from explorer.h, which reads this
// node's files and waits for its lock: a thread does that and hands over a copy,
// so a frame never touches the disk or waits on the node.

#include "imgui/imgui.h"
#include "headers_core.h"
#include <algorithm>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "explorer.h"
#include "gui_explorer.h"

bool g_showExplorer = false;

string DateTimeStr(int64 nTime);

static const int PAGE_BLOCKS = 25;
static const int RECENT_REFRESH_SECONDS = 5;

enum Page { PAGE_LIST, PAGE_BLOCK, PAGE_TX };
struct Place
{
    Page page;
    uint256 hash;
    int nTop;   // the list: the height it starts from, negative for the tip
    bool operator==(const Place& b) const { return page == b.page && hash == b.hash && nTop == b.nTop; }
};

static Place g_place = { PAGE_LIST, uint256(0), -1 };
static std::vector<Place> g_back;
static bool g_needLoad = true;
static std::string g_message;
static char g_query[80];
static bool g_searchWanted = false;

// What a page shows, as the thread handed it over.
struct Loaded
{
    Place place;
    bool fSearch;
    std::string strQuery;
    explorer::Result result;
    uint256 found;
    std::vector<explorer::BlockRow> rows;
    int nTip;
    explorer::BlockView block;
    explorer::TxView tx;
};
static Loaded g_shown;
static bool g_haveShown = false;
static int64 g_loadedAt = 0;

// The thread's side. It only ever runs one at a time.
// A read can still be waiting when the program exits, so what it touches is
// never destroyed.
static std::mutex& g_lock = *new std::mutex;
static bool g_working = false;
static bool g_done = false;
static Loaded& g_result = *new Loaded;

static const char* Unit() { return IsTestNet() ? "tBTF" : "BTF"; }

static std::string Coins(int64 n) { return explorer::Money(n) + " " + Unit(); }

static void Go(Page page, const uint256& hash, int nTop = -1)
{
    g_back.push_back(g_place);
    g_place.page = page;
    g_place.hash = hash;
    g_place.nTop = nTop;
    g_needLoad = true;
    g_message.clear();
}

void ExplorerOpenTx(const uint256& txid)
{
    Go(PAGE_TX, txid);
    g_showExplorer = true;
}

static void Work(Loaded job)
{
    if (job.fSearch)
        job.result = explorer::Find(job.strQuery, job.found);
    else if (job.place.page == PAGE_LIST)
        job.result = explorer::Recent(job.place.nTop, PAGE_BLOCKS, job.rows, job.nTip);
    else if (job.place.page == PAGE_BLOCK)
        job.result = explorer::ReadBlock(job.place.hash, job.block);
    else
        job.result = explorer::ReadTx(job.place.hash, job.tx);
    std::lock_guard<std::mutex> lock(g_lock);
    g_result = job;
    g_done = true;
    g_working = false;
}

// Once a frame: takes what the thread finished, and starts what is wanted next.
static void Pump()
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_done)
    {
        g_done = false;
        if (g_result.fSearch)
        {
            if (g_result.result == explorer::IS_BLOCK)
                Go(PAGE_BLOCK, g_result.found);
            else if (g_result.result == explorer::IS_TX)
                Go(PAGE_TX, g_result.found);
            else if (g_result.result == explorer::NOT_FOUND)
                g_message = "This node knows no such block or transaction.";
            else
                g_message = "Search by block height, block hash or transaction id.";
        }
        else if (g_result.place == g_place)     // else the reader moved on
        {
            g_shown = g_result;
            g_haveShown = true;
            g_needLoad = false;
            g_loadedAt = GetTime();
            if (g_result.result != explorer::FOUND)
                g_message = "This node does not have that.";
        }
    }
    if (g_working || (!g_searchWanted && !g_needLoad))
        return;
    Loaded job;
    job.place = g_place;
    job.fSearch = g_searchWanted;
    job.strQuery = g_query;
    job.result = explorer::NOT_FOUND;
    job.nTip = 0;
    g_searchWanted = false;
    g_working = true;
    std::thread(Work, job).detach();
}

// A hash that opens what it names. Ids in the same frame repeat, so the caller
// gives the row its own PushID.
static bool HashLink(const uint256& hash, size_t nShort = 0)
{
    std::string str = hash.GetHex();
    if (nShort && str.size() > nShort * 2)
        str = str.substr(0, nShort) + "..." + str.substr(str.size() - nShort);
    return ImGui::TextLink(str.c_str());
}

static void CopyButton(const std::string& str)
{
    ImGui::SameLine();
    ImGui::PushID(str.c_str());
    if (ImGui::SmallButton("copy"))
        ImGui::SetClipboardText(str.c_str());
    ImGui::PopID();
}

static void Label(const char* pszLabel)
{
    ImGui::TextDisabled("%s", pszLabel);
    ImGui::SameLine(130.0f);
}

static void DrawList()
{
    if (ImGui::BeginTable("explorerblocks", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp))
    {
        ImGui::TableSetupColumn("Height", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Txs", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Reward", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("To", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < g_shown.rows.size(); i++)
        {
            const explorer::BlockRow& row = g_shown.rows[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID((int)i);
            if (ImGui::TextLink(strprintf("%d", row.height).c_str()))
                Go(PAGE_BLOCK, row.hash);
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(DateTimeStr(row.time).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%d", row.nTx);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(Coins(row.reward).c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(row.to.c_str());
        }
        ImGui::EndTable();
    }
    int nBottom = g_shown.rows.empty() ? 0 : g_shown.rows.back().height;
    ImGui::BeginDisabled(g_place.nTop < 0 || g_place.nTop >= g_shown.nTip);
    if (ImGui::Button("Newer"))
    {
        g_place.nTop = g_place.nTop + PAGE_BLOCKS >= g_shown.nTip ? -1 : g_place.nTop + PAGE_BLOCKS;
        g_needLoad = true;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(nBottom <= 0);
    if (ImGui::Button("Older"))
    {
        g_place.nTop = nBottom - 1;
        g_needLoad = true;
    }
    ImGui::EndDisabled();
}

static void DrawBlock()
{
    ImGui::Text("Block %d", g_shown.block.height);
    if (!g_shown.block.fMainChain)
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "not on the main chain");
    }
    ImGui::Spacing();
    Label("Hash");
    ImGui::TextUnformatted(g_shown.block.hash.GetHex().c_str());
    CopyButton(g_shown.block.hash.GetHex());
    Label("Time");
    ImGui::TextUnformatted(DateTimeStr(g_shown.block.time).c_str());
    Label("Size");
    ImGui::Text("%u bytes", g_shown.block.nSize);
    Label("Version");
    ImGui::Text("%d", g_shown.block.nVersion);
    Label("Bits / nonce");
    ImGui::Text("%08x / %u", g_shown.block.nBits, g_shown.block.nNonce);
    Label("Merkle root");
    ImGui::TextUnformatted(g_shown.block.merkleRoot.GetHex().c_str());
    if (g_shown.block.height > 0)
    {
        Label("Previous");
        ImGui::PushID("prev");
        if (HashLink(g_shown.block.prev))
            Go(PAGE_BLOCK, g_shown.block.prev);
        ImGui::PopID();
    }
    if (g_shown.block.next != uint256(0))
    {
        Label("Next");
        ImGui::PushID("next");
        if (HashLink(g_shown.block.next))
            Go(PAGE_BLOCK, g_shown.block.next);
        ImGui::PopID();
    }
    ImGui::Spacing();
    if (ImGui::BeginTable("explorertxs", 3,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp))
    {
        ImGui::TableSetupColumn("Transaction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("In / out", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < g_shown.block.txs.size(); i++)
        {
            const explorer::TxRow& row = g_shown.block.txs[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID((int)i);
            if (HashLink(row.txid))
                Go(PAGE_TX, row.txid);
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            if (row.fCoinBase)
                ImGui::TextDisabled("coinbase");
            else
                ImGui::Text("%d / %d", row.nIn, row.nOut);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(Coins(row.value).c_str());
        }
        ImGui::EndTable();
    }
}

static void DrawTx()
{
    ImGui::TextUnformatted("Transaction");
    ImGui::Spacing();
    Label("Id");
    ImGui::TextUnformatted(g_shown.tx.txid.GetHex().c_str());
    CopyButton(g_shown.tx.txid.GetHex());
    Label("Status");
    if (g_shown.tx.fInChain)
    {
        ImGui::Text("%d confirmations, in block", g_shown.tx.nConfirmations);
        ImGui::SameLine();
        if (ImGui::TextLink(strprintf("%d", g_shown.tx.height).c_str()))
            Go(PAGE_BLOCK, g_shown.tx.block);
        Label("Time");
        ImGui::TextUnformatted(DateTimeStr(g_shown.tx.time).c_str());
    }
    else
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "waiting to be mined");
    Label("Size");
    ImGui::Text("%u bytes", g_shown.tx.nSize);
    if (g_shown.tx.fFeeKnown)
    {
        Label("Fee");
        ImGui::TextUnformatted(Coins(g_shown.tx.fee).c_str());
    }

    ImGui::Spacing();
    ImGui::SeparatorText("From");
    if (g_shown.tx.fCoinBase)
        ImGui::TextDisabled("newly mined");
    for (size_t i = 0; i < g_shown.tx.in.size(); i++)
    {
        const explorer::Input& in = g_shown.tx.in[i];
        ImGui::PushID((int)i);
        if (HashLink(in.prev, 8))
            Go(PAGE_TX, in.prev);
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::Text(":%u", in.n);
        if (in.fKnown)
        {
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::Text("%s  %s", Coins(in.value).c_str(), in.from.c_str());
        }
        ImGui::PopID();
    }

    ImGui::Spacing();
    ImGui::SeparatorText("To");
    for (size_t i = 0; i < g_shown.tx.out.size(); i++)
    {
        const explorer::Output& out = g_shown.tx.out[i];
        ImGui::PushID((int)i + 100000);
        ImGui::Text("%u:  %s  %s", (unsigned int)i, Coins(out.value).c_str(), out.to.c_str());
        if (out.spentBy != uint256(0))
        {
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::TextDisabled("spent by");
            ImGui::SameLine();
            if (HashLink(out.spentBy, 8))
                Go(PAGE_TX, out.spentBy);
        }
        else if (g_shown.tx.fInChain)
        {
            ImGui::SameLine(0.0f, 16.0f);
            ImGui::TextDisabled("unspent");
        }
        ImGui::PopID();
    }
}

void DrawExplorerWindow()
{
    if (!g_showExplorer)
        return;
    ImVec2 area = ImGui::GetMainViewport()->WorkSize;
    ImGui::SetNextWindowPos(ImVec2(area.x * 0.5f, area.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(820.0f, area.x - 40.0f), std::min(600.0f, area.y - 40.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Block Explorer", &g_showExplorer, ImGuiWindowFlags_NoCollapse))
    {
        ImGui::End();
        return;
    }
    // The list follows the chain while it shows the tip.
    if (g_place.page == PAGE_LIST && g_place.nTop < 0 && GetTime() - g_loadedAt >= RECENT_REFRESH_SECONDS)
        g_needLoad = true;
    Pump();

    ImGui::TextDisabled("Read from your own node. Nothing here leaves this computer.");
    ImGui::Spacing();
    ImGui::BeginDisabled(g_back.empty());
    if (ImGui::Button("Back"))
    {
        g_place = g_back.back();
        g_back.pop_back();
        g_needLoad = true;
        g_message.clear();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Latest blocks"))
        Go(PAGE_LIST, uint256(0));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-60.0f);
    bool fEnter = ImGui::InputTextWithHint("##explorerquery", "height, block hash or txid", g_query, sizeof(g_query),
                                           ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Find") || fEnter)
        g_searchWanted = true;
    if (!g_message.empty())
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%s", g_message.c_str());
    ImGui::Separator();

    if (ImGui::BeginChild("##explorerpage"))
    {
        // The list keeps showing while it refreshes; the rest wait for their page.
        if (g_place.page == PAGE_LIST && g_haveShown && g_shown.place.page == PAGE_LIST)
            DrawList();
        else if (!g_haveShown || !(g_shown.place == g_place))
            ImGui::TextDisabled("Reading...");
        else if (g_message.empty() && g_place.page == PAGE_BLOCK)
            DrawBlock();
        else if (g_message.empty() && g_place.page == PAGE_TX)
            DrawTx();
    }
    ImGui::EndChild();
    ImGui::End();
}
