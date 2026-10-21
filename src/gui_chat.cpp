// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The btfchat window.
//
// NOTHING HERE BLOCKS. One outgoing message is a Tor circuit, which is seconds,
// and a frame is sixteen milliseconds. So every call that touches the network is
// handed to one worker thread and the window shows what it is doing. A GUI that
// freezes while it dials looks broken, and a user who thinks it is broken
// retries -- which is how a message gets sent twice.
//
// ONE WORKER, NOT A POOL. Actions are serialized on purpose: two dials at once
// would open two Tor circuits from the same identity at the same moment, which
// is a correlation signal handed out for no benefit at all.
//
// THE PASSWORD FIELD IS THE WHOLE SECURITY MODEL OF THIS SCREEN. A wrong
// password does not fail -- it opens a different, empty identity -- so the
// address is shown big after unlocking and the user is the one who confirms it.
// That is not a workaround: it is what makes the password impossible to check
// offline by anybody, including whoever steals the file.

// imgui.h first, as in gui.cpp: util.h defines printf as a macro, and on Linux
// imgui marks its formatting functions __attribute__((format(printf, ...))) --
// after the macro that reads format(OutputDebugStringF, ...), which GCC
// rejects. MinGW takes imgui's gnu_printf branch instead, which is why only
// the Linux build ever saw it.
#include "imgui.h"

#include "headers.h"
#include "gui_chat.h"
#include "btfchatnode.h"
#include "btfchatnet.h"
#include "btfchatwallet.h"
#include "chatdir.h"
#include "community.h"
#include "chatswap.h"
#include "btfchatswap.h"
#include "bip21.h"
#include "tor.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

bool g_showChat = false;

namespace
{

// ---- the worker ------------------------------------------------------------

enum ActionKind
{
    ACT_NONE = 0,
    ACT_UNLOCK,
    ACT_INVITE,
    ACT_ACCEPT,
    ACT_DECLINE,
    ACT_BLOCK,
    ACT_SEND,
    ACT_REQUEST,   // share an address of our wallet, maybe asking for an amount
    ACT_PAY,       // pay them from our wallet at the address they signed
    ACT_DIRECTORY, // fetch the public community directory from the nodes
    ACT_CREATE,    // list a public community on the chain (burns 0.01 BTF)
    ACT_POST,      // post in a community
    ACT_OFFER,     // post a swap offer in a community
    ACT_TAKE,      // take somebody's swap offer
    ACT_SWAP_OK,   // the person's yes on a swap: accept a take, or lock our side
    ACT_SWAP_CANCEL,
};

CCriticalSection cs_ui;
ActionKind  g_pending = ACT_NONE;   // queued, not yet started
ActionKind  g_running = ACT_NONE;
std::string g_argAddr;
std::string g_argText;
std::string g_argPassword;
std::string g_message;              // shown to the user: progress or the last error
std::vector<CChatListing> g_directory;  // the last public directory the nodes sent
// Whether that message is bad news. One string carried both "this failed" and
// "this worked, with something you should know", and everything came out in the
// error colour -- so being told the message was safely left in the recipient's
// mailbox looked exactly like being told it could not be sent. The sentence was
// right and the colour was calling it a lie.
bool        g_fMessageOk = false;
bool        g_fWorkerAlive = false;

// What the worker is doing, in words a person can act on.
const char* ActionLabel(ActionKind k)
{
    switch (k)
    {
    case ACT_UNLOCK:  return "deriving your identity (Argon2id, a second or so)";
    case ACT_INVITE:  return "sending the invite over Tor";
    case ACT_ACCEPT:  return "telling them you accepted";
    case ACT_DECLINE: return "declining";
    case ACT_BLOCK:   return "blocking";
    case ACT_SEND:    return "sending over Tor";
    case ACT_REQUEST: return "asking your wallet for an address and sending it";
    case ACT_PAY:     return "paying from your wallet";
    case ACT_DIRECTORY: return "asking the nodes for the public directory";
    case ACT_CREATE:  return "listing the community on the chain (burns 0.01 BTF)";
    case ACT_POST:    return "posting";
    case ACT_OFFER:   return "checking your wallet and posting the offer";
    case ACT_TAKE:    return "starting the swap";
    case ACT_SWAP_OK: return "telling the swap to go on";
    case ACT_SWAP_CANCEL: return "cancelling the swap";
    default:          return "";
    }
}

void ThreadChatUiWorker(void*)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatUiWorker(NULL));
    try
    {
        while (!fShutdown)
        {
            ActionKind  k = ACT_NONE;
            std::string addr, text, password;
            CRITICAL_BLOCK(cs_ui)
            {
                k = g_pending;
                g_pending = ACT_NONE;
                g_running = k;
                addr = g_argAddr;
                text = g_argText;
                password = g_argPassword;
                // The password is not kept a moment longer than the call needs.
                g_argPassword.clear();
            }

            if (k == ACT_NONE)
            {
                Sleep(50);
                continue;
            }

            std::string err;
            bool fOk = false;
            switch (k)
            {
            case ACT_UNLOCK:
                fOk = btfchat::ChatUnlock(password, err);
                if (fOk)
                {
                    // The service can only start once there is a key to answer a
                    // handshake with, so it is started here and not at boot.
                    std::string e2;
                    if (!btfchat::ChatServiceStart(e2))
                        err = "unlocked, but the service did not start: " + e2;
                }
                break;
            case ACT_INVITE:  fOk = btfchat::ChatInvite(addr, text, err); break;
            case ACT_ACCEPT:  fOk = btfchat::ChatAcceptInvite(addr, err); break;
            case ACT_DECLINE: fOk = btfchat::ChatDeclineInvite(addr, err); break;
            case ACT_BLOCK:   fOk = btfchat::ChatBlock(addr, err); break;
            case ACT_SEND:
            {
                bool fMailbox = false;
                fOk = btfchat::ChatSendText(addr, text, fMailbox, err);
                // "Sent" and "left for them" are different promises. Saying
                // "sent" for a message sitting on a relay waiting for somebody to
                // come online would be the kind of small lie a user plans around.
                if (fOk && fMailbox)
                    err = "they are not online -- left in their mailbox, they get it when they open the chat";
                break;
            }
            case ACT_DIRECTORY:
            {
                std::vector<CChatListing> v;
                fOk = btfchat::ChatCommunityDirectory(v, err);
                if (fOk)
                {
                    CRITICAL_BLOCK(cs_ui)
                        g_directory = v;
                    err = strprintf("%u public communit%s on the chain", (unsigned)v.size(),
                                    v.size() == 1 ? "y" : "ies");
                }
                break;
            }
            case ACT_CREATE:
            {
                std::string txid, id;
                fOk = btfchat::ChatCommunityCreatePublic(text, txid, id, err);
                if (fOk)
                    err = strprintf("#%s listed (%s...): public and permanent once it is in a block",
                                    text.c_str(), txid.substr(0, 12).c_str());
                break;
            }
            case ACT_POST:
                fOk = btfchat::ChatCommunityPost(addr, text, err);
                break;
            case ACT_OFFER:
            {
                btfchat::SwapOffer o;
                fOk = btfchat::ParseSwapOffer(text, o, err) && btfchat::ChatSwapPostOffer(addr, o, err);
                if (fOk)
                    err = "offer posted: " + btfchat::DescribeSwapOffer(o);
                break;
            }
            case ACT_TAKE:
                fOk = btfchat::ChatSwapTake(addr, text, err);
                if (fOk)
                    err = "swap started -- it goes on in your conversation with them";
                break;
            case ACT_SWAP_OK:
                fOk = btfchat::ChatSwapApprove(text, err);
                break;
            case ACT_SWAP_CANCEL:
                fOk = btfchat::ChatSwapCancel(text, err);
                break;
            case ACT_REQUEST:
            case ACT_PAY:
            {
                // text is "<amount>\n<note>"; the amount was parsed when queued.
                size_t nl = text.find('\n');
                int64 nAmount = 0;
                ParseMoney(text.substr(0, nl).c_str(), nAmount);
                std::string note = nl == std::string::npos ? std::string() : text.substr(nl + 1);
                bool fMailbox = false;
                if (k == ACT_REQUEST)
                {
                    fOk = btfchat::ChatShareAddress(addr, nAmount, note, fMailbox, err);
                    if (fOk && err.empty())
                        err = fMailbox ? "address left in their mailbox" : "address sent";
                }
                else
                {
                    std::string txid;
                    fOk = btfchat::ChatPay(addr, nAmount, note, txid, fMailbox, err);
                    if (fOk && err.empty())
                        err = strprintf("paid %s BTF (%s...)%s", FormatMoney(nAmount).c_str(),
                                        txid.substr(0, 12).c_str(),
                                        fMailbox ? " -- they will see the note when they come online" : "");
                }
                break;
            }
            default: break;
            }

            // Zero the password buffer we copied out, not just the shared one.
            if (!password.empty())
                memset(&password[0], 0, password.size());

            CRITICAL_BLOCK(cs_ui)
            {
                g_running = ACT_NONE;
                g_fMessageOk = fOk;
                if (!err.empty())
                    g_message = err;     // a success with something to say still says it
                else
                    g_message.clear();
            }
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatUiWorker()"); }
    catch (...)               { PrintException(NULL, "ThreadChatUiWorker()"); }

    CRITICAL_BLOCK(cs_ui)
        g_fWorkerAlive = false;
}

bool Busy()
{
    CRITICAL_BLOCK(cs_ui)
        return g_running != ACT_NONE || g_pending != ACT_NONE;
    return false;
}

// Queue one action. Refuses while another is running, so the button cannot be
// double-pressed into two dials.
bool Queue(ActionKind k, const std::string& addr, const std::string& text,
           const std::string& password)
{
    CRITICAL_BLOCK(cs_ui)
    {
        if (g_running != ACT_NONE || g_pending != ACT_NONE)
            return false;
        g_pending = k;
        g_argAddr = addr;
        g_argText = text;
        g_argPassword = password;
        g_message.clear();
        if (!g_fWorkerAlive)
        {
            if (_beginthread(ThreadChatUiWorker, 0, NULL) == -1)
            {
                g_pending = ACT_NONE;
                g_message = "could not start the chat worker thread";
                return false;
            }
            g_fWorkerAlive = true;
        }
    }
    return true;
}

std::string Message()
{
    CRITICAL_BLOCK(cs_ui)
        return g_message;
    return std::string();
}

// ---- money: what our own wallet says ------------------------------------------
//
// The window never calls the wallet itself -- a wallet that hangs would freeze
// the chat. A thread asks, every few seconds, about the payments the window
// has on screen, and the window reads the answers.

struct PayStatus
{
    bool    fKnown;     // our wallet has seen the transaction
    int64_t nReceived;  // what of it came to us
    int     nConf;
    PayStatus() : fKnown(false), nReceived(0), nConf(0) {}
};
std::map<std::string, PayStatus> g_payStatus;   // txid -> what the wallet said
std::set<std::string> g_payWanted;              // txids the window wants news of
std::string g_walletStatus = "wallet: checking";
bool g_fWalletLinked = false;
bool g_fPayThreadAlive = false;

void ThreadPaymentStatus(void*)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadPaymentStatus(NULL));
    try
    {
        while (!fShutdown)
        {
            std::string st;
            bool fLinked = btfchat::WalletLinked(st);
            std::vector<std::string> want;
            CRITICAL_BLOCK(cs_ui)
            {
                g_walletStatus = st;
                g_fWalletLinked = fLinked;
                want.assign(g_payWanted.begin(), g_payWanted.end());
            }
            for (size_t i = 0; fLinked && i < want.size() && !fShutdown; i++)
            {
                PayStatus ps;
                std::string err;
                ps.fKnown = btfchat::WalletLookup(want[i], ps.nReceived, ps.nConf, err);
                CRITICAL_BLOCK(cs_ui)
                    g_payStatus[want[i]] = ps;
            }
            for (int s = 0; s < 10 && !fShutdown; s++)
                Sleep(1000);
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadPaymentStatus()"); }
    catch (...)               { PrintException(NULL, "ThreadPaymentStatus()"); }
}

void EnsurePaymentThread()
{
    CRITICAL_BLOCK(cs_ui)
    {
        if (g_fPayThreadAlive)
            return;
        if (_beginthread(ThreadPaymentStatus, 0, NULL) != -1)
            g_fPayThreadAlive = true;
    }
}

// MessageColour() is defined with the palette, further down.

ActionKind Running()
{
    CRITICAL_BLOCK(cs_ui)
        return g_running;
    return ACT_NONE;
}

// ---- the look --------------------------------------------------------------
//
// Square, hairline, almost black. Deliberately not the rounded pastel of a
// consumer messenger: this is the same bench the node runs on, and looking like
// a toy would be the wrong promise.

const ImVec4 COL_BG     = ImVec4(0.02f, 0.02f, 0.02f, 1.0f);
const ImVec4 COL_PANEL  = ImVec4(0.045f, 0.045f, 0.045f, 1.0f);
const ImVec4 COL_LINE   = ImVec4(0.16f, 0.16f, 0.16f, 1.0f);
const ImVec4 COL_DIM    = ImVec4(0.45f, 0.45f, 0.45f, 1.0f);
const ImVec4 COL_TEXT   = ImVec4(0.82f, 0.82f, 0.82f, 1.0f);
const ImVec4 COL_OK     = ImVec4(0.35f, 0.85f, 0.45f, 1.0f);
const ImVec4 COL_WARN   = ImVec4(1.00f, 0.62f, 0.15f, 1.0f);
const ImVec4 COL_BAD    = ImVec4(0.95f, 0.35f, 0.35f, 1.0f);
const ImVec4 COL_MINE   = ImVec4(0.55f, 0.72f, 1.00f, 1.0f);

// Amber for "it worked, and here is what happened", red for "it did not". The
// same sentence in the wrong colour is a different sentence.
ImVec4 MessageColour()
{
    CRITICAL_BLOCK(cs_ui)
        return g_fMessageOk ? COL_WARN : COL_BAD;
    return COL_BAD;
}

// A hairline, the way the mock has it: one pixel, no gradient, no shadow.
void Hairline()
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    dl->AddLine(ImVec2(p.x, p.y), ImVec2(p.x + w, p.y), ImGui::GetColorU32(COL_LINE), 1.0f);
    ImGui::Dummy(ImVec2(0.0f, 3.0f));
}

// The address, shortened for a list: the first and last few characters are what
// a person actually compares, and the middle never gets read.
std::string ShortAddr(const std::string& a)
{
    if (a.size() <= 22)
        return a;
    return a.substr(0, 10) + "..." + a.substr(a.size() - 9);
}

// Just the clock time. A conversation is read newest-first and the day is
// obvious from context; a full date on every line is noise that pushes the
// message itself off the edge on a narrow window.
std::string FmtWhen(int64_t t)
{
    if (t <= 0)
        return "";
    time_t tt = (time_t)t;
    struct tm* p = localtime(&tt);
    if (!p)
        return "";
    char buf[16];
    strftime(buf, sizeof(buf), "%H:%M", p);
    return buf;
}

// ---- state the window keeps ------------------------------------------------

char g_passwordBuf[128]   = {0};
char g_inviteAddrBuf[128] = {0};
char g_inviteNoteBuf[200] = {0};
char g_msgBuf[1024]       = {0};
char g_payAmountBuf[32]   = {0};   // BTF, for "ask" and "pay"
bool g_fConfirmPay        = false; // second press of "pay" -- money does not move on one click
std::string g_selected;               // which conversation is open
std::string g_selectedCommunity;      // or which community (its id); one or the other
bool g_fShowDirectory = false;
char g_communityNameBuf[40] = {0};
char g_postBuf[1024] = {0};
// A swap offer being written: what we give (0 BTF, 1 BTC) and the two amounts.
int  g_offerGive = 0;
char g_offerGiveBuf[32] = {0};
char g_offerWantBuf[32] = {0};
// The swap whose lock is waiting for its second press.
std::string g_swapConfirm;
bool g_fShowInvite = false;           // the "add someone" panel
bool g_fConfirmAddress = false;       // showing the just-unlocked address

// Wipe the password box. Called the moment it has been handed to the worker and
// whenever the window locks, so it is not sitting in a buffer for the next hour.
void WipePassword()
{
    memset(g_passwordBuf, 0, sizeof(g_passwordBuf));
}

// ---- panels ----------------------------------------------------------------

void DrawLockedPanel()
{
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::TextUnformatted("btfchat");
    ImGui::PopStyleColor();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("identity derived from your 12 words plus a session password");
    ImGui::PopStyleColor();
    Hairline();
    ImGui::Dummy(ImVec2(0.0f, 6.0f));

    if (btfchat::ChatPort() == 0)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
        ImGui::TextWrapped("The chat is not enabled in this run.");
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextWrapped(
            "Close and start again with /chat. The port and the chat's onion service are "
            "settled before Tor starts, because the torrc is written once -- turning the "
            "chat on later would mean restarting Tor and changing the onion address.");
        ImGui::PopStyleColor();
        return;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("session password (12 characters minimum)");
    ImGui::PopStyleColor();

    ImGui::SetNextItemWidth(-1.0f);
    bool fEnter = ImGui::InputText("##chatpw", g_passwordBuf, sizeof(g_passwordBuf),
                                   ImGuiInputTextFlags_Password |
                                   ImGuiInputTextFlags_EnterReturnsTrue);
    size_t nLen = strlen(g_passwordBuf);
    bool fLongEnough = nLen >= btfchat::MIN_PASSWORD_CHARS;

    ImGui::PushStyleColor(ImGuiCol_Text, fLongEnough ? COL_OK : COL_DIM);
    ImGui::Text("%d/%d", (int)nLen, (int)btfchat::MIN_PASSWORD_CHARS);
    ImGui::PopStyleColor();

    bool fGo = ImGui::Button("  unlock  ") || fEnter;
    if (fGo && fLongEnough && !Busy())
    {
        Queue(ACT_UNLOCK, "", "", std::string(g_passwordBuf, nLen));
        WipePassword();
        g_fConfirmAddress = true;
    }

    ImGui::Dummy(ImVec2(0.0f, 8.0f));
    Hairline();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    // The thing a user has to understand before they type, said once, plainly.
    ImGui::TextWrapped(
        "The password goes into deriving the key; it is not checked against anything "
        "stored. A wrong one does not fail -- it opens a different, empty identity. "
        "That is why the address is shown after unlocking: you are the one who "
        "recognises it. There is no password recovery, because there is nothing to "
        "compare against.");
    ImGui::PopStyleColor();
}

void DrawStatusStrip()
{
    std::string addr = btfchat::ChatAddress();
    std::string onion = btfchat::ChatOnionEndpoint();

    ImGui::PushStyleColor(ImGuiCol_Text, COL_OK);
    ImGui::TextUnformatted("e2e active");
    ImGui::PopStyleColor();
    ImGui::SameLine(0.0f, 10.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    // Spelled out because it is the claim the whole thing rests on, and because
    // "end to end" on its own has been used to mean almost nothing.
    ImGui::TextUnformatted("x25519+x25519+ml-kem-1024 - a ratchet per message");
    ImGui::PopStyleColor();

    ImGui::SameLine();
    float w = ImGui::GetContentRegionAvail().x;
    int64_t nLeft = btfchat::ChatSecondsBeforeLock();
    char buf[64];
    snprintf(buf, sizeof(buf), "locks in %d:%02d", (int)(nLeft / 60), (int)(nLeft % 60));
    ImGui::SameLine(ImGui::GetCursorPosX() + w - ImGui::CalcTextSize(buf).x - 4.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, nLeft < 120 ? COL_WARN : COL_DIM);
    ImGui::TextUnformatted(buf);
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("you:");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::TextUnformatted(addr.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::SmallButton("copy"))
        ImGui::SetClipboardText(addr.c_str());

    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("service: %s", btfchat::ChatServiceStatus().c_str());
    ImGui::PopStyleColor();
    if (onion.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
        ImGui::TextWrapped("The chat's onion service is not up yet. Nobody can reach you until Tor "
                           "creates that address -- you can still call anyone who is already "
                           "online.");
        ImGui::PopStyleColor();
    }
    Hairline();
}

void DrawInvitePanel()
{
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::TextUnformatted("invite someone");
    ImGui::PopStyleColor();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("their .btf chat address");
    ImGui::PopStyleColor();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##invaddr", g_inviteAddrBuf, sizeof(g_inviteAddrBuf));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("note (optional, %d characters)", (int)btfchat::MAX_INVITE_NOTE);
    ImGui::PopStyleColor();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##invnote", g_inviteNoteBuf, sizeof(g_inviteNoteBuf));

    bool fCan = strlen(g_inviteAddrBuf) > 4 && !Busy();
    if (!fCan) ImGui::BeginDisabled();
    if (ImGui::Button("  send invite  "))
    {
        Queue(ACT_INVITE, g_inviteAddrBuf, g_inviteNoteBuf, "");
        memset(g_inviteAddrBuf, 0, sizeof(g_inviteAddrBuf));
        memset(g_inviteNoteBuf, 0, sizeof(g_inviteNoteBuf));
        g_fShowInvite = false;
    }
    if (!fCan) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("  cancel  "))
        g_fShowInvite = false;
    Hairline();
}

void DrawSidebar(float width)
{
    ImGui::BeginChild("##chatside", ImVec2(width, 0.0f), false);

    if (ImGui::Button(g_fShowInvite ? " - " : " + ", ImVec2(28.0f, 0.0f)))
        g_fShowInvite = !g_fShowInvite;
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("invite someone");
    ImGui::PopStyleColor();
    Hairline();

    // Pending invites first: they are the only thing on this screen that needs a
    // decision, and burying them under the contact list is how people accept
    // things without reading them.
    std::vector<btfchat::Invite> pending;
    btfchat::ChatPendingInvites(pending);
    if (!pending.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
        ImGui::Text("invites (%d)", (int)pending.size());
        ImGui::PopStyleColor();
        for (size_t i = 0; i < pending.size(); i++)
        {
            ImGui::PushID((int)i);
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
            ImGui::TextUnformatted(ShortAddr(pending[i].address).c_str());
            ImGui::PopStyleColor();
            if (!pending[i].note.empty())
            {
                ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
                ImGui::TextWrapped("%s", pending[i].note.c_str());
                ImGui::PopStyleColor();
            }
            bool fBusy = Busy();
            if (fBusy) ImGui::BeginDisabled();
            if (ImGui::SmallButton("accept"))
                Queue(ACT_ACCEPT, pending[i].address, "", "");
            ImGui::SameLine();
            if (ImGui::SmallButton("decline"))
                Queue(ACT_DECLINE, pending[i].address, "", "");
            ImGui::SameLine();
            if (ImGui::SmallButton("block"))
                Queue(ACT_BLOCK, pending[i].address, "", "");
            if (fBusy) ImGui::EndDisabled();
            ImGui::PopID();
            Hairline();
        }
    }

    // Invites we sent and nobody answered yet. Shown, so a person knows the
    // invite exists and can send it again -- the first try routinely fails
    // while the other side's onion is still coming up.
    std::vector<std::string> sent;
    btfchat::ChatSentInvites(sent);
    if (!sent.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::Text("invites sent (%d)", (int)sent.size());
        ImGui::PopStyleColor();
        for (size_t i = 0; i < sent.size(); i++)
        {
            ImGui::PushID(("sent" + sent[i]).c_str());
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
            ImGui::TextUnformatted(ShortAddr(sent[i]).c_str());
            ImGui::PopStyleColor();
            ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
            ImGui::TextUnformatted("waiting for them to accept");
            ImGui::PopStyleColor();
            bool fBusy = Busy();
            if (fBusy) ImGui::BeginDisabled();
            if (ImGui::SmallButton("send again"))
                Queue(ACT_INVITE, sent[i], "", "");
            if (fBusy) ImGui::EndDisabled();
            ImGui::PopID();
        }
        Hairline();
    }

    std::vector<std::string> contacts;
    btfchat::ChatContacts(contacts);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("conversations (%d)", (int)contacts.size());
    ImGui::PopStyleColor();

    if (contacts.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextWrapped("None yet. Nobody can write to you before you accept an invite, "
                           "and that is on purpose.");
        ImGui::PopStyleColor();
    }
    for (size_t i = 0; i < contacts.size(); i++)
    {
        bool fSel = contacts[i] == g_selected;
        if (ImGui::Selectable(ShortAddr(contacts[i]).c_str(), fSel))
        {
            g_selected = contacts[i];
            g_selectedCommunity.clear();
        }
    }

    // Public communities: rooms whose directory is the chain (community.h).
    Hairline();
    std::vector<std::pair<std::string, std::string> > rooms;
    btfchat::ChatCommunities(rooms);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("communities (%d)", (int)rooms.size());
    ImGui::PopStyleColor();
    for (size_t i = 0; i < rooms.size(); i++)
    {
        ImGui::PushID((int)(1000 + i));
        bool fSel = rooms[i].first == g_selectedCommunity;
        if (ImGui::Selectable(("#" + rooms[i].second).c_str(), fSel))
        {
            g_selectedCommunity = rooms[i].first;
            g_selected.clear();
        }
        ImGui::PopID();
    }
    bool fBusy = Busy();
    if (fBusy) ImGui::BeginDisabled();
    if (ImGui::SmallButton(g_fShowDirectory ? "hide directory" : "public directory"))
    {
        g_fShowDirectory = !g_fShowDirectory;
        if (g_fShowDirectory)
            Queue(ACT_DIRECTORY, "", "", "");
    }
    if (fBusy) ImGui::EndDisabled();

    if (g_fShowDirectory)
    {
        std::vector<CChatListing> dir;
        CRITICAL_BLOCK(cs_ui)
            dir = g_directory;
        std::map<std::string, bool> joined;
        for (size_t i = 0; i < rooms.size(); i++)
            joined[rooms[i].first] = true;
        if (dir.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
            ImGui::TextWrapped("Nothing listed yet -- or the nodes have not answered.");
            ImGui::PopStyleColor();
        }
        for (size_t i = 0; i < dir.size(); i++)
        {
            ImGui::PushID((int)(5000 + i));
            std::string id = community::IdHex(&dir[i].key[0]);
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
            ImGui::Text("#%s", dir[i].name.c_str());
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("id %s\nlisted in block %d, burned %s BTF",
                                  id.substr(0, 16).c_str(), dir[i].nHeight, FormatMoney(dir[i].nBurn).c_str());
            ImGui::SameLine();
            if (joined.count(id))
            {
                ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
                ImGui::TextUnformatted("joined");
                ImGui::PopStyleColor();
            }
            else if (ImGui::SmallButton("join"))
            {
                std::string newId, err;
                // Local only: the key is already in the block, joining is
                // remembering it. No network, so no worker.
                if (btfchat::ChatCommunityJoin(HexStr(dir[i].key.begin(), dir[i].key.end(), false),
                                               dir[i].name, newId, err))
                {
                    g_selectedCommunity = newId;
                    g_selected.clear();
                }
            }
            ImGui::PopID();
        }

        ImGui::SetNextItemWidth(width - 70.0f);
        ImGui::InputTextWithHint("##newcommunity", "new public name", g_communityNameBuf, sizeof(g_communityNameBuf));
        ImGui::SameLine();
        bool fNameOk = community::NameOk(g_communityNameBuf) && !Busy();
        if (!fNameOk) ImGui::BeginDisabled();
        if (ImGui::SmallButton("create"))
        {
            Queue(ACT_CREATE, "", g_communityNameBuf, "");
            memset(g_communityNameBuf, 0, sizeof(g_communityNameBuf));
        }
        if (!fNameOk) ImGui::EndDisabled();
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextWrapped("Creating one burns 0.01 BTF from your linked wallet. It is listed in "
                           "a block for good: nobody can take it down, you included.");
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
}

void DrawCommunity()
{
    ImGui::BeginChild("##community", ImVec2(0.0f, 0.0f), false);
    std::vector<std::pair<std::string, std::string> > rooms;
    btfchat::ChatCommunities(rooms);
    std::string name;
    for (size_t i = 0; i < rooms.size(); i++)
        if (rooms[i].first == g_selectedCommunity)
            name = rooms[i].second;
    if (name.empty())
    {
        g_selectedCommunity.clear();
        ImGui::EndChild();
        return;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::Text("#%s", name.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("public -- anybody with the key reads it, and the key is on the chain");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::SmallButton("leave##community"))
    {
        std::string err;
        btfchat::ChatCommunityLeave(g_selectedCommunity, err);
        g_selectedCommunity.clear();
        ImGui::EndChild();
        return;
    }
    Hairline();

    const float inputH = 92.0f;
    ImGui::BeginChild("##communitylog", ImVec2(0.0f, -inputH), false);
    std::vector<btfchat::LogEntry> log;
    btfchat::ChatCommunityLog(g_selectedCommunity, log);
    if (log.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextWrapped("No posts in the last day yet. Posts are collected every two minutes.");
        ImGui::PopStyleColor();
    }
    for (size_t i = 0; i < log.size(); i++)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextUnformatted(FmtWhen(log[i].sent).c_str());
        ImGui::SameLine();
        ImGui::TextUnformatted(ShortAddr(log[i].from).c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        btfchat::SwapOffer offer;
        std::string offerErr;
        if (log[i].kind == btfchat::MSG_SWAP_OFFER && btfchat::ParseSwapOffer(log[i].text, offer, offerErr))
        {
            // An offer: the terms are the signed post, the take goes to whoever signed it.
            ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
            ImGui::TextWrapped("[SWAP] gives %s%s%s", btfchat::DescribeSwapOffer(offer).c_str(),
                               offer.note.empty() ? "" : " -- ", offer.note.c_str());
            ImGui::PopStyleColor();
            if (!log[i].outgoing)
            {
                ImGui::SameLine();
                bool fCanTake = !Busy();
                if (!fCanTake) ImGui::BeginDisabled();
                if (ImGui::SmallButton(("take##" + log[i].id).c_str()))
                    Queue(ACT_TAKE, g_selectedCommunity, log[i].id, "");
                if (!fCanTake) ImGui::EndDisabled();
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Starts a swap with them in your conversation. Nothing is locked until\n"
                                      "their side is on the chain, checked, and you confirm.");
            }
            continue;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, log[i].outgoing ? COL_MINE : COL_TEXT);
        ImGui::TextWrapped("%s", log[i].text.c_str());
        ImGui::PopStyleColor();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    Hairline();
    ImGui::SetNextItemWidth(-90.0f);
    bool fEnter = ImGui::InputText("##postinput", g_postBuf, sizeof(g_postBuf),
                                   ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    bool fCan = strlen(g_postBuf) > 0 && !Busy();
    if (!fCan) ImGui::BeginDisabled();
    bool fPost = ImGui::Button(" post ");
    if (!fCan) ImGui::EndDisabled();
    if ((fPost || fEnter) && fCan)
    {
        Queue(ACT_POST, g_selectedCommunity, g_postBuf, "");
        memset(g_postBuf, 0, sizeof(g_postBuf));
    }

    // A swap offer: what we give and what we want for it. Posting locks
    // nothing; whoever takes it locks second, after we do.
    const char* coins[] = { "BTF", "BTC" };
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::TextUnformatted("swap: give");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputTextWithHint("##offergive", "amount", g_offerGiveBuf, sizeof(g_offerGiveBuf),
                             ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(64.0f);
    ImGui::Combo("##offercoin", &g_offerGive, coins, 2);
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("for");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputTextWithHint("##offerwant", "amount", g_offerWantBuf, sizeof(g_offerWantBuf),
                             ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::Text("%s", coins[1 - g_offerGive]);
    ImGui::SameLine();
    btfchat::SwapOffer o;
    o.give = coins[g_offerGive];
    o.want = coins[1 - g_offerGive];
    int64 nGive = 0, nWant = 0;
    bool fOfferOk = ParseMoney(g_offerGiveBuf, nGive) && nGive > 0 && ParseMoney(g_offerWantBuf, nWant) && nWant > 0 &&
                    !Busy();
    if (!fOfferOk) ImGui::BeginDisabled();
    if (ImGui::Button("offer"))
    {
        o.giveAmount = nGive;
        o.wantAmount = nWant;
        Queue(ACT_OFFER, g_selectedCommunity, btfchat::FormatSwapOffer(o), "");
        memset(g_offerGiveBuf, 0, sizeof(g_offerGiveBuf));
        memset(g_offerWantBuf, 0, sizeof(g_offerWantBuf));
    }
    if (!fOfferOk) ImGui::EndDisabled();
    ImGui::EndChild();
}

// The swaps with this person, above the conversation: where each stands, and
// the one button it may be waiting for.
void DrawSwaps(const std::string& peer)
{
    std::vector<btfchat::SwapView> swaps;
    btfchat::ChatSwapList(swaps);
    for (size_t i = 0; i < swaps.size(); i++)
    {
        const btfchat::SwapView& s = swaps[i];
        if (s.peer != peer)
            continue;
        bool fFinal = s.stage == btfchat::SW_DONE || s.stage == btfchat::SW_REFUNDED ||
                      s.stage == btfchat::SW_CANCELLED || s.stage == btfchat::SW_FAILED;
        // Finished swaps stay a day, then make room.
        if (fFinal && GetTime() - s.updated > 24 * 3600)
            continue;
        ImVec4 col = s.stage == btfchat::SW_DONE ? COL_OK
                   : (s.stage == btfchat::SW_FAILED ? COL_BAD : (fFinal ? COL_DIM : COL_WARN));
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextWrapped("[SWAP] you give %s %s, get %s %s -- %s",
                           btfchat::FormatSwapAmount(s.giveAmount).c_str(), s.give.c_str(),
                           btfchat::FormatSwapAmount(s.wantAmount).c_str(), s.want.c_str(), s.status.c_str());
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered() && (!s.myTxid.empty() || !s.theirTxid.empty()))
            ImGui::SetTooltip("ours   %s\ntheirs %s\nredeem %s\nrefund %s", s.myTxid.c_str(), s.theirTxid.c_str(),
                              s.redeemTxid.c_str(), s.refundTxid.c_str());
        if (!fFinal && (s.give == "BTC" || s.want == "BTC"))
        {
            ImGui::PushID(s.id.c_str());
            static std::map<std::string, std::string> destinations;
            std::string& text = destinations[s.id];
            if (text.empty()) text = s.btcDestination;
            char address[96] = {0}; strncpy(address, text.c_str(), sizeof(address)-1);
            bool editable = s.myTxid.empty() && s.paymentAddress.empty();
            if (!editable) ImGui::BeginDisabled();
            if (ImGui::InputTextWithHint("your Bitcoin receiving address", "1... / 3... / bc1... / tb1... / bcrt1...", address, sizeof(address)))
                text = address;
            ImGui::SameLine();
            if (ImGui::SmallButton("save address")) btfchat::ChatSwapBitcoinDestination(s.id, text);
            if (!editable) ImGui::EndDisabled();
            if (s.stage == btfchat::SW_WAIT_PAYMENT)
            {
                ImGui::TextWrapped("Waiting for you to pay the contract. Pay exactly %s BTC.", btfchat::FormatSwapAmount(s.giveAmount).c_str());
                ImGui::TextWrapped("%s", s.paymentAddress.c_str());
                if (ImGui::SmallButton("copy payment address")) ImGui::SetClipboardText(s.paymentAddress.c_str());
            }
            ImGui::PopID();
        }
        bool fBusy = Busy();
        if (s.fNeedsMe)
        {
            std::string label = strprintf("%s: lock %s %s", s.fMaker ? "accept" : "go on",
                                          btfchat::FormatSwapAmount(s.giveAmount).c_str(), s.give.c_str());
            if (fBusy) ImGui::BeginDisabled();
            if (g_swapConfirm != s.id)
            {
                if (ImGui::SmallButton((label + "##" + s.id).c_str()))
                    g_swapConfirm = s.id;
            }
            else
            {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.45f, 0.25f, 0.05f, 1.0f));
                if (ImGui::SmallButton(("confirm: " + label + "##c" + s.id).c_str()))
                {
                    Queue(ACT_SWAP_OK, peer, s.id, "");
                    g_swapConfirm.clear();
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Your coins go into the contract. They come back by themselves if the\n"
                                      "swap does not finish -- keep the chat open until it does.");
            }
            if (fBusy) ImGui::EndDisabled();
            ImGui::SameLine();
        }
        if (s.fCanCancel)
        {
            if (fBusy) ImGui::BeginDisabled();
            if (ImGui::SmallButton(("cancel##swap" + s.id).c_str()))
            {
                Queue(ACT_SWAP_CANCEL, peer, s.id, "");
                g_swapConfirm.clear();
            }
            if (fBusy) ImGui::EndDisabled();
        }
        else if (s.fNeedsMe)
            ImGui::NewLine();
    }
}

// A swap step as a line of the conversation: what happened, not the JSON.
std::string DescribeStep(const btfchat::LogEntry& e)
{
    btfchat::SwapStep st;
    std::string err;
    if (!btfchat::ParseSwapStep(e.text, st, err))
        return "a swap step this build cannot read";
    const char* who = e.outgoing ? "you" : "they";
    if (st.step == "take")
        return strprintf("%s asked to take the offer: %s", who, btfchat::DescribeSwapOffer(st.terms).c_str());
    if (st.step == "lock1" || st.step == "lock2")
        return strprintf("%s locked %s side on the %s chain", who, e.outgoing ? "your" : "their", st.chain.c_str());
    if (st.step == "redeemed")
        return strprintf("%s took the other side with the secret", who);
    if (st.step == "cancel")
        return strprintf("%s cancelled%s%s", who, st.why.empty() ? "" : ": ", st.why.c_str());
    return st.step;
}

void DrawConversation()
{
    ImGui::BeginChild("##chatmain", ImVec2(0.0f, 0.0f), false);

    if (g_selected.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextWrapped("Pick a conversation on the left, or invite someone with + .");
        ImGui::PopStyleColor();
        ImGui::EndChild();
        return;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::TextUnformatted(g_selected.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::SmallButton("copy##sel"))
        ImGui::SetClipboardText(g_selected.c_str());
    ImGui::SameLine();
    bool fBusy = Busy();
    if (fBusy) ImGui::BeginDisabled();
    if (ImGui::SmallButton("block##sel"))
    {
        Queue(ACT_BLOCK, g_selected, "", "");
        g_selected.clear();
    }
    if (fBusy) ImGui::EndDisabled();
    Hairline();

    if (g_selected.empty())
    {
        ImGui::EndChild();
        return;
    }

    const float inputH = 92.0f;
    DrawSwaps(g_selected);
    ImGui::BeginChild("##chatlog", ImVec2(0.0f, -inputH), false);
    std::vector<btfchat::LogEntry> log;
    btfchat::ChatConversation(g_selected, log);
    for (size_t i = 0; i < log.size(); i++)
    {
        const btfchat::LogEntry& e = log[i];
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextUnformatted(FmtWhen(e.sent).c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (e.kind == btfchat::MSG_SWAP)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
            ImGui::TextWrapped("[swap] %s", DescribeStep(e).c_str());
            ImGui::PopStyleColor();
            continue;
        }
        if (e.kind == btfchat::MSG_PAY_ADDRESS)
        {
            std::string what = e.amount > 0
                ? strprintf("%s %s BTF", e.outgoing ? "you asked for" : "they ask for", FormatMoney(e.amount).c_str())
                : std::string(e.outgoing ? "you shared an address to be paid at" : "they shared an address to be paid at");
            ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
            ImGui::TextWrapped("[BTF] %s%s%s", what.c_str(), e.text.empty() ? "" : " -- ", e.text.c_str());
            ImGui::PopStyleColor();
            if (!e.outgoing)
            {
                // The same request as a payment link, for paying it from
                // another wallet: the address is still the one they signed.
                ImGui::SameLine();
                if (ImGui::SmallButton(("copy link##" + e.id).c_str()))
                {
                    PaymentLink link;
                    link.address = e.payTo;
                    link.amount = e.amount;
                    link.message = e.text;
                    ImGui::SetClipboardText(MakePaymentLink(link).c_str());
                }
            }
            continue;
        }
        if (e.kind == btfchat::MSG_PAYMENT)
        {
            std::string status;
            ImVec4 col = COL_OK;
            if (e.outgoing)
                status = "sent from your wallet";
            else
            {
                // What THEIR note says is a claim. What OUR wallet sees is the fact.
                PayStatus ps;
                CRITICAL_BLOCK(cs_ui)
                {
                    g_payWanted.insert(e.txid);
                    std::map<std::string, PayStatus>::const_iterator it = g_payStatus.find(e.txid);
                    if (it != g_payStatus.end())
                        ps = it->second;
                }
                if (!ps.fKnown)
                {
                    status = "not seen by your wallet yet";
                    col = COL_WARN;
                }
                else if (ps.nReceived < e.amount)
                {
                    status = strprintf("your wallet sees only %s BTF of it", FormatMoney(ps.nReceived).c_str());
                    col = COL_BAD;
                }
                else
                    status = strprintf("in your wallet, %d confirmation%s", ps.nConf, ps.nConf == 1 ? "" : "s");
            }
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::TextWrapped("[BTF] %s %s BTF  (%s)%s%s", e.outgoing ? "you paid" : "they paid you",
                               FormatMoney(e.amount).c_str(), status.c_str(),
                               e.text.empty() ? "" : " -- ", e.text.c_str());
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("txid %s\nto %s", e.txid.c_str(), e.payTo.c_str());
            continue;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, e.outgoing ? COL_MINE : COL_TEXT);
        ImGui::TextWrapped("%s", e.text.c_str());
        ImGui::PopStyleColor();
    }

    // What is still waiting, below the conversation and visibly not part of it.
    //
    // These have NOT been delivered. Drawing them like sent messages would be
    // the one lie this program must not tell, so they carry the word and the
    // dim colour, and they move up into the conversation on the day they
    // actually leave.
    std::vector<btfchat::Pending> waiting;
    btfchat::ChatPendingFor(g_selected, waiting);
    for (size_t i = 0; i < waiting.size(); i++)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
        ImGui::TextUnformatted(FmtWhen(waiting[i].sent).c_str());
        ImGui::SameLine();
        ImGui::TextWrapped("%s   [waiting -- they are not online]", waiting[i].text.c_str());
        ImGui::PopStyleColor();
    }

    // Keep the newest line in view, but only when the user is already at the
    // bottom: yanking the view while somebody is reading history is rude.
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    Hairline();
    ImGui::SetNextItemWidth(-90.0f);
    bool fEnter = ImGui::InputText("##chatinput", g_msgBuf, sizeof(g_msgBuf),
                                   ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    bool fCan = strlen(g_msgBuf) > 0 && !Busy();
    if (!fCan) ImGui::BeginDisabled();
    bool fSend = ImGui::Button(" send ");
    if (!fCan) ImGui::EndDisabled();
    if ((fSend || fEnter) && fCan)
    {
        Queue(ACT_SEND, g_selected, g_msgBuf, "");
        memset(g_msgBuf, 0, sizeof(g_msgBuf));
    }

    // Money. The chat holds none: these ask the person's own wallet, through
    // -chatwallet, and the address paid is only ever one the contact signed.
    EnsurePaymentThread();
    bool fLinked = false;
    std::string walletStatus;
    CRITICAL_BLOCK(cs_ui)
    {
        fLinked = g_fWalletLinked;
        walletStatus = g_walletStatus;
    }
    std::string theirAddr;
    int64_t nAsked = 0;
    bool fCanPay = btfchat::ChatPeerPayAddress(g_selected, theirAddr, nAsked);
    if (nAsked > 0 && g_payAmountBuf[0] == 0)
        snprintf(g_payAmountBuf, sizeof(g_payAmountBuf), "%s", FormatMoney(nAsked).c_str());

    ImGui::SetNextItemWidth(110.0f);
    ImGui::InputTextWithHint("##payamt", "amount BTF", g_payAmountBuf, sizeof(g_payAmountBuf),
                             ImGuiInputTextFlags_CharsDecimal);
    int64 nAmount = 0;
    bool fAmountOk = g_payAmountBuf[0] && ParseMoney(g_payAmountBuf, nAmount) && nAmount > 0;
    ImGui::SameLine();
    bool fReqOk = fLinked && !Busy();
    if (!fReqOk) ImGui::BeginDisabled();
    if (ImGui::Button("ask to be paid"))
    {
        // An empty amount is "pay me, whatever you like".
        Queue(ACT_REQUEST, g_selected, strprintf("%s\n", fAmountOk ? g_payAmountBuf : "0"), "");
        g_fConfirmPay = false;
    }
    if (!fReqOk) ImGui::EndDisabled();
    ImGui::SameLine();
    bool fPayOk = fLinked && fCanPay && fAmountOk && !Busy();
    if (!fPayOk) ImGui::BeginDisabled();
    if (!g_fConfirmPay)
    {
        if (ImGui::Button("pay"))
            g_fConfirmPay = true;
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.45f, 0.25f, 0.05f, 1.0f));
        if (ImGui::Button(strprintf("confirm: pay %s BTF", g_payAmountBuf).c_str()))
        {
            Queue(ACT_PAY, g_selected, strprintf("%s\n", g_payAmountBuf), "");
            g_fConfirmPay = false;
            memset(g_payAmountBuf, 0, sizeof(g_payAmountBuf));
        }
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (ImGui::SmallButton("cancel##pay"))
            g_fConfirmPay = false;
    }
    if (!fPayOk) ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, fLinked ? COL_DIM : COL_WARN);
    if (!fLinked)
        ImGui::TextWrapped("%s", walletStatus.c_str());
    else if (!fCanPay)
        ImGui::TextWrapped("%s -- they have not shared an address yet", walletStatus.c_str());
    else
        ImGui::TextWrapped("%s -- pays %s", walletStatus.c_str(), theirAddr.c_str());
    ImGui::PopStyleColor();

    ImGui::EndChild();
}

} // namespace

void DrawChatWindow()
{
    if (!g_showChat)
        return;

    // The inactivity lock is checked here because this is the only place that
    // knows whether anybody is looking. It runs even while the window is open
    // and idle, which is the case it exists for.
    if (btfchat::ChatCheckInactivity())
    {
        WipePassword();
        g_selected.clear();
        g_fConfirmAddress = false;
    }

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(ImVec2(760.0f, 520.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, COL_BG);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_PANEL);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, COL_PANEL);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_LINE);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);

    if (ImGui::Begin("btfchat", &g_showChat, ImGuiWindowFlags_NoCollapse))
    {
        // Any interaction with this window counts as the user being here.
        if (ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
            (io.MouseDown[0] || io.MouseWheel != 0.0f))
            btfchat::ChatTouch();
        if (io.WantTextInput)
            btfchat::ChatTouch();

        ActionKind running = Running();
        std::string msg = Message();

        if (!btfchat::ChatUnlocked())
        {
            DrawLockedPanel();
            if (running != ACT_NONE)
            {
                ImGui::Dummy(ImVec2(0.0f, 6.0f));
                ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
                ImGui::Text("%s...", ActionLabel(running));
                ImGui::PopStyleColor();
            }
            if (!msg.empty())
            {
                ImGui::PushStyleColor(ImGuiCol_Text, MessageColour());
                ImGui::TextWrapped("%s", msg.c_str());
                ImGui::PopStyleColor();
            }
        }
        else
        {
            DrawStatusStrip();

            if (g_fConfirmAddress)
            {
                // Shown once, right after unlocking, because a wrong password
                // lands on a different identity instead of failing.
                ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
                ImGui::TextWrapped("Check: is this address yours? If it is not, the password differs "
                                   "from the one you used before -- and this is a different, "
                                   "empty identity.");
                ImGui::PopStyleColor();
                if (ImGui::SmallButton("it is mine"))
                    g_fConfirmAddress = false;
                ImGui::SameLine();
                if (ImGui::SmallButton("it is not -- lock"))
                {
                    btfchat::ChatLock();
                    g_fConfirmAddress = false;
                    g_selected.clear();
                }
                Hairline();
            }

            if (running != ACT_NONE)
            {
                ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
                ImGui::Text("%s...", ActionLabel(running));
                ImGui::PopStyleColor();
            }
            if (!msg.empty())
            {
                ImGui::PushStyleColor(ImGuiCol_Text, MessageColour());
                ImGui::TextWrapped("%s", msg.c_str());
                ImGui::PopStyleColor();
            }

            if (g_fShowInvite)
                DrawInvitePanel();

            const float sideW = 230.0f;
            DrawSidebar(sideW);
            ImGui::SameLine();
            if (!g_selectedCommunity.empty()) DrawCommunity(); else DrawConversation();
        }
    }
    ImGui::End();

    ImGui::PopStyleColor(5);
    ImGui::PopStyleVar(4);

    // Closing the window locks the session: leaving a chat unlocked behind a
    // closed window is the same mistake as leaving it unlocked on screen, minus
    // the reminder that it is open.
    if (!g_showChat && btfchat::ChatUnlocked())
    {
        btfchat::ChatLock();
        WipePassword();
        g_selected.clear();
        g_fConfirmAddress = false;
    }
}

// ---------------------------------------------------------------------------
// btfchat's own window
// ---------------------------------------------------------------------------
//
// Only built into btfchat.exe. The wallet build has no entry point into this,
// which is the point: one process, one identity, one door.

#ifdef BITFLASH_CHAT_APP

#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include "font_roboto.h"


namespace
{

// The bottom strip: the two doors this program has to the network, and whether
// they are open.
//
// No chain height here, because there is no chain. btfchat reaches the outside
// through the Nostr relays over Tor, to look an address up, and through the
// other person's onion, to talk. Showing exactly that -- and nothing that sounds
// bigger -- is the honest version: a status line that implies a node when there
// is no node is a status line that lies.
void DrawChainStrip()
{
    ImGuiIO& io = ImGui::GetIO();
    const float h = 22.0f;
    ImGui::SetNextWindowPos(ImVec2(0.0f, io.DisplaySize.y - h));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 3.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
    ImGui::Begin("##chainstrip", NULL,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    std::string onion = btfchat::ChatOnionEndpoint();
    bool fReachable = !onion.empty();

    ImGui::PushStyleColor(ImGuiCol_Text, fReachable ? COL_OK : COL_WARN);
    ImGui::TextUnformatted(fReachable ? "onion up" : "onion starting");
    ImGui::PopStyleColor();

    ImGui::SameLine(0.0f, 14.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    ImGui::Text("tor: %s", BtfManagedTorStatus().c_str());
    ImGui::PopStyleColor();

    ImGui::SameLine(0.0f, 14.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);
    // Said plainly, because a chat with no chain is the kind of thing a user
    // should be told rather than left to infer from a missing number.
    {
        size_t nKnown = 0, nGood = 0;
        btfchat::NetNodeCounts(nKnown, nGood);
        ImGui::Text("no chain - %u node%s answering, onion only",
                    (unsigned)nGood, nGood == 1 ? "" : "s");
    }
    ImGui::PopStyleColor();

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

// The chat, filling the window instead of floating in one.
void DrawChatFullWindow()
{
    ImGuiIO& io = ImGui::GetIO();
    const float stripH = 22.0f;

    if (btfchat::ChatCheckInactivity())
    {
        WipePassword();
        g_selected.clear();
        g_fConfirmAddress = false;
    }

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - stripH));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 10.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, COL_BG);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_PANEL);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, COL_PANEL);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_LINE);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);

    ImGui::Begin("##btfchatroot", NULL,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (io.MouseDown[0] || io.MouseWheel != 0.0f || io.WantTextInput)
        btfchat::ChatTouch();

    ActionKind running = Running();
    std::string msg = Message();

    if (!btfchat::ChatUnlocked())
    {
        DrawLockedPanel();
        if (running != ACT_NONE)
        {
            ImGui::Dummy(ImVec2(0.0f, 6.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
            ImGui::Text("%s...", ActionLabel(running));
            ImGui::PopStyleColor();
        }
        if (!msg.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, MessageColour());
            ImGui::TextWrapped("%s", msg.c_str());
            ImGui::PopStyleColor();
        }
    }
    else
    {
        DrawStatusStrip();

        if (g_fConfirmAddress)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
            ImGui::TextWrapped("Check: is this address yours? If it is not, the password differs from "
                               "the one you used before -- and this is a different, empty "
                               "identity.");
            ImGui::PopStyleColor();
            if (ImGui::SmallButton("it is mine"))
                g_fConfirmAddress = false;
            ImGui::SameLine();
            if (ImGui::SmallButton("it is not -- lock"))
            {
                btfchat::ChatLock();
                g_fConfirmAddress = false;
                g_selected.clear();
                WipePassword();
            }
            Hairline();
        }

        if (running != ACT_NONE)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, COL_WARN);
            ImGui::Text("%s...", ActionLabel(running));
            ImGui::PopStyleColor();
        }
        if (!msg.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, MessageColour());
            ImGui::TextWrapped("%s", msg.c_str());
            ImGui::PopStyleColor();
        }

        if (g_fShowInvite)
            DrawInvitePanel();

        const float sideW = 250.0f;
        DrawSidebar(sideW);
        ImGui::SameLine();
        if (!g_selectedCommunity.empty()) DrawCommunity(); else DrawConversation();
    }

    ImGui::End();
    ImGui::PopStyleColor(5);
    ImGui::PopStyleVar(4);
}

} // namespace

int RunChatGUI(int argc, char* argv[])
{
    (void)argc; (void)argv;

    if (!glfwInit())
    {
        printf("btfchat: glfwInit() failed -- no display or GL available.\n");
        return 1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(880, 600, "btfchat", NULL, NULL);
    if (!window)
    {
        printf("btfchat: could not create an OpenGL 3.3 window.\n");
        printf("         Update the graphics driver, or use a software OpenGL (Mesa).\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = NULL;
    io.Fonts->AddFontFromMemoryCompressedTTF(
        RobotoMedium_compressed_data, RobotoMedium_compressed_size, 14.0f);

    ImGui::StyleColorsDark();
    ImGuiStyle& st = ImGui::GetStyle();
    // Square and hairline, not the rounded pastel of a consumer messenger. This
    // runs on the same bench as the node and looking like a toy would be the
    // wrong promise about what it is.
    st.WindowRounding = st.FrameRounding = st.PopupRounding = st.ChildRounding = 0.0f;
    st.GrabRounding = st.ScrollbarRounding = 0.0f;
    st.WindowBorderSize = st.FrameBorderSize = 1.0f;
    st.ItemSpacing  = ImVec2(8.0f, 6.0f);
    st.FramePadding = ImVec2(7.0f, 4.0f);
    st.Colors[ImGuiCol_Button]        = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    st.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.20f, 0.20f, 0.20f, 1.0f);
    st.Colors[ImGuiCol_ButtonActive]  = ImVec4(0.28f, 0.28f, 0.28f, 1.0f);
    st.Colors[ImGuiCol_Header]        = ImVec4(0.16f, 0.16f, 0.16f, 1.0f);
    st.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.22f, 0.22f, 0.22f, 1.0f);
    st.Colors[ImGuiCol_HeaderActive]  = ImVec4(0.26f, 0.26f, 0.26f, 1.0f);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    while (!glfwWindowShouldClose(window) && !fShutdown)
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        DrawChatFullWindow();
        DrawChainStrip();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.02f, 0.02f, 0.02f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // Closing the window locks the session and wipes the keys, the same as the
    // inactivity timer would. A chat left unlocked in a process that is exiting
    // is a chat whose keys were in memory when the memory was handed back.
    btfchat::ChatServiceStop();
    btfchat::ChatLock();
    WipePassword();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    fShutdown = true;
    return 0;
}

// The node core calls this to ask the wallet window to repaint. btfchat has no
// wallet window, and its own loop redraws every frame anyway.
void MainFrameRepaint()
{
}

#endif // BITFLASH_CHAT_APP
