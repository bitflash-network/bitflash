// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat in a terminal: the same chat as the window -- same identity, same
// mailbox in the nodes, same money and swaps -- driven by typed commands, with
// what arrives printed as it arrives. It is the whole of btfchat on macOS,
// where it ships without a window, and `btfchat -terminal` anywhere else.
//
// Nothing here is chat logic. Every command is one call into btfchatnode /
// btfchatswap, the calls the window's buttons make (gui_chat.cpp), so the two
// cannot drift apart in what they do -- only in how it looks.

#include "headers.h"
#include "btfchatnode.h"
#include "btfchatnet.h"
#include "btfchatwallet.h"
#include "chatdir.h"
#include "chatswap.h"
#include "btfchatswap.h"
#include "bip21.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

int RunChatTerminal(int argc, char* argv[]);

namespace
{
std::mutex g_out;                       // one line at a time on the screen

// What the last listing showed, so a command can say "2" instead of an address.
std::vector<std::string>   g_contacts;
std::vector<CChatListing>  g_directory;
std::vector<std::pair<std::string, std::string> > g_rooms;   // id, name
std::vector<std::string>   g_offerIds;  // frame ids of offers in the open room
std::vector<std::string>   g_swapIds;

std::string g_peer;                     // the open conversation, or
std::string g_room;                     // the open community (its id)
volatile bool g_fQuit = false;

void Say(const std::string& s)
{
    std::lock_guard<std::mutex> lock(g_out);
    printf("%s\n", s.c_str());
    fflush(stdout);
}

std::string Short(const std::string& addr)
{
    return addr.size() > 16 ? addr.substr(0, 10) + "..." + addr.substr(addr.size() - 8) : addr;
}

std::string When(int64_t t)
{
    time_t tt = (time_t)t;
    char buf[32] = "";
    struct tm* tmv = localtime(&tt);
    if (tmv)
        strftime(buf, sizeof(buf), "%d/%m %H:%M", tmv);
    return buf;
}

std::string RoomName(const std::string& id)
{
    for (size_t i = 0; i < g_rooms.size(); i++)
        if (g_rooms[i].first == id)
            return g_rooms[i].second;
    std::vector<std::pair<std::string, std::string> > v;
    btfchat::ChatCommunities(v);
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].first == id)
            return v[i].second;
    return id.substr(0, 8);
}

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

// One line of a conversation, as the window draws it.
std::string Line(const btfchat::LogEntry& e, bool fWalletStatus)
{
    std::string head = When(e.sent) + "  " + (e.outgoing ? "you" : "them") + ": ";
    if (e.kind == btfchat::MSG_SWAP)
        return head + "[swap] " + DescribeStep(e);
    if (e.kind == btfchat::MSG_PAY_ADDRESS)
    {
        std::string what = e.amount > 0
            ? strprintf("%s %s BTF", e.outgoing ? "you asked for" : "they ask for", FormatMoney(e.amount).c_str())
            : std::string(e.outgoing ? "you shared an address to be paid at" : "they shared an address to be paid at");
        std::string s = head + "[BTF] " + what + (e.text.empty() ? "" : " -- " + e.text);
        if (!e.outgoing)
        {
            // The same request as a link, for paying it from another wallet.
            PaymentLink link;
            link.address = e.payTo;
            link.amount = e.amount;
            link.message = e.text;
            s += "\n      pay it here with: pay " + (e.amount > 0 ? FormatMoney(e.amount) : std::string("<amount>")) +
                 "   or from any wallet: " + MakePaymentLink(link);
        }
        return s;
    }
    if (e.kind == btfchat::MSG_PAYMENT)
    {
        std::string status = "sent from your wallet";
        if (!e.outgoing)
        {
            // What THEIR note says is a claim; what OUR wallet sees is the fact.
            status = "not checked";
            if (fWalletStatus)
            {
                int64_t nReceived = 0;
                int nConf = 0;
                std::string err;
                if (!btfchat::WalletLookup(e.txid, nReceived, nConf, err))
                    status = "not seen by your wallet yet";
                else if (nReceived < e.amount)
                    status = strprintf("your wallet sees only %s BTF of it", FormatMoney(nReceived).c_str());
                else
                    status = strprintf("in your wallet, %d confirmation%s", nConf, nConf == 1 ? "" : "s");
            }
        }
        return head + strprintf("[BTF] %s %s BTF  (%s)%s%s  txid %s", e.outgoing ? "you paid" : "they paid you",
                                FormatMoney(e.amount).c_str(), status.c_str(),
                                e.text.empty() ? "" : " -- ", e.text.c_str(), e.txid.c_str());
    }
    return head + e.text;
}

std::string PostLine(const btfchat::LogEntry& e)
{
    std::string who = e.outgoing ? std::string("you") : Short(e.from);
    if (e.kind == btfchat::MSG_SWAP_OFFER)
    {
        btfchat::SwapOffer o;
        std::string err;
        if (btfchat::ParseSwapOffer(e.text, o, err))
            return When(e.sent) + "  " + who + ": [offer] " + btfchat::DescribeSwapOffer(o);
    }
    return When(e.sent) + "  " + who + ": " + e.text;
}

// "2", a whole .btf address, or the start of one, among the conversations.
bool ResolvePeer(const std::string& token, std::string& out)
{
    std::vector<std::string> v;
    btfchat::ChatContacts(v);
    std::vector<std::string> sent;
    btfchat::ChatSentInvites(sent);
    std::vector<btfchat::Invite> pend;
    btfchat::ChatPendingInvites(pend);
    for (size_t i = 0; i < pend.size(); i++)
        v.push_back(pend[i].address);
    v.insert(v.end(), sent.begin(), sent.end());
    if (!token.empty() && token.find_first_not_of("0123456789") == std::string::npos)
    {
        size_t n = (size_t)atoi(token.c_str());
        if (n >= 1 && n <= g_contacts.size())
        {
            out = g_contacts[n - 1];
            return true;
        }
        return false;
    }
    std::string hit;
    for (size_t i = 0; i < v.size(); i++)
        if (v[i] == token || v[i].compare(0, token.size(), token) == 0)
        {
            if (!hit.empty() && hit != v[i])
                return false;   // ambiguous
            hit = v[i];
        }
    if (hit.empty() && token.size() > 10 && token.find(".btf") != std::string::npos)
        hit = token;            // someone new
    out = hit;
    return !out.empty();
}

bool ResolveSwap(const std::string& token, btfchat::SwapView& out)
{
    std::vector<btfchat::SwapView> v;
    btfchat::ChatSwapList(v);
    if (!token.empty() && token.find_first_not_of("0123456789") == std::string::npos)
    {
        size_t n = (size_t)atoi(token.c_str());
        if (n < 1 || n > g_swapIds.size())
            return false;
        for (size_t i = 0; i < v.size(); i++)
            if (v[i].id == g_swapIds[n - 1])
            {
                out = v[i];
                return true;
            }
        return false;
    }
    for (size_t i = 0; i < v.size(); i++)
        if (!token.empty() && v[i].id.compare(0, token.size(), token) == 0)
        {
            out = v[i];
            return true;
        }
    return false;
}

std::string ReadLine(bool* pfEof = NULL)
{
    std::string s;
    if (!std::getline(std::cin, s))
    {
        if (pfEof) *pfEof = true;
        return std::string();
    }
    if (!s.empty() && s[s.size() - 1] == '\r')
        s.erase(s.size() - 1);
    return s;
}

// The session password, not echoed. Piped input (a script, a test) is read
// as it is.
std::string ReadPassword()
{
#ifdef _WIN32
    if (!_isatty(_fileno(stdin)))
        return ReadLine();
    std::string s;
    for (;;)
    {
        int c = _getch();
        if (c == '\r' || c == '\n' || c == EOF)
            break;
        if (c == 8)
        {
            if (!s.empty()) s.erase(s.size() - 1);
            continue;
        }
        s += (char)c;
    }
    printf("\n");
    return s;
#else
    if (!isatty(STDIN_FILENO))
        return ReadLine();
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::string s = ReadLine();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    return s;
#endif
}

void Help()
{
    Say("commands (an address can be a number from the last list, or its first letters):\n"
        "  me                         your address, Tor, nodes, wallet\n"
        "  invite ADDRESS [note]      ask someone to talk\n"
        "  invites                    invites to answer, and yours still waiting\n"
        "  accept ADDR | decline ADDR | block ADDR\n"
        "  chats                      your conversations\n"
        "  open ADDR                  open one; then just type to send\n"
        "  history [N]                the open conversation (last N lines, default 20)\n"
        "  ask AMOUNT [note]          ask to be paid, in BTF, at a fresh address of your wallet\n"
        "  pay AMOUNT [note]          pay what they asked, from your wallet (asks to confirm)\n"
        "  directory                  public communities on the chain\n"
        "  join N                     join one from the directory\n"
        "  rooms                      the communities you are in\n"
        "  room N                     open one; then just type to post\n"
        "  leave N                    leave one\n"
        "  create NAME                list a new public community (burns 0.01 BTF, asks to confirm)\n"
        "  offer AMOUNT BTF|BTC for AMOUNT   post a swap offer in the open room\n"
        "  offers                     the swap offers in the open room\n"
        "  take N                     take one of them\n"
        "  swaps                      your swaps and where each stands\n"
        "  swap ok N | swap cancel N  the press a swap may be waiting for\n"
        "  swap btc N ADDRESS         your Bitcoin address to receive (and be refunded) at\n"
        "  lock | unlock              wipe the keys from memory / unlock again\n"
        "  help | quit");
}

bool Unlock()
{
    if (btfchat::ChatPort() == 0)
    {
        Say("The chat is not enabled in this run (no chat port).");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_out);
        printf("session password (%d characters minimum): ", (int)btfchat::MIN_PASSWORD_CHARS);
        fflush(stdout);
    }
    std::string pw = ReadPassword();
    if (pw.size() < btfchat::MIN_PASSWORD_CHARS)
    {
        if (!pw.empty()) memset(&pw[0], 0, pw.size());
        Say(strprintf("too short: at least %d characters", (int)btfchat::MIN_PASSWORD_CHARS));
        return false;
    }
    Say("deriving your identity (Argon2id, a second or so)...");
    std::string err;
    bool fOk = btfchat::ChatUnlock(pw, err);
    memset(&pw[0], 0, pw.size());
    if (!fOk)
    {
        Say("could not unlock: " + err);
        return false;
    }
    std::string e2;
    if (!btfchat::ChatServiceStart(e2))
        Say("unlocked, but the service did not start: " + e2);
    Say("you are " + btfchat::ChatAddress());
    Say("Give that address to people who should be able to invite you. Use the same password every time:\n"
        "a different one is a different identity.");
    return true;
}

void ShowMe()
{
    std::string wallet;
    bool fWallet = btfchat::WalletLinked(wallet);
    size_t nKnown = 0, nGood = 0;
    btfchat::NetNodeCounts(nKnown, nGood);
    Say("you:     " + (btfchat::ChatUnlocked() ? btfchat::ChatAddress() : std::string("(locked)")));
    Say("service: " + btfchat::ChatServiceStatus());
    Say(strprintf("nodes:   %u answering, %u known", (unsigned)nGood, (unsigned)nKnown));
    Say(std::string("wallet:  ") + (fWallet ? wallet : "not linked -- " + wallet));
    if (btfchat::ChatUnlocked())
        Say(strprintf("locks after %d more minutes without a command", (int)(btfchat::ChatSecondsBeforeLock() / 60)));
}

void ShowInvites()
{
    std::vector<btfchat::Invite> pend;
    btfchat::ChatPendingInvites(pend);
    std::vector<std::string> sent;
    btfchat::ChatSentInvites(sent);
    if (pend.empty() && sent.empty())
        Say("no invites");
    for (size_t i = 0; i < pend.size(); i++)
        Say("from " + pend[i].address + (pend[i].note.empty() ? "" : "  \"" + pend[i].note + "\"") +
            "   -> accept / decline / block " + Short(pend[i].address).substr(0, 10));
    for (size_t i = 0; i < sent.size(); i++)
        Say("sent to " + sent[i] + "  (waiting for them to accept; 'invite' again to resend)");
}

void ShowChats()
{
    btfchat::ChatContacts(g_contacts);
    if (g_contacts.empty())
        Say("no conversations yet -- 'invite ADDRESS', or accept an invite");
    for (size_t i = 0; i < g_contacts.size(); i++)
        Say(strprintf("%2u  %s%s", (unsigned)(i + 1), g_contacts[i].c_str(), g_contacts[i] == g_peer ? "   (open)" : ""));
}

void ShowHistory(size_t nLast)
{
    if (g_peer.empty())
    {
        Say("no conversation open -- 'chats', then 'open N'");
        return;
    }
    std::vector<btfchat::LogEntry> log;
    btfchat::ChatConversation(g_peer, log);
    size_t from = log.size() > nLast ? log.size() - nLast : 0;
    Say("--- " + g_peer);
    for (size_t i = from; i < log.size(); i++)
        Say(Line(log[i], true));
    std::vector<btfchat::Pending> waiting;
    btfchat::ChatPendingFor(g_peer, waiting);
    for (size_t i = 0; i < waiting.size(); i++)
        Say(When(waiting[i].sent) + "  you: " + waiting[i].text + "   [waiting -- they are not online]");
    std::vector<btfchat::SwapView> swaps;
    btfchat::ChatSwapList(swaps);
    for (size_t i = 0; i < swaps.size(); i++)
        if (swaps[i].peer == g_peer)
            Say("[swap " + swaps[i].id.substr(0, 8) + "] " + swaps[i].status);
}

void ShowRoom()
{
    std::vector<btfchat::LogEntry> log;
    btfchat::ChatCommunityLog(g_room, log);
    g_offerIds.clear();
    Say("--- #" + RoomName(g_room));
    size_t from = log.size() > 30 ? log.size() - 30 : 0;
    for (size_t i = from; i < log.size(); i++)
    {
        std::string s = PostLine(log[i]);
        if (log[i].kind == btfchat::MSG_SWAP_OFFER && !log[i].outgoing)
        {
            g_offerIds.push_back(log[i].id);
            s += strprintf("   -> take %u", (unsigned)g_offerIds.size());
        }
        Say(s);
    }
}

void ShowSwaps()
{
    std::vector<btfchat::SwapView> v;
    btfchat::ChatSwapList(v);
    g_swapIds.clear();
    if (v.empty())
        Say("no swaps");
    for (size_t i = 0; i < v.size(); i++)
    {
        const btfchat::SwapView& s = v[i];
        g_swapIds.push_back(s.id);
        Say(strprintf("%2u  [%s] with %s: you give %s %s, get %s %s -- %s", (unsigned)(i + 1), s.id.substr(0, 8).c_str(),
                      Short(s.peer).c_str(), btfchat::FormatSwapAmount(s.giveAmount).c_str(), s.give.c_str(),
                      btfchat::FormatSwapAmount(s.wantAmount).c_str(), s.want.c_str(), s.status.c_str()));
        if (s.stage == btfchat::SW_WAIT_PAYMENT && !s.paymentAddress.empty())
            Say("      pay exactly " + btfchat::FormatSwapAmount(s.giveAmount) + " BTC to " + s.paymentAddress);
        if ((s.give == "BTC" || s.want == "BTC") && s.btcDestination.empty() && s.myTxid.empty())
            Say(strprintf("      your Bitcoin address: swap btc %u ADDRESS", (unsigned)(i + 1)));
        if (s.fNeedsMe)
            Say(strprintf("      waiting for you: swap ok %u  (%s: lock %s %s)", (unsigned)(i + 1),
                          s.fMaker ? "accept" : "go on", btfchat::FormatSwapAmount(s.giveAmount).c_str(), s.give.c_str()));
        if (s.fCanCancel)
            Say(strprintf("      can still be called off: swap cancel %u", (unsigned)(i + 1)));
    }
}

bool Confirm(const std::string& question)
{
    {
        std::lock_guard<std::mutex> lock(g_out);
        printf("%s -- type yes to go on: ", question.c_str());
        fflush(stdout);
    }
    return ReadLine() == "yes";
}

// What arrives while nobody types: messages, invites, posts, swap moves.
void Watch()
{
    std::map<std::string, size_t> seenChat, seenRoom;
    std::set<std::string> seenInvites;
    std::map<std::string, std::string> seenSwap;
    bool fPrimed = false;
    while (!g_fQuit && !fShutdown)
    {
        Sleep(1000);
        if (btfchat::ChatCheckInactivity())
        {
            Say("\n(locked after 15 minutes without a command -- type 'unlock')");
            fPrimed = false;
            continue;
        }
        if (!btfchat::ChatUnlocked())
            continue;

        std::vector<std::string> contacts;
        btfchat::ChatContacts(contacts);
        for (size_t i = 0; i < contacts.size(); i++)
        {
            std::vector<btfchat::LogEntry> log;
            btfchat::ChatConversation(contacts[i], log);
            size_t& n = seenChat[contacts[i]];
            if (fPrimed)
                for (size_t k = n; k < log.size(); k++)
                    if (!log[k].outgoing)
                        Say("\n[" + Short(contacts[i]) + "] " + Line(log[k], false));
            n = log.size();
        }

        std::vector<btfchat::Invite> pend;
        btfchat::ChatPendingInvites(pend);
        for (size_t i = 0; i < pend.size(); i++)
            if (seenInvites.insert(pend[i].address).second && fPrimed)
                Say("\n[invite] from " + pend[i].address + (pend[i].note.empty() ? "" : "  \"" + pend[i].note + "\"") +
                    "\n         accept " + pend[i].address.substr(0, 10) + "   (or decline / block)");

        std::vector<std::pair<std::string, std::string> > rooms;
        btfchat::ChatCommunities(rooms);
        for (size_t i = 0; i < rooms.size(); i++)
        {
            std::vector<btfchat::LogEntry> log;
            btfchat::ChatCommunityLog(rooms[i].first, log);
            size_t& n = seenRoom[rooms[i].first];
            if (fPrimed)
                for (size_t k = n; k < log.size(); k++)
                    if (!log[k].outgoing)
                        Say("\n[#" + rooms[i].second + "] " + PostLine(log[k]));
            n = log.size();
        }

        std::vector<btfchat::SwapView> swaps;
        btfchat::ChatSwapList(swaps);
        for (size_t i = 0; i < swaps.size(); i++)
        {
            std::string& last = seenSwap[swaps[i].id];
            if (fPrimed && last != swaps[i].status)
                Say("\n[swap " + swaps[i].id.substr(0, 8) + "] " + swaps[i].status +
                    (swaps[i].fNeedsMe ? "   -- 'swaps' to see what it waits for" : ""));
            last = swaps[i].status;
        }
        fPrimed = true;
    }
}

void Command(const std::string& line)
{
    std::istringstream in(line);
    std::string cmd;
    in >> cmd;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    std::string rest;
    std::getline(in, rest);
    size_t b = rest.find_first_not_of(' ');
    rest = b == std::string::npos ? std::string() : rest.substr(b);
    std::string arg1, arg2;
    {
        std::istringstream a(rest);
        a >> arg1;
        std::getline(a, arg2);
        size_t c = arg2.find_first_not_of(' ');
        arg2 = c == std::string::npos ? std::string() : arg2.substr(c);
    }
    std::string err, addr;
    btfchat::ChatTouch();

    if (cmd == "help" || cmd == "?") { Help(); return; }
    if (cmd == "quit" || cmd == "exit") { g_fQuit = true; return; }
    if (cmd == "me") { ShowMe(); return; }
    if (cmd == "unlock") { if (!btfchat::ChatUnlocked()) Unlock(); else Say("already unlocked"); return; }
    if (cmd == "lock") { btfchat::ChatLock(); g_peer.clear(); g_room.clear(); Say("locked -- the keys are wiped from memory"); return; }
    if (!btfchat::ChatUnlocked()) { Say("locked -- type 'unlock'"); return; }

    if (cmd == "invite")
    {
        if (arg1.empty()) { Say("invite ADDRESS [note]"); return; }
        Say("sending the invite over Tor...");
        if (btfchat::ChatInvite(arg1, arg2, err))
            Say("invite sent. When they accept, 'chats' shows the conversation.");
        else
            Say("not delivered yet: " + err + "\n(it is kept -- 'invite' again in a minute or two; their onion may still be coming up)");
        return;
    }
    if (cmd == "invites") { ShowInvites(); return; }
    if (cmd == "accept" || cmd == "decline" || cmd == "block")
    {
        if (!ResolvePeer(arg1, addr)) { Say("which one? 'invites' lists them"); return; }
        bool fOk = cmd == "accept" ? btfchat::ChatAcceptInvite(addr, err)
                 : cmd == "decline" ? btfchat::ChatDeclineInvite(addr, err) : btfchat::ChatBlock(addr, err);
        std::string done = cmd == "accept" ? "accepted " : cmd == "decline" ? "declined " : "blocked ";
        Say(fOk ? done + addr + (err.empty() ? "" : " (" + err + ")") : "could not: " + err);
        if (fOk && cmd == "accept") { g_peer = addr; g_room.clear(); Say("conversation open -- type to send"); }
        if (fOk && cmd == "block" && g_peer == addr) g_peer.clear();
        return;
    }
    if (cmd == "chats") { ShowChats(); return; }
    if (cmd == "open")
    {
        if (g_contacts.empty()) btfchat::ChatContacts(g_contacts);
        if (!ResolvePeer(arg1, addr)) { Say("which one? 'chats' lists them"); return; }
        g_peer = addr;
        g_room.clear();
        ShowHistory(20);
        return;
    }
    if (cmd == "history") { ShowHistory(arg1.empty() ? 20 : (size_t)std::max(1, atoi(arg1.c_str()))); return; }
    if (cmd == "ask" || cmd == "pay")
    {
        if (g_peer.empty()) { Say("open a conversation first"); return; }
        int64 nAmount = 0;
        if (!ParseMoney(arg1.c_str(), nAmount) || nAmount <= 0) { Say(cmd + " AMOUNT [note]   (in BTF)"); return; }
        bool fMailbox = false;
        if (cmd == "ask")
        {
            if (btfchat::ChatShareAddress(g_peer, nAmount, arg2, fMailbox, err))
                Say(fMailbox ? "asked -- left in their mailbox" : "asked");
            else
                Say("could not: " + err);
            return;
        }
        std::string payTo;
        int64_t nRequested = 0;
        if (!btfchat::ChatPeerPayAddress(g_peer, payTo, nRequested))
        {
            Say("they have not asked to be paid -- a payment only goes to an address they signed");
            return;
        }
        if (!Confirm(strprintf("pay %s BTF to %s (%s)", FormatMoney(nAmount).c_str(), Short(g_peer).c_str(), payTo.c_str())))
        {
            Say("not paid");
            return;
        }
        std::string txid;
        if (btfchat::ChatPay(g_peer, nAmount, arg2, txid, fMailbox, err))
            Say(strprintf("paid %s BTF (txid %s)%s", FormatMoney(nAmount).c_str(), txid.c_str(),
                          fMailbox ? " -- they will see the note when they come online" : ""));
        else
            Say("not paid: " + err);
        return;
    }
    if (cmd == "directory")
    {
        Say("asking the nodes for the public directory...");
        if (!btfchat::ChatCommunityDirectory(g_directory, err)) { Say("could not: " + err); return; }
        for (size_t i = 0; i < g_directory.size(); i++)
            Say(strprintf("%2u  #%s  (block %d)", (unsigned)(i + 1), g_directory[i].name.c_str(), g_directory[i].nHeight));
        if (g_directory.empty()) Say("no public communities yet");
        return;
    }
    if (cmd == "join")
    {
        size_t n = (size_t)atoi(arg1.c_str());
        if (n < 1 || n > g_directory.size()) { Say("join N -- a number from 'directory'"); return; }
        std::string id;
        const CChatListing& l = g_directory[n - 1];
        if (!btfchat::ChatCommunityJoin(HexStr(l.key.begin(), l.key.end(), false), l.name, id, err)) { Say("could not: " + err); return; }
        g_room = id;
        g_peer.clear();
        btfchat::ChatCommunities(g_rooms);
        Say("joined #" + l.name + " -- posts arrive within a couple of minutes; type to post");
        return;
    }
    if (cmd == "rooms")
    {
        btfchat::ChatCommunities(g_rooms);
        if (g_rooms.empty()) Say("you are in no community -- 'directory', then 'join N'");
        for (size_t i = 0; i < g_rooms.size(); i++)
            Say(strprintf("%2u  #%s%s", (unsigned)(i + 1), g_rooms[i].second.c_str(), g_rooms[i].first == g_room ? "   (open)" : ""));
        return;
    }
    if (cmd == "room" || cmd == "leave")
    {
        if (g_rooms.empty()) btfchat::ChatCommunities(g_rooms);
        size_t n = (size_t)atoi(arg1.c_str());
        if (n < 1 || n > g_rooms.size()) { Say(cmd + " N -- a number from 'rooms'"); return; }
        std::string id = g_rooms[n - 1].first;
        if (cmd == "leave")
        {
            Say(btfchat::ChatCommunityLeave(id, err) ? "left #" + g_rooms[n - 1].second : "could not: " + err);
            if (g_room == id) g_room.clear();
            btfchat::ChatCommunities(g_rooms);
            return;
        }
        g_room = id;
        g_peer.clear();
        ShowRoom();
        return;
    }
    if (cmd == "create")
    {
        if (rest.empty()) { Say("create NAME"); return; }
        if (!Confirm("list #" + rest + " on the chain -- public and permanent, burns 0.01 BTF from your wallet")) { Say("not created"); return; }
        std::string txid, id;
        if (btfchat::ChatCommunityCreatePublic(rest, txid, id, err))
            Say("#" + rest + " listed (" + txid.substr(0, 12) + "...): public once it is in a block");
        else
            Say("could not: " + err);
        return;
    }
    if (cmd == "offer")
    {
        // offer AMOUNT BTF|BTC for AMOUNT
        std::istringstream a(rest);
        std::string sGive, coin, sFor, sWant;
        a >> sGive >> coin >> sFor >> sWant;
        std::transform(coin.begin(), coin.end(), coin.begin(), ::toupper);
        int64 nGive = 0, nWant = 0;
        if (g_room.empty() || (coin != "BTF" && coin != "BTC") || sFor != "for" ||
            !ParseMoney(sGive.c_str(), nGive) || nGive <= 0 || !ParseMoney(sWant.c_str(), nWant) || nWant <= 0)
        {
            Say("in an open room: offer AMOUNT BTF for AMOUNT   (or AMOUNT BTC for AMOUNT)");
            return;
        }
        btfchat::SwapOffer o;
        o.give = coin;
        o.want = coin == "BTF" ? "BTC" : "BTF";
        o.giveAmount = nGive;
        o.wantAmount = nWant;
        if (btfchat::ChatSwapPostOffer(g_room, o, err))
            Say("offer posted: " + btfchat::DescribeSwapOffer(o));
        else
            Say("could not: " + err);
        return;
    }
    if (cmd == "offers") { if (g_room.empty()) Say("open a room first ('rooms')"); else ShowRoom(); return; }
    if (cmd == "take")
    {
        size_t n = (size_t)atoi(arg1.c_str());
        if (g_room.empty() || n < 1 || n > g_offerIds.size()) { Say("take N -- a number from 'offers' in the open room"); return; }
        if (btfchat::ChatSwapTake(g_room, g_offerIds[n - 1], err))
            Say("swap started -- it goes on in your conversation with them; 'swaps' shows it");
        else
            Say("could not: " + err);
        return;
    }
    if (cmd == "swaps") { ShowSwaps(); return; }
    if (cmd == "swap")
    {
        std::istringstream a(rest);
        std::string what, which, extra;
        a >> what >> which >> extra;
        if (g_swapIds.empty()) { std::vector<btfchat::SwapView> v; btfchat::ChatSwapList(v); for (size_t i = 0; i < v.size(); i++) g_swapIds.push_back(v[i].id); }
        btfchat::SwapView s;
        if (!ResolveSwap(which, s)) { Say("swap ok|cancel|btc N -- a number from 'swaps'"); return; }
        if (what == "ok")
        {
            if (!s.fNeedsMe) { Say("that swap is not waiting for you"); return; }
            if (!Confirm(strprintf("%s: lock %s %s in the contract (it comes back by itself if the swap does not finish; keep the chat open)",
                                   s.fMaker ? "accept" : "go on", btfchat::FormatSwapAmount(s.giveAmount).c_str(), s.give.c_str())))
            { Say("nothing locked"); return; }
            Say(btfchat::ChatSwapApprove(s.id, err) ? "going on" : "could not: " + err);
            return;
        }
        if (what == "cancel") { Say(btfchat::ChatSwapCancel(s.id, err) ? "cancelled" : "could not: " + err); return; }
        if (what == "btc")
        {
            if (extra.empty()) { Say("swap btc N ADDRESS"); return; }
            Say(btfchat::ChatSwapBitcoinDestination(s.id, extra) ? "saved" : "not saved (already locked, or not a Bitcoin address)");
            return;
        }
        Say("swap ok|cancel|btc N");
        return;
    }

    // Anything else is a message to the open conversation, or a post in the open room.
    if (!g_peer.empty())
    {
        bool fMailbox = false;
        if (btfchat::ChatSendText(g_peer, line, fMailbox, err))
            Say(fMailbox ? "(they are not online -- left in their mailbox)" : (err.empty() ? "" : "(" + err + ")"));
        else
            Say("not sent: " + err);
        return;
    }
    if (!g_room.empty())
    {
        if (!btfchat::ChatCommunityPost(g_room, line, err))
            Say("not posted: " + err);
        return;
    }
    Say("unknown command -- 'help'. To talk, 'open' a conversation first.");
}
} // namespace

int RunChatTerminal(int argc, char* argv[])
{
    (void)argc; (void)argv;
    Say("btfchat (terminal) -- " + std::string(IsTestNet() ? "TESTNET" : "mainnet") + ". 'help' lists the commands.");
    std::string wallet;
    if (!btfchat::WalletLinked(wallet))
        Say("wallet: not linked (" + wallet + ")\n        start the node with -chatwallet for 'ask' and 'pay'");
    while (!btfchat::ChatUnlocked() && !fShutdown)
    {
        if (Unlock())
            break;
        bool fEof = false;
        if (!std::cin.good()) fEof = true;
        if (fEof) { fShutdown = true; return 1; }
    }

    std::thread watcher(Watch);
    while (!g_fQuit && !fShutdown)
    {
        {
            std::lock_guard<std::mutex> lock(g_out);
            std::string where = !g_peer.empty() ? Short(g_peer) : (!g_room.empty() ? "#" + RoomName(g_room) : std::string());
            printf("%s> ", where.c_str());
            fflush(stdout);
        }
        bool fEof = false;
        std::string line = ReadLine(&fEof);
        if (fEof)
            break;
        if (line.find_first_not_of(" \t") == std::string::npos)
            continue;
        try { Command(line); }
        catch (std::exception& e) { Say(std::string("error: ") + e.what()); }
    }
    g_fQuit = true;
    watcher.join();
    // Leaving locks the session and wipes the keys, as closing the window does.
    btfchat::ChatServiceStop();
    btfchat::ChatLock();
    fShutdown = true;
    return 0;
}
