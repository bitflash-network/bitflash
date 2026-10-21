// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See invoice.h.

#include "headers.h"
#include "invoice.h"
#include "bip21.h"
#include "qrcodegen.hpp"
#include "proxy.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <map>

using json = nlohmann::json;

namespace invoice
{

struct Invoice
{
    std::string id, address, scriptHex, description, orderId;
    int64_t amount = 0, created = 0, expires = 0;
    bool fCancelled = false;
    std::string lastStatus;          // what the shop was last told
    int lastConfirmations = -1;
};

struct Event
{
    std::string id;
    std::string body;                // the JSON posted
    int attempts = 0;
    int64_t nextTry = 0;
};

static CCriticalSection cs_invoices;
static std::map<std::string, Invoice> g_invoices;
static std::vector<Event> g_events;
static Config g_config;
static bool g_fLoaded = false;

static const size_t MAX_INVOICES = 100000;
static const int MAX_ATTEMPTS = 40;          // about a day of backing off

static std::string StorePath() { return GetAppDir() + "/invoices.json"; }

static int MinConf()
{
    int n = 0;
    CRITICAL_BLOCK(cs_invoices)
        n = g_config.nMinConf;
    return n > 0 ? n : (IsTestNet() ? 1 : 2);
}

// ---- pure ------------------------------------------------------------------

std::string StatusFor(int64_t nAmount, int64_t nReceived, int64_t nReceivedConfirmed,
                      bool fCancelled, int64_t nExpires, int64_t nNow)
{
    if (fCancelled)
        return "cancelled";
    if (nReceivedConfirmed >= nAmount)
        return "paid";
    if (nReceived >= nAmount)
        return "seen";
    if (nNow > nExpires)
        return "expired";
    if (nReceived > 0)
        return "partial";
    return "waiting";
}

std::string QrSvg(const std::string& text)
{
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    int n = qr.getSize();
    std::string path;
    for (int y = 0; y < n; y++)
        for (int x = 0; x < n; x++)
            if (qr.getModule(x, y))
                path += strprintf("M%d,%dh1v1h-1z", x + 4, y + 4);
    return strprintf("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\" shape-rendering=\"crispEdges\">"
                     "<rect width=\"100%%\" height=\"100%%\" fill=\"#ffffff\"/><path d=\"%s\" fill=\"#000000\"/></svg>",
                     n + 8, n + 8, path.c_str());
}

std::string SignBody(const std::string& secret, const std::string& body)
{
    unsigned char mac[32];
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), (int)secret.size(), (const unsigned char*)body.data(), body.size(), mac, &len);
    return HexStr(mac, mac + len, false);
}

bool ParseHttpUrl(const std::string& url, std::string& hostOut, unsigned short& portOut, std::string& pathOut)
{
    if (url.compare(0, 7, "http://") != 0)
        return false;
    std::string rest = url.substr(7);
    size_t slash = rest.find('/');
    std::string hostport = rest.substr(0, slash);
    pathOut = slash == std::string::npos ? "/" : rest.substr(slash);
    size_t colon = hostport.rfind(':');
    portOut = 80;
    if (colon != std::string::npos && hostport.find(']') == std::string::npos)
    {
        int p = atoi(hostport.substr(colon + 1).c_str());
        if (p <= 0 || p > 65535)
            return false;
        portOut = (unsigned short)p;
        hostport = hostport.substr(0, colon);
    }
    hostOut = hostport;
    return !hostOut.empty() && hostOut.find_first_of(" \r\n") == std::string::npos &&
           pathOut.find_first_of(" \r\n") == std::string::npos;
}

// ---- the store ---------------------------------------------------------------

static json ToJsonStore()
{
    json j;
    j["invoices"] = json::array();
    j["events"] = json::array();
    for (std::map<std::string, Invoice>::const_iterator it = g_invoices.begin(); it != g_invoices.end(); ++it)
    {
        const Invoice& v = it->second;
        j["invoices"].push_back(json{{"id", v.id}, {"address", v.address}, {"script", v.scriptHex},
                                     {"description", v.description}, {"orderId", v.orderId},
                                     {"amount", v.amount}, {"created", v.created}, {"expires", v.expires},
                                     {"cancelled", v.fCancelled}, {"lastStatus", v.lastStatus},
                                     {"lastConf", v.lastConfirmations}});
    }
    for (size_t i = 0; i < g_events.size(); i++)
        j["events"].push_back(json{{"id", g_events[i].id}, {"body", g_events[i].body},
                                   {"attempts", g_events[i].attempts}, {"next", g_events[i].nextTry}});
    return j;
}

// Under cs_invoices.
static void SaveLocked()
{
    std::string path = StorePath(), tmp = path + ".new";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f)
        return;
    std::string s = ToJsonStore().dump();
    bool fOk = fwrite(s.data(), 1, s.size(), f) == s.size();
    fflush(f);
    fclose(f);
    if (!fOk)
    {
        unlink(tmp.c_str());
        return;
    }
    unlink(path.c_str());
    rename(tmp.c_str(), path.c_str());
}

// Under cs_invoices.
static void LoadLocked()
{
    if (g_fLoaded)
        return;
    g_fLoaded = true;
    FILE* f = fopen(StorePath().c_str(), "rb");
    if (!f)
        return;
    std::string s;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        s.append(buf, n);
    fclose(f);
    try
    {
        json j = json::parse(s);
        for (size_t i = 0; j.contains("invoices") && i < j["invoices"].size(); i++)
        {
            const json& e = j["invoices"][i];
            Invoice v;
            v.id = e.value("id", std::string());
            v.address = e.value("address", std::string());
            v.scriptHex = e.value("script", std::string());
            v.description = e.value("description", std::string());
            v.orderId = e.value("orderId", std::string());
            v.amount = e.value("amount", (int64_t)0);
            v.created = e.value("created", (int64_t)0);
            v.expires = e.value("expires", (int64_t)0);
            v.fCancelled = e.value("cancelled", false);
            v.lastStatus = e.value("lastStatus", std::string());
            v.lastConfirmations = e.value("lastConf", -1);
            if (v.id.size() == 32 && !v.scriptHex.empty())
                g_invoices[v.id] = v;
        }
        for (size_t i = 0; j.contains("events") && i < j["events"].size(); i++)
        {
            const json& e = j["events"][i];
            Event ev;
            ev.id = e.value("id", std::string());
            ev.body = e.value("body", std::string());
            ev.attempts = e.value("attempts", 0);
            ev.nextTry = e.value("next", (int64_t)0);
            g_events.push_back(ev);
        }
    }
    catch (...)
    {
        printf("invoices: %s does not parse; starting empty (the file is left as it is)\n", StorePath().c_str());
        rename(StorePath().c_str(), (StorePath() + ".unreadable").c_str());
    }
}

bool Configure(const Config& cfg, std::string& errOut)
{
    if (!cfg.strWebhookUrl.empty())
    {
        std::string host, path;
        unsigned short port = 0;
        if (!ParseHttpUrl(cfg.strWebhookUrl, host, port, path))
        {
            errOut = "-invoicewebhook takes http://host[:port]/path (https is not spoken; point it at the shop's "
                     "own machine, or use -invoicenotify)";
            return false;
        }
    }
    CRITICAL_BLOCK(cs_invoices)
        g_config = cfg;
    return true;
}

// ---- what the wallet has received ---------------------------------------------

struct Seen
{
    int64_t nAll = 0;          // in blocks or still in the memory pool
    int64_t nConfirmed = 0;    // with at least MinConf() confirmations
    int nMinDepth = -1;        // confirmations of the least-confirmed payment
    json txs = json::array();
};

static Seen Received(const std::string& scriptHex)
{
    Seen s;
    std::vector<unsigned char> v = ParseHex(scriptHex);
    CScript script(v.begin(), v.end());
    int nMinConf = MinConf();
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            int64_t nHere = 0;
            for (unsigned int i = 0; i < wtx.vout.size(); i++)
                if (wtx.vout[i].scriptPubKey == script)
                    nHere += wtx.vout[i].nValue;
            if (nHere == 0)
                continue;
            int nDepth = wtx.GetDepthInMainChain();
            if (nDepth <= 0)
            {
                // Unconfirmed counts only while it is actually waiting: one
                // that was replaced or dropped is not a payment.
                bool fWaiting = false;
                CRITICAL_BLOCK(cs_mapTransactions)
                    fWaiting = mapTransactions.count(wtx.GetHash()) > 0;
                if (!fWaiting)
                    continue;
                nDepth = 0;
            }
            s.nAll += nHere;
            if (nDepth >= nMinConf)
                s.nConfirmed += nHere;
            if (s.nMinDepth < 0 || nDepth < s.nMinDepth)
                s.nMinDepth = nDepth;
            s.txs.push_back(json{{"txid", wtx.GetHash().GetHex()}, {"amount", (double)nHere / COIN},
                                 {"confirmations", nDepth}});
        }
    }
    return s;
}

static json View(const Invoice& v, const Seen& s, int64_t nNow)
{
    json j;
    j["id"] = v.id;
    j["status"] = StatusFor(v.amount, s.nAll, s.nConfirmed, v.fCancelled, v.expires, nNow);
    j["amount"] = (double)v.amount / COIN;
    j["received"] = (double)s.nAll / COIN;
    j["receivedConfirmed"] = (double)s.nConfirmed / COIN;
    j["overpaid"] = s.nAll > v.amount ? (double)(s.nAll - v.amount) / COIN : 0.0;
    j["confirmations"] = s.nMinDepth < 0 ? 0 : s.nMinDepth;
    j["minConfirmations"] = MinConf();
    j["address"] = v.address;
    j["description"] = v.description;
    j["orderId"] = v.orderId;
    j["created"] = v.created;
    j["expires"] = v.expires;
    j["payments"] = s.txs;
    PaymentLink link;
    link.address = v.address;
    link.amount = v.amount;
    link.message = v.description;
    j["link"] = MakePaymentLink(link);
    return j;
}

// ---- the RPCs -----------------------------------------------------------------

json Create(int64_t nAmount, const std::string& strDescription, int64_t nExpirySecs, const std::string& strOrderId)
{
    if (nAmount <= 0 || nAmount > MAX_MONEY)
        throw std::runtime_error("the amount is above 0 and at most 21 million");
    if (strDescription.size() > 200 || strOrderId.size() > 100)
        throw std::runtime_error("description up to 200 characters, order id up to 100");
    if (nExpirySecs < 60 || nExpirySecs > 30 * 86400)
        throw std::runtime_error("an invoice stays open from 60 seconds to 30 days");
    std::vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
        throw std::runtime_error("could not draw a key from the wallet (is it locked?)");
    Invoice v;
    unsigned char rnd[16];
    RAND_bytes(rnd, sizeof(rnd));
    v.id = HexStr(rnd, rnd + sizeof(rnd), false);
    v.address = PubKeyToAddress(vchPubKey);
    CScript script;
    script << OP_DUP << OP_HASH160 << Hash160(vchPubKey) << OP_EQUALVERIFY << OP_CHECKSIG;
    v.scriptHex = HexStr(script.begin(), script.end(), false);
    v.description = strDescription;
    v.orderId = strOrderId;
    v.amount = nAmount;
    v.created = GetTime();
    v.expires = v.created + nExpirySecs;
    v.lastStatus = "waiting";
    SetAddressBookName(v.address, "Invoice " + v.id.substr(0, 8) + (strOrderId.empty() ? "" : " " + strOrderId));
    CRITICAL_BLOCK(cs_invoices)
    {
        LoadLocked();
        if (g_invoices.size() >= MAX_INVOICES)
            throw std::runtime_error("this node holds the maximum number of invoices");
        g_invoices[v.id] = v;
        SaveLocked();
    }
    json j = View(v, Seen(), v.created);
    j["copyPaste"] = j["link"];
    j["qrSvg"] = QrSvg(j["link"].get<std::string>());
    return j;
}

static Invoice Find(const std::string& id)
{
    CRITICAL_BLOCK(cs_invoices)
    {
        LoadLocked();
        std::map<std::string, Invoice>::iterator it = g_invoices.find(id);
        if (it != g_invoices.end())
            return it->second;
    }
    throw std::runtime_error("no invoice with that id");
}

json Get(const std::string& id)
{
    Invoice v = Find(id);
    json j = View(v, Received(v.scriptHex), GetTime());
    j["copyPaste"] = j["link"];
    j["qrSvg"] = QrSvg(j["link"].get<std::string>());
    return j;
}

json List(const std::string& strStatusFilter)
{
    std::vector<Invoice> v;
    CRITICAL_BLOCK(cs_invoices)
    {
        LoadLocked();
        for (std::map<std::string, Invoice>::iterator it = g_invoices.begin(); it != g_invoices.end(); ++it)
            v.push_back(it->second);
    }
    json a = json::array();
    int64_t nNow = GetTime();
    for (size_t i = 0; i < v.size(); i++)
    {
        json j = View(v[i], Received(v[i].scriptHex), nNow);
        if (strStatusFilter.empty() || j["status"] == strStatusFilter)
            a.push_back(j);
    }
    return a;
}

json Cancel(const std::string& id)
{
    CRITICAL_BLOCK(cs_invoices)
    {
        LoadLocked();
        std::map<std::string, Invoice>::iterator it = g_invoices.find(id);
        if (it == g_invoices.end())
            throw std::runtime_error("no invoice with that id");
        it->second.fCancelled = true;
        SaveLocked();
    }
    return Get(id);
}

// ---- telling the shop ---------------------------------------------------------

// One POST. True on any 2xx answer.
static bool PostWebhook(const Config& cfg, const std::string& body, std::string& errOut)
{
    std::string host, path;
    unsigned short port = 0;
    if (!ParseHttpUrl(cfg.strWebhookUrl, host, port, path))
    {
        errOut = "bad webhook URL";
        return false;
    }
    SOCKET s = INVALID_SOCKET;
    bool fLocal = host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
    if (fLocal)
    {
        // The shop's own machine: straight there, never through Tor.
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET)
        {
            struct sockaddr_in a;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = htons(port);
            if (connect(s, (struct sockaddr*)&a, sizeof(a)) != 0)
            {
                closesocket(s);
                s = INVALID_SOCKET;
            }
        }
    }
    else
        // Elsewhere: the way this node reaches anything, through Tor when it runs with it.
        s = BtfConnectSocket(host, port, SOCK_ONION_PEER, 30);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not connect to " + host;
        return false;
    }
#ifdef _WIN32
    DWORD tv = 30000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\n"
                      "User-Agent: bitflash-invoices\r\nContent-Length: " + strprintf("%u", (unsigned)body.size()) + "\r\n";
    if (!cfg.strWebhookSecret.empty())
        req += "X-Bitflash-Signature: sha256=" + SignBody(cfg.strWebhookSecret, body) + "\r\n";
    req += "Connection: close\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < req.size())
    {
        int n = send(s, req.data() + sent, (int)(req.size() - sent), 0);
        if (n <= 0)
            break;
        sent += n;
    }
    char buf[256];
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    closesocket(s);
    if (n <= 0)
    {
        errOut = "no answer";
        return false;
    }
    buf[n] = 0;
    // "HTTP/1.x 2xx"
    if (n >= 12 && strncmp(buf, "HTTP/1.", 7) == 0 && buf[9] == '2')
        return true;
    errOut = std::string("answered ") + std::string(buf, std::min(n, 12));
    return false;
}

static void RunCommand(const std::string& cmd, const std::string& id)
{
    std::string c = cmd;
    size_t p;
    // The id is 32 hex characters: nothing in it a shell would read as more.
    while ((p = c.find("%s")) != std::string::npos)
        c.replace(p, 2, id);
    int rc = system(c.c_str());
    if (rc != 0)
        printf("invoices: -invoicenotify for %s exited with %d\n", id.c_str(), rc);
}

static void ThreadRunCommand(void* parg)
{
    std::pair<std::string, std::string>* p = (std::pair<std::string, std::string>*)parg;
    RunCommand(p->first, p->second);
    delete p;
}

void ThreadInvoices(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadInvoices(parg));
    while (!fShutdown)
    {
        try
        {
            Config cfg;
            std::vector<Invoice> v;
            CRITICAL_BLOCK(cs_invoices)
            {
                LoadLocked();
                cfg = g_config;
                for (std::map<std::string, Invoice>::iterator it = g_invoices.begin(); it != g_invoices.end(); ++it)
                    v.push_back(it->second);
            }
            int64_t nNow = GetTime();
            bool fNotify = !cfg.strWebhookUrl.empty() || !cfg.strNotifyCommand.empty();
            // Look at every invoice still in play, and at a finished one only
            // until its confirmations stop moving (a reorg can still change a
            // "paid", and the shop should hear about it).
            for (size_t i = 0; i < v.size(); i++)
            {
                if ((v[i].lastStatus == "cancelled" || v[i].lastStatus == "expired") && nNow - v[i].expires > 86400)
                    continue;
                if (v[i].lastStatus == "paid" && v[i].lastConfirmations >= 6)
                    continue;
                Seen s = Received(v[i].scriptHex);
                json j = View(v[i], s, nNow);
                std::string st = j["status"].get<std::string>();
                int nConf = j["confirmations"].get<int>();
                bool fChanged = st != v[i].lastStatus ||
                                (st == "paid" && nConf != v[i].lastConfirmations && nConf <= 6);
                if (!fChanged)
                    continue;
                // (No continue inside CRITICAL_BLOCK: it is a loop, and would
                // only leave the block.)
                bool fStill = false;
                CRITICAL_BLOCK(cs_invoices)
                {
                    std::map<std::string, Invoice>::iterator it = g_invoices.find(v[i].id);
                    if (it != g_invoices.end())
                    {
                        fStill = true;
                        it->second.lastStatus = st;
                        it->second.lastConfirmations = nConf;
                        if (fNotify)
                        {
                            Event ev;
                            ev.id = v[i].id;
                            ev.body = json{{"event", "invoice"}, {"invoice", j}}.dump();
                            ev.nextTry = nNow;
                            g_events.push_back(ev);
                        }
                        SaveLocked();
                    }
                }
                if (fStill && !cfg.strNotifyCommand.empty())
                    _beginthread(ThreadRunCommand, 0, new std::pair<std::string, std::string>(cfg.strNotifyCommand, v[i].id));
            }

            // Deliver what is due, oldest first; back off on failure.
            if (!cfg.strWebhookUrl.empty())
            {
                std::vector<Event> due;
                CRITICAL_BLOCK(cs_invoices)
                    for (size_t k = 0; k < g_events.size(); k++)
                        if (g_events[k].nextTry <= nNow)
                            due.push_back(g_events[k]);
                for (size_t k = 0; k < due.size() && !fShutdown; k++)
                {
                    std::string err;
                    bool fOk = PostWebhook(cfg, due[k].body, err);
                    CRITICAL_BLOCK(cs_invoices)
                    {
                        for (size_t m = 0; m < g_events.size(); m++)
                            if (g_events[m].id == due[k].id && g_events[m].body == due[k].body)
                            {
                                if (fOk || g_events[m].attempts + 1 >= MAX_ATTEMPTS)
                                {
                                    if (!fOk)
                                        printf("invoices: gave up telling the shop about %s: %s\n", due[k].id.c_str(), err.c_str());
                                    g_events.erase(g_events.begin() + m);
                                }
                                else
                                {
                                    g_events[m].attempts++;
                                    g_events[m].nextTry = nNow + std::min<int64_t>(3600, 10LL << std::min(g_events[m].attempts, 9));
                                }
                                break;
                            }
                        SaveLocked();
                    }
                }
            }
            else
                CRITICAL_BLOCK(cs_invoices)
                    if (!g_events.empty())
                    {
                        g_events.clear();
                        SaveLocked();
                    }
        }
        catch (std::exception& e)
        {
            printf("invoices: %s\n", e.what());
        }
        for (int i = 0; i < 5 && !fShutdown; i++)
            Sleep(1000);
    }
}

} // namespace invoice
