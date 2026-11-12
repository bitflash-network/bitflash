// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the answers the node reads when it is the client: every
// outgoing HTTP-shaped request it makes, with the server played by the input.
//
//   0  JSON-RPC over HTTP to a program on this machine (LoopbackRpcCall): the
//      chat asking the wallet, the wallet asking Bitcoin Core / litecoind /
//      dogecoind ... for the other half of a swap. The response goes through
//      ParseLoopbackRpcResponse, everything LoopbackRpcCall does after recv.
//   1  an invoice webhook's answer (invoice::WebhookAnswerOk): the first
//      bytes the shop's server sends back
//   2  an IP echo service's answer to GetMyExternalIP (plain HTTP, port 80:
//      anything on the path can answer), ParseExternalIPResponse
//   3  a Nostr relay: the answer to the WebSocket upgrade, then frames, read
//      over a socketpair by the node's own CWebSocket (BtfNostrReadRelayStream)
//   4  the webhook URL the operator configures (invoice::ParseHttpUrl)
//
// The relays' messages themselves (the Nostr events in the frames) are JSON
// handled inside the discovery loops of nostr.cpp and are not reached here.
//
// Input layout: byte 0 selects the mode above, the rest is the answer.
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "rpcclient.h"
#include "invoice.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static void FuzzHttpInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzHttpInit
#include "fuzz_datadir.h"
#include "fuzz_socket.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

// nostr.cpp; not in nostr.h, which does not know SOCKET.
bool BtfNostrReadRelayStream(SOCKET s, size_t nMax, vector<string>& vMsgOut);

using json = nlohmann::json;

static void Check(bool f, const char* pszWhat)
{
    if (!f)
    {
        fprintf(stderr, "fuzz-http-client: %s\n", pszWhat);
        abort();
    }
}

static bool Printable(const std::string& s)
{
    for (size_t i = 0; i < s.size(); i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] >= 0x7f)
            return false;
    return true;
}

static void FuzzLoopbackRpc(const std::string& resp)
{
    LoopbackRpc to;
    to.nPort = 8332;
    to.strWho = "Bitcoin Core";
    json result;
    std::string err;
    int nCode = 12345;
    bool fOk = ParseLoopbackRpcResponse(to, resp, result, err, &nCode);
    if (fOk)
        Check(nCode == 0, "a success came with an error code");
    else
        Check(!err.empty(), "a failure came without a reason");
    // What a caller does next with the result: walk it, print it.
    if (fOk)
        (void)result.dump(-1, ' ', false, json::error_handler_t::replace);
}

static void FuzzWebhook(const std::string& answer)
{
    // The node reads one recv of at most 255 bytes.
    std::string a = answer.substr(0, 255);
    std::string err;
    if (invoice::WebhookAnswerOk(a, err))
        Check(a.compare(0, 7, "HTTP/1.") == 0 && a.size() >= 12 && a[9] == '2', "a non-2xx answer taken as delivered");
    else
        Check(Printable(err) && err.size() <= 9 + 12, "the refusal quotes unprintable or too much text");
}

static void FuzzExternalIP(const std::string& response)
{
    unsigned int ip = 0;
    if (!ParseExternalIPResponse(response, ip))
        return;
    unsigned char b[4];
    memcpy(b, &ip, 4);
    std::string s = strprintf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    Check(b[0] != 0 && b[0] != 127 && b[0] < 224, "a non-public address taken as ours");
    // The body is that address and nothing else (bar trailing blanks); since
    // leading zeros are allowed in the answer, compare numerically.
    size_t p = response.find("\r\n\r\n");
    size_t skip = 4;
    if (p == std::string::npos) { p = response.find("\n\n"); skip = 2; }
    Check(p != std::string::npos, "an address without a header block");
    unsigned int a[4];
    char tail = 0;
    std::string body = response.substr(p + skip);
    Check(sscanf(body.c_str(), "%u.%u.%u.%u%c", &a[0], &a[1], &a[2], &a[3], &tail) >= 4 &&
          a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3], "the address is not the body's");
}

static void FuzzRelay(const uint8_t* data, size_t size)
{
    CFuzzSocketPair sp(data, size);
    sp.NodeWritesFailWhenFull();   // the pongs are never read (fuzz_socket.h)
    std::vector<std::string> msgs;
    bool fUp = BtfNostrReadRelayStream(sp.fdNode, 16, msgs);
    std::string in((const char*)data, size);
    if (fUp)
        Check(in.compare(0, 12, "HTTP/1.1 101") == 0, "an upgrade accepted without a 101 status line");
    else
        Check(msgs.empty(), "messages read from a refused upgrade");
    size_t nTotal = 0;
    for (size_t i = 0; i < msgs.size(); i++)
        nTotal += msgs[i].size();
    Check(nTotal <= size, "more message bytes than the relay sent");
}

static void FuzzUrl(const std::string& url)
{
    std::string host, path;
    unsigned short port = 0;
    if (!invoice::ParseHttpUrl(url, host, port, path))
        return;
    Check(!host.empty() && port != 0 && !path.empty() && path[0] == '/', "a URL accepted without host, port or path");
    Check(host.find_first_of(" \r\n") == std::string::npos && path.find_first_of(" \r\n") == std::string::npos,
          "a URL that would split the request line");
}

static void WriteSeed(const std::string& strDir, const char* pszName, unsigned char nMode, const std::string& body)
{
    std::string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    fputc(nMode, f);
    fwrite(body.data(), 1, body.size(), f);
    fclose(f);
}

static std::string Frame(unsigned char b0, const std::string& payload)
{
    std::string f;
    f += (char)b0;
    if (payload.size() < 126)
        f += (char)payload.size();
    else
    {
        f += (char)126;
        f += (char)(payload.size() >> 8);
        f += (char)(payload.size() & 0xff);
    }
    return f + payload;
}

static void WriteSeeds(const std::string& d)
{
    WriteSeed(d, "rpc-result", 0, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n"
                                  "{\"result\":{\"chain\":\"main\"},\"error\":null,\"id\":1}");
    WriteSeed(d, "rpc-error", 0, "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                                 "{\"result\":null,\"error\":{\"code\":-8,\"message\":\"Block height out of range\"},\"id\":1}");
    WriteSeed(d, "rpc-error-object", 0, "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"result\":null,\"error\":[1,{\"x\":2}],\"id\":1}");
    WriteSeed(d, "rpc-401", 0, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\r\n");
    WriteSeed(d, "rpc-404", 0, "HTTP/1.1 404 Not Found\r\n\r\n<html>no wallet</html>");
    WriteSeed(d, "rpc-big-code", 0, "HTTP/1.1 500 x\r\n\r\n{\"error\":{\"code\":4294967271,\"message\":\"m\"}}");
    WriteSeed(d, "webhook-ok", 1, "HTTP/1.1 204 No Content\r\n\r\n");
    WriteSeed(d, "webhook-bad", 1, "HTTP/1.0 500 Oops\r\n\r\n");
    WriteSeed(d, "ip", 2, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.7\n");
    WriteSeed(d, "ip-bare-lf", 2, "HTTP/1.0 200 OK\n\n198.51.100.1\r\n");
    WriteSeed(d, "ip-lf-cr", 2, "\n\n\r");
    WriteSeed(d, "ip-bad", 2, "HTTP/1.1 200 OK\r\n\r\n999.1.1.1");
    std::string up = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    WriteSeed(d, "relay", 3, up + Frame(0x81, "[\"EOSE\",\"bf-sub\"]") + Frame(0x89, "ping") +
                             Frame(0x01, "[\"NOTICE\",") + Frame(0x80, "\"hi\"]") + Frame(0x88, ""));
    WriteSeed(d, "relay-long", 3, up + Frame(0x81, std::string(300, 'x')));
    WriteSeed(d, "relay-refused", 3, "HTTP/1.1 403 Forbidden\r\nX-Note: 101 \r\n\r\n");
    WriteSeed(d, "url", 4, "http://127.0.0.1:8080/hook");
    WriteSeed(d, "url-v6", 4, "http://[::1]/x");
}

static void FuzzHttpInit()
{
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > FUZZ_SOCKET_MAX_INPUT)
        return 0;
    std::string rest((const char*)data + 1, size - 1);
    switch (data[0] % 5)
    {
    case 0: FuzzLoopbackRpc(rest); break;
    case 1: FuzzWebhook(rest); break;
    case 2: FuzzExternalIP(rest); break;
    case 3: FuzzRelay(data + 1, size - 1); break;
    case 4: FuzzUrl(rest); break;
    }
    return 0;
}
