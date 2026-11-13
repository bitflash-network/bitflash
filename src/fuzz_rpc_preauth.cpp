// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for exactly what an unauthenticated caller reaches on the
// JSON-RPC port: the bytes of one connection, read by JsonRpcRecvRequest()
// (request line, headers, Content-Length, body) over a socketpair, then
// JsonRpcHandleRequest(), whose first step is the credential check. The
// server runs in cookie mode (-chatwallet): a fresh random password, written
// to the private data directory's .cookie and never read here, so no input
// can carry valid credentials. Only the 250 ms pause after a refusal and the
// socket write are left out, as HandleConnection() does them around these two.
//
// Checks, beyond the sanitizers:
//   - every complete request is refused with 401: anything else would be the
//     check letting a caller through without the password
//   - JsonRpcRecvRequest takes a request exactly when JsonRpcRequestLength
//     says the bytes hold a whole one (differential: the socket loop against
//     the pure length rule), and the length it reports fits in what arrived
//
// The constant-time comparison is not something a fuzzer can measure; it is
// ConstantTimeEqual in jsonrpc.cpp, unchanged.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "btfsock.h"
#include "jsonrpc.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static void FuzzPreauthInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzPreauthInit
#include "fuzz_datadir.h"
#include "fuzz_socket.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

// jsonrpc.cpp; not in jsonrpc.h, which does not know sockets.
bool JsonRpcRecvRequest(btf_socket_t s, std::string& out, int nTimeoutSecs);

static void Check(bool f, const char* pszWhat)
{
    if (!f)
    {
        fprintf(stderr, "fuzz-rpc-preauth: %s\n", pszWhat);
        abort();
    }
}

static void WriteSeed(const std::string& strDir, const char* pszName, const std::string& body)
{
    std::string strPath = strDir + "/" + pszName;
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    fwrite(body.data(), 1, body.size(), f);
    fclose(f);
}

static void WriteSeeds(const std::string& d)
{
    const std::string body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getinfo\",\"params\":[]}";
    const std::string len = strprintf("%u", (unsigned)body.size());
    WriteSeed(d, "no-auth", "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: " + len + "\r\n\r\n" + body);
    // "__cookie__:wrong" and "user:password", in Base64
    WriteSeed(d, "wrong-cookie", "POST / HTTP/1.1\r\nAuthorization: Basic X19jb29raWVfXzp3cm9uZw==\r\nContent-Length: " + len + "\r\n\r\n" + body);
    WriteSeed(d, "wrong-user", "POST / HTTP/1.1\r\nauthorization:basic dXNlcjpwYXNzd29yZA==\r\ncontent-length:" + len + "\r\n\r\n" + body);
    WriteSeed(d, "get", "GET / HTTP/1.0\r\n\r\n");
    WriteSeed(d, "auth-in-request-line", "POST /Authorization:%20Basic%20x HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    WriteSeed(d, "negative-length", "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n{}");
    WriteSeed(d, "two-lengths", "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}x");
    WriteSeed(d, "short-body", "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n{}");
    WriteSeed(d, "no-header-end", "POST / HTTP/1.1\r\nAuthorization: Basic ");
    WriteSeed(d, "scheme-bearer", "POST / HTTP/1.1\r\nAuthorization: Bearer X19jb29raWVfXzp4\r\n\r\n");
}

static void FuzzPreauthInit()
{
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
    // -chatwallet's configuration: user __cookie__, 64 random hex characters.
    if (!JsonRpcConfigureCookie(""))
    {
        fprintf(stderr, "fuzz-rpc-preauth: JsonRpcConfigureCookie failed\n");
        abort();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > FUZZ_SOCKET_MAX_INPUT)
        return 0;
    std::string input((const char*)data, size);

    std::string req;
    bool fGot;
    {
        CFuzzSocketPair sp(data, size);
        fGot = JsonRpcRecvRequest(sp.fdNode, req, 30);
    }

    size_t nTotal = 0;
    int nLen = JsonRpcRequestLength(input, nTotal);
    Check(fGot == (nLen == 1), "the socket reader and the length rule disagree");
    Check(nLen != 1 || nTotal <= size, "a complete request longer than what arrived");
    if (!fGot)
        return 0;
    Check(req.size() <= size && input.compare(0, req.size(), req) == 0, "the request read is not what was sent");
    size_t nTotalReq = 0;
    Check(JsonRpcRequestLength(req, nTotalReq) == 1 && nTotalReq == nTotal, "the request read is not complete");

    std::string reply;
    int nCode = JsonRpcHandleRequest(req, reply);
    Check(nCode == 401, "a request without the password was not refused");
    Check(reply.empty(), "a refused request got a body");
    return 0;
}
