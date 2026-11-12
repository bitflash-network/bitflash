// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the SOCKS5 proxy's side of a connection: Tor's SOCKS port,
// or any proxy given with -socks. Everything the node dials (peers, onion
// services, relays, webhooks) goes through BtfConnectSocket and, with a proxy
// configured, through BtfSocks5Handshake on the connected socket. The harness
// plays the proxy over a socketpair and drives that function as the node
// does.
//
// Input layout:
//   byte 0   which destination the node asks for (see kHosts) and, in bit 7,
//            whether the port is 8433 or 443
//   rest     everything the proxy sends: method selection, CONNECT reply with
//            any address type, then what the destination would send
//
// Checks, beyond the sanitizers:
//   - what the node sent is exactly the no-auth greeting and a CONNECT by
//     domain name (the proxy resolves: nothing may go to local DNS)
//   - the handshake succeeds only on a reply that says success, read in full
//   - it reads not one byte past that reply: what follows on the socket is
//     the destination's, and it must reach the caller untouched
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "proxy.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static void FuzzSocksInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzSocksInit
#include "fuzz_datadir.h"
#include "fuzz_socket.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

static const char* const kHosts[] = {
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion",
    "relay.example.org",
    "a",
    NULL,     // 255 characters, the most a domain name in SOCKS5 can hold
    NULL,     // 256 characters, one too many: refused before anything is sent
};
static const size_t kNumHosts = sizeof(kHosts) / sizeof(kHosts[0]);

static std::string HostFor(size_t i)
{
    if (kHosts[i])
        return kHosts[i];
    return std::string(i == 3 ? 255 : 256, 'h');
}

static void Check(bool f, const char* pszWhat)
{
    if (!f)
    {
        fprintf(stderr, "fuzz-socks5: %s\n", pszWhat);
        abort();
    }
}

// Everything queued on fd, without waiting (the writer is done).
static std::string Drain(int fd)
{
    std::string s;
    char buf[4096];
    for (;;)
    {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0)
            break;
        s.append(buf, n);
    }
    return s;
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
    const std::string ok("\x05\x00", 2);
    WriteSeed(d, "ipv4", std::string("\x00", 1) + ok + std::string("\x05\x00\x00\x01\x7f\x00\x00\x01\x20\xf1", 10) + "payload");
    WriteSeed(d, "ipv6", std::string("\x81", 1) + ok + std::string("\x05\x00\x00\x04", 4) + std::string(16, '\x01') + std::string("\x01\xbb", 2));
    WriteSeed(d, "domain", std::string("\x01", 1) + ok + std::string("\x05\x00\x00\x03\x0b" "example.org" "\x00\x50", 18) + "x");
    WriteSeed(d, "domain-empty", std::string("\x02", 1) + ok + std::string("\x05\x00\x00\x03\x00\x00\x50", 7));
    WriteSeed(d, "refused", std::string("\x00", 1) + ok + std::string("\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10));
    WriteSeed(d, "wants-auth", std::string("\x00", 1) + std::string("\x05\x02", 2));
    WriteSeed(d, "bad-atyp", std::string("\x00", 1) + ok + std::string("\x05\x00\x00\x07", 4));
    WriteSeed(d, "truncated", std::string("\x03", 1) + ok + std::string("\x05\x00\x00\x01\x7f", 5));
    WriteSeed(d, "long-host", std::string("\x04", 1) + ok + std::string("\x05\x00\x00\x01\x7f\x00\x00\x01\x20\xf1", 10));
}

static void FuzzSocksInit()
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
    std::string host = HostFor((data[0] & 0x7f) % kNumHosts);
    unsigned short port = (data[0] & 0x80) ? 443 : 8433;
    const uint8_t* reply = data + 1;
    size_t nReply = size - 1;

    CFuzzSocketPair sp(reply, nReply);
    bool fOk = BtfSocks5Handshake(sp.fdNode, host, port);
    std::string sent = Drain(sp.fdPeer);
    std::string rest = Drain(sp.fdNode);

    if (host.size() > 255)
    {
        Check(!fOk && sent.empty(), "a host too long for SOCKS5 was sent anyway");
        return 0;
    }

    // What the node sent: the greeting, and after a no-auth answer, CONNECT
    // by name.
    std::string hello("\x05\x01\x00", 3);
    Check(sent.compare(0, 3, hello) == 0, "the greeting is not SOCKS5 no-auth");
    std::string req("\x05\x01\x00\x03", 4);
    req += (char)host.size();
    req += host;
    req += (char)(port >> 8);
    req += (char)(port & 0xff);
    bool fNoAuth = nReply >= 2 && reply[0] == 0x05 && reply[1] == 0x00;
    if (fNoAuth)
        Check(sent == hello + req, "the CONNECT request is not by domain name, or not what was asked");
    else
        Check(sent == hello, "the node went on past a proxy that refused no-auth");

    if (!fOk)
        return 0;

    // Success only on a complete success reply, and nothing read past it.
    Check(fNoAuth, "success without a no-auth answer");
    Check(nReply >= 6 && reply[2] == 0x05 && reply[3] == 0x00, "success on a reply that is not success");
    size_t nAddr = 0;
    switch (reply[5])
    {
    case 0x01: nAddr = 4; break;
    case 0x04: nAddr = 16; break;
    case 0x03: Check(nReply >= 7, "domain reply without its length"); nAddr = 1 + reply[6]; break;
    default: Check(false, "success on an unknown address type");
    }
    size_t nUsed = 2 + 4 + nAddr + 2;
    Check(nReply >= nUsed, "success on a truncated reply");
    Check(rest == std::string((const char*)reply + nUsed, nReply - nUsed),
          "the bytes after the reply did not reach the caller untouched");
    return 0;
}
