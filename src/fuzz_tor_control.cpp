// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for what the node reads from its own Tor: the replies on the
// control port and the hostname file of an onion service. A Tor that is
// buggy, replaced or compromised must not crash the node or make it believe
// something false.
//
// What the node actually sends Tor (tor.cpp): AUTHENTICATE with the cookie,
// GETINFO status/bootstrap-phase every five seconds, SIGNAL SHUTDOWN. Every
// reply to them goes through BtfTorReadReply (socket) into BtfTorReplyParser;
// the bootstrap answer then through BtfTorParseBootstrap, whose percentage
// decides when the bridge ladder stops. Onion services come from the torrc
// (no ADD_ONION), and Tor's answer there is the hostname file, read by
// BtfTorHostnameEndpoint. Bridge lines (bridges.txt, or the settorbridges
// RPC) go through BtfParseBridgeLines into the torrc.
//
// Input layout: byte 0 selects
//   0  control-port replies: the rest is what Tor sent. Read by the buffer
//      reader, reply after reply, and the first reply also by the socket
//      reader over a socketpair: the two must agree (differential), and each
//      reply is checked for what it may and may not contain
//   1  hostname file: bytes 1-2 the port (little-endian), the rest the file
//   2  bridge lines: the rest is the text of bridges.txt
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "tor.h"
#include "btfaddr.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static void FuzzTorInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzTorInit
#include "fuzz_datadir.h"
#include "fuzz_socket.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

// tor.cpp; not in tor.h, which does not know SOCKET.
bool BtfTorReadReply(SOCKET s, BtfTorReply& out);

static void Check(bool f, const char* pszWhat)
{
    if (!f)
    {
        fprintf(stderr, "fuzz-tor-control: %s\n", pszWhat);
        abort();
    }
}

static bool SameReply(const BtfTorReply& a, const BtfTorReply& b)
{
    return a.nCode == b.nCode && a.vLines == b.vLines;
}

static void CheckReply(const BtfTorReply& r)
{
    Check(r.nCode >= 0 && r.nCode <= 999, "status code out of range");
    Check(!r.vLines.empty() && r.vLines.size() <= BtfTorReplyParser::MAX_LINES, "line count out of range");
    size_t nBytes = 0;
    for (size_t i = 0; i < r.vLines.size(); i++)
    {
        Check(r.vLines[i].find('\r') == std::string::npos, "a reply line kept a CR");
        nBytes += r.vLines[i].size();
    }
    Check(nBytes <= BtfTorReplyParser::MAX_BYTES, "reply larger than the cap");

    int pct = -7;
    std::string summary;
    if (BtfTorParseBootstrap(r, pct, summary))
    {
        // Only from a positive reply, from the line that answers the question,
        // and only a real percentage with a printable, short summary.
        Check(r.nCode == 250, "bootstrap read from a reply that is not 250");
        bool fLine = false;
        for (size_t i = 0; i < r.vLines.size(); i++)
            if (r.vLines[i].compare(0, 23, "status/bootstrap-phase=") == 0)
                fLine = true;
        Check(fLine, "bootstrap read without a status/bootstrap-phase line");
        Check(pct >= 0 && pct <= 100, "bootstrap percentage out of range");
        Check(summary.size() <= 160, "bootstrap summary too long");
        for (size_t i = 0; i < summary.size(); i++)
            Check(summary[i] >= 0x20 && summary[i] < 0x7f, "bootstrap summary not printable");
    }
}

static void FuzzReplies(const uint8_t* data, size_t size)
{
    std::string buf((const char*)data, size);

    BtfTorReply first;
    size_t pos = 0;
    bool fFirst = BtfTorReadReplyBuffer(buf, pos, first);
    Check(pos <= buf.size(), "buffer reader ran past the input");
    if (fFirst)
        CheckReply(first);

    // The socket reader the node uses, on the same bytes.
    {
        CFuzzSocketPair sp(data, size);
        BtfTorReply viaSocket;
        bool fSocket = BtfTorReadReply(sp.fdNode, viaSocket);
        Check(fSocket == fFirst, "socket and buffer readers disagree on success");
        if (fSocket)
            Check(SameReply(viaSocket, first), "socket and buffer readers disagree on the reply");
    }

    // The rest of the stream, reply after reply, as the next commands' replies.
    for (int n = 0; fFirst && n < 64; n++)
    {
        BtfTorReply next;
        size_t before = pos;
        if (!BtfTorReadReplyBuffer(buf, pos, next))
            break;
        Check(pos > before && pos <= buf.size(), "buffer reader did not advance");
        CheckReply(next);
    }
}

static void FuzzHostname(const uint8_t* data, size_t size)
{
    if (size < 2)
        return;
    unsigned short port = (unsigned short)(data[0] | (data[1] << 8));
    std::string contents((const char*)data + 2, size - 2);
    std::string endpoint;
    if (!BtfTorHostnameEndpoint(contents, port, endpoint))
        return;
    // A v3 name: 56 base32 characters, ".onion", the port; and normalising it
    // again changes nothing (round trip).
    Check(endpoint.size() > 63 && endpoint.compare(56, 7, ".onion:") == 0, "endpoint is not NAME.onion:PORT");
    for (size_t i = 0; i < 56; i++)
        Check((endpoint[i] >= 'a' && endpoint[i] <= 'z') || (endpoint[i] >= '2' && endpoint[i] <= '7'),
              "endpoint name is not base32");
    Check(endpoint.substr(63) == strprintf("%u", (unsigned)port), "endpoint port is not the service's");
    std::string again;
    Check(btf::NormalizeOnionEndpoint(endpoint, again) && again == endpoint, "endpoint does not normalise to itself");
}

static void FuzzBridges(const uint8_t* data, size_t size)
{
    std::string text((const char*)data, size);
    std::vector<std::string> v = BtfParseBridgeLines(text);
    for (size_t i = 0; i < v.size(); i++)
    {
        // Each becomes one "Bridge ..." line of the torrc.
        const std::string& l = v[i];
        Check(!l.empty(), "an empty bridge line");
        Check(l.find('\n') == std::string::npos && l.find('\r') == std::string::npos, "a bridge line spans lines");
        Check(l[0] != ' ' && l[0] != '\t' && l[0] != '#', "a bridge line starts with a blank or a comment");
        std::string tr = BtfBridgeTransport(l);
        Check(tr.find(' ') == std::string::npos && tr.find('\t') == std::string::npos, "a transport name holds a blank");
        Check(l.compare(0, tr.size(), tr) == 0, "the transport is not the line's first word");
    }
    // What the torrc gets is "Bridge " + line; read back, that is the line.
    for (size_t i = 0; i < v.size(); i++)
    {
        std::vector<std::string> again = BtfParseBridgeLines("Bridge " + v[i]);
        Check(again.size() == 1 && again[0] == v[i], "a torrc bridge line does not read back as itself");
    }
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

static void WriteSeeds(const std::string& d)
{
    WriteSeed(d, "auth-ok", 0, "250 OK\r\n");
    WriteSeed(d, "auth-bad", 0, "515 Authentication failed: Wrong length on authentication cookie.\r\n");
    WriteSeed(d, "bootstrap", 0,
              "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=requesting_status "
              "SUMMARY=\"Asking for networkstatus consensus\"\r\n250 OK\r\n");
    WriteSeed(d, "bootstrap-done", 0,
              "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n");
    WriteSeed(d, "bootstrap-escaped", 0,
              "250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=5 TAG=conn SUMMARY=\"Say \\\"hi\\\"\" "
              "WARNING=\"Connection refused\" REASON=CONNECTREFUSED COUNT=3 RECOMMENDATION=ignore\r\n250 OK\r\n");
    WriteSeed(d, "data-block", 0,
              "250+config-text=\r\nSocksPort 9050\r\n..dot\r\n.\r\n250 OK\r\n");
    WriteSeed(d, "two-replies", 0, "250 OK\r\n250 closing connection\r\n");
    WriteSeed(d, "protocolinfo", 0,
              "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/lib/tor/control_auth_cookie\"\r\n"
              "250-VERSION Tor=\"0.4.9.15\"\r\n250 OK\r\n");
    WriteSeed(d, "event", 0, "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n");
    std::string host = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion\n";
    WriteSeed(d, "hostname", 1, std::string("\x55\x20", 2) + host);
    WriteSeed(d, "bridges", 2,
              "# comment\nBridge obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x iat-mode=0\n"
              "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72\r\n\t\n");
}

static void FuzzTorInit()
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
    switch (data[0] % 3)
    {
    case 0: FuzzReplies(data + 1, size - 1); break;
    case 1: FuzzHostname(data + 1, size - 1); break;
    case 2: FuzzBridges(data + 1, size - 1); break;
    }
    return 0;
}
